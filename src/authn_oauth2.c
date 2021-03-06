/*****************************************************************************
 * authn_oauth2.c: Basic Authentication mode
 * this file is part of https://github.com/ouistiti-project/ouistiti
 *****************************************************************************
 * Copyright (C) 2016-2017
 *
 * Authors: Marc Chalain <marc.chalain@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *****************************************************************************/
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>

#include <jansson.h>

#include "ouistiti/httpserver.h"
#include "ouistiti/hash.h"
#include "ouistiti/utils.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
#include "authn_oauth2.h"
#include "authz_jwt.h"

#define auth_dbg(...)

#ifdef TLS
const httpclient_ops_t *tlsclient_ops;
#endif

static const char *str_authresp = "/auth/resp";
static const char *str_oauth2 = "oauth2";
static const char *str_auth = "auth";

static const char *str_authorization_code = "code";
static const char *str_access_token = "access_token";
static const char *str_state = "session_state";
static const char *str_expires = "expires";

typedef struct authn_oauth2_s authn_oauth2_t;
struct authn_oauth2_s
{
	authn_oauth2_config_t *config;
	authz_t *authz;
	http_client_t *clt;
	void *vhost;
	int state;
};

typedef struct _mod_oauth2_ctx_s _mod_oauth2_ctx_t;
struct _mod_oauth2_ctx_s
{
	authn_oauth2_t *mod;
};

json_t *json_load_callback(json_load_callback_t callback, void *data, size_t flags, json_error_t *error);
struct _json_load_s
{
	http_client_t *client;
	http_message_t *request;
	http_message_t *response;
	const char *content;
};

#ifdef FILE_CONFIG
void *authn_oauth2_config(const config_setting_t *configauth)
{
	authn_oauth2_config_t *authn_config = NULL;
	const char *auth_ep = NULL;
	const char *discovery = NULL;

	config_setting_lookup_string(configauth, "discovery", (const char **)&discovery);
	config_setting_lookup_string(configauth, "auth_ep", (const char **)&auth_ep);

	authn_config = calloc(1, sizeof(*authn_config));
	authn_config->discovery = discovery;
	authn_config->auth_ep = auth_ep;

	config_setting_lookup_string(configauth, "realm", (const char **)&authn_config->realm);

	config_setting_lookup_string(configauth, "client_id", (const char **)&authn_config->client_id);
	if (authn_config->client_id == NULL)
		authn_config->client_id = authn_config->realm;

	config_setting_lookup_string(configauth, "client_passwd", (const char **)&authn_config->client_passwd);
	if (authn_config->client_passwd == NULL)
	{
		config_setting_lookup_string(configauth, "secret", (const char **)&authn_config->client_passwd);
	}

	if (authn_config->iss == NULL)
		authn_config->iss = authn_config->realm;

	return authn_config;
}
#endif

size_t _json_load(void *buffer, size_t buflen, void *data)
{
	int ret;
	size_t size;
	struct _json_load_s *info = (struct _json_load_s *)data;

	if (info->response == NULL)
		info->response = httpmessage_create(654);

	do
	{
		ret = httpclient_sendrequest(info->client, info->request, info->response);
	} while (ret == EINCOMPLETE);

	char *content = NULL;
	unsigned long long length = 0;
	size = httpmessage_content(info->response, &content, &length);
	if (size > 0 && size < buflen)
	{
		memcpy(buffer, content, size);
	}
	else if (size == EREJECT)
		size = 0;
	else if (size < 0)
		size = sizeof(size) - 1;
	return size;
}

static int _oauth2_checkidtoken(authn_oauth2_t *mod, json_t *json_idtoken, authsession_t *authinfo)
{
	authn_oauth2_config_t *config = (authn_oauth2_config_t *)mod->config;

	const char *id_token = json_string_value(json_idtoken);
	const char *data = id_token;
	const char *sign = strrchr(id_token, '.');
	if (sign != NULL)
	{
		size_t datalen = sign - data;
		sign++;
		if (authn_checksignature(config->client_passwd, data, datalen, sign, strlen(sign)) == ESUCCESS)
		{
			jwt_decode(id_token, authinfo);
			auth_dbg("oAuth2 id_token: %s", id_token);
			return ESUCCESS;
		}
	}
	return EREJECT;
}

static json_t *_oauth2_authresp_send(authn_oauth2_t *mod, http_message_t *request)
{
	json_t *json_authtokens = NULL;
	authn_oauth2_config_t *config = (authn_oauth2_config_t *)mod->config;
	http_client_t *client = NULL;
	http_message_t *response2 = NULL;
	http_message_t *request2 = NULL;

	request2 = httpmessage_create();

	const char *code = httpmessage_parameter(request, str_authorization_code);
	if (code == NULL)
		return NULL;

	char location[256];
	snprintf(location, 256, "%s", config->token_ep);

	client = httpmessage_request(request2, "POST", location);

	if (client != NULL)
	{
		const char *type = "authorization_code"; /** RFC6749 4.1.2 */


		httpmessage_addheader(request2, str_authorization, "Basic ");

		char authorization[256] = {0};
		char basic[164];
		snprintf(basic, 164, "%s:%s", config->client_id, config->client_passwd);
		int length = strlen(basic) * 1.5 + 5;
		base64_urlencoding->encode(basic, strlen(basic), authorization, 256);
		httpmessage_appendheader(request2, str_authorization, authorization, NULL);

		response2 = httpmessage_create();

		struct _json_load_s _json_load_data = {
			.client = client,
			.request = request2,
			.response = response2,
			.content = 0,
		};

		http_server_t *server = httpclient_server(mod->clt);
		const char *scheme = httpserver_INFO(server, "scheme");
		const char *host = httpserver_INFO(server, "host");
		if (host == NULL)
		{
			host = httpmessage_SERVER(request, "addr");
		}
		const char *port = httpserver_INFO(server, "port");
		_json_load_data.content += httpmessage_addcontent(request2, "application/x-www-form-urlencoded", "grant_type=", -1);
		_json_load_data.content += httpmessage_appendcontent(request2, type, -1);
		_json_load_data.content += httpmessage_appendcontent(request2, "&code=", -1);
		_json_load_data.content += httpmessage_appendcontent(request2, code, -1);
		_json_load_data.content += httpmessage_appendcontent(request2, "&client_id=", -1);
		_json_load_data.content += httpmessage_appendcontent(request2, config->client_id, -1);
		_json_load_data.content += httpmessage_appendcontent(request2, "&scope=openid roles profile", -1);
		_json_load_data.content += httpmessage_appendcontent(request2, "&redirect_uri=", -1);
		_json_load_data.content += httpmessage_appendcontent(request2, scheme, -1);
		_json_load_data.content += httpmessage_appendcontent(request2, "://", -1);
		_json_load_data.content += httpmessage_appendcontent(request2, host, -1);
		if (port[0] != '\0')
		{
			_json_load_data.content += httpmessage_appendcontent(request2, ":", -1);
			_json_load_data.content += httpmessage_appendcontent(request2, port, -1);
		}
		_json_load_data.content += httpmessage_appendcontent(request2, str_authresp, -1);
		_json_load_data.content += httpmessage_appendcontent(request2, "&state=", -1);
		char state[4] = {0};
		snprintf(state, 4, "%.3d", mod->state);
		_json_load_data.content += httpmessage_appendcontent(request2, state, -1);

		/**
		 * send checking request to the authmanager
		 */
		json_error_t error;
		json_authtokens = json_load_callback(_json_load, &_json_load_data, 0, &error);
		if (json_authtokens == NULL)
		{
			int result = atoi(httpmessage_REQUEST(_json_load_data.response, "Status"));
			if (result == 200)
				err("oauth2 json decoding error %s", error.text);
			else
				err("oauth2 authorization error %d", result);
		}
	}
	if (request2 != NULL)
		httpmessage_destroy(request2);
	if (response2 != NULL)
		httpmessage_destroy(response2);
	if (client != NULL)
		httpclient_destroy(client);
	return json_authtokens;
}

static int _oauth2_authresp_receive(authn_oauth2_t *mod, json_t *json_authtokens, authsession_t *authinfo)
{
	int ret = EREJECT;
	if (json_is_object(json_authtokens))
	{
		const char *access_token = NULL;
		const char *user;

		json_t *json_error = json_object_get(json_authtokens, "error");
		if (json_error != NULL && json_is_string(json_error))
		{
			const char *error = json_string_value(json_error);
			const char *desc = NULL;
			json_t *json_desc = json_object_get(json_authtokens, "error");
			if (json_desc != NULL && json_is_string(json_desc))
				desc = json_string_value(json_desc);
			err("oAuth2 authorization error: %s (%s)", error, desc);
		}
		json_t *json_acctoken = json_object_get(json_authtokens, "access_token");
		if (json_acctoken != NULL && json_is_string(json_acctoken))
		{
			access_token = json_string_value(json_acctoken);
			auth_dbg("oAuth2 access_token: %s", access_token);
		}
		json_t *json_idtoken = json_object_get(json_authtokens, "id_token");
		if (json_idtoken != NULL && json_is_string(json_idtoken))
		{
			ret = _oauth2_checkidtoken(mod, json_idtoken, authinfo);
		}
		json_t *json_username = json_object_get(json_authtokens, "username");
		if (json_username != NULL && json_is_string(json_username))
		{
			strncpy(authinfo->user, json_string_value(json_username), sizeof(authinfo->user));
			strncpy(authinfo->group, "users", sizeof(authinfo->group));
			ret = ESUCCESS;
		}
		json_t *json_expire = json_object_get(json_authtokens, "expires_in");
		if (json_expire != NULL && json_is_integer(json_expire))
		{
			authinfo->expires = json_integer_value(json_expire);
			auth_dbg("oAuth2 access_token expire in: %ds", authinfo->expires);
		}

		if (access_token != NULL)
		{
			/**
			 * keep only the signature of the access_token.
			 * The KeyCloak token is too long for ouistiti.
			 */
			if (strlen(access_token) > TOKEN_MAX)
			{
				char *tmp = strrchr(access_token, '.');
				if (tmp != NULL)
				{
					access_token = tmp + 1;
				}
				tmp = (char *)access_token + TOKEN_MAX;
				*tmp = '\0';
			}
			strncpy(authinfo->token, access_token, TOKEN_MAX);
		}
		else
			ret = EREJECT;
	}
	return ret;
}

static int _oauth2_authresp_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	authn_oauth2_t *mod = (authn_oauth2_t *)arg;
	authn_oauth2_config_t *config = (authn_oauth2_config_t *)mod->config;

	const char *uri = httpmessage_REQUEST(request, "uri");
	if (utils_searchexp(uri, str_authresp, NULL) == ESUCCESS)
	{
		mod->state = 1;
		/** set the default result */
		httpmessage_result(response, RESULT_500);
		warn("authentication from server: %s", uri);
		char squery[1024];
		json_t *json_authtokens = NULL;
		const char *username = "root";
		authsession_t authinfo = {0};
		int expires_in = -1;
		char *state = NULL;
		char *end = NULL;

		json_authtokens = _oauth2_authresp_send(mod, request);
		mod->state++;
		if (json_authtokens != NULL)
			ret = _oauth2_authresp_receive(mod,json_authtokens, &authinfo);

		if (ret == ESUCCESS)
		{
			httpmessage_SESSION(request, str_auth, &authinfo, sizeof(authinfo));

			httpmessage_addheader(response, str_authorization, "oAuth2 ");
			httpmessage_appendheader(response, str_authorization, authinfo.token);

			const char *scheme = httpmessage_REQUEST(request, "scheme");
			httpmessage_addheader(response, str_location, scheme);
			const char *host = httpmessage_REQUEST(request, "host");
			httpmessage_appendheader(response, str_location, "://", host, "/", NULL);
			httpmessage_result(response, RESULT_302);

			ret = ESUCCESS;
		}
		else
		{
			httpmessage_result(response, RESULT_401);
			ret = ESUCCESS;
		}

		if (json_authtokens != NULL)
		{
			json_decref(json_authtokens);
		}
	}
	return ret;
}

static void *authn_oauth2_create(const authn_t *authn, authz_t *authz, void *config)
{
	if (authn->hash == NULL)
		return NULL;
	authn_oauth2_t *mod = calloc(1, sizeof(*mod));
	mod->config = (authn_oauth2_config_t *)config;
	mod->authz = authz;
	mod->state = 0;
	if (mod->config->realm == NULL)
		mod->config->realm = httpserver_INFO(authn->server, "host");

	return mod;
}

static void authn_oauth2_destroy(void *arg)
{
	authn_oauth2_t *mod = (authn_oauth2_t *)arg;

	free(mod);
}

static int authn_oauth2_setup(void *arg, http_client_t *clt, struct sockaddr *addr, int addrsize)
{
	authn_oauth2_t *mod = (authn_oauth2_t *)arg;

	mod->clt = clt;
	httpclient_addconnector(clt, _oauth2_authresp_connector, mod, CONNECTOR_AUTH, str_oauth2);
	return ESUCCESS;
}

static int authn_oauth2_challenge(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = ECONTINUE;
	authn_oauth2_t *mod = (authn_oauth2_t *)arg;
	authn_oauth2_config_t *config = mod->config;

	const char *uri = httpmessage_REQUEST(request, "uri");
	char authenticate[256];
	snprintf(authenticate, 256, "Bearer realm=\"%s\"", config->realm);
	httpmessage_addheader(response, str_authenticate, authenticate);

	if (!utils_searchexp(uri, str_authresp, NULL))
	{
		ret = EREJECT;
	}
	else if (config->token_ep != NULL && config->token_ep[0] != '\0')
	{
		http_server_t *server = httpclient_server(mod->clt);
		const char *scheme = httpserver_INFO(server, "scheme");
		const char *host = httpserver_INFO(server, "host");
		const char *port = httpserver_INFO(server, "port");

		const char *portseparator = "";
		if (port[0] != '\0')
			portseparator = ":";
		httpmessage_addheader(response, str_location, config->auth_ep);
		httpmessage_appendheader(response, str_location, "?",
								"response_type=code&",
								"scope=openid roles&",
								"client_id=",config->client_id,"&",
								"redirect_uri=", scheme, host, portseparator, port, "/", str_authresp,
								NULL
								);
		httpmessage_result(response, RESULT_302);
		ret = ESUCCESS;
	}
	return ret;
}

static const char *authn_oauth2_check(void *arg, const char *method, const char *uri, const char *string)
{
	authn_oauth2_t *mod = (authn_oauth2_t *)arg;
	authn_oauth2_config_t *config = mod->config;
	const char *user = NULL;
	int ret;

	if (string == NULL)
		return NULL;

	if (!strcmp(uri, config->token_ep))
	{
		return str_anonymous;
	}
	warn("oauth2 check %s", string);
	user = mod->authz->rules->check(mod->authz->ctx, NULL, NULL, string);
	warn("oauth2 check %s", user);
	return user;
}

authn_rules_t authn_oauth2_rules =
{
	.create = &authn_oauth2_create,
	.setup = &authn_oauth2_setup,
	.challenge = &authn_oauth2_challenge,
	.check = &authn_oauth2_check,
	.destroy = &authn_oauth2_destroy,
};
