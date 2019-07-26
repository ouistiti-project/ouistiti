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

#include <jansson.h>

#include "httpserver/httpserver.h"
#include "httpserver/hash.h"
#include "httpserver/utils.h"
#include "mod_auth.h"
#include "authn_oauth2.h"
#include "authz_jwt.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

#ifdef TLS
const httpclient_ops_t *tlsclient_ops;
#endif

static const char *str_authresp = "authresp";
static const char *str_oauth2 = "oauth2";

static const char *str_authorization_code = "code";
static const char *str_access_token = "access_token";
static const char *str_state = "session_state";

typedef struct authn_oauth2_s authn_oauth2_t;
struct authn_oauth2_s
{
	authn_oauth2_config_t *config;
	authz_t *authz;
	http_client_t *clt;
	void *vhost;
	int state;
};

static void utils_searchstring(const char **result, char *haystack, char *needle, int length)
{
	if ((*result == NULL || *result[0] == '\0') &&
		!strncmp(haystack, needle, length) && haystack[length] == '=')
	{
		char *end = NULL;
		*result = strchr(haystack, '=') + 1;
		if (**result == '"')
		{
			*result = *result + 1;
			end = strchr(*result, '"');
		}
		else
		{
			end = (char *)*result;
			while(*end != 0 && *end != ' ' && *end != ',')
			{
				end++;
			}
		}
		if (end)
			*end = 0;
	}
}

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
		size = httpmessage_content(info->request, NULL, NULL);
		if (size == 0 && strlen(info->content) > 0)
		{
			info->content += httpmessage_addcontent(info->request, NULL, info->content, -1);
		}

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

static int oauth2_authresp_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	authn_oauth2_t *mod = (authn_oauth2_t *)arg;
	authn_oauth2_config_t *config = (authn_oauth2_config_t *)mod->config;

	char *uri = utils_urldecode(httpmessage_REQUEST(request, "uri"));
	if (utils_searchexp(uri, str_authresp) == ESUCCESS)
	{
		mod->state = 1;
		/** set the default result */
		httpmessage_result(response, RESULT_500);
		warn("authentication from server: %s", uri);
		char squery[1024];
		json_t *json_authtokens = NULL;
		const char *access_token = NULL;
		const char *username = "root";
		authsession_t *authinfo = NULL;
		int expires_in = -1;
		const char *code = httpmessage_parameter(request, str_authorization_code);
		char *state = NULL;
		char *end = NULL;

		http_client_t *client = NULL;
		http_message_t *response2 = NULL;
		http_message_t *request2 = NULL;
		if (code != NULL)
		{
			request2 = httpmessage_create();

			char location[256];
			snprintf(location, 256, "%s", config->token_ep);

			client = httpmessage_request(request2, "POST", location);

			if (client != NULL)
			{
				const char *type = "authorization_code"; /** RFC6749 4.1.2 */

				char authorization[256] = {0};
				char basic[164];
				snprintf(basic, 164, "%s:%s", config->client_id, config->client_passwd);
				strcpy(authorization, "Basic ");
				int length = strlen(basic) * 1.5 + 5;
				base64_urlencoding->encode(basic, strlen(basic), authorization + strlen(authorization), length - 1);
				httpmessage_addheader(request2, str_authorization, authorization);

				response2 = httpmessage_create();

				struct _json_load_s _json_load_data = {
					.client = client,
					.request = request2,
					.response = response2,
				};

				http_server_t *server = httpclient_server(mod->clt);
				const char *scheme = httpserver_INFO(server, "scheme");
				const char *host = httpserver_INFO(server, "host");
				const char *port = httpserver_INFO(server, "port");
				const char *portseparator = "";
				if (port[0] != '\0')
					portseparator = ":";
				char content[1024];
				snprintf(content, 1024, "grant_type=%s&" \
							"code=%s&" \
							"client_id=%s&" \
							"scope=openid roles profile&" \
							"redirect_uri=%s://%s%s%s/%s&" \
							"state=%.3d\r\n",
							type,
							code,
							config->client_id,
							scheme, host, portseparator, port, str_authresp,
							mod->state);
				_json_load_data.content = content;
				_json_load_data.content += httpmessage_addcontent(request2, "application/x-www-form-urlencoded", (char *)content, -1);

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
				if (json_authtokens != NULL && json_is_object(json_authtokens))
				{
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
						dbg("oAuth2 access_token: %s", access_token);
					}
					json_t *json_idtoken = json_object_get(json_authtokens, "id_token");
					if (json_idtoken != NULL && json_is_string(json_idtoken))
					{
						const char *id_token = json_string_value(json_idtoken);
						authinfo = jwt_decode(id_token, config->client_passwd);
						dbg("oAuth2 id_token: %s", id_token);
						if (authinfo != NULL)
						{
							mod->authz->rules->adduser(mod->authz->ctx, authinfo);
						}
					}
					json_t *json_username = json_object_get(json_authtokens, "username");
					if (json_username != NULL && json_is_string(json_username))
					{
						authsession_t authinfo = {0};
						strncpy(authinfo.user, json_string_value(json_username), sizeof(authinfo.user));
						strcpy(authinfo.group, "users");
						mod->authz->rules->adduser(mod->authz->ctx, &authinfo);
					}
					json_t *json_expire = json_object_get(json_authtokens, "expires_in");
					if (json_expire != NULL && json_is_integer(json_expire))
					{
						expires_in = json_integer_value(json_expire);
						dbg("oAuth2 access_token expire in: %ds", expires_in);
					}
				}
			}
			mod->state++;
		}

		if (access_token != NULL)
		{
#define MAX_TOKEN 123
			/**
			 * keep only the signature of the access_token.
			 * The KeyCloak token is too long for ouistiti.
			 */
			if (strlen(access_token) > MAX_TOKEN)
			{
				char *tmp = strrchr(access_token, '.');
				if (tmp != NULL)
				{
					access_token = tmp + 1;
				}
				tmp = (char *)access_token + MAX_TOKEN;
				*tmp = '\0';
			}
			if (authinfo != NULL)
			{
				ret = mod->authz->rules->join(mod->authz->ctx, authinfo->user, access_token, expires_in);
			}
			if (ret != ESUCCESS)
			{
				err("oauth2 db error on insert %d", ret);
			}
			else
			{
				char authorization[MAX_TOKEN + 7 + 1];
				snprintf(authorization, MAX_TOKEN + 7 + 1, "oAuth2 %s", access_token);
				httpmessage_addheader(response, str_authorization, authorization);

				char location[1024];
				const char *scheme = httpmessage_REQUEST(request, "scheme");
				const char *host = httpmessage_REQUEST(request, "host");
				snprintf(location, 1024, "%s://%s/",
										scheme,
										host);
				httpmessage_addheader(response, str_location, location);
				httpmessage_result(response, RESULT_302);

				cookie_set(response, str_authorization, authorization);
				ret = ESUCCESS;
			}
		}
		else
		{
			httpmessage_result(response, RESULT_401);
			ret = ESUCCESS;
		}

		if (authinfo != NULL)
		{
			free(authinfo);
		}
		if (request2 != NULL)
			httpmessage_destroy(request2);
		if (response2 != NULL)
			httpmessage_destroy(response2);
		if (client != NULL)
			httpclient_destroy(client);
		if (json_authtokens != NULL)
		{
			json_decref(json_authtokens);
		}
	}
	free(uri);
	return ret;
}

static void *authn_oauth2_create(authn_t *authn, authz_t *authz, void *config)
{
	if (authz->rules->adduser == NULL)
	{
		err("oauth2 needs to run with SQLITE authz");
		warn("set auth dbname configuration");
		return NULL;
	}
	if (authn->hash == NULL)
		return NULL;
	authn_oauth2_t *mod = calloc(1, sizeof(*mod));
	mod->config = (authn_oauth2_config_t *)config;
	mod->authz = authz;
	mod->state = 0;

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
	httpclient_addconnector(clt, mod->vhost, oauth2_authresp_connector, mod, str_oauth2);
	return ESUCCESS;
}

static int authn_oauth2_challenge(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = ESUCCESS;
	authn_oauth2_t *mod = (authn_oauth2_t *)arg;
	authn_oauth2_config_t *config = mod->config;

	const char *uriencoded = httpmessage_REQUEST(request, "uri");
	char *uri = utils_urldecode(uriencoded);
	char authenticate[256];
	snprintf(authenticate, 256, "Bearer realm=\"%s\"", config->realm);
	httpmessage_addheader(response, str_authenticate, authenticate);

	if (!utils_searchexp(uri, str_authresp))
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
		char location[256];
		snprintf(location, 256, "%s?" \
								"response_type=%s&" \
								"scope=openid roles&" \
								"client_id=%s&" \
								"redirect_uri=%s://%s%s%s/%s",
								config->auth_ep,
								"code",
								config->client_id,
								scheme, host, portseparator, port, str_authresp);
		httpmessage_addheader(response, (char *)str_location, location);
		httpmessage_result(response, RESULT_302);
	}
	else
	{
		httpmessage_result(response, RESULT_401);
	}
	free(uri);
	return ret;
}

static const char *authn_oauth2_check(void *arg, const char *method, const char *uri, char *string)
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
	.create = authn_oauth2_create,
	.setup = authn_oauth2_setup,
	.challenge = authn_oauth2_challenge,
	.check = authn_oauth2_check,
	.destroy = authn_oauth2_destroy,
};
