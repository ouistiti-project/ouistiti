/*****************************************************************************
 * authn_bearer.c: Basic Authentication mode
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
#include <sys/stat.h>

#include "httpserver/httpserver.h"
#include "httpserver/uri.h"
#include "httpserver/utils.h"
#include "mod_auth.h"
#include "authn_bearer.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

#define auth_dbg(...)

#define MAX_TOKEN 123

typedef struct authn_bearer_s authn_bearer_t;
struct authn_bearer_s
{
	authn_bearer_config_t *config;
	authz_t *authz;
	http_client_t *clt;
};

static void *authn_bearer_create(const authn_t *authn, authz_t *authz, void *arg)
{
	authn_bearer_t *mod = calloc(1, sizeof(*mod));
	mod->authz = authz;
	mod->config = (authn_bearer_config_t *)arg;
	if (mod->config->realm == NULL)
		mod->config->realm = httpserver_INFO(authn->server, "host");

	return mod;
}

static int authn_bearer_challenge(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = ECONTINUE;
	const authn_bearer_t *mod = (authn_bearer_t *)arg;
	authn_bearer_config_t *config = mod->config;

	const char *uriencoded = httpmessage_REQUEST(request, "uri");
	char *uri = utils_urldecode(uriencoded);
	char authenticate[256];
	snprintf(authenticate, 256, "Bearer realm=\"%s\"", config->realm);
	httpmessage_addheader(response, str_authenticate, authenticate);

	if (config->token_ep != NULL && config->token_ep[0] != '\0')
	{
		http_server_t *server = httpclient_server(httpmessage_client(request));
		const char *scheme = httpserver_INFO(server, "scheme");
		const char *host = httpserver_INFO(server, "host");
		if (host == NULL)
		{
			host = httpmessage_SERVER(request, "addr");
		}
		const char *port = httpserver_INFO(server, "port");
		const char *portseparator = "";
		if (port[0] != '\0')
			portseparator = ":";
		char location[256];
		snprintf(location, 256, "%s?redirect_uri=%s://%s%s%s/%s",
			config->token_ep,
			scheme, host, portseparator, port, uri);
		dbg("auth: redirection to %s", location);
		httpmessage_addheader(response, str_location, location);
		httpmessage_result(response, RESULT_302);
		ret = ESUCCESS;
	}
	free(uri);
	return ret;
}

static const char *authn_bearer_check(void *arg, const char *method, const char *uri, const char *string)
{
	const authn_bearer_t *mod = (authn_bearer_t *)arg;
	(void) method;
	(void) uri;

	if (!strncmp(string, "Bearer ", 7))
		string += 7;
	return mod->authz->rules->check(mod->authz->ctx, NULL, NULL, string);
}

static void authn_bearer_destroy(void *arg)
{
	authn_bearer_t *mod = (authn_bearer_t *)arg;
	free(mod);
}

authn_rules_t authn_bearer_rules =
{
	.create = authn_bearer_create,
	.challenge = authn_bearer_challenge,
	.check = authn_bearer_check,
	.destroy = authn_bearer_destroy,
};
