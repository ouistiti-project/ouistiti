/*****************************************************************************
 * authn_basic.c: Basic Authentication mode
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

#include "httpserver/httpserver.h"
#include "httpserver/hash.h"
#include "mod_auth.h"
#include "authn_basic.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

#define auth_dbg(...)

typedef struct authn_basic_s authn_basic_t;
struct authn_basic_s
{
	authn_basic_config_t *config;
	authz_t *authz;
	char *challenge;
};

static void *authn_basic_create(authn_t *authn, authz_t *authz, void *arg)
{
	char format_realm[] = "%s realm=\"%s\"";
	authn_basic_t *mod = calloc(1, sizeof(*mod));
	mod->authz = authz;
	mod->config = (authn_basic_config_t *)arg;
	if (mod->config->realm == NULL)
		mod->config->realm = httpserver_INFO(authn->server, "host");
	int length = sizeof(format)
						+ sizeof(format_realm) - 4
						+ strlen(mod->config->realm) + 1;
	mod->challenge = calloc(1, length);
	if (mod->challenge)
		snprintf(mod->challenge, length, format_realm, format, mod->config->realm);

	return mod;
}

static int authn_basic_challenge(void *arg, http_message_t *request, http_message_t *response)
{
	int ret;
	authn_basic_t *mod = (authn_basic_t *)arg;

	httpmessage_addheader(response, (char *)str_authenticate, mod->challenge);
	ret = ECONTINUE;
	return ret;
}

static char user[256] = {0};
static const char *authn_basic_check(void *arg, const char *method, const char *uri, char *string)
{
	authn_basic_t *mod = (authn_basic_t *)arg;
	char *passwd;

	memset(user, 0, 256);
	base64->decode(string, strlen(string), user, 256);
	passwd = strchr(user, ':');
	if (passwd != NULL)
	{
		*passwd = 0;
		passwd++;
	}
	auth_dbg("auth basic check: %s %s", user, passwd);
	return mod->authz->rules->check(mod->authz->ctx, user, passwd, string);
}

static void authn_basic_destroy(void *arg)
{
	authn_basic_t *mod = (authn_basic_t *)arg;
	if (mod->challenge)
		free(mod->challenge);
	free(mod);
}

authn_rules_t authn_basic_rules =
{
	.create = authn_basic_create,
	.challenge = authn_basic_challenge,
	.check = authn_basic_check,
	.destroy = authn_basic_destroy,
};
