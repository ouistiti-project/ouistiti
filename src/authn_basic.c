/*****************************************************************************
 * authn_basic.c: Basic Authentication mode
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
#include "mod_auth.h"
#include "authn_basic.h"
#include "b64/cencode.h"
#include "b64/cdecode.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

typedef struct authn_basic_s authn_basic_t;
struct authn_basic_s
{
	authn_basic_config_t *config;
	authz_t *authz;
	char *challenge;
};

void *authn_basic_create(authz_t *authz, void *arg)
{
	char format_realm[] = "%s realm=\"%s\"";
	const char *format = str_authenticate_types[AUTHN_BASIC_E];
	authn_basic_t *mod = calloc(1, sizeof(*mod));
	mod->authz = authz;
	mod->config = (authn_basic_config_t *)arg;
	if (mod->config->realm)
	{
		mod->challenge = calloc(1, sizeof(format)
							+ sizeof(format_realm) - 4
							+ strlen(mod->config->realm) + 1);
		if (mod->challenge)
			sprintf(mod->challenge, format_realm, format, mod->config->realm);
	}
	else
	{
		mod->challenge = calloc(1, sizeof(format) + 1);
		if (mod->challenge)
			sprintf(mod->challenge, format);
	}

	return mod;
}

int authn_basic_challenge(void *arg, http_message_t *request, http_message_t *response)
{
	int ret;
	authn_basic_t *mod = (authn_basic_t *)arg;

	httpmessage_addheader(response, (char *)str_authenticate, mod->challenge);
	httpmessage_result(response, RESULT_401);
	httpmessage_keepalive(response);
	ret = ESUCCESS;
	dbg("error 401");
	return ret;
}

static char user[256] = {0};
char *authn_basic_check(void *arg, char *method, char *string)
{
	authn_basic_t *mod = (authn_basic_t *)arg;
	char *passwd;

	memset(user, 0, 256);
	base64_decodestate decoder;
	base64_init_decodestate(&decoder);
	base64_decode_block(string, strlen(string), user, &decoder);
	passwd = strchr(user, ':');
	passwd[0] = 0;
	passwd++;

	if (mod->authz->rules->check(mod->authz->ctx, user, passwd))
	{
		return user;
	}
	return NULL;
}

void authn_basic_destroy(void *arg)
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
