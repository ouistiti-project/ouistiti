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

#include "ouistiti/httpserver.h"
#include "ouistiti/hash.h"
#include "ouistiti/log.h"
#include "mod_auth.h"

#define auth_dbg(...)

typedef struct authn_basic_s authn_basic_t;
struct authn_basic_s
{
	const authn_t *authn;
	authz_t *authz;
	string_t *issuer;
};

void *authn_basic_config(const void *configauth, authn_type_t *type)
{
	return (void *)(long)1;
}

static void *authn_basic_create(const authn_t *authn, string_t *issuer, void *arg)
{
	authn_basic_t *mod = calloc(1, sizeof(*mod));
	mod->issuer = issuer;
	mod->authn = authn;
	return mod;
}

static int authn_basic_challenge(void *arg, http_message_t *UNUSED(request), http_message_t *response)
{
	int ret;
	const authn_basic_t *mod = (authn_basic_t *)arg;
	const mod_auth_t *config = mod->authn->config;

	httpmessage_addheader(response, str_authenticate, STRING_REF("Basic realm=\""));
	const string_t *realm = mod->issuer;
	if (!string_empty(&config->realm))
		realm = &config->realm;
	httpmessage_appendheader(response, str_authenticate, string_toc(realm), string_length(realm));
	httpmessage_appendheader(response, str_authenticate, STRING_REF("\""));
	ret = ECONTINUE;
	return ret;
}

static char user[256] = {0};
static const char *authn_basic_check(void *arg, authz_t *authz, const char *method, size_t methodlen, const char *uri, size_t urilen, const char *string, size_t stringlen)
{
	char *passwd;
	const char *found = NULL;
	(void) method;
	(void) uri;

	memset(user, 0, 256);
	auth_dbg("auth: basic check: %s", string);
	base64->decode(string, stringlen, user, 256);
	passwd = strchr(user, ':');
	if (passwd != NULL)
	{
		*passwd = 0;
		passwd++;
		found = authz->rules->check(authz->ctx, user, passwd, NULL);
	}
	else
		found = authz->rules->check(authz->ctx, NULL, NULL, string);
	auth_dbg("auth: basic check: %s %s", user, passwd);
	return found;
}

static void authn_basic_destroy(void *arg)
{
	authn_basic_t *mod = (authn_basic_t *)arg;
	free(mod);
}

authn_rules_t authn_basic_rules =
{
	.config = &authn_basic_config,
	.create = &authn_basic_create,
	.challenge = &authn_basic_challenge,
	.check = &authn_basic_check,
	.destroy = &authn_basic_destroy,
};

static const string_t authn_name = STRING_DCL("Basic");
static void __attribute__ ((constructor)) _init()
{
	auth_registerauthn(&authn_name, &authn_basic_rules);
}
