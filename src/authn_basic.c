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

typedef struct authn_mod_s authn_mod_t;
struct authn_mod_s
{
	const mod_auth_t *config;
	string_t *issuer;
};

typedef struct authn_ctx_s authn_ctx_t;
struct authn_ctx_s
{
	authn_mod_t *mod;
	char user[256];
};

static string_t string_basic = STRING_DCL("Basic ");

void *authn_basic_config(const void *configauth, authn_type_t *type)
{
	return (void *)(long)1;
}

static void *authn_basic_create(const authn_t *authn, string_t *issuer, void *arg)
{
	authn_mod_t *mod = calloc(1, sizeof(*mod));
	mod->issuer = issuer;
	mod->config = authn->config;
	return mod;
}

static void * authn_basic_setup(void *arg, http_client_t *UNUSED(ctl), struct sockaddr *UNUSED(addr), int UNUSED(addrsize))
{
	authn_mod_t *mod = (authn_mod_t *)arg;

	authn_ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->mod = mod;
	return ctx;
}

static int authn_basic_challenge(void *arg, http_message_t *UNUSED(request), http_message_t *response)
{
	int ret;
	const authn_ctx_t *ctx = (authn_ctx_t *)arg;
	const authn_mod_t *mod = ctx->mod;
	const mod_auth_t *config = mod->config;

	ret = httpmessage_addheader(response, str_authenticate, STRING_REF("Basic realm=\""));
	if (ret)
		return ret;
	const string_t *realm = mod->issuer;
	if (!string_empty(&config->realm))
		realm = &config->realm;
	httpmessage_appendheader(response, str_authenticate, string_toc(realm), string_length(realm));
	httpmessage_appendheader(response, str_authenticate, STRING_REF("\""));
	ret = ECONTINUE;
	return ret;
}

static const char *authn_basic_check(void *arg, authz_t *authz, const char *method, size_t methodlen, const char *uri, size_t urilen, const char *string, size_t stringlen)
{
	authn_ctx_t *ctx = (authn_ctx_t *)arg;
	char *passwd;
	const char *found = NULL;
	(void) method;
	(void) uri;

	string_t data = {0};
	string_store(&data, string, stringlen);
	string_t *authorization = &data;
	authorization = string_rest(authorization, &string_basic);
	if (authorization == NULL)
		return NULL;

	auth_dbg("auth: basic check: %s", string);
	base64->decode(string_toc(authorization), string_length(authorization), ctx->user, sizeof(ctx->user));
	passwd = strchr(ctx->user, ':');
	if (passwd != NULL)
	{
		*passwd = 0;
		passwd++;
		found = authz->rules->check(authz->ctx, ctx->user, passwd, NULL);
	}
	else
		found = authz->rules->check(authz->ctx, NULL, NULL, string_toc(authorization));
	auth_dbg("auth: basic check: %s", found);
	return found;
}

static void authn_basic_cleanup(void *arg)
{
	authn_ctx_t *ctx = (authn_ctx_t *)arg;
	free(ctx);
}

static void authn_basic_destroy(void *arg)
{
	authn_mod_t *mod = (authn_mod_t *)arg;
	free(mod);
}

authn_rules_t authn_basic_rules =
{
	.config = authn_basic_config,
	.create = authn_basic_create,
	.setup = authn_basic_setup,
	.challenge = authn_basic_challenge,
	.check = authn_basic_check,
	.cleanup = authn_basic_cleanup,
	.destroy = authn_basic_destroy,
};

static const string_t authn_name = STRING_DCL("Basic");
static void __attribute__ ((constructor)) _init()
{
	auth_registerauthn(&authn_name, &authn_basic_rules);
}
