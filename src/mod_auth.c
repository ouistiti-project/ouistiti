/*****************************************************************************
 * mod_auth.c: callbacks and management of connection
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

/**
    auth module needs the type of authentication ("Basic" or "Digest").
    After the rule to check the password is an authn_<type>_<name>
    sublibrary (just a C file).

    With this solution each server may has its own authentication type.
    After the checking of the password is done by a library linked to the
    mod_auth library.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "httpserver/httpserver.h"
#include "mod_auth.h"
#include "authn_basic.h"
#include "authz_simple.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif


typedef struct _mod_auth_s _mod_auth_t;
typedef struct _mod_auth_ctx_s _mod_auth_ctx_t;

static http_server_config_t mod_auth_config;

static void *_mod_auth_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize);
static void _mod_auth_freectx(void *vctx);
static int _authn_connector(void *arg, http_message_t *request, http_message_t *response);

struct _mod_auth_ctx_s
{
	_mod_auth_t *mod;
	char *authenticate;
};

struct _mod_auth_s
{
	mod_auth_t	*config;
	char *realm;
	const char *type;
	authn_t *authn;
	authz_t *authz;
	int typelength;
};

const char *str_authenticate = "WWW-Authenticate";
static const char *str_authorization = "Authorization";
static const char *str_realm = "ouistiti";
static const char *str_types[] =
{
	"None",
	"Basic",
	"Digest",
};

void *mod_auth_create(http_server_t *server, mod_auth_t *config)
{
	_mod_auth_t *mod;

	if (!config)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = config;

	if (config->realm == NULL)
	{
		mod->realm = (char *)str_realm;
	}
	else
		mod->realm = config->realm;

	mod->authz = calloc(1, sizeof(*mod->authz));
	mod->authz->type = config->authz_type;
	switch (config->authz_type)
	{
	case AUTHZ_SIMPLE_E:
		mod->authz->rules = &authz_simple_rules;
		mod->authz->ctx = mod->authz->rules->create(config->authz_config);
	break;
	}

	mod->authn = calloc(1, sizeof(*mod->authn));
	mod->authn->type = config->authn_type;
	switch (config->authn_type)
	{
	case AUTHN_BASIC_E:
		mod->authn->rules = &authn_basic_rules;
		mod->authn->ctx = mod->authn->rules->create(mod->authz, config->authn_config);
		mod->type = str_types[config->authn_type];
	break;
	default:
		mod->type = str_types[0];
	}
	mod->typelength = strlen(mod->type);

	httpserver_addmod(server, _mod_auth_getctx, _mod_auth_freectx, mod);

	return mod;
}

void mod_auth_destroy(void *arg)
{
	_mod_auth_t *mod = (_mod_auth_t *)arg;
	if (mod->authn->ctx  && mod->authn->rules->destroy)
	{
		mod->authn->rules->destroy(mod->authn->ctx);
	}
	if (mod->authz->ctx && mod->authz->rules->destroy)
	{
		mod->authz->rules->destroy(mod->authz->ctx);
	}
	free(mod);
}

static void *_mod_auth_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_auth_ctx_t *ctx = calloc(1, sizeof(*ctx));
	_mod_auth_t *mod = (_mod_auth_t *)arg;

	ctx->mod = mod;

	httpclient_addconnector(ctl, NULL, _authn_connector, ctx);
	return ctx;
}

static void _mod_auth_freectx(void *vctx)
{
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)vctx;
	free(ctx->authenticate);
	free(ctx);
}

static int _authn_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = ECONTINUE;
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)arg;
	_mod_auth_t *mod = ctx->mod;
	char *authorization;
	authorization = httpmessage_REQUEST(request, (char *)str_authorization);
	if (mod->authn->ctx && authorization != NULL && !strncmp(authorization, mod->type, mod->typelength))
	{
		char *authentication = strchr(authorization, ' ');
		if (authentication)
			authentication++;
		char *user = mod->authn->rules->check(mod->authn->ctx, authentication);
		if (user != NULL)
		{
			dbg("user \"%s\" accepted", user);
			httpmessage_SESSION(request, "%user", user);
			httpmessage_SESSION(request, "%authtype", (char *)mod->type);
			ret = EREJECT;
		}
		else
		{
			dbg("bad passwd");
			authorization = NULL;
		}
	}
	else
		authorization = NULL;

	if (authorization == NULL || authorization[0] == '\0')
	{
		ret = mod->authn->rules->challenge(mod->authn->ctx, request, response);
	}
	return ret;
}
