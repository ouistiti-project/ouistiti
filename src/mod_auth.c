/*****************************************************************************
 * mod_auth.c: Authentication module
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
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include "httpserver/httpserver.h"
#include "mod_auth.h"
#include "authn_basic.h"
#include "authn_digest.h"
#include "authz_simple.h"
#include "authz_file.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

#ifndef RESULT_401
#error mod_auth require RESULT_401
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
	char *vhost;
	const char *type;
	authn_t *authn;
	authz_t *authz;
	int typelength;
	int loginfd;
};

const char *str_authenticate = "WWW-Authenticate";
static const char *str_authorization = "Authorization";
const char *str_authenticate_types[] =
{
	"None",
	"Basic",
	"Digest",
};
authn_rules_t *authn_rules[] = {
	NULL,
#ifdef AUTHN_BASIC
	&authn_basic_rules,
#else
	NULL,
#endif
#ifdef AUTHN_DIGEST
	&authn_digest_rules,
#else
	NULL,
#endif
};

void *mod_auth_create(http_server_t *server, char *vhost, mod_auth_t *config)
{
	_mod_auth_t *mod;

	if (!config)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = config;
	mod->vhost = vhost;

	mod->authz = calloc(1, sizeof(*mod->authz));
	mod->authz->type = config->authz_type;
	switch (config->authz_type)
	{
#ifdef AUTHZ_SIMPLE
	case AUTHZ_SIMPLE_E:
		mod->authz->rules = &authz_simple_rules;
		mod->authz->ctx = mod->authz->rules->create(config->authz_config);
	break;
#endif
#ifdef AUTHZ_FILE
	case AUTHZ_FILE_E:
		mod->authz->rules = &authz_file_rules;
		mod->authz->ctx = mod->authz->rules->create(config->authz_config);
	break;
#endif
	}
	if (mod->authz->ctx == NULL)
	{
		free(mod->authz);
		free(mod);
		return NULL;
	}

	mod->authn = calloc(1, sizeof(*mod->authn));
	mod->authn->type = config->authn_type;
	mod->authn->rules = authn_rules[config->authn_type];
	if (mod->authn->rules && mod->authz->rules)
	{
		mod->authn->ctx = mod->authn->rules->create(mod->authz, config->authn_config);
	}
	if (mod->authn->ctx)
	{
		mod->type = str_authenticate_types[config->authn_type];
		mod->typelength = strlen(mod->type);

		httpserver_addmod(server, _mod_auth_getctx, _mod_auth_freectx, mod);
	}
	else
	{
		mod->authz->rules->destroy(mod->authz->ctx);
		free(mod->authz);
		free(mod->authn);
		free(mod);
		mod = NULL;
	}
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

	if(mod->authn->rules->setup)
		mod->authn->rules->setup(mod->authn->ctx, addr, addrsize);
	httpclient_addconnector(ctl, mod->vhost, _authn_connector, ctx);
	return ctx;
}

static void _mod_auth_freectx(void *vctx)
{
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)vctx;
	free(ctx->authenticate);
	free(ctx);
}

#define CONTENTCHUNK 63
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
		char *method = httpmessage_REQUEST(request, "method");
		char *user = mod->authn->rules->check(mod->authn->ctx, method, authentication);
		if (user != NULL)
		{
			dbg("user \"%s\" accepted", user);
			httpmessage_SESSION(request, "%user", user);
			httpmessage_SESSION(request, "%authtype", (char *)mod->type);

			if (mod->authz->rules->group)
			{
				char *group = mod->authz->rules->group(mod->authz->ctx, user);
				httpmessage_SESSION(request, "%authgroup", group);
				dbg("group %s", group);
			}
			ret = EREJECT;
		}
		else
		{
			authorization = NULL;
		}
	}
	else
		authorization = NULL;

	if (authorization == NULL || authorization[0] == '\0')
	{
		int length = CONTENTCHUNK;
		if (mod->loginfd == 0)
		{
			ret = mod->authn->rules->challenge(mod->authn->ctx, request, response);
			if (ret == ESUCCESS)
			{
				if (mod->config->login)
				{
					mod->loginfd = open(mod->config->login, O_RDONLY);
					struct stat stat;
					fstat(mod->loginfd, &stat);
					length = stat.st_size;
					httpmessage_addcontent(response, "text/html", NULL, stat.st_size);
#if defined(RESULT_403)
					httpmessage_result(response, RESULT_403);
#elif defined(RESULT_401)
					httpmessage_result(response, RESULT_401);
#else
					httpmessage_result(response, RESULT_400);
#endif
				}
				else
				{
#if defined(RESULT_403)
					char *X_Requested_With = httpmessage_REQUEST(request, "X-Requested-With");
					if (X_Requested_With && strstr(X_Requested_With, "XMLHttpRequest") != NULL)
						httpmessage_result(response, RESULT_403);
					else
#endif
#if defined(RESULT_401)
						httpmessage_result(response, RESULT_401);
#else
						httpmessage_result(response, RESULT_400);
#endif
				}
			}
		}
		if (mod->loginfd > 0)
		{
			char content[CONTENTCHUNK];
			length = (length < CONTENTCHUNK)?length:CONTENTCHUNK;
			length = read(mod->loginfd, content, length);
			if (length > 0)
			{
				httpmessage_addcontent(response, "text/html", content, length);
				ret = ECONTINUE;
			}
			else
			{
				close(mod->loginfd);
				mod->loginfd = 0;
			}
		}
	}

	return ret;
}
