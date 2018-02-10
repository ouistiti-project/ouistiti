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
#include <unistd.h>

#include "httpserver/httpserver.h"
#include "httpserver/utils.h"
#include "mod_auth.h"
#include "authn_none.h"
#include "authn_basic.h"
#include "authn_digest.h"
#include "authz_simple.h"
#include "authz_file.h"
#include "authz_unix.h"

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

static void *_mod_auth_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize);
static void _mod_auth_freectx(void *vctx);
static int _home_connector(void *arg, http_message_t *request, http_message_t *response);
static int _authn_connector(void *arg, http_message_t *request, http_message_t *response);

static const char str_auth[] = "auth";

struct _mod_auth_ctx_s
{
	_mod_auth_t *mod;
	http_client_t *ctl;
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
};

const char *str_authenticate = "WWW-Authenticate";
static const char *str_authorization = "Authorization";
static const char *str_xuser = "X-Remote-User";
static const char *str_xgroup = "X-Remote-Group";
static const char *str_wilcard = "*";
const char *str_authenticate_types[] =
{
	"None",
	"Basic",
	"Digest",
};
authn_rules_t *authn_rules[] = {
#ifdef AUTHN_NONE
	&authn_none_rules,
#else
	NULL,
#endif
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
	switch (config->authz_type & AUTHZ_TYPE_MASK)
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
#ifdef AUTHZ_UNIX
	case AUTHZ_UNIX_E:
		mod->authz->rules = &authz_unix_rules;
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

		httpserver_addmod(server, _mod_auth_getctx, _mod_auth_freectx, mod, str_auth);
	}
	else
	{
		if (mod->authn->rules && mod->authz->rules->destroy)
			mod->authz->rules->destroy(mod->authz->ctx);
		free(mod->authz);
		free(mod->authn);
		free(mod);
		mod = NULL;
	}

	if (mod != NULL && (!config->protect || config->protect[0] == '\0'))
	{
		config->protect = (char *)str_wilcard;
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
	free(mod->authn);
	free(mod->authz);
	free(mod);
}

static void *_mod_auth_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_auth_ctx_t *ctx = calloc(1, sizeof(*ctx));
	_mod_auth_t *mod = (_mod_auth_t *)arg;

	ctx->mod = mod;
	ctx->ctl = ctl;

	if(mod->authn->rules->setup)
		mod->authn->rules->setup(mod->authn->ctx, addr, addrsize);
	if (mod->authz->type & AUTHZ_HOME_E)
		httpclient_addconnector(ctl, mod->vhost, _home_connector, ctx, str_auth);
	httpclient_addconnector(ctl, mod->vhost, _authn_connector, ctx, str_auth);

	return ctx;
}

static void _mod_auth_freectx(void *vctx)
{
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)vctx;
	free(ctx->authenticate);
	free(ctx);
}

static int _home_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	char *home = httpmessage_SESSION(request, "%authhome", NULL);
	if (home)
	{
		char *uri = utils_urldecode(httpmessage_REQUEST(request, "uri"));
		int homelength = strlen(home);
		if (homelength > 0 && strncmp(home + 1, uri, homelength - 1) != 0)
		{
			dbg("redirect the url to home %s", home);
#if defined(RESULT_301)
			char *location = calloc(1, homelength + 1 + 1);
			sprintf(location, "%s/", home);
			httpmessage_addheader(response, str_location, location);
			httpmessage_result(response, RESULT_301);
			free(location);
			ret = ESUCCESS;
#endif
		}
		free(uri);
	}
	return ret;
}

#define CONTENTCHUNK 63
static int _authn_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = ECONTINUE;
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)arg;
	_mod_auth_t *mod = ctx->mod;
	mod_auth_t *config = mod->config;
	char *authorization = NULL;
	char *uriencoded = httpmessage_REQUEST(request, "uri");
	char *uri = utils_urldecode(uriencoded);
	int protect = 1;
	protect = utils_searchexp(uri, config->protect);
	if (protect != ESUCCESS)
	{
		ret = EREJECT;
	}
	else
	{
		protect = utils_searchexp(uri, config->unprotect);
		if (protect == ESUCCESS)
		{
			ret = EREJECT;
		}
		const char *redirect = config->redirect;
		if (redirect)
		{
			if (redirect[0] == '/')
				redirect++;
			protect = utils_searchexp(uri, redirect);
			if (protect == ESUCCESS)
			{
				ret = EREJECT;
			}
		}
	}

	authorization = httpmessage_REQUEST(request, (char *)str_authenticate);
	if (authorization != NULL && authorization[0] != '\0')
	{
		ret = ESUCCESS;
	}

	if (ret == ECONTINUE)
	{
		if (authorization == NULL || authorization[0] == '\0')
		{
			authorization = httpmessage_REQUEST(request, (char *)str_authorization);
		}
		if (authorization == NULL || authorization[0] == '\0')
		{
			authorization = httpmessage_COOKIE(request, (char *)str_authorization);
		}
		if (mod->authn->ctx && authorization != NULL && !strncmp(authorization, mod->type, mod->typelength))
		{
			char *authentication = strchr(authorization, ' ');
			if (authentication)
				authentication++;
			char *method = httpmessage_REQUEST(request, "method");
			char *user = mod->authn->rules->check(mod->authn->ctx, method, authentication);
			if (user != NULL)
			{
				warn("user \"%s\" accepted from %p", user, ctx->ctl);
				httpmessage_SESSION(request, "%user", user);
				httpmessage_addheader(response, (char *)str_xuser, user);
				httpmessage_SESSION(request, "%authtype", (char *)mod->type);
				ret = EREJECT;

				if (mod->authz->rules->group)
				{
					char *group = mod->authz->rules->group(mod->authz->ctx, user);
					if (group)
					{
						httpmessage_SESSION(request, "%authgroup", group);
						httpmessage_addheader(response, (char *)str_xgroup, group);
					}
				}
				if (mod->authz->rules->home)
				{
					char *home = mod->authz->rules->home(mod->authz->ctx, user);
					if (home)
					{
						httpmessage_SESSION(request, "%authhome", home);
					}
				}
			}
		}
	}
	if (ret != EREJECT)
	{
		int length = CONTENTCHUNK;
		ret = mod->authn->rules->challenge(mod->authn->ctx, request, response);
		if (ret == ESUCCESS)
		{
			dbg("auth challenge failed");
			char *X_Requested_With = httpmessage_REQUEST(request, "X-Requested-With");
			if ((X_Requested_With && strstr(X_Requested_With, "XMLHttpRequest") != NULL))
			{
#if defined(RESULT_403)
				httpmessage_result(response, RESULT_403);
#elif defined(RESULT_401)
				httpmessage_result(response, RESULT_401);
#else
				httpmessage_result(response, RESULT_400);
#endif
			}
			else if (config->redirect)
			{
				httpmessage_addheader(response, str_location, config->redirect);
				httpmessage_result(response, RESULT_301);
			}
			else
			{
#if defined(RESULT_401)
				httpmessage_result(response, RESULT_401);
#else
				httpmessage_result(response, RESULT_400);
#endif
			}
		}
	}
	free(uri);
	return ret;
}
