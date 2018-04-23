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
#include "httpserver/hash.h"
#include "mod_auth.h"
#include "authn_none.h"
#include "authn_basic.h"
#include "authn_digest.h"
#include "authz_simple.h"
#include "authz_file.h"
#include "authz_unix.h"
#include "authz_sqlite.h"

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

typedef struct authsession_s
{
	char *type;
	char *user;
	char *group;
	char *home;
} authsession_t;

struct _mod_auth_ctx_s
{
	_mod_auth_t *mod;
	http_client_t *ctl;
	char *authenticate;
	authsession_t *info;
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
#ifdef AUTHZ_SQLITE
	case AUTHZ_SQLITE_E:
		mod->authz->rules = &authz_sqlite_rules;
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
	if (config->algo)
	{
		if (hash_sha1 && !strcmp(config->algo, hash_sha1->name))
		{
			mod->authn->hash = hash_sha1;
		}
		if (hash_sha224 && !strcmp(config->algo, hash_sha224->name))
		{
			mod->authn->hash = hash_sha224;
		}
		if (hash_sha256 && !strcmp(config->algo, hash_sha256->name))
		{
			mod->authn->hash = hash_sha256;
		}
		if (hash_sha512 && !strcmp(config->algo, hash_sha512->name))
		{
			mod->authn->hash = hash_sha512;
		}
		dbg("auth : use %d as hash method", config->algo);
	}
	if (mod->authn->hash == NULL && hash_md5)
	{
		dbg("auth : use default md5 as hash method");
		mod->authn->hash = hash_md5;
	}
	mod->authn->rules = authn_rules[config->authn_type];
	if (mod->authn->rules && mod->authz->rules)
	{
		mod->authn->ctx = mod->authn->rules->create(mod->authn, mod->authz, config->authn_config);
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
	if (ctx->info)
	{
		if (ctx->info->user)
			free(ctx->info->user);
		if (ctx->info->type)
			free(ctx->info->type);
		if (ctx->info->group)
			free(ctx->info->group);
		if (ctx->info->home)
			free(ctx->info->home);
		free(ctx->info);
	}
	free(ctx->authenticate);
	free(ctx);
}

static int _home_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	const authsession_t *info = httpmessage_SESSION(request, str_auth, NULL);
	if (info)
	{
		const char *home = info->home;
		const char *websocket = httpmessage_REQUEST(request, "Sec-WebSocket-Version");
		if (websocket && websocket[0] != '\0')
			return ret;
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

static int _authn_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = ECONTINUE;
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)arg;
	_mod_auth_t *mod = ctx->mod;
	mod_auth_t *config = mod->config;
	const char *authorization = NULL;
	const char *uriencoded = httpmessage_REQUEST(request, "uri");
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
		int cookie = 0;
		if (authorization == NULL || authorization[0] == '\0')
		{
			authorization = httpmessage_REQUEST(request, (char *)str_authorization);
		}
		if (authorization == NULL || authorization[0] == '\0')
		{
			authorization = cookie_get(request, (char *)str_authorization);
			if (authorization)
			{
				authorization = strchr(authorization, '=') + 1;
				cookie = 1;
			}
		}
		if (mod->authn->ctx && authorization != NULL && !strncmp(authorization, mod->type, mod->typelength))
		{
			char *authentication = strchr(authorization, ' ');
			if (authentication)
				authentication++;
			const char *method = httpmessage_REQUEST(request, "method");
			const char *uri = httpmessage_REQUEST(request, "uri");
			char *user = mod->authn->rules->check(mod->authn->ctx, method, uri, authentication);
			if (user != NULL)
			{
				authsession_t *info = NULL;
				info = ctx->info;
				if (info == NULL)
				{
					char *group = NULL;
					char *home = NULL;
					if (mod->authz->rules->group)
						group = mod->authz->rules->group(mod->authz->ctx, user);
					if (mod->authz->rules->home)
						home = mod->authz->rules->home(mod->authz->ctx, user);

					info = calloc(1, sizeof(*info));
					info->user = calloc(strlen(user) + 1, sizeof(char));
					strcpy(info->user, user);
					info->type = calloc(strlen(mod->type) + 1, sizeof(char));
					strcpy(info->type, mod->type);
					if (group)
					{
						info->group = calloc(strlen(group) + 1, sizeof(char));
						strcpy(info->group, group);
					}
					if (home)
					{
						info->home = calloc(strlen(home) + 1, sizeof(char));
						strcpy(info->home, home);
					}
					ctx->info = info;
					httpmessage_SESSION(request, str_auth, info);
					httpmessage_addheader(response, str_xuser, user);
					if (group)
						httpmessage_addheader(response, str_xgroup, group);
					cookie_set(request, str_authorization, (char *)authorization);
				}
				warn("user \"%s\" accepted from %p", user, ctx->ctl);
				ret = EREJECT;
			}
		}
	}
	if (ret != EREJECT)
	{
		ret = mod->authn->rules->challenge(mod->authn->ctx, request, response);
		if (ret == ESUCCESS)
		{
			dbg("auth challenge failed");
			const char *X_Requested_With = httpmessage_REQUEST(request, "X-Requested-With");
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

const char *auth_info(http_message_t *request, const char *key)
{
	const authsession_t *info = NULL;
	info = httpmessage_SESSION(request, str_auth, NULL);
	const char *value = NULL;

	if (info && !strcmp(key, "user"))
		value = (const char *)info->user;
	if (info && !strcmp(key, "group"))
		value = (const char *)info->group;
	if (info && !strcmp(key, "type"))
		value = (const char *)info->type;
	if (info && !strcmp(key, "home"))
		value = (const char *)info->home;
	return value;
}
