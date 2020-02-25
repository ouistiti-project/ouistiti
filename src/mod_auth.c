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
#include <pwd.h>
#include <time.h>

#include "httpserver/httpserver.h"
#include "httpserver/utils.h"
#include "httpserver/hash.h"
#include "mod_auth.h"
#include "authn_none.h"
#ifdef AUTHN_BASIC
#include "authn_basic.h"
#endif
#ifdef AUTHN_DIGEST
#include "authn_digest.h"
#endif
#ifdef AUTHN_BEARER
#include "authn_bearer.h"
#endif
#ifdef AUTHN_OAUTH2
#include "authn_oauth2.h"
#endif
#include "authz_simple.h"
#include "authz_file.h"
#include "authz_unix.h"
#include "authz_sqlite.h"
#include "authz_jwt.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

#define auth_dbg(...)

#ifndef RESULT_401
#error mod_auth require RESULT_401
#endif

#ifdef DEBUG
#warning "debug mode in unsafe"
#endif

typedef struct _mod_auth_s _mod_auth_t;
typedef struct _mod_auth_ctx_s _mod_auth_ctx_t;

static void *_mod_auth_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize);
static void _mod_auth_freectx(void *vctx);
static int _home_connector(void *arg, http_message_t *request, http_message_t *response);
static int _authn_connector(void *arg, http_message_t *request, http_message_t *response);
static char *authz_generatetoken(mod_auth_t *mod, authsession_t *info);

static const char str_auth[] = "auth";
static const char str_cachecontrol[] = "Cache-Control";

struct _mod_auth_ctx_s
{
	_mod_auth_t *mod;
	http_client_t *ctl;
	char *authenticate;
	authsession_t *info;
	char *authorization;
};

struct _mod_auth_s
{
	mod_auth_t	*config;
	const char *type;
	authn_t *authn;
	authz_t *authz;
	int typelength;
};

const char str_authenticate[] = "WWW-Authenticate";
const char str_authorization[] = "Authorization";
const char str_anonymous[] = "anonymous";

static const char *str_xtoken = "X-Auth-Token";
static const char *str_xuser = "X-Remote-User";
static const char *str_xgroup = "X-Remote-Group";
static const char *str_xhome = "X-Remote-Home";
static const char *str_user = "USER";
static const char *str_group = "GROUP";
static const char *str_home = "HOME";
static const char *str_wilcard = "*";

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
#ifdef AUTHN_BEARER
	&authn_bearer_rules,
#else
	NULL,
#endif
#ifdef AUTHN_OAUTH2
	&authn_oauth2_rules,
#else
	NULL,
#endif
};

authz_rules_t *authz_rules[] = {
	NULL,
#ifdef AUTHZ_SIMPLE
	&authz_simple_rules,
#else
	NULL,
#endif
#ifdef AUTHZ_FILE
	&authz_file_rules,
#else
	NULL,
#endif
#ifdef AUTHZ_UNIX
	&authz_unix_rules,
#else
	NULL,
#endif
#ifdef AUTHZ_SQLITE
	&authz_sqlite_rules,
#else
	NULL,
#endif
#ifdef AUTHZ_JWT
	&authz_jwt_rules,
#else
	NULL,
#endif
};

static const hash_t *_mod_findhash(const char *name, int nameid)
{
	const hash_t *hash_list[] =
	{
		hash_md5,
		hash_sha1,
		hash_sha224,
		hash_sha256,
		hash_sha512,
		hash_macsha256,
		NULL
	};

	int i;
	static const hash_t *hash = NULL;
	for (i = 0; i < (sizeof(hash_list) / sizeof(*hash_list)); i++)
	{
		hash = hash_list[i];
		if (hash != NULL)
		{
			if ((name != NULL && !strcmp(name, hash->name)) ||
				(nameid == hash->nameid))
				break;
		}
	}
	return hash;
}

static int _mod_sethash(_mod_auth_t *mod, mod_auth_t *config)
{
	int ret = EREJECT;
	if (config->algo)
	{
		mod->authn->hash = _mod_findhash(config->algo, -1);
	}
	if (mod->authn->hash != NULL)
	{
		ret = ESUCCESS;
	}
	else if (mod->authn->hash == NULL && hash_sha256)
	{
		mod->authn->hash = hash_sha256;
		ret = ESUCCESS;
	}

	if (ret == EREJECT)
	{
		warn("auth: bad algorithm %s (%s | %s | %s | %s | %s)",
			config->algo,
			(hash_sha1?hash_sha1->name:""),
			(hash_sha224?hash_sha224->name:""),
			(hash_sha256?hash_sha256->name:""),
			(hash_sha512?hash_sha512->name:""),
			(hash_macsha256?hash_macsha256->name:""));
	}

	return ret;
}

void *mod_auth_create(http_server_t *server, mod_auth_t *config)
{
	_mod_auth_t *mod;

	srandom(time(NULL));

	if (!config)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = config;

	mod->authz = calloc(1, sizeof(*mod->authz));
	mod->authz->type = config->authz.type;
	mod->authz->name = config->authz.name;

	mod->authz->rules = authz_rules[config->authz.type & AUTHZ_TYPE_MASK];
	if (mod->authz->rules == NULL)
	{
		err("authentication storage not set, change configuration");
		free(mod->authz);
		free(mod);
		return NULL;
	}

#ifdef AUTHZ_JWT
	/**
	 * jwt token contains user information
	 * it is useless to "join" the token to the user.
	 */
	mod->authz->generatetoken = authz_generatejwtoken;
#else
	if ((config->authz.type & AUTHZ_TOKEN_E) &&  (authz_rules[config->authz.type & AUTHZ_TYPE_MASK])->join == NULL)
	{
		err("Please use other authz module (sqlite) to enable token");
		config->authz.type &= ~AUTHZ_TOKEN_E;
	}
	else
		mod->authz->generatetoken = authz_generatetoken;
#endif

	mod->authz->ctx = mod->authz->rules->create(config->authz.config);
	if (mod->authz->ctx == NULL)
	{
		free(mod->authz);
		free(mod);
		return NULL;
	}

	mod->authn = calloc(1, sizeof(*mod->authn));
	mod->authn->config = config;
	mod->authn->server = server;
	mod->authn->type = config->authn.type;
	mod->authn->rules = authn_rules[config->authn.type];

	_mod_sethash(mod, config);

	if (mod->authn->rules == NULL)
		err("authentication type is not availlable, change configuration");
	else
	{
		mod->authn->ctx = mod->authn->rules->create(mod->authn, mod->authz, config->authn.config);
	}
	if (mod->authn->ctx)
	{
		mod->type = config->authn.name;
		mod->typelength = strlen(mod->type);
		httpserver_addmod(server, _mod_auth_getctx, _mod_auth_freectx, mod, str_auth);
	}
	else
	{
		if (mod->authz->rules->destroy)
			mod->authz->rules->destroy(mod->authz->ctx);
		free(mod->authz);
		free(mod->authn);
		free(mod);
		mod = NULL;
	}

	if (mod != NULL && (!config->protect || config->protect[0] == '\0'))
	{
		config->protect = str_wilcard;
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

	if (mod->authz->type & AUTHZ_HOME_E)
		httpclient_addconnector(ctl, _home_connector, ctx, CONNECTOR_AUTH, str_auth);
	httpclient_addconnector(ctl, _authn_connector, ctx, CONNECTOR_AUTH, str_auth);
	/**
	 * authn may require prioritary connector and it has to be added after this one
	 */
	if(mod->authn->rules->setup)
		mod->authn->rules->setup(mod->authn->ctx, ctl, addr, addrsize);

	return ctx;
}

static void _mod_auth_freectx(void *vctx)
{
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)vctx;
	if (ctx->info)
	{
		if (ctx->info->token)
			free(ctx->info->token);
		free(ctx->info);
		if (ctx->authorization)
			free(ctx->authorization);
	}
	free(ctx->authenticate);
	free(ctx);
}

static int _home_connector(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)arg;
	int ret = EREJECT;
	const authsession_t *info = httpmessage_SESSION(request, str_auth, NULL);

	if (info)
	{
		const char *home = info->home;
		/**
		 * disable home redirection for websocket
		 */
		const char *websocket = httpmessage_REQUEST(request, "Sec-WebSocket-Version");
		if (websocket && websocket[0] != '\0')
			return ret;
		const char *uri = httpmessage_REQUEST(request, "uri");
		int homelength = strlen(home);
		if ((homelength > 0) &&
			(strncmp(home + 1, uri, homelength - 1) != 0))
		{
			dbg("redirect the url to home %s", home);
#if defined(RESULT_301)
			httpmessage_addheader(response, str_location, home);
			httpmessage_appendheader(response, str_location, "/", NULL);
			httpmessage_result(response, RESULT_301);
			ret = ESUCCESS;
#endif
		}
	}
	return ret;
}

int authz_checkpasswd(const char *checkpasswd, const char *user, const char *realm, const char *passwd)
{
	int ret = EREJECT;
	dbg("auth: check %s %s", passwd, checkpasswd);
	if (checkpasswd[0] == '$')
	{
		const hash_t *hash = NULL;
		int i = 1;
		int a1decode = 0;
		if (checkpasswd[i] == 'a')
		{
			a1decode = 1;
			i++;
		}

		hash = _mod_findhash(NULL, checkpasswd[i]);
		if (hash)
		{
			char hashpasswd[32];
			void *ctx;
			int length;

			ctx = hash->init();
			checkpasswd = strchr(checkpasswd+1, '$');
			if (a1decode)
			{
				if (realm != NULL && strncmp(checkpasswd, realm, strlen(realm)))
				{
					err("auth: realm error in password");
					// return ret;
				}
				realm = strstr(checkpasswd, "realm=");
			}
			if (realm)
			{
				realm += 6;
				int length = strchr(realm, '$') - realm;
				hash->update(ctx, user, strlen(user));
				hash->update(ctx, ":", 1);
				hash->update(ctx, realm, length);
				hash->update(ctx, ":", 1);
			}
			hash->update(ctx, passwd, strlen(passwd));
			hash->finish(ctx, hashpasswd);
			char b64passwd[50];
			base64->encode(hashpasswd, hash->size, b64passwd, 50);

			checkpasswd = strrchr(checkpasswd, '$');
			if (checkpasswd)
			{
				checkpasswd++;
				auth_dbg("auth: check %s %s", b64passwd, checkpasswd);
				if (!strcmp(b64passwd, checkpasswd))
					ret = ESUCCESS;
			}
		}
		else
			err("auth: %.3s not supported change password encryption", checkpasswd);
	}
	else if (!strcmp(passwd, checkpasswd))
	{
		ret = ESUCCESS;;
	}
	return ret;
}

static authsession_t *_authn_setsession(_mod_auth_t *mod, const char * user)
{
	authsession_t *info = NULL;

	info = calloc(1, sizeof(*info));
	strncpy(info->user, user, sizeof(info->user));
	strncpy(info->type, mod->type, sizeof(info->type));
	if (mod->authz->rules->group)
	{
		const char *group = NULL;
		group = mod->authz->rules->group(mod->authz->ctx, user);
		if (group)
			strncpy(info->group, group, sizeof(info->group));
	}
	if (mod->authz->rules->home)
	{
		const char *home = NULL;
		home = mod->authz->rules->home(mod->authz->ctx, user);
		if (home)
			strncpy(info->home, home, sizeof(info->home));
	}
	if (mod->authz->rules->token)
	{
		char *token = NULL;
		token = mod->authz->rules->token(mod->authz->ctx, user);
		if (token)
			info->token = token;
	}
	return info;
}

char *authz_generatetoken(mod_auth_t *config, authsession_t *info)
{
	int tokenlen = (((24 + 1 + sizeof(time_t)) * 1.5) + 1) + 1;
	char *token = calloc(1, tokenlen);
	char _nonce[(24 + 1 + sizeof(time_t))];
	int i;
	for (i = 0; i < (24 / sizeof(int)); i++)
	{
		*(int *)(_nonce + i * 4) = random();
	}
	_nonce[24] = '.';
	time_t expire = (config->expire * 60);
	if (expire == 0)
		expire = 60 * 30;
	expire += time(NULL);
	memcpy(&_nonce[25], &expire, sizeof(time_t));
	int ret = 0;
	ret = base64_urlencoding->encode(_nonce, 24, token, tokenlen);
	return token;
}

#ifdef AUTH_TOKEN
static const char *_authn_gettoken(_mod_auth_ctx_t *ctx, http_message_t *request)
{
	_mod_auth_t *mod = ctx->mod;
	const char *authorization = NULL;
	/**
	 * The authorization may be accepted and replaced by a token.
	 * This token is available inside the cookie.
	 */
	if (mod->authz->type & AUTHZ_HEADER_E)
	{
		authorization = httpmessage_REQUEST(request, str_xtoken);
	}
	else
	{
		authorization = cookie_get(request, str_xtoken);
	}
	return authorization;
}

int authn_checksignature(const char *key,
		const char *data, int datalen,
		const char *sign, int signlen)
{
	if (hash_macsha256 != NULL && key != NULL)
	{
		void *ctx = hash_macsha256->initkey(key, strlen(key));
		if (ctx)
		{
			hash_macsha256->update(ctx, data, datalen);
			char signature[HASH_MAX_SIZE];
			int signlen = hash_macsha256->finish(ctx, signature);
			char b64signature[(int)(HASH_MAX_SIZE * 1.5) + 1];
			base64_urlencoding->encode(signature, signlen, b64signature, sizeof(b64signature));
			if (!strncmp(b64signature, sign, signlen))
				return ESUCCESS;
		}
	}
	return EREJECT;
}

int authn_checktoken(_mod_auth_ctx_t *ctx, const char *token)
{
	int ret = ECONTINUE;
	_mod_auth_t *mod = ctx->mod;

	const char *string = token;
	const char *user = NULL;
	const char *data = string;
	const char *sign = strrchr(string, '.');
	if (sign != NULL)
	{
		int datalen = sign - data;
		sign++;
		if (authn_checksignature(mod->authn->config->secret, data, datalen, sign, strlen(sign)) == ESUCCESS)
		{
			user = mod->authz->rules->check(mod->authz->ctx, NULL, NULL, string);
			if (user == NULL)
			{
				user = str_anonymous;
			}
			if (ctx->info == NULL)
			{
				ctx->info = _authn_setsession(mod, user);
			}
			if (ctx->info->token == NULL)
			{
				ctx->info->token = strdup(string);
				char *sign = strrchr(ctx->info->token, '.');
				if (sign != NULL)
					sign[0] = '\0';
			}
			ret = EREJECT;
		}
	}
	return ret;
}
#endif

static const char *_authn_getauthorization(_mod_auth_ctx_t *ctx, http_message_t *request)
{
	_mod_auth_t *mod = ctx->mod;
	const char *authorization = NULL;
	/**
	 * with standard authentication, the authorization code
	 * is sended info header
	 */
	if (authorization == NULL || authorization[0] == '\0')
	{
		authorization = httpmessage_REQUEST(request, str_authorization);
	}
	/**
	 * to send the authorization header only once, the "cookie"
	 * option of the server store the authorization inside cookie.
	 * This method allow to use little client which manage only cookie.
	 */
	if (authorization == NULL || authorization[0] == '\0')
	{
		authorization = cookie_get(request, str_authorization);
		err("cookie get %s %p",str_authorization, authorization);
	}

	if (authorization != NULL && strncmp(authorization, mod->type, mod->typelength))
	{
		err("authorization type: %.*s, %.*s", mod->typelength, authorization, mod->typelength, mod->type);
		authorization = NULL;
	}
	return authorization;
}

typedef void (*_httpmessage_set)(http_message_t *, const char *, const char *);
typedef int (*_httpmessage_append)(http_message_t *, const char *, const char *, ...);
static void _authn_cookie_set(http_message_t *request, const char *key, const char *value)
{
	/**
	 * this facade allows to extend the parameters
	 */
	cookie_set(request, key, value, NULL);
}

static int _authn_setauthorization(_mod_auth_ctx_t *ctx,
			const char *authorization, authsession_t *info,
			_httpmessage_set httpmessage_set, _httpmessage_append httpmessage_append,
			http_message_t *response)
{
#ifdef AUTH_TOKEN
	if (info->token)
	{
		const char *key = ctx->mod->config->secret;
		if (hash_macsha256 != NULL && key != NULL)
		{
			void *ctx = hash_macsha256->initkey(key, strlen(key));
			if (ctx)
			{
				hash_macsha256->update(ctx, info->token, strlen(info->token));
				char signature[HASH_MAX_SIZE];
				int signlen = hash_macsha256->finish(ctx, signature);
				char b64signature[(int)(HASH_MAX_SIZE * 1.5) + 1];
				base64_urlencoding->encode(signature, signlen, b64signature, sizeof(b64signature));
				httpmessage_append(response, str_xtoken, info->token, ".", b64signature, NULL);
			}
		}
		else
			httpmessage_set(response, str_xtoken, info->token);
	}
	else
#endif
	if (authorization != NULL)
	{
		httpmessage_set(response, str_authorization, authorization);
	}
	httpmessage_set(response, str_xuser, info->user);
	if (info->group)
		httpmessage_set(response, str_xgroup, info->group);
	if (info->home)
		httpmessage_set(response, str_xhome, "~/");
	return ESUCCESS;
}

static int _authn_checkauthorization(_mod_auth_ctx_t *ctx,
		const char *authorization, http_message_t *request)
{
	int ret = ECONTINUE;
	_mod_auth_t *mod = ctx->mod;
	mod_auth_t *config = mod->config;
	const char *authentication = strchr(authorization, ' ');
	const char *method = httpmessage_REQUEST(request, "method");
	const char *uri = httpmessage_REQUEST(request, "uri");

	if (authentication)
		authentication++;
	else
		authentication = authorization;
	/**
	 * The current authentication is made by the client (the browser).
	 * In this case the client compute the autorization for each file to download.
	 * With redirection to the login page, all files should contain the code
	 * to compute the autorizarion. But it is impossible to do it. Then
	 * only the method HEAD is used to login and the client must send
	 * same autorization for all files to download.
	 * WARNING: It is incorrect to use this method for security.
	 * The autorization is always acceptable and it is dangerous.
	 */
	if (config->redirect)
		method = str_head;
	const char *user = mod->authn->rules->check(mod->authn->ctx, method, uri, authentication);
	if (user != NULL)
	{
		if (ctx->info == NULL)
		{
			ctx->info = _authn_setsession(mod, user);
			ctx->authorization = strdup(authorization);
		}

#ifdef AUTH_TOKEN
		if (mod->authz->type & AUTHZ_TOKEN_E && ctx->info->token == NULL)
		{
			char *token = mod->authz->generatetoken(mod->config, ctx->info);
			if (mod->authz->rules->join)
				mod->authz->rules->join(mod->authz->ctx, ctx->info->user, token, mod->config->expire);
			ctx->info->token = token;
		}
#endif
		warn("user \"%s\" accepted from %p", user, ctx->ctl);
		ret = EREJECT;
	}
	return ret;
}

static int _authn_challenge(_mod_auth_ctx_t *ctx, http_message_t *request, http_message_t *response)
{
	int ret = ECONTINUE;
	_mod_auth_t *mod = ctx->mod;
	mod_auth_t *config = mod->config;
	const char *uri = httpmessage_REQUEST(request, "uri");


	ret = mod->authn->rules->challenge(mod->authn->ctx, request, response);
	if (ret == ECONTINUE)
	{
		ret = ESUCCESS;
		auth_dbg("auth challenge failed");
		const char *X_Requested_With = httpmessage_REQUEST(request, "X-Requested-With");
		if (X_Requested_With && strstr(X_Requested_With, "XMLHttpRequest") != NULL)
		{
			httpmessage_result(response, RESULT_403);
		}
		else if (config->redirect)
		{
			int protect = 1;
			/**
			 * check the url redirection
			 */
			const char *redirect = strstr(config->redirect, "://");
			if (redirect != NULL)
			{
				redirect += 3;
				redirect = strchr(redirect, '/');
			}
			else
				redirect = config->redirect;
			if (redirect[0] == '/')
				redirect++;
			protect = utils_searchexp(uri, redirect, NULL);
			if (protect == ESUCCESS)
			{
				/**
				 * the request URI is the URL of the redirection
				 * the authentication has to accept (this module
				 * reject to manage the request and another module
				 * should send response to the request0.
				 */
				httpmessage_result(response, RESULT_200);
				ret = EREJECT;
			}
			else
			{
				httpmessage_addheader(response, str_location, config->redirect);
				httpmessage_addheader(response, str_cachecontrol, "no-cache");
				httpmessage_result(response, RESULT_302);
			}
		}
		else
		{
			httpmessage_result(response, RESULT_401);
		}
	}
	return ret;
}

static int _authn_checkuri(mod_auth_t *config, http_message_t *request)
{
	const char *uri = httpmessage_REQUEST(request, "uri");
	int ret = ECONTINUE;
	int protect = 1;
	/**
	 * check uri
	 */
	protect = utils_searchexp(uri, config->unprotect, NULL);
	if (protect == ESUCCESS)
	{
		ret = EREJECT;
	}
	protect = utils_searchexp(uri, config->protect, NULL);
	if (protect == ESUCCESS)
	{
		ret = ECONTINUE;
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

	/**
	 * If ctx->info is set, this connection has been already authenticated.
	 * It is useless to authenticate again.
	 */
	if (ctx->info != NULL)
	{
		ret = EREJECT;
	}

	/**
	 * The header WWW-Authenticate inside the request
	 * allows to disconnect the user.
	 */
	authorization = httpmessage_REQUEST(request, str_authenticate);
	if (ret == ECONTINUE && authorization != NULL && authorization[0] != '\0')
	{
		ret = ESUCCESS;
	}

#ifdef AUTH_TOKEN
	if (ret == ECONTINUE && mod->authz->type & AUTHZ_TOKEN_E)
	{
		authorization = _authn_gettoken(ctx, request);
		if (mod->authn->ctx && authorization != NULL)
		{
			const char *string = authorization;
			int fieldnamelen = strlen(str_xtoken);
			if (!strncmp(string, str_xtoken, fieldnamelen))
			{
				string += fieldnamelen + 1; // +1 for the tailing '='
			}
			ret = authn_checktoken( ctx, string);
		}
	}
#endif
	if (ret == ECONTINUE)
	{
		authorization = _authn_getauthorization(ctx, request);
		if (mod->authn->ctx && authorization != NULL)
		{
			ret = _authn_checkauthorization( ctx, authorization, request);
		}
	}

	if (ret != EREJECT)
		ret = _authn_checkuri(config, request);

	if (ret != EREJECT)
	{
		ret = _authn_challenge(ctx, request, response);
	}
	else
	{
		httpmessage_SESSION(request, str_auth, ctx->info);
		if (ctx->info && mod->authz->type & AUTHZ_HEADER_E)
		{
			_authn_setauthorization(ctx,
					authorization, ctx->info,
					httpmessage_addheader, httpmessage_appendheader,
					response);
		}
		else if (ctx->info && mod->authz->type & AUTHZ_COOKIE_E)
		{
			_authn_setauthorization(ctx,
					authorization, ctx->info,
					_authn_cookie_set, cookie_set,
					response);
		}

		if (mod->authz->type & AUTHZ_CHOWN_E)
		{
			auth_setowner(ctx->info->user);
		}
	}
	return ret;
}

const module_t mod_auth =
{
	.name = str_auth,
	.create = (module_create_t)&mod_auth_create,
	.destroy = &mod_auth_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_auth")));
#endif
