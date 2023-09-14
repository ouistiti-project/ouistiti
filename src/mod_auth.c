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

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/hash.h"
#include "ouistiti/log.h"
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

#define auth_dbg(...)

#ifndef RESULT_401
#error mod_auth require RESULT_401
#endif
#ifndef RESULT_403
#error mod_auth require RESULT_403
#endif

#ifdef DEBUG
#warning "debug mode in unsafe"
#endif

typedef struct _mod_auth_s _mod_auth_t;
typedef struct _mod_auth_ctx_s _mod_auth_ctx_t;

static void *_mod_auth_getctx(void *arg, http_client_t *clt, struct sockaddr *addr, int addrsize);
static void _mod_auth_freectx(void *vctx);
static int _home_connector(void *arg, http_message_t *request, http_message_t *response);
static int _authn_connector(void *arg, http_message_t *request, http_message_t *response);
#ifndef AUTHZ_JWT
static char *authz_generatetoken(const mod_auth_t *mod, const authsession_t *info);
#endif

static const char str_auth[] = "auth";

struct _mod_auth_ctx_s
{
	_mod_auth_t *mod;
	http_client_t *clt;
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
	size_t typelength;
};

const char str_authenticate[] = "WWW-Authenticate";
const char str_authorization[] = "Authorization";
const char str_anonymous[] = "anonymous";

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

	static const hash_t *hash = NULL;
	for (int i = 0; i < (sizeof(hash_list) / sizeof(*hash_list)); i++)
	{
		hash = hash_list[i];
		if (hash != NULL &&
			((name != NULL && !strcmp(name, hash->name)) ||
				(nameid == hash->nameid)))
			break;
	}
	return hash;
}

static int _mod_sethash(const _mod_auth_t *mod, const mod_auth_t *config)
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

#ifdef FILE_CONFIG
struct _authn_s
{
	void *(*config)(const config_setting_t *);
	authn_type_t type;
	const char *name;
};

struct _authn_s *authn_list[] =
{
#ifdef AUTHN_BASIC
	&(struct _authn_s){
		.config = &authn_basic_config,
		.type = AUTHN_BASIC_E,
		.name = "Basic",
	},
#endif
#ifdef AUTHN_DIGEST
	&(struct _authn_s){
		.config = &authn_digest_config,
		.type = AUTHN_DIGEST_E,
		.name = "Digest",
	},
#endif
#ifdef AUTHN_BEARER
	&(struct _authn_s){
		.config = &authn_bearer_config,
		.type = AUTHN_BEARER_E | AUTHN_REDIRECT_E,
		.name = "Bearer",
	},
#endif
#ifdef AUTHN_OAUTH2
	&(struct _authn_s){
		.config = &authn_oauth2_config,
		.type = AUTHN_OAUTH2_E | AUTHN_REDIRECT_E,
		.name = "oAuth2",
	},
#endif
#ifdef AUTHN_NONE
	&(struct _authn_s){
		.config = &authn_none_config,
		.type = AUTHN_NONE_E,
		.name = "None",
	},
#endif
};

static int authn_config(const config_setting_t *configauth, mod_authn_t *mod)
{
	int ret = EREJECT;

	char *type = NULL;
	config_setting_lookup_string(configauth, "type", (const char **)&type);
	if (type == NULL)
	{
		return ret;
	}

	const struct _authn_s *authn = NULL;
	for (int i = 0; i < (sizeof(authn_list) / sizeof(*authn_list)); i++)
	{
		if (!strcmp(type, authn_list[i]->name))
			mod->config = authn_list[i]->config(configauth);
		if (mod->config != NULL)
		{
			authn = authn_list[i];
			break;
		}
	}

	if (authn != NULL)
	{
		mod->type |= authn->type;
		mod->name = authn->name;
		ret = ESUCCESS;
	}
	return ret;
}


struct _authz_s
{
	void *(*config)(const config_setting_t *);
	authz_type_t type;
	const char *name;
};

struct _authz_s *authz_list[] =
{
#ifdef AUTHZ_UNIX
	&(struct _authz_s){
		.config = &authz_unix_config,
		.type = AUTHZ_UNIX_E,
		.name = "unix",
	},
#endif
#ifdef AUTHZ_FILE
	&(struct _authz_s){
		.config = &authz_file_config,
		.type = AUTHZ_FILE_E,
		.name = "file",
	},
#endif
#ifdef AUTHZ_SQLITE
	&(struct _authz_s){
		.config = &authz_sqlite_config,
		.type = AUTHZ_SQLITE_E,
		.name = "sqlite",
	},
#endif
#ifdef AUTHZ_SIMPLE
	&(struct _authz_s){
		.config = &authz_simple_config,
		.type = AUTHZ_SIMPLE_E,
		.name = "simple",
	},
#endif
#ifdef AUTHZ_JWT
	&(struct _authz_s){
		.config = &authz_jwt_config,
		.type = AUTHZ_JWT_E,
		.name = "jwt",
	},
#endif
};

static void authz_optionscb(void *arg, const char *option)
{
	mod_auth_t *auth = (mod_auth_t *)arg;

	if (utils_searchexp("home", option, NULL) == ESUCCESS)
		auth->authz.type |= AUTHZ_HOME_E;
	if (utils_searchexp("token", option, NULL) == ESUCCESS)
		auth->authz.type |= AUTHZ_TOKEN_E;
	if (utils_searchexp("chown", option, NULL) == ESUCCESS)
		auth->authz.type |= AUTHZ_CHOWN_E;
	if (utils_searchexp("management", option, NULL) == ESUCCESS)
		auth->authz.type |= AUTHZ_MNGT_E;

	if (utils_searchexp("cookie", option, NULL) == ESUCCESS)
		auth->authn.type |= AUTHN_COOKIE_E;
	if (utils_searchexp("header", option, NULL) == ESUCCESS)
		auth->authn.type |= AUTHN_HEADER_E;
	if (utils_searchexp("redirect", option, NULL) == ESUCCESS)
		auth->authn.type |= AUTHN_REDIRECT_E;
}

static int authz_config(const config_setting_t *configauth, mod_authz_t *mod)
{
	int ret = EREJECT;
	const struct _authz_s *authz = NULL;
	for (int i = 0; i < (sizeof(authz_list) / sizeof(*authz_list)); i++)
	{
		if (authz_list[i]->config != NULL)
			mod->config = authz_list[i]->config(configauth);
		if (mod->config != NULL)
		{
			authz = authz_list[i];
			break;
		}
	}
	if (authz != NULL)
	{
		mod->type |= authz->type;
		mod->name = authz->name;
		ret = ESUCCESS;
	}
	return ret;
}

static void *auth_config(config_setting_t *iterator, server_t *server)
{
	mod_auth_t *auth = NULL;
#if LIBCONFIG_VER_MINOR < 5
	const config_setting_t *configauth = config_setting_get_member(iterator, "auth");
#else
	const config_setting_t *configauth = config_setting_lookup(iterator, "auth");
#endif
	if (configauth)
	{
		auth = calloc(1, sizeof(*auth));
		/**
		 * signin URI allowed to access to the signin page
		 */
		config_setting_lookup_string(configauth, "signin", &auth->redirect);
		if (auth->redirect == NULL || auth->redirect[0] == '\0')
			config_setting_lookup_string(configauth, "token_ep", &auth->redirect);
		config_setting_lookup_string(configauth, "protect", &auth->protect);
		config_setting_lookup_string(configauth, "unprotect", &auth->unprotect);
		/**
		 * algorithm allow to change secret algorithm used during authentication default is md5. (see authn_digest.c)
		 */
		config_setting_lookup_string(configauth, "algorithm", &auth->algo);
		/**
		 * secret is the secret used during the token generation. (see authz_jwt.c)
		 */
		config_setting_lookup_string(configauth, "secret", &auth->secret);

		const char *mode = NULL;
		config_setting_lookup_string(configauth, "options", &mode);
		if (ouistiti_issecure(server))
			auth->authz.type |= AUTHZ_TLS_E;
		if (mode != NULL)
		{
			authz_optionscb(auth, mode);
		}
		config_setting_lookup_int(configauth, "expire", &auth->expire);

		int ret;
		ret = authz_config(configauth, &auth->authz);
		if (ret == EREJECT)
		{
			err("config: authz is not set");
		}

		ret = authn_config(configauth, &auth->authn);
		if (ret == EREJECT)
		{
			err("config: authn type is not set");
		}
	}
	return auth;
}
#else
static const mod_auth_t g_auth_config =
{
	.authz = &(mod_authz_t){
		.config = &(authz_sqlite_config_t){
			.dbname = "/etc/ouistiti/auth.db",
		},
		.type = AUTHZ_SQLITE_E,
		.name = "sqlite",
	},
	.authn = &(mod_authn_t){
		.config = &(authn_basic_config_t){
			.realm = NULL,
		},
		.type = AUTHN_BASIC_E,
		.name = "Basic",
	},
};

static void *auth_config(void *iterator, server_t *server)
{
	return (void *)&g_auth_config;
}
#endif

static void *mod_auth_create(http_server_t *server, mod_auth_t *config)
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

	mod->authz->ctx = mod->authz->rules->create(server, config->authz.config);
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
	mod->authn->rules = authn_rules[config->authn.type & AUTHN_TYPE_MASK];

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
		if (mod != NULL && (config->authz.type & AUTHZ_TOKEN_E) &&
			(mod->authn->config->secret == NULL || strlen(mod->authn->config->secret) == 0))
		{
			err("auth: to enable the token, set the \"secret\" into configuration");
		}
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

	return mod;
}

static void mod_auth_destroy(void *arg)
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
#ifdef FILE_CONFIG
	free(mod->config);
#endif
	free(mod);
}

static void *_mod_auth_getctx(void *arg, http_client_t *clt, struct sockaddr *addr, int addrsize)
{
	_mod_auth_ctx_t *ctx = calloc(1, sizeof(*ctx));
	_mod_auth_t *mod = (_mod_auth_t *)arg;

	ctx->mod = mod;
	ctx->clt = clt;

	if (mod->authz->type & AUTHZ_HOME_E)
		httpclient_addconnector(clt, _home_connector, ctx, CONNECTOR_AUTH, str_auth);
	httpclient_addconnector(clt, _authn_connector, ctx, CONNECTOR_AUTH, str_auth);
	/**
	 * authn may require prioritary connector and it has to be added after this one
	 */
	if(mod->authn->rules->setup)
		mod->authn->rules->setup(mod->authn->ctx, clt, addr, addrsize);

	return ctx;
}

static void _mod_auth_freectx(void *vctx)
{
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)vctx;

	if (ctx->info)
	{
		free(ctx->info);
		if (ctx->authorization)
			free(ctx->authorization);
	}
	free(ctx->authenticate);
	free(ctx);
}

static int _home_connector(void *UNUSED(arg), http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	const authsession_t *info = httpmessage_SESSION(request, str_auth, NULL, 0);

	if (info && info->home)
	{
		const char *home = info->home;
		/**
		 * disable home redirection for websocket
		 */
		const char *websocket = httpmessage_REQUEST(request, "Sec-WebSocket-Version");
		if (websocket && websocket[0] != '\0')
			return ret;
		const char *uri = httpmessage_REQUEST(request, "uri");
		size_t homelength = strlen(home);
		if ((homelength > 0) &&
			(strncmp(home + 1, uri, homelength - 1) != 0))
		{
			dbg("redirect the url to home %s", home);
#if defined(RESULT_301)
			httpmessage_addheader(response, str_location, home, -1);
			httpmessage_appendheader(response, str_location, STRING_REF("/"));
			httpmessage_result(response, RESULT_301);
			ret = ESUCCESS;
#endif
		}
	}
	return ret;
}

static int _authz_computepasswd(const hash_t *hash, const char *user, const char *realm, const char *passwd,
			char *string, int stringlen)
{
	char hashpasswd[32];
	void *ctx;

	ctx = hash->init();
	if (realm)
	{
		hash->update(ctx, user, strlen(user));
		hash->update(ctx, ":", 1);
		hash->update(ctx, realm, strlen(realm));
		hash->update(ctx, ":", 1);
	}
	hash->update(ctx, passwd, strlen(passwd));
	hash->finish(ctx, hashpasswd);

	int length = base64->encode(hashpasswd, hash->size, string, stringlen);
	return length;
}

int authz_checkpasswd(const char *checkpasswd, const char *user, const char *realm, const char *passwd)
{
	int ret = EREJECT;
	auth_dbg("auth: check %s %s", passwd, checkpasswd);
	if (checkpasswd[0] == '$')
	{
		const hash_t *hash = NULL;
		char hashtype = checkpasswd[1];
		if (checkpasswd[1] == 'a')
		{
			hashtype = checkpasswd[2];
		}
		const char *checkrealm = NULL;
		int realmlength = 0;
		/**
		 * If the realm is linked to the password,
		 * it must be the same as the requested realm.
		 * If no realm is available with the password,
		 * we check directly the password
		 */
		checkrealm = strstr(checkpasswd, "realm=");
		if (checkrealm)
		{
			checkrealm += 6;
			realmlength = strpbrk(checkrealm, ";$") - checkrealm - 1;
			if (strncmp(checkrealm, realm, realmlength))
				return ret;
		}
		else
			realm = NULL;

		hash = _mod_findhash(NULL, hashtype);

		checkpasswd = strrchr(checkpasswd + 1, '$');
		if (checkpasswd)
			checkpasswd++;
		if (hash && checkpasswd)
		{
			char b64passwd[50] = {0};
			int length = _authz_computepasswd(hash, user, realm, passwd, b64passwd, sizeof(b64passwd));

			auth_dbg("auth: check %s %s", b64passwd, checkpasswd);
			if (!strncmp(b64passwd, checkpasswd, length))
				ret = ESUCCESS;
		}
		else
			err("auth: %.3s not supported change password encryption", checkpasswd);
	}
	else if (!strcmp(passwd, checkpasswd))
	{
		ret = ESUCCESS;
	}
	return ret;
}

#ifndef AUTHZ_JWT
static char *authz_generatetoken(const mod_auth_t *config, const authsession_t *UNUSED(info))
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
	base64_urlencoding->encode(_nonce, 24, token, tokenlen);
	return token;
}
#endif

#ifdef AUTH_TOKEN
static const char *_authn_gettoken(const _mod_auth_ctx_t *ctx, http_message_t *request)
{
	const _mod_auth_t *mod = ctx->mod;
	const char *authorization = NULL;
	/**
	 * The authorization may be accepted and replaced by a token.
	 * This token is available inside the cookie.
	 */
	if (mod->authn->type & AUTHN_HEADER_E)
	{
		authorization = httpmessage_REQUEST(request, str_xtoken);
		if (authorization != NULL && authorization[0] != '\0')
		{
			auth_dbg("token from headers");
			return authorization;
		}
	}

	authorization = cookie_get(request, str_xtoken);
	if (authorization != NULL && authorization[0] != '\0')
	{
		auth_dbg("token from cookie");
		return authorization;
	}
	return NULL;
}

int authn_checksignature(const char *key,
		const char *data, size_t datalen,
		const char *sign, size_t signlen)
{
	if (hash_macsha256 != NULL && key != NULL)
	{
		void *ctx = hash_macsha256->initkey(key, strlen(key));
		if (ctx)
		{
			hash_macsha256->update(ctx, data, datalen);
			char signature[HASH_MAX_SIZE];
			size_t len = hash_macsha256->finish(ctx, signature);
			if (signlen < len)
			{
				err("auth: signature buffer too small");
				len = signlen / 3 * 2;
			}
			char b64signature[(int)(HASH_MAX_SIZE * 1.5) + 1];
			base64_urlencoding->encode(signature, len, b64signature, sizeof(b64signature));
			auth_dbg("auth: signature %s", b64signature);
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

	const char *user = NULL;
	const char *data = token;
	const char *sign = strrchr(token, '.');
	if (sign != NULL)
	{
		size_t signlen = 0;
		const char *end = strchr(sign, ';');
		if (end != NULL)
			signlen = end - sign - 1;
		else
			signlen = strlen(sign);
		size_t datalen = sign - data;
		sign++;
		if (authn_checksignature(mod->authn->config->secret, data, datalen, sign, signlen) == ESUCCESS)
		{
			ctx->info = calloc(1, sizeof(*ctx->info));
			strncpy(ctx->info->type, str_xtoken, FIELD_MAX);
			if (user == NULL)
				user = mod->authz->rules->check(mod->authz->ctx, NULL, NULL, token);
			if (user == NULL)
			{
				user = str_anonymous;
			}

#ifdef AUTHZ_JWT
			if (jwt_decode(token, ctx->info) == ESUCCESS)
			{
				auth_dbg("auth: jwt user %s", ctx->info->user);
				ret = EREJECT;
			}
			else
#endif
			if (user != NULL)
			{
				mod->authz->rules->setsession(mod->authz->ctx, user, ctx->info);
#ifndef DEBUG
				time_t now = time(NULL);
				if (mod->config->expire > 0 &&
					ctx->info->expires > now &&
					(ctx->info->expires + mod->config->expire) < now)
					ret = EREJECT;
#else
				ret = EREJECT;
#endif
			}

			if (ctx->info->token[0] == '\0')
			{
				strncpy(ctx->info->token, sign, TOKEN_MAX);
			}
		}
		else
		{
			warn("auth: token with bad signature");
		}
	}
	return ret;
}

int authn_checktokens(_mod_auth_ctx_t *ctx, const char *token)
{
	int ret = ECONTINUE;
	_mod_auth_t *mod = ctx->mod;
	const char *string = token;
	do
	{
		if (!strncmp(string, str_xtoken, sizeof(str_xtoken) - 1))
		{
			string += sizeof(str_xtoken) - 1 + 1; // +1 for the tailing '='
		}
		ret = authn_checktoken(ctx, string);
		string = strstr(string, str_xtoken);
	} while ((ret == ECONTINUE) && (string != NULL));
	return ret;
}
#endif

static const char *_authn_getauthorization(const _mod_auth_ctx_t *ctx, http_message_t *request)
{
	const _mod_auth_t *mod = ctx->mod;
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
		warn("auth: cookie get %s %p",str_authorization, authorization);
	}

	if (authorization != NULL && strncmp(authorization, mod->type, mod->typelength))
	{
		err("auth: type mismatch %.*s, %.*s", (int)mod->typelength, authorization, (int)mod->typelength, mod->type);
		authorization = NULL;
	}
	return authorization;
}

static int _authn_setauthorization_cookie(const _mod_auth_ctx_t *ctx,
			const char *authorization, const authsession_t *info,
			http_message_t *response)
{
#ifdef AUTH_TOKEN
	_mod_auth_t *mod = ctx->mod;

	if (mod->authz->type & AUTHZ_TOKEN_E)
	{
		char *token = mod->authz->generatetoken(mod->config, info);
		const char *key = ctx->mod->config->secret;
		if (hash_macsha256 != NULL && key != NULL)
		{
			void *hctx = hash_macsha256->initkey(key, strlen(key));
			if (hctx)
			{
				hash_macsha256->update(hctx, token, strlen(token));
				char signature[HASH_MAX_SIZE];
				int signlen = hash_macsha256->finish(hctx, signature);
				char b64signature[(int)(HASH_MAX_SIZE * 1.5) + 1];
				base64_urlencoding->encode(signature, signlen, b64signature, sizeof(b64signature));
				cookie_set(response, str_xtoken, token, ".", b64signature, NULL);
				if (mod->authz->rules->join)
					mod->authz->rules->join(mod->authz->ctx, info->user, b64signature, mod->config->expire);
			}
		}
		else if (mod->authz->rules->join)
			mod->authz->rules->join(mod->authz->ctx, info->user, token, mod->config->expire);
		free(token);
	}
	else
#endif
	if (authorization != NULL)
	{
		cookie_set(response, str_authorization, authorization, NULL);
	}
	cookie_set(response, str_xuser, info->user, NULL);
	if (info->group[0] != '\0')
		cookie_set(response, str_xgroup, info->group, NULL);
	if (info->home[0] != '\0')
		cookie_set(response, str_xhome, "~/", NULL);
	return ESUCCESS;
}

static int _authn_setauthorization_header(const _mod_auth_ctx_t *ctx,
			const char *authorization, const authsession_t *info,
			http_message_t *response)
{
#ifdef AUTH_TOKEN
	_mod_auth_t *mod = ctx->mod;

	if (mod->authz->type & AUTHZ_TOKEN_E)
	{
		char *token = mod->authz->generatetoken(mod->config, info);
		httpmessage_addheader(response, str_xtoken, token, -1);
		const char *key = ctx->mod->config->secret;
		if (hash_macsha256 != NULL && key != NULL)
		{
			void *hctx = hash_macsha256->initkey(key, strlen(key));
			if (hctx)
			{
				hash_macsha256->update(hctx, token, strlen(token));
				char signature[HASH_MAX_SIZE];
				int signlen = hash_macsha256->finish(hctx, signature);
				char b64signature[(int)(HASH_MAX_SIZE * 1.5) + 1];
				signlen = base64_urlencoding->encode(signature, signlen, b64signature, sizeof(b64signature));
				httpmessage_appendheader(response, str_xtoken, STRING_REF("."));
				httpmessage_appendheader(response, str_xtoken, b64signature, signlen);
				if (mod->authz->rules->join)
					mod->authz->rules->join(mod->authz->ctx, info->user, b64signature, mod->config->expire);
			}
		}
		else if (mod->authz->rules->join)
			mod->authz->rules->join(mod->authz->ctx, info->user, token, mod->config->expire);
		free(token);
		httpmessage_addheader(response, "Access-Control-Expose-Headers", STRING_REF(str_xtoken));
	}
	else
#endif
	if (authorization != NULL)
	{
		httpmessage_addheader(response, str_authorization, authorization, -1);
	}
	httpmessage_addheader(response, str_xuser, info->user, -1);
	httpmessage_addheader(response, "Access-Control-Expose-Headers", STRING_REF(str_xuser));
	if (info->group[0] != '\0')
	{
		httpmessage_addheader(response, str_xgroup, info->group, -1);
		httpmessage_addheader(response, "Access-Control-Expose-Headers", STRING_REF(str_xgroup));
	}
	if (info->home[0] != '\0')
	{
		httpmessage_addheader(response, str_xhome, STRING_REF("~/"));
	}
	return ESUCCESS;
}

static int _authn_checkauthorization(_mod_auth_ctx_t *ctx,
		const char *authorization, http_message_t *request)
{
	int ret = ECONTINUE;
	_mod_auth_t *mod = ctx->mod;
	const mod_auth_t *config = mod->config;
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
	 * The authorization is always acceptable and it is dangerous.
	 */
	if (config->redirect)
		method = str_head;
	const char *user = mod->authn->rules->check(mod->authn->ctx, method, uri, authentication);
	if (user != NULL)
	{
		if (ctx->info == NULL)
		{
			ctx->info = calloc(1, sizeof(*ctx->info));
			ctx->info->expires = mod->config->expire * 60;
			ctx->info->expires += time(NULL);
			mod->authz->rules->setsession(mod->authz->ctx, user, ctx->info);
			strncpy(ctx->info->type, mod->type, FIELD_MAX);
			ctx->authorization = strdup(authorization);
		}

		if (!strcmp(ctx->info->status, str_status_reapproving) && mod->authz->type & AUTHZ_MNGT_E)
		{
			warn("auth: user \"%s\" accepted from %p to change password", ctx->info->user, ctx->clt);
			ret = EREJECT;
		}
		else if (strcmp(ctx->info->status, str_status_activated) != 0)
		{
			err("auth: user \"%s\" is not yet activated (%s)", ctx->info->user, ctx->info->status);
		}
		else
		{
			warn("auth: user \"%s\" accepted from %p", ctx->info->user, ctx->clt);
			ret = EREJECT;
		}
	}
	return ret;
}

static int auth_redirect_uri(_mod_auth_ctx_t *ctx, http_message_t *request, http_message_t *response)
{
	int ret = ESUCCESS;
	const _mod_auth_t *mod = ctx->mod;
	const mod_auth_t *config = mod->config;

	httpmessage_addheader(response, str_location, config->redirect, -1);

	const char *uri = NULL;
	int urilen = httpmessage_REQUEST2(request, "uri", &uri);
	const char *query = NULL;
	int querylen = httpmessage_REQUEST2(request, "query", &query);
	if (utils_searchexp(query, "noredirect", NULL) != ESUCCESS &&
			utils_searchexp(uri, config->protect, NULL) != ESUCCESS)
	{
		http_server_t *server = httpclient_server(httpmessage_client(request));
		httpmessage_appendheader(response, str_location, STRING_REF("?redirect_uri="));
		const char *scheme = httpserver_INFO(server, "scheme");
		httpmessage_appendheader(response, str_location, scheme, -1);
		httpmessage_appendheader(response, str_location, STRING_REF("://"));
		const char *host = httpserver_INFO(server, "host");
		if (host == NULL || host[0] == '\0')
		{
			host = httpmessage_SERVER(request, "addr");
		}
		httpmessage_appendheader(response, str_location, host, -1);
		const char *port = httpserver_INFO(server, "port");
		if (port && port[0] != '\0')
		{
			httpmessage_appendheader(response, str_location, STRING_REF(":"));
			httpmessage_appendheader(response, str_location, port, -1);
		}
		httpmessage_appendheader(response, str_location, uri, urilen);
		if (query && query[0] != '\0')
		{
			httpmessage_appendheader(response, str_location, STRING_REF("?"));
			httpmessage_appendheader(response, str_location, query, querylen);
		}
	}

	httpmessage_addheader(response, str_cachecontrol, STRING_REF("no-cache"));

	ret = ESUCCESS;

	return ret;
}

static int _authn_challenge(_mod_auth_ctx_t *ctx, http_message_t *request, http_message_t *response)
{
	int ret = ECONTINUE;
	const _mod_auth_t *mod = ctx->mod;
	const mod_auth_t *config = mod->config;
	const char *uri = httpmessage_REQUEST(request, "uri");

	ret = mod->authn->rules->challenge(mod->authn->ctx, request, response);
	if (ret == ECONTINUE)
	{
		if (mod->authn->type & AUTHN_COOKIE_E)
			cookie_set(response, "X-Auth-Token", "", ";Max-Age=0", NULL);

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
				 * should send response to the request.
				 */
				httpmessage_result(response, RESULT_200);
				ret = EREJECT;
			}
			else if (config->authn.type & AUTHN_REDIRECT_E)
			{
				ret = auth_redirect_uri(ctx, request, response);
				httpmessage_result(response, RESULT_302);
			}
			else
			{
				httpmessage_addheader(response, str_location, config->redirect, -1);
				httpmessage_addheader(response, str_cachecontrol, STRING_REF("no-cache"));
				httpmessage_result(response, RESULT_302);
				ret = ESUCCESS;
			}
		}
		else
		{
			httpmessage_result(response, RESULT_401);
		}
	}
	return ret;
}

static int _authn_checkuri(const mod_auth_t *config, http_message_t *request, http_message_t *response)
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
		auth_dbg("unprotected uri %s", config->unprotect);
		ret = EREJECT;
	}
	protect = utils_searchexp(uri, config->protect, NULL);
	if (protect == ESUCCESS)
	{
		auth_dbg("protected uri %s", config->protect);
		httpmessage_result(response, RESULT_403);
		ret = ESUCCESS;
	}
	return ret;
}

static int _authn_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = ECONTINUE;
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)arg;
	const _mod_auth_t *mod = ctx->mod;
	mod_auth_t *config = mod->config;
	const char *authorization = NULL;

	/**
	 * authz may need setup the user setting for each message
	 **/
	if(mod->authz->rules->setup)
		mod->authz->rules->setup(mod->authz->ctx);

	ret = _authn_checkuri(config, request, response);
	auth_dbg("auth: checkuri %d", ret);
#if 0
	/**
	 * If ctx->info is set, this connection has been already authenticated.
	 * It should be useless to authenticate again, but if another connection
	 * try to unauthenticate, this may break the security.
	 */
	if (ret == ECONTINUE && ctx->info != NULL)
	{
		ret = EREJECT;
	}
#endif

	/**
	 * The header WWW-Authenticate inside the request
	 * allows to disconnect the user.
	 */
	authorization = httpmessage_REQUEST(request, str_authenticate);
	if (ret == ECONTINUE && authorization != NULL && authorization[0] != '\0')
	{
		ret = ESUCCESS;
	}
	auth_dbg("auth: authenticate %d", ret);

#ifdef AUTH_TOKEN
	if (ret == ECONTINUE && mod->authz->type & AUTHZ_TOKEN_E)
	{
		authorization = _authn_gettoken(ctx, request);
		auth_dbg("auth: gettoken %d", ret);
		if (mod->authn->ctx && authorization != NULL && authorization[0] != '\0')
		{
			ret = authn_checktokens( ctx, authorization);
		}
	}
#endif
	authorization = _authn_getauthorization(ctx, request);
	auth_dbg("auth: getauthorization %d", ret);
	if (ret != ESUCCESS && mod->authn->ctx && authorization != NULL && authorization[0] != '\0')
	{
		ret = _authn_checkauthorization( ctx, authorization, request);
	}
	auth_dbg("auth: checkauthorization %d", ret);

	if (ret != EREJECT)
	{
		if (ctx->info != NULL)
		{
			free(ctx->info);
			ctx->info = NULL;
		}
		httpmessage_SESSION(request, str_auth, "", 0);
		ret = _authn_challenge(ctx, request, response);
	}
	else
	{
		if (httpclient_setsession(ctx->clt, authorization) == EREJECT)
		{
			dbg("auth: session already open");
		}
		const authsession_t *info = httpclient_session(ctx->clt, str_auth, sizeof(str_auth) - 1, ctx->info, sizeof(*ctx->info));

		if (ctx->info && mod->authn->type & AUTHN_HEADER_E)
		{
			_authn_setauthorization_header(ctx,
					authorization, ctx->info,
					response);
		}
		else if (ctx->info && mod->authn->type & AUTHN_COOKIE_E)
		{
			_authn_setauthorization_cookie(ctx,
					authorization, ctx->info,
					response);
		}

		if (ctx->info && mod->authz->type & AUTHZ_CHOWN_E)
		{
			auth_setowner(ctx->info->user);
		}
	}
	/**
	 * As the setup, the authz may need to cleanup between each message
	 **/
	if (mod->authz->ctx  && mod->authz->rules->cleanup)
	{
		mod->authz->rules->cleanup(mod->authz->ctx);
	}
	return ret;
}

const module_t mod_auth =
{
	.name = str_auth,
	.configure = (module_configure_t)&auth_config,
	.create = (module_create_t)&mod_auth_create,
	.destroy = &mod_auth_destroy
};

#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_auth")));
#endif
