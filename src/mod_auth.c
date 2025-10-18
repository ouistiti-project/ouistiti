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

    https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml
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
#include <limits.h>

#ifdef HAVE_LIBCONFIG
#include <libconfig.h>
#endif

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/hash.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
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
static int _forbidden_connector(void *arg, http_message_t *request, http_message_t *response);
static int _authn_connector(void *arg, http_message_t *request, http_message_t *response);
#ifdef AUTH_TOKEN
static string_t *_mod_auth_generatetoken(authtoken_ctx_t *ctx, http_message_t *UNUSED(request));
static int _authn_checktoken(authtoken_ctx_t *ctx, const string_t *token, const char **cuser);

#endif

static const char str_auth[] = "auth";

struct _mod_auth_ctx_s
{
	_mod_auth_t *mod;
	http_client_t *clt;
	char *authenticate;
	authn_t authn;
	authz_t authz;
	struct
	{
		authtoken_ctx_t *ctx;
		authtoken_rule_generate_t generate;
		authtoken_rule_check_t check;
	} token;
};

struct _mod_auth_s
{
	mod_auth_t	*config;
	string_t type;
	authn_t *authn;
	authz_t *authz;
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
			((name != NULL && !strcasecmp(name, hash->name)) ||
				(nameid == hash->nameid)))
			break;
	}
	return hash;
}

static int _mod_sethash(mod_authn_t *config, const char *algo)
{
	int ret = EREJECT;
	if (algo)
	{
		config->hash = _mod_findhash(algo, -1);
	}
	if (config->hash != NULL)
	{
		ret = ESUCCESS;
	}
	else if (config->hash == NULL && hash_sha256)
	{
		config->hash = hash_sha256;
		ret = ESUCCESS;
	}

	if (ret == EREJECT && algo)
	{
		warn("auth: bad algorithm %s (%s | %s | %s | %s | %s)",
			algo,
			(hash_sha1?hash_sha1->name:""),
			(hash_sha224?hash_sha224->name:""),
			(hash_sha256?hash_sha256->name:""),
			(hash_sha512?hash_sha512->name:""),
			(hash_macsha256?hash_macsha256->name:""));
	}

	return ret;
}

struct _authn_s
{
	authn_rule_config_t config;
	authn_type_t type;
	string_t *name;
	authn_rules_t *rules;
	struct _authn_s *next;
};

struct _authz_s
{
	authz_rule_config_t config;
	authz_type_t type;
	string_t *name;
	authz_rules_t *rules;
	struct _authz_s *next;
};

static struct _authn_s *authn_list = NULL;
static struct _authz_s *authz_list = NULL;

void auth_registerauthn(const string_t *name, authn_rules_t *rules)
{
	struct _authn_s *entry = calloc(1, sizeof(*entry));
	entry->name = string_dup(name);
	entry->rules = rules;
	entry->config = rules->config;
	entry->next = authn_list;
	authn_list = entry;
}

void auth_registerauthz(const string_t *name, authz_rules_t *rules)
{
	struct _authz_s *entry = calloc(1, sizeof(*entry));
	entry->name = string_dup(name);
	entry->rules = rules;
	entry->config = rules->config;
	entry->next = authz_list;
	authz_list = entry;
}


#ifdef FILE_CONFIG
static int authn_config(const config_setting_t *configauth, mod_authn_t *mod)
{
	int ret = EREJECT;

	char *type = NULL;
	if (config_setting_lookup_string(configauth, "type", (const char **)&type) != CONFIG_TRUE)
	{
		err("auth: authn type is not set");
		return ret;
	}

	struct _authn_s *authn = NULL;
	for (authn = authn_list; authn != NULL; authn = authn->next)
	{
		if (!string_cmp(authn->name, type, -1))
			mod->config = authn->config(configauth, &authn->type);
		if (mod->config != NULL)
		{
			break;
		}
	}

	if (authn != NULL)
	{
		mod->rules = authn->rules;
		mod->type |= authn->type;
		string_store(&mod->name, string_toc(authn->name), string_length(authn->name));

		/**
		 * algorithm allow to change secret algorithm used during authentication default is md5. (see authn_digest.c)
		 */
		const char *algo = NULL;
		config_setting_lookup_string(configauth, "algorithm", &algo);
		_mod_sethash(mod, algo);

		ret = ESUCCESS;
	}
	else
		err("auth: authn '%s' not found", type);
	return ret;
}

static void authz_optionscb(void *arg, const char *option)
{
	mod_auth_t *auth = (mod_auth_t *)arg;

	if (utils_searchexp("home", option, NULL) == ESUCCESS)
		auth->authz.type |= AUTHZ_HOME_E;
	if (utils_searchexp("token", option, NULL) == ESUCCESS)
	{
		auth->authz.type |= AUTHZ_TOKEN_E;
		auth->token.type = E_OUITOKEN;
	}
	if (utils_searchexp("jwt", option, NULL) == ESUCCESS)
	{
		auth->authz.type |= AUTHZ_TOKEN_E;
		auth->token.type = E_JWT;
	}
	if (utils_searchexp("chown", option, NULL) == ESUCCESS)
		auth->authz.type |= AUTHZ_CHOWN_E;

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
	struct _authz_s *authz = NULL;
	const char *name = NULL;
	ret = config_setting_lookup_string(configauth, "authz", &name);
	if (ret == CONFIG_FALSE)
		name = NULL;
	for (authz = authz_list; authz != NULL; authz = authz->next)
	{
		if (name != NULL)
		{
			if (! string_cmp(authz->name, name, -1))
			{
				mod->config = authz->config(configauth, &authz->type);
				break;
			}
		}
		else if (authz->config != NULL)
		{
			mod->config = authz->config(configauth, &authz->type);
		}
		if (mod->config != NULL)
		{
			break;
		}
	}
	if (authz != NULL)
	{
		mod->rules = authz->rules;
		mod->type |= authz->type;
		string_store(&mod->name, string_toc(authz->name), string_length(authz->name));
		ret = ESUCCESS;
	}
	else
		err("auth: password engine not found");
	return ret;
}

static mod_auth_t *_auth_config(const config_setting_t *config, server_t *server, const char *hostname)
{
	mod_auth_t *auth = NULL;
	int ret = ESUCCESS;
	auth = calloc(1, sizeof(*auth));
	/**
	 * signin URI allowed to access to the signin page
	 */
	const char *data = NULL;
	ret = config_setting_lookup_string(config, "signin", &data);
	if (ret == CONFIG_FALSE)
		ret = config_setting_lookup_string(config, "token_ep", &data);
	if (ret != CONFIG_FALSE)
		string_store(&auth->redirect, data, -1);
	ret = config_setting_lookup_string(config, "token_ep", &data);
	if (ret != CONFIG_FALSE)
		string_store(&auth->token_ep, data, -1);

	config_setting_lookup_string(config, "protect", &auth->protect);
	config_setting_lookup_string(config, "unprotect", &auth->unprotect);

	/**
	 * secret is the secret used during the token generation. (see authz_jwt.c)
	 */
	if (config_setting_lookup_string(config, "secret", &data) != CONFIG_FALSE)
		string_store(&auth->token.secret, data, -1);
	const char *mode = NULL;
	config_setting_lookup_string(config, "options", &mode);
	if (ouistiti_issecure(server))
		auth->authz.type |= AUTHZ_TLS_E;
	if (mode != NULL)
	{
		authz_optionscb(auth, mode);
	}
	int int_expire = 0;
	if (config_setting_lookup_int(config, "expire", &int_expire) == CONFIG_FALSE)
		auth->token.expire = 30;
	else
		auth->token.expire = (time_t)int_expire;

	if (config_setting_lookup_string(config, "realm", &data) == CONFIG_TRUE)
		string_store(&auth->realm, data, -1);
	else if (config_setting_lookup_string(config, str_issuer, &data) == CONFIG_TRUE)
		string_store(&auth->realm, data, -1);
	else
		string_store(&auth->realm, hostname, -1);

	ret = authz_config(config, &auth->authz);
	if (ret == EREJECT)
	{
		err("config: authz is not set");
		auth->authn.type = AUTHN_FORBIDDEN_E;
	}
	if (auth->authz.type & AUTHZ_JWT_E)
		auth->token.type = E_JWT;
	if (config_setting_lookup_string(config, str_issuer, &data) == CONFIG_TRUE)
		string_store(&auth->token.issuer, data, -1);
	else if (config_setting_lookup_string(config, "realm", &data) == CONFIG_TRUE)
		string_store(&auth->token.issuer, data, -1);
	else
		string_store(&auth->token.issuer, STRING_INFO(auth->authz.name));

	ret = authn_config(config, &auth->authn);
	if (ret == EREJECT)
	{
		auth->authn.type = AUTHN_FORBIDDEN_E;
	}

	if (auth->token.secret.data == NULL && auth->authz.type & AUTHZ_TOKEN_E)
	{
		err("auth: to enable the token, set the \"secret\" into configuration");
		auth->authn.type = AUTHN_FORBIDDEN_E;
	}
	return auth;
}

static int auth_config(config_setting_t *iterator, server_t *server, int index, void **modconfig)
{
	int conf_ret = ESUCCESS;
	mod_auth_t *auth = NULL;
#if LIBCONFIG_VER_MINOR < 5
	const config_setting_t *config = config_setting_get_member(iterator, "auth");
#else
	const config_setting_t *config = config_setting_lookup(iterator, "auth");
#endif
	const char *hostname = NULL;
	if (config_setting_lookup_string(iterator, "hostname", &hostname) == CONFIG_FALSE)
		hostname = str_servername;
	if (config && config_setting_is_list(config))
	{
			if (index >= config_setting_length(config))
				return EREJECT;
			config = config_setting_get_elem(config, index);
			conf_ret = ECONTINUE;
	}
	if (config)
	{
		auth = _auth_config(config, server, hostname);
	}
	else
		conf_ret = EREJECT;
	*modconfig = (void *)auth;
	return conf_ret;
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
		.rules = &authz_sqlite_rules,
	},
	.authn = &(mod_authn_t){
		.type = AUTHN_BASIC_E,
		.name = "Basic",
		.rules = &authn_basic_rules,
	},
	.realm = NULL,
};

static int auth_config(void *iterator, server_t *server, int index, void **config)
{
	*config = (void *)&g_auth_config;
	return ESUCCESS;
}
#endif

static authz_t *_authz_dup(mod_authz_t *authz)
{
	authz_t *newauthz = calloc(1, sizeof(*newauthz));
	newauthz->type = authz->type;
	newauthz->rules = authz->rules;
	newauthz->name = &authz->name;
	return newauthz;
}

static void *mod_auth_create(http_server_t *server, mod_auth_t *config)
{
	_mod_auth_t *mod;

	srandom(time(NULL));

	if (!config)
	if (!config || config->authz.rules == NULL)
	{
		err("auth: storage not set, change configuration");
		return NULL;
	}

	mod = calloc(1, sizeof(*mod));
	mod->config = config;

	mod->authz = _authz_dup(&config->authz);

	string_t *issuer = mod->authz->name;
	if (!string_empty(&config->token.issuer))
		issuer = &config->token.issuer;
	mod->authz->ctx = mod->authz->rules->create(server, issuer, config->authz.config);
	if (mod->authz->ctx == NULL)
	{
		err("auth: authz %s not supported", string_toc(mod->authz->name));
		free(mod->authz);
		free(mod);
		return NULL;
	}

	mod->authn = calloc(1, sizeof(*mod->authn));
	mod->authn->config = config;
	if (config->authn.type != AUTHN_FORBIDDEN_E)
	{
		mod->authn->server = server;
		mod->authn->type = config->authn.type;
		mod->authn->rules = config->authn.rules;
	}
	if (mod->authn->rules == NULL)
		err("authentication type is not availlable, change configuration");
	else
	{
		mod->authn->ctx = mod->authn->rules->create(mod->authn, issuer, config->authn.config);
	}
	if (mod->authn->ctx)
	{
		string_store(&mod->type, string_toc(&config->authn.name), string_length(&config->authn.name));
		httpserver_addmod(server, _mod_auth_getctx, _mod_auth_freectx, mod, str_auth);
	}
	else
	{
		httpserver_addconnector(server, _forbidden_connector, mod, CONNECTOR_AUTH, str_auth);
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
	mod_auth_t *config = mod->config;

	ctx->mod = mod;
	ctx->clt = clt;

	ctx->token.ctx = calloc(1, sizeof(*ctx->token.ctx));
	ctx->token.ctx->config = &config->token;
	if (config->token.type == E_OUITOKEN)
	{
		ctx->token.generate = _mod_auth_generatetoken;
		ctx->token.check = _authn_checktoken;
	}
	else if (config->token.type == E_JWT)
	{
		ctx->token.generate = authz_jwt_generatetoken;
		ctx->token.check = authz_jwt_checktoken;
	}

	if (mod->authz->type & AUTHZ_HOME_E)
		httpclient_addconnector(clt, _home_connector, ctx, CONNECTOR_AUTH, str_auth);
	httpclient_addconnector(clt, _authn_connector, ctx, CONNECTOR_AUTH, str_auth);
	/**
	 * authn may require prioritary connector and it has to be added after this one
	 */
	if(mod->authn->ctx && mod->authn->rules->setup)
	{
		ctx->authn.ctx = mod->authn->rules->setup(mod->authn->ctx, clt, addr, addrsize);
		ctx->authn.rules = mod->authn->rules;
		ctx->authn.type = mod->authn->type;
		ctx->authn.config = mod->authn->config;
	}

	if(mod->authz->ctx && mod->authz->rules->setup)
	{
		ctx->authz.ctx = mod->authz->rules->setup(mod->authz->ctx, clt, addr, addrsize);
		ctx->authz.rules = mod->authz->rules;
		ctx->authz.type = mod->authz->type;
		ctx->authz.name = &mod->config->authz.name;
	}

	return ctx;
}

static void _mod_auth_freectx(void *vctx)
{
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)vctx;

	if(ctx->authn.ctx && ctx->authn.rules->cleanup)
		ctx->authn.rules->cleanup(ctx->authn.ctx);
	if(ctx->authz.ctx && ctx->authz.rules->cleanup)
		ctx->authz.rules->cleanup(ctx->authz.ctx);
	if (ctx->token.ctx)
		free(ctx->token.ctx);
	if (ctx->authenticate)
		free(ctx->authenticate);
	free(ctx);
}

static int _forbidden_connector(void *UNUSED(arg), http_message_t *request, http_message_t *response)
{
	int ret = ESUCCESS;
	err("auth: configuration error, all access are lock");
	httpmessage_result(response, RESULT_401);
	return ret;
}

static int _home_connector(void *UNUSED(arg), http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	const char *home = NULL;
	size_t homelength = auth_info2(request, "home", &home);

	if (home)
	{
		/**
		 * disable home redirection for websocket
		 */
		const char *websocket = httpmessage_REQUEST(request, "Sec-WebSocket-Version");
		if (websocket && websocket[0] != '\0')
			return ret;
		const char *uri = httpmessage_REQUEST(request, "uri");

		if ((homelength > 0) && !strncmp(home + 1, uri, homelength - 1))
		{
			dbg("redirect the url to home %s", home);
#if defined(RESULT_301)
			httpmessage_addheader(response, str_location, home, homelength);
			httpmessage_appendheader(response, str_location, STRING_REF("/"));
			httpmessage_result(response, RESULT_301);
			ret = ESUCCESS;
#endif
		}
	}
	return ret;
}

static int _authz_computepasswd(const hash_t *hash, const string_t *user,
			const string_t *realm, const string_t *passwd,
			char *string, int stringlen)
{
	char hashpasswd[32];
	void *ctx;

	ctx = hash->init();
	if (realm)
	{
		hash->update(ctx, user->data, user->length);
		hash->update(ctx, ":", 1);
		hash->update(ctx, realm->data, realm->length);
		hash->update(ctx, ":", 1);
	}
	hash->update(ctx, passwd->data, passwd->length);
	hash->finish(ctx, hashpasswd);

	int length = base64->encode(hashpasswd, hash->size, string, stringlen);
	return length;
}

int authz_checkpasswd(const char *checkpasswd,  const string_t *user,
		const string_t *realm, const string_t *passwd)
{
	int ret = EREJECT;
	auth_dbg("auth: %s check %s %s", user->data, passwd->data, checkpasswd);
	if (checkpasswd[0] == '$')
	{
		const hash_t *hash = NULL;
		char hashtype = checkpasswd[1];
		if (checkpasswd[1] == 'a')
		{
			hashtype = checkpasswd[2];
		}
		const char *checkrealm = NULL;
		int checkrealmlen = 0;
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
			checkrealmlen = strpbrk(checkrealm, ";$") - checkrealm - 1;
			if (string_empty(realm) || string_cmp(realm, checkrealm, checkrealmlen))
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
			int length = _authz_computepasswd(hash, user,
						realm, passwd, b64passwd, sizeof(b64passwd));

			auth_dbg("auth: check %s %s", b64passwd, checkpasswd);
			if (!strncmp(b64passwd, checkpasswd, length))
				ret = ESUCCESS;
		}
		else
			err("auth: %.3s not supported change password encryption", checkpasswd);
	}
	else if (!string_cmp(passwd, checkpasswd, -1))
	{
		ret = ESUCCESS;
	}
	return ret;
}

#ifdef AUTH_TOKEN
static string_t *_mod_auth_generatetoken(authtoken_ctx_t *ctx, http_message_t *request)
{
	const authtoken_config_t *config = ctx->config;

	string_t user = {0};
	ouimessage_SESSION(request, str_user, &user);
	size_t _noncelen = config->issuer.length + 1 + 24 + 1 + sizeof(time_t) + 1 + string_length(&user);
	size_t tokenlen = (_noncelen * 5) / 3;

	string_t *token = NULL;
	token = string_create(tokenlen + 1);

	size_t length = 0;
	char *_nonce = calloc(1, _noncelen + 1);
	int i;
	for (i = 0; i < (24 / sizeof(int)); i++)
	{
		*(int *)(_nonce + i * 4) = random();
	}
	length += 24;
	_nonce[length] = '.';
	length++;
	time_t expire = (config->expire * 60);
	if (expire == 0)
		expire = 60 * 30;
	expire += time(NULL);
	memcpy(&_nonce[length], &expire, sizeof(time_t));
	length += sizeof(time_t);
	if (!string_empty(&config->issuer))
	{
		_nonce[length] = '.';
		length++;
		memcpy(&_nonce[length], string_toc(&config->issuer), string_length(&config->issuer));
	}
	if (!string_empty(&user))
	{
		_nonce[length] = '.';
		length++;
		memcpy(&_nonce[length], string_toc(&user), string_length(&user));
	}
	tokenlen = base64_urlencoding->encode(_nonce, length, string_storage(token), string_size(token));
	string_slice(token, 0, tokenlen);
	free(_nonce);
	return token;
}

static int _authn_checktoken(authtoken_ctx_t *ctx, const string_t *token, const char **cuser)
{
	const authtoken_config_t *config = ctx->config;

	size_t _noncelen = config->issuer.length + 1 + 24 + 1 + sizeof(time_t);
	char *_nonce = calloc(1, _noncelen + 1);
	_noncelen = base64_urlencoding->decode(string_toc(token), string_length(token), _nonce, _noncelen);
	size_t length = 0;
	length += 24; // passthrough the random part of nonce
	length += 1; // the , separator
	time_t expire = 0;
	memcpy(&expire, &_nonce[length], sizeof(time_t));
	free(_nonce);
	length += sizeof(time_t);
	if (expire < time(NULL))
	{
		err("auth: token expired");
		free(_nonce);
		return EREJECT;
	}
	length += 1; // the , separator
	string_t user = {0};
	string_t issuer = {0};
	string_store(&issuer, &_nonce[length], _noncelen - length);
	string_split(&issuer, ',', &issuer, &user, NULL);
	auth_dbg("auth: check issuer %.*s/%s", string_length(&issuer), string_toc(&issuer), string_toc(&config->issuer));
	if (string_contain(&issuer, string_toc(&config->issuer), string_length(&config->issuer), '+'))
	{
		free(_nonce);
		return EREJECT;
	}
	// the user is stored into _nonce. keep the memory to the freectx function
	ctx->user = string_dup(&user);
	if (cuser)
		*cuser = string_toc(ctx->user);
	return ESUCCESS;
}

static int _authn_gettoken(const _mod_auth_ctx_t *ctx, http_message_t *request, string_t *token, string_t *authorization)
{
	const _mod_auth_t *mod = ctx->mod;
	/**
	 * The authorization may be accepted and replaced by a token.
	 * This token is available inside the cookie.
	 */
	if (mod->authn->type & AUTHN_HEADER_E)
		ouimessage_REQUEST(request, str_xtoken, token);
	if (string_empty(token))
	{
		ouimessage_cookie(request, str_xtoken, token);
	}
	if (!string_empty(token))
	{
		string_t data[2] = {0};
		string_split(token, '.', &data[0], &data[1], authorization, NULL);
		if (string_empty(authorization))
		{
			string_store(authorization, string_toc(&data[1]), string_length(&data[1]));
		}
		string_slice(token, 0, string_length(token) - string_length(authorization) - 1);
		return ESUCCESS;
	}
	return EREJECT;
}

static const char *_authn_gettokenuser(const _mod_auth_ctx_t *ctx, http_message_t *request)
{
	const _mod_auth_t *mod = ctx->mod;
	const char *user = NULL;
	size_t length = 0;
	/**
	 * The authorization may be accepted and replaced by a token.
	 * This token is available inside the cookie.
	 */
	if (mod->authn->type & AUTHN_HEADER_E)
		length = httpmessage_REQUEST2(request, str_xuser, &user);
	if (length == 0)
		length = httpmessage_cookie(request, str_xuser, &user);
	if (length == 0)
		user = str_anonymous;
	return user;
}

static string_t *_authn_signtoken(const string_t *key,	const string_t *data)
{
	string_t *sign = NULL;

	if (hash_macsha256 != NULL && key != NULL)
	{
		void *ctx = hash_macsha256->initkey(string_toc(key), string_length(key));
		if (ctx)
		{
			hash_macsha256->update(ctx, string_toc(data), string_length(data));
			char signature[HASH_MAX_SIZE];
			size_t signlen = hash_macsha256->finish(ctx, signature);
			sign = string_create((int)(HASH_MAX_SIZE * 1.5) + 1);
			size_t length = 0;
			length = base64_urlencoding->encode(signature, signlen, string_storage(sign), string_size(sign));
			string_slice(sign, 0, length);
			auth_dbg("auth: signature %.*s", string_size(sign), string_toc(sign));
		}
	}
	return sign;
}

int authn_checksignature(const string_t *key, const string_t *data, const string_t *sign)
{
	string_t *signature = NULL;
	signature = _authn_signtoken(key, data);
	if (signature == NULL)
		return EREJECT;
	int ret = string_compare(signature, sign);
	string_destroy(signature);
	return ret?EREJECT:ESUCCESS;
}

static int authn_checktoken(_mod_auth_ctx_t *ctx, authz_t *authz, const string_t *token, const string_t *sign, const char **user)
{
	int ret = ECONTINUE;
	_mod_auth_t *mod = ctx->mod;

	ret = authn_checksignature(&mod->config->token.secret, token, sign);
	if (ret == ESUCCESS)
	{
		/// some authz may join a token to an user
		*user = authz->rules->check(authz->ctx, NULL, NULL, string_toc(sign));
		if (*user == NULL)
		{
			ret = ctx->token.check(ctx->token.ctx, token, user);
		}
	}
	else
		err("auth: token with bad signature %.*s", string_length(sign), string_toc(sign));
	return ret;
}
#endif

static int _authn_getauthorization(const _mod_auth_ctx_t *ctx, http_message_t *request, string_t *authorization)
{
	const _mod_auth_t *mod = ctx->mod;
	/**
	 * with standard authentication, the authorization code
	 * is sended info header
	 */
	ouimessage_REQUEST(request, str_authorization, authorization);
	/**
	 * to send the authorization header only once, the "cookie"
	 * option of the server store the authorization inside cookie.
	 * This method allow to use little client which manage only cookie.
	 */
	if (string_empty(authorization))
		ouimessage_cookie(request, str_authorization, authorization);

	if (!string_empty(authorization) && !string_startwith(authorization, &mod->type))
	{
		err("auth: type mismatch %.*s, %.*s", string_length(&mod->type), string_toc(authorization),
			string_length(&mod->type), string_toc(&mod->type));
		string_slice(authorization, 0, 0);
	}
	return (!string_empty(authorization))? ESUCCESS : EREJECT;
}

static int _authn_setauthorization_cookie(const _mod_auth_ctx_t *ctx,
			const string_t *authorization,
			const string_t *token, const string_t *sign,
			http_message_t *response)
{
	string_t tsecure = STRING_DCL("; Secure");
	string_t tsamesitelax = STRING_DCL("; Samesite=Lax");

	if (!string_empty(token))
	{
		if (string_empty(sign))
			ouimessage_setcookie(response, str_xtoken, token, &tsecure, &tsamesitelax, NULL);
		else
			ouimessage_setcookie(response, str_xtoken, token, &string_dot, sign, &tsecure, &tsamesitelax, NULL);
	}

	const char *user = NULL;
	size_t userlen = auth_info2(response, str_user, &user);
	string_t tuser = {0};
	string_store(&tuser, user, userlen);
	ouimessage_setcookie(response, str_xuser, &tuser, NULL);
	const char *group = NULL;
	size_t grouplen = auth_info2(response, str_group, &group);
	string_t tgroup = {0};
	string_store(&tgroup, group, grouplen);
	if (!string_empty(&tgroup))
		ouimessage_setcookie(response, str_xgroup, &tgroup, NULL);
	const char *home = NULL;
	size_t homelen = auth_info2(response, str_home, &home);
	string_t thome = {0};
	string_store(&thome, home, homelen);
	if (!string_empty(&thome))
	{
		string_t string_tylde = STRING_DCL("~/");
		ouimessage_setcookie(response, str_xhome, &string_tylde, NULL);
	}
	return ESUCCESS;
}

static int _authn_setauthorization_header(const _mod_auth_ctx_t *ctx,
			const string_t *authorization,
			const string_t *token, const string_t *sign,
			http_message_t *response)
{
	if (!string_empty(token))
	{
		httpmessage_addheader(response, str_xtoken, string_toc(token), string_length(token));
		if (!string_empty(sign))
		{
			httpmessage_appendheader(response, str_xtoken, STRING_REF("."));
			httpmessage_appendheader(response, str_xtoken, string_toc(sign), string_length(sign));
		}
	}
	const char *user = NULL;
	size_t userlen = auth_info2(response, str_user, &user);
	httpmessage_addheader(response, str_xuser, user, userlen);
	httpmessage_addheader(response, "Access-Control-Expose-Headers", STRING_REF(str_xuser));
	const char *group = NULL;
	size_t grouplen = auth_info2(response, str_group, &group);
	if (group && grouplen > 0)
	{
		httpmessage_addheader(response, str_xgroup, group, grouplen);
		httpmessage_addheader(response, "Access-Control-Expose-Headers", STRING_REF(str_xgroup));
	}
	const char *home = auth_info(response, STRING_REF(str_home));
	if (home && home[0] != '\0')
	{
		httpmessage_addheader(response, str_xhome, STRING_REF("~/"));
	}
	return ESUCCESS;
}

static const char * _authn_checkauthorization(_mod_auth_ctx_t *ctx, authn_t *authn, authz_t *authz,
		const string_t *authorization, http_message_t *request)
{
	_mod_auth_t *mod = ctx->mod;
	const mod_auth_t *config = mod->config;
	string_t method = {0};
	string_t uri = {0};
	ouimessage_REQUEST(request, "method", &method);
	ouimessage_REQUEST(request, "uri", &uri);

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
	if (!string_empty(&config->redirect))
	{
		string_store(&method, str_head, -1);
	}
	const char *user = authn->rules->check(authn->ctx, authz,
			string_toc(&method), string_length(&method),
			string_toc(&uri), string_length(&uri),
			string_toc(authorization), string_length(authorization));
	return user;
}

static int _authn_check(_mod_auth_ctx_t *ctx, authz_t *authz, http_message_t *request, string_t *authorization, const char **user)
{
	_mod_auth_t *mod = ctx->mod;
	int ret = ECONTINUE;
	const char *tuser = NULL;

	/// authn may use setup for initialize some data, and the ctx change with client
	authn_t *authn = mod->authn;
	if (ctx->authn.ctx)
		authn = &ctx->authn;
	if (authn->rules->check)
	{
		_authn_getauthorization(ctx, request, authorization);
		if (!string_empty(authorization))
			tuser = _authn_checkauthorization( ctx, authn, authz, authorization, request);
	}
	else if (authn->rules->checkrequest)
	{
		tuser = authn->rules->checkrequest(authn->ctx, authz, request);
		string_store(authorization, string_toc(authz->name), string_length(authz->name));
	}
	if (tuser != NULL)
	{
		*user = tuser;
		ret = EREJECT;
	}
	return ret;
}
static int auth_redirect_uri(_mod_auth_ctx_t *ctx, http_message_t *request, http_message_t *response)
{
	int ret = ESUCCESS;
	const _mod_auth_t *mod = ctx->mod;
	const mod_auth_t *config = mod->config;

	const char *uri = NULL;
	size_t urilen = httpmessage_REQUEST2(request, "uri", &uri);
	const char *query = NULL;
	size_t querylen = httpmessage_REQUEST2(request, "query", &query);
	if (utils_searchexp(query, "noredirect", NULL) == ESUCCESS)
		return ret;

	httpmessage_addheader(response, str_location, string_toc(&config->redirect), string_length(&config->redirect));

	// if redirect_uri is present, the next one must not be added
	char sep = '?';
	if (strchr(config->redirect.data, sep))
		sep = '&';
	if ((config->authn.type & AUTHN_REDIRECT_E) &&
		(utils_searchexp(query, "redirect_uri", NULL) != ESUCCESS))
	{
		http_server_t *server = httpclient_server(httpmessage_client(request));
		httpmessage_appendheader(response, str_location, &sep, 1);
		sep = '&';
		httpmessage_appendheader(response, str_location, STRING_REF("redirect_uri"));
		httpmessage_appendheader(response, str_location, STRING_REF("="));
		/// append redirect_uri if not exist other with it will append later with query part
		const char *scheme = NULL;
		size_t schemelen = httpserver_INFO2(server, "scheme", &scheme);
		httpmessage_appendheader(response, str_location, scheme, schemelen);
		httpmessage_appendheader(response, str_location, STRING_REF("://"));
		const char *host = NULL;
		size_t hostlen = httpserver_INFO2(server, "hostname", &host);
		if (hostlen == 0)
		{
			hostlen = httpmessage_REQUEST2(request, "addr", &host);
		}
		httpmessage_appendheader(response, str_location, host, hostlen);
		const char *port = NULL;
		size_t portlen = httpserver_INFO2(server, "port", &port);
		if (portlen != 0)
		{
			httpmessage_appendheader(response, str_location, STRING_REF(":"));
			httpmessage_appendheader(response, str_location, port, portlen);
		}
		httpmessage_appendheader(response, str_location, uri, urilen);
	}
	if (query && query[0] != '\0')
	{
		httpmessage_appendheader(response, str_location, &sep, 1);
		httpmessage_appendheader(response, str_location, query, querylen);
	}

	ret = ESUCCESS;

	return ret;
}

static int _authn_challenge(_mod_auth_ctx_t *ctx, http_message_t *request, http_message_t *response)
{
	int ret = ECONTINUE;
	const _mod_auth_t *mod = ctx->mod;
	const mod_auth_t *config = mod->config;
	const char *uri = httpmessage_REQUEST(request, "uri");

	if (mod->authn->ctx)
	{
		ret = mod->authn->rules->challenge(mod->authn->ctx, request, response);
	}
	else
	{
		err("auth: error during configuration, server locked");
		httpmessage_result(response, RESULT_511);
		ret = ESUCCESS;
	}
	if (ret == ECONTINUE)
	{
		/// In MFA usage, the second step may set a challenge but the
		/// cookie contains information for the first step and we should to keep it
		/// In normal usage the challenge is set before any Cookie creation.
		/// If the token is present and we have a challenge, the cookie is bad.
		/// But it is not dangerous to keep it, because we send a new challenge.
#if 0
		/// ---reset the Cookie to remove it on the client---
		if (mod->authn->type & AUTHN_COOKIE_E)
			ouimessage_setcookie(response, str_xtoken, "", ";Max-Age=0", NULL);
#endif

		ret = ESUCCESS;
		auth_dbg("auth: challenge failed");
		const char *X_Requested_With = httpmessage_REQUEST(request, "X-Requested-With");
		if (X_Requested_With && strstr(X_Requested_With, "XMLHttpRequest") != NULL)
		{
			/// request from XMLHttpRequest was coming from JS script.
			/// The page tried an authentication and want to stay on top.
			httpmessage_result(response, RESULT_403);
		}
		else if (!string_empty(&config->redirect))
		{
			int protect = 1;
			/**
			 * check the url redirection
			 */
			protect = string_contain(&config->redirect, uri, -1, '?')?EREJECT:ESUCCESS;
			if (protect == ESUCCESS)
			{
				/**
				 * the request URI is the URL of the redirection
				 * the authentication has to accept (this module
				 * reject to manage the request and another module
				 * should send response to the request.
				 */
				warn("auth: accept redirection on challenge");
				httpmessage_result(response, RESULT_200);
				ret = EREJECT;
			}
			else
			{
				ret = auth_redirect_uri(ctx, request, response);
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

static int _authn_checkuri(const mod_auth_t *config, http_message_t *request, http_message_t *response)
{
	const char *uri = httpmessage_REQUEST(request, "uri");
	int ret = ECONTINUE;
	int protect = 1;

	/// the access to home file needs an authorization
	if (strchr(uri, '~') != NULL)
		return ret;
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
	protect = utils_searchexp(uri, config->token_ep.data, NULL);
	if (protect == ESUCCESS)
	{
		auth_dbg("protected uri %s", config->token_ep.data);
		httpmessage_result(response, RESULT_403);
		ret = ESUCCESS;
	}
	return ret;
}

static int auth_saveinfo(void *arg, const char *key, size_t keylen, const char *value, size_t valuelen)
{
	int ret = ECONTINUE;
	http_client_t *clt = (http_client_t *)arg;

	httpclient_session(clt, key, keylen, value, valuelen);
	return ret;
}

static int _auth_prepareresponse(_mod_auth_ctx_t *ctx, http_message_t *request, http_message_t *response,
					const string_t *authorization)
{
	const _mod_auth_t *mod = ctx->mod;
	const mod_auth_t *config = mod->config;

	string_t *token = NULL;
	string_t *sign = NULL;
#ifdef AUTH_TOKEN
	if (config->authz.type & AUTHZ_TOKEN_E)
	{
		token = ctx->token.generate(ctx->token.ctx, request);
	}
	if (!string_empty(token) && config->authz.type & AUTHZ_TOKEN_E)
	{
		sign = _authn_signtoken(&mod->config->token.secret, token);

		char strexpire[100];
		size_t lenexpire = snprintf(strexpire, 100, "max-age=%lu, must-revalidate", config->token.expire * 60);
		httpmessage_addheader(response, str_cachecontrol, strexpire, lenexpire);
	}
#endif

	if (mod->authn->type & AUTHN_HEADER_E)
	{
		_authn_setauthorization_header(ctx, authorization, token, sign, response);
	}
	else if (mod->authn->type & AUTHN_COOKIE_E)
	{
		_authn_setauthorization_cookie(ctx, authorization, token, sign, response);
	}

	if (mod->authz->type & AUTHZ_CHOWN_E)
	{
		const char *user = auth_info(request, STRING_REF(str_user));
		ouistiti_setprocessowner(user);
	}
	if (token)
		string_destroy(token);
	if (sign)
		string_destroy(sign);
	return ESUCCESS;
}

static int _authn_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = ECONTINUE;
	_mod_auth_ctx_t *ctx = (_mod_auth_ctx_t *)arg;
	const _mod_auth_t *mod = ctx->mod;
	mod_auth_t *config = mod->config;
	string_t authorization = {0};
	const char *user = NULL;
	string_t token = {0};
	string_t issuer = {0};

	auth_dbg("auth: check for %s (%s)", string_toc(&config->token.issuer),string_toc(&config->authz.name));

	ouimessage_SESSION(request, str_issuer, &issuer);
	if (!string_contain(&issuer, string_toc(&config->token.issuer), string_length(&config->token.issuer), '+'))
	{
		ret = EREJECT;
		auth_info2(request, str_user, &user);
		string_store(&authorization, string_toc(&config->token.issuer), string_length(&config->token.issuer));
		dbg("auth: session already set for this %.*s issuer", string_length(&config->token.issuer), string_toc(&config->token.issuer));
	}


	/**
	 * authz may need setup the user setting for each message
	 **/
	authz_t *authz = mod->authz;
	if(ctx->authz.ctx)
	{
		authz = &ctx->authz;
	}

#ifdef AUTH_TOKEN
	if (mod->authn->type & AUTHN_TOKEN_E || authz->type & AUTHZ_TOKEN_E)
	{
		_authn_gettoken(ctx, request, &token, &authorization);
		auth_dbg("auth: gettoken %s / %s", string_toc(&token), string_toc(&authorization));
		if (mod->authn->ctx && !string_empty(&authorization) && !string_empty(&token))
		{
			/// the signature is concated to the end of token
			/// only the token part must be checked
			/// remove the signature and the leading dot to the tokenlen
			if (authn_checktoken( ctx, authz, &token, &authorization, &user) == ESUCCESS)
			{
				ret = EREJECT;
			}
			else
				string_slice(&token, 0, 0);
			auth_dbg("auth: checktoken %d", ret);
		}
	}
	else
		warn("auth: token not checked. Configure (%s) token or jwt", string_toc(&config->token.issuer));
#endif
	if (ret == ECONTINUE)
	{
		/**
		 * The header WWW-Authenticate inside the request
		 * allows to disconnect the user.
		 */
		ouimessage_REQUEST(request, str_authenticate, &authorization);
		if (!string_empty(&authorization))
		{
			ret = ESUCCESS;
		}
		auth_dbg("auth: authenticate %d", ret);
	}

	if (ret == ECONTINUE)
	{
		ret = _authn_check(ctx, authz, request, &authorization, &user);
		auth_dbg("auth: checkauthorization %d", ret);
	}
	if (ret == EREJECT)
	{
		const char *sessionuser = NULL;
		auth_info2(request, str_user, &sessionuser);
		if (sessionuser && strcmp(user, sessionuser))
		{
			httpmessage_result(response, RESULT_500);
			ret = ESUCCESS;
		}
	}

	if (ret == ECONTINUE)
	{
		/// any authorization doesn't satisfy the authentication
		string_slice(&authorization, 0, 0);
		ret = _authn_checkuri(config, request, response);
		auth_dbg("auth: checkuri %d", ret);
	}

	if (ret != EREJECT)
	{
		httpclient_dropsession(ctx->clt);
		err("auth: %s rejects autorisation for %s", string_toc(&config->token.issuer), user);
		ret = _authn_challenge(ctx, request, response);
	}
	else if (!string_empty(&authorization))
	{
		if (httpclient_setsession(ctx->clt, string_toc(&authorization), -1) >= 0)
		{
			auth_dbg("auth: set the session");
			// The first MFA authenticator must know the group, and status
			// the next authenticator haven't to modify this values
			if (authz->rules->setsession)
				authz->rules->setsession(authz->ctx, user, string_toc(&token), auth_saveinfo, ctx->clt);
			httpclient_session(ctx->clt, STRING_REF(str_issuer), STRING_INFO(config->token.issuer));
			if (authz->rules->join)
			{
				authz->rules->join(authz->ctx, user, string_toc(&authorization), mod->config->token.expire);
			}
		}
		else if (string_contain(&issuer, string_toc(&config->token.issuer), string_length(&config->token.issuer), '+'))
		{
			httpclient_appendsession(ctx->clt, str_issuer, "+", 1);
			httpclient_appendsession(ctx->clt, str_issuer, STRING_INFO(config->token.issuer));
		}
		ouimessage_SESSION(request, str_issuer, &issuer);
		char issuerdata[254] = {0};
		size_t length = 0;
		if (authz->rules->issuer)
			length = authz->rules->issuer(authz->ctx, user, issuerdata, sizeof(issuerdata));
		if (length > 0 &&
			string_contain(&issuer, issuerdata, length, '+'))
		{
			httpclient_appendsession(ctx->clt, str_issuer, "+", 1);
			httpclient_appendsession(ctx->clt, str_issuer, issuerdata, length);
		}
		ouimessage_SESSION(request, str_issuer, &issuer);
		dbg("auth: type %.*s", string_length(&issuer), string_toc(&issuer));
		const char *user = auth_info(request, STRING_REF(str_user));
		string_t status = {0};
		ouimessage_SESSION(request, str_status, &status);
		if (!string_cmp(&status, str_status_reapproving, -1))
		{
			warn("auth: user \"%s\" accepted from %p to change password", user, ctx->clt);
			httpclient_session(ctx->clt, STRING_REF(str_group), STRING_REF(str_status_reapproving));
			ret = EREJECT;
		}
		else if (string_cmp(&status, str_status_activated, -1) != 0)
		{
			err("auth: user \"%s\" is not yet activated (%s) from %p", user, status, ctx->clt);
			httpclient_dropsession(ctx->clt);
			return _authn_challenge(ctx, request, response);
		}
		else
		{
			string_t tempo = {0};
			ouimessage_SESSION(request, str_issuer, &tempo);
			warn("auth: user \"%s\" accepted for %s from %p", user, string_toc(&tempo), ctx->clt);
			ret = EREJECT;
		}
		_auth_prepareresponse(ctx, request, response, &authorization);
	}
	else
	{
		warn("auth: accepted without authorization (unprotect files, shortcut,...) from %p", ctx->clt);
	}
	/**
	 * As the setup, the authz may need to cleanup between each message
	 **/
	if (authz->ctx  && authz->rules->cleanup)
	{
		authz->rules->cleanup(authz->ctx);
		authz->ctx = NULL;
	}
	return ret;
}

const module_t mod_auth =
{
	.version = 0x01,
	.name = str_auth,
	.configure = (module_configure_t)&auth_config,
	.create = (module_create_t)&mod_auth_create,
	.destroy = &mod_auth_destroy
};

#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_auth")));
#endif
