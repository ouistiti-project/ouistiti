/*****************************************************************************
 * authz_jwt.c: Check Authentication on passwd file
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

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

//#include <mbedtls/md.h>
#include <jansson.h>

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/hash.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
#include "authz_jwt.h"

#define auth_dbg(...)

//#define FILE_MMAP
#define MAXLENGTH 255

typedef struct authz_mod_s authz_mod_t;
struct authz_mod_s
{
	authtoken_config_t *config;
	string_t *issuer;
};

typedef struct authz_ctx_s authz_ctx_t;
struct authz_ctx_s
{
	authz_mod_t *mod;
	const char *token;
	string_t *user;
};

#ifdef FILE_CONFIG
#include <libconfig.h>
void *authz_jwt_config(const void *configauth, authz_type_t *type)
{
	const char *name = NULL;
	int ret = config_setting_lookup_string(configauth, "authz", &name);
	if (ret != CONFIG_TRUE)
		ret = config_setting_lookup_string(configauth, "options", &name);
	if (ret != CONFIG_TRUE || utils_searchexp("jwt", name, NULL) != ESUCCESS)
		return NULL;

	authtoken_config_t *authz_config = calloc(1, sizeof(*authz_config));
	const char *issuer = NULL;
	*type |= AUTHZ_JWT_E;

	ret = config_setting_lookup_string(configauth, str_issuer, &issuer);
	if (ret == CONFIG_TRUE)
	{
		string_store(&authz_config->issuer, issuer, -1);
	}
	return authz_config;
}
#endif

string_t *authz_jwt_generatetoken(authtoken_ctx_t *ctx, http_message_t *request)
{
	const authtoken_config_t *config = ctx->config;
#ifdef JWT_FORMATHEADER
	json_t *jheader = json_object();
	json_object_set(jheader, "alg", json_string("HS256"));
	json_object_set(jheader, "typ", json_string("JWT"));
	char *theader = json_dumps(jheader, 0);
	size_t theaderlen = strlen(theader);
	json_decref(jheader);
#else
	char theader[] = "{\"alg\": \"HS256\", \"typ\": \"JWT\"}";
	size_t theaderlen = sizeof(theader) - 1;
#endif

	size_t len = 0;
	json_t *jtoken = json_object();
	const char *info = NULL;
	len = auth_info2(request, str_user, &info);
	if (len > 0)
	{
		json_t *juser = json_stringn(info, len);
		json_object_set(jtoken, str_user, juser);
	}
	len = auth_info2(request, str_home, &info);
	if (len > 0)
	{
		json_t *jhome = json_stringn(info, len);
		json_object_set(jtoken, str_home, jhome);
	}
	len = auth_info2(request, str_status, &info);
	if (len > 0)
	{
		json_t *jstatus = json_stringn(info, len);
		json_object_set(jtoken, str_status, jstatus);
	}
	len = auth_info2(request, str_group, &info);
	if (len > 0)
	{
		json_t *jroles = json_stringn(info, len);
		json_object_set(jtoken, "roles", jroles);
	}
#ifndef DEBUG
	time_t now = time(NULL);
#else
	time_t now = 0;
#endif
	json_t *jexpire = NULL;
	if (config->expire > 0)
	{
		jexpire = json_integer((config->expire * 60) + now);
	}
	else
		jexpire = json_integer((30 * 60) + now);
	json_object_set(jtoken, "exp", jexpire);
	const char *issuer = NULL;
	len = auth_info2(request, str_issuer, &issuer);

	if (issuer)
		json_object_set(jtoken, "iss", json_stringn(issuer, len));
#ifdef AUTH_OPENID
	json_object_set(jtoken, "sub", juser);
	json_object_set(jtoken, "preferred_username", juser);
	json_object_set(jtoken, "aud", json_string(str_servername));
	json_object_set(jtoken, "iat", json_integer(now));
#endif
	size_t ttokenlen = json_dumpb(jtoken, NULL, 0, 0);
	if (ttokenlen == 0)
		return NULL;
	char *ttoken = malloc(ttokenlen);
	json_dumpb(jtoken, ttoken, ttokenlen, 0);
	auth_dbg("jwt: encode %.*s", ttokenlen, ttoken);
	json_decref(jtoken);

	size_t ret = 0;
	size_t length = (theaderlen + 1 + ttokenlen + 1);

	string_t *token = string_create((length * 5) / 3);
	char *offset = string_storage(token);
	length = string_size(token);
	ret = base64_urlencoding->encode(theader, theaderlen, offset, length);
	offset += ret;
	length -= ret;
#ifdef JWT_FORMATHEADER
	free(theader);
#endif

	*offset = '.';
	offset++;
	ret++;
	length--;

	ret += base64_urlencoding->encode(ttoken, ttokenlen, offset, length);
	free(ttoken);
	string_slice(token, 0, ret);
	warn("auth: jwttoken %s", string_toc(token));
	/**
	 * the signature is added inside mod_auth
	 */
	return token;
}

static json_t *jwt_decode_json(const char *id_token, int header)
{
	if (id_token == NULL)
		return NULL;
	const char *b64header = id_token;
	int length = 0;
	json_error_t error;
	char data[1024] = {0};
	json_t *jpayload = NULL;

	const char *b64payload = strchr(b64header, '.');
	long b64payloadlength = 0;
	const char *b64signature = strrchr(b64header, '.');
	if (b64payload == NULL)
		return NULL;

	b64payload++;
	b64payloadlength = b64signature - b64payload;

	if (header)
	{
#ifdef AUTHZ_JWT_CHECKHEADER
		long b64headerlength = 0;
		b64headerlength = b64payload - b64header;
		length = base64_urlencoding->decode(b64header, b64headerlength, data, 1024);
		dbg("id_token header %s", data);
		jpayload = json_loadb(data, length, 0, &error);
		if (jpayload == NULL)
		{
			err("jwt: token error %s", error.text);
		}
#endif
	}
	else
	{
		length = base64_urlencoding->decode(b64payload, b64payloadlength, data, 1024);
		auth_dbg("jwt: decode %s", data);
		jpayload = json_loadb(data, length, 0, &error);
		if (jpayload == NULL)
			err("jwt: decode error %s", error.text);
	}
	return jpayload;
}

static int _jwt_checkexpiration(const json_t *jinfo)
{
	const json_t *jexpire = json_object_get(jinfo, "exp");
	if (jexpire && json_is_integer(jexpire))
	{
		time_t expire = json_integer_value(jexpire);
#ifndef DEBUG
		time_t now = time(NULL);
#else
		time_t now = 1800; // 30 * 60 (set by default
#endif
		if (expire < now)
		{
			err("auth: jwt expired");
			return EREJECT;
		}
	}
	else
	{
		warn("auth: jwt doesn't contain exp");
		return EREJECT;
	}
	return ESUCCESS;
}

static int _jwt_get(const json_t *jinfo, const char *key, string_t *value)
{
	const json_t *jvalue = json_object_get(jinfo, key);
	if (jvalue && json_is_string(jvalue))
	{
		string_store(value, json_string_value(jvalue), json_string_length(jvalue));
		return ESUCCESS;
	}
	return EREJECT;
}

static int _jwt_getuser(const json_t *jinfo, string_t *user)
{
	int ret = _jwt_get(jinfo, str_user, user);
	if (ret == EREJECT)
		ret = _jwt_get(jinfo, "preferred_username", user);
	if (ret == EREJECT)
		ret = _jwt_get(jinfo, "name", user);
	if (ret == EREJECT)
		ret = _jwt_get(jinfo, "username", user);
	if (ret == EREJECT)
		ret = string_store(user, str_anonymous, -1);
	return ret;
}

#if 0
/// unused function
int authz_jwt_get(const char *id_token, const char *key, string_t *value)
{
	const json_t *jinfo = jwt_decode_json(id_token, 0);
	if (jinfo == NULL)
		return EREJECT;
	if (!strcmp(key, str_user))
		return _jwt_getuser(jinfo, value);
	if (!strcmp(key, str_issuer))
		return _jwt_get(jinfo, "iss", value);
	return _jwt_get(jinfo, key, value);
}
#endif

int authz_jwt_getinfo(const char *id_token, string_t *user, string_t *issuer)
{
	const json_t *jinfo = jwt_decode_json(id_token, 0);
	if (jinfo == NULL)
		return EREJECT;
	_jwt_getuser(jinfo, user);
	_jwt_get(jinfo, "iss", issuer);
	return 0;
}

static void *authz_jwt_create(http_server_t *UNUSED(server), string_t *issuer, void *arg)
{
	authz_mod_t *ctx = NULL;
	authtoken_config_t *config = (authtoken_config_t *)arg;

	ctx = calloc(1, sizeof(*ctx));
	ctx->config = config;
	ctx->issuer = issuer;

	return ctx;
}

static void *authz_jwt_setup(void *arg, http_client_t *clt, struct sockaddr *addr, int addrsize)
{
	authz_mod_t *mod = (authz_mod_t *)arg;
	authz_ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->mod = mod;
	ctx->user = string_create(USER_MAX);
	return ctx;
}

static int _authn_jwt_checktoken(const string_t *issuer, const char *token, json_t *jinfo)
{
	int ret = EREJECT;
	if (jinfo != NULL)
	{
		if (_jwt_checkexpiration(jinfo) != ESUCCESS)
		{
			return EREJECT;
		}
		string_t iss = {0};
		_jwt_get(jinfo, "iss", &iss);
		if (string_contain(&iss, string_toc(issuer), string_length(issuer), '+'))
		{
			err("auth: token with bad issuer: %s / %s",  string_toc(&iss), string_toc(issuer));
			return EREJECT;
		}
		ret = ESUCCESS;
	}
#ifdef AUTHZ_JWT_CHECKHEADER
	jinfo = jwt_decode_json(token, 1);
	if (jinfo != NULL)
	{
		const json_t *jtype = json_object_get(jinfo, "typ");
		if (jtype == NULL || !json_is_string(jtype) || strncmp(json_string_value(jtype), "JWT", 3))
		{
			err("auth: token is not jwt");
			json_decref(jinfo);
			ret = EREJECT;
		}
		const json_t *jalg = json_object_get(jinfo, "alg");
		if (jalg == NULL || !json_is_string(jalg) || strncmp(json_string_value(jalg), "HS256", 3))
		{
			err("auth: jwt support only Hmac sha256");
			json_decref(jinfo);
			ret = EREJECT;
		}
	}
	else
		ret = EREJECT;
#endif
	return ret;
}

int authz_jwt_checktoken(authtoken_ctx_t *ctx, const string_t *token, const char **user)
{
	json_t *jinfo = jwt_decode_json(string_toc(token), 0);
	int ret = _authn_jwt_checktoken(&ctx->config->issuer, string_toc(token), jinfo);
	string_t tuser = {0};
	_jwt_getuser(jinfo, &tuser);
	ctx->user = string_dup(&tuser);
	if (user)
		*user = string_toc(ctx->user);
	json_decref(jinfo);
	return ret;
}

static const char *authz_jwt_check(void *arg, const char *UNUSED(user), const char *UNUSED(passwd), const char *token)
{
	authz_ctx_t *ctx = (authz_ctx_t *)arg;
	json_t *jinfo = jwt_decode_json(token, 0);
	if (_authn_jwt_checktoken(ctx->mod->issuer, token, jinfo) == ESUCCESS)
	{
		ctx->token = token;
		_jwt_getuser(jinfo, ctx->user);
		json_decref(jinfo);
		return string_toc(ctx->user);
	}
	json_decref(jinfo);
	return NULL;
}

static int authz_jwt_setsession(void *arg, const char *user, const char *token, auth_saveinfo_t cb, void *cbarg)
{
	const authz_ctx_t *ctx = (const authz_ctx_t *)arg;
	if (token == NULL)
		token = ctx->token;
	json_t *jinfo = jwt_decode_json(token, 0);
	if (jinfo == NULL)
		return EREJECT;

	const json_t *jhome = json_object_get(jinfo, str_home);
	if (jhome && json_is_string(jhome))
	{
		cb(cbarg, STRING_REF(str_home), json_string_value(jhome), -1);
	}

	const json_t *jroles = json_object_get(jinfo, "roles");
	if (jroles && json_is_string(jroles))
	{
		cb(cbarg, STRING_REF(str_group), json_string_value(jroles), -1);
	}
	else if (jroles && json_is_array(jroles))
	{
		cb(cbarg, STRING_REF(str_group), json_string_value(json_array_get(jroles, 0)), -1);
	}
	else
	{
		cb(cbarg, STRING_REF(str_group), STRING_REF(str_anonymous));
	}
	const json_t *jstatus = json_object_get(jinfo, str_status);
	if (jstatus && json_is_string(jstatus))
	{
		cb(cbarg, STRING_REF(str_status), json_string_value(jstatus), -1);
	}
	string_t tuser = {0};
	_jwt_getuser(jinfo, &tuser);
	cb(cbarg, STRING_REF(str_user), string_toc(&tuser), string_length(&tuser));

	const json_t *jexpire = json_object_get(jinfo, "exp");
	if (jexpire && json_is_integer(jexpire))
	{
		time_t expire = json_integer_value(jexpire);
		struct tm *tmp;
		char expire_str[16] = {0};
		tmp = localtime(&expire);
		size_t length = strftime(expire_str, sizeof(expire_str), "%s", tmp);
		if (length > 0)
			cb(cbarg, STRING_REF("expire"), expire_str, length);
	}

	json_decref(jinfo);

	return ESUCCESS;
}

#ifdef AUTH_TOKEN
static int authz_jwt_join(void *arg, const char *user, const char *UNUSED(token), int expire)
{
	return ESUCCESS;
}
#else
#define authz_jwt_join NULL
#endif

static void authz_jwt_cleanup(void *arg)
{
	authz_ctx_t *ctx = (authz_ctx_t *)arg;
	string_destroy(ctx->user);
	free(ctx);
}
static void authz_jwt_destroy(void *arg)
{
	authz_mod_t *ctx = (authz_mod_t *)arg;
	free(ctx->config);
	free(ctx);
}

authz_rules_t authz_jwt_rules =
{
	.config = authz_jwt_config,
	.create = authz_jwt_create,
	.setup = authz_jwt_setup,
	.check = authz_jwt_check,
	.passwd = NULL,
	.setsession = authz_jwt_setsession,
	.join = authz_jwt_join,
	.cleanup = authz_jwt_cleanup,
	.destroy = authz_jwt_destroy,
};

static const string_t authz_name = STRING_DCL("jwt");
static void __attribute__ ((constructor)) _init()
{
	auth_registerauthz(&authz_name, &authz_jwt_rules);
}
