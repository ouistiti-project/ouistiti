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
#include "ouistiti/hash.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
#include "authz_jwt.h"

#define HASH_MAX_SIZE 32

#define auth_dbg(...)

//#define FILE_MMAP
#define MAXLENGTH 255

typedef struct authz_jwt_s authz_jwt_t;
struct authz_jwt_s
{
	authz_jwt_config_t *config;
	const char *token;
};

#ifdef FILE_CONFIG
void *authz_jwt_config(const config_setting_t *UNUSED(configauth))
{
	authz_jwt_config_t *authz_config = calloc(1, sizeof(*authz_config));
	return authz_config;
}
#endif

char *authz_generatejwtoken(const mod_auth_t *config, http_message_t *request)
{
	json_t *jheader = json_object();
	json_object_set(jheader, "alg", json_string("HS256"));
	json_object_set(jheader, "typ", json_string("JWT"));
	char *theader = json_dumps(jheader, 0);
	json_decref(jheader);

	json_t *jtoken = json_object();
	const char *user = auth_info(request, STRING_REF("user"));
	if (user)
	{
		json_t *juser = json_string(user);
		json_object_set(jtoken, "user", juser);
	}
	const char *home = auth_info(request, STRING_REF("home"));
	if (home)
	{
		json_t *jhome = json_string(home);
		json_object_set(jtoken, "home", jhome);
	}
	const char *status = auth_info(request, STRING_REF("status"));
	if (status)
	{
		json_t *jstatus = json_string(status);
		json_object_set(jtoken, "status", jstatus);
	}
	const char *group = auth_info(request, STRING_REF("group"));
	if (group)
	{
		json_t *jroles = json_string(group);
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
#ifdef AUTH_OPENID
	json_object_set(jtoken, "sub", juser);
	json_object_set(jtoken, "preferred_username", juser);
	json_object_set(jtoken, "aud", json_string("ouistiti"));
	json_object_set(jtoken, "iat", json_integer(now));
	if (info->urlspace && info->urlspace[0] != '\0')
		json_object_set(jtoken, "iss", json_string(info->urlspace));
#endif
	char *ttoken = json_dumps(jtoken, 0);
	auth_dbg("jwt: encode %s", ttoken);
	json_decref(jtoken);

	int ret;
	size_t length = (strlen(theader) + 1 + strlen(ttoken) + 1) * 3 / 2;

	char *token = calloc(2, length + 1);
	char *offset = token;
	length *= 2;
	ret = base64_urlencoding->encode(theader, strlen(theader), offset, length);
	offset += ret;
	length -= ret;
	free(theader);

	*offset = '.';
	offset++;
	length--;

	ret = base64_urlencoding->encode(ttoken, strlen(ttoken), offset, length);
	free(ttoken);
	warn("token %s", token);
	/**
	 * the signature is added inside mod_auth
	 */
	return token;
}

static json_t *jwt_decode_json(const char *id_token)
{
	if (id_token == NULL)
		return NULL;
	const char *b64header = id_token;
	const char *b64payload = strchr(b64header, '.');
	long b64payloadlength = 0;
	const char *b64signature = strrchr(b64header, '.');
	int length = 0;
	json_error_t error;
	char data[1024] = {0};

	if (b64payload != NULL)
	{
		b64payload++;
#if 0
		long b64headerlength = 0;
		b64headerlength = b64payload - b64header;
		length = base64_urlencoding->decode(b64header, b64headerlength, data, 1024);
		auth_dbg("id_token header %s", data);
		json_t *jheader = json_loadb(data, length, 0, &error);
		if (jheader != NULL)
		{
			json_decref(jheader);
		}
		else
		{
			err("oAuth2 id token error %s", error.text);
		}
#endif
		b64payloadlength = b64signature - b64payload;
	}

	json_t *jpayload = NULL;
	length = base64_urlencoding->decode(b64payload, b64payloadlength, data, 1024);
	auth_dbg("jwt: decode %s", data);
	jpayload = json_loadb(data, length, 0, &error);
	if (jpayload == NULL)
		err("jwt: decode error %s", error.text);
	return jpayload;
}

static int _jwt_checkexpiration(json_t *jinfo, authsession_t *authsession)
{
	const json_t *jexpire = json_object_get(jinfo, "exp");
	if (jexpire && json_is_integer(jexpire))
	{
		time_t expire = json_integer_value(jexpire);
#ifndef DEBUG
		time_t now = time(NULL);
#else
		time_t now = 0;
#endif
		if (expire > now)
			authsession->expires = expire;
		else
		{
			warn("auth: jwt expired");
#ifndef DEBUG
			return EREJECT;
#else
			err("auth: DEBUG is unsecure please rebuild as release");
#endif
		}
	}
	else
	{
		warn("auth: jwt doesn't contain exp");
		return EREJECT;
	}
	return ESUCCESS;
}

static const char *_jwt_getuser(const json_t *jinfo)
{
	const char *user = NULL;
	const json_t *juser = json_object_get(jinfo, "preferred_username");
	if (juser && json_is_string(juser))
		user = json_string_value(juser);
	juser = json_object_get(jinfo, "username");
	if (juser && json_is_string(juser))
		user = json_string_value(juser);
	juser = json_object_get(jinfo, "user");
	if (juser && json_is_string(juser))
		user = json_string_value(juser);

	if (user == NULL || user[0] == '\0')
		user = str_anonymous;
	return user;
}

static void *authz_jwt_create(http_server_t *UNUSED(server), void *arg)
{
	authz_jwt_t *ctx = NULL;
	authz_jwt_config_t *config = (authz_jwt_config_t *)arg;

	ctx = calloc(1, sizeof(*ctx));
	ctx->config = config;

	return ctx;
}

static const char *_authz_jwt_checktoken(authz_jwt_t *ctx, const char *token)
{
	json_t *jinfo = jwt_decode_json(token);
	if (jinfo != NULL)
	{
		authsession_t authsession = {0};
		if (_jwt_checkexpiration(jinfo, &authsession) != ESUCCESS)
			return NULL;
		ctx->token = token;
		return _jwt_getuser(jinfo);
	}
	return NULL;
}

static const char *authz_jwt_check(void *arg, const char *UNUSED(user), const char *UNUSED(passwd), const char *token)
{
	authz_jwt_t *ctx = (authz_jwt_t *)arg;
	return _authz_jwt_checktoken(ctx, token);
}

static int authz_jwt_setsession(void *arg, const char *user, auth_saveinfo_t cb, void *cbarg)
{
	const authz_jwt_t *ctx = (const authz_jwt_t *)arg;
	const char *token = ctx->token;
	json_t *jinfo = jwt_decode_json(token);
	if (jinfo == NULL)
		return EREJECT;

	const json_t *jhome = json_object_get(jinfo, "home");
	if (jhome && json_is_string(jhome))
	{
		cb(cbarg, STRING_REF("home"), json_string_value(jhome), -1);
	}

	const json_t *jroles = json_object_get(jinfo, "roles");
	if (jroles && json_is_string(jroles))
	{
		cb(cbarg, STRING_REF("group"), json_string_value(jroles), -1);
	}
	else if (jroles && json_is_array(jroles))
	{
		cb(cbarg, STRING_REF("group"), json_string_value(json_array_get(jroles, 0)), -1);
	}
	else
	{
		cb(cbarg, STRING_REF("group"), STRING_REF(str_anonymous));
	}
	const json_t *jstatus = json_object_get(jinfo, "status");
	if (jstatus && json_is_string(jstatus))
	{
		cb(cbarg, STRING_REF("status"), json_string_value(jstatus), -1);
	}
	cb(cbarg, STRING_REF("user"), _jwt_getuser(jinfo), -1);

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

#ifdef AUTHN_OAUTH2
static int authz_jwt_adduser(void *arg, authsession_t *newuser)
{
	authz_jwt_t *ctx = (authz_jwt_t *)arg;
	memcpy(&ctx->token, newuser, sizeof(ctx->token));
	return ESUCCESS;
}
#endif

static void authz_jwt_destroy(void *arg)
{
	authz_jwt_t *ctx = (authz_jwt_t *)arg;
	free(ctx);
}

authz_rules_t authz_jwt_rules =
{
	.create = &authz_jwt_create,
	.check = &authz_jwt_check,
	.passwd = NULL,
	.setsession = &authz_jwt_setsession,
	.join = &authz_jwt_join,
	.destroy = &authz_jwt_destroy,
};
