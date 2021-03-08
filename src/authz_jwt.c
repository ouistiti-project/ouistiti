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

#include "httpserver/httpserver.h"
#include "httpserver/hash.h"
#include "httpserver/log.h"
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
	authsession_t token;
};

#ifdef FILE_CONFIG
void *authz_jwt_config(config_setting_t *configauth)
{
	authz_jwt_config_t *authz_config = calloc(1, sizeof(*authz_config));
	return authz_config;
}
#endif

char *authz_generatejwtoken(mod_auth_t *config, const authsession_t *info)
{
	json_t *jheader = json_object();
	json_object_set(jheader, "alg", json_string("HS256"));
	json_object_set(jheader, "typ", json_string("JWT"));
	char *theader = json_dumps(jheader, 0);

	json_t *jtoken = json_object();
	json_t *juser = json_string(info->user);
	json_object_set(jtoken, "user", juser);
	json_t *jhome = json_string(info->home);
	json_object_set(jtoken, "home", jhome);
	json_t *jstatus = json_string(info->status);
	json_object_set(jtoken, "status", jstatus);
	json_t *jroles = json_string(info->group);
	json_object_set(jtoken, "roles", jroles);
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

	int ret;
	size_t length = (strlen(theader) + 1 + strlen(ttoken) + 1) * 3 / 2;

	char *token = calloc(2, length + 1);
	char *offset = token;
	length *= 2;
	ret = base64_urlencoding->encode(theader, strlen(theader), offset, length);
	offset += ret;
	length -= ret;

	*offset = '.';
	offset++;
	length--;

	ret = base64_urlencoding->encode(ttoken, strlen(ttoken), offset, length);
	offset += ret;
	length = offset - token;
	err("token %s", token);
	/**
	 * the signature is added inside mod_auth
	 */
	return token;
}

json_t *jwt_decode_json(const char *id_token)
{
	if (id_token == NULL)
		return NULL;
	const char *b64header = id_token;
	int b64headerlength = 0;
	const char *b64payload = strchr(b64header, '.');
	int b64payloadlength = 0;
	const char *b64signature = strrchr(b64header, '.');
	int length = 0;
	json_error_t error;
	if (b64payload != NULL)
	{
		b64headerlength = b64payload - b64header;
		b64payload++;
	}
	char data[1024] = {0};
#if 0
	length = base64_urlencoding->decode(b64header, length, data, 1024);
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
	if (b64payload != NULL)
	{
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

int jwt_decode(const char *id_token, authsession_t *authsession)
{
	json_t *jinfo = jwt_decode_json(id_token);
	if (jinfo != NULL)
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
			if (expire < now)
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
		strncpy(authsession->user, user, USER_MAX);

		const json_t *jhome = json_object_get(jinfo, "home");
		if (jhome && json_is_string(jhome))
		{
			strncpy(authsession->home, json_string_value(jhome), PATH_MAX);
		}

		const json_t *jroles = json_object_get(jinfo, "roles");
		if (jroles && json_is_string(jroles))
		{
			strncpy(authsession->group, json_string_value(jroles), FIELD_MAX);
		}
		else if (jroles && json_is_array(jroles))
		{
			strncpy(authsession->group, json_string_value(json_array_get(jroles, 0)), FIELD_MAX);
		}
		else
		{
			strncpy(authsession->group, "anonymous", FIELD_MAX);
		}
		const json_t *jstatus = json_object_get(jinfo, "status");
		if (jstatus && json_is_string(jstatus))
		{
			strncpy(authsession->status, json_string_value(jstatus), FIELD_MAX);
		}

		json_decref(jinfo);
	}
	return ESUCCESS;
}

static void *authz_jwt_create(http_server_t *server, void *arg)
{
	authz_jwt_t *ctx = NULL;
	authz_jwt_config_t *config = (authz_jwt_config_t *)arg;

	ctx = calloc(1, sizeof(*ctx));
	ctx->config = config;

	return ctx;
}

static const char *_authz_jwt_checktoken(authz_jwt_t *ctx, const char *token)
{
	jwt_decode(token, &ctx->token);
	if (ctx->token.user[0] != '\0')
		return ctx->token.user;
	return NULL;
}

static const char *authz_jwt_check(void *arg, const char *UNUSED(user), const char *UNUSED(passwd), const char *token)
{
	authz_jwt_t *ctx = (authz_jwt_t *)arg;
	return _authz_jwt_checktoken(ctx, token);
}

static const char *authz_jwt_group(void *arg, const char *user)
{
	const authz_jwt_t *ctx = (const authz_jwt_t *)arg;
	if (ctx->token.group[0] != '\0')
		return ctx->token.group;
	return NULL;
}

static const char *authz_jwt_home(void *arg, const char *UNUSED(user))
{
	const authz_jwt_t *ctx = (const authz_jwt_t *)arg;
	if (ctx->token.home[0] != '\0')
		return ctx->token.home;
	return NULL;
}

static int authz_jwt_setsession(void *arg, const char *UNUSED(user), authsession_t *authsession)
{
	const authz_jwt_t *ctx = (const authz_jwt_t *)arg;
	memcpy(authsession, &ctx->token, sizeof(*authsession));
	return ESUCCESS;
}

#ifdef AUTH_TOKEN
static int authz_jwt_join(void *arg, const char *user, const char *UNUSED(token), int UNUSED(expire))
{
	const authz_jwt_t *ctx = (const authz_jwt_t *)arg;
	if (!strcmp(ctx->token.user, user))
		return ESUCCESS;
	return EREJECT;
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
	.setsession = &authz_jwt_setsession,
	.join = &authz_jwt_join,
	.destroy = &authz_jwt_destroy,
};
