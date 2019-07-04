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
#include "mod_auth.h"
#include "authz_jwt.h"

#define HASH_MAX_SIZE 32

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

//#define FILE_MMAP
#define MAXLENGTH 255

typedef struct authz_jwt_s authz_jwt_t;
struct authz_jwt_s
{
	authz_jwt_config_t *config;
	authsession_t *token;
};

int jwt_sign(const char *key, const char *input, size_t len, char *output)
{
	int ret = EREJECT;
	if (hash_macsha256 != NULL)
	{
		void *ctx = hash_macsha256->initkey(key, strlen(key));
		if (ctx)
		{
			hash_macsha256->update(ctx, input, len);
			char signature[HASH_MAX_SIZE];
			hash_macsha256->finish(ctx, signature);

			base64->encode(signature, HASH_MAX_SIZE, output, 64);

			char *offset = output;
			offset = strchr(offset, '=');
			if (offset)
			{
				*offset = '\0';
			}
			offset = strchr(output, '/');
			while (offset != NULL)
			{
				*offset = '_';
				offset = strchr(offset, '/');
			}
			ret = ESUCCESS;
		}
	}
	return ret;
}

char *authz_generatejwtoken(mod_auth_t *mod, authsession_t *info)
{
	json_t *jheader = json_object();
	json_object_set(jheader, "alg", json_string("HS256"));
	json_object_set(jheader, "typ", json_string("JWT"));
	char *theader = json_dumps(jheader, 0);

	json_t *jtoken = json_object();
	json_t *juser = json_string(info->user);
	json_object_set(jtoken, "user", juser);
	json_object_set(jtoken, "home", json_string(info->home));
	json_object_set(jtoken, "roles", json_string(info->group));
#ifdef AUTH_OPENID
	json_object_set(jtoken, "sub", juser);
	json_object_set(jtoken, "preferred_username", juser);
	json_object_set(jtoken, "aud", json_string("ouistiti"));
	time_t now = time(NULL);
	json_object_set(jtoken, "exp", json_integer(mod->expire + now));
	json_object_set(jtoken, "iat", json_integer(now));
	if (info->urlspace && info->urlspace[0] != '\0')
		json_object_set(jtoken, "iss", json_string(info->urlspace));
#endif
	char *ttoken = json_dumps(jtoken, 0);

	int ret;
	int length = strlen(theader) + 1 + strlen(ttoken) + 1;
	char *token = calloc(2, length + 32);
	char *offset = token;
	length *= 2;
	ret = base64->encode(theader, strlen(theader), offset, length);
	offset += ret;
	length -= ret;

	*offset = '.';
	offset++;
	length--;

	ret = base64->encode(ttoken, strlen(ttoken), offset, length);
	offset += ret;
	length = offset - token;
	*offset = '.';
	offset++;

	ret = jwt_sign(mod->secret, token, length, offset);
	err("token %s", token);

	return token;
}

json_t *jwt_decode_json(const char *id_token, const char *key)
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
	length = base64->decode(b64header, length, data, 1024);
	dbg("id_token header %s", data);
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

	int ret = EREJECT;
	char b64signature2[64] = {0};
	if (b64signature != NULL)
	{

		ret = jwt_sign(key, b64header, b64signature - b64header, b64signature2);

		b64payloadlength = b64signature - b64payload;
		b64signature++;
	}
	if (ret == ESUCCESS)
	{

		if (strcmp(b64signature2, b64signature))
		{
			err("jwt token signature failed %s / %s", b64signature2, b64signature);
			ret = EREJECT;
		}
	}
	json_t *jpayload = NULL;
#ifndef AUTHZ_JWT_SIGNNOTCHECK
	if (ret == ESUCCESS)
#endif
	{
		length = base64->decode(b64payload, b64payloadlength, data, 1024);
		dbg("JWT: %s", data);
		jpayload = json_loadb(data, length, 0, &error);
	}
	return jpayload;
}

authsession_t *jwt_decode(const char *id_token, const char *key)
{
	authsession_t *authsession = NULL;
	json_t *jinfo = jwt_decode_json(id_token, key);
	if (jinfo != NULL)
	{
		authsession = calloc(1, sizeof(*authsession));
		const char *user = NULL;
		json_t *juser = json_object_get(jinfo, "preferred_username");
		if (juser && json_is_string(juser))
			user = json_string_value(juser);
		juser = json_object_get(jinfo, "username");
		if (juser && json_is_string(juser))
			user = json_string_value(juser);
		juser = json_object_get(jinfo, "user");
		if (juser && json_is_string(juser))
			user = json_string_value(juser);
		if (user == NULL)
			user = str_anonymous;
		strncpy(authsession->user, user, sizeof(authsession->user));

		json_t *jhome = json_object_get(jinfo, "home");
		if (jhome && json_is_string(jhome))
		{
			strncpy(authsession->home, json_string_value(jhome), sizeof(authsession->home));
		}

		json_t *jroles = json_object_get(jinfo, "roles");
		if (jroles && json_is_string(jroles))
		{
			strncpy(authsession->group, json_string_value(jroles), sizeof(authsession->group));
		}
		else if (jroles && json_is_array(jroles))
		{
			strncpy(authsession->group, json_string_value(json_array_get(jroles, 0)), sizeof(authsession->group));
		}
		else
		{
			strncpy(authsession->group, "anonymous", sizeof(authsession->group));
		}

		json_decref(jinfo);
	}
	return authsession;
}

static void *authz_jwt_create(void *arg)
{
	authz_jwt_t *ctx = NULL;
	authz_jwt_config_t *config = (authz_jwt_config_t *)arg;

	ctx = calloc(1, sizeof(*ctx));
	ctx->config = config;

	return ctx;
}

static const char *_authz_jwt_checktoken(authz_jwt_t *ctx, const char *token)
{
	if (ctx->token == NULL)
		ctx->token = jwt_decode(token, ctx->config->key);
	if (ctx->token != NULL)
		return ctx->token->user;
	return NULL;
}

static const char *authz_jwt_check(void *arg, const char *user, const char *passwd, const char *token)
{
	authz_jwt_t *ctx = (authz_jwt_t *)arg;
	return _authz_jwt_checktoken(ctx, token);
}

static const char *authz_jwt_group(void *arg, const char *user)
{
	authz_jwt_t *ctx = (authz_jwt_t *)arg;
	if (ctx->token)
		return ctx->token->group;
	return NULL;
}

static const char *authz_jwt_home(void *arg, const char *user)
{
	authz_jwt_t *ctx = (authz_jwt_t *)arg;
	if (ctx->token)
		return ctx->token->home;
	return NULL;
}

static void authz_jwt_destroy(void *arg)
{
	authz_jwt_t *ctx = (authz_jwt_t *)arg;

	free(ctx->token);
	free(ctx);
}

authz_rules_t authz_jwt_rules =
{
	.create = authz_jwt_create,
	.check = authz_jwt_check,
	.group = authz_jwt_group,
	.home = authz_jwt_home,
	.destroy = authz_jwt_destroy,
};
