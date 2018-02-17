/*****************************************************************************
 * authz_sqlite.c: Check Authentication on passwd file
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
#include <sqlite3.h>

#include "httpserver/httpserver.h"
#include "mod_auth.h"
#include "authz_sqlite.h"

#if defined(MBEDTLS)
# include <mbedtls/base64.h>
# define BASE64_encode(in, inlen, out, outlen) \
	do { \
		size_t cnt = 0; \
		mbedtls_base64_encode(out, outlen, &cnt, in, inlen); \
	}while(0)
# define BASE64_decode(in, inlen, out, outlen) \
	do { \
		size_t cnt = 0; \
		mbedtls_base64_decode(out, outlen, &cnt, in, inlen); \
	}while(0)
#else
# include "b64/cencode.h"
# define BASE64_encode(in, inlen, out, outlen) \
	do { \
		base64_encodestate state; \
		base64_init_encodestate(&state); \
		int cnt = base64_encode_block(in, inlen, out, &state); \
		cnt = base64_encode_blockend(out + cnt, &state); \
		out[cnt - 1] = '\0'; \
	}while(0)
#endif

#if defined(MBEDTLS)
# include <mbedtls/md5.h>
# define MD5_ctx mbedtls_md5_context
# define MD5_init(pctx) \
	do { \
		mbedtls_md5_init(pctx); \
		mbedtls_md5_starts(pctx); \
	} while(0)
# define MD5_update(pctx, in, len) \
	mbedtls_md5_update(pctx, in, len)
# define MD5_finish(out, pctx) \
	do { \
		mbedtls_md5_finish((pctx), out); \
		mbedtls_md5_free((pctx)); \
	} while(0)
#elif defined (MD5_RONRIVEST)
# include "../utils/md5-c/global.h"
# include "../utils/md5-c/md5.h"
# define MD5_ctx MD5_CTX
# define MD5_init MD5Init
# define MD5_update MD5Update
# define MD5_finish MD5Final
#else
# include "../utils/md5/md5.h"
# define MD5_ctx md5_state_t
# define MD5_init md5_init
# define MD5_update md5_append
# define MD5_finish(out, pctx) md5_finish(pctx, out)
#endif

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

typedef struct authz_sqlite_s authz_sqlite_t;
struct authz_sqlite_s
{
	authz_sqlite_config_t *config;
	sqlite3 *db;
};

void *authz_sqlite_create(void *arg)
{
	authz_sqlite_t *ctx = NULL;
	authz_sqlite_config_t *config = (authz_sqlite_config_t *)arg;

	sqlite3_open_v2(config->dbname, &ctx->db, SQLITE_OPEN_READWRITE, NULL);
	return ctx;
}

static char *authz_sqlite_search(authz_sqlite_t *ctx, char *user, char *field)
{
	char *value = NULL;
	sqlite3_stmt *statement;
	char *sql = "select @COLUMN from users where name=@NAME;";
	sqlite3_prepare_v2(ctx->db, sql, strlen(sql), &statement, NULL);
	int index = sqlite3_bind_parameter_index(statement, "@NAME");
	if (index > 0)
		sqlite3_bind_text(statement, index, user, -1, SQLITE_STATIC);
	index = sqlite3_bind_parameter_index(statement, "@COLUMN");
	if (index > 0)
		sqlite3_bind_text(statement, index, field, -1, SQLITE_STATIC);
	int ret = sqlite3_step(statement);
	do
	{
		int i = 0;
		if (sqlite3_column_type(statement, i) == SQLITE_TEXT)
		{
			value = (char *)sqlite3_column_text(statement, i);
		}
		ret = sqlite3_step(statement);
	} while (ret == SQLITE_ROW);
	sqlite3_finalize(statement);
	return value;
}

char *authz_sqlite_passwd(void *arg, char *user)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

	return authz_sqlite_search(ctx, user, "passwd");
}

int authz_sqlite_check(void *arg, char *user, char *passwd)
{
	int ret = 0;
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	authz_sqlite_config_t *config = ctx->config;

	char *chekpasswd = authz_sqlite_passwd(arg, user);
	if (chekpasswd)
	{
		if (chekpasswd[0] == '$')
		{
			if (!strncmp(chekpasswd, "$a1", 3))
			{
				char md5passwd[16];
				MD5_ctx ctx;
				int length;

				MD5_init(&ctx);
				chekpasswd = strchr(chekpasswd, '$');
				char *realm = strstr(chekpasswd, "realm=");
				if (realm)
				{
					realm += 6;
					int length = strchr(realm, '$') - realm;
					MD5_update(&ctx, user, strlen(user));
					MD5_update(&ctx, ":", 1);
					MD5_update(&ctx, realm, length);
					MD5_update(&ctx, ":", 1);
				}
				MD5_update(&ctx, passwd, strlen(passwd));
				MD5_finish(md5passwd, &ctx);
				char b64passwd[25];
				BASE64_encode(md5passwd, 16, b64passwd, 25);

				chekpasswd = strrchr(chekpasswd, '$');
				if (chekpasswd)
				{
					chekpasswd++;
				}
				if (!strcmp(b64passwd, chekpasswd))
					ret = 1;
			}
		}
		else
		{
			if (!strcmp(passwd, chekpasswd))
				ret = 1;
		}
	}
	return ret;
}

char *authz_sqlite_group(void *arg, char *user)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

	return authz_sqlite_search(ctx, user, "group");
}

char *authz_sqlite_home(void *arg, char *user)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

	return authz_sqlite_search(ctx, user, "home");
}

void authz_sqlite_destroy(void *arg)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

	sqlite3_close(ctx->db);
	free(ctx);
}

authz_rules_t authz_sqlite_rules =
{
	.create = authz_sqlite_create,
	.check = authz_sqlite_check,
	.passwd = authz_sqlite_passwd,
	.group = authz_sqlite_group,
	.home = authz_sqlite_home,
	.destroy = authz_sqlite_destroy,
};
