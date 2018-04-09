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
#include "httpserver/hash.h"
#include "mod_auth.h"
#include "authz_sqlite.h"

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
			hash_t *hash = NULL;
			if (!strncmp(chekpasswd, "$a1", 3))
			{
				hash = hash_md5;
			}
			if (!strncmp(chekpasswd, "$a5", 3))
			{
				hash = hash_sha256;
			}
			if (!strncmp(chekpasswd, "$a6", 3))
			{
				hash = hash_sha512;
			}
			if (hash)
			{
				char hashpasswd[32];
				void *ctx;
				int length;

				ctx = hash->init();
				chekpasswd = strchr(chekpasswd + 1, '$');
				char *realm = strstr(chekpasswd, "realm=");
				if (realm)
				{
					realm += 6;
					int length = strchr(realm, '$') - realm;
					hash->update(&ctx, user, strlen(user));
					hash->update(&ctx, ":", 1);
					hash->update(&ctx, realm, length);
					hash->update(&ctx, ":", 1);
				}
				hash->update(&ctx, passwd, strlen(passwd));
				hash->finish(ctx, hashpasswd);
				char b64passwd[50];
				base64->encode(hashpasswd, hash->size, b64passwd, 50);

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
