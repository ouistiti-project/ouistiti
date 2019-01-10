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

typedef struct authz_sqlite_user_s authz_sqlite_user_t;
struct authz_sqlite_user_s
{
	char *name;
	char *group;
	char *home;
};

typedef struct authz_sqlite_s authz_sqlite_t;
struct authz_sqlite_s
{
	authz_sqlite_config_t *config;
	sqlite3 *db;
	char *value;
	authz_sqlite_user_t user;
};

void *authz_sqlite_create(void *arg)
{
	authz_sqlite_t *ctx = NULL;
	authz_sqlite_config_t *config = (authz_sqlite_config_t *)arg;
	int ret;
	sqlite3 *db;

	if (access(config->dbname, R_OK))
	{
		ret = sqlite3_open_v2(config->dbname, &db, SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE, NULL);
		const char *query[] = {
			"create table groups (\"id\" INTEGER PRIMARY KEY, \"name\" TEXT UNIQUE NOT NULL);",
			"create table users (\"name\" TEXT UNIQUE,\"groupid\" INTEGER  NOT NULL,\"passwd\" TEXT,\"home\" TEXT, FOREIGN KEY (groupid) REFERENCES groups(id) ON UPDATE SET NULL);",
			"insert into groups (name) values(\"root\");",
			"insert into groups (name) values(\"users\");",
			"insert into users values(\"root\",(select id from groups where name=\"root\"),\"test\",\"\");",
			"insert into users values(\"foo\",(select id from groups where name=\"users\"),\"bar\",\"foo\");",
			NULL,
		};
		char *error = NULL;
		int i = 0;
		while (query[i] != NULL)
		{
			if (ret != SQLITE_OK)
			{
				warn("auth: sqlite create(%d) error %d", i, ret);
				break;
			}
			ret = sqlite3_exec(db, query[i], NULL, NULL, &error);
			i++;
		}
		sqlite3_close(db);
		chmod(config->dbname, S_IWGRP|S_IRGRP);
	}
	ret = sqlite3_open_v2(config->dbname, &db, SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK)
	{
		err("auth: database not found %s", config->dbname);
		return NULL;
	}

	ctx = calloc(1, sizeof(*ctx));
	ctx->db = db;
	ctx->config = config;
	return ctx;
}

static char *authz_sqlite_search(authz_sqlite_t *ctx, char *user, char *field)
{
	authz_sqlite_config_t *config = ctx->config;
	int ret;
	const char *query = "select %s from users inner join groups on groups.id=users.groupid where users.name=@NAME;";

	int size = strlen(query) + strlen(field);
	char *sql = sqlite3_malloc(size);
	snprintf(sql, size, query, field);

	sqlite3_stmt *statement;
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	int index;
	index = sqlite3_bind_parameter_index(statement, "@NAME");
	if (index > 0)
		ret = sqlite3_bind_text(statement, index, user, -1, SQLITE_STATIC);

	ret = sqlite3_step(statement);
	do
	{
		if (ret < SQLITE_ROW)
			break;
		int i = 0;
		const char *key = sqlite3_column_name(statement, i);
		if (sqlite3_column_type(statement, i) == SQLITE_TEXT)
		{
			const char *data = sqlite3_column_text(statement, i);
			int length = strlen(data);
			if (ctx->value && length > strlen(ctx->value))
			{
				free(ctx->value);
				ctx->value = NULL;
			}
			if (!ctx->value)
				ctx->value = malloc(length + 1);
			strcpy(ctx->value, data);
			break;
		}
		ret = sqlite3_step(statement);
	} while (ret == SQLITE_ROW);
	sqlite3_finalize(statement);
	sqlite3_free(sql);
	dbg("auth: sqlite %s contains %s", field, ctx->value);
	return ctx->value;
}

char *authz_sqlite_passwd(void *arg, char *user)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

	char * passwd = authz_sqlite_search(ctx, user, "passwd");
	return passwd;
}

int authz_sqlite_check(void *arg, char *user, char *passwd)
{
	int ret = 0;
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	authz_sqlite_config_t *config = ctx->config;

	char *checkpasswd = authz_sqlite_passwd(arg, user);
	if (checkpasswd)
	{
		if (checkpasswd[0] == '$')
		{
			const hash_t *hash = NULL;
			if (!strncmp(checkpasswd, "$a1", 3))
			{
				hash = hash_md5;
			}
			if (!strncmp(checkpasswd, "$a5", 3))
			{
				hash = hash_sha256;
			}
			if (!strncmp(checkpasswd, "$a6", 3))
			{
				hash = hash_sha512;
			}
			if (hash)
			{
				char hashpasswd[32];
				void *ctx;
				int length;

				ctx = hash->init();
				checkpasswd = strchr(checkpasswd + 1, '$');
				char *realm = strstr(checkpasswd, "realm=");
				if (realm)
				{
					realm += 6;
					int length = strchr(realm, '$') - realm;
					hash->update(&ctx, user, strlen(user));
					hash->update(&ctx, ":", 1);
					hash->update(&ctx, realm, length);
					hash->update(&ctx, ":", 1);
				}
				hash->update(ctx, passwd, strlen(passwd));
				hash->finish(ctx, hashpasswd);
				char b64passwd[50];
				base64->encode(hashpasswd, hash->size, b64passwd, 50);

				checkpasswd = strrchr(checkpasswd, '$');
				if (checkpasswd)
				{
					checkpasswd++;
				}
				char *bug = strstr(b64passwd, "AAAAA");
				if (bug != NULL)
				{
					err("auth: bug on utf8 password");
					bug[0] = '\0';
					bug = strstr(checkpasswd, "AAAAA");
					bug[0] = '\0';
				}
				if (!strcmp(b64passwd, checkpasswd))
					ret = 1;
			}
			else
				err("auth: hash %s not found", checkpasswd);
		}
		else
		{
			if (!strcmp(passwd, checkpasswd))
				ret = 1;
		}
	}
	return ret;
}

char *authz_sqlite_group(void *arg, char *user)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

	return authz_sqlite_search(ctx, user, "groups.name as \"group\"");
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
	if (ctx->value)
		free(ctx->value);
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
