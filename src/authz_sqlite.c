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

#ifdef DEBUG
#define SQLITE3_CHECK(ret, value, sql) \
	if (ret != SQLITE_OK) {\
		err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, sql, sqlite3_errmsg(ctx->db)); \
		return value; \
	}
#else
#define SQLITE3_CHECK(...)
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

static void *authz_sqlite_create(void *arg)
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
			"create table users (\"id\" INTEGER PRIMARY KEY, \"name\" TEXT UNIQUE NOT NULL,\"groupid\" INTEGER NOT NULL,\"passwd\" TEXT,\"home\" TEXT, FOREIGN KEY (groupid) REFERENCES groups(id) ON UPDATE SET NULL);",
			"create table session (\"token\" TEXT PRIMARY KEY, \"userid\" INTEGER NOT NULL,\"expire\" INTEGER NOT NULL, FOREIGN KEY (userid) REFERENCES users(id) ON UPDATE SET NULL);",
			"insert into groups (name) values(\"root\");",
			"insert into groups (name) values(\"users\");",
			"insert into users (name,groupid,passwd,home) values(\"root\",(select id from groups where name=\"root\"),\"test\",\"\");",
			"insert into users (name,groupid,passwd,home) values(\"foo\",(select id from groups where name=\"users\"),\"bar\",\"foo\");",
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
		chmod(config->dbname, S_IWUSR|S_IRUSR|S_IWGRP|S_IRGRP);
	}
	ret = sqlite3_open_v2(config->dbname, &db, SQLITE_OPEN_READWRITE, NULL);
	if (ret != SQLITE_OK)
	{
		err("auth: database not found %s", config->dbname);
		return NULL;
	}
	/** empty the session table */
	sqlite3_stmt *statement;
	const char *sql = "delete from session;";
	ret = sqlite3_prepare_v2(db, sql, -1, &statement, NULL);

	ret = sqlite3_step(statement);
	sqlite3_finalize(statement);

	ctx = calloc(1, sizeof(*ctx));
	ctx->db = db;
	ctx->config = config;
	return ctx;
}

static char *authz_sqlite_search(authz_sqlite_t *ctx, const char *user, char *field)
{
	authz_sqlite_config_t *config = ctx->config;
	int ret;
	char *value = NULL;
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
			if (length > 0)
			{
				if (!ctx->value)
					ctx->value = malloc(length + 1);
				strcpy(ctx->value, data);
				value = ctx->value;
			}
			break;
		}
		ret = sqlite3_step(statement);
	} while (ret == SQLITE_ROW);
	sqlite3_finalize(statement);
	sqlite3_free(sql);
	return value;
}

static const char *authz_sqlite_passwd(void *arg, const char *user)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

	char * passwd = authz_sqlite_search(ctx, user, "passwd");
	return passwd;
}

static const char *_authz_sqlite_checktoken(authz_sqlite_t *ctx, const char *token, int expirable)
{
	int ret;
	const char *value = NULL;
	sqlite3_stmt *statement = NULL;
	const char *sql[] = {
		"select users.name from session inner join users on users.id = session.userid where session.token=@TOKEN and session.expire = NULL;",
		"select users.name from session inner join users on users.id = session.userid where session.token=@TOKEN and session.expire > strftime('%s','now');",
		"select users.name from session inner join users on users.id = session.userid where session.token=@TOKEN;",
	};
	ret = sqlite3_prepare_v2(ctx->db, sql[expirable], -1, &statement, NULL);
	SQLITE3_CHECK(ret, NULL, sql[expirable]);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@TOKEN");
	ret = sqlite3_bind_text(statement, index, token, -1, SQLITE_STATIC);
	SQLITE3_CHECK(ret, NULL, sql[expirable]);

	ret = sqlite3_step(statement);
	if (ret == SQLITE_ROW)
	{
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
			if (length > 0)
			{
				if (!ctx->value)
					ctx->value = malloc(length + 1);
				strcpy(ctx->value, data);
				value = ctx->value;
			}
		}
	}
	else
		err("user not found");
	sqlite3_finalize(statement);
	return value;
}

static int _authz_sqlite_checkpasswd(authz_sqlite_t *ctx, const char *user, const char *passwd)
{
	int ret = 0;
	authz_sqlite_config_t *config = ctx->config;

	const char *checkpasswd = authz_sqlite_passwd(ctx, user);
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

static int authz_sqlite_check(void *arg, const char *user, const char *passwd, const char *token)
{
	int ret = 0;
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

	if (user != NULL && passwd != NULL)
		ret = _authz_sqlite_checkpasswd(ctx, user, passwd);
	if (ret == 0 && token != NULL)
	{
		ret = (_authz_sqlite_checktoken(ctx, token, 1) != NULL);
		if (ret == 0)
			ret = (_authz_sqlite_checktoken(ctx, token, 0) != NULL);
	}
	return ret;
}

static const char *authz_sqlite_group(void *arg, const char *user)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

	return authz_sqlite_search(ctx, user, "groups.name as \"group\"");
}

static const char *authz_sqlite_home(void *arg, const char *user)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

	return authz_sqlite_search(ctx, user, "home");
}

static void authz_sqlite_destroy(void *arg)
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
