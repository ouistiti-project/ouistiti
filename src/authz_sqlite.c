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

#include "ouistiti/httpserver.h"
#include "ouistiti/hash.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
#include "authz_sqlite.h"

#define auth_dbg(...)

#define DEFAULT_GROUPID 2
#define STRINGIFY(x) #x

#ifdef DEBUG
#define SQLITE3_CHECK(ret, value, sql) \
	do { \
		if (ret != SQLITE_OK) { \
			err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, sql, sqlite3_errmsg(ctx->db)); \
			return value; \
		} \
	} while(0)
#else
#define SQLITE3_CHECK(...)
#endif

typedef struct authz_sqlite_s authz_sqlite_t;
struct authz_sqlite_s
{
	const authz_sqlite_config_t *config;
	sqlite3 *db;
	sqlite3_stmt *statement;
};

static int authz_sqlite_userid(authz_sqlite_t *ctx, const char *user);

#ifdef FILE_CONFIG
void *authz_sqlite_config(const config_setting_t *configauth)
{
	authz_sqlite_config_t *authz_config = NULL;
	char *path = NULL;

	config_setting_lookup_string(configauth, "dbname", (const char **)&path);
	if (path != NULL && path[0] != '0')
	{
		authz_config = calloc(1, sizeof(*authz_config));
		authz_config->dbname = path;
	}
	return authz_config;
}
#endif

#define FIELD_NAME 0
#define FIELD_GROUP 1
#define FIELD_STATUS 2
#define FIELD_PASSWD 3
#define FIELD_HOME 4

static int _authz_sqlite_createdb(const char *dbname)
{
	int ret;
	sqlite3 *db;
	ret = sqlite3_open_v2(dbname, &db, SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE, NULL);
	const char *query[] = {
		"create table groups (\"id\" INTEGER PRIMARY KEY, \"name\" TEXT UNIQUE NOT NULL);",
		"create table status (\"id\" INTEGER PRIMARY KEY, \"name\" TEXT UNIQUE NOT NULL);",
		"create table users (\"id\" INTEGER PRIMARY KEY,"
					"\"name\" TEXT UNIQUE NOT NULL,"
					"\"groupid\" INTEGER DEFAULT " STRINGIFY(DEFAULT_GROUPID) ","
					"\"statusid\" INTEGER DEFAULT 1,"
					"\"passwd\" TEXT,"
					"\"home\" TEXT,"
					"FOREIGN KEY (groupid) REFERENCES groups(id) ON UPDATE SET NULL,"
					"FOREIGN KEY (statusid) REFERENCES status(id) ON UPDATE SET NULL);",
		"create table session (\"token\" TEXT PRIMARY KEY, \"userid\" INTEGER NOT NULL,\"expire\" INTEGER,"
					"FOREIGN KEY (userid) REFERENCES users(id) ON UPDATE SET NULL);",
		"insert into status (name) values(\"approving\");",
		"insert into status (name) values(\"activated\");",
		"insert into status (name) values(\"repudiated\");",
		"insert into status (name) values(\"reapproving\");",
		"insert into groups (name) values(\"root\");",
		"insert into groups (name) values(\"anonymous\");",
		"insert into groups (name) values(\"users\");",
		"insert into users (name,groupid, statusid,passwd,home)"
#ifdef DEBUG
			"values(\"root\",(select id from groups where name=\"root\"),(select id from status where name=\"activated\"),\"root\",\"/home/root\");",
#else
			"values(\"root\",(select id from groups where name=\"root\"),(select id from status where name=\"reapproving\"),\"root\",\"/home/root\");",
#endif
#ifdef AUTH_ANONYMOUS
		"insert into users (name,groupid, statusid,passwd,home)"
			"values(\"anonymous\",(select id from groups where name=\"anonymous\"),(select id from status where name=\"activated\"),\"\",\"null\");",
#endif
#ifdef DEBUG
		"insert into users (name,groupid, statusid,passwd,home)"
			"values(\"foo\",(select id from groups where name=\"users\"),(select id from status where name=\"activated\"),\"bar\",\"/home/foo\");",
#endif
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
	chmod(dbname, S_IWUSR|S_IRUSR|S_IWGRP|S_IRGRP);
	if (ret == SQLITE_OK)
		warn("auth: generate new database %s", dbname);
	return (ret == SQLITE_OK)?ESUCCESS:EREJECT;
}

static void *authz_sqlite_create(http_server_t *UNUSED(server), void *arg)
{
	authz_sqlite_t *ctx = NULL;
	const authz_sqlite_config_t *config = (const authz_sqlite_config_t *)arg;

	if (access(config->dbname, R_OK))
	{
		_authz_sqlite_createdb(config->dbname);
	}
	auth_dbg("auth: authentication DB storage on %s", config->dbname);

	ctx = calloc(1, sizeof(*ctx));
	ctx->config = config;
	return ctx;
}

static void *authmngt_sqlite_create(http_server_t *UNUSED(server), void *arg)
{
	authz_sqlite_t *ctx = NULL;
	const authz_sqlite_config_t *config = (const authz_sqlite_config_t *)arg;
	int ret;
	sqlite3 *db;

	if (access(config->dbname, R_OK))
	{
		_authz_sqlite_createdb(config->dbname);
	}

	ret = sqlite3_open_v2(config->dbname, &db, SQLITE_OPEN_READWRITE, NULL);
	if (ret != SQLITE_OK)
	{
		err("authmngt: database not found %s", config->dbname);
		return NULL;
	}
	/** empty the session table */
	sqlite3_stmt *statement;
	const char *sql = "delete from session;";
	sqlite3_prepare_v2(db, sql, -1, &statement, NULL);

	sqlite3_step(statement);
	sqlite3_finalize(statement);
	ctx = calloc(1, sizeof(*ctx));
	ctx->db = db;
	ctx->config = config;
	return ctx;
}

static int authz_sqlite_setup(void *arg)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	int ret;

	/**
	 * sqlite3 documentation tells to open the database for each process
	 */
	ret = sqlite3_open_v2(ctx->config->dbname, &ctx->db, SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK)
	{
		err("auth: database not found %s", ctx->config->dbname);
		return EREJECT;
	}
	auth_dbg("auth: authentication DB storage on %s", ctx->config->dbname);

	return ESUCCESS;
}

#define SEARCH_QUERY "select %s " \
						"from users " \
						"inner join groups on groups.id=users.groupid " \
						"inner join status on status.id=users.statusid " \
						"where users.name=@NAME;"

static const char *authz_sqlite_search(authz_sqlite_t *ctx, const char *user, char *field)
{
	int ret;
	const char *value = NULL;

	size_t size = sizeof(SEARCH_QUERY) + strlen(field);
	char *sql = sqlite3_malloc(size);
	snprintf(sql, size, SEARCH_QUERY, field);

	if (ctx->statement != NULL)
		sqlite3_finalize(ctx->statement);
	sqlite3_prepare_v2(ctx->db, sql, -1, &ctx->statement, NULL);

	int index;
	index = sqlite3_bind_parameter_index(ctx->statement, "@NAME");
	if (index > 0)
		sqlite3_bind_text(ctx->statement, index, user, -1, SQLITE_STATIC);
	ret = sqlite3_step(ctx->statement);
	while (ret == SQLITE_ROW)
	{
		int i = 0;
		if (sqlite3_column_type(ctx->statement, i) == SQLITE_TEXT)
		{
			value = sqlite3_column_text(ctx->statement, i);
			break;
		}
		ret = sqlite3_step(ctx->statement);
	}
	sqlite3_free(sql);
	return value;
}

static int _authz_sqlite_storeuser(const authz_sqlite_t *UNUSED(ctx), sqlite3_stmt *statement, authsession_t *info)
{
	const char *field;
	int i = 0;
	field = sqlite3_column_text(statement, i);
	if (field != NULL)
		strncpy(info->user, field, USER_MAX);
	i++;
	field = sqlite3_column_text(statement, i);
	if (field != NULL)
		strncpy(info->group, field, FIELD_MAX);
	i++;
	field = sqlite3_column_text(statement, i);
	if (field != NULL)
		strncpy(info->status, field, FIELD_MAX);
	i++;
	field = sqlite3_column_text(statement, i);
	if (field != NULL)
		strncpy(info->home, field, PATH_MAX);
	i++;

	auth_dbg("auth: session user %s", info->user);
	auth_dbg("auth: session group %s", info->group);
	auth_dbg("auth: session status %s", info->status);
	auth_dbg("auth: session home %s", info->home);

	return ESUCCESS;
}

static int authz_sqlite_getuser_byName(void *arg, const char * user, authsession_t *info)
{
	int ret;
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	const char *sql = "select users.name as \"user\", groups.name as \"group\", status.name as \"status\", home " \
						"from users " \
						"inner join groups on groups.id=users.groupid " \
						"inner join status on status.id=users.statusid " \
						"where users.name=@NAME;";

	if (user == NULL)
		return EREJECT;

	sqlite3_stmt *statement = NULL; /// use a specific statement
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index = 0;
	index = sqlite3_bind_parameter_index(statement, "@NAME");
	ret = sqlite3_bind_text(statement, index, user, -1, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	ret = sqlite3_step(statement);
	if (ret == SQLITE_ROW)
	{
		ret = _authz_sqlite_storeuser(ctx, statement, info);
		sqlite3_finalize(statement);
		return ret;
	}
	err("auth: setsession error %s", sqlite3_errmsg(ctx->db));
	sqlite3_finalize(statement);
	return EREJECT;
}

static int authz_sqlite_getuser_byID(void *arg, int id, authsession_t *info)
{
	int ret;
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
#if 0
	const char *sql = "select users.name as \"user\", groups.name as \"group\", status.name as \"status\", home " \
						"from users " \
						"inner join groups on groups.id=users.groupid " \
						"inner join status on status.id=users.statusid " \
						"where users.ROWID=@ID;";
#else
	const char *sql = "select users.name as \"user\", groups.name as \"group\", status.name as \"status\", home " \
						"from users " \
						"inner join groups on groups.id=users.groupid " \
						"inner join status on status.id=users.statusid;";
#endif

	sqlite3_stmt *statement = NULL; /// use a specific statement
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

#if 0
	int index = 0;
	index = sqlite3_bind_parameter_index(statement, "@ID");
	ret = sqlite3_bind_int(statement, index, id);
	SQLITE3_CHECK(ret, EREJECT, sql);
#endif

	ret = sqlite3_step(statement);
	int j = 1;
	while (ret == SQLITE_ROW)
	{
		if (j != id)
		{
			ret = sqlite3_step(statement);
			j++;
			continue;
		}
		ret = _authz_sqlite_storeuser(ctx, statement, info);
		sqlite3_finalize(statement);
		return ret;
	}
	err("auth: getuser error %s", sqlite3_errmsg(ctx->db));
	sqlite3_finalize(statement);
	return EREJECT;
}

static const char *authz_sqlite_passwd(void *arg, const char *user)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

	const char * passwd = authz_sqlite_search(ctx, user, "passwd");
	return passwd;
}

#ifdef AUTH_TOKEN
static const char *_authz_sqlite_checktoken(authz_sqlite_t *ctx, const char *token, int expirable)
{
	int ret;
	const char *value = NULL;
	const char *sql[] = {
		"select users.name from session inner join users on users.id = session.userid where session.token=@TOKEN and session.expire is null;",
		"select users.name from session inner join users on users.id = session.userid where session.token=@TOKEN and session.expire > strftime('%s','now');",
		"select users.name from session inner join users on users.id = session.userid where session.token=@TOKEN;"
	};

	sqlite3_stmt *statement = NULL; /// use a specific statement
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
		if (sqlite3_column_type(statement, i) == SQLITE_TEXT)
		{
			value = sqlite3_column_text(statement, i);
		}
	}

	sqlite3_finalize(statement);
	return value;
}
#endif

static int _authz_sqlite_checkpasswd(authz_sqlite_t *ctx, const char *user, const char *passwd)
{
	int ret = 0;
	const char *checkpasswd = authz_sqlite_passwd(ctx, user);
	auth_dbg("auth: check password for %s => %s (%s)", user, passwd, checkpasswd);
	if (checkpasswd != NULL &&
			authz_checkpasswd(checkpasswd, user, NULL,  passwd) == ESUCCESS)
		ret = 1;
	else
		err("auth: user %s not found in DB", user);
	if (ctx->statement != NULL)
		sqlite3_finalize(ctx->statement);
	ctx->statement = NULL;
	return ret;
}

static const char *authz_sqlite_check(void *arg, const char *user, const char *passwd, const char *token)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

#ifdef AUTH_TOKEN
	if (token != NULL)
	{
		/** check expirable token */
		user = _authz_sqlite_checktoken(ctx, token, 1);
		if (user == NULL)
			/** check unexpirable token */
			user = _authz_sqlite_checktoken(ctx, token, 0);
		if (user != NULL)
			return user;
	}
#endif
	if (user != NULL && passwd != NULL &&
		!_authz_sqlite_checkpasswd(ctx, user, passwd))
	{
		user = NULL;
	}
	return user;
}

static int authz_sqlite_getid(authz_sqlite_t *ctx, const char *name, int group)
{
	int userid = EREJECT;
	int ret;
	const char *sql[] = {
		"select id from users where name=@NAME;",
		"select id from groups where name=@NAME;",
		"select id from status where name=@NAME;",
		NULL,
		NULL,
	};

	if (group > (sizeof(sql)/sizeof(*sql)) || sql[group] == NULL)
		return userid;

	sqlite3_stmt *statement = NULL; /// use a specific statement because name may come from ctx->statement
	ret = sqlite3_prepare_v2(ctx->db, sql[group], -1, &statement, NULL);
	if (ret != SQLITE_OK) {
		err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, sql[group], sqlite3_errmsg(ctx->db));
		return EREJECT;
	}

	int index;
	index = sqlite3_bind_parameter_index(statement, "@NAME");
	if (index > 0)
		ret = sqlite3_bind_text(statement, index, name, -1, SQLITE_STATIC);
	if (ret != SQLITE_OK) {
		err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, sql[group], sqlite3_errmsg(ctx->db));
		sqlite3_finalize(statement);
		return EREJECT;
	}

	ret = sqlite3_step(statement);
	if ((ret == SQLITE_ROW) &&
		(sqlite3_column_type(statement, 0) == SQLITE_INTEGER))
	{
		userid = sqlite3_column_int(statement, 0);
	}
	sqlite3_finalize(statement);
	return userid;
}

static int authz_sqlite_updatefield(authz_sqlite_t *ctx, int userid, const char *field, int group)
{
	int ret;
	const char *sql[] = {
		"update users set name=@FIELD where id=@USERID",
		"update users set groupid=(select id from groups where name=@FIELD) where id=@USERID",
		"update users set statusid=(select id from status where name=@FIELD) where id=@USERID",
		"update users set passwd=@FIELD where id=@USERID",
		"update users set home=@FIELD where id=@USERID",
		NULL,
	};

	if (sql[group] == NULL)
		return EREJECT;

	sqlite3_stmt *statement; /// use a specific statement because name may come from ctx->statement
	ret = sqlite3_prepare_v2(ctx->db, sql[group], -1, &statement, NULL);
	if (ret != SQLITE_OK) {
		err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, sql[group], sqlite3_errmsg(ctx->db));
		sqlite3_finalize(statement);
		return EREJECT;
	}

	int index;
	index = sqlite3_bind_parameter_index(statement, "@USERID");
	if (index > 0)
		ret = sqlite3_bind_int(statement, index, userid);
	if (ret != SQLITE_OK) {
		err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, sql[group], sqlite3_errmsg(ctx->db));
		sqlite3_finalize(statement);
		return EREJECT;
	}

	index = sqlite3_bind_parameter_index(statement, "@FIELD");
	if (index > 0)
		ret = sqlite3_bind_text(statement, index, field, -1, SQLITE_STATIC);
	if (ret != SQLITE_OK) {
		err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, sql[group], sqlite3_errmsg(ctx->db));
		sqlite3_finalize(statement);
		return EREJECT;
	}

	ret = sqlite3_step(statement);
	sqlite3_finalize(statement);
	if (ret == SQLITE_DONE)
	{
		auth_dbg("auth: change %d to %s", group, field);
		return ESUCCESS;
	}
	err("auth: changing error on %d", group);
	return EREJECT;
}

static int authz_sqlite_userid(authz_sqlite_t *ctx, const char *name)
{
	return authz_sqlite_getid(ctx, name, 0);
}

#ifdef AUTH_TOKEN
static int authz_sqlite_unjoin(authz_sqlite_t *ctx, int userid, const char *token)
{
	int ret;
	const char *sql = "delete from session where userid=@USERID or token=@TOKEN;";

	sqlite3_stmt *statement; /// use a specific statement, it is useless to keep the result at exit
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@TOKEN");
	ret = sqlite3_bind_text(statement, index, token, -1, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@USERID");
	ret = sqlite3_bind_int(statement, index, userid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	ret = sqlite3_step(statement);
	if ((ret == SQLITE_ROW) &&
		(sqlite3_column_type(statement, 0) == SQLITE_INTEGER))
	{
		userid = sqlite3_column_int(statement, 0);
	}
	sqlite3_finalize(statement);
	return userid;
}

static int authz_sqlite_join(void *arg, const char *user, const char *token, int expire)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	int userid = authz_sqlite_userid(ctx, user);

	if (userid == EREJECT)
	{
		err("authz associatie unknown user %s", user);
		return EREJECT;
	}
	authz_sqlite_unjoin(ctx, userid, token);

	int ret;
	const char *sql[] = {
		"insert into session (\"token\",\"userid\",\"expire\") values (@TOKEN,@USERID,strftime('%s','now') + @EXPIRE);",
		"insert into session (\"token\",\"userid\",\"expire\") values (@TOKEN,@USERID,@EXPIRE);"
	};
	int sqlid = 0;

	sqlite3_stmt *statement; /// use a specific statement, it is useless to keep the result at exit
	ret = sqlite3_prepare_v2(ctx->db, sql[sqlid], -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql[sqlid]);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@TOKEN");
	ret = sqlite3_bind_text(statement, index, token, -1, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql[sqlid]);

	index = sqlite3_bind_parameter_index(statement, "@USERID");
	ret = sqlite3_bind_int(statement, index, userid);
	SQLITE3_CHECK(ret, EREJECT, sql[sqlid]);

	index = sqlite3_bind_parameter_index(statement, "@EXPIRE");
	if (expire > 0)
		ret = sqlite3_bind_int(statement, index, expire);
	else
		ret = sqlite3_bind_null(statement, index);
	SQLITE3_CHECK(ret, EREJECT, sql[sqlid]);

	ret = sqlite3_step(statement);
	sqlite3_finalize(statement);

#if 0
	{
		int ret;
		const char *sql = "select token from session where userid=@USERID;";

		sqlite3_stmt *statement; /// use a specific statement, it is useless to keep the result at exit
		ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
		SQLITE3_CHECK(ret, EREJECT, sql);

		int index;
		index = sqlite3_bind_parameter_index(statement, "@USERID");
		ret = sqlite3_bind_int(statement, index, userid);
		SQLITE3_CHECK(ret, EREJECT, sql);

		ret = sqlite3_step(statement);
		while (ret == SQLITE_ROW)
		{
			if (sqlite3_column_type(statement, 0) == SQLITE_TEXT)
				warn("session token found %s", sqlite3_column_text(statement, 0));
			ret = sqlite3_step(statement);
		}
		sqlite3_finalize(statement);
	}
#endif
	return (ret == SQLITE_DONE)?ESUCCESS:EREJECT;
 }
#else
#define authz_sqlite_join NULL
#endif

static int _compute_passwd(const char *input, char *output, int outlen)
{
	if (input == NULL)
		return -1;
	const hash_t *hash = NULL;
	hash = hash_sha256;

	if (hash != NULL)
	{
		char *hashpasswd = malloc(hash->size);
		void *ctx;
		ctx = hash->init();
		hash->update(ctx, input, strlen(input));
		hash->finish(ctx, hashpasswd);

		strncpy(output, "$5$", outlen - 1);
		base64->encode(hashpasswd, hash->size, output + 4, outlen - 4);
		free(hashpasswd);
	}
	else
	{
		strncpy(output, input, outlen);
	}
	return 0;
}

#ifdef AUTHZ_MANAGER
static int authz_sqlite_adduser(void *arg, authsession_t *authinfo)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

	if (authz_sqlite_userid(ctx, authinfo->user) != EREJECT)
		return ESUCCESS;
	// force the first status to approving
	strncpy(authinfo->status, str_status_approving, FIELD_MAX);

	int ret;
	const char *sql = "insert into users (\"name\",\"passwd\",\"groupid\",\"statusid\",\"home\")"
			"values (@NAME,@PASSWD,@GROUPID,(select id from status where name=@STATUS),@HOME);";

	sqlite3_stmt *statement; /// use a specific statement, it is useless to keep the result at exit
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@NAME");
	ret = sqlite3_bind_text(statement, index, authinfo->user, -1, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@PASSWD");
	if (authinfo->passwd[0] != '\0')
	{
		ret = sqlite3_bind_text(statement, index, authinfo->passwd, -1, SQLITE_STATIC);
	}
	else
		ret = sqlite3_bind_text(statement, index, "*", -1, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@HOME");
	ret = sqlite3_bind_text(statement, index, authinfo->home, -1, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@GROUPID");
	ret = sqlite3_bind_int(statement, index, DEFAULT_GROUPID);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@STATUS");
	ret = sqlite3_bind_text(statement, index, authinfo->status, -1, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	ret = sqlite3_step(statement);
	sqlite3_finalize(statement);
	if (ret != SQLITE_DONE)
		err("auth: add user error %d %s", ret, sqlite3_errmsg(ctx->db));
	return (ret == SQLITE_DONE)?ESUCCESS:EREJECT;
}

static int authz_sqlite_addgroup(void *arg, const char *group)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	int ret;
	const char *sql = "insert into groups (\"name\")"
			"values (@NAME);";

	sqlite3_stmt *statement; /// use a specific statement, it is useless to keep the result at exit
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@NAME");
	ret = sqlite3_bind_text(statement, index, group, -1, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	ret = sqlite3_step(statement);
	sqlite3_finalize(statement);
	if (ret != SQLITE_DONE)
		err("auth: add group error %d %s", ret, sqlite3_errmsg(ctx->db));
	return (ret == SQLITE_DONE)?ESUCCESS:EREJECT;
}

static int authz_sqlite_changepasswd(void *arg, authsession_t *authinfo)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	int userid = 0;
	int ret = ESUCCESS;

	userid = authz_sqlite_userid(ctx, authinfo->user);
	if (userid == EREJECT)
		return EREJECT;

	if (ret == ESUCCESS && authinfo->passwd[0] != '\0')
	{
		ret = authz_sqlite_updatefield(ctx, userid, authinfo->passwd, FIELD_PASSWD);
	}
	authz_sqlite_getuser_byName(ctx, authinfo->user, authinfo);

	return ret;
}

static int authz_sqlite_changeinfo(void *arg, authsession_t *authinfo)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	int userid = 0;
	int ret = ESUCCESS;

	userid = authz_sqlite_userid(ctx, authinfo->user);
	if (userid == EREJECT)
		return EREJECT;

	if (ret == ESUCCESS && authinfo->group[0] != '\0')
	{
		if (authz_sqlite_getid(ctx, authinfo->group, FIELD_GROUP) == EREJECT)
		{
			ret = authz_sqlite_addgroup(ctx, authinfo->group);
		}
		if (ret == ESUCCESS)
			ret = authz_sqlite_updatefield(ctx, userid, authinfo->group, FIELD_GROUP);
	}

	if (ret == ESUCCESS && authinfo->status[0] != '\0')
	{
		if (authz_sqlite_getid(ctx, authinfo->status, FIELD_STATUS) == -1)
			err("authmngt: update unknown status %s", authinfo->status);
		else
			ret = authz_sqlite_updatefield(ctx, userid, authinfo->status, FIELD_STATUS);
	}

	if (ret == ESUCCESS && authinfo->home[0] != '\0')
	{
		ret = authz_sqlite_updatefield(ctx, userid, authinfo->home, FIELD_HOME);
	}

	return ret;
}

static int authz_sqlite_removeuser(void *arg, authsession_t *authinfo)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	int userid = 0;

	userid = authz_sqlite_userid(ctx, authinfo->user);
	if (userid == EREJECT)
		return EREJECT;

	int ret;
	const char *sql = "delete from users where id=@USERID;";

	sqlite3_stmt *statement; /// use a specific statement, it is useless to keep the result at exit
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@USERID");
	ret = sqlite3_bind_int(statement, index, userid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	ret = sqlite3_step(statement);
	sqlite3_finalize(statement);
	if (ret != SQLITE_DONE)
	{
		err("auth: remove user error %s", sqlite3_errmsg(ctx->db));
		strncpy(authinfo->status, sqlite3_errmsg(ctx->db), FIELD_MAX);
	}
	else
		strncpy(authinfo->status, "removed", FIELD_MAX);
	return (ret == SQLITE_DONE)?ESUCCESS:EREJECT;
}
#endif

static void authz_sqlite_cleanup(void *arg)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

	if (ctx->statement != NULL)
		sqlite3_finalize(ctx->statement);
	ctx->statement = NULL;
	sqlite3_close(ctx->db);
	ctx->db = NULL;
}

static void authz_sqlite_destroy(void *arg)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

	free(ctx);
}

authz_rules_t authz_sqlite_rules =
{
	.create = &authz_sqlite_create,
	.setup = &authz_sqlite_setup,
	.check = &authz_sqlite_check,
	.passwd = &authz_sqlite_passwd,
	.setsession = &authz_sqlite_getuser_byName,
	.join = &authz_sqlite_join,
	.cleanup = &authz_sqlite_cleanup,
	.destroy = &authz_sqlite_destroy,
};

#ifdef AUTHZ_MANAGER
authmngt_rules_t authmngt_sqlite_rules =
{
	.create = &authmngt_sqlite_create,
	.setsession = &authz_sqlite_getuser_byName,
	.getuser = &authz_sqlite_getuser_byID,
	.adduser = &authz_sqlite_adduser,
	.changepasswd = &authz_sqlite_changepasswd,
	.changeinfo = &authz_sqlite_changeinfo,
	.removeuser = &authz_sqlite_removeuser,
	.destroy = &authz_sqlite_destroy,
};
#endif
