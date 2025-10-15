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
#include <limits.h>

#include <sqlite3.h>

#include "ouistiti/httpserver.h"
#include "ouistiti/hash.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
#include "authz_sqlite.h"

#define auth_dbg(...)

#define STRINGIFY(x) #x

#define AUTHZ_SQLITE_CONTEXTSETUP
#define AUTHZ_SQLITE_GLOBALDB

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

static sqlite3 *g_db = NULL;
int g_dbref = 0;

static int authz_sqlite_userid(authz_sqlite_t *ctx, const char *user);

#ifdef FILE_CONFIG
#include <libconfig.h>
void *authz_sqlite_config(const void *configauth, authz_type_t *type)
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
		"insert into groups (id, name) values(0, \"root\");",
		"insert into groups (id, name) values(1, \"anonymous\");",
		"insert into groups (id, name) values(2, \"users\");",
		"create table status (\"id\" INTEGER PRIMARY KEY, \"name\" TEXT UNIQUE NOT NULL);",
		"insert into status (id, name) values(1, \"approving\");",
		"insert into status (id, name) values(2, \"activated\");",
		"insert into status (id, name) values(3, \"repudiated\");",
		"insert into status (id, name) values(4, \"reapproving\");",
		"create table users (\"id\" INTEGER PRIMARY KEY,"
					"\"name\" TEXT UNIQUE NOT NULL,"
					"\"groupid\" INTEGER DEFAULT 1,"
					"\"home\" TEXT,"
					"FOREIGN KEY (groupid) REFERENCES groups(id) ON UPDATE SET NULL);",
		"create table passwds (\"userid\" INTEGER NOT NULL,"
					"\"passwd\" TEXT,\"issuer\" TEXT,"
					"\"statusid\" INTEGER DEFAULT 1,"
					"FOREIGN KEY (userid) REFERENCES users(id) ON DELETE CASCADE,"
					"FOREIGN KEY (statusid) REFERENCES status(id) ON UPDATE SET NULL);",
		"create table session (\"token\" TEXT PRIMARY KEY, \"userid\" INTEGER NOT NULL,\"expire\" INTEGER,"
					"FOREIGN KEY (userid) REFERENCES users(id) ON DELETE CASCADE);",
		"create table issuers (\"userid\" INTEGER NOT NULL,\"issuer\" TEXT,"
					"FOREIGN KEY (userid) REFERENCES users(id) ON DELETE CASCADE);",
#ifdef DEBUG
		"insert into users (name,groupid,home)"
			"values(\"root\",(select id from groups where name=\"root\"),\"/home/root\");",
		"insert into passwds (userid,passwd,statusid)"
			"values((select id from users where name=\"root\"),\"root\",(select id from status where name=\"activated\"));",
#else
		"insert into users (name,groupid,home)"
			"values(\"root\",(select id from groups where name=\"root\"),\"/home/root\");",
		"insert into passwds (userid,passwd,statusid)"
			"values((select id from users where name=\"root\"),\"root\",(select id from status where name=\"reapproving\"));",
#endif
#ifdef AUTH_ANONYMOUS
		"insert into users (name,groupid,home)"
			"values(\"anonymous\",(select id from groups where name=\"anonymous\"),\"null\");",
		"insert into passwds (userid,passwd,statusid)"
			"values((select id from users where name=\"anonymous\"),\"\",(select id from status where name=\"activated\"));",
#endif
#ifdef DEBUG
		"insert into users (name,groupid,home)"
			"values(\"foo\",(select id from groups where name=\"users\"),\"/home/foo\");",
		"insert into passwds (userid,passwd,statusid)"
			"values((select id from users where name=\"foo\"),\"bar\",(select id from status where name=\"activated\"));",
		"insert into users (name,groupid,home)"
			"values(\"johnDoe\",(select id from groups where name=\"users\"),\"/home/john\");",
		"insert into passwds (userid,passwd,statusid)"
			"values((select id from users where name=\"johnDoe\"),\"jane\",(select id from status where name=\"activated\"));",
		"insert into issuers (userid,issuer)"
			"values((select id from users where name=\"johnDoe\"),\"totp\");",
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
		auth_dbg("auth: create DB command %s\n\t%s", query[i], (ret != SQLITE_OK)?"KO":sqlite3_errmsg(db));
		i++;
	}
	sqlite3_close(db);
	chmod(dbname, S_IWUSR|S_IRUSR|S_IWGRP|S_IRGRP);
	if (ret == SQLITE_OK)
		warn("auth: generate new database %s", dbname);
	return (ret == SQLITE_OK)?ESUCCESS:EREJECT;
}

static sqlite3 * _authz_sqlite_opendb(const char *dbname)
{
#ifdef AUTHZ_SQLITE_GLOBALDB
	g_dbref++;
	if (g_db != NULL)
		return g_db;
#endif
	sqlite3 *db = NULL;
	/// sqlite3 documentation tells to open the database for each process and only once per process
	int ret = sqlite3_open_v2(dbname, &db, SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK)
	{
		err("auth: database %s not found", dbname);
		return NULL;
	}
#ifdef AUTHZ_SQLITE_GLOBALDB
	g_db = db;
#endif
	return db;
}

static void *authz_sqlite_create(http_server_t *UNUSED(server), string_t *issuer, void *arg)
{
	authz_sqlite_t *ctx = NULL;
	authz_sqlite_config_t *config = (authz_sqlite_config_t *)arg;

	if (access(config->dbname, R_OK) && _authz_sqlite_createdb(config->dbname) == EREJECT)
	{
		err("auth: database %s storage not allowed", config->dbname);
		warn("auth: check if %s is not a broken link", config->dbname);
		return NULL;
	}
	auth_dbg("auth: authentication DB storage on %s", config->dbname);

	ctx = calloc(1, sizeof(*ctx));
	ctx->config = config;
	ctx->issuer = issuer;
	ctx->db = _authz_sqlite_opendb(config->dbname);
	return ctx;
}

static void *authz_sqlite_setup(void *arg, http_client_t *clt, struct sockaddr *addr, int addrsize)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	const authz_sqlite_config_t *config = ctx->config;
	authz_sqlite_t *cltctx = ctx;
#ifdef AUTHZ_SQLITE_CONTEXTSETUP
	cltctx = calloc(1, sizeof(*cltctx));
	cltctx->config = ctx->config;
	cltctx->issuer = ctx->issuer;
	cltctx->ref = ctx->ref;
	if (ctx->db == NULL && config)
	{
#endif
		ctx->db = _authz_sqlite_opendb(config->dbname);
		auth_dbg("auth: authentication DB storage on %s from setup", ctx->config->dbname);
#ifdef AUTHZ_SQLITE_CONTEXTSETUP
	}
	cltctx->db = ctx->db;
#endif
	ctx->ref++;
	return cltctx;
}

#define SEARCH_QUERY "select %s " \
						"from users " \
						"inner join groups on groups.id=users.groupid " \
						"where users.name=@NAME;"

static int authz_sqlite_search(authz_sqlite_t *ctx, const string_t *user, char *field, int fieldlen, string_t *passwd)
{
	int ret;
	const unsigned char *value = NULL;
	int length = 0;

	size_t size = sizeof(SEARCH_QUERY) + fieldlen;
	char *sql = sqlite3_malloc(size);
	snprintf(sql, size, SEARCH_QUERY, field);

	sqlite3_stmt *statement = NULL; /// use a specific statement
	sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@NAME");
	if (index > 0)
		sqlite3_bind_text(statement, index, string_toc(user), string_length(user), SQLITE_STATIC);
	ret = sqlite3_step(statement);
	while (ret == SQLITE_ROW)
	{
		int i = 0;
		if (sqlite3_column_type(statement, i) == SQLITE_TEXT)
		{
			value = sqlite3_column_text(statement, i);
			length = sqlite3_column_bytes(statement, i);
			break;
		}
		ret = sqlite3_step(statement);
	}
	sqlite3_free(sql);
	ret = length;
	if (value && passwd)
		ret = string_cpy(passwd, (const char *)value, length);
	sqlite3_finalize(statement);
	return ret;
}

static int _authz_sqlite_storeuser(const authz_sqlite_t *UNUSED(ctx), sqlite3_stmt *statement, storeinfo_t callback, void *cbarg)
{
	const unsigned char *field;
	int i = 0;
	field = sqlite3_column_text(statement, i);
	callback(cbarg, STRING_REF(str_user), (const char *)field, -1);
	i++;
	field = sqlite3_column_text(statement, i);
	callback(cbarg, STRING_REF(str_group), (const char *)field, -1);
	i++;
	field = sqlite3_column_text(statement, i);
	callback(cbarg, STRING_REF(str_home), (const char *)field, -1);
	i++;

	return ESUCCESS;
}

static int authz_sqlite_getstatus_byID(authz_sqlite_t *ctx, int userid, string_t *issuer, storeinfo_t callback, void *cbarg)
{
	int ret = -1;
	if (userid != EREJECT)
	{
		string_t *status = string_create(32);
		if (issuer == NULL)
			issuer = ctx->issuer;
		ret = authz_sqlite_passwd_byID(ctx, userid, issuer, NULL, status);
		if (ret == 0)
		{
			string_t empty = STRING_DCL("");
			ret = authz_sqlite_passwd_byID(ctx, userid, &empty, NULL, status);
		}
		if (ret > 0)
			ret = callback(cbarg, STRING_REF(str_status), string_toc(status), string_length(status));
		else
			ret = EREJECT;
		string_destroy(status);
	}
	return ret;
}

int authz_sqlite_getuser_byName(authz_sqlite_t *ctx, const char * user, storeinfo_t callback, void *cbarg)
{
	int ret;
	const char *sql = "select users.name as \"user\", groups.name as \"group\", home " \
						"from users " \
						"inner join groups on groups.id=users.groupid " \
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

	auth_dbg("auth: sql query %s", sqlite3_expanded_sql(statement));
	ret = sqlite3_step(statement);
	if (ret == SQLITE_ROW)
	{
		ret = _authz_sqlite_storeuser(ctx, statement, callback, cbarg);
		sqlite3_finalize(statement);
		if (ret == ESUCCESS)
		{
			int userid = authz_sqlite_userid(ctx, user);
			authz_sqlite_getstatus_byID(ctx, userid, ctx->issuer, callback, cbarg);
		}
		return ret;
	}
	if (ret == SQLITE_DONE)
		err("auth: setsession error %s", sqlite3_errmsg(ctx->db));
	else
		warn("auth: user %s not found in database", user);
	sqlite3_finalize(statement);
	return EREJECT;
}

#define GETUSER_ONID 1
#ifdef GETUSER_ONID
int authz_sqlite_getuser_byID(authz_sqlite_t *ctx, int id, storeinfo_t callback, void *cbarg)
{
	int ret;
	const char *sql = "select users.name as \"user\", groups.name as \"group\", home " \
						"from users " \
						"inner join groups on groups.id=users.groupid " \
						"where users.id=@ID;";

	sqlite3_stmt *statement = NULL; /// use a specific statement
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index = 0;
	index = sqlite3_bind_parameter_index(statement, "@ID");
	ret = sqlite3_bind_int(statement, index, id);
	SQLITE3_CHECK(ret, EREJECT, sql);

	auth_dbg("auth: sql query %s", sqlite3_expanded_sql(statement));
	ret = sqlite3_step(statement);
	if (ret == SQLITE_ROW)
	{
		ret = _authz_sqlite_storeuser(ctx, statement, callback, cbarg);
		sqlite3_finalize(statement);
		if (ret == ESUCCESS)
		{
			authz_sqlite_getstatus_byID(ctx, id, ctx->issuer, callback, cbarg);
		}
		return ret;
	}
	err("auth: user (%d) not found", id);
	sqlite3_finalize(statement);
	return EREJECT;
}
#else
int authz_sqlite_getuser_byID(authz_sqlite_t *ctx, int id, storeinfo_t callback, void *cbarg)
{
	int ret;
	const char *sql = "select users.name as \"user\", groups.name as \"group\", home " \
						"from users " \
						"inner join groups on groups.id=users.groupid;";

	sqlite3_stmt *statement = NULL; /// use a specific statement
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	auth_dbg("auth: sql query %s", sqlite3_expanded_sql(statement));
	ret = sqlite3_step(statement);
	for (int j = 0; ret == SQLITE_ROW) && j != id; j++
	{
		ret = sqlite3_step(statement);
	}
	if (ret == SQLITE_ROW)
	{
		ret = _authz_sqlite_storeuser(ctx, statement, callback, cbarg);
		sqlite3_finalize(statement);
		return ret;
	}
	err("auth: user (%d) not found", id);
	sqlite3_finalize(statement);
	return EREJECT;
}
#endif

int authz_sqlite_passwd_byID(authz_sqlite_t *ctx, int userid, const string_t *issuer, string_t *passwd, string_t *status)
{
	int ret = -1;
	const char *sql[2] = {
		"select passwd, status.name as \"status\" from passwds "\
					"inner join status on status.id=passwds.statusid " \
					"where userid=@USERID & issuer=@ISSUER;",
		"select passwd, status.name as \"status\" from passwds "\
					"inner join status on status.id=passwds.statusid " \
					"where userid=@USERID;"
	};

	int sqlid = 0;
	if (string_empty(issuer))
		sqlid = 1;
	sqlite3_stmt *statement; /// use a specific statement, it is useless to keep the result at exit
	ret = sqlite3_prepare_v2(ctx->db, sql[sqlid], -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@USERID");
	ret = sqlite3_bind_int(statement, index, userid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	if (sqlid == 0)
	{
		index = sqlite3_bind_parameter_index(statement, "@ISSUER");
		ret = sqlite3_bind_text(statement, index, string_toc(issuer), string_length(issuer), SQLITE_STATIC);
		SQLITE3_CHECK(ret, EREJECT, sql);
	}

	auth_dbg("auth: sql query %s", sqlite3_expanded_sql(statement));
	ret = sqlite3_step(statement);
	if (ret == SQLITE_ROW)
	{
		int len = sqlite3_column_bytes(statement, 0);
		if (passwd)
		{
			const unsigned char *data = sqlite3_column_text(statement, 0);
			if (data[0] == '\0')
				len = 0;
			string_cpy(passwd, data, len);
			ret = ESUCCESS;
		}
		else
			ret = len;
		if (status)
		{
			int len = sqlite3_column_bytes(statement, 1);
			const unsigned char *data = sqlite3_column_text(statement, 1);
			if (data[0] == '\0')
				len = 0;
			string_cpy(status, data, len);
		}
	}
	else if (passwd)
		ret = EREJECT;
	else
		ret = 0;
	sqlite3_finalize(statement);
	return ret;
}

static int authz_sqlite_passwd(void *arg, const string_t *user, string_t *passwd)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	int userid = authz_sqlite_userid(ctx, string_toc(user));
	int ret = -1;
	if (userid == EREJECT)
		return (passwd)? EREJECT:0;
	ret = authz_sqlite_passwd_byID(ctx, userid, ctx->issuer, passwd, NULL);
	if ((passwd && ret != ESUCCESS) || (!passwd && ret == 0))
	{
		string_t empty = STRING_DCL("");
		ret = authz_sqlite_passwd_byID(ctx, userid, &empty, passwd, NULL);
	}
	return ret;
}

static int authz_sqlite_setsession(void *arg, const char *user, const char *token, storeinfo_t cb, void *cbarg)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	int ret = authz_sqlite_getuser_byName(ctx, user, cb, cbarg);
	if (ret == ESUCCESS && token)
		cb(cbarg, STRING_REF(str_token), token, -1);
	return ret;
}

#ifdef AUTH_TOKEN
static const char *_authz_sqlite_checktoken(authz_sqlite_t *ctx, const char *token, int expirable)
{
	int ret;
	const unsigned char *value = NULL;
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
	return (const char *)value;
}
#endif

static int _authz_sqlite_checkpasswd(authz_sqlite_t *ctx, const string_t *user, const string_t *passwd)
{
	int ret = 0;
	ret = authz_sqlite_passwd(ctx, user, NULL);
	string_t *checkpasswd = NULL;
	if (ret > 0)
	{
		checkpasswd = string_create(ret + 1);
		ret = authz_sqlite_passwd(ctx, user, checkpasswd);
		auth_dbg("auth: check password for %s => %s (%s)", string_toc(user), string_toc(passwd), string_toc(checkpasswd));
	}
	if (checkpasswd)
	{
		if (authz_checkpasswd(string_toc(checkpasswd), user, NULL, passwd) == ESUCCESS)
			ret = 1;
		string_cleansafe(checkpasswd);
		string_destroy(checkpasswd);
	}
	else
		err("auth: user %s not found in DB", string_toc(user));
	return ret;
}

static const char *authz_sqlite_check(void *arg, const char *user, const char *passwd, const char *token)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	string_t userstr = {0};
	string_store(&userstr, user, -1);
	string_t passwdstr = {0};
	string_store(&passwdstr, passwd, -1);

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
	if (!string_empty(&userstr) && !string_empty(&passwdstr) &&
		!_authz_sqlite_checkpasswd(ctx, &userstr, &passwdstr))
	{
		user = NULL;
	}
	return user;
}

int authz_sqlite_getid(authz_sqlite_t *ctx, const char *name, int length, int group)
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
		ret = sqlite3_bind_text(statement, index, name, length, SQLITE_STATIC);
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

static int authz_sqlite_userid(authz_sqlite_t *ctx, const char *name)
{
	return authz_sqlite_getid(ctx, name, -1, 0);
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
		err("auth: impossible to join user \"%s\" at the DB", user);
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

size_t authz_sqlite_issuer(void *arg, const char *user, char *issuer, size_t length)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
	int userid = authz_sqlite_userid(ctx, user);
	if (userid == EREJECT)
	{
		return 0;
	}

	size_t len = 0;
	int ret;
	const char *sql = "select issuer from issuers where userid=@USERID;";

	sqlite3_stmt *statement; /// use a specific statement, it is useless to keep the result at exit
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@USERID");
	ret = sqlite3_bind_int(statement, index, userid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	ret = sqlite3_step(statement);
	if (ret == SQLITE_ROW)
	{
		if (sqlite3_column_type(statement, 0) == SQLITE_TEXT)
		{
			len = sqlite3_column_bytes(statement, 0);
			const unsigned char *data = sqlite3_column_text(statement, 0);
			if (data[0] == '\0')
				len = 0;
			snprintf(issuer, length, "%.*s", (int)(len & INT_MAX), data);
		}
		ret = sqlite3_step(statement);
	}
	sqlite3_finalize(statement);
	return len;
}

static void authz_sqlite_cleanup(void *arg)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;

	ctx->ref--;
#ifdef AUTHZ_SQLITE_CONTEXTSETUP
	free(ctx);
#endif
}

static void authz_sqlite_destroy(void *arg)
{
	authz_sqlite_t *ctx = (authz_sqlite_t *)arg;
#ifdef AUTHZ_SQLITE_GLOBALDB
	if (g_dbref == 0)
#endif
	{
		sqlite3_close(ctx->db);
	}
	free(ctx->config);
	free(ctx);
}

authz_rules_t authz_sqlite_rules =
{
	.config = authz_sqlite_config,
	.create = authz_sqlite_create,
	.setup = authz_sqlite_setup,
	.check = authz_sqlite_check,
	.passwd = authz_sqlite_passwd,
	.issuer = authz_sqlite_issuer,
	.setsession = authz_sqlite_setsession,
	.join = authz_sqlite_join,
	.cleanup = authz_sqlite_cleanup,
	.destroy = authz_sqlite_destroy,
};

static const string_t authz_name = STRING_DCL("sqlite");
static void __attribute__ ((constructor)) _init()
{
	auth_registerauthz(&authz_name, &authz_sqlite_rules);
}
