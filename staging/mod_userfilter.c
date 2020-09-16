/*****************************************************************************
 * mod_userfilter.c: callbacks and management of request method
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
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include <sqlite3.h>

#include "httpserver/httpserver.h"
#include "httpserver/utils.h"
#include "httpserver/log.h"
#include "mod_auth.h"
#include "mod_userfilter.h"

#define userfilter_dbg(...)

#define SQLITE3_CHECK(ret, value, sql) \
	if (ret != SQLITE_OK) {\
		err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, sql, sqlite3_errmsg(ctx->db)); \
		sqlite3_finalize(statement); \
		return value; \
	}

static const char str_userfilter[] = "userfilter";
static const char str_annonymous[] = "annonymous";

typedef struct _mod_userfilter_s _mod_userfilter_t;

typedef int (*cmp_t)(_mod_userfilter_t *mod, const char *value,
				const char *user, const char *group, const char *home,
				const char *uri);

struct _mod_userfilter_s
{
	sqlite3 *db;
	cmp_t cmp;
	mod_userfilter_t *config;
};

int _exp_cmp(_mod_userfilter_t *ctx, const char *value,
				const char *user, const char *group, const char *home,
				const char *uri)
{
	int ret = EREJECT;
	const char *entries[3];
	int nbentries = 0;

	char *p, *valuefree = strdup(value);
	p = strchr(valuefree, '%');
	while (p != NULL)
	{
		p++;
		switch (*p)
		{
			case 'u':
				*p = 's';
				entries[nbentries] = user;
				nbentries++;
			break;
			case 'g':
				*p = 's';
				entries[nbentries] = group;
				nbentries++;
			break;
			case 'h':
				*p = 's';
				entries[nbentries] = home;
				nbentries++;
			break;
			default:
				return ret;
		}
		p = strchr(p, '%');
	}
	char *checking;
	if (asprintf(&checking, valuefree, entries[0], entries[1], entries[2]) < 0)
	{
		free(valuefree);
		return EREJECT;
	}
	userfilter_dbg("userfilter: check %s %s", uri, checking);
	if (utils_searchexp(uri, checking, NULL) == ESUCCESS)
		ret = ESUCCESS;
	free(valuefree);
	free(checking);
	return ret;
}

static int _search_method(_mod_userfilter_t *ctx, const char *method)
{
	int ret = EREJECT;
	int step;
	sqlite3_stmt *statement;
	const char *sql = "select id from methods where name=@METHOD;";
	step = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(step, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@METHOD");
	step = sqlite3_bind_text(statement, index, method, -1, SQLITE_STATIC);
	SQLITE3_CHECK(step, EREJECT, sql);

	step = sqlite3_step(statement);
	if (step == SQLITE_ROW)
	{
		ret = sqlite3_column_int(statement,0);
	}
	sqlite3_finalize(statement);
	return ret;
}

static int _search_role(_mod_userfilter_t *ctx, const char *role)
{
	int ret = EREJECT;
	int step;
	sqlite3_stmt *statement;
	const char *sql = "select id from roles where name=@ROLE;";
	step = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(step, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@ROLE");
	step = sqlite3_bind_text(statement, index, role, -1, SQLITE_STATIC);
	SQLITE3_CHECK(step, EREJECT, sql);
	step = sqlite3_step(statement);
	if (step == SQLITE_ROW)
	{
		ret = sqlite3_column_int(statement,0);
	}
	sqlite3_finalize(statement);
	return ret;
}

static int _request(_mod_userfilter_t *ctx, const char *method,
				const char *user, const char *group, const char *home,
				const char *uri)
{
	int ret = EREJECT;
	int methodid = _search_method(ctx, method);
	int userid = _search_role(ctx, user);
	int groupid = _search_role(ctx, group);
	sqlite3_stmt *statement;
	const char *sql = "select exp from rules \
		where methodid=@METHODID and \
		(roleid=@USERID or roleid=@GROUPID or roleid=2);";
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@METHODID");
	ret = sqlite3_bind_int(statement, index, methodid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@USERID");
	ret = sqlite3_bind_int(statement, index, userid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@GROUPID");
	ret = sqlite3_bind_int(statement, index, groupid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	userfilter_dbg("select exp from rules \
			where methodid=%d and \
			(roleid=%d or roleid=%d or roleid=2);",
			methodid, userid, groupid);
	ret = EREJECT;
	int step = sqlite3_step(statement);
	while (step == SQLITE_ROW)
	{
		int i = 0;
		if (sqlite3_column_type(statement, i) == SQLITE_TEXT)
		{
			const char *value = NULL;
			value = sqlite3_column_text(statement, i);
			userfilter_dbg("=> %s", value);
			if (!ctx->cmp(ctx, value, user, group, home, uri))
			{
				ret = ESUCCESS;
				break;
			}
		}
		step = sqlite3_step(statement);
	}
	if (step != SQLITE_DONE && ret != ESUCCESS)
		err("request %d %s", ret, sqlite3_errmsg(ctx->db));
	sqlite3_finalize(statement);
	return ret;
}

static int _insert_method(_mod_userfilter_t *ctx, const char *method)
{
	int ret = EREJECT;
	sqlite3_stmt *statement;
	const char *sql = "insert into methods (name) values(@METHOD);";
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@METHOD");
	ret = sqlite3_bind_text(statement, index, method, -1, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int step = sqlite3_step(statement);
	if (step == SQLITE_DONE)
	{
		ret = sqlite3_last_insert_rowid(ctx->db);
	}
	sqlite3_finalize(statement);
	return ret;
}

static int _insert_role(_mod_userfilter_t *ctx, const char *role)
{
	int ret = EREJECT;
	sqlite3_stmt *statement;
	const char *sql = "insert into roles (name) values(@ROLE);";
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@ROLE");
	ret = sqlite3_bind_text(statement, index, role, -1, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int step = sqlite3_step(statement);
	if (step == SQLITE_DONE)
	{
		ret = sqlite3_last_insert_rowid(ctx->db);
	}
	sqlite3_finalize(statement);
	return ret;
}

static int _insert_rules(_mod_userfilter_t *ctx, int methodid, int roleid, const char *exp)
{
	int ret = EREJECT;
	sqlite3_stmt *statement;
	const char *sql = "insert into rules (exp,methodid,roleid) values(@EXP,@METHODID,@ROLEID);";
	ret = sqlite3_prepare_v2(ctx->db, sql, -1, &statement, NULL);
	SQLITE3_CHECK(ret, EREJECT, sql);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@METHODID");
	ret = sqlite3_bind_int(statement, index, methodid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@ROLEID");
	ret = sqlite3_bind_int(statement, index, roleid);
	SQLITE3_CHECK(ret, EREJECT, sql);

	index = sqlite3_bind_parameter_index(statement, "@EXP");
	ret = sqlite3_bind_text(statement, index, exp, -1, SQLITE_STATIC);
	SQLITE3_CHECK(ret, EREJECT, sql);

	userfilter_dbg("insert into rules (exp,methodid,roleid) values(%s,%d,%d);",
		exp, methodid, roleid);
	int step = sqlite3_step(statement);
	if (step == SQLITE_DONE)
	{
		ret = ESUCCESS;
	}
	sqlite3_finalize(statement);
	return ret;
}

static int _insert(_mod_userfilter_t *ctx, const char *method, const char *role, const char *exp)
{
	int ret = EREJECT;
	int methodid = _search_method(ctx, method);
	if (methodid == EREJECT)
		methodid = _insert_method(ctx, method);
	int roleid = _search_role(ctx, role);
	if (roleid == EREJECT)
		roleid = _insert_role(ctx, role);
	if (methodid != EREJECT && roleid != EREJECT)
		ret = _insert_rules(ctx, methodid, roleid, exp);
	if (ret == ESUCCESS)
		warn("userfilter: insert %s for %s %s", exp, method, role);

	return ret;
}

static int userfilter_connector(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_userfilter_t *ctx = (_mod_userfilter_t *)arg;
	mod_userfilter_t *config = ctx->config;
	int ret = ESUCCESS;
	const char *uri = httpmessage_REQUEST(request,"uri");
	const char *method = httpmessage_REQUEST(request, "method");
	const char *user = auth_info(request, "user");
	if (user == NULL)
		user = str_annonymous;

	if ((utils_searchexp(uri, config->allow, NULL) == ESUCCESS) &&
		(strcmp(uri, config->configuri) != 0))
	{
		/**
		 * this path is always allowed
		 */
		userfilter_dbg("userfilter: forward to allowed path %s", config->allow);
		ret = EREJECT;
	}
	else if (_request(ctx, method, user,
				auth_info(request, "group"),
				auth_info(request, "home"),
				uri) == 0)
	{
		ret = EREJECT;
	}
	else
	{
		warn("userfilter: role %s forbidden for %s", user, uri);
		if (user == str_annonymous)
			httpmessage_result(response, RESULT_401);
		else
#if defined RESULT_403
			httpmessage_result(response, RESULT_403);
#else
			httpmessage_result(response, RESULT_400);
#endif
		ret = ESUCCESS;
	}
	return ret;
}

static int rootgenerator_connector(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_userfilter_t *ctx = (_mod_userfilter_t *)arg;
	mod_userfilter_t *config = ctx->config;
	int ret = EREJECT;
	const char *uri = httpmessage_REQUEST(request,"uri");
	if (!strcmp(uri, config->configuri))
	{
		const char *method = httpmessage_REQUEST(request, "method");
		const char *query = httpmessage_REQUEST(request, "query");
		if (!strcmp(method, str_post) && query != NULL)
		{
			char *nquery = strdup(query);
			ret = EINCOMPLETE;
			char *role = strstr(nquery, "role=");
			if (role == NULL)
				ret = EREJECT;
			else
			{
				role += 5;
			}
			char *method = strstr(nquery, "method=");
			if (method == NULL)
				ret = EREJECT;
			else
			{
				method += 7;
			}
			char *exp = strstr(nquery, "pathexp=");
			if (exp == NULL)
				ret = EREJECT;
			else
			{
				exp += 8;
			}
			if (ret == EINCOMPLETE)
			{
				char *end = NULL;
				end = strchr(role, '&');
				if (end != NULL)
					*end = '\0';
				end = strchr(method, '&');
				if (end != NULL)
					*end = '\0';
				end = strchr(exp, '&');
				if (end != NULL)
					*end = '\0';
				if (_insert(ctx, method, role, exp))
					httpmessage_result(response, RESULT_500);
#if defined RESULT_204
				else
					httpmessage_result(response, RESULT_204);
#endif
				free(nquery);
			}
			else
				httpmessage_result(response, RESULT_400);
		}
		else
		{
#if defined RESULT_405
			httpmessage_result(response, RESULT_405);
#else
			httpmessage_result(response, RESULT_400);
#endif
		}
		ret = ESUCCESS;
	}

	return ret;
}

void *mod_userfilter_create(http_server_t *server, void *arg)
{
	mod_userfilter_t *config = (mod_userfilter_t *)arg;
	if (config == NULL)
		return NULL;

	_mod_userfilter_t *mod = calloc(1, sizeof(*mod));
	sqlite3 *db;
	int ret;

	if (access(config->dbname, R_OK))
	{
		ret = sqlite3_open_v2(config->dbname, &db, SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE, NULL);
		const char *query[] = {
			"create table methods (\"id\" INTEGER PRIMARY KEY, \"name\" TEXT UNIQUE NOT NULL);",
			"insert into methods (name) values(\"GET\");",
			"insert into methods (name) values(\"POST\");",
			"insert into methods (name) values(\"PUT\");",
			"insert into methods (name) values(\"DELETE\");",
			"insert into methods (name) values(\"HEAD\");",
			"create table roles (\"id\" INTEGER PRIMARY KEY, \"name\" TEXT UNIQUE NOT NULL);",
			"insert into roles (id, name) values(0, @SUPERUSER);",
			"insert into roles (id, name) values(1, \"annonymous\");",
			"insert into roles (id, name) values(2, \"*\");",
			"create table rules (\"exp\" TEXT NOT NULL, \"methodid\" INTEGER NOT NULL,\"roleid\" INTEGER NOT NULL, FOREIGN KEY (methodid) REFERENCES methods(id) ON UPDATE SET NULL, FOREIGN KEY (roleid) REFERENCES roles(id) ON UPDATE SET NULL);",
			"insert into rules (exp,methodid,roleid) values(@CONFIGURI,(select id from methods where name=\"POST\"),0);",
			"insert into rules (exp,methodid,roleid) values(\"^/auth/*\",(select id from methods where name=\"GET\"),0);",
			"insert into rules (exp,methodid,roleid) values(\"^/auth/*\",(select id from methods where name=\"PUT\"),0);",
			"insert into rules (exp,methodid,roleid) values(\"^/auth/*\",(select id from methods where name=\"POST\"),0);",
			"insert into rules (exp,methodid,roleid) values(\"^/auth/*\",(select id from methods where name=\"DELETE\"),0);",
			"insert into rules (exp,methodid,roleid) values(\"^/auth/mngt/%u/*\",(select id from methods where name=\"GET\"),2);",
			"insert into rules (exp,methodid,roleid) values(\"^/auth/mngt/%u/*\",(select id from methods where name=\"POST\"),2);",
			"insert into rules (exp,methodid,roleid) values(\"^/auth/mngt/%u/*\",(select id from methods where name=\"DELETE\"),2);",
			NULL,
		};
		char *error = NULL;
		char *configuriexp = calloc(1, strlen(config->configuri) + 2 + 1);
		sprintf(configuriexp, "^%s$", config->configuri);
		int i = 0;
		while (query[i] != NULL)
		{
			sqlite3_stmt *statement;
			ret = sqlite3_prepare_v2(db, query[i], -1, &statement, NULL);

			int index;
			index = sqlite3_bind_parameter_index(statement, "@SUPERUSER");
			ret = sqlite3_bind_text(statement, index, config->superuser, -1, SQLITE_STATIC);

			index = sqlite3_bind_parameter_index(statement, "@CONFIGURI");
			ret = sqlite3_bind_text(statement, index, configuriexp, -1, SQLITE_STATIC);

			ret = sqlite3_step(statement);
			sqlite3_finalize(statement);
			if (ret != SQLITE_OK && ret != SQLITE_DONE)
			{
				err("%s(%d) %d: %s\n%s", __FUNCTION__, __LINE__, ret, query[i], sqlite3_errmsg(db)); \
				break;
			}
			i++;
		}
		free(configuriexp);
		sqlite3_close(db);
		chmod(config->dbname, S_IWUSR|S_IRUSR|S_IWGRP|S_IRGRP);
	}
	ret = sqlite3_open_v2(config->dbname, &db, SQLITE_OPEN_READWRITE, NULL);
	if (ret != SQLITE_OK)
	{
		err("userfilter: database not found %s", config->dbname);
		return NULL;
	}
	dbg("userfilter: DB storage on %s", config->dbname);

	mod->config = config;
	mod->cmp = &_exp_cmp;
	mod->db = db;
	httpserver_addconnector(server, userfilter_connector, mod, CONNECTOR_DOCFILTER, str_userfilter);
	httpserver_addconnector(server, rootgenerator_connector, mod, CONNECTOR_DOCUMENT, str_userfilter);

	return mod;
}

void mod_userfilter_destroy(void *arg)
{
	_mod_userfilter_t *ctx = (_mod_userfilter_t *)arg;
	sqlite3_close(ctx->db);
	free(arg);
}

const module_t mod_userfilter =
{
	.name = str_userfilter,
	.create = (module_create_t)&mod_userfilter_create,
	.destroy = &mod_userfilter_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_userfilter")));
#endif
