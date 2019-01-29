/*****************************************************************************
 * jsonauth.c: json RPC library for authentication
 *****************************************************************************
 * Copyright (C) 2016-2017
 *
 * Authors: Marc Chalain <marc.chalain@gmail.com
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sched.h>
#include <sys/stat.h>
#include <sqlite3.h>

#include "httpserver/hash.h"
#include "../websocket.h"
#include "jsonrpc.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

#define ROOTUSER 0x8000
typedef struct jsonauth_ctx_s jsonauth_ctx_t;
struct jsonauth_ctx_s
{
	sqlite3 *db;
	const char *user;
	int userid;
};

static int _compute_passwd(const char *input, char *output, int outlen)
{
	const hash_t *hash = NULL;
	hash = hash_sha256;

	if (hash != NULL)
	{
		char *hashpasswd = malloc(hash->size);
		void *ctx;
		ctx = hash->init();
		hash->update(ctx, input, strlen(input));
		hash->finish(ctx, hashpasswd);

		size_t cnt = 0;
		strcpy(output, "$a5$");
		base64->encode(hashpasswd, hash->size, output + 4, outlen - 4);
		free(hashpasswd);
	}
	else
	{
		strncpy(output, input, outlen);
	}
}

static int _change_passwd(int id, const char *passwd, json_t **result, void *userdata)
{
	jsonauth_ctx_t *ctx = (jsonauth_ctx_t *)userdata;
	sqlite3 *db = ctx->db;
	int ret = 0;

	const char query[] = "update users set passwd=@PASSWD where ROWID=@ROWID";
	char *error = NULL;

	sqlite3_stmt *statement;
	ret = sqlite3_prepare_v2(db, query, -1, &statement, NULL);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@PASSWD");
	if (index > 0)
	{
		char b64passwd[4 + 100];
		_compute_passwd(passwd, b64passwd, 4 + 100);
		sqlite3_bind_text(statement, index, b64passwd, -1, SQLITE_STATIC);
	}
	index = sqlite3_bind_parameter_index(statement, "@ROWID");
	if (index > 0)
	{
		sqlite3_bind_int(statement, index, id);
	}

	ret = sqlite3_step(statement);
	if (ret == SQLITE_DONE)
	{
		json_t *value = json_string("password changed");
		json_object_set(*result, "message", value);		
	}
	else
	{
		warn("auth: password rejected %d", ret);
		json_decref(*result);
		*result = jsonrpc_error_object(ret, "password rejected", json_string("password rejected"));
	}
	sqlite3_finalize(statement);
}

static int _remove_user(int id, json_t **result, void *userdata)
{
	jsonauth_ctx_t *ctx = (jsonauth_ctx_t *)userdata;
	sqlite3 *db = ctx->db;
	int ret = 0;

	const char query[] = "delete from users where ROWID=@ROWID";
	char *error = NULL;

	sqlite3_stmt *statement;
	ret = sqlite3_prepare_v2(db, query, -1, &statement, NULL);

	int index;
	index = sqlite3_bind_parameter_index(statement, "@ROWID");
	if (index > 0)
	{
		sqlite3_bind_int(statement, index, id);
	}

	ret = sqlite3_step(statement);
	if (ret == SQLITE_DONE)
	{
		json_t *value = json_string("user removed");
		json_object_set(*result, "message", value);		
	}
	else
	{
		json_decref(*result);
		*result = jsonrpc_error_object(ret, "access rejected", json_string("acess rejected"));
	}
	sqlite3_finalize(statement);
}

static int _searchuser(const char *user, const char *passwd, json_t **result, void *userdata)
{
	jsonauth_ctx_t *ctx = (jsonauth_ctx_t *)userdata;
	sqlite3 *db = ctx->db;
	int ret;
	const char *query[] = 
	{
		"select ROWID from users where name=@USER and passwd=@PASSWD",
		"select users.ROWID, passwd, groups.name as \"group\", home from users inner join groups on groups.id=users.groupid where users.name=@USER;",
	};
	char *error = NULL;
	sqlite3_stmt *statement;
	int index;

	index = 0;
	if (!passwd)
		index = 1;
	ret = sqlite3_prepare_v2(db, query[index], -1, &statement, NULL);

	int id = -1;

	index = sqlite3_bind_parameter_index(statement, "@USER");
	if (index > 0)
	{
		sqlite3_bind_text(statement, index, user, -1, SQLITE_STATIC);
	}
	index = sqlite3_bind_parameter_index(statement, "@PASSWD");
	if (index > 0)
	{
		char b64passwd[3 + 50];
		_compute_passwd(passwd, b64passwd, 3 + 50);
		sqlite3_bind_text(statement, index, b64passwd, -1, SQLITE_STATIC);
	}

	ret = sqlite3_step(statement);
	if (ret >= SQLITE_ROW)
	{
		int type;
		index = 0;
		type = sqlite3_column_type(statement, index);
		if (type == SQLITE_INTEGER)
		{
			id = sqlite3_column_int(statement, index);
		}
		if (!passwd)
		{
			index = 1;
			type = sqlite3_column_type(statement, index);
			if (type == SQLITE_TEXT)
			{
				const char *passwd = sqlite3_column_text(statement, index);
				if (!strncmp(passwd, "$a1", 3))
				{
					json_t *value = json_string("MD5");
					json_object_set(*result, "algorithm", value);
				}
				if (!strncmp(passwd, "$a5", 3))
				{
					json_t *value = json_string("SHA-256");
					json_object_set(*result, "algorithm", value);
				}
				if (!strncmp(passwd, "$a6", 3))
				{
					json_t *value = json_string("SHA-512");
					json_object_set(*result, "algorithm", value);
				}
			}
			index = 2;
			type = sqlite3_column_type(statement, index);
			if (type == SQLITE_TEXT)
			{
				const char *group = sqlite3_column_text(statement, index);
				json_t *value = json_string(group);
				json_object_set(*result, "group", value);
				if (id == ctx->userid && !strcmp(group, "root"))
					ctx->userid |= ROOTUSER;
			}
			index = 3;
			type = sqlite3_column_type(statement, index);
			if (type == SQLITE_TEXT)
			{
				const char *home = sqlite3_column_text(statement, index);
				json_t *value = json_string(home);
				json_object_set(*result, "home", value);
			}
		}
	}
	sqlite3_finalize(statement);

	return id;
}

static int method_passwd(json_t *json_params, json_t **result, void *userdata)
{
	jsonauth_ctx_t *ctx = (jsonauth_ctx_t *)userdata;
	sqlite3 *db = ctx->db;
	int ret = 0;
	const char *user = NULL;
	const char *old = NULL;
	const char *new = NULL;
	const char *confirm = NULL;
	*result = json_object();
	if (json_is_object(json_params))
	{
		const char *key;
		json_t *value;
		json_object_foreach(json_params, key, value)
		{
			if (json_is_string(value) && !strcmp(key, "user"))
			{
				user = json_string_value(value);
			}
			else if (json_is_string(value) && !strcmp(key, "old"))
			{
				old = json_string_value(value);
			}
			else if (json_is_string(value) && !strcmp(key, "new"))
			{
				new = json_string_value(value);
			}
			else if (json_is_string(value) && !strcmp(key, "confirm"))
			{
				confirm = json_string_value(value);
			}
		}
		if(user && new && confirm && !strcmp(new,confirm))
		{
			int id = -1;
			if (old)
				id = _searchuser(user, old, result, userdata);
			else if (ctx->userid & ROOTUSER)
			{
				id = _searchuser(user, NULL, result, userdata);
			}
			if (id > -1)
			{
				_change_passwd(id, new, result, userdata);
			}
			else
			{
				json_decref(*result);
				*result = jsonrpc_error_object(ret, "user or password not found", json_string("user or password not found"));
			}
		}
		else if (strcmp(new,confirm))
		{
			json_decref(*result);
			*result = jsonrpc_error_object(ret, "confirm new password", json_string("confirm new password"));
		}
		else
		{
			json_decref(*result);
			*result = jsonrpc_error_object(ret, "incomplete command", json_string("incomplete command"));
		}
	}
	else
		ret = -1;
	return ret;
}

static int get_groupid(sqlite3 *db, const char *group)
{
	int groupid = -1;
	int ret;
	do
	{
		const char *query = "select id from groups where name=@GROUP;";
		char *error = NULL;
		sqlite3_stmt *statement;
		ret = sqlite3_prepare_v2(db, query, -1, &statement, NULL);

		int index;
		index = sqlite3_bind_parameter_index(statement, "@GROUP");
		if (index > 0)
		{
			sqlite3_bind_text(statement, index, group, -1, SQLITE_STATIC);
			ret = sqlite3_step(statement);
			if (ret == SQLITE_ROW)
			{
				groupid = sqlite3_column_int(statement, 0);
			}
			else
				group = "users";
		}
		else
			break;
		sqlite3_finalize(statement);
	} while (groupid == -1);
	return groupid;
}

static int method_adduser(json_t *json_params, json_t **result, void *userdata)
{
	jsonauth_ctx_t *ctx = (jsonauth_ctx_t *)userdata;
	sqlite3 *db = ctx->db;
	int ret = 0;
	*result = json_object();
	const char *group = "users";
	int groupid = -1;

	int prepare = 0;
	if (json_is_object(json_params))
	{
		json_t *value;
		value = json_object_get(json_params, "group");
		if (json_is_string(value))
		{
			const char *grouptmp = json_string_value(value);
			if (!strcmp(grouptmp, "root"))
			{
				if (ctx->userid & ROOTUSER)
					group = grouptmp;
			}
			else
				group = grouptmp;
		}
		groupid = get_groupid(db, group);

		const char query[] = "insert into users (name,groupid,passwd,home) values(@USER,@GROUPID,@PASSWD,@HOME);";
		char *error = NULL;
		sqlite3_stmt *statement;
		ret = sqlite3_prepare_v2(db, query, -1, &statement, NULL);

		const char *key;
		json_object_foreach(json_params, key, value)
		{
			int index;

			if (json_is_string(value) && !strcmp(key, "user"))
			{
				index = sqlite3_bind_parameter_index(statement, "@USER");
				if (index > 0)
				{
					ret = sqlite3_bind_text(statement, index, json_string_value(value), -1, SQLITE_STATIC);
				}
				prepare |= 0x0001;
			}
			else if (json_is_string(value) && !strcmp(key, "passwd"))
			{
				index = sqlite3_bind_parameter_index(statement, "@PASSWD");
				if (index > 0)
				{
					const char *passwd = json_string_value(value);
					char b64passwd[3 + 50];
					_compute_passwd(passwd, b64passwd, 3 + 50);
					ret = sqlite3_bind_text(statement, index, b64passwd, -1, SQLITE_STATIC);
				}
				prepare |= 0x0002;
			}
			else if (json_is_string(value) && !strcmp(key, "home"))
			{
				index = sqlite3_bind_parameter_index(statement, "@HOME");
				if (index > 0)
				{
					ret = sqlite3_bind_text(statement, index, json_string_value(value), -1, SQLITE_STATIC);
				}
				prepare |= 0x0004;
			}
		}
		if ((prepare & 0x00001) == 0)
		{
			err("adduser: User name missing");
			ret = -1;
		}
		if ((prepare & 0x00002) == 0)
		{
			err("adduser: Password missing");
			ret = -1;
		}
		if ((prepare & 0x00004) == 0)
		{
			int index;
			index = sqlite3_bind_parameter_index(statement, "@HOME");
			if (index > 0)
			{
				sqlite3_bind_null(statement, index);
			}
		}
		int index;
		index = sqlite3_bind_parameter_index(statement, "@GROUPID");
		if (index > 0)
		{
			ret = sqlite3_bind_int(statement, index, groupid);
		}
		if (ret == 0)
		{
			ret = sqlite3_step(statement);
			if (ret == SQLITE_DONE)
			{
				json_t *value = json_string("user added");
				json_object_set(*result, "message", value);
			}
			else
			{
				json_decref(*result);
				*result = jsonrpc_error_object(ret, "internal error", json_string("internal error"));
			}
		}
		else
		{
			json_decref(*result);
			*result = jsonrpc_error_object(ret, "incomplete command", json_string("incomplete command"));
		}
		sqlite3_finalize(statement);
	}
	return ret;
}

static int method_rmuser(json_t *json_params, json_t **result, void *userdata)
{
	jsonauth_ctx_t *ctx = (jsonauth_ctx_t *)userdata;
	sqlite3 *db = ctx->db;
	int ret = 0;
	const char *user = NULL;
	const char *passwd = NULL;
	*result = json_object();
	if (json_is_object(json_params))
	{
		const char *key;
		json_t *value;
		json_object_foreach(json_params, key, value)
		{
			if (json_is_string(value) && !strcmp(key, "user"))
			{
				user = json_string_value(value);
			}
			else if (json_is_string(value) && !strcmp(key, "passwd"))
			{
				passwd = json_string_value(value);
			}
		}
		if(user)
		{
			int id = -1;
			if (passwd)
				id = _searchuser(user, passwd, result, userdata);
			else if (ctx->userid & ROOTUSER)
				id = _searchuser(user, NULL, result, userdata);
			if (id > -1)
			{
				_remove_user(id, result, userdata);
			}
			else
			{
				json_decref(*result);
				*result = jsonrpc_error_object(ret, "user or password not found", json_string("user or password not found"));
			}
		}
		else
		{
			json_decref(*result);
			*result = jsonrpc_error_object(ret, "incomplete command", json_string("incomplete command"));
		}
	}
	else
		ret = -1;
	return ret;
}

static int method_auth(json_t *json_params, json_t **result, void *userdata)
{
	jsonauth_ctx_t *ctx = (jsonauth_ctx_t *)userdata;
	sqlite3 *db = ctx->db;
	int ret = 0;
	const char *user = NULL;
	const char *passwd = NULL;
	*result = json_object();
	if (json_is_object(json_params))
	{
		const char *key;
		json_t *value;
		json_object_foreach(json_params, key, value)
		{
			if (json_is_string(value) && !strcmp(key, "user"))
			{
				user = json_string_value(value);
			}
			else if (json_is_string(value) && !strcmp(key, "passwd"))
			{
				passwd = json_string_value(value);
			}
		}
		if(user && passwd)
		{
			int id = -1;
			id = _searchuser(user, passwd, result, userdata);
			if (id != -1)
			{
				ctx->userid = id;
				ctx->user = user;
				_searchuser(user, NULL, result, userdata);
				json_t *value = json_string(user);
				json_object_set(*result, "user", value);
			}
			else
			{
				json_decref(*result);
				*result = jsonrpc_error_object(ret, "user or password not found", json_string("user or password not found"));
			}
		}
		else
		{
			json_decref(*result);
			*result = jsonrpc_error_object(ret, "incomplete command", json_string("incomplete command"));
		}
	}
	return 0;
}

static struct jsonrpc_method_entry_t jsonsql_table[] = {
	{ "auth", method_auth, "o" },
	{ "passwd", method_passwd, "o" },
	{ "adduser", method_adduser, "o" },
	{ "rmuser", method_rmuser, "o" },
	{ NULL },
};

//__attribute__((constructor)) void *jsonrpc_init(struct jsonrpc_method_entry_t **table, char *config)
void *jsonrpc_init(struct jsonrpc_method_entry_t **table, char *config)
{
	jsonauth_ctx_t *ctx;
	ctx = calloc(1, sizeof(*ctx));
	//sqlite3_initialize();
	warn("Auth sqlite DB: %s", config);
	if (config)
	{
		int ret;
		if (!access(config, R_OK|W_OK))
		{
			ret = sqlite3_open_v2(config, &ctx->db, SQLITE_OPEN_READWRITE, NULL);
			warn("sqlite open 1 %d", ret);
		}
		else if (!access(config, R_OK))
		{
			ret = sqlite3_open_v2(config, &ctx->db, SQLITE_OPEN_READONLY, NULL);
			warn("sqlite open 2 %d", ret);
		}
		else
		{
			ret = sqlite3_open_v2(config, &ctx->db, SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE, NULL);
			warn("sqlite open 3 %d", ret);
		}
		if (ret != SQLITE_OK)
		{
			err("Auth sqlite DB error on open");
			ctx->db = NULL;
		}
	}
	if (ctx->db != NULL)
	{
		ctx->userid = -1;
		*table = jsonsql_table;
	}
	else
	{
		free(ctx);
		ctx = NULL;
	}
	return ctx;
}

//__attribute__((destructor)) void jsonrpc_release(void *arg)
void jsonrpc_release(void *arg)
{
	jsonauth_ctx_t *ctx = (jsonauth_ctx_t *)arg;
	if (ctx->db)
		sqlite3_close(ctx->db);
	//sqlite3_shutdown();
	free(ctx);
}
