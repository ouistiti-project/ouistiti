/*****************************************************************************
 * jsonrpc.c: json RPC server
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

#include "../websocket.h"
#include "httpserver/websocket.h"
#include "jsonrpc.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

typedef struct jsonsql_ctx_s jsonsql_ctx_t;
struct jsonsql_ctx_s
{
	sqlite3 *db;
};

static int row_callback(void *arg, int nbColumns, char **values, char **keys);

static int row_callback(void *arg, int nbColumns, char **values, char **keys)
{
	json_t **result = (json_t **)arg;
	json_t *row = json_object();
	int i;
	for (i = 0; i < nbColumns; i++)
	{
		json_t *value = json_string(values[i]);
		json_object_set(row, keys[i], value);
	}
	if (json_is_array(*result))
	{
		json_array_append(*result, row);
	}
	return 0;
}

static int method_exec(json_t *json_params, json_t **result, void *userdata)
{
	jsonsql_ctx_t *ctx = (jsonsql_ctx_t *)userdata;
	sqlite3 *db = ctx->db;
	int ret = 0;
	if (json_is_object(json_params))
	{
		const char *key;
		json_t *value;
		json_object_foreach(json_params, key, value)
		{
			if (json_is_string(value) && !strcmp(key, "db"))
			{
				const char *dbname = NULL;
				dbname = json_string_value(value);
				sqlite3_open(dbname, &db);
			}
			else if (json_is_string(value) && !strcmp(key, "query"))
			{
				const char *query = NULL;
				char *error = NULL;
				query = json_string_value(value);
				*result = json_array();
				int ret = sqlite3_exec(db, query, row_callback, result, &error);
				if (ret != SQLITE_OK)
				{
					json_decref(*result);
					*result = jsonrpc_error_object(ret, sqlite3_errmsg(db), json_string(sqlite3_errmsg(db)));
				}
				else if (json_array_size(*result) == 0)
				{
					json_decref(*result);
					*result = json_object();
					json_t *value = json_string("Query OK");
					json_object_set(*result, "message", value);
				}
			}
		}
		if (db != ctx->db)
			sqlite3_close(db);
	}
	else
		ret = -1;
	return ret;
}

static int method_X(json_t *json_params, json_t **result, void *userdata, char *query)
{
	jsonsql_ctx_t *ctx = (jsonsql_ctx_t *)userdata;
	sqlite3 *db = ctx->db;
	int ret = 0;
	if (json_is_object(json_params))
	{
		sqlite3_stmt *statement;
		sqlite3_prepare_v2(db, query, -1, &statement, NULL);

		const char *key;
		json_t *value;
		json_object_foreach(json_params, key, value)
		{
			if (json_is_string(value) && !strcmp(key, "db"))
			{
				const char *dbname = NULL;
				dbname = json_string_value(value);
				sqlite3_open(dbname, &db);
				sqlite3_finalize(statement);
				sqlite3_prepare_v2(db, query, -1, &statement, NULL);
			}
			else if (json_is_string(value) && !strcmp(key, "table"))
			{
				int index = sqlite3_bind_parameter_index(statement, "@TABLE");
				if (index > 0)
				{
					const char *table = NULL;
					table = json_string_value(value);
					sqlite3_bind_text(statement, index, table, -1, SQLITE_STATIC);
				}
			}
			else if (json_is_integer(value) && !strcmp(key, "id"))
			{
				const int id = json_integer_value(value);
				int index = sqlite3_bind_parameter_index(statement, "@ROWID");
				if (index > 0 && id > -1)
					sqlite3_bind_int(statement, index, id);
			}
			else if (json_is_string(value))
			{
				char parameter[32];
				snprintf(parameter, 31, "@%s", key);
				int index = sqlite3_bind_parameter_index(statement, parameter);
				if (index > 0)
				{
					const char *data = NULL;
					data = json_string_value(value);
					if (data)
						sqlite3_bind_text(statement, index, data, -1, SQLITE_STATIC);
				}
			}
			else if (json_is_integer(value))
			{
				char parameter[32];
				snprintf(parameter, 31, "@%s", key);
				int index = sqlite3_bind_parameter_index(statement, parameter);
				if (index > 0)
				{
					const int data = json_integer_value(value);
					sqlite3_bind_int(statement, index, data);
				}
			}
		}
		int ret;
		ret = sqlite3_step(statement);
		do
		{
			*result = json_object();
			int i, nbColumns = sqlite3_column_count(statement);
			for (i = 0; i < nbColumns; i++)
			{
				const char *key = sqlite3_column_name(statement, i);
				switch (sqlite3_column_type(statement, i))
				{
				case SQLITE_INTEGER:
				{
					json_t *value = json_integer(sqlite3_column_int(statement, i));
					json_object_set(*result, key, value);
				}
				break;
				case SQLITE_FLOAT:
				{
					json_t *value = json_real(sqlite3_column_double(statement, i));
					json_object_set(*result, key, value);
				}
				break;
				case SQLITE_BLOB:
				{
					int size = sqlite3_column_bytes(statement, i);
					json_t *value = json_array();
					const unsigned char *blob = sqlite3_column_blob(statement, i);
					int j;
					for (j = 0; j < size; j++)
					{
						json_t *byte = json_integer(blob[j]);
						json_array_append(value, byte);
					}
					json_object_set(*result, key, value);
				}
				break;
				case SQLITE_TEXT:
				{
					json_t *value = json_string(sqlite3_column_text(statement, i));
					json_object_set(*result, key, value);
				}
				break;
				case SQLITE_NULL:
				{
					json_t *value = json_null();
					json_object_set(*result, key, value);
				}
				break;
				}
			}
			ret = sqlite3_step(statement);
		} while (ret == SQLITE_ROW);
		sqlite3_finalize(statement);
		if (db != ctx->db)
			sqlite3_close(db);
	}
	else
		ret = -1;
	return 0;
}

static int method_get(json_t *json_params, json_t **result, void *userdata)
{
	char sql[] = "select * from @TABLE where ROWID=@ROWID";
	return method_X(json_params, result, userdata, sql);
}

static int method_view(json_t *json_params, json_t **result, void *userdata)
{
	char sql[] = "PRAGMA table_info('@TABLE')";
	return method_X(json_params, result, userdata, sql);
}

static int method_list(json_t *json_params, json_t **result, void *userdata)
{
	char sql[] = "select * from @TABLE";
	return method_X(json_params, result, userdata, sql);
}

static int method_insert(json_t *json_params, json_t **result, void *userdata)
{
	char sql[] = "insert into @TABLE (@COLUMNS) values (@VALUES)";
	return method_X(json_params, result, userdata, sql);
}

/*
static int method_list(json_t *json_params, json_t **result, void *userdata)
{
	jsonsql_ctx_t *ctx = (jsonsql_ctx_t *)userdata;
	sqlite3 *db = ctx->db;
	int ret = 0;
	if (json_is_object(json_params))
	{
		*result = json_array();

		sqlite3_stmt *statement;
		char sql[] = "select * from @TABLE";
		sqlite3_prepare_v2(db, sql, -1, &statement, NULL);

		const char *key;
		json_t *value;
		json_object_foreach(json_params, key, value)
		{
			if (json_is_string(value) && !strcmp(key, "db"))
			{
				const char *dbname = NULL;
				dbname = json_string_value(value);
				sqlite3_open(dbname, &db);
				sqlite3_finalize(statement);
				sqlite3_prepare_v2(db, sql, -1, &statement, NULL);
			}
			else if (json_is_string(value) && !strcmp(key, "table"))
			{
				const char *table = NULL;
				table = json_string_value(value);
				int index = sqlite3_bind_parameter_index(statement, "@TABLE");
				sqlite3_bind_text(statement, index, table, -1, SQLITE_STATIC);
			}
		}
		int ret;
		do
		{
			ret = sqlite3_step(statement);
			json_t *row = json_object();
			int i, nbColumns = sqlite3_column_count(statement);
			for (i = 0; i < nbColumns; i++)
			{
				const char *key = sqlite3_column_name(statement, i);
				switch (sqlite3_column_type(statement, i))
				{
				case SQLITE_INTEGER:
				{
					json_t *value = json_integer(sqlite3_column_int(statement, i));
					json_object_set(row, key, value);
				}
				break;
				case SQLITE_FLOAT:
				{
					json_t *value = json_real(sqlite3_column_double(statement, i));
					json_object_set(row, key, value);
				}
				break;
				case SQLITE_BLOB:
				{
					int size = sqlite3_column_bytes(statement, i);
					json_t *value = json_array();
					const unsigned char *blob = sqlite3_column_blob(statement, i);
					int j;
					for (j = 0; j < size; j++)
					{
						json_t *byte = json_integer(blob[j]);
						json_array_append(value, byte);
					}
					json_object_set(row, key, value);
				}
				break;
				case SQLITE_TEXT:
				{
					json_t *value = json_string(sqlite3_column_text(statement, i));
					json_object_set(row, key, value);
				}
				break;
				case SQLITE_NULL:
				{
					json_t *value = json_null();
					json_object_set(row, key, value);
				}
				break;
				}
			}
			if (json_is_array(*result))
			{
				json_array_append(*result, row);
			}
		} while (ret == SQLITE_ROW);
		sqlite3_finalize(statement);
		if (db != ctx->db)
			sqlite3_close(db);
	}
	else
		ret = -1;
	return 0;
}
*/
/*
static int method_view(json_t *json_params, json_t **result, void *userdata)
{
	jsonsql_ctx_t *ctx = (jsonsql_ctx_t *)userdata;
	sqlite3 *db = ctx->db;
	int ret = 0;
	if (json_is_object(json_params))
	{
		*result = json_array();

		sqlite3_stmt *statement;
		char sql[] = "PRAGMA table_info('@TABLE')";
		sqlite3_prepare_v2(db, sql, -1, &statement, NULL);

		const char *key;
		json_t *value;
		json_object_foreach(json_params, key, value)
		{
			if (json_is_string(value) && !strcmp(key, "db"))
			{
				const char *dbname = NULL;
				dbname = json_string_value(value);
				sqlite3_open(dbname, &db);
				sqlite3_finalize(statement);
				sqlite3_prepare_v2(db, sql, -1, &statement, NULL);
			}
			else if (json_is_string(value) && !strcmp(key, "table"))
			{
				const char *table = NULL;
				table = json_string_value(value);
				int index = sqlite3_bind_parameter_index(statement, "@TABLE");
				sqlite3_bind_text(statement, index, table, -1, SQLITE_STATIC);
			}
		}
		int ret;
		do
		{
			ret = sqlite3_step(statement);
			json_t *row = json_object();
			int i, nbColumns = sqlite3_column_count(statement);
			for (i = 0; i < nbColumns; i++)
			{
				const char *key = sqlite3_column_name(statement, i);
				switch (sqlite3_column_type(statement, i))
				{
				case SQLITE_INTEGER:
				{
					json_t *value = json_integer(sqlite3_column_int(statement, i));
					json_object_set(row, key, value);
				}
				break;
				case SQLITE_FLOAT:
				{
					json_t *value = json_real(sqlite3_column_double(statement, i));
					json_object_set(row, key, value);
				}
				break;
				case SQLITE_BLOB:
				{
					int size = sqlite3_column_bytes(statement, i);
					json_t *value = json_array();
					const unsigned char *blob = sqlite3_column_blob(statement, i);
					int j;
					for (j = 0; j < size; j++)
					{
						json_t *byte = json_integer(blob[j]);
						json_array_append(value, byte);
					}
					json_object_set(row, key, value);
				}
				break;
				case SQLITE_TEXT:
				{
					json_t *value = json_string(sqlite3_column_text(statement, i));
					json_object_set(row, key, value);
				}
				break;
				case SQLITE_NULL:
				{
					json_t *value = json_null();
					json_object_set(row, key, value);
				}
				break;
				}
			}
			if (json_is_array(*result))
			{
				json_array_append(*result, row);
			}
		} while (ret == SQLITE_ROW);
		sqlite3_finalize(statement);
		if (db != ctx->db)
			sqlite3_close(db);
	}
	else
		ret = -1;
	return 0;
}
*/
static int method_auth(json_t *json_params, json_t **result, void *userdata)
{
	return 0;
}

static struct jsonrpc_method_entry_t jsonsql_table[] = {
	{ "auth", method_auth, "o" },
	{ "list", method_list, "o" },
	{ "get", method_get, "o" },
	{ "exec", method_exec, "o" },
	{ "view", method_view, "o" },
	{ NULL },
};

void *jsonrpc_init(struct jsonrpc_method_entry_t **table, char *config)
{
	jsonsql_ctx_t *ctx;
	ctx = calloc(1, sizeof(*ctx));

	//sqlite3_initialize();
	if (config)
	{
		int ret;
		if (!access(config, R_OK|W_OK))
		{
			ret = sqlite3_open_v2(config, &ctx->db, SQLITE_OPEN_READWRITE, NULL);
		}
		else if (!access(config, R_OK))
		{
			ret = sqlite3_open_v2(config, &ctx->db, SQLITE_OPEN_READONLY, NULL);
		}
		else
		{
			ret = sqlite3_open_v2(config, &ctx->db, SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE, NULL);
		}
		if (ret != SQLITE_OK)
			ctx->db = NULL;
	}
	*table = jsonsql_table;
	return ctx;
}

void jsonrpc_release(void *arg)
{
	jsonsql_ctx_t *ctx = (jsonsql_ctx_t *)arg;
	if (ctx->db)
		sqlite3_close(ctx->db);
	//sqlite3_shutdown();
	free(ctx);
}
