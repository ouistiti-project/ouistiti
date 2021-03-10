/*****************************************************************************
 * mod_authmngt.c: Authentication management module
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>

#include "httpserver/httpserver.h"
#include "httpserver/utils.h"
#include "httpserver/hash.h"
#include "httpserver/log.h"

#include "mod_auth.h"
#include "mod_authmngt.h"

#include "authz_sqlite.h"

#define auth_dbg dbg

typedef struct _mod_authmngt_s _mod_authmngt_t;

static int _authmngt_connector(void *arg, http_message_t *request, http_message_t *response);

static const char str_authmngt[] = "authmngt";

struct _mod_authmngt_s
{
	mod_authmngt_t *config;
	void *ctx;
};

static const char str_put[] = "PUT";
static const char str_delete[] = "DELETE";

static const char str_mngtpath[] = "^/auth/mngt*";

#ifdef FILE_CONFIG
#include <libconfig.h>
#ifdef AUTHZ_SQLITE
static void *authmngt_sqlite_config(config_setting_t *configauth)
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

struct _authmngt_s
{
	void *(*config)(config_setting_t *);
	authmngt_rules_t *rules;
	const char *name;
};

struct _authmngt_s *authmngt_list[] =
{
#ifdef AUTHZ_SQLITE
	&(struct _authmngt_s){
		.config = &authmngt_sqlite_config,
		.rules = &authmngt_sqlite_rules,
		.name = "sqlite",
	},
#endif
	NULL
};

static void *mod_authmngt_config(config_setting_t *iterator, server_t *server)
{
	mod_authmngt_t *mngtconfig = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configauth = config_setting_get_member(iterator, "auth");
#else
	config_setting_t *configauth = config_setting_lookup(iterator, "auth");
#endif
	if (configauth)
	{
		mngtconfig = calloc(1, sizeof(*mngtconfig));
		/**
		 * signin URI allowed to access to the signin page
		 */
		int ret;
		int i = 0;
		while (authmngt_list[i] != NULL)
		{
			mngtconfig->mngt.config = authmngt_list[i]->config(configauth);
			if (mngtconfig->mngt.config != NULL)
			{
				dbg("authmngt: manager %s", authmngt_list[i]->name);
				mngtconfig->mngt.rules = authmngt_list[i]->rules;
				break;
			}
			i++;
		}
		if (mngtconfig->mngt.rules == NULL)
		{
			free(mngtconfig);
			mngtconfig = NULL;
		}
	}
	return mngtconfig;
}
#else
static const mod_authmngt_t g_authmngt_config =
{
	.mngt = &(mod_authz_t){
		.config = &(authz_sqlite_config_t){
			.dbname = "/etc/ouistiti/auth.db",
		},
		.rules = &authmngt_sqlite_rules,
		.name = "sqlite",
	},
};

static void *mod_authmngt_config(void *iterator, server_t *server)
{
	return (void *)&g_authmngt_config;
}
#endif

static void *mod_authmngt_create(http_server_t *server, mod_authmngt_t *config)
{
	_mod_authmngt_t *mod;

	if (!config)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = config;

	mod->ctx = mod->config->mngt.rules->create(server, config->mngt.config);
	if (mod->ctx == NULL)
	{
#ifdef FILE_CONFIG
		free(mod->config);
#endif
		free(mod);
		return NULL;
	}

	httpserver_addmethod(server, str_put, MESSAGE_ALLOW_CONTENT);
	httpserver_addmethod(server, str_delete, MESSAGE_ALLOW_CONTENT);
	httpserver_addconnector(server, _authmngt_connector, mod, CONNECTOR_DOCUMENT, "authmngt");

	return mod;
}

static void mod_authmngt_destroy(void *arg)
{
	_mod_authmngt_t *mod = (_mod_authmngt_t *)arg;
	if (mod->ctx  && mod->config->mngt.rules->destroy)
	{
		mod->config->mngt.rules->destroy(mod->ctx);
	}
#ifdef FILE_CONFIG
	free(mod->config);
#endif
	free(mod);
}

static int authmngt_jsonifyuser(_mod_authmngt_t *mod, http_message_t *response, const authsession_t *info)
{
	if (info->user[0] == '\0')
		return EREJECT;

	httpmessage_addcontent(response, "text/json", "", -1);

	httpmessage_appendcontent(response, "{\"user\":\"", -1);
	httpmessage_appendcontent(response, info->user, -1);
	httpmessage_appendcontent(response, "\"", -1);
	if (info->group != NULL)
	{
		httpmessage_appendcontent(response, ",\"group\":\"", -1);
		httpmessage_appendcontent(response, info->group, -1);
		httpmessage_appendcontent(response, "\"", -1);
	}
	if (info->status != NULL)
	{
		httpmessage_appendcontent(response, ",\"status\":\"", -1);
		httpmessage_appendcontent(response, info->status, -1);
		httpmessage_appendcontent(response, "\"", -1);
	}
	if (info->home != NULL)
	{
		httpmessage_appendcontent(response, ",\"home\":\"", -1);
		httpmessage_appendcontent(response, info->home, -1);
		httpmessage_appendcontent(response, "\"", -1);
	}
	if (info->token != NULL)
	{
		httpmessage_appendcontent(response, ",\"token\":\"", -1);
		httpmessage_appendcontent(response, info->token, -1);
		httpmessage_appendcontent(response, "\"", -1);
	}
	httpmessage_appendcontent(response, "}", -1);
	return 0;
}

static int authmngt_stringifyuser(_mod_authmngt_t *mod, http_message_t *response, const authsession_t *info)
{
	if (info->user[0] == '\0')
		return EREJECT;

	httpmessage_addcontent(response, "application/x-www-form-urlencoded",
		"user=", -1);

	httpmessage_appendcontent(response, info->user, -1);
	if (info->group[0] != '\0')
	{
		httpmessage_appendcontent(response, "&group=", -1);
		httpmessage_appendcontent(response, info->group, -1);
	}
	if (info->status[0] != '\0')
	{
		httpmessage_appendcontent(response, "&status=", -1);
		httpmessage_appendcontent(response, info->status, -1);
	}
	if (info->home[0] != '\0')
	{
		httpmessage_appendcontent(response, "&home=", -1);
		httpmessage_appendcontent(response, info->home, -1);
	}
	if (info->token[0] != '\0')
	{
		httpmessage_appendcontent(response, "&token=", -1);
		httpmessage_appendcontent(response, info->token, -1);
	}
	return 0;
}

typedef struct _authmngt_printuser_s
{
	_mod_authmngt_t *mod;
	http_message_t *response;
} _authmngt_printuser_t;

static int _authmngt_printuser(void*arg, int nfields, char** values,char** keys)
{
	_authmngt_printuser_t *printctx = (_authmngt_printuser_t *)arg;
	http_message_t *response = printctx->response;

	httpmessage_appendcontent(response, "{\"", -1);
	for (int i = 0; i < nfields; i++)
	{
		if (i > 0)
			httpmessage_appendcontent(response, ",\"", -1);
		httpmessage_appendcontent(response, keys[i], -1);
		httpmessage_appendcontent(response, "\"=\"", -1);
		httpmessage_appendcontent(response, values[i], -1);
		httpmessage_appendcontent(response, "\"", -1);
	}
	httpmessage_appendcontent(response, "},", -1);
	return ESUCCESS;
}

static int _authmngt_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	_mod_authmngt_t *mod = (_mod_authmngt_t *)arg;

	const char *uri = httpmessage_REQUEST(request, "uri");
	const char *method = httpmessage_REQUEST(request, "method");
	const char *user = NULL;

	if (!utils_searchexp(uri, str_mngtpath, &user))
	{
		const char *group = NULL;
		const char *home = NULL;
		const char *token = NULL;
		const char *passwd = NULL;
		const char *status = NULL;

		authsession_t session = {0};
		const char *query = httpmessage_REQUEST(request, "query");

		char *storage = strdup(query);
		if (user == NULL)
		{
			user = strstr(storage, "user=");
			if (user != NULL)
			{
				user += 5;
				char *end = strchr(user, '&');
				if (end != NULL)
					*end = '\0';
			}
		}
		else
		{
			int i = 0;
			while (user[i] == '/') i++;
			user += i;
		}

		group = strstr(storage, "group=");
		home = strstr(storage, "home=");
		passwd = strstr(storage, "password=");
		status = strstr(storage, "status=");
		if (!strcmp(method, str_get))
		{
			ret = ESUCCESS;
		}
		else
		{
			int add_passwd = 0;

			if (user != NULL)
			{
				strncpy(session.user, user, sizeof(session.user));
			}
			if (group != NULL)
			{
				group += 6;
				char *end = strchr(group, '&');
				if (end != NULL)
					*end = '\0';
				strncpy(session.group, group, sizeof(session.group));
			}
			if (home != NULL)
			{
				home += 5;
				char *end = strchr(home, '&');
				if (end != NULL)
					*end = '\0';
				strncpy(session.home, home, sizeof(session.home));
			}
			if (passwd != NULL)
			{
				passwd += 9;
				char *end = strchr(passwd, '&');
				if (end != NULL)
					*end = '\0';
				strncpy(session.passwd, passwd, sizeof(session.passwd));
			}
			if (status != NULL)
			{
				status += 7;
				char *end = strchr(status, '&');
				if (end != NULL)
					*end = '\0';
				strncpy(session.status, status, sizeof(session.status));
			}
			auth_dbg("authmngt: on %s %s %s", session.user, session.group, session.passwd);
			if (!strcmp(method, str_put) &&
				session.user[0] != '\0' && session.group[0] != '\0' &&
				(mod->config->mngt.rules->adduser != NULL) &&
				(ret = mod->config->mngt.rules->adduser(mod->ctx, &session)) == ESUCCESS)
			{
				httpmessage_result(response, 201);
				add_passwd = 1;
			}
			if ((add_passwd || !strcmp(method, str_post)) &&
				session.user[0] != '\0' && session.passwd[0] != '\0' &&
				mod->config->mngt.rules->changepasswd != NULL)
			{
				ret = mod->config->mngt.rules->changepasswd(mod->ctx, &session);
			}
			if ((add_passwd || !strcmp(method, str_post)) &&
				session.user[0] != '\0' &&
				mod->config->mngt.rules->changeinfo != NULL)
			{
				ret = mod->config->mngt.rules->changeinfo(mod->ctx, &session);
			}
			if (!strcmp(method, str_delete) &&
				session.user[0] != '\0' &&
				mod->config->mngt.rules->removeuser != NULL)
			{
				ret = mod->config->mngt.rules->removeuser(mod->ctx, &session);
			}
		}
		if (ret != ESUCCESS)
		{
			httpmessage_result(response, RESULT_500);
			ret = ESUCCESS;
		}
		else if (user != NULL)
		{
			authsession_t info = {0};

			if (mod->config->mngt.rules->setsession != NULL)
				mod->config->mngt.rules->setsession(mod->ctx, user, &info);

			const char *accept = httpmessage_REQUEST(request, "Accept");

			if (strstr(accept, "text/json") != NULL)
				authmngt_jsonifyuser(mod, response, &info);
			else
				authmngt_stringifyuser(mod, response, &info);
		}
		else if (mod->config->mngt.rules->listuser != NULL)
		{
			httpmessage_addcontent(response, "text/json",
				"[", -1);
			_authmngt_printuser_t printctx = {
				.mod = mod,
				.response = response,
			};
			mod->config->mngt.rules->listuser(mod->ctx, _authmngt_printuser, &printctx);
			httpmessage_appendcontent(response, "{}]\n", -1);
		}
		free(storage);
	}
	return ret;
}

const module_t mod_authmngt =
{
	.name = str_authmngt,
	.configure = (module_configure_t)&mod_authmngt_config,
	.create = (module_create_t)&mod_authmngt_create,
	.destroy = &mod_authmngt_destroy
};

#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_authmngt")));
#endif
