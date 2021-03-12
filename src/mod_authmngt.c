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

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

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
static const char str_empty[] = "";

static const char str_mngtpath[] = "^/auth/mngt*";

#ifdef FILE_CONFIG
#ifdef AUTHZ_SQLITE
static void *authmngt_sqlite_config(const config_setting_t *configauth)
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
	void *(*config)(const config_setting_t *);
	authmngt_rules_t *rules;
	const char *name;
};

static const struct _authmngt_s *authmngt_list[] =
{
#ifdef AUTHZ_SQLITE
	&(struct _authmngt_s){
		.config = &authmngt_sqlite_config,
		.rules = &authmngt_sqlite_rules,
		.name = "sqlite",
	},
#endif
};

static int authmngt_setrules(const config_setting_t *configauth, mod_authmngt_t *mngtconfig)
{
	for (int i = 0; i < (sizeof(authmngt_list) / sizeof(*authmngt_list)); i++)
	{
		mngtconfig->mngt.config = authmngt_list[i]->config(configauth);
		if (mngtconfig->mngt.config != NULL)
		{
			dbg("authmngt: manager %s", authmngt_list[i]->name);
			mngtconfig->mngt.rules = authmngt_list[i]->rules;
			break;
		}
	}
	if (mngtconfig->mngt.rules == NULL)
		return EREJECT;
	return ESUCCESS;
}

static void *mod_authmngt_config(config_setting_t *iterator, server_t *UNUSED(server))
{
	mod_authmngt_t *mngtconfig = NULL;
#if LIBCONFIG_VER_MINOR < 5
	const config_setting_t *configauth = config_setting_get_member(iterator, "auth");
#else
	const config_setting_t *configauth = config_setting_lookup(iterator, "auth");
#endif
	if (configauth)
	{
		mngtconfig = calloc(1, sizeof(*mngtconfig));
		if (authmngt_setrules(configauth, mngtconfig) != ESUCCESS)
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

static int authmngt_jsonifyuser(_mod_authmngt_t *UNUSED(mod), http_message_t *response, const authsession_t *info)
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

static int authmngt_stringifyuser(_mod_authmngt_t *UNUSED(mod), http_message_t *response, const authsession_t *info)
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

static int _authmngt_parsesession(const char *query, authsession_t *session)
{
	const char *user = strstr(query, "user=");
	if (user != NULL)
	{
		size_t length = sizeof(session->user);
		user += 5;
		const char *end = strchr(user, '&');
		if (end != NULL)
			length = end - user;
		strncpy(session->user, user, length);
	}
	const char *group = strstr(query, "group=");
	if (group != NULL)
	{
		size_t length = sizeof(session->group);
		group += 6;
		const char *end = strchr(group, '&');
		if (end != NULL)
			length = end - group;
		strncpy(session->group, group, length);
	}
	const char *home = strstr(query, "home=");
	if (home != NULL)
	{
		size_t length = sizeof(session->home);
		home += 5;
		const char *end = strchr(home, '&');
		if (end != NULL)
			length = end - home;
		strncpy(session->home, home, length);
	}
	const char *passwd = strstr(query, "passwd=");
	if (passwd != NULL)
	{
		size_t length = sizeof(session->passwd);
		passwd += 9;
		const char *end = strchr(passwd, '&');
		if (end != NULL)
			length = end - passwd;
		strncpy(session->passwd, passwd, length);
	}
	const char *status = strstr(query, "status=");
	if (status != NULL)
	{
		size_t length = sizeof(session->status);
		status += 7;
		const char *end = strchr(status, '&');
		if (end != NULL)
			length = end - status;
		strncpy(session->status, status, length);
	}
	return 0;
}

static int _authmngt_execute(_mod_authmngt_t *mod, http_message_t *request, http_message_t *response, authsession_t *info)
{
	int ret = EREJECT;
	int add_passwd = 0;
	const char *method = httpmessage_REQUEST(request, "method");
	const char *query = httpmessage_REQUEST(request, "query");

	_authmngt_parsesession(query, info);
	
	auth_dbg("authmngt: on %s %s %s", info->user, info->group, info->passwd);
	if (!strcmp(method, str_put) &&
		info->user[0] != '\0' && info->group[0] != '\0' &&
		(mod->config->mngt.rules->adduser != NULL) &&
		((ret = mod->config->mngt.rules->adduser(mod->ctx, info)) == ESUCCESS))
	{
		httpmessage_result(response, 201);
		add_passwd = 1;
	}
	if ((add_passwd || !strcmp(method, str_post)) &&
		info->user[0] != '\0' && info->passwd[0] != '\0' &&
		mod->config->mngt.rules->changepasswd != NULL)
	{
		ret = mod->config->mngt.rules->changepasswd(mod->ctx, info);
	}
	if ((add_passwd || !strcmp(method, str_post)) &&
		info->user[0] != '\0' &&
		mod->config->mngt.rules->changeinfo != NULL)
	{
		ret = mod->config->mngt.rules->changeinfo(mod->ctx, info);
	}
	if (!strcmp(method, str_delete) &&
		info->user[0] != '\0' &&
		mod->config->mngt.rules->removeuser != NULL)
	{
		ret = mod->config->mngt.rules->removeuser(mod->ctx, info);
	}
	return ret;
}

static int _authmngt_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	_mod_authmngt_t *mod = (_mod_authmngt_t *)arg;

	const char *uri = httpmessage_REQUEST(request, "uri");
	const char *method = httpmessage_REQUEST(request, "method");
	const char *user = NULL;
	authsession_t info = {0};

	if (!utils_searchexp(uri, str_mngtpath, &user))
	{

		if (user != NULL)
		{
			int i = 0;
			while (user[i] == '/') i++;
			user += i;
			strncpy(info.user, user, USER_MAX);
		}

		if (!strcmp(method, str_get))
		{
			ret = ESUCCESS;
		}
		else
		{
			ret = _authmngt_execute(mod, request, response, &info);
		}
		if (ret == ESUCCESS && !strcmp(info.user, "all") &&
			mod->config->mngt.rules->listuser != NULL)
		{
			httpmessage_addcontent(response, "text/json",
				"[", -1);
			_authmngt_printuser_t printctx = {
				.mod = mod,
				.response = response,
			};
			ret = mod->config->mngt.rules->listuser(mod->ctx, _authmngt_printuser, &printctx);
			httpmessage_appendcontent(response, "{}]\n", -1);
		}
		else if (ret == ESUCCESS &&
			mod->config->mngt.rules->setsession != NULL)
		{
			mod->config->mngt.rules->setsession(mod->ctx, user, &info);

			const char *accept = httpmessage_REQUEST(request, "Accept");

			if (strstr(accept, "text/json") != NULL)
				ret = authmngt_jsonifyuser(mod, response, &info);
			else
				ret = authmngt_stringifyuser(mod, response, &info);
		}

		if (ret != ESUCCESS)
		{
			httpmessage_result(response, RESULT_500);
			ret = ESUCCESS;
		}
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
