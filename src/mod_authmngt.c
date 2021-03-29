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

#define authmngt_dbg(...)

typedef struct _mod_authmngt_s _mod_authmngt_t;

static int _authmngt_connector(void *arg, http_message_t *request, http_message_t *response);

static const char str_authmngt[] = "authmngt";

struct _mod_authmngt_s
{
	mod_authmngt_t *config;
	void *ctx;
	const char *error;
	int list;
	unsigned int isroot:1;
	unsigned int isuser:1;
};

static const char str_put[] = "PUT";
static const char str_delete[] = "DELETE";

static const char str_mngtpath[] = "^/auth/mngt*";

static const char error_usernotfound[] = "user not found";
static const char error_accessdenied[] = "access denied";
static const char error_badvalue[] = "bad value";

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
			authmngt_dbg("authmngt: manager %s", authmngt_list[i]->name);
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

	httpserver_addmethod(server, str_post, MESSAGE_ALLOW_CONTENT | MESSAGE_PROTECTED);
	httpserver_addmethod(server, str_put, MESSAGE_ALLOW_CONTENT | MESSAGE_PROTECTED);
	httpserver_addmethod(server, str_delete, MESSAGE_ALLOW_CONTENT | MESSAGE_PROTECTED);
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
	return ESUCCESS;
}

static int authmngt_stringifyuser(_mod_authmngt_t *UNUSED(mod), http_message_t *response, const authsession_t *info)
{
	if (info->user[0] == '\0')
		return EREJECT;

	httpmessage_appendcontent(response, "user=", -1);

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

static int _authmngt_checkrights(_mod_authmngt_t *mod, const char *user, http_message_t *request)
{
	const char *auth = auth_info(request, "user");
	if (auth && user)
		mod->isuser = !strcmp(auth, user);
	const char *group = auth_info(request, "group");
	if (group && !strcmp(group, "root"))
	{
		mod->isroot = 1;
		mod->isuser = 1;
	}
	return mod->isuser;
}

static int _authmngt_parsesession(_mod_authmngt_t *mod, const char *user, http_message_t *request, authsession_t *session)
{
	int ret = ESUCCESS;
	const char *query = httpmessage_REQUEST(request, "query");

	if (user == NULL)
	{
		user = strstr(query, "user=");
		user += 5;
	}
	if (user != NULL)
	{
		size_t length = USER_MAX;
		char *decode = utils_urldecode(user, -1);
		if (decode != NULL)
		{
			length = strlen(decode);
			length = (length > USER_MAX)? USER_MAX : length;
			strncpy(session->user, decode, length);
			free(decode);
		}
	}
	else
		return EREJECT;

	const char *group = strstr(query, "group=");
	if (group != NULL)
	{
		size_t length = FIELD_MAX;
		group += 6;
		const char *end = strchr(group, '&');
		if (end != NULL && (end - group) < FIELD_MAX)
			length = end - group;
		strncpy(session->group, group, length);
		if (!mod->isroot)
			ret = EREJECT;
	}
	const char *home = strstr(query, "home=");
	if (home != NULL)
	{
		size_t length = PATH_MAX;
		home += 5;
		const char *end = strchr(home, '&');
		if (end != NULL && (end - home) < PATH_MAX)
			length = end - home;
		strncpy(session->home, home, length);
		if (!mod->isroot)
			ret = EREJECT;
	}
	const char *passwd = strstr(query, "passwd=");
	if (passwd != NULL)
	{
		size_t length = TOKEN_MAX;
		passwd += 7;
		char *decode = utils_urldecode(passwd, -1);
		if (decode != NULL)
		{
			length = strlen(decode);
			length = (length > TOKEN_MAX)? TOKEN_MAX : length;
			strncpy(session->passwd, decode, length);
			free(decode);
		}
		if (!mod->isuser)
			ret = EREJECT;
	}
	const char *status = strstr(query, "status=");
	if (status != NULL)
	{
		size_t length = FIELD_MAX;
		status += 7;
		const char *end = strchr(status, '&');
		if (end != NULL && (end - status) < FIELD_MAX)
			length = end - status;
		strncpy(session->status, status, length);
		if (!mod->isroot)
			ret = EREJECT;
	}
	return ret;
}

static int _authmngt_listresponse(_mod_authmngt_t *mod, http_message_t *response)
{
	int ret = EREJECT;
	authsession_t info = {0};
	if (mod->config->mngt.rules->getuser != NULL)
		ret = mod->config->mngt.rules->getuser(mod->ctx, mod->list + 1, &info);
	if (ret == ESUCCESS)
	{
		if (mod->list > 0)
			httpmessage_appendcontent(response, ",", -1);
		ret = authmngt_jsonifyuser(mod, response, &info);
	}
	if (ret == EREJECT)
	{
		httpmessage_appendcontent(response, "]", -1);
		mod->list = -1;
	}
	else
	{
		mod->list++;
	}
	return ECONTINUE;
}

static int _authmngt_userresponse(_mod_authmngt_t *mod, authsession_t *info, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	const char *http_accept = httpmessage_REQUEST(request, "Accept");

	if (strstr(http_accept, "text/json") != NULL)
	{
		httpmessage_addcontent(response, "text/json", "", -1);
		ret = authmngt_jsonifyuser(mod, response, info);
	}
	else
	{
		httpmessage_addcontent(response, "application/x-www-form-urlencoded", "", -1);
		ret = authmngt_stringifyuser(mod, response, info);
	}
	return ret;
}

static int _authmngt_errorresponse(_mod_authmngt_t *mod, const char *user, http_message_t *request, http_message_t *response)
{
	const char *http_accept = httpmessage_REQUEST(request, "Accept");
	httpmessage_result(response, RESULT_500);
	if (strstr(http_accept, "text/json") != NULL)
	{
		httpmessage_addcontent(response, "text/json", "{\"method\":\"", -1);
		httpmessage_appendcontent(response, httpmessage_REQUEST(request, "method"), -1);
		httpmessage_appendcontent(response, "\",\"user\":\"", -1);
		httpmessage_appendcontent(response, user, -1);
		httpmessage_appendcontent(response, "\",\"error\":\"", -1);
		httpmessage_appendcontent(response, mod->error, -1);
		httpmessage_appendcontent(response, "\"}", -1);
	}

	return ESUCCESS;
}

static int _authmngt_getconnector(_mod_authmngt_t *mod, const char *user, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;

	if (user != NULL)
	{
		authsession_t info = {0};
		if (mod->config->mngt.rules->setsession != NULL)
			ret = mod->config->mngt.rules->setsession(mod->ctx, user, &info);
		if (ret == ESUCCESS)
			ret = _authmngt_userresponse(mod, &info, request, response);
		else
			mod->error = error_usernotfound;
	}
	else if (mod->list == 0)
	{
		httpmessage_addcontent(response, "text/json", NULL, -1);
		httpmessage_appendcontent(response, "[", -1);
		ret = _authmngt_listresponse(mod, response);
	}
	else if (mod->list > 0)
	{
		httpmessage_addcontent(response, NULL, "", -1);
		ret = _authmngt_listresponse(mod, response);
	}
	else
	{
		httpclient_shutdown(httpmessage_client(request));
		ret = ESUCCESS;
	}
	
	return ret;
}

static int _authmngt_deleteconnector(_mod_authmngt_t *mod, const char *user, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	if (!_authmngt_checkrights(mod, user, request))
	{
		mod->error = error_accessdenied;
	}
	else if (user != NULL && mod->config->mngt.rules->removeuser != NULL)
	{
		authsession_t info = {0};
		strncpy(info.user, user, USER_MAX);
		ret = mod->config->mngt.rules->removeuser(mod->ctx, &info);
		if (ret == EREJECT)
			mod->error = error_usernotfound;
	}
	else
	{
		mod->error = error_badvalue;
	}
	return ret;
}

static int _authmngt_putconnector(_mod_authmngt_t *mod, const char *user, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;

	_authmngt_checkrights(mod, user, request);
	mod->isuser = 1;

	authsession_t info = {0};
	ret = _authmngt_parsesession(mod, user, request, &info);
	if (ret == ESUCCESS && mod->config->mngt.rules->adduser != NULL)
	{
		ret = mod->config->mngt.rules->adduser(mod->ctx, &info);
		if (ret == ESUCCESS && mod->config->mngt.rules->setsession != NULL)
		{
			ret = mod->config->mngt.rules->setsession(mod->ctx, info.user, &info);
			if (ret == ESUCCESS)
				ret = _authmngt_userresponse(mod, &info, request, response);
			else
				mod->error = error_usernotfound;
		}
		else
			mod->error = error_badvalue;
		if (ret == ESUCCESS)
			httpmessage_result(response, 201);
	}
	else
		mod->error = error_accessdenied;
	return ret;
}

static int _authmngt_postconnector(_mod_authmngt_t *mod, const char *user, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	if (!_authmngt_checkrights(mod, user, request))
	{
		mod->error = error_accessdenied;
		return ret;
	}

	authsession_t info = {0};
	ret = _authmngt_parsesession(mod, user, request, &info);

	if (ret == ESUCCESS && mod->isroot && mod->config->mngt.rules->changeinfo != NULL)
	{
		ret = mod->config->mngt.rules->changeinfo(mod->ctx, &info);
	}
	if (ret == ESUCCESS && mod->isuser && mod->config->mngt.rules->changepasswd != NULL)
	{
		ret = mod->config->mngt.rules->changepasswd(mod->ctx, &info);
		if (!strcmp(info.status, str_status_reapproving) && mod->config->mngt.rules->changeinfo != NULL)
		{
			authsession_t newinfo;
			strncpy(newinfo.user, info.user, USER_MAX);
			strncpy(newinfo.status, str_status_activated, FIELD_MAX);
			ret = mod->config->mngt.rules->changeinfo(mod->ctx, &newinfo);
		}
	}
	if (ret == EREJECT)
		mod->error = error_badvalue;
	return ret;
}

static int _authmngt_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	_mod_authmngt_t *mod = (_mod_authmngt_t *)arg;
	const char *uri = httpmessage_REQUEST(request, "uri");
	const char *user = NULL;

	authmngt_dbg("authmngt: search %s", str_mngtpath);
	if (utils_searchexp(uri, str_mngtpath, &user))
		return EREJECT;

	const char *method = httpmessage_REQUEST(request, "method");

	authmngt_dbg("authmngt: access to %s", uri);

	while (user && user[0] == '/') user++;
	if (!strcmp(method, str_get))
	{
		ret = _authmngt_getconnector(mod, user, request, response);
	}
	else if (!strcmp(method, str_delete))
	{
		ret = _authmngt_deleteconnector(mod, user, request, response);
	}
	else if (!strcmp(method, str_put))
	{
		authsession_t info = {0};
		ret = _authmngt_putconnector(mod, user, request, response);
	}
	else if (!strcmp(method, str_post))
	{
		authsession_t info = {0};
		ret = _authmngt_postconnector(mod, user, request, response);
		if (ret == ESUCCESS && user != NULL && mod->config->mngt.rules->setsession != NULL)
			ret = mod->config->mngt.rules->setsession(mod->ctx, user, &info);
		else
			ret = EREJECT;
		if (ret == ESUCCESS)
			ret = _authmngt_userresponse(mod, &info, request, response);
		else
			mod->error = error_usernotfound;
	}
	if (ret == EREJECT)
	{
		ret = _authmngt_errorresponse(mod, user, request, response);
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
