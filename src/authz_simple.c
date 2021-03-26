/*****************************************************************************
 * authz_simple.c: Check Authentication in configuration file
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
#include <pwd.h>

#include "httpserver/httpserver.h"
#include "httpserver/log.h"
#include "mod_auth.h"
#include "authz_simple.h"

#define auth_dbg(...)

typedef authz_simple_config_t authz_simple_t;

#ifdef FILE_CONFIG
void *authz_simple_config(const config_setting_t *configauth)
{
	authz_simple_config_t *authz_config = NULL;
	const char *user = NULL;
	config_setting_lookup_string(configauth, "user", &user);
	if (user != NULL && user[0] != '0')
	{
		const char *passwd = NULL;
		const char *group = NULL;
		const char *home = NULL;
		config_setting_lookup_string(configauth, "passwd", &passwd);
		config_setting_lookup_string(configauth, "group", &group);
		config_setting_lookup_string(configauth, "home", &home);
		authz_config = calloc(1, sizeof(*authz_config));
		authz_config->user = user;
		authz_config->group = group;
		authz_config->home = home;
		authz_config->passwd = passwd;
	}
	return authz_config;
}
#endif

static void *authz_simple_create(http_server_t *UNUSED(server), void *config)
{
	return config;
}

static const char *authz_simple_passwd(void *arg,const  char *user)
{
	const authz_simple_t *ctx = (const authz_simple_t *)arg;
	if (!strcmp(user, ctx->user))
		return ctx->passwd;
	return NULL;
}

static const char *authz_simple_check(void *arg, const char *user, const char *passwd, const char *UNUSED(token))
{
	const authz_simple_t *ctx = (const authz_simple_t *)arg;

	if (user != NULL && passwd != NULL && !strcmp(user, ctx->user) &&
		ctx->passwd && (authz_checkpasswd(passwd, ctx->user, NULL,  ctx->passwd) == ESUCCESS))
	{
			return user;
	}
	return NULL;
}

static int authz_simple_setsession(void *arg, const char * user, authsession_t *info)
{
	const authz_simple_t *config = (const authz_simple_t *)arg;

	if (user == NULL)
		return EREJECT;

	if (strcmp(user, config->user))
		return EREJECT;

	strncpy(info->user, config->user, USER_MAX);
	if (config->group && config->group[0] != '\0')
		strncpy(info->group, config->group, FIELD_MAX);
	else if (!strcmp(user, "anonymous"))
		strncpy(info->group, "anonymous", FIELD_MAX);
	if (config->home && config->home[0] != '\0')
		strncpy(info->home, config->home, PATH_MAX);
	strncpy(info->status, str_status_activated, FIELD_MAX);
	return ESUCCESS;
}

authz_rules_t authz_simple_rules =
{
	.create = &authz_simple_create,
	.check = &authz_simple_check,
	.passwd = &authz_simple_passwd,
	.setsession = &authz_simple_setsession,
	.destroy = NULL,
};
