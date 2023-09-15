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

#include "ouistiti/httpserver.h"
#include "ouistiti/log.h"
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
	if (user == NULL || user[0] == '0')
		return NULL;

	authz_config = calloc(1, sizeof(*authz_config));
	_string_store(&authz_config->user, user, -1);

	const char *passwd = NULL;
	config_setting_lookup_string(configauth, "passwd", &passwd);
	if (passwd != NULL && passwd[0] != '0')
		_string_store(&authz_config->passwd, passwd, -1);

	const char *group = NULL;
	config_setting_lookup_string(configauth, "group", &group);
	if (group != NULL && group[0] != '0')
		_string_store(&authz_config->group, group, -1);

	const char *home = NULL;
	config_setting_lookup_string(configauth, "home", &home);
	if (home != NULL && home[0] != '0')
		_string_store(&authz_config->home, home, -1);

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
	if (!_string_cmp(&ctx->user, user, -1))
		return ctx->passwd.data;
	return NULL;
}

static const char *authz_simple_check(void *arg, const char *user, const char *passwd, const char *UNUSED(token))
{
	const authz_simple_t *ctx = (const authz_simple_t *)arg;

	if (user != NULL && passwd != NULL &&
		!_string_cmp(&ctx->user, user, -1) && !_string_empty(&ctx->passwd) &&
		(authz_checkpasswd(passwd, &ctx->user, NULL,  &ctx->passwd) == ESUCCESS))
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

	if (_string_cmp(&config->user, user, -1))
		return EREJECT;

	snprintf(info->user, USER_MAX, "%s", config->user.data);
	if (!_string_empty(&config->group))
		snprintf(info->group, FIELD_MAX, "%s", config->group.data);
	else if (!strcmp(user, str_anonymous))
		snprintf(info->group, FIELD_MAX, "%s", str_anonymous);
	if (!_string_empty(&config->home))
		snprintf(info->home, PATH_MAX, "%s", config->home.data);
	snprintf(info->status, FIELD_MAX, "%s", str_status_activated);
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
