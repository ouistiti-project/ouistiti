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
#  include <pwd.h>

#include "httpserver/httpserver.h"
#include "mod_auth.h"
#include "authz_simple.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

typedef authz_simple_config_t authz_simple_t;
void *authz_simple_create(void *config)
{
	return config;
}

char *authz_simple_passwd(void *arg, char *user)
{
	authz_simple_t *config = (authz_simple_t *)arg;
	if (!strcmp(user, config->user))
		return config->passwd;
	return NULL;
}

int authz_simple_check(void *arg, char *user, char *passwd)
{
	authz_simple_t *config = (authz_simple_t *)arg;

	if (!strcmp(user, config->user)  && config->passwd && !strcmp(passwd, config->passwd))
		return 1;
	return 0;
}

char *authz_simple_group(void *arg, char *user)
{
	authz_simple_t *config = (authz_simple_t *)arg;
	if (!strcmp(user, config->user) && config->group && config->group[0] != '\0')
	{
		return config->group;
	}
	if (!strcmp(user, "anonymous"))
		return "anonymous";
	return NULL;
}

char *authz_simple_home(void *arg, char *user)
{
	authz_simple_t *config = (authz_simple_t *)arg;
	if (!strcmp(user, config->user) && config->home && config->home[0] != '\0')
	{
		return config->home;
	}
	return NULL;
}

authz_rules_t authz_simple_rules =
{
	.create = authz_simple_create,
	.check = authz_simple_check,
	.passwd = authz_simple_passwd,
	.group = authz_simple_group,
	.home = authz_simple_home,
	.destroy = NULL,
};
