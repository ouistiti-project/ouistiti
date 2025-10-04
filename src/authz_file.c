/*****************************************************************************
 * authz_file.c: Check Authentication on passwd file
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

#include "ouistiti/httpserver.h"
#include "ouistiti/log.h"
#include "mod_auth.h"


#define auth_dbg(...)

//#define FILE_MMAP
#define MAXLENGTH 255

typedef struct authz_file_config_s authz_file_config_t;
typedef struct authz_file_s authz_file_t;
struct authz_file_s
{
	authz_file_config_t *config;
	string_t *issuer;
	string_t *storage;
	string_t user;
	string_t passwd;
	string_t group;
	string_t home;
#ifdef FILE_MMAP
	char *map;
	int map_size;
	int fd;
#endif
};

struct authz_file_config_s
{
	const char *path;
};

#ifdef FILE_CONFIG
#include <libconfig.h>
void *authz_file_config(const void *configauth, authz_type_t * type)
{
	authz_file_config_t *authz_config = NULL;
	const char *path = NULL;

	config_setting_lookup_string(configauth, "file", &path);
	if (path != NULL && path[0] != '0')
	{
		authz_config = calloc(1, sizeof(*authz_config));
		authz_config->path = path;
	}
	return authz_config;
}
#endif

static void *authz_file_create(http_server_t *UNUSED(server), string_t *issuer, void *arg)
{
	authz_file_t *ctx = NULL;
	authz_file_config_t *config = (authz_file_config_t *)arg;

#ifdef FILE_MMAP
	struct stat sb;
	int fd = open(config->path, O_RDONLY);
	if (fd == -1)
	{
		err("authz file open error: %s", strerror(errno));
		return NULL;
	}
	if (fstat(fd, &sb) == -1)
	{
		err("authz file access error: %s", strerror(errno));
		close(fd);
		return NULL;
	}

	char *addr = mmap(NULL, sb.st_size, PROT_READ,
				MAP_PRIVATE, fd, 0);
	if (addr != MAP_FAILED)
	{
#endif
		ctx = calloc(1, sizeof(*ctx));
		ctx->config = config;
		ctx->issuer = issuer;
#ifndef FILE_MMAP
		ctx->storage = string_create(MAXLENGTH + 1);
#else
		ctx->map = addr;
		ctx->map_size = sb.st_size;
		ctx->fd = fd;
	}
	else
	{
		err("authz file map error: %s", strerror(errno));
	}
#endif
	dbg("auth: authentication file storage on %s", config->path);
	return ctx;
}

static int authz_file_passwd(void *arg, const string_t *user, string_t *passwd)
{
	authz_file_t *ctx = (authz_file_t *)arg;
	const authz_file_config_t *config = ctx->config;
	int ret = EREJECT;

#ifdef FILE_MMAP
	char *line;
	line = strstr(ctx->map, string_toc(user));
	if (line)
	{
		size_t len = 0;
		const char *end = strchr(line, '\n');
		if (end)
			len = end - line;
		else
			len = strlen(line);
		len = (len > MAXLENGTH)?MAXLENGTH:len;

		end = strchr(line, ':');
		if (end == NULL)
			end = line + 1;
		if (!string_cmp(&user, line, end - line))
		{
			ret = _authz_file_parsestring(line, len, &ctx->user, passwd, &ctx->group, &ctx->home);
		}
	}
#else
	FILE *file = fopen(config->path, "r");
	while(file && !feof(file))
	{
		if (string_fgetline(ctx->storage, file) == EREJECT)
			break;
		string_t usertest = {0};
		string_t passwdtest = {0};
		ret = string_split(ctx->storage, ':', &usertest, &passwdtest, NULL);
		if (ret == 2 && string_is(&usertest, user))
		{
			if (passwd)
			{
				ret = EREJECT;
				if (string_split(ctx->storage, ':', &ctx->user, passwd, &ctx->group, &ctx->home, NULL) > 1)
					ret = ESUCCESS;
			}
			else
				ret = string_length(&passwdtest);
			break;
		}
	}
	if (file)
		fclose(file);
	else
		err("authz: password file not found");
#endif
	return ret;
}

static int _authz_file_checkpasswd(authz_file_t *ctx, string_t *user, string_t *passwd)
{
	int ret = EREJECT;

	string_t *checkpasswd = string_create(1024);
	ret = authz_file_passwd(ctx, user, checkpasswd);
	if (ret == ESUCCESS)
	{
		ret = EREJECT;
		if (authz_checkpasswd(string_toc(checkpasswd), user, NULL,  passwd) == ESUCCESS)
			ret = 1;
	}
	else
		err("auth: user %s not found in file", string_toc(user));
	string_cleansafe(checkpasswd);
	string_destroy(checkpasswd);
	return ret;
}

static const char *authz_file_check(void *arg, const char *user, const char *passwd, const char *token)
{
	authz_file_t *ctx = (authz_file_t *)arg;

	string_t userstr = {0};
	string_store(&userstr, user, -1);
	string_t passwdstr = {0};
	string_store(&passwdstr, passwd, -1);
	if (!string_empty(&userstr) && !string_empty(&passwdstr) && _authz_file_checkpasswd(ctx, &userstr, &passwdstr))
		return user;
	return NULL;
}

static int authz_file_setsession(void *arg, const char *user, const char *token, auth_saveinfo_t cb, void *cbarg)
{
	const authz_file_t *ctx = (const authz_file_t *)arg;

	cb(cbarg, STRING_REF(str_user), STRING_INFO(ctx->user));
	if (!strcmp(ctx->user.data, str_anonymous))
		cb(cbarg, STRING_REF(str_group), STRING_REF(str_anonymous));
	else if (ctx->group.data && ctx->group.length > 0)
		cb(cbarg, STRING_REF(str_group), STRING_INFO(ctx->group));
	else
		cb(cbarg, STRING_REF(str_group), STRING_REF("users"));
	if (ctx->home.data && ctx->home.length > 0)
		cb(cbarg, STRING_REF(str_home), STRING_INFO(ctx->home));
	cb(cbarg, STRING_REF(str_status), STRING_REF(str_status_activated));
	if (token)
		cb(cbarg, STRING_REF(str_token), STRING_REF(token));

	return ESUCCESS;
}

static void authz_file_destroy(void *arg)
{
	authz_file_t *ctx = (authz_file_t *)arg;

#ifdef FILE_MMAP
	munmap(ctx->map, ctx->map_size);
	close(ctx->fd);
#else
	if (ctx->storage)
		string_destroy(ctx->storage);
#endif
	free(ctx->config);
	free(ctx);
}

authz_rules_t authz_file_rules =
{
	.config = authz_file_config,
	.create = &authz_file_create,
	.check = &authz_file_check,
	.passwd = &authz_file_passwd,
	.setsession = &authz_file_setsession,
	.destroy = &authz_file_destroy,
};

static const string_t authz_name = STRING_DCL("file");
static void __attribute__ ((constructor)) _init()
{
	auth_registerauthz(&authz_name, &authz_file_rules);
}
