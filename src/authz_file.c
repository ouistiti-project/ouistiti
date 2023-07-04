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
#include "authz_file.h"


#define auth_dbg(...)

//#define FILE_MMAP
#define MAXLENGTH 255

typedef struct authz_file_s authz_file_t;
struct authz_file_s
{
	authz_file_config_t *config;
	char *user;
	char *passwd;
	char *group;
	char *home;
#ifdef FILE_MMAP
	char *map;
	int map_size;
	int fd;
#endif
};

#ifdef FILE_CONFIG
void *authz_file_config(const config_setting_t *configauth)
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

static void *authz_file_create(http_server_t *UNUSED(server), void *arg)
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
		ctx->user = calloc(1, MAXLENGTH + 1);
#ifdef FILE_MMAP
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

static int _authz_file_parsestring(char *string,
			char **puser,
			char **ppasswd,
			char **pgroup,
			char **phome)
{
	*ppasswd = NULL;
	*pgroup = NULL;
	*phome = NULL;
	*puser = string;
	*ppasswd = strchr(*puser, ':');
	if (*ppasswd)
	{
		*ppasswd[0] = '\0';
		*ppasswd += 1;
		*pgroup = strchr(*ppasswd, ':');
	}
	if (*ppasswd && *pgroup)
	{
		*pgroup[0] = '\0';
		*pgroup += 1;
		*phome = strchr(*pgroup, ':');
	}
	if (*ppasswd && *pgroup && *phome)
	{
		*phome[0] = '\0';
		*phome += 1;
	}
	return 0;
}

static const char *authz_file_passwd(void *arg, const char *user)
{
	authz_file_t *ctx = (authz_file_t *)arg;
	const authz_file_config_t *config = ctx->config;

#ifdef FILE_MMAP
	char *line;
	line = strstr(ctx->map, user);
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
		if (!strncmp(line, user, end - line))
		{
			strncpy(ctx->user, line, len);
			_authz_file_parsestring(ctx->user, &ctx->user, &ctx->passwd, &ctx->group, &ctx->home);
			return ctx->passwd;
		}
	}
#else
	FILE *file = fopen(config->path, "r");
	while(file && !feof(file))
	{
		size_t len = 0;
		if (fgets(ctx->user, MAXLENGTH, file) == NULL)
			break;
		const char *end = strchr(ctx->user, ':');
		if (end == NULL)
			end = strchr(ctx->user, '\n');
		if (end)
			len = end - ctx->user;
		else
			len = strlen(ctx->user);
		len = (len > MAXLENGTH)?MAXLENGTH:len;
		if (!strncmp(user, ctx->user, len))
		{
			_authz_file_parsestring(ctx->user, &ctx->user, &ctx->passwd, &ctx->group, &ctx->home);
			fclose(file);
			return ctx->passwd;
		}
		ctx->user[0] = 0;
	}
	if (file) fclose(file);
#endif
	memset(ctx->user, 0, MAXLENGTH);
	return NULL;
}

static int _authz_file_checkpasswd(authz_file_t *ctx, const char *user, const char *passwd)
{
	int ret = 0;

	const char *checkpasswd = authz_file_passwd(ctx, user);
	if (checkpasswd != NULL &&
			authz_checkpasswd(checkpasswd, user, NULL,  passwd) == ESUCCESS)
		return 1;
	else
		err("auth: user %s not found in file", user);
	return ret;
}

static const char *authz_file_check(void *arg, const char *user, const char *passwd, const char *UNUSED(token))
{
	authz_file_t *ctx = (authz_file_t *)arg;

	if (user != NULL && passwd != NULL && _authz_file_checkpasswd(ctx, user, passwd))
		return user;
	return NULL;
}

static int authz_file_setsession(void *arg, const char *user, authsession_t *info)
{
	const authz_file_t *ctx = (const authz_file_t *)arg;
	const char *group = "users";
	const char *home = "";

	strncpy(info->user, ctx->user, USER_MAX);
	if (!strcmp(user, "anonymous"))
		group = "anonymous";
	if (ctx->group && ctx->group[0] != '\0')
		group = ctx->group;
	strncpy(info->group, group, FIELD_MAX);
	if (ctx->home && ctx->home[0] != '\0')
		home = ctx->home;
	strncpy(info->home, home, PATH_MAX);
	strncpy(info->status, str_status_activated, FIELD_MAX);
	
	return ESUCCESS;
}

static void authz_file_destroy(void *arg)
{
	authz_file_t *ctx = (authz_file_t *)arg;

#ifdef FILE_MMAP
	munmap(ctx->map, ctx->map_size);
	close(ctx->fd);
	free(ctx->passwd);
	free(ctx->group);
	if (ctx->home)
		free(ctx->home);
#else
	free(ctx->user);
#endif
	free(ctx);
}

authz_rules_t authz_file_rules =
{
	.create = &authz_file_create,
	.check = &authz_file_check,
	.passwd = &authz_file_passwd,
	.setsession = &authz_file_setsession,
	.destroy = &authz_file_destroy,
};
