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

#include "httpserver/httpserver.h"
#include "httpserver/hash.h"
#include "mod_auth.h"
#include "authz_file.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

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

static void *authz_file_create(void *arg)
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
#ifdef FILE_MMAP
		ctx->passwd = calloc(1, MAXLENGTH + 1);
		ctx->group = calloc(1, MAXLENGTH + 1);
		ctx->map = addr;
		ctx->map_size = sb.st_size;
		ctx->fd = fd;
	}
	else
	{
		err("authz file map error: %s", strerror(errno));
	}
#else
		ctx->user = calloc(1, MAXLENGTH + 1);
#endif
	dbg("auth: authentication file storage on %s", config->path);
	return ctx;
}

static const char *authz_file_passwd(void *arg, const char *user)
{
	authz_file_t *ctx = (authz_file_t *)arg;
	authz_file_config_t *config = ctx->config;

#ifdef FILE_MMAP
	char *line;
	line = strstr(ctx->map, user);
	if (line)
	{
		char *passwd = strchr(line, ':');
		if (passwd)
		{
			passwd++;
			char *iterator = ctx->passwd;
			while (*passwd != ':' &&
					*passwd != '\n' &&
					*passwd != '\0' &&
						iterator < ctx->passwd + MAXLENGTH)
			{
				*iterator = *passwd;
				iterator++;
				passwd++;
			}
			*iterator = '\0';
			iterator = ctx->group;
			if (*passwd == ':')
			{
				passwd++;
				while (*passwd != ':' &&
						*passwd != '\n' &&
						*passwd != '\0' &&
						iterator < ctx->group + MAXLENGTH)
				{
					*iterator = *passwd;
					iterator++;
					passwd++;
				}
			}
			*iterator = '\0';
			return ctx->passwd;
		}
	}
#else
	FILE *file = fopen(config->path, "r");
	while(file && !feof(file))
	{
		if (fgets(ctx->user, MAXLENGTH, file) == NULL)
			break;
		char *end = strchr(ctx->user, '\n');
		if (end)
			*end = '\0';
		ctx->passwd = strchr(ctx->user, ':');
		if (ctx->passwd)
		{
			*ctx->passwd = '\0';
			ctx->passwd++;
			if (!strcmp(user, ctx->user))
			{
				ctx->group = strchr(ctx->passwd, ':');
				if (ctx->group)
				{
					*ctx->group = '\0';
					ctx->group++;
					ctx->home = strchr(ctx->group, ':');
					if (ctx->home)
					{
						*ctx->home = '\0';
						ctx->home++;
					}
				}
				fclose(file);
				return ctx->passwd;
			}
		}
	}
	if (file) fclose(file);
#endif
	return NULL;
}

static int _authz_file_checkpasswd(authz_file_t *ctx, const char *user, const char *passwd)
{
	int ret = 0;
	authz_file_config_t *config = ctx->config;

	struct passwd *userpasswd = NULL;
	userpasswd = getpwnam(user);
	if (userpasswd)
		warn("user %s pwd %s home %s", userpasswd->pw_name, userpasswd->pw_passwd, userpasswd->pw_dir);

	const char *checkpasswd = authz_file_passwd(ctx, user);
	if (checkpasswd != NULL &&
			authz_checkpasswd(checkpasswd, user, NULL,  passwd) == ESUCCESS)
		return 1;
	else
		err("auth: user %s not found in file", user);
	return ret;
}

static const char *authz_file_check(void *arg, const char *user, const char *passwd, const char *token)
{
	authz_file_t *ctx = (authz_file_t *)arg;

	if (user != NULL && passwd != NULL && _authz_file_checkpasswd(ctx, user, passwd))
		return user;
	return NULL;
}

static const char *authz_file_group(void *arg, const char *user)
{
	authz_file_t *ctx = (authz_file_t *)arg;
	authz_file_config_t *config = ctx->config;

	if (ctx->group && ctx->group[0] != '\0')
		return ctx->group;
	if (!strcmp(user, "anonymous"))
		return "anonymous";
	return NULL;
}

static const char *authz_file_home(void *arg, const char *user)
{
	authz_file_t *ctx = (authz_file_t *)arg;
	authz_file_config_t *config = ctx->config;

	if (ctx->home && ctx->home[0] != '\0')
		return ctx->home;
	return NULL;
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
	.create = authz_file_create,
	.check = authz_file_check,
	.passwd = authz_file_passwd,
	.group = authz_file_group,
	.home = authz_file_home,
	.destroy = authz_file_destroy,
};
