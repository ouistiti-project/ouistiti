/*****************************************************************************
 * authz_unix.c: Check Authentication on passwd file
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
#include <shadow.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include "../compliant.h"
#include "httpserver/httpserver.h"
#include "mod_auth.h"
#include "authz_unix.h"

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

#ifdef HAVE_PWD

typedef struct authz_unix_s authz_unix_t;
struct authz_unix_s
{
	authz_file_config_t *config;
	char *user;
	char *passwd;
	char *group;
	char *home;
};

static void *authz_unix_create(void *arg)
{
	authz_unix_t *ctx = NULL;
	authz_file_config_t *config = (authz_file_config_t *)arg;

	ctx = calloc(1, sizeof(*ctx));
	ctx->config = config;
	return ctx;
}

static int _authz_unix_checkpasswd(authz_unix_t *ctx, const char *user, const char *passwd)
{
	int ret = 0;
	authz_file_config_t *config = ctx->config;

	if (ctx->user && !strcmp(user, ctx->user))
		ret = 1;

	struct passwd *pw = NULL;
	pw = getpwnam(user);
	if (passwd && pw)
	{
		char *cryptpasswd = pw->pw_passwd;
		/* get the shadow password if possible */
		uid_t uid;
		uid = geteuid();
		if (seteuid(0) < 0)
			warn("not enought rights to change user to root");
		struct spwd *spasswd = getspnam(pw->pw_name);
		if (seteuid(uid) < 0)
			warn("not enought rights to change user");
		if (spasswd && spasswd->sp_pwdp) {
			cryptpasswd = spasswd->sp_pwdp;
		}

		char *testpasswd = NULL;
		if (strcmp(cryptpasswd, "x"))
			testpasswd = crypt(passwd, cryptpasswd);
		else
		{
			warn("authz unix: unaccessible user");
			if (geteuid() != 0)
				err("authz unix: run ouistiti as root for unix file authentication");
		}

		if (testpasswd && !strcmp(testpasswd, cryptpasswd))
		{
			ret = 1;
#ifdef HAVE_STRDUP
			ctx->user = strdup(pw->pw_name);
			ctx->home = strdup(pw->pw_dir);
#else
			ctx->user = pw->pw_name;
			ctx->home = pw->pw_dir;
#endif
			struct group *grp;
			grp = getgrgid(pw->pw_gid);
			if (grp)
			{
#ifdef HAVE_STRDUP
				ctx->group = strdup(grp->gr_name);
#else
				ctx->group = grp->gr_name;
#endif
			}
		}
		else
		{
			auth_dbg("authz unix: passwd error");
		}
	}
	else
	{
		auth_dbg("authz unix: user %s not found", user);
	}
	return ret;
}

static const char *authz_unix_check(void *arg, const char *user, const char *passwd, const char *token)
{
	authz_unix_t *ctx = (authz_unix_t *)arg;

	if (user != NULL && passwd != NULL && _authz_unix_checkpasswd(ctx, user, passwd))
		return user;
	return NULL;
}

static const char *authz_unix_group(void *arg, const char *user)
{
	authz_unix_t *ctx = (authz_unix_t *)arg;
	authz_file_config_t *config = ctx->config;

	if (ctx->group && ctx->group[0] != '\0')
		return ctx->group;
	if (!strcmp(user, "anonymous"))
		return "anonymous";
	return NULL;
}

static const char *authz_unix_home(void *arg, const char *user)
{
	authz_unix_t *ctx = (authz_unix_t *)arg;
	authz_file_config_t *config = ctx->config;

	if (ctx->home && ctx->home[0] != '\0')
		return ctx->home;
	return NULL;
}

static void authz_unix_destroy(void *arg)
{
	authz_unix_t *ctx = (authz_unix_t *)arg;

#ifdef HAVE_STRDUP
	if (ctx->user)
		free(ctx->user);
	if (ctx->home)
		free(ctx->home);
	if (ctx->group)
		free(ctx->group);
#endif
	free(ctx);
}

authz_rules_t authz_unix_rules =
{
	.create = authz_unix_create,
	.check = authz_unix_check,
	.passwd = NULL,
	.group = authz_unix_group,
	.home = authz_unix_home,
	.destroy = authz_unix_destroy,
};
#endif
