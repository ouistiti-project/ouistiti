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
#include <crypt.h>
#include <time.h>

#include "ouistiti/httpserver.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
#include "daemonize.h"

#define auth_dbg(...)

#define USE_PASSWD_R
//#define FILE_MMAP
#define MAXLENGTH 255

#ifdef USE_REENTRANT
# ifdef CRYPT_DATA_RESERVED_SIZE
#  define USE_CRYPT_R
# endif
# ifdef NSS_BUFLEN_GROUP
#  define USE_GROUP_R
# endif
# ifdef NSS_BUFLEN_PASSWD
#  define USE_PASSWD_R
# endif
#endif

typedef struct authz_file_config_s authz_file_config_t;
struct authz_file_config_s
{
	const char *path;
};

typedef struct authz_mod_s authz_mod_t;
struct authz_mod_s
{
	authz_file_config_t *config;
	string_t *issuer;
};

typedef struct authz_ctx_s authz_ctx_t;
struct authz_ctx_s
{
	authz_mod_t *mod;
	struct passwd pwstore;
	char passwd[NSS_BUFLEN_PASSWD];
	string_t status;
};

#ifdef FILE_CONFIG
#include <libconfig.h>
void *authz_unix_config(const void *configauth, authz_type_t * type)
{
	authz_file_config_t *authz_config = NULL;
	const char *path = NULL;
	const char *name = NULL;

	config_setting_lookup_string(configauth, "file", (const char **)&path);
	int ret = config_setting_lookup_string(configauth, "authz", &name);
	if (ret == CONFIG_TRUE && strstr(name, "unix") != NULL)
	{
		authz_config = calloc(1, sizeof(*authz_config));
		authz_config->path = path;
	}
	else if (path != NULL && path[0] != '0' && strstr(path, "shadow"))
	{
		authz_config = calloc(1, sizeof(*authz_config));
		authz_config->path = path;
	}
	else
		warn("auth: no shadow");
	return authz_config;
}
#endif

static void *authz_unix_create(http_server_t *UNUSED(server), string_t *issuer, void *arg)
{
	authz_mod_t *ctx = NULL;
	authz_file_config_t *config = (authz_file_config_t *)arg;

	ctx = calloc(1, sizeof(*ctx));
	ctx->config = config;
	ctx->issuer = issuer;
	return ctx;
}

static void *authz_unix_setup(void *arg, http_client_t *clt, struct sockaddr *addr, int addrsize)
{
	authz_mod_t *mod = (authz_mod_t *)arg;
	authz_ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->mod = mod;
	return ctx;
}

typedef struct authz_shadow_s authz_shadow_t;
struct authz_shadow_s
{
	authz_ctx_t *ctx;
	string_t *user;
	string_t *passwd;
};

static int _authz_unix_checkshadow(void *arg)
{
	int ret = EREJECT;
	authz_shadow_t *shadow = (authz_shadow_t *)arg;
	authz_ctx_t *ctx = shadow->ctx;
	struct spwd *pw = NULL;
	string_t status = STRING_DCL(str_status_activated);

#ifdef USE_PASSWD_R
	struct spwd spwdstore;
	char shadowdata[NSS_BUFLEN_PASSWD];
	getspnam_r(string_toc(shadow->user), &spwdstore, shadowdata, sizeof(shadowdata), &pw);
#else
	pw = getspnam(string_toc(shadow->user));
#endif
	if (pw)
	{
		const char *testpasswd = NULL;
		const char *cryptpasswd = pw->sp_pwdp;
#ifdef USE_CRYPT_R
		struct crypt_data crdata = {0};
		testpasswd = crypt_r(string_toc(shadow->passwd), cryptpasswd, &crdata);
#else
		testpasswd = crypt(string_toc(shadow->passwd), cryptpasswd);
#endif
		if (testpasswd && !strcmp(testpasswd, cryptpasswd))
		{
			time_t now = time(NULL);
			long day = now / (60 * 60 * 24);
			if (pw->sp_max > 0 && day > (pw->sp_lstchg + pw->sp_max))
				string_store(&status, STRING_REF(str_status_reapproving));
			if (pw->sp_expire > 0 && day > pw->sp_expire)
				string_store(&status, STRING_REF(str_status_repudiated));
			else
				ret = ESUCCESS;
			string_store(&ctx->status, STRING_INFO(status));
		}
	}
	return ret;
}

static int _authz_unix_checkpasswd(authz_ctx_t *ctx, const char *user, const char *passwd)
{
	int ret = EREJECT;
	struct passwd *pw = NULL;

#ifdef USE_PASSWD_R
	getpwnam_r(user, &ctx->pwstore, ctx->passwd, sizeof(ctx->passwd), &pw);
#else
	pw = getpwnam(user);
#endif
	const char *cryptpasswd = NULL;
	if (pw)
		cryptpasswd = pw->pw_passwd;
	if (cryptpasswd && !strcmp(cryptpasswd, "x"))
	{
		string_t string_user;
		string_t string_passwd;
		string_store(&string_user, user, -1);
		string_store(&string_passwd, passwd, -1);
		authz_shadow_t shadow = {0};
		shadow.ctx= ctx;
		shadow.user = &string_user;
		shadow.passwd = &string_passwd;
		ret = daemonize_supercall(_authz_unix_checkshadow, &shadow);
	}
	else if (cryptpasswd)
	{
		string_t status = STRING_DCL(str_status_activated);
		if (cryptpasswd[0] == '!')
		{
			string_store(&status, STRING_REF(str_status_repudiated));
			cryptpasswd += 1;
		}

		const char *testpasswd = NULL;
#ifdef USE_CRYPT_R
		struct crypt_data crdata = {0};
		testpasswd = crypt_r(passwd, cryptpasswd, &crdata);
#else
		testpasswd = crypt(passwd, cryptpasswd);
#endif
		if (testpasswd && !strcmp(testpasswd, cryptpasswd))
		{
			ret = ESUCCESS;
			string_store(&ctx->status, STRING_INFO(status));
		}
		else
		{
			auth_dbg("authz unix: passwd error");
		}
	}
	else
	{
		warn("authz unix: user %s not found %m", user);
	}
	return ret;
}

static const char *authz_unix_check(void *arg, const char *user, const char *passwd, const char *token)
{
	authz_ctx_t *ctx = (authz_ctx_t *)arg;

	if (user != NULL)
	{
		if (passwd != NULL && _authz_unix_checkpasswd(ctx, user, passwd) == ESUCCESS)
			return user;
		else if (passwd == NULL)
		{
			if (getpwnam(user) != NULL)
				return user;
			else
				auth_dbg("authz unix: user %s not found", user);
		}
	}
	return NULL;
}

static int authz_unix_setsession(void *arg, const char *user, const char *token, auth_saveinfo_t cb, void *cbarg)
{
	const authz_ctx_t *ctx = (const authz_ctx_t *)arg;

	cb(cbarg, STRING_REF(str_user), ctx->pwstore.pw_name, -1);

	struct group *grp = NULL;
	struct group grpstorage;
	char group[NSS_BUFLEN_PASSWD];
#ifdef USE_GROUP_R
	getgrgid_r(ctx->pwstore.pw_gid, &grpstorage, group, sizeof(group), &grp);
#else
	grp = getgrgid(ctx->pwstore.pw_gid);
#endif
	if (grp != NULL)
		cb(cbarg, STRING_REF(str_group), grp->gr_name, -1);
	cb(cbarg, STRING_REF(str_home), ctx->pwstore.pw_dir, -1);
	cb(cbarg, STRING_REF(str_status), STRING_INFO(ctx->status));
	if (token)
		cb(cbarg, STRING_REF(str_token), STRING_REF(token));
	return ESUCCESS;
}

static void authz_unix_cleanup(void *arg)
{
	authz_ctx_t *ctx = (authz_ctx_t *)arg;
	free(ctx);
}

static void authz_unix_destroy(void *arg)
{
	authz_mod_t *ctx = (authz_mod_t *)arg;
	free(ctx->config);
	free(ctx);
}

authz_rules_t authz_unix_rules =
{
	.config = authz_unix_config,
	.create = authz_unix_create,
	.setup = authz_unix_setup,
	.check = authz_unix_check,
	.passwd = NULL,
	.setsession = authz_unix_setsession,
	.cleanup = authz_unix_cleanup,
	.destroy = authz_unix_destroy,
};

static const string_t authz_name = STRING_DCL("unix");
static void __attribute__ ((constructor)) _init()
{
	auth_registerauthz(&authz_name, &authz_unix_rules);
}
