/*****************************************************************************
 * authz_pam.c: Check Authentication with PAM
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
#include <grp.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <security/pam_appl.h>

#include "ouistiti/httpserver.h"
#include "ouistiti/log.h"
#include "mod_auth.h"
#include "daemonize.h"

#define auth_dbg(...)

#define DEFAULT_SERVICE "ouistiti"

typedef struct authz_pam_config_s authz_pam_config_t;
struct authz_pam_config_s
{
	const char *service;
};

typedef struct authz_mod_s authz_mod_t;
struct authz_mod_s
{
	authz_pam_config_t *config;
	string_t *issuer;
};

typedef struct authz_ctx_s authz_ctx_t;
struct authz_ctx_s
{
	authz_mod_t *mod;
	struct passwd pwstore;
	char passwd[512];
	string_t status;
};

#ifdef FILE_CONFIG
#include <libconfig.h>
void *authz_pam_config(const void *configauth, authz_type_t *UNUSED(type))
{
	authz_pam_config_t *authz_config = NULL;

	const char *name = NULL;
	int ret = config_setting_lookup_string(configauth, "authz", &name);
	if (ret != CONFIG_TRUE || strstr(name, "pam") == NULL)
		return NULL;

	const char *service = NULL;

	config_setting_lookup_string(configauth, "service", &service);
	if (service == NULL || service[0] == '0')
		service = DEFAULT_SERVICE;

	authz_config = calloc(1, sizeof(*authz_config));
	authz_config->service = service;
	return authz_config;
}
#endif

static void *authz_pam_create(http_server_t *UNUSED(server), string_t *issuer, void *arg)
{
	authz_mod_t *ctx = NULL;
	authz_pam_config_t *config = (authz_pam_config_t *)arg;

	ctx = calloc(1, sizeof(*ctx));
	ctx->config = config;
	ctx->issuer = issuer;
	return ctx;
}

static void *authz_pam_setup(void *arg, http_client_t *UNUSED(clt), struct sockaddr *UNUSED(addr), int UNUSED(addrsize))
{
	authz_mod_t *mod = (authz_mod_t *)arg;
	authz_ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->mod = mod;
	return ctx;
}

/**
 * @brief PAM conversation function
 *
 * The password is already known (received from the client's Authorization
 * header), so the conversation just replays it for every prompt PAM asks.
 * No interactive terminal is ever involved.
 */
static int _authz_pam_conv(int num_msg, const struct pam_message **msg,
		struct pam_response **resp, void *appdata_ptr)
{
	const char *passwd = (const char *)appdata_ptr;
	struct pam_response *reply = calloc(num_msg, sizeof(*reply));
	if (reply == NULL)
		return PAM_BUF_ERR;

	for (int i = 0; i < num_msg; i++)
	{
		switch (msg[i]->msg_style)
		{
			case PAM_PROMPT_ECHO_OFF:
			case PAM_PROMPT_ECHO_ON:
				reply[i].resp = strdup((passwd != NULL) ? passwd : "");
			break;
			default:
				reply[i].resp = NULL;
			break;
		}
		reply[i].resp_retcode = 0;
	}
	*resp = reply;
	return PAM_SUCCESS;
}

static int _authz_pam_run(void *arg)
{
	pam_handle_t *pamh = (pam_handle_t *)arg;
	int pamret = pam_authenticate(pamh, 0);
	if (pamret == PAM_SUCCESS)
		pamret = pam_acct_mgmt(pamh, 0);
	return pamret;
}

static int _authz_pam_checkpasswd(authz_ctx_t *ctx, const char *user, const char *passwd)
{
	int ret = 0;
	pam_handle_t *pamh = NULL;
	struct pam_conv conv = {
		.conv = _authz_pam_conv,
		.appdata_ptr = (void *)passwd,
	};

	int pamret = pam_start(ctx->mod->config->service, user, &conv, &pamh);
	if (pamret != PAM_SUCCESS)
	{
		err("authz pam: start error %s", pam_strerror(pamh, pamret));
		return 0;
	}

	pamret = daemonize_supercall(_authz_pam_run, pamh);

	if (pamret == PAM_SUCCESS)
	{
		ret = 1;
		string_store(&ctx->status, STRING_REF(str_status_activated));
	}
	else
	{
		auth_dbg("authz pam: %s", pam_strerror(pamh, pamret));
	}
	pam_end(pamh, pamret);
	return ret;
}

static const char *authz_pam_check(void *arg, const char *user, const char *passwd, const char *UNUSED(token))
{
	authz_ctx_t *ctx = (authz_ctx_t *)arg;

	if (user == NULL)
		return NULL;
	if (passwd == NULL)
	{
		/// check only the presence of the system account
		struct passwd *pw = NULL;
#ifdef USE_PASSWD_R
		getpwnam_r(user, &ctx->pwstore, ctx->passwd, sizeof(ctx->passwd), &pw);
#else
		pw = getpwnam(user);
#endif
		return (pw != NULL) ? user : NULL;
	}
	if (_authz_pam_checkpasswd(ctx, user, passwd))
		return user;
	return NULL;
}

static int authz_pam_setsession(void *arg, const char *user, const char *token, auth_saveinfo_t cb, void *cbarg)
{
	authz_ctx_t *ctx = (authz_ctx_t *)arg;
	struct passwd *pw = NULL;

#ifdef USE_PASSWD_R
	getpwnam_r(user, &ctx->pwstore, ctx->passwd, sizeof(ctx->passwd), &pw);
#else
	pw = getpwnam(user);
	if (pw)
		ctx->pwstore = *pw;
#endif
	if (pw == NULL)
		return EREJECT;

	cb(cbarg, STRING_REF(str_user), ctx->pwstore.pw_name, -1);

	struct group *grp = NULL;
	struct group grpstorage;
	char group[512];
#ifdef USE_GROUP_R
	getgrgid_r(ctx->pwstore.pw_gid, &grpstorage, group, sizeof(group), &grp);
#else
	grp = getgrgid(ctx->pwstore.pw_gid);
#endif
	if (grp != NULL)
		cb(cbarg, STRING_REF(str_group), grp->gr_name, -1);
	cb(cbarg, STRING_REF(str_home), ctx->pwstore.pw_dir, -1);
	if (!string_empty(&ctx->status))
		cb(cbarg, STRING_REF(str_status), STRING_INFO(ctx->status));
	else
		cb(cbarg, STRING_REF(str_status), STRING_REF(str_status_activated));
	if (token)
		cb(cbarg, STRING_REF(str_token), STRING_REF(token));
	return ESUCCESS;
}

static void authz_pam_cleanup(void *arg)
{
	authz_ctx_t *ctx = (authz_ctx_t *)arg;
	free(ctx);
}

static void authz_pam_destroy(void *arg)
{
	authz_mod_t *ctx = (authz_mod_t *)arg;
	free(ctx->config);
	free(ctx);
}

authz_rules_t authz_pam_rules =
{
	.config = authz_pam_config,
	.create = authz_pam_create,
	.setup = authz_pam_setup,
	.check = authz_pam_check,
	.passwd = NULL,
	.setsession = authz_pam_setsession,
	.cleanup = authz_pam_cleanup,
	.destroy = authz_pam_destroy,
};

static const string_t authz_name = STRING_DCL("pam");
static void __attribute__ ((constructor)) _init()
{
	auth_registerauthz(&authz_name, &authz_pam_rules);
}
