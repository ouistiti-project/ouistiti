/*****************************************************************************
 * authn_wwwform.c: x-www-form-urlencoded Authentication mode
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

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/log.h"
#include "mod_auth.h"

#define auth_dbg(...)

typedef struct authn_wwwform_s authn_wwwform_t;
struct authn_wwwform_s
{
	const authn_t *authn;
	http_client_t *clt;
};

#ifdef FILE_CONFIG
#include <libconfig.h>
void *authn_wwwform_config(const void *configauth, authn_type_t *type)
{
	return (void *)1;
}
#endif

static void *authn_wwwform_create(const authn_t *authn, void *UNUSED(arg))
{
	if (authn->config->token_ep.length == 0)
	{
		err("auth: token_ep must be defined in configuration file");
		return NULL;
	}
	authn_wwwform_t *mod = calloc(1, sizeof(*mod));
	mod->authn = authn;
	return mod;
}

static int authn_wwwform_challenge(void *arg, http_message_t *UNUSED(request), http_message_t *response)
{
	int ret = ECONTINUE;
	const authn_wwwform_t *mod = (authn_wwwform_t *)arg;
	const mod_auth_t *config = mod->authn->config;

	httpmessage_addheader(response, str_authenticate, STRING_REF("WWW-Form"));
	if (!string_empty(&config->realm))
	{
		httpmessage_appendheader(response, str_authenticate, STRING_REF(" realm=\""));
		httpmessage_appendheader(response, str_authenticate, STRING_INFO(config->realm));
		httpmessage_appendheader(response, str_authenticate, STRING_REF("\""));
	}
	return ret;
}

static const char *authn_wwwform_checkrequest(void *arg, authz_t *authz, http_message_t *request)
{
	const authn_wwwform_t *mod = (authn_wwwform_t *)arg;
	const mod_auth_t *config = mod->authn->config;
	const char *user = NULL;

	const char *content_type = NULL;
	size_t content_typelen = httpmessage_REQUEST2(request, str_contenttype, &content_type);
	string_t contenttype = {0};
	string_store(&contenttype, content_type, content_typelen);
	if (! string_cmp(&contenttype, str_form_urlencoded, -1))
	{
		const char *username = NULL;
		httpmessage_parameter(request, "username", &username);
		const char *password = NULL;
		httpmessage_parameter(request, "password", &password);
		auth_dbg("auth: www-form-urlencoding %s %s", username, password);
		if (username && password)
			user = authz->rules->check(authz->ctx, username, password, NULL);
	}
	return user;
}

static void authn_wwwform_destroy(void *arg)
{
	authn_wwwform_t *mod = (authn_wwwform_t *)arg;
	free(mod);
}

authn_rules_t authn_wwwform_rules =
{
	.config = authn_wwwform_config,
	.create = &authn_wwwform_create,
	.challenge = &authn_wwwform_challenge,
	.checkrequest = &authn_wwwform_checkrequest,
	.destroy = &authn_wwwform_destroy,
};

static const string_t authn_name = STRING_DCL("wwwform");
static void __attribute__ ((constructor)) _init()
{
	auth_registerauthn(&authn_name, &authn_wwwform_rules);
}
