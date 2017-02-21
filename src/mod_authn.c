/*****************************************************************************
 * mod_authn.c: callbacks and management of connection
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

#include "httpserver/httpserver.h"
#include "mod_authn.h"
#include "b64/cencode.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

typedef struct _mod_authn_s _mod_authn_t;
typedef struct _mod_authn_ctx_s _mod_authn_ctx_t;

static http_server_config_t mod_authn_config;

static void *_mod_authn_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize);
static void _mod_authn_freectx(void *vctx);
static int _authn_connector(void *arg, http_message_t *request, http_message_t *response);

struct _mod_authn_ctx_s
{
	_mod_authn_t *mod;
	char *authenticate;
};

struct _mod_authn_s
{
	mod_authn_t	*config;
	char *realm;
	char *base64;
};

static const char *str_authenticate = "WWW-Authenticate";
static const char *str_authorization = "Authorization";
static const char *str_realm = "ouistiti";
void *mod_authn_create(http_server_t *server, mod_authn_t *config)
{
	_mod_authn_t *mod;

	if (!config)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = config;

	if (config->realm == NULL)
	{
		mod->realm = (char *)str_realm;
	}
	else
		mod->realm = config->realm;

	int length = 0;
	int ulength = strlen(config->user);
	int plength = strlen(config->passwd);
	mod->base64 = calloc(1, (ulength + plength + 1 + 1) * 2);
	base64_encodestate encoder;
	base64_init_encodestate(&encoder);
	length += base64_encode_block(config->user, ulength, mod->base64 + length, &encoder);
	length += base64_encode_block(":", 1, mod->base64 + length, &encoder);
	length += base64_encode_block(config->passwd, plength, mod->base64 + length, &encoder);
	length += base64_encode_blockend(mod->base64 + length, &encoder);
	char *end = strrchr(mod->base64, '=');
	if (end)
	{
		end++;
		*end = 0;
	}

	httpserver_addmod(server, _mod_authn_getctx, _mod_authn_freectx, mod);

	return mod;
}

void mod_authn_destroy(void *arg)
{
	_mod_authn_t *mod = (_mod_authn_t *)arg;
	if (mod->base64)
		free(mod->base64);
	free(mod);
}

static void *_mod_authn_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_authn_ctx_t *ctx = calloc(1, sizeof(*ctx));
	_mod_authn_t *mod = (_mod_authn_t *)arg;

	ctx->mod = mod;
	ctx->authenticate = calloc(1, sizeof("Basic realm=\"\"") + strlen(mod->realm) + 1);
	sprintf(ctx->authenticate, "Basic realm=\"%s\"", mod->realm);

	httpclient_addconnector(ctl, NULL, _authn_connector, ctx);
	return ctx;
}

static void _mod_authn_freectx(void *vctx)
{
	_mod_authn_ctx_t *ctx = (_mod_authn_ctx_t *)vctx;
	free(ctx->authenticate);
	free(ctx);
}

static int _authn_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = ECONTINUE;
	_mod_authn_ctx_t *ctx = (_mod_authn_ctx_t *)arg;
	_mod_authn_t *mod = ctx->mod;

	char *authorization;
	authorization = httpmessage_REQUEST(request, (char *)str_authorization);
	if (authorization != NULL && !strncmp(authorization, "Basic", 5))
	{
		char *base64 = strchr(authorization, ' ');
		if (base64)
			base64++;
		if (!strcmp(base64, mod->base64))
			ret = EREJECT;
		else
			authorization = NULL;
	}
	if (authorization == NULL || authorization[0] == '\0')
	{
		httpmessage_SESSION(request, "%user", mod->config->user);
		httpmessage_SESSION(request, "%authtype", "Basic");
		httpmessage_addheader(response, (char *)str_authenticate, ctx->authenticate);
		httpmessage_result(response, RESULT_401);
		httpmessage_keepalive(response);
		ret = ESUCCESS;
	}
	return ret;
}
