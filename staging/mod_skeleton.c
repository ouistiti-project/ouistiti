/*****************************************************************************
 * mod_skeleton.c: callbacks and management of connection
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

#include <httpserver/log.h>
#include <httpserver/httpserver.h>
#include "mod_skeleton.h"

typedef struct _mod_skeleton_config_s _mod_skeleton_config_t;
typedef struct _mod_skeleton_s _mod_skeleton_t;

static http_server_config_t mod_skeleton_config;

static void *_mod_skeleton_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize);
static void _mod_skeleton_freectx(void *vctx);
static int _mod_skeleton_recv(void *vctx, char *data, int size);
static int _mod_skeleton_send(void *vctx, char *data, int size);
static int _skeleton_connector(void *arg, http_message_t *request, http_message_t *response);

#define STATE_1 1
#define STATE_2 2
#define STATE_3 3
#define STATE_4 4
#define STATE_5 5
struct _mod_skeleton_s
{
	int state;
	_mod_skeleton_config_t *config;
	http_client_t *ctl;
};

struct _mod_skeleton_config_s
{
	char *header_key;
	char *header_value;
};

void *mod_skeleton_create(http_server_t *server, mod_skeleton_t *modconfig)
{
	_mod_skeleton_config_t *config;

	if (!modconfig)
		return NULL;

	config = calloc(1, sizeof(*config));

	config->header_key = calloc(1, sizeof("SKELETON") + 1);
	strcpy(config->header_key, "SKELETON");
	config->header_value = calloc(1, sizeof("V1.0") + 1);
	sprintf(config->header_value, "V%01d.%01d",modconfig->version_h,modconfig->version_l);
	httpserver_addconnector(server, _skeleton_connector, config, CONNECTOR_ERROR, "skeleton");
	httpserver_addmod(server, _mod_skeleton_getctx, _mod_skeleton_freectx, config);

	return config;
}

void mod_skeleton_destroy(void *mod)
{
	_mod_skeleton_config_t *config = (_mod_skeleton_config_t *)mod;
	free(config->header_key);
	free(config->header_value);
	free(config);
}

static void *_mod_skeleton_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_skeleton_t *ctx = calloc(1, sizeof(*ctx));
	_mod_skeleton_config_t *config = (_mod_skeleton_config_t *)arg;

	ctx->state = STATE_1;
	ctx->ctl = ctl;
	ctx->config = config;

	httpclient_addreceiver(ctl, _mod_skeleton_recv, ctx);
	httpclient_addsender(ctl, _mod_skeleton_send, ctx);

	return ctx;
}

static void _mod_skeleton_freectx(void *vctx)
{
	_mod_skeleton_t *ctx = (_mod_skeleton_t *)vctx;
	ctx->state = STATE_5;
	free(ctx);
}

static int _mod_skeleton_recv(void *vctx, char *data, int size)
{
	int ret;
	_mod_skeleton_t *ctx = (_mod_skeleton_t *)vctx;
	ret = httpclient_recv(ctx->ctl, data, size);
	ctx->state = STATE_2;
	return ret;
}

static int _mod_skeleton_send(void *vctx, char *data, int size)
{
	int ret;
	_mod_skeleton_t *ctx = (_mod_skeleton_t *)vctx;
	ret = httpclient_send(ctx->ctl, data, size);
	ctx->state = STATE_3;
	return ret;
}

static int _skeleton_connector(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_skeleton_t *ctx = (_mod_skeleton_t *)arg;
	_mod_skeleton_config_t *config = ctx->config;

	ctx->state = STATE_4;
	httpmessage_addheader(response, config->header_key, config->header_value);
	return ECONTINUE;
}

const module_t mod_skeleton =
{
	.name = str_skeleton,
	.create = (module_create_t)mod_skeleton_create,
	.destroy = mod_skeleton_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_skeleton")));
#endif
