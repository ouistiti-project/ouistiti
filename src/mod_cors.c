/*****************************************************************************
 * mod_cors.c: webstream server module
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
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <wait.h>

#include "httpserver/httpserver.h"
#include "httpserver/utils.h"
#include "mod_cors.h"

#define CLIENT_CONNECTOR

extern int ouistiti_websocket_run(void *arg, int sock, char *protocol, http_message_t *request);
extern int ouistiti_websocket_socket(void *arg, int sock, char *filepath, http_message_t *request);

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

typedef struct _mod_cors_s _mod_cors_t;
typedef struct _mod_cors_ctx_s _mod_cors_ctx_t;

typedef int (*socket_t)(mod_cors_t *config, char *filepath);

struct _mod_cors_s
{
	mod_cors_t *config;
	void *vhost;
	socket_t socket;
};

static const char str_cors[] = "cors";
static const char str_options[] = "OPTIONS";
#ifdef DOCUMENTREST
#define RESTMETHODS	", PUT" \
					", DELETE"
#else
#define RESTMETHODS	""
#endif

static const char str_methodslist[] =
				"GET, " \
				"POST, " \
				"HEAD, " \
				"OPTIONS" \
				RESTMETHODS \
				"";

static int cors_connector(void **arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	_mod_cors_t *mod = (_mod_cors_t *)*arg;
	mod_cors_t *config = (mod_cors_t *)mod->config;

	const char *origin = httpmessage_REQUEST(request, "Origin");
	if (origin && origin[0] != '\0' && (utils_searchexp(origin, mod->config->origin) == ESUCCESS))
	{
		const char *method = httpmessage_REQUEST(request, "method");
		if (!strcmp(method, str_options))
		{
			const char *ac_request;
			httpmessage_addheader(response, "Access-Control-Allow-Origin", origin);

			ac_request = httpmessage_REQUEST(request, "Access-Control-Request-Method");
			if (ac_request)
			{
				httpmessage_addheader(response, "Access-Control-Allow-Methods", str_methodslist);
			}
			ac_request = httpmessage_REQUEST(request, "Access-Control-Request-Headers");
			if (ac_request)
			{
				httpmessage_addheader(response, "Access-Control-Allow-Headers", ac_request);
			}
			httpmessage_addheader(response, "Access-Control-Allow-Credentials", "true");
			httpmessage_result(response, 200);
			ret = ESUCCESS;
		}
	}
	else if (origin && origin[0] != '\0')
	{
		httpmessage_result(response, 405);
		ret = ESUCCESS;
	}
	return ret;
}

#ifdef CLIENT_CONNECTOR
static void *_mod_cors_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_cors_t *mod = (_mod_cors_t *)arg;

	httpclient_addconnector(ctl, mod->vhost, cors_connector, mod, str_cors);

	return mod;
}

static void _mod_cors_freectx(void *arg)
{
	_mod_cors_t *ctx = (_mod_cors_t *)arg;
}
#endif

void *mod_cors_create(http_server_t *server, char *vhost, mod_cors_t *config)
{
	_mod_cors_t *mod = calloc(1, sizeof(*mod));

	mod->vhost = vhost;
	mod->config = config;

	httpserver_addmethod(server, str_options, 1);
#ifdef CLIENT_CONNECTOR
	httpserver_addmod(server, _mod_cors_getctx, _mod_cors_freectx, mod, str_cors);
#else
	httpserver_addconnector(server, vhost, cors_connector, mod);
#endif
	return mod;
}

void mod_cors_destroy(void *data)
{
	free(data);
}

const module_t mod_cors =
{
	.name = str_cors,
	.create = (module_create_t)mod_cors_create,
	.destroy = mod_cors_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_cors")));
#endif
