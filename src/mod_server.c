/*****************************************************************************
 * mod_server.c: callbacks and management of request method
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
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>

#include "httpserver/httpserver.h"
#include "httpserver/uri.h"
#include "mod_server.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

static const char str_server[] = "server";

typedef struct _mod_server_s _mod_server_t;

struct _mod_server_s
{
	void *vhost;
	mod_security_t *config;
};

static int server_connector(void **arg, http_message_t *request, http_message_t *response)
{
	_mod_server_t *mod = (_mod_server_t *)*arg;
	mod_security_t *config = mod->config;
	int ret = EREJECT;
	int options = 0;

	httpmessage_addheader(response, "Server", httpmessage_SERVER(request, "software"));
	if (config)
	{
		options = config->options;
	}
	if (!(options & SECURITY_FRAME))
	{
		httpmessage_addheader(response, "X-Frame-Options", "DENY");
	}
	if (!(options & SECURITY_CACHE))
	{
		httpmessage_addheader(response, "Cache-Control", "no-cache,no-store,max-age=0,must-revalidate");
		httpmessage_addheader(response, "Pragma", "no-cache");
		httpmessage_addheader(response, "Expires", "0");
	}
	if (!(options & SECURITY_CONTENTTYPE))
	{
		httpmessage_addheader(response, "X-Content-Type-Options", "nosniff");
	}
	if (!(options & SECURITY_OTHERORIGIN))
	{
		if (options & SECURITY_FRAME)
			httpmessage_addheader(response, "X-Frame-Options", "SAMEORIGIN");

		httpmessage_addheader(response, "Referrer-Policy", "origin-when-cross-origin");

#ifndef SECURITY_UNCHECKORIGIN
		const char *origin = httpmessage_REQUEST(request, "Origin");
		if (origin != NULL)
		{
			const char *host = httpmessage_SERVER(request, "hostname");
			const char *refererhost = strstr(origin, "://");
			if (refererhost == NULL)
				refererhost = origin;
			char *end = strchr(refererhost, '/');
			int len;
			if (end == NULL)
				len = strlen(refererhost);
			else
				len = end - refererhost;
			if ((strlen(host) != len) || strncmp(refererhost, host, len))
			{
				httpmessage_result(response, RESULT_403);
				ret = ESUCCESS;
			}
		}
#else
# warning "request origin is not check"
#endif
	}
	return ret;
}

static void *_mod_server_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_server_t *mod = (_mod_server_t *)arg;

	httpclient_addconnector(ctl, mod->vhost, server_connector, arg, str_server);

	return mod;
}

void *mod_server_create(http_server_t *server, char *vhost, void *config)
{
	_mod_server_t *mod = calloc(1, sizeof(*mod));

	mod->vhost = vhost;
	mod->config = config;
	httpserver_addmod(server, _mod_server_getctx, NULL, mod, str_server);

	return mod;
}

void mod_server_destroy(void *data)
{
	free(data);
}

const module_t mod_server =
{
	.name = str_server,
	.create = (module_create_t)mod_server_create,
	.destroy = mod_server_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_server")));
#endif
