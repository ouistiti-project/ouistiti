/*****************************************************************************
 * mod_redirect404.c: Redirect the request on 404 error
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
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "httpserver/httpserver.h"
#include "httpserver/utils.h"
#include "mod_redirect404.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

typedef struct _mod_redirect404_s _mod_redirect404_t;

static void *_mod_redirect404_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize);
static void _mod_redirect404_freectx(void *vctx);
static int _mod_redirect404_connector(void *arg, http_message_t *request, http_message_t *response);

static const char str_redirect404[] = "redirect404";

struct _mod_redirect404_s
{
	mod_redirect404_t	*config;
	char *vhost;
};

void *mod_redirect404_create(http_server_t *server, char *vhost, mod_redirect404_t *config)
{
	_mod_redirect404_t *mod;

	if (!config)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = config;
	mod->vhost = vhost;

	httpserver_addmod(server, _mod_redirect404_getctx, _mod_redirect404_freectx, mod, str_redirect404);
	return mod;
}

void mod_redirect404_destroy(void *arg)
{
	_mod_redirect404_t *mod = (_mod_redirect404_t *)arg;
	free(mod);
}

static void *_mod_redirect404_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_redirect404_t *mod = (_mod_redirect404_t *)arg;
	mod_redirect404_t *config = mod->config;

	httpclient_addconnector(ctl, mod->vhost, _mod_redirect404_connector, arg, str_redirect404);
	return mod;
}

static void _mod_redirect404_freectx(void *vctx)
{
}

static int _mod_redirect404_connector(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_redirect404_t *mod = (_mod_redirect404_t *)arg;
	mod_redirect404_t *config = mod->config;

#if defined(RESULT_301)
	if (config->redirect)
		httpmessage_addheader(response, str_location, config->redirect);
	else
		httpmessage_addheader(response, str_location, "/");
	httpmessage_result(response, RESULT_301);
	return ESUCCESS;
#else
#error "redirect404 needs to define 301"
#endif
}
