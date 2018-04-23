/*****************************************************************************
 * mod_clientfilter.c: filter the client address module
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
#include "mod_clientfilter.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

typedef struct _mod_clientfilter_s _mod_clientfilter_t;

static void *_mod_clientfilter_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize);
static void _mod_clientfilter_freectx(void *vctx);

static const char str_clientfilter[] = "clientfilter";

struct _mod_clientfilter_s
{
	mod_clientfilter_t	*config;
	char *vhost;
	http_client_t *ctl;
};

static const char *str_wilcard = "*";
static const char *str_empty = "";

void *mod_clientfilter_create(http_server_t *server, char *vhost, mod_clientfilter_t *config)
{
	_mod_clientfilter_t *mod;

	if (!config)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = config;
	mod->vhost = vhost;

	httpserver_addmod(server, _mod_clientfilter_getctx, _mod_clientfilter_freectx, mod, str_clientfilter);
	return mod;
}

void mod_clientfilter_destroy(void *arg)
{
	_mod_clientfilter_t *mod = (_mod_clientfilter_t *)arg;
	free(mod);
}

static void *_mod_clientfilter_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_clientfilter_t *mod = (_mod_clientfilter_t *)arg;
	mod_clientfilter_t *config = mod->config;
	int protect = 1, ret = ESUCCESS;
	static char address[NI_MAXHOST];

	mod->ctl = ctl;
	if (!getnameinfo(addr, addrsize, address, NI_MAXHOST, 0, 0, NI_NUMERICHOST))
	{
		if (config->deny)
		{
			protect = utils_searchexp(address, mod->config->deny);
			if (protect == ESUCCESS)
			{
				ret = EREJECT;
				if (config->accept)
				{
					protect = utils_searchexp(address, mod->config->accept);
					if (protect == ESUCCESS)
					{
						ret = ESUCCESS;
					}
					else
						warn("clientfilter: refuses %s", address);
				}
			}
		}
	}
	else
	{
		err("clientfilter: getnameinfo %s", strerror(errno));
	}
	return (ret == ESUCCESS)?(void *)-1: NULL;
}

static void _mod_clientfilter_freectx(void *vctx)
{
}

const module_t mod_clientfilter =
{
	.name = str_clientfilter,
	.create = (module_create_t)mod_clientfilter_create,
	.destroy = mod_clientfilter_destroy
};
