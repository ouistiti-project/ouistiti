/*****************************************************************************
 * mod_methodlock.c: callbacks and management of request method
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
#include "mod_methodlock.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

static const char str_methodlock[] = "methodlock";

typedef struct _mod_methodlock_s _mod_methodlock_t;

struct _mod_methodlock_s
{
	void *vhost;
	char *unlock_groups;
};

static int methodlock_connector(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_methodlock_t *mod = (_mod_methodlock_t *)arg;
	int ret = ESUCCESS;

	const char *method = httpmessage_REQUEST(request, "method");
	switch (httpmessage_isprotected(request))
	{
	case -1:
	{
		warn("methodlock: method %s forbidden", method);
#if defined RESULT_405
		httpmessage_result(response, RESULT_405);
#else
		httpmessage_result(response, RESULT_400);
#endif
	}
	break;
	case 0:
	{
		ret = EREJECT;
	}
	break;
	default:
	{
		const char *group = httpmessage_SESSION(request, "%authgroup",NULL);
		if (group && group[0] != '\0')
		{
			int length = strlen(group);
			if (mod->unlock_groups && mod->unlock_groups[0] != '\0')
			{
				char *iterator = mod->unlock_groups;
				while (iterator != NULL)
				{
					if (!strncmp(iterator, group, length))
					{
						ret = EREJECT;
						break;
					}
					iterator = strchr(iterator, ',');
					if (iterator != NULL)
						iterator++;
				}
			}
			if (ret != EREJECT)
			{
				warn("method use with bad user group %s set unlock_groups", group);
#if defined RESULT_403
				httpmessage_result(response, RESULT_403);
#else
				httpmessage_result(response, RESULT_400);
#endif
			}
		}
	}
	}
	return ret;
}

static void *_mod_methodlock_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_methodlock_t *mod = (_mod_methodlock_t *)arg;

	httpclient_addconnector(ctl, mod->vhost, methodlock_connector, mod, str_methodlock);

	return arg;
}

void *mod_methodlock_create(http_server_t *server, char *vhost, void *config)
{
	_mod_methodlock_t *mod = calloc(1, sizeof(*mod));

	mod->vhost = vhost;
	mod->unlock_groups = config;
	httpserver_addmod(server, _mod_methodlock_getctx, NULL, mod, str_methodlock);

	return mod;
}

void mod_methodlock_destroy(void *data)
{
	free(data);
}
