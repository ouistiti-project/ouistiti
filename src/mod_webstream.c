/*****************************************************************************
 * mod_webstream.c: webstream server module
 * this file is part of https://github.com/ouistiti-project/libhttpserver
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
#include "mod_webstream.h"

extern int ouistiti_websocket_run(void *arg, int sock, char *protocol, http_message_t *request);
extern int ouistiti_websocket_socket(void *arg, int sock, char *filepath, http_message_t *request);

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

typedef struct _mod_webstream_s _mod_webstream_t;
typedef struct _mod_webstream_ctx_s _mod_webstream_ctx_t;

typedef int (*socket_t)(mod_webstream_t *config, char *filepath);

struct _mod_webstream_s
{
	mod_webstream_t *config;
	void *vhost;
	socket_t socket;
};

struct _mod_webstream_ctx_s
{
	_mod_webstream_t *mod;
	char *protocol;
	int socket;
	int client;
	pid_t pid;
	http_client_t *ctl;
};

int _webstream_run(_mod_webstream_ctx_t *ctx, http_message_t *request);

static const char str_webstream[] = "webstream";

static int _checkname(_mod_webstream_ctx_t *ctx, char *pathname)
{
	_mod_webstream_t *mod = ctx->mod;
	mod_webstream_t *config = (mod_webstream_t *)mod->config;
	if (pathname[0] == '.')
	{
		return  EREJECT;
	}
	if (utils_searchexp(pathname, config->deny) == ESUCCESS &&
		utils_searchexp(pathname, config->allow) != ESUCCESS)
	{
		return  EREJECT;
	}
	return ESUCCESS;
}

static int webstream_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	_mod_webstream_ctx_t *ctx = (_mod_webstream_ctx_t *)arg;
	_mod_webstream_t *mod = ctx->mod;
	mod_webstream_t *config = (mod_webstream_t *)mod->config;

	if (ctx->client == 0)
	{
		char *uri = utils_urldecode(httpmessage_REQUEST(request, "uri"));
		if (_checkname(ctx, uri) != ESUCCESS)
		{
			free(uri);
			return ret;
		}

		struct stat filestat;
		char *filepath = utils_buildpath(config->docroot, uri, "", "", &filestat);
		if (filepath)
		{
			if (S_ISSOCK(filestat.st_mode))
			{
				ctx->socket = httpmessage_keepalive(response);
				int wssock;
				if (config->options & WEBSOCKET_REALTIME)
				{
					wssock = ouistiti_websocket_run(NULL, ctx->socket, filepath, request);
				}
				else
					wssock = ouistiti_websocket_socket(NULL, ctx->socket, filepath, request);

				if (wssock > 0)
				{
					const char *mime = NULL;
					mime = utils_getmime(filepath);
					httpmessage_addcontent(response, mime, "", -1);

					ctx->client = wssock;
					ret = ECONTINUE;
				}
			}
		}
		free(uri);
	}
	else
	{
		ctx->socket = httpmessage_lock(response);
		if (!(config->options & WEBSOCKET_REALTIME))
		{
			ctx->pid = _webstream_run(ctx, request);
		}
		ret = ESUCCESS;
	}
	return ret;
}

static void *_mod_webstream_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_webstream_t *mod = (_mod_webstream_t *)arg;

	_mod_webstream_ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->mod = mod;
	ctx->ctl = ctl;
	httpclient_addconnector(ctl, mod->vhost, webstream_connector, ctx, str_webstream);

	return ctx;
}

static void _mod_webstream_freectx(void *arg)
{
	_mod_webstream_ctx_t *ctx = (_mod_webstream_ctx_t *)arg;

	if (ctx->pid > 0)
	{
#ifdef VTHREAD
		dbg("webstream: waitpid");
		waitpid(ctx->pid, NULL, 0);
		warn("webstream: end stream %p", ctx->ctl);
#else
		/**
		 * ignore SIGCHLD allows the child to die without to create a z$
		 */
		struct sigaction action;
		action.sa_flags = SA_SIGINFO;
		sigemptyset(&action.sa_mask);
		action.sa_handler = SIG_IGN;
		sigaction(SIGCHLD, &action, NULL);
#endif
	}
	free(ctx);
}

void *mod_webstream_create(http_server_t *server, char *vhost, mod_webstream_t *config)
{
	_mod_webstream_t *mod = calloc(1, sizeof(*mod));

	mod->vhost = vhost;
	mod->config = config;

	httpserver_addmod(server, _mod_webstream_getctx, _mod_webstream_freectx, mod, str_webstream);
	return mod;
}

void mod_webstream_destroy(void *data)
{
	free(data);
}

typedef struct _webstream_main_s _webstream_main_t;
struct _webstream_main_s
{
	int client;
	int socket;
	http_recv_t recvreq;
	http_send_t sendresp;
	void *ctx;
};

static void *_webstream_main(void *arg)
{
	_webstream_main_t *info = (_webstream_main_t *)arg;
	int client = info->client;
	int end = 0;

	while (!end)
	{
		fd_set rdfs;
		int maxfd = client;
		FD_ZERO(&rdfs);
		FD_SET(client, &rdfs);
		int ret = select(maxfd + 1, &rdfs, NULL, NULL, NULL);
		if (ret > 0 && FD_ISSET(client, &rdfs))
		{
			int length;
			ret = ioctl(client, FIONREAD, &length);
			while (length > 0)
			{
				char *buffer;
				buffer = calloc(1, length);
				ret = recv(client, buffer, length, MSG_NOSIGNAL);
				if (ret > 0)
				{
					length -= ret;
					ssize_t size = 0;
					while (size < ret)
					{
						int outlength = 0;
						outlength = info->sendresp(info->ctx, (char *)buffer, ret);
						if (outlength == EINCOMPLETE)
							continue;
						if (outlength == EREJECT)
						{
							end = 1;
							break;
						}
						size += outlength;
					}
				}
				free(buffer);
			}
		}
		else if (errno != EAGAIN)
		{
			end = 1;
		}
	}
	close(client);
	return 0;
}

int _webstream_run(_mod_webstream_ctx_t *ctx, http_message_t *request)
{
	pid_t pid;

	_webstream_main_t info = {.socket = ctx->socket, .client = ctx->client};
	info.ctx = httpclient_context(ctx->ctl);
	info.recvreq = httpclient_addreceiver(ctx->ctl, NULL, NULL);
	info.sendresp = httpclient_addsender(ctx->ctl, NULL, NULL);

	if ((pid = fork()) == 0)
	{
		_webstream_main(&info);
		exit(0);
	}
	return pid;
}

const module_t mod_webstream =
{
	.name = str_webstream,
	.create = (module_create_t)mod_webstream_create,
	.destroy = mod_webstream_destroy
};
