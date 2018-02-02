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

#include "httpserver/httpserver.h"
#include "httpserver/utils.h"
#include "mod_webstream.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

typedef struct _mod_webstream_s _mod_webstream_t;
typedef struct _mod_webstream_ctx_s _mod_webstream_ctx_t;

struct _mod_webstream_s
{
	mod_webstream_t *config;
	void *vhost;
	mod_webstream_run_t run;
	void *runarg;
};

struct _mod_webstream_ctx_s
{
	_mod_webstream_t *mod;
	char *protocol;
	int socket;
};

static const char str_webstream[] = "webstream";

static int webstream_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	_mod_webstream_ctx_t *ctx = (_mod_webstream_ctx_t *)arg;

	if (ctx->protocol == NULL)
	{
		const char *mimetype = utils_getmime(ctx->protocol);
		ctx->protocol = utils_urldecode(httpmessage_REQUEST(request, "uri"));
		ret = utils_searchexp(ctx->protocol, ctx->mod->config->services);

		if (ret == ESUCCESS && mimetype != NULL)
		{
			httpmessage_addcontent(response, mimetype, "", -1);
			ret = ECONTINUE;
		}
	}
	else
	{
		ctx->socket = httpmessage_lock(response);
		ctx->mod->run(ctx->mod->runarg, ctx->socket, ctx->protocol, request);
		free(ctx->protocol);
		ctx->protocol = NULL;
		ret = ESUCCESS;
	}
	return ret;
}

static void *_mod_webstream_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_webstream_t *mod = (_mod_webstream_t *)arg;

	_mod_webstream_ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->mod = mod;
	httpclient_addconnector(ctl, mod->vhost, webstream_connector, ctx, str_webstream);

	return ctx;
}

static void _mod_webstream_freectx(void *arg)
{
	_mod_webstream_ctx_t *ctx = (_mod_webstream_ctx_t *)arg;

	free(ctx);
}

void *mod_webstream_create(http_server_t *server, char *vhost, void *config, mod_webstream_run_t run, void *runarg)
{
	_mod_webstream_t *mod = calloc(1, sizeof(*mod));

	mod->vhost = vhost;
	mod->config = config;
	mod->run = run;
	mod->runarg = runarg;
	httpserver_addmod(server, _mod_webstream_getctx, _mod_webstream_freectx, mod, str_webstream);
	warn("webstream support %s %s", mod->config->path, mod->config->services);
	return mod;
}

void mod_webstream_destroy(void *data)
{
	free(data);
}

static int _webstream_socket(void *arg, char *protocol)
{
	mod_webstream_t *config = (mod_webstream_t *)arg;
	int sock;
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path) - 1, "%s/%s", config->path, protocol);

	dbg("webstream %s", addr.sun_path);
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock > 0)
	{
		int ret = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
		if (ret < 0)
		{
			close(sock);
			sock = -1;
		}
	}
	if (sock == -1)
	{
		warn("webstream error: %s", strerror(errno));
	}
	return sock;
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
							break;
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

int default_webstream_run(void *arg, int socket, char *protocol, http_message_t *request)
{
	int wssock = _webstream_socket(arg, protocol);

	if (wssock > 0)
	{
		_webstream_main_t info = {.socket = socket, .client = wssock};
		http_client_t *ctl = httpmessage_client(request);
		info.ctx = httpclient_context(ctl);
		info.recvreq = httpclient_addreceiver(ctl, NULL, NULL);
		info.sendresp = httpclient_addsender(ctl, NULL, NULL);

		/**
		 * ignore SIGCHLD allows the child to die without to create a zombie.
		 */
		struct sigaction action;
		action.sa_flags = SA_SIGINFO;
		sigemptyset(&action.sa_mask);
		action.sa_handler = SIG_IGN;
		sigaction(SIGCHLD, &action, NULL);

		pid_t pid;

		if ((pid = fork()) == 0)
		{
			_webstream_main(&info);
			exit(0);
		}
	}
	return wssock;
}
