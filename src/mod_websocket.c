/*****************************************************************************
 * mod_websocket.c: websocket server module
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
/**
 * CAUTION!!!
 * Websocket module is not able to run on TLS socket if VTHREAD is not
 * activated.
 */
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
#include <sys/wait.h>

#include "httpserver/log.h"
#include "httpserver/httpserver.h"
#include "httpserver/hash.h"
#include "httpserver/uri.h"
#include "httpserver/mod_websocket.h"
#include "httpserver/utils.h"
#include "httpserver/websocket.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define websocket_dbg(...)

typedef struct _mod_websocket_s _mod_websocket_t;
typedef struct _mod_websocket_ctx_s _mod_websocket_ctx_t;

struct _mod_websocket_s
{
	mod_websocket_t *config;
	mod_websocket_run_t run;
	void *runarg;
	int fdroot;
};

struct _mod_websocket_ctx_s
{
	_mod_websocket_t *mod;
	int fddir;
	int socket;
	pid_t pid;
};

static const char str_connection[] = "Connection";
static const char str_upgrade[] = "Upgrade";
static const char str_websocket[] = "websocket";
static const char str_protocol[] = "Sec-WebSocket-Protocol";
static const char str_accept[] = "Sec-WebSocket-Accept";
static const char str_key[] = "Sec-WebSocket-Key";

static void _mod_websocket_handshake(_mod_websocket_ctx_t *ctx, http_message_t *request, http_message_t *response)
{
	const char *key = httpmessage_REQUEST(request, str_key);
	if (key && key[0] != 0)
	{
		char accept[20] = {0};
		void *ctx;
		ctx = hash_sha1->init();
		hash_sha1->update(ctx, key, strlen(key));
		hash_sha1->update(ctx, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", sizeof("258EAFA5-E914-47DA-95CA-C5AB0DC85B11") -1);
		hash_sha1->finish(ctx, accept);

		char out[40];
		base64->encode(accept, hash_sha1->size, out, 40);
		websocket_dbg("%s: handshake %s", str_websocket, out);

		httpmessage_addheader(response, str_accept, out);
	}
}

static int _checkname(mod_websocket_t *config, const char *pathname)
{
	if (pathname[0] == '.')
	{
		return  EREJECT;
	}
	if (utils_searchexp(pathname, config->deny, NULL) == ESUCCESS &&
		utils_searchexp(pathname, config->allow, NULL) != ESUCCESS)
	{
		return  EREJECT;
	}
	return ESUCCESS;
}

static int websocket_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	_mod_websocket_ctx_t *ctx = (_mod_websocket_ctx_t *)arg;
	const char *connection = httpmessage_REQUEST(request, str_connection);
	const char *upgrade = httpmessage_REQUEST(request, str_upgrade);
	const char *uri = httpmessage_REQUEST(request, "uri");
	if (uri[0] == '/')
		uri++;

	if (ctx->socket == 0 &&
		connection != NULL && (strcasestr(connection, str_upgrade) != NULL) &&
		upgrade != NULL && (strcasestr(upgrade, str_websocket) != NULL))
	{

		if (_checkname(ctx->mod->config, uri) != ESUCCESS)
		{
			warn("websocket: %s forbidden", uri);
			httpmessage_result(response, RESULT_403);
			return ESUCCESS;
		}
		const char *protocol = httpmessage_REQUEST(request, str_protocol);

		int fdfile = openat(ctx->mod->fdroot, uri, O_PATH);
		if (fdfile == -1 && protocol != NULL && protocol[0] != '\0')
		{
			fdfile = openat(ctx->mod->fdroot, protocol, O_PATH);
		}
		if (fdfile == -1)
		{
			warn("websocket: uri %s not found", uri);
			httpmessage_result(response, RESULT_403);
			return ESUCCESS;
		}

		struct stat filestat;
		fstat(fdfile, &filestat);
		if (S_ISDIR(filestat.st_mode))
		{
			int fdroot = fdfile;
			if (protocol != NULL)
				fdfile = openat(fdroot, protocol, O_PATH);
			else
				fdfile = -1;
			if (fdfile == -1)
			{
				warn("websocket: protocol %s not found", protocol);
				httpmessage_result(response, RESULT_403);
				close(fdroot);
				return ESUCCESS;
			}
			fstat(fdfile, &filestat);
			ctx->fddir = dup(fdroot);
		}
		else
			ctx->fddir = dup(ctx->mod->fdroot);
		close(fdfile);

		if (!S_ISSOCK(filestat.st_mode))
		{
			close(ctx->fddir);
			httpmessage_result(response, RESULT_403);
			return ESUCCESS;
		}
		if (protocol != NULL)
			httpmessage_addheader(response, str_protocol, protocol);

		_mod_websocket_handshake(ctx, request, response);
		httpmessage_addheader(response, str_connection, (char *)str_upgrade);
		httpmessage_addheader(response, str_upgrade, (char *)str_websocket);
		/** disable Content-Type and Content-Length inside the headers **/
		httpmessage_addcontent(response, "none", NULL, -1);
		httpmessage_result(response, RESULT_101);
		websocket_dbg("%s: result 101", str_websocket);
		ctx->socket = httpmessage_lock(response);
		ret = ECONTINUE;
	}
	else if (ctx->socket > 0)
	{
		if (fchdir(ctx->fddir) == -1)
		{
			err("websocket: ");
		}
		else
			ctx->pid = ctx->mod->run(ctx->mod->runarg, ctx->socket, uri, request);
		ret = ESUCCESS;
	}
	return ret;
}

static void *_mod_websocket_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_websocket_t *mod = (_mod_websocket_t *)arg;

	_mod_websocket_ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->mod = mod;
	httpclient_addconnector(ctl, websocket_connector, ctx, CONNECTOR_DOCUMENT, str_websocket);

	return ctx;
}

static void _mod_websocket_freectx(void *arg)
{
	_mod_websocket_ctx_t *ctx = (_mod_websocket_ctx_t *)arg;

	if (ctx->pid > 0)
	{
#ifdef VTHREAD
		websocket_dbg("%s: waitpid", str_websocket);
		waitpid(ctx->pid, NULL, 0);
		websocket_dbg("%s: freectx", str_websocket);
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

void *mod_websocket_create(http_server_t *server, mod_websocket_t *config)
{
	_mod_websocket_t *mod = calloc(1, sizeof(*mod));

	mod_websocket_run_t run = config->run;
	if (run == NULL)
		run = default_websocket_run;
	mod->config = config;
	mod->run = run;
	mod->runarg = config;
	mod->fdroot = open(config->docroot, O_DIRECTORY);
	httpserver_addmod(server, _mod_websocket_getctx, _mod_websocket_freectx, mod, str_websocket);
	warn("%s: support %s", str_websocket, mod->config->docroot);
	return mod;
}

void mod_websocket_destroy(void *data)
{
	free(data);
}

static int _websocket_socket(const char *filepath)
{
	int sock;
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, filepath, sizeof(addr.sun_path) - 1);

	warn("%s: open %s", str_websocket, addr.sun_path);
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
		err("%s: open error (%s)", str_websocket, strerror(errno));
	}
	return sock;
}

typedef struct _websocket_main_s _websocket_main_t;
struct _websocket_main_s
{
	int client;
	int socket;
	http_recv_t recvreq;
	http_send_t sendresp;
	void *ctx;
	int type;
};

static int websocket_close(void *arg, int status)
{
	_websocket_main_t *info = (_websocket_main_t *)arg;
	char message[] = { 0x88, 0x02, 0x03, 0xEA};
	return info->sendresp(info->ctx, message, sizeof(message));
}

static int websocket_pong(void *arg, char *data)
{
	_websocket_main_t *info = (_websocket_main_t *)arg;
	char message[] = { 0x8A, 0x00};
	return info->sendresp(info->ctx, message, sizeof(message));
}

static int websocket_ping(void *arg, char *data)
{
	_websocket_main_t *info = (_websocket_main_t *)arg;
	char message[] = { 0x8A, 0x00};
	return info->sendresp(info->ctx, message, sizeof(message));
}

static void *_websocket_main(void *arg)
{
	_websocket_main_t *info = (_websocket_main_t *)arg;
	/** socket to the webclient **/
	int socket = info->socket;
	/** socket to the unix server **/
	int client = info->client;
	int end = 0;
	while (!end)
	{
		int ret;
		fd_set rdfs;
		int maxfd = socket;
		FD_ZERO(&rdfs);
		FD_SET(socket, &rdfs);
		maxfd = (maxfd > client)?maxfd:client;
		FD_SET(client, &rdfs);

		ret = select(maxfd + 1, &rdfs, NULL, NULL, NULL);
		if (ret > 0 && FD_ISSET(socket, &rdfs))
		{
			int length = 0;

			ret = ioctl(socket, FIONREAD, &length);
			if (ret == 0 && length > 0)
			{
				char *buffer = calloc(1, length);
				ret = info->recvreq(info->ctx, (char *)buffer, length);
				//char buffer[64];
				//ret = read(socket, buffer, 63);
				if (ret > 0)
				{
					websocket_dbg("%s: ws => u: recv %d bytes", str_websocket, ret);
					char *out = calloc(1, length);
					ret = websocket_unframed(buffer, ret, out, arg);
					websocket_dbg("%s: ws => u: send %d bytes\n\t%s", str_websocket, ret, out);
					if (ret > 0)
						ret = send(client, out, ret, MSG_NOSIGNAL);
					fsync(client);
					free(out);
				}
				if (ret < 0)
				{
					err("%s: data transfer error %d %s", str_websocket, ret, strerror(errno));
					end = 1;
				}
				free(buffer);
			}
			else
			{
				char buffer[64];
				ret = read(socket, buffer, 63);
				err("%s: %d %d error %s", str_websocket, ret, length, strerror(errno));
				end = 1;
			}
		}
		else if (ret > 0 && FD_ISSET(client, &rdfs))
		{
			int inlength;
			ret = ioctl(client, FIONREAD, &inlength);
			if (ret == 0 && inlength > 0)
			{
				char *buffer;
				buffer = calloc(1, inlength);
				while (inlength > 0)
				{
					ret = recv(client, buffer, inlength, MSG_NOSIGNAL);
					if (ret > 0)
					{
						websocket_dbg("%s: u => ws: recv %d bytes", str_websocket, ret);
						inlength -= ret;
						ssize_t size = 0;
						char *out = calloc(1, ret + MAX_FRAGMENTHEADER_SIZE);
						while (size < ret)
						{
							ssize_t length = ret;
							int outlength = 0;

							if (info->type == WS_TEXT)
							{
								length = strlen(buffer + size);
								if ((length + size) < ret)
								{
									warn("%s: two messages in ONE", str_websocket);
									/**
									 * add size to create frame with (length - size) characters
									 */
									length += size;
								}
							}
							length = websocket_framed(info->type, (char *)buffer + size, length - size, out, &outlength, arg);
							if (outlength > 0)
								outlength = info->sendresp(info->ctx, (char *)out, outlength);
							websocket_dbg("%s: u => ws: send %d bytes\n\t%.*s", str_websocket, outlength, (int)length, buffer + size);
							if (outlength == EINCOMPLETE)
								continue;
							if (outlength == EREJECT)
								break;
							size += length;
							/**
							 * remove the null character from the end of the string
							 */
							if ((info->type == WS_TEXT) && (buffer[size] == '\0'))
								size++;
						}
						free(out);
						if (size < ret)
						{
							ret = -1;
							break;
						}
					}
					else
						break;
				}
				free(buffer);
			}
			else
				ret = -1;
			if (ret < 0)
			{
				end = 1;
				warn("%s: server died", str_websocket);
			}
		}
		else if (errno != EAGAIN)
		{
			err("%s: error %s", str_websocket, strerror(errno));
			end = 1;
		}
	}
	shutdown(socket, SHUT_RDWR);
	close(socket);
	close(client);
	return 0;
}

static websocket_t _wsdefaul_config =
{
	.onclose = websocket_close,
	.onping = websocket_pong,
	.type = WS_TEXT,
};
int default_websocket_run(void *arg, int socket, const char *filepath, http_message_t *request)
{
	pid_t pid;
	int wssock = _websocket_socket(filepath);

	if (wssock > 0)
	{
		_websocket_main_t info = {.socket = socket, .client = wssock, .type = _wsdefaul_config.type};
		http_client_t *ctl = httpmessage_client(request);
		info.ctx = httpclient_context(ctl);
		info.recvreq = httpclient_addreceiver(ctl, NULL, NULL);
		info.sendresp = httpclient_addsender(ctl, NULL, NULL);

		websocket_init(&_wsdefaul_config);

		if ((pid = fork()) == 0)
		{
			_websocket_main(&info);
			warn("%s: process died", str_websocket);
			exit(0);
		}
		close(wssock);
	}
	return pid;
}

const module_t mod_websocket =
{
	.name = str_websocket,
	.create = (module_create_t)mod_websocket_create,
	.destroy = mod_websocket_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_websocket")));
#endif
