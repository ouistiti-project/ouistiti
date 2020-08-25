/*****************************************************************************
 * mod_upgrade.c: upgrade server module
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
#include "mod_upgrade.h"
#include "httpserver/utils.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define upgrade_dbg(...)

typedef struct _mod_upgrade_s _mod_upgrade_t;
typedef struct _mod_upgrade_ctx_s _mod_upgrade_ctx_t;

struct _mod_upgrade_s
{
	mod_upgrade_t *config;
	mod_upgrade_run_t run;
	void *runarg;
	const char *upgrade;
	int fdroot;
};

struct _mod_upgrade_ctx_s
{
	_mod_upgrade_t *mod;
	int fddir;
	int socket;
	pid_t pid;
};

static const char str_connection[] = "Connection";
static const char str_upgrade[] = "Upgrade";
const char str_rhttp[] = "PTTH/1.0";

static int _checkname(mod_upgrade_t *config, const char *pathname)
{
	if (utils_searchexp(pathname, config->deny, NULL) == ESUCCESS &&
		utils_searchexp(pathname, config->allow, NULL) != ESUCCESS)
	{
		return  EREJECT;
	}
	return ESUCCESS;
}

static int upgrade_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	_mod_upgrade_ctx_t *ctx = (_mod_upgrade_ctx_t *)arg;
	_mod_upgrade_t *mod = ctx->mod;
	const char *connection = httpmessage_REQUEST(request, str_connection);
	const char *upgrade = httpmessage_REQUEST(request, str_upgrade);
	const char *uri = httpmessage_REQUEST(request, "uri");

	if (ctx->socket == 0 &&
		connection != NULL && (strcasestr(connection, str_upgrade) != NULL) &&
		upgrade != NULL && (strcasestr(upgrade, mod->upgrade) != NULL))
	{

		if (_checkname(mod->config, uri) != ESUCCESS)
		{
			warn("upgrade: %s forbidden", uri);
			httpmessage_result(response, RESULT_403);
			return ESUCCESS;
		}
		/**
		 * use openat + fstat instead fstatat
		 */
		while (*uri == '/' && *uri != '\0') uri++;
		int fdfile = openat(mod->fdroot, uri, O_PATH);
		if (fdfile == -1)
		{
			warn("upgrade: uri %s not found", uri);
			httpmessage_result(response, RESULT_403);
			return ESUCCESS;
		}

		struct stat filestat;
		fstat(fdfile, &filestat);
		if (S_ISDIR(filestat.st_mode) || !S_ISSOCK(filestat.st_mode))
		{
			warn("upgrade: protocol %s not found", uri);
			httpmessage_result(response, RESULT_403);
			close(fdfile);
			return ESUCCESS;
		}
		else
			ctx->fddir = dup(mod->fdroot);
		close(fdfile);

		httpmessage_addheader(response, str_connection, str_upgrade);
		httpmessage_addheader(response, str_upgrade, mod->upgrade);
		/** disable Content-Type and Content-Length inside the headers **/
		httpmessage_addcontent(response, "none", NULL, -1);
		httpmessage_result(response, RESULT_101);
		upgrade_dbg("upgrade: to %s result 101", mod->upgrade);
		ctx->socket = httpmessage_lock(response);
		ret = ECONTINUE;
	}
	else if (ctx->socket > 0)
	{
		if (fchdir(ctx->fddir) == -1)
		{
			err("upgrade: ");
		}
		else
		{
			while (*uri == '/' && *uri != '\0') uri++;
			ctx->pid = ctx->mod->run(ctx->mod->runarg, ctx->socket, uri, request);
		}
		ret = ESUCCESS;
	}
	return ret;
}

static void *_mod_upgrade_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_upgrade_t *mod = (_mod_upgrade_t *)arg;

	_mod_upgrade_ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->mod = mod;
	httpclient_addconnector(ctl, upgrade_connector, ctx, CONNECTOR_DOCUMENT, str_upgrade);

	return ctx;
}

static void _mod_upgrade_freectx(void *arg)
{
	_mod_upgrade_ctx_t *ctx = (_mod_upgrade_ctx_t *)arg;

	if (ctx->pid > 0)
	{
#ifdef VTHREAD
		upgrade_dbg("upgrade: waitpid");
		waitpid(ctx->pid, NULL, 0);
		upgrade_dbg("upgrade: freectx");
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

void *mod_upgrade_create(http_server_t *server, mod_upgrade_t *config)
{
	int fdroot = open(config->docroot, O_DIRECTORY);
	if (fdroot == -1)
	{
		err("upgrade: docroot %s not found", config->docroot);
		return NULL;
	}

	_mod_upgrade_t *mod = calloc(1, sizeof(*mod));

	mod_upgrade_run_t run = config->run;
	if (run == NULL)
		run = default_upgrade_run;
	mod->config = config;
	if (!strcasecmp(config->upgrade, "rhttp"))
		mod->upgrade = str_rhttp;
	else
		mod->upgrade = config->upgrade;
	mod->run = run;
	mod->runarg = config;
	mod->fdroot = fdroot;
	httpserver_addmod(server, _mod_upgrade_getctx, _mod_upgrade_freectx, mod, str_upgrade);
	return mod;
}

void mod_upgrade_destroy(void *data)
{
	free(data);
}

static int _upgrade_socket(const char *filepath)
{
	int sock;
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, filepath, sizeof(addr.sun_path) - 1);

	warn("upgrade: open %s", addr.sun_path);
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
		err("upgrade: open error (%s)", strerror(errno));
	}
	return sock;
}

typedef struct _upgrade_main_s _upgrade_main_t;
struct _upgrade_main_s
{
	int client;
	int server;
	http_recv_t recvreq;
	http_send_t sendresp;
	void *ctx;
};

static void *_upgrade_main(void *arg)
{
	_upgrade_main_t *info = (_upgrade_main_t *)arg;
	/** socket to the webclient **/
	int server = info->server;
	/** socket to the unix server **/
	int client = info->client;
	int end = 0;
	while (!end)
	{
		char buffer[1500];
		int ret;
		fd_set rdfs;
		int maxfd = server;
		FD_ZERO(&rdfs);
		FD_SET(server, &rdfs);
		maxfd = (maxfd > client)?maxfd:client;
		FD_SET(client, &rdfs);

		ret = select(maxfd + 1, &rdfs, NULL, NULL, NULL);
		if (ret > 0 && FD_ISSET(server, &rdfs))
		{
			ret = recv(server, buffer, sizeof(buffer), MSG_NOSIGNAL);
			upgrade_dbg("upgrade u => c %d", ret);
			if (ret > 0)
			{
				ssize_t size = 0;
				while (size < ret)
				{
					int outlength = 0;
					outlength = info->sendresp(info->ctx, (char *)buffer + size, ret - size);
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
			if (ret == 0)
			{
				/**
				 * end of stream
				 */
				end = 1;
			}
			if (ret == EREJECT)
			{
				end = 1;
				err("upgrade: socket error %s", strerror(errno));
			}
			if (ret == EINCOMPLETE)
			{
				err("upgrade: socket wait data");
			}
		}
		if (ret > 0 && FD_ISSET(client, &rdfs))
		{
			ret = info->recvreq(info->ctx, buffer, sizeof(buffer));
			upgrade_dbg("upgrade c => u %d", ret);
			if (ret > 0)
			{
				ssize_t size = 0;
				while (size < ret)
				{
					int outlength = 0;
					outlength = send(server, buffer + size, ret - size, MSG_NOSIGNAL);
					if (outlength == -1)
					{
						ret = -1;
						break;
					}
					size += outlength;
				}
			}
			if (ret == 0)
			{
				/**
				 * end of stream
				 */
				end = 1;
			}
			if (ret == -1)
			{
				end = 1;
				err("upgrade: unix error %s %d %d", strerror(errno), errno, EAGAIN);
			}
		}
	}
	shutdown(server, SHUT_RDWR);
	close(server);
	close(client);
	return 0;
}

int default_upgrade_run(void *arg, int sock, const char *filepath, http_message_t *request)
{
	_mod_upgrade_ctx_t *ctx = (_mod_upgrade_ctx_t *)arg;
	pid_t pid = -1;
	int usock = _upgrade_socket(filepath);

	if (usock > 0)
	{
		_upgrade_main_t info = {.client = sock, .server = usock};
		http_client_t *clt = httpmessage_client(request);
		info.ctx = httpclient_context(clt);
		info.recvreq = httpclient_addreceiver(clt, NULL, NULL);
		info.sendresp = httpclient_addsender(clt, NULL, NULL);

		if ((pid = fork()) == 0)
		{
			_upgrade_main(&info);
			warn("upgrade: process died");
			exit(0);
		}
		close(usock);
	}
	return pid;
}

const module_t mod_upgrade =
{
	.name = "upgrade",
	.create = (module_create_t)mod_upgrade_create,
	.destroy = mod_upgrade_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_upgrade")));
#endif
