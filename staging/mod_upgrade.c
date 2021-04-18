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
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/wait.h>

#include <sys/socket.h>
#include <sys/un.h>
#ifdef UPGRADE_INET
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "ouistiti/log.h"
#include "ouistiti/httpserver.h"
#include "ouistiti/hash.h"
#include "mod_upgrade.h"
#include "ouistiti/utils.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define upgrade_dbg(...)

typedef struct _mod_upgrade_s _mod_upgrade_t;
typedef struct _mod_upgrade_ctx_s _mod_upgrade_ctx_t;

struct _mod_upgrade_s
{
	mod_upgrade_t *config;
	const char *upgrade;
	int fdroot;
};

struct _mod_upgrade_ctx_s
{
	_mod_upgrade_t *mod;
	int serversock;
	int socket;
	pid_t pid;
};

static const char str_connection[] = "Connection";
static const char str_upgrade[] = "Upgrade";
const char str_rhttp[] = "PTTH/1.0";

static int default_upgrade_run(void *arg, int sock, http_message_t *request);

static int _checkname(mod_upgrade_t *config, const char *pathname)
{
	if (utils_searchexp(pathname, config->deny, NULL) == ESUCCESS &&
		utils_searchexp(pathname, config->allow, NULL) != ESUCCESS)
	{
		return  EREJECT;
	}
	return ESUCCESS;
}

static int _upgrade_socket_unix(_mod_upgrade_ctx_t *ctx, const char *filepath)
{
	_mod_upgrade_t *mod = ctx->mod;
	/**
	 * use openat + fstat instead fstatat
	 */
	int fdfile = openat(mod->fdroot, filepath, O_PATH);
	if (fdfile > 0)
	{
		struct stat filestat;
		fstat(fdfile, &filestat);
		close(fdfile);
		if (S_ISDIR(filestat.st_mode) || !S_ISSOCK(filestat.st_mode))
		{
			return EINCOMPLETE;
		}
		else
		{
			int sock;
			struct sockaddr_un addr;
			memset(&addr, 0, sizeof(struct sockaddr_un));
			addr.sun_family = AF_UNIX;
			snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s", mod->config->docroot, filepath);

			warn("upgrade: open %s", addr.sun_path);
			sock = socket(AF_UNIX, SOCK_STREAM, 0);
			if (sock > 0)
			{
				int ret = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
				if (ret < 0)
				{
					close(sock);
					return EINCOMPLETE;
				}
			}
			if (sock == -1)
			{
				err("upgrade: open error (%s)", strerror(errno));
			}
			ctx->serversock = sock;
			return ECONTINUE;
		}
	}
	return EREJECT;
}

#ifdef UPGRADE_INET
static int _upgrade_socket_inet(_mod_upgrade_ctx_t *ctx, const char *uri)
{
	_mod_upgrade_t *mod = ctx->mod;
	int sock;
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(mod->config->port);
	inet_aton(mod->config->uri, &addr.sin_addr);

	warn("upgrade: open %s:%d", mod->config->uri, mod->config->port);
	sock = socket(AF_INET, SOCK_STREAM, 0);
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
#endif

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
		while (*uri == '/' && *uri != '\0') uri++;
		ret = _upgrade_socket_unix(ctx, uri);
#ifdef UPGRADE_INET
		if (ret == EINCOMPLETE)
		{
			ret = _upgrade_socket_inet(ctx, uri);
		}
#endif
		if (ret == EINCOMPLETE)
		{
			warn("upgrade: protocol %s not found", uri);
			httpmessage_result(response, RESULT_403);
			ret = ESUCCESS;
		}
		else if (ret == ECONTINUE)
		{
			httpmessage_addheader(response, str_connection, str_upgrade);
			httpmessage_addheader(response, str_upgrade, mod->upgrade);
			/** disable Content-Type and Content-Length inside the headers **/
			httpmessage_addcontent(response, "none", NULL, -1);
			httpmessage_result(response, RESULT_101);
			upgrade_dbg("upgrade: to %s result 101", mod->upgrade);
			ctx->socket = httpmessage_lock(response);
		}
	}
	else if (ctx->socket > 0)
	{
		ctx->pid = default_upgrade_run(ctx, ctx->socket, request);
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

#ifdef FILE_CONFIG
#include <libconfig.h>

static void *upgrade_config(config_setting_t *iterator, server_t *server)
{
	mod_upgrade_t *conf = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configws = config_setting_get_member(iterator, "upgrade");
#else
	config_setting_t *configws = config_setting_lookup(iterator, "upgrade");
#endif
	if (configws)
	{
		const char *mode = NULL;
		conf = calloc(1, sizeof(*conf));
		config_setting_lookup_string(configws, "docroot", &conf->docroot);
#ifdef UPGRADE_INET
		config_setting_lookup_string(configws, "serveraddr", &conf->uri);
		config_setting_lookup_int(configws, "port", &conf->port);
#endif
		config_setting_lookup_string(configws, "allow", &conf->allow);
		config_setting_lookup_string(configws, "deny", &conf->deny);
		config_setting_lookup_string(configws, "upgrade", &conf->upgrade);
		config_setting_lookup_string(configws, "options", &mode);
	}
	return conf;
}
#else
static mod_upgrade_t g_upgrade_config =
{
	.docroot = "/srv/www""/upgrade",
	.upgrade = "test",
};
static void *upgrade_config(void *iterator, server_t *server)
{
	return &g_upgrade_config;
}
#endif

static void *mod_upgrade_create(http_server_t *server, mod_upgrade_t *config)
{
	if (config == NULL)
		return NULL;

	int fdroot = open(config->docroot, O_DIRECTORY);
	if (fdroot == -1)
	{
		err("upgrade: docroot %s not found", config->docroot);
		return NULL;
	}

	_mod_upgrade_t *mod = calloc(1, sizeof(*mod));

	mod->config = config;
	if (!strcasecmp(config->upgrade, "rhttp"))
		mod->upgrade = str_rhttp;
	else
		mod->upgrade = config->upgrade;
	mod->fdroot = fdroot;
	httpserver_addmod(server, _mod_upgrade_getctx, _mod_upgrade_freectx, mod, str_upgrade);
	return mod;
}

void mod_upgrade_destroy(void *data)
{
	_mod_upgrade_t *mod = (_mod_upgrade_t *)data;
#ifdef FILE_CONFIG
	free(mod->config);
#endif
	close(mod->fdroot);
	free(data);
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

static int default_upgrade_run(void *arg, int sock, http_message_t *request)
{
	_mod_upgrade_ctx_t *ctx = (_mod_upgrade_ctx_t *)arg;
	pid_t pid = -1;

	if (ctx->serversock > 0)
	{
		_upgrade_main_t info = {.client = sock, .server = ctx->serversock};
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
		close(ctx->serversock);
	}
	return pid;
}

const module_t mod_upgrade =
{
	.name = "upgrade",
	.configure = (module_configure_t)&upgrade_config,
	.create = (module_create_t)mod_upgrade_create,
	.destroy = mod_upgrade_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_upgrade")));
#endif
