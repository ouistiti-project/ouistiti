/*****************************************************************************
 * mod_webstream.c: webstream server module
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

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "mod_webstream.h"

extern int ouistiti_websocket_run(void *arg, int sock, const char *protocol, http_message_t *request);
extern int ouistiti_websocket_socket(void *arg, int sock, const char *filepath, http_message_t *request);

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

#define WEBSTREAM_REALTIME	0x01
#define WEBSTREAM_TLS		0x02
#define WEBSTREAM_MULTIPART	0x04

typedef struct mod_webstream_s mod_webstream_t;
struct mod_webstream_s
{
	char *docroot;
	char *allow;
	char *deny;
	int options;
};

typedef struct _mod_webstream_s _mod_webstream_t;
typedef struct _mod_webstream_ctx_s _mod_webstream_ctx_t;

typedef int (*socket_t)(mod_webstream_t *config, char *filepath);

struct _mod_webstream_s
{
	mod_webstream_t *config;
	socket_t socket;
	int fdroot;
};

struct _mod_webstream_ctx_s
{
	_mod_webstream_t *mod;
	char *protocol;
	int socket;
	int client;
	pid_t pid;
	http_client_t *clt;
	const char *mime;
	const char *boundary;
};

static int _webstream_run(_mod_webstream_ctx_t *ctx, http_message_t *request);

/**
 * strings defined in libouistiti
 */
extern const char str_contenttype[];
extern const char str_contentlength[];

const char str_contenttype[] = "Content-Type";
const char str_contentlength[] = "Content-Length";

static const char str_webstream[] = "webstream";
static const char str_multipart_replace[] = "multipart/x-mixed-replace";
static const char str_boundary[] = "FRAME";

static int _checkname(_mod_webstream_ctx_t *ctx, const char *pathname)
{
	_mod_webstream_t *mod = ctx->mod;
	mod_webstream_t *config = (mod_webstream_t *)mod->config;
	if (utils_searchexp(pathname, config->deny, NULL) == ESUCCESS &&
		utils_searchexp(pathname, config->allow, NULL) != ESUCCESS)
	{
		return  EREJECT;
	}
	return ESUCCESS;
}

static int _webstream_socket(void *arg, int sock, const char *filepath)
{
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, filepath, sizeof(addr.sun_path) - 1);

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
		warn("websocket %s error: %s", filepath, strerror(errno));
	}
	return sock;
}

static int _webstream_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	_mod_webstream_ctx_t *ctx = (_mod_webstream_ctx_t *)arg;
	_mod_webstream_t *mod = ctx->mod;
	mod_webstream_t *config = (mod_webstream_t *)mod->config;

	if (ctx->client == 0)
	{
		const char *uri = httpmessage_REQUEST(request, "uri");
		if (_checkname(ctx, uri) != ESUCCESS)
		{
			return ret;
		}

		while (*uri == '/' && *uri != '\0') uri++;
		int fdfile = openat(mod->fdroot, uri, O_PATH);
		if (fdfile == -1)
		{
			return EREJECT;
		}
		struct stat filestat;
		fstat(fdfile, &filestat);
		close(fdfile);

		if (S_ISSOCK(filestat.st_mode))
		{
			ctx->socket = httpmessage_lock(response);
			ctx->mime = utils_getmime(uri);
			if (config->options & WEBSTREAM_MULTIPART)
			{
				ctx->boundary = str_boundary;
				char mime[256];
				mime[255] = 0;
				snprintf(mime, 255, "%s; boundary=%s", str_multipart_replace, ctx->boundary);
				httpmessage_addcontent(response, mime, NULL, -1);
			}
			else
				httpmessage_addcontent(response, ctx->mime, NULL, -1);

			if (fchdir(ctx->mod->fdroot) == -1)
				warn("webstream: impossible to change directory");
			int wssock;
#ifdef WEBSOCKET_RT
			if (config->options & WEBSTREAM_REALTIME)
			{
				wssock = ouistiti_websocket_run(NULL, ctx->socket, uri, request);
			}
			else
#endif
				wssock = _webstream_socket(NULL, ctx->socket, uri);

			if (wssock > 0)
			{
				ctx->client = wssock;
				ret = ECONTINUE;
			}
		}

		if (ctx->client <= 0)
		{
			httpmessage_result(response, RESULT_400);
			ret = ESUCCESS;
		}
		else
			ctx->socket = httpmessage_lock(response);
	}
	else
	{
		if (!(config->options & WEBSTREAM_REALTIME))
		{
			ctx->pid = _webstream_run(ctx, request);
		}
		ret = ESUCCESS;
	}
	return ret;
}

static void *_mod_webstream_getctx(void *arg, http_client_t *clt, struct sockaddr *addr, int addrsize)
{
	_mod_webstream_t *mod = (_mod_webstream_t *)arg;
	_mod_webstream_ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->mod = mod;
	ctx->clt = clt;
	httpclient_addconnector(clt, _webstream_connector, ctx, CONNECTOR_DOCUMENT, str_webstream);

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
		warn("webstream: end stream %p", ctx->clt);
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
		shutdown(ctx->client, SHUT_RD);
		close(ctx->client);
		httpclient_shutdown(ctx->clt);

	}
	free(ctx);
}

#ifdef FILE_CONFIG

static void *webstream_config(config_setting_t *iterator, server_t *server)
{
	mod_webstream_t *conf = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configws = config_setting_get_member(iterator, "webstream");
#else
	config_setting_t *configws = config_setting_lookup(iterator, "webstream");
#endif
	if (configws)
	{
		char *mode = NULL;
		conf = calloc(1, sizeof(*conf));
		config_setting_lookup_string(configws, "docroot", (const char **)&conf->docroot);
		config_setting_lookup_string(configws, "deny", (const char **)&conf->deny);
		config_setting_lookup_string(configws, "allow", (const char **)&conf->allow);
		config_setting_lookup_string(configws, "options", (const char **)&mode);
		if (utils_searchexp("direct", mode, NULL) == ESUCCESS && ouistiti_issecure(server))
			conf->options |= WEBSTREAM_REALTIME;
		if (utils_searchexp("multipart", mode, NULL) == ESUCCESS)
			conf->options |= WEBSTREAM_MULTIPART;
	}
	return conf;
}
#else
static const mod_webstream_t g_webstream_config =
{
	.docroot = "/srv/www""/webstream",
};

static void *webstream_config(void *iterator, server_t *server)
{
	return (void *)&g_webstream_config;
}
#endif

static void *mod_webstream_create(http_server_t *server, mod_webstream_t *config)
{
	if (config == NULL)
		return NULL;

	int fdroot = open(config->docroot, O_DIRECTORY);
	if (fdroot == -1)
	{
		err("webstream: docroot %s not found", config->docroot);
		return NULL;
	}

	_mod_webstream_t *mod = calloc(1, sizeof(*mod));

	mod->config = config;
	mod->fdroot = fdroot;
	httpserver_addmod(server, _mod_webstream_getctx, _mod_webstream_freectx, mod, str_webstream);
	return mod;
}

static void mod_webstream_destroy(void *data)
{
	_mod_webstream_t *mod = (_mod_webstream_t *)data;
#ifdef FILE_CONFIG
	free(mod->config);
#endif
	close(mod->fdroot);
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
	const char *mime;
	const char *boundary;
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
			if (length == 0)
				end = 1;
			else if (info->boundary != NULL)
			{
				char buffer[256];
				buffer[255] = 0;
				ret = snprintf(buffer, 255, "\r\n--%s\r\n", info->boundary);
				info->sendresp(info->ctx, buffer, ret - 1);
				ret = snprintf(buffer, 255, "%s: %s\r\n", str_contenttype, info->mime);
				info->sendresp(info->ctx, buffer, ret - 1);
				ret = snprintf(buffer, 255, "%s: %d\r\n", str_contentlength, length);
				info->sendresp(info->ctx, buffer, ret - 1);
				info->sendresp(info->ctx, "\r\n", 2);
			}
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

static int _webstream_run(_mod_webstream_ctx_t *ctx, http_message_t *request)
{
	pid_t pid;
	_mod_webstream_t *mod = ctx->mod;
	mod_webstream_t *config = (mod_webstream_t *)mod->config;

	_webstream_main_t info = {.socket = ctx->socket, .client = ctx->client, .boundary = NULL};
	info.ctx = httpclient_context(ctx->clt);
	info.recvreq = httpclient_addreceiver(ctx->clt, NULL, NULL);
	info.sendresp = httpclient_addsender(ctx->clt, NULL, NULL);
	if (config->options & WEBSTREAM_MULTIPART)
	{
		info.mime = ctx->mime;
		info.boundary = ctx->boundary;
	}

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
	.configure = (module_configure_t)&webstream_config,
	.create = (module_create_t)&mod_webstream_create,
	.destroy = &mod_webstream_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_webstream")));
#endif
