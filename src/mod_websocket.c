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
#include <sched.h>

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "ouistiti/log.h"
#include "ouistiti/httpserver.h"
#include "ouistiti/hash.h"
#include "mod_websocket.h"
#include "ouistiti/utils.h"
#include "ouistiti/websocket.h"

typedef int (*mod_websocket_run_t)(void *arg, int socket, int wssock, http_message_t *request);
int default_websocket_run(void *arg, int socket, int wssock, http_message_t *request);
#ifdef WEBSOCKET_RT
extern int ouistiti_websocket_run(void *arg, int socket, int wssock, http_message_t *request);
#endif

static int _mod_websocket_socket(const char *filepath);

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
	const char *host;
};

struct _mod_websocket_ctx_s
{
	_mod_websocket_t *mod;
	char *uri;
	int fddir;
	int socket;
	pid_t pid;
};

static void _mod_websocket_handshake(_mod_websocket_ctx_t *UNUSED(ctx), http_message_t *request, http_message_t *response)
{
	const char *key = httpmessage_REQUEST(request, str_sec_ws_key);
	if (key && key[0] != 0)
	{
		char accept[20] = {0};
		void *hctx;
		hctx = hash_sha1->init();
		hash_sha1->update(hctx, key, strlen(key));
		hash_sha1->update(hctx, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", sizeof("258EAFA5-E914-47DA-95CA-C5AB0DC85B11") -1);
		hash_sha1->finish(hctx, accept);

		char out[40];
		int outlen = base64->encode(accept, hash_sha1->size, out, 40);
		websocket_dbg("websocket: handshake %s", out);

		httpmessage_addheader(response, str_sec_ws_accept, out, outlen);
	}
}

static int _checkname(const mod_websocket_t *config, const char *pathname)
{
	if (utils_searchexp(pathname, config->deny, NULL) == ESUCCESS &&
		utils_searchexp(pathname, config->allow, NULL) != ESUCCESS)
	{
		return  EREJECT;
	}
	return ESUCCESS;
}

static int _checkfile(_mod_websocket_ctx_t *ctx, const char *uri, const char *protocol)
{
	int fdfile = openat(ctx->mod->fdroot, uri, O_PATH);
	if (fdfile == -1 && protocol != NULL)
	{
		uri = protocol;
		fdfile = openat(ctx->mod->fdroot, uri, O_PATH);
	}
	if (fdfile == -1)
	{
		warn("websocket: uri %s not found", uri);
		return EREJECT;
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
			close(fdroot);
			return EREJECT;
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
		return EREJECT;
	}
	ctx->uri = strdup(uri);
	return ESUCCESS;
}

static int websocket_connector_init(_mod_websocket_ctx_t *ctx, http_message_t *request, http_message_t *response)
{
	_mod_websocket_t *mod = ctx->mod;
	int ret = EREJECT;

	const char *uri = httpmessage_REQUEST(request, "uri");
	if (_checkname(mod->config, uri) != ESUCCESS)
	{
		warn("websocket: %s forbidden", uri);
		return EREJECT;
	}
	const char *protocol = httpmessage_REQUEST(request, str_sec_ws_protocol);
	if (protocol[0] == '\0')
		protocol = NULL;

	while (*uri == '/' && *uri != '\0') uri++;
	if (mod->fdroot > 0)
	{
		ret = _checkfile(ctx, uri, protocol);
	}
	else if (mod->host)
	{
		ctx->uri = strdup(mod->host);
		ret = ESUCCESS;
	}
	else
	{
		return EREJECT;
	}

	if (ret == EREJECT)
	{
		httpmessage_result(response, RESULT_403);
		return ESUCCESS;
	}

	if (fchdir(ctx->fddir) == -1)
	{
		httpmessage_result(response, RESULT_500);
		return ESUCCESS;
	}

	if (protocol != NULL)
	{
		httpmessage_addheader(response, str_sec_ws_protocol, protocol, -1);
		warn("websocket: protocol returns %s", protocol);
	}

	_mod_websocket_handshake(ctx, request, response);
	httpmessage_addheader(response, str_connection, STRING_REF(str_upgrade));
	httpmessage_addheader(response, str_upgrade, STRING_REF(str_websocket));
	/** disable Content-Type and Content-Length inside the headers **/
	httpmessage_addcontent(response, "none", NULL, -1);
	httpmessage_result(response, RESULT_101);
	ctx->socket = httpmessage_lock(response);
	return ECONTINUE;
}

static int websocket_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	_mod_websocket_ctx_t *ctx = (_mod_websocket_ctx_t *)arg;
	const char *connection = httpmessage_REQUEST(request, str_connection);
	const char *upgrade = httpmessage_REQUEST(request, str_upgrade);

	if (ctx->socket == 0 &&
		connection != NULL && (strcasestr(connection, str_upgrade) != NULL) &&
		upgrade != NULL && (strcasestr(upgrade, str_websocket) != NULL))
	{
		ret = websocket_connector_init(ctx, request, response);
	}
	else if (ctx->socket > 0)
	{
		char *uri = ctx->uri;
		while (*uri == '/' && *uri != '\0') uri++;
		int wssock = _mod_websocket_socket(uri);
		if (wssock > 0)
		{
			ctx->pid = ctx->mod->run(ctx->mod->runarg, ctx->socket, wssock, request);
			free(ctx->uri);
			ctx->uri = NULL;
			ret = ESUCCESS;
		}
	}
	return ret;
}

static void *_mod_websocket_getctx(void *arg, http_client_t *ctl, struct sockaddr *UNUSED(addr), int UNUSED(addrsize))
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
		websocket_dbg("websocket: waitpid");
		waitpid(ctx->pid, NULL, 0);
		websocket_dbg("websocket: freectx");
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
static void *websocket_config(config_setting_t *iterator, server_t *server)
{
	mod_websocket_t *conf = NULL;
#if LIBCONFIG_VER_MINOR < 5
	const config_setting_t *configws = config_setting_get_member(iterator, "websocket");
#else
	const config_setting_t *configws = config_setting_lookup(iterator, "websocket");
#endif
	if (configws)
	{
		const char *mode = NULL;
		conf = calloc(1, sizeof(*conf));
		config_setting_lookup_string(configws, "docroot", &conf->docroot);
		config_setting_lookup_string(configws, "server", &conf->server);
		config_setting_lookup_string(configws, "allow", &conf->allow);
		config_setting_lookup_string(configws, "deny", &conf->deny);
		config_setting_lookup_string(configws, "options", &mode);
#ifdef WEBSOCKET_RT
		if (utils_searchexp("direct", mode, NULL) == ESUCCESS)
		{
			if (!ouistiti_issecure(server))
				conf->options |= WEBSOCKET_REALTIME;
			else
				warn("websocket: realtime configuration is not allowed with tls");
		}
#else
#endif
	}
	return conf;
}
#else
static const mod_websocket_t g_websocket_config =
{
	.docroot = "/srv/www""/websocket",
};

static void *websocket_config(void *iterator, server_t *server)
{
	return (void *)&g_websocket_config;
}
#endif

static void *mod_websocket_create(http_server_t *server, mod_websocket_t *config)
{
	int fdroot = -1;

	if (config == NULL)
		return NULL;
	if (config->docroot != NULL)
	{
		fdroot = open(config->docroot, O_DIRECTORY);
		if (fdroot == -1)
		{
			err("websocket: docroot %s not found from %s", config->docroot, getenv("PWD"));
			return NULL;
		}
	}
	_mod_websocket_t *mod = calloc(1, sizeof(*mod));

	mod->config = config;
#ifdef WEBSOCKET_RT
	if (config->options & WEBSOCKET_REALTIME)
	{
		mod->run = ouistiti_websocket_run;
		warn("server %p runs realtime websocket!", server);
	}
	else
#else
	(void)(server);
#endif
	mod->run = default_websocket_run;

	mod->runarg = config;
	mod->fdroot = fdroot;
	mod->host = config->server;
	httpserver_addmod(server, _mod_websocket_getctx, _mod_websocket_freectx, mod, str_websocket);
	return mod;
}

static void mod_websocket_destroy(void *data)
{
	_mod_websocket_t *mod = (_mod_websocket_t *)data;
#ifdef FILE_CONFIG
	free(mod->config);
#endif
	close(mod->fdroot);
	free(data);
}

static int _websocket_unix(const char *filepath)
{
	int sock;
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, filepath, sizeof(addr.sun_path) - 1);

	warn("websocket: open %s", addr.sun_path);
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
		err("websocket: open error (%s)", strerror(errno));
	}
	return sock;
}

static int _websocket_tcp(const char *host, const char *port)
{
	int sock = -1;
	struct addrinfo *result;
	struct addrinfo hints;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	if (getaddrinfo(host, port, &hints, &result) != 0)
	{
		return -1;
	}

	for (struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next)
	{
		sock = socket(rp->ai_family, rp->ai_socktype,
			rp->ai_protocol);
		if (sock == -1)
			continue;

		if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)
			break;

		close(sock);
		sock = -1;
	}
	if (sock == -1)
	{
		err("websocket: open error (%s)", strerror(errno));
	}
	else
		warn("websocket: open %s", host);

	return sock;
}

static int _mod_websocket_socket(const char *filepath)
{
	int sock = -1;
	char *port;
	if (!access(filepath, F_OK))
	{
		sock = _websocket_unix(filepath);
	}
	else if ((port = strchr(filepath, ':')) != NULL)
	{
		*port = '\0';
		port += 1;
		sock = _websocket_tcp(filepath, port);
	}
	return sock;
}

typedef struct _websocket_main_s _websocket_main_t;
struct _websocket_main_s
{
	int client;
	int server;
	http_recv_t recvreq;
	http_send_t sendresp;
	void *ctx;
	int type;
	int end;
};

static int websocket_close(void *arg, int UNUSED(status))
{
	_websocket_main_t *info = (_websocket_main_t *)arg;
	char message[] = { 0x88, 0x02, 0x03, 0xEA};
	info->end = 1;
	return info->sendresp(info->ctx, message, sizeof(message));
}

static int websocket_pong(void *arg, char *UNUSED(data))
{
	_websocket_main_t *info = (_websocket_main_t *)arg;
	char message[] = { 0x8A, 0x00};
	return info->sendresp(info->ctx, message, sizeof(message));
}

#ifdef WEBSOCKET_PING
static int websocket_ping(void *arg, char *data)
{
	_websocket_main_t *info = (_websocket_main_t *)arg;
	char message[] = { 0x8A, 0x00};
	return info->sendresp(info->ctx, message, sizeof(message));
}
#endif

static int _websocket_recieveclient(_websocket_main_t *info, char **buffer)
{
	int client = info->client;
	int length;
	int ret;

	ret = ioctl(client, FIONREAD, &length);
	if (ret == 0 && length > 0)
	{
		*buffer = calloc(1, length);
		ret = info->recvreq(info->ctx, *buffer, length);
		if (ret > 0)
		{
			websocket_dbg("websocket: c => ws: recv %d bytes", ret);
		}
		else
		{
			free(*buffer);
			*buffer = NULL;
		}
	}
	return ret;
}

static int _websocket_forwardtoclient(_websocket_main_t *info, char *buffer, int size)
{
	ssize_t length = size;
	if (info->type == WS_TEXT && strlen(buffer) < size)
	{
		warn("websocket: two messages in ONE");
	}
	int ret = EINCOMPLETE;
	int outlength = 0;
	char *out = calloc(1, length + MAX_FRAGMENTHEADER_SIZE);
	length = websocket_framed(info->type, buffer, length, out, &outlength, (void *)info);
	while (outlength > 0 && ret == EINCOMPLETE)
	{
		ret = info->sendresp(info->ctx, out, outlength);
		websocket_dbg("websocket: ws => c: send %d/%d bytes\n\t%.*s", ret, outlength, (int)length, buffer);
		if (ret > 0)
			outlength -= ret;
	}
	free(out);
	sched_yield();
	if (ret == EREJECT)
	{
		warn("websocket: connection closed by client");
		return EREJECT;
	}
	if (size > length && buffer[length - 1] == '\0')
	{
		length ++;
		buffer += length;
		size -= length;
		length += _websocket_forwardtoclient(info, buffer, size);
	}
	return length;
}

static int _websocket_recieveserver(_websocket_main_t *info, char **buffer)
{
	int server = info->server;
	int ret;
	int length = 0;

	ret = ioctl(server, FIONREAD, &length);
	if (ret == 0 && length > 0)
	{
		*buffer = calloc(1, length);
		ret = recv(server, *buffer, length, MSG_NOSIGNAL);
		if (ret > 0)
		{
			websocket_dbg("websocket: u => ws: recv %d bytes", ret);
		}
		else
		{
			free(*buffer);
			*buffer = NULL;
		}
	}
	return ret;
}

static int _websocket_forwardtoserver(_websocket_main_t *info, char *buffer, int length)
{
	int server = info->server;
	int ret = 0;

	char *out = calloc(1, length);
	int outlength = websocket_unframed(buffer, length, out, (void *)info);
	while (outlength > 0 && ret != -1)
	{
		if (outlength == 1 && out[0] == '\0')
		{
			dbg("websocket: try to send empty string");
			ret = -1;
		}
		else
			ret = send(server, out, outlength, MSG_NOSIGNAL | MSG_DONTWAIT);
		if (ret == -1 && errno == EAGAIN)
			ret = 0;
		websocket_dbg("websocket: ws => u: send %d bytes\n\t%s", ret, out);
		outlength -= ret;
	}
	fsync(server);
	sched_yield();
	free(out);
	if (ret == -1)
	{
		err("websocket: data transfer error %d %s", ret, strerror(errno));
		ret = EREJECT;
	}
	return ret;
}

static void *_websocket_main(void *arg)
{
	_websocket_main_t *info = (_websocket_main_t *)arg;
	/** socket to the unix server **/
	int server = info->server;
	/** socket to the webclient **/
	int client = info->client;
	info->end = 0;
	struct timeval timeout = {5,0};
	while (!info->end)
	{
		int ret;
		fd_set rdfs;
		int maxfd = server;
		FD_ZERO(&rdfs);
		FD_SET(server, &rdfs);
		FD_SET(client, &rdfs);
		maxfd = (maxfd > client)?maxfd:client;

		ret = select(maxfd + 1, &rdfs, NULL, NULL, &timeout);
		if (ret > 0 && FD_ISSET(server, &rdfs))
		{
			char *buffer = NULL;
			int size = _websocket_recieveserver(info, &buffer);
			if (size > 0 && buffer != NULL)
			{
				ret = _websocket_forwardtoclient(info, buffer, size);
				free(buffer);
				if (ret == EREJECT)
				{
					warn("websocket: client died");
					info->end = 1;
				}
			}
			else
			{
				warn("websocket: server died");
				info->end = 1;
			}
		}
		else if (ret > 0 && FD_ISSET(client, &rdfs))
		{
			char *buffer = NULL;
			int size = _websocket_recieveclient(info, &buffer);
			if (size > 0 && buffer != NULL)
			{
				ret = _websocket_forwardtoserver(info, buffer, size);
				free(buffer);
				if (ret == EREJECT)
				{
					warn("websocket: server died");
					info->end = 1;
				}
			}
			else
			{
				warn("websocket: client died");
				info->end = 1;
			}
			// reinitialize the timeout each time that the ws receive
			// data from client.
			timeout.tv_sec = 5;
			timeout.tv_usec = 0;
		}
		else if (ret == 0)
		{
			// ping the client when ws doesn't receive data
			// from client for 5s
			// this feature may be available only with Linux
			// as other systems don't modify timeout on select.
#ifdef WEBSOCKET_PING
			if (websocket_ping(info, NULL) < 0)
			{
				warn("websocket: client died");
				info->end = 1;
			}
#endif
			timeout.tv_sec = 5;
		}
		else if (errno != EAGAIN)
		{
			err("websocket: error %s", strerror(errno));
			info->end = 1;
		}
	}
	shutdown(server, SHUT_RDWR);
	close(server);
	close(client);
	return 0;
}

static websocket_t _wsdefaul_config =
{
	.onclose = websocket_close,
	.onping = websocket_pong,
	.type = WS_TEXT,
};
int default_websocket_run(void *arg, int sock, int wssock, http_message_t *request)
{
	pid_t pid = -1;
	_websocket_main_t info = {.client = sock, .server = wssock, .type = _wsdefaul_config.type};
	http_client_t *clt = httpmessage_client(request);
	info.ctx = httpclient_context(clt);
	info.recvreq = httpclient_addreceiver(clt, NULL, NULL);
	info.sendresp = httpclient_addsender(clt, NULL, NULL);

	websocket_init(&_wsdefaul_config);

	if ((pid = fork()) == 0)
	{
		_websocket_main(&info);
		warn("websocket: process died");
		exit(0);
	}
	close(wssock);
	return pid;
}

const module_t mod_websocket =
{
	.name = str_websocket,
	.configure = (module_configure_t)&websocket_config,
	.create = (module_create_t)mod_websocket_create,
	.destroy = mod_websocket_destroy
};

#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_websocket")));
#endif
