/*****************************************************************************
 * mod_cgi.c: callbacks and management of connection
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
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libgen.h>

#include "httpserver.h"
#include "uri.h"
#include "mod_cgi.h"

typedef struct _mod_cgi_config_s _mod_cgi_config_t;
typedef struct _mod_cgi_s _mod_cgi_t;
typedef struct mod_cgi_ctx_s mod_cgi_ctx_t;

static http_server_config_t mod_cgi_config;

static void *_mod_cgi_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize);
static void _mod_cgi_freectx(void *vctx);
static int _mod_cgi_recv(void *vctx, char *data, int size);
static int _mod_cgi_send(void *vctx, char *data, int size);
static int _cgi_connector(void *arg, http_message_t *request, http_message_t *response);

struct mod_cgi_ctx_s
{
	enum
	{
		STATE_START,
		STATE_INFINISH,
		STATE_HEADERCOMPLETE,
		STATE_OUTFINISH,
		STATE_END,
	} state;
	_mod_cgi_t *mod;
	http_client_t *ctl;
	void *oldctx;
	http_recv_t recvreq;
	http_send_t sendresp;
	char *input;
	int inputlen;

	char *cgipath;
	
	pid_t pid;
	int tocgi[2];
	int fromcgi[2];
};

struct _mod_cgi_s
{
	http_server_t *server;
	mod_cgi_config_t *config;
};

void *mod_cgi_create(http_server_t *server, mod_cgi_config_t *modconfig)
{
	_mod_cgi_t *mod;

	if (!modconfig)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = modconfig;
	mod->server = server;

	httpserver_addmod(server, _mod_cgi_getctx, _mod_cgi_freectx, mod);

	return mod;
}

void mod_cgi_destroy(void *arg)
{
	_mod_cgi_t *mod = (_mod_cgi_t *)arg;
	free(mod);
}

static void *_mod_cgi_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_cgi_t *mod = (_mod_cgi_t *)arg;
	mod_cgi_ctx_t *ctx = calloc(1, sizeof(*ctx));

	ctx->ctl = ctl;
	ctx->mod = mod;
	ctx->oldctx = httpclient_context(ctl);
	httpclient_addconnector(ctl, NULL, _cgi_connector, ctx);
	ctx->recvreq = httpclient_addreceiver(ctl, _mod_cgi_recv, ctx);
	ctx->sendresp = httpclient_addsender(ctl, _mod_cgi_send, ctx);

	return ctx;
}

static void _mod_cgi_freectx(void *vctx)
{
	mod_cgi_ctx_t *ctx = (mod_cgi_ctx_t *)vctx;
	if (ctx->cgipath)
		free(ctx->cgipath);
	if (ctx->fromcgi[0])
	{
		if (ctx->fromcgi[0])
			close(ctx->fromcgi[0]);
		if (ctx->tocgi[1] > 0)
			close(ctx->tocgi[1]);
	}
	free(ctx);
}

static int _mod_cgi_recv(void *vctx, char *data, int size)
{
	int ret;
	mod_cgi_ctx_t *ctx = (mod_cgi_ctx_t *)vctx;

	ret = ctx->recvreq(ctx->oldctx, data, size);
	if (ret < size)
		ctx->state = STATE_INFINISH;
	ctx->input = data;
	ctx->inputlen = size;
	return ret;
}

static int _mod_cgi_send(void *vctx, char *data, int size)
{
	int ret = 0;
	mod_cgi_ctx_t *ctx = (mod_cgi_ctx_t *)vctx;
	ret = ctx->sendresp(ctx->oldctx, data, size);
	return ret;
}

typedef char *(*httpenv_callback_t)(http_message_t request);
struct httpenv_s
{
	char *target;
	int length;
	httpenv_callback_t cb;
};
typedef struct httpenv_s httpenv_t;

#define SERVER_SOFTWARE_CB(msg) httpmessage_SERVER(msg, "name")
#define SERVER_NAME_CB(msg) httpmessage_SERVER(msg, "name")
#define GATEWAY_INTERFACE_CB(msg) httpmessage_SERVER(msg, "gw")
#define SERVER_PROTOCOL_CB(msg) httpmessage_SERVER(msg, "protocol")
#define SERVER_PORT_CB(msg) httpmessage_SERVER(msg, "port")
#define REQUEST_METHOD_CB(msg) httpmessage_REQUEST(msg, "method")
#define HTTP_ACCEPT_CB(msg) httpmessage_REQUEST(msg, "Accept")
enum cgi_env_e
{
	SERVER_SOFTWARE,
	SERVER_NAME,
	GATEWAY_INTERFACE,
	SERVER_PROTOCOL,
	SERVER_PORT,
	REQUEST_METHOD,
	HTTP_ACCEPT,
	PATH_INFO,
	PATH_TRANSLATED,
	SCRIPT_NAME,
	QUERY_STRING,
	REMOTE_HOST,
	REMOTE_ADDR,
	REMOTE_USER,
	AUTH_TYPE,

	NBENVS,
};
const httpenv_t cgi_env[] =
{
	{
		.target = "SERVER_SOFTWARE=",
		.length = 26,
	},
	{
		.target = "SERVER_NAME=",
		.length = 26,
	},
	{
		.target = "GATEWAY_INTERFACE=",
		.length = 26,
	},
	{
		.target = "SERVER_PROTOCOL=",
		.length = 26,
	},
	{
		.target = "SERVER_PORT=",
		.length = 26,
	},
	{
		.target = "REQUEST_METHOD=",
		.length = 26,
	},
	{
		.target = "HTTP_ACCEPT=",
		.length = 26,
	},
	{
		.target = "PATH_INFO=",
		.length = 26,
	},
	{
		.target = "PATH_TRANSLATED=",
		.length = 26,
	},
	{
		.target = "SCRIPT_NAME=",
		.length = 26,
	},
	{
		.target = "QUERY_STRING=",
		.length = 26,
	},
	{
		.target = "REMOTE_HOST=",
		.length = 26,
	},
	{
		.target = "REMOTE_ADDR=",
		.length = 26,
	},
	{
		.target = "REMOTE_USER=",
		.length = 26,
	},
	{
		.target = "AUTH_TYPE=",
		.length = 26,
	}
};

static int _mod_cgi_fork(mod_cgi_ctx_t *ctx, http_message_t *request)
{
	pipe(ctx->tocgi);
	pipe(ctx->fromcgi);
	pid_t pid = fork();
	if (pid)
	{
		/* keep only input of the pipe */
		close(ctx->tocgi[0]);
		/* keep only output of the pipe */
		close(ctx->fromcgi[1]);
	}
	else /* into child */
	{
		int flags;
		flags = fcntl(ctx->tocgi[0],F_GETFD);
		fcntl(ctx->tocgi[0],F_SETFD, flags | FD_CLOEXEC);
		flags = fcntl(ctx->fromcgi[1],F_GETFD);
		fcntl(ctx->fromcgi[1],F_SETFD, flags | FD_CLOEXEC);
		/* send data from server to the stdin of the cgi */
		close(ctx->tocgi[1]);
		dup2(ctx->tocgi[0], STDIN_FILENO);
		close(ctx->tocgi[0]);
		/* send data from the stdout of the cgi to server */
		close(ctx->fromcgi[0]);
		dup2(ctx->fromcgi[1], STDOUT_FILENO);
		close(ctx->fromcgi[1]);

		int sock = httpmessage_keepalive(request);
		close(sock);

		char *argv[2];
		argv[0] = basename(ctx->cgipath);
		argv[1] = NULL;
		char *env[NBENVS];
		int i = 0;

		for (i = 0; i < NBENVS; i++)
		{
			env[i] = calloc(1, strlen(cgi_env[i].target) + cgi_env[i].length + 1);
			sprintf(env[i], "%s", cgi_env[i].target);
			char *value = NULL;
			switch (i)
			{
				case SERVER_SOFTWARE:
				case SERVER_NAME:
					value = httpmessage_SERVER(request, "name");
				break;
				case SERVER_PROTOCOL:
					value = SERVER_PROTOCOL_CB(request);
				break;
				case SERVER_PORT:
					value = SERVER_PORT_CB(request);
				break;
				case REQUEST_METHOD:
					value = REQUEST_METHOD_CB(request);
				break;
				case HTTP_ACCEPT:
					value = HTTP_ACCEPT_CB(request);
				break;
				case SCRIPT_NAME:
					value = basename(ctx->cgipath);
				break;
				case PATH_INFO:
					value = ctx->cgipath;
				break;
			}
			if (value)
				strncat(env[i], value, cgi_env[i].length);
		}
		env[i] = NULL;
		execve(ctx->cgipath, argv, env);
		exit(0);
	}
	return pid;
}

static int _cgi_connector(void *arg, http_message_t *request, http_message_t *response)
{
	mod_cgi_ctx_t *ctx = (mod_cgi_ctx_t *)arg;
	mod_cgi_config_t *config = ctx->mod->config;
	char *str = httpmessage_REQUEST(request,"uri");
	if (ctx->pid == -1)
		return EREJECT;
	if (str && ctx->cgipath == NULL)
	{
		char filepath[512];
		uri_t *uri = NULL;

		uri = uri_create(str);
		snprintf(filepath, 511, "%s/%s", config->docroot, uri_part(uri, "path"));
		uri_free(uri);
		struct stat filestat;
		int ret = stat(filepath, &filestat);
		if (S_ISDIR(filestat.st_mode))
		{
			char *ext;
			char ext_str[64];

			strncpy(ext_str, config->accepted_ext, 63);
			ext = strtok(ext_str, ",");
			while (ext != NULL)
			{
				snprintf(filepath, 511, "%s%s/index%s", config->docroot, uri_part(uri, "path"), ext);
				ret = stat(filepath, &filestat);
				if (ret == 0)
					break;
				ext = strtok(NULL, ",");
			}
		}
		if (ret != 0)
		{
			ctx->pid = -1;
			return EREJECT;
		}
		/* at least user or group may execute the CGI */
		if (filestat.st_mode & (S_IXUSR | S_IXGRP) == 0)
		{
			ctx->pid = -1;
			return EREJECT;
		}
		ctx->cgipath = calloc(1, strlen(filepath) + 1);
		strcpy(ctx->cgipath, filepath);

	}
	if (ctx->pid == 0)
		ctx->pid = _mod_cgi_fork(ctx, request);
	if (ctx->state <= STATE_INFINISH && ctx->input)
	{
		write(ctx->tocgi[1], ctx->input, ctx->inputlen);
		ctx->input = NULL;
		ctx->inputlen = 0;
		if (ctx->state <= STATE_INFINISH)
		{
			close(ctx->tocgi[1]);
			ctx->tocgi[1] = -1;
		}
		httpmessage_addcontent(response, "text/html", NULL, -1);
	}
	if (ctx->state >= STATE_INFINISH)
	{
		int ret;
		fd_set rfds;
		struct timeval timeout = { 0, 10000 };

		FD_ZERO(&rfds);
		FD_SET(ctx->fromcgi[0], &rfds);
		ret = select(ctx->fromcgi[0] + 1, &rfds, NULL, NULL, &timeout);
		if (ret > 0 && FD_ISSET(ctx->fromcgi[0], &rfds))
		{
			char data[65];
			int size = 64;
			size = read(ctx->fromcgi[0], data, size);
			if (size < 1)
				ctx->state = STATE_OUTFINISH;
			else
			{
				if (data[size - 1] == '\n' && data[size - 2] != '\r')
				{
					data[size - 1] = '\r';
					data[size] = '\n';
					size++;
				}
				if (data[0] = '\r' && data[1] == '\n')
					ctx->state = STATE_HEADERCOMPLETE;
				if (ctx->state >= STATE_HEADERCOMPLETE)
					httpmessage_addcontent(response, NULL,data, size);
				else
				{
					char *key = data;
					char *value = strchr(data, ':');
					if (value == NULL)
					{
						ctx->state = STATE_HEADERCOMPLETE;
						httpmessage_addcontent(response, NULL,data, size);
					}
					else
					{
						*value = '\0';
						value++;
						httpmessage_addheader(response, key, value);
					}
				}
			}
		}
	}

	if (ctx->state >= STATE_OUTFINISH)
	{
		int status, ret;

		ret = waitpid(ctx->pid, &status, WNOHANG);
		ctx->state = STATE_END;
		return ESUCCESS;
	}

	/* this mod returns INCOMPLETE 
	 * because it needs to wait the end 
	 * to know the length of the content */
	return EINCOMPLETE;
}
