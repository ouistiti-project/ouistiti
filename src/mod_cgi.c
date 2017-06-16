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
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libgen.h>
#include <netinet/in.h>

#include "httpserver/httpserver.h"
#include "httpserver/uri.h"
#include "httpserver/utils.h"
#include "mod_cgi.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define warn(...)
#define dbg(...)
#endif

static char str_null[] = "";
static char str_gatewayinterface[] = "CGI/1.1";

typedef struct _mod_cgi_config_s _mod_cgi_config_t;
typedef struct _mod_cgi_s _mod_cgi_t;
typedef struct mod_cgi_ctx_s mod_cgi_ctx_t;

static void *_mod_cgi_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize);
static void _mod_cgi_freectx(void *vctx);
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

	char *cgipath;
	char *path_info;
	
	pid_t pid;
	int tocgi[2];
	int fromcgi[2];
};

struct _mod_cgi_s
{
	http_server_t *server;
	mod_cgi_config_t *config;
	char *vhost;
};

void *mod_cgi_create(http_server_t *server, char *vhost, mod_cgi_config_t *modconfig)
{
	_mod_cgi_t *mod;

	if (!modconfig)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = modconfig;
	mod->vhost = vhost;
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
	httpclient_addconnector(ctl, mod->vhost, _cgi_connector, ctx);

	return ctx;
}

static void _mod_cgi_freectx(void *vctx)
{
	mod_cgi_ctx_t *ctx = (mod_cgi_ctx_t *)vctx;
	if (ctx->cgipath)
		free(ctx->cgipath);
	if (ctx->path_info)
		free(ctx->path_info);
	if (ctx->fromcgi[0])
	{
		if (ctx->fromcgi[0])
			close(ctx->fromcgi[0]);
		if (ctx->tocgi[1] > 0)
			close(ctx->tocgi[1]);
	}
	free(ctx);
}

typedef char *(*httpenv_callback_t)(http_message_t request);
struct httpenv_s
{
	char *target;
	int length;
	httpenv_callback_t cb;
};
typedef struct httpenv_s httpenv_t;

enum cgi_env_e
{
	DOCUMENT_ROOT,
	SERVER_SOFTWARE,
	SERVER_NAME,
	GATEWAY_INTERFACE,
	SERVER_PROTOCOL,
	SERVER_ADDR,
	SERVER_PORT,
	REQUEST_METHOD,
	REQUEST_SCHEME,
	REQUEST_URI,
	CONTENT_LENGTH,
	CONTENT_TYPE,
	QUERY_STRING,
	HTTP_ACCEPT,
	HTTP_ACCEPT_ENCODING,
	HTTP_ACCEPT_LANGUAGE,
	PATH_INFO,
	PATH_TRANSLATED,
	SCRIPT_FILENAME,
	SCRIPT_NAME,
	REMOTE_HOST,
	REMOTE_ADDR,
	REMOTE_PORT,
	REMOTE_USER,
	AUTH_TYPE,

	NBENVS,
};
const httpenv_t cgi_env[] =
{
	{
		.target = "DOCUMENT_ROOT=",
		.length = 26,
	},
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
		.length = 10,
	},
	{
		.target = "SERVER_ADDR=",
		.length = 26,
	},
	{
		.target = "SERVER_PORT=",
		.length = 26,
	},
	{
		.target = "REQUEST_METHOD=",
		.length = 6,
	},
	{
		.target = "REQUEST_SCHEME=",
		.length = 6,
	},
	{
		.target = "REQUEST_URI=",
		.length = 512,
	},
	{
		.target = "CONTENT_LENGTH=",
		.length = 16,
	},
	{
		.target = "CONTENT_TYPE=",
		.length = 126,
	},
	{
		.target = "QUERY_STRING=",
		.length = 256,
	},
	{
		.target = "HTTP_ACCEPT=",
		.length = 256,
	},
	{
		.target = "HTTP_ACCEPT_ENCODING=",
		.length = 256,
	},
	{
		.target = "HTTP_ACCEPT_LANGUAGE=",
		.length = 256,
	},
	{
		.target = "PATH_INFO=",
		.length = 512,
	},
	{
		.target = "PATH_TRANSLATED=",
		.length = 512,
	},
	{
		.target = "SCRIPT_FILENAME=",
		.length = 512,
	},
	{
		.target = "SCRIPT_NAME=",
		.length = 64,
	},
	{
		.target = "REMOTE_HOST=",
		.length = 26,
	},
	{
		.target = "REMOTE_ADDR=",
		.length = INET6_ADDRSTRLEN,
	},
	{
		.target = "REMOTE_PORT=",
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
		char **env = NULL;

		int i = 0;
		char *uri = httpmessage_REQUEST(request, "uri");
		char *query = strchr(uri,'?');

		env = calloc(sizeof(char *), NBENVS + ctx->mod->config->nbenvs + 1);
		for (i = 0; i < NBENVS; i++)
		{
			int length = strlen(cgi_env[i].target) + cgi_env[i].length;
			env[i] = (char *)calloc(1, length + 1);
			char *value = NULL;
			switch (i)
			{
				case DOCUMENT_ROOT:
					value = ctx->mod->config->docroot;
				break;
				case GATEWAY_INTERFACE:
					value = str_gatewayinterface;
				break;
				case SERVER_SOFTWARE:
					value = httpmessage_SERVER(request, "software");
				break;
				case SERVER_NAME:
					value = httpmessage_SERVER(request, "name");
				break;
				case SERVER_PROTOCOL:
					value = httpmessage_SERVER(request, "protocol");
				break;
				case SERVER_PORT:
					value = httpmessage_SERVER(request, "port");
				break;
				case SERVER_ADDR:
					value = httpmessage_SERVER(request, "addr");
				break;
				case REQUEST_METHOD:
					value = httpmessage_REQUEST(request, "method");
				break;
				case REQUEST_SCHEME:
					value = httpmessage_REQUEST(request, "remote_port");
				break;
				case REQUEST_URI:
					value = uri;
				break;
				case CONTENT_LENGTH:
					value = httpmessage_REQUEST(request, "Content-Length");
				break;
				case CONTENT_TYPE:
					value = httpmessage_REQUEST(request, "Content-Type");
				break;
				case QUERY_STRING:
					if (query != NULL)
						value = query + 1;
				break;
				case HTTP_ACCEPT:
					value = httpmessage_REQUEST(request, "Accept");
				break;
				case HTTP_ACCEPT_ENCODING:
					value = httpmessage_REQUEST(request, "Accept-Encoding");
				break;
				case HTTP_ACCEPT_LANGUAGE:
					value = httpmessage_REQUEST(request, "Accept-Language");
				break;
				case SCRIPT_NAME:
					value = argv[0];
				break;
				case SCRIPT_FILENAME:
					value = ctx->cgipath;
				break;
				case PATH_INFO:
					value = ctx->path_info;
				break;
				case PATH_TRANSLATED:
					value = ctx->cgipath;
				break;
				case REMOTE_ADDR:
					value = httpmessage_REQUEST(request, "remote_addr");
				break;
				case REMOTE_HOST:
					value = httpmessage_REQUEST(request, "remote_host");
				break;
				case REMOTE_PORT:
					value = httpmessage_REQUEST(request, "remote_port");
				break;
				case REMOTE_USER:
					value = httpmessage_SESSION(request, "%user", NULL);
				break;
				case AUTH_TYPE:
					value = httpmessage_SESSION(request, "%authtype", NULL);
				break;
				default:
					value = str_null;
			}
			if (value == NULL)
				value = str_null;
			snprintf(env[i], length + 1, "%s%s", cgi_env[i].target, value);
		}
		for (; i < NBENVS + ctx->mod->config->nbenvs; i++)
		{
			env[i] = (char *)ctx->mod->config->env[i - NBENVS];
		}
		env[i] = NULL;

		char *dirpath;
		dirpath = dirname(ctx->cgipath);
		if (dirpath)
		{
			chdir(dirpath);
		}
		setbuf(stdout, 0);
		execve(argv[0], argv, env);
		err("cgi error: %s", strerror(errno));
		exit(0);
	}
	return pid;
}

static int _cgi_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EINCOMPLETE;
	mod_cgi_ctx_t *ctx = (mod_cgi_ctx_t *)arg;
	mod_cgi_config_t *config = ctx->mod->config;
	if (ctx->pid == -1)
	{
		warn("cgi: pid -1");
		return EREJECT;
	}

	if (ctx->pid == 0)
	{
		if (ctx->path_info)
			free(ctx->path_info);
		ctx->path_info = utils_urldecode(httpmessage_REQUEST(request,"uri"));
		char *str = ctx->path_info;
		if (str && config->docroot && ctx->cgipath == NULL)
		{
			int length = strlen(str);
			length += strlen(config->docroot) + 1;

			char *filepath;
			filepath = calloc(1, length + 1);
			snprintf(filepath, length + 1, "%s/%s", config->docroot, str);

			if (utils_searchext(filepath, config->ignored_ext) == ESUCCESS)
			{
				dbg("cgi: %s forbidden extension", ctx->path_info);
				free(filepath);
				return EREJECT;
			}
			struct stat filestat;
			int ret = stat(filepath, &filestat);
			if (ret != 0)
			{
				dbg("cgi: %s not found", ctx->path_info);
				free(filepath);
				return EREJECT;
			}
			if (S_ISDIR(filestat.st_mode))
			{
				dbg("cgi: %s is directory", ctx->path_info);
				free(filepath);
				return EREJECT;
			}
			/* at least user or group may execute the CGI */
			if ((filestat.st_mode & (S_IXUSR | S_IXGRP)) != (S_IXUSR | S_IXGRP))
			{
				httpmessage_result(response, RESULT_404);
				warn("cgi: %s access denied", ctx->path_info);
				free(filepath);
				return ESUCCESS;
			}
			if (utils_searchext(filepath, config->accepted_ext) != ESUCCESS)
			{
				warn("cgi: %s not accepted extension", ctx->path_info);
				free(filepath);
				return EREJECT;
			}
			dbg("cgi: run %s", filepath);
			ctx->cgipath = filepath;
		}
		ctx->pid = _mod_cgi_fork(ctx, request);
	}
	if (ctx->tocgi[1] > 0 && ctx->state <= STATE_INFINISH)
	{
		char *input;
		int inputlen;
		int rest;
		rest = httpmessage_content(request, &input, &inputlen);
		if (rest > 0)
		{
			write(ctx->tocgi[1], input, inputlen);
		}
		else
			ctx->state = STATE_INFINISH;
		if (ctx->state == STATE_INFINISH)
		{
			close(ctx->tocgi[1]);
			ctx->tocgi[1] = -1;
		}
	}
	if (ctx->state >= STATE_INFINISH)
	{
		int sret;
		fd_set rfds;
		struct timeval timeout = { 3,0 };

		FD_ZERO(&rfds);
		FD_SET(ctx->fromcgi[0], &rfds);
		sret = select(ctx->fromcgi[0] + 1, &rfds, NULL, NULL, &timeout);
		if (sret > 0 && FD_ISSET(ctx->fromcgi[0], &rfds))
		{
			char data[64];
			int size = 63;
			size = read(ctx->fromcgi[0], data, size);
			if (size < 1)
			{
				ctx->state = STATE_OUTFINISH;
			}
			else
			{
				data[size] = 0;
				/**
				 * if content_length is not null, parcgi is able to
				 * create the content.
				 * But the cgi know the length at the end, is too late
				 * to set the header. And the parsecgi is ended just
				 * after the header.
				 */
				ret = httpmessage_parsecgi(response, data, &size);
				//dbg("cgi data %d\n%s#\n", size, data);
				if (ret != EINCOMPLETE)
				{
					char *offset = data;
					if (ctx->state < STATE_HEADERCOMPLETE)
					{
						httpmessage_addcontent(response, NULL, NULL, -1);
						if (*offset == 0)
						{
							size = 0;
						}
					}
					ctx->state = STATE_HEADERCOMPLETE;
					if (size > 0)
					{
						httpmessage_addcontent(response, NULL, offset, size);
					}
					ret = ECONTINUE;
				}
			}
		}
		else
			ctx->state = STATE_OUTFINISH;
	}

	if (ctx->state >= STATE_OUTFINISH)
	{
		int status, ret;
		/**
		 * RFC 3875 : 6.2.3
		 */
		char *location = httpmessage_REQUEST(response, str_location);
		if (location != NULL && location[0] != '\0')
			httpmessage_result(response, RESULT_302);
		ret = waitpid(ctx->pid, &status, WNOHANG);
		ctx->state = STATE_END;
		ctx->pid = 0;
		return ESUCCESS;
	}

	/* this mod returns EINCOMPLETE 
	 * because it needs to wait the end 
	 * to know the length of the content */
	return ret;
}
