/*****************************************************************************
 * mod_cgi.c: callbacks and management of connection
 * this file is part of https://github.com/ouistiti-project/ouistiti
 *
 * follow RFC3875 : https://tools.ietf.org/html/rfc3875
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <libgen.h>
#include <netinet/in.h>
#include <sched.h>

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

#define cgi_dbg(...)

static const char str_cgi[] = "cgi";

typedef struct _mod_cgi_config_s _mod_cgi_config_t;
typedef struct _mod_cgi_s _mod_cgi_t;
typedef struct mod_cgi_ctx_s mod_cgi_ctx_t;

static int _cgi_connector(void *arg, http_message_t *request, http_message_t *response);

struct mod_cgi_ctx_s
{
	enum
	{
		STATE_SETUP,
		STATE_START,
		STATE_INFINISH,
		STATE_HEADERCOMPLETE,
		STATE_CONTENTCOMPLETE,
		STATE_OUTFINISH,
		STATE_END,
		STATE_MASK = 0x00FF,
		STATE_SHUTDOWN = 0x0100,
	} state;
	_mod_cgi_t *mod;
	http_client_t *ctl;

	char cgipath[256];
	const char *path_info;

	pid_t pid;
	int tocgi[2];
	int fromcgi[2];

	char *chunk;
};

struct _mod_cgi_s
{
	http_server_t *server;
	mod_cgi_config_t *config;
	int rootfd;
};

void *mod_cgi_create(http_server_t *server, mod_cgi_config_t *modconfig)
{
	_mod_cgi_t *mod;

	if (!modconfig)
		return NULL;

	int rootfd = open(modconfig->docroot, O_PATH | O_DIRECTORY);
	if (rootfd == -1)
	{
		err("cgi: %s access denied", modconfig->docroot);
		return NULL;
	}

	mod = calloc(1, sizeof(*mod));
	mod->rootfd = rootfd;
	mod->config = modconfig;
	mod->server = server;
	if (modconfig->timeout == 0)
		modconfig->timeout = 3;

	httpserver_addconnector(server, _cgi_connector, mod, CONNECTOR_DOCUMENT, str_cgi);

	return mod;
}

void mod_cgi_destroy(void *arg)
{
	_mod_cgi_t *mod = (_mod_cgi_t *)arg;
	// nothing to do
	close(mod->rootfd);
}

static void _cgi_freectx(mod_cgi_ctx_t *ctx)
{
	if (ctx->chunk)
		free(ctx->chunk);
	if (ctx->fromcgi[0])
		close(ctx->fromcgi[0]);
	if (ctx->tocgi[1] > 0)
		close(ctx->tocgi[1]);
	free(ctx);
}

static int _mod_cgi_fork(mod_cgi_ctx_t *ctx, http_message_t *request)
{
	_mod_cgi_t *mod = ctx->mod;
	mod_cgi_config_t *config = mod->config;

	if (pipe(ctx->tocgi) < 0)
		return EREJECT;
	if (pipe(ctx->fromcgi))
		return EREJECT;
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

		char * const argv[2] = { (char *)ctx->cgipath, NULL };

		char **env = NULL;
		env = cgi_buildenv(config, request, ctx->cgipath, ctx->path_info);

		close(sock);

		setbuf(stdout, 0);
		sched_yield();
		/**
		 * cgipath is absolute, but in fact execveat runs in docroot.
		 */
#ifdef USE_EXECVEAT
		execveat(mod->rootfd, ctx->cgipath, argv, env);
#else
		int scriptfd = openat(mod->rootfd, ctx->cgipath, __O_PATH);
		close(mod->rootfd);
		fexecve(scriptfd, argv, env);
#endif
		err("cgi error: %s", strerror(errno));
		exit(0);
	}
	return pid;
}

static int _cgi_checkname(const char *uri, mod_cgi_config_t *config, const char **path_info)
{
	if (uri[0] == '/')
		uri++;
	if (uri[0] == '.' && uri[1] != '/')
	{
		return  EREJECT;
	}
	if (utils_searchexp(uri, config->deny, NULL) == ESUCCESS)
	{
		return  EREJECT;
	}
	if (utils_searchexp(uri, config->allow, path_info) != ESUCCESS)
	{
		return  EREJECT;
	}
	return ESUCCESS;
}

static int _cgi_start(_mod_cgi_t *mod, http_message_t *request, http_message_t *response)
{
	mod_cgi_config_t *config = mod->config;
	int ret = EREJECT;
	const char *url = httpmessage_REQUEST(request,"uri");
	if (url && config->docroot)
	{
		const char *path_info = NULL;
		if (_cgi_checkname(url, config, &path_info) != ESUCCESS)
		{
			dbg("cgi: %s forbidden extension", url);
			return EREJECT;
		}

		char cgipath[256];
		int length = 256;
		if (path_info != NULL && (path_info - url) < length)
		{
			length = path_info - url;
		}
		strncpy(cgipath, url + 1, length - 1);
		warn("cgi: %s search %d", cgipath, mod->rootfd);
		int scriptfd = openat(mod->rootfd, cgipath, O_PATH);
		if (scriptfd < 0)
		{
			warn("cgi: %s not found", cgipath);
			warn("cgi: %s", strerror(errno));
			return EREJECT;
		}

		struct stat filestat = {0};
		fstat(scriptfd, &filestat);

		if (S_ISDIR(filestat.st_mode))
		{
			dbg("cgi: %s is directory", url);
			close(scriptfd);
			return EREJECT;
		}
		/* at least user or group may execute the CGI */
		if ((filestat.st_mode & (S_IXUSR | S_IXGRP)) != (S_IXUSR | S_IXGRP))
		{
			httpmessage_result(response, RESULT_403);
			warn("cgi: %s access denied", cgipath);
			warn("cgi: %s", strerror(errno));
			close(scriptfd);
			return ESUCCESS;
		}

		mod_cgi_ctx_t *ctx;
		dbg("cgi: run %s", url);
		ctx = calloc(1, sizeof(*ctx));
		strncpy(ctx->cgipath, cgipath, length);
		ctx->mod = mod;
		ctx->path_info = path_info;
		ctx->pid = _mod_cgi_fork(ctx, request);
		ctx->state = STATE_START;
		if (config->chunksize == 0)
			config->chunksize = 64;
		ctx->chunk = malloc(config->chunksize + 1);
		httpmessage_private(request, ctx);
		ret = EINCOMPLETE;
	}
	return ret;
}

static int _cgi_request(mod_cgi_ctx_t *ctx, http_message_t *request)
{
	_mod_cgi_t *mod = ctx->mod;
	mod_cgi_config_t *config = mod->config;
	int ret = ECONTINUE;
	char *input;
	int inputlen;
	unsigned long long rest;

	inputlen = httpmessage_content(request, &input, &rest);
	if (inputlen > 0)
	{
		int len;
#ifdef DEBUG
		static int length = 0;
		length += inputlen;
		cgi_dbg("cgi: %d input %s", length,input);
#endif
		len = write(ctx->tocgi[1], input, inputlen);
		if (inputlen != len)
			ret = EREJECT;
	}
	else if (rest != EINCOMPLETE)
		ctx->state = STATE_INFINISH;
	if (ctx->state == STATE_INFINISH)
	{
		close(ctx->tocgi[1]);
		ctx->tocgi[1] = -1;
	}
	return ret;
}

static int _cgi_response(mod_cgi_ctx_t *ctx, http_message_t *response)
{
	_mod_cgi_t *mod = ctx->mod;
	mod_cgi_config_t *config = mod->config;
	int ret = ECONTINUE;
	int sret;
	fd_set rfds;
	struct timeval timeout = { config->timeout,0 };

	FD_ZERO(&rfds);
	FD_SET(ctx->fromcgi[0], &rfds);
	sret = select(ctx->fromcgi[0] + 1, &rfds, NULL, NULL, &timeout);
	if (sret > 0 && FD_ISSET(ctx->fromcgi[0], &rfds))
	{
		int size = config->chunksize;
		size = read(ctx->fromcgi[0], ctx->chunk, size);
		if (size < 1)
		{
			ctx->state = STATE_CONTENTCOMPLETE;
			ret = ECONTINUE;
			if (size < 0)
			{
				err("cgi read %s", strerror(errno));
			}
		}
		else
		{
			ctx->chunk[size] = 0;
			cgi_dbg("cgi: receive (%d)\n%s", size, ctx->chunk);
			/**
			 * if content_length is not null, parcgi is able to
			 * create the content.
			 * But the cgi know the length at the end, is too late
			 * to set the header.
			 */
			int rest = size;
			if (rest > 0)
			{
				ret = httpmessage_parsecgi(response, ctx->chunk, &rest);
				cgi_dbg("cgi: parse %d data %d %d\n%s#", ret, size, rest, ctx->chunk);
				if (ret == ECONTINUE && ctx->state < STATE_HEADERCOMPLETE)
				{
#if defined(RESULT_302)
					/**
					 * RFC 3875 : 6.2.3
					 */
					const char *location = httpmessage_REQUEST(response, str_location);
					if (location != NULL && location[0] != '\0')
						httpmessage_result(response, RESULT_302);
#endif
					ctx->state = STATE_HEADERCOMPLETE;
				}
				if (ret == ESUCCESS)
				{
					ctx->state = STATE_CONTENTCOMPLETE;
					//parse_cgi is complete but not this module
				}
			}
		}
		/**
		 * the request is completed to not wait more data the module
		 * must returns ECONTINUE or ESUCCESS now
		 */
		ret = ECONTINUE;
	}
	else
	{
		ctx->state = STATE_OUTFINISH | STATE_SHUTDOWN;
		kill(ctx->pid, SIGTERM);
		dbg("cgi complete");
		ret = ECONTINUE;
	}
	return ret;
}
static int _cgi_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EINCOMPLETE;
	mod_cgi_ctx_t *ctx = httpmessage_private(request, NULL);
	_mod_cgi_t *mod = (_mod_cgi_t *)arg;
	mod_cgi_config_t *config = mod->config;

	if (ctx == NULL)
	{
		ret = _cgi_start(mod, request, response);
		return ret;
	}
	else if (ctx->tocgi[1] > 0 && ctx->state == STATE_START)
	{
		_cgi_request(ctx, request);
	}
	/**
	 * when the request is complete the module must check the CGI immedialty
	 * otherwise the client will wait more data from request
	 */
	if ((ctx->state & STATE_MASK) >= STATE_INFINISH && (ctx->state & STATE_MASK) < STATE_CONTENTCOMPLETE)
	{
		ret = _cgi_response(ctx, response);
	}
	else if ((ctx->state & STATE_MASK) == STATE_CONTENTCOMPLETE)
	{
		close(ctx->fromcgi[0]);
		httpmessage_parsecgi(response, NULL, 0);
		ret = ECONTINUE;
		ctx->state = STATE_OUTFINISH | STATE_SHUTDOWN;
	}
	else if ((ctx->state & STATE_MASK) == STATE_OUTFINISH)
	{
		long long length;
		ret = httpmessage_content(response, NULL, &length);
		cgi_dbg("content len %d %lld", ret, length);
		if (ret == 0)
			ctx->state = STATE_END | STATE_SHUTDOWN;
		ret = ECONTINUE;
	}
	else if ((ctx->state & STATE_MASK) == STATE_END)
	{
		_cgi_freectx(ctx);
		httpmessage_private(request, NULL);
		ret = ESUCCESS;
	}
	/* this mod returns EINCOMPLETE
	 * because it needs to wait the end
	 * to know the length of the content */
	return ret;
}

const module_t mod_cgi =
{
	.name = str_cgi,
	.create = (module_create_t)&mod_cgi_create,
	.destroy = &mod_cgi_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_cgi")));
#endif
