/*****************************************************************************
 * mod_document.c: callbacks and management of files
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>

#include "httpserver/httpserver.h"
#include "httpserver/uri.h"
#include "httpserver/utils.h"
#include "mod_document.h"
#include "mod_auth.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

/**
 * transfer function for getfile_connector
 */
int mod_send_read(document_connector_t *private, http_message_t *response);
#ifdef SENDFILE
extern int mod_send_sendfile(document_connector_t *private, http_message_t *response);
#endif

static const char str_put[] = "PUT";
static const char str_delete[] = "DELETE";

static const char str_document[] = "document";

/**
 * USE_PRIVATE is used to keep a sample of cade which uses
 * the httpmessage_private function
 */
typedef struct _document_connector_s document_connector_t;

int mod_send(document_connector_t *private, http_message_t *response);

int document_close(document_connector_t *private)
{
	if (private->filepath)
		free(private->filepath);
	private->filepath = NULL;
	if (private->path_info)
		free(private->path_info);
	private->path_info = NULL;
	private->fd = 0;
	private->func = NULL;
	private->dir = NULL;
}

static int document_checkname(document_connector_t *private, http_message_t *response)
{
	_mod_document_mod_t *mod = private->mod;
	mod_document_t *config = (mod_document_t *)mod->config;
	if (private->path_info[0] == '.')
	{
		return  EREJECT;
	}
	if (utils_searchexp(private->path_info, config->deny) == ESUCCESS ||
		utils_searchexp(private->path_info, config->allow) != ESUCCESS)
	{
		return  EREJECT;
	}
	return ESUCCESS;
}

static int document_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret =  EREJECT;
	document_connector_t *private = (document_connector_t *)arg;
	_mod_document_mod_t *mod = private->mod;
	mod_document_t *config = (mod_document_t *)mod->config;
	if (private->fd == 0)
	{
		private->size = 0;
		private->offset = 0;
		struct stat filestat;
		if (private->path_info)
			free(private->path_info);
		const char *uri = httpmessage_REQUEST(request,"uri");
		private->path_info = utils_urldecode(uri);

		if (private->path_info == NULL)
			return EREJECT;

		const char *docroot = config->docroot;
#ifdef DOCUMENTHOME
		if (config->options & DOCUMENT_HOME)
		{
			const char *home = auth_info(request, "home");
			if (home != NULL)
				docroot = home;
		}
#endif
		private->filepath = utils_buildpath(docroot, private->path_info, "", "", &filestat);
#ifdef DOCUMENTREST
		const char *method = httpmessage_REQUEST(request, "method");
		if (config->options & DOCUMENT_REST)
		{
			const char *method = httpmessage_REQUEST(request, "method");
			if ((private->filepath == NULL) && (!strcmp(method, str_put)))
			{
				private->filepath = utils_buildpath(docroot, private->path_info, "", "", NULL);
				private->func = putfile_connector;
				private->size = 0;
			}
		}
#endif
		if (private->filepath == NULL)
		{
			dbg("document: %s not exist", private->path_info);
			document_close(private);
			return  EREJECT;
		}
		else if (document_checkname(private, response) == EREJECT)
		{
			warn("document: forbidden %s file %s", private->path_info, (ret == 0)?"deny":"not allow");
			httpmessage_result(response, RESULT_403);
			document_close(private);
			return  EREJECT;
		}

		if (S_ISDIR(filestat.st_mode))
		{
			int length = strlen(private->path_info);
			const char *X_Requested_With = httpmessage_REQUEST(request, "X-Requested-With");
#if defined(RESULT_301)
			if (length > 0 && private->path_info[length - 1] != '/')
			{
				char *location = calloc(1, length + 3);
				sprintf(location, "/%s/", private->path_info);
				httpmessage_addheader(response, str_location, location);
				httpmessage_result(response, RESULT_301);
				free(location);
				document_close(private);
				return ESUCCESS;
			}
			else
#endif
			{
				char *indexpath = utils_buildpath(config->docroot, private->path_info,
												config->defaultpage, "", &filestat);
				dbg("document: move to %s", indexpath);
#ifdef DIRLISTING
				if ((X_Requested_With && strstr(X_Requested_With, "XMLHttpRequest") != NULL) ||
					(indexpath == NULL && ((config->options & DOCUMENT_DIRLISTING) ||
						(length > 0 && private->path_info[length - 1] != '/'))))
				{
					private->func = dirlisting_connector;
					if (indexpath)
						free(indexpath);
				}
				else
#endif
				if (indexpath)
				{
#if defined(RESULT_301)
					char *location = calloc(1, length + strlen(config->defaultpage) + 2);
					sprintf(location, "/%s%s", private->path_info, config->defaultpage);
					httpmessage_addheader(response, str_location, location);
					httpmessage_result(response, RESULT_301);
					free(indexpath);
					document_close(private);
					return ESUCCESS;
#else
					free(private->filepath);
					private->filepath = indexpath;
					dbg("document: reject directory path");
#endif
				}
				else
				{
					dbg("document: %s is directory", private->path_info);
					document_close(private);
					return EREJECT;
				}
			}
		}
		if (private->func == NULL)
		{
			private->func = getfile_connector;
			private->size = filestat.st_size;
		}
		private->offset = 0;

#ifdef DOCUMENTREST
		if (config->options & DOCUMENT_REST)
		{
			if (!strcmp(method, str_put))
				private->func = putfile_connector;
			else if (!strcmp(method, "POST"))
				private->func = postfile_connector;
			else if (!strcmp(method, str_delete))
				private->func = deletefile_connector;
		}
#endif
	}
	if (private->func == NULL)
		document_close(private);
	return EREJECT;
}

int getfile_connector(void *arg, http_message_t *request, http_message_t *response)
{
	document_connector_t *private = (document_connector_t *)arg;
	_mod_document_mod_t *mod = private->mod;
	mod_document_t *config = (mod_document_t *)mod->config;

	if (private->type & DOCUMENT_DIRLISTING || private->filepath == NULL)
		return EREJECT;
	else if (private->size == 0)
	{
		dbg("document: empty file");
#if defined(RESULT_204)
		httpmessage_result(response, RESULT_204);
#else
		const char *mime = NULL;
		mime = utils_getmime(private->filepath);
		httpmessage_addcontent(response, (char *)mime, NULL, private->size);
#endif
		if (private->fd > 0)
			close(private->fd);
		document_close(private);
		return ESUCCESS;
	}
	if (private->fd == 0)
	{
		private->fd = open(private->filepath, O_RDONLY);
		if (private->fd < 0)
		{
#ifdef RESULT_500
			if (errno == ENFILE || errno == EMFILE)
				httpmessage_result(response, RESULT_500);
			else
#endif
#ifdef RESULT_403
				httpmessage_result(response, RESULT_403);
#else
				httpmessage_result(response, RESULT_400);
#endif
			err("document open %s %s", private->filepath, strerror(errno));
			document_close(private);
			return ESUCCESS;
		}
		else
		{
			const char *mime = NULL;
			mime = utils_getmime(private->filepath);
			lseek(private->fd, private->offset, SEEK_SET);
			httpmessage_addcontent(response, (char *)mime, NULL, private->size);
			if (!strcmp(httpmessage_REQUEST(request, "method"), "HEAD"))
			{
				close(private->fd);
				private->fd = 0;
				document_close(private);
				return ESUCCESS;
			}
			dbg("document: send %llu bytes", private->size);
			mod->transfer = mod_send_read;
#ifdef DEBUG
			clock_gettime(CLOCK_REALTIME, &private->start);
			private->datasize = private->size;
#endif
#ifdef SENDFILE
			if (config->options & DOCUMENT_SENDFILE)
				mod->transfer = mod_send_sendfile;
#endif
		}
	}
	else if (private->fd)
	{
		int ret;
		ret = mod->transfer(private, response);
		if (ret < 0)
		{
			if (errno == EAGAIN)
				return EINCOMPLETE;
			err("document: send %s (%d,%s)", private->filepath, ret, strerror(errno));
			close(private->fd);
			document_close(private);
			/**
			 * it is too late to set an error here
			 */
			return EREJECT;
		}
		private->offset += ret;
		private->size -= ret;
		if (ret == 0 || private->size <= 0)
		{
#ifdef DEBUG
			struct timespec stop;
			struct timespec value;
			clock_gettime(CLOCK_REALTIME, &stop);

			value.tv_sec = stop.tv_sec - private->start.tv_sec;
			value.tv_nsec = stop.tv_nsec - private->start.tv_nsec;
			dbg("document: (%llu bytes) %d:%3d", private->datasize, value.tv_sec, value.tv_nsec/1000000);
#endif
			dbg("document: send %s", private->filepath);
			close(private->fd);
			document_close(private);
			return ESUCCESS;
		}
	}
	return ECONTINUE;
}

int mod_send_read(document_connector_t *private, http_message_t *response)
{
	int ret = 0, size, chunksize;

	char content[CONTENTCHUNK];
	do
	{
		chunksize = ((private->size - ret) < CONTENTCHUNK)? (private->size - ret) : CONTENTCHUNK - 1;
		size = read(private->fd, content, chunksize);
		if (size > 0)
		{
			ret += size;
			content[size] = 0;
			size = httpmessage_appendcontent(response, content, size);
			if ((private->size - ret) == 0)
				break;
		}
		else
		{
			if (ret == 0)
				ret = -1;
			break;
		}
	} while (chunksize < size);
	return ret;
}

static int transfer_connector(void *arg, http_message_t *request, http_message_t *response)
{
	document_connector_t *private = (document_connector_t *)arg;
	if (private->func)
		return private->func(arg, request, response);
	return EREJECT;
}

static void *_mod_document_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_document_mod_t *mod = (_mod_document_mod_t *)arg;
	mod_document_t *config = mod->config;
	document_connector_t *ctx = calloc(1, sizeof(*ctx));

	ctx->mod = mod;
	ctx->ctl = ctl;

	httpclient_addconnector(ctl, mod->vhost, transfer_connector, ctx, str_document);
#ifdef RANGEREQUEST
	if (config->options & DOCUMENT_RANGE)
		httpclient_addconnector(ctl, mod->vhost, range_connector, ctx, str_document);
#endif
	httpclient_addconnector(ctl, mod->vhost, document_connector, ctx, str_document);

	return ctx;
}

static void _mod_document_freectx(void *vctx)
{
	document_connector_t *ctx = vctx;
	if (ctx->path_info)
		free(ctx->path_info);
	free(ctx);
}

void *mod_document_create(http_server_t *server, char *vhost, mod_document_t *config)
{
	if (!config)
	{
		err("document: configuration empty");
		return NULL;
	}
	_mod_document_mod_t *mod = calloc(1, sizeof(*mod));

	mod->config = config;
	mod->vhost = vhost;
	httpserver_addmod(server, _mod_document_getctx, _mod_document_freectx, mod, str_document);
#ifdef DOCUMENTREST
	if (config->options & DOCUMENT_REST)
	{
		httpserver_addmethod(server, str_put, 1);
		httpserver_addmethod(server, str_delete, 1);
	}
#endif
	return mod;
}

void mod_document_destroy(void *data)
{
	free(data);
}

const module_t mod_document =
{
	.name = str_document,
	.create = (module_create_t)mod_document_create,
	.destroy = mod_document_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_document")));
#endif
