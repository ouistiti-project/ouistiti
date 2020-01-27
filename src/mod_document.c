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

int document_close(document_connector_t *private, http_message_t *request)
{
	if (private->filepath)
		free(private->filepath);
	private->filepath = NULL;
	private->fd = 0;
	private->func = NULL;
	private->dir = NULL;
	httpmessage_private(request, NULL);
	free(private);
}

static int document_checkname(document_connector_t *private, const char *uri, http_message_t *response)
{
	_mod_document_mod_t *mod = private->mod;
	mod_document_t *config = (mod_document_t *)mod->config;

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
	if (utils_searchexp(uri, config->allow, NULL) != ESUCCESS)
	{
		return  EREJECT;
	}
	return ESUCCESS;
}

static const char *_document_userroot(_mod_document_mod_t *mod,
		http_message_t *request, const char *url, const char **other)
{
	const char *docroot = NULL;
	mod_document_t *config = (mod_document_t *)mod->config;

#ifdef DOCUMENTHOME
	if (config->dochome != NULL)
	{
		docroot = config->dochome;
#ifdef AUTH
		if (url[0] == '/')
		{
			*other = auth_info(request, "user");
		}
#endif
	}
#ifdef AUTH
	if (config->options & DOCUMENT_HOME)
	{
		const char *home = auth_info(request, "home");
		if (home != NULL)
			docroot = home;
	}
#endif
#endif
	return docroot;
}

static int _document_connectordir(_mod_document_mod_t *mod, http_message_t *request, http_message_t *response, const char *docroot, const char *url)
{
	document_connector_t *private = httpmessage_private(request, NULL);
	mod_document_t *config = (mod_document_t *)mod->config;
	const char *uri = httpmessage_REQUEST(request,"uri");

	int length = strlen(uri);

#ifdef DIRLISTING
	const char *X_Requested_With = httpmessage_REQUEST(request, "X-Requested-With");
	if ((X_Requested_With && strstr(X_Requested_With, "XMLHttpRequest") != NULL) &&
		(config->options & DOCUMENT_DIRLISTING))
	{
		private->func = dirlisting_connector;
	}
	else
#endif
	{
		struct stat filestat;
		char *indexpath = utils_buildpath(docroot, "", url,
										config->defaultpage, &filestat);
		if (indexpath)
		{
			dbg("document: move to %s", indexpath);
#if defined(RESULT_301)
			int locationlength = length + strlen(config->defaultpage) + 3;
			char *location = calloc(1, locationlength);
			/**
			 * Check uri is only one character.
			 * It should be "/"
			 */
			if ((uri[0] == '/') && (uri[1] == '\0'))
				uri++;
			snprintf(location, locationlength, "%s/%s", uri, config->defaultpage);
			httpmessage_addheader(response, str_location, location);
			httpmessage_result(response, RESULT_301);
			free(indexpath);
			free(location);
			document_close(private, request);
			return ESUCCESS;
#else
			free(private->filepath);
			private->filepath = indexpath;
			dbg("document: reject directory path");
#endif
		}
		else
		{
			dbg("document: %s is directory", uri);
			document_close(private, request);
			return EREJECT;
		}
	}
	return ECONTINUE;
}

static int _document_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret =  EREJECT;
	document_connector_t *private = httpmessage_private(request, NULL);
	_mod_document_mod_t *mod = (_mod_document_mod_t *)arg;
	mod_document_t *config = (mod_document_t *)mod->config;

	if (private == 0)
	{
		private = calloc(1, sizeof(*private));
		httpmessage_private(request, private);

		private->mod = mod;
		private->ctl = httpmessage_client(request);
		private->size = 0;
		private->offset = 0;
		struct stat filestat;
		const char *uri = httpmessage_REQUEST(request,"uri");
		const char *url = uri;

		const char *docroot = NULL;
		const char *other = "";
		if (url[1] == '~')
		{
			url = uri + 2;
			docroot = _document_userroot(mod, request, url, &other);
			if (docroot == NULL)
			{
				httpmessage_result(response, RESULT_403);
				document_close(private, request);
				return  EREJECT;
			}
		}
		if (docroot == NULL)
			docroot = config->docroot;
		private->filepath = utils_buildpath(docroot, other, url, "", &filestat);
#ifdef DOCUMENTREST
		const char *method = httpmessage_REQUEST(request, "method");
		if (config->options & DOCUMENT_REST)
		{
			const char *method = httpmessage_REQUEST(request, "method");
			if ((private->filepath == NULL) && (!strcmp(method, str_put)))
			{
				private->filepath = utils_buildpath(docroot, other, url, "", NULL);
				private->func = putfile_connector;
				private->size = 0;
			}
		}
#endif
		if (private->filepath == NULL)
		{
			dbg("document: %s not exist", uri);
			document_close(private, request);
			return  EREJECT;
		}
		else if (document_checkname(private, uri, response) == EREJECT)
		{
			dbg("document: %s forbidden extension", uri);
			/**
			 * Another module may have the same docroot and
			 * accept the name of the uri.
			 * The module has not to return an error.
			 */
			document_close(private, request);
			return  EREJECT;
		}

		if (S_ISDIR(filestat.st_mode))
		{
			int ret = _document_connectordir(mod, request, response, docroot, url);
			if (ret != ECONTINUE)
				return ret;
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
		document_close(private, request);
	return EREJECT;
}

int getfile_connector(void *arg, http_message_t *request, http_message_t *response)
{
	document_connector_t *private = httpmessage_private(request, NULL);
	_mod_document_mod_t *mod = (_mod_document_mod_t *)arg;
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
		document_close(private, request);
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
			document_close(private, request);
			return ESUCCESS;
		}
		else
		{
			const char *mime = NULL;
			mime = utils_getmime(private->filepath);
			lseek(private->fd, private->offset, SEEK_SET);
			httpmessage_addcontent(response, mime, NULL, private->size);
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
			document_close(private, request);
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
			dbg("document: (%llu bytes) time %ld:%03ld", private->datasize, value.tv_sec, value.tv_nsec/1000000);
#endif
			warn("document: send %s", private->filepath);
			close(private->fd);
			document_close(private, request);
			return ESUCCESS;
		}
	}
	return ECONTINUE;
}

int mod_send_read(document_connector_t *private, http_message_t *response)
{
	int ret = 0, size, chunksize;

	char content[CONTENTCHUNK];
	/**
	 * check the size for the rnage support
	 * the size may be different of the real size file
	 */
	chunksize = (CONTENTCHUNK > private->size)?private->size:CONTENTCHUNK;
	size = read(private->fd, content, chunksize);
	if (size > 0)
	{
		ret = size;
		content[size] = 0;
		size = httpmessage_addcontent(response, NULL, content, size);
	}
	else if (ret == 0)
	{
		ret = ESUCCESS;
	}
	return ret;
}

static int _transfer_connector(void *arg, http_message_t *request, http_message_t *response)
{
	document_connector_t *private = (document_connector_t *)httpmessage_private(request, NULL);
	if (private && private->func)
		return private->func(arg, request, response);
	return EREJECT;
}

void *mod_document_create(http_server_t *server, mod_document_t *config)
{
	if (!config)
	{
		err("document: configuration empty");
		return NULL;
	}
	_mod_document_mod_t *mod = calloc(1, sizeof(*mod));

	mod->config = config;
	httpserver_addconnector(server, _document_connector, mod, CONNECTOR_DOCUMENT, str_document);
#ifdef RANGEREQUEST
	if (config->options & DOCUMENT_RANGE)
		httpserver_addconnector(server, range_connector, mod, CONNECTOR_DOCUMENT, str_document);
#endif
	httpserver_addconnector(server, _transfer_connector, mod, CONNECTOR_DOCUMENT, str_document);

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
	.create = (module_create_t)&mod_document_create,
	.destroy = &mod_document_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_document")));
#endif
