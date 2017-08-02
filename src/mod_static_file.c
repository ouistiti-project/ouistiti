/*****************************************************************************
 * mod_static_file.c: callbacks and management of files
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

#include "httpserver/httpserver.h"
#include "httpserver/uri.h"
#include "httpserver/utils.h"
#include "mod_static_file.h"
#include "mod_dirlisting.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

/**
 * USE_PRIVATE is used to keep a sample of cade which uses
 * the httpmessage_private function
 */
typedef struct _static_file_connector_s static_file_connector_t;

int mod_send(static_file_connector_t *private, http_message_t *response);

static int static_file_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret =  EREJECT;
	static_file_connector_t *private = (static_file_connector_t *)arg;
	_mod_static_file_mod_t *mod = private->mod;
	mod_static_file_t *config = (mod_static_file_t *)mod->config;

	if (private->fd == 0)
	{
		struct stat filestat;
		if (private->path_info)
			free(private->path_info);
		private->path_info = utils_urldecode(httpmessage_REQUEST(request,"uri"));
		if (private->path_info == NULL)
			return EREJECT;
		private->filepath = utils_buildpath(config->docroot, private->path_info, "", "", &filestat);
		if (private->filepath == NULL)
		{
			dbg("static file: %s not exist", private->path_info);
			return ret;
		}
		else if (S_ISDIR(filestat.st_mode))
		{
			int length = strlen(private->filepath);
			if (private->filepath[length - 1] != '/')
			{
				free(private->filepath);
				private->filepath = NULL;
#if defined(RESULT_301)
				char *location = calloc(1, strlen(private->path_info) + 2);
				sprintf(location, "%s/", private->path_info);
				httpmessage_addheader(response, str_location, location);
				httpmessage_result(response, RESULT_301);
				free(location);
				free(private->filepath);
				private->filepath = NULL;
				free(private->path_info);
				private->path_info = NULL;
				return ESUCCESS;
#else
				free(private->filepath);
				private->filepath = NULL;
				free(private->path_info);
				private->path_info = NULL;
				dbg("static file: reject directory path bad formatting");
				return EREJECT;
#endif
			}
			char ext_str[64];
			ext_str[63] = 0;
			strncpy(ext_str, config->accepted_ext, 63);
			char *ext = ext_str;
			char *ext_end = strchr(ext, ',');
			if (ext_end)
				*ext_end = 0;

			char *dirpath = private->filepath;
			while(ext != NULL)
			{
				private->filepath = utils_buildpath(config->docroot, private->path_info, "index", ext, &filestat);
				if (private->filepath && !S_ISDIR(filestat.st_mode))
				{
					ret = ECONTINUE;
					break;
				}
				else if (ext_end)
					ext = ext_end + 1;
				else
				{
					break;
				}
				ext_end = strchr(ext, ',');
				if (ext_end)
					*ext_end = 0;
				free(private->filepath);
				private->filepath = NULL;
			}
			if (!private->filepath)
			{
				private->filepath = dirpath;
				private->type |= STATIC_FILE_DIRLISTING;
				return EREJECT;
			}
		}
		else
			ret = ECONTINUE;
		if (ret != ECONTINUE)
		{
			dbg("static file: %s not found (%s)", private->path_info, strerror(errno));
			free(private->filepath);
			private->filepath = NULL;
			free(private->path_info);
			private->path_info = NULL;
			return EREJECT;
		}
		if (utils_searchext(private->filepath, config->ignored_ext) == ESUCCESS)
		{
			warn("static file: %s forbidden extension", private->path_info);
			free(private->filepath);
			private->filepath = NULL;
			free(private->path_info);
			private->path_info = NULL;
			return  EREJECT;
		}
		private->size = filestat.st_size;
		private->offset = 0;

		/**
		 * file is found
		 * check the extension
		 */
		if (utils_searchext(private->filepath, config->accepted_ext) != ESUCCESS)
		{
			warn("static file: forbidden extension");
			free(private->filepath);
			private->filepath = NULL;
			free(private->path_info);
			private->path_info = NULL;
#if defined(RESULT_403)
			httpmessage_result(response, RESULT_403);
			return ESUCCESS;
#endif
		}
		else if (private->size == 0)
		{
			warn("static file: empty file");
#if defined(RESULT_204)
			free(private->filepath);
			private->filepath = NULL;
			free(private->path_info);
			private->path_info = NULL;
			httpmessage_result(response, RESULT_204);
			return ESUCCESS;
#endif
		}
	}
	else
	{
		warn("static_file: internal error");
	}
	/**
	 * this connector reject always
	 * another connector will continue with filepath
	 * to send the data
	 **/
	return  EREJECT;
}

static int transfer_connector(void *arg, http_message_t *request, http_message_t *response)
{
	static_file_connector_t *private = (static_file_connector_t *)arg;
	_mod_static_file_mod_t *mod = private->mod;
	mod_static_file_t *config = (mod_static_file_t *)mod->config;

	if (private->type & STATIC_FILE_DIRLISTING || private->filepath == NULL)
		return EREJECT;
	if (private->fd == 0)
	{
		private->fd = open(private->filepath, O_RDONLY);
		if (private->fd < 0)
		{
			free(private->filepath);
			private->filepath = NULL;
			free(private->path_info);
			private->path_info = NULL;
			private->fd = 0;
			return EREJECT;
		}
		else
		{
			const char *mime = NULL;
			mime = utils_getmime(private->filepath);
			lseek(private->fd, private->offset, SEEK_CUR);
			dbg("static file: send %s (%d)", private->filepath, private->size);
			httpmessage_addcontent(response, (char *)mime, NULL, private->size);
			// create a content for an empty file
			if (private->size == 0)
			{
				char empty[1] = {0};
				httpmessage_addcontent(response, NULL, empty, 1);
			}
		}
	}
	else if (private->fd)
	{
		int ret;
		ret = mod->transfer(private, response);
		if (ret < 0)
		{
			close(private->fd);
			private->fd = 0;
			return EREJECT;
		}
		private->offset += ret;
		private->size -= ret;
		if (ret == 0 || private->size <= 0)
		{
			close(private->fd);
			private->fd = 0;
			free(private->filepath);
			private->filepath = NULL;
			free(private->path_info);
			private->path_info = NULL;
			return ESUCCESS;
		}
	}
	return ECONTINUE;
}

int mod_send_read(static_file_connector_t *private, http_message_t *response)
{
	int ret, size;

	char content[CONTENTCHUNK];
	size = (private->size < CONTENTCHUNK)? private->size : CONTENTCHUNK - 1;
	ret = read(private->fd, content, size);
	if (ret > 0)
	{
		content[ret] = 0;
		httpmessage_addcontent(response, NULL, content, ret);
	}
	return ret;
}

static void *_mod_static_file_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_static_file_mod_t *mod = (_mod_static_file_mod_t *)arg;
	mod_static_file_t *config = mod->config;
	static_file_connector_t *ctx = calloc(1, sizeof(*ctx));

	ctx->mod = mod;
	ctx->ctl = ctl;

#ifdef DIRLISTING
	if (config->options & STATIC_FILE_DIRLISTING)
		httpclient_addconnector(ctl, mod->vhost, dirlisting_connector, ctx);
#endif
#ifdef SENDFILE
	if (config->options & STATIC_FILE_SENDFILE)
		mod->transfer = mod_send_sendfile;
#endif
	httpclient_addconnector(ctl, mod->vhost, transfer_connector, ctx);
#ifdef RANGEREQUEST
	httpclient_addconnector(ctl, mod->vhost, range_connector, ctx);
#endif
	httpclient_addconnector(ctl, mod->vhost, static_file_connector, ctx);

	return ctx;
}

static void _mod_static_file_freectx(void *vctx)
{
	static_file_connector_t *ctx = vctx;
	if (ctx->path_info)
		free(ctx->path_info);
	free(ctx);
}

void *mod_static_file_create(http_server_t *server, char *vhost, mod_static_file_t *config)
{
	if (!config)
	{
		err("static file: configuration empty");
		return NULL;
	}
	_mod_static_file_mod_t *mod = calloc(1, sizeof(*mod));

	mod->config = config;
	mod->vhost = vhost;
	mod->transfer = mod_send_read;
	httpserver_addmod(server, _mod_static_file_getctx, _mod_static_file_freectx, mod);

	return mod;
}

void mod_static_file_destroy(void *data)
{
	free(data);
}
