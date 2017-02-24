/*****************************************************************************
 * mod_static_file.c: callbacks and management of files
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

#include "httpserver.h"
#include "uri.h"
#include "mod_static_file.h"

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

struct _mod_static_file_mod_s
{
	mod_static_file_t *config;
	mod_transfert_t transfert;
};

int mod_send(static_file_connector_t *private, http_message_t *response);

static mod_static_file_t default_config = 
{
	.docroot = "/srv/www/htdocs",
	.accepted_ext = ".html,.xhtml,.htm,.css",
	.ignored_ext = ".php",
};
#define CONNECTOR_TYPE 0xAABBCCDD

typedef enum
{
	MIME_TEXTPLAIN,
	MIME_TEXTHTML,
	MIME_TEXTCSS,
	MIME_APPLICATIONJAVASCRIPT,
	MIME_IMAGEPNG,
	MIME_IMAGEJPEG,
	MIME_APPLICATIONOCTETSTREAM,
} _mimetype_enum;
static const char *_mimetype[] =
{
	"text/plain",
	"text/html",
	"text/css",
	"application/javascript",
	"image/png",
	"image/jpeg",
	"application/octet-stream",
};

typedef struct mime_entry_s
{
	char *ext;
	_mimetype_enum type;
} mime_entry_t;

static const mime_entry_t *mime_entry[] =
{ 
	&(mime_entry_t){
		.ext = ".html,.xhtml,.htm",
		.type = MIME_TEXTHTML,
	},
	&(mime_entry_t){
		.ext = ".css",
		.type = MIME_TEXTCSS,
	},
	&(mime_entry_t){
		.ext = ".js",
		.type = MIME_APPLICATIONJAVASCRIPT,
	},
	&(mime_entry_t){
		.ext = ".text",
		.type = MIME_TEXTPLAIN,
	},
	&(mime_entry_t){
		.ext = ".png",
		.type = MIME_IMAGEPNG,
	},
	&(mime_entry_t){
		.ext = ".jpg",
		.type = MIME_IMAGEJPEG,
	},
	&(mime_entry_t){
		.ext = "*",
		.type = MIME_APPLICATIONOCTETSTREAM,
	},
	NULL
};

static int searchext(char *filepath, char *extlist)
{
	int ret = EREJECT;
	char *fileext = strrchr(filepath,'.');
	char ext_str[64];
	ext_str[63] = 0;
	if (fileext != NULL)
	{
		strncpy(ext_str, extlist, 63);
		char *ext = ext_str;
		char *ext_end = strchr(ext, ',');
		if (ext_end)
			*ext_end = 0;
		while (ext != NULL)
		{
			if (!strcmp(ext, fileext) || !strcmp(ext, "*"))
			{
				ret = ESUCCESS;
				break;
			}
			if (ext_end)
				ext = ext_end + 1;
			else
				break;
			ext_end = strchr(ext, ',');
			if (ext_end)
				*ext_end = 0;
		}
	}
	return ret;
}

static int static_file_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret;
#ifdef USE_PRIVATE
	_mod_static_file_mod_t *mod = (_mod_static_file_mod_t *)arg;
	mod_static_file_t *config = mod->config;
	static_file_connector_t *private = httpmessage_private(request, NULL);
	private->mod = mod;

	do
	{
		if (!private)
		{
			private = calloc(1, sizeof(*private));
			private->type = CONNECTOR_TYPE;
		}
		else if (private->type != CONNECTOR_TYPE)
		{
			if (private->previous)
			{
				private = private->previous;
				continue;
			}
			private->previous = calloc(1, sizeof(*private));
			private->type = CONNECTOR_TYPE;
			private = private->previous;
		}
	} while(0);
#else
	static_file_connector_t *private = (static_file_connector_t *)arg;
	_mod_static_file_mod_t *mod = private->mod;
	mod_static_file_t *config = (mod_static_file_t *)mod->config;
#endif

	if (private->fd == -1)
	{
		warn("static file: -1");
		return EREJECT;
	}

	if (private->fd == 0)
	{
		char *str = httpmessage_REQUEST(request,"uri");

		if (str == NULL)
		{
			warn("static file: uri == NULL");
			return EREJECT;
		}

		int length = 0;
		char *query = strchr(str, '?');
		if (query)
			length = query - str;
		else
			length = strlen(str);
		length += strlen(config->docroot) + 1; /* for the '/' separator */

		char *filepath;
		filepath = calloc(1, length + 1);
		snprintf(filepath, length + 1, "%s/%s", config->docroot, str);
		filepath[length] = '\0';
		if (searchext(filepath,config->ignored_ext) == ESUCCESS)
		{
			warn("static file: forbidden extension");
			free(filepath);
#ifdef USE_PRIVATE
			free(private);
#endif
			return EREJECT;
		}
		struct stat filestat;
		memset(&filestat, 0, sizeof(filestat));
		int ret = stat(filepath, &filestat);
		if (S_ISDIR(filestat.st_mode))
		{
#ifndef HTTP_STATUS_PARTIAL
			if (filepath[length - 1] != '/')
			{
				httpmessage_result(response, RESULT_301);
				free(filepath);
#ifdef USE_PRIVATE
				free(private);
#endif
				return ESUCCESS;
			}
#endif
			char ext_str[64];
			ext_str[63] = 0;
			strncpy(ext_str, config->accepted_ext, 63);
			char *ext = ext_str;
			char *ext_end = strchr(ext, ',');
			if (ext_end)
				*ext_end = 0;
			
			while(ext != NULL)
			{
				int extlength = strlen(ext);
				extlength += sizeof("index");
				char *tempopath = calloc(1, length + extlength + 1);
				snprintf(tempopath, length + extlength, "%sindex%s", filepath, ext);
				ret = stat(tempopath, &filestat);
				if (ret == 0)
				{
					free(filepath);
					filepath = tempopath;
					break;
				}
				if (ext_end)
					ext = ext_end + 1;
				else
					break;
				ext_end = strchr(ext, ',');
				if (ext_end)
					*ext_end = 0;
				free(tempopath);
			}
		}
		/**
		 * file is found
		 * check the extension
		 */
		mime_entry_t *mime = (mime_entry_t *)mime_entry[0];
		if (ret == 0)
		{
			if (searchext(filepath,config->accepted_ext) == ESUCCESS)
			{
				char *fileext = strrchr(filepath,'.');
				while (mime)
				{
					if (searchext(fileext,mime->ext) == ESUCCESS)
					{
						break;
					}
					mime++;
				}
			}
			else
				ret = -1;
		}
		if (ret != 0)
		{
			warn("static file: %s not found %s", filepath, strerror(errno));
			free(filepath);
#ifdef USE_PRIVATE
			free(private);
#endif
			return EREJECT;
		}
		private->fd = open(filepath, O_RDONLY);
		private->offset = 0;
		if (private->fd > 0)
			dbg("static file: send %s (%d)", filepath, filestat.st_size);
		httpmessage_private(request, (void *)private);
		private->size = filestat.st_size;
		if (mime)
			httpmessage_addcontent(response, (char *)_mimetype[mime->type], NULL, private->size);
		else
			httpmessage_addcontent(response, "", NULL, private->size);
		free(filepath);
		return ECONTINUE;
	}
	ret = mod->transfert(private, response);
	//ret = mod_send(private, response);
	if (ret < 1)
	{
		close(private->fd);
		private->fd = 0;
#ifdef USE_PRIVATE
		free(private);
#endif
		if (ret == 0)
			return ESUCCESS;
		else
			return EREJECT;
	}
	else
		private->offset += ret;
	return ECONTINUE;
}

int mod_send_read(static_file_connector_t *private, http_message_t *response)
{
	int ret, size;

	char content[CONTENTCHUNK];
	size = sizeof(content) - 1;
	ret = read(private->fd, content, size);
	if (ret > 0)
	{
		content[size] = 0;
		httpmessage_addcontent(response, NULL, content, ret);
	}
	return ret;
}

//int mod_send(static_file_connector_t *private, http_message_t *response) __attribute__ ((weak, alias ("mod_send_read")));

#ifndef USE_PRIVATE
static void *_mod_static_file_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_static_file_mod_t *mod = (_mod_static_file_mod_t *)arg;
	mod_static_file_t *config = mod->config;
	static_file_connector_t *ctx = calloc(1, sizeof(*ctx));

	ctx->mod = mod;
	httpclient_addconnector(ctl, NULL, static_file_connector, ctx);

	return ctx;
}

static void _mod_static_file_freectx(void *vctx)
{
	free(vctx);
}
#endif

void *mod_static_file_create(http_server_t *server, mod_static_file_t *config)
{
	_mod_static_file_mod_t *mod = calloc(1, sizeof(*mod));

	if (!config)
		config = &default_config;
	if (!config->docroot)
		config->docroot = default_config.docroot;
	if (!config->accepted_ext)
		config->accepted_ext = default_config.accepted_ext;
	if (!config->ignored_ext)
		config->ignored_ext = default_config.ignored_ext;
	mod->config = config;
	mod->transfert = mod_send_read;
#ifdef USE_PRIVATE
	httpserver_addconnector(server, NULL, static_file_connector, mod);
#else
	httpserver_addmod(server, _mod_static_file_getctx, _mod_static_file_freectx, mod);
#endif

	int length;
	char *ext = config->transferttype;
	while (ext != NULL)
	{
		length = strlen(ext);
		char *ext_end = strchr(ext, ',');
		if (ext_end)
			length -= strlen(ext_end + 1);
#ifdef SENDFILE
		if (!strncmp(ext, "sendfile", length))
		{
			mod->transfert = mod_send_sendfile;
			break;
		}
#endif
		ext = ext_end;
	}
	return mod;
}

void mod_static_file_destroy(void *data)
{
	free(data);
}
