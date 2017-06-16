/*****************************************************************************
 * mod_dirlisting.c: callbacks and management of directories
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
#include <dirent.h>

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

typedef struct _static_file_connector_s static_file_connector_t;

struct _mod_static_file_mod_s
{
	mod_static_file_t *config;
	void *vhost;
	mod_transfer_t transfer;
};

#define DIRLISTING_HEADER "<html><head><link rel=\"stylesheet\" type=\"text/css\" href=\"%s\"/></head><body><h1>%s</h1><ul>\n"
#define DIRLISTING_HEADER_LENGTH (sizeof(DIRLISTING_HEADER) - 4)
#define DIRLISTING_LINE_FILE "<li id=\"file\"><a href=\"%s%s\">%s</a><span id=\"size\">%d</span></li>\n"
#define DIRLISTING_LINE_FILE_LENGTH (sizeof(DIRLISTING_LINE_FILE) - 8)
#define DIRLISTING_LINE_DIR "<li id=\"dir\"><a href=\"%s%s\">%s</a></li>\n"
#define DIRLISTING_LINE_DIR_LENGTH (sizeof(DIRLISTING_LINE_DIR) - 6)
#define DIRLISTING_FOOTER "</ul></body></html>"
typedef struct line_s
{
	int length;
	char *line;
} line_t;
static line_t *dirlisting_lines[] =
{
	&(line_t){
		DIRLISTING_LINE_DIR_LENGTH,
		DIRLISTING_LINE_DIR,
	},
	&(line_t){
		DIRLISTING_LINE_FILE_LENGTH,
		DIRLISTING_LINE_FILE,
	},
};

int dirlisting_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	static_file_connector_t *private = (static_file_connector_t *)arg;
	_mod_static_file_mod_t *mod = private->mod;
	mod_static_file_t *config = (mod_static_file_t *)mod->config;

	if (private->dir == NULL)
	{
		struct stat filestat;
		char *filepath;
		if (private->path_info)
			free(private->path_info);
		private->path_info = utils_urldecode(httpmessage_REQUEST(request,"uri"));
		filepath = utils_buildpath(config->docroot, private->path_info, "", "", &filestat);
		if (filepath && S_ISDIR(filestat.st_mode))
		{
			ret = ECONTINUE;
			private->dir = opendir(filepath);
			if (private->dir)
			{
				httpmessage_addcontent(response, (char*)utils_getmime(".html"), NULL, -1);

				int length = strlen(private->path_info);
				char *data = calloc(1, DIRLISTING_HEADER_LENGTH + length + 1);
				snprintf(data, DIRLISTING_HEADER_LENGTH + length, DIRLISTING_HEADER, "", private->path_info);
				httpmessage_addcontent(response, NULL, data, strlen(data));
				free(data);
				if (strlen(private->path_info) > 1)
				{
					line_t *line = dirlisting_lines[0];
					int length = (sizeof("..") - 1) * 2 + strlen(private->path_info);
					char *data = calloc(1, line->length + length + 1);
					snprintf(data, line->length + length, line->line, private->path_info, "..", "..");
					httpmessage_addcontent(response, NULL, data, strlen(data));
					free(data);
				}
				ret = ECONTINUE;
			}
			else
				warn("dirlisting: directory not open");
		}
		else
		{
			dbg("dirlisting: not a directory");
		}
	}
	else
	{
		struct dirent *ent;
		ent = readdir(private->dir);
		if (ent)
		{
			if (ent->d_name[0] != '.')
			{
				line_t *line;

				switch (ent->d_type)
				{
					case DT_DIR:
						line = dirlisting_lines[0];
					break;
					case DT_REG:
						line = dirlisting_lines[1];
					break;
					default:
						line = NULL;
					break;
				}
				if (line != NULL)
				{
					int length = strlen(private->path_info) + strlen(ent->d_name) * 2 + 4;
					char *data = calloc(1, line->length + length + 1);
					snprintf(data, line->length + length, line->line, private->path_info, ent->d_name, ent->d_name, ent->d_reclen);
					char *content = httpmessage_addcontent(response, NULL, data, -1);
					free(data);
				}
			}
			ret = ECONTINUE;
		}
		else
		{
			if (private->path_info)
			{
				free(private->path_info);
				private->path_info = NULL;
			}
			httpmessage_addcontent(response, NULL, DIRLISTING_FOOTER, -1);
			closedir(private->dir);
			private->dir = NULL;
			ret = ESUCCESS;
		}
	}
	return ret;
}

#ifndef STATIC_FILE
static void *_mod_dirlisting_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_static_file_mod_t *mod = (_mod_static_file_mod_t *)arg;
	mod_static_file_t *config = mod->config;
	static_file_connector_t *ctx = calloc(1, sizeof(*ctx));

	ctx->mod = mod;
	httpclient_addconnector(ctl, mod->vhost, dirlisting_connector, ctx);

	return ctx;
}

static void _mod_dirlisting_freectx(void *vctx)
{
	static_file_connector_t *ctx = vctx;
	if (ctx->path_info)
	{
		free(ctx->path_info);
		ctx->path_info = NULL;
	}
	free(ctx);
}

void *mod_dirlisting_create(http_server_t *server, char *vhost, mod_static_file_t *config)
{
	_mod_static_file_mod_t *mod = calloc(1, sizeof(*mod));

	if (config == NULL)
		return NULL;

	mod->config = config;
	mod->vhost = vhost;
	httpserver_addmod(server, _mod_dirlisting_getctx, _mod_dirlisting_freectx, mod);

	return mod;
}

void mod_dirlisting_destroy(void *data)
{
	free(data);
}
#endif
