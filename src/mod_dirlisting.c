/*****************************************************************************
 * mod_dirlisting.c: callbacks and management of directories
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

#define DIRLISTING_HEADER "\
{\
\"method\":\"GET\",\
\"result\":\"OK\",\
\"name\":\"%s\",\
\"content\":["
#define DIRLISTING_HEADER_LENGTH (sizeof(DIRLISTING_HEADER) - 2)
#define DIRLISTING_LINE "{\"name\":\"%s\",\"size\":\"%u %s\",\"type\":%d},"
#define DIRLISTING_LINE_LENGTH (sizeof(DIRLISTING_LINE))
#define DIRLISTING_FOOTER "\
{}]}"

static char *_sizeunit[] = {
	"B",
	"kB",
	"MB",
	"GB",
	"TB",
};
int dirlisting_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	static_file_connector_t *private = (static_file_connector_t *)arg;
	_mod_static_file_mod_t *mod = private->mod;
	mod_static_file_t *config = (mod_static_file_t *)mod->config;

	if (private->dir == NULL)
	{
		chdir(private->filepath);
		private->dir = opendir(private->filepath);
		if (private->dir)
		{
			warn("dirlisting: open /%s", private->path_info);
			httpmessage_addcontent(response, (char*)utils_getmime(".json"), NULL, -1);

			int length = strlen(private->path_info);
			char *data = calloc(1, DIRLISTING_HEADER_LENGTH + length + 1);
			snprintf(data, DIRLISTING_HEADER_LENGTH + length, DIRLISTING_HEADER, private->path_info);
			httpmessage_addcontent(response, (char*)utils_getmime(".json"), data, strlen(data));
			free(data);
			ret = ECONTINUE;
		}
		else
		{
			warn("dirlisting: directory not open %s %s", private->filepath, strerror(errno));
			static_file_close(private);
			httpmessage_result(response, RESULT_400);
			ret = ESUCCESS;
		}
	}
	else if (private->path_info == NULL)
	{
		httpclient_shutdown(private->ctl);
		closedir(private->dir);
		static_file_close(private);
		ret = ESUCCESS;
	}
	else
	{
		struct dirent *ent;
		ent = readdir(private->dir);
		if (ent)
		{
			if (ent->d_name[0] != '.')
			{
				int length = strlen(ent->d_name);
				struct stat filestat;
				stat(ent->d_name, &filestat);
				int size = filestat.st_size;
				int unit = 0;
				while (size > 2000)
				{
					size /= 1024;
					unit++;
				}

				length += 4 + 2 + 4;
				char *data = calloc(1, DIRLISTING_LINE_LENGTH + length + 1);
				snprintf(data, DIRLISTING_LINE_LENGTH + length, DIRLISTING_LINE, ent->d_name, size, _sizeunit[unit], ((filestat.st_mode & S_IFMT) >> 12));
				char *content = httpmessage_addcontent(response, NULL, data, -1);
				free(data);
			}
			ret = ECONTINUE;
		}
		else
		{
			free(private->path_info);
			private->path_info = NULL;
			httpmessage_addcontent(response, NULL, DIRLISTING_FOOTER, -1);
			ret = ECONTINUE;
		}
	}
	return ret;
}

#ifdef DIRLISTING_MOD
static void *_mod_dirlisting_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_static_file_mod_t *mod = (_mod_static_file_mod_t *)arg;
	mod_static_file_t *config = mod->config;
	static_file_connector_t *ctx = calloc(1, sizeof(*ctx));

	ctx->mod = mod;
	ctx->ctl = ctl;
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
