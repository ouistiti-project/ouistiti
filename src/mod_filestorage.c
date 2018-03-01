/*****************************************************************************
 * mod_filestorage.c: RESTfull file storage module
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
#include <sys/sendfile.h>
#include <errno.h>
#include <signal.h>

#include "httpserver/httpserver.h"
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

static const char str_put[] = "PUT";
static const char str_delete[] = "DELETE";
static const char str_OK[] = "OK";
static const char str_KO[] = "KO";
static const char str_filestorage[] = "filestorage";

static int filestorage_checkname(static_file_connector_t *private, http_message_t *response)
{
	_mod_static_file_mod_t *mod = private->mod;
	mod_static_file_t *config = (mod_static_file_t *)mod->config;
	if (private->path_info[0] == '.')
	{
		return  EREJECT;
	}
	if (utils_searchexp(private->path_info, config->deny) == ESUCCESS &&
		utils_searchexp(private->path_info, config->allow) != ESUCCESS)
	{
		return  EREJECT;
	}
	return ESUCCESS;
}

int putfile_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret =  EREJECT;
	static_file_connector_t *private = (static_file_connector_t *)arg;
	_mod_static_file_mod_t *mod = private->mod;
	mod_static_file_t *config = (mod_static_file_t *)mod->config;

	if (private->fd == 0)
	{
		int length = strlen(private->path_info);
		if (private->path_info[length - 1] == '/')
		{
			httpmessage_addcontent(response, "text/json", "{\"method\":\"PUT\",\"name\":\"", -1);
			httpmessage_appendcontent(response, private->path_info, -1);
			httpmessage_appendcontent(response, "\",\"result\":\"", -1);
			if (mkdir(private->filepath, 0777) > 0)
			{
				err("directory creation not allowed %s", private->path_info);
				httpmessage_appendcontent(response, "KO\"}", -1);
#if defined RESULT_403
				httpmessage_result(response, RESULT_403);
#else
				httpmessage_result(response, RESULT_400);
#endif
			}
			else
			{
				warn("directory creation %s", private->path_info);
				httpmessage_appendcontent(response, "OK\"}", -1);
			}
			ret = ESUCCESS;
			static_file_close(private);

		}
		else
		{
			if (private->size > private->offset)
			{
				char range[20];
				sprintf(range, "bytes %d/*", private->size);
				httpmessage_addheader(response, "Content-Range", range);
			}
			else
				private->fd = open(private->filepath, O_WRONLY | O_CREAT, 0644);
			if (private->fd > 0)
			{
				if (private->offset > 0)
					lseek(private->fd, private->offset, SEEK_CUR);
				ret = EINCOMPLETE;
				httpmessage_addcontent(response, "text/json", "{\"method\":\"PUT\",\"result\":\"OK\",\"name\":\"", -1);
				httpmessage_appendcontent(response, private->path_info, -1);
				httpmessage_appendcontent(response, "\"}", -1);
			}
			else
			{
				err("file creation not allowed %s", private->path_info);
				httpmessage_addcontent(response, "text/json", "{\"method\":\"PUT\",\"result\":\"KO\",\"name\":\"", -1);
				httpmessage_appendcontent(response, private->path_info, -1);
				httpmessage_appendcontent(response, "\"}", -1);
				if (private->size > 0)
#if defined RESULT_416
					httpmessage_result(response, RESULT_416);
#else
					httpmessage_result(response, RESULT_400);
#endif
				else
#if defined RESULT_403
					httpmessage_result(response, RESULT_403);
#else
					httpmessage_result(response, RESULT_400);
#endif
				ret = ESUCCESS;
				private->fd = 0;
				static_file_close(private);
			}
		}
	}
	/**
	 * we are into PRECONTENT, the data is no yet available
	 * Then the first loop as to complete on the opening
	 */
	else if (private->fd > 0)
	{
#ifdef DEBUG
		static int filesize = 0;
#endif
		char *input;
		int inputlen;
		unsigned long long rest;
		inputlen = httpmessage_content(request, &input, &rest);

		if (inputlen > 0)
		{
#ifdef DEBUG
			filesize += inputlen;
#endif
			ret = write(private->fd, input, inputlen);
		}
		if (rest == EINCOMPLETE)
			ret = EINCOMPLETE;
		else if (rest < 1)
		{
			close(private->fd);
			private->fd = 0;
			ret = ESUCCESS;
			static_file_close(private);
		}
	}
	return ret;
}

typedef int (*changefunc)(const char *oldpath, const char *newpath);
static int changename(mod_static_file_t *config, char *oldpath, const char *newname, changefunc func)
{
	int ret = -1;
	if (newname && newname[0] != '\0')
	{
		char *newpath = utils_buildpath(config->docroot, newname, "", "", NULL);
		if (newpath)
		{
			warn("change %s to %s", oldpath, newpath);
			if (!func(oldpath, newpath))
				ret = 0;
			free(newpath);
		}
	}
	return ret;
}

int postfile_connector(void *arg, http_message_t *request, http_message_t *response)
{
	static_file_connector_t *private = (static_file_connector_t *)arg;
	_mod_static_file_mod_t *mod = private->mod;
	mod_static_file_t *config = (mod_static_file_t *)mod->config;

	warn("change %s", private->filepath);
	char *result = (char *)str_KO;
	const char *cmd = httpmessage_REQUEST(request, "X-POST-CMD");
	if (cmd && !strcmp("mv", cmd))
	{
		const char *arg = httpmessage_REQUEST(request, "X-POST-ARG");
		if (!changename(config, private->filepath, arg, rename))
			result = (char *)str_OK;
	}
	else if (cmd && !strcmp("chmod", cmd))
	{
		const char *arg = httpmessage_REQUEST(request, "X-POST-ARG");
		int mod = atoi(arg);
		if (!chmod(private->filepath, mod))
			result = (char *)str_OK;
	}
	else if (cmd && !strcmp("ln", cmd))
	{
		const char *arg = httpmessage_REQUEST(request, "X-POST-ARG");
		if (!changename(config, private->filepath, arg, symlink))
			result = (char *)str_OK;
	}
	httpmessage_addcontent(response, "text/json", "{\"method\":\"POST\",\"name\":\"", -1);
	httpmessage_appendcontent(response, private->path_info, -1);
	httpmessage_appendcontent(response, "\",\"result\":\"", -1);
	httpmessage_appendcontent(response, result, -1);
	httpmessage_appendcontent(response, "\"}", 2);
	static_file_close(private);
	return ESUCCESS;
}

int deletefile_connector(void *arg, http_message_t *request, http_message_t *response)
{
	static_file_connector_t *private = (static_file_connector_t *)arg;
	_mod_static_file_mod_t *mod = private->mod;
	mod_static_file_t *config = (mod_static_file_t *)mod->config;

	httpmessage_addcontent(response, "text/json", "{\"method\":\"DELETE\",\"name\":\"", -1);
	httpmessage_appendcontent(response, private->path_info, -1);
	httpmessage_appendcontent(response, "\",\"result\":\"", -1);
	struct stat statistic;
	stat(private->filepath, &statistic);
	int (*rmfunction)(const char *pathname);
	if (S_ISDIR(statistic.st_mode))
		rmfunction = rmdir;
	else
		rmfunction = unlink;
	if (rmfunction(private->filepath) < 0)
	{
		err("file removing not allowed %s", private->path_info);
		httpmessage_appendcontent(response, "KO\"}", -1);
#if defined RESULT_403
		httpmessage_result(response, RESULT_403);
#else
		httpmessage_result(response, RESULT_400);
#endif
	}
	else
	{
		warn("remove file : %s", private->path_info);
		httpmessage_appendcontent(response, "OK\"}", -1);
	}
	static_file_close(private);
	return ESUCCESS;
}

static int filestorage_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret =  EREJECT;
	static_file_connector_t *private = (static_file_connector_t *)arg;
	_mod_static_file_mod_t *mod = private->mod;
	mod_static_file_t *config = (mod_static_file_t *)mod->config;

	if (private->func == NULL)
	{
		struct stat filestat;
		if (private->path_info)
			free(private->path_info);
		const char *uri = httpmessage_REQUEST(request,"uri");
		private->path_info = utils_urldecode(uri);
		if (private->path_info == NULL)
			return EREJECT;
		const char *method = httpmessage_REQUEST(request, "method");
		private->filepath = utils_buildpath(config->docroot, private->path_info, "", "", &filestat);
		if ((private->filepath == NULL) && (!strcmp(method, "PUT")))
		{
			private->filepath = utils_buildpath(config->docroot, private->path_info, "", "", NULL);
			private->func = putfile_connector;
		}
		else if (private->filepath && filestorage_checkname(private, response) == ESUCCESS)
		{
			if (!strcmp(method, "GET") || !strcmp(method, "HEAD"))
			{
				if (S_ISDIR(filestat.st_mode))
				{
					int length = strlen(private->path_info);
					const char *X_Requested_With = httpmessage_REQUEST(request, "X-Requested-With");
					if ((X_Requested_With && strstr(X_Requested_With, "XMLHttpRequest") != NULL) ||
						(private->path_info[length - 1] != '/'))
					{
						private->func = dirlisting_connector;
					}
					else
					{
#ifdef DIRLISTING
						if (config->options & STATIC_FILE_DIRLISTING)
						{
							private->func = dirlisting_connector;
						}
#else
						warn("static file: %s is directory", private->path_info);
#endif
						char *indexpath = utils_buildpath(config->docroot, private->path_info,
														config->defaultpage, "", &filestat);
						if (indexpath)
						{
							free(indexpath);
#if defined(RESULT_301)
							char *location = calloc(1, length + strlen(config->defaultpage) + 2);
							sprintf(location, "/%s%s", private->path_info, config->defaultpage);
							httpmessage_addheader(response, str_location, location);
							httpmessage_result(response, RESULT_301);
							free(location);
							static_file_close(private);
							return ESUCCESS;
#endif
						}
					}
				}
				else
				{
					private->func = getfile_connector;
					private->size = filestat.st_size;
					private->offset = 0;
				}
			}
			else if (!strcmp(method, "PUT"))
			{
				private->size = filestat.st_size;
				private->offset = 0;
				private->func = putfile_connector;
			}
			else if (!strcmp(method, "POST"))
			{
				private->func = postfile_connector;
			}
			else if (!strcmp(method, "DELETE"))
			{
				private->func = deletefile_connector;
			}
		}
		else
			warn("filestorage: forbidden file %s", private->path_info);
	}
	return  EREJECT;
}

static int transfer_connector(void *arg, http_message_t *request, http_message_t *response)
{
	static_file_connector_t *private = (static_file_connector_t *)arg;
	if (private->func)
		return private->func(arg, request, response);
	static_file_close(private);
	return EREJECT;
}

static void *_mod_filestorage_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_static_file_mod_t *mod = (_mod_static_file_mod_t *)arg;
	mod_static_file_t *config = mod->config;
	static_file_connector_t *ctx = calloc(1, sizeof(*ctx));

	ctx->mod = mod;
	ctx->ctl = ctl;
	httpclient_addconnector(ctl, mod->vhost, transfer_connector, ctx, str_filestorage);
#ifdef RANGEREQUEST
	if (config->options & STATIC_FILE_RANGE)
		httpclient_addconnector(ctl, mod->vhost, range_connector, ctx, str_filestorage);
#endif
	httpclient_addconnector(ctl, mod->vhost, filestorage_connector, ctx, str_filestorage);

	return ctx;
}

static void _mod_filestorage_freectx(void *vctx)
{
	static_file_connector_t *ctx = vctx;
	if (ctx->path_info)
	{
		free(ctx->path_info);
		ctx->path_info = NULL;
	}
	free(ctx);
}

void *mod_filestorage_create(http_server_t *server, char *vhost, mod_static_file_t *config)
{
	_mod_static_file_mod_t *mod = calloc(1, sizeof(*mod));

	if (config == NULL)
		return NULL;

	mod->config = config;
	mod->vhost = vhost;
	httpserver_addmod(server, _mod_filestorage_getctx, _mod_filestorage_freectx, mod, str_filestorage);
	httpserver_addmethod(server, str_put, 1);
	httpserver_addmethod(server, str_delete, 1);
	return mod;
}

void mod_filestorage_destroy(void *data)
{
	free(data);
}
