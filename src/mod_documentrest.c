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
#include <time.h>
#include <libgen.h>

#include "httpserver/httpserver.h"
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

static const char str_OK[] = "OK";
static const char str_KO[] = "KO";

static int filestorage_checkname(document_connector_t *private, http_message_t *response)
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

int putfile_connector(void **arg, http_message_t *request, http_message_t *response)
{
	int ret =  EREJECT;
	document_connector_t *private = (document_connector_t *)*arg;
	_mod_document_mod_t *mod = private->mod;
	mod_document_t *config = (mod_document_t *)mod->config;

	if (private->fd == 0)
	{
		int length = strlen(private->filepath);
		if (private->filepath[length - 1] == '/')
		{
			httpmessage_addcontent(response, "text/json", "{\"method\":\"PUT\",\"name\":\"", -1);
			httpmessage_appendcontent(response, private->path_info, -1);
			httpmessage_appendcontent(response, "\",\"result\":\"", -1);
			if (mkdir(private->filepath, 0777) > 0)
			{
				err("document: directory creation not allowed %s", private->filepath);
				httpmessage_appendcontent(response, "KO\"}", -1);
#if defined RESULT_405
				httpmessage_result(response, RESULT_405);
#else
				httpmessage_result(response, RESULT_400);
#endif
			}
			else
			{
				warn("document: directory creation %s", private->filepath);
				httpmessage_appendcontent(response, "OK\"}", -1);
			}
			ret = ESUCCESS;
			document_close(private);

		}
		else
		{
			if (private->size > private->offset)
			{
				char range[20];
				sprintf(range, "bytes %ld/*", (long)private->size);
				httpmessage_addheader(response, "Content-Range", range);
			}
			else
			{
#ifdef PUTTMPFILE
#ifndef O_TMPFILE
#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)
#endif
				/**
				 * tmpfile will be not visible before to be closed
				 */
				char filepath[PATH_MAX];
				strncpy(filepath, private->filepath, PATH_MAX);
				char *dirpath = dirname(filepath);
				private->fd = open(dirpath, O_WRONLY | O_TMPFILE, 0644);
#else
				private->fd = open(private->filepath, O_WRONLY | O_CREAT, 0644);
#endif
			}
			if (private->fd > 0)
			{
				if (private->offset > 0)
				{
					lseek(private->fd, private->offset, SEEK_SET);
				}
				ret = EINCOMPLETE;
				httpmessage_addcontent(response, "text/json", "{\"method\":\"PUT\",\"result\":\"OK\",\"name\":\"", -1);
				httpmessage_appendcontent(response, private->path_info, -1);
				httpmessage_appendcontent(response, "\"}", -1);
#ifdef DEBUG
				clock_gettime(CLOCK_REALTIME, &private->start);
				dbg("document transfer start: %ld:%ld", private->start.tv_sec, private->start.tv_nsec);
#endif
			}
			else
			{
				err("document: file creation not allowed %s (size: %ld)", private->filepath, (long)private->size);
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
#if defined RESULT_405
					httpmessage_result(response, RESULT_405);
#else
					httpmessage_result(response, RESULT_400);
#endif
				ret = ESUCCESS;
				private->fd = 0;
				document_close(private);
			}
		}
	}
	/**
	 * we are into PRECONTENT, the data is no yet available
	 * Then the first loop as to complete on the opening
	 */
	else if (private->fd > 0)
	{
		char *input;
		int inputlen;
		/**
		 * rest = 1 to close the connection on end of file or
		 * on connection error
		 */
		unsigned long long rest = 1;
		inputlen = httpmessage_content(request, &input, &rest);

		/**
		 * the function returns EINCOMPLETE to wait before to send
		 * the response.
		 */
		ret = EINCOMPLETE;
		while (inputlen > 0)
		{
			int wret = write(private->fd, input, inputlen);
			if (wret < 0)
			{
				err("document: access file %s error %s", private->filepath, strerror(errno));
				if (errno != EAGAIN)
				{
#ifdef RESULT_500
					httpmessage_result(response, RESULT_500);
#else
					httpmessage_result(response, RESULT_404);
#endif
					rest = 0;
					break;
				}
			}
			else if (wret > 0)
			{
#ifdef DEBUG
				private->datasize += wret;
#endif
				inputlen -= wret;
				input += wret;
			}
		}
		if (inputlen == EREJECT)
		{
			rest = 0;
		}
		if (rest < 1)
		{
#ifdef DEBUG
			struct timespec stop;
			struct timespec value;
			clock_gettime(CLOCK_REALTIME, &stop);

			value.tv_sec = stop.tv_sec - private->start.tv_sec;
			value.tv_nsec = stop.tv_nsec - private->start.tv_nsec;
			dbg("document: (%llu bytes) %ld:%3ld", private->datasize, value.tv_sec, value.tv_nsec/1000000);
#endif
			warn("document: %s uploaded", private->filepath);
			if (private->fd)
			{
#ifdef PUTTMPFILE
				char path[PATH_MAX];
				snprintf(path, PATH_MAX, "/proc/self/fd/%d", private->fd);
				linkat(AT_FDCWD, path, AT_FDCWD, private->filepath,AT_SYMLINK_FOLLOW);
#endif
				close(private->fd);
			}
			private->fd = 0;
			ret = ESUCCESS;
			document_close(private);
		}
	}
	return ret;
}

typedef int (*changefunc)(const char *oldpath, const char *newpath);
static int changename(mod_document_t *config, http_message_t *request, char *oldpath, const char *newname, changefunc func)
{
	int ret = -1;
	if (newname && newname[0] != '\0')
	{
		const char *docroot = config->docroot;
		const char *other = "";
		const char *homepath = strstr(newname, "~");
		if (homepath != NULL && config->dochome != NULL)
		{
			docroot = config->dochome;
			newname = homepath + 1;
#ifdef AUTH
			if (newname[0] == '/')
			{
				other = auth_info(request, "user");
			}
#endif
		}
		char *newpath = utils_buildpath(docroot, other, newname, "", NULL);
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

int postfile_connector(void **arg, http_message_t *request, http_message_t *response)
{
	document_connector_t *private = (document_connector_t *)*arg;
	_mod_document_mod_t *mod = private->mod;
	mod_document_t *config = (mod_document_t *)mod->config;

	char *result = (char *)str_KO;
	const char *cmd = httpmessage_REQUEST(request, "X-POST-CMD");
	if (cmd == NULL || cmd[0] == '\0')
	{
		return getfile_connector(arg, request, response);
	}
	else if (cmd && !strcmp("mv", cmd))
	{
		warn("move %s", private->filepath);
		const char *arg = httpmessage_REQUEST(request, "X-POST-ARG");
		if (!changename(config, request, private->filepath, arg, rename))
			result = (char *)str_OK;
	}
	else if (cmd && !strcmp("chmod", cmd))
	{
		warn("chmod %s", private->filepath);
		const char *arg = httpmessage_REQUEST(request, "X-POST-ARG");
		int mod = atoi(arg);
		if (!chmod(private->filepath, mod))
			result = (char *)str_OK;
	}
#ifdef HAVE_SYMLINK
	else if (cmd && !strcmp("ln", cmd))
	{
		warn("link %s", private->filepath);
		const char *arg = httpmessage_REQUEST(request, "X-POST-ARG");
		if (!changename(config, private->filepath, arg, symlink))
			result = (char *)str_OK;
	}
#endif
	httpmessage_addcontent(response, "text/json", "{\"method\":\"POST\",\"name\":\"", -1);
	httpmessage_appendcontent(response, private->path_info, -1);
	httpmessage_appendcontent(response, "\",\"result\":\"", -1);
	httpmessage_appendcontent(response, result, -1);
	httpmessage_appendcontent(response, "\"}", 2);
	document_close(private);
	return ESUCCESS;
}

int deletefile_connector(void **arg, http_message_t *request, http_message_t *response)
{
	document_connector_t *private = (document_connector_t *)*arg;
	_mod_document_mod_t *mod = private->mod;
	mod_document_t *config = (mod_document_t *)mod->config;

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
		err("file removing not allowed %s", private->filepath);
		httpmessage_appendcontent(response, "KO\"}", -1);
#if defined RESULT_405
		httpmessage_result(response, RESULT_405);
#else
		httpmessage_result(response, RESULT_400);
#endif
	}
	else
	{
		warn("remove file : %s", private->filepath);
		httpmessage_appendcontent(response, "OK\"}", -1);
	}
	document_close(private);
	return ESUCCESS;
}
