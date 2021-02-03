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
#include "httpserver/log.h"
#include "mod_document.h"
#include "mod_auth.h"

#define document_dbg(...)

#define HAVE_SYMLINK

static int restheader_connector(document_connector_t *private, http_message_t *request, http_message_t *response)
{
	const char *uri = httpmessage_REQUEST(request,"uri");
	const char *method = httpmessage_REQUEST(request,"method");

	httpmessage_addcontent(response, "text/json", NULL, 0);
	httpmessage_appendcontent(response, "{\"method\":\"", -1);
	httpmessage_appendcontent(response, method, -1);
	httpmessage_appendcontent(response, "\",\"result\":\"", -1);
	if (httpmessage_result(response, 0) == 200)
		httpmessage_appendcontent(response, "OK", -1);
	else
	{
		httpmessage_appendcontent(response, "KO\",\"error\":\"", -1);
		httpmessage_appendcontent(response, strerror(errno), -1);
	}
	httpmessage_appendcontent(response, "\",\"name\":\"", -1);
	httpmessage_appendcontent(response, uri, -1);
	httpmessage_appendcontent(response, "\"}\n", -1);
#ifdef DEBUG
	clock_gettime(CLOCK_REALTIME, &private->start);
	dbg("document transfer start: %ld:%ld", private->start.tv_sec, private->start.tv_nsec);
#endif

	return ESUCCESS;
}

static int putdir_connector(document_connector_t *private, http_message_t *request, http_message_t *response)
{
	int ret =  EREJECT;

	if (mkdirat(private->fdroot, private->url, 0777) > 0)
	{
		err("document: directory creation not allowed %s", private->url);
#if defined RESULT_405
		httpmessage_result(response, RESULT_405);
#else
		httpmessage_result(response, RESULT_400);
#endif
	}
	else
	{
		warn("document: directory creation %s", private->url);
	}
	ret = ESUCCESS;
	document_close(private, request);
	return ret;
}

static int putcontent_connector(document_connector_t *private, http_message_t *request, http_message_t *response)
{
	int ret =  EREJECT;

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
		int wret = write(private->fdfile, input, inputlen);
		if (wret < 0)
		{
			err("document: access file %s error %s", private->url, strerror(errno));
			if (errno != EAGAIN)
			{
#ifdef RESULT_500
				httpmessage_result(response, RESULT_500);
#else
				httpmessage_result(response, RESULT_404);
#endif
				rest = -1;
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
		dbg("document: (%llu bytes) time %ld:%03ld", private->datasize, value.tv_sec, value.tv_nsec/1000000);
#endif
		warn("document: %s uploaded", private->url);
		if (private->fdfile)
		{
#ifdef PUTTMPFILE
			char path[PATH_MAX];
			snprintf(path, PATH_MAX, "/proc/self/fd/%d", private->fdfile);
			if (linkat(mode->fdroot, path, AT_FDCWD, private->url, AT_SYMLINK_FOLLOW) == -1)
#if defined RESULT_405
				httpmessage_result(response, RESULT_405);
#else
				httpmessage_result(response, RESULT_400);
#endif
			else
#endif
#if defined RESULT_201
				httpmessage_result(response, RESULT_201);
#else
				httpmessage_result(response, RESULT_200);
#endif
			close(private->fdfile);
		}
		private->fdfile = 0;
		document_close(private, request);
		ret = ESUCCESS;
	}
	return ret;
}

int putfile_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret =  EREJECT;
	document_connector_t *private = httpmessage_private(request, NULL);
	_mod_document_mod_t *mod = (_mod_document_mod_t *)arg;

	if (private->type & DOCUMENT_DIRLISTING)
	{
		ret = putdir_connector(private, request, response);
	}
	/**
	 * we are into PRECONTENT, the data is no yet available
	 * Then the first loop as to complete on the opening
	 */
	else if (private->fdfile > 0)
	{
		ret = putcontent_connector(private, request, response);
	}
	if (ret == ESUCCESS)
	{
		ret = restheader_connector(private, request, response);
	}
	return ret;
}

int _document_renameat(int fddir, const char *oldpath, const char *newpath)
{
	return renameat(fddir, oldpath, fddir, newpath);
}

int _document_symlinkat(int fddir, const char *oldpath, const char *newpath)
{
	return symlinkat(oldpath, fddir, newpath);
}

typedef int (*changefunc)(int fddir, const char *oldpath, const char *newpath);
static int changename(document_connector_t *private, http_message_t *UNUSED(request), const char *oldpath, const char *newname, changefunc func)
{
	int ret = -1;
	if (newname && newname[0] != '\0')
	{
		warn("change %s to %s", oldpath, newname);
		if (!func(private->fdroot, oldpath, newname))
			ret = 0;
	}
	return ret;
}

int postfile_connector(void *arg, http_message_t *request, http_message_t *response)
{
	document_connector_t *private = httpmessage_private(request, NULL);
	_mod_document_mod_t *mod = (_mod_document_mod_t *)arg;

	const char *cmd = httpmessage_REQUEST(request, "X-POST-CMD");

	if (cmd == NULL || cmd[0] == '\0')
	{
		return getfile_connector(arg, request, response);
	}
	else if (cmd && !strcmp("mv", cmd))
	{
		const char *postarg = httpmessage_REQUEST(request, "X-POST-ARG");
		if (postarg[0] == '/')
			postarg++;
		warn("move %s to %s", private->url, postarg);
		if (changename(private, request, private->url, postarg, _document_renameat) == -1)
#if defined RESULT_405
			httpmessage_result(response, RESULT_405);
#else
			httpmessage_result(response, RESULT_400);
#endif
	}
	else if (cmd && !strcmp("chmod", cmd))
	{
		warn("chmod %s", private->url);
		const char *postarg = httpmessage_REQUEST(request, "X-POST-ARG");
		int mod = strtol(postarg, NULL, 8);
		if (fchmodat(private->fdroot, private->url, mod, 0) == -1)
#if defined RESULT_405
			httpmessage_result(response, RESULT_405);
#else
			httpmessage_result(response, RESULT_400);
#endif
	}
#ifdef HAVE_SYMLINK
	else if (cmd && !strcmp("ln", cmd))
	{
		const char *postarg = httpmessage_REQUEST(request, "X-POST-ARG");
		if (postarg[0] == '/')
			postarg++;
		warn("document: link %s to %s", private->url, postarg);
		if (changename(private, request, private->url, postarg, _document_symlinkat) == -1)
#if defined RESULT_405
			httpmessage_result(response, RESULT_405);
#else
			httpmessage_result(response, RESULT_400);
#endif
	}
#endif
	else
	{
		err("document: %s unknown", cmd);
		errno = 22;
#if defined RESULT_405
		httpmessage_result(response, RESULT_405);
#else
		httpmessage_result(response, RESULT_400);
#endif
	}
	restheader_connector(private, request, response);
	document_close(private, request);

	return ESUCCESS;
}

int deletefile_connector(void *arg, http_message_t *request, http_message_t *response)
{
	document_connector_t *private = httpmessage_private(request, NULL);

	int flags = 0;
	if (private->type & DOCUMENT_DIRLISTING)
		flags |= AT_REMOVEDIR;
	if (unlinkat(private->fdroot, private->url, flags) < 0)
	{
		err("file removing not allowed %s", private->url);
#if defined RESULT_405
		httpmessage_result(response, RESULT_405);
#else
		httpmessage_result(response, RESULT_400);
#endif
	}
	else
	{
		warn("remove file : %s", private->url);
	}
	restheader_connector(private, request, response);
	document_close(private, request);
	return ESUCCESS;
}
