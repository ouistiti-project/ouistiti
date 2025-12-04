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

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/log.h"
#include "mod_document.h"
#include "mod_auth.h"

#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT         0x800   /* Suppress terminal automount traversal */
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH           0x1000  /* Allow empty relative pathname */
#endif

#define document_dbg(...)

#define HAVE_SYMLINK

static int _document_delete(_mod_document_mod_t *mod, int fdroot, const char *url, int urllen);

static int restheader_connector(http_message_t *request, http_message_t *response, int error)
{
	const char *uri = NULL;
	int urilen = httpmessage_REQUEST2(request,"uri", &uri);
	const char *method = NULL;
	int methodlen = httpmessage_REQUEST2(request,"method", &method);

	httpmessage_addcontent(response, "text/json", STRING_REF("{\"method\":\""));
	httpmessage_appendcontent(response, method, methodlen);
	httpmessage_appendcontent(response, STRING_REF("\",\"result\":\""));
	if (error > 0)
	{
		httpmessage_appendcontent(response, STRING_REF("KO\",\"error\":\""));
		httpmessage_appendcontent(response, strerror(error), -1);
	}
	else
		httpmessage_appendcontent(response, STRING_REF("OK"));
	httpmessage_appendcontent(response, STRING_REF("\",\"name\":\""));
	httpmessage_appendcontent(response, uri, urilen);
	httpmessage_appendcontent(response, STRING_REF("\"}\n"));

	return ESUCCESS;
}

static int putfile_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret =  EREJECT;
	document_connector_t *private = (document_connector_t *)arg;

	/**
	 * we are into PRECONTENT, the data is no yet available
	 * Then the first loop as to complete on the opening
	 */

	const char *input;
	int inputlen;
	int error = 0;
	/**
	 * rest = 1 to close the connection on end of file or
	 * on connection error
	 */
	size_t rest = 1;
	inputlen = httpmessage_content(request, &input, &rest);
	document_dbg("document: put %d/%lu bytes into file %s", inputlen, rest, private->url);

	/**
	 * the function returns EINCOMPLETE to wait before to send
	 * the response.
	 */
	ret = EINCOMPLETE;
	errno = 0;
	while (inputlen > 0)
	{
		int wret = write(private->fdfile, input, inputlen);
		if (wret < 0)
		{
			err("document: access file %s error %m", private->url);
			if (errno != EAGAIN)
			{
				error = errno;
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
#ifdef DEBUG
	document_dbg("document: put %lu rest %lu", private->datasize, rest);
#endif
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
			ret = close(private->fdfile);
#ifdef PUTTMPFILE
			char path[PATH_MAX];
			snprintf(path, PATH_MAX, "/proc/self/fd/%d", private->fdfile);
			ret = linkat(mode->fdroot, path, AT_FDCWD, private->url, AT_SYMLINK_FOLLOW);
#endif
		}
		private->fdfile = 0;
		if (rest < 0)
#ifdef RESULT_500
			httpmessage_result(response, RESULT_500);
#else
			httpmessage_result(response, RESULT_404);
#endif
		else
#ifdef RESULT_201
			httpmessage_result(response, RESULT_201);
#else
			httpmessage_result(response, RESULT_200);
#endif
		restheader_connector(request, response, error);
	}
	return ret;
}

int _document_getconnnectorput(_mod_document_mod_t *mod,
		int fdroot, const char *url, int urllen, const char **mime,
		http_message_t *request, http_message_t *response,
		http_connector_t *connector)
{
	int fdfile = -1;
	string_t contenttype = {0};
	ouimessage_REQUEST(request,"Content-Type", &contenttype);
	errno = 0;
	if (url[urllen - 1] == '/' ||
		(!string_empty(&contenttype) && !string_cmp(&contenttype, STRING_REF(str_mime_inode_directory))))
	{
		fdfile = mkdirat(fdroot, url, 0755);
		if (fdfile == -1)
			err("document: Directory creation error(%m). Check parent directory access.");
		restheader_connector(request, response, errno);
		fdfile = 0; /// The request is complete by this connector even on error
	}
	else if (!string_empty(&contenttype) && !string_cmp(&contenttype, STRING_REF(str_mime_inode_symlink)))
	{
		/**
		 * The Content-Location may contain a forbidden path for the user.
		 * To limit the risk, a global file path is forbidden and to PUT
		 * a file the user must have the permission of creation.
		 * To guaranted the protection, the signature module should
		 * sign the Content-Location data.
		 */
		string_t location = {0};
		ouimessage_REQUEST(request,"Content-Location", &location);
		if (!string_empty(&location))
		{
			errno = 0;
			const char *target = string_toc(&location);
			while (target[0] == '/') target++;
			dbg("PUT symlink %s => %s", url, target);
			fdfile = symlinkat(target, fdroot, url);
			if (fdfile == -1)
				err("Document: Symbolic Link creation error(%m). Check parent directory access.");
		}
		else
			errno = EINVAL;
		restheader_connector(request, response, errno);
		fdfile = 0; /// The request is complete by this connector even on error
	}
	if (!string_empty(&contenttype) && !string_cmp(&contenttype, STRING_REF(str_multipart_form_data)))
	{
		err("document: form data unsupported with rest API");
	}
	else if (fdfile != 0)
	{
		fdfile = openat(fdroot, url, O_WRONLY | O_CREAT | O_EXCL, 0640);
		if (fdfile < 0)
		{
			err("Document: File creation error(%m). Check parent file access.");
			restheader_connector(request, response, errno);
			fdfile = 0; /// The request is complete by this connector
		}
		else
			*connector = putfile_connector;
	}
#ifdef RESULT_201
	else
		/// PUT directory or symlink are successfull
		httpmessage_result(response, RESULT_201);
#endif
	return fdfile;
}

static int _document_renameat(int fddir, const char *oldpath, const char *newpath)
{
	return renameat(fddir, oldpath, fddir, newpath);
}

static int _document_symlinkat(int fddir, const char *oldpath, const char *newpath)
{
	return symlinkat(oldpath, fddir, newpath);
}

typedef int (*changefunc)(int fddir, const char *oldpath, const char *newpath);
static int changename(int fdroot, http_message_t *UNUSED(request), const char *oldpath, const char *newname, changefunc func)
{
	int ret = -1;
	if (newname && newname[0] != '\0')
	{
		warn("change %s to %s", oldpath, newname);
		if (!func(fdroot, oldpath, newname))
			ret = 0;
	}
	return ret;
}

int _document_getconnnectorpost(_mod_document_mod_t *mod,
		int fdroot, const char *url, int urllen, const char **mime,
		http_message_t *request, http_message_t *response,
		http_connector_t *connector)
{
	int error = 0;
	int fdfile = -1;
	if (faccessat(fdroot, url, F_OK, 0) == -1)
		return fdfile;

	string_t cmd = {0};
	ouimessage_REQUEST(request, "X-POST-CMD", &cmd);

	errno = 0;
	if (!string_empty(&cmd) && !string_cmp(&cmd, "mv", 2))
	{
		const char *postarg = httpmessage_REQUEST(request, "X-POST-ARG");
		if (postarg[0] == '/')
			postarg++;
		warn("move %s to %s", url, postarg);
		fdfile = changename(fdroot, request, url, postarg, _document_renameat);
		error = errno;
		fdfile = 0; /// The request is complete by this connector
		restheader_connector(request, response, error);
	}
	else if (!string_empty(&cmd) && !string_cmp(&cmd, "chmod", 5))
	{
		warn("chmod %s", url);
		const char *postarg = httpmessage_REQUEST(request, "X-POST-ARG");
		int mod = strtol(postarg, NULL, 8);
		fdfile = fchmodat(fdroot, url, mod, 0);
		error = errno;
		fdfile = 0; /// The request is complete by this connector
		restheader_connector(request, response, error);
	}
#ifdef HAVE_SYMLINK
	else if (!string_empty(&cmd) && !string_cmp(&cmd, "ln", 2))
	{
		const char *postarg = httpmessage_REQUEST(request, "X-POST-ARG");
		if (postarg[0] == '/')
			postarg++;
		warn("document: link %s to %s", url, postarg);
		fdfile = changename(fdroot, request, url, postarg, _document_symlinkat);
		error = errno;
		fdfile = 0; /// The request is complete by this connector
		restheader_connector(request, response, error);
	}
#endif
	else if (string_empty(&cmd))
	{
		fdfile = openat(fdroot, url, O_WRONLY | O_TRUNC, 0640);
		if (fdfile < 0)
		{
			restheader_connector(request, response, errno);
			fdfile = 0; /// The request is complete by this connector
		}
		else
			*connector = putfile_connector;
	}
	else
	{
		err("document: %s unknown", string_toc(&cmd));
		error = 22;
		fdfile = 0; /// The request is complete by this connector
		restheader_connector(request, response, error);
	}
	return fdfile;
}

static int _document_delete(_mod_document_mod_t *mod,
		int fdroot, const char *url, int urllen)
{
	errno = 0;
	if (faccessat(fdroot, url, F_OK, 0) == -1)
	{
		err("document: delete error. File is doesn't exist'");
		return -1;
	}
	if (faccessat(fdroot, url, W_OK, AT_EACCESS | AT_SYMLINK_NOFOLLOW ))
	{
		err("document: delete error. File is not writeable");
		return 0;
	}
	struct stat filestat;
	if (fstatat(fdroot, url, &filestat, AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW) == -1)
	{
		return 0;
	}
	int flags = 0;
	if (S_ISDIR(filestat.st_mode))
		flags |= AT_REMOVEDIR;
	if (unlinkat(fdroot, url, flags) == -1)
	{
		err("document: delete error. Check directory access");
		return 0;
	}
	return 1;
}

int _document_getconnnectordelete(_mod_document_mod_t *mod,
		int fdroot, const char *url, int urllen, const char **mime,
		http_message_t *request, http_message_t *response,
		http_connector_t *connector)
{
	int fdfile;
	fdfile = _document_delete(mod, fdroot, url, urllen);
	if (fdfile >= 0)
	{
		restheader_connector(request, response, errno);
		fdfile = 0; /// The request is complete by this connector
	}
	return fdfile;
}
