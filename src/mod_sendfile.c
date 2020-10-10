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
#include <sys/sendfile.h>
#include <errno.h>
#include <signal.h>

#include "../compliant.h"
#include "httpserver/httpserver.h"
#include "mod_document.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

#define sighandler_t __sighandler_t

#define CONTENTSIZE 1024
int mod_send_sendfile(document_connector_t *private, http_message_t *response)
{
	int ret;
	ssize_t size;

	if (!(private->type & DOCUMENT_SENDFILE))
	{
		/**
		 * the first loop must not send content
		 * it should send the header first.
		 */
		private->type |= DOCUMENT_SENDFILE;
		errno = EAGAIN;
		return ECONTINUE;
	}

	/**
	 * check the size for the rnage support
	 * the size may be different of the real size file
	 */
	size = (private->size < CONTENTSIZE)? private->size : CONTENTSIZE;
#ifdef HAVE_SIGACTION
	sigset_t sigset;
	sigemptyset (&sigset);
	sigaddset(&sigset, SIGPIPE);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
#else
	sighandler_t handler_old;
	handler_old = signal(SIGPIPE, SIG_IGN);
#endif

	do
	{
		ret = httpclient_wait(httpmessage_client(response), 1);
	}
	while (ret == EINCOMPLETE);
	if (ret > 0)
	{
		do
		{
			int sock = ret;
			ret = sendfile(sock, private->fdfile, NULL, size);
		}
		while (ret < 0 && errno == EINTR);
	}
	if (ret >= 0)
#ifdef HAVE_SIGACTION
		sigprocmask(SIG_UNBLOCK, &sigset, NULL);
#else
		signal(SIGPIPE, handler_old);
#endif
	if (ret == 0 && size > 0)
	{
		ret = -1;
		errno = EAGAIN;
	}
	if (ret < 0)
		warn("sendfile %d %d", ret, errno);
	return ret;
}

/**
 * this method is replaced by the transfer type selector in config
 */

