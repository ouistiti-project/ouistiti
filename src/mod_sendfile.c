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

#include "httpserver/httpserver.h"
#include "httpserver/uri.h"
#include "mod_static_file.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif


#define CONTENTSIZE 1024
int mod_send_sendfile(static_file_connector_t *private, http_message_t *response)
{
	int ret, size;

	size = (private->size < CONTENTSIZE)? private->size : CONTENTSIZE;
	sigset_t sigset;
	sigemptyset (&sigset);
	sigaddset(&sigset, SIGPIPE);
	sigprocmask(SIG_BLOCK, &sigset, NULL);

	do
	{
		ret = httpclient_wait(private->ctl, 1);
	}
	while (ret == EINCOMPLETE);
	if (ret > 0)
	{
		do
		{
			int sock = ret;
			ret = sendfile(sock, private->fd, NULL, size);
		}
		while (ret < 0 && errno == EINTR);
	}
	if (ret >= 0)
		sigprocmask(SIG_UNBLOCK, &sigset, NULL);
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
/**
 * mod_send is defined into mod_static_file.c too.
 * This is a redifinition to overload the previous version.
 * Then this library must be load before libmod_static_file.so
 * This may be done during the binary link or with LD_PRELOAD
 */
// int mod_send(static_file_connector_t *private, http_message_t *response) __attribute__ ((weak, alias ("mod_send_sendfile")));

