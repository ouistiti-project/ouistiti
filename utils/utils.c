/*****************************************************************************
 * websocket.c: socket wraper for websocket
 * this file is part of https://github.com/ouistiti-project/ouistiti
 *****************************************************************************
 * Copyright (C) 2016-2017
 *
 * Authors: Marc Chalain <marc.chalain@gmail.com
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
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
# define dbg(...)
#endif

int ouistiti_recvaddr(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int ret = -1;
	struct msghdr msg = {0};
	int length;
	char buffer[256];
	struct iovec io = { .iov_base = buffer, .iov_len = sizeof(buffer) };
	msg.msg_iov = &io;
	msg.msg_iovlen = 1;

	char c_buffer[256];
	memset(c_buffer, 0, sizeof(c_buffer));
	msg.msg_control = c_buffer;
	msg.msg_controllen = sizeof(c_buffer);

	ret = recvmsg(sockfd, &msg, MSG_DONTWAIT);
	if (ret > 0)
	{
		if (addrlen && addr && msg.msg_iov)
		{
			length = *addrlen;
			*addrlen = msg.msg_iov[0].iov_len;
			length = (*addrlen < length)? *addrlen: length;
			memcpy(addr, msg.msg_iov[0].iov_base, length);
		}
		{
			struct cmsghdr *cmsg;
			unsigned char *data;

			cmsg = CMSG_FIRSTHDR(&msg);
			data = CMSG_DATA(cmsg);
			if (data)
			{
				ret = *(int *)data;
				close(sockfd);
			}
		}
	}
	return ret;
}
