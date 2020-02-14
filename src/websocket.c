/*****************************************************************************
 * websocket.c: callbacks and management of request method
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
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "httpserver/httpserver.h"
#include "httpserver/mod_websocket.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

int ouistiti_websocket_socket(void *arg, int sock, const char *filepath, http_message_t *request)
{
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, filepath, sizeof(addr.sun_path) - 1);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock > 0)
	{
		int ret = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
		if (ret < 0)
		{
			close(sock);
			sock = -1;
		}
	}
	if (sock == -1)
	{
		warn("websocket %s error: %s", filepath, strerror(errno));
	}
	return sock;
}

static int _websocket_connect(int client, int socket)
{
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(socket))];  /* ancillary data buffer */
	int *fdptr;

	struct sockaddr_storage addr;
	int addrsize = sizeof(struct sockaddr_in);
	getpeername(socket, (struct sockaddr*)&addr, &addrsize);
    struct iovec io = { .iov_base = &addr, .iov_len = addrsize };

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

	memset(buf, '\0', sizeof(buf));
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(socket));

	/* Initialize the payload: */
	*((int *) CMSG_DATA(cmsg)) = socket;
	/* Sum of the length of all control messages in the buffer: */
	msg.msg_controllen = cmsg->cmsg_len;

	return sendmsg(client, &msg, MSG_DONTWAIT);
}

int ouistiti_websocket_run(void *arg, int sock, const char *filepath, http_message_t *request)
{
	int client = ouistiti_websocket_socket(arg, sock, filepath, request);
	if (client)
		_websocket_connect(client, sock);
	dbg("websocket releases the socket for direct access");
	return 0;
}
