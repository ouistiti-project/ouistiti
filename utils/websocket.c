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
#include <dlfcn.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "httpserver/websocket.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
# define dbg(...)
#endif

#define AF_WEBSOCKET PF_MAX + 0x0100 /* on Linux currently 0x0129 */

typedef struct _websocket_s _websocket_t;
struct _websocket_s
{
	int sock;
	_websocket_t *next;
};

typedef int (*socket_t)(int domain, int type, int protocol);
typedef int (*bind_t)(int sockfd, const struct sockaddr *addr,
                socklen_t addrlen);
typedef int (*listen_t)(int sockfd, int backlog);
typedef int (*accept_t)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
typedef ssize_t (*read_t)(int sockfd, void *buf, size_t len);
typedef ssize_t (*write_t)(int sockfd, const void *buf, size_t len);
typedef ssize_t (*recvfrom_t)(int sockfd, void *buf, size_t len, int flags,
			struct sockaddr *src_addr, socklen_t *addrlen);
typedef ssize_t (*sendto_t)(int sockfd, const void *buf, size_t len, int flags,
			const struct sockaddr *dest_addr, socklen_t addrlen);
typedef int (*close_t)(int sockfd);

socket_t std_socket = NULL;
bind_t std_bind = NULL;
listen_t std_listen = NULL;
accept_t std_accept = NULL;
read_t std_read = NULL;
write_t std_write = NULL;
recvfrom_t std_recvfrom = NULL;
sendto_t std_sendto = NULL;
close_t std_close = NULL;

static void _lib_init() __attribute__((constructor));
static int _lib_inited = 0;
static void _lib_exit() __attribute__((destructor));

static _websocket_t *_websocket_first = NULL;
static _websocket_t *_webclient_first = NULL;

static int websocket_close(void *arg, int status);
static int websocket_pong(void *arg, char *data);
websocket_t wsconfig = {
	.mtu = 0,
	.type = 0,
	.onclose = websocket_close,
	.onping = websocket_pong,
};

int socket(int domain, int type, int protocol)
{
	int sock = -1;
	int websocket_domain = AF_WEBSOCKET;

	if (domain == websocket_domain)
	{
		if (type == SOCK_STREAM)
		{
			if (protocol == WS_TEXT)
			{
				wsconfig.type = WS_TEXT;
			}
			sock = std_socket(AF_UNIX, SOCK_DGRAM, 0);

			_websocket_t *socket = calloc(1, sizeof(*socket));
			socket->sock = sock;
			socket->next = _websocket_first;
			_websocket_first = socket;
		}
		else
		{
			domain = AF_UNIX;
		}
	}
	if (sock == -1)
		sock = std_socket(domain, type, protocol);
	return sock;
}

int bind(int sockfd, const struct sockaddr *addr,
                socklen_t addrlen)
{
	return std_bind(sockfd, addr, addrlen);
}

int listen(int sockfd, int backlog)
{
	_websocket_t *socket = _websocket_first;
	while (socket && socket->sock != sockfd) socket = socket->next;
	if (socket)
	{
		return 0;
	}
	return std_listen(sockfd, backlog);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	_websocket_t *sockinfo = _websocket_first;
	while (sockinfo && sockinfo->sock != sockfd) sockinfo = sockinfo->next;
	if (sockinfo)
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

		recvmsg(sockinfo->sock, &msg, 0);

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
				ret = *(int *)data;
		}
		if (ret > 0)
		{
			_websocket_t *client = calloc(1, sizeof(*client));
			client->sock = ret;
			client->next = _webclient_first;
			_webclient_first = client;
		}
		return ret;
	}
	return std_accept(sockfd, addr, addrlen);
}


ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
			const struct sockaddr *dest_addr, socklen_t addrlen)
{
	ssize_t size = 0;
	_websocket_t *client = _webclient_first;
	while (client && client->sock != sockfd)
	{
		client = client->next;
	}
	if (client)
	{
		char *out = calloc(1, len + MAX_FRAGMENTHEADER_SIZE);
		while (size < len)
		{
			ssize_t length;
			int outlength = 0;
			length = websocket_framed(wsconfig.type, (char *)buf, len, out, &outlength, client);
			std_sendto(sockfd, out, outlength, flags, dest_addr, addrlen);
			size += length;
		}
		free(out);
	}
	else
		size = std_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	return size;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
	return sendto(sockfd, buf, len, flags, NULL, 0);
}

ssize_t write(int sockfd, const void *buf, size_t len)
{
	ssize_t size;
	_websocket_t *client = _webclient_first;
	while (client && client->sock != sockfd) client = client->next;
	if (client)
	{
		size = sendto(sockfd, buf, len, 0, NULL, 0);
	}
	else
		size = std_write(sockfd, buf, len);
	return size;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
			struct sockaddr *src_addr, socklen_t *addrlen)
{
	ssize_t size = -1;
	_websocket_t *client = _webclient_first;
	while (client && client->sock != sockfd)
	{
		client = client->next;
	}
	size = std_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
	if (client && size > 0)
	{
		int length = size;
		size = websocket_unframed(buf, length, buf, (void*)client);
	}
/*
	struct frame_s frame;
	int tmp;
	char *data = (char *) &frame;
	memset(data, 0, sizeof(frame));
	frame.fin = 1;
	frame.opcode = fo_ping;
	tmp = std_sendto(sockfd, &frame, sizeof(frame), MSG_DONTWAIT, NULL, 0);
*/
	return size;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
	return recvfrom(sockfd, buf, len, flags, NULL, NULL);
}

ssize_t read(int sockfd, void *buf, size_t len)
{
	ssize_t size;
	_websocket_t *client = _webclient_first;
	while (client && client->sock != sockfd) client = client->next;
	if (client)
	{
		size = recvfrom(sockfd, buf, len, 0, NULL, NULL);
	}
	else
		size = std_read(sockfd, buf, len);
	return size;
}

int close(int sockfd)
{
	_websocket_t *client = _webclient_first;
	_websocket_t *prev = _webclient_first;
	while (client && client->sock != sockfd)
	{
		prev = client;
		client = client->next;
	}
	if (client)
	{
		if (client != _webclient_first)
			prev->next = client->next;
		else
			_webclient_first = client->next;
		free(client);
		std_close(sockfd);
		return 0;
	}
	return std_close(sockfd);
}

static int websocket_close(void *arg, int status)
{
	int sockfd = ((_websocket_t *)arg)->sock;
	char message[] = { 0x88, 0x02, 0x03, 0xEA};
	return std_sendto(sockfd, message, sizeof(message), MSG_DONTWAIT, NULL, 0);
}

static int websocket_pong(void *arg, char *data)
{
	int sockfd = ((_websocket_t *)arg)->sock;
	char message[] = { 0x8A, 0x00};
	return std_sendto(sockfd, message, sizeof(message), MSG_DONTWAIT, NULL, 0);
}

static void _lib_init()
{
	if (_lib_inited) return;

	websocket_init(&wsconfig);
	if(!std_socket)
	{
		std_socket =  (socket_t)dlsym(RTLD_NEXT, "socket");
	}
	if(!std_bind)
	{
		std_bind = (bind_t)dlsym(RTLD_NEXT, "bind");
	}
	if(!std_listen)
	{
		std_listen = (listen_t)dlsym(RTLD_NEXT, "listen");
	}
	if(!std_accept)
	{
		std_accept = (accept_t)dlsym(RTLD_NEXT, "accept");
	}
	if(!std_read)
	{
		std_read = (read_t)dlsym(RTLD_NEXT, "read");
	}
	if(!std_write)
	{
		std_write = (write_t)dlsym(RTLD_NEXT, "write");
	}
	if(!std_recvfrom)
	{
		std_recvfrom = (recvfrom_t)dlsym(RTLD_NEXT, "recvfrom");
	}
	if(!std_sendto)
	{
		std_sendto = (sendto_t)dlsym(RTLD_NEXT, "sendto");
	}
	if(!std_close)
	{
		std_close  = (close_t)dlsym(RTLD_NEXT, "close");
	}
	_lib_inited = 1;
}

static void _lib_exit()
{
}

