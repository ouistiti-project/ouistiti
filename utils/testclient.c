/*****************************************************************************
 * testclient.c: Simple HTTP client
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define HAVE_GETOPT
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifndef WIN32
# include <sys/socket.h>
# include <sys/ioctl.h>
# include <sys/un.h>
# include <net/if.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
# include <arpa/inet.h>
# include <netdb.h>
#else
#endif

#define DEBUG
#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
# define dbg(...)
#endif

enum
{
	CONNECTION_START,
	REQUEST_START=0x01,
	REQUEST_HEADER=0x02,
	REQUEST_END=0x04,
	RESPONSE_START=0x10,
	RESPONSE_END=0x20,
	CONNECTION_END=0x40,
};

void display_help(char **name)
{
	printf("%s [-a <address>][-p <port>][-w]\n", name[0]);
}

#define OPT_WEBSOCKET 0x01
int main(int argc, char **argv)
{
	int port = 80;
	char *serveraddr = "127.0.0.1";
	int sock = -1;
	struct sockaddr_in saddr;
	struct addrinfo hints;
	int options = 0;

	setbuf(stdout, NULL);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Stream socket */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;


#ifdef HAVE_GETOPT
	int opt;
	do
	{
		opt = getopt(argc, argv, "a:p:hw");
		switch (opt)
		{
			case 'a':
				serveraddr = optarg;
			break;
			case 'p':
				port = atoi(optarg);
			break;
			case 'h':
				display_help(argv);
				return -1;
			break;
			case 'w':
				options |= OPT_WEBSOCKET;
			break;
		}
	} while(opt != -1);
#endif

	struct addrinfo *result, *rp;
	getaddrinfo(serveraddr, NULL, &hints, &result);

	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock == -1)
			continue;

		((struct sockaddr_in *)rp->ai_addr)->sin_port = htons(port);
		if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		close(sock);
		sock = -1;
	}

	if (sock == -1)
	{
		return -1;
	}

	int flags;

	int state = CONNECTION_START;
	int length;
	int ret = 0;
	char content[249];
	int contentlength = 0;
	do
	{
		char buffer[512];
		while ((state & REQUEST_END) == 0)
		{
			length = 511;
			length = read(0, buffer, length);
			if (length > 0)
			{
				buffer[length] = 0;
				//first read is blocking
				flags = fcntl(0, F_GETFL, 0);
				fcntl(0, F_SETFL, flags | O_NONBLOCK);

				state |= REQUEST_START;
				int i, emptyline = 0, headerlength = length;
				for (i = 0; i < length; i++)
				{

					if (buffer[i] == '\n')
					{
						if (emptyline > 0 && emptyline < 3)
						{
							headerlength = i + 1;
							state |= REQUEST_HEADER;
							break;
						}
						emptyline = 0;
					}
					emptyline++;
				}
				int ret;
				ret = send(sock, buffer, headerlength, MSG_NOSIGNAL);
				dbg("testclient: send header (%d)", headerlength);
				if (ret != headerlength)
				{
					err("testclient: send error");
					state |= CONNECTION_END;
					ret = -1;
				}
				if (state & REQUEST_HEADER)
				{
					contentlength = length - headerlength;
					if (options & OPT_WEBSOCKET)
					{
						state |= REQUEST_END;
						memcpy(content, buffer + headerlength, contentlength);
					}
					else if (contentlength)
					{
						/**
						 * send content
						 **/
						usleep(50);
						ret = send(sock, buffer + headerlength, contentlength, MSG_NOSIGNAL);
						dbg("testclient: send content (%d)", contentlength);
					}
				}
			}
			else if (length == 0)
				state |= REQUEST_END;
			else if (state > CONNECTION_START && !(state & REQUEST_END))
			{
				if (errno != EAGAIN)
				{
					if (length < 0)
						err("testclient: request clomplete %s", strerror(errno));
					state |= REQUEST_END;
				}
			}
			if (state & REQUEST_START)
				break;
		}
		flags = fcntl(sock, F_GETFL, 0);
		fcntl(sock, F_SETFL, flags | O_NONBLOCK);

		if (state & REQUEST_END)
		{
			length = 511;
			length = recv(sock, buffer, length, MSG_NOSIGNAL);
			if (length > 0)
			{
				ret += length;
				state |= RESPONSE_START;
				buffer[length] = 0;
				write(1, buffer, length);
			}
			else if (length == 0)
			{
				state |= RESPONSE_END;
			}
			else if (errno == EAGAIN)
			{
				int sret;
				struct timeval *ptimeout = NULL;
				struct timeval timeout;
				fd_set rfds;
				timeout.tv_sec = 1;
				timeout.tv_usec = 0;
				ptimeout = &timeout;
				FD_ZERO(&rfds);
				FD_SET(sock, &rfds);
				sret = select(sock + 1, &rfds, NULL, NULL, ptimeout);
				if (sret == 0)
					warn("testclient: receive timeout");
				if (sret != 1)
					state |= RESPONSE_END;
			}
		}
		if (state & RESPONSE_END)
		{
			if (options & OPT_WEBSOCKET)
			{
				ret = send(sock, content, contentlength - 1, MSG_NOSIGNAL);
				while ((state & CONNECTION_END) == 0)
				{
					int sret;
					struct timeval *ptimeout = NULL;
					struct timeval timeout;
					fd_set rfds;
					timeout.tv_sec = 1;
					timeout.tv_usec = 0;
					ptimeout = &timeout;
					FD_ZERO(&rfds);
					FD_SET(sock, &rfds);
					sret = select(sock + 1, &rfds, NULL, NULL, ptimeout);
					if (sret != 1)
						state |= CONNECTION_END;
					length = 248;
					contentlength = read(sock, content, length);
					if (contentlength == 0)
						state |= CONNECTION_END;
					else
					{
						dbg("testclient: websocket receive (%d)", contentlength);
						int i;
						for (i = 0; i < contentlength; i++)
						{
							printf("%02hhX", content[i]);
						}
						printf("\n");
					}
				}
			}
			else
				state |= CONNECTION_END;
		}
	} while (!(state & CONNECTION_END));
	dbg("testclient: quit");
	close(sock);
	return ret;
}
