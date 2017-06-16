/*****************************************************************************
 * websocket_echo.c: Simple echo server
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sched.h>

typedef int (*server_t)(int sock);

int echo(int sock)
{
	int ret = 0;

	while (sock > 0)
	{
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);

		ret = select(sock + 1, &rfds, NULL, NULL, NULL);
		if (ret > 0 && FD_ISSET(sock, &rfds))
		{
			char buffer[256];
			ret = recv(sock, buffer, 256, MSG_NOSIGNAL);
			if (ret > 0)
			{
				printf("echo: receive %d %s\n", ret, buffer);
				char *out = buffer;
				ret = strlen(out);
				ret = send(sock, out, ret, MSG_DONTWAIT | MSG_NOSIGNAL);
			}
			if (ret <= 0)
			{
				if (errno != EAGAIN)
				{
					printf("echo: close %s\n", strerror(errno));
					close(sock);
					sock = -1;
				}
			}
		}
	}
	return ret;
}

void help(char **argv)
{
	fprintf(stderr, "%s [-R <socket directory>] [-m <nb max clients>] [-u <user>][ -h]\n", argv[0]);
}

#ifndef PTHREAD
int start(server_t server, int newsock)
{
	if (fork() == 0)
	{
		printf("run\n");
		server(newsock);
		exit(0);
	}
	sched_yield();
	sched_yield();
	usleep(50);
	printf("close\n");
	close(newsock);
	return 0;
}
#else
#include <pthread.h>
typedef void *(*start_routine_t)(void*);
int start(server_t server, int newsock)
{
	pthread_t thread;
	pthread_create(&thread, NULL, (start_routine_t)server, (void *)newsock);
}
#endif

const char *str_username = "apache";
#ifndef SOCKDOMAIN
#define SOCKDOMAIN AF_UNIX
#endif
#ifndef SOCKPROTOCOL
#define SOCKPROTOCOL 0
#endif
int main(int argc, char **argv)
{
	int ret = -1;
	int sock;
	char *root = "/var/run/websocket";
	char *proto = "echo";
	int maxclients = 50;
	const char *username = str_username;

	int opt;
	do
	{
		opt = getopt(argc, argv, "u:R:m:h");
		switch (opt)
		{
			case 'R':
				root = optarg;
			break;
			case 'h':
				help(argv);
				return -1;
			break;
			case 'm':
				maxclients = atoi(optarg);
			break;
			case 'u':
				username = optarg;
			break;
		}
	} while(opt != -1);

	if (getuid() == 0)
	{
		struct passwd *user = NULL;
		user = getpwnam(username);
		setgid(user->pw_gid);
		setuid(user->pw_uid);
	}

	sock = socket(SOCKDOMAIN, SOCK_STREAM, SOCKPROTOCOL);
	if (sock > 0)
	{
		struct sockaddr_un addr;
		memset(&addr, 0, sizeof(struct sockaddr_un));
		addr.sun_family = AF_UNIX;
		snprintf(addr.sun_path, sizeof(addr.sun_path) - 1, "%s/%s", root, proto);
		unlink(addr.sun_path);

		ret = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
		if (ret == 0)
		{
			ret = listen(sock, maxclients);
		}
		if (ret == 0)
		{
			int newsock = 0;
			do
			{
				struct sockaddr_in addr;
				int addrsize = sizeof(addr);
				newsock = accept(sock, (struct sockaddr *)&addr, &addrsize);
				printf("echo: new connection from %s\n", inet_ntoa(addr.sin_addr));
				if (newsock > 0)
				{
					start(echo, newsock);
				}
			} while(newsock > 0);
		}
	}
	if (ret)
	{
		fprintf(stderr, "error : %s\n", strerror(errno));
	}
	return ret;
}
