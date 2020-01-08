/*****************************************************************************
 * client_chat.c: Simple Chat client
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
#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sched.h>
#include <sys/stat.h>
#include <signal.h>

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

static void help(char **name)
{
}

static void hello(int sock, const char *id, const char *nickname, const char *color)
{
	int length = 0;
	length += strlen(id) + strlen(id) + strlen(nickname) + strlen(color) + 96;
	char *buffer = calloc(1, length);
	length = snprintf(buffer,length, "{\"type\":\"hello\",\"id\":\"%s\",\"data\":{\"id\":\"%s\",\"nickname\":\"%s\",\"color\":\"%s\"}}", id, id, nickname, color);
	send(sock, buffer, length, MSG_NOSIGNAL);
	warn("send %s", buffer);
	free(buffer);
}

static void welcome(int sock, const char *id, const char *nickname, const char *color)
{
	int length = 0;
	length += strlen(id) + strlen(id) + strlen(nickname) + strlen(color) + 96;
	char *buffer = calloc(1, length);
	length = snprintf(buffer,length, "{\"type\":\"welcome\",\"id\":\"%s\",\"data\":{\"id\":\"%s\",\"nickname\":\"%s\",\"color\":\"%s\"}}", id, id, nickname, color);
	send(sock, buffer, length, MSG_NOSIGNAL);
	warn("send %s", buffer);
	free(buffer);
}

static void goodbye(int sock, const char *id, const char *nickname, const char *color)
{
	int length = 0;
	length += strlen(id) + strlen(id) + strlen(nickname) + strlen(color) + 96;
	char *buffer = calloc(1, length);
	length = snprintf(buffer,length, "{\"type\":\"goodbye\",\"id\":\"%s\",\"data\":{\"id\":\"%s\",\"nickname\":\"%s\",\"color\":\"%s\"}}", id, id, nickname, color);
	send(sock, buffer, length, MSG_NOSIGNAL);
	warn("send %s", buffer);
	free(buffer);
}

const char *str_username = "apache";

static int run = 1;
#ifdef HAVE_SIGACTION
static void handler(int sig, siginfo_t *si, void *arg)
#else
static void handler(int sig)
#endif
{
	run = 0;

}

#define WS_MSG 0x01
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
	char *root = "/var/run/ouistiti";
	char *proto = "chat";
	int maxclients = 50;
	const char *username = str_username;
	int options = 0;
	const char *color = "blue";
	const char *id = "C client";
	const char *nickname = "C client";

	int opt;
	do
	{
		opt = getopt(argc, argv, "u:n:R:m:wh");
		switch (opt)
		{
			case 'R':
				root = optarg;
			break;
			case 'h':
				help(argv);
			return -1;
			case 'm':
				maxclients = atoi(optarg);
			break;
			case 'u':
				username = optarg;
			break;
			case 'n':
				proto = optarg;
			break;
			case 'w':
				options |= WS_MSG;
		}
	} while(opt != -1);

	if (access(root, R_OK|W_OK|X_OK))
	{
		err("access %s error %s", root, strerror(errno));
		return -1;
	}

	if (getuid() == 0)
	{
		struct passwd *user = NULL;
		user = getpwnam(username);
		if (user != NULL)
		{
			if (setegid(user->pw_gid) < 0)
				warn("not enought rights to change group");
			if (seteuid(user->pw_uid) < 0)
				warn("not enought rights to change user");
		}
		else
			warn("user not found");
	}

#ifdef HAVE_SIGACTION
	struct sigaction action;
	action.sa_flags = SA_SIGINFO;
	sigemptyset(&action.sa_mask);
	action.sa_sigaction = handler;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);
#else
	signal(SIGTERM, handler);
	signal(SIGINT, handler);
#endif

	sock = socket(SOCKDOMAIN, SOCK_STREAM, SOCKPROTOCOL);
	if (sock > 0)
	{
		struct sockaddr_un addr;
		memset(&addr, 0, sizeof(struct sockaddr_un));
		addr.sun_family = AF_UNIX;
		snprintf(addr.sun_path, sizeof(addr.sun_path) - 1, "%s/%s", root, proto);

		ret = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
		if (ret == 0)
		{
			hello(sock, id, nickname, color);
			do
			{
				fd_set rfds;
				int maxfd = sock;
				FD_ZERO(&rfds);
				FD_SET(sock, &rfds);
				FD_SET(0, &rfds);
				ret = select(maxfd + 1, &rfds, NULL, NULL, NULL);
				if (ret > 0 && FD_ISSET(sock, &rfds))
				{
					int length = 0;

					ret = ioctl(sock, FIONREAD, &length);
					if (ret == 0 && length > 0)
					{
						char *buffer = calloc(1, length);
						ret = recv(sock, buffer, length, MSG_NOSIGNAL);
						if (ret > 0)
						{
							if (!strncmp(buffer, "WS", 2))
							{
							}
							else if (buffer[0] == '{')
							{
								dbg("receive %s", buffer);
								char *type = strstr(buffer, "\"type\":\"");
								int typelen = 0;
								if (type)
								{
									type += 8;
									typelen = strchr(type, '"') - type;
								}
								char *color = strstr(buffer, "\"color\":\"");
								int colorlen = 0;
								if (color)
								{
									color += 9;
									colorlen = strchr(color, '"') - color;
								}
								char *message = strstr(buffer, "\"data\":\"");
								int messagelen = 0;
								if (message)
								{
									message += 8;
									messagelen = strchr(message, '"') - message;
									dbg("receive %s %d", message, messagelen);
								}
								char *id = strstr(buffer, "\"id\":\"");
								int idlen = 0;
								if (id)
								{
									id += 6;
									idlen = strchr(id, '"') - id;
								}
								if (!strncmp(color, "red", colorlen))
									printf("\x1B[31m");
								if (!strncmp(color, "green", colorlen))
									printf("\x1B[32m");
								if (!strncmp(color, "blue", colorlen))
									printf("\x1B[33m");
								type[typelen] = 0;
								if (!strcmp(type, "hello"))
								{
									welcome(sock, id, nickname, color);
								}
								if (!strcmp(type, "message"))
								{
									message[messagelen] = 0;
									printf("%s", message);
								}
								printf("\x1B[0m\n");
							}
						}
						free(buffer);
					}
				}
				else if (ret > 0 && FD_ISSET(0, &rfds))
				{
					int length = 0;

					ret = ioctl(0, FIONREAD, &length);
					if (ret == 0 && length > 0)
					{
						char *message = calloc(1, length);
						if (fgets(message, length, stdin) != NULL && strlen(message) > 1)
						{
							if (!strcmp(message, "quit"))
							{
								run = 0;
							}
							else
							{
								length += strlen(color) + 71;
								char *buffer = calloc(1, length);
								length = snprintf(buffer,length, "{\"type\":\"message\",\"id\":\"%s\",\"data\":\"%s\",\"color\":\"%s\"}", id, message, color);
								send(sock, buffer, length, MSG_NOSIGNAL);
								free(buffer);
							}
						}
						free(message);
					}
				}
				else
				{
					warn("ret %d", ret);
					run = 0;
				}
			} while(run);
		}
	}
	goodbye(sock, id, nickname, color);
	close(sock);
	if (ret)
	{
		err("chat: error %s\n", strerror(errno));
	}
	return ret;
}
