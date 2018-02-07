/*****************************************************************************
 * websocket_chat.c: Simple Chat server
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

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

typedef int (*server_t)(int sock);

typedef struct identity_s identity_t;
struct identity_s
{
	char name[30];
};

typedef struct user_s user_t;
struct user_s
{
	int sock;
	identity_t *identity;
	user_t *next;
	user_t *prev;
};

#define WS_MSG 0x01

static user_t *first_user = NULL;

int chatmsg(user_t *user, char *buffer, int length)
{
	int ret = 0;
	user_t *iterator = first_user;
	while (iterator)
	{
		if (iterator->sock != user->sock)
		{
			send(iterator->sock, buffer, length, MSG_DONTWAIT);
			dbg("send to %d : %s", iterator->sock, buffer);
		}
		iterator = iterator->next;
	}
	return ret;
}

int privatemsg(user_t *dest, char *buffer, int length)
{
	int ret = 0;
	user_t *iterator = first_user;
	while (iterator)
	{
		if (iterator->sock == dest->sock)
		{
			send(iterator->sock, buffer, length, MSG_DONTWAIT);
			dbg("send to %d : %s", iterator->sock, buffer);
		}
		iterator = iterator->next;
	}
	return ret;
}

int chat(user_t *user, char *buffer, int length)
{
	int ret = 0;

	if (!strncmp(buffer,"WSHello ", 8))
	{
		char *identity = buffer + 8;
		buffer += 8;
		length = 0;
		while ((*buffer != '\n') && (*buffer != ' ') && (*buffer != '\0'))
		{
			buffer++;
			length++;
		}
		if (length > 0)
		{
			*buffer = 0;
			int i = 0;
			user_t *iterator = first_user;
			while (iterator)
			{
				if (!strncmp(iterator->identity->name, identity, 30))
				{
					i++;
				}
				iterator = iterator->next;
			}
			strncpy(user->identity->name, identity, sizeof(user->identity->name));
			if (i > 0)
			{
				
				if (length > 27)
					length = 27;
				sprintf(user->identity->name + length, "%03hd", i);
			}
				
			char resp[40];
			sprintf(resp, "WSWelcome %s", user->identity->name);
			privatemsg(user, resp, strlen(resp));
		}
	}
	else if (!strncmp(buffer,"WSPrivate ", 10))
	{
		char *identity = buffer + 10;
		
		buffer += 10;
		length -= 10;
		while ((*buffer != '\n') && (*buffer != ' ') && (length > 0))
		{
			buffer++;
			length--;
		}
		if (length > 0)
		{
			*buffer = 0;
			buffer++;
			length--;
			user_t *iterator = first_user;
			while (iterator)
			{
				if (!strncmp(iterator->identity->name, identity, 30))
					ret = privatemsg(iterator, buffer, length);
				iterator = iterator->next;
			}
		}
	}
	else if (!strncmp(buffer,"WSWhois ", 8))
	{
		char *identity = buffer + 8;
		buffer += 8;
		length = 0;
		while ((*buffer != '\n') && (*buffer != ' ') && (*buffer != '\0'))
		{
			buffer++;
			length++;
		}
		if (length > 0)
		{
			*buffer = 0;
			int i = 0;
			user_t *iterator = first_user;
			while (iterator)
			{
				if (!strncmp(iterator->identity->name, identity, 30))
				{
					break;
				}
				iterator = iterator->next;
			}
			char resp[52];
			struct sockaddr_storage addr;
			int addrsize = sizeof(addr);
			if (iterator)
			{
				getpeername(iterator->sock, (struct sockaddr*)&addr, &addrsize);
				if (addr.ss_family == AF_INET)
				{
					struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
					sprintf(resp, "WSIs %s %s", identity, inet_ntoa(addr_in->sin_addr));
				}
				else
					sprintf(resp, "WSIs %s network error", identity);
			}
			else
				sprintf(resp, "WSIs %s undefined", identity);
			privatemsg(user, resp, strlen(resp));
		}
	}
	else
		ret = chatmsg(user, buffer, length);
	return ret;
}

void help(char **argv)
{
	fprintf(stderr, "%s [-R <socket directory>] [-m <nb max clients>] [-u <user>] [-w] [ -h]\n", argv[0]);
	fprintf(stderr, "\t-R <dir>\tset the socket directory for the connection\n");
	fprintf(stderr, "\t-m <num>\tset the maximum number of clients\n");
	fprintf(stderr, "\t-u <name>\tset the user to run\n");
	fprintf(stderr, "\t-w \tstart chat with specific ouistiti features\n");
}

static const char *str_hello = "{\"type\":\"hello\",\"data\":\"%2hd\"}";
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
	char *proto = "chat";
	int maxclients = 50;
	const char *username = str_username;
	int options = 0;

	int opt;
	do
	{
		opt = getopt(argc, argv, "u:R:m:wh");
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
			case 'w':
				options |= WS_MSG;
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
			chmod(addr.sun_path, 0777);
			ret = listen(sock, maxclients);
		}
		if (ret == 0)
		{
			int newsock = 0;
			do
			{
				fd_set rfds;
				int maxfd = sock;
				FD_ZERO(&rfds);
				FD_SET(sock, &rfds);
				user_t *user = first_user;
				while (user)
				{
					FD_SET(user->sock, &rfds);
					maxfd = (maxfd < user->sock)?user->sock:maxfd;
					user = user->next;
				}
				ret = select(maxfd + 1, &rfds, NULL, NULL, NULL);
				if (ret > 0)
				{
					if (FD_ISSET(sock, &rfds))
					{
						struct sockaddr_storage addr;
						int addrsize = sizeof(addr);
						newsock = accept(sock, (struct sockaddr *)&addr, &addrsize);
						if (newsock > 0)
						{
							user_t *user = calloc(1, sizeof(*user));
							user->identity = calloc(1, sizeof(*(user->identity)));
							user->sock = newsock;
							user->next = first_user;
							if (first_user)
								first_user->prev = user;
							first_user = user;	
							if (addr.ss_family == AF_INET)
							{
								struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
								warn("chat: new connection from %s %p", inet_ntoa(addr_in->sin_addr), user);
							}
							/*
							char *buffer = calloc(1, strlen(str_hello) + 1);	
							sprintf(buffer, str_hello, newsock);
							privatemsg(user, buffer, strlen(buffer));
							free(buffer);
							*/
						}
					}
					user_t *user = first_user;
					while (user)
					{
						if (FD_ISSET(user->sock, &rfds))
						{
							char buffer[512];
							int length = 512;
							length = read(user->sock, buffer, length);
							if ((length <= 0) && (errno != EAGAIN))
							{
								warn("chat: goodbye %p", user);
								if (user->prev)
								{
									user->prev->next = user->next;
								}
								else
									first_user = user->next;
								if (user->next)
									user->next->prev = user->prev;
								close(user->sock);
								if (user->identity)
									free(user->identity);
								free(user);
								break;
							}
							else if (length > 0)
							{
								dbg("chat: receive from %d : %s", user->sock, buffer);
								if (options & WS_MSG)
									chat(user, buffer, length);
								else
									chatmsg(user, buffer, length);
							}
						}
						user = user->next;
					}
				
				}
			} while(newsock > 0);
		}
		unlink(addr.sun_path);
	}
	if (ret)
	{
		err("chat: error %s\n", strerror(errno));
	}
	return ret;
}
