/*****************************************************************************
 * jsonrpc.c: json RPC server
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
#define _POSIX_C_SOURCE 199309L

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
#include <sched.h>
#include <sys/stat.h>
#ifdef MODULES
#include <dlfcn.h>
#endif
#include <time.h>

#include "../websocket.h"
#include "jsonrpc.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

typedef int (*server_t)(int sock);

int jsonrpc_runner(int sock,
	struct jsonrpc_method_entry_t *methods_table, void *methods_context)
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
			char buffer[1500];
			ret = recv(sock, buffer, 1500, MSG_NOSIGNAL);
			err("recv %d", ret);
			if (ret > 0)
			{
				// remove the null terminated
				ret--;
				printf("echo: receive %d %s\n", ret, buffer);
				char *out = jsonrpc_handler(buffer, ret, methods_table, methods_context);
				ret = strlen(out) + 1;
				printf("echo: send %d %s\n", ret, out);
				ret = send(sock, out, ret, MSG_DONTWAIT | MSG_NOSIGNAL);
			}
		}
		if (ret == 0)
		{
			printf("echo: close from server\n");
			close(sock);
			sock = -1;
		}
		if (ret < 0)
		{
			if (errno != EAGAIN)
			{
				printf("echo: close %s\n", strerror(errno));
				close(sock);
				sock = -1;
			}
		}
	}
	return ret;
}

void help(char **argv)
{
	fprintf(stderr, "%s [-L <jsonlibrary>] [-C <jsonLibrary argument> [-R <socket directory>] [-n <socket name>] [-m <nb max clients>] [-u <user>][ -h]\n", argv[0]);
}

static char *g_library_config = NULL;
typedef void *(*jsonrpc_init_t)(struct jsonrpc_method_entry_t **, char *config);
typedef void (*jsonrpc_release_t)(void *ctx);
#ifdef MODULES
jsonrpc_init_t jsonrpc_init = NULL;
jsonrpc_release_t jsonrpc_release = NULL;
#else
extern jsonrpc_init_t jsonrpc_init;
extern jsonrpc_release_t jsonrpc_release;
#endif

int jsonrpc_server(int sock)
{
	struct jsonrpc_method_entry_t *table;
	dbg("jsonrpc: init");
	void *ctx = jsonrpc_init(&table, g_library_config);
	int ret = jsonrpc_runner(sock, table, ctx);
	dbg("jsonrpc: release");
	jsonrpc_release(ctx);
	return ret;
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
	struct timespec req = {0, 50000000};
	nanosleep(&req, NULL);
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
	const char *root = "/var/run/ouistiti";
	const char *name = "jsonrpc";
	int maxclients = 50;
	const char *username = NULL;
	int domain = SOCKDOMAIN;
	int proto = SOCKPROTOCOL;
	void *lhandler = NULL;

	int opt;
	do
	{
#ifdef WEBSOCKET_RT
		opt = getopt(argc, argv, "u:n:R:m:hrL:C:");
#else
		opt = getopt(argc, argv, "u:n:R:m:hL:C:");
#endif
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
				name = optarg;
			break;
			case 'r':
				domain = AF_WEBSOCKET;
				proto = WS_TEXT;
			break;
			case 'L':
#ifdef MODULES
				lhandler = dlopen(optarg, RTLD_LAZY);
				if (lhandler)
				{
					jsonrpc_init = (jsonrpc_init_t)dlsym(lhandler, "jsonrpc_init");
					jsonrpc_release = (jsonrpc_release_t)dlsym(lhandler, "jsonrpc_release");
				}
				else
				{
					err("library not found: %s", dlerror());
				}
#endif
			break;
			case 'C':
				g_library_config = optarg;
			break;
		}
	} while(opt != -1);

	if (jsonrpc_init == NULL)
	{
		help(argv);
		return -1;
	}

	if (access(root, R_OK|W_OK|X_OK))
	{
		if (mkdir(root, 0777))
		{
			err("access %s error %s", root, strerror(errno));
			return -1;
		}
		chmod(root, 0777);
	}

	if (getuid() == 0 && username != NULL)
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

	sock = socket(domain, SOCK_STREAM, proto);
	if (sock > 0)
	{
		struct sockaddr_un addr;
		memset(&addr, 0, sizeof(struct sockaddr_un));
		addr.sun_family = AF_UNIX;
		snprintf(addr.sun_path, sizeof(addr.sun_path) - 1, "%s/%s", root, name);
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
				struct sockaddr_un addr;
				int addrsize = sizeof(addr);
				newsock = accept(sock, (struct sockaddr *)&addr, &addrsize);
				printf("echo: new connection from %s\n", addr.sun_path);
				if (newsock > 0)
				{
					start(jsonrpc_server, newsock);
				}
			} while(newsock > 0);
		}
	}
	if (ret)
	{
		fprintf(stderr, "error : %s\n", strerror(errno));
	}
	if (lhandler != NULL)
		dlclose(lhandler);
	return ret;
}
