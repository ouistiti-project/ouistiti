/*****************************************************************************
 * main.c: main entry file
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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef WIN32
# include <pwd.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <unistd.h>
#else
# include <winsock2.h>
#endif

#include "httpserver.h"

#include "mod_mbedtls.h"
#include "mod_static_file.h"

#define __OUISTITI_CONFIG__
#include "config.h"

typedef struct server_s
{
	serverconfig_t *config;
	struct passwd *user;
	http_server_t *server;
	void *mod_mbedtls;
	void *mod_static_file;

	struct server_s *next;
} servert_t;
int main(int argc, char * const *argv)
{
	servert_t *server, *first = NULL;
	serverconfig_t *it;
	int i;

	setbuf(stdout, NULL);

	for (i = 0, it = config[i]; it != NULL; i++, it = config[i])
	{
		server = calloc(1, sizeof(*server));
		server->config = it;

		if (server->config->user)
		{
			server->user = getpwnam(server->config->user);
			if (server->user == NULL)
			{
				fprintf(stderr, "Error: start as root\n");
				return -1;
			}
		}

		server->server = httpserver_create(server->config->server);
		if (server->server)
		{
			httpserver_connect(server->server);
		}
		server->next = first;
		first = server;
	}
	server = first;
	while (server != NULL)
	{
		if (server->server)
		{
			if (server->config->mbedtls)
				server->mod_mbedtls = mod_mbedtls_create(server->server, server->config->mbedtls);
			if (server->config->static_file)
				server->mod_static_file = mod_static_file_create(server->server, server->config->static_file);
			if (server->user != NULL)
			{
				setgid(server->user->pw_gid);
				setuid(server->user->pw_uid);

			}
		}
		server = server->next;
	}
	while (1)
	{
		sleep(1);
	}
	server = first;
	while (server != NULL)
	{
		if (server->mod_mbedtls)
			mod_mbedtls_destroy(server->mod_mbedtls);
		if (server->mod_static_file)
			mod_static_file_destroy(server->mod_static_file);
		httpserver_disconnect(server->server);
		httpserver_destroy(server->server);
		server = server->next;
	}
	return 0;
}
