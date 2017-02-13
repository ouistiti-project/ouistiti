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
# define HAVE_GETOPT
#else
# include <winsock2.h>
#endif

#include "httpserver.h"

#include "mod_mbedtls.h"
#include "mod_static_file.h"
#include "mod_cgi.h"

#include "config.h"

#define DEFAULT_CONFIGPATH sysconfdir"/ouistiti.conf"

typedef struct server_s
{
	serverconfig_t *config;
	http_server_t *server;
	void *mod_mbedtls;
	void *mod_static_file;
	void *mod_cgi;

	struct server_s *next;
} servert_t;

void display_help(char * const *argv)
{
	fprintf(stderr, "%s [-f <configfile>]\n", argv[0]);
	fprintf(stderr, "\t-f <configfile>\tset the cofniguration file path\n");
}

int main(int argc, char * const *argv)
{
	struct passwd *user;
	servert_t *server, *first = NULL;
	char *configfile = DEFAULT_CONFIGPATH;
	ouistiticonfig_t *ouistiticonfig;
	serverconfig_t *it;
	int i;

	setbuf(stdout, NULL);

#ifdef HAVE_GETOPT
	int opt;
	do
	{
		opt = getopt(argc, argv, "f:");
		switch (opt)
		{
			case 'f':
				configfile = optarg;
			break;
			case 'h':
				display_help(argv);
				return -1;
			break;
		}
	} while(opt != -1);
#endif
#ifdef STATIC_CONFIG
	ouistiticonfig = &g_ouistiticonfig;
#else
	ouistiticonfig = ouistiticonfig_create(configfile);
#endif

	if (ouistiticonfig == NULL)
		return -1;

	if (ouistiticonfig->user)
	{
		user = getpwnam(ouistiticonfig->user);
		if (user == NULL)
		{
			fprintf(stderr, "Error: start as root\n");
			return -1;
		}
	}

	if (ouistiticonfig->servers)
	{
		for (i = 0, it = ouistiticonfig->servers[i]; it != NULL; i++, it = ouistiticonfig->servers[i])
		{
			server = calloc(1, sizeof(*server));
			server->config = it;

			server->server = httpserver_create(server->config->server);
			if (server->server)
			{
				httpserver_connect(server->server);
			}
			server->next = first;
			first = server;
		}
	}
	server = first;
	while (server != NULL)
	{
		if (server->server)
		{
#ifdef CGI
			if (server->config->cgi)
				server->mod_cgi = mod_cgi_create(server->server, server->config->cgi);
#endif
#ifdef MBEDTLS
			if (server->config->mbedtls)
				server->mod_mbedtls = mod_mbedtls_create(server->server, server->config->mbedtls);
#endif
			if (server->config->static_file)
				server->mod_static_file = mod_static_file_create(server->server, server->config->static_file);
		}
		server = server->next;
	}
	setgid(user->pw_gid);
	setuid(user->pw_uid);
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
#ifndef STATIC_CONFIG
	ouistiticonfig_destroy(ouistiticonfig);
#endif
	return 0;
}
