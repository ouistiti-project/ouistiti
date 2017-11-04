/*****************************************************************************
 * main.c: main entry file
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
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>

#ifndef WIN32
# include <sys/socket.h>
# include <sys/types.h>
# include <unistd.h>
# include <fcntl.h>
# define HAVE_GETOPT
# define HAVE_PWD_H
# ifdef HAVE_PWD_H
#  include <pwd.h>
#  include <grp.h>
# endif
#else
# include <winsock2.h>
#endif

#include "httpserver/httpserver.h"

#include "httpserver/mod_mbedtls.h"
#include "httpserver/mod_websocket.h"
#include "mod_static_file.h"
#include "mod_filestorage.h"
#include "mod_cgi.h"
#include "mod_auth.h"
#include "mod_vhosts.h"
#include "mod_methodlock.h"
#include "mod_server.h"

#if defined WEBSOCKET
extern int ouistiti_websocket_run(void *arg, int socket, char *protocol, http_message_t *request);
#endif

#include "config.h"
#include "../version.h"

#define PACKAGEVERSION PACKAGE "/" VERSION
#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

#define DEFAULT_CONFIGPATH sysconfdir"/ouistiti.conf"

typedef struct server_s
{
	serverconfig_t *config;
	http_server_t *server;
	void *mod_mbedtls;
	void *mod_static_file;
	void *mod_filestorage;
	void *mod_cgi;
	void *mod_auth;
	void *mod_methodlock;
	void *mod_server;
	void *mod_websocket;
	void *mod_vhosts[MAX_SERVERS - 1];

	struct server_s *next;
} servert_t;

void display_help(char * const *argv)
{
	fprintf(stderr, "%s [-h][-V][-f <configfile>]\n", argv[0]);
	fprintf(stderr, "\t-h \tshow this help and exit\n");
	fprintf(stderr, "\t-V \treturn the version and exit\n");
	fprintf(stderr, "\t-f <configfile>\tset the configuration file path\n");
}

static servert_t *first = NULL;
static char run = 0;
static void
handler(int sig, siginfo_t *si, void *arg)
{
	run = 'q';
	servert_t *server = arg;
	server = first;

	while (server != NULL)
	{
		if (server->server)
			httpserver_disconnect(server->server);
		server = server->next;
	}
}

static char servername[] = PACKAGEVERSION;
int main(int argc, char * const *argv)
{
	struct passwd *user = NULL;
	struct group *grp = NULL;
	servert_t *server;
	char *configfile = DEFAULT_CONFIGPATH;
	ouistiticonfig_t *ouistiticonfig;
	serverconfig_t *it;
	int i;
	int daemonize = 0;

	setbuf(stdout, NULL);

	httpserver_software = servername;

#ifdef HAVE_GETOPT
	int opt;
	do
	{
		opt = getopt(argc, argv, "f:hDV");
		switch (opt)
		{
			case 'f':
				configfile = optarg;
			break;
			case 'h':
				display_help(argv);
				return -1;
			break;
			case 'V':
				printf("%s\n",PACKAGEVERSION);
				return -1;
			break;
			case 'D':
				daemonize = 1;
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

	if (daemonize && fork() != 0)
	{
		return 0;
	}

	struct sigaction action;
	action.sa_flags = SA_SIGINFO;
	sigemptyset(&action.sa_mask);
	action.sa_sigaction = handler;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);

#ifdef HAVE_PWD_H
	if (ouistiticonfig->user)
	{
		user = getpwnam(ouistiticonfig->user);
		if (user == NULL)
		{
			fprintf(stderr, "Error: start as root\n");
			return -1;
		}
		grp = getgrgid(user->pw_gid);
		if (grp == NULL)
		{
			fprintf(stderr, "Error: start as root\n");
			return -1;
		}
	}
#endif
	for (i = 0, it = ouistiticonfig->servers[i]; it != NULL; i++, it = ouistiticonfig->servers[i])
	{
		server = calloc(1, sizeof(*server));
		server->config = it;

		server->server = httpserver_create(server->config->server);
		server->next = first;
		first = server;
	}
	server = first;

	while (server != NULL)
	{
		if (server->server)
		{
#if defined VHOSTS
			for (i = 0; i < (MAX_SERVERS - 1); i++)
			{
				if (server->config->vhosts[i])
					server->mod_vhosts[i] = mod_vhost_create(server->server,server->config->vhosts[i]);
			}
#endif
#if defined AUTH
			if (server->config->auth)
			{
				server->mod_auth = mod_auth_create(server->server, NULL, server->config->auth);
			}
#endif
#if defined METHODLOCK
			server->mod_methodlock = mod_methodlock_create(server->server, NULL, server->config->unlock_groups);
#endif
#if defined SERVERHEADER
			server->mod_server = mod_server_create(server->server, NULL, NULL);
#endif
#if defined CGI
			if (server->config->cgi)
				server->mod_cgi = mod_cgi_create(server->server, NULL, server->config->cgi);
#endif
#if defined WEBSOCKET
			if (server->config->websocket)
			{
				mod_websocket_run_t run = default_websocket_run;
#if defined WEBSOCKET_RT
				/**
				 * ouistiti_websocket_run is more efficient than
				 * default_websocket_run. But it doesn't run with TLS
				 **/
				if (server->config->websocket->options & WEBSOCKET_REALTIME)
					run = ouistiti_websocket_run;
#endif
				server->mod_websocket = mod_websocket_create(server->server,
					NULL, server->config->websocket,
					run, server->config->websocket);
			}
#endif
#if defined MBEDTLS
			if (server->config->tls)
				server->mod_mbedtls = mod_mbedtls_create(server->server, server->config->tls);
#endif
#if defined FILESTORAGE
			if (server->config->filestorage)
				server->mod_filestorage = mod_filestorage_create(server->server, NULL, server->config->filestorage);
#endif
#if defined STATIC_FILE
			if (server->config->static_file)
				server->mod_static_file = mod_static_file_create(server->server, NULL, server->config->static_file);
#endif
		}
		server = server->next;
	}

#ifdef HAVE_PWD_H
	setgid(user->pw_gid);
	setuid(user->pw_uid);
#endif
	server = first;

	/**
	 * connection must be after the owner change
	 */
	while (server != NULL)
	{
		if (server->server)
		{
			httpserver_connect(server->server);
		}
		server = server->next;
	}

	while(run != 'q') sleep(120);

	server = first;
	while (server != NULL)
	{
		servert_t *next = server->next;
#if defined MBEDTLS
		if (server->mod_mbedtls)
			mod_mbedtls_destroy(server->mod_mbedtls);
#endif
#if defined STATIC_FILE
		if (server->mod_static_file)
			mod_static_file_destroy(server->mod_static_file);
#endif
#if defined FILESTORAGE
		if (server->mod_filestorage)
			mod_filestorage_destroy(server->mod_filestorage);
#endif
#if defined METHODLOCK
		if (server->mod_methodlock)
			mod_methodlock_destroy(server->mod_methodlock);
#endif
#if defined SERVERHEADER
		if (server->mod_server)
			mod_server_destroy(server->mod_server);
#endif
#if defined WEBSOCKET
		if (server->mod_websocket)
			mod_websocket_destroy(server->mod_websocket);
#endif
#if defined CGI
		if (server->mod_cgi)
			mod_cgi_destroy(server->mod_cgi);
#endif
#if defined AUTH
		if (server->mod_auth)
			mod_auth_destroy(server->mod_auth);
#endif
#if defined VHOSTS
		for (i = 0; i < (MAX_SERVERS - 1); i++)
		{
			if (server->mod_vhosts[i])
				mod_vhost_destroy(server->mod_vhosts[i]);
		}
#endif
		httpserver_disconnect(server->server);
		httpserver_destroy(server->server);
		free(server);
		server = next;
	}
#ifndef STATIC_CONFIG
	ouistiticonfig_destroy(ouistiticonfig);
#endif
	return 0;
}
