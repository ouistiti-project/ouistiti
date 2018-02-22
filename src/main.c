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
#include <errno.h>
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
#include "mod_redirect404.h"
#include "mod_webstream.h"

#if defined WEBSOCKET || defined WEBSTREAM
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
	void *mod_clientfilter;
	void *mod_methodlock;
	void *mod_server;
	void *mod_websocket;
	void *mod_redirect404;
	void *mod_webstream;
	void *mod_vhosts[MAX_SERVERS - 1];

	struct server_s *next;
} servert_t;

void display_help(char * const *argv)
{
	fprintf(stderr, "%s [-h][-V][-f <configfile>]\n", argv[0]);
	fprintf(stderr, "\t-h \tshow this help and exit\n");
	fprintf(stderr, "\t-V \treturn the version and exit\n");
	fprintf(stderr, "\t-f <configfile>\tset the configuration file path\n");
	fprintf(stderr, "\t-p <pidfile>\tset the file path to save the pid\n");
}

static servert_t *first = NULL;
static char run = 0;
static void handler(int sig, siginfo_t *si, void *arg)
{
	run = 'q';
	servert_t *server;
	server = first;

	while (server != NULL)
	{
		if (server->server)
		{
			httpserver_disconnect(server->server);
		}
		server = server->next;
	}
	kill(0, SIGPIPE);
}

static void _setpidfile(char *pidfile)
{
	if (pidfile[0] != '\0')
	{
		int pidfd = open(pidfile,O_RDWR|O_CREAT,0640);
		if (pidfd > 0)
		{
			char buffer[32];
			int length;
			pid_t pid = 1;

			if (lockf(pidfd, F_TLOCK,0)<0)
			{
				err("server already running");
				exit(0);
			}
			pid = getpid();
			length = snprintf(buffer, 32, "%d\n", pid);
			write(pidfd, buffer, length);
			close(pidfd);
		}
		else
		{
			err("pid file error %s", strerror(errno));
			pidfile = NULL;
		}
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
	char *pidfile = NULL;
	serverconfig_t *it;
	int i;
	int daemonize = 0;
	int serverid = -1;

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	httpserver_software = servername;

#ifdef HAVE_GETOPT
	int opt;
	do
	{
		opt = getopt(argc, argv, "s:f:p:hDV");
		switch (opt)
		{
			case 's':
				serverid = atoi(optarg) - 1;
			break;
			case 'f':
				configfile = optarg;
			break;
			case 'p':
				pidfile = optarg;
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

	if (daemonize && fork() != 0)
	{
		return 0;
	}

#ifdef STATIC_CONFIG
	ouistiticonfig = &g_ouistiticonfig;
#else
	ouistiticonfig = ouistiticonfig_create(configfile);
#endif

	if (ouistiticonfig == NULL)
		return -1;

	if (pidfile)
		_setpidfile(pidfile);
	else if (ouistiticonfig->pidfile)
		_setpidfile(ouistiticonfig->pidfile);

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
	if (serverid < 0)
	{
		for (i = 0, it = ouistiticonfig->servers[i]; it != NULL; i++, it = ouistiticonfig->servers[i])
		{
			server = calloc(1, sizeof(*server));
			server->config = it;

			server->server = httpserver_create(server->config->server);
			server->next = first;
			first = server;
		}
	}
	else
	{
		server = calloc(1, sizeof(*server));
		server->config = ouistiticonfig->servers[serverid];

		server->server = httpserver_create(server->config->server);
		server->next = NULL;
		first = server;
	}
	server = first;

	while (server != NULL)
	{
		if (server->server)
		{
#if defined MBEDTLS
			/**
			 * TLS must be first to free the connection after all others modules
			 */
			if (server->config->tls)
				server->mod_mbedtls = mod_mbedtls_create(server->server, server->config->tls);
#endif
#if defined VHOSTS
			for (i = 0; i < (MAX_SERVERS - 1); i++)
			{
				if (server->config->vhosts[i])
					server->mod_vhosts[i] = mod_vhost_create(server->server,server->config->vhosts[i]);
			}
#endif
#if defined CLIENTFILTER
			/**
			 * clientfilter must be at the beginning to stop the connection if necessary
			 */
			if (server->config->modules.clientfilter)
			{
				server->mod_clientfilter = mod_clientfilter_create(server->server, NULL, server->config->modules.clientfilter);
			}
#endif
#if defined AUTH
			if (server->config->modules.auth)
			{
				server->mod_auth = mod_auth_create(server->server, NULL, server->config->modules.auth);
			}
#endif
#if defined METHODLOCK
			server->mod_methodlock = mod_methodlock_create(server->server, NULL, server->config->unlock_groups);
#endif
#if defined SERVERHEADER
			server->mod_server = mod_server_create(server->server, NULL, NULL);
#endif
#if defined CGI
			if (server->config->modules.cgi)
				server->mod_cgi = mod_cgi_create(server->server, NULL, server->config->modules.cgi);
#endif
#if defined FILESTORAGE
			if (server->config->modules.filestorage)
				server->mod_filestorage = mod_filestorage_create(server->server, NULL, server->config->modules.filestorage);
#endif
#if defined STATIC_FILE
			if (server->config->modules.static_file)
				server->mod_static_file = mod_static_file_create(server->server, NULL, server->config->modules.static_file);
#endif
#if defined WEBSTREAM
			if (server->config->modules.webstream)
				server->mod_webstream = mod_webstream_create(server->server, NULL, 
							server->config->modules.webstream);
#endif
#if defined WEBSOCKET
			if (server->config->modules.websocket)
			{
				mod_websocket_run_t run = default_websocket_run;
#if defined WEBSOCKET_RT
				/**
				 * ouistiti_websocket_run is more efficient than
				 * default_websocket_run. But it doesn't run with TLS
				 **/
				if (server->config->modules.websocket->options & WEBSOCKET_REALTIME)
				{
					run = ouistiti_websocket_run;
					warn("server %p runs realtime websocket!", server->server);
				}
#endif
				server->mod_websocket = mod_websocket_create(server->server,
					NULL, server->config->modules.websocket,
					run, server->config->modules.websocket);
			}
#endif
#if defined REDIRECT404
			server->mod_redirect404 = mod_redirect404_create(server->server, NULL, server->config->modules.redirect404);
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

	while(run != 'q')
	{
		if (httpserver_run(first->server) == ESUCCESS)
			break;
	}

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
#if defined WEBSTREAM
		if (server->mod_webstream)
			mod_webstream_destroy(server->mod_webstream);
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
