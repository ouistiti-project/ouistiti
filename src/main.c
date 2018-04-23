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

#include "httpserver/mod_tls.h"
#include "httpserver/mod_websocket.h"
#include "httpserver/mod_cookie.h"
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

static const char str_tls[] = "tls";
static const char str_vhost[] = "vhost";
static const char str_clientfilter[] = "clientfilter";
static const char str_cookie[] = "cookie";
static const char str_auth[] = "auth";
static const char str_methodlock[] = "methodlock";
static const char str_serverheader[] = "serverheader";
static const char str_cgi[] = "cgi";
static const char str_filestorage[] = "filestorage";
static const char str_static_file[] = "static_file";
static const char str_webstream[] = "webstream";
static const char str_websocket[] = "websocket";
static const char str_redirect404[] = "redirect404";

typedef struct mod_s
{
	void *config;
	void (*destroy)(void*);
} mod_t;

typedef struct server_s
{
	serverconfig_t *config;
	http_server_t *server;
	mod_t mod_tls;
	mod_t mod_cookie;
	mod_t mod_static_file;
	mod_t mod_filestorage;
	mod_t mod_cgi;
	mod_t mod_auth;
	mod_t mod_clientfilter;
	mod_t mod_methodlock;
	mod_t mod_server;
	mod_t mod_websocket;
	mod_t mod_redirect404;
	mod_t mod_webstream;
	mod_t mod_vhosts[MAX_SERVERS - 1];

	struct server_s *next;
} server_t;

void display_help(char * const *argv)
{
	fprintf(stderr, "%s [-h][-V][-f <configfile>]\n", argv[0]);
	fprintf(stderr, "\t-h \tshow this help and exit\n");
	fprintf(stderr, "\t-V \treturn the version and exit\n");
	fprintf(stderr, "\t-f <configfile>\tset the configuration file path\n");
	fprintf(stderr, "\t-p <pidfile>\tset the file path to save the pid\n");
}

static server_t *first = NULL;
static char run = 0;
static void handler(int sig, siginfo_t *si, void *arg)
{
	run = 'q';
	server_t *server;
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

void *loadmodule(const char *name, http_server_t * server, void *config, void (**destroy)(void*))
{
	void *mod;
#if defined TLS
	if (name == str_tls)
	{
		mod = mod_tls_create(server, config);
		*destroy = mod_tls_destroy;
	}
#endif
#if defined VHOSTS
	if (name == str_vhost)
	{
		mod = mod_vhost_create(server, config);
		*destroy = mod_vhost_destroy;
	}
#endif
#if defined CLIENTFILTER
	if (name == str_clientfilter)
	{
		mod = mod_clientfilter_create(server, NULL, config);
		*destroy = mod_clientfilter_destroy;
	}
#endif
#if defined COOKIE
	if (name == str_cookie)
	{
		mod = mod_cookie_create(server, NULL, config);
		*destroy = mod_cookie_destroy;
	}
#endif
#if defined AUTH
	if (name == str_auth)
	{
		mod = mod_auth_create(server, NULL, config);
		*destroy = mod_auth_destroy;
	}
#endif
#if defined METHODLOCK
	if (name == str_methodlock)
	{
		mod = mod_methodlock_create(server, NULL, config);
		*destroy = mod_methodlock_destroy;
	}
#endif
#if defined SERVERHEADER
	if (name == str_serverheader)
	{
		mod = mod_server_create(server, NULL, config);
		*destroy = mod_server_destroy;
	}
#endif
#if defined CGI
	if (name == str_serverheader)
	{
		mod = mod_cgi_create(server, NULL, config);
		*destroy = mod_server_destroy;
	}
#endif
#if defined FILESTORAGE
	if (name == str_filestorage)
	{
		mod = mod_filestorage_create(server, NULL, config);
		*destroy = mod_filestorage_destroy;
	}
#endif
#if defined STATIC_FILE
	if (name == str_static_file)
	{
		mod = mod_static_file_create(server, NULL, config);
		*destroy = mod_static_file_destroy;
	}
#endif
#if defined WEBSTREAM
	if (name == str_webstream)
	{
		mod = mod_webstream_create(server, NULL, config);
		*destroy = mod_webstream_destroy;
	}
#endif
#if defined WEBSOCKET
	if (name == str_websocket)
	{
		mod_websocket_run_t run = default_websocket_run;
#if defined WEBSOCKET_RT
		/**
		 * ouistiti_websocket_run is more efficient than
		 * default_websocket_run. But it doesn't run with TLS
		 **/
		if (((websocket_t*)config)->options & WEBSOCKET_REALTIME)
		{
			run = ouistiti_websocket_run;
			warn("server %p runs realtime websocket!", server->server);
		}
#endif
		mod = mod_websocket_create(server, NULL, config, run , config);
		*destroy = mod_websocket_destroy;
	}
#endif
#if defined REDIRECT404
	if (name == str_redirect404)
	{
		mod = mod_redirect404_create(server, NULL, config);
		*destroy = mod_redirect404_destroy;
	}
#endif

	return mod;
}

static char servername[] = PACKAGEVERSION;
int main(int argc, char * const *argv)
{
	struct passwd *user = NULL;
	struct group *grp = NULL;
	server_t *server;
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
			/**
			 * TLS must be first to free the connection after all others modules
			 */
			if (server->config->tls)
				server->mod_tls.config = loadmodule(str_tls, server->server, server->config->tls, &server->mod_tls.destroy);
			for (i = 0; i < (MAX_SERVERS - 1); i++)
			{
				if (server->config->vhosts[i])
					server->mod_vhosts[i].config = loadmodule(str_vhost, server->server, server->config->vhosts[i], &server->mod_vhosts[i].destroy);
			}
			/**
			 * clientfilter must be at the beginning to stop the connection if necessary
			 */
			if (server->config->modules.clientfilter)
				server->mod_clientfilter.config = loadmodule(str_clientfilter, server->server, server->config->modules.clientfilter, &server->mod_clientfilter.destroy);
			server->mod_cookie.config = loadmodule(str_cookie, server->server, NULL, &server->mod_cookie.destroy);
			if (server->config->modules.auth)
				server->mod_auth.config = loadmodule(str_auth, server->server, server->config->modules.auth, &server->mod_auth.destroy);
			server->mod_methodlock.config = loadmodule(str_methodlock, server->server, server->config->unlock_groups, &server->mod_methodlock.destroy);
			server->mod_server.config = loadmodule(str_serverheader, server->server, NULL, &server->mod_server.destroy);
			if (server->config->modules.cgi)
				server->mod_cgi.config = loadmodule(str_cgi, server->server, server->config->modules.cgi, &server->mod_cgi.destroy);
			if (server->config->modules.filestorage)
				server->mod_filestorage.config = loadmodule(str_filestorage, server->server, server->config->modules.filestorage, &server->mod_filestorage.destroy);
			if (server->config->modules.static_file)
				server->mod_static_file.config = loadmodule(str_static_file, server->server, server->config->modules.static_file, &server->mod_static_file.destroy);
			if (server->config->modules.webstream)
				server->mod_webstream.config = loadmodule(str_webstream, server->server, server->config->modules.webstream, &server->mod_webstream.destroy);
			if (server->config->modules.websocket)
				server->mod_websocket.config = loadmodule(str_websocket, server->server, server->config->modules.websocket, &server->mod_websocket.destroy);
			server->mod_redirect404.config = loadmodule(str_redirect404, server->server, server->config->modules.redirect404, &server->mod_redirect404.destroy);
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
		server_t *next = server->next;
		if (server->mod_tls.destroy && server->mod_tls.config)
			server->mod_tls.destroy(server->mod_tls.config);
		if (server->mod_static_file.destroy && server->mod_static_file.config)
			server->mod_static_file.destroy(server->mod_static_file.config);
		if (server->mod_filestorage.destroy && server->mod_filestorage.config)
			server->mod_filestorage.destroy(server->mod_filestorage.config);
		if (server->mod_methodlock.destroy && server->mod_methodlock.config)
			server->mod_methodlock.destroy(server->mod_methodlock.config);
		if (server->mod_server.destroy && server->mod_server.config)
			server->mod_server.destroy(server->mod_server.config);
		if (server->mod_websocket.destroy && server->mod_websocket.config)
			server->mod_websocket.destroy(server->mod_websocket.config);
		if (server->mod_cgi.destroy && server->mod_cgi.config)
			server->mod_cgi.destroy(server->mod_cgi.config);
		if (server->mod_webstream.destroy && server->mod_webstream.config)
			server->mod_webstream.destroy(server->mod_webstream.config);
		if (server->mod_auth.destroy && server->mod_auth.config)
			server->mod_auth.destroy(server->mod_auth.config);
		if (server->mod_cookie.destroy && server->mod_cookie.config)
			server->mod_cookie.destroy(server->mod_cookie.config);
		for (i = 0; i < (MAX_SERVERS - 1); i++)
		{
			if (server->mod_vhosts[i].destroy && server->mod_vhosts[i].config)
				server->mod_vhosts[i].destroy(server->mod_vhosts[i].config);
		}
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
