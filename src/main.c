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
# include <pwd.h>
# include <grp.h>
#else
# include <winsock2.h>
#endif
#ifdef MODULES
#include <dlfcn.h>
#endif

#include "../compliant.h"
#include "httpserver/httpserver.h"

#ifndef FILE_CONFIG
#define STATIC_CONFIG
#endif
#include "httpserver/mod_tls.h"
#include "httpserver/mod_websocket.h"
#include "httpserver/mod_cookie.h"
#include "mod_document.h"
#include "mod_cgi.h"
#include "mod_auth.h"
#include "mod_vhosts.h"
#include "mod_methodlock.h"
#include "mod_server.h"
#include "mod_redirect404.h"
#include "mod_redirect.h"
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

#define DEFAULT_CONFIGPATH SYSCONFDIR"/ouistiti.conf"

static const char str_tls[] = "tls";
static const char str_vhost[] = "vhost";
static const char str_clientfilter[] = "clientfilter";
static const char str_cookie[] = "cookie";
static const char str_auth[] = "auth";
static const char str_methodlock[] = "methodlock";
static const char str_serverheader[] = "server";
static const char str_cgi[] = "cgi";
static const char str_document[] = "document";
static const char str_webstream[] = "webstream";
static const char str_websocket[] = "websocket";
static const char str_redirect[] = "redirect";
static const char str_redirect404[] = "redirect404";
static const char str_cors[] = "cors";

const char *auth_info(http_message_t *request, const char *key)
{
	const authsession_t *info = NULL;
	info = httpmessage_SESSION(request, str_auth, NULL);
	const char *value = NULL;

	if (info && !strcmp(key, "user"))
		value = (const char *)info->user;
	if (info && !strcmp(key, "group"))
		value = (const char *)info->group;
	if (info && !strcmp(key, "type"))
		value = (const char *)info->type;
	if (info && !strcmp(key, "home"))
		value = (const char *)info->home;
	return value;
}

#ifndef MODULES
static const module_t *modules[] =
{
#if defined TLS
	&mod_tls,
#endif
#if defined VHOSTS_DEPRECATED
	&mod_vhost,
#endif
#if defined CLIENTFILTER
	&mod_clientfilter,
#endif
#if defined COOKIE
	&mod_cookie,
#endif
#if defined AUTH
	&mod_auth,
#endif
#if defined METHODLOCK
	&mod_methodlock,
#endif
#if defined SERVERHEADER
	&mod_server,
#endif
#if defined CGI
	&mod_cgi,
#endif
#if defined DOCUMENT
	&mod_document,
#endif
#if defined WEBSTREAM
	&mod_webstream,
#endif
#if defined WEBSOCKET
	&mod_websocket,
#endif
#if defined REDIRECT
	&mod_redirect404,
	&mod_redirect,
#endif
#if defined CORS
	&mod_cors,
	NULL
#endif
};
#endif

typedef struct mod_s
{
	void *config;
	void (*destroy)(void*);
} mod_t;

#define MAX_MODULES 12
typedef struct server_s
{
	serverconfig_t *config;
	http_server_t *server;
	mod_t modules[MAX_MODULES + MAX_SERVERS];

	struct server_s *next;
} server_t;

void display_help(char * const *argv)
{
	fprintf(stderr, PACKAGE" "VERSION" build: "__DATE__" "__TIME__"\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "%s [-h][-V][-f <configfile>]\n", argv[0]);
	fprintf(stderr, "\t-h \t\tshow this help and exit\n");
	fprintf(stderr, "\t-V \t\treturn the version and exit\n");
	fprintf(stderr, "\t-f <configfile>\tset the configuration file path\n");
	fprintf(stderr, "\t-p <pidfile>\tset the file path to save the pid\n");
	fprintf(stderr, "\t-D \t\tto daemonize the server\n");
	fprintf(stderr, "\t-s <server num>\tselect a server into the configuration file\n");
}

static server_t *first = NULL;
static char run = 0;
#ifdef HAVE_SIGACTION
static void handler(int sig, siginfo_t *si, void *arg)
#else
static void handler(int sig)
#endif
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
		int pidfd = open(pidfile,O_RDWR|O_CREAT|O_TRUNC,0640);
		if (pidfd > 0)
		{
			char buffer[32];
			int length;
			pid_t pid = 1;

#ifdef HAVE_LOCKF
			if (lockf(pidfd, F_TLOCK,0)<0)
			{
				err("server already running");
				exit(0);
			}
#endif
			pid = getpid();
			length = snprintf(buffer, 32, "%d\n", pid);
			write(pidfd, buffer, length);
			/**
			 * the file must be open while the process is running
			close(pidfd);
			 */
		}
		else
		{
			err("pid file error %s", strerror(errno));
			pidfile = NULL;
		}
	}
}

void *loadmodule(const char *name, http_server_t *server, void *config, void (**destroy)(void*))
{
	void *mod = NULL;
#ifndef MODULES
	int i = 0;
	while (modules[i] != NULL)
	{
		if (!strcmp(modules[i]->name, name))
		{
			mod = modules[i]->create(server, config);
			*destroy = modules[i]->destroy;
			break;
		}
		i++;
	}
#else
	char file[512];
	snprintf(file, 511, PKGLIBDIR"/mod_%s.so", name);
	void *dh = dlopen(file, RTLD_LAZY | RTLD_GLOBAL);
	if (dh != NULL)
	{
		module_t *module = dlsym(dh, "mod_info");
		if (module && !strcmp(module->name, name))
		{
			mod = module->create(server, config);
			*destroy = module->destroy;
			dbg("module %s loaded", name);
		}
		else if (module)
			warn("module %s error : named %s", name, module->name);
		else
			err("module symbol error: %s", dlerror());
	}
	else
	{
		err("module %s loading error: %s", file, dlerror());
	}
#endif
	return mod;
}

static char servername[] = PACKAGEVERSION;
int main(int argc, char * const *argv)
{
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

#ifndef FILE_CONFIG
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

#ifdef HAVE_PWD
	uid_t   pw_uid = -1;
	gid_t   pw_gid;
	if (ouistiticonfig->user)
	{
		struct passwd *result;

		result = getpwnam(ouistiticonfig->user);
		if (result == NULL)
		{
			err("Error: user %s not found\n", ouistiticonfig->user);
			return -1;
		}
		pw_uid = result->pw_uid;
		pw_gid = result->pw_gid;
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
			int j = 0;
			/**
			 * TLS must be first to free the connection after all others modules
			 */
			if (server->config->tls)
				server->modules[j].config = loadmodule(str_tls, server->server, server->config->tls, &server->modules[j++].destroy);
			for (i = 0; i < (MAX_SERVERS - 1); i++)
			{
				if (server->config->vhosts[i])
					server->modules[j].config = loadmodule(str_vhost, server->server, server->config->vhosts[i], &server->modules[j++].destroy);
			}
			/**
			 * clientfilter must be at the beginning to stop the connection if necessary
			 */
			if (server->config->modules.clientfilter)
				server->modules[j].config = loadmodule(str_clientfilter, server->server, server->config->modules.clientfilter, &server->modules[j++].destroy);
			server->modules[j].config = loadmodule(str_cookie, server->server, NULL, &server->modules[j++].destroy);
			if (server->config->modules.cors)
				server->modules[j].config = loadmodule(str_cors, server->server, server->config->modules.cors, &server->modules[j++].destroy);
			if (server->config->modules.auth)
				server->modules[j].config = loadmodule(str_auth, server->server, server->config->modules.auth, &server->modules[j++].destroy);
#if defined(REDIRECT)
			if (server->config->modules.redirect)
				server->modules[j].config = loadmodule(str_redirect, server->server, server->config->modules.redirect, &server->modules[j++].destroy);
#endif
			server->modules[j].config = loadmodule(str_methodlock, server->server, server->config->unlock_groups, &server->modules[j++].destroy);
			server->modules[j].config = loadmodule(str_serverheader, server->server, NULL, &server->modules[j++].destroy);
			if (server->config->modules.cgi)
				server->modules[j].config = loadmodule(str_cgi, server->server, server->config->modules.cgi, &server->modules[j++].destroy);
			if (server->config->modules.webstream)
				server->modules[j].config = loadmodule(str_webstream, server->server, server->config->modules.webstream, &server->modules[j++].destroy);
			if (server->config->modules.websocket)
			{
#ifdef WEBSOCKET_RT
				if (((mod_websocket_t*)server->config->modules.websocket)->options & WEBSOCKET_REALTIME)
				{
					((mod_websocket_t*)server->config->modules.websocket)->run = ouistiti_websocket_run;
					warn("server %p runs realtime websocket!", server->server);
				}
#endif
				server->modules[j].config = loadmodule(str_websocket, server->server, server->config->modules.websocket, &server->modules[j++].destroy);
			}
			if (server->config->modules.document)
				server->modules[j].config = loadmodule(str_document, server->server, server->config->modules.document, &server->modules[j++].destroy);
#if defined(REDIRECT)
			if (server->config->modules.redirect)
			{
				server->modules[j].config = loadmodule(str_redirect404, server->server, NULL, &server->modules[j++].destroy);
				server->modules[j].config = loadmodule(str_redirect, server->server, server->config->modules.redirect, &server->modules[j++].destroy);
			}
#endif
			server->modules[j].config = NULL;
		}
		server = server->next;
	}

#ifdef HAVE_PWD
	if (pw_uid > 0)
	{
		setegid(pw_gid);
		if (seteuid(pw_uid))
			err("Error: start server as root");
	}
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
		int j = 0;
		while (server->modules[j].config)
		{
			if (server->modules[j].destroy)
				server->modules[j].destroy(server->modules[j].config);
			j++;
		}
		httpserver_disconnect(server->server);
		httpserver_destroy(server->server);
		free(server);
		server = next;
	}
#ifdef FILE_CONFIG
	ouistiticonfig_destroy(ouistiticonfig);
#endif
	return 0;
}
