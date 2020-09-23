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

#include "daemonize.h"
#include "../compliant.h"
#include "httpserver/httpserver.h"

#ifndef FILE_CONFIG
#define STATIC_CONFIG
#endif
#include "mod_tls.h"
#include "mod_websocket.h"
#include "mod_cookie.h"
#include "mod_document.h"
#include "mod_cgi.h"
#include "mod_auth.h"
#include "mod_vhosts.h"
#include "mod_methodlock.h"
#include "mod_server.h"
#include "mod_redirect404.h"
#include "mod_redirect.h"
#include "mod_webstream.h"
#include "mod_tinysvcmdns.h"

#include "ouistiti.h"

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
static const char str_vhosts[] = "vhosts";
static const char str_clientfilter[] = "clientfilter";
static const char str_cookie[] = "cookie";
static const char str_auth[] = "auth";
static const char str_userfilter[] = "userfilter";
static const char str_methodlock[] = "methodlock";
static const char str_serverheader[] = "server";
static const char str_cgi[] = "cgi";
static const char str_document[] = "document";
static const char str_webstream[] = "webstream";
static const char str_websocket[] = "websocket";
static const char str_redirect[] = "redirect";
static const char str_redirect404[] = "redirect404";
static const char str_cors[] = "cors";
static const char str_tinysvcmdns[] = "tinysvcmdns";
static const char str_upgrade[] = "upgrade";

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

int auth_setowner(const char *user)
{
	int ret = EREJECT;
#ifdef HAVE_PWD
	struct passwd *pw;
	pw = getpwnam(user);
	if (pw != NULL)
	{
		uid_t uid;
		uid = getuid();
		//only "saved set-uid", "uid" and "euid" may be set
		//first step: set the "saved set-uid" (root)
		if (seteuid(uid) < 0)
			warn("not enought rights to change user");
		//second step: set the new "euid"
		else if (setegid(pw->pw_gid) < 0)
			warn("not enought rights to change group");
		else if (seteuid(pw->pw_uid) < 0)
			warn("not enought rights to change user");
		else
			ret = ESUCCESS;
	}
#else
	ret = ESUCCESS;
#endif
	return ret;
}

#ifndef MODULES
static const module_t *modules[] =
{
#if defined TLS
	&mod_tls,
#endif
#if defined VHOSTS_DEPRECATED
	&mod_vhosts,
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
#if defined USERFILTER
	&mod_userfilter,
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
#endif
#if defined TINYSVCMDNS
	&mod_tinysvcmdns,
#endif
	NULL
};
#endif

typedef struct mod_s
{
	void *obj;
	module_t *ops;
} mod_t;

#define MAX_MODULES 16
struct server_s
{
	serverconfig_t *config;
	http_server_t *server;
	mod_t modules[MAX_MODULES + MAX_SERVERS];

	struct server_s *next;
	unsigned int id;
};

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
}

int ouistiti_issecure(server_t *server)
{
	return (server->config->tls != NULL);
}

int ouistiti_loadmodule(server_t *server, const char *name, configure_t configure, void *parser)
{
	int i = 0;
	mod_t *mod = &server->modules[i];
	while (i < MAX_MODULES && server->modules[i].obj != NULL)
		mod = &server->modules[++i];
	if (i == MAX_MODULES)
		return EREJECT;

#ifndef MODULES
	int i = 0;
	while (modules[i] != NULL)
	{
		if (!strcmp(modules[i]->name, name))
		{
			void *config = NULL;
			if (modules[i]->configure != NULL)
				config = modules[i]->configure(parser, server->config);
			else
				config = configure(parser, name, server->config);
			mod->obj = modules[i]->create(server->server, config);
			mod->ops = modules[i];
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
			void *config = NULL;
			if (module->configure != NULL)
				config = module->configure(parser, server);
			else
				config = configure(parser, name, server);
			mod->obj = module->create(server->server, config);
			mod->ops = module;
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
	return (mod->obj != NULL)?ESUCCESS:EREJECT;
}

int ouistiti_setmodules(server_t *server, configure_t configure, void *parser)
{
	ouistiti_loadmodule(server, str_tinysvcmdns, configure, parser);
	/**
	 * TLS must be first to free the connection after all others modules
	 */
	ouistiti_loadmodule(server, str_tls, configure, parser);
	/**
	 * clientfilter must be at the beginning to stop the connection if necessary
	 */
	ouistiti_loadmodule(server, str_clientfilter, configure, parser);

	int i;
	for (i = 0; i < (MAX_SERVERS - 1); i++)
	{
		ouistiti_loadmodule(server, str_vhosts, configure, parser);
	}
	ouistiti_loadmodule(server, str_cookie, configure, parser);
	ouistiti_loadmodule(server, str_cors, configure, parser);
	ouistiti_loadmodule(server, str_auth, configure, parser);
	ouistiti_loadmodule(server, str_userfilter, configure, parser);
	ouistiti_loadmodule(server, str_redirect404, configure, parser);
	ouistiti_loadmodule(server, str_redirect, configure, parser);
	ouistiti_loadmodule(server, str_methodlock, configure, parser);
	ouistiti_loadmodule(server, str_serverheader, configure, parser);
	ouistiti_loadmodule(server, str_cgi, configure, parser);
	ouistiti_loadmodule(server, str_webstream, configure, parser);
	ouistiti_loadmodule(server, str_upgrade, configure, parser);
	ouistiti_loadmodule(server, str_websocket, configure, parser);
	ouistiti_loadmodule(server, str_document, configure, parser);
	return 0;
}

server_t *ouistiti_loadserver(serverconfig_t *config)
{
	if (first != NULL && first->id == MAX_SERVERS)
		return NULL;

	http_server_t *httpserver = httpserver_create(config->server);
	if (httpserver == NULL)
		return NULL;

	server_t *server = NULL;
	server = calloc(1, sizeof(*server));

	server->server = httpserver;
	server->config = config;
	server->next = first;
	if (first != NULL)
		server->id = first->id + 1;
	first = server;
	return server;
}

static int main_run(server_t *first)
{
	server_t *server = first;
	/**
	 * connection must be after the owner change
	 */
	while (server != NULL)
	{
		httpserver_connect(server->server);
		server = server->next;
	}

	while(run != 'q')
	{
		if (first == NULL || first->server == NULL || httpserver_run(first->server) == ESUCCESS)
			break;
	}

	server = first;
	while (server != NULL)
	{
		server_t *next = server->next;
		int j = 0;
		while (server->modules[j].obj)
		{
			if (server->modules[j].ops->destroy)
				server->modules[j].ops->destroy(server->modules[j].obj);
			j++;
		}
		httpserver_disconnect(server->server);
		httpserver_destroy(server->server);
		free(server);
		server = next;
	}
	return 0;
}

#define DAEMONIZE 0x01
#define KILLDAEMON 0x02
static char servername[] = PACKAGEVERSION;
int main(int argc, char * const *argv)
{
	const char *configfile = DEFAULT_CONFIGPATH;
	ouistiticonfig_t *ouistiticonfig;
	const char *pidfile = NULL;
	int mode = 0;
	int serverid = -1;

	setlinebuf(stdout);
	setlinebuf(stderr);

	httpserver_software = servername;

#ifdef HAVE_GETOPT
	int opt;
	do
	{
		opt = getopt(argc, argv, "s:f:p:hDKV");
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
			case 'V':
				printf("%s\n",PACKAGEVERSION);
			return -1;
			case 'D':
				mode |= DAEMONIZE;
			break;
			case 'K':
				mode |= KILLDAEMON;
			break;
			default:
			break;
		}
	} while(opt != -1);
#endif

	if (mode & KILLDAEMON)
	{
		if (pidfile == NULL && ouistiticonfig && ouistiticonfig->pidfile)
		{
#ifdef STATIC_CONFIG
			ouistiticonfig = &g_ouistiticonfig;
#else
			ouistiticonfig = ouistiticonfig_create(configfile, serverid);
#endif
			pidfile = ouistiticonfig->pidfile;
		}
		killdaemon(pidfile);
		return 0;
	}

#ifdef STATIC_CONFIG
	ouistiticonfig = &g_ouistiticonfig;
#else
	ouistiticonfig = ouistiticonfig_create(configfile, serverid);
#endif

	if (mode & DAEMONIZE)
	{
		if (pidfile == NULL && ouistiticonfig && ouistiticonfig->pidfile)
			pidfile = ouistiticonfig->pidfile;
		if (daemonize(pidfile) == -1)
			return 0;
	}

	if (ouistiticonfig == NULL)
		return -1;

#ifdef HAVE_SIGACTION
	struct sigaction action;
	action.sa_flags = SA_SIGINFO;
	sigemptyset(&action.sa_mask);
	action.sa_sigaction = handler;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);

	struct sigaction unaction;
	unaction.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);
#else
	signal(SIGTERM, handler);
	signal(SIGINT, handler);

	signal(SIGPIPE, SIG_IGN);
#endif

	if (auth_setowner(ouistiticonfig->user) == EREJECT)
		err("Error: user %s not found\n", ouistiticonfig->user);

	main_run(first);

#ifdef FILE_CONFIG
	ouistiticonfig_destroy(ouistiticonfig);
#endif
	killdaemon(pidfile);
	warn("good bye");
	return 0;
}
