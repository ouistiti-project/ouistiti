/*****************************************************************************
 * config.c: configuration file parser
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
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <libconfig.h>

#include "httpserver/httpserver.h"

#include "httpserver/mod_mbedtls.h"
#include "httpserver/mod_websocket.h"
#include "mod_static_file.h"
#include "mod_cgi.h"
#include "mod_auth.h"
#include "mod_vhosts.h"

#include "config.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
# define dbg(...)
#endif

static config_t configfile;
static char *logfile = NULL;
static int logfd = 0;
static char *pidfile = NULL;
static int pidfd = 0;

#ifdef STATIC_FILE
static mod_static_file_t *static_file_config(config_setting_t *iterator)
{
	mod_static_file_t * static_file = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configstaticfile = config_setting_get_member(iterator, "static_file");
#else
	config_setting_t *configstaticfile = config_setting_lookup(iterator, "static_file");
#endif
	if (configstaticfile)
	{
		static_file = calloc(1, sizeof(*static_file));
		config_setting_lookup_string(configstaticfile, "docroot", (const char **)&static_file->docroot);
		config_setting_lookup_string(configstaticfile, "accepted_ext", (const char **)&static_file->accepted_ext);
		config_setting_lookup_string(configstaticfile, "ignored_ext", (const char **)&static_file->ignored_ext);
		config_setting_lookup_string(configstaticfile, "transfer_type", (const char **)&static_file->transfertype);
	}
	return static_file;
}
#else
#define static_file_config(...) NULL
#endif

#if defined(MBEDTLS)
static mod_tls_t *tls_config(config_setting_t *iterator)
{
	mod_tls_t *tls = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configtls = config_setting_get_member(iterator, "tls");
#else
	config_setting_t *configtls = config_setting_lookup(iterator, "tls");
#endif
	if (configtls)
	{
		tls = calloc(1, sizeof(*tls));
		config_setting_lookup_string(configtls, "crtfile", (const char **)&tls->crtfile);
		config_setting_lookup_string(configtls, "pemfile",(const char **) &tls->pemfile);
		config_setting_lookup_string(configtls, "cachain", (const char **)&tls->cachain);
		config_setting_lookup_string(configtls, "dhmfile", (const char **)&tls->dhmfile);
	}
	return tls;
}
#else
#define tls_config(...) NULL
#endif

#ifdef AUTH
static mod_auth_t *auth_config(config_setting_t *iterator)
{
	mod_auth_t *auth = NULL;
#if LIBCONFIG_VER_MINOR < 5
					config_setting_t *configauth = config_setting_get_member(iterator, "auth");
#else
					config_setting_t *configauth = config_setting_lookup(iterator, "auth");
#endif
	if (configauth)
	{
		auth = calloc(1, sizeof(*auth));
		config_setting_lookup_string(configauth, "realm", (const char **)&auth->realm);
#ifdef AUTHZ_SIMPLE
		char *user = NULL;
		int rights = 5;
		config_setting_lookup_string(configauth, "user", (const char **)&user);
		if (user == NULL || user[0] == '0')
		{
			config_setting_lookup_string(configauth, "superuser", (const char **)&user);
			rights = 11;
		}
		if (user != NULL && user[0] != '0')
		{
			char *passwd;
			config_setting_lookup_string(configauth, "passwd", (const char **)&passwd);
			auth->authz_type = AUTHZ_SIMPLE_E;
			authz_simple_config_t *authz_config = calloc(1, sizeof(*authz_config));
			authz_config->user = user;
			authz_config->passwd = passwd;
			authz_config->rights = rights;
			auth->authz_config = authz_config;
		}
#endif
		char *type = NULL;
		config_setting_lookup_string(configauth, "type", (const char **)&type);
#ifdef AUTHN_BASIC
		if (type != NULL && !strncmp(type, "Basic", 5))
		{
			authn_basic_config_t *authn_config = calloc(1, sizeof(*authn_config));
			auth->authn_type = AUTHN_BASIC_E;
			authn_config->realm = auth->realm;
			auth->authn_config = authn_config;
		}
#endif
#ifdef AUTHN_DIGEST
		if (type != NULL && !strncmp(type, "Digest", 5))
		{
			authn_digest_config_t *authn_config = calloc(1, sizeof(*authn_config));
			auth->authn_type = AUTHN_DIGEST_E;
			authn_config->realm = auth->realm;
			config_setting_lookup_string(configauth, "opaque", (const char **)&authn_config->opaque);
			auth->authn_config = authn_config;
		}
#endif
	}
	return auth;
}
#else
#define auth_config(...) NULL
#endif

#ifdef CGI
static mod_cgi_config_t *cgi_config(config_setting_t *iterator)
{
	mod_cgi_config_t *cgi = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configcgi = config_setting_get_member(iterator, "cgi");
#else
	config_setting_t *configcgi = config_setting_lookup(iterator, "cgi");
#endif
	if (configcgi)
	{
		cgi = calloc(1, sizeof(*cgi));
		config_setting_lookup_string(configcgi, "docroot", (const char **)&cgi->docroot);
		config_setting_lookup_string(configcgi, "accepted_ext", (const char **)&cgi->accepted_ext);
		config_setting_lookup_string(configcgi, "ignored_ext", (const char **)&cgi->ignored_ext);
		cgi->nbenvs = 0;
#if LIBCONFIG_VER_MINOR < 5
		config_setting_t *cgienv = config_setting_get_member(configcgi, "env");
#else
		config_setting_t *cgienv = config_setting_lookup(configcgi, "env");
#endif
		if (cgienv)
		{
			int count = config_setting_length(cgienv);
			int i;
			cgi->env = calloc(sizeof(char *), count);
			for (i = 0; i < count; i++)
			{
				config_setting_t *iterator = config_setting_get_elem(cgienv, i);
				cgi->env[i] = config_setting_get_string(iterator);
			}
			cgi->nbenvs = count;
		}
	}
	return cgi;
}
#else
#define cgi_config(...) NULL
#endif

#ifdef WEBSOCKET
static mod_websocket_t *websocket_config(config_setting_t *iterator)
{
	mod_websocket_t *ws = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configws = config_setting_get_member(iterator, "websocket");
#else
	config_setting_t *configws = config_setting_lookup(iterator, "websocket");
#endif
	if (configws)
	{
		ws = calloc(1, sizeof(*ws));
		config_setting_lookup_string(configws, "protocols", (const char **)&ws->services);
		config_setting_lookup_string(configws, "root", (const char **)&ws->path);
	}
	return ws;
}
#else
#define websocket_config(...) NULL
#endif

#ifdef VHOSTS
static mod_vhost_t *vhost_config(config_setting_t *iterator)
{
	mod_vhost_t *vhost = NULL;
	char *hostname;

	config_setting_lookup_string(iterator, "hostname", (const char **)&hostname);
	if (hostname && hostname[0] != '0')
	{
		vhost = calloc(1, sizeof(*vhost));
		vhost->hostname = hostname;
		vhost->static_file = static_file_config(iterator);
		vhost->auth = auth_config(iterator);
		vhost->cgi = cgi_config(iterator);
		vhost->websocket = websocket_config(iterator);
	}
	else
	{
		warn("vhost configuration without hostname");
	}

	return vhost;
}
#else
#define vhost_config(...) NULL
#endif

ouistiticonfig_t *ouistiticonfig_create(char *filepath)
{
	int ret;
	ouistiticonfig_t *ouistiticonfig = NULL;

	config_init(&configfile);
	ret = config_read_file(&configfile, filepath);
	if (ret == CONFIG_TRUE)
	{
		ouistiticonfig = calloc(1, sizeof(*ouistiticonfig));

		config_lookup_string(&configfile, "user", (const char **)&ouistiticonfig->user);
		config_lookup_string(&configfile, "log-file", (const char **)&logfile);
		if (logfile != NULL && logfile[0] != '\0')
		{
			logfd = open(logfile, O_WRONLY | O_CREAT);
			if (logfd > 0)
			{
				dup2(logfd, 1);
				dup2(logfd, 2);
			}
			else
				err("log file error %s", strerror(errno));
		}
		config_lookup_string(&configfile, "pid-file", (const char **)&pidfile);
		if (pidfile != NULL && pidfile[0] != '\0')
		{
			pidfd = open(pidfile,O_RDWR|O_CREAT,0640);
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
			}
			else
			{
				err("pid file error %s", strerror(errno));
				pidfile = NULL;
			}
		}
		config_setting_t *configservers = config_lookup(&configfile, "servers");
		if (configservers)
		{
			int count = config_setting_length(configservers);
			int i;

			for (i = 0; i < count && i < MAX_SERVERS; i++)
			{
				config_setting_t *iterator = config_setting_get_elem(configservers, i);
				if (iterator)
				{
					ouistiticonfig->servers[i] = calloc(1, sizeof(*ouistiticonfig->servers[i]));
					serverconfig_t *config = ouistiticonfig->servers[i];

					config->server = calloc(1, sizeof(*config->server));

					config_setting_lookup_string(iterator, "hostname", (const char **)&config->server->hostname);
					config_setting_lookup_int(iterator, "port", &config->server->port);
					config_setting_lookup_string(iterator, "addr", (const char **)&config->server->addr);
					config_setting_lookup_int(iterator, "keepalivetimeout", &config->server->keepalive);
					config->server->chunksize = 64;
					config_setting_lookup_int(iterator, "chunksize", &config->server->chunksize);
					config->server->maxclients = 10;
					config_setting_lookup_int(iterator, "maxclients", &config->server->maxclients);
					config->server->version = HTTP11;
					const char *version = NULL;
					config_setting_lookup_string(iterator, "version", &version);
					if (version && !strncmp(version, "HTTP", 4))
					{
						if (version[4] == '0' && version[5] == '9')
							config->server->version = HTTP09;
						if (version[4] == '1' && version[5] == '0')
							config->server->version = HTTP09;
						if (version[6] == 'P' && version[7] == 'I' &&
							version[8] == 'P' && version[9] == 'E')
							config->server->version |= HTTP_PIPELINE;
					}
					config->tls = tls_config(iterator);
					config->static_file = static_file_config(iterator);
					config->auth = auth_config(iterator);
					config->cgi = cgi_config(iterator);
					config->websocket = websocket_config(iterator);
#ifdef VHOSTS
#if LIBCONFIG_VER_MINOR < 5
					config_setting_t *configvhosts = config_setting_get_member(iterator, "vhosts");
#else
					config_setting_t *configvhosts = config_setting_lookup(iterator, "vhosts");
#endif
					if (configvhosts)
					{
						int count = config_setting_length(configvhosts);
						int j;

						for (j = 0; j < count && (j + i) < MAX_SERVERS; i++)
						{
							config_setting_t *iterator = config_setting_get_elem(configvhosts, j);
							config->vhosts[j] = vhost_config(iterator);
						}
					}
#endif
				}
			}
			ouistiticonfig->servers[i] = NULL;
		}

	}
	else
		printf("%s\n", config_error_text(&configfile));
	return ouistiticonfig;
}

void ouistiticonfig_destroy(ouistiticonfig_t *ouistiticonfig)
{
	int i;

	if (pidfd > 0)
		close(pidfd);
	if (logfd > 0)
		close(logfd);
	config_destroy(&configfile);

	for (i = 0; i < MAX_SERVERS; i++)
	{
		serverconfig_t *config = ouistiticonfig->servers[i];
		if (ouistiticonfig->servers[i])
		{
			if (config->server)
				free(config->server);
			if (config->tls)
				free(config->tls);
			if (config->static_file)
				free(config->static_file);
			if (config->websocket)
				free(config->websocket);
			if (config->auth)
			{
				if (config->auth->authn_config)
					free(config->auth->authn_config);
				if (config->auth->authz_config)
					free(config->auth->authz_config);
				free(config->auth);
			}
			if (config->cgi)
			{
				if (config->cgi->env)
					free(config->cgi->env);
				free(config->cgi);
			}
			free(ouistiticonfig->servers[i]);
			ouistiticonfig->servers[i] = NULL;
		}
	}

	free(ouistiticonfig);
}
