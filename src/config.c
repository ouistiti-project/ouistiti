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

#include "httpserver.h"

#include "mod_mbedtls.h"
#include "mod_static_file.h"
#include "mod_cgi.h"
#include "mod_auth.h"
#include "authn_basic_conf.h"

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

					config_setting_t *configtls = config_setting_lookup(iterator, "mbedtls");
					if (configtls)
					{
						config->tls = calloc(1, sizeof(*config->tls));
						config_setting_lookup_string(configtls, "crtfile", (const char **)&config->tls->crtfile);
						config_setting_lookup_string(configtls, "pemfile",(const char **) &config->tls->pemfile);
						config_setting_lookup_string(configtls, "cachain", (const char **)&config->tls->cachain);
						config_setting_lookup_string(configtls, "dhmfile", (const char **)&config->tls->dhmfile);
					}

					config_setting_t *configstaticfile = config_setting_lookup(iterator, "static_file");
					if (configstaticfile)
					{
						config->static_file = calloc(1, sizeof(*config->static_file));
						config_setting_lookup_string(configstaticfile, "docroot", (const char **)&config->static_file->docroot);
						config_setting_lookup_string(configstaticfile, "accepted_ext", (const char **)&config->static_file->accepted_ext);
						config_setting_lookup_string(configstaticfile, "ignored_ext", (const char **)&config->static_file->ignored_ext);
						config_setting_lookup_string(configstaticfile, "transfer_type", (const char **)&config->static_file->transfertype);
					}

					config_setting_t *configauthn = config_setting_lookup(iterator, "authn");
					if (configauthn)
					{
						config->authn = calloc(1, sizeof(*config->authn));
						config_setting_lookup_string(configauthn, "realm", (const char **)&config->authn->realm);
						char *type = NULL;
						config_setting_lookup_string(configauthn, "type", (const char **)&type);
						if (type != NULL && !strncmp(type, "Basic", 5))
						{
							void *authn_basic_config = NULL;
							authn_rule_t *rule = NULL;
#ifdef AUTHN_BASIC_CONF
							authn_basic_config_t *authn_basic_config_config;
							authn_basic_config_config = calloc(1, sizeof(*authn_basic_config));
							config_setting_lookup_string(configauthn, "user", (const char **)&authn_basic_config_config->user);
							config_setting_lookup_string(configauthn, "passwd", (const char **)&authn_basic_config_config->passwd);
							authn_basic_config = authn_basic_config_config;
							rule = &authn_basic_rule;
#endif
							config->authn->rule = rule;
							config->authn->rule->config = authn_basic_config;
						}
					}

					config_setting_t *configcgi = config_setting_lookup(iterator, "cgi");
					if (configcgi)
					{
						config->cgi = calloc(1, sizeof(*config->cgi));
						config_setting_lookup_string(configcgi, "docroot", (const char **)&config->cgi->docroot);
						config_setting_lookup_string(configcgi, "accepted_ext", (const char **)&config->cgi->accepted_ext);
						config_setting_lookup_string(configcgi, "ignored_ext", (const char **)&config->cgi->ignored_ext);
						config_setting_t *cgienv = config_setting_lookup(configcgi, "env");
						if (cgienv)
						{
							int count = config_setting_length(cgienv);
							int i;
							config->cgi->env = calloc(sizeof(char *), count);
							for (i = 0; i < count; i++)
							{
								config_setting_t *iterator = config_setting_get_elem(cgienv, i);
								config->cgi->env[i] = config_setting_get_string(iterator);
							}
							config->cgi->nbenvs = count;
						}
					}
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
			if (config->authn)
				free(config->authn);
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
