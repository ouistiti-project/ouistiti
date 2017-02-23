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

#include <libconfig.h>

#include "httpserver.h"

#include "mod_mbedtls.h"
#include "mod_static_file.h"
#include "mod_cgi.h"
#include "mod_authn.h"

#include "config.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
# define dbg(...)
#endif

config_t configfile;

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

					config_setting_t *configmbedtls = config_setting_lookup(iterator, "mbedtls");
					if (configmbedtls)
					{
						config->mbedtls = calloc(1, sizeof(*config->mbedtls));
						config_setting_lookup_string(configmbedtls, "pers", (const char **)&config->mbedtls->pers);
						config_setting_lookup_string(configmbedtls, "crtfile", (const char **)&config->mbedtls->crtfile);
						config_setting_lookup_string(configmbedtls, "pemfile",(const char **) &config->mbedtls->pemfile);
						config_setting_lookup_string(configmbedtls, "cachain", (const char **)&config->mbedtls->cachain);
						config_setting_lookup_string(configmbedtls, "dhmfile", (const char **)&config->mbedtls->dhmfile);
					}

					config_setting_t *configstaticfile = config_setting_lookup(iterator, "static_file");
					if (configstaticfile)
					{
						config->static_file = calloc(1, sizeof(*config->static_file));
						config_setting_lookup_string(configstaticfile, "docroot", (const char **)&config->static_file->docroot);
						config_setting_lookup_string(configstaticfile, "accepted_ext", (const char **)&config->static_file->accepted_ext);
						config_setting_lookup_string(configstaticfile, "ignored_ext", (const char **)&config->static_file->ignored_ext);
					}

					config_setting_t *configauthn = config_setting_lookup(iterator, "authn");
					if (configauthn)
					{
						config->authn = calloc(1, sizeof(*config->authn));
						config_setting_lookup_string(configauthn, "realm", (const char **)&config->authn->realm);
						config_setting_lookup_string(configauthn, "user", (const char **)&config->authn->user);
						config_setting_lookup_string(configauthn, "passwd", (const char **)&config->authn->passwd);
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
	config_destroy(&configfile);

	for (i = 0; i < MAX_SERVERS; i++)
	{
		serverconfig_t *config = ouistiticonfig->servers[i];
		if (ouistiticonfig->servers[i])
		{
			if (config->server)
				free(config->server);
			if (config->mbedtls)
				free(config->mbedtls);
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
