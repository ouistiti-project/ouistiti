/*****************************************************************************
 * config.c: configuration file parser
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
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

#include <libconfig.h>

#include "httpserver/httpserver.h"
#include "httpserver/utils.h"

#include "mod_tls.h"
#include "mod_websocket.h"
#include "mod_webstream.h"
#include "mod_document.h"
#include "mod_cgi.h"
#include "mod_auth.h"
#include "mod_vhosts.h"
#include "mod_cors.h"
#include "mod_upgrade.h"
#include "mod_userfilter.h"
#include "mod_clientfilter.h"
#include "mod_redirect.h"

#include "ouistiti.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
# define dbg(...)
#endif

char str_hostname[HOST_NAME_MAX + 7];

static config_t configfile;
static char *logfile = NULL;
static int logfd = 0;

typedef void (*_parsercb_t)(void *arg, const char *option, size_t length);

static void config_mimes(config_setting_t *configmimes)
{
	if (configmimes == NULL)
		return;

	int count = config_setting_length(configmimes);
	int i;
	for (i = 0; i < count; i++)
	{
		char *ext = NULL;
		char *mime = NULL;
		config_setting_t *iterator = config_setting_get_elem(configmimes, i);
		if (iterator)
		{
			config_setting_lookup_string(iterator, "ext", (const char **)&ext);
			config_setting_lookup_string(iterator, "mime", (const char **)&mime);
			if (mime != NULL && ext != NULL)
			{
				utils_addmime(ext, mime);
			}
		}
	}
}

static serverconfig_t *config_server(config_setting_t *iterator)
{
	serverconfig_t *config = calloc(1, sizeof(*config));

	config->server = calloc(1, sizeof(*config->server));
	char *hostname = NULL;
	config_setting_lookup_string(iterator, "hostname", (const char **)&hostname);
	if (hostname && strchr(hostname, '.') == NULL)
	{
		err("hostname must contain the domain");
	}
	else if (hostname == NULL)
	{
		hostname = str_hostname;
	}
	warn("hostname %s", hostname);
	config->server->hostname = hostname;
	config->server->port = 80;
	config_setting_lookup_int(iterator, "port", &config->server->port);
	config_setting_lookup_string(iterator, "addr", (const char **)&config->server->addr);
	config_setting_lookup_int(iterator, "keepalivetimeout", &config->server->keepalive);
	config->server->chunksize = DEFAULT_CHUNKSIZE;
	config_setting_lookup_int(iterator, "chunksize", &config->server->chunksize);
	config->server->maxclients = DEFAULT_MAXCLIENTS;
	config_setting_lookup_int(iterator, "maxclients", &config->server->maxclients);
	config->server->version = HTTP11;
	const char *version = NULL;
	config_setting_lookup_string(iterator, "version", &version);
	if (version)
	{
		int i = 0;
		for (i = 0; httpversion[i] != NULL; i++)
		{
			if (!strcmp(version,  httpversion[i]))
			{
				config->server->version = i;
				break;
			}
		}
	}
	config->server->versionstr = httpversion[config->server->version];
	return config;
}

static struct _config_module_s
{
	const char *name;
	void *(*configure)(config_setting_t *iterator, server_t *server);
} list_config_modules [] =
{
	{
		.name = "end",
	}
};
static void *_config_modules(void *data, const char *name, server_t *server)
{
	config_setting_t *iterator = (config_setting_t *)data;
	void *mod = NULL;
	int i;
	for (i = 0; i < sizeof(list_config_modules)/ sizeof(struct _config_module_s); i++)
	{
		if (!strcmp(name, list_config_modules[i].name))
			mod = list_config_modules[i].configure(iterator, server);
	}
	return mod;
}

ouistiticonfig_t *ouistiticonfig_create(const char *filepath, int serverid)
{
	int ret;

	gethostname(str_hostname, HOST_NAME_MAX);
	strncat(str_hostname, ".local", 7);

	if (access(filepath, R_OK))
	{
		err("config file: %s not found", filepath);
		return NULL;
	}
	config_init(&configfile);
	dbg("config file: %s", filepath);
	ret = config_read_file(&configfile, filepath);
	if (ret != CONFIG_TRUE)
	{
		err("%s", config_error_text(&configfile));
		return NULL;
	}
	ouistiticonfig_t *ouistiticonfig = calloc(1, sizeof(*ouistiticonfig));

	config_lookup_string(&configfile, "user", (const char **)&ouistiticonfig->user);
	config_lookup_string(&configfile, "log-file", (const char **)&logfile);
	if (logfile != NULL && logfile[0] != '\0')
	{
		logfd = open(logfile, O_WRONLY | O_CREAT | O_TRUNC, 00644);
		if (logfd > 0)
		{
			dup2(logfd, 1);
			dup2(logfd, 2);
			close(logfd);
		}
		else
			err("log file error %s", strerror(errno));
	}
	config_lookup_string(&configfile, "pid-file", (const char **)&ouistiticonfig->pidfile);
	config_setting_t *configmimes = config_lookup(&configfile, "mimetypes");
	config_mimes(configmimes);
	config_setting_t *configservers = config_lookup(&configfile, "servers");
	if (configservers)
	{
		int count = config_setting_length(configservers);
		int i = 0;

		if (serverid != -1)
		{
			i = serverid;
			count = 1;
			if (serverid < count)
				serverid = 0;
		}

		for (; i < count && i < MAX_SERVERS; i++)
		{
			config_setting_t *iterator = config_setting_get_elem(configservers, i);
			if (iterator)
			{
				serverconfig_t *config = config_server(iterator);
				server_t *server = ouistiti_loadserver(config);
				ouistiti_setmodules(server, _config_modules, iterator);
			}
		}
		ouistiticonfig->servers[i] = NULL;
	}

	return ouistiticonfig;
}

void ouistiticonfig_destroy(ouistiticonfig_t *ouistiticonfig)
{
	int i;

	if (logfd > 0)
		close(logfd);
	config_destroy(&configfile);

	for (i = 0; i < MAX_SERVERS; i++)
	{
		serverconfig_t *config = ouistiticonfig->servers[i];
		if (config)
		{
			free(config->server);
			free(config);
			ouistiticonfig->servers[i] = NULL;
		}
	}

	free(ouistiticonfig);
}
