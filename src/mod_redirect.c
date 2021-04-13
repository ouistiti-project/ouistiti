/*****************************************************************************
 * mod_redirect.c: Redirect the request on 404 error
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "httpserver/httpserver.h"
#include "httpserver/utils.h"
#include "mod_redirect.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

#ifndef RESULT_204
#define RESULT_204 204
#endif

typedef struct _mod_redirect_s _mod_redirect_t;

static int _mod_redirect_connector(void *arg, http_message_t *request, http_message_t *response);

static const char str_redirect[] = "redirect";
#ifndef __STR_HTTPS
static const char str_https[] = "https";
#endif
static const char str_upgrade_insec_req[] = "Upgrade-Insecure-Requests";

struct _mod_redirect_s
{
	mod_redirect_t	*config;
	int result;
};

#ifdef FILE_CONFIG
static int redirect_mode(const char *mode)
{
	int options = 0;
	if (utils_searchexp("generate_204", mode, NULL) == ESUCCESS)
	{
		options |= REDIRECT_GENERATE204;
	}
	if (utils_searchexp("hsts", mode, NULL) == ESUCCESS)
	{
		options |= REDIRECT_HSTS;
	}
	if (utils_searchexp("temporary", mode, NULL) == ESUCCESS)
	{
		options |= REDIRECT_TEMPORARY;
	}
	else if (utils_searchexp("permanently", mode, NULL) == ESUCCESS)
	{
		options |= REDIRECT_PERMANENTLY;
	}
	if (utils_searchexp("error", mode, NULL) == ESUCCESS)
	{
		options |= REDIRECT_ERROR;
	}
	return options;
}

static mod_redirect_link_t *redirect_linkconfig(config_setting_t *iterator)
{
	mod_redirect_link_t *link = NULL;
	char *destination = NULL;
	const char *origin = NULL;
	char *mode = NULL;
	int options = 0;

	static char origin_error[4];
	config_setting_t *originset = config_setting_lookup(iterator, "origin");
	if (config_setting_is_number(originset))
	{
		int value;
		value = config_setting_get_int(originset);
		snprintf(origin_error, 4, "%.3d", value);
		origin = origin_error;
		config_setting_set_string(originset, origin_error);
		//originset = config_setting_lookup(iterator, "origin");
		if (value == 204)
			options |= REDIRECT_GENERATE204;
		else
			options |= REDIRECT_ERROR;
	}
	else
		origin = config_setting_get_string(originset);
	config_setting_lookup_string(iterator, "destination", (const char **)&destination);
	if (origin != NULL)
	{
		link = calloc(1, sizeof(*link));
		link->origin = strdup(origin);

		config_setting_lookup_string(iterator, "options", (const char **)&mode);
		link->options = redirect_mode(mode);
		link->destination = destination;
	}
	return link;
}

static int redirect_linksconfig(config_setting_t *configlinks, mod_redirect_t *conf)
{
	conf->options |= REDIRECT_LINK;
	int count = config_setting_length(configlinks);
	int i;
	for (i = 0; i < count; i++)
	{
		config_setting_t *iterator = config_setting_get_elem(configlinks, i);
		if (iterator)
		{
			mod_redirect_link_t *link = redirect_linkconfig(iterator);
			if (link != NULL)
			{
				link->next = conf->links;
				conf->links = link;
			}
		}
	}
	return count;
}

static void *redirect_config(config_setting_t *iterator, server_t *server)
{
	mod_redirect_t *conf = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *config = config_setting_get_member(iterator, "redirect");
#else
	config_setting_t *config = config_setting_lookup(iterator, "redirect");
#endif
	if (config)
	{
		conf = calloc(1, sizeof(*conf));
		char *mode = NULL;
		config_setting_lookup_string(config, "options", (const char **)&mode);
		conf->options = redirect_mode(mode);

		config_setting_t *configlinks = config_setting_lookup(config, "links");
		if (configlinks)
		{
			redirect_linksconfig(configlinks, conf);
		}
	}
	return conf;
}
#else
static const mod_redirect_t g_redirect_config =
{
	.links = &(mod_redirect_link_t)
	{
		.origin = "^/token$",
		.options = REDIRECT_TEMPORARY,
		.next = NULL,
	},
	.options = REDIRECT_LINK,
};

static void *redirect_config(void *iterator, server_t *server)
{
	 return (void *)&g_redirect_config;
}
#endif

static void *mod_redirect_create(http_server_t *server, mod_redirect_t *config)
{
	_mod_redirect_t *mod;

	if (!config)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = config;
	if (config->options & REDIRECT_PERMANENTLY)
		mod->result = RESULT_301;
	else if (config->options & REDIRECT_TEMPORARY)
		mod->result = RESULT_307;
	else
		mod->result = RESULT_302;

	httpserver_addconnector(server, _mod_redirect_connector, mod, CONNECTOR_DOCFILTER, str_redirect);
	httpserver_addconnector(server, _mod_redirect_connector, mod, CONNECTOR_ERROR, str_redirect);
	return mod;
}

void mod_redirect_destroy(void *arg)
{
	_mod_redirect_t *mod = (_mod_redirect_t *)arg;
#ifdef FILE_CONFIG
	mod_redirect_t *config = mod->config;
	mod_redirect_link_t *link = config->links;
	while (link != NULL)
	{
		mod_redirect_link_t *next = link->next;
		free(link->origin);
		free(link);
		link = next;
	}
	free(config);
#endif
	free(mod);
}

static int _mod_redirect_connectorlinkquery(_mod_redirect_t *mod, http_message_t *request,
									http_message_t *response, mod_redirect_link_t *link,
									const char *search)
{
	char *redirect = NULL;

	if (search)
		redirect = strstr(search, "redirect_uri=");
	if (redirect != NULL)
	{
		int result = mod->result;
		redirect += 13;
		char *end = strchr(redirect, '&');
		if (end != NULL)
			*end = '\0';
		httpmessage_addheader(response, str_location, redirect);
		if (link->options & REDIRECT_PERMANENTLY)
			result = RESULT_301;
		else if (link->options & REDIRECT_TEMPORARY)
			result = RESULT_307;
		httpmessage_result(response, result);
		return ESUCCESS;
	}
	return ECONTINUE;
}

static int _mod_redirect_connectorlink(_mod_redirect_t *mod, http_message_t *request,
									http_message_t *response, mod_redirect_link_t *link,
									const char *status, const char *uri)
{
	int ret = ECONTINUE;
	const char *path_info = NULL;

	if (utils_searchexp(uri, link->origin, &path_info) == ESUCCESS)
	{
		if (link->destination != NULL &&
				utils_searchexp(uri, link->destination, NULL) != ESUCCESS)
		{
			int result = mod->result;
			httpmessage_addheader(response, str_location, link->destination);
			if (path_info != NULL)
			{
				httpmessage_appendheader(response, str_location, path_info, NULL);
			}
			if (link->options & REDIRECT_PERMANENTLY)
				result = RESULT_301;
			else if (link->options & REDIRECT_TEMPORARY)
				result = RESULT_307;
			httpmessage_result(response, result);
			ret = ESUCCESS;
		}
		else if (link->options & REDIRECT_GENERATE204)
		{
			httpmessage_result(response, RESULT_204);
			ret = ESUCCESS;
		}
		else
		{
			const char *search = httpmessage_REQUEST(request, "query");
			ret =_mod_redirect_connectorlinkquery(mod, request, response, link, search);
		}
	}
	if (link->options & REDIRECT_ERROR && status != NULL)
	{
		if (!strncmp(status, link->origin, 3))
		{
			httpmessage_addheader(response, str_location, link->destination);
			httpmessage_result(response, RESULT_301);
			ret = ESUCCESS;
		}
	}
	return ret ;
}
static int _mod_redirect_connector(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_redirect_t *mod = (_mod_redirect_t *)arg;
	mod_redirect_t *config = mod->config;

	if (config->options & REDIRECT_HSTS)
	{
		const char *scheme = httpmessage_REQUEST(request, "scheme");
		if (strcmp(scheme, str_https))
		{
			scheme = str_https;
			const char *host = httpmessage_SERVER(request, "host");
			const char *port = httpmessage_SERVER(request, "port");
			const char *uri = httpmessage_REQUEST(request, "uri");
			const char *portseparator = "";
			if (port[0] != '\0')
				portseparator = ":";

			const char *upgrade = httpmessage_REQUEST(request, str_upgrade_insec_req);
			if (!strcmp(upgrade, "1"))
			{
				httpmessage_addheader(response, str_location, scheme);
				httpmessage_appendheader(response, str_location, "://", host, portseparator, port, uri, NULL);
				httpmessage_addheader(response, "Vary", str_upgrade_insec_req);
				httpmessage_result(response, RESULT_301);
				return ESUCCESS;
			}
		}
		else
		{
			httpmessage_addheader(response, "Strict-Transport-Security", "max-age=31536000; includeSubDomains");
		}
	}
	if (config->options & REDIRECT_GENERATE204)
	{
		const char *uri = httpmessage_REQUEST(request, "uri");
		if (utils_searchexp(uri, "generate_204", NULL) == ESUCCESS)
		{
			httpmessage_result(response, RESULT_204);
			return ESUCCESS;
		}
	}
	if (config->options & REDIRECT_LINK)
	{
		const char *status = httpmessage_REQUEST(response, "result");
		if (status != NULL)
			while (*status == ' ') status++;
		const char *uri = httpmessage_REQUEST(request, "uri");

		mod_redirect_link_t *link = config->links;
		while (link != NULL)
		{
			int ret = _mod_redirect_connectorlink(mod, request, response, link, status, uri);
			if (ret != ECONTINUE)
			{
				return ret;
			}
			link = link->next;
		}
	}
	return EREJECT;
}

const module_t mod_redirect =
{
	.name = str_redirect,
	.configure = (module_configure_t)&redirect_config,
	.create = (module_create_t)&mod_redirect_create,
	.destroy = &mod_redirect_destroy
};

#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_redirect")));
#endif
