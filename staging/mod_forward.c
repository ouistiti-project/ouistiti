/*****************************************************************************
 * mod_forward.c: Forward request to another server
 * this file is part of https://github.com/ouistiti-project/ouistiti
 *
 * follow RFC3875 : https://tools.ietf.org/html/rfc3875
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

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <libgen.h>
#include <netinet/in.h>
#include <sched.h>

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#define HTTPCLIENT_FEATURES
#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/log.h"

#include "ouistiti.h"

#define forward_dbg(...)

static const char str_forward[] = "forward";

typedef struct mod_forward_link_s mod_forward_link_t;
struct mod_forward_link_s
{
	char *origin;
	const char *destination;
	mod_forward_link_t *next;
};

typedef struct mod_forward_config_s
{
	int options;
	mod_forward_link_t *links;
} mod_forward_config_t;

typedef struct mod_forward_config_s mod_forward_config_t;
typedef struct mod_forward_s mod_forward_t;
typedef struct mod_forward_ctx_s mod_forward_ctx_t;

static int _forward_connector(void *arg, http_message_t *request, http_message_t *response);

struct mod_forward_ctx_s
{
	mod_forward_t *mod;
	http_client_t *ctl;

	http_message_t *request;
	http_client_t *client;
	http_message_t *response;

	int toforward[2];
};

struct mod_forward_s
{
	http_server_t *server;
	mod_forward_config_t *config;
	int rootfd;
};

#ifdef FILE_CONFIG
static mod_forward_link_t *redirect_linkconfig(config_setting_t *iterator)
{
	mod_forward_link_t *link = NULL;
	const char *origin = NULL;
	char *mode = NULL;
	int options = 0;

	static char origin_error[5];
	config_setting_t *originset = config_setting_lookup(iterator, "origin");
	origin = config_setting_get_string(originset);

	if (origin != NULL)
	{
		link = calloc(1, sizeof(*link));
		link->origin = strdup(origin);

		const char *destination = NULL;
		config_setting_lookup_string(iterator, "destination", (const char **)&destination);
		if (destination != NULL && destination[0] != '\0')
			link->destination = destination;
	}
	return link;
}

static int redirect_linksconfig(config_setting_t *configlinks, mod_forward_config_t *conf)
{
	int count = config_setting_length(configlinks);
	int i;
	for (i = 0; i < count; i++)
	{
		config_setting_t *iterator = config_setting_get_elem(configlinks, i);
		if (iterator)
		{
			mod_forward_link_t *link = redirect_linkconfig(iterator);
			if (link != NULL)
			{
				link->next = conf->links;
				conf->links = link;
			}
		}
	}
	return count;
}

static void *forward_config(config_setting_t *iterator, server_t *server)
{
	mod_forward_config_t *conf = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *config = config_setting_get_member(iterator, "forward");
#else
	config_setting_t *config = config_setting_lookup(iterator, "forward");
#endif
	if (config)
	{
		conf = calloc(1, sizeof(*conf));

		config_setting_t *configlinks = config_setting_lookup(config, "links");
		if (configlinks)
		{
			redirect_linksconfig(configlinks, conf);
		}
	}
	return conf;
}
#else
static const mod_forward_config_t g_forward_config =
{
};

static void *forward_config(void *iterator, server_t *server)
{
	return (void *)&g_forward_config;
}
#endif

static void *mod_forward_create(http_server_t *server, mod_forward_config_t *modconfig)
{
	mod_forward_t *mod = NULL;

	if (!modconfig)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = modconfig;
	mod->server = server;

	httpserver_addconnector(server, _forward_connector, mod, CONNECTOR_DOCUMENT, str_forward);

	return mod;
}

static void mod_forward_destroy(void *arg)
{
	mod_forward_t *mod = (mod_forward_t *)arg;
	// nothing to do
	free(mod->config);
	free(mod);
}


static mod_forward_ctx_t * _mod_forward_connectorlink(mod_forward_t *mod, http_message_t *request,
									http_message_t *response, mod_forward_link_t *link,
									const char *uri)
{
	mod_forward_ctx_t *ctx = NULL;
	const char *path_info = NULL;
	if (utils_searchexp(uri, link->origin, &path_info) == ESUCCESS)
	{
		int length = strlen(uri);
		ctx = calloc(1, sizeof(*ctx));

		ctx->request = httpmessage_create();
		const char *query = httpmessage_REQUEST(request, "query");
		warn("forward: run %s => %s%s?%s", uri, link->destination, path_info, query);
		if (path_info != NULL && query != NULL && query[0] != '\0')
		{
			ctx->client = httpmessage_request(ctx->request, "GET", link->destination, path_info, "?", query, NULL);
		}
		else if (path_info != NULL)
		{
			ctx->client = httpmessage_request(ctx->request, "GET", link->destination, path_info, NULL);
		}
		else if (query != NULL && query[0] != '\0')
		{
			ctx->client = httpmessage_request(ctx->request, "GET", link->destination, "?", query, NULL);
		}
		else
		{
			ctx->client = httpmessage_request(ctx->request, "GET", link->destination, NULL);
		}
		if (ctx->client != NULL)
		{
			httpmessage_appendheader(ctx->request, "User-Agent", STRING_REF(PACKAGE_NAME "/" PACKAGE_VERSION));
		}
	}
	return ctx;
}

static int _forward_start(mod_forward_t *mod, http_message_t *request, http_message_t *response)
{
	const mod_forward_config_t *config = mod->config;
	int ret = EREJECT;
	const char *uri = httpmessage_REQUEST(request,"uri");

	if (uri)
	{
		mod_forward_link_t *link = config->links;
		mod_forward_ctx_t *ctx = NULL;
		while (link != NULL)
		{
			ctx = _mod_forward_connectorlink(mod, request, response, link, uri);
			if (ctx != NULL)
			{
				ret = EINCOMPLETE;
				break;
			}
			link = link->next;
		}
		httpmessage_private(request, ctx);
	}
	return ret;
}

static int _forward_request(mod_forward_ctx_t *ctx, http_message_t *response)
{
	int ret = EREJECT;

	do
	{
		ret = httpclient_sendrequest(ctx->client, ctx->request, response);
	} while (ret == EINCOMPLETE);

	if (ret == ESUCCESS)
	{
		httpclient_destroy(ctx->client);
		ctx->client = NULL;
		httpmessage_destroy(ctx->request);
		free(ctx);
	}
	return ret;
}

static int _forward_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	mod_forward_t *mod = (mod_forward_t *)arg;
	mod_forward_ctx_t *ctx = httpmessage_private(request, NULL);

	if (ctx == NULL)
	{
		ret = _forward_start(mod, request, response);
	}
	else if (ctx->client != NULL)
	{
		ret = _forward_request(ctx, response);
	}
	else
	{
		httpmessage_result(response, 400);
		httpmessage_destroy(ctx->request);
		free(ctx);
	}
	return ret;
}

const module_t mod_forward =
{
	.name = str_forward,
	.configure = (module_configure_t)&forward_config,
	.create = (module_create_t)&mod_forward_create,
	.destroy = &mod_forward_destroy
};

#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_forward")));
#endif
