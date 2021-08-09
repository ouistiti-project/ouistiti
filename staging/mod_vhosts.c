/*****************************************************************************
 * mod_vhosts.c: callbacks and management of connection
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

/**
    auth module needs the type of authentication ("Basic" or "Digest").
    After the rule to check the password is an authn_<type>_<name>
    sublibrary (just a C file).

    With this solution each server may has its own authentication type.
    After the checking of the password is done by a library linked to the
    mod_vhosts library.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef MODULES
#include <dlfcn.h>
#endif

#include "ouistiti/httpserver.h"
#include "mod_websocket.h"
#include "mod_document.h"
#include "mod_cgi.h"
#include "mod_auth.h"
#include "mod_clientfilter.h"
#include "mod_vhosts.h"
#include "mod_methodlock.h"
#include "mod_server.h"

#warning VHOSTS is deprecated

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

static const char str_vhosts[] = "vhosts";

typedef struct _mod_vhost_s _mod_vhost_t;

typedef struct _module_s
{
	void *ctx;
	module_t *ops;
} _module_t;

struct _mod_vhost_s
{
	mod_vhost_t	*config;
	http_server_t *vserver;
	_module_t *modules;
};


#warning libhttpserver must be modified to remove the static declaration of the following functions
#warning As ouistiti should run on embedded device, the virtual hosting is not a required feature.

extern int _httpserver_setmod(http_server_t *server, http_client_t *client);
extern int _httpclient_checkconnector(http_client_t *client, http_message_t *request, http_message_t *response);
static int _vhost_connector(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_vhost_t *mod = (_mod_vhost_t *)arg;

	const char *vhost = httpmessage_REQUEST(request, "host");
	if (vhost == NULL || strcmp(vhost, mod->config->hostname))
		return EREJECT;

	http_client_t *clt = httpmessage_client(request);
	_httpserver_setmod(mod->vserver, clt);
	int ret = _httpclient_checkconnector(httpmessage_client(request), request, response);
	return ret;
}

static void *_mod_vhost_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_vhost_t *mod = (_mod_vhost_t *)arg;

	httpclient_addconnector(ctl, _vhost_connector, arg, CONNECTOR_FILTER, str_vhosts);

	return mod;
}

#ifdef FILE_CONFIG
#include <libconfig.h>

static void *vhost_config(config_setting_t *iterator, server_t *server)
{
	mod_vhost_t *vhost = NULL;

#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *config = config_setting_get_member(iterator, "vhost");
#else
	config_setting_t *config = config_setting_lookup(iterator, "vhost");
#endif
	if (config)
	{
		vhost = calloc(1, sizeof(*vhost));
		config_setting_lookup_string(config, "hostname", (const char **)&vhost->hostname);
		if (vhost->hostname != NULL && vhost->hostname[0] = '\0')
			ouistiti_setmodules(server, NULL, config);
		else
			warn("vhost configuration without hostname");
	}

	return vhost;
}
#else
#define vhost_config(...) NULL
#endif

static void *mod_vhost_create(http_server_t *server, mod_vhost_t *config)
{
	_mod_vhost_t *mod;

	if (!config)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = config;

	httpserver_addmod(server, _mod_vhost_getctx, NULL, mod, str_vhosts);
	mod->vserver = httpserver_dup(server);

	dbg("create vhost for %s", config->hostname);

	return mod;
}

void mod_vhost_destroy(void *arg)
{
	_mod_vhost_t *mod = (_mod_vhost_t *)arg;
	httpserver_destroy(mod->vserver);
	free(mod);
}

const module_t mod_vhosts =
{
	.name = str_vhosts,
	.configure = (module_configure_t)&vhost_config,
	.create = (module_create_t)&mod_vhost_create,
	.destroy = &mod_vhost_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_vhosts")));
#endif
