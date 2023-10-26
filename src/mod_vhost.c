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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef MODULES
#include <dlfcn.h>
#endif
#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "ouistiti/httpserver.h"
#include "ouistiti/ouistiti.h"
#include "mod_vhost.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

static const char str_vhost[] = "vhost";

struct mod_vhost_s
{
	/** @param name of the server */
	const char *hostname;
	server_t *server;
	void *modulesconfig;
};

typedef struct _mod_vhost_s _mod_vhost_t;

struct _mod_vhost_s
{
	mod_vhost_t	*config;
	http_server_t *vserver;
	mod_t *modules;
};

static int _vhost_connector(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_vhost_t *mod = (_mod_vhost_t *)arg;

	const char *vhost = httpmessage_REQUEST(request, "host");
	if (vhost == NULL || strcmp(vhost, mod->config->hostname))
		return EREJECT;

	return httpserver_reloadclient(mod->vserver, httpmessage_client(request));
}

#ifdef FILE_CONFIG
static int vhost_config(config_setting_t *iterator, server_t *server, int index, void **modconfig)
{
	int ret = ESUCCESS;
	mod_vhost_t *vhost = NULL;

#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *config = config_setting_get_member(iterator, "vhost");
#else
	config_setting_t *config = config_setting_lookup(iterator, "vhost");
#endif
	if (config && config_setting_is_list(config))
	{
			if (index >= config_setting_length(config))
				return EREJECT;
			config = config_setting_get_elem(config, index);
			ret = ECONTINUE;
	}
	if (config && config_setting_is_group(config))
	{
		const char *hostname;
		config_setting_lookup_string(config, "hostname", (const char **)&hostname);
		if (hostname == NULL || hostname[0] == '\0')
		{
			err("vhost configuration without hostname");
			return EREJECT;
		}
		vhost = calloc(1, sizeof(*vhost));
		vhost->hostname = hostname;
		vhost->server = server;
		vhost->modulesconfig = config;
	}
	else
		ret = EREJECT;

	*modconfig = vhost;
	return ret;
}
#else
void vhost_config(void *modconfig, server_t *server, int index, void *config);
#endif

static mod_t *mod_vhost_loadmodule(_mod_vhost_t *vhost, const module_t *module)
{
	int ret = ECONTINUE;
	void *config = NULL;
	http_server_t *vserver = vhost->vserver;
	void *modconfig = vhost->config->modulesconfig;
	server_t *server = vhost->config->server;
	mod_t *first = NULL;

	int i = 0;
	while (ret == ECONTINUE)
	{
		if (module->configure != NULL && module->version == 0)
		{
			config = ((module_configure_v0_t)module->configure)(modconfig, server);
			ret = ESUCCESS;
		}
		else if (module->configure != NULL && module->version == 0x01)
		{
			ret = module->configure(modconfig, server, i++, &config);
		}
		else
			ret = ESUCCESS;
		void *obj = NULL;
		if (ret == ESUCCESS || ret == ECONTINUE)
		{
			obj = module->create(vserver, config);
		}
		if (obj)
		{
			mod_t *mod = calloc(1, sizeof(*mod));
			mod->ops = module;
			mod->obj = obj;
			mod->next = first;
			first = mod;
		}
	}
	return first;
}

static void *mod_vhost_create(http_server_t *server, mod_vhost_t *config)
{
	_mod_vhost_t *mod;

	if (!config)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = config;

	mod->vserver = httpserver_dup(server);
	httpserver_addconnector(server, _vhost_connector, mod, CONNECTOR_SERVER, str_vhost);
	const module_list_t *iterator = ouistiti_modules(config->server);
	while (iterator != NULL)
	{
		if (strcmp(iterator->module->name, str_vhost))
		{
			mod_t *entry = mod_vhost_loadmodule(mod, iterator->module);
			if (entry)
			{
				mod_t *last = entry;
				while (last->next) last = last->next;
				last->next = mod->modules;
				mod->modules = entry;
			}
		}
		iterator = iterator->next;
	}

	dbg("create vhost for %s", config->hostname);

	return mod;
}

void mod_vhost_destroy(void *arg)
{
	_mod_vhost_t *mod = (_mod_vhost_t *)arg;
	httpserver_destroy(mod->vserver);
	mod_t *module = mod->modules;
	while (module)
	{
		mod_t *next = module->next;
		if (module->ops->destroy)
			module->ops->destroy(module->obj);
		free(module);
		module = next;
	}
	free(mod);
}

const module_t mod_vhost =
{
	.version = 0x01,
	.name = str_vhost,
	.configure = (module_configure_t)&vhost_config,
	.create = (module_create_t)&mod_vhost_create,
	.destroy = &mod_vhost_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_vhost")));
#endif
