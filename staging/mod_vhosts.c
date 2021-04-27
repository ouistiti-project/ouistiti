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
	_module_t mod_document;
	_module_t mod_dirlisting;
	_module_t mod_cgi;
	_module_t mod_auth;
	_module_t mod_clientfilter;
	_module_t mod_webstream;
	_module_t mod_websocket;
	_module_t mod_methodlock;
	_module_t mod_server;
	_module_t mod_redirect404;
	_module_t mod_redirect;
};

#ifndef MODULES
static const module_t *modules[] =
{
#if defined TLS
	&mod_tls,
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

static int _loadmodule(const char *name, http_server_t *server, char *hostname, void *config, _module_t *module)
{
	int ret = -1;
	void *mod = NULL;
#ifndef MODULES
	int i = 0;
	while (modules[i] != NULL)
	{
		if (!strcmp(modules[i]->name, name))
		{
			module->ops = modules[i];
			module->ctx = module->create(server, config);
			ret = 0;
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
		module->ops = dlsym(dh, "mod_info");
		if (module->ops && !strcmp(module->ops->name, name))
		{
			module->ctx = module->ops->create(server, config);
			dbg("module %s loaded", name);
			ret = 0;
		}
		else if (module->ops)
			warn("module %s error : named %s", name, module->ops->name);
		else
			err("module symbol error: %s", dlerror());
	}
	else
	{
		err("module %s loading error: %s", file, dlerror());
	}
#endif
	return ret;
}

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
	char *hostname = NULL;

	config_setting_lookup_string(iterator, "hostname", (const char **)&hostname);
	if (hostname && hostname[0] != '0')
	{
		vhost = calloc(1, sizeof(*vhost));
		vhost->hostname = hostname;
		vhost->modules.document = document_config(iterator, tls);
		vhost->modules.auth = auth_config(iterator, tls);
		vhost->modules.cgi = cgi_config(iterator, tls);
		vhost->modules.websocket = websocket_config(iterator, tls);
		vhost->modules.redirect = redirect_config(iterator,tls);
		vhost->modules.cors = cors_config(iterator, tls);
		vhost->modules.upgrade = upgrade_config(iterator, tls);
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
#if defined AUTH
	if (config->modules.auth)
	{
		_loadmodule("auth", mod->vserver, config->hostname, config->modules.auth, &mod->mod_auth);
	}
#endif
#if 0 && defined METHODLOCK
	_loadmodule("methodlock", mod->vserver, config->hostname, NULL, &mod->mod_auth);
#endif
#if defined REDIRECT
	if (config->modules.redirect)
	{
		_loadmodule("redirect", mod->vserver, config->hostname, config->modules.redirect, &mod->mod_redirect);
	}
#endif
#if defined WEBSTREAM
	if (config->modules.webstream)
	{
		_loadmodule("webstream", mod->vserver, config->hostname, config->modules.webstream, &mod->mod_webstream);
	}
#endif
#if defined WEBSOCKET
	if (config->modules.websocket)
	{
		_loadmodule("websocket", mod->vserver, config->hostname, config->modules.websocket, &mod->mod_websocket);
	}
#endif
#if defined CGI
	if (config->modules.cgi)
		_loadmodule("cgi", mod->vserver, config->hostname, config->modules.cgi, &mod->mod_cgi);
#endif
#if defined DOCUMENT
	if (config->modules.document)
	{
		_loadmodule("document", mod->vserver, config->hostname, config->modules.document, &mod->mod_document);
	}
#endif
#if defined REDIRECT
	if (config->modules.redirect)
	{
		_loadmodule("redirect404", mod->vserver, config->hostname, NULL, &mod->mod_redirect404);
	}
#endif

	return mod;
}

void mod_vhost_destroy(void *arg)
{
	_mod_vhost_t *mod = (_mod_vhost_t *)arg;
#if defined REDIRECT
	if (mod->mod_redirect404.ops)
		mod->mod_redirect404.ops->destroy(mod->mod_redirect404.ctx);
#endif
#if defined DOCUMENT
	if (mod->mod_document.ops)
		mod->mod_document.ops->destroy(mod->mod_document.ctx);
#endif
#if defined CGI
	if (mod->mod_cgi.ops)
		mod->mod_cgi.ops->destroy(mod->mod_cgi.ctx);
#endif
#if defined WEBSTREAM
	if (mod->mod_webstream.ops)
		mod->mod_webstream.ops->destroy(mod->mod_webstream.ctx);
#endif
#if defined WEBSOCKET
	if (mod->mod_websocket.ops)
		mod->mod_websocket.ops->destroy(mod->mod_websocket.ctx);
#endif
#if defined REDIRECT
	if (mod->mod_redirect.ops)
		mod->mod_redirect.ops->destroy(mod->mod_redirect.ctx);
#endif
#if defined AUTH
	if (mod->mod_auth.ops)
		mod->mod_auth.ops->destroy(mod->mod_auth.ctx);
#endif
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
