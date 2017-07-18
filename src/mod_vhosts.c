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

#include "httpserver/httpserver.h"
#include "httpserver/mod_websocket.h"
#include "mod_static_file.h"
#include "mod_cgi.h"
#include "mod_auth.h"
#include "mod_vhosts.h"
#include "mod_methodlock.h"
#include "mod_server.h"

#if defined WEBSOCKET
extern int ouistiti_websocket_run(void *arg, int socket, char *protocol, http_message_t *request);
#endif

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif


typedef struct _mod_vhost_s _mod_vhost_t;

struct _mod_vhost_s
{
	mod_vhost_t	*config;
	void *mod_static_file;
	void *mod_cgi;
	void *mod_auth;
	void *mod_websocket;
	void *mod_methodlock;
	void *mod_server;
};

void *mod_vhost_create(http_server_t *server, mod_vhost_t *config)
{
	_mod_vhost_t *mod;

	if (!config)
		return NULL;

	mod = calloc(1, sizeof(*mod));
	mod->config = config;

	dbg("create vhost for %s", config->hostname);
#if defined AUTH
	if (config->auth)
	{
		mod->mod_auth = mod_auth_create(server, config->hostname, config->auth);
	}
#endif
#if defined METHODLOCK
			mod->mod_methodlock = mod_methodlock_create(server, config->hostname, NULL);
#endif
#if defined SERVERHEADER
			mod->mod_server = mod_server_create(server, config->hostname, NULL);
#endif
#if defined WEBSOCKET
	if (config->websocket)
		mod->mod_websocket = mod_websocket_create(server,
			NULL, config->websocket,
#if defined MBEDTLS
			default_websocket_run, config->websocket);
#else
			ouistiti_websocket_run, config->websocket);
#endif
#endif
#if defined CGI
	if (config->cgi)
		mod->mod_cgi = mod_cgi_create(server, config->hostname, config->cgi);
#endif
#if defined STATIC_FILE
	if (config->static_file)
		mod->mod_static_file = mod_static_file_create(server, config->hostname, config->static_file);
#endif

	return mod;
}

void mod_vhost_destroy(void *arg)
{
	_mod_vhost_t *mod = (_mod_vhost_t *)arg;
#if defined STATIC_FILE
	if (mod->mod_static_file)
		mod_static_file_destroy(mod->mod_static_file);
#endif
#if defined CGI
	if (mod->mod_cgi)
		mod_cgi_destroy(mod->mod_cgi);
#endif
#if defined AUTH
	if (mod->mod_auth)
		mod_auth_destroy(mod->mod_auth);
#endif
#if defined METHODLOCK
	if (mod->mod_methodlock)
		mod_methodlock_destroy(mod->mod_methodlock);
#endif
#if defined SERVERHEADER
	if (mod->mod_server)
		mod_server_destroy(mod->mod_server);
#endif
	free(mod);
}
