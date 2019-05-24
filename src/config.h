/*****************************************************************************
 * config.h: configuration file parser
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

#ifndef __OUISTITI_CONFIG_H__
#define __OUISTITI_CONFIG_H__

#ifndef MAX_SERVERS
#define MAX_SERVERS 4
#endif

#include "mod_document.h"
#include "mod_cgi.h"
#include "mod_auth.h"
#include "mod_clientfilter.h"
#include "mod_redirect404.h"
#include "mod_webstream.h"
#include "mod_cors.h"
#include "httpserver/mod_websocket.h"
#include "httpserver/mod_tls.h"
#define WEBSOCKET_REALTIME 0x01

typedef struct modulesconfig_s
{
	mod_document_t *document;
	mod_cgi_config_t *cgi;
	mod_auth_t *auth;
	mod_clientfilter_t *clientfilter;
	mod_websocket_t *websocket;
	mod_redirect404_t *redirect404;
	mod_webstream_t *webstream;
	mod_cors_t *cors;
} modulesconfig_t;

typedef struct serverconfig_s
{
	http_server_config_t *server;
	char *unlock_groups;
	mod_tls_t *tls;
	modulesconfig_t modules;
	mod_vhost_t *vhosts[MAX_SERVERS - 1];
} serverconfig_t;

typedef struct ouistiticonfig_s
{
	char *user;
	char *pidfile;
	serverconfig_t *servers[MAX_SERVERS];
} ouistiticonfig_t;

/**
user="apache";
servers={
	({
		server = {
			hostname = "www.ouistiti.net";
			port = 80;
			keepalive = true;
			maxclients = 10;
		};
		static_file = {
			docroot = "/srv/www/htdocs";
			accepted_ext = ".html,.htm,.css,.js,.txt";
			ignored_ext = ".htaccess,.php";
		};
		cgi = {
			docroot = "/srv/www/cgi-bin";
			accepted_ext = ",.cgi,.sh";
			ignored_ext = ".htaccess";
		};
	},
	{
		server = {
			hostname = "www.ouistiti.net";
			port = 443;
			keepalive = true;
		};
		mbedtls =  {
			crtfile = "/etc/ssl/private/server.pem",
			dhmfile = "/etc/ssl/private/dhparam.pem",
		};
		document = {
			docroot = "/srv/www/htdocs";
			accepted_ext = ".html,.htm,.css,.js,.txt";
			ignored_ext = ".htaccess,.php";
		};
		cgi = {
			docroot = "/srv/www/cgi-bin";
			accepted_ext = ",.cgi,.sh";
			ignored_ext = ".htaccess";
		};
	})
};
**/
#ifdef STATIC_CONFIG
ouistiticonfig_t g_ouistiticonfig =
{
	.user = "apache",
	.servers =
	{
		&(serverconfig_t) {
		.server = 
			&(http_server_config_t) {
				.hostname = "www.ouistiti.net",
				.port = 80,
				.addr = NULL,
				.keepalive = 10,
				.version = HTTP11
			},
		.tls = NULL,
		.modules = {
			.document = 
				&(mod_document_t) {
					.docroot = "/srv/www/htdocs",
					.allow = ".html,.htm,.css,.js,.txt",
					.deny = ".htaccess,.php"
				},
			.cgi =
				&(mod_cgi_config_t) {
					.docroot = "/srv/www/cgi-bin",
					.allow = ",.cgi,.sh",
					.deny = ".htaccess"
				},
			},
		},
		&(serverconfig_t) {
		.server = 
			&(http_server_config_t) {
				.port = 443,
				.addr = NULL,
				.keepalive = 10,
				.version = HTTP11,
			},
		.tls = 
			&(mod_tls_t) {
				.crtfile = "/etc/ssl/private/server.pem",
				.pemfile = NULL,
				.cachain = NULL,
				.dhmfile = "/etc/ssl/private/dhparam.pem",
			},
		.modules = {
			.document =
				&(mod_document_t) {
					.docroot = "/srv/www/htdocs",
					.allow = ".html,.htm,.css,.js,.txt",
					.deny = ".htaccess,.php"
				},
			},
		},
		NULL,
	},
};
#else
ouistiticonfig_t *ouistiticonfig_create(char *filepath);
void ouistiticonfig_destroy(ouistiticonfig_t *ouistiticonfig);

#endif
#endif
