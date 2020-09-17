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

typedef struct server_s server_t;

typedef struct module_s module_t;
typedef struct modulesconfig_s modulesconfig_t;

#define WEBSOCKET_REALTIME 0x01

typedef void *(*module_create_t)(http_server_t *server, void *config);
struct module_s
{
	const char *name;
	void *(*create)(http_server_t *server, void *config);
	void (*destroy)(void*);
};

struct modulesconfig_s
{
	void *document;
	void *cgi;
	void *auth;
	void *clientfilter;
	void *websocket;
	void *redirect;
	void *webstream;
	void *cors;
	void *upgrade;
	void *userfilter;
};

typedef struct serverconfig_s
{
	http_server_config_t *server;
	char *unlock_groups;
	void *tls;
	modulesconfig_t modules;
	void *vhosts[MAX_SERVERS - 1];
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
	.user = "www-data",
	.servers =
	{
		&(serverconfig_t) {
		.server =
			&(http_server_config_t) {
				.hostname = "www.ouistiti.net",
				.port = 80,
				.addr = NULL,
				.keepalive = 10,
				.maxclients = 10,
				.version = HTTP11,
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
				.maxclients = 10,
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
					.docroot = "/srv/wwwS/htdocs",
					.allow = ".html,.htm,.css,.js,.txt",
					.deny = ".htaccess,.php"
				},
			},
		},
		NULL,
	},
};
#else
ouistiticonfig_t *ouistiticonfig_create(const char *filepath, int serverid);
void ouistiticonfig_destroy(ouistiticonfig_t *ouistiticonfig);

int ouistiti_loadserver(serverconfig_t *config);
int ouistiti_loadmodule(server_t *server, const char *name, void *config);

#endif
#endif
