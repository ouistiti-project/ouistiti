#ifndef __OUISTITI_CONFIG_H__
#define __OUISTITI_CONFIG_H__

#define MAX_SERVERS 4

typedef struct serverconfig_s
{
	http_server_config_t *server;
	mod_mbedtls_t *mbedtls;
	mod_static_file_t *static_file;
	mod_cgi_config_t *cgi;
} serverconfig_t;

typedef struct ouistiticonfig_s
{
	char *user;
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
			pers = "httpserver-mbedtls",
			crtfile = "/etc/ssl/private/server.pem",
			dhmfile = "/etc/ssl/private/dhparam.pem",
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
				.keepalive = 1,
				.version = HTTP10
			},
		.mbedtls = NULL,
		.static_file = 
			&(mod_static_file_t) {
				.docroot = "/srv/www/htdocs",
				.accepted_ext = ".html,.htm,.css,.js,.txt",
				.ignored_ext = ".htaccess,.php"
			},
		.cgi =
			&(mod_cgi_config_t) {
				.docroot = "/srv/www/cgi-bin",
				.accepted_ext = ",.cgi,.sh",
				.ignored_ext = ".htaccess"
			},
		},
		&(serverconfig_t) {
		.server = 
			&(http_server_config_t) {
				.port = 443,
				.addr = NULL,
				.keepalive = 1,
				.version = HTTP10
			},
		.mbedtls = 
			&(mod_mbedtls_t) {
				.pers = "httpserver-mbedtls",
				.crtfile = "/etc/ssl/private/server.pem",
				.pemfile = NULL,
				.cachain = NULL,
				.dhmfile = "/etc/ssl/private/dhparam.pem",
			},
		.static_file =
			&(mod_static_file_t) {
				.docroot = "/srv/www/htdocs",
				.accepted_ext = ".html,.htm,.css,.js,.txt",
				.ignored_ext = ".htaccess,.php"
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
