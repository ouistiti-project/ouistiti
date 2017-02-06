#ifndef __OUISTITI_CONFIG_H__
#define __OUISTITI_CONFIG_H__

typedef struct serverconfig_s
{
	char *user;
	http_server_config_t *server;
	mod_mbedtls_t *mbedtls;
	mod_static_file_t *static_file;
	mod_cgi_config_t *cgi;
} serverconfig_t;

#ifdef __OUISTITI_CONFIG__
serverconfig_t *config[] =
{
	&(serverconfig_t) {
	.user = "apache",
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
	.user = NULL,
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
};
#endif
#endif
