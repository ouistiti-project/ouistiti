/*****************************************************************************
 * config.c: configuration file parser
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

#include <libconfig.h>

#include "httpserver/httpserver.h"
#include "httpserver/utils.h"

#include "mod_tls.h"
#include "mod_websocket.h"
#include "mod_document.h"
#include "mod_cgi.h"
#include "mod_auth.h"
#include "mod_vhosts.h"
#include "mod_cors.h"
#include "mod_upgrade.h"
#include "mod_userfilter.h"

#include "config.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
# define dbg(...)
#endif

char str_hostname[HOST_NAME_MAX + 7];
char str_userfilterpath[] = SYSCONFDIR"/userfilter.db";

static config_t configfile;
static char *logfile = NULL;
static int logfd = 0;

typedef void (*_parsercb_t)(void *arg, const char *option, size_t length);

static int config_parseoptions(const char *options, _parsercb_t cb, void *cbdata)
{
	const char *ext = options;

	while (ext != NULL)
	{
		size_t length = strlen(ext);
		const char *ext_end = strchr(ext, ',');
		if (ext_end)
		{
			length -= strlen(ext_end + 1) + 1;
			ext_end++;
		}
		cb(cbdata, ext, length);
		ext = ext_end;
	}
	return 0;
}

#ifdef DOCUMENT
static void document_optioncb(void *arg, const char *option, size_t length)
{
	mod_document_t *static_file = (mod_document_t *)arg;

#ifdef DIRLISTING
	if (!strncmp(option, "dirlisting", length))
		static_file->options |= DOCUMENT_DIRLISTING;
#endif
#ifdef SENDFILE
	if (!strncmp(option, "sendfile", length))
	{
		if (!(static_file->options & DOCUMENT_TLS))
			static_file->options |= DOCUMENT_SENDFILE;
		else
			warn("sendfile configuration is not allowed with tls");
	}
#endif
#ifdef RANGEREQUEST
	if (!strncmp(option, "range", length))
	{
		static_file->options |= DOCUMENT_RANGE;
	}
#endif
#ifdef DOCUMENTREST
	if (!strncmp(option, "rest", length))
	{
		static_file->options |= DOCUMENT_REST;
	}
#endif
#ifdef DOCUMENTHOME
	if (!strncmp(option, "home", length))
	{
		static_file->options |= DOCUMENT_HOME;
	}
#endif
}

static const char *str_index = "index.html";
static mod_document_t *document_config(config_setting_t *iterator, int tls, char *entry)
{
	mod_document_t * static_file = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configstaticfile = config_setting_get_member(iterator, entry);
#else
	config_setting_t *configstaticfile = config_setting_lookup(iterator, entry);
#endif
	if (configstaticfile)
	{
		int length;
		char *transfertype = NULL;
		static_file = calloc(1, sizeof(*static_file));
		config_setting_lookup_string(configstaticfile, "docroot", (const char **)&static_file->docroot);
		config_setting_lookup_string(configstaticfile, "dochome", (const char **)&static_file->dochome);
		config_setting_lookup_string(configstaticfile, "allow", (const char **)&static_file->allow);
		config_setting_lookup_string(configstaticfile, "deny", (const char **)&static_file->deny);
		config_setting_lookup_string(configstaticfile, "defaultpage", (const char **)&static_file->defaultpage);
		if (static_file->defaultpage == NULL)
			static_file->defaultpage = str_index;
		if (tls)
			static_file->options |= DOCUMENT_TLS;
		config_setting_lookup_string(configstaticfile, "options", (const char **)&transfertype);
		config_parseoptions(transfertype, &document_optioncb, static_file);
	}
	return static_file;
}
#else
#define document_config(...) NULL
#endif


#if defined(TLS)
static mod_tls_t *tls_config(config_setting_t *iterator)
{
	mod_tls_t *tls = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configtls = config_setting_get_member(iterator, "tls");
#else
	config_setting_t *configtls = config_setting_lookup(iterator, "tls");
#endif
	if (configtls)
	{
		tls = calloc(1, sizeof(*tls));
		config_setting_lookup_string(configtls, "crtfile", (const char **)&tls->crtfile);
		config_setting_lookup_string(configtls, "pemfile",(const char **) &tls->pemfile);
		config_setting_lookup_string(configtls, "cachain", (const char **)&tls->cachain);
		config_setting_lookup_string(configtls, "dhmfile", (const char **)&tls->dhmfile);
	}
	return tls;
}
#else
#define tls_config(...) NULL
#endif

#ifdef CLIENTFILTER
static mod_clientfilter_t *clientfilter_config(config_setting_t *iterator, int tls)
{
	mod_clientfilter_t *clientfilter = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *config = config_setting_get_member(iterator, "clientfilter");
#else
	config_setting_t *config = config_setting_lookup(iterator, "clientfilter");
#endif
	if (config)
	{
		clientfilter = calloc(1, sizeof(*clientfilter));
		config_setting_lookup_string(config, "allow", (const char **)&clientfilter->accept);
		config_setting_lookup_string(config, "deny", (const char **)&clientfilter->deny);
	}
	return clientfilter;
}
#else
#define clientfilter_config(...) NULL
#endif

#ifdef USERFILTER
static mod_userfilter_t *userfilter_config(config_setting_t *iterator, int tls)
{
	mod_userfilter_t *modconfig = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *config = config_setting_get_member(iterator, "userfilter");
#else
	config_setting_t *config = config_setting_lookup(iterator, "userfilter");
#endif
	if (config)
	{
		modconfig = calloc(1, sizeof(*modconfig));
		config_setting_lookup_string(config, "superuser", &modconfig->superuser);
		config_setting_lookup_string(config, "allow", &modconfig->allow);
		config_setting_lookup_string(config, "configuri", &modconfig->configuri);
		config_setting_lookup_string(config, "dbname", &modconfig->dbname);
		if (modconfig->dbname == NULL || modconfig->dbname[0] == '\0')
			modconfig->dbname = str_userfilterpath;
	}
	return modconfig;
}
#else
#define userfilter_config(...) NULL
#endif

#ifdef AUTH
#ifdef AUTHN_NONE
static void *authn_none_config(config_setting_t *configauth)
{
	authn_none_config_t *authn_config = NULL;
	const char *user = NULL;

	config_setting_lookup_string(configauth, "user", (const char **)&user);
	if (user != NULL)
	{
		authn_config = calloc(1, sizeof(*authn_config));
		authn_config->user = user;
	}
	else
		warn("config: authn_none needs to set the user");
	return authn_config;
}
#endif

#ifdef AUTHN_BASIC
static void *authn_basic_config(config_setting_t *configauth)
{
	authn_basic_config_t *authn_config = NULL;

	authn_config = calloc(1, sizeof(*authn_config));
	config_setting_lookup_string(configauth, "realm", (const char **)&authn_config->realm);
	return authn_config;
}
#endif

#ifdef AUTHN_DIGEST
static void *authn_digest_config(config_setting_t *configauth)
{
	authn_digest_config_t *authn_config = NULL;

	authn_config = calloc(1, sizeof(*authn_config));
	config_setting_lookup_string(configauth, "realm", (const char **)&authn_config->realm);
	config_setting_lookup_string(configauth, "opaque", (const char **)&authn_config->opaque);
	return authn_config;
}
#endif

#ifdef AUTHN_BEARER
static void *authn_bearer_config(config_setting_t *configauth)
{
	authn_bearer_config_t *authn_config = NULL;

	authn_config = calloc(1, sizeof(*authn_config));
	config_setting_lookup_string(configauth, "token_ep", (const char **)&authn_config->token_ep);
	if (authn_config->token_ep == NULL)
		config_setting_lookup_string(configauth, "signin", (const char **)&authn_config->token_ep);
	config_setting_lookup_string(configauth, "realm", (const char **)&authn_config->realm);
	return authn_config;
}
#endif

#ifdef AUTHN_OAUTH2
static void *authn_oauth2_config(config_setting_t *configauth)
{
	authn_oauth2_config_t *authn_config = NULL;
	const char *auth_ep = NULL;
	const char *token_ep = NULL;
	const char *discovery = NULL;

	config_setting_lookup_string(configauth, "discovery", (const char **)&discovery);
	config_setting_lookup_string(configauth, "auth_ep", (const char **)&auth_ep);
	config_setting_lookup_string(configauth, "token_ep", (const char **)&token_ep);

	authn_config = calloc(1, sizeof(*authn_config));
	authn_config->discovery = discovery;
	authn_config->auth_ep = auth_ep;
	authn_config->token_ep = token_ep;

	config_setting_lookup_string(configauth, "realm", (const char **)&authn_config->realm);

	config_setting_lookup_string(configauth, "client_id", (const char **)&authn_config->client_id);
	if (authn_config->client_id == NULL)
		authn_config->client_id = authn_config->realm;

	config_setting_lookup_string(configauth, "client_passwd", (const char **)&authn_config->client_passwd);
	if (authn_config->client_passwd == NULL)
	{
		config_setting_lookup_string(configauth, "secret", (const char **)&authn_config->client_passwd);
	}

	if (authn_config->iss == NULL)
		authn_config->iss = authn_config->realm;

	return authn_config;
}
#endif

struct _authn_s
{
	void *(*config)(config_setting_t *);
	authn_type_t type;
	const char *name;
};

struct _authn_s *authn_list[] =
{
#ifdef AUTHN_BASIC
	&(struct _authn_s){
		.config = &authn_basic_config,
		.type = AUTHN_BASIC_E,
		.name = "Basic",
	},
#endif
#ifdef AUTHN_DIGEST
	&(struct _authn_s){
		.config = &authn_digest_config,
		.type = AUTHN_DIGEST_E,
		.name = "Digest",
	},
#endif
#ifdef AUTHN_BEARER
	&(struct _authn_s){
		.config = &authn_bearer_config,
		.type = AUTHN_BEARER_E,
		.name = "Bearer",
	},
#endif
#ifdef AUTHN_OAUTH2
	&(struct _authn_s){
		.config = &authn_oauth2_config,
		.type = AUTHN_OAUTH2_E,
		.name = "oAuth2",
	},
#endif
#ifdef AUTHN_NONE
	&(struct _authn_s){
		.config = &authn_none_config,
		.type = AUTHN_NONE_E,
		.name = "None",
	},
#endif
	NULL
};

static int authn_config(config_setting_t *configauth, mod_authn_t *mod)
{
	int ret = EREJECT;

	char *type = NULL;
	config_setting_lookup_string(configauth, "type", (const char **)&type);
	if (type == NULL)
	{
		return ret;
	}

	int i = 0;
	struct _authn_s *authn = authn_list[i];
	while (authn != NULL && authn->config != NULL)
	{
		if (!strcmp(type, authn->name))
			mod->config = authn->config(configauth);
		if (mod->config != NULL)
		{
			break;
		}
		i++;
		authn = authn_list[i];
	}
	if (authn != NULL)
	{
		mod->type |= authn->type;
		mod->name = authn->name;
		ret = ESUCCESS;
	}
	return ret;
}

#ifdef AUTHZ_UNIX
static void *authz_unix_config(config_setting_t *configauth)
{
	authz_file_config_t *authz_config = NULL;
	char *path = NULL;

	config_setting_lookup_string(configauth, "file", (const char **)&path);
	if (path != NULL && path[0] != '0' && strstr(path, "shadow"))
	{
		authz_config = calloc(1, sizeof(*authz_config));
		authz_config->path = path;
	}
	return authz_config;
}
#endif
#ifdef AUTHZ_FILE
static void *authz_file_config(config_setting_t *configauth)
{
	authz_file_config_t *authz_config = NULL;
	char *path = NULL;

	config_setting_lookup_string(configauth, "file", (const char **)&path);
	if (path != NULL && path[0] != '0')
	{
		authz_config = calloc(1, sizeof(*authz_config));
		authz_config->path = path;
	}
	return authz_config;
}
#endif
#ifdef AUTHZ_SQLITE
static void *authz_sqlite_config(config_setting_t *configauth)
{
	authz_sqlite_config_t *authz_config = NULL;
	char *path = NULL;

	config_setting_lookup_string(configauth, "dbname", (const char **)&path);
	if (path != NULL && path[0] != '0')
	{
		authz_config = calloc(1, sizeof(*authz_config));
		authz_config->dbname = path;
	}
	return authz_config;
}
#endif
#ifdef AUTHZ_SIMPLE
static void *authz_simple_config(config_setting_t *configauth)
{
	authz_simple_config_t *authz_config = NULL;
	char *user = NULL;
	config_setting_lookup_string(configauth, "user", (const char **)&user);
	if (user != NULL && user[0] != '0')
	{
		char *passwd = NULL;
		char *group = NULL;
		char *home = NULL;
		config_setting_lookup_string(configauth, "passwd", (const char **)&passwd);
		config_setting_lookup_string(configauth, "group", (const char **)&group);
		config_setting_lookup_string(configauth, "home", (const char **)&home);
		authz_config = calloc(1, sizeof(*authz_config));
		authz_config->user = user;
		authz_config->group = group;
		authz_config->home = home;
		authz_config->passwd = passwd;
	}
	return authz_config;
}
#endif
#ifdef AUTHZ_JWT
	/**
	 * defautl configuration
	 */
static void *authz_jwt_config(config_setting_t *configauth)
{
	authz_jwt_config_t *authz_config = calloc(1, sizeof(*authz_config));
	return authz_config;
}
#endif

struct _authz_s
{
	void *(*config)(config_setting_t *);
	authz_type_t type;
	const char *name;
};

struct _authz_s *authz_list[] =
{
#ifdef AUTHZ_UNIX
	&(struct _authz_s){
		.config = &authz_unix_config,
		.type = AUTHZ_UNIX_E,
		.name = "unix",
	},
#endif
#ifdef AUTHZ_FILE
	&(struct _authz_s){
		.config = &authz_file_config,
		.type = AUTHZ_FILE_E,
		.name = "file",
	},
#endif
#ifdef AUTHZ_SQLITE
	&(struct _authz_s){
		.config = &authz_sqlite_config,
		.type = AUTHZ_SQLITE_E,
		.name = "sqlite",
	},
#endif
#ifdef AUTHZ_SIMPLE
	&(struct _authz_s){
		.config = &authz_simple_config,
		.type = AUTHZ_SIMPLE_E,
		.name = "simple",
	},
#endif
#ifdef AUTHZ_JWT
	&(struct _authz_s){
		.config = &authz_jwt_config,
		.type = AUTHZ_JWT_E,
		.name = "jwt",
	},
#endif
	NULL
};

static void authz_optionscb(void *arg, const char *option, size_t length)
{
	mod_auth_t *auth = (mod_auth_t *)arg;

	if (!strncmp(option, "home", length))
		auth->authz.type |= AUTHZ_HOME_E;
	if (!strncmp(option, "token", length))
		auth->authz.type |= AUTHZ_TOKEN_E;
	if (!strncmp(option, "chown", length))
		auth->authz.type |= AUTHZ_CHOWN_E;

	if (!strncmp(option, "cookie", length))
		auth->authn.type |= AUTHN_COOKIE_E;
	if (!strncmp(option, "header", length))
		auth->authn.type |= AUTHN_HEADER_E;
	if (!strncmp(option, "redirect", length))
		auth->authn.type |= AUTHN_REDIRECT_E;
}

static int authz_config(config_setting_t *configauth, mod_authz_t *mod)
{
	int ret = EREJECT;
	int i = 0;
	struct _authz_s *authz = authz_list[i];
	while (authz != NULL && authz->config != NULL)
	{
		mod->config = authz->config(configauth);
		if (mod->config != NULL)
		{
			break;
		}
		i++;
		authz = authz_list[i];
	}
	if (authz != NULL)
	{
		mod->type |= authz->type;
		mod->name = authz->name;
		ret = ESUCCESS;
	}
	return ret;
}

static mod_auth_t *auth_config(config_setting_t *iterator, int tls)
{
	mod_auth_t *auth = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configauth = config_setting_get_member(iterator, "auth");
#else
	config_setting_t *configauth = config_setting_lookup(iterator, "auth");
#endif
	if (configauth)
	{
		auth = calloc(1, sizeof(*auth));
		/**
		 * signin URI allowed to access to the signin page
		 */
		config_setting_lookup_string(configauth, "signin", &auth->redirect);
		config_setting_lookup_string(configauth, "protect", &auth->protect);
		config_setting_lookup_string(configauth, "unprotect", &auth->unprotect);
		/**
		 * algorithm allow to change secret algorithm used during authentication default is md5. (see authn_digest.c)
		 */
		config_setting_lookup_string(configauth, "algorithm", (const char **)&auth->algo);
		/**
		 * secret is the secret used during the token generation. (see authz_jwt.c)
		 */
		config_setting_lookup_string(configauth, "secret", (const char **)&auth->secret);

		char *mode = NULL;
		config_setting_lookup_string(configauth, "options", (const char **)&mode);
		if (tls)
			auth->authz.type |= AUTHZ_TLS_E;
		if (mode != NULL)
		{
			config_parseoptions(mode, &authz_optionscb, auth);
		}
		config_setting_lookup_int(configauth, "expire", &auth->expire);

		int ret;
		ret = authz_config(configauth, &auth->authz);
		if (ret == EREJECT)
		{
			err("config: authz is not set");
		}

		ret = authn_config(configauth, &auth->authn);
		if (ret == EREJECT)
		{
			err("config: authn type is not set");
		}
	}
	return auth;
}
#else
#define auth_config(...) NULL
#endif

#ifdef CGI
static mod_cgi_config_t *cgi_config(config_setting_t *iterator, int tls)
{
	mod_cgi_config_t *cgi = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configcgi = config_setting_get_member(iterator, "cgi");
#else
	config_setting_t *configcgi = config_setting_lookup(iterator, "cgi");
#endif
	if (configcgi)
	{
		cgi = calloc(1, sizeof(*cgi));
		config_setting_lookup_string(configcgi, "docroot", (const char **)&cgi->docroot);
		config_setting_lookup_string(configcgi, "allow", (const char **)&cgi->allow);
		config_setting_lookup_string(configcgi, "deny", (const char **)&cgi->deny);
		cgi->nbenvs = 0;
		cgi->chunksize = 64;
		cgi->options |= CGI_OPTION_TLS;
		cgi->chunksize = DEFAULT_CHUNKSIZE;
		config_setting_lookup_int(iterator, "chunksize", &cgi->chunksize);
#if LIBCONFIG_VER_MINOR < 5
		config_setting_t *cgienv = config_setting_get_member(configcgi, "env");
#else
		config_setting_t *cgienv = config_setting_lookup(configcgi, "env");
#endif
		if (cgienv)
		{
			int count = config_setting_length(cgienv);
			int i;
			cgi->env = calloc(sizeof(char *), count);
			for (i = 0; i < count; i++)
			{
				config_setting_t *iterator = config_setting_get_elem(cgienv, i);
				cgi->env[i] = config_setting_get_string(iterator);
			}
			cgi->nbenvs = count;
		}
	}
	return cgi;
}
#else
#define cgi_config(...) NULL
#endif

#ifdef WEBSOCKET
static void websocket_optionscb(void *arg, const char *option, size_t length)
{
	mod_websocket_t *conf = (mod_websocket_t *)arg;
#ifdef WEBSOCKET_RT
	if (!strncmp(option, "direct", length))
	{
		if (!(conf->options & WEBSOCKET_TLS))
			conf->options |= WEBSOCKET_REALTIME;
		else
			warn("realtime configuration is not allowed with tls");
	}
#endif
}

static mod_websocket_t *websocket_config(config_setting_t *iterator, int tls)
{
	mod_websocket_t *conf = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configws = config_setting_get_member(iterator, "websocket");
#else
	config_setting_t *configws = config_setting_lookup(iterator, "websocket");
#endif
	if (configws)
	{
		char *mode = NULL;
		conf = calloc(1, sizeof(*conf));
		config_setting_lookup_string(configws, "docroot", (const char **)&conf->docroot);
		config_setting_lookup_string(configws, "allow", (const char **)&conf->allow);
		config_setting_lookup_string(configws, "deny", (const char **)&conf->deny);
		config_setting_lookup_string(configws, "options", (const char **)&mode);
		if (tls)
			conf->options |= WEBSOCKET_TLS;
		config_parseoptions(mode, &websocket_optionscb, conf);
	}
	return conf;
}
#else
#define websocket_config(...) NULL
#endif

#ifdef WEBSTREAM
static void webstream_optionscb(void *arg, const char *option, size_t length)
{
	mod_webstream_t *conf = (mod_webstream_t *)arg;
#ifdef WEBSOCKET_RT
	if (!strncmp(option, "direct", length))
	{
		if (!(conf->options & WEBSOCKET_TLS))
			conf->options |= WEBSOCKET_REALTIME;
		else
			warn("realtime configuration is not allowed with tls");
	}
#endif
}

static mod_webstream_t *webstream_config(config_setting_t *iterator, int tls)
{
	mod_webstream_t *conf = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configws = config_setting_get_member(iterator, "webstream");
#else
	config_setting_t *configws = config_setting_lookup(iterator, "webstream");
#endif
	if (configws)
	{
		char *url = NULL;
		char *mode = NULL;
		conf = calloc(1, sizeof(*conf));
		config_setting_lookup_string(configws, "docroot", (const char **)&conf->docroot);
		config_setting_lookup_string(configws, "deny", (const char **)&conf->deny);
		config_setting_lookup_string(configws, "allow", (const char **)&conf->allow);
		config_setting_lookup_string(configws, "options", (const char **)&mode);
		if (tls)
			conf->options |= WEBSOCKET_TLS;
		config_parseoptions(mode, &webstream_optionscb, conf);
	}
	return conf;
}
#else
#define webstream_config(...) NULL
#endif

#ifdef UPGRADE
static void upgrade_optionscb(void *arg, const char *option, size_t length)
{
	mod_upgrade_t *conf = (mod_upgrade_t *)arg;
#ifdef WEBSOCKET_RT
	if (!strncmp(option, "direct", length))
	{
		if (!(conf->options & WEBSOCKET_TLS))
			conf->options |= WEBSOCKET_REALTIME;
		else
			warn("realtime configuration is not allowed with tls");
	}
#endif
}

static mod_upgrade_t *upgrade_config(config_setting_t *iterator, int tls)
{
	mod_upgrade_t *conf = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configws = config_setting_get_member(iterator, "upgrade");
#else
	config_setting_t *configws = config_setting_lookup(iterator, "upgrade");
#endif
	if (configws)
	{
		char *mode = NULL;
		conf = calloc(1, sizeof(*conf));
		config_setting_lookup_string(configws, "docroot", (const char **)&conf->docroot);
		config_setting_lookup_string(configws, "allow", (const char **)&conf->allow);
		config_setting_lookup_string(configws, "deny", (const char **)&conf->deny);
		config_setting_lookup_string(configws, "upgrade", (const char **)&conf->upgrade);
		config_setting_lookup_string(configws, "options", (const char **)&mode);
		if (tls)
			conf->options |= UPGRADE_TLS;
		config_parseoptions(mode, &upgrade_optionscb, conf);
	}
	return conf;
}
#else
#define upgrade_config(...) NULL
#endif

#ifdef REDIRECT
static int redirect_mode(const char *option, size_t length)
{
	int options = 0;
	if (!strncmp(option, "generate_204", length))
	{
		options |= REDIRECT_GENERATE204;
	}
	else if (!strncmp(option, "hsts", length))
	{
		options |= REDIRECT_HSTS;
	}
	else if (!strncmp(option, "temporary", length))
	{
		options |= REDIRECT_TEMPORARY;
	}
	else if (!strncmp(option, "permanently", length))
	{
		options |= REDIRECT_PERMANENTLY;
	}
	else if (!strncmp(option, "error", length))
	{
		options |= REDIRECT_ERROR;
	}
	return options;
}

static void redirect_optionscb(void *arg, const char *option, size_t length)
{
	mod_redirect_t *conf = (mod_redirect_t *)arg;
	conf->options = redirect_mode(option, length);
}

static void redirect_linkoptionscb(void *arg, const char *option, size_t length)
{
	mod_redirect_link_t *link = (mod_redirect_link_t *)arg;
	link->options = redirect_mode(option, length);
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
		config_parseoptions(mode, &redirect_linkoptionscb, link);
		link->options |= options;

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

static mod_redirect_t *redirect_config(config_setting_t *iterator, int tls)
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
		config_parseoptions(mode, &redirect_optionscb, conf);

		config_setting_t *configlinks = config_setting_lookup(config, "links");
		if (configlinks)
		{
			redirect_linksconfig(configlinks, conf);
		}
	}
	return conf;
}
#else
#define redirect_config(...) NULL
#endif

#ifdef CORS
static mod_cors_t *cors_config(config_setting_t *iterator, int tls)
{
	mod_cors_t *config = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *config_set = config_setting_get_member(iterator, "cors");
#else
	config_setting_t *config_set = config_setting_lookup(iterator, "cors");
#endif
	if (config_set)
	{
		config = calloc(1, sizeof(*config));
		config_setting_lookup_string(config_set, "origin", (const char **)&config->origin);
	}
	return config;
}
#else
#define cors_config(...) NULL
#endif

#ifdef VHOSTS
#warning VHOSTS is deprecated
static mod_vhost_t *vhost_config(config_setting_t *iterator, int tls)
{
	mod_vhost_t *vhost = NULL;
	char *hostname = NULL;

	config_setting_lookup_string(iterator, "hostname", (const char **)&hostname);
	if (hostname && hostname[0] != '0')
	{
		vhost = calloc(1, sizeof(*vhost));
		vhost->hostname = hostname;
		vhost->modules.document = document_config(iterator, tls, "document");
		if (vhost->modules.document == NULL)
			vhost->modules.document = document_config(iterator, tls, "static_file");
		if (vhost->modules.document == NULL)
		{
			vhost->modules.document = document_config(iterator, tls, "filestorage");
			if (vhost->modules.document != NULL)
				vhost->modules.document->options |= DOCUMENT_REST;
		}
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

static void config_mimes(config_setting_t *configmimes)
{
	if (configmimes == NULL)
		return;

	int count = config_setting_length(configmimes);
	int i;
	for (i = 0; i < count; i++)
	{
		char *ext = NULL;
		char *mime = NULL;
		config_setting_t *iterator = config_setting_get_elem(configmimes, i);
		if (iterator)
		{
			config_setting_lookup_string(iterator, "ext", (const char **)&ext);
			config_setting_lookup_string(iterator, "mime", (const char **)&mime);
			if (mime != NULL && ext != NULL)
			{
				utils_addmime(ext, mime);
			}
		}
	}
}

static serverconfig_t *config_server(config_setting_t *iterator)
{
	serverconfig_t *config = calloc(1, sizeof(*config));

	config->server = calloc(1, sizeof(*config->server));
	char *hostname = NULL;
	config_setting_lookup_string(iterator, "hostname", (const char **)&hostname);
	if (hostname && strchr(hostname, '.') == NULL)
	{
		err("hostname must contain the domain");
	}
	else if (hostname == NULL)
	{
		hostname = str_hostname;
	}
	warn("hostname %s", hostname);
	config->server->hostname = hostname;
	config->server->port = 80;
	config_setting_lookup_int(iterator, "port", &config->server->port);
	config_setting_lookup_string(iterator, "addr", (const char **)&config->server->addr);
	config_setting_lookup_int(iterator, "keepalivetimeout", &config->server->keepalive);
	config->server->chunksize = DEFAULT_CHUNKSIZE;
	config_setting_lookup_int(iterator, "chunksize", &config->server->chunksize);
	config->server->maxclients = DEFAULT_MAXCLIENTS;
	config_setting_lookup_int(iterator, "maxclients", &config->server->maxclients);
	config->server->version = HTTP11;
	const char *version = NULL;
	config_setting_lookup_string(iterator, "version", &version);
	if (version)
	{
		int i = 0;
		for (i = 0; httpversion[i] != NULL; i++)
		{
			if (!strcmp(version,  httpversion[i]))
			{
				config->server->version = i;
				break;
			}
		}
	}
	config->server->versionstr = httpversion[config->server->version];
	return config;
}

static void config_modules(config_setting_t *iterator, serverconfig_t *config)
{
	config_setting_lookup_string(iterator, "unlock_groups", (const char **)&config->unlock_groups);
	config->tls = tls_config(iterator);
	config->modules.document = document_config(iterator,(config->tls!=NULL), "document");
	if (config->modules.document == NULL)
		config->modules.document = document_config(iterator,(config->tls!=NULL), "static_file");
	if (config->modules.document == NULL)
	{
		config->modules.document = document_config(iterator,(config->tls!=NULL), "filestorage");
		if (config->modules.document != NULL)
			config->modules.document->options |= DOCUMENT_REST;
	}
	config->modules.auth = auth_config(iterator,(config->tls!=NULL));
	config->modules.clientfilter = clientfilter_config(iterator,(config->tls!=NULL));
	config->modules.userfilter = userfilter_config(iterator,(config->tls!=NULL));
	config->modules.cgi = cgi_config(iterator,(config->tls!=NULL));
	config->modules.websocket = websocket_config(iterator,(config->tls!=NULL));
	config->modules.redirect = redirect_config(iterator,(config->tls!=NULL));
	config->modules.cors = cors_config(iterator,(config->tls!=NULL));
	config->modules.webstream = webstream_config(iterator,(config->tls!=NULL));
	config->modules.upgrade = upgrade_config(iterator,(config->tls!=NULL));
#ifdef VHOSTS
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configvhosts = config_setting_get_member(iterator, "vhosts");
#else
	config_setting_t *configvhosts = config_setting_lookup(iterator, "vhosts");
#endif
	if (configvhosts)
	{
		int count = config_setting_length(configvhosts);
		int j;

		for (j = 0; j < count && j < MAX_SERVERS; j++)
		{
			config_setting_t *iterator = config_setting_get_elem(configvhosts, j);
			config->vhosts[j] = vhost_config(iterator,(config->tls!=NULL));
		}
	}
#endif
}


ouistiticonfig_t *ouistiticonfig_create(const char *filepath)
{
	int ret;

	gethostname(str_hostname, HOST_NAME_MAX);
	strncat(str_hostname, ".local", 7);

	if (access(filepath, R_OK))
	{
		err("config file: %s not found", filepath);
		return NULL;
	}
	config_init(&configfile);
	dbg("config file: %s", filepath);
	ret = config_read_file(&configfile, filepath);
	if (ret != CONFIG_TRUE)
	{
		err("%s", config_error_text(&configfile));
		return NULL;
	}
	ouistiticonfig_t *ouistiticonfig = calloc(1, sizeof(*ouistiticonfig));

	config_lookup_string(&configfile, "user", (const char **)&ouistiticonfig->user);
	config_lookup_string(&configfile, "log-file", (const char **)&logfile);
	if (logfile != NULL && logfile[0] != '\0')
	{
		logfd = open(logfile, O_WRONLY | O_CREAT | O_TRUNC, 00644);
		if (logfd > 0)
		{
			dup2(logfd, 1);
			dup2(logfd, 2);
			close(logfd);
		}
		else
			err("log file error %s", strerror(errno));
	}
	config_lookup_string(&configfile, "pid-file", (const char **)&ouistiticonfig->pidfile);
	config_setting_t *configmimes = config_lookup(&configfile, "mimetypes");
	config_mimes(configmimes);
	config_setting_t *configservers = config_lookup(&configfile, "servers");
	if (configservers)
	{
		int count = config_setting_length(configservers);
		int i;

		for (i = 0; i < count && i < MAX_SERVERS; i++)
		{
			config_setting_t *iterator = config_setting_get_elem(configservers, i);
			if (iterator)
			{
				ouistiticonfig->servers[i] = config_server(iterator);
				serverconfig_t *config = ouistiticonfig->servers[i];
				config_modules(iterator, config);
			}
		}
		ouistiticonfig->servers[i] = NULL;
	}

	return ouistiticonfig;
}

static void _modulesconfig_destroy(modulesconfig_t *config)
{
	if (config->document)
		free(config->document);
	if (config->websocket)
		free(config->websocket);
	if (config->redirect)
	{
		mod_redirect_link_t *link = config->redirect->links;
		while (link != NULL)
		{
			mod_redirect_link_t *old = link->next;
			free(link);
			link = old;
		}
		free(config->redirect);
	}
	if (config->auth)
	{
		if (config->auth->authn.config)
			free(config->auth->authn.config);
		if (config->auth->authz.config)
			free(config->auth->authz.config);
		free(config->auth);
	}
	if (config->cgi)
	{
		if (config->cgi->env)
			free(config->cgi->env);
		free(config->cgi);
	}
}

void ouistiticonfig_destroy(ouistiticonfig_t *ouistiticonfig)
{
	int i;

	if (logfd > 0)
		close(logfd);
	config_destroy(&configfile);

	for (i = 0; i < MAX_SERVERS; i++)
	{
		serverconfig_t *config = ouistiticonfig->servers[i];
		if (config)
		{
			_modulesconfig_destroy(&config->modules);
			if (config->tls)
				free(config->tls);
			free(config->server);
			free(config);
			ouistiticonfig->servers[i] = NULL;
		}
	}

	free(ouistiticonfig);
}
