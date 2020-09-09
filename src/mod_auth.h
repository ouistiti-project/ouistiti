/*****************************************************************************
 * mod_auth.h: HTTP Authentication module
 * this file is part of https://github.com/ouistiti-project/ouistiti
 *****************************************************************************
 * Copyright (C) 2016-2017
 *
 * Authors: Marc Chalain <marc.chalain@gmail.com
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

#ifndef __MOD_AUTH_H__
#define __MOD_AUTH_H__

#include <linux/limits.h>

#ifdef __cplusplus
extern "C"
{
#endif
extern const char str_authenticate[];
extern const char str_authorization[];
extern const char str_anonymous[];
extern const char *str_authenticate_engine[];

typedef struct mod_auth_s mod_auth_t;

typedef struct authsession_s
{
	char *type;
	char *user;
	char *group;
	char *home;
	char *passwd;
	char *urlspace;
	char *token;
} authsession_t;

typedef struct authz_simple_config_s authz_simple_config_t;
struct authz_simple_config_s
{
	const char *user;
	const char *passwd;
	const char *group;
	const char *home;
};

typedef struct authz_file_config_s authz_file_config_t;
struct authz_file_config_s
{
	const char *path;
};

typedef struct authz_sqlite_config_s authz_sqlite_config_t;
struct authz_sqlite_config_s
{
	const char *dbname;
};

typedef struct authz_jwt_config_s authz_jwt_config_t;
struct authz_jwt_config_s
{
	const char *none;
};

typedef void *(*authz_rule_create_t)(http_server_t *server, void *config);
typedef const char *(*authz_rule_check_t)(void *arg, const char *user, const char *passwd, const char *token);
typedef const int (*authz_rule_join_t)(void *arg, const char *user, const char *token, int expire);
typedef const char *(*authz_rule_passwd_t)(void *arg, const char *user);
typedef const char *(*authz_rule_group_t)(void *arg, const char *user);
typedef const char *(*authz_rule_home_t)(void *arg, const char *user);
typedef char *(*authz_rule_token_t)(void *arg, const char *user);
typedef int (*authz_rule_adduser_t)(void *arg, authsession_t *newuser);
typedef int (*authz_rule_changepasswd_t)(void *arg, authsession_t *newuser);
typedef int (*authz_rule_removeuser_t)(void *arg, authsession_t *newuser);
typedef void (*authz_rule_destroy_t)(void *arg);
typedef struct authz_rules_s authz_rules_t;
struct authz_rules_s
{
	authz_rule_create_t create;
	authz_rule_check_t check;
	authz_rule_join_t join;
	authz_rule_passwd_t passwd;
	authz_rule_group_t group;
	authz_rule_home_t home;
	authz_rule_token_t token;
	authz_rule_adduser_t adduser;
	authz_rule_changepasswd_t changepasswd;
	authz_rule_removeuser_t removeuser;
	authz_rule_destroy_t destroy;
};
typedef enum
{
	AUTHZ_SIMPLE_E = 1,
	AUTHZ_FILE_E,
	AUTHZ_UNIX_E,
	AUTHZ_SQLITE_E,
	AUTHZ_JWT_E,
	AUTHZ_TYPE_MASK = 0x0F,
	AUTHZ_HOME_E = 0x10,
	AUTHZ_TOKEN_E = 0x80,
	AUTHZ_CHOWN_E = 0x100,
	AUTHZ_TLS_E = 0x200,
} authz_type_t;
typedef struct authz_s authz_t;
typedef char *(*generatetoken_t)(mod_auth_t *mod, authsession_t *info);
struct authz_s
{
	void *ctx;
	authz_rules_t *rules;
	authz_type_t type;
	generatetoken_t generatetoken;
	const char *name;
};

struct mod_authz_s
{
	void *config;
	authz_type_t type;
	const char *name;
};
typedef struct mod_authz_s mod_authz_t;

typedef struct authn_none_config_s authn_none_config_t;
struct authn_none_config_s
{
	const char *user;
};

typedef struct authn_basic_config_s authn_basic_config_t;
struct authn_basic_config_s
{
	const char *realm;
};

typedef struct authn_digest_config_s authn_digest_config_t;
struct authn_digest_config_s
{
	const char *realm;
	const char *opaque;
};

typedef struct authn_bearer_config_s authn_bearer_config_t;
struct authn_bearer_config_s
{
	const char *realm;
};

typedef struct authn_oauth2_config_s authn_oauth2_config_t;
struct authn_oauth2_config_s
{
	const char *realm;
	const char *client_id;
	const char *client_passwd;
	const char *discovery;
	const char *auth_ep;
	const char *token_ep;
	const char *iss;
};

typedef struct authn_s authn_t;
typedef void *(*authn_rule_create_t)(const authn_t *authn, authz_t *authz, void *config);
typedef int (*authn_rule_setup_t)(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize);
typedef int (*authn_rule_challenge_t)(void *arg, http_message_t *request, http_message_t *response);
typedef const char *(*authn_rule_check_t)(void *arg, const char *method, const char *uri, const char *string);
typedef void (*authn_rule_destroy_t)(void *arg);
typedef struct authn_rules_s authn_rules_t;
struct authn_rules_s
{
	authn_rule_create_t create;
	authn_rule_setup_t setup;
	authn_rule_challenge_t challenge;
	authn_rule_check_t check;
	authn_rule_destroy_t destroy;
};
typedef enum
{
	AUTHN_NONE_E = 0,
	AUTHN_BASIC_E = 1,
	AUTHN_DIGEST_E,
	AUTHN_BEARER_E,
	AUTHN_OAUTH2_E,
	AUTHN_TYPE_MASK = 0x0F,
	AUTHN_REDIRECT_E = 0x10,
	AUTHN_COOKIE_E = 0x20,
	AUTHN_HEADER_E = 0x40,
} authn_type_t;

typedef struct hash_s hash_t;

struct authn_s
{
	void *ctx;
	authn_rules_t *rules;
	authn_type_t type;
	const hash_t *hash;
	http_server_t *server;
	mod_auth_t *config;
};

struct mod_authn_s
{
	void *config;
	authn_type_t type;
	const char *name;
};
typedef struct mod_authn_s mod_authn_t;

struct mod_auth_s
{
	mod_authn_t authn;
	mod_authz_t authz;
	const char *algo;
	const char *secret;
	const char *redirect;
	const char *protect;
	const char *unprotect;
	int expire;
};

extern const module_t mod_auth;

int authz_checkpasswd(const char *checkpasswd,
		const char *user, const char *realm, const char *passwd);
int authn_checksignature(const char *key,
		const char *data, size_t datalen,
		const char *sign, size_t signlen);

const char *auth_info(http_message_t *request, const char *key);
int auth_setowner(const char *user);

#ifdef __cplusplus
}
#endif

#endif
