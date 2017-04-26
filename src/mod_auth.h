/*****************************************************************************
 * mod_auth.h: Simple HTTP module
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

#ifdef __cplusplus
extern "C"
{
#endif
extern const char *str_authenticate;

typedef struct authz_simple_config_s authz_simple_config_t;
struct authz_simple_config_s
{
	char *user;
	char *passwd;
};

typedef void *(*authz_rule_create_t)(void *config);
typedef int (*authz_rule_check_t)(void *arg, char *user, char *passwd);
typedef char *(*authz_rule_passwd_t)(void *arg, char *user);
typedef void (*authz_rule_destroy_t)(void *arg);
typedef struct authz_rules_s authz_rules_t;
struct authz_rules_s
{
	authz_rule_create_t create;
	authz_rule_check_t check;
	authz_rule_passwd_t passwd;
	authz_rule_destroy_t destroy;
};
typedef enum
{
	AUTHZ_SIMPLE_E = 1,
} authz_type_t;
struct authz_s
{
	void *ctx;
	authz_rules_t *rules;
	authz_type_t type;
};
typedef struct authz_s authz_t;

typedef struct authn_basic_config_s authn_basic_config_t;
struct authn_basic_config_s
{
	char *realm;
};

typedef void *(*authn_rule_create_t)(authz_t *authz, void *config);;
typedef int (*authn_rule_challenge_t)(void *arg, http_message_t *request, http_message_t *response);
typedef char *(*authn_rule_check_t)(void *arg, char *string);
typedef void (*authn_rule_destroy_t)(void *arg);
typedef struct authn_rules_s authn_rules_t;
struct authn_rules_s
{
	authn_rule_create_t create;
	authn_rule_challenge_t challenge;
	authn_rule_check_t check;
	authn_rule_destroy_t destroy;
};
typedef enum
{
	AUTHN_BASIC_E = 1,
	AUTHN_DIGEST_E,
} authn_type_t;
typedef struct authn_s authn_t;
struct authn_s
{
	void *ctx;
	authn_rules_t *rules;
	authn_type_t type;
};

typedef struct mod_auth_s
{
	char *realm;
	void *authn_config;
	authn_type_t authn_type;
	void *authz_config;
	authz_type_t authz_type;
} mod_auth_t;

void *mod_auth_create(http_server_t *server, mod_auth_t *modconfig);
void mod_auth_destroy(void *mod);

#ifdef __cplusplus
}
#endif

#endif
