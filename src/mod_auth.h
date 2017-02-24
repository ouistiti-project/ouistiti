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

typedef void *(*authn_rule_create_t)(void *config);
typedef char *(*authn_rule_check_t)(void *arg, char *string);
typedef void (*authn_rule_destroy_t)(void *arg);
typedef struct authn_rule_s authn_rule_t;
struct authn_rule_s
{
	void *config;
	void *ctx;
	authn_rule_create_t create;
	authn_rule_check_t check;
	authn_rule_destroy_t destroy;
	enum
	{
		AUTHN_BASIC,
		AUTHN_DIGEST,
	} type;
};

typedef struct mod_auth_s
{
	char *realm;
	authn_rule_t *rule;
} mod_auth_t;

void *mod_auth_create(http_server_t *server, mod_auth_t *modconfig);
void mod_auth_destroy(void *mod);

#ifdef __cplusplus
}
#endif

#endif
