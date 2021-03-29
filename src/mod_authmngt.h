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

#ifndef __MOD_AUTHMNGT_H__
#define __MOD_AUTHMNGT_H__


#include "ouistiti.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef int (*authmngt_userlist_t)(void*arg, int nfields, char** values,char** keys);

typedef void *(*authmngt_rule_create_t)(http_server_t *server, void *config);
typedef int (*authmngt_rule_setsession_t)(void* arg, const char *user, authsession_t *info);
typedef int (*authmngt_rule_getuser_t)(void* arg, int id, authsession_t *info);
typedef int (*authmngt_rule_adduser_t)(void *arg, authsession_t *newuser);
typedef int (*authmngt_rule_changepasswd_t)(void *arg, authsession_t *newuser);
typedef int (*authmngt_rule_changeinfo_t)(void *arg, authsession_t *user);
typedef int (*authmngt_rule_removeuser_t)(void *arg, authsession_t *olduser);
typedef void (*authmngt_rule_destroy_t)(void *arg);
typedef struct authmngt_rules_s authmngt_rules_t;
struct authmngt_rules_s
{
	authmngt_rule_create_t create;
	authmngt_rule_setsession_t setsession;
	authmngt_rule_getuser_t getuser;
	authmngt_rule_adduser_t adduser;
	authmngt_rule_changepasswd_t changepasswd;
	authmngt_rule_changeinfo_t changeinfo;
	authmngt_rule_removeuser_t removeuser;
	authmngt_rule_destroy_t destroy;
};

typedef struct authmngt_s authmngt_t;
struct authmngt_s
{
	void *config;
	authmngt_rules_t *rules;
	const char *name;
};

typedef struct mod_authmngt_s mod_authmngt_t;
struct mod_authmngt_s
{
	authmngt_t mngt;
};

extern const module_t mod_authmngt;

#ifdef __cplusplus
}
#endif

#endif
