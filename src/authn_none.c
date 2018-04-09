/*****************************************************************************
 * authn_none.c: None Authentication mode
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
 * this module doesn't authenticate the user.
 * It changes the owner of the client process only.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

#include "httpserver/httpserver.h"
#include "httpserver/hash.h"
#include "mod_auth.h"
#include "authn_none.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

typedef struct authn_none_s authn_none_t;
struct authn_none_s
{
	authn_none_config_t *config;
	authz_t *authz;
	char *challenge;
};

static void *authn_none_create(authn_t *authn, authz_t *authz, void *arg)
{
	authn_none_t *mod = calloc(1, sizeof(*mod));
	mod->config = (authn_none_config_t *)arg;

	return mod;
}

static int authn_none_challenge(void *arg, http_message_t *request, http_message_t *response)
{
	authn_none_t *mod = (authn_none_t *)arg;
	authn_none_config_t *config = mod->config;
	struct passwd *pw = NULL;
	if (config->user)
	{
		errno = 0;
		pw = getpwnam(config->user);
	}
	if (pw)
	{
		setgid(pw->pw_gid);
		setuid(pw->pw_uid);
	}
	else
	{
		if (errno == 0 || errno == ENOENT || errno == ESRCH ||
				errno == EBADF || errno == EPERM)
			err("Security set the user of authentication in configuration");
		else
			err("auth getpwnam error %s", strerror(errno));
		setuid(1000);
	}
	return EREJECT;
}

static char *authn_none_check(void *arg, const char *method, const char *uri, char *string)
{
	return NULL;
}

static void authn_none_destroy(void *arg)
{
	authn_none_t *mod = (authn_none_t *)arg;
	free(mod);
}

authn_rules_t authn_none_rules =
{
	.create = authn_none_create,
	.challenge = authn_none_challenge,
	.check = authn_none_check,
	.destroy = authn_none_destroy,
};
