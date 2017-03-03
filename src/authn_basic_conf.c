/*****************************************************************************
 * mod_auth.c: callbacks and management of connection
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "httpserver/httpserver.h"
#include "mod_auth.h"
#include "authn_basic_conf.h"
#include "b64/cencode.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

typedef struct authn_basic_s authn_basic_t;
struct authn_basic_s
{
	authn_basic_config_t *config;
	char *base64;
};

void *authn_basic_config_create(void *arg)
{
	authn_basic_config_t *config = (authn_basic_config_t *)arg;
	authn_basic_t *mod = calloc(1, sizeof(*mod));

	mod->config = config;

	int length = 0;
	int ulength = strlen(config->user);
	int plength = strlen(config->passwd);
	mod->base64 = calloc(1, (ulength + plength + 1 + 1) * 2);
	base64_encodestate encoder;
	base64_init_encodestate(&encoder);
	length += base64_encode_block(config->user, ulength, mod->base64 + length, &encoder);
	length += base64_encode_block(":", 1, mod->base64 + length, &encoder);
	length += base64_encode_block(config->passwd, plength, mod->base64 + length, &encoder);
	length += base64_encode_blockend(mod->base64 + length, &encoder);
	char *end = strrchr(mod->base64, '=');
	if (end)
	{
		end++;
		*end = 0;
	}
	return mod;
}

char *authn_basic_config_check(void *arg, char *string)
{
	authn_basic_t *mod = (authn_basic_t *)arg;
	if (!strcmp(string, mod->base64))
		return mod->config->user;
	return NULL;
}

void authn_basic_config_destroy(void *arg)
{
	authn_basic_t *mod = (authn_basic_t *)arg;
	if (mod->base64)
		free(mod->base64);
	free(mod);
}

authn_rule_t authn_basic_rule =
{
	.create = authn_basic_config_create,
	.check = authn_basic_config_check,
	.destroy = authn_basic_config_destroy,
	.type = AUTHN_BASIC,
};
