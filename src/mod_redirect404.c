/*****************************************************************************
 * mod_redirect404.c: Redirect the request on 404 error
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "mod_redirect404.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

typedef struct _mod_redirect404_s _mod_redirect404_t;

static int _mod_redirect404_connector(void *arg, http_message_t *request, http_message_t *response);

static const char str_redirect404[] = "redirect404";

struct _mod_redirect404_s
{
	char *nothing;
};

static void *mod_redirect404_create(http_server_t *server, mod_redirect404_t *config)
{
	httpserver_addconnector(server, _mod_redirect404_connector, config, 9, str_redirect404);
	return config;
}

static void mod_redirect404_destroy(void *arg)
{
	// nothing to do
}

static int _mod_redirect404_connector(void *arg, http_message_t *request, http_message_t *response)
{
	const char *uri = httpmessage_REQUEST(request, "uri");
	warn("redirect 404: %s", uri);
	httpmessage_result(response, RESULT_404);
	return EREJECT;
}

const module_t mod_redirect404 =
{
	.name = str_redirect404,
	.create = (module_create_t)&mod_redirect404_create,
	.destroy = &mod_redirect404_destroy
};

#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_redirect404")));
#endif
