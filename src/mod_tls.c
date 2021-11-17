/*****************************************************************************
 * mod_tls.c: tls configuration functions
 * this file is part of https://github.com/ouistiti-project/libhttpserver
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
#include <errno.h>

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "ouistiti/log.h"
#include "ouistiti/httpserver.h"
#ifdef httpserver_config
#include "ouistiti/config.h"
#endif
#include "mod_tls.h"

#define tls_dbg(...)

const char str_tls[] = "tls";

#ifdef FILE_CONFIG
void *tls_config(void *arg, server_t *server)
{
	config_setting_t *iterator = (config_setting_t *)arg;
	mod_tls_t *tls = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configtls = config_setting_get_member(iterator, str_tls);
#else
	config_setting_t *configtls = config_setting_lookup(iterator, str_tls);
#endif
	if (configtls)
	{
		tls = calloc(1, sizeof(*tls));
		config_setting_lookup_string(configtls, "crtfile", (const char **)&tls->crtfile);
		config_setting_lookup_string(configtls, "keyfile", (const char **)&tls->keyfile);
		config_setting_lookup_string(configtls, "cachain", (const char **)&tls->cachain);
		config_setting_lookup_string(configtls, "dhmfile", (const char **)&tls->dhmfile);
	}
	return tls;
}
#else
static const mod_tls_t g_tls_config = {
	.crtfile = SYSCONFDIR"/ouistiti_srv.crt",
	.keyfile = SYSCONFDIR"/ouistiti_srv.key",
	.cachain = SYSCONFDIR"/ouistiti_ca.crt",
	.dhmfile = SYSCONFDIR"/ouistiti_dhparam.crt",
};

void *tls_config(void *arg, server_t *server)
{
	http_server_t *httpserver = ouistiti_httpserver(server);
	const char *port = httpserver_INFO(httpserver, "port");

	if (strstr(port, "443") != NULL)
		return (void *) &g_tls_config;
	return NULL;
}
#endif
