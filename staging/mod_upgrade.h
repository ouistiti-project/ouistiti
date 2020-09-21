/*****************************************************************************
 * mod_rhttp.h: rhttp server module
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

#ifndef __MOD_UPGRADE_H__
#define __MOD_UPGRADE_H__

#include "ouistiti.h"
#include "mod_websocket.h"

#define UPGRADE_REALTIME 0x01
#define UPGRADE_TLS      0x02

typedef int (*mod_upgrade_run_t)(void *arg, int socket, const char *filepath, http_message_t *request);
int default_upgrade_run(void *arg, int sock, const char *filepath, http_message_t *request);

#ifdef __cplusplus
extern "C"
{
#endif
typedef struct mod_upgrade_s mod_upgrade_t;
struct mod_upgrade_s
{
	char *docroot;
	char *upgrade;
	char *allow;
	char *deny;
	int options;
	mod_upgrade_run_t run;
};

extern const module_t mod_upgrade;

#ifdef __cplusplus
}
#endif

#endif
