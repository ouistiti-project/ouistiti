/*****************************************************************************
 * mod_webstream.h: webstream server module
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

#ifndef __MOD_WEBSTREAM_H__
#define __MOD_WEBSTREAM_H__

#ifdef __cplusplus
extern "C"
{
#endif

typedef int (*mod_webstream_run_t)(void *arg, int socket, char *protocol, http_message_t *request);
int default_webstream_run(void *arg, int socket, char *protocol, http_message_t *request);

#define WS_SOCK_STREAM 0x01
#define WS_SOCK_DGRAM 0x02
#define WS_AF_UNIX 0x10
#define WS_AF_INET 0x20
#define WS_PROTO_DIRECT 0x0000
#define WS_PROTO_HTTP 0x0100

typedef struct mod_webstream_s mod_webstream_t;
struct mod_webstream_s
{
	char *mimetype;
	char *pathname;
	char *address;
	int port;
	int options;
};

void *mod_webstream_create(http_server_t *server, char *vhost, mod_webstream_t *config);
void mod_webstream_destroy(void *data);

#ifdef __cplusplus
}
#endif

#endif
