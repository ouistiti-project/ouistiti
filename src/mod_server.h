/*****************************************************************************
 * mod_server.h: Simple HTTPS module
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

#ifndef __MOD_SERVERHEADER_H__
#define __MOD_SERVERHEADER_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define SECURITY_FRAME			0x0001
#define SECURITY_OTHERORIGIN	0x0002
#define SECURITY_CACHE			0x0004
#define SECURITY_CONTENTTYPE	0x0008
typedef struct mod_security_s
{
	int options;
} mod_security_t;

extern const module_t mod_server;
void *mod_server_create(http_server_t *server, char *vhost, void *config);
void mod_server_destroy(void *data);

#ifdef __cplusplus
}
#endif

#endif
