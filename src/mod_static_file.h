/*****************************************************************************
 * mod_static_file.h: Simple HTTPS module
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

#ifndef __MOD_STATIC_FILE_H__
#define __MOD_STATIC_FILE_H__

#include <dirent.h>

#define STATIC_FILE_DIRLISTING 0x01
#define STATIC_FILE_SENDFILE 0x02
#define STATIC_FILE_RANGE 0x04

#ifdef __cplusplus
extern "C"
{
#endif
typedef struct mod_static_file_s
{
	const char *docroot;
	const char *allow;
	const char *deny;
	const char *defaultpage;
	int options;
} mod_static_file_t;

void *mod_static_file_create(http_server_t *server, char *vhost, mod_static_file_t *config);
void mod_static_file_destroy(void *data);

/**
 * interface to change the data transfer function
 */
#define CONTENTCHUNK 63

typedef struct _mod_static_file_mod_s _mod_static_file_mod_t;
typedef struct _static_file_connector_s static_file_connector_t;
typedef int (*mod_transfer_t)(static_file_connector_t *private, http_message_t *response);

struct _mod_static_file_mod_s
{
	mod_static_file_t *config;
	void *vhost;
	mod_transfer_t transfer;
};

struct _static_file_connector_s
{
	int type;
	_mod_static_file_mod_t *mod;
	http_client_t *ctl;
	void *previous;
	char *path_info;
	char *filepath;
	int fd;
	DIR *dir;
	http_connector_t func;
	unsigned long long size;
	unsigned long long offset;
};

/**
 * specific connectors
 */
#ifdef RANGEREQUEST
int range_connector(void *arg, http_message_t *request, http_message_t *response);
#endif
int getfile_connector(void *arg, http_message_t *request, http_message_t *response);

int static_file_close(static_file_connector_t *private);

#ifdef __cplusplus
}
#endif

#endif
