/*****************************************************************************
 * mod_document.h: Simple HTTPS module
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

#ifndef __MOD_DOCUMENT_H__
#define __MOD_DOCUMENT_H__

#include <dirent.h>

#define DOCUMENT_DIRLISTING 0x01
#define DOCUMENT_SENDFILE 0x02
#define DOCUMENT_RANGE 0x04
#define DOCUMENT_REST 0x08
#define DOCUMENT_HOME 0x10
#define DOCUMENT_TLS 0x20

#include "ouistiti.h"

#ifdef __cplusplus
extern "C"
{
#endif
typedef struct mod_document_s
{
	const char *docroot;
	const char *dochome;
	const char *allow;
	const char *deny;
	const char *defaultpage;
	int options;
} mod_document_t;

extern const module_t mod_document;

/**
 * interface to change the data transfer function
 */
#define CONTENTCHUNK 64

typedef struct _mod_document_mod_s _mod_document_mod_t;
typedef struct _document_connector_s document_connector_t;
typedef int (*mod_transfer_t)(document_connector_t *private, http_message_t *response);

struct _mod_document_mod_s
{
	mod_document_t *config;
	void *vhost;
	mod_transfer_t transfer;
	int fdroot;
	int fdhome;
};

struct _document_connector_s
{
	_mod_document_mod_t *mod;
	http_client_t *ctl;
	void *previous;
	const char *url;
	int fdfile;
	int fdroot;
	int type;
	DIR *dir;
	http_connector_t func;
	unsigned long long size;
	unsigned long long offset;
#ifdef DEBUG
	struct timespec start;
	unsigned long long datasize;
#endif
};

/**
 * specific connectors
 */
#ifdef RANGEREQUEST
int range_connector(void *arg, http_message_t *request, http_message_t *response);
#endif
#ifdef DIRLISTING
int dirlisting_connector(void *arg, http_message_t *request, http_message_t *response);
#endif
int getfile_connector(void *arg, http_message_t *request, http_message_t *response);
#ifdef DOCUMENTREST
int putfile_connector(void *arg, http_message_t *request, http_message_t *response);
int postfile_connector(void *arg, http_message_t *request, http_message_t *response);
int deletefile_connector(void *arg, http_message_t *request, http_message_t *response);
#endif

int document_close(document_connector_t *private, http_message_t *request);

#ifdef __cplusplus
}
#endif

#endif
