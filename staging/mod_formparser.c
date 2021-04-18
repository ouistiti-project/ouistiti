/*****************************************************************************
 * mod_form_urlencoded.c: callbacks and management of connection
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
#if defined(__GNUC__) && !defined(_GNU_SOURCE)
# define _GNU_SOURCE
#else
# define strcasestr strstr
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "ouistiti/log.h"
#include "ouistiti/httpserver.h"
#include "ouistiti/dbentry.h"
#include "mod_form_urlencoded.h"

typedef struct _mod_form_urlencoded_config_s _mod_form_urlencoded_config_t;
typedef struct _mod_form_urlencoded_s _mod_form_urlencoded_t;

static http_server_config_t mod_form_urlencoded_config;

static void *_mod_form_urlencoded_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize);
static void _mod_form_urlencoded_freectx(void *vctx);
static int _mod_form_urlencoded_recv(void *vctx, char *data, int size);
static int _mod_form_urlencoded_send(void *vctx, char *data, int size);
static int _form_connector(void **arg, http_message_t *request, http_message_t *response);
static int _form_urlencoded_connector(void *arg, http_message_t *request, http_message_t *response);
static int _form_data_connector(void *arg, http_message_t *request, http_message_t *response);
static void _mod_form_urlencoded_addpost(http_message_t *message, char *key, char *value);

struct _mod_form_urlencoded_s
{
	_mod_form_urlencoded_config_t *config;
	http_client_t *ctl;
	void *oldctx;
	http_recv_t recvreq;
	http_send_t sendresp;
	char *data;
	int datasize;
	char *boundary;
	char keylen;
	char end;
};

#define CONNECTOR_TYPE 0xC001
struct _form_urlencoded_connector_s
{
	int type;
	void *previous;
	dbentry_t *post;
};

struct _mod_form_urlencoded_config_s
{
	char *header_key;
	char *header_value;
};

void *mod_form_urlencoded_create(http_server_t *server, mod_form_urlencoded_t *modconfig)
{
	_mod_form_urlencoded_config_t *config;

	config = calloc(1, sizeof(*config));

	httpserver_addmod(server, _mod_form_urlencoded_getctx, _mod_form_urlencoded_freectx, config);

	return config;
}

void mod_form_urlencoded_destroy(void *mod)
{
	_mod_form_urlencoded_config_t *config = (_mod_form_urlencoded_config_t *)mod;
	free(config);
}

static void *_mod_form_urlencoded_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_form_urlencoded_t *ctx = calloc(1, sizeof(*ctx));
	_mod_form_urlencoded_config_t *config = (_mod_form_urlencoded_config_t *)arg;

	ctx->ctl = ctl;
	ctx->config = config;

	ctx->oldctx = httpclient_context(ctl);
	httpclient_addconnector(ctl, _form_connector, ctx, CONNECTOR_DOCFILTER, "formparser");
	ctx->recvreq = httpclient_addreceiver(ctl, _mod_form_urlencoded_recv, ctx);
	ctx->sendresp = httpclient_addsender(ctl, _mod_form_urlencoded_send, ctx);

	return ctx;
}

static void _mod_form_urlencoded_freectx(void *vctx)
{
	_mod_form_urlencoded_t *ctx = (_mod_form_urlencoded_t *)vctx;
	free(ctx);
}

static int _mod_form_urlencoded_recv(void *vctx, char *data, int size)
{
	int ret;
	_mod_form_urlencoded_t *ctx = (_mod_form_urlencoded_t *)vctx;
	ret = ctx->recvreq(ctx->oldctx, data, size);
	if (ret < size)
		ctx->end = 1;
	ctx->data = data;
	return ret;
}

static int _mod_form_urlencoded_send(void *vctx, char *data, int size)
{
	int ret;
	_mod_form_urlencoded_t *ctx = (_mod_form_urlencoded_t *)vctx;
	ret = ctx->sendresp(ctx->oldctx, data, size);
	return ret;
}

static const char empty[] = "";
static const char _form_urlencoded_mime[] = "application/x-www-form-urlencoded";
static const char _multipart_form_data_mime[] = "multipart/form-data";
static int _form_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EREJECT;
	_mod_form_urlencoded_t *ctx = (_mod_form_urlencoded_t *)arg;
	_mod_form_urlencoded_config_t *config = ctx->config;

	char *content_type = httpmessage_REQUEST(request, "Content-Type");
	char *urlencoded = strstr(content_type, _form_urlencoded_mime);
	char *data =  strstr(content_type, _multipart_form_data_mime);
	if (urlencoded)
	{
		httpmessage_addcontent(request, (char *)_form_urlencoded_mime, ctx->data, -1);
		ret = _form_urlencoded_connector(arg, request, response);
	}
	else if (data)
	{
		ctx->boundary = strchr(strstr(data, "boundary"), '=') + 1;
		//ret = _form_data_connector(arg, request, response);
	}
	printf("message post %s\n", mod_form_urlencoded_post(request, "toto"));

	return ret;
}

static int _form_urlencoded_connector(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_form_urlencoded_t *ctx = (_mod_form_urlencoded_t *)arg;
	_mod_form_urlencoded_config_t *config = ctx->config;

		char *data = httpmessage_REQUEST(request, "content") + ctx->datasize - ctx->keylen;
		int size = strlen(ctx->data);
		ctx->datasize += size;
		char *offset = data;
		char *key = data;
		char *value = 0;
		int length;

		data += size + ctx->keylen;
		while (offset < data)
		{
			int insert = 0;
			switch (*offset)
			{
				case '\0':
				{
					insert = 1;
				}
				break;
				case '=':
				{
					if (value == NULL)
					{
						//*offset  = '\0';
						value = offset + 1;
						length = 0;
					}
				}
				break;
				case '\r':
				{
					*offset = '\0';
				}
				break;
				case '\n':
				{
					*offset = '\0';
					insert = 1;
				}
				break;
				default:
				{
					length++;
				}
			}
			if (insert)
			{
				if (length > 0 && value != NULL)
				{
					*(value - 1) = '\0';
					_mod_form_urlencoded_addpost(request, key, value);
				}
				else
				{
					_mod_form_urlencoded_addpost(request, key, (char *)empty);
				}
				ctx->keylen = 0;
				key = offset + 1;
				value = NULL;
			}
			ctx->keylen++;
			offset++;
		}
		if (ctx->end)
		{
			if (length > 0 && value != NULL)
			{
				*(value - 1) = '\0';
				_mod_form_urlencoded_addpost(request, key, value);
			}
			else
			{
				_mod_form_urlencoded_addpost(request, key, (char *)empty);
			}
			ctx->keylen = 0;
			key = offset + 1;
			value = NULL;
		}
	return EREJECT;
}

/**
Content-Type: multipart/form-data; boundary=---------------------------424515057184651579458938494
Content-Length: 331

-----------------------------424515057184651579458938494
Content-Disposition: form-data; name="test"; filename=""
Content-Type: application/octet-stream


-----------------------------424515057184651579458938494
Content-Disposition: form-data; name="toto"

test
-----------------------------424515057184651579458938494--
**/
static int _form_data_connector(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_form_urlencoded_t *ctx = (_mod_form_urlencoded_t *)arg;
	_mod_form_urlencoded_config_t *config = ctx->config;

	char *data = ctx->data;
	int size = strlen(ctx->data);
	ctx->datasize += size;
	char *offset = data;
	char *key = data;
	char *value = 0;
	int length;

	data += size + ctx->keylen;
	while (offset < data)
	{
		int insert = 0;
		switch (*offset)
		{
			case '-':
			{
				if (ctx->boundary && strstr(offset, ctx->boundary))
				{
					offset += strlen(ctx->boundary) + 1;
					if (*offset == '-')
						ctx->end = 1;
					if (key != NULL)
						insert = 1;
				}
			}
			break;
			case 'C':
			{
				char *disposition = strcasestr(offset, "Content-Disposition");
				if (disposition)
				{
					char *info = strchr(disposition, ':');
					char *name = strcasestr(info, "name");
					if (name)
					{
						int length = 0;
						name = strchr(name, '=') + 1;
						if (*name == '\"')
							name++;
						while (name[length] != '\"' && name[length] != ';') length++;
						key = httpmessage_addcontent(request, (char *)_form_urlencoded_mime, name, length);
						httpmessage_addcontent(request, (char *)_form_urlencoded_mime, "", 1);
						name += length;
						offset = name;
					}
					char *filename = strcasestr(info, "filename");
					if (filename)
					{
						int length = 0;
						filename = strchr(filename, '=') + 1;
						if (*filename == '\"')
							filename++;
						while (filename[length] != '\"' && filename[length] != ';') length++;
						char *tkey = httpmessage_addcontent(request, (char *)_form_urlencoded_mime, "filename", 8);
						if (key)
						{
							httpmessage_addcontent(request, (char *)_form_urlencoded_mime, "_", 1);
							httpmessage_addcontent(request, (char *)_form_urlencoded_mime, key, strlen(key));
						}
						httpmessage_addcontent(request, (char *)_form_urlencoded_mime, "", 1);
						char *tvalue = httpmessage_addcontent(request, (char *)_form_urlencoded_mime, filename, length);
						httpmessage_addcontent(request, (char *)_form_urlencoded_mime, "", 1);

						_mod_form_urlencoded_addpost(request, tkey, tvalue);
					}
					offset = strchr(offset,';');
				}
				else
				{
					length++;
				}
			}
			break;
			case '\r':
			{
				*offset = '\0';
			}
			break;
			case '\n':
			{
				*offset = '\0';
				if (length == 0)
					value = offset + 1;
				length = 0;
			}
			break;
			default:
			{
				length++;
			}
		}
		if (insert)
		{
			if (length > 0 && value != NULL)
			{
				*(value - 1) = '\0';
				_mod_form_urlencoded_addpost(request, key, value);
			}
			else
			{
				_mod_form_urlencoded_addpost(request, key, (char *)empty);
			}
			ctx->keylen = 0;
			key = offset + 1;
			value = NULL;
		}
		ctx->keylen++;
		offset++;
	}
	return EREJECT;
}

char *mod_form_urlencoded_post(http_message_t *message, char *key)
{
	struct _form_urlencoded_connector_s *private = httpmessage_private(message, NULL);

	do
	{
		if (!private)
		{
			return NULL;
		}
		else if (private->type != CONNECTOR_TYPE)
		{
			private = private->previous;
			continue;
		}
	} while(0);

	char *value = NULL;
	dbentry_t *post = private->post;
	while (post != NULL)
	{
		if (!strcasecmp(post->key, key))
		{
			value = post->value;
			break;
		}
		post = post->next;
	}
	return value;
}

static void _mod_form_urlencoded_addpost(http_message_t *message, char *key, char *value)
{
	struct _form_urlencoded_connector_s *private = httpmessage_private(message, NULL);

	do
	{
		if (!private)
		{
			private = calloc(1, sizeof(*private));
			private->type = CONNECTOR_TYPE;
			httpmessage_private(message, (void *)private);
		}
		else if (private->type != CONNECTOR_TYPE)
		{
			if (private->previous)
			{
				private = private->previous;
				continue;
			}
			private->previous = calloc(1, sizeof(*private));
			private->type = CONNECTOR_TYPE;
			private = private->previous;
		}
	} while(0);

	dbentry_t *headerinfo;
	headerinfo = calloc(1, sizeof(dbentry_t));
	headerinfo->key = key;
	headerinfo->value = value;
	headerinfo->next = private->post;
	private->post = headerinfo;
}

const module_t mod_formparser =
{
	.name = str_formparser,
	.create = (module_create_t)mod_formparser_create,
	.destroy = mod_formparser_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_formparser")));
