/*****************************************************************************
 * cgi_env.c: Generate environment variables for CGI
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
#include <unistd.h>
#include <libgen.h>

#include "httpserver/httpserver.h"
#include "mod_cgi.h"
#include "mod_auth.h"

static char str_null[] = "";
static char str_gatewayinterface[] = "CGI/1.1";
static char str_contenttype[] = "Content-Type";

typedef char *(*httpenv_callback_t)(http_message_t request);
struct httpenv_s
{
	char *target;
	int length;
	httpenv_callback_t cb;
};
typedef struct httpenv_s httpenv_t;

enum cgi_env_e
{
	DOCUMENT_ROOT,
	SERVER_SOFTWARE,
	SERVER_NAME,
	GATEWAY_INTERFACE,
	SERVER_PROTOCOL,
	SERVER_ADDR,
	SERVER_PORT,
	REQUEST_METHOD,
	REQUEST_SCHEME,
	REQUEST_URI,
	CONTENT_LENGTH,
	CONTENT_TYPE,
	QUERY_STRING,
	HTTP_ACCEPT,
	HTTP_ACCEPT_ENCODING,
	HTTP_ACCEPT_LANGUAGE,
	PATH_INFO,
	PATH_TRANSLATED,
	SCRIPT_FILENAME,
	SCRIPT_NAME,
	REMOTE_HOST,
	REMOTE_ADDR,
	REMOTE_PORT,
	REMOTE_USER,
	AUTH_TYPE,
	HTTP_COOKIE,

	NBENVS,
};
static const httpenv_t cgi_env[] =
{
	{
		.target = "DOCUMENT_ROOT=",
		.length = 26,
	},
	{
		.target = "SERVER_SOFTWARE=",
		.length = 26,
	},
	{
		.target = "SERVER_NAME=",
		.length = 26,
	},
	{
		.target = "GATEWAY_INTERFACE=",
		.length = 26,
	},
	{
		.target = "SERVER_PROTOCOL=",
		.length = 10,
	},
	{
		.target = "SERVER_ADDR=",
		.length = 26,
	},
	{
		.target = "SERVER_PORT=",
		.length = 26,
	},
	{
		.target = "REQUEST_METHOD=",
		.length = 6,
	},
	{
		.target = "REQUEST_SCHEME=",
		.length = 6,
	},
	{
		.target = "REQUEST_URI=",
		.length = 512,
	},
	{
		.target = "CONTENT_LENGTH=",
		.length = 16,
	},
	{
		.target = "CONTENT_TYPE=",
		.length = 126,
	},
	{
		.target = "QUERY_STRING=",
		.length = 256,
	},
	{
		.target = "HTTP_ACCEPT=",
		.length = 256,
	},
	{
		.target = "HTTP_ACCEPT_ENCODING=",
		.length = 256,
	},
	{
		.target = "HTTP_ACCEPT_LANGUAGE=",
		.length = 256,
	},
	{
		.target = "PATH_INFO=",
		.length = 512,
	},
	{
		.target = "PATH_TRANSLATED=",
		.length = 512,
	},
	{
		.target = "SCRIPT_FILENAME=",
		.length = 512,
	},
	{
		.target = "SCRIPT_NAME=",
		.length = 64,
	},
	{
		.target = "REMOTE_HOST=",
		.length = 26,
	},
	{
		.target = "REMOTE_ADDR=",
		.length = INET6_ADDRSTRLEN,
	},
	{
		.target = "REMOTE_PORT=",
		.length = 26,
	},
	{
		.target = "REMOTE_USER=",
		.length = 26,
	},
	{
		.target = "AUTH_TYPE=",
		.length = 26,
	},
	{
		.target = "HTTP_COOKIE=",
		.length = 512,
	}
};

char **cgi_buildenv(mod_cgi_config_t *config, http_message_t *request, char *cgi_path)
{
	char **env = NULL;
	int nbenvs = NBENVS;

	const char *uri = httpmessage_REQUEST(request, "uri");
	char *query = strchr(uri,'?');

	env = calloc(sizeof(char *), nbenvs + config->nbenvs + 1);

	int i = 0;
	for (i = 0; i < nbenvs; i++)
	{
		int length = strlen(cgi_env[i].target) + cgi_env[i].length;
		env[i] = (char *)calloc(1, length + 1);
		const char *value = NULL;
		switch (i)
		{
			case DOCUMENT_ROOT:
				value = config->docroot;
			break;
			case GATEWAY_INTERFACE:
				value = str_gatewayinterface;
			break;
			case SERVER_SOFTWARE:
				value = httpmessage_SERVER(request, "software");
			break;
			case SERVER_NAME:
				value = httpmessage_SERVER(request, "name");
			break;
			case SERVER_PROTOCOL:
				value = httpmessage_SERVER(request, "protocol");
			break;
			case SERVER_PORT:
				value = httpmessage_SERVER(request, "port");
			break;
			case SERVER_ADDR:
				value = httpmessage_SERVER(request, "addr");
			break;
			case REQUEST_METHOD:
				value = httpmessage_REQUEST(request, "method");
			break;
			case REQUEST_SCHEME:
				value = httpmessage_REQUEST(request, "scheme");
			break;
			case REQUEST_URI:
				value = uri;
			break;
			case CONTENT_LENGTH:
				value = httpmessage_REQUEST(request, "Content-Length");
			break;
			case CONTENT_TYPE:
				value = httpmessage_REQUEST(request, str_contenttype);
			break;
			case QUERY_STRING:
				if (query != NULL)
					value = query + 1;
			break;
			case HTTP_ACCEPT:
				value = httpmessage_REQUEST(request, "Accept");
			break;
			case HTTP_ACCEPT_ENCODING:
				value = httpmessage_REQUEST(request, "Accept-Encoding");
			break;
			case HTTP_ACCEPT_LANGUAGE:
				value = httpmessage_REQUEST(request, "Accept-Language");
			break;
			case SCRIPT_NAME:
				value = basename(cgi_path);
			break;
			case SCRIPT_FILENAME:
				value = cgi_path;
			break;
			case PATH_INFO:
				value = cgi_path;
			break;
			case PATH_TRANSLATED:
				value = cgi_path;
			break;
			case REMOTE_ADDR:
				value = httpmessage_REQUEST(request, "remote_addr");
			break;
			case REMOTE_HOST:
				value = httpmessage_REQUEST(request, "remote_host");
			break;
			case REMOTE_PORT:
				value = httpmessage_REQUEST(request, "remote_port");
			break;
			case REMOTE_USER:
				value = auth_info(request, "user");
			break;
			case AUTH_TYPE:
				value = auth_info(request, "type");
			break;
			case HTTP_COOKIE:
				value = httpmessage_REQUEST(request, "Cookie");
			break;
			default:
				value = str_null;
		}
		if (value == NULL)
			value = str_null;
		snprintf(env[i], length + 1, "%s%s", cgi_env[i].target, value);
	}
	int j;
	for (j = 0; j < config->nbenvs; j++)
	{
		env[i + j] = (char *)config->env[j];
	}
	env[i + j] = NULL;
	return env;
}
