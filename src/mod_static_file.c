/*****************************************************************************
 * mod_static_file.c: callbacks and management of files
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
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "httpserver.h"
#include "uri.h"
#include "mod_static_file.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

static mod_static_file_t default_config = 
{
	.docroot = "/srv/www/htdocs",
	.accepted_ext = ".html,.xhtml,.htm,.css",
	.ignored_ext = ".php",
};
#define CONNECTOR_TYPE 0xAABBCCDD
struct _static_file_connector_s
{
	int type;
	void *previous;
	FILE *fileno;
};

static int static_file_connector(void *arg, http_message_t *request, http_message_t *response)
{
	mod_static_file_t *config = (mod_static_file_t *)arg;
	char content[64];
	char ext_str[64];
	char *ext;
	int size;
	struct _static_file_connector_s *private = httpmessage_private(request, NULL);

	do
	{
		if (!private)
		{
			private = calloc(1, sizeof(*private));
			private->type = CONNECTOR_TYPE;
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

	if (private->fileno == (void *)-1)
		return EREJECT;

	if (private->fileno == NULL)
	{
		char *str = httpmessage_REQUEST(request,"uri");

		if (str == NULL)
			return EREJECT;

		int length = 0;
		char *query = strchr(str, '?');
		if (query)
			length = query - str + 1;
		length = strlen(str) - length;
		length += strlen(config->docroot) + 1;

		char *filepath;
		filepath = calloc(1, length + 1);
		snprintf(filepath, length + 1, "%s/%s", config->docroot, str);

		char *fileext = strrchr(filepath,'.');
		if (fileext != NULL)
		{
			strncpy(ext_str, config->ignored_ext, 63);
			ext = strtok(ext_str, ",");
			while (ext != NULL)
			{
				if (!strcmp(ext, fileext))
				{
					free(filepath);
					free(private);
					private->fileno = (void *)-1;
					return EREJECT;
				}
				ext = strtok(NULL, ",");
			}
		}
		struct stat filestat;
		int ret = stat(filepath, &filestat);
		if (S_ISDIR(filestat.st_mode))
		{
			strncpy(ext_str, config->accepted_ext, 63);
			ext = strtok(ext_str, ",");
			length += sizeof("/index");
			while (ext != NULL)
			{
				int extlength = strlen(ext);
				free(filepath);
				filepath = calloc(1, length + extlength + 1);
				snprintf(filepath, length + extlength + 1, "%s/%s/index%s", config->docroot, str, ext);
				ret = stat(filepath, &filestat);
				if (ret == 0)
				{
					break;
				}
				ext = strtok(NULL, ",");
			}
		}
		/**
		 * file is found
		 * check the extension
		 */
		if (ret == 0)
		{
			ret = -1;
			fileext = strrchr(filepath,'.');
			if (fileext != NULL)
			{
				strncpy(ext_str, config->accepted_ext, 63);
				ext = strtok(ext_str, ",");
				while (ext != NULL)
				{
					if (!strcmp(ext, fileext))
					{
						ret = 0;
						break;
					}
					ext = strtok(NULL, ",");
				}
			}
		}
		if (ret != 0)
		{
			printf("file: %s not found\n", filepath);
			free(filepath);
			free(private);
			private->fileno = (void *)-1;
			return EREJECT;
		}
		private->fileno = fopen(filepath, "rb");
		httpmessage_private(request, (void *)private);
		httpmessage_addcontent(response, "text/html", NULL, filestat.st_size);
		return ECONTINUE;
	}
	if (feof(private->fileno))
	{
		fclose(private->fileno);
		private->fileno = NULL;
		free(private);
		return ESUCCESS;
	}
	size = fread(content, 1, sizeof(content) - 1, private->fileno);
	content[size] = 0;
	httpmessage_addcontent(response, NULL, content, -1);
	return ECONTINUE;
}

void *mod_static_file_create(http_server_t *server, mod_static_file_t *config)
{
	if (!config)
		config = &default_config;
	if (!config->docroot)
		config->docroot = default_config.docroot;
	if (!config->accepted_ext)
		config->accepted_ext = default_config.accepted_ext;
	if (!config->ignored_ext)
		config->ignored_ext = default_config.ignored_ext;
	httpserver_addconnector(server, NULL, static_file_connector, config);
	return config;
}

void mod_static_file_destroy(void *data)
{
}
