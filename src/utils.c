/*****************************************************************************
 * utils.c: ouistiti utils  for modules
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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

#include "httpserver/httpserver.h"
#include "utils.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

static const char *_mimetype[] =
{
	"text/plain",
	"text/html",
	"text/css",
	"application/javascript",
	"image/png",
	"image/jpeg",
	"application/octet-stream",
};

typedef struct mime_entry_s
{
	char *ext;
	utils_mimetype_enum type;
} mime_entry_t;

static const mime_entry_t *mime_entry[] =
{
	&(mime_entry_t){
		.ext = ".html,.xhtml,.htm",
		.type = MIME_TEXTHTML,
	},
	&(mime_entry_t){
		.ext = ".css",
		.type = MIME_TEXTCSS,
	},
	&(mime_entry_t){
		.ext = ".js",
		.type = MIME_APPLICATIONJAVASCRIPT,
	},
	&(mime_entry_t){
		.ext = ".text",
		.type = MIME_TEXTPLAIN,
	},
	&(mime_entry_t){
		.ext = ".png",
		.type = MIME_IMAGEPNG,
	},
	&(mime_entry_t){
		.ext = ".jpg",
		.type = MIME_IMAGEJPEG,
	},
	&(mime_entry_t){
		.ext = "*",
		.type = MIME_APPLICATIONOCTETSTREAM,
	},
	NULL
};

const char *utils_getmime(char *filepath)
{
	mime_entry_t *mime = (mime_entry_t *)mime_entry[0];
	char *fileext = strrchr(filepath,'.');
	if (fileext == NULL)
		return NULL;
	while (mime)
	{
		if (utils_searchext(fileext, mime->ext) == ESUCCESS)
		{
			break;
		}
		mime++;
	}
	if (mime)
		return _mimetype[mime->type];
	return NULL;
}

char *str_location = "Location";

char *utils_urldecode(char *encoded)
{
	if (encoded == NULL)
		return NULL;
	int length = strlen(encoded);
	if (length == 0)
		return NULL;
	char *decoded = calloc(1, length + 1);
	char *offset = decoded;
	while (*encoded != '\0')
	{
		if (*encoded == '%')
		{
			encoded++;
			char *end = strchr(encoded, ';');
			if (end == NULL)
			{
				char encchar[2] = { encoded[0], encoded[1]};
				int encval = atoi(encchar);
				*offset = (char) encval;
				encoded += 2;
				offset++;
			}
			else
				encoded = end;
		}
		else if (encoded[0] == '.' && encoded[1] == '.' && encoded[2] == '/')
		{
			encoded+=3;
			if (offset > decoded && *(offset - 1) == '/')
			{
				offset--;
				*offset = '\0';
			}
			offset = strrchr(decoded, '/');
			if (offset == NULL)
				offset = decoded;
		}
		else if (*encoded == '?')
		{
			break;
		}
		else
		{
			*offset = *encoded;
			encoded++;
			offset++;
		}
	}
	*offset = 0;
	return decoded;
}

int utils_searchext(char *filepath, char *extlist)
{
	int ret = EREJECT;
	char *fileext = strrchr(filepath,'.');
	char ext_str[64];
	ext_str[63] = 0;
	if (fileext != NULL)
	{
		strncpy(ext_str, extlist, 63);
		char *ext = ext_str;
		char *ext_end = strchr(ext, ',');
		if (ext_end)
			*ext_end = 0;
		while (ext != NULL)
		{
			if (!strcmp(ext, fileext) || ext[0] == '*')
			{
				ret = ESUCCESS;
				break;
			}
			if (ext_end)
				ext = ext_end + 1;
			else
				break;
			ext_end = strchr(ext, ',');
			if (ext_end)
				*ext_end = 0;
		}
	}
	return ret;
}

char *utils_buildpath(char *docroot, char *path_info, char *filename, char *ext, struct stat *filestat)
{
	char *filepath;
	int length;

	length = strlen(docroot) + 1;
	length += strlen(path_info) + 1;
	length += strlen(filename);
	length += strlen(ext);
	filepath = calloc(1, length + 1);
	snprintf(filepath, length + 1, "%s/%s%s%s", docroot, path_info, filename, ext);

	filepath[length] = '\0';

	memset(filestat, 0, sizeof(*filestat));
	if (stat(filepath, filestat))
	{
		free(filepath);
		return NULL;
	}
	return filepath;
}
