/*****************************************************************************
 * testclient.c: Simple HTTP client
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "httpserver/httpserver.h"
#define CHUNKSIZE 64

#define HEADER 0x01
#define CONTENT 0x02
#define END 0x04

int main(int argc, char ** argv)
{
	int fd = 0;
	char *buffer;
	int length = CHUNKSIZE;
	int state = 0;
	int headerlength = 0;
	int contentlength = 0;

	int opt;
	do
	{
		opt = getopt(argc, argv, "i:");
		switch (opt)
		{
			case 'i':
				fd = open(optarg, O_RDWR);
			break;
		}
	} while(opt != -1);

	buffer = calloc(1, length);

	http_message_t *message;
	message = httpmessage_create(CHUNKSIZE);
	state |= HEADER;
	do
	{
		length = CHUNKSIZE;
		length = read(fd, buffer, length);
		buffer[length] = 0;
		if (length > 0)
		{
			int ret = 0;
			int rest = length;
			while (rest > 0)
			{
				length = rest;
				ret = httpmessage_parsecgi(message, buffer, &rest);
				fprintf(stderr, "rest %d %d/%d\n", ret, rest, length);
				if (ret != EINCOMPLETE)
				{
					contentlength += length;
				}
				else
				{
					length -= rest;
					headerlength += length;
				}
			}
		}
		else
		{
			fprintf(stderr, "no more data\n");
			state |= END;
		}
	} while (!(state & END));
	int result = httpmessage_result(message, 0);
	printf("%d %d %d\n", result, headerlength, contentlength);
	httpmessage_destroy(message);
	return 0;
}
