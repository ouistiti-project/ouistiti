/*****************************************************************************
 * ouipasswd.c: Password file generator
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
#define HAVE_GETOPT

#include "../version.h"

#define PACKAGEVERSION PACKAGE "/" VERSION

#if defined(MBEDTLS)
# include <mbedtls/base64.h>
# define BASE64_encode(in, inlen, out, outlen) \
	do { \
		size_t cnt = 0; \
		mbedtls_base64_encode(out, outlen, &cnt, in, inlen); \
	}while(0)
# define BASE64_decode(in, inlen, out, outlen) \
	do { \
		size_t cnt = 0; \
		mbedtls_base64_decode(out, outlen, &cnt, in, inlen); \
	}while(0)
#else
# include "b64/cencode.h"
# define BASE64_encode(in, inlen, out, outlen) \
	do { \
		base64_encodestate state; \
		base64_init_encodestate(&state); \
		int cnt = base64_encode_block(in, inlen, out, &state); \
		cnt = base64_encode_blockend(out + cnt, &state); \
		out[cnt - 1] = '\0'; \
	}while(0)
#endif

#if defined(MBEDTLS)
# include <mbedtls/md5.h>
# define MD5_ctx mbedtls_md5_context
# define MD5_init(pctx) \
	do { \
		mbedtls_md5_init(pctx); \
		mbedtls_md5_starts(pctx); \
	} while(0)
# define MD5_update(pctx, in, len) \
	mbedtls_md5_update(pctx, in, len)
# define MD5_finish(out, pctx) \
	do { \
		mbedtls_md5_finish((pctx), out); \
		mbedtls_md5_free((pctx)); \
	} while(0)
#elif defined (MD5_RONRIVEST)
# include "../utils/md5-c/global.h"
# include "../utils/md5-c/md5.h"
# define MD5_ctx MD5_CTX
# define MD5_init MD5Init
# define MD5_update MD5Update
# define MD5_finish MD5Final
#else
# include "../utils/md5/md5.h"
# define MD5_ctx md5_state_t
# define MD5_init md5_init
# define MD5_update md5_append
# define MD5_finish(out, pctx) md5_finish(pctx, out)
#endif

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

int crypt_ouimd5(const char *user, const char *passwd, const char *realm)
{
	char md5passwd[16];
	MD5_ctx ctx;
	MD5_init(&ctx);
	MD5_update(&ctx, user, strlen(user));
	MD5_update(&ctx, ":", 1);
	MD5_update(&ctx, realm, strlen(realm));
	MD5_update(&ctx, ":", 1);
	MD5_update(&ctx, passwd, strlen(passwd));
	MD5_finish(md5passwd, &ctx);
	char b64passwd[25];
	BASE64_encode(md5passwd, 16, b64passwd, 25);

	printf("%s:$a1$realm=%s$%s\n", user, realm, b64passwd);
	return 0;
}

void display_help(char * const *argv)
{
	fprintf(stderr, "%s [-h][-V]\n", argv[0]);
	fprintf(stderr, "\t-h \tshow this help and exit\n");
	fprintf(stderr, "\t-V \treturn the version and exit\n");
}

#define DIGESTMD5 1

int main(int argc, char * const *argv)
{
	int ret = -1;
	int mode = DIGESTMD5;
	const char *realm = NULL;
	const char *user = NULL;
	char *passwd = NULL;
	char *type = "Digest";
#ifdef HAVE_GETOPT
	int opt;
	do
	{
		opt = getopt(argc, argv, "hVR:u:p:");
		switch (opt)
		{
			case 'h':
				display_help(argv);
				return -1;
			break;
			case 'V':
				printf("%s\n",PACKAGEVERSION);
				return -1;
			break;
			case 'T':
				type = optarg;
			break;
			case 'R':
				realm = optarg;
			break;
			case 'u':
				user = optarg;
			break;
			case 'p':
				passwd = optarg;
			break;
		}
	} while(opt != -1);
#endif
	if (user != NULL && passwd != NULL)
	{
		switch (mode)
		{
			case DIGESTMD5:
				if (realm != NULL)
					ret = crypt_ouimd5(user, passwd, realm);
			break;
		}
	}
	return ret;
}
