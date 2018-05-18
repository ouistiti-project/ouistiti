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

int method_digest(const char *user, const char *passwd, const char *realm, char *out, int outlen)
{
	int len = 0;
	if (len > outlen)
		return -1;
	len  += sprintf(out + len, user);
	if (len > outlen)
		return -1;
	len  += sprintf(out + len, ":");
	if (len > outlen)
		return -1;
	len  += sprintf(out + len, realm);
	if (len > outlen)
		return -1;
	len  += sprintf(out + len, ":");
	if (len > outlen)
		return -1;
	len  += sprintf(out + len, passwd);
	if (len > outlen)
		return -1;
	return len;
}
int crypt_ouimd5(char *string, char *out, int outlen)
{
	char md5passwd[16];
	MD5_ctx ctx;
	MD5_init(&ctx);
	MD5_update(&ctx, string, strlen(string));
	MD5_finish(md5passwd, &ctx);
	char b64passwd[25];
	BASE64_encode(md5passwd, 16, out, outlen);

	return strlen(out);
}

void display_help(char * const *argv)
{
	fprintf(stderr, "%s [-h][-V]\n", argv[0]);
	fprintf(stderr, "\t-h \tshow this help and exit\n");
	fprintf(stderr, "\t-V \treturn the version and exit\n");
	fprintf(stderr, "\t-R \tset the realm of the connection\n");
	fprintf(stderr, "\t-T <Basic|Digest>\tset the type of security\n");
	fprintf(stderr, "\t-u <name>\tset the user name\n");
	fprintf(stderr, "\t-p <value>\tset the password\n");
	fprintf(stderr, "\t-g <name>\tset the group\n");
	fprintf(stderr, "\t-H <directory>\tset the home directory\n");
	fprintf(stderr, "\t-A [MD5|SHA-256|SHA-512)\tset the encryption method\n");
}

#define MD5 1
#define SHA256 5
#define SHA512 6
#define BASIC 0x1000
#define DIGEST 0x2000
int main(int argc, char * const *argv)
{
	int ret = -1;
	int mode = DIGEST|MD5;
	const char *realm = NULL;
	const char *user = NULL;
	char *passwd = NULL;
	char *group = NULL;
	char *home = NULL;
#ifdef HAVE_GETOPT
	int opt;
	do
	{
		opt = getopt(argc, argv, "hVR:u:g:p:T:H:A:");
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
				if (!strcmp(optarg, "Digest"))
					mode |= DIGEST;
				if (!strcmp(optarg, "Basic"))
					mode |= BASIC;
			break;
			case 'R':
				realm = optarg;
			break;
			case 'u':
				user = optarg;
			break;
			case 'g':
				group = optarg;
			break;
			case 'p':
				passwd = optarg;
			break;
			case 'H':
				home = optarg;
			break;
			case 'A':
				if (!strcmp(optarg, "MD5"))
					mode |= MD5;
				if (!strcmp(optarg, "SHA-256"))
					mode |= SHA256;
				if (!strcmp(optarg, "SHA-512"))
					mode |= SHA512;
			break;
		}
	} while(opt != -1);
#endif
	setbuf(stdout, NULL);
	if (user != NULL)
	{
		if (passwd == NULL)
		{
			printf("Enter a new password: ");
			int i;
			passwd = calloc(256, sizeof(char));
			for(i = 0; i < 256; i++)
			{
				char c;
				read(0, &c, 1);
				if (c == '\n' || c == '\r')
					break;
				passwd[i] = c;
			}
			printf("Enter again the new password: ");
			char *passwdagain = calloc(256, sizeof(char));
			for(i = 0; i < 256; i++)
			{
				char c;
				read(0, &c, 1);
				if (c == '\n' || c == '\r')
					break;
				passwdagain[i] = c;
			}
			if (strcmp(passwd, passwdagain))
			{
				free(passwd);
				free(passwdagain);
				printf("Password not corresponding\n");
				exit(-1);
			}
			free(passwdagain);
		}

		char *output = calloc(256, sizeof(char));
		if (mode & DIGEST)
		{
			method_digest(user, passwd, realm, output, 256);
		}
		char cryptpasswd[64];
		switch (mode & 0xFF)
		{
			case MD5:
				ret = crypt_ouimd5(output, cryptpasswd, 64);
			break;
			case SHA256:
				ret = crypt_ouimd5(output, cryptpasswd, 64);
			break;
			case SHA512:
				ret = crypt_ouimd5(output, cryptpasswd, 64);
			break;
		}
		printf("%s:", user);
		if (mode & DIGEST && realm != NULL)
		{
			printf("$a%d$realm=%s$", mode & 0xFF, realm);
		}
		else if (mode & BASIC)
		{
			printf("$a%d$$", mode & 0xFF);
		}
		printf(cryptpasswd);
		if (group)
			printf(":%s",group);
		if (group  && home)
			printf(":%s",home);
		else if (home)
			printf("::%s",home);
		printf("\n");
	}
	return ret;
}
