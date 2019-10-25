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

#include "httpserver/hash.h"

#define PACKAGEVERSION PACKAGE "/" VERSION

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
	len  += sprintf(out + len, "%.*s", 32, user);
	if (len > outlen)
		return -1;
	len  += sprintf(out + len, ":");
	if (len > outlen)
		return -1;
	len  += sprintf(out + len, "%.*s", 32, realm);
	if (len > outlen)
		return -1;
	len  += sprintf(out + len, ":");
	if (len > outlen)
		return -1;
	len  += sprintf(out + len, "%.*s", 32, passwd);
	if (len > outlen)
		return -1;
	return len;
}
int crypt_password(char *string, char *out, int outlen, const hash_t *hash)
{
	char md5passwd[64];
	void * ctx = hash->init();
	hash->update(ctx, string, strlen(string));
	hash->finish(ctx, md5passwd);

	char b64passwd[25];
	base64->encode(md5passwd, hash->size, out, outlen);

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
	int mode = DIGEST;
	const hash_t *hash = NULL;
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
				mode &= ~MD5;
				if (!strcmp(optarg, "SHA-256"))
				{
					hash = hash_sha256;
					mode |= SHA256;
				}
				else if (!strcmp(optarg, "SHA-512"))
				{
					hash = hash_sha512;
					mode |= SHA512;
				}
				else if (!strcmp(optarg, "MD5"))
				{
					hash = hash_md5;
					mode |= SHA512;
				}
			break;
		}
	} while(opt != -1);
#endif
	setbuf(stdout, NULL);
	if (user != NULL)
	{
		if (passwd == NULL)
		{
			printf("Enter a new password (8 > 32: ");
			int i;
			passwd = calloc(33, sizeof(char));
			for(i = 0; i < 32; i++)
			{
				char c;
				read(0, &c, 1);
				if (c == '\n' || c == '\r')
					break;
				passwd[i] = c;
			}
			printf("Enter again the new password: ");
			char passwdagain[33];
			for(i = 0; i < sizeof(passwdagain); i++)
			{
				char c;
				read(0, &c, 1);
				if (c == '\n' || c == '\r')
					break;
				passwdagain[i] = c;
			}
			passwdagain[i] = 0;
			if (strcmp(passwd, passwdagain))
			{
				free(passwd);
				printf("Password not corresponding\n");
				exit(-1);
			}
		}

		char *output = calloc(100, sizeof(char));
		if (mode & DIGEST)
		{
			method_digest(user, passwd, realm, output, 100);
		}
		else
			output = passwd;
		char cryptpasswd[256];
		if (hash != NULL)
			ret = crypt_password(output, cryptpasswd, 256, hash);
		else
			base64->encode(output, strlen(output), cryptpasswd, 256);
		printf("%s:", user);
		if (mode & DIGEST && realm != NULL)
		{
			printf("$a%d$realm=%.*s$", mode & 0xFF, 32, realm);
		}
		else if (mode & BASIC)
		{
			printf("$a%d$$", mode & 0xFF);
		}
		printf("%s", cryptpasswd);
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
