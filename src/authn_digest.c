/*****************************************************************************
 * authn_digest.c: Basic Authentication mode
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
#include <time.h>

#include "httpserver/httpserver.h"
#include "mod_auth.h"
#include "authn_digest.h"
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
# include "b64/cdecode.h"
# define BASE64_decode(in, inlen, out, outlen) \
	do { \
		base64_decodestate state; \
		int cnt = base64_decode_block(in, inlen, out, &state); \
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

typedef struct authn_digest_s authn_digest_t;
struct authn_digest_s
{
	authn_digest_config_t *config;
	authz_t *authz;
	char *challenge;
	char opaque[33];
	char nonce[35];
	int stale;
};

static void authn_digest_opaque(void *arg, char *opaque, int opaquelen);

static void utils_searchstring(char **result, char *haystack, char *needle, int length)
{
	if ((*result == NULL || *result[0] == '\0') &&
		!strncmp(haystack, needle, length) && haystack[length] == '=')
	{
		char *end = NULL;
		*result = strchr(haystack, '=') + 1;
		if (**result == '"')
		{
			*result = *result + 1;
			end = strchr(*result, '"');
		}
		else
		{
			end = *result;
			while(*end != 0 && *end != ' ' && *end != ',')
			{
				end++;
			}
		}
		if (end)
			*end = 0;
	}
}

static char *utils_stringify(unsigned char *data, int len)
{
	int i;
	char *result = calloc(2, len + 1);
	for (i = 0; i < len; i++)
	{
		snprintf(result + i * 2, 3, "%02x", data[i]);
	}
	return result;
}

static void *authn_digest_create(authz_t *authz, void *config)
{
	authn_digest_t *mod = calloc(1, sizeof(*mod));
	mod->config = (authn_digest_config_t *)config;
	mod->authz = authz;
	mod->challenge = calloc(1, 256);

	return mod;
}

static void authn_digest_nonce(void *arg, char *nonce, int noncelen)
{
	authn_digest_t *mod = (authn_digest_t *)arg;
	char _nonce[24];
	int i;

/**
 *  nonce and opaque may be B64 encoded data
 * or hexa encoded data
 */
#ifndef DEBUG
	srandom(time(NULL));
	for (i = 0; i < 6; i++)
		*(int *)(_nonce + i * 4) = random();
	BASE64_encode(_nonce, 24, nonce, noncelen);
#else
	memcpy(nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093", noncelen);
	nonce[noncelen] = 0;
#endif
}

static void authn_digest_opaque(void *arg, char *opaque, int opaquelen)
{
	authn_digest_t *mod = (authn_digest_t *)arg;

#ifndef DEBUG
	BASE64_encode(mod->config->opaque, 22, opaque, opaquelen);
#else
	memcpy(opaque, "5ccc069c403ebaf9f0171e9517f40e41", opaquelen);
	opaque[opaquelen] = 0;
#endif
}

static int authn_digest_setup(void *arg, struct sockaddr *addr, int addrsize)
{
	authn_digest_t *mod = (authn_digest_t *)arg;

	mod->stale = 0;
	authn_digest_opaque(mod, mod->opaque, sizeof(mod->opaque) - 1);
	authn_digest_nonce(arg, mod->nonce, sizeof(mod->nonce) - 1);
}

static int authn_digest_challenge(void *arg, http_message_t *request, http_message_t *response)
{
	int ret;
	authn_digest_t *mod = (authn_digest_t *)arg;

	snprintf(mod->challenge, 256, "%s realm=\"%s\" qop=\"auth\" nonce=\"%s\" opaque=\"%s\" stale=%s",
						str_authenticate_types[AUTHN_DIGEST_E],
						mod->config->realm,
						mod->nonce,
						mod->opaque,
						(mod->stale)?"true":"false");
	httpmessage_addheader(response, (char *)str_authenticate, mod->challenge);
	httpmessage_keepalive(response);
	ret = ESUCCESS;
	return ret;
}

struct authn_digest_computing_s
{
	char *(*digest)(char *a1, const char *nonce, const char *nc, const char *cnonce, const char *qop, char *a2);
	char *(*a1)(const char *username, const char *realm, const char *passwd);
	char *(*a2)(const char *method, const char *uri, const char *entity);
};

static char *authn_digest_md5_digest(char *a1, const const char *nonce, const char *nc, const char *cnonce, const char *qop, char *a2)
{
	if (a1 && a2)
	{
		char digest[16];
		MD5_ctx ctx;

		MD5_init(&ctx);
		MD5_update(&ctx, a1, strlen(a1));
		MD5_update(&ctx, ":", 1);
		MD5_update(&ctx, nonce, strlen(nonce));
		if (qop && !strcmp(qop, "auth"))
		{
			if (nc)
			{
				MD5_update(&ctx, ":", 1);
				MD5_update(&ctx, nc, strlen(nc));
			}
			if (cnonce)
			{
				MD5_update(&ctx, ":", 1);
				MD5_update(&ctx, cnonce, strlen(cnonce));
			}
			MD5_update(&ctx, ":", 1);
			MD5_update(&ctx, qop, strlen(qop));
		}
		MD5_update(&ctx, ":", 1);
		MD5_update(&ctx, a2, strlen(a2));
		MD5_finish(digest, &ctx);
		return utils_stringify(digest, 16);
	}
	return NULL;
}

static char *authn_digest_md5_a1(const char *username, const char *realm, const char *passwd)
{
	if (passwd[0] != '$')
	{
		char A1[16];
		MD5_ctx ctx;

		MD5_init(&ctx);
		MD5_update(&ctx, username, strlen(username));
		MD5_update(&ctx, ":", 1);
		MD5_update(&ctx, realm, strlen(realm));
		MD5_update(&ctx, ":", 1);
		MD5_update(&ctx, passwd, strlen(passwd));
		MD5_finish(A1, &ctx);
		return utils_stringify(A1, 16);
	}
	else if (!strncmp(passwd, "$a1", 3))
	{
		passwd = strrchr(passwd + 1, '$') + 1;
		if (passwd)
		{
			char b64passwd[17];
			BASE64_decode(passwd, strlen(passwd), b64passwd, 17);
			char *a1 = utils_stringify(b64passwd, 16);
			return a1;
		}
	}
	return NULL;
}

static char *authn_digest_md5_a2(const char *method, const char *uri, const char *entity)
{
	char A2[16];
	MD5_ctx ctx;

	MD5_init(&ctx);
	MD5_update(&ctx, method, strlen(method));
	MD5_update(&ctx, ":", 1);
	MD5_update(&ctx, uri, strlen(uri));
	if (entity)
	{
	MD5_update(&ctx, ":", 1);
		MD5_update(&ctx, entity, strlen(entity));
	}
	MD5_finish(A2, &ctx);
	return utils_stringify(A2, 16);
}
struct authn_digest_computing_s authn_digest_md5_computing = 
{
	.digest = authn_digest_md5_digest,
	.a1 = authn_digest_md5_a1,
	.a2 = authn_digest_md5_a2,
};

struct authn_digest_computing_s *authn_digest_computing = &authn_digest_md5_computing;

static char *str_empty = "";
static char *authn_digest_check(void *arg, const char *method, const char *url, char *string)
{
	authn_digest_t *mod = (authn_digest_t *)arg;
	char *passwd = NULL;
	char *user = str_empty;
	char *uri = NULL;
	char *realm = str_empty;
	char *qop = NULL;
	char *nonce = NULL;
	char *cnonce = str_empty;
	char *nc = NULL;
	char *opaque = str_empty;
	char *response = NULL;
	int length, i;

	length = strlen(string);
	for (i = 0; i < length; i++)
	{
		switch (string[i])
		{
		case 'r':
			utils_searchstring(&realm, string + i, "realm", sizeof("realm") - 1);
			utils_searchstring(&response, string + i, "response", sizeof("response") - 1);
		break;
		case 'c':
			utils_searchstring(&cnonce, string + i, "cnonce", sizeof("cnonce") - 1);
		break;
		case 'n':
			utils_searchstring(&nonce, string + i, "nonce", sizeof("nonce") - 1);
			utils_searchstring(&nc, string + i, "nc", sizeof("nc") - 1);
		break;
		case 'o':
			utils_searchstring(&opaque, string + i, "opaque", sizeof("opaque") - 1);
		break;
		case 'q':
			utils_searchstring(&qop, string + i, "qop", sizeof("qop") - 1);
		break;
		case 'u':
			utils_searchstring(&user, string + i, "username", sizeof("username") - 1);
			utils_searchstring(&uri, string + i, "uri", sizeof("uri") - 1);
		break;
		}
	}
	if (nonce == NULL)
		return NULL;

	if (strcmp(nonce, mod->nonce))
	{
		mod->stale++;
		mod->stale %= 5;
		return NULL;
	}
	mod->stale = 0;
	if (strcmp(opaque, mod->opaque) || strcmp(realm, mod->config->realm))
	{
		return NULL;
	}
	if (strcmp(url, uri))
	{
		warn("try connection on %s with authorization on %s", url, uri);
		return NULL;
	}
	passwd = mod->authz->rules->passwd(mod->authz->ctx, user);
	if (passwd && authn_digest_computing)
	{
		char *a1 = authn_digest_computing->a1(user, realm, passwd);
		char *a2 = authn_digest_computing->a2(method, uri, NULL);
		char *digest = authn_digest_computing->digest(a1, nonce, nc, cnonce, qop, a2);

		//warn("Digest %s", digest);
		if (digest && !strcmp(digest, response))
		{
			free (a1);
			free (a2);
			free (digest);
			return user;
		}
		free (a1);
		free (a2);
		free (digest);
	}
	else
	{
		warn("unknown user");
	}
	return NULL;
}

static void authn_digest_destroy(void *arg)
{
	authn_digest_t *mod = (authn_digest_t *)arg;
	if (mod->challenge)
		free(mod->challenge);
	free(mod);
}

authn_rules_t authn_digest_rules =
{
	.create = authn_digest_create,
	.setup = authn_digest_setup,
	.challenge = authn_digest_challenge,
	.check = authn_digest_check,
	.destroy = authn_digest_destroy,
};
