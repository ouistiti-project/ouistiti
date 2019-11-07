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
#include "httpserver/hash.h"
#include "mod_auth.h"
#include "authn_digest.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

#define auth_dbg(...)

typedef struct authn_digest_s authn_digest_t;
struct authn_digest_s
{
	authn_digest_config_t *config;
	authz_t *authz;
	const hash_t *hash;
	char *challenge;
	char opaque[33];
	char nonce[35];
	int stale;
};

static void authn_digest_opaque(void *arg, char *opaque, int opaquelen);

static void utils_searchstring(const char **result, char *haystack, char *needle, int length)
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
			end = (char *)*result;
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

static void *authn_digest_create(authn_t *authn, authz_t *authz, void *config)
{
	if (authn->hash == NULL)
		return NULL;
	if (authz->rules->passwd == NULL)
	{
		err("authn Digest is not compatible with authz %s", str_authenticate_engine[authz->type&AUTHZ_TYPE_MASK]);
		return NULL;
	}
	authn_digest_t *mod = calloc(1, sizeof(*mod));
	mod->config = (authn_digest_config_t *)config;
	mod->authz = authz;
	mod->challenge = calloc(1, 256);
	mod->hash = authn->hash;
	authn_digest_opaque(mod, mod->opaque, sizeof(mod->opaque) - 1);

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
	base64->encode(_nonce, 24, nonce, noncelen);
#else
	memcpy(nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093", noncelen);
	nonce[noncelen] = 0;
#endif
}

static void authn_digest_opaque(void *arg, char *opaque, int opaquelen)
{
	authn_digest_t *mod = (authn_digest_t *)arg;

#ifndef DEBUG
	base64->encode(mod->config->opaque, 22, opaque, opaquelen);
#else
	memcpy(opaque, "5ccc069c403ebaf9f0171e9517f40e41", opaquelen);
	opaque[opaquelen] = 0;
#endif
}

static int authn_digest_setup(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	authn_digest_t *mod = (authn_digest_t *)arg;

	mod->stale = 0;
	authn_digest_nonce(arg, mod->nonce, sizeof(mod->nonce) - 1);
}

static int authn_digest_challenge(void *arg, http_message_t *request, http_message_t *response)
{
	int ret;
	authn_digest_t *mod = (authn_digest_t *)arg;

	snprintf(mod->challenge, 256, "%s realm=\"%s\",qop=\"auth\",nonce=\"%s\",opaque=\"%s\",stale=%s",
						str_authenticate_types[AUTHN_DIGEST_E],
						mod->config->realm,
						mod->nonce,
						mod->opaque,
						(mod->stale)?"true":"false");
	if (mod->hash != hash_md5)
	{
		int len = strlen(mod->challenge);
		snprintf(mod->challenge + len, 256 - len, " algorithm=\%s\"", mod->hash->name);
	}
	httpmessage_addheader(response, (char *)str_authenticate, mod->challenge);
	httpmessage_keepalive(response);
	httpmessage_result(response, RESULT_401);
	ret = ESUCCESS;
	return ret;
}

struct authn_digest_computing_s
{
	char *(*digest)(const hash_t * hash, char *a1, const char *nonce, const char *nc, const char *cnonce, const char *qop, char *a2);
	char *(*a1)(const hash_t * hash, const char *username, const char *realm, const char *passwd);
	char *(*a2)(const hash_t * hash, const char *method, const char *uri, const char *entity);
};

static char *authn_digest_digest(const hash_t * hash, char *a1, const const char *nonce, const char *nc, const char *cnonce, const char *qop, char *a2)
{
	if (a1 && a2)
	{
		char digest[32];
		void *ctx;

		ctx = hash->init();
		hash->update(ctx, a1, strlen(a1));
		hash->update(ctx, ":", 1);
		hash->update(ctx, nonce, strlen(nonce));
		if (qop && !strcmp(qop, "auth"))
		{
			if (nc)
			{
				hash->update(ctx, ":", 1);
				hash->update(ctx, nc, strlen(nc));
			}
			if (cnonce)
			{
				hash->update(ctx, ":", 1);
				hash->update(ctx, cnonce, strlen(cnonce));
			}
			hash->update(ctx, ":", 1);
			hash->update(ctx, qop, strlen(qop));
		}
		hash->update(ctx, ":", 1);
		hash->update(ctx, a2, strlen(a2));
		hash->finish(ctx, digest);
		return utils_stringify(digest, hash->size);
	}
	return NULL;
}

static char *authn_digest_a1(const hash_t * hash, const char *username, const char *realm, const char *passwd)
{
	if (passwd[0] != '$')
	{
		char A1[32];
		void *ctx;

		ctx = hash->init();
		hash->update(ctx, username, strlen(username));
		hash->update(ctx, ":", 1);
		hash->update(ctx, realm, strlen(realm));
		hash->update(ctx, ":", 1);
		hash->update(ctx, passwd, strlen(passwd));
		hash->finish(ctx, A1);
		return utils_stringify(A1, hash->size);
	}
	else if (!strncmp(passwd, "$a", 2))
	{
		int decrypt = 0;
		if (!strcmp(hash->name, "MD5") && passwd[2] == '1')
			decrypt = 1;
		if (!strcmp(hash->name, "SHA-256") && passwd[2] == '5')
			decrypt = 1;
		if (!strcmp(hash->name, "SHA-512") && passwd[2] == '6')
			decrypt = 1;
		if (decrypt)
		{
			passwd = strrchr(passwd + 1, '$') + 1;
			if (passwd)
			{
				char b64passwd[17];
				base64->decode(passwd, strlen(passwd), b64passwd, 17);
				char *a1 = utils_stringify(b64passwd, 16);
				return a1;
			}
		}
	}
	return NULL;
}

static char *authn_digest_a2(const hash_t * hash, const char *method, const char *uri, const char *entity)
{
	char A2[32];
	void *ctx;

	ctx = hash->init();
	hash->update(ctx, method, strlen(method));
	hash->update(ctx, ":", 1);
	hash->update(ctx, uri, strlen(uri));
	if (entity)
	{
		hash->update(ctx, ":", 1);
		hash->update(ctx, entity, strlen(entity));
	}
	hash->finish(ctx, A2);
	return utils_stringify(A2, hash->size);
}
static struct authn_digest_computing_s authn_digest_md5_computing =
{
	.digest = authn_digest_digest,
	.a1 = authn_digest_a1,
	.a2 = authn_digest_a2,
};

static struct authn_digest_computing_s *authn_digest_computing = &authn_digest_md5_computing;

static char *str_empty = "";
static const char *authn_digest_check(void *arg, const char *method, const char *url, char *string)
{
	authn_digest_t *mod = (authn_digest_t *)arg;
	const char *passwd = NULL;
	const char *user = str_empty;
	const char *user_ret = NULL;
	const char *uri = NULL;
	const char *realm = str_empty;
	const char *qop = NULL;
	const char *nonce = NULL;
	const char *cnonce = str_empty;
	const char *nc = NULL;
	const char *opaque = str_empty;
	const char *algorithm = hash_md5->name;
	const char *response = NULL;
	int length, i;

	length = strlen(string);
	for (i = 0; i < length; i++)
	{
		switch (string[i])
		{
		case 'a':
			utils_searchstring(&algorithm, string + i, "algorithm", sizeof("algorithm") - 1);
		break;
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
	{
		warn("auth: nonce is unset");
	}
	else if (strcmp(nonce, mod->nonce))
	{
		mod->stale++;
		mod->stale %= 5;
		warn("auth: nonce is corrupted");
	}
	else if (strcmp(algorithm, mod->hash->name))
	{
		warn("auth: algorithm is bad");
#ifdef AUTH_DOWNGRADE
		mod->hash = hash_md5;
#else
		mod->stale++;
		mod->stale %= 5;
#endif
	}
	else if (strcmp(opaque, mod->opaque) || strcmp(realm, mod->config->realm))
	{
		warn("auth: opaque or realm is bad");
	}
	else
	{
		passwd = mod->authz->rules->passwd(mod->authz->ctx, (char *)user);
	}
	if (strcmp(url, uri))
	{
		warn("try connection on %s with authorization on %s", url, uri);
	}
	if (passwd && authn_digest_computing)
	{
		char *a1 = authn_digest_computing->a1(mod->hash, user, realm, passwd);
		char *a2 = authn_digest_computing->a2(mod->hash, method, uri, NULL);
		char *digest = authn_digest_computing->digest(mod->hash, a1, nonce, nc, cnonce, qop, a2);

		auth_dbg("Digest %s", digest);
		if (digest && !strcmp(digest, response))
		{
			user_ret = (char *)user;
		}
		free (a1);
		free (a2);
		free (digest);
	}
	else
	{
		user_ret = mod->authz->rules->check(mod->authz->ctx, NULL, NULL, string);
	}
	return user_ret;
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
