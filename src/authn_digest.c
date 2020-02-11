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

#define MAXNONCE 64
#define MAXUSER 64

static const char *str_digest;

typedef struct authn_digest_s authn_digest_t;
struct authn_digest_s
{
	authn_digest_config_t *config;
	authz_t *authz;
	const hash_t *hash;
	const char *opaque;
	char nonce[MAXNONCE];
	char user[MAXUSER];
	int stale;
	int encode;
};

static int utils_searchstring(char **result, const char *haystack, const char *needle, int length)
{
	if ((*result == NULL || *result[0] == '\0') &&
		!strncmp(haystack, needle, length) && haystack[length] == '=')
	{
		char *end = NULL;
		*result = strchr(haystack, '=');
		if (*result == NULL)
			return 0;
		*result += 1;
		if (**result == '"')
		{
			*result = *result + 1;
			end = strchr(*result, '"');
		}
		if (end == NULL)
		{
			end = *result;
			while(*end != 0 && *end != ' ' && *end != ',')
			{
				end++;
			}
		}
		//*end = 0;
		return end - *result;
	}
	return 0;
}

static char *utils_stringify(const unsigned char *data, int len)
{
	int i;
	char *result = calloc(2, len + 1);
	for (i = 0; i < len; i++)
	{
		snprintf(result + i * 2, 3, "%02x", data[i]);
	}
	return result;
}

static char str_opaque[] = "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS";

static void *authn_digest_create(const authn_t *authn, authz_t *authz, void *config)
{
	if (authn->hash == NULL)
		return NULL;
	if (authz->rules->passwd == NULL)
	{
		err("authn Digest is not compatible with authz %s", authz->name);
		return NULL;
	}
	str_digest = authn->auth->authn.name;

	authn_digest_t *mod = calloc(1, sizeof(*mod));
	mod->config = (authn_digest_config_t *)config;
	mod->authz = authz;
	mod->hash = authn->hash;
	if (mod->config->opaque == NULL)
		mod->opaque = str_opaque;
	else
		mod->opaque = mod->config->opaque;
	if (mod->config->realm == NULL)
		mod->config->realm = httpserver_INFO(authn->server, "host");
	return mod;
}

static void authn_digest_nonce(void *arg, char *nonce, int noncelen)
{
	const authn_digest_t *mod = (authn_digest_t *)arg;
/**
 *  nonce and opaque may be B64 encoded data
 * or hexa encoded data
 */
#ifndef DEBUG
	(void) arg;
	char _nonce[24];
	int i;

	srandom(time(NULL));
	int usedate = random() % 5;
	if (usedate)
	{
		struct tm nowtm;
		time_t now = time(NULL) / (60 * 30); // 30 minutes of validity
		strftime(_nonce, 24, "%M%H%Y%A%B", localtime_r(&now, &nowtm));
		const char *key = mod->config->secret;
		if (hash_macsha256 != NULL && key != NULL)
		{
			void *ctx = hash_macsha256->initkey(key, strlen(key));
			if (ctx)
			{
				hash_macsha256->update(ctx, _nonce, 24);
				char signature[HASH_MAX_SIZE];
				hash_macsha256->finish(ctx, signature);
				memcpy(_nonce, signature, 24);
			}
		}
	}
	else
	{
		for (i = 0; i < 6; i++)
			*(int *)(_nonce + i * 4) = random();
	}
	base64->encode(_nonce, 24, nonce, noncelen);
#else
	err("Auth DIGEST is not secure in DEBUG mode, rebuild!!!");
	if (!strcmp(mod->opaque, str_opaque))
		strncpy(nonce, "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", noncelen); //RFC7616
	else
		strncpy(nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093", noncelen);  //RFC2617
#endif
}

static int authn_digest_setup(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	authn_digest_t *mod = (authn_digest_t *)arg;
	(void) ctl;
	(void) addr;
	(void) addrsize;

	mod->stale = 0;
	authn_digest_nonce(arg, mod->nonce, MAXNONCE);
}

static void authn_digest_www_authenticate(authn_digest_t *mod, http_message_t * response)
{
	httpmessage_addheader(response, str_authenticate, "Digest ");
	if (mod->config->realm != NULL && mod->config->realm[0] != 0)
	{
		httpmessage_appendheader(response, str_authenticate,
				"realm=\"", mod->config->realm, "\"", NULL);
	}
	httpmessage_appendheader(response, str_authenticate,
				"\",qop=\"auth\",nonce=\"", mod->nonce,
				"\",opaque=\"", mod->opaque,
				"\",stale=", (mod->stale)?"true":"false", NULL);
}

static int authn_digest_challenge(void *arg, http_message_t *request, http_message_t *response)
{
	int ret;
	authn_digest_t *mod = (authn_digest_t *)arg;

	/**
	 * WWW-AUTHENTICATE header without algorithm is mandatory
	 * Firefox and Chrome doesn't support other algorithm than MD5
	 */
	authn_digest_www_authenticate(mod, response);

	if (mod->hash != hash_md5)
	{
		/**
		 * this adds a second WWW-AUTHENTICATE header with algorithm
		 */
		authn_digest_www_authenticate(mod, response);
		httpmessage_appendheader(response, str_authenticate,
				",algorithm=", mod->hash->name, "", NULL);
	}
	httpmessage_keepalive(response);
	ret = ECONTINUE;
	return ret;
}

struct authn_digest_computing_s
{
	char *(*digest)(const hash_t * hash, const char *a1, const char *nonce, int noncelen, const char *nc, int nclen, const char *cnonce, int cnoncelen, const char *qop, int qoplen, const char *a2);
	char *(*a1)(const hash_t * hash, const char *user, int userlen, const char *realm, int realmlen, const char *passwd, int passwdlen);
	char *(*a2)(const hash_t * hash, const char *method, int methodlen, const char *uri, int urilen, const char *entity, int entitylen);
};

static char *authn_digest_digest(const hash_t * hash, const char *a1, const char *nonce, int noncelen, const char *nc, int nclen, const char *cnonce, int cnoncelen, const char *qop, int qoplen, const char *a2)
{
	if (a1 && a2)
	{
		char digest[32];
		void *ctx;

		ctx = hash->init();
		hash->update(ctx, a1, strlen(a1));
		hash->update(ctx, ":", 1);
		hash->update(ctx, nonce, noncelen);
		if (qop && !strncmp(qop, "auth", qoplen))
		{
			if (nc)
			{
				hash->update(ctx, ":", 1);
				hash->update(ctx, nc, nclen);
			}
			if (cnonce)
			{
				hash->update(ctx, ":", 1);
				hash->update(ctx, cnonce, cnoncelen);
			}
			hash->update(ctx, ":", 1);
			hash->update(ctx, qop, qoplen);
		}
		hash->update(ctx, ":", 1);
		hash->update(ctx, a2, strlen(a2));
		hash->finish(ctx, digest);
		return utils_stringify(digest, hash->size);
	}
	return NULL;
}

static char *authn_digest_a1(const hash_t * hash, const char *user, int userlen, const char *realm, int realmlen, const char *passwd, int passwdlen)
{
	if (passwd[0] != '$')
	{
		char A1[32];
		void *ctx;

		ctx = hash->init();
		hash->update(ctx, user, userlen);
		hash->update(ctx, ":", 1);
		hash->update(ctx, realm, realmlen);
		hash->update(ctx, ":", 1);
		hash->update(ctx, passwd, passwdlen);
		hash->finish(ctx, A1);
		return utils_stringify(A1, hash->size);
	}
	else if (passwd[0] == '$')
	{
		int i = 1;
		int decode = 0;
		if (passwd[i] == 'a')
		{
			decode = 1;
			i++;
		}
		if (passwd[i] == 'd')
		{
			i++;
		}
		int decrypt = 0;
		if ( passwd[i] == hash->nameid)
			decrypt = 1;
		if (decrypt)
		{
			passwd = strrchr(passwd + 1, '$');
			if (passwd)
			{
				passwd += 1;
				char *a1 = NULL;
				if (decode)
				{
					char b64passwd[64];
					int len = base64->decode(passwd, strlen(passwd), b64passwd, 64);
					a1 = utils_stringify(b64passwd, len);
				}
				else
					a1 = strdup(passwd);
				return a1;
			}
		}
	}
	return NULL;
}

static char *authn_digest_a2(const hash_t * hash, const char *method, int methodlen, const char *uri, int urilen, const char *entity, int entitylen)
{
	char A2[32];
	void *ctx;

	ctx = hash->init();
	hash->update(ctx, method, methodlen);
	hash->update(ctx, ":", 1);
	hash->update(ctx, uri, urilen);
	if (entity)
	{
		hash->update(ctx, ":", 1);
		hash->update(ctx, entity, entitylen);
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
static const char *authn_digest_check(void *arg, const char *method, const char *url, const char *string)
{

	authn_digest_t *mod = (authn_digest_t *)arg;
	const char *passwd = NULL;
	char *user = str_empty;
	int userlen = 0;
	const char *user_ret = NULL;
	char *uri = NULL;
	int urilen = 0;
	char *realm = str_empty;
	int realmlen = 0;
	char *qop = NULL;
	int qoplen = 0;
	char *nonce = NULL;
	int noncelen = 0;
	char *cnonce = str_empty;
	int cnoncelen = 0;
	char *nc = NULL;
	int nclen = 0;
	char *opaque = str_empty;
	int opaquelen = 0;
	char *algorithm = NULL;
	int algorithmlen = 0;
	char *response = NULL;
	int responselen = 0;
	int length, i;

	length = strlen(string);
	auth_dbg("digest: parsing %s", string);
	for (i = 0; i < length; i++)
	{

		switch (string[i])
		{
		case 'a':
			if (algorithmlen == 0)
			{
				algorithmlen = utils_searchstring(&algorithm, string + i, "algorithm", sizeof("algorithm") - 1);
				if (algorithmlen > 0)
					i += algorithmlen + sizeof("algorithm=");
			}
		break;
		case 'r':
			if (realmlen == 0)
			{
				realmlen = utils_searchstring(&realm, string + i, "realm", sizeof("realm") - 1);
				if (realmlen > 0)
					i += realmlen + sizeof("realm=") + 1;
			}
			if (responselen == 0)
			{
				responselen = utils_searchstring(&response, string + i, "response", sizeof("response") - 1);
				if (responselen > 0)
					i += responselen + sizeof("response=") + 1;
			}
		break;
		case 'c':
			if (cnoncelen == 0)
			{
				cnoncelen = utils_searchstring(&cnonce, string + i, "cnonce", sizeof("cnonce") - 1);
				if (cnoncelen > 0)
					i += cnoncelen + sizeof("cnonce=") + 1;
			}
		break;
		case 'n':
			if (noncelen == 0)
			{
				noncelen = utils_searchstring(&nonce, string + i, "nonce", sizeof("nonce") - 1);
				if (noncelen > 0)
					i += noncelen + sizeof("nonce=") + 1;
			}
			if (nclen == 0)
			{
				nclen = utils_searchstring(&nc, string + i, "nc", sizeof("nc") - 1);
				if (nclen > 0)
					i += nclen + sizeof("nc=");
			}
		break;
		case 'o':
			if (opaquelen == 0)
			{
				opaquelen = utils_searchstring(&opaque, string + i, "opaque", sizeof("opaque") - 1);
				if (opaquelen > 0)
					i += opaquelen + sizeof("opaque=") + 1;
			}
		break;
		case 'q':
			if (qoplen == 0)
			{
				qoplen = utils_searchstring(&qop, string + i, "qop", sizeof("qop") - 1);
				if (qoplen > 0)
					i += qoplen + sizeof("qop=");
			}
		break;
		case 'u':
			if (userlen == 0)
			{
				userlen = utils_searchstring(&user, string + i, "username", sizeof("username") - 1);
				if (userlen > 0)
					i += userlen + sizeof("username=") + 1;
			}
			if (urilen == 0)
			{
				urilen = utils_searchstring(&uri, string + i, "uri", sizeof("uri") - 1);
				if (urilen > 0)
					i += urilen + sizeof("uri=") + 1;
			}
		break;
		default:
		break;
		}
	}
	const hash_t *hash = hash_md5;

	if (algorithm != NULL)
	{
		/**
		 * Firefox and Chrome doesn't support other algorithm than MD5
		 * https://bugzilla.mozilla.org/show_bug.cgi?id=472823
		 */
		if(!strncmp(algorithm, mod->hash->name, algorithmlen))
			hash = mod->hash;
		else
		{
			warn("auth: algorithm is bad %s/%s", algorithm, mod->hash->name);
			return NULL;
		}
	}

	int check = 1;
	if (nonce == NULL)
	{
		warn("auth: nonce is unset");
		check = 0;
	}
	else if (strncmp(nonce, mod->nonce, noncelen))
	{
		mod->stale++;
		mod->stale %= 5;
		warn("auth: nonce is corrupted");
		check = 0;
	}
	else if (strncmp(opaque, mod->opaque, opaquelen) || strncmp(realm, mod->config->realm, realmlen))
	{
		warn("auth: opaque or realm is bad");
		check = 0;
	}
	else if (uri == NULL)
	{
		warn("auth: uri is unset");
		check = 0;
	}
	else if (strncmp(url, uri, urilen))
	{
		warn("try connection on %s with authorization on %s", url, uri);
		check = 0;
	}
#ifndef DEBUG
	else
#endif
	{
		strncpy(mod->user, user, userlen);
		passwd = mod->authz->rules->passwd(mod->authz->ctx, mod->user);
	}
	if (response && passwd && authn_digest_computing)
	{
		auth_dbg("user %.*s", userlen, user);
		auth_dbg("passwd %s", passwd);
		auth_dbg("response %.*s", responselen, response);
		auth_dbg("algorithm %s", mod->hash->name);
		auth_dbg("algorithm %.*s", algorithmlen, algorithm);
		auth_dbg("realm %.*s", realmlen, realm);
		auth_dbg("cnonce %.*s", cnoncelen, cnonce);
		auth_dbg("nonce %.*s", noncelen, nonce);
		auth_dbg("nc %.*s", nclen, nc);
		auth_dbg("opaque %.*s", opaquelen, opaque);
		auth_dbg("qop %.*s", qoplen, qop);
		auth_dbg("uri %.*s", urilen, uri);

		char *a1 = authn_digest_computing->a1(hash, user, userlen, realm, realmlen, passwd, strlen(passwd));
		char *a2 = authn_digest_computing->a2(hash, method, strlen(method), uri, urilen, NULL, 0);
		char *digest = authn_digest_computing->digest(hash, a1, nonce, noncelen, nc, nclen, cnonce, cnoncelen, qop, qoplen, a2);

		auth_dbg("Digest %s", digest);
		if (digest && !strncmp(digest, response, responselen) && check)
		{
			user_ret = mod->user;
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
	free(mod);
}

authn_rules_t authn_digest_rules =
{
	.create = &authn_digest_create,
	.setup = &authn_digest_setup,
	.challenge = &authn_digest_challenge,
	.check = &authn_digest_check,
	.destroy = &authn_digest_destroy,
};
