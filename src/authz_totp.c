/*****************************************************************************
 * authz_totp.c: Check Authentication on Time based One Time Password
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

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include "b64/cencode.h"
#include "ouistiti/httpserver.h"
#include "ouistiti/log.h"
#include "ouistiti/hash.h"
#include "ouistiti/utils.h"
#include "mod_auth.h"
#include "authz_totp.h"

#define auth_dbg(...)

#define OTP_STEP 30
#define OTP_MAXDIGITS 10
#define OTP_MAXURL 1024
static unsigned long otp_modulus[] =
{ (unsigned long)-1, 1000000, 10000000, 100000000, 1000000000, 10000000000};

const char str_totp[] = "totp";

typedef struct authz_totp_config_s authz_totp_config_t;
struct authz_totp_config_s
{
	const hash_t *hash;
	string_t key;
	string_t token_ep;
	string_t issuer;
	unsigned int digits;
	unsigned long digitsmodulus;
	unsigned int period;
};

typedef struct authz_totp_s authz_totp_t;
struct authz_totp_s
{
	authz_totp_config_t *config;
	string_t *userkey;
	char passwd[OTP_MAXDIGITS + 1];
	http_server_t *server;
	size_t offset;
};

size_t otp_url(const string_t* key, const char *user, const char *issuer, const hash_t *hash, int digits, char output[OTP_MAXURL]);
static int authz_totp_generateK(const authz_totp_config_t *config, const string_t *user, string_t *output);

#ifdef FILE_CONFIG
void *authz_totp_config(const config_setting_t *configauth)
{
	authz_totp_config_t *authz_config = NULL;
	const char *key = NULL;

	if (config_setting_lookup_string(configauth, "secret", &key) == CONFIG_TRUE)
	{
		authz_config = calloc(1, sizeof(*authz_config));
		authz_config->hash = hash_macsha1;
		string_store(&authz_config->key, key, -1);
		int digits = 6;
		authz_config->digits = digits;
		authz_config->period = OTP_STEP;
		authz_config->digitsmodulus = otp_modulus[authz_config->digits - 5];
		const char *token_ep = NULL;
		if (config_setting_lookup_string(configauth, "token_ep", &token_ep) == CONFIG_TRUE)
		{
			string_store(&authz_config->token_ep, token_ep, -1);
		}
		const char *issuer = NULL;
		if (config_setting_lookup_string(configauth, "issuer", &issuer) == CONFIG_TRUE)
		{
			string_store(&authz_config->issuer, issuer, -1);
		}
	}
	return authz_config;
}
#endif

static int _authz_totp_connector(void *arg, http_message_t *request, http_message_t *response)
{
	authz_totp_t *ctx = (authz_totp_t *)arg;
	const char *uri = httpmessage_REQUEST(request, "uri");
	if (utils_searchexp(uri, string_toc(&ctx->config->token_ep), NULL) == ESUCCESS)
	{
		const char *sessionuser = NULL;
		size_t length = auth_info2(request, str_user, &sessionuser);
		if (length > 0)
		{
			const authz_totp_config_t *config = ctx->config;
			if (string_toc(ctx->userkey)[0] == '\0')
			{
				string_t userstr = {0};
				string_store(&userstr, sessionuser, length);
				authz_totp_generateK(config, &userstr, ctx->userkey);
			}

			const char *issuer = "test";
			if (!string_empty(&config->issuer))
				issuer = string_toc(&config->issuer);

			char url[OTP_MAXURL];
			const char *otpurl = NULL;
			size_t length = auth_info2(request, "otpauth", &otpurl);
			if (length == 0)
			{
				length = otp_url(ctx->userkey, sessionuser, issuer, config->hash, config->digits, url);
				otpurl = url;
			}
			size_t len = 0;
			if (!ctx->offset)
				len = httpmessage_addcontent(response, str_mime_textplain, otpurl, length + 1);
			else
				len = httpmessage_appendcontent(response, otpurl + ctx->offset, length - ctx->offset);
			if (len < (length - ctx->offset))
			{
				ctx->offset += len;
				return ECONTINUE;
			}
			else
			{
				httpmessage_appendcontent(response, STRING_REF("\n"));
				return ESUCCESS;
			}
		}
	}
	return EREJECT;
}

static void *authz_totp_create(http_server_t *server, void *arg)
{
	authz_totp_t *ctx = NULL;
	authz_totp_config_t *config = (authz_totp_config_t *)arg;

	ctx = calloc(1, sizeof(*ctx));
	ctx->config = config;
	ctx->server = server;
	ctx->userkey = string_create(HASH_MAX_SIZE + 1);
	return ctx;
}

static void *authz_totp_setup(void *arg, http_client_t *clt, struct sockaddr *addr, int addrsize)
{
	authz_totp_t *ctx = (authz_totp_t *)arg;
	httpclient_addconnector(clt, _authz_totp_connector, ctx, CONNECTOR_DOCUMENT, str_totp);
	ctx->offset = 0;
	return ctx;
}

static uint32_t hotp_generator(const hash_t *hash, const string_t* key, unsigned long modulus, uint64_t counter)
{
	uint64_t t = counter;
	char T[17] = {0};
#if 0
	int Tlen = snprintf(T, 17, "%.016X", (unsigned int)t);
#endif
	for (int i = sizeof(t) - 1; i >= 0; i--)
	{
		if ( t == 0) break;
		T[i] = t & 0x0ff;
		t = t >> 8;
	}
	T[0] &= 0x7f;
	int Tlen = sizeof(t);
	void *hmac = hash->initkey(string_toc(key), string_length(key));
	hash->update(hmac, T, Tlen);

	char longpassd[HASH_MAX_SIZE];
	int length = hash->finish(hmac, longpassd);
	int offset = longpassd[ length - 1] & 0x0F;
	uint32_t binary = ((longpassd[ offset] & 0x7F) << 24) |
		((longpassd[ offset + 1] & 0xFF) << 16) |
		((longpassd[ offset + 2] & 0xFF) << 8) |
		(longpassd[ offset + 3] & 0xFF);
	uint32_t otp = binary % modulus;
	return otp;
}

static uint32_t totp_generator(const hash_t *hash, const string_t* key, unsigned long modulus, int period)
{
#ifndef DEBUG
	long t0 = 0;
	long x = period;
	long t = (time(NULL) - t0 ) / x;
#else
	time_t t = 56666053;
#endif
	return hotp_generator(hash, key, modulus, t);
}

size_t otp_url(const string_t* key, const char *user, const char *issuer, const hash_t *hash, int digits, char output[OTP_MAXURL])
{
	void *base32state = base32->encoder.init();
	char *keyb32 = malloc((int)string_length(key) * 2);
	size_t keyb32len = base32->encoder.update(base32state, keyb32, string_toc(key), string_length(key));
	keyb32len += base32->encoder.finish(base32state, keyb32 + keyb32len);
	free(base32state);
	while (keyb32[keyb32len - 1] == '=') keyb32len --;
	size_t length = snprintf(output, OTP_MAXURL, "otpauth://totp/");
	if (issuer != NULL)
		length += snprintf(output + length, OTP_MAXURL - length, "%s:", issuer);
	length += snprintf(output + length, OTP_MAXURL - length, "%s?", user);
	length += snprintf(output + length, OTP_MAXURL - length, "secret=%.*s&", (int)keyb32len, keyb32);
	if (issuer != NULL)
		length += snprintf(output + length, OTP_MAXURL - length, "issuer=%s&", issuer);
	if (hash && strncmp(hash->name, "hmac-sha1", 9))
		length += snprintf(output + length, OTP_MAXURL - length, "algorithm=%s&", hash->name);
	length += snprintf(output + length, OTP_MAXURL - length, "digits=%d", digits);
	free(keyb32);
	return length;
}

static int authz_totp_generateK(const authz_totp_config_t *config, const string_t *user, string_t *output)
{
	void *hmac = hash_macsha256->initkey(config->key.data, config->key.length);
	hash_macsha256->update(hmac, user->data, user->length);
	hash_macsha256->update(hmac, config->key.data, config->key.length);

	if (output->size < HASH_MAX_SIZE)
		return EREJECT;
	char value[HASH_MAX_SIZE];
	size_t length = hash_macsha256->finish(hmac, value);
	string_cpy(output, value, length);
	return ESUCCESS;
}

static int authz_totp_passwd(void *arg, const string_t *user, string_t *passwd)
{
	int ret = EREJECT;
	authz_totp_t *ctx = (authz_totp_t *)arg;
	const authz_totp_config_t *config = ctx->config;
	if (passwd == NULL)
		return config->digits;

	authz_totp_generateK(config, user, ctx->userkey);

	uint32_t totp = totp_generator(config->hash, ctx->userkey, config->digitsmodulus, config->period);
	ret = string_printf(passwd, "%.*u", config->digits, totp);
	auth_dbg("auth: totp user %s passwd %s", string_toc(user), string_toc(passwd));
	return ret;
}

static int _authz_totp_checkpasswd(authz_totp_t *ctx, const char *user, const char *passwd)
{
	int ret = 0;
	const authz_totp_config_t *config = ctx->config;

	string_t userstr = {0};
	string_store(&userstr, user, -1);

	string_t *checkpasswd = string_create(config->digitsmodulus + 1);
	ret = authz_totp_passwd(ctx, &userstr, checkpasswd);
	if (ret == ESUCCESS)
	{
		string_t passwdstr = {0};
		string_store(&passwdstr, passwd, -1);
		if (authz_checkpasswd(string_toc(checkpasswd), &userstr, NULL,  &passwdstr) == ESUCCESS)
			ret = 1;
	}
	else
		err("auth: user %s not found in file", user);
	string_cleansafe(checkpasswd);
	string_destroy(checkpasswd);
	return ret;
}

static const char *authz_totp_check(void *arg, const char *user, const char *passwd, const char *token)
{
	authz_totp_t *ctx = (authz_totp_t *)arg;

	if (user != NULL && passwd != NULL && _authz_totp_checkpasswd(ctx, user, passwd))
		return user;
	return NULL;
}

static int authz_totp_setsession(void *arg, const char *user, const char *token, auth_saveinfo_t cb, void *cbarg)
{
	authz_totp_t *ctx = (authz_totp_t *)arg;
	const authz_totp_config_t *config = ctx->config;

	cb(cbarg, STRING_REF(str_user), user, -1);
	cb(cbarg, STRING_REF(str_group), STRING_REF("users"));
	cb(cbarg, STRING_REF(str_status), STRING_REF(str_status_activated));
	if (token)
		cb(cbarg, STRING_REF(str_token), STRING_REF(token));
	return ESUCCESS;
}

static void authz_totp_destroy(void *arg)
{
	authz_totp_t *ctx = (authz_totp_t *)arg;
	string_cleansafe(ctx->userkey);
	string_destroy(ctx->userkey);
	free(ctx->config);
	free(ctx);
}

authz_rules_t authz_totp_rules =
{
	.create = &authz_totp_create,
	.setup = &authz_totp_setup,
	.check = &authz_totp_check,
	.passwd = &authz_totp_passwd,
	.setsession = &authz_totp_setsession,
	.destroy = &authz_totp_destroy,
};
