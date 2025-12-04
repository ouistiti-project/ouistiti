/*****************************************************************************
 * mod_signature.c: rfc9421
 *****************************************************************************
 * Copyright (C) 2024-2027
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

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "ouistiti/log.h"
#include "ouistiti/httpserver.h"
#include "ouistiti/hash.h"
#include "ouistiti/utils.h"
#include "mod_document.h"
#include "ouistiti.h"

#ifndef BASE64HASH_MAX_SIZE
#define BASE64HASH_MAX_SIZE ((HASH_MAX_SIZE * 3) / 2 + 1)
#endif

static const char str_signature[] = "Signature";
static const char str_signature_input[] = "Signature-Input";

typedef struct mod_signature_s mod_signature_t;
struct mod_signature_s
{
	string_t *components;
	const char *alg;
	string_t key;
	htaccess_t htaccess;
};

typedef struct signature_element_s signature_element_t;
struct signature_element_s
{
	string_t component;
	string_t field;
};

static signature_element_t _default_elemts[] =
{
	{
		.component = STRING_DCL("content-type"),
		.field = STRING_DCL("Content-Type"),
	},
	{
		.component = STRING_DCL("content-length"),
		.field = STRING_DCL("Content-Length"),
	},
	{
		.component = STRING_DCL("content-digest"),
		.field = STRING_DCL("Content-Digest"),
	},
	{
		.component = STRING_DCL("content-location"),
		.field = STRING_DCL("Content-Location"),
	},
	{
		.component = STRING_DCL("@status"),
		.field = STRING_DCL("status"),
	},
};

typedef struct _signature_component_s _signature_component_t;
struct _signature_component_s
{
	string_t data;
	_signature_component_t *next;
};

typedef struct _mod_signature_s _mod_signature_t;
struct _mod_signature_s
{
	http_server_t *server;
	mod_signature_t *config;
	const hash_t *hash;
	string_t key;
	_signature_component_t *components;
};

typedef struct _mod_signature_ctx_s _mod_signature_ctx_t;
struct _mod_signature_ctx_s
{
	_mod_signature_t *mod;
	int enabled;
	http_message_t *req;
};

static void *_mod_signature_getctx(void *arg, http_client_t *clt, struct sockaddr *UNUSED(addr), int UNUSED(addrsize));
static void _mod_signature_freectx(void *arg);
static int _signature_connectorcheck(void *arg, http_message_t *request, http_message_t *response);
static int _signature_connectorcomplete(void *arg, http_message_t *request, http_message_t *response);

static int _signature_add_component(_mod_signature_t *signature, const char *component, size_t length)
{
	int ret = -1;
	_signature_component_t *entry = calloc(1, sizeof(*entry));
	string_store(&entry->data, component, length);
	entry->next = signature->components;
	signature->components = entry;
	return ret;
}

void *mod_signature_create(http_server_t *server, mod_signature_t *config)
{
	if (config == NULL || config->components == NULL)
		return NULL;
	_mod_signature_t *mod = calloc(1, sizeof(*mod));
	mod->server = server;
	mod->config = config;
	string_t components[5];
	int ncomponents = string_split(config->components, ',',
			&components[0],
			&components[1],
			&components[2],
			&components[3],
			&components[4],
			NULL);

	for (int i = 0; i < ncomponents; i++)
	{
		_signature_component_t *elem = calloc(1, sizeof(*elem));
		string_store(&elem->data, string_toc(&components[i]), string_length(&components[i]));
		elem->next = mod->components;
		mod->components = elem;
	}
	mod->hash = hash_macsha256;
	string_store(&mod->key, config->key.data, config->key.length);
	httpserver_addmod(server, _mod_signature_getctx, _mod_signature_freectx, mod, str_signature);
	return mod;
}

void mod_signature_destroy(void *arg)
{
	_mod_signature_t *mod = (_mod_signature_t *)arg;
	free(mod->config);
	free(mod);
}

static void *_mod_signature_getctx(void *arg, http_client_t *clt, struct sockaddr *UNUSED(addr), int UNUSED(addrsize))
{
	_mod_signature_t *mod = (_mod_signature_t *)arg;
	_mod_signature_ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->mod = mod;
	httpclient_addconnector(clt, _signature_connectorcheck, ctx, CONNECTOR_DOCFILTER, str_signature);
	httpclient_addconnector(clt, _signature_connectorcomplete, ctx, CONNECTOR_COMPLETE, str_signature);
	return ctx;
}

static void _mod_signature_freectx(void *arg)
{
	_mod_signature_ctx_t *ctx = (_mod_signature_ctx_t *)arg;
	free(ctx);
}

static int _signature_sign(_mod_signature_ctx_t *ctx, http_message_t *message, string_t *input, char signature[BASE64HASH_MAX_SIZE])
{
	_mod_signature_t *mod = ctx->mod;
	const hash_t *hash = mod->hash;
	void *hashctx = NULL;
	int resultlen = 0;

	string_append(input, "(", 1);
	for (_signature_component_t *component = mod->components; component != NULL; component = component->next)
	{
		string_t field = {0};
		string_t tmp = {0};
		string_store(&tmp, "@", 1);
		if (string_startwith(&component->data, &tmp))
		{
			warn("signature: %s filed not yet supported", string_toc(&component->data));
			continue;
		}
		else
			ouimessage_REQUEST(message, string_toc(&component->data), &field);
		if (string_empty(&field))
			continue;
		if (hashctx == NULL)
			hashctx = hash->initkey(STRING_INFO(mod->key));

		string_append(input, "\"", 1);
		string_append(input, string_toc(&component->data), string_length(&component->data));
		string_append(input, "\" ", 2);

		hash->update(hashctx, "\"", 1);
		hash->update(hashctx, string_toc(&component->data), string_length(&component->data));
		hash->update(hashctx, "\": ", 3);
		hash->update(hashctx, string_toc(&field), string_length(&field));
		hash->update(hashctx, "\n", 1);
	}
	string_append(input, ")", 1);

	if (hashctx != NULL)
	{
		hash->update(hashctx, "\"", 1);
		hash->update(hashctx, "@signature-params", 17);
		hash->update(hashctx, "\": ", 3);
		hash->update(hashctx, string_toc(input), string_length(input));
		hash->update(hashctx, "\n", 1);
		char hashsign[HASH_MAX_SIZE];
		size_t signlen = hash->finish(hashctx, hashsign);
		resultlen = base64->encode(hashsign, signlen, signature, BASE64HASH_MAX_SIZE);
	}
	return resultlen;
}

static int _signature_connectorcheck(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_signature_ctx_t *ctx = (_mod_signature_ctx_t *)arg;
	_mod_signature_t *mod = ctx->mod;

	const char *path_info = NULL;
	const char *uri = httpmessage_REQUEST(request, "uri");
	if (htaccess_check(&mod->config->htaccess, uri, &path_info) == ESUCCESS)
	{
		ctx->enabled = 1;
	}
	ctx->req = request;
	return EREJECT;
}

static int _signature_connectorcomplete(void *arg, http_message_t *request, http_message_t *response)
{
	_mod_signature_ctx_t *ctx = (_mod_signature_ctx_t *)arg;
	if (ctx->enabled == 0)
		return EREJECT;
	_mod_signature_t *mod = ctx->mod;

	/*
	 * TODO this is not the real algo of rfc9530
	 * it's just a test
	 */
	char result[BASE64HASH_MAX_SIZE] = {0};
	string_t *input = string_create(512);
	size_t resultlen = _signature_sign(ctx, response, input, result);

	httpmessage_addheader(response, str_signature_input, string_toc(input), string_length(input));
	string_destroy(input);
	httpmessage_addheader(response, str_signature, result, resultlen);
	httpmessage_appendheader(response, str_signature, ";created=", 9);
	time_t t = time(NULL);
	char tstr[24];
	int tlen = snprintf(tstr, 24, "%.23ld", t);
	httpmessage_appendheader(response, str_signature, tstr, tlen);
	httpmessage_appendheader(response, str_signature, ";alg=", 5);
	httpmessage_appendheader(response, str_signature, mod->hash->name, -1);
	dbg("signature: connector ready");
	return ESUCCESS;
}

#ifdef FILE_CONFIG
static void * _signature_config(config_setting_t *config, server_t *server)
{
	mod_signature_t *signature = NULL;

	const char *key = NULL;
	config_setting_lookup_string(config, "key", &key);
	if (key != NULL && key[0] != '0')
	{
		signature = calloc(1,sizeof(*signature));

		signature->key.data = key;
		signature->key.length = strlen(signature->key.data);
		config_setting_t *components = NULL;
		components = config_setting_lookup(config, "components");
		if (components)
			signature->components = string_create(256);
		if (components && config_setting_is_list(components))
		{
			int nbelems = 0;
			nbelems = config_setting_length(components);
			for (int i = 0; i < nbelems; i++)
			{
				config_setting_t *component = config_setting_get_elem(components, i);
				if (component && config_setting_type(component) ==  CONFIG_TYPE_STRING)
				{
					const char *value = config_setting_get_string(component);
					string_append(signature->components, value, -1);
				}
			}
		}
		else if (components && config_setting_is_scalar(components))
		{
			const char *value = config_setting_get_string(components);
			string_cpy(signature->components, value, -1);
		}

		config_setting_lookup_string(config, "algorithm", &signature->alg);
		htaccess_config(config, &signature->htaccess);
	}
	return signature;
}
static void *mod_signature_config(config_setting_t *iterator, server_t *server)
{
	mod_signature_t *signature = NULL;

#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *config = config_setting_get_member(iterator, "signature");
#else
	config_setting_t *config = config_setting_lookup(iterator, "signature");
#endif
	if (config && config_setting_is_group(config))
	{
		signature = _signature_config(config, server);
	}
	return signature;
}
#else
static void *mod_signature_config(void *iterator, server_t *server)
{
	mod_signature_t *signature = NULL;

	signature = calloc(1,sizeof(*signature));
	return signature;
}
#endif

const module_t mod_signature =
{
	.name = str_signature,
	.configure = (module_configure_t)&mod_signature_config,
	.create = (module_create_t)mod_signature_create,
	.destroy = mod_signature_destroy,
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_signature")));
#endif
