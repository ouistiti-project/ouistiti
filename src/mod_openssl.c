/*****************************************************************************
 * mod_openssl.c: callbacks and management of https connection
 * this file is part of https://github.com/ouistiti-project/libhttpserver
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ouistiti/log.h"
#include "ouistiti/httpserver.h"
#include "mod_tls.h"

#define tls_dbg(...)

#define HANDSHAKE 0x01
#define RECV_COMPLETE 0x02

static const char str_https[] = "https";

typedef struct _mod_openssl_s _mod_openssl_t;

typedef struct _mod_openssl_ctx_s
{
	SSL *ssl;
	http_client_t *clt;
	const httpclient_ops_t *protocolops;
	void *protocol;
	_mod_openssl_t *mod;
	int state;
} _mod_openssl_ctx_t;

struct _mod_openssl_s
{
	const httpclient_ops_t *protocolops;
	void *protocol;
	SSL_CTX *openssl_ctx;
};

static http_server_config_t mod_openssl_config;
static const httpclient_ops_t *tlsserver_ops;

void *mod_openssl_create(http_server_t *server, mod_tls_t *modconfig)
{
	int ret;
	int is_set_pemkey = 0;
	_mod_openssl_t *mod = NULL;

	if (!modconfig)
	{
		err("tls: module configuration not found");
		return NULL;
	}

	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	SSL_CTX_set_ecdh_auto(ctx, 1);
	if (modconfig->crtfile)
	{
		int ret = SSL_CTX_use_certificate_file(ctx, (const char *) modconfig->crtfile, SSL_FILETYPE_PEM);
		if (ret <= 0)
		{
			long error = ERR_get_error();
			err("tls: certificate not found %s", ERR_reason_error_string(error));
			if (ERR_GET_REASON(error) == SSL_R_EE_KEY_TOO_SMALL)
				err("tls: modify your certificate to be at least 2048 bits long");
			SSL_CTX_free(ctx);
			return NULL;
		}
	}

	if (modconfig->keyfile)
	{
		int ret = SSL_CTX_use_PrivateKey_file(ctx, (const char *) modconfig->keyfile, SSL_FILETYPE_PEM);
		if (ret <= 0)
		{
			long error = ERR_get_error();
			err("tls: key not found %s", ERR_reason_error_string(error));
			ERR_print_errors_fp(stderr);
			SSL_CTX_free(ctx);
			return NULL;
		}
	}
	if (ctx != NULL)
	{
		mod = calloc(1, sizeof(*mod));
		mod->openssl_ctx = ctx;

		mod->protocolops = httpserver_changeprotocol(server, tlsserver_ops, mod);
		mod->protocol = server;
	}
	return mod;
}
void *mod_tls_create(http_server_t *server, mod_tls_t *modconfig) __attribute__ ((weak, alias ("mod_openssl_create")));

void mod_openssl_destroy(void *arg)
{
	_mod_openssl_t *mod = (_mod_openssl_t *)arg;

	SSL_CTX_free(mod->openssl_ctx);
	free(mod);
}
void mod_tls_destroy(void *arg) __attribute__ ((weak, alias ("mod_openssl_destroy")));

static void *_tlsserver_create(void *arg, http_client_t *clt);
static int _tls_connect(void *vctx, const char *addr, int port);
static void _tls_disconnect(void *vctx);
static void _tls_destroy(void *vctx);

static void *_tlsserver_create(void *arg, http_client_t *clt)
{
	_mod_openssl_ctx_t *ctx = calloc(1, sizeof(*ctx));
	_mod_openssl_t *mod = (_mod_openssl_t *)arg;
	void *protocolconfig;
	ctx->clt = clt;
	ctx->mod = mod;
	ctx->protocolops = mod->protocolops;
	ctx->protocol = ctx->protocolops->create(mod->protocol, clt);
	if (ctx->protocol == NULL)
	{
		free(ctx);
		return NULL;
	}
	dbg("tls create");
	ctx->ssl = SSL_new(mod->openssl_ctx);
	int sock = httpclient_socket(clt);

	SSL_set_fd(ctx->ssl, sock);
	int ret = SSL_accept(ctx->ssl);
	if (ret <= 0)
	{
		int error = SSL_get_error(ctx->ssl, ret);
		err("tls: create error %d %s", error, ERR_reason_error_string(error));
		_tls_disconnect(ctx);
		_tls_destroy(ctx);
		return NULL;
	}
	dbg("tls: connection accepted");
	return ctx;
}

static int _tls_connect(void *vctx, const char *addr, int port)
{
	int ret = ESUCCESS;
	_mod_openssl_ctx_t *ctx = (_mod_openssl_ctx_t *)vctx;
	dbg("tls: connect");
	ret = ctx->protocolops->connect(ctx->protocol, addr, port);
	return ret;
}

static void _tls_disconnect(void *vctx)
{
	_mod_openssl_ctx_t *ctx = (_mod_openssl_ctx_t *)vctx;
	dbg("tls: disconnect");
	SSL_shutdown(ctx->ssl);
	SSL_free(ctx->ssl);
	ctx->protocolops->disconnect(ctx->protocol);
}

static void _tls_destroy(void *vctx)
{
	_mod_openssl_ctx_t *ctx = (_mod_openssl_ctx_t *)vctx;
	dbg("tls: complete");
	ctx->protocolops->destroy(ctx->protocol);
	free(ctx);
}

static int _tls_recv(void *vctx, char *data, int size)
{
	int ret;
	_mod_openssl_ctx_t *ctx = (_mod_openssl_ctx_t *)vctx;

//	do {
		ret = SSL_read(ctx->ssl, (unsigned char *)data, size);
		tls_dbg("tls: recv %d %.*s", ret, ret, data);
		if (ret < 0)
		{
			int error = SSL_get_error(ctx->ssl, ret);
			if (error == SSL_ERROR_WANT_READ ||
				error == SSL_ERROR_WANT_WRITE ||
				error == SSL_ERROR_WANT_X509_LOOKUP)
			{
				ret = EINCOMPLETE;
				sched_yield();
			}
			else
			{
				err("tls: recv error(%d)", error);
				ret = EREJECT;
				ctx->state |= RECV_COMPLETE;
			}
		}
		else if (ret == 0)
		{
			ret = EREJECT;
			ctx->state |= RECV_COMPLETE;
		}
		else
		{
			ctx->state &= ~RECV_COMPLETE;
		}
//	} while (ret == EINCOMPLETE);
	return ret;
}

static int _tls_send(void *vctx, const char *data, int size)
{
	int ret = 0;
	_mod_openssl_ctx_t *ctx = (_mod_openssl_ctx_t *)vctx;

	do {
		ret = SSL_write(ctx->ssl, (unsigned char *)data, size);
		tls_dbg("tls: send %d %.*s", ret, size, data);
		if (ret < 0)
		{
			warn("tls: send %d %.*s", ret, size, data);
			int error = SSL_get_error(ctx->ssl, ret);
			if (error == SSL_ERROR_WANT_WRITE ||
				error == SSL_ERROR_WANT_READ ||
				error == SSL_ERROR_WANT_X509_LOOKUP)
			{
				err("tls: send error(%d) WANT_DATA", error);
				ret = EINCOMPLETE;
				sched_yield();
			}
			else
			{
				err("tls: send error(%d)", error);
				ret = EREJECT;
			}
		}
	} while (ret == EINCOMPLETE);
	return ret;
}

static int tls_wait(void *vctx, int options)
{
	_mod_openssl_ctx_t *ctx = (_mod_openssl_ctx_t *)vctx;
	int ret = ESUCCESS;
	tls_dbg("tls: wait %x", options);
	tls_dbg("tls: wait %x", ctx->state);
	if (!(options & WAIT_SEND) && SSL_want_read(ctx->ssl))
	{
		tls_dbg("tls: wait continue");
		ret = ctx->protocolops->wait(ctx->protocol, options);
	}
	return ret;
}


static int _tls_status(void *vctx)
{
	_mod_openssl_ctx_t *ctx = (_mod_openssl_ctx_t *)vctx;
	tls_dbg("tls: status %x", ctx->state);

	if ((ctx->state & RECV_COMPLETE) == RECV_COMPLETE)
		return ctx->protocolops->status(ctx->protocol);
	return ESUCCESS;
}

static void _tls_flush(void *vctx)
{
	_mod_openssl_ctx_t *ctx = (_mod_openssl_ctx_t *)vctx;
	return ctx->protocolops->flush(ctx->protocol);
}

static const httpclient_ops_t *tlsserver_ops = &(httpclient_ops_t)
{
	.scheme = str_https,
	.default_port = 443,
	.type = HTTPCLIENT_TYPE_SECURE,
	.create = _tlsserver_create,
	.recvreq = _tls_recv,
	.sendresp = _tls_send,
	.wait = tls_wait,
	.status = _tls_status,
	.flush = _tls_flush,
	.disconnect = _tls_disconnect,
	.destroy = _tls_destroy,
};

const module_t mod_tls =
{
	.name = str_tls,
	.configure = (module_configure_t)&tls_config,
	.create = (module_create_t)&mod_tls_create,
	.destroy = &mod_tls_destroy,
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_tls")));
#endif
