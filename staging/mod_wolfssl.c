/*****************************************************************************
 * mod_wolftls.c: callbacks and management of https connection
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

#include <wolfssl/ssl.h>

typedef int (wolftls_ssl_send_t)(void *, const unsigned char *, size_t);
typedef int (wolfls_ssl_recv_t)(void *, unsigned char *, size_t);

#include "ouistiti/log.h"
#include "ouistiti/httpserver.h"
#include "mod_tls.h"

static const char str_wolftls[] = "tls";

typedef struct _mod_wolftls_ctx_s
{
	WOLFSSL *ssl;
	http_client_t *ctl;
	http_recv_t recvreq;
	http_send_t sendresp;
	void *ctx;
} _mod_wolftls_ctx_t;

typedef struct _mod_wolftls_s
{
	WOLFSSL_METHOD* method;
	WOLFSSL_CTX* ctx;
} _mod_wolftls_t;

static http_server_config_t mod_wolftls_config;

static void *_mod_wolftls_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize);
static void _mod_wolftls_freectx(void *vctx);
static int _mod_wolftls_recv(void *vctx, char *data, int size);
static int _mod_wolftls_send(void *vctx, char *data, int size);

void *mod_wolftls_create(http_server_t *server, char *unused, mod_tls_t *modconfig)
{
	int ret;
	_mod_wolftls_t *mod;

	if (!modconfig)
		return NULL;

	warn("TLS uses WolfSSL: This version may require Commercial licence");
	mod = calloc(1, sizeof(*mod));

	wolfSSL_Init();
	mod->method = wolfTLSv1_2_server_method();

	if ( (mod->ctx = wolfSSL_CTX_new(mod->method)) == NULL)
		goto wolfftls_out_ctx;

	if (modconfig->crtfile)
	{
		ret = wolfSSL_CTX_use_certificate_file(mod->ctx, modconfig->crtfile, SSL_FILETYPE_PEM);
		if (ret != WOLFSSL_SUCCESS)
		{
			err("wolftls: CTX_use_certificate_file %d %d\n", ret, WOLFSSL_SUCCESS);
			goto wolfftls_out_certfile;
		}
	}

	if (modconfig->pemfile)
	{
		ret =  wolfSSL_CTX_use_PrivateKey_file(mod->ctx, modconfig->pemfile, SSL_FILETYPE_PEM);
		if (ret != WOLFSSL_SUCCESS)
		{
			err("wolftls: CTX_use_PrivateKey_file pem %d\n", ret);
			goto wolfftls_out_certfile;
		}
	}
	if (modconfig->cachain)
	{
		ret = wolfSSL_CTX_use_certificate_chain_file(mod->ctx, modconfig->cachain);
		if (ret != WOLFSSL_SUCCESS)
		{
			err("wolftls: CTX_use_certificate_chain_file cachain %d\n", ret);
			goto wolfftls_out_certfile;
		}
	}

	httpserver_addmod(server, _mod_wolftls_getctx, _mod_wolftls_freectx, mod, str_wolftls);

	return mod;
wolfftls_out_certfile:
	wolfSSL_CTX_free(mod->ctx);
wolfftls_out_ctx:
	free(mod);
	return NULL;
}
void *mod_tls_create(http_server_t *server, char *unused, mod_tls_t *modconfig) __attribute__ ((weak, alias ("mod_wolftls_create")));

void mod_wolftls_destroy(void *arg)
{
	_mod_wolftls_t *mod = (_mod_wolftls_t *)arg;

	wolfSSL_CTX_free(mod->ctx);
	wolfSSL_Cleanup();
	free(mod);
}
void mod_tls_destroy(void *arg) __attribute__ ((weak, alias ("mod_wolftls_destroy")));

static void *_mod_wolftls_getctx(void *arg, http_client_t *ctl, struct sockaddr *addr, int addrsize)
{
	_mod_wolftls_t *mod = (_mod_wolftls_t *)arg;
	WOLFSSL	*ssl = NULL;

	ssl = wolfSSL_new(mod->ctx);
	if (ssl == NULL)
	{
		err("wolftls connection error");
		return NULL;
	}
	dbg("TLS Open 1");

	wolfSSL_set_fd(ssl, httpclient_wait(ctl, WAIT_ACCEPT));

	int ret;
	dbg("TLS accept");

	do
	{
		ret = wolfSSL_accept(ssl);

		if (ret != SSL_SUCCESS)
		{
			if (wolfSSL_want_read(ssl))
				continue;
			err("wolftls handshake error");
			char buffer[80];
			int err = wolfSSL_get_error(ssl, ret);
			wolfSSL_ERR_error_string(err, buffer);
			warn("wolfssl err %s", buffer);
			return NULL;
		}
	} while (ret != SSL_SUCCESS);
	dbg("TLS run");

	_mod_wolftls_ctx_t *ctx = calloc(1, sizeof(*ctx));
	ctx->ssl = ssl;
	ctx->ctl = ctl;
	ctx->ctx = httpclient_context(ctl);
	ctx->recvreq = httpclient_addreceiver(ctl, _mod_wolftls_recv, ctx);
	ctx->sendresp = httpclient_addsender(ctl, _mod_wolftls_send, ctx);

	return ctx;
}

static void _mod_wolftls_freectx(void *vctx)
{
	int ret;
	_mod_wolftls_ctx_t *ctx = (_mod_wolftls_ctx_t *)vctx;
	dbg("TLS Close");
	wolfSSL_free(ctx->ssl);
	httpclient_addreceiver(ctx->ctl, ctx->recvreq, ctx->ctx);
	httpclient_addsender(ctx->ctl, ctx->sendresp, ctx->ctx);
	free(ctx);
}

static int _mod_wolftls_recv(void *vctx, char *data, int size)
{
	int ret;
	_mod_wolftls_ctx_t *ctx = (_mod_wolftls_ctx_t *)vctx;
warn("wolfssl read");
#ifndef SOCKET_BLOCKING
	do
	{
	ret = wolfSSL_pending(ctx->ssl);
	} while (ret == 0);
	if (ret > 0)
#endif
	{
		ret = wolfSSL_read(ctx->ssl, (unsigned char *)data, size);
warn("wolfssl read %d", ret);
	}
	int err = wolfSSL_get_error(ctx->ssl, ret);
warn("wolfssl err %d", err);
	if (ret != WOLFSSL_SUCCESS && err == SSL_ERROR_WANT_READ)
		ret = EINCOMPLETE;
	else if (ret < 0)
	{
		ret = EREJECT;
	}
	return ret;
}

static int _mod_wolftls_send(void *vctx, char *data, int size)
{
	int ret;
	_mod_wolftls_ctx_t *ctx = (_mod_wolftls_ctx_t *)vctx;
	ret = wolfSSL_write(ctx->ssl, (unsigned char *)data, size);
	if (ret == 0 && wolfSSL_get_error(ctx->ssl, ret) == SSL_ERROR_WANT_WRITE)
		ret = EINCOMPLETE;
	else if (ret < 0)
		ret = EREJECT;
	return ret;
}

const module_t mod_tls =
{
	.name = str_wolftls,
	.create = (module_create_t)mod_tls_create,
	.destroy = mod_tls_destroy,
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_tls")));
#endif
