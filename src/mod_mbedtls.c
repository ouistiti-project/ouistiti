/*****************************************************************************
 * mod_mbedtls.c: callbacks and management of https connection
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include <mbedtls/platform.h>
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_free       free
#define mbedtls_calloc    calloc
#endif

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>
#include <mbedtls/error.h>
#if MBEDTLS_VERSION_MAJOR==2 && MBEDTLS_VERSION_MINOR>=4
#include <mbedtls/net_sockets.h>
#elif MBEDTLS_VERSION_MAJOR==2 && MBEDTLS_VERSION_MINOR==2
#include <mbedtls/net.h>

#else
#error MBEDTLS not found
#endif

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "ouistiti/log.h"
#include "ouistiti/httpserver.h"
#ifdef httpserver_config
#include "ouistiti/config.h"
#endif
#include "mod_tls.h"

#define tls_dbg(...)

#define HANDSHAKE 0x01
#define RECV_COMPLETE 0x02

typedef struct _mod_mbedtls_config_s _mod_mbedtls_config_t;

typedef struct _mod_mbedtls_s
{
	mbedtls_ssl_context ssl;
	http_client_t *clt;
	int state;
	const httpclient_ops_t *protocolops;
	void *protocol;
	_mod_mbedtls_config_t *config;
} _mod_mbedtls_t;

struct _mod_mbedtls_config_s
{
	const httpclient_ops_t *protocolops;
	mod_tls_t *config;
	const char *pers;
	size_t perslen;
	void *protocol;
	mbedtls_ssl_config conf;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_x509_crt srvcert;
	mbedtls_x509_crt cachain;
	mbedtls_pk_context pkey;
	mbedtls_dhm_context dhm;
};

static const httpclient_ops_t *_tlsclient_ops;
static const httpclient_ops_t *_tlsserver_ops;

static int _mod_mbedtls_crtfile(_mod_mbedtls_config_t *config, mod_tls_t *modconfig)
{
	int ret;
	int is_set_pemkey = 0;

	ret = mbedtls_x509_crt_parse_file(&config->srvcert, (const char *) modconfig->crtfile);
	if (ret)
		err("tls: x509 certificate error 0x%X\n", -ret);
	else
		is_set_pemkey++;
	mbedtls_pk_init(&config->pkey);
	if (modconfig->keyfile)
	{
		ret =  mbedtls_pk_parse_keyfile(&config->pkey, (const char *) modconfig->keyfile, NULL);
		if (ret)
			err("tls: key error  0x%X\n", -ret);
		else
			is_set_pemkey++;
	}
	else
	{
		ret =  mbedtls_pk_parse_keyfile(&config->pkey, (const char *) modconfig->crtfile, NULL);
		if (ret)
			err("tls: key from cert error 0x%X\n", -ret);
		else
			is_set_pemkey++;
	}
	if (is_set_pemkey == 2)
	{
		ret = mbedtls_ssl_conf_own_cert(&config->conf, &config->srvcert, &config->pkey);
		if (ret)
			err("tls: conf error 0x%X\n", -ret);
		else
			ret = EREJECT;
	}
	else
		ret = EREJECT;
	return ret;
}

static int _mod_mbedtls_setup(_mod_mbedtls_config_t *mod)
{
	mod_tls_t *config = mod->config;
	int ret;

	if (config == NULL)
		return ECONTINUE;

	mbedtls_x509_crt_init(&mod->srvcert);
	mbedtls_x509_crt_init(&mod->cachain);

	mbedtls_ssl_config_init(&mod->conf);

	mbedtls_ctr_drbg_init(&mod->ctr_drbg);
	mbedtls_entropy_init(&mod->entropy);

	ret = mbedtls_ssl_config_defaults(&mod->conf,
		MBEDTLS_SSL_IS_SERVER,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret)
	{
		err("mbedtls_ssl_config_defaults 0x%X\n", -ret);
		return EREJECT;
	}

	if (config->crtfile)
	{
		ret = _mod_mbedtls_crtfile(mod, config);
	}
	if (config->cachain)
	{
		ret = mbedtls_x509_crt_parse_file(&mod->cachain, (const char *) config->cachain);
		if (ret)
		{
			err("tls: cachain error 0x%X\n", -ret);
			return EREJECT;
		}
		else
			mbedtls_ssl_conf_ca_chain(&mod->conf, &mod->cachain, NULL);
	}

	if (mod->pers)
	{
		warn("tls: wait for random generator...");
		ret = mbedtls_ctr_drbg_seed(&mod->ctr_drbg, mbedtls_entropy_func, &mod->entropy,
			(const unsigned char *) mod->pers, mod->perslen);
		if (ret)
		{
			err("tls: entropy error 0x%X\n", -ret);
			return EREJECT;
		}
		else
			mbedtls_ssl_conf_rng(&mod->conf, mbedtls_ctr_drbg_random, &mod->ctr_drbg );
		warn("tls: crng init done");
	}


	if (config->dhmfile)
	{
		mbedtls_dhm_init(&mod->dhm);
		ret = mbedtls_dhm_parse_dhmfile(&mod->dhm, config->dhmfile);
		if (ret)
		{
			err("tls: dhmparam error 0x%X\n", -ret);
			return EREJECT;
		}
	}
	return ESUCCESS;
}

static void *mod_mbedtls_create(http_server_t *server, mod_tls_t *modconfig)
{
	_mod_mbedtls_config_t *mod;
	if (!modconfig)
		return NULL;

	mod = mbedtls_calloc(1, sizeof(*mod));
	mod->protocolops = httpserver_changeprotocol(server, _tlsserver_ops, mod);
	mod->protocol = server;
	mod->config = modconfig;
	mod->pers = httpserver_INFO(server, "name");
	if (! mod->pers)
	{
		mod->pers = str_tls;
		mod->perslen = sizeof(str_tls) - 1;
	}
	else
		mod->perslen = strlen(mod->pers);
	if (_mod_mbedtls_setup(mod) == ESUCCESS)
		warn("tls: enables on %s %s", httpserver_INFO(server, "hostname"), httpserver_INFO(server, "port"));
	else
	{
		mbedtls_free(mod);
		mod = NULL;
	}

	return mod;
}

static void mod_mbedtls_destroy(void *arg)
{
	_mod_mbedtls_config_t *mod = (_mod_mbedtls_config_t *)arg;
#ifdef FILE_CONFIG
	if (mod->config)
		free(mod->config);
#endif

	mbedtls_dhm_free(&mod->dhm);
	mbedtls_x509_crt_free(&mod->srvcert);
	mbedtls_x509_crt_free(&mod->cachain);
	mbedtls_pk_free(&mod->pkey);
	mbedtls_ctr_drbg_free(&mod->ctr_drbg);
	mbedtls_entropy_free(&mod->entropy);
	mbedtls_ssl_config_free(&mod->conf);
	mbedtls_free(mod);
}

static int _mod_mbedtls_read(void *arg, unsigned char *data, int size)
{
	_mod_mbedtls_t *ctx = (_mod_mbedtls_t *)arg;
	int ret = ctx->protocolops->recvreq(ctx->protocol, (char *)data, size);
	tls_dbg("tls: recvreq %d", ret);
	if (ret == EINCOMPLETE)
		ret = MBEDTLS_ERR_SSL_WANT_READ;
	else if (ret == EREJECT)
		ret = MBEDTLS_ERR_NET_RECV_FAILED;
	return ret;
}

static int _mod_mbedtls_write(void *arg, unsigned char *data, int size)
{
	_mod_mbedtls_t *ctx = (_mod_mbedtls_t *)arg;
	int ret = ctx->protocolops->sendresp(ctx->protocol, (char *)data, size);
	tls_dbg("tls: sendresp %d", ret);
	if (ret == EINCOMPLETE)
	{
		ret = MBEDTLS_ERR_SSL_WANT_WRITE;
	}
	else if (ret == EREJECT)
		ret = MBEDTLS_ERR_NET_SEND_FAILED;
	return ret;
}

static int _tls_handshake(_mod_mbedtls_t *ctx)
{
	int ret = ESUCCESS;
	if (!(ctx->state & HANDSHAKE))
	{
		ctx->state &= ~RECV_COMPLETE;
		tls_dbg("tls: handshake");
		while((ret = mbedtls_ssl_handshake(&ctx->ssl)) != 0 )
		{
			if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
				break;
		}
		if (ret == ESUCCESS)
		{
			ctx->state |= HANDSHAKE;
		}
		else
		{
			char error[256];
			mbedtls_strerror(ret, error, 256);
			err("tls: handshake error %X %s", -ret, error);
			mbedtls_ssl_free(&ctx->ssl);
			ret = EREJECT;
		}
	}
	return ret;
}

#ifdef HTTPCLIENT_FEATURES
static void *_tlsclient_create(void *arg, http_client_t *clt)
{
	_mod_mbedtls_t *ctx = calloc(1, sizeof(*ctx));
	_mod_mbedtls_config_t *config = (_mod_mbedtls_config_t *)arg;

	ctx->clt = clt;

	/**
	 * client connection
	 */
	int ret;
	char *tls_certificat = NULL;

	if (arg != NULL)
	{
		tls_certificat = arg;
		if (tls_certificat[0] < 0x20 || tls_certificat[0] > 0x7F)
			tls_certificat = NULL;
	}

	config = calloc(1, sizeof(*config));;
	config->protocolops = tcpclient_ops;
	config->protocol = NULL;

	mbedtls_x509_crt_init(&config->srvcert);

	mbedtls_ctr_drbg_init(&config->ctr_drbg);
	mbedtls_entropy_init(&config->entropy);

	ret = mbedtls_ctr_drbg_seed(&config->ctr_drbg, mbedtls_entropy_func, &config->entropy,
			STRING_REF(str_servername));
	if (ret)
	{
		err("mbedtls_ctr_drbg_seed %d\n", ret);
		free(ctx);
		return NULL;
	}

	if (tls_certificat != NULL)
	{
		ret = mbedtls_x509_crt_parse_file( &config->srvcert, tls_certificat);
		if (ret)
		{
			err("mbedtls_x509_crt_parse %d\n", ret);
			free(ctx);
			return NULL;
		}
	}

	ret = mbedtls_ssl_config_defaults( &config->conf,
					MBEDTLS_SSL_IS_CLIENT,
					MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT );
	if (ret)
	{
		err("mbedtls_ssl_config_defaults %d\n", ret);
		free(ctx);
		return NULL;
	}
	mbedtls_ssl_conf_authmode( &config->conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
	mbedtls_ssl_conf_ca_chain( &config->conf, &config->srvcert, NULL );
	mbedtls_ssl_conf_rng( &config->conf, mbedtls_ctr_drbg_random, &config->ctr_drbg );

	ctx->config = config;
	ctx->protocolops = config->protocolops;
	ctx->protocol = ctx->protocolops->create(config->protocol, clt);
	if (ctx->protocol == NULL)
	{
		free(ctx);
		return NULL;
	}
	mbedtls_ssl_init(&ctx->ssl);
	mbedtls_ssl_setup(&ctx->ssl, &ctx->config->conf);
	mbedtls_ssl_set_bio(&ctx->ssl, ctx, (mbedtls_ssl_send_t *)_mod_mbedtls_write, (mbedtls_ssl_recv_t *)_mod_mbedtls_read, NULL);

	return ctx;
}
#endif

static void *_tlsserver_create(void *arg, http_client_t *clt)
{
	_mod_mbedtls_t *ctx = calloc(1, sizeof(*ctx));
	_mod_mbedtls_config_t *config = (_mod_mbedtls_config_t *)arg;

	ctx->clt = clt;
	ctx->config = config;
	ctx->protocolops = config->protocolops;
	ctx->protocol = ctx->protocolops->create(config->protocol, clt);
	if (ctx->protocol == NULL)
	{
		free(ctx);
		return NULL;
	}
	mbedtls_ssl_init(&ctx->ssl);
	mbedtls_ssl_setup(&ctx->ssl, &ctx->config->conf);
	mbedtls_ssl_set_bio(&ctx->ssl, ctx, (mbedtls_ssl_send_t *)_mod_mbedtls_write, (mbedtls_ssl_recv_t *)_mod_mbedtls_read, NULL);
	if (_tls_handshake(ctx) == EREJECT)
	{
		free(ctx);
		ctx = NULL;
	}

	return ctx;
}

static int _tls_connect(void *vctx, const char *addr, int port)
{
	int ret = ESUCCESS;
	_mod_mbedtls_t *ctx = (_mod_mbedtls_t *)vctx;

	ctx->protocolops->connect(ctx->protocol, addr, port);
	ret = _tls_handshake(ctx);
	tls_dbg("tls: connect %d", ret);
	return ret;
}

static void _tls_disconnect(void *vctx)
{
	_mod_mbedtls_t *ctx = (_mod_mbedtls_t *)vctx;
	int ret;
	while ((ret = mbedtls_ssl_close_notify(&ctx->ssl)) == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
	ctx->protocolops->disconnect(ctx->protocol);
	tls_dbg("tls: disconnect");
}

static void _tls_destroy(void *vctx)
{
	_mod_mbedtls_t *ctx = (_mod_mbedtls_t *)vctx;
	tls_dbg("tls: end");
	mbedtls_ssl_free(&ctx->ssl);
	ctx->protocolops->destroy(ctx->protocol);
	free(ctx);
}

static int _tls_recv(void *vctx, char *data, size_t size)
{
	int ret;
	_mod_mbedtls_t *ctx = (_mod_mbedtls_t *)vctx;
#ifdef SOCKET_BLOCKING
	ret = MBEDTLS_ERR_SSL_WANT_READ;
	while (ret == MBEDTLS_ERR_SSL_WANT_READ)
#endif
	{
		ret = mbedtls_ssl_read(&ctx->ssl, (unsigned char *)data, size);
	}
	if (ret > 0)
		tls_dbg("tls: recv %d %.*s", ret, ret, data);
	else
		tls_dbg("tls: recv %X %X", ret, MBEDTLS_ERR_SSL_WANT_READ);
	if (ret == MBEDTLS_ERR_SSL_WANT_READ)
	{
		ctx->state |= RECV_COMPLETE;
		ret = EINCOMPLETE;
	}
	else if (ret <= 0)
	{
		if (ret <0)
		{
			char buffer[256];
			mbedtls_strerror(ret, buffer, sizeof(buffer));
			err("tls: recv error %s", buffer);
		}
		ret = EREJECT;
		ctx->state |= RECV_COMPLETE;
	}
	else
	{
		ctx->state &= ~RECV_COMPLETE;
	}
	return ret;
}

static int _tls_send(void *vctx, const char *data, size_t size)
{
	int ret;
	_mod_mbedtls_t *ctx = (_mod_mbedtls_t *)vctx;

#ifdef SOCKET_BLOCKING
	ret = MBEDTLS_ERR_SSL_WANT_WRITE;
	while (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
#endif
	{
		ret = mbedtls_ssl_write(&ctx->ssl, (const unsigned char *)data, size);
	}
	tls_dbg("tls: send %d %.*s", ret, size, data);
	if (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
		ret = EINCOMPLETE;
	else if (ret < 0)
	{
		char buffer[256];
		mbedtls_strerror(ret, buffer, sizeof(buffer));
		err("tls: send error(%d) %s", ret, buffer);
		ret = EREJECT;
	}
	return ret;
}

static int tls_wait(void *vctx, int options)
{
	_mod_mbedtls_t *ctx = (_mod_mbedtls_t *)vctx;
	int ret = ESUCCESS;
	if (!mbedtls_ssl_get_bytes_avail(&ctx->ssl))
	{
		ret = ctx->protocolops->wait(ctx->protocol, options);
	}
	return ret;
}

static int _tls_status(void *vctx)
{
	_mod_mbedtls_t *ctx = (_mod_mbedtls_t *)vctx;

	if ((ctx->state & RECV_COMPLETE) == RECV_COMPLETE)
		return ctx->protocolops->status(ctx->protocol);
	return ESUCCESS;
}

static void _tls_flush(void *vctx)
{
	_mod_mbedtls_t *ctx = (_mod_mbedtls_t *)vctx;
	return ctx->protocolops->flush(ctx->protocol);
}

static const httpclient_ops_t *_tlsserver_ops = &(httpclient_ops_t)
{
	.scheme = str_https,
	.default_port = 443,
	.type = HTTPCLIENT_TYPE_SECURE,
	.create = &_tlsserver_create,
	.recvreq = &_tls_recv,
	.sendresp = &_tls_send,
	.wait = &tls_wait,
	.status = &_tls_status,
	.flush = &_tls_flush,
	.disconnect = &_tls_disconnect,
	.destroy = &_tls_destroy,
};

#ifdef HTTPCLIENT_FEATURES
static const httpclient_ops_t *_tlsclient_ops = &(httpclient_ops_t)
{
	.scheme = str_https,
	.default_port = 443,
	.type = HTTPCLIENT_TYPE_SECURE,
	.create = &_tlsclient_create,
	.connect = &_tls_connect,
	.recvreq = &_tls_recv,
	.sendresp = &_tls_send,
	.wait = &tls_wait,
	.status = &_tls_status,
	.flush = &_tls_flush,
	.disconnect = &_tls_disconnect,
	.destroy = &_tls_destroy,
};
#endif

const module_t mod_tls =
{
	.name = str_tls,
	.configure = (module_configure_t)&tls_config,
	.create = (module_create_t)&mod_mbedtls_create,
	.destroy = &mod_mbedtls_destroy,
};

static void __attribute__ ((constructor))_init(void)
{
#ifdef HTTPCLIENT_FEATURES
	httpclient_appendops((httpclient_ops_t *)_tlsclient_ops);
#endif
}

#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_tls")));
#endif
