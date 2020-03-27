/*****************************************************************************
 * testclient.c: Simple HTTP client
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define HAVE_GETOPT
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifndef WIN32
# include <sys/socket.h>
# include <sys/ioctl.h>
# include <sys/un.h>
# include <net/if.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
# include <arpa/inet.h>
# include <netdb.h>
#else
#endif

#ifdef MBEDTLS
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/debug.h>

#include <mbedtls/net_sockets.h>

#endif

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
# define dbg(...)
#endif

enum
{
	CONNECTION_START,
	REQUEST_START=0x01,
	REQUEST_HEADER=0x02,
	REQUEST_CONTENT=0x04,
	REQUEST_END=0x08,
	RESPONSE_START=0x10,
	RESPONSE_END=0x20,
	CONNECTION_END=0x40,
};

void display_help(char **name)
{
	printf("%s [-t][-a <address>][-p <port>][-w]\n", name[0]);
}

typedef struct net_api_s
{
	void *(*connect)(const char *serveraddr, const int port);
	int (*fd)(void *arg);
	int (*send)(void *arg, const void *buf, size_t len);
	int (*recv)(void *arg, void *buf, size_t len);
	void (*close)(void *sock);
} net_api_t;

#ifdef MBEDTLS
typedef struct tls_s
{
	mbedtls_ssl_context ssl;
	mbedtls_net_context server_fd;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
} tls_t;

void *tls_connect(const char *serveraddr, const int port)
{
	int ret;

	tls_t *tls = calloc(1, sizeof(*tls));

    mbedtls_ssl_init( &tls->ssl );

    mbedtls_net_init( &tls->server_fd );

    mbedtls_ssl_config_init( &tls->conf );

    mbedtls_x509_crt_init( &tls->cacert );

    mbedtls_ctr_drbg_init( &tls->ctr_drbg );

    mbedtls_entropy_init( &tls->entropy );

    if( ( ret = mbedtls_net_connect( &tls->server_fd, serveraddr, "443", MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        err(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_config_defaults( &tls->conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        err( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_conf_authmode( &tls->conf, MBEDTLS_SSL_VERIFY_OPTIONAL );


    ret = mbedtls_x509_crt_parse( &tls->cacert, (const unsigned char *) mbedtls_test_cas_pem,
                          mbedtls_test_cas_pem_len );
    if( ret < 0 )
    {
        err(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        goto exit;
    }
    mbedtls_ssl_conf_ca_chain( &tls->conf, &tls->cacert, NULL );

	const char *pers = "ssl_client1";
    if( ( ret = mbedtls_ctr_drbg_seed( &tls->ctr_drbg, mbedtls_entropy_func, &tls->entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        err(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }
    mbedtls_ssl_conf_rng( &tls->conf, mbedtls_ctr_drbg_random, &tls->ctr_drbg );

    if( ( ret = mbedtls_ssl_setup( &tls->ssl, &tls->conf ) ) != 0 )
    {
       err(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &tls->ssl, serveraddr ) ) != 0 )
    {
        err(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_set_bio( &tls->ssl, &tls->server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    while( ( ret = mbedtls_ssl_handshake( &tls->ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            err(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
            goto exit;
        }
    }

	uint32_t flags;
    if( ( flags = mbedtls_ssl_get_verify_result( &tls->ssl ) ) != 0 )
    {
        char vrfy_buf[512];

        err("failed\n  ! mbedtls_ssl_get_verify_result \n" );

        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        err("%s\n", vrfy_buf );
    }

	return tls;
exit:
	return NULL;
}

int tls_fd(void *arg)
{
	tls_t *tls = (tls_t *)arg;
	return tls->server_fd.fd;
}

int tls_send(void *arg, const void *buf, size_t len)
{
	tls_t *tls = (tls_t *)arg;
	int ret;
    while( ( ret = mbedtls_ssl_write( &tls->ssl, buf, len ) ) <= 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            err(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            return -1;
        }
    }
    return ret;
}

int tls_recv(void *arg, void *buf, size_t len)
{
	tls_t *tls = (tls_t *)arg;
	return mbedtls_ssl_read( &tls->ssl, buf, len );
}

void tls_close(void *arg)
{
	tls_t *tls = (tls_t *)arg;
	mbedtls_ssl_close_notify(&tls->ssl);
	free(tls);
}

net_api_t tls =
{
	.connect = tls_connect,
	.fd = tls_fd,
	.send = tls_send,
	.recv = tls_recv,
	.close = tls_close,
};
#endif

int direct_fd(void *arg)
{
	return (long)arg;
}

void *direct_connect(const char *serveraddr, const int port)
{
	int sock = -1;
	struct sockaddr_in saddr;
	struct addrinfo hints;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Stream socket */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	struct addrinfo *result, *rp;
	getaddrinfo(serveraddr, NULL, &hints, &result);

	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock == -1)
			continue;

		((struct sockaddr_in *)rp->ai_addr)->sin_port = htons(port);
		if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		close(sock);
		sock = -1;
	}

	if (sock == -1)
	{
		return NULL;
	}

	return (void *)((long)sock);
}

int direct_send(void *arg, const void *buf, size_t len)
{
	int sock = (long)arg;
	return send(sock, buf, len, MSG_NOSIGNAL);
}

int direct_recv(void *arg, void *buf, size_t len)
{
	int sock = (long)arg;
	int flags;
	flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);

	int ret;
	while ((ret = recv(sock, buf, len, MSG_NOSIGNAL)) == -1 && (errno == EAGAIN))
	{
		int sret;
		struct timeval *ptimeout = NULL;
		struct timeval timeout;
		fd_set rfds;
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		ptimeout = &timeout;
		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		sret = select(sock + 1, &rfds, NULL, NULL, ptimeout);
		if (sret != 1)
			return -1;
	}

	return ret;
}

void direct_close(void *arg)
{
	int sock = (long)arg;
	close(sock);
}

net_api_t direct =
{
	.fd = direct_fd,
	.connect = direct_connect,
	.send = direct_send,
	.recv = direct_recv,
	.close = direct_close,
};

#define OPT_WEBSOCKET 0x01
#define OPT_PIPELINE 0x02
int main(int argc, char **argv)
{
	int port = 80;
	const char *serveraddr = "127.0.0.1";
	void *sock = NULL;
	int options = 0;
	net_api_t *net = &direct;

#ifndef DEBUG
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
#endif

#ifdef HAVE_GETOPT
	int opt;
	do
	{
		opt = getopt(argc, argv, "a:p:hwPt");
		switch (opt)
		{
			case 'a':
				serveraddr = optarg;
			break;
			case 'p':
				port = atoi(optarg);
			break;
			case 'h':
				display_help(argv);
				return -1;
			case 'w':
				options |= OPT_WEBSOCKET;
			break;
			case 'P':
				options |= OPT_PIPELINE;
			break;
#ifdef MBEDTLS
			case 't':
				port = 443;
				net = &tls;
			break;
#endif
		}
	} while(opt != -1);
#endif

	sock = net->connect(serveraddr, port);

	int state = CONNECTION_START;
	int reqlength = 0;
	char reqbuffer[512];
	int resplength = 0;
	char respbuffer[2048];
	int headerlength = 0;
	int ret = 0;
	do
	{
		fd_set rfds;
		FD_ZERO(&rfds);
		if (!(state & REQUEST_END))
		{
			FD_SET(0, &rfds);
		}
		FD_SET(net->fd(sock), &rfds);

		int ret;
		if (reqlength == 0 || (state & REQUEST_END))
		{
			ret = select(net->fd(sock) + 1, &rfds, NULL, NULL, NULL);
			if (ret > 0 && FD_ISSET(net->fd(sock), &rfds))
			{
				resplength = net->recv(sock, respbuffer + resplength, sizeof(respbuffer) - resplength);
				if (resplength > 0)
				{
					dbg("testclient: recieve (%d)", resplength);
					resplength -= write(1, respbuffer, resplength);
					if (options & OPT_WEBSOCKET)
					{
						state &= ~REQUEST_END;
					}
				}
				else if (!(options & OPT_WEBSOCKET))
					state |= CONNECTION_END;
				ret--;
			}
		}
		else
			ret = 1;
		if ( ret > 0)
		{
			if (FD_ISSET(0, &rfds) && reqlength == 0)
			{
				reqlength = read(0, reqbuffer, sizeof(reqbuffer));
				headerlength = 0;
			}
			if (reqlength > 0)
			{
				int contentlength = 0;
				char *content = NULL;
				if (options & OPT_WEBSOCKET)
					strstr(reqbuffer + headerlength, "\r\n\r\n");
				if (content)
				{
					content += 4;
					contentlength = reqlength + reqbuffer - content;
					reqlength -= contentlength;
					state |= REQUEST_CONTENT;
				}
				dbg("testclient: send (%d)", reqlength);
				int length = net->send(sock, reqbuffer + headerlength, reqlength);
				if (content || !(state && REQUEST_CONTENT))
					headerlength = reqlength;
				reqlength -= length;
				if (options & OPT_WEBSOCKET && strstr(reqbuffer, "Upgrade: websocket"))
					state |= REQUEST_END;
				reqlength += contentlength;
			}
			else if (options & OPT_WEBSOCKET)
				state |= CONNECTION_END;
			else
			{
				state |= REQUEST_END;
			}
			ret--;
		}
	} while (!(state & CONNECTION_END));
	dbg("testclient: quit");
	net->close(sock);
	return ret;
}
