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
	return (int)arg;
}

void *direct_connect(const char *serveraddr, const int port)
{
	int sock;
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

	return (void *)sock;
}

int direct_send(void *arg, const void *buf, size_t len)
{
	int sock = (int)arg;
	return send(sock, buf, len, MSG_NOSIGNAL);
}

int direct_recv(void *arg, void *buf, size_t len)
{
	int sock = (int)arg;
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
	int sock = (int)arg;
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

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

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
			break;
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
	int length;
	int ret = 0;
	char content[249];
	int contentlength = 0;
	do
	{
		char buffer[512];
#if 0
		while ((state & REQUEST_END) == 0)
		{
			length = 511;
			length = read(0, buffer, length);
			if (length > 0)
			{
				int ret;
//				ret = net->send(sock, buffer, length);

				buffer[length] = 0;
				//first read is blocking
				int flags;
				flags = fcntl(0, F_GETFL, 0);
				fcntl(0, F_SETFL, flags | O_NONBLOCK);

				state |= REQUEST_START;
				int headerlength = length;
				if (!(state & REQUEST_HEADER))
				{
					int i, emptyline = 0;
					for (i = 0; i < length; i++)
					{

						if (buffer[i] == '\n')
						{
							if (emptyline > 0 && emptyline < 3)
							{
								headerlength = i + 1;
								state |= REQUEST_HEADER;
								break;
							}
							emptyline = 0;
						}
						emptyline++;
					}
				}
				ret = net->send(sock, buffer, headerlength);
				if (ret < 0)
				{
					state |= REQUEST_END;
					state |= CONNECTION_END;
				}
				else if (ret != headerlength)
				{
					err("testclient: send error");
					state |= CONNECTION_END;
					ret = -1;
				}
				else if ((state & REQUEST_HEADER) && !(state & REQUEST_CONTENT))
				{
					dbg("testclient: send header (%d)", headerlength);
					contentlength = length - headerlength;
					if (options & OPT_WEBSOCKET)
					{
						state |= REQUEST_END;
						memcpy(content, buffer + headerlength, contentlength);
					}
					else if (contentlength)
					{

						/// send content
						usleep(50);
						ret = net->send(sock, buffer + headerlength, contentlength);
						dbg("testclient: send content (%d)", contentlength);
						state |= REQUEST_CONTENT;
					}
				}

			}
			else if (length == 0)
				state |= REQUEST_END;
			else if (state > CONNECTION_START && !(state & REQUEST_END))
			{
				if (errno != EAGAIN)
				{
					if (length < 0)
						err("testclient: request clomplete %s", strerror(errno));
					state |= REQUEST_END;
				}
			}
			if (state & REQUEST_START)
				break;
		}

		if (state & REQUEST_END)
		{
			length = 511;
			length = net->recv(sock, buffer, length);
			if (length > 0)
			{
				ret += length;
				state |= RESPONSE_START;
				buffer[length] = 0;
				write(1, buffer, length);
			}
			else if (length == 0)
			{
				state |= RESPONSE_END;
			}
			else
			{
				state |= CONNECTION_END;
			}
		}
		if (state & RESPONSE_END)
		{
			if (options & OPT_WEBSOCKET)
			{
				ret = net->send(sock, content, contentlength - 1);
				while ((state & CONNECTION_END) == 0)
				{
					length = 248;
					contentlength = net->recv(sock, content, length);
					if (contentlength <= 0)
						state |= CONNECTION_END;
					else
					{
						dbg("testclient: websocket receive (%d)", contentlength);
						int i;
						for (i = 0; i < contentlength; i++)
						{
							printf("%02hhX", content[i]);
						}
						printf("\n");
					}
				}
			}
			else if (options & OPT_PIPELINE)
				state = CONNECTION_START;
			else
				state |= CONNECTION_END;
		}

#else
		fd_set rfds;
		FD_ZERO(&rfds);
		if (!(state & REQUEST_END))
			FD_SET(0, &rfds);
		FD_SET(net->fd(sock), &rfds);

		int ret;
		ret = select(net->fd(sock) + 1, &rfds, NULL, NULL, NULL);
		if ( ret > 0 && FD_ISSET(0, &rfds))
		{
			length = 512;
			length = read(0, buffer, length);
			if (length > 0)
			{
				length = net->send(sock, buffer, length);
			}
			else
				state |= REQUEST_END;
		}
		if (ret > 0 && FD_ISSET(net->fd(sock), &rfds))
		{
			length = 512;
			length = net->recv(sock, buffer, length);
			if (length > 0)
			{
				length = write(1, buffer, length);
			}
			else
				state |= CONNECTION_END;
		}
#endif
	} while (!(state & CONNECTION_END));
	dbg("testclient: quit");
	net->close(sock);
	return ret;
}
