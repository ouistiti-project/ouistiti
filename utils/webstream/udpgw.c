/*****************************************************************************
 * udpgw.c: UDP/IP streaming Gateway
 *****************************************************************************
 * Copyright (C) 2016-2017
 *
 * Authors: Marc Chalain <marc.chalain@gmail.com
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
#define __USE_GNU
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sched.h>
#include <sys/stat.h>
#include <pthread.h>
#include <netdb.h>
#include <libgen.h>

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

#define CHUNKSIZE 4500

typedef int (*server_t)(int sock);

typedef struct stream_s stream_t;
typedef struct buffer_s buffer_t;

extern int ouistiti_recvaddr(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

int multicast(buffer_t *buffer, int resume);

struct stream_s
{
	int sock;
	buffer_t *buffer;
	pthread_t thread;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	stream_t *next;
};

struct buffer_s
{
	int sock;
	int ready;
	struct addrinfo *sourceaddress;
	char *data;
	ssize_t size;
	ssize_t length;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	stream_t *first;
};

void *runstream(void *arg)
{
	stream_t *stream = (stream_t *)arg;
	buffer_t *buffer = stream->buffer;
	int ret;
	int run = 1;

	warn("new stream %p %d", stream, stream->sock);
	pthread_mutex_lock(&stream->mutex);
	while (run)
	{
		pthread_mutex_lock(&buffer->mutex);
		do
		{
			ret = pthread_cond_wait(&buffer->cond, &buffer->mutex);
		} while (!buffer->ready && ret < 0);
		pthread_mutex_unlock(&buffer->mutex);
		ret = send(stream->sock, buffer->data, buffer->length, MSG_NOSIGNAL);
		if (ret < 0 && errno != EAGAIN)
		{
			dbg("send error %d %s", ret, strerror(errno));
			run = 0;
		}
	}
	warn("end stream %p", stream);
	pthread_mutex_unlock(&stream->mutex);
	return NULL;
}

stream_t *startstream(int sock, buffer_t *origin)
{
	pthread_attr_t attr;

	stream_t *stream = calloc(1, sizeof(*stream));

	stream->sock = sock;
	stream->buffer = origin;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	pthread_create(&stream->thread, &attr, runstream, stream);
	return stream;
}

void *rungenerator(void *arg)
{
	buffer_t *buffer = (buffer_t *)arg;
	int elem = 0;
	int run = 1;
	struct timespec timeout;
	timeout.tv_sec = 1;
	timeout.tv_nsec = 0;

	while (run)
	{
		int maxfd = buffer->sock;
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(buffer->sock, &rfds);
		int ret = select(maxfd + 1, &rfds, NULL, NULL, NULL);
		if (ret > 0 && FD_ISSET(buffer->sock, &rfds))
		{
			buffer->ready = 0;
			buffer->length = recvfrom(buffer->sock, buffer->data, buffer->size, 0,
				NULL, NULL);
				//(struct sockaddr *)&buffer->saddr, &buffer->addrlen);
			buffer->ready = 1;
			pthread_cond_broadcast(&buffer->cond);
	//		pthread_mutex_lock(&buffer->mutex);
	//		pthread_mutex_lock(&buffer->mutex);
		}
	}
	free(buffer->data);
	return NULL;
}

buffer_t *startgernerator(buffer_t *origin)
{
	pthread_t thread;
	pthread_attr_t attr;
	socklen_t sizelength = sizeof(origin->size);

	int ret = getsockopt( origin->sock, SOL_SOCKET, SO_RCVBUF, &origin->size, &sizelength);
	if (ret == 0)
	{
		origin->data = malloc(origin->size);

		pthread_cond_init(&origin->cond, NULL);
		pthread_mutex_init(&origin->mutex, NULL);

		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

		pthread_create(&thread, &attr, rungenerator, origin);
	}
	return origin;
}

void help(char **argv)
{
	fprintf(stderr, "%s [-R <socket directory>][-m <nb max clients>][-u <user>][-w][-h][-D]\n", basename(argv[0]));
	fprintf(stderr, "\t-R <dir>\tset the socket directory for the connection\n");
	fprintf(stderr, "\t-m <num>\tset the maximum number of clients\n");
	fprintf(stderr, "\t-u <name>\tset the user to run\n");
	fprintf(stderr, "\t-w \tstart chat with specific ouistiti features\n");
	fprintf(stderr, "\t-n <name> \tthe name of the stream\n");
}

static const char *str_hello = "{\"type\":\"hello\",\"data\":\"%2hd\"}";
const char *str_username = "apache";

#define OPTION_OUISTITI 0x01
#define OPTION_DAEMON 0x02

int multicast(buffer_t *buffer, int resume)
{
	int ret = -1;
	if (buffer->sourceaddress)
	{
		struct addrinfo *sourceaddress = buffer->sourceaddress;
		if ( sourceaddress->ai_family == PF_INET)
		{
#ifdef _GNU_SOURCE
			struct sockaddr_in *addr = ((struct sockaddr_in*)(sourceaddress->ai_addr));
			if (IN_MULTICAST(addr->sin_addr.s_addr))
			{
				struct ip_mreq imreq;
				memset(&imreq, 0, sizeof(struct ip_mreq));
				imreq.imr_multiaddr.s_addr = addr->sin_addr.s_addr;
				imreq.imr_interface.s_addr = INADDR_ANY; // use DEFAULT interface

				if (resume)
				{
					// JOIN multicast group on default interface
					ret = setsockopt(buffer->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
						(const void *)&imreq, sizeof(struct ip_mreq));
				}
				else
				{
					// JOIN multicast group on default interface
					ret = setsockopt(buffer->sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,
						(const void *)&imreq, sizeof(struct ip_mreq));
				}
			}
#endif
		}
		if ( sourceaddress->ai_family == PF_INET6)
		{
			struct sockaddr_in6 *addr = ((struct sockaddr_in6*)(sourceaddress->ai_addr));
			if (IN6_IS_ADDR_MULTICAST(addr->sin6_addr.s6_addr))
			{
				struct ipv6_mreq imreq;
				memset(&imreq, 0, sizeof(struct ipv6_mreq));
				//memcpy(imreq.ipv6mr_multiaddr.s6_addr, addr->sin6_addr.s6_addr, sizeof(imreq.ipv6mr_multiaddr.s6_addr));
				imreq.ipv6mr_multiaddr = addr->sin6_addr;
				imreq.ipv6mr_interface = 0;

				if (resume)
				{
					// JOIN multicast group on default interface
					ret = setsockopt(buffer->sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
						(const void *)&imreq, sizeof(struct ipv6_mreq));
				}
				else
				{
					// JOIN multicast group on default interface
					ret = setsockopt(buffer->sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
						(const void *)&imreq, sizeof(struct ipv6_mreq));
				}
			}
		}
	}

	return ret;
}

int udpsocket(const char *address, const char *port, struct addrinfo **sourceaddress)
{
	int ret;
	int sock;
	struct addrinfo hints;
	struct addrinfo *result, *rp;

	memset(&hints, 0, sizeof(struct addrinfo));
#ifdef IPV6
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
#else
	hints.ai_family = AF_INET;    /* Allow IPv4 or IPv6 */
#endif
	if (address && address[0] != '\0')
	{
		hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_NUMERICHOST;    /* For wildcard IP address */

		ret = getaddrinfo(address, NULL, &hints, sourceaddress);
		if (ret != 0)
		{
			err("getaddrinfo: %s\n", gai_strerror(ret));
			return -1;
		}

		hints.ai_family = (*sourceaddress)->ai_family;
	}
	hints.ai_socktype = SOCK_DGRAM; /* Stream socket */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */

	ret = getaddrinfo(NULL, port, &hints, &result);
	if (ret != 0) {
		err("getaddrinfo: %s\n", gai_strerror(ret));
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock == -1)
			continue;

		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&(int){ 1 }, sizeof(int)) < 0)
				warn("setsockopt(SO_REUSEADDR) failed");
#ifdef SO_REUSEPORT
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (void *)&(int){ 1 }, sizeof(int)) < 0)
				warn("setsockopt(SO_REUSEPORT) failed");
#endif

		if (bind(sock, rp->ai_addr, rp->ai_addrlen) == 0)
			break;                  /* Success */
		close(sock);
	}
	freeaddrinfo(result);

	if (ret < 0)
	{
		err("Error joining socket %s", strerror(errno));
		close(sock);
		sock = ret;
	}
	return sock;
}

int mainloop(buffer_t *buffer, int options)
{
	int ret = 0;
	int newsock = 0;
	do
	{
		fd_set rfds;
		int maxfd = buffer->sock;
		FD_ZERO(&rfds);
		FD_SET(buffer->sock, &rfds);

		struct timeval timeout;
		if (buffer->first != NULL)
			timeout.tv_sec = 1;
		else
			timeout.tv_sec = 3600;
		timeout.tv_usec = 0;

		ret = select(maxfd + 1, &rfds, NULL, NULL, &timeout);
		if (ret > 0 && FD_ISSET(buffer->sock, &rfds))
		{
			newsock = accept(buffer->sock, NULL, NULL);
			dbg("streamer: new client");
			if (newsock > 0)
			{
				if (options & OPTION_OUISTITI)
				{
					newsock = ouistiti_recvaddr(newsock, NULL, NULL);
				}
				stream_t *newstream = startstream(newsock, buffer);
				if (newstream)
				{
					newstream->next = buffer->first;
					buffer->first = newstream;
					multicast(buffer, 1);
				}
			}
			else
			{
				dbg("streamer: accept error %d %s", newsock, strerror(errno));
			}
		}
		else
		{
			dbg("streamer: error %d %s", ret, strerror(errno));
		}
		stream_t *previous = NULL;
		stream_t *stream = buffer->first;
		while (stream != 0)
		{
			ret = pthread_mutex_trylock(&stream->mutex);
			if (ret == 0)
			{
				pthread_join(stream->thread, NULL);
				pthread_mutex_unlock(&stream->mutex);
				if (stream == buffer->first)
					buffer->first = stream->next;
				else
					previous->next = stream->next;
				free(stream);
				stream = previous;
			}
			else
				previous = stream;
			stream = stream->next;
		}
		if (buffer->first == NULL)
		{
			multicast(buffer, 0);
		}
	} while(newsock > 0);
	return ret;
}

int main(int argc, char **argv)
{
	int ret = -1;
	int sock = -1;
	const char *root = "/var/run/ouistiti";
	const char *proto = basename(argv[0]);
	int maxclients = 50;
	const char *username = str_username;
	int options = 0;
	const char *address = NULL;
	const char *port;

	int opt;
	do
	{
		opt = getopt(argc, argv, "p:a:u:R:m:hon:D");
		switch (opt)
		{
			case 'R':
				root = optarg;
			break;
			case 'h':
				help(argv);
				return -1;
			break;
			case 'm':
				maxclients = atoi(optarg);
			break;
			case 'n':
				proto = optarg;
			break;
			case 'a':
				address = optarg;
			break;
			case 'p':
				port = optarg;
			break;
			case 'u':
				username = optarg;
			break;
			case 'o':
				options |= OPTION_OUISTITI;
			break;
			case 'D':
				options |= OPTION_DAEMON;
			break;
		}
	} while(opt != -1);

	if (access(root, R_OK|W_OK|X_OK))
	{
		if (mkdir(root, 0777))
		{
			err("access %s error %s", root, strerror(errno));
			return -1;
		}
		chmod(root, 0777);
	}

	if (getuid() == 0)
	{
		struct passwd *user = NULL;
		user = getpwnam(username);
		if (user != NULL)
		{
			if (setegid(user->pw_gid) < 0)
				warn("not enought rights to change group");
			if (seteuid(user->pw_uid) < 0)
				warn("not enought rights to change user");
		}
		else
			warn("user not found");
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock > 0)
	{
		struct sockaddr_un addr;
		memset(&addr, 0, sizeof(struct sockaddr_un));
		addr.sun_family = AF_UNIX;
		snprintf(addr.sun_path, sizeof(addr.sun_path) - 1, "%s/%s", root, proto);
		unlink(addr.sun_path);

		ret = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
		if (ret == 0)
		{
			chmod(addr.sun_path, 0777);
			ret = listen(sock, maxclients);
		}
		if ((options & OPTION_DAEMON) && (fork() != 0))
		{
			printf("udpgw: daemonize\n");
			sched_yield();
			return 0;
		}
		if (ret == 0)
		{
			buffer_t origin = {0};
			origin.sock = udpsocket(address, port, &origin.sourceaddress);

			buffer_t* buffer = startgernerator(&origin);

			if (buffer)
			{
				mainloop(buffer, options);
			}
		}
		unlink(addr.sun_path);
	}
	if (ret)
	{
		err("error : %s\n", strerror(errno));
	}
	return ret;
}
