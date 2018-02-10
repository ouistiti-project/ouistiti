/*****************************************************************************
 * stream.c: dummy stream
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

struct stream_s
{
	int sock;
	buffer_t *buffer;
};

struct buffer_s
{
	int ready;
	char *data;
	int size;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

void *runstream(void *arg)
{
	stream_t *stream = (stream_t *)arg;
	buffer_t *buffer = stream->buffer;
	int ret;
	int run = 1;

	warn("new stream %p %d", stream, stream->sock);
	while (run)
	{
		pthread_mutex_lock(&buffer->mutex);
		do
		{
			ret = pthread_cond_wait(&buffer->cond, &buffer->mutex);
		} while (!buffer->ready && ret < 0);
		pthread_mutex_unlock(&buffer->mutex);
		ret = send(stream->sock, buffer->data, buffer->size, MSG_NOSIGNAL);
		if (ret < 0 && errno != EAGAIN)
		{
			dbg("send error %d %s", ret, strerror(errno));
			run = 0;
		}
	}
	warn("end stream %p", stream);
	free(stream);
	return NULL;
}

int startstream(int sock, buffer_t *origin)
{
	pthread_t thread;
	pthread_attr_t attr;

	stream_t *stream = calloc(1, sizeof(*stream));

	stream->sock = sock;
	stream->buffer = origin;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	
	pthread_create(&thread, &attr, runstream, stream);
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
		memset(buffer->data, elem, buffer->size);
		buffer->ready = 1;
		pthread_cond_broadcast(&buffer->cond);
		nanosleep(&timeout, NULL);
		elem++;
//		pthread_mutex_lock(&buffer->mutex);
		buffer->ready = 0;
//		pthread_mutex_lock(&buffer->mutex);
	}
	free(buffer->data);
	return NULL;
}

int startgernerator(buffer_t *origin)
{
	pthread_t thread;
	pthread_attr_t attr;

	origin->size = CHUNKSIZE;
	origin->data = malloc(origin->size);

	pthread_cond_init(&origin->cond, NULL);
	pthread_mutex_init(&origin->mutex, NULL);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	
	pthread_create(&thread, &attr, rungenerator, origin);
}

void help(char **argv)
{
	fprintf(stderr, "%s [-R <socket directory>] [-m <nb max clients>] [-u <user>] [-w] [ -h]\n", argv[0]);
	fprintf(stderr, "\t-R <dir>\tset the socket directory for the connection\n");
	fprintf(stderr, "\t-m <num>\tset the maximum number of clients\n");
	fprintf(stderr, "\t-u <name>\tset the user to run\n");
	fprintf(stderr, "\t-w \tstart chat with specific ouistiti features\n");
	fprintf(stderr, "\t-n <name> \tthe name of the stream\n");
}

static const char *str_hello = "{\"type\":\"hello\",\"data\":\"%2hd\"}";
const char *str_username = "apache";

#define OPTION_OUISTITI 0x01

int main(int argc, char **argv)
{
	int ret = -1;
	int sock;
	char *root = "/var/run/ouistiti";
	char *proto = "stream";
	int maxclients = 50;
	const char *username = str_username;
	int options = 0;

	int opt;
	do
	{
		opt = getopt(argc, argv, "u:R:m:hon:");
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
			case 'u':
				username = optarg;
			break;
			case 'o':
				options |= OPTION_OUISTITI;
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
		setgid(user->pw_gid);
		setuid(user->pw_uid);
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
		if (ret == 0)
		{
			buffer_t origin;
			startgernerator(&origin);
			
			int newsock = 0;
			do
			{
				fd_set rfds;
				int maxfd = sock;
				FD_ZERO(&rfds);
				FD_SET(sock, &rfds);

				ret = select(maxfd + 1, &rfds, NULL, NULL, NULL);
				if (ret > 0 && FD_ISSET(sock, &rfds))
				{
					newsock = accept(sock, NULL, NULL);
					dbg("streamer: new client");
					if (newsock > 0)
					{
						if (options & OPTION_OUISTITI)
						{
							newsock = ouistiti_recvaddr(newsock, NULL, NULL);
						}
						startstream(newsock, &origin);
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
			} while(newsock > 0);
		}
		unlink(addr.sun_path);
	}
	if (ret)
	{
		err("error : %s\n", strerror(errno));
	}
	return ret;
}
