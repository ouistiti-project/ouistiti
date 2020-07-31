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
#include <libgen.h>

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

#define CHUNKSIZE 4500

#define OPTION_OUISTITI 0x01
#define OPTION_TEST 0x02
#define OPTION_DAEMON 0x04

typedef int (*server_t)(int sock);

typedef struct stream_s stream_t;
typedef struct buffer_s buffer_t;

extern int ouistiti_recvaddr(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

struct stream_s
{
	int sock;
	buffer_t *buffer;
	int options;
};

struct buffer_s
{
	int ready;
	char *data;
	int size;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int options;
};

void *runstream(void *arg)
{
	stream_t *stream = (stream_t *)arg;
	buffer_t *buffer = stream->buffer;
	int ret;
	int run = 10;

	warn("new stream %p %d", stream, stream->sock);
	while (run > 0)
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
			err("send error %d %s", ret, strerror(errno));
			run = 0;
		}
		else
		{
			dbg("send %d", ret);
		}
		if (stream->options & OPTION_TEST)
		{
			usleep(5000);
			run--;
		}
	}
	if (stream->options & OPTION_TEST)
	{
		pthread_mutex_lock(&buffer->mutex);
		buffer->ready = 2;
		pthread_mutex_unlock(&buffer->mutex);
	}

	warn("end stream %p", stream);
	free(stream);
	shutdown(stream->sock, SHUT_RDWR);
	close(stream->sock);
	return NULL;
}

int startstream(int sock, buffer_t *origin, int options, pthread_t *thread)
{
	pthread_attr_t attr;

	stream_t *stream = calloc(1, sizeof(*stream));

	stream->sock = sock;
	stream->buffer = origin;
	stream->options = options;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	pthread_create(thread, &attr, runstream, stream);
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
		memset(buffer->data, elem + 0x30, buffer->size);
		pthread_mutex_lock(&buffer->mutex);
		buffer->ready = 1;
		pthread_mutex_unlock(&buffer->mutex);
		pthread_cond_broadcast(&buffer->cond);
		nanosleep(&timeout, NULL);
		if (!(buffer->options & OPTION_TEST))
		{
			elem++;
			elem %= 10;
		}
		pthread_mutex_lock(&buffer->mutex);
		if (buffer->ready == 2)
			run = 0;
		else
			buffer->ready = 0;
		pthread_mutex_unlock(&buffer->mutex);
	}
	free(buffer->data);
	warn("generator end");
	return NULL;
}

void startgernerator(buffer_t *origin, pthread_t *thread)
{
	pthread_attr_t attr;

	origin->data = malloc(origin->size);

	pthread_cond_init(&origin->cond, NULL);
	pthread_mutex_init(&origin->mutex, NULL);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	pthread_create(thread, &attr, rungenerator, origin);
}

void help(char **argv)
{
	fprintf(stderr, "%s [-R <socket directory>][-m <nb max clients>][-u <user>][-w][-h][-D]\n", basename(argv[0]));
	fprintf(stderr, "\t-R <dir>\tset the socket directory for the connection (default: /var/run/webstream)\n");
	fprintf(stderr, "\t-n <name>\tset the protocol (default: %s)\n", basename(argv[0]));
	fprintf(stderr, "\t-m <num>\tset the maximum number of clients (default: 50)\n");
	fprintf(stderr, "\t-u <name>\tset the user to run (default: current)\n");
	fprintf(stderr, "\t-D \tdaemonize the server\n");
	fprintf(stderr, "\t-w \tstart streamer with specific ouistiti features\n");
	fprintf(stderr, "\t-t \ttest mode\n");
}

static const char *str_hello = "{\"type\":\"hello\",\"data\":\"%2hd\"}";

int main(int argc, char **argv)
{
	int ret = -1;
	int sock;
	char *root = "/var/run/webstream";
	char *proto = basename(argv[0]);
	int maxclients = 50;
	const char *username = NULL;
	int options = 0;
	pthread_t thread;
	pthread_t streamthread;
	int chunksize = CHUNKSIZE;
	int opt;

	do
	{
		opt = getopt(argc, argv, "u:R:m:hon:ts:D");
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
			case 's':
				chunksize = atoi(optarg);
			break;
			case 'o':
				options |= OPTION_OUISTITI;
			break;
			case 't':
				options |= OPTION_TEST;
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

	if (getuid() == 0 && username != NULL)
	{
		int ret = 0;
		struct passwd *user = NULL;
		user = getpwnam(username);
		ret = setgid(user->pw_gid);
		ret = setuid(user->pw_uid);
		if (ret == -1)
			err("change owner to launch");
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
			printf("jsonrpc: daemonize\n");
			sched_yield();
			return 0;
		}
		if (ret == 0)
		{
			buffer_t origin;
			origin.size = chunksize;
			origin.options = options;
			startgernerator(&origin, &thread);

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
						startstream(newsock, &origin, options, &streamthread);
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
			} while(newsock > 0 && !(options & OPTION_TEST));
		}
		pthread_join(thread, NULL);
		pthread_join(streamthread, NULL);
		unlink(addr.sun_path);
	}
	return ret;
}
