#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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

#define DEBUG
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
	REQUEST_END=0x02,
	RESPONSE_START=0x10,
	RESPONSE_END=0x20,
};

int main(int argc, char **argv)
{
	int port = 80;
	char *serveraddr = "127.0.0.1";
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
		return -1;
	}

	int flags;

	int state = CONNECTION_START;
	int length;
	int ret = 0;
	do
	{
		char buffer[249];
		while ((state & REQUEST_END) == 0)
		{
			length = 248;
			length = read(0, buffer, length);
			if (length > 0)
			{
				buffer[length] = 0;
				//first read is blocking
				flags = fcntl(0, F_GETFL, 0);
				fcntl(0, F_SETFL, flags | O_NONBLOCK);

				state |= REQUEST_START;
				int ret;
				ret = send(sock, buffer, length, MSG_NOSIGNAL);
				if (ret != length)
				{
					err("send error");
					state |= RESPONSE_END;
					ret = -1;
				}
			}
			else if (state > CONNECTION_START && !(state & REQUEST_END))
			{
				if (errno != EAGAIN)
					err("request clomplete %s", strerror(errno));
				state |= REQUEST_END;
			}
			if (state & REQUEST_START)
				break;
		}
		flags = fcntl(sock, F_GETFL, 0);
		fcntl(sock, F_SETFL, flags | O_NONBLOCK);

		length = 248;
		length = recv(sock, buffer, length, MSG_NOSIGNAL);
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
		else if ((state & REQUEST_END) && (state & RESPONSE_START))
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
				state |= RESPONSE_END;
		}
	} while (!(state & RESPONSE_END));
	close(sock);
	return ret;
}
