/*****************************************************************************
 * mod_tinysvcmdns.c: webstream server module
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
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <wait.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include <mdns.h>
#include <mdnsd.h>

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "mod_tinysvcmdns.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

typedef struct _mod_tinysvcmdns_s _mod_tinysvcmdns_t;

typedef int (*socket_t)(mod_tinysvcmdns_t *config, char *filepath);

struct _mod_tinysvcmdns_s
{
	const char *hostname;
	char *type;
	int svrn;
	struct mdnsd *svr[3];
	struct mdns_service *svc[3];
};

static const char str_tinysvcmdns[] = "tinysvcmdns";

void *mod_tinysvcmdns_create(http_server_t *server, mod_tinysvcmdns_t *config)
{
	const char *hostname = httpserver_INFO(server, "host");
	if (hostname == NULL || hostname[0] == '\0' || strstr(hostname, ".local") == NULL)
		return NULL;

	_mod_tinysvcmdns_t *mod = calloc(1, sizeof(*mod));
	mod->hostname = hostname;

	int port = atoi(httpserver_INFO(server, "port"));
	const char *scheme = httpserver_INFO(server, "scheme");
	if (scheme == NULL || scheme[0] == '\0')
		scheme = "http";
	const char *typeformat = "_%s._tcp.local";
	int length = strlen(typeformat) - 2 + strlen(scheme);
	mod->type = calloc(1, length + 1);
	snprintf(mod->type, length + 1, typeformat, scheme);

	const char *txt[] =
		{httpserver_INFO(server, "service"), NULL};

	struct ifaddrs *ifa_list;
	struct ifaddrs *ifa_main;

	if (getifaddrs(&ifa_list) < 0) {
		warn("%s: getifaddrs() failed", str_tinysvcmdns);
		free(mod->type);
		free(mod);
		return NULL;
	}

	int j = 0;
	for (ifa_main = ifa_list; ifa_main != NULL && j < 3; ifa_main = ifa_main->ifa_next)
	{
		if ((ifa_main->ifa_flags & IFF_LOOPBACK) || !(ifa_main->ifa_flags & IFF_MULTICAST))
			continue;
		if (ifa_main->ifa_addr && ifa_main->ifa_addr->sa_family == AF_INET)
		{
			if (mod->svr[j] == NULL)
			{
				mod->svr[j] = mdnsd_start(((struct sockaddr_in *)ifa_main->ifa_addr)->sin_addr);
			}
			if (mod->svr[j] == NULL) {
				err("%s: start error %s\n", str_tinysvcmdns, strerror(errno));
				continue;
			}

			mdnsd_set_hostname(mod->svr[j], mod->hostname, ((struct sockaddr_in *)ifa_main->ifa_addr)->sin_addr); // TTL should be 120 seconds

			mod->svc[j] = mdnsd_register_svc(mod->svr[j], mod->hostname, mod->type, port, NULL, txt);
			dbg("%s: register %s:%d on mDNS", str_tinysvcmdns, mod->hostname, port);
			j++;
		}
#ifdef IPV6
		else if (ifa_main->ifa_addr && ifa_main->ifa_addr->sa_family == AF_INET6)
		{
		}
#endif
	}

	if (j == 0)
	{
		err("%s: ipv4 or ipv6 interface different of loopback not found", str_tinysvcmdns);
		free(mod->type);
		free(mod);
		return NULL;
	}

	mod->svrn = j;

	return mod;
}

void mod_tinysvcmdns_destroy(void *data)
{
	_mod_tinysvcmdns_t *mod = (_mod_tinysvcmdns_t *)data;
	int j = 0;
	for (j = 0; j < mod->svrn; j++)
	{
		//mdnsd_stop(mod->svr[j]);
		mdns_service_destroy(mod->svc[j]);
	}
	free(mod->type);
	free(data);
}

const module_t mod_tinysvcmdns =
{
	.name = str_tinysvcmdns,
	.create = (module_create_t)&mod_tinysvcmdns_create,
	.destroy = &mod_tinysvcmdns_destroy
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_tinysvcmdns")));
#endif
