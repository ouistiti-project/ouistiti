#ifndef __DEAMONIZE_H__
#define __DEAMONIZE_H__

int daemonize(const char *pidfile);
void killdaemon(const char *pidfile);

#endif
