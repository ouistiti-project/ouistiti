#ifndef __DEAMONIZE_H__
#define __DEAMONIZE_H__

int daemon_setlogfile(const char *logfile);
int daemon_setroot(const char *rootfs);
int daemon_setowner(const char *user, int fortify);
int daemonize(unsigned char onoff, const char *logfile, const char *pidfile, const char *owner, const char *rootfs);
void killdaemon(const char *pidfile);
unsigned char isrunning();

#endif
