/*****************************************************************************
 * deamonize.c
 * this file is part of https://github.com/mchalain
 *****************************************************************************
 * Copyright (C) 2016-2024
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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#ifdef BACKTRACE
#include <execinfo.h> // for backtrace
#endif
#include <pwd.h>
#include <grp.h>
#if _POSIX_C_SOURCE >= 199309L
# define HAVE_SIGACTION
#endif

#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <linux/securebits.h>

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
# define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
# define dbg(...)
#endif


#ifndef LOG_MAXFILESIZE
#define LOG_MAXFILESIZE -1
#endif

#if LOG_MAXFILESIZE != -1
static const char *g_logfile = NULL;
static size_t g_logmax = LOG_MAXFILESIZE;
#endif

int daemon_setlogfile(const char *logfile)
{
	int logfd = -1;

	if (strcmp(logfile,"-"))
	{
#if LOG_MAXFILESIZE != -1
		unsigned long logmax = 0;
		const char *logmaxenv = getenv("LOG_MAXFILESIZE");
		if (logmaxenv)
			logmax = strtoul(logmaxenv, NULL, 10);
		if (logmax)
			g_logmax = logmax;
		g_logfile = logfile;
#endif
		logfd = open(logfile, O_WRONLY | O_CREAT | O_TRUNC, 00644);
		if (logfd >= 0)
		{
			/// flush the disk after each \n, keep the order or each log traces
			setvbuf(stdout, NULL, _IOLBF, 0);
			setvbuf(stderr, NULL, _IOLBF, 0);
			dup2(logfd, 1);
			dup2(logfd, 2);
			close(logfd);
		}
		else
		{
			err("log file error %m");
		}
	}
	return (logfd == -1);
}

static char _run = 0;
#ifdef HAVE_SIGACTION
static void _handler(int sig, siginfo_t *UNUSED(si), void *UNUSED(arg))
#else
static void _handler(int sig)
#endif
{
	err("main: signal %d", sig);
	if (sig == SIGSEGV)
	{
#ifdef BACKTRACE
		void *array[10];
		size_t size;

		// get void*'s for all entries on the stack
		size = backtrace(array, 10);

		// print out all the frames to stderr
		backtrace_symbols_fd(array, size, STDERR_FILENO);
#endif
#ifdef DEBUG
		err("main: pausing");
		pause();
#else
		exit(1);
#endif
	}
	_run = 'k';
}

unsigned char isrunning()
{
#if LOG_MAXFILESIZE != -1
	struct stat logstat = {0};
	if (g_logfile && !stat(g_logfile, &logstat) && (logstat.st_size > g_logmax))
	{
		daemon_setlogfile(g_logfile);
		warn("main: reset logfile");
	}
#endif
	return _run == 'r';
}

static int _pidfd = -1;
static int _setpidfile(const char *pidfile)
{
	if (pidfile[0] != '\0')
	{
		_pidfd = open(pidfile,O_WRONLY|O_CREAT|O_TRUNC,0644);
		if (_pidfd > 0)
		{
			char buffer[12];
			ssize_t length;
			pid_t pid = 1;

			struct flock fl;
			memset(&fl, 0, sizeof(fl));
			fl.l_type = F_WRLCK;
			fl.l_whence = SEEK_SET;
			fl.l_start = 0;
			fl.l_len = 0;
			fl.l_pid = 0;
			if (fcntl(_pidfd, F_SETLK, &fl) == -1) {
				err("server already running");
				close(_pidfd);
				exit(1);
			}

			pid = getpid();
			length = snprintf(buffer, 12, "%.10d\n", pid);
			ssize_t len = write(_pidfd, buffer, length);
			if (len != length)
				err("pid file error %s", strerror(errno));
			fsync(_pidfd);
			/**
			 * the file must be open while the process is running
			close pidfd
			 */
		}
		else
		{
			err("pid file error %s", strerror(errno));
			pidfile = NULL;
			return -1;
		}
	}
	return 0;
}

static int _capset(uint64_t keep_mask)
{
	struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct data[2] = {{0,0,0},{0,0,0}};

	data[0].permitted   = (uint32_t)(keep_mask & 0xffffffff);
	data[0].effective   = data[0].permitted;
	data[1].permitted   = (uint32_t)(keep_mask >> 32);
	data[1].effective   = data[1].permitted;

	return syscall(SYS_capset, &hdr, data);
}

static void _dropcapabilities(void)
{
	uint64_t keep_mask = (1ULL << CAP_SETUID) | (1ULL << CAP_SETGID);
	int last_cap = 40;
	FILE *f = fopen("/proc/sys/kernel/cap_last_cap", "r");
	if (f)
	{
		fscanf(f, "%d", &last_cap);
		fclose(f);
	}

	for (int cap = 0; cap <= last_cap; cap++)
	{
		/// To keep SETUID and SETGID permit to change the owner of a process
		/// But it is dangerous for a code injection
		if (keep_mask & (1ULL << cap))
			continue;
		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) == -1 && errno != EINVAL)
			warn("capability %d not dropped: %m", cap);
	}

	if (_capset(keep_mask) == -1)
		warn("capset failed: %m");
}

/**
 * @brief change the effective uid of the calling thread only
 *
 * The POSIX "seteuid" affects all threads and glibc generate a signal
 * to propagate the change.
 * The linux System Call "seteuid" affects only the calling thread.
 */
static int _deamonize_seteuid(uid_t euid)
{
	return syscall(SYS_setresuid, -1, euid, -1);
}

int daemonize_supercall(int (*func)(void *), void * func_arg)
{
	uid_t uid = geteuid();
	if (_deamonize_seteuid(0))
	{
		return -1;
	}
	int ret = func(func_arg);
	_deamonize_seteuid(uid);
	return ret;
}

int daemon_setowner(const char *user, int fortify)
{
	if (user == NULL)
		return 0;
	int ret = -1;
	if (getuid() == 0)
		_dropcapabilities();
	struct passwd *pw;
	pw = getpwnam(user);
	if (pw != NULL)
	{
		if (initgroups(user, pw->pw_gid) < 0)
			warn("not enought rights to change user");
		else if (setegid(pw->pw_gid) < 0)
			warn("not enought rights to change group");
		else if (seteuid(pw->pw_uid) < 0)
			warn("not enought rights to change user");
		else
			ret = 0;
		if (!ret && fortify)
		{
			setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid);
			setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid);
		}
		if (!ret)
			warn("process owner changed to %s", user);
	}
	return ret;
}

int daemon_setroot(const char *rootfs)
{
	if (chroot(rootfs) == 0)
	{
		chdir("/");
		warn("daemon runs inside a sandbox");
	}
	else if (chdir(rootfs) != 0)
	{
		err("%s directory not accessible", rootfs);
		return -1;
	}
	dbg("current directory %s", get_current_dir_name());
	return 0;
}

int daemonize(unsigned char onoff, const char *logfile, const char *pidfile, const char *owner, const char *rootfs)
{
	pid_t pid = -1;
	pid_t sid = -1;
	if ( getppid() == 1 )
	{
		return -1;
	}
	if (onoff && (pid = fork()) == (pid_t)-1)
	{
		err("process may not be daemonized");
		return -1;
	}
	if (pid > 0)
	{
		dbg("start daemon on pid %d", pid);
		exit(0);
	}

	if (pid == 0 && (sid = setsid()) == (pid_t)-1)
	{
		err("process may not be owner group");
		return -1;
	}

	int nullfd = open("/dev/null", O_RDONLY, 00644);
	if (nullfd > 0)
		dup2(nullfd, 0);
	if (nullfd > 0)	
		close(nullfd);

	if (logfile != NULL && daemon_setlogfile(logfile))
		return -1;

	if (pidfile != NULL && _setpidfile(pidfile))
		return -1;

	if (rootfs != NULL && daemon_setroot(rootfs))
		return -1;

	if (owner != NULL && daemon_setowner(owner, 1))
		return -1;

#ifdef HAVE_SIGACTION
	struct sigaction action;
	action.sa_flags = SA_SIGINFO;
	sigemptyset(&action.sa_mask);
	action.sa_sigaction = _handler;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);
# ifdef BACKTRACE
	sigaction(SIGSEGV, &action, NULL);
# endif
#else
	signal(SIGTERM, handler);
	signal(SIGINT, handler);
# ifdef BACKTRACE
	signal(SIGSEGV, handler);
# endif
#endif
	_run = 'r';

	return 0;
}

void killdaemon(const char *pidfile)
{
	if (_pidfd > 0)
	{
		close(_pidfd);
		_pidfd = -1;
		_run = 's';
	}
	else if (pidfile != NULL)
	{
		_run = 's';
		_pidfd = open(pidfile,O_RDWR);
		if (_pidfd > 0)
		{
			struct flock fl;
			memset(&fl, 0, sizeof(fl));
			fl.l_type = F_WRLCK;
			fl.l_whence = SEEK_SET;
			fl.l_start = 0;
			fl.l_len = 0;
			fl.l_pid = 0;
			if (fcntl(_pidfd, F_GETLK, &fl) == -1)
				err("lock error %s", strerror(errno));
			else if (fl.l_type == F_UNLCK)
				err("server not running");
			else if (getpid() != fl.l_pid)
				kill(fl.l_pid, SIGTERM);
			close(_pidfd);
		}
	}
	if (pidfile && !access(pidfile, W_OK))
		unlink(pidfile);
}
