/*****************************************************************************
 * main.c
 * this file is part of https://github.com/ouistiti-project/putv
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
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

static int _pidfd = -1;
static void _setpidfile(const char *pidfile)
{
	if (pidfile[0] != '\0')
	{
		_pidfd = open(pidfile,O_WRONLY|O_CREAT|O_TRUNC,0644);
		if (_pidfd > 0)
		{
			char buffer[12];
			int length;
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
			close pidfd ;
			 */
		}
		else
		{
			err("pid file error %s", strerror(errno));
			pidfile = NULL;
			exit(0);
		}
	}
}

int daemonize(const char *pidfile)
{
	pid_t pid;
	if ( getppid() == 1 )
	{
		return -1;
	}
	if ((pid = fork()) > 0)
	{
		dbg("start daemon on pid %d", pid);
		return -1;
	}
	int sid = setsid();
	dbg("start daemon sid %d", sid);

	if (pidfile != NULL)
	{
		_setpidfile(pidfile);
	}
	return 0;
}

void killdaemon(const char *pidfile)
{
	if (_pidfd > 0)
	{
		close(_pidfd);
	}
	else if (pidfile != NULL)
	{
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
			if (fcntl(_pidfd, F_GETLK, &fl) == -1) {
				err("server not running");
				exit(1);
			}
			kill(fl.l_pid, SIGTERM);
			close(_pidfd);
		}
	}
	if (pidfile && !access(pidfile, W_OK))
		unlink(pidfile);
}
