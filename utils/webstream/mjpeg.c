#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <pwd.h>
#include <pthread.h>
#include <libgen.h>
#include <errno.h>
#include <sched.h>

#include <linux/videodev2.h>

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
# define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
# define dbg(...)
#endif

#ifndef BIT
#define BIT(x) (0x1L<<x)
#endif

#ifndef V4L2_FOURCC_CONV
#define V4L2_FOURCC_CONV "%c%c%c%c%s"
#define V4L2_FOURCC_CONV_ARGS(fourcc) \
	(fourcc) & 0x7f, ((fourcc) >> 8) & 0x7f, ((fourcc) >> 16) & 0x7f, \
	((fourcc) >> 24) & 0x7f, (fourcc) & BIT(31) ? "-BE" : ""
#endif

#define MAX_BUFFERS 4
#define DEFAULT_INPUT "/dev/video0"
#define DEFAULT_OUTPUT "camera.mjpeg"

extern int ouistiti_recvaddr(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

static struct {
	uint32_t fourcc;
} formats[] =
{
	{
		.fourcc = V4L2_PIX_FMT_H264,
	},{
		.fourcc = V4L2_PIX_FMT_MJPEG,
	},{
		.fourcc = V4L2_PIX_FMT_JPEG,
	},{
		.fourcc = V4L2_PIX_FMT_YUYV,
	},{
		.fourcc = 0,
	}
};

struct Buffer_s
{
	unsigned char *input;
	size_t length;
	int state;
};
typedef struct Buffer_s Buffer_t;

static int xioctl(int fh, int request, void *arg)
{
	int ret;

	do
	{
		ret = ioctl(fh, request, arg);
	} while (ret == -1 && EINTR == errno);

	return ret;
}

ssize_t (*_write)(int fd, const void *buf, size_t count) = write;

ssize_t _send(int fd, const void *buf, size_t count)
{
	return send(fd, buf, count, MSG_DONTWAIT);
}

static int _save_frame(int ofd, unsigned char *buffer, size_t length)
{
	int ret = 0;
	size_t rest = 0;
	do
	{
		ret = write(ofd, buffer + rest, length - rest);
		if (ret > 0)
		{
			warn("send %d/%ld", ret, length - rest);
			rest += ret;
		}
		else
		{
			warn("write error %s", strerror(errno));
			break;
		}
		if (rest < length)
			warn("message too big");
	} while (rest < length);
	send(ofd, NULL, 0, MSG_DONTWAIT);
	sched_yield();
	return ret;
}

static int _camera_negociate(int fd, int defaultid, int width, int height)
{
	struct v4l2_format fmt;
	fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	xioctl(fd, VIDIOC_G_FMT, &fmt);

	struct v4l2_fmtdesc fmtdesc = {0};
	fmtdesc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	warn("Formats:");
	while (xioctl(fd,VIDIOC_ENUM_FMT,&fmtdesc) == 0)
	{
		warn("\t"V4L2_FOURCC_CONV" => %s", V4L2_FOURCC_CONV_ARGS(fmtdesc.pixelformat), fmtdesc.description);
		fmtdesc.index++;
		if (defaultid > -1 && formats[defaultid].fourcc == fmtdesc.pixelformat)
		{
			fmt.fmt.pix.pixelformat = fmtdesc.pixelformat;
			warn("default format found");
			goto NEGOCIATION_FOUND;
		}
	}
	int i = 0;
	for (i = 0; formats[i].fourcc != 0; i++)
	{
		fmtdesc.index = 0;
		while (xioctl(fd,VIDIOC_ENUM_FMT,&fmtdesc) == 0)
		{
			if (formats[i].fourcc == fmtdesc.pixelformat)
			{
				fmt.fmt.pix.pixelformat = fmtdesc.pixelformat;
				goto NEGOCIATION_FOUND;
			}
			fmtdesc.index++;
		}
	}
NEGOCIATION_FOUND:
	if (width > 0)
	{
		fmt.fmt.pix.width = width;
		fmt.fmt.pix.height = height;
	}
	if (xioctl(fd, VIDIOC_S_FMT, &fmt) != 0)
		return -1;
	
	return 0;
}

static Buffer_t * _camera_setup(int fd, int *nbuffers)
{
	struct v4l2_format fmt = {0};
	fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	xioctl(fd, VIDIOC_G_FMT, &fmt);

	struct v4l2_streamparm parm = {0};
	parm.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	xioctl(fd, VIDIOC_G_PARM, &parm);

	warn("Image %u, %u %2.2ffps "V4L2_FOURCC_CONV"",
			fmt.fmt.pix.width,
			fmt.fmt.pix.height,
			(float)parm.parm.capture.timeperframe.denominator / (float)parm.parm.capture.timeperframe.numerator,
			V4L2_FOURCC_CONV_ARGS(fmt.fmt.pix.pixelformat));

	struct v4l2_requestbuffers req = {0};
	req.count = MAX_BUFFERS;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	req.memory = V4L2_MEMORY_MMAP;
	if (xioctl(fd, VIDIOC_REQBUFS, &req) != 0)
	{
		err("buffer request error: %s", strerror(errno));
		return NULL;
	}
	
	Buffer_t *buffers = calloc(req.count, sizeof(*buffers));
	*nbuffers = req.count;
	for (int i = 0; i < *nbuffers; i++)
	{
		struct v4l2_buffer buf = {0};
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.index = i;
		if (xioctl(fd, VIDIOC_QUERYBUF, &buf) != 0)
		{
			err("buffer[%d] query error %s", i, strerror(errno));
			free(buffers);
			return NULL;
		}

		buffers[i].length = buf.length;
		buffers[i].input = mmap(NULL, buf.length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, buf.m.offset);
		if (xioctl(fd, VIDIOC_QBUF, &buf) != 0)
		{
			err("buffer[%d] queued error %s", i, strerror(errno));
			free(buffers);
			return NULL;
		}
	}
	return buffers;
}

typedef struct Camera_s
{
	const char *device;
	int defaultid;
	int ofd;
	struct
	{
		int width;
		int height;
	} resizing;
} Camera_t;

static int _camera_run(Camera_t *camera, int fd, Buffer_t *buffers)
{
	int run = 1;
	enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	warn("start");
	if (xioctl(fd, VIDIOC_STREAMON, &type) != 0)
		err("camera start error %s", strerror(errno));
	while (run)
	{
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		struct timeval timeout = {
			.tv_sec = 2,
			.tv_usec = 0,
		};
		int ret;
		ret = select(fd + 1, &rfds, NULL, NULL, &timeout);
		if (ret == -1 && errno == EINTR)
			continue;
		if (ret == 1)
		{
			struct v4l2_buffer buf;
			buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
			buf.memory = V4L2_MEMORY_MMAP;
			buf.index = 0;
			if (xioctl(fd, VIDIOC_DQBUF, &buf) != 0)
			{
				run = 0;
				warn("VIDIOC_DQBUF error on %d", buf.index);
			}
			else if (camera->ofd > 0)
			{
				ret = _save_frame(camera->ofd, buffers[buf.index].input, buf.bytesused);
				if (ret <= 0)
				{
					close(camera->ofd);
					camera->ofd = -1;
				}
			}
			if (xioctl(fd, VIDIOC_QBUF, &buf) != 0)
			{
				run = 0;
				warn("VIDIOC_QBUF error");
			}
		}
		else
			warn("error %d", ret);
		if (ret == 0)
			run = 0;
	}
	warn("stop");
	xioctl(fd, VIDIOC_STREAMOFF, &type);
	return 0;
}

static void *_camera_thread(void *arg)
{
	Camera_t *camera = arg;
	const char *device = camera->device;
	int defaultid = camera->defaultid;

	struct stat st;
	stat(device, &st);
	if (!S_ISCHR(st.st_mode))
		return (void *)-1;

	int fd = open(device, O_RDWR | O_NONBLOCK, 0);
	if (fd == -1)
	{
		err("device %s not found", device);
		return (void *)-1;
	}

	struct v4l2_capability cap;
	if ((xioctl(fd, VIDIOC_QUERYCAP, &cap) != 0) ||
		!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE))
	{
		err("device %s not capture", device);
		close(fd);
		return (void *)-1;
	}
	if (!(cap.capabilities & V4L2_CAP_STREAMING))
	{
		err("device %s not camera", device);
		close(fd);
		return (void *)-1;
	}

	if (_camera_negociate(fd, defaultid, camera->resizing.width, camera->resizing.height))
		return (void *)-1;
	int nbuffers = 0;
	Buffer_t *buffers = NULL;
	buffers = _camera_setup(fd, &nbuffers);
	if (buffers == NULL)
		return (void *)-1;

	_camera_run(camera, fd, buffers);
	close(fd);
	return NULL;
}

static void *runstream(void *arg)
{
	return NULL;
}

static int startstream(void *(*thread_run)(void *arg), Camera_t *camera, pthread_t *thread)
{
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	pthread_create(thread, &attr, thread_run, camera);
	return 0;
}

#define MODE_UNIX 0x01
#define MODE_OUISTITI 0x02
#define MODE_DAEMON 0x04
#define MODE_STREAM 0x08

void help(char **argv)
{
	fprintf(stderr, "%s [-R <socket directory>][-m <nb max clients>][-u <user>][-w][-h][-D]\n", basename(argv[0]));
	fprintf(stderr, "\t-R <dir>\tset the socket directory for the connection (default: /var/run/webstream)\n");
	fprintf(stderr, "\t-n <name>\tset the output socket name (default: %s)\n", DEFAULT_OUTPUT);
	fprintf(stderr, "\t-m <num>\tset the maximum number of clients (default: 50)\n");
	fprintf(stderr, "\t-u <name>\tset the user to run (default: current)\n");
	fprintf(stderr, "\t-U \topen a Unix SEQPACKET socket to send images\n");
	fprintf(stderr, "\t-S \topen a Unix STREAM socket to send images\n");
	fprintf(stderr, "\t-D \tdaemonize the server\n");
	fprintf(stderr, "\t-w \tstart streamer with specific ouistiti features\n");
	fprintf(stderr, "\t-d <device> \tset the path to the video device (default: %s)\n", DEFAULT_INPUT);
}

int main(int argc, char *argv[])
{
	Camera_t camera = {0};
	camera.device = DEFAULT_INPUT ;
	camera.defaultid = -1;
	camera.ofd = -1;
	const char *output = DEFAULT_OUTPUT;
	const char *root = "/var/run/webstream";
	int maxclients = 50;
	const char *username = NULL;
	int mode = 0;

	int opt;
	do
	{
		opt = getopt(argc, argv, "hd:R:mn:u:f:UODS");
		switch (opt)
		{
			case 'h':
				help(argv);
				return -1;
			break;
			case 'd':
				camera.device = optarg;
			break;
			case 'R':
				root = optarg;
			break;
			case 'm':
				maxclients = atoi(optarg);
			break;
			case 'n':
				output = optarg;
			break;
			case 'u':
				username = optarg;
			break;
			case 'f':
				if (!strcmp(optarg, "small"))
				{
					camera.resizing.width = 640;
					camera.resizing.height = 360;
				}
				if (!strcmp(optarg, "medium"))
				{
					camera.resizing.width = 800;
					camera.resizing.height = 480;
				}
				if (!strcmp(optarg, "large"))
				{
					camera.resizing.width = 1280;
					camera.resizing.height = 720;
				}
			break;
			case 'U':
				mode |= MODE_UNIX;
				_write = _send;
			break;
			case 'O':
				mode |= MODE_OUISTITI;
			break;
			case 'D':
				mode |= MODE_DAEMON;
			break;
			case 'S':
				mode |= MODE_STREAM;
				mode |= MODE_UNIX;
				_write = _send;
			break;
			default:
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

	const char *ext = strrchr(output, '.');
	if (ext != NULL)
	{
		if (!strcmp(ext, ".h264"))
		{
			camera.defaultid = 0;
			mode |= MODE_STREAM;
		}
		if (!strcmp(ext, ".jpg") || !strcmp(ext, ".jpeg"))
			camera.defaultid = 2;
		if (!strcmp(ext, ".mjpg") || !strcmp(ext, ".mjpeg"))
			camera.defaultid = 1;
	}

	pthread_t camera_thread;
	startstream(_camera_thread, &camera, &camera_thread);

	int ofd = -1;
	if (output != NULL)
	{
		if (mode & MODE_UNIX)
		{
			signal(SIGPIPE, SIG_IGN);
			unlink(output);
			int sock = -1;
			if (mode & MODE_STREAM)
				sock = socket(AF_UNIX, SOCK_STREAM, 0);
			else
				sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);

			if (sock == -1)
			{
				return -1;
			}

			struct sockaddr_un addr;
			memset(&addr, 0, sizeof(addr));
			addr.sun_family = AF_UNIX;
			snprintf(addr.sun_path, sizeof(addr.sun_path) - 1, "%s/%s", root, output);
			unlink(addr.sun_path);

			if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) != 0)
				return -1;

			chmod(addr.sun_path, 0666);
			listen(sock, 1);

SOCKET_RESTART:
			warn("wait connection");
			ofd = accept(sock, NULL, NULL);
			if (mode & MODE_OUISTITI)
			{
				ofd = ouistiti_recvaddr(ofd, NULL, NULL);
			}
			warn("new connection");
		}
		else
		{
			ofd = open(output, O_RDWR | O_CREAT, 0666);
			warn("createfile");
		}
	}
	if (ofd != -1)
	{
		if (camera.ofd > 0)
			close(camera.ofd);
		camera.ofd = ofd;
	}
	else
		err("Output avorted");

	if (mode & MODE_UNIX)
		goto SOCKET_RESTART;
	pthread_join(camera_thread, NULL);
	close(camera.ofd);
	return 0;
}
