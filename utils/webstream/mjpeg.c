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

static int _save_frame(int ofd, unsigned char *buffer, size_t length)
{
	int ret = 0;
	size_t rest = 0;
	do
	{
		ret = write(ofd, buffer + rest, length - rest);
		if (ret > 0)
			rest += ret;
		else
		{
			warn("write error %d",ret);
			break;
		}
	} while (rest < length);
	return ret;
}

static int _camera_negociate(int fd, int defaultid)
{
	struct v4l2_format fmt;
	fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	xioctl(fd, VIDIOC_G_FMT, &fmt);

	struct v4l2_fmtdesc fmtdesc = {0};
	fmtdesc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	warn("Formats:");
	if (defaultid >= 0)
	{
		while (xioctl(fd,VIDIOC_ENUM_FMT,&fmtdesc) == 0)
		{
			fmtdesc.index++;
			if (formats[defaultid].fourcc == fmtdesc.pixelformat)
			{
				fmt.fmt.pix.pixelformat = fmtdesc.pixelformat;
				warn("default format found");
				goto NEGOCIATION_FOUND;
			}
		}
	}
	int i = 0;
	for (i = 0; formats[i].fourcc != 0; i++)
	{
		fmtdesc.index = 0;
		while (xioctl(fd,VIDIOC_ENUM_FMT,&fmtdesc) == 0)
		{
			if (i == 0)
				warn("\t"V4L2_FOURCC_CONV" => %s", V4L2_FOURCC_CONV_ARGS(fmtdesc.pixelformat), fmtdesc.description);
			if (formats[i].fourcc == fmtdesc.pixelformat)
			{
				fmt.fmt.pix.pixelformat = fmtdesc.pixelformat;
				goto NEGOCIATION_FOUND;
			}
			fmtdesc.index++;
		}
	}
NEGOCIATION_FOUND:
	if (xioctl(fd, VIDIOC_S_FMT, &fmt) != 0)
		return -1;
	return 0;
}

static Buffer_t * _camera_setup(int fd, int *nbuffers)
{
	struct v4l2_format fmt;
	fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	xioctl(fd, VIDIOC_G_FMT, &fmt);
	warn("Image %u, %u "V4L2_FOURCC_CONV"", fmt.fmt.pix.width, fmt.fmt.pix.height, V4L2_FOURCC_CONV_ARGS(fmt.fmt.pix.pixelformat));

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

static int _camera_run(int fd, int ofd, Buffer_t *buffers)
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
			else
				ret = _save_frame(ofd, buffers[buf.index].input, buf.bytesused);
			if (ret <= 0)
			{
				err("save frame %d", ret);
				run = 0;
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

#define MODE_UNIX 0x01
#define MODE_OUISTITI 0x02

int main(int argc, char *argv[])
{
	const char *device = "/dev/video0";
	const char *output = "camera.mjpeg";
	int mode = 0;
	int defaultid = -1;

	int opt;
	do
	{
		opt = getopt(argc, argv, "d:o:uO");
		switch (opt)
		{
			case 'd':
				device = optarg;
			break;
			case 'o':
				output = optarg;
			break;
			case 'u':
				mode |= MODE_UNIX;
			break;
			case 'O':
				mode |= MODE_OUISTITI;
			break;
			default:
			break;
		}
	} while(opt != -1);

	struct stat st;
	stat(device, &st);
	if (!S_ISCHR(st.st_mode))
		return -1;

	const char *ext = strrchr(output, '.');
	if (ext != NULL)
	{
	warn("ext %s", ext);
		if (!strcmp(ext, ".hd64"))
			defaultid = 1;
		if (!strcmp(ext, ".jpg"))
			defaultid = 2;
	}
	warn("default id %d", defaultid);
	int fd = open(device, O_RDWR | O_NONBLOCK, 0);
	if (fd == -1)
	{
		err("device %s not found", device);
		return -1;
	}

	struct v4l2_capability cap;
	if ((xioctl(fd, VIDIOC_QUERYCAP, &cap) != 0) ||
		!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE))
	{
		err("device %s not capture", device);
		close(fd);
		return -1;
	}
	if (!(cap.capabilities & V4L2_CAP_STREAMING))
	{
		err("device %s not camera", device);
		close(fd);
		return -1;
	}

	if (_camera_negociate(fd, defaultid))
		return -1;
	int nbuffers = 0;
	Buffer_t *buffers = NULL;
	buffers = _camera_setup(fd, &nbuffers);
	if (buffers == NULL)
		return -1;

	int ofd = 1;
	if (output != NULL)
	{
		if (mode & MODE_UNIX)
		{
			signal(SIGPIPE, SIG_IGN);
			unlink(output);
			int sock = socket(AF_UNIX, SOCK_STREAM, 0);

			if (sock == -1)
			{
				return -1;
			}

			struct sockaddr_un addr;
			memset(&addr, 0, sizeof(addr));
			addr.sun_family = AF_UNIX;
			strcpy(addr.sun_path, output);

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
			ofd = open(output, O_RDWR | O_CREAT, 0666);
	}
	if (ofd == -1)
	{
		err("output %s not found", output);
		return -1;
	}

	_camera_run(fd, ofd, buffers);
	close(ofd);
	if (mode & MODE_UNIX)
		goto SOCKET_RESTART;
	return 0;
}
