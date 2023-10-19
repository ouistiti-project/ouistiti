WS_DIR=webstream/

ifneq ($(USE_PTHREAD),y)
  DUMMYSTREAM=n
  UDPGW=n
endif
bin-$(DUMMYSTREAM)+=streamer
streamer_INSTALL:=libexec
streamer_SOURCES+=$(WS_DIR)streamer.c utils.c
streamer_LIBS+=pthread
streamer_CFLAGS-$(DEBUG)+=-g -DDEBUG

bin-$(UDPGW)+=udpgw
udpgw_INSTALL:=libexec
udpgw_SOURCES+=$(WS_DIR)udpgw.c utils.c
udpgw_LIBS+=pthread
udpgw_CFLAGS-$(DEBUG)+=-g -DDEBUG

bin-$(MJPEG)+=mjpeg
mjpeg_INSTALL:=libexec
mjpeg_SOURCES+=$(WS_DIR)mjpeg.c utils.c
mjpeg_LIBS+=pthread
mjpeg_CFLAGS-$(DEBUG)+=-g -DDEBUG

subdir-y+=$(WS_DIR)/htdocs.mk
