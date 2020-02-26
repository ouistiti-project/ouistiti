WS_DIR=webstream/

ifneq ($(USE_PTHREAD),y)
  DUMMYSTREAM=n
  UDPGW=n
endif
bin-$(DUMMYSTREAM)+=streamer
streamer_SOURCES+=$(WS_DIR)streamer.c utils.c
streamer_LIBS+=pthread
streamer_CFLAGS-$(DEBUG)+=-g -DDEBUG

bin-$(UDPGW)+=udpgw
udpgw_SOURCES+=$(WS_DIR)udpgw.c utils.c
udpgw_LIBS+=pthread
udpgw_CFLAGS-$(DEBUG)+=-g -DDEBUG
