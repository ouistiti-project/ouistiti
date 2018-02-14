WS_DIR=webstream/
bin-$(DUMMYSTREAM)+=streamer
streamer_SOURCES+=$(WS_DIR)streamer.c utils.c
streamer_LIBS+=pthread
streamer_CFLAGS-$(DEBUG)+=-g -DDEBUG
