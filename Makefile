include scripts.mk

package=ouistiti
version=2.1

#libhttpserver has to be static in all configuration
export SLIB_HTTPSERVER=y
export MAXCHUNKS_HEADER=20
export MAXCHUNKS_URI=4

LIBHTTPSERVER_DIR?=$(srcdir)libhttpserver
export LIBHTTPSERVER_DIR

ifneq ($(wildcard $(LIBHTTPSERVER_DIR)/Makefile),)
subdir-y+=$(LIBHTTPSERVER_DIR)
endif

ifneq ($(wildcard $(LIBHTTPSERVER_DIR)/src/httpserver/libhttpserver.so),)
LIBHTTPSERVER_LDFLAGS+=-L$(LIBHTTPSERVER_DIR)/src/httpserver
LIBHTTPSERVER_LDFLAGS+=-L$(LIBHTTPSERVER_DIR)/src
endif
ifneq ($(wildcard $(LIBHTTPSERVER_DIR)/lib/libhttpserver.so),)
LIBHTTPSERVER_LDFLAGS+=-L$(LIBHTTPSERVER_DIR)/lib
endif
ifneq ($(wildcard $(LIBHTTPSERVER_DIR)/libhttpserver.so),)
LIBHTTPSERVER_LDFLAGS+=-L$(LIBHTTPSERVER_DIR)
endif
export LIBHTTPSERVER_LDFLAGS

ifneq ($(wildcard $(LIBHTTPSERVER_DIR)/include/httpserver/httpserver.h),)
LIBHTTPSERVER_CFLAGS+=-I$(LIBHTTPSERVER_DIR)/include
endif
ifneq ($(wildcard $(LIBHTTPSERVER_DIR)/httpserver/httpserver.h),)
LIBHTTPSERVER_CFLAGS+=-I$(LIBHTTPSERVER_DIR)
endif
export LIBHTTPSERVER_CFLAGS

subdir-y+=utils
subdir-y+=src

