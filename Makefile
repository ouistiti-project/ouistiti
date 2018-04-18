include scripts.mk

package=ouistiti
version=1.0

#libhttpserver has to be static in all configuration
export SLIB_HTTPSERVER=y
export MAXCHUNKS_HEADER=20
export MAXCHUNKS_URI=4

LIBHTTPSERVER_DIR?=libhttpserver
ifneq ($(wildcard $(LIBHTTPSERVER_DIR)/Makefile),)
subdir-y:=$(LIBHTTPSERVER_DIR)
libhttpserver_dir:=$(realpath $(LIBHTTPSERVER_DIR))
export CFLAGS+=-I$(libhttpserver_dir)/include/
export LDFLAGS+=-L$(buildpath)$(LIBHTTPSERVER_DIR)/src -L$(buildpath)$(LIBHTTPSERVER_DIR)/src/httpserver
endif

ifneq ($(wildcard $(LIBHTTPSERVER_DIR)/libhttpserver.so $(LIBHTTPSERVER_DIR)/libhttpserver.a),)
libhttpserver_dir:=$(realpath $(LIBHTTPSERVER_DIR))
ifneq ($(wildcard $(libhttpserver_dir)/include/httpserver),)
export CFLAGS+=-I$(libhttpserver_dir)/include/
else
ifneq ($(wildcard $(libhttpserver_dir)/../include/httpserver),)
export CFLAGS+=-I$(libhttpserver_dir)/../include/
else
ifneq ($(wildcard $(libhttpserver_dir)/../../include/httpserver),)
export CFLAGS+=-I$(libhttpserver_dir)/../include/
endif
endif
endif
export LDFLAGS+=-L$(libhttpserver_dir)
endif

subdir-y+=utils
subdir-y+=src

