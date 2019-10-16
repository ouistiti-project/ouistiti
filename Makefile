include scripts.mk

package=ouistiti
version=2.1

#libhttpserver has to be static in all configuration
export SLIB_HTTPSERVER=y
export MAXCHUNKS_HEADER=20
export MAXCHUNKS_URI=4

LIBHTTPSERVER_DIR?=libhttpserver
export LIBHTTPSERVER_DIR

download-$(LIBHTTPSERVER_DL)+=libhttpserver
libhttpserver_SOURCE=libhttpserver
libhttpserver_SITE=https://github.com/ouistiti-project/libhttpserver.git
libhttpserver_SITE_METHOD=git

ifneq ($(wildcard $(LIBHTTPSERVER_DIR)/Makefile),)
subdir-y+=$(LIBHTTPSERVER_DIR)
endif

ifneq ($(wildcard $(buildpath)/$(LIBHTTPSERVER_DIR)/src/httpserver/libhttpserver.so) $(wildcard $(buildpath)/$(LIBHTTPSERVER_DIR)/src/httpserver/libhttpserver.a),)
LIBHTTPSERVER_LDFLAGS+=-L$(buildpath)/$(LIBHTTPSERVER_DIR)/src/httpserver
LIBHTTPSERVER_LDFLAGS+=-L$(buildpath)/$(LIBHTTPSERVER_DIR)/src
endif
ifneq ($(wildcard $(buildpath)/$(LIBHTTPSERVER_DIR)/lib/libhttpserver.so),)
LIBHTTPSERVER_LDFLAGS+=-L$(buildpath)/$(LIBHTTPSERVER_DIR)/lib
endif
ifneq ($(wildcard $(buildpath)/$(LIBHTTPSERVER_DIR)/libhttpserver.so),)
LIBHTTPSERVER_LDFLAGS+=-L$(buildpath)/$(LIBHTTPSERVER_DIR)
endif
export LIBHTTPSERVER_LDFLAGS

ifneq ($(wildcard $(srcdir)$(LIBHTTPSERVER_DIR)/include/httpserver/httpserver.h),)
LIBHTTPSERVER_CFLAGS+=-I$(srcdir)$(LIBHTTPSERVER_DIR)/include
endif
ifneq ($(wildcard $(srcdir)$(LIBHTTPSERVER_DIR)/httpserver/httpserver.h),)
LIBHTTPSERVER_CFLAGS+=-I$(srcdir)$(LIBHTTPSERVER_DIR)
endif
export LIBHTTPSERVER_CFLAGS

subdir-y+=utils
subdir-y+=src
