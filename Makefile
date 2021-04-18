package=ouistiti
version=3.1

include scripts.mk

#libhttpserver has to be static in all configuration
export SLIB_HTTPSERVER=y
export MAXCHUNKS_HEADER=20
export MAXCHUNKS_URI=4

ifeq ($(VTHREAD_TYPE),pthread)
 USE_PTHREAD=y
endif

download-$(LIBHTTPSERVER_DL)+=libhttpserver
libhttpserver_SOURCE=libhttpserver
libhttpserver_SITE=https://github.com/ouistiti-project/libhttpserver.git
libhttpserver_SITE_METHOD=git

LIBHTTPSERVER_DIR?=libhttpserver
export LIBHTTPSERVER_DIR

ifneq ($(wildcard $(sysroot)$(includedir)/ouistiti/version.h),)
LIBHTTPSERVER_NAME?=$(shell cat $(sysroot)$(includedir)/ouistiti/version.h | awk '/PACKAGE /{print $$3}')
else
 ifneq ($(wildcard $(LIBHTTPSERVER_DIR)/Makefile),)
LIBHTTPSERVER_NAME?=$(package)
subdir-y+=$(LIBHTTPSERVER_DIR)
 endif

 ifeq ($(LIBHTTPSERVER_CFLAGS), )

  ifneq ($(wildcard $(LIBHTTPSERVER_DIR)/Makefile),)
LIBHTTPSERVER_LDFLAGS+=-L$(LIBHTTPSERVER_DIR)/src/httpserver
LIBHTTPSERVER_LDFLAGS+=-L$(LIBHTTPSERVER_DIR)/src
  endif
  ifneq ($(wildcard $(srcdir)$(LIBHTTPSERVER_DIR)/Makefile),)
LIBHTTPSERVER_LDFLAGS+=-L$(srcdir)$(LIBHTTPSERVER_DIR)/src/httpserver
LIBHTTPSERVER_LDFLAGS+=-L$(srcdir)$(LIBHTTPSERVER_DIR)/src
  endif

LIBHTTPSERVER_LDFLAGS+=-L$(obj)$(LIBHTTPSERVER_DIR)/src/httpserver
LIBHTTPSERVER_LDFLAGS+=-L$(obj)$(LIBHTTPSERVER_DIR)/src

LIBHTTPSERVER_LDFLAGS+=-L$(hostobj)$(LIBHTTPSERVER_DIR)/src/httpserver
LIBHTTPSERVER_LDFLAGS+=-L$(hostobj)$(LIBHTTPSERVER_DIR)/src

  ifneq ($(wildcard $(LIBHTTPSERVER_DIR)/lib/libhttpserver.so),)
LIBHTTPSERVER_LDFLAGS+=-L$(builddir)$(LIBHTTPSERVER_DIR)/lib
  endif

  ifneq ($(wildcard $(srcdir)$(LIBHTTPSERVER_DIR)/include/ouistiti/httpserver.h), )
LIBHTTPSERVER_CFLAGS+=-I$(srcdir)$(LIBHTTPSERVER_DIR)/include
  endif
  ifneq ($(wildcard $(LIBHTTPSERVER_DIR)/include/osuititi/httpserver.h), )
LIBHTTPSERVER_CFLAGS+=-I$(LIBHTTPSERVER_DIR)/include
  endif
 endif

endif
ifeq ($(LIBHTTPSERVER_NAME), )
$(warning libouistiti not found $(LIBHTTPSERVER_NAME))
endif
LIBHTTPSERVER_NAME:=$(LIBHTTPSERVER_NAME:lib%=%)
export LIBHTTPSERVER_NAME
export LIBHTTPSERVER_LDFLAGS
export LIBHTTPSERVER_CFLAGS

ifeq ($(HTTPCLIENT_FEATURES),y)
override AUTHN_OAUTH2:=n
endif

subdir-y+=staging
subdir-y+=src
subdir-y+=utils
