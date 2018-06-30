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
subdir-y+=utils
subdir-y+=src

