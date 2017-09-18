include scripts.mk

package=ouistiti
version=1.0

#libhttpserver has to be static in all configuration
export SLIB_HTTPSERVER=y
export MAXCHUNKS_HEADER=20
export MAXCHUNKS_URI=4
ifneq ($(wildcard libhttpserver/Makefile),)
subdir-y:=libhttpserver
export CFLAGS+=-I../libhttpserver/include/
export LDFLAGS+=-L../libhttpserver/src -L../libhttpserver/src/httpserver
endif
subdir-y+=utils
subdir-y+=src

