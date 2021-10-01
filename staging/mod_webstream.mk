modules-$(MODULES)+=mod_webstream
slib-$(STATIC)+=mod_webstream
mod_webstream_SOURCES-$(SERVERHEADER)+=mod_webstream.c
mod_webstream_CFLAGS+=-I$(srcdir)src
mod_webstream_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_webstream_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_webstream_LIBS+=$(LIBHTTPSERVER_NAME)
mod_webstream_LIBRARY+=libconfig
mod_webstream_LIBS+=ouiutils
mod_webstream_LIBS-$(WEBSOCKET_RT)+=websocket_clirt


mod_webstream_CFLAGS-$(DEBUG)+=-g -DDEBUG

