LIBB64_DIR=../libb64

modules-$(MODULES)+=mod_websocket
slib-$(STATIC)+=mod_websocket
mod_websocket_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_websocket_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_websocket_SOURCES-$(WEBSOCKET)+=mod_websocket.c
mod_websocket_LDFLAGS+=-L../staging
mod_websocket_LIBS-$(WEBSOCKET_RT)+=websocket_clirt
mod_websocket_LIBS+=websocket
mod_websocket_LIBS+=ouihash

mod_websocket_CFLAGS-$(DEBUG)+=-g -DDEBUG

