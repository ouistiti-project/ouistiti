modules-$(MODULES)+=mod_server
slib-$(STATIC)+=mod_server
mod_server_SOURCES-$(SERVERHEADER)+=mod_server.c
mod_server_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_server_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_server_LIBS+=$(LIBHTTPSERVER_NAME)

mod_server_CFLAGS-$(DEBUG)+=-g -DDEBUG

