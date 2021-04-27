modules-$(MODULES)+=mod_redirect404
slib-$(STATIC)+=mod_redirect404
mod_redirect404_SOURCES+=mod_redirect404.c
mod_redirect404_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_redirect404_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)

mod_redirect404_CFLAGS-$(DEBUG)+=-g -DDEBUG
