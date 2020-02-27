modules-$(MODULES)+=mod_redirect
slib-y+=mod_redirect
mod_redirect_SOURCES+=mod_redirect.c
mod_redirect_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_redirect_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)

mod_redirect_CFLAGS-$(DEBUG)+=-g -DDEBUG
