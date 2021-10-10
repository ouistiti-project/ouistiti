modules-$(MODULES)+=mod_redirect
slib-$(STATIC)+=mod_redirect
mod_redirect_SOURCES+=mod_redirect.c
mod_redirect_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_redirect_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_redirect_LIBS+=$(LIBHTTPSERVER_NAME)
mod_redirect_LIBRARY+=libconfig
mod_redirect_LIBS+=ouiutils

mod_redirect_CFLAGS-$(DEBUG)+=-g -DDEBUG
