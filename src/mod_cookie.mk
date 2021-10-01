modules-$(MODULES)+=mod_cookie
slib-$(STATIC)+=mod_cookie
mod_cookie_SOURCES+=mod_cookie.c
mod_cookie_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_cookie_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_cookie_LIBS+=$(LIBHTTPSERVER_NAME)
mod_cookie_LIBRARY+=libconfig

mod_cookie_CFLAGS-$(DEBUG)+=-g -DDEBUG
