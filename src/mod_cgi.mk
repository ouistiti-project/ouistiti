modules-$(MODULES)+=mod_cgi
slib-$(STATIC)+=mod_cgi
mod_cgi_SOURCES+=mod_cgi.c
mod_cgi_SOURCES+=cgi_env.c
mod_cgi_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_cgi_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_cgi_LIBS+=$(LIBHTTPSERVER_NAME)
mod_cgi_LIBRARY+=libconfig
mod_cgi_LIBS+=ouiutils

mod_cgi_CFLAGS-$(DEBUG)+=-g -DDEBUG
