modules-$(MODULES)+=mod_cgi
slib-y+=mod_cgi
mod_cgi_SOURCES+=mod_cgi.c
mod_cgi_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_cgi_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)

mod_cgi_CFLAGS-$(DEBUG)+=-g -DDEBUG
