
modules-$(DYNAMIC)+=mod_cgi
slib-$(STATIC)+=mod_cgi
mod_cgi_SOURCES+=mod_cgi.c
mod_cgi_CFLAGS+=-I../libhttpserver/include/

mod_cgi_CFLAGS-$(DEBUG)+=-g -DDEBUG
