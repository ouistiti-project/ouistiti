
lib-$(DYNAMIC)+=utils_mod
slib-$(STATIC)+=utils_mod
utils_mod_SOURCES=utils.c
utils_mod_CFLAGS+=-I../libhttpserver/include 

utils_mod_CFLAGS-$(DEBUG)+=-g -DDEBUG

lib-$(DYNAMIC)+=mod_cgi
slib-$(STATIC)+=mod_cgi
mod_cgi_SOURCES+=mod_cgi.c
mod_cgi_CFLAGS+=-I../libhttpserver/include/

mod_cgi_CFLAGS-$(DEBUG)+=-g -DDEBUG
