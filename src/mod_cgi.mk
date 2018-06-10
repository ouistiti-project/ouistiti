modules-$(MODULES)+=mod_cgi
slib-y+=mod_cgi
mod_cgi_SOURCES+=mod_cgi.c
mod_cgi_CFLAGS+=-I../libhttpserver/include/
mod_cgi_CFLAGS-$(MODULES)+=-DMODULES
mod_cgi_CFLAGS-$(AUTH)+=-DAUTH

mod_cgi_CFLAGS-$(DEBUG)+=-g -DDEBUG
