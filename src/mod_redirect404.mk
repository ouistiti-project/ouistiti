modules-$(MODULES)+=mod_redirect404
slib-y+=mod_redirect404
mod_redirect404_SOURCES+=mod_redirect404.c
mod_redirect404_CFLAGS+=-I../libhttpserver/include
mod_redirect404_CFLAGS+=-DREDIRECT404
mod_redirect404_CFLAGS-$(MODULES)+=-DMODULES

mod_redirect404_CFLAGS-$(DEBUG)+=-g -DDEBUG
