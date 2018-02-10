modules-$(DYNAMIC)+=mod_redirect404
slib-$(STATIC)+=mod_redirect404
mod_redirect404_SOURCES+=mod_redirect404.c
mod_redirect404_CFLAGS+=-I../libhttpserver/include

mod_redirect404_CFLAGS-$(DEBUG)+=-g -DDEBUG
