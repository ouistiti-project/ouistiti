modules-$(DYNAMIC)+=mod_clientfilter
slib-$(STATIC)+=mod_clientfilter
mod_clientfilter_SOURCES+=mod_clientfilter.c
mod_clientfilter_CFLAGS+=-I../libhttpserver/include

mod_clientfilter_CFLAGS-$(DEBUG)+=-g -DDEBUG
