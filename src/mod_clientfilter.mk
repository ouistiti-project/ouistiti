modules-$(MODULES)+=mod_clientfilter
slib-y+=mod_clientfilter
mod_clientfilter_SOURCES+=mod_clientfilter.c
mod_clientfilter_CFLAGS+=-I../libhttpserver/include

mod_clientfilter_CFLAGS-$(DEBUG)+=-g -DDEBUG
