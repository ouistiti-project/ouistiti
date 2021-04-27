modules-$(MODULES)+=mod_clientfilter
slib-$(STATIC)+=mod_clientfilter
mod_clientfilter_SOURCES+=mod_clientfilter.c
mod_clientfilter_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)

mod_clientfilter_CFLAGS-$(DEBUG)+=-g -DDEBUG
