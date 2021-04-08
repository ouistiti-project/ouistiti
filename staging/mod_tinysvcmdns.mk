modules-$(MODULES)+=mod_tinysvcmdns
slib-$(STATIC)+=mod_tinysvcmdns
mod_tinysvcmdns_SOURCES-$(TINYSVCMDNS)+=mod_tinysvcmdns.c
mod_tinysvcmdns_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_tinysvcmdns_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_tinysvcmdns_CFLAGS+=-I$(srcdir)src -I=/usr/include/tinysvcmdns
mod_tinysvcmdns_LIBS+=tinysvcmdns

mod_tinysvcmdns_CFLAGS-$(DEBUG)+=-g -DDEBUG

