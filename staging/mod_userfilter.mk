modules-$(MODULES)+=mod_userfilter
slib-y+=mod_userfilter
mod_userfilter_SOURCES-$(USERFILTER)+=mod_userfilter.c
mod_userfilter_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_userfilter_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_userfilter_CFLAGS+=-I$(srcdir)src
mod_userfilter_LDFLAGS+=-L$(srcdir)src

mod_userfilter_CFLAGS-$(DEBUG)+=-g -DDEBUG

