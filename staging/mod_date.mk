modules-$(MODULES)+=mod_date
slib-y+=mod_date
mod_date_SOURCES+=mod_date.c
mod_date_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_date_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_date_CFLAGS+=-I$(srcdir)src

mod_date_CFLAGS-$(DEBUG)+=-g -DDEBUG
