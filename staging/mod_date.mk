modules-$(MODULES)+=mod_date
slib-$(STATIC)+=mod_date
mod_date_SOURCES+=mod_date.c
mod_date_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_date_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_date_LIBS+=$(LIBHTTPSERVER_NAME)
mod_date_LIBRARY+=libconfig
mod_date_CFLAGS+=-I$(srcdir)src

mod_date_CFLAGS-$(DEBUG)+=-g -DDEBUG
