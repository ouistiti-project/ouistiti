modules-$(MODULES)+=mod_methodlock
slib-$(STATIC)+=mod_methodlock
mod_methodlock_SOURCES+=mod_methodlock.c
mod_methodlock_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_methodlock_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_methodlock_LIBS+=$(LIBHTTPSERVER_NAME)
mod_methodlock_LIBRARY+=libconfig
mod_methodlock_CFLAGS+=-I$(srcdir)src
mod_methodlock_LDFLAGS+=-L$(srcdir)src

mod_methodlock_CFLAGS-$(DEBUG)+=-g -DDEBUG

