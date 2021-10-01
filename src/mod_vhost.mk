modules-$(MODULES)+=mod_vhost
slib-$(STATIC)+=mod_vhost
mod_vhost_SOURCES+=mod_vhost.c
mod_vhost_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_vhost_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_vhost_LIBS+=$(LIBHTTPSERVER_NAME)
mod_vhost_CFLAGS+=-I$(srcdir)include
mod_vhost_CFLAGS+=-I$(srcdir)src
mod_vhost_LDFLAGS+=-L$(srcdir)src
mod_vhost_LIBRARY+=libconfig


mod_vhost_CFLAGS-$(DEBUG)+=-g -DDEBUG
