modules-$(MODULES)+=mod_forward
slib-$(STATIC)+=mod_forward
mod_forward_SOURCES+=mod_forward.c
mod_forward_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_forward_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_forward_LIBS+=$(LIBHTTPSERVER_NAME)
mod_forward_LIBRARY+=libconfig
mod_forward_LIBS+=ouiutils

mod_forward_CFLAGS-$(DEBUG)+=-g -DDEBUG
