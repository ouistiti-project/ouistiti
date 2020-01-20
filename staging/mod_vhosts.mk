modules-$(MODULES)+=mod_vhosts
slib-y+=mod_vhosts
mod_vhosts_SOURCES+=mod_vhosts.c
mod_vhosts_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_vhosts_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_vhosts_CFLAGS+=-I$(srcdir)src
mod_vhosts_LDFLAGS+=-L$(srcdir)src


mod_vhosts_CFLAGS-$(DEBUG)+=-g -DDEBUG
