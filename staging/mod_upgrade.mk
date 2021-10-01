modules-$(MODULES)+=mod_upgrade
slib-$(STATIC)+=mod_upgrade
mod_upgrade_SOURCES+=mod_upgrade.c
mod_upgrade_CFLAGS+=-I$(srcdir)src
mod_upgrade_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_upgrade_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_upgrade_LIBS+=$(LIBHTTPSERVER_NAME)
mod_upgrade_LIBRARY+=libconfig
mod_upgrade_LIBS+=ouiutils

mod_upgrade_CFLAGS-$(DEBUG)+=-g -DDEBUG

