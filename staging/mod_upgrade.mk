
modules-$(MODULES)+=mod_upgrade
slib-y+=mod_upgrade
mod_upgrade_SOURCES+=mod_upgrade.c
mod_upgrade_CFLAGS+=-I../src
mod_upgrade_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_upgrade_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)

mod_upgrade_CFLAGS-$(DEBUG)+=-g -DDEBUG

