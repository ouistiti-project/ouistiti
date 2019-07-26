modules-$(MODULES)+=mod_server
slib-y+=mod_server
mod_server_SOURCES-$(SERVERHEADER)+=mod_server.c
mod_server_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_server_CFLAGS+=-DSERVERHEADER
mod_server_CFLAGS-$(MODULES)+=-DMODULES
mod_server_CFLAGS-$(SECURITY_UNCHECKORIGIN)+=-DSECURITY_UNCHECKORIGIN

mod_server_CFLAGS-$(DEBUG)+=-g -DDEBUG

