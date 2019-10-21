
modules-$(MODULES)+=mod_cors
slib-y+=mod_cors
mod_cors_SOURCES-$(CORS)+=mod_cors.c
mod_cors_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_cors_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_cors_CFLAGS+=-DCORS
mod_cors_CFLAGS-$(MODULES)+=-DMODULES
mod_cors_CFLAGS-$(DOCUMENTREST)+=-DDOCUMENTREST

mod_cors_CFLAGS-$(DEBUG)+=-g -DDEBUG

