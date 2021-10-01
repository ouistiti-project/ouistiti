modules-$(MODULES)+=mod_cors
slib-$(STATIC)+=mod_cors
mod_cors_SOURCES-$(CORS)+=mod_cors.c
mod_cors_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_cors_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_cors_LIBS+=$(LIBHTTPSERVER_NAME)
mod_cors_LIBS+=ouiutils
mod_cors_LIBRARY+=libconfig

mod_cors_CFLAGS-$(DEBUG)+=-g -DDEBUG

