modules-$(MODULES)+=mod_wolfssl
slib-$(STATIC)+=mod_wolfssl
mod_wolfssl_SOURCES+=mod_wolfssl.c
mod_wolfssl_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_wolfssl_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_wolfssl_CFLAGS-$(MODULES)+=-DMODULES
mod_wolfssl_ALIAS-$(MODULES)+=mod_tls.so

mod_wolfssl_CFLAGS-$(DEBUG)+=-g -DDEBUG
