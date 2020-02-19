modules-$(MODULES)+=mod_openssl
slib-y+=mod_openssl
mod_openssl_SOURCES+=mod_openssl.c
mod_openssl_LIBRARY+=ssl crypto
mod_openssl_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_openssl_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_openssl_ALIAS-$(MODULES)+=mod_tls.so

mod_openssl_CFLAGS-$(DEBUG)+=-g -DDEBUG
