modules-$(MODULES)+=mod_openssl
slib-$(STATIC)+=mod_openssl
mod_openssl_SOURCES+=mod_openssl.c
mod_openssl_LIBRARY+=libssl libcrypto
mod_openssl_CFLAGS+=-I../src
mod_openssl_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_openssl_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_openssl_LIBS+=$(LIBHTTPSERVER_NAME)
mod_openssl_LIBRARY+=libconfig
mod_openssl_ALIAS-$(MODULES)+=mod_tls.so

mod_openssl_CFLAGS-$(DEBUG)+=-g -DDEBUG
