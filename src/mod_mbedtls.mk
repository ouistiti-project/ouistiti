modules-$(MODULES)+=mod_mbedtls
slib-y+=mod_mbedtls
mod_mbedtls_SOURCES+=mod_mbedtls.c
mod_mbedtls_LIBRARY+=mbedtls mbedx509 mbedcrypto
mod_mbedtls_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_mbedtls_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_mbedtls_ALIAS-$(MODULES)+=mod_tls.so

mod_mbedtls_CFLAGS-$(DEBUG)+=-g -DDEBUG
