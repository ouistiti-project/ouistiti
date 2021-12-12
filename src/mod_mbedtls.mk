modules-$(MODULES)+=mod_mbedtls
slib-$(STATIC)+=mod_mbedtls
mod_mbedtls_SOURCES+=mod_mbedtls.c
mod_mbedtls_SOURCES+=mod_tls.c
mod_mbedtls_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_mbedtls_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_mbedtls_LIBS+=$(LIBHTTPSERVER_NAME)
mod_mbedtls_LIBS+=mbedtls mbedx509 mbedcrypto
mod_mbedtls_LIBRARY+=libconfig
mod_mbedtls_ALIAS-$(MODULES)+=mod_tls.so
ifneq ($(wildcard $(sysroot)$(includedir)/httpserver/config.h),)
mod_mbedtls_CFLAGS+=-Dhttpserver_config
endif

mod_mbedtls_CFLAGS-$(DEBUG)+=-g -DDEBUG
