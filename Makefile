include scripts.mk

subdir-y:=libhttpserver/src/httpserver
subdir-$(MBEDTLS)+=libhttpserver/src/mod_mbedtls.mk
subdir-y+=src

