include scripts.mk

subdir-y:=libhttpserver/src/httpserver
subdir-$(MBEDTLS)+=libhttpserver/src/mod_mbedtls.mk
subdir-$(STATIC_FILE)+=libhttpserver/src/mod_static_file.mk
subdir-$(FORM_URLENCODED)+=libhttpserver/src/mod_form_urlencoded.mk
subdir-y+=src

