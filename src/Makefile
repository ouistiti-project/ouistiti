TARGET=ouistiti
bin-y+=$(TARGET)
$(TARGET)_CFLAGS+=-I../libhttpserver/include/httpserver
$(TARGET)_LDFLAGS+=-L. -L../libhttpserver/src/httpserver -L../libhttpserver/src
$(TARGET)_SOURCES+=main.c
$(TARGET)_LIBRARY+=httpserver pthread rt
$(TARGET)_LIBRARY-$(MBEDTLS)+=mod_mbedtls mbedtls mbedx509 mbedcrypto
$(TARGET)_CFLAGS-$(MBEDTLS)+=-DMBEDTLS
$(TARGET)_LIBRARY-$(STATIC_FILE)+=mod_static_file
$(TARGET)_CFLAGS-$(STATIC_FILE)+=-DSTATIC_FILE
$(TARGET)_LIBRARY-$(STATIC_FILE)+=mod_cgi
$(TARGET)_CFLAGS-$(STATIC_FILE)+=-DCGI
$(TARGET)_LIBRARY-$(FORM_URLENCODED)+=mod_form_urlencoded
$(TARGET)_CFLAGS-$(FORM_URLENCODED)+=-DFORM_URLENCODED
$(TARGET)_LIBRARY+=uri

$(TARGET)_CFLAGS-$(DEBUG)+=-g -DDEBUG

lib-y+=mod_cgi
mod_cgi_SOURCES+=mod_cgi.c
mod_cgi_CFLAGS+=-I../libhttpserver/include/httpserver 

mod_cgi_CFLAGS-$(DEBUG)+=-g -DDEBUG

lib-$(STATIC_FILE)+=mod_static_file
mod_static_file_SOURCES+=mod_static_file.c
mod_static_file_CFLAGS+=-I../libhttpserver/include/httpserver 

mod_static_file_CFLAGS-$(DEBUG)+=-g -DDEBUG
