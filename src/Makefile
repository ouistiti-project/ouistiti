TARGET=ouistiti
bin-y+=$(TARGET)
$(TARGET)_CFLAGS+=-I../libhttpserver/include/httpserver
$(TARGET)_LDFLAGS+=-L. -L../libhttpserver/src ../libhttpserver/src/httpserver/libhttpserver.a
$(TARGET)_LIBRARY+=pthread rt
$(TARGET)_SOURCES+=main.c
main_CFLAGS+= -Dsysconfdir="\"$(sysconfdir)\""
$(TARGET)_CFLAGS-$(STATIC_CONFIG)+=-DSTATIC_CONFIG
$(TARGET)_SOURCES-$(FILE_CONFIG)+=config.c
$(TARGET)_LIBRARY-$(FILE_CONFIG)+=config

$(TARGET)_LIBRARY-$(MBEDTLS)+=mod_mbedtls mbedtls mbedx509 mbedcrypto
$(TARGET)_CFLAGS-$(MBEDTLS)+=-DMBEDTLS
$(TARGET)_LIBRARY-$(STATIC_FILE)+=mod_static_file
$(TARGET)_CFLAGS-$(STATIC_FILE)+=-DSTATIC_FILE
$(TARGET)_LIBRARY-$(CGI)+=mod_cgi
$(TARGET)_CFLAGS-$(CGI)+=-DCGI
$(TARGET)_LIBRARY-$(SENDFILE)+=mod_sendfile
$(TARGET)_CFLAGS-$(SENDFILE)+=-DSTATIC_FILE

$(TARGET)_CFLAGS-$(DEBUG)+=-g -DDEBUG

lib-$(DYNAMIC)+=mod_cgi
slib-$(STATIC)+=mod_cgi
mod_cgi_SOURCES+=mod_cgi.c
mod_cgi_CFLAGS+=-I../libhttpserver/include/httpserver 

mod_cgi_CFLAGS-$(DEBUG)+=-g -DDEBUG

lib-$(DYNAMIC)+=mod_static_file
slib-$(STATIC)+=mod_static_file
mod_static_file_SOURCES+=mod_static_file.c
mod_static_file_CFLAGS+=-I../libhttpserver/include/httpserver

mod_static_file_CFLAGS-$(DEBUG)+=-g -DDEBUG

lib-$(DYNAMIC)+=mod_sendfile
slib-$(STATIC)+=mod_sendfile
mod_sendfile_SOURCES+=mod_sendfile.c
mod_sendfile_CFLAGS+=-I../libhttpserver/include/httpserver

mod_sendfile_CFLAGS-$(DEBUG)+=-g -DDEBUG
