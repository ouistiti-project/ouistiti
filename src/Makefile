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
$(TARGET)_LIBRARY-$(SENDFILE)+=mod_sendfile
$(TARGET)_CFLAGS-$(SENDFILE)+=-DSTATIC_FILE -DSENDFILE
$(TARGET)_LIBRARY-$(STATIC_FILE)+=mod_static_file
$(TARGET)_CFLAGS-$(STATIC_FILE)+=-DSTATIC_FILE
$(TARGET)_LIBRARY-$(CGI)+=mod_cgi
$(TARGET)_CFLAGS-$(CGI)+=-DCGI
$(TARGET)_LIBRARY-$(AUTH)+=mod_auth
$(TARGET)_CFLAGS-$(AUTH)+=-DAUTH
$(TARGET)_CFLAGS-$(AUTHN_BASIC_CONF)+=-DAUTHN_BASIC_CONF

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
mod_static_file_CFLAGS-$(SENDFILE)+=-DSENDFILE


mod_static_file_CFLAGS-$(DEBUG)+=-g -DDEBUG

lib-$(DYNAMIC)+=mod_sendfile
slib-$(STATIC)+=mod_sendfile
mod_sendfile_SOURCES+=mod_sendfile.c
mod_sendfile_CFLAGS+=-I../libhttpserver/include/httpserver

mod_sendfile_CFLAGS-$(DEBUG)+=-g -DDEBUG

LIBB64_DIR=../libb64
lib-$(DYNAMIC)+=mod_auth
slib-$(STATIC)+=mod_auth
mod_auth_SOURCES+=mod_auth.c
mod_auth_CFLAGS+=-I../libhttpserver/include

mod_auth_SOURCES-$(AUTHN_BASIC_CONF)+=authn_basic_conf.c ../utils/libb64.a
mod_auth_CFLAGS-$(AUTHN_BASIC_CONF)+=-DAUTHN_BASIC_CONF -I$(LIBB64_DIR)/include

mod_auth_CFLAGS-$(DEBUG)+=-g -DDEBUG
