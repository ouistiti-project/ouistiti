TARGET=ouistiti
sbin-y+=$(TARGET)
$(TARGET)_CFLAGS+=-I../libhttpserver/include/httpserver
$(TARGET)_LDFLAGS+=-L. -L../libhttpserver/src
$(TARGET)_LIBS+=httpserver
ifeq ($(VTHREAD_TYPE),pthread)
$(TARGET)_LIBRARY-$(VTHREAD)+=pthread rt
endif
$(TARGET)_SOURCES+=main.c ../libhttpserver/src/httpserver/libhttpserver.a
main_CFLAGS+= -Dsysconfdir="\"$(sysconfdir)\""
$(TARGET)_CFLAGS-$(STATIC_CONFIG)+=-DSTATIC_CONFIG
$(TARGET)_SOURCES-$(FILE_CONFIG)+=config.c
$(TARGET)_LIBRARY-$(FILE_CONFIG)+=config

$(TARGET)_LIBS-$(MBEDTLS)+=mod_mbedtls
$(TARGET)_LIBRARY-$(MBEDTLS)+=mbedtls mbedx509 mbedcrypto
$(TARGET)_CFLAGS-$(MBEDTLS)+=-DMBEDTLS
$(TARGET)_LIBS-$(SENDFILE)+=mod_sendfile
$(TARGET)_CFLAGS-$(SENDFILE)+=-DSTATIC_FILE -DSENDFILE
$(TARGET)_LIBS-$(STATIC_FILE)+=mod_static_file utils_mod
$(TARGET)_CFLAGS-$(STATIC_FILE)+=-DSTATIC_FILE
$(TARGET)_LIBS-$(CGI)+=mod_cgi utils_mod
$(TARGET)_CFLAGS-$(CGI)+=-DCGI
$(TARGET)_LIBS-$(AUTH)+=mod_auth
$(TARGET)_CFLAGS-$(AUTH)+=-DAUTH
$(TARGET)_CFLAGS-$(AUTHN_BASIC_CONF)+=-DAUTHN_BASIC_CONF

$(TARGET)_CFLAGS-$(DEBUG)+=-g -DDEBUG

ifeq ($(STATIC),y)
	static=s
endif

$(static)lib-$(STATIC)+=utils_mod
utils_mod_SOURCES=utils.c
utils_mod_CFLAGS+=-I../libhttpserver/include 

utils_mod_CFLAGS-$(DEBUG)+=-g -DDEBUG

$(static)lib-$(CGI)+=mod_cgi
mod_cgi_SOURCES+=mod_cgi.c
mod_cgi_CFLAGS+=-I../libhttpserver/include/

mod_cgi_CFLAGS-$(DEBUG)+=-g -DDEBUG

$(static)lib-$(STATIC_FILE)+=mod_static_file
mod_static_file_SOURCES+=mod_static_file.c
mod_static_file_CFLAGS+=-I../libhttpserver/include
mod_static_file_CFLAGS-$(SENDFILE)+=-DSENDFILE

mod_static_file_CFLAGS-$(DEBUG)+=-g -DDEBUG

$(static)lib-$(SENDFILE)+=mod_sendfile
mod_sendfile_SOURCES+=mod_sendfile.c
mod_sendfile_CFLAGS+=-I../libhttpserver/include

mod_sendfile_CFLAGS-$(DEBUG)+=-g -DDEBUG

LIBB64_DIR=../libb64
$(static)lib-$(AUTH)+=mod_auth
mod_auth_SOURCES+=mod_auth.c
mod_auth_CFLAGS+=-I../libhttpserver/include

mod_auth_SOURCES-$(AUTHN_BASIC_CONF)+=authn_basic_conf.c ../utils/libb64.a
mod_auth_CFLAGS-$(AUTHN_BASIC_CONF)+=-DAUTHN_BASIC_CONF -I$(LIBB64_DIR)/include

mod_auth_CFLAGS-$(DEBUG)+=-g -DDEBUG
