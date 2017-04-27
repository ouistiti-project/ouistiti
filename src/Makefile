TARGET=ouistiti
sbin-y+=$(TARGET)
$(TARGET)_CFLAGS+=-I../libhttpserver/include/httpserver
$(TARGET)_LDFLAGS+=-L. -L../libhttpserver/src
ifeq ($(VTHREAD_TYPE),pthread)
$(TARGET)_LIBRARY-$(VTHREAD)+=pthread rt
endif
$(TARGET)_SOURCES+=main.c
$(TARGET)_SOURCES-$(STATIC)+=../libhttpserver/src/httpserver/libhttpserver.a
$(TARGET)_LIBS-$(DYNAMIC)+=httpserver
$(TARGET)_LDFLAGS-$(DYNAMIC)+=-L../libhttpserver/src/httpserver
main_CFLAGS+= -Dsysconfdir="\"$(sysconfdir)\""
$(TARGET)_CFLAGS-$(STATIC_CONFIG)+=-DSTATIC_CONFIG
$(TARGET)_SOURCES-$(FILE_CONFIG)+=config.c
$(TARGET)_LIBRARY-$(FILE_CONFIG)+=config

ifeq ($(DYNAMIC),y)
$(TARGET)_LIBS-$(MBEDTLS)+=mod_mbedtls
$(TARGET)_LIBS-$(STATIC_FILE)+=mod_static_file utils_mod
$(TARGET)_LIBS-$(CGI)+=mod_cgi utils_mod
$(TARGET)_LIBS-$(AUTH)+=mod_auth
endif

ifeq ($(STATIC),y)
$(TARGET)_SOURCES-$(MBEDTLS)+=../libhttpserver/src/libmod_mbedtls.a
$(TARGET)_SOURCES-$(STATIC_FILE)+=libmod_static_file.a libutils_mod.a
$(TARGET)_SOURCES-$(CGI)+=libmod_cgi.a libutils_mod.a
$(TARGET)_SOURCES-$(AUTH)+=libmod_auth.a ../utils/libb64.a
endif

$(TARGET)_LIBRARY-$(MBEDTLS)+=mbedtls mbedx509 mbedcrypto
$(TARGET)_CFLAGS-$(MBEDTLS)+=-DMBEDTLS
$(TARGET)_CFLAGS-$(SENDFILE)+=-DSENDFILE
$(TARGET)_CFLAGS-$(STATIC_FILE)+=-DSTATIC_FILE
$(TARGET)_CFLAGS-$(CGI)+=-DCGI
$(TARGET)_CFLAGS-$(AUTH)+=-DAUTH
$(TARGET)_CFLAGS-$(AUTHN_BASIC)+=-DAUTHN_BASIC
$(TARGET)_CFLAGS-$(AUTHN_DIGEST)+=-DAUTHN_DIGEST
$(TARGET)_CFLAGS-$(AUTHZ_SIMPLE)+=-DAUTHZ_SIMPLE

$(TARGET)_CFLAGS-$(DEBUG)+=-g -DDEBUG

subdir-${CGI}+=mod_cgi.mk
subdir-${STATIC_FILE}+=mod_static_file.mk
subdir-${AUTH}+=mod_auth.mk
