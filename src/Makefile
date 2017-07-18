TARGET=ouistiti
sbin-y+=$(TARGET)
$(TARGET)_CFLAGS+=-I../libhttpserver/include/
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

ifneq ($(MBEDTLS), y)
$(TARGET)_SOURCES-$(WEBSOCKET)+=websocket.c
endif

ifneq ($(MAX_SERVERS),)
$(TARGET)_CFLAGS+=-DMAX_SERVERS=$(MAX_SERVERS)
endif

ifeq ($(DYNAMIC),y)
$(TARGET)_LIBS-$(MBEDTLS)+=:mod_mbedtls.so
$(TARGET)_LIBS-$(STATIC_FILE)+=:mod_static_file.so :utils_mod.so
$(TARGET)_LIBS-$(CGI)+=:mod_cgi.so :utils_mod.so
$(TARGET)_LIBS-$(AUTH)+=:mod_auth.so
$(TARGET)_LIBS-$(VHOSTS)+=:mod_vhosts.so
$(TARGET)_LIBS-$(METHODLOCK)+=:mod_methodlock.so
$(TARGET)_LIBS-$(WEBSOCKET)+=:mod_websocket.so
$(TARGET)_LIBS-$(SERVERHEADER)+=:mod_server.so
endif

ifeq ($(STATIC),y)
$(TARGET)_SOURCES-$(MBEDTLS)+=../libhttpserver/src/libmod_mbedtls.a
$(TARGET)_SOURCES-$(STATIC_FILE)+=libmod_static_file.a libutils_mod.a
$(TARGET)_SOURCES-$(CGI)+=libmod_cgi.a libutils_mod.a
$(TARGET)_SOURCES-$(AUTH)+=libmod_auth.a ../utils/libb64.a
ifneq ($(MBEDTLS),y)
ifeq ($(MD5_RONRIVEST),y)
$(TARGET)_SOURCES-$(AUTHN_DIGEST)+=../utils/md5-c/libmd5.a
else
$(TARGET)_SOURCES-$(AUTHN_DIGEST)+=../utils/md5/libmd5.a
endif
endif
$(TARGET)_SOURCES-$(VHOSTS)+=libmod_vhosts.a
$(TARGET)_SOURCES-$(METHODLOCK)+=libmod_methodlock.a
$(TARGET)_SOURCES-$(WEBSOCKET)+=libmod_websocket.a
$(TARGET)_SOURCES-$(SERVERHEADER)+=libmod_server.a
endif

$(TARGET)_LIBRARY-$(MBEDTLS)+=mbedtls mbedx509 mbedcrypto
$(TARGET)_CFLAGS-$(MBEDTLS)+=-DMBEDTLS
$(TARGET)_CFLAGS-$(DIRLISTING)+=-DDIRLISTING
$(TARGET)_CFLAGS-$(SENDFILE)+=-DSENDFILE
$(TARGET)_CFLAGS-$(STATIC_FILE)+=-DSTATIC_FILE
$(TARGET)_CFLAGS-$(CGI)+=-DCGI
$(TARGET)_CFLAGS-$(AUTH)+=-DAUTH
$(TARGET)_CFLAGS-$(AUTHN_BASIC)+=-DAUTHN_BASIC
$(TARGET)_CFLAGS-$(AUTHN_DIGEST)+=-DAUTHN_DIGEST
$(TARGET)_CFLAGS-$(AUTHZ_SIMPLE)+=-DAUTHZ_SIMPLE
$(TARGET)_CFLAGS-$(VHOSTS)+=-DVHOSTS
$(TARGET)_CFLAGS-$(METHODLOCK)+=-DMETHODLOCK
$(TARGET)_CFLAGS-$(WEBSOCKET)+=-DWEBSOCKET
$(TARGET)_CFLAGS-$(SERVERHEADER)+=-DSERVERHEADER

$(TARGET)_CFLAGS-$(DEBUG)+=-g -DDEBUG

subdir-$(CGI)+=mod_cgi.mk
subdir-$(STATIC_FILE)+=mod_static_file.mk
subdir-$(AUTH)+=mod_auth.mk
subdir-$(VHOSTS)+=mod_vhosts.mk
subdir-$(METHODLOCK)+=mod_methodlock.mk
subdir-$(SERVERHEADER)+=mod_server.mk
