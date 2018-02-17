TARGET=ouistiti
sbin-y+=$(TARGET)
ifeq ($(VTHREAD_TYPE),pthread)
$(TARGET)_LIBRARY-$(VTHREAD)+=pthread rt
endif
$(TARGET)_SOURCES+=main.c
$(TARGET)_LIBS+=httpserver
main_CFLAGS+= -Dsysconfdir="\"$(sysconfdir)\""
$(TARGET)_CFLAGS-$(STATIC_CONFIG)+=-DSTATIC_CONFIG
$(TARGET)_SOURCES-$(FILE_CONFIG)+=config.c
$(TARGET)_LIBRARY-$(FILE_CONFIG)+=config

$(TARGET)_CFLAGS-$(WEBSOCKET_RT)+=-DWEBSOCKET_RT
$(TARGET)_SOURCES-$(WEBSOCKET_RT)+=websocket.c
$(TARGET)_SOURCES-$(WEBSTREAM)+=websocket.c

ifneq ($(MAX_SERVERS),)
$(TARGET)_CFLAGS+=-DMAXSERVERS=$(MAX_SERVERS)
endif

ifeq ($(FILESTORAGE),y)
STATIC_FILE=y
DIRLISTING=y
endif

ifeq ($(DYNAMIC),y)
$(TARGET)_LIBS-$(MBEDTLS)+=:mod_mbedtls.so
$(TARGET)_LIBS-$(STATIC_FILE)+=:mod_static_file.so :utils_mod.so
$(TARGET)_LIBS-$(FILESTORAGE)+=:mod_filestorage.so
$(TARGET)_LIBS-$(CGI)+=:mod_cgi.so :utils_mod.so
$(TARGET)_LIBS-$(AUTH)+=:mod_auth.so
$(TARGET)_LIBS-$(VHOSTS)+=:mod_vhosts.so
$(TARGET)_LIBS-$(METHODLOCK)+=:mod_methodlock.so
$(TARGET)_LIBS-$(WEBSOCKET)+=:mod_websocket.so
$(TARGET)_LIBS-$(SERVERHEADER)+=:mod_server.so
$(TARGET)_LIBS-$(CLIENTFILTER)+=:mod_clientfilter.so
$(TARGET)_LIBS-$(REDIRECT404)+=:mod_redirect404.so
$(TARGET)_LIBS-$(WEBSTREAM)+=:mod_webstream.so
else
$(TARGET)_LIBS-$(MBEDTLS)+=mod_mbedtls
$(TARGET)_LIBS-$(STATIC_FILE)+=mod_static_file utils_mod
$(TARGET)_LIBS-$(FILESTORAGE)+=mod_filestorage
$(TARGET)_LIBS-$(CGI)+=mod_cgi utils_mod
$(TARGET)_LIBS-$(AUTH)+=mod_auth
$(TARGET)_LIBS-$(VHOSTS)+=mod_vhosts
$(TARGET)_LIBS-$(METHODLOCK)+=mod_methodlock
$(TARGET)_LIBS-$(WEBSOCKET)+=mod_websocket
$(TARGET)_LIBS-$(SERVERHEADER)+=mod_server
$(TARGET)_LIBS-$(CLIENTFILTER)+=mod_clientfilter
$(TARGET)_LIBS-$(REDIRECT404)+=mod_redirect404
$(TARGET)_LIBS-$(WEBSTREAM)+=mod_webstream
endif
$(TARGET)_LIBS-$(WEBSOCKET)+=websocket

#ifeq ($(STATIC),y)
#$(TARGET)_SOURCES-$(STATIC_FILE)+=libmod_static_file.a libutils_mod.a
#$(TARGET)_SOURCES-$(CGI)+=libmod_cgi.a libutils_mod.a
#$(TARGET)_SOURCES-$(AUTH)+=libmod_auth.a
#ifneq ($(MBEDTLS),y)
#$(TARGET)_SOURCES-$(AUTH)+=../utils/libb64.a
#ifeq ($(MD5_RONRIVEST),y)
#$(TARGET)_SOURCES-$(AUTHN_DIGEST)+=../utils/md5-c/libmd5.a
#else
#$(TARGET)_SOURCES-$(AUTHN_DIGEST)+=../utils/md5/libmd5.a
#endif
#endif
#$(TARGET)_SOURCES-$(VHOSTS)+=libmod_vhosts.a
#$(TARGET)_SOURCES-$(METHODLOCK)+=libmod_methodlock.a
#$(TARGET)_SOURCES-$(WEBSOCKET)+=libmod_websocket.a
#$(TARGET)_SOURCES-$(SERVERHEADER)+=libmod_server.a
#endif

$(TARGET)_LIBRARY-$(MBEDTLS)+=mbedtls mbedx509 mbedcrypto
$(TARGET)_LIBRARY-$(AUTHZ_SQLITE)+=sqlite3
$(TARGET)_CFLAGS-$(MBEDTLS)+=-DMBEDTLS
$(TARGET)_CFLAGS-$(STATIC_FILE)+=-DSTATIC_FILE
$(TARGET)_CFLAGS-$(SENDFILE)+=-DSENDFILE
$(TARGET)_CFLAGS-$(DIRLISTING)+=-DDIRLISTING
$(TARGET)_CFLAGS-$(FILESTORAGE)+=-DFILESTORAGE
$(TARGET)_CFLAGS-$(RANGEREQUEST)+=-DRANGEREQUEST
$(TARGET)_CFLAGS-$(CGI)+=-DCGI
$(TARGET)_CFLAGS-$(AUTH)+=-DAUTH
$(TARGET)_CFLAGS-$(AUTHN_NONE)+=-DAUTHN_NONE
$(TARGET)_CFLAGS-$(AUTHN_BASIC)+=-DAUTHN_BASIC
$(TARGET)_CFLAGS-$(AUTHN_DIGEST)+=-DAUTHN_DIGEST
$(TARGET)_CFLAGS-$(AUTHZ_SIMPLE)+=-DAUTHZ_SIMPLE
$(TARGET)_CFLAGS-$(AUTHZ_FILE)+=-DAUTHZ_FILE
$(TARGET)_CFLAGS-$(AUTHZ_UNIX)+=-DAUTHZ_UNIX
$(TARGET)_CFLAGS-$(AUTHZ_SQLITE)+=-DAUTHZ_SQLITE
$(TARGET)_CFLAGS-$(VHOSTS)+=-DVHOSTS
$(TARGET)_CFLAGS-$(METHODLOCK)+=-DMETHODLOCK
$(TARGET)_CFLAGS-$(WEBSOCKET)+=-DWEBSOCKET
$(TARGET)_CFLAGS-$(SERVERHEADER)+=-DSERVERHEADER
$(TARGET)_CFLAGS-$(CLIENTFILTER)+=-DCLIENTFILTER
$(TARGET)_CFLAGS-$(REDIRECT404)+=-DREDIRECT404
$(TARGET)_CFLAGS-$(WEBSTREAM)+=-DWEBSTREAM

$(TARGET)_CFLAGS-$(DEBUG)+=-g -DDEBUG

subdir-$(CGI)+=mod_cgi.mk
subdir-$(STATIC_FILE)+=mod_static_file.mk
subdir-$(FILESTORAGE)+=mod_filestorage.mk
subdir-$(AUTH)+=mod_auth.mk
subdir-$(VHOSTS)+=mod_vhosts.mk
subdir-$(METHODLOCK)+=mod_methodlock.mk
subdir-$(SERVERHEADER)+=mod_server.mk
subdir-$(CLIENTFILTER)+=mod_clientfilter.mk
subdir-$(REDIRECT404)+=mod_redirect404.mk
subdir-$(WEBSTREAM)+=mod_webstream.mk
