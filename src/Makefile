ifneq ($(AUTH), y)
AUTHN_NONE=n
AUTHN_BASIC=n
AUTHN_DIGEST=n
AUTHZ_SIMPLE=n
AUTHZ_FILE=n
AUTHZ_UNIX=n
AUTHZ_SQLITE=n
endif

ifneq ($(DOCUMENT), y)
SENDFILE=n
DOCUMENTREST=n
DIRLISTING=n
RANGEREQUEST=n
DOCUMENTHOME=n
endif

TARGET?=$(package)
sbin-y+=$(TARGET)
ifeq ($(VTHREAD_TYPE),pthread)
$(TARGET)_LIBRARY-$(VTHREAD)+=pthread rt
endif
$(TARGET)_SOURCES+=main.c
$(TARGET)_LIBS+=$(LIBHTTPSERVER_NAME)
$(TARGET)_LIBS+=ouiutils

$(TARGET)_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
$(TARGET)_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)

$(TARGET)_LDFLAGS+=-L$(srcdir)staging
$(TARGET)_CFLAGS+=-I$(srcdir)staging

$(TARGET)_SOURCES-$(FILE_CONFIG)+=config.c
$(TARGET)_LIBRARY-$(FILE_CONFIG)+=config

$(TARGET)_LIBS-$(MODULES)+=dl

$(TARGET)_SOURCES-$(WEBSOCKET_RT)+=websocket.c
$(TARGET)_SOURCES-$(WEBSTREAM)+=websocket.c

ifneq ($(MODULES),y)
$(TARGET)_LIBS-$(MBEDTLS)+=mod_mbedtls
$(TARGET)_LIBS-$(WOLFSSL)+=mod_wolfssl
$(TARGET)_LIBS-$(OPENSSL)+=mod_openssl
$(TARGET)_LIBS-$(DOCUMENT)+=mod_document
$(TARGET)_LIBS-$(CGI)+=mod_cgi
$(TARGET)_LIBS-$(AUTH)+=mod_auth
$(TARGET)_LIBS-$(VHOSTS_DEPRECATED)+=mod_vhosts
$(TARGET)_LIBS-$(METHODLOCK)+=mod_methodlock
$(TARGET)_LIBS-$(WEBSOCKET)+=mod_websocket
$(TARGET)_LIBS-$(SERVERHEADER)+=mod_server
$(TARGET)_LIBS-$(CLIENTFILTER)+=mod_clientfilter
$(TARGET)_LIBS-$(REDIRECT)+=mod_redirect404
$(TARGET)_LIBS-$(REDIRECT)+=mod_redirect
$(TARGET)_LIBS-$(WEBSTREAM)+=mod_webstream
$(TARGET)_LIBS-$(COOKIE)+=mod_cookie
$(TARGET)_LIBS-$(CORS)+=mod_cors
$(TARGET)_LIBS-$(TINYSVCMDNS)+=mod_tinysvcmdns

$(TARGET)_LIBRARY-$(MBEDTLS)+=mbedtls mbedx509 mbedcrypto
$(TARGET)_LIBRARY-$(WOLFSSL)+=wolfssl
$(TARGET)_LIBRARY-$(OPENSSL)+=ssl crypto

$(TARGET)_LIBRARY-$(AUTHZ_SQLITE)+=sqlite3 pthread dl m
$(TARGET)_LIBRARY-$(AUTHZ_UNIX)+=crypt
$(TARGET)_LIBRARY-$(AUTHZ_JWT)+=jansson
$(TARGET)_LIBRARY-$(AUTHN_OAUTH2)+=jansson

$(TARGET)_LIBRARY-$(TINYSVCMDNS)+=tinysvcmdns

endif
$(TARGET)_LIBS-$(WEBSOCKET)+=websocket
$(TARGET)_LIBS-$(WEBSOCKET)+=ouihash
$(TARGET)_LIBS-$(AUTH)+=ouihash

$(TARGET)_CFLAGS-$(MBEDTLS)+=-DTLS
$(TARGET)_CFLAGS-$(WOLFSSL)+=-DTLS
$(TARGET)_CFLAGS-$(OPENSSL)+=-DTLS

$(TARGET)_CFLAGS-$(DEBUG)+=-g -DDEBUG
$(TARGET)_LIBRARY-$(DEBUG)+=rt

subdir-$(CGI)+=mod_cgi.mk
subdir-$(DOCUMENT)+=mod_document.mk
subdir-$(AUTH)+=mod_auth.mk
subdir-$(SERVERHEADER)+=mod_server.mk
subdir-$(CLIENTFILTER)+=mod_clientfilter.mk
subdir-$(REDIRECT)+=mod_redirect404.mk
subdir-$(REDIRECT)+=mod_redirect.mk
subdir-$(CORS)+=mod_cors.mk
