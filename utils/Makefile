subdir-$(WEBSOCKET)+=websocket.mk
subdir-$(WEBSOCKET)+=client_websocket.mk
subdir-$(WEBSTREAM)+=webstream.mk

hostbin-$(HOST_UTILS)+=testclient
testclient_SOURCES+=testclient.c
testclient_LIBS-$(MBEDTLS)+=mbedtls mbedx509 mbedcrypto
testclient_CFLAGS-$(DEBUG)+=-g -DDEBUG

ifeq ($(HTTPCLIENT_FEATURES),y)
hostbin-$(HOST_UTILS_DEPRECATED)+=httpparser
endif
httpparser_SOURCES+=httpparser.c
httpparser_LIBS+=$(LIBHTTPSERVER_NAME)
httpparser_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
httpparser_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
httpparser_CFLAGS-$(DEBUG)+=-g -DDEBUG
httpparser_LDFLAGS+=-pthread

hostbin-$(HOST_UTILS)+=ouipasswd
ouipasswd_SOURCES+=ouipasswd.c
ouipasswd_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
ouipasswd_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
ouipasswd_LIBS+=ouihash
ouipasswd_LIBS-$(MBEDTLS)+=mbedcrypto
ouipasswd_LIBS-$(OPENSSL)+=crypto
ouipasswd_LIBS-$(WOLFSSL)+=wolfssl
ouipasswd_CFLAGS-$(DEBUG)+=-g -DDEBUG

sysconf-${FILE_CONFIG}+=ouistiti.conf
sysconf-${FILE_CONFIG}+=ouistiti.d/default.conf

subdir-$(CERTIFICATE)+=certificate.mk

data-y+=certificate.mk
data-y+=certificate.sh
data-y+=ca.conf

subdir-y+=samples.mk
