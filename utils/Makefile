subdir-$(WEBSOCKET)+=websocket.mk
subdir-$(WEBSTREAM)+=webstream.mk

hostbin-$(HOST_UTILS)+=testclient
testclient_SOURCES+=testclient.c
testclient_CFLAGS-$(MBEDTLS)+=-DMBEDTLS
testclient_LIBS-$(MBEDTLS)+=mbedtls mbedx509 mbedcrypto
testclient_CFLAGS-$(DEBUG)+=-g -DDEBUG

ifeq ($(HTTPCLIENT_FEATURES),y)
hostbin-$(HOST_UTILS)+=httpparser
endif
httpparser_SOURCES+=httpparser.c
httpparser_LIBS+=httpserver
httpparser_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
httpparser_CFLAGS-$(DEBUG)+=-g -DDEBUG
httpparser_LDFLAGS+=-pthread

hostbin-$(HOST_UTILS)+=ouipasswd
ouipasswd_SOURCES+=ouipasswd.c
ouipasswd_CFLAGS-$(MBEDTLS)+=-DMBEDTLS
ouipasswd_LIBS-$(MBEDTLS)+=mbedcrypto
ouipasswd_CFLAGS-$(DEBUG)+=-g -DDEBUG

sysconf-${FILE_CONFIG}+=ouistiti.conf
