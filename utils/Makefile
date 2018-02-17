ifneq ($(MBEDTLS),y)
subdir-$(AUTH)+=libb64.mk md5/md5.mk
subdir-$(MD5_RONRIVEST)+=md5-c/md5.mk
endif
subdir-$(WEBSOCKET)+=websocket.mk
subdir-$(WEBSTREAM)+=webstream.mk

hostbin-$(HOST_UTILS)+=testclient
testclient_SOURCES+=testclient.c

ifeq ($(HTTPCLIENT_FEATURES),y)
hostbin-$(HOST_UTILS)+=httpparser
endif
httpparser_SOURCES+=httpparser.c
httpparser_LIBS+=httpserver
httpparser_CFLAGS+=-I../libhttpserver/include/
httpparser_CFLAGS-$(DEBUG)+=-g -DDEBUG
httpparser_LDFLAGS+=-pthread

hostbin-$(HOST_UTILS)+=ouipasswd
ouipasswd_SOURCES+=ouipasswd.c
ouipasswd_CFLAGS-$(MBEDTLS)+=-DMBEDTLS
ouipasswd_LIBS-$(MBEDTLS)+=mbedcrypto
ouipasswd_CFLAGS-$(DEBUG)+=-g -DDEBUG

sysconf-${FILE_CONFIG}+=ouistiti.conf
