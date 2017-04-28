subdir-$(AUTH)+=libb64.mk md5/md5.mk
subdir-$(MD5_RONRIVEST)+=md5-c/md5.mk

hostbin-$(HOST_UTILS)+=testclient httpparser
testclient_SOURCES+=testclient.c
httpparser_SOURCES+=httpparser.c
httpparser_SOURCES+=../libhttpserver/src/httpserver/libhttpserver.a
httpparser_CFLAGS+=-I../libhttpserver/include/
httpparser_CFLAGS-$(DEBUG)+=-g
httpparser_LDFLAGS+=-pthread

sysconf-${FILE_CONFIG}+=ouistiti.conf
