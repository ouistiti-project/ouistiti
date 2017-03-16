subdir-$(AUTH)+=libb64.mk

bin-y+=testclient httpparser
testclient_SOURCES+=testclient.c
httpparser_SOURCES+=httpparser.c
httpparser_SOURCES+=../libhttpserver/src/httpserver/libhttpserver.a
httpparser_CFLAGS+=-I../libhttpserver/include/
httpparser_CFLAGS-$(DEBUG)+=-g
httpparser_LDFLAGS+=-pthread

sysconf-${FILE_CONFIG}+=ouistiti.conf
