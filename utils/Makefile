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
httpparser_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
httpparser_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
httpparser_CFLAGS-$(DEBUG)+=-g -DDEBUG
httpparser_LDFLAGS+=-pthread

hostbin-$(HOST_UTILS)+=ouipasswd
ouipasswd_SOURCES+=ouipasswd.c
ouipasswd_CFLAGS-$(MBEDTLS)+=-DMBEDTLS
ouipasswd_LIBS-$(MBEDTLS)+=mbedcrypto
ouipasswd_CFLAGS-$(DEBUG)+=-g -DDEBUG

sysconf-${FILE_CONFIG}+=ouistiti.conf
sysconf-${CERTIFICATE}+=ouistiti_ca.crt
sysconf-${CERTIFICATE}+=ouistiti_srv.crt
sysconf-${CERTIFICATE}+=ouistiti_srv.key
sysconf-${CERTIFICATE}+=ouistiti_dhparam.key

SERVER?=ouistiti.net

ouistiti_ca.crt:
	$(Q)openssl req -newkey rsa:2048 -days 3650 -x509 -nodes -out $@ -keyout $(@:%.crt=%.key) -subj '/CN=Certificate authority/'

index:
	$(Q)touch $@

serial:
	$(Q)echo 0001 > $@

ouistiti_ca.conf: ca.conf index serial ouistiti_ca.crt
	$(Q)cat $< | sed 's/%CA_PEM%/ouistiti_ca.crt/' \
			| sed 's/%CA_KEY%/ouistiti_ca.key/' \
			| sed 's/%INDEX%/.\/index/' \
			| sed 's/%SERIAL%/.\/serial/' > $@

ouistiti_srv.csr ouistiti_srv.key:
	$(Q)openssl req -newkey rsa:1024 -nodes -out $(@:%.key=%.csr) -keyout $(@:%.csr=%.key) -subj "/CN=$(SERVER)/"

ouistiti_srv.crt: ouistiti_srv.csr ouistiti_ca.conf
	$(Q)openssl ca -batch -config ouistiti_ca.conf -notext -in $< -out $@

ouistiti_dhparam.key:
	$(Q)openssl dhparam 4096 > $@
