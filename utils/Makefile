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
sysconf-${CERTIFICATE}+=ouistiti_ca.crt
ouistiti_ca.crt_GENERATED+=$(objdir)ouistiti_ca.crt
ouistiti_ca.crt_GENERATED+=$(objdir)ouistiti_ca.key
ouistiti_ca.crt_GENERATED+=$(objdir)index
ouistiti_ca.crt_GENERATED+=$(objdir)index.attr
ouistiti_ca.crt_GENERATED+=$(objdir)index.old
ouistiti_ca.crt_GENERATED+=$(objdir)serial
ouistiti_ca.crt_GENERATED+=$(objdir)serial.old
ouistiti_ca.crt_GENERATED+=$(objdir)01.pem
sysconf-${CERTIFICATE}+=ouistiti_srv.key
sysconf-${CERTIFICATE}+=ouistiti_srv.crt
ouistiti_srv.crt_GENERATED+=$(objdir)ouistiti_srv.key
ouistiti_srv.crt_GENERATED+=$(objdir)ouistiti_srv.crt
ouistiti_srv.crt_GENERATED+=$(objdir)ouistiti_srv.csr
ouistiti_srv.crt_GENERATED+=$(objdir)ouistiti_ca.conf
sysconf-${CERTIFICATE}+=ouistiti_dhparam.key
ouistiti_dhparam.key_GENERATED=$(objdir)ouistiti_dhparam.key

SERVER?=www.ouistiti.net
CRTLEN=2048

ouistiti_ca.crt:
	$(Q)openssl req -newkey rsa:$(CRTLEN) -days 3650 -x509 -nodes -out $(@:%.key=%.crt) -keyout $(@:%.crt=%.key) -subj '/CN=Certificate authority/'

$(objdir)index:
	$(Q)touch $@

$(objdir)serial:
	$(Q)echo 0001 > $@

$(objdir)ouistiti_ca.conf: ca.conf $(objdir)index $(objdir)serial $(objdir)ouistiti_ca.crt
	$(Q)cat $< | sed "s,%CA_PEM%,$(objdir)ouistiti_ca.crt," \
			| sed "s,%CA_KEY%,$(objdir)ouistiti_ca.key," \
			| sed "s,%INDEX%,$(objdir)index," \
			| sed "s,%SERIAL%,$(objdir)serial," > $@

ouistiti_srv.key:
	$(Q)openssl req -newkey rsa:$(CRTLEN) -nodes -out $(@:%.key=%.csr) -keyout $(@:%.csr=%.key) -subj "/CN=$(SERVER)/"

ouistiti_srv.crt: ouistiti_srv.key $(objdir)ouistiti_srv.csr $(objdir)ouistiti_ca.conf
	$(Q)openssl ca -batch -config $(objdir)ouistiti_ca.conf -notext -in $(objdir)ouistiti_srv.csr -out $@

ouistiti_dhparam.key:
	$(Q)openssl dhparam 4096 > $@

