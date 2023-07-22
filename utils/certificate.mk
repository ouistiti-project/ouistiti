sysconf-y+=ouistiti_ca.crt
ouistiti_ca.crt_GENERATED+=$(objdir)ouistiti_ca.crt
ouistiti_ca.crt_GENERATED+=$(objdir)ouistiti_ca.key
ouistiti_ca.crt_GENERATED+=$(objdir)index
ouistiti_ca.crt_GENERATED+=$(objdir)index.attr
ouistiti_ca.crt_GENERATED+=$(objdir)index.old
ouistiti_ca.crt_GENERATED+=$(objdir)serial
ouistiti_ca.crt_GENERATED+=$(objdir)serial.old
ouistiti_ca.crt_GENERATED+=$(objdir)01.pem
sysconf-y+=ouistiti_srv.key
sysconf-y+=ouistiti_srv.crt
ouistiti_srv.crt_GENERATED+=$(objdir)ouistiti_srv.key
ouistiti_srv.crt_GENERATED+=$(objdir)ouistiti_srv.crt
ouistiti_srv.crt_GENERATED+=$(objdir)ouistiti_srv.csr
ouistiti_srv.crt_GENERATED+=$(objdir)ouistiti_ca.conf
sysconf-y+=ouistiti_dhparam.key
ouistiti_dhparam.key_GENERATED=$(objdir)ouistiti_dhparam.key

SERVER?=www.ouistiti.net
CRTLEN=2048

ifeq ($(V),1)
	Q=
else
	Q=@
endif

sysconfdir?=/etc/ouistiti
generate: cleangenerate $(sysconf-y)
	$(Q)install -d ouistiti_ca.crt $(sysconfdir)/ouistiti_ca.crt
	$(Q)install -d ouistiti_srv.key $(sysconfdir)/ouistiti_srv.key
	$(Q)install -d ouistiti_srv.crt $(sysconfdir)/ouistiti_srv.crt
	$(Q)install -d ouistiti_dhparam.key $(sysconfdir)/ouistiti_dhparam.key
cleangenerate:
	$(foreach f,$(sysconf-y),rm -f $(f);)
	$(Q)rm -f $(objdir)index* $(objdir)serial* $(objdir)ouistiti_ca.key  $(objdir)ouistiti_ca.conf 

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

