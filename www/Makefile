datadir:=$(datadir)/$(WEBCOMMON_PATH)
CERTDIR?=ssl/

BOOTSTRAP_DOCS?=htdocs/trust
JQUERY_DOCS?=htdocs/trust
export BOOTSTRAP_DOCS JQUERY_DOCS
subdir-$(BOOTSTRAP)+=bootstrap-5.mk
subdir-$(JQUERY)+=jquery.mk

data-$(GLYPHICONS)+=htdocs/trust/css/glyphicons.css
data-$(GLYPHICONS)+=htdocs/trust/fonts/glyphicons-halflings-regular.woff2

subdir-$(WEBCOMMON_EXTRA)+=extra.mk

sysconf-y+=passwd.db
sysconf-y+=filter.db

WEBSOCKET?=websocket/
hook-install-$(WEBCOMMON)+=websocket_dir
websocket_dir:
	mkdir -p $(DESTDIR)$(datadir)/$(WEBCOMMON_PATH)/$(WEBSOCKET)

WEBSTREAM?=webstream/
hook-install-y+=webstream_dir
webstream_dir:
	mkdir -p $(DESTDIR)$(datadir)/$(WEBSTREAM)

CGI_BIN?=cgi-bin/apps/
hook-install-y+=cgibin_dir
cgibin_dir:
	mkdir -p $(DESTDIR)$(datadir)/$(CGI_BIN)

hook-install-y+=conf_link
conf_link:
	rm -f $(DESTDIR)$(datadir)/conf
	ln -sf $(sysconfdir) $(DESTDIR)$(datadir)/conf
hook-install-y+=certs_link
certs_link:
	rm -f $(DESTDIR)$(datadir)/ssl
	ln -sf /etc/ssl/certs $(DESTDIR)$(datadir)/ssl
