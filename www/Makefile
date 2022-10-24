HTDOCS?=htdocs/
CGI_BIN?=cgi-bin/apps/
WEBSOCKET?=websocket/
WEBSTREAM?=webstream/
CERTDIR?=ssl/

data-y+=$(HTDOCS)index.html
data-y+=$(HTDOCS)common/js/jsonrpc.js
data-y+=$(HTDOCS)common/js/cmdbar.js
data-y+=$(HTDOCS)common/js/auth.js

BOOTSTRAP_DOCS?=htdocs/trust
JQUERY_DOCS?=htdocs/trust
export BOOTSTRAP_DOCS JQUERY_DOCS
subdir-$(BOOTSTRAP)+=bootstrap-5.mk
subdir-$(JQUERY)+=jquery.mk

data-$(GLYPHICONS)+=$(HTDOCS)trust/css/glyphicons.css
data-$(GLYPHICONS)+=$(HTDOCS)trust/fonts/glyphicons-halflings-regular.woff2

sysconf-y+=passwd.db
sysconf-y+=filter.db

hook-install-y+=websocket_dir
websocket_dir:
	mkdir -p $(DESTDIR)$(datadir)/$(WEBSOCKET)
hook-install-y+=webstream_dir
webstream_dir:
	mkdir -p $(DESTDIR)$(datadir)/$(WEBSTREAM)
hook-install-y+=conf_link
conf_link:
	rm -f $(DESTDIR)$(datadir)/conf
	ln -sf $(sysconfdir) $(DESTDIR)$(datadir)/conf
hook-install-y+=certs_link
certs_link:
	rm -f $(DESTDIR)$(datadir)/ssl
	ln -sf /etc/ssl/certs $(DESTDIR)$(datadir)/ssl
