JQUERY_VERSION=3.6.0
JQUERY_DOCS?=srv/www/htdocs
JQUERY_FILES+=$(JQUERY_DOCS)/js/jquery-$(JQUERY_VERSION).min.js

download-y+=jquery
jquery_SITE?=https://code.jquery.com
jquery_SOURCE=jquery-$(JQUERY_VERSION).min.js

data-y+=$(JQUERY_FILES)

$(JQUERY_FILES): $(JQUERY_DOCS)/js/%:
	$(Q)mkdir -p $(@D)
	$(Q)mv -f $* $@

$(JQUERY_DOCS)/js/jquery-$(JQUERY_VERSION).min.js_ALIAS+=jquery.min.js
