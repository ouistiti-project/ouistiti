JQUERY_VERSION=3.6.0
JQUERY_DOCS?=htdocs
JQUERY_FILES+=$(JQUERY_DOCS)/js/jquery-$(JQUERY_VERSION).min.js

data-y+=$(JQUERY_FILES)

jquery-$(JQUERY_VERSION).min.js:
	wget -c -O $@ https://code.jquery.com/$@

$(JQUERY_FILES): jquery-$(JQUERY_VERSION).min.js
	$(Q)mkdir -p $(@D)
	$(Q)mv -f $< $@

$(JQUERY_DOCS)/js/jquery-$(JQUERY_VERSION).min.js_ALIAS+=jquery.min.js
