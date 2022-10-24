BOOTSTRAP_VERSION=5.0.2
BOOTSTRAP_FILES+=$(BOOTSTRAP_DOCS)/bootstrap-5/css/bootstrap.min.css
#BOOTSTRAP_FILES+=$(BOOTSTRAP_DOCS)/bootstrap-5/css/bootstrap.min.css.map
BOOTSTRAP_FILES+=$(BOOTSTRAP_DOCS)/bootstrap-5/js/bootstrap.min.js
BOOTSTRAP_FILES+=$(BOOTSTRAP_DOCS)/bootstrap-5/js/bootstrap.min.js.map
BOOTSTRAP_FILES+=$(BOOTSTRAP_DOCS)/bootstrap-5/js/bootstrap.bundle.min.js
BOOTSTRAP_FILES+=$(BOOTSTRAP_DOCS)/bootstrap-5/js/bootstrap.bundle.min.js.map
data-y+=$(BOOTSTRAP_FILES)

bootstrap-v$(BOOTSTRAP_VERSION).zip:
	wget -c -O $@ https://github.com/twbs/bootstrap/archive/v$(BOOTSTRAP_VERSION).zip || if [ ! -s $@ ]; then rm $@; fi

bootstrap-$(BOOTSTRAP_VERSION)/: bootstrap-v$(BOOTSTRAP_VERSION).zip
	unzip -o $<

$(BOOTSTRAP_FILES): $(BOOTSTRAP_DOCS)/%: bootstrap-$(BOOTSTRAP_VERSION)/
	mkdir -p $(dir $@)
	cp $</dist/$* $@
