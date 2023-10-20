DL?=$(builddir)/.dl
$(foreach dl,$(download-y),$(if $($(dl)_SOURCE),, \
	$(eval $(dl)_SOURCE:=$(notdir $($(dl)_SITE))) \
	$(eval $(dl)_SITE:=$(dir $($(dl)_SITE)))))
$(foreach dl,$(download-y),$(eval $(dl)_URL=$($(dl)_SITE)$($(dl)_SOURCE:%=/%)))
$(foreach dl,$(download-y),$(if $(findstring .zip,$($(dl)_SOURCE)),$(eval $(dl)_SITE_METHOD:=zip)))
$(foreach dl,$(download-y),$(if $(findstring .tar,$($(dl)_SOURCE)),$(eval $(dl)_SITE_METHOD:=tar)))

$(foreach dl,$(download-y),$(eval $($(dl)_SITE_METHOD)download-target+=$(objdir)$(dl)))

targets+=$(download-target)
targets+=$(zipdownload-target)
targets+=$(tardownload-target)
targets+=$(gitdownload-target)

###############################################################################
# Commands for download
##

DL_DIR:=$(DL:%/=%)/
quiet_cmd_download=DOWNLOAD $*
define cmd_download
	echo $*
	echo 'wget -q -O' $(DL_DIR)$2 $($2_URL)
	wget -q -O $(DL_DIR)$2/$($2_SOURCE) $($2_URL)
endef

quiet_cmd_gitclone=CLONE $*
define cmd_gitclone
git clone --depth 1 $($*_SITE) $($*_VERSION:%=-b %) $(DL_DIR)$*
endef

ifneq ($(download-y),)
$(shell $(MKDIR) $(DL_DIR))
endif

.SECONDEXPANSION:
$(DL_DIR)%:
	@$(call qcmd,mkdir,$(dir $@))
	@$(call cmd,download,$(patsubst %/,%,$(dir $*)))

$(tardownload-target): $(objdir)%: $(DL_DIR)%
	tar -xf $< -C $@
	
$(zipdownload-target): $(objdir)%: $(DL_DIR)%/$$(%_SOURCE) FORCE
	unzip -o -d $@ $<

$(download-target): $(objdir)%: $(DL_DIR)%/$$(%_SOURCE)
	@$(call qcmd,mkdir,$(dir $@))
	@cp $< $(dir $@)

$(gitdownload-target): $(objdir)%:
	@$(call cmd,gitclone)
	@ln -snf $(DL_DIR)$* $@
