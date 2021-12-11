################################################################################
#
# OUICLOUD
#
################################################################################

#OUICLOUD_VERSION = v2.4
#OUICLOUD_SITE = $(call github,ouistiti-project,libhttpserver,$(OUICLOUD_VERSION))
OUICLOUD_VERSION = HEAD
OUICLOUD_SITE = https://github.com/ouistiti-project/ouicloud
OUICLOUD_SITE_METHOD = git
OUICLOUD_LICENSE = MIT
OUICLOUD_LICENSE_FILES = LICENSE

OUILOGIN_DEPENDENCIES += ouistiti

define OUICLOUD_CONFIGURE_CMDS
	$(MAKE) -C $(@D) sysconfdir=/etc/ouistiti datadir=/srv/www defconfig
endef

define OUICLOUD_INSTALL_CMDS
	$(MAKE) -C $(@D) DESTDIR=$(TARGET_DIR) install
endef
$(eval $(generic-package))
