################################################################################
#
# OUILOGIN
#
################################################################################

#OUILOGIN_VERSION = v2.4
#OUILOGIN_SITE = $(call github,ouistiti-project,libhttpserver,$(OUILOGIN_VERSION))
OUILOGIN_VERSION = HEAD
OUILOGIN_SITE = https://github.com/ouistiti-project/ouilogin
OUILOGIN_SITE_METHOD = git
OUILOGIN_LICENSE = MIT
OUILOGIN_LICENSE_FILES = LICENSE

OUILOGIN_DEPENDENCIES += ouistiti

define OUILOGIN_CONFIGURE_CMDS
	$(MAKE) -C $(@D) sysconfdir=/etc/ouistiti datadir=/srv/www-ouilogin defconfig
endef

define OUILOGIN_INSTALL_TARGET_CMDS
	$(MAKE) -C $(@D)  DESTDIR=$(TARGET_DIR) install
endef

$(eval $(generic-package))
