################################################################################
#
# ouistiti
#
################################################################################

OUISTITI_VERSION = 1.0
OUISTITI_SOURCE = ouistiti-full-$(OUISTITI_VERSION).tar.gz
OUISTITI_SITE = https://github.com/ouistiti-net/ouistiti/releases/download/ouistiti-$(OUISTITI_VERSION)
OUISTITI_LICENSE = MIT
OUISTITI_LICENSE_FILES = LICENSE
OUISTITI_DEPENDENCIES = libconfig

OUISTITI_KCONFIG_FILE = ouistiti.config

OUISTITI_CONF_OPTS = \
	--prefix=/usr \
	--libdir=/usr/lib/ouistiti \
	--sysconfdir=/etc \
	--host=$(TARGET_CC:%gcc=%) \
	--disable-dynamic \
	--enable-static

TARGET_MAKE_ENV+=LD=$(TARGET_CC)

ifeq ($(BR2_PACKAGE_OUISTITI_MBEDTLS),y)
OUISTITI_DEPENDENCIES += mbedtls
OUISTITI_CONF_OPTS += --enable-mbedtls
else
OUISTITI_CONF_OPTS += --disable-mbedtls
endif

define OUISTITI_CONFIGURE_CMDS
	cd $(@D); ./configure $(OUISTITI_CONF_OPTS)
endef

define OUISTITI_BUILD_CMDS
	$(TARGET_CONFIGURE_OPTS) $(TARGET_MAKE_ENV) \
		$(MAKE1) -C $(@D) V=1 $(OUISTITI_MAKE_OPTS)
endef

define OUISTITI_INSTALL_TARGET_CMDS
	$(TARGET_CONFIGURE_OPTS) $(TARGET_MAKE_ENV) \
		$(MAKE1) -C $(@D) $(OUISTITI_MAKE_OPTS) \
		DESTDIR=$(TARGET_DIR) install
endef

$(eval $(generic-package))
