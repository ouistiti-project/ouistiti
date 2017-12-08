################################################################################
#
# ouistiti
#
################################################################################

#OUISTITI_VERSION = 1.0
#OUISTITI_SOURCE = v$(OUISTITI_VERSION).tar.gz
#OUISTITI_SITE = https://github.com/ouistiti-project/ouistiti/archive
OUISTITI_VERSION = HEAD
OUISTITI_SITE = https://github.com/ouistiti-project/ouistiti.git
OUISTITI_SITE_METHOD = git
OUISTITI_LICENSE = MIT
OUISTITI_LICENSE_FILES = LICENSE
OUISTITI_DEPENDENCIES += libhttpserver
OUISTITI_DEPENDENCIES += libconfig

OUISTITI_KCONFIG_FILE = ouistiti.config

OUISTITI_CONF_OPTS = \
	--prefix=/usr \
	--sysconfdir=/etc/ouistiti \
	--host=$(TARGET_CC:%gcc=%) \
	--enable-static \
	--disable-dynamic \
	--enable-websocket \
	--disable-websocket-rt \
	--with-vthread-type=fork

TARGET_MAKE_ENV+=LD=$(TARGET_CC) sysroot=$(STAGING_DIR)

ifeq ($(BR2_PACKAGE_LIBHTTPSERVER_MBEDTLS),y)
OUISTITI_DEPENDENCIES += mbedtls
OUISTITI_CONF_OPTS += --enable-mbedtls
else
OUISTITI_CONF_OPTS += --disable-mbedtls
endif

define OUISTITI_CONFIGURE_CMDS
	cd $(@D); ./configure $(OUISTITI_CONF_OPTS)
endef

#OUISTITI_MAKE_OPTS+=DEBUG=y
#OUISTITI_MAKE_OPTS+=VTHREAD_TYPE=pthread

define OUISTITI_BUILD_CMDS
	$(TARGET_CONFIGURE_OPTS) $(TARGET_MAKE_ENV) \
		$(MAKE1) -C $(@D) $(OUISTITI_MAKE_OPTS) clean
	$(TARGET_CONFIGURE_OPTS) V=1 $(TARGET_MAKE_ENV) \
		$(MAKE1) -C $(@D) $(OUISTITI_MAKE_OPTS)
endef

define OUISTITI_INSTALL_TARGET_CMDS
	$(TARGET_CONFIGURE_OPTS) $(TARGET_MAKE_ENV) \
		$(MAKE1) -C $(@D) $(OUISTITI_MAKE_OPTS) \
		DESTDIR=$(TARGET_DIR) install
	$(INSTALL) -d -m 0775 $(TARGET_DIR)/var/run/websocket
	$(INSTALL) -D -m 0755 $(@D)/packages/buildroot/S50ouistiti \
		$(TARGET_DIR)/etc/init.d/S50ouistiti
endef

define OUISTITI_INSTALL_STAGING_CMDS
	$(TARGET_CONFIGURE_OPTS) $(TARGET_MAKE_ENV) \
		$(MAKE1) -C $(@D) $(OUISTITI_MAKE_OPTS) \
		DESTDIR=$(STAGING_DIR) install
endef

define OUISTITI_INSTALL_INIT_SYSV
	$(INSTALL) -D -m 0755 $(@D)/packages/buildroot/S50ouistiti \
		$(TARGET_DIR)/etc/init.d/S50ouistiti
endef


$(eval $(generic-package))

