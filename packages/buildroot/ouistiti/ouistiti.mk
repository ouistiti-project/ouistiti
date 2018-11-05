################################################################################
#
# ouistiti
#
################################################################################

#OUISTITI_VERSION = 2.0
#OUISTITI_SOURCE = v$(OUISTITI_VERSION).tar.gz
#OUISTITI_SITE = https://github.com/ouistiti-project/ouistiti/archive
OUISTITI_VERSION = HEAD
OUISTITI_SITE = https://github.com/ouistiti-project/ouistiti.git
OUISTITI_SITE_METHOD = git
OUISTITI_LICENSE = MIT
OUISTITI_LICENSE_FILES = LICENSE
OUISTITI_DEPENDENCIES += libhttpserver
OUISTITI_DEPENDENCIES += libconfig
OUISTITI_MAKE=$(MAKE1)

OUISTITI_USERS += www-data

OUISTITI_OVERRIDE_SRCDIR=$(BR2_EXTERNAL_MALTESE_PATH)/../ouistiti

OUISTITI_KCONFIG_FILE = $(call qstrip,$(OUISTITI_PKGDIR)/default.config)
OUISTITI_MAKE_OPTS = \
	ARCH=$(KERNEL_ARCH) \
	SYSROOT=$(STAGING_DIR) \
	DESTDIR="$(TARGET_DIR)"

#OUISTITI_MAKE_OPTS+=V=1

ifeq ($(BR2_PACKAGE_LIBHTTPSERVER_MBEDTLS),y)
OUISTITI_DEPENDENCIES += mbedtls
OUISTITI_MBEDTLS_OPTS=$(call KCONFIG_ENABLE_OPT,MBEDTLS,$(@D)/.config)
else
OUISTITI_MBEDTLS_OPTS=$(call KCONFIG_DISABLE_OPT,MBEDTLS,$(@D)/.config)
endif

ifeq ($(BR2_PACKAGE_LIBHTTPSERVER_WEBSOCKET),y)
OUISTITI_WEBDSOCKET_OPTS=$(call KCONFIG_ENABLE_OPT,WEBSOCKET,$(@D)/.config)
else
OUISTITI_WEBDSOCKET_OPTS=$(call KCONFIG_DISABLE_OPT,WEBSOCKET,$(@D)/.config)
endif

ifeq ($(BR2_PACKAGE_OUISTITI_AUTH),y)
OUISTITI_AUTH_OPTS=$(call KCONFIG_ENABLE_OPT,AUTH,$(@D)/.config)
else
OUISTITI_AUTH_OPTS=$(call KCONFIG_DISABLE_OPT,AUTH,$(@D)/.config)
endif

ifeq ($(BR2_PACKAGE_OUISTITI_AUTH_SQLITE),y)
OUISTITI_DEPENDENCIES += sqlite
OUISTITI_AUTH_SQLITE_OPTS=$(call KCONFIG_ENABLE_OPT,AUTHZ_SQLITE,$(@D)/.config)
else
OUISTITI_AUTH_SQLITE_OPTS=$(call KCONFIG_ENABLE_OPT,AUTHZ_SQLITE,$(@D)/.config)
endif

ifeq ($(BR2_PACKAGE_OUISTITI_WS_JSONRPC),y)
OUISTITI_WS_JSONRPC_OPTS=$(call KCONFIG_ENABLE_OPT,WS_JSONRPC,$(@D)/.config)
OUISTITI_DEPENDENCIES += jansson
else
OUISTITI_WS_JSONRPC_OPTS=$(call KCONFIG_DISABLE_OPT,WS_JSONRPC,$(@D)/.config)
endif

ifeq ($(BR2_PACKAGE_OUISTITI_WS_CHAT),y)
OUISTITI_WS_CHAT_OPTS=$(call KCONFIG_ENABLE_OPT,WS_CHAT,$(@D)/.config)
else
OUISTITI_WS_CHAT_OPTS=$(call KCONFIG_DISABLE_OPT,WS_CHAT,$(@D)/.config)
endif

OUISTITI_MAKE_OPTS+=DEBUG=y

define OUISTITI_KCONFIG_FIXUP_CMDS
	$(OUISTITI_MBEDTLS_OPTS)
	$(OUISTITI_WEBDSOCKET_OPTS)
	$(OUISTITI_AUTH_OPTS)
	$(OUISTITI_AUTH_SQLITE_OPTS)
	$(OUISTITI_WS_JSONRPC_OPTS)
	$(OUISTITI_WS_CHAT_OPTS)
endef

define OUISTITI_BUILD_CMDS
	$(TARGET_CONFIGURE_OPTS) $(TARGET_MAKE_ENV) \
		$(MAKE1) -C $(@D) $(OUISTITI_MAKE_OPTS)
endef

define OUISTITI_INSTALL_TARGET_CMDS
	$(MAKE) -C $(@D) $(OUISTITI_MAKE_OPTS) install
endef

define OUISTITI_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0644 $(OUISTITI_PKGDIR)/ouistiti.conf \
		$(TARGET_DIR)/etc/ouistiti/ouistiti.conf
	$(INSTALL) -D -m 644 $(OUISTITI_PKGDIR)/ouistiti.service \
		$(TARGET_DIR)/usr/lib/systemd/system/ouistiti.service
	mkdir -p $(TARGET_DIR)/etc/systemd/system/multi-user.target.wants
	ln -fs ../../../../usr/lib/systemd/system/ouistiti.service \
		$(TARGET_DIR)/etc/systemd/system/multi-user.target.wants/ouistiti.service
endef
define OUISTITI_INSTALL_INIT_SYSV
	$(INSTALL) -D -m 0644 $(OUISTITI_PKGDIR)/ouistiti.conf \
		$(TARGET_DIR)/etc/ouistiti/ouistiti.conf
	$(INSTALL) -D -m 755 $(OUISTITI_PKGDIR)/S50ouistiti \
		$(TARGET_DIR)/etc/init.d/S50ouistiti
endef

$(eval $(kconfig-package))
#$(eval $(autotools-package))
