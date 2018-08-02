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

OUISTITI_KCONFIG_FILE = $(call qstrip,$(OUISTITI_PKGDIR)/config)
OUISTITI_KCONFIG_OPTS = \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	ARCH=$(KERNEL_ARCH) \
	DESTDIR="$(TARGET_DIR)" \

OUISTITI_CONF_OPTS = \
	--sysroot=$(STAGING_DIR) \
	--prefix=/usr \
	--sysconfdir=/etc/ouistiti \
	--enable-static \
	--disable-shared \
	--disable-error \
	--disable-check \
	--disable-websocket-rt \
	--with-vthread-type=fork \
	--with-libhttpserver-dir=$(BUILD_DIR)/libhttpserver-$(LIBHTTPSERVER_VERSION)

OUISTITI_MAKE_OPTS+=V=1

ifeq ($(BR2_PACKAGE_LIBHTTPSERVER_MBEDTLS),y)
OUISTITI_DEPENDENCIES += mbedtls
OUISTITI_CONF_OPTS += --enable-mbedtls
OUISTITI_KCONFIG_OPTS+=MBEDTLS=y
else
OUISTITI_CONF_OPTS += --disable-mbedtls
OUISTITI_KCONFIG_OPTS+=MBEDTLS=n
endif

ifeq ($(BR2_PACKAGE_LIBHTTPSERVER_WEBSOCKET),y)
OUISTITI_CONF_OPTS += --enable-websocket
OUISTITI_KCONFIG_OPTS+=WEBDSOCKET=y
else
OUISTITI_CONF_OPTS += --disable-websocket
OUISTITI_KCONFIG_OPTS+=WEBDSOCKET=n
endif

ifeq ($(BR2_PACKAGE_OUISTITI_AUTH),y)
OUISTITI_CONF_OPTS += --enable-auth
OUISTITI_KCONFIG_OPTS+=AUTH=y
else
OUISTITI_CONF_OPTS += --disable-auth
OUISTITI_KCONFIG_OPTS+=AUTH=n
endif

ifeq ($(BR2_PACKAGE_OUISTITI_AUTH_SQLITE),y)
OUISTITI_DEPENDENCIES += sqlite
OUISTITI_CONF_OPTS += --enable-authz-sqlite
OUISTITI_KCONFIG_OPTS+=AUTH_SQLITE=y
else
OUISTITI_CONF_OPTS += --disable-authz-sqlite
OUISTITI_KCONFIG_OPTS+=AUTH_SQLITE=n
endif

ifeq ($(BR2_PACKAGE_OUISTITI_WS_JSONRPC),y)
OUISTITI_CONF_OPTS += --enable-ws-jsonrpc
OUISTITI_KCONFIG_OPTS+=WS_JSONRPC=y
else
OUISTITI_CONF_OPTS += --disable-ws-jsonrpc
OUISTITI_KCONFIG_OPTS+=WS_JSONRPC=n
endif

ifeq ($(BR2_PACKAGE_OUISTITI_WS_CHAT),y)
OUISTITI_CONF_OPTS += --enable-ws-chat
OUISTITI_KCONFIG_OPTS+=WS_CHAT=y
else
OUISTITI_CONF_OPTS += --disable-ws-chat
OUISTITI_KCONFIG_OPTS+=WS_CHAT=n
endif

#OUISTITI_MAKE_OPTS+=DEBUG=y

define OUISTITI_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0644 $(OUISTITI_PKGDIR)/ouistiti.conf \
		$(TARGET_DIR)/etc/ouistiti/ouistiti.conf
endef

define OUISTITI_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 644 $(OUISTITI_PKGDIR)/ouistiti.service \
		$(TARGET_DIR)/usr/lib/systemd/system/ouistiti.service
	mkdir -p $(TARGET_DIR)/etc/systemd/system/multi-user.target.wants
	ln -fs ../../../../usr/lib/systemd/system/ouistiti.service \
		$(TARGET_DIR)/etc/systemd/system/multi-user.target.wants/ouistiti.service
endef
define OUISTITI_INSTALL_INIT_SYSV
	$(INSTALL) -D -m 755 $(OUISTITI_PKGDIR)/S50ouistiti \
		$(TARGET_DIR)/etc/init.d/S50ouistiti
endef

#$(eval $(kconfig-package))
$(eval $(autotools-package))

