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

OUISTITI_USERS += www-data

OUISTITI_KCONFIG_FILE = ouistiti.config

OUISTITI_CONF_OPTS = \
	--prefix=/usr \
	--sysconfdir=/etc/ouistiti \
	--enable-static \
	--disable-dynamic \
	--disable-websocket-rt \
	--with-vthread-type=fork \
	--with-libhttpserver-dir=$(BUILD_DIR)/libhttpserver-$(LIBHTTPSERVER_VERSION)

OUISTITI_MAKE_OPTS+=LD=$(TARGET_CC) sysroot=$(STAGING_DIR)

ifeq ($(BR2_PACKAGE_LIBHTTPSERVER_MBEDTLS),y)
OUISTITI_DEPENDENCIES += mbedtls
OUISTITI_CONF_OPTS += --enable-mbedtls
else
OUISTITI_CONF_OPTS += --disable-mbedtls
endif

ifeq ($(BR2_PACKAGE_LIBHTTPSERVER_WEBSOCKET),y)
OUISTITI_CONF_OPTS += --enable-websocket
else
OUISTITI_CONF_OPTS += --disable-websocket
endif

ifeq ($(BR2_PACKAGE_OUISTITI_AUTH),y)
OUISTITI_CONF_OPTS += --enable-auth
else
OUISTITI_CONF_OPTS += --disable-auth
endif

ifeq ($(BR2_PACKAGE_OUISTITI_AUTH_SQLITE),y)
OUISTITI_DEPENDENCIES += sqlite
OUISTITI_CONF_OPTS += --enable-authz-sqlite
else
OUISTITI_CONF_OPTS += --disable-authz-sqlite
endif

ifeq ($(BR2_PACKAGE_OUISTITI_WS_JSONRPC),y)
OUISTITI_CONF_OPTS += --enable-ws-jsonrpc
else
OUISTITI_CONF_OPTS += --disable-ws-jsonrpc
endif

ifeq ($(BR2_PACKAGE_OUISTITI_WS_CHAT),y)
OUISTITI_CONF_OPTS += --enable-ws-chat
else
OUISTITI_CONF_OPTS += --disable-ws-chat
endif

#OUISTITI_MAKE_OPTS+=DEBUG=y

define OUISTITI_CONFIGURE_CMDS
	cd $(@D); ./configure $(OUISTITI_CONF_OPTS)
endef

define OUISTITI_BUILD_CMDS
	$(TARGET_CONFIGURE_OPTS) $(TARGET_MAKE_ENV) \
		$(MAKE1) -C $(@D) $(OUISTITI_MAKE_OPTS) clean
	$(TARGET_CONFIGURE_OPTS) $(TARGET_MAKE_ENV) \
		$(MAKE1) -C $(@D) $(OUISTITI_MAKE_OPTS) V=1
endef

define OUISTITI_INSTALL_TARGET_CMDS
	$(TARGET_CONFIGURE_OPTS) $(TARGET_MAKE_ENV) \
		$(MAKE1) -C $(@D) $(OUISTITI_MAKE_OPTS) \
		DESTDIR=$(TARGET_DIR) install
	$(INSTALL) -d -m 0775 $(TARGET_DIR)/var/run/websocket
	$(INSTALL) -D -m 0755 $(OUISTITI_PKGDIR)/ouistiti.conf \
		$(TARGET_DIR)/etc/ouistiti/ouistiti.conf
endef

define OUISTITI_INSTALL_STAGING_CMDS
	$(TARGET_CONFIGURE_OPTS) $(TARGET_MAKE_ENV) \
		$(MAKE1) -C $(@D) $(OUISTITI_MAKE_OPTS) \
		DESTDIR=$(STAGING_DIR) install
endef

define OUISTITI_INSTALL_INIT_SYSV
	$(INSTALL) -D -m 0755 $(OUISTITI_PKGDIR)/S50ouistiti \
		$(TARGET_DIR)/etc/init.d/S50ouistiti
endef

define OUISTITI_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0644 $(OUISTITI_PKGDIR)/ouistiti.service \
		$(TARGET_DIR)/usr/lib/systemd/system/ouistiti.service

	mkdir -p $(TARGET_DIR)/etc/systemd/system/multi-user.target.wants

	ln -fs ../../../../usr/lib/systemd/system/ouistiti.service \
		$(TARGET_DIR)/etc/systemd/system/multi-user.target.wants/ouistiti.service
endef


$(eval $(generic-package))

