################################################################################
#
# libhttpserver
#
################################################################################

#LIBHTTPSERVER_VERSION = 1.0
#LIBHTTPSERVER_SOURCE = v$(LIBHTTPSERVER_VERSION).tar.gz
#LIBHTTPSERVER_SITE = https://github.com/ouistiti-project/libhttpserver/archive
LIBHTTPSERVER_VERSION = HEAD
LIBHTTPSERVER_SITE = https://github.com/ouistiti-project/libhttpserver.git
LIBHTTPSERVER_SITE_METHOD = git
LIBHTTPSERVER_LICENSE = MIT
LIBHTTPSERVER_LICENSE_FILES = LICENSE
LIBHTTPSERVER_INSTALL_STAGING = YES

LIBHTTPSERVER_KCONFIG_FILE = libhttpserver.config

LIBHTTPSERVER_CONF_OPTS = \
	--prefix=/usr \
	--libdir=/usr/lib/ouistiti \
	--sysconfdir=/etc/ouistiti \
	--host=$(TARGET_CC:%gcc=%) \
	--enable-static \
	--disable-dynamic \
	--enable-websocket \
	--enable-libutils \
	--with-vthread-type=fork

TARGET_MAKE_ENV+=LD=$(TARGET_CC) sysroot=$(STAGING_DIR)

ifeq ($(BR2_PACKAGE_LIBHTTPSERVER_MBEDTLS),y)
LIBHTTPSERVER_DEPENDENCIES += mbedtls
LIBHTTPSERVER_CONF_OPTS += --enable-mbedtls
else
LIBHTTPSERVER_CONF_OPTS += --disable-mbedtls
endif

#LIBHTTPSERVER_MAKE_OPTS+=VTHREAD_TYPE=pthread
#LIBHTTPSERVER_MAKE_OPTS+=DEBUG=y

define LIBHTTPSERVER_CONFIGURE_CMDS
	cd $(@D); ./configure $(LIBHTTPSERVER_CONF_OPTS)
endef

define LIBHTTPSERVER_BUILD_CMDS
	$(TARGET_CONFIGURE_OPTS) $(TARGET_MAKE_ENV) \
		$(MAKE1) -C $(@D) $(LIBHTTPSERVER_MAKE_OPTS) clean
	$(TARGET_CONFIGURE_OPTS) $(TARGET_MAKE_ENV) \
		$(MAKE1) -C $(@D) $(LIBHTTPSERVER_MAKE_OPTS)
endef

define LIBHTTPSERVER_INSTALL_TARGET_CMDS
		$(MAKE1) -C $(@D) $(LIBHTTPSERVER_MAKE_OPTS) \
		DESTDIR=$(TARGET_DIR) install
endef

define LIBHTTPSERVER_INSTALL_STAGING_CMDS
		$(MAKE1) -C $(@D) $(LIBHTTPSERVER_MAKE_OPTS) \
		DESTDIR=$(STAGING_DIR) install
endef


$(eval $(generic-package))
