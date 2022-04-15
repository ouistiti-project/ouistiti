################################################################################
#
# ouistiti
#
################################################################################

OUISTITI_VERSION = 3.2.1
OUISTITI_SITE = $(call github,ouistiti-project,ouistiti,ouistiti-$(OUISTITI_VERSION))
OUISTITI_LICENSE = MIT
OUISTITI_LICENSE_FILES = LICENSE
OUISTITI_DEPENDENCIES += libouistiti
OUISTITI_DEPENDENCIES += libconfig
OUISTITI_MAKE=$(MAKE1)

OUISTITI_USERS += www-data
define OUISTITI_USERS
        www-data -1 www-data -1 * - - - http server
endef

ifndef OUISTITI_DEFCONFIG
OUISTITI_DEFCONFIG=fullforked_defconfig
endif

OUISTITI_CONFIGURE_OPTS = \
	LIBHTTPSERVER_NAME=ouistiti \
	package=ouistiti \
	prefix=/usr \
	sysconfdir=/etc/ouistiti

#OUISTITI_MAKE_OPTS+=V=1
#OUISTITI_MAKE_OPTS+=DEBUG=y

ifeq ($(BR2_PACKAGE_OUISTITI_TINYSVCMDNS),y)
  OUISTITI_DEPENDENCIES += tinysvcmdns
endif

ifeq ($(BR2_PACKAGE_OUISTITI_OPENSSL),y)
  OUISTITI_DEPENDENCIES += openssl
  OUISTITI_TLS_OPTS=OPENSSL=y
endif

ifeq ($(BR2_PACKAGE_OUISTITI_MBEDTLS),y)
  OUISTITI_DEPENDENCIES += mbedtls
  OUISTITI_TLS_OPTS=MBEDTLS=y
endif

ifeq ($(BR2_PACKAGE_OUISTITI_AUTH_SQLITE),y)
  OUISTITI_DEPENDENCIES += sqlite
endif
ifeq ($(BR2_PACKAGE_OUISTITI_AUTH_JWT),y)
  OUISTITI_DEPENDENCIES += jansson
endif
ifeq ($(BR2_PACKAGE_OUISTITI_WS_JSONRPC),y)
  OUISTITI_DEPENDENCIES += jansson
endif

ifeq (y,$(BR2_SHARED_LIBS))
  OUISTITI_CONFIGURE_OPTS+=MODULES=y
  OUISTITI_CONFIGURE_OPTS+=SHARED=y
  OUISTITI_CONFIGURE_OPTS+=STATIC=n
endif
ifeq (y,$(BR2_STATIC_LIBS))
  OUISTITI_CONFIGURE_OPTS+=MODULES=n
  OUISTITI_CONFIGURE_OPTS+=SHARED=n
  OUISTITI_CONFIGURE_OPTS+=STATIC=y
endif
ifeq (y,$(BR2_SHARED_STATIC_LIBS))
  OUISTITI_CONFIGURE_OPTS+=MODULES=y
  OUISTITI_CONFIGURE_OPTS+=SHARED=y
  OUISTITI_CONFIGURE_OPTS+=STATIC=y
endif

OUISTITI_CONFIGURE_OPTS+=USE_PTHREAD=$(BR2_TOOLCHAIN_HAS_THREADS)

OUISTITI_CONFIGURE_OPTS+=TINYSVCMDNS=$(BR2_PACKAGE_OUISTITI_TINYSVCMDNS)
OUISTITI_CONFIGURE_OPTS+=OPENSSL=n MBEDTLS=n $(OUISTITI_TLS_OPTS)
OUISTITI_CONFIGURE_OPTS+=AUTH=$(BR2_PACKAGE_OUISTITI_AUTH) AUTHZ_SIMPLE=$(BR2_PACKAGE_OUISTITI_AUTH)
OUISTITI_CONFIGURE_OPTS+=AUTHZ_SQLITE=$(BR2_PACKAGE_OUISTITI_AUTH_SQLITE)
OUISTITI_CONFIGURE_OPTS+=AUTHZ_UNIX=$(BR2_PACKAGE_OUISTITI_AUTH_UNIX)
OUISTITI_CONFIGURE_OPTS+=USE_REENTRANT=$(BR2_TOOLCHAIN_USES_UCLIBC)
OUISTITI_CONFIGURE_OPTS+=AUTH_TOKEN=$(BR2_PACKAGE_OUISTITI_AUTH_TOKEN)
OUISTITI_CONFIGURE_OPTS+=AUTHZ_JWT=$(BR2_PACKAGE_OUISTITI_AUTH_JWT)
OUISTITI_CONFIGURE_OPTS+=AUTHN_BASIC=$(BR2_PACKAGE_OUISTITI_AUTH_BASIC)
OUISTITI_CONFIGURE_OPTS+=AUTHN_DIGEST=$(BR2_PACKAGE_OUISTITI_AUTH_DIGEST)
OUISTITI_CONFIGURE_OPTS+=AUTHN_BEARER=$(BR2_PACKAGE_OUISTITI_AUTH_BEARER)
OUISTITI_CONFIGURE_OPTS+=AUTHN_OAUTH2=$(BR2_PACKAGE_OUISTITI_AUTH_OAUTH2)
OUISTITI_CONFIGURE_OPTS+=DOCUMENT=$(BR2_PACKAGE_OUISTITI_DOCUMENT)
OUISTITI_CONFIGURE_OPTS+=DOCUMENTREST=$(BR2_PACKAGE_OUISTITI_DOCUMENT_REST)
OUISTITI_CONFIGURE_OPTS+=RANGEREQUEST=$(BR2_PACKAGE_OUISTITI_DOCUMENT_RANGE)
OUISTITI_CONFIGURE_OPTS+=DOCUMENTHOME=$(BR2_PACKAGE_OUISTITI_DOCUMENT_HOME)
OUISTITI_CONFIGURE_OPTS+=CGI=$(BR2_PACKAGE_OUISTITI_CGI)
OUISTITI_CONFIGURE_OPTS+=WEBSOCKET=$(BR2_PACKAGE_OUISTITI_WEBSOCKET)
OUISTITI_CONFIGURE_OPTS+=WS_JSONRPC=$(BR2_PACKAGE_OUISTITI_WS_JSONRPC)
OUISTITI_CONFIGURE_OPTS+=WS_CHAT=$(BR2_PACKAGE_OUISTITI_WS_CHAT)
OUISTITI_CONFIGURE_OPTS+=WEBSTREAM=$(BR2_PACKAGE_OUISTITI_WEBSTREAM)
OUISTITI_CONFIGURE_OPTS+=

define OUISTITI_CONFIGURE_CMDS
	$(TARGET_CONFIGURE_OPTS) $(TARGET_MAKE_ENV) \
		$(MAKE1) -C $(@D) $(OUISTITI_CONFIGURE_OPTS) defconfig
endef

define OUISTITI_BUILD_CMDS
	$(TARGET_CONFIGURE_OPTS) $(TARGET_MAKE_ENV) \
		$(MAKE1) -C $(@D) $(OUISTITI_MAKE_OPTS)
endef

define OUISTITI_INSTALL_TARGET_CMDS
	$(MAKE) -C $(@D) $(OUISTITI_MAKE_OPTS) \
		DESTDIR="$(TARGET_DIR)" DEVINSTALL=n install
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

$(eval $(generic-package))
