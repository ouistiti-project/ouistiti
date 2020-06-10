################################################################################
#
# ouistiti
#
################################################################################

#OUISTITI_VERSION = 2.4
#OUISTITI_SOURCE = v$(OUISTITI_VERSION).tar.gz
#OUISTITI_SITE = https://github.com/ouistiti-project/ouistiti/archive
OUISTITI_VERSION = HEAD
OUISTITI_SITE = https://github.com/ouistiti-project/ouistiti.git
OUISTITI_SITE_METHOD = git
OUISTITI_LICENSE = MIT
OUISTITI_LICENSE_FILES = LICENSE
OUISTITI_DEPENDENCIES += libouistiti
OUISTITI_DEPENDENCIES += libconfig
OUISTITI_MAKE=$(MAKE1)

OUISTITI_USERS += www-data

ifndef OUISTITI_DEFCONFIG
OUISTITI_DEFCONFIG=fullforked_defconfig
endif

OUISTITI_MAKE_OPTS = \
	LIBHTTPSERVER_NAME=ouistiti \
	package=ouistiti \
	prefix=/usr \
	libdir=/usr/lib/ouistiti \
	sysconfdir=/etc/ouistiti \
	ARCH=$(KERNEL_ARCH) \
	SYSROOT=$(STAGING_DIR)

#OUISTITI_MAKE_OPTS+=V=1
#OUISTITI_MAKE_OPTS+=DEBUG=y

OUISTITI_KCONFIG_DEFCONFIG = $(OUISTITI_DEFCONFIG)
#OUISTITI_KCONFIG_FRAGMENT_FILES = $(call qstrip,$(BR2_PACKAGE_OUISTITI_CONFIG_FRAGMENT_FILES))
OUISTITI_KCONFIG_EDITORS = config
OUISTITI_KCONFIG_OPTS = $(OUISTITI_MAKE_OPTS)

ifeq ($(BR2_PACKAGE_LIBOUISTITI_CLIENT),y)
OUISTITI_CLIENT_OPTS=$(call KCONFIG_ENABLE_OPT,HTTPCLIENT_FEATURES,$(@D)/.config)
else
OUISTITI_CLIENT_OPTS=$(call KCONFIG_DISABLE_OPT,HTTPCLIENT_FEATURES,$(@D)/.config)
endif

ifeq ($(BR2_PACKAGE_OUISTITI_TINYSVCMDNS),y)
  OUISTITI_DEPENDENCIES += tinysvcmdns
  OUISTITI_TINYSVCMDNS_OPTS+=$(call KCONFIG_ENABLE_OPT,TINYSVCMDNS,$(@D)/.config)
else
  OUISTITI_TINYSVCMDNS_OPTS+=$(call KCONFIG_DISABLE_OPT,TINYSVCMDNS,$(@D)/.config)
endif

ifeq ($(BR2_PACKAGE_OUISTITI_MBEDTLS),y)
  OUISTITI_DEPENDENCIES += mbedtls
  OUISTITI_TLS_OPTS+=$(call KCONFIG_ENABLE_OPT,MBEDTLS,$(@D)/.config)
else
  OUISTITI_TLS_OPTS+=$(call KCONFIG_DISABLE_OPT,MBEDTLS,$(@D)/.config)
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

define OUISTITI_FEATURES_OPTS
	$(if $(findstring y,$(BR2_TOOLCHAIN_HAS_THREADS)),
		$(call KCONFIG_ENABLE_OPT,USE_PTHREAD,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,USE_PTHREAD,$(@D)/.config))
endef

define OUISTITI_LIBRARIES_OPTS
	$(if $(findstring y,$(BR2_SHARED_LIBS)),
		$(call KCONFIG_ENABLE_OPT,MODULES,$(@D)/.config)
		$(call KCONFIG_ENABLE_OPT,SHARED,$(@D)/.config)
		$(call KCONFIG_DISABLE_OPT,STATIC,$(@D)/.config))
	$(if $(findstring y,$(BR2_STATIC_LIBS)),
		$(call KCONFIG_DISABLE_OPT,MODULES,$(@D)/.config)
		$(call KCONFIG_DISABLE_OPT,SHARED,$(@D)/.config)
		$(call KCONFIG_ENABLE_OPT,STATIC,$(@D)/.config))
	$(if $(findstring y,$(BR2_SHARED_STATIC_LIBS)),
		$(call KCONFIG_ENABLE_OPT,MODULES,$(@D)/.config)
		$(call KCONFIG_ENABLE_OPT,SHARED,$(@D)/.config)
		$(call KCONFIG_ENABLE_OPT,STATIC,$(@D)/.config))
endef

define OUISTITI_AUTH_OPTS
	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_AUTH)),
		$(call KCONFIG_ENABLE_OPT,AUTH,$(@D)/.config)
		$(call KCONFIG_ENABLE_OPT,AUTHZ_SIMPLE,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,AUTH,$(@D)/.config)
		$(call KCONFIG_DISABLE_OPT,AUTHZ_SIMPLE,$(@D)/.config))

	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_AUTH_SQLITE)),
		$(call KCONFIG_ENABLE_OPT,AUTHZ_SQLITE,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,AUTHZ_SQLITE,$(@D)/.config))

	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_AUTH_UNIX)),
		$(call KCONFIG_ENABLE_OPT,AUTHZ_UNIX,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,AUTHZ_UNIX,$(@D)/.config))

	$(if $(findstring y,$(BR2_TOOLCHAIN_USES_UCLIBC)),
		$(call KCONFIG_DISABLE_OPT,USE_REENTRANT,$(@D)/.config),
		$(call KCONFIG_ENABLE_OPT,USE_REENTRANT,$(@D)/.config))

	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_AUTH_TOKEN)),
		$(call KCONFIG_ENABLE_OPT,AUTH_TOKEN,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,AUTH_TOKEN,$(@D)/.config))

	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_AUTH_JWT)),
		$(call KCONFIG_ENABLE_OPT,AUTHZ_JWT,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,AUTHZ_JWT,$(@D)/.config))

	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_AUTH_BASIC)),
		$(call KCONFIG_ENABLE_OPT,AUTHN_BASIC,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,AUTHN_BASIC,$(@D)/.config))

	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_AUTH_DIGEST)),
		$(call KCONFIG_ENABLE_OPT,AUTHN_DIGEST,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,AUTHN_DIGEST,$(@D)/.config))

	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_AUTH_BEARER)),
		$(call KCONFIG_ENABLE_OPT,AUTHN_BEARER,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,AUTHN_BEARER,$(@D)/.config))

	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_AUTH_OAUTH2)),
		$(call KCONFIG_ENABLE_OPT,AUTHN_OAUTH2,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,AUTHN_OAUTH2,$(@D)/.config))
endef

define OUISTITI_DOCUMENT_OPTS
	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_DOCUMENT)),
		$(call KCONFIG_ENABLE_OPT,DOCUMENT,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,DOCUMENT,$(@D)/.config))
	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_DOCUMENT_REST)),
		$(call KCONFIG_ENABLE_OPT,DOCUMENTREST,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,DOCUMENTREST,$(@D)/.config))
	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_DOCUMENT_RANGE)),
		$(call KCONFIG_ENABLE_OPT,RANGEREQUEST,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,RANGEREQUEST,$(@D)/.config))
	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_DOCUMENT_HOME)),
		$(call KCONFIG_ENABLE_OPT,DOCUMENTHOME,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,DOCUMENTHOME,$(@D)/.config))
endef

define OUISTITI_CGI_OPTS
	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_CGI)),
		$(call KCONFIG_ENABLE_OPT,CGI,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,CGI,$(@D)/.config))
endef

define OUISTITI_WEBDSOCKET_OPTS
	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_WEBSOCKET)),
		$(call KCONFIG_ENABLE_OPT,WEBSOCKET,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,WEBSOCKET,$(@D)/.config))

	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_WS_JSONRPC)),
		$(call KCONFIG_ENABLE_OPT,WS_JSONRPC,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,WS_JSONRPC,$(@D)/.config))

	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_WS_CHAT)),
		$(call KCONFIG_ENABLE_OPT,WS_CHAT,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,WS_CHAT,$(@D)/.config))
endef

define OUISTITI_WEBSTREAM_OPTS
	$(if $(findstring y,$(BR2_PACKAGE_OUISTITI_WEBSTREAM)),
		$(call KCONFIG_ENABLE_OPT,WEBSTREAM,$(@D)/.config),
		$(call KCONFIG_DISABLE_OPT,WEBSTREAM,$(@D)/.config))
endef

define OUISTITI_KCONFIG_FIXUP_CMDS
	$(OUISTITI_CLIENT_OPTS)
	$(OUISTITI_FEATURES_OPTS)
	$(OUISTITI_LIBRARIES_OPTS)
	$(OUISTITI_TINYSVCMDNS_OPTS)
	$(OUISTITI_MBEDTLS_OPTS)
	$(OUISTITI_AUTH_OPTS)
	$(OUISTITI_DOCUMENT_OPTS)
	$(OUISTITI_CGI_OPTS)
	$(OUISTITI_WEBDSOCKET_OPTS)
	$(OUISTITI_WEBSTREAM_OPTS)
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

$(eval $(kconfig-package))
