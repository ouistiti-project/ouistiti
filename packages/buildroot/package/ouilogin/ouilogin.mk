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
OUILOGIN_CONFIG_OPTS += datadir=/srv/www-ouilogin

$(eval $(autotools-package))
