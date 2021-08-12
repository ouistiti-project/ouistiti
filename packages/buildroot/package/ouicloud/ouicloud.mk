################################################################################
#
# OUICLOUD
#
################################################################################

#OUICLOUD_VERSION = v2.4
#OUICLOUD_SITE = $(call github,ouistiti-project,libhttpserver,$(OUICLOUD_VERSION))
OUICLOUD_VERSION = HEAD
OUICLOUD_SITE = https://github.com/ouistiti-project/ouilogin
OUICLOUD_SITE_METHOD = git
OUICLOUD_LICENSE = MIT
OUICLOUD_LICENSE_FILES = LICENSE

$(eval $(autotools-package))
