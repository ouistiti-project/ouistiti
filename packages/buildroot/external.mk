################################################################################
#
# ouistiti
#
################################################################################

include $(sort $(wildcard $(BR2_EXTERNAL_OUISTITI_PATH)/package/ouistiti/libhttpserver/libhttpserver.mk))
include $(sort $(wildcard $(BR2_EXTERNAL_OUISTITI_PATH)/package/ouistiti/ouistiti/ouistiti.mk))

