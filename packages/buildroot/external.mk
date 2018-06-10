################################################################################
#
# ouistiti
#
################################################################################

include $(sort $(wildcard $(BR2_EXTERNAL_OUISTITI_PATH)/libhttpserver/libhttpserver.mk))
include $(sort $(wildcard $(BR2_EXTERNAL_OUISTITI_PATH)/ouistiti/ouistiti.mk))

