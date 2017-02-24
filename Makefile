include scripts.mk

sysconf-${FILE_CONFIG}+=ouistiti.conf
#libhttpserver has to be static in all configuration
export SLIB_HTTPSERVER=y
subdir-y:=libhttpserver
subdir-y+=utils
subdir-y+=src

