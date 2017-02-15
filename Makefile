include scripts.mk

#libhttpserver has to be static in all configuration
export SLIB_HTTPSERVER=y
subdir-y:=libhttpserver
subdir-y+=utils
subdir-y+=src

