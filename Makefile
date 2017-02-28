include scripts.mk

package=ouistiti
version=1.0

sysconf-${FILE_CONFIG}+=ouistiti.conf
#libhttpserver has to be static in all configuration
export SLIB_HTTPSERVER=y
subdir-y:=libhttpserver
subdir-y+=utils
subdir-y+=src

