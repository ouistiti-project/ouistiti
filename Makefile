include scripts.mk

package=ouistiti
version=1.0

#libhttpserver has to be static in all configuration
export SLIB_HTTPSERVER=y
export MAXCHUNKS_HEADER=20
export MAXCHUNKS_URI=4
subdir-y:=libhttpserver
subdir-y+=utils
subdir-y+=src

