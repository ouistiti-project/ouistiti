LIBB64_DIR=../libb64

slib-y+=b64
b64_SOURCES+=$(LIBB64_DIR)/src/cencode.c
b64_SOURCES+=$(LIBB64_DIR)/src/cdecode.c
b64_CFLAGS+=-I$(LIBB64_DIR)/include
b64_CFLAGS+=-fPIC

export LIBB64_DIR
