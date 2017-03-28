LIBB64_DIR=../libb64
lib-$(DYNAMIC)+=mod_auth
slib-$(STATIC)+=mod_auth
mod_auth_SOURCES+=mod_auth.c
mod_auth_CFLAGS+=-I../libhttpserver/include

mod_auth_SOURCES-$(AUTHN_BASIC_CONF)+=authn_basic_conf.c ../utils/libb64.a
mod_auth_CFLAGS-$(AUTHN_BASIC_CONF)+=-DAUTHN_BASIC_CONF -I$(LIBB64_DIR)/include

mod_auth_CFLAGS-$(DEBUG)+=-g -DDEBUG
