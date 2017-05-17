LIBB64_DIR=../libb64
modules-$(DYNAMIC)+=mod_auth
slib-$(STATIC)+=mod_auth
mod_auth_SOURCES+=mod_auth.c
mod_auth_CFLAGS+=-I../libhttpserver/include

mod_auth_SOURCES-$(AUTHN_BASIC)+=authn_basic.c
mod_auth_CFLAGS-$(AUTHN_BASIC)+=-DAUTHN_BASIC -I$(LIBB64_DIR)/include

mod_auth_SOURCES-$(AUTHN_DIGEST)+=authn_digest.c
mod_auth_CFLAGS-$(AUTHN_DIGEST)+=-DAUTHN_DIGEST -I$(LIBB64_DIR)/include
mod_auth_CFLAGS-$(MBEDTLS)+=-DMBEDTLS
#md5 from Ron Rivest workeds only on 32 bits CPU
#the current version was modified for 32 and 64 bits CPU
mod_auth_CFLAGS-$(MD5_RONRIVEST)+=-DMD5_RONRIVEST
mod_auth_LIBS-$(MBEDTLS)+=mbedtls

mod_auth_SOURCES-$(AUTHZ_SIMPLE)+=authz_simple.c
mod_auth_CFLAGS-$(AUTHZ_SIMPLE)+=-DAUTHZ_SIMPLE

#libb64 must the last source
mod_auth_SOURCES-$(AUTHN_BASIC)+= ../utils/libb64.a
mod_auth_SOURCES-$(AUTHN_DIGEST)+= ../utils/libb64.a
ifneq ($(MBEDTLS),y)
ifeq ($(MD5_RONRIVEST),y)
mod_auth_SOURCES-$(AUTHN_DIGEST)+= ../utils/md5-c/libmd5.a
else
mod_auth_SOURCES-$(AUTHN_DIGEST)+= ../utils/md5/libmd5.a
endif
endif

mod_auth_CFLAGS-$(DEBUG)+=-g -DDEBUG
