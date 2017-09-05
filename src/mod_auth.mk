LIBB64_DIR=../libb64
modules-$(DYNAMIC)+=mod_auth
slib-$(STATIC)+=mod_auth
mod_auth_SOURCES+=mod_auth.c
mod_auth_CFLAGS+=-I../libhttpserver/include

mod_auth_SOURCES-$(AUTHN_BASIC)+=authn_basic.c
mod_auth_CFLAGS-$(AUTHN_BASIC)+=-DAUTHN_BASIC

mod_auth_SOURCES-$(AUTHN_DIGEST)+=authn_digest.c
mod_auth_CFLAGS-$(AUTHN_DIGEST)+=-DAUTHN_DIGEST
mod_auth_CFLAGS-$(MBEDTLS)+=-DMBEDTLS
mod_auth_LIBS-$(MBEDTLS)+=mbedtls

mod_auth_SOURCES-$(AUTHZ_SIMPLE)+=authz_simple.c
mod_auth_CFLAGS-$(AUTHZ_SIMPLE)+=-DAUTHZ_SIMPLE

mod_auth_SOURCES-$(AUTHZ_FILE)+=authz_file.c
mod_auth_CFLAGS-$(AUTHZ_FILE)+=-DAUTHZ_FILE

#libb64 must the last source
ifneq ($(MBEDTLS),y)
mod_auth_LDFLAGS+=-L../utils
mod_auth_LIBS-$(AUTHN_BASIC)+=b64
mod_auth_LIBS-$(AUTHN_DIGEST)+=b64
mod_auth_CFLAGS+=-I$(LIBB64_DIR)/include

#md5 from Ron Rivest workeds only on 32 bits CPU
#the current version was modified for 32 and 64 bits CPU
mod_auth_CFLAGS-$(MD5_RONRIVEST)+=-DMD5_RONRIVEST
ifeq ($(MD5_RONRIVEST),y)
mod_auth_SOURCES-$(AUTHN_DIGEST)+= ../utils/md5-c/libmd5.a
else
mod_auth_SOURCES-$(AUTHN_DIGEST)+= ../utils/md5/libmd5.a
endif
endif

mod_auth_CFLAGS-$(DEBUG)+=-g -DDEBUG
