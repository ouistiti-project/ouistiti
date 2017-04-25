LIBB64_DIR=../libb64
lib-$(DYNAMIC)+=mod_auth
slib-$(STATIC)+=mod_auth
mod_auth_SOURCES+=mod_auth.c
mod_auth_CFLAGS+=-I../libhttpserver/include

mod_auth_SOURCES-$(AUTHN_BASIC)+=authn_basic.c ../utils/libb64.a
mod_auth_CFLAGS-$(AUTHN_BASIC)+=-DAUTHN_BASIC -I$(LIBB64_DIR)/include

mod_auth_SOURCES-$(AUTHZ_SIMPLE)+=authz_simple.c
mod_auth_CFLAGS-$(AUTHZ_SIMPLE)+=-DAUTHZ_SIMPLE

mod_auth_CFLAGS-$(DEBUG)+=-g -DDEBUG
