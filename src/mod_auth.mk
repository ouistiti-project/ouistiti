modules-$(MODULES)+=mod_auth
slib-y+=mod_auth
mod_auth_SOURCES+=mod_auth.c
mod_auth_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_auth_CFLAGS-$(MODULES)+=-DMODULES

mod_auth_SOURCES-$(AUTHN_NONE)+=authn_none.c
mod_auth_CFLAGS-$(AUTHN_NONE)+=-DAUTHN_NONE

mod_auth_SOURCES-$(AUTHN_BASIC)+=authn_basic.c
mod_auth_CFLAGS-$(AUTHN_BASIC)+=-DAUTHN_BASIC

mod_auth_SOURCES-$(AUTHN_DIGEST)+=authn_digest.c
mod_auth_CFLAGS-$(AUTHN_DIGEST)+=-DAUTHN_DIGEST
mod_auth_LIBS-$(AUTHN_DIGEST)+=hash_mod

mod_auth_SOURCES-$(AUTHZ_SIMPLE)+=authz_simple.c
mod_auth_CFLAGS-$(AUTHZ_SIMPLE)+=-DAUTHZ_SIMPLE

mod_auth_SOURCES-$(AUTHZ_FILE)+=authz_file.c
mod_auth_CFLAGS-$(AUTHZ_FILE)+=-DAUTHZ_FILE

mod_auth_SOURCES-$(AUTHZ_UNIX)+=authz_unix.c
mod_auth_CFLAGS-$(AUTHZ_UNIX)+=-DAUTHZ_UNIX
mod_auth_LIBRARY-$(AUTHZ_UNIX)+=crypt

mod_auth_SOURCES-$(AUTHZ_SQLITE)+=authz_sqlite.c
mod_auth_CFLAGS-$(AUTHZ_SQLITE)+=-DAUTHZ_SQLITE
mod_auth_LIBRARY-$(AUTHZ_SQLITE)+=sqlite3

mod_auth_CFLAGS-$(DEBUG)+=-g -DDEBUG
