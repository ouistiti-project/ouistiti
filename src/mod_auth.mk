modules-$(MODULES)+=mod_auth
slib-$(STATIC)+=mod_auth
mod_auth_SOURCES+=mod_auth.c
mod_auth_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_auth_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_auth_LIBS+=ouihash

mod_auth_SOURCES-$(AUTHN_NONE)+=authn_none.c

mod_auth_SOURCES-$(AUTHN_BASIC)+=authn_basic.c

mod_auth_SOURCES-$(AUTHN_DIGEST)+=authn_digest.c

mod_auth_SOURCES-$(AUTHN_BEARER)+=authn_bearer.c

mod_auth_SOURCES-$(AUTHN_OAUTH2)+=authn_oauth2.c
mod_auth_LIBRARY-$(AUTHN_OAUTH2)+=jansson

mod_auth_SOURCES-$(AUTHZ_SIMPLE)+=authz_simple.c

mod_auth_SOURCES-$(AUTHZ_FILE)+=authz_file.c

mod_auth_SOURCES-$(AUTHZ_UNIX)+=authz_unix.c
mod_auth_LIBRARY-$(AUTHZ_UNIX)+=crypt

mod_auth_SOURCES-$(AUTHZ_SQLITE)+=authz_sqlite.c
mod_auth_LIBRARY-$(AUTHZ_SQLITE)+=sqlite3

mod_auth_SOURCES-$(AUTHZ_JWT)+=authz_jwt.c
mod_auth_LIBRARY-$(AUTHZ_JWT)+=jansson

mod_auth_CFLAGS-$(MBEDTLS)+=-DTLS
mod_auth_CFLAGS-$(WOLFSSL)+=-DTLS
mod_auth_CFLAGS-$(OPENSSL)+=-DTLS

mod_auth_CFLAGS-$(DEBUG)+=-g -DDEBUG
