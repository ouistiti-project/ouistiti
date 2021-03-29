modules-$(MODULES)+=mod_authmngt
slib-y+=mod_authmngt
mod_authmngt_SOURCES+=mod_authmngt.c
mod_authmngt_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_authmngt_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)

# mod_authmngt depends on mod_auth
#mod_authmngt_SOURCES-$(AUTHZ_SQLITE)+=authz_sqlite.c
#mod_authmngt_LIBRARY-$(AUTHZ_SQLITE)+=sqlite3

mod_authmngt_CFLAGS-$(DEBUG)+=-g -DDEBUG
