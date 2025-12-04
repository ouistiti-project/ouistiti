modules-$(MODULES)+=mod_document
slib-$(STATIC)+=mod_document
mod_document_SOURCES+=mod_document.c
mod_document_SOURCES+=document_htaccess.c
mod_document_CFLAGS+=-DSTATIC_FILE
mod_document_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_document_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_document_LIBS+=$(LIBHTTPSERVER_NAME)
mod_document_LIBS+=ouiutils
mod_document_LIBRARY+=libconfig

mod_document_SOURCES-$(SENDFILE)+=mod_sendfile.c
ifneq ($(DIRLISTING_MOD),y)
mod_document_SOURCES-$(DIRLISTING)+=mod_dirlisting.c
endif

mod_document_SOURCES-$(RANGEREQUEST)+=mod_range.c

mod_document_SOURCES-$(DOCUMENTREST)+=mod_documentrest.c

mod_document_CFLAGS-$(DEBUG)+=-g -DDEBUG

ifeq ($(DIRLISTING_MOD),y)
modules-$(MODULES)+=mod_dirlisting
slib-$(STATIC)+=mod_dirlisting
mod_dirlisting_SOURCES+=mod_dirlisting.c
mod_dirlisting_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_dirlisting_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_dirlisting_LIBS+=$(LIBHTTPSERVER_NAME)
mod_dirlisting_LIBS+=ouiutils
mod_dirlisting_LIBRARY+=libconfig
mod_dirlisting_CFLAGS-$(DEBUG)+=-g -DDEBUG
endif
