
modules-$(MODULES)+=mod_document
slib-y+=mod_document
mod_document_SOURCES+=mod_document.c
mod_document_CFLAGS+=-DSTATIC_FILE
mod_document_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_document_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_document_LIBS+=ouiutils

mod_document_SOURCES-$(SENDFILE)+=mod_sendfile.c

mod_document_SOURCES-$(DIRLISTING)+=mod_dirlisting.c

mod_document_SOURCES-$(RANGEREQUEST)+=mod_range.c

mod_document_SOURCES-$(DOCUMENTREST)+=mod_documentrest.c

mod_document_CFLAGS-$(DEBUG)+=-g -DDEBUG

