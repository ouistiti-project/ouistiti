
modules-$(DYNAMIC)+=mod_filestorage
slib-$(STATIC)+=mod_filestorage
mod_filestorage_SOURCES+=mod_filestorage.c
mod_filestorage_CFLAGS+=-DFILESTORAGE -I../libhttpserver/include

mod_filestorage_CFLAGS-$(SENDFILE)+=-DSENDFILE

mod_filestorage_CFLAGS+=-DDIRLISTING

mod_filestorage_CFLAGS-$(RANGEREQUEST)+=-DRANGEREQUEST

mod_filestorage_CFLAGS-$(DEBUG)+=-g -DDEBUG

