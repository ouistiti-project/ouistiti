
modules-$(DYNAMIC)+=mod_static_file
slib-$(STATIC)+=mod_static_file
mod_static_file_SOURCES+=mod_static_file.c
mod_static_file_CFLAGS+=-DSTATIC_FILE -I../libhttpserver/include

mod_static_file_SOURCES-$(SENDFILE)+=mod_sendfile.c
mod_static_file_CFLAGS-$(SENDFILE)+=-DSENDFILE

mod_static_file_SOURCES-$(DIRLISTING)+=mod_dirlisting.c
mod_static_file_CFLAGS-$(DIRLISTING)+=-DDIRLISTING

mod_static_file_CFLAGS-$(DEBUG)+=-g -DDEBUG

