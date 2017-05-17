
modules-$(DYNAMIC)+=utils_mod
slib-$(STATIC)+=utils_mod
utils_mod_SOURCES=utils.c
utils_mod_CFLAGS+=-I../libhttpserver/include 

utils_mod_CFLAGS-$(DEBUG)+=-g -DDEBUG

modules-$(DYNAMIC)+=mod_static_file
slib-$(STATIC)+=mod_static_file
mod_static_file_SOURCES+=mod_static_file.c
mod_static_file_CFLAGS+=-DSTATIC_FILE -I../libhttpserver/include

mod_static_file_SOURCES-$(SENDFILE)+=mod_sendfile.c
mod_static_file_CFLAGS-$(SENDFILE)+=-DSENDFILE

mod_static_file_SOURCES-$(DIRLISTING)+=mod_dirlisting.c
mod_static_file_CFLAGS-$(DIRLISTING)+=-DDIRLISTING

mod_static_file_CFLAGS-$(DEBUG)+=-g -DDEBUG

