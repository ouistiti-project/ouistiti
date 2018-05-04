
modules-$(MODULES)+=mod_webstream
slib-y+=mod_webstream
mod_webstream_SOURCES-$(SERVERHEADER)+=mod_webstream.c
mod_webstream_CFLAGS+=-I../libhttpserver/include
mod_webstream_CFLAGS+=-DWEBSTREAM
mod_webstream_CFLAGS-$(MODULES)+=-DMODULES
mod_webstream_CFLAGS-$(VTHREAD)+=-DVTHREAD

mod_webstream_CFLAGS-$(DEBUG)+=-g -DDEBUG

