modules-$(MODULES)+=mod_form_urlencoded
slib-$(STATIC)+=mod_form_urlencoded
mod_form_urlencoded_SOURCES+=mod_form_urlencoded.c
mod_form_urlencoded_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_form_urlencoded_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_form_urlencoded_CFLAGS-$(MODULES)+=-DMODULES

mod_form_urlencoded_CFLAGS-$(DEBUG)+=-g -DDEBUG
