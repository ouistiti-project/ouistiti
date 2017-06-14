modules-$(DYNAMIC)+=mod_vhosts
slib-$(STATIC)+=mod_vhosts
mod_vhosts_SOURCES+=mod_vhosts.c
mod_vhosts_CFLAGS+=-I../libhttpserver/include
mod_vhosts_CFLAGS-$(AUTH)+=-DAUTH
mod_vhosts_CFLAGS-$(STATIC_FILE)+=-DSTATIC_FILE
mod_vhosts_CFLAGS-$(CGI)+=-DCGI
mod_vhosts_CFLAGS-$(WEBSOCKET)+=-DWEBSOCKET


mod_vhosts_CFLAGS-$(DEBUG)+=-g -DDEBUG
