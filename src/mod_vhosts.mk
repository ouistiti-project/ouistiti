modules-$(MODULES)+=mod_vhosts
slib-y+=mod_vhosts
mod_vhosts_SOURCES+=mod_vhosts.c
mod_vhosts_CFLAGS+=-I../libhttpserver/include
mod_vhosts_CFLAGS-$(AUTH)+=-DAUTH
mod_vhosts_CFLAGS-$(STATIC_FILE)+=-DSTATIC_FILE
mod_vhosts_CFLAGS-$(CGI)+=-DCGI
mod_vhosts_CFLAGS-$(MBEDTLS)+=-DMBEDTLS
mod_vhosts_CFLAGS-$(WEBSOCKET)+=-DWEBSOCKET
mod_vhosts_CFLAGS-$(METHODLOCK)+=-DMETHODLOCK
mod_vhosts_CFLAGS-$(SERVERHEADER)+=-DSERVERHEADER


mod_vhosts_CFLAGS-$(DEBUG)+=-g -DDEBUG
