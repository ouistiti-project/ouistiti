lib-$(WEBSOCKET)=ouistiti_ws
ouistiti_ws_SOURCES+=websocket.c
ouistiti_ws_LIBS+=dl
ouistiti_ws_LIBS+=websocket
ouistiti_ws_CFLAGS+=-I../libhttpserver/include
ouistiti_ws_DFLAGS+=-L../libhttpserver/src/httpserver
ouistiti_ws_CFLAGS-$(DEBUG)+=-g -DDEBUG

bin-$(WS_ECHO)=websocket_echo
websocket_echo_SOURCES+=websocket/echo.c
websocket_echo_CFLAGS-$(WEBSOCKET)+=-DSOCKDOMAIN="(AF_MAX+0X100)" -DPTHREAD
websocket_echo_LDFLAGS-$(WEBSOCKET)+=-nodefaultlibs
websocket_echo_LDFLAGS-$(WEBSOCKET)+=-L../libhttpserver/src/httpserver
websocket_echo_LIBS-$(WEBSOCKET)+=websocket ouistiti_ws c pthread

websocket_echo_CFLAGS-$(DEBUG)+=-g -DDEBUG
