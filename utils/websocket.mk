lib-$(WEBSOCKET)=ouistiti_ws
ouistiti_ws_SOURCES+=websocket.c
ouistiti_ws_LIBS+=dl
ouistiti_ws_LIBS+=websocket
ouistiti_ws_CFLAGS+=-I../libhttpserver/include
ouistiti_ws_DFLAGS+=-L../libhttpserver/src/httpserver
ouistiti_ws_CFLAGS-$(DEBUG)+=-g -DDEBUG

bin-$(WS_ECHO)=websocket_echo
websocket_echo_SOURCES+=websocket/echo.c
websocket_echo_CFLAGS-$(WEBSOCKET)+=-DPTHREAD
websocket_echo_CFLAGS-$(WEBSOCKET)+=-DSOCKDOMAIN="(AF_MAX+0X100)"
websocket_echo_CFLAGS-$(WEBSOCKET)+=-DSOCKPROTOCOL=153
websocket_echo_LDFLAGS-$(WEBSOCKET)+=-nodefaultlibs
websocket_echo_LDFLAGS-$(WEBSOCKET)+=-L../libhttpserver/src/httpserver
websocket_echo_LIBS-$(WEBSOCKET)+=websocket ouistiti_ws c pthread

websocket_echo_CFLAGS-$(DEBUG)+=-g -DDEBUG

bin-$(WS_CHAT)=websocket_chat
websocket_chat_SOURCES+=websocket/chat.c
websocket_chat_CFLAGS-$(WEBSOCKET)+=-DPTHREAD
websocket_chat_CFLAGS-$(WEBSOCKET)+=-DSOCKDOMAIN="(AF_MAX+0X100)"
websocket_chat_CFLAGS-$(WEBSOCKET)+=-DSOCKPROTOCOL=153
websocket_chat_LDFLAGS-$(WEBSOCKET)+=-nodefaultlibs
websocket_chat_LDFLAGS-$(WEBSOCKET)+=-L../libhttpserver/src/httpserver
websocket_chat_LIBS-$(WEBSOCKET)+=websocket ouistiti_ws c pthread

websocket_chat_CFLAGS-$(DEBUG)+=-g -DDEBUG
