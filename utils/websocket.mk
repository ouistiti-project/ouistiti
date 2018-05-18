WS_SRC:=websocket/
lib-$(WEBSOCKET_RT)+=ouistiti_ws
ouistiti_ws_SOURCES+=websocket.c utils.c
ouistiti_ws_LIBS+=dl
ouistiti_ws_LIBS+=websocket
ouistiti_ws_CFLAGS+=-I../libhttpserver/include
ouistiti_ws_CFLAGS-$(DEBUG)+=-g -DDEBUG

bin-$(WS_ECHO)+=websocket_echo
websocket_echo_SOURCES+=$(WS_SRC)echo.c
websocket_echo_CFLAGS+=-DPTHREAD
websocket_echo_CFLAGS-$(WEBSOCKET_RT)+=-DSOCKDOMAIN="(AF_MAX+0X100)"
websocket_echo_CFLAGS-$(WEBSOCKET_RT)+=-DSOCKPROTOCOL=153
websocket_echo_LDFLAGS-$(WEBSOCKET_RT)+=-nodefaultlibs
websocket_echo_LIBS-$(WEBSOCKET_RT)+=ouistiti_ws websocket c
websocket_echo_LIBS+=pthread

websocket_echo_CFLAGS-$(DEBUG)+=-g -DDEBUG

bin-$(WS_GPS)+=websocket_gps
websocket_gps_SOURCES+=$(WS_SRC)nmea.c
websocket_gps_CFLAGS+=-DPTHREAD
websocket_gps_CFLAGS-$(WEBSOCKET_RT)+=-DWEBSOCKET_RT
websocket_gps_LIBS-$(WEBSOCKET_RT)+=ouistiti_ws websocket
websocket_gps_LIBS+=pthread nmea

websocket_gps_CFLAGS-$(DEBUG)+=-g -DDEBUG

bin-$(WS_CHAT)+=websocket_chat
websocket_chat_SOURCES+=$(WS_SRC)chat.c
websocket_chat_CFLAGS+=-DPTHREAD
websocket_chat_LIBS-$(WEBSOCKET_RT)+=ouistiti_ws websocket
websocket_chat_LIBS+=pthread

websocket_chat_CFLAGS-$(DEBUG)+=-g -DDEBUG

bin-$(WS_JSONRPC)+=websocket_jsonrpc
websocket_jsonrpc_SOURCES+=$(WS_SRC)jsonrpc.c
websocket_jsonrpc_SOURCES+=jsonrpc/jsonrpc.c
websocket_jsonrpc_LDFLAGS-$(WEBSOCKET_RT)+=-nodefaultlibs
websocket_jsonrpc_LIBS-$(WEBSOCKET_RT)+=ouistiti_ws websocket c
websocket_jsonrpc_LIBS+=dl jansson
websocket_jsonrpc_CFLAGS-$(PTHREAD)+=-DPTHREAD
websocket_jsonrpc_LIBS-$(PTHREAD)+=pthread
websocket_jsonrpc_CFLAGS-$(DEBUG)+=-g -DDEBUG

modules-$(WS_JSONRPC)+=jsonsql
jsonsql_SOURCES+=$(WS_SRC)jsonsql.c
jsonsql_LIBRARY+=sqlite3
jsonsql_CFLAGS-$(DEBUG)+=-g -DDEBUG

modules-$(WS_JSONRPC)+=authrpc
authrpc_SOURCES+=$(WS_SRC)authrpc.c
authrpc_LIBRARY+=sqlite3
authrpc_CFLAGS-$(DEBUG)+=-g -DDEBUG

bin-$(WS_SYSLOGD)+=websocket_syslogd
websocket_syslogd_SOURCES+=$(WS_SRC)syslogd.c
ifeq ($(WEBSOCKET_RT), y)
websocket_syslogd_CFLAGS-$(WEBSOCKET)+=-DPTHREAD
websocket_syslogd_CFLAGS-$(WEBSOCKET)+=-DSOCKDOMAIN="(AF_MAX+0X100)"
websocket_syslogd_CFLAGS-$(WEBSOCKET)+=-DSOCKPROTOCOL=153
websocket_syslogd_LDFLAGS-$(WEBSOCKET)+=-nodefaultlibs
websocket_syslogd_LIBS-$(WEBSOCKET)+=ouistiti_ws websocket c pthread
endif

websocket_syslogd_CFLAGS-$(DEBUG)+=-g -DDEBUG
