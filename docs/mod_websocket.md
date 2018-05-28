Websocket
--------------

# Description

The websocket module allows to create a gateway between a HTTP(S) client and a UNIX server.

## Features

The module will connect to a UNIX socket of a system server, and transfer data from the HTTP client to the server.

# Build options:

MOD_WEBSOCKET : build this module.  
WEBSOCKET_RT : add the "direct" mode.

# Configuration:

## server configuration:
"websocket" : gateway object of the server. Each server may contain one and only one object of the type.

## websocket configuration:

### "docroot":
The directory of the websocket server.  
Example: *docroot="/var/run/ouistiti";*

### "allow":
The list of websockets name enabled for the clients. Default: "*".  
Example: *allow="ws_\*";*

### "deny":
The list of websocket name disabled for the clients. Default: "".  
Example: *deny="internal/\*";*

### "mode":
The list of features availables on the websocket. Currently the mode "direct" is available only for HTTP connection (not for HTTPS).

#### direct mode:
This feature allows the websocket server to read/write directly on the client socket. For this feature, the websocket server has to be link to libwebsocket.so.  
Example: *mode="direct";*

## Examples:

	websocket = {
		docroot="/var/ouistiti";
	};

# Tools and usages

## Introduction
This module MUST be use with a system server. The server may wait messages from th clients and/or send  messages to the clients.
Because the module manages websocket handshake and data, the server only needs to use the messages.

## Javascript connection

The URL of Websocket is :
 * scheme : "ws://" on HTTP, "wss://" on HTTPS
 * hostname
 * pathname

The pathname is defined by the websocket server (see below)

Example:

	var uri;
	if (location.protocol === "http:")
		uri += "ws://";
	else if (location.protocol === "https:")
		uri += "wss://";
	uri += location.hostname;
	uri += "/auth";
	websocket = new WebSocket(uri);
	websocket.onopen = function(evt) { onOpen(evt) };
	websocket.onclose = function(evt) { onClose(evt) };
	websocket.onmessage = function(evt) { onMessage(evt) };
	websocket.onerror = function(evt) { onError(evt) };

## Server samples

### "echo" server
This is a UNIX server to receive data from each client and send the same data to same client.

#### Usage

The server accepts the following options:

 * -R \<directory\> the *docroot* of the websocket module.
 * -n \<name\>		the pathname of the URL.
 * -u \<user\>		the process owner.

### "chat" server
This is a UNIX server to receive data from each client and send the same data to all clients.
The server may (with -w option) interpreted some commands from the clients.

#### Usage

The server accepts the following options:

 * -R \<directory\>	the *docroot* of the websocket module.
 * -n \<name\>		the pathname of the URL.
 * -u \<user\>		the process owner.
 * -w			the management of ouistiti command.

Example:

	$ ./utils/websocket_chat -R /var/run/ouistiti/ -n auth -u apache -w
	...
	$ |

### "jsonrpc" server
This is a UNIX server which is able to receive JsonRPC commands and use an external library to interpret and run features.

#### Usage

The server accepts the following options:

 * -R \<directory\>	the *docroot* of the websocket module.
 * -n \<name\>		the pathname of the URL.
 * -u \<user\>		the process owner.
 * -L \<library\> the library of RPC.
 * -C \<string\>	the options of the RPC library.

Example:

	$ ./utils/websocket_jsonrpc -R /var/run/ouistiti/ -n auth -u apache -L ./utils/authrpc.so -C /tmp/ouistiti.db
	...
	$ |

