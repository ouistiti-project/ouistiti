Webstream
--------------

# Description

The webstream module opens a gateway between a HTTP client and local server.

## Features

The module will connect to a UNIX socket of a system server, and transfer data from the HTTP client to the server.

# Build options:

 * WEBSTREAM : build this module.  
 * WEBSOCKET_RT : add the "direct" mode.

# Configuration:

## server configuration:
"webstream" : gateway object of the server. Each server may contain one and only one object of the type.

## webstream configuration:

### "docroot":
The directory of the websocket server.  
Example:

```Config
docroot="/srv/www/webstream";
```

### "allow":
The list of regulare expression as URI enabled for the clients. Default: "*".  
Example:

```Config
allow="ws_\*";
```

### "deny":
The list of regulare expression as URI disabled for the clients. Default: "".  

Example:

```Config
deny="internal/\*";
```

### "options":
The list of features availables on all webstreams:

 * *direct* is available only for HTTP connection (not for HTTPS).
 * *multipart*

#### direct mode:
This feature allows the streamer to read/write directly on the client socket. The module use the UNIX socket to send the file
descriptor of the web connection.

For this feature, the streamer may be linked to libwebsocket.so.  
Example: 

```Config
options="direct";
```

#### multipart:
This feature wait data from UNIX server and send the block inside a "multipart/x-mixed-replace" boundary part.
The **Content-Type** of the request is always *multipart/x-mixed-replace*, foreach received packet, the module generate a new
part with *boundary*, *headers* ( **Content-Type** , **Content-Length** ) and data's packet.

 - the **Content-Type** is defined by the file extension of the UNIX socket.
 - the **Content-Length** is the length of data's packet.

Becarefull it is impossible to split the data from the UNIX server. The server may sent with a laps of time between each packet, and the
module may set a *frame per second* between each boundary part, the default value is around 30 fps.

Two data's slots from UNIX server may be sent inside the same boundary, if *fps* is two large.
One data's slot from UNIX server may be split in several boundaries, if *fps* is two small.

### "fps":
The number of boundaries per second. See **multipart** options.

Example:
## Examples:

```Config
	webstream = {
		docroot = "/srv/www/webstream";
		allow = "*.mp3";
		deny = "*";
		options = "multipart";
		fps = 60;
	};
```

# Tools and usages

## Introduction
This module MUST be use with a streamer. The streamer sends the data on a UNIX socket in stream mode.

## Server samples

### "streamer" server
This is a UNIX server to send a JSON string each 1 second.

#### Usage:

The server accepts the following options:

 * -R \<directory\>	set the socket directory for the connection
 * -n \<name\>		the name of the stream
 * -u \<user\>		set the user to run
 * -m \<num\>		set the maximum number of clients
 * -D				start as daemon

#### Example:

The streamer.html page offers an example of usage.

```Shell
	$ ./utils/mjpeg -R /srv/www/webstream -n camera.mjpeg -u apache
	...
	$ |
```

### "mjpeg" server
This is a UNIX server to send video stream from a webcam.

#### Usage

The server accepts the following options:

 * -R \<directory\>	set the socket directory for the connection
 * -n \<name\>		the name of the stream
 * -u \<user\>		set the user to run
 * -m \<num\>		set the maximum number of clients
 * -D				start as daemon

#### Example:

The mjpeg.html page offers an example of usage.

```Shell
	$ ./utils/mjpeg -R /srv/www/webstream -n camera.mjpeg -u apache
	...
	$ |
```

### "udpgw" server
This is a UNIX server which is able to forward **UDP** packets to the *webstream* module.

#### Usage:

The server accepts the following options:

 * -R \<directory\>	set the socket directory for the connection
 * -n \<name\>		the name of the stream
 * -u \<user\>		set the user to run
 * -m \<num\>		set the maximum number of clients
 * -D				start as daemon
 * -a \<address\>	set the address of the UDP server (or Multicast address)
 * -p \<port\>		set the port of the UDP stream

#### Example:

```Shell
	$ ./utils/udpgw -R /srv/www/webstream -n stream.json -u apache -p 4900 -a 239.1.1.1
	...
	$ |
```
