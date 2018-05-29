# Introduction

Ouistiti needs some configuration for the servers and the modules.  
Each my be configure in static header file (src/config.h) or dynamicly
with a file format defined by [libconfig](http://www.hyperrealm.com/libconfig/) library.

This chapter introduce the libconfig format, refer to the config.h file to use the static mode.

Each information is defined as 

    information		key=value;
    key			string
    value 			string|integer|object|table
    table			(element*[,element])
    element			string|integer|object
    object			{information[,information]}

Examples:

	pid-file = "/var/run/ouistiti.pid";
	maxservers = 4;
	static_file = { docroot = "/srv/www/htdocs"; };
	servers= ({port = 80;},{port=443;});

## Main entry

Ouistiti application needs the following entries:

### "user" :
define the user to set for the main processus. Ouistiti must
be start with rights of "root", after to create the sockets server,
it is more secure to change the user of all process used by Ouistiti.  
To use the Unix' authentication the server must be root too, then
in this case, "user" must be set with "root". The authentication will
change the user. The default user is "root", but Ouistiti will request
to change the user.

### "log-file" :
define the path to the file to store the log. By default
the value is the standard error pipe.

### "pid-file" :
define the path to a file where Ouistiti will store the
main process id. This value is optional.

### "mimetypes" :

define a table of objects :  
   * "ext" : define a list of extensions file
   * "mime" : define the mime value affected to the extensions.

### "[servers](#servers)" :
define a table of servers. Each is an object describing 
the socket server and the modules to use during a client connection.

Examples:

	user="www-data";
	log-file="/var/log/ouistiti.log";
	pid-file="/var/run/ouistiti.pid";
	mimetypes = ({
			ext = ".mp3";
			mime = "audio/mp3";
		});
	servers = ({...});

## servers

The server is defined with several informations:

### "hostname" :
the name associated to the server. The default value is the IP
 address of the ethernet interface.
### "port" :
the port number of socket's server. The default value is 80. For a
 HTTPS server this value should be set to 443.
### "addr" :
the address of the ethernet interface to listen. By default
 the server listen on all ethernet interface.
### "keepalivetimeout" :
the timeout of the keepalive. The default value is 0 and
 there is not keepalive, after each client request the socket is closed.
### "chunksize" :
the value defines a size of data. Please refer to the specific chapter
 for more informations. The default value is 63 but for a normal use case
 use 1500 (the MTU of the main interface).
### "maxclients" :
the maximum number of clients at the same time connected
 to the server. The default value is 10. For very stressed server,
 you can use a value of 2048.
### "version" : define the HTTP version to use. The availables values are :
    - "HTTP/0.9"
    - "HTTP/1.0"
    - "HTTP/1.1"
 
Example:
 
	{
	  user="www-data";
	  log-file="/var/log/ouistiti.log";
	  pid-file="/var/run/ouistiti.pid";
	  servers = ({
	    hostname="ouistiti.net";
	    port=80;
	    chunksize = 1500;
	    maxclients=100;
	    keepalivetimeout=5;
	    });
	}

## modules
 
Each module may have is own configuration. 
 
### "auth" :
[mod_auth](mod_auth.md) allows to set the users and their password for restricted access.
### "websocket" :
[mod_websocket](mod_websocket.md) allows to use a location of websocket servers.
### "tls" :
[mod_{mbedtls|wolfssl|openssl] allows to set a SSL/TLS connection and its certificates files.

Example:

	servers = ({
	  hostname = "www.ouistiti.net";
	  port=443;
	  version="HTTP11";
	  tls = {
	    crtfile = "/etc/ouistiti/ouistiti_srv.crt";
	    pemfile = "/etc/ouistiti/ouistiti_srv.key";
	    dhmfile = "/etc/ouistiti/ouistiti_dhparam.key";
	  };
	});

### "document" :
[mod_document] allows to GET files from a root directory. This module
accepts somme options:

	* "dirlisting" to send the directory listing if the default page is not present.
	* "sendfile" to optimize the sending into HTTP (not available on HTTPS).
	* "range" to allows the sending packet by packet.
	* "rest" to allows the management of the files with Rest (PUT/DELETE/POST) commands.
	* "home" to change the "docroot" with the "home" directory of the authenticated user.

Example:

	servers = ({
	    hostname="ouistiti.net";
	    port=80;
		document = {
			docroot = "/srv/www/htdocs";
			allow = ".html,.htm,.css,.js,.txt,*";
			deny = "^.htaccess,.php";
			options = "dirlisting,sendfile,range,rest";
		};
	});

	servers = ({
	    hostname="ouistiti.net";
	    port=80;
		auth = {
			protect = "";
			unprotect = "*";
			type = "Basic";
			user = "test";
			passwd = "test";
			group = "user";
			home = "/home/test/htdocs";
		};
		document = {
			docroot = "/srv/www/htdocs";
			allow = ".html,.*htm*,.css,.js,.txt,*";
			deny = ".htaccess,.php";
			options = "dirlisting,rest,home";
		};
	});
