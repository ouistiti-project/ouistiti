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
defines the user to set for the main processus. Ouistiti must
be start with rights of "root", after to create the sockets server,
it is more secure to change the user of all process used by Ouistiti.
To use the Unix' authentication the server must be root too, then
in this case, "user" must be set with "root". The authentication will
change the user. The default user is "root", but Ouistiti will request
to change the user.

### "log-file" :
defines the path to the file to store the log. By default
the value is the standard error pipe.

### "pid-file" :
defines the path to a file where Ouistiti will store the
main process id. This value is optional.

### "config_d" :
defines the path to a directory which contains configuration
files for servers.

Each server available inside the sub file are stored in the
same list of the application.

*Note:* Each server must run on different port.

*Note:* Only *servers* entry is used.

### "init_d" :
defines the path to a script or a directory contening files.
Each executable file is launched after module configuration
and before starting the servers.

This is useful to start daemon for websocket or to set data inside
DB.

*Note:* non-executable file are not called. It may be important to
change rights of the files after initialization.

### "mimetypes" :
defines a table of objects :
   * "ext" : define a list of extensions file
   * "mime" : define the mime value affected to the extensions.

### "[servers](#servers)" :
define a table of servers. Each is an object describing
the socket server and the modules to use during a client connection.

#### Examples:

```config
	user="www-data";
	log-file="/var/log/ouistiti.log";
	pid-file="/var/run/ouistiti.pid";
	config_d="etc/ouistiti/ouistiti.d";
	init_d="/etc/ouistiti/init.d";
	mimetypes = ({
			ext = ".mp3";
			mime = "audio/mp3";
		});
	servers = ({...});
```

### "config_d" :
defines a directory to parse the file as "servers" configuration.
Each *config_d*/<name>.conf file may contains a *servers* entry, to add
one or more new servers. Becarefull *ouistiti* doesn't check if two servers
use the same "port".

#### Examples:

Main entry:
```config
	user="www-data";
	log-file="/var/log/ouistiti.log";
	pid-file="/var/run/ouistiti.pid";
	mimetypes = ({
			ext = ".mp3";
			mime = "audio/mp3";
		});
	config_d="/etc/ouistiti/ouistiti.d";
```
/etc/ouistiti/ouistiti.d/server1.conf
```config
	servers = ({...});
```
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

#### Example:

```config
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
```

## modules

Each module may have is own configuration.

### "auth" :
[mod_auth](mod_auth.md) allows to set the users and their password for restricted access.

#### Example :

```config
	auth = {
		type="Digest";
		algorithm="SHA-256";
		unprotect="lib;login.html";
		dbname="/etc/ouistiti/passwd.db";
		options="cookie";
	};
```

### "websocket" :
[mod_websocket](mod_websocket.md) allows to use a location of websocket servers.

#### Example :

```config
	websocket = {
		docroot="/var/run/websocket";
	};
```

### "tls" :
[mod_{mbedtls|wolfssl|openssl}] allows to set a SSL/TLS connection and its certificates files.

#### Example:

```config
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
```

### "document" :
[mod_document](mod_document.md) allows to GET files from a root directory.

#### Example:

```config
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
```

### "userfilter":
[mod_userfilter](mod_userfilter.md) allows to filter the request on the authentication's information.

#### Example:

```config
	servers = ({
	    hostname="ouistiti.net";
	    port=80;
        userfilter = {
                superuser = "root";
                configuri = "^/auth/filter*";
                dbname = "/etc/ouistiti/filter.db";
                allow = "^/trust/*,^/token$,^/apps/*";
        };
	});
```

### "redirect":
mod_redirect allows to send "301", "302" or "307" response on some requests or modify some error response.

#### Example:

```config
	servers = ({
	    hostname="ouistiti.net";
	    port=80;
		redirect = {
			options = "generate_204";
			links = ({
				origin = "test.html";
				destination = "index.html";
			},{
				origin = "permanently.html";
				destination = "index.html";
				options = "permanently";
			},{
				origin = "temporary.html";
				destination = "index.html";
				options = "temporary";
			},{
				origin = "temporary/*";
				destination = "dirlisting/";
				options = "temporary";
			},{
				origin = "token";
			},{
				origin = "empty";
				options = "generate_204";
			},{
				options = "error";
				destination = "error_404.html";
				origin = 404;
			});
		};
	});

 * options: *generate_204* will manage the GOOGLE URI /generate_204 to send an empty response.
 * a request on the */**any_thing/**test.html* will respond with
        302
        Location: /any_thing/index.html
 * a request on the */**any_thing/**permanently.html* will respond with
        301
        Location: /any_thing/index.html
 * a request on the */**any_thing/**temporary.html* will respond with
        307
        Location: /any_thing/index.html
 * a request on the */**any_thing/**temporary/index.html* will respond with
        307
        Location: /any_thing/dirlisting/index.html
 * a request on the */**any_thing/**token?redirect_uri=**any_address*** will respond with
        302
        Location: any_address
 * a request on the */**any_thing/**empty* will respond with
        204
 * any requests which should respond 404, will respond with
        302
        Location: /error_404.html
