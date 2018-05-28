Authentication
--------------

# Description

The authentication module allows to request login/password information before send data into a response.

## Features

The module may use several method for the request :

 1. Basic: the login/password are sent with Base64 encoding. This method allows to use all method of password storage, but the password is readable during the communication.
 2. Digest: the login/password are sent with encoding method. This method add more security during the communication but some password storage are disallowed.
 3. None: this is not a real method, there is not login/password exchange, but this method allows to set the host user of the server process after the client connection.

The module may store the password into several formats:

 1. configuration file: the ouistiti configuration file contains only one login/password.
 2. text file: a file contains a list of login/password. The format is :
    <user>:<password>:<group>:<home>
    The password may be readable or encrypted with md5, sha256 or sha512. "ouipasswd" is a tool to generate a line of this file.
 3. sqlite database: 
 4. unix password system: the module uses directly the logine informations of the host's users.

The module allows some other features:

 * if the login is a user on the system and the server still change the process owner, the module will do it.
 * the user's informations like "group" and "home" may be sent to the client and may be use by other modules.
 * the module may sent user's informations into the Set-Cookie headers or into specific headers (cf. configuration of "mode").
 * the module may discard the authentication of some URI or check authentication only on some URI.

# Build options:

MOD_AUTH : build this module.  
AUTHN_NONE : add support of "None" login method.  
AUTHN_BASIC : add support of "Basic" login method.  
AUTHN_DIGEST : add support of "Digest" login method.  
AUTHZ_SIMPLE : add support of password storage into the configuration file.  
AUTHZ_FILE :  add support of password storage into text file.  
AUTHZ_SQLITE : add support of password storage into sqlite database.  
AUTHZ_UNIX : add support of unix login system.  

# Configuration:

## server configuration:
"auth" : authentication object of the server. Each server may contain one and only one object of the type.

## authentication configuration:

###"type" :
the authentication method:

 * "None" : this is not a real login and just set the process owner after client connection.
 * "Basic" : this is a Basic authentication described into RFC 7617.
 * "Digest" : this is a Digest authentication described into RFC 7616.

Example: *type="Digest";*

###"algorithm" :
the algorithm to use with digest authentication. The  RFC requires the support of sha256, but the default value is "MD5".

 * "MD5"
 * "SHA1"
 * "SHA-256"
 * "SHA-512"

Example: *algorithm="SHA-256";*

###"protect" :
a string which contains a list of pathes to request a login. By default "protect" is widlcard ("\*") and request login for all pathes.  
Example: *protect="^private/\*,^tools/\*";*

###"unprotect" :
a string which contains a list of pathes to accept directly without login request. This allows to send some generics files like javascrypt libraries (jquery, bootstrap...).  
Example: *unprotect="^public/\*,^js/\*";*

###"file" :
the path to the login/password storage file or unix login system.  
Example: *file="/etc/shadow";*  
Example: *file="/etc/ouistiti/passwd";*

###"dbname" :
the path to the sqlite database file.  
Example: *dbname="/etc/ouistiti/passwd.db";*

###"user" :
the login available of the server for configuration file storage or the "None" method.  
Example: *user="nobody";*

###"passwd" :
the passwd of "user" to use for configuration file storage.  
Example: *passwd="0u1sTi#i";*  
Example: *passwd="$a1$realm=testrealm@host.com$k551eO2ePFGKRSrO52O86Q==";*

###"group" :
the group of "user" to use for configuration file storage.
Example: *group="www-data";*

###"home" :
the home directory of "user" to use for configuration file storage.
Example: *home="private";*

###"mode" :
a string with a list of options to set some features:

 * "home" : force the path on the directory of the user. All URL has to contains :  
     *https://www.example.net/<home>/...*  
 or the server send redirection on this URL.
 * "cookie" : set cookie with user's setting:  
    USER=\<user>  
    GROUP=\<group>  
    HOME=\<home>
 * "header" : set header entries with user's setting:  
    X-Remote-User: \<user>  
    X-Remote-Group: \<group>  
    X-Remote-Home: \<home>
  
Example: *mode="cookie,header";*

##Examples

	auth = {
		type="Digest";
		algorithm="SHA-256";
		unprotect="lib;login.html";
		dbname="/etc/ouistiti/passwd.db";
		mode="cookie";
	};

	auth = {
		type="Basic";
		algorithm="SHA-256";
		protect="^private/*";
		dbname="/etc/ouistiti/passwd.db";
	};

# Tools and usages:

## "ouipasswd"
This is a tool distributed with Ouistiti to generate line for password file storage. 

### Build
HOST_UTILS=y must be set during the build.

	$ make DEBUG=y HOST_UTILS=y
	make[1] : ...
	  HOSTCC ouipasswd
	  HOSTLD ouipasswd
	make[2] : ...
	$ |


### Usage

	$ ./host/utils/ouipasswd -R ouistiti -T Digest -A MD5 -u johndoe -p foobar -g users -H jdoe
	johndoe:$a1$realm=ouistiti$rSBEWOmexQZg3BE/rPxOfw==:users:jdoe
	$ ./host/utils/ouipasswd -R ouistiti -T Digest -A MD5 -u johndoe -p foobar -g users -H jdoe > /etc/ouistiti/passwd
	$ |

## "passwdrpc.so"
This is jsonrpc library for websocket_jsonrpc server. This library allow to change the entries of the sqlite database from websocket connection.

### Build

WEBSOCKET=y must be set during the build.

### Usage

	$ ./utils/websocket_jsonrpc -R /var/run/ouistiti/ -n auth -u apache -L ./utils/authrpc.so -C /tmp/ouistiti.db
	...
	$ |

See websocket_rpc for more information on the usage

### RPC: auth
Authentication:  
This command allows to authenticate the connection with the server. Some other commands require to be authenticated before using.

	{
		"jsonrpc":"2.0",
		"method":"auth",
		"params": {
			"user":"foo",
			"passwd":"bar"
		},
		"id":3740816340
	}

### RPC: passwd
Change password:  
This command allows to change the password. The command requires the current password before to change it, or to be authenticated as "root".

	{
		"jsonrpc":"2.0",
		"method":"passwd",
		"params": {
			"user":"foo",
			"old":"bar",
			"new":"bar2",
			"confirm":"bar2"
		},
		"id":3740816340
	}

### RPC: adduser
Create new user:  
This command allow to create a new user in the database.

	{
		"jsonrpc":"2.0",
		"method":"adduser",
		"params": {
			"user":"johndoe",
			"passwd":"foobar",
			"group":"users",
			"home":"jdoe"
		},
		"id":3740816340
	}

### RPC: rmuser
Remove an user:  
This command allows to delete the entry of an user. The command require the current password of the user or to be authenticate as "root".

	{
		"jsonrpc":"2.0",
		"method":"rmuser",
		"params": {
			"user":"johndoe",
			"passwd":"foobar",
		},
		"id":3740816340
	}

