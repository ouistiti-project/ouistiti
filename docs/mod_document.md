File access
-----------

# Description

The file access is available with the "mod_document" module. The access
is from the server to the client (download), and may be from the client 
to the server (upload).

## Features

# Build options:

 - DOCUMENT : to build this module.
 - DIRLISTING : to allow the "dirlisting" option.
 - RANGEREQUEST : to allow the "range" option.
 - SENDFILE : to allow the "sendfile" option.
 - DOCUMENTREST : to allow the "rest" option.
 - DOCUMENTHOME : to allow the "home" option.

# Configuration:

## server configuration

### "document" :
The file access entry point. The object defines one root directory and
the options to use with the file inside it. 

## document configuration

### "docroot" :
The path of the root directory where to find the files to read.

Example :

	docroot="/srv/www/htdocs";

### "allow" :
A list of filters to check on the URL before to send the response. Each
entry is a regular expression separated by a coma. The accepted rules are:
 \^ \$ \*

Note:
 \*.html and .html have the same meaning.

### "deny" :
A list of filters to check on the URL before to send the response. Each
entry is a regular expression separated by a coma. The accepted rules are:
 \^ \$ \*

Note:
 \*.html and .html have the same meaning.

Example:

	allow=".html,.js";
	deny=".cgi,.htaccess";

### "options" :
A list of options separated by a coma. Each option has its own rule:

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
			allow = ".html,.htm,.css,.js,.txt,\*";
			deny = ".htaccess,.php";
			options = "dirlisting,sendfile,range,rest";
		};
	});

## Example

### Configuration

	servers = ({
	    hostname="ouistiti.net";
	    port=80;
		auth = {
			protect = "";
			unprotect = "\*";
			type = "Basic";
			user = "test";
			passwd = "test";
			group = "user";
			home = "/home/test/htdocs";
		};
		document = {
			docroot = "/srv/www/htdocs";
			allow = ".html,.\*htm\*,.css,.js,.txt,\*";
			deny = ".htaccess,.php";
			options = "dirlisting,home";
		};
	});

### Explanation

	...
		auth = {
			protect = "";
			unprotect = "*";

This part disables the authentication on the website. But the client may
continue to authenticate.

	...
			user = "test";
			passwd = "test";
			group = "user";
			home = "/home/test/htdocs";

One user ("test") with password is available on the site. Its home directory
is "/home/test/htdocs".

	...
		document = {
			docroot = "/srv/www/htdocs";

Each request without authentication will search the file into "/srv/www/htdocs".

	...
			allow = ".html,.\*htm\*,.css,.js,.txt,\*";

This part allows to send all files with the .html, .js, .css, .txt, .xhtml,
.htm extensions and all others files too.
	...
			options = "dirlisting,home";

If the server  receives a request with an authentication, the module will
search the file into the "home" directory of the user ("/home/test/htdocs")
instead the root directory.
