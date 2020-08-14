URI redirection
---------------

# Description

This module allows to redirect some URI to another one.

# Configuration

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

## options

Some generic options are availables:

 * *generate\_204* : all GET request on the ressource "/generate_204" generates a empty ressource.
It is useful for hotspot to emulate an internet access with Google user-agent.
 * *hsts* : all request on an unsecure server is redirected to the same URI on a secure server.
 * temporary :
 * permanently :

## links

This is a list of links with an originate URI and the destination URI.

### origin

The URI of the request to check. It may be a string or a number or a regular expression.

The regular expression must follow some rules depending of the destination.

 - ^ : means the beginning of the URI, and no character must be present before.
 - $ : means the end of the URI, and no character must be present after.
 - \* : is the standard wildcard.
 - ~~ \. : is not available. ~~

If the origin is a number, the module checks the response and change the response
to redirect if the result is equal the value of the origin.

Request:

		GET /unknown.html HTTP/1.1
		HOST: www.ouistiti.net

Response:

		HTTP/1.1 301 Moved Permanently
		Location: error_404.html

### destination

The URI of the redirection to send. It **must** be a string or it may not be present.

The destination may be a relativ URI or a full URL to redirect onto another server.

#### redirection without destination

If the _destination_ field is not present, the module use the query part of the request, and looks
for "redirect_uri", to know the requesting redirection. This allow to the client to
receive some information from the server inside the header, and to send them to the
redirection server.

> This is useful to create a token server for bearer authentication.

		GET /token?redirect_uri=https://example.com/index.html HTTP/1.1
		HOST: www.ouistiti.net
		Authorization: Basic Zm9vOmJhcg==

Here our server (www.ouistiti.net) will authenticate the user and may send
a token with response like:

		HTTP/1.1 302 Found
		Set-Cookie: X-Auth-Token=eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VyIjogImZvbyIsICJob21lIjogImZvbyIsICJyb2xlcyI6ICJ1c2VycyIsICJleHAiOiAxODAwfQ.9y7krxxJ_n1Mmq8yhSfwkKw5Mx1Ycwht0nWjLBjJB90; Path=/; Domain=.ouistiti.net
		Set-Cookie: X-Remote-User=foo; Path=/; Domain=.ouistiti.net
		Set-Cookie: X-Remote-Group=users; Path=/; Domain=.ouistiti.net
		Set-Cookie: X-Remote-Home=~/; Path=/; Domain=.ouistiti.net
		Location: https://localhost/index.html

The redirection server (example.com) must allow to receive Cookie from our server
and it must know how to use it.

A token server may set like that:

		auth = {
			realm = "welcome to ouistiti";
			file = "shadow";
			type = "Basic";
			unprotect="^trust/*";
			options = "cookie,token";
			signin = "trust/signin.htnl";
		};
		redirect = {
			links = ({
				origin = "^token$";
			});
		};

 1. The User-Agent tries to connect on example.com which refused the connection
 and redirectes it to the
 https://www.ouistiti.net/token=redirect_uri=http://www.example.com server.
 2. The first request on "/token" is refused and redirected on the "trust/signin.html".
 3. If the credential are good, the response contains user's information and his token.
 4. The User-Agent uses this credential to request twice the "/token".
 5. The authentication server accepts and uses the "redirect_uri" to move the user to
 http://www.example.com server.

Read [Beare authentication](auth_bearer.md) for more information.

### options

Same options of the server are availables on each link (generate_204, hsts, temporary,
permanently)

A specific option is availlable:

 * error : to use with a numbered origin.
