Ouistiti - Small HTTP server
============================

Ouistiti is the french name of [Marmoset](https://en.wikipedia.org/wiki/Marmoset)
a little Monkey of the New world. The choice of the name comes from the size of
this monkey and the pronunciation _(ˈwistiti)_ which remembers HTTP.
 
The main goal of Ouistiti is a very small HTTP server to be embedded into
very small devices.

 all features statically linked:   66ko  
 with the features as modules: 35ko  
 in embedded configuration:    29ko  

libhttpserver
=============

Ouistiti is build over the libhttpserver library. This library is an
external project and may be use into other projects.

The project is available on github

    https://github.com/mchalain/libhttpserver

This library may be integrated into another application to allows
a HTTP service.

Dependencies
============

Ouistiti is written to be built on a maximum of system. The code is 
C standard, the threads may be disabled and the configuration may be
loaded from memory.

For an optimal featured solution, Ouistiti needs:  
 * pthread library
 * [libconfig](http://www.hyperrealm.com/libconfig/) library

Some modules need external libraries:  
 * [mbedtls](https://tls.mbed.org/) library
 * [libb64](http://libb64.sourceforge.net/) library (as a git submodule)

 (optionals)  
 * [md5-c](http://userpages.umbc.edu/~mabzug1/cs/md5/md5-c-100.tar.gz) library
 * [libmd5-rfc](https://sourceforge.net/projects/libmd5-rfc/) library

The memory allocation is dynamic, but the functions "calloc" and "free" are
inside macros, to allow the specific implementation.

Platforms support
=================

The first version ran on Linux and Windows.
Currently only the Linux version is tested.

Features
========

 1) Multi HTTP versions: The server configuration may set the version
  of HTTP to response: HTTP/0.9 HTTP/1.0 HTTP/1.1 .
  HTTP/2.0 may be possible with a future modules.

 2) Keep Alive connection:  
 The client connection may be keep between several requests.

 3) HTTP pipelining:  
 The server in HTTP/1.1 and over may receive several requests and send the responses in the same time.
 
 5) HTTP streaming:  
 A module may send big binary file or live streaming.

 4) HTTPS:
	TLS/SSL connection is available as module with mbedtls library.

 5) CGI/1.1:  
	CGI scripts may be call from the client. The server may run "webmin".

 6) Files exposure:  
	file sending use "sendfile" system call;  
	dirlisting display the directory content if the index is not availlable.  

 7) Authentication:  
	* Basic challenge.  
	* Digest challenge.  

 8) Virtual hosting:  
	Each server socket may manage several Hostname with files, cgi and authentication managers. 
 
Build and installation
======================

The first step is to add the libhttpserver source tree.

    git clone https://github.com/mchalain/libhttpserver

The project configuration may be done with the "config" file edition
(a "default.config" file is available). Or it may be done with "configure"
script.

    ./configure --prefix=/usr --libdir=/usr/lib64/ouistiti --sysconfdir=/etc

Other build setup are available into the "config" file (see Build Setup chapter).

The compilation is done with make and accept configuration in command line.

    make DEBUG=y

The installation will copy the library into /usr/local/lib/ directory,
and binary into /usr/local/bin with the default configuration. The paths
may be changed during the project configuration (see below)

    make DESTDIR=~/packages/ouistiti install

Build setup
==============

Each option may be set with "y" to be included. Other value disables the
feature.

DEBUG : allow more debug traces and add debugger symbols.  

STATIC_CONFIG : use the configuration defined into the src/config.h file.  
FILE_CONFIG : use the ouistiti.conf file for the configuration.  

VTHREAD : enable the multithreading into the server.  
VTHREAD_TYPE : take a value like [fork|pthread|windows] to specify how to manage threads.  
STATIC : build the application and the modules into one binary file.  
DYNAMIC :  allow to load dynamicly the modules.  
MAX_SERVERS : allow to choice the number of servers and virtual hosts to manage.  

MBEDTLS : build the SSL/TLS support with mbedtls.  
CGI : build the CGI/1.1 support.  
STATIC_FILE : build the delivery of static files.  
SENDFILE : build the extension of STATIC_FILE to increase the speed.  
DIRLISTING : build the extention of STATIC_FILE to display the directory content.  
AUTH : build the support of the authentication.  
AUTHN_BASIC : add a Basic challenge method for AUTH.  
AUTHN_DIGEST : add a Digest challenge method for AUTH.  
AUTHZ_SIMPLE : add simple user/password configuration.
VHOSTS : build virtual hosting's extension.

Configuration
=============

Ouistiti uses [libconfig](http://www.hyperrealm.com/libconfig/) for 
the configuration. The configuration file looks like a C file, with variables
and structure.


