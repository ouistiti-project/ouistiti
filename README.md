
Ouistiti - Small HTTP server
============================

# Ouistiti

Ouistiti _(ˈwistiti)_ is the french name of [Marmoset](https://en.wikipedia.org/wiki/Marmoset)
a little monkey of the New World.
 
Ouistiti is a small web server to manage and to configure small devices.
It allows to create an **unified Web interface** for **security** on 
**Documents**, **Websocket**, **Rest API** and more.

# libhttpserver

**ouistiti** is build over the libhttpserver library. This library contains
HTTP parser, the socket's management and some generic modules.

The project is available on *github*

    https://github.com/ouistiti-project/libhttpserver

# Features

 1) Multi HTTP versions: The server configuration may set the version
  of HTTP to response: HTTP/0.9 HTTP/1.0 HTTP/1.1 .
  HTTP/2.0 may be possible with a future modules.

 2) Keep Alive connection:  
 The client connection may be keep between several requests.

 3) HTTP pipelining:  
 The server in **HTTP/1.1 pipelining** and it may receive several
 requests and send the responses in the same time.
 
 4) HTTPS:
    **TLS/SSL connection** is available as module with mbedtls library.

 5) Authentication:  
 The *authentication is available on all client connection*. The users'
 password may be encrypted for the storage. The following challenge
 are supported:
 
    * **Basic Authentication** RFC7616.  
    * **Digest Authentication** RFC7617.  

 6) HTTP streaming:  
 A module may connect a UNIX socket from another application to the
 client connection.

 7) Websocket:  
 A module build a **Websocket bridge** between HTTP socket client and UNIX socket.
 It may manage the handshake and transfer the data to another application,or
 just get the socket handler to another application which manages websocket
 protocol itself.

 8) Static documents:
 The server may send files from a directory, with optimization for UNIX
 system.

 9) HTTP RangeRequest:
 The HTTP headers **RangeRequest** is supported to send a part of a file.

 10) Rest API on the documents:
 The server allows to manage the document files with the **Rest API**. It's
 possible to upload, delete files.

 11) CGI/1.1:  
 **CGI scripts** may be call from the client.

 12) Virtual hosting:  
 Each server socket may manage several Hostname  with files, cgi and
 authentication managers.

 13) Connection filtering
 The server may start with a list of IP address to refuse or IP address
 to accept.

# Dependencies

Ouistiti is written to be built on a maximum of system. The code is
C99 compliant, the threads may be disabled and the configuration may be
loaded from memory.

For an optimal featured solution, Ouistiti needs:  
 * pthread library, if the configuration contains : VTHREAD_TYPE=pthread .
 * [libconfig](http://www.hyperrealm.com/libconfig/) library if the configuration contains FILE_CONFIG=y .

Some modules need external libraries:  
 * SSL/TLS module: [mbedtls](https://tls.mbed.org/) library
 * Authentication module: [jansson](https://jansson.org) and
 [sqlite](https://) libraries

 If any SSL/TLS module is available, the following libraries may be used:
 * [md5-c](http://userpages.umbc.edu/~mabzug1/cs/md5/md5-c-100.tar.gz) library
 * [libmd5-rfc](https://sourceforge.net/projects/libmd5-rfc/) library
 * [libb64](http://libb64.sourceforge.net/) library (as a git submodule)

The memory allocation is dynamic, but the functions "calloc" and "free" are
inside macros, to allow a specific implementation.

# Platforms support

The first version ran on Linux and Windows.
Currently only the Linux version is tested.

# Build and installation

## Download
The first step download the  source tree.

```sh
    git clone https://github.com/ouistiti-project/ouistiti
```

And the libhttpserver project

```sh
    git clone https://github.com/ouistiti-project/libhttpserver
```

There is 2 ways to build:

 * Build the libhtppserver outside the ouistiti tree
 * Add libhttpserver directory inside the root of ouistiti

## Configuration

The project uses [makemore](https://github.com/mchalain/makemore) to build
all binaries.

[makemore] contains a gnumake file and a *configure* script. The script is used
to write a *config* file from the *default.config* file. With *configure*
you may select the installation directories and the parts to build.

You may use the default setting or watch the options available:

```sh
 ./configure --help
```

A simple installation setup is :

```sh
 ./configure --prefix=/usr --libdir=/usr/lib/ouistiti --sysconfdir=/etc/ouistiti
```

When *configure* is completing, it generates several files. The most
important one is *config* that you may modify yourself.

The *config* file contains variables and their value. Currently the
value should be **y** or **n**. For some specific cases, it is a string.

### Server configuration:

 * STATIC_CONFIG : use the configuration defined into the src/config.h file.  
 * FILE_CONFIG : use the ouistiti.conf file for the configuration.  

 * VTHREAD : enable the multithreading into the server.  
 * VTHREAD_TYPE : take a value like [fork|pthread|windows] to specify how to manage threads.  

 * STATIC : build the application, libraries (libhttpserver, libutils...) and modules into a standalone binary.  
 * SHARED : build/link the dynamic libraries (libhttpserver, ...) and the application with integrated modules.  
 * MODULES : build the modules as dynamic libraries, the application will load at the run time.

 * MAX_SERVERS : allow to choice the number of servers and virtual hosts to manage.  

### Modules configuration:

 * MBEDTLS : build the SSL/TLS support with mbedtls.  
 * CGI : build the CGI/1.1 support.  
 * DOCUMENT : build the [document](docs/mod_document.md) module.  
 * AUTH : build the [authentication](docs/mod_auth.md) module.  
 * VHOSTS : build virtual hosting's extension.  
 * WEBSOCKET : build the [websocket](docs/mod_websocket.md) module.  
 * CLIENTFILTER : build the connection filtering module.


## Compilation

The compilation is done with **gmake** and accepts configuration in command line.

```sh
 make DEBUG=y
```

### Cross compilation

**Ouistiti** may be build for another target than the build host. To do
that you needs to add some configurations:

 * CROSS_COMPILE : defines the **gcc** prefix to use.
 * sysroot : defines the path of the sysroot where the tools should find
 the dependences.

```sh
 make CROSS_COMPILE=arm-linux-gnueabihf
```
 
## Installation

The default installation will copy the library into */usr/local/lib/* directory,
and binary into */usr/local/bin* with the default configuration. The paths
may be changed during the project configuration (see below)

> make install

To create a new directories' tree before the installation, the *DESTDIR*
variable may be changed.

> make DESTDIR=~/packages/ouistiti install

## Packaging

**ouistiti** is distributed with rules to build a distribution's package.

 * [buildroot](http://buildroot.org)
 * [slackware](http://slackware.com)
 * [debian](http://debian.org)

# Configuration

Ouistiti uses [libconfig](http://www.hyperrealm.com/libconfig/) for
the configuration. Find more information into
[configuration chapter](docs/config.md).

# Performances

## Binaries size

Ouistiti allows to select each feature that you need during the build configuration.
The default configuration allows to use all features into the minimum place.

Here some sizes for arm after stripping:

 * all features statically linked:   **79ko** + (mbedtls, libconfig, sqlite3, crypt and c libraries)
 * a small configuration (document):    47ko + (c library)
 * with the features as modules: 28ko + 177ko of modules + 85ko of libhttpserver and other libraries

## Memory usage

The memory usage depends to the build configuration and the number of simultanous connections.

With the default configuration for arm architecture the usage is around **4.5Mo** for the main process
and around **13.5Mo** for each client's connection. But the small configuration needs only **5.5 Mo**.

The [performance](docs/performance.md) page gives more informations about memory usage.

## Timing

Ouistiti is not a web server for big network, but it get good results for the document delivery.
The performances depend to the build configuration and you need.

 * To get the best results, Ouistiti needs to be build without thread
 management (VTHREAD=n).
 * To get the maximum of security, Ouistiti needs to be build with one
 process per client (VHTREAD=y and VTHREAD_TYPE=fork).

Ouistiti may be faster than lighttpd 1.4, but without all features.
You can find some test results into the [performance](docs/performance.md) page.

