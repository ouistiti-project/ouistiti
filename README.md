Ouistiti - Small featured HTTP server
=====================================
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=ouistiti-project_ouistiti&metric=alert_status)](https://sonarcloud.io/dashboard?id=ouistiti-project_ouistiti)
[![Build Status](https://travis-ci.com/ouistiti-project/ouistiti.svg?branch=master)](https://travis-ci.com/ouistiti-project/ouistiti)

# Ouistiti

Ouistiti _(ˈwistiti)_ is the french name of [Marmoset](https://en.wikipedia.org/wiki/Marmoset)
a little monkey of the New World.

Ouistiti is a small web server to manage and to configure small devices.
It allows to create an **unified Web interface** for **security** on
**Documents**, **Websocket**, **Rest API** and more.

Ouistiti is dedicated to be embedded on device for control from a web server.

With *Ouistiti*, all pages, websockets, scripts are protected by the same way.
It is useless to manage the authentication by your-self.

# Features

## Multi HTTP versions:

   * **HTTP/0.9** **HTTP/1.0** **HTTP/1.1** : *Ouistiti* is able to manage each version
    of the HTTP protocol from the requests or to accept only the requests of one version.
   * **Keep Alive** connection: A client connection may be use for several requests.
   * **pipeline** requests: *Ouistiti* is able to receive request during the management
    of the previous one in the same connection.

## Secure HTTP - *HTTPS*:

   **TLS/SSL connection** is available as module with *mbedtls* or *openssl* library.

## Authentication:

  The __authentication__ is available on *all client's connection*. The users'
  password may be encrypted for the storage. The following challenge
  are supported:

   * **Basic Authentication**: *Ouistiti* is able to check the users to the simplest way.
   * **Digest Authentication**: *Ouistiti* allows to create your connection page and check
    the rights.
   * **Bearer Authentication**: *Ouistiti* is able to create a token and all instances
    of *Ouistiti* is able to check this token on the same network domain.
   * **OpenID Authentication**: Manage the users on a OpenID server (like Google) and
    *Ouistiti* checks the user's rights on it.

## Websocket:

   A module build a **Websocket bridge** between HTTP socket client and UNIX socket.
   It is able to manage the handshake and the transfer of data to your application.
   You develop a STREAM server on a UNIX socket, *Ouistiti* protects it on a HTTPS
   connection.

## HTTP streaming:

   Like the *Websocket*, *Ouistiti* is able to protect your __stream's server__. Your
   application should only send data on a STREAM socket, *Ouistiti* does the rest.

## Static documents:

   Like any webserver, *Ouistiti* is able to send any kinds of files to your client.
   And in the same time it can manage them on your server:

   * **Rest API**: it allows to manage the document files with a **Rest API** to
     upload, delete, rename the files directly on the server.
   * **Home directory**: each user can manage his own directory with his __private rights__.
   * **Range request**: file may be broken into many chunks for the download.

## CGI/1.1:

   **CGI scripts** may be call from the client.

## Connection filtering:

   The server may start with a __blacklist__ and a __whitelist__ of IP address.

## Mono threading or multi threading:

   *Ouistiti* may be build to manage client connections with only one process, to
   be the __fastest webserver__.
   Or it may create a independants process for each client connection, to create
   a __sandbox__ around it.

# Dependencies

Ouistiti is written to be built on a maximum of system. The code is
C99 compliant, the threads may be disabled and the configuration may be
loaded from memory.

## libhttpserver (libouistiti)

*Ouistiti* is build over the libhttpserver library. This library contains
HTTP parser, the socket's management and some generic modules.

The project is available on *[github](https://github.com/ouistiti-project/libhttpserver)*

*libhttpserver* may be renamed *libouistiti* when the sources of
the library is available inside *ouistiti* project.

## libb64

The project [libb64](http://libb64.sourceforge.net/) is mandatory with some patches.
The source is available in [ouistiti-project](https://ouistiti-project.github.com/libb64)
or inside *ouistiti* project.

## cryptographic library

SSL/TLS support may be provided by several libraries:

 * [mbedtls](https://tls.mbed.org/) library
 * [openssl](https://www.openssl.org/) library

For authentication dialog with the client the password may be encrypted
with *md5* algorithm (this one is not safe, but it is mandatory at least
for Basic and Digest authentication). If SSL/TLS is not available, one
md5 library is mandatory for authentication modules:

 * [md5-c](http://userpages.umbc.edu/~mabzug1/cs/md5/md5-c-100.tar.gz) library
 * [libmd5-rfc](https://sourceforge.net/projects/libmd5-rfc/) library

## thread library

*ouistiti* may not use the pthread library, this depends on the configuration.
But some tools may use the pthread library like websocket servers.

## other libraries

 * [libconfig](http://www.hyperrealm.com/libconfig/) library if the configuration contains FILE_CONFIG=y .
 * [jansson](https://jansson.org) library for JWT inside the authentication module
 * [sqlite](https://) library to manage users database of the authentication

# Platforms support

The first version ran on Linux and Windows.
Currently only the Linux version is tested.

# Build and installation

## Download
The first step download the  source tree.

```sh
    $ git clone https://github.com/ouistiti-project/ouistiti
```

And the libhttpserver project

```sh
    $ git clone https://github.com/ouistiti-project/libhttpserver
```

There is 2 ways to build:

 * Build the libhtppserver outside the ouistiti tree
 * Add libhttpserver directory inside the root of ouistiti

## Configuration

The project uses [makemore](https://github.com/mchalain/makemore) to build
all binaries.

[makemore](https://github.com/mchalain/makemore) contains a gnumake file
and a *configure* script. The script is used to write a *config* file from
the *default.config* file. With *configure* you may select the installation
directories and the parts to build.

```sh
$ ./configure --prefix=/usr --libdir=/usr/lib/ouistiti --sysconfdir=/etc/ouistiti
```

[makemore](https://github.com/mchalain/makemore) may run as Kbuild makefile.
It is possible to select a configuration file directly with make.

Other configurations are availables inside *configs/* directory:
	* *fastmono_defconfig* for a fast server but without crash protection.
	* *fullforked_defconfig* for a server which is able to continue to run
	after a crash of a connection.

```sh
$ make fastmono_defconfig
```
or
```sh
$ make fullforked_defconfig
```
or for a default configuration:
```sh
$ make defconfig
```

For an embedded device like a gateway or a box, the *fullforked_defconfig*
is recommanded.

### Build configuration:

The configuration is a text file with fields and values.
The *defconfig* file on the root directory must not be changed. It is possible
to modify or copy an existing file in *configs/* directory.

The fields
 * FILE_CONFIG : use the ouistiti.conf file for the configuration.

 * VTHREAD : enable the multithreading into the server.
 * VTHREAD_TYPE : take a value like [fork|pthread|windows] to specify how to manage threads.

 * STATIC : build the application, libraries (libhttpserver, libouiutils...) and modules into a standalone binary.
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

*Ouistiti* is available a specific option *DEBUG* to add traces in the code and
the debug symbol.
```sh
$ make DEBUG=y
```

[makemore] allows to watch the compilation line with the *V* option:
```sh
$ make V=1
```

### Cross compilation

*Ouistiti* may be build for another target than the build host. To do
that you needs to add some configurations:

 * CROSS_COMPILE : defines the **gcc** prefix to use.
 * sysroot : defines the path of the sysroot where the tools should find
 the dependences.

```sh
$ make CROSS_COMPILE=arm-linux-gnueabihf
```

## Installation

The default installation will copy the library into */usr/local/lib/* directory,
and binary into */usr/local/bin* with the default configuration. The paths
may be changed during the project configuration (see below)

```sh
> make install
```

To create a new directories' tree before the installation, the *DESTDIR*
variable may be changed.

```sh
> make DESTDIR=~/packages/ouistiti install
```

## Packaging

*Ouistiti* is distributed with the recipes to build a distribution's package.

 * [buildroot](https://www.buildroot.org)
 * [yocto](https://www.yoctoproject.org/)
 * [slackware](http://slackware.com)
 * [debian](https://debian.org)

# Configuration

Ouistiti uses [libconfig](http://www.hyperrealm.com/libconfig/) for
the configuration. Find more information into
[configuration chapter](docs/config.md).

# Performances

## Binaries size

Ouistiti allows to select each feature that you need during the build configuration.
The default configuration allows to use all features into the minimum place.

Here some sizes for arm after stripping:

 * all features statically linked:   **154ko** + (mbedtls, libconfig, sqlite3, crypt and c libraries)
 * a small configuration (document):    73ko + (c library)
 * with the features as modules: 24ko + 158ko of modules + 60ko of libhttpserver and other libraries

## Memory usage

The memory usage depends to the build configuration and the number of simultanous connections.

With the default configuration for arm architecture the usage is around **4.5Mo** for the main process
and around **13.5Mo** for each client's connection. But the small configuration needs only **5.5 Mo**.

With only one process in *Ouistiti* the VmSize is around **26Mo**.

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

