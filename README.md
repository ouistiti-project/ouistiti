Ouistiti - Small HTTP server
============================

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

Ouistiti is written to be build on a maximum of system. The code is 
C standard, the threads may be disabled and the configuration may be
loaded from memory.

For an optimal featured solution, Ouistiti needs:
 * pthread library
 * libconfig library

Some modules need external libraries:
 * mbedtls library
 * libb64 library (as a git submodule)

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

 2) Keep Alive connection: The client connection may be keep between
 several requests.

 3) HTTP pipelining: The server in HTTP/1.1 and over may receive several
 requests and send the responses in the same time.
 
 5) HTTP streaming: A module may send big binary file or live streaming.

 4) HTTPS: SSL connection is available as module with mbedtls library.

 5) CGI/1.1: CGI scripts may be call from the client. The server may
 run "webmin".

 6) Authentication: Basic authentication is available.

Build and installation
======================

The first step is to add the libhttpserver source tree.

    git clone https://github.com/mchalain/libhttpserver

The project configuration may be done with the "config" file edition
(a "default.config" file is available). Or it may be done with "configure"
script.

    ./configure --prefix=/usr --libdir=/usr/lib64/ouistiti --sysconfdir=/etc

The compilation is done with make and accept configuration in command line.

    make DEBUG=y

The installation will copy the library into /usr/local/lib/ directory,
and binary into /usr/local/bin with the default configuration. The paths
may be changed during the project configuration (see below)

    make DESTDIR=~/packages/ouistiti install

Configurations
==============

Each option may be set with "y" to be included. Other value disables the
feature.

STATIC_CONFIG use the configuration defined into the src/config.h file.
