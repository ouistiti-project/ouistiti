Name:           ouistiti
Version:        3.1
Release:        2
Summary:        HTTP server
Group:          Application/Network
License:        MIT
URL:            https://github.com/ouistiti-project/ouistiti
Vendor:         Object Computing, Incorporated
Source:         https://github.com/ouistiti-project/ouistiti/archive/refs/tags/ouistiti-%{version}.tar.gz
Prefix:         %{_prefix}
Packager:       Marc Chalain <marc.chalain@gmail.com>
BuildRoot:      %{_tmppath}/ouistiti
Requires:	libouistiti libconfig mbedtls sqlite jansson
BuildRequires:	libouistiti-devel libconfig-devel mbedtls-devel sqlite-devel jansson-devel

%package utils
Version:        %{version}
Summary:	Utils for ouistiti HTTP server
Group:          Application/Network
Requires:       libouistiti

%description
Small HTTP server for Embed System

%description utils
Small utilities for websocket with ouistiti HTTP server

%global debug_package %{nil}

%prep
%setup -q -c ouistiti
rm -f .config

%build
CFLAGS="$RPM_OPT_FLAGS" make prefix=/usr sysconfdir=/etc/ouistiti libdir=/usr/lib64 pkglibdir=/usr/lib64/ouistiti STATIC=n TINYSVCMDNS=n fullforked_defconfig
CFLAGS="$RPM_OPT_FLAGS" make LIBHTTPSERVER_NAME=ouistiti

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
CFLAGS="$RPM_OPT_FLAGS" make package=ouistiti DESTDIR=$RPM_BUILD_ROOT install

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
CFLAGS="$RPM_OPT_FLAGS" make package=ouistiti clean

%files
%defattr(-,root,root)
%doc README.md LICENSE
%{_sbindir}/ouistiti
%{_libdir}/ouistiti/mod_*.so
%{_sysconfdir}/ouistiti/*

%files utils
%defattr(-,root,root)
%doc README.md LICENSE
%{_libexecdir}/ouistiti/*
%{_libdir}/ouistiti/authrpc.so
%{_libdir}/ouistiti/jsonsql.so

%changelog


