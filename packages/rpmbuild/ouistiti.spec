Name:           ouistiti
Version:        3.4.0
Release:        0
Summary:        HTTP server
Group:          Application/Network
License:        MIT
URL:            https://github.com/ouistiti-project/ouistiti
Vendor:         Object Computing, Incorporated
Source:         https://github.com/ouistiti-project/ouistiti/archive/refs/tags/ouistiti-%{version}.tar.gz
Prefix:         %{_prefix}
Packager:       Marc Chalain <marc.chalain@gmail.com>
BuildRoot:      %{_tmppath}/ouistiti
Requires:	libconfig openssl sqlite jansson
BuildRequires:	libconfig-devel openssl-devel sqlite-devel jansson-devel

%package devel
Version:        %{version}
Summary:	Development files for ouistiti Webserver
Group:          Application/Development
Requires:       ouistiti

%package utils
Version:        %{version}
Summary:	Utils for ouistiti Webserver
Group:          Application/Network
Requires:       ouistiti

%description
Small HTTP server for Embed System

%description devel
Development files for ouistiti Webserver

%description utils
Small utilities running with ouistiti HTTP server.
This offers:
 - websocket server: chat, echo, gps
 - sebstream server: mjpeg from camera

%global debug_package %{nil}

%prep
%setup -q -c ouistiti
rm -f .config

%build
cd ouistiti-%{version}
CFLAGS="$RPM_OPT_FLAGS" make prefix=/usr sysconfdir=/etc/ouistiti libdir=/usr/lib64 pkglibdir=/usr/lib64/ouistiti MJPEG=y WEBCOMMON=y threadpool_defconfig

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
cd ouistiti-%{version}
CFLAGS="$RPM_OPT_FLAGS" make DESTDIR=$RPM_BUILD_ROOT install

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
cd ouistiti-%{version}
CFLAGS="$RPM_OPT_FLAGS" make clean

%files
%defattr(-,root,root)
%doc README.md LICENSE
%{_sbindir}/ouistiti
%{_libdir}/ouistiti/mod_*.so
%{_sysconfdir}/ouistiti/*
/srv/www/*

%files devel
%defattr(-,root,root)
%doc README.md LICENSE
%{_includedir}/ouistiti/*

%files utils
%defattr(-,root,root)
%doc README.md LICENSE
%{_libexecdir}/ouistiti/*
%{_libdir}/ouistiti/authrpc.so
%{_libdir}/ouistiti/jsonsql.so
%{_datadir}/ouistiti/*

%changelog


