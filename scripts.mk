MAKEFLAGS+=--no-print-directory
ifeq ($(inside_makemore),)
makemore?=$(word 2,$(MAKEFILE_LIST))
export makemore
file?=$(notdir $(firstword $(MAKEFILE_LIST)))
inside_makemore:=yes

version_m=$(firstword $(subst ., ,$(version)))
export package
export version

##
# debug tools
##
V=0
ifeq ($(V),1)
quiet=
Q=
else
quiet=quiet_
Q=@
endif
echo-cmd = $(if $($(quiet)cmd_$(1)), echo '  $($(quiet)cmd_$(1))';)
cmd = $(echo-cmd) $(cmd_$(1))

##
# file extention definition
bin-ext=
slib-ext=a
dlib-ext=so
makefile-ext=mk

##
# make file with targets definition
##
bin-y:=
sbin-y:=
lib-y:=
slib-y:=
modules-y:=
modules-y:=
data-y:=
hostbin-y:=

srcdir?=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

#ifneq ($(findstring -arch,$(CFLAGS)),)
#ARCH=$(shell echo $(CFLAGS) 2>&1 | $(AWK) 'BEGIN {FS="[- ]"} {print $$2}')
#buildpath=$(join $(srcdir),$(ARCH))
#endif
ifneq ($(BUILDDIR),)
  builddir=$(BUILDDIR:%/=%)/
  buildpath:=$(if $(wildcard $(addprefix /.,$(builddir))),$(builddir),$(join $(srcdir),$(builddir)))
else
  builddir=$(srcdir)
endif

# internal configuration to install HEADERS file or not
DEVINSTALL?=y
# CONFIG could define LD CC or/and CFLAGS
# CONFIG must be included before "Commands for build and link"
VERSIONFILE?=$(builddir)version.h
CONFIGFILE?=$(builddir)config.h
DEFCONFIG?=$(srcdir)defconfig
CONFIG:=$(builddir).config

ifneq ($(wildcard $(CONFIG)),)
  include $(CONFIG)
# define all unset variable as variable defined as n
  $(foreach config,$(shell cat $(CONFIG) | awk '/^. .* is not set/{print $$2}'),$(eval $(config)=n))
endif
PATHCACHE=$(builddir).pathcache
ifneq ($(wildcard $(PATHCACHE)),)
  include $(PATHCACHE)
endif

ifneq ($(file),)
  include $(file)
endif

ifneq ($(buildpath),)
  obj=$(addprefix $(buildpath),$(cwdir))
else
  ifneq ($(CROSS_COMPILE),)
	buildpath:=$(builddir)$(CROSS_COMPILE:%-=%)/
    obj:=$(addprefix $(buildpath),$(cwdir))
  else
    obj=
  endif
endif
hostobj:=$(builddir)host/$(cwdir)

PATH:=$(value PATH):$(hostobj)
TMPDIR:=/tmp
TESTFILE:=makemore_test
##
# default Macros for installation
##
# not set variable if not into the build step
AWK?=awk
GREP?=grep
RM?=rm -f
LN?=ln -f -s
INSTALL?=install
INSTALL_PROGRAM?=$(INSTALL) -D
INSTALL_DATA?=$(INSTALL) -m 644 -D
PKGCONFIG?=pkg-config
YACC?=bison
MOC?=moc$(QT:%=-%)
UIC?=uic$(QT:%=-%)

TOOLCHAIN?=
CROSS_COMPILE?=
CC?=gcc
CFLAGS?=
CXX?=g++
CXXFLAGS?=
LD?=gcc
LDFLAGS?=
AR?=ar
RANLIB?=ranlib
GCOV?=gcov
HOSTCC?=$(CC)
HOSTCXX?=$(CXX)
HOSTLD?=$(LD)
HOSTAR?=$(AR)
HOSTRANLIB?=$(RANLIB)
HOSTCFLAGS?=$(CFLAGS)
HOSTLDFLAGS?=$(LDFLAGS)

export PATH:=$(PATH):$(TOOLCHAIN):$(TOOLCHAIN)/bin
# if cc is a link on gcc, prefer to use directly gcc for ld
ifeq ($(CC),cc)
 TARGETCC:=gcc
else
 TARGETCC:=$(CC)
endif
TARGETLD:=$(LD)
TARGETAS:=$(AS)
TARGETCXX:=$(CXX)
TARGETAR:=$(AR)
TARGETRANLIB:=$(RANLIB)
TARGETGCOV:=$(GCOV)

CCVERSION:=$(shell $(TARGETCC) -v 2>&1)
ifneq ($(dir $(TARGETCC)),./)
	TARGETPREFIX=
else
	ifneq ($(CROSS_COMPILE),)
		ifeq ($(findstring $(CROSS_COMPILE),$(TARGETCC)),)
			TARGETPREFIX=$(CROSS_COMPILE:%-=%)-
		endif
	else
		TARGETPREFIX=
	endif
endif
TARGETCC:=$(TARGETPREFIX)$(TARGETCC)
TARGETLD:=$(TARGETPREFIX)$(LD)
TARGETAS:=$(TARGETPREFIX)$(AS)
TARGETCXX:=$(TARGETPREFIX)$(CXX)
TARGETAR:=$(TARGETPREFIX)$(AR)
TARGETRANLIB:=$(TARGETPREFIX)$(RANLIB)
TARGETGCOV:=$(TARGETPREFIX)$(GCOV)

ARCH?=$(shell LANG=C $(TARGETCC) -dumpmachine | awk -F- '{print $$1}')
libsuffix?=/$(shell $(TARGETCC) -dumpmachine)
ifeq ($(CC),gcc)
SYSROOT=$(shell $(TARGETCC) -print-sysroot)
endif

ifneq ($(SYSROOT),)
sysroot:=$(patsubst "%",%,$(SYSROOT:%/=%)/)
TARGETPATHPREFIX=$(sysroot)
SYSROOT_CFLAGS+=--sysroot=$(sysroot)
SYSROOT_CFLAGS+=-isysroot $(sysroot)
SYSROOT_LDFLAGS+=--sysroot=$(sysroot)
else
sysroot:=
TARGETPATHPREFIX=
endif

ifneq ($(PREFIX),)
prefix=$(PREFIX)
endif
prefix?=/usr/local
exec_prefix?=$(prefix)
program_prefix?=
library_prefix?=lib
bindir?=$(exec_prefix)/bin
sbindir?=$(exec_prefix)/sbin
libexecdir?=$(exec_prefix)/libexec/$(package:"%"=%)
libdir?=$(strip $(exec_prefix)/lib$(if $(wildcard $(sysroot)$(exec_prefix)/lib$(libsuffix)),$(libsuffix)))
sysconfdir?=$(prefix)/etc
includedir?=$(prefix)/include
datadir?=$(prefix)/share/$(package:"%"=%)
pkgdatadir?=$(datadir)
pkglibdir?=$(libdir)/$(package:"%"=%)
localstatedir?=$(prefix)/var
PATHES=prefix exec_prefix library_prefix bindir sbindir libexecdir libdir sysconfdir includedir datadir pkgdatadir pkglibdir localstatedir
export $(PATHES)
ifeq ($(destdir),)
destdir:=$(abspath $(DESTDIR))
export destdir
endif

#CFLAGS+=$(foreach macro,$(DIRECTORIES_LIST),-D$(macro)=\"$($(macro))\")
LIBRARY+=
LDFLAGS+=

GCOV_CFLAGS:=--coverage -fprofile-arcs -ftest-coverage
GCOV_LDFLAGS:=--coverage -fprofile-arcs -ftest-coverage
GCOV_LIBS:=gcov

ifneq ($(strip $(includedir)),)
SYSROOT_CFLAGS+=-I$(TARGETPATHPREFIX)$(strip $(includedir))
ifneq ($(destdir),)
SYSROOT_CFLAGS+=-I$(destdir)$(strip $(includedir))
endif
endif
ifneq ($(strip $(libdir)),)
RPATHFLAGS+=-Wl,-rpath,$(strip $(libdir))
SYSROOT_LDFLAGS+=-L$(TARGETPATHPREFIX)$(strip $(libdir))
ifneq ($(destdir),)
SYSROOT_LDFLAGS+=-L$(destdir)$(strip $(libdir))
endif
endif
ifneq ($(strip $(pkglibdir)),)
RPATHFLAGS+=-Wl,-rpath,$(strip $(pkglibdir))
SYSROOT_LDFLAGS+=-L$(TARGETPATHPREFIX)$(strip $(pkglibdir))
ifneq ($(destdir),)
SYSROOT_LDFLAGS+=-L$(destdir)$(strip $(pkglibdir))
endif
endif

INTERN_CFLAGS+=-I.
INTERN_CXXFLAGS+=-I.
INTERN_LDFLAGS+=-L.
ifneq ($(obj),)
INTERN_LDFLAGS+=-L$(obj)
endif
ifneq ($(hostobj),)
INTERN_LDFLAGS+=-L$(hostobj)
endif
ifneq ($(src),)
INTERN_CFLAGS+=-I$(src)
INTERN_CXXFLAGS+=-I$(src)
endif
INTERN_CFLAGS+=-include $(VERSIONFILE)
ifneq ($(wildcard $(builddir)config.h),)
INTERN_CFLAGS+=-include $(builddir)config.h
endif

##
# objects recipes generation
##
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y), $(eval $(t)_SOURCES+=$(patsubst %.hpp,%.moc.cpp,$($(t)_QTHEADERS) $($(t)_QTHEADERS-y))))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y), $(if $(findstring .cpp, $(notdir $($(t)_SOURCES))), $(eval $(t)_LIBS+=stdc++)))

$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y), $(eval $(t)-objs+=$(patsubst %.s,%.o,$(patsubst %.S,%.o,$(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$($(t)_SOURCES) $($(t)_SOURCES-y)))))))
target-objs:=$(foreach t, $(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y), $(if $($(t)-objs), $(addprefix $(obj),$($(t)-objs)), $(obj)$(t).o))

$(foreach t,$(hostbin-y), $(eval $(t)-objs:=$(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$($(t)_SOURCES) $($(t)_SOURCES-y)))))
$(foreach t,$(hostslib-y), $(eval $(t)-objs:=$(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$($(t)_SOURCES) $($(t)_SOURCES-y)))))
target-hostobjs:=$(foreach t, $(hostbin-y) $(hostslib-y), $(if $($(t)-objs), $(addprefix $(hostobj)/,$($(t)-objs)), $(hostobj)/$(t).o))

$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach s, $($(t)_SOURCES) $($(t)_SOURCES-y),$(eval $(t)_LIBS+=$($(s:%.c=%)_LIBS)) ))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach s, $($(t)_SOURCES) $($(t)_SOURCES-y),$(eval $(t)_LIBS+=$($(s:%.cpp=%)_LIBS)) ))

$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach s, $($(t)_SOURCES) $($(t)_SOURCES-y),$(eval $(t)_LIBRARY+=$($(s:%.c=%)_LIBRARY)) ))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach s, $($(t)_SOURCES) $($(t)_SOURCES-y),$(eval $(t)_LIBRARY+=$($(s:%.cpp=%)_LIBRARY)) ))

$(foreach t,$(lib-y) $(modules-y),$(eval $(t)_LDFLAGS+=-Wl,-soname,lib$(t).so$(version_m:%=.%)))

$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y) $(hostbin-y),$(eval $(t)_CFLAGS+=$($(t)_CFLAGS-y)))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y) $(hostbin-y),$(eval $(t)_CXXFLAGS+=$($(t)_CXXFLAGS-y)))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y) $(hostbin-y),$(eval $(t)_LDFLAGS+=$($(t)_LDFLAGS-y)))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y) $(hostbin-y),$(eval $(t)_LIBS+=$($(t)_LIBS-y)))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y) $(hostbin-y),$(eval $(t)_LIBRARY+=$($(t)_LIBRARY-y)))

$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y) $(hostbin-y),$(eval $(t)_CFLAGS+=$(INTERN_CFLAGS)))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y) $(hostbin-y),$(eval $(t)_LDFLAGS+=$(INTERN_LDFLAGS)))

ifeq ($(G),1)
CFLAGS+=$(GCOV_CFLAGS)
LDFLAGS+=$(GCOV_LDFLAGS)
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y) $(hostbin-y),$(eval $(t)_LIBS+=$(GCOV_LIBS)))
CFLAGS+=-O0
else
CFLAGS+=-O2
endif
gcov-target:=$(target-objs:%.o=%.gcov)

$(foreach t,$(slib-y) $(lib-y),$(eval include-y+=$($(t)_HEADERS)))

define cmd_pkgconfig
	$(shell $(PKGCONFIG) --silence-errors $(2) $(1))
endef
# LIBRARY may contain libraries name to check
# The name may terminate with {<version>} informations like LIBRARY+=usb{1.0}
# The LIBRARY values use pkg-config to update CFLAGS, LDFLAGS and LIBS
# After LIBS contains all libraries name to link

$(foreach l,$(LIBRARY),$(eval CFLAGS+=$(call cmd_pkgconfig,$(firstword $(subst {, ,$(subst },,$(l)))), --cflags) ) )
$(foreach l,$(LIBRARY),$(eval LDFLAGS+=$(call cmd_pkgconfig,$(firstword $(subst {, ,$(subst },,$(l)))), --libs-only-L) ) )
$(eval LIBS=$(sort $(LIBS)))
$(foreach l,$(LIBRARY),$(eval LIBS+=$(subst -l,,$(call cmd_pkgconfig,$(firstword $(subst {, ,$(subst },,$(l)))), --libs-only-l)) ) )
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach l, $($(t)_LIBRARY),$(eval $(t)_CFLAGS+=$(call cmd_pkgconfig,$(firstword $(subst {, ,$(subst },,$(l)))), --cflags))))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach l, $($(t)_LIBRARY),$(eval $(t)_LDFLAGS+=$(call cmd_pkgconfig,$(firstword $(subst {, ,$(subst },,$(l)))), --libs-only-L) ) ))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach l, $($(t)_LIBRARY),$(eval $(t)_LIBS+=$(subst -l,,$(call cmd_pkgconfig,$(firstword $(subst {, ,$(subst },,$(l)))), --libs-only-l)) ) ))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(eval $(t)_LIBS=$(sort $($(t)_LIBS))))

# set the CFLAGS of each source file
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach s, $($(t)_SOURCES) $($(t)_SOURCES-y),$(eval $(s:%.c=%)_CFLAGS+=$($(t)_CFLAGS)) ))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach s, $($(t)_SOURCES) $($(t)_SOURCES-y),$(eval $(s:%.cpp=%)_CFLAGS+=$($(t)_CFLAGS)) ))

$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach s, $($(t)_SOURCES) $($(t)_SOURCES-y),$(eval $(t)_LDFLAGS+=$($(s:%.c=%)_LDFLAGS)) ))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach s, $($(t)_SOURCES) $($(t)_SOURCES-y),$(eval $(t)_LDFLAGS+=$($(s:%.cpp=%)_LDFLAGS)) ))

# The Dynamic_Loader library (libdl) allows to load external libraries.
# If this libraries has to link to the binary functions,
# this binary has to export the symbol with -rdynamic flag
$(foreach t,$(bin-y) $(sbin-y),$(if $(findstring dl, $($(t)_LIBS) $(LIBS)),$(eval $(t)_LDFLAGS+=-rdynamic)))

##
# targets recipes generation
##

lib-check-target:=$(sort $(LIBRARY:%=check_%) $(sort $(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$($(t)_LIBRARY:%=check_%))))

ifeq (STATIC,y)
lib-static-target:=$(addprefix $(obj),$(addsuffix $(slib-ext:%=.%),$(addprefix $(library_prefix),$(slib-y) $(lib-y))))
else
lib-static-target:=$(addprefix $(obj),$(addsuffix $(slib-ext:%=.%),$(addprefix $(library_prefix),$(slib-y))))
lib-dynamic-target:=$(addprefix $(obj),$(addsuffix $(dlib-ext:%=.%),$(addprefix $(library_prefix),$(lib-y))))
endif
modules-target:=$(addprefix $(obj),$(addsuffix $(dlib-ext:%=.%),$(modules-y)))
bin-target:=$(addprefix $(obj),$(addprefix $(program_prefix),$(addsuffix $(bin-ext:%=.%),$(bin-y) $(sbin-y))))
hostslib-target:=$(addprefix $(hostobj),$(addsuffix $(slib-ext:%=.%),$(addprefix lib,$(hostslib-y))))
hostbin-target:=$(addprefix $(hostobj),$(addsuffix $(bin-ext:%=.%),$(hostbin-y)))

#create subproject
$(foreach t,$(subdir-y),$(eval $(t)_CONFIGURE+=$($(t)_CONFIGURE-y)))
$(foreach t,$(subdir-y),$(if $($(t)_CONFIGURE), $(eval subdir-project+=$(t))))
subdir-y:=$(filter-out $(subdir-project),$(subdir-y))

#append Makefile to each directory and only directory subdir
subdir-target:=$(foreach sdir,$(subdir-y),$(if $(filter-out %$(makefile-ext:%=.%), $(filter-out %Makefile, $(sdir))),$(wildcard $(addsuffix /Makefile,$(sdir:%/.=%))),$(wildcard $(sdir))))


#download-target+=$(foreach dl,$(download-y),$(DL)/$(dl)/$($(dl)_SOURCE))
$(foreach dl,$(download-y),$(if $(findstring git,$($(dl)_SITE_METHOD)),$(eval gitclone-target+=$(dl)),$(eval download-target+=$(dl))))

pkgconfig-target:=$(foreach pkgconfig,$(sort $(pkgconfig-y)),$(addprefix $(builddir),$(addsuffix .pc,$(pkgconfig))))
lib-pkgconfig-target:=$(sort $(foreach lib,$(sort $(lib-y) $(slib-y)),$(addprefix $(builddir).,$(addsuffix .pc.in,$($(lib)_PKGCONFIG)))))

objdir:=$(sort $(dir $(target-objs)))

hostobjdir:=$(sort $(dir $(target-hostobjs)))

targets:=
targets+=$(lib-dynamic-target)
targets+=$(modules-target)
targets+=$(lib-static-target)
targets+=$(bin-target)
targets+=$(lib-pkgconfig-target)
targets+=$(pkgconfig-target)

hook-targets:=$(hook-$(action:_%=%)) $(hook-$(action:_%=%)-y)

ifneq ($(CROSS_COMPILE),)
destdir?=$(sysroot:"%"=%)
endif
##
# install recipes generation
##
sysconf-install:=$(addprefix $(destdir)$(sysconfdir:%/=%)/,$(sysconf-y))
data-install:=$(addprefix $(destdir)$(datadir:%/=%)/,$(data-y))
include-install:=$(addprefix $(destdir)$(includedir:%/=%)/,$(include-y))
lib-static-install:=$(addprefix $(destdir)$(libdir:%/=%)/,$(addsuffix $(slib-ext:%=.%),$(addprefix lib,$(slib-y))))
lib-dynamic-install:=$(addprefix $(destdir)$(libdir:%/=%)/,$(addsuffix $(version:%=.%),$(addsuffix $(dlib-ext:%=.%),$(addprefix lib,$(lib-y)))))
lib-link-install:=$(addprefix $(destdir)$(libdir:%/=%)/,$(addsuffix $(version_m:%=.%),$(addsuffix $(dlib-ext:%=.%),$(addprefix lib,$(lib-y)))))
modules-install:=$(addprefix $(destdir)$(pkglibdir:%/=%)/,$(addsuffix $(dlib-ext:%=.%),$(modules-y)))
pkgconfig-install:=$(addprefix $(destdir)$(libdir:%/=%)/pkgconfig/,$(addsuffix .pc,$(sort $(pkgconfig-y))))

$(foreach t,$(bin-y),$(if $(findstring libexec,$($(t)_INSTALL)),$(eval libexec-y+=$(t))))
$(foreach t,$(bin-y),$(if $(findstring sbin,$($(t)_INSTALL)),$(eval sbin-y+=$(t))))
bin-install:=$(addprefix $(destdir)$(bindir:%/=%)/,$(addprefix $(program_prefix),$(addsuffix $(bin-ext:%=.%),$(filter-out $(libexec-y) $(sbin-y),$(bin-y)))))
sbin-install:=$(addprefix $(destdir)$(sbindir:%/=%)/,$(addprefix $(program_prefix),$(addsuffix $(bin-ext:%=.%),$(sbin-y))))
libexec-install:=$(addprefix $(destdir)$(libexecdir:%/=%)/,$(addprefix $(program_prefix),$(addsuffix $(bin-ext:%=.%),$(libexec-y))))

install:=
dev-install-y:=
dev-install-$(DEVINSTALL)+=$(lib-static-install)
install+=$(lib-dynamic-install)
install+=$(lib-link-install)
install+=$(modules-install)
install+=$(data-install)
install+=$(sysconf-install)
dev-install-$(DEVINSTALL)+=$(include-install)
install+=$(bin-install)
install+=$(sbin-install)
install+=$(libexec-install)
dev-install-$(DEVINSTALL)+=$(pkgconfig-install)

###############################################################################
# main entries
##
action:=_build
build:=$(action) -f $(srcdir)$(makemore) file
.DEFAULT_GOAL:=_entry
.PHONY:_entry _build _install _clean _distclean _check _hostbuild
_entry: _configbuild _versionbuild default_action

_info:
	@:

_hostbuild: action:=_hostbuild
_hostbuild: build:=$(action) -f $(srcdir)$(makemore) file
_hostbuild: _info $(subdir-target) $(hostobjdir) $(hostslib-target) $(hostbin-target) _hook
	@:

_gcov: action:=_gcov
_gcov: build:=$(action) -f $(srcdir)$(makemore) file
_gcov: _info $(subdir-target) $(gcov-target)
	@:

_configbuild: $(obj) $(CONFIGFILE)
_versionbuild: $(if $(package) $(version), $(VERSIONFILE))

_build: _info $(download-target) $(gitclone-target) $(objdir) $(subdir-project) $(subdir-target) $(data-y) $(targets) _hook
	@:

_install: action:=_install
_install: build:=$(action) -f $(srcdir)$(makemore) file
_install: _info $(install) $(dev-install-y) $(subdir-target) _hook
	@:

_clean: action:=_clean
_clean: build:=$(action) -f $(srcdir)$(makemore) file
_clean: _info $(subdir-target) _clean_objs _clean_targets _hook
	@:

_clean_targets:
	$(Q)$(call cmd,clean,$(wildcard $(gcov-target)))
	$(Q)$(call cmd,clean,$(wildcard $(targets)))
	$(Q)$(call cmd,clean,$(wildcard $(hostslib-target) $(hostbin-target)))

_clean_objs:
	$(Q)$(call cmd,clean,$(wildcard $(target-objs)) $(wildcard $(target-hostobjs)))

_distclean: action:=_distclean
_distclean: build:=$(action) -f $(srcdir)$(makemore) file
_distclean: $(subdir-target) _clean
	$(Q)$(call cmd,clean_dir,$(filter-out $(src),$(obj)))

_check: action:=_check
_check: build:=$(action) -s -f $(srcdir)$(makemore) file
_check: $(subdir-target) $(lib-check-target)

_hook:
	$(Q)$(foreach target,$(hook-$(action:_%=%)-y),$(MAKE) -f $(file) $(target))

PHONY:clean distclean install check default_action pc all
clean: action:=_clean
clean: build:=$(action) -f $(srcdir)$(makemore) file
clean: default_action ;

distclean: action:=_distclean
distclean: build:=$(action) -f $(srcdir)$(makemore) file
distclean: default_action cleanconfig
	$(Q)$(call cmd,clean_dir,$(wildcard $(buildpath:%=%/)host))
	$(Q)$(call cmd,clean_dir,$(wildcard $(gitclone-target)))
	$(Q)$(call cmd,clean,$(wildcard $(download-target)))
	$(Q)$(call cmd,clean,$(if $(package), $(wildcard $(builddir).*.pc.in)))

install:: action:=_install
install:: build:=$(action) -f $(srcdir)$(makemore) file
install:: _configbuild _versionbuild default_action ;

check: action:=_check
check: build:=$(action) -s -f $(srcdir)$(makemore) file
check: $(.DEFAULT_GOAL) ;

hosttools: action:=_hostbuild
hosttools: build:=$(action) -f $(srcdir)$(makemore) file
hosttools: default_action ;

gcov: action:=_gcov
gcov: build:=$(action) -f $(srcdir)$(makemore) file
gcov: default_action ;

default_action: _info
	$(Q)$(MAKE) $(build)=$(file)
	@:

all: _configbuild _versionbuild default_action ;

###############################################################################
# Commands for clean
##
quiet_cmd_clean=$(if $(2),CLEAN  $(notdir $(2)))
 cmd_clean=$(if $(2),$(RM) $(2))
quiet_cmd_clean_dir=$(if $(2),CLEAN $(notdir $(2)))
 cmd_clean_dir=$(if $(2),$(RM) -r $(2))

###############################################################################
# Commands for build and link
##
RPATH=$(wildcard $(addsuffix /.,$(wildcard $(CURDIR:%/=%)/* $(obj)*)))
quiet_cmd_yacc_y=YACC $*
 cmd_yacc_y=$(YACC) -o $@ $<
quiet_cmd_as_o_s=AS $*
 cmd_as_o_s=$(TARGETAS) $(ASFLAGS) $($*_CFLAGS) $(if $(SYSROOT),$(SYSROOT_CFLAGS)) -c -o $@ $<
quiet_cmd_cc_o_c=CC $*
 cmd_cc_o_c=$(TARGETCC) $(CFLAGS) $($*_CFLAGS) $(SYSROOT_CFLAGS) -c -o $@ $<
quiet_cc_gcov_c=GCOV $*
 cmd_cc_gcov_c=$(TARGETGCOV) -p $<
quiet_cmd_cc_o_cpp=CXX $*
 cmd_cc_o_cpp=$(TARGETCXX) $(CXXFLAGS) $(CFLAGS) $($*_CXXFLAGS) $($*_CFLAGS) $(if $(SYSROOT),$(SYSROOT_CFLAGS)) -c -o $@ $<
quiet_cmd_moc_hpp=QTMOC $*
 cmd_moc_hpp=$(MOC) $(INCLUDES) $($*_MOCFLAGS) $($*_MOCFLAGS-y) -o $@ $<
quiet_cmd_uic_hpp=QTUIC $*
 cmd_uic_hpp=$(UIC) $< > $@
quiet_cmd_ld_bin=LD $*
 cmd_ld_bin=$(TARGETCC) -L. $($*_LDFLAGS) $(LDFLAGS) $(if $(SYSROOT),$(SYSROOT_LDFLAGS)) $(RPATHFLAGS) -o $@ $^ -Wl,--start-group $(LIBS:%=-l%) $($*_LIBS:%=-l%) -Wl,--end-group -lc
quiet_cmd_ld_slib=LD $*
 cmd_ld_slib=$(RM) $@ && \
	$(TARGETAR) -cvq $@ $^ > /dev/null && \
	$(TARGETRANLIB) $@
quiet_cmd_ld_dlib=LD $*
 cmd_ld_dlib=$(TARGETCC) $($*_LDFLAGS) $(LDFLAGS) $(if $(SYSROOT),$(SYSROOT_LDFLAGS)) $(RPATHFLAGS) -Bdynamic -shared -o $@ $^ $(LIBS:%=-l%) $($*_LIBS:%=-l%) -lc

quiet_cmd_hostcc_o_c=HOSTCC $*
 cmd_hostcc_o_c=$(HOSTCC) $(HOSTCFLAGS) $($*_CFLAGS) -c -o $@ $<
quiet_hostcmd_cc_o_cpp=HOSTCXX $*
 cmd_hostcc_o_cpp=$(HOSTCXX) $(HOSTCXXFLAGS) $($*_CFLAGS) -c -o $@ $<
quiet_cmd_hostld_bin=HOSTLD $*
 cmd_hostld_bin=$(HOSTCC) -o $@ $^ $($*_LDFLAGS) $(HOSTLDFLAGS) -L. $(LIBS:%=-l%) $($*_LIBS:%=-l%)
quiet_cmd_hostld_slib=HOSTLD $*
 cmd_hostld_slib=$(RM) $@ && \
	$(HOSTAR) -cvq $@ $^ > /dev/null && \
	$(HOSTRANLIB) $@

##
# build rules
##
.SECONDEXPANSION:
$(hostobjdir) $(objdir) $(buildpath):
	$(Q)mkdir -p $@

$(obj)%.tab.c:%.y
	@$(call cmd,yacc_y)

$(obj)%.o:%.s
	@$(call cmd,as_o_s)

$(obj)%.o:%.c
	@$(call cmd,cc_o_c)

$(obj)%.o:%.cpp
	@$(call cmd,cc_o_cpp)

$(obj)%.gcov:%.c
	@$(call cmd,cc_gcov_c)

$(obj)%.moc.cpp:$(obj)%.ui.hpp
$(obj)%.moc.cpp:%.hpp
	@$(call cmd,moc_hpp)

$(obj)%.ui.hpp:%.ui
	@$(call cmd,uic_hpp)

$(hostobj)%.o:%.c
	@$(call cmd,hostcc_o_c)

$(hostobj)%.o:%.cpp
	@$(call cmd,hostcc_o_cpp)

$(lib-static-target): $(obj)lib%$(slib-ext:%=.%): $$(if $$(%-objs), $$(addprefix $(obj),$$(%-objs)), $(obj)%.o)
	@$(call cmd,ld_slib)

$(lib-dynamic-target): CFLAGS+=-fPIC
$(lib-dynamic-target): $(obj)lib%$(dlib-ext:%=.%): $$(if $$(%-objs), $$(addprefix $(obj),$$(%-objs)), $(obj)%.o)
	@$(call cmd,ld_dlib)

$(modules-target): CFLAGS+=-fPIC
$(modules-target): $(obj)%$(dlib-ext:%=.%): $$(if $$(%-objs), $$(addprefix $(obj),$$(%-objs)), $(obj)%.o)
	@$(call cmd,ld_dlib)

#$(bin-target): $(obj)/%$(bin-ext:%=.%): $$(if $$(%_SOURCES), $$(addprefix $(src)/,$$(%_SOURCES)), $(src)/%.c)
$(bin-target): $(obj)%$(bin-ext:%=.%): $$(if $$(%-objs), $$(addprefix $(obj),$$(%-objs)), $(obj)%.o)
	@$(call cmd,ld_bin)

$(hostbin-target): $(hostobj)%$(bin-ext:%=.%): $$(if $$(%-objs), $$(addprefix $(hostobj),$$(%-objs)), $(hostobj)%.o)
	@$(call cmd,hostld_bin)

$(hostslib-target): $(hostobj)lib%$(slib-ext:%=.%): $$(if $$(%-objs), $$(addprefix $(hostobj),$$(%-objs)), $(hostobj)%.o)
	@$(call cmd,hostld_slib)

###############################################################################
# subdir evaluation
#
quiet_cmd_subdir=SUBDIR $*
define cmd_subdir
	$(MAKE) -C $(dir $*) cwdir=$(cwdir)$(dir $*) builddir=$(builddir) $(build)=$(notdir $*)
endef

quiet_cmd_subdir-project=PROJECT $*
define cmd_subdir-project
	$(if $($(*)_CONFIGURE),cd $* && $($(*)_CONFIGURE))
	$(MAKE) -C $*
	$(MAKE) -C $* DESTDIR=$(destdir) install
endef

.PHONY: $(subdir-project) $(subdir-target) FORCE
$(subdir-project): %: FORCE
	@$(call cmd,subdir-project)

$(subdir-target): %: FORCE
	@$(call cmd,subdir)

###############################################################################
# Libraries dependencies checking
#
quiet_cmd_check_lib=CHECK $*
define cmd_check_lib
	$(RM) $(TMPDIR)/$(TESTFILE:%=%.c) $(TMPDIR)/$(TESTFILE)
	echo "int main(){}" > $(TMPDIR)/$(TESTFILE:%=%.c)
	$(eval CHECKLIB=$(firstword $(subst {, ,$(subst },,$2))))
	$(eval CHECKVERSION=$(if $(findstring {, $(2)),$(subst -, - ,$(lastword $(subst {, ,$(subst },,$2))))))
	$(eval CHECKOPTIONS=$(if $(CHECKVERSION),$(if $(findstring -,$(firstword $(CHECKVERSION))),--atleast-version=$(word 2,$(CHECKVERSION)))))
	$(eval CHECKOPTIONS+=$(if $(CHECKVERSION),$(if $(findstring -,$(lastword $(CHECKVERSION))),--max-version=$(word 1,$(CHECKVERSION)))))
	$(eval CHECKOPTIONS+=$(if $(CHECKVERSION),$(if $(findstring -,$(CHECKVERSION)),,--exact-version=$(CHECKVERSION))))
	$(PKGCONFIG) --exists --print-errors $(CHECKOPTIONS) $(CHECKLIB)
	$(eval CHECKCFLAGS:=$(call cmd_pkgconfig,$(CHECKLIB),--cflags))
	$(eval CHECKLDFLAGS:=$(call cmd_pkgconfig,$(CHECKLIB),--libs))
	$(TARGETCC) -c -o $(TMPDIR)/$(TESTFILE:%=%.o) $(TMPDIR)/$(TESTFILE:%=%.c) $(INTERN_CFLAGS) $(CHECKCFLAGS) > /dev/null 2>&1
	$(TARGETLD) -o $(TMPDIR)/$(TESTFILE) $(TMPDIR)/$(TESTFILE:%=%.o) $(INTERN_LDFLAGS) $(CHECKLDFLAGS) > /dev/null 2>&1
endef

$(lib-check-target): check_%:
	$(Q)$(RM) $(TMPDIR)/$(TESTFILE:%=%.c) $(TMPDIR)/$(TESTFILE)
	$(Q)echo "int main(){}" > $(TMPDIR)/$(TESTFILE:%=%.c)
	$(Q)$(call cmd,check_lib,$*)

###############################################################################
# Commands for install
##
quiet_cmd_install_data=INSTALL $*
define cmd_install_data
	$(INSTALL_DATA) $< $@
endef
quiet_cmd_install_bin=INSTALL $*
define cmd_install_bin
	$(INSTALL_PROGRAM) $< $@
endef
quiet_cmd_install_link=INSTALL $*
define cmd_install_link
$(LN) $(subst $(destdir),,$(subst .$(version_m),,$@))$(version:%=.%) $@
endef

##
# install rules
##
$(foreach dir, includedir datadir sysconfdir libdir bindir sbindir ,$(destdir)$($(dir))/):
	$(Q)mkdir -p $@

$(include-install): $(destdir)$(includedir:%/=%)/%: %
	@$(call cmd,install_data)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(dir $@) && $(RM) $(a) && ln -s $(includedir:%/=%)/$* $(a)))

$(sysconf-install): $(destdir)$(sysconfdir:%/=%)/%: %
	@$(call cmd,install_data)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(dir $@) && $(RM) $(a) && ln -s $(sysconfdir:%/=%)/$* $(a)))

$(data-install): $(destdir)$(datadir:%/=%)/%: %
	@$(call cmd,install_data)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(dir $@) && $(RM) $(a) && ln -s $(datadir:%/=%)/$* $(a)))

$(lib-static-install): $(destdir)$(libdir:%/=%)/lib%$(slib-ext:%=.%): $(obj)lib%$(slib-ext:%=.%)
	@$(call cmd,install_bin)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(dir $@) && $(RM) $(a) && ln -s (libdir:%/=%)/lib$*$(slib-ext:%=.%) $(a)))

$(lib-link-install):
	@$(call cmd,install_link)

$(lib-dynamic-install): $(destdir)$(libdir:%/=%)/lib%$(dlib-ext:%=.%)$(version:%=.%): $(obj)lib%$(dlib-ext:%=.%)
	@$(call cmd,install_bin)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(dir $@) && $(RM) $(a) && ln -s $(libdir:%/=%)/lib$*$(dlib-ext:%=.%) $(a)))

$(modules-install): $(destdir)$(pkglibdir:%/=%)/%$(dlib-ext:%=.%): $(obj)%$(dlib-ext:%=.%)
	@$(call cmd,install_bin)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(dir $@) && $(RM) $(a) && ln -s $(pkglibdir:%/=%)/$*$(dlib-ext:%=.%) $(a)))

$(bin-install): $(destdir)$(bindir:%/=%)/%$(bin-ext:%=.%): $(obj)%$(bin-ext:%=.%)
	@$(call cmd,install_bin)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(dir $@) && $(RM) $(a) && ln -s $(bindir:%/=%)/$*$(bin-ext:%=.%) $(a)))

$(sbin-install): $(destdir)$(sbindir:%/=%)/%$(bin-ext:%=.%): $(obj)%$(bin-ext:%=.%)
	@$(call cmd,install_bin)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(dir $@) && $(RM) $(a) && ln -s $(sbindir:%/=%)/$*$(bin-ext:%=.%) $(a)))

$(libexec-install): $(destdir)$(libexecdir:%/=%)/%$(bin-ext:%=.%): $(obj)%$(bin-ext:%=.%)
	@$(call cmd,install_bin)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(dir $@) && $(RM) $(a) && ln -s $(libexecdir:%/=%)/$*$(bin-ext:%=.%) $(a)))

$(pkgconfig-install): $(destdir)$(libdir:%/=%)/pkgconfig/%.pc: $(builddir)%.pc
	@$(call cmd,install_data)

###############################################################################
# Commands for download
##
DL?=$(srcdir)/.dl

quiet_cmd_download=DOWNLOAD $*
define cmd_download
	wget -q -O $(OUTPUT) $(URL)
endef

quiet_cmd_gitclone=CLONE $*
define cmd_gitclone
	$(if $(wildcard $(OUTPUT)),,git clone --depth 1 $(URL) $(VERSION) $(OUTPUT))
endef

$(DL)/:
	mkdir -p $@

$(download-target): %: $(DL)/
	$(eval URL=$($*_SITE)/$($*_SOURCE))
	$(eval DL=$(realpath $(DL)))
	$(eval OUTPUT=$(DL)/$($*_SOURCE))
	@$(call cmd,download)
	@$(if $(findstring .zip, $($*_SOURCE)),unzip -o -d $(cwdir)/$* $(OUTPUT))
	@$(if $(findstring .tar.gz, $($*_SOURCE)),tar -xzf $(OUTPUT) -C $(cwdir)/$*)

$(gitclone-target): %:
	$(eval URL=$($*_SITE))
	$(eval OUTPUT=$(cwdir)/$*)
	$(eval VERSION=$(if $($*_VERSION),-b $($*_VERSION)))
	@$(call cmd,gitclone)

###############################################################################
# Project configuration
#
NO$(CONFIG):
	$(warning "Configure the project first")
	$(warning "  make <...>_defconfig")
	$(warning "  make defconfig")
	$(warning "  make config")
	$(error  )

quiet_cmd_generate_config_h=CONFIG $(notdir $@)
define cmd_generate_config_h
	echo '#ifndef __CONFIG_H__' > $@
	echo '#define __CONFIG_H__' >> $@
	$(if $(wildcard $(CONFIG)),echo '' >> $@; $(GREP) -v "^#" $(CONFIG) | $(AWK) -F= 't$$1 != t {if ($$2 != "n") print "#define "toupper($$1)" "$$2}' >> $@)
	echo '' >> $@
	$(if $(pkglibdir), sed -i -e "/\\<PKGLIBDIR\\>/d" $@; echo '#define PKGLIBDIR "'$(pkglibdir)'"' >> $@)
	$(if $(datadir), sed -i -e "/\\<DATADIR\\>/d" $@; echo '#define DATADIR "'$(datadir)'"' >> $@)
	$(if $(pkgdatadir), sed -i -e "/\\<PKG_DATADIR\\>/d" $@; echo '#define PKG_DATADIR "'$(pkgdatadir)'"' >> $@)
	$(if $(sysconfdir), sed -i -e "/\\<SYSCONFDIR\\>/d" $@; echo '#define SYSCONFDIR "'$(sysconfdir)'"' >> $@)
	$(if $(localsatedir), sed -i -e "/\\<LOCALSTATEDIR\\>/d" $@; echo '#define LOCALSTATEDIR "'$(localstatedir)'"' >> $@)
	echo '#endif' >> $@
endef

quiet_cmd_generate_version_h=VERSION $(notdir $@)
define cmd_generate_version_h
	echo '#ifndef __VERSION_H__' > $@
	echo '#define __VERSION_H__' >> $@
	echo '' >> $@
	$(if $(version), echo '#define VERSION '$(version)'' >> $@)
	$(if $(version), echo '#define VERSION_MAJOR '$(firstword $(subst ., ,$(version)))'' >> $@)
	$(if $(version), echo '#define VERSION_MINOR '$(word 2,$(subst ., ,$(version)))'' >> $@)
	$(if $(package), echo '#define PACKAGE '$(package)'' >> $@)
	$(if $(version), echo '#define PACKAGE_VERSION "'$(version)'"' >> $@)
	$(if $(package), echo '#define PACKAGE_NAME "'$(package)'"' >> $@)
	$(if $(package), echo '#define PACKAGE_TARNAME "'$(subst " ","_",$(package))'"' >> $@)
	$(if $(package), echo '#define PACKAGE_STRING "'$(package) $(version)'"' >> $@)
	echo '#endif' >> $@
endef

quiet_cmd_generate_pkgconfig=PKGCONFIG $*
define cmd_generate_pkgconfig
	printf '# generated by makemore\n' > $@
	printf 'prefix=$(prefix)\n' >> $@
	printf 'exec_prefix=$${prefix}\n' >> $@
	printf 'sysconfdir=$(sysconfdir:$(prefix)/%=$${prefix}/%)\n' >> $@
	printf 'libdir=$(libdir:$(prefix)/%=$${exec_prefix}/%)\n' >> $@
	printf 'pkglibdir=$(pkglibdir:$(prefix)/%=$${exec_prefix}/%)\n' >> $@
	printf 'includedir=$(includedir:$(prefix)/%=$${prefix}/%)\n' >> $@
	printf '\n' >> $@
	printf 'Name: $(package)\n' >> $@
	printf 'Version: $(version)\n' >> $@
	printf 'Description: $(package)\n' >> $@
	printf 'Cflags: -I$${includedir}\n' >> $@
	printf 'Libs: -L$${libdir}' >> $@
	cat $< >> $@
	echo "" >> $@
endef
quiet_cmd_oldconfig=OLDCONFIG
cmd_oldconfig=cat $(DEFCONFIG) | grep $(addprefix -e ,$(RESTCONFIGS)) >> $(CONFIG)

##
# config rules
##
$(CONFIGFILE):
	@$(call cmd,generate_config_h)

$(VERSIONFILE):
	@$(call cmd,generate_version_h)

.PHONY: $(lib-y) $(slib-y)
$(lib-pkgconfig-target): $(lib-y) $(slib-y)
	@touch $@
	@sed -i $(foreach lib, $(sort $^),-e 's/-l$(lib)//g') $@
	@printf '$(foreach lib,$(sort $^), -l$(lib))' >> $@
#	@sed -i $(foreach lib, $(sort $(lib-y) $(slib-y)),-e 's/-l$(lib)//g') $@
#	@printf '$(foreach lib,$(sort $(lib-y) $(slib-y)), -l$(lib))' >> $@

$(pkgconfig-target): $(builddir)%.pc:$(builddir).%.pc.in
	@$(call cmd,generate_pkgconfig)


.PHONY: menuconfig gconfig xconfig config oldconfig _oldconfig saveconfig defconfig FORCE
menuconfig gconfig xconfig config:
	$(EDITOR) $(CONFIG)

configfiles+=$(wildcard $(CONFIG))
configfiles+=$(wildcard $(CONFIGFILE))
configfiles+=$(wildcard $(VERSIONFILE))
configfiles+=$(wildcard $(TMPCONFIG))
configfiles+=$(wildcard $(PATHCACHE))
cleanconfig: FORCE
	@$(foreach file,$(configfiles), $(call cmd,clean,$(file)))

$(CONFIG).old: $(wildcard $(CONFIG))
	$(Q)$(if $<,mv $< $@)

# set the list of configuration variables
ifneq ($(wildcard $(DEFCONFIG)),)
SETCONFIGS=$(shell cat $(DEFCONFIG) | sed 's/\"/\\\"/g' | grep -v '^\#' | awk -F= 't$$1 != t {print $$1}'; )
UNSETCONFIGS=$(shell cat $(DEFCONFIG) | awk '/^. .* is not set/{print $$2}')
endif
CONFIGS:=$(SETCONFIGS) $(UNSETCONFIGS)

oldconfig: _info $(CONFIG) FORCE
	@$(call cmd,clean,$(PATHCACHE))
	$(Q)$(MAKE) _oldconfig

_oldconfig: RESTCONFIGS:=$(foreach config,$(CONFIGS),$(if $($(config)),,$(config)))
_oldconfig: $(DEFCONFIG) $(PATHCACHE)
	@$(if $(strip $(RESTCONFIGS)),$(call cmd,oldconfig))

# manage the defconfig files
# 1) use the default defconfig file
# 2) relaunch with _defconfig target
defconfig: TMPCONFIG:=$(builddir).tmpconfig
defconfig: _info cleanconfig FORCE
	$(Q)$(MAKE) TMPCONFIG=$(TMPCONFIG) _defconfig

# manage the defconfig files
# 1) set the DEFCONFIG variable
# 2) relaunch with _defconfig target
%_defconfig: TMPCONFIG=$(builddir).tmpconfig
%_defconfig: $(srcdir)configs/%_defconfig _info cleanconfig
	$(Q)$(MAKE) DEFCONFIG=$< TMPCONFIG=$(TMPCONFIG) _defconfig

quiet_cmd__saveconfig=DEFCONFIG $(notdir $(DEFCONFIG))
cmd__saveconfig=printf "$(strip $(foreach config,$(CONFIGS),$(config)=$($(config))\n))" > $(CONFIG)

$(PATHCACHE):
	@printf "$(strip $(foreach config,$(PATHES),$(config)=$($(config))\n))" > $@

ifneq ($(TMPCONFIG),)
# create a temporary defconfig file in the format of the config file
$(TMPCONFIG): $(DEFCONFIG)
	@cat $< | sed 's/\"/\\\"/g' | grep -v '^\#' > $@
	@cat $< | awk '/^. .* is not set/{print $$2"=n"}' >> $@

# load the temporary defconfig file
# if a value is already set on the command line of 'make', the value stay:
-include $(TMPCONFIG)

# 1) load the defconfig file to replace the .config file
# 2) build the pathcache
# recipes) create the .config file with the variables from DEFCONFIG
_defconfig: $(TMPCONFIG) $(PATHCACHE) FORCE
	$(Q)$(call cmd,_saveconfig)
	$(Q)$(RM) $(TMPCONFIG)
endif # ifneq ($(TMPCONFIG),)
endif
