makemore:=$(notdir $(lastword $(MAKEFILE_LIST)))
ifeq ($(inside_makemore),)
inside_makemore:=yes
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
data-y:=
hostbin-y:=

srcdir?=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))
file?=$(notdir $(firstword $(MAKEFILE_LIST)))

VERSIONFILE=version

CROSS_COMPILE?=

# CONFIG could define LD CC or/and CFLAGS
# CONFIG must be included before "Commands for build and link"
CONFIGURE_STATUS:=configure.status
ifneq ($(wildcard $(obj)$(CONFIGURE_STATUS)),)
include $(obj)$(CONFIGURE_STATUS)
else ifneq ($(wildcard $(srcdir)$(CONFIGURE_STATUS)),)
include $(srcdir)$(CONFIGURE_STATUS)
endif

CONFIG?=config
ifneq ($(wildcard $(obj)$(CONFIG)),)
configfile:=$(obj)$(CONFIG)
else ifneq ($(wildcard $(srcdir)$(CONFIG)),)
configfile:=$(srcdir)$(CONFIG)
endif
ifneq ($(configfile),)
include $(configfile)
endif

#ifneq ($(findstring -arch,$(CFLAGS)),)
#ARCH=$(shell echo $(CFLAGS) 2>&1 | $(AWK) 'BEGIN {FS="[- ]"} {print $$2}')
#buildpath=$(join $(srcdir),$(ARCH))
#endif
ifneq ($(builddir),)
buildpath=$(if $(wildcard $(addprefix /.,$(builddir))),$(builddir:%/=%)/,$(join $(srcdir),$(builddir:%/=%)/))
else ifneq ($(CROSS_COMPILE),)
buildpath=$(join $(srcdir),$(CROSS_COMPILE:%-=%)/)
endif
ifneq ($(buildpath),)
obj=$(addprefix $(buildpath),$(cwdir))
else
obj=
endif
hostobj:=$(srcdir:%=%/)host/$(cwdir)

ifneq ($(file),)
include $(file)
endif

PATH:=$(value PATH):$(hostobj)
TMPDIR:=/tmp
TESTFILE:=makemore_test
##
# default Macros for installation
##
# not set variable if not into the build step
AWK?=awk
RM?=rm -f
INSTALL?=install
INSTALL_PROGRAM?=$(INSTALL) -D
INSTALL_DATA?=$(INSTALL) -m 644 -D
PKGCONFIG?=pkg-config
YACC?=bison
MOC?=moc$(QT:%=-%)
UIC?=uic$(QT:%=-%)

CC?=gcc
CXX?=g++
LD?=gcc
AR?=ar
RANLIB?=ranlib
HOSTCC?=$(CC)
HOSTCXX?=$(CXX)
HOSTLD?=$(LD)
HOSTAR?=$(AR)
HOSTRANLIB?=$(RANLIB)
HOSTCFLAGS?=$(CFLAGS)
HOSTLDFLAGS?=$(LDFLAGS)

ifneq ($(CROSS_COMPILE),)
CROSS_COMPILE:=$(CROSS_COMPILE:%-=%)-
ifeq ($(CC),cc)
CC=gcc
endif
endif

# if cc is a link on gcc, prefer to use directly gcc for ld
CCVERSION=$(shell $(TOOLCHAIN:%=%/)$(CROSS_COMPILE)$(CC) -v 2>&1)
ifneq ($(findstring GCC,$(CCVERSION)), )
	LD=gcc
	HOSTLD=$(LD)
	ldgcc=-Wl,$(1),$(2)
else ifneq ($(findstring gcc,$(CC)),)
	LD=gcc
	ldgcc=-Wl,$(1),$(2)
else
	ldgcc=$(1) $(2)
endif

ARCH?=$(shell LANG=C $(CC) -v 2>&1 | grep Target | $(AWK) 'BEGIN {FS="[- ]"} {print $$2}')
libsuffix=$(findstring 64,$(ARCH))

prefix?=/usr/local
prefix:=$(prefix:"%"=%)
bindir?=$(prefix)/bin
bindir:=$(bindir:"%"=%)
sbindir?=$(prefix)/sbin
sbindir:=$(sbindir:"%"=%)
libdir?=$(word 1,$(wildcard $(prefix)/lib$(libsuffix) $(prefix)/lib))
libdir:=$(if $(libdir), $(libdir),$(prefix)/lib)
libdir:=$(libdir:"%"=%)
sysconfdir?=$(prefix)/etc
sysconfdir:=$(sysconfdir:"%"=%)
includedir?=$(prefix)/include
includedir:=$(includedir:"%"=%)
datadir?=$(prefix)/share/$(package:"%"=%)
datadir:=$(datadir:"%"=%)
pkglibdir?=$(libdir)/$(package:"%"=%)
pkglibdir:=$(pkglibdir:"%"=%)

ifneq ($(sysroot:"%"=%),)
SYSROOT_CFLAGS+=--sysroot=$(sysroot:"%"=%)
SYSROOT_CFLAGS+=-isysroot $(sysroot:"%"=%)
SYSROOT_CFLAGS+=-I$(sysroot:"%"=%)$(includedir)
SYSROOT_LDFLAGS+=--sysroot=$(sysroot:"%"=%)
SYSROOT_LDFLAGS+=-L$(sysroot:"%"=%)$(libdir)
SYSROOT_LDFLAGS+=-L$(sysroot:"%"=%)$(pkglibdir)
endif

#CFLAGS+=$(foreach macro,$(DIRECTORIES_LIST),-D$(macro)=\"$($(macro))\")
ifneq ($(src),)
CFLAGS+=-I$(src)
endif
CFLAGS+=-I$(CURDIR) -I.
LIBRARY+=
ifneq ($(obj),)
LDFLAGS+=-L$(obj:%/=%)
else
LDFLAGS+=-L.
endif
LDFLAGS+=$(if $(strip $(libdir)),$(call ldgcc,-rpath,$(strip $(libdir))))
LDFLAGS+=$(if $(strip $(pkglibdir)),$(call ldgcc,-rpath,$(strip $(pkglibdir))))

#export package version prefix bindir sbindir libdir includedir datadir pkglibdir srcdir

##
# objects recipes generation
##
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y), $(eval $(t)_SOURCES+=$(patsubst %.hpp,%.moc.cpp,$($(t)_QTHEADERS) $($(t)_QTHEADERS-y))))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y), $(if $(findstring .cpp, $(notdir $($(t)_SOURCES))), $(eval $(t)_LIBRARY+=stdc++)))

$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y), $(eval $(t)-objs+=$(patsubst %.s,%.o,$(patsubst %.S,%.o,$(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$($(t)_SOURCES) $($(t)_SOURCES-y)))))))
target-objs:=$(foreach t, $(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y), $(if $($(t)-objs), $(addprefix $(obj),$($(t)-objs)), $(obj)$(t).o))

$(foreach t,$(hostbin-y), $(eval $(t)-objs:=$(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$($(t)_SOURCES) $($(t)_SOURCES-y)))))
$(foreach t,$(hostslib-y), $(eval $(t)-objs:=$(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$($(t)_SOURCES) $($(t)_SOURCES-y)))))
target-hostobjs:=$(foreach t, $(hostbin-y) $(hostslib-y), $(if $($(t)-objs), $(addprefix $(hostobj)/,$($(t)-objs)), $(hostobj)/$(t).o))

$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach s, $($(t)_SOURCES) $($(t)_SOURCES-y),$(eval $(t)_LIBS+=$($(s:%.c=%)_LIBS)) ))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach s, $($(t)_SOURCES) $($(t)_SOURCES-y),$(eval $(t)_LIBS+=$($(s:%.cpp=%)_LIBS)) ))

$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach s, $($(t)_SOURCES) $($(t)_SOURCES-y),$(eval $(t)_LIBRARY+=$($(s:%.c=%)_LIBRARY)) ))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach s, $($(t)_SOURCES) $($(t)_SOURCES-y),$(eval $(t)_LIBRARY+=$($(s:%.cpp=%)_LIBRARY)) ))

$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y) $(hostbin-y),$(eval $(t)_CFLAGS+=$($(t)_CFLAGS-y)))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y) $(hostbin-y),$(eval $(t)_LDFLAGS+=$($(t)_LDFLAGS-y)))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y) $(hostbin-y),$(eval $(t)_LIBS+=$($(t)_LIBS-y)))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y) $(hostbin-y),$(eval $(t)_LIBRARY+=$($(t)_LIBRARY-y)))

# LIBRARY contains libraries name to check
# The name may terminate with {<version>} informations like LIBRARY+=usb{1.0}
# Here the commands remove the informations and store the name into LIBS
# After LIBS contains all libraries name to link
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach l, $($(t)_LIBRARY),$(eval $(t)_LIBS+=$(firstword $(subst {, ,$(subst },,$(l)))) ) ))
$(foreach l, $(LIBRARY),$(eval LIBS+=$(firstword $(subst {, ,$(subst },,$(l)))) ) )

$(foreach l, $(LIBS),$(eval CFLAGS+=$(shell $(PKGCONFIG) --cflags lib$(l) 2> /dev/null) ) )
$(foreach l, $(LIBS),$(eval LDFLAGS+=$(shell $(PKGCONFIG) --libs-only-L lib$(l) 2> /dev/null) ) )
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach l, $($(t)_LIBS),$(eval $(t)_CFLAGS+=$(shell $(PKGCONFIG) --cflags lib$(l) 2> /dev/null))))
$(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$(foreach l, $($(t)_LIBS),$(eval $(t)_LDFLAGS+=$(shell $(PKGCONFIG) --libs-only-L lib$(l) 2> /dev/null) ) ))

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
ifeq (STATIC,y)
lib-static-target:=$(addprefix $(obj),$(addsuffix $(slib-ext:%=.%),$(addprefix lib,$(slib-y) $(lib-y))))
else
lib-static-target:=$(addprefix $(obj),$(addsuffix $(slib-ext:%=.%),$(addprefix lib,$(slib-y))))
lib-dynamic-target:=$(addprefix $(obj),$(addsuffix $(dlib-ext:%=.%),$(addprefix lib,$(lib-y))))
endif
modules-target:=$(addprefix $(obj),$(addsuffix $(dlib-ext:%=.%),$(modules-y)))
bin-target:=$(addprefix $(obj),$(addsuffix $(bin-ext:%=.%),$(bin-y) $(sbin-y)))
hostslib-target:=$(addprefix $(hostobj),$(addsuffix $(slib-ext:%=.%),$(addprefix lib,$(hostslib-y))))
hostbin-target:=$(addprefix $(hostobj),$(addsuffix $(bin-ext:%=.%),$(hostbin-y)))

#create subproject
$(foreach t,$(subdir-y),$(eval $(t)_CONFIGURE+=$($(t)_CONFIGURE-y)))
$(foreach t,$(subdir-y),$(if $($(t)_CONFIGURE), $(eval subdir-project+=$(t))))
subdir-y:=$(filter-out $(subdir-project),$(subdir-y))

#subdir-y may contain directory's names or file's names.
#for each directory, the script may check Makefile and *.mk files
#list of directories
subdir-dir:=$(wildcard $(foreach dir,$(subdir-y),$(join $(dir)/,$(notdir $(join $(dir),/.)))))

#target each Makefile in directories
subdir-target:=$(wildcard $(addsuffix /Makefile,$(subdir-dir:%/.=%)))
#target all *.mk file in directories
#subdir-target+=$(wildcard $(filter-out */scripts.mk,$(addsuffix /*$(makefile-ext:%=.%),$(subdir-dir:%/.=%))))
#remove all directories from the list
subdir-files:=$(subdir-y)
$(foreach dir, $(subdir-dir:%/.=%),$(eval subdir-files:=$(filter-out $(dir),$(subdir-files))))
#target the files from the list
subdir-target+=$(wildcard $(subdir-files))


objdir:=$(sort $(dir $(target-objs)))

targets:=
targets+=$(lib-dynamic-target)
targets+=$(modules-target)
targets+=$(lib-static-target)
targets+=$(bin-target)

ifneq ($(CROSS_COMPILE),)
DESTDIR:=$(sysroot:"%"=%)
endif
##
# install recipes generation
##
sysconf-install:=$(addprefix $(DESTDIR:%=%/)$(sysconfdir)/,$(sysconf-y))
data-install:=$(addprefix $(DESTDIR:%=%/)$(datadir)/,$(data-y))
include-install:=$(addprefix $(DESTDIR:%=%/)$(includedir)/,$(include-y))
lib-static-install:=$(addprefix $(DESTDIR:%=%/)$(libdir)/,$(addsuffix $(slib-ext:%=.%),$(addprefix lib,$(slib-y))))
lib-dynamic-install:=$(addprefix $(DESTDIR:%=%/)$(libdir)/,$(addsuffix $(dlib-ext:%=.%),$(addprefix lib,$(lib-y))))
modules-install:=$(addprefix $(DESTDIR:%=%/)$(pkglibdir)/,$(addsuffix $(dlib-ext:%=.%),$(modules-y)))
bin-install:=$(addprefix $(DESTDIR:%=%/)$(bindir)/,$(addsuffix $(bin-ext:%=.%),$(bin-y)))
sbin-install:=$(addprefix $(DESTDIR:%=%/)$(sbindir)/,$(addsuffix $(bin-ext:%=.%),$(sbin-y)))

DEVINSTALL?=y
install:=
dev-install-y:=
ifneq ($(CROSS_COMPILE),)
ifneq ($(DESTDIR),)
install+=$(bin-install)
install+=$(sbin-install)
dev-install-$(DEVINSTALL)+=$(lib-static-install)
install+=$(lib-dynamic-install)
install+=$(modules-install)
install+=$(data-install)
install+=$(sysconf-install)
dev-install-$(DEVINSTALL)+=$(include-install)
endif
else
install+=$(bin-install)
install+=$(sbin-install)
dev-install-$(DEVINSTALL)+=$(lib-static-install)
install+=$(lib-dynamic-install)
install+=$(modules-install)
install+=$(data-install)
install+=$(sysconf-install)
dev-install-$(DEVINSTALL)+=$(include-install)
endif

##
# main entries
##
action:=_build
build:=$(action) -f $(srcdir)$(makemore) file
.DEFAULT_GOAL:=_entry
.PHONY:_entry _build _install _clean _distclean _check
_entry: default_action

_info:
	@:

_hostbuild: $(if $(strip $(hostslib-y) $(hostbin-y)), $(hostobj) $(hostslib-target) $(hostbin-target))
_configbuild: $(obj) $(if $(wildcard $(configfile)),$(join $(obj),$(CONFIG:%=%.h)))
_versionbuild: $(if $(package) $(version), $(join $(obj),$(VERSIONFILE:%=%.h)))

_build: _info $(objdir) $(subdir-project) $(subdir-target) _hostbuild $(targets)
	@:

_install: action:=_install
_install: build:=$(action) -f $(srcdir)$(makemore) file
_install: _info $(install) $(dev-install-y) $(subdir-target)
	@:

_clean: action:=_clean
_clean: build:=$(action) -f $(srcdir)$(makemore) file
_clean: $(subdir-target) _clean_objs
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
_check: $(subdir-target) $(LIBRARY) $(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$($(t)_LIBRARY))

clean: action:=_clean
clean: build:=$(action) -f $(srcdir)$(makemore) file
clean: $(.DEFAULT_GOAL)

distclean: action:=_distclean
distclean: build:=$(action) -f $(srcdir)$(makemore) file
distclean: $(.DEFAULT_GOAL)
distclean:
	$(Q)$(call cmd,clean_dir,$(wildcard $(buildpath:%=%/)host))
	$(Q)$(call cmd,clean,$(wildcard $(configfile)))
	$(Q)$(call cmd,clean,$(wildcard $(join $(obj),$(CONFIG:%=%.h))))
	$(Q)$(call cmd,clean,$(wildcard $(join $(obj),$(VERSIONFILE:%=%.h))))

install: action:=_install
install: build:=$(action) -f $(srcdir)$(makemore) file
install: $(.DEFAULT_GOAL)

check: action:=_check
check: build:=$(action) -s -f $(srcdir)$(makemore) file
check: $(.DEFAULT_GOAL)

default_action: _info _configbuild _versionbuild
	$(Q)$(MAKE) $(build)=$(file)
	@:

pc: $(obj)$(package:%=%.pc)

all: default_action

$(obj)$(CONFIG:%=%.h): $(configfile)
	@$(call cmd,config)

$(obj)$(VERSIONFILE:%=%.h):
	@$(call cmd,versionfile)

quiet_cmd_versionfile=VERSION $*
define cmd_versionfile
	echo '#ifndef __VERSION_H__' >> $@
	echo '#define __VERSION_H__' >> $@
	$(if $(version), echo '#define VERSION "'$(version)'"' >> $@)
	$(if $(package), echo '#define PACKAGE "'$(package)'"' >> $@)
	$(if $(sysconfdir), echo '#define SYSCONFDIR "'$(sysconfdir)'"' >> $@)
	echo '#endif' >> $@
endef

##
# Commands for clean
##
quiet_cmd_clean=$(if $(2),CLEAN  $(notdir $(2)))
 cmd_clean=$(if $(2),$(RM) $(2))
quiet_cmd_clean_dir=$(if $(2),CLEAN $(notdir $(2)))
 cmd_clean_dir=$(if $(2),$(RM) -r $(2))
##
# Commands for build and link
##
RPATH=$(wildcard $(addsuffix /.,$(wildcard $(CURDIR:%/=%)/* $(obj)*)))
quiet_cmd_yacc_y=YACC $*
 cmd_yacc_y=$(YACC) -o $@ $<
quiet_cmd_as_o_s=AS $*
 cmd_as_o_s=$(TOOLCHAIN:%=%/)$(CROSS_COMPILE)$(AS) $(SYSROOT_CFLAGS) $(ASFLAGS) $($*_CFLAGS) -c -o $@ $<
quiet_cmd_cc_o_c=CC $*
 cmd_cc_o_c=$(TOOLCHAIN:%=%/)$(CROSS_COMPILE)$(CC) $(SYSROOT_CFLAGS) $(CFLAGS) $($*_CFLAGS) -c -o $@ $<
quiet_cmd_cc_o_cpp=CXX $*
 cmd_cc_o_cpp=$(TOOLCHAIN:%=%/)$(CROSS_COMPILE)$(CXX) $(SYSROOT_CFLAGS) $(CFLAGS) $($*_CFLAGS) -c -o $@ $<
quiet_cmd_moc_hpp=QTMOC $*
 cmd_moc_hpp=$(MOC) $(INCLUDES) $($*_MOCFLAGS) $($*_MOCFLAGS-y) -o $@ $<
quiet_cmd_uic_hpp=QTUIC $*
 cmd_uic_hpp=$(UIC) $< > $@
quiet_cmd_ld_bin=LD $*
 cmd_ld_bin=$(TOOLCHAIN:%=%/)$(CROSS_COMPILE)$(LD) $(SYSROOT_LDFLAGS) -o $@ $^ $(LDFLAGS) $($*_LDFLAGS) -L. $(LIBS:%=-l%) $($*_LIBS:%=-l%)
quiet_cmd_ld_slib=LD $*
 cmd_ld_slib=$(RM) $@ && \
	$(TOOLCHAIN:%=%/)$(CROSS_COMPILE)$(AR) -cvq $@ $^ > /dev/null && \
	$(TOOLCHAIN:%=%/)$(CROSS_COMPILE)$(RANLIB) $@
quiet_cmd_ld_dlib=LD $*
 cmd_ld_dlib=$(TOOLCHAIN:%=%/)$(CROSS_COMPILE)$(LD) $(SYSROOT_LDFLAGS) $(LDFLAGS) $($*_LDFLAGS) -shared $(call ldgcc,-soname,$(strip $(notdir $@))) -o $@ $^ $(addprefix -L,$(RPATH)) $(LIBS:%=-l%) $($*_LIBS:%=-l%)

quiet_cmd_hostcc_o_c=HOSTCC $*
 cmd_hostcc_o_c=$(HOSTCC) $(HOSTCFLAGS) $($*_CFLAGS) -c -o $@ $<
quiet_hostcmd_cc_o_cpp=HOSTCXX $*
 cmd_hostcc_o_cpp=$(HOSTCXX) $(HOSTCFLAGS) $($*_CFLAGS) -c -o $@ $<
quiet_cmd_hostld_bin=HOSTLD $*
 cmd_hostld_bin=$(HOSTLD) -o $@ $^ $(HOSTLDFLAGS) $($*_LDFLAGS) -L. $(LIBS:%=-l%) $($*_LIBS:%=-l%)
quiet_cmd_hostld_slib=HOSTLD $*
 cmd_hostld_slib=$(RM) $@ && \
	$(HOSTAR) -cvq $@ $^ > /dev/null && \
	$(HOSTRANLIB) $@

quiet_cmd_check_lib=CHECK $*
define cmd_check_lib
	$(RM) $(TMPDIR)/$(TESTFILE:%=%.c) $(TMPDIR)/$(TESTFILE)
	echo "int main(){}" > $(TMPDIR)/$(TESTFILE:%=%.c)
	$(CC) -c -o $(TMPDIR)/$(TESTFILE:%=%.o) $(TMPDIR)/$(TESTFILE:%=%.c) $(CFLAGS) > /dev/null 2>&1
	$(LD) -o $(TMPDIR)/$(TESTFILE) $(TMPDIR)/$(TESTFILE:%=%.o) $(LDFLAGS) $(addprefix -l, $2) > /dev/null 2>&1
endef

checkoption:=--exact-version
prepare_check=$(if $(filter %-, $2),$(eval checkoption:=--atleast-version),$(if $(filter -%, $2),$(eval checkoption:=--max-version)))
cmd_check2_lib=$(if $(findstring $(3:%-=%), $3),$(if $(findstring $(3:-%=%), $3),,$(eval checkoption:=--atleast-version),$(eval checkoption:=--max-version))) \
	$(PKGCONFIG) --print-errors $(checkoption) $(subst -,,$3) lib$2

##
# build rules
##
.SECONDEXPANSION:
$(hostobj) $(objdir) $(buildpath):
	$(Q)mkdir -p $@

$(obj)%.tab.c:%.y
	@$(call cmd,yacc_y)

$(obj)%.o:%.s
	@$(call cmd,as_o_s)

$(obj)%.o:%.c
	@$(call cmd,cc_o_c)

$(obj)%.o:%.cpp
	@$(call cmd,cc_o_cpp)

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

.PHONY: $(subdir-project) $(subdir-target) FORCE
$(subdir-project): %: FORCE
	$(Q)cd $* && $($*_CONFIGURE)
	$(Q)$(MAKE) -C $* 
	$(Q)$(MAKE) -C $* install

$(subdir-target): %: FORCE
	$(Q)$(MAKE) -C $(dir $*) cwdir=$(cwdir)$(dir $*) builddir=$(builddir) $(build)=$(notdir $*)

$(LIBRARY) $(sort $(foreach t,$(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$($(t)_LIBRARY))): %:
	@$(RM) $(TMPDIR)/$(TESTFILE:%=%.c) $(TMPDIR)/$(TESTFILE)
	@echo "int main(){}" > $(TMPDIR)/$(TESTFILE:%=%.c)
	@$(call cmd,check_lib,$(firstword $(subst {, ,$(subst },,$@))))
	@$(call prepare_check,$(lastword $(subst {, ,$(subst },,$@))))
	@$(if $(findstring $(words $(subst {, ,$(subst },,$@))),2),$(call cmd,check2_lib,$(firstword $(subst {, ,$(subst },,$@))),$(lastword $(subst {, ,$(subst },,$@)))))

##
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

##
# install rules
##
$(include-install): $(DESTDIR:%=%/)$(includedir)/%: %
	@$(call cmd,install_data)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(DESTDIR:%=%/)$(includedir) && rm -f $(a) && ln -s $(includedir)$* $(a)))
$(sysconf-install): $(DESTDIR:%=%/)$(sysconfdir)/%: %
	@$(call cmd,install_data)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(DESTDIR:%=%/)$(sysconfdir) && rm -f $(a) && ln -s $(sysconfdir)$* $(a)))
$(data-install): $(DESTDIR:%=%/)$(datadir)/%: %
	@$(call cmd,install_data)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(DESTDIR:%=%/)$(datadir) && rm -f $(a) && ln -s $(datadir)$* $(a)))
$(lib-static-install): $(DESTDIR:%=%/)$(libdir)/lib%$(slib-ext:%=.%): $(obj)lib%$(slib-ext:%=.%)
	@$(call cmd,install_bin)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(DESTDIR:%=%/)$(libdir) && rm -f $(a) && ln -s $(libdir)$*$(slib-ext:%=.%) $(a)))
$(lib-dynamic-install): $(DESTDIR:%=%/)$(libdir)/lib%$(dlib-ext:%=.%): $(obj)lib%$(dlib-ext:%=.%)
	@$(call cmd,install_bin)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(DESTDIR:%=%/)$(libdir) && rm -f $(a) && ln -s $(libdir)$*$(dlib-ext:%=.%) $(a)))
$(modules-install): $(DESTDIR:%=%/)$(pkglibdir)/%$(dlib-ext:%=.%): $(obj)%$(dlib-ext:%=.%)
	@$(call cmd,install_bin)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(DESTDIR:%=%/)$(pkglibdir) && rm -f $(a) && ln -s $(pkglibdir)$*$(dlib-ext:%=.%) $(a)))
$(bin-install): $(DESTDIR:%=%/)$(bindir)/%$(bin-ext:%=.%): $(obj)%$(bin-ext:%=.%)
	@$(call cmd,install_bin)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(DESTDIR:%=%/)$(bindir) && rm -f $(a) && ln -s $(bindir)$*$(bin-ext:%=.%) $(a)))
$(sbin-install): $(DESTDIR:%=%/)$(sbindir)/%$(bin-ext:%=.%): $(obj)%$(bin-ext:%=.%)
	@$(call cmd,install_bin)
	@$(foreach a,$($*_ALIAS) $($*_ALIAS-y), $(shell cd $(DESTDIR:%=%/)$(sbindir) && rm -f $(a) && ln -s $(sbindir)$*$(bin-ext:%=.%) $(a)))

##
# commands for configuration
##
empty=
space=$(empty) $(empty)
quote="
sharp=\#
quiet_cmd_config=CONFIG $*
 cmd_config=$(AWK) -F= '$$1 != $(quote)$(quote) {print $(quote)$(sharp)define$(space)$(quote)$$1$(quote)$(space)$(quote)$$2}' $< > $@

#if inside makemore
endif
