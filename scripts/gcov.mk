GCOV?=gcov --relative-only
LCOV?=lcov
GENHTML?=genhtml
TARGETGCOV:=$(TARGETPREFIX)$(GCOV)

ifeq ($(G),1)
INTERN_CFLAGS+=--coverage -fprofile-arcs -ftest-coverage
INTERN_LDFLAGS+=--coverage -fprofile-arcs -ftest-coverage
INTERN_LIBS+=gcov
O:=0
endif

reportpath?=$(builddir)
gcov-target:=$(patsubst %.o,%.c.gcov,$(sort $(foreach t, $(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$($(t)_GENERATED) $(addprefix $(reportpath)$(cwdir),$($(t)-objs)))))
gcda-target:=$(patsubst %.o,%.gcda,$(sort $(foreach t, $(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$($(t)_GENERATED) $(addprefix $(reportpath)$(cwdir),$($(t)-objs)))))
gcno-target:=$(patsubst %.o,%.gcno,$(sort $(foreach t, $(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$($(t)_GENERATED) $(addprefix $(reportpath)$(cwdir),$($(t)-objs)))))
clean-target+=$(gcov-target) $(gcda-target) $(gcno-target)

_gcov: action:=_gcov
_gcov: build:=$(action) -f $(makemore) file
_gcov: _info $(subdir-target) $(gcov-target)
	@:

gcov: action:=_gcov
gcov: build:=$(action) -f $(makemore) file
gcov: default_action ;

gcovhtml: $(reportpath)index.html

quiet_cmd_cc_gcov_c=GCOV $*
 cmd_cc_gcov_c=$(TARGETGCOV) $(GCOV_OPTIONS) -p $(notdir $<) -t > $@;
quiet_cmd_lcov=LCOV
 cmd_lcov=$(LCOV) --directory $(builddir) --capture --output-file $@
quiet_cmd_genhtml=GENHTML $@
 cmd_genhtml=$(GENHTML) $< --output-directory $@

$(reportpath)$(cwdir)%.c.gcov: GCOV_OPTIONS+=-o $(dir $@) -s $(dir $<)
$(reportpath)$(cwdir)%.c.gcov:%.c $(file)
	@$(call cmd,cc_gcov_c)

$(reportpath)$(cwdir)%.c.gcov: GCOV_OPTIONS+=-o $(dir $@) -s $(dir $<)
$(reportpath)$(cwdir)%.c.gcov:%.cpp $(file)
	@$(call cmd,cc_gcov_c)

# for generated files
$(reportpath)$(cwdir)%.c.gcov: GCOV_OPTIONS+=-o $(dir $@) -s $(dir $<)
$(reportpath)$(cwdir)%.c.gcov:$(obj)%.c $(file)
	@$(call cmd,cc_gcov_c)

$(reportpath)$(cwdir)%.c.gcov: GCOV_OPTIONS+=-o $(dir $@) -s $(dir $<)
$(reportpath)$(cwdir)%.c.gcov:$(obj)%.cpp $(file)
	@$(call cmd,cc_gcov_c)

$(reportpath)gcov.info: $(gcov-target)
	@$(call cmd,lcov)

$(reportpath)index.html: $(reportpath)gcov.info
	@$(call cmd,genhtml)

_help_options_gcov:
	@echo " make gcov :"
	@echo "  options:"
	@echo "    GCOV_OPTIONS=<string>"
	@echo ""
	@echo " make gcovhtml :"
	@echo ""

_help_entries_gcov:
	@

