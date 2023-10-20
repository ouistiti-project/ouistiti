bin-y+=thrift
thrift_SOURCES+=thrift.cpp
thrift_GENERATED+=gen-cpp/Calculator.cpp
thrift_GENERATED+=gen-cpp/tutorial_constants.cpp
thrift_GENERATED+=gen-cpp/tutorial_types.cpp
thrift_GENERATED+=gen-cpp/SharedService.cpp
thrift_GENERATED-$(THRIFT_OLD)+=gen-cpp/shared_constants.cpp
thrift_GENERATED+=gen-cpp/shared_types.cpp
thrift_LIBRARY+=thrift{0.13}
thrift_CXXFLAGS+=-I$(objdir)gen-cpp/
thrift_LIBS+=pthread

$(objdir)gen-cpp/:
	@mkdir -p $@

$(objdir)gen-cpp/Calculator.cpp: tutorial.thrift $(objdir)gen-cpp/shared_types.h $(objdir)gen-js/Calculator.js $(objdir)gen-js/SharedService.js $(objdir)gen-cpp/
	thrift -out $(@D) -gen cpp:templates $<

$(objdir)gen-cpp/tutorial_constants.cpp: tutorial.thrift $(objdir)gen-cpp/
	thrift -out $(@D) -gen cpp:templates $<

$(objdir)gen-cpp/tutorial_types.cpp: tutorial.thrift $(objdir)gen-cpp/
	thrift -out $(@D) -gen cpp:templates $<

$(objdir)gen-cpp/SharedService.cpp: shared.thrift $(objdir)gen-cpp/
	thrift -out $(@D) -gen cpp:templates $<

$(objdir)gen-cpp/shared_constants.cpp: shared.thrift $(objdir)gen-cpp/
	thrift -out $(@D) -gen cpp:templates $<

$(objdir)gen-cpp/shared_types.cpp: shared.thrift $(objdir)gen-cpp/
	thrift -out $(@D) -gen cpp:templates $<

$(objdir)gen-cpp/shared_types.h: shared.thrift $(objdir)gen-cpp/
	thrift -out $(@D) -gen cpp:templates $<

HTDOCS=htdocs/websocket/
data-y+=$(HTDOCS)thrift.html
data-y+=$(HTDOCS)gen-js/Calculator.js
data-y+=$(HTDOCS)gen-js/SharedService.js
$(HTDOCS)gen-js/Calculator.js_GENERATED+=$(objdir)$(HTDOCS)gen-js/Calculator.js
$(HTDOCS)gen-js/SharedService.js_GENERATED+=$(objdir)$(HTDOCS)gen-js/SharedService.js

$(objdir)$(HTDOCS)gen-js/:
	@mkdir -p $@

$(objdir)$(HTDOCS)gen-js/Calculator.js: tutorial.thrift $(objdir)$(HTDOCS)gen-js/
	thrift -out $(@D) -gen js: $<

$(objdir)$(HTDOCS)gen-js/SharedService.js: shared.thrift $(objdir)$(HTDOCS)gen-js/
	thrift -out $(@D) -gen js: $<
