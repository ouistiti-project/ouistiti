bin-y+=thrift
thrift_SOURCES+=thrift.cpp
thrift_GENERATED+=gen-cpp/Calculator.cpp
thrift_GENERATED+=gen-cpp/tutorial_constants.cpp
thrift_GENERATED+=gen-cpp/tutorial_types.cpp
thrift_GENERATED+=gen-cpp/SharedService.cpp
thrift_GENERATED+=gen-cpp/shared_constants.cpp
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

data-y+=thrif.html
thrift.html_GENERATED+=$(objdir)gen-js/Calculator.js

$(objdir)gen-js/:
	@mkdir -p $@

$(objdir)gen-js/Calculator.js: tutorial.thrift $(objdir)gen-js/
	thrift -out $(@D) -gen js: $<

$(objdir)gen-js/SharedService.js: shared.thrift $(objdir)gen-js/
	thrift -out $(@D) -gen js: $<
