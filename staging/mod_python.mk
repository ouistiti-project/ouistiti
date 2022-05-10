modules-$(MODULES)+=mod_python
slib-$(STATIC)+=mod_python
mod_python_SOURCES+=mod_python.c
mod_python_SOURCES+=../src/cgi_env.c
mod_python_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_python_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_python_LIBS+=$(LIBHTTPSERVER_NAME)
mod_python_LIBRARY+=libconfig
PYTHON3_LIBS=$(shell python3-config --embed --libs)
mod_python_LIBS+=$(patsubst -l%,%,$(PYTHON3_LIBS))
mod_python_LDFLAGS+=$(shell python3-config --embed --ldflags)
mod_python_CFLAGS+=$(shell python3-config --embed --cflags)
mod_python_CFLAGS+=-I../src
mod_python_LIBS+=ouiutils

mod_python_CFLAGS-$(DEBUG)+=-g -DDEBUG
