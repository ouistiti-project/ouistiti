/*****************************************************************************
 * mod_python.c: callbacks and management of connection
 * this file is part of https://github.com/ouistiti-project/ouistiti
 *
 * follow RFC3875 : https://tools.ietf.org/html/rfc3875
 *****************************************************************************
 * Copyright (C) 2016-2017
 *
 * Authors: Marc Chalain <marc.chalain@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *****************************************************************************/

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <libgen.h>
#include <netinet/in.h>
#include <sched.h>

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include <Python.h>

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/log.h"
#include "mod_cgi.h"

#define python_dbg(...)

static const char str_python[] = "python";

typedef struct mod_cgi_config_s mod_python_config_t;
typedef struct _mod_python_s _mod_python_t;
typedef struct mod_python_ctx_s mod_python_ctx_t;

static int _python_connector(void *arg, http_message_t *request, http_message_t *response);

struct mod_python_ctx_s
{
	_mod_python_t *mod;
	http_client_t *ctl;

	PyObject *pyfunc;
	PyObject *pyenv;
	PyObject *pycontent;
	PyObject *pymodule;

	enum
	{
		STATE_SETUP,
		STATE_START,
		STATE_INFINISH,
		STATE_HEADERCOMPLETE,
		STATE_CONTENTCOMPLETE,
		STATE_OUTFINISH,
		STATE_END,
		STATE_MASK = 0x00FF,
		STATE_SHUTDOWN = 0x0100,
	} state;
};

typedef struct _mod_python_script_s _mod_python_script_t;
struct _mod_python_script_s
{
	string_t path;
	PyObject *pymodule;
	_mod_python_script_t *next;
};
struct _mod_python_s
{
	http_server_t *server;
	mod_python_config_t *config;
	int rootfd;
	_mod_python_script_t *scripts;
};

#ifdef FILE_CONFIG
static int _python_configscript(config_setting_t *setting, mod_python_config_t *python)
{
	const char *data = config_setting_get_string(setting);
	if (data == NULL)
		return EREJECT;
	mod_cgi_config_script_t *script = calloc(1, sizeof(*script));
	script->path.data = data;
	script->path.length = strlen(script->path.data);
	script->next = python->scripts;
	python->scripts = script;
	return ESUCCESS;
}

static void *python_config(config_setting_t *iterator, server_t *server)
{
	mod_python_config_t *python = NULL;
#if LIBCONFIG_VER_MINOR < 5
	config_setting_t *configpython = config_setting_get_member(iterator, "python");
#else
	config_setting_t *configpython = config_setting_lookup(iterator, "python");
#endif
	if (configpython)
	{
		python = calloc(1, sizeof(*python));
		config_setting_lookup_string(configpython, "docroot", (const char **)&python->docroot);
		config_setting_lookup_string(configpython, "allow", (const char **)&python->allow);
		config_setting_lookup_string(configpython, "deny", (const char **)&python->deny);
		config_setting_t *scripts = config_setting_lookup(configpython, "scripts");
		if (scripts && config_setting_is_scalar(scripts))
		{
			_python_configscript(scripts, python);
		}
		else if (scripts && config_setting_is_aggregate(scripts))
		{
			for (int i = 0; i < config_setting_length(scripts); i++)
			{
				config_setting_t *script = config_setting_get_elem(scripts, i);
				_python_configscript(script, python);
			}
		}
		python->nbenvs = 0;
		python->options |= CGI_OPTION_TLS;
		python->chunksize = HTTPMESSAGE_CHUNKSIZE;
		config_setting_lookup_int(iterator, "chunksize", &python->chunksize);
#if LIBCONFIG_VER_MINOR < 5
		config_setting_t *pythonenv = config_setting_get_member(configpython, "env");
#else
		config_setting_t *pythonenv = config_setting_lookup(configpython, "env");
#endif
		if (pythonenv)
		{
			int count = config_setting_length(pythonenv);
			int i;
			python->env = calloc(sizeof(char *), count);
			for (i = 0; i < count; i++)
			{
				config_setting_t *iterator = config_setting_get_elem(pythonenv, i);
				python->env[i] = config_setting_get_string(iterator);
			}
			python->nbenvs = count;
		}
	}
	return python;
}
#else
static const mod_python_config_t g_python_config =
{
	.docroot = "/srv/www""/python",
	.deny = "*",
	.allow = "*.py*",
};

static void *python_config(void *iterator, server_t *server)
{
	return (void *)&g_python_config;
}
#endif

static PyObject *_mod_python_modulize(const char *uri, size_t urilen)
{
	PyObject *script_name = PyUnicode_DecodeFSDefaultAndSize(uri, urilen);
	//PyObject *pymodule = PyImport_Import(script_name);
	PyObject *pymodule = PyImport_ImportModuleLevelObject(script_name, NULL, NULL, NULL, 0);
	Py_DECREF(script_name);
	return pymodule;
}

static void *mod_python_create(http_server_t *server, mod_python_config_t *modconfig)
{
	_mod_python_t *mod;

	if (!modconfig)
		return NULL;

	if (access(modconfig->docroot, R_OK) == -1)
	{
		err("python: %s access denied", modconfig->docroot);
		return NULL;
	}
	int rootfd = open(modconfig->docroot, O_PATH | O_DIRECTORY);
	struct stat rootstat;
	if (fstat(rootfd, &rootstat) == -1 || !S_ISDIR(rootstat.st_mode))
	{
		err("python: %s not a directory", modconfig->docroot);
		return NULL;
	}
	PyObject *sys = PyImport_ImportModule("sys");
	PyObject *path = PyObject_GetAttrString(sys, "path");
	PyObject *pwd = PyUnicode_FromString(modconfig->docroot);
	PyList_Append(path, pwd);
	Py_DECREF(sys);
	Py_DECREF(path);
	Py_DECREF(pwd);

	mod = calloc(1, sizeof(*mod));
	mod->config = modconfig;
	mod->server = server;
	mod->rootfd = rootfd;
	if (modconfig->timeout == 0)
		modconfig->timeout = 3;

	mod_cgi_config_script_t *script = modconfig->scripts;
	while (script)
	{
		PyObject *pymodule = _mod_python_modulize(script->path.data, script->path.length);
		if (pymodule)
		{
			_mod_python_script_t *pscript = calloc(1, sizeof(*pscript));
			pscript->pymodule = pymodule;
			_string_store(&pscript->path, script->path.data, script->path.length);
			pscript->next = mod->scripts;
			mod->scripts = pscript;
		}
		script = script->next;
	}
	PyErr_Clear();
	httpserver_addconnector(server, _python_connector, mod, CONNECTOR_DOCUMENT, str_python);

	return mod;
}

static void mod_python_destroy(void *arg)
{
	_mod_python_t *mod = (_mod_python_t *)arg;

	if (mod->config->env)
		free(mod->config->env);
	free(mod->config);
	free(mod);
}

static void _python_freectx(mod_python_ctx_t *ctx)
{
	free(ctx);
}

static int _python_checkname(_mod_python_t *mod, const char *uri, const char **path_info)
{
	const mod_python_config_t *config = mod->config;
	if (utils_searchexp(uri, config->deny, NULL) == ESUCCESS)
	{
		return  EREJECT;
	}
	if (utils_searchexp(uri, config->allow, path_info) != ESUCCESS)
	{
		return  EREJECT;
	}
	if (*path_info == uri)
	{
		// path_info must not be the first caracter of uri
		*path_info = strchr(*path_info + 1, '/');
	}
	return ESUCCESS;
}

static int _python_start(_mod_python_t *mod, http_message_t *request, http_message_t *response)
{
	const mod_python_config_t *config = mod->config;
	int ret = EREJECT;
	const char *uri = NULL;
	size_t urilen = httpmessage_REQUEST2(request,"uri", &uri);
	if (uri && config->docroot)
	{
		const char *function = NULL;
		if (_python_checkname(mod, uri, &function) != ESUCCESS)
		{
			dbg("python: %s forbidden extension", uri);
			return EREJECT;
		}
		/**
		 * split the URI between the Python script path and the
		 * function name.
		 * /test.python/function => /test.python and  function
		 */
		if (function != NULL && (size_t)(function - uri) < urilen)
		{
			urilen = function - uri;
		}
		else
			function = uri + urilen;

		while (*uri == '/' && *uri != '\0')
		{
			uri++;
			urilen--;
		}
		while (*function == '/' && *function != '\0')
		{
			function++;
		}
		const char *ext = strstr(uri, ".py");
		if (ext != NULL)
			urilen = ext - uri;
		if (uri[urilen - 1] == '/')
			urilen--;

		char *iterator = (char *)uri;
		while (*iterator != '\0')
		{
			if (*iterator == '/')
				*iterator = '.';
			iterator++;
		}

		python_dbg("python: new uri %.*s", (int)urilen, uri);
		python_dbg("python: function %s", function);
		PyObject *pymodule = NULL;
		_mod_python_script_t *script = mod->scripts;
		while (script)
		{
			if (((size_t)urilen == script->path.length) && !strncasecmp(script->path.data, uri, urilen))
			{
				pymodule = script->pymodule;
				break;
			}
			script = script->next;
		}
		if (pymodule == NULL)
		{
			pymodule = _mod_python_modulize(uri, urilen);
		}
		PyObject *pyfunc = NULL;
		if (pymodule != NULL)
		{
			pyfunc = PyObject_GetAttrString(pymodule, function);
		}
		else
			warn("python: unable to modulize %.*s", (int)urilen, uri);
		if (!pyfunc || !PyCallable_Check(pyfunc))
		{
			httpmessage_result(response, RESULT_403);
			warn("python: unable to instanciate %s", function);
			return ESUCCESS;
		}

		mod_python_ctx_t *ctx;
		ctx = calloc(1, sizeof(*ctx));
		ctx->mod = mod;
		ctx->pymodule = pymodule;
		ctx->pyfunc = pyfunc;
		char **env = cgi_buildenv(config, request, uri, urilen, NULL, 0);
		int count = 0;
		ctx->pyenv = PyDict_New();
		for (;env[count] != NULL; count++)
		{
			PyObject *key = NULL;
			PyObject *value = NULL;
			char *separator = strchr(env[count], '=');
			if (separator != NULL)
			{
				*separator = '\0';
				key = PyUnicode_FromStringAndSize(env[count], separator - env[count]);
				value = PyUnicode_FromString(separator + 1);
			}
			else
				key = PyUnicode_FromString(env[count]);
			PyDict_SetItem(ctx->pyenv, key, value);
		}
		ctx->pycontent = NULL;

		httpmessage_private(request, ctx);
		ret = EINCOMPLETE;
	}
	return ret;
}

static int _python_request(mod_python_ctx_t *ctx, http_message_t *request)
{
	int ret = ECONTINUE;
	const char *input = NULL;
	int inputlen;
	size_t rest;

	inputlen = httpmessage_content(request, &input, &rest);
	if (inputlen > 0)
	{
#ifdef DEBUG
		static int length = 0;
		length += inputlen;
		python_dbg("python: %d input %s", length,input);
#endif
		PyObject *pychunk = PyUnicode_FromStringAndSize(input, inputlen);
		if (ctx->pycontent == NULL)
			ctx->pycontent = pychunk;
		else
		{
			PyUnicode_AppendAndDel(&ctx->pycontent, pychunk);
		}
	}
	else if (inputlen != EINCOMPLETE)
		ctx->state = STATE_INFINISH;
	return ret;
}

#if 0
static void _python_is(const char * name,PyObject *obj)
{
	dbg("%s", name);
	if (obj)
	{
		dbg("\tis Bytes %d", PyBytes_Check(obj));
		dbg("\tis Dict %d", PyDict_Check(obj));
		dbg("\tis Index %d", PyIndex_Check(obj));
		dbg("\tis Mapping %d", PyMapping_Check(obj));
		dbg("\tis List %d", PyList_Check(obj));
		dbg("\tis Tuple %d", PyTuple_Check(obj));
		dbg("\tis Unicode %d", PyUnicode_Check(obj));
		dbg("\tis Callable %d", PyCallable_Check(obj));
	}
	else
	{
		dbg("\tis null");
	}
}
#endif

static int _python_response(mod_python_ctx_t *ctx, http_message_t *response)
{
	int ret = ECONTINUE;
	ctx->state = STATE_CONTENTCOMPLETE;

	PyObject *pyrequestclass = PyObject_GetAttrString(ctx->pymodule, "HttpRequest");
	if (pyrequestclass == NULL || !PyCallable_Check(pyrequestclass))
	{
		httpmessage_result(response, RESULT_500);
		warn("python: script bad syntax HttpRequest not available");
		return ESUCCESS;
	}
	PyObject *pyrequest = PyObject_CallObject(pyrequestclass, NULL);
	Py_DECREF(pyrequestclass);
	if (pyrequest == NULL)
	{
		httpmessage_result(response, RESULT_500);
		warn("python: script bad syntax HttpRequest not available");
		return ESUCCESS;
	}
	PyObject_SetAttrString(pyrequest, "META", ctx->pyenv);
	if (ctx->pycontent)
	{
		PyObject_SetAttrString(pyrequest, "_body", ctx->pycontent);
	}
	PyObject *pyrequestfunc = PyObject_GetAttrString(pyrequest, "_load");
	if (pyrequestfunc && PyCallable_Check(pyrequestfunc))
	{
		PyObject_CallNoArgs(pyrequestfunc);
		Py_DECREF(pyrequestfunc);
	}

	PyObject *pyresponse = PyObject_GetAttrString(ctx->pymodule, "HttpResponse");
	if (pyresponse == NULL)
	{
		httpmessage_result(response, RESULT_500);
		warn("python: script bad syntax HttpResponse not available");
		return ESUCCESS;
	}
	PyObject *pyresult = PyObject_CallFunctionObjArgs(ctx->pyfunc, pyrequest, NULL);
	if (pyresult)
	{
		PyObject *pystatus = PyObject_GetAttrString(pyresult, "status_code");
		if (pystatus != NULL)
		{
			httpmessage_result(response, PyLong_AsLong(pystatus));
			Py_DECREF(pystatus);
		}
		char *mime = NULL;
		Py_ssize_t length = 0;
		if (PyMapping_Check(pyresult))
		{
			PyObject *pyheaders = PyMapping_Items(pyresult);
			for (int i = 0; i < PyList_Size(pyheaders); i++)
			{
				PyObject *pyheader = PyList_GetItem(pyheaders, i);
				PyObject *pykey = PyTuple_GetItem(pyheader, 0);
				PyObject *pyvalue = PyTuple_GetItem(pyheader, 1);
				PyObject *pyasciikey = PyUnicode_AsASCIIString(pykey);
				PyObject *pylatin1value = PyUnicode_AsLatin1String(pyvalue);
				const char *key = PyBytes_AsString(pyasciikey);
				const char *value = PyBytes_AsString(pylatin1value);
				python_dbg("python: header %s: %s", key, value);
				if (key && value && strcmp(key, str_contenttype) && strcmp(key, str_contentlength))
					httpmessage_addheader(response, key, value, -1);
				else if (key && !strcmp(key, str_contenttype))
					mime = strdup(value);
				else if (key && !strcmp(key, str_contentlength))
					length = atol(value);
				Py_DECREF(pyheader);
				Py_DECREF(pyasciikey);
				Py_DECREF(pylatin1value);
				Py_DECREF(pykey);
				Py_DECREF(pyvalue);
			}
			Py_DECREF(pyheaders);
		}
		PyObject *pycontentfunc = PyObject_GetAttrString(pyresult, "content");
		PyObject *pycontent = NULL;
		if (pycontentfunc && PyCallable_Check(pycontentfunc))
			pycontent = PyObject_CallNoArgs(pycontentfunc);
		else
			pycontent = pycontentfunc;

		Py_ssize_t size = 0;
		char *content = NULL;
		if (pycontent != NULL)
			PyBytes_AsStringAndSize(pycontent, &content, &size);
		python_dbg("python: content %s", content);
		if (content != NULL)
		{
			if (length == 0)
				httpmessage_addcontent(response, mime, content, size);
			else
				httpmessage_addcontent(response, mime, content, length);
			if (mime)
				free(mime);
		}
		Py_DECREF(pycontent);
		Py_DECREF(pycontentfunc);
	}
	else
		httpmessage_result(response, RESULT_500);
	ctx->state = STATE_OUTFINISH;
	return ret;
}
static int _python_connector(void *arg, http_message_t *request, http_message_t *response)
{
	int ret = EINCOMPLETE;
	mod_python_ctx_t *ctx = httpmessage_private(request, NULL);
	_mod_python_t *mod = (_mod_python_t *)arg;

	if (ctx == NULL)
	{
		ret = _python_start(mod, request, response);
		if (ret != EINCOMPLETE)
			return ret;
		ctx = httpmessage_private(request, NULL);
		_python_request(ctx, request);
	}
	else
	{
		switch (ctx->state & STATE_MASK)
		{
		case STATE_START:
			_python_request(ctx, request);
			/**
			 * Read the request. The connector is still EINCOMPLETE
			 */
		break;
		case STATE_INFINISH:
			_python_response(ctx, response);
			ret = ECONTINUE;
		break;
		case STATE_OUTFINISH:
		{
			size_t length;
			ret = httpmessage_content(response, NULL, &length);
			python_dbg("python: content len %d %lu", ret, length);
			if (ret == 0)
				ctx->state = STATE_END | STATE_SHUTDOWN;
			ret = ECONTINUE;
		}
		break;
		case STATE_CONTENTCOMPLETE:
			ret = httpmessage_parsecgi(response, NULL, 0);
			ret = ECONTINUE;
			ctx->state = STATE_OUTFINISH | STATE_SHUTDOWN;
		break;
		case STATE_END:
			_python_freectx(ctx);
			httpmessage_private(request, NULL);
			ret = ESUCCESS;
		break;
		}
	}
	/* this mod returns EINCOMPLETE
	 * because it needs to wait the end
	 * to know the length of the content */
	return ret;
}

const module_t mod_python =
{
	.name = str_python,
	.configure = (module_configure_t)&python_config,
	.create = (module_create_t)&mod_python_create,
	.destroy = &mod_python_destroy
};

#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_python")));
#endif

static void __attribute__ ((constructor)) _mod_python_init(void);
static void __attribute__ ((destructor)) _mod_python_finalize(void);

static void _mod_python_init(void)
{
	Py_SetProgramName(L"ouistiti");
	Py_Initialize();
}

static void _mod_python_finalize(void)
{
	Py_Finalize();
}
