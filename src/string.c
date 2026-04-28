/*****************************************************************************
 * string.c: string manipulation API
 * this file is part of https://github.com/ouistiti-project/ouistiti
 *****************************************************************************
 * Copyright (C) 2016-2027
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
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifdef USE_STDARG
#include <stdarg.h>
#endif

#include "ouistiti/ouistiti.h"
#include "ouistiti/log.h"

#define string_match_dbg(...)
#define MAX_STRING 1024

#if _STRING_TEST_
typedef struct string_s string_t;
struct string_s
{
	const char *data;
	size_t length;
	size_t size;
	char *ddata;
};

#define STRING_REF(string) string, sizeof(string)-1
#define STRING_INFO(string) string.data, string.length
#define STRING_DCL(string) {.data=string, .size=sizeof(string), .length=sizeof(string)-1}
#endif


string_t *string_create(size_t size)
{
	string_t *str = calloc(1, sizeof(*str) + size);
	str->ddata = (void *)str + sizeof(*str);
	str->data = str->ddata;
	str->size = size;
	return str;
}

void string_debug(const string_t *str, const char *name)
{
	dbg("string: %s %.*s", name, (int)(str->length & INT_MAX), str->data);
}

size_t string_length(const string_t *str)
{
	if (str->data && str->length == (size_t) -1)
		((string_t*)str)->length = strnlen(str->data, MAX_STRING);
	return str->length;
}

size_t string_size(const string_t *str)
{
	return str->size;
}

int string_store(string_t *str, const char *pointer, size_t length)
{
	if (str->ddata)
	{
		return string_cpy(str, pointer, length);
	}
	str->data = pointer;
	/// set length and check if value is -1
	str->length = length;
	str->length = string_length(str);
	str->size = str->length + 1;
	if (str->data == NULL)
	{
		str->length = 0;
		str->size = 0;
	}
	return ESUCCESS;
}

int string_cmp(const string_t *str, const char *cmp, size_t length)
{
	if (cmp == NULL)
		return -1;
	if ((length != (size_t) -1) && (length != str->length))
		return (length - str->length);
	return strncasecmp(str->data, cmp, str->length);
}

int string_compare(const string_t *str1, const string_t *str2)
{
	if (str2 == NULL)
		return -1;
	if (str2->length != str1->length)
		return (str2->length - str1->length);
	return strncasecmp(str1->data, str2->data, str1->length);
}

int string_into(const string_t *nail, const string_t *stack, const char sep)
{
	int ret = -1;
	if (string_empty(stack))
		return -1;
	size_t stacklen = string_length(stack);
	string_t it = {.data = stack->data, .length = stack->length, .size = stack->size};
	size_t next = 0;
	do
	{
		next = string_browse(&it, sep, next);
		string_match_dbg("string_into: %.*s", string_length(&it), string_toc(&it));
		if (!string_match(nail, &it, NULL))
		{
			ret = 0;
			break;
		}
	} while (next != 0);
	return ret;
}

int string_contain(const string_t *stack, const char *nail, size_t length, const char sep)
{
	int ret = -1;
	if (nail == NULL)
		return -1;
	if (length == (size_t) -1)
		length = strnlen(nail, stack->length);
	size_t naillen = length;
	const char *offset = stack->data;
	while (offset && offset[0] != '\0' && length > 0)
	{
		for (naillen = 0; nail[naillen] && nail[naillen] != sep; naillen++);
		if (nail[0] == '*')
		{
			nail++;
			naillen--;
			offset = strstr(offset, nail);
		}
		if (offset && !strncasecmp(offset, nail, naillen))
		{
			if (nail[naillen] == '*')
				ret = 0;
			/// a string_t may not be a null terminated array
			if (((offset + naillen) == (stack->data + stack->length)) || offset[naillen] == sep)
				ret = 0;
		}
		if (ret != 0 && naillen < length)
		{
			offset = stack->data;
			nail += naillen + 1;
			length -= naillen + 1;
			continue;
		}
		if (ret == 0)
			break;
		for (offset; offset < (stack->data + stack->size) && offset[0] != sep; offset++);
		if (offset < stack->data + stack->size)
			offset++;
		else
			offset = NULL;
	}
	return ret;
}

int string_split(const string_t *str, char sep, ...)
{
	int ret = 0;
#ifdef USE_STDARG
	va_list ap;
	va_start(ap, sep);
	string_t *arg = va_arg(ap, string_t *);
	for (size_t index = 0; index < str->length; index++)
	{
		if (ret > 10) ///10 for max elements
			break;
		ret++;
		if (arg != NULL)
			arg->data = &str->data[index];
		while (str->data[index] != sep && index < str->length) index++;
		if (arg == NULL)
			continue;
		arg->length = &str->data[index] - arg->data;
		if (arg->ddata && arg != str)
		{
			string_cpy(arg, arg->data, arg->length);
			arg->data = arg->ddata;
		}
		arg = va_arg(ap, string_t *);
	}
	va_end(ap);
#endif
	return ret;
}

int string_chr(const string_t *str, char c, int index)
{
	int i;
	for (i = index; i < str->length && str->data[i] != c; i++);
	if (i == str->length)
		return -1;
	return i;
}

int string_rchr(const string_t *str, char c, int index)
{
	int i;
	for (i = str->length; i > index && str->data[i - 1] != c; i--);
	if (i == 0)
		return -1;
	return i - 1;
}

int string_is(const string_t *str1, const string_t *str2)
{
	if ((str1 == NULL) || (str2 == NULL))
		return 0;
	if ((str1->length != str2->length))
		return 0;
	if (!strncmp(str1->data, str2->data, str1->length))
		return 1;
	return 0;
}

int string_startwith(const string_t *str1, const string_t *str2)
{
	if ((str1 == NULL) || (str2 == NULL))
		return 0;
	if ((str1->length < str2->length))
		return 0;
	if (!strncasecmp(str1->data, str2->data, str2->length))
		return 1;
	return 0;
}

string_t *string_rest(string_t *str1, const string_t *str2)
{
	if ((str1 == NULL) || (str2 == NULL))
		return NULL;
	if ((str1->length < str2->length))
		return NULL;
	if (strncasecmp(str1->data, str2->data, str2->length))
		return NULL;
	str1->data += str2->length;
	str1->length -= str2->length;
	return str1;
}

int string_match(const string_t *str1, const string_t *str2, ...)
{
	if (string_empty(str1))
		return -1;
	if (string_empty(str2))
		return -1;
	int ret = -1;
	int str1index = 0;
	int str2index = 0;
	int str2length = string_length(str2);
	int wildcard = 0;
	if (string_index(str2, str2index) == '^')
	{
		str2index++;
		str2length--;
		wildcard = 0;
	}
#ifdef USE_STDARG
	va_list ap;
	va_start(ap, str2);
#endif
	string_t *arg = NULL;
	while (str1index < string_length(str1) && str2index < string_length(str2))
	{
		string_match_dbg("string_match: contains %s (%.*s)", str1->data + str1index, str2length, str2->data + str2index);
		char c = string_index(str2, str2index);
		if (c == '*')
		{
#ifdef USE_STDARG
			arg = va_arg(ap, string_t *);
#endif
			if (arg)
			{
				arg->data = str1->data + str1index;
				arg->length = str1->length - str1index;
				arg->size = arg->length;
			}
			wildcard = 1;
			str2index++;
			continue;
		}
		if (c == '$' && str1index < string_length(str1))
		{
			ret = -1;
			goto match_out;
		}
		int end = -1;
		end = string_chr(str2, '*', str2index);
		if (end == -1)
			end = string_chr(str2, '$', str2index);
		if (end == -1)
			end = string_length(str2);

		if (wildcard)
		{
			str1index = string_chr(str1, c, str1index);
			if (str1index == -1 && c != '\0')
				goto match_out;
		}
		do
		{
			string_match_dbg("string_match: compares %.*s (%.*s)", end - (str2index), str1->data + str1index, end - (str2index), str2->data + str2index);
			ret = strncasecmp(str1->data + str1index, str2->data + str2index, end - str2index);
			if (ret)
				str1index++;
		} while (ret && wildcard && str1index < string_length(str1));
		if (ret)
			goto match_out;
		if (wildcard && arg)
		{
			arg->length = str1index - (arg->data - str1->data);
		}
		wildcard = 0;
		str1index += end - (str2index);
		str2length -= end - str2index;
		str2index = end;
	}
	ret = 0;
match_out:
#ifdef USE_STDARG
	va_end(ap);
#endif
	return ret;
}

int string_empty(const string_t *str)
{
	return ! (str != NULL && str->data != NULL && str->data[0] != '\0' && str->length > 0);
}

int string_cpy(string_t *str, const char *source, size_t length)
{
	if (str->ddata == NULL)
	{
		dbg("string: fgetline requires a dynamic string");
		return EREJECT;
	}
	if ((length == (size_t) -1) || (length > INT_MAX))
		str->length = snprintf(str->ddata, str->size, "%s", source);
	else
		str->length = snprintf(str->ddata, str->size, "%.*s", (int)length, source);
	if (str->length == str->size)
		return EREJECT;
	str->data = str->ddata;
	return ESUCCESS;
}

int string_append(string_t *str, const char *source, size_t length)
{
	if (str->ddata == NULL || (length == (size_t) -1) || (length > INT_MAX))
		return EREJECT;
	if ((str->length + length) > str->size)
	{
		str->size = str->length + length + 1;
		str->ddata = realloc(str->ddata, str->size);
	}
	str->length += snprintf(str->ddata + str->length, str->size, "%.*s", (int)length, source);
	if (str->length == str->size)
		return EREJECT;
	return ESUCCESS;
}

int string_printf(string_t *str, void *fmt,...)
{
	if (str->ddata != NULL)
	{
#ifdef USE_STDARG
		va_list ap;
		va_start(ap, fmt);
		str->length = vsnprintf(str->ddata, str->size, fmt, ap);
		va_end(ap);
		str->data = str->ddata;
		if (str->length < str->size)
			return ESUCCESS;
#endif
	}
	dbg("string: printf requires a dynamic string");
	return EREJECT;
}

string_t *string_dup(const string_t *src)
{
	string_t *dst = NULL;
	if (string_empty(src))
		return dst;
	dst = calloc(1, sizeof(*dst));
	dst->ddata = strndup(src->data, src->length);
	dst->data = dst->ddata;
	dst->size = src->length + 1;
	dst->length = src->length;
	return dst;
}

size_t string_slice(string_t *str, int start, int length)
{
	size_t offset = str->data - str->ddata;
	if (start > 0)
	{
		str->data += start;
		str->length -= start;
		if (str->ddata == NULL)
			str->size -= start;
		if (length == 0)
			length = str->length;
	}
	if (((str->data - str->ddata + length) < (offset + str->size)))
		str->length = length;
	return str->length;
}

size_t string_browse(string_t *str, char sep, size_t next)
{
	str->data += next;
	str->length = 0;
	str->size -= next;
	if (str->size == 0)
		return 0;
	for (next = 0; next < (str->size - 1) && str->data[next] != sep; next++) str->length++;
	if (next == str->size)
		return 0;
	if (str->data[next] != sep)
		return 0;
	next++; /// leave the separator
	return next;
}

void string_unquote(string_t *str)
{
	if (str->data[0] == '\"')
	{
		str->data++;
		str->length--;
	}
	if (str->data[str->length - 1] == '\"')
		str->length--;
}

void string_unroot(string_t *str)
{
	if (string_empty(str))
		return;
	while(str->data[0] == '/' || str->data[0] == '.' )
	{
		str->data++;
		str->length--;
	}
}

long int string_tol(const string_t *str, int base)
{
	return strtol(str->data, NULL, base);
}

const char string_index(const string_t *str, ssize_t index)
{
	if (string_empty(str))
		return '\0';
	if (index < 0)
		return str->data[str->length + index];
	if (index < str->length)
		return str->data[index];
	return '\0';
}

string_t *string_value(string_t *str, const char *header, size_t length)
{
	string_t key = {0};
	string_store(&key, header, length);
	string_t *value = string_rest(str, &key);
	string_unquote(value);
	return value;
}

int string_fgetline(string_t *str, FILE *file)
{
	if (str->ddata == NULL)
	{
		dbg("string: fgetline requires a dynamic string");
		return EREJECT;
	}
	size_t length = 0;
#if 1
	do
	{
		char c = fgetc(file);
		if (c == EOF || c == '\n')
			break;
		str->ddata[length++] = c;
	} while (length < str->size);
#elif 0
	while (((str->ddata[length] = fgetc(file)) != EOF) &&
			(str->ddata[length] != '\n') &&
			(length < str->size)) length++;
#else
	ssize_t ret = getline(&str->ddata, &str->size, file);
	if (ret == -1)
		return EREJECT;
#endif
	if (str->ddata[length] == '\n')
		length--;
	if (length == 0)
		return EREJECT;
	str->length = length;
	return ESUCCESS;
}

const char *string_toc(const string_t *str)
{
	if (str)
		return str->data;
	return NULL;
}

char *string_storage(const string_t *str)
{
	if (str)
		return str->ddata;
	return NULL;
}

void string_cleansafe(string_t *str)
{
	volatile char *p = str->ddata;
	if (p == NULL)
	{
		warn("string: clean safe a static string");
		str->length = 0;
		return;
	}
	while (str->length--)
	{
		*p++ = (char)random();
	}
}

void string_destroy(string_t *str)
{
	if (str->ddata && ((void*)str->ddata != ((void *)str + sizeof(*str))))
		free(str->ddata);
	str->ddata = NULL;
	str->data = NULL;
	str->length = 0;
	str->size = 0;
	free(str);
}

#if _STRING_TEST_
int main(int argc, char * const *argv)
{
	string_t dstr1 = {0};
	string_t *str1 = &dstr1;
	string_t dstr2 = {0};
	string_t *str2 = &dstr2;
	string_store(str1, "hello world on earth", -1);
	warn("main string is\n%s", string_toc(str1));
	string_t arg1 = {0};
	string_t arg2 = {0};
	string_store(str2, "hello * on *arth", -1);
	if (string_match(str1, str2, &arg1, &arg2, NULL))
		err("%s doesn't match", string_toc(str2));
	else
		warn("%s OK", string_toc(str2));
	if (!string_empty(&arg1) && !string_cmp(&arg1, "world", 5))
		warn("good arg1");
	else
		err("arg1: %.*s", string_length(&arg1), string_toc(&arg1));
	if (!string_empty(&arg2) && !string_cmp(&arg2, "e", 1))
		warn("good arg2");
	else
		err("arg2: %.*s", string_length(&arg2), string_toc(&arg2));
	string_store(str2, "* on earth$", -1);
	string_store(&arg1, "", 0);
	string_store(&arg2, "", 0);
	if (string_match(str1, str2, &arg1, &arg2, NULL))
		err("%s doesn't match", string_toc(str2));
	else
		warn("%s OK", string_toc(str2));
	if (!string_empty(&arg1) && !string_cmp(&arg1, "hello world", 11))
		warn("good arg1");
	else
		err("arg1: %.*s", string_length(&arg1), string_toc(&arg1));
	if (string_empty(&arg2))
		warn("good arg2");
	else
		err("arg2: %.*s", string_length(&arg2), string_toc(&arg2));
	string_store(str2, "hello world on *", -1);
	string_store(&arg1, "", 0);
	string_store(&arg2, "", 0);
	if (string_match(str1, str2, &arg1, &arg2, NULL))
		err("%s doesn't match", string_toc(str2));
	else
		warn("%s OK", string_toc(str2));
	if (!string_empty(&arg1) && !string_cmp(&arg1, "earth", 5))
		warn("good arg1");
	else
		err("arg1: %.*s", string_length(&arg1), string_toc(&arg1));
	if (string_empty(&arg2))
		warn("good arg2");
	else
		err("arg2: %.*s", string_length(&arg2), string_toc(&arg2));
	string_store(str2, "^hello world on earth$", -1);
	if (string_match(str1, str2, NULL))
		err("%s doesn't match", string_toc(str2));
	else
		warn("%s OK", string_toc(str2));
	string_store(str2, "bonjour le monde", -1);
	if (!string_match(str1, str2, NULL))
		err("%s match", string_toc(str2));
	else
		warn("%s OK", string_toc(str2));
	string_store(str2, "^world on earth$", -1);
	if (!string_match(str1, str2, NULL))
		err("%s match", string_toc(str2));
	else
		warn("%s OK", string_toc(str2));
	string_store(str2, "^hello world on$earth", -1);
	if (!string_match(str1, str2, NULL))
		err("%s match", string_toc(str2));
	else
		warn("%s OK", string_toc(str2));
	return 0;
}
#endif
