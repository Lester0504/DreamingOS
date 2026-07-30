/*
  Copyright (c) 2009 Dave Gamble

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#include "k_json.h"

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

struct cjson_parse_ctx {
	size_t nodes;
	size_t allocated;
	unsigned int depth;
};

struct cjson_printbuf {
	char *data;
	size_t length;
	size_t capacity;
};

static void *cJSON_malloc(size_t size)
{
	if (!size)
		return NULL;
	return kmalloc(size, GFP_KERNEL);
}

static void *cJSON_realloc(void *ptr, size_t size)
{
	if (!size)
		return NULL;
	return krealloc(ptr, size, GFP_KERNEL);
}

static void cJSON_free(void *ptr)
{
	kfree(ptr);
}

static bool size_add_overflow(size_t left, size_t right, size_t *result)
{
	if (right > (size_t)-1 - left)
		return true;
	*result = left + right;
	return false;
}

static void *parse_alloc(struct cjson_parse_ctx *ctx, size_t size)
{
	size_t total;

	if (!ctx || !size || size_add_overflow(ctx->allocated, size, &total) ||
	    total > CJSON_PARSE_MAX_TOTAL_ALLOC)
		return NULL;

	ctx->allocated = total;
	return cJSON_malloc(size);
}

static char *cJSON_strdup(const char *str)
{
	size_t len;
	char *copy;

	if (!str)
		return NULL;
	len = strlen(str);
	if (len == (size_t)-1)
		return NULL;
	copy = cJSON_malloc(len + 1);
	if (!copy)
		return NULL;
	memcpy(copy, str, len + 1);
	return copy;
}

static cJSON *cJSON_New_Item(void)
{
	cJSON *node = cJSON_malloc(sizeof(*node));

	if (node)
		memset(node, 0, sizeof(*node));
	return node;
}

static cJSON *parse_new_item(struct cjson_parse_ctx *ctx)
{
	cJSON *node;

	if (!ctx || ctx->nodes >= CJSON_PARSE_MAX_NODES)
		return NULL;
	node = parse_alloc(ctx, sizeof(*node));
	if (!node)
		return NULL;
	memset(node, 0, sizeof(*node));
	ctx->nodes++;
	return node;
}

void cJSON_Delete(cJSON *item)
{
	cJSON *next;

	while (item) {
		next = item->next;
		if (item->child)
			cJSON_Delete(item->child);
		cJSON_free(item->valuestring);
		cJSON_free(item->string);
		cJSON_free(item);
		item = next;
	}
}

static const char *skip(const char *input)
{
	while (input && *input && (unsigned char)*input <= 32)
		input++;
	return input;
}

static int hex_value(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	if (value >= 'a' && value <= 'f')
		return value - 'a' + 10;
	if (value >= 'A' && value <= 'F')
		return value - 'A' + 10;
	return -1;
}

static int parse_hex_quad(const char *input, unsigned int *value)
{
	unsigned int codepoint = 0;
	int index;

	if (!input || !value)
		return -1;
	for (index = 0; index < 4; index++) {
		int digit = hex_value(input[index]);

		if (digit < 0)
			return -1;
		codepoint = (codepoint << 4) | (unsigned int)digit;
	}
	*value = codepoint;
	return 0;
}

static size_t valid_utf8_sequence_length(const unsigned char *input)
{
	if (!input || !input[0])
		return 0;
	if (input[0] < 0x80)
		return 1;
	if (input[0] >= 0xc2 && input[0] <= 0xdf &&
	    input[1] >= 0x80 && input[1] <= 0xbf)
		return 2;
	if (input[0] == 0xe0 && input[1] >= 0xa0 && input[1] <= 0xbf &&
	    input[2] >= 0x80 && input[2] <= 0xbf)
		return 3;
	if (((input[0] >= 0xe1 && input[0] <= 0xec) ||
	     (input[0] >= 0xee && input[0] <= 0xef)) &&
	    input[1] >= 0x80 && input[1] <= 0xbf &&
	    input[2] >= 0x80 && input[2] <= 0xbf)
		return 3;
	if (input[0] == 0xed && input[1] >= 0x80 && input[1] <= 0x9f &&
	    input[2] >= 0x80 && input[2] <= 0xbf)
		return 3;
	if (input[0] == 0xf0 && input[1] >= 0x90 && input[1] <= 0xbf &&
	    input[2] >= 0x80 && input[2] <= 0xbf &&
	    input[3] >= 0x80 && input[3] <= 0xbf)
		return 4;
	if (input[0] >= 0xf1 && input[0] <= 0xf3 &&
	    input[1] >= 0x80 && input[1] <= 0xbf &&
	    input[2] >= 0x80 && input[2] <= 0xbf &&
	    input[3] >= 0x80 && input[3] <= 0xbf)
		return 4;
	if (input[0] == 0xf4 && input[1] >= 0x80 && input[1] <= 0x8f &&
	    input[2] >= 0x80 && input[2] <= 0xbf &&
	    input[3] >= 0x80 && input[3] <= 0xbf)
		return 4;
	return 0;
}

static const char *parse_number(cJSON *item, const char *number)
{
	const char *cursor = number;
	unsigned int value = 0;
	unsigned int limit = 0x7fffffffU;
	bool negative = false;

	if (*cursor == '-') {
		negative = true;
		limit++;
		cursor++;
	}
	if (*cursor < '0' || *cursor > '9')
		return NULL;
	if (*cursor == '0' && cursor[1] >= '0' && cursor[1] <= '9')
		return NULL;

	do {
		unsigned int digit = (unsigned int)(*cursor - '0');

		if (value > (limit - digit) / 10U)
			return NULL;
		value = value * 10U + digit;
		cursor++;
	} while (*cursor >= '0' && *cursor <= '9');

	if (negative && value == 0x80000000U)
		item->valueint = -2147483647 - 1;
	else
		item->valueint = negative ? -(int)value : (int)value;
	item->type = cJSON_Number;
	return cursor;
}

static const char *parse_string(cJSON *item, const char *string,
				struct cjson_parse_ctx *ctx)
{
	const char *cursor;
	char *output;
	char *write;
	size_t encoded_len = 0;

	if (!item || !string || !ctx || *string != '"')
		return NULL;

	cursor = string + 1;
	while (*cursor && *cursor != '"') {
		size_t sequence_len = 1;

		if ((unsigned char)*cursor < 32 || encoded_len >= CJSON_PARSE_MAX_STRING)
			return NULL;
		if ((unsigned char)*cursor >= 0x80) {
			sequence_len = valid_utf8_sequence_length(
				(const unsigned char *)cursor);
			if (!sequence_len || sequence_len > CJSON_PARSE_MAX_STRING - encoded_len)
				return NULL;
			encoded_len += sequence_len;
			cursor += sequence_len;
			continue;
		}
		encoded_len++;
		if (*cursor++ != '\\')
			continue;
		if (!*cursor)
			return NULL;
		if (*cursor == 'u') {
			unsigned int codepoint;
			size_t escape_tail = 5;

			if (parse_hex_quad(cursor + 1, &codepoint) != 0)
				return NULL;
			if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
				unsigned int low;

				if (cursor[5] != '\\' || cursor[6] != 'u' ||
				    parse_hex_quad(cursor + 7, &low) != 0 ||
				    low < 0xdc00 || low > 0xdfff)
					return NULL;
				escape_tail = 11;
			} else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) {
				return NULL;
			}
			if (encoded_len > CJSON_PARSE_MAX_STRING - escape_tail)
				return NULL;
			encoded_len += escape_tail;
			cursor += escape_tail;
		} else {
			if (!strchr("\\\"/bfnrt", *cursor))
				return NULL;
			encoded_len++;
			cursor++;
		}
	}
	if (*cursor != '"' || encoded_len > CJSON_PARSE_MAX_STRING)
		return NULL;

	output = parse_alloc(ctx, encoded_len + 1);
	if (!output)
		return NULL;

	cursor = string + 1;
	write = output;
	while (*cursor != '"') {
		unsigned int codepoint;

		if (*cursor != '\\') {
			*write++ = *cursor++;
			continue;
		}
		cursor++;
		switch (*cursor) {
		case 'b': *write++ = '\b'; cursor++; break;
		case 'f': *write++ = '\f'; cursor++; break;
		case 'n': *write++ = '\n'; cursor++; break;
		case 'r': *write++ = '\r'; cursor++; break;
		case 't': *write++ = '\t'; cursor++; break;
		case '\\': case '"': case '/': *write++ = *cursor++; break;
		case 'u':
			if (parse_hex_quad(cursor + 1, &codepoint) != 0) {
				cJSON_free(output);
				return NULL;
			}
			cursor += 5;
			if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
				unsigned int low;

				if (cursor[0] != '\\' || cursor[1] != 'u' ||
				    parse_hex_quad(cursor + 2, &low) != 0 ||
				    low < 0xdc00 || low > 0xdfff) {
					cJSON_free(output);
					return NULL;
				}
				codepoint = 0x10000 + ((codepoint - 0xd800) << 10) +
					(low - 0xdc00);
				cursor += 6;
			} else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) {
				cJSON_free(output);
				return NULL;
			}
			if (codepoint < 0x80) {
				*write++ = (char)codepoint;
			} else if (codepoint < 0x800) {
				*write++ = (char)(0xc0 | (codepoint >> 6));
				*write++ = (char)(0x80 | (codepoint & 0x3f));
			} else if (codepoint < 0x10000) {
				*write++ = (char)(0xe0 | (codepoint >> 12));
				*write++ = (char)(0x80 | ((codepoint >> 6) & 0x3f));
				*write++ = (char)(0x80 | (codepoint & 0x3f));
			} else {
				*write++ = (char)(0xf0 | (codepoint >> 18));
				*write++ = (char)(0x80 | ((codepoint >> 12) & 0x3f));
				*write++ = (char)(0x80 | ((codepoint >> 6) & 0x3f));
				*write++ = (char)(0x80 | (codepoint & 0x3f));
			}
			break;
		default:
			cJSON_free(output);
			return NULL;
		}
	}
	*write = '\0';
	item->valuestring = output;
	item->type = cJSON_String;
	return cursor + 1;
}

static const char *parse_value(cJSON *item, const char *value,
			       struct cjson_parse_ctx *ctx);

static const char *parse_array(cJSON *item, const char *value,
			       struct cjson_parse_ctx *ctx)
{
	cJSON *child;

	if (!item || !value || !ctx || *value != '[' ||
	    ctx->depth >= CJSON_PARSE_MAX_DEPTH)
		return NULL;
	item->type = cJSON_Array;
	value = skip(value + 1);
	if (*value == ']')
		return value + 1;

	ctx->depth++;
	child = parse_new_item(ctx);
	if (!child)
		goto fail;
	item->child = child;

	for (;;) {
		value = parse_value(child, skip(value), ctx);
		if (!value)
			goto fail;
		value = skip(value);
		if (*value == ']') {
			ctx->depth--;
			return value + 1;
		}
		if (*value != ',')
			goto fail;
		child->next = parse_new_item(ctx);
		if (!child->next)
			goto fail;
		child->next->prev = child;
		child = child->next;
		value = skip(value + 1);
	}

fail:
	ctx->depth--;
	return NULL;
}

static const char *parse_object(cJSON *item, const char *value,
				struct cjson_parse_ctx *ctx)
{
	cJSON *child;

	if (!item || !value || !ctx || *value != '{' ||
	    ctx->depth >= CJSON_PARSE_MAX_DEPTH)
		return NULL;
	item->type = cJSON_Object;
	value = skip(value + 1);
	if (*value == '}')
		return value + 1;

	ctx->depth++;
	child = parse_new_item(ctx);
	if (!child)
		goto fail;
	item->child = child;

	for (;;) {
		value = parse_string(child, skip(value), ctx);
		if (!value)
			goto fail;
		child->string = child->valuestring;
		child->valuestring = NULL;
		value = skip(value);
		if (*value != ':')
			goto fail;
		value = parse_value(child, skip(value + 1), ctx);
		if (!value)
			goto fail;
		value = skip(value);
		if (*value == '}') {
			ctx->depth--;
			return value + 1;
		}
		if (*value != ',')
			goto fail;
		child->next = parse_new_item(ctx);
		if (!child->next)
			goto fail;
		child->next->prev = child;
		child = child->next;
		value = skip(value + 1);
	}

fail:
	ctx->depth--;
	return NULL;
}

static const char *parse_value(cJSON *item, const char *value,
			       struct cjson_parse_ctx *ctx)
{
	if (!item || !value || !ctx)
		return NULL;
	if (!strncmp(value, "null", 4)) {
		item->type = cJSON_NULL;
		return value + 4;
	}
	if (!strncmp(value, "false", 5)) {
		item->type = cJSON_False;
		return value + 5;
	}
	if (!strncmp(value, "true", 4)) {
		item->type = cJSON_True;
		item->valueint = 1;
		return value + 4;
	}
	if (*value == '"')
		return parse_string(item, value, ctx);
	if (*value == '-' || (*value >= '0' && *value <= '9'))
		return parse_number(item, value);
	if (*value == '[')
		return parse_array(item, value, ctx);
	if (*value == '{')
		return parse_object(item, value, ctx);
	return NULL;
}

cJSON *cJSON_Parse(const char *value)
{
	struct cjson_parse_ctx ctx = { 0 };
	const char *end;
	cJSON *root;

	if (!value)
		return NULL;
	root = parse_new_item(&ctx);
	if (!root)
		return NULL;
	end = parse_value(root, skip(value), &ctx);
	if (!end || *skip(end) != '\0') {
		cJSON_Delete(root);
		return NULL;
	}
	return root;
}

static bool printbuf_reserve(struct cjson_printbuf *buffer, size_t additional)
{
	size_t required;
	size_t capacity;
	char *resized;

	if (!buffer || size_add_overflow(buffer->length, additional, &required) ||
	    size_add_overflow(required, 1, &required))
		return false;
	if (required <= buffer->capacity)
		return true;

	capacity = buffer->capacity ? buffer->capacity : 32;
	while (capacity < required) {
		if (capacity > (size_t)-1 / 2) {
			capacity = required;
			break;
		}
		capacity *= 2;
	}
	resized = cJSON_realloc(buffer->data, capacity);
	if (!resized)
		return false;
	buffer->data = resized;
	buffer->capacity = capacity;
	return true;
}

static bool printbuf_append(struct cjson_printbuf *buffer, const char *data,
			    size_t length)
{
	if (!buffer || (!data && length) || !printbuf_reserve(buffer, length))
		return false;
	if (length)
		memcpy(buffer->data + buffer->length, data, length);
	buffer->length += length;
	buffer->data[buffer->length] = '\0';
	return true;
}

static bool printbuf_char(struct cjson_printbuf *buffer, char value)
{
	return printbuf_append(buffer, &value, 1);
}

static bool print_string_ptr(struct cjson_printbuf *buffer, const char *string)
{
	const unsigned char *cursor = (const unsigned char *)string;

	if (!buffer || !string || !printbuf_char(buffer, '"'))
		return false;
	while (*cursor) {
		const char *escape = NULL;

		switch (*cursor) {
		case '\\': escape = "\\\\"; break;
		case '"': escape = "\\\""; break;
		case '\b': escape = "\\b"; break;
		case '\f': escape = "\\f"; break;
		case '\n': escape = "\\n"; break;
		case '\r': escape = "\\r"; break;
		case '\t': escape = "\\t"; break;
		default: break;
		}
		if (escape) {
			if (!printbuf_append(buffer, escape, 2))
				return false;
		} else if (*cursor >= 32) {
			if (!printbuf_append(buffer, (const char *)cursor, 1))
				return false;
		}
		cursor++;
	}
	return printbuf_char(buffer, '"');
}

static bool print_value(struct cjson_printbuf *buffer, const cJSON *item,
			unsigned int depth);

static bool print_array(struct cjson_printbuf *buffer, const cJSON *item,
			unsigned int depth)
{
	const cJSON *child;

	if (!printbuf_char(buffer, '['))
		return false;
	for (child = item->child; child; child = child->next) {
		if (!print_value(buffer, child, depth + 1))
			return false;
		if (child->next && !printbuf_append(buffer, ", ", 2))
			return false;
	}
	return printbuf_char(buffer, ']');
}

static bool print_indent(struct cjson_printbuf *buffer, unsigned int depth)
{
	while (depth--)
		if (!printbuf_char(buffer, '\t'))
			return false;
	return true;
}

static bool print_object(struct cjson_printbuf *buffer, const cJSON *item,
			 unsigned int depth)
{
	const cJSON *child;

	if (!printbuf_append(buffer, "{\n", 2))
		return false;
	for (child = item->child; child; child = child->next) {
		if (!child->string || !print_indent(buffer, depth + 1) ||
		    !print_string_ptr(buffer, child->string) ||
		    !printbuf_append(buffer, ":\t", 2) ||
		    !print_value(buffer, child, depth + 1))
			return false;
		if (child->next && !printbuf_char(buffer, ','))
			return false;
		if (!printbuf_char(buffer, '\n'))
			return false;
	}
	return print_indent(buffer, depth) && printbuf_char(buffer, '}');
}

static bool print_number(struct cjson_printbuf *buffer, int number)
{
	char text[16];
	unsigned int value;
	char *cursor = text + sizeof(text);

	*--cursor = '\0';
	value = number < 0 ? 0U - (unsigned int)number : (unsigned int)number;
	do {
		*--cursor = (char)('0' + value % 10U);
		value /= 10U;
	} while (value);
	if (number < 0)
		*--cursor = '-';
	return printbuf_append(buffer, cursor, strlen(cursor));
}

static bool print_value(struct cjson_printbuf *buffer, const cJSON *item,
			unsigned int depth)
{
	if (!buffer || !item || depth > CJSON_PARSE_MAX_DEPTH)
		return false;
	switch (item->type) {
	case cJSON_NULL:
		return printbuf_append(buffer, "null", 4);
	case cJSON_False:
		return printbuf_append(buffer, "false", 5);
	case cJSON_True:
		return printbuf_append(buffer, "true", 4);
	case cJSON_Number:
		return print_number(buffer, item->valueint);
	case cJSON_String:
		return print_string_ptr(buffer, item->valuestring);
	case cJSON_Array:
		return print_array(buffer, item, depth);
	case cJSON_Object:
		return print_object(buffer, item, depth);
	default:
		return false;
	}
}

char *cJSON_Print(cJSON *item)
{
	struct cjson_printbuf buffer = { 0 };

	if (!item || !print_value(&buffer, item, 0)) {
		cJSON_free(buffer.data);
		return NULL;
	}
	return buffer.data;
}

#define static_strlen(string_literal) (sizeof(string_literal) - sizeof(""))

static void skip_oneline_comment(char **input)
{
	*input += static_strlen("//");
	for (; (*input)[0] != '\0'; ++(*input)) {
		if ((*input)[0] == '\n') {
			*input += static_strlen("\n");
			return;
		}
	}
}

static void skip_multiline_comment(char **input)
{
	*input += static_strlen("/*");
	for (; (*input)[0] != '\0'; ++(*input)) {
		if ((*input)[0] == '*' && (*input)[1] == '/') {
			*input += static_strlen("*/");
			return;
		}
	}
}

static void minify_string(char **input, char **output)
{
	(*output)[0] = (*input)[0];
	*input += static_strlen("\"");
	*output += static_strlen("\"");

	for (; (*input)[0] != '\0'; (void)++(*input), ++(*output)) {
		(*output)[0] = (*input)[0];
		if ((*input)[0] == '"') {
			*input += static_strlen("\"");
			*output += static_strlen("\"");
			return;
		} else if ((*input)[0] == '\\' && (*input)[1] == '"') {
			(*output)[1] = (*input)[1];
			*input += static_strlen("\"");
			*output += static_strlen("\"");
		}
	}
}

void cJSON_Minify(char *json)
{
	char *into = json;

	if (!json)
		return;
	while (json[0] != '\0') {
		switch (json[0]) {
		case ' ':
		case '\t':
		case '\r':
		case '\n':
			json++;
			break;
		case '/':
			if (json[1] == '/')
				skip_oneline_comment(&json);
			else if (json[1] == '*')
				skip_multiline_comment(&json);
			else
				json++;
			break;
		case '"':
			minify_string(&json, &into);
			break;
		default:
			*into++ = *json++;
			break;
		}
	}
	*into = '\0';
}

int cJSON_GetArraySize(cJSON *array)
{
	cJSON *child;
	int count = 0;

	if (!array)
		return 0;
	for (child = array->child; child; child = child->next)
		count++;
	return count;
}

cJSON *cJSON_GetArrayItem(cJSON *array, int index)
{
	cJSON *child;

	if (!array || index < 0)
		return NULL;
	child = array->child;
	while (child && index--)
		child = child->next;
	return child;
}

cJSON *cJSON_GetObjectItem(cJSON *object, const char *string)
{
	cJSON *child;

	if (!object || !string)
		return NULL;
	for (child = object->child; child; child = child->next)
		if (child->string && !strcasecmp(child->string, string))
			return child;
	return NULL;
}

static void suffix_object(cJSON *previous, cJSON *item)
{
	previous->next = item;
	item->prev = previous;
}

void cJSON_AddItemToArray(cJSON *array, cJSON *item)
{
	cJSON *child;

	if (!item)
		return;
	if (!array) {
		cJSON_Delete(item);
		return;
	}
	child = array->child;
	if (!child) {
		array->child = item;
		return;
	}
	while (child->next)
		child = child->next;
	suffix_object(child, item);
}

void cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)
{
	char *name;

	if (!object || !string || !item) {
		cJSON_Delete(item);
		return;
	}
	name = cJSON_strdup(string);
	if (!name) {
		cJSON_Delete(item);
		return;
	}
	cJSON_free(item->string);
	item->string = name;
	cJSON_AddItemToArray(object, item);
}

static cJSON *create_typed_item(int type)
{
	cJSON *item = cJSON_New_Item();

	if (item)
		item->type = type;
	return item;
}

cJSON *cJSON_CreateNull(void)
{
	return create_typed_item(cJSON_NULL);
}

cJSON *cJSON_CreateTrue(void)
{
	cJSON *item = create_typed_item(cJSON_True);

	if (item)
		item->valueint = 1;
	return item;
}

cJSON *cJSON_CreateFalse(void)
{
	return create_typed_item(cJSON_False);
}

cJSON *cJSON_CreateNumber(int number)
{
	cJSON *item = create_typed_item(cJSON_Number);

	if (item)
		item->valueint = number;
	return item;
}

cJSON *cJSON_CreateString(const char *string)
{
	cJSON *item;

	if (!string)
		return NULL;
	item = create_typed_item(cJSON_String);
	if (!item)
		return NULL;
	item->valuestring = cJSON_strdup(string);
	if (!item->valuestring) {
		cJSON_Delete(item);
		return NULL;
	}
	return item;
}

cJSON *cJSON_CreateArray(void)
{
	return create_typed_item(cJSON_Array);
}

cJSON *cJSON_CreateObject(void)
{
	return create_typed_item(cJSON_Object);
}

cJSON *cJSON_CreateIntArray(int *numbers, int count)
{
	cJSON *array;
	cJSON *previous = NULL;
	int index;

	if (count < 0 || (count && !numbers))
		return NULL;
	array = cJSON_CreateArray();
	if (!array)
		return NULL;
	for (index = 0; index < count; index++) {
		cJSON *item = cJSON_CreateNumber(numbers[index]);

		if (!item) {
			cJSON_Delete(array);
			return NULL;
		}
		if (!previous)
			array->child = item;
		else
			suffix_object(previous, item);
		previous = item;
	}
	return array;
}

cJSON *cJSON_CreateStringArray(const char **strings, int count)
{
	cJSON *array;
	cJSON *previous = NULL;
	int index;

	if (count < 0 || (count && !strings))
		return NULL;
	array = cJSON_CreateArray();
	if (!array)
		return NULL;
	for (index = 0; index < count; index++) {
		cJSON *item = cJSON_CreateString(strings[index]);

		if (!item) {
			cJSON_Delete(array);
			return NULL;
		}
		if (!previous)
			array->child = item;
		else
			suffix_object(previous, item);
		previous = item;
	}
	return array;
}
