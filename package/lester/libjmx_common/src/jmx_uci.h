// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#ifndef __JMX_UCI_H__
#define __JMX_UCI_H__
#include <uci.h>

#define MAX_PARAM_LIST_LEN 1024

int jmx_uci_get_int_value(struct uci_context *ctx, const char *key);
int jmx_uci_get_value(struct uci_context *ctx, const char *key, char *output, int out_len);
int jmx_uci_add_list(struct uci_context *ctx, const char *key, const char *value);
int jmx_uci_get_list_value(struct uci_context *ctx, const char *key, char *output, int out_len, const char *delimt);
int jmx_uci_add_int_list(struct uci_context *ctx, const char *key, int value);
int jmx_uci_del_list(struct uci_context *ctx, const char *key, const char *value);
int jmx_uci_set_value(struct uci_context *ctx, const char *key, const char *value);
int jmx_uci_set_int_value(struct uci_context *ctx, const char *key, int value);
int jmx_uci_del_array_value(struct uci_context *ctx, const char *key_fmt, int index);
int jmx_uci_set_array_value(struct uci_context *ctx, const char *key_fmt, int index, const char *value);
int jmx_uci_get_list_num(struct uci_context * ctx, const char *package, const char *section);
int jmx_uci_get_array_value(struct uci_context *ctx, const char *key_fmt, int index, char *output, int out_len);
int jmx_uci_add_section(struct uci_context * ctx, const char *package_name, const char *section);
int jmx_uci_commit(struct uci_context *ctx, const char * package);
int jmx_uci_delete(struct uci_context *ctx, const char *key);
#endif
