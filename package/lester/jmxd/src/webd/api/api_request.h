// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_REQUEST_H
#define WEBD_API_REQUEST_H

#include <stddef.h>

int webd_hex_value(char c);
void webd_query_decode(const char *src, size_t src_len,
                       char *out, size_t out_len);
int webd_query_get(const char *query, const char *key,
                   char *out, size_t out_len);

#endif /* WEBD_API_REQUEST_H */
