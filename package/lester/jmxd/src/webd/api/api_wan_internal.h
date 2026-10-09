// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_WAN_INTERNAL_H
#define WEBD_API_WAN_INTERNAL_H

#include <stdint.h>

/*
 * Borrowed from jmx_app_api.c. webd_put_int and webd_ws_semantic_hash are
 * de-static'd there (their definitions stay in main with their other callers);
 * the WAN BFF response builders in api_wan.c reuse the single implementation of
 * each. gen_random_hex_checked is already extern in main (used def-before-use, so
 * main needs no header) — the WAN TU is a separate compilation unit and needs the
 * prototype.
 */
struct json_object;

void webd_put_int(struct json_object *obj, const char *key, int value);
uint64_t webd_ws_semantic_hash(uint64_t hash, struct json_object *value);
int gen_random_hex_checked(char *out, int len);

#endif /* WEBD_API_WAN_INTERNAL_H */
