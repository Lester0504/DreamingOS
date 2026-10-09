// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Private contract between the legacy core in jmx_app_api.c and the split
 * client-control module. It reaches <sqlite3.h>, which is why it is not in
 * api_client_control.h: that header is included by api_router.c, and the
 * matcher fixture compiles the router without sqlite3 present.
 *
 * The runtime-DB globals are owned and defined by jmx_app_api.c; the module
 * only reads g_config_db and drives app_db_open_runtime(), exactly as the
 * closure did before it moved.
 */
#ifndef WEBD_API_CLIENT_CONTROL_INTERNAL_H
#define WEBD_API_CLIENT_CONTROL_INTERNAL_H

#include <stddef.h>
#include <sqlite3.h>

extern sqlite3 *g_config_db;
int app_db_open_runtime(void);
sqlite3_stmt *config_prepare(const char *sql);
int gen_random_hex_checked(char *out, int len);
int webd_normalize_mac_text(const char *in, char *out, size_t out_len);

#endif
