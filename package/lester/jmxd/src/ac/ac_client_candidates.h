// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef AC_CLIENT_CANDIDATES_H
#define AC_CLIENT_CANDIDATES_H
#include <stdint.h>
#include <sqlite3.h>
#include <json-c/json.h>

/* Reads existing roaming audit measurements only. All API times are Unix ms;
 * the audit's observed_at and signal_observed_at columns/fields are seconds.
 * Freshness is evaluated at the requested window's end, including for history.
 * The caller owns the returned object. No tables, probes or actions are created. */
struct json_object *ac_client_candidates_query(sqlite3 *db, const char *mac,
    int64_t start_ms, int64_t end_ms, int64_t now_ms);
#endif
