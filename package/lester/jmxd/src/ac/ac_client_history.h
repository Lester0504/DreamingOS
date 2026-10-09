// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef AC_CLIENT_HISTORY_H
#define AC_CLIENT_HISTORY_H
#include <stdint.h>
#include <sqlite3.h>
#include <json-c/json.h>

#define AC_CLIENT_HISTORY_RETENTION_MS (7LL * 86400 * 1000)
/* AP telemetry can suppress unchanged 30 s checks until its 300 s refresh.
 * Allow scheduling/transport slack, but never bridge a missing full refresh. */
#define AC_CLIENT_HISTORY_GAP_MS 360000LL
#define AC_CLIENT_HISTORY_LIMIT_MAX 256
int ac_client_history_init(sqlite3 *db);
int ac_client_history_ingest(sqlite3 *db, const char *ap_id,
    const char *epoch, int64_t observed_s, int64_t received_s,
    struct json_object *snapshot);
int ac_client_history_mac_valid(const char *mac);
/* client_health.activity summarizes the full requested retained window, even
 * when history[] is paginated. Only valid byte-counter intervals contribute. */
struct json_object *ac_client_history_query(sqlite3 *db, const char *mac,
    int64_t start_ms, int64_t end_ms, int limit, int64_t after_id,
    int64_t now_ms);
#endif
