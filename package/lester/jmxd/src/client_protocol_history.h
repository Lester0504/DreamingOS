#ifndef DREAMINGWRT_CLIENT_PROTOCOL_HISTORY_H
#define DREAMINGWRT_CLIENT_PROTOCOL_HISTORY_H

#include <stdint.h>

struct json_object;

#define JMX_CLIENT_PROTOCOL_HISTORY_WINDOW_SEC 300
#define JMX_CLIENT_PROTOCOL_HISTORY_LOOKBACK_SEC 420
#define JMX_CLIENT_PROTOCOL_HISTORY_MAX_INTERVAL_SEC 120
#define JMX_CLIENT_PROTOCOL_HISTORY_MAX_POINTS 72
#define JMX_CLIENT_PROTOCOL_HISTORY_MAX_SERIES 32
#define JMX_CLIENT_PROTOCOL_HISTORY_MAX_SERIES_PER_POINT \
    (JMX_CLIENT_PROTOCOL_HISTORY_MAX_SERIES + 1)

int jmx_client_protocol_history_sample_tick(int64_t now, int64_t monotonic_ms);

/* Deterministic producer entry point used by the runtime fixture. */
int jmx_client_protocol_history_sample_snapshot(const char *snapshot,
                                                uint64_t source_generation,
                                                int64_t now,
                                                int64_t monotonic_ms);

void jmx_client_protocol_history_reset(void);

struct json_object *jmx_client_protocol_history_query(const char *db_path,
                                                      const char *mac,
                                                      int64_t now,
                                                      int window_sec);

#endif
