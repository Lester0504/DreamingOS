// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __JMX_METRICS_STORE_H__
#define __JMX_METRICS_STORE_H__

#include <json-c/json.h>
#include <stdint.h>
#include <sqlite3.h>

#define JMX_METRICS_DB_PATH_DEFAULT "/etc/dreamingwrt/metrics.db"

struct jmx_metrics_usage {
    int64_t up_bytes;
    int64_t down_bytes;
    int64_t total_bytes;
    int64_t period_start;
    int64_t period_end;
    int sample_count;
    double completeness_ratio;
    int estimated;
    int counter_reset;
    char source[32];
    char gap_reason[64];
};

int jmx_metrics_store_init(void);
void jmx_metrics_store_close(void);
void jmx_metrics_store_set_legacy_db(sqlite3 *db);
void jmx_metrics_record_sample(const char *wan_id, int64_t up_rate,
                               int64_t down_rate, int connections,
                               double latency_avg, double latency_min,
                               double latency_max);
void jmx_metrics_counter_observe(const char *wan_id, uint64_t rx_bytes,
                                 uint64_t tx_bytes, int online);
int jmx_metrics_usage_query(const char *wan_id, int64_t start, int64_t end,
                            struct jmx_metrics_usage *out);
struct json_object *jmx_metrics_activity_api(struct json_object *req);
int jmx_metrics_store_maintenance(void);

#endif
