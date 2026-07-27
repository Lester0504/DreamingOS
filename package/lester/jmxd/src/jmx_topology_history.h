#ifndef JMX_TOPOLOGY_HISTORY_H
#define JMX_TOPOLOGY_HISTORY_H

#include <stdint.h>
#include <json-c/json.h>

int jmx_topology_history_capture(struct json_object *snapshot, int force_anchor,
                                 struct json_object **result_out);
struct json_object *jmx_topology_history_timeline(int64_t start_ms, int64_t end_ms);
struct json_object *jmx_topology_history_timestamps(int64_t start_ms, int64_t end_ms);
struct json_object *jmx_topology_history_at(int64_t timestamp_ms);
struct json_object *jmx_topology_history_status(void);
void jmx_topology_history_close(void);

#endif /* JMX_TOPOLOGY_HISTORY_H */
