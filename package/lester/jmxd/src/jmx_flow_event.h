#ifndef JMX_FLOW_EVENT_H
#define JMX_FLOW_EVENT_H

#include <json-c/json.h>

int jmx_flow_event_collector_start(void);
void jmx_flow_event_collector_stop(void);
struct json_object *jmx_flow_event_status_json(void);

#endif /* JMX_FLOW_EVENT_H */
