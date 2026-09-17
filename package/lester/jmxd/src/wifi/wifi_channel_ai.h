#ifndef DREAMINGWRT_WIFI_CHANNEL_AI_H
#define DREAMINGWRT_WIFI_CHANNEL_AI_H

#include <stdint.h>

#include <json-c/json.h>

/* Build a read-only Channel AI plan from an already collected Wi-Fi snapshot.
 * The planner never runs scans and never writes configuration. */
struct json_object *wifi_channel_ai_plan_json(struct json_object *wifi_data,
                                              int64_t now_s);

/* Return the capability/status projection used by API callers. */
struct json_object *wifi_channel_ai_status_json(struct json_object *wifi_data,
                                                int64_t now_s);

/* Channel-plan writes remain fail-closed until the AC/APD transaction gate is
 * explicitly opened. */
struct json_object *wifi_channel_ai_apply_disabled_json(const char *plan_id,
                                                        const char *reason);

#endif
