#ifndef DREAMINGWRT_WEBD_WIFI_AGGREGATE_H
#define DREAMINGWRT_WEBD_WIFI_AGGREGATE_H

#include <stddef.h>
#include <json-c/json.h>

typedef int (*webd_wifi_model_image_resolver_fn)(
    const char *model, char *image_url, size_t image_url_len,
    char *matched_model, size_t matched_model_len);

/* Returns a newly owned wifi-management data object. */
struct json_object *webd_wifi_aggregate_data(struct json_object *local_response,
                                             struct json_object *ac_response,
                                             int runtime_status);

struct json_object *webd_wifi_aggregate_data_with_resolver(
    struct json_object *local_response, struct json_object *ac_response,
    int runtime_status, webd_wifi_model_image_resolver_fn image_resolver);

void webd_wifi_merge_environment_scan(struct json_object *data,
                                      struct json_object *ac_results,
                                      struct json_object *ac_capabilities);

void webd_wifi_merge_station_events_capability(
    struct json_object *data, struct json_object *ac_capabilities);
void webd_wifi_merge_survey_history(struct json_object *data,
                                    struct json_object *response);

/*
 * Joins client identity (display name, fingerprint model, image) onto
 * data.stations[] by MAC, using the /api/v1/clients inventory as the authority.
 * clients_response is the raw jmx response for the "clients" ubus method; when
 * it is missing or carries no usable rows, every station gets
 * identity_available=false plus identity_reason instead of placeholder values.
 */
void webd_wifi_merge_station_identity(struct json_object *data,
                                      struct json_object *clients_response);

/* True when AC status/list data contains at least one managed AP. */
int webd_wifi_managed_available(struct json_object *ac_response);

#endif
