// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DWRT_AD_ANALYZER_H
#define DWRT_AD_ANALYZER_H
#include <json-c/json.h>
#include <stdint.h>

struct ada_environment {
    const char *database;
    const char *dns_log;
    const char *leases;
    int64_t now;
    struct json_object *(*provider)(void *context, const char *operation, struct json_object *request);
    void *provider_context;
    const char *conntrack;
    const char *flow_database;
};
struct json_object *ada_handle(const struct ada_environment *env, const char *operator_id,
                               int operate, const char *method, const char *path,
                               struct json_object *query, struct json_object *body, int *status);
/* Called by the webd service timer, never by a read request. */
int ada_tick(const struct ada_environment *env, int service_start);
#endif
