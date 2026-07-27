// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_VPN_AGGREGATE_H
#define WEBD_VPN_AGGREGATE_H

#include <stdint.h>
#include <json-c/json.h>

struct json_object *webd_vpn_aggregate_data(struct json_object *config,
                                            struct json_object *legacy_runtime);
struct json_object *webd_vpn_aggregate_data_at(struct json_object *config,
                                               struct json_object *legacy_runtime,
                                               const char *sys_class_net,
                                               int64_t observed_at);
struct json_object *webd_vpn_resource_view(struct json_object *snapshot,
                                           const char *resource);

#endif
