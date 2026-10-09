/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef JMX_SAFEOPS_PORT_SNAPSHOT_H
#define JMX_SAFEOPS_PORT_SNAPSHOT_H

#include <json-c/json.h>
#include <stddef.h>

static inline struct json_object *safeops_port_saved_value(
    struct json_object *config, struct json_object *port, const char *key)
{
    struct json_object *value = NULL;

    if (config && json_object_object_get_ex(config, key, &value) && value)
        return value;
    if (port && json_object_object_get_ex(port, key, &value) && value)
        return value;
    return NULL;
}

/* Missing snapshot fields are not defaults and must not become writes. */
static inline struct json_object *safeops_port_restore_payload(
    struct json_object *changes)
{
    static const char *const keys[] = {
        "profile_id", "native_vlan", "tagged_vlans",
        "configured_speed_mbps", "configured_duplex", "configured_autoneg",
        "sort_order"
    };
    struct json_object *plan = NULL, *port = NULL, *config = NULL;
    struct json_object *payload, *value;
    const char *ifname;
    size_t i;

    if (!changes || !json_object_object_get_ex(changes, "plan", &plan) ||
        !plan || !json_object_object_get_ex(plan, "current_port", &port) ||
        !port || !json_object_is_type(port, json_type_object))
        return NULL;
    json_object_object_get_ex(port, "config", &config);
    value = safeops_port_saved_value(changes, plan, "ifname");
    if (!value || !json_object_is_type(value, json_type_string))
        return NULL;
    ifname = json_object_get_string(value);
    if (!ifname[0])
        return NULL;
    payload = json_object_new_object();
    json_object_object_add(payload, "ifname", json_object_get(value));
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        value = safeops_port_saved_value(config, port, keys[i]);
        if (value)
            json_object_object_add(payload, keys[i], json_object_get(value));
    }
    /* Prefer the saved alias to the generated display label. Empty is valid. */
    value = safeops_port_saved_value(config, NULL, "display_name");
    if (!value)
        value = safeops_port_saved_value(port, NULL, "configured_display_name");
    if (!value)
        value = safeops_port_saved_value(port, NULL, "alias");
    if (!value)
        value = safeops_port_saved_value(port, NULL, "display_name");
    if (value)
        json_object_object_add(payload, "display_name", json_object_get(value));
    return payload;
}

#endif
