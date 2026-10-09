// SPDX-License-Identifier: GPL-2.0-or-later
#include <time.h>

#include <json-c/json.h>

#include "jmx_app_perms.h"
#include "jmx_wifi_contract.h"

static int capability_true(struct json_object *capabilities, const char *name)
{
    struct json_object *value = NULL;

    return capabilities &&
        json_object_object_get_ex(capabilities, name, &value) &&
        value && json_object_is_type(value, json_type_boolean) &&
        json_object_get_boolean(value);
}

static void add_capability(struct json_object *caps,
                           struct json_object *reasons,
                           struct json_object *source,
                           const char *name,
                           const char *fallback_reason)
{
    struct json_object *source_reasons = NULL;
    struct json_object *reason = NULL;
    int supported = capability_true(source, name);

    if (source)
        json_object_object_get_ex(source, "reasons", &source_reasons);
    if (source_reasons)
        json_object_object_get_ex(source_reasons, name, &reason);

    json_object_object_add(caps, name, json_object_new_boolean(supported));
    json_object_object_add(reasons, name, reason ? json_object_get(reason) :
        json_object_new_string(supported ? "available" : fallback_reason));
}

static struct json_object *build_wifi_capabilities(struct json_object *data)
{
    struct json_object *caps = json_object_new_object();
    struct json_object *reasons = json_object_new_object();
    struct json_object *source = NULL;

    if (data)
        json_object_object_get_ex(data, "capabilities", &source);
    add_capability(caps, reasons, source, "read_config",
                   "wifi_config_source_unavailable");
    add_capability(caps, reasons, source, "save_config",
                   "wifi_save_capability_unavailable");
    add_capability(caps, reasons, source, "apply_config",
                   "wifi_apply_capability_unavailable");
    add_capability(caps, reasons, source, "roaming_write",
                   "roaming_write_capability_not_reported");
    add_capability(caps, reasons, source, "band_steering",
                   "band_steering_capability_not_reported");
    add_capability(caps, reasons, source, "mesh",
                   "mesh_capability_not_reported");
    json_object_object_add(caps, "reasons", reasons);

    return caps;
}

static struct json_object *build_wifi_permissions(jmx_role_t role)
{
    struct json_object *perms = json_object_new_object();

    json_object_object_add(perms, "wifi:read", json_object_new_boolean(
        jmx_perm_check(role, JMX_RISK_LOW)));
    json_object_object_add(perms, "wifi:write", json_object_new_boolean(
        jmx_perm_check(role, JMX_RISK_MEDIUM)));
    return perms;
}

struct json_object *wifi_contract_read(struct json_object *wifi_data,
                                       const char *role_name)
{
    struct json_object *envelope = json_object_new_object();
    struct json_object *meta = json_object_new_object();
    struct json_object *source_caps = NULL;
    struct json_object *revision = NULL;

    json_object_object_add(envelope, "contract",
                           json_object_new_string("product-plane.v1"));
    json_object_object_add(envelope, "resource",
                           json_object_new_string("wifi.config"));
    json_object_object_add(envelope, "ok", json_object_new_boolean(1));
    json_object_object_add(envelope, "data", wifi_data ?
                           json_object_get(wifi_data) :
                           json_object_new_object());
    json_object_object_add(meta, "source",
                           json_object_new_string("config.db:wireless"));
    json_object_object_add(meta, "observed_at",
                           json_object_new_int64((int64_t)time(NULL)));
    json_object_object_add(meta, "stale", json_object_new_boolean(0));
    if (wifi_data &&
        json_object_object_get_ex(wifi_data, "capabilities", &source_caps) &&
        source_caps &&
        json_object_object_get_ex(source_caps, "wifi_desired_revision",
                                  &revision) && revision)
        json_object_object_add(meta, "revision", json_object_get(revision));
    json_object_object_add(envelope, "meta", meta);
    json_object_object_add(envelope, "capabilities",
                           build_wifi_capabilities(wifi_data));
    json_object_object_add(envelope, "permissions",
                           build_wifi_permissions(jmx_perm_parse_role(role_name)));
    return envelope;
}
