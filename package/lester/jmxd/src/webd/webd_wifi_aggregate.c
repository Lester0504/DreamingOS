#include "webd_wifi_aggregate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

enum webd_wifi_resource_kind {
    WEBD_WIFI_RADIO,
    WEBD_WIFI_SSID,
    WEBD_WIFI_STATION,
};

static struct json_object *wifi_child(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;

    if (!obj || !key || !json_object_is_type(obj, json_type_object) ||
        !json_object_object_get_ex(obj, key, &value) || !value)
        return NULL;
    return value;
}

static struct json_object *wifi_child_object(struct json_object *obj,
                                              const char *key)
{
    struct json_object *value = wifi_child(obj, key);

    return value && json_object_is_type(value, json_type_object) ? value : NULL;
}

static struct json_object *wifi_child_array(struct json_object *obj,
                                             const char *key)
{
    struct json_object *value = wifi_child(obj, key);

    return value && json_object_is_type(value, json_type_array) ? value : NULL;
}

static const char *wifi_string(struct json_object *obj, const char *key,
                               const char *fallback)
{
    struct json_object *value = wifi_child(obj, key);
    const char *text;

    if (!value || !json_object_is_type(value, json_type_string))
        return fallback;
    text = json_object_get_string(value);
    return text ? text : fallback;
}

static int wifi_bool(struct json_object *obj, const char *key, int fallback)
{
    struct json_object *value = wifi_child(obj, key);

    if (!value || (!json_object_is_type(value, json_type_boolean) &&
                   !json_object_is_type(value, json_type_int)))
        return fallback;
    return json_object_get_boolean(value);
}

static int64_t wifi_int64(struct json_object *obj, const char *key,
                          int64_t fallback)
{
    struct json_object *value = wifi_child(obj, key);

    if (!value || (!json_object_is_type(value, json_type_int) &&
                   !json_object_is_type(value, json_type_double)))
        return fallback;
    return json_object_get_int64(value);
}

static int wifi_number(struct json_object *obj, const char *key, double *out)
{
    struct json_object *value = wifi_child(obj, key);

    if (!value || (!json_object_is_type(value, json_type_int) &&
                   !json_object_is_type(value, json_type_double)))
        return 0;
    if (out)
        *out = json_object_get_double(value);
    return 1;
}

static struct json_object *wifi_clone(struct json_object *value)
{
    const char *serialized;

    if (!value)
        return NULL;
    serialized = json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN);
    return serialized ? json_tokener_parse(serialized) : NULL;
}

static int wifi_response_available(struct json_object *response)
{
    struct json_object *value = NULL;

    if (!response || !json_object_is_type(response, json_type_object))
        return 0;
    if (json_object_object_get_ex(response, "code", &value) && value &&
        json_object_get_int(value) != 2000)
        return 0;
    if (json_object_object_get_ex(response, "ok", &value) && value &&
        !json_object_get_boolean(value))
        return 0;
    value = wifi_child_object(response, "data");
    if (value && wifi_child(value, "ok") && !wifi_bool(value, "ok", 0))
        return 0;
    return 1;
}

static struct json_object *wifi_response_data_clone(struct json_object *response)
{
    struct json_object *data = wifi_child_object(response, "data");

    if (!wifi_response_available(response))
        return json_object_new_object();
    if (!data && response && json_object_is_type(response, json_type_object))
        data = response;
    data = wifi_clone(data);
    return data && json_object_is_type(data, json_type_object) ? data :
           json_object_new_object();
}

int webd_wifi_managed_available(struct json_object *ac_response)
{
    struct json_object *root;
    struct json_object *managed;
    struct json_object *items;

    if (!wifi_response_available(ac_response))
        return 0;
    root = wifi_child_object(ac_response, "data");
    if (!root)
        root = ac_response;
    managed = wifi_child_object(root, "managed_aps");
    if (managed && (wifi_bool(managed, "available", 0) ||
                    wifi_int64(managed, "count", 0) > 0 ||
                    wifi_int64(managed, "online", 0) > 0))
        return 1;
    items = wifi_child_array(root, "items");
    return items && json_object_array_length(items) > 0;
}

static struct json_object *wifi_ensure_object(struct json_object *parent,
                                               const char *key)
{
    struct json_object *value = wifi_child_object(parent, key);

    if (value)
        return value;
    value = json_object_new_object();
    json_object_object_del(parent, key);
    json_object_object_add(parent, key, value);
    return value;
}

static struct json_object *wifi_ensure_array(struct json_object *parent,
                                              const char *key)
{
    struct json_object *value = wifi_child_array(parent, key);

    if (value)
        return value;
    value = json_object_new_array();
    json_object_object_del(parent, key);
    json_object_object_add(parent, key, value);
    return value;
}

static const char *wifi_kind_name(enum webd_wifi_resource_kind kind)
{
    switch (kind) {
    case WEBD_WIFI_RADIO: return "radio";
    case WEBD_WIFI_SSID: return "ssid";
    case WEBD_WIFI_STATION: return "station";
    }
    return "resource";
}

static const char *wifi_resource_local_id(struct json_object *resource,
                                          enum webd_wifi_resource_kind kind,
                                          char *fallback,
                                          size_t fallback_len,
                                          size_t index)
{
    const char *id = wifi_string(resource, "local_id", "");

    if (!id[0]) id = wifi_string(resource, "id", "");
    if (!id[0] && kind == WEBD_WIFI_RADIO)
        id = wifi_string(resource, "phy", wifi_string(resource, "device", ""));
    if (!id[0] && kind == WEBD_WIFI_SSID)
        id = wifi_string(resource, "interface", wifi_string(resource, "section", ""));
    if (!id[0] && kind == WEBD_WIFI_STATION) {
        const char *mac = wifi_string(resource, "mac",
                          wifi_string(resource, "client_mac", ""));
        const char *interface = wifi_string(resource, "interface",
                                wifi_string(resource, "bss", ""));

        if (mac[0] && interface[0]) {
            snprintf(fallback, fallback_len, "%s@%s", mac, interface);
            return fallback;
        }
        id = mac;
    }
    if (id[0])
        return id;
    snprintf(fallback, fallback_len, "unidentified-%zu", index);
    return fallback;
}

static void wifi_replace_string(struct json_object *obj, const char *key,
                                const char *value)
{
    json_object_object_del(obj, key);
    json_object_object_add(obj, key, json_object_new_string(value ? value : ""));
}

static void wifi_replace_bool(struct json_object *obj, const char *key, int value)
{
    json_object_object_del(obj, key);
    json_object_object_add(obj, key, json_object_new_boolean(value));
}

static void wifi_replace_null(struct json_object *obj, const char *key)
{
    json_object_object_del(obj, key);
    json_object_object_add(obj, key, json_object_new_null());
}

static void wifi_namespace_reference(struct json_object *resource,
                                     const char *key, const char *scope,
                                     const char *ap_id, const char *kind)
{
    const char *raw = wifi_string(resource, key, "");
    char id[512];

    if (!raw[0] || !strncmp(raw, "local:", 6) || !strncmp(raw, "ap:", 3))
        return;
    if (!strcmp(scope, "local"))
        snprintf(id, sizeof(id), "local:%s:%s", kind, raw);
    else
        snprintf(id, sizeof(id), "ap:%s:%s:%s", ap_id, kind, raw);
    wifi_replace_string(resource, key, id);
}

static void wifi_normalize_aliases(struct json_object *resource,
                                   enum webd_wifi_resource_kind kind)
{
    const char *value;
    struct json_object *bands;

    if (kind == WEBD_WIFI_RADIO) {
        if (!wifi_child(resource, "width") && wifi_child(resource, "width_mhz"))
            json_object_object_add(resource, "width",
                                   json_object_get(wifi_child(resource, "width_mhz")));
        if (!wifi_child(resource, "tx_power") && wifi_child(resource, "txpower_dbm"))
            json_object_object_add(resource, "tx_power",
                                   json_object_get(wifi_child(resource, "txpower_dbm")));
        return;
    }
    if (kind == WEBD_WIFI_SSID) {
        value = wifi_string(resource, "name", "");
        if (!value[0])
            value = wifi_string(resource, "ssid",
                    wifi_string(resource, "essid",
                    wifi_string(resource, "broadcast_name", "")));
        if (value[0]) {
            if (!wifi_child(resource, "name"))
                json_object_object_add(resource, "name", json_object_new_string(value));
            if (!wifi_child(resource, "ssid"))
                json_object_object_add(resource, "ssid", json_object_new_string(value));
        }
        if (!wifi_child(resource, "encryption") &&
            wifi_string(resource, "security_mode", "")[0])
            json_object_object_add(resource, "encryption", json_object_new_string(
                wifi_string(resource, "security_mode", "")));
        if (!wifi_child(resource, "bands") &&
            wifi_string(resource, "band", "")[0]) {
            bands = json_object_new_array();
            json_object_array_add(bands, json_object_new_string(
                                  wifi_string(resource, "band", "")));
            json_object_object_add(resource, "bands", bands);
        }
    }
}

static void wifi_decorate_resource(struct json_object *resource,
                                   enum webd_wifi_resource_kind kind,
                                   const char *scope, const char *ap_id,
                                   const char *ap_name, const char *model,
                                   int online, int stale, int runtime_status,
                                   size_t index)
{
    const char *local_id;
    char fallback[64];
    char id[768];
    int configured_enabled = wifi_bool(resource, "enabled", 1);

    local_id = wifi_resource_local_id(resource, kind, fallback,
                                      sizeof(fallback), index);
    if (!strcmp(scope, "local"))
        snprintf(id, sizeof(id), "local:%s:%s", wifi_kind_name(kind), local_id);
    else
        snprintf(id, sizeof(id), "ap:%s:%s:%s", ap_id,
                 wifi_kind_name(kind), local_id);
    wifi_replace_string(resource, "local_id", local_id);
    wifi_replace_string(resource, "id", id);
    wifi_replace_string(resource, "source",
                        !strcmp(scope, "local") ? "local" : "managed_ap");
    wifi_replace_string(resource, "scope",
                        !strcmp(scope, "local") ? "controller_local" : "remote");
    wifi_replace_bool(resource, "online", online);
    wifi_replace_bool(resource, "stale", stale);
    wifi_replace_bool(resource, "configured_enabled", configured_enabled);
    if (runtime_status && (!online || stale))
        wifi_replace_bool(resource, "enabled", 0);
    if (strcmp(scope, "local")) {
        wifi_replace_string(resource, "ap_id", ap_id);
        wifi_replace_string(resource, "ap_name", ap_name);
        wifi_replace_string(resource, "ap", ap_name);
        if (model && model[0])
            wifi_replace_string(resource, "model", model);
        wifi_namespace_reference(resource, "radio_id", scope, ap_id, "radio");
        wifi_namespace_reference(resource, "ssid_id", scope, ap_id, "ssid");
    } else {
        wifi_replace_string(resource, "ap_id", "local");
        wifi_replace_string(resource, "ap_name", "Local Gateway");
        wifi_replace_string(resource, "ap", "Local Gateway");
        wifi_namespace_reference(resource, "radio_id", scope, "", "radio");
        wifi_namespace_reference(resource, "ssid_id", scope, "", "ssid");
    }
    wifi_normalize_aliases(resource, kind);
}

static void wifi_namespace_array(struct json_object *array,
                                 enum webd_wifi_resource_kind kind,
                                 int runtime_status)
{
    size_t i;

    if (!array)
        return;
    for (i = 0; i < json_object_array_length(array); i++) {
        struct json_object *resource = json_object_array_get_idx(array, i);

        if (resource && json_object_is_type(resource, json_type_object))
            wifi_decorate_resource(resource, kind, "local", "local",
                                   "Local Gateway", "", 1, 0,
                                   runtime_status, i);
    }
}

static struct json_object *wifi_ac_items(struct json_object *response,
                                         int *available)
{
    struct json_object *data;
    struct json_object *items;

    *available = wifi_response_available(response);
    if (!*available)
        return NULL;
    data = wifi_child_object(response, "data");
    if (!data)
        data = response;
    items = wifi_child_array(data, "items");
    if (!items)
        items = wifi_child_array(data, "aps");
    return items;
}

static const char *wifi_ap_model(struct json_object *ap,
                                 struct json_object *snapshot)
{
    struct json_object *identity = wifi_child_object(snapshot, "identity");
    const char *model = wifi_string(ap, "model", "");

    if (!model[0]) model = wifi_string(ap, "reported_model", "");
    if (!model[0]) model = wifi_string(ap, "hardware_model", "");
    if (!model[0]) model = wifi_string(identity, "model", "");
    return model;
}

static const char *wifi_first_nonempty(const char *a, const char *b,
                                       const char *c)
{
    if (a && a[0]) return a;
    if (b && b[0]) return b;
    return c ? c : "";
}

static int wifi_contains_nocase(const char *text, const char *needle)
{
    size_t needle_len;

    if (!text || !needle || !needle[0])
        return 0;
    needle_len = strlen(needle);
    for (; *text; text++) {
        if (!strncasecmp(text, needle, needle_len))
            return 1;
    }
    return 0;
}

static void wifi_normalize_model(const char *model, char *out, size_t out_len)
{
    size_t length;
    char *suffix;

    if (!out || out_len == 0)
        return;
    snprintf(out, out_len, "%s", model ? model : "");
    length = strlen(out);
    while (length > 0 && (out[length - 1] == ' ' || out[length - 1] == '\t'))
        out[--length] = '\0';
    suffix = strrchr(out, '(');
    if (suffix && suffix > out && suffix[-1] == ' ' &&
        (wifi_contains_nocase(suffix, "wi-fi") ||
         wifi_contains_nocase(suffix, "wifi"))) {
        suffix[-1] = '\0';
        length = strlen(out);
        while (length > 0 && (out[length - 1] == ' ' || out[length - 1] == '\t'))
            out[--length] = '\0';
    }
}

static int wifi_resolve_model_image(webd_wifi_model_image_resolver_fn resolver,
                                    const char *model, char *image_url,
                                    size_t image_url_len, char *matched_model,
                                    size_t matched_model_len)
{
    char normalized[256];

    if (image_url && image_url_len)
        image_url[0] = '\0';
    if (matched_model && matched_model_len)
        matched_model[0] = '\0';
    if (!resolver || !model || !model[0])
        return 0;
    if (resolver(model, image_url, image_url_len,
                 matched_model, matched_model_len) == 0 && image_url[0])
        return 1;
    wifi_normalize_model(model, normalized, sizeof(normalized));
    if (!normalized[0] || !strcmp(normalized, model))
        return 0;
    if (image_url && image_url_len)
        image_url[0] = '\0';
    if (matched_model && matched_model_len)
        matched_model[0] = '\0';
    return resolver(normalized, image_url, image_url_len,
                    matched_model, matched_model_len) == 0 && image_url[0];
}

static void wifi_append_remote(struct json_object *target,
                               struct json_object *source,
                               enum webd_wifi_resource_kind kind,
                               const char *ap_id, const char *ap_name,
                               const char *model, const char *image_url,
                               const char *image_model_match,
                               int online, int stale,
                               int runtime_status, int runtime_source)
{
    size_t i;

    if (!target || !source)
        return;
    for (i = 0; i < json_object_array_length(source); i++) {
        struct json_object *item = wifi_clone(json_object_array_get_idx(source, i));
        const char *band;

        if (!item || !json_object_is_type(item, json_type_object)) {
            if (item) json_object_put(item);
            continue;
        }
        /* QSDK exposes an MLD pseudo-PHY without a channel or frequency. */
        band = wifi_string(item, "band", "");
        if (runtime_source && kind == WEBD_WIFI_RADIO &&
            (!band[0] || !strcmp(band, "unknown")) &&
            !wifi_child(item, "channel") && !wifi_child(item, "frequency_mhz")) {
            json_object_put(item);
            continue;
        }
        wifi_decorate_resource(item, kind, "remote", ap_id, ap_name,
                               model, online, stale, runtime_status, i);
        wifi_replace_string(item, "image_url", image_url);
        wifi_replace_bool(item, "image_available", image_url && image_url[0]);
        wifi_replace_string(item, "image_source",
                            image_url && image_url[0] ?
                            "fingerprint_model_catalog" : "unavailable");
        wifi_replace_string(item, "image_model_match", image_model_match);
        if (!image_url || !image_url[0])
            wifi_replace_string(item, "image_reason", "fingerprint_model_not_found");
        wifi_replace_string(item, "configuration_source",
                            runtime_source ? "runtime_observed_read_only" :
                                             "apd_desired_read_only");
        json_object_array_add(target, item);
    }
}

static int wifi_array_has_band(struct json_object *bands, const char *band)
{
    size_t i;

    for (i = 0; bands && i < json_object_array_length(bands); i++) {
        const char *existing = json_object_get_string(
            json_object_array_get_idx(bands, i));
        if (existing && !strcmp(existing, band))
            return 1;
    }
    return 0;
}

static const char *wifi_normalized_band(const char *raw)
{
    if (!raw) return "";
    if (!strcasecmp(raw, "2g") || !strcasecmp(raw, "2.4g") ||
        !strcasecmp(raw, "2.4GHz")) return "2g";
    if (!strcasecmp(raw, "5g") || !strcasecmp(raw, "5GHz")) return "5g";
    if (!strcasecmp(raw, "6g") || !strcasecmp(raw, "6GHz")) return "6g";
    return raw;
}

static struct json_object *wifi_collect_bands(struct json_object *radios)
{
    struct json_object *bands = json_object_new_array();
    size_t i;

    for (i = 0; radios && i < json_object_array_length(radios); i++) {
        struct json_object *radio = json_object_array_get_idx(radios, i);
        const char *band = wifi_normalized_band(wifi_string(radio, "band", ""));

        if (band[0] && strcmp(band, "unknown") &&
            !wifi_array_has_band(bands, band))
            json_object_array_add(bands, json_object_new_string(band));
    }
    return bands;
}

static struct json_object *wifi_ap_summary(struct json_object *ap,
                                           struct json_object *runtime,
                                           struct json_object *snapshot,
                                           const char *ap_id,
                                           const char *ap_name,
                                           const char *model,
                                           const char *image_url,
                                           const char *image_model_match,
                                           int online, int stale)
{
    struct json_object *summary = json_object_new_object();

    json_object_object_add(summary, "ap_id", json_object_new_string(ap_id));
    json_object_object_add(summary, "name", json_object_new_string(ap_name));
    json_object_object_add(summary, "display_name", json_object_new_string(ap_name));
    json_object_object_add(summary, "configured_name", json_object_new_string(
        wifi_string(ap, "name", wifi_string(ap, "ap_name", ""))));
    json_object_object_add(summary, "name_available", json_object_new_boolean(
        wifi_string(ap, "name", wifi_string(ap, "ap_name", ""))[0] != '\0'));
    json_object_object_add(summary, "name_source", json_object_new_string(
        wifi_string(ap, "name", wifi_string(ap, "ap_name", ""))[0] ?
        "ac_inventory" : (model[0] ? "model_fallback" : "ap_id_fallback")));
    json_object_object_add(summary, "model", json_object_new_string(model));
    json_object_object_add(summary, "reported_model", json_object_new_string(
        wifi_string(ap, "reported_model", model)));
    json_object_object_add(summary, "model_override", json_object_new_string(
        wifi_string(ap, "model_override", "")));
    json_object_object_add(summary, "model_available",
                           json_object_new_boolean(model[0] != '\0'));
    json_object_object_add(summary, "model_source", json_object_new_string(
        wifi_string(ap, "model_source", model[0] ? "apd_reported" : "unavailable")));
    json_object_object_add(summary, "image_url",
                           json_object_new_string(image_url ? image_url : ""));
    json_object_object_add(summary, "image_available",
                           json_object_new_boolean(image_url && image_url[0]));
    json_object_object_add(summary, "image_source", json_object_new_string(
        image_url && image_url[0] ? "fingerprint_model_catalog" : "unavailable"));
    json_object_object_add(summary, "image_model_match",
                           json_object_new_string(image_model_match ?
                                                  image_model_match : ""));
    if (!image_url || !image_url[0])
        json_object_object_add(summary, "image_reason",
                               json_object_new_string("fingerprint_model_not_found"));
    json_object_object_add(summary, "online", json_object_new_boolean(online));
    json_object_object_add(summary, "stale", json_object_new_boolean(stale));
    json_object_object_add(summary, "adoption_state", json_object_new_string(
        wifi_string(ap, "adoption_state", wifi_string(ap, "state", ""))));
    json_object_object_add(summary, "control_protocol", json_object_new_string(
        wifi_string(ap, "control_protocol", "")));
    json_object_object_add(summary, "control_protocol_version",
                           json_object_new_int64(
                               wifi_int64(ap, "control_protocol_version", 0)));
    json_object_object_add(summary, "session_connected",
                           json_object_new_boolean(
                               wifi_bool(ap, "session_connected", 0)));
    json_object_object_add(summary, "scan_execution",
                           json_object_new_boolean(
                               wifi_bool(ap, "scan_execution", 0)));
    json_object_object_add(summary, "last_seen_at", json_object_new_int64(
        wifi_int64(ap, "last_seen_at", 0)));
    json_object_object_add(summary, "observed_at", json_object_new_int64(
        wifi_int64(snapshot, "observed_at", wifi_int64(runtime, "observed_at", 0))));
    json_object_object_add(summary, "runtime_available", json_object_new_boolean(
        runtime && snapshot && wifi_bool(runtime, "available", 1)));
    json_object_object_add(summary, "runtime_complete", json_object_new_boolean(
        snapshot && wifi_bool(snapshot, "complete", wifi_bool(runtime, "complete", 0))));
    json_object_object_add(summary, "runtime_reason", json_object_new_string(
        wifi_string(snapshot, "reason", wifi_string(runtime, "reason", ""))));
    json_object_object_add(summary, "uplink_type", json_object_new_null());
    json_object_object_add(summary, "uplink_type_reason",
                           json_object_new_string("ap_uplink_not_reported"));
    /* UniFi AP-details facts from the APD read-only system section.  A
     * field is copied only when the APD produced evidence; everything
     * else stays null with the APD reason (or a clear "not reported"
     * reason for pre-system-facts APD builds).  No placeholder values. */
    {
        static const struct {
            const char *key;
            const char *reason_key;
        } facts_map[] = {
            { "ip", "ip_reason" },
            { "mac", "mac_reason" },
            { "firmware_version", "firmware_reason" },
            { "uptime_seconds", "uptime_reason" },
        };
        struct json_object *facts = snapshot ?
            wifi_child_object(snapshot, "system") : NULL;
        size_t fact;

        for (fact = 0; fact < sizeof(facts_map) / sizeof(facts_map[0]);
             fact++) {
            struct json_object *value = facts ?
                wifi_child(facts, facts_map[fact].key) : NULL;

            if (value && !json_object_is_type(value, json_type_null)) {
                json_object_object_add(summary, facts_map[fact].key,
                                       json_object_get(value));
            } else {
                const char *reason = facts ?
                    wifi_string(facts, facts_map[fact].reason_key,
                                "ap_system_facts_not_reported") :
                    "ap_system_facts_not_reported";

                json_object_object_add(summary, facts_map[fact].key,
                                       json_object_new_null());
                json_object_object_add(summary,
                                       facts_map[fact].reason_key,
                                       json_object_new_string(reason));
            }
        }
        if (facts) {
            struct json_object *revision = wifi_child(facts,
                                                      "firmware_revision");

            if (revision && !json_object_is_type(revision, json_type_null))
                json_object_object_add(summary, "firmware_revision",
                                       json_object_get(revision));
        }
    }
    return summary;
}

static int wifi_station_source_state(struct json_object *snapshot,
                                     int *inventory, int *metrics,
                                     const char **inventory_reason,
                                     const char **metrics_reason)
{
    struct json_object *sources = wifi_child_object(snapshot, "sources");
    struct json_object *hostapd = wifi_child_object(sources, "hostapd");
    const char *reason = "station_source_not_reported";
    int complete;

    if (inventory) *inventory = 0;
    if (metrics) *metrics = 0;
    if (inventory_reason) *inventory_reason = reason;
    if (metrics_reason) *metrics_reason = reason;
    if (!snapshot || !hostapd)
        return 0;
    reason = wifi_string(hostapd, "reason", "station_source_unavailable");
    if (inventory_reason) *inventory_reason = reason;
    if (metrics_reason) *metrics_reason = reason;
    if (!wifi_bool(hostapd, "available", 0))
        return 0;
    complete = wifi_bool(hostapd, "complete", 0);
    if (!complete) {
        if (!reason[0] || !strcmp(reason, "available"))
            reason = "station_source_partial";
        if (inventory_reason) *inventory_reason = reason;
        if (metrics_reason) *metrics_reason = reason;
        return 0;
    }
    if (inventory) *inventory = 1;
    if (metrics) *metrics = 1;
    if (inventory_reason) *inventory_reason = "available";
    if (metrics_reason) *metrics_reason = "available";
    return 1;
}

static int wifi_radio_tx_power(struct json_object *radio, double *out)
{
    struct json_object *interfaces = wifi_child_array(radio, "interfaces");
    double value;
    size_t i;

    if (wifi_number(radio, "tx_power_dbm", &value) ||
        wifi_number(radio, "txpower_dbm", &value) ||
        wifi_number(radio, "tx_power", &value)) {
        if (out) *out = value;
        return 1;
    }
    for (i = 0; interfaces && i < json_object_array_length(interfaces); i++) {
        struct json_object *interface = json_object_array_get_idx(interfaces, i);

        if (wifi_number(interface, "txpower_dbm", &value) ||
            wifi_number(interface, "tx_power_dbm", &value)) {
            if (out) *out = value;
            return 1;
        }
    }
    return 0;
}

static void wifi_decorate_radio_metrics(struct json_object *radios,
                                        size_t first_radio,
                                        struct json_object *stations,
                                        int station_inventory,
                                        int station_metrics,
                                        const char *station_reason)
{
    size_t i;

    for (i = first_radio; radios && i < json_object_array_length(radios); i++) {
        struct json_object *radio = json_object_array_get_idx(radios, i);
        const char *radio_id = wifi_string(radio, "id", "");
        int clients = 0;
        int signals = 0;
        double signal_sum = 0.0;
        double tx_power = 0.0;
        size_t j;

        for (j = 0; station_inventory && stations &&
                    j < json_object_array_length(stations); j++) {
            struct json_object *station = json_object_array_get_idx(stations, j);
            double signal;

            if (strcmp(wifi_string(station, "radio_id", ""), radio_id))
                continue;
            clients++;
            if (station_metrics && wifi_number(station, "signal_dbm", &signal)) {
                signal_sum += signal;
                signals++;
            }
        }
        if (station_inventory) {
            json_object_object_del(radio, "clients");
            json_object_object_add(radio, "clients", json_object_new_int(clients));
            wifi_replace_string(radio, "clients_source", "hostapd_control");
        } else {
            wifi_replace_null(radio, "clients");
            wifi_replace_string(radio, "clients_reason", station_reason);
        }
        if (signals > 0) {
            json_object_object_del(radio, "avg_signal_dbm");
            json_object_object_add(radio, "avg_signal_dbm",
                                   json_object_new_double(signal_sum / signals));
            wifi_replace_string(radio, "avg_signal_source", "hostapd_control");
        } else {
            wifi_replace_null(radio, "avg_signal_dbm");
            wifi_replace_string(radio, "avg_signal_reason",
                station_metrics ? "no_associated_station_signal_samples" :
                                  station_reason);
        }
        if (wifi_radio_tx_power(radio, &tx_power)) {
            json_object_object_del(radio, "tx_power_dbm");
            json_object_object_add(radio, "tx_power_dbm",
                                   json_object_new_double(tx_power));
            wifi_replace_string(radio, "tx_power_source", "iw_dev");
        } else {
            wifi_replace_null(radio, "tx_power_dbm");
            wifi_replace_string(radio, "tx_power_reason", "not_reported_by_driver");
        }
        wifi_replace_null(radio, "tx_power_mode");
        wifi_replace_string(radio, "tx_power_mode_reason", "not_reported_by_driver");
        wifi_replace_null(radio, "history_24h");
        wifi_replace_string(radio, "history_24h_reason", "radio_history_not_collected");
        {
            struct json_object *survey = wifi_child_object(radio, "survey");
            struct json_object *utilization = wifi_child(survey, "utilization_pct");

            if (utilization && json_object_is_type(utilization, json_type_double) &&
                json_object_get_double(utilization) >= 0.0 &&
                json_object_get_double(utilization) <= 100.0) {
                json_object_object_del(radio, "channel_utilization_pct");
                json_object_object_add(radio, "channel_utilization_pct",
                                       json_object_new_double(
                                           json_object_get_double(utilization)));
                wifi_replace_string(radio, "channel_utilization_source", "iw_survey");
            } else {
                wifi_replace_null(radio, "channel_utilization_pct");
                wifi_replace_string(radio, "channel_utilization_source",
                                    survey ? "iw_survey_unavailable" :
                                             "channel_survey_not_reported");
            }
        }
        wifi_replace_null(radio, "avg_interference_pct");
        wifi_replace_string(radio, "avg_interference_reason",
                            "interference_telemetry_not_collected");
        wifi_replace_null(radio, "mimo");
        wifi_replace_string(radio, "mimo_reason", "spatial_streams_not_reported");
        wifi_replace_null(radio, "uplink_type");
        wifi_replace_string(radio, "uplink_type_reason", "ap_uplink_not_reported");
        wifi_replace_null(radio, "supported_channels");
        wifi_replace_null(radio, "dfs_channels");
        wifi_replace_null(radio, "unavailable_channels");
        wifi_replace_null(radio, "excluded_channels");
        wifi_replace_string(radio, "channel_plan_reason",
                            "regdomain_driver_channel_catalog_pending");
        wifi_replace_bool(radio, "metrics_complete", station_metrics && signals == clients);
    }
}

static void wifi_capability_bool(struct json_object *capabilities,
                                 const char *key, int value);
static void wifi_capability_reason(struct json_object *capabilities,
                                   const char *key, const char *reason);

static struct json_object *wifi_response_root(struct json_object *response)
{
    struct json_object *data;

    if (!wifi_response_available(response))
        return NULL;
    data = wifi_child_object(response, "data");
    return data ? data : response;
}

static const char *wifi_environment_ap_name(struct json_object *data,
                                            const char *ap_id)
{
    struct json_object *managed = wifi_child_object(data, "managed_aps");
    struct json_object *items = wifi_child_array(managed, "items");
    size_t i;

    for (i = 0; items && i < json_object_array_length(items); i++) {
        struct json_object *item = json_object_array_get_idx(items, i);

        if (item && !strcmp(wifi_string(item, "ap_id", ""), ap_id))
            return wifi_first_nonempty(wifi_string(item, "display_name", ""),
                                       wifi_string(item, "name", ""), ap_id);
    }
    return ap_id;
}

static const char *wifi_environment_radio_band(struct json_object *data,
                                               const char *radio_id,
                                               int64_t frequency_mhz)
{
    struct json_object *radios = wifi_child_array(data, "radios");
    size_t i;

    for (i = 0; radios && i < json_object_array_length(radios); i++) {
        struct json_object *radio = json_object_array_get_idx(radios, i);

        if (radio && !strcmp(wifi_string(radio, "id", ""), radio_id))
            return wifi_normalized_band(wifi_string(radio, "band", ""));
    }
    if (frequency_mhz >= 2400 && frequency_mhz < 2500)
        return "2g";
    if (frequency_mhz >= 4900 && frequency_mhz < 5925)
        return "5g";
    if (frequency_mhz >= 5925 && frequency_mhz < 7125)
        return "6g";
    return "";
}

static void wifi_environment_copy(struct json_object *out,
                                  struct json_object *source,
                                  const char *from, const char *to)
{
    struct json_object *value = wifi_child(source, from);

    if (value)
        json_object_object_add(out, to, json_object_get(value));
}

static void wifi_environment_interference_add(
    struct json_object *data, struct json_object *interference,
    struct json_object *item, const char *job_id, const char *ap_id,
    const char *radio_id, const char *local_radio_id, int64_t sample_time,
    int sample_complete, int sample_truncated)
{
    struct json_object *row = json_object_new_object();
    const char *ap_name = wifi_environment_ap_name(data, ap_id);
    const char *bssid = wifi_string(item, "bssid", "");
    const char *ssid = wifi_string(item, "ssid", "");
    int64_t frequency_mhz = wifi_int64(item, "frequency_mhz", 0);
    char row_id[256];

    if (!row)
        return;
    snprintf(row_id, sizeof(row_id), "ap:%s:radio:%s:bssid:%s",
             ap_id, local_radio_id, bssid[0] ? bssid : "unknown");
    json_object_object_add(row, "id", json_object_new_string(row_id));
    json_object_object_add(row, "source",
                           json_object_new_string("dreamingwrt-ac.radio_job"));
    json_object_object_add(row, "source_mode",
                           json_object_new_string("latest_neighbor_scan"));
    json_object_object_add(row, "job_id", json_object_new_string(job_id));
    json_object_object_add(row, "sample_time",
                           json_object_new_int64(sample_time));
    json_object_object_add(row, "ap_id", json_object_new_string(ap_id));
    json_object_object_add(row, "nearest_ap_id", json_object_new_string(ap_id));
    json_object_object_add(row, "ap", json_object_new_string(ap_name));
    json_object_object_add(row, "ap_name", json_object_new_string(ap_name));
    json_object_object_add(row, "nearest_ap", json_object_new_string(ap_name));
    json_object_object_add(row, "radio_id", json_object_new_string(radio_id));
    json_object_object_add(row, "local_radio_id",
                           json_object_new_string(local_radio_id));
    json_object_object_add(row, "band", json_object_new_string(
        wifi_environment_radio_band(data, radio_id, frequency_mhz)));
    json_object_object_add(row, "name", json_object_new_string(ssid));
    wifi_environment_copy(row, item, "ssid", "ssid");
    wifi_environment_copy(row, item, "ssid_hidden", "ssid_hidden");
    wifi_environment_copy(row, item, "bssid", "bssid");
    wifi_environment_copy(row, item, "bssid", "mac");
    wifi_environment_copy(row, item, "rssi_dbm", "rssi_dbm");
    wifi_environment_copy(row, item, "rssi_dbm", "rssi");
    wifi_environment_copy(row, item, "rssi_dbm", "signal");
    wifi_environment_copy(row, item, "frequency_mhz", "frequency_mhz");
    wifi_environment_copy(row, item, "channel", "channel");
    wifi_environment_copy(row, item, "width_mhz", "width_mhz");
    wifi_environment_copy(row, item, "width_mhz", "width");
    wifi_environment_copy(row, item, "width_mhz", "channel_width");
    wifi_environment_copy(row, item, "width_mode", "width_mode");
    wifi_environment_copy(row, item, "standard", "standard");
    wifi_environment_copy(row, item, "security", "security");
    wifi_environment_copy(row, item, "vendor", "vendor");
    wifi_environment_copy(row, item, "vendor_reason", "vendor_reason");
    wifi_environment_copy(row, item, "complete", "complete");
    wifi_environment_copy(row, item, "missing_fields", "missing_fields");
    json_object_object_add(row, "sample_complete",
                           json_object_new_boolean(sample_complete));
    json_object_object_add(row, "sample_truncated",
                           json_object_new_boolean(sample_truncated));
    json_object_array_add(interference, row);
}

void webd_wifi_merge_environment_scan(struct json_object *data,
                                      struct json_object *ac_results,
                                      struct json_object *ac_capabilities)
{
    struct json_object *environment;
    struct json_object *neighbor;
    struct json_object *capabilities;
    struct json_object *reasons;
    struct json_object *result_root = wifi_response_root(ac_results);
    struct json_object *cap_root = wifi_response_root(ac_capabilities);
    struct json_object *ac_cap = wifi_child_object(cap_root, "capabilities");
    struct json_object *source_samples = wifi_child_array(result_root, "samples");
    struct json_object *samples = json_object_new_array();
    struct json_object *interference;
    int execution_available = ac_cap &&
        wifi_bool(ac_cap, "scan_execution", 0);
    int dispatch_available = ac_cap &&
        wifi_bool(ac_cap, "scan_dispatch", execution_available);
    int job_control_available = ac_cap &&
        wifi_bool(ac_cap, "scan_job_control_plane", 0);
    int complete = 1;
    int samples_available;
    size_t i;

    if (!data || !samples)
        return;
    environment = wifi_ensure_object(data, "environment");
    capabilities = wifi_ensure_object(data, "capabilities");
    reasons = wifi_ensure_object(capabilities, "reasons");
    interference = wifi_ensure_array(data, "interference");
    for (i = 0; source_samples && i < json_object_array_length(source_samples);
         i++) {
        struct json_object *sample = wifi_clone(
            json_object_array_get_idx(source_samples, i));
        const char *ap_id;
        const char *local_radio_id;
        const char *job_id;
        struct json_object *items;
        int64_t sample_time;
        int sample_complete;
        int sample_truncated;
        char aggregate_id[160];
        char local_radio_id_copy[64];
        size_t item_index;

        if (!sample || !json_object_is_type(sample, json_type_object)) {
            json_object_put(sample);
            continue;
        }
        ap_id = wifi_string(sample, "ap_id", "");
        local_radio_id = wifi_string(sample, "radio_id", "");
        job_id = wifi_string(sample, "job_id", "");
        sample_time = wifi_int64(sample, "sample_time", 0);
        sample_complete = wifi_bool(sample, "complete", 0);
        sample_truncated = wifi_bool(sample, "truncated", !sample_complete);
        snprintf(local_radio_id_copy, sizeof(local_radio_id_copy), "%s",
                 local_radio_id);
        if (!ap_id[0] || !local_radio_id[0] ||
            snprintf(aggregate_id, sizeof(aggregate_id), "ap:%s:radio:%s",
                     ap_id, local_radio_id) >= (int)sizeof(aggregate_id)) {
            json_object_put(sample);
            continue;
        }
        wifi_replace_string(sample, "local_radio_id", local_radio_id);
        wifi_replace_string(sample, "radio_id", aggregate_id);
        wifi_replace_string(sample, "source", "dreamingwrt-ac.radio_job");
        if (!sample_complete)
            complete = 0;
        items = wifi_child_array(sample, "items");
        for (item_index = 0; items &&
             item_index < json_object_array_length(items); item_index++) {
            struct json_object *item = json_object_array_get_idx(items,
                                                                  item_index);

            if (item && json_object_is_type(item, json_type_object))
                wifi_environment_interference_add(
                    data, interference, item, job_id, ap_id, aggregate_id,
                    local_radio_id_copy, sample_time, sample_complete,
                    sample_truncated);
        }
        json_object_array_add(samples, sample);
    }
    samples_available = json_object_array_length(samples) > 0;
    neighbor = json_object_new_object();
    json_object_object_add(neighbor, "supported",
                           json_object_new_boolean(execution_available));
    json_object_object_add(neighbor, "execution_available",
                           json_object_new_boolean(execution_available));
    json_object_object_add(neighbor, "sample_available",
                           json_object_new_boolean(samples_available));
    json_object_object_add(neighbor, "source",
                           json_object_new_string("dreamingwrt-ac.radio_job"));
    json_object_object_add(neighbor, "sample_count",
                           json_object_new_int((int)json_object_array_length(samples)));
    json_object_object_add(neighbor, "complete", json_object_new_boolean(
        json_object_array_length(samples) > 0 && complete));
    json_object_object_add(neighbor, "samples", samples);
    json_object_object_add(neighbor, "reason", json_object_new_string(
        !execution_available ? "ap_control_v2_scan_execution_unavailable" :
        !samples_available ? "scan_not_yet_run" :
        complete ? "available" : "available_with_truncated_samples"));
    json_object_object_del(environment, "neighbor_scan");
    json_object_object_add(environment, "neighbor_scan", neighbor);
    wifi_capability_bool(capabilities, "scan_dispatch", dispatch_available);
    wifi_capability_bool(capabilities, "scan_execution", execution_available);
    wifi_capability_bool(capabilities, "scan_jobs", job_control_available);
    wifi_capability_bool(capabilities, "neighbor_scan", samples_available);
    wifi_capability_bool(capabilities, "environment_scan", samples_available);
    wifi_capability_bool(capabilities, "scan", execution_available);
    wifi_capability_bool(capabilities, "airview_realtime", samples_available);
    wifi_replace_string(capabilities, "airview_mode",
                        samples_available ? "latest_neighbor_scan" :
                                            "unavailable");
    wifi_replace_string(reasons, "scan_dispatch",
        dispatch_available ? "available" :
                             "ap_control_v2_scan_dispatch_unavailable");
    wifi_replace_string(reasons, "scan_execution",
        execution_available ? "available" :
                              "ap_control_v2_scan_execution_unavailable");
    wifi_replace_string(reasons, "scan_jobs",
        job_control_available ? "available" :
                                "scan_job_control_plane_unavailable");
    wifi_replace_string(reasons, "neighbor_scan",
        samples_available ? "available" :
        execution_available ? "scan_not_yet_run" :
                              "ap_control_v2_scan_execution_unavailable");
    wifi_replace_string(reasons, "environment_scan",
        samples_available ? "available" :
        execution_available ? "scan_not_yet_run" :
                              "ap_control_v2_scan_execution_unavailable");
    wifi_replace_string(reasons, "scan",
        execution_available ? "available" :
                              "ap_control_v2_scan_execution_unavailable");
    wifi_replace_string(reasons, "airview_realtime",
        samples_available ? "latest_neighbor_scan_available" :
        execution_available ? "scan_not_yet_run" :
                              "ap_control_v2_scan_execution_unavailable");
}

struct wifi_survey_history_point {
    struct json_object *source;
    int64_t timestamp;
};

static int wifi_survey_history_point_compare(const void *left,
                                             const void *right)
{
    const struct wifi_survey_history_point *a = left;
    const struct wifi_survey_history_point *b = right;

    if (a->timestamp < b->timestamp)
        return -1;
    if (a->timestamp > b->timestamp)
        return 1;
    return 0;
}

static int wifi_survey_history_radio_matches(struct json_object *radio,
                                             struct json_object *point)
{
    const char *radio_ap_id = wifi_string(radio, "ap_id", "local");
    const char *radio_id = wifi_string(radio, "id", "");
    const char *radio_local_id = wifi_string(radio, "local_id", "");
    const char *point_ap_id = wifi_string(point, "ap_id", "");
    const char *point_radio_id = wifi_string(point, "radio_id", "");

    return point_ap_id[0] && point_radio_id[0] &&
           !strcmp(radio_ap_id, point_ap_id) &&
           (!strcmp(radio_id, point_radio_id) ||
            (radio_local_id[0] && !strcmp(radio_local_id, point_radio_id)));
}

static struct json_object *wifi_survey_history_output_point(
    struct json_object *source)
{
    struct json_object *timestamp = wifi_child(source, "timestamp");
    struct json_object *source_name = wifi_child(source, "source");
    struct json_object *point = json_object_new_object();
    double value;
    double utilization;
    int has_value = wifi_number(source, "value", &value);
    int has_utilization = wifi_number(source, "utilization_pct", &utilization);

    if (!point || !timestamp || (!has_value && !has_utilization)) {
        if (point)
            json_object_put(point);
        return NULL;
    }
    if (!has_value)
        value = utilization;
    if (!has_utilization)
        utilization = value;
    json_object_object_add(point, "timestamp", json_object_get(timestamp));
    json_object_object_add(point, "value", json_object_new_double(value));
    json_object_object_add(point, "utilization",
                           json_object_new_double(utilization));
    json_object_object_add(point, "source",
        source_name && json_object_is_type(source_name, json_type_string) ?
        json_object_get(source_name) : json_object_new_null());
    json_object_object_add(point, "complete",
                           json_object_new_boolean(
                               wifi_bool(source, "complete", 0)));
    return point;
}

void webd_wifi_merge_survey_history(struct json_object *data,
                                    struct json_object *response)
{
    struct json_object *radios;
    struct json_object *capabilities;
    struct json_object *root = wifi_response_root(response);
    struct json_object *points = wifi_child_array(root, "points");
    const char *response_reason = wifi_string(root, "reason", "");
    const char *reason = "survey_history_empty";
    int any_mapped_point = 0;
    int history_available = 0;
    size_t radio_index;

    if (!data || !json_object_is_type(data, json_type_object))
        return;
    radios = wifi_ensure_array(data, "radios");
    capabilities = wifi_ensure_object(data, "capabilities");

    for (radio_index = 0; radio_index < json_object_array_length(radios);
         radio_index++) {
        struct json_object *radio = json_object_array_get_idx(radios, radio_index);
        struct json_object *history = json_object_new_array();
        struct wifi_survey_history_point *matches = NULL;
        size_t point_count = points ? json_object_array_length(points) : 0;
        size_t match_count = 0;
        size_t complete_numeric_count = 0;
        size_t point_index;

        if (!radio || !json_object_is_type(radio, json_type_object)) {
            json_object_put(history);
            continue;
        }
        if (point_count)
            matches = calloc(point_count, sizeof(*matches));
        for (point_index = 0; matches && point_index < point_count;
             point_index++) {
            struct json_object *source = json_object_array_get_idx(points,
                                                                   point_index);
            struct json_object *timestamp;
            double value;

            if (!source || !json_object_is_type(source, json_type_object) ||
                !wifi_survey_history_radio_matches(radio, source))
                continue;
            timestamp = wifi_child(source, "timestamp");
            if (!timestamp ||
                (!json_object_is_type(timestamp, json_type_int) &&
                 !json_object_is_type(timestamp, json_type_double)) ||
                (!wifi_number(source, "value", &value) &&
                 !wifi_number(source, "utilization_pct", &value)))
                continue;
            matches[match_count].source = source;
            matches[match_count].timestamp = json_object_get_int64(timestamp);
            match_count++;
            if (wifi_bool(source, "complete", 0))
                complete_numeric_count++;
        }
        if (match_count > 1)
            qsort(matches, match_count, sizeof(*matches),
                  wifi_survey_history_point_compare);
        for (point_index = 0; point_index < match_count; point_index++) {
            struct json_object *point = wifi_survey_history_output_point(
                matches[point_index].source);

            if (point)
                json_object_array_add(history, point);
        }
        free(matches);
        json_object_object_del(radio, "channel_history");
        json_object_object_add(radio, "channel_history", history);
        if (match_count > 0)
            any_mapped_point = 1;
        if (complete_numeric_count >= 2)
            history_available = 1;
    }

    if (history_available)
        reason = "available";
    else if (!root)
        reason = "survey_history_source_unavailable";
    else if (!points || json_object_array_length(points) == 0)
        reason = response_reason[0] && strcmp(response_reason, "available") ?
                 response_reason : "survey_history_empty";
    else if (!any_mapped_point)
        reason = "survey_history_radio_mapping_unavailable";
    else
        reason = "insufficient_complete_numeric_points";
    wifi_capability_bool(capabilities, "survey_history", history_available);
    wifi_capability_bool(capabilities, "airview_history", history_available);
    wifi_capability_reason(capabilities, "survey_history", reason);
    wifi_capability_reason(capabilities, "airview_history", reason);
}

static void wifi_collect_environment_samples(struct json_object *data,
                                             struct json_object *radios,
                                             struct json_object *capabilities)
{
    struct json_object *environment = wifi_ensure_object(data, "environment");
    struct json_object *surveys = json_object_new_array();
    struct json_object *neighbor = json_object_new_object();
    struct json_object *spectral = json_object_new_object();
    struct json_object *channel = json_object_new_object();
    size_t i;
    int sample_count = 0;
    int fresh_count = 0;
    int complete_count = 0;

    for (i = 0; radios && i < json_object_array_length(radios); i++) {
        struct json_object *radio = json_object_array_get_idx(radios, i);
        struct json_object *survey = wifi_child_object(radio, "survey");
        struct json_object *copy;
        struct json_object *complete;
        int fresh;
        int survey_complete;

        if (!survey || !(copy = wifi_clone(survey)))
            continue;
        fresh = wifi_bool(radio, "online", 0) && !wifi_bool(radio, "stale", 1) &&
                !wifi_bool(survey, "stale", 0);
        survey_complete = wifi_bool(survey, "complete", 0);
        json_object_object_add(copy, "radio_id",
                               json_object_new_string(wifi_string(radio, "id", "")));
        json_object_object_add(copy, "ap_id",
                               json_object_new_string(wifi_string(radio, "ap_id", "local")));
        json_object_object_add(copy, "band",
                               json_object_new_string(wifi_string(radio, "band", "")));
        json_object_object_del(copy, "stale");
        json_object_object_add(copy, "stale", json_object_new_boolean(!fresh));
        if (json_object_object_get_ex(survey, "complete", &complete) && complete &&
            survey_complete && fresh)
            complete_count++;
        if (fresh)
            fresh_count++;
        sample_count++;
        json_object_array_add(surveys, copy);
    }

    json_object_object_add(channel, "supported",
                           json_object_new_boolean(complete_count > 0));
    json_object_object_add(channel, "source",
                           json_object_new_string("apd.iw_survey"));
    json_object_object_add(channel, "sample_count",
                           json_object_new_int(sample_count));
    json_object_object_add(channel, "fresh_sample_count",
                           json_object_new_int(fresh_count));
    json_object_object_add(channel, "complete",
                           json_object_new_boolean(sample_count > 0 &&
                                                    complete_count == sample_count));
    json_object_object_add(channel, "samples", surveys);
    json_object_object_add(channel, "reason", json_object_new_string(
        complete_count > 0 ? "available" :
        (sample_count > 0 ? "iw_survey_samples_stale_or_incomplete" :
                            "iw_survey_sample_unavailable")));

    json_object_object_add(neighbor, "supported", json_object_new_boolean(0));
    json_object_object_add(neighbor, "samples", json_object_new_array());
    json_object_object_add(neighbor, "reason",
                           json_object_new_string("neighbor_bssid_scan_producer_pending"));
    json_object_object_add(spectral, "supported", json_object_new_boolean(0));
    json_object_object_add(spectral, "samples", json_object_new_array());
    json_object_object_add(spectral, "reason",
                           json_object_new_string("spectral_fft_driver_producer_pending"));

    json_object_object_del(environment, "channel_survey");
    json_object_object_del(environment, "neighbor_scan");
    json_object_object_del(environment, "spectral_fft");
    json_object_object_add(environment, "channel_survey", channel);
    json_object_object_add(environment, "neighbor_scan", neighbor);
    json_object_object_add(environment, "spectral_fft", spectral);
    json_object_object_add(environment, "complete", json_object_new_boolean(0));

    wifi_capability_bool(capabilities, "channel_survey", complete_count > 0);
    wifi_capability_bool(capabilities, "survey_history", 0);
    wifi_capability_bool(capabilities, "neighbor_scan", 0);
    wifi_capability_bool(capabilities, "spectral_fft", 0);
    wifi_capability_reason(capabilities, "channel_survey",
                           complete_count > 0 ? "available" :
                           (sample_count > 0 ?
                                               "iw_survey_samples_stale_or_incomplete" :
                                               "iw_survey_sample_unavailable"));
    wifi_capability_reason(capabilities, "survey_history",
                           "channel_survey_history_store_pending");
    wifi_capability_reason(capabilities, "neighbor_scan",
                           "neighbor_bssid_scan_producer_pending");
    wifi_capability_reason(capabilities, "spectral_fft",
                           "spectral_fft_driver_producer_pending");
}

static void wifi_capability_bool(struct json_object *capabilities,
                                 const char *key, int value)
{
    wifi_replace_bool(capabilities, key, value);
}

static void wifi_capability_reason(struct json_object *capabilities,
                                   const char *key, const char *reason)
{
    struct json_object *reasons = wifi_ensure_object(capabilities, "reasons");

    wifi_replace_string(reasons, key, reason);
}

/* Flip the connectivity/roaming capability truthfully once the AC
 * declares its bounded station event store.  The events are derived from
 * consecutive telemetry snapshots (source=ac_snapshot_diff), so the
 * capability carries that source explicitly and the store being present
 * never claims hostapd event-stream granularity. */
void webd_wifi_merge_station_events_capability(
    struct json_object *data, struct json_object *ac_capabilities)
{
    struct json_object *capabilities;
    struct json_object *cap_root = wifi_response_root(ac_capabilities);
    struct json_object *ac_cap = wifi_child_object(cap_root, "capabilities");
    int store_available = ac_cap &&
        wifi_bool(ac_cap, "station_event_store", 0);

    if (!data || !store_available)
        return;
    capabilities = wifi_ensure_object(data, "capabilities");
    wifi_capability_bool(capabilities, "connectivity_events", 1);
    wifi_capability_bool(capabilities, "roaming_history", 1);
    wifi_capability_reason(capabilities, "connectivity_events", "available");
    wifi_capability_reason(capabilities, "roaming_history", "available");
    wifi_replace_string(capabilities, "connectivity_events_source",
                        "ac_snapshot_diff");
    wifi_replace_string(capabilities, "connectivity_events_endpoint",
                        "/api/v1/wifi/connectivity/events");
}

struct json_object *webd_wifi_aggregate_data_with_resolver(
    struct json_object *local_response, struct json_object *ac_response,
    int runtime_status, webd_wifi_model_image_resolver_fn image_resolver)
{
    struct json_object *data = wifi_response_data_clone(local_response);
    struct json_object *capabilities = wifi_ensure_object(data, "capabilities");
    struct json_object *radios = wifi_ensure_array(data, "radios");
    struct json_object *ssids = wifi_ensure_array(data, "ssids");
    struct json_object *stations = wifi_ensure_array(data, "stations");
    struct json_object *runtime_radios = runtime_status ?
        wifi_ensure_array(data, "runtime_radios") : radios;
    struct json_object *runtime = wifi_ensure_object(data, "runtime");
    struct json_object *managed_items = json_object_new_array();
    struct json_object *ac_items;
    struct json_object *managed;
    struct json_object *local_summary;
    struct json_object *sources;
    struct json_object *summary;
    struct json_object *bands;
    int local_source_available = wifi_response_available(local_response);
    int local_runtime_available = runtime_status && wifi_bool(runtime, "available", 0);
    int ac_available = 0;
    int managed_online = 0;
    int remote_snapshots = 0;
    int remote_fresh = 0;
    int remote_stale = 0;
    int remote_offline = 0;
    int remote_complete = 1;
    int station_inventory = 0;
    int station_metrics = 0;
    int ap_radio_mapping = 0;
    const char *station_inventory_reason = "station_source_not_reported";
    const char *station_metrics_reason = "station_source_not_reported";
    int remote_station_inventory_sources = 0;
    int remote_station_metric_sources = 0;
    int local_station_inventory;
    int local_station_metrics;
    int desired_available = 0;
    size_t local_radio_count;
    size_t local_ssid_count;
    size_t local_station_count;
    size_t i;

    wifi_replace_string(data, "contract_version", "wifi-management.v2");
    if (!wifi_child(data, "ts"))
        json_object_object_add(data, "ts", json_object_new_int64((int64_t)time(NULL)));

    wifi_namespace_array(radios, WEBD_WIFI_RADIO, runtime_status);
    if (runtime_radios != radios)
        wifi_namespace_array(runtime_radios, WEBD_WIFI_RADIO, 1);
    wifi_namespace_array(ssids, WEBD_WIFI_SSID, runtime_status);
    wifi_namespace_array(stations, WEBD_WIFI_STATION, runtime_status);

    local_radio_count = json_object_array_length(runtime_status ? runtime_radios : radios);
    local_ssid_count = json_object_array_length(ssids);
    local_station_count = json_object_array_length(stations);
    local_station_inventory = wifi_bool(capabilities, "station_inventory",
                              wifi_bool(capabilities, "station_telemetry", 0));
    local_station_metrics = wifi_bool(capabilities, "station_metrics",
                            wifi_bool(capabilities, "station_telemetry", 0));
    {
        struct json_object *local_reasons = wifi_child_object(capabilities, "reasons");

        if (!local_station_inventory)
            station_inventory_reason = wifi_string(
                local_reasons, "station_inventory",
                "local_station_source_not_authoritative");
        if (!local_station_metrics)
            station_metrics_reason = wifi_string(
                local_reasons, "station_metrics",
                "local_station_metrics_not_authoritative");
    }
    if (runtime_status && local_radio_count > 0)
        wifi_decorate_radio_metrics(
            runtime_radios, 0, stations, local_station_inventory,
            local_station_metrics, local_station_inventory ?
            (local_station_metrics ? "available" : "local_station_metrics_partial") :
            "local_station_source_not_authoritative");
    ac_items = wifi_ac_items(ac_response, &ac_available);

    for (i = 0; ac_items && i < json_object_array_length(ac_items); i++) {
        struct json_object *ap = json_object_array_get_idx(ac_items, i);
        struct json_object *ap_runtime;
        struct json_object *snapshot;
        struct json_object *desired;
        struct json_object *source_radios;
        struct json_object *source_ssids;
        struct json_object *source_stations;
        const char *ap_id;
        const char *ap_name;
        const char *configured_name;
        const char *model;
        const char *ap_station_inventory_reason = "station_source_not_reported";
        const char *ap_station_metrics_reason = "station_source_not_reported";
        char image_url[768];
        char image_model_match[256];
        int ap_station_inventory = 0;
        int ap_station_metrics = 0;
        size_t remote_radio_start = 0;
        int online;
        int stale;
        int runtime_available;
        int fresh;

        if (!ap || !json_object_is_type(ap, json_type_object))
            continue;
        ap_id = wifi_string(ap, "ap_id", wifi_string(ap, "id", ""));
        if (!ap_id[0])
            continue;
        ap_runtime = wifi_child_object(ap, "runtime");
        snapshot = wifi_child_object(ap_runtime, "snapshot");
        if (!snapshot)
            snapshot = wifi_child_object(ap, "snapshot");
        desired = wifi_child_object(snapshot, "desired");
        model = wifi_ap_model(ap, snapshot);
        configured_name = wifi_first_nonempty(wifi_string(ap, "name", ""),
                          wifi_string(ap, "ap_name", ""),
                          wifi_string(ap, "hostname", ""));
        ap_name = wifi_first_nonempty(configured_name, model, ap_id);
        wifi_resolve_model_image(image_resolver, model, image_url,
                                 sizeof(image_url), image_model_match,
                                 sizeof(image_model_match));
        online = wifi_bool(ap, "online", 0);
        stale = wifi_bool(ap, "stale", 0) || wifi_bool(ap_runtime, "stale", 0) ||
                (snapshot && wifi_bool(snapshot, "stale", 0));
        runtime_available = snapshot && wifi_bool(ap_runtime, "available", 1);
        fresh = online && !stale && runtime_available;
        if (online && !stale)
            managed_online++;
        if (snapshot)
            remote_snapshots++;
        if (stale)
            remote_stale++;
        if (!online)
            remote_offline++;
        if (fresh)
            remote_fresh++;
        if (fresh && !wifi_bool(snapshot, "complete", wifi_bool(ap_runtime, "complete", 0)))
            remote_complete = 0;
        wifi_station_source_state(snapshot, &ap_station_inventory,
                                  &ap_station_metrics,
                                  &ap_station_inventory_reason,
                                  &ap_station_metrics_reason);
        if (fresh && ap_station_inventory)
            remote_station_inventory_sources++;
        if (fresh && ap_station_metrics)
            remote_station_metric_sources++;
        if (fresh && !ap_station_inventory)
            station_inventory_reason = ap_station_inventory_reason;
        if (fresh && !ap_station_metrics)
            station_metrics_reason = ap_station_metrics_reason;
        if (snapshot && wifi_child_array(snapshot, "radios") &&
            json_object_array_length(wifi_child_array(snapshot, "radios")) > 0)
            ap_radio_mapping = 1;

        json_object_array_add(managed_items, wifi_ap_summary(
            ap, ap_runtime, snapshot, ap_id, ap_name, model, image_url,
            image_model_match, online, stale));

        if (!snapshot)
            continue;
        if (runtime_status) {
            source_radios = wifi_child_array(snapshot, "radios");
            source_ssids = wifi_child_array(snapshot, "ssids");
            source_stations = wifi_child_array(snapshot, "stations");
            remote_radio_start = json_object_array_length(runtime_radios);
            wifi_append_remote(runtime_radios, source_radios, WEBD_WIFI_RADIO,
                               ap_id, ap_name, model, image_url, image_model_match,
                               online, stale, 1, 1);
            wifi_append_remote(ssids, source_ssids, WEBD_WIFI_SSID,
                               ap_id, ap_name, model, image_url, image_model_match,
                               online, stale, 1, 1);
            if (fresh && ap_station_inventory)
                wifi_append_remote(stations, source_stations, WEBD_WIFI_STATION,
                                   ap_id, ap_name, model, image_url,
                                   image_model_match, online, stale, 1, 1);
            wifi_decorate_radio_metrics(
                runtime_radios, remote_radio_start, stations,
                fresh && ap_station_inventory,
                fresh && ap_station_metrics,
                fresh ? ap_station_inventory_reason :
                (stale ? "telemetry_stale" : "managed_ap_offline"));
        } else {
            source_radios = wifi_child_array(desired, "radios");
            source_ssids = wifi_child_array(desired, "ssids");
            if (!source_radios) source_radios = wifi_child_array(snapshot, "radios");
            if (!source_ssids) source_ssids = wifi_child_array(snapshot, "ssids");
            desired_available |= desired &&
                (wifi_child_array(desired, "radios") || wifi_child_array(desired, "ssids"));
            wifi_append_remote(radios, source_radios, WEBD_WIFI_RADIO,
                               ap_id, ap_name, model, image_url, image_model_match,
                               online, stale, 0,
                               source_radios != wifi_child_array(desired, "radios"));
            wifi_append_remote(ssids, source_ssids, WEBD_WIFI_SSID,
                               ap_id, ap_name, model, image_url, image_model_match,
                               online, stale, 0,
                               source_ssids != wifi_child_array(desired, "ssids"));
        }
    }

    station_inventory =
        (!(local_radio_count || local_ssid_count) || local_station_inventory) &&
        (remote_fresh == 0 || remote_station_inventory_sources == remote_fresh) &&
        ((local_radio_count || local_ssid_count) || remote_fresh > 0) &&
        (!(local_radio_count || local_ssid_count) || local_station_inventory);
    station_metrics = station_inventory &&
        (!(local_radio_count || local_ssid_count) || local_station_metrics) &&
        (remote_fresh == 0 || remote_station_metric_sources == remote_fresh);
    if (station_inventory)
        station_inventory_reason = "available";
    else if ((local_radio_count || local_ssid_count) && !local_station_inventory)
        station_inventory_reason = "local_station_source_not_authoritative";
    else if (remote_fresh == 0 && remote_stale > 0)
        station_inventory_reason = "telemetry_stale";
    else if (remote_fresh == 0 && remote_offline > 0)
        station_inventory_reason = "managed_ap_offline";
    if (station_metrics)
        station_metrics_reason = "available";
    else if ((local_radio_count || local_ssid_count) && !local_station_metrics)
        station_metrics_reason = "local_station_metrics_not_authoritative";
    else if (remote_fresh == 0 && remote_stale > 0)
        station_metrics_reason = "telemetry_stale";
    else if (remote_fresh == 0 && remote_offline > 0)
        station_metrics_reason = "managed_ap_offline";

    if (runtime_status) {
        struct json_object *runtime_radios_copy = wifi_clone(runtime_radios);

        if (runtime_radios_copy) {
            json_object_object_del(data, "radios");
            json_object_object_add(data, "radios", runtime_radios_copy);
            radios = runtime_radios_copy;
        } else {
            radios = runtime_radios;
        }
    }

    managed = json_object_new_object();
    json_object_object_add(managed, "available", json_object_new_boolean(ac_available));
    json_object_object_add(managed, "count", json_object_new_int(
        ac_items ? (int)json_object_array_length(ac_items) : 0));
    json_object_object_add(managed, "online", json_object_new_int(managed_online));
    json_object_object_add(managed, "runtime_snapshots", json_object_new_int(remote_snapshots));
    json_object_object_add(managed, "runtime_available", json_object_new_boolean(remote_fresh > 0));
    json_object_object_add(managed, "items", managed_items);
    json_object_object_add(data, "managed_aps", managed);

    local_summary = json_object_new_object();
    json_object_object_add(local_summary, "available", json_object_new_boolean(
        runtime_status ? local_runtime_available :
        (local_radio_count > 0 || local_ssid_count > 0)));
    json_object_object_add(local_summary, "source_available",
                           json_object_new_boolean(local_source_available));
    json_object_object_add(local_summary, "radio_count",
                           json_object_new_int((int)local_radio_count));
    json_object_object_add(local_summary, "ssid_count",
                           json_object_new_int((int)local_ssid_count));
    if (!(local_radio_count || local_ssid_count)) {
        json_object_object_add(local_summary, "station_count",
                               json_object_new_int(0));
        json_object_object_add(local_summary, "station_count_reason",
                               json_object_new_string("no_phy_detected"));
    } else if (local_station_inventory) {
        json_object_object_add(local_summary, "station_count",
                               json_object_new_int((int)local_station_count));
        json_object_object_add(local_summary, "station_count_reason",
                               json_object_new_string("available"));
    } else {
        json_object_object_add(local_summary, "station_count",
                               json_object_new_null());
        json_object_object_add(local_summary, "station_count_reason",
                               json_object_new_string(
                                   "local_station_source_not_authoritative"));
    }
    json_object_object_add(local_summary, "reason", json_object_new_string(
        (runtime_status && wifi_string(runtime, "reason", "")[0]) ?
        wifi_string(runtime, "reason", "") :
        ((local_radio_count || local_ssid_count) ? "available" : "no_phy_detected")));
    json_object_object_add(data, "local_wifi", local_summary);

    sources = json_object_new_object();
    json_object_object_add(sources, "local", json_object_get(local_summary));
    json_object_object_add(sources, "managed", json_object_get(managed));
    json_object_object_add(data, "sources", sources);

    bands = wifi_collect_bands(radios);
    json_object_object_del(capabilities, "bands");
    json_object_object_add(capabilities, "bands", bands);
    wifi_capability_bool(capabilities, "wifi",
        json_object_array_length(radios) > 0 || json_object_array_length(ssids) > 0);
    wifi_capability_bool(capabilities, "local_wifi", local_radio_count > 0 || local_ssid_count > 0);
    wifi_capability_bool(capabilities, "managed_ap_inventory", ac_available);
    wifi_capability_bool(capabilities, "remote_telemetry", remote_snapshots > 0);
    wifi_capability_bool(capabilities, "remote_runtime_available", remote_fresh > 0);
    wifi_capability_bool(capabilities, "station_inventory", station_inventory);
    wifi_capability_bool(capabilities, "station_metrics", station_metrics);
    wifi_capability_bool(capabilities, "station_telemetry",
                         station_inventory && station_metrics);
    wifi_capability_bool(capabilities, "ap_radio_mapping", ap_radio_mapping);
    wifi_capability_reason(capabilities, "station_inventory",
        station_inventory ? "available" : station_inventory_reason);
    wifi_capability_reason(capabilities, "station_metrics",
        station_metrics ? "available" : station_metrics_reason);
    wifi_capability_reason(capabilities, "ap_radio_mapping",
        ap_radio_mapping ? "snapshot_resource_identity" :
                           "managed_ap_radio_snapshot_unavailable");
    wifi_capability_bool(capabilities, "channel_plan", 0);
    wifi_capability_bool(capabilities, "channel_ai", 0);
    wifi_capability_bool(capabilities, "connectivity_events", 0);
    wifi_capability_bool(capabilities, "roaming_history", 0);
    wifi_capability_bool(capabilities, "environment_scan", 0);
    /* channel_catalog is the read-only driver/regdb channel truth from
     * `iw phy` (per-radio channel_catalog objects pass through from the
     * APD snapshot).  channel_plan additionally requires exclusions and
     * plan transactions, so it stays false until those exist. */
    {
        int catalog_available = 0;
        size_t catalog_index;

        for (catalog_index = 0; radios &&
             catalog_index < json_object_array_length(radios);
             catalog_index++) {
            struct json_object *catalog = wifi_child_object(
                json_object_array_get_idx(radios, catalog_index),
                "channel_catalog");

            if (catalog && wifi_bool(catalog, "complete", 0)) {
                catalog_available = 1;
                break;
            }
        }
        wifi_capability_bool(capabilities, "channel_catalog",
                             catalog_available);
        wifi_capability_reason(capabilities, "channel_catalog",
            catalog_available ? "iw_phy_channel_catalog" :
                                "channel_catalog_not_reported");
    }
    wifi_capability_reason(capabilities, "channel_plan",
                           "regdomain_driver_channel_catalog_pending");
    wifi_capability_reason(capabilities, "channel_ai",
                           "channel_ai_producer_pending");
    wifi_capability_reason(capabilities, "connectivity_events",
                           "wifi_connectivity_event_store_pending");
    wifi_capability_reason(capabilities, "roaming_history",
                           "wifi_roaming_event_store_pending");
    wifi_capability_reason(capabilities, "environment_scan",
                           "neighbor_bssid_scan_producer_pending");
    wifi_collect_environment_samples(data, radios, capabilities);
    wifi_capability_bool(capabilities, "mixed_source",
        (local_radio_count > 0 || local_ssid_count > 0) && remote_snapshots > 0);
    wifi_capability_bool(capabilities, "runtime_status",
        local_runtime_available || remote_fresh > 0);
    wifi_capability_bool(capabilities, "radio_runtime",
        (runtime_status && local_radio_count > 0 && local_runtime_available) || remote_fresh > 0);
    wifi_capability_bool(capabilities, "read_config",
        local_source_available || desired_available || remote_snapshots > 0);
    if (ac_items && json_object_array_length(ac_items) > 0) {
        const char *const writes[] = {
            "save_config", "apply_config", "ssid_create", "ssid_update",
            "ssid_delete", "radio_update", "global_update", "scan", NULL
        };
        const char *const *write;

        for (write = writes; *write; write++) {
            wifi_capability_bool(capabilities, *write, 0);
            wifi_capability_reason(capabilities, *write,
                                   "managed_ap_transaction_pending");
        }
    }

    if (runtime_status) {
        int available = local_runtime_available || remote_fresh > 0;
        int complete = available &&
            (!local_runtime_available || wifi_bool(runtime, "complete", 0)) &&
            remote_complete;
        const char *reason;

        if (!available)
            reason = ac_items && json_object_array_length(ac_items) > 0 ?
                     "managed_aps_offline_stale_or_without_snapshot" :
                     "no_local_phy_or_managed_ap_runtime";
        else if (!complete)
            reason = "partial_runtime_sources";
        else
            reason = "available";
        wifi_replace_bool(runtime, "available", available);
        wifi_replace_bool(runtime, "supported", available || remote_snapshots > 0);
        wifi_replace_bool(runtime, "complete", complete);
        wifi_replace_string(runtime, "reason", reason);
        json_object_object_del(runtime, "radios");
        json_object_object_add(runtime, "radios", json_object_get(runtime_radios));
        json_object_object_del(runtime, "stations");
        json_object_object_add(runtime, "stations", json_object_get(stations));
    }

    summary = wifi_ensure_object(data, "summary");
    json_object_object_del(summary, "radio_count");
    json_object_object_add(summary, "radio_count", json_object_new_int(
        (int)json_object_array_length(radios)));
    json_object_object_del(summary, "ssid_count");
    json_object_object_add(summary, "ssid_count", json_object_new_int(
        (int)json_object_array_length(ssids)));
    json_object_object_del(summary, "station_count");
    json_object_object_del(summary, "clients");
    if (station_inventory) {
        json_object_object_add(summary, "station_count", json_object_new_int(
            (int)json_object_array_length(stations)));
        json_object_object_add(summary, "clients", json_object_new_int(
            (int)json_object_array_length(stations)));
    } else {
        json_object_object_add(summary, "station_count", json_object_new_null());
        json_object_object_add(summary, "clients", json_object_new_null());
        wifi_replace_string(summary, "station_count_reason",
                            station_inventory_reason);
        wifi_replace_string(summary, "clients_reason",
                            station_inventory_reason);
    }
    json_object_object_del(summary, "managed_ap_count");
    json_object_object_add(summary, "managed_ap_count", json_object_new_int(
        ac_items ? (int)json_object_array_length(ac_items) : 0));
    json_object_object_del(summary, "managed_ap_online");
    json_object_object_add(summary, "managed_ap_online",
                           json_object_new_int(managed_online));
    wifi_replace_string(summary, "source", "local+dreamingwrt-ac");
    return data;
}

struct json_object *webd_wifi_aggregate_data(struct json_object *local_response,
                                             struct json_object *ac_response,
                                             int runtime_status)
{
    return webd_wifi_aggregate_data_with_resolver(local_response, ac_response,
                                                   runtime_status, NULL);
}
