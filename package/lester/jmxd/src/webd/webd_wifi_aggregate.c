#include "webd_wifi_aggregate.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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

/* 802.11be allows at most 16 spatial streams per direction. */
#define WIFI_MAX_SPATIAL_STREAMS 16

/*
 * Copies one air-stats counter from the collector's block onto the radio.
 *
 * A measured 0 and an unread counter are different facts and must stay
 * different: apd already reports `Total PER = 0` as 0 and a firmware-disabled
 * counter as null with a reason, so this only forwards what it found. Turning a
 * null into 0 here would invent a measurement.
 */
static void wifi_air_stat_copy(struct json_object *radio,
                               struct json_object *air, const char *key)
{
    struct json_object *value = wifi_child(air, key);

    json_object_object_del(radio, key);
    if (value && (json_object_is_type(value, json_type_int) ||
                  json_object_is_type(value, json_type_double))) {
        json_object_object_add(radio, key, json_object_get(value));
        return;
    }
    json_object_object_add(radio, key, json_object_new_null());
}

/* The survey reason is produced by apd (`iw survey dump`). Promote it verbatim
 * so the UI shows why a driver withheld the sample instead of a generic text. */
static const char *wifi_survey_absence_reason(struct json_object *survey,
                                              const char *missing_survey,
                                              const char *missing_field)
{
    const char *reason;

    if (!survey)
        return missing_survey;
    reason = wifi_string(survey, "reason", "");
    return reason[0] ? reason : missing_field;
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

/*
 * QSDK writes a numeric band code into UCI (`option band '3'`), which is a
 * driver-internal encoding rather than anything a caller can interpret. It used
 * to be forwarded verbatim, so the UI rendered a band literally named "3".
 *
 * Only the codes actually observed on the managed AP are translated. An unknown
 * code returns "" rather than a guess: reporting no band is honest, while
 * mapping an unrecognised number onto a plausible band would put a wrong
 * frequency in front of the user.
 */
static const char *wifi_band_from_uci_code(const char *raw)
{
    if (!raw || !raw[0])
        return "";
    if (!strcmp(raw, "1"))
        return "2.4GHz";
    if (!strcmp(raw, "2"))
        return "5GHz";
    if (!strcmp(raw, "3"))
        return "6GHz";
    return "";
}

/*
 * True when `value` is one of the driver's numeric band codes rather than a
 * band name. Used to decide whether a desired-view band needs translating.
 */
static int wifi_band_is_uci_code(const char *raw)
{
    return raw && raw[0] && raw[1] == '\0' && raw[0] >= '0' && raw[0] <= '9';
}

/*
 * Finds the runtime radio that owns a desired-view radio id.
 *
 * The two views use different identifier spaces - desired uses UCI section
 * names (`wifi0`), runtime uses phy names (`phy1`) - so joining them by id is
 * wrong. What makes an exact join possible is that the runtime radio's
 * `interfaces[]` list contains the UCI section name itself: on the managed AP,
 * `phy1` lists `wifi0` alongside its `athN` VAPs. Verified on 31.31, where each
 * `wifiN` appears under exactly one phy:
 *
 *   phy1 -> ath05..ath0, wifi0     phy2 -> ath15..ath1, wifi1
 *   phy3 -> ath21, ath2,  wifi2    phy0 -> MLD1, mld-wifi0   (no wifiN)
 *
 * That also means the MLD pseudo-PHY cannot be matched by accident: it carries
 * no UCI section name at all.
 *
 * Returns NULL when there is no unambiguous match, so the caller can say the
 * views were not aligned instead of inventing values.
 */
static struct json_object *wifi_runtime_radio_for_desired(
        struct json_object *runtime_radios, const char *desired_id)
{
    struct json_object *match = NULL;
    size_t i, j;

    if (!runtime_radios || !desired_id || !desired_id[0])
        return NULL;
    for (i = 0; i < json_object_array_length(runtime_radios); i++) {
        struct json_object *radio = json_object_array_get_idx(runtime_radios, i);
        struct json_object *interfaces = wifi_child_array(radio, "interfaces");

        for (j = 0; interfaces && j < json_object_array_length(interfaces); j++) {
            struct json_object *iface = json_object_array_get_idx(interfaces, j);
            const char *name = wifi_string(iface, "interface", "");

            if (name[0] && !strcmp(name, desired_id)) {
                /* Two phys claiming one UCI section would make the join
                 * ambiguous; refuse rather than pick the first. */
                if (match && match != radio)
                    return NULL;
                match = radio;
            }
        }
    }
    return match;
}

/*
 * Fills band / width / tx_power on desired-view radios from the runtime
 * snapshot, and records where each value came from.
 *
 * The desired view is the UCI config, which simply has no width_mhz or
 * txpower_dbm field, so `wifi_normalize_aliases()` had nothing to alias and
 * both columns rendered empty. The values do exist - one level up, in the
 * runtime snapshot - so the fix is to merge them rather than to synthesise
 * anything.
 *
 * Every field that gets filled is attributed via `*_source`, and a radio that
 * could not be aligned gets an explicit reason. A caller must be able to tell a
 * measured value from a missing one without guessing.
 */
static void wifi_desired_merge_runtime(struct json_object *desired_radios,
                                       struct json_object *runtime_radios)
{
    size_t i;

    if (!desired_radios)
        return;
    for (i = 0; i < json_object_array_length(desired_radios); i++) {
        struct json_object *radio = json_object_array_get_idx(desired_radios, i);
        struct json_object *runtime;
        const char *raw_band;
        const char *id;

        if (!radio || !json_object_is_type(radio, json_type_object))
            continue;
        id = wifi_string(radio, "id", "");

        /*
         * Translate the driver band code first, so a radio keeps a usable band
         * even when no runtime match exists.
         */
        raw_band = wifi_string(radio, "band", "");
        if (wifi_band_is_uci_code(raw_band)) {
            const char *named = wifi_band_from_uci_code(raw_band);

            json_object_object_del(radio, "band");
            if (named[0]) {
                json_object_object_add(radio, "band",
                                       json_object_new_string(named));
                json_object_object_add(radio, "band_source",
                    json_object_new_string("uci_band_code"));
            } else {
                json_object_object_add(radio, "band_reason",
                    json_object_new_string("uci_band_code_unrecognised"));
            }
        }

        runtime = wifi_runtime_radio_for_desired(runtime_radios, id);
        if (!runtime) {
            /*
             * Do not overwrite a reason already set above. An unrecognised UCI
             * band code is a more specific explanation than "not aligned", and
             * clobbering it would replace the actual cause with a generic one.
             */
            if (!wifi_child(radio, "band") && !wifi_child(radio, "band_reason"))
                json_object_object_add(radio, "band_reason",
                    json_object_new_string(
                        runtime_radios ? "desired_not_aligned_to_runtime_radio" :
                                         "runtime_snapshot_unavailable"));
            if (!wifi_child(radio, "width") && !wifi_child(radio, "width_mhz") &&
                !wifi_child(radio, "width_reason"))
                json_object_object_add(radio, "width_reason",
                    json_object_new_string(
                        runtime_radios ? "desired_not_aligned_to_runtime_radio" :
                                         "runtime_snapshot_unavailable"));
            if (!wifi_child(radio, "tx_power") &&
                !wifi_child(radio, "txpower_dbm") &&
                !wifi_child(radio, "tx_power_reason"))
                json_object_object_add(radio, "tx_power_reason",
                    json_object_new_string(
                        runtime_radios ? "desired_not_aligned_to_runtime_radio" :
                                         "runtime_snapshot_unavailable"));
            continue;
        }

        json_object_object_add(radio, "runtime_radio_id",
            json_object_new_string(wifi_string(runtime, "id", "")));

        if (!wifi_child(radio, "band") && wifi_child(runtime, "band")) {
            json_object_object_add(radio, "band",
                json_object_get(wifi_child(runtime, "band")));
            json_object_object_add(radio, "band_source",
                json_object_new_string("managed_ap_runtime_snapshot"));
        }
        if (!wifi_child(radio, "width") && !wifi_child(radio, "width_mhz") &&
            wifi_child(runtime, "width_mhz")) {
            json_object_object_add(radio, "width_mhz",
                json_object_get(wifi_child(runtime, "width_mhz")));
            json_object_object_add(radio, "width_source",
                json_object_new_string("managed_ap_runtime_snapshot"));
        }
        /*
         * `channel` in the desired view is the UCI setting, which is literally
         * "auto" on any radio left on automatic selection. That is a real
         * configuration value, not a missing one, so it stays - but a caller
         * asking "which channel is this radio on" needs the operating channel
         * too, and the runtime snapshot has it (phy3 operates on 33 while UCI
         * says auto). Publish it separately so neither meaning is lost.
         */
        if (wifi_child(runtime, "channel")) {
            char desired_channel[32];

            /*
             * Copy before deleting: wifi_string() hands back a pointer into
             * the json object, and json_object_object_del() frees it, so
             * reading it afterwards is a use-after-free.
             */
            snprintf(desired_channel, sizeof(desired_channel), "%s",
                     wifi_string(radio, "channel", ""));

            if (!wifi_child(radio, "operating_channel")) {
                json_object_object_add(radio, "operating_channel",
                    json_object_get(wifi_child(runtime, "channel")));
                json_object_object_add(radio, "operating_channel_source",
                    json_object_new_string("managed_ap_runtime_snapshot"));
            }
            /*
             * Only an unusable desired channel gets replaced. Overwriting a
             * pinned channel would hide a mismatch between what was asked for
             * and what the radio actually does.
             */
            if (!desired_channel[0] || !strcmp(desired_channel, "auto") ||
                !strcmp(desired_channel, "0")) {
                json_object_object_del(radio, "channel");
                json_object_object_add(radio, "channel",
                    json_object_get(wifi_child(runtime, "channel")));
                json_object_object_add(radio, "channel_source",
                    json_object_new_string("managed_ap_runtime_snapshot"));
                if (desired_channel[0])
                    json_object_object_add(radio, "channel_desired",
                        json_object_new_string(desired_channel));
            }
        }
        if (!wifi_child(radio, "tx_power") &&
            !wifi_child(radio, "txpower_dbm") &&
            wifi_child(runtime, "txpower_dbm")) {
            json_object_object_add(radio, "txpower_dbm",
                json_object_get(wifi_child(runtime, "txpower_dbm")));
            json_object_object_add(radio, "tx_power_source",
                json_object_new_string("managed_ap_runtime_snapshot"));
        }
        /*
         * The runtime radio object itself carries no txpower_dbm, but its VAPs
         * do (`interfaces[].txpower_dbm` is 24 on every AP-type VAP of phy3).
         * A radio's transmit power is a property of the radio, so the VAP
         * readings are only usable when they agree; if two VAPs on one phy
         * report different power, there is no single radio-level answer and
         * saying so beats picking one.
         */
        if (!wifi_child(radio, "tx_power") &&
            !wifi_child(radio, "txpower_dbm")) {
            struct json_object *ifaces = wifi_child_array(runtime, "interfaces");
            struct json_object *found = NULL;
            int conflict = 0;
            size_t k;

            for (k = 0; ifaces && k < json_object_array_length(ifaces); k++) {
                struct json_object *iface =
                    json_object_array_get_idx(ifaces, k);
                struct json_object *power = wifi_child(iface, "txpower_dbm");

                if (!power)
                    continue;
                if (found && json_object_get_int(found) !=
                             json_object_get_int(power)) {
                    conflict = 1;
                    break;
                }
                if (!found)
                    found = power;
            }
            if (conflict)
                json_object_object_add(radio, "tx_power_reason",
                    json_object_new_string(
                        "managed_ap_vap_txpower_disagrees"));
            else if (found) {
                json_object_object_add(radio, "txpower_dbm",
                    json_object_get(found));
                json_object_object_add(radio, "tx_power_source",
                    json_object_new_string("managed_ap_runtime_vap_txpower"));
            }
        }
        /*
         * Neither the radio nor any of its VAPs reported power: say so instead
         * of leaving the field silently absent.
         */
        if (!wifi_child(radio, "tx_power") &&
            !wifi_child(radio, "txpower_dbm") &&
            !wifi_child(radio, "tx_power_reason"))
            json_object_object_add(radio, "tx_power_reason",
                json_object_new_string("managed_ap_reports_no_radio_txpower"));
    }
}

/*
 * Gives desired-view SSIDs the band of the radio they sit on.
 *
 * The UCI SSID sections carry no band field at all, so a caller had no way to
 * label an SSID by frequency without inferring one - which is exactly the
 * fabrication the companion frontend handoff reported. The relation is already
 * explicit and needs no guessing: an SSID's `radio_id` is the desired radio id
 * (`wifi0`), so once the radios have a band the SSIDs can inherit it.
 *
 * Must run after wifi_desired_merge_runtime(), otherwise the radios have no
 * band to inherit.
 */
static void wifi_desired_ssid_bands(struct json_object *desired_ssids,
                                    struct json_object *desired_radios)
{
    size_t i, j;

    if (!desired_ssids || !desired_radios)
        return;
    for (i = 0; i < json_object_array_length(desired_ssids); i++) {
        struct json_object *ssid = json_object_array_get_idx(desired_ssids, i);
        const char *radio_id;

        if (!ssid || !json_object_is_type(ssid, json_type_object))
            continue;
        if (wifi_child(ssid, "band"))
            continue;
        radio_id = wifi_string(ssid, "radio_id", "");
        if (!radio_id[0]) {
            json_object_object_add(ssid, "band_reason",
                json_object_new_string("ssid_has_no_radio_id"));
            continue;
        }
        for (j = 0; j < json_object_array_length(desired_radios); j++) {
            struct json_object *radio = json_object_array_get_idx(desired_radios, j);

            if (strcmp(wifi_string(radio, "id", ""), radio_id))
                continue;
            if (wifi_child(radio, "band")) {
                json_object_object_add(ssid, "band",
                    json_object_get(wifi_child(radio, "band")));
                json_object_object_add(ssid, "band_source",
                    json_object_new_string("inherited_from_radio"));
            } else {
                json_object_object_add(ssid, "band_reason",
                    json_object_new_string("radio_band_unavailable"));
            }
            break;
        }
        if (!wifi_child(ssid, "band") && !wifi_child(ssid, "band_reason"))
            json_object_object_add(ssid, "band_reason",
                json_object_new_string("radio_id_not_found_in_desired_radios"));
    }
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

static int wifi_number_positive(struct json_object *obj, const char *key)
{
    double value;

    return wifi_number(obj, key, &value) && value > 0.0;
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
        /*
         * Partial is not the same as absent.
         *
         * On QCA APs only the `global` hostapd control socket exists, so the
         * per-VAP station query fails on every BSS and `complete` is false
         * even though STATUS still yielded a full station list. Treating that
         * as "no data" discarded 30 rows that each carried a real signal
         * reading, and the wireless page showed no clients and a null average
         * signal for an AP with 30 associated stations.
         *
         * When rows are actually present we use them and keep the reason so
         * the payload still says the source was partial. Nothing is fabricated:
         * a missing row stays missing, it just no longer voids the rest.
         */
        if (wifi_number_positive(hostapd, "station_count")) {
            if (inventory) *inventory = 1;
            if (metrics) *metrics = 1;
            if (!reason[0] || !strcmp(reason, "available"))
                reason = "station_source_partial";
            if (inventory_reason) *inventory_reason = reason;
            if (metrics_reason) *metrics_reason = reason;
            return 1;
        }
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

/*
 * Does this station belong to this radio?
 *
 * `radio_id` is the direct answer when the collector supplies it. Managed-AP
 * snapshots do not: their station rows carry the VAP name (`ath01`) because
 * that is what hostapd and wlanconfig report, and the radio owns the
 * interface list that resolves it. Matching on `radio_id` alone made every
 * managed radio report 0 clients and a null average signal while 30 stations
 * with real signal values sat in the same payload.
 */
static int wifi_station_on_radio(struct json_object *station,
                                 struct json_object *radio,
                                 const char *radio_id)
{
    struct json_object *interfaces;
    const char *station_radio = wifi_string(station, "radio_id", "");
    const char *station_interface;
    size_t i;

    if (station_radio[0])
        return !strcmp(station_radio, radio_id);
    station_interface = wifi_string(station, "interface", "");
    if (!station_interface[0])
        return 0;
    interfaces = wifi_child_array(radio, "interfaces");
    for (i = 0; interfaces && i < json_object_array_length(interfaces); i++) {
        struct json_object *interface = json_object_array_get_idx(interfaces, i);

        if (!strcmp(wifi_string(interface, "interface", ""), station_interface))
            return 1;
    }
    return 0;
}

/*
 * Publishes the per-radio channel plan from the read-only `channel_catalog`.
 *
 * apd already builds that catalog from `iw phy` and the AC stores it as the
 * evidence `ac_wifi_validate_radio_change()` checks a requested channel
 * against, so the numbers below are the same ones a write is validated with.
 * webd nonetheless hardcoded `supported_channels` to null while separately
 * reading the catalog to raise `capabilities.channel_catalog`, so the payload
 * simultaneously claimed the catalog was available and reported no channels.
 *
 * Only forwarding happens here. `dfs_channels` comes from each entry's
 * `radar_detection` flag, and an empty result stays an empty array rather than
 * a null: "the driver listed no DFS channels" is a fact, distinct from "nobody
 * asked". `unavailable_channels`/`excluded_channels` remain null because the
 * catalog carries no evidence for either.
 */
static int wifi_publish_channel_plan(struct json_object *radio)
{
    struct json_object *catalog = wifi_child_object(radio, "channel_catalog");
    struct json_object *supported = catalog ?
        wifi_child_array(catalog, "supported_channels") : NULL;
    struct json_object *entries;
    struct json_object *dfs;
    struct json_object *copy;
    size_t i;

    if (!catalog || !supported || !wifi_bool(catalog, "complete", 0))
        return 0;
    copy = wifi_clone(supported);
    if (!copy)
        return 0;
    json_object_object_del(radio, "supported_channels");
    json_object_object_add(radio, "supported_channels", copy);

    dfs = json_object_new_array();
    entries = wifi_child_array(catalog, "channels");
    for (i = 0; dfs && entries && i < json_object_array_length(entries); i++) {
        struct json_object *entry = json_object_array_get_idx(entries, i);
        struct json_object *channel;

        if (!entry || !wifi_bool(entry, "radar_detection", 0))
            continue;
        channel = wifi_child(entry, "channel");
        if (channel && json_object_is_type(channel, json_type_int))
            json_object_array_add(dfs, json_object_get(channel));
    }
    if (dfs) {
        json_object_object_del(radio, "dfs_channels");
        json_object_object_add(radio, "dfs_channels", dfs);
    }

    wifi_replace_string(radio, "channel_plan_source",
                        wifi_string(catalog, "source", "iw_phy"));
    wifi_replace_string(radio, "channel_plan_regdomain",
                        wifi_string(catalog, "regdomain", ""));
    return 1;
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
        /*
         * Taken from the station rows that actually matched this radio, so a
         * managed AP that fell back to `wlanconfig` does not get reported as
         * `hostapd_control`.
         */
        const char *matched_source = NULL;
        /*
         * Highest spatial-stream count seen among this radio's stations.
         * `wlanconfig` reports RXNSS/TXNSS per station; a radio's usable MIMO
         * width is the best a client actually negotiated, so the maximum is
         * the honest summary rather than an average.
         */
        int max_rx_nss = 0;
        int max_tx_nss = 0;
        size_t j;

        for (j = 0; station_inventory && stations &&
                    j < json_object_array_length(stations); j++) {
            struct json_object *station = json_object_array_get_idx(stations, j);
            double signal;

            if (!wifi_station_on_radio(station, radio, radio_id))
                continue;
            clients++;
            if (!matched_source) {
                const char *row = wifi_string(station, "source", "");

                if (row[0])
                    matched_source = row;
            }
            if (station_metrics && wifi_number(station, "signal_dbm", &signal)) {
                signal_sum += signal;
                signals++;
            }
            {
                double nss;

                /*
                 * Spatial streams are bounded by the standard: 802.11be tops
                 * out at 16 per direction. A vendor tool that prints anything
                 * outside 1..16 is reporting garbage rather than a wider radio,
                 * so it is discarded instead of widening the reported MIMO.
                 * The bound also keeps the "RXxTX" formatting below provably
                 * within its buffer.
                 */
                if (wifi_number(station, "rx_nss", &nss) &&
                    nss >= 1.0 && nss <= WIFI_MAX_SPATIAL_STREAMS &&
                    (int)nss > max_rx_nss)
                    max_rx_nss = (int)nss;
                if (wifi_number(station, "tx_nss", &nss) &&
                    nss >= 1.0 && nss <= WIFI_MAX_SPATIAL_STREAMS &&
                    (int)nss > max_tx_nss)
                    max_tx_nss = (int)nss;
            }
        }
        if (station_inventory) {
            json_object_object_del(radio, "clients");
            json_object_object_add(radio, "clients", json_object_new_int(clients));
            wifi_replace_string(radio, "clients_source",
                                matched_source ? matched_source :
                                                 "hostapd_control");
        } else {
            wifi_replace_null(radio, "clients");
            wifi_replace_string(radio, "clients_reason", station_reason);
        }
        if (signals > 0) {
            json_object_object_del(radio, "avg_signal_dbm");
            json_object_object_add(radio, "avg_signal_dbm",
                                   json_object_new_double(signal_sum / signals));
            wifi_replace_string(radio, "avg_signal_source",
                                matched_source ? matched_source :
                                                 "hostapd_control");
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
        /* `iw dev` reports an effective dBm only; neither it nor the UCI
         * wifi-device sections carry an auto/manual selector, and the desired
         * radio ids (wifi0..n) cannot be mapped onto runtime phys, so there is
         * no honest source for a mode. */
        wifi_replace_string(radio, "tx_power_mode_reason",
                            "tx_power_mode_not_exposed_by_driver_or_uci");
        wifi_replace_null(radio, "history_24h");
        wifi_replace_string(radio, "history_24h_reason", "radio_history_not_collected");
        {
            struct json_object *survey = wifi_child_object(radio, "survey");
            struct json_object *utilization = wifi_child(survey, "utilization_pct");
            struct json_object *noise = wifi_child(survey, "noise_dbm");
            struct json_object *air = wifi_child_object(survey, "air_stats");
            /*
             * apd rewrites the survey source to `apstats_radio` when `iw survey
             * dump` came back empty and the vendor counters supplied the sample
             * instead. Publishing a hardcoded "iw_survey" regardless was the
             * same class of defect that started this investigation: a reported
             * source that had produced no data made an empty page look like an
             * empty environment. So the actual source is forwarded.
             */
            const char *survey_source = wifi_string(survey, "source", "iw_survey");

            /*
             * Accept int as well as double.
             *
             * apd emits this as a JSON double, but a whole-numbered percent
             * survives the ubus/json round trip as an integer (`3`, not
             * `3.0`), and a double-only check silently dropped it. That is why
             * the wireless page showed `iw_survey_unavailable` while the AC
             * payload already carried utilization 3 / 12 / 47 from
             * `apstats_radio`. The noise branch below already accepted both.
             */
            if (utilization &&
                (json_object_is_type(utilization, json_type_double) ||
                 json_object_is_type(utilization, json_type_int)) &&
                json_object_get_double(utilization) >= 0.0 &&
                json_object_get_double(utilization) <= 100.0) {
                double pct = json_object_get_double(utilization);

                json_object_object_del(radio, "channel_utilization_pct");
                json_object_object_add(radio, "channel_utilization_pct",
                                       json_object_new_double(pct));
                /* Both frontends read `channel_utilization`; publish the same
                 * percent scale under both names rather than a second unit. */
                json_object_object_del(radio, "channel_utilization");
                json_object_object_add(radio, "channel_utilization",
                                       json_object_new_double(pct));
                wifi_replace_string(radio, "channel_utilization_source",
                                    survey_source);
            } else {
                wifi_replace_null(radio, "channel_utilization_pct");
                wifi_replace_null(radio, "channel_utilization");
                wifi_replace_string(radio, "channel_utilization_source",
                                    survey ? "iw_survey_unavailable" :
                                             "channel_survey_not_reported");
                wifi_replace_string(radio, "channel_utilization_reason",
                    wifi_survey_absence_reason(survey,
                                               "channel_survey_not_reported",
                                               "channel_utilization_not_sampled"));
            }
            if (noise && (json_object_is_type(noise, json_type_int) ||
                          json_object_is_type(noise, json_type_double))) {
                json_object_object_del(radio, "noise_dbm");
                json_object_object_add(radio, "noise_dbm",
                                       json_object_new_double(
                                           json_object_get_double(noise)));
                wifi_replace_string(radio, "noise_source", survey_source);
            } else {
                wifi_replace_null(radio, "noise_dbm");
                wifi_replace_string(radio, "noise_source",
                                    survey ? "iw_survey_unavailable" :
                                             "channel_survey_not_reported");
                wifi_replace_string(radio, "noise_reason",
                    wifi_survey_absence_reason(survey,
                                               "channel_survey_not_reported",
                                               "noise_floor_not_reported_by_driver"));
            }
            /*
             * Air statistics are collected onto the survey object, but the
             * wireless page reads them at `radio.air_stats`, so the block is
             * republished there. Without this the vendor collector works and the
             * table still shows nothing.
             */
            if (air) {
                static const char *const counters[] = {
                    "tx_packets", "tx_bytes", "rx_packets", "rx_bytes",
                    "tx_failures", "dropped", "retries", "rx_phy_errors",
                    "rx_crc_errors", "total_per_pct", "retry_rate_pct",
                    "self_bss_util_pct", "obss_util_pct", "noise_floor_dbm",
                    NULL
                };
                struct json_object *published = json_object_new_object();
                size_t i;

                if (published) {
                    for (i = 0; counters[i]; i++)
                        wifi_air_stat_copy(published, air, counters[i]);
                    /* Provenance travels with the numbers: a table that cannot
                     * say where a figure came from cannot be audited. */
                    wifi_replace_string(published, "source",
                                        wifi_string(air, "source", ""));
                    wifi_replace_bool(published, "available",
                                      wifi_bool(air, "available", 0));
                    wifi_replace_string(published, "interface",
                                        wifi_string(air, "interface", ""));
                    wifi_replace_string(published, "reason",
                                        wifi_string(air, "reason", ""));
                    /*
                     * Radio-level `apstats` prints no Retries line, so `retries`
                     * is null here. tx_failures is deliberately NOT copied into
                     * it: a transmit failure is not a retry, and relabelling one
                     * as the other would put a real number under a heading it
                     * does not belong to. The UI shows a dash, which is true.
                     */
                    wifi_replace_bool(published,
                                      "firmware_disabled_channel_utilization",
                        wifi_bool(air, "firmware_disabled_channel_utilization", 0));
                    wifi_replace_bool(published, "firmware_disabled_throughput",
                        wifi_bool(air, "firmware_disabled_throughput", 0));
                    json_object_object_del(radio, "air_stats");
                    json_object_object_add(radio, "air_stats", published);
                }
                /* The page also reads a flat `retry_rate`. */
                json_object_object_del(radio, "retry_rate");
                {
                    struct json_object *rate = wifi_child(air, "retry_rate_pct");

                    if (rate && (json_object_is_type(rate, json_type_double) ||
                                 json_object_is_type(rate, json_type_int)))
                        json_object_object_add(radio, "retry_rate",
                                               json_object_get(rate));
                    else
                        json_object_object_add(radio, "retry_rate",
                                               json_object_new_null());
                }
            } else {
                wifi_replace_null(radio, "air_stats");
                wifi_replace_null(radio, "retry_rate");
                wifi_replace_string(radio, "air_stats_reason",
                                    survey ? "air_statistics_not_collected" :
                                             "channel_survey_not_reported");
            }
            /*
             * Interference is the airtime other networks occupy on this
             * channel, which is exactly what `apstats` reports as OBSS
             * utilization. It is taken from the same vendor counter block as
             * `channel_utilization_pct` rather than derived from neighbor-scan
             * RSSI: a count of audible BSSIDs says how many neighbours exist,
             * not how much air they consume, and converting signal strength
             * into a percentage would be a fabricated unit.
             *
             * Self-BSS airtime is deliberately excluded. Traffic this radio
             * generates is load, not interference, and folding it in would make
             * a busy AP with no neighbours look congested by other networks.
             */
            {
                struct json_object *obss = wifi_child(air, "obss_util_pct");

                if (obss && (json_object_is_type(obss, json_type_double) ||
                             json_object_is_type(obss, json_type_int))) {
                    json_object_object_del(radio, "avg_interference_pct");
                    json_object_object_add(radio, "avg_interference_pct",
                                           json_object_get(obss));
                    wifi_replace_string(radio, "avg_interference_source",
                                        survey_source);
                    json_object_object_del(radio, "avg_interference_reason");
                } else {
                    wifi_replace_null(radio, "avg_interference_pct");
                    wifi_replace_string(radio, "avg_interference_reason",
                        air ? "obss_utilization_not_reported" :
                              "interference_telemetry_not_collected");
                }
            }
        }
        /*
         * Reported as RXxTX (e.g. "2x2") when the station rows carry spatial
         * stream counts. Only hostapd lacks them; the vendor `wlanconfig` path
         * has RXNSS/TXNSS columns, so this stays null on a mac80211 AP and
         * fills in on a QCA one instead of claiming "not reported" everywhere.
         */
        if (max_rx_nss > 0 && max_tx_nss > 0) {
            char mimo[16];

            /*
             * Re-clamped at the point of use. The ingest filter above already
             * rejects out-of-range streams, but restating the bound here keeps
             * the format provably in-buffer without depending on the optimizer
             * to track the range across the station loop.
             */
            int rx = max_rx_nss > WIFI_MAX_SPATIAL_STREAMS ?
                     WIFI_MAX_SPATIAL_STREAMS : max_rx_nss;
            int tx = max_tx_nss > WIFI_MAX_SPATIAL_STREAMS ?
                     WIFI_MAX_SPATIAL_STREAMS : max_tx_nss;

            snprintf(mimo, sizeof(mimo), "%dx%d", rx, tx);
            wifi_replace_string(radio, "mimo", mimo);
            wifi_replace_string(radio, "mimo_source",
                                matched_source ? matched_source : "station_nss");
            json_object_object_del(radio, "mimo_reason");
        } else {
            wifi_replace_null(radio, "mimo");
            wifi_replace_string(radio, "mimo_reason",
                clients > 0 ? "station_spatial_streams_not_reported" :
                              "spatial_streams_not_reported");
        }
        wifi_replace_null(radio, "uplink_type");
        wifi_replace_string(radio, "uplink_type_reason", "ap_uplink_not_reported");
        /*
         * The catalog is authoritative for what the driver and regdomain
         * permit; exclusions and plan transactions are a separate producer, so
         * those two stay null with their own reason even when it is present.
         */
        if (wifi_publish_channel_plan(radio)) {
            wifi_replace_string(radio, "channel_plan_reason", "available");
        } else {
            wifi_replace_null(radio, "supported_channels");
            wifi_replace_null(radio, "dfs_channels");
            wifi_replace_string(radio, "channel_plan_reason",
                                "regdomain_driver_channel_catalog_pending");
        }
        wifi_replace_null(radio, "unavailable_channels");
        wifi_replace_null(radio, "excluded_channels");
        wifi_replace_string(radio, "channel_exclusion_reason",
                            "channel_exclusion_producer_pending");
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

/*
 * BSSID vendor enrichment.
 *
 * apd cannot resolve a vendor: the OUI table lives on the controller, not on
 * the AP, so every scanned neighbour arrives with vendor=null and
 * vendor_reason="controller_enrichment_pending". This is the controller side of
 * that contract. The lookup is deliberately self-contained instead of calling
 * jmx_ht_match_mac(): that symbol lives in jmx_hosttype.o, which is linked into
 * dreamingwrt-core but not into webd, and pulling it in would drag the core's
 * logging and signature plumbing into this translation unit.
 *
 * The table is nmap's, already shipped for client identification, and is loaded
 * once on first use. webd is a single-threaded uloop process, so the cache
 * needs no lock.
 */
#define WIFI_OUI_TABLE_PATH "/usr/share/nmap/nmap-mac-prefixes"

struct wifi_oui_entry {
    uint32_t prefix;    /* first three MAC bytes, big-endian */
    const char *vendor; /* points into wifi_oui_strings */
};

static struct wifi_oui_entry *wifi_oui_entries;
static char *wifi_oui_strings;
static size_t wifi_oui_count;
static int wifi_oui_load_attempted;

static const char *wifi_oui_table_path(void)
{
    const char *override = getenv("DREAMINGWRT_OUI_PREFIX_PATH");

    return override && override[0] ? override : WIFI_OUI_TABLE_PATH;
}

static int wifi_oui_entry_cmp(const void *a, const void *b)
{
    uint32_t left = ((const struct wifi_oui_entry *)a)->prefix;
    uint32_t right = ((const struct wifi_oui_entry *)b)->prefix;

    if (left < right)
        return -1;
    return left > right ? 1 : 0;
}

/* Splits "AABBCC Vendor Name" into its prefix and a trimmed vendor name. */
static int wifi_oui_parse_line(char *line, uint32_t *prefix, char **vendor,
                               size_t *vendor_len)
{
    unsigned int bytes[3];
    char *space = strchr(line, ' ');
    size_t length;

    if (!space || space - line != 6)
        return 0;
    if (sscanf(line, "%2x%2x%2x", &bytes[0], &bytes[1], &bytes[2]) != 3)
        return 0;
    space++;
    while (*space == ' ' || *space == '\t')
        space++;
    length = strlen(space);
    while (length > 0 && (space[length - 1] == '\n' || space[length - 1] == '\r' ||
                          space[length - 1] == ' ' || space[length - 1] == '\t'))
        length--;
    if (length == 0)
        return 0;
    *prefix = ((uint32_t)bytes[0] << 16) | ((uint32_t)bytes[1] << 8) |
              (uint32_t)bytes[2];
    *vendor = space;
    *vendor_len = length;
    return 1;
}

static void wifi_oui_table_release(void)
{
    free(wifi_oui_entries);
    wifi_oui_entries = NULL;
    free(wifi_oui_strings);
    wifi_oui_strings = NULL;
    wifi_oui_count = 0;
}

static void wifi_oui_table_load(void)
{
    const char *path = wifi_oui_table_path();
    FILE *file;
    char line[256];
    size_t rows = 0;
    size_t bytes = 0;
    char *pool;
    size_t loaded = 0;

    wifi_oui_load_attempted = 1;
    file = fopen(path, "r");
    if (!file)
        return;
    while (fgets(line, sizeof(line), file)) {
        uint32_t prefix;
        char *vendor;
        size_t vendor_len;

        if (!wifi_oui_parse_line(line, &prefix, &vendor, &vendor_len))
            continue;
        rows++;
        bytes += vendor_len + 1;
    }
    if (rows == 0) {
        fclose(file);
        return;
    }
    wifi_oui_entries = calloc(rows, sizeof(*wifi_oui_entries));
    wifi_oui_strings = malloc(bytes);
    if (!wifi_oui_entries || !wifi_oui_strings) {
        fclose(file);
        wifi_oui_table_release();
        return;
    }
    rewind(file);
    pool = wifi_oui_strings;
    while (fgets(line, sizeof(line), file) && loaded < rows) {
        uint32_t prefix;
        char *vendor;
        size_t vendor_len;

        if (!wifi_oui_parse_line(line, &prefix, &vendor, &vendor_len))
            continue;
        memcpy(pool, vendor, vendor_len);
        pool[vendor_len] = '\0';
        wifi_oui_entries[loaded].prefix = prefix;
        wifi_oui_entries[loaded].vendor = pool;
        pool += vendor_len + 1;
        loaded++;
    }
    fclose(file);
    if (loaded == 0) {
        wifi_oui_table_release();
        return;
    }
    qsort(wifi_oui_entries, loaded, sizeof(*wifi_oui_entries),
          wifi_oui_entry_cmp);
    wifi_oui_count = loaded;
}

static const char *wifi_oui_lookup(uint32_t prefix)
{
    size_t low = 0;
    size_t high;

    if (!wifi_oui_load_attempted)
        wifi_oui_table_load();
    if (!wifi_oui_entries || wifi_oui_count == 0)
        return NULL;
    high = wifi_oui_count - 1;
    while (low <= high) {
        size_t mid = low + (high - low) / 2;
        uint32_t have = wifi_oui_entries[mid].prefix;

        if (have == prefix)
            return wifi_oui_entries[mid].vendor;
        if (have < prefix)
            low = mid + 1;
        else if (mid == 0)
            break;
        else
            high = mid - 1;
    }
    return NULL;
}

/* Parses the first three bytes of "aa:bb:cc:dd:ee:ff". */
static int wifi_bssid_prefix(const char *bssid, uint32_t *prefix)
{
    unsigned int bytes[3];

    if (!bssid || !prefix)
        return 0;
    if (sscanf(bssid, "%2x:%2x:%2x", &bytes[0], &bytes[1], &bytes[2]) != 3)
        return 0;
    *prefix = ((uint32_t)bytes[0] << 16) | ((uint32_t)bytes[1] << 8) |
              (uint32_t)bytes[2];
    return 1;
}

/*
 * Fills the row's vendor from the OUI table and keeps vendor_reason honest: a
 * randomised BSSID stays unresolvable by definition, and a real prefix the
 * table does not carry is a different fact from "not implemented yet".
 *
 * The row always ends up carrying a vendor key. wifi_environment_copy() drops
 * a JSON null, so apd's explicit "vendor": null would otherwise vanish from the
 * row and read as a field nobody ever reported.
 */
static void wifi_environment_resolve_vendor(struct json_object *row,
                                            struct json_object *item,
                                            const char *bssid)
{
    uint32_t prefix = 0;
    const char *vendor;

    if (wifi_string(item, "vendor", "")[0])
        return;
    if (wifi_bool(item, "locally_administered", 0)) {
        /* Randomised BSSID: apd's reason is already terminal, keep it. */
        wifi_replace_null(row, "vendor");
        return;
    }
    if (!wifi_bssid_prefix(bssid, &prefix)) {
        wifi_replace_null(row, "vendor");
        wifi_replace_string(row, "vendor_reason", "bssid_unparsable");
        return;
    }
    vendor = wifi_oui_lookup(prefix);
    if (vendor && vendor[0]) {
        wifi_replace_string(row, "vendor", vendor);
        wifi_replace_string(row, "vendor_reason", "oui_prefix_match");
        return;
    }
    wifi_replace_null(row, "vendor");
    wifi_replace_string(row, "vendor_reason",
                        wifi_oui_count ? "oui_prefix_not_in_table" :
                                         "oui_table_unavailable");
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
    wifi_environment_resolve_vendor(row, item, bssid);
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
    /*
     * TX retry ("TX n") history starts denied here and is flipped later by
     * webd_wifi_merge_tx_retry_history() once ac_radio_tx_retry_bucket actually
     * returns two or more differenced samples for a radio. This is the default,
     * not the verdict: the scan-capability pass runs before the history query,
     * so leaving it true here would advertise a chart that may have no rows.
     */
    wifi_capability_bool(capabilities, "tx_n_history", 0);
    wifi_replace_string(reasons, "tx_n_history",
                        "tx_retry_history_not_queried");
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
        /*
         * `history_24h` is the same series the radio card draws, so it has to
         * come from the same buckets rather than staying null with a
         * "not collected" reason once the producer is live. A single point is
         * not a series: below two complete numeric samples the field stays null
         * and keeps a reason, which is what the AC's own warming_up state means.
         */
        if (complete_numeric_count >= 2) {
            json_object_object_del(radio, "history_24h");
            json_object_object_add(radio, "history_24h",
                                   json_object_get(history));
            wifi_replace_string(radio, "history_24h_source",
                                "ac_radio_survey_bucket");
            json_object_object_del(radio, "history_24h_reason");
            json_object_object_add(radio, "history_24h_reason",
                                   json_object_new_null());
        } else {
            wifi_replace_null(radio, "history_24h");
            wifi_replace_string(radio, "history_24h_reason",
                match_count > 0 ? "survey_history_warming_up" :
                                  "survey_history_empty");
        }
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

/* Projects one `tx_retry_history` bucket onto the radio series. Only the
 * differenced fields are published: `retry_rate_pct` is derived from the two
 * deltas inside the bucket, so a point without them cannot be plotted. */
static struct json_object *wifi_tx_retry_history_output_point(
    struct json_object *source)
{
    struct json_object *timestamp = wifi_child(source, "timestamp");
    struct json_object *source_name = wifi_child(source, "source");
    struct json_object *point;
    double value;
    double rate;
    int has_value = wifi_number(source, "value", &value);
    int has_rate = wifi_number(source, "retry_rate_pct", &rate);
    double tx_total_delta = 0.0;
    double tx_retries_delta = 0.0;
    int has_totals = wifi_number(source, "tx_total_delta", &tx_total_delta) &&
                     wifi_number(source, "tx_retries_delta", &tx_retries_delta);

    if (!timestamp || (!has_value && !has_rate))
        return NULL;
    point = json_object_new_object();
    if (!point)
        return NULL;
    if (!has_value)
        value = rate;
    if (!has_rate)
        rate = value;
    json_object_object_add(point, "timestamp", json_object_get(timestamp));
    json_object_object_add(point, "value", json_object_new_double(value));
    json_object_object_add(point, "retry_rate_pct",
                           json_object_new_double(rate));
    json_object_object_add(point, "tx_total_delta", has_totals ?
        json_object_new_int64((int64_t)tx_total_delta) : json_object_new_null());
    json_object_object_add(point, "tx_retries_delta", has_totals ?
        json_object_new_int64((int64_t)tx_retries_delta) :
        json_object_new_null());
    json_object_object_add(point, "source",
        source_name && json_object_is_type(source_name, json_type_string) ?
        json_object_get(source_name) : json_object_new_null());
    json_object_object_add(point, "complete",
                           json_object_new_boolean(
                               wifi_bool(source, "complete", 0)));
    return point;
}

/*
 * Joins `dreamingwrt.ac tx_retry_history` onto data.radios[].tx_retry_history
 * and decides the `tx_n_history` capability from what actually came back.
 *
 * The bit is the whole point of this function. It used to be hardcoded false
 * with a reason saying the series was never persisted, and a hardcoded true
 * would be just as wrong the other way: the page would draw an empty chart
 * while the producer is still warming up. Two complete differenced buckets for
 * at least one radio is the threshold, matching the AC's own `available`
 * verdict, so the bit flips on its own once real samples land.
 */
void webd_wifi_merge_tx_retry_history(struct json_object *data,
                                      struct json_object *response)
{
    struct json_object *radios;
    struct json_object *capabilities;
    struct json_object *root = wifi_response_root(response);
    struct json_object *points = wifi_child_array(root, "points");
    const char *response_reason = wifi_string(root, "reason", "");
    const char *reason;
    int any_mapped_point = 0;
    int history_available = 0;
    size_t radio_index;

    if (!data || !json_object_is_type(data, json_type_object))
        return;
    radios = wifi_ensure_array(data, "radios");
    capabilities = wifi_ensure_object(data, "capabilities");

    for (radio_index = 0; radio_index < json_object_array_length(radios);
         radio_index++) {
        struct json_object *radio = json_object_array_get_idx(radios,
                                                             radio_index);
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

            /* Same ap_id/radio_id join as the survey series, including the
             * local_id spelling used for radios on the controller itself. */
            if (!source || !json_object_is_type(source, json_type_object) ||
                !wifi_survey_history_radio_matches(radio, source))
                continue;
            timestamp = wifi_child(source, "timestamp");
            if (!timestamp ||
                (!json_object_is_type(timestamp, json_type_int) &&
                 !json_object_is_type(timestamp, json_type_double)) ||
                (!wifi_number(source, "value", &value) &&
                 !wifi_number(source, "retry_rate_pct", &value)))
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
            struct json_object *point = wifi_tx_retry_history_output_point(
                matches[point_index].source);

            if (point)
                json_object_array_add(history, point);
        }
        free(matches);
        json_object_object_del(radio, "tx_retry_history");
        json_object_object_add(radio, "tx_retry_history", history);
        if (match_count > 0)
            any_mapped_point = 1;
        if (complete_numeric_count >= 2)
            history_available = 1;
    }

    /*
     * Reasons are deliberately specific about which link in the chain is
     * missing, because "unavailable" alone sent acceptance looking in the wrong
     * place twice: an AP whose driver has no cumulative retry counter looks
     * identical to a controller that was never asked.
     */
    if (history_available)
        reason = "available";
    else if (!root)
        reason = "tx_retry_source_unavailable";
    else if (!points || json_object_array_length(points) == 0)
        reason = response_reason[0] && strcmp(response_reason, "available") ?
                 response_reason : "tx_retry_history_empty";
    else if (!any_mapped_point)
        reason = "tx_retry_history_radio_mapping_unavailable";
    else
        reason = "tx_retry_history_warming_up";
    wifi_capability_bool(capabilities, "tx_n_history", history_available);
    wifi_capability_reason(capabilities, "tx_n_history", reason);
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

/* Reads a capability bit that was already published, so scope reporting can
 * follow the flat bits instead of duplicating the logic that produced them. */
static int wifi_capability_true(struct json_object *capabilities,
                                const char *key)
{
    struct json_object *value = NULL;

    if (!capabilities || !key ||
        !json_object_object_get_ex(capabilities, key, &value) || !value)
        return 0;
    return json_object_get_boolean(value) ? 1 : 0;
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

/* Lower-cases a MAC and drops separators so the two inventories can be
 * compared regardless of how each side formats the address. Returns 0 when the
 * result is not a 12-hex-digit address, which keeps malformed values from
 * matching each other by accident. */
static int wifi_mac_key(const char *mac, char *out, size_t out_len)
{
    size_t n = 0;

    if (!mac || !out || out_len < 13)
        return 0;
    for (; *mac; mac++) {
        unsigned char c = (unsigned char)*mac;

        if (c == ':' || c == '-' || c == '.')
            continue;
        if (c >= '0' && c <= '9')
            ;
        else if (c >= 'a' && c <= 'f')
            ;
        else if (c >= 'A' && c <= 'F')
            c = (unsigned char)(c - 'A' + 'a');
        else
            return 0;
        if (n >= 12)
            return 0;
        out[n++] = (char)c;
    }
    out[n] = '\0';
    return n == 12;
}

static struct json_object *wifi_client_rows(struct json_object *clients_response)
{
    struct json_object *root;
    struct json_object *rows;

    if (!wifi_response_available(clients_response))
        return NULL;
    root = wifi_response_root(clients_response);
    rows = wifi_child_array(root, "clients");
    if (!rows)
        rows = wifi_child_array(root, "devices");
    return rows;
}

/* Picks the client row for a station MAC. Exact match only: guessing across
 * near-miss addresses would attach one device's name and photo to another. */
static struct json_object *wifi_client_for_mac(struct json_object *rows,
                                               const char *station_key)
{
    size_t i;

    for (i = 0; rows && i < json_object_array_length(rows); i++) {
        struct json_object *row = json_object_array_get_idx(rows, i);
        char key[16];

        if (!row || !json_object_is_type(row, json_type_object))
            continue;
        if (!wifi_mac_key(wifi_string(row, "mac", ""), key, sizeof(key)))
            continue;
        if (!strcmp(key, station_key))
            return row;
    }
    return NULL;
}

/*
 * Attaches the client-inventory identity to each station so the App can list
 * an AP's clients and jump to the device detail page without doing its own MAC
 * matching. Only identity fields are copied; the Wi-Fi metrics already on the
 * station are left untouched.
 *
 * Every station gets identity_available plus, when false, identity_reason, so a
 * station the client inventory does not know about is visibly unresolved
 * instead of silently carrying its MAC as a display name.
 */
void webd_wifi_merge_station_identity(struct json_object *data,
                                      struct json_object *clients_response)
{
    struct json_object *stations = wifi_child_array(data, "stations");
    struct json_object *rows = wifi_client_rows(clients_response);
    const char *source_reason = rows ? "station_mac_not_in_client_inventory" :
                                       "client_inventory_unavailable";
    size_t i;

    for (i = 0; stations && i < json_object_array_length(stations); i++) {
        struct json_object *station = json_object_array_get_idx(stations, i);
        struct json_object *client;
        struct json_object *fingerprint;
        const char *mac;
        const char *name;
        const char *image_url;
        char key[16];

        if (!station || !json_object_is_type(station, json_type_object))
            continue;
        mac = wifi_string(station, "mac", wifi_string(station, "client_mac", ""));
        /* Publish the address the App should align on, normalized to the
         * colon-separated lower-case form /api/v1/clients uses. */
        if (wifi_mac_key(mac, key, sizeof(key))) {
            char pretty[18];

            snprintf(pretty, sizeof(pretty),
                     "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
                     key[0], key[1], key[2], key[3], key[4], key[5],
                     key[6], key[7], key[8], key[9], key[10], key[11]);
            wifi_replace_string(station, "mac", pretty);
        } else {
            wifi_replace_null(station, "mac");
            wifi_replace_string(station, "mac_reason", "station_mac_not_reported");
            wifi_replace_bool(station, "identity_available", 0);
            wifi_replace_string(station, "identity_reason",
                                "station_mac_not_reported");
            continue;
        }
        client = wifi_client_for_mac(rows, key);
        if (!client) {
            wifi_replace_bool(station, "identity_available", 0);
            wifi_replace_string(station, "identity_reason", source_reason);
            wifi_replace_null(station, "display_name");
            wifi_replace_null(station, "hostname");
            wifi_replace_null(station, "image_url");
            wifi_replace_string(station, "identity_source", "unavailable");
            continue;
        }
        fingerprint = wifi_child_object(client, "fingerprint");
        name = wifi_first_nonempty(wifi_string(client, "name", ""),
                                   wifi_string(client, "display_name", ""),
                                   wifi_string(client, "hostname", ""));
        image_url = wifi_string(client, "image_url", "");
        wifi_replace_bool(station, "identity_available", 1);
        wifi_replace_string(station, "identity_source", "client_inventory");
        if (name[0])
            wifi_replace_string(station, "display_name", name);
        else {
            wifi_replace_null(station, "display_name");
            wifi_replace_string(station, "display_name_reason",
                                "client_row_without_name");
        }
        if (wifi_string(client, "hostname", "")[0])
            wifi_replace_string(station, "hostname",
                                wifi_string(client, "hostname", ""));
        else {
            wifi_replace_null(station, "hostname");
            wifi_replace_string(station, "hostname_reason",
                                "client_hostname_not_reported");
        }
        if (image_url[0]) {
            wifi_replace_string(station, "image_url", image_url);
            wifi_replace_string(station, "image_source",
                                wifi_string(client, "image_source",
                                            "client_inventory"));
        } else {
            wifi_replace_null(station, "image_url");
            wifi_replace_string(station, "image_reason",
                                "client_image_not_resolved");
        }
        if (wifi_string(client, "ip", "")[0])
            wifi_replace_string(station, "ip", wifi_string(client, "ip", ""));
        if (fingerprint) {
            struct json_object *out = json_object_new_object();
            const char *device_name = wifi_string(fingerprint, "device_name", "");
            const char *vendor = wifi_string(fingerprint, "vendor_name", "");
            const char *device_type = wifi_string(fingerprint, "device_type", "");

            if (device_name[0])
                json_object_object_add(out, "device_name",
                                       json_object_new_string(device_name));
            else {
                json_object_object_add(out, "device_name", json_object_new_null());
                json_object_object_add(out, "device_name_reason",
                    json_object_new_string("fingerprint_model_unresolved"));
            }
            if (vendor[0])
                json_object_object_add(out, "vendor_name",
                                       json_object_new_string(vendor));
            if (device_type[0])
                json_object_object_add(out, "device_type",
                                       json_object_new_string(device_type));
            json_object_object_del(station, "fingerprint");
            json_object_object_add(station, "fingerprint", out);
        } else {
            json_object_object_del(station, "fingerprint");
            wifi_replace_null(station, "fingerprint");
            wifi_replace_string(station, "fingerprint_reason",
                                "client_row_without_fingerprint");
        }
    }
    if (stations) {
        struct json_object *capabilities = wifi_ensure_object(data, "capabilities");

        wifi_capability_bool(capabilities, "station_identity", rows ? 1 : 0);
        wifi_capability_reason(capabilities, "station_identity",
                               rows ? "available" : "client_inventory_unavailable");
    }
}

/*
 * Airtime aggregates rolled up from whatever radios actually reported, local or
 * managed. The previous implementation derived these from the local survey
 * alone, which is permanently null on an x86 router with no phy, while the
 * managed AP's values sat unused in the same response. Radios carry
 * `channel_utilization_pct` / `noise_dbm` / `retry_rate` already decorated by
 * wifi_decorate_radio_metrics, so the roll-up reads those instead of
 * re-deriving from survey internals.
 *
 * `sample_source` is set to the source that produced the samples so the caller
 * can say where a number came from rather than asserting a tool that ran dry.
 * Counts stay separate from values: zero samples yields null, never 0.
 */
struct wifi_airtime_rollup {
    double utilization_sum;
    int utilization_samples;
    double retry_sum;
    int retry_samples;
    double worst_noise;
    int noise_samples;
    double signal_sum;
    int signal_samples;
    int local_samples;
    int managed_samples;
};

static void wifi_airtime_rollup_radio(struct json_object *radio,
                                      struct wifi_airtime_rollup *roll)
{
    double value;
    int counted = 0;

    if (!radio || !roll)
        return;
    if (wifi_number(radio, "channel_utilization_pct", &value) &&
        value >= 0.0 && value <= 100.0) {
        roll->utilization_sum += value;
        roll->utilization_samples++;
        counted = 1;
    }
    if (wifi_number(radio, "retry_rate", &value) &&
        value >= 0.0 && value <= 100.0) {
        roll->retry_sum += value;
        roll->retry_samples++;
        counted = 1;
    }
    /* Worst noise is the least negative floor, i.e. the noisiest radio. */
    if (wifi_number(radio, "noise_dbm", &value) && value < 0.0) {
        if (roll->noise_samples == 0 || value > roll->worst_noise)
            roll->worst_noise = value;
        roll->noise_samples++;
        counted = 1;
    }
    if (wifi_number(radio, "avg_signal_dbm", &value) && value < 0.0) {
        roll->signal_sum += value;
        roll->signal_samples++;
        counted = 1;
    }
    if (!counted)
        return;
    if (!strcmp(wifi_string(radio, "source", ""), "managed_ap"))
        roll->managed_samples++;
    else
        roll->local_samples++;
}

static void wifi_summary_replace_double(struct json_object *summary,
                                        const char *key, int have,
                                        double value)
{
    json_object_object_del(summary, key);
    json_object_object_add(summary, key, have ?
        json_object_new_double(value) : json_object_new_null());
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
    /*
     * Which side produced the reason currently held in
     * `station_inventory_reason`. Without this the summary published a string
     * like `per_interface_control_unavailable` with no indication whether it
     * described this router or the managed AP, and a reason about the local
     * hostapd channel read as an explanation for an empty remote client list.
     */
    const char *station_inventory_reason_scope = "unknown";
    const char *station_metrics_reason_scope = "unknown";
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

        if (!local_station_inventory) {
            station_inventory_reason = wifi_string(
                local_reasons, "station_inventory",
                "local_station_source_not_authoritative");
            station_inventory_reason_scope = "local";
        }
        if (!local_station_metrics) {
            station_metrics_reason = wifi_string(
                local_reasons, "station_metrics",
                "local_station_metrics_not_authoritative");
            station_metrics_reason_scope = "local";
        }
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
        if (fresh && !ap_station_inventory) {
            station_inventory_reason = ap_station_inventory_reason;
            station_inventory_reason_scope = "managed_ap";
        }
        if (fresh && !ap_station_metrics) {
            station_metrics_reason = ap_station_metrics_reason;
            station_metrics_reason_scope = "managed_ap";
        }
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
            /*
             * Merge the runtime snapshot's band / width / tx_power into the
             * desired view before appending.
             *
             * This branch runs when the AP reports no runtime *status*, but the
             * snapshot's `radios[]` is still present and still carries those
             * fields - the desired view is the UCI config, which has no
             * width_mhz or txpower_dbm at all. Without this merge the band,
             * width and tx-power columns were empty even though the values were
             * sitting one level up in the same response.
             *
             * Only the desired branch is touched. The runtime branch above
             * already has complete fields, and changing it would risk
             * regressing wifi/status's runtime_radios.
             */
            if (source_radios == wifi_child_array(desired, "radios"))
                wifi_desired_merge_runtime(source_radios,
                                           wifi_child_array(snapshot, "radios"));
            if (source_ssids == wifi_child_array(desired, "ssids"))
                wifi_desired_ssid_bands(source_ssids,
                                        wifi_child_array(desired, "radios"));
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
    if (station_inventory) {
        station_inventory_reason = "available";
        station_inventory_reason_scope =
            (local_radio_count || local_ssid_count) ?
                (remote_fresh > 0 ? "local+managed_ap" : "local") :
                (remote_fresh > 0 ? "managed_ap" : "none");
    } else if ((local_radio_count || local_ssid_count) &&
               !local_station_inventory) {
        station_inventory_reason = "local_station_source_not_authoritative";
        station_inventory_reason_scope = "local";
    } else if (remote_fresh == 0 && remote_stale > 0) {
        station_inventory_reason = "telemetry_stale";
        station_inventory_reason_scope = "managed_ap";
    } else if (remote_fresh == 0 && remote_offline > 0) {
        station_inventory_reason = "managed_ap_offline";
        station_inventory_reason_scope = "managed_ap";
    }
    if (station_metrics) {
        station_metrics_reason = "available";
        station_metrics_reason_scope = station_inventory_reason_scope;
    } else if ((local_radio_count || local_ssid_count) &&
               !local_station_metrics) {
        station_metrics_reason = "local_station_metrics_not_authoritative";
        station_metrics_reason_scope = "local";
    } else if (remote_fresh == 0 && remote_stale > 0) {
        station_metrics_reason = "telemetry_stale";
        station_metrics_reason_scope = "managed_ap";
    } else if (remote_fresh == 0 && remote_offline > 0) {
        station_metrics_reason = "managed_ap_offline";
        station_metrics_reason_scope = "managed_ap";
    }
    /*
     * A local reason must not stand as the summary's explanation when the local
     * side has no radio at all. On a router without a phy the stations can only
     * come from a managed AP, so a string describing the local hostapd control
     * channel is not an answer about the remote client list.
     */
    if (!station_inventory && !(local_radio_count || local_ssid_count) &&
        !strcmp(station_inventory_reason_scope, "local")) {
        station_inventory_reason = remote_fresh > 0 ?
            "managed_ap_station_source_unavailable" :
            "no_local_phy_and_no_managed_ap_runtime";
        station_inventory_reason_scope = "managed_ap";
    }
    if (!station_metrics && !(local_radio_count || local_ssid_count) &&
        !strcmp(station_metrics_reason_scope, "local")) {
        station_metrics_reason = remote_fresh > 0 ?
            "managed_ap_station_metrics_unavailable" :
            "no_local_phy_and_no_managed_ap_runtime";
        station_metrics_reason_scope = "managed_ap";
    }

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
    /*
     * The scope says whose failure the reason describes. `station_inventory`
     * false plus scope `managed_ap` is a remote collection gap; the same flag
     * with scope `local` is this router's. The frontend hides station UI on the
     * capability alone, so it needs to know which.
     */
    {
        struct json_object *scopes = wifi_ensure_object(capabilities,
                                                       "reason_scopes");

        wifi_replace_string(scopes, "station_inventory",
                            station_inventory_reason_scope);
        wifi_replace_string(scopes, "station_metrics",
                            station_metrics_reason_scope);
    }
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
    /*
     * Publish the write capability per scope alongside the flat bits above.
     *
     * The flat bits are deliberately left exactly as they are: a managed AP
     * present means every write is refused, because the AP-side transaction
     * (validate, push, read back, roll back on failure) is not implemented and
     * opening the entry point would turn "atomic configuration" into "possibly
     * half applied". Nothing here relaxes that.
     *
     * What the flat bits cannot express is *which* target is blocked. Today the
     * question is moot on 30.1, whose local_wifi reports no_phy_detected, so
     * there is no local write path to lose. It stops being moot the moment a
     * controller has its own PHY and also adopts an AP: the loop above would
     * refuse local writes too, purely because a remote AP cannot do
     * transactions. That is the trap the acceptance handoff for this asked to
     * avoid, and recording the scopes now means the eventual fix does not also
     * have to invent the contract.
     *
     * `write_scopes.local.supported` follows the local PHY only, so it stays
     * false on this device for the honest reason rather than by inheriting the
     * managed-AP one.
     */
    {
        struct json_object *scopes = json_object_new_object();
        struct json_object *local_scope = json_object_new_object();
        struct json_object *managed_scope = json_object_new_object();
        int has_managed = ac_items && json_object_array_length(ac_items) > 0;
        int local_present = local_radio_count > 0 || local_ssid_count > 0;

        /* The local scope now follows what jmxd actually reports for this box.
         * Secrets survive a save (AEAD vault keyed by secret_id) and apply
         * verifies by readback, so hardcoding false here would understate a
         * path that works.  It still reads false on a unit with no PHY, and it
         * deliberately does not consult the managed-AP state. */
        int local_write = local_present &&
                          wifi_capability_true(capabilities, "save_config") &&
                          wifi_capability_true(capabilities, "apply_config");

        json_object_object_add(local_scope, "present",
                               json_object_new_boolean(local_present));
        json_object_object_add(local_scope, "supported",
                               json_object_new_boolean(local_write));
        json_object_object_add(local_scope, "reason",
            json_object_new_string(!local_present ? "no_local_phy_detected" :
                local_write ? "available" :
                "local_write_capability_reported_false"));

        json_object_object_add(managed_scope, "present",
                               json_object_new_boolean(has_managed));
        json_object_object_add(managed_scope, "supported",
                               json_object_new_boolean(0));
        json_object_object_add(managed_scope, "reason",
            json_object_new_string(has_managed ?
                "managed_ap_transaction_pending" :
                "no_managed_ap_adopted"));

        json_object_object_add(scopes, "local", local_scope);
        json_object_object_add(scopes, "managed_ap", managed_scope);
        /*
         * States plainly that the flat bits above are the AND of both scopes,
         * so a reader knows they are not scope-aware and must not infer "local
         * is writable" from anything here.
         */
        json_object_object_add(scopes, "flat_bits_are_scope_agnostic",
                               json_object_new_boolean(1));
        json_object_object_add(capabilities, "write_scopes", scopes);
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
    /*
     * `interface_count` / `phy_count` are produced by the local chain and count
     * local phys only. Left under those names they contradict `radio_count`,
     * which includes managed AP radios: a reader sees 3 radios on 0 phys. They
     * are republished with explicit `local_` names, and the bare names are kept
     * as aliases so existing frontend readers keep working, with a reason field
     * saying what they count.
     */
    {
        struct json_object *local_interfaces = wifi_child(summary,
                                                          "interface_count");
        struct json_object *local_phys = wifi_child(summary, "phy_count");
        int interface_count = local_interfaces ?
            json_object_get_int(local_interfaces) : 0;
        int phy_count = local_phys ? json_object_get_int(local_phys) : 0;

        json_object_object_del(summary, "local_interface_count");
        json_object_object_add(summary, "local_interface_count",
                               json_object_new_int(interface_count));
        json_object_object_del(summary, "local_phy_count");
        json_object_object_add(summary, "local_phy_count",
                               json_object_new_int(phy_count));
        wifi_replace_string(summary, "interface_count_scope", "local_only");
        wifi_replace_string(summary, "phy_count_scope", "local_only");
    }
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
    /* Same distinction as the capability scope: whose gap this reason is. */
    wifi_replace_string(summary, "station_count_reason_scope",
                        station_inventory ? "available" :
                                            station_inventory_reason_scope);
    json_object_object_del(summary, "managed_ap_count");
    json_object_object_add(summary, "managed_ap_count", json_object_new_int(
        ac_items ? (int)json_object_array_length(ac_items) : 0));
    json_object_object_del(summary, "managed_ap_online");
    json_object_object_add(summary, "managed_ap_online",
                           json_object_new_int(managed_online));
    /*
     * Airtime aggregates. The local chain writes these as null with
     * `local_survey_source_unavailable` because a router without a phy can
     * never sample a channel. That reason is correct about the local source and
     * wrong as the summary's answer: the managed AP's radios are in this same
     * response. Roll the published radios up instead, and name the source that
     * supplied them.
     */
    {
        struct wifi_airtime_rollup roll;
        size_t radio_index;
        const char *airtime_source;
        const char *airtime_reason;

        memset(&roll, 0, sizeof(roll));
        for (radio_index = 0; radios &&
             radio_index < json_object_array_length(radios); radio_index++)
            wifi_airtime_rollup_radio(
                json_object_array_get_idx(radios, radio_index), &roll);

        wifi_summary_replace_double(summary, "avg_utilization",
            roll.utilization_samples > 0,
            roll.utilization_samples > 0 ?
                roll.utilization_sum / roll.utilization_samples : 0.0);
        wifi_summary_replace_double(summary, "avg_retry_rate",
            roll.retry_samples > 0,
            roll.retry_samples > 0 ? roll.retry_sum / roll.retry_samples : 0.0);
        wifi_summary_replace_double(summary, "worst_noise",
            roll.noise_samples > 0, roll.worst_noise);
        /*
         * avg_signal comes from per-radio station signal averages. It stays
         * null when no station reported one; with no associated client there is
         * no signal to average, and 0 dBm would be a fabricated reading.
         */
        if (roll.signal_samples > 0)
            wifi_summary_replace_double(summary, "avg_signal", 1,
                roll.signal_sum / roll.signal_samples);

        if (roll.managed_samples > 0 && roll.local_samples > 0)
            airtime_source = "local+managed_ap_radios";
        else if (roll.managed_samples > 0)
            airtime_source = "managed_ap_radios";
        else if (roll.local_samples > 0)
            airtime_source = "local_radios";
        else
            airtime_source = NULL;

        /*
         * When nothing reported, say which sources were tried rather than
         * blaming the local survey for a deployment that has no local radio.
         */
        if (airtime_source)
            airtime_reason = "available";
        else if (json_object_array_length(radios) > 0)
            airtime_reason = "radio_airtime_not_sampled_by_local_survey_or_managed_ap";
        else if (ac_items && json_object_array_length(ac_items) > 0)
            airtime_reason = "no_radio_reported_by_local_phy_or_managed_ap";
        else
            airtime_reason = "no_local_phy_and_no_managed_ap";
        wifi_replace_string(summary, "airtime_reason", airtime_reason);
        json_object_object_del(summary, "airtime_source");
        json_object_object_add(summary, "airtime_source", airtime_source ?
            json_object_new_string(airtime_source) : json_object_new_null());
        json_object_object_del(summary, "airtime_radio_samples");
        json_object_object_add(summary, "airtime_radio_samples",
            json_object_new_int(roll.local_samples + roll.managed_samples));
    }
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
