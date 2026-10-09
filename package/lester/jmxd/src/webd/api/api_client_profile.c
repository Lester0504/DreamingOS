// SPDX-License-Identifier: GPL-2.0-or-later
/* Client profile: the full per-device profile response and the connection /
 * protocol labeling helpers it drives. Extracted from jmx_app_api.c. */
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../jmx_app_api.h"
#include "api_client_profile.h"
#include "api_client_control.h"
#include "api_context.h"
#include "api_insights_internal.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"
#include "webd_http_req.h"

/* Constants the moved region uses. The monolith defines its own copies (it
 * still uses WEBD_CURRENT_FLOWS_PAGE_MAX on the insights path); these are in a
 * separate translation unit, so the values simply have to agree. */
#define WEBD_CURRENT_FLOWS_PAGE_MAX 200
#define WEBD_GENERIC_ROUTER_WEB_IMAGE "/luci-static/dreamingwrt/fingerprint/images/engine-0/3797/257x257.png"

/* Insights-owned helpers borrowed through the existing core-ops vtable, so
 * they stay static in the monolith (mirrors api_insights.c). */
#define INSIGHTS_CORE (webd_insights_core_ops_get())
#define webd_current_flows_diag_publish(...) INSIGHTS_CORE->current_flows_diag_publish(__VA_ARGS__)
#define webd_insights_fetch_current_flows_diag(...) INSIGHTS_CORE->fetch_current_flows_diag(__VA_ARGS__)
#define webd_insights_app_lookup(...) INSIGHTS_CORE->app_lookup(__VA_ARGS__)

/* Already-non-static utilities owned by the monolith; declared here to avoid
 * pulling <uci.h> (webd_normalize_mac_text lives behind that in its header). */
struct json_object *webd_jmx_data_ref(struct json_object *resp);
int webd_normalize_mac_text(const char *in, char *out, size_t out_len);
const char *webd_first_nonempty4(const char *a, const char *b,
                                 const char *c, const char *d);
const char *webd_first_nonempty6(const char *a, const char *b,
                                 const char *c, const char *d,
                                 const char *e, const char *f);
int webd_ipv6_is_link_local(const char *addr);

/* Genuinely private monolith helpers the profile builders call; un-static'd in
 * the monolith by this split so the module links to them. */
int webd_str_contains_i(const char *haystack, const char *needle);
int webd_ikuai_router_identity(const char *vendor, const char *device_type,
                               const char *model);
const char *webd_image_format_of(const char *url);
int webd_image_format_is_bitmap(const char *format);
int webd_ipv6_is_ula(const char *addr);
int webd_ipv6_is_loopback(const char *addr);

static void webd_profile_add_ipv6_aliases(struct json_object *basic,
                                          struct json_object *client,
                                          struct json_object *topology)
{
    struct json_object *arr = json_object_new_array();
    struct json_object *src_arr = NULL;
    const char *global = webd_first_nonempty4(
        app_nc_json_str(client, "ipv6_global", ""),
        app_nc_json_str(client, "global_ipv6", ""),
        app_nc_json_str(topology, "ipv6_global", ""),
        app_nc_json_str(topology, "global_ipv6", ""));
    const char *link_local = webd_first_nonempty4(
        app_nc_json_str(client, "ipv6_link_local", ""),
        app_nc_json_str(client, "link_local_ipv6", ""),
        app_nc_json_str(topology, "ipv6_link_local", ""),
        app_nc_json_str(topology, "link_local_ipv6", ""));
    const char *lan = webd_first_nonempty4(
        app_nc_json_str(client, "ipv6_lan", ""),
        app_nc_json_str(client, "lan_ipv6", ""),
        app_nc_json_str(topology, "ipv6_lan", ""),
        app_nc_json_str(topology, "lan_ipv6", ""));
    const char *raw = webd_first_nonempty4(
        app_nc_json_str(client, "ipv6", ""),
        app_nc_json_str(topology, "ipv6", ""),
        app_nc_json_str(client, "ip6", ""),
        app_nc_json_str(topology, "ip6", ""));

    if (!global[0] && raw[0] && !webd_ipv6_is_link_local(raw) &&
        !webd_ipv6_is_ula(raw) && !webd_ipv6_is_loopback(raw))
        global = raw;
    else if (!link_local[0] && raw[0] && webd_ipv6_is_link_local(raw))
        link_local = raw;
    else if (!lan[0] && raw[0] && webd_ipv6_is_ula(raw))
        lan = raw;

    if (json_object_object_get_ex(client, "ipv6_addrs", &src_arr) && src_arr &&
        json_object_is_type(src_arr, json_type_array)) {
        int i, n = (int)json_object_array_length(src_arr);
        for (i = 0; i < n; i++)
            json_object_array_add(arr, json_object_get(json_object_array_get_idx(src_arr, i)));
    } else if (json_object_object_get_ex(topology, "ipv6_addrs", &src_arr) && src_arr &&
               json_object_is_type(src_arr, json_type_array)) {
        int i, n = (int)json_object_array_length(src_arr);
        for (i = 0; i < n; i++)
            json_object_array_add(arr, json_object_get(json_object_array_get_idx(src_arr, i)));
    }
    if (json_object_array_length(arr) == 0) {
        if (global[0]) json_object_array_add(arr, json_object_new_string(global));
        if (lan[0]) json_object_array_add(arr, json_object_new_string(lan));
        if (link_local[0]) json_object_array_add(arr, json_object_new_string(link_local));
    }

    webd_obj_add_str(basic, "ipv6_global", global);
    webd_obj_add_str(basic, "global_ipv6", global);
    webd_obj_add_str(basic, "ipv6_lan", lan);
    webd_obj_add_str(basic, "ipv6_link_local", link_local);
    webd_obj_add_str(basic, "link_local_ipv6", link_local);
    json_object_object_add(basic, "ipv6_addrs", arr);
    webd_obj_add_str(basic, "ipv6", global[0] ? global : (lan[0] ? lan : link_local));
}

static struct json_object *webd_client_profile_basic(const char *norm_mac,
                                                     struct json_object *client,
                                                     struct json_object *identity,
                                                     struct json_object *topology)
{
    struct json_object *basic = json_object_new_object();
    struct json_object *fp = webd_obj_child_obj(identity, "fingerprint");
    struct json_object *client_fp = webd_obj_child_obj(client, "fingerprint");
    struct json_object *fp_image = webd_obj_child_obj(fp, "image");
    struct json_object *client_fp_image = webd_obj_child_obj(client_fp, "image");
    struct json_object *identity_override = webd_obj_child_obj(identity, "override");
    struct json_object *top_client = webd_obj_child_obj(topology, "client");
    const char *hostname = webd_first_nonempty4(
        app_nc_json_str(client, "hostname", ""),
        app_nc_json_str(top_client, "hostname", ""),
        app_nc_json_str(topology, "hostname", ""),
        "");
    const char *nickname = webd_first_nonempty4(
        app_nc_json_str(client, "custom_name", ""),
        app_nc_json_str(client, "nickname", ""),
        app_nc_json_str(identity ? webd_obj_child_obj(identity, "override") : NULL, "nickname", ""),
        app_nc_json_str(client, "name", ""));
    const char *vendor = webd_first_nonempty4(
        app_nc_json_str(client, "vendor_name", ""),
        app_nc_json_str(client, "vendor", ""),
        app_nc_json_str(fp, "vendor_name", ""),
        app_nc_json_str(client_fp, "vendor_name", ""));
    const char *device_type = webd_first_nonempty4(
        app_nc_json_str(client, "device_type", ""),
        app_nc_json_str(client, "type", ""),
        app_nc_json_str(fp, "device_type", ""),
        app_nc_json_str(client_fp, "device_type", ""));
    const char *model = webd_first_nonempty4(
        app_nc_json_str(client, "model", ""),
        app_nc_json_str(client, "device_name", ""),
        app_nc_json_str(fp, "device_name", ""),
        app_nc_json_str(client_fp, "device_name", ""));
    const char *os_name = webd_first_nonempty4(
        app_nc_json_str(client, "os_name", ""),
        app_nc_json_str(fp, "os_name", ""),
        app_nc_json_str(client_fp, "os_name", ""),
        "");
    const char *custom_image = webd_first_nonempty4(
        app_nc_json_str(client, "custom_image_path", ""),
        app_nc_json_str(client, "custom_icon", ""),
        app_nc_json_str(identity_override, "custom_image_path", ""),
        "");
    const char *detected_image = webd_first_nonempty4(
        app_nc_json_str(client, "detected_image", ""),
        app_nc_json_str(client_fp, "detected_image", ""),
        app_nc_json_str(fp_image, "path", ""),
        app_nc_json_str(client_fp_image, "path", ""));
    const char *image = webd_first_nonempty4(
        custom_image,
        app_nc_json_str(client, "image_url", ""),
        app_nc_json_str(client, "image", ""),
        detected_image);
    const char *image_source = app_nc_json_str(client, "image_source",
        custom_image[0] ? "override" : (detected_image[0] ? "fingerprint" : "none"));
    int image_fallback = 0;
    const char *image_fallback_reason = "";
    int confidence = app_nc_json_int(fp, "confidence",
        app_nc_json_int(client_fp, "confidence", app_nc_json_int(client, "fingerprint_confidence", 0)));

    if (!image[0] && webd_ikuai_router_identity(vendor, device_type, model)) {
        image = WEBD_GENERIC_ROUTER_WEB_IMAGE;
        image_fallback = 1;
        image_fallback_reason = "generic_router_icon_for_ikuai";
    }

    webd_obj_add_str(basic, "mac", norm_mac);
    webd_obj_add_str(basic, "ip", webd_first_nonempty4(
        app_nc_json_str(client, "ip", ""),
        app_nc_json_str(top_client, "ip", ""),
        app_nc_json_str(topology, "ip", ""),
        ""));
    webd_profile_add_ipv6_aliases(basic, client, topology);
    webd_obj_add_str(basic, "hostname", hostname);
    webd_obj_add_str(basic, "nickname", nickname);
    webd_obj_add_str(basic, "name", webd_first_nonempty4(nickname, hostname, model, norm_mac));
    webd_obj_add_str(basic, "vendor_name", vendor);
    webd_obj_add_str(basic, "vendor", vendor);
    webd_obj_add_str(basic, "device_type", device_type);
    webd_obj_add_str(basic, "type", device_type);
    webd_obj_add_str(basic, "model", model);
    webd_obj_add_str(basic, "os_name", os_name);
    webd_obj_add_str(basic, "interface", webd_first_nonempty4(
        app_nc_json_str(client, "interface", ""),
        app_nc_json_str(top_client, "interface", ""),
        app_nc_json_str(topology, "interface", ""),
        ""));
    webd_obj_add_str(basic, "network", webd_first_nonempty4(
        app_nc_json_str(client, "network", ""),
        app_nc_json_str(top_client, "network", ""),
        app_nc_json_str(topology, "network", ""),
        ""));
    webd_obj_add_str(basic, "ssid", webd_first_nonempty4(
        app_nc_json_str(client, "ssid", ""),
        app_nc_json_str(top_client, "ssid", ""),
        app_nc_json_str(topology, "essid", ""),
        ""));
    webd_obj_add_str(basic, "vlan", webd_first_nonempty4(
        app_nc_json_str(client, "vlan", ""),
        app_nc_json_str(client, "vlan_id", ""),
        app_nc_json_str(top_client, "vlan", ""),
        app_nc_json_str(topology, "vlan", "")));
    json_object_object_add(basic, "signal", json_object_new_int(app_nc_json_int(client, "signal",
        app_nc_json_int(top_client, "signal", app_nc_json_int(topology, "signal", 0)))));
    json_object_object_add(basic, "fingerprint_confidence", json_object_new_int(confidence));
    webd_obj_add_str(basic, "image", image);
    webd_obj_add_str(basic, "image_url", image);
    webd_obj_add_str(basic, "effective_image", image);
    webd_obj_add_str(basic, "custom_image_path", custom_image);
    webd_obj_add_str(basic, "detected_image", detected_image);
    webd_obj_add_str(basic, "fingerprint_image", detected_image[0] ? detected_image : image);
    webd_obj_add_str(basic, "image_source", image_fallback ? "fallback" : image_source);
    json_object_object_add(basic, "image_fallback", json_object_new_boolean(image_fallback));
    webd_obj_add_str(basic, "image_fallback_reason", image_fallback_reason);
    /* Mirrors the same pair emitted by /api/v1/clients (jmx_db.c). */
    webd_obj_add_str(basic, "image_format", webd_image_format_of(image));
    json_object_object_add(basic, "image_is_bitmap",
                           json_object_new_boolean(
                               webd_image_format_is_bitmap(
                                   webd_image_format_of(image))));
    return basic;
}

static struct json_object *webd_client_profile_detected_identity(struct json_object *client,
                                                                  struct json_object *identity)
{
    struct json_object *out = json_object_new_object();
    struct json_object *signals = webd_obj_child_array(identity, "signals");
    struct json_object *fp = webd_obj_child_obj(identity, "fingerprint");
    struct json_object *client_fp = webd_obj_child_obj(client, "fingerprint");
    const char *vendor = "";
    const char *model = "";
    const char *device_type = "unknown";
    const char *source = "";
    const char *image = app_nc_json_str(client, "detected_image",
        app_nc_json_str(client_fp, "detected_image", ""));
    int vendor_conf = -1, model_conf = -1, type_conf = -1, confidence = 0;
    int i;

    if (signals) {
        for (i = 0; i < (int)json_object_array_length(signals); i++) {
            struct json_object *s = json_object_array_get_idx(signals, i);
            const char *key = app_nc_json_str(s, "key", "");
            const char *value = app_nc_json_str(s, "value", "");
            const char *signal_source = app_nc_json_str(s, "source", "");
            int conf = app_nc_json_int(s, "confidence", 0);

            if (!value[0] || !strcmp(signal_source, "override"))
                continue;
            if ((!strcmp(key, "manufacturer") || !strcmp(key, "vendor")) && conf > vendor_conf) {
                vendor = value;
                vendor_conf = conf;
                if (conf >= confidence) { confidence = conf; source = signal_source; }
            } else if ((!strcmp(key, "modelName") || !strcmp(key, "model") ||
                        !strcmp(key, "friendlyName")) && conf > model_conf) {
                model = value;
                model_conf = conf;
                if (conf >= confidence) { confidence = conf; source = signal_source; }
            } else if (!strcmp(key, "device_type") && conf > type_conf) {
                device_type = value;
                type_conf = conf;
                if (conf >= confidence) { confidence = conf; source = signal_source; }
            }
        }
    }
    if (!vendor[0] && strcmp(app_nc_json_str(fp, "source", ""), "override"))
        vendor = app_nc_json_str(fp, "vendor_name", app_nc_json_str(client_fp, "vendor_name", ""));
    if (!model[0] && strcmp(app_nc_json_str(fp, "source", ""), "override"))
        model = app_nc_json_str(fp, "device_name", app_nc_json_str(client_fp, "device_name", ""));
    if (!strcmp(device_type, "unknown") && strcmp(app_nc_json_str(fp, "source", ""), "override"))
        device_type = app_nc_json_str(fp, "device_type", app_nc_json_str(client_fp, "device_type", "unknown"));
    if (!source[0] && strcmp(app_nc_json_str(fp, "source", ""), "override"))
        source = app_nc_json_str(fp, "source", app_nc_json_str(client_fp, "source", ""));
    if (confidence <= 0)
        confidence = app_nc_json_int(fp, "confidence", app_nc_json_int(client_fp, "confidence", 0));

    webd_obj_add_str(out, "vendor_name", vendor);
    webd_obj_add_str(out, "model", model);
    webd_obj_add_str(out, "device_type", device_type);
    webd_obj_add_str(out, "image", image);
    webd_obj_add_str(out, "source", source);
    json_object_object_add(out, "confidence", json_object_new_int(confidence));
    return out;
}

static struct json_object *webd_client_profile_effective_identity(struct json_object *basic)
{
    struct json_object *out = json_object_new_object();

    webd_obj_add_str(out, "vendor_name", app_nc_json_str(basic, "vendor_name", ""));
    webd_obj_add_str(out, "model", app_nc_json_str(basic, "model", ""));
    webd_obj_add_str(out, "device_type", app_nc_json_str(basic, "device_type", "unknown"));
    webd_obj_add_str(out, "custom_image_path", app_nc_json_str(basic, "custom_image_path", ""));
    webd_obj_add_str(out, "image", app_nc_json_str(basic, "image", ""));
    webd_obj_add_str(out, "image_url", app_nc_json_str(basic, "image_url", ""));
    webd_obj_add_str(out, "image_source", app_nc_json_str(basic, "image_source", "none"));
    return out;
}

static struct json_object *webd_client_profile_current(struct json_object *client,
                                                       struct json_object *topology,
                                                       struct json_object *today_metrics,
                                                       int session_count)
{
    struct json_object *current = json_object_new_object();
    struct json_object *top_client = webd_obj_child_obj(topology, "client");
    const char *visiting_app = webd_first_nonempty4(
        app_nc_json_str(client, "visiting_app_name", ""),
        app_nc_json_str(client, "active_app", ""),
        app_nc_json_str(top_client, "active_app", ""),
        app_nc_json_str(topology, "active_app", ""));
    const char *visiting_url = webd_first_nonempty4(
        app_nc_json_str(client, "visiting_url", ""),
        app_nc_json_str(top_client, "visiting_url", ""),
        app_nc_json_str(topology, "visiting_url", ""),
        "");
    int session_sample_count = session_count >= 0 ? session_count : 0;
    int connections = app_nc_json_int(client, "connections",
        app_nc_json_int(topology, "connections", session_sample_count));

    json_object_object_add(current, "online", json_object_new_boolean(app_nc_json_bool(client, "online",
        app_nc_json_bool(top_client, "online", app_nc_json_bool(topology, "online", 0)))));
    {
        int64_t online_since = app_nc_json_int64(client, "online_since",
            app_nc_json_int64(client, "connected_at",
            app_nc_json_int64(client, "session_started_at",
            app_nc_json_int64(topology, "online_since", 0))));
        int64_t online_duration = app_nc_json_int64(client, "online_duration",
            app_nc_json_int64(client, "online_seconds",
            app_nc_json_int64(client, "connected_seconds",
            app_nc_json_int64(topology, "online_duration", 0))));
        if (online_since > 0) {
            json_object_object_add(current, "online_since", json_object_new_int64(online_since));
            json_object_object_add(current, "connected_at", json_object_new_int64(online_since));
            json_object_object_add(current, "session_started_at", json_object_new_int64(online_since));
        }
        if (online_since > 0 || online_duration > 0) {
            json_object_object_add(current, "online_duration", json_object_new_int64(online_duration));
            json_object_object_add(current, "online_seconds", json_object_new_int64(online_duration));
            json_object_object_add(current, "connected_seconds", json_object_new_int64(online_duration));
            json_object_object_add(current, "session_duration", json_object_new_int64(online_duration));
        }
        webd_obj_add_str(current, "online_duration_source", webd_first_nonempty4(
            app_nc_json_str(client, "online_duration_source", ""),
            app_nc_json_str(topology, "online_duration_source", ""),
            "", ""));
    }
    json_object_object_add(current, "up_rate", json_object_new_int64(app_nc_json_int64(client, "up_rate",
        app_nc_json_int64(client, "tx_rate", app_nc_json_int64(topology, "up_rate", 0)))));
    json_object_object_add(current, "down_rate", json_object_new_int64(app_nc_json_int64(client, "down_rate",
        app_nc_json_int64(client, "rx_rate", app_nc_json_int64(topology, "down_rate", 0)))));
    json_object_object_add(current, "tx_rate", json_object_new_int64(app_nc_json_int64(client, "tx_rate",
        app_nc_json_int64(client, "up_rate", app_nc_json_int64(topology, "tx_rate", 0)))));
    json_object_object_add(current, "rx_rate", json_object_new_int64(app_nc_json_int64(client, "rx_rate",
        app_nc_json_int64(client, "down_rate", app_nc_json_int64(topology, "rx_rate", 0)))));
    json_object_object_add(current, "connections", json_object_new_int(connections));
    json_object_object_add(current, "session_sample_count", json_object_new_int(session_sample_count));
    json_object_object_add(current, "sample_valid", json_object_new_boolean(app_nc_json_bool(client, "sample_valid",
        app_nc_json_bool(topology, "sample_valid", 0))));
    json_object_object_add(current, "sample_age_ms", json_object_new_int64(app_nc_json_int64(client, "sample_age_ms",
        app_nc_json_int64(topology, "sample_age_ms", -1))));
    json_object_object_add(current, "updated_at", json_object_new_int64(app_nc_json_int64(client, "updated_at",
        app_nc_json_int64(topology, "updated_at", 0))));
    json_object_object_add(current, "last_seen_age", json_object_new_int64(app_nc_json_int64(client, "last_seen_age",
        app_nc_json_int64(topology, "last_seen_age", -1))));
    webd_obj_add_str(current, "rate_source", webd_first_nonempty4(
        app_nc_json_str(client, "rate_source", ""),
        app_nc_json_str(topology, "rate_source", ""),
        "", ""));
    webd_obj_add_str(current, "online_source", webd_first_nonempty4(
        app_nc_json_str(client, "online_source", ""),
        app_nc_json_str(topology, "online_source", ""),
        "", ""));
    webd_obj_add_str(current, "neigh_state", webd_first_nonempty4(
        app_nc_json_str(client, "neigh_state", ""),
        app_nc_json_str(topology, "neigh_state", ""),
        "", ""));
    webd_obj_add_str(current, "zero_reason", webd_first_nonempty4(
        app_nc_json_str(client, "zero_reason", ""),
        app_nc_json_str(topology, "zero_reason", ""),
        "", ""));
    json_object_object_add(current, "today_up_bytes", json_object_new_int64(
        app_nc_json_bool(today_metrics, "bytes_available", 0) ?
        app_nc_json_int64(today_metrics, "up_bytes", 0) :
        app_nc_json_int64(client, "today_up_bytes",
        app_nc_json_int64(client, "up_bytes", app_nc_json_int64(client, "tx_bytes", 0)))));
    json_object_object_add(current, "today_down_bytes", json_object_new_int64(
        app_nc_json_bool(today_metrics, "bytes_available", 0) ?
        app_nc_json_int64(today_metrics, "down_bytes", 0) :
        app_nc_json_int64(client, "today_down_bytes",
        app_nc_json_int64(client, "down_bytes", app_nc_json_int64(client, "rx_bytes", 0)))));
    json_object_object_add(current, "today_online_time", json_object_new_int64(
        app_nc_json_int64(today_metrics, "online_time", app_nc_json_int64(client, "today_online_time", 0))));
    json_object_object_add(current, "today_active_time", json_object_new_int64(
        app_nc_json_int64(today_metrics, "active_time", app_nc_json_int64(client, "today_active_time", 0))));
    webd_obj_add_str(current, "today_metrics_source",
                     app_nc_json_str(today_metrics, "source", "unavailable"));
    json_object_object_add(current, "today_metrics_complete",
                           json_object_new_boolean(app_nc_json_bool(today_metrics, "complete", 0)));
    json_object_object_add(current, "today_bytes_available",
                           json_object_new_boolean(app_nc_json_bool(today_metrics, "bytes_available", 0)));
    webd_obj_add_str(current, "today_metrics_reason",
                     app_nc_json_str(today_metrics, "degraded_reason", "today_runtime_bucket_unavailable"));
    webd_obj_add_str(current, "visiting_app_name", visiting_app);
    webd_obj_add_str(current, "visiting_url", visiting_url);
    return current;
}

static void webd_profile_normalize_records(struct json_object *records)
{
    int i, n;

    if (!records || !json_object_is_type(records, json_type_array))
        return;
    n = (int)json_object_array_length(records);
    for (i = 0; i < n; i++) {
        struct json_object *r = json_object_array_get_idx(records, i);
        const char *type = app_nc_json_str(r, "type", "");
        int64_t ts = app_nc_json_int64(r, "timestamp", app_nc_json_int64(r, "ts", 0));

        if (!r || !json_object_is_type(r, json_type_object))
            continue;
        json_object_object_add(r, "timestamp", json_object_new_int64(ts));
        json_object_object_add(r, "online", json_object_new_boolean(!strcmp(type, "online")));
    }
}

/*
 * "tcp/30185" is a synthesized debug string, not an application name.  Upstream
 * dw_conntrack_service_name() emits it for any port it cannot name, and it used
 * to travel in the service field all the way into the UI's 应用 column.  Match
 * the whole ^(tcp|udp|ip|icmp)/\d+$ shape so such a string can never be mistaken
 * for a label.
 */
static int webd_connection_label_proto_port(const char *s)
{
    const char *slash;
    const char *p;
    size_t proto_len;

    if (!s || !s[0])
        return 0;
    slash = strchr(s, '/');
    if (!slash || slash == s || !slash[1])
        return 0;
    proto_len = (size_t)(slash - s);
    if (!((proto_len == 3 && (!strncasecmp(s, "tcp", 3) || !strncasecmp(s, "udp", 3))) ||
          (proto_len == 2 && !strncasecmp(s, "ip", 2)) ||
          (proto_len == 4 && !strncasecmp(s, "icmp", 4))))
        return 0;
    for (p = slash + 1; *p; p++) {
        if (!isdigit((unsigned char)*p))
            return 0;
    }
    return 1;
}

static int webd_connection_label_raw_proto(const char *s)
{
    return s && (!strcasecmp(s, "tcp") || !strcasecmp(s, "udp") ||
                 !strcasecmp(s, "icmp") || !strcasecmp(s, "ip") ||
                 !strcasecmp(s, "unknown") || !strcmp(s, "--") ||
                 webd_connection_label_proto_port(s));
}

static int webd_connection_label_ip_literal(const char *s)
{
    unsigned char buf[sizeof(struct in6_addr)];
    char tmp[256];
    size_t len;
    const char *start;
    const char *end;

    if (!s || !s[0])
        return 0;
    start = s;
    end = s + strlen(s);
    if (*start == '[') {
        start++;
        if (end > start && end[-1] == ']')
            end--;
    }
    len = (size_t)(end - start);
    if (len == 0 || len >= sizeof(tmp))
        return 0;
    memcpy(tmp, start, len);
    tmp[len] = '\0';
    return inet_pton(AF_INET, tmp, buf) == 1 || inet_pton(AF_INET6, tmp, buf) == 1;
}

static int webd_connection_label_good(const char *s)
{
    return s && s[0] && !webd_connection_label_raw_proto(s) &&
           !webd_connection_label_ip_literal(s);
}

static int webd_connection_label_is_app_placeholder(const char *s)
{
    const char *p;

    if (!s || !s[0])
        return 0;
    if (strncasecmp(s, "app ", 4))
        return 0;
    p = s + 4;
    if (!*p)
        return 0;
    while (*p) {
        if (!isdigit((unsigned char)*p))
            return 0;
        p++;
    }
    return 1;
}

static int webd_connection_label_generic(const char *s)
{
    if (!s || !s[0])
        return 1;
    if (webd_connection_label_raw_proto(s) || webd_connection_label_ip_literal(s))
        return 1;
    if (!strcasecmp(s, "unknown") || !strcasecmp(s, "unknown app") ||
        !strcasecmp(s, "unknown p2p") || !strcasecmp(s, "p2p") ||
        !strcasecmp(s, "https") || !strcasecmp(s, "http") ||
        !strcasecmp(s, "quic") || !strcasecmp(s, "dns") ||
        !strcasecmp(s, "dot") || !strcasecmp(s, "doh") ||
        !strcasecmp(s, "ntp") || !strcasecmp(s, "ssh") ||
        !strcasecmp(s, "icmp") || !strcasecmp(s, "mdns") ||
        !strcasecmp(s, "ssdp") || !strcasecmp(s, "smtp") ||
        !strcasecmp(s, "pop3") || !strcasecmp(s, "imap"))
        return 1;
    if (!strcmp(s, "未知") || !strcmp(s, "未知应用") ||
        !strcasecmp(s, "未知P2P") || !strcasecmp(s, "未知p2p"))
        return 1;
    if (webd_connection_label_is_app_placeholder(s))
        return 1;
    return 0;
}

static int webd_connection_label_specific(const char *s)
{
    return webd_connection_label_good(s) && !webd_connection_label_generic(s);
}

static const char *webd_connection_host_source_contract(const char *source)
{
    if (!source || !source[0])
        return "unknown";
    if (!strcasecmp(source, "af_active_host"))
        return "dns_cache";
    if (!strcasecmp(source, "signature_host"))
        return "signature";
    if (!strcasecmp(source, "http_host") || !strcasecmp(source, "sni") ||
        !strcasecmp(source, "dns_cache") || !strcasecmp(source, "audit_url") ||
        !strcasecmp(source, "signature") || !strcasecmp(source, "port_fallback") ||
        !strcasecmp(source, "p2p_heuristic"))
        return source;
    return source;
}

const char *webd_connection_service_field_label(const char *service)
{
    if (!service || !service[0])
        return "";
    if (!strcasecmp(service, "https"))
        return "HTTPS";
    if (!strcasecmp(service, "quic"))
        return "QUIC";
    if (!strcasecmp(service, "http"))
        return "HTTP";
    if (!strcasecmp(service, "dns"))
        return "DNS";
    if (!strcasecmp(service, "dot"))
        return "DoT";
    if (!strcasecmp(service, "doh"))
        return "DoH";
    if (!strcasecmp(service, "ntp"))
        return "NTP";
    if (!strcasecmp(service, "ssh"))
        return "SSH";
    if (!strcasecmp(service, "icmp"))
        return "ICMP";
    if (!strcasecmp(service, "mdns"))
        return "mDNS";
    if (!strcasecmp(service, "ssdp"))
        return "SSDP";
    if (!strcasecmp(service, "smtp"))
        return "SMTP";
    if (!strcasecmp(service, "pop3"))
        return "POP3";
    if (!strcasecmp(service, "imap"))
        return "IMAP";
    return "";
}

const char *webd_connection_service_label(const char *proto, int port,
                                                 int *is_p2p)
{
    /*
     * Do not label arbitrary high ports as P2P.  Client detail is a
     * per-connection view; without an explicit DPI/signature hit a high
     * destination port is only an unknown TCP/UDP service, not proof of P2P.
     * Dashboard app cards are resolved from af_active_host/signature data, so
     * this fallback must stay conservative and keep the app unknown.
     */
    if (is_p2p)
        *is_p2p = 0;
    if (proto && !strcasecmp(proto, "icmp"))
        return "ICMP";
    if (port == 443) {
        if (proto && !strcasecmp(proto, "udp"))
            return "QUIC";
        return "HTTPS";
    }
    if (port == 8443 && proto && !strcasecmp(proto, "udp"))
        return "QUIC";
    if (port == 80)
        return "HTTP";
    if (port == 53)
        return "DNS";
    if (port == 123)
        return "NTP";
    if (port == 853)
        return "DoT";
    if (port == 22)
        return "SSH";
    if (port == 25 || port == 465 || port == 587)
        return "SMTP";
    if (port == 110 || port == 995)
        return "POP3";
    if (port == 143 || port == 993)
        return "IMAP";
    if (port == 1900)
        return "SSDP";
    if (port == 5353)
        return "mDNS";
    return "";
}

static void webd_connection_pick_label(struct json_object *src,
                                       const char *proto,
                                       int dst_port,
                                       const char **app,
                                       const char **app_type,
                                       const char **app_source,
                                       const char **domain,
                                       const char **host,
                                       const char **sni,
                                       const char **app_raw_name,
                                       const char **app_raw_source,
                                       const char **app_label_rank,
                                       const char **app_resolution_reason,
                                       int *app_generic_label)
{
    const char *domain_label;
    const char *app_name;
    const char *service_name;
    const char *service_label;
    const char *raw_source;
    const char *upstream_reason;
    int p2p = 0;

    *domain = webd_first_nonempty6(app_nc_json_str(src, "domain", ""),
                                   app_nc_json_str(src, "host", ""),
                                   app_nc_json_str(src, "destination_host", ""),
                                   app_nc_json_str(src, "fqdn", ""),
                                   app_nc_json_str(src, "server_name", ""),
                                   app_nc_json_str(src, "url_host", ""));
    *sni = app_nc_json_str(src, "sni", "");
    if (!(*domain)[0] && *sni && (*sni)[0])
        *domain = *sni;
    *host = (*domain)[0] ? *domain : app_nc_json_str(src, "host", "");
    domain_label = *domain;
    app_name = webd_first_nonempty6(app_nc_json_str(src, "app_name", ""),
                                    app_nc_json_str(src, "destination_app_name", ""),
                                    app_nc_json_str(src, "application_name", ""),
                                    app_nc_json_str(src, "application", ""),
                                    app_nc_json_str(src, "app", ""),
                                    app_nc_json_str(src, "service_name", ""));
    raw_source = webd_first_nonempty4(app_nc_json_str(src, "app_match_source", ""),
                                      app_nc_json_str(src, "app_resolution_source", ""),
                                      app_nc_json_str(src, "source", ""),
                                      "");
    upstream_reason = app_nc_json_str(src, "unknown_reason", "");
    service_name = app_nc_json_str(src, "service", "");
    if (app_raw_name)
        *app_raw_name = app_name;
    if (app_raw_source)
        *app_raw_source = raw_source;
    if (app_generic_label)
        *app_generic_label = app_name && app_name[0] &&
                             webd_connection_label_generic(app_name);

    if (webd_connection_label_specific(app_name) &&
        (app_nc_json_int(src, "app_id", 0) > 0 ||
         app_nc_json_int(src, "destination_app_id", 0) > 0 ||
         webd_str_contains_i(app_nc_json_str(src, "app_match_source", ""), "signature"))) {
        *app = app_name;
        *app_type = "signature";
        *app_source = webd_connection_host_source_contract(
            app_nc_json_str(src, "app_match_source", "signature"));
        if (app_label_rank) *app_label_rank = "signature";
        if (app_resolution_reason) *app_resolution_reason = "signature_app_match";
        return;
    }
    if (webd_connection_label_specific(domain_label)) {
        *app = domain_label;
        *app_type = "domain";
        *app_source = webd_connection_host_source_contract(
            app_nc_json_str(src, "host_source", "dns_cache"));
        if (app_label_rank) *app_label_rank = "domain";
        if (app_resolution_reason) *app_resolution_reason =
            app_name && app_name[0] && webd_connection_label_generic(app_name) ?
            "generic_app_label_discarded_domain_available" : "host_or_domain_available";
        return;
    }
    if (webd_connection_label_specific(app_name)) {
        *app = app_name;
        *app_type = "signature";
        *app_source = webd_connection_host_source_contract(
            app_nc_json_str(src, "app_match_source", "signature"));
        if (app_label_rank) *app_label_rank = "signature";
        if (app_resolution_reason) *app_resolution_reason = "app_name_without_domain";
        return;
    }
    service_label = webd_connection_service_field_label(service_name);
    if (!service_label[0])
        service_label = webd_connection_service_label(proto, dst_port, &p2p);
    if (service_label[0]) {
        *app = service_label;
        *app_type = p2p ? "p2p" : "service";
        *app_source = p2p ? "p2p_heuristic" : "port_fallback";
        if (app_label_rank) *app_label_rank = "service";
        if (app_resolution_reason) *app_resolution_reason =
            service_name && service_name[0] ? "service_field_fallback" : "port_fallback";
        return;
    }
    *app = "";
    *app_type = "unknown";
    *app_source = "unknown";
    if (app_label_rank) *app_label_rank = "unknown";
    if (app_resolution_reason) *app_resolution_reason =
        upstream_reason && upstream_reason[0] ? upstream_reason : "no_domain_signature_or_known_service";
}

static void webd_protocol_category_for(const char *app,
                                       const char *app_type,
                                       const char *app_source,
                                       const char *proto,
                                       const char *domain,
                                       const char *service,
                                       const char **key,
                                       const char **name);

/*
 * Per-connection classification.
 *
 * webd_protocol_category_for() answers "which application category" and is
 * driven by name substrings; on a row whose app is genuinely unresolved it has
 * nothing to match and lands on 未知应用.  A connection row additionally needs to
 * say *why* it is unknown, in the vocabulary the user asked for, without
 * inventing an app name for it.  So: keep the existing category taxonomy as the
 * single source of truth when the app is known, and refine only the unknown
 * bucket into 未知协议 / 未知应用 / 未知P2P.
 *
 * This must not widen the P2P heuristic.  webd_connection_service_label()
 * deliberately refuses to call a high port P2P, and that stays: 未知P2P is used
 * only where an upstream signature already said p2p.
 */
static void webd_connection_category_for(struct json_object *src,
                                         const char *app,
                                         const char *app_type,
                                         const char *app_source,
                                         const char *proto,
                                         const char *domain,
                                         const char *service,
                                         const char **key,
                                         const char **name)
{
    const char *base_key = "unknown";
    const char *base_name = "未知应用";

    webd_protocol_category_for(app, app_type, app_source, proto, domain, service,
                               &base_key, &base_name);
    if (app && app[0] && strcmp(base_key, "unknown")) {
        if (key) *key = base_key;
        if (name) *name = base_name;
        return;
    }
    /* Unresolved row: name the kind of ignorance, not a fabricated app. */
    if ((app_type && !strcasecmp(app_type, "p2p")) ||
        (app_source && !strcasecmp(app_source, "p2p_heuristic"))) {
        if (key) *key = "unknown_p2p";
        if (name) *name = "未知P2P";
        return;
    }
    if (!app || !app[0]) {
        /*
         * No app, no domain, no nameable service: all we truly know is the
         * transport.  That is a protocol-level unknown, which is what the
         * synthesized tcp/<port> string used to be pretending to describe.
         */
        const char *host = domain && domain[0] ? domain :
                           app_nc_json_str(src, "destination_host", "");

        if (!host[0]) {
            if (key) *key = "unknown_protocol";
            if (name) *name = "未知协议";
            return;
        }
    }
    if (key) *key = base_key;
    if (name) *name = base_name;
}

static void webd_profile_lines_add_unique_label(struct json_object *lines,
                                                const char *wan_id,
                                                const char *ifname,
                                                const char *label)
{
    const char *id = wan_id && wan_id[0] ? wan_id : ifname;
    int i, n;
    struct json_object *line;
    /*
     * design.md 947/948: a line is identified by its stable logical owner
     * (wan, wan2, ...), and the physical ifname (eth1, eth3) stays in its own
     * field.  The fallback used to prefer ifname whenever it differed from the
     * id, which put eth3 in the user-visible label of a line named wan3.
     */
    const char *display = label && label[0] ? label :
        ((wan_id && wan_id[0]) ? wan_id : id);

    if (!lines || !id || !id[0] || !json_object_is_type(lines, json_type_array))
        return;
    n = (int)json_object_array_length(lines);
    for (i = 0; i < n; i++) {
        struct json_object *l = json_object_array_get_idx(lines, i);
        if (!strcasecmp(app_nc_json_str(l, "id", ""), id))
            return;
    }
    line = json_object_new_object();
    webd_obj_add_str(line, "id", id);
    webd_obj_add_str(line, "value", id);
    webd_obj_add_str(line, "line", id);
    webd_obj_add_str(line, "wan_id", wan_id && wan_id[0] ? wan_id : id);
    webd_obj_add_str(line, "ifname", ifname);
    webd_obj_add_str(line, "name", display);
    webd_obj_add_str(line, "label", display);
    json_object_array_add(lines, line);
}

static void webd_profile_lines_add_unique(struct json_object *lines,
                                          const char *wan_id,
                                          const char *ifname)
{
    webd_profile_lines_add_unique_label(lines, wan_id, ifname, NULL);
}

/*
 * A connection row's user-visible line label must name the logical line, not
 * the physical port.  Upstream dw_insights_conntrack_flows() fills wan_ifname
 * from the WAN's *device* (eth3), so preferring it here rendered the whole
 * "线路" column as eth1..eth4 for lines named wan..wan4.  design.md 947/948
 * requires the logical owner in the label and the ifname in its own field.
 *
 * Precedence: an explicitly provided readable name (wan3(联通-2)) wins, then the
 * logical id, and only if neither exists do we fall back to the device name,
 * which is still better than an empty column.
 */
static const char *webd_connection_line_label(const char *wan_name,
                                              const char *wan_id,
                                              const char *wan_ifname)
{
    if (wan_name && wan_name[0])
        return wan_name;
    if (wan_id && wan_id[0])
        return wan_id;
    return wan_ifname ? wan_ifname : "";
}

static void webd_profile_lines_add_from_flow_control(struct json_object *lines)
{
    struct json_object *resp;
    struct json_object *data = NULL;
    struct json_object *wans = NULL;
    int i, n;

    if (!lines || !json_object_is_type(lines, json_type_array))
        return;
    resp = app_ubus_invoke("flow_control_rules_get", NULL);
    if (!resp)
        return;
    data = webd_jmx_data_ref(resp);
    if (data && json_object_object_get_ex(data, "wans", &wans) && wans &&
        json_object_is_type(wans, json_type_array)) {
        n = (int)json_object_array_length(wans);
        for (i = 0; i < n; i++) {
            struct json_object *wan = json_object_array_get_idx(wans, i);
            const char *id = webd_first_nonempty4(app_nc_json_str(wan, "id", ""),
                                                  app_nc_json_str(wan, "wan_id", ""),
                                                  app_nc_json_str(wan, "ifname", ""),
                                                  app_nc_json_str(wan, "name", ""));
            const char *ifname = app_nc_json_str(wan, "ifname", id);
            const char *name = webd_first_nonempty4(app_nc_json_str(wan, "name", ""),
                                                    app_nc_json_str(wan, "label", ""),
                                                    ifname, id);
            webd_profile_lines_add_unique_label(lines, id, ifname, name);
        }
    }
    if (data) json_object_put(data);
    json_object_put(resp);
}

static struct json_object *webd_profile_connections_from_flows(struct json_object *flows,
                                                               struct json_object *lines)
{
    struct json_object *out = json_object_new_array();
    int i, n;

    if (!flows || !json_object_is_type(flows, json_type_array))
        return out;
    n = (int)json_object_array_length(flows);
    for (i = 0; i < n; i++) {
        struct json_object *f = json_object_array_get_idx(flows, i);
        const char *proto;
        const char *domain = "";
        const char *host = "";
        const char *sni = "";
        const char *app = "";
        const char *app_type = "unknown";
        const char *app_source = "unknown";
        const char *app_raw_name = "";
        const char *app_raw_source = "";
        const char *app_label_rank = "unknown";
        const char *app_resolution_reason = "";
        int app_generic_label = 0;
        const char *wan_id;
        const char *wan_ifname;
        const char *wan_name;
        const char *state;
        const char *dst_ip;
        const char *src_ip;
        int src_port;
        int dst_port;
        struct json_object *c;

        if (!f || !json_object_is_type(f, json_type_object))
            continue;
        proto = app_nc_json_str(f, "proto", app_nc_json_str(f, "protocol", ""));
        src_port = app_nc_json_int(f, "source_port", app_nc_json_int(f, "sport", 0));
        dst_port = app_nc_json_int(f, "destination_port", app_nc_json_int(f, "dport", 0));
        src_ip = webd_first_nonempty4(app_nc_json_str(f, "source_ip", ""),
                                      app_nc_json_str(f, "client_ip", ""),
                                      app_nc_json_str(f, "src", ""),
                                      "");
        dst_ip = webd_first_nonempty4(app_nc_json_str(f, "destination_ip", ""),
                                      app_nc_json_str(f, "remote_ip", ""),
                                      app_nc_json_str(f, "dst", ""),
                                      "");
        webd_connection_pick_label(f, proto, dst_port, &app, &app_type, &app_source,
                                   &domain, &host, &sni, &app_raw_name,
                                   &app_raw_source, &app_label_rank,
                                   &app_resolution_reason, &app_generic_label);
        wan_id = app_nc_json_str(f, "wan_id", "");
        wan_ifname = app_nc_json_str(f, "wan_ifname", "");
        /*
         * Readable alias if upstream has one; it must never fall back to the
         * device name, or the label regresses to eth3.
         */
        wan_name = webd_first_nonempty4(app_nc_json_str(f, "wan_name", ""),
                                       app_nc_json_str(f, "wan_label", ""),
                                       app_nc_json_str(f, "line_name", ""),
                                       "");
        webd_profile_lines_add_unique_label(lines, wan_id, wan_ifname,
                                           wan_name[0] ? wan_name : NULL);
        state = app_nc_json_str(f, "state", "");

        c = json_object_new_object();
        {
            char sig[512];
            char fallback_id[560];
            const char *flow_id = app_nc_json_str(f, "id", "");
            const char *flow_sig = app_nc_json_str(f, "signature", "");

            snprintf(sig, sizeof(sig), "%s|%s|%d|%s|%d",
                     proto ? proto : "", src_ip ? src_ip : "", src_port,
                     dst_ip ? dst_ip : "", dst_port);
            snprintf(fallback_id, sizeof(fallback_id), "ct:%s:%s:%d:%s:%d",
                     proto ? proto : "", src_ip ? src_ip : "", src_port,
                     dst_ip ? dst_ip : "", dst_port);
            webd_obj_add_str(c, "id", fallback_id);
            webd_obj_add_str(c, "signature", sig);
            webd_obj_add_str(c, "ct_signature", sig);
            webd_obj_add_str(c, "upstream_id", flow_id);
            webd_obj_add_str(c, "upstream_signature", flow_sig);
        }
        json_object_object_add(c, "ts", json_object_new_int64(app_nc_json_int64(f, "ts", 0)));
        webd_obj_add_str(c, "app", app);
        webd_obj_add_str(c, "app_type", app_type);
        webd_obj_add_str(c, "app_source", app_source);
        webd_obj_add_str(c, "app_resolution_source", app_nc_json_str(f, "app_resolution_source", app_source));
        webd_obj_add_str(c, "app_raw_name", app_raw_name);
        webd_obj_add_str(c, "app_raw_source", app_raw_source);
        webd_obj_add_str(c, "app_label_rank", app_label_rank);
        webd_obj_add_str(c, "app_resolution_reason", app_resolution_reason);
        json_object_object_add(c, "app_generic_label", json_object_new_boolean(app_generic_label));
        webd_obj_add_str(c, "unknown_reason", app_nc_json_str(f, "unknown_reason", ""));
        json_object_object_add(c, "historical_join", json_object_new_boolean(app_nc_json_bool(f, "historical_join", 0)));
        json_object_object_add(c, "destination_host_last_update", json_object_new_int64(
            app_nc_json_int64(f, "destination_host_last_update", 0)));
        webd_obj_add_str(c, "domain", domain);
        webd_obj_add_str(c, "host", host);
        webd_obj_add_str(c, "sni", sni);
        webd_obj_add_str(c, "proto", proto);
        webd_obj_add_str(c, "protocol", app_nc_json_str(f, "protocol", proto));
        webd_obj_add_str(c, "app_proto", app_nc_json_str(f, "app_proto", ""));
        webd_obj_add_str(c, "protocol_label", app_nc_json_str(f, "app_proto",
                         app_nc_json_str(f, "protocol", proto)));
        /*
         * service carries only genuinely nameable services (https/quic/dns/...).
         * Upstream synthesizes "tcp/30185" for unnamed ports; that is a debug
         * hint, so it moves to service_hint and is explicitly marked as not an
         * application name.  The UI reads service as a label candidate.
         */
        {
            const char *raw_service = app_nc_json_str(f, "service", "");
            const char *clean_service = raw_service;
            const char *cat_key = "unknown";
            const char *cat_name = "未知应用";

            if (webd_connection_label_proto_port(raw_service)) {
                clean_service = "";
                webd_obj_add_str(c, "service", "");
                webd_obj_add_str(c, "service_hint", raw_service);
                webd_obj_add_str(c, "service_hint_kind", "proto_port_not_an_app_name");
            } else {
                webd_obj_add_str(c, "service", raw_service);
            }
            /*
             * Row-level classification so the caller does not have to guess from
             * substrings.  app_resolution_reason stays as-is: it explains the
             * resolution attempt, this names the bucket.  Classification sees the
             * sanitized service -- feeding it "tcp/30185" would match on "tcp"
             * and mislabel an unresolved row as 网络协议.
             */
            webd_connection_category_for(f, app, app_type, app_source, proto,
                                         domain, clean_service,
                                         &cat_key, &cat_name);
            webd_obj_add_str(c, "category_key", cat_key);
            webd_obj_add_str(c, "category_name", cat_name);
        }
        json_object_object_add(c, "app_id", json_object_new_int(
            app_nc_json_int(f, "app_id", app_nc_json_int(f, "destination_app_id", 0))));
        webd_obj_add_str(c, "app_name", app_nc_json_str(f, "app_name",
                         app_nc_json_str(f, "destination_app_name", "")));
        webd_obj_add_str(c, "destination_app_name", app_nc_json_str(f, "destination_app_name",
                         app_nc_json_str(f, "app_name", "")));
        json_object_object_add(c, "destination_app_id", json_object_new_int(
            app_nc_json_int(f, "destination_app_id", app_nc_json_int(f, "app_id", 0))));
        webd_obj_add_str(c, "line", wan_id && wan_id[0] ? wan_id : wan_ifname);
        webd_obj_add_str(c, "line_label",
                         webd_connection_line_label(wan_name, wan_id, wan_ifname));
        webd_obj_add_str(c, "line_name",
                         webd_connection_line_label(wan_name, wan_id, wan_ifname));
        webd_obj_add_str(c, "wan", wan_id);
        webd_obj_add_str(c, "wan_id", wan_id);
        /*
         * wan_ifname keeps its upstream value (the WAN device, e.g. eth3) for
         * compatibility; wan_device is the honestly named alias.  Neither is a
         * display label -- see webd_connection_line_label().
         */
        webd_obj_add_str(c, "wan_ifname", wan_ifname);
        webd_obj_add_str(c, "wan_device", wan_ifname);
        webd_obj_add_str(c, "line_ifname", wan_ifname);
        webd_obj_add_str(c, "src_ip", src_ip);
        webd_obj_add_str(c, "source_ip", src_ip);
        webd_obj_add_str(c, "dst_ip", dst_ip);
        webd_obj_add_str(c, "destination_ip", dst_ip);
        webd_obj_add_str(c, "server_ip", dst_ip);
        webd_obj_add_str(c, "remote_ip", dst_ip);
        webd_obj_add_str(c, "external_ip", dst_ip);
        json_object_object_add(c, "src_port", json_object_new_int(src_port));
        json_object_object_add(c, "source_port", json_object_new_int(src_port));
        json_object_object_add(c, "dst_port", json_object_new_int(dst_port));
        json_object_object_add(c, "destination_port", json_object_new_int(dst_port));
        json_object_object_add(c, "remote_port", json_object_new_int(dst_port));
        json_object_object_add(c, "up_bytes", json_object_new_int64(
            app_nc_json_int64(f, "tx_bytes", app_nc_json_int64(f, "up_bytes", 0))));
        json_object_object_add(c, "down_bytes", json_object_new_int64(
            app_nc_json_int64(f, "rx_bytes", app_nc_json_int64(f, "down_bytes", 0))));
        json_object_object_add(c, "tx_bytes", json_object_new_int64(
            app_nc_json_int64(f, "tx_bytes", app_nc_json_int64(f, "up_bytes", 0))));
        json_object_object_add(c, "rx_bytes", json_object_new_int64(
            app_nc_json_int64(f, "rx_bytes", app_nc_json_int64(f, "down_bytes", 0))));
        webd_obj_add_str(c, "state", state);
        json_object_object_add(c, "connected", json_object_new_boolean(
            state[0] ? strcasecmp(state, "TIME_WAIT") != 0 : 1));
        webd_obj_add_str(c, "direction", app_nc_json_str(f, "direction", ""));
        webd_obj_add_str(c, "risk", app_nc_json_str(f, "risk", "unknown"));
        webd_obj_add_str(c, "action", app_nc_json_str(f, "action", "allow"));
        webd_obj_add_str(c, "source", "insights_current_flows");
        json_object_array_add(out, c);
    }
    return out;
}

static struct json_object *webd_profile_sessions_from_connections(struct json_object *connections,
                                                                  const char *client_ip,
                                                                  struct json_object *lines)
{
    struct json_object *sessions = json_object_new_array();
    int i, n;

    if (!connections || !json_object_is_type(connections, json_type_array))
        return sessions;
    n = (int)json_object_array_length(connections);
    for (i = 0; i < n; i++) {
        struct json_object *c = json_object_array_get_idx(connections, i);
        const char *src = app_nc_json_str(c, "src", "");
        const char *dst = app_nc_json_str(c, "dst", "");
        const char *proto = app_nc_json_str(c, "proto", "");
        const char *app_proto = app_nc_json_str(c, "app_proto", "");
        int sport = app_nc_json_int(c, "sport", 0);
        int dport = app_nc_json_int(c, "dport", 0);
        int client_is_src = client_ip && client_ip[0] && !strcmp(src, client_ip);
        int client_is_dst = client_ip && client_ip[0] && !strcmp(dst, client_ip);
        int64_t bytes_orig = app_nc_json_int64(c, "bytes_orig", 0);
        int64_t bytes_reply = app_nc_json_int64(c, "bytes_reply", 0);
        const char *remote_ip = client_is_dst ? src : dst;
        int remote_port = client_is_dst ? sport : dport;
        int local_port = client_is_dst ? dport : sport;
        int64_t tx_bytes = client_is_dst ? bytes_reply : bytes_orig;
        int64_t rx_bytes = client_is_dst ? bytes_orig : bytes_reply;
        const char *app = "";
        const char *app_type = "unknown";
        const char *app_source = "unknown";
        const char *app_raw_name = "";
        const char *app_raw_source = "";
        const char *app_label_rank = "unknown";
        const char *app_resolution_reason = "";
        int app_generic_label = 0;
        const char *domain = "";
        const char *host = "";
        const char *sni = "";
        const char *local_ip = client_is_dst ? dst : src;
        char sig[512];
        char id[560];
        struct json_object *s;

        if (!c || !json_object_is_type(c, json_type_object))
            continue;
        webd_connection_pick_label(c, proto, remote_port, &app, &app_type, &app_source,
                                   &domain, &host, &sni, &app_raw_name,
                                   &app_raw_source, &app_label_rank,
                                   &app_resolution_reason, &app_generic_label);
        snprintf(sig, sizeof(sig), "%s|%s|%d|%s|%d",
                 proto ? proto : "", local_ip ? local_ip : "", local_port,
                 remote_ip ? remote_ip : "", remote_port);
        snprintf(id, sizeof(id), "ct:%s:%s:%d:%s:%d",
                 proto ? proto : "", local_ip ? local_ip : "", local_port,
                 remote_ip ? remote_ip : "", remote_port);
        s = json_object_new_object();
        webd_obj_add_str(s, "id", id);
        webd_obj_add_str(s, "signature", sig);
        webd_obj_add_str(s, "ct_signature", sig);
        webd_obj_add_str(s, "src_ip", local_ip);
        webd_obj_add_str(s, "source_ip", local_ip);
        webd_obj_add_str(s, "dst_ip", remote_ip);
        webd_obj_add_str(s, "destination_ip", remote_ip);
        webd_obj_add_str(s, "server_ip", remote_ip);
        webd_obj_add_str(s, "remote_ip", remote_ip);
        webd_obj_add_str(s, "external_ip", remote_ip);
        json_object_object_add(s, "src_port", json_object_new_int(local_port));
        json_object_object_add(s, "source_port", json_object_new_int(local_port));
        json_object_object_add(s, "dst_port", json_object_new_int(remote_port));
        json_object_object_add(s, "destination_port", json_object_new_int(remote_port));
        json_object_object_add(s, "remote_port", json_object_new_int(remote_port));
        webd_obj_add_str(s, "proto", proto);
        webd_obj_add_str(s, "protocol", proto);
        webd_obj_add_str(s, "app_proto", app_proto);
        webd_obj_add_str(s, "protocol_label", app_proto && app_proto[0] ? app_proto : proto);
        {
            const char *raw_service = app_nc_json_str(c, "service", "");
            const char *clean_service = raw_service;
            const char *cat_key = "unknown";
            const char *cat_name = "未知应用";

            if (webd_connection_label_proto_port(raw_service)) {
                clean_service = "";
                webd_obj_add_str(s, "service", "");
                webd_obj_add_str(s, "service_hint", raw_service);
                webd_obj_add_str(s, "service_hint_kind", "proto_port_not_an_app_name");
            } else {
                webd_obj_add_str(s, "service", raw_service);
            }
            /* Same classification contract as the flows source. */
            webd_connection_category_for(c, app, app_type, app_source, proto,
                                         domain, clean_service,
                                         &cat_key, &cat_name);
            webd_obj_add_str(s, "category_key", cat_key);
            webd_obj_add_str(s, "category_name", cat_name);
        }
        webd_obj_add_str(s, "app", app);
        webd_obj_add_str(s, "app_type", app_type);
        webd_obj_add_str(s, "app_source", app_source);
        webd_obj_add_str(s, "app_resolution_source", app_source);
        webd_obj_add_str(s, "app_raw_name", app_raw_name);
        webd_obj_add_str(s, "app_raw_source", app_raw_source);
        webd_obj_add_str(s, "app_label_rank", app_label_rank);
        webd_obj_add_str(s, "app_resolution_reason", app_resolution_reason);
        json_object_object_add(s, "app_generic_label", json_object_new_boolean(app_generic_label));
        if (!app || !app[0] || !strcmp(app_type, "unknown"))
            webd_obj_add_str(s, "unknown_reason", "no_host_signature_conntrack_fallback");
        else
            webd_obj_add_str(s, "unknown_reason", "");
        json_object_object_add(s, "historical_join", json_object_new_boolean(0));
        webd_obj_add_str(s, "domain", domain);
        webd_obj_add_str(s, "host", host);
        webd_obj_add_str(s, "sni", sni);
        json_object_object_add(s, "tx_bytes", json_object_new_int64(tx_bytes));
        json_object_object_add(s, "rx_bytes", json_object_new_int64(rx_bytes));
        json_object_object_add(s, "up_bytes", json_object_new_int64(tx_bytes));
        json_object_object_add(s, "down_bytes", json_object_new_int64(rx_bytes));
        json_object_object_add(s, "bytes_orig", json_object_new_int64(bytes_orig));
        json_object_object_add(s, "bytes_reply", json_object_new_int64(bytes_reply));
        webd_obj_add_str(s, "direction", client_is_src ? "outbound" : (client_is_dst ? "inbound" : "unknown"));
        /*
         * The conntrack fallback source (client_connections) carries no WAN
         * attribution at all -- its rows are proto/src/dst/ports/bytes only.
         * Empty is the honest answer here, but it must be distinguishable from
         * "attribution exists and is blank", so the reason travels with it.
         * Same semantics as the flows source: label never holds a device name.
         */
        webd_obj_add_str(s, "line", "");
        webd_obj_add_str(s, "line_label", "");
        webd_obj_add_str(s, "line_name", "");
        webd_obj_add_str(s, "wan_id", "");
        webd_obj_add_str(s, "line_unknown_reason",
                         "client_connections_source_has_no_wan_attribution");
        webd_obj_add_str(s, "state", app_nc_json_str(c, "state", ""));
        json_object_object_add(s, "connected", json_object_new_boolean(1));
        webd_obj_add_str(s, "source", "nf_conntrack");
        json_object_array_add(sessions, s);
    }
    (void)lines;
    return sessions;
}

static void webd_protocol_category_for(const char *app,
                                       const char *app_type,
                                       const char *app_source,
                                       const char *proto,
                                       const char *domain,
                                       const char *service,
                                       const char **key,
                                       const char **name)
{
    char text[1536];

    if (key)
        *key = "unknown";
    if (name)
        *name = "未知应用";
    snprintf(text, sizeof(text), "%s %s %s %s %s %s",
             app ? app : "", app_type ? app_type : "", app_source ? app_source : "",
             proto ? proto : "", domain ? domain : "", service ? service : "");

    if ((app_type && !strcasecmp(app_type, "p2p")) ||
        (app_source && !strcasecmp(app_source, "p2p_heuristic")) ||
        webd_str_contains_i(text, "p2p") || webd_str_contains_i(text, "torrent") ||
        webd_str_contains_i(text, "qbittorrent") || webd_str_contains_i(text, "transmission") ||
        webd_str_contains_i(text, "xunlei") || webd_str_contains_i(text, "thunder") ||
        webd_str_contains_i(text, "aria2") || webd_str_contains_i(text, "download") ||
        webd_str_contains_i(text, "cdn") || webd_str_contains_i(text, "下载")) {
        if (key) *key = "download";
        if (name) *name = "传输下载";
        return;
    }
    if (webd_str_contains_i(text, "steam") || webd_str_contains_i(text, "epic") ||
        webd_str_contains_i(text, "riot") || webd_str_contains_i(text, "xbox") ||
        webd_str_contains_i(text, "playstation") || webd_str_contains_i(text, "battle.net") ||
        webd_str_contains_i(text, "game") || webd_str_contains_i(text, "游戏")) {
        if (key) *key = "game";
        if (name) *name = "网络游戏";
        return;
    }
    if (webd_str_contains_i(text, "youtube") || webd_str_contains_i(text, "bilibili") ||
        webd_str_contains_i(text, "netflix") || webd_str_contains_i(text, "iqiyi") ||
        webd_str_contains_i(text, "douyin") || webd_str_contains_i(text, "tiktok") ||
        webd_str_contains_i(text, "music") || webd_str_contains_i(text, "video") ||
        webd_str_contains_i(text, "live") || webd_str_contains_i(text, "audio") ||
        webd_str_contains_i(text, "stream") || webd_str_contains_i(text, "娱乐")) {
        if (key) *key = "leisure";
        if (name) *name = "休闲娱乐";
        return;
    }
    if (webd_str_contains_i(text, "wechat") || webd_str_contains_i(text, "weixin") ||
        webd_str_contains_i(text, "telegram") || webd_str_contains_i(text, "discord") ||
        webd_str_contains_i(text, "qq") || webd_str_contains_i(text, "mail") ||
        webd_str_contains_i(text, "push") || webd_str_contains_i(text, "social") ||
        webd_str_contains_i(text, "社交")) {
        if (key) *key = "social";
        if (name) *name = "社交通讯";
        return;
    }
    if (webd_str_contains_i(text, "github") || webd_str_contains_i(text, "gitlab") ||
        webd_str_contains_i(text, "icloud") || webd_str_contains_i(text, "onedrive") ||
        webd_str_contains_i(text, "dropbox") || webd_str_contains_i(text, "drive") ||
        webd_str_contains_i(text, "sync") || webd_str_contains_i(text, "office") ||
        webd_str_contains_i(text, "productivity")) {
        if (key) *key = "efficiency";
        if (name) *name = "效率工具";
        return;
    }
    if (webd_str_contains_i(text, "bank") || webd_str_contains_i(text, "pay") ||
        webd_str_contains_i(text, "alipay") || webd_str_contains_i(text, "finance") ||
        webd_str_contains_i(text, "wallet") || webd_str_contains_i(text, "金融")) {
        if (key) *key = "finance";
        if (name) *name = "金融理财";
        return;
    }
    if (webd_str_contains_i(text, "edu") || webd_str_contains_i(text, "school") ||
        webd_str_contains_i(text, "course") || webd_str_contains_i(text, "study") ||
        webd_str_contains_i(text, "学习")) {
        if (key) *key = "study";
        if (name) *name = "教育学习";
        return;
    }
    if (webd_str_contains_i(text, "dns") || webd_str_contains_i(text, "http") ||
        webd_str_contains_i(text, "https") || webd_str_contains_i(text, "quic") ||
        webd_str_contains_i(text, "icmp") || webd_str_contains_i(text, "ntp") ||
        webd_str_contains_i(text, "ssh") || webd_str_contains_i(text, "smtp") ||
        webd_str_contains_i(text, "imap") || webd_str_contains_i(text, "pop3") ||
        webd_str_contains_i(text, "dot") || webd_str_contains_i(text, "mdns") ||
        webd_str_contains_i(text, "ssdp") || webd_str_contains_i(text, "vpn") ||
        webd_str_contains_i(text, "tcp") || webd_str_contains_i(text, "udp")) {
        if (key) *key = "network";
        if (name) *name = "网络协议";
        return;
    }
}


static void webd_protocol_make_id(const char *category_key,
                                  const char *name,
                                  const char *proto,
                                  char *out,
                                  size_t out_len)
{
    char raw[512];
    size_t i, o = 0;

    if (!out || out_len == 0)
        return;
    snprintf(raw, sizeof(raw), "%s-%s-%s",
             category_key && category_key[0] ? category_key : "unknown",
             name && name[0] ? name : "unknown",
             proto && proto[0] ? proto : "ip");
    for (i = 0; raw[i] && o + 1 < out_len; i++) {
        unsigned char c = (unsigned char)raw[i];
        if (isalnum(c))
            out[o++] = (char)tolower(c);
        else if (c == '.' || c == '_' || c == '-')
            out[o++] = (char)c;
        else if (o > 0 && out[o - 1] != '-')
            out[o++] = '-';
    }
    while (o > 0 && out[o - 1] == '-')
        o--;
    out[o] = '\0';
    if (!out[0])
        snprintf(out, out_len, "unknown");
}

static struct json_object *webd_protocol_find_by_key(struct json_object *arr,
                                                     const char *key)
{
    int i, n;

    if (!arr || !json_object_is_type(arr, json_type_array) || !key || !key[0])
        return NULL;
    n = (int)json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        struct json_object *row = json_object_array_get_idx(arr, i);
        if (!strcmp(app_nc_json_str(row, "aggregate_key", ""), key))
            return row;
    }
    return NULL;
}

static void webd_protocol_row_add_int64(struct json_object *row,
                                        const char *key,
                                        int64_t delta)
{
    int64_t current;

    if (!row || !key)
        return;
    current = app_nc_json_int64(row, key, 0);
    json_object_object_add(row, key, json_object_new_int64(current + delta));
}

static void webd_protocol_category_add(struct json_object *categories,
                                       const char *category_key,
                                       const char *category_name,
                                       int64_t connections,
                                       int64_t up_bytes,
                                       int64_t down_bytes,
                                       int64_t up_rate,
                                       int64_t down_rate)
{
    struct json_object *row = NULL;
    int i, n;

    if (!categories || !json_object_is_type(categories, json_type_array))
        return;
    n = (int)json_object_array_length(categories);
    for (i = 0; i < n; i++) {
        struct json_object *candidate = json_object_array_get_idx(categories, i);
        if (!strcmp(app_nc_json_str(candidate, "category_key", ""), category_key)) {
            row = candidate;
            break;
        }
    }
    if (!row) {
        row = json_object_new_object();
        webd_obj_add_str(row, "category_key", category_key);
        webd_obj_add_str(row, "key", category_key);
        webd_obj_add_str(row, "category_name", category_name);
        webd_obj_add_str(row, "name", category_name);
        json_object_object_add(row, "connections", json_object_new_int64(0));
        json_object_object_add(row, "up_rate", json_object_new_int64(0));
        json_object_object_add(row, "down_rate", json_object_new_int64(0));
        json_object_object_add(row, "up_bytes", json_object_new_int64(0));
        json_object_object_add(row, "down_bytes", json_object_new_int64(0));
        json_object_object_add(row, "traffic_bytes", json_object_new_int64(0));
        json_object_object_add(row, "total_bytes", json_object_new_int64(0));
        json_object_array_add(categories, row);
    }
    webd_protocol_row_add_int64(row, "connections", connections > 0 ? connections : 0);
    webd_protocol_row_add_int64(row, "up_rate", up_rate);
    webd_protocol_row_add_int64(row, "down_rate", down_rate);
    webd_protocol_row_add_int64(row, "up_bytes", up_bytes);
    webd_protocol_row_add_int64(row, "down_bytes", down_bytes);
    webd_protocol_row_add_int64(row, "traffic_bytes", up_bytes + down_bytes);
    webd_protocol_row_add_int64(row, "total_bytes", up_bytes + down_bytes);
}

static struct json_object *webd_profile_protocol_summary(struct json_object *connections,
                                                         struct json_object *overview_history,
                                                         struct json_object *protocol_history,
                                                         struct json_object *current,
                                                         const char *connection_source)
{
    struct json_object *summary = json_object_new_object();
    struct json_object *protocols = json_object_new_array();
    struct json_object *categories = json_object_new_array();
    struct json_object *rate_history = json_object_new_array();
    struct json_object *total_rate_history = json_object_new_array();
    struct json_object *protocol_history_fallback = NULL;
    int i, n;
    int rows_with_rate = 0;
    int rate_history_points = 0;
    int protocol_history_series = 0;
    int protocol_history_producer_supported =
        protocol_history && app_nc_json_bool(protocol_history, "producer_supported", 0);
    int protocol_history_split_supported =
        protocol_history &&
        (app_nc_json_bool(protocol_history, "per_app_supported", 0) ||
         app_nc_json_bool(protocol_history, "per_protocol_supported", 0));
    int protocol_history_ready =
        protocol_history_producer_supported && protocol_history_split_supported &&
        app_nc_json_bool(protocol_history, "available", 0) &&
        app_nc_json_bool(protocol_history, "supported", 0);
    int protocol_history_complete =
        protocol_history_ready && app_nc_json_bool(protocol_history, "complete", 0);
    const char *protocol_history_source =
        app_nc_json_str(protocol_history, "source", "unavailable");
    int protocol_history_fallback_available = 0;

    if (protocol_history &&
        json_object_object_get_ex(protocol_history, "fallback",
                                  &protocol_history_fallback) &&
        protocol_history_fallback &&
        json_object_is_type(protocol_history_fallback, json_type_object))
        protocol_history_fallback_available =
            app_nc_json_bool(protocol_history_fallback, "available", 0) &&
            app_nc_json_int(protocol_history_fallback, "series_sample_count", 0) > 0;

    if (!connections || !json_object_is_type(connections, json_type_array))
        n = 0;
    else
        n = (int)json_object_array_length(connections);

    for (i = 0; i < n; i++) {
        struct json_object *c = json_object_array_get_idx(connections, i);
        const char *proto = app_nc_json_str(c, "proto", app_nc_json_str(c, "protocol", ""));
        const char *app = app_nc_json_str(c, "app", "");
        const char *app_type = app_nc_json_str(c, "app_type", "unknown");
        const char *app_source = app_nc_json_str(c, "app_source", "unknown");
        const char *domain = webd_first_nonempty4(app_nc_json_str(c, "domain", ""),
                                                  app_nc_json_str(c, "host", ""),
                                                  app_nc_json_str(c, "sni", ""),
                                                  "");
        const char *service = app_nc_json_str(c, "service", "");
        const char *category_key = "unknown";
        const char *category_name = "未知应用";
        const char *name = app;
        int dst_port = app_nc_json_int(c, "dst_port", app_nc_json_int(c, "destination_port",
                                      app_nc_json_int(c, "remote_port", 0)));
        int p2p = 0;
        const char *service_label;
        char aggregate_key[768];
        char id[256];
        int64_t up_bytes = app_nc_json_int64(c, "up_bytes", app_nc_json_int64(c, "tx_bytes", 0));
        int64_t down_bytes = app_nc_json_int64(c, "down_bytes", app_nc_json_int64(c, "rx_bytes", 0));
        int64_t up_rate = app_nc_json_int64(c, "up_rate",
                          app_nc_json_int64(c, "tx_rate",
                          app_nc_json_int64(c, "tx_bytes-r", 0)));
        int64_t down_rate = app_nc_json_int64(c, "down_rate",
                            app_nc_json_int64(c, "rx_rate",
                            app_nc_json_int64(c, "rx_bytes-r", 0)));
        int64_t ts = app_nc_json_int64(c, "ts", 0);
        struct json_object *row;

        if (!c || !json_object_is_type(c, json_type_object))
            continue;
        if (!webd_connection_label_specific(name))
            name = domain;
        if (!webd_connection_label_specific(name)) {
            service_label = webd_connection_service_field_label(service);
            if (!service_label || !service_label[0])
                service_label = webd_connection_service_label(proto, dst_port, &p2p);
            if (service_label && service_label[0]) {
                name = service_label;
                if (!strcasecmp(app_type, "unknown"))
                    app_type = p2p ? "p2p" : "service";
                if (!strcasecmp(app_source, "unknown"))
                    app_source = p2p ? "p2p_heuristic" : "port_fallback";
            }
        }
        if (!webd_connection_label_good(name)) {
            if (proto && !strcasecmp(proto, "icmp"))
                name = "ICMP";
            else
                name = "未知应用";
        }
        webd_protocol_category_for(name, app_type, app_source, proto, domain, service,
                                   &category_key, &category_name);
        snprintf(aggregate_key, sizeof(aggregate_key), "%s|%s|%s|%s",
                 category_key, name, proto ? proto : "", domain ? domain : "");
        row = webd_protocol_find_by_key(protocols, aggregate_key);
        if (!row) {
            row = json_object_new_object();
            webd_protocol_make_id(category_key, name, proto, id, sizeof(id));
            webd_obj_add_str(row, "aggregate_key", aggregate_key);
            webd_obj_add_str(row, "id", id);
            webd_obj_add_str(row, "key", id);
            webd_obj_add_str(row, "protocol_name", name);
            webd_obj_add_str(row, "name", name);
            webd_obj_add_str(row, "category_key", category_key);
            webd_obj_add_str(row, "category_name", category_name);
            webd_obj_add_str(row, "type_name", category_name);
            webd_obj_add_str(row, "proto", proto);
            webd_obj_add_str(row, "protocol", proto);
            webd_obj_add_str(row, "domain", domain);
            webd_obj_add_str(row, "host", domain);
            webd_obj_add_str(row, "service", service);
            webd_obj_add_str(row, "app_source", app_source);
            webd_obj_add_str(row, "app_type", app_type);
            webd_obj_add_str(row, "source", "client_profile.connections");
            webd_obj_add_str(row, "rate_source", "connection_rate_fields");
            json_object_object_add(row, "connections", json_object_new_int64(0));
            json_object_object_add(row, "flow_count", json_object_new_int64(0));
            json_object_object_add(row, "up_rate", json_object_new_int64(0));
            json_object_object_add(row, "down_rate", json_object_new_int64(0));
            json_object_object_add(row, "up_bytes", json_object_new_int64(0));
            json_object_object_add(row, "down_bytes", json_object_new_int64(0));
            json_object_object_add(row, "total_bytes", json_object_new_int64(0));
            if (ts > 0) {
                json_object_object_add(row, "first_seen", json_object_new_int64(ts));
                json_object_object_add(row, "latest_seen", json_object_new_int64(ts));
            }
            json_object_array_add(protocols, row);
        }
        webd_protocol_row_add_int64(row, "connections", 1);
        webd_protocol_row_add_int64(row, "flow_count", 1);
        webd_protocol_row_add_int64(row, "up_rate", up_rate);
        webd_protocol_row_add_int64(row, "down_rate", down_rate);
        webd_protocol_row_add_int64(row, "up_bytes", up_bytes);
        webd_protocol_row_add_int64(row, "down_bytes", down_bytes);
        webd_protocol_row_add_int64(row, "total_bytes", up_bytes + down_bytes);
        if (ts > 0) {
            int64_t first_seen = app_nc_json_int64(row, "first_seen", ts);
            int64_t latest_seen = app_nc_json_int64(row, "latest_seen", ts);
            if (ts < first_seen)
                json_object_object_add(row, "first_seen", json_object_new_int64(ts));
            if (ts > latest_seen)
                json_object_object_add(row, "latest_seen", json_object_new_int64(ts));
        }
        if (up_rate > 0 || down_rate > 0)
            rows_with_rate++;
        webd_protocol_category_add(categories, category_key, category_name, 1,
                                   up_bytes, down_bytes, up_rate, down_rate);
    }

    if (overview_history && json_object_is_type(overview_history, json_type_array)) {
        int hn = (int)json_object_array_length(overview_history);

        for (i = 0; i < hn; i++) {
            struct json_object *src = json_object_array_get_idx(overview_history, i);
            int64_t ts = app_nc_json_int64(src, "ts",
                         app_nc_json_int64(src, "timestamp", 0));
            int64_t up_rate = app_nc_json_int64(src, "up_rate",
                              app_nc_json_int64(src, "tx_rate",
                              app_nc_json_int64(src, "upload_rate", 0)));
            int64_t down_rate = app_nc_json_int64(src, "down_rate",
                                app_nc_json_int64(src, "rx_rate",
                                app_nc_json_int64(src, "download_rate", 0)));
            int64_t connections = app_nc_json_int64(src, "connections",
                                  app_nc_json_int64(src, "conn_count", 0));
            struct json_object *point;

            if (!src || !json_object_is_type(src, json_type_object) || ts <= 0)
                continue;
            point = json_object_new_object();
            json_object_object_add(point, "ts", json_object_new_int64(ts));
            json_object_object_add(point, "timestamp", json_object_new_int64(ts));
            json_object_object_add(point, "up_rate", json_object_new_int64(up_rate));
            json_object_object_add(point, "down_rate", json_object_new_int64(down_rate));
            json_object_object_add(point, "connections", json_object_new_int64(connections));
            webd_obj_add_str(point, "source", "client_runtime_ring_total");
            json_object_array_add(total_rate_history, point);
            rate_history_points++;
        }
    }

    if (protocol_history_ready) {
        struct json_object *history_points = webd_obj_child_array(protocol_history, "points");
        int hn = history_points ? (int)json_object_array_length(history_points) : 0;

        for (i = 0; i < hn; i++) {
            struct json_object *src_point = json_object_array_get_idx(history_points, i);
            struct json_object *src_items = webd_obj_child_array(src_point, "items");
            struct json_object *point;
            struct json_object *point_categories;
            int j, sn;
            int64_t point_up = 0;
            int64_t point_down = 0;

            if (!src_items || !json_object_is_type(src_items, json_type_array))
                continue;
            point = json_object_new_object();
            point_categories = json_object_new_array();
            json_object_object_add(point, "ts", json_object_new_int64(
                app_nc_json_int64(src_point, "ts", 0)));
            json_object_object_add(point, "timestamp", json_object_new_int64(
                app_nc_json_int64(src_point, "timestamp",
                                  app_nc_json_int64(src_point, "ts", 0))));
            json_object_object_add(point, "interval_seconds", json_object_new_int(
                app_nc_json_int(src_point, "interval_seconds", 0)));
            webd_obj_add_str(point, "source", protocol_history_source);
            sn = (int)json_object_array_length(src_items);
            for (j = 0; j < sn; j++) {
                struct json_object *sample = json_object_array_get_idx(src_items, j);
                const char *app = app_nc_json_str(sample, "app",
                                  app_nc_json_str(sample, "app_name", ""));
                const char *proto = app_nc_json_str(sample, "proto",
                                    app_nc_json_str(sample, "protocol", ""));
                const char *domain = app_nc_json_str(sample, "domain",
                                     app_nc_json_str(sample, "host", ""));
                const char *service = app_nc_json_str(sample, "service", "");
                const char *category_key = "unknown";
                const char *category_name = "未知应用";
                char signature_app[256] = "";
                char signature_category[128] = "";
                char signature_family[128] = "";
                int canonical_app_id = 0;
                int app_id = app_nc_json_int(sample, "app_id", 0);
                int64_t flow_count = app_nc_json_int64(sample, "flow_count", 0);
                int64_t up_rate = app_nc_json_int64(sample, "up_rate", 0);
                int64_t down_rate = app_nc_json_int64(sample, "down_rate", 0);

                if ((!app || !app[0]) && app_id > 0 &&
                    webd_insights_app_lookup(app_id,
                                             signature_app, sizeof(signature_app),
                                             signature_category, sizeof(signature_category),
                                             signature_family, sizeof(signature_family),
                                             &canonical_app_id))
                    app = signature_app;
                webd_protocol_category_for(app,
                                           app && app[0] ?
                                           (signature_category[0] ? signature_category : "application") :
                                           "service",
                                           app && app[0] ? "signature_app_id" : "port_fallback",
                                           proto, domain, service,
                                           &category_key, &category_name);
                webd_protocol_category_add(point_categories, category_key, category_name,
                                           flow_count,
                                           app_nc_json_int64(sample, "up_bytes_delta", 0),
                                           app_nc_json_int64(sample, "down_bytes_delta", 0),
                                           up_rate, down_rate);
                point_up += up_rate;
                point_down += down_rate;
                protocol_history_series++;
            }
            if (json_object_array_length(point_categories) <= 0) {
                json_object_put(point);
                json_object_put(point_categories);
                continue;
            }
            json_object_object_add(point, "categories", point_categories);
            json_object_object_add(point, "items", json_object_get(point_categories));
            json_object_object_add(point, "up_rate", json_object_new_int64(point_up));
            json_object_object_add(point, "down_rate", json_object_new_int64(point_down));
            json_object_array_add(rate_history, point);
        }
    }

    json_object_object_add(summary, "protocols", protocols);
    json_object_object_add(summary, "items", json_object_get(protocols));
    json_object_object_add(summary, "rows", json_object_get(protocols));
    json_object_object_add(summary, "categories", categories);
    json_object_object_add(summary, "rate_history", rate_history);
    json_object_object_add(summary, "history", json_object_get(rate_history));
    json_object_object_add(summary, "total_rate_history", total_rate_history);
    json_object_object_add(summary, "sample_count", json_object_new_int(n));
    json_object_object_add(summary, "protocol_count",
                           json_object_new_int((int)json_object_array_length(protocols)));
    json_object_object_add(summary, "category_count",
                           json_object_new_int((int)json_object_array_length(categories)));
    json_object_object_add(summary, "degraded", json_object_new_boolean(n == 0));
    webd_obj_add_str(summary, "source", connection_source && connection_source[0] ?
                     connection_source : "client_profile.connections");
    webd_obj_add_str(summary, "rate_source", rows_with_rate > 0 ?
                     "connection_rate_fields" : "unavailable");
    json_object_object_add(summary, "protocol_rate_live_supported",
                           json_object_new_boolean(rows_with_rate > 0));
    json_object_object_add(summary, "rate_history_supported",
                           json_object_new_boolean(protocol_history_series > 0));
    json_object_object_add(summary, "rate_history_complete",
                           json_object_new_boolean(protocol_history_complete));
    json_object_object_add(summary, "rate_history_degraded",
                           json_object_new_boolean(!protocol_history_complete));
    json_object_object_add(summary, "rate_history_total_only",
                           json_object_new_boolean(0));
    json_object_object_add(summary, "per_protocol_rate_history_supported",
                           json_object_new_boolean(protocol_history_series > 0));
    webd_obj_add_str(summary, "rate_history_reason", protocol_history_series > 0 ?
                     app_nc_json_str(protocol_history, "reason",
                                     protocol_history_complete ? "" :
                                     "partial_hot_window_after_producer_start") :
                     (protocol_history_fallback_available ?
                      "minute_flow_sample_fallback_not_full_hot_window" :
                      app_nc_json_str(protocol_history, "reason",
                                      "per_protocol_rate_history_unavailable")));
    webd_obj_add_str(summary, "rate_history_source", protocol_history_series > 0 ?
                     protocol_history_source : "unavailable");
    json_object_object_add(summary, "rate_history_point_count",
                           json_object_new_int((int)json_object_array_length(rate_history)));
    json_object_object_add(summary, "rate_history_series_sample_count",
                           json_object_new_int(protocol_history_series));
    json_object_object_add(summary, "rate_history_window_sec", json_object_new_int(
                           app_nc_json_int(protocol_history, "window_sec", 300)));
    webd_obj_add_str(summary, "rate_history_byte_semantics",
                     protocol_history_series > 0 ?
                     app_nc_json_str(protocol_history, "byte_semantics",
                                     "monotonic_client_app_counter_delta") : "unavailable");
    json_object_object_add(summary, "rate_history_producer_supported",
                           json_object_new_boolean(protocol_history_producer_supported));
    json_object_object_add(summary, "rate_history_per_app_supported",
                           json_object_new_boolean(protocol_history_ready &&
                               app_nc_json_bool(protocol_history, "per_app_supported", 0)));
    json_object_object_add(summary, "rate_history_per_protocol_supported",
                           json_object_new_boolean(protocol_history_ready &&
                               app_nc_json_bool(protocol_history, "per_protocol_supported", 0)));
    json_object_object_add(summary, "rate_history_fallback_available",
                           json_object_new_boolean(protocol_history_fallback_available));
    json_object_object_add(summary, "rate_history_fallback_point_count",
                           json_object_new_int(protocol_history_fallback_available ?
                               app_nc_json_int(protocol_history_fallback, "point_count", 0) : 0));
    json_object_object_add(summary, "rate_history_fallback_series_sample_count",
                           json_object_new_int(protocol_history_fallback_available ?
                               app_nc_json_int(protocol_history_fallback,
                                               "series_sample_count", 0) : 0));
    json_object_object_add(summary, "rate_history_revision", json_object_new_int64(
                           app_nc_json_int64(protocol_history, "revision", 0)));
    json_object_object_add(summary, "rate_history_observed_at", json_object_new_int64(
                           app_nc_json_int64(protocol_history, "observed_at", 0)));
    json_object_object_add(summary, "rate_history_coverage_ratio", json_object_new_double(
                           app_nc_json_double(protocol_history, "coverage_ratio", 0.0)));
    json_object_object_add(summary, "rate_history_reset_count", json_object_new_int64(
                           app_nc_json_int64(protocol_history, "reset_count", 0)));
    json_object_object_add(summary, "rate_history_gap_count", json_object_new_int64(
                           app_nc_json_int64(protocol_history, "gap_count", 0)));
    webd_obj_add_str(summary, "rate_history_producer_generation",
                     app_nc_json_str(protocol_history, "producer_generation", ""));
    json_object_object_add(summary, "total_rate_history_supported",
                           json_object_new_boolean(rate_history_points > 0));
    json_object_object_add(summary, "total_rate_history_complete", json_object_new_boolean(0));
    webd_obj_add_str(summary, "total_rate_history_reason", rate_history_points > 0 ?
                     "runtime_ring_may_be_partial_after_core_restart" : "no_runtime_samples_yet");
    webd_obj_add_str(summary, "total_rate_history_source", rate_history_points > 0 ?
                     "client_runtime_ring" : "unavailable");
    webd_obj_add_str(summary, "history_contract", protocol_history_series > 0 ?
                     "per_app_protocol_hot_window_separate_from_client_total_ring" :
                     "total_only_separate_from_protocol_history");
    json_object_object_add(summary, "total_current_up_rate",
                           json_object_new_int64(app_nc_json_int64(current, "up_rate", 0)));
    json_object_object_add(summary, "total_current_down_rate",
                           json_object_new_int64(app_nc_json_int64(current, "down_rate", 0)));
    if (n == 0)
        webd_obj_add_str(summary, "reason", "no_connection_samples");
    return summary;
}

static void webd_profile_normalize_visits(struct json_object *arr, int app_history)
{
    int i, n;

    if (!arr || !json_object_is_type(arr, json_type_array))
        return;
    n = (int)json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        struct json_object *v = json_object_array_get_idx(arr, i);
        int64_t ts = app_nc_json_int64(v, "ts", app_nc_json_int64(v, "last_seen", 0));
        const char *app_name = webd_first_nonempty4(
            app_nc_json_str(v, "app_name", ""),
            app_nc_json_str(v, "appname", ""),
            app_nc_json_str(v, "name", ""),
            app_nc_json_str(v, "app", ""));
        int app_id = app_nc_json_int(v, "appid", app_nc_json_int(v, "app_id", 0));

        if (!v || !json_object_is_type(v, json_type_object))
            continue;
        json_object_object_add(v, "appid", json_object_new_int(app_id));
        json_object_object_add(v, "app_id", json_object_new_int(app_id));
        webd_obj_add_str(v, "app_name", app_name);
        webd_obj_add_str(v, "appname", app_name);
        if (!json_object_object_get(v, "first_time"))
            json_object_object_add(v, "first_time", json_object_new_int64(ts));
        if (!json_object_object_get(v, "latest_time"))
            json_object_object_add(v, "latest_time", json_object_new_int64(ts));
        if (!json_object_object_get(v, "duration")) {
            json_object_object_add(v, "duration", json_object_new_int64(0));
            json_object_object_add(v, "duration_source", json_object_new_string("unavailable"));
        }
        if (!json_object_object_get(v, "total_time"))
            json_object_object_add(v, "total_time", json_object_new_int64(app_nc_json_int64(v, "duration", 0)));
        if (app_history && !json_object_object_get(v, "status"))
            json_object_object_add(v, "status", json_object_new_string("seen"));
    }
}

static int webd_policy_text_matches_client(const char *text, const char *mac, const char *ip)
{
    if (!text || !text[0])
        return 0;
    if (mac && mac[0] && webd_str_contains_i(text, mac))
        return 1;
    if (ip && ip[0] && strstr(text, ip))
        return 1;
    return 0;
}

static void webd_profile_add_matching_rules(struct json_object *out,
                                            struct json_object *all_rules,
                                            const char *out_key,
                                            const char *policy_type,
                                            const char *mac,
                                            const char *ip,
                                            int *blocked,
                                            int *rate_limit,
                                            struct json_object *combined)
{
    struct json_object *matches = json_object_new_array();
    int i, n;

    if (!all_rules || !json_object_is_type(all_rules, json_type_array)) {
        json_object_object_add(out, out_key, matches);
        return;
    }
    n = (int)json_object_array_length(all_rules);
    for (i = 0; i < n; i++) {
        struct json_object *rule = json_object_array_get_idx(all_rules, i);
        const char *rule_mac = app_nc_json_str(rule, "mac", "");
        const char *address = app_nc_json_str(rule, "address", "");
        const char *source = app_nc_json_str(rule, "source", "");
        const char *mode = app_nc_json_str(rule, "mode", "");
        const char *action = app_nc_json_str(rule, "action", "");
        int match = 0;

        if (!rule || !json_object_is_type(rule, json_type_object))
            continue;
        if (rule_mac[0] && mac && mac[0] && !strcasecmp(rule_mac, mac))
            match = 1;
        if (!match && address[0] &&
            ((mac && mac[0] && !strcasecmp(address, mac)) ||
             (ip && ip[0] && !strcmp(address, ip))))
            match = 1;
        if (!match && webd_policy_text_matches_client(source, mac, ip))
            match = 1;
        if (!match)
            continue;

        json_object_object_add(rule, "policy_type", json_object_new_string(policy_type));
        json_object_array_add(matches, json_object_get(rule));
        json_object_array_add(combined, json_object_get(rule));
        if (blocked && (!strcasecmp(mode, "deny") || !strcasecmp(mode, "block") ||
                        !strcasecmp(action, "deny") || !strcasecmp(action, "block")))
            *blocked = 1;
        if (rate_limit && !strcmp(policy_type, "terminal_limit"))
            *rate_limit = 1;
    }
    json_object_object_add(out, out_key, matches);
}

static struct json_object *webd_client_profile_policies(struct json_object *netctl,
                                                        const char *mac,
                                                        const char *ip,
                                                        int *available)
{
    struct json_object *policies = json_object_new_object();
    struct json_object *rules = json_object_new_array();
    int blocked = 0;
    int rate_limit = 0;

    if (available)
        *available = netctl != NULL;
    json_object_object_add(policies, "degraded", json_object_new_boolean(netctl == NULL));
    webd_obj_add_str(policies, "source", netctl ? "network_control_get" : "unavailable");
    webd_obj_add_str(policies, "filtering", netctl ? "best_effort_mac_ip" : "unavailable");
    if (!netctl) {
        webd_obj_add_str(policies, "reason", "network_control_unavailable");
        json_object_object_add(policies, "rules", rules);
        json_object_object_add(policies, "blocked", json_object_new_boolean(0));
        json_object_object_add(policies, "rate_limit", json_object_new_boolean(0));
        json_object_object_add(policies, "parental_control", json_object_new_boolean(0));
        json_object_object_add(policies, "wan_policy", json_object_new_boolean(0));
        return policies;
    }

    if (webd_obj_child(netctl, "global"))
        json_object_object_add(policies, "global", json_object_get(webd_obj_child(netctl, "global")));
    if (webd_obj_child(netctl, "other_control"))
        json_object_object_add(policies, "other_control", json_object_get(webd_obj_child(netctl, "other_control")));
    webd_profile_add_matching_rules(policies, webd_obj_child_array(netctl, "mac_rules"),
                                    "mac_rules", "mac", mac, ip, &blocked, NULL, rules);
    webd_profile_add_matching_rules(policies, webd_obj_child_array(netctl, "terminal_limits"),
                                    "terminal_limits", "terminal_limit", mac, ip, NULL, &rate_limit, rules);
    webd_profile_add_matching_rules(policies, webd_obj_child_array(netctl, "app_rules"),
                                    "app_rules", "app", mac, ip, &blocked, NULL, rules);
    webd_profile_add_matching_rules(policies, webd_obj_child_array(netctl, "url_access_rules"),
                                    "url_access_rules", "url_access", mac, ip, &blocked, NULL, rules);
    webd_profile_add_matching_rules(policies, webd_obj_child_array(netctl, "connection_limits"),
                                    "connection_limits", "connection_limit", mac, ip, NULL, NULL, rules);
    json_object_object_add(policies, "rules", rules);
    json_object_object_add(policies, "blocked", json_object_new_boolean(blocked));
    json_object_object_add(policies, "rate_limit", json_object_new_boolean(rate_limit));
    json_object_object_add(policies, "parental_control", json_object_new_boolean(0));
    json_object_object_add(policies, "wan_policy", json_object_new_boolean(0));
    return policies;
}

struct json_object *webd_client_profile_response(const struct http_req *req)
{
    char mac[64] = {0};
    char norm_mac[32] = {0};
    struct json_object *params = NULL;
    struct json_object *profile = json_object_new_object();
    struct json_object *current = NULL;
    struct json_object *basic = NULL;
    struct json_object *cap = json_object_new_object();
    struct json_object *traffic_points = json_object_new_array();
    struct json_object *overview_history = json_object_new_array();
    struct json_object *protocol_history = json_object_new_object();
    struct json_object *today_metrics = json_object_new_object();
    struct json_object *online_records = json_object_new_array();
    struct json_object *visit_records = json_object_new_array();
    struct json_object *app_history = json_object_new_array();
    struct json_object *sessions = json_object_new_array();
    struct json_object *connections = json_object_new_array();
    struct json_object *lines = json_object_new_array();
    struct json_object *control_rules = NULL;
    struct json_object *protocol_summary = NULL;
    struct json_object *policies = NULL;
    struct json_object *diagnostics = json_object_new_object();
    struct json_object *missing = json_object_new_array();
    struct json_object *client = NULL;
    struct json_object *identity = NULL;
    struct json_object *topology = NULL;
    struct json_object *netctl = NULL;
    int session_count = -1;
    int policies_available = 0;
    int connection_app_domain = 0;
    int connection_source_flows = 0;
    int include_connections = 1;

    {
        char include_text[16] = {0};

        if (webd_query_get(req ? req->query : "", "include_connections",
                           include_text, sizeof(include_text)) &&
            (!strcmp(include_text, "0") || !strcasecmp(include_text, "false") ||
             !strcasecmp(include_text, "no")))
            include_connections = 0;
    }

    if (!webd_query_get(req ? req->query : "", "mac", mac, sizeof(mac)) ||
        webd_normalize_mac_text(mac, norm_mac, sizeof(norm_mac)) != 0) {
        json_object_object_add(profile, "ok", json_object_new_boolean(0));
        json_object_object_add(profile, "error", json_object_new_string("missing_mac"));
        return profile;
    }

    params = json_object_new_object();
    json_object_object_add(params, "mac", json_object_new_string(norm_mac));
    {
        struct json_object *cg = app_ubus_invoke("client_get", params);
        struct json_object *data = NULL;

        if (cg && (data = webd_jmx_data_ref(cg)) &&
            json_object_object_get_ex(data, "client", &client) && client) {
            client = json_object_get(client);
            json_object_object_add(cap, "current", json_object_new_boolean(1));
            json_object_object_add(cap, "basic", json_object_new_boolean(1));
        } else {
            json_object_object_add(cap, "current", json_object_new_boolean(0));
            json_object_object_add(cap, "basic", json_object_new_boolean(0));
            json_object_array_add(missing, json_object_new_string("client_get"));
        }
        if (data) json_object_put(data);
        if (cg) json_object_put(cg);
    }
    {
        struct json_object *ci = app_ubus_invoke("client_identity", params);
        struct json_object *data = NULL;

        if (ci && (data = webd_jmx_data_ref(ci))) {
            struct json_object *fp = NULL;
            struct json_object *signals = NULL;
            struct json_object *candidates = NULL;
            struct json_object *override = NULL;

            identity = json_object_get(data);
            if (json_object_object_get_ex(data, "fingerprint", &fp) && fp)
                json_object_object_add(profile, "fingerprint", json_object_get(fp));
            if (json_object_object_get_ex(data, "signals", &signals) && signals)
                json_object_object_add(profile, "signals", json_object_get(signals));
            if (json_object_object_get_ex(data, "candidates", &candidates) && candidates)
                json_object_object_add(profile, "candidates", json_object_get(candidates));
            if (json_object_object_get_ex(data, "override", &override) && override)
                json_object_object_add(profile, "override", json_object_get(override));
            json_object_object_add(cap, "identity", json_object_new_boolean(1));
        } else {
            json_object_object_add(cap, "identity", json_object_new_boolean(0));
            json_object_array_add(missing, json_object_new_string("client_identity"));
        }
        if (data) json_object_put(data);
        if (ci) json_object_put(ci);
    }
    {
        struct json_object *td_params = json_object_new_object();
        struct json_object *td;
        struct json_object *td_data = NULL;

        json_object_object_add(td_params, "mac", json_object_new_string(norm_mac));
        json_object_object_add(td_params, "type", json_object_new_string("CLIENT"));
        td = app_ubus_invoke("topology_node_detail", td_params);
        json_object_put(td_params);
        if (td && (td_data = webd_jmx_data_ref(td))) {
            topology = json_object_get(td_data);
            json_object_object_add(profile, "topology_node", json_object_get(td_data));
            json_object_object_add(cap, "topology_node", json_object_new_boolean(1));
        } else {
            json_object_object_add(cap, "topology_node", json_object_new_boolean(0));
            json_object_array_add(missing, json_object_new_string("topology_node_detail"));
        }
        if (td_data) json_object_put(td_data);
        if (td) json_object_put(td);
    }
    {
        struct json_object *th = app_ubus_invoke("client_traffic_history", params);
        struct json_object *points = NULL;
        struct json_object *overview = NULL;
        struct json_object *protocol = NULL;
        struct json_object *today = NULL;

        if (th && json_object_object_get_ex(th, "points", &points) && points &&
            json_object_is_type(points, json_type_array)) {
            json_object_put(traffic_points);
            traffic_points = json_object_get(points);
            json_object_object_add(cap, "traffic_history", json_object_new_boolean(1));
        } else {
            json_object_object_add(cap, "traffic_history", json_object_new_boolean(0));
            json_object_array_add(missing, json_object_new_string("client_traffic_history"));
        }
        if (th && json_object_object_get_ex(th, "overview_history", &overview) && overview &&
            json_object_is_type(overview, json_type_array)) {
            json_object_put(overview_history);
            overview_history = json_object_get(overview);
            json_object_object_add(cap, "overview_history", json_object_new_boolean(
                json_object_array_length(overview_history) > 0));
            json_object_object_add(cap, "overview_history_window_sec", json_object_new_int(
                app_nc_json_int(th, "overview_window_sec", 300)));
            json_object_object_add(cap, "overview_history_step_sec", json_object_new_int(
                app_nc_json_int(th, "overview_step_sec", 4)));
            json_object_object_add(cap, "overview_history_source", json_object_new_string(
                app_nc_json_str(th, "overview_source", "client_runtime_ring")));
            if (json_object_array_length(overview_history) == 0)
                json_object_object_add(cap, "overview_history_reason", json_object_new_string(
                    app_nc_json_str(th, "overview_reason", "no_runtime_samples_yet")));
        } else {
            json_object_object_add(cap, "overview_history", json_object_new_boolean(0));
            json_object_object_add(cap, "overview_history_reason",
                                   json_object_new_string("client_runtime_ring_unavailable"));
        }
        if (th && json_object_object_get_ex(th, "today_metrics", &today) && today &&
            json_object_is_type(today, json_type_object)) {
            json_object_put(today_metrics);
            today_metrics = json_object_get(today);
        }
        if (th && json_object_object_get_ex(th, "protocol_rate_history", &protocol) &&
            protocol && json_object_is_type(protocol, json_type_object)) {
            json_object_put(protocol_history);
            protocol_history = json_object_get(protocol);
        }
        if (th) json_object_put(th);
    }
    {
        struct json_object *oh = app_ubus_invoke("client_online_history", params);
        struct json_object *records = NULL;

        if (oh && json_object_object_get_ex(oh, "records", &records) && records &&
            json_object_is_type(records, json_type_array)) {
            json_object_put(online_records);
            online_records = json_object_get(records);
            json_object_object_add(cap, "online_history", json_object_new_boolean(1));
        } else {
            json_object_object_add(cap, "online_history", json_object_new_boolean(0));
            json_object_array_add(missing, json_object_new_string("client_online_history"));
        }
        if (oh) json_object_put(oh);
    }
    if (include_connections) {
        struct json_object *flow_data = NULL;
        struct json_object *items = NULL;
        const char *client_ip = app_nc_json_str(client, "ip", "");
        struct webd_current_flows_diag flow_diag;

        /*
         * First page only: a busy client can hold thousands of conntrack flows
         * and the ubus reply must stay under the ~1 MiB stability bound.  The
         * page size starts at the upstream maximum; when 200 rich rows do not
         * fit, the fetch shrinks the page and says so, instead of dropping to
         * client_connections - that fallback has no WAN attribution, so the
         * line column went blank for exactly the busiest clients.  The real
         * total plus a has-more fact are published below so the caller pages
         * through /api/v1/insights/flows/current.
         */
        flow_data = webd_insights_fetch_current_flows_diag(norm_mac, "",
                                                          WEBD_CURRENT_FLOWS_PAGE_MAX,
                                                          0, &flow_diag);
        if (flow_data &&
            ((json_object_object_get_ex(flow_data, "items", &items) && items) ||
             (json_object_object_get_ex(flow_data, "flows", &items) && items)) &&
            json_object_is_type(items, json_type_array) &&
            json_object_array_length(items) > 0) {
            json_object_put(connections);
            connections = webd_profile_connections_from_flows(items, lines);
            json_object_put(sessions);
            sessions = json_object_get(connections);
            session_count = (int)json_object_array_length(connections);
            connection_app_domain = 1;
            connection_source_flows = 1;
            json_object_object_add(cap, "sessions", json_object_new_boolean(1));
            json_object_object_add(cap, "connections", json_object_new_boolean(1));
            json_object_object_add(cap, "connection_details", json_object_new_boolean(1));
            json_object_object_add(cap, "connection_app_domain", json_object_new_boolean(1));
            json_object_object_add(cap, "connection_source", json_object_new_string("insights_current_flows"));
            webd_current_flows_diag_publish(cap, &flow_diag);
            webd_json_copy_key(cap, "connection_source_state", flow_data, "source_state");
            webd_json_copy_key(cap, "connection_app_resolution_priority", flow_data,
                               "app_resolution_priority");
            /*
             * connections[] is one page; current.connections reports the live
             * total.  Publishing both facts explicitly keeps the frontend from
             * comparing the two and guessing.
             */
            {
                int page_len = (int)json_object_array_length(connections);
                int total = app_nc_json_int(flow_data, "total", page_len);

                if (total < page_len)
                    total = page_len;
                json_object_object_add(cap, "connection_total", json_object_new_int(total));
                json_object_object_add(cap, "connection_page_size",
                                       json_object_new_int(flow_diag.limit_used > 0 ?
                                                           flow_diag.limit_used :
                                                           WEBD_CURRENT_FLOWS_PAGE_MAX));
                json_object_object_add(cap, "connection_page_offset", json_object_new_int(0));
                json_object_object_add(cap, "connection_returned", json_object_new_int(page_len));
                json_object_object_add(cap, "connection_has_more",
                                       json_object_new_boolean(page_len < total));
                json_object_object_add(cap, "connection_total_exact",
                    json_object_new_boolean(app_nc_json_bool(flow_data, "total_exact", 1)));
                /*
                 * Always name the paging endpoint. Its absence was read as a
                 * missing contract field rather than as "there is no next page".
                 */
                json_object_object_add(cap, "connection_page_source",
                    json_object_new_string("/api/v1/insights/flows/current?mac=<mac>&limit=<n>&offset=<n>"));
            }
        }
        if (!flow_data) {
            webd_current_flows_diag_publish(cap, &flow_diag);
            webd_obj_add_str(cap, "connection_flow_source_reason",
                             flow_diag.too_large ? "response_too_large" :
                             (flow_diag.reason[0] ? flow_diag.reason :
                              "insights_current_flows_unavailable"));
        }
        if (flow_data) json_object_put(flow_data);
        (void)client_ip;
    }
    if (include_connections && !connection_source_flows) {
        struct json_object *cc_params = json_object_new_object();
        struct json_object *cc;
        struct json_object *conns = NULL;
        const char *client_ip = app_nc_json_str(client, "ip", "");

        json_object_object_add(cc_params, "mac", json_object_new_string(norm_mac));
        /*
         * Fallback source. Upstream dw_handle_client_connections() defaults to
         * 200 and allows up to DW_CONN_LIMIT_MAX (2000); it also reports total /
         * returned / truncated. Ask for one page of the same size the primary
         * source uses and republish its counts, instead of clamping to 100 and
         * leaving the caller unable to tell a short list from a truncated one.
         */
        json_object_object_add(cc_params, "limit",
                               json_object_new_int(WEBD_CURRENT_FLOWS_PAGE_MAX));
        cc = app_ubus_invoke("client_connections", cc_params);
        json_object_put(cc_params);
        if (cc && !app_nc_json_bool(cc, "degraded", 0) &&
            json_object_object_get_ex(cc, "connections", &conns) && conns &&
            json_object_is_type(conns, json_type_array)) {
            json_object_put(connections);
            connections = webd_profile_sessions_from_connections(conns, client_ip, lines);
            json_object_put(sessions);
            sessions = json_object_get(connections);
            session_count = (int)json_object_array_length(sessions);
            json_object_object_add(cap, "sessions", json_object_new_boolean(1));
            json_object_object_add(cap, "connections", json_object_new_boolean(1));
            json_object_object_add(cap, "connection_details", json_object_new_boolean(1));
            json_object_object_add(cap, "connection_app_domain", json_object_new_boolean(0));
            json_object_object_add(cap, "connection_app_domain_reason",
                                   json_object_new_string("host_or_signature_source_unavailable; using port/proto fallback"));
            json_object_object_add(cap, "connection_source", json_object_new_string("client_connections"));
            {
                int page_len = (int)json_object_array_length(connections);
                int total = app_nc_json_int(cc, "total", page_len);

                if (total < page_len)
                    total = page_len;
                json_object_object_add(cap, "connection_total", json_object_new_int(total));
                json_object_object_add(cap, "connection_page_size",
                                       json_object_new_int(WEBD_CURRENT_FLOWS_PAGE_MAX));
                json_object_object_add(cap, "connection_page_offset", json_object_new_int(0));
                json_object_object_add(cap, "connection_returned", json_object_new_int(page_len));
                json_object_object_add(cap, "connection_has_more",
                    json_object_new_boolean(page_len < total ||
                                            app_nc_json_bool(cc, "truncated", 0)));
                json_object_object_add(cap, "connection_total_exact", json_object_new_boolean(1));
            }
        } else {
            json_object_object_add(cap, "sessions", json_object_new_boolean(0));
            json_object_object_add(cap, "connections", json_object_new_boolean(0));
            json_object_object_add(cap, "connection_details", json_object_new_boolean(0));
            json_object_object_add(cap, "connection_app_domain", json_object_new_boolean(0));
            if (cc)
                json_object_object_add(cap, "sessions_reason",
                    json_object_new_string(app_nc_json_str(cc, "reason", "client_connections_unavailable")));
            json_object_array_add(missing, json_object_new_string("client_connections"));
        }
        if (cc) json_object_put(cc);
    } else if (!include_connections) {
        /*
         * This branch is for "the caller asked us to skip connections", and only
         * that.  It used to be the plain else of the fallback block, so a
         * *successful* flows fetch fell through here and had its own capability
         * flags overwritten: connection_source became client_connections_snapshot
         * and connections/connection_details went back to false while a full page
         * of attributed rows sat in connections[].
         */
        json_object_object_add(cap, "sessions", json_object_new_boolean(0));
        json_object_object_add(cap, "connections", json_object_new_boolean(0));
        json_object_object_add(cap, "connection_details", json_object_new_boolean(0));
        json_object_object_add(cap, "connection_source",
                               json_object_new_string("client_connections_snapshot"));
        json_object_object_add(cap, "connection_skipped",
                               json_object_new_boolean(1));
    }
    {
        struct json_object *vh = app_ubus_invoke("client_visit_history", params);
        struct json_object *visits = NULL;
        struct json_object *apps = NULL;
        int degraded = 0;

        if (vh && json_object_object_get_ex(vh, "visits", &visits) && visits &&
            json_object_is_type(visits, json_type_array)) {
            json_object_put(visit_records);
            visit_records = json_object_get(visits);
            json_object_object_add(cap, "visit_history", json_object_new_boolean(1));
        } else {
            json_object_object_add(cap, "visit_history", json_object_new_boolean(0));
            json_object_array_add(missing, json_object_new_string("client_visit_history"));
        }
        if (vh && json_object_object_get_ex(vh, "app_history", &apps) && apps &&
            json_object_is_type(apps, json_type_array)) {
            json_object_put(app_history);
            app_history = json_object_get(apps);
            json_object_object_add(cap, "app_history", json_object_new_boolean(1));
        } else {
            json_object_object_add(cap, "app_history", json_object_new_boolean(0));
        }
        if (vh)
            degraded = app_nc_json_bool(vh, "degraded", 0);
        json_object_object_add(cap, "visit_history_degraded", json_object_new_boolean(degraded));
        if (vh) json_object_put(vh);
    }
    {
        struct json_object *nc = app_ubus_invoke("network_control_get", NULL);

        if (nc)
            netctl = webd_jmx_data_ref(nc);
        if (nc)
            json_object_put(nc);
    }
    json_object_put(params);

    basic = webd_client_profile_basic(norm_mac, client, identity, topology);
    current = webd_client_profile_current(client, topology, today_metrics, session_count);
    {
        struct json_object *profile_fp = webd_obj_child_obj(profile, "fingerprint");
        if (profile_fp) {
            webd_obj_add_str(profile_fp, "detected_image",
                             app_nc_json_str(basic, "detected_image", ""));
            webd_obj_add_str(profile_fp, "image_url",
                             app_nc_json_str(basic, "detected_image", ""));
            webd_obj_add_str(profile_fp, "effective_image",
                             app_nc_json_str(basic, "image", ""));
            webd_obj_add_str(profile_fp, "image_source",
                             app_nc_json_str(basic, "image_source", "none"));
        }
    }
    webd_profile_lines_add_from_flow_control(lines);
    control_rules = webd_client_control_rules_load(norm_mac);
    protocol_summary = webd_profile_protocol_summary(connections, overview_history,
        protocol_history, current,
        connection_source_flows ? "insights_current_flows" : "client_connections");
    webd_profile_normalize_records(online_records);
    webd_profile_normalize_visits(visit_records, 0);
    webd_profile_normalize_visits(app_history, 1);
    policies = webd_client_profile_policies(netctl, norm_mac,
        app_nc_json_str(basic, "ip", ""), &policies_available);
    json_object_object_add(cap, "records", json_object_new_boolean(app_nc_json_bool(cap, "online_history", 0)));
    json_object_object_add(cap, "visits", json_object_new_boolean(
        app_nc_json_bool(cap, "visit_history", 0) || app_nc_json_bool(cap, "app_history", 0)));
    json_object_object_add(cap, "policies", json_object_new_boolean(policies_available));
    json_object_object_add(cap, "control_rules", json_object_new_boolean(
        control_rules && json_object_array_length(control_rules) > 0));
    webd_client_control_add_capabilities(cap);
    json_object_object_add(cap, "client_control_l4_filter", json_object_new_boolean(1));
    json_object_object_add(cap, "client_control_l4_filter_action", json_object_new_string("rate_limit_only"));
    json_object_object_add(cap, "client_control_protocol_scoped_rate_limit", json_object_new_boolean(1));
    json_object_object_add(cap, "client_control_app_policy", json_object_new_boolean(0));
    json_object_object_add(cap, "client_control_wan_policy", json_object_new_boolean(0));
    json_object_object_add(cap, "client_control_shared_rate_limit", json_object_new_boolean(0));
    json_object_object_add(cap, "client_control_schedule_plan", json_object_new_boolean(0));
    json_object_object_add(cap, "client_control_schedule", json_object_new_boolean(1));
    json_object_object_add(cap, "client_control_schedule_source", json_object_new_string("dreamingwrt-maintenanced:_maintenance_tick.client_control_schedule"));
    json_object_object_add(cap, "client_control_runtime_apply", json_object_new_string("IP限速=>client_rate_limit_set; others persisted unsupported"));
    json_object_object_add(cap, "client_control_ip_rate_limit_runtime", json_object_new_boolean(1));
    json_object_object_add(cap, "client_control_runtime_scope", json_object_new_string("client_mac_on_lan_bridge"));
    json_object_object_add(cap, "client_control_runtime_precision", json_object_new_string("mac_or_mac_l4_protocol"));
    json_object_object_add(cap, "client_control_runtime_dataplane", json_object_new_string("tc_ifb_htb_u32"));
    json_object_object_add(cap, "client_control_runtime_lan_bridge", json_object_new_string("br-lan"));
    json_object_object_add(cap, "client_control_line_runtime", json_object_new_boolean(0));
    json_object_object_add(cap, "client_control_line_runtime_reason",
                           json_object_new_string("line_filter_persisted_only_tc_runtime_not_implemented"));
    json_object_object_add(cap, "client_control_protocol_runtime", json_object_new_boolean(1));
    json_object_object_add(cap, "client_control_protocol_runtime_supported", json_object_new_string("TCP,UDP,ICMP,ICMPv6"));
    json_object_object_add(cap, "client_control_protocol_runtime_reason",
                           json_object_new_string("protocol_filter_applied_by_tc_u32_ip_ip6_protocol_when_selected"));
    json_object_object_add(cap, "bandwidth_history", json_object_new_boolean(
        app_nc_json_bool(cap, "overview_history", 0)));
    if (!app_nc_json_bool(cap, "overview_history", 0) && !app_nc_json_has(cap, "bandwidth_history_reason"))
        json_object_object_add(cap, "bandwidth_history_reason",
                               json_object_new_string(app_nc_json_str(cap, "overview_history_reason",
                                                        "no_runtime_samples_yet")));
    json_object_object_add(cap, "lines", json_object_new_boolean(json_object_array_length(lines) > 0));
    json_object_object_add(cap, "protocol_summary", json_object_new_boolean(1));
    json_object_object_add(cap, "protocol_summary_source", json_object_new_string(
        connection_source_flows ? "insights_current_flows" : "client_connections"));
    json_object_object_add(cap, "protocol_rate_live", json_object_new_boolean(
        app_nc_json_bool(protocol_summary, "protocol_rate_live_supported", 0)));
    json_object_object_add(cap, "protocol_rate_history", json_object_new_boolean(
        app_nc_json_bool(protocol_summary, "per_protocol_rate_history_supported", 0)));
    json_object_object_add(cap, "protocol_rate_history_reason", json_object_new_string(
        app_nc_json_str(protocol_summary, "rate_history_reason",
                        "per_protocol_rate_history_unavailable")));
    json_object_object_add(cap, "total_rate_history", json_object_new_boolean(
        app_nc_json_bool(protocol_summary, "total_rate_history_supported", 0)));
    json_object_object_add(cap, "total_rate_history_complete", json_object_new_boolean(
        app_nc_json_bool(protocol_summary, "total_rate_history_complete", 0)));
    webd_obj_add_str(cap, "total_rate_history_source",
                     app_nc_json_str(protocol_summary, "total_rate_history_source", "unavailable"));
    webd_obj_add_str(cap, "total_rate_history_reason",
                     app_nc_json_str(protocol_summary, "total_rate_history_reason", "no_runtime_samples_yet"));
    json_object_object_add(cap, "today_online_time", json_object_new_boolean(
        app_nc_json_bool(today_metrics, "available", 0)));
    json_object_object_add(cap, "today_active_time", json_object_new_boolean(
        app_nc_json_bool(today_metrics, "available", 0)));
    json_object_object_add(cap, "today_metrics_complete", json_object_new_boolean(
        app_nc_json_bool(today_metrics, "complete", 0)));
    webd_obj_add_str(cap, "today_metrics_source",
                     app_nc_json_str(today_metrics, "source", "unavailable"));
    webd_obj_add_str(cap, "today_metrics_reason",
                     app_nc_json_str(today_metrics, "degraded_reason", "today_runtime_bucket_unavailable"));
    json_object_object_add(diagnostics, "connection_source",
                           json_object_new_string(connection_source_flows ?
                                                  "insights_current_flows" : "client_connections"));
    json_object_object_add(diagnostics, "connection_app_domain",
                           json_object_new_boolean(connection_app_domain));
    json_object_object_add(diagnostics, "missing", missing);
    json_object_object_add(diagnostics, "complete", json_object_new_boolean(json_object_array_length(missing) == 0));
    json_object_object_add(diagnostics, "source", json_object_new_string("webd.client_profile+bff"));

    json_object_object_add(profile, "ok", json_object_new_boolean(1));
    json_object_object_add(profile, "mac", json_object_new_string(norm_mac));
    json_object_object_add(profile, "current", current);
    json_object_object_add(profile, "basic", basic);
    json_object_object_add(profile, "detected_identity",
                           webd_client_profile_detected_identity(client, identity));
    json_object_object_add(profile, "effective_identity",
                           webd_client_profile_effective_identity(basic));
    {
        struct json_object *override_fields = webd_obj_child_array(client, "override_fields");
        json_object_object_add(profile, "override_fields",
                               override_fields ? json_object_get(override_fields) :
                               json_object_new_array());
    }
    json_object_object_add(profile, "traffic_history", traffic_points);
    json_object_object_add(profile, "overview_history", overview_history);
    {
        struct json_object *history = webd_obj_child_array(protocol_summary, "rate_history");
        json_object_object_add(profile, "protocol_rate_history",
                               history ? json_object_get(history) : json_object_new_array());
    }
    json_object_object_add(profile, "today_metrics", today_metrics);
    json_object_object_add(profile, "visits", visit_records);
    json_object_object_add(profile, "app_history", app_history);
    json_object_object_add(profile, "records", json_object_get(online_records));
    json_object_object_add(profile, "online_history", online_records);
    json_object_object_add(profile, "connections", connections);
    json_object_object_add(profile, "lines", lines);
    json_object_object_add(profile, "wans", json_object_get(lines));
    json_object_object_add(profile, "wan_list", json_object_get(lines));
    json_object_object_add(profile, "interfaces", json_object_get(lines));
    json_object_object_add(profile, "sessions", sessions);
    json_object_object_add(profile, "protocol_summary", protocol_summary);
    json_object_object_add(profile, "policies", policies);
    json_object_object_add(profile, "control_rules", control_rules ? control_rules : json_object_new_array());
    json_object_object_add(profile, "controls", json_object_get(webd_obj_child(profile, "control_rules")));
    json_object_object_add(profile, "limit_rules", json_object_get(webd_obj_child(profile, "control_rules")));
    json_object_object_add(profile, "policy_rules", json_object_get(webd_obj_child(profile, "control_rules")));
    json_object_object_add(profile, "qos_rules", json_object_new_array());
    json_object_object_add(profile, "parental_rules", json_object_new_array());
    json_object_object_add(profile, "capabilities", cap);
    json_object_object_add(profile, "diagnostics", diagnostics);
    json_object_object_add(profile, "source", json_object_new_string("webd.client_profile"));
    if (client) json_object_put(client);
    if (identity) json_object_put(identity);
    if (topology) json_object_put(topology);
    if (netctl) json_object_put(netctl);
    json_object_put(protocol_history);
    return profile;
}

static struct json_object *client_profile_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = webd_client_profile_response(ctx->req);
    if (!app_nc_json_bool(resp, "ok", 0))
        ctx->status = 400;
    return resp;
}

const struct jmx_api_route client_profile_api_routes[] = {
    JMX_API_ROUTE(587, "/api/v1/client_profile", "GET", JMX_API_EXACT, client_profile_get),
    JMX_API_ROUTE_END,
};
