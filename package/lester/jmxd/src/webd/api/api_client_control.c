// SPDX-License-Identifier: GPL-2.0-or-later
/* Client-control rules CRUD: validation, capability gating, and rollback. */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "../jmx_app_api.h"
#include "api_client_control.h"
#include "api_client_control_internal.h"
#include "api_error.h"
#include "api_json.h"
#include "api_ubus.h"
#include "api_util.h"

static int webd_client_control_mac_valid(const char *mac)
{
    unsigned int first = 0;

    if (!mac || sscanf(mac, "%2x", &first) != 1 || (first & 1U))
        return 0;
    return strcmp(mac, "00:00:00:00:00:00") && strcmp(mac, "ff:ff:ff:ff:ff:ff");
}

static int webd_control_limit_to_kbps(int value, const char *unit)
{
    if (value <= 0)
        return 0;
    if (!unit || !unit[0])
        return value * 8;
    if (!strcmp(unit, "Kbps") || !strcmp(unit, "kbps") ||
        !strcmp(unit, "Kb/s") || !strcmp(unit, "kb/s") ||
        !strcmp(unit, "Kbit/s") || !strcmp(unit, "kbit/s"))
        return value;
    if (!strcmp(unit, "Mbps") || !strcmp(unit, "mbps") ||
        !strcmp(unit, "Mb/s") || !strcmp(unit, "mb/s") ||
        !strcmp(unit, "Mbit/s") || !strcmp(unit, "mbit/s"))
        return value * 1024;
    if (!strcmp(unit, "KB/s") || !strcmp(unit, "KBps") ||
        !strcmp(unit, "KByte/s") || !strcmp(unit, "KBytes/s") ||
        !strcasecmp(unit, "KiB/s"))
        return value * 8;
    if (!strcmp(unit, "MB/s") || !strcmp(unit, "MBps") ||
        !strcmp(unit, "MByte/s") || !strcmp(unit, "MBytes/s") ||
        !strcasecmp(unit, "MiB/s"))
        return value * 8 * 1024;
    return value * 8;
}

static void webd_control_normalize_days_delimiters(char *s)
{
    char out[256];
    size_t i = 0, j = 0;

    if (!s)
        return;
    while (s[i] && j + 1 < sizeof(out)) {
        if (!strncmp(s + i, "，", strlen("，")) ||
            !strncmp(s + i, "；", strlen("；")) ||
            !strncmp(s + i, "、", strlen("、"))) {
            out[j++] = ' ';
            i += strlen("，");
            continue;
        }
        out[j++] = s[i++];
    }
    out[j] = '\0';
    snprintf(s, 256, "%s", out);
}

/*
 * Length of the UTF-8 sequence starting at s, or 0 if s does not begin a
 * well-formed sequence. Rejects overlong forms, surrogates and > U+10FFFF so a
 * malformed byte run can never be accepted as "valid enough" to store.
 */
static size_t webd_utf8_seq_len(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    unsigned char c = p[0];
    size_t need, i;

    if (c < 0x80)
        return 1;
    if (c >= 0xc2 && c <= 0xdf)
        need = 2;
    else if (c >= 0xe0 && c <= 0xef)
        need = 3;
    else if (c >= 0xf0 && c <= 0xf4)
        need = 4;
    else
        return 0;               /* continuation byte or invalid lead */

    for (i = 1; i < need; i++) {
        if (p[i] < 0x80 || p[i] > 0xbf)
            return 0;           /* truncated or corrupted sequence */
    }
    if (need == 3) {
        if (c == 0xe0 && p[1] < 0xa0)
            return 0;           /* overlong */
        if (c == 0xed && p[1] > 0x9f)
            return 0;           /* UTF-16 surrogate */
    } else if (need == 4) {
        if (c == 0xf0 && p[1] < 0x90)
            return 0;           /* overlong */
        if (c == 0xf4 && p[1] > 0x8f)
            return 0;           /* beyond U+10FFFF */
    }
    return need;
}

static int webd_text_is_valid_utf8(const char *s)
{
    size_t i = 0;

    if (!s)
        return 0;
    while (s[i]) {
        size_t n = webd_utf8_seq_len(s + i);

        if (n == 0)
            return 0;
        i += n;
    }
    return 1;
}

/*
 * Copy src into dst without ever splitting a multi-byte character. A plain
 * snprintf() truncating mid-sequence is how "一 二 三" turns into bytes that no
 * UTF-8 reader can decode.
 */
static void webd_utf8_copy_truncate(char *dst, size_t dst_len, const char *src)
{
    size_t i = 0, out = 0;

    if (!dst || dst_len == 0)
        return;
    dst[0] = '\0';
    if (!src)
        return;
    while (src[i]) {
        size_t n = webd_utf8_seq_len(src + i);

        if (n == 0)
            break;              /* caller validates; stop rather than emit junk */
        if (out + n >= dst_len)
            break;
        memcpy(dst + out, src + i, n);
        out += n;
        i += n;
    }
    dst[out] = '\0';
}

static int webd_control_days_from_body(struct json_object *body,
                                       char *days_text, size_t days_text_len,
                                       char *days_json, size_t days_json_len,
                                       struct json_object **days_array_out)
{
    struct json_object *days = NULL;
    struct json_object *arr = json_object_new_array();
    char text[256] = {0};
    size_t used = 0;
    int i, n;

    if (days_array_out)
        *days_array_out = NULL;
    if (!arr)
        return -1;
    if (json_object_object_get_ex(body, "days", &days) && days &&
        json_object_is_type(days, json_type_array)) {
        n = (int)json_object_array_length(days);
        for (i = 0; i < n; i++) {
            struct json_object *v = json_object_array_get_idx(days, i);
            const char *s = json_object_get_string(v);
            if (!s || !s[0])
                continue;
            if (!webd_text_is_valid_utf8(s)) {
                json_object_put(arr);
                return -1;
            }
            json_object_array_add(arr, json_object_new_string(s));
            if (used + strlen(s) + 2 < sizeof(text)) {
                if (used > 0)
                    text[used++] = ' ';
                used += snprintf(text + used, sizeof(text) - used, "%s", s);
            }
        }
    } else {
        const char *raw = app_nc_json_str(body, "days",
            app_nc_json_str(body, "days_text", ""));
        char tmp[256];
        char *save = NULL;
        char *tok;

        if (raw && raw[0] && !webd_text_is_valid_utf8(raw)) {
            json_object_put(arr);
            return -1;
        }
        webd_utf8_copy_truncate(tmp, sizeof(tmp),
                                raw && raw[0] ? raw : "一 二 三 四 五 六 日");
        webd_control_normalize_days_delimiters(tmp);
        for (tok = strtok_r(tmp, " ,;\t\r\n", &save); tok; tok = strtok_r(NULL, " ,;\t\r\n", &save)) {
            json_object_array_add(arr, json_object_new_string(tok));
            if (used + strlen(tok) + 2 < sizeof(text)) {
                if (used > 0)
                    text[used++] = ' ';
                used += snprintf(text + used, sizeof(text) - used, "%s", tok);
            }
        }
    }
    if (!text[0])
        snprintf(text, sizeof(text), "%s", "一 二 三 四 五 六 日");
    /*
     * Last line of defence: never let a malformed byte run reach the database,
     * whatever path built `text`. A corrupted days string fails silently at
     * match time (strstr misses that weekday) instead of erroring, so it has to
     * be caught here.
     */
    if (!webd_text_is_valid_utf8(text)) {
        json_object_put(arr);
        return -1;
    }
    if (days_text && days_text_len > 0)
        webd_utf8_copy_truncate(days_text, days_text_len, text);
    if (days_json && days_json_len > 0)
        snprintf(days_json, days_json_len, "%s", json_object_to_json_string_ext(arr, JSON_C_TO_STRING_PLAIN));
    if (days_array_out)
        *days_array_out = json_object_get(arr);
    json_object_put(arr);
    return 0;
}

static struct json_object *webd_control_days_array_from_json(const char *json, const char *fallback_text)
{
    struct json_object *arr = NULL;

    if (json && json[0])
        arr = json_tokener_parse(json);
    if (!arr || !json_object_is_type(arr, json_type_array)) {
        if (arr)
            json_object_put(arr);
        arr = json_object_new_array();
        if (fallback_text && fallback_text[0]) {
            char tmp[256];
            char *save = NULL;
            char *tok;
            snprintf(tmp, sizeof(tmp), "%s", fallback_text);
            webd_control_normalize_days_delimiters(tmp);
            for (tok = strtok_r(tmp, " ,;\t\r\n", &save); tok; tok = strtok_r(NULL, " ,;\t\r\n", &save))
                json_object_array_add(arr, json_object_new_string(tok));
        }
    }
    return arr ? arr : json_object_new_array();
}

static int webd_control_match_value_selected(const char *value)
{
    if (!value || !value[0])
        return 0;
    return strcmp(value, "任意") && strcmp(value, "全部") &&
           strcasecmp(value, "any") && strcasecmp(value, "all") &&
           strcasecmp(value, "*");
}

static int webd_control_protocol_runtime_supported(const char *protocol)
{
    if (!webd_control_match_value_selected(protocol))
        return 0;
    return !strcasecmp(protocol, "tcp") || !strcasecmp(protocol, "udp") ||
           !strcasecmp(protocol, "icmp") || !strcasecmp(protocol, "icmpv6") ||
           !strcasecmp(protocol, "ipv6-icmp");
}

static int webd_control_schedule_mode_supported(const char *mode)
{
    if (!mode || !mode[0])
        return 1;
    return !strcasecmp(mode, "week") || !strcasecmp(mode, "range") ||
           !strcasecmp(mode, "always") || !strcasecmp(mode, "all") ||
           !strcasecmp(mode, "daily") || !strcmp(mode, "按周循环") ||
           !strcmp(mode, "时间段") || !strcmp(mode, "每天") ||
           !strcmp(mode, "每日") || !strcmp(mode, "永久");
}

static int webd_control_time_valid(const char *value)
{
    int hour = 0;
    int minute = 0;
    char tail = 0;

    return value && sscanf(value, "%d:%d%c", &hour, &minute, &tail) == 2 &&
           hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59;
}

static int webd_control_limit_value(struct json_object *body, const char *key,
                                    const char *unit, int *value_out)
{
    struct json_object *raw = NULL;
    const char *text = NULL;
    char *end = NULL;
    long long value;
    long long factor = 8;

    if (value_out)
        *value_out = 0;
    if (!body || !json_object_object_get_ex(body, key, &raw) || !raw)
        return 1;
    if (json_object_is_type(raw, json_type_int)) {
        value = json_object_get_int64(raw);
    } else if (json_object_is_type(raw, json_type_string)) {
        text = json_object_get_string(raw);
        if (!text || !text[0])
            return 0;
        errno = 0;
        value = strtoll(text, &end, 10);
        if (errno || !end || *end)
            return 0;
    } else {
        return 0;
    }
    if (value < 0)
        return 0;
    if (!strcmp(unit, "Kbps") || !strcmp(unit, "kbps") ||
        !strcmp(unit, "Kb/s") || !strcmp(unit, "kb/s"))
        factor = 1;
    else if (!strcmp(unit, "Mbps") || !strcmp(unit, "mbps") ||
             !strcmp(unit, "Mb/s") || !strcmp(unit, "mb/s"))
        factor = 1024;
    else if (!strcmp(unit, "MB/s") || !strcmp(unit, "MBps"))
        factor = 8 * 1024;
    else if (strcmp(unit, "KB/s") && strcmp(unit, "KBps"))
        return 0;
    if (value > INT_MAX || value * factor > INT_MAX)
        return 0;
    if (value_out)
        *value_out = (int)value;
    return 1;
}

static struct json_object *webd_client_control_write_error(const char *code,
                                                            const char *message,
                                                            const char *field,
                                                            const char *capability,
                                                            const char *reason,
                                                            int *status,
                                                            int http_status)
{
    struct json_object *resp = webd_error(code, message, field,
                                          "webd.client_control_rule");
    struct json_object *err = NULL;
    struct json_object *details = NULL;

    if (status)
        *status = http_status;
    webd_obj_add_str(resp, "field", field);
    webd_obj_add_str(resp, "capability", capability);
    webd_obj_add_str(resp, "reason", reason);
    json_object_object_add(resp, "changed", json_object_new_boolean(0));
    json_object_object_add(resp, "persisted", json_object_new_boolean(0));
    json_object_object_add(resp, "applied", json_object_new_boolean(0));
    if (json_object_object_get_ex(resp, "error", &err) && err &&
        json_object_object_get_ex(err, "details", &details) && details) {
        webd_obj_add_str(details, "field", field);
        webd_obj_add_str(details, "capability", capability);
        webd_obj_add_str(details, "reason", reason);
    }
    return resp;
}

static struct json_object *webd_client_control_validate_write(struct json_object *body,
                                                               int *up_limit_out,
                                                               int *down_limit_out,
                                                               int *status)
{
    const char *control_type = app_nc_json_str(body, "control_type",
        app_nc_json_str(body, "type", "IP限速"));
    const char *limit_mode = app_nc_json_str(body, "limit_mode", "独立限速");
    const char *line = app_nc_json_str(body, "line", "");
    const char *protocol = app_nc_json_str(body, "protocol", "任意");
    const char *schedule_mode = app_nc_json_str(body, "schedule_mode", "week");
    const char *start_time = app_nc_json_str(body, "start_time", "00:00");
    const char *end_time = app_nc_json_str(body, "end_time", "23:59");
    const char *up_unit = app_nc_json_str(body, "up_unit", "KB/s");
    const char *down_unit = app_nc_json_str(body, "down_unit", "KB/s");
    const char *name = app_nc_json_str(body, "name", "");
    const char *note = app_nc_json_str(body, "note", app_nc_json_str(body, "remark", ""));

    if (!control_type || strcmp(control_type, "IP限速"))
        return webd_client_control_write_error("capability_disabled",
            "this client control type has no runtime dataplane",
            "control_type", "client_control_rate_limit",
            "unsupported_control_type", status, 409);
    if (strcmp(limit_mode, "独立限速") && strcasecmp(limit_mode, "independent"))
        return webd_client_control_write_error("capability_disabled",
            "shared client rate limiting is not implemented",
            "limit_mode", "client_control_shared_rate_limit",
            "shared_rate_limit_dataplane_not_implemented", status, 409);
    if (webd_control_match_value_selected(line))
        return webd_client_control_write_error("capability_disabled",
            "line-scoped client rate limiting is not implemented",
            "line", "client_control_line_runtime",
            "line_scoped_client_rate_limit_not_implemented", status, 409);
    if (webd_control_match_value_selected(protocol) &&
        !webd_control_protocol_runtime_supported(protocol))
        return webd_client_control_write_error("capability_disabled",
            "the requested L4 protocol is not supported by the client rate-limit dataplane",
            "protocol", "client_control_protocol_runtime",
            "unsupported_l4_protocol", status, 409);
    if (!webd_control_schedule_mode_supported(schedule_mode))
        return webd_client_control_write_error("capability_disabled",
            "the requested schedule mode has no executable schedule reference",
            "schedule_mode", "client_control_schedule_plan",
            "schedule_plan_reference_not_implemented", status, 409);
    if (!name || !name[0] || strlen(name) > 128)
        return webd_client_control_write_error("invalid_argument",
            "name is required and must not exceed 128 bytes",
            "name", "client_control_rule_crud", "invalid_name", status, 422);
    if (note && strlen(note) > 1024)
        return webd_client_control_write_error("invalid_argument",
            "note must not exceed 1024 bytes",
            "note", "client_control_rule_crud", "note_too_long", status, 422);
    if (!webd_control_time_valid(start_time) || !webd_control_time_valid(end_time))
        return webd_client_control_write_error("invalid_argument",
            "start_time and end_time must use HH:MM",
            !webd_control_time_valid(start_time) ? "start_time" : "end_time",
            "client_control_schedule", "invalid_time", status, 422);
    if (!webd_control_limit_value(body, "up_limit", up_unit, up_limit_out))
        return webd_client_control_write_error("invalid_argument",
            "up_limit or up_unit is invalid or overflows runtime kbps",
            "up_limit", "client_control_rate_limit", "invalid_rate_limit", status, 422);
    if (!webd_control_limit_value(body, "down_limit", down_unit, down_limit_out))
        return webd_client_control_write_error("invalid_argument",
            "down_limit or down_unit is invalid or overflows runtime kbps",
            "down_limit", "client_control_rate_limit", "invalid_rate_limit", status, 422);
    return NULL;
}

static void webd_control_rule_add_runtime_contract(struct json_object *rule)
{
    const char *control_type;
    const char *line;
    const char *protocol;
    int is_ip_rate;
    int line_selected;
    int protocol_selected;
    int protocol_supported;

    if (!rule)
        return;
    control_type = app_nc_json_str(rule, "control_type", "");
    line = app_nc_json_str(rule, "line", "");
    protocol = app_nc_json_str(rule, "protocol", "任意");
    is_ip_rate = control_type && !strcmp(control_type, "IP限速");
    line_selected = webd_control_match_value_selected(line);
    protocol_selected = webd_control_match_value_selected(protocol);
    protocol_supported = is_ip_rate && webd_control_protocol_runtime_supported(protocol);

    webd_obj_add_str(rule, "runtime_match_scope",
                     is_ip_rate ? "client_mac_on_lan_bridge" : "persisted_only");
    webd_obj_add_str(rule, "runtime_match_precision",
                     is_ip_rate ? (line_selected ?
                         (protocol_supported ? "client_mac_and_l4_protocol_degraded_from_requested_line" :
                                             "client_mac_only_degraded_from_requested_line_or_protocol") :
                         (protocol_supported ? "client_mac_and_l4_protocol" : "client_mac_exact")) :
                         "unsupported_control_type");
    webd_obj_add_str(rule, "runtime_dataplane", is_ip_rate ? "tc_ifb_htb_u32" : "none");
    webd_obj_add_str(rule, "runtime_lan_bridge", "br-lan");
    webd_obj_add_str(rule, "runtime_effective_line", "all");
    webd_obj_add_str(rule, "runtime_effective_protocol", protocol_supported ? protocol : "any");
    json_object_object_add(rule, "line_persisted", json_object_new_boolean(line_selected));
    json_object_object_add(rule, "protocol_persisted", json_object_new_boolean(protocol_selected));
    json_object_object_add(rule, "line_runtime_supported", json_object_new_boolean(0));
    json_object_object_add(rule, "line_runtime_applied", json_object_new_boolean(0));
    webd_obj_add_str(rule, "line_runtime_reason", line_selected ?
        "line_filter_persisted_only_tc_runtime_not_implemented" :
        "line_filter_not_requested");
    json_object_object_add(rule, "protocol_runtime_supported", json_object_new_boolean(protocol_supported));
    json_object_object_add(rule, "protocol_runtime_applied",
                           json_object_new_boolean(protocol_supported && app_nc_json_bool(rule, "runtime_apply", 0)));
    webd_obj_add_str(rule, "protocol_runtime_reason", protocol_selected ?
        (protocol_supported ? "protocol_filter_applied_tc_u32_l4" :
                              "protocol_filter_value_unsupported_runtime_mac_only") :
        "protocol_filter_not_requested");
    json_object_object_add(rule, "client_mac_runtime_supported", json_object_new_boolean(is_ip_rate));
    json_object_object_add(rule, "client_mac_runtime_applied",
                           json_object_new_boolean(is_ip_rate && app_nc_json_bool(rule, "runtime_apply", 0)));
    if (line_selected || (protocol_selected && !protocol_supported))
        webd_obj_add_str(rule, "runtime_warning", line_selected ?
                         "line filter is saved but current dataplane enforces all WAN lines; protocol may be applied when supported" :
                         "protocol filter is saved but unsupported value falls back to client MAC only");
    {
        struct json_object *requested = json_object_new_object();
        struct json_object *effective = json_object_new_object();
        webd_obj_add_str(requested, "client", app_nc_json_str(rule, "mac", ""));
        webd_obj_add_str(requested, "line", line_selected ? line : "all");
        webd_obj_add_str(requested, "protocol", protocol_selected ? protocol : "any");
        webd_obj_add_str(effective, "client", app_nc_json_str(rule, "mac", ""));
        webd_obj_add_str(effective, "line", "all");
        webd_obj_add_str(effective, "protocol", protocol_supported ? protocol : "any");
        json_object_object_add(rule, "requested_scope", requested);
        json_object_object_add(rule, "effective_scope", effective);
        webd_obj_add_str(rule, "precision", app_nc_json_str(rule, "runtime_match_precision", "unknown"));
        json_object_object_add(rule, "runtime_applied",
                               json_object_new_boolean(app_nc_json_bool(rule, "runtime_apply", 0)));
        webd_obj_add_str(rule, "runtime_reason", app_nc_json_str(rule, "apply_reason", ""));
    }
}

static void webd_control_rule_add_aliases(struct json_object *rule)
{
    if (!rule)
        return;
    json_object_object_add(rule, "runtime_applied",
                           json_object_new_boolean(app_nc_json_bool(rule, "runtime_apply", 0)));
    webd_obj_add_str(rule, "type", app_nc_json_str(rule, "control_type", ""));
    webd_obj_add_str(rule, "remark", app_nc_json_str(rule, "note", ""));
    json_object_object_add(rule, "up_kbps", json_object_new_int(
        webd_control_limit_to_kbps(app_nc_json_int(rule, "up_limit", 0),
                                   app_nc_json_str(rule, "up_unit", "KB/s"))));
    json_object_object_add(rule, "down_kbps", json_object_new_int(
        webd_control_limit_to_kbps(app_nc_json_int(rule, "down_limit", 0),
                                   app_nc_json_str(rule, "down_unit", "KB/s"))));
    webd_control_rule_add_runtime_contract(rule);
}

/*
 * Single source of truth for the client-control write capabilities. Both the
 * per-client profile and the rule list report these, so they must be derived
 * once here instead of being restated at each call site.
 *
 * `control_rule_crud` and `client_control_rule_api` describe the CRUD surface,
 * which requires the persisted rule table to be reachable. The rate-limit
 * capability additionally depends on the tc/ifb dataplane the writer uses, and
 * fail-closed reflects that the write path rejects anything it cannot enforce
 * rather than persisting it silently.
 */
static int webd_client_control_store_ready(void)
{
    sqlite3_stmt *st;

    if (app_db_open_runtime() != 0)
        return 0;
    st = config_prepare("SELECT 1 FROM client_control_rules LIMIT 1");
    if (!st)
        return 0;
    sqlite3_finalize(st);
    return 1;
}

void webd_client_control_add_capabilities(struct json_object *cap)
{
    int store_ready;
    int rate_limit_ready;

    if (!cap)
        return;
    store_ready = webd_client_control_store_ready();
    /* The rate-limit writer programs tc on the LAN bridge; without that
     * dataplane the capability must not be advertised. */
    rate_limit_ready = store_ready && access("/sbin/tc", X_OK) == 0;

    json_object_object_add(cap, "control_rule_crud", json_object_new_boolean(store_ready));
    json_object_object_add(cap, "client_control_rule_api", json_object_new_boolean(store_ready));
    json_object_object_add(cap, "client_control_fail_closed", json_object_new_boolean(store_ready));
    json_object_object_add(cap, "client_control_rate_limit",
                           json_object_new_boolean(rate_limit_ready));
    /* `kick` only flushes conntrack. A wireless station keeps its association
     * and resumes immediately, so the client must be told that a real
     * disconnect is unavailable instead of inferring it from the per-action
     * `partially_applied` status. */
    json_object_object_add(cap, "client_deauth", json_object_new_boolean(0));
    webd_obj_add_str(cap, "client_deauth_reason",
                     "ieee80211_deauth_dispatch_not_implemented");
    if (!store_ready)
        webd_obj_add_str(cap, "client_control_unavailable_reason",
                         "client_control_rules_store_unavailable");
    else if (!rate_limit_ready)
        webd_obj_add_str(cap, "client_control_rate_limit_reason",
                         "tc_dataplane_binary_unavailable");
}

/*
 * Shared projection for client control rules. `mac` selects a single client's
 * rules; passing NULL returns every rule so the list endpoint and the
 * per-client profile cannot drift apart.
 */
struct json_object *webd_client_control_rules_load(const char *mac)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st;

    if (!arr)
        return NULL;
    if (app_db_open_runtime() != 0)
        return arr;
    st = mac && mac[0]
        ? config_prepare(
            "SELECT id,mac,name,enabled,control_type,schedule_mode,days_json,days_text,start_time,end_time,"
            "limit_mode,up_limit,up_unit,down_limit,down_unit,line,protocol,note,runtime_apply,apply_state,"
            "apply_reason,created_at,updated_at,last_runtime_enabled,last_runtime_apply_at,last_runtime_reason "
            "FROM client_control_rules WHERE mac=?1 ORDER BY updated_at DESC,id")
        : config_prepare(
            "SELECT id,mac,name,enabled,control_type,schedule_mode,days_json,days_text,start_time,end_time,"
            "limit_mode,up_limit,up_unit,down_limit,down_unit,line,protocol,note,runtime_apply,apply_state,"
            "apply_reason,created_at,updated_at,last_runtime_enabled,last_runtime_apply_at,last_runtime_reason "
            "FROM client_control_rules ORDER BY updated_at DESC,id");
    if (!st)
        return arr;
    if (mac && mac[0])
        sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *days_json = (const char *)sqlite3_column_text(st, 6);
        const char *days_text = (const char *)sqlite3_column_text(st, 7);
        struct json_object *rule = json_object_new_object();

        webd_obj_add_str(rule, "id", (const char *)sqlite3_column_text(st, 0));
        webd_obj_add_str(rule, "mac", (const char *)sqlite3_column_text(st, 1));
        webd_obj_add_str(rule, "name", (const char *)sqlite3_column_text(st, 2));
        json_object_object_add(rule, "enabled", json_object_new_boolean(sqlite3_column_int(st, 3)));
        webd_obj_add_str(rule, "control_type", (const char *)sqlite3_column_text(st, 4));
        webd_obj_add_str(rule, "schedule_mode", (const char *)sqlite3_column_text(st, 5));
        webd_obj_add_str(rule, "days", days_text);
        webd_obj_add_str(rule, "days_text", days_text);
        json_object_object_add(rule, "days_array", webd_control_days_array_from_json(days_json, days_text));
        webd_obj_add_str(rule, "start_time", (const char *)sqlite3_column_text(st, 8));
        webd_obj_add_str(rule, "end_time", (const char *)sqlite3_column_text(st, 9));
        webd_obj_add_str(rule, "limit_mode", (const char *)sqlite3_column_text(st, 10));
        json_object_object_add(rule, "up_limit", json_object_new_int(sqlite3_column_int(st, 11)));
        webd_obj_add_str(rule, "up_unit", (const char *)sqlite3_column_text(st, 12));
        json_object_object_add(rule, "down_limit", json_object_new_int(sqlite3_column_int(st, 13)));
        webd_obj_add_str(rule, "down_unit", (const char *)sqlite3_column_text(st, 14));
        webd_obj_add_str(rule, "line", (const char *)sqlite3_column_text(st, 15));
        webd_obj_add_str(rule, "protocol", (const char *)sqlite3_column_text(st, 16));
        webd_obj_add_str(rule, "note", (const char *)sqlite3_column_text(st, 17));
        json_object_object_add(rule, "runtime_apply", json_object_new_boolean(sqlite3_column_int(st, 18)));
        webd_obj_add_str(rule, "apply_state", (const char *)sqlite3_column_text(st, 19));
        webd_obj_add_str(rule, "apply_reason", (const char *)sqlite3_column_text(st, 20));
        json_object_object_add(rule, "created_at", json_object_new_int64(sqlite3_column_int64(st, 21)));
        json_object_object_add(rule, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 22)));
        json_object_object_add(rule, "last_runtime_enabled", json_object_new_int(sqlite3_column_int(st, 23)));
        json_object_object_add(rule, "last_runtime_apply_at", json_object_new_int64(sqlite3_column_int64(st, 24)));
        webd_obj_add_str(rule, "last_runtime_reason", (const char *)sqlite3_column_text(st, 25));
        webd_control_rule_add_aliases(rule);
        json_object_array_add(arr, rule);
    }
    sqlite3_finalize(st);
    return arr;
}

static int webd_client_control_schedule_tick_request(void)
{
    struct json_object *params = json_object_new_object();
    int ok;

    if (!params)
        return 0;
    json_object_object_add(params, "client_control_schedule", json_object_new_int(1));
    ok = app_ubus_call_ok("_maintenance_tick", params);
    json_object_put(params);
    return ok;
}

static int webd_client_control_rule_runtime_refresh(const char *id,
                                                    const char *mac,
                                                    int *runtime_apply,
                                                    char *apply_state,
                                                    size_t apply_state_len,
                                                    char *apply_reason,
                                                    size_t apply_reason_len,
                                                    int64_t *last_apply_at)
{
    sqlite3_stmt *st;
    int found = 0;

    if (!id || !id[0] || !mac || !mac[0])
        return 0;
    st = config_prepare(
        "SELECT runtime_apply,apply_state,apply_reason,last_runtime_apply_at "
        "FROM client_control_rules WHERE id=?1 AND mac=?2");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *v;
        found = 1;
        if (runtime_apply)
            *runtime_apply = sqlite3_column_int(st, 0);
        v = (const char *)sqlite3_column_text(st, 1);
        if (apply_state && apply_state_len)
            snprintf(apply_state, apply_state_len, "%s", v ? v : "");
        v = (const char *)sqlite3_column_text(st, 2);
        if (apply_reason && apply_reason_len)
            snprintf(apply_reason, apply_reason_len, "%s", v ? v : "");
        if (last_apply_at)
            *last_apply_at = sqlite3_column_int64(st, 3);
    }
    sqlite3_finalize(st);
    return found;
}

static int webd_client_control_rule_snapshot(const char *id, const char *mac)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (!id || !id[0] || !mac || !mac[0] || !g_config_db)
        return -1;
    if (sqlite3_exec(g_config_db,
        "DROP TABLE IF EXISTS temp.client_control_rule_rollback;"
        "CREATE TEMP TABLE client_control_rule_rollback AS "
        "SELECT * FROM main.client_control_rules WHERE 0;",
        NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    st = config_prepare(
        "INSERT INTO temp.client_control_rule_rollback "
        "SELECT * FROM main.client_control_rules WHERE id=?1 AND mac=?2");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, mac, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st) == SQLITE_DONE ? sqlite3_changes(g_config_db) : -1;
    sqlite3_finalize(st);
    return rc == 1 ? 0 : -1;
}

static int webd_client_control_rule_restore_snapshot(const char *id, const char *mac)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!id || !id[0] || !mac || !mac[0] || !g_config_db ||
        sqlite3_exec(g_config_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    st = config_prepare("DELETE FROM main.client_control_rules WHERE id=?1 AND mac=?2");
    if (!st)
        goto rollback;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        goto rollback;
    }
    sqlite3_finalize(st);
    st = config_prepare(
        "INSERT INTO main.client_control_rules "
        "SELECT * FROM temp.client_control_rule_rollback WHERE id=?1 AND mac=?2");
    if (!st)
        goto rollback;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        goto rollback;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_changes(g_config_db) != 1)
        goto rollback;
    if (sqlite3_exec(g_config_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        goto rollback_after_commit;
    st = config_prepare(
        "SELECT COUNT(*) FROM main.client_control_rules WHERE id=?1 AND mac=?2");
    if (!st)
        goto out;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) == 1)
        rc = 0;
    sqlite3_finalize(st);
    st = NULL;
    goto out;

rollback:
    if (st)
        sqlite3_finalize(st);
    sqlite3_exec(g_config_db, "ROLLBACK", NULL, NULL, NULL);
    goto out;
rollback_after_commit:
    sqlite3_exec(g_config_db, "ROLLBACK", NULL, NULL, NULL);
out:
    sqlite3_exec(g_config_db, "DROP TABLE IF EXISTS temp.client_control_rule_rollback",
                 NULL, NULL, NULL);
    return rc;
}

static void webd_client_control_rule_drop_snapshot(void)
{
    if (g_config_db)
        sqlite3_exec(g_config_db, "DROP TABLE IF EXISTS temp.client_control_rule_rollback",
                     NULL, NULL, NULL);
}

static int webd_client_control_rule_compensating_delete(const char *id, const char *mac)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!id || !id[0] || !mac || !mac[0] || !g_config_db ||
        sqlite3_exec(g_config_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    st = config_prepare(
        "DELETE FROM main.client_control_rules WHERE id=?1 AND mac=?2");
    if (!st)
        goto rollback;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_config_db) != 1) {
        sqlite3_finalize(st);
        st = NULL;
        goto rollback;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_exec(g_config_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        goto rollback_after_commit;
    st = config_prepare(
        "SELECT COUNT(*) FROM main.client_control_rules WHERE id=?1 AND mac=?2");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) == 0)
        rc = 0;
    sqlite3_finalize(st);
    return rc;

rollback:
    if (st)
        sqlite3_finalize(st);
    sqlite3_exec(g_config_db, "ROLLBACK", NULL, NULL, NULL);
    return -1;
rollback_after_commit:
    sqlite3_exec(g_config_db, "ROLLBACK", NULL, NULL, NULL);
    return -1;
}

static int webd_client_control_runtime_restore_from_db(const char *id, const char *mac)
{
    struct json_object *params = NULL;
    sqlite3_stmt *st = NULL;
    char state[64] = "";
    char reason[160] = "";
    int runtime_apply = 0;
    int64_t last_apply_at = 0;
    int pending = -1;

    if (!id || !id[0] || !mac || !mac[0] || !g_config_db)
        return -1;
    params = json_object_new_object();
    if (!params)
        return -1;
    json_object_object_add(params, "mac", json_object_new_string(mac));
    if (!app_ubus_call_ok("client_rate_limit_delete", params)) {
        json_object_put(params);
        return -1;
    }
    json_object_put(params);
    if (sqlite3_exec(g_config_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    st = config_prepare(
        "UPDATE main.client_control_rules SET runtime_apply=0,apply_state='queued',"
        "apply_reason='rollback_runtime_reconcile',last_runtime_enabled=-1,"
        "last_runtime_apply_at=0,last_runtime_reason='rollback_runtime_reconcile' "
        "WHERE mac=?1");
    if (!st)
        goto rollback;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        st = NULL;
        goto rollback;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_exec(g_config_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    if (!webd_client_control_schedule_tick_request())
        return -1;
    if (!webd_client_control_rule_runtime_refresh(id, mac, &runtime_apply,
                                                   state, sizeof(state),
                                                   reason, sizeof(reason),
                                                   &last_apply_at))
        return -1;
    if (!runtime_apply &&
        (!strcmp(state, "failed") || !strcmp(state, "pending") ||
         !strcmp(state, "queued")))
        return -1;
    st = config_prepare(
        "SELECT COUNT(*) FROM main.client_control_rules WHERE mac=?1 "
        "AND apply_state IN ('failed','pending','queued')");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        pending = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    if (pending != 0)
        return -1;
    return 0;

rollback:
    if (st)
        sqlite3_finalize(st);
    sqlite3_exec(g_config_db, "ROLLBACK", NULL, NULL, NULL);
    return -1;
}

static int webd_client_control_runtime_reconcile_after_create_rollback(const char *id,
                                                                        const char *mac)
{
    struct json_object *params = NULL;
    sqlite3_stmt *st = NULL;
    int absent = 0;
    int pending = -1;

    if (!id || !id[0] || !mac || !mac[0] || !g_config_db)
        return -1;
    st = config_prepare(
        "SELECT COUNT(*) FROM main.client_control_rules WHERE id=?1 AND mac=?2");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) == 0)
        absent = 1;
    sqlite3_finalize(st);
    if (!absent)
        return -1;
    params = json_object_new_object();
    if (!params)
        return -1;
    json_object_object_add(params, "mac", json_object_new_string(mac));
    if (!app_ubus_call_ok("client_rate_limit_delete", params)) {
        json_object_put(params);
        return -1;
    }
    json_object_put(params);
    if (sqlite3_exec(g_config_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    st = config_prepare(
        "UPDATE main.client_control_rules SET runtime_apply=0,apply_state='queued',"
        "apply_reason='rollback_runtime_reconcile',last_runtime_enabled=-1,"
        "last_runtime_apply_at=0,last_runtime_reason='rollback_runtime_reconcile' "
        "WHERE mac=?1");
    if (!st)
        goto create_rollback;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        st = NULL;
        goto create_rollback;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_exec(g_config_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    if (!webd_client_control_schedule_tick_request())
        return -1;
    st = config_prepare(
        "SELECT COUNT(*) FROM main.client_control_rules WHERE mac=?1 "
        "AND apply_state IN ('failed','pending','queued')");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        pending = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    if (pending != 0)
        return -1;
    return 0;

create_rollback:
    if (st)
        sqlite3_finalize(st);
    sqlite3_exec(g_config_db, "ROLLBACK", NULL, NULL, NULL);
    return -1;
}

static struct json_object *webd_client_control_rule_upsert_response(struct json_object *body,
                                                                    int is_update,
                                                                    int *status)
{
    char norm_mac[32] = {0};
    char id[96] = {0};
    char days_text[256] = {0};
    char days_json[512] = {0};
    char apply_state[64] = "draft";
    char apply_reason[160] = "";
    struct json_object *days_array = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *data = json_object_new_object();
    const char *mac_in = app_nc_json_str(body, "mac",
        app_nc_json_str(body, "client_mac", app_nc_json_str(body, "device_mac", "")));
    const char *id_in = app_nc_json_str(body, "id", "");
    const char *control_type = app_nc_json_str(body, "control_type",
        app_nc_json_str(body, "type", "IP限速"));
    const char *name = app_nc_json_str(body, "name", "");
    const char *schedule_mode = app_nc_json_str(body, "schedule_mode", "week");
    const char *start_time = app_nc_json_str(body, "start_time", "00:00");
    const char *end_time = app_nc_json_str(body, "end_time", "23:59");
    const char *limit_mode = app_nc_json_str(body, "limit_mode", "独立限速");
    const char *up_unit = app_nc_json_str(body, "up_unit", "KB/s");
    const char *down_unit = app_nc_json_str(body, "down_unit", "KB/s");
    const char *line = app_nc_json_str(body, "line", "");
    const char *protocol = app_nc_json_str(body, "protocol", "任意");
    const char *note = app_nc_json_str(body, "note", app_nc_json_str(body, "remark", ""));
    int enabled = app_nc_json_bool(body, "enabled", 1);
    int up_limit = app_nc_json_int(body, "up_limit", app_nc_json_int(body, "upload_limit", 0));
    int down_limit = app_nc_json_int(body, "down_limit", app_nc_json_int(body, "download_limit", 0));
    int runtime_apply = 0;
    int schedule_tick_ok = 0;
    int compensation_ok = 1;
    int had_existing = 0;
    int64_t last_apply_at = 0;
    int64_t ts = now_s();
    sqlite3_stmt *st;
    int rc;

    if (status)
        *status = 200;
    if (!body || !json_object_is_type(body, json_type_object)) {
        struct json_object *error = webd_client_control_write_error(
            "invalid_argument", "request body must be a JSON object",
            "body", "client_control_rule_crud", "empty_body", status, 422);
        json_object_put(resp);
        json_object_put(data);
        return error;
    }
    if (webd_normalize_mac_text(mac_in, norm_mac, sizeof(norm_mac)) != 0 ||
        !webd_client_control_mac_valid(norm_mac)) {
        struct json_object *error = webd_client_control_write_error(
            "invalid_argument", "mac must be a valid unicast client address",
            "mac", "client_control_rule_crud", "invalid_client_mac", status, 422);
        json_object_put(resp);
        json_object_put(data);
        return error;
    }
    if (is_update && (!id_in || !id_in[0])) {
        struct json_object *error = webd_client_control_write_error(
            "invalid_argument", "id is required for rule update",
            "id", "client_control_rule_crud", "missing_rule_id", status, 422);
        json_object_put(resp);
        json_object_put(data);
        return error;
    }
    if (is_update && strlen(id_in) >= sizeof(id)) {
        struct json_object *error = webd_client_control_write_error(
            "invalid_argument", "id is too long",
            "id", "client_control_rule_crud", "invalid_rule_id", status, 422);
        json_object_put(resp);
        json_object_put(data);
        return error;
    }
    {
        struct json_object *validation_error =
            webd_client_control_validate_write(body, &up_limit, &down_limit, status);
        if (validation_error) {
            json_object_put(resp);
            json_object_put(data);
            return validation_error;
        }
    }
    if (is_update)
        snprintf(id, sizeof(id), "%s", id_in);
    else {
        char rnd[17];

        /* Not a credential, but an empty suffix would collide across records. */
        if (gen_random_hex_checked(rnd, 16) != 0) {
            if (status) *status = 500;
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            webd_obj_add_str(resp, "error", "id_entropy_unavailable");
            json_object_put(data);
            return resp;
        }
        snprintf(id, sizeof(id), "ccr_%s", rnd);
    }
    if (webd_control_days_from_body(body, days_text, sizeof(days_text),
                                    days_json, sizeof(days_json), &days_array) != 0) {
        struct json_object *error = webd_client_control_write_error(
            "invalid_argument", "days must be valid UTF-8 weekday text",
            "days", "client_control_rule_crud", "invalid_days_encoding", status, 422);
        json_object_put(resp);
        json_object_put(data);
        return error;
    }
    snprintf(apply_state, sizeof(apply_state), "%s", "queued");
    snprintf(apply_reason, sizeof(apply_reason), "%s", "queued_for_client_control_schedule");
    if (app_db_open_runtime() != 0) {
        if (status) *status = 503;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "db_unavailable");
        if (days_array) json_object_put(days_array);
        json_object_put(data);
        return resp;
    }
    if (is_update) {
        int owned = 0;
        st = config_prepare("SELECT enabled FROM client_control_rules WHERE id=?1 AND mac=?2");
        if (st) {
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, norm_mac, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW) {
                owned = 1;
                had_existing = 1;
            }
            sqlite3_finalize(st);
        }
        if (!owned) {
            struct json_object *error = webd_client_control_write_error(
                "rule_not_found", "rule does not belong to this client",
                "id", "client_control_rule_ownership", "rule_not_owned_by_client",
                status, 404);
            json_object_put(resp);
            if (days_array) json_object_put(days_array);
            json_object_put(data);
            return error;
        }
        if (webd_client_control_rule_snapshot(id, norm_mac) != 0) {
            if (status) *status = 500;
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            webd_obj_add_str(resp, "error", "rollback_snapshot_failed");
            json_object_object_add(resp, "persisted", json_object_new_boolean(0));
            json_object_object_add(resp, "applied", json_object_new_boolean(0));
            if (days_array) json_object_put(days_array);
            json_object_put(data);
            return resp;
        }
    }
    st = config_prepare(
        "INSERT INTO client_control_rules"
        "(id,mac,name,enabled,control_type,schedule_mode,days_json,days_text,start_time,end_time,"
        "limit_mode,up_limit,up_unit,down_limit,down_unit,line,protocol,note,runtime_apply,apply_state,"
        "apply_reason,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23) "
        "ON CONFLICT(id) DO UPDATE SET mac=excluded.mac,name=excluded.name,enabled=excluded.enabled,"
        "control_type=excluded.control_type,schedule_mode=excluded.schedule_mode,days_json=excluded.days_json,"
        "days_text=excluded.days_text,start_time=excluded.start_time,end_time=excluded.end_time,"
        "limit_mode=excluded.limit_mode,up_limit=excluded.up_limit,up_unit=excluded.up_unit,"
        "down_limit=excluded.down_limit,down_unit=excluded.down_unit,line=excluded.line,protocol=excluded.protocol,"
        "note=excluded.note,runtime_apply=excluded.runtime_apply,apply_state=excluded.apply_state,"
        "apply_reason=excluded.apply_reason,updated_at=excluded.updated_at");
    if (!st) {
        if (status) *status = 500;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "db_prepare_failed");
        if (had_existing)
            webd_client_control_rule_restore_snapshot(id, norm_mac);
        if (days_array) json_object_put(days_array);
        json_object_put(data);
        return resp;
    }
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, norm_mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, name && name[0] ? name : id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, enabled ? 1 : 0);
    sqlite3_bind_text(st, 5, control_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, schedule_mode, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, days_json, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, days_text, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, start_time, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, end_time, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, limit_mode, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 12, up_limit);
    sqlite3_bind_text(st, 13, up_unit, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 14, down_limit);
    sqlite3_bind_text(st, 15, down_unit, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 16, line, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 17, protocol, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 18, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 19, runtime_apply);
    sqlite3_bind_text(st, 20, apply_state, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 21, apply_reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 22, ts);
    sqlite3_bind_int64(st, 23, ts);
    rc = sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(st);
    if (rc != 0) {
        if (status) *status = 500;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "db_write_failed");
        if (had_existing)
            webd_client_control_rule_restore_snapshot(id, norm_mac);
        if (days_array) json_object_put(days_array);
        json_object_put(data);
        return resp;
    }
    schedule_tick_ok = webd_client_control_schedule_tick_request();
    if (schedule_tick_ok)
        webd_client_control_rule_runtime_refresh(id, norm_mac, &runtime_apply,
                                                 apply_state, sizeof(apply_state),
                                                 apply_reason, sizeof(apply_reason),
                                                 &last_apply_at);
    if ((!schedule_tick_ok || (enabled && !runtime_apply)) && g_config_db) {
        if (had_existing) {
            compensation_ok =
                webd_client_control_rule_restore_snapshot(id, norm_mac) == 0 &&
                webd_client_control_runtime_restore_from_db(id, norm_mac) == 0;
        } else {
            compensation_ok =
                webd_client_control_rule_compensating_delete(id, norm_mac) == 0 &&
                webd_client_control_runtime_reconcile_after_create_rollback(
                    id, norm_mac) == 0;
        }
    } else if (had_existing)
        webd_client_control_rule_drop_snapshot();
    if (!compensation_ok) {
        if (status) *status = 500;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "rollback_failed_runtime_state_unknown");
        webd_obj_add_str(resp, "consistency", "unknown_manual_reconciliation_required");
    } else if (!schedule_tick_ok) {
        if (status) *status = 503;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "schedule_worker_unavailable");
    } else if (enabled && !runtime_apply) {
        if (status) *status = 503;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "runtime_apply_failed");
    } else {
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
    }
    json_object_object_add(resp, "changed", json_object_new_boolean(compensation_ok && schedule_tick_ok && (!enabled || runtime_apply)));
    json_object_object_add(resp, "persisted", json_object_new_boolean(compensation_ok && schedule_tick_ok && (!enabled || runtime_apply)));
    json_object_object_add(resp, "applied", json_object_new_boolean(runtime_apply));
    json_object_object_add(resp, "rollback_verified", json_object_new_boolean(compensation_ok));
    webd_obj_add_str(resp, "apply_state", apply_state);
    webd_obj_add_str(resp, "runtime_reason", apply_reason);
    webd_obj_add_str(data, "id", id);
    webd_obj_add_str(data, "mac", norm_mac);
    webd_obj_add_str(data, "apply_state", apply_state);
    webd_obj_add_str(data, "apply_reason", apply_reason);
    json_object_object_add(data, "runtime_apply", json_object_new_boolean(runtime_apply));
    json_object_object_add(data, "runtime_applied", json_object_new_boolean(runtime_apply));
    json_object_object_add(data, "schedule_tick_requested", json_object_new_boolean(schedule_tick_ok));
    json_object_object_add(data, "last_runtime_apply_at", json_object_new_int64(last_apply_at));
    webd_obj_add_str(data, "runtime_scope", "client_mac_on_lan_bridge");
    webd_obj_add_str(data, "runtime_precision",
                     webd_control_match_value_selected(protocol) ? "client_mac_and_l4_protocol" : "client_mac_exact");
    json_object_object_add(data, "up_kbps", json_object_new_int(webd_control_limit_to_kbps(up_limit, up_unit)));
    json_object_object_add(data, "down_kbps", json_object_new_int(webd_control_limit_to_kbps(down_limit, down_unit)));
    if (days_array)
        json_object_object_add(data, "days_array", days_array);
    json_object_object_add(resp, "data", data);
    jmx_app_audit_log("web", "", is_update ? "client_control_rule.update" : "client_control_rule.create",
                      "medium", norm_mac, "", "");
    return resp;
}

static struct json_object *webd_client_control_rule_toggle_response(struct json_object *body,
                                                                    int *status)
{
    char norm_mac[32] = {0};
    char apply_state[64] = "draft";
    char apply_reason[160] = "";
    struct json_object *resp = json_object_new_object();
    struct json_object *data = json_object_new_object();
    const char *mac_in = app_nc_json_str(body, "mac",
        app_nc_json_str(body, "client_mac", app_nc_json_str(body, "device_mac", "")));
    const char *id = app_nc_json_str(body, "id", "");
    int enabled = app_nc_json_bool(body, "enabled", 1);
    sqlite3_stmt *st;
    int up_limit = 0, down_limit = 0;
    int runtime_apply = 0;
    int schedule_tick_ok = 0;
    int compensation_ok = 1;
    int64_t last_apply_at = 0;
    char control_type[64] = "";
    char name[160] = "";
    char schedule_mode[48] = "";
    char start_time[24] = "";
    char end_time[24] = "";
    char limit_mode[64] = "";
    char line[96] = "";
    char protocol[64] = "";
    char up_unit[32] = "KB/s";
    char down_unit[32] = "KB/s";
    char note[256] = "";
    int found = 0;

    if (status) *status = 200;
    if (webd_normalize_mac_text(mac_in, norm_mac, sizeof(norm_mac)) != 0 ||
        !webd_client_control_mac_valid(norm_mac) || !id[0]) {
        const char *field = !id[0] ? "id" : "mac";
        struct json_object *error = webd_client_control_write_error(
            "invalid_argument", !id[0] ? "id is required" :
            "mac must be a valid unicast client address",
            field, "client_control_rule_crud",
            !id[0] ? "missing_rule_id" : "invalid_client_mac", status, 422);
        json_object_put(resp);
        json_object_put(data);
        return error;
    }
    if (app_db_open_runtime() != 0) {
        if (status) *status = 503;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "db_unavailable");
        json_object_put(data);
        return resp;
    }
    st = config_prepare(
        "SELECT enabled,control_type,name,schedule_mode,start_time,end_time,limit_mode,"
        "up_limit,up_unit,down_limit,down_unit,line,protocol,note "
        "FROM client_control_rules WHERE id=?1 AND mac=?2");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, norm_mac, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *v;
            found = 1;
            v = (const char *)sqlite3_column_text(st, 1); snprintf(control_type, sizeof(control_type), "%s", v ? v : "IP限速");
            v = (const char *)sqlite3_column_text(st, 2); snprintf(name, sizeof(name), "%s", v ? v : "");
            v = (const char *)sqlite3_column_text(st, 3); snprintf(schedule_mode, sizeof(schedule_mode), "%s", v ? v : "week");
            v = (const char *)sqlite3_column_text(st, 4); snprintf(start_time, sizeof(start_time), "%s", v ? v : "00:00");
            v = (const char *)sqlite3_column_text(st, 5); snprintf(end_time, sizeof(end_time), "%s", v ? v : "23:59");
            v = (const char *)sqlite3_column_text(st, 6); snprintf(limit_mode, sizeof(limit_mode), "%s", v ? v : "独立限速");
            up_limit = sqlite3_column_int(st, 7);
            v = (const char *)sqlite3_column_text(st, 8); snprintf(up_unit, sizeof(up_unit), "%s", v ? v : "KB/s");
            down_limit = sqlite3_column_int(st, 9);
            v = (const char *)sqlite3_column_text(st, 10); snprintf(down_unit, sizeof(down_unit), "%s", v ? v : "KB/s");
            v = (const char *)sqlite3_column_text(st, 11); snprintf(line, sizeof(line), "%s", v ? v : "");
            v = (const char *)sqlite3_column_text(st, 12); snprintf(protocol, sizeof(protocol), "%s", v ? v : "任意");
            v = (const char *)sqlite3_column_text(st, 13); snprintf(note, sizeof(note), "%s", v ? v : "");
        }
        sqlite3_finalize(st);
    }
    if (!found) {
        struct json_object *error = webd_client_control_write_error(
            "rule_not_found", "rule does not belong to this client",
            "id", "client_control_rule_ownership", "rule_not_owned_by_client",
            status, 404);
        json_object_put(resp);
        json_object_put(data);
        return error;
    }
    if (enabled) {
        struct json_object *stored = json_object_new_object();
        struct json_object *validation_error;
        json_object_object_add(stored, "control_type", json_object_new_string(control_type));
        json_object_object_add(stored, "name", json_object_new_string(name));
        json_object_object_add(stored, "schedule_mode", json_object_new_string(schedule_mode));
        json_object_object_add(stored, "start_time", json_object_new_string(start_time));
        json_object_object_add(stored, "end_time", json_object_new_string(end_time));
        json_object_object_add(stored, "limit_mode", json_object_new_string(limit_mode));
        json_object_object_add(stored, "up_limit", json_object_new_int(up_limit));
        json_object_object_add(stored, "up_unit", json_object_new_string(up_unit));
        json_object_object_add(stored, "down_limit", json_object_new_int(down_limit));
        json_object_object_add(stored, "down_unit", json_object_new_string(down_unit));
        json_object_object_add(stored, "line", json_object_new_string(line));
        json_object_object_add(stored, "protocol", json_object_new_string(protocol));
        json_object_object_add(stored, "note", json_object_new_string(note));
        validation_error = webd_client_control_validate_write(stored, &up_limit, &down_limit, status);
        json_object_put(stored);
        if (validation_error) {
            webd_client_control_rule_drop_snapshot();
            json_object_put(resp);
            json_object_put(data);
            return validation_error;
        }
    }
    if (webd_client_control_rule_snapshot(id, norm_mac) != 0) {
        if (status) *status = 500;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "rollback_snapshot_failed");
        json_object_object_add(resp, "persisted", json_object_new_boolean(0));
        json_object_object_add(resp, "applied", json_object_new_boolean(0));
        json_object_put(data);
        return resp;
    }
    snprintf(apply_state, sizeof(apply_state), "%s", "queued");
    snprintf(apply_reason, sizeof(apply_reason), "%s", "queued_for_client_control_schedule");
    st = config_prepare("UPDATE client_control_rules SET enabled=?1,runtime_apply=?2,apply_state=?3,apply_reason=?4,updated_at=?5 WHERE id=?6 AND mac=?7");
    if (!st) {
        if (status) *status = 500;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "db_prepare_failed");
        webd_client_control_rule_drop_snapshot();
        json_object_put(data);
        return resp;
    }
    sqlite3_bind_int(st, 1, enabled ? 1 : 0);
    sqlite3_bind_int(st, 2, runtime_apply);
    sqlite3_bind_text(st, 3, apply_state, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, apply_reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, now_s());
    sqlite3_bind_text(st, 6, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, norm_mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        webd_client_control_rule_drop_snapshot();
        if (status) *status = 500;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "db_write_failed");
        json_object_object_add(resp, "persisted", json_object_new_boolean(0));
        json_object_object_add(resp, "applied", json_object_new_boolean(0));
        json_object_put(data);
        return resp;
    }
    sqlite3_finalize(st);
    schedule_tick_ok = webd_client_control_schedule_tick_request();
    if (schedule_tick_ok)
        webd_client_control_rule_runtime_refresh(id, norm_mac, &runtime_apply,
                                                 apply_state, sizeof(apply_state),
                                                 apply_reason, sizeof(apply_reason),
                                                 &last_apply_at);
    if (!schedule_tick_ok || (enabled && !runtime_apply)) {
        compensation_ok =
            webd_client_control_rule_restore_snapshot(id, norm_mac) == 0 &&
            webd_client_control_runtime_restore_from_db(id, norm_mac) == 0;
    } else
        webd_client_control_rule_drop_snapshot();
    if (!compensation_ok) {
        if (status) *status = 500;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "rollback_failed_runtime_state_unknown");
        webd_obj_add_str(resp, "consistency", "unknown_manual_reconciliation_required");
    } else if (!schedule_tick_ok || !runtime_apply) {
        if (status) *status = 503;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", schedule_tick_ok ?
                         "runtime_apply_failed" : "schedule_worker_unavailable");
    } else {
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
    }
    json_object_object_add(resp, "changed", json_object_new_boolean(compensation_ok && schedule_tick_ok && (!enabled || runtime_apply)));
    json_object_object_add(resp, "persisted", json_object_new_boolean(compensation_ok && schedule_tick_ok && (!enabled || runtime_apply)));
    json_object_object_add(resp, "applied", json_object_new_boolean(runtime_apply));
    json_object_object_add(resp, "rollback_verified", json_object_new_boolean(compensation_ok));
    webd_obj_add_str(resp, "apply_state", apply_state);
    webd_obj_add_str(resp, "runtime_reason", apply_reason);
    webd_obj_add_str(data, "id", id);
    webd_obj_add_str(data, "mac", norm_mac);
    json_object_object_add(data, "enabled", json_object_new_boolean(enabled));
    json_object_object_add(data, "runtime_apply", json_object_new_boolean(runtime_apply));
    webd_obj_add_str(data, "apply_state", apply_state);
    webd_obj_add_str(data, "apply_reason", apply_reason);
    json_object_object_add(data, "schedule_tick_requested", json_object_new_boolean(schedule_tick_ok));
    json_object_object_add(data, "last_runtime_apply_at", json_object_new_int64(last_apply_at));
    json_object_object_add(data, "runtime_enabled", json_object_new_boolean(
        enabled && !strcmp(apply_state, "applied")));
    json_object_object_add(resp, "data", data);
    jmx_app_audit_log("web", "", "client_control_rule.toggle", "medium", norm_mac, "", "");
    return resp;
}

static struct json_object *webd_client_control_rule_delete_response(struct json_object *body,
                                                                    int *status)
{
    char norm_mac[32] = {0};
    struct json_object *resp = json_object_new_object();
    struct json_object *data = json_object_new_object();
    const char *mac_in = app_nc_json_str(body, "mac",
        app_nc_json_str(body, "client_mac", app_nc_json_str(body, "device_mac", "")));
    const char *id = app_nc_json_str(body, "id", "");
    sqlite3_stmt *st;
    int changes;
    int schedule_tick_ok = 0;
    int runtime_delete_ok = 0;

    if (status) *status = 200;
    if (webd_normalize_mac_text(mac_in, norm_mac, sizeof(norm_mac)) != 0 ||
        !webd_client_control_mac_valid(norm_mac) || !id[0]) {
        const char *field = !id[0] ? "id" : "mac";
        struct json_object *error = webd_client_control_write_error(
            "invalid_argument", !id[0] ? "id is required" :
            "mac must be a valid unicast client address",
            field, "client_control_rule_crud",
            !id[0] ? "missing_rule_id" : "invalid_client_mac", status, 422);
        json_object_put(resp);
        json_object_put(data);
        return error;
    }
    if (app_db_open_runtime() != 0) {
        if (status) *status = 503;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "db_unavailable");
        json_object_put(data);
        return resp;
    }
    st = config_prepare("SELECT 1 FROM client_control_rules WHERE id=?1 AND mac=?2");
    if (!st) {
        if (status) *status = 500;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "db_prepare_failed");
        json_object_put(data);
        return resp;
    }
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, norm_mac, -1, SQLITE_TRANSIENT);
    changes = sqlite3_step(st) == SQLITE_ROW ? 1 : 0;
    sqlite3_finalize(st);
    if (changes <= 0) {
        struct json_object *error = webd_client_control_write_error(
            "rule_not_found", "rule does not belong to this client",
            "id", "client_control_rule_ownership", "rule_not_owned_by_client",
            status, 404);
        json_object_put(resp);
        json_object_put(data);
        return error;
    }
    if (webd_client_control_rule_snapshot(id, norm_mac) != 0) {
        if (status) *status = 500;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "rollback_snapshot_failed");
        json_object_object_add(resp, "persisted", json_object_new_boolean(0));
        json_object_object_add(resp, "applied", json_object_new_boolean(0));
        json_object_put(data);
        return resp;
    }
    {
        struct json_object *params = json_object_new_object();
        json_object_object_add(params, "mac", json_object_new_string(norm_mac));
        runtime_delete_ok = app_ubus_call_ok("client_rate_limit_delete", params);
        json_object_put(params);
    }
    if (!runtime_delete_ok) {
        if (status) *status = 503;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "runtime_remove_failed");
        json_object_object_add(resp, "changed", json_object_new_boolean(0));
        json_object_object_add(resp, "persisted", json_object_new_boolean(0));
        json_object_object_add(resp, "applied", json_object_new_boolean(0));
        webd_client_control_rule_drop_snapshot();
        json_object_put(data);
        return resp;
    }
    st = config_prepare("DELETE FROM client_control_rules WHERE id=?1 AND mac=?2");
    if (!st) {
        if (status) *status = 500;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "db_prepare_failed");
        json_object_object_add(resp, "persisted", json_object_new_boolean(0));
        json_object_object_add(resp, "applied", json_object_new_boolean(1));
        webd_client_control_schedule_tick_request();
        webd_client_control_rule_drop_snapshot();
        json_object_put(data);
        return resp;
    }
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, norm_mac, -1, SQLITE_TRANSIENT);
    changes = sqlite3_step(st) == SQLITE_DONE ? 1 : 0;
    sqlite3_finalize(st);
    if (!changes) {
        if (status) *status = 500;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "db_write_failed");
        json_object_object_add(resp, "persisted", json_object_new_boolean(0));
        json_object_object_add(resp, "applied", json_object_new_boolean(1));
        webd_client_control_schedule_tick_request();
        webd_client_control_rule_drop_snapshot();
        json_object_put(data);
        return resp;
    }
    schedule_tick_ok = webd_client_control_schedule_tick_request();
    if (!schedule_tick_ok) {
        webd_client_control_rule_restore_snapshot(id, norm_mac);
        webd_client_control_schedule_tick_request();
        if (status) *status = 503;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "schedule_worker_unavailable");
        json_object_object_add(resp, "changed", json_object_new_boolean(0));
        json_object_object_add(resp, "persisted", json_object_new_boolean(0));
        json_object_object_add(resp, "applied", json_object_new_boolean(0));
        json_object_put(data);
        return resp;
    }
    webd_client_control_rule_drop_snapshot();
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "changed", json_object_new_boolean(1));
    json_object_object_add(resp, "persisted", json_object_new_boolean(1));
    json_object_object_add(resp, "applied", json_object_new_boolean(1));
    webd_obj_add_str(data, "id", id);
    webd_obj_add_str(data, "mac", norm_mac);
    json_object_object_add(data, "deleted", json_object_new_boolean(1));
    json_object_object_add(data, "runtime_removed", json_object_new_boolean(1));
    json_object_object_add(data, "schedule_tick_requested", json_object_new_boolean(schedule_tick_ok));
    json_object_object_add(resp, "data", data);
    jmx_app_audit_log("web", "", "client_control_rule.delete", "medium", norm_mac, "", "");
    return resp;
}

/*
 * Aggregated read for the client rate-limit page. The write routes are per
 * rule, but the page needs every rule plus the write capabilities in one
 * response; it deliberately does not walk client_profile per device.
 */
static struct json_object *webd_client_control_rules_response(int *status)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *cap = json_object_new_object();
    struct json_object *rules;

    if (status) *status = 200;
    if (!resp || !cap) {
        json_object_put(resp);
        json_object_put(cap);
        if (status) *status = 500;
        return NULL;
    }
    webd_client_control_add_capabilities(cap);
    if (app_db_open_runtime() != 0) {
        /* Fail closed: report the outage instead of an empty rule set that
         * would look like "no rules configured". */
        if (status) *status = 503;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        webd_obj_add_str(resp, "error", "db_unavailable");
        json_object_object_add(resp, "items", json_object_new_array());
        json_object_object_add(resp, "capabilities", cap);
        return resp;
    }
    rules = webd_client_control_rules_load(NULL);
    if (!rules)
        rules = json_object_new_array();
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "count",
                           json_object_new_int((int)json_object_array_length(rules)));
    json_object_object_add(resp, "capabilities", cap);
    json_object_object_add(resp, "items", rules);
    return resp;
}


static struct json_object *client_control_rules_get(struct jmx_api_ctx *ctx)
{
    return webd_client_control_rules_response(&ctx->status);
}

static struct json_object *client_control_rule_create(struct jmx_api_ctx *ctx)
{
    return webd_client_control_rule_upsert_response(ctx->body, 0, &ctx->status);
}

static struct json_object *client_control_rule_update(struct jmx_api_ctx *ctx)
{
    return webd_client_control_rule_upsert_response(ctx->body, 1, &ctx->status);
}

static struct json_object *client_control_rule_toggle(struct jmx_api_ctx *ctx)
{
    return webd_client_control_rule_toggle_response(ctx->body, &ctx->status);
}

static struct json_object *client_control_rule_delete(struct jmx_api_ctx *ctx)
{
    return webd_client_control_rule_delete_response(ctx->body, &ctx->status);
}

const struct jmx_api_route client_control_api_routes[] = {
    JMX_API_ROUTE(588, "/api/v1/client_control_rules", "GET", JMX_API_EXACT, client_control_rules_get),
    JMX_API_ROUTE(589, "/api/v1/client_control_rule", "POST", JMX_API_EXACT, client_control_rule_create),
    JMX_API_ROUTE(590, "/api/v1/client_control_rule/update", "POST", JMX_API_EXACT, client_control_rule_update),
    JMX_API_ROUTE(591, "/api/v1/client_control_rule/toggle", "POST", JMX_API_EXACT, client_control_rule_toggle),
    JMX_API_ROUTE(592, "/api/v1/client_control_rule/delete", "POST", JMX_API_EXACT, client_control_rule_delete),
    JMX_API_ROUTE_END,
};
