// SPDX-License-Identifier: GPL-2.0-or-later
/* Client inventory REST adapter and its single-source read model. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>

#include "../jmx_app_cache.h"
#include "../../proc_path.h"
#include "api_clients_list.h"
#include "api_people.h"
#include "api_error.h"
#include "api_insights_internal.h"
#include "api_json.h"
#include "api_request.h"
#include "api_runtime_cache.h"
#include "api_shared_json.h"
#include "api_ubus.h"
#include "api_util.h"

static void webd_clients_mark_stale(struct json_object *resp, int age_ms)
{
    struct json_object *meta = NULL;
    struct json_object *data = NULL;

    if (!resp)
        return;
    if (!json_object_object_get_ex(resp, "meta", &meta) || !meta ||
        !json_object_is_type(meta, json_type_object)) {
        meta = webd_meta("webd.clients_cache");
        json_object_object_add(resp, "meta", meta);
    }
    json_object_object_add(meta, "cached", json_object_new_boolean(1));
    json_object_object_add(meta, "stale", json_object_new_boolean(1));
    json_object_object_add(meta, "degraded", json_object_new_boolean(1));
    json_object_object_add(meta, "cache_age_ms", json_object_new_int(age_ms));
    webd_obj_add_str(meta, "source_error", "clients_upstream_unavailable");
    if (json_object_object_get_ex(resp, "data", &data) && data &&
        json_object_is_type(data, json_type_object)) {
        json_object_object_add(data, "stale", json_object_new_boolean(1));
        json_object_object_add(data, "degraded", json_object_new_boolean(1));
        json_object_object_add(data, "cache_age_ms", json_object_new_int(age_ms));
        webd_obj_add_str(data, "source_error", "clients_upstream_unavailable");
    }
}

/*
 * The full client inventory and the realtime client snapshot are separate read
 * models.  If the inventory DB is briefly busy during a cold start, the core
 * snapshot is still a useful, explicitly degraded answer for dashboard reads.
 * Do not turn that short window into a 503 and a false empty state.
 */
static struct json_object *webd_clients_realtime_fallback(int with_apps)
{
    static const char *const copy_keys[] = {
        "clients_by_access", "clients_online", "clients_total", NULL
    };
    struct json_object *params = NULL;
    struct json_object *snapshot = NULL;
    struct json_object *snapshot_data = NULL;
    struct json_object *metrics = NULL;
    struct json_object *clients = NULL;
    struct json_object *fallback_clients = NULL;
    struct json_object *data = NULL;
    struct json_object *response = NULL;
    struct json_object *meta = NULL;
    struct json_object *value = NULL;
    int64_t sample_age_ms = 0;
    int shared_age_ms = 0;
    const char *fallback_source = "realtime_snapshot.clients.metrics";
    int i;
    int n;

    /*
     * dashboard/live publishes the same compact clients.metrics read model
     * into a cross-worker snapshot.  Prefer that bounded last-known-good
     * answer before opening another UBUS request: a cold inventory timeout
     * must not immediately turn into a second control-plane read and a false
     * "client inventory source is not available" state.
     */
    snapshot = webd_shared_json_read(WEBD_DASHBOARD_LIVE_SHARED_CACHE_PATH,
                                     WEBD_DASHBOARD_LIVE_SHARED_STALE_MS,
                                     WEBD_DASHBOARD_LIVE_SHARED_MAX_BYTES,
                                     &shared_age_ms);
    if (snapshot)
        fallback_source = "dashboard_live_shared.clients.metrics";
    if (!snapshot) {
        params = json_object_new_object();
        if (!params)
            goto out;
        {
            struct json_object *topics = json_object_new_array();

            if (!topics)
                goto out;
            json_object_array_add(topics,
                                  json_object_new_string("clients.metrics"));
            json_object_object_add(params, "topics", topics);
        }
        snapshot = app_ubus_invoke_timeout("realtime_snapshot", params, 1500);
        json_object_put(params);
        params = NULL;
    }
    snapshot_data = webd_data_or_self_from_jmx_response(snapshot);
    if (!snapshot_data ||
        !json_object_object_get_ex(snapshot_data, "clients.metrics", &metrics) ||
        !metrics || !json_object_is_type(metrics, json_type_object) ||
        !json_object_object_get_ex(metrics, "clients", &clients) ||
        !clients || !json_object_is_type(clients, json_type_array))
        goto out;

    fallback_clients = webd_json_clone(clients);
    data = json_object_new_object();
    if (!fallback_clients || !data)
        goto out;
    json_object_object_add(data, "clients", fallback_clients);
    fallback_clients = NULL;
    for (i = 0; copy_keys[i]; i++) {
        if (json_object_object_get_ex(metrics, copy_keys[i], &value) && value)
            json_object_object_add(data, copy_keys[i], json_object_get(value));
    }
    n = (int)json_object_array_length(clients);
    for (i = 0; with_apps && i < n; i++) {
        struct json_object *client = json_object_array_get_idx(
            json_object_object_get(data, "clients"), i);
        struct json_object *apps = NULL;
        int app_count;

        if (!client || !json_object_is_type(client, json_type_object) ||
            !json_object_object_get_ex(client, "apps", &apps) || !apps ||
            !json_object_is_type(apps, json_type_array))
            continue;
        app_count = (int)json_object_array_length(apps);
        json_object_object_add(client, "active_apps", json_object_get(apps));
        json_object_object_add(client, "active_app_count",
                               json_object_new_int(app_count));
        json_object_object_add(client, "active_apps_returned",
                               json_object_new_int(app_count));
        webd_obj_add_str(client, "active_apps_source", "realtime_snapshot");
    }
    for (i = 0; i < n; i++) {
        struct json_object *client = json_object_array_get_idx(clients, i);

        if (!client || !json_object_is_type(client, json_type_object) ||
            !json_object_object_get_ex(client, "sample_age_ms", &value) || !value)
            continue;
        if (json_object_get_int64(value) > sample_age_ms)
            sample_age_ms = json_object_get_int64(value);
    }
    json_object_object_add(data, "data_source", json_object_new_string(
        fallback_source));
    json_object_object_add(data, "inventory_degraded", json_object_new_boolean(1));
    webd_obj_add_str(data, "inventory_source_error",
                     "clients_inventory_temporarily_unavailable");
    json_object_object_add(data, "sample_age_ms",
                           json_object_new_int64(sample_age_ms));
    json_object_object_add(data, "stale", json_object_new_boolean(0));
    json_object_object_add(data, "degraded", json_object_new_boolean(1));
    response = webd_envelope(data, "webd.clients.realtime_fallback");
    data = NULL;
    if (response && json_object_object_get_ex(response, "meta", &meta) && meta) {
        json_object_object_add(meta, "degraded", json_object_new_boolean(1));
        json_object_object_add(meta, "fallback", json_object_new_boolean(1));
        webd_obj_add_str(meta, "fallback_source",
                         fallback_source);
        json_object_object_add(meta, "sample_age_ms",
                               json_object_new_int64(sample_age_ms));
        if (shared_age_ms > 0)
            json_object_object_add(meta, "shared_cache_age_ms",
                                   json_object_new_int(shared_age_ms));
        json_object_object_add(meta, "with_apps",
                               json_object_new_boolean(with_apps));
    }

out:
    if (params)
        json_object_put(params);
    if (fallback_clients)
        json_object_put(fallback_clients);
    if (data)
        json_object_put(data);
    if (snapshot_data)
        json_object_put(snapshot_data);
    if (snapshot)
        json_object_put(snapshot);
    return response;
}

/*
 * Per-client active application rollup for /api/v1/clients?with_apps=1.
 *
 * The same af_active_app rows already feed dashboard/snapshot, but there they
 * arrive as one flat connection list that every caller has to bucket by MAC
 * itself. The App was doing exactly that: two requests per device-list refresh
 * plus a client-side join. Aggregating here removes the second request without
 * inventing a new data source.
 */
/*
 * Emitted per client, and tracked per client. Tracking more than is emitted
 * keeps active_app_count truthful: reporting the capped figure would tell the
 * App a device has 8 apps when it has 20, and the App shows that count.
 */
#define WEBD_CLIENT_APPS_MAX 8
#define WEBD_CLIENT_APPS_TRACK 64
#define WEBD_CLIENT_APPS_ACTIVE_WINDOW_S 180

/* Rows are grouped by MAC into this table, then attached to the client array. */
struct webd_client_app_row {
    unsigned int app_id;
    unsigned int flows;
    unsigned int last_update;
    /*
     * Destination host of the most recent flow for this app, from the Host
     * column of af_active_app. One app can talk to several hosts, so the newest
     * one is kept: that is what "what is it talking to right now" means, and
     * keeping them all would need an unbounded per-app list.
     */
    char host[256];
};

struct webd_client_app_bucket {
    char mac[32];
    struct webd_client_app_row apps[WEBD_CLIENT_APPS_TRACK];
    int app_count;
    unsigned int flows;
    /* Distinct apps seen beyond the tracking array; only reachable on a device
     * with more than WEBD_CLIENT_APPS_TRACK concurrent applications. */
    unsigned int untracked_rows;
};

static void webd_client_apps_note(struct webd_client_app_bucket *bucket,
                                  unsigned int app_id, unsigned int last_update,
                                  const char *host)
{
    int i;
    /* af_active_app writes "-" for an unresolved host; that is a placeholder,
     * not a hostname, so it is normalised away here rather than shipped. */
    int host_usable = host && host[0] && strcmp(host, "-");

    bucket->flows++;
    for (i = 0; i < bucket->app_count; i++) {
        if (bucket->apps[i].app_id == app_id) {
            bucket->apps[i].flows++;
            if (last_update > bucket->apps[i].last_update) {
                bucket->apps[i].last_update = last_update;
                if (host_usable)
                    snprintf(bucket->apps[i].host,
                             sizeof(bucket->apps[i].host), "%s", host);
            } else if (host_usable && !bucket->apps[i].host[0]) {
                /* Keep the first real host seen when later rows have none, so a
                 * placeholder row does not erase a known destination. */
                snprintf(bucket->apps[i].host, sizeof(bucket->apps[i].host),
                         "%s", host);
            }
            return;
        }
    }
    if (bucket->app_count >= WEBD_CLIENT_APPS_TRACK) {
        bucket->untracked_rows++;
        return;
    }
    bucket->apps[bucket->app_count].app_id = app_id;
    bucket->apps[bucket->app_count].flows = 1;
    bucket->apps[bucket->app_count].last_update = last_update;
    bucket->apps[bucket->app_count].host[0] = '\0';
    if (host_usable)
        snprintf(bucket->apps[bucket->app_count].host,
                 sizeof(bucket->apps[bucket->app_count].host), "%s", host);
    bucket->app_count++;
}

/*
 * Reads af_active_app once and buckets it by MAC.
 *
 * Returns a JSON object keyed by lowercase MAC so the merge below is a lookup
 * rather than a scan per client. NULL means the source was unavailable, which
 * the caller reports rather than passing off as "no apps".
 */
static struct json_object *webd_client_apps_index(int *out_rows)
{
    FILE *fp = jmx_fopen_af("af_active_app", "r");
    struct webd_client_app_bucket *buckets = NULL;
    struct json_object *index = NULL;
    int bucket_count = 0;
    int bucket_capacity = 0;
    int rows = 0;
    char line[1024];
    int header = 1;
    int i, j;
    time_t now = time(NULL);

    if (out_rows)
        *out_rows = 0;
    if (!fp)
        return NULL;

    while (fgets(line, sizeof(line), fp)) {
        unsigned int app_id, src_port, dst_port, app_proto, drop, last_update;
        char mac[32] = {0};
        char src_ip[64] = {0};
        char dst_ip[64] = {0};
        char proto[8] = {0};
        char host[256] = {0};
        struct webd_client_app_bucket *bucket = NULL;
        int parsed;

        if (header) {
            header = 0;
            continue;
        }
        parsed = sscanf(line, "%u %31s %63s %u %63s %u %7s %u %u %255s %u",
                        &app_id, mac, src_ip, &src_port, dst_ip, &dst_port,
                        proto, &app_proto, &drop, host, &last_update);
        if (parsed < 11)
            continue;
        /* Same staleness cut as get_dashboard_active_app, so both views agree. */
        if ((unsigned int)now > last_update &&
            ((unsigned int)now - last_update) > WEBD_CLIENT_APPS_ACTIVE_WINDOW_S)
            continue;
        for (char *p = mac; *p; p++)
            *p = (char)tolower((unsigned char)*p);

        for (i = 0; i < bucket_count; i++) {
            if (!strcmp(buckets[i].mac, mac)) {
                bucket = &buckets[i];
                break;
            }
        }
        if (!bucket) {
            if (bucket_count == bucket_capacity) {
                int next = bucket_capacity ? bucket_capacity * 2 : 32;
                struct webd_client_app_bucket *grown =
                    realloc(buckets, (size_t)next * sizeof(*grown));

                if (!grown)
                    break;
                buckets = grown;
                bucket_capacity = next;
            }
            bucket = &buckets[bucket_count++];
            memset(bucket, 0, sizeof(*bucket));
            snprintf(bucket->mac, sizeof(bucket->mac), "%s", mac);
        }
        webd_client_apps_note(bucket, app_id, last_update, host);
        rows++;
    }
    fclose(fp);

    index = json_object_new_object();
    for (i = 0; i < bucket_count; i++) {
        struct json_object *entry = json_object_new_object();
        struct json_object *apps = json_object_new_array();

        /* Busiest app first: the App shows a short summary line per device. */
        for (j = 1; j < buckets[i].app_count; j++) {
            struct webd_client_app_row key = buckets[i].apps[j];
            int k = j - 1;

            while (k >= 0 && buckets[i].apps[k].flows < key.flows) {
                buckets[i].apps[k + 1] = buckets[i].apps[k];
                k--;
            }
            buckets[i].apps[k + 1] = key;
        }
        /* Emit only the busiest WEBD_CLIENT_APPS_MAX, but count all of them. */
        int emit = buckets[i].app_count < WEBD_CLIENT_APPS_MAX ?
                   buckets[i].app_count : WEBD_CLIENT_APPS_MAX;

        for (j = 0; j < emit; j++) {
            struct json_object *app = json_object_new_object();
            char name[256] = "";
            char category[128] = "";
            char family[128] = "";
            char icon_url[384] = "";
            int canonical = 0;
            int resolved = webd_insights_app_lookup_ex((int)buckets[i].apps[j].app_id,
                                                       name, sizeof(name),
                                                       category, sizeof(category),
                                                       family, sizeof(family),
                                                       icon_url, sizeof(icon_url),
                                                       &canonical);

            json_object_object_add(app, "id",
                                   json_object_new_int((int)buckets[i].apps[j].app_id));
            /* Name comes from the signature DB. When it has no row, say so
             * rather than printing "unknown" as if it were the app's name. */
            webd_obj_add_str(app, "name", (resolved && name[0]) ? name : "");
            webd_obj_add_str(app, "name_source",
                             (resolved && name[0]) ? "signature_db" : "app_id_only");
            if (category[0])
                webd_obj_add_str(app, "category", category);
            if (family[0])
                webd_obj_add_str(app, "family", family);
            /*
             * Always present so the App can tell "no icon in the signature DB"
             * from "this build does not send icons". Empty means no mapping; a
             * placeholder path is never invented.
             */
            webd_obj_add_str(app, "icon_url", icon_url);
            /* Destination host of the newest flow, "" when af_active_app had no
             * resolved name for it. */
            webd_obj_add_str(app, "host", buckets[i].apps[j].host);
            if (canonical > 0 && canonical != (int)buckets[i].apps[j].app_id)
                json_object_object_add(app, "canonical_app_id",
                                       json_object_new_int(canonical));
            json_object_object_add(app, "flows",
                                   json_object_new_int((int)buckets[i].apps[j].flows));
            json_object_object_add(app, "last_seen",
                                   json_object_new_int64((int64_t)buckets[i].apps[j].last_update));
            json_object_array_add(apps, app);
        }
        json_object_object_add(entry, "apps", apps);
        /* Distinct apps for this client, not the number emitted: the App shows
         * this figure, and capping it would understate the device's activity. */
        json_object_object_add(entry, "app_count",
                               json_object_new_int(buckets[i].app_count));
        json_object_object_add(entry, "apps_returned", json_object_new_int(emit));
        json_object_object_add(entry, "flow_count",
                               json_object_new_int((int)buckets[i].flows));
        if (buckets[i].app_count > emit)
            json_object_object_add(entry, "apps_truncated",
                                   json_object_new_int(buckets[i].app_count - emit));
        /* Only set on a device busy enough to overflow the tracking array, in
         * which case app_count itself is a floor rather than an exact figure. */
        if (buckets[i].untracked_rows)
            json_object_object_add(entry, "app_count_is_floor",
                                   json_object_new_boolean(1));
        json_object_object_add(index, buckets[i].mac, entry);
    }
    free(buckets);

    if (out_rows)
        *out_rows = rows;
    return index;
}

/*
 * Attaches active_apps to every client in a clients response.
 *
 * A client with no rows gets an empty array, not a missing field: the App would
 * otherwise have to tell "idle" apart from "not supported" by guessing.
 */
static void webd_clients_attach_apps(struct json_object *resp)
{
    struct json_object *data = NULL;
    struct json_object *clients = NULL;
    struct json_object *index = NULL;
    struct json_object *meta = NULL;
    int rows = 0;
    int matched = 0;
    int i, n;

    if (!resp || !json_object_object_get_ex(resp, "data", &data) || !data ||
        !json_object_is_type(data, json_type_object))
        return;
    if (!json_object_object_get_ex(data, "clients", &clients) || !clients ||
        !json_object_is_type(clients, json_type_array))
        return;

    index = webd_client_apps_index(&rows);
    n = (int)json_object_array_length(clients);
    for (i = 0; i < n; i++) {
        struct json_object *client = json_object_array_get_idx(clients, i);
        struct json_object *entry = NULL;
        struct json_object *apps = NULL;
        char mac[32] = {0};
        const char *raw;

        if (!client || !json_object_is_type(client, json_type_object))
            continue;
        raw = app_nc_json_str(client, "mac", "");
        snprintf(mac, sizeof(mac), "%s", raw);
        for (char *p = mac; *p; p++)
            *p = (char)tolower((unsigned char)*p);

        if (!index) {
            /* Source unavailable: say so per client rather than implying idle. */
            json_object_object_add(client, "active_apps", NULL);
            webd_obj_add_str(client, "active_apps_reason", "af_active_app_unavailable");
            continue;
        }
        if (mac[0] && json_object_object_get_ex(index, mac, &entry) && entry &&
            json_object_object_get_ex(entry, "apps", &apps) && apps) {
            struct json_object *field = NULL;

            json_object_object_add(client, "active_apps", json_object_get(apps));
            json_object_object_add(client, "active_app_count",
                                   json_object_get(json_object_object_get(entry, "app_count")));
            json_object_object_add(client, "active_apps_returned",
                                   json_object_get(json_object_object_get(entry, "apps_returned")));
            json_object_object_add(client, "active_flow_count",
                                   json_object_get(json_object_object_get(entry, "flow_count")));
            if (json_object_object_get_ex(entry, "apps_truncated", &field) && field)
                json_object_object_add(client, "active_apps_truncated",
                                       json_object_get(field));
            if (json_object_object_get_ex(entry, "app_count_is_floor", &field) && field)
                json_object_object_add(client, "active_app_count_is_floor",
                                       json_object_get(field));
            matched++;
        } else {
            json_object_object_add(client, "active_apps", json_object_new_array());
            json_object_object_add(client, "active_app_count", json_object_new_int(0));
            json_object_object_add(client, "active_apps_returned", json_object_new_int(0));
            json_object_object_add(client, "active_flow_count", json_object_new_int(0));
        }
    }

    if (!json_object_object_get_ex(resp, "meta", &meta) || !meta ||
        !json_object_is_type(meta, json_type_object)) {
        meta = webd_meta("webd.clients");
        json_object_object_add(resp, "meta", meta);
    }
    json_object_object_add(meta, "with_apps", json_object_new_boolean(1));
    json_object_object_add(meta, "active_apps_available",
                           json_object_new_boolean(index != NULL));
    if (index) {
        json_object_object_add(meta, "active_apps_rows", json_object_new_int(rows));
        json_object_object_add(meta, "active_apps_matched_clients",
                               json_object_new_int(matched));
        webd_obj_add_str(meta, "active_apps_source", "af_active_app");
        json_object_put(index);
    } else {
        webd_obj_add_str(meta, "active_apps_source", "unavailable");
        webd_obj_add_str(meta, "active_apps_reason", "af_active_app_unavailable");
    }
}

static void webd_client_field_capability(struct json_object *fields,
                                         const char *name, int supported,
                                         const char *reason)
{
    struct json_object *field;

    if (!fields || !name)
        return;
    field = json_object_new_object();
    json_object_object_add(field, "supported",
                           json_object_new_boolean(supported));
    webd_obj_add_str(field, "reason", reason ? reason : "");
    json_object_object_add(fields, name, field);
}

static int webd_client_has_explicit_identity_override(
    struct json_object *override_fields)
{
    static const char *const identity_fields[] = {
        "nickname", "custom_image_path", "device_type", "vendor_name",
        NULL
    };
    size_t i, j, n;

    if (!override_fields ||
        !json_object_is_type(override_fields, json_type_array))
        return 0;
    n = json_object_array_length(override_fields);
    for (i = 0; i < n; i++) {
        struct json_object *value = json_object_array_get_idx(override_fields,
                                                               i);
        const char *field;

        if (!value || !json_object_is_type(value, json_type_string))
            continue;
        field = json_object_get_string(value);
        for (j = 0; identity_fields[j]; j++) {
            if (field && !strcmp(field, identity_fields[j]))
                return 1;
        }
    }
    return 0;
}

/*
 * The client table has historically exposed a wide best-effort row without a
 * contract for fields the collectors do not own. Publish one explicit schema
 * alongside every successful source, including cached and realtime fallback
 * responses, so an empty value cannot be mistaken for implemented telemetry.
 */
static void webd_clients_add_contract(struct json_object *resp)
{
    struct json_object *data = NULL;
    struct json_object *clients = NULL;
    struct json_object *cap = NULL;
    struct json_object *fields;
    struct json_object *bytes;
    struct json_object *realtime;
    struct json_object *topics;
    struct json_object *add;
    int i, n;

    if (!resp || !json_object_object_get_ex(resp, "data", &data) || !data ||
        !json_object_is_type(data, json_type_object))
        return;
    if (!json_object_object_get_ex(data, "capabilities", &cap) || !cap ||
        !json_object_is_type(cap, json_type_object)) {
        cap = json_object_new_object();
        json_object_object_add(data, "capabilities", cap);
    }

    fields = json_object_new_object();
    webd_client_field_capability(fields, "configured", 1,
                                 "explicit_identity_override_only");
    webd_client_field_capability(fields, "experience_score", 0,
                                 "client_experience_producer_unavailable");
    webd_client_field_capability(fields, "channel", 0,
                                 "per_client_wifi_channel_not_collected");
    webd_client_field_capability(fields, "dot1x_identity", 0,
                                 "dot1x_client_identity_not_collected");
    webd_client_field_capability(fields, "dot1x_vlan", 0,
                                 "dot1x_vlan_assignment_not_collected");
    webd_client_field_capability(fields, "vlan_id", 0,
                                 "stable_client_vlan_mapping_unavailable");
    webd_client_field_capability(fields, "vlan_name", 0,
                                 "stable_client_vlan_mapping_unavailable");
    json_object_object_add(cap, "fields", fields);

    bytes = json_object_new_object();
    webd_obj_add_str(bytes, "window", "today");
    webd_obj_add_str(bytes, "reset_at", "local_midnight");
    json_object_object_add(bytes, "estimated", json_object_new_boolean(1));
    json_object_object_add(bytes, "rolling_24h_supported",
                           json_object_new_boolean(0));
    webd_obj_add_str(bytes, "rolling_24h_reason",
                     "rolling_24h_client_counter_unavailable");
    json_object_object_add(cap, "bytes", bytes);

    realtime = json_object_new_object();
    topics = json_object_new_array();
    json_object_array_add(topics, json_object_new_string("client.detail"));
    json_object_array_add(topics, json_object_new_string("client.overview"));
    json_object_array_add(topics, json_object_new_string("client.protocols"));
    json_object_array_add(topics, json_object_new_string("client.connections"));
    json_object_array_add(topics, json_object_new_string("client.connections.v2"));
    json_object_object_add(realtime, "supported", json_object_new_boolean(1));
    json_object_object_add(realtime, "requires_mac", json_object_new_boolean(1));
    json_object_object_add(realtime, "topics", topics);
    webd_obj_add_str(realtime, "detail_contract", "client-detail.v1");
    json_object_object_add(cap, "realtime_authority", realtime);

    add = json_object_new_object();
    json_object_object_add(add, "supported", json_object_new_boolean(0));
    json_object_object_add(add, "atomic", json_object_new_boolean(0));
    webd_obj_add_str(add, "reason",
                     "identity_override_and_dhcp_reservation_have_no_shared_rollback_transaction");
    webd_obj_add_str(add, "identity_endpoint", "/api/v1/client_override");
    webd_obj_add_str(add, "dhcp_endpoint",
                     "/api/v1/clients/{mac}/actions action=dhcp_reserve");
    json_object_object_add(add, "local_dns_supported",
                           json_object_new_boolean(0));
    webd_obj_add_str(add, "local_dns_reason",
                     "local_dns_client_contract_unavailable");
    json_object_object_add(cap, "atomic_client_add", add);

    if (!json_object_object_get_ex(data, "clients", &clients) || !clients ||
        !json_object_is_type(clients, json_type_array))
        return;
    n = (int)json_object_array_length(clients);
    for (i = 0; i < n; i++) {
        struct json_object *client = json_object_array_get_idx(clients, i);
        struct json_object *override_fields = NULL;
        int known;
        int configured;

        if (!client || !json_object_is_type(client, json_type_object))
            continue;
        known = json_object_object_get_ex(client, "override_fields",
                                          &override_fields) &&
                override_fields &&
                json_object_is_type(override_fields, json_type_array);
        configured = known &&
                     webd_client_has_explicit_identity_override(override_fields) == 1;
        json_object_object_add(client, "configured",
                               json_object_new_boolean(configured));
        json_object_object_add(client, "configured_known",
                               json_object_new_boolean(known));
        webd_obj_add_str(client, "configured_source",
                         known ? "explicit_identity_override" : "unavailable");
        webd_obj_add_str(client, "configured_reason",
                         !known ? "identity_override_state_unavailable_in_current_source" :
                         (configured ? "explicit_identity_override_present" :
                                       "no_explicit_identity_override"));
    }
}

/*
 * Applies with_apps to a clients response.
 *
 * The cache holds the plain inventory and hands out shared references, so the
 * merge has to happen on a private copy. Writing into the cached object would
 * leak active_apps into every later request, including the ones that did not
 * ask for it.
 */
static struct json_object *webd_clients_finish(struct json_object *resp, int with_apps)
{
    struct json_object *own;

    if (!resp)
        return resp;

    own = webd_json_clone(resp);
    if (!own) {
        /* Clone failed. resp may be the shared cached object, so nothing is
         * written into it: annotating it here would leak the note into later
         * requests that never asked for with_apps. The caller gets the plain
         * inventory, which is a correct client list without the rollup. */
        return resp;
    }
    json_object_put(resp);
    if (with_apps)
        webd_clients_attach_apps(own);
    webd_clients_add_contract(own);
    return own;
}

struct json_object *webd_clients_response(int *http_status, int with_apps,
                                                 int include_stale)
{
    int cache_age_ms = 0;
    int cache_stale = 0;
    /* Two separate cache entries: the filtered inventory and the full history
     * are different answers, so they must not overwrite each other. */
    const char *cache_key = include_stale ? "clients_inventory_all"
                                          : "clients_inventory";
    struct json_object *cached = jmx_cache_get_allow_stale(
        cache_key, 30, &cache_age_ms, &cache_stale);
    struct json_object *params = NULL;
    struct json_object *upstream;
    struct json_object *data = NULL;
    struct json_object *clients = NULL;
    struct json_object *shared = NULL;
    int shared_age_ms = 0;
    int lock_fd = -1;

    if (cached && !cache_stale)
        return webd_clients_finish(cached, with_apps);
    /* A worker-local cache is not enough: another persistent worker may have
     * published a valid answer immediately before this request arrived. Read
     * that shared snapshot before spending the bounded inventory timeout. */
    shared = webd_shared_json_read(WEBD_CLIENTS_SHARED_CACHE_PATH,
                                   WEBD_CLIENTS_SHARED_FRESH_MS,
                                   WEBD_CLIENTS_SHARED_MAX_BYTES, &shared_age_ms);
    if (shared) {
        if (cached)
            json_object_put(cached);
        return webd_clients_finish(shared, with_apps);
    }
    /* Serialize a cold inventory refresh across persistent workers. Without
     * this, a dashboard burst makes every worker issue the same 1.5s UBUS
     * request and can exhaust the core read lane before fallback engages. */
    lock_fd = webd_shared_lock_open(WEBD_CLIENTS_SHARED_LOCK_PATH);
    if (lock_fd >= 0) {
        shared = webd_shared_json_read(WEBD_CLIENTS_SHARED_CACHE_PATH,
                                       WEBD_CLIENTS_SHARED_FRESH_MS,
                                       WEBD_CLIENTS_SHARED_MAX_BYTES, &shared_age_ms);
        if (shared) {
            flock(lock_fd, LOCK_UN);
            close(lock_fd);
            if (cached)
                json_object_put(cached);
            return webd_clients_finish(shared, with_apps);
        }
    }
    if (include_stale) {
        params = json_object_new_object();
        if (params)
            json_object_object_add(params, "include_stale", json_object_new_int(1));
    }
    /* Keep the inventory lane bounded.  A cold SQLite read must not hold a
     * dashboard worker for two consecutive five-second attempts; the realtime
     * snapshot below is a valid, explicitly degraded answer while the inventory
     * read catches up on a later poll. */
    upstream = app_ubus_invoke_timeout("clients", params,
                                       WEBD_CLIENTS_UPSTREAM_TIMEOUT_MS);
    if (params)
        json_object_put(params);
    data = webd_data_from_jmx_response(upstream);
    if (data && json_object_object_get_ex(data, "clients", &clients) && clients &&
        json_object_is_type(clients, json_type_array)) {
        jmx_cache_put_with_stale(cache_key, upstream, 2, 30);
        (lock_fd >= 0) ?
            webd_shared_json_write_locked(WEBD_CLIENTS_SHARED_CACHE_PATH,
                                          WEBD_CLIENTS_SHARED_MAX_BYTES,
                                          upstream, lock_fd) :
            webd_shared_json_write(WEBD_CLIENTS_SHARED_CACHE_PATH,
                                   WEBD_CLIENTS_SHARED_LOCK_PATH,
                                   WEBD_CLIENTS_SHARED_MAX_BYTES, upstream);
        json_object_put(data);
        if (cached)
            json_object_put(cached);
        if (lock_fd >= 0) {
            flock(lock_fd, LOCK_UN);
            close(lock_fd);
        }
        return webd_clients_finish(upstream, with_apps);
    }
    if (data)
        json_object_put(data);
    if (upstream)
        json_object_put(upstream);
    if (cached) {
        struct json_object *response = webd_json_clone(cached);

        json_object_put(cached);
        if (response) {
            webd_clients_mark_stale(response, cache_age_ms);
            if (lock_fd >= 0) {
                flock(lock_fd, LOCK_UN);
                close(lock_fd);
            }
            return webd_clients_finish(response, with_apps);
        }
    }
    /*
     * The caller asked for with_apps but the app rollup cannot be produced.
     * Never let that turn a usable client inventory into a hard 503. A plain
     * inventory is strictly better than the dashboard showing "client
     * inventory source is not available" for a missing af_active_app file.
     */
    if (with_apps) {
        struct json_object *recheck = jmx_cache_get(cache_key);

        if (recheck) {
            webd_clients_mark_stale(recheck, cache_age_ms);
            if (lock_fd >= 0) {
                flock(lock_fd, LOCK_UN);
                close(lock_fd);
            }
            return webd_clients_finish(recheck, 0);
        }
    }
    /* Re-read after the upstream attempt: a concurrent worker may have won the
     * single-flight race while this worker was waiting on ubus. Permit a stale
     * shared answer for up to one minute, but label it explicitly. */
    shared = webd_shared_json_read(WEBD_CLIENTS_SHARED_CACHE_PATH,
                                   WEBD_CLIENTS_SHARED_STALE_MS,
                                   WEBD_CLIENTS_SHARED_MAX_BYTES, &shared_age_ms);
    if (shared) {
        webd_clients_mark_stale(shared, shared_age_ms);
        if (lock_fd >= 0) {
            flock(lock_fd, LOCK_UN);
            close(lock_fd);
        }
        return webd_clients_finish(shared, with_apps);
    }
    {
        struct json_object *fallback = webd_clients_realtime_fallback(with_apps);

        if (fallback) {
            jmx_cache_put_with_stale(cache_key, fallback, 1, 15);
            if (cached)
                json_object_put(cached);
            if (lock_fd >= 0) {
                flock(lock_fd, LOCK_UN);
                close(lock_fd);
            }
            return webd_clients_finish(fallback, 0);
        }
    }
    if (lock_fd >= 0) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
    }
    if (http_status)
        *http_status = 503;
    return webd_error("source_unavailable",
                      "client inventory source is not available",
                      "dreamingwrt.clients", "webd.clients");
}


static struct json_object *clients_list_any(struct jmx_api_ctx *ctx)
{
    char with_apps[8] = {0};
    char include_stale[8] = {0};
    int merge_apps = 0;
    int want_stale = 0;

    if (webd_query_get(ctx->req->query, "with_apps", with_apps,
                       sizeof(with_apps)) && with_apps[0])
        merge_apps = !strcmp(with_apps, "1") ||
                     !strcasecmp(with_apps, "true") ||
                     !strcasecmp(with_apps, "yes");
    if (webd_query_get(ctx->req->query, "include_stale", include_stale,
                       sizeof(include_stale)) && include_stale[0])
        want_stale = !strcmp(include_stale, "1") ||
                     !strcasecmp(include_stale, "true") ||
                     !strcasecmp(include_stale, "yes");
    struct json_object *response = webd_clients_response(&ctx->status, merge_apps, want_stale);
    webd_people_project_clients(response);
    return response;
}

const struct jmx_api_route clients_list_api_routes[] = {
    JMX_API_ROUTE(582, "/api/v1/clients", "", JMX_API_EXACT, clients_list_any),
    JMX_API_ROUTE_END,
};
