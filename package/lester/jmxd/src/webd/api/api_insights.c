// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
/* Insights flow response builders and their ordered HTTP routes. */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#include <json-c/json.h>

#include "../../jmx_dataset_path.h"
#include "../jmx_app_cache.h"
#include "api_error.h"
#include "api_insights.h"
#include "api_insights_internal.h"
#include "api_json.h"
#include "api_request.h"
#include "api_shared_json.h"
#include "api_ubus.h"
#include "api_util.h"

#define WEBD_INSIGHTS_CACHE_FRESH_SEC 15
#define WEBD_INSIGHTS_CACHE_STALE_SEC 60
#define WEBD_INSIGHTS_CACHE_BUCKET_SEC 60
#define WEBD_INSIGHTS_SHARED_DIR "/tmp/dreamingwrt"
#define WEBD_INSIGHTS_SHARED_FRESH_MS 90000
#define WEBD_INSIGHTS_SHARED_STALE_MS 120000
#define WEBD_INSIGHTS_SHARED_MAX_BYTES (1024U * 1024U)

#define INSIGHTS_CORE (webd_insights_core_ops_get())
#define webd_insights_db_open_runtime(...) INSIGHTS_CORE->db_open_runtime(__VA_ARGS__)
#define webd_insights_config_prepare(...) INSIGHTS_CORE->config_prepare(__VA_ARGS__)
#define webd_insights_safe_token(...) INSIGHTS_CORE->safe_token(__VA_ARGS__)
#define webd_insights_sqlite_table_exists(...) INSIGHTS_CORE->sqlite_table_exists(__VA_ARGS__)
#define webd_insights_aegis_events_count_cached(...) INSIGHTS_CORE->aegis_events_count_cached(__VA_ARGS__)
#define webd_insights_aegis_policy_type_counts_cached(...) INSIGHTS_CORE->aegis_policy_type_counts_cached(__VA_ARGS__)
#define webd_current_flows_diag_publish(...) INSIGHTS_CORE->current_flows_diag_publish(__VA_ARGS__)
#define webd_first_nonempty4(...) INSIGHTS_CORE->first_nonempty4(__VA_ARGS__)
#define webd_insights_read_query(...) INSIGHTS_CORE->read_query(__VA_ARGS__)
#define webd_insights_build_dataset(...) INSIGHTS_CORE->build_dataset(__VA_ARGS__)
#define webd_insights_fetch_current_flows_diag(...) INSIGHTS_CORE->fetch_current_flows_diag(__VA_ARGS__)
#define webd_insights_fetch_history_flows(...) INSIGHTS_CORE->fetch_history_flows(__VA_ARGS__)
#define webd_insights_fetch_history_flows_limit(...) INSIGHTS_CORE->fetch_history_flows_limit(__VA_ARGS__)
#define webd_insights_fetch_audit_urls(...) INSIGHTS_CORE->fetch_audit_urls(__VA_ARGS__)
#define webd_insights_fetch_clients(...) INSIGHTS_CORE->fetch_clients(__VA_ARGS__)
#define webd_insights_fetch_flow_app_summary(...) INSIGHTS_CORE->fetch_flow_app_summary(__VA_ARGS__)
#define webd_insights_geo_from_flows(...) INSIGHTS_CORE->geo_from_flows(__VA_ARGS__)
#define webd_insights_capabilities(...) INSIGHTS_CORE->capabilities(__VA_ARGS__)
#define webd_insights_ubus_data_timeout(...) INSIGHTS_CORE->ubus_data_timeout(__VA_ARGS__)
#define webd_insights_add_option(...) INSIGHTS_CORE->add_option(__VA_ARGS__)
#define webd_insights_add_risk_options(...) INSIGHTS_CORE->add_risk_options(__VA_ARGS__)
#define webd_insights_add_geo_region_options_for_ip(...) INSIGHTS_CORE->add_geo_region_options_for_ip(__VA_ARGS__)
#define webd_insights_aegis_stats_load(...) INSIGHTS_CORE->aegis_stats_load(__VA_ARGS__)
#define webd_insights_aegis_stats_json(...) INSIGHTS_CORE->aegis_stats_json(__VA_ARGS__)
#define webd_insights_aegis_policy_type_breakdown_json(...) INSIGHTS_CORE->aegis_policy_type_breakdown_json(__VA_ARGS__)
#define webd_insights_policy_scope_from_stats(...) INSIGHTS_CORE->policy_scope_from_stats(__VA_ARGS__)
#define webd_insights_risk_ctx_init(...) INSIGHTS_CORE->risk_ctx_init(__VA_ARGS__)
#define webd_insights_risk_ctx_close(...) INSIGHTS_CORE->risk_ctx_close(__VA_ARGS__)
#define webd_insights_annotate_flow_data(...) INSIGHTS_CORE->annotate_flow_data(__VA_ARGS__)
#define webd_insights_risk_available(...) INSIGHTS_CORE->risk_available(__VA_ARGS__)
#define webd_insights_cached_city_mmdb(...) INSIGHTS_CORE->cached_city_mmdb(__VA_ARGS__)
#define webd_insights_cached_country_mmdb(...) INSIGHTS_CORE->cached_country_mmdb(__VA_ARGS__)
#define webd_insights_filter_clear_selection(...) INSIGHTS_CORE->filter_clear_selection(__VA_ARGS__)
#define webd_insights_find_client(...) INSIGHTS_CORE->find_client(__VA_ARGS__)
#define webd_insights_client_name(...) INSIGHTS_CORE->client_name(__VA_ARGS__)
#define webd_insights_app_lookup(...) INSIGHTS_CORE->app_lookup(__VA_ARGS__)
#define webd_insights_seen_string(...) INSIGHTS_CORE->seen_string(__VA_ARGS__)

/* Follows the aegis storage binding, same as dreamingwrt-aegisxd. */
#define WEBD_AEGIS_DB_PATH jmx_dataset_path("aegis")

static void webd_insights_dataset_add_common(struct json_object *data,
                                             const char *source,
                                             unsigned int parts);

int webd_insights_local_location_apply(struct json_object *local,
                                       const char *wan_id,
                                       const char *public_ip)
{
    sqlite3_stmt *st;
    int applied = 0;

    if (!local || !wan_id || !wan_id[0] || webd_insights_db_open_runtime() != 0)
        return 0;
    st = webd_insights_config_prepare(
        "SELECT public_ip,country_code,country_name,region_name,city_name,lat,lon,accuracy_radius "
        "FROM insights_map_local_locations WHERE wan_id=?1 AND enabled=1 "
        "AND (public_ip='' OR public_ip=?2) LIMIT 1");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, public_ip ? public_ip : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *v;
        double lat = sqlite3_column_double(st, 5);
        double lon = sqlite3_column_double(st, 6);

        v = webd_sql_text(st, 1);
        if (v[0]) webd_obj_add_str(local, "country_code", v);
        v = webd_sql_text(st, 2);
        if (v[0]) webd_obj_add_str(local, "country_name", v);
        v = webd_sql_text(st, 3);
        if (v[0]) webd_obj_add_str(local, "region_name", v);
        v = webd_sql_text(st, 4);
        if (v[0]) webd_obj_add_str(local, "city_name", v);
        json_object_object_add(local, "lat", json_object_new_double(lat));
        json_object_object_add(local, "lon", json_object_new_double(lon));
        json_object_object_add(local, "latitude", json_object_new_double(lat));
        json_object_object_add(local, "longitude", json_object_new_double(lon));
        json_object_object_add(local, "accuracy_radius",
                               json_object_new_int(sqlite3_column_int(st, 7)));
        json_object_object_add(local, "city_geo_supported", json_object_new_boolean(1));
        json_object_object_add(local, "mappable", json_object_new_boolean(1));
        webd_obj_add_str(local, "coordinate_source", "configured_wan_location");
        json_object_object_add(local, "coordinate_override", json_object_new_boolean(1));
        applied = 1;
    }
    sqlite3_finalize(st);
    return applied;
}

struct json_object *webd_insights_local_locations_json(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *items = json_object_new_array();
    sqlite3_stmt *st;

    if (webd_insights_db_open_runtime() == 0 &&
        (st = webd_insights_config_prepare(
            "SELECT wan_id,public_ip,enabled,country_code,country_name,region_name,city_name,"
            "lat,lon,accuracy_radius,updated_at FROM insights_map_local_locations "
            "ORDER BY wan_id")) != NULL) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            webd_obj_add_str(o, "wan_id", webd_sql_text(st, 0));
            webd_obj_add_str(o, "public_ip", webd_sql_text(st, 1));
            json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
            webd_obj_add_str(o, "country_code", webd_sql_text(st, 3));
            webd_obj_add_str(o, "country_name", webd_sql_text(st, 4));
            webd_obj_add_str(o, "region_name", webd_sql_text(st, 5));
            webd_obj_add_str(o, "city_name", webd_sql_text(st, 6));
            json_object_object_add(o, "lat", json_object_new_double(sqlite3_column_double(st, 7)));
            json_object_object_add(o, "lon", json_object_new_double(sqlite3_column_double(st, 8)));
            json_object_object_add(o, "accuracy_radius", json_object_new_int(sqlite3_column_int(st, 9)));
            json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 10)));
            webd_obj_add_str(o, "coordinate_source", "configured_wan_location");
            json_object_array_add(items, o);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(data, "items", items);
    json_object_object_add(data, "total", json_object_new_int(json_object_array_length(items)));
    json_object_object_add(data, "source", json_object_new_string("config.db:insights_map_local_locations"));
    return data;
}

int webd_insights_local_location_update(struct json_object *body)
{
    sqlite3_stmt *st;
    const char *wan_id = app_nc_json_str(body, "wan_id", "");
    double lat = app_nc_json_double(body, "lat", 999.0);
    double lon = app_nc_json_double(body, "lon", 999.0);
    int rc;

    if (!body || !wan_id[0] || !webd_insights_safe_token(wan_id) ||
        lat < -90.0 || lat > 90.0 || lon < -180.0 || lon > 180.0 ||
        webd_insights_db_open_runtime() != 0)
        return -1;
    st = webd_insights_config_prepare(
        "INSERT INTO insights_map_local_locations(wan_id,public_ip,enabled,country_code,country_name,"
        "region_name,city_name,lat,lon,accuracy_radius,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) "
        "ON CONFLICT(wan_id) DO UPDATE SET public_ip=excluded.public_ip,enabled=excluded.enabled,"
        "country_code=excluded.country_code,country_name=excluded.country_name,"
        "region_name=excluded.region_name,city_name=excluded.city_name,lat=excluded.lat,lon=excluded.lon,"
        "accuracy_radius=excluded.accuracy_radius,updated_at=excluded.updated_at");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, app_nc_json_str(body, "public_ip", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, app_nc_json_bool(body, "enabled", 1));
    sqlite3_bind_text(st, 4, app_nc_json_str(body, "country_code", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, app_nc_json_str(body, "country_name", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, app_nc_json_str(body, "region_name", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, app_nc_json_str(body, "city_name", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(st, 8, lat);
    sqlite3_bind_double(st, 9, lon);
    sqlite3_bind_int(st, 10, app_nc_json_int(body, "accuracy_radius", 0));
    sqlite3_bind_int64(st, 11, now_s());
    rc = sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(st);
    return rc;
}

struct json_object *webd_insights_map_config_json(void)
{
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "enabled", json_object_new_boolean(1));
    json_object_object_add(data, "configured", json_object_new_boolean(1));
    webd_obj_add_str(data, "provider", "local_geojson");
    webd_obj_add_str(data, "world_url", "/static/maps/world.json");
    webd_obj_add_str(data, "china_url", "/static/maps/china.json");
    json_object_object_add(data, "external_tiles", json_object_new_boolean(0));
    json_object_object_add(data, "requires_key", json_object_new_boolean(0));
    json_object_object_add(data, "maplibre_required", json_object_new_boolean(0));
    webd_obj_add_str(data, "source", "firmware_bundled_geojson");
    webd_obj_add_str(data, "reason", "external_map_provider_retired");
    return data;
}

struct json_object *webd_insights_cybersecure_status_response(int *http_status)
{
    struct json_object *aegis = app_ubus_invoke_object_timeout(
        "dreamingwrt.aegis", "status", NULL, 1500);
    struct json_object *data = json_object_new_object();

    if (http_status)
        *http_status = 200;
    if (aegis) {
        json_object_object_add(data, "available", json_object_new_boolean(1));
        json_object_object_add(data, "enabled",
                               json_object_new_boolean(app_nc_json_bool(aegis, "enabled", 0)));
        json_object_object_add(data, "provider",
                               json_object_new_string("dreamingwrt-aegisxd"));
        json_object_object_add(data, "enhanced_available",
                               json_object_new_boolean(app_nc_json_bool(
                                   webd_obj_child_obj(aegis, "enhanced"), "available", 0)));
        {
            int schema = 0;
            int total_events = webd_insights_aegis_events_count_cached(&schema);
            char policy_scope[64] = "unavailable";
            struct json_object *breakdown = NULL;
            int dns = 0, rep = 0, ids = 0, route = 0, other = 0;

            webd_insights_aegis_policy_type_counts_cached(policy_scope, sizeof(policy_scope),
                &breakdown, &dns, &rep, &ids, &route, &other);
            json_object_object_add(data, "aegis_events_supported",
                                   json_object_new_boolean(schema));
            json_object_object_add(data, "aegis_events", json_object_new_int(total_events));
            json_object_object_add(data, "policy_scope", json_object_new_string(
                total_events > 0 ? policy_scope : "unavailable"));
            json_object_object_add(data, "policy_type_breakdown",
                                   breakdown ? breakdown : json_object_new_object());
            json_object_object_add(data, "dns_filter_policy_hit_supported",
                                   json_object_new_boolean(dns > 0));
            json_object_object_add(data, "reputation_ip_policy_hit_supported",
                                   json_object_new_boolean(rep > 0));
            json_object_object_add(data, "reputation_ip_per_flow_hit_supported",
                                   json_object_new_boolean(1));
            json_object_object_add(data, "reputation_ip_per_flow_precision",
                                   json_object_new_string("conntrack_flow_snapshot"));
            json_object_object_add(data, "reputation_ip_drop_confirmed_supported",
                                   json_object_new_boolean(1));
            json_object_object_add(data, "reputation_ip_drop_confirmed_source",
                                   json_object_new_string("nft_counter_delta"));
            json_object_object_add(data, "ids_ips_policy_hit_supported",
                                   json_object_new_boolean(ids > 0));
            json_object_object_add(data, "policy_route_hit_supported",
                                   json_object_new_boolean(route > 0));
            json_object_object_add(data, "full_policy_supported",
                                   json_object_new_boolean(0));
        }
        json_object_object_add(data, "aegis", aegis);
    } else {
        json_object_object_add(data, "available", json_object_new_boolean(0));
        json_object_object_add(data, "enabled", json_object_new_boolean(0));
        json_object_object_add(data, "provider",
                               json_object_new_string("dreamingwrt-aegisxd"));
        json_object_object_add(data, "enhanced_available", json_object_new_boolean(0));
        json_object_object_add(data, "reason",
                               json_object_new_string("aegisxd_unavailable"));
    }
    json_object_object_add(data, "activation_action",
                           json_object_new_string("open_aegis_settings"));
    json_object_object_add(data, "status_api",
                           json_object_new_string("/api/v1/aegis/status"));
    return webd_envelope(data, "webd.insights_cybersecure");
}

static void webd_insights_dataset_cache_key(char *out, size_t out_len,
                                            const char *prefix,
                                            const struct webd_insights_query *q,
                                            int wants_items,
                                            unsigned int parts)
{
    unsigned long filter_digest = 1469598103UL;
    int side;

    for (side = 0; side < 2; side++) {
        const struct webd_insights_filter_entry *set =
            side ? q->exclude_filters : q->include_filters;
        int count = side ? q->exclude_filter_count : q->include_filter_count;
        int i;

        for (i = 0; i < count; i++) {
            const char *p = set[i].field;
            int v;

            while (*p)
                filter_digest = (filter_digest ^ (unsigned char)*p++) * 16777619UL;
            for (v = 0; v < set[i].count; v++) {
                const char *val = set[i].values[v];

                while (*val)
                    filter_digest = (filter_digest ^ (unsigned char)*val++) * 16777619UL;
                filter_digest = (filter_digest ^ 0x1fU) * 16777619UL;
            }
            filter_digest = (filter_digest ^ (unsigned long)(side + 1)) * 16777619UL;
        }
    }
    /*
     * The text fields together can exceed any fixed key buffer (search and
     * destination_host are 256 each), and callers pass 192-320 bytes. Printing
     * them raw meant a long query lost its tail to truncation and then shared a
     * key with a different query -- precisely the "plausible data for the wrong
     * question" this function exists to prevent. So fold every text field into
     * the digest, which is what actually guarantees uniqueness, and print only a
     * bounded prefix of each for readability when reading cache keys by hand.
     */
    {
        const char *const texts[] = {
            q->period, q->map_scope, q->search, q->risk, q->action,
            q->direction, q->protocol, q->mode, q->dataset, q->source_mac,
            q->destination_host, q->source_ip, q->destination_ip, q->service,
        };
        size_t t;

        for (t = 0; t < sizeof(texts) / sizeof(texts[0]); t++) {
            const char *p = texts[t];

            while (p && *p)
                filter_digest = (filter_digest ^ (unsigned char)*p++) * 16777619UL;
            filter_digest = (filter_digest ^ 0x1dU) * 16777619UL;
        }
    }
    snprintf(out, out_len,
             "%s:%u:%d:%.16s:%.16s:%lld:%lld:%d:%d:%d:%d:%d:%d:%.24s:%.12s:%.12s:%.12s:%.12s:%.12s:%.12s:%.18s:%.24s:%lx",
             prefix, parts, wants_items ? 1 : 0,
             q->period, q->map_scope,
             (long long)(q->ts_from / WEBD_INSIGHTS_CACHE_BUCKET_SEC),
             (long long)(q->ts_to / WEBD_INSIGHTS_CACHE_BUCKET_SEC),
             q->page_number, q->page_size, q->top, q->matrix_offset, q->matrix_limit,
             q->security_only,
             q->search, q->risk, q->action, q->direction, q->protocol,
             q->mode, q->dataset, q->source_mac, q->destination_host,
             filter_digest);
}

static void webd_insights_mark_cached(struct json_object *envelope,
                                      int cache_age_ms, int cache_stale)
{
    struct json_object *data = webd_obj_child_obj(envelope, "data");

    if (!data)
        return;
    json_object_object_add(data, "cache_hit", json_object_new_boolean(1));
    json_object_object_add(data, "cache_age_ms", json_object_new_int(cache_age_ms));
    json_object_object_add(data, "sample_age_ms", json_object_new_int(cache_age_ms));
    json_object_object_add(data, "stale", json_object_new_boolean(cache_stale ? 1 : 0));
    json_object_object_add(data, "cache_stale", json_object_new_boolean(cache_stale ? 1 : 0));
}

static void webd_insights_cache_store(const char *key,
                                      struct json_object *envelope,
                                      struct json_object *data)
{
    struct json_object *diag;
    struct json_object *late = NULL;
    int degraded;

    if (!key || !envelope || !data)
        return;
    degraded = app_nc_json_bool(data, "degraded", 0);
    diag = webd_obj_child_obj(data, "diagnostics");
    if (diag)
        late = webd_obj_child_array(diag, "timed_out_sources");
    /*
     * Only a source that missed the deadline shortens the window.
     *
     * partial_sources looks like the obvious signal and was used here first,
     * but it conflates two different facts. On this deployment it always
     * carries structural absences -- historical_five_tuple_flow_table,
     * policy_hit_events -- sources this box simply does not have. Those never
     * "come back on the next request", so treating them as partial expired the
     * entry after 2s and labelled every hit stale: the cache existed but was
     * rebuilt on nearly every dashboard poll, and the UI was told current data
     * was old. timed_out_sources is the transient set, and it is the one worth
     * retrying soon.
     */
    if (!degraded && late && json_object_array_length(late) > 0) {
        /*
         * A build that dropped a late source should not outlive its own fresh
         * window: that section may well be back on the next request.
         */
        jmx_cache_put_with_stale(key, envelope, 2, 10);
        json_object_object_add(data, "cache_hit", json_object_new_boolean(0));
        return;
    }
    json_object_object_add(data, "cache_hit", json_object_new_boolean(0));
    if (degraded)
        return;
    jmx_cache_put_with_stale(key, envelope, WEBD_INSIGHTS_CACHE_FRESH_SEC,
                             WEBD_INSIGHTS_CACHE_STALE_SEC);
}

static struct json_object *webd_insights_flows_response(const struct http_req *req,
                                                        struct json_object *body,
                                                        int *http_status)
{
    struct webd_insights_query q;
    struct json_object *data;
    int fetch_limit;

    if (http_status)
        *http_status = 200;
    webd_insights_read_query(req, body, &q);
    /*
     * Size the sample from the page actually requested instead of always
     * scanning 1000 rows. The old literal 1000 meant a five-row page cost the
     * same as a full one, which is where the measured 4-7 s came from; the reads
     * themselves are not slow.
     *
     * The page is still over-fetched, because post-filtering can drop rows and a
     * sample sized exactly to the page could come back short. Requesting a
     * deeper page needs proportionally more rows since offset is applied after
     * the fetch. The 1000 ceiling is kept so this can never be slower than
     * before, and the floor keeps aggregate fields meaningful on tiny pages.
     *
     * When post-filtering is active the dataset builder already caps history at
     * 300 internally, so it does not depend on this value being large.
     */
    fetch_limit = q.page_size > 0 ? q.page_size * q.page_number * 2 + 50 : 200;
    if (fetch_limit < 100)
        fetch_limit = 100;
    if (fetch_limit > 1000)
        fetch_limit = 1000;
    data = webd_insights_build_dataset(&q, fetch_limit, 1, q.page_number, q.page_size,
                                       WEBD_INSIGHTS_PART_ALL);
    return webd_envelope(data, "webd.insights_flows_bff");
}

static int webd_insights_page_size_requested(const struct http_req *req,
                                             struct json_object *body)
{
    static const char *keys[] = { "pageSize", "page_size", "limit" };
    char buf[32];
    size_t i;

    for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        if (req && webd_query_get(req->query, keys[i], buf, sizeof(buf)))
            return 1;
        if (body && json_object_object_get(body, keys[i]))
            return 1;
    }
    return 0;
}

static unsigned int webd_insights_shared_hash(const char *key)
{
    unsigned int h = 2166136261U;

    while (key && *key) {
        h ^= (unsigned char)*key++;
        h *= 16777619U;
    }
    return h;
}

static void webd_insights_shared_paths(const char *key, char *path,
                                       size_t path_len, char *lock_path,
                                       size_t lock_len)
{
    unsigned int hash = webd_insights_shared_hash(key);

    if (path && path_len)
        snprintf(path, path_len, WEBD_INSIGHTS_SHARED_DIR
                 "/insights-summary-%08x.json", hash);
    if (lock_path && lock_len)
        snprintf(lock_path, lock_len, WEBD_INSIGHTS_SHARED_DIR
                 "/insights-summary-%08x.lock", hash);
}

static struct json_object *webd_insights_shared_read(const char *key,
                                                     int *age_ms)
{
    char path[256];
    struct json_object *wrapper;
    struct json_object *stored_key = NULL;
    struct json_object *response = NULL;

    webd_insights_shared_paths(key, path, sizeof(path), NULL, 0);
    wrapper = webd_shared_json_read(path, WEBD_INSIGHTS_SHARED_STALE_MS,
                                    WEBD_INSIGHTS_SHARED_MAX_BYTES, age_ms);
    if (!wrapper ||
        !json_object_object_get_ex(wrapper, "cache_key", &stored_key) ||
        !stored_key || strcmp(json_object_get_string(stored_key), key) ||
        !json_object_object_get_ex(wrapper, "response", &response) ||
        !response || !json_object_is_type(response, json_type_object)) {
        if (wrapper)
            json_object_put(wrapper);
        return NULL;
    }
    response = json_object_get(response);
    json_object_put(wrapper);
    return response;
}

static void webd_insights_shared_write(const char *key,
                                       struct json_object *response)
{
    char path[256];
    char lock_path[256];
    struct json_object *wrapper;

    if (!key || !response || !json_object_is_type(response, json_type_object))
        return;
    webd_insights_shared_paths(key, path, sizeof(path), lock_path,
                               sizeof(lock_path));
    wrapper = json_object_new_object();
    if (!wrapper)
        return;
    json_object_object_add(wrapper, "cache_key", json_object_new_string(key));
    json_object_object_add(wrapper, "response", json_object_get(response));
    (void)webd_shared_json_write(path, lock_path,
                                  WEBD_INSIGHTS_SHARED_MAX_BYTES, wrapper);
    json_object_put(wrapper);
}

static void webd_insights_shared_write_locked(const char *key,
                                              struct json_object *response)
{
    char path[256];
    char lock_path[256];
    char tmp[320];
    struct json_object *wrapper;
    const char *json;
    int fd;

    if (!key || !response || !json_object_is_type(response, json_type_object))
        return;
    webd_insights_shared_paths(key, path, sizeof(path), lock_path,
                               sizeof(lock_path));
    wrapper = json_object_new_object();
    if (!wrapper)
        return;
    json_object_object_add(wrapper, "cache_key", json_object_new_string(key));
    json_object_object_add(wrapper, "response", json_object_get(response));
    json = json_object_to_json_string_ext(wrapper, JSON_C_TO_STRING_PLAIN);
    if (json && strlen(json) <= WEBD_INSIGHTS_SHARED_MAX_BYTES &&
        snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) <
            (int)sizeof(tmp)) {
        fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd >= 0) {
            if (webd_write_all(fd, json, strlen(json)) == 0 &&
                close(fd) == 0)
                (void)rename(tmp, path);
            else {
                close(fd);
                unlink(tmp);
            }
        }
    }
    json_object_put(wrapper);
}

static struct json_object *webd_insights_flows_summary_response(const struct http_req *req,
                                                                struct json_object *body,
                                                                int *http_status)
{
    struct webd_insights_query q;
    struct json_object *data;
    struct json_object *cached;
    char cache_key[320];
    int cache_age_ms = 0;
    int cache_stale = 0;
    int shared_lock_fd = -1;

    if (http_status)
        *http_status = 200;
    webd_insights_read_query(req, body, &q);
    /*
     * Cross-request cache. This dataset is the same for every viewer of the
     * same window and filters, and rebuilding it per tab is what made the
     * dashboard cost seconds on each load. The key covers everything that
     * changes the payload, so two different queries cannot share an entry.
     *
     * Deliberately not keyed by user: the response carries no per-identity
     * data, and the route is already gated by the LOW-risk permission check
     * before it is reached. Anything identity-specific must not be added to
     * this payload without keying it here as well.
     */
    webd_insights_dataset_cache_key(cache_key, sizeof(cache_key),
                                    "insights_summary", &q,
                                    webd_insights_page_size_requested(req, body),
                                    WEBD_INSIGHTS_PART_ALL);
    cached = jmx_cache_get_allow_stale(cache_key,
                                       WEBD_INSIGHTS_CACHE_STALE_SEC,
                                       &cache_age_ms, &cache_stale);
    if (cached) {
        webd_insights_mark_cached(cached, cache_age_ms, cache_stale);
        return cached;
    }
    {
        int shared_age_ms = 0;
        struct json_object *shared =
            webd_insights_shared_read(cache_key, &shared_age_ms);

        if (shared && shared_age_ms <= WEBD_INSIGHTS_SHARED_FRESH_MS) {
            webd_insights_mark_cached(shared, shared_age_ms, 0);
            return shared;
        }
        if (shared)
            json_object_put(shared);
    }

    /*
     * Cross-bucket stale: the 60-second cache bucket means the snapshot from
     * the previous bucket is still a perfectly usable answer for a daily or
     * hourly period.  Serve it immediately so no user blocks on a 3-6 s
     * rebuild that only differs by one tick of the timestamp window.
     */
    {
        char prev_key[320];
        int64_t shifted_from = q.ts_from - WEBD_INSIGHTS_CACHE_BUCKET_SEC;
        int64_t shifted_to = q.ts_to - WEBD_INSIGHTS_CACHE_BUCKET_SEC;
        struct webd_insights_query shifted = q;
        struct json_object *prev_shared = NULL;
        int prev_age_ms = 0;

        if (shifted_from >= 0 && shifted_to >= 0) {
            shifted.ts_from = shifted_from;
            shifted.ts_to = shifted_to;
            webd_insights_dataset_cache_key(prev_key, sizeof(prev_key),
                                            "insights_summary", &shifted,
                                            webd_insights_page_size_requested(req, body),
                                            WEBD_INSIGHTS_PART_ALL);
            prev_shared = webd_insights_shared_read(prev_key, &prev_age_ms);
            if (prev_shared && prev_age_ms <= WEBD_INSIGHTS_SHARED_STALE_MS) {
                webd_insights_mark_cached(prev_shared, prev_age_ms, 1);
                return prev_shared;
            }
            if (prev_shared)
                json_object_put(prev_shared);
        }
    }
    /* Same-key cold requests must not all scan audit.db. The first worker owns
     * the lock through build+publish; followers re-check after waiting and
     * return the published snapshot. */
    {
    char shared_lock_path[256];
        int shared_age_ms = 0;
        struct json_object *shared;

        webd_insights_shared_paths(cache_key, NULL, 0, shared_lock_path,
                                   sizeof(shared_lock_path));
        shared_lock_fd = webd_shared_lock_open(shared_lock_path);
        if (shared_lock_fd >= 0) {
            shared = webd_insights_shared_read(cache_key, &shared_age_ms);
            if (shared && shared_age_ms <= WEBD_INSIGHTS_SHARED_FRESH_MS) {
                webd_insights_mark_cached(shared, shared_age_ms, 0);
                flock(shared_lock_fd, LOCK_UN);
                close(shared_lock_fd);
                return shared;
            }
            if (shared)
                json_object_put(shared);
        }
    }
    /*
     * pageSize/page_size/limit were parsed and then discarded here: this call
     * passed include_items = 0 with page_size = 1, so every request answered
     * items: [] and echoed pageSize: 1 no matter what was asked for. The
     * summary's own aggregates do not need items, but a caller that explicitly
     * asks for a page should get one rather than a silently empty list.
     *
     * Absent an explicit request the behaviour is unchanged (aggregate only),
     * so the default summary payload does not grow.
     */
    {
        int wants_items = webd_insights_page_size_requested(req, body);
        int page_size = wants_items ? q.page_size : 1;

        data = webd_insights_build_dataset(&q, 1000, wants_items ? 1 : 0,
                                          wants_items ? q.page_number : 1,
                                          page_size,
                                          WEBD_INSIGHTS_PART_ALL);
        json_object_object_add(data, "items_included",
                               json_object_new_boolean(wants_items ? 1 : 0));
        if (!wants_items)
            json_object_object_add(data, "items_omitted_reason",
                json_object_new_string("summary_defaults_to_aggregates_pass_pageSize_for_items"));
    }
    webd_insights_dataset_add_common(data, "webd.insights_flows_summary_bff",
                                     WEBD_INSIGHTS_PART_ALL);
    cached = webd_envelope(data, "webd.insights_flows_summary_bff");
    webd_insights_cache_store(cache_key, cached, data);
    if (shared_lock_fd >= 0) {
        webd_insights_shared_write_locked(cache_key, cached);
        flock(shared_lock_fd, LOCK_UN);
        close(shared_lock_fd);
    } else {
        webd_insights_shared_write(cache_key, cached);
    }
    return cached;
}

static int webd_insights_key_in(const char *key, const char **list, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        if (list[i] && !strcmp(key, list[i]))
            return 1;
    }
    return 0;
}

static struct json_object *webd_insights_dataset_keep_only(struct json_object *data,
                                                           unsigned int parts)
{
    static const char *common[] = {
        "total", "period", "timestampFrom", "timestampTo",
        "degraded", "degraded_reason", "diagnostics",
        "source", "sample_age_ms", "stale", "partial_sources", "parts"
    };
    static const char *top_apps[] = {
        "top_all_traffic_by_application", "top_apps"
    };
    static const char *top_dests[] = {
        "top_all_count_by_destination",
        "top_all_named_count_by_destination",
        "top_destinations"
    };
    static const char *risk[] = {
        "all_count_by_risk", "risk_breakdown", "security_risk_breakdown",
        "top_cards", "action_split_supported", "action_split_reason"
    };
    struct json_object *kept = json_object_new_object();

    json_object_object_foreach(data, key, val) {
        int keep = webd_insights_key_in(key, common,
                                        sizeof(common) / sizeof(common[0]));

        if (!keep && (parts & WEBD_INSIGHTS_PART_TOP_APPS) &&
            webd_insights_key_in(key, top_apps,
                                 sizeof(top_apps) / sizeof(top_apps[0])))
            keep = 1;
        if (!keep && (parts & WEBD_INSIGHTS_PART_TOP_DESTINATIONS) &&
            webd_insights_key_in(key, top_dests,
                                 sizeof(top_dests) / sizeof(top_dests[0])))
            keep = 1;
        if (!keep && (parts & WEBD_INSIGHTS_PART_RISK) &&
            (webd_insights_key_in(key, risk,
                                  sizeof(risk) / sizeof(risk[0])) ||
             !strncmp(key, "risk_count_", 11)))
            keep = 1;
        if (keep)
            json_object_object_add(kept, key, json_object_get(val));
    }
    json_object_put(data);
    return kept;
}

static void webd_insights_dataset_add_common(struct json_object *data,
                                             const char *source,
                                             unsigned int parts)
{
    struct json_object *partial = json_object_new_array();
    struct json_object *diag = webd_obj_child_obj(data, "diagnostics");
    struct json_object *missing = diag ?
        webd_obj_child_array(diag, "missing_items") : NULL;

    if (missing) {
        int i, n = (int)json_object_array_length(missing);

        for (i = 0; i < n; i++) {
            const char *s = json_object_get_string(json_object_array_get_idx(missing, i));

            if (s)
                json_object_array_add(partial, json_object_new_string(s));
        }
    }
    webd_obj_add_str(data, "source", source);
    json_object_object_add(data, "sample_age_ms", json_object_new_int(0));
    json_object_object_add(data, "stale", json_object_new_boolean(0));
    json_object_object_add(data, "partial_sources", partial);
    json_object_object_add(data, "parts", json_object_new_int((int)parts));
}

static struct json_object *webd_insights_flows_split_response(const struct http_req *req,
                                                              struct json_object *body,
                                                              int *http_status,
                                                              unsigned int parts,
                                                              const char *source)
{
    struct webd_insights_query q;
    struct json_object *data;
    struct json_object *cached;
    char cache_key[320];
    int cache_age_ms = 0;
    int cache_stale = 0;

    if (http_status)
        *http_status = 200;
    webd_insights_read_query(req, body, &q);
    webd_insights_dataset_cache_key(cache_key, sizeof(cache_key),
                                    "insights_part", &q, 0, parts);
    cached = jmx_cache_get_allow_stale(cache_key,
                                       WEBD_INSIGHTS_CACHE_STALE_SEC,
                                       &cache_age_ms, &cache_stale);
    if (cached) {
        webd_insights_mark_cached(cached, cache_age_ms, cache_stale);
        return cached;
    }

    /*
     * Cross-bucket stale: serve the previous bucket's snapshot instead of
     * blocking on a full rebuild at every 60 s boundary.
     */
    {
        char prev_key[320];
        int64_t shifted_from = q.ts_from - WEBD_INSIGHTS_CACHE_BUCKET_SEC;
        int64_t shifted_to = q.ts_to - WEBD_INSIGHTS_CACHE_BUCKET_SEC;
        struct webd_insights_query shifted = q;

        if (shifted_from >= 0 && shifted_to >= 0) {
            shifted.ts_from = shifted_from;
            shifted.ts_to = shifted_to;
            webd_insights_dataset_cache_key(prev_key, sizeof(prev_key),
                                            "insights_part", &shifted, 0, parts);
            cached = jmx_cache_get_allow_stale(prev_key,
                                               WEBD_INSIGHTS_CACHE_STALE_SEC,
                                               &cache_age_ms, &cache_stale);
            if (cached) {
                webd_insights_mark_cached(cached, cache_age_ms, 1);
                return cached;
            }
        }
    }
    data = webd_insights_build_dataset(&q, 200, 0, 1, 1, parts);
    webd_insights_dataset_add_common(data, source, parts);
    data = webd_insights_dataset_keep_only(data, parts);
    cached = webd_envelope(data, source);
    webd_insights_cache_store(cache_key, cached, data);
    return cached;
}

static struct json_object *webd_insights_flows_top_apps_response(const struct http_req *req,
                                                                 struct json_object *body,
                                                                 int *http_status)
{
    return webd_insights_flows_split_response(req, body, http_status,
                                              WEBD_INSIGHTS_PART_TOP_APPS,
                                              "webd.insights_flows_top_apps_bff");
}

static struct json_object *webd_insights_flows_top_destinations_response(const struct http_req *req,
                                                                         struct json_object *body,
                                                                         int *http_status)
{
    return webd_insights_flows_split_response(req, body, http_status,
                                              WEBD_INSIGHTS_PART_TOP_DESTINATIONS,
                                              "webd.insights_flows_top_destinations_bff");
}

static struct json_object *webd_insights_flows_risk_response(const struct http_req *req,
                                                             struct json_object *body,
                                                             int *http_status)
{
    return webd_insights_flows_split_response(req, body, http_status,
                                              WEBD_INSIGHTS_PART_RISK,
                                              "webd.insights_flows_risk_bff");
}

static struct json_object *webd_insights_current_flows_response(const struct http_req *req,
                                                                struct json_object *body,
                                                                int *http_status)
{
    char mac_buf[128] = {0};
    char ip_buf[128] = {0};
    char limit_buf[32];
    char offset_buf[32];
    const char *mac = app_nc_json_str(body, "source_mac", app_nc_json_str(body, "mac", ""));
    const char *ip = app_nc_json_str(body, "source_ip", app_nc_json_str(body, "ip", ""));
    int limit = app_nc_json_int(body, "limit", 200);
    int offset = app_nc_json_int(body, "offset", 0);
    struct json_object *data;

    if (req) {
        if (webd_query_get(req->query, "source_mac", mac_buf, sizeof(mac_buf)) ||
            webd_query_get(req->query, "mac", mac_buf, sizeof(mac_buf)))
            mac = mac_buf;
        if (webd_query_get(req->query, "source_ip", ip_buf, sizeof(ip_buf)) ||
            webd_query_get(req->query, "ip", ip_buf, sizeof(ip_buf)))
            ip = ip_buf;
        if (webd_query_get(req->query, "limit", limit_buf, sizeof(limit_buf)))
            limit = atoi(limit_buf);
        if (webd_query_get(req->query, "offset", offset_buf, sizeof(offset_buf)))
            offset = atoi(offset_buf);
    }
    if (offset < 0)
        offset = 0;
    if (http_status)
        *http_status = 200;
    {
        struct webd_current_flows_diag diag;

        data = webd_insights_fetch_current_flows_diag(mac, ip, limit, offset, &diag);
        if (!data) {
            if (http_status)
                *http_status = 503;
            data = json_object_new_object();
            json_object_object_add(data, "items", json_object_new_array());
            json_object_object_add(data, "flows", json_object_new_array());
            json_object_object_add(data, "total", json_object_new_int(0));
            json_object_object_add(data, "offset", json_object_new_int(offset));
            json_object_object_add(data, "returned", json_object_new_int(0));
            json_object_object_add(data, "has_more", json_object_new_boolean(0));
            json_object_object_add(data, "degraded", json_object_new_boolean(1));
            /*
             * Name the real failure. An oversized upstream reply is a distinct,
             * actionable condition and must not read as "the source is dead".
             */
            json_object_object_add(data, "reason",
                json_object_new_string(diag.too_large ? "response_too_large" :
                                       (diag.reason[0] ? diag.reason :
                                        "insights_current_flows_unavailable")));
            webd_obj_add_str(data, "degraded_reason",
                             diag.too_large ? "response_too_large" : diag.reason);
            webd_current_flows_diag_publish(data, &diag);
        } else {
            struct webd_insights_risk_ctx risk_ctx;

            webd_current_flows_diag_publish(data, &diag);
            webd_insights_risk_ctx_init(&risk_ctx);
            webd_insights_annotate_flow_data(data, &risk_ctx);
            webd_insights_risk_ctx_close(&risk_ctx);
        }
    }
    return webd_envelope(data, "jmxd.insights_current_flows");
}

static struct json_object *webd_insights_history_flows_response(const struct http_req *req,
                                                                struct json_object *body,
                                                                int *http_status)
{
    struct webd_insights_query q;
    struct json_object *data;

    webd_insights_read_query(req, body, &q);
    if (http_status)
        *http_status = 200;
    data = webd_insights_fetch_history_flows(&q);
    if (!data) {
        if (http_status)
            *http_status = 503;
        data = json_object_new_object();
        json_object_object_add(data, "items", json_object_new_array());
        json_object_object_add(data, "flows", json_object_new_array());
        json_object_object_add(data, "total", json_object_new_int(0));
        json_object_object_add(data, "degraded", json_object_new_boolean(1));
        json_object_object_add(data, "reason", json_object_new_string("audit_flows_unavailable"));
    } else {
        struct webd_insights_risk_ctx risk_ctx;

        webd_insights_risk_ctx_init(&risk_ctx);
        webd_insights_annotate_flow_data(data, &risk_ctx);
        webd_insights_risk_ctx_close(&risk_ctx);
    }
    json_object_object_add(data, "period", json_object_new_string(q.period));
    json_object_object_add(data, "timestampFrom", json_object_new_int64(q.ts_from));
    json_object_object_add(data, "timestampTo", json_object_new_int64(q.ts_to));
    return webd_envelope(data, "jmxd.audit_flows");
}

static struct json_object *webd_insights_filter_data_response(const struct http_req *req,
                                                             struct json_object *body,
                                                             int *http_status)
{
    struct webd_insights_query q;
    struct json_object *urls;
    struct json_object *clients;
    struct json_object *history;
    struct json_object *data = json_object_new_object();
    struct json_object *sources = json_object_new_array();
    struct json_object *source_macs = json_object_new_array();
    struct json_object *source_ips = json_object_new_array();
    struct json_object *destination_hosts = json_object_new_array();
    struct json_object *destination_ips = json_object_new_array();
    struct json_object *source_regions = json_object_new_array();
    struct json_object *destination_regions = json_object_new_array();
    struct json_object *all_regions = json_object_new_array();
    struct json_object *networks = json_object_new_array();
    struct json_object *source_networks = json_object_new_array();
    struct json_object *destination_networks = json_object_new_array();
    struct json_object *interfaces = json_object_new_array();
    struct json_object *in_interfaces = json_object_new_array();
    struct json_object *out_interfaces = json_object_new_array();
    struct json_object *wan_interfaces = json_object_new_array();
    struct json_object *services = json_object_new_array();
    struct json_object *protocols = json_object_new_array();
    webd_mmdb_t *city_mmdb = webd_insights_cached_city_mmdb();
    webd_mmdb_t *country_mmdb = webd_insights_cached_country_mmdb();
    struct webd_insights_risk_ctx risk_ctx;
    struct webd_insights_aegis_stats aegis_stats;
    int i, n;

    if (http_status)
        *http_status = 200;
    webd_insights_read_query(req, body, &q);
    webd_insights_filter_clear_selection(&q);
    urls = webd_insights_fetch_audit_urls(&q, 1000);
    clients = webd_insights_fetch_clients();
    history = webd_insights_fetch_history_flows_limit(&q, 200);
    webd_insights_risk_ctx_init(&risk_ctx);
    webd_insights_aegis_stats_load(&q, &aegis_stats);

    if (clients && json_object_is_type(clients, json_type_array)) {
        n = (int)json_object_array_length(clients);
        for (i = 0; i < n; i++) {
            struct json_object *c = json_object_array_get_idx(clients, i);
            const char *mac = app_nc_json_str(c, "mac", "");
            const char *ip = app_nc_json_str(c, "ip", "");
            const char *name = webd_insights_client_name(c, mac);
            struct json_object *src;

            if (!mac[0])
                continue;
            webd_insights_add_option(source_macs, mac, mac, "mac");
            if (ip[0])
                webd_insights_add_option(source_ips, ip, ip, "ip");
            if (app_nc_json_str(c, "network", "")[0]) {
                webd_insights_add_option(networks, app_nc_json_str(c, "network", ""),
                                         app_nc_json_str(c, "network", ""), "id");
                webd_insights_add_option(source_networks, app_nc_json_str(c, "network", ""),
                                         app_nc_json_str(c, "network", ""), "id");
            }
            if (app_nc_json_str(c, "interface", "")[0]) {
                webd_insights_add_option(interfaces, app_nc_json_str(c, "interface", ""),
                                         app_nc_json_str(c, "interface", ""), "id");
                webd_insights_add_option(in_interfaces, app_nc_json_str(c, "interface", ""),
                                         app_nc_json_str(c, "interface", ""), "id");
            }
            if (webd_insights_seen_string(sources, "mac", mac))
                continue;
            src = json_object_new_object();
            webd_obj_add_str(src, "mac", mac);
            webd_obj_add_str(src, "ip", ip);
            webd_obj_add_str(src, "name", name);
            webd_obj_add_str(src, "label", name);
            json_object_array_add(sources, src);
        }
    }
    if (urls && json_object_is_type(urls, json_type_array)) {
        n = (int)json_object_array_length(urls);
        for (i = 0; i < n; i++) {
            struct json_object *u = json_object_array_get_idx(urls, i);
            const char *host = webd_first_nonempty4(
                app_nc_json_str(u, "host", ""),
                app_nc_json_str(u, "sni", ""),
                app_nc_json_str(u, "uri", ""),
                "");

            if (!host[0])
                continue;
            webd_insights_add_option(destination_hosts, host, host, "host");
            webd_insights_add_option(services, host, host, "service");
        }
    }
    {
        struct json_object *flows = webd_obj_child_array(history, "items");

        if (flows && json_object_is_type(flows, json_type_array)) {
            n = (int)json_object_array_length(flows);
            for (i = 0; i < n; i++) {
                struct json_object *f = json_object_array_get_idx(flows, i);
                const char *dst_ip = webd_first_nonempty4(
                    app_nc_json_str(f, "destination_ip", ""),
                    app_nc_json_str(f, "remote_ip", ""),
                    app_nc_json_str(f, "dst", ""),
                    "");
                const char *src_ip = webd_first_nonempty4(
                    app_nc_json_str(f, "source_ip", ""),
                    app_nc_json_str(f, "client_ip", ""),
                    app_nc_json_str(f, "src", ""),
                    "");
                const char *proto = app_nc_json_str(f, "protocol",
                    app_nc_json_str(f, "proto", ""));
                const char *service = app_nc_json_str(f, "service", "");
                const char *wan_id = app_nc_json_str(f, "wan_id", "");
                const char *wan_ifname = app_nc_json_str(f, "wan_ifname", "");
                const char *in_if = webd_first_nonempty4(app_nc_json_str(f, "in_interface", ""),
                                                         app_nc_json_str(f, "interface", ""),
                                                         app_nc_json_str(f, "client_interface", ""), "");
                const char *out_if = webd_first_nonempty4(app_nc_json_str(f, "out_interface", ""),
                                                          wan_ifname, wan_id, "");
                const char *in_net = webd_first_nonempty4(app_nc_json_str(f, "in_network_id", ""),
                                                          app_nc_json_str(f, "source_network_id", ""),
                                                          app_nc_json_str(f, "network", ""), "");
                const char *out_net = webd_first_nonempty4(app_nc_json_str(f, "out_network_id", ""),
                                                           app_nc_json_str(f, "destination_network_id", ""),
                                                           wan_id, wan_ifname);

                if (dst_ip[0])
                    webd_insights_add_option(destination_ips, dst_ip, dst_ip, "ip");
                webd_insights_add_geo_region_options_for_ip(destination_regions, all_regions,
                                                            dst_ip, "destination_region",
                                                            city_mmdb, country_mmdb);
                webd_insights_add_geo_region_options_for_ip(source_regions, all_regions,
                                                            src_ip, "source_region",
                                                            city_mmdb, country_mmdb);
                if (proto[0])
                    webd_insights_add_option(protocols, proto, proto, "id");
                if (service[0])
                    webd_insights_add_option(services, service, service, "service");
                if (in_net[0]) {
                    webd_insights_add_option(networks, in_net, in_net, "id");
                    webd_insights_add_option(source_networks, in_net, in_net, "id");
                }
                if (out_net[0]) {
                    webd_insights_add_option(networks, out_net, out_net, "id");
                    webd_insights_add_option(destination_networks, out_net, out_net, "id");
                }
                if (in_if[0]) {
                    webd_insights_add_option(interfaces, in_if, in_if, "id");
                    webd_insights_add_option(in_interfaces, in_if, in_if, "id");
                }
                if (out_if[0]) {
                    webd_insights_add_option(interfaces, out_if, out_if, "id");
                    webd_insights_add_option(out_interfaces, out_if, out_if, "id");
                    webd_insights_add_option(wan_interfaces, out_if, out_if, "id");
                }
                if (wan_id[0]) {
                    webd_insights_add_option(destination_networks, wan_id, wan_id, "id");
                    webd_insights_add_option(wan_interfaces, wan_id, wan_id, "id");
                }
                if (wan_ifname[0]) {
                    webd_insights_add_option(out_interfaces, wan_ifname, wan_ifname, "id");
                    webd_insights_add_option(wan_interfaces, wan_ifname, wan_ifname, "id");
                }
            }
        }
    }

    json_object_object_add(data, "sources", sources);
    json_object_object_add(data, "source_hosts", json_object_get(sources));
    json_object_object_add(data, "source_macs", source_macs);
    json_object_object_add(data, "source_ips", source_ips);
    json_object_object_add(data, "destination_hosts", destination_hosts);
    json_object_object_add(data, "destination_macs", json_object_new_array());
    json_object_object_add(data, "destination_ips", destination_ips);
    json_object_object_add(data, "source_regions", source_regions);
    json_object_object_add(data, "destination_regions", destination_regions);
    json_object_object_add(data, "regions", all_regions);
    json_object_object_add(data, "networks", networks);
    json_object_object_add(data, "source_networks", source_networks);
    json_object_object_add(data, "source_network_ids", json_object_get(webd_obj_child(data, "source_networks")));
    json_object_object_add(data, "destination_networks", destination_networks);
    json_object_object_add(data, "destination_network_ids", json_object_get(webd_obj_child(data, "destination_networks")));
    json_object_object_add(data, "interfaces", interfaces);
    json_object_object_add(data, "in_interfaces", in_interfaces);
    json_object_object_add(data, "out_interfaces", out_interfaces);
    json_object_object_add(data, "wan_interfaces", wan_interfaces);
    json_object_object_add(data, "services", services);
    if (json_object_array_length(protocols) <= 0)
        webd_insights_add_option(protocols, "unknown", "Unknown", "id");
    json_object_object_add(data, "protocols", protocols);
    {
        struct json_object *actions = json_object_new_array();
        webd_insights_add_option(actions, "allow", "Allow", "id");
        if (aegis_stats.schema_supported) {
            webd_insights_add_option(actions, "block", "Block", "id");
            webd_insights_add_option(actions, "alert", "Alert", "id");
        }
        json_object_object_add(data, "actions", actions);
    }
    {
        struct json_object *risks = json_object_new_array();
        webd_insights_add_risk_options(risks, &risk_ctx);
        if (aegis_stats.schema_supported) {
            webd_insights_add_option(risks, "low", "Low", "id");
            webd_insights_add_option(risks, "suspicious", "Suspicious", "id");
            webd_insights_add_option(risks, "medium", "Medium", "id");
            webd_insights_add_option(risks, "concerning", "Concerning", "id");
            webd_insights_add_option(risks, "high", "High", "id");
        }
        json_object_object_add(data, "risks", risks);
    }
    {
        struct json_object *policies = json_object_new_array();
        struct json_object *policy_types = json_object_new_array();

        for (i = 0; i < aegis_stats.policy_count; i++) {
            const char *policy_id = aegis_stats.policies[i].family[0] ?
                aegis_stats.policies[i].family : aegis_stats.policies[i].key;
            const char *policy_type = aegis_stats.policies[i].category;

            webd_insights_add_option(policies, policy_id,
                                     aegis_stats.policies[i].label, "id");
            if (policy_type && policy_type[0])
                webd_insights_add_option(policy_types, policy_type, policy_type, "id");
        }
        json_object_object_add(data, "policies", policies);
        json_object_object_add(data, "policy_types", policy_types);
    }
    {
        struct json_object *test_events = json_object_new_array();
        struct json_object *manual_ingests = json_object_new_array();
        webd_insights_add_option(test_events, "true", "Test / validation events", "bool");
        webd_insights_add_option(test_events, "false", "Production events", "bool");
        webd_insights_add_option(manual_ingests, "true", "Manual ingest", "bool");
        webd_insights_add_option(manual_ingests, "false", "Runtime ingest", "bool");
        json_object_object_add(data, "test_events", test_events);
        json_object_object_add(data, "manual_ingests", manual_ingests);
    }
    json_object_object_add(data, "capabilities", webd_insights_capabilities());
    json_object_object_add(data, "filter_exclude_supported", json_object_new_boolean(1));
    json_object_object_add(data, "filter_include_then_exclude", json_object_new_boolean(1));
    json_object_object_add(data, "security_only_filter_supported", json_object_new_boolean(1));
    json_object_object_add(data, "security_event_dataset_supported", json_object_new_boolean(1));
    json_object_object_add(data, "dataset_filter_supported", json_object_new_boolean(1));
    json_object_object_add(data, "test_event_filter_supported", json_object_new_boolean(1));
    json_object_object_add(data, "manual_ingest_filter_supported", json_object_new_boolean(1));
    json_object_object_add(data, "network_interface_filter_candidates_supported", json_object_new_boolean(1));
    json_object_object_add(data, "network_interface_filter_source",
                           json_object_new_string("clients+audit_flow_sample"));
    json_object_object_add(data, "geo_region_filter_candidates_supported",
                           json_object_new_boolean(city_mmdb != NULL || country_mmdb != NULL));
    json_object_object_add(data, "geo_region_filter_source",
                           json_object_new_string((city_mmdb || country_mmdb) ?
                                                  "audit_flow_sample_geoip_mmdb" : "geoip_mmdb_unavailable"));
    json_object_object_add(data, "candidate_scope", json_object_new_string("time_window_unfiltered_by_selected_include_exclude"));
    json_object_object_add(data, "history_sample_limit", json_object_new_int(200));
    json_object_object_add(data, "risk_source_available", json_object_new_boolean(webd_insights_risk_available(&risk_ctx)));
    json_object_object_add(data, "risk_source_error", json_object_new_string(risk_ctx.error));
    json_object_object_add(data, "aegis_events", webd_insights_aegis_stats_json(&aegis_stats, q.top));
    json_object_object_add(data, "policy_hit_supported", json_object_new_boolean(aegis_stats.available));
    json_object_object_add(data, "policy_scope", json_object_new_string(webd_insights_policy_scope_from_stats(&aegis_stats)));
    json_object_object_add(data, "policy_type_breakdown", webd_insights_aegis_policy_type_breakdown_json(&aegis_stats));
    json_object_object_add(data, "reason", json_object_new_string("filter-data derived from audit_urls, audit_flow_sample, GeoIP MMDB, client inventory and aegis_events; unsupported dimensions are empty"));
    if (urls) json_object_put(urls);
    if (clients) json_object_put(clients);
    if (history) json_object_put(history);
    webd_insights_risk_ctx_close(&risk_ctx);
    return webd_envelope(data, "webd.insights_filter_data_bff");
}

static struct json_object *webd_insights_geo_response(const struct http_req *req,
                                                      struct json_object *body,
                                                      int *http_status)
{
    struct webd_insights_query q;
    struct json_object *data;
    struct json_object *cached = NULL;
    char cache_key[192];
    int cache_age_ms = 0;
    int cache_stale = 0;

    webd_insights_read_query(req, body, &q);
    snprintf(cache_key, sizeof(cache_key), "insights_geo:%s:%s:%lld:%lld:%d",
             q.period, q.map_scope[0] ? q.map_scope : "world",
             (long long)q.ts_from, (long long)q.ts_to, q.top);
    cached = jmx_cache_get_allow_stale(cache_key, 30, &cache_age_ms, &cache_stale);
    if (cached) {
        struct json_object *cached_data = webd_obj_child_obj(cached, "data");

        if (cached_data) {
            json_object_object_add(cached_data, "cache_hit", json_object_new_boolean(1));
            json_object_object_add(cached_data, "cache_age_ms", json_object_new_int(cache_age_ms));
            json_object_object_add(cached_data, "cache_stale", json_object_new_boolean(cache_stale));
        }
        if (http_status)
            *http_status = 200;
        return cached;
    }
    data = webd_insights_geo_from_flows(&q, http_status);
    json_object_object_add(data, "period", json_object_new_string(q.period));
    json_object_object_add(data, "timestampFrom", json_object_new_int64(q.ts_from));
    json_object_object_add(data, "timestampTo", json_object_new_int64(q.ts_to));
    json_object_object_add(data, "cache_hit", json_object_new_boolean(0));
    json_object_object_add(data, "cache_ttl_sec", json_object_new_int(5));
    /*
     * Keep the canonical contract as regions/routes.  Old aliases such as
     * items/countries/arcs duplicated the same arrays and made Geo responses
     * several times larger, which is painful for webd child workers.
     */
    json_object_object_del(data, "items");
    json_object_object_del(data, "countries");
    json_object_object_del(data, "arcs");
    cached = webd_envelope(data, "webd.insights_geo_flow_bff");
    if (cached && (!http_status || *http_status < 500))
        jmx_cache_put_with_stale(cache_key, cached, 5, 30);
    return cached;
}

static int64_t webd_insights_parse_epoch_ms(const char *s, int64_t def)
{
    char *end = NULL;
    int64_t v;

    if (!s || !s[0])
        return def;
    v = strtoll(s, &end, 10);
    if (end == s)
        return def;
    if (v > 100000000000LL)
        v /= 1000;
    return v;
}

static void webd_insights_activity_window(const struct http_req *req,
                                          struct json_object *body,
                                          int64_t *start_ts,
                                          int64_t *end_ts,
                                          char *range,
                                          size_t range_len)
{
    char start_s[64] = "";
    char end_s[64] = "";
    int64_t now = now_s();
    int64_t start;
    int64_t end;
    int64_t span;
    const char *body_start = app_nc_json_str(body, "start",
        app_nc_json_str(body, "timestampFrom", app_nc_json_str(body, "ts_from", "")));
    const char *body_end = app_nc_json_str(body, "end",
        app_nc_json_str(body, "timestampTo", app_nc_json_str(body, "ts_to", "")));

    if (req) {
        webd_query_get(req->query, "start", start_s, sizeof(start_s));
        webd_query_get(req->query, "end", end_s, sizeof(end_s));
    }
    start = webd_insights_parse_epoch_ms(start_s[0] ? start_s : body_start, now - 86400);
    end = webd_insights_parse_epoch_ms(end_s[0] ? end_s : body_end, now);
    if (end <= 0)
        end = now;
    if (start <= 0)
        start = end - 86400;
    if (start > end) {
        int64_t t = start;
        start = end;
        end = t;
    }
    span = end - start;
    if (span <= 2 * 3600)
        snprintf(range, range_len, "1h");
    else if (span <= 2 * 86400)
        snprintf(range, range_len, "1d");
    else if (span <= 10 * 86400)
        snprintf(range, range_len, "1w");
    else
        snprintf(range, range_len, "1m");
    if (start_ts)
        *start_ts = start;
    if (end_ts)
        *end_ts = end;
}

struct json_object *webd_insights_activity_rate_response(const struct http_req *req,
                                                         struct json_object *body,
                                                         int *http_status)
{
    int64_t start_ts = 0, end_ts = 0;
    char range[16] = "1d";
    struct json_object *params = json_object_new_object();
    struct json_object *upstream;
    struct json_object *traffic = NULL;
    struct json_object *rates = json_object_new_array();
    struct json_object *data = json_object_new_object();
    const char *upstream_source = "unavailable";
    const char *upstream_hot_source = "";
    int64_t max_up = 0, max_down = 0, total_up = 0, total_down = 0;
    int nonzero_points = 0;
    int i, n;

    if (http_status)
        *http_status = 200;
    webd_insights_activity_window(req, body, &start_ts, &end_ts, range, sizeof(range));
    json_object_object_add(params, "range", json_object_new_string(range));
    upstream = app_ubus_invoke_timeout("activity", params, 2000);
    json_object_put(params);
    if (!upstream) {
        if (http_status)
            *http_status = 503;
        json_object_object_add(data, "items", rates);
        json_object_object_add(data, "rates", json_object_get(rates));
        json_object_object_add(data, "degraded", json_object_new_boolean(1));
        json_object_object_add(data, "reason", json_object_new_string("activity_source_unavailable"));
        return webd_envelope(data, "jmxd.activity");
    }
    upstream_source = app_nc_json_str(upstream, "source", "unavailable");
    upstream_hot_source = app_nc_json_str(upstream, "hot_source", "");
    json_object_object_get_ex(upstream, "traffic", &traffic);
    n = traffic && json_object_is_type(traffic, json_type_array) ? (int)json_object_array_length(traffic) : 0;
    for (i = 0; i < n; i++) {
        struct json_object *b = json_object_array_get_idx(traffic, i);
        int64_t ts = app_nc_json_int64(b, "ts", 0);
        int64_t up = app_nc_json_int64(b, "up_avg", app_nc_json_int64(b, "up_rate", 0));
        int64_t down = app_nc_json_int64(b, "down_avg", app_nc_json_int64(b, "down_rate", 0));
        struct json_object *p;

        if (ts < start_ts || ts > end_ts)
            continue;
        if (up > max_up)
            max_up = up;
        if (down > max_down)
            max_down = down;
        total_up += up;
        total_down += down;
        if (up > 0 || down > 0)
            nonzero_points++;
        p = json_object_new_object();
        json_object_object_add(p, "timestamp", json_object_new_int64(ts));
        json_object_object_add(p, "ts", json_object_new_int64(ts));
        json_object_object_add(p, "interval_seconds", json_object_new_int64(app_nc_json_int64(upstream, "bucket_sec", 0)));
        json_object_object_add(p, "rx_bytes", json_object_new_int64(down));
        json_object_object_add(p, "tx_bytes", json_object_new_int64(up));
        json_object_object_add(p, "rx_byte-r", json_object_new_int64(down));
        json_object_object_add(p, "tx_byte-r", json_object_new_int64(up));
        json_object_object_add(p, "download", json_object_new_int64(down));
        json_object_object_add(p, "upload", json_object_new_int64(up));
        json_object_object_add(p, "total_bytes", json_object_new_int64(up + down));
        json_object_object_add(p, "unit", json_object_new_string("B/s"));
        json_object_array_add(rates, p);
    }
    json_object_object_add(data, "items", rates);
    json_object_object_add(data, "rates", json_object_get(rates));
    json_object_object_add(data, "records", json_object_get(rates));
    json_object_object_add(data, "range", json_object_new_string(range));
    json_object_object_add(data, "start", json_object_new_int64(start_ts));
    json_object_object_add(data, "end", json_object_new_int64(end_ts));
    json_object_object_add(data, "bucket_sec", json_object_new_int64(app_nc_json_int64(upstream, "bucket_sec", 0)));
    json_object_object_add(data, "source", json_object_new_string("dreamingwrt.activity"));
    json_object_object_add(data, "data_source", json_object_new_string(upstream_source));
    if (upstream_hot_source[0])
        json_object_object_add(data, "hot_source", json_object_new_string(upstream_hot_source));
    {
        const char *meta_keys[] = {
            "resolution_sec", "sample_count", "expected_sample_count",
            "completeness_ratio", "generation", "gap_reason", "counter_reset",
            "estimated", "period_start", "period_end", NULL
        };
        for (i = 0; meta_keys[i]; i++) {
            struct json_object *meta = NULL;
            if (json_object_object_get_ex(upstream, meta_keys[i], &meta) && meta)
                json_object_object_add(data, meta_keys[i], json_object_get(meta));
        }
    }
    json_object_object_add(data, "unit", json_object_new_string("B/s"));
    json_object_object_add(data, "aggregation", json_object_new_string("backend_bucketed"));
    json_object_object_add(data, "metric_basis", json_object_new_string("rate_sample_avg"));
    json_object_object_add(data, "point_count", json_object_new_int((int)json_object_array_length(rates)));
    if (!json_object_object_get_ex(data, "sample_count", NULL))
        json_object_object_add(data, "sample_count", json_object_new_int((int)json_object_array_length(rates)));
    json_object_object_add(data, "nonzero_points", json_object_new_int(nonzero_points));
    json_object_object_add(data, "max_up_rate", json_object_new_int64(max_up));
    json_object_object_add(data, "max_down_rate", json_object_new_int64(max_down));
    json_object_object_add(data, "sum_up_rate", json_object_new_int64(total_up));
    json_object_object_add(data, "sum_down_rate", json_object_new_int64(total_down));
    json_object_object_add(data, "rate_samples_supported", json_object_new_boolean(json_object_array_length(rates) > 0));
    json_object_object_add(data, "rate_values_supported", json_object_new_boolean(nonzero_points > 0));
    {
        struct json_object *cap = json_object_new_object();
        json_object_object_add(cap, "backend_bucketed", json_object_new_boolean(1));
        json_object_object_add(cap, "range_selected_by_backend", json_object_new_boolean(1));
        json_object_object_add(cap, "rate_samples", json_object_new_boolean(json_object_array_length(rates) > 0));
        json_object_object_add(cap, "nonzero_rate_values", json_object_new_boolean(nonzero_points > 0));
        json_object_object_add(cap, "per_application_rate", json_object_new_boolean(0));
        json_object_object_add(cap, "per_client_rate", json_object_new_boolean(0));
        json_object_object_add(cap, "byte_counters", json_object_new_boolean(0));
        webd_obj_add_str(cap, "source", upstream_source);
        json_object_object_add(data, "capabilities", cap);
    }
    if (json_object_array_length(rates) <= 0) {
        json_object_object_add(data, "degraded", json_object_new_boolean(1));
        json_object_object_add(data, "reason", json_object_new_string("no_activity_rate_samples"));
    } else if (nonzero_points <= 0) {
        json_object_object_add(data, "degraded", json_object_new_boolean(1));
        json_object_object_add(data, "reason", json_object_new_string("activity_rate_samples_all_zero; sampler_not_unified_with_summary_rate"));
    }
    json_object_put(upstream);
    return webd_envelope(data, "jmxd.activity");
}

struct json_object *webd_insights_activity_traffic_response(const struct http_req *req,
                                                            struct json_object *body,
                                                            int *http_status)
{
    int64_t start_ts = 0, end_ts = 0;
    char range[16] = "1d";
    char buf[256];
    struct json_object *apps;
    struct json_object *clients;
    struct json_object *app_rows;
    struct json_object *total_usage = json_object_new_array();
    struct json_object *client_usage = json_object_new_array();
    struct json_object *data = json_object_new_object();
    int64_t total_hits = 0;
    int top = app_nc_json_int(body, "top", 30);
    int matrix_offset = app_nc_json_int(body, "matrix_offset", 0);
    int matrix_limit = app_nc_json_int(body, "matrix_limit", WEBD_ACTIVITY_MATRIX_DEFAULT);
    int activity_timed_out_or_empty = 0;
    int activity_timeout_ms = 2500;
    int i, n;

    if (http_status)
        *http_status = 200;
    webd_insights_activity_window(req, body, &start_ts, &end_ts, range, sizeof(range));
    if (req && webd_query_get(req->query, "top", buf, sizeof(buf)))
        top = atoi(buf);
    if (req && webd_query_get(req->query, "matrix_offset", buf, sizeof(buf)))
        matrix_offset = atoi(buf);
    if (req && webd_query_get(req->query, "matrix_limit", buf, sizeof(buf)))
        matrix_limit = atoi(buf);
    if (top <= 0)
        top = 30;
    if (top > 100)
        top = 100;
    if (matrix_offset < 0)
        matrix_offset = 0;
    if (matrix_limit <= 0)
        matrix_limit = WEBD_ACTIVITY_MATRIX_DEFAULT;
    if (matrix_limit > WEBD_ACTIVITY_MATRIX_MAX)
        matrix_limit = WEBD_ACTIVITY_MATRIX_MAX;
    /*
     * jmxd now maintains audit_client_app_usage_bucket for windows outside the
     * 1h raw sample retention. Always try audit_activity_usage first: short
     * windows use raw flow samples, long windows use bucketed client×app deltas.
     * Keep flow_app_summary only as a truthful fallback if the bucket source is
     * not populated yet or the call times out.
     */
    activity_timeout_ms = (end_ts - start_ts) > (2 * 3600) ? 6000 : 2500;

    {
        struct json_object *params = json_object_new_object();
        struct json_object *activity = NULL;
        struct json_object *activity_rows = NULL;

        json_object_object_add(params, "ts_from", json_object_new_int64(start_ts));
        json_object_object_add(params, "ts_to", json_object_new_int64(end_ts));
        json_object_object_add(params, "timestampFrom", json_object_new_int64(start_ts));
        json_object_object_add(params, "timestampTo", json_object_new_int64(end_ts));
        json_object_object_add(params, "top", json_object_new_int(top));
        json_object_object_add(params, "limit", json_object_new_int(top));
        json_object_object_add(params, "matrix_offset", json_object_new_int(matrix_offset));
        json_object_object_add(params, "matrix_limit", json_object_new_int(matrix_limit));
        if (req && webd_query_get(req->query, "search_text", buf, sizeof(buf)))
            json_object_object_add(params, "search_text", json_object_new_string(buf));
        else if (req && webd_query_get(req->query, "q", buf, sizeof(buf)))
            json_object_object_add(params, "search_text", json_object_new_string(buf));
        else if (app_nc_json_str(body, "search_text", "")[0])
            json_object_object_add(params, "search_text", json_object_new_string(app_nc_json_str(body, "search_text", "")));
        else if (app_nc_json_str(body, "q", "")[0])
            json_object_object_add(params, "search_text", json_object_new_string(app_nc_json_str(body, "q", "")));

#define WEBD_ACTIVITY_COPY_FILTER(name) do { \
            if (req && webd_query_get(req->query, (name), buf, sizeof(buf))) \
                json_object_object_add(params, (name), json_object_new_string(buf)); \
            else if (app_nc_json_str(body, (name), "")[0]) \
                json_object_object_add(params, (name), json_object_new_string(app_nc_json_str(body, (name), ""))); \
        } while (0)
        WEBD_ACTIVITY_COPY_FILTER("source_mac");
        WEBD_ACTIVITY_COPY_FILTER("mac");
        WEBD_ACTIVITY_COPY_FILTER("source_ip");
        WEBD_ACTIVITY_COPY_FILTER("ip");
        WEBD_ACTIVITY_COPY_FILTER("destination_ip");
        WEBD_ACTIVITY_COPY_FILTER("remote_ip");
        WEBD_ACTIVITY_COPY_FILTER("protocol");
        WEBD_ACTIVITY_COPY_FILTER("service");
        WEBD_ACTIVITY_COPY_FILTER("direction");
        WEBD_ACTIVITY_COPY_FILTER("source_network_id");
        WEBD_ACTIVITY_COPY_FILTER("in_network_id");
        WEBD_ACTIVITY_COPY_FILTER("in_interface");
        WEBD_ACTIVITY_COPY_FILTER("destination_network_id");
        WEBD_ACTIVITY_COPY_FILTER("out_network_id");
        WEBD_ACTIVITY_COPY_FILTER("out_interface");
        WEBD_ACTIVITY_COPY_FILTER("wan_id");
        WEBD_ACTIVITY_COPY_FILTER("wan_ifname");
        WEBD_ACTIVITY_COPY_FILTER("mode");
#undef WEBD_ACTIVITY_COPY_FILTER

        activity = webd_insights_ubus_data_timeout("audit_activity_usage", params, activity_timeout_ms);
        json_object_put(params);
        if (activity &&
            ((json_object_object_get_ex(activity, "total_usage_by_app", &activity_rows) &&
              activity_rows && json_object_is_type(activity_rows, json_type_array) &&
              json_object_array_length(activity_rows) > 0) ||
             app_nc_json_bool(activity, "bytes_supported", 0))) {
            json_object_object_add(activity, "range", json_object_new_string(range));
            json_object_object_add(activity, "start", json_object_new_int64(start_ts));
            json_object_object_add(activity, "end", json_object_new_int64(end_ts));
            json_object_object_add(activity, "bff_source", json_object_new_string("webd.insights_activity_traffic"));
            json_object_put(total_usage);
            json_object_put(client_usage);
            json_object_put(data);
            return webd_envelope(activity, "jmxd.audit_activity_usage");
        }
        activity_timed_out_or_empty = 1;
        if (activity)
            json_object_put(activity);
    }

    /*
     * If raw/bucketed activity is unavailable, do not fall back to zero-byte
     * audit_apps rows when a cheaper flow app summary is available; return
     * truthful per-app bytes and clearly mark that the client matrix is degraded.
     */
    {
        struct webd_insights_query q;
        struct json_object *flow_app_summary;
        struct json_object *summary_items;

        memset(&q, 0, sizeof(q));
        snprintf(q.period, sizeof(q.period), "%s", range);
        q.ts_from = start_ts;
        q.ts_to = end_ts;
        q.top = top;
        q.page_number = 1;
        q.page_size = top;
        flow_app_summary = webd_insights_fetch_flow_app_summary(&q, top);
        summary_items = webd_obj_child_array(flow_app_summary, "items");
        if (summary_items && json_object_array_length(summary_items) > 0) {
            int64_t rx_total = 0, tx_total = 0, bytes_total = 0;
            int64_t flow_rows = app_nc_json_int64(flow_app_summary, "flow_rows", 0);
            int64_t private_rows = app_nc_json_int64(flow_app_summary, "private_flow_skipped",
                                                     app_nc_json_int64(flow_app_summary, "local_or_private_flow_skipped", 0));
            int si, sn = (int)json_object_array_length(summary_items);

            for (si = 0; si < sn; si++) {
                struct json_object *row = json_object_array_get_idx(summary_items, si);
                int64_t rx = app_nc_json_int64(row, "rx_bytes",
                                               app_nc_json_int64(row, "download_bytes", 0));
                int64_t tx = app_nc_json_int64(row, "tx_bytes",
                                               app_nc_json_int64(row, "upload_bytes", 0));
                int64_t b = app_nc_json_int64(row, "bytes",
                                              app_nc_json_int64(row, "total_bytes", rx + tx));

                rx_total += rx;
                tx_total += tx;
                bytes_total += b;
            }
            json_object_put(total_usage);
            json_object_put(client_usage);
            total_usage = json_object_get(summary_items);
            client_usage = json_object_new_array();
            json_object_object_add(data, "total_usage_by_app", total_usage);
            json_object_object_add(data, "total_usage_by_application", json_object_get(total_usage));
            json_object_object_add(data, "client_usage_by_app", client_usage);
            json_object_object_add(data, "items", json_object_get(total_usage));
            json_object_object_add(data, "rows", json_object_get(total_usage));
            json_object_object_add(data, "total", json_object_new_int64(bytes_total));
            json_object_object_add(data, "total_bytes", json_object_new_int64(bytes_total));
            json_object_object_add(data, "download_bytes", json_object_new_int64(rx_total));
            json_object_object_add(data, "upload_bytes", json_object_new_int64(tx_total));
            json_object_object_add(data, "rx_bytes", json_object_new_int64(rx_total));
            json_object_object_add(data, "tx_bytes", json_object_new_int64(tx_total));
            json_object_object_add(data, "flow_count", json_object_new_int64(flow_rows));
            json_object_object_add(data, "private_flow_count", json_object_new_int64(private_rows));
            json_object_object_add(data, "range", json_object_new_string(range));
            json_object_object_add(data, "start", json_object_new_int64(start_ts));
            json_object_object_add(data, "end", json_object_new_int64(end_ts));
            json_object_object_add(data, "timestampFrom", json_object_new_int64(start_ts));
            json_object_object_add(data, "timestampTo", json_object_new_int64(end_ts));
            json_object_object_add(data, "bytes_supported", json_object_new_boolean(1));
            json_object_object_add(data, "app_usage_supported", json_object_new_boolean(1));
            json_object_object_add(data, "per_app_bytes_supported", json_object_new_boolean(1));
            json_object_object_add(data, "client_app_matrix_supported", json_object_new_boolean(0));
            json_object_object_add(data, "per_client_app_matrix_supported", json_object_new_boolean(0));
            json_object_object_add(data, "anchor_semantics_supported", json_object_new_boolean(1));
            webd_obj_add_str(data, "anchor", "application");
            webd_obj_add_str(data, "secondary_anchor", "client");
            webd_obj_add_str(data, "aggregation", "backend_grouped");
            webd_obj_add_str(data, "metric_type", "bytes");
            webd_obj_add_str(data, "ranking_basis", "audit_flow_app_summary_bytes");
            webd_obj_add_str(data, "source", "jmxd.audit_flow_app_summary");
            {
                struct json_object *anchors = json_object_new_array();
                struct json_object *cap = json_object_new_object();

                json_object_array_add(anchors, json_object_new_string("application"));
                json_object_array_add(anchors, json_object_new_string("client"));
                json_object_object_add(data, "supported_anchors", anchors);
                json_object_object_add(cap, "application_anchor", json_object_new_boolean(1));
                json_object_object_add(cap, "client_anchor", json_object_new_boolean(0));
                json_object_object_add(cap, "hit_count", json_object_new_boolean(1));
                json_object_object_add(cap, "bytes", json_object_new_boolean(1));
                json_object_object_add(cap, "per_app_bytes", json_object_new_boolean(1));
                json_object_object_add(cap, "per_client_app_matrix", json_object_new_boolean(0));
                json_object_object_add(cap, "filter_anchor_parameter", json_object_new_boolean(0));
                json_object_object_add(cap, "filter_exclude_supported",
                                       json_object_new_boolean(app_nc_json_bool(flow_app_summary, "filter_exclude_supported", 1)));
                json_object_object_add(cap, "filter_include_then_exclude",
                                       json_object_new_boolean(app_nc_json_bool(flow_app_summary, "filter_include_then_exclude", 1)));
                json_object_object_add(cap, "exact_window_bytes", json_object_new_boolean(0));
                webd_obj_add_str(cap, "source", "jmxd.audit_flow_app_summary");
                webd_obj_add_str(cap, "byte_semantics",
                                 app_nc_json_str(flow_app_summary, "byte_semantics",
                                                 "historical_flow_bytes_or_conntrack_counter_summary"));
                json_object_object_add(data, "capabilities", cap);
            }
            json_object_object_add(data, "degraded", json_object_new_boolean(1));
            json_object_object_add(data, "reason", json_object_new_string(
                activity_timed_out_or_empty ?
                "audit_activity_usage_matrix_unavailable_fallback_to_flow_app_summary" :
                "client_app_matrix_unavailable_fallback_to_flow_app_summary"));
            json_object_object_add(data, "matrix_reason", json_object_new_string("per_client_app_matrix_unavailable_for_this_window"));
            if (flow_app_summary)
                json_object_put(flow_app_summary);
            return webd_envelope(data, "webd.insights_activity_traffic.flow_app_summary_fallback");
        }
        if (flow_app_summary)
            json_object_put(flow_app_summary);
    }

    apps = webd_insights_ubus_data_timeout("audit_apps", NULL, 1500);
    clients = webd_insights_fetch_clients();
    app_rows = webd_obj_child_array(apps, "apps");
    n = app_rows && json_object_is_type(app_rows, json_type_array) ? (int)json_object_array_length(app_rows) : 0;
    for (i = 0; i < n; i++) {
        struct json_object *a = json_object_array_get_idx(app_rows, i);
        const char *mac = app_nc_json_str(a, "mac", "");
        int appid = app_nc_json_int(a, "appid", app_nc_json_int(a, "app_id", 0));
        int hits = app_nc_json_int(a, "hit_count", app_nc_json_int(a, "count", 1));
        int64_t ts = app_nc_json_int64(a, "ts", 0);
        struct json_object *client = webd_insights_find_client(clients, mac);
        const char *client_name = webd_insights_client_name(client, mac);
        char app_name[128] = "";
        char app_category[96] = "";
        char app_family[64] = "";
        int canonical_appid = appid;
        int found;
        struct json_object *row;

        if (ts && (ts < start_ts || ts > end_ts))
            continue;
        if (hits <= 0)
            hits = 1;
        total_hits += hits;
        found = webd_insights_app_lookup(appid, app_name, sizeof(app_name),
                                         app_category, sizeof(app_category),
                                         app_family, sizeof(app_family),
                                         &canonical_appid);
        if (!found || !app_name[0])
            snprintf(app_name, sizeof(app_name), appid > 0 ? "App %d" : "Unknown app", appid);
        row = json_object_new_object();
        webd_obj_add_str(row, "application_name", app_name);
        webd_obj_add_str(row, "app_name", app_name);
        webd_obj_add_str(row, "name", app_name);
        webd_obj_add_str(row, "category", app_category);
        webd_obj_add_str(row, "family", app_family);
        webd_obj_add_str(row, "top_client", client_name);
        webd_obj_add_str(row, "topClientName", client_name);
        webd_obj_add_str(row, "client_name", client_name);
        webd_obj_add_str(row, "mac", mac);
        webd_obj_add_str(row, "source", "audit_apps_hit_count");
        json_object_object_add(row, "app_id", json_object_new_int(appid));
        json_object_object_add(row, "appid", json_object_new_int(appid));
        json_object_object_add(row, "canonical_app_id", json_object_new_int(canonical_appid));
        json_object_object_add(row, "hit_count", json_object_new_int(hits));
        json_object_object_add(row, "count", json_object_new_int(hits));
        json_object_object_add(row, "client_count", json_object_new_int(mac[0] ? 1 : 0));
        json_object_object_add(row, "clients", json_object_new_int(mac[0] ? 1 : 0));
        json_object_object_add(row, "total_bytes", json_object_new_int64(0));
        json_object_object_add(row, "download_bytes", json_object_new_int64(0));
        json_object_object_add(row, "upload_bytes", json_object_new_int64(0));
        json_object_object_add(row, "rx_bytes", json_object_new_int64(0));
        json_object_object_add(row, "tx_bytes", json_object_new_int64(0));
        json_object_object_add(row, "bytes_supported", json_object_new_boolean(0));
        json_object_array_add(total_usage, json_object_get(row));
        json_object_array_add(client_usage, row);
    }
    json_object_object_add(data, "total_usage_by_app", total_usage);
    json_object_object_add(data, "total_usage_by_application", json_object_get(total_usage));
    json_object_object_add(data, "client_usage_by_app", client_usage);
    json_object_object_add(data, "items", json_object_get(total_usage));
    json_object_object_add(data, "rows", json_object_get(total_usage));
    json_object_object_add(data, "total", json_object_new_int64(0));
    json_object_object_add(data, "total_bytes", json_object_new_int64(0));
    json_object_object_add(data, "download_bytes", json_object_new_int64(0));
    json_object_object_add(data, "upload_bytes", json_object_new_int64(0));
    json_object_object_add(data, "hit_count", json_object_new_int64(total_hits));
    json_object_object_add(data, "range", json_object_new_string(range));
    json_object_object_add(data, "start", json_object_new_int64(start_ts));
    json_object_object_add(data, "end", json_object_new_int64(end_ts));
    json_object_object_add(data, "bytes_supported", json_object_new_boolean(0));
    json_object_object_add(data, "app_usage_supported", json_object_new_boolean(n > 0));
    json_object_object_add(data, "per_app_bytes_supported", json_object_new_boolean(0));
    json_object_object_add(data, "client_app_matrix_supported", json_object_new_boolean(0));
    json_object_object_add(data, "anchor_semantics_supported", json_object_new_boolean(1));
    webd_obj_add_str(data, "anchor", "application");
    webd_obj_add_str(data, "secondary_anchor", "client");
    webd_obj_add_str(data, "aggregation", "backend_grouped");
    webd_obj_add_str(data, "metric_type", "hit_count");
    webd_obj_add_str(data, "ranking_basis", n > 0 ? "audit_apps_hit_count" : "none");
    webd_obj_add_str(data, "empty_reason", n > 0 ? "" : "no_activity_app_usage_samples");
    {
        struct json_object *anchors = json_object_new_array();
        struct json_object *cap = json_object_new_object();

        json_object_array_add(anchors, json_object_new_string("application"));
        json_object_array_add(anchors, json_object_new_string("client"));
        json_object_object_add(data, "supported_anchors", anchors);
        json_object_object_add(cap, "application_anchor", json_object_new_boolean(1));
        json_object_object_add(cap, "client_anchor", json_object_new_boolean(1));
        json_object_object_add(cap, "hit_count", json_object_new_boolean(n > 0));
        json_object_object_add(cap, "bytes", json_object_new_boolean(0));
        json_object_object_add(cap, "per_app_bytes", json_object_new_boolean(0));
        json_object_object_add(cap, "per_client_app_matrix", json_object_new_boolean(0));
        json_object_object_add(cap, "filter_anchor_parameter", json_object_new_boolean(0));
        webd_obj_add_str(cap, "source", "jmxd.audit_apps");
        json_object_object_add(data, "capabilities", cap);
    }
    json_object_object_add(data, "degraded", json_object_new_boolean(1));
    json_object_object_add(data, "reason", json_object_new_string(
        n > 0 ? "audit_apps_hit_count_only; per-app byte aggregation pending" : "no_activity_app_usage_samples"));
    json_object_object_add(data, "source", json_object_new_string("jmxd.audit_apps"));
    if (apps) json_object_put(apps);
    if (clients) json_object_put(clients);
    return webd_envelope(data, "webd.insights_activity_traffic");
}

static struct json_object *webd_insights_flows_activity_response(const struct http_req *req,
                                                                 struct json_object *body,
                                                                 int *http_status)
{
    int status_traffic = 200, status_rate = 200;
    struct json_object *traffic;
    struct json_object *rate;
    struct json_object *traffic_data;
    struct json_object *rate_data;
    struct json_object *data;
    struct json_object *partial;
    struct json_object *cached;
    struct webd_insights_query q;
    char cache_key[320];
    int cache_age_ms = 0;
    int cache_stale = 0;

    webd_insights_read_query(req, body, &q);
    webd_insights_dataset_cache_key(cache_key, sizeof(cache_key),
                                    "insights_activity", &q, 0,
                                    WEBD_INSIGHTS_PART_ACTIVITY);
    cached = jmx_cache_get_allow_stale(cache_key,
                                       WEBD_INSIGHTS_CACHE_STALE_SEC,
                                       &cache_age_ms, &cache_stale);
    if (cached) {
        if (http_status)
            *http_status = 200;
        webd_insights_mark_cached(cached, cache_age_ms, cache_stale);
        return cached;
    }

    /*
     * Activity is a large, shared read model too.  The in-process cache alone
     * meant that every forked worker could pay the 2.5-6 s upstream cost once.
     * Reuse the same atomic cross-worker snapshot used by the summary BFF.
     */
    {
        int shared_age_ms = 0;
        struct json_object *shared =
            webd_insights_shared_read(cache_key, &shared_age_ms);

        if (shared && shared_age_ms <= WEBD_INSIGHTS_SHARED_FRESH_MS) {
            if (http_status)
                *http_status = 200;
            webd_insights_mark_cached(shared, shared_age_ms, 0);
            return shared;
        }
        if (shared)
            json_object_put(shared);
    }

    /* A rolling day/hour window changes its key at the bucket boundary.  The
     * previous bucket remains valid as an explicitly stale last-known-good
     * answer while this request (or a later worker) refreshes the new bucket. */
    {
        char prev_key[320];
        struct webd_insights_query shifted = q;
        struct json_object *prev = NULL;
        int prev_age_ms = 0;
        int64_t shifted_from = q.ts_from - WEBD_INSIGHTS_CACHE_BUCKET_SEC;
        int64_t shifted_to = q.ts_to - WEBD_INSIGHTS_CACHE_BUCKET_SEC;

        if (shifted_from >= 0 && shifted_to >= 0) {
            shifted.ts_from = shifted_from;
            shifted.ts_to = shifted_to;
            webd_insights_dataset_cache_key(prev_key, sizeof(prev_key),
                                            "insights_activity", &shifted, 0,
                                            WEBD_INSIGHTS_PART_ACTIVITY);
            prev = webd_insights_shared_read(prev_key, &prev_age_ms);
            if (prev && prev_age_ms <= WEBD_INSIGHTS_SHARED_STALE_MS) {
                if (http_status)
                    *http_status = 200;
                webd_insights_mark_cached(prev, prev_age_ms, 1);
                return prev;
            }
            if (prev)
                json_object_put(prev);
        }
    }
    traffic = webd_insights_activity_traffic_response(req, body, &status_traffic);
    rate = webd_insights_activity_rate_response(req, body, &status_rate);
    traffic_data = traffic ? webd_obj_child_obj(traffic, "data") : NULL;
    rate_data = rate ? webd_obj_child_obj(rate, "data") : NULL;
    data = json_object_new_object();
    partial = json_object_new_array();
    if (http_status)
        *http_status = (status_traffic == 200 && status_rate == 200) ? 200 : 503;
    if (traffic_data)
        json_object_object_add(data, "activity_traffic", json_object_get(traffic_data));
    else
        json_object_array_add(partial, json_object_new_string("activity_traffic"));
    if (rate_data)
        json_object_object_add(data, "activity_rate", json_object_get(rate_data));
    else
        json_object_array_add(partial, json_object_new_string("activity_rate"));
    webd_obj_add_str(data, "source", "webd.insights_flows_activity_bff");
    json_object_object_add(data, "sample_age_ms", json_object_new_int(0));
    json_object_object_add(data, "stale", json_object_new_boolean(0));
    json_object_object_add(data, "degraded", json_object_new_boolean(!traffic_data || !rate_data));
    json_object_object_add(data, "partial_sources", partial);
    if (traffic)
        json_object_put(traffic);
    if (rate)
        json_object_put(rate);
    cached = webd_envelope(data, "webd.insights_flows_activity_bff");
    if (status_traffic == 200 && status_rate == 200) {
        webd_insights_cache_store(cache_key, cached, data);
        webd_insights_shared_write(cache_key, cached);
    }
    return cached;
}

/* ---- Thin ctx adapters ---- */

static struct json_object *insights_flows_summary(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = webd_insights_flows_summary_response(
        ctx->req, ctx->body, &ctx->status);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *insights_flows_top_apps(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = webd_insights_flows_top_apps_response(
        ctx->req, ctx->body, &ctx->status);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *insights_flows_top_destinations(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = webd_insights_flows_top_destinations_response(
        ctx->req, ctx->body, &ctx->status);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *insights_flows_risk(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = webd_insights_flows_risk_response(
        ctx->req, ctx->body, &ctx->status);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *insights_flows_activity(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = webd_insights_flows_activity_response(
        ctx->req, ctx->body, &ctx->status);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *insights_filter_data(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = webd_insights_filter_data_response(
        ctx->req, ctx->body, &ctx->status);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *insights_current_flows(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = webd_insights_current_flows_response(
        ctx->req, ctx->body, &ctx->status);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *insights_history_flows(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = webd_insights_history_flows_response(
        ctx->req, ctx->body, &ctx->status);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *insights_geo(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = webd_insights_geo_response(
        ctx->req, ctx->body, &ctx->status);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *insights_activity_traffic(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = webd_insights_activity_traffic_response(
        ctx->req, ctx->body, &ctx->status);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *insights_activity_rate(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = webd_insights_activity_rate_response(
        ctx->req, ctx->body, &ctx->status);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *insights_map_config(struct jmx_api_ctx *ctx)
{
    (void)ctx;
    return webd_envelope(webd_insights_map_config_json(), "webd.insights_map_config");
}

static struct json_object *insights_local_locations(struct jmx_api_ctx *ctx)
{
    (void)ctx;
    return webd_envelope(webd_insights_local_locations_json(),
                         "webd.insights_map_local_locations");
}

static struct json_object *insights_local_location_update(struct jmx_api_ctx *ctx)
{
    if (webd_insights_local_location_update(ctx->body) == 0)
        return webd_envelope(webd_insights_local_locations_json(),
                             "webd.insights_map_local_locations");
    ctx->status = 400;
    return webd_error("invalid_local_location",
                      "wan_id and valid lat/lon are required",
                      "wan_id|lat|lon", "webd.insights");
}

static struct json_object *insights_cybersecure_status(struct jmx_api_ctx *ctx)
{
    return webd_insights_cybersecure_status_response(&ctx->status);
}

static struct json_object *insights_flows(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = webd_insights_flows_response(
        ctx->req, ctx->body, &ctx->status);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

/* ---- Predicate helpers for legacy alias paths ---- */

/*
 * Matches paths containing the substring "/traffic-flow-latest-statistics".
 * Legacy compat alias for /api/v1/insights/flows/summary.
 */
static int is_traffic_flow_latest_statistics(const char *path)
{
    return path && strstr(path, "/traffic-flow-latest-statistics") != NULL;
}

static int is_top_apps_alias(const char *path)
{
    return path && !strcmp(path, "/api/v1/insights/flows/top_apps");
}

static int is_top_destinations_alias(const char *path)
{
    return path && !strcmp(path, "/api/v1/insights/flows/top_destinations");
}

/*
 * Matches paths containing "/traffic-flows/filter-data".
 * Legacy compat alias for /api/v1/insights/flows/filter-data.
 */
static int is_traffic_flows_filter_data(const char *path)
{
    return path && strstr(path, "/traffic-flows/filter-data") != NULL;
}

/*
 * Matches paths ending in "/traffic" (but not exactly "/api/v1/insights/activity/traffic",
 * which is handled by the exact route). Legacy compat for any path ending in /traffic.
 */
static int ends_with_traffic(const char *path)
{
    const char *suffix = "/traffic";
    size_t plen, slen;

    if (!path)
        return 0;
    plen = strlen(path);
    slen = strlen(suffix);
    return plen >= slen && !strcmp(path + plen - slen, suffix);
}

/*
 * Matches paths containing "/app-traffic-rate".
 * Legacy compat alias for /api/v1/insights/activity/app-traffic-rate.
 */
static int is_app_traffic_rate(const char *path)
{
    return path && strstr(path, "/app-traffic-rate") != NULL;
}

/*
 * Matches paths containing "/traffic-flows" (exact substring).
 * Legacy compat alias for /api/v1/insights/flows.
 * Checked after all more specific /api/v1/insights/flows/DOTDOTDOT routes.
 */
static int is_traffic_flows(const char *path)
{
    return path && (strstr(path, "/traffic-flows") != NULL ||
                    !strcmp(path, "/api/v1/insights/flows/list"));
}

/*
 * ---- Route table ----
 *
 * Order matches the original handle_client() if-else chain. The
 * test_route_inventory_stability test locks sequence numbers against
 * the committed baseline.
 */
const struct jmx_api_route insights_api_routes[] = {
    /* seq 212: /api/v1/insights/flows/summary + /traffic-flow-latest-statistics */
    JMX_API_PREDICATE_ROUTE(212, "/api/v1/insights/flows/summary",
                            "GET", JMX_API_EXACT,
                            is_traffic_flow_latest_statistics,
                            insights_flows_summary),
    /* seq 213: /api/v1/insights/flows/top-apps + top_apps alias */
    JMX_API_PREDICATE_ROUTE(213, "/api/v1/insights/flows/top-apps",
                            "GET", JMX_API_EXACT,
                            is_top_apps_alias,
                            insights_flows_top_apps),
    /* seq 214: /api/v1/insights/flows/top-destinations + top_destinations alias */
    JMX_API_PREDICATE_ROUTE(214, "/api/v1/insights/flows/top-destinations",
                            "GET", JMX_API_EXACT,
                            is_top_destinations_alias,
                            insights_flows_top_destinations),
    /* seq 215: /api/v1/insights/flows/risk */
    JMX_API_ROUTE(215, "/api/v1/insights/flows/risk",
                  "GET", JMX_API_EXACT, insights_flows_risk),
    /* seq 216: /api/v1/insights/flows/activity */
    JMX_API_ROUTE(216, "/api/v1/insights/flows/activity",
                  "GET", JMX_API_EXACT, insights_flows_activity),
    /* seq 217: /api/v1/insights/flows/filter-data + /traffic-flows/filter-data */
    JMX_API_PREDICATE_ROUTE(217, "/api/v1/insights/flows/filter-data",
                            "GET", JMX_API_EXACT,
                            is_traffic_flows_filter_data,
                            insights_filter_data),
    /* seq 218: /api/v1/insights/flows/current (GET + POST) */
    JMX_API_ROUTE(218, "/api/v1/insights/flows/current",
                  "GET,POST", JMX_API_EXACT, insights_current_flows),
    /* seq 219: /api/v1/insights/flows/history (GET + POST) */
    JMX_API_ROUTE(219, "/api/v1/insights/flows/history",
                  "GET,POST", JMX_API_EXACT, insights_history_flows),
    /* seq 220: /api/v1/insights/flows/geo */
    JMX_API_ROUTE(220, "/api/v1/insights/flows/geo",
                  "GET", JMX_API_EXACT, insights_geo),
    /* seq 221: /api/v1/insights/activity/traffic + path ending in /traffic */
    JMX_API_PREDICATE_ROUTE(221, "/api/v1/insights/activity/traffic",
                            "GET", JMX_API_EXACT,
                            ends_with_traffic,
                            insights_activity_traffic),
    /* seq 222: /api/v1/insights/activity/app-traffic-rate + /app-traffic-rate */
    JMX_API_PREDICATE_ROUTE(222, "/api/v1/insights/activity/app-traffic-rate",
                            "GET,POST,PUT", JMX_API_EXACT,
                            is_app_traffic_rate,
                            insights_activity_rate),
    /* seq 223: /api/v1/insights/map/config */
    JMX_API_ROUTE(223, "/api/v1/insights/map/config",
                  "GET", JMX_API_EXACT, insights_map_config),
    /* seq 224: /api/v1/insights/map/local-locations (GET) */
    JMX_API_ROUTE(224, "/api/v1/insights/map/local-locations",
                  "GET", JMX_API_EXACT, insights_local_locations),
    /* seq 225: /api/v1/insights/map/local-locations (write) */
    JMX_API_ROUTE(225, "/api/v1/insights/map/local-locations",
                  "POST,PUT,PATCH", JMX_API_EXACT, insights_local_location_update),
    /* seq 226: /api/v1/insights/cybersecure/status */
    JMX_API_ROUTE(226, "/api/v1/insights/cybersecure/status",
                  "GET", JMX_API_EXACT, insights_cybersecure_status),
    /* seq 227: /api/v1/insights/flows + /traffic-flows */
    JMX_API_PREDICATE_ROUTE(227, "/api/v1/insights/flows",
                            "GET,POST,PUT", JMX_API_EXACT,
                            is_traffic_flows,
                            insights_flows),
    JMX_API_ROUTE_END,
};
