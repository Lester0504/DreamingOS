// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Standalone Insights / LuCI advanced audit BFF (Phase 6J). The /api/v1/audit/*
 * read surface: status, urls, online-records, im-records, traffic, protocols
 * (list + per-protocol detail) and apps (list + per-app detail). The entire
 * audit-BFF subsystem — the webd_audit_bff_query struct, the query readers,
 * match predicates, pagination helpers and the 9 response builders — moves here
 * VERBATIM from jmx_app_api.c and stays file-static; only the 9 thin dispatch
 * delegations become ctx-adapter route handlers. Behavior is preserved: each
 * response fn takes a const struct http_req *, so passing ctx->req directly is
 * identical to the legacy &req read-only copy.
 *
 * Borrowed from jmx_app_api.c (declared in api_audit_internal.h; definitions
 * stay in main with their other insights/utility callers): the 4 webd_insights_*
 * helpers (de-static'd) and the 2 already-extern webd_first_nonempty4 /
 * webd_str_contains_i (prototype only). The full webd_insights_query type comes
 * from api_insights_internal.h (the struct is used by value here).
 */
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <json-c/json.h>

#include "api_audit.h"
#include "api_audit_internal.h"
#include "api_insights_internal.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"
#include "api_util.h"
#include "webd_http_req.h"
#include "../jmx_app_api.h"

/* ── audit BFF subsystem (moved verbatim from jmx_app_api.c) ── */

struct webd_audit_bff_query {
    int64_t ts_from;
    int64_t ts_to;
    int page;
    int page_number;
    int page_size;
    int offset;
    char q[256];
    char mode[32];
    char action[64];
    char category[128];
    char ifname[64];
    char app[128];
    char state[64];
    char sort[64];
    int unknown_first;
    char exclude_action[64];
    char exclude_category[128];
    char exclude_ifname[64];
    char exclude_app[128];
    char exclude_state[64];
};


static void webd_audit_query_get_any(const struct http_req *req, char *out, size_t out_len,
                                     const char *a, const char *b, const char *c, const char *d)
{
    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!req)
        return;
    if (a && webd_query_get(req->query, a, out, out_len) && out[0])
        return;
    if (b && webd_query_get(req->query, b, out, out_len) && out[0])
        return;
    if (c && webd_query_get(req->query, c, out, out_len) && out[0])
        return;
    if (d)
        webd_query_get(req->query, d, out, out_len);
}

static void webd_audit_read_query(const struct http_req *req, struct json_object *body,
                                  struct webd_audit_bff_query *q)
{
    char buf[256];
    int64_t now = now_s();

    if (!q)
        return;
    memset(q, 0, sizeof(*q));
    q->ts_to = now;
    q->ts_from = now - 86400;
    q->page = 0;
    q->page_number = 1;
    q->page_size = 50;

    snprintf(q->q, sizeof(q->q), "%s", app_nc_json_str(body, "q",
             app_nc_json_str(body, "search_text", "")));
    snprintf(q->mode, sizeof(q->mode), "%s", app_nc_json_str(body, "mode",
             app_nc_json_str(body, "view", "records")));
    snprintf(q->action, sizeof(q->action), "%s", app_nc_json_str(body, "action", ""));
    snprintf(q->category, sizeof(q->category), "%s", app_nc_json_str(body, "category", ""));
    snprintf(q->ifname, sizeof(q->ifname), "%s", app_nc_json_str(body, "ifname",
             app_nc_json_str(body, "interface", "")));
    snprintf(q->app, sizeof(q->app), "%s", app_nc_json_str(body, "app",
             app_nc_json_str(body, "application", "")));
    snprintf(q->state, sizeof(q->state), "%s", app_nc_json_str(body, "state",
             app_nc_json_str(body, "status", "")));
    /* exclude filters: flat keys (exclude_action etc.) and nested exclude:{} */
    {
        struct json_object *exc = NULL;
        const char *ea, *ec, *ei, *eapp, *es;
        if (json_object_object_get_ex(body, "exclude", &exc) && exc && json_object_is_type(exc, json_type_object)) {
            ea   = app_nc_json_str(exc, "action", "");
            ec   = app_nc_json_str(exc, "category", "");
            ei   = app_nc_json_str(exc, "ifname", app_nc_json_str(exc, "interface", ""));
            eapp = app_nc_json_str(exc, "app", app_nc_json_str(exc, "application", ""));
            es   = app_nc_json_str(exc, "state", app_nc_json_str(exc, "status", ""));
        } else {
            ea = ec = ei = eapp = es = "";
        }
        snprintf(q->exclude_action,   sizeof(q->exclude_action),   "%s",
                 ea[0] ? ea : app_nc_json_str(body, "exclude_action", ""));
        snprintf(q->exclude_category, sizeof(q->exclude_category), "%s",
                 ec[0] ? ec : app_nc_json_str(body, "exclude_category", ""));
        snprintf(q->exclude_ifname,   sizeof(q->exclude_ifname),   "%s",
                 ei[0] ? ei : app_nc_json_str(body, "exclude_ifname",
                         app_nc_json_str(body, "exclude_interface", "")));
        snprintf(q->exclude_app,      sizeof(q->exclude_app),      "%s",
                 eapp[0] ? eapp : app_nc_json_str(body, "exclude_app",
                         app_nc_json_str(body, "exclude_application", "")));
        snprintf(q->exclude_state,    sizeof(q->exclude_state),    "%s",
                 es[0] ? es : app_nc_json_str(body, "exclude_state",
                         app_nc_json_str(body, "exclude_status", "")));
    }
    snprintf(q->sort, sizeof(q->sort), "%s", app_nc_json_str(body, "sort", ""));
    q->unknown_first = app_nc_json_bool(body, "unknownFirst",
                       app_nc_json_bool(body, "unknown_first", 0));
    /*
     * "limit" is accepted as a third spelling. It was previously dropped, so
     * /api/v1/audit/urls?limit=400 returned the default 50 rows with HTTP 200
     * and no indication the value had been ignored. pageSize and page_size did
     * work, which made the endpoint look like it honoured paging while one of
     * the three documented names silently did nothing.
     */
    q->page_size = app_nc_json_int(body, "pageSize",
                   app_nc_json_int(body, "page_size",
                   app_nc_json_int(body, "limit", q->page_size)));
    if (app_nc_json_has(body, "pageNumber") || app_nc_json_has(body, "page_number")) {
        q->page_number = app_nc_json_int(body, "pageNumber", app_nc_json_int(body, "page_number", 1));
        q->page = q->page_number > 0 ? q->page_number - 1 : 0;
    } else if (app_nc_json_has(body, "page")) {
        q->page = app_nc_json_int(body, "page", 0);
        q->page_number = q->page + 1;
    }
    q->ts_from = webd_insights_ts_normalize(app_nc_json_int64(body, "timestampFrom",
                 app_nc_json_int64(body, "ts_from", app_nc_json_int64(body, "from",
                 app_nc_json_int64(body, "start", q->ts_from)))));
    q->ts_to = webd_insights_ts_normalize(app_nc_json_int64(body, "timestampTo",
               app_nc_json_int64(body, "ts_to", app_nc_json_int64(body, "to",
               app_nc_json_int64(body, "end", q->ts_to)))));

    if (req) {
        webd_audit_query_get_any(req, buf, sizeof(buf), "q", "search_text", "query", NULL);
        if (buf[0]) snprintf(q->q, sizeof(q->q), "%s", buf);
        webd_audit_query_get_any(req, buf, sizeof(buf), "mode", "view", NULL, NULL);
        if (buf[0]) snprintf(q->mode, sizeof(q->mode), "%s", buf);
        if (webd_query_get(req->query, "action", buf, sizeof(buf)))
            snprintf(q->action, sizeof(q->action), "%s", buf);
        if (webd_query_get(req->query, "category", buf, sizeof(buf)))
            snprintf(q->category, sizeof(q->category), "%s", buf);
        webd_audit_query_get_any(req, buf, sizeof(buf), "ifname", "interface", NULL, NULL);
        if (buf[0]) snprintf(q->ifname, sizeof(q->ifname), "%s", buf);
        webd_audit_query_get_any(req, buf, sizeof(buf), "app", "application", "app_name", NULL);
        if (buf[0]) snprintf(q->app, sizeof(q->app), "%s", buf);
        webd_audit_query_get_any(req, buf, sizeof(buf), "state", "status", NULL, NULL);
        if (buf[0]) snprintf(q->state, sizeof(q->state), "%s", buf);
        webd_audit_query_get_any(req, buf, sizeof(buf), "exclude_action", "exc_action", NULL, NULL);
        if (buf[0]) snprintf(q->exclude_action, sizeof(q->exclude_action), "%s", buf);
        if (webd_query_get(req->query, "exclude_category", buf, sizeof(buf)))
            snprintf(q->exclude_category, sizeof(q->exclude_category), "%s", buf);
        webd_audit_query_get_any(req, buf, sizeof(buf), "exclude_ifname", "exclude_interface", NULL, NULL);
        if (buf[0]) snprintf(q->exclude_ifname, sizeof(q->exclude_ifname), "%s", buf);
        webd_audit_query_get_any(req, buf, sizeof(buf), "exclude_app", "exclude_application", NULL, NULL);
        if (buf[0]) snprintf(q->exclude_app, sizeof(q->exclude_app), "%s", buf);
        webd_audit_query_get_any(req, buf, sizeof(buf), "exclude_state", "exclude_status", NULL, NULL);
        if (buf[0]) snprintf(q->exclude_state, sizeof(q->exclude_state), "%s", buf);
        if (webd_query_get(req->query, "sort", buf, sizeof(buf)))
            snprintf(q->sort, sizeof(q->sort), "%s", buf);
        if (webd_query_get(req->query, "unknownFirst", buf, sizeof(buf)) ||
            webd_query_get(req->query, "unknown_first", buf, sizeof(buf)))
            q->unknown_first = atoi(buf) != 0 || !strcasecmp(buf, "true") || !strcasecmp(buf, "yes");
        if (webd_query_get(req->query, "pageSize", buf, sizeof(buf)) ||
            webd_query_get(req->query, "page_size", buf, sizeof(buf)) ||
            webd_query_get(req->query, "limit", buf, sizeof(buf)))
            q->page_size = atoi(buf);
        if (webd_query_get(req->query, "pageNumber", buf, sizeof(buf)) ||
            webd_query_get(req->query, "page_number", buf, sizeof(buf))) {
            q->page_number = atoi(buf);
            q->page = q->page_number > 0 ? q->page_number - 1 : 0;
        } else if (webd_query_get(req->query, "page", buf, sizeof(buf))) {
            q->page = atoi(buf);
            q->page_number = q->page + 1;
        }
        webd_audit_query_get_any(req, buf, sizeof(buf), "timestampFrom", "ts_from", "from", "start");
        if (buf[0]) q->ts_from = webd_insights_ts_normalize(atoll(buf));
        webd_audit_query_get_any(req, buf, sizeof(buf), "timestampTo", "ts_to", "to", "end");
        if (buf[0]) q->ts_to = webd_insights_ts_normalize(atoll(buf));
    }

    if (q->page_size <= 0)
        q->page_size = 50;
    if (q->page_size > 500)
        q->page_size = 500;
    if (q->page < 0)
        q->page = 0;
    if (q->page_number <= 0)
        q->page_number = q->page + 1;
    if (q->ts_to <= 0)
        q->ts_to = now;
    if (q->ts_from <= 0)
        q->ts_from = q->ts_to - 86400;
    if (q->ts_from > q->ts_to) {
        int64_t t = q->ts_from;
        q->ts_from = q->ts_to;
        q->ts_to = t;
    }
    q->offset = q->page * q->page_size;
}

/*
 * Capability tri-state.  Each source-derived bit below accepts:
 *
 *   > 0  the source was queried and is available
 *   = 0  the source was queried and is genuinely unavailable
 *   < 0  this endpoint never queried the source
 *
 * The distinction matters because a handler that simply passed 0 used to emit
 * the same "source unavailable" reason as a handler that had really checked,
 * so /audit/status claimed the IM collector was missing while
 * /audit/im-records was returning live rows from it.  The JSON boolean stays
 * false for both 0 and negative so the payload shape never changes; only the
 * reason string tells a consumer whether the false is authoritative.
 */
static void webd_audit_add_caps(struct json_object *data,
                                int persistent_url_records,
                                int protocol_snapshots,
                                int flow_summary_supported,
                                int online_records_historical,
                                int im_records_supported,
                                int filter_exclude_supported)
{
    struct json_object *cap;
    struct json_object *reasons;

    if (!data)
        return;
    cap = json_object_new_object();
    json_object_object_add(cap, "url_audit_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "url_persistent_records_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "url_persistent_records_available", json_object_new_boolean(persistent_url_records > 0));
    json_object_object_add(cap, "url_runtime_fallback_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "url_domains_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "traffic_audit_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "online_records_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "online_records_historical", json_object_new_boolean(online_records_historical));
    json_object_object_add(cap, "online_records_runtime_fallback", json_object_new_boolean(1));
    json_object_object_add(cap, "im_records_supported", json_object_new_boolean(im_records_supported > 0));
    json_object_object_add(cap, "protocol_summary_supported", json_object_new_boolean(protocol_snapshots > 0 || flow_summary_supported));
    json_object_object_add(cap, "protocol_snapshot_supported", json_object_new_boolean(protocol_snapshots > 0));
    json_object_object_add(cap, "protocol_flow_summary_fallback", json_object_new_boolean(flow_summary_supported));
    json_object_object_add(cap, "app_audit_supported", json_object_new_boolean(flow_summary_supported));
    json_object_object_add(cap, "app_flow_summary_supported", json_object_new_boolean(flow_summary_supported));
    json_object_object_add(cap, "filter_exclude_supported", json_object_new_boolean(filter_exclude_supported));
    json_object_object_add(cap, "pagination", json_object_new_boolean(1));
    json_object_object_add(cap, "export_source", json_object_new_string("current_page"));
    reasons = json_object_new_object();
    if (persistent_url_records <= 0)
        webd_obj_add_str(reasons, "url_persistent_records_available",
                         persistent_url_records < 0 ?
                         "url_persistent_source_not_evaluated_by_this_endpoint" :
                         "audit_url_event_source_unavailable");
    if (!online_records_historical)
        webd_obj_add_str(reasons, "online_records_historical",
                         "online_event_journal_not_available");
    if (im_records_supported <= 0)
        webd_obj_add_str(reasons, "im_records_supported",
                         im_records_supported < 0 ?
                         "im_capability_not_evaluated_by_this_endpoint" :
                         "im_presence_source_unavailable_af_active_app_af_active_host_unreadable");
    if (protocol_snapshots <= 0)
        webd_obj_add_str(reasons, "protocol_snapshot_supported",
                         protocol_snapshots < 0 ?
                         "protocol_snapshot_source_not_evaluated_by_this_endpoint" :
                         flow_summary_supported ?
                         "protocol_snapshot_unavailable_using_flow_summary" :
                         "protocol_snapshot_source_unavailable");
    if (!filter_exclude_supported)
        webd_obj_add_str(reasons, "filter_exclude_supported",
                         "audit_bff_exclude_filters_not_implemented");
    json_object_object_add(cap, "reasons", reasons);
    json_object_object_add(data, "capabilities", cap);
}

static int webd_audit_status_table_rows(struct json_object *status, const char *name)
{
    struct json_object *tables = webd_obj_child_array(status, "tables");
    int i, n;

    if (!tables || !name)
        return 0;
    n = (int)json_object_array_length(tables);
    for (i = 0; i < n; i++) {
        struct json_object *t = json_object_array_get_idx(tables, i);
        if (!strcmp(app_nc_json_str(t, "name", ""), name))
            return app_nc_json_int(t, "rows", 0);
    }
    return 0;
}

static int webd_audit_status_has_table(struct json_object *status, const char *name)
{
    struct json_object *tables = webd_obj_child_array(status, "tables");
    int i, n;

    if (!tables || !name)
        return 0;
    n = (int)json_object_array_length(tables);
    for (i = 0; i < n; i++) {
        struct json_object *table = json_object_array_get_idx(tables, i);

        if (!strcmp(app_nc_json_str(table, "name", ""), name))
            return 1;
    }
    return 0;
}

static struct json_object *webd_audit_fetch_view(void)
{
    return webd_insights_ubus_data_timeout("audit_view", NULL, 1800);
}

static struct json_object *webd_audit_fetch_status(void)
{
    return webd_insights_ubus_data_timeout("audit_status", NULL, 1800);
}

/*
 * The IM collector is authoritative about its own availability: audit_view
 * carries im_records_supported, set from whether af_active_app /
 * af_active_host could be read at all.  Deriving this from a row count would
 * report "unsupported" whenever nobody happens to be on an IM app, which is
 * the opposite of the truth.  Returns the tri-state expected by
 * webd_audit_add_caps(): 1 available, 0 source unreadable, -1 no view.
 */
static int webd_audit_view_im_supported(struct json_object *view)
{
    struct json_object *flag = NULL;

    if (!view)
        return -1;
    if (!json_object_object_get_ex(view, "im_records_supported", &flag) || !flag)
        return -1;
    return json_object_get_boolean(flag) ? 1 : 0;
}

static int webd_audit_row_any_contains(struct json_object *row, const char *needle,
                                       const char *const *keys, int key_count)
{
    int i;

    if (!needle || !needle[0])
        return 1;
    if (!row)
        return 0;
    for (i = 0; i < key_count; i++) {
        const char *v = app_nc_json_str(row, keys[i], "");
        if (v[0] && webd_str_contains_i(v, needle))
            return 1;
    }
    return 0;
}

static int webd_audit_row_field_contains(struct json_object *row, const char *needle,
                                         const char *const *keys, int key_count)
{
    return webd_audit_row_any_contains(row, needle, keys, key_count);
}

static int webd_audit_url_record_match(struct json_object *row, const struct webd_audit_bff_query *q)
{
    static const char *search_keys[] = {
        "client", "client_name", "name", "ip", "mac", "account", "url", "host",
        "domain", "path", "app", "app_name", "application", "category", "evidence", "wan"
    };
    static const char *action_keys[] = { "action", "verdict", "policy_action" };
    static const char *category_keys[] = { "category", "type", "class", "audit_category" };

    if (!webd_audit_row_any_contains(row, q ? q->q : "", search_keys,
                                     (int)(sizeof(search_keys) / sizeof(search_keys[0]))))
        return 0;
    if (q && q->action[0] && !webd_audit_row_field_contains(row, q->action, action_keys,
                                                            (int)(sizeof(action_keys) / sizeof(action_keys[0]))))
        return 0;
    if (q && q->category[0] && !webd_audit_row_field_contains(row, q->category, category_keys,
                                                              (int)(sizeof(category_keys) / sizeof(category_keys[0]))))
        return 0;
    /* exclude filters: reject rows matching any exclude field */
    if (q && q->exclude_action[0] && webd_audit_row_field_contains(row, q->exclude_action, action_keys,
                                                                   (int)(sizeof(action_keys) / sizeof(action_keys[0]))))
        return 0;
    if (q && q->exclude_category[0] && webd_audit_row_field_contains(row, q->exclude_category, category_keys,
                                                                     (int)(sizeof(category_keys) / sizeof(category_keys[0]))))
        return 0;
    return 1;
}

static int webd_audit_online_match(struct json_object *row, const struct webd_audit_bff_query *q)
{
    static const char *search_keys[] = {
        "client", "client_name", "hostname", "device", "name", "ip", "mac", "ifname",
        "interface", "network", "vlan", "connection", "vendor", "device_type", "model", "os",
        "source", "reason"
    };
    static const char *action_keys[] = { "action", "event", "state", "status" };
    static const char *if_keys[] = { "ifname", "interface", "port" };

    if (!webd_audit_row_any_contains(row, q ? q->q : "", search_keys,
                                     (int)(sizeof(search_keys) / sizeof(search_keys[0]))))
        return 0;
    if (q && q->action[0] && !webd_audit_row_field_contains(row, q->action, action_keys,
                                                            (int)(sizeof(action_keys) / sizeof(action_keys[0]))))
        return 0;
    if (q && q->ifname[0] && !webd_audit_row_field_contains(row, q->ifname, if_keys,
                                                            (int)(sizeof(if_keys) / sizeof(if_keys[0]))))
        return 0;
    if (q && q->exclude_action[0] && webd_audit_row_field_contains(row, q->exclude_action, action_keys,
                                                                    (int)(sizeof(action_keys) / sizeof(action_keys[0]))))
        return 0;
    if (q && q->exclude_ifname[0] && webd_audit_row_field_contains(row, q->exclude_ifname, if_keys,
                                                                   (int)(sizeof(if_keys) / sizeof(if_keys[0]))))
        return 0;
    return 1;
}

static int webd_audit_im_match(struct json_object *row, const struct webd_audit_bff_query *q)
{
    static const char *search_keys[] = {
        "client", "client_name", "hostname", "device", "name", "app", "application", "app_name",
        "account", "user", "username", "state", "status", "ip", "mac", "device_type", "os",
        "last_domain", "domain", "host", "evidence", "reason"
    };
    static const char *app_keys[] = { "app", "application", "app_name", "name" };
    static const char *state_keys[] = { "state", "status" };

    if (!webd_audit_row_any_contains(row, q ? q->q : "", search_keys,
                                     (int)(sizeof(search_keys) / sizeof(search_keys[0]))))
        return 0;
    if (q && q->app[0] && !webd_audit_row_field_contains(row, q->app, app_keys,
                                                         (int)(sizeof(app_keys) / sizeof(app_keys[0]))))
        return 0;
    if (q && q->state[0] && !webd_audit_row_field_contains(row, q->state, state_keys,
                                                           (int)(sizeof(state_keys) / sizeof(state_keys[0]))))
        return 0;
    if (q && q->exclude_app[0] && webd_audit_row_field_contains(row, q->exclude_app, app_keys,
                                                                 (int)(sizeof(app_keys) / sizeof(app_keys[0]))))
        return 0;
    if (q && q->exclude_state[0] && webd_audit_row_field_contains(row, q->exclude_state, state_keys,
                                                                   (int)(sizeof(state_keys) / sizeof(state_keys[0]))))
        return 0;
    return 1;
}

static int webd_audit_entity_match(struct json_object *row, const struct webd_audit_bff_query *q)
{
    static const char *search_keys[] = {
        "id", "key", "name", "display_name", "app", "app_name", "application_name",
        "protocol", "service", "type", "category", "subcategory", "family", "evidence",
        "domain", "host", "domains", "ports", "wan", "ifname", "source"
    };
    static const char *category_keys[] = { "category", "type", "subcategory", "family" };

    if (!webd_audit_row_any_contains(row, q ? q->q : "", search_keys,
                                     (int)(sizeof(search_keys) / sizeof(search_keys[0]))))
        return 0;
    if (q && q->category[0] && !webd_audit_row_field_contains(row, q->category, category_keys,
                                                              (int)(sizeof(category_keys) / sizeof(category_keys[0]))))
        return 0;
    if (q && q->exclude_category[0] && webd_audit_row_field_contains(row, q->exclude_category, category_keys,
                                                                      (int)(sizeof(category_keys) / sizeof(category_keys[0]))))
        return 0;
    return 1;
}

static int webd_audit_traffic_match(struct json_object *row, const struct webd_audit_bff_query *q)
{
    static const char *search_keys[] = {
        "terminal", "name", "display_name", "client", "client_name", "ip", "mac",
        "account", "last_seen", "source"
    };

    return webd_audit_row_any_contains(row, q ? q->q : "", search_keys,
                                       (int)(sizeof(search_keys) / sizeof(search_keys[0])));
}

static int webd_audit_entity_unknown(struct json_object *row)
{
    const char *name;

    if (!row)
        return 0;
    if (app_nc_json_bool(row, "unknown", 0) || app_nc_json_bool(row, "app_unresolved", 0))
        return 1;
    if (app_nc_json_int(row, "app_id", app_nc_json_int(row, "appid", 0)) == 0 &&
        app_nc_json_int(row, "canonical_app_id", 0) == 0)
        return 1;
    name = webd_first_nonempty4(app_nc_json_str(row, "name", ""),
                                app_nc_json_str(row, "app_name", ""),
                                app_nc_json_str(row, "application_name", ""),
                                app_nc_json_str(row, "display_name", ""));
    return webd_str_contains_i(name, "unknown") || webd_str_contains_i(name, "未知");
}

static void webd_audit_entity_add_aliases(struct json_object *row)
{
    int64_t count;
    int64_t bytes;
    const char *service;

    if (!row)
        return;
    count = app_nc_json_int64(row, "connections",
            app_nc_json_int64(row, "flow_count", app_nc_json_int64(row, "count", app_nc_json_int64(row, "hit_count", 0))));
    bytes = app_nc_json_int64(row, "bytes", app_nc_json_int64(row, "total_bytes",
            app_nc_json_int64(row, "up_bytes", app_nc_json_int64(row, "tx_bytes", app_nc_json_int64(row, "upload_bytes", 0))) +
            app_nc_json_int64(row, "down_bytes", app_nc_json_int64(row, "rx_bytes", app_nc_json_int64(row, "download_bytes", 0)))));
    service = app_nc_json_str(row, "service", "");
    if (!app_nc_json_has(row, "connections"))
        json_object_object_add(row, "connections", json_object_new_int64(count));
    if (!app_nc_json_has(row, "bytes"))
        json_object_object_add(row, "bytes", json_object_new_int64(bytes));
    if (!app_nc_json_has(row, "total_bytes"))
        json_object_object_add(row, "total_bytes", json_object_new_int64(bytes));
    if (!app_nc_json_has(row, "clients"))
        json_object_object_add(row, "clients", json_object_new_int(app_nc_json_int(row, "client_count", 0)));
    if (!app_nc_json_has(row, "up_rate"))
        json_object_object_add(row, "up_rate", json_object_new_int64(0));
    if (!app_nc_json_has(row, "down_rate"))
        json_object_object_add(row, "down_rate", json_object_new_int64(0));
    if (!app_nc_json_has(row, "evidence"))
        webd_obj_add_str(row, "evidence", webd_first_nonempty4(app_nc_json_str(row, "semantic", ""),
                         app_nc_json_str(row, "name_source", ""), app_nc_json_str(row, "source", ""), ""));
    if (service[0] && !app_nc_json_has(row, "ports"))
        webd_obj_add_str(row, "ports", service);
    if (!app_nc_json_has(row, "rate_supported"))
        json_object_object_add(row, "rate_supported", json_object_new_boolean(0));
}

static struct json_object *webd_audit_paginate_array(struct json_object *src,
                                                     const struct webd_audit_bff_query *q,
                                                     int (*match)(struct json_object *, const struct webd_audit_bff_query *),
                                                     int unknown_first,
                                                     int *total_out)
{
    struct json_object *arr = json_object_new_array();
    struct json_object *unknown = NULL;
    int total = 0;
    int emitted = 0;
    int i, n;

    if (unknown_first)
        unknown = json_object_new_array();
    if (!src || !json_object_is_type(src, json_type_array)) {
        if (total_out) *total_out = 0;
        if (unknown) json_object_put(unknown);
        return arr;
    }
    n = (int)json_object_array_length(src);
    for (i = 0; i < n; i++) {
        struct json_object *row = json_object_array_get_idx(src, i);
        int is_unknown;

        if (match && !match(row, q))
            continue;
        total++;
        if (total <= (q ? q->offset : 0))
            continue;
        if (emitted >= (q ? q->page_size : 50))
            continue;
        webd_audit_entity_add_aliases(row);
        is_unknown = unknown_first && webd_audit_entity_unknown(row);
        if (is_unknown)
            json_object_array_add(unknown, json_object_get(row));
        else
            json_object_array_add(arr, json_object_get(row));
        emitted++;
    }
    if (unknown_first && unknown) {
        struct json_object *merged = json_object_new_array();
        int un = (int)json_object_array_length(unknown);
        int an = (int)json_object_array_length(arr);
        for (i = 0; i < un; i++)
            json_object_array_add(merged, json_object_get(json_object_array_get_idx(unknown, i)));
        for (i = 0; i < an; i++)
            json_object_array_add(merged, json_object_get(json_object_array_get_idx(arr, i)));
        json_object_put(unknown);
        json_object_put(arr);
        arr = merged;
    }
    if (total_out)
        *total_out = total;
    return arr;
}

static void webd_audit_add_page_meta(struct json_object *data,
                                     const struct webd_audit_bff_query *q,
                                     int total, int returned,
                                     const char *source)
{
    if (!data)
        return;
    json_object_object_add(data, "total", json_object_new_int(total));
    json_object_object_add(data, "total_count", json_object_new_int(total));
    json_object_object_add(data, "count", json_object_new_int(total));
    json_object_object_add(data, "returned", json_object_new_int(returned));
    json_object_object_add(data, "page", json_object_new_int(q ? q->page : 0));
    json_object_object_add(data, "pageNumber", json_object_new_int(q ? q->page_number : 1));
    json_object_object_add(data, "pageSize", json_object_new_int(q ? q->page_size : 50));
    json_object_object_add(data, "offset", json_object_new_int(q ? q->offset : 0));
    json_object_object_add(data, "has_more", json_object_new_boolean(q ? ((q->offset + returned) < total) : 0));
    json_object_object_add(data, "timestampFrom", json_object_new_int64(q ? q->ts_from : 0));
    json_object_object_add(data, "timestampTo", json_object_new_int64(q ? q->ts_to : 0));
    json_object_object_add(data, "ts_from", json_object_new_int64(q ? q->ts_from : 0));
    json_object_object_add(data, "ts_to", json_object_new_int64(q ? q->ts_to : 0));
    webd_obj_add_str(data, "source", source ? source : "webd.audit_bff");
}

static struct json_object *webd_audit_status_response(const struct http_req *req,
                                                      struct json_object *body,
                                                      int *http_status)
{
    struct json_object *status = webd_audit_fetch_status();
    struct json_object *view = webd_audit_fetch_view();
    struct json_object *url = webd_obj_child_obj(view, "url_audit");
    struct json_object *im_rows = webd_obj_child_array(view, "im_records");
    struct json_object *data = json_object_new_object();
    int im_supported = webd_audit_view_im_supported(view);
    int url_rows = webd_audit_status_table_rows(status, "audit_url_event");
    int protocol_rows = webd_audit_status_table_rows(status, "audit_protocol_snapshot");
    int flow_rows = webd_audit_status_table_rows(status, "audit_flow_sample") +
                    webd_audit_status_table_rows(status, "audit_flow_lifecycle");

    (void)req;
    (void)body;
    if (http_status)
        *http_status = 200;
    json_object_object_add(data, "enabled", json_object_new_boolean(url ? app_nc_json_bool(url, "enabled", 1) : 1));
    webd_obj_add_str(data, "status", url ? app_nc_json_str(url, "status", "ok") : (status ? "ok" : "source_unavailable"));
    webd_obj_add_str(data, "mode", url ? app_nc_json_str(url, "mode", "dedup") : "dedup");
    json_object_object_add(data, "retention_days", json_object_new_int(url ? app_nc_json_int(url, "retention_days", 0) : 0));
    webd_obj_add_str(data, "storage", url ? app_nc_json_str(url, "storage", app_nc_json_str(status, "db_path", "")) : app_nc_json_str(status, "db_path", ""));
    json_object_object_add(data, "max_rows", json_object_new_int(url ? app_nc_json_int(url, "max_rows", app_nc_json_int(status, "url_max_rows", 0)) : app_nc_json_int(status, "url_max_rows", 0)));
    json_object_object_add(data, "db_size_bytes", json_object_new_int64(app_nc_json_int64(status, "db_size_bytes", url ? app_nc_json_int64(url, "db_size_bytes", 0) : 0)));
    json_object_object_add(data, "wal_size_bytes", json_object_new_int64(app_nc_json_int64(status, "wal_size_bytes", 0)));
    json_object_object_add(data, "queue_depth", json_object_new_int(url ? app_nc_json_int(url, "queue_depth", 0) : 0));
    json_object_object_add(data, "dropped_events", json_object_new_int64(app_nc_json_int64(status, "dropped_events", url ? app_nc_json_int64(url, "dropped_events", 0) : 0)));
    json_object_object_add(data, "last_flush_at", json_object_new_int64(url ? app_nc_json_int64(url, "last_flush_at", app_nc_json_int64(status, "ts", 0)) : app_nc_json_int64(status, "ts", 0)));
    json_object_object_add(data, "url_row_count", json_object_new_int(url_rows));
    json_object_object_add(data, "flow_sample_row_count", json_object_new_int(webd_audit_status_table_rows(status, "audit_flow_sample")));
    json_object_object_add(data, "flow_lifecycle_row_count", json_object_new_int(webd_audit_status_table_rows(status, "audit_flow_lifecycle")));
    json_object_object_add(data, "protocol_snapshot_row_count", json_object_new_int(protocol_rows));
    json_object_object_add(data, "app_usage_bucket_row_count", json_object_new_int(webd_audit_status_table_rows(status, "audit_client_app_usage_bucket")));
    if (status && webd_obj_child_array(status, "tables"))
        json_object_object_add(data, "tables", json_object_get(webd_obj_child_array(status, "tables")));
    if (status && webd_obj_child_obj(status, "worker"))
        json_object_object_add(data, "worker", json_object_get(webd_obj_child_obj(status, "worker")));
    webd_audit_add_caps(data,
                         webd_audit_status_has_table(status, "audit_url_event"),
                         webd_audit_status_has_table(status, "audit_protocol_snapshot"),
                         flow_rows > 0, 0, im_supported, 1);
    json_object_object_add(data, "url_persistent_records_present",
                           json_object_new_boolean(url_rows > 0));
    json_object_object_add(data, "protocol_snapshot_records_present",
                           json_object_new_boolean(protocol_rows > 0));
    /*
     * Mirror the im-records endpoint so a consumer reading either one gets the
     * same answer.  records_present is deliberately separate from supported:
     * a live collector with nobody on an IM app is supported with no rows.
     */
    json_object_object_add(data, "im_records_supported",
                           json_object_new_boolean(im_supported > 0));
    json_object_object_add(data, "im_records_present",
                           json_object_new_boolean(im_rows &&
                                                  json_object_array_length(im_rows) > 0));
    webd_obj_add_str(data, "source", "jmxd.audit_status+audit_view");
    if (!status) {
        json_object_object_add(data, "degraded", json_object_new_boolean(1));
        webd_obj_add_str(data, "reason", "audit_status_unavailable_using_runtime_defaults");
    }
    if (view)
        json_object_put(view);
    if (status)
        json_object_put(status);
    return webd_envelope(data, "webd.audit.status_bff");
}

static struct json_object *webd_audit_domains_from_records(struct json_object *records,
                                                          const struct webd_audit_bff_query *q,
                                                          int *total_out)
{
    struct json_object *domains = json_object_new_array();
    int n = records && json_object_is_type(records, json_type_array) ?
        (int)json_object_array_length(records) : 0;

    if (total_out)
        *total_out = 0;
    for (int i = 0; i < n; i++) {
        struct json_object *row = json_object_array_get_idx(records, i);
        const char *host = app_nc_json_str(row, "host", app_nc_json_str(row, "sni", ""));
        struct json_object *found = NULL;
        int dn = (int)json_object_array_length(domains);

        if (!host || !host[0])
            continue;
        for (int j = 0; j < dn; j++) {
            struct json_object *d = json_object_array_get_idx(domains, j);
            if (!strcasecmp(app_nc_json_str(d, "host", ""), host)) {
                found = d;
                break;
            }
        }
        if (!found) {
            found = json_object_new_object();
            webd_obj_add_str(found, "host", host);
            webd_obj_add_str(found, "url", app_nc_json_str(row, "url", ""));
            webd_obj_add_str(found, "app", app_nc_json_str(row, "app_name", ""));
            webd_obj_add_str(found, "app_name", app_nc_json_str(row, "app_name", ""));
            if (app_nc_json_int(row, "app_id", app_nc_json_int(row, "appid", 0)) > 0) {
                json_object_object_add(found, "app_id", json_object_new_int(app_nc_json_int(row, "app_id", app_nc_json_int(row, "appid", 0))));
                json_object_object_add(found, "appid", json_object_new_int(app_nc_json_int(row, "app_id", app_nc_json_int(row, "appid", 0))));
            }
            webd_obj_add_str(found, "category", app_nc_json_str(row, "category", ""));
            webd_obj_add_str(found, "action", app_nc_json_str(row, "action", "allow"));
            webd_obj_add_str(found, "wan", app_nc_json_str(row, "wan", ""));
            webd_obj_add_str(found, "evidence", app_nc_json_str(row, "evidence", ""));
            json_object_object_add(found, "clients", json_object_new_int(0));
            json_object_object_add(found, "hits", json_object_new_int(0));
            json_object_object_add(found, "hit_count", json_object_new_int(0));
            json_object_object_add(found, "up_bytes", json_object_new_int64(0));
            json_object_object_add(found, "down_bytes", json_object_new_int64(0));
            json_object_object_add(found, "first_seen", json_object_new_int64(app_nc_json_int64(row, "ts", 0)));
            json_object_object_add(found, "last_seen", json_object_new_int64(app_nc_json_int64(row, "ts", 0)));
            json_object_object_add(found, "_client_keys", json_object_new_array());
            json_object_array_add(domains, found);
        }
        {
            int64_t ts = app_nc_json_int64(row, "ts", 0);
            int64_t first = app_nc_json_int64(found, "first_seen", ts);
            int64_t last = app_nc_json_int64(found, "last_seen", ts);
            int hits = app_nc_json_int(found, "hits", 0) + app_nc_json_int(row, "hit_count", 1);
            int64_t up = app_nc_json_int64(found, "up_bytes", 0) + app_nc_json_int64(row, "up_bytes", 0);
            int64_t down = app_nc_json_int64(found, "down_bytes", 0) + app_nc_json_int64(row, "down_bytes", 0);
            struct json_object *clients = webd_obj_child_array(found, "_client_keys");
            const char *ck = app_nc_json_str(row, "mac", app_nc_json_str(row, "ip", ""));
            int seen = 0;

            json_object_object_del(found, "hits");
            json_object_object_add(found, "hits", json_object_new_int(hits));
            json_object_object_del(found, "hit_count");
            json_object_object_add(found, "hit_count", json_object_new_int(hits));
            json_object_object_del(found, "up_bytes");
            json_object_object_add(found, "up_bytes", json_object_new_int64(up));
            json_object_object_del(found, "down_bytes");
            json_object_object_add(found, "down_bytes", json_object_new_int64(down));
            if (ts > 0 && (first <= 0 || ts < first)) {
                json_object_object_del(found, "first_seen");
                json_object_object_add(found, "first_seen", json_object_new_int64(ts));
            }
            if (ts > last) {
                json_object_object_del(found, "last_seen");
                json_object_object_add(found, "last_seen", json_object_new_int64(ts));
            }
            if (clients && ck && ck[0]) {
                int cn = (int)json_object_array_length(clients);
                for (int k = 0; k < cn; k++) {
                    const char *old = json_object_get_string(json_object_array_get_idx(clients, k));
                    if (old && !strcasecmp(old, ck)) {
                        seen = 1;
                        break;
                    }
                }
                if (!seen) {
                    json_object_array_add(clients, json_object_new_string(ck));
                    json_object_object_del(found, "clients");
                    json_object_object_add(found, "clients", json_object_new_int(json_object_array_length(clients)));
                }
            }
        }
    }
    for (int i = 0; i < (int)json_object_array_length(domains); i++) {
        struct json_object *d = json_object_array_get_idx(domains, i);
        json_object_object_del(d, "_client_keys");
    }
    if (total_out)
        *total_out = (int)json_object_array_length(domains);
    return webd_audit_paginate_array(domains, q, webd_audit_url_record_match, 0, total_out);
}

static struct json_object *webd_audit_urls_response(const struct http_req *req,
                                                    struct json_object *body,
                                                    int *http_status)
{
    struct webd_audit_bff_query q;
    struct json_object *persistent = NULL;
    struct json_object *view = NULL;
    struct json_object *source_url = NULL;
    struct json_object *src_records = NULL;
    struct json_object *src_domains = NULL;
    struct json_object *records = NULL;
    struct json_object *domains = NULL;
    struct json_object *url_audit = json_object_new_object();
    struct json_object *data = json_object_new_object();
    int total_records = 0;
    int total_domains = 0;
    int persistent_total = 0;
    int use_persistent = 0;
    const char *source = "audit_view.url_audit.runtime_fallback";

    if (http_status)
        *http_status = 200;
    webd_audit_read_query(req, body, &q);
    {
        struct json_object *params = json_object_new_object();
        int fetch_limit = !strcasecmp(q.mode, "domains") ? 1000 : q.page_size;
        json_object_object_add(params, "limit", json_object_new_int(fetch_limit));
        json_object_object_add(params, "pageSize", json_object_new_int(fetch_limit));
        json_object_object_add(params, "pageNumber", json_object_new_int(!strcasecmp(q.mode, "domains") ? 1 : q.page_number));
        json_object_object_add(params, "ts_from", json_object_new_int64(q.ts_from));
        json_object_object_add(params, "ts_to", json_object_new_int64(q.ts_to));
        if (q.q[0]) json_object_object_add(params, "search_text", json_object_new_string(q.q));
        if (q.action[0]) json_object_object_add(params, "action", json_object_new_string(q.action));
        persistent = webd_insights_ubus_data_timeout("audit_urls", params, 2200);
        json_object_put(params);
    }
    if (persistent) {
        src_records = webd_obj_child_array(persistent, "urls");
        persistent_total = app_nc_json_int(persistent, "total", src_records ? (int)json_object_array_length(src_records) : 0);
        if (src_records) {
            use_persistent = 1;
            source = !strcasecmp(q.mode, "domains") ?
                "jmxd.audit_urls.audit_url_event.domain_aggregate" :
                "jmxd.audit_urls.audit_url_event";
        }
    }
    if (!use_persistent) {
        view = webd_audit_fetch_view();
        source_url = webd_obj_child_obj(view, "url_audit");
        if (source_url) {
            src_records = webd_obj_child_array(source_url, "records");
            src_domains = webd_obj_child_array(source_url, "domains");
            if (webd_obj_child_array(source_url, "categories"))
                json_object_object_add(url_audit, "categories", json_object_get(webd_obj_child_array(source_url, "categories")));
        }
    }
    /*
     * On the persistent path jmxd has already applied both the filters and the
     * page offset, so the match callback is dropped and the offset is zeroed on
     * a local copy. The query itself must still be passed: this function falls
     * back to a hardcoded page size of 50 when q is NULL, which silently
     * re-truncated every reply to 50 rows regardless of the requested page size.
     * Requests below 50 looked correct only because jmxd had already returned
     * fewer rows than that cap.
     *
     * Zeroing the offset matters as much as the size: applying it a second time
     * over an already-paged slice would skip page_size rows within the page and
     * return an empty tail for every page after the first.
     */
    {
        struct webd_audit_bff_query pq = q;

        if (use_persistent)
            pq.offset = 0;
        records = webd_audit_paginate_array(src_records, &pq,
                                           use_persistent ? NULL : webd_audit_url_record_match,
                                           0, &total_records);
    }
    if (use_persistent) {
        total_records = persistent_total;
        if (q.category[0] || q.q[0] || q.action[0]) {
            /*
             * Same offset hazard as above: "records" is already the requested
             * page, so re-applying q.offset here would drop the whole slice for
             * any page past the first. Only the residual filtering is wanted.
             */
            struct webd_audit_bff_query fq = q;
            struct json_object *filtered;

            fq.offset = 0;
            filtered = webd_audit_paginate_array(records, &fq,
                                                 webd_audit_url_record_match, 0,
                                                 &total_records);
            json_object_put(records);
            records = filtered;
        }
    }
    if (use_persistent)
        domains = webd_audit_domains_from_records(src_records, &q, &total_domains);
    else if (src_domains)
        domains = webd_audit_paginate_array(src_domains, &q, webd_audit_url_record_match, 0, &total_domains);
    else
        domains = json_object_new_array();

    json_object_object_add(url_audit, "enabled", json_object_new_boolean(1));
    webd_obj_add_str(url_audit, "status", "ok");
    webd_obj_add_str(url_audit, "mode", q.mode[0] ? q.mode : "records");
    json_object_object_add(url_audit, "records", json_object_get(records));
    json_object_object_add(url_audit, "urls", json_object_get(records));
    json_object_object_add(url_audit, "domains", json_object_get(domains));
    webd_audit_add_page_meta(url_audit, &q,
                             !strcasecmp(q.mode, "domains") ? total_domains : total_records,
                             !strcasecmp(q.mode, "domains") ? (int)json_object_array_length(domains) : (int)json_object_array_length(records),
                             source);
    json_object_object_add(data, "url_audit", json_object_get(url_audit));
    json_object_object_add(data, "records", records);
    json_object_object_add(data, "urls", json_object_get(webd_obj_child_array(url_audit, "urls")));
    json_object_object_add(data, "domains", domains);
    webd_audit_add_page_meta(data, &q,
                             !strcasecmp(q.mode, "domains") ? total_domains : total_records,
                             !strcasecmp(q.mode, "domains") ? (int)json_object_array_length(webd_obj_child_array(data, "domains")) : (int)json_object_array_length(webd_obj_child_array(data, "records")),
                             source);
    if (!use_persistent) {
        json_object_object_add(data, "degraded", json_object_new_boolean(1));
        json_object_object_add(url_audit, "degraded", json_object_new_boolean(1));
        webd_obj_add_str(data, "reason", "audit_url_event_empty_or_unavailable_using_audit_view_runtime_fallback");
        webd_obj_add_str(url_audit, "reason", "audit_url_event_empty_or_unavailable_using_audit_view_runtime_fallback");
        json_object_object_add(data, "persistent", json_object_new_boolean(0));
    } else {
        json_object_object_add(data, "persistent", json_object_new_boolean(1));
    }
    webd_audit_add_caps(data, use_persistent, -1, 0, 0,
                         webd_audit_view_im_supported(view), 1);
    json_object_object_add(data, "url_persistent_records_present",
                           json_object_new_boolean(total_records > 0));
    json_object_put(url_audit);
    if (persistent) json_object_put(persistent);
    if (view) json_object_put(view);
    return webd_envelope(data, "webd.audit.urls_bff");
}

static struct json_object *webd_audit_online_records_response(const struct http_req *req,
                                                              struct json_object *body,
                                                              int *http_status)
{
    struct webd_audit_bff_query q;
    struct json_object *view;
    struct json_object *src;
    struct json_object *rows;
    struct json_object *data = json_object_new_object();
    int total = 0;

    if (http_status)
        *http_status = 200;
    webd_audit_read_query(req, body, &q);
    view = webd_audit_fetch_view();
    src = webd_obj_child_array(view, "online_records");
    rows = webd_audit_paginate_array(src, &q, webd_audit_online_match, 0, &total);
    json_object_object_add(data, "online_records", json_object_get(rows));
    json_object_object_add(data, "records", json_object_get(rows));
    json_object_object_add(data, "items", rows);
    {
        /* Read online_records_historical from core view to decide degradation */
        int has_history = view ? app_nc_json_bool(view, "online_records_historical", 0) : 0;
        webd_audit_add_page_meta(data, &q, total, (int)json_object_array_length(webd_obj_child_array(data, "online_records")),
                                 has_history ? "audit_view.online_records.historical"
                                             : "audit_view.online_records.runtime_client_list");
        json_object_object_add(data, "historical_exact", json_object_new_boolean(has_history));
        json_object_object_add(data, "degraded", json_object_new_boolean(!has_history));
        if (!has_history)
            webd_obj_add_str(data, "reason",
                             "runtime_client_list_only; dhcp/arp/wifi online event journal pending");
        webd_audit_add_caps(data, -1, -1, 0, has_history,
                             webd_audit_view_im_supported(view), 1);
    }
    if (view) json_object_put(view);
    return webd_envelope(data, "webd.audit.online_records_bff");
}

static struct json_object *webd_audit_im_records_response(const struct http_req *req,
                                                          struct json_object *body,
                                                          int *http_status)
{
    struct webd_audit_bff_query q;
    struct json_object *upstream;
    struct json_object *view;
    struct json_object *src;
    struct json_object *rows;
    struct json_object *data = json_object_new_object();
    int supported = 0;
    int total = 0;

    if (http_status)
        *http_status = 200;
    webd_audit_read_query(req, body, &q);
    upstream = webd_insights_ubus_response_timeout("audit_view", NULL, 1800);
    if (!upstream) {
        if (http_status)
            *http_status = 503;
        return webd_error("source_unavailable",
                          "audit IM presence source is unavailable",
                          "dreamingwrt audit_view",
                          "webd.audit.im_records_bff");
    }
    if (!app_ubus_response_ok(upstream)) {
        if (http_status)
            *http_status = app_response_status(upstream, 503);
        return upstream;
    }
    view = webd_data_or_self_from_jmx_response(upstream);
    json_object_put(upstream);
    if (!view || !json_object_is_type(view, json_type_object)) {
        if (view)
            json_object_put(view);
        if (http_status)
            *http_status = 503;
        return webd_error("source_unavailable",
                          "audit IM presence source returned no usable data",
                          "dreamingwrt audit_view.data",
                          "webd.audit.im_records_bff");
    }
    src = webd_obj_child_array(view, "im_records");
    rows = webd_audit_paginate_array(src, &q, webd_audit_im_match, 0, &total);
    supported = webd_audit_view_im_supported(view) > 0;
    json_object_object_add(data, "im_records", json_object_get(rows));
    json_object_object_add(data, "records", json_object_get(rows));
    json_object_object_add(data, "items", rows);
    webd_audit_add_page_meta(data, &q, total, (int)json_object_array_length(webd_obj_child_array(data, "im_records")),
                             "audit_view.im_records");
    json_object_object_add(data, "im_records_supported", json_object_new_boolean(supported));
    json_object_object_add(data, "records_present", json_object_new_boolean(total > 0));
    /*
     * Presence lives in jmxd memory and there is no im_event journal yet, so
     * history does not survive a restart -- but a working live collector is not
     * "degraded".  Only a collector that could not read its sources is.
     */
    json_object_object_add(data, "persistent", json_object_new_boolean(0));
    json_object_object_add(data, "accounts_supported", json_object_new_boolean(0));
    json_object_object_add(data, "degraded", json_object_new_boolean(!supported));
    webd_obj_add_str(data, "reason", supported ?
                     "live_presence_from_dpi_appid_chat_category; accounts and login/logout journal not implemented" :
                     "im_presence_source_unavailable_af_active_app_af_active_host_unreadable");
    webd_audit_add_caps(data, 0, 0, 0, 0, supported, 1);
    if (view) json_object_put(view);
    return webd_envelope(data, "webd.audit.im_records_bff");
}

static struct json_object *webd_audit_traffic_response(const struct http_req *req,
                                                       struct json_object *body,
                                                       int *http_status)
{
    struct webd_audit_bff_query q;
    struct json_object *view;
    struct json_object *traffic;
    struct json_object *src = NULL;
    struct json_object *rows;
    struct json_object *data = json_object_new_object();
    int total = 0;

    if (http_status)
        *http_status = 200;
    webd_audit_read_query(req, body, &q);
    if (!q.mode[0])
        snprintf(q.mode, sizeof(q.mode), "%s", "mac");
    view = webd_audit_fetch_view();
    traffic = webd_obj_child_obj(view, "traffic_audit");
    if (traffic)
        src = webd_obj_child_array(traffic, !strcasecmp(q.mode, "account") || !strcasecmp(q.mode, "accounts") ? "accounts" : "mac");
    rows = webd_audit_paginate_array(src, &q, webd_audit_traffic_match, 0, &total);
    json_object_object_add(data, "traffic", json_object_get(rows));
    json_object_object_add(data, "records", json_object_get(rows));
    json_object_object_add(data, "items", rows);
    webd_obj_add_str(data, "mode", !strcasecmp(q.mode, "account") || !strcasecmp(q.mode, "accounts") ? "account" : "mac");
    webd_audit_add_page_meta(data, &q, total, (int)json_object_array_length(webd_obj_child_array(data, "traffic")),
                             "audit_view.traffic_audit.runtime_client_traffic");
    json_object_object_add(data, "historical_exact", json_object_new_boolean(0));
    json_object_object_add(data, "degraded", json_object_new_boolean(1));
    webd_obj_add_str(data, "reason", "runtime_client_traffic_only; audit_traffic_day ledger pending");
    webd_audit_add_caps(data, -1, -1, 0, 0,
                         webd_audit_view_im_supported(view), 0);
    if (view) json_object_put(view);
    return webd_envelope(data, "webd.audit.traffic_bff");
}

static int webd_audit_flow_summary_has_items(struct json_object *summary)
{
    struct json_object *items = webd_obj_child_array(summary, "items");

    return items && json_object_array_length(items) > 0;
}

static const char *webd_audit_flow_summary_mode(const struct webd_audit_bff_query *q)
{
    const char *mode = q ? q->mode : "";

    if (mode && (!strcasecmp(mode, "sample") ||
                 !strcasecmp(mode, "lifecycle") ||
                 !strcasecmp(mode, "flow_lifecycle") ||
                 !strcasecmp(mode, "event_lifecycle") ||
                 !strcasecmp(mode, "flow_event_lifecycle") ||
                 !strcasecmp(mode, "ctnetlink_lifecycle") ||
                 !strcasecmp(mode, "exact_lifecycle")))
        return mode;

    /*
     * The standalone audit BFF backs the LuCI Advanced Audit compatible
     * Applications/Protocols tabs.  The runtime protocol snapshot can be empty
     * while audit_flow_event_lifecycle already has exact completed-flow rows, so
     * default these summaries to the ctnetlink DESTROY lifecycle ledger and only
     * fall back to the sampled summary when the exact ledger is unavailable.
     */
    return "event_lifecycle";
}

static struct json_object *webd_audit_flow_summary_rows(const struct webd_audit_bff_query *q,
                                                        int top)
{
    struct webd_insights_query iq;
    struct json_object *summary;
    const char *mode;

    memset(&iq, 0, sizeof(iq));
    snprintf(iq.period, sizeof(iq.period), "%s", "day");
    mode = webd_audit_flow_summary_mode(q);
    if (mode && mode[0])
        snprintf(iq.mode, sizeof(iq.mode), "%s", mode);
    if (q) {
        iq.ts_from = q->ts_from;
        iq.ts_to = q->ts_to;
        iq.page_number = 1;
        iq.page_size = top;
        iq.top = top;
        snprintf(iq.search, sizeof(iq.search), "%s", q->q);
    } else {
        iq.ts_to = now_s();
        iq.ts_from = iq.ts_to - 86400;
        iq.top = top;
        iq.page_size = top;
        iq.page_number = 1;
    }

    summary = webd_insights_fetch_flow_app_summary(&iq, top);
    if (summary && webd_audit_flow_summary_has_items(summary))
        return summary;

    if (summary && q && q->mode[0] && strcasecmp(q->mode, "records") &&
        strcasecmp(q->mode, "apps") && strcasecmp(q->mode, "protocols"))
        return summary;

    if (summary)
        json_object_put(summary);

    memset(iq.mode, 0, sizeof(iq.mode));
    summary = webd_insights_fetch_flow_app_summary(&iq, top);
    if (summary) {
        json_object_object_add(summary, "fallback_from", json_object_new_string(mode && mode[0] ? mode : "event_lifecycle"));
        json_object_object_add(summary, "fallback_reason", json_object_new_string("event_lifecycle_summary_empty_or_unavailable"));
    }
    return summary;
}

static struct json_object *webd_audit_protocols_response(const struct http_req *req,
                                                         struct json_object *body,
                                                         int *http_status)
{
    struct webd_audit_bff_query q;
    struct json_object *view;
    struct json_object *status;
    struct json_object *src;
    struct json_object *flow_summary = NULL;
    struct json_object *rows;
    struct json_object *data = json_object_new_object();
    struct json_object *proto_src = NULL;
    int total = 0;
    int flow_fallback = 0;
    int protocol_source_available = 0;

    if (http_status)
        *http_status = 200;
    webd_audit_read_query(req, body, &q);
    status = webd_audit_fetch_status();
    protocol_source_available =
        webd_audit_status_has_table(status, "audit_protocol_snapshot");
    view = webd_audit_fetch_view();
    src = webd_obj_child_array(view, "protocols");
    if (!src || json_object_array_length(src) == 0) {
        flow_summary = webd_audit_flow_summary_rows(&q, 500);
        src = webd_obj_child_array(flow_summary, "items");
        flow_fallback = src != NULL;
    }
    proto_src = json_object_new_array();
    if (src) {
        int i, n = (int)json_object_array_length(src);
        for (i = 0; i < n; i++) {
            struct json_object *row = json_object_array_get_idx(src, i);
            const char *name_source = app_nc_json_str(row, "name_source", "");
            int app_id = app_nc_json_int(row, "app_id", app_nc_json_int(row, "appid", 0));
            if (flow_fallback && app_id > 0 && !webd_str_contains_i(name_source, "service"))
                continue;
            webd_audit_entity_add_aliases(row);
            if (!app_nc_json_has(row, "name") && app_nc_json_str(row, "service", "")[0])
                webd_obj_add_str(row, "name", app_nc_json_str(row, "service", ""));
            if (!app_nc_json_has(row, "type"))
                webd_obj_add_str(row, "type", app_nc_json_str(row, "protocol", "protocol"));
            json_object_array_add(proto_src, json_object_get(row));
        }
    }
    rows = webd_audit_paginate_array(proto_src, &q, webd_audit_entity_match, 0, &total);
    json_object_object_add(data, "protocols", json_object_get(rows));
    json_object_object_add(data, "records", json_object_get(rows));
    json_object_object_add(data, "items", rows);
    webd_audit_add_page_meta(data, &q, total, (int)json_object_array_length(webd_obj_child_array(data, "protocols")),
                             flow_fallback ? "jmxd.audit_flow_app_summary.service_fallback" : "audit_view.protocols");
    json_object_object_add(data, "protocol_snapshot_supported",
                           json_object_new_boolean(protocol_source_available));
    json_object_object_add(data, "protocol_snapshot_records_present",
                           json_object_new_boolean(!flow_fallback && total > 0));
    json_object_object_add(data, "flow_summary_fallback", json_object_new_boolean(flow_fallback));
    if (flow_fallback) {
        json_object_object_add(data, "degraded", json_object_new_boolean(1));
        webd_obj_add_str(data, "reason", "audit_protocol_snapshot_empty_using_flow_service_summary");
    }
    webd_audit_add_caps(data,
                         webd_audit_status_has_table(status, "audit_url_event"),
                         protocol_source_available, flow_fallback,
                         0, webd_audit_view_im_supported(view), 1);
    json_object_put(proto_src);
    if (flow_summary) json_object_put(flow_summary);
    if (view) json_object_put(view);
    if (status) json_object_put(status);
    return webd_envelope(data, "webd.audit.protocols_bff");
}


static void webd_path_tail_token(const char *path, const char *prefix,
                                 char *out, size_t out_len)
{
    const char *p;
    size_t i, j = 0;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!path || !prefix)
        return;
    p = path;
    if (!strncmp(path, prefix, strlen(prefix)))
        p = path + strlen(prefix);
    while (*p == '/')
        p++;
    for (i = 0; p[i] && p[i] != '?' && p[i] != '/' && j + 1 < out_len; i++) {
        if (p[i] == '%' && isxdigit((unsigned char)p[i + 1]) && isxdigit((unsigned char)p[i + 2])) {
            char hex[3] = { p[i + 1], p[i + 2], 0 };
            out[j++] = (char)strtol(hex, NULL, 16);
            i += 2;
        } else if (p[i] == '+') {
            out[j++] = ' ';
        } else {
            out[j++] = p[i];
        }
    }
    out[j] = '\0';
}

static struct json_object *webd_audit_protocol_detail_response(const struct http_req *req,
                                                               struct json_object *body,
                                                               int *http_status)
{
    char id[160] = "";
    struct json_object *params = json_object_new_object();
    struct json_object *detail;
    struct json_object *data = json_object_new_object();

    if (http_status)
        *http_status = 200;
    webd_path_tail_token(req ? req->path : "", "/api/v1/audit/protocols/", id, sizeof(id));
    if ((!id[0] || !strcmp(id, "detail")) && body)
        snprintf(id, sizeof(id), "%s", app_nc_json_str(body, "id", app_nc_json_str(body, "protocol", "")));
    if (req && req->query[0]) {
        char qid[160] = "";
        if (webd_query_get(req->query, "id", qid, sizeof(qid)) || webd_query_get(req->query, "protocol", qid, sizeof(qid)))
            snprintf(id, sizeof(id), "%s", qid);
    }
    webd_obj_add_str(data, "id", id);
    webd_obj_add_str(data, "type", "protocol");
    if (!id[0]) {
        if (http_status) *http_status = 400;
        webd_obj_add_str(data, "error", "missing_protocol_id");
        return webd_envelope(data, "webd.audit.protocol_detail_bff");
    }
    json_object_object_add(params, "id", json_object_new_string(id));
    detail = webd_insights_ubus_data_timeout("audit_protocol_detail", params, 1800);
    json_object_put(params);
    if (detail) {
        webd_json_copy_key(data, "id", detail, "id");
        webd_json_copy_key(data, "name", detail, "name");
        webd_json_copy_key(data, "type", detail, "type");
        webd_json_copy_key(data, "category", detail, "type");
        webd_json_copy_key(data, "connections", detail, "connections");
        webd_json_copy_key(data, "up_rate", detail, "up_rate");
        webd_json_copy_key(data, "down_rate", detail, "down_rate");
        webd_json_copy_key(data, "bytes", detail, "bytes");
        webd_json_copy_key(data, "client_count", detail, "client_count");
        webd_json_copy_key(data, "evidence", detail, "evidence");
        if (webd_obj_child_array(detail, "clients"))
            json_object_object_add(data, "clients", json_object_get(webd_obj_child_array(detail, "clients")));
        else
            json_object_object_add(data, "clients", json_object_new_array());
        if (webd_obj_child_array(detail, "domains"))
            json_object_object_add(data, "domains", json_object_get(webd_obj_child_array(detail, "domains")));
        else
            json_object_object_add(data, "domains", json_object_new_array());
        if (webd_obj_child_array(detail, "time_series"))
            json_object_object_add(data, "time_series", json_object_get(webd_obj_child_array(detail, "time_series")));
        else
            json_object_object_add(data, "time_series", json_object_new_array());
        if (app_nc_json_str(detail, "error", "")[0]) {
            json_object_object_add(data, "degraded", json_object_new_boolean(1));
            webd_obj_add_str(data, "reason", app_nc_json_str(detail, "error", "audit_protocol_detail_degraded"));
        }
        json_object_put(detail);
    } else {
        json_object_object_add(data, "degraded", json_object_new_boolean(1));
        webd_obj_add_str(data, "reason", "audit_protocol_detail_unavailable");
        json_object_object_add(data, "clients", json_object_new_array());
        json_object_object_add(data, "domains", json_object_new_array());
        json_object_object_add(data, "time_series", json_object_new_array());
    }
    if (!app_nc_json_str(data, "name", "")[0] &&
        app_nc_json_int64(data, "bytes", 0) <= 0 &&
        app_nc_json_int64(data, "connections", app_nc_json_int64(data, "flow_count", 0)) <= 0) {
        struct webd_audit_bff_query q;
        struct json_object *flow_summary;
        struct json_object *items;
        struct json_object *matched = json_object_new_array();
        int i, n;

        memset(&q, 0, sizeof(q));
        q.ts_to = now_s();
        q.ts_from = q.ts_to - 86400;
        q.page = 0;
        q.page_number = 1;
        q.page_size = 500;
        snprintf(q.q, sizeof(q.q), "%s", id);
        flow_summary = webd_audit_flow_summary_rows(&q, 500);
        items = webd_obj_child_array(flow_summary, "items");
        n = items ? (int)json_object_array_length(items) : 0;
        for (i = 0; i < n; i++) {
            struct json_object *row = json_object_array_get_idx(items, i);
            const char *name = webd_first_nonempty4(app_nc_json_str(row, "service", ""),
                                                    app_nc_json_str(row, "name", ""),
                                                    app_nc_json_str(row, "app_name", ""),
                                                    app_nc_json_str(row, "protocol", ""));
            if (!strcasecmp(name, id) || webd_str_contains_i(name, id) ||
                webd_str_contains_i(app_nc_json_str(row, "protocol", ""), id)) {
                webd_audit_entity_add_aliases(row);
                json_object_array_add(matched, json_object_get(row));
            }
        }
        if (json_object_array_length(matched) > 0) {
            struct json_object *first = json_object_array_get_idx(matched, 0);
            webd_obj_add_str(data, "name", webd_first_nonempty4(app_nc_json_str(first, "service", ""),
                             app_nc_json_str(first, "name", ""), app_nc_json_str(first, "app_name", ""), id));
            webd_json_copy_key(data, "protocol", first, "protocol");
            webd_json_copy_key(data, "service", first, "service");
            webd_json_copy_key(data, "connections", first, "connections");
            webd_json_copy_key(data, "flow_count", first, "flow_count");
            webd_json_copy_key(data, "bytes", first, "bytes");
            webd_json_copy_key(data, "rx_bytes", first, "rx_bytes");
            webd_json_copy_key(data, "tx_bytes", first, "tx_bytes");
            json_object_object_add(data, "records", json_object_get(matched));
            json_object_object_add(data, "items", json_object_get(matched));
            json_object_object_add(data, "summary_fallback", json_object_new_boolean(1));
            json_object_object_add(data, "degraded", json_object_new_boolean(1));
            webd_obj_add_str(data, "reason", "audit_protocol_detail_empty_using_flow_service_summary");
            webd_obj_add_str(data, "source", "jmxd.audit_flow_app_summary.service_detail_fallback");
        }
        json_object_put(matched);
        if (flow_summary) json_object_put(flow_summary);
    }
    json_object_object_add(data, "detail_supported", json_object_new_boolean(1));
    json_object_object_add(data, "domains_supported", json_object_new_boolean(json_object_array_length(webd_obj_child_array(data, "domains")) > 0));
    json_object_object_add(data, "clients_supported", json_object_new_boolean(json_object_array_length(webd_obj_child_array(data, "clients")) > 0));
    if (!app_nc_json_str(data, "source", "")[0])
        webd_obj_add_str(data, "source", "jmxd.audit_protocol_detail");
    return webd_envelope(data, "webd.audit.protocol_detail_bff");
}

static struct json_object *webd_audit_apps_response(const struct http_req *req,
                                                    struct json_object *body,
                                                    int *http_status)
{
    struct webd_audit_bff_query q;
    struct json_object *flow_summary;
    struct json_object *src;
    struct json_object *app_src = json_object_new_array();
    struct json_object *rows;
    struct json_object *data = json_object_new_object();
    int total = 0;
    int i, n;
    int unresolved_fallback_count = 0;

    if (http_status)
        *http_status = 200;
    webd_audit_read_query(req, body, &q);
    flow_summary = webd_audit_flow_summary_rows(&q, 500);
    src = webd_obj_child_array(flow_summary, "items");
    n = src ? (int)json_object_array_length(src) : 0;
    for (i = 0; i < n; i++) {
        struct json_object *row = json_object_array_get_idx(src, i);
        int app_id = app_nc_json_int(row, "app_id", app_nc_json_int(row, "appid", 0));
        const char *entity = app_nc_json_str(row, "entity_type", "");
        const char *name_source = app_nc_json_str(row, "name_source", "");

        if (app_id <= 0 && !webd_str_contains_i(entity, "app") && !webd_str_contains_i(name_source, "app")) {
            const char *fallback_name = webd_first_nonempty4(app_nc_json_str(row, "app_name", ""),
                                                             app_nc_json_str(row, "name", ""),
                                                             app_nc_json_str(row, "service", ""),
                                                             app_nc_json_str(row, "protocol", ""));
            if (!fallback_name[0])
                continue;
            unresolved_fallback_count++;
            if (!app_nc_json_has(row, "app_unresolved"))
                json_object_object_add(row, "app_unresolved", json_object_new_boolean(1));
            if (!app_nc_json_has(row, "application_identity_precision"))
                webd_obj_add_str(row, "application_identity_precision", "service_or_protocol_fallback_not_app_id");
            if (!app_nc_json_has(row, "entity_type"))
                webd_obj_add_str(row, "entity_type", "service");
            if (!app_nc_json_has(row, "category"))
                webd_obj_add_str(row, "category", "network_service");
        }
        webd_audit_entity_add_aliases(row);
        if (!app_nc_json_has(row, "app") && app_nc_json_str(row, "app_name", "")[0])
            webd_obj_add_str(row, "app", app_nc_json_str(row, "app_name", ""));
        json_object_array_add(app_src, json_object_get(row));
    }
    rows = webd_audit_paginate_array(app_src, &q, webd_audit_entity_match, q.unknown_first, &total);
    json_object_object_add(data, "app_records", json_object_get(rows));
    json_object_object_add(data, "apps", json_object_get(rows));
    json_object_object_add(data, "records", json_object_get(rows));
    json_object_object_add(data, "items", rows);
    webd_audit_add_page_meta(data, &q, total, (int)json_object_array_length(webd_obj_child_array(data, "app_records")),
                             flow_summary ? "jmxd.audit_flow_app_summary" : "jmxd.audit_apps.empty");
    json_object_object_add(data, "unknown_first", json_object_new_boolean(q.unknown_first));
    json_object_object_add(data, "bytes_supported", json_object_new_boolean(flow_summary ? app_nc_json_bool(flow_summary, "bytes_supported", 1) : 0));
    json_object_object_add(data, "application_identity_partial", json_object_new_boolean(unresolved_fallback_count > 0));
    json_object_object_add(data, "service_or_protocol_fallback_count", json_object_new_int(unresolved_fallback_count));
    json_object_object_add(data, "flow_summary_fallback", json_object_new_boolean(1));
    json_object_object_add(data, "degraded", json_object_new_boolean(flow_summary ? 0 : 1));
    webd_obj_add_str(data, "reason", flow_summary ? "application_audit_from_flow_summary" : "audit_flow_app_summary_unavailable");
    /*
     * This handler queries neither audit_status nor audit_view, so it must not
     * claim those sources are unavailable; -1 keeps the boolean false while the
     * reason says the bit was simply not evaluated here.
     */
    webd_audit_add_caps(data, -1, -1, flow_summary != NULL, 0, -1, 1);
    json_object_put(app_src);
    if (flow_summary) json_object_put(flow_summary);
    return webd_envelope(data, "webd.audit.apps_bff");
}


static struct json_object *webd_audit_app_detail_response(const struct http_req *req,
                                                          struct json_object *body,
                                                          int *http_status)
{
    char id[160] = "";
    struct webd_audit_bff_query q;
    struct json_object *flow_summary;
    struct json_object *items;
    struct json_object *matched = json_object_new_array();
    struct json_object *data = json_object_new_object();
    int i, n;
    int app_id_filter = 0;

    if (http_status)
        *http_status = 200;
    webd_audit_read_query(req, body, &q);
    webd_path_tail_token(req ? req->path : "", "/api/v1/audit/apps/", id, sizeof(id));
    if ((!id[0] || !strcmp(id, "detail")) && body)
        snprintf(id, sizeof(id), "%s", app_nc_json_str(body, "id", app_nc_json_str(body, "app_id", app_nc_json_str(body, "app", ""))));
    if (req && req->query[0]) {
        char qid[160] = "";
        if (webd_query_get(req->query, "id", qid, sizeof(qid)) || webd_query_get(req->query, "app_id", qid, sizeof(qid)))
            snprintf(id, sizeof(id), "%s", qid);
    }
    if (!id[0]) {
        if (http_status) *http_status = 400;
        webd_obj_add_str(data, "error", "missing_app_id");
        json_object_put(matched);
        return webd_envelope(data, "webd.audit.app_detail_bff");
    }
    app_id_filter = atoi(id);
    snprintf(q.q, sizeof(q.q), "%s", id);
    flow_summary = webd_audit_flow_summary_rows(&q, 500);
    items = webd_obj_child_array(flow_summary, "items");
    n = items ? (int)json_object_array_length(items) : 0;
    for (i = 0; i < n; i++) {
        struct json_object *row = json_object_array_get_idx(items, i);
        int row_app_id = app_nc_json_int(row, "app_id", app_nc_json_int(row, "appid", app_nc_json_int(row, "canonical_app_id", 0)));
        const char *name = webd_first_nonempty4(app_nc_json_str(row, "app_name", ""),
                                                app_nc_json_str(row, "name", ""),
                                                app_nc_json_str(row, "application_name", ""),
                                                app_nc_json_str(row, "service", ""));
        if ((app_id_filter > 0 && row_app_id == app_id_filter) ||
            webd_str_contains_i(name, id) || webd_str_contains_i(app_nc_json_str(row, "service", ""), id)) {
            webd_audit_entity_add_aliases(row);
            json_object_array_add(matched, json_object_get(row));
        }
    }
    webd_obj_add_str(data, "id", id);
    webd_obj_add_str(data, "type", "app");
    json_object_object_add(data, "records", json_object_get(matched));
    json_object_object_add(data, "items", json_object_get(matched));
    if (json_object_array_length(matched) > 0) {
        struct json_object *first = json_object_array_get_idx(matched, 0);
        webd_json_copy_key(data, "app_id", first, "app_id");
        webd_json_copy_key(data, "appid", first, "appid");
        webd_obj_add_str(data, "name", webd_first_nonempty4(app_nc_json_str(first, "app_name", ""),
                         app_nc_json_str(first, "name", ""), app_nc_json_str(first, "application_name", ""), id));
        webd_json_copy_key(data, "category", first, "category");
        webd_json_copy_key(data, "connections", first, "connections");
        webd_json_copy_key(data, "bytes", first, "bytes");
        webd_json_copy_key(data, "total_bytes", first, "total_bytes");
        webd_json_copy_key(data, "clients", first, "clients");
        webd_json_copy_key(data, "evidence", first, "evidence");
    } else {
        json_object_object_add(data, "degraded", json_object_new_boolean(1));
        webd_obj_add_str(data, "reason", flow_summary ? "app_not_found_in_flow_summary_window" : "audit_flow_app_summary_unavailable");
    }
    json_object_object_add(data, "detail_supported", json_object_new_boolean(flow_summary != NULL));
    json_object_object_add(data, "domains", json_object_new_array());
    json_object_object_add(data, "time_series", json_object_new_array());
    json_object_object_add(data, "domains_supported", json_object_new_boolean(0));
    json_object_object_add(data, "time_series_supported", json_object_new_boolean(0));
    webd_obj_add_str(data, "source", "jmxd.audit_flow_app_summary");
    webd_obj_add_str(data, "note", "app detail is summary-backed; per-app domains/clients/time-series await dedicated audit ledger");
    json_object_put(matched);
    if (flow_summary) json_object_put(flow_summary);
    return webd_envelope(data, "webd.audit.app_detail_bff");
}

/* ── audit route handlers (ctx adapters over the verbatim response builders) ── */

static struct json_object *audit_status(struct jmx_api_ctx *ctx)
{
    int status = ctx->status;
    struct json_object *resp =
        webd_audit_status_response(ctx->req, ctx->body, &status);
    ctx->status = status;
    return resp;
}

static struct json_object *audit_urls(struct jmx_api_ctx *ctx)
{
    int status = ctx->status;
    struct json_object *resp =
        webd_audit_urls_response(ctx->req, ctx->body, &status);
    ctx->status = status;
    return resp;
}

static struct json_object *audit_online_records(struct jmx_api_ctx *ctx)
{
    int status = ctx->status;
    struct json_object *resp =
        webd_audit_online_records_response(ctx->req, ctx->body, &status);
    ctx->status = status;
    return resp;
}

static struct json_object *audit_im_records(struct jmx_api_ctx *ctx)
{
    int status = ctx->status;
    struct json_object *resp =
        webd_audit_im_records_response(ctx->req, ctx->body, &status);
    ctx->status = status;
    return resp;
}

static struct json_object *audit_traffic(struct jmx_api_ctx *ctx)
{
    int status = ctx->status;
    struct json_object *resp =
        webd_audit_traffic_response(ctx->req, ctx->body, &status);
    ctx->status = status;
    return resp;
}

static struct json_object *audit_protocol_detail(struct jmx_api_ctx *ctx)
{
    int status = ctx->status;
    struct json_object *resp =
        webd_audit_protocol_detail_response(ctx->req, ctx->body, &status);
    ctx->status = status;
    return resp;
}

static struct json_object *audit_protocols(struct jmx_api_ctx *ctx)
{
    int status = ctx->status;
    struct json_object *resp =
        webd_audit_protocols_response(ctx->req, ctx->body, &status);
    ctx->status = status;
    return resp;
}

static struct json_object *audit_app_detail(struct jmx_api_ctx *ctx)
{
    int status = ctx->status;
    struct json_object *resp =
        webd_audit_app_detail_response(ctx->req, ctx->body, &status);
    ctx->status = status;
    return resp;
}

static struct json_object *audit_apps(struct jmx_api_ctx *ctx)
{
    int status = ctx->status;
    struct json_object *resp =
        webd_audit_apps_response(ctx->req, ctx->body, &status);
    ctx->status = status;
    return resp;
}

const struct jmx_api_route audit_api_routes[] = {
    JMX_API_ROUTE(207, "/api/v1/audit/status", "GET", JMX_API_EXACT, audit_status),
    JMX_API_ROUTE(208, "/api/v1/audit/urls", "GET", JMX_API_EXACT, audit_urls),
    JMX_API_ROUTE(209, "/api/v1/audit/online-records", "GET", JMX_API_EXACT, audit_online_records),
    JMX_API_ROUTE(210, "/api/v1/audit/im-records", "GET", JMX_API_EXACT, audit_im_records),
    JMX_API_ROUTE(211, "/api/v1/audit/traffic", "GET", JMX_API_EXACT, audit_traffic),
    JMX_API_ROUTE(228, "/api/v1/audit/protocols/", "GET", JMX_API_PREFIX, audit_protocol_detail),
    JMX_API_ROUTE(229, "/api/v1/audit/protocols", "GET", JMX_API_EXACT, audit_protocols),
    JMX_API_ROUTE(230, "/api/v1/audit/apps/", "GET", JMX_API_PREFIX, audit_app_detail),
    JMX_API_ROUTE(231, "/api/v1/audit/apps", "GET", JMX_API_EXACT, audit_apps),
    JMX_API_ROUTE_END,
};
