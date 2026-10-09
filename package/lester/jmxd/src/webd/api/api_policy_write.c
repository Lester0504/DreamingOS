// SPDX-License-Identifier: GPL-2.0-or-later
/* Policy Table: write executors. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <libubox/utils.h>

#include "api_policy_write.h"
#include "api_policy_write_internal.h"
#include "api_policy_paths.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_shared_json.h"
#include "api_ubus.h"
#include "api_util.h"
#include "../webd_admin_transaction.h"

#define WEBD_POLICY_REORDER_MAX 512
#define WEBD_POLICY_REORDER_PACKAGE_MAX 4096
#define WEBD_POLICY_REORDER_LOCK "/tmp/dreamingwrt/policy-reorder.lock"

struct webd_policy_reorder_scope {
    const char *policy_type;   /* canonical Policy Table policy_type */
    const char *package;       /* UCI package name */
    const char *types[3];      /* participating UCI section types */
    const char *id_prefixes[3];/* accepted row id prefixes */
    const char *config_path;   /* file backed up before commit */
    const char *scope_label;   /* reported scope string */
};

static const struct webd_policy_reorder_scope webd_policy_reorder_scopes[] = {
    { "firewall",        "firewall", { "rule", NULL, NULL },
      { "uci-firewall-rule-", NULL, NULL },
      WEBD_POLICY_CONFIG_FIREWALL, "uci:firewall:rule" },
    { "port_forwarding", "firewall", { "redirect", NULL, NULL },
      { "uci-firewall-redirect-", NULL, NULL },
      WEBD_POLICY_CONFIG_FIREWALL, "uci:firewall:redirect" },
    { "nat",             "firewall", { "nat", NULL, NULL },
      { "uci-firewall-nat-", NULL, NULL },
      WEBD_POLICY_CONFIG_FIREWALL, "uci:firewall:nat" },
    { "static_route",    "network",  { "route", "route6", NULL },
      { "uci-network-route-", "uci-network-route6-", NULL },
      WEBD_POLICY_CONFIG_NETWORK,  "uci:network:route" },
    { "dns",             "dhcp",     { "domain", "cname", "host" },
      { "uci-dhcp-", NULL, NULL },
      WEBD_POLICY_CONFIG_DHCP,     "uci:dhcp:domain_cname_host" },
    { "qos",             "sqm",      { "queue", NULL, NULL },
      { "uci-sqm-queue-", NULL, NULL },
      WEBD_POLICY_CONFIG_SQM,      "uci:sqm:queue" },
};

static void webd_policy_add_affected_file(struct json_object *arr,
                                          const char *path,
                                          const char *role);
static int webd_policy_json_value_to_string(struct json_object *v, char *out, size_t out_len);
static int webd_policy_write_apply_requested(const struct http_req *req,
                                             struct json_object *body);
static int webd_policy_write_is_firewall_rule(const char *operation,
                                              const char *policy_type,
                                              const char *id);
static int webd_policy_write_is_port_forwarding(const char *operation,
                                                const char *policy_type,
                                                const char *id);
static int webd_policy_write_is_dns(const char *operation,
                                    const char *policy_type,
                                    const char *id);
static int webd_policy_write_is_qos(const char *operation,
                                    const char *policy_type,
                                    const char *id);
static int webd_policy_write_is_nat(const char *operation,
                                    const char *policy_type,
                                    const char *id);
static int webd_policy_write_is_static_route(const char *operation,
                                             const char *policy_type,
                                             const char *id);
static int webd_policy_write_is_pbr(const char *operation,
                                    const char *policy_type,
                                    const char *id);
static int webd_policy_write_is_acl(const char *operation,
                                    const char *policy_type,
                                    const char *id,
                                    struct json_object *body);
static const struct webd_policy_reorder_scope *webd_policy_reorder_scope_by_type(const char *policy_type);
static const struct webd_policy_reorder_scope *webd_policy_reorder_scope_by_id(const char *id);
static int webd_policy_reorder_scope_has_type(const struct webd_policy_reorder_scope *sc,
                                              const char *type);
static struct uci_section *webd_policy_reorder_find_section(struct uci_package *pkg,
                                                            const struct webd_policy_reorder_scope *sc,
                                                            const char *id);
static int webd_policy_reorder_position_of(struct uci_package *pkg,
                                            struct uci_section *target);
static int webd_policy_reorder_collect_all(struct uci_package *pkg,
                                           struct uci_section **sections,
                                           int max_sections);
static int webd_policy_reorder_collect_slots(struct uci_package *pkg,
                                              const struct webd_policy_reorder_scope *sc,
                                              int *slots, int max_slots);
static char *webd_policy_reorder_backup_path(const struct webd_policy_reorder_scope *sc,
                                             char *out, size_t out_len);
static int webd_policy_reorder_config_validate(const struct webd_policy_reorder_scope *sc,
                                                struct json_object *steps,
                                                struct json_object *warnings,
                                                char *err, size_t err_len);
static int webd_policy_reorder_runtime_reload(const struct webd_policy_reorder_scope *sc,
                                               const struct http_req *req,
                                               struct json_object *body,
                                               struct json_object *steps,
                                               struct json_object *warnings,
                                               struct json_object *tx);
static struct json_object *webd_policy_uci_reorder_response(const struct http_req *req,
                                                            struct json_object *body,
                                                            const struct webd_policy_reorder_scope *sc,
                                                            struct json_object *input,
                                                            int apply_requested,
                                                            int *http_status);
static struct json_object *webd_policy_reorder_response(const struct http_req *req,
                                                        struct json_object *body,
                                                        int apply_requested,
                                                        int *http_status);
static struct json_object *webd_policy_write_preview_response(const struct http_req *req,
                                                              struct json_object *body,
                                                              int *http_status);

int webd_policy_str_false(const char *s)
{
    return s && (!strcasecmp(s, "0") || !strcasecmp(s, "false") ||
                 !strcasecmp(s, "no") || !strcasecmp(s, "off") ||
                 !strcasecmp(s, "disabled"));
}

int webd_policy_str_true(const char *s)
{
    return !s || !s[0] || !webd_policy_str_false(s);
}

int webd_policy_str_eq(const char *a, const char *b)
{
    return a && b && !strcmp(a, b);
}

const char *webd_policy_action_key_from_target(const char *target)
{
    const char *t = target ? target : "";

    if (!t[0]) return "allow";
    if (!strcasecmp(t, "ACCEPT") || !strcasecmp(t, "allow") ||
        !strcasecmp(t, "permit")) return "allow";
    if (!strcasecmp(t, "DROP") || !strcasecmp(t, "block") ||
        !strcasecmp(t, "deny")) return "block";
    if (!strcasecmp(t, "REJECT")) return "reject";
    if (!strcasecmp(t, "DNAT") || !strcasecmp(t, "SNAT") ||
        !strcasecmp(t, "MASQUERADE") || !strcasecmp(t, "REDIRECT") ||
        !strcasecmp(t, "redirect") || !strcasecmp(t, "rewrite") ||
        !strcasecmp(t, "route") || !strcasecmp(t, "mark") ||
        !strcasecmp(t, "qos") || !strcasecmp(t, "throttle") ||
        !strcasecmp(t, "nat") || !strcasecmp(t, "convert")) return "convert";
    return "allow";
}

struct json_object *webd_policy_extract_data_ref(struct json_object *resp)
{
    struct json_object *data = NULL;
    struct json_object *okv = NULL;

    if (!resp)
        return NULL;
    if (json_object_object_get_ex(resp, "ok", &okv) && okv && !json_object_get_boolean(okv))
        return NULL;
    if (json_object_object_get_ex(resp, "data", &data) && data)
        return json_object_get(data);
    return json_object_get(resp);
}

struct json_object *webd_policy_capabilities(void)
{
    struct json_object *cap = json_object_new_object();
    struct json_object *write_types = json_object_new_array();
    struct json_object *action_contract = json_object_new_object();
    struct json_object *action_reasons = json_object_new_object();

    json_object_object_add(cap, "list", json_object_new_boolean(1));
    json_object_object_add(cap, "facets", json_object_new_boolean(1));
    json_object_object_add(cap, "details", json_object_new_boolean(1));
    json_object_object_add(cap, "catalog", json_object_new_boolean(1));
    /*
     * 应用目录的分页自述。前端此前只发一次裸请求、在返回的 100 条里做本地过滤，
     * 于是 5873 个应用里只有前 100 个可选；能力位在这里把参数名和上限写明，
     * 免得前端靠猜（交接单要求：不能靠前端猜）。参数名与 /api/v1/signatures/apps
     * 保持同一套方言：limit / offset / q，本端点另接受 app_ 前缀形式。
     */
    json_object_object_add(cap, "catalog_applications_paginated",
                           json_object_new_boolean(1));
    json_object_object_add(cap, "catalog_applications_page_size_max",
                           json_object_new_int(500));
    json_object_object_add(cap, "catalog_applications_page_size_default",
                           json_object_new_int(100));
    {
        struct json_object *params = json_object_new_array();
        const char *names[] = { "app_limit", "app_offset", "app_q",
                                "limit", "offset", "q", NULL };
        int i;

        for (i = 0; names[i]; i++)
            json_object_array_add(params, json_object_new_string(names[i]));
        json_object_object_add(cap, "catalog_applications_query_params", params);
    }
    json_object_object_add(cap, "catalog_applications_server_side_search",
                           json_object_new_boolean(1));
    json_object_object_add(cap, "create", json_object_new_boolean(1));
    json_object_object_add(cap, "update", json_object_new_boolean(1));
    json_object_object_add(cap, "delete", json_object_new_boolean(1));
    json_object_object_add(cap, "reorder", json_object_new_boolean(1));
    json_object_object_add(cap, "reorder_partial", json_object_new_boolean(1));
    {
        struct json_object *types = json_object_new_array();
        json_object_array_add(types, json_object_new_string("pbr"));
        json_object_array_add(types, json_object_new_string("firewall"));
        json_object_array_add(types, json_object_new_string("port_forwarding"));
        json_object_array_add(types, json_object_new_string("nat"));
        json_object_array_add(types, json_object_new_string("static_route"));
        json_object_array_add(types, json_object_new_string("dns"));
        json_object_array_add(types, json_object_new_string("qos"));
        json_object_object_add(cap, "reorder_supported_policy_types", types);
    }
    json_object_object_add(cap, "reorder_scope",
                           json_object_new_string("same_source_only"));
    json_object_object_add(cap, "reorder_mixed_sources_supported",
                           json_object_new_boolean(0));
    json_object_object_add(cap, "reorder_full_scope_required",
                           json_object_new_boolean(1));
    json_object_object_add(cap, "reorder_uci_foreign_sections_preserved",
                           json_object_new_boolean(1));
    json_object_object_add(cap, "static_route_reorder_runtime_semantics",
                           json_object_new_string("config_order_only; route selection remains metric/prefix/table based"));
    {
        struct json_object *scopes = json_object_new_array();
        const char *names[] = {
            "config.db:policy_route_rule", "uci:firewall:rule",
            "uci:firewall:redirect", "uci:firewall:nat",
            "uci:network:route", "uci:dhcp:domain_cname_host",
            "uci:sqm:queue", NULL
        };
        int i;

        for (i = 0; names[i]; i++)
            json_object_array_add(scopes, json_object_new_string(names[i]));
        json_object_object_add(cap, "reorder_scopes", scopes);
    }
    json_object_object_add(cap, "enable_disable", json_object_new_boolean(1));
    json_object_object_add(cap, "write_preview", json_object_new_boolean(1));
    json_object_object_add(cap, "write_preview_endpoint",
                           json_object_new_string("/api/v1/policy-engine/policy-table/preview"));
    json_object_array_add(write_types, json_object_new_string("firewall"));
    json_object_array_add(write_types, json_object_new_string("port_forwarding"));
    json_object_array_add(write_types, json_object_new_string("dns"));
    json_object_array_add(write_types, json_object_new_string("nat"));
    json_object_array_add(write_types, json_object_new_string("static_route"));
    json_object_array_add(write_types, json_object_new_string("qos"));
    json_object_array_add(write_types, json_object_new_string("pbr"));
    json_object_array_add(write_types, json_object_new_string("acl"));
    json_object_object_add(cap, "write_supported_policy_types", write_types);
    json_object_object_add(cap, "firewall_rule_create", json_object_new_boolean(1));
    json_object_object_add(cap, "firewall_rule_update", json_object_new_boolean(1));
    json_object_object_add(cap, "firewall_rule_delete", json_object_new_boolean(1));
    json_object_object_add(cap, "firewall_rule_enable_disable", json_object_new_boolean(1));
    json_object_object_add(cap, "port_forwarding_create", json_object_new_boolean(1));
    json_object_object_add(cap, "port_forwarding_update", json_object_new_boolean(1));
    json_object_object_add(cap, "port_forwarding_delete", json_object_new_boolean(1));
    json_object_object_add(cap, "port_forwarding_enable_disable", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_record_create", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_record_update", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_record_delete", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_record_enable_disable", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_record_enable_disable_mode",
                           json_object_new_string("dnsmasq_instance_quarantine"));
    json_object_object_add(cap, "dns_record_conflict_detection", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_record_conflict_scope",
                           json_object_new_string("enabled_and_disabled_records"));
    json_object_object_add(cap, "dns_record_stable_section_id", json_object_new_boolean(1));
    json_object_object_add(cap, "nat_create", json_object_new_boolean(1));
    json_object_object_add(cap, "nat_update", json_object_new_boolean(1));
    json_object_object_add(cap, "nat_delete", json_object_new_boolean(1));
    json_object_object_add(cap, "nat_enable_disable", json_object_new_boolean(1));
    json_object_object_add(cap, "static_route_create", json_object_new_boolean(1));
    json_object_object_add(cap, "static_route_update", json_object_new_boolean(1));
    json_object_object_add(cap, "static_route_delete", json_object_new_boolean(1));
    json_object_object_add(cap, "static_route_enable_disable", json_object_new_boolean(1));
    json_object_object_add(cap, "qos_sqm_create", json_object_new_boolean(1));
    json_object_object_add(cap, "qos_sqm_update", json_object_new_boolean(1));
    json_object_object_add(cap, "qos_sqm_delete", json_object_new_boolean(1));
    json_object_object_add(cap, "qos_sqm_enable_disable", json_object_new_boolean(1));
    json_object_object_add(cap, "pbr_create", json_object_new_boolean(1));
    json_object_object_add(cap, "pbr_update", json_object_new_boolean(1));
    json_object_object_add(cap, "pbr_delete", json_object_new_boolean(1));
    json_object_object_add(cap, "pbr_enable_disable", json_object_new_boolean(1));
    json_object_object_add(cap, "pbr_runtime_sync", json_object_new_boolean(1));
    json_object_object_add(cap, "pbr_runtime_sync_method", json_object_new_string("dreamingwrt.route_reload"));
    /* One versioned action contract is shared by policy-table and routing-table.
     * The URL map is data, so consumers do not need to duplicate endpoint rules. */
    webd_obj_add_str(action_contract, "version", "policy-table.v2");
    webd_obj_add_str(action_contract, "endpoint", "/api/v1/policy-engine/policy-table");
    webd_obj_add_str(action_contract, "preview_endpoint", "/api/v1/policy-engine/policy-table/preview");
    webd_obj_add_str(action_contract, "transaction_order",
                     "validate -> persist -> apply/reload -> config_readback -> runtime_readback -> commit");
    webd_obj_add_str(action_contract, "conflict_field", "revision");
    webd_obj_add_str(action_contract, "etag_field", "etag");
    json_object_object_add(action_contract, "stable_identity", json_object_new_boolean(1));
    webd_policy_action_add(action_contract, "create", "POST",
                           "/api/v1/policy-engine/policy-table?apply=true", 1, "");
    webd_policy_action_add(action_contract, "update", "PATCH",
                           "/api/v1/policy-engine/policy-table/{id}?apply=true", 1, "");
    webd_policy_action_add(action_contract, "delete", "DELETE",
                           "/api/v1/policy-engine/policy-table/{id}?apply=true", 1, "");
    webd_policy_action_add(action_contract, "enable", "POST",
                           "/api/v1/policy-engine/policy-table/{id}/enable?apply=true", 1, "");
    webd_policy_action_add(action_contract, "disable", "POST",
                           "/api/v1/policy-engine/policy-table/{id}/disable?apply=true", 1, "");
    webd_obj_add_str(action_reasons, "static_route",
                     "static_route_executor_available; network UCI guarded transaction");
    webd_obj_add_str(action_reasons, "pbr",
                     "pbr_executor_available; config.db transaction plus dreamingwrt.route_reload");
    webd_obj_add_str(action_reasons, "external_pbr",
                     "external_source_not_canonical; adopt/import preview required");
    json_object_object_add(action_contract, "reasons", action_reasons);
    json_object_object_add(cap, "canonical_action_contract", action_contract);
    json_object_object_add(cap, "canonical_action_contract_version", json_object_new_string("policy-table.v2"));
    json_object_object_add(cap, "canonical_action_endpoint", json_object_new_string("/api/v1/policy-engine/policy-table"));
    json_object_object_add(cap, "canonical_preview_endpoint", json_object_new_string("/api/v1/policy-engine/policy-table/preview"));
    json_object_object_add(cap, "static_route_action_reason", json_object_new_string("static_route_executor_available; network UCI guarded transaction"));
    json_object_object_add(cap, "pbr_action_reason", json_object_new_string("pbr_executor_available; config.db transaction plus dreamingwrt.route_reload"));
    json_object_object_add(cap, "external_policy_action_reason", json_object_new_string("external_source_not_canonical; adopt/import preview required"));
    json_object_object_add(cap, "external_policy_management", json_object_new_string("diagnostic_or_adopt_only"));
    json_object_object_add(cap, "external_policy_adopt_endpoint", json_object_new_string("/api/v1/policy-engine/policy-table/preview"));
    json_object_object_add(cap, "external_policy_source_identity", json_object_new_string("source + package/path + section identity"));
    json_object_object_add(cap, "transaction_failure_fields", json_object_new_string("error,stage,field,rollback,rollback_result"));
    json_object_object_add(cap, "pbr_hit_counter_source", json_object_new_string("jmx_route_kernel route_rule_counter"));
    /*
     * The hit counter chain is broken at the database layer, not the contract
     * layer, and the old capability set could not say so. pbr_hit_counter_source
     * names where counters come from, which reads as "implemented" -- but the
     * rows this endpoint serves come from a different database that nothing ever
     * writes these two columns into:
     *
     *   writer  /var/lib/dreamingwrt/network_state.db
     *           route_rule_counter / route_rule_counter_v2, driven by the jmx
     *           kernel snapshot (route_rule_counter_upsert()). Only aegisxd
     *           consumes it; webd never opens that database.
     *   reader  /etc/dreamingwrt/config.db
     *           policy_route_rule.hit_count / last_hit, declared DEFAULT 0 and
     *           never assigned by any statement in the tree -- the INSERT does
     *           not list them and its ON CONFLICT clause does not touch them.
     *
     * So hit_count is structurally 0 and last_hit structurally 0, regardless of
     * real traffic. Reporting that as the number 0 is a false statement about
     * live behaviour: "no packets matched" and "this counter is not collected"
     * are different facts, and only the latter is true here. The UI needs to be
     * able to render an unavailable state instead of a plausible-looking zero,
     * hence an explicit availability bit rather than a source string alone.
     *
     * Joining the runtime counters in is blocked upstream of this decision:
     * kernel route_rule v1 does not carry configured_id (jmx_route.c:3221), so
     * runtime rows cannot be attributed back to policy_route_rule.id. Matching
     * on priority instead would silently mis-attribute counters after any
     * reorder, which is worse than reporting nothing.
     */
    json_object_object_add(cap, "pbr_hit_counter_available", json_object_new_boolean(0));
    json_object_object_add(cap, "pbr_hit_counter_reason",
        json_object_new_string("counter_written_to_network_state_db_not_joined_to_config_db"));
    json_object_object_add(cap, "pbr_hit_counter_writer_db",
        json_object_new_string("/var/lib/dreamingwrt/network_state.db:route_rule_counter_v2"));
    json_object_object_add(cap, "pbr_hit_counter_reader_db",
        json_object_new_string("/etc/dreamingwrt/config.db:policy_route_rule"));
    /*
     * Spelled out separately so the UI does not present the zero as data: the
     * columns exist and parse, they are simply never populated.
     */
    json_object_object_add(cap, "pbr_hit_counter_zero_is_placeholder", json_object_new_boolean(1));
    json_object_object_add(cap, "pbr_hit_counter_blocker",
        json_object_new_string("kernel_route_rule_v1_does_not_carry_configured_id"));
    json_object_object_add(cap, "acl_write", json_object_new_boolean(1));
    json_object_object_add(cap, "acl_write_partial", json_object_new_boolean(1));
    json_object_object_add(cap, "acl_create", json_object_new_boolean(1));
    json_object_object_add(cap, "acl_update", json_object_new_boolean(1));
    json_object_object_add(cap, "acl_delete", json_object_new_boolean(1));
    json_object_object_add(cap, "acl_enable_disable", json_object_new_boolean(1));
    {
        struct json_object *types = json_object_new_array();
        json_object_array_add(types, json_object_new_string("mac"));
        json_object_object_add(cap, "acl_write_supported_types", types);
    }
    {
        struct json_object *types = json_object_new_array();
        json_object_array_add(types, json_object_new_string("connection_limit"));
        json_object_array_add(types, json_object_new_string("app"));
        json_object_array_add(types, json_object_new_string("url_access"));
        json_object_array_add(types, json_object_new_string("terminal_limit"));
        json_object_object_add(cap, "acl_write_pending_types", types);
    }
    /*
     * Why each pending type is pending, one reason per type.
     *
     * Only connection_limit used to carry a reason, so the UI had to render the
     * other three as bare labels with no way to tell "not built yet" from
     * "stored but never enforced". The three causes are genuinely different and
     * a single shared reason string would misreport two of them:
     *
     *   app, terminal_limit  dataplane exists and is complete
     *                        (nc_nft_for_each_app_rule() for app; the tc police
     *                        plan for terminal_limit). They are refused only by
     *                        the mac-only gate in
     *                        webd_policy_acl_type_supported(), so the honest
     *                        reason names the gate, not a missing feature.
     *
     *   url_access           persisted by network_control_save and read back,
     *                        but no generator anywhere emits it. This is the
     *                        real "writes land in config.db and silently never
     *                        take effect" case.
     *
     *   connection_limit     the generator emits `ct count over N drop`, but
     *                        nft_connlimit is absent from the running kernel,
     *                        so `nft --check` rejects the file before anything
     *                        is applied. Because netctl publishes mac, app and
     *                        connection_limit as one atomic ruleset file, one
     *                        enabled rule of this kind fails the whole ruleset
     *                        and takes working MAC ACL rules down with it. That
     *                        is strictly worse than "this rule does nothing",
     *                        hence a distinct reason string.
     */
    {
        struct json_object *reasons = json_object_new_object();
        json_object_object_add(reasons, "connection_limit",
            json_object_new_string("nft_connlimit_kmod_missing_blocks_whole_ruleset"));
        json_object_object_add(reasons, "app",
            json_object_new_string("dataplane_ready_blocked_by_mac_only_write_gate"));
        json_object_object_add(reasons, "url_access",
            json_object_new_string("persisted_without_dataplane"));
        json_object_object_add(reasons, "terminal_limit",
            json_object_new_string("dataplane_ready_blocked_by_mac_only_write_gate"));
        json_object_object_add(cap, "acl_write_pending_reasons", reasons);
    }
    /*
     * url_access is the one pending type whose writes actually land, so it needs
     * a flag of its own rather than only a pending-reason string.
     *
     * nc_netctl_save_url_access() persists into
     * config.db:network_control_url_access_rule and network_control_get reads it
     * back, so a saved rule survives a reload and renders as a real rule. But no
     * generator anywhere emits it: the netctl nft writer has a per-type emitter
     * for mac, app and connection_limit and none for url_access. The rule is
     * stored, listed, and never enforced.
     *
     * That is the dangerous half-state -- the user sees a rule that looks active
     * and concludes their domain block works. acl_write_pending_reasons already
     * carries persisted_without_dataplane for this type, but that field explains
     * why the *write path* is pending; it says nothing about rules already in the
     * database. A client rendering the existing rule list has nothing to key off.
     * These bits let it mark those rows "saved but not in effect".
     */
    json_object_object_add(cap, "acl_url_access_enforced", json_object_new_boolean(0));
    json_object_object_add(cap, "acl_url_access_persisted", json_object_new_boolean(1));
    json_object_object_add(cap, "acl_url_access_reason",
                           json_object_new_string("persisted_without_dataplane"));
    json_object_object_add(cap, "acl_url_access_runtime",
                           json_object_new_string("none:no_nft_generator_emits_url_access"));
    /*
     * Generalised so a client does not need a hardcoded list of which types are
     * safe to trust. Any type named here stores rules that never reach the
     * dataplane, so its existing rows must not be presented as active.
     */
    {
        struct json_object *types = json_object_new_array();
        json_object_array_add(types, json_object_new_string("url_access"));
        json_object_object_add(cap, "acl_persisted_unenforced_types", types);
    }
    json_object_object_add(cap, "acl_runtime_source",
                           json_object_new_string("config.db:network_control_rule+nftables"));
    /*
     * Kept for compatibility with clients that already read this single field,
     * but corrected: the old value named the symptom ("the expression is
     * unavailable") and read as a permanent nftables limitation. The cause is a
     * missing kernel module, and the blast radius is the entire netctl ruleset.
     */
    json_object_object_add(cap, "acl_connection_limit_reason",
                           json_object_new_string("nft_connlimit_kmod_missing_blocks_whole_ruleset"));
    json_object_object_add(cap, "acl_connection_limit_config_writable",
                           json_object_new_boolean(1));
    json_object_object_add(cap, "acl_connection_limit_runtime_enforced",
                           json_object_new_boolean(0));
    /*
     * Spelled out because "config writable but not enforced" is the dangerous
     * half-state this capability exists to prevent the UI from hiding. No HTTP
     * route reaches it today (the mac-only gate refuses it), so the only way in
     * is ubus network_control_save.
     */
    json_object_object_add(cap, "acl_connection_limit_failure_mode",
                           json_object_new_string("nft_check_rejects_whole_netctl_ruleset_before_apply"));
    json_object_object_add(cap, "acl_connection_limit_http_reachable",
                          json_object_new_boolean(0));
    /*
     * terminal_limit vs client_rate_limit: two coexisting subsystems, not two
     * names for one thing. The ACL pending list names the former; the writable
     * path the UI already uses is the latter.
     *
     *   terminal_limit      config.db network_control_terminal_limit, enforced
     *                       by the tc police plan built from
     *                       network_control_rule. Reached through the ACL
     *                       surface, which is gated to mac only.
     *   client_rate_limit   the "terminal network control" client-control path
     *                       (ubus client_rate_limit_set). Already writable and
     *                       not part of the ACL surface at all.
     *
     * Stated explicitly because reading terminal_limit as an alias leads to the
     * wrong conclusion that ACL rate limiting is already shipping.
     */
    json_object_object_add(cap, "acl_terminal_limit_relation",
                           json_object_new_string("distinct_from_client_rate_limit"));
    json_object_object_add(cap, "acl_terminal_limit_runtime",
                           json_object_new_string("tc_police_from_network_control_terminal_limit"));
    json_object_object_add(cap, "acl_terminal_limit_writable_alternative",
                           json_object_new_string("client_control:client_rate_limit_set"));
    /*
     * One gate refuses all four pending types, so name it once. Without this the
     * per-type reasons look like four unrelated features to build, when three of
     * them are one decision about this gate.
     */
    json_object_object_add(cap, "acl_write_gate",
                           json_object_new_string("webd_policy_acl_type_supported:mac_only"));
    json_object_object_add(cap, "acl_schedule_supported",
                           json_object_new_boolean(1));
    json_object_object_add(cap, "acl_schedule_mode",
                           json_object_new_string("always_or_single_window"));
    /*
     * Exactly one window per rule: nftables evaluates one time expression per
     * rule, so several disjoint windows require several rules. Stated as a
     * capability so the UI can cap its editor instead of discovering the limit
     * through a 400.
     */
    json_object_object_add(cap, "acl_schedule_max_windows", json_object_new_int(1));
    json_object_object_add(cap, "acl_schedule_weekdays_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "acl_schedule_time_basis",
                           json_object_new_string("device_local_time"));
    json_object_object_add(cap, "acl_schedule_runtime",
                           json_object_new_string("nft_meta_hour_and_meta_day"));
    json_object_object_add(cap, "acl_expires_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "acl_expires_unit",
                           json_object_new_string("absolute_unix_seconds"));
    /*
     * An expired rule keeps its row and simply stops being rendered, so the user
     * can see what lapsed and re-arm it. Reported so the UI does not assume the
     * rule was deleted.
     */
    json_object_object_add(cap, "acl_expires_retains_rule", json_object_new_boolean(1));
    json_object_object_add(cap, "acl_mac_unique_per_mac", json_object_new_boolean(1));
    /*
     * Group binding: source_kind:"group" + source_ref:"<terminal_group_id>".
     * Stated as a capability so the UI can offer the group picker instead of
     * discovering support through a 400.
     */
    json_object_object_add(cap, "acl_mac_group_binding_supported",
                           json_object_new_boolean(1));
    {
        struct json_object *kinds = json_object_new_array();

        json_object_array_add(kinds, json_object_new_string("mac"));
        json_object_array_add(kinds, json_object_new_string("group"));
        json_object_object_add(cap, "acl_mac_source_kinds", kinds);
    }
    json_object_object_add(cap, "acl_mac_group_source_field",
                           json_object_new_string("source=terminal_group:<id>"));
    json_object_object_add(cap, "acl_mac_group_expansion",
                           json_object_new_string("expanded_per_member_mac_at_apply_time"));
    /* Membership changes take effect on the next apply, not instantly: the UI
     * must say so rather than implying a group edit re-arms the block by itself. */
    json_object_object_add(cap, "acl_mac_group_recompute",
                           json_object_new_string("network_control_apply_or_reload_rules"));
    /* A group rule occupies no MAC slot, so acl_mac_unique_per_mac constrains
     * single-MAC rules only. A MAC hit by both a single rule and a group rule
     * gets both nft rules; the lower-priority rule is evaluated first and nft is
     * first-match-wins, so the effective action is the earlier rule's. */
    json_object_object_add(cap, "acl_mac_unique_applies_to_single_mac_rules_only",
                           json_object_new_boolean(1));
    json_object_object_add(cap, "acl_mac_group_overlap_resolution",
                           json_object_new_string("nft_first_match_wins_by_rule_priority"));
    {
        struct json_object *actions = json_object_new_array();
        json_object_array_add(actions, json_object_new_string("deny"));
        json_object_object_add(cap, "acl_mac_supported_actions", actions);
    }
    /*
     * Allowlist ("whitelist") mode is available, but not as a per-rule allow
     * action: acl_mac_supported_actions above stays deny-only because a
     * base-chain accept in this table cannot stop a later firewall chain from
     * dropping the packet. The mode is a table-wide switch instead, rendered as
     * the inverse - everything not in the set is dropped - so it needs no accept.
     */
    json_object_object_add(cap, "acl_mac_allow_supported", json_object_new_boolean(1));
    {
        struct json_object *modes = json_object_new_array();
        json_object_array_add(modes, json_object_new_string("blacklist"));
        json_object_array_add(modes, json_object_new_string("whitelist"));
        json_object_object_add(cap, "acl_mac_modes", modes);
    }
    json_object_object_add(cap, "acl_mac_allow_mode",
                           json_object_new_string("negated_set_drop"));
    json_object_object_add(cap, "acl_mac_allow_semantics",
                           json_object_new_string("ether saddr != @macacl_allow drop on LAN ingress; "
                                                  "devices outside the whitelist lose internet access"));
    json_object_object_add(cap, "acl_mac_allow_rule_action_supported",
                           json_object_new_boolean(0));
    json_object_object_add(cap, "acl_mac_allow_rule_action_reason",
                           json_object_new_string("standalone nft base-chain accept cannot bypass later firewall chains"));
    json_object_object_add(cap, "acl_mac_allow_scope",
                           json_object_new_string("forward_chain_lan_ingress_only_router_admin_still_reachable"));
    json_object_object_add(cap, "acl_mac_allow_source",
                           json_object_new_string("network_control_whitelist(kind=mac)"));
    json_object_object_add(cap, "acl_mac_allow_members_route",
                           json_object_new_string("PUT /api/v1/network-control/mac-allowlist/members"));
    json_object_object_add(cap, "acl_mac_allow_members_edit_while_enabled",
                           json_object_new_boolean(0));
    json_object_object_add(cap, "acl_mac_allow_mode_field",
                           json_object_new_string("mode=blacklist|whitelist"));
    json_object_object_add(cap, "acl_mac_allow_config_revision_field",
                           json_object_new_string("config_revision"));
    json_object_object_add(cap, "acl_mac_allow_runtime_fields",
                           json_object_new_string("runtime_applied,runtime_reason,runtime_revision"));
    json_object_object_add(cap, "acl_mac_allow_requires_confirm",
                           json_object_new_boolean(1));
    json_object_object_add(cap, "acl_mac_allow_confirm_route",
                           json_object_new_string("POST /api/v1/network-control/mac-allowlist/confirm"));
    json_object_object_add(cap, "acl_mac_allow_confirm_timeout_range",
                           json_object_new_string("30..900s, default 180"));
    json_object_object_add(cap, "acl_mac_allow_empty_list_rejected",
                           json_object_new_boolean(1));
    json_object_object_add(cap, "acl_mac_allow_admin_origin_autoallowed",
                           json_object_new_boolean(1));
    json_object_object_add(cap, "acl_mac_allow_admin_origin_field",
                           json_object_new_string("request_origin.peer_ip"));
    json_object_object_add(cap, "generic_policy_write", json_object_new_boolean(0));
    json_object_object_add(cap, "transaction_required", json_object_new_boolean(1));
    json_object_object_add(cap, "transaction_executor", json_object_new_boolean(1));
    json_object_object_add(cap, "rollback_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "dry_run_default", json_object_new_boolean(1));
    json_object_object_add(cap, "apply_requires_explicit_apply_true", json_object_new_boolean(1));
    json_object_object_add(cap, "runtime_reload_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "reason",
                           json_object_new_string("firewall/port_forwarding/dns/nat/static_route/qos_sqm/pbr and MAC ACL writes can apply through guarded transactions; reorder is transactional within each same-source PBR/UCI scope; mixed-source reorder, other ACL subtypes and composite object writes remain unavailable"));
    json_object_object_add(cap, "uci_firewall", json_object_new_boolean(access(WEBD_POLICY_CONFIG_FIREWALL, R_OK) == 0));
    json_object_object_add(cap, "uci_network", json_object_new_boolean(access(WEBD_POLICY_CONFIG_NETWORK, R_OK) == 0));
    json_object_object_add(cap, "uci_dhcp", json_object_new_boolean(access(WEBD_POLICY_CONFIG_DHCP, R_OK) == 0));
    json_object_object_add(cap, "uci_sqm", json_object_new_boolean(access(WEBD_POLICY_CONFIG_SQM, R_OK) == 0));
    json_object_object_add(cap, "flowd_rules_overlay", json_object_new_boolean(1));
    json_object_object_add(cap, "network_control_overlay", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_service_overlay", json_object_new_boolean(1));
    json_object_object_add(cap, "zones_list", json_object_new_boolean(1));
    json_object_object_add(cap, "zones_crud", json_object_new_boolean(1));
    json_object_object_add(cap, "zone_member_uniqueness", json_object_new_boolean(1));
    json_object_object_add(cap, "zone_matrix", json_object_new_boolean(1));
    /*
     * PBR source dimension. These are deliberately separate from objects_crud:
     * an interface/zone source needs no entry in the object catalogue, so it is
     * available while objects_crud is still blocked.
     */
    json_object_object_add(cap, "pbr_source_kinds_supported", json_object_new_boolean(1));
    {
        struct json_object *kinds = json_object_new_array();

        json_object_array_add(kinds, json_object_new_string("object"));
        json_object_array_add(kinds, json_object_new_string("interface"));
        json_object_array_add(kinds, json_object_new_string("zone"));
        json_object_array_add(kinds, json_object_new_string("network"));
        json_object_object_add(cap, "pbr_source_kinds", kinds);
    }
    json_object_object_add(cap, "pbr_source_interface", json_object_new_boolean(1));
    json_object_object_add(cap, "pbr_source_zone", json_object_new_boolean(1));
    json_object_object_add(cap, "pbr_pin_wan", json_object_new_boolean(1));
    json_object_object_add(cap, "pbr_pin_wan_scope",
                           json_object_new_string("interface_zone_network_sources_only"));
    json_object_object_add(cap, "pbr_pin_wan_enforcement",
                           json_object_new_string("ip_rule_iif_above_fwmark_rules"));
    json_object_object_add(cap, "pbr_pin_wan_on_target_wan_down",
                           json_object_new_string("stays_pinned_traffic_blackholes_until_wan_returns"));
    json_object_object_add(cap, "objects_list", json_object_new_boolean(1));
    /*
     * objects_crud and objects_atomic_apply are both true: composite objects
     * can be created, edited and deleted through /api/v1/policy-engine/objects,
     * and enabled objects with components trigger a cross-component atomic
     * transaction spanning firewall / PBR / SQM / flowd.
     */
    json_object_object_add(cap, "objects_crud", json_object_new_boolean(1));
    json_object_object_add(cap, "objects_atomic_apply", json_object_new_boolean(1));
    /*
     * objects_crud here is the COMPOSITE object catalog spanning firewall, PBR, SQM
     * and flowd. routed reports object_crud=1 for a different resource: its own
     * route_object table, which really is writable. Both readings were correct and
     * the interface gave no way to tell them apart, so the scope is now explicit
     * and each side points at the other's write endpoint.
     */
    json_object_object_add(cap, "objects_crud_scope",
                           json_object_new_string("policy_engine:composite_object"));
    json_object_object_add(cap, "route_object_crud", json_object_new_boolean(1));
    json_object_object_add(cap, "route_object_crud_scope",
                           json_object_new_string("routed:route_object"));
    json_object_object_add(cap, "route_object_crud_owner", json_object_new_string("routed"));
    json_object_object_add(cap, "route_object_write_endpoint",
                           json_object_new_string("/api/v1/routing/objects"));
    return cap;
}

static void webd_policy_add_affected_file(struct json_object *arr,
                                          const char *path,
                                          const char *role)
{
    struct json_object *o;

    if (!arr || !json_object_is_type(arr, json_type_array) || !path || !path[0])
        return;
    o = json_object_new_object();
    webd_obj_add_str(o, "path", path);
    webd_obj_add_str(o, "role", role);
    json_object_object_add(o, "readable", json_object_new_boolean(access(path, R_OK) == 0));
    json_object_object_add(o, "writable", json_object_new_boolean(access(path, W_OK) == 0));
    json_object_array_add(arr, o);
}

int webd_policy_value_is_any(const char *s)
{
    if (!s || !s[0])
        return 1;
    return !strcmp(s, "-") || !strcmp(s, "*") ||
           !strcasecmp(s, "any") || !strcasecmp(s, "all") ||
           !strcmp(s, "任何") || !strcmp(s, "全部");
}

int webd_policy_value_safe(const char *s)
{
    size_t i;

    if (!s)
        return 1;
    if (strlen(s) > 512)
        return 0;
    for (i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7f)
            return 0;
    }
    return 1;
}

static int webd_policy_json_value_to_string(struct json_object *v, char *out, size_t out_len)
{
    int i, n;

    if (!out || out_len == 0)
        return 0;
    out[0] = '\0';
    if (!v)
        return 0;
    if (json_object_is_type(v, json_type_array)) {
        n = json_object_array_length(v);
        for (i = 0; i < n; i++) {
            char one[256];
            struct json_object *item = json_object_array_get_idx(v, i);
            if (webd_policy_json_value_to_string(item, one, sizeof(one)) && one[0])
                webd_policy_append(out, out_len, one);
        }
        return out[0] ? 1 : 0;
    }
    if (json_object_is_type(v, json_type_object)) {
        static const char *obj_keys[] = {
            "value", "id", "key", "name", "label", "display_name",
            "address", "ip", "mac", "port", "zone", "network"
        };
        size_t k;

        for (k = 0; k < sizeof(obj_keys) / sizeof(obj_keys[0]); k++) {
            struct json_object *child = NULL;
            if (json_object_object_get_ex(v, obj_keys[k], &child) && child &&
                webd_policy_json_value_to_string(child, out, out_len) && out[0])
                return 1;
        }
        return 0;
    }
    snprintf(out, out_len, "%s", json_object_get_string(v) ? json_object_get_string(v) : "");
    return out[0] ? 1 : 0;
}

int webd_policy_body_string_any(struct json_object *body, const char **keys,
                                       char *out, size_t out_len)
{
    size_t i;

    if (!out || out_len == 0)
        return 0;
    out[0] = '\0';
    if (!body || !keys)
        return 0;
    for (i = 0; keys[i]; i++) {
        struct json_object *v = NULL;
        if (json_object_object_get_ex(body, keys[i], &v) && v &&
            webd_policy_json_value_to_string(v, out, out_len))
            return 1;
    }
    return 0;
}

int webd_policy_body_bool_any(struct json_object *body, const char **keys,
                                     int def, int *present)
{
    size_t i;

    if (present)
        *present = 0;
    if (!body || !keys)
        return def;
    for (i = 0; keys[i]; i++) {
        struct json_object *v = NULL;
        if (json_object_object_get_ex(body, keys[i], &v) && v) {
            if (present)
                *present = 1;
            return json_object_get_boolean(v);
        }
    }
    return def;
}

int webd_policy_query_or_body_bool(const struct http_req *req,
                                          struct json_object *body,
                                          const char *key,
                                          int def)
{
    char q[32] = "";

    if (req && webd_query_get(req->query, key, q, sizeof(q)))
        return webd_policy_str_true(q);
    if (body && app_nc_json_has(body, key))
        return app_nc_json_bool(body, key, def);
    return def;
}

static int webd_policy_write_apply_requested(const struct http_req *req,
                                             struct json_object *body)
{
    if (req && strstr(req->path, "/preview"))
        return 0;
    if (webd_policy_query_or_body_bool(req, body, "apply", 0))
        return 1;
    return 0;
}

void webd_policy_zone_to_uci(const char *in, char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (webd_policy_value_is_any(in))
        return;
    if (!strcmp(in, "内部") || !strcasecmp(in, "internal") || !strcasecmp(in, "lan"))
        snprintf(out, out_len, "lan");
    else if (!strcmp(in, "外部") || !strcasecmp(in, "internet") || !strcasecmp(in, "external") ||
             !strcasecmp(in, "wan"))
        snprintf(out, out_len, "wan");
    else
        snprintf(out, out_len, "%s", in);
}

const char *webd_policy_action_to_target(const char *action)
{
    const char *key = webd_policy_action_key_from_target(action);

    if (!strcmp(key, "allow"))
        return "ACCEPT";
    if (!strcmp(key, "block"))
        return "DROP";
    if (!strcmp(key, "reject"))
        return "REJECT";
    return "";
}

int webd_policy_copy_file(const char *src, const char *dst, char *err, size_t err_len)
{
    FILE *in;
    FILE *out;
    char buf[8192];
    size_t n;
    int rc = -1;

    in = fopen(src, "rb");
    if (!in) {
        if (err && err_len)
            snprintf(err, err_len, "open %s failed: %s", src, strerror(errno));
        return -1;
    }
    out = fopen(dst, "wb");
    if (!out) {
        if (err && err_len)
            snprintf(err, err_len, "open %s failed: %s", dst, strerror(errno));
        fclose(in);
        return -1;
    }
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            if (err && err_len)
                snprintf(err, err_len, "write %s failed: %s", dst, strerror(errno));
            goto out;
        }
    }
    if (ferror(in)) {
        if (err && err_len)
            snprintf(err, err_len, "read %s failed: %s", src, strerror(errno));
        goto out;
    }
    rc = 0;
out:
    fclose(out);
    fclose(in);
    return rc;
}

int webd_policy_run_cmd(const char *cmd)
{
    int rc;

    if (!cmd || !cmd[0])
        return -1;
    rc = system(cmd);
    if (rc == -1)
        return -1;
    if (WIFEXITED(rc))
        return WEXITSTATUS(rc);
    return rc;
}

int webd_policy_uci_set_option(struct uci_context *ctx,
                                      const char *section,
                                      const char *option,
                                      const char *value,
                                      int delete_if_empty,
                                      char *err, size_t err_len)
{
    return webd_policy_uci_set_pkg_option(ctx, "firewall", section, option,
                                          value, delete_if_empty, err, err_len);
}

int webd_policy_db_exec(sqlite3 *db, const char *sql, char *err, size_t err_len)
{
    char *sql_err = NULL;
    int rc;

    if (!db || !sql)
        return -1;
    rc = sqlite3_exec(db, sql, NULL, NULL, &sql_err);
    if (rc != SQLITE_OK) {
        if (err && err_len)
            snprintf(err, err_len, "sqlite exec failed: %s", sql_err ? sql_err : sqlite3_errmsg(db));
        sqlite3_free(sql_err);
        return -1;
    }
    return 0;
}

int webd_policy_uci_rename_section(struct uci_context *ctx,
                                          const char *package,
                                          const char *type,
                                          const char *new_name,
                                          char *err, size_t err_len)
{
    struct uci_ptr ptr;
    char lookup[512];
    int lookup_len;

    if (!ctx || !package || !package[0] || !type || !type[0] ||
        !new_name || !new_name[0])
        return -1;
    if (!webd_policy_value_safe(new_name)) {
        if (err && err_len)
            snprintf(err, err_len, "invalid section name: %s", new_name);
        return -1;
    }
    lookup_len = snprintf(lookup, sizeof(lookup), "%s.@%s[-1]=%s", package, type, new_name);
    if (lookup_len < 0 || (size_t)lookup_len >= sizeof(lookup)) {
        if (err && err_len)
            snprintf(err, err_len, "uci section rename lookup too long");
        return -1;
    }
    memset(&ptr, 0, sizeof(ptr));
    if (uci_lookup_ptr(ctx, &ptr, lookup, true) != UCI_OK) {
        if (err && err_len)
            snprintf(err, err_len, "uci section rename lookup failed");
        return -1;
    }
    if (uci_rename(ctx, &ptr) != UCI_OK) {
        if (err && err_len)
            snprintf(err, err_len, "uci section rename failed");
        return -1;
    }
    return 0;
}

int webd_policy_ip_addr_valid(const char *ip)
{
    unsigned char buf[16];

    if (!ip || !ip[0])
        return 0;
    return inet_pton(AF_INET, ip, buf) == 1 || inet_pton(AF_INET6, ip, buf) == 1;
}

int webd_policy_network_backup(char *backup, size_t backup_len,
                                      char *err, size_t err_len)
{
    time_t now = now_s();

    if (!backup || backup_len == 0)
        return -1;
    backup[0] = '\0';
    mkdir("/tmp/dreamingwrt", 0755);
    mkdir("/tmp/dreamingwrt/policy-backups", 0755);
    snprintf(backup, backup_len, "/tmp/dreamingwrt/policy-backups/network.%lld.%ld.bak",
             (long long)now, (long)getpid());
    return webd_policy_copy_file(WEBD_POLICY_CONFIG_NETWORK, backup, err, err_len);
}

int webd_policy_network_reload(struct json_object *steps,
                                      struct json_object *warnings)
{
    int rc;

    json_object_array_add(steps, json_object_new_string("reload network runtime"));
    rc = webd_policy_run_cmd("(/etc/init.d/network reload || ubus call network reload) >/tmp/dreamingwrt-policy-network-reload.log 2>&1");
    if (rc != 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "network_reload_failed_rc_%d", rc);
        json_object_array_add(warnings, json_object_new_string(msg));
        return -1;
    }
    return 0;
}

static int webd_policy_write_is_firewall_rule(const char *operation,
                                              const char *policy_type,
                                              const char *id)
{
    if (policy_type && (!strcasecmp(policy_type, "firewall") ||
                        !strcasecmp(policy_type, "防火墙") ||
                        !strcasecmp(policy_type, "rule")))
        return 1;
    if (id && (!strncmp(id, "uci-firewall-rule-", 18) || !strncmp(id, "firewall.", 9)))
        return 1;
    if (id && id[0] && operation &&
        (!strcmp(operation, "update") || !strcmp(operation, "delete") ||
         !strcmp(operation, "enable") || !strcmp(operation, "disable")))
        return webd_policy_firewall_section_is_type(id, "rule");
    return operation && !strcmp(operation, "create") && (!policy_type || !policy_type[0]);
}

static int webd_policy_write_is_port_forwarding(const char *operation,
                                                const char *policy_type,
                                                const char *id)
{
    if (policy_type && (!strcasecmp(policy_type, "port_forwarding") ||
                        !strcasecmp(policy_type, "port-forwarding") ||
                        !strcasecmp(policy_type, "port_forward") ||
                        !strcasecmp(policy_type, "redirect") ||
                        !strcasecmp(policy_type, "端口转发")))
        return 1;
    if (id && (!strncmp(id, "uci-firewall-redirect-", 22) || !strncmp(id, "redirect.", 9)))
        return 1;
    if (id && id[0] && operation &&
        (!strcmp(operation, "update") || !strcmp(operation, "delete") ||
         !strcmp(operation, "enable") || !strcmp(operation, "disable")))
        return webd_policy_firewall_section_is_type(id, "redirect");
    return 0;
}

static int webd_policy_write_is_dns(const char *operation,
                                    const char *policy_type,
                                    const char *id)
{
    if (id && !strncmp(id, "network_control.", 16))
        return 0;
    if (policy_type && (!strcasecmp(policy_type, "dns") ||
                        !strcasecmp(policy_type, "static_dns") ||
                        !strcasecmp(policy_type, "domain") ||
                        !strcasecmp(policy_type, "cname") ||
                        !strcasecmp(policy_type, "host") ||
                        !strcasecmp(policy_type, "DNS 记录")))
        return 1;
    if (id && (!strncmp(id, "uci-dhcp-", 9) || !strncmp(id, "dns.", 4) ||
               !strncmp(id, "dhcp.", 5)))
        return 1;
    if (id && id[0] && operation &&
        (!strcmp(operation, "update") || !strcmp(operation, "delete") ||
         !strcmp(operation, "enable") || !strcmp(operation, "disable")))
        return webd_policy_dhcp_section_exists(id);
    return 0;
}

static int webd_policy_write_is_qos(const char *operation,
                                    const char *policy_type,
                                    const char *id)
{
    if (id && !strncmp(id, "network_control.", 16))
        return 0;
    if (policy_type && (!strcasecmp(policy_type, "qos") ||
                        !strcasecmp(policy_type, "sqm") ||
                        !strcasecmp(policy_type, "queue") ||
                        !strcasecmp(policy_type, "QoS") ||
                        !strcasecmp(policy_type, "限速") ||
                        !strcasecmp(policy_type, "智能队列")))
        return 1;
    if (id && (!strncmp(id, "uci-sqm-queue-", 14) || !strncmp(id, "sqm.", 4)))
        return 1;
    if (id && id[0] && operation &&
        (!strcmp(operation, "update") || !strcmp(operation, "delete") ||
         !strcmp(operation, "enable") || !strcmp(operation, "disable")))
        return webd_policy_sqm_queue_exists(id);
    return 0;
}

static int webd_policy_write_is_nat(const char *operation,
                                    const char *policy_type,
                                    const char *id)
{
    if (policy_type && (!strcasecmp(policy_type, "nat") ||
                        !strcasecmp(policy_type, "snat") ||
                        !strcasecmp(policy_type, "source_nat") ||
                        !strcasecmp(policy_type, "NAT 规则")))
        return 1;
    if (id && (!strncmp(id, "uci-firewall-nat-", 17) || !strncmp(id, "nat.", 4)))
        return 1;
    if (id && id[0] && operation &&
        (!strcmp(operation, "update") || !strcmp(operation, "delete") ||
         !strcmp(operation, "enable") || !strcmp(operation, "disable")))
        return webd_policy_firewall_section_is_type(id, "nat");
    return 0;
}

static int webd_policy_write_is_static_route(const char *operation,
                                             const char *policy_type,
                                             const char *id)
{
    if (policy_type && (!strcasecmp(policy_type, "static_route") ||
                        !strcasecmp(policy_type, "static-route") ||
                        !strcasecmp(policy_type, "route") ||
                        !strcasecmp(policy_type, "route6") ||
                        !strcasecmp(policy_type, "静态路由")))
        return 1;
    if (id && (!strncmp(id, "uci-network-route-", 18) ||
               !strncmp(id, "uci-network-route6-", 19) ||
               !strncmp(id, "route.", 6) || !strncmp(id, "network.", 8)))
        return 1;
    if (id && id[0] && operation &&
        (!strcmp(operation, "update") || !strcmp(operation, "delete") ||
         !strcmp(operation, "enable") || !strcmp(operation, "disable")))
        return webd_policy_network_route_exists(id);
    return 0;
}

static int webd_policy_write_is_pbr(const char *operation,
                                    const char *policy_type,
                                    const char *id)
{
    if (policy_type && (!strcasecmp(policy_type, "pbr") ||
                        !strcasecmp(policy_type, "policy_route") ||
                        !strcasecmp(policy_type, "policy-route") ||
                        !strcasecmp(policy_type, "traffic_route") ||
                        !strcasecmp(policy_type, "route_policy") ||
                        !strcasecmp(policy_type, "基于策略的路由") ||
                        !strcasecmp(policy_type, "策略路由")))
        return 1;
    if (id && (!strncmp(id, "policy_route_rule.", 18) ||
               !strncmp(id, "pbr.", 4) ||
               !strncmp(id, "uci-pbr-policy-", 15) ||
               !strncmp(id, "flowd-split_rules_get-", 22) ||
               !strncmp(id, "adv:", 4)))
        return 1;
    if (id && id[0] && operation &&
        (!strcmp(operation, "update") || !strcmp(operation, "delete") ||
         !strcmp(operation, "enable") || !strcmp(operation, "disable")))
        return webd_policy_pbr_rule_exists(id);
    return 0;
}

static int webd_policy_write_is_acl(const char *operation,
                                    const char *policy_type,
                                    const char *id,
                                    struct json_object *body)
{
    const char *acl_type = app_nc_json_str(body, "acl_type", "");
    char id_type[64] = "";
    char raw_id[128] = "";

    (void)operation;
    if (id && webd_policy_acl_parse_id(id, id_type, sizeof(id_type), raw_id, sizeof(raw_id)))
        return webd_policy_acl_type_supported(id_type);
    return policy_type && (!strcasecmp(policy_type, "acl") ||
                           !strcasecmp(policy_type, "ACL") ||
                           !strcmp(policy_type, "ACL 规则")) &&
           webd_policy_acl_type_supported(acl_type);
}

static const struct webd_policy_reorder_scope *webd_policy_reorder_scope_by_type(const char *policy_type)
{
    size_t i;

    if (!policy_type || !policy_type[0])
        return NULL;
    for (i = 0; i < ARRAY_SIZE(webd_policy_reorder_scopes); i++) {
        const struct webd_policy_reorder_scope *sc = &webd_policy_reorder_scopes[i];

        if (!strcasecmp(policy_type, sc->policy_type))
            return sc;
    }
    if (!strcasecmp(policy_type, "port-forwarding") ||
        !strcasecmp(policy_type, "portforward") ||
        !strcasecmp(policy_type, "port_forward"))
        return webd_policy_reorder_scope_by_type("port_forwarding");
    if (!strcasecmp(policy_type, "static-route") || !strcasecmp(policy_type, "route"))
        return webd_policy_reorder_scope_by_type("static_route");
    if (!strcasecmp(policy_type, "sqm") || !strcasecmp(policy_type, "qos_sqm"))
        return webd_policy_reorder_scope_by_type("qos");
    return NULL;
}

static const struct webd_policy_reorder_scope *webd_policy_reorder_scope_by_id(const char *id)
{
    size_t i, p;

    if (!id || !id[0])
        return NULL;
    for (i = 0; i < ARRAY_SIZE(webd_policy_reorder_scopes); i++) {
        const struct webd_policy_reorder_scope *sc = &webd_policy_reorder_scopes[i];

        for (p = 0; p < ARRAY_SIZE(sc->id_prefixes); p++) {
            const char *prefix = sc->id_prefixes[p];

            if (!prefix)
                break;
            if (!strncmp(id, prefix, strlen(prefix)))
                return sc;
        }
    }
    return NULL;
}

static int webd_policy_reorder_scope_has_type(const struct webd_policy_reorder_scope *sc,
                                              const char *type)
{
    size_t i;

    if (!sc || !type)
        return 0;
    for (i = 0; i < ARRAY_SIZE(sc->types); i++) {
        if (!sc->types[i])
            break;
        if (!strcmp(type, sc->types[i]))
            return 1;
    }
    return 0;
}

static struct uci_section *webd_policy_reorder_find_section(struct uci_package *pkg,
                                                            const struct webd_policy_reorder_scope *sc,
                                                            const char *id)
{
    struct uci_element *e;
    int scope_no = 0;      /* index among participating types only */
    int global_no = 0;     /* index among all sections of the package */

    if (!pkg || !sc || !id || !id[0])
        return NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (!s || !s->type)
            continue;
        global_no++;
        if (!webd_policy_reorder_scope_has_type(sc, s->type))
            continue;
        scope_no++;
        if (!strcmp(sc->package, "firewall")) {
            /* firewall/network rows number sections across the whole package */
            if (webd_policy_firewall_rule_id_match(s, id, global_no))
                return s;
        } else if (!strcmp(sc->package, "network")) {
            if (webd_policy_network_route_id_match(s, id, scope_no))
                return s;
        } else if (!strcmp(sc->package, "dhcp")) {
            if (webd_policy_dhcp_section_id_match(s, id, scope_no))
                return s;
        } else if (!strcmp(sc->package, "sqm")) {
            if (webd_policy_sqm_queue_id_match(s, id, scope_no))
                return s;
        }
    }
    return NULL;
}

static int webd_policy_reorder_position_of(struct uci_package *pkg,
                                            struct uci_section *target)
{
    struct uci_element *e;
    int pos = 0;

    if (!pkg || !target)
        return -1;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (s == target)
            return pos;
        pos++;
    }
    return -1;
}

static int webd_policy_reorder_collect_all(struct uci_package *pkg,
                                           struct uci_section **sections,
                                           int max_sections)
{
    struct uci_element *e;
    int n = 0;

    if (!pkg || !sections || max_sections <= 0)
        return -1;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (!s)
            continue;
        if (n >= max_sections)
            return -1;
        sections[n++] = s;
    }
    return n;
}

static int webd_policy_reorder_collect_slots(struct uci_package *pkg,
                                              const struct webd_policy_reorder_scope *sc,
                                              int *slots, int max_slots)
{
    struct uci_element *e;
    int pos = 0;
    int n = 0;

    if (!pkg || !sc || !slots || max_slots <= 0)
        return 0;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (!s || !s->type) {
            pos++;
            continue;
        }
        if (webd_policy_reorder_scope_has_type(sc, s->type)) {
            if (n >= max_slots)
                return -1;
            slots[n++] = pos;
        }
        pos++;
    }
    return n;
}

static char *webd_policy_reorder_backup_path(const struct webd_policy_reorder_scope *sc,
                                             char *out, size_t out_len)
{
    time_t now = now_s();

    if (!out || out_len == 0)
        return NULL;
    out[0] = '\0';
    if (!sc)
        return out;
    mkdir("/tmp/dreamingwrt", 0755);
    mkdir("/tmp/dreamingwrt/policy-backups", 0755);
    snprintf(out, out_len, "/tmp/dreamingwrt/policy-backups/%s.reorder.%lld.%ld.bak",
             sc->package, (long long)now, (long)getpid());
    return out;
}

static int webd_policy_reorder_config_validate(const struct webd_policy_reorder_scope *sc,
                                                struct json_object *steps,
                                                struct json_object *warnings,
                                                char *err, size_t err_len)
{
    if (!sc)
        return -1;
    if (!strcmp(sc->package, "firewall"))
        return webd_policy_firewall_validate(steps, warnings, err, err_len);
    /* network/dhcp/sqm have no offline syntax checker comparable to fw4 check;
     * report it instead of pretending the change was validated. */
    json_object_array_add(warnings,
        json_object_new_string("reorder_offline_validator_unavailable"));
    json_object_array_add(steps,
        json_object_new_string("no offline validator for this package; UCI commit accepted without external validation"));
    return 0;
}

static int webd_policy_reorder_runtime_reload(const struct webd_policy_reorder_scope *sc,
                                               const struct http_req *req,
                                               struct json_object *body,
                                               struct json_object *steps,
                                               struct json_object *warnings,
                                               struct json_object *tx)
{
    int requested;

    if (!sc)
        return 0;
    if (!strcmp(sc->package, "firewall")) {
        requested = webd_policy_query_or_body_bool(req, body, "reload_firewall", 1);
        json_object_object_add(tx, "reload_requested", json_object_new_boolean(requested));
        if (requested)
            return webd_policy_firewall_reload(steps, warnings);
        return 0;
    }
    if (!strcmp(sc->package, "dhcp")) {
        requested = webd_policy_query_or_body_bool(req, body, "reload_dnsmasq", 1);
        json_object_object_add(tx, "reload_requested", json_object_new_boolean(requested));
        if (requested)
            return webd_policy_dnsmasq_reload(steps, warnings);
        return 0;
    }
    if (!strcmp(sc->package, "network")) {
        /* default off: reordering routes should not risk the management path */
        requested = webd_policy_query_or_body_bool(req, body, "reload_network", 0);
        json_object_object_add(tx, "reload_requested", json_object_new_boolean(requested));
        if (requested)
            return webd_policy_network_reload(steps, warnings);
        return 0;
    }
    if (!strcmp(sc->package, "sqm")) {
        requested = webd_policy_query_or_body_bool(req, body, "reload_sqm", 0);
        json_object_object_add(tx, "reload_requested", json_object_new_boolean(requested));
        if (requested)
            return webd_policy_sqm_reload(steps, warnings);
        return 0;
    }
    return 0;
}

static struct json_object *webd_policy_uci_reorder_response(const struct http_req *req,
                                                            struct json_object *body,
                                                            const struct webd_policy_reorder_scope *sc,
                                                            struct json_object *input,
                                                            int apply_requested,
                                                            int *http_status)
{
    struct json_object *data = json_object_new_object();
    struct json_object *ordered = json_object_new_array();
    struct json_object *steps = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *tx = json_object_new_object();
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *targets[WEBD_POLICY_REORDER_MAX];
    struct uci_section *desired[WEBD_POLICY_REORDER_PACKAGE_MAX];
    int slots[WEBD_POLICY_REORDER_MAX];
    char backup[256] = "";
    char err[512] = "";
    int n = json_object_array_length(input);
    int scope_total = 0;
    int slot_count = 0;
    int package_count = 0;
    int lock_fd = -1;
    int i, ok = 0;

    if (n <= 0 || n > WEBD_POLICY_REORDER_MAX) {
        if (http_status) *http_status = 400;
        json_object_put(ordered); json_object_put(steps);
        json_object_put(warnings); json_object_put(tx);
        webd_obj_add_str(data, "error", "invalid_request");
        webd_obj_add_str(data, "message", "ids/order/items must be a non-empty array within 512 entries");
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        return webd_envelope(data, "webd.policy_engine.uci_reorder");
    }

    if (apply_requested) {
        mkdir("/tmp/dreamingwrt", 0755);
        lock_fd = open(WEBD_POLICY_REORDER_LOCK, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
        if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
            if (http_status) *http_status = errno == EWOULDBLOCK ? 409 : 500;
            json_object_put(ordered); json_object_put(steps);
            json_object_put(warnings); json_object_put(tx);
            webd_obj_add_str(data, "error",
                errno == EWOULDBLOCK ? "policy_write_busy" : "policy_write_lock_failed");
            webd_obj_add_str(data, "message",
                errno == EWOULDBLOCK ? "another policy reorder transaction is in progress" :
                                       "unable to acquire policy reorder transaction lock");
            json_object_object_add(data, "ok", json_object_new_boolean(0));
            if (lock_fd >= 0)
                close(lock_fd);
            return webd_envelope(data, "webd.policy_engine.uci_reorder");
        }
    }

    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, sc->package, &pkg) != UCI_OK || !pkg) {
        if (http_status) *http_status = 503;
        json_object_put(ordered); json_object_put(steps);
        json_object_put(warnings); json_object_put(tx);
        webd_obj_add_str(data, "error", "source_unavailable");
        webd_obj_add_str(data, "message", "unable to load UCI package for reorder");
        webd_obj_add_str(data, "package", sc->package);
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        if (ctx) uci_free_context(ctx);
        if (lock_fd >= 0) {
            flock(lock_fd, LOCK_UN);
            close(lock_fd);
        }
        return webd_envelope(data, "webd.policy_engine.uci_reorder");
    }

    slot_count = webd_policy_reorder_collect_slots(pkg, sc, slots, WEBD_POLICY_REORDER_MAX);
    if (slot_count < 0) {
        if (http_status) *http_status = 409;
        json_object_put(ordered); json_object_put(steps);
        json_object_put(warnings); json_object_put(tx);
        webd_obj_add_str(data, "error", "reorder_scope_too_large");
        webd_obj_add_str(data, "message", "too many sections of this type to reorder safely");
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        uci_unload(ctx, pkg);
        uci_free_context(ctx);
        if (lock_fd >= 0) {
            flock(lock_fd, LOCK_UN);
            close(lock_fd);
        }
        return webd_envelope(data, "webd.policy_engine.uci_reorder");
    }
    scope_total = slot_count;
    package_count = webd_policy_reorder_collect_all(
        pkg, desired, WEBD_POLICY_REORDER_PACKAGE_MAX);
    if (package_count < 0) {
        if (http_status) *http_status = 409;
        json_object_put(ordered); json_object_put(steps);
        json_object_put(warnings); json_object_put(tx);
        webd_obj_add_str(data, "error", "reorder_package_too_large");
        webd_obj_add_str(data, "message", "UCI package contains too many sections to reorder safely");
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        uci_unload(ctx, pkg);
        uci_free_context(ctx);
        if (lock_fd >= 0) {
            flock(lock_fd, LOCK_UN);
            close(lock_fd);
        }
        return webd_envelope(data, "webd.policy_engine.uci_reorder");
    }

    /* Resolve every requested id, rejecting cross-scope, unknown and
     * duplicate rows before touching the config. */
    for (i = 0; i < n; i++) {
        struct json_object *item = json_object_array_get_idx(input, i);
        const char *id = json_object_is_type(item, json_type_string) ?
                         json_object_get_string(item) : app_nc_json_str(item, "id", "");
        const struct webd_policy_reorder_scope *item_scope;
        struct uci_section *s;
        int j;

        item_scope = webd_policy_reorder_scope_by_id(id);
        if (!item_scope || item_scope != sc) {
            if (http_status) *http_status = 409;
            webd_obj_add_str(data, "error", "reorder_scope_conflict");
            webd_obj_add_str(data, "message", "all reordered rows must belong to the same policy source");
            webd_obj_add_str(data, "unsupported_id", id ? id : "");
            webd_obj_add_str(data, "supported_scope", sc->scope_label);
            goto fail;
        }
        s = webd_policy_reorder_find_section(pkg, sc, id);
        if (!s) {
            if (http_status) *http_status = 404;
            webd_obj_add_str(data, "error", "policy_not_found");
            webd_obj_add_str(data, "message", "policy row not found in current configuration");
            webd_obj_add_str(data, "policy_id", id ? id : "");
            goto fail;
        }
        for (j = 0; j < i; j++) {
            if (targets[j] == s) {
                if (http_status) *http_status = 400;
                webd_obj_add_str(data, "error", "invalid_request");
                webd_obj_add_str(data, "message", "duplicate policy id in reorder request");
                webd_obj_add_str(data, "policy_id", id ? id : "");
                goto fail;
            }
        }
        targets[i] = s;
        json_object_array_add(ordered, json_object_new_string(id ? id : ""));
    }

    /* Partial reorder would leave the remaining rows' relative order
     * ambiguous, so require the full same-source set. */
    if (n != scope_total) {
        if (http_status) *http_status = 409;
        webd_obj_add_str(data, "error", "reorder_incomplete_scope");
        webd_obj_add_str(data, "message", "reorder must include every row of this policy source");
        json_object_object_add(data, "expected_count", json_object_new_int(scope_total));
        json_object_object_add(data, "received_count", json_object_new_int(n));
        webd_obj_add_str(data, "supported_scope", sc->scope_label);
        goto fail;
    }

    if (!apply_requested) {
        struct json_object *preview = json_object_new_object();

        if (http_status) *http_status = 409;
        json_object_object_add(preview, "can_apply", json_object_new_boolean(1));
        json_object_object_add(preview, "applies_changes", json_object_new_boolean(0));
        json_object_object_add(preview, "apply_requires_explicit_apply_true", json_object_new_boolean(1));
        webd_obj_add_str(preview, "policy_type", sc->policy_type);
        webd_obj_add_str(preview, "scope", sc->scope_label);
        webd_obj_add_str(preview, "config_path", sc->config_path);
        json_object_object_add(preview, "section_count", json_object_new_int(scope_total));
        json_object_object_add(preview, "ordered_ids", json_object_get(ordered));
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        webd_obj_add_str(data, "error", "policy_write_preview_only");
        webd_obj_add_str(data, "message", "add apply=true to execute transactional UCI reorder");
        json_object_object_add(data, "preview", preview);
        json_object_object_add(data, "capabilities", webd_policy_capabilities());
        json_object_put(ordered);
        json_object_put(steps);
        json_object_put(warnings);
        json_object_put(tx);
        uci_unload(ctx, pkg);
        uci_free_context(ctx);
        if (lock_fd >= 0) {
            flock(lock_fd, LOCK_UN);
            close(lock_fd);
        }
        return webd_envelope(data, "webd.policy_engine.uci_reorder_preview");
    }

    json_object_array_add(steps, json_object_new_string("backup config"));
    if (webd_policy_copy_file(sc->config_path,
                              webd_policy_reorder_backup_path(sc, backup, sizeof(backup)),
                              err, sizeof(err)) != 0) {
        if (http_status) *http_status = 500;
        webd_obj_add_str(data, "error", "policy_reorder_backup_failed");
        webd_obj_add_str(data, "message", err[0] ? err : "unable to back up config");
        goto fail_tx;
    }
    webd_obj_add_str(tx, "backup_path", backup);

    /* Build the complete desired package order. Only the slots occupied by
     * this scope are replaced; every foreign section remains at its original
     * absolute position. Applying the complete order avoids list-shift side
     * effects from moving only participating sections. */
    for (i = 0; i < n; i++) {
        if (slots[i] < 0 || slots[i] >= package_count) {
            if (http_status) *http_status = 500;
            snprintf(err, sizeof(err), "invalid reorder slot at index %d", i);
            webd_obj_add_str(data, "error", "policy_reorder_failed");
            webd_obj_add_str(data, "message", err);
            goto fail_restore;
        }
        desired[slots[i]] = targets[i];
    }
    for (i = 0; i < package_count; i++) {
        int current = webd_policy_reorder_position_of(pkg, desired[i]);

        if (current < 0) {
            if (http_status) *http_status = 500;
            snprintf(err, sizeof(err), "section disappeared before reorder index %d", i);
            webd_obj_add_str(data, "error", "policy_reorder_failed");
            webd_obj_add_str(data, "message", err);
            goto fail_restore;
        }
        if (current == i)
            continue;
        if (uci_reorder_section(ctx, desired[i], i) != UCI_OK) {
            if (http_status) *http_status = 500;
            snprintf(err, sizeof(err), "uci_reorder_section failed at package index %d", i);
            webd_obj_add_str(data, "error", "policy_reorder_failed");
            webd_obj_add_str(data, "message", err);
            goto fail_restore;
        }
    }
    json_object_array_add(steps,
        json_object_new_string("uci reorder complete package sequence while preserving foreign section slots"));

    if (uci_save(ctx, pkg) != UCI_OK) {
        if (http_status) *http_status = 500;
        webd_obj_add_str(data, "error", "policy_reorder_failed");
        webd_obj_add_str(data, "message", "uci_save failed");
        goto fail_restore;
    }
    if (uci_commit(ctx, &pkg, false) != UCI_OK) {
        if (http_status) *http_status = 500;
        webd_obj_add_str(data, "error", "policy_reorder_failed");
        webd_obj_add_str(data, "message", "uci_commit failed");
        goto fail_restore;
    }
    json_object_array_add(steps, json_object_new_string("uci commit"));

    if (webd_policy_reorder_config_validate(sc, steps, warnings, err, sizeof(err)) != 0) {
        if (http_status) *http_status = 400;
        webd_obj_add_str(data, "error", "policy_reorder_validation_failed");
        webd_obj_add_str(data, "message", err[0] ? err : "config validation failed after reorder");
        goto fail_restore;
    }

    if (webd_policy_reorder_runtime_reload(sc, req, body, steps, warnings, tx) != 0) {
        if (http_status) *http_status = 500;
        webd_obj_add_str(data, "error", "policy_reorder_runtime_reload_failed");
        webd_obj_add_str(data, "message", "runtime reload failed after reorder; restoring config backup");
        goto fail_restore;
    }
    ok = 1;
    if (http_status) *http_status = 200;
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    webd_obj_add_str(data, "policy_type", sc->policy_type);
    webd_obj_add_str(data, "scope", sc->scope_label);
    json_object_object_add(data, "ordered_ids", json_object_get(ordered));
    json_object_object_add(data, "refresh_required", json_object_new_boolean(1));
    json_object_object_add(data, "row_ids_may_change", json_object_new_boolean(1));
    json_object_object_add(tx, "steps", json_object_get(steps));
    json_object_object_add(tx, "warnings", json_object_get(warnings));
    webd_obj_add_str(tx, "config_path", sc->config_path);
    json_object_object_add(tx, "section_count", json_object_new_int(scope_total));
    json_object_object_add(data, "transaction", json_object_get(tx));
    json_object_object_add(data, "capabilities", webd_policy_capabilities());

fail_restore:
    if (!ok && backup[0]) {
        json_object_array_add(steps,
            json_object_new_string("restore config from backup after failed reorder"));
        if (webd_policy_copy_file(backup, sc->config_path, NULL, 0) == 0)
            json_object_array_add(warnings,
                json_object_new_string("config_restored_from_backup"));
        else
            json_object_array_add(warnings,
                json_object_new_string("config_restore_failed"));
        /* If the failed transaction attempted a runtime reload, make a
         * best-effort reload of the restored configuration as well. */
        if (app_nc_json_bool(tx, "reload_requested", 0)) {
            if (webd_policy_reorder_runtime_reload(sc, req, body, steps, warnings, tx) != 0)
                json_object_array_add(warnings,
                    json_object_new_string("restored_config_runtime_reload_failed"));
            else
                json_object_array_add(warnings,
                    json_object_new_string("restored_config_runtime_reloaded"));
        }
    }
fail_tx:
    if (!ok) {
        json_object_object_add(tx, "steps", json_object_get(steps));
        json_object_object_add(tx, "warnings", json_object_get(warnings));
        webd_obj_add_str(tx, "config_path", sc->config_path);
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        webd_obj_add_str(data, "policy_type", sc->policy_type);
        webd_obj_add_str(data, "scope", sc->scope_label);
        json_object_object_add(data, "transaction", json_object_get(tx));
        json_object_object_add(data, "capabilities", webd_policy_capabilities());
    }
    json_object_put(ordered);
    json_object_put(steps);
    json_object_put(warnings);
    json_object_put(tx);
    if (pkg)
        uci_unload(ctx, pkg);
    uci_free_context(ctx);
    if (lock_fd >= 0) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
    }
    return webd_envelope(data, "webd.policy_engine.uci_reorder");

fail:
    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "applied", json_object_new_boolean(0));
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    json_object_put(ordered);
    json_object_put(steps);
    json_object_put(warnings);
    json_object_put(tx);
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    if (lock_fd >= 0) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
    }
    return webd_envelope(data, "webd.policy_engine.uci_reorder");
}

static struct json_object *webd_policy_reorder_response(const struct http_req *req,
                                                        struct json_object *body,
                                                        int apply_requested,
                                                        int *http_status)
{
    struct json_object *input = NULL;
    const struct webd_policy_reorder_scope *sc = NULL;
    const char *policy_type;

    if (!body || !json_object_is_type(body, json_type_object))
        return webd_policy_pbr_reorder_response(body, apply_requested, http_status);

    policy_type = app_nc_json_str(body, "policy_type",
                  app_nc_json_str(body, "type", ""));
    if (policy_type[0])
        sc = webd_policy_reorder_scope_by_type(policy_type);

    if (!json_object_object_get_ex(body, "ids", &input) &&
        !json_object_object_get_ex(body, "order", &input) &&
        !json_object_object_get_ex(body, "policy_ids", &input) &&
        !json_object_object_get_ex(body, "items", &input))
        input = NULL;

    /* If policy_type is absent, infer the scope from the first row id so the
     * frontend can reorder without restating the type. */
    if (!sc && !policy_type[0] && input && json_object_is_type(input, json_type_array) &&
        json_object_array_length(input) > 0) {
        struct json_object *item = json_object_array_get_idx(input, 0);
        const char *id = json_object_is_type(item, json_type_string) ?
                         json_object_get_string(item) : app_nc_json_str(item, "id", "");

        sc = webd_policy_reorder_scope_by_id(id);
    }

    if (!sc)
        return webd_policy_pbr_reorder_response(body, apply_requested, http_status);

    if (!input || !json_object_is_type(input, json_type_array)) {
        struct json_object *data = json_object_new_object();

        if (http_status) *http_status = 400;
        webd_obj_add_str(data, "error", "invalid_request");
        webd_obj_add_str(data, "message", "ids/order/items must be a non-empty array");
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        return webd_envelope(data, "webd.policy_engine.uci_reorder");
    }
    return webd_policy_uci_reorder_response(req, body, sc, input,
                                            apply_requested, http_status);
}

static struct json_object *webd_policy_write_preview_response(const struct http_req *req,
                                                              struct json_object *body,
                                                              int *http_status)
{
    struct json_object *data = json_object_new_object();
    struct json_object *preview = json_object_new_object();
    struct json_object *affected = json_object_new_array();
    struct json_object *blocked = json_object_new_array();
    struct json_object *steps = json_object_new_array();
    struct json_object *diff = json_object_new_array();
    char id[256] = "";
    const char *method = req ? req->method : "";
    const char *path = req ? req->path : "";
    const char *operation = app_nc_json_str(body, "operation", "");
    const char *policy_type = app_nc_json_str(body, "policy_type",
        app_nc_json_str(body, "type", ""));
    int apply_requested = webd_policy_write_apply_requested(req, body);
    int can_apply;

    if (http_status)
        *http_status = 409;
    if (!operation[0]) {
        if (strstr(path, "/reorder"))
            operation = "reorder";
        else if (strstr(path, "/enable"))
            operation = "enable";
        else if (strstr(path, "/disable"))
            operation = "disable";
        else if (!strcmp(method, "POST"))
            operation = "create";
        else if (!strcmp(method, "PATCH") || !strcmp(method, "PUT"))
            operation = "update";
        else if (!strcmp(method, "DELETE"))
            operation = "delete";
        else
            operation = "preview";
    }
    if (req) {
        const char *base = "/api/v1/policy-engine/policy-table/";
        size_t blen = strlen(base);
        if (!strncmp(path, base, blen)) {
            const char *tail = path + blen;
            const char *slash = strchr(tail, '/');
            size_t n = slash ? (size_t)(slash - tail) : strlen(tail);

            if (n > 0 && n < sizeof(id) && strcmp(tail, "preview") && strcmp(tail, "reorder")) {
                memcpy(id, tail, n);
                id[n] = '\0';
            }
        }
    }
    if (!id[0])
        snprintf(id, sizeof(id), "%s", app_nc_json_str(body, "id", ""));
    if (strstr(path, "/enable"))
        operation = "enable";
    else if (strstr(path, "/disable"))
        operation = "disable";
    else if (!strcmp(method, "DELETE") || strstr(path, "/delete"))
        operation = "delete";

    if (!strcmp(operation, "reorder"))
        return webd_policy_reorder_response(req, body, apply_requested, http_status);

    if (apply_requested && webd_policy_write_is_acl(operation, policy_type, id, body))
        return webd_policy_acl_apply_response(body, operation, id, http_status);
    if (apply_requested && webd_policy_write_is_dns(operation, policy_type, id))
        return webd_policy_dns_apply_response(req, body, operation, id, http_status);
    if (apply_requested && webd_policy_write_is_static_route(operation, policy_type, id))
        return webd_policy_static_route_apply_response(req, body, operation, id, http_status);
    if (apply_requested && webd_policy_write_is_pbr(operation, policy_type, id))
        return webd_policy_pbr_apply_response(req, body, operation, id, http_status);
    if (apply_requested && webd_policy_write_is_qos(operation, policy_type, id))
        return webd_policy_sqm_apply_response(req, body, operation, id, http_status);
    if (apply_requested && webd_policy_write_is_nat(operation, policy_type, id))
        return webd_policy_firewall_nat_apply_response(req, body, operation, id, http_status);
    if (apply_requested && webd_policy_write_is_port_forwarding(operation, policy_type, id))
        return webd_policy_firewall_redirect_apply_response(req, body, operation, id, http_status);
    if (apply_requested && webd_policy_write_is_firewall_rule(operation, policy_type, id))
        return webd_policy_firewall_rule_apply_response(req, body, operation, id, http_status);

    can_apply = webd_policy_write_is_acl(operation, policy_type, id, body) ||
                webd_policy_write_is_dns(operation, policy_type, id) ||
                webd_policy_write_is_static_route(operation, policy_type, id) ||
                webd_policy_write_is_pbr(operation, policy_type, id) ||
                webd_policy_write_is_qos(operation, policy_type, id) ||
                webd_policy_write_is_nat(operation, policy_type, id) ||
                webd_policy_write_is_port_forwarding(operation, policy_type, id) ||
                webd_policy_write_is_firewall_rule(operation, policy_type, id);

    webd_policy_add_affected_file(affected, WEBD_POLICY_CONFIG_FIREWALL, "firewall_rules_nat_redirect_forwarding");
    webd_policy_add_affected_file(affected, WEBD_POLICY_CONFIG_NETWORK, "static_routes_interfaces");
    webd_policy_add_affected_file(affected, WEBD_POLICY_CONFIG_DHCP, "dns_hosts_domains");
    webd_policy_add_affected_file(affected, WEBD_POLICY_CONFIG_SQM, "qos_sqm");
    webd_policy_add_affected_file(affected, "/etc/config/pbr", "policy_based_routing");
    webd_policy_add_affected_file(affected, "/etc/config/mwan3", "multi_wan_policy");
    webd_policy_add_affected_file(affected, WEBD_POLICY_CONFIG_DB, "network_control_acl");

    if (can_apply) {
        json_object_array_add(blocked, json_object_new_string("dry_run_default; send apply=true to execute guarded policy transaction"));
    } else {
        json_object_array_add(blocked, json_object_new_string("unsupported_policy_type_for_apply"));
        json_object_array_add(blocked, json_object_new_string("policy_object_model_incomplete"));
        json_object_array_add(blocked, json_object_new_string("flowd_rule_write_mapping_pending"));
    }

    json_object_array_add(steps, json_object_new_string("normalize UniFi policy form into DreamingWrt object model"));
    json_object_array_add(steps, json_object_new_string("generate UCI/flowd diff without applying it"));
    json_object_array_add(steps, json_object_new_string("snapshot affected configs and validate syntax"));
    json_object_array_add(steps, json_object_new_string("apply through guarded transaction with rollback"));
    json_object_array_add(steps, json_object_new_string("verify firewall/pbr/qos runtime and confirm"));

    json_object_array_add(diff, json_object_new_string("--- policy-engine (preview only)"));
    json_object_array_add(diff, json_object_new_string("+++ policy-engine (not applied)"));
    {
        char line[384];
        snprintf(line, sizeof(line), "+ operation: %s", operation);
        json_object_array_add(diff, json_object_new_string(line));
        snprintf(line, sizeof(line), "+ policy_type: %s", policy_type && policy_type[0] ? policy_type : "unknown");
        json_object_array_add(diff, json_object_new_string(line));
        if (id[0]) {
            snprintf(line, sizeof(line), "+ policy_id: %s", id);
            json_object_array_add(diff, json_object_new_string(line));
        }
    }

    json_object_object_add(preview, "supported", json_object_new_boolean(1));
    json_object_object_add(preview, "read_only", json_object_new_boolean(!can_apply));
    json_object_object_add(preview, "applies_changes", json_object_new_boolean(0));
    json_object_object_add(preview, "can_apply", json_object_new_boolean(can_apply));
    json_object_object_add(preview, "apply_requires_explicit_apply_true", json_object_new_boolean(1));
    json_object_object_add(preview, "operation", json_object_new_string(operation));
    json_object_object_add(preview, "id", json_object_new_string(id));
    json_object_object_add(preview, "policy_type", json_object_new_string(policy_type ? policy_type : ""));
    json_object_object_add(preview, "affected_files", affected);
    json_object_object_add(preview, "planned_steps", steps);
    json_object_object_add(preview, "dry_run_diff", diff);
    json_object_object_add(preview, "blocked_by", blocked);
    json_object_object_add(preview, "transaction_required", json_object_new_boolean(1));
    json_object_object_add(preview, "transaction_executor_available", json_object_new_boolean(can_apply));
    json_object_object_add(preview, "rollback_supported", json_object_new_boolean(can_apply));
    json_object_object_add(preview, "reason",
                           json_object_new_string(can_apply ?
                               "dry-run preview only; send apply=true to mutate policy through guarded UCI transaction" :
                               "this policy family is preview-only; no UCI/flowd mutation was applied"));
    if (body && json_object_is_type(body, json_type_object))
        json_object_object_add(preview, "request", json_object_get(body));

    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error", json_object_new_string(can_apply ?
                                                                 "policy_write_preview_only" :
                                                                 "policy_write_not_available"));
    json_object_object_add(data, "message",
                           json_object_new_string(can_apply ?
                               "Policy write dry-run preview only; add apply=true to execute" :
                               "Policy write executor is not implemented for this policy family; this response is a safe preview only"));
    json_object_object_add(data, "preview", preview);
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    return webd_envelope(data, "webd.policy_engine.write_preview");
}


static int policy_write_path(const char *path)
{
    return path &&
           (!strcmp(path, "/api/v1/policy-engine/policy-table") ||
            !strcmp(path, "/api/v1/policy-engine/policy-table/preview") ||
            !strncmp(path, "/api/v1/policy-engine/policy-table/", 35));
}

static struct json_object *policy_write_handler(struct jmx_api_ctx *ctx)
{
    return webd_policy_write_preview_response(ctx->req, ctx->body, &ctx->status);
}

const struct jmx_api_route policy_write_api_routes[] = {
    JMX_API_PREDICATE_ROUTE(142, "/api/v1/policy-engine/policy-table", "POST,PUT,PATCH,DELETE", JMX_API_PREDICATE_MIXED, policy_write_path, policy_write_handler),
    JMX_API_ROUTE_END,
};
