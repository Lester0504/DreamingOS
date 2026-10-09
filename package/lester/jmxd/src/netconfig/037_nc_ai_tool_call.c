        sqlite3_finalize(statement);
    if (error)
        sqlite3_free(error);
    return rc;
}

static struct json_object *nc_kernel_restore_response(
    int ok, const char *failed_stage, const char *reason,
    int actions_attempted, int actions_applied, int readback_verified,
    int rollback_attempted, int rollback_succeeded)
{
    struct json_object *data = json_object_new_object();

    if (ok)
        json_object_object_add(data, "ok", json_object_new_boolean(1));
    else
        json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "failed_stage",
                           json_object_new_string(failed_stage ? failed_stage : ""));
    json_object_object_add(data, "reason",
                           json_object_new_string(reason ? reason : ""));
    json_object_object_add(data, "actions_attempted",
                           json_object_new_int(actions_attempted));
    json_object_object_add(data, "actions_applied",
                           json_object_new_int(actions_applied));
    json_object_object_add(data, "readback_verified",
                           json_object_new_boolean(readback_verified));
    json_object_object_add(data, "rollback_attempted",
                           json_object_new_boolean(rollback_attempted));
    json_object_object_add(data, "rollback_succeeded",
                           json_object_new_boolean(rollback_succeeded));
    json_object_object_add(data, "message", json_object_new_string(
        ok ? "kernel parameters restored to defaults" :
             "kernel parameter restore failed"));
    json_object_object_add(data, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(ok ? API_CODE_SUCCESS : API_CODE_ERROR,
                                     data);
}

struct json_object *jmx_system_kernel_restore_defaults(struct json_object *cfg)
{
    struct nc_kernel_restore_item items[] = {
        { "net.ipv4.tcp_congestion_control", "cubic", "", 0, 0 },
        { "net.core.default_qdisc", "fq_codel", "", 0, 0 },
        { "net.ipv4.tcp_fastopen", "3", "", 0, 0 },
        { "net.ipv4.tcp_tw_reuse", "1", "", 0, 0 },
        { "net.core.somaxconn", "128", "", 0, 0 },
        { "net.ipv4.ip_forward", "1", "", 0, 0 },
        { "net.ipv6.conf.all.forwarding", "1", "", 0, 0 },
        { "net.netfilter.nf_conntrack_tcp_timeout_established", "1800", "", 0, 0 },
        { "net.netfilter.nf_conntrack_tcp_timeout_time_wait", "10", "", 0, 0 },
        { "net.netfilter.nf_conntrack_tcp_timeout_close_wait", "10", "", 0, 0 },
        { "net.netfilter.nf_conntrack_tcp_timeout_fin_wait", "10", "", 0, 0 },
        { "net.netfilter.nf_conntrack_tcp_timeout_syn_sent", "5", "", 0, 0 },
        { "net.netfilter.nf_conntrack_tcp_timeout_syn_recv", "5", "", 0, 0 },
        { "net.netfilter.nf_conntrack_tcp_timeout_last_ack", "10", "", 0, 0 },
        { "net.netfilter.nf_conntrack_tcp_timeout_close", "5", "", 0, 0 },
        { "net.netfilter.nf_conntrack_udp_timeout", "10", "", 0, 0 },
        { "net.netfilter.nf_conntrack_udp_timeout_stream", "60", "", 0, 0 },
        { "net.netfilter.nf_conntrack_icmp_timeout", "5", "", 0, 0 },
        { "net.netfilter.nf_conntrack_generic_timeout", "120", "", 0, 0 }
    };
    struct nc_kernel_restore_uci_snapshot uci_snapshot;
    struct nc_kernel_restore_file_snapshot tuning_snapshot;
    struct json_object *confirm = NULL;
    const char *failed_stage = "";
    const char *reason = "applied";
    int item_count = (int)(sizeof(items) / sizeof(items[0]));
    int actions_attempted = 0;
    int actions_applied = 0;
    int readback_verified = 0;
    int sysctl_apply_attempted = 0;
    int uci_apply_attempted = 0;
    int uci_applied = 0;
    int tuning_removed = 0;
    int tuning_mutation_attempted = 0;
    int tuning_published = 0;
    int rollback_attempted = 0;
    int rollback_succeeded = 0;
    int i;

    memset(&uci_snapshot, 0, sizeof(uci_snapshot));
    memset(&tuning_snapshot, 0, sizeof(tuning_snapshot));
    if (!cfg || !json_object_object_get_ex(cfg, "confirm", &confirm) ||
        !confirm || !json_object_is_type(confirm, json_type_boolean) ||
        !json_object_get_boolean(confirm)) {
        return nc_kernel_restore_response(0, "validation", "confirm_required",
                                          0, 0, 0, 0, 0);
    }
    if (jmx_netconfig_db_init() != 0) {
        return nc_kernel_restore_response(0, "preflight", "database_unavailable",
                                          0, 0, 0, 0, 0);
    }
    nc_sys_settings_db_init();
    if (nc_kernel_restore_tuning_snapshot(&tuning_snapshot) != 0) {
        return nc_kernel_restore_response(0, "snapshot", "tuning_snapshot_failed",
                                          0, 0, 0, 0, 0);
    }
    if (nc_kernel_restore_uci_snapshot(&uci_snapshot) != 0) {
        failed_stage = "snapshot";
        reason = "uci_snapshot_failed";
        goto failed;
    }
    for (i = 0; i < item_count; i++) {
        if (nc_kernel_restore_sysctl_read(items[i].key, items[i].old_value,
                                          sizeof(items[i].old_value)) != 0) {
            failed_stage = "snapshot";
            reason = "sysctl_snapshot_failed";
            goto failed;
        }
        items[i].old_captured = 1;
    }
    for (i = 0; i < item_count; i++) {
        actions_attempted++;
        sysctl_apply_attempted = 1;
        items[i].applied = 1;
        if (nc_kernel_restore_sysctl_write(items[i].key, items[i].value) != 0) {
            failed_stage = "runtime_apply";
            reason = "sysctl_write_or_readback_failed";
            goto failed;
        }
        actions_applied++;
    }
    readback_verified = 1;

    actions_attempted++;
    tuning_mutation_attempted = 1;
    if (nc_kernel_restore_tuning_remove(&tuning_removed) != 0) {
        failed_stage = "persistent_cleanup";
        reason = "tuning_unlink_failed";
        goto failed;
    }
    if (nc_kernel_restore_tuning_publish(items, item_count) != 0) {
        failed_stage = "persistent_publish";
        reason = "tuning_publish_or_readback_failed";
        goto failed;
    }
    tuning_published = 1;
    actions_applied++;

    actions_attempted++;
    uci_apply_attempted = 1;
    if (nc_kernel_restore_uci_apply(&uci_snapshot) != 0) {
        failed_stage = "uci_apply";
        reason = "uci_commit_or_readback_failed";
        goto failed;
    }
    uci_applied = 1;
    actions_applied++;

    if (!readback_verified || !uci_applied) {
        failed_stage = "readback";
        reason = "runtime_or_uci_not_verified";
        goto failed;
    }
    actions_attempted++;
    if (nc_kernel_restore_db_commit() != 0) {
        failed_stage = "database_commit";
        reason = "sqlite_transaction_failed";
        goto failed;
    }
    actions_applied++;
    nc_kernel_restore_file_snapshot_free(&tuning_snapshot);
    return nc_kernel_restore_response(1, "", "applied", actions_attempted,
                                      actions_applied, readback_verified, 0, 0);

failed:
    rollback_attempted = sysctl_apply_attempted || actions_applied > 0 ||
                         uci_apply_attempted ||
                         tuning_removed || tuning_mutation_attempted ||
                         tuning_published;
    if (rollback_attempted) {
        int rollback_ok = 1;

        if (uci_apply_attempted &&
            nc_kernel_restore_uci_rollback(&uci_snapshot) != 0)
            rollback_ok = 0;
        if (tuning_mutation_attempted &&
            nc_kernel_restore_tuning_rollback(&tuning_snapshot) != 0)
            rollback_ok = 0;
        if (nc_kernel_restore_sysctl_rollback(items, item_count) != 0)
            rollback_ok = 0;
        rollback_succeeded = rollback_ok;
        if (!rollback_ok)
            reason = "rollback_incomplete";
    }
    nc_kernel_restore_file_snapshot_free(&tuning_snapshot);
    return nc_kernel_restore_response(0, failed_stage, reason,
                                      actions_attempted, actions_applied,
                                      readback_verified, rollback_attempted,
                                      rollback_succeeded);
}

/* ═══ AI Tool Call ═══ */
#define NC_AI_TOOL_PARAMS_MAX (32 * 1024)
#define NC_AI_TOOL_RESULT_STORE_MAX (64 * 1024)
#define NC_AI_TOOL_AUTH_RETAIN_MAX 1000
#define NC_AI_TOOL_AUTH_RETAIN_SEC (30 * 86400)
#define NC_AI_TOOL_AUTH_PENDING_SEC 900
#define NC_AI_TOOL_AUTH_EXECUTING_SEC 120

static struct json_object *nc_ai_tool_error(const char *error, const char *message,
                                             const char *tool, const char *risk)
{
    struct json_object *d = json_object_new_object();
    json_object_object_add(d, "ok", json_object_new_boolean(0));
    json_object_object_add(d, "error", json_object_new_string(error ? error : "tool_error"));
    if (message && message[0]) json_object_object_add(d, "message", json_object_new_string(message));
    if (tool && tool[0]) json_object_object_add(d, "tool", json_object_new_string(tool));
    if (risk && risk[0]) json_object_object_add(d, "risk_level", json_object_new_string(risk));
    return jmx_gen_api_response_data(API_CODE_ERROR, d);
}

static int nc_ai_tool_result_ok(struct json_object *result)
{
    struct json_object *code = NULL;
    return result && json_object_object_get_ex(result, "code", &code) && code &&
           json_object_get_int(code) == API_CODE_SUCCESS;
}

static int nc_ai_contains_i(const char *text, const char *needle)
{
    size_t needle_len;
    if (!text || !needle || !(needle_len = strlen(needle))) return 0;
    for (; *text; text++)
        if (!strncasecmp(text, needle, needle_len)) return 1;
    return 0;
}

static int nc_ai_tool_params_sensitive(struct json_object *value)
{
    if (!value) return 0;
    if (json_object_is_type(value, json_type_array)) {
        for (int i = 0; i < json_object_array_length(value); i++)
            if (nc_ai_tool_params_sensitive(json_object_array_get_idx(value, i))) return 1;
        return 0;
    }
    if (!json_object_is_type(value, json_type_object)) return 0;
    json_object_object_foreach(value, key, child) {
        if (nc_ai_contains_i(key, "password") || nc_ai_contains_i(key, "passwd") ||
            nc_ai_contains_i(key, "api_key") || nc_ai_contains_i(key, "private_key") ||
            nc_ai_contains_i(key, "secret") || nc_ai_contains_i(key, "credential") ||
            nc_ai_contains_i(key, "token"))
            return 1;
        if (nc_ai_tool_params_sensitive(child)) return 1;
    }
    return 0;
}

static int nc_ai_sensitive_result_key(const char *key)
{
    static const char *needles[] = {
        "password", "passwd", "password_ref", "username", "api_key", "private_key",
        "secret", "credential", "token", "authorization", "cookie", "psk", NULL
    };
    for (int i = 0; key && needles[i]; i++)
        if (nc_ai_contains_i(key, needles[i])) return 1;
    return 0;
}

static struct json_object *nc_ai_tool_result_redact(struct json_object *value,
                                                     const char *key)
{
    if (key && nc_ai_sensitive_result_key(key))
        return json_object_new_string("[REDACTED]");
    if (!value) return json_object_new_null();
    if (json_object_is_type(value, json_type_object)) {
        struct json_object *copy = json_object_new_object();
        json_object_object_foreach(value, child_key, child) {
            json_object_object_add(copy, child_key,
                                   nc_ai_tool_result_redact(child, child_key));
        }
        return copy;
    }
    if (json_object_is_type(value, json_type_array)) {
        struct json_object *copy = json_object_new_array();
        for (int i = 0; i < json_object_array_length(value); i++)
            json_object_array_add(copy, nc_ai_tool_result_redact(
                json_object_array_get_idx(value, i), NULL));
        return copy;
    }
    return json_object_get(value);
}

static int nc_ai_role_allows_risk(const char *role, const char *risk)
{
    if (!role || !risk) return 0;
    if (!strcmp(risk, "high")) return !strcmp(role, "owner");
    if (!strcmp(risk, "medium"))
        return !strcmp(role, "owner") || !strcmp(role, "admin");
    return !strcmp(role, "owner") || !strcmp(role, "admin") ||
           !strcmp(role, "operator") || !strcmp(role, "ai-agent");
}

static int nc_ai_actor_ok(const char *actor)
{
    size_t len;
    if (!actor || !actor[0]) return 0;
    len = strlen(actor);
    if (len > 127) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)actor[i];
        if (c < 0x20 || c == 0x7f) return 0;
    }
    return 1;
}

static struct json_object *nc_ai_tool_dispatch(const char *tool_name,
                                                struct json_object *params)
{
    if (!strcmp(tool_name, "get_system_status")) return jmx_system_settings_get();
    if (!strcmp(tool_name, "network_overview")) return jmx_bulk_ip_get();
    if (!strcmp(tool_name, "wan_list")) return jmx_netconfig_wan_list();
    if (!strcmp(tool_name, "lan_list")) return jmx_netconfig_lan_list();
    if (!strcmp(tool_name, "dns_service_get")) return jmx_dns_service_get();
    if (!strcmp(tool_name, "upnp_service_get")) return jmx_upnp_service_get();
    if (!strcmp(tool_name, "flow_control_get")) return jmx_flow_control_get();
    if (!strcmp(tool_name, "routing_get")) return jmx_api_route_config_get(NULL);
    if (!strcmp(tool_name, "firewall_service_get")) return jmx_firewall_service_get();
    if (!strcmp(tool_name, "wan_set")) {
        int rc = jmx_netconfig_wan_set(params);
        return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, NULL);
    }
    if (!strcmp(tool_name, "lan_set")) {
        int rc = jmx_netconfig_lan_set(params);
        return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, NULL);
    }
    if (!strcmp(tool_name, "dns_service_set")) {
        return jmx_dns_service_save_apply_result(params, 1);
    }
    if (!strcmp(tool_name, "upnp_service_set")) {
        return jmx_upnp_service_save_apply_result(params);
    }
    if (!strcmp(tool_name, "flow_control_set")) {
        int rc = jmx_flow_control_set(params);
        return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, NULL);
    }
    if (!strcmp(tool_name, "firewall_service_set")) {
        int rc = jmx_firewall_service_set(params);
        return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, NULL);
    }
    if (!strcmp(tool_name, "config_apply")) {
        const char *module = nc_json_str_def(params, "module", "network");
        if (!strcmp(module, "network")) {
            int rc = jmx_netconfig_global_apply();
            return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, NULL);
        }
        if (!strcmp(module, "dns")) {
            return nc_ai_tool_error("capability_disabled",
                                    "DNS apply requires a complete transactional configuration payload",
                                    tool_name, "high");
        }
        if (!strcmp(module, "upnp")) {
            int rc = jmx_upnp_service_apply();
            return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, NULL);
        }
        if (!strcmp(module, "flow_control")) return jmx_flow_control_apply(params);
        if (!strcmp(module, "firewall")) return jmx_firewall_service_apply(params);
        return nc_ai_tool_error("invalid_apply_module", "Apply module is not allowlisted",
                                tool_name, "high");
    }
    return nc_ai_tool_error("unknown_tool", "Tool is not registered", tool_name, "");
}

static struct json_object *nc_ai_tool_dispatch_redacted(const char *tool_name,
                                                         struct json_object *params)
{
    struct json_object *raw = nc_ai_tool_dispatch(tool_name, params);
    struct json_object *safe;
    if (!raw) return NULL;
    safe = nc_ai_tool_result_redact(raw, NULL);
    json_object_put(raw);
    return safe;
}

static void nc_ai_tool_auth_prune(void)
{
    sqlite3_stmt *st = NULL;
    int64_t now = nc_now_s();
    if (nc_prepare(&st,
        "UPDATE ai_tool_auth SET status='expired',error='authorization_expired',resolved_at=?1 "
        "WHERE status='pending' AND created_at<?2") == 0) {
        sqlite3_bind_int64(st, 1, now);
        sqlite3_bind_int64(st, 2, now - NC_AI_TOOL_AUTH_PENDING_SEC);
        nc_step_done(st);
        sqlite3_finalize(st);
        st = NULL;
    }
    if (nc_prepare(&st,
        "UPDATE ai_tool_auth SET status='execution_unknown',error='execution_interrupted',"
        "resolved_at=?1 WHERE status='executing' AND "
        "COALESCE(NULLIF(resolved_at,0),created_at)<?2") == 0) {
        sqlite3_bind_int64(st, 1, now);
        sqlite3_bind_int64(st, 2, now - NC_AI_TOOL_AUTH_EXECUTING_SEC);
        nc_step_done(st);
        sqlite3_finalize(st);
        st = NULL;
    }
    if (nc_prepare(&st,
        "DELETE FROM ai_tool_auth WHERE status NOT IN ('pending','executing') AND "
        "(created_at<?1 OR id NOT IN (SELECT id FROM ai_tool_auth ORDER BY id DESC LIMIT ?2))") != 0)
        return;
    sqlite3_bind_int64(st, 1, now - NC_AI_TOOL_AUTH_RETAIN_SEC);
    sqlite3_bind_int(st, 2, NC_AI_TOOL_AUTH_RETAIN_MAX);
    nc_step_done(st);
    sqlite3_finalize(st);
}

static struct json_object *nc_ai_tool_record_response(sqlite3_stmt *st)
{
    struct json_object *d = json_object_new_object();
    const char *result_text = (const char *)sqlite3_column_text(st, 8);
    struct json_object *result = result_text && result_text[0] ?
                                 json_tokener_parse(result_text) : NULL;
    json_object_object_add(d, "ok", json_object_new_boolean(1));
    json_object_object_add(d, "auth_id", json_object_new_int(sqlite3_column_int(st, 0)));
    nc_add_text(d, "conversation_id", st, 1);
    nc_add_text(d, "tool_call_id", st, 2);
    nc_add_text(d, "tool", st, 3);
    nc_add_text(d, "risk_level", st, 4);
    nc_add_text(d, "status", st, 5);
    nc_add_text(d, "actor", st, 6);
    nc_add_text(d, "approved_by", st, 7);
    if (result) json_object_object_add(d, "result", result);
    nc_add_text(d, "error", st, 9);
    json_object_object_add(d, "created_at", json_object_new_int64(sqlite3_column_int64(st, 10)));
    json_object_object_add(d, "resolved_at", json_object_new_int64(sqlite3_column_int64(st, 11)));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

static struct json_object *nc_ai_tool_existing(const char *conversation_id,
                                                const char *tool_call_id,
                                                const char *tool_id,
                                                const char *parameters_json, const char *actor)
{
    sqlite3_stmt *st = NULL;
    struct json_object *response = NULL;
    if (!conversation_id || !conversation_id[0] || !tool_call_id || !tool_call_id[0]) return NULL;
    if (nc_prepare(&st,
        "SELECT id,conversation_id,tool_call_id,tool_id,risk_level,status,actor,approved_by,"
        "result_json,error,created_at,resolved_at,parameters_json FROM ai_tool_auth "
        "WHERE conversation_id=?1 AND tool_call_id=?2") == 0) {
        sqlite3_bind_text(st, 1, conversation_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, tool_call_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *stored_tool = nc_sql_text(st, 3);
            const char *stored_parameters = nc_sql_text(st, 12);
            if (strcmp(nc_sql_text(st, 6), actor))
                response = nc_ai_tool_error("not_found", "Tool call was not found", "", "");
            else if (strcmp(stored_tool, tool_id ? tool_id : "") ||
                strcmp(stored_parameters, parameters_json ? parameters_json : "{}"))
                response = nc_ai_tool_error("tool_call_conflict",
                                            "Tool call ID was already used with different parameters",
                                            tool_id, nc_sql_text(st, 4));
            else
                response = nc_ai_tool_record_response(st);
        }
        sqlite3_finalize(st);
    }
    return response;
}

struct json_object *jmx_ai_tool_call(struct json_object *req)
{
    struct json_object *params = NULL;
    struct json_object *result = NULL;
    struct json_object *existing = NULL;
    sqlite3_stmt *st = NULL;
    const char *requested_tool;
    const char *conversation_id;
    const char *requested_call_id;
    const char *actor;
    char tool_id[96] = "";
    char tool_name[96] = "";
    char risk[32] = "";
    char policy[32] = "confirm_medium";
    char tool_call_id[128] = "";
    const char *params_text;
    const char *result_text;
    int sensitive_params;
    int enabled = 0;
    int needs_authorization;
    int auth_id = -1;
    int64_t now = nc_now_s();

    if (!req || !json_object_is_type(req, json_type_object))
        return nc_ai_tool_error("invalid_request", "Tool request must be an object", "", "");
    requested_tool = nc_json_str_def(req, "tool", nc_json_str_def(req, "name", ""));
    conversation_id = nc_json_str_def(req, "conversation_id", "");
    requested_call_id = nc_json_str_def(req, "tool_call_id", nc_json_str_def(req, "call_id", ""));
    actor = nc_json_str_def(req, "actor", "ai-runtime");
    if (!nc_ai_public_id_ok(requested_tool) ||
        (conversation_id[0] && !nc_ai_public_id_ok(conversation_id)) ||
        (requested_call_id[0] && !nc_ai_public_id_ok(requested_call_id)) ||
        !nc_ai_actor_ok(actor))
        return nc_ai_tool_error("invalid_tool_request", "Tool, call, conversation, or actor ID is invalid",
                                requested_tool, "");
    if (!json_object_object_get_ex(req, "parameters", &params) || !params)
        params = json_object_new_object();
    else
        params = json_object_get(params);
    if (!json_object_is_type(params, json_type_object)) {
        json_object_put(params);
        return nc_ai_tool_error("invalid_parameters", "Tool parameters must be an object",
                                requested_tool, "");
    }
    params_text = json_object_to_json_string_ext(params, JSON_C_TO_STRING_PLAIN);
    sensitive_params = nc_ai_tool_params_sensitive(params);
    if (!params_text || strlen(params_text) > NC_AI_TOOL_PARAMS_MAX || sensitive_params) {
        json_object_put(params);
        return nc_ai_tool_error(sensitive_params ? "sensitive_parameters_blocked" :
                                "parameters_too_large",
                                "AI tool parameters contain secrets or exceed the size limit",
                                requested_tool, "");
    }
    if (jmx_netconfig_db_init() != 0) {
        json_object_put(params);
        return nc_ai_tool_error("storage_error", "AI tool database is unavailable",
                                requested_tool, "");
    }
    nc_ai_db_init();
    nc_ai_ensure_tools();
    if (nc_prepare(&st, "SELECT id,name,risk_level,enabled FROM ai_tool WHERE id=?1 OR name=?1") == 0) {
        sqlite3_bind_text(st, 1, requested_tool, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(tool_id, sizeof(tool_id), "%s", nc_sql_text(st, 0));
            snprintf(tool_name, sizeof(tool_name), "%s", nc_sql_text(st, 1));
            snprintf(risk, sizeof(risk), "%s", nc_sql_text(st, 2));
            enabled = sqlite3_column_int(st, 3);
        }
        sqlite3_finalize(st); st = NULL;
    }
    if (!tool_id[0] || !enabled) {
        json_object_put(params);
        return nc_ai_tool_error(!tool_id[0] ? "unknown_tool" : "tool_disabled",
                                !tool_id[0] ? "Tool is not registered" : "Tool is disabled",
                                requested_tool, risk);
    }
    if (!strcmp(risk, "blocked")) {
        json_object_put(params);
        return nc_ai_tool_error("tool_blocked", "Tool cannot be executed by AI", tool_id, risk);
    }
    if (nc_prepare(&st, "SELECT tool_policy FROM ai_config WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW)
            snprintf(policy, sizeof(policy), "%s", nc_sql_text(st, 0));
        sqlite3_finalize(st); st = NULL;
    }
    if (strcmp(policy, "read_only") && strcmp(policy, "confirm_all") &&
        strcmp(policy, "confirm_medium"))
        snprintf(policy, sizeof(policy), "%s", "confirm_medium");
    if (!strcmp(policy, "read_only") && strcmp(risk, "low")) {
        json_object_put(params);
        return nc_ai_tool_error("tool_policy_read_only",
                                "Configured AI tool policy allows read-only tools only",
                                tool_id, risk);
    }
    if (requested_call_id[0]) snprintf(tool_call_id, sizeof(tool_call_id), "%s", requested_call_id);
    else {
        unsigned int random_part = 0;
        sqlite3_randomness((int)sizeof(random_part), &random_part);
        snprintf(tool_call_id, sizeof(tool_call_id), "tool-%lld-%08x", (long long)now, random_part);
    }
    existing = nc_ai_tool_existing(conversation_id, tool_call_id, tool_id, params_text, actor);
    if (existing) {
        json_object_put(params);
        return existing;
    }
    needs_authorization = !strcmp(policy, "confirm_all") ||
                          (!strcmp(policy, "confirm_medium") && strcmp(risk, "low"));
    if (needs_authorization) {
        if (nc_prepare(&st,
            "INSERT INTO ai_tool_auth(conversation_id,tool_call_id,tool_id,parameters_json,actor,"
            "risk_level,status,created_at) VALUES(?1,?2,?3,?4,?5,?6,'pending',?7)") == 0) {
            sqlite3_bind_text(st, 1, conversation_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, tool_call_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, tool_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 4, params_text, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 5, actor, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 6, risk, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 7, now);
            if (nc_step_done(st) == 0) auth_id = (int)sqlite3_last_insert_rowid(g_netconfig_db);
            sqlite3_finalize(st); st = NULL;
        }
        json_object_put(params);
        if (auth_id < 0)
            return nc_ai_tool_error("storage_error", "Tool authorization could not be created",
                                    tool_id, risk);
        struct json_object *d = json_object_new_object();
        json_object_object_add(d, "ok", json_object_new_boolean(1));
        json_object_object_add(d, "status", json_object_new_string("pending_authorization"));
        json_object_object_add(d, "auth_id", json_object_new_int(auth_id));
        json_object_object_add(d, "conversation_id", json_object_new_string(conversation_id));
        json_object_object_add(d, "tool_call_id", json_object_new_string(tool_call_id));
        json_object_object_add(d, "tool", json_object_new_string(tool_id));
        json_object_object_add(d, "risk_level", json_object_new_string(risk));
        json_object_object_add(d, "required_role", json_object_new_string(
            !strcmp(risk, "high") ? "owner" : "admin_or_owner"));
        json_object_object_add(d, "ts", json_object_new_int64(now));
        return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
    }

    result = nc_ai_tool_dispatch_redacted(tool_name, params);
    result_text = result ? json_object_to_json_string_ext(result, JSON_C_TO_STRING_PLAIN) : "";
    int result_ok = nc_ai_tool_result_ok(result);
    int result_cached = result_text && strlen(result_text) <= NC_AI_TOOL_RESULT_STORE_MAX;
    if (nc_prepare(&st,
        "INSERT INTO ai_tool_auth(conversation_id,tool_call_id,tool_id,parameters_json,actor,"
        "risk_level,status,result_json,error,created_at,resolved_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)") == 0) {
        sqlite3_bind_text(st, 1, conversation_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, tool_call_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, tool_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, params_text, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, actor, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, risk, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, result_ok ? "executed" : "execution_failed", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, result_cached ? result_text : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, result_ok ?
                          (result_cached ? "" : "result_not_cached_too_large") :
                          "tool_execution_failed", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 10, now);
        if (nc_step_done(st) == 0) auth_id = (int)sqlite3_last_insert_rowid(g_netconfig_db);
        sqlite3_finalize(st); st = NULL;
    }
    json_object_put(params);
    if (auth_id < 0) {
        if (result) json_object_put(result);
        return nc_ai_tool_error("storage_error", "Tool execution record could not be saved",
                                tool_id, risk);
    }
    nc_ai_tool_auth_prune();
    struct json_object *d = json_object_new_object();
    json_object_object_add(d, "ok", json_object_new_boolean(result_ok));
    json_object_object_add(d, "status", json_object_new_string(result_ok ? "executed" : "execution_failed"));
    json_object_object_add(d, "auth_id", json_object_new_int(auth_id));
    json_object_object_add(d, "conversation_id", json_object_new_string(conversation_id));
    json_object_object_add(d, "tool_call_id", json_object_new_string(tool_call_id));
    json_object_object_add(d, "tool", json_object_new_string(tool_id));
    json_object_object_add(d, "risk_level", json_object_new_string(risk));
    if (result) json_object_object_add(d, "result", result);
    if (!result_ok) json_object_object_add(d, "error", json_object_new_string("tool_execution_failed"));
    json_object_object_add(d, "ts", json_object_new_int64(now));
    return jmx_gen_api_response_data(result_ok ? API_CODE_SUCCESS : API_CODE_ERROR, d);
}

struct json_object *jmx_ai_tool_authorization_resolve(int auth_id, int approve,
                                                      const char *actor,
                                                      const char *role)
{
    sqlite3_stmt *st = NULL;
    char conversation_id[128] = "";
    char tool_call_id[128] = "";
    char request_actor[160] = "";
    char tool[96] = "";
    char risk[32] = "";
    char status[32] = "";
    char parameters[NC_AI_TOOL_PARAMS_MAX + 1] = "{}";
    struct json_object *params = NULL;
    struct json_object *result = NULL;
    const char *result_text;
    int64_t now = nc_now_s();

    if (auth_id <= 0 || !actor || !actor[0] || !role || !role[0])
        return nc_ai_tool_error("invalid_authorization", "Authorization request is invalid", "", "");
    if (jmx_netconfig_db_init() != 0)
        return nc_ai_tool_error("storage_error", "AI tool database is unavailable", "", "");
    nc_ai_db_init();
    nc_ai_tool_auth_prune();
    if (nc_prepare(&st,
        "SELECT tool_id,risk_level,status,parameters_json,conversation_id,tool_call_id,actor "
        "FROM ai_tool_auth WHERE id=?1") != 0)
        return nc_ai_tool_error("storage_error", "Authorization lookup failed", "", "");
    sqlite3_bind_int(st, 1, auth_id);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return nc_ai_tool_error("not_found", "Authorization request was not found", "", "");
    }
    snprintf(tool, sizeof(tool), "%s", nc_sql_text(st, 0));
    snprintf(risk, sizeof(risk), "%s", nc_sql_text(st, 1));
    snprintf(status, sizeof(status), "%s", nc_sql_text(st, 2));
    snprintf(parameters, sizeof(parameters), "%s", nc_sql_text(st, 3));
    snprintf(conversation_id, sizeof(conversation_id), "%s", nc_sql_text(st, 4));
    snprintf(tool_call_id, sizeof(tool_call_id), "%s", nc_sql_text(st, 5));
    snprintf(request_actor, sizeof(request_actor), "%s", nc_sql_text(st, 6));
    sqlite3_finalize(st); st = NULL;
    if (strcmp(request_actor, actor))
        return nc_ai_tool_error("not_found", "Authorization request was not found", "", "");
    if (strcmp(status, "pending"))
        return nc_ai_tool_error("authorization_not_pending",
                                "Authorization request has already been resolved", tool, risk);
    if (!nc_ai_role_allows_risk(role, risk))
        return nc_ai_tool_error("insufficient_role",
                                !strcmp(risk, "high") ? "High-risk tools require owner approval" :
                                "Tool approval requires an authorized role", tool, risk);
    if (!approve) {
        if (nc_prepare(&st,
            "UPDATE ai_tool_auth SET status='denied',approved_by=?1,resolved_at=?2 "
            "WHERE id=?3 AND status='pending'") != 0)
            return nc_ai_tool_error("storage_error", "Authorization denial failed", tool, risk);
        sqlite3_bind_text(st, 1, actor, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, now);
        sqlite3_bind_int(st, 3, auth_id);
        int rc = nc_step_done(st);
        sqlite3_finalize(st);
        if (rc != 0 || nc_sqlite_changes() != 1)
            return nc_ai_tool_error("authorization_not_pending",
                                    "Authorization request is no longer pending", tool, risk);
        struct json_object *d = json_object_new_object();
        json_object_object_add(d, "ok", json_object_new_boolean(1));
        json_object_object_add(d, "auth_id", json_object_new_int(auth_id));
        json_object_object_add(d, "conversation_id", json_object_new_string(conversation_id));
        json_object_object_add(d, "tool_call_id", json_object_new_string(tool_call_id));
        json_object_object_add(d, "request_actor", json_object_new_string(request_actor));
        json_object_object_add(d, "tool", json_object_new_string(tool));
        json_object_object_add(d, "risk_level", json_object_new_string(risk));
        json_object_object_add(d, "status", json_object_new_string("denied"));
        json_object_object_add(d, "approved_by", json_object_new_string(actor));
        return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
    }
    if (nc_prepare(&st,
        "UPDATE ai_tool_auth SET status='executing',approved_by=?1,resolved_at=?2 "
        "WHERE id=?3 AND status='pending'") != 0)
        return nc_ai_tool_error("storage_error", "Authorization claim failed", tool, risk);
    sqlite3_bind_text(st, 1, actor, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_int(st, 3, auth_id);
    int claim_rc = nc_step_done(st);
    sqlite3_finalize(st); st = NULL;
    if (claim_rc != 0 || nc_sqlite_changes() != 1)
        return nc_ai_tool_error("authorization_not_pending",
                                "Authorization request is no longer pending", tool, risk);
    params = json_tokener_parse(parameters);
    if (!params || !json_object_is_type(params, json_type_object)) {
        if (params) json_object_put(params);
        params = json_object_new_object();
    }
    result = nc_ai_tool_dispatch_redacted(tool, params);
    json_object_put(params);
    int result_ok = nc_ai_tool_result_ok(result);
    result_text = result ? json_object_to_json_string_ext(result, JSON_C_TO_STRING_PLAIN) : "";
    int result_cached = result_text && strlen(result_text) <= NC_AI_TOOL_RESULT_STORE_MAX;
    if (nc_prepare(&st,
        "UPDATE ai_tool_auth SET status=?1,result_json=?2,error=?3,resolved_at=?4 "
        "WHERE id=?5 AND status='executing'") != 0) {
        if (result) json_object_put(result);
        return nc_ai_tool_error("storage_error", "Authorization result save failed", tool, risk);
    }
    sqlite3_bind_text(st, 1, result_ok ? "executed" : "execution_failed", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, result_cached ? result_text : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, result_ok ?
                      (result_cached ? "" : "result_not_cached_too_large") :
                      "tool_execution_failed", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, now);
    sqlite3_bind_int(st, 5, auth_id);
    int update_rc = nc_step_done(st);
    sqlite3_finalize(st);
    if (update_rc != 0) {
        if (result) json_object_put(result);
        return nc_ai_tool_error("storage_error", "Authorization result save failed", tool, risk);
    }
    nc_ai_tool_auth_prune();
    struct json_object *d = json_object_new_object();
    json_object_object_add(d, "ok", json_object_new_boolean(result_ok));
    json_object_object_add(d, "auth_id", json_object_new_int(auth_id));
    json_object_object_add(d, "conversation_id", json_object_new_string(conversation_id));
    json_object_object_add(d, "tool_call_id", json_object_new_string(tool_call_id));
    json_object_object_add(d, "request_actor", json_object_new_string(request_actor));
    json_object_object_add(d, "tool", json_object_new_string(tool));
    json_object_object_add(d, "risk_level", json_object_new_string(risk));
    json_object_object_add(d, "status", json_object_new_string(result_ok ? "executed" : "execution_failed"));
    json_object_object_add(d, "approved_by", json_object_new_string(actor));
    if (result) json_object_object_add(d, "result", result);
    if (!result_ok) json_object_object_add(d, "error", json_object_new_string("tool_execution_failed"));
    return jmx_gen_api_response_data(result_ok ? API_CODE_SUCCESS : API_CODE_ERROR, d);
}

/* ═══ AI Tool Authorizations List ═══ */
struct json_object *jmx_ai_tool_authorizations_list(const char *actor) {
    if (!nc_ai_actor_ok(actor)) return nc_ai_tool_error("identity_required", "Authenticated subject is required", "", "");
    struct json_object *d = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    if (jmx_netconfig_db_init() != 0) goto done;
    nc_ai_db_init();
    nc_ai_tool_auth_prune();
    if (nc_prepare(&st, "SELECT id,conversation_id,tool_call_id,tool_id,parameters_json,actor,risk_level,status,result_json,error,approved_by,created_at,resolved_at FROM ai_tool_auth WHERE actor=?1 ORDER BY created_at DESC,id DESC LIMIT 200") == 0) {
        sqlite3_bind_text(st, 1, actor, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            json_object_object_add(o, "id", json_object_new_int(sqlite3_column_int(st, 0)));
            nc_add_text(o, "conversation_id", st, 1);
            nc_add_text(o, "tool_call_id", st, 2);
            nc_add_text(o, "tool_id", st, 3);
            const char *pj = (const char *)sqlite3_column_text(st, 4);
            struct json_object *params = pj ? json_tokener_parse(pj) : json_object_new_object();
            json_object_object_add(o, "parameters", params ? params : json_object_new_object());
            nc_add_text(o, "actor", st, 5);
            nc_add_text(o, "risk_level", st, 6);
            nc_add_text(o, "status", st, 7);
            const char *rj = (const char *)sqlite3_column_text(st, 8);
            struct json_object *result = rj && rj[0] ? json_tokener_parse(rj) : NULL;
            if (result) json_object_object_add(o, "result", result);
            nc_add_text(o, "error", st, 9);
            nc_add_text(o, "approved_by", st, 10);
            json_object_object_add(o, "created_at", json_object_new_int64(sqlite3_column_int64(st, 11)));
            json_object_object_add(o, "resolved_at", json_object_new_int64(sqlite3_column_int64(st, 12)));
            json_object_array_add(arr, o);
        }
        sqlite3_finalize(st);
    }
done:
    json_object_object_add(d, "items", arr);
    json_object_object_add(d, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

struct json_object *jmx_ai_tool_authorizations_get(const char *actor, const char *conversation_id)
{
    if (!nc_ai_actor_ok(actor)) return nc_ai_tool_error("identity_required", "Authenticated subject is required", "", "");
    struct json_object *d = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;

    if (!conversation_id || !nc_ai_public_id_ok(conversation_id)) {
        json_object_put(arr);
        json_object_put(d);
        return nc_ai_tool_error("invalid_conversation_id",
                                "Conversation ID is invalid", "", "");
    }
    if (jmx_netconfig_db_init() != 0) {
        json_object_put(arr);
        json_object_put(d);
        return nc_ai_tool_error("storage_error",
                                "AI tool database is unavailable", "", "");
    }
    nc_ai_db_init();
    nc_ai_tool_auth_prune();
    if (nc_prepare(&st,
        "SELECT id,conversation_id,tool_call_id,tool_id,parameters_json,actor,risk_level,"
        "status,result_json,error,approved_by,created_at,resolved_at FROM ai_tool_auth "
        "WHERE conversation_id=?1 AND actor=?2 ORDER BY id") == 0) {
        sqlite3_bind_text(st, 1, conversation_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, actor, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            const char *pj;
            const char *rj;
            struct json_object *params;
            struct json_object *result;

            json_object_object_add(o, "id", json_object_new_int(sqlite3_column_int(st, 0)));
            nc_add_text(o, "conversation_id", st, 1);
            nc_add_text(o, "tool_call_id", st, 2);
            nc_add_text(o, "tool_id", st, 3);
            pj = (const char *)sqlite3_column_text(st, 4);
            params = pj ? json_tokener_parse(pj) : NULL;
            json_object_object_add(o, "parameters",
                                   params ? params : json_object_new_object());
            nc_add_text(o, "actor", st, 5);
            nc_add_text(o, "risk_level", st, 6);
            nc_add_text(o, "status", st, 7);
            rj = (const char *)sqlite3_column_text(st, 8);
            result = rj && rj[0] ? json_tokener_parse(rj) : NULL;
            if (result) json_object_object_add(o, "result", result);
            nc_add_text(o, "error", st, 9);
            nc_add_text(o, "approved_by", st, 10);
            json_object_object_add(o, "created_at",
                                   json_object_new_int64(sqlite3_column_int64(st, 11)));
            json_object_object_add(o, "resolved_at",
                                   json_object_new_int64(sqlite3_column_int64(st, 12)));
            json_object_array_add(arr, o);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(d, "conversation_id", json_object_new_string(conversation_id));
    json_object_object_add(d, "items", arr);
    json_object_object_add(d, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}
