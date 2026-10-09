    if (json_object_object_get_ex(cfg, "failover_max_attempts", &v) && v) {
        if (!json_object_is_type(v, json_type_int))
            return -7;
        max_attempts = json_object_get_int(v);
        if (max_attempts < 1 || max_attempts > 5)
            return -7;
    }
    if (nc_txn_begin() != 0)
        return -1;
    if (nc_prepare(&st, "INSERT OR IGNORE INTO ai_dispatch_policy(id,updated_at) "
                        "VALUES(1,?1)") != 0)
        goto out;
    sqlite3_bind_int64(st, 1, nc_now_s());
    if (nc_step_done(st) != 0)
        goto out;
    sqlite3_finalize(st);
    st = NULL;
    if (strategy) {
        if (nc_prepare(&st, "UPDATE ai_dispatch_policy SET strategy=?1 WHERE id=1") != 0)
            goto out;
        sqlite3_bind_text(st, 1, strategy, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0)
            goto out;
        sqlite3_finalize(st);
        st = NULL;
    }
    if (timeout_ms > 0) {
        if (nc_prepare(&st, "UPDATE ai_dispatch_policy SET failover_timeout_ms=?1 WHERE id=1") != 0)
            goto out;
        sqlite3_bind_int(st, 1, timeout_ms);
        if (nc_step_done(st) != 0)
            goto out;
        sqlite3_finalize(st);
        st = NULL;
    }
    if (max_attempts > 0) {
        if (nc_prepare(&st, "UPDATE ai_dispatch_policy SET failover_max_attempts=?1 WHERE id=1") != 0)
            goto out;
        sqlite3_bind_int(st, 1, max_attempts);
        if (nc_step_done(st) != 0)
            goto out;
        sqlite3_finalize(st);
        st = NULL;
    }
    if (nc_prepare(&st, "UPDATE ai_dispatch_policy SET updated_at=?1 WHERE id=1") != 0)
        goto out;
    sqlite3_bind_int64(st, 1, nc_now_s());
    if (nc_step_done(st) != 0)
        goto out;
    sqlite3_finalize(st);
    st = NULL;
    rc = 0;
out:
    if (st) sqlite3_finalize(st);
    return nc_txn_end(rc);
}

/* ═══ AI Tool Registry ═══ */

/* Built-in tool definitions — these are the jmxd-provided tools for AI */
static const struct { const char *id; const char *name; const char *title; const char *desc; const char *params; const char *risk; const char *category; } nc_ai_builtin_tools[] = {
    { "get_system_status",   "get_system_status",   "读取系统状态", "读取路由器当前系统状态（CPU、内存、磁盘、运行时长、温度、连接数）。",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}", "low", "system" },
    { "network_overview",    "network_overview",    "读取网络概览", "读取网络概览：WAN、LAN、DHCP 租约和流量汇总。",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}", "low", "network" },
    { "wan_list",            "wan_list",            "读取 WAN 列表", "读取所有 WAN 线路的配置和运行状态。",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}", "low", "network" },
    { "lan_list",            "lan_list",            "读取 LAN 列表", "读取所有 LAN 接口的配置和 DHCP 状态。",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}", "low", "network" },
    { "dns_service_get",     "dns_service_get",     "读取 DNS 服务", "读取 DNS 服务配置、上游、规则和统计信息。",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}", "low", "services" },
    { "upnp_service_get",    "upnp_service_get",    "读取 UPnP 服务", "读取 UPnP 服务配置、ACL 规则和活跃映射。",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}", "low", "services" },
    { "flow_control_get",    "flow_control_get",    "读取流控配置", "读取 QoS/流控配置、规则、分类和客户端限制。",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}", "low", "services" },
    { "routing_get",         "routing_get",         "读取高级路由", "读取高级路由：静态路由、策略路由和路由表。",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}", "low", "network" },
    { "firewall_service_get","firewall_service_get","读取防火墙服务","读取防火墙规则、端口转发、NAT 和防护设置。",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}", "low", "security" },
    { "wan_set",             "wan_set",             "更新 WAN 配置", "创建或更新 WAN 接口配置。",
      "{\"type\":\"object\",\"properties\":{\"id\":{\"type\":\"string\"},\"device\":{\"type\":\"string\"},\"access_mode\":{\"type\":\"string\",\"enum\":[\"dhcp\",\"static\",\"pppoe\",\"bridge\"]}},\"required\":[\"id\"],\"additionalProperties\":true}", "medium", "network" },
    { "lan_set",             "lan_set",             "更新 LAN 配置", "更新 LAN 接口配置（IP、DHCP、端口）。",
      "{\"type\":\"object\",\"properties\":{\"id\":{\"type\":\"string\"}},\"required\":[\"id\"],\"additionalProperties\":true}", "medium", "network" },
    { "dns_service_set",     "dns_service_set",     "更新 DNS 服务", "更新 DNS 服务配置。",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":true}", "medium", "services" },
    { "upnp_service_set",    "upnp_service_set",    "更新 UPnP 服务", "更新 UPnP 服务配置。",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":true}", "medium", "services" },
    { "flow_control_set",    "flow_control_set",    "更新流控配置", "更新 QoS/流控规则和设置。",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":true}", "medium", "services" },
    { "firewall_service_set","firewall_service_set","更新防火墙服务","更新防火墙规则和防护设置。",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":true}", "medium", "security" },
    { "config_apply",        "config_apply",        "应用配置变更", "应用挂起的配置变更到路由器。",
      "{\"type\":\"object\",\"properties\":{\"module\":{\"type\":\"string\"}},\"additionalProperties\":false}", "high", "system" },
    { "system_reboot",       "system_reboot",       "重启路由器", "重启路由器。已阻断，AI 不可使用。",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}", "blocked", "system" },
    { "factory_reset",       "factory_reset",       "恢复出厂设置", "恢复出厂设置。已阻断，AI 不可使用。",
      "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}", "blocked", "system" },
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};

static void nc_ai_ensure_tools(void)
{
    sqlite3_stmt *st = NULL;
    int64_t now = nc_now_s();
    for (int i = 0; nc_ai_builtin_tools[i].id; i++) {
        if (nc_prepare(&st, "INSERT INTO ai_tool(id,name,title,description,parameters_json,risk_level,enabled,category,sort_order) VALUES(?1,?2,?3,?4,?5,?6,1,?7,?8) ON CONFLICT(id) DO UPDATE SET name=excluded.name,title=excluded.title,description=excluded.description,parameters_json=excluded.parameters_json,risk_level=excluded.risk_level,category=excluded.category,sort_order=excluded.sort_order") == 0) {
            sqlite3_bind_text(st, 1, nc_ai_builtin_tools[i].id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, nc_ai_builtin_tools[i].name, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, nc_ai_builtin_tools[i].title, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 4, nc_ai_builtin_tools[i].desc, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 5, nc_ai_builtin_tools[i].params, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 6, nc_ai_builtin_tools[i].risk, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 7, nc_ai_builtin_tools[i].category, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 8, i);
            nc_step_done(st);
            sqlite3_finalize(st);
            st = NULL;
        }
    }
}

struct json_object *jmx_ai_models_get(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    struct json_object *details = json_object_new_array();
    /* Hardcoded common models — provider-specific listing would need API call */
    const char *models[] = {
        "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo",
        "claude-3.5-sonnet", "claude-3-haiku",
        "deepseek-chat", "deepseek-reasoner",
        "qwen-plus", "qwen-turbo",
        NULL
    };
    for (int i = 0; models[i]; i++) {
        struct json_object *detail = json_object_new_object();
        json_object_array_add(arr, json_object_new_string(models[i]));
        json_object_object_add(detail, "id", json_object_new_string(models[i]));
        json_object_object_add(detail, "vision", json_object_new_null());
        json_object_object_add(detail, "file_input", json_object_new_null());
        json_object_object_add(detail, "tool_calling", json_object_new_null());
        json_object_object_add(detail, "streaming", json_object_new_null());
        json_object_object_add(detail, "context_window", json_object_new_null());
        json_object_object_add(detail, "capability_source",
                               json_object_new_string("static_catalog_unspecified"));
        json_object_array_add(details, detail);
    }
    json_object_object_add(data, "models", arr);
    json_object_object_add(data, "model_details", details);
    json_object_object_add(data, "model_capabilities_normalized", json_object_new_boolean(1));
    json_object_object_add(data, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_ai_tools_get(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    if (jmx_netconfig_db_init() != 0) goto done;
    nc_ai_db_init();
    nc_ai_ensure_tools();
    if (nc_prepare(&st, "SELECT id,name,title,description,parameters_json,risk_level,enabled,category FROM ai_tool ORDER BY sort_order,id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            nc_add_text(o, "id", st, 0); nc_add_text(o, "name", st, 1); nc_add_text(o, "title", st, 2); nc_add_text(o, "description", st, 3);
            const char *pj = (const char *)sqlite3_column_text(st, 4);
            struct json_object *params = pj ? json_tokener_parse(pj) : json_object_new_object();
            json_object_object_add(o, "parameters", params ? params : json_object_new_object());
            nc_add_text(o, "risk_level", st, 5);
            json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 6)));
            nc_add_text(o, "category", st, 7);
            json_object_array_add(arr, o);
        }
        sqlite3_finalize(st);
    }
done:
    json_object_object_add(data, "tools", arr);
    json_object_object_add(data, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

int jmx_ai_tool_authorize(int auth_id, int approve, const char *role)
{
    struct json_object *response = jmx_ai_tool_authorization_resolve(auth_id, approve,
                                                                     role, role);
    struct json_object *code = NULL;
    int ok = response && json_object_object_get_ex(response, "code", &code) && code &&
             json_object_get_int(code) == API_CODE_SUCCESS;
    if (response) json_object_put(response);
    return ok ? 0 : -1;
}

/* ═══ AI Chat ═══ */
/* The chat endpoint delegates to an LLM provider via HTTP.
 * Risk policy: low → execute directly, medium → create auth request + return to frontend,
 * high → block with error, blocked → never available.
 */
struct json_object *jmx_ai_chat(struct json_object *req)
{
    struct json_object *data = json_object_new_object();
    struct json_object *resp_arr = json_object_new_array();
    if (!req) {
        json_object_object_add(data, "error", json_object_new_string("empty request"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    /* Check AI is enabled */
    sqlite3_stmt *st = NULL;
    int ai_enabled = 0;
    if (jmx_netconfig_db_init() == 0) {
        nc_ai_db_init();
        nc_ai_ensure_tools();
        if (nc_prepare(&st, "SELECT enabled FROM ai_config WHERE id=1") == 0) {
            if (sqlite3_step(st) == SQLITE_ROW) ai_enabled = sqlite3_column_int(st, 0);
            sqlite3_finalize(st); st = NULL;
        }
    }
    if (!ai_enabled) {
        json_object_object_add(data, "error", json_object_new_string("AI assistant is not enabled. Configure it first."));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    /* For now, return tool list as the "response" — actual LLM integration
     * requires HTTP client to provider API, which is a larger piece.
     * This endpoint validates the request and returns available tools.
     */
    const char *cfg_effort = "auto";
    const char *cfg_shape = "chat_completions";
    sqlite3_stmt *est = NULL;
    if (nc_prepare(&est, "SELECT reasoning_effort,reasoning_api_shape FROM ai_config WHERE id=1") == 0) {
        if (sqlite3_step(est) == SQLITE_ROW) {
            cfg_effort = (const char *)sqlite3_column_text(est, 0);
            cfg_shape = (const char *)sqlite3_column_text(est, 1);
            if (!cfg_effort || !cfg_effort[0]) cfg_effort = "auto";
            if (!cfg_shape || !cfg_shape[0]) cfg_shape = "chat_completions";
        }
        sqlite3_finalize(est); est = NULL;
    }
    sqlite3_stmt *cst = NULL;
    const char *cfg_provider = "openai";
    const char *cfg_model = "gpt-4o";
    if (nc_prepare(&cst, "SELECT provider,model FROM ai_config WHERE id=1") == 0) {
        if (sqlite3_step(cst) == SQLITE_ROW) {
            cfg_provider = (const char *)sqlite3_column_text(cst, 0);
            cfg_model = (const char *)sqlite3_column_text(cst, 1);
            if (!cfg_provider || !cfg_provider[0]) cfg_provider = "openai";
            if (!cfg_model || !cfg_model[0]) cfg_model = "gpt-4o";
        }
        sqlite3_finalize(cst); cst = NULL;
    }
    int effort_supported = 1;
    if (!strcasecmp(cfg_provider, "openai") || !strcasecmp(cfg_provider, "openai-compatible")) {
        if (!strncasecmp(cfg_model, "gpt-3.5", 7) || !strcasecmp(cfg_model, "gpt-4-0314") || !strcasecmp(cfg_model, "gpt-4-32k-0314") || !strcasecmp(cfg_model, "gpt-4o-audio-preview")) effort_supported = 0;
