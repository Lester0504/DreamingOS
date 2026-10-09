        "lb_cursor INTEGER NOT NULL DEFAULT 0,"
        "updated_at INTEGER NOT NULL DEFAULT 0"
    ")");
    nc_add_column_if_missing("ai_dispatch_policy", "lb_cursor",
                             "INTEGER NOT NULL DEFAULT 0");
    nc_ai_multi_provider_migrate_once();
}

/* ═══ AI Config CRUD ═══ */
struct json_object *jmx_ai_config_get(void)
{
    struct json_object *data = json_object_new_object();
    sqlite3_stmt *st = NULL;

    json_object_object_add(data, "provider", json_object_new_string("openai"));
    json_object_object_add(data, "api_base", json_object_new_string(""));
    json_object_object_add(data, "api_key", json_object_new_string(""));
    json_object_object_add(data, "api_key_set", json_object_new_boolean(0));
    json_object_object_add(data, "model", json_object_new_string("gpt-4o"));
    json_object_object_add(data, "temperature", json_object_new_double(0.7));
    json_object_object_add(data, "max_tokens", json_object_new_int(4096));
    json_object_object_add(data, "system_prompt", json_object_new_string(""));
    json_object_object_add(data, "tool_policy", json_object_new_string("confirm_medium"));
    json_object_object_add(data, "enabled", json_object_new_boolean(0));
    json_object_object_add(data, "reasoning_effort", json_object_new_string("auto"));
    json_object_object_add(data, "reasoning_api_shape", json_object_new_string("chat_completions"));
    json_object_object_add(data, "auth_mode", json_object_new_string("api_key"));

    if (jmx_netconfig_db_init() != 0) goto done;
    nc_ai_db_init();
    if (nc_prepare(&st, "SELECT provider,api_base,api_key,model,temperature,max_tokens,system_prompt,tool_policy,enabled,reasoning_effort,reasoning_api_shape,auth_mode FROM ai_config WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            nc_add_text(data, "provider", st, 0);
            nc_add_text(data, "api_base", st, 1);
            /* Mask api_key: only show last 4 chars */
            const char *key = (const char *)sqlite3_column_text(st, 2);
            if (key && strlen(key) > 4) {
                char masked[64];
                snprintf(masked, sizeof(masked), "***%s", key + strlen(key) - 4);
                json_object_object_add(data, "api_key", json_object_new_string(masked));
                json_object_object_add(data, "api_key_set", json_object_new_boolean(1));
            } else {
                json_object_object_add(data, "api_key", json_object_new_string(""));
                json_object_object_add(data, "api_key_set", json_object_new_boolean(0));
            }
            nc_add_text(data, "model", st, 3);
            json_object_object_add(data, "temperature", json_object_new_double(sqlite3_column_double(st, 4)));
            json_object_object_add(data, "max_tokens", json_object_new_int(sqlite3_column_int(st, 5)));
            nc_add_text(data, "system_prompt", st, 6);
            nc_add_text(data, "tool_policy", st, 7);
            json_object_object_add(data, "enabled", json_object_new_boolean(sqlite3_column_int(st, 8)));
            nc_add_text(data, "reasoning_effort", st, 9);
            nc_add_text(data, "reasoning_api_shape", st, 10);
            nc_add_text(data, "auth_mode", st, 11);
        }
        sqlite3_finalize(st);
    }
done:;
    const char *provider = nc_json_str_def(data, "provider", "openai");
    const char *model = nc_json_str_def(data, "model", "gpt-4o");
    const char *shape = nc_json_str_def(data, "reasoning_api_shape", "chat_completions");
    int reasoning_supported = 1;
    if (!strcasecmp(provider, "openai") || !strcasecmp(provider, "openai-compatible") ||
        !strcasecmp(provider, "openai_compatible")) {
        if (!strncasecmp(model, "gpt-3.5", 7) || !strcasecmp(model, "gpt-4-0314") || !strcasecmp(model, "gpt-4-32k-0314") || !strcasecmp(model, "gpt-4o-audio-preview")) reasoning_supported = 0;
    } else if (!strcasecmp(provider, "deepseek")) {
        if (!strncasecmp(model, "deepseek-chat", 13)) reasoning_supported = 0;
    } else if (!strcasecmp(provider, "qwen")) {
        if (strstr(model, "turbo")) reasoning_supported = 0;
    } else if (!strcasecmp(provider, "custom") && !nc_json_bool_def(data, "api_key_set", 0)) {
        reasoning_supported = 0;
    }
    if (!strcmp(shape, "responses")) reasoning_supported = 1;
    struct json_object *caps = json_object_new_object();
    json_object_object_add(caps, "reasoning_effort_supported", json_object_new_boolean(reasoning_supported));
    struct json_object *values = json_object_new_array();
    const char *vals[] = {"auto","none","minimal","low","medium","high","xhigh",NULL};
    for (int i = 0; vals[i]; i++) json_object_array_add(values, json_object_new_string(vals[i]));
    json_object_object_add(caps, "reasoning_effort_values", values);
    json_object_object_add(caps, "reasoning_api_shape", json_object_new_string(shape));
    json_object_object_add(data, "capabilities", caps);
    json_object_object_add(data, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

static int nc_ai_temperature(struct json_object *cfg, double *out)
{
    struct json_object *value = NULL;
    double temperature;

    if (!out) return -1;
    *out = 0.7;
    if (!cfg || !json_object_object_get_ex(cfg, "temperature", &value) || !value)
        return 0;
    if (!json_object_is_type(value, json_type_int) &&
        !json_object_is_type(value, json_type_double))
        return -1;
    temperature = json_object_get_double(value);
    if (!isfinite(temperature) || temperature < 0)
        return -1;
    if (temperature <= 2.0) {
        *out = temperature;
        return 0;
    }
    /* Compatibility with the old web payload: 70 means 0.7. */
    if (json_object_is_type(value, json_type_int) && temperature <= 200.0) {
        *out = temperature / 100.0;
        return 0;
    }
    return -1;
}

int jmx_ai_config_set(struct json_object *cfg)
{
    sqlite3_stmt *st = NULL;
    struct json_object *key_obj = NULL;
    double temperature = 0.7;
    char auth_mode[16] = "api_key";
    int rc = -1;
    if (!cfg) return -1;
    const char *tool_policy = nc_json_str_def(cfg, "tool_policy", "confirm_medium");
    if (strcmp(tool_policy, "read_only") && strcmp(tool_policy, "confirm_medium") &&
        strcmp(tool_policy, "confirm_all")) return -4;
    if (jmx_netconfig_db_init() != 0) return -1;
    nc_ai_db_init();
    if (nc_ai_temperature(cfg, &temperature) != 0) return -2;
    {
        struct json_object *mode_obj = NULL;
        const char *requested_mode = NULL;

        if (json_object_object_get_ex(cfg, "auth_mode", &mode_obj) && mode_obj) {
            if (!json_object_is_type(mode_obj, json_type_string)) return -5;
            requested_mode = json_object_get_string(mode_obj);
            if (strcmp(requested_mode, "api_key") && strcmp(requested_mode, "oauth")) return -5;
            snprintf(auth_mode, sizeof(auth_mode), "%s", requested_mode);
        } else if (nc_prepare(&st, "SELECT auth_mode FROM ai_config WHERE id=1") == 0) {
            if (sqlite3_step(st) == SQLITE_ROW) {
                const char *stored_mode = (const char *)sqlite3_column_text(st, 0);
                if (stored_mode && (!strcmp(stored_mode, "api_key") || !strcmp(stored_mode, "oauth")))
                    snprintf(auth_mode, sizeof(auth_mode), "%s", stored_mode);
            }
            sqlite3_finalize(st);
            st = NULL;
        }
    }
    /* Empty, omitted, or masked means preserve. Only clear_api_key clears it. */
    int clear_key = nc_json_bool_def(cfg, "clear_api_key", 0);
    int key_supplied = json_object_object_get_ex(cfg, "api_key", &key_obj) &&
                       key_obj && json_object_is_type(key_obj, json_type_string);
    const char *key = key_supplied ? json_object_get_string(key_obj) : "";
    int masked_key = key && !strncmp(key, "***", 3);
    int write_key = clear_key || (key_supplied && key && key[0] && !masked_key);
    if (clear_key && key_supplied && key && key[0] && !masked_key) return -3;
    if (!key) key = "";
    if (!write_key) {
        if (nc_prepare(&st, "INSERT INTO ai_config(id,provider,api_base,model,temperature,max_tokens,system_prompt,tool_policy,enabled,reasoning_effort,reasoning_api_shape,auth_mode,updated_at) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) ON CONFLICT(id) DO UPDATE SET provider=excluded.provider,api_base=excluded.api_base,model=excluded.model,temperature=excluded.temperature,max_tokens=excluded.max_tokens,system_prompt=excluded.system_prompt,tool_policy=excluded.tool_policy,enabled=excluded.enabled,reasoning_effort=excluded.reasoning_effort,reasoning_api_shape=excluded.reasoning_api_shape,auth_mode=excluded.auth_mode,updated_at=excluded.updated_at") == 0) {
            sqlite3_bind_text(st, 1, nc_json_str_def(cfg, "provider", "openai"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, nc_json_str_def(cfg, "api_base", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, nc_json_str_def(cfg, "model", "gpt-4o"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_double(st, 4, temperature);
            sqlite3_bind_int(st, 5, nc_json_int_def(cfg, "max_tokens", 4096));
            sqlite3_bind_text(st, 6, nc_json_str_def(cfg, "system_prompt", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 7, tool_policy, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 8, nc_json_bool_def(cfg, "enabled", 0));
            sqlite3_bind_text(st, 9, nc_json_str_def(cfg, "reasoning_effort", "auto"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 10, nc_json_str_def(cfg, "reasoning_api_shape", "chat_completions"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 11, auth_mode, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 12, nc_now_s());
            if (nc_step_done(st) == 0) rc = 0;
            sqlite3_finalize(st);
        }
    } else {
        if (nc_prepare(&st, "INSERT INTO ai_config(id,provider,api_base,api_key,model,temperature,max_tokens,system_prompt,tool_policy,enabled,reasoning_effort,reasoning_api_shape,auth_mode,updated_at) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13) ON CONFLICT(id) DO UPDATE SET provider=excluded.provider,api_base=excluded.api_base,api_key=excluded.api_key,model=excluded.model,temperature=excluded.temperature,max_tokens=excluded.max_tokens,system_prompt=excluded.system_prompt,tool_policy=excluded.tool_policy,enabled=excluded.enabled,reasoning_effort=excluded.reasoning_effort,reasoning_api_shape=excluded.reasoning_api_shape,auth_mode=excluded.auth_mode,updated_at=excluded.updated_at") == 0) {
            sqlite3_bind_text(st, 1, nc_json_str_def(cfg, "provider", "openai"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, nc_json_str_def(cfg, "api_base", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, clear_key ? "" : key, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 4, nc_json_str_def(cfg, "model", "gpt-4o"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_double(st, 5, temperature);
            sqlite3_bind_int(st, 6, nc_json_int_def(cfg, "max_tokens", 4096));
            sqlite3_bind_text(st, 7, nc_json_str_def(cfg, "system_prompt", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 8, tool_policy, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 9, nc_json_bool_def(cfg, "enabled", 0));
            sqlite3_bind_text(st, 10, nc_json_str_def(cfg, "reasoning_effort", "auto"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 11, nc_json_str_def(cfg, "reasoning_api_shape", "chat_completions"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 12, auth_mode, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 13, nc_now_s());
            if (nc_step_done(st) == 0) rc = 0;
            sqlite3_finalize(st);
        }
    }
    return rc;
}

/* ═══ AI Multi-Provider CRUD ═══ */

static int nc_ai_provider_kind_ok(const char *provider)
{
    static const char *kinds[] = {
        "openai", "anthropic", "claude", "gemini", "google-gemini", "deepseek",
        "qwen", "moonshot", "kimi", "kimi-code", "kimi_code", "custom",
        "openai-compatible", "openai_compatible", NULL
    };
    if (!provider || !provider[0])
        return 0;
    for (int i = 0; kinds[i]; i++) {
        if (!strcasecmp(provider, kinds[i]))
            return 1;
    }
    return 0;
}

static int nc_ai_strategy_ok(const char *strategy)
{
    return strategy && (!strcmp(strategy, "single") ||
                        !strcmp(strategy, "failover") ||
                        !strcmp(strategy, "load_balance"));
}

static int nc_ai_provider_id_ok(const char *id)
{
    size_t n = id ? strlen(id) : 0;
    if (n == 0 || n > 64)
        return 0;
    for (size_t i = 0; i < n; i++) {
        if (!isalnum((unsigned char)id[i]) && id[i] != '-' && id[i] != '_')
            return 0;
    }
    return 1;
}

/* Never echo a stored key back. Hint is first 3 + last 4; anything shorter
 * than 12 chars degrades to "***" so a short key cannot be reconstructed. */
static void nc_ai_key_hint(const char *key, char *out, size_t out_len)
{
    size_t n = key ? strlen(key) : 0;
    if (!out || out_len == 0)
        return;
    if (n == 0) {
        out[0] = '\0';
        return;
    }
    if (n < 12) {
        snprintf(out, out_len, "***");
        return;
    }
    snprintf(out, out_len, "%.3s...%s", key, key + n - 4);
}

static void nc_ai_provider_row_json(struct json_object *o, sqlite3_stmt *st)
{
    const char *key = nc_text_or_empty(st, 4);
    char hint[64] = "";
    struct json_object *last = json_object_new_object();
    int64_t synced_at = sqlite3_column_int64(st, 18);

    json_object_object_add(o, "id", json_object_new_string(nc_text_or_empty(st, 0)));
    json_object_object_add(o, "provider", json_object_new_string(nc_text_or_empty(st, 1)));
    json_object_object_add(o, "display_name", json_object_new_string(nc_text_or_empty(st, 2)));
    json_object_object_add(o, "api_base", json_object_new_string(nc_text_or_empty(st, 3)));
    json_object_object_add(o, "api_key_set", json_object_new_boolean(key[0] ? 1 : 0));
    nc_ai_key_hint(key, hint, sizeof(hint));
    json_object_object_add(o, "api_key_hint", json_object_new_string(hint));
    json_object_object_add(o, "auth_mode", json_object_new_string(nc_text_or_empty(st, 5)));
    json_object_object_add(o, "default_model", json_object_new_string(nc_text_or_empty(st, 6)));
    json_object_object_add(o, "role", json_object_new_string(nc_text_or_empty(st, 7)));
    json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 8)));
    json_object_object_add(o, "weight", json_object_new_int(sqlite3_column_int(st, 9)));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 10)));
    json_object_object_add(o, "reasoning_effort", json_object_new_string(nc_text_or_empty(st, 11)));
    json_object_object_add(o, "reasoning_api_shape", json_object_new_string(nc_text_or_empty(st, 12)));
    json_object_object_add(o, "model_count", json_object_new_int(sqlite3_column_int(st, 17)));
    json_object_object_add(o, "models_synced_at",
                          synced_at > 0 ? json_object_new_int64(synced_at) : NULL);
    /* last_check_ok is -1 until the provider has actually been tested. Report
     * that as null rather than false, so the UI can distinguish "never tested"
     * from "tested and failed". */
    if (sqlite3_column_int(st, 14) < 0) {
        json_object_object_add(last, "ok", NULL);
        json_object_object_add(last, "latency_ms", NULL);
        json_object_object_add(last, "checked_at", NULL);
        json_object_object_add(last, "error", json_object_new_string(""));
    } else {
        int latency = sqlite3_column_int(st, 15);
        json_object_object_add(last, "ok",
                               json_object_new_boolean(sqlite3_column_int(st, 14) ? 1 : 0));
        json_object_object_add(last, "latency_ms",
                               latency >= 0 ? json_object_new_int(latency) : NULL);
        json_object_object_add(last, "checked_at",
                               json_object_new_int64(sqlite3_column_int64(st, 13)));
        json_object_object_add(last, "error", json_object_new_string(nc_text_or_empty(st, 16)));
    }
    json_object_object_add(o, "last_check", last);
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 19)));
}

#define NC_AI_PROVIDER_SELECT \
    "SELECT p.id,p.provider,p.display_name,p.api_base,p.api_key,p.auth_mode," \
    "p.default_model,p.role,p.priority,p.weight,p.enabled,p.reasoning_effort," \
    "p.reasoning_api_shape,p.last_check_ts,p.last_check_ok,p.last_check_latency_ms," \
    "p.last_check_error," \
    "(SELECT COUNT(*) FROM ai_provider_model m WHERE m.provider_id=p.id)," \
    "(SELECT MAX(m.synced_at) FROM ai_provider_model m WHERE m.provider_id=p.id)," \
    "p.updated_at FROM ai_provider p "

struct json_object *jmx_ai_providers_list(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;

    if (jmx_netconfig_db_init() != 0) {
        json_object_object_add(data, "providers", arr);
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    nc_ai_db_init();
    if (nc_prepare(&st, NC_AI_PROVIDER_SELECT
                   "ORDER BY p.priority,p.id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            nc_ai_provider_row_json(o, st);
            json_object_array_add(arr, o);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(data, "providers", arr);
    json_object_object_add(data, "count", json_object_new_int(json_object_array_length(arr)));
    json_object_object_add(data, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_ai_provider_get(const char *id)
{
    struct json_object *data = NULL;
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (!nc_ai_provider_id_ok(id) || jmx_netconfig_db_init() != 0)
        return NULL;
    nc_ai_db_init();
    if (nc_prepare(&st, NC_AI_PROVIDER_SELECT "WHERE p.id=?1") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            data = json_object_new_object();
            nc_ai_provider_row_json(data, st);
            found = 1;
        }
        sqlite3_finalize(st);
    }
    if (!found)
        return NULL;
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/*
 * Return codes shared by create/update:
 *  -1 internal, -2 invalid_provider_kind, -3 conflicting_api_key_action,
 *  -4 invalid_role, -5 invalid_auth_mode, -6 provider_not_found,
 *  -7 invalid_field
 */
static int nc_ai_provider_validate_common(struct json_object *cfg, int creating)
{
    struct json_object *v = NULL;
    const char *s;

    if (json_object_object_get_ex(cfg, "provider", &v) && v) {
        if (!json_object_is_type(v, json_type_string) ||
            !nc_ai_provider_kind_ok(json_object_get_string(v)))
            return -2;
    } else if (creating) {
        return -2;
    }
    if (json_object_object_get_ex(cfg, "auth_mode", &v) && v) {
        if (!json_object_is_type(v, json_type_string))
            return -5;
        s = json_object_get_string(v);
        if (strcmp(s, "api_key") && strcmp(s, "oauth"))
            return -5;
    }
    if (json_object_object_get_ex(cfg, "role", &v) && v) {
        if (!json_object_is_type(v, json_type_string))
            return -4;
        s = json_object_get_string(v);
        if (strcmp(s, "primary") && strcmp(s, "standby"))
            return -4;
    }
    if (json_object_object_get_ex(cfg, "priority", &v) && v) {
        if (!json_object_is_type(v, json_type_int) ||
            json_object_get_int(v) < 0 || json_object_get_int(v) > 10000)
            return -7;
    }
    if (json_object_object_get_ex(cfg, "weight", &v) && v) {
        if (!json_object_is_type(v, json_type_int) ||
            json_object_get_int(v) < 1 || json_object_get_int(v) > 1000)
            return -7;
    }
    return 0;
}

/* Only one primary is allowed; promoting one demotes the others. */
static int nc_ai_provider_demote_others(const char *id)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (nc_prepare(&st, "UPDATE ai_provider SET role='standby',updated_at=?2 "
                        "WHERE role='primary' AND id<>?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, nc_now_s());
    rc = nc_step_done(st);
    sqlite3_finalize(st);
    return rc;
}

int jmx_ai_provider_create(struct json_object *cfg, char out_id[65])
{
    sqlite3_stmt *st = NULL;
    char id[33] = "";
    int rc = -1, vrc;
    const char *role;

    if (!cfg || jmx_netconfig_db_init() != 0)
        return -1;
    nc_ai_db_init();
    vrc = nc_ai_provider_validate_common(cfg, 1);
    if (vrc != 0)
        return vrc;
    if (nc_ai_provider_id_new(id) != 0)
        return -1;
    role = nc_json_str_def(cfg, "role", "standby");
    if (nc_txn_begin() != 0)
        return -1;
    if (nc_prepare(&st,
        "INSERT INTO ai_provider(id,provider,display_name,api_base,api_key,auth_mode,"
        "default_model,role,priority,weight,enabled,reasoning_effort,"
        "reasoning_api_shape,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)") != 0)
        goto out;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, nc_json_str_def(cfg, "provider", "openai"), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, nc_json_str_def(cfg, "display_name", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, nc_json_str_def(cfg, "api_base", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, nc_json_str_def(cfg, "api_key", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, nc_json_str_def(cfg, "auth_mode", "api_key"), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, nc_json_str_def(cfg, "default_model", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, role, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 9, nc_json_int_def(cfg, "priority", 100));
    sqlite3_bind_int(st, 10, nc_json_int_def(cfg, "weight", 1));
    sqlite3_bind_int(st, 11, nc_json_bool_def(cfg, "enabled", 0) ? 1 : 0);
    sqlite3_bind_text(st, 12, nc_json_str_def(cfg, "reasoning_effort", "auto"), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 13, nc_json_str_def(cfg, "reasoning_api_shape", "chat_completions"), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 14, nc_now_s());
    if (nc_step_done(st) != 0)
        goto out;
    sqlite3_finalize(st);
    st = NULL;
    if (!strcmp(role, "primary") && nc_ai_provider_demote_others(id) != 0)
        goto out;
    rc = 0;
    if (out_id)
        snprintf(out_id, 65, "%s", id);
out:
    if (st) sqlite3_finalize(st);
    return nc_txn_end(rc);
}

/*
 * Partial update. A field that is absent from the payload keeps its stored
 * value; this is why every column gets its own guarded UPDATE instead of one
 * blanket statement. `api_key` absent means keep, empty string means clear.
 */
int jmx_ai_provider_update(const char *id, struct json_object *cfg)
{
    static const struct { const char *key; const char *column; } text_fields[] = {
        { "provider", "provider" },
        { "display_name", "display_name" },
        { "api_base", "api_base" },
        { "auth_mode", "auth_mode" },
        { "default_model", "default_model" },
        { "reasoning_effort", "reasoning_effort" },
        { "reasoning_api_shape", "reasoning_api_shape" },
        { NULL, NULL }
    };
    static const struct { const char *key; const char *column; } int_fields[] = {
        { "priority", "priority" },
        { "weight", "weight" },
        { NULL, NULL }
    };
    sqlite3_stmt *st = NULL;
    struct json_object *v = NULL;
    int rc = -1, vrc, exists = 0;
    char sql[160];

    if (!nc_ai_provider_id_ok(id) || !cfg || jmx_netconfig_db_init() != 0)
        return -1;
    nc_ai_db_init();
    vrc = nc_ai_provider_validate_common(cfg, 0);
    if (vrc != 0)
        return vrc;
    if (nc_prepare(&st, "SELECT 1 FROM ai_provider WHERE id=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    exists = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    st = NULL;
    if (!exists)
        return -6;

    if (nc_txn_begin() != 0)
        return -1;
    for (int i = 0; text_fields[i].key; i++) {
        if (!json_object_object_get_ex(cfg, text_fields[i].key, &v) || !v ||
            !json_object_is_type(v, json_type_string))
            continue;
        snprintf(sql, sizeof(sql), "UPDATE ai_provider SET %s=?2 WHERE id=?1",
                 text_fields[i].column);
        if (nc_prepare(&st, sql) != 0)
            goto out;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, json_object_get_string(v), -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0)
            goto out;
        sqlite3_finalize(st);
        st = NULL;
    }
    for (int i = 0; int_fields[i].key; i++) {
        if (!json_object_object_get_ex(cfg, int_fields[i].key, &v) || !v ||
            !json_object_is_type(v, json_type_int))
            continue;
        snprintf(sql, sizeof(sql), "UPDATE ai_provider SET %s=?2 WHERE id=?1",
                 int_fields[i].column);
        if (nc_prepare(&st, sql) != 0)
            goto out;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, json_object_get_int(v));
        if (nc_step_done(st) != 0)
            goto out;
        sqlite3_finalize(st);
        st = NULL;
    }
    if (json_object_object_get_ex(cfg, "enabled", &v) && v) {
        if (nc_prepare(&st, "UPDATE ai_provider SET enabled=?2 WHERE id=?1") != 0)
            goto out;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, json_object_get_boolean(v) ? 1 : 0);
        if (nc_step_done(st) != 0)
            goto out;
        sqlite3_finalize(st);
        st = NULL;
    }
    if (json_object_object_get_ex(cfg, "api_key", &v) && v &&
        json_object_is_type(v, json_type_string)) {
        if (nc_prepare(&st, "UPDATE ai_provider SET api_key=?2 WHERE id=?1") != 0)
            goto out;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, json_object_get_string(v), -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0)
            goto out;
        sqlite3_finalize(st);
        st = NULL;
    }
    if (json_object_object_get_ex(cfg, "role", &v) && v &&
        json_object_is_type(v, json_type_string)) {
        const char *role = json_object_get_string(v);
        if (nc_prepare(&st, "UPDATE ai_provider SET role=?2 WHERE id=?1") != 0)
            goto out;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, role, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0)
            goto out;
        sqlite3_finalize(st);
        st = NULL;
        if (!strcmp(role, "primary") && nc_ai_provider_demote_others(id) != 0)
            goto out;
    }
    if (nc_prepare(&st, "UPDATE ai_provider SET updated_at=?2 WHERE id=?1") != 0)
        goto out;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, nc_now_s());
    if (nc_step_done(st) != 0)
        goto out;
    sqlite3_finalize(st);
    st = NULL;
    rc = 0;
out:
    if (st) sqlite3_finalize(st);
    return nc_txn_end(rc);
}

int jmx_ai_provider_delete(const char *id)
{
    sqlite3_stmt *st = NULL;
    int rc = -1, removed = 0;

    if (!nc_ai_provider_id_ok(id) || jmx_netconfig_db_init() != 0)
        return -1;
    nc_ai_db_init();
    if (nc_txn_begin() != 0)
        return -1;
    if (nc_prepare(&st, "DELETE FROM ai_provider WHERE id=?1") != 0)
        goto out;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (nc_step_done(st) != 0)
        goto out;
    removed = sqlite3_changes(g_netconfig_db);
    sqlite3_finalize(st);
    st = NULL;
    if (!removed) {
        rc = -6;
        goto out;
    }
    if (nc_prepare(&st, "DELETE FROM ai_provider_model WHERE provider_id=?1") != 0)
        goto out;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (nc_step_done(st) != 0)
        goto out;
    sqlite3_finalize(st);
    st = NULL;
    rc = 0;
out:
    if (st) sqlite3_finalize(st);
    if (rc == -6) {
        nc_txn_end(-1);
        return -6;
    }
    return nc_txn_end(rc);
}

int jmx_ai_provider_check_record(const char *id, int ok, int latency_ms,
                                 const char *error)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (!nc_ai_provider_id_ok(id) || jmx_netconfig_db_init() != 0)
        return -1;
    nc_ai_db_init();
    if (nc_prepare(&st,
        "UPDATE ai_provider SET last_check_ts=?2,last_check_ok=?3,"
        "last_check_latency_ms=?4,last_check_error=?5 WHERE id=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, nc_now_s());
    sqlite3_bind_int(st, 3, ok ? 1 : 0);
    sqlite3_bind_int(st, 4, latency_ms);
    sqlite3_bind_text(st, 5, error ? error : "", -1, SQLITE_TRANSIENT);
    rc = nc_step_done(st);
    sqlite3_finalize(st);
    return rc;
}

struct json_object *jmx_ai_provider_models_list(const char *id)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int64_t synced_at = 0;

    if (!nc_ai_provider_id_ok(id) || jmx_netconfig_db_init() != 0) {
        json_object_put(data);
        json_object_put(arr);
        return NULL;
    }
    nc_ai_db_init();
    if (nc_prepare(&st, "SELECT 1 FROM ai_provider WHERE id=?1") == 0) {
        int exists;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        exists = sqlite3_step(st) == SQLITE_ROW;
        sqlite3_finalize(st);
        st = NULL;
        if (!exists) {
            json_object_put(data);
            json_object_put(arr);
            return NULL;
        }
    }
    if (nc_prepare(&st, "SELECT model_id,display_name,synced_at FROM ai_provider_model "
                        "WHERE provider_id=?1 ORDER BY model_id") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            int64_t ts = sqlite3_column_int64(st, 2);
            json_object_object_add(o, "id", json_object_new_string(nc_text_or_empty(st, 0)));
            json_object_object_add(o, "display_name", json_object_new_string(nc_text_or_empty(st, 1)));
            json_object_object_add(o, "synced_at", json_object_new_int64(ts));
            if (ts > synced_at) synced_at = ts;
            json_object_array_add(arr, o);
        }
        sqlite3_finalize(st);
    }
