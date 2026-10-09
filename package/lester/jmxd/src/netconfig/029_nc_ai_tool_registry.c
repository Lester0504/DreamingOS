    json_object_object_add(data, "provider_id", json_object_new_string(id));
    json_object_object_add(data, "models", arr);
    json_object_object_add(data, "model_count", json_object_new_int(json_object_array_length(arr)));
    json_object_object_add(data, "models_synced_at",
                          synced_at > 0 ? json_object_new_int64(synced_at) : NULL);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

int jmx_ai_provider_models_replace(const char *id, struct json_object *models)
{
    sqlite3_stmt *st = NULL;
    int rc = -1, n;
    int64_t now = nc_now_s();

    if (!nc_ai_provider_id_ok(id) || !models ||
        !json_object_is_type(models, json_type_array) ||
        jmx_netconfig_db_init() != 0)
        return -1;
    nc_ai_db_init();
    if (nc_txn_begin() != 0)
        return -1;
    if (nc_prepare(&st, "DELETE FROM ai_provider_model WHERE provider_id=?1") != 0)
        goto out;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (nc_step_done(st) != 0)
        goto out;
    sqlite3_finalize(st);
    st = NULL;
    n = json_object_array_length(models);
    for (int i = 0; i < n; i++) {
        struct json_object *item = json_object_array_get_idx(models, i);
        const char *model_id = NULL, *display = "";

        if (item && json_object_is_type(item, json_type_string)) {
            model_id = json_object_get_string(item);
        } else if (item && json_object_is_type(item, json_type_object)) {
            model_id = nc_json_str_def(item, "id", "");
            display = nc_json_str_def(item, "display_name", "");
        }
        if (!model_id || !model_id[0])
            continue;
        if (nc_prepare(&st, "INSERT OR REPLACE INTO ai_provider_model"
                            "(provider_id,model_id,display_name,synced_at) "
                            "VALUES(?1,?2,?3,?4)") != 0)
            goto out;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, model_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, display, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, now);
        if (nc_step_done(st) != 0)
            goto out;
        sqlite3_finalize(st);
        st = NULL;
    }
    rc = 0;
out:
    if (st) sqlite3_finalize(st);
    return nc_txn_end(rc);
}

struct json_object *jmx_ai_dispatch_policy_get(void)
{
    struct json_object *data = json_object_new_object();
    sqlite3_stmt *st = NULL;
    struct json_object *strategies = json_object_new_array();

    json_object_object_add(data, "strategy", json_object_new_string("single"));
    json_object_object_add(data, "failover_timeout_ms", json_object_new_int(20000));
    json_object_object_add(data, "failover_max_attempts", json_object_new_int(2));
    json_object_object_add(data, "updated_at", json_object_new_int64(0));
    if (jmx_netconfig_db_init() != 0)
        goto done;
    nc_ai_db_init();
    if (nc_prepare(&st, "SELECT strategy,failover_timeout_ms,failover_max_attempts,"
                        "updated_at FROM ai_dispatch_policy WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            json_object_object_add(data, "strategy",
                                   json_object_new_string(nc_text_or_empty(st, 0)));
            json_object_object_add(data, "failover_timeout_ms",
                                   json_object_new_int(sqlite3_column_int(st, 1)));
            json_object_object_add(data, "failover_max_attempts",
                                   json_object_new_int(sqlite3_column_int(st, 2)));
            json_object_object_add(data, "updated_at",
                                   json_object_new_int64(sqlite3_column_int64(st, 3)));
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    if (nc_prepare(&st, "SELECT COUNT(*),SUM(enabled),"
                        "SUM(CASE WHEN role='primary' AND enabled=1 THEN 1 ELSE 0 END) "
                        "FROM ai_provider") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            json_object_object_add(data, "provider_count",
                                   json_object_new_int(sqlite3_column_int(st, 0)));
            json_object_object_add(data, "enabled_provider_count",
                                   json_object_new_int(sqlite3_column_int(st, 1)));
            json_object_object_add(data, "primary_ready",
                                   json_object_new_boolean(sqlite3_column_int(st, 2) > 0));
        }
        sqlite3_finalize(st);
        st = NULL;
    }
done:
    json_object_array_add(strategies, json_object_new_string("single"));
    json_object_array_add(strategies, json_object_new_string("failover"));
    json_object_array_add(strategies, json_object_new_string("load_balance"));
    json_object_object_add(data, "available_strategies", strategies);
    json_object_object_add(data, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* -2 invalid_strategy, -7 invalid_field */
int jmx_ai_dispatch_policy_set(struct json_object *cfg)
{
    sqlite3_stmt *st = NULL;
    struct json_object *v = NULL;
    const char *strategy = NULL;
    int timeout_ms = -1, max_attempts = -1;
    int rc = -1;

    if (!cfg || jmx_netconfig_db_init() != 0)
        return -1;
    nc_ai_db_init();
    if (json_object_object_get_ex(cfg, "strategy", &v) && v) {
        if (!json_object_is_type(v, json_type_string) ||
            !nc_ai_strategy_ok(json_object_get_string(v)))
            return -2;
        strategy = json_object_get_string(v);
    }
    if (json_object_object_get_ex(cfg, "failover_timeout_ms", &v) && v) {
        if (!json_object_is_type(v, json_type_int))
            return -7;
        timeout_ms = json_object_get_int(v);
        if (timeout_ms < 1000 || timeout_ms > 120000)
            return -7;
    }
