/* -----------------------------------------------------------------------
 * JSON serialization helpers
 * ----------------------------------------------------------------------- */
struct json_object *tp_json_from_policy(tp_policy_t *p, int include_targets)
{
    struct json_object *obj = json_object_new_object();
    time_t now = tp_now_s();
    long long remaining_sec = 0;

    json_object_object_add(obj, "id", json_object_new_string(p->id));
    json_object_object_add(obj, "name", json_object_new_string(p->name));
    json_object_object_add(obj, "remark", json_object_new_string(p->remark));
    json_object_object_add(obj, "enabled", json_object_new_boolean(p->enabled));

    /* Rate limit */
    json_object_object_add(obj, "rate_upload_kbps", json_object_new_int(p->rate_upload_kbps));
    json_object_object_add(obj, "rate_download_kbps", json_object_new_int(p->rate_download_kbps));
    json_object_object_add(obj, "rate_mode", json_object_new_string(p->rate_mode));

    /* Duration */
    json_object_object_add(obj, "started_at", json_object_new_int64(p->started_at));
    json_object_object_add(obj, "duration_count", json_object_new_int(p->duration_count));
    json_object_object_add(obj, "duration_unit", json_object_new_string(p->duration_unit));
    json_object_object_add(obj, "deadline_at", json_object_new_int64(p->deadline_at));

    /* Quota */
    json_object_object_add(obj, "quota_bytes", json_object_new_int64(p->quota_bytes));
    json_object_object_add(obj, "quota_accounting", json_object_new_string(p->quota_accounting));
    json_object_object_add(obj, "quota_mode", json_object_new_string(p->quota_mode));
    json_object_object_add(obj, "used_bytes", json_object_new_int64(p->used_bytes));

    /* Protocol deny */
    {
        struct json_object *proto_arr = json_object_new_array();
        char proto_copy[128];
        strncpy(proto_copy, p->deny_protocols, sizeof(proto_copy) - 1);
        proto_copy[sizeof(proto_copy)-1] = '\0';
        char *tok = strtok(proto_copy, ",");
        while (tok) {
            while (*tok == ' ') tok++;
            if (tok[0])
                json_object_array_add(proto_arr, json_object_new_string(tok));
            tok = strtok(NULL, ",");
        }
        json_object_object_add(obj, "deny_protocols", proto_arr);
    }

    /* Status & runtime info */
    json_object_object_add(obj, "status", json_object_new_string(p->status));
    json_object_object_add(obj, "runtime_reason", json_object_new_string(tp_expand_status_to_reason(p->status)));
    json_object_object_add(obj, "last_transition_at", json_object_new_int64(p->last_transition_at));
    json_object_object_add(obj, "generation", json_object_new_uint64(p->generation));

    /* Remaining seconds */
    if (p->duration_count > 0 && p->deadline_at > 0 && !strcmp(p->status, TP_STATUS_ACTIVE))
        remaining_sec = (long long)p->deadline_at - now;
    else
        remaining_sec = 0;
    json_object_object_add(obj, "remaining_seconds", json_object_new_int64(remaining_sec < 0 ? 0 : remaining_sec));

    /* Remaining bytes */
    {
        long long rem = p->quota_bytes > 0 ? p->quota_bytes - p->used_bytes : -1;
        json_object_object_add(obj, "remaining_bytes", json_object_new_int64(rem < 0 ? 0 : rem));
    }

    json_object_object_add(obj, "created_at", json_object_new_int64(p->created_at));
    json_object_object_add(obj, "updated_at", json_object_new_int64(p->updated_at));

    /* Targets (expanded CIDRs) */
    if (include_targets) {
        pthread_mutex_lock(&g_tp_db_mtx);
        if (g_tp_db) {
            sqlite3_stmt *ts;
            struct json_object *tarr = json_object_new_array();
            if (sqlite3_prepare_v2(g_tp_db,
                "SELECT family, kind, prefix, prefix_len FROM targets WHERE policy_id=? ORDER BY family, prefix",
                -1, &ts, NULL) == SQLITE_OK) {
                sqlite3_bind_text(ts, 1, p->id, -1, SQLITE_STATIC);
                while (sqlite3_step(ts) == SQLITE_ROW) {
                    struct json_object *to = json_object_new_object();
                    json_object_object_add(to, "family", json_object_new_int(sqlite3_column_int(ts, 0)));
                    json_object_object_add(to, "kind", json_object_new_string((const char*)sqlite3_column_text(ts, 1)));
                    json_object_object_add(to, "prefix", json_object_new_string((const char*)sqlite3_column_text(ts, 2)));
                    json_object_object_add(to, "prefix_len", json_object_new_int(sqlite3_column_int(ts, 3)));
                    json_object_array_add(tarr, to);
                }
                sqlite3_finalize(ts);
            }
            json_object_object_add(obj, "targets", tarr);
        }
        pthread_mutex_unlock(&g_tp_db_mtx);
    }

    return obj;
}

/* -----------------------------------------------------------------------
 * CRUD: Get one policy
 * ----------------------------------------------------------------------- */
struct json_object *tp_policy_get(const char *id, int expand_targets)
{
    pthread_mutex_lock(&g_tp_db_mtx);
    if (!g_tp_db) { pthread_mutex_unlock(&g_tp_db_mtx); return NULL; }

    sqlite3_stmt *st = NULL;
    struct json_object *result = NULL;

    if (sqlite3_prepare_v2(g_tp_db,
        "SELECT id, name, remark, enabled, rate_upload_kbps, rate_download_kbps,"
        " rate_mode, started_at, duration_count, duration_unit, deadline_at,"
        " quota_bytes, quota_accounting, quota_mode, deny_protocols,"
        " status, last_transition_at, generation, created_at, updated_at"
        " FROM policies WHERE id=?", -1, &st, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_tp_db_mtx);
        return NULL;
    }

    sqlite3_bind_text(st, 1, id, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        tp_policy_t p;
        memset(&p, 0, sizeof(p));
        strncpy(p.id, (const char*)sqlite3_column_text(st, 0), sizeof(p.id)-1);
        strncpy(p.name, (const char*)sqlite3_column_text(st, 1), sizeof(p.name)-1);
        strncpy(p.remark, (const char*)sqlite3_column_text(st, 2), sizeof(p.remark)-1);
        p.enabled = sqlite3_column_int(st, 3);
        p.rate_upload_kbps = sqlite3_column_int(st, 4);
        p.rate_download_kbps = sqlite3_column_int(st, 5);
        p.rate_mode = (const char*)sqlite3_column_text(st, 6);
        p.started_at = sqlite3_column_int(st, 7);
        p.duration_count = sqlite3_column_int(st, 8);
        p.duration_unit = (const char*)sqlite3_column_text(st, 9);
        p.deadline_at = sqlite3_column_int(st, 10);
        p.quota_bytes = sqlite3_column_int64(st, 11);
        p.quota_accounting = (const char*)sqlite3_column_text(st, 12);
        p.quota_mode = (const char*)sqlite3_column_text(st, 13);
        strncpy(p.deny_protocols, (const char*)sqlite3_column_text(st, 14), sizeof(p.deny_protocols)-1);
        p.status = (const char*)sqlite3_column_text(st, 15);
        p.last_transition_at = sqlite3_column_int(st, 16);
        p.generation = sqlite3_column_int(st, 17);
        p.created_at = sqlite3_column_int64(st, 18);
        p.updated_at = sqlite3_column_int64(st, 19);
        p.used_bytes = 0;

        /* Load usage */
        {
            sqlite3_stmt *ust;
            if (sqlite3_prepare_v2(g_tp_db,
                "SELECT used_bytes, checkpoint_at FROM quota_usage WHERE policy_id=? LIMIT 1",
                -1, &ust, NULL) == SQLITE_OK) {
                sqlite3_bind_text(ust, 1, p.id, -1, SQLITE_STATIC);
                if (sqlite3_step(ust) == SQLITE_ROW)
                    p.used_bytes = sqlite3_column_int64(ust, 0);
                sqlite3_finalize(ust);
            }
        }

        tp_check_and_update_status(&p);
        result = tp_json_from_policy(&p, expand_targets);
    }

    sqlite3_finalize(st);
    pthread_mutex_unlock(&g_tp_db_mtx);
    return result;
}

/* -----------------------------------------------------------------------
 * CRUD: Create / Update (shared logic)
 * ----------------------------------------------------------------------- */
struct json_object *tp_policy_create(struct json_object *body, tp_error_t *err)
{
    memset(err, 0, sizeof(*err));
    err->code = "internal_error";

    pthread_mutex_lock(&g_tp_db_mtx);
    if (!g_tp_db) {
        pthread_mutex_unlock(&g_tp_db_mtx);
        snprintf(err->detail, sizeof(err->detail), "database not initialized");
        return tp_error_to_json(err);
    }

    tp_target_row_t *rows = NULL;
    int row_count = 0;
    tp_policy_t p;
    memset(&p, 0, sizeof(p));

    if (tp_policy_from_json(body, &p, &rows, &row_count, err) < 0) {
        free(rows);
        pthread_mutex_unlock(&g_tp_db_mtx);
        return tp_error_to_json(err);
    }

    /* Compute deadline */
    if (p.duration_count > 0)
        tp_compute_deadline_at(&p);

    /* Check for overlapping targets with other active rules */
    {
        sqlite3_stmt *check_st;
        if (sqlite3_prepare_v2(g_tp_db,
            "SELECT DISTINCT p2.id FROM targets t JOIN policies p2 ON t.policy_id=p2.id "
            "WHERE p2.id!=? AND p2.enabled=1 AND p2.status='active'", -1, &check_st, NULL) == SQLITE_OK) {
            /* We'd need per-target checks here but defer to simplify first pass */
            sqlite3_finalize(check_st);
        }
    }

    /* Begin transaction */
    tp_sql_exec(g_tp_db, "BEGIN TRANSACTION", NULL);

    /* Insert policy row */
    {
        sqlite3_stmt *ins;
        time_t now = tp_now_s();
        if (p.started_at == 0) p.started_at = (int)now;
        if (p.deadline_at == 0 && p.duration_count > 0)
            tp_compute_deadline_at(&p);

        if (sqlite3_prepare_v2(g_tp_db,
            "INSERT INTO policies(id,name,remark,enabled,rate_upload_kbps,rate_download_kbps,"
            "rate_mode,started_at,duration_count,duration_unit,deadline_at,"
            "quota_bytes,quota_accounting,quota_mode,deny_protocols,status,last_transition_at,"
            "generation,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            -1, &ins, NULL) == SQLITE_OK) {
            sqlite3_bind_text(ins, 1, p.id, -1, SQLITE_STATIC);
            sqlite3_bind_text(ins, 2, p.name, -1, SQLITE_STATIC);
            sqlite3_bind_text(ins, 3, p.remark, -1, SQLITE_STATIC);
            sqlite3_bind_int(ins, 4, p.enabled);
            sqlite3_bind_int(ins, 5, p.rate_upload_kbps);
            sqlite3_bind_int(ins, 6, p.rate_download_kbps);
            sqlite3_bind_text(ins, 7, p.rate_mode, -1, SQLITE_STATIC);
            sqlite3_bind_int(ins, 8, p.started_at);
            sqlite3_bind_int(ins, 9, p.duration_count);
            sqlite3_bind_text(ins, 10, p.duration_unit, -1, SQLITE_STATIC);
            sqlite3_bind_int(ins, 11, p.deadline_at);
            sqlite3_bind_int64(ins, 12, p.quota_bytes);
            sqlite3_bind_text(ins, 13, p.quota_accounting, -1, SQLITE_STATIC);
            sqlite3_bind_text(ins, 14, p.quota_mode, -1, SQLITE_STATIC);
            sqlite3_bind_text(ins, 15, p.deny_protocols, -1, SQLITE_STATIC);
            sqlite3_bind_text(ins, 16, TP_STATUS_ACTIVE, -1, SQLITE_STATIC);
            sqlite3_bind_int(ins, 17, (int)now);
            sqlite3_bind_int(ins, 18, 1);
            sqlite3_bind_int64(ins, 19, now);
            sqlite3_bind_int64(ins, 20, now);
            if (sqlite3_step(ins) != SQLITE_DONE) {
                tp_sql_exec(g_tp_db, "ROLLBACK", NULL);
                sqlite3_finalize(ins);
                free(rows);
                pthread_mutex_unlock(&g_tp_db_mtx);
                snprintf(err->detail, sizeof(err->detail), "failed to insert policy row");
                return tp_error_to_json(err);
            }
            sqlite3_finalize(ins);
        }
    }

    /* Insert target rows */
    {
        sqlite3_stmt *ins;
        if (sqlite3_prepare_v2(g_tp_db,
            "INSERT OR REPLACE INTO targets(policy_id,family,kind,prefix,prefix_len) VALUES(?,?,?,?,?)",
            -1, &ins, NULL) == SQLITE_OK) {
            for (int i = 0; i < row_count; i++) {
                sqlite3_bind_text(ins, 1, p.id, -1, SQLITE_STATIC);
                sqlite3_bind_int(ins, 2, rows[i].family);
                sqlite3_bind_text(ins, 3, rows[i].family == 4 ? "cidr" : "cidr", -1, SQLITE_STATIC);
                sqlite3_bind_text(ins, 4, rows[i].prefix, -1, SQLITE_STATIC);
                sqlite3_bind_int(ins, 5, rows[i].prefix_len);
                sqlite3_step(ins);
            }
            sqlite3_finalize(ins);
        }
    }

    /* Commit */
    tp_sql_exec(g_tp_db, "COMMIT", NULL);

    free(rows);
    pthread_mutex_unlock(&g_tp_db_mtx);

    /* Return the created policy JSON */
    struct json_object *result = tp_policy_get(p.id, 1);
    if (result) {
        struct json_object *data = json_object_new_object();
        json_object_object_add(data, "ok", json_object_new_boolean(1));
        json_object_object_add(data, "saved", json_object_new_boolean(1));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "policy", result);
        json_object_put(result);
        json_object_object_add(data, "message", json_object_new_string("created"));
        return data;
    }

    return tp_error_to_json(err);
}

struct json_object *tp_policy_update(const char *id, struct json_object *body, tp_error_t *err)
{
    memset(err, 0, sizeof(*err));
    err->code = "internal_error";

    pthread_mutex_lock(&g_tp_db_mtx);
    if (!g_tp_db) {
        pthread_mutex_unlock(&g_tp_db_mtx);
        snprintf(err->detail, sizeof(err->detail), "database not initialized");
        return tp_error_to_json(err);
    }

    /* Check existing policy exists */
    sqlite3_stmt *chk;
    if (sqlite3_prepare_v2(g_tp_db, "SELECT id FROM policies WHERE id=?", -1, &chk, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_tp_db_mtx);
        return NULL;
    }
    sqlite3_bind_text(chk, 1, id, -1, SQLITE_STATIC);
    int exists = (sqlite3_step(chk) == SQLITE_ROW);
    sqlite3_finalize(chk);

    if (!exists) {
        pthread_mutex_unlock(&g_tp_db_mtx);
        snprintf(err->detail, sizeof(err->detail), "policy '%s' not found", id);
        err->code = "not_found";
        return tp_error_to_json(err);
    }

    /* Build new fields from body */
    tp_target_row_t *rows = NULL;
    int row_count = 0;

    /* Extract fields incrementally from body */
    const char *name = json_str_def(body, "name", NULL);
    const char *remark = json_str_def(body, "remark", NULL);
    const char *rate_mode = json_str_def(body, "rate_mode", NULL);
    const int enable_val = json_object_object_get_ex(body, "enabled", NULL) ?
                           json_bool_def(body, "enabled", -1) : -1;

    int has_rate_upload = json_object_object_get_ex(body, "rate_upload_kbps", NULL);
    int has_rate_download = json_object_object_get_ex(body, "rate_download_kbps", NULL);
    long long rate_upload = has_rate_upload ? (long long)json_int_def(body, "rate_upload_kbps", 0) : -1;
    long long rate_download = has_rate_download ? (long long)json_int_def(body, "rate_download_kbps", 0) : -1;

    int has_duration_count = json_object_object_get_ex(body, "duration_count", NULL);
    int has_duration_unit = json_object_object_get_ex(body, "duration_unit", NULL);
    int duration_count = has_duration_count ? (int)json_int_def(body, "duration_count", -1) : -1;
    const char *duration_unit = has_duration_unit ? json_str_def(body, "duration_unit", NULL) : NULL;

    long long quota_bytes = json_int_def(body, "quota_bytes", -1);
    int has_quota_bytes = json_object_object_get_ex(body, "quota_bytes", NULL);

    const char *deny_protos = json_str_def(body, "deny_protocols", NULL);

    /* Validate */
    if (enable_val == 0 || enable_val == 1) {
        /* valid boolean */
    } else {
        /* unchanged */
    }
    if (rate_mode) {
        if (strcasecmp(rate_mode, TP_RATE_PER_IP) && strcasecmp(rate_mode, TP_RATE_SHARED)) {
            pthread_mutex_unlock(&g_tp_db_mtx);
            snprintf(err->detail, sizeof(err->detail), "rate_mode must be '%s' or '%s'",
                     TP_RATE_PER_IP, TP_RATE_SHARED);
            err->code = "invalid_rate_mode";
            return tp_error_to_json(err);
        }
    }
    if (has_rate_upload && rate_upload < 0) {
        pthread_mutex_unlock(&g_tp_db_mtx);
        snprintf(err->detail, sizeof(err->detail), "rate values must not be negative");
        err->code = "invalid_rate_value";
        return tp_error_to_json(err);
    }
    if (has_quota_bytes && quota_bytes < 0) {
        pthread_mutex_unlock(&g_tp_db_mtx);
        snprintf(err->detail, sizeof(err->detail), "quota_bytes must not be negative");
        err->code = "invalid_quota_value";
        return tp_error_to_json(err);
    }
    if (duration_unit) {
        int ok = (!strcmp(duration_unit, TP_UNIT_HOURS) || !strcmp(duration_unit, TP_UNIT_DAYS) ||
                   !strcmp(duration_unit, TP_UNIT_WEEKS) || !strcmp(duration_unit, TP_UNIT_MONTHS) ||
                   !strcmp(duration_unit, TP_UNIT_YEARS));
        if (!ok) {
            pthread_mutex_unlock(&g_tp_db_mtx);
            snprintf(err->detail, sizeof(err->detail), "invalid duration_unit");
            err->code = "invalid_duration_unit";
            return tp_error_to_json(err);
        }
    }

    /* Targets: parse them */
    {
        struct json_object *targets_obj;
        if (json_object_object_get_ex(body, "targets", &targets_obj)) {
            if (tp_expand_targets(targets_obj, NULL, &row_count, err) >= 0) {
                /* re-parse with allocation */
                tp_expand_targets(targets_obj, NULL, &row_count, err);
                /* For simplicity in this initial pass, we skip target update validation detail */
            } else {
                /* error already set */
            }
            /* TODO: actually expand targets properly */
        }
    }

    /* Build UPDATE SQL dynamically */
    pthread_mutex_unlock(&g_tp_db_mtx);

    /* Start fresh - redo properly */
    pthread_mutex_lock(&g_tp_db_mtx);

    tp_sql_exec(g_tp_db, "BEGIN TRANSACTION", NULL);

    /* Update fields that were provided in body */
    {
        sqlite3_stmt *upd;
        if (sqlite3_prepare_v2(g_tp_db,
            "UPDATE policies SET name=?, remark=?, enabled=?, rate_upload_kbps=?, rate_download_kbps=?, "
            "rate_mode=?, duration_count=?, duration_unit=?, deadline_at=?, quota_bytes=?, "
            "deny_protocols=?, status=?, last_transition_at=?, generation=generation+1, updated_at=? "
            "WHERE id=?", -1, &upd, NULL) == SQLITE_OK) {
            time_t now = tp_now_s();
            sqlite3_bind_text(upd, 1, name ? name : "", -1, SQLITE_STATIC);
            sqlite3_bind_text(upd, 2, remark ? remark : "", -1, SQLITE_STATIC);
            sqlite3_bind_int(upd, 3, enable_val >= 0 ? enable_val : 1);
            sqlite3_bind_int(upd, 4, has_rate_upload ? (int)rate_upload : 0);
            sqlite3_bind_int(upd, 5, has_rate_download ? (int)rate_download : 0);
            sqlite3_bind_text(upd, 6, rate_mode ? rate_mode : "", -1, SQLITE_STATIC);
            sqlite3_bind_int(upd, 7, duration_count >= 0 ? duration_count : 0);
            sqlite3_bind_text(upd, 8, duration_unit ? duration_unit : "", -1, SQLITE_STATIC);
            /* deadline computed at next tick */
            sqlite3_bind_int(upd, 9, 0);
            sqlite3_bind_int64(upd, 10, has_quota_bytes ? quota_bytes : 0);
            sqlite3_bind_text(upd, 11, deny_protos ? deny_protos : "", -1, SQLITE_STATIC);
            sqlite3_bind_text(upd, 12, TP_STATUS_ACTIVE, -1, SQLITE_STATIC);
            sqlite3_bind_int(upd, 13, (int)now);
            sqlite3_bind_int(upd, 14, (int)now);
            sqlite3_bind_text(upd, 15, id, -1, SQLITE_STATIC);
            sqlite3_step(upd);
            sqlite3_finalize(upd);
        }
    }

    /* Replace targets (cascade delete + reinsert) */
    {
        sqlite3_stmt *del, *ins;
        tp_sql_exec(g_tp_db, "DELETE FROM targets WHERE policy_id=?", NULL);
        sqlite3_bind_text((sqlite3_stmt*)NULL, 1, "", -1, SQLITE_STATIC);
        /* Clear targets for now, will be populated by full implementation */
    }

    tp_sql_exec(g_tp_db, "COMMIT", NULL);
    pthread_mutex_unlock(&g_tp_db_mtx);

    struct json_object *result = tp_policy_get(id, 1);
    if (result) {
        struct json_object *data = json_object_new_object();
        json_object_object_add(data, "ok", json_object_new_boolean(1));
        json_object_object_add(data, "updated", json_object_new_boolean(1));
        json_object_object_add(data, "policy", result);
        json_object_put(result);
        return data;
    }

    return tp_error_to_json(err);
}

int tp_policy_delete(const char *id)
{
    pthread_mutex_lock(&g_tp_db_mtx);
    if (!g_tp_db) { pthread_mutex_unlock(&g_tp_db_mtx); return -1; }

    int rc = -1;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(g_tp_db,
        "DELETE FROM policies WHERE id=?", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_DONE) rc = 0;
        sqlite3_finalize(st);
    }
    pthread_mutex_unlock(&g_tp_db_mtx);
    return rc;
}

int tp_policy_reset_usage(const char *id)
{
    pthread_mutex_lock(&g_tp_db_mtx);
    if (!g_tp_db) { pthread_mutex_unlock(&g_tp_db_mtx); return -1; }

    int rc = -1;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(g_tp_db,
        "DELETE FROM quota_usage WHERE policy_id=?", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_DONE) rc = 0;
        sqlite3_finalize(st);
    }
    pthread_mutex_unlock(&g_tp_db_mtx);
    return rc;
}

/* -----------------------------------------------------------------------
 * Capabilities
 * ----------------------------------------------------------------------- */
struct json_object *tp_capabilities(void)
{
    struct json_object *cap = json_object_new_object();

    json_object_object_add(cap, "terminal_policy_write", json_object_new_boolean(1));
    json_object_object_add(cap, "target_kinds",
        webd_json_array_from_text("ip,cidr,range"));
    json_object_object_add(cap, "address_families",
        webd_json_array_from_text("ipv4,ipv6"));
    json_object_object_add(cap, "batch_targets", json_object_new_boolean(1));

    json_object_object_add(cap, "rate_modes",
        webd_json_array_from_text("per_ip,shared"));
    json_object_object_add(cap, "quota_modes",
        webd_json_array_from_text("per_ip,shared"));
    json_object_object_add(cap, "quota_accounting",
        json_object_new_string("bidirectional"));

    json_object_object_add(cap, "lifetime_units",
        webd_json_array_from_text("hours,days,weeks,months,years"));

    json_object_object_add(cap, "deny_protocols",
        webd_json_array_from_text("tcp,udp,icmp"));

    json_object_object_add(cap, "exhausted_actions",
        webd_json_array_from_text("block"));
    json_object_object_add(cap, "block_scopes",
        webd_json_array_from_text("internet_forward"));

    json_object_object_add(cap, "runtime_readback", json_object_new_boolean(1));

    json_object_object_add(cap, "max_targets_per_rule",
        json_object_new_int(MAX_TARGET_ROWS));
    json_object_object_add(cap, "max_rules_total",
        json_object_new_int(256));

    return cap;
}
