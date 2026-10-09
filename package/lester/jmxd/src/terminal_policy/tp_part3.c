/* -----------------------------------------------------------------------
 * tp_error_to_json: convert tp_error_t -> json object with code/message
 * ----------------------------------------------------------------------- */
static struct json_object *tp_error_to_json(tp_error_t *err)
{
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "ok", json_object_new_boolean(0));
    json_object_object_add(obj, "code", json_object_new_string(err ? err->code : "internal_error"));
    json_object_object_add(obj, "message", json_object_new_string(err ? err->detail : "unknown error"));
    return obj;
}

/* -----------------------------------------------------------------------
 * tp_policy_from_json: parse REST body into internal tp_policy_t
 * ----------------------------------------------------------------------- */
static int tp_policy_from_json(struct json_object *body, tp_policy_t *p,
                                tp_target_row_t **out_rows, int *out_row_count,
                                tp_error_t *err)
{
    const char *id = json_str_def(body, "id", "");
    if (!id[0]) {
        /* generate id from name+timestamp */
        time_t now = (time_t)tp_now_s();
        snprintf(p->id, sizeof(p->id), "tp_%ld", (long)now);
    } else {
        strncpy(p->id, id, sizeof(p->id) - 1);
        p->id[sizeof(p->id) - 1] = '\0';
        /* sanitize id chars */
        for (char *c = p->id; *c; c++) {
            if (!isalnum((unsigned char)*c) && *c != '_' && *c != '-' && *c != '.')
                *c = '_';
        }
    }

    strncpy(p->name, json_str_def(body, "name", ""), sizeof(p->name) - 1);
    p->name[sizeof(p->name) - 1] = '\0';

    strncpy(p->remark, json_str_def(body, "remark", ""), sizeof(p->remark) - 1);
    p->remark[sizeof(p->remark) - 1] = '\0';

    p->enabled = json_bool_def(body, "enabled", 1);

    /* rate limit */
    p->rate_upload_kbps = (int)json_int_def(body, "rate_upload_kbps", 0);
    p->rate_download_kbps = (int)json_int_def(body, "rate_download_kbps", 0);
    p->rate_mode = json_str_def(body, "rate_mode", TP_RATE_PER_IP);
    if (strcasecmp(p->rate_mode, TP_RATE_PER_IP) && strcasecmp(p->rate_mode, TP_RATE_SHARED)) {
        snprintf(err->detail, sizeof(err->detail),
                 "rate_mode must be '%s' or '%s'", TP_RATE_PER_IP, TP_RATE_SHARED);
        err->code = "invalid_rate_mode";
        return -1;
    }

    /* both zero = only quota/protocol control, allowed */
    if (p->rate_upload_kbps < 0 || p->rate_download_kbps < 0) {
        snprintf(err->detail, sizeof(err->detail),
                 "rate values must not be negative");
        err->code = "invalid_rate_value";
        return -1;
    }

    /* duration */
    p->started_at = (int)json_int_def(body, "started_at", 0);
    p->duration_count = (int)json_int_def(body, "duration_count", 0);
    p->duration_unit = json_str_def(body, "duration_unit", TP_UNIT_DAYS);

    int valid_unit = (!strcmp(p->duration_unit, TP_UNIT_HOURS) ||
                      !strcmp(p->duration_unit, TP_UNIT_DAYS) ||
                      !strcmp(p->duration_unit, TP_UNIT_WEEKS) ||
                      !strcmp(p->duration_unit, TP_UNIT_MONTHS) ||
                      !strcmp(p->duration_unit, TP_UNIT_YEARS));
    if (!valid_unit) {
        snprintf(err->detail, sizeof(err->detail),
                 "duration_unit must be one of: %s, %s, %s, %s, %s",
                 TP_UNIT_HOURS, TP_UNIT_DAYS, TP_UNIT_WEEKS, TP_UNIT_MONTHS, TP_UNIT_YEARS);
        err->code = "invalid_duration_unit";
        return -1;
    }

    if (p->duration_count <= 0)
        p->started_at = 0; /* force use of started_at field if no count */

    /* quota */
    p->quota_bytes = (long long)json_int_def(body, "quota_bytes", 0);
    p->quota_accounting = json_str_def(body, "quota_accounting", "bidirectional");
    p->quota_mode = json_str_def(body, "quota_mode", TP_QUOTA_SHARED);
    if (strcasecmp(p->quota_mode, TP_QUOTA_PER_IP) && strcasecmp(p->quota_mode, TP_QUOTA_SHARED)) {
        snprintf(err->detail, sizeof(err->detail),
                 "quota_mode must be '%s' or '%s'", TP_QUOTA_PER_IP, TP_QUOTA_SHARED);
        err->code = "invalid_quota_mode";
        return -1;
    }
    if (p->quota_bytes < 0) {
        snprintf(err->detail, sizeof(err->detail),
                 "quota_bytes must not be negative");
        err->code = "invalid_quota_value";
        return -1;
    }

    /* protocol deny */
    strncpy(p->deny_protocols, json_str_def(body, "deny_protocols", ""),
            sizeof(p->deny_protocols) - 1);
    p->deny_protocols[sizeof(p->deny_protocols) - 1] = '\0';
    /* validate each protocol token */
    {
        char proto_copy[128];
        strncpy(proto_copy, p->deny_protocols, sizeof(proto_copy) - 1);
        proto_copy[sizeof(proto_copy)-1] = '\0';
        char *tok = strtok(proto_copy, ",");
        while (tok) {
            /* trim whitespace */
            while (*tok == ' ') tok++;
            if (tp_protocol_valid(tok)) {
                tok = strtok(NULL, ",");
                continue;
            }
            snprintf(err->detail, sizeof(err->detail),
                     "unknown deny protocol: '%s'", tok);
            err->code = "invalid_deny_protocol";
            return -1;
        }
    }

    /* targets */
    struct json_object *targets_obj;
    if (!json_object_object_get_ex(body, "targets", &targets_obj) || !targets_obj) {
        snprintf(err->detail, sizeof(err->detail), "targets is required");
        err->code = "missing_targets";
        return -1;
    }

    tp_target_row_t rows[MAX_TARGET_ROWS];
    int row_count = 0;
    if (tp_expand_targets(targets_obj, rows, &row_count, err) < 0)
        return -1;

    *out_rows = calloc(row_count, sizeof(tp_target_row_t));
    if (!*out_rows && row_count > 0) {
        err->code = "internal_error";
        snprintf(err->detail, sizeof(err->detail), "memory allocation failed");
        return -1;
    }
    memcpy(*out_rows, rows, row_count * sizeof(tp_target_row_t));
    *out_row_count = row_count;

    return 0;
}

/* -----------------------------------------------------------------------
 * tp_policy_compute_deadline: recalculate deadline_at from policy fields
 * ----------------------------------------------------------------------- */
static int tp_compute_deadline_at(tp_policy_t *p)
{
    time_t dl;
    int ret;

    if (p->duration_count <= 0) {
        p->deadline_at = 0;
        return 0;
    }

    int base_time = p->started_at;
    if (base_time == 0) {
        /* will be set at apply time */
        p->deadline_at = 0;
        return 0;
    }

    ret = tp_compute_deadline(base_time, p->duration_count,
                               p->duration_unit, &dl);
    p->deadline_at = (ret >= 0) ? (int)dl : 0;
    return ret;
}

/* -----------------------------------------------------------------------
 * tp_check_status: evaluate current status based on deadline/quota
 * Returns new status string (owned by caller's storage or static).
 * Modifies in-place: updates status and last_transition_at on p.
 * ----------------------------------------------------------------------- */
const char *tp_expand_status_to_reason(const char *status)
{
    if (!strcmp(status, TP_STATUS_ACTIVE)) return "no reason";
    if (!strcmp(status, TP_STATUS_BLOCKED_TIME)) return "duration expired";
    if (!strcmp(status, TP_STATUS_BLOCKED_QUOTA)) return "quota exceeded";
    if (!strcmp(status, TP_STATUS_APPLY_FAILED)) return "data-plane apply failed";
    return "disabled by operator";
}

static void tp_check_and_update_status(tp_policy_t *p)
{
    time_t now = tp_now_s();
    int was_blocked = (!strcmp(p->status, TP_STATUS_BLOCKED_TIME) ||
                       !strcmp(p->status, TP_STATUS_BLOCKED_QUOTA));

    if (!p->enabled) {
        if (strcmp(p->status, TP_STATUS_DISABLED)) {
            p->last_transition_at = (int)now;
            strncpy((char *)p->status, TP_STATUS_DISABLED, 32);
        }
        return;
    }

    /* Check quota first (higher priority than time) */
    if (p->quota_bytes > 0 && p->used_bytes >= p->quota_bytes) {
        if (strcmp(p->status, TP_STATUS_BLOCKED_QUOTA)) {
            p->last_transition_at = (int)now;
            strncpy((char *)p->status, TP_STATUS_BLOCKED_QUOTA, 32);
        }
        return;
    }

    /* Check deadline */
    if (p->duration_count > 0 && p->deadline_at > 0 && now >= p->deadline_at) {
        if (strcmp(p->status, TP_STATUS_BLOCKED_TIME)) {
            p->last_transition_at = (int)now;
            strncpy((char *)p->status, TP_STATUS_BLOCKED_TIME, 32);
        }
        return;
    }

    /* Not blocked anymore */
    if (was_blocked) {
        p->last_transition_at = (int)now;
        strncpy((char *)p->status, TP_STATUS_ACTIVE, 32);
    }
}

/* -----------------------------------------------------------------------
 * CRUD: List
 * ----------------------------------------------------------------------- */
struct json_object *tp_policy_list(void)
{
    pthread_mutex_lock(&g_tp_db_mtx);
    if (!g_tp_db) { pthread_mutex_unlock(&g_tp_db_mtx); return NULL; }

    sqlite3_stmt *st = NULL;
    struct json_object *arr = json_object_new_array();

    if (sqlite3_prepare_v2(g_tp_db,
        "SELECT id, name, remark, enabled, rate_upload_kbps, rate_download_kbps,"
        " rate_mode, started_at, duration_count, duration_unit, deadline_at,"
        " quota_bytes, quota_accounting, quota_mode, deny_protocols,"
        " status, last_transition_at, generation, created_at, updated_at"
        " FROM policies ORDER BY created_at DESC", -1, &st, NULL) != SQLITE_OK) {
        json_object_put(arr);
        pthread_mutex_unlock(&g_tp_db_mtx);
        return NULL;
    }

    while (sqlite3_step(st) == SQLITE_ROW) {
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
        p.used_bytes = 0; /* separate query below */

        /* Load usage from quota_usage table */
        {
            sqlite3_stmt *ust;
            if (sqlite3_prepare_v2(g_tp_db,
                "SELECT used_bytes, checkpoint_at FROM quota_usage WHERE policy_id=? LIMIT 1",
                -1, &ust, NULL) == SQLITE_OK) {
                sqlite3_bind_text(ust, 1, p.id, -1, SQLITE_STATIC);
                if (sqlite3_step(ust) == SQLITE_ROW) {
                    p.used_bytes = sqlite3_column_int64(ust, 0);
                }
                sqlite3_finalize(ust);
            }
        }

        tp_check_and_update_status(&p);

        struct json_object *o = tp_json_from_policy(&p, 0);
        if (o) json_object_array_add(arr, o);
    }

    sqlite3_finalize(st);
    pthread_mutex_unlock(&g_tp_db_mtx);
    return arr;
}

