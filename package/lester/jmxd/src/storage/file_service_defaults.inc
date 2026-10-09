/* Defaults are templates for explicitly created exports, never bulk edits. */
static void fs_nfs_defaults_read(sqlite3 *db, struct json_object *data)
{
    sqlite3_stmt *st = NULL;
    if (fs_prepare(db, &st, "SELECT clients,options,revision FROM nfs_service_defaults WHERE id=1") == 0 &&
        sqlite3_step(st) == SQLITE_ROW) {
        json_object_object_add(data, "default_clients", json_object_new_string(fs_sql_text(st, 0, "")));
        json_object_object_add(data, "default_options", json_object_new_string(fs_sql_text(st, 1, "")));
        json_object_object_add(data, "revision", json_object_new_int64(sqlite3_column_int64(st, 2)));
    }
    if (st) sqlite3_finalize(st);
    struct json_object *fields = json_object_new_array();
    json_object_array_add(fields, json_object_new_string("default_clients"));
    json_object_array_add(fields, json_object_new_string("default_options"));
    json_object_object_add(data, "settings_fields", fields);
    json_object_object_add(data, "defaults_scope", json_object_new_string("new_export_form_only"));
    json_object_object_add(data, "affected_existing_exports", json_object_new_int(0));
}

struct json_object *jmx_nfs_defaults_set(struct json_object *req)
{
    struct json_object *p = fs_payload(req), *current = NULL, *v, *response = NULL;
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int present = 0, in_tx = 0;
    int64_t expected = 0;
    if (!fs_confirmed(req)) return fs_error("confirmation_required", "confirm_true_required");
    if (fs_json_positive_int64(p, "expected_revision", &expected, &present) != 0 || !present)
        return fs_error("missing_expected_revision", "nfs_defaults_revision_required");
    json_object_object_foreach(p, key, value) {
        (void)value;
        if (strcmp(key, "confirm") && strcmp(key, "apply") && strcmp(key, "expected_revision") &&
            strcmp(key, "default_clients") && strcmp(key, "default_options"))
            return fs_error("invalid_field", key);
    }
    if (fs_db_open(&db) != 0) return fs_error("storage_unavailable", "config_db_open_failed");
    if (fs_sql_exec(db, "BEGIN IMMEDIATE") != 0) goto out;
    in_tx = 1;
    current = json_object_new_object(); fs_nfs_defaults_read(db, current);
    json_object_object_get_ex(current, "revision", &v);
    if (json_object_get_int64(v) != expected) {
        response = fs_revision_conflict("nfs_defaults_changed", expected, json_object_get_int64(v)); goto out;
    }
    const char *keys[] = {"default_clients", "default_options"};
    for (int i = 0; i < 2; i++) if (json_object_object_get_ex(p, keys[i], &v)) {
        const char *text = json_object_get_string(v);
        if (!json_object_is_type(v, json_type_string) ||
            (i ? !fs_nfs_options_ok(text) : (text[0] && !fs_nfs_clients_ok(text)))) {
            response = fs_error("invalid_settings", keys[i]); goto out;
        }
        json_object_object_add(current, keys[i], json_object_get(v));
    }
    if (fs_prepare(db, &st, "UPDATE nfs_service_defaults SET clients=?1,options=?2,revision=revision+1 WHERE id=1 AND revision=?3") != 0) goto out;
    for (int i = 0; i < 2; i++) {
        json_object_object_get_ex(current, keys[i], &v);
        sqlite3_bind_text(st, i+1, json_object_get_string(v), -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int64(st, 3, expected);
    if (fs_step_done(st) != 0 || sqlite3_changes(db) != 1) goto out;
    sqlite3_finalize(st); st = NULL;
    if (fs_sql_exec(db, "COMMIT") != 0) goto out;
    in_tx = 0;
    json_object_object_add(current, "revision", json_object_new_int64(expected+1));
    json_object_object_add(current, "persisted", json_object_new_boolean(1));
    json_object_object_add(current, "applied", json_object_new_boolean(0));
    json_object_object_add(current, "service_action", json_object_new_string("none"));
    response = fs_success(current); current = NULL;
out:
    if (st) sqlite3_finalize(st);
    if (in_tx) fs_sql_exec(db, "ROLLBACK");
    if (db) sqlite3_close(db);
    if (current) json_object_put(current);
    return response ? response : fs_error("storage_error", "nfs_defaults_save_failed");
}
