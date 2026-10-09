    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_finalize(st); st = NULL; goto not_found; }
    if (strcmp((const char *)sqlite3_column_text(st, 0), "app")) { sqlite3_finalize(st); st = NULL; goto type_conflict; }
    sqlite3_finalize(st); st = NULL;
    if (nc_prepare(&st, "UPDATE network_control_global SET revision=revision+1,apply_state='draft',updated_at=?1 WHERE id=1 AND revision=?2") != 0) goto rollback;
    sqlite3_bind_int64(st,1,nc_now_s()); sqlite3_bind_int64(st,2,expected_revision);
    if (nc_step_done(st) != 0 || nc_sqlite_changes() != 1) { sqlite3_finalize(st); st = NULL; goto conflict; }
    sqlite3_finalize(st); st = NULL;
    if (nc_prepare(&st, "DELETE FROM network_control_app_rule WHERE rule_id=?1") != 0) goto rollback;
    sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
    if (nc_step_done(st) != 0) { sqlite3_finalize(st); st=NULL; goto rollback; }
    sqlite3_finalize(st); st=NULL;
    if (nc_prepare(&st, "DELETE FROM network_control_rule WHERE id=?1 AND type='app'") != 0) goto rollback;
    sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
    if (nc_step_done(st) != 0 || nc_sqlite_changes() != 1) { sqlite3_finalize(st); st=NULL; goto rollback; }
    sqlite3_finalize(st); st=NULL;
    if (nc_exec("UPDATE network_control_status SET apply_state='draft',warnings='Aegis app block deleted; rulesd runtime readback pending',updated_at=strftime('%s','now') WHERE id=1") != 0)
        goto rollback;
    if (nc_exec("COMMIT") != 0) { nc_exec("ROLLBACK"); goto write_failed; }
    signal_ok = nc_aegis_app_block_signal_rulesd() == 0;
    appfilter_enabled = nc_aegis_app_block_global_enabled();
    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "id", json_object_new_string(id));
    json_object_object_add(data, "deleted", json_object_new_boolean(1));
    json_object_object_add(data, "configured", json_object_new_boolean(0));
    json_object_object_add(data, "revision", json_object_new_int64(nc_aegis_app_block_revision()));
    nc_aegis_app_block_runtime_fields(data, appfilter_enabled, signal_ok,
                                      signal_ok ? NULL : "rulesd_reinit_signal_failed");
    json_object_object_add(data, "capabilities", nc_aegis_app_block_capabilities(appfilter_enabled));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);

conflict:
    if (st) sqlite3_finalize(st);
    nc_exec("ROLLBACK");
    return nc_aegis_app_block_error("revision_conflict", "revision", current_revision);
not_found:
    nc_exec("ROLLBACK");
    return nc_aegis_app_block_error("rule_not_found", "id", current_revision);
type_conflict:
    nc_exec("ROLLBACK");
    return nc_aegis_app_block_error("rule_type_conflict", "id", current_revision);
rollback:
    if (st) sqlite3_finalize(st);
    nc_exec("ROLLBACK");
write_failed:
    return nc_aegis_app_block_error("database_write_failed", "", nc_aegis_app_block_revision());
}

static int nc_rulesd_save_runtime_fields(struct json_object *arr, const char *type)
{
    if (!arr || !json_object_is_type(arr, json_type_array)) return 0;
    for (int i = 0; i < json_object_array_length(arr); i++) {
        struct json_object *o = json_object_array_get_idx(arr, i); sqlite3_stmt *st = NULL;
        if (nc_json_int_def(o, "runtime_rule_id", 0) <= 0) return -1;
        if (nc_prepare(&st, "UPDATE network_control_rule SET runtime_rule_id=?1 WHERE id=?2 AND type=?3") != 0) return -1;
        sqlite3_bind_int(st, 1, nc_json_int_def(o, "runtime_rule_id", 0)); sqlite3_bind_text(st, 2, nc_json_str_def(o, "id", ""), -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 3, type, -1, SQLITE_STATIC);
        if (nc_step_done(st) != 0 || nc_sqlite_changes() != 1) { sqlite3_finalize(st); return -1; } sqlite3_finalize(st);
        if (!strcmp(type, "app")) { if (nc_prepare(&st, "UPDATE network_control_app_rule SET filter_quic=?1 WHERE rule_id=?2") != 0) return -1; sqlite3_bind_int(st,1,nc_json_int_def(o,"filter_quic",0)); sqlite3_bind_text(st,2,nc_json_str_def(o,"id",""),-1,SQLITE_TRANSIENT); if(nc_step_done(st)!=0){sqlite3_finalize(st);return -1;} sqlite3_finalize(st); }
    }
    return 0;
}

static int nc_rulesd_save_whitelist(struct json_object *arr, const char *kind)
{
    if (!arr || !json_object_is_type(arr, json_type_array)) return 0;
    for (int i = 0; i < json_object_array_length(arr); i++) { const char *mac = json_object_get_string(json_object_array_get_idx(arr,i)); char norm[32]; sqlite3_stmt *st=NULL; nc_netctl_mac_norm(mac,norm,sizeof(norm)); if(!nc_netctl_mac_ok(norm))return -1; if(nc_prepare(&st,"INSERT OR IGNORE INTO network_control_whitelist(kind,mac,created_at) VALUES(?1,?2,?3)")!=0)return -1; sqlite3_bind_text(st,1,kind,-1,SQLITE_STATIC);sqlite3_bind_text(st,2,norm,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,3,nc_now_s());if(nc_step_done(st)!=0){sqlite3_finalize(st);return -1;}sqlite3_finalize(st); }
    return 0;
}

/*
 * True while the negated-set drop rule is installed. Defined here, ahead of the
 * allowlist implementation further down, because the whitelist write path needs
 * it to refuse emptying a list the ruleset is currently enforcing.
 */
static int nc_macacl_enforcing(void)
{
    sqlite3_stmt *st = NULL;
    int enabled = 0;

    if (nc_prepare(&st,
        "SELECT enabled FROM network_control_mac_allowlist WHERE id=1") != 0)
        return 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        enabled = sqlite3_column_int(st, 0) ? 1 : 0;
    sqlite3_finalize(st);
    return enabled;
}

static int nc_rulesd_replace_whitelist(struct json_object *arr, const char *kind)
{
    sqlite3_stmt *st = NULL;
    if (!arr || !json_object_is_type(arr, json_type_array)) return -1;
    /*
     * Refuse to leave the MAC allowlist empty while allowlist mode is enforcing.
     * An empty set turns "ether saddr != @set" into "match everything", so the
     * next ruleset generation would either drop the whole LAN or fail outright
     * and take the unrelated rules in the same file down with it. Rejected at the
     * write instead, where the caller can still be told why; the mode has to be
     * disabled first.
     */
    if (!strcmp(kind, "mac") && json_object_array_length(arr) == 0 &&
        nc_macacl_enforcing())
        return -1;
    if (nc_prepare(&st, "DELETE FROM network_control_whitelist WHERE kind=?1") != 0) return -1;
    sqlite3_bind_text(st, 1, kind, -1, SQLITE_STATIC);
    if (nc_step_done(st) != 0) { sqlite3_finalize(st); return -1; }
    sqlite3_finalize(st);
    return nc_rulesd_save_whitelist(arr, kind);
}

static int nc_rulesd_join_count(const char *type)
{
    const char *sql = !strcmp(type, "app")
        ? "SELECT COUNT(*) FROM network_control_rule r JOIN network_control_app_rule d ON d.rule_id=r.id WHERE r.type='app'"
        : "SELECT COUNT(*) FROM network_control_rule r JOIN network_control_mac_rule d ON d.rule_id=r.id WHERE r.type='mac'";
    sqlite3_stmt *st = NULL;
    int count = -1;
    if (nc_prepare(&st, sql) == 0 && sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int(st, 0);
    if (st) sqlite3_finalize(st);
    return count;
}

struct json_object *jmx_rulesd_config_migrate(struct json_object *cfg)
{
    struct json_object *data = json_object_new_object();
    struct json_object *app = NULL, *mac = NULL, *aw = NULL, *mw = NULL;
    sqlite3_stmt *st = NULL;
    int existing = 0, rows = 0, rc = -1;

    if (!cfg || jmx_netconfig_db_init() != 0)
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    nc_netctl_db_init();
    if (nc_exec("BEGIN IMMEDIATE") != 0)
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    if (nc_prepare(&st, "SELECT 1 FROM config_migration WHERE name=?1 AND status='done'") != 0)
        goto done;
    sqlite3_bind_text(st, 1, RULESD_UCI_MIGRATION, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        sqlite3_finalize(st);
        st = NULL;
        rc = 0;
        json_object_object_add(data, "already_done", json_object_new_boolean(1));
        goto done;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st, "SELECT COUNT(*) FROM network_control_rule WHERE type IN ('app','mac')") != 0 ||
        sqlite3_step(st) != SQLITE_ROW)
        goto done;
    existing = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;

    if (existing == 0) {
        json_object_object_get_ex(cfg, "app_rules", &app);
        json_object_object_get_ex(cfg, "mac_rules", &mac);
        json_object_object_get_ex(cfg, "app_whitelist", &aw);
        json_object_object_get_ex(cfg, "mac_whitelist", &mw);
        if (nc_netctl_save_app(app) != 0 || nc_netctl_save_mac(mac) != 0 ||
            nc_rulesd_save_runtime_fields(app, "app") != 0 ||
            nc_rulesd_save_runtime_fields(mac, "mac") != 0 ||
            nc_rulesd_save_whitelist(aw, "app") != 0 ||
            nc_rulesd_save_whitelist(mw, "mac") != 0)
            goto done;
        if (nc_rulesd_join_count("app") != (app ? json_object_array_length(app) : 0) ||
            nc_rulesd_join_count("mac") != (mac ? json_object_array_length(mac) : 0))
            goto done;
        rows = (app ? json_object_array_length(app) : 0) +
               (mac ? json_object_array_length(mac) : 0) +
               (aw ? json_object_array_length(aw) : 0) +
               (mw ? json_object_array_length(mw) : 0);
    }
    if (nc_prepare(&st, "INSERT INTO config_migration(name,status,source,imported_rows,imported_at,detail) VALUES(?1,'done','uci:/etc/config/appfilter,macfilter',?2,?3,?4)") != 0)
        goto done;
    sqlite3_bind_text(st, 1, RULESD_UCI_MIGRATION, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, rows);
    sqlite3_bind_int64(st, 3, nc_now_s());
    sqlite3_bind_text(st, 4, existing ? "preserved_existing_config_db_rules" : "legacy_uci_imported", -1, SQLITE_STATIC);
    if (nc_step_done(st) != 0) goto done;
    sqlite3_finalize(st);
    st = NULL;
    rc = 0;

done:
    if (st) sqlite3_finalize(st);
    if (nc_exec(rc == 0 ? "COMMIT" : "ROLLBACK") != 0) rc = -1;
    json_object_object_add(data, "imported_rows", json_object_new_int(rows));
    json_object_object_add(data, "preserved_existing", json_object_new_boolean(existing > 0));
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

/* ── nft rule generation from network_control rules ─────────────── */

/*
 * Strict "HH:MM" validator. Deliberately rejects anything that is not exactly
 * five characters of the expected shape, because the value is interpolated into
 * the generated nft ruleset and a loose check here would let arbitrary text
 * reach the parser.
 */
static int nc_netctl_hhmm_ok(const char *s)
{
    int hh, mm;

    if (!s || strlen(s) != 5 || s[2] != ':')
        return 0;
    if (!isdigit((unsigned char)s[0]) || !isdigit((unsigned char)s[1]) ||
        !isdigit((unsigned char)s[3]) || !isdigit((unsigned char)s[4]))
        return 0;
    hh = (s[0] - '0') * 10 + (s[1] - '0');
    mm = (s[3] - '0') * 10 + (s[4] - '0');
    /* 24:00 is accepted as an end-of-day marker; nft treats it as midnight. */
    if (hh == 24)
        return mm == 0;
    return hh <= 23 && mm <= 59;
}


/*
 * Translate a stored schedule into an nft match clause.
 *
 * Storage format is either the literal "always" (or empty) or the JSON array
 * already used by nc_rulesd_add_time_rules():
 *
 *   [{"weekdays":[1,2,3,4,5],"start_time":"18:00","end_time":"22:00"}]
 *
 * Writes the clause (leading space included) into `out` and returns 0. An
 * always-on schedule yields an empty string. Returns -1 when the schedule
 * cannot be represented, and the caller must then refuse to emit the rule
 * rather than silently dropping the time restriction — a MAC block whose
 * schedule was ignored would apply 24/7 instead of during the chosen window.
 *
 * Only the first entry is translated. nft matches one rule against one
 * expression, so several disjoint windows need several rules; that is why
 * multi-window schedules are rejected here instead of being partially applied.
 *
 * Timezone note, verified on 30.1 with nft v1.1.6 (--debug=netlink):
 * nft converts "18:00" to seconds-of-day in UTC using the timezone of the
 * process that parses the ruleset, and the kernel then matches UTC. So the
 * clause is written in local time on purpose and must be parsed by a process
 * whose timezone matches the device. A window that crosses UTC midnight after
 * the shift is handled by nft itself, which inverts it into a "range neq"
 * expression, so no wrap handling is needed here.
 */
static int nc_nft_schedule_clause(const char *schedule, char *out, size_t out_len)
{
    struct json_object *parsed = NULL, *entry, *days, *v;
    const char *start, *end;
    int written, day_count, i;
    size_t used = 0;

    if (!out || out_len == 0)
        return -1;
    out[0] = '\0';
    if (!schedule || !schedule[0] || !strcmp(schedule, "always"))
        return 0;
    if (schedule[0] != '[')
        return -1;
    parsed = json_tokener_parse(schedule);
    if (!parsed || !json_object_is_type(parsed, json_type_array)) {
        if (parsed) json_object_put(parsed);
        return -1;
    }
    if (json_object_array_length(parsed) != 1) {
        json_object_put(parsed);
        return -1;
    }
    entry = json_object_array_get_idx(parsed, 0);
    if (!entry || !json_object_is_type(entry, json_type_object)) {
        json_object_put(parsed);
        return -1;
    }

    start = json_object_object_get_ex(entry, "start_time", &v) && v ?
            json_object_get_string(v) : NULL;
    end = json_object_object_get_ex(entry, "end_time", &v) && v ?
          json_object_get_string(v) : NULL;
    if (!nc_netctl_hhmm_ok(start) || !nc_netctl_hhmm_ok(end)) {
        json_object_put(parsed);
        return -1;
    }
    /*
     * A window covering the whole day is the same as no restriction. Emitting
     * it as a range would be harmless but pointless, and 00:00-23:59 shifted
     * out of local time is exactly the wrapping case, so skip it.
     */
    if (!(!strcmp(start, "00:00") && (!strcmp(end, "23:59") || !strcmp(end, "24:00")))) {
        written = snprintf(out + used, out_len - used,
                           " meta hour \"%s\"-\"%s\"", start, end);
        if (written < 0 || (size_t)written >= out_len - used) {
            json_object_put(parsed);
            return -1;
        }
        used += (size_t)written;
    }

    if (json_object_object_get_ex(entry, "weekdays", &days) && days &&
        json_object_is_type(days, json_type_array)) {
        day_count = json_object_array_length(days);
        /* All seven days present means no weekday restriction to express. */
        if (day_count > 0 && day_count < 7) {
            static const char *const names[7] = {
                "Sunday", "Monday", "Tuesday", "Wednesday",
                "Thursday", "Friday", "Saturday"
            };
            int seen[7] = { 0 };
            int emitted = 0;

            written = snprintf(out + used, out_len - used, " meta day { ");
            if (written < 0 || (size_t)written >= out_len - used) {
                json_object_put(parsed);
                return -1;
            }
            used += (size_t)written;
            for (i = 0; i < day_count; i++) {
                struct json_object *d = json_object_array_get_idx(days, i);
                int n;

                if (!d || !json_object_is_type(d, json_type_int)) {
                    json_object_put(parsed);
                    return -1;
                }
                n = json_object_get_int(d);
                if (n < 0 || n > 6 || seen[n]) {
                    json_object_put(parsed);
                    return -1;
                }
                seen[n] = 1;
                written = snprintf(out + used, out_len - used, "%s\"%s\"",
                                   emitted ? ", " : "", names[n]);
                if (written < 0 || (size_t)written >= out_len - used) {
                    json_object_put(parsed);
                    return -1;
                }
                used += (size_t)written;
                emitted++;
            }
            written = snprintf(out + used, out_len - used, " }");
            if (written < 0 || (size_t)written >= out_len - used) {
                json_object_put(parsed);
                return -1;
            }
            used += (size_t)written;
        } else if (day_count > 7) {
            json_object_put(parsed);
            return -1;
        }
    }

    json_object_put(parsed);
    return 0;
}

static int nc_nft_gen_mac_rules(FILE *fp)
{
    sqlite3_stmt *st = NULL;
    int count = 0;
    int step_rc;
    int64_t now = nc_now_s();

    /*
     * Expired rules are filtered in SQL (expires=0 means "never"), so a
     * temporary block stops taking effect on the next ruleset regeneration
     * without needing its row deleted. The row is kept on purpose: the user can
     * see and re-arm a rule that lapsed.
     */
    /*
     * A rule whose source is "terminal_group:<id>" contributes one row per group
     * member instead of a single row, so group membership is what decides which
     * devices are blocked. The join is a LEFT JOIN with a COALESCE so a
     * single-MAC rule still yields exactly its own MAC, and a group whose
     * members were all removed yields no row at all rather than a malformed one.
     */
    if (!fp || nc_prepare(&st,
            "SELECT COALESCE(NULLIF(d.mac,''), g.mac) AS emit_mac, r.name, d.mode, r.schedule, r.expires, r.source "
            "FROM network_control_rule r "
            "JOIN network_control_mac_rule d ON d.rule_id=r.id "
            "LEFT JOIN terminal_group_member g "
            "  ON d.mac='' AND g.mac<>'' "
            "  AND g.group_id=substr(r.source,length('terminal_group:')+1) "
            "WHERE r.type='mac' AND r.enabled=1 AND (r.expires=0 OR r.expires>?1) "
            "GROUP BY emit_mac, r.id "
            "ORDER BY r.priority, r.id, emit_mac") != 0)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)now);
    while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) {
            const char *mac = (const char*)sqlite3_column_text(st, 0);
            const char *name = (const char*)sqlite3_column_text(st, 1);
            const char *mode = (const char*)sqlite3_column_text(st, 2);
            const char *schedule = (const char*)sqlite3_column_text(st, 3);
            const char *source = (const char*)sqlite3_column_text(st, 5);
            const unsigned char *p;
            char when[256];

            /*
             * A group-bound rule with no usable member is skipped rather than
             * failing the whole generation: an empty group is a legitimate state
             * (the user emptied it), and refusing to build the ruleset would take
             * every other rule down with it.
             */
            if ((!mac || !mac[0]) && nc_netctl_group_source_id(source))
                continue;
            if (!nc_netctl_mac_ok(mac) || !name || strlen(name) > 128 ||
                !mode || (strcmp(mode, "deny") && strcmp(mode, "block") &&
                          strcmp(mode, "allow")))
                goto fail;
            for (p = (const unsigned char *)name; *p; p++)
                if (*p < 0x20 || *p == 0x7f)
                    goto fail;
            /*
             * Fail the whole generation rather than emit a rule without its
             * time restriction: a block that was meant for 18:00-22:00 would
             * otherwise silently apply all day.
             */
            if (nc_nft_schedule_clause(schedule, when, sizeof(when)) != 0)
                goto fail;
            if(!strcmp(mode, "deny") || !strcmp(mode, "block")) {
                if (fprintf(fp, "\t\tether saddr %s%s drop  # %s\n",
                            mac, when, name) < 0)
                    goto fail;
            } else if(!strcmp(mode, "allow")) {
                if (fprintf(fp, "\t\tether saddr %s%s accept  # %s\n",
                            mac, when, name) < 0)
                    goto fail;
            }
            count++;
    }
    sqlite3_finalize(st);
    return step_rc == SQLITE_DONE ? count : -1;

fail:
    sqlite3_finalize(st);
    return -1;
}

int nc_sig_open(sqlite3 **db);

/*
 * ── MAC allowlist mode (deny-by-default via a negated set) ──
 *
 * "Allowlist" is rendered as a drop, not an accept: an accept in this table's
 * base chain does not stop a later firewall chain from dropping the packet, so a
 * per-MAC accept could not implement "only these devices may reach the internet".
 * A single negated-set match can:
 *
 *     set macacl_allow { type ether_addr; elements = { ... } }
 *     iifname "br-lan" ether saddr != @macacl_allow drop
 *
 * The iifname qualifier is load-bearing rather than cosmetic. In the forward
 * chain the reply direction carries the upstream gateway's MAC as ether saddr,
 * which is never in the allowlist, so an unqualified negated match would drop
 * every reply and take the allowed devices down with the denied ones. Scoping to
 * the LAN ingress interface leaves the reply path alone.
 *
 * Enforcement is forward-only on purpose. It answers "not allowed on the
 * internet", and leaves the router's own input chain reachable, so a device that
 * was left off the list can still open the admin UI to be added.
 */
#define NC_NETCTL_MACACL_SET "macacl_allow"
#define NC_NETCTL_MACACL_MAX_ELEMENTS 2048
#define NC_NETCTL_MACACL_CONFIRM_MIN_S 30
#define NC_NETCTL_MACACL_CONFIRM_MAX_S 900
#define NC_NETCTL_MACACL_CONFIRM_DEFAULT_S 180

static int nc_tc_lan_ifname(char *ifname, size_t ifname_len);

struct nc_macacl_state {
    int enabled;
    int confirmed;
    int64_t confirm_deadline;
    int64_t enabled_at;
    int64_t config_revision;
    int64_t runtime_revision;
    int runtime_applied;
    char admin_mac[32];
    char admin_ip[64];
    char admin_mac_source[64];
    char last_reason[128];
    char runtime_reason[128];
};

static void nc_macacl_copy_text(char *dst, size_t dst_len, sqlite3_stmt *st,
                                int col)
{
    const char *value = (const char *)sqlite3_column_text(st, col);

    snprintf(dst, dst_len, "%s", value ? value : "");
}

static int nc_macacl_state_load(struct nc_macacl_state *out)
{
    sqlite3_stmt *st = NULL;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (nc_prepare(&st,
        "SELECT enabled,confirmed,confirm_deadline,enabled_at,admin_mac,"
        "admin_ip,admin_mac_source,last_reason,config_revision,"
        "runtime_revision,runtime_applied,runtime_reason "
        "FROM network_control_mac_allowlist WHERE id=1") != 0)
        return -1;
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return -1;
    }
    out->enabled = sqlite3_column_int(st, 0) ? 1 : 0;
    out->confirmed = sqlite3_column_int(st, 1) ? 1 : 0;
    out->confirm_deadline = (int64_t)sqlite3_column_int64(st, 2);
    out->enabled_at = (int64_t)sqlite3_column_int64(st, 3);
    nc_macacl_copy_text(out->admin_mac, sizeof(out->admin_mac), st, 4);
    nc_macacl_copy_text(out->admin_ip, sizeof(out->admin_ip), st, 5);
    nc_macacl_copy_text(out->admin_mac_source, sizeof(out->admin_mac_source), st, 6);
    nc_macacl_copy_text(out->last_reason, sizeof(out->last_reason), st, 7);
    out->config_revision = (int64_t)sqlite3_column_int64(st, 8);
    out->runtime_revision = (int64_t)sqlite3_column_int64(st, 9);
    out->runtime_applied = sqlite3_column_int(st, 10) ? 1 : 0;
    nc_macacl_copy_text(out->runtime_reason, sizeof(out->runtime_reason), st, 11);
    sqlite3_finalize(st);
    return 0;
}

static int nc_macacl_state_store(const struct nc_macacl_state *in)
{
    sqlite3_stmt *st = NULL;

    if (!in || nc_prepare(&st,
        "UPDATE network_control_mac_allowlist SET enabled=?1,confirmed=?2,"
        "confirm_deadline=?3,admin_mac=?4,admin_ip=?5,admin_mac_source=?6,"
        "last_reason=?7,enabled_at=?8,config_revision=?9,runtime_revision=?10,"
        "runtime_applied=?11,runtime_reason=?12,updated_at=?13 WHERE id=1") != 0)
        return -1;
    sqlite3_bind_int(st, 1, in->enabled ? 1 : 0);
    sqlite3_bind_int(st, 2, in->confirmed ? 1 : 0);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)in->confirm_deadline);
    sqlite3_bind_text(st, 4, in->admin_mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, in->admin_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, in->admin_mac_source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, in->last_reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 8, (sqlite3_int64)in->enabled_at);
    sqlite3_bind_int64(st, 9, (sqlite3_int64)in->config_revision);
    sqlite3_bind_int64(st, 10, (sqlite3_int64)in->runtime_revision);
    sqlite3_bind_int(st, 11, in->runtime_applied ? 1 : 0);
    sqlite3_bind_text(st, 12, in->runtime_reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 13, (sqlite3_int64)nc_now_s());
    if (nc_step_done(st) != 0) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

/* Stored allowlist members. Returns the element count, or -1 on a malformed row. */
static int nc_macacl_collect(char (*out)[32], int max_out)
{
    sqlite3_stmt *st = NULL;
    int count = 0;
    int step_rc;

    if (!out || max_out < 1)
        return -1;
    if (nc_prepare(&st,
        "SELECT mac FROM network_control_whitelist WHERE kind='mac' ORDER BY mac") != 0)
        return -1;
    while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *raw = (const char *)sqlite3_column_text(st, 0);
        char norm[32];

        nc_netctl_mac_norm(raw, norm, sizeof(norm));
        if (!nc_netctl_mac_ok(norm)) {
            sqlite3_finalize(st);
            return -1;
        }
        if (count >= max_out) {
            sqlite3_finalize(st);
            return -1;
        }
        snprintf(out[count], sizeof(out[count]), "%s", norm);
        count++;
    }
    sqlite3_finalize(st);
    if (step_rc != SQLITE_DONE)
        return -1;
    return count;
}

/*
 * The enabling session's MAC is written into the whitelist as an ordinary row
 * rather than merged in at generation time.
 *
 * A generation-time merge would be an exemption the operator can neither see in
 * the whitelist nor remove, which is exactly the kind of invisible special case
 * the user ruled out. As a real row it shows up in mac_whitelist, survives on
 * its own terms, and can be deleted by anyone who genuinely wants that device
 * off the internet.
 *
 * Returns 1 when a row was added, 0 when it was already there, -1 on failure.
 */
static int nc_macacl_whitelist_ensure(const char *mac)
{
    sqlite3_stmt *st = NULL;
    int present = 0;

    if (!nc_netctl_mac_ok(mac))
        return -1;
    if (nc_prepare(&st,
        "SELECT 1 FROM network_control_whitelist WHERE kind='mac' AND mac=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_STATIC);
    present = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    if (present)
        return 0;
    if (nc_prepare(&st,
        "INSERT OR IGNORE INTO network_control_whitelist(kind,mac,created_at) "
        "VALUES('mac',?1,?2)") != 0)
        return -1;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)nc_now_s());
    if (nc_step_done(st) != 0) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return 1;
}

static int nc_macacl_whitelist_remove(const char *mac)
{
    sqlite3_stmt *st = NULL;

    if (!nc_netctl_mac_ok(mac) || nc_prepare(&st,
        "DELETE FROM network_control_whitelist WHERE kind='mac' AND mac=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_STATIC);
    if (nc_step_done(st) != 0) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

/* Stored whitelist size. "Empty" is judged on this, before any admin row is
 * added, so a list holding only the operator's own device still counts as a
 * deliberate one-device allowlist rather than an empty one. */
static int nc_macacl_stored_count(void)
{
    sqlite3_stmt *st = NULL;
    int count = -1;

    if (nc_prepare(&st,
        "SELECT COUNT(*) FROM network_control_whitelist WHERE kind='mac'") != 0)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return count;
}

/* Number of allowlist elements that would be rendered, or -1 if unusable. */
static int nc_macacl_element_count(void)
{
    char (*macs)[32];
    int count;

    macs = calloc(NC_NETCTL_MACACL_MAX_ELEMENTS, sizeof(*macs));
    if (!macs)
        return -1;
    count = nc_macacl_collect(macs, NC_NETCTL_MACACL_MAX_ELEMENTS);
    free(macs);
    return count;
}

/*
 * Emits the set definition, and only when the mode is on. Nothing else
 * references the set, so omitting it while disabled keeps a stale element list
 * from lingering in the ruleset and makes the file itself say which state the
 * device is in.
 */
static int nc_nft_gen_macacl_set(FILE *fp, const struct nc_macacl_state *state,
                                 int *count_out)
{
    char (*macs)[32];
    int count;
    int rc = -1;

    if (count_out)
        *count_out = 0;
    if (!fp || !state)
        return -1;
    if (!state->enabled)
        return 0;
    macs = calloc(NC_NETCTL_MACACL_MAX_ELEMENTS, sizeof(*macs));
    if (!macs)
        return -1;
    count = nc_macacl_collect(macs, NC_NETCTL_MACACL_MAX_ELEMENTS);
    /*
     * An empty set makes "!= @set" match every packet, so generation fails
     * rather than rendering a rule that would drop the whole LAN. The enable
     * path refuses an empty list up front; this is the second line of defence
     * for the case where the list is emptied while the mode is already on.
     */
    if (count <= 0)
        goto out;
    if (fprintf(fp, "\tset " NC_NETCTL_MACACL_SET " {\n") < 0 ||
        fprintf(fp, "\t\ttype ether_addr\n") < 0 ||
        fprintf(fp, "\t\telements = {") < 0)
        goto out;
    for (int i = 0; i < count; i++) {
        if (fprintf(fp, "%s %s", i ? "," : "", macs[i]) < 0)
            goto out;
    }
    if (fprintf(fp, " }\n\t}\n\n") < 0)
        goto out;
    if (count_out)
        *count_out = count;
    rc = count;
out:
    free(macs);
    return rc;
}

/* The one rule that enforces the mode. Forward chain only; see the note above. */
static int nc_nft_gen_macacl_rule(FILE *fp, const struct nc_macacl_state *state)
{
    char lan[32];

    if (!fp || !state)
        return -1;
    if (!state->enabled)
        return 0;
    /*
     * No LAN device means no place to anchor the match. Failing generation is
     * the safe direction: without iifname the rule would drop the reply path.
     */
    if (nc_tc_lan_ifname(lan, sizeof(lan)) != 0)
        return -1;
    if (fprintf(fp,
                "\t\tiifname \"%s\" ether saddr != @" NC_NETCTL_MACACL_SET
                " drop  # mac allowlist mode\n", lan) < 0)
        return -1;
    return 1;
}

static int nc_netctl_comment_ok(const char *text, size_t max_len)
{
    const unsigned char *p = (const unsigned char *)text;
    size_t len;

    if (!text || (len = strlen(text)) == 0 || len > max_len)
        return 0;
    for (; *p; p++)
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    return 1;
}

static int nc_nft_emit_port_rule(FILE *fp, const char *proto, int a, int b,
                                 unsigned mark, int app_id,
                                 const char *rule_name)
{
    if (!fp || (!proto || (strcmp(proto, "tcp") && strcmp(proto, "udp"))) ||
        a < 1 || a > 65535 || b < a || b > 65535 || app_id < 1 ||
        !nc_netctl_comment_ok(rule_name, 128))
        return -1;
    if (b > a)
        return fprintf(fp, "\t\t%s dport %d-%d meta mark set 0x%04x ct mark set 0x%04x  # dpi app=%d rule=%s\n",
                       proto, a, b, mark, mark, app_id, rule_name) < 0 ? -1 : 0;
    return fprintf(fp, "\t\t%s dport %d meta mark set 0x%04x ct mark set 0x%04x  # dpi app=%d rule=%s\n",
                   proto, a, mark, mark, app_id, rule_name) < 0 ? -1 : 0;
}
static int nc_nft_app_emit_ports(FILE *fp,sqlite3 *sig,int app_id,unsigned mark,const char*rule_name)
{
    sqlite3_stmt *ps = NULL;
    int n = 0, step_rc;

    if (!fp || !sig || app_id < 1 || !nc_netctl_comment_ok(rule_name, 128) ||
        sqlite3_prepare_v2(sig, "SELECT DISTINCT COALESCE(NULLIF(r.proto,''),'both'),p.min_port,p.max_port FROM dpi_rule r JOIN dpi_rule_port p ON p.rule_id=r.rule_id WHERE r.enabled=1 AND r.app_id=? AND p.min_port IS NOT NULL AND p.min_port>0 ORDER BY r.proto,p.min_port,p.max_port", -1, &ps, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(ps, 1, app_id);
    while ((step_rc = sqlite3_step(ps)) == SQLITE_ROW) {
        const char *proto = (const char *)sqlite3_column_text(ps, 0);
        int a = sqlite3_column_int(ps, 1), b = sqlite3_column_int(ps, 2);

        if (b <= 0) b = a;
        if (a < 1 || a > 65535 || b < a || b > 65535 || !proto)
            goto fail;
        if (!strcmp(proto, "both")) {
            if (nc_nft_emit_port_rule(fp, "tcp", a, b, mark, app_id, rule_name) != 0 ||
                nc_nft_emit_port_rule(fp, "udp", a, b, mark, app_id, rule_name) != 0)
                goto fail;
            n += 2;
        } else if (!strcmp(proto, "tcp") || !strcmp(proto, "udp")) {
            if (nc_nft_emit_port_rule(fp, proto, a, b, mark, app_id, rule_name) != 0)
                goto fail;
            n++;
        } else {
            goto fail;
        }
    }
    sqlite3_finalize(ps);
    return step_rc == SQLITE_DONE ? n : -1;

fail:
    sqlite3_finalize(ps);
    return -1;
}

static int nc_nft_for_each_app_rule(FILE *fp, int emit_mark)
{
    sqlite3_stmt *st = NULL; sqlite3 *sig=NULL; int count = 0, ridx = 1, step_rc;
    if (!fp || (emit_mark && nc_sig_open(&sig) != 0))
        return -1;
    /*
     * expires is filtered here for the same reason as in nc_nft_gen_mac_rules():
     * 0 means "never", and a lapsed rule stops being rendered while its row is
     * kept so the user can see and re-arm it. Without this condition the UI
     * showed "expired" from a read-time comparison while the nft rule stayed in
     * force forever -- and unlike a rebuild delay there was no path that ever
     * cleared it.
     */
    if (nc_prepare(&st, "SELECT r.id,d.app_ids,d.action,r.name FROM network_control_rule r JOIN network_control_app_rule d ON d.rule_id=r.id WHERE r.type='app' AND r.enabled=1 AND (r.expires=0 OR r.expires BETWEEN ?1 AND 9223372036854775807) ORDER BY r.priority, r.id") != 0)
        goto fail;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)nc_now_s() + 1);
    while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) {
            const char *rule_id=(const char*)sqlite3_column_text(st,0); const char *app_ids=(const char*)sqlite3_column_text(st,1);
            const char *action=(const char*)sqlite3_column_text(st,2); const char *name=(const char*)sqlite3_column_text(st,3);
            struct json_object *a = NULL;
            unsigned mark;
            int an;

            if (!rule_id || !nc_valid_name(rule_id) || strlen(rule_id) > 95 ||
                !nc_netctl_comment_ok(name, 128) || !app_ids || !app_ids[0] ||
                !action || (strcmp(action, "block") && strcmp(action, "deny") &&
                            strcmp(action, "allow")))
                goto fail;
            a = json_tokener_parse(app_ids);
            if (!a || !json_object_is_type(a, json_type_array) ||
                (an = (int)json_object_array_length(a)) < 1 ||
                an > NC_AEGIS_APPFILTER_MAX_APP_IDS) {
                if (a) json_object_put(a);
                goto fail;
            }
            mark=(unsigned)(0x0100 | (ridx&0xff)); if(ridx<255)ridx++;
            if(emit_mark){
                int emitted=0;
                if (fprintf(fp,"\t\t# app classify: %s id=%s action=%s mark=0x%04x\n",name,rule_id,action,mark) < 0) { json_object_put(a); goto fail; }
                for(int i=0;i<an;i++){struct json_object*v=json_object_array_get_idx(a,i);int app_id;if(!v||!json_object_is_type(v,json_type_int)||(app_id=json_object_get_int(v))<1){json_object_put(a);goto fail;}int added=nc_nft_app_emit_ports(fp,sig,app_id,mark,name);if(added<0){json_object_put(a);goto fail;}emitted+=added;}
                if(emitted<=0 && fprintf(fp,"\t\t# app rule has no dpi_rule_port hits\n") < 0){json_object_put(a);goto fail;}
            } else {
                if((!strcmp(action,"block")||!strcmp(action,"deny")) && fprintf(fp,"\t\tmeta mark 0x%04x drop  # app_block %s\n",mark,name)<0){json_object_put(a);goto fail;}
                if(!strcmp(action,"allow") && fprintf(fp,"\t\tmeta mark 0x%04x accept  # app_allow %s\n",mark,name)<0){json_object_put(a);goto fail;}
            }
            json_object_put(a);
            count++;
    }
    sqlite3_finalize(st);
    if(sig) jmx_signature_db_close(sig);
    return step_rc == SQLITE_DONE ? count : -1;

fail:
    if (st) sqlite3_finalize(st);
    if (sig) jmx_signature_db_close(sig);
    return -1;
}
static int nc_nft_gen_app_mark_rules(FILE *fp){return nc_nft_for_each_app_rule(fp,1);}
static int nc_nft_gen_app_action_rules(FILE *fp){return nc_nft_for_each_app_rule(fp,0);}

static int nc_nft_gen_connection_limit_rules(FILE *fp)
{
    sqlite3_stmt *st = NULL;
    int count = 0;
    int step_rc;
    /* Same expiry filter as the mac and app generators; see nc_nft_gen_mac_rules(). */
    if (!fp || nc_prepare(&st, "SELECT d.protocol, d.wan_port, d.connection_limit, d.burst, d.action, r.name FROM network_control_rule r JOIN network_control_connection_limit d ON d.rule_id=r.id WHERE r.type='connection_limit' AND r.enabled=1 AND (r.expires=0 OR r.expires BETWEEN ?1 AND 9223372036854775807) ORDER BY r.priority, r.id") != 0)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)nc_now_s() + 1);
    while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) {
            const char *proto = (const char*)sqlite3_column_text(st, 0);
            const char *wan_port = (const char*)sqlite3_column_text(st, 1);
            int limit = sqlite3_column_int(st, 2);
            int burst = sqlite3_column_int(st, 3);
            const char *action = (const char*)sqlite3_column_text(st, 4);
            const char *name = (const char*)sqlite3_column_text(st, 5);
            int tcp, udp;
            if (!proto || (!strcmp(proto, "tcp") ? 0 : !strcmp(proto, "udp") ? 0 :
                           !strcmp(proto, "tcp,udp") ? 0 : !strcmp(proto, "udp,tcp") ? 0 : -1) < 0 ||
                !wan_port || !nc_netctl_comment_ok(name, 128) || !action ||
                (strcmp(action, "limit") && strcmp(action, "block") && strcmp(action, "deny")) ||
                limit < 1 || limit > 10000000 || burst < 1 || burst > 1000000)
                goto fail;
            if (strcmp(wan_port, "any")) {
                int first = 0, last = 0; char tail = '\0';
                if (sscanf(wan_port, "%d-%d%c", &first, &last, &tail) == 2) {
                    if (first < 1 || last < first || last > 65535) goto fail;
                } else if (sscanf(wan_port, "%d%c", &first, &tail) == 1) {
                    if (first < 1 || first > 65535) goto fail;
                } else goto fail;
            }
            tcp = !strcmp(proto, "tcp") || strstr(proto, "tcp") != NULL;
            udp = !strcmp(proto, "udp") || strstr(proto, "udp") != NULL;
            /* nftables meter/limit */
            fprintf(fp, "\t\t# connection limit: %s (proto=%s port=%s limit=%d burst=%d)\n",
                    name?name:"", proto?proto:"tcp,udp", wan_port?wan_port:"any", limit, burst);
            if(tcp) {
                if(wan_port && strcmp(wan_port, "any") && wan_port[0])
                    fprintf(fp, "\t\ttcp dport %s ct count over %d drop\n", wan_port, limit);
                else
                    fprintf(fp, "\t\tmeta l4proto tcp ct count over %d drop\n", limit);
            }
            if(udp) {
                if(wan_port && strcmp(wan_port, "any") && wan_port[0])
                    fprintf(fp, "\t\tudp dport %s ct count over %d drop\n", wan_port, limit);
                else
                    fprintf(fp, "\t\tmeta l4proto udp ct count over %d drop\n", limit);
            }
            count++;
    }
    sqlite3_finalize(st);
    return step_rc == SQLITE_DONE && !ferror(fp) ? count : -1;

fail:
    sqlite3_finalize(st);
    return -1;
}

/* ── Structured tc policing for terminal speed limits ─────────── */
#define NC_NETCTL_TC_TIMEOUT_MS 10000
#define NC_NETCTL_TC_OUTPUT_MAX (256U * 1024U)
#define NC_NETCTL_TC_MAX_RULES 512
#define NC_NETCTL_TC_PREF_SPAN 1000
#define NC_NETCTL_TC_INGRESS_PREF_BASE 7000
#define NC_NETCTL_TC_EGRESS_PREF_BASE 8000
#define NC_NETCTL_TC_LOCK "network-control-tc.lock"

struct nc_tc_rule {
    char rule_id[96];
    char direction[16];
    char address[INET6_ADDRSTRLEN];
    char protocol[16];
    int pref;
    int family;
    int src_port;
    int dest_port;
    int rate_kbit;
};

struct nc_tc_plan {
    char ifname[IFNAMSIZ];
    struct nc_tc_rule rules[NC_NETCTL_TC_MAX_RULES];
    size_t count;
    int clsact_owned;
};

static const char *nc_tc_tool_path(void)
{
    if (nc_netctl_trusted_tool("/usr/sbin/tc"))
        return "/usr/sbin/tc";
    if (nc_netctl_trusted_tool("/usr/libexec/tc-full"))
        return "/usr/libexec/tc-full";
    if (nc_netctl_trusted_tool("/sbin/tc"))
        return "/sbin/tc";
    return NULL;
}

static int nc_tc_result_ok(int rc, const struct jmx_exec_result *result)
{
    if (rc != 0 || !result || result->timed_out || result->truncated ||
        result->term_signal != 0 || result->exit_code != 0)
        return -1;
    return 0;
}

static int nc_tc_exec_wait(const char *tc, char *const argv[])
{
    struct jmx_exec_result result;
    int rc;

    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    rc = jmx_exec_wait(tc, argv, NC_NETCTL_TC_TIMEOUT_MS, &result);
    if (nc_tc_result_ok(rc, &result) != 0) {
        jmx_exec_result_free(&result);
        return -1;
    }
    jmx_exec_result_free(&result);
    return 0;
}

static int nc_tc_exec_capture(const char *tc, char *const argv[],
                              struct jmx_exec_result *result)
{
    int rc;

    if (!tc || !argv || !result)
        return -1;
    memset(result, 0, sizeof(*result));
    result->exit_code = -1;
    rc = jmx_exec_capture(tc, argv, NC_NETCTL_TC_OUTPUT_MAX,
                          NC_NETCTL_TC_TIMEOUT_MS, result);
    return nc_tc_result_ok(rc, result);
}

static int nc_tc_port_value(const char *text, int *port)
{
    char *end = NULL;
    long value;

    if (!port)
        return -1;
    *port = 0;
    if (!text || !text[0] || !strcasecmp(text, "any") || !strcmp(text, "*"))
        return 0;
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno || !end || *end || value < 1 || value > 65535)
        return -1;
    *port = (int)value;
    return 0;
}

static int nc_tc_protocol_ok(const char *protocol, int family,
                             int src_port, int dest_port)
{
    if (!protocol || !protocol[0] || !strcasecmp(protocol, "all") ||
        !strcasecmp(protocol, "any"))
        return src_port == 0 && dest_port == 0;
    if (!strcasecmp(protocol, "tcp") || !strcasecmp(protocol, "udp"))
        return 1;
    if (!strcasecmp(protocol, "icmp"))
        return family == AF_INET && src_port == 0 && dest_port == 0;
    if (!strcasecmp(protocol, "icmpv6") ||
        !strcasecmp(protocol, "ipv6-icmp"))
        return family == AF_INET6 && src_port == 0 && dest_port == 0;
    return 0;
}

static unsigned int nc_tc_rule_hash(const char *id, const char *direction)
{
    const unsigned char *p;
    unsigned int hash = 2166136261U;

    for (p = (const unsigned char *)(id ? id : ""); *p; p++)
        hash = (hash ^ *p) * 16777619U;
    for (p = (const unsigned char *)(direction ? direction : ""); *p; p++)
        hash = (hash ^ *p) * 16777619U;
    return hash;
}

static int nc_tc_pref_used(const struct nc_tc_plan *plan, int pref)
{
    size_t i;

    for (i = 0; plan && i < plan->count; i++)
        if (plan->rules[i].pref == pref)
            return 1;
    return 0;
}

static int nc_tc_assign_pref(struct nc_tc_plan *plan, const char *rule_id,
                             const char *direction)
{
    int base = !strcmp(direction, "ingress") ?
               NC_NETCTL_TC_INGRESS_PREF_BASE : NC_NETCTL_TC_EGRESS_PREF_BASE;
    unsigned int slot = nc_tc_rule_hash(rule_id, direction) %
                        NC_NETCTL_TC_PREF_SPAN;
    unsigned int i;

    for (i = 0; i < NC_NETCTL_TC_PREF_SPAN; i++) {
        int pref = base + (int)((slot + i) % NC_NETCTL_TC_PREF_SPAN);
        if (!nc_tc_pref_used(plan, pref))
            return pref;
    }
    return -1;
}

static int nc_tc_lan_ifname(char *ifname, size_t ifname_len)
{
    sqlite3_stmt *st = NULL;
    const char *value = NULL;

    if (!ifname || ifname_len < 2)
        return -1;
    snprintf(ifname, ifname_len, "br-lan");
    if (nc_prepare(&st,
        "SELECT lan_ifname FROM legacy_jmx_settings WHERE id=1") == 0 &&
        sqlite3_step(st) == SQLITE_ROW)
        value = (const char *)sqlite3_column_text(st, 0);
    if (value && value[0])
        snprintf(ifname, ifname_len, "%s", value);
    if (st)
        sqlite3_finalize(st);
    return nc_physical_port_ifname_strict_ok(ifname) &&
           if_nametoindex(ifname) != 0 ? 0 : -1;
}

static int nc_tc_plan_append(struct nc_tc_plan *plan, const char *rule_id,
                             const char *direction, const char *address,
                             const char *protocol, int family, int src_port,
                             int dest_port, double rate_mbps)
{
    struct nc_tc_rule *rule;
    double rate_kbit;
    int pref;

    if (!plan || !rule_id || !rule_id[0] || !direction || !address ||
        !address[0] || rate_mbps <= 0 ||
        plan->count >= NC_NETCTL_TC_MAX_RULES)
        return -1;
    pref = nc_tc_assign_pref(plan, rule_id, direction);
    rate_kbit = rate_mbps * 1000.0;
    if (pref < 0 || rate_kbit < 1.0 || rate_kbit > 10000000.0)
        return -1;
    rule = &plan->rules[plan->count++];
    memset(rule, 0, sizeof(*rule));
    snprintf(rule->rule_id, sizeof(rule->rule_id), "%s", rule_id);
    snprintf(rule->direction, sizeof(rule->direction), "%s", direction);
    snprintf(rule->address, sizeof(rule->address), "%s", address);
    snprintf(rule->protocol, sizeof(rule->protocol), "%s",
             protocol && protocol[0] ? protocol : "all");
    rule->pref = pref;
    rule->family = family;
    rule->src_port = src_port;
    rule->dest_port = dest_port;
    rule->rate_kbit = (int)(rate_kbit + 0.5);
    return 0;
}

static int nc_tc_build_plan(struct nc_tc_plan *plan)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!plan)
        return -1;
    memset(plan, 0, sizeof(*plan));
    if (nc_tc_lan_ifname(plan->ifname, sizeof(plan->ifname)) != 0)
        return -1;
    if (nc_prepare(&st,
        "SELECT r.id,d.limit_type,d.line,d.address,d.protocol,d.speed_mode,"
        "d.src_port,d.dest_port,d.upload_mbps,d.download_mbps "
        "FROM network_control_rule r JOIN network_control_terminal_limit d "
        "ON d.rule_id=r.id WHERE r.type='terminal_limit' AND r.enabled=1 "
        "AND (r.expires=0 OR r.expires BETWEEN ?1 AND 9223372036854775807) "
        "ORDER BY r.priority,r.id") != 0)
        return -1;
    /*
     * A lapsed rate limit drops out of the plan, and nc_tc_guarded_apply()
     * removes the whole committed plan before installing the new one, so the
     * filter is actually torn off the interface rather than merely omitted from
     * a future install. That removal is readback-verified and rolled back on
     * failure, which is what makes expiry safe to honour on the tc side.
     */
    sqlite3_bind_int64(st, 1, (sqlite3_int64)nc_now_s() + 1);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *rule_id = (const char *)sqlite3_column_text(st, 0);
        const char *limit_type = (const char *)sqlite3_column_text(st, 1);
        const char *line = (const char *)sqlite3_column_text(st, 2);
        const char *address = (const char *)sqlite3_column_text(st, 3);
        const char *protocol = (const char *)sqlite3_column_text(st, 4);
        const char *speed_mode = (const char *)sqlite3_column_text(st, 5);
        const char *src_port_text = (const char *)sqlite3_column_text(st, 6);
        const char *dest_port_text = (const char *)sqlite3_column_text(st, 7);
        double upload_mbps = sqlite3_column_double(st, 8);
        double download_mbps = sqlite3_column_double(st, 9);
        struct in_addr v4;
        struct in6_addr v6;
        int family;
        int src_port;
        int dest_port;

        if (!rule_id || !rule_id[0] || !limit_type ||
            strcasecmp(limit_type, "ip") || !line ||
            (strcasecmp(line, "all") && strcmp(line, "*")) ||
            !speed_mode || (strcasecmp(speed_mode, "shared") &&
                            strcasecmp(speed_mode, "per_ip")) ||
            !address || !address[0])
            goto out;
        if (inet_pton(AF_INET, address, &v4) == 1)
            family = AF_INET;
        else if (inet_pton(AF_INET6, address, &v6) == 1)
            family = AF_INET6;
        else
            goto out;
        if (nc_tc_port_value(src_port_text, &src_port) != 0 ||
            nc_tc_port_value(dest_port_text, &dest_port) != 0 ||
            !nc_tc_protocol_ok(protocol, family, src_port, dest_port) ||
            upload_mbps < 0 || download_mbps < 0)
            goto out;
        if (upload_mbps > 0 &&
            nc_tc_plan_append(plan, rule_id, "ingress", address, protocol,
                              family, src_port, dest_port,
                              upload_mbps) != 0)
            goto out;
        if (download_mbps > 0 &&
            nc_tc_plan_append(plan, rule_id, "egress", address, protocol,
                              family, src_port, dest_port,
                              download_mbps) != 0)
            goto out;
    }
    rc = 0;

out:
    sqlite3_finalize(st);
    return rc;
}

static int nc_tc_load_committed_plan(struct nc_tc_plan *plan)
{
    sqlite3_stmt *st = NULL;

    if (!plan)
        return -1;
    memset(plan, 0, sizeof(*plan));
    if (nc_prepare(&st,
        "SELECT ifname,clsact_owned FROM network_control_tc_state WHERE id=1") == 0 &&
        sqlite3_step(st) == SQLITE_ROW) {
        const char *ifname = (const char *)sqlite3_column_text(st, 0);
        if (ifname)
            snprintf(plan->ifname, sizeof(plan->ifname), "%s", ifname);
        plan->clsact_owned = sqlite3_column_int(st, 1) == 1;
    }
    if (st) {
        sqlite3_finalize(st);
        st = NULL;
    }
    if (nc_prepare(&st,
        "SELECT rule_id,direction,pref,family,address,protocol,src_port,"
        "dest_port,rate_kbit FROM network_control_tc_runtime "
        "ORDER BY direction,pref") != 0)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct nc_tc_rule *rule;

        if (plan->count >= NC_NETCTL_TC_MAX_RULES) {
            sqlite3_finalize(st);
            return -1;
        }
        rule = &plan->rules[plan->count++];
        memset(rule, 0, sizeof(*rule));
        snprintf(rule->rule_id, sizeof(rule->rule_id), "%s",
                 sqlite3_column_text(st, 0));
        snprintf(rule->direction, sizeof(rule->direction), "%s",
                 sqlite3_column_text(st, 1));
        rule->pref = sqlite3_column_int(st, 2);
        rule->family = sqlite3_column_int(st, 3);
        snprintf(rule->address, sizeof(rule->address), "%s",
                 sqlite3_column_text(st, 4));
        snprintf(rule->protocol, sizeof(rule->protocol), "%s",
                 sqlite3_column_text(st, 5));
        rule->src_port = sqlite3_column_int(st, 6);
        rule->dest_port = sqlite3_column_int(st, 7);
        rule->rate_kbit = sqlite3_column_int(st, 8);
    }
    sqlite3_finalize(st);
    if ((plan->count || plan->clsact_owned) &&
        (!nc_physical_port_ifname_strict_ok(plan->ifname) ||
         if_nametoindex(plan->ifname) == 0))
        return -1;
    return 0;
}

static int nc_tc_store_committed_plan(const struct nc_tc_plan *plan)
{
    sqlite3_stmt *st = NULL;
    size_t i;
    int ok = 0;

    if (!plan ||
        ((plan->count || plan->clsact_owned) &&
         (!nc_physical_port_ifname_strict_ok(plan->ifname) ||
          if_nametoindex(plan->ifname) == 0)) ||
        (!plan->count && !plan->clsact_owned && plan->ifname[0] &&
         !nc_physical_port_ifname_strict_ok(plan->ifname)))
        return -1;
    if (nc_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (nc_exec("DELETE FROM network_control_tc_runtime") != 0)
        goto out;
    if (nc_prepare(&st,
        "INSERT INTO network_control_tc_runtime(rule_id,direction,pref,family,"
        "address,protocol,src_port,dest_port,rate_kbit) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)") != 0)
        goto out;
    for (i = 0; i < plan->count; i++) {
        const struct nc_tc_rule *rule = &plan->rules[i];

        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        sqlite3_bind_text(st, 1, rule->rule_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, rule->direction, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, rule->pref);
        sqlite3_bind_int(st, 4, rule->family);
        sqlite3_bind_text(st, 5, rule->address, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, rule->protocol, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 7, rule->src_port);
        sqlite3_bind_int(st, 8, rule->dest_port);
        sqlite3_bind_int(st, 9, rule->rate_kbit);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto out;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st,
        "INSERT INTO network_control_tc_state(id,ifname,generation,updated_at,clsact_owned) "
        "VALUES(1,?1,1,strftime('%s','now'),?2) ON CONFLICT(id) DO UPDATE SET "
        "ifname=excluded.ifname,generation=generation+1,"
        "updated_at=excluded.updated_at,clsact_owned=excluded.clsact_owned") != 0)
        goto out;
    sqlite3_bind_text(st, 1, plan->ifname, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, plan->clsact_owned ? 1 : 0);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto out;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_exec("COMMIT") != 0)
        goto out;
    return 0;

out:
    if (st)
        sqlite3_finalize(st);
    ok = nc_exec("ROLLBACK");
    (void)ok;
    return -1;
}

static int nc_tc_qdisc_has_clsact(const char *tc, const char *ifname,
                                  int *present)
{
    struct jmx_exec_result result;
    struct json_object *root = NULL;
    char *argv[] = { (char *)tc, "-j", "qdisc", "show", "dev",
                     (char *)ifname, NULL };
    int ok = 0;

    if (!present)
        return -1;
    *present = 0;
    if (nc_tc_exec_capture(tc, argv, &result) != 0 || !result.output)
        goto out;
    root = json_tokener_parse(result.output);
    if (!root || !json_object_is_type(root, json_type_array))
        goto out;
    for (size_t i = 0; i < json_object_array_length(root); i++) {
        struct json_object *item = json_object_array_get_idx(root, i);
        struct json_object *kind = NULL;
        if (item && json_object_object_get_ex(item, "kind", &kind) &&
            kind && !strcmp(json_object_get_string(kind), "clsact")) {
            *present = 1;
            break;
        }
    }
    ok = 1;

out:
    if (root) json_object_put(root);
    jmx_exec_result_free(&result);
    return ok ? 0 : -1;
}

static int nc_tc_ensure_clsact(const char *tc, const char *ifname, int *created)
{
    char *argv[] = { (char *)tc, "qdisc", "add", "dev", (char *)ifname,
                     "clsact", NULL };
    int present = 0;

    if (!created)
        return -1;
    *created = 0;
    if (nc_tc_qdisc_has_clsact(tc, ifname, &present) != 0)
        return -1;
    if (!present) {
        if (nc_tc_exec_wait(tc, argv) != 0)
            return -1;
        *created = 1;
    }
    return nc_tc_qdisc_has_clsact(tc, ifname, &present) == 0 && present ? 0 : -1;
}

static int nc_tc_rate_token_kbit(const char *text, char **end_out,
                                 unsigned long *rate_kbit)
{
    char *end = NULL;
    unsigned long value;
    unsigned long multiplier;
    size_t suffix_len;

    if (!text || !end_out || !rate_kbit)
        return -1;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || !end || end == text)
        return -1;
    if (!strncasecmp(end, "Kbit", 4)) {
        multiplier = 1;
        suffix_len = 4;
    } else if (!strncasecmp(end, "Mbit", 4)) {
        multiplier = 1000;
        suffix_len = 4;
    } else if (!strncasecmp(end, "Gbit", 4)) {
        multiplier = 1000000;
        suffix_len = 4;
    } else if (!strncasecmp(end, "bit", 3)) {
        if (value % 1000 != 0)
            return -1;
        value /= 1000;
        multiplier = 1;
        suffix_len = 3;
    } else {
        return -1;
    }
    if (value > ULONG_MAX / multiplier)
        return -1;
    *rate_kbit = value * multiplier;
    *end_out = end + suffix_len;
    return 0;
}

static int nc_tc_remove_owned_clsact(const char *tc, const char *ifname,
                                     int owned)
{
    char *argv[] = { (char *)tc, "qdisc", "delete", "dev",
                     (char *)ifname, "clsact", NULL };
    int present = 0;

    if (!owned)
        return 0;
    if (nc_tc_qdisc_has_clsact(tc, ifname, &present) != 0)
        return -1;
    if (!present)
        return 0;
    if (nc_tc_exec_wait(tc, argv) != 0)
        return -1;
    return nc_tc_qdisc_has_clsact(tc, ifname, &present) == 0 &&
           !present ? 0 : -1;
}

static int nc_tc_rule_readback(const char *tc, const char *ifname,
                               const struct nc_tc_rule *rule, int *present)
{
    struct jmx_exec_result result;
    struct jmx_exec_result detail;
    struct json_object *root = NULL;
    char pref[16];
    char *argv[] = { (char *)tc, "-j", "-s", "-d", "filter", "show", "dev",
                     (char *)ifname, (char *)rule->direction, "pref", pref,
                     NULL };
    char *detail_argv[] = { (char *)tc, "-s", "-d", "filter", "show",
                            "dev", (char *)ifname, (char *)rule->direction,
                            "pref", pref, NULL };
    const char *expected_family;
    const char *expected_addr_key;
    int ok = 0;
    int matched = 0;

    if (!rule || !present)
        return -1;
    *present = 0;
    memset(&result, 0, sizeof(result));
    memset(&detail, 0, sizeof(detail));
    result.exit_code = -1;
    detail.exit_code = -1;
    snprintf(pref, sizeof(pref), "%d", rule->pref);
    if (nc_tc_exec_capture(tc, argv, &result) != 0 || !result.output)
        goto out;
    root = json_tokener_parse(result.output);
    if (!root || !json_object_is_type(root, json_type_array))
        goto out;
    if (json_object_array_length(root) == 0) {
        ok = 1;
        goto out;
    }
    expected_family = rule->family == AF_INET6 ? "ipv6" : "ip";
    expected_addr_key = !strcmp(rule->direction, "ingress") ?
                        "src_ip" : "dst_ip";
    for (size_t i = 0; i < json_object_array_length(root); i++) {
        struct json_object *item = json_object_array_get_idx(root, i);
        struct json_object *protocol = NULL, *kind = NULL, *options = NULL;
        struct json_object *keys = NULL, *value = NULL, *actions = NULL;
        int action_ok = 0;

        if (!item || !json_object_object_get_ex(item, "options", &options) ||
            !options || !json_object_is_type(options, json_type_object))
            continue;
        if (!json_object_object_get_ex(item, "protocol", &protocol) ||
            !protocol || strcmp(json_object_get_string(protocol), expected_family) ||
            !json_object_object_get_ex(item, "kind", &kind) || !kind ||
            strcmp(json_object_get_string(kind), "flower") ||
            !json_object_object_get_ex(options, "keys", &keys) || !keys ||
            !json_object_is_type(keys, json_type_object) ||
            !json_object_object_get_ex(keys, expected_addr_key, &value) || !value ||
            strcmp(json_object_get_string(value), rule->address))
            goto out;
        if (strcasecmp(rule->protocol, "all") &&
            strcasecmp(rule->protocol, "any")) {
            if (!json_object_object_get_ex(keys, "ip_proto", &value) || !value ||
                strcasecmp(json_object_get_string(value), rule->protocol))
                goto out;
        } else if (json_object_object_get_ex(keys, "ip_proto", &value)) {
            goto out;
        }
        if (rule->src_port) {
            if (!json_object_object_get_ex(keys, "src_port", &value) || !value ||
                json_object_get_int(value) != rule->src_port)
                goto out;
        } else if (json_object_object_get_ex(keys, "src_port", &value)) {
            goto out;
        }
        if (rule->dest_port) {
            if (!json_object_object_get_ex(keys, "dst_port", &value) || !value ||
                json_object_get_int(value) != rule->dest_port)
                goto out;
        } else if (json_object_object_get_ex(keys, "dst_port", &value)) {
            goto out;
        }
        if (!json_object_object_get_ex(options, "actions", &actions) || !actions ||
            !json_object_is_type(actions, json_type_array) ||
            json_object_array_length(actions) != 1)
            goto out;
        {
            struct json_object *action = json_object_array_get_idx(actions, 0);
            struct json_object *control = NULL, *type = NULL;
            if (action && json_object_object_get_ex(action, "kind", &value) &&
                value && !strcmp(json_object_get_string(value), "police") &&
                json_object_object_get_ex(action, "control_action", &control) &&
                control && json_object_object_get_ex(control, "type", &type) &&
                type && !strcmp(json_object_get_string(type), "drop"))
                action_ok = 1;
        }
        if (!action_ok || matched)
            goto out;
        matched = 1;
    }
    if (!matched || nc_tc_exec_capture(tc, detail_argv, &detail) != 0 ||
        !detail.output)
        goto out;
    {
        const char *cursor = detail.output;
        int rate_matches = 0;

        while ((cursor = strstr(cursor, " rate ")) != NULL) {
            char *end = NULL;
            unsigned long rate;

            cursor += 6;
            if (nc_tc_rate_token_kbit(cursor, &end, &rate) != 0 ||
                (*end && !isspace((unsigned char)*end)) ||
                rate != (unsigned long)rule->rate_kbit)
                goto out;
            rate_matches++;
            cursor = end;
        }
        if (rate_matches != 1)
            goto out;
    }
    *present = 1;
    ok = 1;

out:
    if (root) json_object_put(root);
    jmx_exec_result_free(&result);
    jmx_exec_result_free(&detail);
    return ok ? 0 : -1;
}

static int nc_tc_rule_delete(const char *tc, const char *ifname,
                             const struct nc_tc_rule *rule)
{
    char pref[16];
    char *argv[] = { (char *)tc, "filter", "delete", "dev",
                     (char *)ifname, (char *)rule->direction, "pref", pref,
                     NULL };
    int present = 0;

    if (nc_tc_rule_readback(tc, ifname, rule, &present) != 0)
        return -1;
    if (!present)
        return 0;
    snprintf(pref, sizeof(pref), "%d", rule->pref);
    if (nc_tc_exec_wait(tc, argv) != 0)
        return -1;
    return nc_tc_rule_readback(tc, ifname, rule, &present) == 0 &&
           !present ? 0 : -1;
}

static int nc_tc_rule_install(const char *tc, const char *ifname,
                              const struct nc_tc_rule *rule)
{
    char pref[16];
    char rate[32];
    char src_port[16];
    char dest_port[16];
    const char *family = rule->family == AF_INET6 ? "ipv6" : "ip";
    const char *addr_key = !strcmp(rule->direction, "ingress") ?
                           "src_ip" : "dst_ip";
    char *argv[36];
    int n = 0;
    int present = 0;

    snprintf(pref, sizeof(pref), "%d", rule->pref);
    snprintf(rate, sizeof(rate), "%dkbit", rule->rate_kbit);
    argv[n++] = (char *)tc;
    argv[n++] = "filter";
    if (nc_tc_rule_readback(tc, ifname, rule, &present) != 0)
        return -1;
    if (present)
        return 0;
    argv[n++] = "add";
    argv[n++] = "dev";
    argv[n++] = (char *)ifname;
    argv[n++] = (char *)rule->direction;
    argv[n++] = "protocol";
    argv[n++] = (char *)family;
    argv[n++] = "pref";
    argv[n++] = pref;
    argv[n++] = "flower";
    argv[n++] = (char *)addr_key;
    argv[n++] = (char *)rule->address;
    if (strcasecmp(rule->protocol, "all") &&
        strcasecmp(rule->protocol, "any")) {
        argv[n++] = "ip_proto";
        argv[n++] = (char *)rule->protocol;
    }
    if (rule->src_port) {
        snprintf(src_port, sizeof(src_port), "%d", rule->src_port);
        argv[n++] = "src_port";
        argv[n++] = src_port;
    }
    if (rule->dest_port) {
        snprintf(dest_port, sizeof(dest_port), "%d", rule->dest_port);
        argv[n++] = "dst_port";
        argv[n++] = dest_port;
    }
    argv[n++] = "action";
    argv[n++] = "police";
    argv[n++] = "rate";
    argv[n++] = rate;
    argv[n++] = "burst";
    argv[n++] = "64k";
    argv[n++] = "conform-exceed";
    argv[n++] = "drop";
    argv[n] = NULL;
    if (nc_tc_exec_wait(tc, argv) != 0)
        return -1;
    return nc_tc_rule_readback(tc, ifname, rule, &present) == 0 &&
           present ? 0 : -1;
}

static int nc_tc_plan_verify(const char *tc, const struct nc_tc_plan *plan)
{
    size_t i;

    for (i = 0; plan && i < plan->count; i++) {
        int present = 0;
        if (nc_tc_rule_readback(tc, plan->ifname, &plan->rules[i],
                                &present) != 0 || !present)
            return -1;
    }
    return 0;
}

static int nc_tc_plan_remove(const char *tc, const struct nc_tc_plan *plan)
{
    size_t i;

    if (!plan)
        return -1;
    for (i = 0; i < plan->count; i++)
        if (nc_tc_rule_delete(tc, plan->ifname, &plan->rules[i]) != 0)
            return -1;
    return 0;
}

static int nc_tc_plan_install(const char *tc, struct nc_tc_plan *plan)
{
    size_t i;
    int created = 0;

    if (!plan || nc_tc_ensure_clsact(tc, plan->ifname, &created) != 0)
        return -1;
    if (created)
        plan->clsact_owned = 1;
    for (i = 0; i < plan->count; i++)
        if (nc_tc_rule_install(tc, plan->ifname, &plan->rules[i]) != 0)
            return -1;
    return nc_tc_plan_verify(tc, plan);
}

static int nc_tc_rollback(const char *tc, const struct nc_tc_plan *current,
                          struct nc_tc_plan *previous)
{
    int rollback_rc = 0;

    if (current && current->ifname[0] &&
        nc_tc_plan_remove(tc, current) != 0)
        rollback_rc = -1;
    if (current && current->ifname[0] && current->clsact_owned &&
        (!previous || !previous->count) &&
        nc_tc_remove_owned_clsact(tc, current->ifname, 1) != 0)
        rollback_rc = -1;
    if (previous && previous->count) {
        if (nc_tc_plan_install(tc, previous) != 0 ||
            nc_tc_plan_verify(tc, previous) != 0)
            rollback_rc = -1;
    } else if (previous && previous->clsact_owned) {
        int created = 0;
        if (nc_tc_ensure_clsact(tc, previous->ifname, &created) != 0)
            rollback_rc = -1;
    }
    return rollback_rc;
}

static int nc_tc_lock_open(void)
{
    struct stat st;
    int dirfd = -1;
    int lockfd = -1;

    if (mkdir(NC_NETCTL_RUNTIME_DIR, 0700) != 0 && errno != EEXIST)
        return -1;
    dirfd = open(NC_NETCTL_RUNTIME_DIR,
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0 || fstat(dirfd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        goto out;
    lockfd = openat(dirfd, NC_NETCTL_TC_LOCK,
                    O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lockfd < 0 || fstat(lockfd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        flock(lockfd, LOCK_EX | LOCK_NB) != 0) {
        if (lockfd >= 0) close(lockfd);
        lockfd = -1;
    }

out:
    if (dirfd >= 0) close(dirfd);
    return lockfd;
}

static int nc_tc_plan_count(void)
{
    struct nc_tc_plan plan;
    return nc_tc_build_plan(&plan) == 0 ? (int)plan.count : -1;
}

static int nc_tc_guarded_apply(char *detail, size_t detail_len,
                               struct nc_tc_plan *previous_out)
{
    struct nc_tc_plan desired;
    struct nc_tc_plan previous;
    const char *tc;
    int lockfd = -1;
    int mutated = 0;

    if (detail && detail_len)
        detail[0] = '\0';
    if (nc_tc_build_plan(&desired) != 0) {
        if (detail) snprintf(detail, detail_len, "tc_plan_invalid");
        return -2;
    }
    if (nc_tc_load_committed_plan(&previous) != 0) {
        if (detail) snprintf(detail, detail_len, "tc_backup_load_failed");
        return -3;
    }
    if (previous_out)
        *previous_out = previous;
    if (!strcmp(previous.ifname, desired.ifname))
        desired.clsact_owned = previous.clsact_owned;
    if (!desired.count && !previous.count && !previous.clsact_owned) {
        if (nc_tc_store_committed_plan(&desired) != 0) {
            if (detail) snprintf(detail, detail_len, "tc_empty_plan_commit_failed");
            return -1;
        }
        if (detail) snprintf(detail, detail_len, "tc_no_rules");
        return 0;
    }
    tc = nc_tc_tool_path();
    if (!tc) {
        if (detail) snprintf(detail, detail_len, "tc_binary_missing_or_untrusted");
        return -1;
    }
    if (desired.count && (previous.count || previous.clsact_owned) &&
        strcmp(previous.ifname, desired.ifname)) {
        if (detail) snprintf(detail, detail_len, "tc_interface_change_requires_cleanup");
        return -4;
    }
    lockfd = nc_tc_lock_open();
    if (lockfd < 0) {
        if (detail) snprintf(detail, detail_len, "tc_apply_in_progress_or_lock_failed");
        return -5;
    }
    if (previous.count && nc_tc_plan_verify(tc, &previous) != 0) {
        if (detail) snprintf(detail, detail_len, "tc_backup_readback_mismatch");
        close(lockfd);
        return -6;
    }
    if (previous.count) {
        mutated = 1;
        if (nc_tc_plan_remove(tc, &previous) != 0) {
        if (detail) snprintf(detail, detail_len, "tc_delete_failed");
        goto rollback;
        }
    }
    if (desired.count && nc_tc_plan_install(tc, &desired) != 0) {
        mutated = 1;
        if (detail) snprintf(detail, detail_len, "tc_apply_or_readback_failed");
        goto rollback;
    }
    mutated = mutated || desired.count > 0;
    if (!desired.count && previous.clsact_owned) {
        mutated = 1;
        if (nc_tc_remove_owned_clsact(tc, previous.ifname, 1) != 0) {
            if (detail) snprintf(detail, detail_len, "tc_owned_clsact_cleanup_failed");
            goto rollback;
        }
        desired.clsact_owned = 0;
    }
    if (nc_tc_store_committed_plan(&desired) != 0) {
        if (detail) snprintf(detail, detail_len, "tc_commit_failed");
        goto rollback;
    }
    if (desired.count && nc_tc_plan_verify(tc, &desired) != 0) {
        if (detail) snprintf(detail, detail_len, "tc_committed_readback_failed");
        goto rollback_store;
    }
    close(lockfd);
    if (detail) snprintf(detail, detail_len, "tc_applied_and_verified");
    return 0;

rollback_store:
    if (nc_tc_rollback(tc, &desired, &previous) != 0 ||
        nc_tc_store_committed_plan(&previous) != 0) {
        if (detail) snprintf(detail, detail_len, "tc_rollback_failed");
        close(lockfd);
        return -8;
    }
    if (detail) snprintf(detail, detail_len, "tc_apply_failed_rollback_verified");
    close(lockfd);
    return -7;
rollback:
    if (mutated && nc_tc_rollback(tc, &desired, &previous) != 0) {
        if (detail) snprintf(detail, detail_len, "tc_rollback_failed");
        close(lockfd);
        return -8;
    }
    if (detail) snprintf(detail, detail_len, "tc_apply_failed_rollback_verified");
    close(lockfd);
    return -7;
}

static int nc_tc_restore_previous(const struct nc_tc_plan *previous)
{
    struct nc_tc_plan current;
    struct nc_tc_plan restore;
    const char *tc;
    int lockfd;
    int rc = -1;

    if (!previous || nc_tc_load_committed_plan(&current) != 0)
        return -1;
    restore = *previous;
    if (!current.count && !current.clsact_owned && !previous->count &&
        !previous->clsact_owned)
        return nc_tc_store_committed_plan(previous);
    tc = nc_tc_tool_path();
    if (!tc)
        return -1;
    lockfd = nc_tc_lock_open();
    if (lockfd < 0)
        return -1;
    if (nc_tc_rollback(tc, &current, &restore) == 0 &&
        nc_tc_store_committed_plan(&restore) == 0 &&
        (!restore.count || nc_tc_plan_verify(tc, &restore) == 0))
        rc = 0;
    close(lockfd);
    return rc;
}

static int nc_netctl_apply_lock_open(void)
{
    struct stat st;
    int dirfd = -1;
    int lockfd = -1;

    if (mkdir(NC_NETCTL_RUNTIME_DIR, 0700) != 0 && errno != EEXIST)
        return -1;
    dirfd = open(NC_NETCTL_RUNTIME_DIR,
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0 || fstat(dirfd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        goto out;
    lockfd = openat(dirfd, "network-control-apply.lock",
                    O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lockfd < 0 || fstat(lockfd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        flock(lockfd, LOCK_EX | LOCK_NB) != 0) {
        if (lockfd >= 0)
            close(lockfd);
        lockfd = -1;
    }

out:
    if (dirfd >= 0)
        close(dirfd);
    return lockfd;
}

static int nc_netctl_persist_apply_status(int applied, const char *nft_state,
                                          const char *tc_state)
{
    sqlite3_stmt *st = NULL;
    char status_text[384];
    const char *state = applied ? "applied" : "failed";
    int rollback_rc;

    snprintf(status_text, sizeof(status_text), "nft=%s; tc=%s",
             nft_state ? nft_state : "unknown",
             tc_state ? tc_state : "unknown");
    if (nc_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (nc_prepare(&st,
        "UPDATE network_control_status SET apply_state=?1,"
        "last_apply_at=strftime('%s','now'),warnings=?2,"
        "updated_at=strftime('%s','now') WHERE id=1") != 0)
        goto failed;
    sqlite3_bind_text(st, 1, state, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, status_text, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_netconfig_db) != 1)
        goto failed;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st,
        "UPDATE network_control_global SET apply_state=?1,"
        "last_apply_at=strftime('%s','now') WHERE id=1") != 0)
        goto failed;
    sqlite3_bind_text(st, 1, state, -1, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_netconfig_db) != 1)
        goto failed;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_exec("COMMIT") != 0)
        goto failed;
    return 0;

failed:
    if (st)
        sqlite3_finalize(st);
    rollback_rc = nc_exec("ROLLBACK");
    (void)rollback_rc;
    return -1;
}

static int nc_nft_write_ruleset(const char *path)
{
    struct stat st;
    FILE *fp = NULL;
    int dirfd = -1, fd = -1, rc = -1;
    int mac_cnt, conn_cnt, app_mark, app_cnt;
    struct nc_macacl_state macacl;
    int macacl_elements = 0;
    int macacl_rules = 0;
    char temporary[96] = {0};
    char backup[96] = {0};
    unsigned long long nonce;
    int backup_present = 0;
    int published = 0;

    memset(&macacl, 0, sizeof(macacl));
    if (nc_macacl_state_load(&macacl) != 0)
        memset(&macacl, 0, sizeof(macacl));
    if (!path || strcmp(path, NC_NETCTL_NFT_RULESET) != 0)
        return -1;
    dirfd = open("/etc/dreamingwrt",
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0 || fstat(dirfd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        goto out;
    for (int attempt = 0; attempt < 32; attempt++) {
        if (getrandom(&nonce, sizeof(nonce), 0) != (ssize_t)sizeof(nonce))
            goto out;
        snprintf(temporary, sizeof(temporary),
                 ".network_control.nft.%016llx", nonce);
        fd = openat(dirfd, temporary,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
        if (fd >= 0)
            break;
        if (errno != EEXIST)
            goto out;
        temporary[0] = '\0';
    }
    if (fd < 0 || fchmod(fd, 0600) != 0 || fchown(fd, 0, 0) != 0 ||
        !(fp = fdopen(fd, "w")))
        goto out;
    fd = -1;
    if (fprintf(fp, "# DreamingWrt network_control nft ruleset - auto generated\n") < 0 ||
        fprintf(fp, "# Do not edit manually; regenerated by jmx network_control_apply\n\n") < 0 ||
        fprintf(fp, "table inet dreamingwrt_netctl {\n") < 0)
        goto out;

    /*
     * The allowlist set is declared before the chains because nft resolves
     * @set references at load time; a rule referring to a set defined later in
     * the same table fails --check rather than loading.
     */
    if (nc_nft_gen_macacl_set(fp, &macacl, &macacl_elements) < 0)
        goto out;

    /* --- input chain: MAC filter + connection limits --- */
    if (fprintf(fp, "\tchain input {\n") < 0 ||
        fprintf(fp, "\t\ttype filter hook input priority 0; policy accept;\n") < 0)
        goto out;
    mac_cnt = nc_nft_gen_mac_rules(fp);
    conn_cnt = nc_nft_gen_connection_limit_rules(fp);
    if (mac_cnt < 0 || conn_cnt < 0 || fprintf(fp, "\t}\n\n") < 0)
        goto out;

    /* --- forward mark chain: classify packets BEFORE the action chain --- */
    if (fprintf(fp, "\tchain forward_mark {\n") < 0 ||
        fprintf(fp, "\t\ttype filter hook forward priority -150; policy accept;\n") < 0)
        goto out;
    app_mark = nc_nft_gen_app_mark_rules(fp);
    if (app_mark < 0 || fprintf(fp, "\t}\n\n") < 0)
        goto out;

    /* --- forward chain: MAC + app action + connection limits --- */
    if (fprintf(fp, "\tchain forward {\n") < 0 ||
        fprintf(fp, "\t\ttype filter hook forward priority 0; policy accept;\n") < 0 ||
        nc_nft_gen_mac_rules(fp) < 0)
        goto out;
    /*
     * Placed after the per-MAC rules so an explicit rule still decides first
     * (nft is first-match-wins), and before the app rules because a device that
     * is not on the allowlist has no business reaching them at all.
     */
    macacl_rules = nc_nft_gen_macacl_rule(fp, &macacl);
    if (macacl_rules < 0)
        goto out;
    app_cnt = nc_nft_gen_app_action_rules(fp);
    if (app_cnt < 0 || nc_nft_gen_connection_limit_rules(fp) < 0 ||
        fprintf(fp, "\t}\n}\n") < 0 || fflush(fp) != 0 ||
        fsync(fileno(fp)) != 0 || fclose(fp) != 0) {
        fp = NULL;
        goto out;
    }
    fp = NULL;
    if (fstatat(dirfd, "network_control.nft", &st,
                AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(st.st_mode) || st.st_uid != 0 ||
            (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
            goto out;
        snprintf(backup, sizeof(backup),
                 ".network_control.nft.backup.%016llx", nonce);
        if (linkat(dirfd, "network_control.nft", dirfd, backup, 0) != 0)
            goto out;
        backup_present = 1;
    } else if (errno != ENOENT) {
        goto out;
    }
    if (renameat(dirfd, temporary, dirfd, "network_control.nft") != 0)
        goto out;
    temporary[0] = '\0';
    published = 1;
    if (fsync(dirfd) != 0) {
        if (backup_present) {
            if (renameat(dirfd, backup, dirfd, "network_control.nft") == 0)
                backup[0] = '\0';
        } else {
            (void)unlinkat(dirfd, "network_control.nft", 0);
        }
        (void)fsync(dirfd);
        goto out;
    }
    if (backup_present) {
        if (unlinkat(dirfd, backup, 0) == 0) {
            backup[0] = '\0';
            (void)fsync(dirfd);
        } else {
            backup[0] = '\0';
        }
    }
    rc = mac_cnt + conn_cnt + app_mark + app_cnt + macacl_rules;

out:
    if (fp)
        fclose(fp);
    else if (fd >= 0)
        close(fd);
    if (dirfd >= 0) {
        if (temporary[0])
            (void)unlinkat(dirfd, temporary, 0);
        if (backup[0]) {
            if (published)
                (void)renameat(dirfd, backup, dirfd, "network_control.nft");
            else
                (void)unlinkat(dirfd, backup, 0);
            (void)fsync(dirfd);
        }
        close(dirfd);
    }
    return rc;
}

/*
 * Defined with the rule-expiry timer below. Declared here because every
 * network-control write ends in the apply path that follows, and that is where
 * the timer has to be re-armed.
 */
static void nc_expiry_arm_after_apply(void);

struct json_object *jmx_network_control_apply(struct json_object *cfg)
{
    struct json_object *data = json_object_new_object();
    struct json_object *runtime = json_object_new_object();
    struct json_object *warnings = json_object_new_array();
    struct nc_tc_plan tc_previous;
    struct nc_nft_transaction nft_transaction;
    char nft_detail[160] = "not_attempted";
    char tc_detail[160] = "not_attempted";
    int dry = cfg ? nc_json_bool_def(cfg, "dry_run", 0) : 0;
    int apply_nft = cfg ? nc_json_bool_def(cfg, "apply_nft", 1) : 1;
    int apply_tc = cfg ? nc_json_bool_def(cfg, "apply_tc", 1) : 1;
    int nft_count = 0;
    int tc_count = 0;
    int nft_rc = 99;
    int tc_rc = 99;
    int runtime_ok = dry;
    int apply_lock = -1;
    int tc_applied = 0;
    int nft_applied = 0;
    int status_persisted = 0;

    memset(&tc_previous, 0, sizeof(tc_previous));
    memset(&nft_transaction, 0, sizeof(nft_transaction));
    if (jmx_netconfig_db_init() != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error",
                               json_object_new_string("database_unavailable"));
        goto response;
    }
    nc_netctl_db_init();
    if (dry)
        goto response;

    apply_lock = nc_netctl_apply_lock_open();
    if (apply_lock < 0) {
        snprintf(nft_detail, sizeof(nft_detail), "apply_in_progress_or_lock_failed");
        snprintf(tc_detail, sizeof(tc_detail), "apply_in_progress_or_lock_failed");
        nft_rc = -10;
        tc_rc = -10;
        goto persist_status;
    }
    if (mkdir("/etc/dreamingwrt", 0755) != 0 && errno != EEXIST) {
        snprintf(nft_detail, sizeof(nft_detail), "runtime_directory_prepare_failed");
        snprintf(tc_detail, sizeof(tc_detail), "runtime_directory_prepare_failed");
        nft_rc = -11;
        tc_rc = -11;
        goto persist_status;
    }

    nft_count = nc_nft_write_ruleset(NC_NETCTL_NFT_RULESET);
    tc_count = nc_tc_plan_count();
    if (nft_count < 0) {
        nft_rc = -12;
        snprintf(nft_detail, sizeof(nft_detail), "nft_ruleset_generation_failed");
        tc_rc = -12;
        snprintf(tc_detail, sizeof(tc_detail), "tc_skipped_nft_generation_failed");
        goto persist_status;
    }
    if (tc_count < 0) {
        tc_rc = -2;
        snprintf(tc_detail, sizeof(tc_detail), "tc_plan_invalid");
        nft_rc = -8;
        snprintf(nft_detail, sizeof(nft_detail), "nft_skipped_invalid_tc_plan");
        goto persist_status;
    }

    if (apply_tc) {
        tc_rc = nc_tc_guarded_apply(tc_detail, sizeof(tc_detail),
                                    &tc_previous);
        if (tc_rc != 0) {
            nft_rc = -13;
            snprintf(nft_detail, sizeof(nft_detail), "nft_skipped_tc_apply_failed");
            goto persist_status;
        }
        tc_applied = 1;
    }
    if (apply_nft) {
        nft_rc = nc_nft_guarded_apply(NC_NETCTL_NFT_RULESET,
                                      nft_detail, sizeof(nft_detail),
                                      &nft_transaction);
        if (nft_rc != 0) {
            if (tc_applied) {
                if (nc_tc_restore_previous(&tc_previous) != 0) {
                    tc_rc = -9;
                    snprintf(tc_detail, sizeof(tc_detail),
                             "tc_compensation_after_nft_failure_failed");
                } else {
                    tc_rc = -7;
                    snprintf(tc_detail, sizeof(tc_detail),
                             "tc_rollback_after_nft_failure_verified");
                }
            }
            goto persist_status;
        }
        nft_applied = 1;
    }
    runtime_ok = 1;

persist_status:
    {
        const char *nft_state = apply_nft ? nft_detail : "disabled_by_request";
        const char *tc_state = apply_tc ? tc_detail : "disabled_by_request";

        if (nc_netctl_persist_apply_status(runtime_ok, nft_state, tc_state) == 0) {
            status_persisted = 1;
            if (runtime_ok)
                nc_nft_transaction_finish(&nft_transaction);
        } else if (runtime_ok) {
            if (nft_applied && nc_nft_transaction_restore(&nft_transaction) != 0) {
                nft_rc = -15;
                snprintf(nft_detail, sizeof(nft_detail),
                         "nft_compensation_after_status_failure_failed");
            } else if (nft_applied) {
                nft_rc = -14;
                snprintf(nft_detail, sizeof(nft_detail),
                         "nft_rollback_after_status_failure_verified");
            }
            if (tc_applied && nc_tc_restore_previous(&tc_previous) != 0) {
                tc_rc = -11;
                snprintf(tc_detail, sizeof(tc_detail),
                         "tc_compensation_after_status_failure_failed");
            } else if (tc_applied) {
                tc_rc = -10;
                snprintf(tc_detail, sizeof(tc_detail),
                         "tc_rollback_after_status_failure_verified");
            }
            runtime_ok = 0;
            (void)nc_netctl_persist_apply_status(0, nft_detail, tc_detail);
        } else {
            runtime_ok = 0;
        }
    }
    if (apply_lock >= 0) {
        close(apply_lock);
        apply_lock = -1;
    }

response:
    json_object_object_add(runtime, "jmx_mac_filter",
                           json_object_new_string(dry ? "dry_run" : "config_db"));
    json_object_object_add(runtime, "jmx_app_filter",
                           json_object_new_string(dry ? "dry_run" : "config_db"));
    json_object_object_add(runtime, "nft",
                           json_object_new_string(dry ? "dry_run" :
                           nft_count > 0 ? "ruleset_generated" : "no_rules"));
    json_object_object_add(runtime, "nft_file",
                           json_object_new_string(NC_NETCTL_NFT_RULESET));
    json_object_object_add(runtime, "tc",
                           json_object_new_string(dry ? "dry_run" :
                           tc_count > 0 ? "structured_plan" : "no_rules"));
    json_object_object_add(runtime, "tc_source",
                           json_object_new_string("config_db"));
    json_object_object_add(runtime, "apply_nft",
                           json_object_new_string(dry ? "dry_run" :
                           apply_nft ? "guarded_attempted" : "disabled_by_request"));
    json_object_object_add(runtime, "apply_tc",
                           json_object_new_string(dry ? "dry_run" :
                           apply_tc ? "guarded_attempted" : "disabled_by_request"));
    json_object_object_add(runtime, "nft_rc", json_object_new_int(nft_rc));
    json_object_object_add(runtime, "tc_rc", json_object_new_int(tc_rc));
    json_object_object_add(runtime, "nft_detail",
                           json_object_new_string(nft_detail));
    json_object_object_add(runtime, "tc_detail",
                           json_object_new_string(tc_detail));
    json_object_object_add(runtime, "status_persisted",
                           json_object_new_boolean(status_persisted));
    json_object_array_add(warnings, json_object_new_string(
        "URL HTTPS rewrite is unsupported without proxy/MITM"));
    json_object_array_add(warnings, json_object_new_string(
        "nft/tc apply is bounded, read back, single-flight, and compensated"));
    json_object_object_add(data, "ok", json_object_new_boolean(dry || runtime_ok));
    json_object_object_add(data, "dry_run", json_object_new_boolean(dry));
    json_object_object_add(data, "applied",
                           json_object_new_boolean(!dry && runtime_ok));
    if (!dry && !runtime_ok) {
        json_object_object_add(data, "error",
                               json_object_new_string("runtime_apply_failed"));
        json_object_object_add(data, "message", json_object_new_string(
            "network control runtime apply failed and compensation was attempted"));
    }
    json_object_object_add(data, "runtime", runtime);
    json_object_object_add(data, "warnings", warnings);
    if (apply_lock >= 0)
        close(apply_lock);
    if (!nft_transaction.applied || runtime_ok)
        nc_nft_transaction_finish(&nft_transaction);
    /*
     * Every network-control write funnels through here, whether it arrived over
     * ubus from webd or from a direct in-process call, so this is the one place
     * that has to notice a newly added or edited expires. Arming here instead of
     * in each write path means no caller can forget to. Dry runs change nothing,
     * and this sits after the lock is released so the timer's own busy check
     * cannot see our lock and back off for no reason.
     */
    if (!dry)
        nc_expiry_arm_after_apply();
    return jmx_gen_api_response_data((dry || runtime_ok) ?
                                     API_CODE_SUCCESS : API_CODE_ERROR, data);
}

/*
 * ── Rule expiry: making "expires" take effect without a human ──
 *
 * nc_nft_gen_mac_rules() already filters expired rows out of the generated
 * ruleset, so a lapsed rule disappears the next time the ruleset is built. The
 * gap was that nothing built it: every caller of jmx_network_control_apply() is
 * event driven (a webd write, reload_rules, an explicit ubus call), so a rule
 * set to lapse in ten minutes kept its nft drop until somebody happened to
 * touch the module again. The list said "expired" while the device was still
 * cut off, which reads as a bug rather than as latency.
 *
 * This is a deadline timer rather than a periodic sweep: it sleeps until the
 * earliest future expiry and does nothing at all when no rule has one, so the
 * cost does not scale with the rule count and there is no idle polling on a
 * system that never uses temporary rules.
 */
static struct uloop_timeout nc_expiry_tm;
static int nc_expiry_armed;
static int64_t nc_expiry_armed_for;

/* Bound the sleep so a clock jump cannot park the timer years out. */
#define NC_EXPIRY_MAX_SLEEP_S 3600
/* Fire just after the deadline: at exactly expires the SQL filter still keeps
 * the row (the predicate is expires > now), so waking a second late is what
 * makes the rebuild actually drop it. */
#define NC_EXPIRY_LAG_S 1
/* Retry delay when the apply lock is held by a concurrent write. */
#define NC_EXPIRY_RETRY_S 5

static void nc_expiry_arm(void);
static void nc_expiry_cb(struct uloop_timeout *t);

/*
 * Rule types whose generator honours expires. Every type listed here is
 * filtered by "(expires=0 OR expires>now)" in the code that renders it:
 * mac and app and connection_limit in the nft ruleset, terminal_limit in the tc
 * plan. The timer must schedule for exactly this set -- waking for a type whose
 * generator ignores expires would rebuild to an identical ruleset and then
 * re-arm on the same row forever, and omitting a type that does honour it
 * leaves that type waiting for the next unrelated write.
 */
#define NC_EXPIRY_RULE_TYPES \
    "('mac','app','connection_limit','terminal_limit')"

/*
 * Earliest expiry strictly in the future, or 0 when no enabled rule has one.
 */
static int64_t nc_expiry_next_deadline(void)
{
    sqlite3_stmt *st = NULL;
    int64_t now = nc_now_s();
    int64_t next = 0;

    if (nc_prepare(&st,
            "SELECT MIN(r.expires) FROM network_control_rule r "
            "WHERE r.type IN " NC_EXPIRY_RULE_TYPES
            " AND r.enabled=1 AND r.expires>?1") != 0)
        return 0;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)now);
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_type(st, 0) != SQLITE_NULL)
        next = (int64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return next;
}

/*
 * Enabled rules already past their deadline. These are the rows the generated
 * ruleset should no longer contain, so a non-zero count means the live ruleset
 * is stale and a rebuild has real work to do.
 */
static int nc_expiry_lapsed_count(void)
{
    sqlite3_stmt *st = NULL;
    int lapsed = 0;

    if (nc_prepare(&st,
            "SELECT COUNT(*) FROM network_control_rule "
            "WHERE type IN " NC_EXPIRY_RULE_TYPES
            " AND enabled=1 AND expires>0 AND expires<=?1") != 0)
        return 0;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)nc_now_s());
    if (sqlite3_step(st) == SQLITE_ROW)
        lapsed = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return lapsed;
}

/* True while another apply holds the flock. Checked before rebuilding so the
 * timer backs off instead of racing a user write and reporting a failure that
 * is really just contention. */
static int nc_expiry_apply_busy(void)
{
    int fd = nc_netctl_apply_lock_open();

    if (fd < 0)
        return 1;
    close(fd);
    return 0;
}

/*
 * Lapsed rules of one type. Used to decide whether the rebuild has to touch tc:
 * terminal_limit lives in the tc plan, every other expiring type is nft only.
 */
static int nc_expiry_due_count_since(const char *type, int64_t since)
{
    sqlite3_stmt *st = NULL;
    int lapsed = 0;
    int64_t now = nc_now_s();

    if (since < 1)
        since = 1;
    if (!type || nc_prepare(&st,
            "SELECT COUNT(*) FROM network_control_rule "
            "WHERE type=?1 AND enabled=1 AND expires BETWEEN ?2 AND ?3") != 0)
        return 0;
    sqlite3_bind_text(st, 1, type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)since);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)now);
    if (sqlite3_step(st) == SQLITE_ROW)
        lapsed = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return lapsed;
}

static int nc_expiry_rebuild(int64_t due_since)
{
    struct json_object *req = json_object_new_object();
    struct json_object *resp;
    int ok = 0;
    /*
     * tc is re-run only when a rate limit actually lapsed. Rebuilding the tc
     * plan tears down and reinstalls every filter on the interface, so doing it
     * for an expiring MAC rule would disturb rate limits that did not change.
     * When a terminal_limit has lapsed the opposite is true: the filter has to
     * come off, and only the tc path can remove it.
     */
    int include_tc = nc_expiry_due_count_since("terminal_limit",
                                                due_since) > 0;

    json_object_object_add(req, "dry_run", json_object_new_boolean(0));
    json_object_object_add(req, "apply_nft", json_object_new_boolean(1));
    json_object_object_add(req, "apply_tc",
                           json_object_new_boolean(include_tc));
    resp = jmx_network_control_apply(req);
    if (resp) {
        struct json_object *data = NULL;
        struct json_object *applied = NULL;

        if (json_object_object_get_ex(resp, "data", &data) && data &&
            json_object_object_get_ex(data, "applied", &applied))
            ok = json_object_get_boolean(applied) ? 1 : 0;
        json_object_put(resp);
    }
    json_object_put(req);
    return ok ? 0 : -1;
}

static void nc_expiry_retry(int64_t due_since)
{
    nc_expiry_tm.cb = nc_expiry_cb;
    if (nc_expiry_armed)
        uloop_timeout_cancel(&nc_expiry_tm);
    nc_expiry_armed = 1;
    /* Preserve the original deadline. Historical rows before this boundary
     * must not turn a five-second retry into a full historical rebuild. */
    nc_expiry_armed_for = due_since > 0 ? due_since : 1;
    uloop_timeout_set(&nc_expiry_tm, NC_EXPIRY_RETRY_S * 1000);
}

static void nc_expiry_cb(struct uloop_timeout *t)
{
    int64_t due_since = nc_expiry_armed_for;

    (void)t;
    nc_expiry_armed = 0;
    nc_expiry_armed_for = 0;
    if (jmx_netconfig_db_init() != 0)
        return;
    nc_netctl_db_init();
    /*
     * Re-read rather than trusting the deadline this timer was armed for: the
     * row may have been deleted, disabled, or pushed further out while we slept.
     */
    if (due_since > nc_now_s()) {
        /*
         * Nothing has lapsed: either the sleep was clamped by
         * NC_EXPIRY_MAX_SLEEP_S and the real deadline is still ahead, or the row
         * moved out while we slept. Re-arm and do not rebuild -- an apply here
         * would be a no-op that still takes the lock.
         */
        nc_expiry_arm();
        return;
    }
    if (due_since <= 0 ||
        (!nc_expiry_due_count_since("mac", due_since) &&
         !nc_expiry_due_count_since("app", due_since) &&
         !nc_expiry_due_count_since("connection_limit", due_since) &&
         !nc_expiry_due_count_since("terminal_limit", due_since))) {
        /* The row was deleted, disabled, or moved while the timer slept. */
        nc_expiry_arm();
        return;
    }
    if (nc_expiry_apply_busy()) {
        /*
         * A user write is applying right now and will regenerate the ruleset
         * itself, which is exactly the rebuild this timer wanted. Come back
         * shortly anyway in case that apply started before the expiry moment
         * and therefore still rendered the lapsed rule.
         */
        nc_expiry_retry(due_since);
        return;
    }
    if (nc_expiry_rebuild(due_since) != 0) {
        fprintf(stderr,
                "[dreamingwrt-core] network control expiry rebuild failed; retrying\n");
        nc_expiry_retry(due_since);
        return;
    }
    fprintf(stderr,
            "[dreamingwrt-core] network control ruleset rebuilt for rule expiry\n");
    /* Chain to the next expiring rule, if any. */
    nc_expiry_arm();
}

/*
 * Idempotent: safe to call after every write. Re-arms only when the earliest
 * deadline actually moved, so a burst of unrelated rule edits does not cancel
 * and reinstall the same timeout repeatedly.
 */
static void nc_expiry_arm(void)
{
    int64_t deadline = nc_expiry_next_deadline();
    int64_t remain;

    if (deadline <= 0) {
        if (nc_expiry_armed) {
            uloop_timeout_cancel(&nc_expiry_tm);
            nc_expiry_armed = 0;
            nc_expiry_armed_for = 0;
        }
        return;
    }
    if (nc_expiry_armed && nc_expiry_armed_for == deadline)
        return;
    remain = deadline - nc_now_s() + NC_EXPIRY_LAG_S;
    if (remain < 1)
        remain = 1;
    if (remain > NC_EXPIRY_MAX_SLEEP_S)
        remain = NC_EXPIRY_MAX_SLEEP_S;
    nc_expiry_tm.cb = nc_expiry_cb;
    if (nc_expiry_armed)
        uloop_timeout_cancel(&nc_expiry_tm);
    nc_expiry_armed = 1;
    /*
     * When the sleep was clamped, armed_for keeps the real deadline so the
     * wakeup re-arms toward it instead of treating the clamp as the deadline.
     */
    nc_expiry_armed_for = deadline;
    uloop_timeout_set(&nc_expiry_tm, (int)(remain * 1000));
}

/*
 * Public entry points. jmx_network_control_expiry_sync() is called after any
 * network-control write so a freshly added or edited expires lands on the
 * timer, and once from startup so a rule that lapsed while jmxd was down is
 * cleared instead of waiting for the next write.
 */

/*
 * Called from jmx_network_control_apply() once a write has landed. Kept separate
 * from the public sync entry point so the apply path does not redo the db init
 * it has already done.
 */
static void nc_expiry_arm_after_apply(void)
{
    nc_expiry_arm();
}

void jmx_network_control_expiry_sync(void)
{
    if (jmx_netconfig_db_init() != 0)
        return;
    nc_netctl_db_init();
    nc_expiry_arm();
}

void jmx_network_control_expiry_boot_check(void)
{
    if (jmx_netconfig_db_init() != 0)
        return;
    nc_netctl_db_init();
    /*
     * The ruleset file survives a reboot but the kernel ruleset does not, and
     * either way a rule may have lapsed while jmxd was not running. Rebuild
     * once if anything is already past its deadline, then arm for the rest.
     */
    {
        int lapsed = nc_expiry_lapsed_count();

        if (lapsed > 0) {
            if (nc_expiry_apply_busy()) {
                /* A concurrent apply should clear the same rows, but retain a
                 * bounded retry so a pre-deadline build or transient lock
                 * holder cannot leave historical drops installed forever. */
                nc_expiry_retry(1);
                return;
            }
            if (nc_expiry_rebuild(1) == 0)
                fprintf(stderr,
                        "[dreamingwrt-core] network control ruleset rebuilt at boot: "
                        "%d expired rule(s)\n", lapsed);
            else {
                fprintf(stderr,
                        "[dreamingwrt-core] network control expiry rebuild failed at boot; retrying\n");
                nc_expiry_retry(1);
                return;
            }
        }
    }
    nc_expiry_arm();
}

/*
 * ── MAC allowlist mode: enable / confirm / rollback ──
 *
 * Enabling installs a deny-by-default rule, so the transition is staged rather
 * than final: the caller has confirm_timeout seconds to prove it can still
 * reach the router, and jmxd puts the previous state back if it does not. The
 * timer runs in jmxd's uloop, which is the process that owns this file.
 */
static struct uloop_timeout nc_macacl_rollback_tm;
static int nc_macacl_rollback_armed;
static int nc_macacl_bump_global_revision(void);
static int nc_macacl_runtime_commit(int64_t config_revision,
                                    const char *reason);
static int nc_macacl_restore_previous(const struct nc_macacl_state *previous,
                                      const char *remove_mac);
static int nc_macacl_reported_elements(void);
static void nc_macacl_rollback_arm(int64_t deadline);

static int nc_macacl_reapply(void)
{
    struct json_object *req = json_object_new_object();
    struct json_object *resp;
    int ok = 0;

    json_object_object_add(req, "dry_run", json_object_new_boolean(0));
    json_object_object_add(req, "apply_nft", json_object_new_boolean(1));
    /*
     * tc is left alone: the allowlist only changes the nft ruleset, and
     * re-running the tc plan would tear down and rebuild rate-limit filters that
     * have nothing to do with this transition.
     */
    json_object_object_add(req, "apply_tc", json_object_new_boolean(0));
    resp = jmx_network_control_apply(req);
    if (resp) {
        struct json_object *data = NULL, *applied = NULL;

        if (json_object_object_get_ex(resp, "data", &data) && data &&
            json_object_object_get_ex(data, "applied", &applied))
            ok = json_object_get_boolean(applied) ? 1 : 0;
        json_object_put(resp);
    }
    json_object_put(req);
    return ok ? 0 : -1;
}

static void nc_macacl_rollback_cb(struct uloop_timeout *t)
{
    struct nc_macacl_state state;
    struct nc_macacl_state previous;
    int runtime_current;

    (void)t;
    nc_macacl_rollback_armed = 0;
    if (jmx_netconfig_db_init() != 0)
        return;
    nc_netctl_db_init();
    if (nc_macacl_state_load(&state) != 0)
        return;
    runtime_current = state.runtime_applied &&
                      state.runtime_revision == state.config_revision;
    if (!state.enabled) {
        if (runtime_current)
            return;
        if (nc_macacl_reapply() == 0 &&
            nc_macacl_runtime_commit(state.config_revision,
                                     "blacklist_mode_runtime_verified") == 0)
            return;
        snprintf(state.runtime_reason, sizeof(state.runtime_reason),
                 "blacklist_runtime_reapply_failed_retrying");
        state.runtime_applied = 0;
        (void)nc_macacl_state_store(&state);
        nc_macacl_rollback_arm(nc_now_s() + 5);
        return;
    }
    if (state.confirmed) {
        if (runtime_current)
            return;
        if (nc_macacl_reapply() == 0 &&
            nc_macacl_runtime_commit(state.config_revision,
                                     "whitelist_runtime_reapplied_after_restart") == 0)
            return;
        snprintf(state.runtime_reason, sizeof(state.runtime_reason),
                 "whitelist_runtime_reapply_failed_retrying");
        state.runtime_applied = 0;
        (void)nc_macacl_state_store(&state);
        nc_macacl_rollback_arm(nc_now_s() + 5);
        return;
    }
    if (state.confirm_deadline > nc_now_s()) {
        if (!runtime_current &&
            (nc_macacl_reapply() != 0 ||
             nc_macacl_runtime_commit(state.config_revision,
                                      "pending_whitelist_runtime_reapplied") != 0)) {
            snprintf(state.runtime_reason, sizeof(state.runtime_reason),
                     "pending_whitelist_reapply_failed_retrying");
            state.runtime_applied = 0;
            (void)nc_macacl_state_store(&state);
            nc_macacl_rollback_arm(
                state.confirm_deadline < nc_now_s() + 5 ?
                state.confirm_deadline : nc_now_s() + 5);
            return;
        }
        nc_macacl_rollback_arm(state.confirm_deadline);
        return;
    }
    previous = state;
    state.enabled = 0;
    state.confirmed = 0;
    state.confirm_deadline = 0;
    state.config_revision++;
    state.runtime_applied = 0;
    snprintf(state.runtime_reason, sizeof(state.runtime_reason),
             "auto_rollback_runtime_pending");
    snprintf(state.last_reason, sizeof(state.last_reason),
             "auto_rollback_not_confirmed_before_deadline");
    if (nc_txn_begin() != 0 || nc_macacl_state_store(&state) != 0 ||
        nc_macacl_bump_global_revision() != 0 || nc_txn_end(0) != 0) {
        (void)nc_txn_end(-1);
        fprintf(stderr,
                "[dreamingwrt-core] mac allowlist auto-rollback could not persist state\n");
        nc_macacl_rollback_arm(nc_now_s() + 5);
        return;
    }
    if (nc_macacl_reapply() != 0) {
        snprintf(previous.last_reason, sizeof(previous.last_reason),
                 "auto_rollback_apply_failed_retrying");
        (void)nc_macacl_restore_previous(&previous, NULL);
        fprintf(stderr,
                "[dreamingwrt-core] mac allowlist auto-rollback reapply failed\n");
        nc_macacl_rollback_arm(nc_now_s() + 5);
        return;
    }
    if (nc_macacl_runtime_commit(state.config_revision,
                                 "auto_rollback_applied_and_verified") != 0) {
        nc_macacl_rollback_arm(nc_now_s() + 5);
        return;
    }
    fprintf(stderr, "[dreamingwrt-core] mac allowlist auto-rolled back (unconfirmed)\n");
}

static void nc_macacl_rollback_arm(int64_t deadline)
{
    int64_t remain = deadline - nc_now_s();

    if (remain < 1)
        remain = 1;
    nc_macacl_rollback_tm.cb = nc_macacl_rollback_cb;
    if (nc_macacl_rollback_armed)
        uloop_timeout_cancel(&nc_macacl_rollback_tm);
    nc_macacl_rollback_armed = 1;
    uloop_timeout_set(&nc_macacl_rollback_tm, (int)(remain * 1000));
}

static void nc_macacl_rollback_disarm(void)
{
    if (nc_macacl_rollback_armed) {
        uloop_timeout_cancel(&nc_macacl_rollback_tm);
        nc_macacl_rollback_armed = 0;
    }
}

static void nc_macacl_add_state(struct json_object *data,
                                const struct nc_macacl_state *state,
                                int elements)
{
    struct json_object *o = json_object_new_object();
    char lan[32] = "";
    const char *mode = state->enabled ? "whitelist" : "blacklist";
    int runtime_current = state->runtime_applied &&
                          state->runtime_revision == state->config_revision;

    json_object_object_add(o, "enabled", json_object_new_boolean(state->enabled));
    json_object_object_add(o, "mode", json_object_new_string(mode));
    json_object_object_add(o, "confirmed", json_object_new_boolean(state->confirmed));
    json_object_object_add(o, "confirm_deadline",
                           json_object_new_int64(state->confirm_deadline));
    json_object_object_add(o, "confirm_seconds_remaining",
                           json_object_new_int(state->enabled && !state->confirmed &&
                                               state->confirm_deadline > nc_now_s() ?
                                               (int)(state->confirm_deadline - nc_now_s()) : 0));
    json_object_object_add(o, "element_count", json_object_new_int(elements));
    json_object_object_add(o, "rule_count", json_object_new_int(elements));
    json_object_object_add(o, "config_revision",
                           json_object_new_int64(state->config_revision));
    json_object_object_add(o, "runtime_revision",
                           json_object_new_int64(state->runtime_revision));
    json_object_object_add(o, "runtime_applied",
                           json_object_new_boolean(runtime_current));
    json_object_object_add(o, "runtime_reason",
                           json_object_new_string(state->runtime_reason));
    json_object_object_add(o, "runtime_mode",
                           json_object_new_string(runtime_current ? mode : "unknown"));
    json_object_object_add(o, "admin_mac",
                           json_object_new_string(state->admin_mac));
    json_object_object_add(o, "admin_mac_source",
                           json_object_new_string(state->admin_mac_source));
    json_object_object_add(o, "admin_origin_field",
                           json_object_new_string("peer_ip"));
    json_object_object_add(o, "last_reason",
                           json_object_new_string(state->last_reason));
    json_object_object_add(o, "enabled_at",
                           json_object_new_int64(state->enabled_at));
    json_object_object_add(o, "implementation",
                           json_object_new_string("ether_saddr_not_in_set_drop"));
    json_object_object_add(o, "enforcement_hook",
                           json_object_new_string("forward_lan_ingress_only"));
    if (nc_tc_lan_ifname(lan, sizeof(lan)) == 0)
        json_object_object_add(o, "enforcement_iifname",
                               json_object_new_string(lan));
    json_object_object_add(data, "mode", json_object_new_string(mode));
    json_object_object_add(data, "enabled", json_object_new_boolean(state->enabled));
    json_object_object_add(data, "rule_count", json_object_new_int(elements));
    json_object_object_add(data, "config_revision",
                           json_object_new_int64(state->config_revision));
    json_object_object_add(data, "runtime_revision",
                           json_object_new_int64(state->runtime_revision));
    json_object_object_add(data, "runtime_applied",
                           json_object_new_boolean(runtime_current));
    json_object_object_add(data, "runtime_reason",
                           json_object_new_string(state->runtime_reason));
    json_object_object_add(data, "mac_allowlist", o);
}

static int nc_macacl_request_revision(struct json_object *cfg,
                                      int64_t *revision_out)
{
    struct json_object *value = NULL;
    int64_t revision;

    if (!revision_out || !cfg ||
        !json_object_object_get_ex(cfg, "config_revision", &value) || !value ||
        !json_object_is_type(value, json_type_int) ||
        (revision = (int64_t)json_object_get_int64(value)) < 1)
        return -1;
    *revision_out = revision;
    return 0;
}

static int nc_macacl_bump_global_revision(void)
{
    return nc_exec("UPDATE network_control_global SET revision=revision+1,"
                   "apply_state='draft',updated_at=strftime('%s','now') WHERE id=1");
}

static int nc_macacl_runtime_mark(int64_t config_revision, int applied,
                                  const char *reason)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (nc_prepare(&st,
        "UPDATE network_control_mac_allowlist SET runtime_revision=?1,"
        "runtime_applied=?2,runtime_reason=?3,updated_at=?4 "
        "WHERE id=1 AND config_revision=?1") != 0)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)config_revision);
    sqlite3_bind_int(st, 2, applied ? 1 : 0);
    sqlite3_bind_text(st, 3, reason ? reason : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)nc_now_s());
    if (nc_step_done(st) == 0 && nc_sqlite_changes() == 1)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

static int nc_macacl_runtime_commit(int64_t config_revision,
                                    const char *reason)
{
    if (nc_txn_begin() != 0)
        return -1;
    if (nc_macacl_runtime_mark(config_revision, 1, reason) != 0)
        return nc_txn_end(-1);
    return nc_txn_end(0);
}

static int nc_macacl_restore_previous(const struct nc_macacl_state *previous,
                                      const char *remove_mac)
{
    struct nc_macacl_state restore;

    if (!previous || nc_txn_begin() != 0)
        return -1;
    restore = *previous;
    restore.runtime_applied = 0;
    snprintf(restore.runtime_reason, sizeof(restore.runtime_reason),
             "runtime_restore_pending");
    if ((remove_mac && remove_mac[0] &&
         nc_macacl_whitelist_remove(remove_mac) != 0) ||
        nc_macacl_state_store(&restore) != 0)
        return nc_txn_end(-1);
    return nc_txn_end(0);
}

static struct json_object *nc_macacl_transition_error(
    const char *message, const struct nc_macacl_state *previous,
    const char *remove_mac)
{
    struct json_object *data = json_object_new_object();
    struct nc_macacl_state readback;
    int config_restored = nc_macacl_restore_previous(previous, remove_mac) == 0;
    int runtime_restored = config_restored && nc_macacl_reapply() == 0 &&
                           nc_macacl_runtime_commit(
                               previous->config_revision,
                               "previous_runtime_restored_and_verified") == 0;
    const char *code = runtime_restored ? "runtime_apply_failed" :
                                          "runtime_rollback_failed";

    memset(&readback, 0, sizeof(readback));
    if (config_restored && nc_macacl_state_load(&readback) != 0)
        readback = *previous;
    else if (!config_restored && previous)
        readback = *previous;
    if (runtime_restored && previous->enabled && !previous->confirmed &&
        previous->confirm_deadline > nc_now_s())
        nc_macacl_rollback_arm(previous->confirm_deadline);
    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error", json_object_new_string(code));
    json_object_object_add(data, "message", json_object_new_string(message));
    json_object_object_add(data, "rolled_back",
                           json_object_new_boolean(runtime_restored));
    json_object_object_add(data, "config_restored",
                           json_object_new_boolean(config_restored));
    json_object_object_add(data, "runtime_restored",
                           json_object_new_boolean(runtime_restored));
    nc_macacl_add_state(data, &readback, nc_macacl_reported_elements());
    return jmx_gen_api_response_data(API_CODE_ERROR, data);
}

static int nc_macacl_requested_enabled(struct json_object *cfg,
                                       int *enabled_out)
{
    struct json_object *enabled = NULL;
    struct json_object *mode_obj = NULL;
    const char *mode = NULL;
    int from_enabled = -1;
    int from_mode = -1;

    if (!cfg || !enabled_out)
        return -1;
    if (json_object_object_get_ex(cfg, "enabled", &enabled) && enabled) {
        if (!json_object_is_type(enabled, json_type_boolean))
            return -1;
        from_enabled = json_object_get_boolean(enabled) ? 1 : 0;
    }
    if (json_object_object_get_ex(cfg, "mode", &mode_obj) && mode_obj) {
        if (!json_object_is_type(mode_obj, json_type_string))
            return -1;
        mode = json_object_get_string(mode_obj);
        if (!strcmp(mode, "whitelist"))
            from_mode = 1;
        else if (!strcmp(mode, "blacklist"))
            from_mode = 0;
        else
            return -1;
    }
    if (from_enabled < 0 && from_mode < 0)
        return -1;
    if (from_enabled >= 0 && from_mode >= 0 && from_enabled != from_mode)
        return -1;
    *enabled_out = from_mode >= 0 ? from_mode : from_enabled;
    return 0;
}

/* element_count as reported to callers: a malformed list reads as 0, not -1. */
static int nc_macacl_reported_elements(void)
{
    int count = nc_macacl_element_count();

    return count < 0 ? 0 : count;
}

static struct json_object *nc_macacl_members_array(void)
{
    struct json_object *members = json_object_new_array();
    sqlite3_stmt *st = NULL;

    if (nc_prepare(&st,
        "SELECT mac FROM network_control_whitelist WHERE kind='mac' ORDER BY mac") != 0)
        return members;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *raw = (const char *)sqlite3_column_text(st, 0);
        char norm[32];

        nc_netctl_mac_norm(raw, norm, sizeof(norm));
        if (nc_netctl_mac_ok(norm))
            json_object_array_add(members, json_object_new_string(norm));
    }
    sqlite3_finalize(st);
    return members;
}

static struct json_object *nc_macacl_error(const char *code, const char *message,
                                           const struct nc_macacl_state *state)
{
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error", json_object_new_string(code));
    json_object_object_add(data, "message", json_object_new_string(message));
    if (state)
        nc_macacl_add_state(data, state, nc_macacl_reported_elements());
    return jmx_gen_api_response_data(API_CODE_ERROR, data);
}

struct json_object *jmx_network_control_mac_allowlist_members_set(struct json_object *cfg)
{
    struct nc_macacl_state state;
    struct json_object *members = NULL;
    struct json_object *data;
    int64_t expected_revision;
    int count;

    if (jmx_netconfig_db_init() != 0)
        return nc_macacl_error("database_unavailable",
                               "config database is not available", NULL);
    nc_netctl_db_init();
    if (nc_macacl_state_load(&state) != 0)
        return nc_macacl_error("state_unavailable",
                               "mac allowlist state row is missing", NULL);
    if (nc_macacl_request_revision(cfg, &expected_revision) != 0)
        return nc_macacl_error("config_revision_required",
                               "config_revision from the latest allowlist GET is required",
                               &state);
    if (expected_revision != state.config_revision)
        return nc_macacl_error("revision_conflict",
                               "mac allowlist config_revision is stale", &state);
    if (state.enabled)
        return nc_macacl_error("allowlist_enabled",
                               "disable mac allowlist mode before editing members",
                               &state);
    if (!cfg || !json_object_object_get_ex(cfg, "members", &members) ||
        !members || !json_object_is_type(members, json_type_array))
        return nc_macacl_error("invalid_parameter",
                               "members must be an array of MAC addresses", &state);
    count = json_object_array_length(members);
    if (count > NC_NETCTL_MACACL_MAX_ELEMENTS)
        return nc_macacl_error("member_limit_reached",
                               "mac allowlist has too many members", &state);
    if (nc_txn_begin() != 0)
        return nc_macacl_error("database_busy",
                               "could not start mac allowlist transaction", &state);
    if (nc_macacl_state_load(&state) != 0) {
        (void)nc_txn_end(-1);
        return nc_macacl_error("state_unavailable",
                               "mac allowlist state row is missing", NULL);
    }
    if (expected_revision != state.config_revision) {
        (void)nc_txn_end(-1);
        return nc_macacl_error("revision_conflict",
                               "mac allowlist config_revision is stale", &state);
    }
    if (nc_rulesd_replace_whitelist(members, "mac") != 0) {
        (void)nc_txn_end(-1);
        return nc_macacl_error("invalid_members",
                               "mac allowlist members could not be saved", &state);
    }
    state.config_revision++;
    state.runtime_revision = state.config_revision;
    state.runtime_applied = 1;
    snprintf(state.runtime_reason, sizeof(state.runtime_reason),
             "blacklist_mode_members_saved_no_runtime_change");
    snprintf(state.last_reason, sizeof(state.last_reason),
             "members_replaced");
    if (nc_macacl_state_store(&state) != 0 ||
        nc_macacl_bump_global_revision() != 0) {
        (void)nc_txn_end(-1);
        return nc_macacl_error("state_write_failed",
                               "mac allowlist transaction could not be saved", &state);
    }
    if (nc_txn_end(0) != 0)
        return nc_macacl_error("state_write_failed",
                               "mac allowlist transaction could not be committed", &state);
    count = nc_macacl_reported_elements();
    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "saved", json_object_new_boolean(1));
    json_object_object_add(data, "members", nc_macacl_members_array());
    nc_macacl_add_state(data, &state, count);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/*
 * network_control_mac_allowlist_set
 *
 * cfg:
 *   mode             "blacklist" or "whitelist"; enabled remains compatible
 *   config_revision  latest revision returned by GET, required
 *   confirm_timeout  seconds, 30..900, default 180 (enable only)
 *   admin_mac        MAC of the session issuing the change, resolved by webd
 *                    from request_origin.peer_ip
 *   admin_ip         peer_ip, recorded for audit only
 */
struct json_object *jmx_network_control_mac_allowlist_set(struct json_object *cfg)
{
    struct nc_macacl_state state;
    struct nc_macacl_state previous;
    struct json_object *data;
    int64_t expected_revision;
    int want_enabled;
    int timeout;
    int elements;
    int admin_added = 0;
    const char *admin_mac;
    const char *admin_ip;
    char norm[32] = "";

    if (jmx_netconfig_db_init() != 0)
        return nc_macacl_error("database_unavailable",
                               "config database is not available", NULL);
    nc_netctl_db_init();
    if (nc_macacl_state_load(&state) != 0)
        return nc_macacl_error("state_unavailable",
                               "mac allowlist state row is missing", NULL);
    previous = state;
    if (nc_macacl_request_revision(cfg, &expected_revision) != 0)
        return nc_macacl_error("config_revision_required",
                               "config_revision from the latest allowlist GET is required",
                               &state);
    if (expected_revision != state.config_revision)
        return nc_macacl_error("revision_conflict",
                               "mac allowlist config_revision is stale", &state);
    if (nc_macacl_requested_enabled(cfg, &want_enabled) != 0)
        return nc_macacl_error("invalid_parameter",
                               "mode must be blacklist or whitelist", &state);
    timeout = nc_json_int_def(cfg, "confirm_timeout",
                              NC_NETCTL_MACACL_CONFIRM_DEFAULT_S);
    if (want_enabled && (timeout < NC_NETCTL_MACACL_CONFIRM_MIN_S ||
                         timeout > NC_NETCTL_MACACL_CONFIRM_MAX_S))
        return nc_macacl_error("invalid_parameter",
                               "confirm_timeout must be between 30 and 900 seconds",
                               &state);
    admin_mac = nc_json_str_def(cfg, "admin_mac", "");
    admin_ip = nc_json_str_def(cfg, "admin_ip", "");

    /*
     * The admin origin is required, not best-effort. Without it an operator on a
     * device that is not on the list loses the session that is making the change
     * and can only recover by waiting for the rollback. webd resolves it from
     * peer_ip; if that lookup failed there is nothing safe to substitute, so the
     * enable is refused and says why.
     */
    nc_netctl_mac_norm(admin_mac, norm, sizeof(norm));
    if (want_enabled && !nc_netctl_mac_ok(norm))
        return nc_macacl_error("admin_origin_required",
                               "admin_mac (resolved from request_origin.peer_ip) is "
                               "required to enable allowlist mode; enabling without it "
                               "can lock the operator out", &state);
    /*
     * Emptiness is judged before the admin row is added. Otherwise an enable on
     * an empty list would quietly become "allow only the operator's laptop",
     * which drops the whole LAN and looks like the feature working.
     */
    elements = nc_macacl_stored_count();
    if (want_enabled && elements < 0)
        return nc_macacl_error("state_unavailable",
                               "could not read the mac whitelist", &previous);
    if (want_enabled && elements == 0)
        return nc_macacl_error("whitelist_empty",
                               "mac allowlist mode needs at least one whitelisted "
                               "device; add entries before enabling it", &previous);
    if (nc_txn_begin() != 0)
        return nc_macacl_error("database_busy",
                               "could not start mac allowlist transaction", &state);
    if (nc_macacl_state_load(&state) != 0) {
        (void)nc_txn_end(-1);
        return nc_macacl_error("state_unavailable",
                               "mac allowlist state row is missing", NULL);
    }
    previous = state;
    if (expected_revision != state.config_revision) {
        (void)nc_txn_end(-1);
        return nc_macacl_error("revision_conflict",
                               "mac allowlist config_revision is stale", &state);
    }
    if (want_enabled) {
        snprintf(state.admin_mac, sizeof(state.admin_mac), "%s", norm);
        snprintf(state.admin_ip, sizeof(state.admin_ip), "%s", admin_ip);
        snprintf(state.admin_mac_source, sizeof(state.admin_mac_source),
                 "%s", nc_json_str_def(cfg, "admin_mac_source",
                                        "webd_request_origin_peer_ip"));
        admin_added = nc_macacl_whitelist_ensure(norm);
        if (admin_added < 0) {
            (void)nc_txn_end(-1);
            return nc_macacl_error("admin_origin_write_failed",
                                   "could not add the administrating device to the mac "
                                   "whitelist", &previous);
        }
        state.enabled = 1;
        state.confirmed = 0;
        state.confirm_deadline = nc_now_s() + timeout;
        state.enabled_at = nc_now_s();
        snprintf(state.last_reason, sizeof(state.last_reason),
                 "enabled_pending_confirmation");
    } else {
        state.enabled = 0;
        state.confirmed = 0;
        state.confirm_deadline = 0;
        snprintf(state.last_reason, sizeof(state.last_reason),
                 "disabled_by_request");
    }
    state.config_revision++;
    state.runtime_applied = 0;
    snprintf(state.runtime_reason, sizeof(state.runtime_reason),
             "runtime_apply_pending");
    if (nc_macacl_state_store(&state) != 0 ||
        nc_macacl_bump_global_revision() != 0) {
        (void)nc_txn_end(-1);
        return nc_macacl_error("state_write_failed",
                               "could not persist mac allowlist transition", &previous);
    }
    if (nc_txn_end(0) != 0) {
        (void)nc_txn_end(-1);
        return nc_macacl_error("state_write_failed",
                               "could not commit mac allowlist transition", &previous);
    }
    elements = nc_macacl_element_count();
    if (elements < 0)
        return nc_macacl_transition_error(
            "mac whitelist contains an unusable entry; the previous state was restored",
            &previous, admin_added > 0 ? norm : NULL);
