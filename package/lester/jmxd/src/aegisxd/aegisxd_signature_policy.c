// SPDX-License-Identifier: GPL-2.0-or-later
#include "aegisxd_internal.h"

#include <limits.h>

#define AEGISXD_SIGNATURE_POLICY_TABLE "aegis_signature_policy_overrides"

struct aegisxd_signature_rule {
    int gid;
    int sid;
    int rev;
    int severity;
    int enabled_default;
    char category[128];
    char classtype[128];
    char action[32];
    char protocol[32];
    char msg[512];
    char source_feed[128];
    int64_t updated_at;
};

struct aegisxd_signature_override {
    int exists;
    int gid;
    int sid;
    int target_rev;
    int enabled_override;
    char action[32];
    int suppressed;
    char reason[512];
    int revision;
    char apply_state[32];
    char last_error[128];
    int64_t created_at;
    int64_t updated_at;
};

static int aegisxd_signature_json_positive_int(struct json_object *body,
                                               const char *key, int *out)
{
    struct json_object *v = NULL;
    int64_t n;
    const char *s;
    char *end = NULL;

    if (!body || !key || !out || !json_object_object_get_ex(body, key, &v) || !v)
        return 0;
    if (json_object_is_type(v, json_type_int)) {
        n = json_object_get_int64(v);
    } else if (json_object_is_type(v, json_type_string)) {
        s = json_object_get_string(v);
        if (!s || !s[0])
            return -1;
        for (const char *p = s; *p; p++) {
            if (!isdigit((unsigned char)*p))
                return -1;
        }
        errno = 0;
        n = strtoll(s, &end, 10);
        if (errno || !end || *end)
            return -1;
    } else {
        return -1;
    }
    if (n <= 0 || n > INT_MAX)
        return -1;
    *out = (int)n;
    return 1;
}

static int aegisxd_signature_json_int(struct json_object *body, const char *key,
                                      int *out)
{
    struct json_object *v = NULL;
    int64_t n;
    const char *s;
    char *end = NULL;

    if (!body || !key || !out || !json_object_object_get_ex(body, key, &v) || !v)
        return 0;
    if (json_object_is_type(v, json_type_int)) {
        n = json_object_get_int64(v);
    } else if (json_object_is_type(v, json_type_string)) {
        s = json_object_get_string(v);
        if (!s || !s[0])
            return -1;
        errno = 0;
        n = strtoll(s, &end, 10);
        if (errno || !end || *end)
            return -1;
    } else {
        return -1;
    }
    if (n < INT_MIN || n > INT_MAX)
        return -1;
    *out = (int)n;
    return 1;
}

static int aegisxd_signature_json_gid_sid(struct json_object *body,
                                          int *gid_out, int *sid_out)
{
    int gid = 1;
    int sid = 0;
    int rc;

    rc = aegisxd_signature_json_positive_int(body, "gid", &gid);
    if (rc < 0)
        return -1;
    rc = aegisxd_signature_json_positive_int(body, "sid", &sid);
    if (rc == 0)
        rc = aegisxd_signature_json_positive_int(body, "signature_id", &sid);
    if (rc <= 0)
        return -1;
    if (gid != 1)
        return -1;
    if (gid_out)
        *gid_out = gid;
    if (sid_out)
        *sid_out = sid;
    return 0;
}

static int aegisxd_signature_action_ok(const char *action)
{
    return action && (!strcmp(action, "inherit") || !strcmp(action, "alert") ||
                      !strcmp(action, "drop") || !strcmp(action, "reject") ||
                      !strcmp(action, "pass"));
}

static int aegisxd_signature_rule_load(int sid, struct aegisxd_signature_rule *rule)
{
    sqlite3_stmt *st;
    int rc = -1;

    if (!rule || sid <= 0)
        return -1;
    memset(rule, 0, sizeof(*rule));
    rule->gid = 1;
    st = aegisxd_prepare(
        "SELECT sid,rev,category,classtype,severity,action,protocol,msg,"
        "enabled_default,source_feed,updated_at FROM aegis_suricata_rules WHERE sid=?1");
    if (!st)
        return -1;
    sqlite3_bind_int(st, 1, sid);
    if (sqlite3_step(st) == SQLITE_ROW) {
        rule->sid = sqlite3_column_int(st, 0);
        rule->rev = sqlite3_column_int(st, 1);
        snprintf(rule->category, sizeof(rule->category), "%s", aegisxd_sqlite_text(st, 2, ""));
        snprintf(rule->classtype, sizeof(rule->classtype), "%s", aegisxd_sqlite_text(st, 3, ""));
        rule->severity = sqlite3_column_int(st, 4);
        snprintf(rule->action, sizeof(rule->action), "%s", aegisxd_sqlite_text(st, 5, "alert"));
        snprintf(rule->protocol, sizeof(rule->protocol), "%s", aegisxd_sqlite_text(st, 6, ""));
        snprintf(rule->msg, sizeof(rule->msg), "%s", aegisxd_sqlite_text(st, 7, ""));
        rule->enabled_default = sqlite3_column_int(st, 8) ? 1 : 0;
        snprintf(rule->source_feed, sizeof(rule->source_feed), "%s", aegisxd_sqlite_text(st, 9, ""));
        rule->updated_at = sqlite3_column_int64(st, 10);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static int aegisxd_signature_override_load(int gid, int sid,
                                           struct aegisxd_signature_override *ov)
{
    sqlite3_stmt *st;
    int rc = -1;

    if (!ov || gid <= 0 || sid <= 0)
        return -1;
    memset(ov, 0, sizeof(*ov));
    ov->gid = gid;
    ov->sid = sid;
    ov->enabled_override = -1;
    snprintf(ov->action, sizeof(ov->action), "%s", "inherit");
    snprintf(ov->apply_state, sizeof(ov->apply_state), "%s", "inherited");
    st = aegisxd_config_prepare(
        "SELECT gid,sid,target_rev,enabled_override,action,suppressed,reason,"
        "revision,apply_state,last_error,created_at,updated_at "
        "FROM " AEGISXD_SIGNATURE_POLICY_TABLE " WHERE gid=?1 AND sid=?2");
    if (!st)
        return -1;
    sqlite3_bind_int(st, 1, gid);
    sqlite3_bind_int(st, 2, sid);
    if (sqlite3_step(st) == SQLITE_ROW) {
        ov->exists = 1;
        ov->gid = sqlite3_column_int(st, 0);
        ov->sid = sqlite3_column_int(st, 1);
        ov->target_rev = sqlite3_column_int(st, 2);
        ov->enabled_override = sqlite3_column_int(st, 3);
        snprintf(ov->action, sizeof(ov->action), "%s", aegisxd_sqlite_text(st, 4, "inherit"));
        ov->suppressed = sqlite3_column_int(st, 5) ? 1 : 0;
        snprintf(ov->reason, sizeof(ov->reason), "%s", aegisxd_sqlite_text(st, 6, ""));
        ov->revision = sqlite3_column_int(st, 7);
        snprintf(ov->apply_state, sizeof(ov->apply_state), "%s", aegisxd_sqlite_text(st, 8, "apply_required"));
        snprintf(ov->last_error, sizeof(ov->last_error), "%s", aegisxd_sqlite_text(st, 9, ""));
        ov->created_at = sqlite3_column_int64(st, 10);
        ov->updated_at = sqlite3_column_int64(st, 11);
    }
    rc = 0;
    sqlite3_finalize(st);
    return rc;
}

static struct json_object *aegisxd_signature_policy_error(const char *code,
                                                          const char *message,
                                                          int gid, int sid)
{
    struct json_object *o = aegisxd_error(code, message);

    aegisxd_json_add_string(o, "operation", "signature_policy");
    json_object_object_add(o, "gid", json_object_new_int(gid > 0 ? gid : 1));
    json_object_object_add(o, "sid", json_object_new_int(sid > 0 ? sid : 0));
    json_object_object_add(o, "changed", json_object_new_boolean(0));
    json_object_object_add(o, "dataplane_changed", json_object_new_boolean(0));
    return o;
}

static struct json_object *aegisxd_signature_override_json(
    const struct aegisxd_signature_override *ov)
{
    struct json_object *o = json_object_new_object();

    if (!ov || !ov->exists) {
        json_object_object_add(o, "exists", json_object_new_boolean(0));
        json_object_object_add(o, "revision", json_object_new_int(0));
        json_object_object_add(o, "enabled_override", json_object_new_int(-1));
        aegisxd_json_add_string(o, "action", "inherit");
        json_object_object_add(o, "suppressed", json_object_new_boolean(0));
        aegisxd_json_add_string(o, "reason", "");
        aegisxd_json_add_string(o, "apply_state", "inherited");
        return o;
    }
    json_object_object_add(o, "exists", json_object_new_boolean(1));
    json_object_object_add(o, "gid", json_object_new_int(ov->gid));
    json_object_object_add(o, "sid", json_object_new_int(ov->sid));
    json_object_object_add(o, "target_rev", json_object_new_int(ov->target_rev));
    json_object_object_add(o, "enabled_override", json_object_new_int(ov->enabled_override));
    aegisxd_json_add_string(o, "action", ov->action);
    json_object_object_add(o, "suppressed", json_object_new_boolean(ov->suppressed));
    aegisxd_json_add_string(o, "reason", ov->reason);
    json_object_object_add(o, "revision", json_object_new_int(ov->revision));
    aegisxd_json_add_string(o, "apply_state", ov->apply_state);
    aegisxd_json_add_string(o, "last_error", ov->last_error);
    json_object_object_add(o, "created_at", json_object_new_int64(ov->created_at));
    json_object_object_add(o, "updated_at", json_object_new_int64(ov->updated_at));
    return o;
}

static struct json_object *aegisxd_signature_policy_item_json(
    const struct aegisxd_signature_rule *rule,
    const struct aegisxd_signature_override *ov)
{
    struct json_object *o = json_object_new_object();
    int stale = ov && ov->exists && ov->target_rev != rule->rev;
    int effective_enabled = rule->enabled_default;
    const char *effective_action = rule->action[0] ? rule->action : "alert";

    if (ov && ov->exists) {
        if (ov->suppressed)
            effective_enabled = 0;
        else if (ov->enabled_override >= 0)
            effective_enabled = ov->enabled_override ? 1 : 0;
        if (strcmp(ov->action, "inherit"))
            effective_action = ov->action;
    }
    json_object_object_add(o, "gid", json_object_new_int(rule->gid));
    json_object_object_add(o, "sid", json_object_new_int(rule->sid));
    json_object_object_add(o, "signature_id", json_object_new_int(rule->sid));
    json_object_object_add(o, "rev", json_object_new_int(rule->rev));
    aegisxd_json_add_string(o, "category", rule->category);
    aegisxd_json_add_string(o, "classtype", rule->classtype);
    json_object_object_add(o, "severity", json_object_new_int(rule->severity));
    aegisxd_json_add_string(o, "default_action", rule->action[0] ? rule->action : "alert");
    aegisxd_json_add_string(o, "protocol", rule->protocol);
    aegisxd_json_add_string(o, "msg", rule->msg);
    json_object_object_add(o, "enabled_default", json_object_new_boolean(rule->enabled_default));
    aegisxd_json_add_string(o, "source_feed", rule->source_feed);
    json_object_object_add(o, "updated_at", json_object_new_int64(rule->updated_at));
    json_object_object_add(o, "override", aegisxd_signature_override_json(ov));
    json_object_object_add(o, "effective_enabled", json_object_new_boolean(effective_enabled));
    aegisxd_json_add_string(o, "effective_action", effective_action);
    json_object_object_add(o, "stale", json_object_new_boolean(stale));
    if (stale)
        aegisxd_json_add_string(o, "stale_reason", "signature_revision_mismatch");
    return o;
}

static int aegisxd_signature_policy_total(int sid)
{
    sqlite3_stmt *st;
    int n = 0;

    if (sid > 0)
        st = aegisxd_prepare("SELECT COUNT(*) FROM aegis_suricata_rules WHERE sid=?1");
    else
        st = aegisxd_prepare("SELECT COUNT(*) FROM aegis_suricata_rules");
    if (!st)
        return 0;
    if (sid > 0)
        sqlite3_bind_int(st, 1, sid);
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

struct json_object *aegisxd_signature_policies_json(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *items = json_object_new_array();
    sqlite3_stmt *st;
    int gid = 1;
    int sid = 0;
    int limit = 100;
    int offset = 0;
    int rc;
    const char *sql;

    rc = aegisxd_signature_json_positive_int(body, "gid", &gid);
    if (rc < 0 || gid != 1)
        goto invalid;
    rc = aegisxd_signature_json_positive_int(body, "sid", &sid);
    if (rc == 0)
        rc = aegisxd_signature_json_positive_int(body, "signature_id", &sid);
    if (rc < 0)
        goto invalid;
    rc = aegisxd_signature_json_positive_int(body, "limit", &limit);
    if (rc < 0)
        goto invalid;
    rc = aegisxd_signature_json_int(body, "offset", &offset);
    if (rc < 0 || offset < 0)
        goto invalid;
    if (limit <= 0)
        limit = 100;
    if (limit > 500)
        limit = 500;

    sql = sid > 0 ?
        "SELECT sid,rev,category,classtype,severity,action,protocol,msg,"
        "enabled_default,source_feed,updated_at FROM aegis_suricata_rules "
        "WHERE sid=?1 ORDER BY sid LIMIT ?2 OFFSET ?3" :
        "SELECT sid,rev,category,classtype,severity,action,protocol,msg,"
        "enabled_default,source_feed,updated_at FROM aegis_suricata_rules "
        "ORDER BY sid LIMIT ?1 OFFSET ?2";
    st = aegisxd_prepare(sql);
    if (!st) {
        json_object_put(items);
        return aegisxd_signature_policy_error("signature_policy_save_failed",
            "signature policy storage unavailable", gid, sid);
    }
    if (sid > 0) {
        sqlite3_bind_int(st, 1, sid);
        sqlite3_bind_int(st, 2, limit);
        sqlite3_bind_int(st, 3, offset);
    } else {
        sqlite3_bind_int(st, 1, limit);
        sqlite3_bind_int(st, 2, offset);
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct aegisxd_signature_rule rule;
        struct aegisxd_signature_override ov;

        memset(&rule, 0, sizeof(rule));
        rule.gid = gid;
        rule.sid = sqlite3_column_int(st, 0);
        rule.rev = sqlite3_column_int(st, 1);
        snprintf(rule.category, sizeof(rule.category), "%s", aegisxd_sqlite_text(st, 2, ""));
        snprintf(rule.classtype, sizeof(rule.classtype), "%s", aegisxd_sqlite_text(st, 3, ""));
        rule.severity = sqlite3_column_int(st, 4);
        snprintf(rule.action, sizeof(rule.action), "%s", aegisxd_sqlite_text(st, 5, "alert"));
        snprintf(rule.protocol, sizeof(rule.protocol), "%s", aegisxd_sqlite_text(st, 6, ""));
        snprintf(rule.msg, sizeof(rule.msg), "%s", aegisxd_sqlite_text(st, 7, ""));
        rule.enabled_default = sqlite3_column_int(st, 8) ? 1 : 0;
        snprintf(rule.source_feed, sizeof(rule.source_feed), "%s", aegisxd_sqlite_text(st, 9, ""));
        rule.updated_at = sqlite3_column_int64(st, 10);
        if (aegisxd_signature_override_load(gid, rule.sid, &ov) != 0)
            memset(&ov, 0, sizeof(ov));
        json_object_array_add(items, aegisxd_signature_policy_item_json(&rule, &ov));
    }
    sqlite3_finalize(st);

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    aegisxd_json_add_string(resp, "operation", "signature_policies");
    json_object_object_add(resp, "gid", json_object_new_int(gid));
    if (sid > 0)
        json_object_object_add(resp, "sid", json_object_new_int(sid));
    json_object_object_add(resp, "items", items);
    json_object_object_add(resp, "total", json_object_new_int(aegisxd_signature_policy_total(sid)));
    json_object_object_add(resp, "limit", json_object_new_int(limit));
    json_object_object_add(resp, "offset", json_object_new_int(offset));
    json_object_object_add(resp, "counts", aegisxd_signature_policy_counts_json());
    return resp;
invalid:
    json_object_put(items);
    return aegisxd_signature_policy_error("invalid_signature_id",
        "gid, sid, limit and offset must be valid integers", gid, sid);
}

static struct json_object *aegisxd_signature_policy_write(struct json_object *body,
                                                          int forced_suppressed,
                                                          int force_suppressed)
{
    struct aegisxd_signature_rule rule;
    struct aegisxd_signature_override old;
    struct aegisxd_signature_override current;
    sqlite3_stmt *st;
    struct json_object *tmp = NULL;
    struct json_object *resp;
    int gid = 1;
    int sid = 0;
    int target_rev = 0;
    int expected_revision = -1;
    int enabled_override = -1;
    int suppressed = 0;
    int new_revision;
    int64_t now = aegisxd_now_s();
    const char *action = "inherit";
    const char *reason = "";
    int rc;

    if (aegisxd_signature_json_gid_sid(body, &gid, &sid) != 0)
        return aegisxd_signature_policy_error("invalid_signature_id",
            "gid and sid must be positive integers", gid, sid);
    if (aegisxd_signature_rule_load(sid, &rule) != 0)
        return aegisxd_signature_policy_error("signature_not_found",
            "signature rule was not found in imported Suricata rules", gid, sid);
    rc = aegisxd_signature_json_positive_int(body, "target_rev", &target_rev);
    if (rc == 0)
        rc = aegisxd_signature_json_positive_int(body, "rev", &target_rev);
    if (rc == 0)
        rc = aegisxd_signature_json_positive_int(body, "signature_rev", &target_rev);
    if (rc <= 0)
        return aegisxd_signature_policy_error(rc < 0 ? "invalid_signature_id" :
            "revision_required", "target_rev must be provided and match the current signature rev", gid, sid);
    if (target_rev != rule.rev)
        return aegisxd_signature_policy_error("signature_revision_mismatch",
            "target_rev does not match current signature rev", gid, sid);
    rc = aegisxd_signature_json_int(body, "revision", &expected_revision);
    if (rc <= 0)
        return aegisxd_signature_policy_error(rc < 0 ? "invalid_signature_id" :
            "revision_required", "override revision is required for optimistic locking", gid, sid);
    if (expected_revision < 0)
        return aegisxd_signature_policy_error("invalid_signature_id",
            "revision must be zero or positive", gid, sid);
    if (aegisxd_signature_override_load(gid, sid, &old) != 0)
        return aegisxd_signature_policy_error("signature_policy_save_failed",
            "signature policy storage unavailable", gid, sid);
    if (expected_revision != (old.exists ? old.revision : 0))
        return aegisxd_signature_policy_error("revision_conflict",
            "signature policy override changed before save", gid, sid);

    if (old.exists) {
        enabled_override = old.enabled_override;
        action = old.action;
        suppressed = old.suppressed;
        reason = old.reason;
    }
    if (json_object_object_get_ex(body, "enabled_override", &tmp)) {
        rc = aegisxd_signature_json_int(body, "enabled_override", &enabled_override);
        if (rc <= 0 || (enabled_override != -1 && enabled_override != 0 && enabled_override != 1))
            return aegisxd_signature_policy_error("invalid_signature_id",
                "enabled_override must be -1, 0 or 1", gid, sid);
    }
    if (json_object_object_get_ex(body, "action", &tmp)) {
        action = aegisxd_json_str(body, "action", "");
        if (!aegisxd_signature_action_ok(action))
            return aegisxd_signature_policy_error("invalid_signature_id",
                "action must be inherit, alert, drop, reject or pass", gid, sid);
    }
    if (json_object_object_get_ex(body, "suppressed", &tmp)) {
        if (!json_object_is_type(tmp, json_type_boolean))
            return aegisxd_signature_policy_error("invalid_signature_id",
                "suppressed must be a boolean", gid, sid);
        suppressed = aegisxd_json_bool(body, "suppressed", 0);
    }
    if (force_suppressed)
        suppressed = forced_suppressed ? 1 : 0;
    if (json_object_object_get_ex(body, "reason", &tmp))
        reason = aegisxd_json_str(body, "reason", "");
    if (reason && strlen(reason) > 480)
        return aegisxd_signature_policy_error("invalid_signature_id",
            "reason is too long", gid, sid);

    if (sqlite3_exec(g_aegisxd_config_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return aegisxd_signature_policy_error("signature_policy_save_failed",
            "failed to start signature policy transaction", gid, sid);
    if (aegisxd_signature_override_load(gid, sid, &current) != 0) {
        sqlite3_exec(g_aegisxd_config_db, "ROLLBACK", NULL, NULL, NULL);
        return aegisxd_signature_policy_error("signature_policy_save_failed",
            "signature policy storage unavailable", gid, sid);
    }
    if (expected_revision != (current.exists ? current.revision : 0)) {
        sqlite3_exec(g_aegisxd_config_db, "ROLLBACK", NULL, NULL, NULL);
        return aegisxd_signature_policy_error("revision_conflict",
            "signature policy override changed before save", gid, sid);
    }
    old = current;
    new_revision = old.exists ? old.revision + 1 : 1;
    st = aegisxd_config_prepare(
        "INSERT INTO " AEGISXD_SIGNATURE_POLICY_TABLE
        "(gid,sid,target_rev,enabled_override,action,suppressed,reason,revision,"
        "apply_state,last_error,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'apply_required','',?9,?10) "
        "ON CONFLICT(gid,sid) DO UPDATE SET target_rev=excluded.target_rev,"
        "enabled_override=excluded.enabled_override,action=excluded.action,"
        "suppressed=excluded.suppressed,reason=excluded.reason,revision=excluded.revision,"
        "apply_state='apply_required',last_error='',updated_at=excluded.updated_at");
    if (!st)
        goto save_failed;
    sqlite3_bind_int(st, 1, gid);
    sqlite3_bind_int(st, 2, sid);
    sqlite3_bind_int(st, 3, target_rev);
    sqlite3_bind_int(st, 4, enabled_override);
    sqlite3_bind_text(st, 5, action, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, suppressed ? 1 : 0);
    sqlite3_bind_text(st, 7, reason ? reason : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 8, new_revision);
    sqlite3_bind_int64(st, 9, old.exists && old.created_at > 0 ? old.created_at : now);
    sqlite3_bind_int64(st, 10, now);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        goto save_failed;
    if (sqlite3_exec(g_aegisxd_config_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        goto save_failed;

    memset(&old, 0, sizeof(old));
    (void)aegisxd_signature_override_load(gid, sid, &old);
    resp = json_object_new_object();
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    aegisxd_json_add_string(resp, "operation", force_suppressed ?
                            (forced_suppressed ? "suppress_signature" : "unsuppress_signature") :
                            "set_signature_policy");
    json_object_object_add(resp, "changed", json_object_new_boolean(1));
    json_object_object_add(resp, "persisted", json_object_new_boolean(1));
    json_object_object_add(resp, "apply_required", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "apply_state", "apply_required");
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    json_object_object_add(resp, "runtime_available",
                           json_object_new_boolean(aegisxd_suricata_runtime_available()));
    aegisxd_json_add_string(resp, "runtime_reason",
        aegisxd_suricata_runtime_available() ? "suricata_apply_required" :
                                               "suricata_runtime_missing");
    json_object_object_add(resp, "gid", json_object_new_int(gid));
    json_object_object_add(resp, "sid", json_object_new_int(sid));
    json_object_object_add(resp, "target_rev", json_object_new_int(target_rev));
    json_object_object_add(resp, "revision", json_object_new_int(old.revision));
    json_object_object_add(resp, "readback", aegisxd_signature_policy_item_json(&rule, &old));
    return resp;

save_failed:
    sqlite3_exec(g_aegisxd_config_db, "ROLLBACK", NULL, NULL, NULL);
    return aegisxd_signature_policy_error("signature_policy_save_failed",
        "failed to persist signature policy override", gid, sid);
}

struct json_object *aegisxd_set_signature_policy_json(struct json_object *body)
{
    return aegisxd_signature_policy_write(body, 0, 0);
}

struct json_object *aegisxd_suppress_signature_json(struct json_object *body)
{
    return aegisxd_signature_policy_write(body, 1, 1);
}

struct json_object *aegisxd_unsuppress_signature_json(struct json_object *body)
{
    return aegisxd_signature_policy_write(body, 0, 1);
}

static int aegisxd_signature_count_config_sql(const char *sql)
{
    sqlite3_stmt *st;
    int n = 0;

    st = aegisxd_config_prepare(sql);
    if (!st)
        return 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static int aegisxd_signature_count_join_sql(const char *predicate)
{
    sqlite3_stmt *st;
    int n = 0;
    char sql[512];

    snprintf(sql, sizeof(sql),
             "SELECT gid,sid,target_rev,enabled_override,action,suppressed FROM "
             AEGISXD_SIGNATURE_POLICY_TABLE "%s%s",
             predicate && predicate[0] ? " WHERE " : "",
             predicate && predicate[0] ? predicate : "");
    st = aegisxd_config_prepare(sql);
    if (!st)
        return 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct aegisxd_signature_rule rule;
        int gid = sqlite3_column_int(st, 0);
        int sid = sqlite3_column_int(st, 1);
        int target_rev = sqlite3_column_int(st, 2);

        if (gid != 1) {
            n++;
            continue;
        }
        if (aegisxd_signature_rule_load(sid, &rule) != 0) {
            if (!predicate || strstr(predicate, "orphan") || strstr(predicate, "1=1"))
                n++;
            continue;
        }
        if (target_rev != rule.rev) {
            if (!predicate || strstr(predicate, "stale") || strstr(predicate, "1=1"))
                n++;
        }
    }
    sqlite3_finalize(st);
    return n;
}

int aegisxd_signature_policy_problem_count(void)
{
    return aegisxd_signature_count_join_sql("1=1");
}

struct json_object *aegisxd_signature_policy_counts_json(void)
{
    struct json_object *o = json_object_new_object();
    int total = aegisxd_signature_count_config_sql(
        "SELECT COUNT(*) FROM " AEGISXD_SIGNATURE_POLICY_TABLE);
    int suppressed = aegisxd_signature_count_config_sql(
        "SELECT COUNT(*) FROM " AEGISXD_SIGNATURE_POLICY_TABLE " WHERE suppressed=1");
    int disabled = aegisxd_signature_count_config_sql(
        "SELECT COUNT(*) FROM " AEGISXD_SIGNATURE_POLICY_TABLE " WHERE enabled_override=0");
    int enabled = aegisxd_signature_count_config_sql(
        "SELECT COUNT(*) FROM " AEGISXD_SIGNATURE_POLICY_TABLE " WHERE enabled_override=1");
    int action_overrides = aegisxd_signature_count_config_sql(
        "SELECT COUNT(*) FROM " AEGISXD_SIGNATURE_POLICY_TABLE " WHERE action<>'inherit'");
    sqlite3_stmt *st;
    int stale = 0;
    int orphan = 0;

    st = aegisxd_config_prepare(
        "SELECT sid,target_rev FROM " AEGISXD_SIGNATURE_POLICY_TABLE);
    while (st && sqlite3_step(st) == SQLITE_ROW) {
        struct aegisxd_signature_rule rule;
        int sid = sqlite3_column_int(st, 0);
        int target_rev = sqlite3_column_int(st, 1);

        if (aegisxd_signature_rule_load(sid, &rule) != 0)
            orphan++;
        else if (target_rev != rule.rev)
            stale++;
    }
    if (st)
        sqlite3_finalize(st);
    json_object_object_add(o, "total", json_object_new_int(total));
    json_object_object_add(o, "enabled_overrides", json_object_new_int(enabled));
    json_object_object_add(o, "disabled_overrides", json_object_new_int(disabled));
    json_object_object_add(o, "suppressed", json_object_new_int(suppressed));
    json_object_object_add(o, "action_overrides", json_object_new_int(action_overrides));
    json_object_object_add(o, "stale", json_object_new_int(stale));
    json_object_object_add(o, "orphan", json_object_new_int(orphan));
    json_object_object_add(o, "apply_required", json_object_new_int(
        aegisxd_signature_count_config_sql("SELECT COUNT(*) FROM "
            AEGISXD_SIGNATURE_POLICY_TABLE " WHERE apply_state='apply_required'")));
    return o;
}

int aegisxd_signature_policy_effective_enabled_count(void)
{
    sqlite3_stmt *st;
    int count = 0;

    st = aegisxd_prepare("SELECT sid,rev,enabled_default FROM aegis_suricata_rules WHERE rule_text<>''");
    if (!st)
        return 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct aegisxd_signature_override ov;
        int sid = sqlite3_column_int(st, 0);
        int rev = sqlite3_column_int(st, 1);
        int enabled = sqlite3_column_int(st, 2) ? 1 : 0;

        if (aegisxd_signature_override_load(1, sid, &ov) == 0 && ov.exists && ov.target_rev == rev) {
            if (ov.suppressed)
                enabled = 0;
            else if (ov.enabled_override >= 0)
                enabled = ov.enabled_override ? 1 : 0;
        }
        if (enabled)
            count++;
    }
    sqlite3_finalize(st);
    return count;
}

static int aegisxd_suricata_action_token_len(const char *rule)
{
    int n = 0;

    if (!rule)
        return 0;
    while (isspace((unsigned char)*rule))
        rule++;
    while (rule[n] && !isspace((unsigned char)rule[n]))
        n++;
    return n;
}

int aegisxd_signature_policy_effective_rule_text(int gid, int sid, int rev,
                                                 int enabled_default,
                                                 const char *default_action,
                                                 const char *rule_text,
                                                 char *out, size_t out_len,
                                                 int *enabled_out,
                                                 const char **error_out)
{
    struct aegisxd_signature_override ov;
    int enabled = enabled_default ? 1 : 0;
    const char *action = default_action && default_action[0] ? default_action : "alert";
    const char *p;
    int token_len;

    if (enabled_out)
        *enabled_out = 0;
    if (error_out)
        *error_out = "";
    if (!rule_text || !rule_text[0] || !out || out_len == 0) {
        if (error_out)
            *error_out = "invalid_rule_text";
        return -1;
    }
    if (aegisxd_signature_override_load(gid > 0 ? gid : 1, sid, &ov) != 0) {
        if (error_out)
            *error_out = "signature_policy_storage_unavailable";
        return -1;
    }
    if (ov.exists) {
        if (ov.target_rev != rev) {
            if (error_out)
                *error_out = "signature_revision_mismatch";
            return -1;
        }
        if (ov.suppressed)
            enabled = 0;
        else if (ov.enabled_override >= 0)
            enabled = ov.enabled_override ? 1 : 0;
        if (strcmp(ov.action, "inherit"))
            action = ov.action;
    }
    if (!enabled) {
        if (enabled_out)
            *enabled_out = 0;
        out[0] = '\0';
        return 0;
    }
    if (!aegisxd_signature_action_ok(action) || !strcmp(action, "inherit"))
        action = "alert";
    p = rule_text;
    while (isspace((unsigned char)*p))
        p++;
    token_len = aegisxd_suricata_action_token_len(p);
    if (token_len <= 0 || strchr(p, '\n') || strchr(p, '\r')) {
        if (error_out)
            *error_out = "invalid_rule_text";
        return -1;
    }
    if (snprintf(out, out_len, "%s%s", action, p + token_len) >= (int)out_len) {
        if (error_out)
            *error_out = "rule_text_too_long";
        return -1;
    }
    if (enabled_out)
        *enabled_out = 1;
    return 0;
}
