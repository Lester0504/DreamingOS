// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_setup.c - DreamingWrt first-run setup wizard backend
 */
#include "jmx_netconfig_db.h"
#include "jmx.h"
#include "jmx_exec.h"
#include "jmx_isp.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <uci.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#define NC_SETUP_TOTP_STEP_S       30
#define NC_SETUP_TOTP_DIGITS       6
#define NC_SETUP_TOTP_WINDOW       1
#define NC_SETUP_TOTP_STEP_MIN_S   15
#define NC_SETUP_TOTP_STEP_MAX_S   120
#define NC_SETUP_TOTP_DIGITS_MAX   8
#define NC_SETUP_TOTP_WINDOW_MAX   5
#define NC_SETUP_AI_RUNTIME_SOCKET "/var/run/dreamingwrt-ai.sock"
#define NC_SETUP_AI_OAUTH_DIR      "/etc/dreamingwrt/ai-oauth"
#define NC_SETUP_AI_OAUTH_KEY      NC_SETUP_AI_OAUTH_DIR "/state.key"
#define NC_SETUP_AI_OAUTH_MAGIC    "DWAO1"
#define NC_SETUP_AI_OAUTH_KEY_LEN  32
#define NC_SETUP_AI_OAUTH_NONCE_LEN 12
#define NC_SETUP_AI_OAUTH_TAG_LEN  16
#define NC_SETUP_AI_OAUTH_MAX_SECRET (256U * 1024U)
#define NC_SETUP_COMMAND_OUTPUT_MAX (16U * 1024U)
#define NC_SETUP_COMMAND_TIMEOUT_MS 5000
#define NC_SETUP_UCI_PATH           "/sbin/uci"
#define NC_SETUP_PPPOE_DISCOVERY_PATH "/usr/sbin/pppoe-discovery"

/* ══════════════════════════════════════════════════════════════════════
 * First-run setup wizard state
 * ══════════════════════════════════════════════════════════════════════ */

static struct json_object *nc_setup_response(int code, struct json_object *data)
{
    if (!data)
        data = json_object_new_object();
    if (!json_object_object_get(data, "ok"))
        json_object_object_add(data, "ok", json_object_new_boolean(code == API_CODE_SUCCESS));
    if (!json_object_object_get(data, "ts"))
        json_object_object_add(data, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(code, data);
}

static char *nc_json_plain_dup(struct json_object *o, const char *fallback)
{
    const char *s;
    if (!o)
        return strdup(fallback ? fallback : "{}");
    s = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN);
    return strdup(s ? s : (fallback ? fallback : "{}"));
}

static struct json_object *nc_json_parse_object_or_empty(const char *raw)
{
    struct json_object *o = raw && raw[0] ? json_tokener_parse(raw) : NULL;
    if (!o || !json_object_is_type(o, json_type_object)) {
        if (o)
            json_object_put(o);
        o = json_object_new_object();
    }
    return o;
}

static int nc_json_object_has_keys(struct json_object *o)
{
    return o && json_object_is_type(o, json_type_object) && json_object_object_length(o) > 0;
}

static sqlite3_int64 nc_setup_json_int64_def(struct json_object *o,
                                             const char *key,
                                             sqlite3_int64 def)
{
    struct json_object *value = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &value) || !value)
        return def;
    return (sqlite3_int64)json_object_get_int64(value);
}

static int nc_setup_set_meta(const char *key, const char *value)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!key || !key[0] || !value)
        return -1;
    if (nc_prepare(&st, "INSERT INTO config_meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value") == 0) {
        sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, value, -1, SQLITE_TRANSIENT);
        rc = nc_step_done(st);
        sqlite3_finalize(st);
    }
    return rc;
}

static int nc_setup_is_initialized(void)
{
    sqlite3_stmt *st = NULL;
    int initialized = 0;

    if (jmx_netconfig_db_init() != 0)
        return 0;
    if (nc_prepare(&st, "SELECT initialized FROM setup_state WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW)
            initialized = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    return initialized;
}

/*
 * Shared "this router is already set up" refusal for the setup write paths.
 *
 * The HTTP layer already refuses these with the same `wizard_already_initialized`
 * error, but every one of these functions is also registered on ubus, so a
 * caller that reaches ubus directly bypassed the only copy of the check. The
 * guard belongs next to the data it protects rather than only in the transport
 * in front of it. Returns NULL when the write may proceed, so a caller can
 * simply forward a non-NULL result.
 *
 * The error string is deliberately identical to the HTTP one: an existing
 * client that already handles that code keeps working unchanged.
 */
static struct json_object *nc_setup_guard_initialized(struct json_object *cfg,
                                                      struct json_object *d)
{
    if (!nc_setup_is_initialized())
        return NULL;
    /*
     * webd sets this after its own 409 gate has already decided the caller may
     * write to an initialized device (an authenticated session re-running the
     * wizard is legitimate). Trusting it here is what keeps this guard from
     * changing the HTTP contract: the point of the check is the ubus caller
     * that never passed through any gate, and such a caller has no reason to
     * set it.
     */
    if (cfg && nc_json_bool_def(cfg, "caller_authorized_initialized_write", 0))
        return NULL;
    if (!d)
        d = json_object_new_object();
    json_object_object_add(d, "ok", json_object_new_boolean(0));
    json_object_object_add(d, "error",
                           json_object_new_string("wizard_already_initialized"));
    json_object_object_add(d, "message", json_object_new_string(
        "setup writes require an uninitialized router; use reset_wizard to return an initialized device to the wizard"));
    return nc_setup_response(API_CODE_ERROR, d);
}

static int nc_setup_save_draft(const char *kind, struct json_object *payload)
{
    sqlite3_stmt *st = NULL;
    char *json;
    int rc = -1;

    if (!kind || !kind[0] || !payload)
        return -1;
    json = nc_json_plain_dup(payload, "{}");
    if (!json)
        return -1;
    if (nc_prepare(&st, "INSERT INTO setup_draft(kind,payload_json,updated_at) VALUES(?1,?2,?3) ON CONFLICT(kind) DO UPDATE SET payload_json=excluded.payload_json,updated_at=excluded.updated_at") == 0) {
        sqlite3_bind_text(st, 1, kind, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, json, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, nc_now_s());
        rc = nc_step_done(st);
        sqlite3_finalize(st);
    }
    free(json);
    return rc;
}

static struct json_object *nc_setup_draft_save_error(const char *kind)
{
    struct json_object *d = json_object_new_object();

    json_object_object_add(d, "ok", json_object_new_boolean(0));
    json_object_object_add(d, "error", json_object_new_string("setup_draft_save_failed"));
    json_object_object_add(d, "kind", json_object_new_string(kind ? kind : ""));
    return d;
}

static struct json_object *nc_setup_state_error(const char *operation)
{
    struct json_object *d = json_object_new_object();

    json_object_object_add(d, "ok", json_object_new_boolean(0));
    json_object_object_add(d, "error", json_object_new_string("setup_state_update_failed"));
    json_object_object_add(d, "operation", json_object_new_string(operation ? operation : ""));
    return d;
}

static int nc_setup_clear_drafts(void)
{
    return nc_exec("DELETE FROM setup_draft");
}

static struct json_object *nc_setup_load_draft(const char *kind)
{
    sqlite3_stmt *st = NULL;
    struct json_object *o = NULL;

    if (!kind || !kind[0])
        return json_object_new_object();
    if (nc_prepare(&st, "SELECT payload_json FROM setup_draft WHERE kind=?1") == 0) {
        sqlite3_bind_text(st, 1, kind, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            o = nc_json_parse_object_or_empty((const char *)sqlite3_column_text(st, 0));
        sqlite3_finalize(st);
    }
    return o ? o : json_object_new_object();
}

static int nc_setup_update_step(const char *step)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!step || !step[0])
        return -1;
    if (nc_prepare(&st, "UPDATE setup_state SET current_step=?1,updated_at=?2 WHERE id=1") == 0) {
        sqlite3_bind_text(st, 1, step, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, nc_now_s());
        rc = nc_step_done(st) == 0 && nc_sqlite_changes() > 0 ? 0 : -1;
        sqlite3_finalize(st);
    }
    return rc;
}

static int nc_setup_set_apply_state(const char *apply_id, const char *state, const char *error)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (nc_prepare(&st, "UPDATE setup_state SET last_apply_id=CASE WHEN ?1<>'' THEN ?1 ELSE last_apply_id END,last_apply_state=?2,last_apply_error=?3,last_apply_at=?4,updated_at=?4 WHERE id=1") == 0) {
        sqlite3_bind_text(st, 1, apply_id ? apply_id : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, state ? state : "idle", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, error ? error : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, nc_now_s());
        rc = nc_step_done(st) == 0 && nc_sqlite_changes() > 0 ? 0 : -1;
        sqlite3_finalize(st);
    }
    return rc;
}

static int nc_setup_set_last_test(struct json_object *test_data, int ok)
{
    sqlite3_stmt *st = NULL;
    char *json = nc_json_plain_dup(test_data, "{}");
    int rc = -1;

    if (!json)
        return -1;
    if (nc_prepare(&st, "UPDATE setup_state SET last_test_ok=?1,last_test_json=?2,updated_at=?3 WHERE id=1") == 0) {
        sqlite3_bind_int(st, 1, ok);
        sqlite3_bind_text(st, 2, json, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, nc_now_s());
        rc = nc_step_done(st) == 0 && nc_sqlite_changes() > 0 ? 0 : -1;
        sqlite3_finalize(st);
    }
    free(json);
    return rc;
}

static int nc_setup_clear_last_test(void)
{
    struct json_object *empty = json_object_new_object();
    int rc;

    if (!empty)
        return -1;
    rc = nc_setup_set_last_test(empty, 0);
    json_object_put(empty);
    return rc;
}

static int nc_setup_api_response_ok(struct json_object *resp)
{
    struct json_object *code = NULL;
    struct json_object *data = NULL;

    if (!resp)
        return 0;
    if (!json_object_object_get_ex(resp, "code", &code) || !code ||
        json_object_get_int(code) != API_CODE_SUCCESS)
        return 0;
    if (json_object_object_get_ex(resp, "data", &data) && data)
        return nc_json_bool_def(data, "ok", 1);
    return 1;
}

static void nc_setup_read_first_line(const char *path, char *buf, size_t len)
{
    FILE *fp;

    if (!buf || len == 0)
        return;
    buf[0] = '\0';
    if (!path)
        return;
    fp = fopen(path, "r");
    if (!fp)
        return;
    if (fgets(buf, len, fp))
        buf[strcspn(buf, "\r\n")] = '\0';
    fclose(fp);
}

static int nc_setup_cmd_success(const char *cmd)
{
    return cmd && cmd[0] && nc_run_quiet(cmd) == 0;
}

static int nc_setup_iface_ipv4_ok(const char *ifname)
{
    char cmd[256];

    if (!ifname || !ifname[0] || !nc_iface_name_ok(ifname))
        return 0;
    snprintf(cmd, sizeof(cmd), "ip -4 addr show dev %s 2>/dev/null | grep -q 'inet '", ifname);
    return nc_setup_cmd_success(cmd);
}

static int nc_setup_wan_addr_ok(const char *device, const char *ifname, const char *id)
{
    char pppoe[128];

    if (nc_setup_iface_ipv4_ok(device))
        return 1;
    if (ifname && ifname[0] && (!device || strcmp(ifname, device)) &&
        nc_setup_iface_ipv4_ok(ifname))
        return 1;
    if (id && id[0] && nc_safe_id_ok(id)) {
        snprintf(pppoe, sizeof(pppoe), "pppoe-%s", id);
        if (nc_setup_iface_ipv4_ok(pppoe))
            return 1;
    }
    if (ifname && ifname[0] && nc_safe_id_ok(ifname)) {
        snprintf(pppoe, sizeof(pppoe), "pppoe-%s", ifname);
        if (nc_setup_iface_ipv4_ok(pppoe))
            return 1;
    }
    return 0;
}

static int nc_setup_wifi_capability(const char *name)
{
    struct json_object *resp = jmx_wifi_config_get();
    struct json_object *data = NULL, *cap = NULL;
    int supported = 0;

    if (resp && json_object_object_get_ex(resp, "data", &data) && data &&
        json_object_object_get_ex(data, "capabilities", &cap) && cap)
        supported = nc_json_bool_def(cap, name, 0);
    if (resp)
        json_object_put(resp);
    return supported;
}

static struct json_object *nc_setup_wifi_capability_error(const char *capability,
                                                           const char *reason)
{
    struct json_object *d = json_object_new_object();

    json_object_object_add(d, "ok", json_object_new_boolean(0));
    json_object_object_add(d, "error", json_object_new_string("capability_disabled"));
    json_object_object_add(d, "capability", json_object_new_string(capability));
    json_object_object_add(d, "reason", json_object_new_string(reason));
    json_object_object_add(d, "persisted", json_object_new_boolean(0));
    json_object_object_add(d, "applied", json_object_new_boolean(0));
    return d;
}

static struct json_object *nc_setup_device_json(void)
{
    struct json_object *dev = json_object_new_object();
    char hostname[128] = "";
    char model[256] = "";
    char release[256] = "";

    nc_setup_read_first_line("/proc/sys/kernel/hostname", hostname, sizeof(hostname));
    nc_setup_read_first_line("/tmp/sysinfo/model", model, sizeof(model));
    nc_setup_read_first_line("/etc/openwrt_release", release, sizeof(release));
    json_object_object_add(dev, "hostname", json_object_new_string(hostname[0] ? hostname : "DreamingWrt"));
    json_object_object_add(dev, "model", json_object_new_string(model[0] ? model : "DreamingWrt Router"));
    json_object_object_add(dev, "version", json_object_new_string(release[0] ? release : "DreamingWrt"));
    json_object_object_add(dev, "hero_asset", json_object_new_string("/luci-static/dreamingwrt/setup/device.png"));
    return dev;
}

static int nc_setup_web_user_count(int *known, int *table_exists, const char **error);

/*
 * Explains what this endpoint's "initialized" actually means, and answers the
 * only question a caller really has: should the console be gated behind the
 * wizard?
 *
 * /api/v1/setup/status and /api/v1/session/init both publish a boolean named
 * "initialized" with different meanings - wizard completion here, login
 * capability there. On a device provisioned by jmctl or a direct database write
 * an account exists while setup_state was never touched, so the two disagree
 * and look like a defect. Both values are correct; the shared name is the
 * problem, and a consumer comparing them cannot tell which one gates the UI.
 *
 * The gate follows login capability, not wizard completion: a device with an
 * account is usable. An unfinished wizard is something to offer, not a reason
 * to hide a working console behind a first-run screen - and forcing a wizard on
 * a configured device risks it being walked through and overwriting live config.
 */
static void nc_setup_add_gate_contract(struct json_object *d, int wizard_done)
{
    int users_known = 0;
    int table_exists = 0;
    const char *users_error = "";
    int users = nc_setup_web_user_count(&users_known, &table_exists, &users_error);
    int login_capable = users_known && users > 0;

    json_object_object_add(d, "initialized_scope",
                           json_object_new_string("setup_wizard_completion"));
    json_object_object_add(d, "initialized_meaning",
        json_object_new_string("the_setup_wizard_ran_to_completion_not_whether_the_device_is_usable"));
    json_object_object_add(d, "initialized_source",
                           json_object_new_string("config.db:setup_state.initialized"));

    /* Login capability, read here so a caller does not have to join two
     * endpoints to answer one question. */
    json_object_object_add(d, "login_capable", json_object_new_boolean(login_capable));
    json_object_object_add(d, "web_user_count",
                           json_object_new_int(users_known ? users : 0));
    json_object_object_add(d, "web_user_count_known",
                           json_object_new_boolean(users_known));
    if (!users_known)
        json_object_object_add(d, "web_user_count_error",
                               json_object_new_string(users_error ? users_error : ""));

    /*
     * The authoritative gate. Only force the wizard when the device cannot be
     * logged into at all. wizard_required stays as it was for compatibility,
     * but it answers "is the wizard unfinished", which is a different question.
     */
    json_object_object_add(d, "setup_gate_required",
                           json_object_new_boolean(users_known && !login_capable));
    json_object_object_add(d, "setup_gate_authority",
                           json_object_new_string("login_capability_web_user_count"));
    json_object_object_add(d, "setup_gate_reason",
        json_object_new_string(!users_known ? "web_user_count_unknown_gate_undecidable" :
                               (login_capable ?
                                "device_has_accounts_and_is_usable_do_not_force_wizard" :
                                "no_account_exists_initial_setup_required")));
    /* The case behind this whole ticket: usable device, wizard never finished. */
    json_object_object_add(d, "provisioned_outside_wizard",
                           json_object_new_boolean(login_capable && !wizard_done));
    if (login_capable && !wizard_done)
        json_object_object_add(d, "provisioned_outside_wizard_note",
            json_object_new_string("accounts_exist_but_setup_state_was_never_completed_wizard_may_be_offered_not_forced"));
    json_object_object_add(d, "login_capability_source",
                           json_object_new_string("/api/v1/session/init"));
}

static void nc_setup_add_state_json(struct json_object *d)
{
    sqlite3_stmt *st = NULL;
    int initialized = 0;

    if (nc_prepare(&st, "SELECT initialized,initialized_at,initialized_version,completed_by,assist_mode,current_step,setup_id,started_at,last_apply_id,last_apply_state,last_apply_error,last_apply_at,last_test_ok,last_test_json FROM setup_state WHERE id=1") == 0 && sqlite3_step(st) == SQLITE_ROW) {
        initialized = sqlite3_column_int(st, 0);
        json_object_object_add(d, "initialized", json_object_new_boolean(initialized));
        json_object_object_add(d, "wizard_completed", json_object_new_boolean(initialized));
        json_object_object_add(d, "first_run", json_object_new_boolean(!initialized));
        json_object_object_add(d, "router_setup_initialized", json_object_new_boolean(initialized));
        json_object_object_add(d, "wizard_required", json_object_new_boolean(!initialized));
        /*
         * Reset is offered whenever the wizard state can be rolled back to
         * `intro`, which jmx_setup_reset_wizard() permits on an uninitialized
         * device too -- it only asks for the extra confirm_reset_initialized
         * flag once initialized is set. Reporting `initialized` here claimed the
         * opposite, and on an install that never reached setup_finish that left
         * the UI with no way forward (finish unreachable) and no way back (reset
         * hidden). Verified on 30.1: reset_wizard with confirm=true returned
         * reset:true while this field still said false.
         */
        json_object_object_add(d, "can_reset_wizard", json_object_new_boolean(1));
        json_object_object_add(d, "initialized_at", json_object_new_int64(sqlite3_column_int64(st, 1)));
        nc_add_text(d, "initialized_version", st, 2);
        nc_add_text(d, "completed_by", st, 3);
        json_object_object_add(d, "setup_finished_at", json_object_new_int64(sqlite3_column_int64(st, 1)));
        nc_add_text(d, "setup_version", st, 2);
        nc_add_text(d, "setup_finished_by", st, 3);
        nc_add_text(d, "assist_mode", st, 4);
        nc_add_text(d, "current_step", st, 5);
        nc_add_text(d, "setup_id", st, 6);
        json_object_object_add(d, "started_at", json_object_new_int64(sqlite3_column_int64(st, 7)));
        nc_add_text(d, "progress_id", st, 8);
        nc_add_text(d, "apply_state", st, 9);
        nc_add_text(d, "apply_error", st, 10);
        json_object_object_add(d, "last_apply_at", json_object_new_int64(sqlite3_column_int64(st, 11)));
        json_object_object_add(d, "last_test_ok", json_object_new_boolean(sqlite3_column_int(st, 12)));
        json_object_object_add(d, "last_test", nc_json_parse_object_or_empty((const char *)sqlite3_column_text(st, 13)));
        sqlite3_finalize(st);
        nc_setup_add_gate_contract(d, initialized);
        return;
    }
    if (st)
        sqlite3_finalize(st);
    json_object_object_add(d, "initialized", json_object_new_boolean(0));
    json_object_object_add(d, "wizard_completed", json_object_new_boolean(0));
    json_object_object_add(d, "first_run", json_object_new_boolean(1));
    json_object_object_add(d, "router_setup_initialized", json_object_new_boolean(0));
    json_object_object_add(d, "wizard_required", json_object_new_boolean(1));
    /*
     * The row is unreadable here, so nothing is known about the wizard. Reset
     * stays offered because it is the recovery path out of exactly this state,
     * and it cannot lose a completed configuration it could not read.
     */
    json_object_object_add(d, "can_reset_wizard", json_object_new_boolean(1));
    json_object_object_add(d, "initialized_at", json_object_new_int64(0));
    json_object_object_add(d, "initialized_version", json_object_new_string(""));
    json_object_object_add(d, "completed_by", json_object_new_string(""));
    json_object_object_add(d, "setup_finished_at", json_object_new_int64(0));
    json_object_object_add(d, "setup_version", json_object_new_string(""));
    json_object_object_add(d, "setup_finished_by", json_object_new_string(""));
    json_object_object_add(d, "assist_mode", json_object_new_string("manual"));
    json_object_object_add(d, "current_step", json_object_new_string("intro"));
    /* Same contract on the unreadable-row path, so a consumer never has to
     * handle these fields being absent. wizard_done is 0 here because nothing
     * about the wizard could be read. */
    nc_setup_add_gate_contract(d, 0);
}

static int nc_setup_table_exists_checked(const char *name, int *exists_out)
{
    sqlite3_stmt *st = NULL;
    int rc;
    int exists = 0;

    if (exists_out)
        *exists_out = 0;
    if (!name || !name[0])
        return -1;
    if (nc_prepare(&st, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1 LIMIT 1") == 0) {
        sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW)
            exists = 1;
        else if (rc != SQLITE_DONE) {
            sqlite3_finalize(st);
            return -1;
        }
        sqlite3_finalize(st);
    } else {
        return -1;
    }
    if (exists_out)
        *exists_out = exists;
    return 0;
}

static int nc_setup_scalar_int_checked(const char *sql, int *value_out)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (value_out)
        *value_out = 0;
    if (!sql || !sql[0])
        return -1;
    if (nc_prepare(&st, sql) == 0) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            if (value_out)
                *value_out = sqlite3_column_int(st, 0);
        } else {
            sqlite3_finalize(st);
            return -1;
        }
        sqlite3_finalize(st);
    } else {
        return -1;
    }
    return 0;
}

static int nc_setup_web_user_count(int *known, int *table_exists, const char **error)
{
    int exists = 0;
    int value = 0;

    if (known)
        *known = 0;
    if (table_exists)
        *table_exists = 0;
    if (error)
        *error = "web_users_query_failed";
    if (nc_setup_table_exists_checked("web_users", &exists) != 0) {
        if (error)
            *error = "web_users_schema_query_failed";
        return 0;
    }
    if (table_exists)
        *table_exists = exists;
    if (!exists) {
        if (known)
            *known = 1;
        if (error)
            *error = "";
        return 0;
    }
    if (nc_setup_scalar_int_checked("SELECT COUNT(*) FROM web_users", &value) != 0) {
        if (error)
            *error = "web_users_count_query_failed";
        return 0;
    }
    if (known)
        *known = 1;
    if (error)
        *error = "";
    return value;
}

static int nc_setup_twofa_enabled_count(int *known, int *table_exists, const char **error)
{
    int exists = 0;
    int value = 0;

    if (known)
        *known = 0;
    if (table_exists)
        *table_exists = 0;
    if (error)
        *error = "twofa_status_query_failed";
    if (nc_setup_table_exists_checked("web_users", &exists) != 0) {
        if (error)
            *error = "web_users_schema_query_failed";
        return 0;
    }
    if (table_exists)
        *table_exists = exists;
    if (!exists) {
        if (known)
            *known = 1;
        if (error)
            *error = "";
        return 0;
    }
    if (nc_setup_scalar_int_checked("SELECT COUNT(*) FROM web_users WHERE twofa_enabled=1", &value) != 0) {
        if (error)
            *error = "twofa_count_query_failed";
        return 0;
    }
    if (known)
        *known = 1;
    if (error)
        *error = "";
    return value;
}

struct nc_setup_twofa_policy {
    char issuer[64];
    int step_s;
    int digits;
    int window;
    int known;
    const char *error;
};

static int nc_setup_totp_step_ok(int step_s)
{
    return step_s >= NC_SETUP_TOTP_STEP_MIN_S && step_s <= NC_SETUP_TOTP_STEP_MAX_S;
}

static int nc_setup_totp_digits_ok(int digits)
{
    return digits >= 6 && digits <= NC_SETUP_TOTP_DIGITS_MAX;
}

static int nc_setup_totp_window_ok(int window)
{
    return window >= 0 && window <= NC_SETUP_TOTP_WINDOW_MAX;
}

static void nc_setup_twofa_policy_defaults(struct nc_setup_twofa_policy *p)
{
    if (!p)
        return;
    snprintf(p->issuer, sizeof(p->issuer), "%s", "DreamingWrt");
    p->step_s = NC_SETUP_TOTP_STEP_S;
    p->digits = NC_SETUP_TOTP_DIGITS;
    p->window = NC_SETUP_TOTP_WINDOW;
    p->known = 0;
    p->error = "twofa_policy_unavailable";
}

static void nc_setup_twofa_policy_load(struct nc_setup_twofa_policy *p)
{
    sqlite3_stmt *st = NULL;
    int exists = 0;

    nc_setup_twofa_policy_defaults(p);
    if (!p)
        return;
    if (nc_setup_table_exists_checked("web_auth_settings", &exists) != 0) {
        p->error = "twofa_policy_schema_query_failed";
        return;
    }
    if (!exists) {
        p->known = 1;
        p->error = "";
        return;
    }
    if (nc_prepare(&st, "SELECT twofa_issuer,twofa_step_s,twofa_digits,twofa_window FROM web_auth_settings WHERE id=1") == 0) {
        int rc = sqlite3_step(st);

        if (rc == SQLITE_ROW) {
            const char *issuer = (const char *)sqlite3_column_text(st, 0);

            if (issuer && issuer[0])
                snprintf(p->issuer, sizeof(p->issuer), "%s", issuer);
            p->step_s = sqlite3_column_int(st, 1);
            p->digits = sqlite3_column_int(st, 2);
            p->window = sqlite3_column_int(st, 3);
            p->known = 1;
            p->error = "";
        } else if (rc == SQLITE_DONE) {
            p->known = 1;
            p->error = "";
        } else {
            p->error = "twofa_policy_query_failed";
        }
        sqlite3_finalize(st);
    } else {
        p->error = "twofa_policy_query_failed";
    }
    if (!nc_setup_totp_step_ok(p->step_s)) p->step_s = NC_SETUP_TOTP_STEP_S;
    if (!nc_setup_totp_digits_ok(p->digits)) p->digits = NC_SETUP_TOTP_DIGITS;
    if (!nc_setup_totp_window_ok(p->window)) p->window = NC_SETUP_TOTP_WINDOW;
}

static int nc_setup_ssh_port(void)
{
    char *const argv[] = {
        NC_SETUP_UCI_PATH, "-q", "get", "dropbear.@dropbear[0].Port", NULL
    };
    struct jmx_exec_result result;
    char buf[32] = "";
    size_t line_len;
    long port;
    char *endp = NULL;

    if (jmx_exec_capture(argv[0], argv, sizeof(buf) - 1,
                         NC_SETUP_COMMAND_TIMEOUT_MS, &result) != 0)
        return 22;
    if (result.timed_out || result.term_signal != 0 || result.truncated ||
        result.exit_code != 0 || !result.output || result.output_len == 0) {
        jmx_exec_result_free(&result);
        return 22;
    }
    line_len = strcspn(result.output, "\r\n");
    if (line_len == 0 || line_len >= sizeof(buf)) {
        jmx_exec_result_free(&result);
        return 22;
    }
    memcpy(buf, result.output, line_len);
    buf[line_len] = '\0';
    jmx_exec_result_free(&result);
    port = strtol(buf, &endp, 10);
    if (!endp || *endp || port < 1 || port > 65535)
        return 22;
    return (int)port;
}

static struct json_object *nc_setup_ssh_json(const char *apply_state)
{
    struct json_object *ssh = json_object_new_object();

    json_object_object_add(ssh, "enabled", json_object_new_boolean(1));
    json_object_object_add(ssh, "port", json_object_new_int(nc_setup_ssh_port()));
    json_object_object_add(ssh, "can_change_port", json_object_new_boolean(1));
    json_object_object_add(ssh, "apply_state", json_object_new_string(apply_state ? apply_state : "ready"));
    return ssh;
}

static struct json_object *nc_setup_security_json(void)
{
    struct json_object *security = json_object_new_object();
    struct json_object *twofa = json_object_new_object();
    struct nc_setup_twofa_policy twofa_policy;
    int users_known = 0;
    int users_table_exists = 0;
    int twofa_known = 0;
    int twofa_table_exists = 0;
    const char *users_error = "";
    const char *twofa_error = "";
    int users = nc_setup_web_user_count(&users_known, &users_table_exists, &users_error);
    int twofa_enabled = nc_setup_twofa_enabled_count(&twofa_known, &twofa_table_exists, &twofa_error);

    nc_setup_twofa_policy_load(&twofa_policy);
    json_object_object_add(security, "ssh", nc_setup_ssh_json("ready"));

    json_object_object_add(twofa, "enabled", json_object_new_boolean(twofa_enabled > 0));
    json_object_object_add(twofa, "bound_users", json_object_new_int(twofa_enabled));
    json_object_object_add(twofa, "status_available", json_object_new_boolean(twofa_known));
    json_object_object_add(twofa, "status_error", json_object_new_string(twofa_known ? "" : (twofa_error ? twofa_error : "twofa_status_query_failed")));
    json_object_object_add(twofa, "bound_users_known", json_object_new_boolean(twofa_known));
    json_object_object_add(twofa, "web_users_known", json_object_new_boolean(users_known));
    json_object_object_add(twofa, "web_users_table_exists", json_object_new_boolean(users_table_exists));
    json_object_object_add(twofa, "web_users_error", json_object_new_string(users_known ? "" : (users_error ? users_error : "web_users_query_failed")));
    json_object_object_add(twofa, "twofa_table_exists", json_object_new_boolean(twofa_table_exists));
    json_object_object_add(twofa, "can_prepare", json_object_new_boolean(users_known && users > 0));
    json_object_object_add(twofa, "warning_required_when_skipped", json_object_new_boolean(1));
    json_object_object_add(twofa, "method", json_object_new_string("totp"));
    json_object_object_add(twofa, "requires_web_session", json_object_new_boolean(0));
    json_object_object_add(twofa, "requires_setup_session", json_object_new_boolean(1));
    json_object_object_add(twofa, "public_setup_prepare", json_object_new_boolean(1));
    json_object_object_add(twofa, "setup_actor_bound", json_object_new_boolean(1));
    json_object_object_add(twofa, "setup_prepare_api", json_object_new_string("/api/setup/security/2fa/prepare"));
    json_object_object_add(twofa, "setup_enable_api", json_object_new_string("/api/setup/security/2fa/enable"));
    json_object_object_add(twofa, "status_api", json_object_new_string("/api/v1/auth/2fa/status"));
    json_object_object_add(twofa, "prepare_api", json_object_new_string("/api/v1/auth/2fa/prepare"));
    json_object_object_add(twofa, "enable_api", json_object_new_string("/api/v1/auth/2fa/enable"));
    json_object_object_add(twofa, "disable_api", json_object_new_string("/api/v1/auth/2fa/disable"));
    json_object_object_add(twofa, "qr_payload_field", json_object_new_string("otpauth_url"));
    json_object_object_add(twofa, "secret_storage", json_object_new_string("config.db:web_users.twofa_secret"));
    json_object_object_add(twofa, "algorithm", json_object_new_string("SHA1"));
    json_object_object_add(twofa, "issuer", json_object_new_string(twofa_policy.issuer));
    json_object_object_add(twofa, "digits", json_object_new_int(twofa_policy.digits));
    json_object_object_add(twofa, "period", json_object_new_int(twofa_policy.step_s));
    json_object_object_add(twofa, "window", json_object_new_int(twofa_policy.window));
    json_object_object_add(twofa, "policy_available", json_object_new_boolean(twofa_policy.known));
    json_object_object_add(twofa, "policy_error", json_object_new_string(twofa_policy.known ? "" : (twofa_policy.error ? twofa_policy.error : "twofa_policy_unavailable")));
    json_object_object_add(security, "twofa", twofa);
    return security;
}

struct json_object *jmx_setup_security_ssh_set(struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();
    struct uci_context *ctx = NULL;
    char port_buf[16];
    char bak[128] = "";
    int port = cfg ? nc_json_int_def(cfg, "port", 0) : 0;
    int rc = -1;

    if (!cfg || port < 1 || port > 65535) {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("invalid_ssh_port"));
        json_object_object_add(d, "message", json_object_new_string("SSH port must be between 1 and 65535"));
        json_object_object_add(d, "port", json_object_new_int(port));
        return nc_setup_response(API_CODE_ERROR, d);
    }

    ctx = uci_alloc_context();
    if (!ctx) {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("uci_alloc_failed"));
        return nc_setup_response(API_CODE_ERROR, d);
    }

    snprintf(port_buf, sizeof(port_buf), "%d", port);
    if (nc_backup_config("dropbear", bak, sizeof(bak)) != 0) {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("backup_failed"));
        uci_free_context(ctx);
        return nc_setup_response(API_CODE_ERROR, d);
    }

    if (nc_uci_set_pkg(ctx, "dropbear", "@dropbear[0]", "Port", port_buf) == UCI_OK &&
        jmx_uci_commit(ctx, "dropbear") == UCI_OK)
        rc = nc_run_quiet("/etc/init.d/dropbear restart >/dev/null 2>&1");

    uci_free_context(ctx);

    if (rc != 0) {
        nc_restore_config("dropbear", bak);
        nc_run_quiet("/etc/init.d/dropbear restart >/dev/null 2>&1");
        nc_cleanup_backup(bak);
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("apply_failed"));
        json_object_object_add(d, "message", json_object_new_string("failed to apply SSH port; restored previous dropbear config"));
        json_object_object_add(d, "port", json_object_new_int(port));
        json_object_object_add(d, "ssh", nc_setup_ssh_json("rollback"));
        return nc_setup_response(API_CODE_ERROR, d);
    }

    nc_cleanup_backup(bak);
    json_object_object_add(d, "applied", json_object_new_boolean(1));
    json_object_object_add(d, "service", json_object_new_string("dropbear"));
    json_object_object_add(d, "port", json_object_new_int(port));
    json_object_object_add(d, "ssh", nc_setup_ssh_json("applied"));
    return nc_setup_response(API_CODE_SUCCESS, d);
}

struct nc_setup_oauth_provider {
    const char *id;
    int supported;
    const char *mode;
    const char *reason;
};

static const struct nc_setup_oauth_provider nc_setup_oauth_providers[] = {
    { "gemini", 1, "authorization_code_pkce_s256", "" },
    { "kimi", 1, "device_oauth", "" },
    { "anthropic", 1, "enterprise_wif",
      "requires_preconfigured_anthropic_workload_identity_federation" },
    { "openai", 1, "chatgpt_authorization_code_pkce_s256", "" },
    { "grok", 0, "api_key_only",
      "no_public_third_party_oauth_for_xai_model_api" },
    { "antigravity", 0, "not_independent_model_api",
      "antigravity_has_no_independent_public_model_api_oauth_contract_use_gemini" },
};

struct nc_setup_oauth_credential {
    int known;
    int connected;
    int expired;
    sqlite3_int64 expires_at;
    const char *reason;
};

static int nc_setup_ai_provider_supported(const char *provider)
{
    static const char *const providers[] = {
        "openai", "openai-compatible", "openai_compatible", "deepseek",
        "qwen", "custom", "anthropic", "gemini", "google-gemini",
        "kimi", "kimi-code", "kimi_code", NULL
    };
    size_t i;

    if (!provider || !provider[0])
        return 0;
    for (i = 0; providers[i]; i++)
        if (!strcasecmp(provider, providers[i]))
            return 1;
    return 0;
}

static const char *nc_setup_oauth_provider_id(const char *provider)
{
    if (!provider)
        return "";
    if (!strcasecmp(provider, "google-gemini"))
        return "gemini";
    if (!strcasecmp(provider, "kimi-code") ||
        !strcasecmp(provider, "kimi_code"))
        return "kimi";
    return provider;
}

static const struct nc_setup_oauth_provider *
nc_setup_oauth_provider_find(const char *provider)
{
    const char *canonical = nc_setup_oauth_provider_id(provider);
    size_t i;

    for (i = 0; i < sizeof(nc_setup_oauth_providers) /
                    sizeof(nc_setup_oauth_providers[0]); i++)
        if (!strcasecmp(canonical, nc_setup_oauth_providers[i].id))
            return &nc_setup_oauth_providers[i];
    return NULL;
}

static int nc_setup_proc_executable_running(const char *name)
{
    DIR *proc;
    struct dirent *entry;
    int running = 0;

    if (!name || !name[0])
        return 0;
    proc = opendir("/proc");
    if (!proc)
        return 0;
    while ((entry = readdir(proc)) != NULL) {
        char path[PATH_MAX];
        char target[PATH_MAX];
        const char *base;
        char *deleted;
        ssize_t n;

        if (entry->d_name[0] < '1' || entry->d_name[0] > '9')
            continue;
        snprintf(path, sizeof(path), "/proc/%s/exe", entry->d_name);
        n = readlink(path, target, sizeof(target) - 1);
        if (n <= 0)
            continue;
        target[n] = '\0';
        deleted = strstr(target, " (deleted)");
        if (deleted)
            *deleted = '\0';
        base = strrchr(target, '/');
        base = base ? base + 1 : target;
        if (!strcmp(base, name)) {
            running = 1;
            break;
        }
    }
    closedir(proc);
    return running;
}

static int nc_setup_unix_listener_active(const char *path)
{
    struct stat st;
    FILE *fp;
    char line[1024];
    int active = 0;

    if (!path || stat(path, &st) != 0 || !S_ISSOCK(st.st_mode))
        return 0;
    fp = fopen("/proc/net/unix", "r");
    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp)) {
        char *save = NULL;
        char *token;
        char *fields[8] = {0};
        unsigned long flags;
        int count = 0;

        for (token = strtok_r(line, " \t\r\n", &save);
             token && count < (int)(sizeof(fields) / sizeof(fields[0]));
             token = strtok_r(NULL, " \t\r\n", &save))
            fields[count++] = token;
        if (count < 8 || strcmp(fields[7], path) || strcmp(fields[4], "0001"))
            continue;
        errno = 0;
        flags = strtoul(fields[3], NULL, 16);
        if (!errno && (flags & 0x00010000UL)) {
            active = 1;
            break;
        }
    }
    fclose(fp);
    return active;
}

static int nc_setup_read_root_secret(const char *path, unsigned char *out,
                                     size_t length)
{
    struct stat st;
    size_t offset = 0;
    int fd;

    if (!path || !out)
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & 077) != 0 ||
        (size_t)st.st_size != length) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    while (offset < length) {
        ssize_t got = read(fd, out + offset, length - offset);

        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            break;
        offset += (size_t)got;
    }
    close(fd);
    if (offset == length)
        return 0;
    OPENSSL_cleanse(out, length);
    return -1;
}

static int nc_setup_root_private_dir_ok(const char *path)
{
    struct stat st;

    if (!path || lstat(path, &st) != 0)
        return errno == ENOENT ? 0 : -1;
    return S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode) &&
           st.st_uid == 0 && (st.st_mode & 077) == 0 ? 1 : -1;
}

static struct json_object *nc_setup_oauth_token_load(const char *provider,
                                                      const char **reason)
{
    unsigned char key[NC_SETUP_AI_OAUTH_KEY_LEN] = {0};
    unsigned char *blob = NULL;
    unsigned char *plain = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    struct json_object *token = NULL;
    struct stat st;
    char path[PATH_MAX];
    char aad[128];
    size_t offset = 0;
    int fd = -1;
    size_t cipher_len;
    int out1 = 0;
    int out2 = 0;
    int aad_len = 0;
    int directory_status;

    if (reason)
        *reason = "oauth_credential_unavailable";
    directory_status = nc_setup_root_private_dir_ok(NC_SETUP_AI_OAUTH_DIR);
    if (directory_status <= 0) {
        if (reason)
            *reason = directory_status == 0 ? "oauth_not_connected" :
                                              "oauth_state_directory_invalid";
        return NULL;
    }
    if (!provider || !provider[0] ||
        snprintf(path, sizeof(path), "%s/%s.token.enc",
                 NC_SETUP_AI_OAUTH_DIR, provider) >= (int)sizeof(path) ||
        snprintf(aad, sizeof(aad), "%s:token", provider) >= (int)sizeof(aad))
        return NULL;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (reason)
            *reason = errno == ENOENT ? "oauth_not_connected" :
                                        "oauth_state_unavailable";
        return NULL;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 077) != 0 ||
        st.st_size <= (off_t)(strlen(NC_SETUP_AI_OAUTH_MAGIC) +
                              NC_SETUP_AI_OAUTH_NONCE_LEN +
                              NC_SETUP_AI_OAUTH_TAG_LEN) ||
        st.st_size > (off_t)NC_SETUP_AI_OAUTH_MAX_SECRET) {
        if (reason)
            *reason = "oauth_state_permissions_or_size_invalid";
        goto done;
    }
    if (nc_setup_read_root_secret(NC_SETUP_AI_OAUTH_KEY, key,
                                  sizeof(key)) != 0) {
        if (reason)
            *reason = "oauth_key_unavailable";
        goto done;
    }
    blob = malloc((size_t)st.st_size);
    plain = calloc(1, (size_t)st.st_size + 1);
    if (!blob || !plain) {
        if (reason)
            *reason = "oauth_state_read_failed";
        goto done;
    }
    while (offset < (size_t)st.st_size) {
        ssize_t got = read(fd, blob + offset, (size_t)st.st_size - offset);

        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            break;
        offset += (size_t)got;
    }
    if (offset != (size_t)st.st_size ||
        memcmp(blob, NC_SETUP_AI_OAUTH_MAGIC,
               strlen(NC_SETUP_AI_OAUTH_MAGIC))) {
        if (reason)
            *reason = "oauth_state_read_failed";
        goto done;
    }
    cipher_len = (size_t)st.st_size - strlen(NC_SETUP_AI_OAUTH_MAGIC) -
                 NC_SETUP_AI_OAUTH_NONCE_LEN - NC_SETUP_AI_OAUTH_TAG_LEN;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx ||
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            NC_SETUP_AI_OAUTH_NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key,
                           blob + strlen(NC_SETUP_AI_OAUTH_MAGIC)) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &aad_len,
                          (const unsigned char *)aad, (int)strlen(aad)) != 1 ||
        EVP_DecryptUpdate(ctx, plain, &out1,
                          blob + strlen(NC_SETUP_AI_OAUTH_MAGIC) +
                          NC_SETUP_AI_OAUTH_NONCE_LEN +
                          NC_SETUP_AI_OAUTH_TAG_LEN,
                          (int)cipher_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            NC_SETUP_AI_OAUTH_TAG_LEN,
                            blob + strlen(NC_SETUP_AI_OAUTH_MAGIC) +
                            NC_SETUP_AI_OAUTH_NONCE_LEN) != 1 ||
        EVP_DecryptFinal_ex(ctx, plain + out1, &out2) != 1) {
        if (reason)
            *reason = "oauth_state_authentication_failed";
        goto done;
    }
    plain[out1 + out2] = '\0';
    token = json_tokener_parse((const char *)plain);
    if (!token || !json_object_is_type(token, json_type_object) ||
        !nc_json_str_def(token, "access_token", "")[0]) {
        if (token)
            json_object_put(token);
        token = NULL;
        if (reason)
            *reason = "oauth_state_invalid";
        goto done;
    }
    if (reason)
        *reason = "";

done:
    if (fd >= 0)
        close(fd);
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    if (plain)
        OPENSSL_cleanse(plain, (size_t)st.st_size + 1);
    free(plain);
    free(blob);
    return token;
}

static void nc_setup_oauth_credential_status(const char *provider,
                                              struct nc_setup_oauth_credential *status)
{
    const struct nc_setup_oauth_provider *catalog_provider;
    struct json_object *token;
    struct json_object *expires = NULL;
    const char *reason = "oauth_credential_unavailable";
    sqlite3_int64 now = nc_now_s();

    memset(status, 0, sizeof(*status));
    status->reason = reason;
    status->known = 1;
    catalog_provider = nc_setup_oauth_provider_find(provider);
    if (!catalog_provider || !catalog_provider->supported) {
        status->reason = "oauth_provider_unsupported";
        return;
    }
    token = nc_setup_oauth_token_load(catalog_provider->id, &reason);
    status->reason = reason;
    if (!token)
        return;
    status->connected = 1;
    if (json_object_object_get_ex(token, "expires_at", &expires) && expires)
        status->expires_at = json_object_get_int64(expires);
    status->expired = status->expires_at > 0 && status->expires_at <= now;
    status->reason = status->expired ? "oauth_credential_expired" : "";
    json_object_put(token);
}

static struct json_object *nc_setup_oauth_catalog_json(int service_available,
                                                       const char *selected_provider,
                                                       const struct nc_setup_oauth_credential *credential)
{
    struct json_object *oauth = json_object_new_object();
    struct json_object *providers = json_object_new_array();
    size_t i;

    for (i = 0; i < sizeof(nc_setup_oauth_providers) /
                    sizeof(nc_setup_oauth_providers[0]); i++) {
        const struct nc_setup_oauth_provider *provider =
            &nc_setup_oauth_providers[i];
        struct json_object *item = json_object_new_object();

        json_object_object_add(item, "provider",
                               json_object_new_string(provider->id));
        json_object_object_add(item, "supported",
                               json_object_new_boolean(provider->supported));
        json_object_object_add(item, "mode",
                               json_object_new_string(provider->mode));
        if (provider->reason[0])
            json_object_object_add(item, "reason",
                                   json_object_new_string(provider->reason));
        json_object_array_add(providers, item);
    }
    json_object_object_add(oauth, "implemented", json_object_new_boolean(1));
    json_object_object_add(oauth, "available",
                           json_object_new_boolean(service_available));
    json_object_object_add(oauth, "service_available",
                           json_object_new_boolean(service_available));
    json_object_object_add(oauth, "service_reason", json_object_new_string(
        service_available ? "" : "dreamingwrt_webd_not_running"));
    json_object_object_add(oauth, "providers", providers);
    json_object_object_add(oauth, "catalog_source",
                           json_object_new_string("webd.ai-oauth.v1"));
    json_object_object_add(oauth, "catalog_endpoint",
                           json_object_new_string("/api/v1/ai/oauth/providers"));
    json_object_object_add(oauth, "setup_catalog_endpoint",
                           json_object_new_string("/api/v1/setup/oauth/providers"));
    json_object_object_add(oauth, "status_endpoint",
                           json_object_new_string("/api/v1/ai/oauth/status"));
    json_object_object_add(oauth, "start_endpoint",
                           json_object_new_string("/api/v1/setup/oauth/start"));
    json_object_object_add(oauth, "poll_endpoint",
                           json_object_new_string("/api/v1/ai/oauth/poll"));
    json_object_object_add(oauth, "refresh_endpoint",
                           json_object_new_string("/api/v1/ai/oauth/refresh"));
    json_object_object_add(oauth, "disconnect_endpoint",
                           json_object_new_string("/api/v1/ai/oauth/disconnect"));
    json_object_object_add(oauth, "selected_provider",
                           json_object_new_string(selected_provider ?
                                                  selected_provider : ""));
    json_object_object_add(oauth, "connected", json_object_new_boolean(
        credential && credential->connected));
    json_object_object_add(oauth, "expired", json_object_new_boolean(
        credential && credential->expired));
    json_object_object_add(oauth, "expires_at", json_object_new_int64(
        credential ? credential->expires_at : 0));
    json_object_object_add(oauth, "status_known", json_object_new_boolean(
        credential && credential->known));
    json_object_object_add(oauth, "status_reason", json_object_new_string(
        credential && credential->reason ? credential->reason :
                                            "oauth_status_unavailable"));
    return oauth;
}

static struct json_object *nc_setup_llm_json(void)
{
    struct json_object *llm = json_object_new_object();
    struct json_object *providers = json_object_new_array();
    struct json_object *ai = jmx_ai_config_get();
    struct json_object *ai_data = NULL;
    struct nc_setup_oauth_credential oauth_credential;
    const char *provider = "";
    const char *model = "";
    const char *auth_mode = "api_key";
    const char *blocked_reason = "ai_config_unavailable";
    int config_known = 0;
    int enabled = 0;
    int api_key_set = 0;
    int auth_mode_supported = 0;
    int provider_supported = 0;
    int credential_configured = 0;
    int configured = 0;
    int webd_available = nc_setup_proc_executable_running("dreamingwrt-webd");
    int local_rpc_available = webd_available &&
        nc_setup_unix_listener_active(NC_SETUP_AI_RUNTIME_SOCKET);
    int runtime_available = webd_available;
    int provider_available;
    static const char *const runtime_providers[] = {
        "openai", "anthropic", "deepseek", "qwen", "openai_compatible",
        "custom", "gemini", "kimi", NULL
    };
    size_t i;

    memset(&oauth_credential, 0, sizeof(oauth_credential));
    oauth_credential.reason = "oauth_not_selected";
    for (i = 0; runtime_providers[i]; i++)
        json_object_array_add(providers,
                              json_object_new_string(runtime_providers[i]));
    if (ai && json_object_object_get_ex(ai, "data", &ai_data) && ai_data) {
        config_known = 1;
        provider = nc_json_str_def(ai_data, "provider", "");
        model = nc_json_str_def(ai_data, "model", "");
        auth_mode = nc_json_str_def(ai_data, "auth_mode", "api_key");
        enabled = nc_json_bool_def(ai_data, "enabled", 0);
        api_key_set = nc_json_bool_def(ai_data, "api_key_set", 0);
    }
    provider_supported = nc_setup_ai_provider_supported(provider);
    auth_mode_supported = !strcmp(auth_mode, "api_key") ||
                          !strcmp(auth_mode, "oauth");
    if (nc_setup_oauth_provider_find(provider))
        nc_setup_oauth_credential_status(provider, &oauth_credential);
    if (auth_mode_supported && !strcmp(auth_mode, "oauth")) {
        credential_configured = oauth_credential.connected;
    } else if (auth_mode_supported) {
        credential_configured = api_key_set;
    }
    configured = config_known && enabled && provider_supported &&
                 auth_mode_supported && model[0] && credential_configured;
    provider_available = runtime_available && configured;
    if (!config_known)
        blocked_reason = "ai_config_unavailable";
    else if (!enabled)
        blocked_reason = "provider_disabled";
    else if (!provider_supported)
        blocked_reason = "provider_unsupported";
    else if (!auth_mode_supported)
        blocked_reason = "auth_mode_unsupported";
    else if (!model[0])
        blocked_reason = "model_not_configured";
    else if (!credential_configured)
        blocked_reason = !strcmp(auth_mode, "oauth") ?
            (oauth_credential.reason && oauth_credential.reason[0] ?
             oauth_credential.reason : "oauth_not_connected") :
            "api_key_not_configured";
    else if (!webd_available)
        blocked_reason = "dreamingwrt_webd_not_running";
    else
        blocked_reason = "";

    json_object_object_add(llm, "provider",
                           json_object_new_string(provider));
    json_object_object_add(llm, "model", json_object_new_string(model));
    json_object_object_add(llm, "auth_mode",
                           json_object_new_string(auth_mode));
    json_object_object_add(llm, "enabled", json_object_new_boolean(enabled));
    json_object_object_add(llm, "api_key_set",
                           json_object_new_boolean(api_key_set));
    json_object_object_add(llm, "providers", providers);
    json_object_object_add(llm, "config_known",
                           json_object_new_boolean(config_known));
    json_object_object_add(llm, "provider_supported",
                           json_object_new_boolean(provider_supported));
    json_object_object_add(llm, "auth_mode_supported",
                           json_object_new_boolean(auth_mode_supported));
    json_object_object_add(llm, "credential_configured",
                           json_object_new_boolean(credential_configured));
    json_object_object_add(llm, "configured",
                           json_object_new_boolean(configured));
    json_object_object_add(llm, "runtime_available",
                           json_object_new_boolean(runtime_available));
    json_object_object_add(llm, "runtime_source",
                           json_object_new_string("dreamingwrt-webd:process"));
    json_object_object_add(llm, "local_rpc_available",
                           json_object_new_boolean(local_rpc_available));
    json_object_object_add(llm, "local_rpc_endpoint",
                           json_object_new_string(NC_SETUP_AI_RUNTIME_SOCKET));
    json_object_object_add(llm, "local_rpc_reason", json_object_new_string(
        local_rpc_available ? "" : "ai_runtime_socket_unavailable"));
    json_object_object_add(llm, "provider_available",
                           json_object_new_boolean(provider_available));
    json_object_object_add(llm, "provider_reachable", json_object_new_null());
    json_object_object_add(llm, "provider_reachability_source",
                           json_object_new_string("provider_test_required"));
    json_object_object_add(llm, "blocked_reason",
                           json_object_new_string(blocked_reason));
    json_object_object_add(llm, "chat_api",
                           json_object_new_string("/api/v1/ai/chat"));
    json_object_object_add(llm, "provider_test_api",
                           json_object_new_string("/api/v1/ai/provider/test"));
    json_object_object_add(llm, "oauth",
                           nc_setup_oauth_catalog_json(webd_available, provider,
                                                       &oauth_credential));
    if (ai)
        json_object_put(ai);
    return llm;
}

static struct json_object *nc_setup_app_pairing_json(void)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *pairing = json_object_new_object();
    int paired = 0;
    int pending = 0;
    int has_pair_expires_at = 0;
    int status_available = 0;
    const char *status_error = "apid_db_missing";

    if (access("/etc/dreamingwrt/apid.db", R_OK) == 0) {
        status_error = "apid_db_open_failed";
        if (sqlite3_open_v2("/etc/dreamingwrt/apid.db", &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
            int rc;

            status_error = "app_devices_schema_query_failed";
            if (sqlite3_prepare_v2(db, "PRAGMA table_info(app_devices)", -1, &st, NULL) == SQLITE_OK) {
                while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
                    const char *name = (const char *)sqlite3_column_text(st, 1);

                    if (name && !strcmp(name, "pair_expires_at")) {
                        has_pair_expires_at = 1;
                        break;
                    }
                }
                status_error = rc == SQLITE_DONE || rc == SQLITE_ROW ? "" : "app_devices_schema_query_failed";
                sqlite3_finalize(st);
                st = NULL;
            }

            if (!status_error[0]) {
                status_error = "paired_devices_query_failed";
                if (sqlite3_prepare_v2(db,
                    "SELECT COUNT(*) FROM app_devices d WHERE d.enabled=1 AND EXISTS ("
                    "SELECT 1 FROM auth_tokens t WHERE t.device_id=d.id AND t.revoked=0 AND t.expires_at>strftime('%s','now'))",
                    -1, &st, NULL) == SQLITE_OK) {
                    rc = sqlite3_step(st);
                    if (rc == SQLITE_ROW) {
                        paired = sqlite3_column_int(st, 0);
                        status_error = "";
                    }
                    sqlite3_finalize(st);
                    st = NULL;
                }
            }

            if (!status_error[0]) {
                status_error = "pending_devices_query_failed";
                if (sqlite3_prepare_v2(db, has_pair_expires_at ?
                    "SELECT COUNT(*) FROM app_devices d WHERE d.enabled=1 AND d.paired_at=0 "
                    "AND (d.pair_expires_at=0 OR d.pair_expires_at>=strftime('%s','now')) "
                    "AND NOT EXISTS (SELECT 1 FROM auth_tokens t WHERE t.device_id=d.id AND t.revoked=0 AND t.expires_at>strftime('%s','now'))" :
                    "SELECT COUNT(*) FROM app_devices d WHERE d.enabled=1 AND d.paired_at=0 "
                    "AND NOT EXISTS (SELECT 1 FROM auth_tokens t WHERE t.device_id=d.id AND t.revoked=0 AND t.expires_at>strftime('%s','now'))",
                    -1, &st, NULL) == SQLITE_OK) {
                    rc = sqlite3_step(st);
                    if (rc == SQLITE_ROW) {
                        pending = sqlite3_column_int(st, 0);
                        status_error = "";
                        status_available = 1;
                    }
                    sqlite3_finalize(st);
                    st = NULL;
                }
            }
            sqlite3_close(db);
        }
    }

    json_object_object_add(pairing, "available", json_object_new_boolean(1));
    json_object_object_add(pairing, "status_available", json_object_new_boolean(status_available));
    json_object_object_add(pairing, "status_error", json_object_new_string(status_available ? "" : status_error));
    json_object_object_add(pairing, "paired_known", json_object_new_boolean(status_available));
    json_object_object_add(pairing, "pending_known", json_object_new_boolean(status_available));
    json_object_object_add(pairing, "paired", json_object_new_boolean(status_available && paired > 0));
    json_object_object_add(pairing, "paired_devices", json_object_new_int(status_available ? paired : 0));
    json_object_object_add(pairing, "pending_devices", json_object_new_int(status_available ? pending : 0));
    json_object_object_add(pairing, "can_init_pairing", json_object_new_boolean(1));
    json_object_object_add(pairing, "requires_pair_init", json_object_new_boolean(1));
    json_object_object_add(pairing, "readonly_status", json_object_new_boolean(1));
    json_object_object_add(pairing, "qr_payload_available", json_object_new_boolean(0));
    json_object_object_add(pairing, "pair_id", json_object_new_string(""));
    json_object_object_add(pairing, "pair_code", json_object_new_string(""));
    json_object_object_add(pairing, "qr_payload", json_object_new_string(""));
    json_object_object_add(pairing, "pair_init_api", json_object_new_string("/api/v1/auth/pair/init"));
    json_object_object_add(pairing, "pair_cancel_api", json_object_new_string("/api/v1/auth/pair/cancel"));
    json_object_object_add(pairing, "pair_id_field", json_object_new_string("pair_id"));
    json_object_object_add(pairing, "pair_code_field", json_object_new_string("code"));
    json_object_object_add(pairing, "app_device_id_field", json_object_new_string("app_device_id"));
    json_object_object_add(pairing, "pair_ttl_s", json_object_new_int(300));
    json_object_object_add(pairing, "requires_local_confirm", json_object_new_boolean(1));
    return pairing;
}

static void nc_setup_add_isp_fields(struct json_object *d)
{
    if (!json_object_object_get(d, "recommended_isp"))
        json_object_object_add(d, "recommended_isp", json_object_new_string(""));
    if (!json_object_object_get(d, "isp_name"))
        json_object_object_add(d, "isp_name", json_object_new_string(""));
    if (!json_object_object_get(d, "isp_logo"))
        json_object_object_add(d, "isp_logo", json_object_new_string(""));
    if (!json_object_object_get(d, "isp_confidence"))
        json_object_object_add(d, "isp_confidence", json_object_new_int(0));
    if (!json_object_object_get(d, "isp_evidence"))
        json_object_object_add(d, "isp_evidence", json_object_new_array());
}

static void nc_setup_add_isp_detection(struct json_object *d,
                                       const char *wan_id,
                                       const char *runtime_ifname)
{
    jmx_isp_entry_t isp;
    struct json_object *evidence = json_object_new_array();
    struct json_object *ev = json_object_new_object();
    int ok;

    if (!d)
        return;
    ok = jmx_isp_detect_sync(wan_id, runtime_ifname, &isp) == 0;
    if (ev) {
        json_object_object_add(ev, "source", json_object_new_string("public_ip_carrier_prefix"));
        json_object_object_add(ev, "wan_id", json_object_new_string(wan_id ? wan_id : ""));
        json_object_object_add(ev, "interface", json_object_new_string(runtime_ifname ? runtime_ifname : ""));
        json_object_object_add(ev, "public_ip", json_object_new_string(isp.public_ip));
        json_object_object_add(ev, "carrier", json_object_new_string(isp.carrier_key));
        json_object_object_add(ev, "carrier_id", json_object_new_int(isp.isp));
        json_object_object_add(ev, "detail", json_object_new_string(isp.source));
        json_object_object_add(ev, "confidence", json_object_new_int(isp.confidence));
        if (!ok && isp.error[0])
            json_object_object_add(ev, "error", json_object_new_string(isp.error));
        json_object_array_add(evidence, ev);
    }
    json_object_object_add(d, "nat_public_ip", json_object_new_string(isp.public_ip));
    json_object_object_add(d, "recommended_isp", json_object_new_string(ok ? isp.carrier_key : "unknown"));
    json_object_object_add(d, "isp_name", json_object_new_string(ok ? isp.carrier_name : "Unknown"));
    json_object_object_add(d, "isp_logo", json_object_new_string(""));
    json_object_object_add(d, "isp_confidence", json_object_new_int(ok ? isp.confidence : 0));
    json_object_object_add(d, "isp_evidence", evidence);
}

static int nc_setup_ascii_tolower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

static int nc_setup_contains_i(const char *s, const char *needle)
{
    size_t nl;

    if (!s || !needle || !needle[0])
        return 0;
    nl = strlen(needle);
    for (; *s; s++) {
        size_t i;

        for (i = 0; i < nl; i++) {
            if (!s[i] || nc_setup_ascii_tolower((unsigned char)s[i]) !=
                nc_setup_ascii_tolower((unsigned char)needle[i]))
                break;
        }
        if (i == nl)
            return 1;
    }
    return 0;
}

struct nc_setup_isp_hint {
    const char *id;
    const char *name;
    const char *logo;
    int confidence;
    const char *keywords[8];
};

static const struct nc_setup_isp_hint nc_setup_isp_hints[] = {
    { "china_telecom", "中国电信", "", 88, { "chinanet", "china telecom", "telecom", "ctcc", "cn2", "电信", NULL } },
    { "china_unicom", "中国联通", "", 86, { "china unicom", "unicom", "cucc", "联通", NULL } },
    { "china_mobile", "中国移动", "", 86, { "china mobile", "cmcc", "mobile", "移动", NULL } },
    { "china_broadnet", "中国广电", "", 82, { "china broadnet", "broadnet", "cbn", "广电", NULL } },
    { "cernet", "教育网", "", 82, { "cernet", "教育网", NULL } },
    { "greatwall_broadband", "长城宽带", "", 78, { "greatwall", "great wall", "gwbn", "长城", NULL } },
};

static void nc_setup_add_isp_inference(struct json_object *d,
                                       struct json_object *evidence,
                                       const char *recommended_proto)
{
    const struct nc_setup_isp_hint *best = NULL;
    const char *best_detail = "";
    const char *best_keyword = "";
    const char *best_source = "";
    const char *best_iface = "";
    struct json_object *isp_ev;
    int best_confidence = 0;
    int i, n;

    if (!d || nc_json_str_def(d, "recommended_isp", "")[0] ||
        !evidence || !json_object_is_type(evidence, json_type_array))
        return;

    n = (int)json_object_array_length(evidence);
    for (i = 0; i < n; i++) {
        struct json_object *e = json_object_array_get_idx(evidence, i);
        const char *type, *detail, *iface;
        size_t hi;

        if (!e || !json_object_is_type(e, json_type_object))
            continue;
        type = nc_json_str_def(e, "type", "");
        detail = nc_json_str_def(e, "detail", "");
        iface = nc_json_str_def(e, "interface", "");
        if (!detail[0])
            continue;
        for (hi = 0; hi < sizeof(nc_setup_isp_hints) / sizeof(nc_setup_isp_hints[0]); hi++) {
            const struct nc_setup_isp_hint *hint = &nc_setup_isp_hints[hi];
            int ki;

            for (ki = 0; hint->keywords[ki]; ki++) {
                int confidence;

                if (!nc_setup_contains_i(detail, hint->keywords[ki]))
                    continue;
                confidence = hint->confidence;
                if (!strcmp(type, "pppoe_pado"))
                    confidence += 5;
                if (recommended_proto && !strcmp(recommended_proto, "pppoe"))
                    confidence += 2;
                if (confidence > 95)
                    confidence = 95;
                if (confidence > best_confidence) {
                    best = hint;
                    best_confidence = confidence;
                    best_detail = detail;
                    best_keyword = hint->keywords[ki];
                    best_source = type[0] ? type : "wan_detection";
                    best_iface = iface;
                }
            }
        }
    }

    if (!best)
        return;

    isp_ev = json_object_new_array();
    if (isp_ev) {
        struct json_object *ev = json_object_new_object();

        if (ev) {
            json_object_object_add(ev, "source", json_object_new_string(best_source));
            json_object_object_add(ev, "interface", json_object_new_string(best_iface));
            json_object_object_add(ev, "detail", json_object_new_string(best_detail));
            json_object_object_add(ev, "matched_keyword", json_object_new_string(best_keyword));
            json_object_object_add(ev, "confidence", json_object_new_int(best_confidence));
            json_object_array_add(isp_ev, ev);
        }
    }

    json_object_object_add(d, "recommended_isp", json_object_new_string(best->id));
    json_object_object_add(d, "isp_name", json_object_new_string(best->name));
    json_object_object_add(d, "isp_logo", json_object_new_string(best->logo));
    json_object_object_add(d, "isp_confidence", json_object_new_int(best_confidence));
    json_object_object_add(d, "isp_evidence", isp_ev ? isp_ev : json_object_new_array());
}

static void nc_setup_wan_detect_ensure_shape(struct json_object *d)
{
    struct json_object *evidence = NULL;

    if (!d)
        return;
    if (!json_object_object_get(d, "state"))
        json_object_object_add(d, "state", json_object_new_string("idle"));
    if (!json_object_object_get(d, "started_at"))
        json_object_object_add(d, "started_at", json_object_new_int64(0));
    if (!json_object_object_get(d, "finished_at"))
        json_object_object_add(d, "finished_at", json_object_new_int64(0));
    if (!json_object_object_get(d, "elapsed_ms"))
        json_object_object_add(d, "elapsed_ms", json_object_new_int64(0));
    if (!json_object_object_get(d, "candidates"))
        json_object_object_add(d, "candidates", json_object_new_array());
    if (!json_object_object_get(d, "recommended_device"))
        json_object_object_add(d, "recommended_device", json_object_new_string(""));
    if (!json_object_object_get(d, "recommended_proto"))
        json_object_object_add(d, "recommended_proto", json_object_new_string(""));
    if (!json_object_object_get(d, "confidence"))
        json_object_object_add(d, "confidence", json_object_new_int(0));
    if (!json_object_object_get(d, "evidence"))
        json_object_object_add(d, "evidence", json_object_new_array());
    if (!json_object_object_get(d, "errors"))
        json_object_object_add(d, "errors", json_object_new_array());
    json_object_object_get_ex(d, "evidence", &evidence);
    nc_setup_add_isp_inference(d, evidence, nc_json_str_def(d, "recommended_proto", ""));
    nc_setup_add_isp_fields(d);
}

static int nc_setup_sysfs_read_ll(const char *ifname, const char *leaf, long long *out)
{
    char path[PATH_MAX];
    char buf[128] = "";

    if (!ifname || !leaf || !out || !nc_iface_name_ok(ifname))
        return -1;
    snprintf(path, sizeof(path), "/sys/class/net/%s/%s", ifname, leaf);
    nc_setup_read_first_line(path, buf, sizeof(buf));
    if (!buf[0])
        return -1;
    *out = atoll(buf);
    return 0;
}

static int nc_setup_lan_port_member(const char *ifname)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (!ifname || !ifname[0])
        return 0;
    if (nc_prepare(&st, "SELECT 1 FROM lan_port WHERE port=?1 LIMIT 1") == 0) {
        sqlite3_bind_text(st, 1, ifname, -1, SQLITE_TRANSIENT);
        found = sqlite3_step(st) == SQLITE_ROW;
        sqlite3_finalize(st);
    }
    return found;
}

static int nc_setup_if_virtual(const char *name)
{
    char path[PATH_MAX];

    if (!name || !name[0])
        return 1;
    if (!strcmp(name, "lo") || !strncmp(name, "br-", 3) || !strncmp(name, "docker", 6) ||
        !strncmp(name, "veth", 4) || !strncmp(name, "tun", 3) || !strncmp(name, "tap", 3) ||
        !strncmp(name, "wg", 2) || !strncmp(name, "ppp", 3) || !strncmp(name, "ifb", 3) || strchr(name, '.'))
        return 1;
    snprintf(path, sizeof(path), "/sys/class/net/%s/device", name);
    return access(path, F_OK) != 0;
}

static struct json_object *nc_setup_load_wan_detect(void)
{
    sqlite3_stmt *st = NULL;
    struct json_object *o = NULL;

    if (nc_prepare(&st, "SELECT result_json FROM setup_wan_detect WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW)
            o = nc_json_parse_object_or_empty((const char *)sqlite3_column_text(st, 0));
        sqlite3_finalize(st);
    }
    if (!o)
        o = json_object_new_object();
    nc_setup_wan_detect_ensure_shape(o);
    return o;
}

static struct json_object *nc_setup_wan_detect_running_json(sqlite3_int64 started)
{
    struct json_object *d = json_object_new_object();

    json_object_object_add(d, "state", json_object_new_string("running"));
    json_object_object_add(d, "started_at", json_object_new_int64(started));
    json_object_object_add(d, "finished_at", json_object_new_int64(0));
    json_object_object_add(d, "elapsed_ms", json_object_new_int64(0));
    json_object_object_add(d, "candidates", json_object_new_array());
    json_object_object_add(d, "recommended_device", json_object_new_string(""));
    json_object_object_add(d, "recommended_proto", json_object_new_string(""));
    json_object_object_add(d, "confidence", json_object_new_int(0));
    json_object_object_add(d, "evidence", json_object_new_array());
    json_object_object_add(d, "errors", json_object_new_array());
    nc_setup_add_isp_fields(d);
    return d;
}

static int nc_setup_mark_wan_detect_running(sqlite3_int64 started, struct json_object *result)
{
    sqlite3_stmt *st = NULL;
    char *json = nc_json_plain_dup(result, "{}");
    int rc = -1;

    if (!json)
        return -1;
    if (nc_prepare(&st, "UPDATE setup_wan_detect SET state='running',started_at=?1,finished_at=0,recommended_device='',recommended_proto='',confidence=0,result_json=?2,error='',updated_at=?1 WHERE id=1") == 0) {
        sqlite3_bind_int64(st, 1, started);
        sqlite3_bind_text(st, 2, json, -1, SQLITE_TRANSIENT);
        rc = nc_step_done(st) == 0 && nc_sqlite_changes() > 0 ? 0 : -1;
        sqlite3_finalize(st);
    }
    free(json);
    return rc;
}

static int nc_setup_store_wan_detect(struct json_object *result, const char *state,
                                     const char *device, const char *proto,
                                     int confidence, const char *error)
{
    sqlite3_stmt *st = NULL;
    char *json = nc_json_plain_dup(result, "{}");
    int rc = -1;

    if (!json)
        return -1;
    if (nc_prepare(&st, "UPDATE setup_wan_detect SET state=?1,finished_at=?2,recommended_device=?3,recommended_proto=?4,confidence=?5,result_json=?6,error=?7,updated_at=?2 WHERE id=1") == 0) {
        sqlite3_int64 now = nc_now_s();
        sqlite3_bind_text(st, 1, state ? state : "done", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, now);
        sqlite3_bind_text(st, 3, device ? device : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, proto ? proto : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 5, confidence);
        sqlite3_bind_text(st, 6, json, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, error ? error : "", -1, SQLITE_TRANSIENT);
        rc = nc_step_done(st) == 0 && nc_sqlite_changes() > 0 ? 0 : -1;
        sqlite3_finalize(st);
    }
    free(json);
    return rc;
}

static int nc_setup_probe_pppoe(const char *ifname, struct json_object *evidence)
{
    char *argv[] = {
        NC_SETUP_PPPOE_DISCOVERY_PATH, "-I", (char *)ifname, "-t", "2", NULL
    };
    struct jmx_exec_result result;
    char *line;
    char *saveptr = NULL;
    char detail[1024] = "";
    int ok = 0;
    int detail_lines = 0;

    if (!ifname || !nc_iface_name_ok(ifname) ||
        access(NC_SETUP_PPPOE_DISCOVERY_PATH, X_OK) != 0)
        return 0;
    if (jmx_exec_capture(argv[0], argv, NC_SETUP_COMMAND_OUTPUT_MAX,
                         NC_SETUP_COMMAND_TIMEOUT_MS, &result) != 0)
        return 0;
    if (result.timed_out || result.term_signal != 0 || result.truncated ||
        result.exit_code != 0 || !result.output) {
        jmx_exec_result_free(&result);
        return 0;
    }
    for (line = strtok_r(result.output, "\r\n", &saveptr); line;
         line = strtok_r(NULL, "\r\n", &saveptr)) {
        if (strstr(line, "Access-Concentrator") || strstr(line, "AC-Name") ||
            strstr(line, "Service-Name") || strstr(line, "PADO")) {
            size_t used;
            size_t separator_len;
            size_t line_len;
            size_t available;

            ok = 1;
            if (!line[0] || detail_lines >= 4)
                continue;
            used = strlen(detail);
            separator_len = used > 0 ? 2U : 0U;
            available = sizeof(detail) - used - 1;
            if (available <= separator_len)
                continue;
            if (separator_len) {
                memcpy(detail + used, "; ", separator_len);
                used += separator_len;
                available -= separator_len;
            }
            line_len = strlen(line);
            if (line_len > available)
                line_len = available;
            memcpy(detail + used, line, line_len);
            detail[used + line_len] = '\0';
            detail_lines++;
        }
    }
    jmx_exec_result_free(&result);
    if (ok) {
        struct json_object *e = json_object_new_object();
        json_object_object_add(e, "type", json_object_new_string("pppoe_pado"));
        json_object_object_add(e, "interface", json_object_new_string(ifname));
        json_object_object_add(e, "detail", json_object_new_string(detail[0] ? detail : "PPPoE discovery response detected"));
        json_object_array_add(evidence, e);
    }
    return ok;
}

static int nc_setup_probe_dhcp(const char *ifname, struct json_object *evidence)
{
    char cmd[256];

    if (!ifname || !nc_iface_name_ok(ifname))
        return 0;
    snprintf(cmd, sizeof(cmd), "udhcpc -n -q -t 1 -T 2 -i %s -s /bin/true >/tmp/dw-setup-udhcpc.log 2>&1", ifname);
    if (nc_run_quiet(cmd) == 0) {
        struct json_object *e = json_object_new_object();
        json_object_object_add(e, "type", json_object_new_string("dhcp_offer"));
        json_object_object_add(e, "interface", json_object_new_string(ifname));
        json_object_object_add(e, "detail", json_object_new_string("temporary DHCP probe received an offer"));
        json_object_array_add(evidence, e);
        return 1;
    }
    return 0;
}

static struct json_object *nc_setup_detect_wan_run(sqlite3_int64 started)
{
    DIR *dir;
    struct dirent *de;
    struct json_object *d = json_object_new_object();
    struct json_object *candidates = json_object_new_array();
    struct json_object *evidence = json_object_new_array();
    struct json_object *errors = json_object_new_array();
    char best[96] = "";
    const char *recommended_proto = "dhcp";
    int best_score = -1;
    int confidence = 20;
    int saw_dhcp = 0;
    int saw_pppoe = 0;

    dir = opendir("/sys/class/net");
    if (!dir) {
        json_object_array_add(errors, json_object_new_string("cannot_open_sys_class_net"));
        json_object_object_add(d, "state", json_object_new_string("error"));
        json_object_object_add(d, "started_at", json_object_new_int64(started));
        json_object_object_add(d, "finished_at", json_object_new_int64(nc_now_s()));
        json_object_object_add(d, "elapsed_ms", json_object_new_int64((nc_now_s() - started) * 1000));
        json_object_object_add(d, "candidates", candidates);
        json_object_object_add(d, "recommended_device", json_object_new_string(""));
        json_object_object_add(d, "recommended_proto", json_object_new_string(""));
        json_object_object_add(d, "confidence", json_object_new_int(0));
        json_object_object_add(d, "evidence", evidence);
        json_object_object_add(d, "errors", errors);
        nc_setup_add_isp_fields(d);
        nc_setup_store_wan_detect(d, "error", "", "", 0, "cannot_open_sys_class_net");
        return d;
    }

    while ((de = readdir(dir)) != NULL) {
        const char *name = de->d_name;
        char oper_path[PATH_MAX], addr_path[PATH_MAX];
        char oper[32] = "";
        char mac[64] = "";
        long long carrier = 0, rx = 0, tx = 0;
        int score = 0;
        struct json_object *o;

        if (name[0] == '.' || !nc_iface_name_ok(name) || nc_setup_if_virtual(name) || nc_setup_lan_port_member(name))
            continue;
        snprintf(oper_path, sizeof(oper_path), "/sys/class/net/%s/operstate", name);
        snprintf(addr_path, sizeof(addr_path), "/sys/class/net/%s/address", name);
        nc_setup_read_first_line(oper_path, oper, sizeof(oper));
        nc_setup_read_first_line(addr_path, mac, sizeof(mac));
        nc_setup_sysfs_read_ll(name, "carrier", &carrier);
        nc_setup_sysfs_read_ll(name, "statistics/rx_packets", &rx);
        nc_setup_sysfs_read_ll(name, "statistics/tx_packets", &tx);
        if (carrier > 0) score += 80;
        if (!strcmp(oper, "up")) score += 30;
        if (rx + tx > 0) score += 10;

        o = json_object_new_object();
        json_object_object_add(o, "device", json_object_new_string(name));
        json_object_object_add(o, "operstate", json_object_new_string(oper));
        json_object_object_add(o, "carrier", json_object_new_boolean(carrier > 0));
        json_object_object_add(o, "mac", json_object_new_string(mac));
        json_object_object_add(o, "rx_packets", json_object_new_int64(rx));
        json_object_object_add(o, "tx_packets", json_object_new_int64(tx));
        json_object_object_add(o, "score", json_object_new_int(score));
        json_object_array_add(candidates, o);
        if (score > best_score) {
            size_t name_len = strlen(name);
            if (name_len >= sizeof(best))
                continue;
            best_score = score;
            memcpy(best, name, name_len + 1);
        }
    }
    closedir(dir);

    if (best[0]) {
        saw_pppoe = nc_setup_probe_pppoe(best, evidence);
        saw_dhcp = nc_setup_probe_dhcp(best, evidence);
        if (saw_pppoe && !saw_dhcp) {
            recommended_proto = "pppoe";
            confidence = 90;
        } else if (saw_dhcp && !saw_pppoe) {
            recommended_proto = "dhcp";
            confidence = 85;
        } else if (saw_dhcp && saw_pppoe) {
            recommended_proto = "dhcp";
            confidence = 65;
        } else if (best_score >= 80) {
            recommended_proto = "dhcp";
            confidence = 35;
            json_object_array_add(evidence, json_object_new_string("link_up_without_dhcp_or_pppoe_evidence"));
        } else {
            recommended_proto = "dhcp";
            confidence = 20;
            json_object_array_add(evidence, json_object_new_string("no_clear_upstream_evidence"));
        }
    } else {
        json_object_array_add(errors, json_object_new_string("no_wan_candidate"));
        json_object_array_add(evidence, json_object_new_string("no_physical_non_lan_interface_found"));
        confidence = 5;
    }

    json_object_object_add(d, "state", json_object_new_string("done"));
    json_object_object_add(d, "started_at", json_object_new_int64(started));
    json_object_object_add(d, "finished_at", json_object_new_int64(nc_now_s()));
    json_object_object_add(d, "elapsed_ms", json_object_new_int64((nc_now_s() - started) * 1000));
    json_object_object_add(d, "candidates", candidates);
    json_object_object_add(d, "recommended_device", json_object_new_string(best));
    json_object_object_add(d, "recommended_proto", json_object_new_string(recommended_proto));
    json_object_object_add(d, "confidence", json_object_new_int(confidence));
    json_object_object_add(d, "evidence", evidence);
    json_object_object_add(d, "errors", errors);
    nc_setup_add_isp_inference(d, evidence, recommended_proto);
    nc_setup_add_isp_fields(d);
    nc_setup_store_wan_detect(d, "done", best, recommended_proto, confidence, "");
    return d;
}

static void nc_setup_detect_wan_worker(sqlite3_int64 started)
{
    struct json_object *result;

    jmx_netconfig_db_close();
    if (jmx_netconfig_db_init() != 0)
        _exit(1);
    result = nc_setup_detect_wan_run(started);
    if (result)
        json_object_put(result);
    jmx_netconfig_db_close();
    _exit(0);
}

static int nc_setup_detect_wan_spawn(sqlite3_int64 started)
{
    pid_t pid = fork();
    int status = 0;

    if (pid < 0)
        return -1;
    if (pid == 0) {
        pid_t grandchild = fork();

        if (grandchild < 0)
            _exit(1);
        if (grandchild == 0)
            nc_setup_detect_wan_worker(started);
        _exit(0);
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR)
            continue;
        return -1;
    }
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

struct json_object *jmx_setup_detect_wan_start(struct json_object *cfg)
{
    sqlite3_int64 started = nc_now_s();
    struct json_object *d;

    (void)cfg;
    if (jmx_netconfig_db_init() != 0)
        return nc_setup_response(API_CODE_ERROR, json_object_new_object());

    d = nc_setup_wan_detect_running_json(started);
    if (nc_setup_mark_wan_detect_running(started, d) != 0) {
        json_object_put(d);
        return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("wan_detect_start"));
    }

    if (nc_setup_detect_wan_spawn(started) != 0) {
        struct json_object *errors = NULL;

        if (!json_object_object_get_ex(d, "errors", &errors) || !errors ||
            !json_object_is_type(errors, json_type_array)) {
            errors = json_object_new_array();
            json_object_object_add(d, "errors", errors);
        }
        json_object_array_add(errors, json_object_new_string("spawn_failed"));
        json_object_object_add(d, "state", json_object_new_string("error"));
        nc_setup_store_wan_detect(d, "error", "", "", 0, "spawn_failed");
        return nc_setup_response(API_CODE_ERROR, d);
    }

    return nc_setup_response(API_CODE_SUCCESS, d);
}

struct json_object *jmx_setup_detect_wan_status(struct json_object *cfg)
{
    sqlite3_stmt *st = NULL;
    struct json_object *d;

    (void)cfg;
    if (jmx_netconfig_db_init() != 0)
        return nc_setup_response(API_CODE_ERROR, json_object_new_object());
    d = nc_setup_load_wan_detect();
    if (nc_prepare(&st, "SELECT state,started_at,finished_at,recommended_device,recommended_proto,confidence,error FROM setup_wan_detect WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            nc_add_text(d, "state", st, 0);
            json_object_object_add(d, "started_at", json_object_new_int64(sqlite3_column_int64(st, 1)));
            json_object_object_add(d, "finished_at", json_object_new_int64(sqlite3_column_int64(st, 2)));
            nc_add_text(d, "recommended_device", st, 3);
            nc_add_text(d, "recommended_proto", st, 4);
            json_object_object_add(d, "confidence", json_object_new_int(sqlite3_column_int(st, 5)));
            nc_add_text(d, "error", st, 6);
        }
        sqlite3_finalize(st);
    }
    return nc_setup_response(API_CODE_SUCCESS, d);
}

static struct json_object *nc_setup_normalize_wan(struct json_object *cfg)
{
    struct json_object *wan = json_object_new_object();
    struct json_object *detect = NULL;
    struct json_object *dns = NULL;
    const char *proto = nc_json_str_def(cfg, "proto", nc_json_str_def(cfg, "access_mode", ""));
    const char *device = nc_json_str_def(cfg, "device", nc_json_str_def(cfg, "ifname", ""));

    if (!proto[0] || !device[0]) {
        detect = nc_setup_load_wan_detect();
        if (!proto[0]) proto = nc_json_str_def(detect, "recommended_proto", "dhcp");
        if (!device[0]) device = nc_json_str_def(detect, "recommended_device", "wan");
    }
    if (!proto[0]) proto = "dhcp";
    json_object_object_add(wan, "id", json_object_new_string(nc_json_str_def(cfg, "id", "wan")));
    json_object_object_add(wan, "name", json_object_new_string(nc_json_str_def(cfg, "name", "WAN")));
    json_object_object_add(wan, "ifname", json_object_new_string(nc_json_str_def(cfg, "ifname", "wan")));
    json_object_object_add(wan, "device", json_object_new_string(device[0] ? device : "wan"));
    json_object_object_add(wan, "access_mode", json_object_new_string(proto));
    json_object_object_add(wan, "gateway", json_object_new_string(nc_json_str_def(cfg, "gateway", "")));
    json_object_object_add(wan, "ipv6_mode", json_object_new_string(nc_json_str_def(cfg, "ipv6_mode", nc_json_str_def(cfg, "ipv6", "disabled"))));
    json_object_object_add(wan, "mtu", json_object_new_int(nc_json_int_def(cfg, "mtu", !strcmp(proto, "pppoe") ? 1492 : 1500)));
    json_object_object_add(wan, "metric", json_object_new_int(nc_json_int_def(cfg, "metric", 10)));
    json_object_object_add(wan, "role", json_object_new_string("primary"));
    json_object_object_add(wan, "enabled", json_object_new_boolean(1));
    json_object_object_add(wan, "vlan_enabled", json_object_new_boolean(nc_json_bool_def(cfg, "vlan_enabled", nc_json_str_def(cfg, "vlan_id", "")[0] != 0)));
    json_object_object_add(wan, "vlan_id", json_object_new_string(nc_json_str_def(cfg, "vlan_id", "")));
    json_object_object_add(wan, "username", json_object_new_string(nc_json_str_def(cfg, "username", "")));
    json_object_object_add(wan, "password_ref", json_object_new_string(nc_json_str_def(cfg, "password", nc_json_str_def(cfg, "password_ref", ""))));
    if (json_object_object_get_ex(cfg, "dns", &dns) && dns && json_object_is_type(dns, json_type_array)) {
        char *dns_json = nc_json_plain_dup(dns, "[]");
        json_object_object_add(wan, "dns_json", json_object_new_string(dns_json ? dns_json : "[]"));
        free(dns_json);
    } else {
        json_object_object_add(wan, "dns_json", json_object_new_string(nc_json_str_def(cfg, "dns_json", "[]")));
    }
    if (!strcmp(proto, "static")) {
        const char *ip = nc_json_str_def(cfg, "ip", nc_json_str_def(cfg, "ipaddr", ""));
        struct json_object *arr = json_object_new_array();
        if (ip[0]) {
            struct json_object *addr = json_object_new_object();
            json_object_object_add(addr, "ip", json_object_new_string(ip));
            json_object_object_add(addr, "prefix", json_object_new_int(nc_json_int_def(cfg, "prefix", 24)));
            json_object_object_add(addr, "is_primary", json_object_new_boolean(1));
            json_object_object_add(addr, "primary", json_object_new_boolean(1));
            json_object_array_add(arr, addr);
        }
        json_object_object_add(wan, "addresses", arr);
    }
    if (detect)
        json_object_put(detect);
    return wan;
}

static struct json_object *nc_setup_normalize_lan(struct json_object *cfg)
{
    struct json_object *lan = json_object_new_object();
    struct json_object *addrs = json_object_new_array();
    struct json_object *addr = json_object_new_object();
    struct json_object *dhcp = json_object_new_object();
    struct json_object *ports = NULL;
    const char *ip = nc_json_str_def(cfg, "ip", nc_json_str_def(cfg, "ipaddr", "192.168.1.1"));

    json_object_object_add(lan, "id", json_object_new_string(nc_json_str_def(cfg, "id", "lan")));
    json_object_object_add(lan, "name", json_object_new_string(nc_json_str_def(cfg, "name", "LAN")));
    json_object_object_add(lan, "ifname", json_object_new_string(nc_json_str_def(cfg, "ifname", "lan")));
    json_object_object_add(lan, "device", json_object_new_string(nc_json_str_def(cfg, "device", "br-lan")));
    json_object_object_add(lan, "mode", json_object_new_string(nc_json_str_def(cfg, "mode", "bridge")));
    json_object_object_add(lan, "enabled", json_object_new_boolean(1));
    json_object_object_add(addr, "ip", json_object_new_string(ip));
    json_object_object_add(addr, "prefix", json_object_new_int(nc_json_int_def(cfg, "prefix", 24)));
    json_object_object_add(addr, "is_primary", json_object_new_boolean(1));
    json_object_object_add(addr, "primary", json_object_new_boolean(1));
    json_object_array_add(addrs, addr);
    json_object_object_add(lan, "addresses", addrs);
    json_object_object_add(lan, "ipaddr", json_object_new_string(ip));
    json_object_object_add(lan, "prefix", json_object_new_int(nc_json_int_def(cfg, "prefix", 24)));
    json_object_object_add(dhcp, "enabled", json_object_new_boolean(nc_json_bool_def(cfg, "dhcp_enabled", nc_json_bool_def(cfg, "enabled", 1))));
    json_object_object_add(dhcp, "pool_start", json_object_new_string(nc_json_str_def(cfg, "pool_start", "100")));
    json_object_object_add(dhcp, "pool_end", json_object_new_string(nc_json_str_def(cfg, "pool_end", "249")));
    json_object_object_add(dhcp, "lease", json_object_new_int(nc_json_int_def(cfg, "lease", nc_json_int_def(cfg, "lease_minutes", 120))));
    json_object_object_add(dhcp, "gateway", json_object_new_string(nc_json_str_def(cfg, "gateway", ip)));
    json_object_object_add(dhcp, "dns1", json_object_new_string(nc_json_str_def(cfg, "dns1", ip)));
    json_object_object_add(dhcp, "dns2", json_object_new_string(nc_json_str_def(cfg, "dns2", "")));
    json_object_object_add(lan, "dhcp", dhcp);
    if (json_object_object_get_ex(cfg, "ports", &ports) && ports && json_object_is_type(ports, json_type_array))
        json_object_object_add(lan, "ports", json_object_get(ports));
    return lan;
}

static struct json_object *nc_setup_redact_json_secret(struct json_object *src,
                                                       const char *secret_key,
                                                       const char *flag_key)
{
    char *raw = nc_json_plain_dup(src, "{}");
    struct json_object *safe = nc_json_parse_object_or_empty(raw);
    struct json_object *secret = NULL;

    free(raw);
    if (!safe)
        return json_object_new_object();
    if (json_object_object_get_ex(safe, secret_key, &secret) && secret) {
        const char *s = json_object_get_string(secret);
        json_object_object_add(safe, flag_key, json_object_new_boolean(s && s[0]));
        json_object_object_del(safe, secret_key);
    }
    return safe;
}

static struct json_object *nc_setup_redact_wan_response(struct json_object *wan)
{
    return nc_setup_redact_json_secret(wan, "password_ref", "password_set");
}

struct json_object *jmx_setup_status(struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();
    int web_users_known = 0;
    int web_users_table_exists = 0;
    const char *web_users_error = "";
    int web_users = 0;
    int internet = 0;
    int wizard_completed = 0;
    int config_ready = 0;

    (void)cfg;
    if (jmx_netconfig_db_init() != 0)
        return nc_setup_response(API_CODE_ERROR, d);
    web_users = nc_setup_web_user_count(&web_users_known, &web_users_table_exists, &web_users_error);
    nc_setup_add_state_json(d);
    json_object_object_add(d, "web_users_initialized", json_object_new_boolean(web_users > 0));
    json_object_object_add(d, "web_user_count", json_object_new_int(web_users));
    json_object_object_add(d, "web_users_known", json_object_new_boolean(web_users_known));
    json_object_object_add(d, "web_users_table_exists", json_object_new_boolean(web_users_table_exists));
    json_object_object_add(d, "web_users_error", json_object_new_string(web_users_known ? "" : (web_users_error ? web_users_error : "web_users_query_failed")));
    json_object_object_add(d, "device", nc_setup_device_json());
    json_object_object_add(d, "main_asset", json_object_new_string("/luci-static/dreamingwrt/setup/device.png"));
    internet = nc_setup_cmd_success("ping -c 1 -W 1 223.5.5.5 >/dev/null 2>&1 || ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1");
    json_object_object_add(d, "internet", json_object_new_boolean(internet));
    /*
     * `config_ready` and `wizard_completed` are deliberately two different
     * questions, because on real installs they disagree.
     *
     * The install path never runs the wizard, so `initialized` (now also
     * published as `wizard_completed`) stays 0 on a router that has been
     * serving traffic for months with an admin account and a working WAN. A
     * single flag standing for both "the wizard finished" and "this box is
     * configured" is what made a fully configured device report first_run=true
     * and, before the webd gate was added, kept the anonymous setup write
     * channel open on it.
     *
     * So: `wizard_completed` answers "did anyone walk the wizard to the end",
     * and is only ever set by setup_finish. `config_ready` answers "is this box
     * actually usable", inferred from observable facts -- somebody can log in,
     * and either the wizard completed or the device has working upstream
     * connectivity. Consumers that mean "do not treat this as a brand-new
     * device" should read `config_ready`; only the wizard UI should read
     * `wizard_completed`.
     *
     * config_ready deliberately requires web_users_known: an unreadable user
     * table must not be reported as a configured device.
     *
     * Published on setup_status only, not on setup_progress/setup_finish, which
     * share nc_setup_add_state_json(): deriving it costs a web_users query and a
     * connectivity probe, and progress is polled during the wizard. Consumers
     * that need it should read setup_status. `wizard_completed` has no such cost
     * and is published everywhere the state block appears.
     */
    wizard_completed = nc_json_bool_def(d, "initialized", 0);
    config_ready = web_users_known && web_users > 0 && (wizard_completed || internet);
    json_object_object_add(d, "config_ready", json_object_new_boolean(config_ready));
    json_object_object_add(d, "wan_link", json_object_new_string("unknown"));
    json_object_object_add(d, "supported_wifi", json_object_new_boolean(nc_setup_wifi_capability("wifi")));
    json_object_object_add(d, "backup_available", json_object_new_boolean(access("/etc/dreamingwrt/backup", R_OK) == 0));
    json_object_object_add(d, "security", nc_setup_security_json());
    json_object_object_add(d, "app_pairing", nc_setup_app_pairing_json());
    json_object_object_add(d, "llm", nc_setup_llm_json());
    json_object_object_add(d, "wan_detection", nc_setup_load_wan_detect());
    return nc_setup_response(API_CODE_SUCCESS, d);
}

struct json_object *jmx_setup_start(struct json_object *cfg)
{
    sqlite3_stmt *st = NULL;
    struct json_object *d = json_object_new_object();
    struct json_object *detect_resp = NULL;
    struct json_object *detect_data = NULL;
    char setup_id[96];
    sqlite3_int64 now = nc_now_s();
    const char *source = cfg ? nc_json_str_def(cfg, "source", "luci") : "luci";
    const char *version = cfg ? nc_json_str_def(cfg, "version", OAF_VERSION) : OAF_VERSION;

    if (jmx_netconfig_db_init() != 0)
        return nc_setup_response(API_CODE_ERROR, d);
    if (nc_setup_is_initialized()) {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("wizard_already_initialized"));
        return nc_setup_response(API_CODE_ERROR, d);
    }
    snprintf(setup_id, sizeof(setup_id), "setup-%lld", (long long)now);
    if (nc_prepare(&st, "UPDATE setup_state SET setup_id=?1,started_at=?2,source=?3,setup_version=?4,current_step='intro',last_apply_id='',last_apply_state='idle',last_apply_error='',last_apply_at=0,last_test_ok=0,last_test_json='{}',updated_at=?2 WHERE id=1") == 0) {
        sqlite3_bind_text(st, 1, setup_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, now);
        sqlite3_bind_text(st, 3, source, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, version, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0 || nc_sqlite_changes() <= 0) {
            sqlite3_finalize(st);
            return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("setup_start"));
        }
        sqlite3_finalize(st);
    } else {
        return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("setup_start"));
    }
    detect_resp = jmx_setup_detect_wan_start(NULL);
    json_object_object_add(d, "setup_id", json_object_new_string(setup_id));
    json_object_object_add(d, "started_at", json_object_new_int64(now));
    json_object_object_add(d, "source", json_object_new_string(source));
    json_object_object_add(d, "version", json_object_new_string(version));
    if (detect_resp && json_object_object_get_ex(detect_resp, "data", &detect_data) && detect_data)
        json_object_object_add(d, "wan_detection", json_object_get(detect_data));
    if (detect_resp)
        json_object_put(detect_resp);
    return nc_setup_response(API_CODE_SUCCESS, d);
}

struct json_object *jmx_setup_save_device(struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();
    struct json_object *payload = json_object_new_object();
    struct json_object *general = json_object_new_object();
    struct json_object *safe = json_object_new_object();
    const char *admin_username = nc_json_str_def(cfg, "admin_username", "root");
    int has_admin_password = nc_json_str_def(cfg, "admin_password", "")[0] != 0;
    struct json_object *guard;

    if (jmx_netconfig_db_init() != 0 || !cfg)
        return nc_setup_response(API_CODE_ERROR, d);
    /*
     * Guarded ahead of the drafts below: this path can carry an admin
     * credential, so it is the least acceptable one to leave reachable on a
     * router that is already in service.
     */
    guard = nc_setup_guard_initialized(cfg, d);
    if (guard) {
        json_object_put(payload);
        json_object_put(general);
        json_object_put(safe);
        return guard;
    }
    json_object_object_add(general, "hostname", json_object_new_string(nc_json_str_def(cfg, "hostname", "")));
    json_object_object_add(general, "description", json_object_new_string(nc_json_str_def(cfg, "description", nc_json_str_def(cfg, "remark", ""))));
    json_object_object_add(general, "note", json_object_new_string(nc_json_str_def(cfg, "note", "")));
    json_object_object_add(payload, "general", general);
    if (has_admin_password) {
        struct json_object *admin = json_object_new_object();
        json_object_object_add(admin, "username", json_object_new_string(admin_username));
        json_object_object_add(admin, "password", json_object_new_string(nc_json_str_def(cfg, "admin_password", "")));
        json_object_object_add(payload, "admin", admin);
    }
    if (nc_setup_save_draft("device", payload) != 0) {
        json_object_put(payload);
        json_object_put(safe);
        json_object_put(d);
        return nc_setup_response(API_CODE_ERROR, nc_setup_draft_save_error("device"));
    }
    if (nc_setup_update_step("device") != 0) {
        json_object_put(payload);
        json_object_put(safe);
        json_object_put(d);
        return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("save_device_step"));
    }
    json_object_object_add(safe, "general", json_object_get(general));
    if (has_admin_password) {
        struct json_object *admin_safe = json_object_new_object();
        json_object_object_add(admin_safe, "username", json_object_new_string(admin_username));
        json_object_object_add(admin_safe, "password_set", json_object_new_boolean(1));
        json_object_object_add(safe, "admin", admin_safe);
    }
    json_object_object_add(d, "draft", safe);
    json_object_put(payload);
    return nc_setup_response(API_CODE_SUCCESS, d);
}

struct json_object *jmx_setup_save_wan(struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();
    struct json_object *wan;
    struct json_object *errors;
    struct json_object *guard;

    if (jmx_netconfig_db_init() != 0 || !cfg)
        return nc_setup_response(API_CODE_ERROR, d);
    guard = nc_setup_guard_initialized(cfg, d);
    if (guard)
        return guard;
    wan = nc_setup_normalize_wan(cfg);
    errors = jmx_netconfig_wan_validate(wan);
    if (errors) {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "validated", json_object_new_boolean(0));
        json_object_object_add(d, "errors", errors);
        json_object_object_add(d, "normalized", nc_setup_redact_wan_response(wan));
        json_object_put(wan);
        return nc_setup_response(API_CODE_ERROR, d);
    }
    if (nc_setup_save_draft("wan", wan) != 0) {
        json_object_put(wan);
        json_object_put(d);
        return nc_setup_response(API_CODE_ERROR, nc_setup_draft_save_error("wan"));
    }
    if (nc_setup_update_step("wan") != 0) {
        json_object_put(wan);
        json_object_put(d);
        return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("save_wan_step"));
    }
    json_object_object_add(d, "validated", json_object_new_boolean(1));
    json_object_object_add(d, "normalized", nc_setup_redact_wan_response(wan));
    json_object_object_add(d, "detection", nc_setup_load_wan_detect());
    json_object_put(wan);
    return nc_setup_response(API_CODE_SUCCESS, d);
}

struct json_object *jmx_setup_test_wan(struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();
    struct json_object *stages = json_object_new_object();
    struct json_object *wan = NULL;
    const char *device = cfg ? nc_json_str_def(cfg, "device", "") : "";
    const char *ifname = cfg ? nc_json_str_def(cfg, "ifname", "") : "";
    const char *id = cfg ? nc_json_str_def(cfg, "id", "") : "";
    long long carrier = 0;
    int link_ok = 0;
    int addr_ok = 0;
    int dns_ok;
    int ntp_ok;
    int public_ok;
    int ok;

    if (!device[0]) {
        wan = nc_setup_load_draft("wan");
        device = nc_json_str_def(wan, "device", "");
        ifname = nc_json_str_def(wan, "ifname", "");
        id = nc_json_str_def(wan, "id", "");
    }
    if (device[0] && nc_iface_name_ok(device)) {
        link_ok = nc_setup_sysfs_read_ll(device, "carrier", &carrier) == 0 && carrier > 0;
        addr_ok = nc_setup_wan_addr_ok(device, ifname, id);
    }
    dns_ok = nc_setup_cmd_success("nslookup openwrt.org 127.0.0.1 >/dev/null 2>&1 || nslookup openwrt.org 223.5.5.5 >/dev/null 2>&1");
    ntp_ok = nc_setup_cmd_success("date +%s >/dev/null 2>&1");
    public_ok = nc_setup_cmd_success("ping -c 1 -W 2 223.5.5.5 >/dev/null 2>&1 || ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1");
    ok = device[0] && link_ok && addr_ok && dns_ok && public_ok;
    nc_setup_add_isp_detection(d, id[0] ? id : "wan", device);
    json_object_object_add(stages, "device", json_object_new_boolean(device[0] != 0));
    json_object_object_add(stages, "link", json_object_new_boolean(link_ok));
    json_object_object_add(stages, "address", json_object_new_boolean(addr_ok));
    json_object_object_add(stages, "dns", json_object_new_boolean(dns_ok));
    json_object_object_add(stages, "ntp", json_object_new_boolean(ntp_ok));
    json_object_object_add(stages, "public_connectivity", json_object_new_boolean(public_ok));
    json_object_object_add(stages, "nat_public_ip", json_object_new_string(nc_json_str_def(d, "nat_public_ip", "")));
    json_object_object_add(d, "device", json_object_new_string(device));
    json_object_object_add(d, "ifname", json_object_new_string(ifname));
    json_object_object_add(d, "stages", stages);
    json_object_object_add(d, "ok", json_object_new_boolean(ok));
    if (!device[0])
        json_object_object_add(d, "error", json_object_new_string("missing_wan_device"));
    else if (!link_ok)
        json_object_object_add(d, "error", json_object_new_string("wan_link_down"));
    else if (!addr_ok)
        json_object_object_add(d, "error", json_object_new_string("wan_address_missing"));
    else if (!dns_ok)
        json_object_object_add(d, "error", json_object_new_string("dns_failed"));
    else if (!public_ok)
        json_object_object_add(d, "error", json_object_new_string("connectivity_failed"));
    if (nc_setup_set_last_test(d, ok) != 0) {
        struct json_object *err = nc_setup_state_error("last_test");
        json_object_object_add(err, "test", d);
        if (wan)
            json_object_put(wan);
        return nc_setup_response(API_CODE_ERROR, err);
    }
    if (wan)
        json_object_put(wan);
    return nc_setup_response(ok ? API_CODE_SUCCESS : API_CODE_ERROR, d);
}

struct json_object *jmx_setup_save_lan(struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();
    struct json_object *lan;
    struct json_object *errors;
    struct json_object *guard;

    if (jmx_netconfig_db_init() != 0 || !cfg)
        return nc_setup_response(API_CODE_ERROR, d);
    guard = nc_setup_guard_initialized(cfg, d);
    if (guard)
        return guard;
    lan = nc_setup_normalize_lan(cfg);
    errors = jmx_netconfig_lan_validate(lan);
    if (errors) {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "validated", json_object_new_boolean(0));
        json_object_object_add(d, "errors", errors);
        json_object_object_add(d, "normalized", lan);
        return nc_setup_response(API_CODE_ERROR, d);
    }
    if (nc_setup_save_draft("lan", lan) != 0) {
        json_object_put(lan);
        json_object_put(d);
        return nc_setup_response(API_CODE_ERROR, nc_setup_draft_save_error("lan"));
    }
    if (nc_setup_update_step("lan") != 0) {
        json_object_put(lan);
        json_object_put(d);
        return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("save_lan_step"));
    }
    json_object_object_add(d, "validated", json_object_new_boolean(1));
    json_object_object_add(d, "normalized", lan);
    return nc_setup_response(API_CODE_SUCCESS, d);
}

struct json_object *jmx_setup_save_wifi(struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();

    if (jmx_netconfig_db_init() != 0 || !cfg)
        return nc_setup_response(API_CODE_ERROR, d);
    json_object_put(d);
    if (!nc_setup_wifi_capability("save_config"))
        return nc_setup_response(API_CODE_ERROR,
            nc_setup_wifi_capability_error("save_config",
                "transactional_secret_safe_save_pending"));

    /* No setup Wi-Fi draft may be persisted until secret-safe storage exists. */
    return nc_setup_response(API_CODE_ERROR,
        nc_setup_wifi_capability_error("save_config",
            "secret_safe_setup_storage_pending"));
}

struct json_object *jmx_setup_apply(struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();
    struct json_object *steps = json_object_new_array();
    struct json_object *device;
    struct json_object *wan;
    struct json_object *lan;
    struct json_object *wifi;
    char apply_id[96];
    int ok = 1;
    int has_device;
    int has_wan;
    int has_lan;
    int has_wifi;
    int wifi_save_supported;
    int wifi_apply_supported;
    struct json_object *guard;

    if (jmx_netconfig_db_init() != 0)
        return nc_setup_response(API_CODE_ERROR, d);
    /*
     * This is the write that reaches the live network configuration, so it is
     * the one an accidental `ubus call` on a working router would hurt most.
     */
    guard = nc_setup_guard_initialized(cfg, d);
    if (guard) {
        json_object_put(steps);
        return guard;
    }
    device = nc_setup_load_draft("device");
    wan = nc_setup_load_draft("wan");
    lan = nc_setup_load_draft("lan");
    wifi = nc_setup_load_draft("wifi");
    has_device = nc_json_object_has_keys(device);
    has_wan = nc_json_object_has_keys(wan);
    has_lan = nc_json_object_has_keys(lan);
    has_wifi = nc_json_object_has_keys(wifi);
    wifi_save_supported = !has_wifi || nc_setup_wifi_capability("save_config");
    wifi_apply_supported = !has_wifi || nc_setup_wifi_capability("apply_config");

    /* Preflight every requested resource before mutating device, WAN, or LAN. */
    if (has_wifi && (!wifi_save_supported || !wifi_apply_supported)) {
        const char *capability = !wifi_save_supported ?
                                 "save_config" : "apply_config";
        const char *reason = !strcmp(capability, "save_config") ?
                             "transactional_secret_safe_save_pending" :
                             "transactional_apply_readback_pending";
        struct json_object *error = nc_setup_wifi_capability_error(capability, reason);

        json_object_object_add(error, "preflight", json_object_new_boolean(1));
        json_object_object_add(error, "partial_apply", json_object_new_boolean(0));
        json_object_put(steps);
        json_object_put(d);
        json_object_put(device);
        json_object_put(wan);
        json_object_put(lan);
        json_object_put(wifi);
        return nc_setup_response(API_CODE_ERROR, error);
    }

    snprintf(apply_id, sizeof(apply_id), "setup-apply-%lld", (long long)nc_now_s());
    if (nc_setup_set_apply_state(apply_id, "applying", "") != 0) {
        json_object_put(steps);
        json_object_put(d);
        json_object_put(device);
        json_object_put(wan);
        json_object_put(lan);
        json_object_put(wifi);
        return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("apply_start"));
    }
    if (nc_setup_clear_last_test() != 0) {
        json_object_put(steps);
        json_object_put(d);
        json_object_put(device);
        json_object_put(wan);
        json_object_put(lan);
        json_object_put(wifi);
        return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("apply_clear_last_test"));
    }

    if (!has_device && !has_wan && !has_lan && !has_wifi) {
        json_object_object_add(d, "progress_id", json_object_new_string(apply_id));
        json_object_object_add(d, "steps", steps);
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("no_setup_draft_to_apply"));
        json_object_object_add(d, "message", json_object_new_string("setup.apply requires at least one saved setup draft"));
        if (nc_setup_set_apply_state("", "error", "no_setup_draft_to_apply") != 0 ||
            nc_setup_update_step("apply_error") != 0) {
            json_object_put(device);
            json_object_put(wan);
            json_object_put(lan);
            json_object_put(wifi);
            return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("apply_missing_drafts_state"));
        }
        json_object_put(device);
        json_object_put(wan);
        json_object_put(lan);
        json_object_put(wifi);
        return nc_setup_response(API_CODE_ERROR, d);
    }

    if (!has_wan || !has_lan) {
        struct json_object *missing = json_object_new_array();

        if (!has_wan)
            json_object_array_add(missing, json_object_new_string("wan"));
        if (!has_lan)
            json_object_array_add(missing, json_object_new_string("lan"));
        json_object_object_add(d, "progress_id", json_object_new_string(apply_id));
        json_object_object_add(d, "steps", steps);
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("missing_required_setup_drafts"));
        json_object_object_add(d, "missing", missing);
        json_object_object_add(d, "message", json_object_new_string("setup.apply requires saved WAN and LAN drafts"));
        if (nc_setup_set_apply_state("", "error", "missing_required_setup_drafts") != 0 ||
            nc_setup_update_step("apply_error") != 0) {
            json_object_put(device);
            json_object_put(wan);
            json_object_put(lan);
            json_object_put(wifi);
            return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("apply_required_drafts_state"));
        }
        json_object_put(device);
        json_object_put(wan);
        json_object_put(lan);
        json_object_put(wifi);
        return nc_setup_response(API_CODE_ERROR, d);
    }

    if (has_device) {
        static const char *const sections[] = {
            "general", "advanced", "ssh", "dreamingwrt", NULL
        };
        struct json_object *settings_payload = json_object_new_object();
        struct json_object *settings;

        for (int i = 0; settings_payload && sections[i]; i++) {
            struct json_object *section = NULL;

            if (json_object_object_get_ex(device, sections[i], &section) && section)
                json_object_object_add(settings_payload, sections[i],
                                       json_object_get(section));
        }
        settings = settings_payload ?
            jmx_system_settings_save_apply_result(settings_payload) : NULL;
        if (settings_payload)
            json_object_put(settings_payload);
        int rc = nc_setup_api_response_ok(settings) ? 0 : -1;
        struct json_object *s = json_object_new_object();
        json_object_object_add(s, "step", json_object_new_string("device"));
        json_object_object_add(s, "ok", json_object_new_boolean(rc == 0));
        json_object_object_add(s, "detail", settings ? settings : json_object_new_object());
        json_object_array_add(steps, s);
        if (rc != 0) ok = 0;
        if (ok) {
            struct json_object *admin = NULL;
            if (json_object_object_get_ex(device, "admin", &admin) && admin) {
                struct json_object *out = json_object_new_object();
                int prc = jmx_admin_password_set_ex(admin, out, 1);
                struct json_object *ps = json_object_new_object();
                json_object_object_add(ps, "step", json_object_new_string("admin_password"));
                json_object_object_add(ps, "ok", json_object_new_boolean(prc == 0));
                json_object_object_add(ps, "detail", out);
                json_object_array_add(steps, ps);
                if (prc != 0) ok = 0;
            }
        }
    }
    if (ok && has_wan) {
        const char *id = nc_json_str_def(wan, "id", "wan");
        int rc = jmx_netconfig_wan_set(wan);
        if (rc == 0) rc = jmx_netconfig_apply_wan(id);
        struct json_object *s = json_object_new_object();
        json_object_object_add(s, "step", json_object_new_string("wan"));
        json_object_object_add(s, "id", json_object_new_string(id));
        json_object_object_add(s, "ok", json_object_new_boolean(rc == 0));
        json_object_object_add(s, "rc", json_object_new_int(rc));
        json_object_array_add(steps, s);
        if (rc != 0) ok = 0;
    }
    if (ok && has_lan) {
        const char *id = nc_json_str_def(lan, "id", "lan");
        int rc = jmx_netconfig_lan_set(lan);
        if (rc == 0) rc = jmx_netconfig_apply_lan(id);
        struct json_object *s = json_object_new_object();
        json_object_object_add(s, "step", json_object_new_string("lan"));
        json_object_object_add(s, "id", json_object_new_string(id));
        json_object_object_add(s, "ok", json_object_new_boolean(rc == 0));
        json_object_object_add(s, "rc", json_object_new_int(rc));
        json_object_array_add(steps, s);
        if (rc != 0) ok = 0;
    }
    if (ok && has_wifi) {
        struct json_object *apply_cfg = json_object_new_object();
        struct json_object *apply_resp = NULL;
        int rc = jmx_wifi_config_save(wifi);
        int apply_ok = 0;
        json_object_object_add(apply_cfg, "reload", json_object_new_boolean(1));
        if (rc == 0) {
            apply_resp = jmx_wifi_config_apply(apply_cfg);
            apply_ok = nc_setup_api_response_ok(apply_resp);
        }
        struct json_object *s = json_object_new_object();
        json_object_object_add(s, "step", json_object_new_string("wifi"));
        json_object_object_add(s, "ok", json_object_new_boolean(rc == 0 && apply_ok));
        json_object_object_add(s, "saved", json_object_new_boolean(rc == 0));
        json_object_object_add(s, "applied", json_object_new_boolean(apply_ok));
        if (apply_resp) json_object_object_add(s, "apply", apply_resp);
        json_object_array_add(steps, s);
        json_object_put(apply_cfg);
        if (rc != 0 || !apply_ok) ok = 0;
    }
    if (ok) {
        struct json_object *test = jmx_setup_test_wan(wan);
        struct json_object *test_data = NULL;
        ok = 0;
        if (test && json_object_object_get_ex(test, "data", &test_data) && test_data)
            ok = nc_json_bool_def(test_data, "ok", 0);
        json_object_object_add(d, "wan_test", test ? test : json_object_new_object());
    }
    json_object_object_add(d, "progress_id", json_object_new_string(apply_id));
    json_object_object_add(d, "steps", steps);
    json_object_object_add(d, "ok", json_object_new_boolean(ok));
    if (nc_setup_set_apply_state("", ok ? "ready" : "error", ok ? "" : "apply_or_test_failed") != 0 ||
        nc_setup_update_step(ok ? "ready" : "apply_error") != 0) {
        json_object_put(device);
        json_object_put(wan);
        json_object_put(lan);
        json_object_put(wifi);
        return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("apply_finish_state"));
    }
    json_object_put(device);
    json_object_put(wan);
    json_object_put(lan);
    json_object_put(wifi);
    return nc_setup_response(ok ? API_CODE_SUCCESS : API_CODE_ERROR, d);
}

struct json_object *jmx_setup_progress(struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();

    (void)cfg;
    if (jmx_netconfig_db_init() != 0)
        return nc_setup_response(API_CODE_ERROR, d);
    nc_setup_add_state_json(d);
    return nc_setup_response(API_CODE_SUCCESS, d);
}

struct json_object *jmx_setup_finish(struct json_object *cfg)
{
    sqlite3_stmt *st = NULL;
    struct json_object *d = json_object_new_object();
    sqlite3_int64 now = nc_now_s();
    const char *completed_by = cfg ? nc_json_str_def(cfg, "completed_by", nc_json_str_def(cfg, "actor", "setup")) : "setup";
    char version[96] = "";
    int can_finish = 0;
    int adopt_existing = 0;
    char tsbuf[32];

    if (jmx_netconfig_db_init() != 0)
        return nc_setup_response(API_CODE_ERROR, d);
    /*
     * Convergence path for devices that were configured without ever walking
     * the wizard.
     *
     * The five conditions below describe a wizard run: a draft was applied, the
     * WAN test passed, and the apply happened during this session. An install
     * that never started the wizard satisfies none of them and can therefore
     * never record completion, which leaves `initialized` at 0 forever on a
     * router that is demonstrably in service. That is the state 30.1 was found
     * in: two web users, working WAN, current_step still 'intro'.
     *
     * `adopt_existing` lets such a device record what is already true instead of
     * pretending a wizard ran. It is not a way to skip the wizard on a new box:
     * it requires the caller to have proved an identity (the same vouch webd
     * attaches after its own gate) and requires the configuration to actually be
     * in place -- a login exists and upstream works. A genuinely fresh device
     * has no users and no internet, so it cannot take this path, and an
     * anonymous ubus caller cannot either.
     *
     * The wizard itself never sets this flag; it goes through the normal
     * conditions below.
     */
    if (cfg && nc_json_bool_def(cfg, "adopt_existing_config", 0) &&
        nc_json_bool_def(cfg, "caller_authorized_initialized_write", 0)) {
        int users_known = 0;
        int users = nc_setup_web_user_count(&users_known, NULL, NULL);

        if (!users_known || users <= 0) {
            json_object_object_add(d, "ok", json_object_new_boolean(0));
            json_object_object_add(d, "error",
                json_object_new_string("adopt_requires_existing_config"));
            json_object_object_add(d, "message", json_object_new_string(
                "adopting an existing configuration requires a web login to already exist"));
            return nc_setup_response(API_CODE_ERROR, d);
        }
        if (!nc_setup_cmd_success("ping -c 1 -W 1 223.5.5.5 >/dev/null 2>&1 || ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1")) {
            json_object_object_add(d, "ok", json_object_new_boolean(0));
            json_object_object_add(d, "error",
                json_object_new_string("adopt_requires_working_upstream"));
            json_object_object_add(d, "message", json_object_new_string(
                "adopting an existing configuration requires working upstream connectivity"));
            return nc_setup_response(API_CODE_ERROR, d);
        }
        adopt_existing = 1;
    }
    if (nc_exec("BEGIN IMMEDIATE") != 0)
        return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("finish_begin"));
    if (nc_prepare(&st, "SELECT initialized,last_apply_state,last_test_ok,last_apply_at,started_at,setup_version FROM setup_state WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            sqlite3_int64 last_apply_at = sqlite3_column_int64(st, 3);
            sqlite3_int64 started_at = sqlite3_column_int64(st, 4);

            snprintf(version, sizeof(version), "%s",
                     nc_sql_text(st, 5)[0] ? nc_sql_text(st, 5) : OAF_VERSION);
            can_finish = !sqlite3_column_int(st, 0) &&
                (adopt_existing ||
                 (!strcmp(nc_sql_text(st, 1), "ready") &&
                  sqlite3_column_int(st, 2) &&
                  last_apply_at > 0 &&
                  (started_at <= 0 || last_apply_at >= started_at)));
        }
        sqlite3_finalize(st);
    }
    if (!can_finish) {
        nc_exec("ROLLBACK");
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("setup_apply_not_ready"));
        return nc_setup_response(API_CODE_ERROR, d);
    }
    if (nc_prepare(&st, "UPDATE setup_state SET initialized=1,initialized_at=?1,initialized_version=?2,completed_by=?3,current_step='finished',updated_at=?1 WHERE id=1 AND initialized=0") == 0) {
        sqlite3_bind_int64(st, 1, now);
        sqlite3_bind_text(st, 2, version, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, completed_by, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0 || nc_sqlite_changes() <= 0) {
            sqlite3_finalize(st);
            nc_exec("ROLLBACK");
            return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("finish_state"));
        }
        sqlite3_finalize(st);
    } else {
        nc_exec("ROLLBACK");
        return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("finish_state"));
    }
    snprintf(tsbuf, sizeof(tsbuf), "%lld", (long long)now);
    if (nc_setup_set_meta("setup.initialized", "1") != 0 ||
        nc_setup_set_meta("setup.initialized_at", tsbuf) != 0 ||
        nc_setup_set_meta("setup.initialized_version", version) != 0 ||
        nc_setup_set_meta("setup.completed_by", completed_by) != 0 ||
        nc_setup_clear_drafts() != 0) {
        nc_exec("ROLLBACK");
        return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("finish_meta"));
    }
    nc_setup_add_state_json(d);
    json_object_object_add(d, "finish_readback_verified", json_object_new_boolean(
        nc_json_bool_def(d, "initialized", 0) &&
        nc_setup_json_int64_def(d, "setup_finished_at", 0) == now &&
        !strcmp(nc_json_str_def(d, "setup_finished_by", ""), completed_by) &&
        !strcmp(nc_json_str_def(d, "setup_version", ""), version)));
    if (!nc_json_bool_def(d, "finish_readback_verified", 0)) {
        nc_exec("ROLLBACK");
        return nc_setup_response(API_CODE_ERROR, d);
    }
    if (nc_exec("COMMIT") != 0) {
        nc_exec("ROLLBACK");
        return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("finish_commit"));
    }
    return nc_setup_response(API_CODE_SUCCESS, d);
}

struct json_object *jmx_setup_reset_wizard(struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();

    if (!cfg || !nc_json_bool_def(cfg, "confirm", 0)) {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("confirm_required"));
        return nc_setup_response(API_CODE_ERROR, d);
    }
    if (jmx_netconfig_db_init() != 0)
        return nc_setup_response(API_CODE_ERROR, d);
    /*
     * Returning an in-service router to the wizard is this method's whole
     * purpose, so it cannot simply refuse when initialized the way the other
     * setup writes do. It asks for a second, differently named flag instead:
     * `confirm` alone is easy to carry over from an unrelated call or to type
     * while debugging, and the consequence here is a router that stops serving
     * its own configuration. An uninitialized device is unaffected.
     */
    if (nc_setup_is_initialized() &&
        !nc_json_bool_def(cfg, "confirm_reset_initialized", 0)) {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error",
            json_object_new_string("confirm_reset_initialized_required"));
        json_object_object_add(d, "message", json_object_new_string(
            "this router is already initialized; resetting it to the wizard needs confirm_reset_initialized=true"));
        return nc_setup_response(API_CODE_ERROR, d);
    }
    if (nc_exec("UPDATE setup_state SET initialized=0,initialized_at=0,initialized_version='',completed_by='',current_step='intro',last_apply_state='idle',last_apply_error='',last_test_ok=0,last_test_json='{}',updated_at=strftime('%s','now') WHERE id=1") != 0 ||
        nc_sqlite_changes() <= 0 ||
        nc_setup_set_meta("setup.initialized", "0") != 0 ||
        nc_setup_set_meta("setup.initialized_at", "0") != 0 ||
        nc_setup_set_meta("setup.initialized_version", "") != 0 ||
        nc_setup_set_meta("setup.completed_by", "") != 0 ||
        nc_setup_clear_drafts() != 0)
        return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("reset_wizard_state"));
    json_object_object_add(d, "reset", json_object_new_boolean(1));
    return nc_setup_response(API_CODE_SUCCESS, d);
}

struct json_object *jmx_setup_support_bundle(struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();
    struct json_object *included = json_object_new_array();
    const char *files[] = {
        "/etc/dreamingwrt/config.db",
        "/tmp/dw-setup-udhcpc.log",
        "/tmp/dw-wan-netifd-reload.log",
        "/tmp/dw-lan-netifd-reload.log",
        NULL
    };
    char path[128];
    char cmd[512];
    char inputs[320] = "";
    int rc;
    int i;

    (void)cfg;
    snprintf(path, sizeof(path), "/tmp/dreamingwrt-setup-support-%lld.tar.gz", (long long)nc_now_s());
    for (i = 0; files[i]; i++) {
        size_t used, left, need;

        if (access(files[i], R_OK) != 0)
            continue;
        used = strlen(inputs);
        left = used < sizeof(inputs) ? sizeof(inputs) - used : 0;
        need = strlen(files[i]) + 2;
        if (left <= need)
            continue;
        if (used > 0)
            strncat(inputs, " ", left - 1);
        strncat(inputs, files[i], sizeof(inputs) - strlen(inputs) - 1);
        json_object_array_add(included, json_object_new_string(files[i]));
    }
    if (!inputs[0]) {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("no_support_files"));
        json_object_object_add(d, "included", included);
        return nc_setup_response(API_CODE_ERROR, d);
    }
    snprintf(cmd, sizeof(cmd), "tar czf %s %s 2>/dev/null", path, inputs);
    rc = nc_run_quiet(cmd);
    json_object_object_add(d, "path", json_object_new_string(path));
    json_object_object_add(d, "included", included);
    json_object_object_add(d, "ok", json_object_new_boolean(rc == 0));
    if (rc != 0)
        json_object_object_add(d, "error", json_object_new_string("bundle_failed"));
    return nc_setup_response(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, d);
}

struct json_object *jmx_setup_assist_mode(struct json_object *cfg)
{
    sqlite3_stmt *st = NULL;
    struct json_object *d = json_object_new_object();
    struct json_object *llm = NULL;
    const char *mode = cfg ? nc_json_str_def(cfg, "assist_mode", nc_json_str_def(cfg, "mode", "")) : "";
    int internet;

    if (jmx_netconfig_db_init() != 0)
        return nc_setup_response(API_CODE_ERROR, d);
    if (mode[0]) {
        if (strcmp(mode, "ai") && strcmp(mode, "manual") && strcmp(mode, "skip_ai")) {
            json_object_object_add(d, "ok", json_object_new_boolean(0));
            json_object_object_add(d, "error", json_object_new_string("invalid_assist_mode"));
            return nc_setup_response(API_CODE_ERROR, d);
        }
        if (nc_prepare(&st, "UPDATE setup_state SET assist_mode=?1,updated_at=?2 WHERE id=1") == 0) {
            sqlite3_bind_text(st, 1, mode, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 2, nc_now_s());
            if (nc_step_done(st) != 0 || nc_sqlite_changes() <= 0) {
                sqlite3_finalize(st);
                return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("assist_mode_state"));
            }
            sqlite3_finalize(st);
        } else {
            return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("assist_mode_state"));
        }
        if (nc_setup_set_meta("setup.assist_mode", mode) != 0)
            return nc_setup_response(API_CODE_ERROR, nc_setup_state_error("assist_mode_meta"));
    }
    internet = nc_setup_cmd_success("ping -c 1 -W 2 223.5.5.5 >/dev/null 2>&1 || ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1");
    llm = nc_setup_llm_json();
    json_object_object_add(d, "assist_mode", json_object_new_string(mode[0] ? mode : "manual"));
    json_object_object_add(d, "internet", json_object_new_boolean(internet));
    json_object_object_add(d, "provider_configured", json_object_new_boolean(
        nc_json_bool_def(llm, "configured", 0)));
    json_object_object_add(d, "provider_available", json_object_new_boolean(
        nc_json_bool_def(llm, "provider_available", 0)));
    json_object_object_add(d, "runtime_available", json_object_new_boolean(
        nc_json_bool_def(llm, "runtime_available", 0)));
    json_object_object_add(d, "blocked_reason", json_object_new_string(
        nc_json_str_def(llm, "blocked_reason", "ai_status_unavailable")));
    json_object_object_add(d, "provider", json_object_new_string(
        nc_json_str_def(llm, "provider", "")));
    json_object_object_add(d, "llm", llm);
    return nc_setup_response(API_CODE_SUCCESS, d);
}
