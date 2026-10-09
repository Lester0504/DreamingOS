// SPDX-License-Identifier: GPL-2.0-or-later
/* PKI task state contains public certificates and generation references only.
 * The database mutex serializes worker and ubus callers, including the short
 * filesystem activation. Private keys never enter this database or JSON. */
#include "ac_certificate_lifecycle.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include "../ap_control_wire.h"
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <time.h>

#define LC_OPEN "phase NOT IN ('completed','cancelled','rolled_back')"
struct lc_task {
    char id[37], operation[24], ap_id[37], phase[24], prior[37];
    unsigned char server[32];
};
static int lc_exec(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}
static const char *lc_text(struct json_object *object, const char *name)
{
    struct json_object *value = NULL;
    return object && json_object_object_get_ex(object, name, &value) &&
        json_object_is_type(value, json_type_string) ? json_object_get_string(value) : "";
}
static int lc_id(const char *id)
{
    size_t i;
    if (!id || strlen(id) != 36) return 0;
    for (i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (id[i] != '-') return 0; }
        else if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f'))) return 0;
    }
    return 1;
}
static void lc_copy(char *out, size_t size, sqlite3_stmt *st, int col)
{
    const char *value = (const char *)sqlite3_column_text(st, col);
    snprintf(out, size, "%s", value ? value : "");
}
static struct json_object *lc_error(const char *error)
{
    struct json_object *result = json_object_new_object();
    json_object_object_add(result, "ok", json_object_new_boolean(0));
    json_object_object_add(result, "error", json_object_new_string(error));
    return result;
}
static int lc_audit(sqlite3 *db, const char *task, const char *actor,
                    const char *action, const char *target, const char *reason)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;
    if (sqlite3_prepare_v2(db, "INSERT INTO ac_certificate_audit(task_id,actor,action,target,reason,at)"
        " VALUES(?1,?2,?3,?4,?5,?6)", -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, task, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, actor, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, action, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, target, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, time(NULL));
    if (sqlite3_step(st) == SQLITE_DONE) rc = 0;
    sqlite3_finalize(st); return rc;
}
int ac_certificate_lifecycle_init(sqlite3 *db)
{
    return db ? lc_exec(db,
        "CREATE TABLE IF NOT EXISTS ac_certificate_tasks("
        "task_id TEXT PRIMARY KEY,operation TEXT NOT NULL,ap_id TEXT NOT NULL DEFAULT '',"
        "phase TEXT NOT NULL,actor TEXT NOT NULL,reason TEXT NOT NULL,prior_generation TEXT NOT NULL,"
        "server_fingerprint BLOB NOT NULL DEFAULT X'',error TEXT NOT NULL DEFAULT '',"
        "created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);"
        "CREATE UNIQUE INDEX IF NOT EXISTS ac_certificate_one_task ON ac_certificate_tasks((1)) WHERE " LC_OPEN ";"
        "CREATE TABLE IF NOT EXISTS ac_certificate_targets("
        "task_id TEXT NOT NULL,ap_id TEXT NOT NULL,old_certificate_id TEXT NOT NULL,"
        "new_certificate_id TEXT NOT NULL DEFAULT '',phase TEXT NOT NULL DEFAULT 'pending',"
        "updated_at INTEGER NOT NULL,PRIMARY KEY(task_id,ap_id));"
        "CREATE TABLE IF NOT EXISTS ac_certificate_audit("
        "id INTEGER PRIMARY KEY,task_id TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,"
        "target TEXT NOT NULL,reason TEXT NOT NULL,at INTEGER NOT NULL);") : -1;
}
int ac_certificate_lifecycle_ready(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int ready = 0;
    if (!db || sqlite3_db_readonly(db, "main") != 0) return 0;
    sqlite3_mutex_enter(sqlite3_db_mutex(db));
    if (sqlite3_prepare_v2(db, "PRAGMA query_only", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW || sqlite3_column_int(st, 0)) goto done;
    sqlite3_finalize(st); st = NULL;
    /* Check the actual task, recovery, target and audit schema without creating
     * tables or changing PKI material from a capabilities read. */
    if (sqlite3_prepare_v2(db,
        "SELECT t.task_id,t.operation,t.phase,t.prior_generation,t.server_fingerprint,"
        "p.ap_id,p.old_certificate_id,p.new_certificate_id,p.phase,"
        "a.actor,a.action,a.target,a.reason,a.at,c.certificate_id,e.public_key "
        "FROM ac_certificate_tasks t,ac_certificate_targets p,ac_certificate_audit a,"
        "ac_device_certificates c,ac_enrollments e LIMIT 0",
        -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_DONE) ready = 1;
done:
    sqlite3_finalize(st); sqlite3_mutex_leave(sqlite3_db_mutex(db)); return ready;
}
static int lc_load(sqlite3 *db, const char *id, struct lc_task *task)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;
    char wanted[37];
    snprintf(wanted, sizeof(wanted), "%s", id);
    memset(task, 0, sizeof(*task));
    if (sqlite3_prepare_v2(db, "SELECT task_id,operation,ap_id,phase,prior_generation,server_fingerprint "
        "FROM ac_certificate_tasks WHERE task_id=?1 OR (?1='' AND " LC_OPEN ") ORDER BY created_at LIMIT 1",
        -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, wanted, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        lc_copy(task->id, sizeof(task->id), st, 0); lc_copy(task->operation, sizeof(task->operation), st, 1);
        lc_copy(task->ap_id, sizeof(task->ap_id), st, 2); lc_copy(task->phase, sizeof(task->phase), st, 3);
        lc_copy(task->prior, sizeof(task->prior), st, 4);
        if (sqlite3_column_bytes(st, 5) == 32) memcpy(task->server, sqlite3_column_blob(st, 5), 32);
        rc = 0;
    }
    sqlite3_finalize(st); return rc;
}
static int lc_phase(sqlite3 *db, const char *id, const char *phase, const char *error)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;
    if (sqlite3_prepare_v2(db, "UPDATE ac_certificate_tasks SET phase=?2,error=?3,updated_at=?4 WHERE task_id=?1",
        -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, phase, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, error, -1, SQLITE_TRANSIENT); sqlite3_bind_int64(st, 4, time(NULL));
    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1) rc = 0;
    sqlite3_finalize(st); return rc;
}
static int lc_remaining(sqlite3 *db, const char *id, const char *phases)
{
    sqlite3_stmt *st = NULL; int count = -1;
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM ac_certificate_targets WHERE task_id=?1 "
        "AND instr(?2,','||phase||',')=0", -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, phases, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st); return count;
}
static int lc_fingerprint(X509 *cert, unsigned char out[32])
{
    unsigned int length = 0;
    return cert && X509_digest(cert, EVP_sha256(), out, &length) == 1 && length == 32 ? 0 : -1;
}
static int lc_tick_locked(sqlite3 *db)
{
    struct lc_task task;
    struct ac_pki *pki = NULL;
    X509 *cert = NULL;
    sqlite3_stmt *st = NULL;
    unsigned char fingerprint[32];
    int rc = -1;
    if (lc_load(db, "", &task)) return 0;
    if (!strcmp(task.phase, "queued")) {
        if (!strcmp(task.operation, "ap_renew")) {
            if (ac_pki_init(&pki)) goto failed;
        } else if (ac_pki_generation_prepare(task.id, !strcmp(task.operation, "ca_rotate"), &pki)) goto failed;
        cert = ac_pki_server_certificate_dup(pki);
        if (lc_fingerprint(cert, fingerprint) || sqlite3_prepare_v2(db,
            "UPDATE ac_certificate_tasks SET server_fingerprint=?2 WHERE task_id=?1", -1, &st, NULL) != SQLITE_OK) goto failed;
        sqlite3_bind_text(st, 1, task.id, -1, SQLITE_TRANSIENT); sqlite3_bind_blob(st, 2, fingerprint, 32, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE) goto failed;
        sqlite3_finalize(st); st = NULL;
        /* Publish dual trust before any AP is offered its new certificate. */
        if (!strcmp(task.operation, "ca_rotate") && ac_transport_certificate_reload()) goto failed;
        if (lc_phase(db, task.id, !strcmp(task.operation, "server_renew") ? "activating" : "distributing", "")) goto failed;
        if (lc_load(db, task.id, &task)) goto failed;
    }
    if (!strcmp(task.phase, "distributing")) {
        if (!strcmp(task.operation, "ap_renew")) {
            if (lc_remaining(db, task.id, ",client_confirmed,confirmed,retired,") == 0)
                rc = lc_phase(db, task.id, "completed", "");
            else rc = 0;
            goto done;
        }
        if (lc_remaining(db, task.id, ",client_confirmed,confirmed,retired,") != 0) { rc = 0; goto done; }
        if (lc_phase(db, task.id, "activating", "")) goto failed;
        snprintf(task.phase, sizeof(task.phase), "activating");
    }
    if (!strcmp(task.phase, "activating")) {
        if (ac_pki_generation_activate(task.id) || ac_transport_certificate_reload()) {
            /* Old sessions are still valid. Restore the old server atomically;
             * CA new-client trust remains installed for already switched APs. */
            (void)ac_pki_generation_activate(task.prior);
            (void)ac_transport_certificate_reload();
            goto failed;
        }
        if (lc_phase(db, task.id, "confirming", "")) goto failed;
        snprintf(task.phase, sizeof(task.phase), "confirming");
    }
    if (!strcmp(task.phase, "confirming")) {
        if (lc_remaining(db, task.id, ",confirmed,retired,") != 0) { rc = 0; goto done; }
        if (!strcmp(task.operation, "server_renew")) { rc = lc_phase(db, task.id, "completed", ""); goto done; }
        if (lc_phase(db, task.id, "retiring", "")) goto failed;
        snprintf(task.phase, sizeof(task.phase), "retiring");
    }
    if (!strcmp(task.phase, "retiring")) {
        /* This durable phase is only reachable after every target has proved
         * a new client certificate and the new server chain over real mTLS. */
        if (ac_pki_generation_retire(task.id) || ac_transport_certificate_reload()) goto failed;
        rc = lc_remaining(db, task.id, ",retired,") == 0 ? lc_phase(db, task.id, "completed", "") : 0;
        goto done;
    }
    rc = 0; goto done;
failed:
    (void)lc_phase(db, task.id, task.phase, "certificate_execution_failed_retryable");
done:
    sqlite3_finalize(st); X509_free(cert); ac_pki_free(pki); return rc;
}
int ac_certificate_lifecycle_tick(sqlite3 *db)
{
    int rc;
    if (!db) return -1;
    sqlite3_mutex_enter(sqlite3_db_mutex(db)); rc = lc_tick_locked(db);
    sqlite3_mutex_leave(sqlite3_db_mutex(db)); return rc;
}
static struct json_object *lc_rows(sqlite3 *db, const char *sql, const char *id)
{
    sqlite3_stmt *st = NULL;
    struct json_object *rows = json_object_new_array();
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) { json_object_put(rows); return NULL; }
    if (id) sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *row = json_object_new_object();
        int i;
        for (i = 0; i < sqlite3_column_count(st); i++) {
            const char *name = sqlite3_column_name(st, i);
            struct json_object *value = sqlite3_column_type(st, i) == SQLITE_INTEGER ?
                json_object_new_int64(sqlite3_column_int64(st, i)) :
                json_object_new_string((const char *)sqlite3_column_text(st, i));
            json_object_object_add(row, name, value);
        }
        json_object_array_add(rows, row);
    }
    sqlite3_finalize(st); return rows;
}
static struct json_object *lc_window(const char *kind)
{
    struct json_object *value = json_object_new_object();
    int64_t start = 0, end = 0, now = time(NULL);
    int available = ac_pki_certificate_window(kind, &start, &end) == 0;
    const char *state = !available ? "certificate_unavailable" : now < start ? "not_yet_valid" :
                        now >= end ? "expired" : end - now < 604800 ? "expiring" : "valid";
    json_object_object_add(value, "available", json_object_new_boolean(available));
    json_object_object_add(value, "not_before", available ? json_object_new_int64(start) : NULL);
    json_object_object_add(value, "not_after", available ? json_object_new_int64(end) : NULL);
    json_object_object_add(value, "validity", json_object_new_string(state));
    json_object_object_add(value, "clock_anomaly", json_object_new_boolean(now < 1704067200 || (available && now < start)));
    json_object_object_add(value, "observed_at", json_object_new_int64(now));
    return value;
}
static struct json_object *lc_status(sqlite3 *db, const char *id)
{
    struct json_object *result = json_object_new_object(), *rows;
    rows = lc_rows(db, "SELECT task_id,operation,ap_id,phase AS state,actor,reason,prior_generation,"
        "error,created_at,updated_at FROM ac_certificate_tasks WHERE ?1='' OR task_id=?1 ORDER BY created_at DESC LIMIT 100", id);
    if (!rows) { json_object_put(result); return lc_error("certificate_store_unavailable"); }
    json_object_object_add(result, "ok", json_object_new_boolean(1));
    json_object_object_add(result, "schema", json_object_new_string("ap-control.certificate-lifecycle.v1"));
    json_object_object_add(result, "tasks", rows);
    json_object_object_add(result, "server_certificate", lc_window("server"));
    json_object_object_add(result, "ca_certificate", lc_window("ca"));
    if (id[0]) {
        json_object_object_add(result, "targets", lc_rows(db,
            "SELECT ap_id,old_certificate_id,new_certificate_id,phase AS state,updated_at "
            "FROM ac_certificate_targets WHERE task_id=?1 ORDER BY ap_id", id));
        json_object_object_add(result, "audit", lc_rows(db,
            "SELECT actor,action,target,reason,at FROM ac_certificate_audit WHERE task_id=?1 ORDER BY id DESC LIMIT 100", id));
    }
    json_object_object_add(result, "certificates", lc_rows(db,
        "SELECT certificate_id,ap_id,not_before,not_after,revoked_at,state,"
        "CASE WHEN revoked_at>0 THEN 'revoked' WHEN strftime('%s','now')<not_before THEN 'clock_before_not_before' "
        "WHEN CAST(strftime('%s','now') AS INTEGER)>=not_after THEN 'expired' "
        "WHEN not_after-CAST(strftime('%s','now') AS INTEGER)<604800 THEN 'expiring' ELSE 'valid' END AS validity "
        "FROM ac_device_certificates ORDER BY issued_at DESC LIMIT 256", NULL));
    return result;
}
static int lc_confirmed_request(struct json_object *request)
{
    struct json_object *v = NULL;
    return json_object_object_get_ex(request, "confirmed", &v) &&
        json_object_is_type(v, json_type_boolean) && json_object_get_boolean(v) &&
        strlen(lc_text(request, "actor")) > 0 && strlen(lc_text(request, "actor")) <= 95 &&
        strlen(lc_text(request, "reason")) > 0 && strlen(lc_text(request, "reason")) <= 256;
}
static struct json_object *lc_submit(sqlite3 *db, struct json_object *request)
{
    const char *id = lc_text(request, "request_id"), *op = lc_text(request, "operation");
    const char *ap = lc_text(request, "ap_id"), *actor = lc_text(request, "actor"), *reason = lc_text(request, "reason");
    struct ac_pki *pki = NULL;
    struct lc_task existing;
    sqlite3_stmt *st = NULL;
    const char *error = "certificate_store_unavailable";
    if (!lc_id(id) || (strcmp(op, "server_renew") && strcmp(op, "ap_renew") && strcmp(op, "ca_rotate")) ||
        (!strcmp(op, "ap_renew") ? !lc_id(ap) : ap[0] != 0)) return lc_error("invalid_request");
    if (!lc_load(db, id, &existing)) {
        int same_actor = 0;
        if (sqlite3_prepare_v2(db, "SELECT 1 FROM ac_certificate_tasks WHERE task_id=?1 AND actor=?2 AND reason=?3", -1, &st, NULL) != SQLITE_OK)
            return lc_error("certificate_store_unavailable");
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, actor, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, reason, -1, SQLITE_TRANSIENT);
        same_actor = sqlite3_step(st) == SQLITE_ROW; sqlite3_finalize(st); st = NULL;
        if (!same_actor || strcmp(op, existing.operation) || strcmp(ap, existing.ap_id)) return lc_error("idempotency_conflict");
        return lc_status(db, id);
    }
    if (!lc_load(db, "", &existing)) return lc_error("certificate_task_in_progress");
    if (ac_pki_init(&pki)) return lc_error(ac_pki_last_reason());
    if (lc_exec(db, "BEGIN IMMEDIATE")) goto done;
    if (sqlite3_prepare_v2(db, "INSERT INTO ac_certificate_tasks(task_id,operation,ap_id,phase,actor,reason,prior_generation,created_at,updated_at)"
        "VALUES(?1,?2,?3,'queued',?4,?5,?6,?7,?7)", -1, &st, NULL) != SQLITE_OK) goto rollback;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, op, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, ap, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 4, actor, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, reason, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 6, ac_pki_generation(pki), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7, time(NULL));
    if (sqlite3_step(st) != SQLITE_DONE) goto rollback;
    sqlite3_finalize(st); st = NULL;
    if (sqlite3_prepare_v2(db, "INSERT INTO ac_certificate_targets(task_id,ap_id,old_certificate_id,new_certificate_id,updated_at) "
        "SELECT ?1,e.ap_id,e.certificate_id,CASE WHEN ?3='server_renew' THEN e.certificate_id ELSE '' END,?4 "
        "FROM ac_enrollments e JOIN ac_device_certificates c ON c.certificate_id=e.certificate_id "
        "WHERE e.state IN ('adopted','mtls_pending') AND c.state IN ('active','pending_activation') AND c.revoked_at=0 AND (?2='' OR e.ap_id=?2)", -1, &st, NULL) != SQLITE_OK) goto rollback;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, ap, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, op, -1, SQLITE_TRANSIENT); sqlite3_bind_int64(st, 4, time(NULL));
    if (sqlite3_step(st) != SQLITE_DONE) goto rollback;
    if (!strcmp(op, "ap_renew") && sqlite3_changes(db) != 1) { error = "ap_not_adopted"; goto rollback; }
    sqlite3_finalize(st); st = NULL;
    if (lc_audit(db, id, actor, "submit", ap, reason) || lc_exec(db, "COMMIT")) goto rollback;
    ac_pki_free(pki);
    (void)lc_tick_locked(db);
    return lc_status(db, id);
rollback:
    sqlite3_finalize(st); st = NULL; (void)lc_exec(db, "ROLLBACK");
done:
    sqlite3_finalize(st); ac_pki_free(pki); return lc_error(error);
}
static int lc_revoke(sqlite3 *db, const char *certificate_id)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;
    if (sqlite3_prepare_v2(db, "UPDATE ac_device_certificates SET revoked_at=?2,state='revoked' "
        "WHERE certificate_id=?1 AND revoked_at=0", -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, certificate_id, -1, SQLITE_TRANSIENT); sqlite3_bind_int64(st, 2, time(NULL));
    if (sqlite3_step(st) == SQLITE_DONE) rc = 0;
    sqlite3_finalize(st); return rc;
}
struct json_object *ac_certificate_lifecycle_request(sqlite3 *db, struct json_object *request)
{
    const char *action = lc_text(request, "action"), *id = lc_text(request, "task_id");
    struct json_object *result = NULL;
    struct lc_task task;
    sqlite3_stmt *st = NULL;
    if (!db || !request) return lc_error("certificate_store_unavailable");
    sqlite3_mutex_enter(sqlite3_db_mutex(db));
    if (!strcmp(action, "status")) { result = lc_status(db, id); goto done; }
    if (!lc_confirmed_request(request)) { result = lc_error("operator_confirmation_required"); goto done; }
    if (!strcmp(action, "submit")) { result = lc_submit(db, request); goto done; }
    if (!strcmp(action, "revoke")) {
        const char *cert = lc_text(request, "certificate_id");
        if (!lc_id(cert)) { result = lc_error("invalid_certificate_id"); goto done; }
        if (sqlite3_prepare_v2(db, "SELECT 1 FROM ac_device_certificates WHERE certificate_id=?1", -1, &st, NULL) != SQLITE_OK) goto store_error;
        sqlite3_bind_text(st, 1, cert, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_ROW) { result = lc_error("certificate_not_found"); goto done; }
        sqlite3_finalize(st); st = NULL;
        if (lc_exec(db, "BEGIN IMMEDIATE")) goto store_error;
        if (lc_revoke(db, cert) || lc_audit(db, "", lc_text(request, "actor"), "revoke", cert, lc_text(request, "reason"))) goto rollback;
        /* An explicitly revoked enrollment cannot redeem an old claim again. */
        if (sqlite3_prepare_v2(db, "UPDATE ac_enrollments SET state='revoked',updated_at=?2 "
            "WHERE certificate_id=?1", -1, &st, NULL) != SQLITE_OK) goto rollback;
        sqlite3_bind_text(st, 1, cert, -1, SQLITE_TRANSIENT); sqlite3_bind_int64(st, 2, time(NULL));
        if (sqlite3_step(st) != SQLITE_DONE) goto rollback;
        sqlite3_finalize(st); st = NULL;
        if (lc_exec(db, "COMMIT")) goto rollback;
        result = lc_status(db, ""); goto done;
    }
    if (!lc_id(id) || lc_load(db, id, &task)) { result = lc_error("certificate_task_not_found"); goto done; }
    if (!strcmp(action, "retry")) {
        if (!strcmp(task.phase, "completed") || !strcmp(task.phase, "cancelled") || !strcmp(task.phase, "rolled_back")) {
            result = lc_error("certificate_task_terminal"); goto done;
        }
        (void)lc_audit(db, id, lc_text(request, "actor"), action, task.ap_id, lc_text(request, "reason"));
        (void)lc_tick_locked(db); result = lc_status(db, id); goto done;
    }
    if (!strcmp(action, "cancel")) {
        if (!strcmp(task.phase, "cancelled")) { result = lc_status(db, id); goto done; }
        if (strcmp(task.phase, "queued") && (strcmp(task.phase, "distributing") ||
            lc_remaining(db, id, ",pending,") != 0)) { result = lc_error("cancel_boundary_crossed"); goto done; }
        if (!strcmp(task.operation, "ca_rotate") && (ac_pki_generation_retire(task.prior) || ac_transport_certificate_reload())) goto store_error;
        if (lc_phase(db, id, "cancelled", "")) goto store_error;
    } else if (!strcmp(action, "rollback")) {
        if (strcmp(task.operation, "server_renew") || (strcmp(task.phase, "activating") && strcmp(task.phase, "confirming"))) {
            result = lc_error("rollback_boundary_crossed"); goto done;
        }
        if (ac_pki_generation_activate(task.prior) || ac_transport_certificate_reload() || lc_phase(db, id, "rolled_back", "operator_rollback")) goto store_error;
    } else { result = lc_error("invalid_action"); goto done; }
    if (lc_audit(db, id, lc_text(request, "actor"), action, task.ap_id, lc_text(request, "reason"))) goto store_error;
    result = lc_status(db, id); goto done;
rollback:
    sqlite3_finalize(st); st = NULL; (void)lc_exec(db, "ROLLBACK");
store_error:
    result = lc_error("certificate_store_unavailable");
done:
    sqlite3_finalize(st); sqlite3_mutex_leave(sqlite3_db_mutex(db)); return result;
}

static int lc_issue(sqlite3 *db, const struct lc_task *task, const char *ap,
                    const unsigned char *csr, size_t length, char certificate_id[37])
{
    struct ac_pki *pki = NULL;
    struct ac_pki_issued_certificate *issued = NULL;
    sqlite3_stmt *st = NULL;
    unsigned char key[32];
    char key_id[72];
    const unsigned char *der; size_t der_len;
    int rc = -1;
    if (!csr || !length || sqlite3_prepare_v2(db,
        "SELECT public_key,key_id FROM ac_enrollments WHERE ap_id=?1 AND state='adopted'",
        -1, &st, NULL) != SQLITE_OK) goto done;
    sqlite3_bind_text(st, 1, ap, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW || sqlite3_column_bytes(st, 0) != 32) goto done;
    memcpy(key, sqlite3_column_blob(st, 0), 32); lc_copy(key_id, sizeof(key_id), st, 1);
    sqlite3_finalize(st); st = NULL;
    if ((!strcmp(task->operation, "ca_rotate") ? ac_pki_generation_open(task->id, &pki) : ac_pki_init(&pki)) ||
        ac_pki_issue_ap_certificate(pki, ap, key, csr, length, &issued) ||
        ap_control_uuid4(certificate_id) != AP_CONTROL_WIRE_OK) goto done;
    der = ac_pki_issued_certificate_der(issued, &der_len);
    if (lc_exec(db, "BEGIN IMMEDIATE")) goto done;
    if (sqlite3_prepare_v2(db, "INSERT INTO ac_device_certificates(certificate_id,ap_id,serial,key_id,not_before,not_after,"
        "state,certificate_der,fingerprint_sha256,issuer_key_id,issued_at) VALUES(?1,?2,?3,?4,?5,?6,'active',?7,?8,?9,?10)",
        -1, &st, NULL) != SQLITE_OK) goto rollback;
    sqlite3_bind_text(st, 1, certificate_id, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, ap, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, ac_pki_issued_certificate_serial(issued), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, key_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, ac_pki_issued_certificate_not_before(issued));
    sqlite3_bind_int64(st, 6, ac_pki_issued_certificate_not_after(issued));
    sqlite3_bind_blob(st, 7, der, (int)der_len, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 8, ac_pki_issued_certificate_fingerprint_sha256(issued), 32, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, ac_pki_issued_certificate_issuer_key_id(issued), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 10, time(NULL));
    if (sqlite3_step(st) != SQLITE_DONE) goto rollback;
    sqlite3_finalize(st); st = NULL;
    if (sqlite3_prepare_v2(db, "UPDATE ac_certificate_targets SET new_certificate_id=?3,phase='issued',updated_at=?4 "
        "WHERE task_id=?1 AND ap_id=?2 AND new_certificate_id=''", -1, &st, NULL) != SQLITE_OK) goto rollback;
    sqlite3_bind_text(st, 1, task->id, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, ap, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, certificate_id, -1, SQLITE_TRANSIENT); sqlite3_bind_int64(st, 4, time(NULL));
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(db) != 1 ||
        lc_audit(db, task->id, "controller", "certificate_issued", ap, "local_ap_csr_verified") || lc_exec(db, "COMMIT")) goto rollback;
    rc = 0; goto done;
rollback:
    sqlite3_finalize(st); st = NULL; (void)lc_exec(db, "ROLLBACK");
done:
    sqlite3_finalize(st); ac_pki_issued_certificate_free(issued); ac_pki_free(pki); return rc;
}
static int lc_target_phase(sqlite3 *db, const char *task, const char *ap, const char *phase)
{
    sqlite3_stmt *st = NULL; int rc = -1;
    if (sqlite3_prepare_v2(db, "UPDATE ac_certificate_targets SET phase=?3,updated_at=?4 WHERE task_id=?1 AND ap_id=?2",
        -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, task, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, ap, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, phase, -1, SQLITE_TRANSIENT); sqlite3_bind_int64(st, 4, time(NULL));
    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1) rc = 0;
    sqlite3_finalize(st); return rc;
}
static int lc_prove(sqlite3 *db, const struct lc_task *task, const char *ap,
                    const char *old, const char *cert, const unsigned char fingerprint[32])
{
    sqlite3_stmt *st = NULL; int rc = -1;
    if (lc_exec(db, "BEGIN IMMEDIATE")) return -1;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM ac_device_certificates c JOIN ac_enrollments e ON e.ap_id=c.ap_id "
        "WHERE c.certificate_id=?1 AND c.ap_id=?2 AND c.fingerprint_sha256=?3 AND c.revoked_at=0 "
        "AND c.state='active' AND e.state='adopted' AND c.not_before<=?4 AND c.not_after>?4", -1, &st, NULL) != SQLITE_OK) goto rollback;
    sqlite3_bind_text(st, 1, cert, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, ap, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, fingerprint, 32, SQLITE_TRANSIENT); sqlite3_bind_int64(st, 4, time(NULL));
    if (sqlite3_step(st) != SQLITE_ROW) goto rollback;
    sqlite3_finalize(st); st = NULL;
    if (strcmp(old, cert)) {
        if (lc_revoke(db, old) || sqlite3_prepare_v2(db, "UPDATE ac_enrollments SET certificate_id=?2,updated_at=?3 "
            "WHERE ap_id=?1 AND state='adopted'", -1, &st, NULL) != SQLITE_OK) goto rollback;
        sqlite3_bind_text(st, 1, ap, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, cert, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, time(NULL));
        if (sqlite3_step(st) != SQLITE_DONE) goto rollback;
        sqlite3_finalize(st); st = NULL;
        if (lc_audit(db, task->id, "controller", "old_certificate_revoked", old, "replacement_mtls_confirmed")) goto rollback;
    }
    if (lc_target_phase(db, task->id, ap, "client_confirmed") || lc_exec(db, "COMMIT")) goto rollback;
    rc = 0; goto done;
rollback:
    (void)lc_exec(db, "ROLLBACK");
done:
    sqlite3_finalize(st); return rc;
}
static void lc_hex_add(struct json_object *object, const char *name, const unsigned char *data, size_t length)
{
    char *hex = malloc(length * 2 + 1);
    if (!hex) return;
    if (ap_control_hex_encode(data, length, hex, length * 2 + 1) == AP_CONTROL_WIRE_OK)
        json_object_object_add(object, name, json_object_new_string(hex));
    free(hex);
}
int ac_certificate_lifecycle_enrollment_allowed(sqlite3 *db)
{
    sqlite3_stmt *st = NULL; int allowed = 0;
    if (!db) return 0;
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM ac_certificate_tasks WHERE operation='ca_rotate' AND " LC_OPEN,
        -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) allowed = sqlite3_column_int(st, 0) == 0;
    sqlite3_finalize(st); return allowed;
}
struct json_object *ac_certificate_lifecycle_poll(sqlite3 *db, const char *ap,
    const char *certificate_id, const unsigned char peer_fingerprint[32],
    const unsigned char server_fingerprint[32], const unsigned char trust_fingerprint[32],
    const unsigned char *csr, size_t csr_len)
{
    struct lc_task task;
    struct ac_pki *pki = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *result = json_object_new_object();
    char old[37], next[37], phase[24];
    unsigned char *bundle = NULL, digest[32]; size_t bundle_len = 0;
    const char *error = "certificate_store_unavailable";
    json_object_object_add(result, "action", json_object_new_string("idle"));
    if (!db) goto failed_unlocked;
    sqlite3_mutex_enter(sqlite3_db_mutex(db));
    if (lc_tick_locked(db)) goto failed;
    if (lc_load(db, "", &task)) goto done;
    if (sqlite3_prepare_v2(db, "SELECT old_certificate_id,new_certificate_id,phase FROM ac_certificate_targets "
        "WHERE task_id=?1 AND ap_id=?2", -1, &st, NULL) != SQLITE_OK) goto failed;
    sqlite3_bind_text(st, 1, task.id, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, ap, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) goto done;
    lc_copy(old, sizeof(old), st, 0); lc_copy(next, sizeof(next), st, 1); lc_copy(phase, sizeof(phase), st, 2);
    sqlite3_finalize(st); st = NULL;
    if (strcmp(certificate_id, old) && strcmp(certificate_id, next)) { error = "certificate_task_identity_mismatch"; goto failed; }
    if (!next[0]) {
        if (lc_issue(db, &task, ap, csr, csr_len, next)) { error = "certificate_csr_rejected"; goto failed; }
        snprintf(phase, sizeof(phase), "issued");
    }
    if (!strcmp(certificate_id, next) && (!strcmp(phase, "issued") || !strcmp(phase, "pending"))) {
        if (lc_prove(db, &task, ap, old, next, peer_fingerprint)) { error = "certificate_mtls_proof_rejected"; goto failed; }
        snprintf(phase, sizeof(phase), "client_confirmed");
    }
    if (!strcmp(certificate_id, next) && !CRYPTO_memcmp(server_fingerprint, task.server, 32) &&
        (!strcmp(task.operation, "ap_renew") || !strcmp(task.phase, "confirming") || !strcmp(task.phase, "retiring"))) {
        if (strcmp(phase, "retired") && lc_target_phase(db, task.id, ap, "confirmed")) goto failed;
        if (strcmp(phase, "retired")) snprintf(phase, sizeof(phase), "confirmed");
    }
    if (lc_tick_locked(db) || lc_load(db, task.id, &task)) goto failed;
    if (!strcmp(task.phase, "completed")) goto done;
    if ((!strcmp(task.operation, "ca_rotate") ? ac_pki_generation_open(task.id, &pki) : ac_pki_init(&pki)) ||
        ac_pki_trust_pem(pki, &bundle, &bundle_len)) goto failed;
    json_object_object_add(result, "task_id", json_object_new_string(task.id));
    json_object_object_add(result, "certificate_id", json_object_new_string(next));
    if (strcmp(certificate_id, next)) {
        if (sqlite3_prepare_v2(db, "SELECT certificate_der FROM ac_device_certificates WHERE certificate_id=?1 AND revoked_at=0",
            -1, &st, NULL) != SQLITE_OK) goto failed;
        sqlite3_bind_text(st, 1, next, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_ROW || sqlite3_column_bytes(st, 0) <= 0) goto failed;
        json_object_object_add(result, "action", json_object_new_string("install"));
        lc_hex_add(result, "certificate_der", sqlite3_column_blob(st, 0), (size_t)sqlite3_column_bytes(st, 0));
        json_object_object_add(result, "trust_pem", json_object_new_string_len((const char *)bundle, (int)bundle_len));
    } else if (!strcmp(task.phase, "retiring")) {
        if (!SHA256(bundle, bundle_len, digest)) goto failed;
        if (!CRYPTO_memcmp(digest, trust_fingerprint, 32)) {
            if (lc_target_phase(db, task.id, ap, "retired") || lc_tick_locked(db)) goto failed;
        } else {
            json_object_object_add(result, "action", json_object_new_string("trust_commit"));
            json_object_object_add(result, "trust_pem", json_object_new_string_len((const char *)bundle, (int)bundle_len));
        }
    } else if (!CRYPTO_memcmp(server_fingerprint, task.server, 32)) {
        /* Current server already observed; waiting for other APs is not a reconnect command. */
    } else if (!strcmp(task.phase, "confirming")) {
        json_object_object_add(result, "action", json_object_new_string("reconnect"));
    }
    goto done;
failed:
    json_object_put(result); result = lc_error(error);
done:
    sqlite3_finalize(st); ac_pki_free(pki); OPENSSL_free(bundle);
    sqlite3_mutex_leave(sqlite3_db_mutex(db)); return result;
failed_unlocked:
    json_object_put(result); return lc_error(error);
}
