// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Async task engine for dreamingos-vm (§7).
 *
 * Only the long-running write verbs (instance_create / instance_delete) run
 * here; the quick libvirt lifecycle actions stay synchronous in vm_libvirt.c.
 * Tasks are persisted in the sqlite store (vm_store.c owns the schema) so a
 * daemon restart can reconcile them: anything left queued/running by a previous
 * run is marked `interrupted` rather than silently resumed or dropped (§7).
 *
 * The worker runs in a uloop timeout on the daemon's single thread. That keeps
 * the one cached libvirt connection free of cross-thread use, at the cost of
 * blocking the loop for the duration of a create/delete; streaming progress and
 * true mid-flight cancellation are a later refinement, and `cancellable` is
 * honestly reported false the moment a task leaves the queue.
 */
#include "vm_internal.h"
#include "../dw_business_event.h"

#define VM_TASK_COLS \
    "task_id,kind,object_id,state,stage,progress,cancellable,created_at,updated_at,result,error"

/* One in-flight worker, tracked in a list only so shutdown can cancel pending
 * timeouts and free them. The task's durable state lives in the store. */
struct vm_task_job {
    struct uloop_timeout t;
    struct vm_task_job *next;
    char task_id[40];
};
static struct vm_task_job *g_jobs;

static void vm_task_job_unlink(struct vm_task_job *job)
{
    struct vm_task_job **pp = &g_jobs;

    while (*pp) {
        if (*pp == job) { *pp = job->next; break; }
        pp = &(*pp)->next;
    }
}
/* Build the §7 task-detail object from a row selected with VM_TASK_COLS. result
 * and error are stored as JSON text and re-parsed so they nest as objects; a
 * NULL column becomes a JSON null. artifact is reserved for export tasks. */
static struct json_object *vm_task_detail_from_stmt(sqlite3_stmt *st)
{
    struct json_object *d = json_object_new_object();
    const unsigned char *s;

    json_object_object_add(d, "task_id", json_object_new_string((const char *)sqlite3_column_text(st, 0)));
    json_object_object_add(d, "kind", json_object_new_string((const char *)sqlite3_column_text(st, 1)));
    s = sqlite3_column_text(st, 2);
    json_object_object_add(d, "object_id", s ? json_object_new_string((const char *)s) : NULL);
    json_object_object_add(d, "state", json_object_new_string((const char *)sqlite3_column_text(st, 3)));
    json_object_object_add(d, "stage", json_object_new_string((const char *)sqlite3_column_text(st, 4)));
    if (sqlite3_column_type(st, 5) == SQLITE_NULL)
        json_object_object_add(d, "progress", NULL);
    else
        json_object_object_add(d, "progress", json_object_new_double(sqlite3_column_double(st, 5)));
    json_object_object_add(d, "cancellable", json_object_new_boolean(sqlite3_column_int(st, 6)));
    json_object_object_add(d, "created_at", json_object_new_int64(sqlite3_column_int64(st, 7)));
    json_object_object_add(d, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 8)));
    s = sqlite3_column_text(st, 9);
    json_object_object_add(d, "result", (s && *s) ? json_tokener_parse((const char *)s) : NULL);
    s = sqlite3_column_text(st, 10);
    json_object_object_add(d, "error", (s && *s) ? json_tokener_parse((const char *)s) : NULL);
    json_object_object_add(d, "artifact", NULL);
    return d;
}

static struct json_object *vm_task_load_detail(const char *task_id)
{
    sqlite3 *db = vm_store_db();
    sqlite3_stmt *st = NULL;
    struct json_object *d = NULL;

    if (!db || !task_id)
        return NULL;
    if (sqlite3_prepare_v2(db, "SELECT " VM_TASK_COLS " FROM vm_tasks WHERE task_id=?1;",
                           -1, &st, NULL) != SQLITE_OK)
        return NULL;
    sqlite3_bind_text(st, 1, task_id, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW)
        d = vm_task_detail_from_stmt(st);
    sqlite3_finalize(st);
    return d;
}
static void vm_task_log_terminal(const char *task_id, const char *state)
{
    if (strcmp(state, "succeeded") && strcmp(state, "failed") && strcmp(state, "cancelled") && strcmp(state, "interrupted")) return;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(vm_store_db(), "SELECT kind,object_id,payload,error FROM vm_tasks WHERE task_id=?1", -1, &st, NULL) != SQLITE_OK) return;
    sqlite3_bind_text(st, 1, task_id, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *detail = json_object_new_object(), *context = NULL, *v = NULL, *cfg = NULL;
        const char *raw = (const char *)sqlite3_column_text(st, 2);
        struct json_object *payload = raw ? json_tokener_parse(raw) : NULL;
        const char *id = (const char *)sqlite3_column_text(st, 1);
        json_object_object_add(detail, "task_id", json_object_new_string(task_id));
        json_object_object_add(detail, "object_id", json_object_new_string(id ? id : ""));
        json_object_object_add(detail, "action", json_object_new_string((const char *)sqlite3_column_text(st, 0)));
        json_object_object_add(detail, "engine", json_object_new_string("libvirt"));
        json_object_object_add(detail, "result", json_object_new_string(!strcmp(state, "succeeded") ? "success" : !strcmp(state, "cancelled") ? "cancelled" : "failed"));
        if (payload) {
            if (!json_object_object_get_ex(payload, "config", &cfg)) cfg = payload;
            if (json_object_object_get_ex(cfg, "name", &v)) json_object_object_add(detail, "object_name", json_object_get(v));
            if (json_object_object_get_ex(payload, "request_id", &v)) json_object_object_add(detail, "request_id", json_object_get(v));
            if (strcmp(state, "cancelled") && json_object_object_get_ex(payload, "_log_context", &context)) {
                if (json_object_object_get_ex(context, "actor", &v)) json_object_object_add(detail, "actor", json_object_get(v));
                if (json_object_object_get_ex(context, "source_ip", &v)) json_object_object_add(detail, "source_ip", json_object_get(v));
            }
        }
        raw = (const char *)sqlite3_column_text(st, 3);
        struct json_object *error = raw ? json_tokener_parse(raw) : NULL;
        if (error && json_object_object_get_ex(error, "code", &v)) json_object_object_add(detail, "failure_reason", json_object_get(v));
        if (!strcmp(state, "interrupted")) json_object_object_add(detail, "failure_reason", json_object_new_string("daemon_restarted"));
        dw_business_event("vm", "VM_OPERATION_FINISHED", detail);
        json_object_put(error); json_object_put(payload); json_object_put(detail);
    }
    sqlite3_finalize(st);
}

static void vm_task_update(const char *task_id, const char *state, const char *stage,
                           int cancellable, const double *progress,
                           const char *result_json, const char *error_json,
                           const char *object_id)
{
    sqlite3 *db = vm_store_db();
    sqlite3_stmt *st = NULL;

    if (!db)
        return;
    if (sqlite3_prepare_v2(db,
            "UPDATE vm_tasks SET state=?2,stage=?3,cancellable=?4,progress=?5,"
            "result=?6,error=?7,object_id=COALESCE(?8,object_id),updated_at=?9 "
            "WHERE task_id=?1;", -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_text(st, 1, task_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, state, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, stage, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 4, cancellable);
    if (progress) sqlite3_bind_double(st, 5, *progress); else sqlite3_bind_null(st, 5);
    if (result_json) sqlite3_bind_text(st, 6, result_json, -1, SQLITE_TRANSIENT); else sqlite3_bind_null(st, 6);
    if (error_json) sqlite3_bind_text(st, 7, error_json, -1, SQLITE_TRANSIENT); else sqlite3_bind_null(st, 7);
    if (object_id && *object_id) sqlite3_bind_text(st, 8, object_id, -1, SQLITE_TRANSIENT); else sqlite3_bind_null(st, 8);
    sqlite3_bind_int64(st, 9, vm_now_s());
    int saved = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) > 0;
    sqlite3_finalize(st);
    if (saved) vm_task_log_terminal(task_id, state);
}
/* uloop worker: transition queued -> running, run the libvirt operation to
 * completion, then persist the terminal state. Runs on the main thread. */
static void vm_task_run(struct uloop_timeout *t)
{
    struct vm_task_job *job = container_of(t, struct vm_task_job, t);
    sqlite3 *db = vm_store_db();
    sqlite3_stmt *st = NULL;
    char *kind = NULL, *payload = NULL;
    struct json_object *pl = NULL, *cfg = NULL, *result = NULL, *error = NULL, *v;
    double pr;
    int rc = -1;

    vm_task_job_unlink(job);
    if (!db)
        goto done;

    /* Load kind+payload; skip the work if the task was cancelled before we ran. */
    if (sqlite3_prepare_v2(db, "SELECT kind,payload,state FROM vm_tasks WHERE task_id=?1;",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, job->task_id, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const unsigned char *k = sqlite3_column_text(st, 0);
            const unsigned char *p = sqlite3_column_text(st, 1);
            const unsigned char *stt = sqlite3_column_text(st, 2);

            if (!stt || strcmp((const char *)stt, "queued")) { sqlite3_finalize(st); goto done; }
            if (k) kind = strdup((const char *)k);
            if (p) payload = strdup((const char *)p);
        }
    }
    sqlite3_finalize(st);
    if (!kind)
        goto done;

    pr = 0.0;
    vm_task_update(job->task_id, "running",
                   !strcmp(kind, "instance_delete") ? "deleting" : "creating_disks",
                   0, &pr, NULL, NULL, NULL);
    pl = payload ? json_tokener_parse(payload) : NULL;
        if (!strcmp(kind, "instance_create")) {
        if (!pl || !json_object_object_get_ex(pl, "config", &cfg))
            cfg = pl;   /* tolerate a bare config as well as { request_id, config } */
        rc = vm_create_domain(cfg, &result, &error);
    } else if (!strcmp(kind, "instance_delete")) {
        const char *id = NULL;
        bool del = false;

        if (pl && json_object_object_get_ex(pl, "id", &v)) id = json_object_get_string(v);
        if (pl && json_object_object_get_ex(pl, "delete_owned_disks", &v)) del = json_object_get_boolean(v);
        rc = vm_delete_domain(id, del, &result, &error);
    } else {
        error = vm_error_obj("bad_request", "unknown task kind", NULL);
    }

    if (rc == 0) {
        const char *oid = NULL;

        if (result && json_object_object_get_ex(result, "vm_id", &v)) oid = json_object_get_string(v);
        else if (result && json_object_object_get_ex(result, "id", &v)) oid = json_object_get_string(v);
        pr = 1.0;
        vm_task_update(job->task_id, "succeeded", "done", 0, &pr,
                       result ? json_object_to_json_string(result) : NULL, NULL, oid);
    } else {
        vm_task_update(job->task_id, "failed", "failed", 0, NULL,
                       NULL, error ? json_object_to_json_string(error) : NULL, NULL);
    }

    json_object_put(pl);
    json_object_put(result);
    json_object_put(error);
done:
    free(kind);
    free(payload);
    free(job);
}
int vm_task_init(void)
{
    sqlite3 *db = vm_store_db();
    char sql[256], *err = NULL;
    sqlite3_stmt *pending = NULL;
    struct json_object *ids = json_object_new_array();

    if (!db) {
        json_object_put(ids);
        return -1;
    }
    if (sqlite3_prepare_v2(db, "SELECT task_id FROM vm_tasks WHERE state IN ('queued','running')", -1, &pending, NULL) == SQLITE_OK) {
        while (sqlite3_step(pending) == SQLITE_ROW)
            json_object_array_add(ids, json_object_new_string((const char *)sqlite3_column_text(pending, 0)));
        sqlite3_finalize(pending);
    }
    /* Reconcile (§7): a task left non-terminal by a previous run cannot be
     * safely resumed, so mark it interrupted rather than dropping it silently. */
    snprintf(sql, sizeof sql,
             "UPDATE vm_tasks SET state='interrupted',stage='interrupted',cancellable=0,"
             "updated_at=%lld WHERE state IN ('queued','running');", (long long)vm_now_s());
    if (sqlite3_exec(db, sql, NULL, NULL, &err) == SQLITE_OK) {
        for (size_t i = 0; i < json_object_array_length(ids); i++)
            vm_task_log_terminal(json_object_get_string(json_object_array_get_idx(ids, i)), "interrupted");
    } else if (err) {
        sqlite3_free(err);
    }
    json_object_put(ids);
    return 0;
}

void vm_task_shutdown(void)
{
    struct vm_task_job *job = g_jobs;

    /* Cancel pending timeouts; the rows stay queued and the next start's
     * vm_task_init reconciles them to interrupted. */
    while (job) {
        struct vm_task_job *next = job->next;

        uloop_timeout_cancel(&job->t);
        free(job);
        job = next;
    }
    g_jobs = NULL;
}
struct json_object *vm_task_submit(const char *kind, const char *object_id,
                                   struct json_object *payload, int *http_status)
{
    sqlite3 *db = vm_store_db();
    sqlite3_stmt *st = NULL;
    struct json_object *v, *d;
    const char *request_id = NULL, *payload_str;
    char task_id[40];
    int64_t now = vm_now_s();
    struct vm_task_job *job;

    if (!db) { *http_status = 503; return NULL; }

    if (payload && json_object_object_get_ex(payload, "request_id", &v))
        request_id = json_object_get_string(v);

    /* Idempotency (§10): a repeated request_id returns the original task. */
    if (request_id && *request_id) {
        char existing[40] = { 0 };

        if (sqlite3_prepare_v2(db, "SELECT task_id FROM vm_idempotency WHERE request_id=?1;",
                               -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, request_id, -1, SQLITE_STATIC);
            if (sqlite3_step(st) == SQLITE_ROW) {
                const unsigned char *tid = sqlite3_column_text(st, 0);
                if (tid) snprintf(existing, sizeof existing, "%s", (const char *)tid);
            }
            sqlite3_finalize(st); st = NULL;
        }
        if (existing[0]) {
            d = vm_task_load_detail(existing);
            *http_status = 202;
            return d;
        }
    }
        vm_uuid_generate(task_id);
    payload_str = payload ? json_object_to_json_string(payload) : NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO vm_tasks(task_id,kind,object_id,state,stage,progress,cancellable,"
            "created_at,updated_at,result,error,payload) "
            "VALUES(?1,?2,?3,'queued','queued',NULL,1,?4,?4,NULL,NULL,?5);",
            -1, &st, NULL) != SQLITE_OK) {
        *http_status = 503; return NULL;
    }
    sqlite3_bind_text(st, 1, task_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, kind ? kind : "", -1, SQLITE_STATIC);
    if (object_id && *object_id) sqlite3_bind_text(st, 3, object_id, -1, SQLITE_STATIC);
    else sqlite3_bind_null(st, 3);
    sqlite3_bind_int64(st, 4, now);
    if (payload_str) sqlite3_bind_text(st, 5, payload_str, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(st, 5);
    if (sqlite3_step(st) != SQLITE_DONE) { sqlite3_finalize(st); *http_status = 503; return NULL; }
    sqlite3_finalize(st); st = NULL;

    if (request_id && *request_id &&
        sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO vm_idempotency(request_id,task_id,created_at)"
                               " VALUES(?1,?2,?3);", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, request_id, -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 2, task_id, -1, SQLITE_STATIC);
        sqlite3_bind_int64(st, 3, now);
        sqlite3_step(st);
        sqlite3_finalize(st); st = NULL;
    }

    /* Run on the next uloop iteration (see file header on the single-thread model). */
    job = calloc(1, sizeof *job);
    if (job) {
        snprintf(job->task_id, sizeof job->task_id, "%s", task_id);
        job->t.cb = vm_task_run;
        job->next = g_jobs;
        g_jobs = job;
        uloop_timeout_set(&job->t, 0);
    }

    d = json_object_new_object();
    json_object_object_add(d, "task_id", json_object_new_string(task_id));
    json_object_object_add(d, "state", json_object_new_string("queued"));
    json_object_object_add(d, "stage", json_object_new_string("queued"));
    json_object_object_add(d, "progress", NULL);
    json_object_object_add(d, "cancellable", json_object_new_boolean(1));
    json_object_object_add(d, "result", NULL);
    *http_status = 202;
    return d;
}
struct json_object *vm_task_get_json(const char *task_id, int *http_status)
{
    struct json_object *d;

    if (!vm_store_db()) { *http_status = 503; return NULL; }
    if (!task_id || !*task_id) { *http_status = 404; return NULL; }
    d = vm_task_load_detail(task_id);
    *http_status = d ? 200 : 404;
    return d;
}

struct json_object *vm_task_list_json(int *http_status)
{
    sqlite3 *db = vm_store_db();
    sqlite3_stmt *st = NULL;
    struct json_object *d, *items;
    int total = 0;

    if (!db) { *http_status = 503; return NULL; }
    items = json_object_new_array();
    if (sqlite3_prepare_v2(db, "SELECT " VM_TASK_COLS " FROM vm_tasks ORDER BY created_at DESC;",
                           -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            json_object_array_add(items, vm_task_detail_from_stmt(st));
            total++;
        }
        sqlite3_finalize(st);
    }
    d = json_object_new_object();
    json_object_object_add(d, "items", items);
    json_object_object_add(d, "total", json_object_new_int(total));
    *http_status = 200;
    return d;
}
struct json_object *vm_task_cancel(const char *task_id, int *http_status)
{
    sqlite3 *db = vm_store_db();
    sqlite3_stmt *st = NULL;
    char state[24] = { 0 };

    if (!db) { *http_status = 503; return NULL; }
    if (!task_id || !*task_id) { *http_status = 404; return NULL; }
    if (sqlite3_prepare_v2(db, "SELECT state FROM vm_tasks WHERE task_id=?1;",
                           -1, &st, NULL) != SQLITE_OK) { *http_status = 503; return NULL; }
    sqlite3_bind_text(st, 1, task_id, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *s = sqlite3_column_text(st, 0);
        if (s) snprintf(state, sizeof state, "%s", (const char *)s);
    }
    sqlite3_finalize(st);
    if (!state[0]) { *http_status = 404; return NULL; }

    /* Only a still-queued task cancels cleanly; once running the synchronous
     * worker is non-cancellable, and terminal tasks are returned unchanged. The
     * returned detail's `cancellable` flag tells the client which case it hit. */
    if (!strcmp(state, "queued"))
        vm_task_update(task_id, "cancelled", "cancelled", 0, NULL, NULL, NULL, NULL);
    *http_status = 200;
    return vm_task_load_detail(task_id);
}
