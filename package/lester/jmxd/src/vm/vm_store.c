// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Persistent store for the VM daemon.
 *
 * libvirt is the source of truth for which domains exist and their runtime
 * state. This store only carries what libvirt does not: a monotonic per-VM
 * revision (the vm.v1 optimistic-concurrency token), the client request_id ->
 * task_id idempotency map, and the async task table (owned by vm_task.c but kept
 * in this one database so a daemon restart can reconcile it).
 */
#include "vm_internal.h"

static sqlite3 *g_vm_db;

static int vm_store_mkdir(void)
{
    /* Best-effort: the parent of VM_STORE_PATH. A single level is enough for the
     * default /etc/dreamingwrt/vm because /etc/dreamingwrt already exists on the
     * device (other components use it). */
    if (mkdir(VM_STATE_DIR, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

int vm_store_open(void)
{
    static const char *schema =
        "CREATE TABLE IF NOT EXISTS vm_revision ("
        "  uuid TEXT PRIMARY KEY,"
        "  revision INTEGER NOT NULL DEFAULT 1);"
        "CREATE TABLE IF NOT EXISTS vm_idempotency ("
        "  request_id TEXT PRIMARY KEY,"
        "  task_id TEXT NOT NULL,"
        "  created_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS vm_tasks ("
        "  task_id TEXT PRIMARY KEY,"
        "  kind TEXT NOT NULL,"
        "  object_id TEXT,"
        "  state TEXT NOT NULL,"
        "  stage TEXT NOT NULL,"
        "  progress REAL,"
        "  cancellable INTEGER NOT NULL DEFAULT 1,"
        "  created_at INTEGER NOT NULL,"
        "  updated_at INTEGER NOT NULL,"
        "  result TEXT,"
        "  error TEXT,"
        "  payload TEXT);";

    if (g_vm_db)
        return 0;
    if (vm_store_mkdir() != 0)
        return -1;
    if (sqlite3_open(VM_STORE_PATH, &g_vm_db) != SQLITE_OK) {
        g_vm_db = NULL;
        return -1;
    }
    sqlite3_busy_timeout(g_vm_db, 3000);
    if (sqlite3_exec(g_vm_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_exec(g_vm_db, schema, NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(g_vm_db);
        g_vm_db = NULL;
        return -1;
    }
    return 0;
}

void vm_store_close(void)
{
    if (g_vm_db) {
        sqlite3_close(g_vm_db);
        g_vm_db = NULL;
    }
}

sqlite3 *vm_store_db(void)
{
    return g_vm_db;
}

int64_t vm_store_revision_get(const char *uuid)
{
    sqlite3_stmt *st = NULL;
    int64_t rev = 1;

    if (!g_vm_db || !uuid)
        return 1;
    if (sqlite3_prepare_v2(g_vm_db,
            "SELECT revision FROM vm_revision WHERE uuid=?1;", -1, &st, NULL) != SQLITE_OK)
        return 1;
    sqlite3_bind_text(st, 1, uuid, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW)
        rev = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return rev;
}

int64_t vm_store_revision_bump(const char *uuid)
{
    sqlite3_stmt *st = NULL;

    if (!g_vm_db || !uuid)
        return -1;
    /* UPSERT: first write seeds revision 1, later writes increment. The value
     * returned is the NEW revision the caller should hand back to clients. */
    if (sqlite3_prepare_v2(g_vm_db,
            "INSERT INTO vm_revision(uuid,revision) VALUES(?1,1) "
            "ON CONFLICT(uuid) DO UPDATE SET revision=revision+1;",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, uuid, -1, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return vm_store_revision_get(uuid);
}
