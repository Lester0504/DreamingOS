// SPDX-License-Identifier: GPL-2.0-or-later
/* Runtime contract for AC persistence of AP-originated management audit. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>
#include <sqlite3.h>

#define AP_ID "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
#define EVENT_A "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
#define EVENT_B "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
#define EPOCH "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
#define SESSION "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

extern sqlite3 *g_ac_db;
int ac_db_init(void);
void ac_db_close(void);
int ac_db_ap_audit_store(const char *, const char *, int64_t, const char *,
                         const char *, const char *, const char *, const char *,
                         const char *, const char *, const char *, const char *,
                         const char *, int64_t);
struct json_object *ac_db_ap_audit_events_json(const char *, int, int64_t);

static int scalar(const char *sql)
{
    sqlite3_stmt *statement = NULL;
    int value = -1;

    if (sqlite3_prepare_v2(g_ac_db, sql, -1, &statement, NULL) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_ROW)
        value = sqlite3_column_int(statement, 0);
    sqlite3_finalize(statement);
    return value;
}

static int store(const char *event_id, const char *actor_session,
                 const char *risk, const char *target, const char *result,
                 const char *reason)
{
    return ac_db_ap_audit_store(
        AP_ID, event_id, 1788080000000LL, EPOCH, "web:admin",
        actor_session, "192.0.2.8", "network.wan.update", risk, target,
        result, reason, "request-fixture-1", 1);
}

static int query_contract(void)
{
    struct json_object *root = ac_db_ap_audit_events_json(AP_ID, 20, 0);
    struct json_object *items = NULL;
    struct json_object *item = NULL;
    struct json_object *value = NULL;
    int ok = 0;

    if (!root || !json_object_object_get_ex(root, "ok", &value) ||
        !json_object_get_boolean(value) ||
        !json_object_object_get_ex(root, "items", &items) ||
        json_object_array_length(items) != 2)
        goto done;
    item = json_object_array_get_idx(items, 0);
    if (!item || !json_object_object_get_ex(item, "source", &value) ||
        strcmp(json_object_get_string(value), "ap_remote") ||
        !json_object_object_get_ex(item, "actor_session", &value) ||
        strncmp(json_object_get_string(value), "sha256:", 7))
        goto done;
    ok = 1;
done:
    json_object_put(root);
    return ok;
}

int main(void)
{
    int rc = 1;

    if (ac_db_init() != 0)
        goto done;

    /* A terminal result may be the first observation and is idempotent. */
    if (store(EVENT_A, SESSION, "medium", "/api/v1/network/wan", "success", "") != 0 ||
        store(EVENT_A, SESSION, "medium", "/api/v1/network/wan", "success", "") != 0 ||
        scalar("SELECT COUNT(*) FROM ac_ap_audit_events") != 1)
        goto done;

    /* Stable fields are immutable once the idempotency key is present. */
    if (store(EVENT_A, SESSION, "medium", "/api/v1/network/lan", "success", "") == 0 ||
        scalar("SELECT COUNT(*) FROM ac_ap_audit_events") != 1)
        goto done;

    /* reserve -> one final state; duplicate final is a no-op. */
    if (store(EVENT_B, SESSION, "high", "/api/v1/system/reboot", "reserved", "") != 0 ||
        store(EVENT_B, SESSION, "high", "/api/v1/system/reboot", "denied", "policy_denied") != 0 ||
        store(EVENT_B, SESSION, "high", "/api/v1/system/reboot", "denied", "policy_denied") != 0 ||
        store(EVENT_B, SESSION, "high", "/api/v1/system/reboot", "success", "") == 0 ||
        scalar("SELECT COUNT(*) FROM ac_ap_audit_events") != 2 ||
        scalar("SELECT COUNT(*) FROM ac_ap_audit_events WHERE event_id='" EVENT_B "' AND result='denied' AND failure_reason='policy_denied'") != 1)
        goto done;

    /* Secret-shaped actor sessions, unknown risk, and reason/result mismatch fail. */
    if (store("11111111-1111-4111-8111-111111111111", "raw-token", "medium",
              "/api/v1/network/wan", "success", "") == 0 ||
        store("22222222-2222-4222-8222-222222222222", SESSION, "unknown",
              "/api/v1/network/wan", "success", "") == 0 ||
        store("33333333-3333-4333-8333-333333333333", SESSION, "medium",
              "/api/v1/network/wan", "failed", "") == 0 ||
        scalar("SELECT COUNT(*) FROM ac_ap_audit_events") != 2 ||
        !query_contract())
        goto done;

    printf("first_terminal=ok reserve_final=ok duplicate=ok conflict=ok "
           "sensitive_rejected=ok query=ok count=2\n");
    rc = 0;
done:
    ac_db_close();
    return rc;
}
