/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "logd/logd_internal.h"
#include <assert.h>

static int count(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *s = NULL;
    assert(sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK);
    assert(sqlite3_step(s) == SQLITE_ROW);
    int n = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    return n;
}
static struct json_object *make_event(int number)
{
    struct json_object *e = json_object_new_object();
    char id[33];
    snprintf(id, sizeof(id), "%032x", number);
    json_object_object_add(e, "id", json_object_new_string(id));
    json_object_object_add(e, "ts", json_object_new_int64(time(NULL)));
    json_object_object_add(e, "severity", json_object_new_string("warning"));
    json_object_object_add(e, "category", json_object_new_string("system"));
    json_object_object_add(e, "event", json_object_new_string("ap_log_runtime_probe"));
    json_object_object_add(e, "source", json_object_new_string("fixture"));
    json_object_object_add(e, "title", json_object_new_string("bounded transport fixture"));
    json_object_object_add(e, "detail_json", json_object_new_string("{\"message\":\"fixture\"}"));
    return e;
}
static int result(struct json_object *r)
{
    int ok = logd_json_bool(r, "ok", 0);
    json_object_put(r);
    return ok;
}
int main(int argc, char **argv)
{
    assert(argc == 3);
    snprintf(g_logd_db_path, sizeof(g_logd_db_path), "%s", argv[2]);
    assert(logd_db_init() == 0);
    assert(logd_storage_ready());
    assert(sqlite3_open(":memory:", &g_config_db) == SQLITE_OK);
    assert(sqlite3_exec(g_config_db, "CREATE TABLE logd_settings(id INTEGER,retention_days INTEGER,max_events INTEGER,auto_cleanup INTEGER);INSERT INTO logd_settings VALUES(1,30,50000,1);", NULL,NULL,NULL) == SQLITE_OK);
    if (logd_ap_mode()) {
        assert(!strcmp(argv[1], "ap"));
        assert(!sqlite3_db_filename(g_logd_db, "main")[0]);
        assert(access(argv[2], F_OK) != 0);
        assert(count(g_logd_db, "PRAGMA max_page_count") == 4096);
        assert(logd_collector_state_set("system_log", "cursor", "42") == 0);
        char value[32];
        assert(logd_collector_state_get("system_log", "cursor", value, sizeof(value), "") == 0);
        assert(!strcmp(value,"42"));
        assert(count(g_config_db,"SELECT COUNT(*) FROM sqlite_master WHERE name='logd_collector_state'") == 0);
        for(int i=0;i<300;i++) {
            struct json_object *e=make_event(i+1);
            assert(logd_ap_enqueue(e, "{}") == 0);
            json_object_put(e);
        }
        assert(count(g_logd_db,"SELECT COUNT(*) FROM ap_log_queue") == AP_LOG_QUEUE_LIMIT);
        struct json_object *status=logd_ap_status();
        assert(logd_json_i64(status,"dropped",0) == 44);
        json_object_put(status);
        struct json_object *batch=logd_ap_exchange("ap_log_peek",NULL);
        struct json_object *batch2=logd_ap_exchange("ap_log_peek",NULL);
        assert(!strcmp(json_object_to_json_string(batch),json_object_to_json_string(batch2)));
        assert(json_object_array_length(json_object_object_get(batch,"events")) == AP_LOG_BATCH_LIMIT);
        assert(!result(logd_ap_exchange("ap_log_ack",NULL)));
        assert(count(g_logd_db,"SELECT COUNT(*) FROM ap_log_queue") == AP_LOG_QUEUE_LIMIT);
        assert(result(logd_ap_exchange("ap_log_ack",batch)));
        assert(result(logd_ap_exchange("ap_log_ack",batch)));
        assert(count(g_logd_db,"SELECT COUNT(*) FROM ap_log_queue") == AP_LOG_QUEUE_LIMIT-4);
        status=logd_ap_status();
        assert(logd_json_i64(status,"acked",0) == 4);
        json_object_put(status);json_object_put(batch);json_object_put(batch2);
        assert(logd_db_reopen_path(argv[2]) == -1);
        puts("ap memory_only=ok bounded=ok no_ack_retained=ok ack_idempotent=ok collector_memory=ok");
    } else {
        struct json_object *batch=json_object_new_object(), *events=json_object_new_array();
        json_object_object_add(batch,"ap_id",json_object_new_string("11111111-1111-4111-8111-111111111111"));
        json_object_array_add(events,make_event(1));
        json_object_array_add(events,make_event(2));
        json_object_object_add(batch,"events",events);
        assert(result(logd_ap_exchange("ap_log_ingest",batch)));
        assert(result(logd_ap_exchange("ap_log_ingest",batch)));
        assert(count(g_logd_db,"SELECT COUNT(*) FROM log_events WHERE source='ap_remote'") == 2);
        assert(count(g_logd_db,"SELECT COUNT(*) FROM log_events WHERE actor='11111111-1111-4111-8111-111111111111'") == 2);
        struct json_object *new_events=json_object_new_array(), *conflict=make_event(1);
        json_object_array_add(new_events,make_event(3));
        json_object_object_add(conflict,"title",json_object_new_string("conflicting retry"));
        json_object_array_add(new_events,conflict);
        json_object_object_add(batch,"events",new_events);
        assert(!result(logd_ap_exchange("ap_log_ingest",batch)));
        assert(count(g_logd_db,"SELECT COUNT(*) FROM log_events") == 2);
        json_object_object_add(conflict,"extra",json_object_new_boolean(1));
        assert(!result(logd_ap_exchange("ap_log_ingest",batch)));
        json_object_object_del(conflict,"extra");
        g_logd_storage_frozen=1;
        assert(!result(logd_ap_exchange("ap_log_ingest",batch)));
        assert(count(g_logd_db,"SELECT COUNT(*) FROM log_events") == 2);
        g_logd_storage_frozen=0;
        assert(!result(logd_ap_exchange("ap_log_peek",NULL)));
        json_object_put(batch);
        puts("ac durable=ok retry_idempotent=ok conflict_rollback=ok strict_fields=ok unavailable_no_ack=ok");
    }
    logd_db_close();
    return 0;
}
