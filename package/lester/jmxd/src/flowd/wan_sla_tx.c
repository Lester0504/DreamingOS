// SPDX-License-Identifier: GPL-2.0-or-later
/* Conditional WAN SLA configuration. Runtime probing remains fail-closed. */
#include "flowd_internal.h"
#include "wan_sla_tx.h"

#include <inttypes.h>

#define WAN_SLA_CONTRACT "wan-sla.v2"

static struct json_object *sla_error(const char *code, const char *message, int status)
{
    struct json_object *out = flowd_error(code, message);
    json_object_object_add(out, "http_status", json_object_new_int(status));
    json_object_object_add(out, "contract_version", json_object_new_string(WAN_SLA_CONTRACT));
    json_object_object_add(out, "ts", json_object_new_int64(flowd_now_s()));
    return out;
}

static struct json_object *sla_ok(void)
{
    struct json_object *out = json_object_new_object();
    json_object_object_add(out, "ok", json_object_new_boolean(1));
    json_object_object_add(out, "contract_version", json_object_new_string(WAN_SLA_CONTRACT));
    json_object_object_add(out, "ts", json_object_new_int64(flowd_now_s()));
    return out;
}

static int sla_exec(const char *sql)
{
    char *error = NULL;
    int rc = sqlite3_exec(g_flowd_config_db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-flowd] WAN SLA transaction: %s\n",
                error ? error : sqlite3_errmsg(g_flowd_config_db));
        sqlite3_free(error);
        return -1;
    }
    return 0;
}

static uint64_t sla_hash_update(uint64_t hash, const char *text)
{
    const unsigned char *p = (const unsigned char *)(text ? text : "");
    while (*p) {
        hash ^= *p++;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static void sla_digest(const char *operation, int64_t revision,
                       struct json_object *plan, char out[17])
{
    uint64_t hash = UINT64_C(1469598103934665603);
    char revision_text[32];
    snprintf(revision_text, sizeof(revision_text), "%" PRId64, revision);
    hash = sla_hash_update(hash, operation);
    hash = sla_hash_update(hash, "|");
    hash = sla_hash_update(hash, revision_text);
    hash = sla_hash_update(hash, "|");
    hash = sla_hash_update(hash, json_object_to_json_string_ext(
        plan, JSON_C_TO_STRING_PLAIN));
    snprintf(out, 17, "%016" PRIx64, hash);
}

static int sla_json_int64_required(struct json_object *body, const char *key,
                                   int64_t *out)
{
    struct json_object *value = NULL;
    if (!body || !json_object_object_get_ex(body, key, &value) || !value ||
        !json_object_is_type(value, json_type_int))
        return -1;
    *out = json_object_get_int64(value);
    return 0;
}

static int sla_wan_exists(const char *wan)
{
    sqlite3_stmt *st = flowd_config_prepare(
        "SELECT 1 FROM wan WHERE id=?1 AND enabled=1 LIMIT 1");
    int found = 0;
    if (!st) return 0;
    sqlite3_bind_text(st, 1, wan, -1, SQLITE_TRANSIENT);
    found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

static int sla_method_ok(const char *method)
{
    return method && (!strcmp(method, "icmp") || !strcmp(method, "tcp") ||
                      !strcmp(method, "dns") || !strcmp(method, "http") ||
                      !strcmp(method, "https"));
}

static int sla_targets_ok(struct json_object *targets)
{
    int i, count;
    if (!targets || !json_object_is_type(targets, json_type_array)) return 0;
    count = (int)json_object_array_length(targets);
    if (count < 1 || count > 16) return 0;
    for (i = 0; i < count; i++) {
        struct json_object *target = json_object_array_get_idx(targets, i);
        const char *text;
        if (!target || !json_object_is_type(target, json_type_string) ||
            !(text = json_object_get_string(target)) || !text[0] ||
            !flowd_text_ok(text, 256)) return 0;
    }
    return flowd_json_fits(targets, FLOWD_MAX_JSON);
}

static struct json_object *sla_targets(struct json_object *body,
                                       struct json_object *fallback)
{
    struct json_object *value = NULL, *parsed = NULL;
    if (!body || (!json_object_object_get_ex(body, "targets", &value) &&
                  !json_object_object_get_ex(body, "targets_json", &value)))
        return fallback ? json_object_get(fallback) : json_object_new_array();
    if (!value) return json_object_new_array();
    if (json_object_is_type(value, json_type_array)) return json_object_get(value);
    if (json_object_is_type(value, json_type_string)) {
        parsed = json_tokener_parse(json_object_get_string(value));
        if (parsed && json_object_is_type(parsed, json_type_array)) return parsed;
        if (parsed) json_object_put(parsed);
    }
    return NULL;
}

static struct json_object *sla_load(const char *id)
{
    sqlite3_stmt *st;
    struct json_object *item = NULL;
    st = flowd_config_prepare(
        "SELECT id,name,enabled,wan,method,targets_json,interval_s,timeout_ms,"
        "loss_threshold_pct,latency_threshold_ms,fail_count,recover_count,remark,"
        "revision,created_at,updated_at FROM flowd_wan_health WHERE id=?1");
    if (!st) return NULL;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        item = json_object_new_object();
        json_object_object_add(item, "id", json_object_new_string(flowd_sqlite_text(st,0,"")));
        json_object_object_add(item, "name", json_object_new_string(flowd_sqlite_text(st,1,"")));
        json_object_object_add(item, "enabled", json_object_new_boolean(sqlite3_column_int(st,2)));
        json_object_object_add(item, "wan", json_object_new_string(flowd_sqlite_text(st,3,"")));
        json_object_object_add(item, "method", json_object_new_string(flowd_sqlite_text(st,4,"icmp")));
        json_object_object_add(item, "targets", flowd_json_parse_or_array(flowd_sqlite_text(st,5,"[]")));
        json_object_object_add(item, "interval_s", json_object_new_int(sqlite3_column_int(st,6)));
        json_object_object_add(item, "timeout_ms", json_object_new_int(sqlite3_column_int(st,7)));
        json_object_object_add(item, "loss_threshold_pct", json_object_new_int(sqlite3_column_int(st,8)));
        json_object_object_add(item, "latency_threshold_ms", json_object_new_int(sqlite3_column_int(st,9)));
        json_object_object_add(item, "fail_count", json_object_new_int(sqlite3_column_int(st,10)));
        json_object_object_add(item, "recover_count", json_object_new_int(sqlite3_column_int(st,11)));
        json_object_object_add(item, "remark", json_object_new_string(flowd_sqlite_text(st,12,"")));
        json_object_object_add(item, "revision", json_object_new_int64(sqlite3_column_int64(st,13)));
        json_object_object_add(item, "created_at", json_object_new_int64(sqlite3_column_int64(st,14)));
        json_object_object_add(item, "updated_at", json_object_new_int64(sqlite3_column_int64(st,15)));
    }
    sqlite3_finalize(st);
    return item;
}

static struct json_object *sla_capabilities(void)
{
    struct json_object *caps = json_object_new_object();
    json_object_object_add(caps, "list", json_object_new_boolean(1));
    json_object_object_add(caps, "create", json_object_new_boolean(1));
    json_object_object_add(caps, "update", json_object_new_boolean(1));
    json_object_object_add(caps, "delete", json_object_new_boolean(1));
    json_object_object_add(caps, "preview", json_object_new_boolean(1));
    json_object_object_add(caps, "conditional_write", json_object_new_boolean(1));
    json_object_object_add(caps, "expected_revision_required", json_object_new_boolean(1));
    json_object_object_add(caps, "plan_digest_required", json_object_new_boolean(1));
    json_object_object_add(caps, "runtime_evaluation", json_object_new_boolean(0));
    json_object_object_add(caps, "runtime_apply", json_object_new_boolean(0));
    json_object_object_add(caps, "runtime_reason",
        json_object_new_string("wan_sla_sampler_executor_not_implemented"));
    return caps;
}

static struct json_object *sla_plan(struct json_object *body, const char *operation,
                                    struct json_object *existing, int64_t expected_revision)
{
    struct json_object *plan = json_object_new_object();
    struct json_object *targets = NULL;
    const char *id = flowd_json_str(body, "id", "");
    const char *name = flowd_json_str(body, "name", existing ? flowd_json_str(existing,"name","") : "");
    const char *wan = flowd_json_str(body, "wan", existing ? flowd_json_str(existing,"wan","") : "");
    const char *method = flowd_json_str(body, "method", existing ? flowd_json_str(existing,"method","icmp") : "icmp");
    const char *remark = flowd_json_str(body, "remark", existing ? flowd_json_str(existing,"remark","") : "");
    int enabled = flowd_json_bool(body, "enabled", existing ? flowd_json_bool(existing,"enabled",0) : 0);
    int interval_s = flowd_json_int(body, "interval_s", existing ? flowd_json_int(existing,"interval_s",5) : 5);
    int timeout_ms = flowd_json_int(body, "timeout_ms", existing ? flowd_json_int(existing,"timeout_ms",1000) : 1000);
    int loss = flowd_json_int(body, "loss_threshold_pct", existing ? flowd_json_int(existing,"loss_threshold_pct",50) : 50);
    int latency = flowd_json_int(body, "latency_threshold_ms", existing ? flowd_json_int(existing,"latency_threshold_ms",300) : 300);
    int fail_count = flowd_json_int(body, "fail_count", existing ? flowd_json_int(existing,"fail_count",3) : 3);
    int recover_count = flowd_json_int(body, "recover_count", existing ? flowd_json_int(existing,"recover_count",2) : 2);
    struct json_object *fallback = NULL;

    if (!strcmp(operation, "delete")) {
        json_object_object_add(plan, "id", json_object_new_string(id));
        json_object_object_add(plan, "operation", json_object_new_string(operation));
        return plan;
    }
    if (existing) json_object_object_get_ex(existing, "targets", &fallback);
    targets = sla_targets(body, fallback);
    if (!flowd_id_ok(id) || !flowd_text_ok(name,128) || !sla_wan_exists(wan) ||
        !sla_method_ok(method) || !sla_targets_ok(targets) ||
        interval_s < 1 || interval_s > 3600 || timeout_ms < 100 || timeout_ms > 60000 ||
        loss < 0 || loss > 100 || latency < 1 || latency > 600000 ||
        fail_count < 1 || fail_count > 100 || recover_count < 1 || recover_count > 100 ||
        !flowd_text_ok(remark,256)) {
        if (targets) json_object_put(targets);
        json_object_put(plan);
        return NULL;
    }
    if (enabled) {
        json_object_put(targets);
        json_object_put(plan);
        return NULL;
    }
    json_object_object_add(plan, "operation", json_object_new_string(operation));
    json_object_object_add(plan, "id", json_object_new_string(id));
    json_object_object_add(plan, "name", json_object_new_string(name));
    json_object_object_add(plan, "enabled", json_object_new_boolean(0));
    json_object_object_add(plan, "wan", json_object_new_string(wan));
    json_object_object_add(plan, "method", json_object_new_string(method));
    json_object_object_add(plan, "targets", targets);
    json_object_object_add(plan, "interval_s", json_object_new_int(interval_s));
    json_object_object_add(plan, "timeout_ms", json_object_new_int(timeout_ms));
    json_object_object_add(plan, "loss_threshold_pct", json_object_new_int(loss));
    json_object_object_add(plan, "latency_threshold_ms", json_object_new_int(latency));
    json_object_object_add(plan, "fail_count", json_object_new_int(fail_count));
    json_object_object_add(plan, "recover_count", json_object_new_int(recover_count));
    json_object_object_add(plan, "remark", json_object_new_string(remark));
    json_object_object_add(plan, "expected_revision", json_object_new_int64(expected_revision));
    return plan;
}

struct json_object *flowd_wan_sla_list(struct json_object *body)
{
    struct json_object *out = sla_ok();
    struct json_object *items = json_object_new_array();
    sqlite3_stmt *st;
    const char *id = flowd_json_str(body, "id", "");
    if (flowd_db_init() != 0) return sla_error("source_unavailable","config database unavailable",503);
    st = flowd_config_prepare(id[0] ?
        "SELECT id FROM flowd_wan_health WHERE id=?1" :
        "SELECT id FROM flowd_wan_health ORDER BY wan,id");
    if (!st) { json_object_put(out); json_object_put(items); return sla_error("source_unavailable","WAN SLA query failed",503); }
    if (id[0]) sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item = sla_load(flowd_sqlite_text(st,0,""));
        if (item) {
            struct json_object *runtime = json_object_new_object();
            json_object_object_add(runtime, "available", json_object_new_boolean(0));
            json_object_object_add(runtime, "reason", json_object_new_string("wan_sla_sampler_executor_not_implemented"));
            json_object_object_add(item, "runtime", runtime);
            json_object_array_add(items,item);
        }
    }
    sqlite3_finalize(st);
    json_object_object_add(out, "items", items);
    json_object_object_add(out, "total", json_object_new_int((int)json_object_array_length(items)));
    json_object_object_add(out, "authority", json_object_new_string("config.db:flowd_wan_health"));
    json_object_object_add(out, "runtime_degraded", json_object_new_boolean(1));
    json_object_object_add(out, "capabilities", sla_capabilities());
    return out;
}

struct json_object *flowd_wan_sla_preview(struct json_object *body)
{
    struct json_object *existing = NULL, *plan, *out;
    const char *operation = flowd_json_str(body, "operation", "upsert");
    const char *id = flowd_json_str(body, "id", "");
    char generated_id[FLOWD_MAX_ID] = "";
    int64_t expected_revision;
    char digest[17];
    if (flowd_db_init() != 0) return sla_error("source_unavailable","config database unavailable",503);
    if (strcmp(operation,"upsert") && strcmp(operation,"delete"))
        return sla_error("invalid_operation","operation must be upsert or delete",400);
    if (sla_json_int64_required(body,"expected_revision",&expected_revision) != 0 || expected_revision < 0)
        return sla_error("expected_revision_required","expected_revision is required",422);
    if (!id[0] && !strcmp(operation, "upsert") && expected_revision == 0) {
        flowd_make_id("wan-sla", generated_id, sizeof(generated_id));
        id = generated_id;
        json_object_object_add(body, "id", json_object_new_string(id));
    }
    if (!flowd_id_ok(id))
        return sla_error("invalid_id", "WAN SLA id is invalid", 400);
    existing = sla_load(id);
    if ((!existing && expected_revision != 0) || (existing && flowd_json_int(existing,"revision",0) != expected_revision)) {
        if (existing) json_object_put(existing);
        return sla_error("revision_conflict","WAN SLA revision changed",409);
    }
    if (!strcmp(operation,"delete") && !existing)
        return sla_error("not_found","WAN SLA does not exist",404);
    plan = sla_plan(body,operation,existing,expected_revision);
    if (existing) json_object_put(existing);
    if (!plan) {
        if (flowd_json_bool(body,"enabled",0))
            return sla_error("runtime_unavailable","enabled WAN SLA requires a sampler executor",409);
        return sla_error("invalid_request","WAN SLA fields are invalid",400);
    }
    sla_digest(operation,expected_revision,plan,digest);
    out = sla_ok();
    json_object_object_add(out, "ready", json_object_new_boolean(1));
    json_object_object_add(out, "operation", json_object_new_string(operation));
    json_object_object_add(out, "resource_id", json_object_new_string(id));
    json_object_object_add(out, "expected_revision", json_object_new_int64(expected_revision));
    json_object_object_add(out, "plan_digest", json_object_new_string(digest));
    json_object_object_add(out, "plan", plan);
    json_object_object_add(out, "capabilities", sla_capabilities());
    return out;
}

static int sla_write_plan(struct json_object *plan, int64_t expected_revision)
{
    sqlite3_stmt *st;
    struct json_object *targets = NULL;
    const char *targets_text;
    const char *operation = flowd_json_str(plan,"operation","");
    const char *id = flowd_json_str(plan,"id","");
    if (strcmp(operation, "delete")) {
        if (!json_object_object_get_ex(plan, "targets", &targets) || !targets ||
            !json_object_is_type(targets, json_type_array))
            return -1;
        targets_text = json_object_to_json_string_ext(targets, JSON_C_TO_STRING_PLAIN);
        if (!targets_text)
            return -1;
    } else {
        targets_text = "[]";
    }
    if (!strcmp(operation,"delete")) {
        st = flowd_config_prepare("DELETE FROM flowd_wan_health WHERE id=?1 AND revision=?2");
        if (!st) return -1;
        sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT); sqlite3_bind_int64(st,2,expected_revision);
    } else if (expected_revision == 0) {
        st = flowd_config_prepare("INSERT INTO flowd_wan_health(id,name,enabled,wan,method,targets_json,interval_s,timeout_ms,loss_threshold_pct,latency_threshold_ms,fail_count,recover_count,remark,revision,created_at,updated_at) VALUES(?1,?2,0,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,1,?13,?13)");
        if (!st) return -1;
        sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,2,flowd_json_str(plan,"name",""),-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,3,flowd_json_str(plan,"wan",""),-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,4,flowd_json_str(plan,"method","icmp"),-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,5,targets_text,-1,SQLITE_TRANSIENT); sqlite3_bind_int(st,6,flowd_json_int(plan,"interval_s",5)); sqlite3_bind_int(st,7,flowd_json_int(plan,"timeout_ms",1000)); sqlite3_bind_int(st,8,flowd_json_int(plan,"loss_threshold_pct",50)); sqlite3_bind_int(st,9,flowd_json_int(plan,"latency_threshold_ms",300)); sqlite3_bind_int(st,10,flowd_json_int(plan,"fail_count",3)); sqlite3_bind_int(st,11,flowd_json_int(plan,"recover_count",2)); sqlite3_bind_text(st,12,flowd_json_str(plan,"remark",""),-1,SQLITE_TRANSIENT); sqlite3_bind_int64(st,13,flowd_now_s());
    } else {
        st = flowd_config_prepare("UPDATE flowd_wan_health SET name=?2,enabled=0,wan=?3,method=?4,targets_json=?5,interval_s=?6,timeout_ms=?7,loss_threshold_pct=?8,latency_threshold_ms=?9,fail_count=?10,recover_count=?11,remark=?12,revision=revision+1,updated_at=?13 WHERE id=?1 AND revision=?14");
        if (!st) return -1;
        sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,2,flowd_json_str(plan,"name",""),-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,3,flowd_json_str(plan,"wan",""),-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,4,flowd_json_str(plan,"method","icmp"),-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,5,targets_text,-1,SQLITE_TRANSIENT); sqlite3_bind_int(st,6,flowd_json_int(plan,"interval_s",5)); sqlite3_bind_int(st,7,flowd_json_int(plan,"timeout_ms",1000)); sqlite3_bind_int(st,8,flowd_json_int(plan,"loss_threshold_pct",50)); sqlite3_bind_int(st,9,flowd_json_int(plan,"latency_threshold_ms",300)); sqlite3_bind_int(st,10,flowd_json_int(plan,"fail_count",3)); sqlite3_bind_int(st,11,flowd_json_int(plan,"recover_count",2)); sqlite3_bind_text(st,12,flowd_json_str(plan,"remark",""),-1,SQLITE_TRANSIENT); sqlite3_bind_int64(st,13,flowd_now_s()); sqlite3_bind_int64(st,14,expected_revision);
    }
    { int ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_flowd_config_db) == 1; sqlite3_finalize(st); return ok ? 0 : -1; }
}

static int sla_readback_matches(struct json_object *plan, struct json_object *readback,
                                int64_t expected_revision)
{
    static const char *strings[] = { "id", "name", "wan", "method", "remark" };
    static const char *integers[] = {
        "interval_s", "timeout_ms", "loss_threshold_pct",
        "latency_threshold_ms", "fail_count", "recover_count"
    };
    struct json_object *plan_targets = NULL, *readback_targets = NULL;
    struct json_object *revision = NULL;
    size_t i;

    if (!plan || !readback || flowd_json_bool(readback, "enabled", 1))
        return 0;
    for (i = 0; i < sizeof(strings) / sizeof(strings[0]); i++)
        if (strcmp(flowd_json_str(plan, strings[i], ""),
                   flowd_json_str(readback, strings[i], "")))
            return 0;
    for (i = 0; i < sizeof(integers) / sizeof(integers[0]); i++)
        if (flowd_json_int(plan, integers[i], -1) !=
            flowd_json_int(readback, integers[i], -2))
            return 0;
    if (!json_object_object_get_ex(plan, "targets", &plan_targets) ||
        !json_object_object_get_ex(readback, "targets", &readback_targets) ||
        !plan_targets || !readback_targets ||
        !json_object_equal(plan_targets, readback_targets))
        return 0;
    if (!json_object_object_get_ex(readback, "revision", &revision) || !revision ||
        !json_object_is_type(revision, json_type_int))
        return 0;
    return json_object_get_int64(revision) ==
           (expected_revision == 0 ? 1 : expected_revision + 1);
}

struct json_object *flowd_wan_sla_commit(struct json_object *body)
{
    struct json_object *preview, *plan = NULL, *submitted_plan = NULL;
    struct json_object *value = NULL, *readback = NULL, *out, *request = NULL;
    const char *provided = flowd_json_str(body,"plan_digest","");
    const char *computed;
    const char *operation;
    const char *id;
    int64_t expected_revision;
    if (!provided[0]) return sla_error("plan_digest_required","plan_digest is required",422);
    if (sla_json_int64_required(body,"expected_revision",&expected_revision) != 0) return sla_error("expected_revision_required","expected_revision is required",422);
    if (!json_object_object_get_ex(body, "plan", &submitted_plan) || !submitted_plan ||
        !json_object_is_type(submitted_plan, json_type_object))
        return sla_error("plan_required","the canonical preview plan is required",422);
    request = json_tokener_parse(json_object_to_json_string_ext(
        submitted_plan, JSON_C_TO_STRING_PLAIN));
    if (!request || !json_object_is_type(request, json_type_object)) {
        if (request) json_object_put(request);
        return sla_error("invalid_plan","canonical preview plan is invalid",400);
    }
    json_object_object_add(request, "expected_revision",
                           json_object_new_int64(expected_revision));
    operation = flowd_json_str(request,"operation","upsert");
    id = flowd_json_str(request,"id","");
    preview = flowd_wan_sla_preview(request);
    if (!json_object_object_get_ex(preview,"ok",&value) || !json_object_get_boolean(value)) {
        json_object_put(request);
        return preview;
    }
    computed = flowd_json_str(preview,"plan_digest","");
    if (strcmp(provided,computed)) { json_object_put(request); json_object_put(preview); return sla_error("plan_conflict","submitted plan does not match preview",409); }
    json_object_object_get_ex(preview,"plan",&plan);
    if (!plan || !json_object_equal(submitted_plan, plan)) { json_object_put(request); json_object_put(preview); return sla_error("plan_not_canonical","submitted plan differs from current canonical plan",409); }
    if (sla_exec("BEGIN IMMEDIATE") != 0) { json_object_put(request); json_object_put(preview); return sla_error("transaction_busy","WAN SLA transaction could not start",409); }
    if (sla_write_plan(plan,expected_revision) != 0) { sla_exec("ROLLBACK"); json_object_put(request); json_object_put(preview); return sla_error("revision_conflict","WAN SLA write conflicted and was rolled back",409); }
    if (strcmp(operation,"delete")) {
        readback = sla_load(id);
        if (!sla_readback_matches(plan, readback, expected_revision)) { if (readback) json_object_put(readback); sla_exec("ROLLBACK"); json_object_put(request); json_object_put(preview); return sla_error("readback_mismatch","WAN SLA write was rolled back after readback mismatch",500); }
    } else {
        struct json_object *deleted_readback = sla_load(id);
        if (deleted_readback) {
            json_object_put(deleted_readback);
            sla_exec("ROLLBACK"); json_object_put(request); json_object_put(preview);
            return sla_error("readback_mismatch","WAN SLA delete was rolled back after readback mismatch",500);
        }
    }
    if (sla_exec("COMMIT") != 0) { if (readback) json_object_put(readback); json_object_put(request); json_object_put(preview); return sla_error("commit_failed","WAN SLA commit failed",500); }
    out = sla_ok();
    json_object_object_add(out,"operation",json_object_new_string(operation));
    json_object_object_add(out,"resource_id",json_object_new_string(id));
    json_object_object_add(out,"applied",json_object_new_boolean(1));
    json_object_object_add(out,"runtime_applied",json_object_new_boolean(0));
    json_object_object_add(out,"runtime_reason",json_object_new_string("wan_sla_sampler_executor_not_implemented"));
    json_object_object_add(out,"plan_digest",json_object_new_string(provided));
    if (readback) json_object_object_add(out,"readback",readback);
    json_object_object_add(out,"capabilities",sla_capabilities());
    json_object_put(request);
    json_object_put(preview);
    return out;
}
