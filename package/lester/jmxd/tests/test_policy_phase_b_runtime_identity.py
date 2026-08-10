#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/routed/jmx_route.c").read_text(encoding="utf-8")


def function_source(signature: str) -> str:
    start = SOURCE.index(signature)
    brace = SOURCE.index("{", start)
    depth = 0
    for index in range(brace, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[start:index + 1]
    raise AssertionError(f"unterminated function: {signature}")


def dependency_flags() -> list[str]:
    explicit = os.environ.get("JMX_TEST_DEPENDENCY_FLAGS")
    if explicit:
        return shlex.split(explicit)
    # JMX_TEST_DEPENDENCY_FLAGS still wins. Otherwise resolve both packages
    # through the shared helper: pkg-config cannot answer for json-c on 31.6,
    # and the old `brew --prefix` fallback pointed at an unusable LTO archive.
    return apd_test_deps.package_flags("json-c", "sqlite3")


FIXTURE = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>
#include <sqlite3.h>

#define JMX_ROUTE_MAX_WAN_IFACES 8

__ROUTE_OBJ_INT__
__ROUTE_OBJ_I64__
__ROUTE_OBJ_STR__

struct route_runtime_identity {
    char runtime_id[160];
    char source[64];
    char reason[96];
    int stable;
};

__HASH__
__HASH_ALT__
__SEMANTIC_KEY__
__DUPLICATES__
__IDENTITY__
__COUNTER_UPSERT__

static struct json_object *rule(int prio, long long hits, int proto,
                                const char *wans)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "prio", json_object_new_int(prio));
    json_object_object_add(o, "enabled", json_object_new_int(1));
    json_object_object_add(o, "proto", json_object_new_int(proto));
    json_object_object_add(o, "appid", json_object_new_int(0));
    json_object_object_add(o, "carrier_id", json_object_new_int(0));
    json_object_object_add(o, "src", json_object_new_string("0.0.0.0/0.0.0.0"));
    json_object_object_add(o, "dst", json_object_new_string("0.0.0.0/0.0.0.0"));
    json_object_object_add(o, "dst_port", json_object_new_int(0));
    json_object_object_add(o, "sticky_mode", json_object_new_int(7));
    json_object_object_add(o, "wan_ids", json_object_new_string(wans));
    json_object_object_add(o, "hit_count", json_object_new_int64(hits));
    json_object_object_add(o, "last_hit_seconds_ago", json_object_new_int(3));
    return o;
}

int main(void)
{
    struct route_runtime_identity first;
    struct route_runtime_identity reordered;
    struct route_runtime_identity changed;
    struct route_runtime_identity duplicated;
    struct json_object *rules = json_object_new_array();
    struct json_object *a = rule(100, 10, 0, "1,2");
    struct json_object *b = rule(900, 999999, 0, "1,2");
    struct json_object *c = rule(100, 10, 6, "1,2");
    struct json_object *d = rule(100, 10, 0, "2,1");
    struct json_object *too_many = rule(100, 10, 0, "1,2,3,4,5,6,7,8,9");
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;

    json_object_array_add(rules, json_object_get(a));
    route_runtime_identity_resolve(rules, 0, a, &first);
    assert(first.stable == 1);
    assert(strncmp(first.runtime_id, "runtime-route:", 14) == 0);

    json_object_array_put_idx(rules, 0, json_object_get(b));
    route_runtime_identity_resolve(rules, 0, b, &reordered);
    assert(reordered.stable == 1);
    assert(strcmp(first.runtime_id, reordered.runtime_id) == 0);

    json_object_array_put_idx(rules, 0, json_object_get(c));
    route_runtime_identity_resolve(rules, 0, c, &changed);
    assert(changed.stable == 1);
    assert(strcmp(first.runtime_id, changed.runtime_id) != 0);

    json_object_array_put_idx(rules, 0, json_object_get(too_many));
    route_runtime_identity_resolve(rules, 0, too_many, &changed);
    assert(changed.stable == 0);
    assert(strcmp(changed.reason, "runtime_semantics_invalid") == 0);

    json_object_array_put_idx(rules, 0, json_object_get(d));
    route_runtime_identity_resolve(rules, 0, d, &changed);
    assert(changed.stable == 1);
    assert(strcmp(first.runtime_id, changed.runtime_id) != 0);

    json_object_array_put_idx(rules, 0, json_object_get(a));
    json_object_array_add(rules, json_object_get(a));
    route_runtime_identity_resolve(rules, 0, a, &duplicated);
    assert(duplicated.stable == 0);
    assert(strcmp(duplicated.reason, "duplicate_runtime_semantics") == 0);

    assert(sqlite3_open(":memory:", &db) == SQLITE_OK);
    assert(sqlite3_exec(db,
        "CREATE TABLE route_rule_counter("
        "rule_id TEXT PRIMARY KEY,prio INTEGER,name TEXT,action TEXT,target TEXT,"
        "hit_count INTEGER,active_flows INTEGER,up_rate INTEGER,down_rate INTEGER,"
        "last_hit INTEGER,updated_at INTEGER);"
        "CREATE TABLE route_rule_counter_v2("
        "runtime_id TEXT PRIMARY KEY,configured_id TEXT,configured_type TEXT,"
        "kernel_prio INTEGER,name TEXT,action TEXT,target TEXT,hit_count INTEGER,"
        "byte_count INTEGER,byte_counter_supported INTEGER,last_hit INTEGER,"
        "observed_at INTEGER,reset_generation INTEGER,counter_source TEXT,"
        "identity_source TEXT,updated_at INTEGER);",
        NULL, NULL, NULL) == SQLITE_OK);
    json_object_object_add(a, "runtime_id", json_object_new_string(first.runtime_id));
    json_object_object_add(a, "runtime_identity_stable", json_object_new_int(1));
    json_object_object_add(a, "runtime_identity_source",
                           json_object_new_string(first.source));
    assert(route_rule_counter_upsert(db, a, 1000) == 0);
    assert(json_object_get_int(json_object_object_get(
        a, "counter_reset_generation")) == 0);
    json_object_object_add(a, "hit_count", json_object_new_int64(5));
    assert(route_rule_counter_upsert(db, a, 1001) == 0);
    assert(json_object_get_int(json_object_object_get(
        a, "counter_reset_generation")) == 1);
    assert(json_object_get_boolean(json_object_object_get(
        a, "counter_reset_detected")) == 1);
    assert(sqlite3_prepare_v2(db,
        "SELECT hit_count,byte_count,byte_counter_supported,reset_generation "
        "FROM route_rule_counter_v2 WHERE runtime_id=?1", -1, &st, NULL) == SQLITE_OK);
    sqlite3_bind_text(st, 1, first.runtime_id, -1, SQLITE_TRANSIENT);
    assert(sqlite3_step(st) == SQLITE_ROW);
    assert(sqlite3_column_int64(st, 0) == 5);
    assert(sqlite3_column_type(st, 1) == SQLITE_NULL);
    assert(sqlite3_column_int(st, 2) == 0);
    assert(sqlite3_column_int(st, 3) == 1);
    sqlite3_finalize(st);
    sqlite3_close(db);

    json_object_put(rules);
    json_object_put(a);
    json_object_put(b);
    json_object_put(too_many);
    json_object_put(c);
    json_object_put(d);
    puts("ok: Phase B runtime identity is priority-independent and fail-closed");
    return 0;
}
'''


def main() -> None:
    identity = function_source("static void route_runtime_identity_resolve(")
    semantic = function_source("static int route_runtime_semantic_key(")
    assert '"prio"' not in semantic
    assert '"hit_count"' not in semantic
    assert '"last_hit"' not in semantic
    assert 'json_object_new_null()' in SOURCE[SOURCE.index("static void route_enrich_rules("):
                                             SOURCE.index("static struct json_object *route_build_policy_groups(")]
    assert "route_rule_counter_v2" in SOURCE
    assert "reset_generation" in SOURCE
    assert "BEGIN IMMEDIATE" in function_source("static int route_state_persist_rule_counters(")
    assert "ROLLBACK" in function_source("static int route_state_persist_rule_counters(")
    assert "jmx_route_kernel_exposes_packet_hits_only" in SOURCE

    fixture = FIXTURE
    replacements = {
        "__ROUTE_OBJ_INT__": function_source("static int route_obj_int("),
        "__ROUTE_OBJ_I64__": function_source("static int64_t route_obj_i64("),
        "__ROUTE_OBJ_STR__": function_source("static const char *route_obj_str("),
        "__HASH__": function_source("static uint64_t route_runtime_hash("),
        "__HASH_ALT__": function_source("static uint64_t route_runtime_hash_alt("),
        "__SEMANTIC_KEY__": semantic,
        "__DUPLICATES__": function_source("static int route_runtime_semantic_duplicates("),
        "__IDENTITY__": identity,
        "__COUNTER_UPSERT__": function_source("static int route_rule_counter_upsert("),
    }
    for marker, body in replacements.items():
        fixture = fixture.replace(marker, body)

    compiler = (os.environ.get("JMX_TEST_CC") or shutil.which("cc") or
                shutil.which("clang") or shutil.which("gcc"))
    assert compiler, "host C compiler unavailable"
    with tempfile.TemporaryDirectory(prefix="policy-phase-b-runtime-id-") as temporary:
        source = Path(temporary) / "fixture.c"
        binary = Path(temporary) / "fixture"
        source.write_text(fixture, encoding="utf-8")
        subprocess.run([
            compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
            str(source), "-o", str(binary), *dependency_flags(),
        ], check=True)
        runtime_env = os.environ.copy()
        library_path = os.environ.get("JMX_TEST_LIBRARY_PATH")
        if library_path:
            current = runtime_env.get("LD_LIBRARY_PATH", "")
            runtime_env["LD_LIBRARY_PATH"] = (
                f"{library_path}:{current}" if current else library_path
            )
        result = subprocess.run([str(binary)], check=True, text=True,
                                capture_output=True, env=runtime_env)
        print(result.stdout.strip())


if __name__ == "__main__":
    main()
