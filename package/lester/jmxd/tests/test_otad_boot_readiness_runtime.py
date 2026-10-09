#!/usr/bin/env python3
"""Compile and execute the OTA boot-readiness classifier against fixtures."""

import os
from pathlib import Path
import subprocess
import tempfile

from otad_test_deps import find_host_dependencies


ROOT = Path(__file__).resolve().parents[1]

STUBS = {
    "libubox/blobmsg.h": "struct blob_attr; struct blob_buf { int unused; };\n",
    "libubox/blobmsg_json.h": "#include <stdbool.h>\nstruct blob_attr; char *blobmsg_format_json(struct blob_attr *, bool);\n",
    "libubox/uloop.h": "#include <sys/types.h>\nstruct uloop_timeout { void (*cb)(struct uloop_timeout *); }; struct uloop_process { pid_t pid; void (*cb)(struct uloop_process *, int); };\n",
    "libubox/utils.h": "#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))\n",
    "libubus.h": "struct ubus_context;\n",
    "linux/fs.h": "#include <sys/ioctl.h>\n#ifndef BLKGETSIZE64\n#define BLKGETSIZE64 _IOR(0x12, 114, unsigned long long)\n#endif\n",
    "sys/mount.h": "#define MS_RDONLY 1UL\n#define MS_NOSUID 2UL\n#define MS_NODEV 4UL\n#define MS_NOEXEC 8UL\n#define MS_NOATIME 1024UL\n#define MNT_DETACH 2\n",
}

HARNESS = r'''
#include "otad_internal.h"

const char *otad_json_str(struct json_object *o, const char *key, const char *def)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, key, &v) || !v ||
        !json_object_is_type(v, json_type_string))
        return def;
    return json_object_get_string(v);
}

#include "otad_boot_readiness.c"

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "check failed line %d: %s\n", __LINE__, #expr); \
    exit(1); \
} } while (0)

static const char *db_names[] = { "config", "apid", "core", "logd", "notifyd" };
static const char *anchors[] = { "web_users", "web_sessions", "clients", "log_events", "notify_outbox" };

static struct json_object *baseline(void)
{
    struct json_object *health = json_object_new_object();
    struct json_object *storage = json_object_new_object();
    struct json_object *databases = json_object_new_array();
    struct json_object *reasons = json_object_new_array();
    size_t i;

    json_object_object_add(health, "supervisor_running", json_object_new_boolean(1));
    json_object_object_add(health, "jmx_module_loaded", json_object_new_boolean(1));
    json_object_object_add(health, "critical_components_failed", json_object_new_int(0));
    json_object_object_add(health, "persistent_store_writable", json_object_new_boolean(1));
    json_object_object_add(health, "required_databases_ready", json_object_new_boolean(1));
    json_object_object_add(health, "required_databases_reason", json_object_new_string("ready"));
    json_object_object_add(health, "storage_source", json_object_new_string("core"));
    json_object_object_add(storage, "health", json_object_new_string("ok"));
    for (i = 0; i < 5; i++) {
        struct json_object *db = json_object_new_object();
        struct json_object *tables = json_object_new_array();
        struct json_object *table = json_object_new_object();
        json_object_object_add(db, "name", json_object_new_string(db_names[i]));
        json_object_object_add(db, "required", json_object_new_boolean(1));
        json_object_object_add(db, "present", json_object_new_boolean(1));
        json_object_object_add(table, "name", json_object_new_string(anchors[i]));
        json_object_object_add(table, "present", json_object_new_boolean(1));
        json_object_array_add(tables, table);
        json_object_object_add(db, "tables", tables);
        json_object_array_add(databases, db);
    }
    json_object_object_add(storage, "databases", databases);
    json_object_object_add(storage, "reasons", reasons);
    json_object_object_add(health, "storage", storage);
    return health;
}

static struct json_object *storage(struct json_object *health)
{
    struct json_object *value = NULL;
    CHECK(json_object_object_get_ex(health, "storage", &value));
    return value;
}

static struct json_object *database(struct json_object *health, size_t index)
{
    struct json_object *databases = NULL;
    CHECK(json_object_object_get_ex(storage(health), "databases", &databases));
    return json_object_array_get_idx(databases, index);
}

static void add_reason(struct json_object *health, const char *level,
                       const char *scope, const char *name, const char *reason)
{
    struct json_object *reasons = NULL;
    struct json_object *item = json_object_new_object();
    json_object_object_get_ex(storage(health), "reasons", &reasons);
    json_object_object_add(item, "level", json_object_new_string(level));
    json_object_object_add(item, "scope", json_object_new_string(scope));
    json_object_object_add(item, "name", json_object_new_string(name));
    json_object_object_add(item, "reason", json_object_new_string(reason));
    json_object_array_add(reasons, item);
    json_object_object_del(storage(health), "health");
    json_object_object_add(storage(health), "health", json_object_new_string(level));
}

static void expect_ready(struct json_object *health, int degraded)
{
    struct otad_boot_readiness result;
    CHECK(otad_boot_readiness_evaluate(health, &result) == 0);
    CHECK(result.ready == 1);
    CHECK(result.degraded == degraded);
}

static void expect_failed(struct json_object *health, const char *dimension,
                          const char *reason)
{
    struct otad_boot_readiness result;
    CHECK(otad_boot_readiness_evaluate(health, &result) != 0);
    CHECK(result.ready == 0);
    CHECK(strcmp(result.dimension, dimension) == 0);
    CHECK(strcmp(result.reason, reason) == 0);
}

int main(void)
{
    struct json_object *h;
    struct json_object *tables = NULL;
    struct json_object *table = NULL;
    struct otad_boot_readiness services;

    CHECK(otad_boot_services_evaluate(0, 1, &services) != 0);
    CHECK(strcmp(services.dimension, "core_ubus") == 0);
    CHECK(strcmp(services.reason, "core_ubus_unavailable") == 0);
    CHECK(otad_boot_services_evaluate(1, 0, &services) != 0);
    CHECK(strcmp(services.dimension, "network_ubus") == 0);
    CHECK(strcmp(services.reason, "network_ubus_unavailable") == 0);
    CHECK(otad_boot_services_evaluate(1, 1, &services) == 0);

    h = baseline(); expect_ready(h, 0); json_object_put(h);

    memset(&services, 0, sizeof(services));
    snprintf(services.reason, sizeof(services.reason), "core_ubus_unavailable");
    CHECK(otad_boot_readiness_requires_rollback(&services) == 1);
    snprintf(services.reason, sizeof(services.reason), "boot_readiness_malformed");
    CHECK(otad_boot_readiness_requires_rollback(&services) == 0);
    snprintf(services.reason, sizeof(services.reason), "table_rows_critical");
    CHECK(otad_boot_readiness_requires_rollback(&services) == 0);

    expect_failed(NULL, "health_contract", "boot_readiness_malformed");
    h = json_object_new_object();
    expect_failed(h, "supervisor", "supervisor_status_missing");
    json_object_put(h);

    h = baseline();
    add_reason(h, "critical", "database.core", "core.dashboard_activity_sample",
               "table_rows_critical");
    expect_ready(h, 1); json_object_put(h);

    h = baseline();
    add_reason(h, "warning", "database", "core", "db_size_warning");
    expect_ready(h, 1); json_object_put(h);

    h = baseline();
    add_reason(h, "critical", "filesystem", "root", "filesystem_usage_critical");
    expect_ready(h, 1); json_object_put(h);

    h = baseline();
    json_object_object_del(h, "supervisor_running");
    json_object_object_add(h, "supervisor_running", json_object_new_boolean(0));
    expect_failed(h, "supervisor", "supervisor_not_running"); json_object_put(h);

    h = baseline();
    json_object_object_del(h, "critical_components_failed");
    json_object_object_add(h, "critical_components_failed", json_object_new_int(1));
    expect_failed(h, "runtime_components", "critical_components_failed"); json_object_put(h);

    h = baseline();
    json_object_object_del(h, "storage_source");
    expect_failed(h, "storage_contract", "core_storage_health_unavailable"); json_object_put(h);

    h = baseline();
    json_object_object_del(h, "persistent_store_writable");
    json_object_object_add(h, "persistent_store_writable", json_object_new_boolean(0));
    expect_failed(h, "storage_runtime", "persistent_store_not_writable"); json_object_put(h);

    h = baseline();
    json_object_object_del(h, "required_databases_ready");
    json_object_object_del(h, "required_databases_reason");
    json_object_object_add(h, "required_databases_ready", json_object_new_boolean(0));
    json_object_object_add(h, "required_databases_reason", json_object_new_string("core_database_integrity_failed"));
    expect_failed(h, "storage_database", "core_database_integrity_failed"); json_object_put(h);

    h = baseline();
    json_object_object_add(database(h, 2), "open_error", json_object_new_string("database disk image is malformed"));
    expect_failed(h, "storage_database", "sqlite_open_failed"); json_object_put(h);

    h = baseline();
    json_object_object_add(database(h, 2), "read_only", json_object_new_boolean(1));
    expect_failed(h, "storage_database", "database_read_only"); json_object_put(h);

    h = baseline();
    json_object_object_get_ex(database(h, 2), "tables", &tables);
    table = json_object_array_get_idx(tables, 0);
    json_object_object_del(table, "present");
    json_object_object_add(table, "present", json_object_new_boolean(0));
    expect_failed(h, "storage_schema", "required_table_missing"); json_object_put(h);

    h = baseline();
    add_reason(h, "critical", "database", "core", "sqlite_open_failed");
    expect_failed(h, "storage", "sqlite_open_failed"); json_object_put(h);

    return 0;
}
'''


def main() -> None:
    deps = find_host_dependencies(ROOT, require_crypto_library=False)
    with tempfile.TemporaryDirectory(prefix="otad-readiness-") as td:
        temp = Path(td)
        for name, content in STUBS.items():
            path = temp / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        harness = temp / "fixture.c"
        binary = temp / "fixture"
        harness.write_text(HARNESS, encoding="utf-8")
        subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=gnu11",
                "-Wall",
                "-Wextra",
                "-Werror",
                f"-I{temp}",
                f"-I{deps.json_include}",
                f"-I{deps.openssl_include}",
                f"-I{ROOT / 'src' / 'otad'}",
                str(harness),
                "-o",
                str(binary),
                str(deps.json_library),
            ],
            check=True,
        )
        subprocess.run([str(binary)], check=True)
    print("ok: structured OTA boot readiness allows only retention watermarks")


if __name__ == "__main__":
    main()
