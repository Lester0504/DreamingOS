#!/usr/bin/env python3
"""Execute otad's real SQLite migration, preflight commit, and apply claim."""

import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]

STUBS = {
    "libubox/blobmsg.h": r"""
#pragma once
struct blob_attr;
struct blob_buf { int unused; };
""",
    "libubox/blobmsg_json.h": r"""
#pragma once
#include <stdbool.h>
struct blob_attr;
char *blobmsg_format_json(struct blob_attr *, bool);
""",
    "libubox/uloop.h": r"""
#pragma once
#include <sys/types.h>
struct uloop_timeout { void (*cb)(struct uloop_timeout *); };
struct uloop_process { pid_t pid; void (*cb)(struct uloop_process *, int); };
""",
    "libubox/utils.h": r"""
#pragma once
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
""",
    "libubus.h": r"""
#pragma once
struct ubus_context;
""",
    "linux/fs.h": r"""
#pragma once
#include <sys/ioctl.h>
#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12, 114, unsigned long long)
#endif
""",
    "sys/mount.h": r"""
#pragma once
#define MS_RDONLY 1UL
#define MS_NOSUID 2UL
#define MS_NODEV 4UL
#define MS_NOEXEC 8UL
#define MS_NOATIME 1024UL
#define MNT_DETACH 2
""",
}

HARNESS = r'''
#include "otad_internal.h"

sqlite3 *g_otad_config_db;
sqlite3 *g_otad_inventory_db;
struct ubus_context *g_otad_ubus;
struct blob_buf g_otad_blob;
struct uloop_timeout g_otad_confirm_timer;

int64_t otad_now_s(void)
{
    static int64_t now = 1700000000;
    return ++now;
}

const char *otad_json_str(struct json_object *o, const char *key, const char *def)
{
    struct json_object *value = NULL;

    if (!o || !json_object_object_get_ex(o, key, &value) ||
        !json_object_is_type(value, json_type_string))
        return def;
    return json_object_get_string(value);
}

struct json_object *otad_error(const char *code, const char *message)
{
    struct json_object *result = json_object_new_object();

    json_object_object_add(result, "ok", json_object_new_boolean(0));
    json_object_object_add(result, "error", json_object_new_string(code ? code : "error"));
    json_object_object_add(result, "message", json_object_new_string(message ? message : ""));
    return result;
}

void otad_json_add_string(struct json_object *o, const char *key, const char *value)
{
    json_object_object_add(o, key, json_object_new_string(value ? value : ""));
}

int otad_mkdir_p(const char *path, mode_t mode)
{
    (void)path;
    (void)mode;
    return 0;
}

#include "otad_db.c"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static int sql(sqlite3 *db, const char *statement)
{
    char *error = NULL;
    int rc = sqlite3_exec(db, statement, NULL, NULL, &error);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite failure: %s sql=%s\n", error ? error : "", statement);
        sqlite3_free(error);
        return -1;
    }
    return 0;
}

static int scalar_int(sqlite3 *db, const char *statement)
{
    sqlite3_stmt *st = NULL;
    int value = -999;

    if (sqlite3_prepare_v2(db, statement, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        value = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return value;
}

static int scalar_text(sqlite3 *db, const char *statement,
                       char *out, size_t out_len)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(db, statement, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) {
        const char *value = (const char *)sqlite3_column_text(st, 0);
        snprintf(out, out_len, "%s", value ? value : "");
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static int create_legacy_inventory(void)
{
    sqlite3 *db = NULL;
    const char *legacy =
        "CREATE TABLE ota_operations ("
        "operation_id TEXT PRIMARY KEY,kind TEXT NOT NULL,action TEXT NOT NULL,"
        "upload_id TEXT NOT NULL DEFAULT '',state TEXT NOT NULL DEFAULT 'validating',"
        "progress INTEGER NOT NULL DEFAULT 0,worker_pid INTEGER NOT NULL DEFAULT 0,"
        "source_size INTEGER NOT NULL DEFAULT 0,source_sha256 TEXT NOT NULL DEFAULT '',"
        "from_version TEXT NOT NULL DEFAULT '',to_version TEXT NOT NULL DEFAULT '',"
        "build_id TEXT NOT NULL DEFAULT '',target_slot TEXT NOT NULL DEFAULT '',"
        "options_json TEXT NOT NULL DEFAULT '{}',result_json TEXT NOT NULL DEFAULT '{}',"
        "error_code TEXT NOT NULL DEFAULT '',error_message TEXT NOT NULL DEFAULT '',"
        "created_at INTEGER NOT NULL,started_at INTEGER NOT NULL DEFAULT 0,"
        "updated_at INTEGER NOT NULL,completed_at INTEGER NOT NULL DEFAULT 0);"
        "INSERT INTO ota_operations(operation_id,kind,action,state,created_at,updated_at) "
        "VALUES('ota-00000000000000000000000000000000','firmware','preflight',"
        "'validating',1,1);";

    if (sqlite3_open(OTAD_INVENTORY_DB_PATH, &db) != SQLITE_OK)
        return -1;
    if (sql(db, legacy) != 0) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_close(db);
    return 0;
}

static int insert_pending(const char *id)
{
    sqlite3_stmt *st = NULL;
    const char *statement =
        "INSERT INTO ota_operations("
        "operation_id,kind,action,state,manifest_digest,signing_key_id,"
        "trust_policy_version,trust_policy_digest,device_identity_digest,"
        "topology_digest,authenticity_verified,target_compatible,policy_passed,"
        "source_size,source_sha256,target_slot,created_at,updated_at) VALUES("
        "?1,'firmware','preflight','pending',?2,'release-2026',7,?3,?4,?5,1,1,1,"
        "1048576,?2,'B',1,1)";
    const char *digest_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const char *digest_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const char *digest_c = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const char *digest_d = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    int rc;

    if (sqlite3_prepare_v2(g_otad_inventory_db, statement, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, digest_a, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, digest_b, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, digest_c, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 5, digest_d, -1, SQLITE_STATIC);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int reset_pending(const char *id, const char *mutation)
{
    char statement[1024];

    snprintf(statement, sizeof(statement),
             "DELETE FROM ota_operations WHERE operation_id='%s';", id);
    if (sql(g_otad_inventory_db, statement) != 0 || insert_pending(id) != 0)
        return -1;
    if (mutation && mutation[0])
        return sql(g_otad_inventory_db, mutation);
    return 0;
}

int main(void)
{
    struct otad_trust_binding binding;
    struct json_object *result;
    struct json_object *second_result;
    char value[128];
    const char *legacy_id = "ota-00000000000000000000000000000000";
    const char *claim_id = "ota-11111111111111111111111111111111";
    const char *bad_mutations[] = {
        "UPDATE ota_operations SET manifest_digest='' WHERE operation_id='ota-11111111111111111111111111111111'",
        "UPDATE ota_operations SET manifest_digest='short' WHERE operation_id='ota-11111111111111111111111111111111'",
        "UPDATE ota_operations SET manifest_digest='zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz' WHERE operation_id='ota-11111111111111111111111111111111'",
        "UPDATE ota_operations SET signing_key_id='' WHERE operation_id='ota-11111111111111111111111111111111'",
        "UPDATE ota_operations SET signing_key_id='bad/key' WHERE operation_id='ota-11111111111111111111111111111111'",
        "UPDATE ota_operations SET trust_policy_version=0 WHERE operation_id='ota-11111111111111111111111111111111'",
        "UPDATE ota_operations SET trust_policy_digest='short' WHERE operation_id='ota-11111111111111111111111111111111'",
        "UPDATE ota_operations SET device_identity_digest='short' WHERE operation_id='ota-11111111111111111111111111111111'",
        "UPDATE ota_operations SET topology_digest='short' WHERE operation_id='ota-11111111111111111111111111111111'",
        "UPDATE ota_operations SET authenticity_verified=0 WHERE operation_id='ota-11111111111111111111111111111111'",
        "UPDATE ota_operations SET target_compatible=0 WHERE operation_id='ota-11111111111111111111111111111111'",
        "UPDATE ota_operations SET policy_passed=0 WHERE operation_id='ota-11111111111111111111111111111111'",
        "UPDATE ota_operations SET source_size=0 WHERE operation_id='ota-11111111111111111111111111111111'",
        "UPDATE ota_operations SET source_sha256='gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg' WHERE operation_id='ota-11111111111111111111111111111111'",
        "UPDATE ota_operations SET target_slot='C' WHERE operation_id='ota-11111111111111111111111111111111'",
    };
    size_t i;

    CHECK(create_legacy_inventory() == 0);
    CHECK(otad_db_init() == 0);

    CHECK(scalar_int(g_otad_inventory_db,
        "SELECT COUNT(*) FROM pragma_table_info('ota_operations') WHERE name IN ("
        "'manifest_digest','signing_key_id','trust_policy_version','trust_policy_digest',"
        "'device_identity_digest','topology_digest','authenticity_verified',"
        "'target_compatible','policy_passed')") == 9);
    CHECK(scalar_int(g_otad_inventory_db,
        "SELECT trust_policy_version FROM ota_operations WHERE operation_id="
        "'ota-00000000000000000000000000000000'") == 0);
    CHECK(scalar_text(g_otad_inventory_db,
        "SELECT manifest_digest FROM ota_operations WHERE operation_id="
        "'ota-00000000000000000000000000000000'", value, sizeof(value)) == 0);
    CHECK(value[0] == '\0');
    CHECK(otad_operation_update(legacy_id, "pending", 20, NULL, NULL, NULL) == -1);
    CHECK(otad_operation_update(legacy_id, "writing", 25, NULL, NULL, NULL) == -1);

    CHECK(otad_operation_set_source(legacy_id, 1048576,
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee") == 0);

    memset(&binding, 0, sizeof(binding));
    snprintf(binding.manifest_digest, sizeof(binding.manifest_digest), "%064d", 1);
    snprintf(binding.signing_key_id, sizeof(binding.signing_key_id), "release-2026");
    binding.trust_policy_version = 7;
    snprintf(binding.trust_policy_digest, sizeof(binding.trust_policy_digest), "%064d", 2);
    snprintf(binding.device_identity_digest, sizeof(binding.device_identity_digest), "%064d", 3);
    binding.authenticity_verified = 1;
    binding.target_compatible = 1;
    binding.policy_passed = 1;
    result = json_object_new_object();
    CHECK(result != NULL);
    json_object_object_add(result, "ok", json_object_new_boolean(1));
    CHECK(otad_operation_commit_preflight(legacy_id, "old", "new", "build-1", "B",
        &binding, "0000000000000000000000000000000000000000000000000000000000000004",
        result) == 0);
    json_object_put(result);
    CHECK(scalar_text(g_otad_inventory_db,
        "SELECT state FROM ota_operations WHERE operation_id="
        "'ota-00000000000000000000000000000000'", value, sizeof(value)) == 0);
    CHECK(strcmp(value, "pending") == 0);
    CHECK(scalar_int(g_otad_inventory_db,
        "SELECT authenticity_verified AND target_compatible AND policy_passed "
        "FROM ota_operations WHERE operation_id="
        "'ota-00000000000000000000000000000000'") == 1);
    second_result = json_object_new_object();
    CHECK(second_result != NULL);
    CHECK(otad_operation_commit_preflight(legacy_id, "x", "y", "z", "A", &binding,
        "0000000000000000000000000000000000000000000000000000000000000004",
        second_result) == -1);
    json_object_put(second_result);
    CHECK(scalar_text(g_otad_inventory_db,
        "SELECT to_version FROM ota_operations WHERE operation_id="
        "'ota-00000000000000000000000000000000'", value, sizeof(value)) == 0);
    CHECK(strcmp(value, "new") == 0);

    for (i = 0; i < sizeof(bad_mutations) / sizeof(bad_mutations[0]); i++) {
        CHECK(reset_pending(claim_id, bad_mutations[i]) == 0);
        CHECK(otad_operation_claim_apply(claim_id) == -1);
        CHECK(scalar_text(g_otad_inventory_db,
            "SELECT state FROM ota_operations WHERE operation_id="
            "'ota-11111111111111111111111111111111'", value, sizeof(value)) == 0);
        CHECK(strcmp(value, "pending") == 0);
    }

    CHECK(reset_pending(claim_id, NULL) == 0);
    CHECK(otad_operation_claim_apply(claim_id) == 0);
    CHECK(otad_operation_claim_apply(claim_id) == -1);
    CHECK(scalar_text(g_otad_inventory_db,
        "SELECT action || ':' || state FROM ota_operations WHERE operation_id="
        "'ota-11111111111111111111111111111111'", value, sizeof(value)) == 0);
    CHECK(strcmp(value, "apply:writing") == 0);

    otad_db_close();
    puts("ok: real SQLite migration, atomic preflight binding, and single fail-closed claim");
    return 0;
}
'''


def dependency_roots() -> tuple[Path, ...]:
    configured = os.environ.get("OTAD_TEST_DEP_ROOT", "")
    roots: list[Path] = []

    if configured:
        root = Path(configured)
        roots.append(root / "usr" if (root / "usr/include").is_dir() else root)
    roots.extend((
        Path("/opt/homebrew"),
        Path("/usr/local"),
        Path("/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19"),
    ))
    return tuple(roots)


def find_dependencies() -> tuple[Path, Path, Path, Path]:
    roots = dependency_roots()
    for root in roots:
        header = root / "include/json-c/json.h"
        library = root / "lib/libjson-c.a"
        if not header.is_file() or not library.is_file():
            continue
        crypto_roots = (root, Path("/opt/homebrew/opt/openssl@3"), Path("/usr/local/opt/openssl@3"))
        for crypto_root in crypto_roots:
            if (crypto_root / "include/openssl/evp.h").is_file():
                return (root / "include", library,
                        crypto_root / "include", root / "lib")
    raise RuntimeError("json-c and OpenSSL development files not found")


def main() -> None:
    json_include, json_library, crypto_include, library_dir = find_dependencies()
    with tempfile.TemporaryDirectory(prefix="otad-sqlite-runtime-") as td:
        temp = Path(td)
        for name, content in STUBS.items():
            path = temp / "stubs" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="ascii")
        harness = temp / "harness.c"
        harness.write_text(HARNESS, encoding="ascii")
        binary = temp / "harness"
        config_db = temp / "config.db"
        inventory_db = temp / "inventory.db"
        command = [
            os.environ.get("CC", "cc"),
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror=implicit-function-declaration",
            "-I", str(temp / "stubs"),
            "-I", str(json_include),
            "-I", str(crypto_include),
            "-I", str(ROOT / "src/otad"),
            f'-DOTAD_CONFIG_DB_PATH="{config_db}"',
            f'-DOTAD_INVENTORY_DB_PATH="{inventory_db}"',
            str(harness),
            str(json_library),
            "-L", str(library_dir),
            "-lsqlite3",
            "-o", str(binary),
        ]
        subprocess.run(command, check=True)
        run_env = os.environ.copy()
        current_library_path = run_env.get("LD_LIBRARY_PATH", "")
        run_env["LD_LIBRARY_PATH"] = str(library_dir) + (
            f":{current_library_path}" if current_library_path else ""
        )
        subprocess.run([str(binary)], check=True, env=run_env)


if __name__ == "__main__":
    main()
