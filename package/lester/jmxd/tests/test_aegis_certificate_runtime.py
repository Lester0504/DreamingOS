#!/usr/bin/env python3
"""Executable lifecycle tests for the isolated AegisX inspection CA."""

from __future__ import annotations

import base64
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import textwrap


ROOT = Path(__file__).resolve().parents[1]
AEGIS = ROOT / "src" / "aegisxd"


def _pkg_config(*packages: str) -> list[str]:
    output = subprocess.check_output(
        [os.environ.get("PKG_CONFIG", "pkg-config"), "--cflags", "--libs", *packages],
        text=True,
    )
    return shlex.split(output)


def _stub_headers(root: Path) -> None:
    (root / "libubox").mkdir(parents=True)
    (root / "libubox" / "blobmsg.h").write_text(
        "struct blob_attr { int unused; }; struct blob_buf { int unused; };\n",
        encoding="ascii",
    )
    (root / "libubox" / "blobmsg_json.h").write_text(
        "char *blobmsg_format_json(struct blob_attr *, int);\n", encoding="ascii"
    )
    (root / "libubox" / "uloop.h").write_text("\n", encoding="ascii")
    (root / "libubox" / "utils.h").write_text("\n", encoding="ascii")
    (root / "libubus.h").write_text(
        "struct ubus_context { int unused; };\n", encoding="ascii"
    )


def test_inspection_ca_full_lifecycle() -> None:
    with tempfile.TemporaryDirectory(prefix="aegis-certificate-") as raw:
        sandbox = Path(raw)
        include = sandbox / "include"
        pki = sandbox / "pki"
        clients_db = sandbox / "dreamingwrt.db"
        source = sandbox / "fixture.c"
        binary = sandbox / "fixture"
        _stub_headers(include)
        source.write_text(
            textwrap.dedent(
                r'''
                #include <assert.h>
                #include "aegisxd_internal.h"
                #include "aegisxd_certificate.c"

                    sqlite3 *g_aegisxd_config_db;
                sqlite3 *g_aegisxd_db;
                struct ubus_context *g_aegisxd_ubus;
                struct blob_buf g_aegisxd_blob;

                int64_t aegisxd_now_s(void) { return (int64_t)time(NULL); }
                int aegisxd_mkdir_p(const char *path, mode_t mode) {
                    char value[AEGISXD_MAX_PATH], *cursor;
                    if (!path || path[0] != '/' || strlen(path) >= sizeof(value)) return -1;
                    snprintf(value, sizeof(value), "%s", path);
                    for (cursor = value + 1; *cursor; cursor++) {
                        if (*cursor != '/') continue;
                        *cursor = '\0';
                        if (mkdir(value, mode) != 0 && errno != EEXIST) return -1;
                        *cursor = '/';
                    }
                    return mkdir(value, mode) == 0 || errno == EEXIST ? 0 : -1;
                }
                void aegisxd_json_add_string(struct json_object *object, const char *key,
                                             const char *value) {
                    json_object_object_add(object, key,
                        json_object_new_string(value ? value : ""));
                }
                const char *aegisxd_json_str(struct json_object *object, const char *key,
                                             const char *fallback) {
                    struct json_object *value = NULL;
                    return object && json_object_object_get_ex(object, key, &value) &&
                           json_object_is_type(value, json_type_string) ?
                           json_object_get_string(value) : fallback;
                }
                int aegisxd_json_bool(struct json_object *object, const char *key, int fallback) {
                    struct json_object *value = NULL;
                    return object && json_object_object_get_ex(object, key, &value) ?
                           !!json_object_get_boolean(value) : fallback;
                }
                struct json_object *aegisxd_error(const char *code, const char *message) {
                    struct json_object *object = json_object_new_object();
                    json_object_object_add(object, "ok", json_object_new_boolean(0));
                    aegisxd_json_add_string(object, "error", code);
                    aegisxd_json_add_string(object, "message", message);
                    return object;
                }
                const char *aegisxd_sqlite_text(sqlite3_stmt *statement, int column,
                                                const char *fallback) {
                    const unsigned char *value = sqlite3_column_text(statement, column);
                    return value ? (const char *)value : fallback;
                }
                sqlite3_stmt *aegisxd_config_prepare(const char *sql) {
                    sqlite3_stmt *statement = NULL;
                    return sqlite3_prepare_v2(g_aegisxd_config_db, sql, -1,
                                              &statement, NULL) == SQLITE_OK ? statement : NULL;
                }

                static struct json_object *request(const char *json) {
                    struct json_object *object = json_tokener_parse(json);
                    assert(object);
                    return object;
                }
                static void expect_error(struct json_object *object, const char *code) {
                    assert(!aegisxd_json_bool(object, "ok", 0));
                    assert(!strcmp(aegisxd_json_str(object, "error", ""), code));
                    json_object_put(object);
                }
                static int integer(struct json_object *object, const char *key) {
                    struct json_object *value = NULL;
                    assert(json_object_object_get_ex(object, key, &value));
                    return json_object_get_int(value);
                }
                static void key_mode(int generation) {
                    char path[AEGISXD_MAX_PATH];
                    struct stat status;
                    snprintf(path, sizeof(path), "%s/inspection-ca-%d.key.pem",
                             AEGISXD_PKI_DIR, generation);
                    assert(lstat(path, &status) == 0 && S_ISREG(status.st_mode));
                    assert((status.st_mode & 0777) == 0600);
                }
                static void key_absent(int generation) {
                    char path[AEGISXD_MAX_PATH];
                    snprintf(path, sizeof(path), "%s/inspection-ca-%d.key.pem",
                             AEGISXD_PKI_DIR, generation);
                    assert(access(path, F_OK) != 0);
                }
                static void key_matches_certificate(int generation) {
                    char key_path[AEGISXD_MAX_PATH], cert_path[AEGISXD_MAX_PATH];
                    BIO *key_bio, *cert_bio;
                    EVP_PKEY *key;
                    X509 *certificate;
                    assert(certificate_paths(generation, key_path, sizeof(key_path),
                                             cert_path, sizeof(cert_path)) == 0);
                    key_bio = BIO_new_file(key_path, "r");
                    cert_bio = BIO_new_file(cert_path, "r");
                    assert(key_bio && cert_bio);
                    key = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
                    certificate = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
                    assert(key && certificate);
                    assert(X509_check_private_key(certificate, key) == 1);
                    EVP_PKEY_free(key);
                    X509_free(certificate);
                    BIO_free(key_bio);
                    BIO_free(cert_bio);
                }
                static void expect_state(const char *distribution_id, const char *state) {
                    struct json_object *body = json_object_new_object();
                    struct json_object *response;
                    aegisxd_json_add_string(body, "distribution_id", distribution_id);
                    response = aegisxd_certificate_distribution_get_json(body);
                    json_object_put(body);
                    assert(aegisxd_json_bool(response, "ok", 0));
                    assert(!strcmp(aegisxd_json_str(response, "state", ""), state));
                    json_object_put(response);
                }

                int main(void) {
                    struct json_object *body, *response, *download, *distribution;
                    const char *encoded;
                    char distribution_id[64], second_distribution_id[64];
                    unsigned char decoded[AEGISXD_CA_MAX_PEM];
                    char old_key[AEGISXD_MAX_PATH];
                    sqlite3 *clients = NULL;
                    int decoded_length;

                    assert(sqlite3_open(":memory:", &g_aegisxd_config_db) == SQLITE_OK);
                    assert(sqlite3_open(AEGISXD_CLIENT_DB_PATH, &clients) == SQLITE_OK);
                    assert(sqlite3_exec(clients,
                        "CREATE TABLE clients(mac TEXT PRIMARY KEY);"
                        "INSERT INTO clients(mac) VALUES('aa:bb:cc:dd:ee:ff')",
                        NULL, NULL, NULL) == SQLITE_OK);
                    sqlite3_close(clients);
                    assert(sqlite3_exec(g_aegisxd_config_db,
                        "CREATE TABLE aegis_certificate_distributions("
                        "distribution_id TEXT PRIMARY KEY,ca_generation INTEGER NOT NULL,"
                        "target_type TEXT NOT NULL,target_id TEXT NOT NULL,"
                        "method TEXT NOT NULL CHECK(method IN ('manual')),"
                        "state TEXT NOT NULL CHECK(state IN "
                        "('ready_for_download','downloaded','cancelled')),"
                        "reason TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL DEFAULT 0,"
                        "downloaded_at INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL DEFAULT 0);"
                        "INSERT INTO aegis_certificate_distributions VALUES("
                        "'00000000-0000-4000-8000-000000000000',0,'client',"
                        "'aa:bb:cc:dd:ee:ff','manual','downloaded','migration_probe',1,1,1)" ,
                        NULL, NULL, NULL) == SQLITE_OK);
                    assert(aegisxd_certificate_schema_init() == 0);
                    assert(sqlite3_exec(g_aegisxd_config_db,
                        "UPDATE aegis_certificate_distributions SET state='superseded' "
                        "WHERE distribution_id='00000000-0000-4000-8000-000000000000';"
                        "DELETE FROM aegis_certificate_distributions WHERE "
                        "distribution_id='00000000-0000-4000-8000-000000000000'",
                        NULL, NULL, NULL) == SQLITE_OK);
                    response = aegisxd_certificate_status_json();
                    assert(aegisxd_json_bool(response, "ok", 0));
                    assert(!aegisxd_json_bool(response, "present", 1));
                    assert(!aegisxd_json_bool(response, "ssl_inspection_active", 1));
                    json_object_put(response);

                    body = request("{}");
                    expect_error(aegisxd_certificate_generate_json(body), "confirmation_required");
                    json_object_put(body);
                    setenv("AEGISXD_CERTIFICATE_FAIL_STAGE", "directory-fsync", 1);
                    body = request("{\"confirm\":true,\"validity_days\":365}");
                    expect_error(aegisxd_certificate_generate_json(body),
                                 "inspection_ca_generation_failed");
                    json_object_put(body);
                    unsetenv("AEGISXD_CERTIFICATE_FAIL_STAGE");
                    response = aegisxd_certificate_status_json();
                    assert(integer(response, "generation") == 0);
                    key_absent(1);
                    json_object_put(response);

                    body = request("{\"confirm\":true,\"validity_days\":365}");
                    response = aegisxd_certificate_generate_json(body);
                    json_object_put(body);
                    assert(aegisxd_json_bool(response, "ok", 0));
                    assert(integer(response, "generation") == 1);
                    assert(aegisxd_json_bool(response, "active", 0));
                    assert(!aegisxd_json_bool(response, "private_key_exportable", 1));
                    assert(!aegisxd_json_bool(response, "automatic_distribution_supported", 1));
                    key_mode(1);
                    json_object_put(response);

                    body = request("{\"confirm\":true}");
                    expect_error(aegisxd_certificate_generate_json(body),
                                 "inspection_ca_already_active");
                    json_object_put(body);

                    body = request("{\"format\":\"pem\"}");
                    download = aegisxd_certificate_download_json(body);
                    json_object_put(body);
                    assert(aegisxd_json_bool(download, "ok", 0));
                    assert(!aegisxd_json_bool(download, "private_key_included", 1));
                    encoded = aegisxd_json_str(download, "content_base64", "");
                    decoded_length = EVP_DecodeBlock(decoded,
                        (const unsigned char *)encoded, (int)strlen(encoded));
                    assert(decoded_length > 0);
                    assert(strstr((const char *)decoded, "BEGIN CERTIFICATE") != NULL);
                    assert(strstr((const char *)decoded, "PRIVATE KEY") == NULL);
                    json_object_put(download);

                    body = request("{\"target_type\":\"client\",\"target_id\":\"aa:bb:cc:dd:ee:ff\",\"method\":\"automatic\"}");
                    expect_error(aegisxd_certificate_distribution_create_json(body),
                                 "automatic_distribution_unavailable");
                    json_object_put(body);
                    body = request("{\"target_type\":\"client\",\"target_id\":\"aa:bb:cc:dd:ee:ff\",\"method\":\"manual\"}");
                    distribution = aegisxd_certificate_distribution_create_json(body);
                    json_object_put(body);
                    assert(aegisxd_json_bool(distribution, "ok", 0));
                    assert(!strcmp(aegisxd_json_str(distribution, "state", ""),
                                   "ready_for_download"));
                    assert(!aegisxd_json_bool(distribution, "installed", 1));
                    snprintf(distribution_id, sizeof(distribution_id), "%s",
                             aegisxd_json_str(distribution, "distribution_id", ""));
                    json_object_put(distribution);
                    response = aegisxd_certificate_distributions_json(NULL);
                    assert(integer(response, "total") == 1);
                    json_object_put(response);
                    body = json_object_new_object();
                    aegisxd_json_add_string(body, "distribution_id", distribution_id);
                    json_object_object_add(body, "ca_generation", json_object_new_int(1));
                    response = aegisxd_certificate_distribution_downloaded_json(body);
                    json_object_put(body);
                    assert(aegisxd_json_bool(response, "ok", 0));
                    assert(!strcmp(aegisxd_json_str(response, "state", ""), "downloaded"));
                    assert(!aegisxd_json_bool(response, "installed", 1));
                    json_object_put(response);

                    setenv("AEGISXD_CERTIFICATE_FAIL_STAGE", "before-db-commit", 1);
                    body = request("{\"confirm\":true,\"expected_generation\":1,\"validity_days\":730}");
                    expect_error(aegisxd_certificate_rotate_json(body),
                                 "inspection_ca_generation_failed");
                    json_object_put(body);
                    unsetenv("AEGISXD_CERTIFICATE_FAIL_STAGE");
                    response = aegisxd_certificate_status_json();
                    assert(integer(response, "generation") == 1);
                    assert(aegisxd_json_bool(response, "active", 0));
                    json_object_put(response);
                    key_mode(1);
                    key_matches_certificate(1);
                    key_absent(2);
                    expect_state(distribution_id, "downloaded");
                    body = json_object_new_object();
                    aegisxd_json_add_string(body, "distribution_id", distribution_id);
                    download = aegisxd_certificate_download_json(body);
                    json_object_put(body);
                    assert(aegisxd_json_bool(download, "ok", 0));
                    assert(integer(download, "generation") == 1);
                    json_object_put(download);

                    body = request("{\"confirm\":true,\"expected_generation\":9}");
                    expect_error(aegisxd_certificate_rotate_json(body),
                                 "certificate_generation_conflict");
                    json_object_put(body);
                    setenv("AEGISXD_CERTIFICATE_FAIL_STAGE",
                           "after-db-commit-before-key-cleanup", 1);
                    body = request("{\"confirm\":true,\"expected_generation\":1,\"validity_days\":730}");
                    response = aegisxd_certificate_rotate_json(body);
                    json_object_put(body);
                    assert(aegisxd_json_bool(response, "ok", 0));
                    assert(integer(response, "generation") == 2);
                    key_mode(2);
                    snprintf(old_key, sizeof(old_key), "%s/inspection-ca-1.key.pem",
                             AEGISXD_PKI_DIR);
                    assert(access(old_key, F_OK) == 0);
                    assert(aegisxd_json_bool(response, "private_key_cleanup_pending", 0));
                    json_object_put(response);
                    unsetenv("AEGISXD_CERTIFICATE_FAIL_STAGE");
                    response = aegisxd_certificate_status_json();
                    assert(!aegisxd_json_bool(response, "private_key_cleanup_pending", 1));
                    assert(access(old_key, F_OK) != 0);
                    json_object_put(response);
                    expect_state(distribution_id, "superseded");
                    body = json_object_new_object();
                    aegisxd_json_add_string(body, "distribution_id", distribution_id);
                    expect_error(aegisxd_certificate_download_json(body),
                                 "certificate_distribution_superseded");
                    json_object_put(body);

                    body = request("{\"target_type\":\"client\",\"target_id\":\"aa:bb:cc:dd:ee:ff\",\"method\":\"manual\"}");
                    distribution = aegisxd_certificate_distribution_create_json(body);
                    json_object_put(body);
                    assert(aegisxd_json_bool(distribution, "ok", 0));
                    snprintf(second_distribution_id, sizeof(second_distribution_id), "%s",
                             aegisxd_json_str(distribution, "distribution_id", ""));
                    json_object_put(distribution);

                    setenv("AEGISXD_CERTIFICATE_FAIL_STAGE", "before-db-commit", 1);
                    body = request("{\"confirm\":true,\"expected_generation\":2}");
                    expect_error(aegisxd_certificate_revoke_json(body),
                                 "inspection_ca_revoke_failed");
                    json_object_put(body);
                    unsetenv("AEGISXD_CERTIFICATE_FAIL_STAGE");
                    response = aegisxd_certificate_status_json();
                    assert(aegisxd_json_bool(response, "active", 0));
                    json_object_put(response);
                    key_mode(2);
                    key_matches_certificate(2);
                    expect_state(second_distribution_id, "ready_for_download");
                    body = json_object_new_object();
                    aegisxd_json_add_string(body, "distribution_id", second_distribution_id);
                    download = aegisxd_certificate_download_json(body);
                    json_object_put(body);
                    assert(aegisxd_json_bool(download, "ok", 0));
                    json_object_put(download);

                    setenv("AEGISXD_CERTIFICATE_FAIL_STAGE",
                           "after-db-commit-before-key-cleanup", 1);
                    body = request("{\"confirm\":true,\"expected_generation\":2}");
                    response = aegisxd_certificate_revoke_json(body);
                    json_object_put(body);
                    assert(aegisxd_json_bool(response, "ok", 0));
                    assert(!strcmp(aegisxd_json_str(response, "state", ""), "revoked"));
                    assert(!aegisxd_json_bool(response, "active", 1));
                    assert(aegisxd_json_bool(response, "private_key_cleanup_pending", 0));
                    json_object_put(response);
                    key_mode(2);
                    expect_state(second_distribution_id, "ca_revoked");
                    body = json_object_new_object();
                    aegisxd_json_add_string(body, "distribution_id", second_distribution_id);
                    expect_error(aegisxd_certificate_download_json(body),
                                 "certificate_distribution_ca_revoked");
                    json_object_put(body);
                    unsetenv("AEGISXD_CERTIFICATE_FAIL_STAGE");
                    response = aegisxd_certificate_status_json();
                    assert(!aegisxd_json_bool(response, "private_key_cleanup_pending", 1));
                    json_object_put(response);
                    key_absent(2);
                    sqlite3_close(g_aegisxd_config_db);
                    return 0;
                }
                '''
            ),
            encoding="ascii",
        )
        command = [
            os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
            f"-I{include}", f"-I{AEGIS}", f'-DAEGISXD_PKI_DIR="{pki}"',
            f'-DAEGISXD_CLIENT_DB_PATH="{clients_db}"',
            "-DAEGISXD_CERTIFICATE_TEST_STANDALONE=1",
            str(source), "-o", str(binary), *_pkg_config("json-c", "sqlite3", "openssl"),
        ]
        subprocess.run(command, check=True)
        subprocess.run([str(binary)], check=True)
