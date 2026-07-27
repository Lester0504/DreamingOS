#!/usr/bin/env python3
"""Static production contract for storage overview and file services."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def read(path: Path) -> str:
    assert path.is_file(), f"missing production source: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


UBUS = read(SRC / "jmx_dreamingwrt_api.c")
WEB = read(SRC / "webd/jmx_app_api.c")
PERMS = read(SRC / "webd/jmx_app_perms.c")
MAKE = read(SRC / "Makefile")


def require_all(text: str, needles: tuple[str, ...], scope: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    assert not missing, f"{scope} missing: {missing}"


def function_body(text: str, name: str, next_name: str) -> str:
    marker = f"struct json_object *{name}("
    end_marker = f"struct json_object *{next_name}("
    assert marker in text, f"missing function: {name}"
    body = text.split(marker, 1)[1]
    assert end_marker in body, f"missing function after {name}: {next_name}"
    return body.split(end_marker, 1)[0]


def test_overview_contract_and_route() -> None:
    overview = read(SRC / "storage/storage_overview.c")
    require_all(overview, (
        "jmx_storage_overview_get", '"storage-overview.v1"', '"summary"',
        '"disks"', '"history"', '"smart"', '"capabilities"',
        '"read_bps"', '"write_bps"', '"read_latency_ms"',
        '"write_latency_ms"', "/proc/diskstats", "/sys/block",
    ), "storage overview")
    require_all(UBUS, ('"storage_overview"', "jmx_storage_overview_get"), "overview ubus")
    require_all(WEB, ('"/api/v1/storage/overview"', '"storage_overview"'), "overview REST")
    assert '"/api/v1/storage/overview"' in PERMS


def test_smart_is_bounded_and_not_shell_concatenated() -> None:
    overview = read(SRC / "storage/storage_overview.c")
    require_all(overview, ("fork(", "exec", "poll(", "SIGKILL", "timed_out",
                           "output_truncated"), "bounded SMART executor")
    assert 'popen("smartctl' not in overview
    assert 'system("smartctl' not in overview


def test_file_service_authority_and_capability_boundaries() -> None:
    services = read(SRC / "storage/file_services.c")
    require_all(services, (
        "/etc/dreamingwrt/config.db", "file_service_meta", "samba_service",
        "samba_share", "nfs_export", '"file-services.v2"',
        '"capabilities"', '"capability_reasons"',
        '"shares"', '"exports"', '"mounts"', '"has_password"',
        '"conditional_write", json_object_new_boolean(1)',
        '"expected_revision_required", json_object_new_boolean(1)',
        '"config_preflight", json_object_new_boolean(1)',
        '"runtime_probe", json_object_new_boolean(1)',
        '"secret_encryption_apply_pending"', '"runtime_not_installed"',
    ), "file-service authority")
    assert 'json_object_object_add' in services
    require_all(services, ("CREATE TABLE IF NOT EXISTS file_service_meta",
                           "CREATE TABLE IF NOT EXISTS samba_service",
                           "CREATE TABLE IF NOT EXISTS samba_share",
                           "CREATE TABLE IF NOT EXISTS nfs_export"),
                "file-service idempotent post-restore migration")
    assert '"password"' not in services.split("jmx_file_service_get", 1)[-1].split("jmx_samba_share_upsert", 1)[0], (
        "file-service GET must not serialize a password field"
    )


def test_one_time_uci_migration_commits_successfully() -> None:
    services = read(SRC / "storage/file_services.c")
    require_all(services, (
        'if (fs_sql_exec(db, "COMMIT") != 0)', "return 0;", "uci_migrated=1",
        "samba_preexisting", "nfs_preexisting",
    ), "one-time UCI migration")
    migration = services.split("static int fs_migrate_once(", 1)[1].split(
        "static int fs_db_open(", 1
    )[0]
    assert re.search(
        r'if \(fs_sql_exec\(db, "COMMIT"\) != 0\)\s*goto rollback;\s*return 0;',
        migration,
    ), (
        "successful migration must return success after commit"
    )


def test_file_service_writes_are_confirmed_validated_and_rollbackable() -> None:
    services = read(SRC / "storage/file_services.c")
    require_all(services, (
        '"confirm"', '"confirmation_required"', "BEGIN IMMEDIATE", "ROLLBACK",
        "COMMIT", "fsync", "rename(", "realpath(", "O_NOFOLLOW",
        '"invalid_path"', '"invalid_options"', "SIGKILL", "CLOCK_MONOTONIC",
        'strstr(output, "Available commands:")',
    ), "file-service safe apply")
    assert "system(" not in services, "file service module must not call a shell"
    assert "popen(" not in services, "file service module must not call a shell"


def test_file_service_resource_writes_use_optimistic_revisions() -> None:
    services = read(SRC / "storage/file_services.c")
    require_all(services, (
        "fs_json_positive_int64", '"expected_revision"',
        '"missing_expected_revision"', '"invalid_expected_revision"',
        '"revision_conflict"', '"expected_revision"',
        '"revision"', "json_object_new_int64(current_revision)",
        '"changed", json_object_new_boolean(0)',
        '"persisted", json_object_new_boolean(0)',
        '"applied", json_object_new_boolean(0)',
    ), "file-service revision errors")

    samba_upsert = function_body(
        services, "jmx_samba_share_upsert", "jmx_samba_share_delete"
    )
    samba_delete = function_body(
        services, "jmx_samba_share_delete", "jmx_nfs_export_upsert"
    )
    nfs_upsert = function_body(
        services, "jmx_nfs_export_upsert", "jmx_nfs_export_delete"
    )
    nfs_delete = services.split("struct json_object *jmx_nfs_export_delete(", 1)[1]

    for scope, body, create_sql, update_sql in (
        (
            "Samba share upsert", samba_upsert,
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,?11,?11)",
            "WHERE id=?1 AND revision=?12",
        ),
        (
            "NFS export upsert", nfs_upsert,
            "VALUES(?1,?2,?3,?4,?5,?6,1,?7,?7)",
            "WHERE id=?1 AND revision=?8",
        ),
    ):
        require_all(body, (
            'fs_json_positive_int64(payload, "expected_revision"',
            'fs_sql_exec(db, "BEGIN IMMEDIATE")', create_sql, update_sql,
            "sqlite3_changes(db)", "fs_revision_conflict(",
            '"revision", json_object_new_int64(new_revision)',
            '"meta_revision", json_object_new_int64(meta_revision)',
        ), scope)
        assert body.index('fs_sql_exec(db, "BEGIN IMMEDIATE")') < body.index(update_sql)
        assert body.index("fs_revision_conflict(") < body.index("fs_apply_new_config(")

    for scope, body, delete_sql in (
        ("Samba share delete", samba_delete,
         "DELETE FROM samba_share WHERE id=?1 AND revision=?2"),
        ("NFS export delete", nfs_delete,
         "DELETE FROM nfs_export WHERE id=?1 AND revision=?2"),
    ):
        require_all(body, (
            'fs_json_positive_int64(payload, "expected_revision"',
            'fs_sql_exec(db, "BEGIN IMMEDIATE")', delete_sql,
            "sqlite3_changes(db)", "fs_revision_conflict(",
            '"deleted_revision"', "json_object_new_int64(expected_revision)",
            '"meta_revision", json_object_new_int64(meta_revision)',
        ), scope)
        assert body.index('fs_sql_exec(db, "BEGIN IMMEDIATE")') < body.index(delete_sql)
        assert body.index("fs_revision_conflict(") < body.index("fs_apply_new_config(")


def test_file_service_revision_http_status_mapping() -> None:
    require_all(WEB, (
        '!strcmp(code_s, "revision_conflict")',
        '!strcmp(code_s, "missing_expected_revision")',
        '!strcmp(code_s, "invalid_expected_revision")',
        "return 409;", "return 422;",
    ), "file-service revision HTTP status")


def test_runtime_status_does_not_accept_init_usage_or_global_nginx() -> None:
    services = read(SRC / "storage/file_services.c")
    require_all(services, (
        'strstr(output, "Syntax:")', 'strstr(output, "Usage:")',
        'access("/etc/nginx/conf.d/webdav.conf", R_OK)',
        "strcmp(script, JMX_NFS_INIT_PATH)",
        'JMX_NFS_EXPORTFS_PATH "/usr/sbin/exportfs"',
        '(char *)"-ua"', '(char *)"-ra"', '"restart+exportfs"',
    ), "file-service runtime status")


def test_generated_config_is_preflighted_and_runtime_is_probed() -> None:
    services = read(SRC / "storage/file_services.c")
    require_all(services, (
        "#include <uci.h>", "fs_config_preflight", "mkdtemp(",
        "uci_alloc_context", "uci_set_confdir", "uci_load(",
        '"config_preflight_failed"', '"runtime_probe_failed"',
        'JMX_SAMBA_TESTPARM_PATH "/usr/bin/testparm"',
        'JMX_SAMBA_NATIVE_CONFIG_PATH "/var/etc/smb.conf"',
        'JMX_NFSD_THREADS_PATH "/proc/fs/nfsd/threads"',
        'JMX_NFS_NATIVE_CONFIG_PATH "/etc/exports"',
        'fs_service_action(JMX_SAMBA_INIT_PATH, "status"',
        '"--section-name=%s"', '"path = %s"',
        '(char *)"-v"', "fs_export_output_scan", "fs_nfsd_threads_positive",
        "fs_render_nfs_exports", "fs_nfs_exports_apply",
        "fs_export_options_include", "actual_entries != expected_entries",
        'strtok_r(client_copy, " ,\\t"',
    ), "file-service preflight and runtime probes")
    apply = services.split("static int fs_apply_new_config(", 1)[1].split(
        "static int fs_restore_old_file(", 1
    )[0]
    assert apply.index("fs_config_preflight(") < apply.index("fs_atomic_replace(")
    assert apply.index("fs_service_reload_or_restart(") < apply.index(
        "fs_runtime_probe("
    )
    rollback = services.split("static struct json_object *fs_apply_failure_rollback(", 1)[1].split(
        "static int fs_samba_load(", 1
    )[0]
    assert "fs_runtime_probe(db, service, &restore_result)" in rollback
    assert "system(" not in services
    assert "popen(" not in services


def test_routes_rbac_csrf_and_audit() -> None:
    require_all(UBUS, (
        '"file_services_get"', '"file_service_get"',
        '"samba_share_upsert"', '"samba_share_delete"',
        '"nfs_export_upsert"', '"nfs_export_delete"',
    ), "file-service ubus")
    require_all(WEB, (
        '"/api/v1/storage/file-services"', '"/api/v1/services/samba"',
        '"/api/v1/services/nfs"', '"/api/v1/services/webdav"',
        '"/api/v1/services/ftp"', "jmx_app_audit_log",
        '"samba.share.upsert"', '"samba.share.delete"',
        '"nfs.export.upsert"', '"nfs.export.delete"',
    ), "file-service REST and audit")
    require_all(PERMS, (
        '"/api/v1/storage/file-services"', '"/api/v1/services/samba"',
        '"/api/v1/services/nfs"', "JMX_RISK_MEDIUM",
    ), "file-service RBAC")
    require_all(WEB, ('!strncmp(req.path, "/api/v1/services/", 17)',
                      "webd_cookie_write_csrf_ok"), "file-service CSRF")


def test_modules_are_linked_into_core() -> None:
    require_all(MAKE, ("storage/storage_overview.o", "storage/file_services.o"),
                "core object list")


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    failures = []
    for test in tests:
        try:
            test()
        except AssertionError as exc:
            failures.append(f"{test.__name__}: {exc}")
    if failures:
        raise SystemExit("storage backend contract failures:\n- " + "\n- ".join(failures))
    print("ok: storage overview and file-service authority, safety, REST, RBAC, and audit contracts")
