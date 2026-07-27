#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/webd/system_ttyd.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src/webd/system_ttyd.h").read_text(encoding="utf-8")
SRC_MAKEFILE = (ROOT / "src/Makefile").read_text(encoding="utf-8")


def require(text: str, *needles: str) -> None:
    for needle in needles:
        assert needle in text, f"missing contract marker: {needle}"


def test_public_module_is_independent_of_rest_routing() -> None:
    require(
        HEADER,
        "system_ttyd_get",
        "system_ttyd_validate",
        "system_ttyd_apply",
    )
    assert "/api/v1/system/ttyd" not in SOURCE
    assert 'json_object_new_string("/terminal/")' in SOURCE
    assert "system_ttyd_proxy_handle_authenticated" not in SOURCE
    assert "Sec-WebSocket" not in SOURCE
    assert "system_ttyd.o" in SRC_MAKEFILE


def test_uci_is_the_only_configuration_authority() -> None:
    require(
        SOURCE,
        '#define SYSTEM_TTYD_CONFIG_PATH "/etc/config/ttyd"',
        "uci_alloc_context",
        "uci_load",
        "uci_import",
        "uci_export",
        '"authority", json_object_new_string("uci:/etc/config/ttyd")',
    )
    assert "sqlite" not in SOURCE.lower()
    assert "config.db" not in SOURCE
    require(SOURCE, "section->anonymous", '"ttyd-%u"')


def test_credentials_are_write_only() -> None:
    require(
        SOURCE,
        '"credential_configured"',
        '"preserve_credential"',
        '"clear_credential"',
        '"ambiguous_empty_credential"',
    )
    emit_start = SOURCE.index("static struct json_object *ttyd_instance_json")
    emit_end = SOURCE.index("static int ttyd_wait_child", emit_start)
    emitter = SOURCE[emit_start:emit_end]
    assert '"credential"' not in emitter


def test_validation_is_strict_and_bounded() -> None:
    require(
        SOURCE,
        '"duplicate_instance"',
        '"random_port_unsupported"',
        '"port_in_use"',
        '"interface_not_found"',
        '"invalid_unix_socket"',
        '"unix_socket_in_use"',
        '"invalid_signal"',
        '"invalid_debug"',
        '"invalid_command"',
        '"invalid_tls_files"',
        '"duplicate_client_option"',
        '"invalid_url_override"',
        "TTYD_MAX_INSTANCES",
        "TTYD_MAX_CLIENT_OPTIONS",
        '"unix_sock_path", "_unix_sock_path"',
        '"running", "listen", "terminal_url"',
        '"ambiguous_unix_socket"',
        "ttyd_decimal(json_object_get_string(value), INT64_MAX",
    )


def test_apply_is_locked_revisioned_atomic_and_rollback_capable() -> None:
    apply_start = SOURCE.index("struct json_object *system_ttyd_apply")
    apply = SOURCE[apply_start:]
    require(
        apply,
        '"confirm_required"',
        "flock(lock_fd, LOCK_EX)",
        "ttyd_backup_write",
        "ttyd_atomic_write(SYSTEM_TTYD_CONFIG_PATH",
        "ttyd_service_apply",
        "ttyd_snapshot_restore",
        '"rollback_ok"',
        "ttyd_backups_prune",
        "ttyd_add_runtime_result",
    )
    assert "ttyd_parse_request(request, &current, &desired, 1" in apply
    assert '"revision_required"' in SOURCE
    assert "if (!rendered->len)" in SOURCE
    assert apply.index("flock(lock_fd, LOCK_EX)") < apply.index("ttyd_backup_write")
    assert apply.count("ttyd_parse_request(request, &current, &desired, 1") == 2
    assert apply.index("ttyd_backup_write") < apply.index(
        "ttyd_atomic_write(SYSTEM_TTYD_CONFIG_PATH"
    )
    write_index = apply.index("ttyd_atomic_write(SYSTEM_TTYD_CONFIG_PATH")
    assert apply.index("ttyd_service_apply", write_index) > write_index


def test_runtime_readback_uses_procd_and_socket_state() -> None:
    require(
        SOURCE,
        '"{\\"name\\":\\"ttyd\\"}"',
        '"service", (char *)"list"',
        '"-lntp"',
        '"-lxnp"',
        "ttyd_listen_matches",
        "ttyd_runtime_verified",
        '"ttyd_runtime_read_failed"',
        '"reload"',
        '"restart"',
    )
    apply_start = SOURCE.index("struct json_object *system_ttyd_apply")
    no_change_start = SOURCE.index("if (!changed)", apply_start)
    no_change_end = SOURCE.index("if (ttyd_file_read", no_change_start)
    no_change = SOURCE[no_change_start:no_change_end]
    assert "ttyd_service_apply(&readback" in no_change
    assert 'json_object_new_string("none")' not in no_change


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("system ttyd backend contract: ok")
