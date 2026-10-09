"""Compile the real VLAN adapter and revision helper with isolated boundaries."""
from pathlib import Path
import shlex
import subprocess
import tempfile

from webd_sources import webd_function_text, webd_module_path

ROOT = Path(__file__).resolve().parents[1]


def test_vlan_revision_and_adapter():
    functions = "\n".join(webd_function_text("api_ports.c", name) for name in (
        "webd_port_vlan_error", "webd_port_vlan_request",
    ))
    flags = shlex.split(subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "json-c", "sqlite3", "openssl"], text=True))
    with tempfile.TemporaryDirectory(prefix="f17-vlan-fixture-") as tmp:
        path = Path(tmp)
        (path / "port_vlan_adapter.inc").write_text(functions)
        binary = path / "fixture"
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        f"-I{ROOT / 'src'}", f"-I{path}",
                        str(ROOT / "tests/port_vlan_fixture.c"),
                        "-o", str(binary), *flags], check=True)
        subprocess.run([str(binary)], check=True)


def test_port_revision_rechecked_under_write_lock_before_task_insert():
    module = "api_config_apply.c" if webd_module_path("api_config_apply.c").exists() else "jmx_app_api.c"
    body = webd_function_text(module, "jmx_config_apply")
    begin = body.index("revision_rc = safeops_revision_begin(")
    gate = body.index('if (port_vlan_runtime && app_nc_json_str(req, "expected_port_revision"')
    insert = body.index('"INSERT INTO config_apply_tasks')
    assert begin < gate < insert
    assert '"ROLLBACK"' in body[gate:insert]
    assert "safeops_port_revision(g_config_db, WEBD_NETWORK_CONFIG_PATH," in body[gate:insert]
    assert "safeops_port_revision(g_app_db," not in body[gate:insert]
    planner = webd_function_text("api_ports.c", "webd_topology_port_plan_response")
    for key in ("idempotency_key", "expected_base_digest", "expected_port_revision"):
        assert f'webd_json_copy_key(tx_params, "{key}", body, "{key}")' in planner


def test_vlan_snapshot_uses_separate_config_database():
    functions = "\n".join(webd_function_text("api_ports.c", name) for name in (
        "webd_port_vlan_error", "webd_port_vlan_snapshot",
    ))
    flags = shlex.split(subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "json-c", "sqlite3", "openssl"], text=True))
    with tempfile.TemporaryDirectory(prefix="f17-vlan-snapshot-") as tmp:
        path = Path(tmp)
        (path / "port_vlan_snapshot.inc").write_text(functions)
        binary = path / "fixture"
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        f"-I{ROOT / 'src'}", f"-I{path}",
                        str(ROOT / "tests/port_vlan_snapshot_fixture.c"),
                        "-o", str(binary), *flags], check=True)
        subprocess.run([str(binary)], check=True)
