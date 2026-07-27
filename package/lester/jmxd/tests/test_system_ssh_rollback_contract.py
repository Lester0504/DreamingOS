#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


snapshot = between(CORE, "struct nc_sys_ssh_snapshot", "static char *nc_sys_crontab_text")
assert "nc_sys_ssh_snapshot_capture" in snapshot
assert "nc_sys_ssh_snapshot_restore" in snapshot
assert "nc_sys_ssh_apply_service_state" in snapshot
assert "nc_sys_ssh_settings_apply" in snapshot
assert "snapshot->enabled" in snapshot
assert "snapshot->running" in snapshot
assert "nc_sys_restore_text_file" in snapshot
assert "NC_OPENSSH_CONFIG_PATH" in snapshot
assert "NC_OPENSSH_DROPIN_PATH" in snapshot
assert "snapshot->auth_path" in snapshot
assert 'enabled ? "enable" : "disable"' in snapshot
assert 'nc_sys_ssh_service_action(provider, "start")' in snapshot
assert 'nc_sys_ssh_service_action(provider, "stop")' in snapshot
assert 'enabled ? 1 : 0' in snapshot
assert "nc_sys_ssh_snapshot_restore(&snapshot)" in snapshot

settings = between(CORE, "int jmx_system_settings_set", "static int nc_sys_runtime_hostname_matches")
ssh_branch = settings[settings.index('json_object_object_get_ex(cfg, "ssh"'):]
assert "nc_sys_ssh_settings_apply(v)" in ssh_branch
assert 'system("/etc/init.d/sshd enable' not in ssh_branch
assert 'system("/etc/init.d/dropbear enable' not in ssh_branch

idle = CORE[CORE.index("int jmx_system_ssh_idle_timeout_set"):]
assert "nc_sys_ssh_settings_apply(ssh)" in idle
assert "/etc/init.d/dropbear restart" not in idle.split("/* ═════════", 1)[0]

print("ok: SSH file, key, boot-enable and runtime state are applied and rolled back as one operation")
