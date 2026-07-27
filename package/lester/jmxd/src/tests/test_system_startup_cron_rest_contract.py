#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYSTEM = (ROOT / "jmx_system.c").read_text(encoding="utf-8")
NETCONFIG = (ROOT / "jmx_netconfig_db.c").read_text(encoding="utf-8")
UBUS = (ROOT / "jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
WEBD = (ROOT / "webd" / "jmx_app_api.c").read_text(encoding="utf-8")
PACKAGE = (ROOT.parent / "Makefile").read_text(encoding="utf-8")

assert "jmx_system_crontab_validate_text" in SYSTEM
assert "cron_special_times_unsupported" in SYSTEM
assert "unsupported_cron_environment" in SYSTEM
assert "jmx_system_text_apply" in NETCONFIG
assert 'opts.mode = 0600;' in NETCONFIG
assert 'opts.mode = 0755;' in NETCONFIG
assert 'opts.reload_bin = "/etc/init.d/cron";' in NETCONFIG
assert 'json_object_object_add(resp, "data", data);' in UBUS
assert '"/api/v1/system/crontab/apply"' in WEBD
assert '"/api/v1/system/startup/rc-local"' in WEBD
assert "fields < 6" not in WEBD
assert "sqlite_only_no_cron_reload" not in WEBD
assert '"special_times_supported"' in NETCONFIG
assert "select BUSYBOX_CONFIG_FEATURE_CROND_SPECIAL_TIMES" in PACKAGE

print("system_startup_cron_rest_contract: PASS")
