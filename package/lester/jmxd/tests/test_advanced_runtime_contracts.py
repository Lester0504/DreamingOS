#!/usr/bin/env python3
"""Static contracts for fail-closed advanced kernel/diagnostic capabilities."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")

assert "advanced_kernel_slim_mode_contract" in SOURCE
assert "module_dependency_graph_executor_missing" in SOURCE
assert "advanced_scheduler_priority_contract" in SOURCE
assert "sched_set_and_setpriority_executor_missing" in SOURCE
assert "advanced_collect_diagnostics_contract" in SOURCE
assert "diagnostics_collector_executor_missing" in SOURCE
assert "advanced_crash_dump_contract" in SOURCE
assert "crashkernel_not_configured" in SOURCE
assert "nc_sys_cmdline_has_crashkernel" in SOURCE
assert "nc_sys_file_is_one(\"/sys/kernel/kexec_crash_loaded\")" in SOURCE
assert "nc_sys_file_is_one(\"/sys/kernel/kexec_loaded\")" in SOURCE
assert '"storage_quota_ready"' in SOURCE
assert 'json_object_new_boolean(0));\n        json_object_object_add(contract, "crashkernel_configured"' in SOURCE
print("ok: advanced kernel, diagnostics, and crashdump capabilities fail closed")
