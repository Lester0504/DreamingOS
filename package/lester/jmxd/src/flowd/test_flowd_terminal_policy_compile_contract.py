#!/usr/bin/env python3
"""Flowd terminal policy compile projection contract.

Union terminal policies surface in flowd's ubus compile projection without
claiming data-plane application until the tc/nft/quota executor exists.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "src/flowd/flowd_terminal_policy.c").read_text(encoding="utf-8")
U = (ROOT / "src/flowd/flowd_ubus.c").read_text(encoding="utf-8")
MK = (ROOT / "src/Makefile").read_text(encoding="utf-8")
H = (ROOT / "src/flowd/flowd_internal.h").read_text(encoding="utf-8")

assert 'flowd/flowd_terminal_policy.o' in MK
assert 'UBUS_METHOD("terminal_policy_compile"' in U
assert 'UBUS_METHOD("terminal_policy_apply"' in U
assert 'UBUS_METHOD("terminal_policy_runtime"' in U
assert 'flowd_handle_terminal_policy_compile' in U
assert 'flowd_handle_terminal_policy_apply' in U
assert 'flowd_handle_terminal_policy_runtime' in U
assert 'flowd_terminal_policy_compile(void);' in H
assert 'flowd_terminal_policy_apply(const struct flowd_settings *settings);' in H
assert 'flowd_terminal_policy_runtime(void);' in H
assert 'FLOWD_TERMINAL_POLICY_DB_PATH' in SRC
assert 'terminal_policy_db_unavailable' in SRC
assert '"runtime_kind", json_object_new_string("terminal_policy")' in SRC
assert 'dataplane_executor_pending' in SRC
assert 'mutates_dataplane", json_object_new_boolean(0)' in SRC
assert 'flowd_tp_render_nft' in SRC
assert 'flowd_terminal_policy_apply' in SRC
assert 'flowd_terminal_policy_runtime' in SRC


# Quota accounting runtime is compiled/linked into flowd.
assert 'flowd_terminal_quota_runtime_start' in (ROOT / "src/flowd/flowd_main.c").read_text(encoding="utf-8")
assert 'flowd_terminal_quota_runtime_start' in H
assert 'flowd_terminal_quota_runtime_stop' in H
assert 'flowd_terminal_quota_runtime.o' in MK
assert 'flowd_terminal_policy_tc.o' in MK
assert 'flowd_terminal_policy_tc_apply' in SRC
assert 'flowd_terminal_policy_tc_runtime' in SRC
assert 'flowd_terminal_policy_tc_executor_available' in H
assert 'flowd_terminal_policy_tc.c' in (ROOT / "src/flowd/flowd_terminal_policy_tc.c").read_text(encoding="utf-8")

assert 'flowd_tp_quota_account_line' in (ROOT / "src/flowd/flowd_terminal_quota_runtime.c").read_text(encoding="utf-8")
assert 'flowd_tp_prefix_match' in (ROOT / "src/flowd/flowd_terminal_quota_runtime.c").read_text(encoding="utf-8")
assert 'flowd_terminal_policy_apply(&g_tp_quota.settings)' in (ROOT / "src/flowd/flowd_terminal_quota_runtime.c").read_text(encoding="utf-8")
assert 'flowd_settings_load(&g_tp_quota.settings)' in (ROOT / "src/flowd/flowd_terminal_quota_runtime.c").read_text(encoding="utf-8")

print('ok: flowd exposes terminal policy compile projection and nft executor surface')
