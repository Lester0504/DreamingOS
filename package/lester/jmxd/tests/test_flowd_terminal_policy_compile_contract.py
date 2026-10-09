#!/usr/bin/env python3
"""Flowd terminal policy compile/readback contract."""
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
assert 'flowd_terminal_policy_lifecycle_scan' in H
assert 'flowd_terminal_policy_lifecycle_scan' in SRC
assert 'SELECT 1 FROM quota_blocks WHERE policy_id=? LIMIT 1' in SRC
assert 'per_ip_blocked' in SRC
assert 'FLOWD_TERMINAL_POLICY_DB_PATH' in SRC
assert 'terminal_policy_db_unavailable' in SRC
assert '"runtime_kind", json_object_new_string("terminal_policy")' in SRC
assert 'runtime_applied' in SRC
assert 'terminal_policy_executor_unavailable' in SRC
assert 'mutates_dataplane", json_object_new_boolean(executor_available)' in SRC
assert 'flowd_tp_render_nft' in SRC
assert 'flowd_terminal_policy_apply' in SRC
assert 'flowd_terminal_policy_runtime' in SRC
assert 'FLOWD_TP_NFT_HOOK_PRIORITY (-150)' in SRC
assert 'priority %d; policy accept' in SRC
assert '"rollback_noop", json_object_new_boolean(1)' in SRC
assert 'terminal_policy_isolated_validation_failed' in SRC


# Quota accounting runtime is compiled/linked into flowd.
assert 'flowd_terminal_quota_runtime_start' in (ROOT / "src/flowd/flowd_main.c").read_text(encoding="utf-8")
assert 'flowd_terminal_quota_runtime_start' in H
assert 'flowd_terminal_quota_runtime_stop' in H
assert 'flowd_terminal_quota_runtime.o' in MK
assert 'flowd_terminal_policy_tc.o' in MK
assert 'flowd_terminal_policy_tc_apply' in SRC
assert 'flowd_terminal_policy_tc_runtime' in SRC
assert 'flowd_terminal_policy_tc_executor_available' in H
assert 'flowd_terminal_policy_tc_apply' in (ROOT / "src/flowd/flowd_terminal_policy_tc.c").read_text(encoding="utf-8")
TC = (ROOT / "src/flowd/flowd_terminal_policy_tc.c").read_text(encoding="utf-8")
assert 'legacy row' in TC
assert 'plen != 32' in TC
assert 'plen != 128' in TC

assert 'flowd_tp_quota_account_line' in (ROOT / "src/flowd/flowd_terminal_quota_runtime.c").read_text(encoding="utf-8")
assert 'flowd_tp_prefix_match' in (ROOT / "src/flowd/flowd_terminal_quota_runtime.c").read_text(encoding="utf-8")
assert 'flowd_terminal_policy_apply(&g_tp_quota.settings)' in (ROOT / "src/flowd/flowd_terminal_quota_runtime.c").read_text(encoding="utf-8")
assert 'flowd_settings_load(&g_tp_quota.settings)' in (ROOT / "src/flowd/flowd_terminal_quota_runtime.c").read_text(encoding="utf-8")
assert 'flowd_tp_quota_lookup' in (ROOT / "src/flowd/flowd_terminal_quota_runtime.c").read_text(encoding="utf-8")
Q = (ROOT / "src/flowd/flowd_terminal_quota_runtime.c").read_text(encoding="utf-8")
assert '#define FLOWD_TP_MAX_TARGETS_PER_ACCOUNT 4096' in Q
assert 'struct flowd_tp_quota_target *targets;' in Q
assert 'flowd_tp_quota_release_accounts' in Q
assert 'terminal_policy_quota_target_limit' in Q
assert 'terminal_policy_quota_target_oom' in Q
assert 'Publish only a complete, validated snapshot' in Q
assert 'targets_loaded' in Q
assert 'max_targets_per_account' in Q
assert 'a->target_count >= 64' not in Q
assert 'nfct_open(CONNTRACK' in Q
assert 'uloop_fd_add(&g_tp_quota.conntrack_fd' in Q
assert 'g_tp_quota.conntrack_resync_needed = 1' in Q
assert 'for (;;) {' in Q
assert 'recvmsg(fd->fd, &msg, MSG_DONTWAIT)' in Q
assert 'Drop them and let subsequent UPDATE/NEW events' in Q
assert 'tp_policy_account_usage_for_client' in Q
assert 'tp_policy_account_usage(slot->policy_id' in Q
assert 'slot->family == 0' in Q
assert 'quota_mode[16]' in Q
assert 'SELECT id,enabled,quota_bytes,quota_mode,status' in Q
assert 'TP_QUOTA_SHARED' in Q
assert 'fopen(FLOWD_TP_CONNTRACK_PROC' not in Q
assert 'quota_usage_ip' in (ROOT / "src/terminal_policy/terminal_policy.c").read_text(encoding="utf-8")
assert 'bytes_sent' in (ROOT / "src/flowd/flowd_export_runtime.h").read_text(encoding="utf-8")
assert 'bytes_received' in (ROOT / "src/flowd/flowd_export_runtime.h").read_text(encoding="utf-8")
assert 'out->bytes_sent = bytes_sent' in (ROOT / "src/flowd/flowd_export_collect.c").read_text(encoding="utf-8")
assert 'out->bytes_received = bytes_received' in (ROOT / "src/flowd/flowd_export_collect.c").read_text(encoding="utf-8")

print('ok: flowd exposes terminal policy compile projection and nft executor surface')

assert "destroy table inet" in SRC
assert "argv[4] = \"inet\"" in SRC
assert "nft_readback_required" in SRC
assert "br-lan" in SRC
