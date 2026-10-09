#!/usr/bin/env python3
"""Terminal policy unified storage/WebD boundary contract.

This is the storage/API boundary phase of the unified IP terminal policy
handoff. It is deliberately not a data-plane claim: capabilities now tell the
frontend the truth (storage_only, runtime_readback=false) until tc/nft/quota
executors are implemented.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
CT = (ROOT / "src/terminal_policy/terminal_policy.c").read_text(encoding="utf-8")
HDR = (ROOT / "src/terminal_policy/terminal_policy.h").read_text(encoding="utf-8")

# The WebD boundary must route to the policy library, not keep a second shadow
# schema in webd itself.
assert '#include "../terminal_policy/terminal_policy.h"' in WEB
assert 'return tp_db_init();' in WEB
assert 'tp_db_close();' in WEB
assert 'CREATE TABLE IF NOT EXISTS terminal_policies' not in WEB or 'tp_db' in WEB
assert 'tp_policy_create' in WEB
assert 'tp_policy_update' in WEB
assert 'tp_policy_list' in WEB
assert 'tp_policy_get' in WEB
assert 'tp_policy_delete' in WEB
assert 'tp_policy_reset_usage' in WEB
HDR = (ROOT / "src/terminal_policy/terminal_policy.h").read_text(encoding="utf-8")
assert 'tp_policy_account_usage(const char *id, int64_t delta_bytes, int64_t *used_out);' in HDR
CT_ALT = (ROOT / "src/terminal_policy/terminal_policy.c").read_text(encoding="utf-8")
assert 'INSERT INTO quota_usage(policy_id,used_bytes,checkpoint_at)' in CT_ALT
assert 'ON CONFLICT(policy_id) DO UPDATE SET used_bytes' in CT_ALT

# No dead shadow write paths or old shadow-table SQL remain in webd.
assert 'webd_terminal_policy_delete(const char *id' not in WEB
assert 'DELETE FROM terminal_policies' not in WEB
assert 'INSERT INTO terminal_policies' not in WEB
assert 'rule_json' not in WEB

# webd exposes flowd terminal-policy apply/readback passthrough routes and
# keeps the permission surface explicit.
assert '"/api/v1/network-control/terminal-policies/apply"' in WEB
assert '"/api/v1/network-control/terminal-policies/runtime"' in WEB
assert 'webd_terminal_policy_flowd' in WEB
assert 'webd_terminal_policy_runtime_overlay' in WEB
assert 'terminal_policy_apply' in WEB
assert 'terminal_policy_runtime' in WEB
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")
assert '"/api/v1/network-control/terminal-policies/apply", "POST", JMX_RISK_MEDIUM' in PERMS
assert '"/api/v1/network-control/terminal-policies/runtime", "GET", JMX_RISK_LOW' in PERMS

assert 'json_object_object_add(data, "runtime", runtime)' in WEB

# The library is the single storage implementation.
assert 'CREATE TABLE IF NOT EXISTS policies' in CT
assert 'CREATE TABLE IF NOT EXISTS targets' in CT
assert 'CREATE TABLE IF NOT EXISTS quota_usage' in CT
assert 'tp_compute_deadline' in CT
assert 'upload_plus_download' in CT

# flowd quota accounting is wired into runtime and must be advertised by the
# authorized union boundary; data-plane apply/readback remain pending.
assert 'runtime_quota_accounting' in CT
assert 'unsupported_rate_mode' in CT
assert 'unsupported_quota_mode' in CT
assert "quota_mode TEXT NOT NULL DEFAULT 'per_ip'" in CT
assert 'only per_ip rate_mode is supported' in CT
assert 'only per_ip quota_mode is supported' in CT
assert 'json_object_new_boolean(1)' in CT
assert 'TP_STATUS_BLOCKED_QUOTA' in CT
assert 'UPDATE policies SET status=?' in CT
# flowd wiring is checked below via flowd_main/internal/Makefile; the
# 'runtime_quota_accounting' capability originates in the policy lib.
assert 'runtime_quota_accounting' in CT
assert 'unsupported_rate_mode' in CT
assert 'unsupported_quota_mode' in CT
assert "quota_mode TEXT NOT NULL DEFAULT 'per_ip'" in CT
assert 'flowd_terminal_quota_runtime_start() != 0' in (ROOT / "src/flowd/flowd_main.c").read_text(encoding="utf-8")
assert 'flowd_terminal_quota_runtime_stop();' in (ROOT / "src/flowd/flowd_main.c").read_text(encoding="utf-8")
assert 'int flowd_terminal_quota_runtime_start(void);' in (ROOT / "src/flowd/flowd_internal.h").read_text(encoding="utf-8")
assert 'void flowd_terminal_quota_runtime_stop(void);' in (ROOT / "src/flowd/flowd_internal.h").read_text(encoding="utf-8")
assert 'flowd/flowd_terminal_quota_runtime.o' in (ROOT / "src/Makefile").read_text(encoding="utf-8")

# Capabilities must not claim data-plane work the storage phase cannot do.
assert 'runtime_readback' in CT
assert 'runtime_apply_supported' in CT
assert 'dataplane' in CT
assert 'storage_only' in CT

# Lifecycle is opened/closed around fork boundaries so a SQLite handle is not
# inherited across a child request handler or an AI worker.
child_zone = WEB[WEB.index('static void app_api_dispatch_ready'):WEB.index('static void webd_ai_local_worker_prepare')]
assert 'webd_terminal_policy_close();' in child_zone
assert 'webd_terminal_policy_open();' in child_zone
ai_zone = WEB[WEB.index('static void webd_ai_local_worker_prepare'):WEB.index('int jmx_app_api_init')]
assert 'webd_terminal_policy_close();' in ai_zone
assert 'webd_terminal_policy_open();' in ai_zone

print('ok: terminal policy storage/WebD boundary is unified and capabilities stay honest')
