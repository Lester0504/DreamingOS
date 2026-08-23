#!/usr/bin/env python3
"""Hot-update apply is gated on a verified release signature, not disabled.

This file used to assert that hot apply could never run: the writer was
compiled out and the assertions pinned it there. The writer is enabled now, so
the contract asserted here changed shape - not "always refuse" but "refuse
unless a signature verifies". The signature check itself is exercised for real,
including the invalid-signature direction, in
test_otad_hot_release_signature_runtime.py; asserting source text alone cannot
tell a working verifier from one that returns success.
"""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = (ROOT / "src/otad/otad_manifest.c").read_text(encoding="utf-8")
HOT = (ROOT / "src/otad/otad_hot.c").read_text(encoding="utf-8")
TRUST = (ROOT / "src/otad/otad_trust.c").read_text(encoding="utf-8")
INTERNAL = (ROOT / "src/otad/otad_internal.h").read_text(encoding="utf-8")
STATUS = (ROOT / "src/otad/otad_status.c").read_text(encoding="utf-8")
UBUS = (ROOT / "src/otad/otad_ubus.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


# otad_check_manifest stays a structure check that never claims a signature was
# verified. It parses an untrusted manifest, so it must not be mistaken for the
# trust decision.
manifest = between(
    MANIFEST,
    "struct json_object *otad_check_manifest(",
    "\n}",
) + "\n}"
assert '"ok", json_object_new_boolean(0)' in manifest
assert '"validated", json_object_new_boolean(err_count == 0)' in manifest
assert '"integrity_verified", json_object_new_boolean(0)' in manifest
assert '"signature_required", json_object_new_boolean(1)' in manifest
assert '"signature_verified", json_object_new_boolean(0)' in manifest
assert '"safe_to_apply_now", json_object_new_boolean(0)' in manifest
assert '"hot_update_release_trust_gate_closed"' in manifest

# Preflight is shared by verify and apply so the two cannot drift: base-version
# and payload integrity are checked identically on both paths.
preflight = between(
    HOT,
    "static int hot_preflight(",
    "static struct json_object *hot_verify_internal(",
)
assert 'otad_json_bool(validation, "validated", 0)' in preflight
assert 'hot_payloads_verify(' in preflight
assert 'hot_targets_verify_base(' in preflight
assert 'hot_deletions_verify_base(' in preflight
assert 'hot_space_gates_check(files, count, gates, 0)' in preflight
assert 'otad_space_gate_record(' not in preflight
assert 'hot_release_trust_error(' in preflight
header_failure = between(
    preflight,
    "if (hot_header_read(",
    "validation = otad_check_manifest(",
)
assert "hot_release_trust_error(" in header_failure
assert '"diagnostic_error"' in header_failure

# Verify reports what it found instead of a fixed refusal, and only claims
# verified when the signature check returned success.
verify = between(
    HOT,
    "static struct json_object *hot_verify_internal(",
    "static int hot_parent_prepare(",
)
assert "hot_preflight(" in verify
assert "otad_hot_release_trust_verify(info.manifest" in verify
assert verify.index("hot_preflight(") < verify.index("otad_hot_release_trust_verify(")
assert '"verified", json_object_new_boolean(1)' in verify
assert verify.index("if (!trusted)") < verify.index(
    '"verified", json_object_new_boolean(1)')
assert 'hot_release_trust_error(' in verify
assert '"release_trust", evidence' in verify

gate_fields = between(
    HOT,
    "static void hot_release_trust_fields(",
    "static struct json_object *hot_release_trust_error(",
)
for field in (
    '"verified"',
    '"integrity_verified"',
    '"authenticity_verified"',
    '"signature_required"',
    '"signature_verified"',
    '"target_compatible"',
    '"policy_passed"',
    '"safe_to_apply_now"',
    '"release_gate_reason"',
):
    assert field in gate_fields, f"hot-update trust gate must expose {field}"
# The refusal reason is now the specific failed precondition. A fixed reason
# sent operators to provision keys even when the keys were fine.
assert "reason && reason[0] ? reason" in gate_fields
for closed in (
    '"verified", json_object_new_boolean(0)',
    '"authenticity_verified", json_object_new_boolean(0)',
    '"signature_verified", json_object_new_boolean(0)',
    '"safe_to_apply_now", json_object_new_boolean(0)',
):
    assert closed in gate_fields, f"a closed gate must report {closed}"

# Apply: integrity, then authenticity, then the writer. The signature check must
# come before anything touches the filesystem.
apply = between(
    HOT,
    "static struct json_object *hot_apply_internal(",
    "struct json_object *otad_update_apply(",
)
assert "hot_preflight(" in apply
assert "otad_hot_release_trust_verify(info.manifest" in apply
assert "hot_stage_and_install(" in apply
assert apply.index("hot_preflight(") < apply.index("otad_hot_release_trust_verify(")
assert apply.index("otad_hot_release_trust_verify(") < apply.index(
    "hot_stage_and_install("
), "apply must verify the release signature before staging any file"
assert apply.index("otad_hot_release_trust_verify(") < apply.index(
    "hot_schedule_restarts("
), "apply must verify the release signature before restarting anything"
# The trust failure branch returns; it must not fall through to the writer.
trust_failure = between(apply, "if (otad_hot_release_trust_verify(", "memset(&failed_gate")
assert "return resp;" in trust_failure
assert "hot_stage_and_install(" not in trust_failure

# The magic dispatch keeps its shape: one entry point, package type decided by
# the header, so callers do not have to know which kind they hold. It now has two
# ways in - a whitelisted device path for direct ubus callers, and a verified
# operation_id for the web chain, which never sends a path at all.
dispatch = between(
    HOT,
    "struct json_object *otad_update_apply(",
    "\n    return otad_firmware_apply(body);",
) + "\n    return otad_firmware_apply(body);\n}"
assert dispatch.index("update_magic_is_hot(path)") < dispatch.index(
    "hot_apply_internal(&src)"
)
assert "otad_firmware_apply(body)" in dispatch
# The path branch must survive: a direct ubus caller staging a package in the
# whitelist still works, and that is the only way a path is ever accepted.
assert "hot_package_path_allowed" in HOT
for whitelisted in ('"/tmp/dreamingwrt/ota/"', '"/data/dreamingwrt/ota/"',
                    '"/opt/dreamingwrt/ota/"'):
    assert whitelisted in HOT, f"the hot package whitelist must still contain {whitelisted}"
# The whitelist must not have grown a staging entry to make the web path work.
assert "upload-staging" not in between(
    HOT, "static int hot_package_path_allowed(", "\n}"
), "the web path must go through upload_id, not a widened path whitelist"

# The web chain: verify records a ledger entry keyed to the upload, apply resolves
# it back and re-checks the bytes before writing.
web_verify = between(
    HOT,
    "static struct json_object *hot_verify_upload(",
    "struct json_object *otad_update_verify(",
)
assert 'otad_operation_create("hot_update", "preflight", upload_id' in web_verify
assert "otad_operation_commit_hot_preflight(" in web_verify
assert "otad_release_trust_binding_get(" in web_verify
assert web_verify.index("hot_verify_internal(") < web_verify.index(
    "otad_operation_create("
), "an operation may only be recorded for a package that verified"

web_apply = between(
    HOT,
    "static struct json_object *hot_apply_operation(",
    "struct json_object *otad_update_apply(",
)
assert "otad_operation_claim_hot_apply(" in web_apply
assert "otad_staged_upload_open(work->upload_id" in web_apply
assert "hot_update_source_binding_mismatch" in web_apply
assert web_apply.index("hot_update_source_binding_mismatch") < web_apply.index(
    "resp = hot_apply_internal(&src);"
), "the staged bytes must be rebound to the preflight before the writer runs"

# The writer must be compiled in, not stubbed out again.
installer = between(HOT, "static int hot_stage_and_install(", "static int hot_run_restart(")
assert "#if 0" not in installer, "the hot-update writer must not be compiled out"
assert "hot_update_release_trust_gate_closed" not in installer
for step in ("hot_copy_payload(", "hot_hash_path(", "rename(", "hot_rollback(",
             "hot_deletions_rollback(", "hot_update_writeback_integrity_mismatch"):
    assert step in installer, f"the writer must still {step}"

restarts = between(HOT, "static int hot_schedule_restarts(", "static int update_magic_is_hot(")
assert "#if 0" not in restarts, "restart orchestration must not be compiled out"
assert "otad_component_name_ok(service)" in restarts
assert "uloop_timeout_set(&g_hot_restart_timer, 500)" in restarts

# The hot statement type must be its own, so a full-slot signature cannot be
# replayed onto a hot package or the other way round.
assert 'OTAD_HOT_STATEMENT_TYPE "dreamingwrt.hot_update.v1"' in INTERNAL
assert 'OTAD_RELEASE_STATEMENT_TYPE "dreamingwrt.full_slot_release.v1"' in INTERNAL

trust = between(
    TRUST,
    "int otad_hot_release_trust_verify(",
    "int otad_release_trust_binding_get(",
)
assert "trust_load_policy(" in trust
assert "trust_key_allowed(policy, key_id" in trust
assert "trust_verify_ed25519(key_id" in trust
assert "json_object_equal(signed_json, outer_statement)" in trust
assert "OTAD_HOT_STATEMENT_TYPE" in trust
assert "trust_target_match(target" in trust
assert "trust_hot_epoch_policy(policy" in trust
assert 'strcmp(otad_json_str(manifest, "release_state", ""), "signed")' in trust
assert 'otad_json_bool(manifest, "publishable", 0)' in trust
# Every accept-side flag starts false and is only replaced after its own check.
assert trust.index('"signature_verified", json_object_new_boolean(0)') < trust.index(
    "trust_verify_ed25519(key_id"
)
assert trust.index("trust_verify_ed25519(key_id") < trust.index(
    '"signature_verified", json_object_new_boolean(1)'
)
assert trust.index("trust_target_match(target") < trust.index(
    '"target_compatible", json_object_new_boolean(1)'
)
assert trust.index("rc = 0;") > trust.index("trust_hot_epoch_policy(policy")

ubus_apply = between(
    UBUS,
    "static int otad_handle_apply(",
    "static int otad_handle_operation_status(",
)
assert "otad_update_apply(otad_payload_or_self(body))" in ubus_apply
assert 'UBUS_METHOD("apply", otad_handle_apply' in UBUS

# Status reports hot apply as implemented and gated on trust readiness alone: it
# needs no slot and no reboot, so the A/B preconditions do not apply to it.
assert '"hot_update_apply_implemented",\n                               json_object_new_boolean(1)' in STATUS
assert '"hot_update_apply_enabled",\n                               json_object_new_boolean(trust_ready)' in STATUS
assert '"hot_update_apply_reason"' in STATUS
assert '"hot_update_writer_disabled_in_build"' not in STATUS

print("ok: hot-update apply is reachable only through a verified release signature")
