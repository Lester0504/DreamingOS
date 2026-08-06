#!/usr/bin/env python3
"""Contract: a firmware apply is bound to durable, freshly verified evidence.

This deliberately source-level test keeps persistence and write ordering visible
while firmware slot writes remain fail closed.  It identifies the preflight
commit by its SQL invariant rather than requiring a particular helper name.
"""
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
DB = (ROOT / "src/otad/otad_db.c").read_text(encoding="utf-8")
FIRMWARE = (ROOT / "src/otad/otad_firmware.c").read_text(encoding="utf-8")
INTERNAL = (ROOT / "src/otad/otad_internal.h").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


def c_function_at(text: str, start: int) -> str:
    body_start = text.index("{", start)
    depth = 0
    for pos in range(body_start, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[start:pos + 1]
    raise AssertionError("unterminated C function")


def c_function(text: str, signature: str) -> str:
    return c_function_at(text, text.index(signature))


def strip_c_comments(text: str) -> str:
    """Blank out /* */ and // comments, preserving length and line structure.

    Ordering assertions below use str.index() to compare call-site offsets. The
    worker's opening comment mentions otad_operation_reverify_trust_binding() by
    name, so a raw index() matched the comment instead of the call and reported an
    ordering violation that does not exist in the code. Replacing comment bytes
    with spaces keeps every other offset identical.
    """
    out = []
    index = 0
    length = len(text)
    while index < length:
        pair = text[index:index + 2]
        if pair == "/*":
            end = text.find("*/", index + 2)
            if end == -1:
                out.append(" " * (length - index))
                break
            block = text[index:end + 2]
            out.append("".join(ch if ch == "\n" else " " for ch in block))
            index = end + 2
        elif pair == "//":
            end = text.find("\n", index)
            if end == -1:
                out.append(" " * (length - index))
                break
            out.append(" " * (end - index))
            index = end
        else:
            out.append(text[index])
            index += 1
    return "".join(out)


def c_function_containing(text: str, needle: str) -> tuple[str, str]:
    """Return the unique C function containing a production invariant marker."""
    needle_pos = text.index(needle)
    definitions = list(re.finditer(
        r"(?m)^(?:static\s+)?(?:int|void|struct\s+json_object\s*\*)\s+"
        r"([A-Za-z_]\w*)\s*\(",
        text[:needle_pos],
    ))
    for definition in reversed(definitions):
        function = c_function_at(text, definition.start())
        if needle in function:
            return definition.group(1), function
    raise AssertionError(f"no C function contains invariant marker: {needle}")


TRUST_TEXT_FIELDS = (
    "manifest_digest",
    "signing_key_id",
    "trust_policy_digest",
    "device_identity_digest",
)
TRUST_VERSION_FIELD = "trust_policy_version"
TRUST_BOOL_FIELDS = (
    "authenticity_verified",
    "target_compatible",
    "policy_passed",
)
TRUST_FIELDS = TRUST_TEXT_FIELDS + (TRUST_VERSION_FIELD,) + TRUST_BOOL_FIELDS
OPERATION_BINDING_FIELDS = TRUST_FIELDS + ("topology_digest",)
DIGEST_FIELDS = (
    "manifest_digest",
    "trust_policy_digest",
    "device_identity_digest",
    "topology_digest",
)


# ota_operations is the durable authorization boundary. result_json is only
# diagnostic output and cannot authorize a later slot write.
schema = between(
    DB,
    '"CREATE TABLE IF NOT EXISTS ota_operations ("',
    "CREATE INDEX IF NOT EXISTS ota_operations_updated_idx",
)
for field in TRUST_TEXT_FIELDS + ("topology_digest",):
    assert f'" {field} TEXT NOT NULL DEFAULT \'\',"' in schema, (
        f"ota_operations schema must persist {field}"
    )
assert f'" {TRUST_VERSION_FIELD} INTEGER NOT NULL DEFAULT 0,"' in schema
for field in TRUST_BOOL_FIELDS:
    assert f'" {field} INTEGER NOT NULL DEFAULT 0,"' in schema, (
        f"ota_operations schema must persist {field}"
    )


# Discover the production preflight commit by the actual validating->pending
# SQL transition. All evidence and pending state must be one conditional UPDATE.
commit_name, commit = c_function_containing(
    DB, '"UPDATE ota_operations SET state=\'pending\''
)
assert commit.count("UPDATE ota_operations SET") == 1, (
    "preflight evidence and pending state must be one persistent UPDATE"
)
assert "SET state='pending'" in commit
assert "AND state='validating'" in commit
assert "source_size>=1048576" in commit
assert "length(source_sha256)=64" in commit
assert "source_sha256 NOT GLOB '*[^0-9A-Fa-f]*'" in commit
for field in OPERATION_BINDING_FIELDS:
    assert f"{field}=?" in commit, (
        f"preflight commit must write {field} atomically with pending state"
    )
for field in TRUST_FIELDS:
    if field == TRUST_VERSION_FIELD:
        assert f"binding->{field} < 1" in commit
    elif field in TRUST_BOOL_FIELDS:
        assert f"!binding->{field}" in commit
    elif field == "signing_key_id":
        assert f"otad_signing_key_id_ok(binding->{field})" in commit
    else:
        assert f"otad_digest_hex_ok(binding->{field})" in commit
assert "otad_digest_hex_ok(topology_digest)" in commit
for field in OPERATION_BINDING_FIELDS:
    empty = "0" if field == TRUST_VERSION_FIELD or field in TRUST_BOOL_FIELDS else "''"
    assert f"{field}={empty}" in commit, (
        f"preflight commit must refuse to overwrite persisted {field}"
    )
for bind_index, source in (
    (5, "binding->manifest_digest"),
    (6, "binding->signing_key_id"),
    (7, "binding->trust_policy_version"),
    (8, "binding->trust_policy_digest"),
    (9, "binding->device_identity_digest"),
    (10, "topology_digest"),
    (11, "binding->authenticity_verified"),
    (12, "binding->target_compatible"),
    (13, "binding->policy_passed"),
):
    assert re.search(
        rf"sqlite3_bind_(?:text|int)\(st,\s*{bind_index},\s*{re.escape(source)}",
        commit,
    ), f"preflight SQL parameter {bind_index} must bind {source}"
assert "sqlite3_changes(g_otad_inventory_db) == 1" in commit

preflight = c_function(FIRMWARE, "struct json_object *otad_firmware_preflight(")
commit_call = f"{commit_name}(operation_id"
assert commit_call in preflight
assert 'otad_operation_update(operation_id, "pending"' not in preflight
assert preflight.index("otad_firmware_validate_fd(") < preflight.index(commit_call), (
    "preflight must validate a release before persisting pending evidence"
)


# Apply claim must atomically reject incomplete, failed, or malformed evidence.
claim = c_function(DB, "int otad_operation_claim_apply(")
assert claim.count("UPDATE ota_operations SET") == 1
assert "AND state='pending'" in claim
assert "source_size>=1048576" in claim
assert "length(source_sha256)=64" in claim
assert "source_sha256 NOT GLOB '*[^0-9A-Fa-f]*'" in claim
assert "target_slot IN ('A','B')" in claim
for field in TRUST_BOOL_FIELDS:
    assert f"AND {field}=1" in claim
for field in TRUST_TEXT_FIELDS + ("topology_digest",):
    assert f"AND {field}<>''" in claim
assert f"AND {TRUST_VERSION_FIELD}>0" in claim
for field in DIGEST_FIELDS:
    assert f"length({field})=64" in claim, f"claim must require complete {field}"
    assert f"{field} NOT GLOB '*[^0-9A-Fa-f]*'" in claim, (
        f"claim must require hexadecimal {field}"
    )
assert "length(signing_key_id)<=128" in claim
assert "signing_key_id NOT GLOB '*[^0-9A-Za-z._-]*'" in claim
assert "sqlite3_changes(g_otad_inventory_db) == 1" in claim

transition = c_function(DB, "static int otad_operation_transition_ok(")
validating = transition[transition.index('if (!strcmp(from, "validating"))'):]
validating = validating[:validating.index('if (!strcmp(from, "pending"))')]
assert '"pending"' not in validating and '"writing"' not in validating, (
    "generic updater must not authorize validating->pending/writing"
)


# Worker authority comes from the exact persisted operation binding.
work_struct = between(INTERNAL, "struct otad_operation_work {", "};")
for field in OPERATION_BINDING_FIELDS:
    assert field in work_struct, f"operation work must carry {field}"

get_work = c_function(DB, "int otad_operation_get_work(")
for field in OPERATION_BINDING_FIELDS:
    assert field in get_work, f"operation work query must read {field}"
    assert f"work->{field}" in get_work, f"operation work must populate {field}"


# Fresh verification must cover signed release, policy/device evidence, and
# topology. It must occur after staging identity checks but before any target
# probe, GRUB mutation, or inactive-slot write.
binding = c_function(FIRMWARE, "int otad_operation_reverify_trust_binding(")
assert "otad_release_trust_verify(" in binding
assert binding.index("otad_release_trust_verify(") < binding.index(
    "otad_ab_topology_discover("
)
assert binding.index("otad_ab_topology_discover(") < binding.index(
    "otad_ab_topology_validate_release("
)
for field in TRUST_FIELDS:
    assert f"work->{field}" in binding, (
        f"fresh trust evidence must be compared with persisted {field}"
    )
assert "topology.topology_digest" in binding
assert "work->topology_digest" in binding

worker = c_function(FIRMWARE, "static int otad_firmware_apply_worker(")
# Ordering is checked against the comment-free text so a call named in a comment
# cannot be mistaken for the call itself.
worker_code = strip_c_comments(worker)
assert "otad_operation_reverify_trust_binding(" in worker_code, (
    "the reverify call must be real code, not only mentioned in a comment"
)
staging_open = worker_code.index("otad_staged_upload_open(")
staging_size = worker_code.index("upload.size != work->source_size")
staging_hash = worker_code.index("upload.sha256, work->source_sha256")
trust_call = worker_code.index("otad_operation_reverify_trust_binding(")
assert staging_open < staging_size < trust_call
assert staging_open < staging_hash < trust_call
for target_boundary in (
    "otad_firmware_validate_fd(",
    "otad_grubenv_prepare_target(",
    "open(target, O_WRONLY",
):
    assert trust_call < worker_code.index(target_boundary), (
        f"worker must reverify binding before {target_boundary}"
    )

validate = c_function(FIRMWARE, "static int otad_firmware_validate_fd(")
assert "open(target, O_RDONLY | O_CLOEXEC)" in validate, (
    "validation boundary must continue to include inactive target probing"
)

print("ok: OTA operation evidence is atomically persisted, claimed, loaded, and reverified before target access")
