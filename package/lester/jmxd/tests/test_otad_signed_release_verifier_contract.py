#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TRUST = (ROOT / "src/otad/otad_trust.c").read_text(encoding="utf-8")
FIRMWARE = (ROOT / "src/otad/otad_firmware.c").read_text(encoding="utf-8")
INTERNAL = (ROOT / "src/otad/otad_internal.h").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "src/Makefile").read_text(encoding="utf-8")
PACKAGE = (ROOT / "Makefile").read_text(encoding="utf-8")


for token in (
    "EVP_PKEY_ED25519",
    "EVP_DigestVerifyInit",
    "EVP_DigestVerify(ctx",
    "PEM_read_PUBKEY",
    "release_signature_contract_invalid",
    "release_signature_invalid",
    "signed_statement_metadata_mismatch",
    "signed_payload_region_sha256_mismatch",
    "signing_key_unknown",
    "signing_key_revoked_or_inactive",
    "signing_key_outside_validity",
    'REQUIRE_TARGET_TEXT("architecture", identity->architecture)',
    'REQUIRE_TARGET_TEXT("libc", identity->libc)',
    'REQUIRE_TARGET_TEXT("abi_version", identity->abi_version)',
    "target_board_mismatch",
    "target_model_mismatch",
    "target_boot_schema_incompatible",
    "security_epoch_below_policy",
    "security_epoch_downgrade_forbidden",
    "build_downgrade_forbidden",
    "same_build_reinstall_forbidden",
):
    assert token in TRUST, token

assert 'json_object_object_del(copy, "release_signature")' in TRUST
assert 'json_object_equal(signed_json, outer_statement)' in TRUST
assert 'region_offset != OTAD_FIRMWARE_HEADER_BYTES' in TRUST
assert 'region_size != firmware_size - OTAD_FIRMWARE_HEADER_BYTES' in TRUST
assert 'OTAD_TRUST_POLICY_PATH "/etc/dreamingwrt/ota-trust/policy.json"' in INTERNAL
assert 'OTAD_TRUST_KEY_DIR "/etc/dreamingwrt/ota-trust/keys"' in INTERNAL
assert 'OTAD_RELEASE_STATEMENT_TYPE "dreamingwrt.full_slot_release.v1"' in INTERNAL
assert "otad/otad_trust.o" in MAKEFILE
assert "+libopenssl" in PACKAGE.split("define Package/dreamingwrt-otad", 1)[1].split("endef", 1)[0]

parse = FIRMWARE[FIRMWARE.index("static int otad_firmware_header_read_fd"):]
parse = parse[:parse.index("static void otad_firmware_info_done")]
assert "out->schema_version != 3" in parse
assert "schema_version != 3" in FIRMWARE

validate = FIRMWARE[FIRMWARE.index("static int otad_firmware_validate_fd"):]
validate = validate[:validate.index("static struct json_object *otad_operation_status_by_id")]
assert validate.index("otad_verify_payload_fd(fd, &info->rootfs") < validate.index(
    "otad_release_trust_verify(fd, info->firmware_size, info->json"
)
assert validate.index("otad_release_trust_verify(fd, info->firmware_size, info->json") < validate.index(
    "otad_firmware_release_gate(resp, error, error_len)"
)
assert validate.rstrip().endswith("return -1;\n}")

print("ok: full-slot release verifier binds Ed25519 statement, target, payload and policy while writes remain closed")
