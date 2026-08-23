#!/usr/bin/env python3
"""Run the real hot-update signature verifier against a real ed25519 key.

This test exists because the previous hot-update contract test only asserted
source text: it could pass while the verifier accepted anything. Here the
package statement is signed with openssl, handed to the compiled
otad_hot_release_trust_verify(), and every rejection path is exercised by
mutating one thing at a time. A verifier that returned 0 unconditionally would
fail the reverse cases below.
"""

import base64
import json
import os
import platform
import subprocess
import tempfile
from pathlib import Path

from otad_test_deps import find_host_dependencies


ROOT = Path(__file__).resolve().parents[1]

STUBS = {
    "libubox/blobmsg.h": r'''
#pragma once
#include <stdbool.h>
#include <stddef.h>
struct blob_attr { int unused; };
struct blob_buf { void *head; };
struct blobmsg_policy { const char *name; int type; };
enum { BLOBMSG_TYPE_UNSPEC = 0 };
void blob_buf_init(struct blob_buf *, int);
void blob_buf_free(struct blob_buf *);
int blobmsg_add_json_from_string(struct blob_buf *, const char *);
''',
    "libubox/blobmsg_json.h": r'''
#pragma once
#include <stdbool.h>
struct blob_attr;
char *blobmsg_format_json(struct blob_attr *, bool);
''',
    "libubox/uloop.h": r'''
#pragma once
#include <sys/types.h>
struct uloop_timeout { void (*cb)(struct uloop_timeout *); };
struct uloop_process { pid_t pid; void (*cb)(struct uloop_process *, int); };
int uloop_timeout_set(struct uloop_timeout *, int);
int uloop_process_add(struct uloop_process *);
''',
    "libubox/utils.h": r'''
#pragma once
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
''',
    "libubus.h": r'''
#pragma once
#include <stdint.h>
struct ubus_context;
struct ubus_request_data;
#define UBUS_STATUS_OK 0
int ubus_lookup_id(struct ubus_context *, const char *, uint32_t *);
''',
    "linux/fs.h": r'''
#pragma once
#include <sys/ioctl.h>
#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12, 114, unsigned long long)
#endif
''',
    "sys/mount.h": r'''
#pragma once
#define MS_RDONLY 1UL
#define MS_NOSUID 2UL
#define MS_NODEV 4UL
#define MS_NOEXEC 8UL
#define MS_NOATIME 1024UL
#define MNT_DETACH 2
int mount(const char *, const char *, const char *, unsigned long, const void *);
int umount(const char *);
int umount2(const char *, int);
''',
    "sqlite3.h": r'''
#pragma once
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
''',
    "zlib.h": r'''
#pragma once
#include <stddef.h>
typedef void *gzFile;
''',
    "unistd.h": r'''
#pragma once
#include_next <unistd.h>
int syncfs(int);
''',
}

HARNESS = r'''
#include "otad_internal.h"

char *blobmsg_format_json(struct blob_attr *attr, bool list)
{
    (void)attr;
    (void)list;
    return NULL;
}

int otad_state_set(const char *key, const char *value)
{
    (void)key;
    (void)value;
    return 0;
}

int main(int argc, char **argv)
{
    struct json_object *manifest;
    struct json_object *evidence = NULL;
    char error[OTAD_MAX_TEXT] = "";
    char *text = NULL;
    size_t len = 0;
    int rc;

    if (argc != 3) {
        fprintf(stderr, "usage: harness <manifest.json> <expected>\n");
        return 2;
    }
    if (otad_file_read_all(argv[1], &text, &len, OTAD_MAX_JSON_BYTES) != 0) {
        fprintf(stderr, "cannot read %s\n", argv[1]);
        return 2;
    }
    manifest = json_tokener_parse(text);
    free(text);
    if (!manifest) {
        fprintf(stderr, "cannot parse %s\n", argv[1]);
        return 2;
    }
    rc = otad_hot_release_trust_verify(manifest, &evidence, error, sizeof(error));
    if (!strcmp(argv[2], "ok")) {
        if (rc != 0) {
            fprintf(stderr, "expected accept, got rc=%d error=%s\n", rc, error);
            return 1;
        }
        if (!otad_json_bool(evidence, "signature_verified", 0) ||
            !otad_json_bool(evidence, "authenticity_verified", 0) ||
            !otad_json_bool(evidence, "target_compatible", 0) ||
            !otad_json_bool(evidence, "policy_passed", 0)) {
            fprintf(stderr, "accepted but evidence is not fully true: %s\n",
                    json_object_to_json_string(evidence));
            return 1;
        }
        if (strcmp(otad_json_str(evidence, "statement_type", ""),
                   OTAD_HOT_STATEMENT_TYPE)) {
            fprintf(stderr, "wrong statement type in evidence\n");
            return 1;
        }
        printf("accepted\n");
    } else {
        if (rc == 0) {
            fprintf(stderr, "expected rejection %s but the package was accepted\n",
                    argv[2]);
            return 1;
        }
        if (strcmp(error, argv[2])) {
            fprintf(stderr, "expected rejection %s, got %s\n", argv[2], error);
            return 1;
        }
        if (otad_json_bool(evidence, "authenticity_verified", 0)) {
            fprintf(stderr, "rejected but evidence still claims authenticity\n");
            return 1;
        }
        printf("rejected: %s\n", error);
    }
    if (evidence)
        json_object_put(evidence);
    json_object_put(manifest);
    return 0;
}
'''

KEY_ID = "dwrt-hot-test-2026"
HOT_STATEMENT = "dreamingwrt.hot_update.v1"


def host_architecture() -> str:
    """What trust_device_identity() will report on this machine.

    The verifier reads uname(), so the fixture has to claim the architecture of
    whatever runs the test rather than a fixed x86_64.
    """
    machine = platform.machine()
    return "x86_64" if machine == "amd64" else machine


def canonical(obj) -> bytes:
    """Byte-for-byte what json-c emits for the same object."""
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def base_manifest(architecture: str = "") -> dict:
    architecture = architecture or host_architecture()
    return {
        "manifest_version": 1,
        "artifact_type": "hot_update",
        "package_id": "dwrt-hot-test",
        "package_type": "hotfix",
        "firmware_type": "component",
        "product": "DreamingWrt",
        "arch": architecture,
        "board": ["generic"],
        "from_versions": ["Build20270517-Alpha"],
        "to_version": "Build20270518-Alpha",
        "requires_reboot": False,
        "slot_required": False,
        "release_state": "signed",
        "publishable": True,
        "payloads": [{
            "name": "usr__bin__dreamingwrt-webd",
            "type": "file",
            "path": "payload/files/usr/bin/dreamingwrt-webd",
            "target_path": "/usr/bin/dreamingwrt-webd",
            "sha256": "a" * 64,
            "md5": "b" * 32,
            "size": 1024,
            "offset_bytes": 1048576,
            "target_exists": True,
            "base_size": 1000,
            "base_sha256": "c" * 64,
            "mode": 493,
            "uid": 0,
            "gid": 0,
        }],
        "deletions": [],
        "service_actions": [
            {"service": "webd", "action": "restart", "when": "post_apply"},
        ],
        "target": {
            "architecture": architecture,
            "target": "x86",
            "subtarget": "64",
            "board": "generic",
            "models": ["generic"],
            "libc": "glibc",
            "abi_version": "1",
            "min_boot_schema": 2,
            "security_epoch": 1,
        },
    }


def ed25519_sign(private_key: Path, payload: bytes) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False) as handle:
        handle.write(payload)
        payload_path = handle.name
    try:
        signature = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key),
             "-in", payload_path], check=True, capture_output=True).stdout
    finally:
        os.unlink(payload_path)
    assert len(signature) == 64, len(signature)
    return signature


def sign(manifest: dict, private_key: Path, key_id: str = KEY_ID,
         statement_type: str = HOT_STATEMENT) -> dict:
    statement = {k: v for k, v in manifest.items() if k != "release_signature"}
    statement["statement_type"] = statement_type
    payload = canonical(statement)
    signature = ed25519_sign(private_key, payload)
    signed = dict(manifest)
    signed["release_signature"] = {
        "key_id": key_id,
        "algorithm": "ed25519",
        "signed_payload_encoding": "base64",
        "signature_encoding": "base64",
        "signed_payload": base64.b64encode(payload).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return signed


def flip_signature(manifest: dict) -> dict:
    """Corrupt exactly one byte, keeping the signature 64 bytes long."""
    broken = json.loads(json.dumps(manifest))
    raw = bytearray(base64.b64decode(broken["release_signature"]["signature"]))
    raw[0] ^= 0x01
    broken["release_signature"]["signature"] = base64.b64encode(bytes(raw)).decode("ascii")
    return broken


def main() -> None:
    deps = find_host_dependencies(ROOT)
    with tempfile.TemporaryDirectory(prefix="otad-hot-signature-") as td:
        temp = Path(td)
        stub_root = temp / "stubs"
        for name, content in STUBS.items():
            path = stub_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="ascii")

        fixture = temp / "fixture"
        keys = fixture / "ota-trust/keys"
        sysinfo = fixture / "sysinfo"
        keys.mkdir(parents=True)
        sysinfo.mkdir(parents=True)
        private_key = temp / "hot-test.key"
        other_key = temp / "other.key"
        for target in (private_key, other_key):
            subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519",
                            "-out", str(target)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(private_key), "-pubout",
                        "-out", str(keys / f"{KEY_ID}.pem")], check=True,
                       capture_output=True)

        policy_path = fixture / "policy.json"
        policy = {
            "schema_version": 1,
            "policy_version": 2,
            "minimum_security_epoch": 1,
            "allow_security_epoch_downgrade": False,
            "allow_build_downgrade": False,
            "allow_same_build": False,
            "keys": [{
                "key_id": KEY_ID,
                "status": "active",
                "algorithm": "ed25519",
                "not_before": 0,
                "not_after": 0,
            }],
        }
        policy_path.write_text(json.dumps(policy), encoding="ascii")
        (fixture / "openwrt_release").write_text(
            "DISTRIB_TARGET='x86/64'\nDISTRIB_ARCH='x86_64'\n", encoding="ascii")
        (sysinfo / "board_name").write_text("generic\n", encoding="ascii")
        (sysinfo / "model").write_text("generic\n", encoding="ascii")
        release_path = fixture / "dreamingwrt-release.json"
        release_path.write_text(json.dumps({
            "product": "DreamingWrt",
            "build_id": "Build20270517-Alpha",
            "schema_version": 3,
            "target": {"security_epoch": 1},
        }), encoding="ascii")

        harness = temp / "harness.c"
        harness.write_text(HARNESS, encoding="ascii")
        binary = temp / "harness"
        command = [
            os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra",
            "-Werror=implicit-function-declaration",
            "-I", str(stub_root),
            "-I", str(deps.json_include),
            "-I", str(deps.openssl_include),
            "-I", str(ROOT / "src/otad"),
            f'-DOTAD_TRUST_POLICY_PATH="{policy_path}"',
            f'-DOTAD_TRUST_KEY_DIR="{keys}"',
            f'-DOTAD_OPENWRT_RELEASE_PATH="{fixture / "openwrt_release"}"',
            f'-DOTAD_SYSINFO_DIR="{sysinfo}"',
            f'-DOTAD_RELEASE_PATH="{release_path}"',
            f'-DOTAD_RELEASE_NEW_PATH="{fixture / "absent-release.json"}"',
            '-DOTAD_IDENTITY_LIBC="glibc"',
            str(harness),
            str(ROOT / "src/otad/otad_trust.c"),
            str(ROOT / "src/otad/otad_common.c"),
        ]
        command += [str(deps.json_library)]
        command += ["-L", str(deps.openssl_library_dir), "-lcrypto", "-o", str(binary)]
        subprocess.run(command, check=True)

        env = os.environ.copy()
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = str(deps.openssl_library_dir) + (f":{existing}" if existing else "")

        def run(manifest: dict, expected: str, label: str) -> None:
            path = temp / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="ascii")
            result = subprocess.run([str(binary), str(path), expected],
                                    env=env, capture_output=True, text=True)
            if result.returncode != 0:
                raise AssertionError(
                    f"{label}: {result.stdout.strip()} {result.stderr.strip()}")

        signed = sign(base_manifest(), private_key)

        # Forward: a properly signed package verifies.
        run(signed, "ok", "correctly signed package must verify")

        # Device identity is fail-closed: a target component that cannot fit the
        # signed identity field must be rejected instead of silently truncated.
        (fixture / "openwrt_release").write_text(
            f"DISTRIB_TARGET='{'x' * 64}/64'\nDISTRIB_ARCH='x86_64'\n",
            encoding="ascii")
        run(signed, "device_target_identity_unavailable",
            "oversized device target identity must fail closed")
        (fixture / "openwrt_release").write_text(
            "DISTRIB_TARGET='x86/64'\nDISTRIB_ARCH='x86_64'\n",
            encoding="ascii")

        # Reverse: one flipped signature byte is refused. Forward and reverse
        # both passing is what makes the forward case meaningful.
        run(flip_signature(signed), "release_signature_invalid",
            "corrupted signature must be rejected")

        # Signed by a different private key while claiming the listed key_id:
        # verification runs against the listed public half and fails.
        run(sign(base_manifest(), other_key), "release_signature_invalid",
            "a package signed by another key must be rejected")

        # Signed by the right key but claiming a key_id the policy does not list.
        run(sign(base_manifest(), private_key, "dwrt-not-in-policy"),
            "signing_key_unknown", "key_id outside the policy must be rejected")

        # No signature at all.
        run(base_manifest(), "release_signature_contract_invalid",
            "unsigned package must be rejected")

        # Signature valid, manifest edited afterwards.
        tampered = json.loads(json.dumps(signed))
        tampered["to_version"] = "Build20270519-Alpha"
        run(tampered, "signed_statement_metadata_mismatch",
            "manifest edited after signing must be rejected")

        # The one that matters most: payload digests are the only thing binding
        # the signed manifest to the bytes the writer installs.
        swapped = json.loads(json.dumps(signed))
        swapped["payloads"][0]["sha256"] = "d" * 64
        run(swapped, "signed_statement_metadata_mismatch",
            "payload digest edited after signing must be rejected")

        # A full-slot statement must not satisfy the hot-update gate.
        run(sign(base_manifest(), private_key, KEY_ID,
                 "dreamingwrt.full_slot_release.v1"),
            "signed_statement_metadata_mismatch",
            "full-slot statement must not satisfy the hot-update gate")

        # Wrong device: another architecture.
        wrong = "riscv64" if host_architecture() != "riscv64" else "aarch64"
        other_arch = base_manifest(wrong)
        run(sign(other_arch, private_key), "target_architecture_mismatch",
            "package for another architecture must be rejected")

        # Wrong libc: glibc binaries must not land on a musl device.
        other_libc = base_manifest()
        other_libc["target"]["libc"] = "musl"
        run(sign(other_libc, private_key), "target_libc_mismatch",
            "package for another libc must be rejected")

        # Below the policy security epoch floor.
        old_epoch = base_manifest()
        old_epoch["target"]["security_epoch"] = 0
        run(sign(old_epoch, private_key), "security_epoch_below_policy",
            "package below the policy security epoch must be rejected")

        # Declared unsigned by its own metadata.
        unsigned_state = base_manifest()
        unsigned_state["release_state"] = "unsigned_development"
        run(sign(unsigned_state, private_key), "signed_hot_update_schema_required",
            "unsigned_development package must be rejected")

        # Revoking the key must stop a package that verified a moment ago.
        revoked = json.loads(json.dumps(policy))
        revoked["keys"][0]["status"] = "revoked"
        policy_path.write_text(json.dumps(revoked), encoding="ascii")
        run(signed, "signing_key_revoked_or_inactive",
            "revoked key must reject a previously accepted package")

    print("ok: hot-update apply is gated on a real ed25519 release signature")


if __name__ == "__main__":
    main()
