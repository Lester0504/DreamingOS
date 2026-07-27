#!/usr/bin/env python3
"""Validate real APD public JSON serializers against secret leakage."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    result = subprocess.run(
        [str(args.binary.resolve())], text=True, capture_output=True, check=True
    )
    lines = result.stdout.splitlines()
    assert len(lines) == 2
    identity = json.loads(lines[0])
    pairing = json.loads(lines[1])
    assert identity == {
        "ok": True,
        "contract_version": "ap-control.v1",
        "ap_id": "12345678-1234-4123-8123-123456789abc",
        "algorithm": "Ed25519",
        "key_id": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "public_key_encoding": "raw-hex",
        "public_key": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "created_at": 42,
        "key_exportable": False,
    }
    assert pairing["state"] == "challenge_pending"
    assert pairing["enrollment_state"] == "challenge_pending"
    assert pairing["challenge_present"] is True
    assert pairing["mtls_ready"] is False
    assert pairing["remote_transport_ready"] is False
    assert pairing["adopted"] is False
    adopted_env = os.environ.copy()
    adopted_env["APD_TEST_ADOPTED"] = "1"
    adopted_result = subprocess.run(
        [str(args.binary.resolve())], text=True, capture_output=True,
        check=True, env=adopted_env
    )
    adopted_pairing = json.loads(adopted_result.stdout.splitlines()[1])
    assert adopted_pairing["state"] == "adopted"
    assert adopted_pairing["enrollment_state"] == "challenge_pending"
    assert adopted_pairing["mtls_ready"] is True
    assert adopted_pairing["adopted"] is True
    serialized = result.stdout.lower()
    for forbidden in (
        "private_key",
        "challenge_hash",
        "pairing_token",
        "secret",
        "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
    ):
        assert forbidden not in serialized
    print("ok: APD public identity and pairing JSON expose no secret material")


if __name__ == "__main__":
    main()
