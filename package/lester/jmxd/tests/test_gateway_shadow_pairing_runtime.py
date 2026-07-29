#!/usr/bin/env python3
"""Real two-node Ed25519 tests for Gateway Shadow pairing."""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import types
from contextlib import contextmanager
from pathlib import Path

try:
    import pytest
except ImportError:
    class _Mark:
        @staticmethod
        def parametrize(*_args, **_kwargs):
            return lambda function: function

    pytest = types.SimpleNamespace(
        fixture=lambda *_args, **_kwargs: (lambda function: function),
        skip=lambda message: (_ for _ in ()).throw(RuntimeError(message)),
        mark=_Mark(),
    )

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/jmx_gateway_shadow_pairing.c"


def find_prefix(variable: str, candidates: list[str], header: str) -> Path | None:
    values = ([os.environ[variable]] if os.environ.get(variable) else []) + candidates
    for value in values:
        prefix = Path(value)
        if (prefix / "include" / header).is_file():
            return prefix
    return None


@pytest.fixture(scope="session")
def library(tmp_path_factory):
    json_c = find_prefix("JSON_C_PREFIX", [
        "/opt/homebrew/opt/json-c",
        "/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19",
        "/usr",
    ], "json-c/json.h")
    openssl = find_prefix("OPENSSL_PREFIX", ["/opt/homebrew/opt/openssl@3", "/usr"],
                          "openssl/evp.h")
    sqlite = find_prefix("SQLITE_PREFIX", ["/opt/homebrew/opt/sqlite", "/usr"],
                         "sqlite3.h")
    if not json_c or not openssl or not sqlite:
        pytest.skip("json-c/OpenSSL/SQLite development headers unavailable")
    out = tmp_path_factory.mktemp("gateway-shadow-pairing")
    library_path = out / ("libpairing.dylib" if sys.platform == "darwin" else "libpairing.so")
    command = [
        os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
        "-fPIC", "-dynamiclib" if sys.platform == "darwin" else "-shared",
        f"-I{ROOT / 'src'}", f"-I{json_c / 'include'}", f"-I{openssl / 'include'}",
        f"-I{sqlite / 'include'}", str(SOURCE), "-o", str(library_path),
        f"-L{json_c / 'lib'}", f"-L{openssl / 'lib'}", f"-L{sqlite / 'lib'}",
        f"-Wl,-rpath,{json_c / 'lib'}", f"-Wl,-rpath,{openssl / 'lib'}",
    ]
    if sys.platform == "darwin":
        # The temporary Homebrew json-c dylib has a placeholder install_name;
        # link its static archive so the test is portable on this workstation.
        command.extend([str(json_c / "lib/libjson-c.a"),
                        str(openssl / "lib/libcrypto.dylib"),
                        str(sqlite / "lib/libsqlite3.dylib")])
    else:
        command.extend(["-ljson-c", "-lcrypto", "-lsqlite3"])
    subprocess.run(command, check=True, text=True, capture_output=True)
    lib = ctypes.CDLL(str(library_path))
    lib.json_tokener_parse.argtypes = [ctypes.c_char_p]
    lib.json_tokener_parse.restype = ctypes.c_void_p
    lib.json_object_to_json_string_ext.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.json_object_to_json_string_ext.restype = ctypes.c_char_p
    lib.json_object_put.argtypes = [ctypes.c_void_p]
    for name in ("jmx_gateway_shadow_pairing_identity",
                 "jmx_gateway_shadow_pairing_protocol_start",
                 "jmx_gateway_shadow_pairing_protocol_approve"):
        function = getattr(lib, name)
        function.restype = ctypes.c_void_p
        function.argtypes = [] if name.endswith("identity") else [ctypes.c_void_p]
    return lib


@contextmanager
def node(root: Path):
    previous = {key: os.environ.get(key) for key in (
        "DREAMINGWRT_CONFIG_DB", "DREAMINGWRT_GATEWAY_SHADOW_DIR")}
    root.mkdir(parents=True, exist_ok=True)
    os.environ["DREAMINGWRT_CONFIG_DB"] = str(root / "config.db")
    os.environ["DREAMINGWRT_GATEWAY_SHADOW_DIR"] = str(root / "gateway-shadow")
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def invoke(lib, name: str, payload: dict | None = None) -> dict:
    argument = None if payload is None else lib.json_tokener_parse(
        json.dumps(payload, separators=(",", ":")).encode())
    try:
        result = getattr(lib, name)(argument) if payload is not None else getattr(lib, name)()
        assert result
        try:
            return json.loads(lib.json_object_to_json_string_ext(result, 0).decode())
        finally:
            lib.json_object_put(result)
    finally:
        if argument:
            lib.json_object_put(argument)


PRIMARY = {
    "role": "primary", "management_ipv4": "192.168.30.2/24",
    "heartbeat_prefix_length": 30, "virtual_ipv4": "192.168.30.1/24",
    "virtual_router_id": 51, "priority": 150,
}
SECONDARY = {
    "role": "secondary", "management_ipv4": "192.168.30.3/24",
    "heartbeat_prefix_length": 30, "virtual_ipv4": "192.168.30.1/24",
    "virtual_router_id": 51, "priority": 100,
}


def trust(root: Path) -> str | None:
    if not (root / "config.db").exists():
        return None
    with sqlite3.connect(root / "config.db") as db:
        row = db.execute(
            "SELECT trust_state FROM gateway_shadow_pairing_peer WHERE id=1"
        ).fetchone()
    return row[0] if row else None


def start(lib, root: Path, config=PRIMARY) -> dict:
    with node(root):
        return invoke(lib, "jmx_gateway_shadow_pairing_protocol_start",
                      {"action": "start", "config": config})


def approve(lib, root: Path, offer: dict, code: str, config=SECONDARY) -> dict:
    with node(root):
        return invoke(lib, "jmx_gateway_shadow_pairing_protocol_approve", {
            "action": "approve", "offer": offer, "pairing_code": code,
            "config": config,
        })


def test_identity_is_stable_ed25519_and_private_key_is_0600(library, tmp_path):
    root = tmp_path / "a"
    with node(root):
        first = invoke(library, "jmx_gateway_shadow_pairing_identity")
        second = invoke(library, "jmx_gateway_shadow_pairing_identity")
    assert first == second
    assert first["ok"] and first["algorithm"] == "Ed25519"
    assert hashlib.sha256(bytes.fromhex(first["public_key"])).hexdigest() == first["fingerprint"]
    assert "private_key" not in first and first["private_key_exportable"] is False
    key = root / "gateway-shadow/identity.key"
    assert key.stat().st_size == 32
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE(key.parent.stat().st_mode) == 0o700


def test_four_step_pairing_binds_ha_configuration(library, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    started = start(library, a)
    assert started["ok"] and not started["paired"]
    code, offer = started["pairing_code"], started["offer"]
    assert "pairing_code" not in json.dumps(offer)
    for key, value in PRIMARY.items():
        assert offer[f"initiator_{key}"] == value

    approved = approve(library, b, offer, code)
    assert approved["ok"] and not approved["paired"] and trust(b) is None
    acceptance = approved["acceptance"]
    assert code not in json.dumps(acceptance)
    for key, value in PRIMARY.items():
        assert acceptance[f"initiator_{key}"] == value
    for key, value in SECONDARY.items():
        assert acceptance[f"responder_{key}"] == value

    with node(a):
        finalized = invoke(library, "jmx_gateway_shadow_pairing_protocol_start", {
            "action": "finalize", "acceptance": acceptance,
        })
    assert finalized["ok"] and finalized["paired"] and trust(a) == "paired"
    confirmation = finalized["confirmation"]
    assert code not in json.dumps(confirmation)

    with node(b):
        confirmed = invoke(library, "jmx_gateway_shadow_pairing_protocol_approve", {
            "action": "confirm", "confirmation": confirmation,
        })
    assert confirmed["ok"] and confirmed["paired"] and trust(b) == "paired"
    assert not list((a / "gateway-shadow").glob("pending-*.code"))


@pytest.mark.parametrize("changed", [
    {"role": "primary"}, {"heartbeat_prefix_length": 29},
    {"virtual_ipv4": "192.168.30.254/24"}, {"virtual_router_id": 52},
])
def test_role_or_cluster_binding_conflict_is_rejected(library, tmp_path, changed):
    a, b = tmp_path / "a", tmp_path / "b"
    started = start(library, a)
    config = {**SECONDARY, **changed}
    rejected = approve(library, b, started["offer"], started["pairing_code"], config)
    assert not rejected["ok"] and rejected["error"] == "pairing_binding_conflict"
    assert trust(b) is None


def test_wrong_code_and_tampered_messages_never_pair(library, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    started = start(library, a)
    wrong = "00000000" if started["pairing_code"] != "00000000" else "99999999"
    assert not approve(library, b, started["offer"], wrong)["ok"]
    tampered_offer = json.loads(json.dumps(started["offer"]))
    tampered_offer["initiator_priority"] = 151
    assert not approve(library, b, tampered_offer, started["pairing_code"])["ok"]
    assert trust(b) is None

    approved = approve(library, b, started["offer"], started["pairing_code"])
    acceptance = json.loads(json.dumps(approved["acceptance"]))
    acceptance["responder_priority"] = 101
    with node(a):
        rejected = invoke(library, "jmx_gateway_shadow_pairing_protocol_start", {
            "action": "finalize", "acceptance": acceptance,
        })
    assert not rejected["ok"] and trust(a) is None


def test_tampered_confirmation_does_not_pair_responder(library, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    started = start(library, a)
    approved = approve(library, b, started["offer"], started["pairing_code"])
    with node(a):
        finalized = invoke(library, "jmx_gateway_shadow_pairing_protocol_start", {
            "action": "finalize", "acceptance": approved["acceptance"],
        })
    confirmation = json.loads(json.dumps(finalized["confirmation"]))
    confirmation["responder_management_ipv4"] = "192.168.30.99/24"
    with node(b):
        rejected = invoke(library, "jmx_gateway_shadow_pairing_protocol_approve", {
            "action": "confirm", "confirmation": confirmation,
        })
    assert not rejected["ok"] and trust(b) is None


def test_environment_path_overrides_are_used(library, tmp_path):
    root = tmp_path / "custom"
    assert start(library, root)["ok"]
    assert (root / "config.db").is_file()
    assert (root / "gateway-shadow/identity.key").is_file()


def _standalone_main() -> int:
    if "pytest" in sys.modules and hasattr(sys.modules["pytest"], "main"):
        return sys.modules["pytest"].main([__file__, "-q"])
    import tempfile
    class Factory:
        def mktemp(self, name):
            return Path(tempfile.mkdtemp(prefix=name))
    lib = library(Factory())
    tests = [
        test_identity_is_stable_ed25519_and_private_key_is_0600,
        test_four_step_pairing_binds_ha_configuration,
        test_wrong_code_and_tampered_messages_never_pair,
        test_tampered_confirmation_does_not_pair_responder,
        test_environment_path_overrides_are_used,
    ]
    for test in tests:
        with tempfile.TemporaryDirectory(prefix=test.__name__) as directory:
            test(lib, Path(directory))
        print(f"PASS {test.__name__}")
    for change in (
        {"role": "primary"}, {"heartbeat_prefix_length": 29},
        {"virtual_ipv4": "192.168.30.254/24"}, {"virtual_router_id": 52},
    ):
        with tempfile.TemporaryDirectory(prefix="binding-conflict") as directory:
            test_role_or_cluster_binding_conflict_is_rejected(lib, Path(directory), change)
    print("PASS test_role_or_cluster_binding_conflict_is_rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(_standalone_main())
