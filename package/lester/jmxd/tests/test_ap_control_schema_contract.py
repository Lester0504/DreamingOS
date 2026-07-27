#!/usr/bin/env python3
"""SQLite ownership and journal contract for AP control Phase 0."""

from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def read_required(path: Path) -> str:
    assert path.is_file(), f"required production file is missing: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def c_strings(text: str) -> str:
    return "".join(
        match.group(1).replace(r'\"', '"')
        for match in re.finditer(r'"((?:\\.|[^"\\])*)"', text)
    )


def function_body(text: str, symbol: str) -> str:
    match = re.search(rf"\b{re.escape(symbol)}\s*\([^;]*?\)\s*\{{", text, re.DOTALL)
    assert match, f"production function body is missing: {symbol}"
    start = match.end()
    depth = 1
    pos = start
    quote = ""
    while pos < len(text) and depth:
        char = text[pos]
        if quote:
            if char == "\\":
                pos += 2
                continue
            if char == quote:
                quote = ""
        elif char in {'"', "'"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        pos += 1
    assert depth == 0, f"could not delimit production function: {symbol}"
    return text[start:pos - 1]


def test_ac_schema_has_explicit_owner_and_authoritative_tables() -> None:
    internal = read_required(SRC / "ac/ac_internal.h")
    database = read_required(SRC / "ac/ac_db.c")
    assert '#define AC_CONFIG_DB_PATH "/etc/dreamingwrt/config.db"' in internal, (
        "AC must own its tables in the canonical configuration database"
    )
    assert '#define AC_SERVICE_NAME "dreamingwrt-ac"' in internal
    assert 'sqlite3_bind_text(st, 2, AC_SERVICE_NAME' in database, (
        "AC schema metadata must persist the formal owner name"
    )

    sql = c_strings(database).lower()
    tables = (
        "ac_schema_meta",
        "ac_controllers",
        "ac_sites",
        "ac_ap_groups",
        "ac_aps",
        "ac_ap_group_members",
        "ac_device_certificates",
        "ac_pairing_tokens",
        "ac_ssids",
        "ac_ssid_bindings",
        "ac_radio_desired",
        "ac_ap_runtime",
        "ac_radio_runtime",
        "ac_station_sessions",
        "ac_transactions",
        "ac_transaction_targets",
        "ac_events",
        "ac_secrets",
    )
    missing = [table for table in tables if f"create table if not exists {table}" not in sql]
    assert not missing, f"dreamingwrt-ac schema is missing authoritative tables: {missing}"

    migrate = function_body(database, "ac_schema_migrate")
    for token in ("BEGIN IMMEDIATE", "COMMIT", "ROLLBACK", "AC_SCHEMA_VERSION"):
        assert token in migrate, f"ac_db_migrate lacks atomic migration evidence: {token}"


def test_apd_uses_an_independent_owned_database_and_transaction_journal() -> None:
    internal = read_required(SRC / "apd/apd_internal.h")
    database = read_required(SRC / "apd/apd_db.c")
    assert '#define APD_DB_PATH "/etc/dreamingwrt/apd.db"' in internal
    assert '#define APD_SERVICE_NAME "dreamingwrt-apd"' in internal
    assert 'sqlite3_bind_text(st, 2, APD_SERVICE_NAME' in database, (
        "APD schema metadata must persist the formal owner name"
    )
    assert "/etc/dreamingwrt/config.db" not in database, (
        "APD must not open or write the controller configuration database"
    )

    sql = c_strings(database).lower()
    tables = (
        "apd_schema_meta",
        "apd_identity",
        "apd_certificate_meta",
        "apd_applied_state",
        "apd_transaction_journal",
    )
    missing = [table for table in tables if f"create table if not exists {table}" not in sql]
    assert not missing, f"dreamingwrt-apd schema is missing local authority tables: {missing}"

    journal_start = sql.find("create table if not exists apd_transaction_journal")
    assert journal_start >= 0
    journal = sql[journal_start:journal_start + 2200]
    fields = (
        "transaction_id",
        "desired_revision",
        "candidate_digest",
        "state",
        "applied_revision",
        "readback_digest",
        "rollback_ref",
        "updated_at",
    )
    missing_fields = [field for field in fields if field not in journal]
    assert not missing_fields, f"APD transaction journal is missing recovery fields: {missing_fields}"
    assert "primary key" in journal or "unique" in journal, (
        "APD transaction_id must provide durable idempotency"
    )

    migrate = function_body(database, "apd_schema_migrate")
    for token in ("BEGIN IMMEDIATE", "COMMIT", "ROLLBACK", "APD_SCHEMA_VERSION"):
        assert token in migrate, f"apd_db_migrate lacks atomic migration evidence: {token}"


def test_phase0_schema_does_not_store_private_keys_or_plaintext_secrets() -> None:
    ac_db = read_required(SRC / "ac/ac_db.c")
    apd_db = read_required(SRC / "apd/apd_db.c")
    schema = c_strings(ac_db + "\n" + apd_db).lower()
    forbidden_columns = (
        "private_key blob",
        "private_key text",
        "ca_private_key",
        "plaintext_password",
        "plain_password",
        "pairing_token text",
    )
    found = [column for column in forbidden_columns if column in schema]
    assert not found, f"AP control schema persists forbidden secret material: {found}"
    assert "token_hash" in schema, "pairing tokens may only be represented by a strong hash"
    for token in ("cipher_text", "nonce", "key_id"):
        assert token in schema, f"AC secret envelope is missing: {token}"


if __name__ == "__main__":
    test_ac_schema_has_explicit_owner_and_authoritative_tables()
    test_apd_uses_an_independent_owned_database_and_transaction_journal()
    test_phase0_schema_does_not_store_private_keys_or_plaintext_secrets()
    print("ok: AC/APD schema ownership, atomic migration, journal, and secret storage boundaries")
