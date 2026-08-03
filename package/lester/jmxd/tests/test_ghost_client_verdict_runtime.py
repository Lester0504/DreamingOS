#!/usr/bin/env python3
"""Runtime proof for the ghost-client fix (Acceptance P1, 30.222 / 30.199).

Acceptance stated the only acceptable proof is reproducing the live shape --
IPv6 STALE together with IPv4 FAILED -- and showing the client comes out
offline, where the pre-fix binary reported ``online: true`` with
``online_source: "arp"``.

So this does not paraphrase the logic: it lifts ``jmx_db_client_online_verdict``
and ``db_client_neigh_reachable`` verbatim out of ``src/jmx_db.c`` plus the two
structs out of ``src/jmx_db.h``, compiles them with the shipped fixture, and
checks the printed verdicts. Regression guards for the real devices that must
stay online are in the same table.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_C = ROOT / "src/jmx_db.c"
DB_H = ROOT / "src/jmx_db.h"
FIXTURE = ROOT / "tests/ghost_client_verdict_fixture.c"

REACHABLE_FN = "static int db_client_neigh_reachable(const char *state)"
VERDICT_FN = ("void jmx_db_client_online_verdict("
              "const struct jmx_db_client_evidence *ev,")
EVIDENCE_STRUCT = "struct jmx_db_client_evidence {"
VERDICT_STRUCT = "struct jmx_db_client_verdict {"

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def take_block(source: str, start_marker: str, is_struct: bool = False) -> str:
    """Return start_marker plus its brace-balanced body, verbatim."""
    start = source.find(start_marker)
    if start < 0:
        raise SystemExit(f"FAIL: marker not found in source: {start_marker!r}")
    brace = source.find("{", start)
    if brace < 0:
        raise SystemExit(f"FAIL: no opening brace after {start_marker!r}")
    depth = 0
    for i in range(brace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                if is_struct:
                    semi = source.find(";", i)
                    if semi < 0:
                        raise SystemExit("FAIL: struct without terminating ;")
                    return source[start:semi + 1]
                return source[start:i + 1]
    raise SystemExit(f"FAIL: unbalanced braces after {start_marker!r}")


def build_header(header_src: str) -> str:
    evidence = take_block(header_src, EVIDENCE_STRUCT, is_struct=True)
    verdict = take_block(header_src, VERDICT_STRUCT, is_struct=True)
    return "\n".join([
        "#ifndef VERDICT_UNDER_TEST_H",
        "#define VERDICT_UNDER_TEST_H",
        "#include <stdint.h>",
        evidence,
        verdict,
        "void jmx_db_client_online_verdict("
        "const struct jmx_db_client_evidence *ev,",
        "                                  struct jmx_db_client_verdict *out);",
        "#endif",
        "",
    ])


def build_unit(db_src: str) -> str:
    reachable = take_block(db_src, REACHABLE_FN)
    verdict = take_block(db_src, VERDICT_FN)
    return "\n".join([
        "#include <string.h>",
        "#include <stdint.h>",
        '#include "verdict_under_test.h"',
        "",
        reachable,
        "",
        verdict,
        "",
    ])


def parse_output(text: str) -> dict:
    rows: dict = {}
    for line in text.strip().splitlines():
        parts = line.split()
        if not parts:
            continue
        fields = {}
        for token in parts[1:]:
            if "=" in token:
                key, value = token.split("=", 1)
                fields[key] = value
        rows[parts[0]] = fields
    return rows


def main() -> None:
    db_src = DB_C.read_text()
    header_src = DB_H.read_text()

    check("jmx_db_client_online_verdict" in db_src,
          "jmx_db_client_online_verdict() is gone from src/jmx_db.c; the online "
          "decision must stay in one testable place")
    # The API path must actually use the shared verdict, not its own copy.
    row_start = db_src.find("static struct json_object *db_row_to_client(")
    check(row_start >= 0, "db_row_to_client() not found")
    row = db_src[row_start:row_start + 20000] if row_start >= 0 else ""
    check("jmx_db_client_online_verdict(&evidence, &verdict)" in row,
          "db_row_to_client() no longer calls the shared verdict function, so "
          "the API could drift away from the tested rules")

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        (tmpdir / "verdict_under_test.h").write_text(build_header(header_src))
        (tmpdir / "verdict_under_test.c").write_text(build_unit(db_src))
        binary = tmpdir / "ghost_verdict"
        compile_cmd = [
            "cc", "-std=gnu99", "-Wall", "-O1",
            "-I" + str(tmpdir),
            str(tmpdir / "verdict_under_test.c"), str(FIXTURE),
            "-o", str(binary),
        ]
        built = subprocess.run(compile_cmd, capture_output=True, text=True)
        if built.returncode != 0:
            print("FAIL: could not compile the extracted verdict code")
            print(built.stderr[-4000:])
            sys.exit(1)
        run = subprocess.run([str(binary)], capture_output=True, text=True,
                             timeout=30)
        if run.returncode != 0:
            print("FAIL: fixture exited " + str(run.returncode))
            print(run.stderr[-4000:])
            sys.exit(1)

    rows = parse_output(run.stdout)

    # The reported defect. Pre-fix this printed online=1 online_source=arp.
    ghost = rows.get("ghost_v6_stale_v4_failed")
    check(ghost is not None, "ghost scenario did not run")
    if ghost:
        check(ghost["online"] == "0",
              "IPv6 STALE + IPv4 FAILED still reports online: this is the exact "
              "ghost-client defect Acceptance reported on 30.222/30.199")
        check(ghost["neigh_failed"] == "1",
              "IPv4 FAILED was not recognised, so an IPv6 STALE entry is still "
              "masking it")
        check(ghost["neigh_reachable"] == "0",
              "STALE must not count as reachable")
        check(ghost["online_source"] != "arp",
              'online_source still claims "arp" for a client that is gone')
        check(ghost["online_source"] == "not_in_bridge_fdb",
              "an offline ghost should say why: expected not_in_bridge_fdb, got "
              + ghost["online_source"])

    unreadable = rows.get("ghost_v4_failed_fdb_unreadable")
    check(unreadable is not None and unreadable["online"] == "0",
          "IPv4 FAILED with no traffic must force offline even when the bridge "
          "FDB cannot be read")
    if unreadable:
        check(unreadable["online_source"] == "neigh_failed",
              "with the FDB unknown the honest reason is neigh_failed, got "
              + unreadable["online_source"])

    stale_absent = rows.get("stale_only_absent_from_fdb")
    check(stale_absent is not None and stale_absent["online"] == "0",
          "a client that is STALE everywhere and absent from the bridge FDB is "
          "the vanished-VM case and must be offline")

    # Regression guards: these must not flip offline.
    for name, why in (
        ("ipv6_only_reachable",
         "an IPv6-only client that is genuinely REACHABLE must stay online; the "
         "fix must not newly exclude IPv6-only devices"),
        ("real_device_reachable_in_fdb",
         "192.168.30.2/30.3 are REACHABLE and in the FDB and must stay online"),
        ("idle_reachable_no_traffic",
         "an idle but reachable client must stay online"),
        ("traffic_overrides_fdb_absence",
         "live traffic must override absence from the bridge FDB"),
        ("conntrack_overrides_fdb_absence",
         "active conntrack entries must override absence from the bridge FDB"),
        ("stale_only_present_in_fdb",
         "STALE but present in the FDB means the bridge saw a frame: stay online"),
    ):
        rowdata = rows.get(name)
        check(rowdata is not None, "scenario " + name + " did not run")
        if rowdata:
            check(rowdata["online"] == "1", name + ": " + why)

    idle = rows.get("idle_reachable_no_traffic")
    if idle:
        check(idle["zero_reason"] == "idle",
              "a reachable client with no traffic should report zero_reason=idle,"
              " got " + idle["zero_reason"])

    offline = rows.get("db_offline_stays_offline")
    if offline:
        check(offline["online"] == "0", "a DB-offline client must stay offline")
        check(offline["online_source"] != "arp",
              "an offline client must not inherit the runtime online_source")

    if failures:
        for item in failures:
            print("FAIL: " + item)
        sys.exit(1)
    print("ok: " + str(len(rows)) +
          " ghost-client verdicts match the required behaviour")


if __name__ == "__main__":
    main()
