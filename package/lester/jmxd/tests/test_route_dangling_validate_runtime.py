#!/usr/bin/env python3
"""The route config write cycle survives dangling route_rule_wan members.

Splitting exported members into wan_ids and dangling_wan_ids left the validator
and the exporter disagreeing about the same rule. That matters because
jmx_route_db_replace_begin() commits only when the canonical payload compares
equal to the post-write readback, so any disagreement failed the whole write
with "config.db transactional readback mismatch". Three cases were broken:

  1. Deleting a WAN a rule still references. The member turns stale as a result
     of that very request, so the export reported it under dangling_wan_ids
     while the canonical copy still had it under wan_ids. An ordinary operation,
     rejected outright.
  2. A rule pinned only to lines that are gone. The validator refused it with
     "enabled rule without WAN targets must match a carrier", so the config
     could not be written back at all.
  3. Any rule whose members had all gone stale. The exporter labels it
     explicit_unresolved, the validator relabelled it auto_carrier.

route_validate_payload(), route_replace_tables() and route_read_config() are
extracted from src/routed/jmx_route_db.c and compiled, so this runs shipped code
against real SQLite built from the real schema. Reading the source cannot show
any of this: each function looks correct alone, and only the round trip disagrees.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_C = ROOT / "src/routed/jmx_route_db.c"
FIXTURE = ROOT / "tests/route_dangling_validate_fixture.c"

# The extracted region runs from the schema literal to the UCI import helpers,
# which need <uci.h> and are not part of the write cycle.
EXTRACT_START = "static const char route_schema_sql[]"
EXTRACT_END = "static const char *route_uci_opt("

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def extract_under_test() -> str:
    source = DB_C.read_text(encoding="utf-8")
    begin = source.find(EXTRACT_START)
    stop = source.find(EXTRACT_END, begin if begin >= 0 else 0)
    if begin < 0 or stop < 0:
        raise SystemExit("extraction anchors not found in jmx_route_db.c")
    return source[begin:stop]


def build(directory: Path) -> Path:
    (directory / "route_dangling_extracted.h").write_text(extract_under_test(),
                                                          encoding="utf-8")
    binary = directory / "route_dangling_validate"
    compiler = shutil.which("cc") or shutil.which("gcc")
    if not compiler:
        raise SystemExit("no C compiler available")
    command = [
        compiler, str(FIXTURE), "-o", str(binary),
        f"-I{directory}", f"-I{ROOT / 'src/routed'}",
        "-ljson-c", "-lsqlite3",
    ]
    for prefix in ("/opt/homebrew", "/usr/local"):
        if Path(prefix, "include").is_dir():
            command[4:4] = [f"-I{prefix}/include", f"-L{prefix}/lib"]
            break
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"fixture build failed:\n{result.stderr}")
    return binary


def run(binary: Path, scenario: str) -> dict:
    result = subprocess.run([str(binary), scenario], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"{scenario} failed to run:\n{result.stderr}")
    return json.loads(result.stdout.strip())


def only_rule(payload: dict, key: str) -> dict:
    return payload[key]["rules"][0]


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        binary = build(Path(directory))

        # 1. The 30.1 shape, read and written straight back.
        case = run(binary, "readback_roundtrip")
        check(case["accepted"], "30.1 shape was rejected by the validator")
        check(case.get("committed") is True,
              "reading the 30.1 config and writing it back does not commit")
        if case.get("committed"):
            rule = only_rule(case, "readback")
            check(rule["wan_ids"] == [1, 2],
                  f"live members changed across the cycle: {rule['wan_ids']}")
            check(rule.get("dangling_wan_ids") == [3, 4],
                  f"stale members lost across the cycle: {rule.get('dangling_wan_ids')}")

        # 2. Deleting a WAN that a rule still names must succeed.
        case = run(binary, "delete_referenced_wan")
        check(case["accepted"],
              f"deleting a referenced WAN was rejected: {case.get('error')}")
        check(case.get("committed") is True,
              "deleting a WAN a rule still references rolls the write back")
        if case.get("committed"):
            rule = only_rule(case, "readback")
            check(rule["wan_ids"] == [1],
                  f"surviving member wrong after WAN delete: {rule['wan_ids']}")
            check(rule.get("dangling_wan_ids") == [2],
                  "the deleted line's member was not reported as stale")

        # 3. A rule pinned only to lines that no longer exist.
        case = run(binary, "all_stale_roundtrip")
        check(case["accepted"],
              f"a fully stale pinned rule blocks the write: {case.get('error')}")
        check(case.get("committed") is True,
              "a fully stale pinned rule does not survive a write cycle")
        if case.get("committed"):
            rule = only_rule(case, "canonical")
            check(rule["wan_selection"] == "explicit_unresolved",
                  f"validator mislabels a pinned rule: {rule['wan_selection']}")
            check(rule.get("dangling_wan_ids") == [3, 4],
                  f"stale members not carried: {rule.get('dangling_wan_ids')}")

        # 4. Restoring one of two stale lines makes that member live again and
        #    leaves the other stale: WAN 3 comes back, WAN 4 is still gone.
        case = run(binary, "restore_stale_wan")
        check(case.get("committed") is True, "restoring a WAN does not commit")
        if case.get("committed"):
            rule = only_rule(case, "readback")
            check(rule["wan_ids"] == [3],
                  f"restored line did not become a live target: {rule['wan_ids']}")
            check(rule.get("dangling_wan_ids") == [4],
                  f"the line still missing should stay stale: {rule.get('dangling_wan_ids')}")
            check(rule["wan_selection"] == "explicit",
                  f"restored rule label wrong: {rule['wan_selection']}")

        # 5. The guard this relaxes must still reject a rule targeting nothing.
        case = run(binary, "no_members_no_carrier")
        check(not case["accepted"],
              "an enabled rule with no members and no carrier is now accepted")
        check("must match a carrier" in case.get("error", ""),
              f"wrong rejection reason: {case.get('error')}")

        # 6. A malformed stale id reports itself rather than the carrier error.
        case = run(binary, "stale_id_out_of_range")
        check(not case["accepted"], "an out-of-range stale id was accepted")
        check("invalid stale WAN target id" in case.get("error", ""),
              f"malformed stale id masked by another error: {case.get('error')}")

    for failure in failures:
        print(f"FAIL: {failure}")
    if failures:
        return 1
    print("ok: validator and exporter agree on dangling members; "
          "WAN delete, full-stale and restore all commit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
