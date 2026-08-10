#!/usr/bin/env python3
"""Proof for the offline-client retention filter.

Acceptance reported ``GET /api/v1/clients`` returning 26 entries of which 23
were offline, median ``last_seen`` 16.7 days and the oldest 20.6 days, so the
list the user saw was four fifths historical residue. The fix ages offline rows
out of the default inventory.

Rather than paraphrasing the rule, this lifts ``jmx_db_client_row_stale``
verbatim out of ``src/jmx_db.c``, compiles it against the shipped fixture, and
checks the printed verdicts. It also asserts the wiring that the fixture cannot
see: that the list handler consults the predicate, that ``include_stale`` and the
retention constant exist, that the response self-describes the retention, and
that the topology merge path still asks for the full history.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DB_C = ROOT / "src/jmx_db.c"
DB_H = ROOT / "src/jmx_db.h"
API_C = ROOT / "src/jmx_dreamingwrt_api.c"
WEBD_C = ROOT / "src/webd/jmx_app_api.c"
FIXTURE = ROOT / "tests/client_stale_retention_fixture.c"

STALE_FN = "int jmx_db_client_row_stale(struct json_object *client, int64_t now,"
MAC_FN = "static int db_mac_is_locally_administered(const char *mac)"

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def take_block(source: str, start_marker: str) -> str:
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
                return source[start:i + 1]
    raise SystemExit(f"FAIL: unbalanced braces after {start_marker!r}")


def build_unit(db_src: str) -> str:
    """The predicates plus the json helpers they call, all lifted verbatim."""
    return "\n".join([
        "#include <string.h>",
        "#include <stdio.h>",
        "#include <stdint.h>",
        "#include <json-c/json.h>",
        "",
        take_block(db_src, "static const char *json_s(struct json_object *o,"),
        "",
        take_block(db_src, "static int json_i(struct json_object *o,"),
        "",
        take_block(db_src, "static int64_t json_i64(struct json_object *o,"),
        "",
        take_block(db_src, STALE_FN),
        "",
        # Lifted verbatim too. It is static in the source, so the fixture reaches
        # it through a thin non-static wrapper rather than a reimplementation.
        take_block(db_src, MAC_FN),
        "",
        "int db_mac_is_locally_administered_probe(const char *mac)",
        "{",
        "    return db_mac_is_locally_administered(mac);",
        "}",
        "",
    ])


def parse_output(text: str) -> dict:
    rows: dict = {}
    for line in text.strip().splitlines():
        parts = line.split()
        if len(parts) < 2 or "=" not in parts[1]:
            continue
        rows[parts[0]] = parts[1].split("=", 1)[1]
    return rows


def json_c_flags() -> tuple[list[str], list[str]]:
    # Falling back to a bare -ljson-c left this test skipping on 31.6, where the
    # library exists in the staging_dir but not on the host link path. The
    # resolver finds it, so have_host_json_c() below now succeeds there and the
    # predicate is actually exercised.
    try:
        return apd_test_deps.split_package_flags("json-c")
    except AssertionError:
        return ([], ["-ljson-c"])


def have_host_json_c(cflags: list[str], libs: list[str]) -> bool:
    """Can this host compile and link a trivial json-c program?

    The build machine carries json-c only as a cross-compiled staging copy, with
    no host library to link against. Probing keeps that case an honest skip
    instead of a failure that looks like a defect in the code under test.
    """
    probe = "#include <json-c/json.h>\nint main(void){return json_object_new_object()?0:1;}\n"
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "probe.c"
        src.write_text(probe)
        cmd = (["cc"] + cflags + [str(src), "-o", str(Path(tmp) / "probe")] + libs)
        try:
            done = subprocess.run(cmd, capture_output=True, text=True)
        except OSError:
            return False
    return done.returncode == 0


def check_wiring(db_src: str, db_h: str, api_src: str, webd_src: str) -> None:
    # The retention has to be a named constant, not a number buried in a branch,
    # because acceptance criterion 2 asks for a stated retention.
    check("JMX_DB_CLIENT_STALE_RETENTION_DAYS" in db_h,
          "the retention constant is gone from src/jmx_db.h; the retention must "
          "stay stated in one place")
    check("#define JMX_DB_CLIENT_STALE_RETENTION_DAYS 7" in db_h,
          "retention is no longer the agreed 7 days; if this changed on purpose, "
          "update the handoff and this test together")

    start = db_src.find("struct json_object *jmx_db_api_clients_list(")
    check(start >= 0, "jmx_db_api_clients_list() not found")
    if start < 0:
        return
    listing = take_block(db_src, "struct json_object *jmx_db_api_clients_list(")

    check("jmx_db_client_row_stale(" in listing,
          "the client list no longer calls the tested predicate, so the API can "
          "drift away from the rules proven here")
    check('json_i(req, "include_stale", 0)' in listing,
          "include_stale is gone: history must stay reachable through an explicit "
          "parameter, not become unreachable")
    check("JMX_DB_CLIENT_STALE_RETENTION_SEC" in listing,
          "the list no longer reads the named retention constant")
    check('"stale_retention_sec"' in listing and '"capabilities"' in listing,
          "the response no longer self-describes the retention; acceptance "
          "criterion 2 requires it be readable from the API")
    check('"stale_hidden"' in listing,
          "the response no longer reports how many rows were hidden, which is "
          "what makes the filter diagnosable instead of mysterious")
    row = take_block(db_src, "static struct json_object *db_row_to_client(")
    check('"mac_randomized"' in row,
          "mac_randomized is gone from the client row; without it the UI cannot "
          "tell the user an unresolvable vendor is a randomized MAC, not an "
          "unknown intruder")
    # Only offline rows may be aged out. An online device must never disappear
    # because its stored last_seen lagged.
    check('!json_i(client, "online", 0)' in listing,
          "the filter is no longer restricted to offline rows: an online client "
          "could be dropped from the list")

    merge = take_block(api_src, "static struct json_object *dw_build_devices_from_client_db(")
    check('"include_stale"' in merge,
          "the topology merge path no longer requests the full history; aged-out "
          "rows would lose their stored identity when a device reappears")

    check("webd_query_get(req.query, \"include_stale\"" in webd_src,
          "?include_stale=1 is no longer parsed in webd, so the escape hatch is "
          "unreachable over HTTP")
    check('"clients_inventory_all"' in webd_src,
          "the filtered and unfiltered inventories no longer use separate cache "
          "keys, so one can be served in place of the other")


def main() -> None:
    db_src = DB_C.read_text()
    db_h = DB_H.read_text()

    check_wiring(db_src, db_h, API_C.read_text(), WEBD_C.read_text())

    cflags, libs = json_c_flags()
    if not have_host_json_c(cflags, libs):
        # The source-level wiring checks above still ran and still count; only the
        # runtime half is unavailable here. Say so rather than printing "ok".
        if failures:
            for item in failures:
                print("FAIL: " + item)
            sys.exit(1)
        print("SKIP: host has no linkable json-c, so the runtime predicate check "
              "did not run; the source wiring checks passed. Run this on a host "
              "with json-c (e.g. the workstation) for the full proof.")
        return

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        unit = tmpdir / "stale_under_test.c"
        unit.write_text(build_unit(db_src))
        binary = tmpdir / "stale_retention"
        compile_cmd = (["cc", "-std=gnu99", "-Wall", "-O1"] + cflags +
                       [str(unit), str(FIXTURE), "-o", str(binary)] + libs)
        built = subprocess.run(compile_cmd, capture_output=True, text=True)
        if built.returncode != 0:
            print("FAIL: could not compile the extracted retention predicate")
            print(built.stderr[-4000:])
            sys.exit(1)
        run = subprocess.run([str(binary)], capture_output=True, text=True,
                             timeout=30)
        if run.returncode != 0:
            print("FAIL: fixture exited " + str(run.returncode))
            print(run.stderr[-4000:])
            sys.exit(1)

    rows = parse_output(run.stdout)

    # Randomized-MAC detection. Acceptance could not resolve a vendor for any of
    # these four, and the reason is the locally-administered bit, not a gap in
    # the vendor database.
    for name, why in (
        ("mac_ea6a_reported",
         "ea:6a:9a:62:3d:96 has the locally-administered bit set and must be "
         "reported as randomized; this is the MAC the user asked about twice"),
        ("mac_30_222", "02:00:5e:a0:80:11 is a randomized MAC"),
        ("mac_30_199", "3e:64:a9:93:c5:f5 is a randomized MAC"),
        ("mac_30_199_alt", "02:00:00:00:00:99 is a randomized MAC"),
    ):
        check(rows.get(name) == "1", name + ": " + why)
    for name, why in (
        ("mac_real_oui_rpi",
         "b8:27:eb is a real OUI and must not be labelled randomized"),
        ("mac_real_oui_plain",
         "00:1a:2b is a real OUI and must not be labelled randomized"),
        ("mac_empty", "an empty MAC must not be labelled randomized"),
        ("mac_unparseable",
         "an unparseable MAC must not be labelled randomized rather than "
         "guessed from uninitialised memory"),
        ("mac_null", "a NULL MAC must not be labelled randomized"),
    ):
        check(rows.get(name) == "0", name + ": " + why)

    # Must be filtered out: the residue Acceptance measured.
    for name, why in (
        ("oldest_20_6_days",
         "the oldest entry Acceptance found (20.6 days) must leave the default "
         "list; this is the reported defect"),
        ("median_16_7_days",
         "the median entry (16.7 days) must leave the default list"),
        ("eight_days",
         "an offline row past the 7-day retention must be filtered"),
        ("just_outside_retention",
         "7.1 days is past retention and must be filtered"),
        ("no_last_seen",
         "a row with no usable last_seen was observed once and never resolved; "
         "treat it as stale"),
    ):
        check(rows.get(name) == "1", name + ": " + why)

    # Must survive: real devices, recent history, and anything the user touched.
    for name, why in (
        ("just_inside_retention",
         "6.9 days is inside retention and must stay visible"),
        ("exactly_at_retention",
         "exactly at the boundary must stay: the rule is strictly older than "
         "retention, so the window is inclusive"),
        ("recent_offline_22h",
         "Acceptance's most recent offline row (22.4h) is recent history the "
         "user still expects to see"),
        ("seen_minutes_ago",
         "a device seen minutes ago must never be filtered"),
        ("ancient_but_pinned",
         "a pinned device is there on purpose; removing it would look like data "
         "loss"),
        ("ancient_but_renamed",
         "a renamed device carries user intent and must survive"),
        ("ancient_but_noted",
         "a device with a note carries user intent and must survive"),
        ("no_last_seen_pinned",
         "user intent outranks a missing timestamp"),
        ("retention_disabled",
         "retention <= 0 must disable ageing entirely"),
        ("last_seen_in_future",
         "a last_seen in the future (NTP step) must not be treated as ancient"),
        ("null_row",
         "a NULL row must not be reported stale"),
    ):
        check(rows.get(name) == "0", name + ": " + why)

    if failures:
        for item in failures:
            print("FAIL: " + item)
        sys.exit(1)
    print("ok: " + str(len(rows)) +
          " retention verdicts match, and the list/webd wiring is in place")


if __name__ == "__main__":
    main()
