#!/usr/bin/env python3
"""Runtime test for GET /api/v1/clients?with_apps=1.

The aggregation is extracted verbatim from src/webd/jmx_app_api.c and compiled
into a small fixture, so this runs the shipped code. Extraction rather than a
copy is deliberate: a copy would keep passing after the real function drifted.

Covers what a static check cannot: per-MAC bucketing, the 180s staleness cut
that must agree with dashboard/snapshot, case-insensitive MAC joining, the
per-client cap and its truncation report, and the difference between "no active
apps" and "the source is unavailable".
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text
FIXTURE = ROOT / "tests/client_active_apps_fixture.c"

# Region lifted into the fixture: from the rollup helpers up to the response
# wrapper, which needs the rest of webd and is covered by the contract test.
EXTRACT = (
    ("#define WEBD_CLIENT_APPS_MAX",
     "static struct json_object *webd_clients_finish"),
)

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def extract_under_test() -> str:
    source = webd_dispatch_text()
    chunks = []
    for start, end in EXTRACT:
        begin = source.find(start)
        if begin < 0:
            raise SystemExit(f"extraction anchor not found: {start!r}")
        stop = source.find(end, begin)
        if stop < 0:
            raise SystemExit(f"extraction end anchor not found: {end!r}")
        chunks.append(source[begin:stop])
    return "\n".join(chunks)


def json_c_flags() -> tuple[list[str], list[str]]:
    """Locate json-c: host package first, then the OpenWrt staging tree."""
    # The staging path is derived from this file's location rather than a
    # hard-coded /home/lester path, so the fixture is not tied to one host.
    return apd_test_deps.split_package_flags("json-c")


def build(workdir: Path) -> Path:
    (workdir / "client_active_apps_extracted.h").write_text(extract_under_test())
    shutil.copy(FIXTURE, workdir / "fixture.c")

    cflags, libs = json_c_flags()
    binary = workdir / "fixture"
    command = [
        os.environ.get("CC", "cc"),
        "-O1", "-Wall", "-Wextra", "-Wno-unused-parameter",
        "-Wno-unused-function",
        "-o", str(binary), str(workdir / "fixture.c"),
        f"-I{workdir}",
        *cflags, *libs,
    ]
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode != 0:
        raise SystemExit(f"fixture build failed:\n{result.stdout}\n{result.stderr}")
    noise = [line for line in result.stderr.splitlines() if "warning:" in line]
    check(not noise, f"extracted aggregation emits warnings: {noise}")
    return binary


HEADER = ("AppID  MAC                SrcIP            SrcPort  DstIP"
          "            DstPort  Proto  AppProto Drop  Host"
          "                             LastUpdate   URI\n")


def row(app_id: int, mac: str, last_update: int, host: str = "example.com") -> str:
    return (f"{app_id} {mac}  192.168.30.2     34658    111.132.40.45    443"
            f"      TCP    2        0     {host}    {last_update}    -\n")


def run(binary: Path, proc_file, macs: list[str]) -> dict:
    argument = str(proc_file) if proc_file is not None else "-"
    result = subprocess.run([str(binary), argument, *macs],
                            text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def clients_of(payload: dict) -> list:
    return payload.get("data", {}).get("clients", [])


def main() -> int:
    with tempfile.TemporaryDirectory() as raw:
        workdir = Path(raw)
        binary = build(workdir)
        now = int(time.time())

        # ---- bucketing, ordering and the MAC join -------------------------
        proc = workdir / "af_active_app"
        proc.write_text(
            HEADER
            + row(100000321, "bc:24:11:1c:9f:ec", now)
            + row(100000321, "bc:24:11:1c:9f:ec", now - 5)
            + row(100000048, "bc:24:11:1c:9f:ec", now - 10)
            # Uppercase in the source must still match a lowercase client.
            + row(100000777, "AA:BB:CC:DD:EE:FF", now - 2)
        )
        payload = run(binary, proc, ["bc:24:11:1c:9f:ec", "aa:bb:cc:dd:ee:ff",
                                     "de:ad:be:ef:00:01"])
        clients = clients_of(payload)
        check(len(clients) == 3, f"expected 3 clients, got {len(clients)}")

        first = clients[0]
        check(first.get("active_flow_count") == 3,
              f"flow count must sum every row for the MAC: {first.get('active_flow_count')}")
        check(first.get("active_app_count") == 2,
              f"app count must be distinct app ids: {first.get('active_app_count')}")
        apps = first.get("active_apps") or []
        check([a.get("id") for a in apps] == [100000321, 100000048],
              f"apps must be ordered by flow count: {[a.get('id') for a in apps]}")
        check(bool(apps) and apps[0].get("flows") == 2,
              "two rows sharing an app id must collapse into one entry")
        check(bool(apps) and apps[0].get("last_seen") == now,
              "last_seen must be the newest row for that app")
        # Odd ids resolve in the stub, even ids do not; the response must say which.
        check(bool(apps) and apps[0].get("name") == "app-100000321"
              and apps[0].get("name_source") == "signature_db",
              f"resolved app must carry its name and source: {apps[0] if apps else None}")
        check(len(apps) > 1 and apps[1].get("name") == ""
              and apps[1].get("name_source") == "app_id_only",
              "unresolved app must report app_id_only rather than a fake name")

        # ---- icon_url and host (Front-to-Backend-active-apps-icon-and-host) --
        # 100000321 is odd and not divisible by 3, so the stub gives it an icon;
        # the field must be present and carry it.
        check(bool(apps) and apps[0].get("icon_url") == "/static/images/logo/app-100000321.svg",
              f"resolved app must carry its icon_url: {apps[0].get('icon_url') if apps else None}")
        # Present even when unresolved, so the App can tell "no mapping" from
        # "this build does not send icons"; empty, never a placeholder path.
        check(len(apps) > 1 and apps[1].get("icon_url") == "",
              f"unresolved app must carry an empty icon_url: {apps[1].get('icon_url') if len(apps) > 1 else None}")
        check(all("icon_url" in a for a in apps),
              "icon_url must be present on every app entry")
        check(bool(apps) and apps[0].get("host") == "example.com",
              f"the newest flow's host must be emitted: {apps[0].get('host') if apps else None}")

        second = clients[1]
        check((second.get("active_apps") or [{}])[0].get("id") == 100000777,
              "an uppercase MAC in the source must join a lowercase client")

        third = clients[2]
        check(third.get("active_apps") == [],
              "a client with no rows must get an empty array, not null")
        check(third.get("active_app_count") == 0 and third.get("active_flow_count") == 0,
              "an idle client must report explicit zeros")

        meta = payload.get("meta", {})
        check(meta.get("with_apps") is True, "meta must declare with_apps")
        check(meta.get("active_apps_available") is True,
              "meta must report the source as available")
        check(meta.get("active_apps_rows") == 4,
              f"meta must report rows read: {meta.get('active_apps_rows')}")
        check(meta.get("active_apps_matched_clients") == 2,
              f"meta must report matched clients: {meta.get('active_apps_matched_clients')}")
        check(meta.get("active_apps_source") == "af_active_app",
              "meta must name the source")

        # ---- staleness cut must agree with dashboard/snapshot -------------
        stale = workdir / "stale"
        stale.write_text(HEADER
                         + row(100000001, "bc:24:11:1c:9f:ec", now - 181)
                         + row(100000003, "bc:24:11:1c:9f:ec", now - 179))
        payload = run(binary, stale, ["bc:24:11:1c:9f:ec"])
        apps = clients_of(payload)[0].get("active_apps") or []
        check([a.get("id") for a in apps] == [100000003],
              f"rows older than 180s must be dropped: {[a.get('id') for a in apps]}")

        # A future timestamp must not be discarded; clocks disagree and the row
        # is still current.
        future = workdir / "future"
        future.write_text(HEADER + row(100000005, "bc:24:11:1c:9f:ec", now + 600))
        payload = run(binary, future, ["bc:24:11:1c:9f:ec"])
        apps = clients_of(payload)[0].get("active_apps") or []
        check([a.get("id") for a in apps] == [100000005],
              "a row timestamped in the future must be kept, not treated as stale")

        # ---- host placeholder handling ------------------------------------
        # af_active_app writes "-" for an unresolved destination. That is a
        # placeholder, not a hostname, and shipping it would make the App render
        # "-" as the app's destination.
        placeholder = workdir / "placeholder"
        placeholder.write_text(HEADER
                               + row(100000007, "bc:24:11:1c:9f:ec", now, host="-"))
        payload = run(binary, placeholder, ["bc:24:11:1c:9f:ec"])
        apps = clients_of(payload)[0].get("active_apps") or []
        check(bool(apps) and apps[0].get("host") == "",
              f'an unresolved "-" host must be normalised to empty: {apps[0].get("host") if apps else None}')

        # A newer row without a host must not erase a destination already known
        # from an older row of the same app.
        keep_host = workdir / "keep_host"
        keep_host.write_text(HEADER
                             + row(100000009, "bc:24:11:1c:9f:ec", now - 20,
                                   host="cdn.example.net")
                             + row(100000009, "bc:24:11:1c:9f:ec", now, host="-"))
        payload = run(binary, keep_host, ["bc:24:11:1c:9f:ec"])
        apps = clients_of(payload)[0].get("active_apps") or []
        check(bool(apps) and apps[0].get("host") == "cdn.example.net",
              f"a placeholder row must not erase a known host: {apps[0].get('host') if apps else None}")

        # ---- per-client cap must be reported, not silent ------------------
        # The emitted list is capped, but the counts must describe the device,
        # not the response: the App displays active_app_count directly, so a
        # capped figure would tell the user a busy device has only 8 apps.
        many = workdir / "many"
        many.write_text(HEADER + "".join(
            row(100001000 + i, "bc:24:11:1c:9f:ec", now) for i in range(12)))
        payload = run(binary, many, ["bc:24:11:1c:9f:ec"])
        entry = clients_of(payload)[0]
        apps = entry.get("active_apps") or []
        check(len(apps) == 8, f"the emitted list should cap at 8: {len(apps)}")
        check(entry.get("active_apps_returned") == 8,
              f"apps_returned must state how many were emitted: {entry.get('active_apps_returned')}")
        check(entry.get("active_app_count") == 12,
              f"app_count must be the device's real distinct-app total: {entry.get('active_app_count')}")
        check(entry.get("active_apps_truncated") == 4,
              f"the dropped tail must be reported: {entry.get('active_apps_truncated')}")
        check(entry.get("active_flow_count") == 12,
              "flow count must still count every row, including capped ones")
        check(entry.get("active_app_count_is_floor") is None,
              "12 apps is well inside the tracking array; app_count must be exact")

        # Beyond the tracking array the count becomes a floor, and must say so
        # rather than quietly reporting a number that is too low.
        huge = workdir / "huge"
        huge.write_text(HEADER + "".join(
            row(100002000 + i, "bc:24:11:1c:9f:ec", now) for i in range(70)))
        payload = run(binary, huge, ["bc:24:11:1c:9f:ec"])
        entry = clients_of(payload)[0]
        check(len(entry.get("active_apps") or []) == 8,
              "the emitted list stays capped no matter how many apps there are")
        check(entry.get("active_app_count") == 64,
              f"app_count saturates at the tracking limit: {entry.get('active_app_count')}")
        check(entry.get("active_app_count_is_floor") is True,
              "past the tracking limit the count must be flagged as a floor")
        check(entry.get("active_flow_count") == 70,
              "every row still counts toward flow_count")

        # ---- header-only and malformed input ------------------------------
        empty = workdir / "empty"
        empty.write_text(HEADER)
        payload = run(binary, empty, ["bc:24:11:1c:9f:ec"])
        check(clients_of(payload)[0].get("active_apps") == [],
              "a header-only source means idle, not unavailable")
        check(clients_of(payload)[0].get("active_apps_returned") == 0,
              "an idle client must report apps_returned as zero, not omit it")
        check(payload.get("meta", {}).get("active_apps_available") is True,
              "a readable but empty source is still available")

        junk = workdir / "junk"
        junk.write_text(HEADER + "not a row at all\n"
                        + row(100000009, "bc:24:11:1c:9f:ec", now))
        payload = run(binary, junk, ["bc:24:11:1c:9f:ec"])
        apps = clients_of(payload)[0].get("active_apps") or []
        check([a.get("id") for a in apps] == [100000009],
              "an unparsable line must be skipped without losing the valid ones")

        # ---- source unavailable must be distinguishable from idle ---------
        payload = run(binary, None, ["bc:24:11:1c:9f:ec"])
        entry = clients_of(payload)[0]
        check(entry.get("active_apps") is None,
              "an unavailable source must not look like an empty app list")
        check(entry.get("active_apps_reason") == "af_active_app_unavailable",
              f"per-client reason missing: {entry.get('active_apps_reason')}")
        meta = payload.get("meta", {})
        check(meta.get("active_apps_available") is False,
              "meta must report the source as unavailable")
        check(meta.get("active_apps_source") == "unavailable",
              "meta source must say unavailable")

    if failures:
        print("FAIL")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("PASS test_client_active_apps_runtime")
    return 0


if __name__ == "__main__":
    sys.exit(main())
