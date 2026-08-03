#!/usr/bin/env python3
"""A vanished virtual interface must not stay reported as online.

Reported by Acceptance as P1 (user-visible: "these two devices, where are they
from?"). Root cause: IPv4 and IPv6 shared one `neigh_state` field, so a
long-lived IPv6 STALE entry overwrote the IPv4 FAILED one and `neigh_failed`
could never become true. FAILED was also dropped entirely by the scan loop.

These assertions read the real source so the defect cannot silently return.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
USER_C = ROOT / "src/jmx_user.c"
USER_H = ROOT / "src/jmx_user.h"
DB_C = ROOT / "src/jmx_db.c"

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def function_body(source: str, signature: str) -> str | None:
    start = source.find(signature)
    if start < 0:
        return None
    brace = source.find("{", start)
    if brace < 0:
        return None
    depth = 0
    for i in range(brace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[brace:i + 1]
    return None


def main() -> None:
    user_c = USER_C.read_text()
    user_h = USER_H.read_text()
    db_c = DB_C.read_text()

    # 1. The families must have separate storage.
    for field in ("neigh_state_v4", "neigh_state_v6", "bridge_fdb_present"):
        check(field in user_h,
              f"client_node_t is missing {field}; IPv4 and IPv6 evidence would "
              "keep overwriting each other")

    # 2. IPv6 must not clobber an IPv4 observation in the shared field.
    v6 = function_body(user_c, "static void client_set_ipv6_evidence(")
    check(v6 is not None, "client_set_ipv6_evidence() not found")
    if v6:
        check("neigh_state_v6" in v6,
              "IPv6 evidence does not record neigh_state_v6")
        check("neigh_state_v4[0]" in v6,
              "IPv6 evidence overwrites the shared neigh_state without checking "
              "whether IPv4 already spoke; this is the original ghost-client bug")

    v4 = function_body(user_c, "static void client_set_ipv4_evidence(")
    check(v4 is not None, "client_set_ipv4_evidence() not found")
    if v4:
        check("neigh_state_v4" in v4,
              "IPv4 evidence does not record neigh_state_v4")

    # 3. FAILED/INCOMPLETE must be recorded, not skipped.
    negative = function_body(user_c, "static int client_neigh_state_negative(")
    check(negative is not None,
          "client_neigh_state_negative() missing; negative neighbour evidence "
          "is still being discarded")
    if negative:
        check("FAILED" in negative and "INCOMPLETE" in negative,
              "negative-state helper must cover FAILED and INCOMPLETE")

    collect = function_body(user_c, "static void client_collect_ip_neigh(")
    check(collect is not None, "client_collect_ip_neigh() not found")
    if collect:
        check("client_neigh_state_negative" in collect,
              "the neighbour scan still drops FAILED/INCOMPLETE, so the offline "
              "fallback has no negative evidence to act on")
        # A failed address must never create a client node.
        neg_index = collect.find("client_neigh_state_negative(state)")
        add_index = collect.find("add_client_node")
        check(neg_index >= 0 and add_index >= 0 and neg_index < add_index,
              "FAILED handling must come before add_client_node() so an "
              "unreachable address cannot create a phantom client")

    # 4. STALE alone must not count as liveness.
    reachable = function_body(db_c, "static int db_client_neigh_reachable(")
    check(reachable is not None,
          "db_client_neigh_reachable() missing; STALE would still imply online")
    if reachable:
        check("STALE" not in reachable,
              "STALE must not be treated as a reachable state: a lingering IPv6 "
              "STALE entry is exactly what kept the ghosts online")
        check("REACHABLE" in reachable,
              "reachable helper lost REACHABLE")

    # 5. Bridge FDB cross-check exists and is read as binary records.
    fdb = function_body(user_c, "static int client_bridge_fdb_has_mac(")
    check(fdb is not None, "bridge FDB lookup is missing")
    if fdb:
        check("brforward" in fdb,
              "FDB lookup must read /sys/class/net/<br>/brforward")
        check("CLIENT_FDB_RECORD_LEN" in fdb or "16" in fdb,
              "FDB lookup must honour the 16-byte record layout")
        check("return -1" in fdb,
              "an unreadable bridge must report unknown, not absent")

    # 5b. The FDB walk must guarantee the LAN interface list is populated.
    # Found on live hardware: the cache was only refreshed as a side effect of
    # client_iface_is_lan(), so client_fdb_lookup() walked an empty list and
    # every client came back bridge_fdb_present=null / bridge_fdb_unreadable,
    # which silently disabled this whole check.
    lookup = function_body(user_c, "static int client_fdb_lookup(")
    check(lookup is not None, "client_fdb_lookup() not found")
    if lookup:
        check("client_iface_cache_ensure()" in lookup,
              "client_fdb_lookup() walks g_client_lan_ifaces without ensuring "
              "the cache is populated; on a fresh pass the list is empty and "
              "every client reports bridge_fdb_unreadable")
    ensure = function_body(user_c, "static void client_iface_cache_ensure(")
    check(ensure is not None,
          "client_iface_cache_ensure() missing; cache refresh must not depend on "
          "being a side effect of another function")
    if ensure:
        check("client_iface_cache_refresh()" in ensure and
              "CLIENT_IFACE_CACHE_TTL" in ensure,
              "the ensure helper must honour the existing TTL rather than "
              "refreshing on every single lookup")

    # 6. The online decision must consult the per-family fields, and absence
    #    from the FDB must not override real traffic.
    check("neigh_state_v4" in db_c and "neigh_state_v6" in db_c,
          "the online decision still reads only the shared neigh_state")
    check("not_in_bridge_fdb" in db_c,
          "no reason code for a client missing from the bridge FDB")
    ghost = re.search(
        r"if \(fdb_absent && !neigh_reachable &&[^)]*\)", db_c, re.S)
    check(ghost is not None,
          "the FDB check must also require no reachable neighbour state")
    if ghost:
        clause = ghost.group(0)
        for guard in ("tx_rate", "rx_rate", "connections"):
            check(guard in clause,
                  f"FDB-absence must not override live {guard}; a real client "
                  "with traffic would be wrongly marked offline")
    check("bridge_fdb_present == 0" in db_c,
          "FDB absence must be distinguished from 'could not read' (-1)")

    # 6b. The FDB answer must be obtained at read time. Found on live hardware:
    # client_node_t.bridge_fdb_present is only refreshed by the legacy scheduler
    # (DREAMINGWRT_CORE_LEGACY_SCHEDULER), which is disabled on 30.1, so reading
    # that field left every client at -1 and disabled the cross-check entirely
    # while still looking correct in the source.
    check("int client_bridge_fdb_present(const char *mac)" in user_c,
          "client_bridge_fdb_present() missing; response builders have no way to "
          "query the bridge without the disabled periodic refresh")
    check("client_bridge_fdb_present(" in db_c,
          "the online decision reads the cached bridge_fdb_present field, which "
          "nothing refreshes when the legacy scheduler is off; it must query the "
          "bridge at read time instead")

    # 7. online_source must stop claiming a live source once offline.
    # The decision now lives in jmx_db_client_online_verdict(); the guard must
    # be inside it, not in the JSON builder.
    verdict = function_body(db_c, "void jmx_db_client_online_verdict(")
    check(verdict is not None,
          "jmx_db_client_online_verdict() not found; the online decision must "
          "stay in one testable function")
    check(verdict is not None and re.search(
              r"\(online && ev->runtime_online_source &&", verdict) is not None,
          "online_source still echoes the runtime value while offline, which is "
          "how it kept reporting \"arp\" for clients that were gone")
    check(verdict is not None and "not_in_bridge_fdb" in verdict,
          "the FDB-absence reason must be produced by the verdict function")
    check("jmx_db_client_online_verdict(&evidence, &verdict)" in db_c,
          "db_row_to_client() must call the shared verdict function so the API "
          "cannot drift from the tested rules")

    if failures:
        for item in failures:
            print(f"FAIL: {item}")
        sys.exit(1)
    print("ok: ghost-client online evidence is per-family and FDB-crosschecked")


if __name__ == "__main__":
    main()
