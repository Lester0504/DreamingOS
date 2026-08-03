#!/usr/bin/env python3
"""Contract: GET /api/v1/clients?with_apps=1 wiring.

The aggregation itself is exercised by test_client_active_apps_runtime.py. This
covers the parts that live outside the extracted function: query parsing, the
permission entry, and the cache interaction.

The cache point is the one that would bite in production. The clients inventory
is cached and handed out as a shared reference, so merging into the cached
object would leak active_apps into later requests that never asked for it, and
would keep serving a stale app list for the cache lifetime.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "src/webd/jmx_app_api.c").read_text()
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text()

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def body(start: str, end: str) -> str:
    begin = API.index(start)
    return API[begin:API.index(end, begin)]


# ---- dispatch --------------------------------------------------------------
dispatch = body('else if (!strcmp(req.path, "/api/v1/clients")) {',
                'else if (!strcmp(req.path, "/api/v1/client_profile")')
check('webd_query_get(req.query, "with_apps"' in dispatch,
      "the clients route must read the with_apps query parameter")
check("webd_clients_response(&status, merge_apps)" in dispatch,
      "the parsed flag must reach webd_clients_response")
# Accepting only "1" would break any client sending true/yes.
for accepted in ('"1"', '"true"', '"yes"'):
    check(accepted in dispatch,
          f"with_apps should accept {accepted}")

# ---- cache safety ----------------------------------------------------------
finish = body("static struct json_object *webd_clients_finish",
              "static struct json_object *webd_clients_response")
check("webd_json_clone(resp)" in finish,
      "the merge must run on a private clone, not the shared cached object")
check("webd_clients_attach_apps(own)" in finish,
      "the merge must be applied to the clone")
check(re.search(r"if\s*\(!resp\s*\|\|\s*!with_apps\)\s*\n\s*return resp;", finish)
      is not None,
      "without with_apps the response must be returned untouched")
# A failed clone must not fall back to touching shared state at all: resp may be
# the cached object, so neither the merge nor an explanatory annotation may be
# written into it.
clone_failure = finish[finish.index("if (!own)"):finish.index("json_object_put(resp);")]
check("webd_clients_attach_apps" not in clone_failure,
      "a failed clone must not merge into the shared object anyway")
check("json_object_object_add" not in clone_failure
      and "webd_obj_add_str" not in clone_failure,
      "a failed clone must not annotate the possibly-cached response either")

response = body("static struct json_object *webd_clients_response",
                "static void webd_system_settings_scrub_sensitive")
check("jmx_cache_put_with_stale(\"clients_inventory\"" in response,
      "the plain inventory must still be what gets cached")
# Every return path that carries clients has to go through the merge wrapper,
# otherwise with_apps would silently do nothing on the cached or stale path.
returns = re.findall(r"return\s+webd_clients_finish\(([^,]+), with_apps\);", response)
check(sorted(returns) == ["cached", "response", "upstream"],
      f"all three client-bearing return paths must apply the merge, found {sorted(returns)}")

# ---- honest reporting ------------------------------------------------------
aggregate = body("static struct json_object *webd_client_apps_index",
                 "static struct json_object *webd_clients_finish")
check('"af_active_app_unavailable"' in aggregate,
      "an unreadable source must be reported, not passed off as no apps")
check("json_object_object_add(client, \"active_apps\", NULL)" in aggregate,
      "an unavailable source must yield null rather than an empty array")
check('"active_apps_truncated"' in aggregate,
      "the per-client cap must be reported when it bites")
# Counts must describe the device, not the response. The App renders
# active_app_count directly, so emitting the capped figure there would
# understate a busy device without any signal that it had been cut.
check('"apps_returned"' in aggregate,
      "the response must state how many apps it actually emitted")
check("WEBD_CLIENT_APPS_TRACK" in API,
      "tracking capacity must be separate from the emitted cap")
track = re.search(r"#define WEBD_CLIENT_APPS_TRACK\s+(\d+)", API)
emit = re.search(r"#define WEBD_CLIENT_APPS_MAX\s+(\d+)", API)
check(track is not None and emit is not None
      and int(track.group(1)) > int(emit.group(1)),
      "the tracking array must be larger than the emitted cap, or app_count "
      "would just restate the cap")
check('"app_count_is_floor"' in aggregate,
      "past the tracking limit app_count must be flagged as a floor, not "
      "silently reported as exact")
check(re.search(r'"app_count",\s*\n?\s*json_object_new_int\(buckets\[i\]\.app_count\)',
                aggregate) is not None,
      "app_count must come from the bucket total, not the emitted length")
check("WEBD_CLIENT_APPS_ACTIVE_WINDOW_S" in API,
      "the staleness window must be a named constant, not a literal")
# The window has to match get_dashboard_active_app's cut, or the two views of
# the same rows would disagree.
window = re.search(r"#define WEBD_CLIENT_APPS_ACTIVE_WINDOW_S\s+(\d+)", API)
check(window is not None and window.group(1) == "180",
      "the staleness window must stay at 180s to agree with dashboard/snapshot")

# ---- permissions -----------------------------------------------------------
# The permission table only lists paths needing elevation; GET /api/v1/clients
# is an ordinary observable read. with_apps widens that same read with data the
# dashboard already exposes, so it must not introduce a privileged entry that
# would silently gate an endpoint the App already relies on.
check('"/api/v1/clients"' not in PERMS,
      "with_apps must not add a privileged entry for GET /api/v1/clients")
check('"/api/v1/clients/"' not in PERMS
      or 'JMX_RISK_LOW' in PERMS[PERMS.index('"/api/v1/clients/"'):][:200],
      "the clients id subtree must not gain a write-grade requirement from this change")

if failures:
    print("FAIL")
    for item in failures:
        print(f"  - {item}")
    sys.exit(1)
print("PASS test_clients_with_apps_contract")
