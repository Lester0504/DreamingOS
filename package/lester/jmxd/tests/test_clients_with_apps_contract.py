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
# Matched without pinning the argument count: webd_clients_response() has since
# grown include_stale, and a test that hardcodes the arity goes red on an
# unrelated signature change while saying nothing about the flag being plumbed.
check(re.search(r"webd_clients_response\(&status,\s*merge_apps\s*[,)]", dispatch)
      is not None,
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
# What matters is that the *unmerged* upstream object is what lands in the
# cache, not the literal key: include_stale needs its own entry, so the key is
# now a variable. Asserting the old literal only proved the key had not been
# renamed.
cache_put = "jmx_cache_put_with_stale(cache_key, upstream"
merge_return = "return webd_clients_finish(upstream, with_apps);"
check(cache_put in response,
      "the plain inventory must still be what gets cached")
# The merge happens in webd_clients_finish, strictly after the cache write, so
# nothing merged can reach the cache.
check(cache_put in response and merge_return in response
      and response.index(cache_put) < response.index(merge_return),
      "the cache write must precede the merge, or active_apps would be cached")
# Filtered and full-history inventories are different answers under one name
# would serve whichever request warmed the cache first.
keys = set(re.findall(r'"(clients_inventory[a-z_]*)"', response))
check(keys == {"clients_inventory", "clients_inventory_all"},
      f"the two inventory variants need distinct cache keys, found {sorted(keys)}")
check(re.search(r"cache_key\s*=\s*include_stale\s*\?", response) is not None,
      "the cache key must be selected by include_stale, not shared")
# Both the read and the write have to use the selected key; a literal on either
# side would cross the two variants back over each other.
check(re.search(r'jmx_cache_get_allow_stale\(\s*\n?\s*cache_key', response)
      is not None,
      "the cache read must use the same selected key as the write")
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

# ---- per-app fields the App consumes --------------------------------------
# Front-to-Backend-active-apps-icon-and-host: without icon_url the App has to
# resolve every icon over separate signature requests, and without host it has
# to query visit history to answer "what is this app talking to".
check('webd_obj_add_str(app, "icon_url", icon_url)' in aggregate,
      "each app entry must carry icon_url so the App needs no extra request")
check("icon_url, sizeof(icon_url)" in aggregate,
      "icon_url must come from the signature-DB lookup, not be invented here")
# Unconditional: an omitted field cannot be told apart from a build that never
# sent icons, whereas "" unambiguously means no mapping in the signature DB.
check(re.search(r'if\s*\([^)]*icon_url\[0\][^)]*\)\s*\n\s*webd_obj_add_str\(app, "icon_url"',
                aggregate) is None,
      "icon_url must be emitted unconditionally, empty when there is no mapping")
check('webd_obj_add_str(app, "host", buckets[i].apps[j].host)' in aggregate,
      "each app entry must carry the destination host parsed from af_active_app")
# The Host column is "-" when the kernel has no resolved name; shipping that
# placeholder as a hostname would make the App render "-" as a destination.
note = body("static void webd_client_apps_note",
            "static struct json_object *webd_client_apps_index")
check('strcmp(host, "-")' in note,
      'the af_active_app "-" placeholder must be normalised to an empty host')
check("host" in re.search(r"struct webd_client_app_row\s*\{[^}]*\}", API,
                          re.S).group(0),
      "the per-app row must retain a host field for the newest flow")

# ---- permissions -----------------------------------------------------------
# The permission table only lists paths needing elevation; GET /api/v1/clients
# is an ordinary observable read. with_apps widens that same read with data the
# dashboard already exposes, so it must not introduce a privileged entry that
# would silently gate an endpoint the App already relies on.
# Read the table rows rather than grepping the whole file: "/api/v1/clients/"
# also appears in a comment and in route_is_client_identity_patch()'s prefix
# constant, so a source-wide search reports entries that do not exist.
table = PERMS[PERMS.index("g_route_risks[] = {"):]
table = table[:table.index("\n};")]
rows = [(m.group(1), m.group(2), m.group(3))
        for m in re.finditer(r'\{\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*(JMX_RISK_\w+)',
                             table)]
check(len(rows) > 50,
      f"the permission table failed to parse, only {len(rows)} rows found")


def matching_rows(path: str, method: str) -> list[tuple[str, str, str]]:
    """First-match lookup mirroring jmx_perm_route_risk/route_prefix_matches."""
    out = []
    for prefix, methods, risk in rows:
        if prefix.endswith("/"):
            hit = path.startswith(prefix)
        else:
            hit = path == prefix or path.startswith(prefix + "/")
        if hit and method in methods.split(","):
            out.append((prefix, methods, risk))
    return out


# GET /api/v1/clients is an ordinary observable read. with_apps widens that same
# read with data the dashboard already exposes, so it must not acquire a
# privileged entry that would silently gate an endpoint the App already uses.
hits = matching_rows("/api/v1/clients", "GET")
check(hits == [],
      f"with_apps must not add a privileged entry for GET /api/v1/clients, found {hits}")
# A subtree row ending in "/clients/" would also swallow
# /api/v1/clients/{mac}/wan-policy, which is traffic policy rather than
# presentation; the table documents that these stay exact paths on purpose.
subtree = [r for r in rows if r[0] in ("/api/v1/clients", "/api/v1/clients/")]
check(subtree == [],
      f"the clients id subtree must stay out of the table as exact paths, found {subtree}")
# And the read must not be reachable through a shorter ancestor row either.
for probe in ("/api/v1/clients", "/api/v1/clients/aa:bb:cc:dd:ee:ff"):
    bad = [r for r in matching_rows(probe, "GET") if r[2] != "JMX_RISK_LOW"]
    check(bad == [],
          f"GET {probe} must not require above-LOW risk, found {bad}")

if failures:
    print("FAIL")
    for item in failures:
        print(f"  - {item}")
    sys.exit(1)
print("PASS test_clients_with_apps_contract")
