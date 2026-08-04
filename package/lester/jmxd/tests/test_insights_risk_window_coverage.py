#!/usr/bin/env python3
"""Risk buckets must be aggregated over the window, not a transportable page.

Guards two handoffs against the same endpoint:
  Acceptance-to-Backend-risk-aggregate-capped-at-76-rows-by-ubus-msglen.md
  Acceptance-to-Backend-insights-flows-summary-pagesize-ignored-items-always-empty.md

``audit_flows`` is capped at 76-144 rows by the ubus payload limit, so risk
buckets accumulated from those rows covered ~0.03% of a 300k-row window and
read zero for every level except "unknown". The fix aggregates per destination
host, since hosts are far fewer than flows and risk is decided per host. The
row caps themselves must stay put: they are measured against the transport
limit, and raising them would truncate replies instead.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API_C = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
WEBD_C = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")

failures = []


def check(cond: bool, message: str) -> None:
    if not cond:
        failures.append(message)


# ---- the row caps must not be "fixed" by raising them ---------------------
for name, value in (("DW_AUDIT_FLOWS_MAX_SAMPLE", 144),
                    ("DW_AUDIT_FLOWS_MAX_LIFECYCLE", 125),
                    ("DW_AUDIT_FLOWS_MAX_EVENT_LIFECYCLE", 76)):
    match = re.search(r"^#define\s+" + name + r"\s+(\d+)", API_C, re.M)
    check(match is not None, f"{name} not found")
    if match:
        check(int(match.group(1)) <= value,
              f"{name} was raised to {match.group(1)}; these caps are measured "
              f"against the ubus payload limit and raising them truncates replies")

# ---- the host rollup exists and reports its own coverage ------------------
check("dw_audit_api_flow_host_rollup" in API_C,
      "the host rollup handler is missing")
check('UBUS_METHOD("audit_flow_host_rollup"' in API_C,
      "audit_flow_host_rollup is not registered on ubus")

start = API_C.find("static struct json_object *dw_audit_api_flow_host_rollup")
end = API_C.find("static struct json_object *dw_audit_api_flow_top_summary", start)
rollup = API_C[start:end] if start >= 0 else ""
for field in ('"hosts"', '"returned"', '"truncated"', '"counted_flows"',
              '"window_rows"'):
    check(field in rollup,
          f"the rollup must publish {field} so the caller can state coverage")
check("GROUP BY h" in rollup, "the rollup must aggregate in SQL, not per row")
check("dw_audit_flow_external_predicate_sql()" in rollup,
      "the rollup must apply the same external-destination predicate as the "
      "row queries, or its counts will not match")
# The grouped expression has to match the host webd actually annotates.
check("NULLIF(destination_host,'')" in rollup and "NULLIF(host,'')" in rollup
      and "NULLIF(remote_ip,'')" in rollup and "NULLIF(destination_ip,'')" in rollup,
      "the rollup must group on the same host coalesce order webd looks up")

# ---- webd must consume it and label the scope honestly --------------------
check("webd_insights_fetch_flow_host_rollup(" in WEBD_C,
      "webd does not fetch the host rollup")
check('"window_rows_by_host"' in WEBD_C,
      "webd must report the window scope when the rollup succeeded")
check('"sampled_rows"' in WEBD_C,
      "webd must still report sampled scope when the rollup is unavailable")
check("risk_count_hosts_truncated" in WEBD_C,
      "webd must surface rollup truncation rather than undercounting silently")
# Falling back is what keeps a rollup failure from zeroing the buckets.
check("rollup_ok ? 1 : 0" in WEBD_C or "rollup_ok ? \"window_rows_by_host\"" in WEBD_C,
      "the window aggregate must be conditional on the rollup succeeding")

# ---- pageSize must no longer be silently discarded -----------------------
check("webd_insights_page_size_requested(" in WEBD_C,
      "the summary endpoint cannot tell an explicit pageSize from the default")
summary_start = WEBD_C.find("static struct json_object *webd_insights_flows_summary_response")
summary = WEBD_C[summary_start:summary_start + 1800] if summary_start >= 0 else ""
check("webd_insights_build_dataset(&q, 1000, 0, 1, 1)" not in summary,
      "the summary endpoint still hardcodes include_items=0 and page_size=1, so "
      "pageSize/page_size/limit are parsed and then discarded")
check("items_included" in summary,
      "the response must say whether items were serialized")

helper_start = WEBD_C.find("static int webd_insights_page_size_requested")
helper = WEBD_C[helper_start:helper_start + 900] if helper_start >= 0 else ""
for key in ('"pageSize"', '"page_size"', '"limit"'):
    check(key in helper,
          f"all three advertised parameter names must be honoured, missing {key}")
check("json_object_object_get(body" in helper,
      "the body form must be honoured too, not only the query string")

if failures:
    for item in failures:
        print("FAIL: " + item)
    raise SystemExit(1)
print("ok: insights risk aggregates cover the window and pageSize is honoured")
