#!/usr/bin/env python3
"""Guard the split insights endpoints and their per-card source gating."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text, webd_module_text, webd_function_text
WEBD_C = webd_dispatch_text()

failures = []


def check(cond: bool, message: str) -> None:
    if not cond:
        failures.append(message)


# ---- routes exist for all five cards -------------------------------
for route in (
    "/api/v1/insights/flows/summary",
    "/api/v1/insights/flows/top-apps",
    "/api/v1/insights/flows/top_apps",
    "/api/v1/insights/flows/top-destinations",
    "/api/v1/insights/flows/top_destinations",
    "/api/v1/insights/flows/risk",
    "/api/v1/insights/flows/activity",
):
    check(f'"{route}"' in WEBD_C, f"route {route} is not registered")

# ---- each card has a dedicated response builder --------------------
for fn in (
    "webd_insights_flows_top_apps_response",
    "webd_insights_flows_top_destinations_response",
    "webd_insights_flows_risk_response",
    "webd_insights_flows_activity_response",
):
    check(f"static struct json_object *{fn}(" in WEBD_C,
          f"{fn} is missing")

# ---- the dataset builder is part-gated, never silently full ---------
check("webd_insights_build_dataset(const struct webd_insights_query *q,\n"
      "                                                       int fetch_limit,\n"
      "                                                       int include_items,\n"
      "                                                       int page_number,\n"
      "                                                       int page_size,\n"
      "                                                       unsigned int parts)"
      in WEBD_C,
      "build_dataset does not accept a parts mask")
for caller in (
    "webd_insights_build_dataset(&q, fetch_limit, 1, q.page_number, q.page_size,\n"
    "                                       WEBD_INSIGHTS_PART_ALL);",
    "webd_insights_build_dataset(&q, 1000, wants_items ? 1 : 0,\n"
    "                                          wants_items ? q.page_number : 1,\n"
    "                                          page_size,\n"
    "                                          WEBD_INSIGHTS_PART_ALL);",
    "webd_insights_build_dataset(&q, 1000, 0, 1, 1, WEBD_INSIGHTS_PART_ALL);",
):
    check(caller in WEBD_C, f"caller is not part-gated:\n{caller}")

# ---- the split envelope carries the shared read-model fields ---------
for field in ('"source"', '"sample_age_ms"', '"stale"', '"partial_sources"', '"parts"'):
    check(field in WEBD_C,
          f"split envelope must carry {field}")

# ---- activity cache varies with the requested client/app matrix page ----
query_block = webd_module_text("api_insights_internal.h")
read_query = webd_function_text("api_insights_core.c", "webd_insights_read_query")
cache_key = webd_function_text("api_insights.c", "webd_insights_dataset_cache_key")
check("int matrix_offset;" in query_block and "int matrix_limit;" in query_block,
      "the normalized insights query must retain matrix pagination")
check('webd_query_get(req->query, "matrix_offset"' in read_query,
      "matrix_offset must be read from the query string")
check('webd_query_get(req->query, "matrix_limit"' in read_query,
      "matrix_limit must be read from the query string")
check("q->matrix_offset" in cache_key and "q->matrix_limit" in cache_key,
      "matrix offset and limit must participate in the insights cache key")

# ---- pruning keeps only the requested card keys ----------------------
check("webd_insights_dataset_keep_only(" in WEBD_C,
      "the keep-only pruner is missing")
for key in (
    "top_all_traffic_by_application",
    "top_all_count_by_destination",
    "top_all_named_count_by_destination",
    "all_count_by_risk",
    "risk_count_",
):
    check(key in WEBD_C, f"pruner must know about {key}")

if failures:
    for item in failures:
        print("FAIL: " + item)
    raise SystemExit(1)
print("ok: insights flows split API routes, gating, and envelope fields are wired")
