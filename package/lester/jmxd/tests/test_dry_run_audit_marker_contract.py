#!/usr/bin/env python3
"""A dry-run client action must stay distinguishable from a real one.

iOS uses `dry_run` as a safety preflight (it confirms the path works without
touching the device). If those preflights land in `api_audit_log` looking
exactly like real executions, a security review cannot tell whether a client
was ever actually blocked. Reported by Acceptance as a P1.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "src/webd/jmx_app_api.c"

# Every client action that can be invoked with dry_run=true.
DRY_RUN_ACTIONS = (
    ("client.block", "high"),
    ("client.unblock", "high"),
    ("client.rate_limit", "medium"),
    ("client.rate_limit_remove", "medium"),
    ("client.dhcp_reserve", "medium"),
    ("client.dhcp_release", "medium"),
    ("client.kick", "medium"),
)

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def main() -> None:
    source = API.read_text()

    helper = re.search(
        r"static void jmx_app_audit_log_dry_run\([^)]*\)\s*\{(.*?)\n\}",
        source, re.S)
    check(helper is not None,
          "jmx_app_audit_log_dry_run() helper is missing; dry-run marking has "
          "no single place to live")
    if helper:
        body = helper.group(1)
        # The marker must be driven by the flag, not hardcoded either way.
        check('"dry_run"' in body and '"applied"' in body,
              "helper must record dry_run vs applied, found: " + body.strip())
        check("dry_run ?" in body,
              "helper must branch on the dry_run flag rather than hardcode a "
              "result")

    for action, risk in DRY_RUN_ACTIONS:
        # Locate the audit call for this action, whichever form it uses.
        pattern = re.compile(
            r"jmx_app_audit_log(?:_dry_run|_full|_ex)?\([^;]*?\"" +
            re.escape(action) + r"\"[^;]*?;", re.S)
        calls = pattern.findall(source)
        check(len(calls) >= 1, f"no audit call found for {action}")
        for call in calls:
            check("dry_run" in call,
                  f"audit call for {action} does not carry the dry_run flag, "
                  f"so a preflight is indistinguishable from a real change: "
                  f"{' '.join(call.split())[:160]}")
            check(f'"{risk}"' in call,
                  f"audit call for {action} lost its risk level {risk}")

        # The bare form (before_hash/after_hash only) cannot carry a result
        # column, so it must not be used for these actions.
        bare = re.search(
            r"jmx_app_audit_log\(\"app\", \"\", \"" + re.escape(action) +
            r"\"[^;]*?\"\", \"\"\);", source, re.S)
        check(bare is None,
              f"{action} still uses the unmarked jmx_app_audit_log() form")

    # The kick path encodes which flush ran in before_hash; that evidence must
    # survive the change.
    kick = re.search(r"jmx_app_audit_log_full\([^;]*?\"client\.kick\"[^;]*?;",
                     source, re.S)
    check(kick is not None, "client.kick audit call not found in _full form")
    if kick:
        check("conntrack_only" in kick.group(0) and
              "conntrack_flush" in kick.group(0),
              "client.kick lost its conntrack flush-path evidence")

    # `kick` cannot actually deauthenticate a wireless station. The capability
    # must stay false with a reason so the App does not promise a disconnect.
    caps = re.search(
        r"static void webd_client_control_add_capabilities\([^)]*\)\s*\{(.*?)\n\}",
        source, re.S)
    check(caps is not None, "webd_client_control_add_capabilities() not found")
    if caps:
        body = caps.group(1)
        deauth = re.search(
            r'"client_deauth",\s*json_object_new_boolean\((\w+)\)', body)
        check(deauth is not None,
              "client_deauth capability is not published; the App cannot tell "
              "that kick does not disconnect wireless stations")
        if deauth:
            check(deauth.group(1) == "0",
                  "client_deauth must stay false until a real deauth dispatch "
                  f"exists, found: {deauth.group(1)}")
        check("client_deauth_reason" in body,
              "client_deauth must ship a reason alongside the false bit")

    if failures:
        for item in failures:
            print(f"FAIL: {item}")
        sys.exit(1)
    print("ok: dry-run client actions are audited with a distinguishable result")


if __name__ == "__main__":
    main()
