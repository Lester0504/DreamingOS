#!/usr/bin/env python3
"""Contract: POST /api/v1/clients/{mac}/actions with action=kick must not report
more than it achieved.

Acceptance found the previous behaviour reported ok:true / status:"applied" for
every client while only flushing conntrack. A wireless station keeps its
association and resumes immediately, so for Wi-Fi devices that was a partial
effect described as a complete one.

Only the AP holding the association can deauthenticate, and dreamingwrt.ac
reports ap_actions:false, so the honest fix is to describe the real effect
rather than to fake a disconnect. This test pins the wording so it cannot drift
back.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "src/webd/jmx_app_api.c").read_text()

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def kick_branch() -> str:
    start = API.index('} else if (!strcmp(action, "kick")) {')
    end = API.index('"unsupported_action"', start)
    return API[start:end]


branch = kick_branch()

# The branch must decide wired vs wireless before claiming anything.
check('"link_type"' in branch,
      "kick must read link_type so it can tell a wired client from a station")
check(re.search(r"int\s+wireless\s*=", branch) is not None,
      "kick must derive a wireless flag rather than assuming one link type")

# is_wired must not be trusted. It is a persisted identity column that
# identityd never populates: verified read-only on 30.1, where all 25 clients
# report is_wired=false including ones sitting on eth0. Using it would classify
# every wired client as wireless.
check('"is_wired"' not in branch,
      "kick must not use is_wired; it is unpopulated and reads false for wired clients")

# link_type alone is not enough either: its collector defaults to "wired" when
# it has no evidence, so a station behind a managed AP could be reported as
# wired. A corroborating switch port is required.
check(re.search(r'wired_link\s*=.*link_type.*"wired"', branch, re.S) is not None,
      "the wired decision must be based on link_type")
check("port_buf[0]" in branch,
      "the wired decision must be corroborated by a switch port, because "
      "link_type defaults to \"wired\" with no evidence")
check("ssid_buf[0]" in branch,
      "a client reporting an SSID must never be classified as wired")
check("wireless = !wired_link" in branch,
      "anything not provably wired must fall to the honest wireless wording")
check('"link_ownership_unknown"' in branch,
      "an unclassifiable link must be reported distinctly from a known station")
check('"link_evidence"' in branch,
      "the response must expose what the wired/wireless call was based on")

# A wireless client must not be told the action was fully applied.
check('"partially_applied"' in branch,
      "a wireless kick must report partially_applied, not applied")
check('"deauth_unsupported"' in branch,
      "a wireless kick must name why the station stays connected")
check('"disconnected"' in branch,
      "kick must state explicitly whether the client was disconnected")

# disconnected must never be asserted true: nothing in this path can disconnect
# a client, wired or wireless.
for match in re.finditer(r'"disconnected", json_object_new_boolean\((\w+)\)', branch):
    check(match.group(1) == "0",
          f"kick claims disconnected={match.group(1)}; no code path here can disconnect a client")

# The old wording claimed success unconditionally.
applied = re.findall(r'"status",\s*\n?\s*json_object_new_string\("applied"\)', branch)
check(len(applied) <= 1,
      "only the wired branch may report applied")
check("station stays associated" in branch,
      "the wireless note must say the station stays associated to its AP")

# The effect field lets the App show the right wording without parsing prose.
check('"effect"' in branch,
      "kick must expose a machine-readable effect field")
check('"conntrack_only"' in branch and '"conntrack_flush"' in branch,
      "effect must distinguish a conntrack-only result from a full flush")

# dry_run must not promise a disconnect either.
dry = branch[branch.index("dry_run"):]
check('"dry_run"' in dry, "dry_run must still be reported as dry_run")

# The audit trail should record which effect was actually attempted.
check(re.search(r'jmx_app_audit_log\("app", "", "client\.kick", "medium", mac_buf,\s*\n?\s*wireless \?', branch)
      is not None,
      "the audit entry must record the effect, not a bare success")

if failures:
    print("FAIL")
    for item in failures:
        print(f"  - {item}")
    sys.exit(1)
print("PASS test_client_kick_honesty_contract")
