#!/usr/bin/env python3
"""Contract: setup_status must name which field gates the console.

A configured device reports first_run=true, because `initialized` answers "did
the wizard run to completion" and the install path never runs the wizard. That
is intended. What was not intended is that the response published the old fields
and the new ones side by side with nothing saying which was authoritative, so
every consumer had to already know, and reading the wrong one produced a defect:

    frontend read initialized/wizard_required  ->  whole console replaced by the
                                                   first-run wizard on a device
                                                   whose own response said
                                                   setup_gate_required: false

This test pins the self-describing contract. It deliberately does NOT assert
that first_run flips on a configured device: the App's new-device contract
depends on the old meaning, and changing it is the user's call, not a bug fix.

What must hold: the gate field is named in the payload, the misleading fields
are listed as unusable for gating, and both survive on the unreadable-row path.
"""
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SETUP = (ROOT / "src/jmx_setup.c").read_text(encoding="utf-8")

start = SETUP.index("static void nc_setup_add_gate_contract(")
depth = 0
brace = SETUP.index("{", start)
contract = None
for pos in range(brace, len(SETUP)):
    if SETUP[pos] == "{":
        depth += 1
    elif SETUP[pos] == "}":
        depth -= 1
        if depth == 0:
            contract = SETUP[start:pos + 1]
            break
assert contract, "could not delimit nc_setup_add_gate_contract()"

# --- the authoritative field must be named, not implied --------------------

assert '"setup_gate_field"' in contract, (
    "the response must name the field that gates the console, so a consumer "
    "can discover it from the payload instead of from tribal knowledge"
)
assert '"setup_gate_required"' in contract, "the named gate field must exist"
assert '"usability_field"' in contract and '"config_ready"' in SETUP, (
    "the response must name the field answering 'is this device usable'"
)

# --- the misleading fields must be listed as unusable for gating ------------

assert '"gate_fields_deprecated"' in contract, (
    "the fields that must not gate the console have to be listed explicitly"
)
for field in ("first_run", "initialized", "wizard_required",
              "router_setup_initialized"):
    assert re.search(rf'json_object_new_string\("{field}"\)', contract), (
        f"{field} reports wizard completion only and must be listed in "
        "gate_fields_deprecated"
    )
assert '"gate_fields_deprecated_note"' in contract, (
    "the list needs a human-readable reason next to it"
)

# --- the old fields must keep their values ---------------------------------
# Flipping them is a product decision (the App's new-device contract), so a
# bug fix must not do it silently. first_run stays the negation of initialized.

assert 'json_object_object_add(d, "first_run", json_object_new_boolean(!initialized));' in SETUP, (
    "first_run must stay the negation of initialized; changing its meaning is "
    "the user's decision, not something a gate fix may do quietly"
)

# --- both publish paths must carry the contract ----------------------------
# The unreadable-row fallback is exactly when a consumer is most likely to
# guess wrong, so it must not be the path that omits the guidance.

assert SETUP.count("nc_setup_add_gate_contract(d,") >= 2, (
    "the gate contract must be published on both the normal and the "
    "unreadable-row path"
)

# --- can_reset_wizard must not regress -------------------------------------
# It was fixed once to be unconditionally true; an unfinished wizard with reset
# hidden leaves the UI with no way forward and no way back.

assert SETUP.count('json_object_object_add(d, "can_reset_wizard", json_object_new_boolean(1));') >= 2, (
    "can_reset_wizard must stay true on both paths"
)

print("ok: setup_status names its gate field and marks the legacy ones unusable")
