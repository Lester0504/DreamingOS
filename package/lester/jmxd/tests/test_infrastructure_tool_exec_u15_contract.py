#!/usr/bin/env python3
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")


def function(name: str) -> str:
    match = re.search(rf"{re.escape(name)}\s*\([^;]*?\)\s*\{{", SOURCE, re.S)
    if not match:
        raise AssertionError(name)
    brace = SOURCE.index("{", match.start())
    depth = 0
    for index in range(brace, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[match.start():index + 1]
    raise AssertionError(name)


capture = function("static int dw_tool_capture")
assert "jmx_exec_capture(" in capture
for state in ("timed_out", "truncated", "term_signal", "exit_code"):
    assert f"result->{state}" in capture

bridge_links = function("static int dw_load_bridge_links")
assert "jmx_interface_name_valid(bridge, 1)" in bridge_links
assert "jmx_interface_name_valid(de->d_name, 1)" in bridge_links
assert "ifname_len >= sizeof(links[count].ifname)" in bridge_links
assert "strtol(raw, &end, 10)" in bridge_links

for name in ("static int dw_bridge_fdb_lookup_port",
             "static struct json_object *dw_infra_bridge_fdb_entries"):
    body = function(name)
    assert 'dw_command_path("brctl", brctl, sizeof(brctl))' in body
    assert '"showmacs", (char *)bridge, NULL' in body
    assert "dw_tool_capture(" in body
    assert "popen(" not in body

lldp = function("static struct json_object *dw_infra_lldp_raw_json")
assert 'dw_command_path("lldpcli", lldpcli, sizeof(lldpcli))' in lldp
assert '"show", "neighbors", "-f", "json", NULL' in lldp
assert "dw_tool_capture(" in lldp
assert "popen(" not in lldp

print("ok: U-15 infrastructure FDB and LLDP probes use bounded argv exec")
