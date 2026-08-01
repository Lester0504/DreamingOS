#!/usr/bin/env python3
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/main.c").read_text(encoding="utf-8")


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


body = function("void update_lan_ip")
for token in ("getifaddrs(&ifaddr)", "ifa->ifa_addr->sa_family != AF_INET",
              "address->sin_addr.s_addr", "netmask->sin_addr.s_addr",
              "freeifaddrs(ifaddr)"):
    assert token in body
for forbidden in ("exec_with_result_line", "system(", "popen(", "ifconfig",
                  "grep", "awk"):
    assert forbidden not in body
assert 'update_jmx_proc_u32_value("lan_ip", lan_ip)' in body
assert 'update_jmx_proc_u32_value("lan_mask", lan_mask)' in body

print("ok: U-15 core LAN address collection is structured and shell-free")
