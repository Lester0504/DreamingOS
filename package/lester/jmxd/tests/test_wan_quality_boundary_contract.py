#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" if (ROOT / "src").is_dir() else ROOT
HEALTHD = (SRC / "healthd/check_main.c").read_text(encoding="utf-8")
ROUTED = (SRC / "routed/jmx_route.c").read_text(encoding="utf-8")


def function(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for pos in range(brace, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[start:pos + 1]
    raise AssertionError(f"unterminated function: {signature}")


gateway = function(HEALTHD, "static int health_gateway_for_device(")
probe = function(HEALTHD, "static void health_probe_wan(")
publish = function(HEALTHD, "static void health_write_wan_status(")
level = function(ROUTED, "static uint8_t route_health_level_for(")

# Prefer a normal default-route gateway, but support PPPoE peers represented
# only by an UP+HOST route in /proc/net/route.
assert "destination == 0 && gateway != 0 && (flags & 0x2)" in gateway
assert "destination != 0 && gateway == 0" in gateway
assert "(flags & 0x1) && (flags & 0x4)" in gateway
assert "peer.s_addr = (uint32_t)destination" in gateway
assert gateway.index("destination == 0") < gateway.index("peer.s_addr")

# Missing RTT is unknown, not a synthetic 999ms measurement. A WAN can have a
# successful HTTP or gateway probe while its ICMP target refuses every packet.
assert "wan->latency_ms = -1;" in probe
assert "loss < 100 ? 1 : -1" in probe
assert "wan->latency_ms = 999;" not in probe
assert "loss < 100 ? 1 : 999" not in probe

# The compatibility loss field feeds line_health and the dashboard. It must be
# real forwarding loss, while the sparse ICMP sample remains separately named.
assert "forwarding_loss_pct" in publish
assert "wans[i].up_loss_pct" in publish
assert "wans[i].down_loss_pct" in publish
assert '"probe_loss=%d' in publish
loss_arguments = publish[publish.index('"target=%s reason=%s\\n"'):]
assert "forwarding_loss_pct" in loss_arguments
assert loss_arguments.index("forwarding_loss_pct") < loss_arguments.index("wans[i].probe_loss_pct")

# Probe disagreement remains visible as a reason, but cannot lower a WAN's
# weight without a measured loss/latency/jitter threshold being crossed.
assert 'strcmp(s->reason, "partial_probe_fail")' not in level
assert "s->probe_loss_pct" not in level
assert 'strcmp(s->reason, "unstable")' not in level
assert 'strcmp(s->reason, "all_probes_failed")' in level
assert "real_loss > 2.0" in level
assert "real_loss > 15.0" in level
assert "real_loss >= 40.0" in level
assert "s->latency_ms >= 180" in level
assert "s->jitter_over_80_pct > 0" in level
assert "s->jitter_over_80_pct > 30" in level

print("ok: PPPoE gateway fallback and quantitative WAN penalty boundary")
