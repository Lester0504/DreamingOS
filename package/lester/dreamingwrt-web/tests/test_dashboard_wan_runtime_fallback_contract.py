#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = (ROOT / "files/www/dreamingwrt/static/js/dashboard.js").read_text(encoding="utf-8")


def require(fragment: str, message: str) -> None:
    assert fragment in DASHBOARD, message


require("realtime.subscribe('wan.metrics'", "Dashboard must consume the WAN health plane")
require("function applyDashboardWanMetrics(data)", "WAN health updates need a local incremental handler")
require("wanHealthSamples", "valid latency must survive slower aggregate snapshots")
require("function deriveWanRatesFromCounters(payload)", "invalid fast samples need a real counter-delta fallback")
require("rate_source: 'frontend_counter_delta'", "derived rates must expose their source")
require("if (!throughputWanRows(data).length)", "invalid throughput payloads must not keep the fast plane fresh")
require("state.dashboard.lastThroughputAt = 0", "invalid throughput must yield to the counter fallback")
require("downBytes < previous.downBytes || upBytes < previous.upBytes", "counter resets must not create spikes")
require("elapsed < 0.2 || elapsed > 30", "counter deltas need a bounded sample interval")
require("positiveNumber(latest.latency, activeWan.latency", "monitor latency must fall back to current WAN health")
require("function mergeDashboardWanInputs(baseRows, liveRows)", "configured WAN runtime must merge with the Dashboard snapshot")
require("liveConnections > 0 || !(baseConnections > 0) ? liveConnections : baseConnections", "snapshot zero must not overwrite a valid configured WAN connection count")
require("connected_seconds: liveUptime > 0 ? liveUptime : baseUptime", "WAN2 connection time must survive an incomplete snapshot")
require('data-wan-runtime="connections"', "each WAN card needs an incremental connection-count slot")
require('data-wan-runtime="uptime"', "each WAN card needs an incremental connection-time slot")
require("if (connections && connections.textContent !== connectionsText) connections.textContent = connectionsText", "WAN realtime updates must patch the existing connection-count node")
throughput_merge = DASHBOARD[DASHBOARD.index("function mergeThroughputIntoLastModel"):DASHBOARD.index("function hasFreshThroughput")]
assert "connections:" not in throughput_merge, "dashboard.throughput must not own per-WAN connection counts"
require("appendWanRealtimePoints(data, { trustIncomingConnections: false })", "throughput chart points must reuse the current per-WAN count")
fresh_preservation = DASHBOARD[DASHBOARD.index("function preserveFreshThroughput"):DASHBOARD.index("function latestDashboardPoint")]
assert "connections:" not in fresh_preservation, "fresh rate preservation must not restore stale WAN connection counts"
require("!['clients', 'overview'].includes(name)", "the 5-second /network/wans runtime refresh must continue while WebSocket is active")
assert "!['clients', 'overview', 'wans'].includes(name)" not in DASHBOARD, "WebSocket zero counts must not freeze the initial /network/wans sample"
uptime_body = DASHBOARD[DASHBOARD.index("function trustedWanUptime"):DASHBOARD.index("function formatRate")]
assert "const limit = Number(systemUptime)" in uptime_body, "system uptime may only bound impossible WAN durations"
assert "candidates = [systemUptime" not in uptime_body, "WAN uptime must not borrow system uptime"

print("dashboard WAN runtime fallback contract: ok")
