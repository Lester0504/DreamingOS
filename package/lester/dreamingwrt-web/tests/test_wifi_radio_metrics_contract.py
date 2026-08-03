#!/usr/bin/env python3
"""AP 射频指标字段对齐合同。

来源：todo/2026-08-02/Handoff/Backend-to-Front-ios-ap-gaps-status.md

后端确认 `noise_dbm` 与 `channel_utilization` 此前前端全都读不到：WebUI 只找
`noise` / `utilization`，而后端从未发过这两个名字。同时缺值原因现在是驱动的真话
（30.1 上的 qcawificfg80211 不支持 `iw survey dump`），必须按正常状态展示。

这里钉住三件事：读到了真实字段名、缺值走 null 而不是 0、原因文案不带告警语气。
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = (ROOT / "files/www/dreamingwrt/plugins/native/wifi-management.js").read_text(encoding="utf-8")
STYLE = (ROOT / "files/www/dreamingwrt/static/css/wifi-management.css").read_text(encoding="utf-8")


def field_line(name: str) -> str:
    for line in MODULE.split("\n"):
        if line.strip().startswith(f"{name}:"):
            return line
    raise AssertionError(f"radio field not found: {name}")


noise = field_line("noise")
assert "radio.noise_dbm" in noise, "noise must read the backend's noise_dbm"
assert "optionalNumber(" in noise, "a missing noise floor must stay null, not collapse to 0 dBm"

utilization = field_line("utilization")
for expected in ("radio.channel_utilization", "radio.channel_utilization_pct"):
    assert expected in utilization, f"utilization must read {expected}"
assert "optionalNumber(" in utilization, "a missing utilization must stay null, not render as 0%"

# 0..100 percent on both names; a 0..1 rescale would silently divide real values by 100.
assert "/ 100" not in utilization and "* 100" not in utilization, "utilization is already a 0..100 percent"

for reason in ("utilization_reason", "noise_reason", "tx_power_mode_reason"):
    field_line(reason)

for key in (
    "iw_survey_unsupported",
    "iw_survey_failed_or_unsupported",
    "iw_survey_current_frequency_unavailable",
    "channel_survey_not_reported",
    "noise_floor_not_reported_by_driver",
    "tx_power_mode_not_exposed_by_driver_or_uci",
):
    assert key in MODULE, f"driver reason not mapped to Chinese copy: {key}"

reasons = MODULE[MODULE.index("const RADIO_METRIC_REASONS") : MODULE.index("function radioMetricNote")]
for alarming in ("失败", "错误", "异常", "故障"):
    assert alarming not in reasons, f"driver reasons must not read as faults: {alarming}"

# The note only appears when the value is genuinely absent.
assert "radio.utilization === null ? radioMetricNote(radio.utilization_reason) : ''" in MODULE
assert "radio.noise === null ? radioMetricNote(radio.noise_reason) : ''" in MODULE

# tx_power_mode stays null by backend decision; the UI must not invent auto/manual.
assert "wifi_replace_null" not in MODULE
assert ".airview-kpi-note" in STYLE, "the reason note needs its own muted style"
assert "var(--wifi-muted)" in STYLE[STYLE.index(".airview-kpi-note"): STYLE.index(".airview-kpi-note") + 240], \
    "the reason note must be muted, not a warning colour"

print("ok: AP radio metrics read the real backend field names and report driver gaps as normal state")
