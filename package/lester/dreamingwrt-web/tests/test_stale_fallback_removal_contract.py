#!/usr/bin/env python3
"""Contract tests for FS-01..FS-04.

Acceptance found four places where the UI claimed "the backend does not provide
this yet" for capabilities the backend actually implements. These tests lock in
the corrected behaviour: each page asks its own endpoint, trusts that endpoint's
own capabilities, and classifies failures by HTTP status instead of collapsing
every error into "not implemented".
"""

import gzip
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
POWER_PATH = WWW / "plugins/native/system-power.js"
USERS_PATH = WWW / "plugins/native/system-users.js"
GLOBAL_PATH = WWW / "plugins/native/global-config.js"
MENU_PATH = WWW / "static/menu/main.json"
POWER = POWER_PATH.read_text()
USERS = USERS_PATH.read_text()
GLOBAL = GLOBAL_PATH.read_text()

STATUS_CLASSES = ("404", "401", "403", "500")


def test_fs01_power_reads_its_own_endpoint_without_a_basic_pre_gate() -> None:
    assert "system_power_read" not in POWER
    assert "/api/v1/system/power" in POWER
    for status in STATUS_CLASSES:
        assert status in POWER, status
    assert "等待电源计划接口" not in POWER


def test_fs01_empty_schedule_list_is_an_empty_state_not_a_missing_contract() -> None:
    assert "尚未提供" not in POWER
    assert "尚未接入" not in POWER
    assert "暂无" in POWER


def test_fs02_directory_endpoints_are_requested_independently() -> None:
    assert "directoryAdvertised" not in USERS
    for endpoint in ("/api/v1/system/users", "/system/user-groups", "/system/user-roles"):
        assert endpoint in USERS, endpoint
    assert "directoryUnavailabilityMessage" in USERS
    assert "groupsError" in USERS
    assert "后端用户组协议尚未接入" not in USERS


def test_fs02_group_failures_are_classified_by_status() -> None:
    for status in STATUS_CLASSES:
        assert status in USERS, status
    assert "暂无用户组" in USERS


def test_fs03_radius_list_is_rendered_from_the_real_endpoint() -> None:
    assert "'/api/v1/services/radius'" in GLOBAL
    assert "applyRadius" in GLOBAL and "normalizeRadiusServer" in GLOBAL
    assert "radiusListMarkup" in GLOBAL
    assert "暂无 RADIUS 服务器" in GLOBAL
    assert "radius_write" not in GLOBAL
    assert "secret 脱敏" not in GLOBAL


def test_fs03_radius_secrets_stay_server_side() -> None:
    assert "secretRef" in GLOBAL
    assert "secret_ref" in GLOBAL
    assert "item.secret)" not in GLOBAL


def test_fs03_radius_fetch_is_wired_into_load_with_aligned_labels() -> None:
    assert "fetchResource('global-radius', ENDPOINTS.radius)" in GLOBAL
    assert "applyRadius(results[9])" in GLOBAL
    labels = GLOBAL.split("'列偏好', 'RADIUS'")
    assert len(labels) == 2, "failure label array must still end with RADIUS at index 9"
    assert "![1,3,4,8,9].includes(index)" in GLOBAL


def test_fs04_gateway_atomic_apply_no_longer_contradicts_the_backend() -> None:
    assert "后端尚未提供 Gateway 端口分配的原子应用合同" not in GLOBAL
    assert "后端尚未提供多端口 WAN 分配原子事务" not in GLOBAL
    assert "gatewayApplyExplanation" in GLOBAL


def test_fs04_capability_false_is_distinct_from_capability_unknown() -> None:
    assert "capabilitiesKnown" in GLOBAL
    assert "capabilityProbeError" in GLOBAL
    assert "当前设备报告不支持" in GLOBAL
    assert "端口能力读取失败" in GLOBAL
    assert "端口能力接口未实现" in GLOBAL


def test_fs04_confirm_and_rollback_prompts_are_preserved() -> None:
    assert "gateway_port_assignment_requires_confirm" in GLOBAL
    assert "自动回滚" in GLOBAL
    assert "确认应用" in GLOBAL
    assert "strictCap('gateway_port_assignment_atomic_apply')" in GLOBAL
    assert "confirm: true" in GLOBAL


def test_honest_backend_limits_are_left_untouched() -> None:
    assert "当前后端尚未提供 WAN 模式、优先级与权重的事务合同" in GLOBAL
    assert "WAN SLA 尚未提供完整列表与 CRUD 合同" in GLOBAL
    menu = json.loads(MENU_PATH.read_text())
    unavailable = []
    def walk(items):
        for item in items:
            if item.get("availability") == "unavailable":
                unavailable.append(item["label"])
            walk(item.get("children", []))
    walk(menu["items"])
    for label in ("网址浏览控制", "APP过滤", "终端联网控制"):
        assert label in unavailable, label


def test_touched_modules_bumped_their_cache_version() -> None:
    menu = json.loads(MENU_PATH.read_text())
    versions = {}
    def walk(items):
        for item in items:
            if item.get("module"):
                versions[item["module"]] = item.get("module_version", "")
            walk(item.get("children", []))
    walk(menu["items"])
    for module in ("native/global-config.js", "native/system-power.js", "native/system-users.js"):
        assert versions[module] in {"20260801-capability-truth-01", "20260802-ui-batch-01"}, module


def test_gzip_assets_match_sources() -> None:
    for source in (POWER_PATH, USERS_PATH, GLOBAL_PATH, MENU_PATH):
        compressed = Path(f"{source}.gz")
        assert compressed.is_file(), source.name
        with gzip.open(compressed, "rb") as stream:
            assert stream.read() == source.read_bytes(), source.name


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
    print(f"ok: {len(tests)} stale-fallback removal contracts")
