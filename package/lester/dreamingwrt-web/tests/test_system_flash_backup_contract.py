#!/usr/bin/env python3
"""备份 / 升级两页的结构与"不许兜底"契约。

用户要求：删掉「配置」Tab，Tab 改为「备份」「升级」；备份页保留下载、恢复、
恢复出厂三张卡，并补上定时备份与版本快照。

勘察后端后发现更严重的问题，这里一并守住：

1. `flash_backup_create` / `flash_backup_restore` / `flash_factory_reset` 这三个
   能力位后端**从来没有下发过**（`jmx_app_api.c` 的 capabilities 组装段里没有对应的
   `json_object_object_add`，全文 `grep -c "flash_backup"` 为 0），而三条路由都是通的。
   前端原先把"位缺失"当成"功能不存在"，于是把三个能用的按钮永久灰掉，还写了
   「后端尚未开放备份生成能力」这种与事实不符的说明。位缺失必须走真实证据判断，
   不能退化成否定。
2. `GET /flash/backups` 返回真实的存档列表（`backup_id`、`created_at`、`size_bytes`、
   `status` 与 manifest 里的 `source_version`），前端此前完全没有请求过它。
3. `restore_backup` 只要一个 finalized 的 `upload_id`，设备上已有的备份天然满足，
   所以恢复不该被 `flash_browser_upload` 一刀切挡住。
4. 定时备份后端确实没有合同，所以那张卡只能如实说明缺口，**不得渲染点了没反应的
   频率选择器与保存按钮**。
"""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
JS = (WWW / "plugins/native/system-settings.js").read_text(encoding="utf-8")
CSS = (WWW / "static/css/system-settings.css").read_text(encoding="utf-8")


def test_tabs_are_backup_and_upgrade() -> None:
    block = JS[JS.index("const SYSTEM_FLASH_TABS") : JS.index("const SYSTEM_ADVANCED_TABS")]
    ids = re.findall(r"id:\s*'([a-z]+)'", block)
    labels = re.findall(r"label:\s*'([^']+)'", block)
    assert ids == ["operations", "firmware"], ids
    assert labels == ["备份", "升级"], labels
    # 「配置」Tab 的面板函数必须彻底消失，不能只是不再挂上去
    assert "systemFlashConfigPanel" not in JS


def test_preserve_editor_moved_into_upgrade_instead_of_deleted() -> None:
    # preserve_config 是通的，而且决定 sysupgrade 保留什么，不能连功能一起删掉
    assert "function systemFlashPreserveCard()" in JS
    firmware = JS[JS.index("function systemFlashFirmwarePanel") : JS.index("function systemFlashActionCard")]
    assert "systemFlashPreserveCard()" in firmware
    assert "systemSignatureUpdateCard(data)" in firmware
    assert "system-flash-firmware-panel" in firmware


def test_backup_page_keeps_three_cards_and_drops_firmware() -> None:
    panel = JS[JS.index("function systemFlashOperationsPanel") : JS.index("function systemFlashFirmwarePanel")]
    assert "flash-create-backup" in panel
    assert "flash-restore-backup" in panel
    assert "flash-factory-reset" in panel
    # 固件与特征库已经搬到升级页
    assert "flash-sysupgrade" not in panel
    assert "systemSignatureUpdateCard" not in panel
    assert "systemFlashBackupArchiveCard()" in panel
    assert "systemFlashScheduleCard()" in panel


def test_backup_list_is_actually_consumed() -> None:
    assert "async function loadFlashBackups()" in JS
    assert "'/api/v1/system/flash/backups'" in JS
    loader = JS[JS.index("async function loadFlashBackups()") : JS.index("async function restoreFlashArchive")]
    # 列表字段必须来自后端真实返回，不能只显示"最近生成时间"
    for field in ("items", "created_at"):
        assert field in loader, field
    row = JS[JS.index("function systemFlashBackupRow") : JS.index("function systemFlashScheduleCard")]
    for field in ("source_version", "size_bytes", "download_url", "backup_id"):
        assert field in row, field


def test_restore_and_delete_hit_the_real_routes() -> None:
    restore = JS[JS.index("async function restoreFlashArchive") : JS.index("async function deleteFlashArchive")]
    assert "'/api/v1/system/flash/restore_backup'" in restore
    assert "upload_id: id" in restore, "restore_backup 只接受 upload_id，不接受 path"
    assert "restore-archive:" in restore, "破坏性动作必须两段确认"
    delete = JS[JS.index("async function deleteFlashArchive") : JS.index("async function loadFlashPreserveConfig")]
    assert "method: 'DELETE'" in delete
    assert "flash/backups/${encodeURIComponent(id)}" in delete
    assert "delete-archive:" in delete


def test_missing_capability_bit_is_not_treated_as_absent_feature() -> None:
    # 判据的形状可以演进（现在优先读 `flash/capabilities` 的规范名，旧位只作兜底），
    # 但"位缺失 != 功能不存在"这条语义必须保住。
    start = JS.index("function flashBackupCapability(")
    helper = JS[start : JS.index("function flashStatusMessage")]
    assert "flashCap(" in helper, (
        "备份能力必须先读 `flash/capabilities` 这个权威来源，而不是只看旧的 capabilities 位"
    )
    # 位为 false 才是否定；缺失时看真实探测结果
    assert "=== false" in helper
    assert "flashBackupsSupported" in helper
    panel = JS[JS.index("function systemFlashOperationsPanel") : JS.index("function systemFlashFirmwarePanel")]
    for name, canonical in (
        ("flash_backup_create", "create_backup"),
        ("flash_backup_restore", "restore_backup"),
        ("flash_factory_reset", "factory_reset"),
    ):
        assert f"flashBackupCapability('{name}'" in panel, name
        assert f"'{canonical}'" in panel, canonical
        assert f"flashCapability('{name}')" not in panel, name


def test_no_false_backend_unavailable_copy() -> None:
    # 这三句把"能力位没下发"说成"后端没这功能"，与源码事实相反
    for phrase in (
        "后端尚未开放备份生成能力",
        "当前后端未开放恢复出厂设置能力",
        "需要后端提供浏览器上传暂存合同后才能恢复。",
    ):
        assert phrase not in JS, phrase


def test_schedule_card_states_the_gap_without_fake_controls() -> None:
    card = JS[JS.index("function systemFlashScheduleCard()") : JS.index("function systemFlashActionCard")]
    assert "后端尚未提供定时备份合同" in card
    # 整张卡（缺口分支与合同就绪分支）都不得出现可交互控件：没有合同时任何控件都是假的，
    # 合同就绪时也只先如实展示后端回报的调度，写入路径要等 API 定稿再单独实现。
    for tag in ("<select", "<input", "<button", "data-system-action="):
        assert tag not in card, f"定时备份卡不得渲染 {tag}"
    # 必须有一个真实的"合同已就绪"分支，而不是永久写死缺口文案
    assert "backup_schedule" in card


def test_row_action_styles_exist() -> None:
    assert ".system-flash-backup-row-actions" in CSS
    assert ".system-flash-schedule-gap" in CSS


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("system flash backup contract: ok")
