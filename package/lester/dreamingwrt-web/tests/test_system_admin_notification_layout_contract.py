#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SYSTEM_JS = (ROOT / "files/www/dreamingwrt/plugins/native/system-settings.js").read_text(encoding="utf-8")
SYSTEM_CSS = (ROOT / "files/www/dreamingwrt/static/css/system-settings.css").read_text(encoding="utf-8")
NOTIFY_JS = (ROOT / "files/www/dreamingwrt/plugins/native/notification-push.js").read_text(encoding="utf-8")
NOTIFY_CSS = (ROOT / "files/www/dreamingwrt/static/css/notification-push.css").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


general = between(SYSTEM_JS, "function systemGeneralDemoPanel", "function systemGeneralLogsPanel")
assert 'class="system-general-card-grid"' in general
assert general.index("设备身份") < general.index("时间与同步")

logs = between(SYSTEM_JS, "function systemGeneralLogsPanel", "function systemGeneralTimePanel")
assert 'class="system-general-card-grid system-log-card-grid"' in logs
assert logs.index("本地日志记录") < logs.index("外部系统日志 (Syslog)")

admin = between(SYSTEM_JS, "function systemAdminPanel", "function systemAdminPolicyTile")
assert 'class="system-admin-ssh-quick-grid"' in admin
assert admin.index("启用 SSH 服务") < admin.index("监听端口") < admin.index("空闲超时")
assert 'data-system-field="admin.web_login_timeout_min"' in admin
assert "webTimeoutSupported ? '' : 'disabled'" in admin

# SSH 开关改用 systemAdvancedHeroCard（用户 pic-4/pic-5），旧的 systemAdminHeroCard
# 及其私有开关样式已删除，不允许再回到两种开关样式并存的状态。
assert "systemAdminHeroCard" not in SYSTEM_JS
assert "system-admin-hero-card" not in SYSTEM_CSS
assert "system-admin-master-switch" not in SYSTEM_CSS
assert "systemAdvancedHeroCard('启用 SSH 服务'" in admin

# 时间同步的三个开关一起改成开关卡片（用户第 15 条），不允许只换其中一个。
time_panel = between(SYSTEM_JS, "function systemGeneralTimePanel", "function systemFlashPanel")
assert time_panel.count("systemAdvancedHeroCard(") == 3
assert "systemIosSwitch('general.time_sync'" not in time_panel
assert 'class="system-advanced-hero-grid system-time-hero-grid"' in time_panel

# zram：两个字段等宽，且 select 只保留原生箭头（用户第 16 条 pic-9）。
assert "select-arrow" not in SYSTEM_JS
assert ".system-field-wrap.select-arrow::after" not in SYSTEM_CSS
assert 'content: "↕"' not in SYSTEM_CSS

assert "扫描二维码并输入动态验证码，请妥善保管密钥。" in SYSTEM_JS
assert "二维码负责发现路由器，设备身份和公钥由 App 提交" not in SYSTEM_JS

avatar = between(SYSTEM_JS, "async function onAvatarUpload", "function patchSystemSetting")
assert "'/api/v1/system/admin/avatar'" in avatar
assert "base64_content" in avatar
assert "avatarUrlFromResponse" in avatar
assert "admin.avatar_upload_data_url" not in avatar

payload = between(SYSTEM_JS, "function systemSettingsRequestPayload", "async function fetchJson")
assert "state.touchedFields.has('admin.new_password')" in payload
assert "else delete payload.admin" in payload
assert "delete payload.admins" in payload

assert ".system-general-card-grid" in SYSTEM_CSS
assert ".system-admin-ssh-quick-grid" in SYSTEM_CSS

render = between(NOTIFY_JS, "function render()", "function patchLiveSummary")
assert 'class="notification-push-page-header"' in render
# 控件收进表格工具栏、删掉手动刷新按钮（用户第 9 条）。轮询仍在，否则页面会变成静态快照。
assert "renderToolbar" not in NOTIFY_JS
assert "data-notify-refresh" not in NOTIFY_JS
assert "</nav></header>" in render
assert "notification-push-table-toolbar" in NOTIFY_JS
assert "dwrt-kit-expand-search notification-push-search" in NOTIFY_JS
assert "window.setInterval" in NOTIFY_JS

# 最近投递与当前策略合并为一张卡（用户第 7 条）。
overview = between(NOTIFY_JS, "function overviewPanel", "function recentMarkup")
assert overview.count("notification-overview-panel") == 1
assert "notification-overview-combined" in overview
assert "notification-overview-split" in overview
assert overview.index("最近投递") < overview.index("当前策略")

# 启用通知推送改为开关卡片（用户第 10 条 pic-5）。
settings = between(NOTIFY_JS, "function settingsPanel", "function overviewPanel")
assert "notification-master-card" in settings
assert 'class="notification-switch-field"><span><strong>启用通知推送' not in settings
assert ".notification-master-card" in NOTIFY_CSS
assert ".notification-overview-split" in NOTIFY_CSS

# icon() 的兜底图形此前未定义，未知名称会把字符串 undefined 画进 svg。
assert "bell: '<path" in NOTIFY_JS

assert ".notification-push-page-header" in NOTIFY_CSS
assert "contain: paint" in NOTIFY_CSS

print("ok: system admin payloads, SSH/time switch cards, zram fields, and notification toolbar/overview merge share the intended contract")
