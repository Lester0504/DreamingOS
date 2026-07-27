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

admin = between(SYSTEM_JS, "function systemAdminPanel", "function systemAdminHeroCard")
assert 'class="system-admin-ssh-quick-grid"' in admin
assert admin.index("启用 SSH 服务") < admin.index("监听端口") < admin.index("空闲超时")
assert 'data-system-field="admin.web_login_timeout_min"' in admin
assert "webTimeoutSupported ? '' : 'disabled'" in admin

hero = between(SYSTEM_JS, "function systemAdminHeroCard", "function systemAdminPolicyTile")
assert "system-admin-master-switch" in hero
assert "system-admin-status-light" not in hero

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
assert "${renderToolbar()}</header>" in render
assert "${renderToolbar()}${contentMarkup()}" not in render
assert ".notification-push-page-header" in NOTIFY_CSS
assert "contain: paint" in NOTIFY_CSS

print("ok: system admin payloads, two-column cards, SSH quick row, and notification header share the intended contract")
