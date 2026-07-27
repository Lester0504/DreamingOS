#!/usr/bin/env python3
"""Keep the Dreaming OS display brand separate from legacy machine contracts."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"

DISPLAY_FILES = [
    ROOT / "Makefile",
    WWW / "index.html",
    WWW / "app/index.html",
    WWW / "login/index.html",
    WWW / "static/js/setup-welcome.js",
    WWW / "plugins/native/ai-assistant.js",
    WWW / "plugins/native/appearance-settings.js",
    WWW / "plugins/native/notification-push.js",
    WWW / "plugins/native/storage-file-services.js",
    WWW / "plugins/native/system-settings.js",
    WWW / "plugins/native/user-authentication.js",
    WWW / "plugins/native/wifi-management.js",
]


for path in DISPLAY_FILES:
    source = path.read_text(encoding="utf-8")
    source = source.replace("DreamingWrtNotify", "LEGACY_NOTIFY_ABI")
    assert "DreamingWrt" not in source, f"legacy display brand remains in {path}"
    assert "DreamingWRT" not in source, f"legacy display brand remains in {path}"

app = (WWW / "app/index.html").read_text(encoding="utf-8")
login = (WWW / "login/index.html").read_text(encoding="utf-8")
menu = (WWW / "static/menu/main.json").read_text(encoding="utf-8")
shell = (WWW / "static/js/menu-shell.js").read_text(encoding="utf-8")
notifications = (WWW / "static/js/notifications.js").read_text(encoding="utf-8")
dashboard = (WWW / "static/js/dashboard.js").read_text(encoding="utf-8")

assert "Dreaming OS 控制台" in app
assert "Dreaming OS 7.2-RC3 Build202607180016" in app
assert "/static/images/logo-wide.png?v=20260725-wide-01" in app
assert ROOT.joinpath("files/www/dreamingwrt/static/images/logo-wide.png").is_file()
assert "Dreaming OS 登录" in login
assert "Dreaming OS standalone console menu" in menu
assert "`Dreaming OS ${version} ${build}`" in shell

# Phase 1 changes display branding only. These old names remain machine contracts.
assert ROOT.joinpath("files/www/dreamingwrt").is_dir()
assert "dreamingwrt.web.accessToken" in login
assert "window.DreamingWrtNotify" in notifications
assert "dreamingwrt_version" in shell
assert "function displayBrandName(value)" in dashboard
assert "/^DreamingWrt$/i.test(text) ? 'Dreaming OS' : text" in dashboard

print("Dreaming OS frontend display-brand contract passed")
