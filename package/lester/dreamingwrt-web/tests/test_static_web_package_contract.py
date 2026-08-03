#!/usr/bin/env python3
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ROOT.parent
WEB_MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
JMXD_MAKEFILE = (PACKAGES / "jmxd" / "Makefile").read_text(encoding="utf-8")
WWW = ROOT / "files" / "www" / "dreamingwrt"
SHELL = (WWW / "static/js/menu-shell.js").read_text(encoding="utf-8")


for relative in (
    "index.html",
    "app/index.html",
    "login/index.html",
    "static/js/menu-shell.js",
    "static/js/page-glass-map-worker.js",
):
    path = WWW / relative
    assert path.is_file() and path.stat().st_size > 0, relative

for relative in (
    "app/index.html",
    "login/index.html",
    "static/js/menu-shell.js",
    "static/js/page-glass-map-worker.js",
    "static/js/shell-prewarm.js",
    "static/ui-kit/dwrt-sampled-liquid-glass.js",
):
    source = WWW / relative
    compressed = source.with_name(source.name + ".gz")
    assert compressed.is_file() and compressed.stat().st_size > 0, f"missing gzip: {relative}"

webd_start = JMXD_MAKEFILE.index("define Package/dreamingwrt-webd\n")
webd_end = JMXD_MAKEFILE.index("endef", webd_start)
webd = JMXD_MAKEFILE[webd_start:webd_end]
assert "+dreamingwrt-web" in webd

web_start = WEB_MAKEFILE.index("define Package/dreamingwrt-web\n")
web_end = WEB_MAKEFILE.index("endef", web_start)
web = WEB_MAKEFILE[web_start:web_end]
assert "+jmxd" not in web
assert "$(RM) -r $(1)/www/dreamingwrt/.playwright-cli" in WEB_MAKEFILE
assert "$(1)/www/dreamingwrt/output" in WEB_MAKEFILE

menu = json.loads((WWW / "static/menu/main.json").read_text(encoding="utf-8"))
assert all(item.get("id") != "ai" and item.get("func_name") != "ai" for item in menu["items"])
assert all(item.get("id") != "container-service" and item.get("func_name") != "container_service" for item in menu["items"])
assert "container_service" in menu["hideFuncs"]
network = next(item for item in menu["items"] if item.get("id") == "network-config")
assert all(item.get("id") != "network-control" for item in network["children"])
assert "/app/#/network/network-control" in menu["hidePages"]
assert "control" not in menu["hideFuncs"]
authentication = next(item for item in menu["items"] if item.get("id") == "user-authentication")
assert authentication["label"] == "认证与管控"
assert authentication["override_runtime_label"] is True
authentication_children = {item.get("id"): item for item in authentication["children"]}
for child_id in (
    "authentication-web-access-control",
    "authentication-app-filter",
    "authentication-client-network-control",
):
    assert authentication_children[child_id]["availability"] == "unavailable"
    assert authentication_children[child_id]["capability"]
    assert authentication_children[child_id]["unavailable_reason"]
client_speed_limit = authentication_children["authentication-client-speed-limit"]
assert client_speed_limit["availability"] == "available"
assert client_speed_limit["frontend_owned"] is True
assert client_speed_limit["module"] == "native/client-speed-limit.js"
assert client_speed_limit["style"] == "/static/css/user-authentication.css"
assert (WWW / "plugins/native/client-speed-limit.js").is_file()
network_children = {item.get("id"): item for item in network["children"]}
assert network_children["bulk-ip"]["label"] == "IP 地址管理"
assert network_children["bulk-ip"]["availability"] == "available"
assert network_children["bulk-ip"]["frontend_owned"] is True
assert network_children["bulk-ip"]["module"] == "native/ip-address-management.js"
assert network_children["bulk-ip"]["style"] == "/static/css/ip-address-management.css"
assert (WWW / "plugins/native/ip-address-management.js").is_file()
assert not {"flow-control", "advanced-routing", "custom-config", "firewall"} & set(network_children)
for old_route, new_route in {
    "#/network/firewall": "#/policy-engine/table",
    "#/network/custom-config": "#/policy-engine/objects",
    "#/network/advanced-routing": "#/policy-engine/routes",
    "#/network/flow-control": "#/policy-engine/flow-engine",
}.items():
    assert old_route in SHELL and new_route in SHELL
native_plugins = next(item for item in menu["items"] if item.get("id") == "native-plugins")
native_children = {item.get("id"): item for item in native_plugins["children"]}
assert "native-plugins-index" not in native_children
assert list(native_children).index("container-docker") < list(native_children).index("container-lxc")
for container_id in ("container-docker", "container-lxc"):
    assert native_children[container_id]["module"] == "native/container-service.js"
    assert native_children[container_id]["style"] == "/static/css/container-service.css"
    assert native_children[container_id]["frontend_owned"] is True
system = next(item for item in menu["items"] if item.get("id") == "system")
llm = next(item for item in system["children"] if item.get("id") == "system-llm-settings")
assert llm["label"] == "LLM 接入设置"
assert llm["path"] == "/app/#/system/llm-settings"
assert llm["module"] == "native/ai-assistant.js"
assert llm["style"] == "/static/css/ai-assistant.css"
assert llm["frontend_owned"] is True
power = next(item for item in system["children"] if item.get("id") == "system-power")
assert power["path"] == "/app/#/system/power"
assert power["module"] == "native/system-power.js"
assert power["style"] == "/static/css/system-power.css"
assert power["frontend_owned"] is True
assert (WWW / "plugins/native/system-power.js").is_file()
assert (WWW / "static/css/system-power.css").is_file()
terminal = next(item for item in system["children"] if item.get("id") == "system-terminal")
assert terminal["path"] == "/app/#/system/terminal"
assert terminal["module"] == "native/system-terminal.js"
assert terminal["module_version"] == "20260722-overlay-01"
assert terminal["style"] == "/static/css/system-terminal.css"
assert terminal["icon"] == "system_terminal"
assert terminal["frontend_owned"] is True
assert (WWW / "plugins/native/system-terminal.js").is_file()
assert (WWW / "static/css/system-terminal.css").is_file()
logs = next(item for item in menu["items"] if item.get("id") == "log-center")
assert logs["module"] == "native/log-center.js"
assert logs["module_version"] == "20260802-ui-batch-01"
assert logs["style"] == "/static/css/log-center.css"
assert logs["style_version"] == "20260802-ui-batch-01"
assert logs["frontend_owned"] is True
assert (WWW / "plugins/native/log-center.js").is_file()
assert (WWW / "static/js/log-center.js").is_file()
assert (WWW / "static/css/log-center.css").is_file()

shell = (WWW / "static/js/menu-shell.js").read_text(encoding="utf-8")
session_gate = (WWW / "static/js/dwrt-session-gate.js").read_text(encoding="utf-8")
app_html = (WWW / "app/index.html").read_text(encoding="utf-8")
ai_module = (WWW / "plugins/native/ai-assistant.js").read_text(encoding="utf-8")
ai_style = (WWW / "static/css/ai-assistant.css").read_text(encoding="utf-8")
container_module = (WWW / "plugins/native/container-service.js").read_text(encoding="utf-8")
network_interface_module = (WWW / "plugins/native/network-interface-config.js").read_text(encoding="utf-8")
system_module = (WWW / "plugins/native/system-settings.js").read_text(encoding="utf-8")
system_style = (WWW / "static/css/system-settings.css").read_text(encoding="utf-8")
ui_kit_style = (WWW / "static/ui-kit/dwrt-ui-kit.css").read_text(encoding="utf-8")
ui_kit_module = (WWW / "static/ui-kit/dwrt-ui-kit.js").read_text(encoding="utf-8")
control_material = (WWW / "static/ui-kit/dwrt-control-material.css").read_text(encoding="utf-8")
power_module = (WWW / "plugins/native/system-power.js").read_text(encoding="utf-8")
power_style = (WWW / "static/css/system-power.css").read_text(encoding="utf-8")
terminal_module = (WWW / "plugins/native/system-terminal.js").read_text(encoding="utf-8")
terminal_style = (WWW / "static/css/system-terminal.css").read_text(encoding="utf-8")
dashboard_module = (WWW / "static/js/dashboard.js").read_text(encoding="utf-8")
assert 'id="aiGlobalRoot"' in app_html
assert 'id="sessionRecovery"' in app_html
# 会话闸门的缓存键会随内容变更而 bump，断言里不写死版本号；真正要守的是
# app/index.html 与 shell-prewarm.js 引用同一个键，否则预热会拉到另一份文件。
_gate_re = re.compile(r"/static/js/dwrt-session-gate\.js\?v=([0-9a-z.-]+)")
_gate_app = _gate_re.findall(app_html)
_gate_prewarm = _gate_re.findall(
    (WWW / "static/js/shell-prewarm.js").read_text(encoding="utf-8")
)
assert _gate_app, "app/index.html 必须带版本号引用 dwrt-session-gate.js"
assert _gate_prewarm, "shell-prewarm.js 必须带版本号预热 dwrt-session-gate.js"
assert set(_gate_app) == set(_gate_prewarm), (
    f"会话闸门缓存键不一致: app={_gate_app} prewarm={_gate_prewarm}"
)
assert "class SessionGate" in session_gate
assert 'id="consolePageFooter"' in app_html
assert 'id="consolePageFooterVersion"' in app_html
assert "Dreaming OS 7.2-RC3 Build202607180016" in app_html
assert "mode: 'global-drawer'" in shell
assert "#/ai/assistant" in shell and "openGlobalAi()" in shell
assert "historyPageSize: 10" in ai_module
assert "dreamingwrt.ai.orb" in ai_module
assert "data-ai-add-page" in ai_module
assert "data-ai-add-file" in ai_module
assert "data-ai-runtime-toggle" in ai_module
assert "dreamingwrt.ai.activeConversation" in ai_module
assert "content === '/new'" in ai_module
assert "data.conversation_title" in ai_module
assert "data-ai-drawer-wallpaper-image" in ai_module
assert "data-ai-open-settings" not in ai_module
assert "auth_mode: firstText(data.auth_mode, 'api_key')" in ai_module
assert "data-ai-auth-mode=\"oauth\"" in ai_module
assert "'/api/v1/ai/oauth/status'" in ai_module
assert "'/api/v1/ai/oauth/start'" in ai_module
assert "'/api/v1/ai/oauth/poll'" in ai_module
assert "'/api/v1/ai/oauth/refresh'" in ai_module
assert "'/api/v1/ai/oauth/disconnect'" in ai_module
assert "poll_after_seconds" in ai_module
assert "verification_uri_complete" in ai_module
assert "identity_token_file" in ai_module
assert "federation_rule_id" in ai_module
assert "function credentialReady()" in ai_module
assert "if (state.sending || !credentialReady()) return;" in ai_module
assert "dwrt:ai-config-updated" in ai_module
assert "dwrt:ai-oauth-updated" in ai_module
assert "localStorage.setItem('dreamingwrt.ai.oauth" not in ai_module
assert 'sessionStorage.setItem("dreamingwrt.ai.oauth' not in ai_module
assert ".ai-auth-mode" in ai_style
assert ".ai-oauth-device-flow" in ai_style
assert ".ai-oauth-card" in ai_style
assert "tab: 'overview'" in container_module
assert "[['overview', '概览'], ['containers', '容器']" in container_module
assert "${toolbar()}<main" in container_module
assert "'container_service'" in shell
assert "'.dwrt-kit-tabs'" in shell
assert "'.container-service-overview .dwrt-kit-overview-card'" not in shell
assert "loadPageFooterRelease().catch(() => {})" in shell
assert "system.dreamingwrt_version" in shell and "system.build_date" in shell
assert "'.ai-settings-section'" in shell
assert "'.system-settings-route-host .system-demo-row'" in shell
assert ".ai-copilot-drawer" in ai_style
assert ".ai-floating-orb" in ai_style
assert ".ai-settings-section + .ai-settings-section" in ai_style
assert ".ai-settings-card" in ai_style and "overflow: visible" in ai_style
assert "dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface system-table-card" in system_module
assert "dwrt-kit-table dwrt-kit-ikuai-table system-startup-table-core" in system_module
assert "systemStatusBadge(running ? '运行中' : '已停止'" in system_module
assert "running\n              ? `${systemActionButton('重启'" in system_module
assert ": systemActionButton('启动'" in system_module
assert "system-status-pill" not in system_module
assert "system-cron-command-label" in system_module
assert ".system-cron-command-label" in system_style and "white-space: nowrap" in system_style
assert 'class="system-admin-chambers"' in system_module
assert "system-admin-account-chamber" in system_module and "system-admin-ssh-chamber" in system_module
assert "管理员与 SSH 远程访问" not in system_module
# SSH 总控改用与「高级」面板一致的开关卡片（systemAdvancedHeroCard），旧的 system-admin-hero-card
# 与自绘 master-switch 已删除；状态灯改由 .ok 类驱动，不再依赖 ssh.enabled 的 :has 联动。
assert "systemAdvancedHeroCard('启用 SSH 服务'" in system_module
assert "system-admin-master-switch" not in system_module and "system-admin-master-switch" not in system_style
assert ".system-admin-ssh-quick-grid" in system_style and ".system-admin-ssh-params" in system_style
assert ".system-admin-status-light.ok" in system_style
assert ".dwrt-kit-status-badge" in ui_kit_style
assert ".dwrt-kit-status-badge-dot" in ui_kit_style
assert ".dwrt-floating-savebar" in ui_kit_style
assert "function confirmationMarkup(options = {})" in ui_kit_module
assert "confirmationMarkup," in ui_kit_module
assert "function lucideIcon(name, options = {})" in ui_kit_module
assert "lucideIcon," in ui_kit_module and "mountLucide" in ui_kit_module
assert "mountLucide(context);" in ui_kit_module
assert "function mount(context = document)" in ui_kit_module
assert "function unmount(context)" in ui_kit_module
assert "observer.observe(document.documentElement" not in ui_kit_module
assert ".dwrt-kit-tabs.dwrt-page-liquid-glass" in control_material
assert ".dwrt-kit-confirmation" in ui_kit_style
assert ".dwrt-kit-confirmation-actions" in ui_kit_style
# 「计划」Tab 已经点明了表格内容，标题栏里的 <strong>重启计划</strong> 属于用户明确要求删除的重复复述；
# 现在标题栏只保留条数与「添加计划」动作。
assert "<strong>重启计划</strong>" not in power_module
assert "data-power-add" in power_module and "system-power-tab-actions" in power_module
assert "data-power-refresh" not in power_module
assert "由系统调度器执行" not in power_module
assert "system-power-safety" not in power_module
assert "window.DWRT_UI_KIT?.confirmationMarkup" in power_module
assert 'd="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"' in power_module
assert ".system-power-table { width: 100%; min-width: 840px" in power_style
assert "const CONFIG_ENDPOINT = '/api/v1/system/ttyd'" in terminal_module
assert "system_ttyd_read" in terminal_module and "system_ttyd_write" in terminal_module
assert "data-terminal-field=\"client_option\"" in terminal_module
assert "preserve_credential" in terminal_module
assert "check_origin: false" in terminal_module
assert "if (!text) return '';" in terminal_module
assert 'data-frame-key="${state.frameKey}"' in terminal_module
assert ".system-terminal-frame" in terminal_style
assert "system_terminal:" in (WWW / "static/js/menu-icons.js").read_text(encoding="utf-8")
assert "normalizeDashboardApps(dashboardAppInputs(snapshot, clientsData), clientsData)" in dashboard_module
assert "window.DWRT_DEVICE_IMAGES?.resolve?.(client)" in dashboard_module
assert "enrichClientRankSource(client, clientsByMac)" in dashboard_module
assert "merged.effective_image = firstText(source.effective_image, client.effective_image)" in dashboard_module
assert "firstText(client.effective_image, client.detected_image, client.image_url, client.image, deviceImage.src)" in dashboard_module
assert "data-fallback=\"${escapeHtml(text || '?')}\"" in dashboard_module
assert "`设备：${" in dashboard_module and "`IP：${" in dashboard_module
assert "`命中：${" in dashboard_module and "`目标IP：${" in dashboard_module
assert "`持续时间：${" in dashboard_module
assert "app.durationKnown ? appTrackDuration(app.duration)" in dashboard_module
assert 'data-dwrt-tooltip="${escapeHtml(appTrackTitle(app))}"' in dashboard_module
assert "white-space: pre-line" in ui_kit_style
assert "min-width: 1120px" not in power_style
assert "confirmationMarkup: (...args)" in shell
assert "function deleteConfirmationMarkup(row)" in network_interface_module
assert "window.DWRT_UI_KIT?.confirmationMarkup" in network_interface_module
assert "data-interface-confirm-delete" not in network_interface_module
assert "item?.frontend_owned !== true" in shell
assert "merged.push(cloneFrontendItem(item))" in shell
assert "reference?.override_runtime_label === true" in shell
assert "normalized.hidePages = [...new Set" in shell
assert "normalized.hideFuncs = [...new Set" in shell
assert "dreamingwrt.shellWarm.menu.v4" in shell
assert "raw = url === STATIC_MENU_URL ? readWarmShellValue" in shell
assert "if (!raw && url === STATIC_MENU_URL) raw = readWarmShellValue" not in shell

prewarm = (WWW / "static/js/shell-prewarm.js").read_text(encoding="utf-8")
assert "dreamingwrt.shellWarm.menu.v4" in prewarm
assert "dreamingwrt.shellWarm.menu.v3" not in prewarm
assert "/plugins/native/ai-assistant.js" not in prewarm
assert "/static/css/ai-assistant.css" not in prewarm
assert "/static/js/dwrt-data-registry.js?v=20260721-02" in prewarm
assert "/static/js/device-images.js?v=20260723-airview-radio-sheet-01" in prewarm
# 外壳缓存键随每次改动 bump；这里断言三个引用点用的是同一个键，而不是某个具体字面量。
_shell_key = re.search(r"const VERSION = '([^']+)'", prewarm)
assert _shell_key, "shell-prewarm.js missing const VERSION"
_shell_key = _shell_key.group(1)
assert f"/static/js/menu-shell.js?v={_shell_key}" in prewarm
assert "/static/ui-kit/dwrt-sampled-liquid-glass.js?v=20260730-safari-glass-lite-06" in prewarm
assert '/static/ui-kit/dwrt-sampled-liquid-glass.js?v=20260730-safari-glass-lite-06' in app_html
assert f'/static/js/menu-shell.js?v={_shell_key}' in app_html
assert f'/static/js/shell-prewarm.js?v={_shell_key}' in app_html
assert '/static/js/device-images.js?v=20260723-airview-radio-sheet-01' in app_html
assert "/static/js/menu-icons.js?v=20260722-auth-control-01" in prewarm
assert "/static/css/dwrt-theme.css?v=20260722-03" in prewarm
assert '/static/css/dwrt-theme.css?v=20260722-03' in app_html
lucide = WWW / "static/ui-kit/lucide.min.js"
assert lucide.is_file() and lucide.stat().st_size > 300_000
assert '/static/ui-kit/lucide.min.js?v=1.25.0' in app_html
assert '/static/ui-kit/lucide.min.js?v=1.25.0' in prewarm

print("ok: webd pulls the static site without a jmxd dependency cycle or test artifacts")
