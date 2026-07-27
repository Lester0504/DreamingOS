#!/usr/bin/env python3
"""Browser fixture for UPnP grouping, capability gates and responsive bounds."""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
# Override with PLAYWRIGHT_RUNTIME to point at a local Node + Playwright install.
RUNTIME = Path(os.environ.get("PLAYWRIGHT_RUNTIME", Path.home() / ".cache/dreamingwrt-playwright"))
NODE = Path(shutil.which("node") or RUNTIME / "node/bin/node")
NODE_MODULES = RUNTIME / "node/node_modules"

if not NODE.is_file():
    raise SystemExit(f"Node.js not found: {NODE}")
if not (NODE_MODULES / "playwright").exists():
    raise SystemExit(f"Playwright not found: {NODE_MODULES / 'playwright'}")

server = subprocess.Popen(
    ["python3", "-m", "http.server", "18772", "--bind", "127.0.0.1"],
    cwd=ROOT,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.PIPE,
    text=True,
)

try:
    time.sleep(.4)
    if server.poll() is not None:
        raise RuntimeError(f"fixture server failed: {(server.stderr.read() if server.stderr else '').strip()}")
    script = r"""
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: true, channel: 'chrome' });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const consoleErrors = [];
  page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });
  page.on('pageerror', error => consoleErrors.push(error.message));
  const viewports = [];
  for (const viewport of [{width:1440,height:1000},{width:1024,height:768},{width:390,height:844}]) {
    await page.setViewportSize(viewport);
    await page.goto('http://127.0.0.1:18772/tests/fixtures/upnp-service.html', { waitUntil: 'networkidle' });
    await page.waitForFunction(() => window.UPNP_FIXTURE);
    if (!await page.evaluate(() => window.UPNP_FIXTURE.ready())) throw new Error('fixture did not become ready');
    const settings = await page.evaluate(viewport => {
      const root = document.getElementById('routePreview');
      const groups = Array.from(root.querySelectorAll('[data-upnp-group-toggle]')).map(node => ({
        title: node.querySelector('strong')?.textContent.trim(), expanded: node.getAttribute('aria-expanded')
      }));
      const disabled = Array.from(root.querySelectorAll('[data-upnp-field]:disabled')).map(node => node.dataset.upnpField);
      return {
        viewport,
        tabs: Array.from(root.querySelectorAll('[data-upnp-tab]')).map(node => node.textContent.trim()),
        groups,
        disabled,
        runtimeValues: Array.from(root.querySelectorAll('.upnp-runtime-summary strong')).map(node => node.textContent.trim()),
        overflow: document.documentElement.scrollWidth > innerWidth + 1 || root.scrollWidth > root.clientWidth + 1,
        glassSurfaces: root.querySelectorAll('.upnp-settings-surface.dwrt-kit-glass-surface').length
      };
    }, viewport);
    await page.locator('[data-upnp-group-toggle="runtime"]').click();
    const expanded = await page.evaluate(() => Array.from(document.querySelectorAll('[data-upnp-group-toggle]')).map(node => node.getAttribute('aria-expanded')));
    await page.locator('[data-upnp-tab="acl"]').click();
    const acl = await page.evaluate(() => ({ rows: document.querySelectorAll('.upnp-table tbody tr').length, createDisabled: Boolean(document.querySelector('[data-upnp-create]:disabled')) }));
    await page.locator('[data-upnp-edit-acl="allow-lan"]').click();
    await page.waitForTimeout(700);
    const aclSheet = await page.evaluate(() => {
      const sheet = document.querySelector('.upnp-sheet');
      const rect = sheet.getBoundingClientRect();
      return { open: Boolean(sheet), right: Math.abs(innerWidth - rect.right), inside: rect.left >= -1, saveDisabled: Boolean(sheet.querySelector('[data-upnp-editor-save]:disabled')) };
    });
    await page.locator('[data-upnp-close]').last().click();
    await page.locator('[data-upnp-tab="dynamic"]').click();
    const dynamic = await page.evaluate(() => ({ rows: document.querySelectorAll('.upnp-table tbody tr').length, editButtons: document.querySelectorAll('[data-upnp-edit-mapping]').length, text: document.querySelector('.upnp-service-workbench').innerText }));
    await page.locator('[data-upnp-tab="static"]').click();
    const staticView = await page.evaluate(() => ({ rows: document.querySelectorAll('.upnp-table tbody tr').length, createDisabled: Boolean(document.querySelector('[data-upnp-create]:disabled')) }));
    await page.locator('[data-upnp-edit-mapping="static-1"]').click();
    await page.waitForTimeout(700);
    const staticSheet = await page.evaluate(() => ({ open: Boolean(document.querySelector('.upnp-sheet')), save: document.querySelector('[data-upnp-editor-save]')?.textContent || '', capability: document.querySelector('.upnp-sheet')?.innerText.includes('当前后端没有静态映射写入') }));
    viewports.push({ settings, expanded, acl, aclSheet, dynamic, staticView, staticSheet, writes: await page.evaluate(() => window.UPNP_FIXTURE.writes.length) });
  }
  await browser.close();
  process.stdout.write(JSON.stringify({ viewports, consoleErrors }));
})().catch(error => { console.error(error); process.exit(1); });
"""
    env = os.environ.copy()
    env["NODE_PATH"] = str(NODE_MODULES)
    result = subprocess.run([str(NODE), "-e", script], cwd=ROOT, env=env, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    data = json.loads(result.stdout)
    assert not data["consoleErrors"], data
    for result in data["viewports"]:
        settings = result["settings"]
        assert settings["tabs"] == ["服务配置", "访问控制", "动态映射", "静态映射"], result
        assert [item["title"] for item in settings["groups"]] == ["协议与安全", "网络边界与端口范围", "运行参数"], result
        assert [item["expanded"] for item in settings["groups"]] == ["true", "false", "false"], result
        assert all(field in settings["disabled"] for field in ["pcp", "use_stun", "force_forwarding"]), result
        assert settings["runtimeValues"] == ["1", "0", "0", "已启用"], result
        assert not settings["overflow"] and settings["glassSurfaces"] == 1, result
        assert result["expanded"] == ["false", "false", "true"], result
        assert result["acl"] == {"rows": 2, "createDisabled": False}, result
        assert result["aclSheet"]["open"] and result["aclSheet"]["inside"] and result["aclSheet"]["right"] <= 1 and not result["aclSheet"]["saveDisabled"], result
        assert result["dynamic"]["rows"] == 1 and result["dynamic"]["editButtons"] == 0 and "不显示伪造流量" in result["dynamic"]["text"], result
        assert result["staticView"] == {"rows": 1, "createDisabled": True}, result
        assert result["staticSheet"]["open"] and not result["staticSheet"]["save"] and result["staticSheet"]["capability"], result
        assert result["writes"] == 0, result
    print("ok: UPnP fixture passes grouping, capability gates, drawers and 1440/1024/390 layouts")
finally:
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
