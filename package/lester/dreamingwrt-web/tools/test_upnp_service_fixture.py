#!/usr/bin/env python3
"""Browser fixture for UPnP grouping, capability gates and responsive bounds."""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies"
NODE = Path(shutil.which("node") or RUNTIME / "node/bin/node")
PROJECT_NODE_MODULES = ROOT.parents[1] / "openwrt-unifi-dashboard/node_modules"
NODE_MODULES = PROJECT_NODE_MODULES if (PROJECT_NODE_MODULES / "playwright").exists() else RUNTIME / "node/node_modules"

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
  const artifactDir = process.env.UPNP_ARTIFACT_DIR || '';
  for (const viewport of [{width:1440,height:1000},{width:1024,height:768},{width:390,height:844}]) {
    await page.setViewportSize(viewport);
    await page.goto('http://127.0.0.1:18772/tests/fixtures/upnp-service.html', { waitUntil: 'networkidle' });
    await page.waitForFunction(() => window.UPNP_FIXTURE);
    if (!await page.evaluate(() => window.UPNP_FIXTURE.ready())) throw new Error('fixture did not become ready');
    if (artifactDir) await page.screenshot({ path: `${artifactDir}/upnp-${viewport.width}x${viewport.height}.png`, fullPage: true });
    const settings = await page.evaluate(viewport => {
      const root = document.getElementById('routePreview');
      const groups = Array.from(root.querySelectorAll('[data-upnp-group-toggle]')).map(node => ({
        title: node.querySelector('strong')?.textContent.trim(), expanded: node.getAttribute('aria-expanded')
      }));
      const disabled = Array.from(root.querySelectorAll('[data-upnp-field]:disabled')).map(node => node.dataset.upnpField);
      const surface = root.querySelector('.upnp-settings-surface');
      const surfaceRect = surface.getBoundingClientRect();
      const groupBottoms = Array.from(root.querySelectorAll('[data-upnp-group]')).map(node => Math.round(node.getBoundingClientRect().bottom));
      return {
        viewport,
        tabs: Array.from(root.querySelectorAll('[data-upnp-tab]')).map(node => node.textContent.trim()),
        groups,
        disabled,
        runtimeValues: Array.from(root.querySelectorAll('.upnp-overview [data-dwrt-overview-value]')).map(node => node.textContent.trim()),
        overviewCards: Array.from(root.querySelectorAll('.upnp-overview [data-dwrt-overview-card]')).map(node => node.dataset.dwrtOverviewCard),
        // These lines are ellipsised, and an ellipsised box reports scrollWidth equal to
        // clientWidth, so truncation only shows up by measuring the text itself.
        overviewClipped: Array.from(root.querySelectorAll('.upnp-overview :where(.dwrt-kit-overview-label, .dwrt-kit-overview-content strong, .dwrt-kit-overview-content small)'))
          .map(node => {
            const style = getComputedStyle(node);
            const ctx = document.createElement('canvas').getContext('2d');
            ctx.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
            const text = node.textContent.trim();
            return { text, needed: Math.ceil(ctx.measureText(text).width), box: node.clientWidth };
          })
          .filter(item => item.needed > item.box)
          .map(item => `${item.text} (${item.needed}>${item.box})`),
        overviewAboveWorkbench: (() => {
          const grid = root.querySelector('.upnp-overview');
          const workbench = root.querySelector('.upnp-service-workbench');
          if (!grid || !workbench) return null;
          return grid.getBoundingClientRect().bottom <= workbench.getBoundingClientRect().top + 1;
        })(),
        primarySwitches: root.querySelectorAll('.upnp-service-primary [data-upnp-field="enabled"]').length,
        settingsRadius: getComputedStyle(root.querySelector('.upnp-settings-surface')).borderRadius,
        settingsContentClipped: groupBottoms.some(bottom => bottom > Math.round(surfaceRect.bottom) + 1),
        settingsHeight: Math.round(surfaceRect.height),
        workbenchClientHeight: root.querySelector('.upnp-service-workbench').clientHeight,
        workbenchScrollHeight: root.querySelector('.upnp-service-workbench').scrollHeight,
        overflow: document.documentElement.scrollWidth > innerWidth + 1 || root.scrollWidth > root.clientWidth + 1,
        glassSurfaces: root.querySelectorAll('.upnp-settings-surface[data-dwrt-surface="stable-glass"]').length,
        sampledRegions: root.querySelectorAll('[data-adaptive-sample]').length,
        unsampledRegions: Array.from(root.querySelectorAll('[data-adaptive-sample]')).filter(node => !node.hasAttribute('data-adaptive-region')).length,
        cardRadii: Array.from(new Set(['.upnp-settings-surface', '.upnp-table-card']
          .map(selector => root.querySelector(selector))
          .filter(Boolean)
          .map(node => getComputedStyle(node).borderRadius))),
        stageOverflow:getComputedStyle(document.querySelector('.console-stage')).overflowY,
        workbenchOverflow:getComputedStyle(root.querySelector('.upnp-service-workbench')).overflowY,
        toolbarTop:Math.round(root.querySelector('.upnp-page-toolbar').getBoundingClientRect().top),
        workbenchTop:Math.round(root.querySelector('.upnp-service-workbench').getBoundingClientRect().top),
        actionCenter:Math.round(root.querySelector('.upnp-page-actions').getBoundingClientRect().top + root.querySelector('.upnp-page-actions').getBoundingClientRect().height / 2),
        tabsCenter:Math.round(root.querySelector('.upnp-tabs').getBoundingClientRect().top + root.querySelector('.upnp-tabs').getBoundingClientRect().height / 2)
      };
    }, viewport);
    await page.locator('[data-upnp-group-toggle="runtime"]').click();
    const expanded = await page.evaluate(() => Array.from(document.querySelectorAll('[data-upnp-group-toggle]')).map(node => node.getAttribute('aria-expanded')));
    await page.locator('[data-upnp-tab="acl"]').click();
    await page.waitForTimeout(120);
    const acl = await page.evaluate(() => ({
      rows: document.querySelectorAll('.upnp-table tbody tr').length,
      createDisabled: Boolean(document.querySelector('[data-upnp-create]:disabled')),
      sampledTable: Boolean(document.querySelector('.upnp-table-card[data-adaptive-region]')),
      unsampled: document.querySelectorAll('#routePreview [data-adaptive-sample]:not([data-adaptive-region])').length,
      search: (() => {
        const host = document.querySelector('.upnp-search');
        if (!host) return null;
        const svg = host.querySelector('.dwrt-kit-expand-search-icon svg');
        return {
          mounted: host.dataset.dwrtExpandSearch === 'true',
          iconVisible: Boolean(svg && svg.getBoundingClientRect().width > 4
            && getComputedStyle(svg).visibility !== 'hidden')
        };
      })()
    }));
    await page.locator('[data-upnp-edit-acl="allow-lan"]').click();
    await page.waitForTimeout(700);
    const aclSheet = await page.evaluate(() => {
      const sheet = document.querySelector('.upnp-sheet');
      const rect = sheet.getBoundingClientRect();
      return { open: Boolean(sheet), right: Math.abs(innerWidth - rect.right), inside: rect.left >= -1, width: Math.round(rect.width), saveDisabled: Boolean(sheet.querySelector('[data-upnp-editor-save]:disabled')) };
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
        # runtime status now reads as a row of shared overview cards above the workbench
        assert settings["overviewCards"] == ["service", "mappings", "requests", "security", "boundary"], result
        assert settings["overviewClipped"] == [], result
        assert settings["runtimeValues"] == ["运行中", "1", "0", "已启用", "2"], result
        assert settings["overviewAboveWorkbench"] is True, result
        assert settings["primarySwitches"] == 1, result
        # Radius must equal the shared surface token, and every card on the page must agree.
        assert settings["settingsRadius"] == "8px", result
        assert settings["cardRadii"] == ["8px"], result
        assert not settings["settingsContentClipped"], result
        if settings["viewport"]["width"] == 390:
            assert settings["workbenchScrollHeight"] > settings["workbenchClientHeight"], result
        assert not settings["overflow"] and settings["glassSurfaces"] == 1, result
        # Readability is only real once the shell has actually stamped every sampled region.
        assert settings["sampledRegions"] >= 1, result
        assert settings["unsampledRegions"] == 0, result
        assert settings["stageOverflow"] == "hidden" and settings["workbenchOverflow"] == "auto", result
        assert settings["workbenchTop"] > settings["toolbarTop"], result
        assert abs(settings["actionCenter"] - settings["tabsCenter"]) <= 1, result
        assert result["expanded"] == ["false", "false", "true"], result
        assert result["acl"]["rows"] == 2 and result["acl"]["createDisabled"] is False, result
        # The list surface must inherit sampled foreground too, not just the settings surface.
        assert result["acl"]["sampledTable"] and result["acl"]["unsampled"] == 0, result
        # regression guard: hardcoded data-dwrt-expand-search="true" left the search box
        # as an empty circle because the kit skipped icon insertion.
        assert result["acl"]["search"], result
        assert result["acl"]["search"]["mounted"] and result["acl"]["search"]["iconVisible"], result
        assert result["aclSheet"]["open"] and result["aclSheet"]["inside"] and result["aclSheet"]["right"] <= 1 and result["aclSheet"]["width"] <= 460 and not result["aclSheet"]["saveDisabled"], result
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
