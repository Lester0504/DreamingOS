#!/usr/bin/env python3
"""Three-viewport browser fixture for the read-only IP address workbench."""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies"
NODE = Path(shutil.which("node") or RUNTIME / "node/bin/node")
NODE_MODULES = ROOT / "node_modules"
if not (NODE_MODULES / "playwright").exists():
    NODE_MODULES = RUNTIME / "node/node_modules"
if not NODE.is_file():
    raise SystemExit(f"Node.js not found: {NODE}")
if not (NODE_MODULES / "playwright").exists():
    raise SystemExit(f"Playwright not found: {NODE_MODULES / 'playwright'}")


server = subprocess.Popen(
    ["python3", "-m", "http.server", "18775", "--bind", "127.0.0.1"],
    cwd=ROOT,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.PIPE,
    text=True,
)

try:
    time.sleep(0.4)
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
  await page.goto('http://127.0.0.1:18775/tests/fixtures/ip-address-management.html', { waitUntil: 'networkidle' });
  await page.waitForFunction(() => Boolean(window.IPAM_FIXTURE));
  const artifactDir = process.env.IPAM_ARTIFACT_DIR || '';

  const viewports = [];
  for (const viewport of [{ width: 1440, height: 1000 }, { width: 1024, height: 768 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    await page.evaluate(() => window.IPAM_FIXTURE.remount('ready'));
    await page.waitForTimeout(80);
    if (artifactDir) await page.screenshot({ path: `${artifactDir}/ipam-${viewport.width}x${viewport.height}.png`, fullPage: true });
    const base = await page.evaluate(() => window.IPAM_FIXTURE.contract());
    // The reported defect was native white controls. Measure the computed material of
    // every filter control so a regression cannot pass as "looks fine".
    const controlMaterial = await page.evaluate(() => {
      const opaqueWhite = (value) => {
        const parts = String(value).match(/[\d.]+/g);
        if (!parts || parts.length < 3) return false;
        const [r, g, b] = parts.map(Number);
        const alpha = parts.length > 3 ? Number(parts[3]) : 1;
        return alpha > 0.9 && r > 240 && g > 240 && b > 240;
      };
      const controls = ['[data-ipam-network]', '[data-ipam-status]', '[data-ipam-source]'].map((selector) => {
        const node = document.querySelector(selector);
        if (!node) return { selector, missing: true };
        const style = getComputedStyle(node);
        // A select never reports overflow, so compare the rendered box against the
        // measured width of its own selected label plus the kit's padding gutters.
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
        const labelWidth = ctx.measureText(node.options[node.selectedIndex]?.text || '').width;
        const gutters = parseFloat(style.paddingLeft) + parseFloat(style.paddingRight)
          + parseFloat(style.borderLeftWidth) + parseFloat(style.borderRightWidth);
        return {
          selector,
          inField: Boolean(node.closest('.dwrt-kit-field')),
          kitClass: node.classList.contains('dwrt-kit-select'),
          appearance: style.appearance,
          whiteBackground: opaqueWhite(style.backgroundColor),
          hasBorder: style.borderTopWidth !== '0px',
          boxWidth: Math.round(node.getBoundingClientRect().width),
          neededWidth: Math.ceil(labelWidth + gutters)
        };
      });
      const searchHost = document.querySelector('.ipam-search');
      const searchStyle = searchHost ? getComputedStyle(searchHost) : null;
      const searchIcon = searchHost ? searchHost.querySelector('.dwrt-kit-expand-search-icon svg') : null;
      return {
        controls,
        search: searchHost ? {
          kitClass: searchHost.classList.contains('dwrt-kit-expand-search'),
          mounted: searchHost.dataset.dwrtExpandSearch === 'true',
          iconVisible: Boolean(searchIcon && searchIcon.getBoundingClientRect().width > 4
            && getComputedStyle(searchIcon).visibility !== 'hidden'),
          collapsedWidth: Math.round(searchHost.getBoundingClientRect().width),
          whiteBackground: opaqueWhite(searchStyle.backgroundColor),
          backdrop: searchStyle.backdropFilter
        } : null
      };
    });
    await page.locator('[data-ipam-network]').selectOption('all');
    await page.locator('[data-ipam-status]').selectOption('conflict');
    const conflictRows = await page.locator('[data-ipam-detail]').count();
    await page.locator('[data-ipam-status]').selectOption('all');
    await page.locator('[data-ipam-source]').selectOption('dhcp');
    const dhcpRows = await page.locator('[data-ipam-detail]').count();
    await page.locator('[data-ipam-source]').selectOption('all');
    const search = page.locator('[data-ipam-search]');
    await search.fill('Workstation');
    const searchRows = await page.locator('[data-ipam-detail]').count();
    await search.fill('');
    await page.locator('[data-ipam-detail]').first().click();
    await page.waitForTimeout(650);
    const sheet = await page.evaluate(() => {
      const node = document.querySelector('.ipam-detail-sheet');
      const rect = node.getBoundingClientRect();
      return {
        width: Math.round(rect.width),
        right: Math.round(Math.abs(innerWidth - rect.right)),
        inside: rect.left >= -1,
        text: node.innerText,
        overflow: node.scrollWidth > node.clientWidth + 1
      };
    });
    await page.locator('.dwrt-kit-sheet-header [data-ipam-detail-close]').click();
    viewports.push({ viewport, base, conflictRows, dhcpRows, searchRows, sheet, controlMaterial });
  }

  await page.setViewportSize({ width: 1440, height: 1000 });
  const loading = await page.evaluate(() => window.IPAM_FIXTURE.remount('loading'));
  const error = await page.evaluate(() => window.IPAM_FIXTURE.remount('error'));
  const lkg = await page.evaluate(() => window.IPAM_FIXTURE.remount('lkg'));
  await browser.close();
  process.stdout.write(JSON.stringify({ consoleErrors, viewports, loading, error, lkg }));
})().catch(error => { console.error(error); process.exit(1); });
"""
    env = os.environ.copy()
    env["NODE_PATH"] = str(NODE_MODULES)
    if os.environ.get("IPAM_ARTIFACT_DIR"):
        artifact_dir = Path(os.environ["IPAM_ARTIFACT_DIR"])
        artifact_dir.mkdir(parents=True, exist_ok=True)
        env["IPAM_ARTIFACT_DIR"] = str(artifact_dir.resolve())
    result = subprocess.run(
        [str(NODE), "-e", script],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    data = json.loads(result.stdout)
    assert not data["consoleErrors"], data
    for item in data["viewports"]:
        base = item["base"]
        assert base["selectedNetwork"] == "lan", item
        assert base["rows"] == 4, item
        assert base["summaryMetrics"] == 5 and base["tableCount"] == 1 and base["columnCount"] == 6, item
        assert base["requests"] and all(request["method"] == "GET" and request["url"] == "/api/v1/bulk-ip" for request in base["requests"]), item
        assert item["conflictRows"] == 1 and item["dhcpRows"] == 2 and item["searchRows"] == 1, item
        assert item["sheet"]["inside"] and item["sheet"]["right"] <= 1 and item["sheet"]["width"] <= 460, item
        assert not item["sheet"]["overflow"] and "当前为只读盘点" in item["sheet"]["text"], item
        assert not base["pageOverflow"] and not base["rootOverflow"], item
        assert base["tableRadius"] == "24px", item
        assert base["tableSurface"] != "none", item
        assert base["workbenchBackground"] == "rgba(0, 0, 0, 0)" and base["workbenchBackdrop"] == "none", item
        assert base["toolbarHeight"] >= 44, item
        # reported defect: filter controls rendered as native white boxes
        for control in item["controlMaterial"]["controls"]:
            assert not control.get("missing"), item
            assert control["kitClass"] and control["inField"], control
            assert control["appearance"] == "none", control
            assert not control["whiteBackground"], control
            assert control["hasBorder"], control
            # reported defect: the mobile filters clipped their own option text
            assert control["boxWidth"] >= control["neededWidth"], control
        search = item["controlMaterial"]["search"]
        assert search and search["kitClass"], item
        # regression guard: hardcoding data-dwrt-expand-search="true" made mountExpandSearch
        # bail out, so the box rendered as an empty circle with no magnifier.
        assert search["mounted"] and search["iconVisible"], search
        assert not search["whiteBackground"], search
        assert search["backdrop"] != "none", search
        if item["viewport"]["width"] == 390:
            assert not base["tableOverflow"], item
            assert base["tableDisplay"] == "block" and base["headerDisplay"] == "none" and base["rowDisplay"] == "grid", item
        else:
            assert not base["tableOverflow"], item
            assert base["tableDisplay"] == "table" and base["headerDisplay"] == "table-header-group" and base["rowDisplay"] == "table-row", item
    assert "正在读取地址" in data["loading"]["text"], data
    assert "fixture IPAM read failed" in data["error"]["text"], data
    assert data["error"]["rows"] == 0, data
    assert data["lkg"]["rows"] == 4 and "最近一次结果" in data["lkg"]["text"], data
    assert all(request["method"] == "GET" for request in data["lkg"]["requests"]), data
    print("ok: IP address management fixture passes read-only data, compact hierarchy, filters, LKG and responsive geometry")
finally:
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
