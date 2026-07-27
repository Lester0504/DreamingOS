#!/usr/bin/env python3
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
    ["python3", "-m", "http.server", "18770", "--bind", "127.0.0.1"],
    cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
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
  await page.goto('http://127.0.0.1:18770/tests/fixtures/wifi-config.html', { waitUntil: 'networkidle' });
  await page.waitForSelector('.wifi-config-table tbody tr');
  const viewports = [];
  for (const viewport of [{width:1440,height:1000},{width:1024,height:768},{width:390,height:844}]) {
    await page.setViewportSize(viewport);
    const views = {};
    for (const view of ['broadcasts','radios','extensions']) {
      await page.locator(`[data-wifi-config-tab="${view}"]`).click();
      views[view] = await page.evaluate(() => ({
        surfaces: document.querySelectorAll('.wifi-config-surface').length,
        nestedGlass: document.querySelectorAll('.wifi-config-surface .policy-stable-glass').length,
        pageOverflow: document.documentElement.scrollWidth > innerWidth + 1,
        routeOverflow: document.getElementById('routePreview').scrollWidth > document.getElementById('routePreview').clientWidth + 1,
        selectedTabs: document.querySelectorAll('[data-wifi-config-tab][aria-selected="true"]').length,
        text: document.querySelector('.wifi-config-surface')?.innerText || ''
      }));
    }
    viewports.push({ ...viewport, views });
  }
  const mesh = await page.evaluate(() => ({
    switchClass: document.querySelector('[data-wifi-setting="global.mesh"]')?.closest('label')?.classList.contains('dwrt-kit-switch'),
    switchRole: document.querySelector('[data-wifi-setting="global.mesh"]')?.getAttribute('role'),
    monitorVisible: Boolean(document.querySelector('.wifi-dependency-panel.is-active')),
    largeRadius: getComputedStyle(document.querySelector('.wifi-config-surface')).borderRadius
  }));
  await page.locator('[data-wifi-setting="global.mesh"]').check();
  const meshEnabled = await page.evaluate(() => ({
    monitorVisible: Boolean(document.querySelector('.wifi-dependency-panel.is-active')),
    monitorDisabled: Boolean(document.querySelector('[data-wifi-setting="global.mesh_monitor"]')?.disabled)
  }));
  await browser.close();
  process.stdout.write(JSON.stringify({ viewports, mesh, meshEnabled }));
})().catch(error => { console.error(error); process.exit(1); });
"""
    env = os.environ.copy()
    env["NODE_PATH"] = str(NODE_MODULES)
    result = subprocess.run([str(NODE), "-e", script], cwd=ROOT, env=env, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    data = json.loads(result.stdout)
    for viewport in data["viewports"]:
        for view in viewport["views"].values():
            assert view["surfaces"] == 1 and view["nestedGlass"] == 0, data
            assert not view["pageOverflow"] and not view["routeOverflow"] and view["selectedTabs"] == 1, data
        assert "DreamingWrt" in viewport["views"]["broadcasts"]["text"], data
        assert all(text in viewport["views"]["radios"]["text"] for text in ["Radio 摘要", "默认 Wi-Fi 速度", "信道计划"]), data
        assert all(text in viewport["views"]["extensions"]["text"] for text in ["控制器能力", "Dreaming OS 扩展设置"]), data
    assert data["mesh"]["switchClass"] and data["mesh"]["switchRole"] == "switch" and not data["mesh"]["monitorVisible"], data
    assert data["meshEnabled"]["monitorVisible"] and not data["meshEnabled"]["monitorDisabled"], data
    assert data["mesh"]["largeRadius"] == "20px", data
    print("ok: Wi-Fi config fixture passes Kit hierarchy, dependency state and three viewports")
finally:
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
