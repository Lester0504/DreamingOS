#!/usr/bin/env python3
"""Three-viewport browser fixture for the multicast service workbench."""

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
    ["python3", "-m", "http.server", "18781", "--bind", "127.0.0.1"],
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
  await page.goto('http://127.0.0.1:18781/tests/fixtures/multicast-service.html', { waitUntil: 'networkidle' });
  await page.waitForFunction(() => Boolean(window.MULTICAST_FIXTURE));
  if (!await page.evaluate(() => window.MULTICAST_FIXTURE.ready())) throw new Error('fixture did not become ready');
  const artifactDir = process.env.MULTICAST_ARTIFACT_DIR || '';

  const viewports = [];
  for (const viewport of [{ width: 1440, height: 1000 }, { width: 1024, height: 768 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    await page.evaluate(() => window.MULTICAST_FIXTURE.remount('ready'));
    await page.waitForTimeout(120);
    if (artifactDir) await page.screenshot({ path: `${artifactDir}/multicast-${viewport.width}x${viewport.height}.png`, fullPage: true });
    const probe = await page.evaluate(() => {
      const root = document.getElementById('routePreview');
      const surface = root.querySelector('.multicast-settings-surface');
      const surfaceStyle = getComputedStyle(surface);
      const cards = Array.from(root.querySelectorAll('.multicast-overview [data-dwrt-overview-card]'));
      const grid = root.querySelector('.multicast-overview');
      const workbench = root.querySelector('.multicast-service-main');
      const clipped = Array.from(root.querySelectorAll('.multicast-overview :where(.dwrt-kit-overview-label, .dwrt-kit-overview-content strong, .dwrt-kit-overview-content small)'))
        .map(node => {
          const style = getComputedStyle(node);
          const ctx = document.createElement('canvas').getContext('2d');
          ctx.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
          const text = node.textContent.trim();
          return { text, needed: Math.ceil(ctx.measureText(text).width), box: node.clientWidth };
        })
        .filter(item => item.needed > item.box)
        .map(item => `${item.text} (${item.needed}>${item.box})`);
      return {
        cards: cards.map(node => node.dataset.dwrtOverviewCard),
        values: cards.map(node => node.querySelector('[data-dwrt-overview-value]')?.textContent.trim()),
        clipped,
        cardsAboveWorkbench: grid && workbench
          ? grid.getBoundingClientRect().bottom <= workbench.getBoundingClientRect().top + 1
          : null,
        // the reported defect was a fully transparent lower half with no card to hold it
        surface: {
          background: surfaceStyle.backgroundColor,
          backdrop: surfaceStyle.backdropFilter,
          radius: surfaceStyle.borderTopLeftRadius,
          hasBorder: surfaceStyle.borderTopWidth !== '0px',
          sampled: surface.hasAttribute('data-adaptive-region')
        },
        // the retired duplicate headings must be gone from every tab
        headings: root.innerText,
        legacySummary: root.querySelectorAll('.multicast-runtime-summary').length,
        overflow: document.documentElement.scrollWidth > innerWidth + 1 || root.scrollWidth > root.clientWidth + 1
      };
    });

    const tabs = [];
    for (const tab of ['igmp', 'iptv', 'udpxy', 'discovery', 'overview']) {
      await page.locator(`[data-multicast-tab="${tab}"]`).click();
      await page.waitForTimeout(90);
      tabs.push(await page.evaluate(tabId => {
        const root = document.getElementById('routePreview');
        return {
          tab: tabId,
          cards: root.querySelectorAll('.multicast-overview [data-dwrt-overview-card]').length,
          glass: root.querySelectorAll('.multicast-settings-surface[data-dwrt-surface="stable-glass"]').length,
          text: root.innerText
        };
      }, tab));
    }
    viewports.push({ viewport, probe, tabs });
  }

  await page.setViewportSize({ width: 1440, height: 1000 });
  const readonly = await page.evaluate(() => window.MULTICAST_FIXTURE.remount('readonly'));
  const writes = await page.evaluate(() => window.MULTICAST_FIXTURE.writes.length);
  await browser.close();
  process.stdout.write(JSON.stringify({ consoleErrors, viewports, readonly, writes }));
})().catch(error => { console.error(error); process.exit(1); });
"""
    env = os.environ.copy()
    env["NODE_PATH"] = str(NODE_MODULES)
    if os.environ.get("MULTICAST_ARTIFACT_DIR"):
        artifact_dir = Path(os.environ["MULTICAST_ARTIFACT_DIR"])
        artifact_dir.mkdir(parents=True, exist_ok=True)
        env["MULTICAST_ARTIFACT_DIR"] = str(artifact_dir.resolve())
    result = subprocess.run([str(NODE), "-e", script], cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    data = json.loads(result.stdout)
    assert not data["consoleErrors"], data["consoleErrors"]

    for item in data["viewports"]:
        probe = item["probe"]
        assert probe["cards"] == ["service", "groups", "throughput", "udpxy"], item
        assert probe["values"][0] == "已配置" and probe["values"][1] == "12", item
        assert probe["cardsAboveWorkbench"] is True, item
        assert probe["clipped"] == [], item
        # reported defect: the settings area was fully transparent with no card around it
        assert probe["surface"]["background"] != "rgba(0, 0, 0, 0)", item
        assert probe["surface"]["backdrop"] != "none", item
        assert probe["surface"]["hasBorder"] and probe["surface"]["radius"] == "8px", item
        assert probe["surface"]["sampled"], item
        assert probe["legacySummary"] == 0, item
        # reported defect:每个面板重复一遍 Tab 名与介绍
        for retired in ("查看当前配置、订阅和转发状态", "配置 IPv4 与 IPv6 组播订阅转发",
                        "设置运营商上联、目标网络与机顶盒端口", "管理组播转单播服务及监听实例",
                        "管理跨网络发现、侦听、查询器与允许组"):
            assert retired not in probe["headings"], (retired, item["viewport"])
        assert not probe["overflow"], item
        for tab in item["tabs"]:
            assert tab["cards"] == 4, tab
            assert tab["glass"] == 1, tab
            for retired in ("查看当前配置、订阅和转发状态", "配置 IPv4 与 IPv6 组播订阅转发"):
                assert retired not in tab["text"], tab

    assert "当前为只读" in data["readonly"], data["readonly"]
    assert data["writes"] == 0, data["writes"]
    print("ok: multicast fixture passes status card row, glass settings surface, deduplicated headings and 1440/1024/390 layouts")
finally:
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
