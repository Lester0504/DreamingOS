#!/usr/bin/env python3
import json
import os
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path(os.environ.get(
    "CODEX_WORKSPACE_DEPENDENCIES",
    str(Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies"),
))
PROJECT_NODE_MODULES = ROOT / "node_modules"
NODE_MODULES = PROJECT_NODE_MODULES if (PROJECT_NODE_MODULES / "playwright").exists() else RUNTIME / "node/node_modules"
NODE = Path(os.environ.get("NODE_BINARY", str(RUNTIME / "node/bin/node")))
if not NODE.exists():
    NODE = Path(subprocess.check_output(["sh", "-c", "command -v node"], text=True).strip())
if not (NODE_MODULES / "playwright").exists():
    raise SystemExit(f"Playwright not found: {NODE_MODULES / 'playwright'}")


server = subprocess.Popen(
    ["python3", "-m", "http.server", "18771", "--bind", "127.0.0.1"],
    cwd=ROOT,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    time.sleep(0.4)
    script = r"""
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: true, channel: 'chrome' });
  const page = await browser.newPage();
  const consoleErrors = [];
  page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });
  page.on('pageerror', error => consoleErrors.push(error.message));
  await page.goto('http://127.0.0.1:18771/tests/fixtures/routing-table-phase-a.html');
  await page.waitForFunction(() => Boolean(window.ROUTING_FIXTURE));

  const viewports = [];
  for (const viewport of [{ width: 1440, height: 1000 }, { width: 1024, height: 768 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    await page.evaluate(() => window.ROUTING_FIXTURE.remount('ready'));
    await page.locator('[data-routing-tab="tables"]').click();
    await page.locator('[data-routing-create="tables"]').click();
    await page.waitForTimeout(700);
    const sheet = await page.evaluate(() => {
      const node = document.querySelector('.routing-drawer');
      const rect = node.getBoundingClientRect();
      return { width: Math.round(rect.width), right: Math.round(Math.abs(innerWidth - rect.right)), inside: rect.left >= -1 };
    });
    await page.locator('[data-routing-field="id"]').fill('reserved-table');
    await page.locator('[data-routing-field="name"]').fill('保留表');
    await page.locator('[data-routing-field="table_id"]').fill('254');
    await page.locator('[data-routing-save]').click();
    const reserved = await page.evaluate(() => ({
      text: document.querySelector('.routing-drawer')?.innerText || '',
      writes: window.ROUTING_FIXTURE.requests.filter(item => item.method !== 'GET').length
    }));
    await page.locator('[data-routing-close]').last().click();
    viewports.push(await page.evaluate(({ viewport, sheet, reserved }) => ({
      viewport,
      sheet,
      reserved,
      tabs: [...document.querySelectorAll('[data-routing-tab]')].map(node => node.textContent.trim()),
      pageOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      rootOverflow: document.getElementById('routePreview').scrollWidth > document.getElementById('routePreview').clientWidth + 1,
      transparentRoot: getComputedStyle(document.querySelector('.routing-table-shell')).backgroundColor === 'rgba(0, 0, 0, 0)',
      tableRadius: getComputedStyle(document.querySelector('.routing-resource-table')).borderRadius,
      directGlassSurfaces: document.querySelectorAll('.routing-table-shell > .dwrt-kit-glass-surface').length
    }), { viewport, sheet, reserved }));
  }

  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.evaluate(() => window.ROUTING_FIXTURE.remount('ready'));
  const initialWrites = await page.evaluate(() => window.ROUTING_FIXTURE.requests.filter(item => item.method !== 'GET').length);
  await page.locator('[data-routing-tab="tables"]').click();
  await page.locator('[data-routing-open="table"]').first().click();
  await page.locator('[data-routing-delete]').click();
  const confirmation = await page.locator('[data-dwrt-confirmation]').isVisible();

  await page.evaluate(() => window.ROUTING_FIXTURE.remount('reference-conflict'));
  await page.locator('[data-routing-tab="tables"]').click();
  await page.locator('[data-routing-open="table"]').first().click();
  await page.locator('[data-routing-delete]').click();
  await page.locator('[data-dwrt-confirm-accept]').click();
  await page.waitForTimeout(80);
  const conflict = await page.evaluate(() => ({
    sheetOpen: Boolean(document.querySelector('.routing-drawer')),
    text: document.querySelector('.routing-drawer')?.innerText || '',
    request: window.ROUTING_FIXTURE.requests.find(item => item.method === 'DELETE') || null
  }));

  await page.evaluate(() => window.ROUTING_FIXTURE.remount('runtime-missing'));
  await page.locator('[data-routing-tab="tables"]').click();
  const failClosed = await page.evaluate(() => ({
    createDisabled: Boolean(document.querySelector('[data-routing-create="tables"]:disabled')),
    text: document.querySelector('.routing-workbench')?.innerText || '',
    writes: window.ROUTING_FIXTURE.requests.filter(item => item.method !== 'GET').length
  }));

  await page.evaluate(() => window.ROUTING_FIXTURE.remount('ready'));
  await page.locator('[data-routing-tab="cross"]').click();
  const crossText = await page.locator('.routing-workbench').innerText();
  await page.locator('[data-routing-tab="runtime"]').click();
  await page.locator('[data-routing-resolve-value]').selectOption('wan2');
  await page.locator('[data-routing-resolve]').click();
  await page.waitForTimeout(80);
  const runtime = await page.evaluate(() => ({
    text: document.querySelector('.routing-workbench')?.innerText || '',
    request: window.ROUTING_FIXTURE.requests.find(item => item.url.endsWith('/runtime-resolve')) || null
  }));

  await browser.close();
  process.stdout.write(JSON.stringify({ consoleErrors, viewports, initialWrites, confirmation, conflict, failClosed, crossText, runtime }));
})().catch(error => { console.error(error); process.exit(1); });
"""
    env = os.environ.copy()
    env["NODE_PATH"] = str(NODE_MODULES)
    result = subprocess.run(
        [str(NODE), "-e", script],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
    )
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    data = json.loads(result.stdout)
    assert not data["consoleErrors"], data
    assert data["initialWrites"] == 0, data
    assert data["confirmation"], data
    assert data["conflict"]["sheetOpen"] and "办公出口" in data["conflict"]["text"], data
    assert data["conflict"]["request"]["url"].endswith("/routing/tables/wan2"), data
    assert data["failClosed"]["createDisabled"] and data["failClosed"]["writes"] == 0, data
    assert "后端未明确声明 table_crud" in data["failClosed"]["text"], data
    assert "运行消费者尚未实现" in data["crossText"], data
    assert data["runtime"]["request"]["body"] == {"route_table": "wan2"}, data
    assert "配置级解析" in data["runtime"]["text"] and "192.0.2.1" in data["runtime"]["text"], data
    for item in data["viewports"]:
        assert item["tabs"] == ["路由策略", "路由表", "路由对象", "跨三层服务", "运行解析"], item
        assert item["sheet"]["inside"] and item["sheet"]["right"] <= 1 and item["sheet"]["width"] <= 460, item
        assert "不能使用 253、254、255" in item["reserved"]["text"] and item["reserved"]["writes"] == 0, item
        assert not item["pageOverflow"] and not item["rootOverflow"], item
        assert item["transparentRoot"] and item["directGlassSurfaces"] == 0, item
        assert item["tableRadius"] == "24px", item
    print("ok: routing Phase A fixture passes capability gates, CRUD geometry, conflicts and runtime semantics")
finally:
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
