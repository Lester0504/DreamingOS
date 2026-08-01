#!/usr/bin/env python3
"""Read-only browser fixture for the LLM settings tabbed layout."""

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
    ["python3", "-m", "http.server", "18775", "--bind", "127.0.0.1"],
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
  const page = await browser.newPage();
  const consoleErrors = [];
  page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });
  page.on('pageerror', error => consoleErrors.push(error.message));
  const results = [];
  for (const viewport of [{width:1440,height:1000},{width:1024,height:768},{width:375,height:812}]) {
    await page.setViewportSize(viewport);
    await page.goto('http://127.0.0.1:18775/tests/fixtures/llm-settings.html', { waitUntil: 'networkidle' });
    await page.waitForFunction(() => window.LLM_SETTINGS_FIXTURE);
    if (!await page.evaluate(() => window.LLM_SETTINGS_FIXTURE.ready())) throw new Error('fixture did not become ready');

    const overviewTab = await page.evaluate(() => {
      const root = document.getElementById('routePreview');
      return {
        tabs: [...root.querySelectorAll('[data-ai-settings-tab]')].map(node => node.textContent.trim()),
        activeTab: root.querySelector('[data-ai-settings-tab].is-active')?.dataset.aiSettingsTab || '',
        cards: root.querySelectorAll('.dwrt-kit-overview-card').length,
        facts: root.querySelectorAll('.ai-settings-facts > div').length,
        providerFields: root.querySelectorAll('[data-ai-provider]').length,
        advancedFields: root.querySelectorAll('[data-ai-config="temperature"]').length,
        hasSave: root.querySelector('[data-ai-save]') !== null,
        text: root.innerText,
        overflow: document.documentElement.scrollWidth > innerWidth + 1 || root.scrollWidth > root.clientWidth + 1
      };
    });

    await page.locator('[data-ai-settings-tab="provider"]').click();
    await page.waitForTimeout(90);
    const providerTab = await page.evaluate(() => {
      const root = document.getElementById('routePreview');
      return {
        activeTab: root.querySelector('[data-ai-settings-tab].is-active')?.dataset.aiSettingsTab || '',
        providerButtons: root.querySelectorAll('[data-ai-provider]').length,
        authModes: root.querySelectorAll('[data-ai-auth-mode]').length,
        apiKeyType: root.querySelector('[data-ai-config="api_key_input"]')?.type || '',
        apiKeyValue: root.querySelector('[data-ai-config="api_key_input"]')?.value ?? null,
        overviewCards: root.querySelectorAll('.dwrt-kit-overview-card').length,
        temperature: root.querySelectorAll('[data-ai-config="temperature"]').length,
        hasSave: root.querySelector('[data-ai-save]') !== null
      };
    });

    await page.locator('[data-ai-settings-tab="advanced"]').click();
    await page.waitForTimeout(90);
    // change a value on the advanced tab, then leave and come back
    await page.selectOption('[data-ai-config="tool_policy"]', 'confirm_all');
    const advancedTab = await page.evaluate(() => {
      const root = document.getElementById('routePreview');
      return {
        activeTab: root.querySelector('[data-ai-settings-tab].is-active')?.dataset.aiSettingsTab || '',
        temperature: root.querySelectorAll('[data-ai-config="temperature"]').length,
        model: root.querySelectorAll('[data-ai-config="model"]').length,
        apiBase: root.querySelectorAll('[data-ai-config="api_base"]').length,
        systemPrompt: root.querySelectorAll('[data-ai-config="system_prompt"]').length,
        providerButtons: root.querySelectorAll('[data-ai-provider]').length,
        overviewCards: root.querySelectorAll('.dwrt-kit-overview-card').length,
        toolPolicy: root.querySelector('[data-ai-config="tool_policy"]')?.value || '',
        hasSave: root.querySelector('[data-ai-save]') !== null
      };
    });

    await page.locator('[data-ai-settings-tab="overview"]').click();
    await page.waitForTimeout(90);
    const backToOverview = await page.evaluate(() => {
      const root = document.getElementById('routePreview');
      return {
        activeTab: root.querySelector('[data-ai-settings-tab].is-active')?.dataset.aiSettingsTab || '',
        text: root.innerText,
        writes: window.LLM_SETTINGS_FIXTURE.writes.length,
        keyLeak: /sk-[A-Za-z0-9]{6,}/.test(root.innerHTML),
        overflow: document.documentElement.scrollWidth > innerWidth + 1
      };
    });

    results.push({ viewport, overviewTab, providerTab, advancedTab, backToOverview });
  }
  await browser.close();
  process.stdout.write(JSON.stringify({ results, consoleErrors }));
})().catch(error => { console.error(error); process.exit(1); });
"""
    environment = os.environ.copy()
    environment["NODE_PATH"] = str(NODE_MODULES)
    result = subprocess.run([str(NODE), "-e", script], cwd=ROOT, env=environment, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    data = json.loads(result.stdout)
    assert not data["consoleErrors"], data["consoleErrors"]
    for entry in data["results"]:
        overview = entry["overviewTab"]
        assert overview["tabs"] == ["概览", "供应商设置", "高级设置"], entry
        assert overview["activeTab"] == "overview", entry
        assert overview["cards"] == 4, entry
        assert overview["facts"] == 4, entry
        assert overview["providerFields"] == 0 and overview["advancedFields"] == 0, entry
        assert overview["hasSave"], entry
        assert not overview["overflow"], entry

        provider = entry["providerTab"]
        assert provider["activeTab"] == "provider", entry
        assert provider["providerButtons"] >= 2, entry
        assert provider["authModes"] == 2, entry
        assert provider["apiKeyType"] == "password" and provider["apiKeyValue"] == "", entry
        assert provider["overviewCards"] == 0 and provider["temperature"] == 0, entry
        assert provider["hasSave"], entry

        advanced = entry["advancedTab"]
        assert advanced["activeTab"] == "advanced", entry
        assert advanced["temperature"] == 1 and advanced["model"] == 1, entry
        assert advanced["apiBase"] == 1 and advanced["systemPrompt"] == 1, entry
        assert advanced["providerButtons"] == 0 and advanced["overviewCards"] == 0, entry
        assert advanced["toolPolicy"] == "confirm_all", entry
        assert advanced["hasSave"], entry

        back = entry["backToOverview"]
        assert back["activeTab"] == "overview", entry
        # tab switching must never write to the device
        assert back["writes"] == 0, entry
        # the unsaved advanced-tab edit must survive a tab round trip
        assert "有未保存的修改" in back["text"], entry
        assert not back["keyLeak"], entry
        assert not back["overflow"], entry
    print("ok: LLM settings fixture passes 1440/1024/375 layouts, tab isolation and state retention")
finally:
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
