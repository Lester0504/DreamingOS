#!/usr/bin/env python3
"""Read-only browser fixture for Gateway Shadow capability and layout behavior."""

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
    ["python3", "-m", "http.server", "18773", "--bind", "127.0.0.1"],
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
    await page.goto('http://127.0.0.1:18773/tests/fixtures/gateway-shadow.html', { waitUntil: 'networkidle' });
    await page.waitForFunction(() => window.GATEWAY_SHADOW_FIXTURE);
    if (!await page.evaluate(() => window.GATEWAY_SHADOW_FIXTURE.ready())) throw new Error('fixture did not become ready');
    const status = await page.evaluate(viewport => {
      const root = document.getElementById('routePreview');
      return {
        viewport, tabs: [...root.querySelectorAll('[data-shadow-tab]')].map(node => node.textContent.trim()),
        text: root.innerText, statusValues: [...root.querySelectorAll('.shadow-status-grid dd')].map(node => node.textContent.trim()),
        sampled: root.querySelectorAll('[data-adaptive-sample]').length,
        unsampled: root.querySelectorAll('[data-adaptive-sample]:not([data-adaptive-region])').length,
        overflow: document.documentElement.scrollWidth > innerWidth + 1 || root.scrollWidth > root.clientWidth + 1,
        workbenchOverflow: getComputedStyle(root.querySelector('.gateway-shadow-workbench')).overflowY
      };
    }, viewport);
    await page.locator('[data-shadow-tab="config"]').click();
    await page.waitForTimeout(80);
    const config = await page.evaluate(() => ({
      applyDisabled: document.querySelector('[data-shadow-confirm="apply"]').disabled,
      preflightDisabled: document.querySelector('[data-shadow-preflight]').disabled,
      saveDisabled: document.querySelector('[data-shadow-save]').disabled,
      passwordType: document.querySelector('[data-shadow-field="auth_key"]').type,
      passwordValue: document.querySelector('[data-shadow-field="auth_key"]').value,
      forcedPreempt: document.querySelector('[data-shadow-field="preempt"]') !== null,
      overflow: document.documentElement.scrollWidth > innerWidth + 1 || document.getElementById('routePreview').scrollWidth > document.getElementById('routePreview').clientWidth + 1
    }));
    await page.locator('[data-shadow-preflight]').click();
    await page.waitForTimeout(80);
    const afterPreflight = await page.evaluate(() => ({
      checks: document.querySelectorAll('.shadow-preflight li').length,
      failed: document.querySelectorAll('.shadow-preflight li.is-fail').length,
      applyDisabled: document.querySelector('[data-shadow-confirm="apply"]').disabled,
      text: document.querySelector('.gateway-shadow-workbench').innerText
    }));
    await page.locator('[data-shadow-tab="pairing"]').click();
    const pairing = await page.evaluate(() => ({
      cards: document.querySelectorAll('.shadow-pair-card').length,
      codeType: document.querySelector('[data-shadow-pair-input="inputCode"]').type,
      writes: window.GATEWAY_SHADOW_FIXTURE.writes.length,
      sensitiveStorage: Object.keys(localStorage).filter(key => /pair|challenge|auth_key/i.test(key)).length,
      overflow: document.documentElement.scrollWidth > innerWidth + 1 || document.getElementById('routePreview').scrollWidth > document.getElementById('routePreview').clientWidth + 1
    }));
    results.push({ status, config, afterPreflight, pairing });
  }
  await browser.close();
  process.stdout.write(JSON.stringify({ results, consoleErrors }));
})().catch(error => { console.error(error); process.exit(1); });
"""
    environment = os.environ.copy()
    environment["NODE_PATH"] = str(NODE_MODULES)
    result = subprocess.run([str(NODE), "-e", script], cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    data = json.loads(result.stdout)
    assert not data["consoleErrors"], data
    for result in data["results"]:
        status = result["status"]
        assert status["tabs"] == ["运行状态", "配置", "设备配对"], result
        assert status["statusValues"][3] == "未知", result
        assert "FAULT" in status["text"] and "best effort" in status["text"] and "split-brain" in status["text"], result
        assert status["sampled"] >= 3 and status["unsampled"] == 0, result
        assert not status["overflow"] and status["workbenchOverflow"] == "auto", result
        config = result["config"]
        assert config["applyDisabled"] and not config["preflightDisabled"] and config["saveDisabled"], result
        assert config["passwordType"] == "password" and config["passwordValue"] == "", result
        assert not config["forcedPreempt"] and not config["overflow"], result
        preflight = result["afterPreflight"]
        assert preflight["checks"] == 6 and preflight["failed"] == 3 and preflight["applyDisabled"], result
        assert "未安装 keepalived" in preflight["text"] and "未安装 conntrackd" in preflight["text"], result
        pairing = result["pairing"]
        assert pairing["cards"] == 2 and pairing["codeType"] == "password", result
        assert pairing["writes"] == 1 and pairing["sensitiveStorage"] == 0 and not pairing["overflow"], result
    print("ok: Gateway Shadow fixture passes 1440/1024/375 layouts and fail-closed controls")
finally:
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
