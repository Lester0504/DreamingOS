#!/usr/bin/env python3
"""Three-viewport fixture for capability-gated flowd NFT revision readback."""

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
    ["python3", "-m", "http.server", "18777", "--bind", "127.0.0.1"],
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
const fs = require('fs');
const path = require('path');
(async () => {
  const browser = await chromium.launch({ headless: true, channel: 'chrome' });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const consoleErrors = [];
  page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });
  page.on('pageerror', error => consoleErrors.push(error.message));
  await page.route('**/static/css/policy-entities.css*', route => route.fulfill({
    status: 200,
    contentType: 'text/css',
    body: fs.readFileSync(path.join(process.cwd(), 'files/www/dreamingwrt/static/css/policy-entities.css'))
  }));
  await page.goto('http://127.0.0.1:18777/tests/fixtures/flow-engine-runtime.html', { waitUntil: 'networkidle' });
  await page.waitForFunction(() => Boolean(window.FLOW_ENGINE_FIXTURE));
  const results = [];
  for (const scenario of ['legacy', 'modern']) {
    for (const viewport of [{ width: 1440, height: 1000 }, { width: 1024, height: 768 }, { width: 390, height: 844 }]) {
      await page.setViewportSize(viewport);
      const contract = await page.evaluate(value => window.FLOW_ENGINE_FIXTURE.remount(value), scenario);
      results.push({ scenario, viewport, contract });
    }
  }
  await browser.close();
  process.stdout.write(JSON.stringify({ consoleErrors, results }));
})().catch(error => { console.error(error); process.exit(1); });
"""
    env = os.environ.copy()
    env["NODE_PATH"] = str(NODE_MODULES)
    result = subprocess.run(
        [str(NODE), "-e", script], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    data = json.loads(result.stdout)
    assert not data["consoleErrors"], data
    for item in data["results"]:
        contract = item["contract"]
        assert contract["writes"] == 0, item
        assert not contract["pageOverflow"] and not contract["rootOverflow"], item
        assert contract["transparentRoot"] and contract["workbenchScrollable"], item
        assert "配置状态" in contract["text"] and "运行应用" in contract["text"], item
        if item["scenario"] == "legacy":
            assert contract["nftRequests"] == 0, item
            assert "未读取 NFT revision" in contract["text"], item
            assert "当前固件未提供运行态真值" in contract["text"], item
        else:
            assert contract["nftRequests"] == 1, item
            assert "仅所有权 sentinel" in contract["text"], item
            assert "不包含分流、QoS、路由、配额或应用策略规则" in contract["text"], item
            assert "fixture-revision-1" in contract["text"], item
    print("ok: flow engine requests NFT revision only when capability exists and preserves sentinel-only truth in three viewports")
finally:
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
