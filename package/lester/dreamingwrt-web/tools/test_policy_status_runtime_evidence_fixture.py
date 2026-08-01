#!/usr/bin/env python3
"""Three-viewport browser contract for policy route runtime evidence."""

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
    ["python3", "-m", "http.server", "18778", "--bind", "127.0.0.1"],
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
  const errors = [];
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('http://127.0.0.1:18778/tests/fixtures/policy-status-runtime-evidence.html', { waitUntil: 'networkidle' });
  await page.waitForFunction(() => Boolean(window.POLICY_STATUS_RUNTIME_FIXTURE));
  const results = [];
  for (const scenario of ['aggregate', 'unavailable', 'legacy']) {
    for (const viewport of [{ width: 1440, height: 1000 }, { width: 1024, height: 768 }, { width: 390, height: 844 }]) {
      await page.setViewportSize(viewport);
      const contract = await page.evaluate(value => window.POLICY_STATUS_RUNTIME_FIXTURE.remount(value), scenario);
      results.push({ scenario, viewport, contract });
    }
  }
  const unmounted = await page.evaluate(() => window.POLICY_STATUS_RUNTIME_FIXTURE.unmount());
  await browser.close();
  process.stdout.write(JSON.stringify({ errors, results, unmounted }));
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
    assert not data["errors"], data
    for item in data["results"]:
        contract = item["contract"]
        assert contract["requests"] == [{"method": "GET", "url": "/api/v1/route_status"}], item
        assert contract["writes"] == 0 and contract["subscriptions"] == 2, item
        assert not contract["pageOverflow"] and not contract["rootOverflow"] and not contract["offenders"], item
        assert contract["transparentRoot"] and contract["tableScrollable"], item
        assert "命中样本" not in contract["text"] and "聚合命中" in contract["text"], item
        assert "未验证候选" in contract["evidence"] and "不计入命中" in contract["evidence"], item
        if item["scenario"] == "aggregate":
            assert contract["hits"] == ["12", "6"], item
            assert all(value != "未采集" for value in contract["lastHits"]), item
            assert "聚合计数" in contract["evidence"], item
            assert "jmx_route 内核计数" in contract["evidence"], item
            assert "规则级聚合计数" in contract["evidence"], item
            assert "内核聚合 18 次" in contract["text"], item
        else:
            assert contract["hits"] == ["--", "--"], item
            assert contract["lastHits"] == ["未采集", "未采集"], item
            assert "命中未采集" in contract["evidence"], item
            assert "内核聚合 0 次" not in contract["text"], item
    assert data["unmounted"] == {"subscriptions": 0, "activeTimers": 0, "children": 0}, data
    print("ok: policy status keeps aggregate counters, unavailable counters, and unverified candidates distinct in three viewports")
finally:
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
