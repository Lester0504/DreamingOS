#!/usr/bin/env python3
"""Fixture gate for the Aegisx 识别 (identification) wiring.

Verifies that when the backend `aegis/identification` capability is online
(the real 30.1 contract: mode=device_and_traffic, capabilities all true), the
frontend renders the three mode radios ENABLED (no more hardcoded "后端未开放"),
preselects the live mode, shows a live status badge, and POSTs the mapped mode
value when the user picks a different option.
"""
import json
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies"
NODE = Path(shutil.which("node") or RUNTIME / "node/bin/node")
NODE_MODULES = RUNTIME / "node/node_modules"

if not NODE.is_file():
    raise SystemExit(f"Node.js not found: {NODE}")
if not (NODE_MODULES / "playwright").exists():
    raise SystemExit(f"Playwright not found: {NODE_MODULES / 'playwright'}")

server = subprocess.Popen(
    ["python3", "-m", "http.server", "18774", "--bind", "127.0.0.1"],
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
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto('http://127.0.0.1:18774/tests/fixtures/aegisx-identification.html', { waitUntil: 'networkidle' });
  await page.waitForSelector('input[name="identification"]');
  await page.waitForFunction(() => {
    const r = [...document.querySelectorAll('input[name="identification"]')];
    return r.length === 3 && r.some((x) => !x.disabled);
  }, { timeout: 5000 });

  const before = await page.evaluate(() => {
    const radios = [...document.querySelectorAll('input[name="identification"]')];
    const rows = [...document.querySelectorAll('.aegisx-setting-row')];
    const idRow = rows.find((r) => r.querySelector('.aegisx-setting-label span')?.textContent.trim() === '识别');
    const badge = idRow?.querySelector('.dwrt-kit-status-badge');
    return {
      radios: radios.map((r) => ({ value: r.value, checked: r.checked, disabled: r.disabled })),
      badgeText: badge?.querySelector('span')?.textContent.trim() || null,
      badgeTone: badge?.getAttribute('data-dwrt-status') || null,
      version: document.querySelector('[data-aegisx-version]')?.dataset.aegisxVersion || null,
    };
  });

  await page.evaluate(() => {
    const el = document.querySelector('input[name="identification"][value="traffic"]');
    el.checked = true;
    el.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await page.waitForFunction(() => (window.__aegisPosts || []).length >= 1, { timeout: 5000 });
  const posts = await page.evaluate(() => window.__aegisPosts || []);

  await browser.close();
  console.log(JSON.stringify({ before, posts, errors }));
})().catch((e) => { console.error(e); process.exit(1); });
"""
    out = subprocess.run(
        [str(NODE), "-e", script],
        cwd=ROOT, capture_output=True, text=True,
        env={"NODE_PATH": str(NODE_MODULES), "PATH": f"{NODE.parent}:/usr/bin:/bin"},
    )
    if out.returncode != 0:
        raise SystemExit(f"fixture run failed:\n{out.stdout}\n{out.stderr}")
    result = json.loads(out.stdout.strip().splitlines()[-1])
finally:
    server.terminate()

errors = result.get("errors") or []
assert not errors, f"page errors: {errors}"

before = result["before"]
radios = before["radios"]
assert len(radios) == 3, f"expected 3 identification radios, got {radios}"
assert all(not r["disabled"] for r in radios), f"identification radios must be enabled when capability is online: {radios}"
selected = [r["value"] for r in radios if r["checked"]]
assert selected == ["device_traffic"], f"expected device_traffic preselected, got {selected}"
assert before["badgeText"] and before["badgeText"] != "后端未开放", f"badge should reflect live state, got {before['badgeText']!r}"
assert before["badgeTone"] == "warning", f"pending_readback should render warning tone, got {before['badgeTone']!r}"

posts = result["posts"]
assert posts and posts[-1].get("mode") in ("traffic_only", "traffic"), f"selecting traffic-only must POST a traffic-only mode, got {posts}"

print("ok: Aegisx identification wired to live capability (radios enabled, mode preselected, badge live, POST sent)")
print(json.dumps(result, ensure_ascii=False))
