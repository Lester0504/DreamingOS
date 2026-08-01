#!/usr/bin/env python3
"""Fixture gate for the AI assistant BLOCKING fallback (the live 30.1 state).

30.1 currently reports streaming:true but streaming_ready:false (no provider
connected), so the frontend must NOT hit /ai/chat/stream. This gate asserts the
fallback still runs the agentic tool loop over the non-streaming routes:
  POST /api/v1/ai/chat            -> pending_authorizations + resume_token
  POST /api/v1/ai/tool-authorize  -> { id, approve, defer_continuation:false }
                                     with the continuation payload consumed inline
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
    ["python3", "-m", "http.server", "18782", "--bind", "127.0.0.1"],
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
  await page.goto('http://127.0.0.1:18782/tests/fixtures/ai-assistant-blocking.html', { waitUntil: 'networkidle' });
  await page.waitForSelector('[data-ai-prompt]:not([disabled])', { timeout: 8000 });
  await page.fill('[data-ai-prompt]', '帮我重启 dnsmasq');
  await page.click('[data-ai-send]');
  await page.waitForSelector('.ai-tool-auth-card', { timeout: 8000 });
  const approveId = await page.getAttribute('[data-ai-tool-approve]', 'data-ai-tool-approve');
  await page.click('[data-ai-tool-approve]');
  await page.waitForFunction(() => {
    const bodies = [...document.querySelectorAll('.ai-message.is-assistant .ai-message-content')];
    return !document.querySelector('.ai-tool-auth-card') && bodies.some((n) => n.textContent.includes('dnsmasq 已重启'));
  }, { timeout: 8000 });
  const finalText = await page.evaluate(() => [...document.querySelectorAll('.ai-message.is-assistant .ai-message-content')].map((n) => n.textContent.trim()));
  const calls = await page.evaluate(() => window.__aiCalls || []);
  await browser.close();
  console.log(JSON.stringify({ approveId, finalText, calls, errors }));
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

calls = result["calls"]
paths = [c["url"] for c in calls]

assert not any(p.endswith("/api/v1/ai/chat/stream") for p in paths), \
    f"streaming must not be used when streaming_ready is false: {paths}"
assert any(p.endswith("/api/v1/ai/chat") for p in paths), f"expected blocking /ai/chat POST, got {paths}"
assert result["approveId"] == "42", f"auth id must come from execution.auth_id, got {result['approveId']!r}"

authorize = [c for c in calls if c["url"].endswith("/api/v1/ai/tool-authorize")]
assert authorize, f"expected tool-authorize POST, got {paths}"
body = authorize[-1]["body"] or {}
assert body.get("id") == 42, f"tool-authorize must send numeric id, got {body}"
assert body.get("defer_continuation") is False, \
    f"without streaming resume the continuation must run inline (defer_continuation=false), got {body}"

assert any("dnsmasq 已重启" in t for t in result["finalText"]), f"final reply missing: {result['finalText']}"

print("ok: blocking fallback keeps the tool loop working when streaming_ready is false")
print(json.dumps({"approveId": result["approveId"], "paths": paths}, ensure_ascii=False))
