#!/usr/bin/env python3
"""Fixture gate for the AI assistant streaming + agentic tool loop wiring (B-01..B-04).

Exercises the real backend contract shape:
  POST /api/v1/ai/chat/stream        -> SSE frames (response.delta, response.requires_action)
  POST /api/v1/ai/tool-authorize     -> { id, approve, defer_continuation }
  POST /api/v1/ai/tool-resume/stream -> SSE frames (tool.call.completed, response.completed)

Asserts that the frontend streams deltas incrementally, surfaces a tool
authorization card with risk + parameters, sends the numeric auth id from
`execution.auth_id`, and resumes the loop to render the final answer.
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
    ["python3", "-m", "http.server", "18781", "--bind", "127.0.0.1"],
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
  await page.goto('http://127.0.0.1:18781/tests/fixtures/ai-assistant-stream.html', { waitUntil: 'networkidle' });
  await page.waitForSelector('[data-ai-prompt]:not([disabled])', { timeout: 8000 });

  await page.fill('[data-ai-prompt]', '帮我重启 dnsmasq');
  await page.click('[data-ai-send]');

  // Round 1 must stream the deltas into an assistant bubble and stop for authorization.
  await page.waitForSelector('.ai-tool-auth-card', { timeout: 8000 });
  const round1 = await page.evaluate(() => ({
    streamedText: [...document.querySelectorAll('.ai-message.is-assistant .ai-message-content')].map((n) => n.textContent.trim()),
    authCards: [...document.querySelectorAll('.ai-tool-auth-card')].map((card) => ({
      title: card.querySelector('strong')?.textContent.trim(),
      badge: card.querySelector('.dwrt-kit-status-badge span')?.textContent.trim() || null,
      params: card.querySelector('.ai-tool-auth-params')?.textContent.trim() || null,
      approveId: card.querySelector('[data-ai-tool-approve]')?.getAttribute('data-ai-tool-approve'),
    })),
    toolChips: [...document.querySelectorAll('.ai-tool-chip')].map((n) => n.textContent.replace(/\s+/g, ' ').trim()),
  }));

  await page.click('[data-ai-tool-approve]');

  // Round 2: resume stream renders the final reply and clears the auth card.
  await page.waitForFunction(() => {
    const bodies = [...document.querySelectorAll('.ai-message.is-assistant .ai-message-content')];
    return !document.querySelector('.ai-tool-auth-card')
      && bodies.some((n) => n.textContent.includes('dnsmasq 已重启'));
  }, { timeout: 8000 });

  const round2 = await page.evaluate(() => ({
    assistantText: [...document.querySelectorAll('.ai-message.is-assistant .ai-message-content')].map((n) => n.textContent.trim()),
    authCards: document.querySelectorAll('.ai-tool-auth-card').length,
    caret: document.querySelectorAll('.ai-stream-caret').length,
    title: document.querySelector('.ai-copilot-title strong')?.textContent.trim() || null,
  }));

  const calls = await page.evaluate(() => window.__aiCalls || []);
  await browser.close();
  console.log(JSON.stringify({ round1, round2, calls, errors }));
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

# 1. Streaming endpoint is used instead of the blocking one when streaming_ready is true.
assert any(p.endswith("/api/v1/ai/chat/stream") for p in paths), f"expected chat/stream POST, got {paths}"
assert not any(p.endswith("/api/v1/ai/chat") for p in paths), f"blocking /ai/chat must not be used when streaming is ready: {paths}"

# 2. Tool registry is read so tool labels/descriptions are real.
assert any(p.endswith("/api/v1/ai/tools") for p in paths), f"expected ai/tools GET, got {paths}"

# 3. Deltas were streamed into the bubble before the pause.
streamed = result["round1"]["streamedText"]
assert any("正在检查系统状态" in t for t in streamed), f"expected streamed deltas concatenated, got {streamed}"

# 4. Authorization card shows the real tool label, risk badge and parameters.
cards = result["round1"]["authCards"]
assert len(cards) == 1, f"expected one authorization card, got {cards}"
card = cards[0]
assert card["title"] == "重启服务", f"card must use tool registry label, got {card['title']!r}"
assert card["badge"] == "中风险", f"card must show risk level, got {card['badge']!r}"
assert card["params"] and "dnsmasq" in card["params"], f"card must show tool parameters, got {card['params']!r}"
assert card["approveId"] == "42", f"approve button must carry execution.auth_id, got {card['approveId']!r}"

# 5. The authorize POST uses the backend contract field names.
authorize = [c for c in calls if c["url"].endswith("/api/v1/ai/tool-authorize")]
assert authorize, f"expected tool-authorize POST, got {paths}"
body = authorize[-1]["body"] or {}
assert body.get("id") == 42, f"tool-authorize must send numeric id, got {body}"
assert body.get("approve") is True, f"approve must be true, got {body}"
assert body.get("defer_continuation") is True, f"streaming resume requires defer_continuation, got {body}"

# 6. Resume continues over SSE and the final answer lands, with no leftover caret/card.
assert any(p.endswith("/api/v1/ai/tool-resume/stream") for p in paths), f"expected tool-resume/stream POST, got {paths}"
assert result["round2"]["authCards"] == 0, "authorization card must clear after resume"
assert result["round2"]["caret"] == 0, "streaming caret must clear when the response completes"
assert any("dnsmasq 已重启" in t for t in result["round2"]["assistantText"]), f"final reply missing: {result['round2']['assistantText']}"
assert result["round2"]["title"] == "重启 DNS 服务", f"conversation title from stream not applied: {result['round2']['title']!r}"

# 7. History is persisted after the loop completes.
assert any(p.endswith("/api/v1/ai/history") and c["method"] == "POST" for p, c in zip(paths, calls)), \
    f"expected conversation persistence POST, got {paths}"

print("ok: AI streaming + tool authorization + resume loop wired (SSE deltas, auth card, auth_id, resume, persistence)")
print(json.dumps(result, ensure_ascii=False)[:2000])
