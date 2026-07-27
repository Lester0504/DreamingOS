#!/usr/bin/env python3
import json
import os
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "skills/playwright/scripts/playwright_cli.sh"
SESSION = "dwrt-ui-kit-async-button-fixture"


if not WRAPPER.is_file():
    raise SystemExit(f"Playwright CLI wrapper not found: {WRAPPER}")


server = subprocess.Popen(
    ["python3", "-m", "http.server", "18769", "--bind", "127.0.0.1"],
    cwd=ROOT,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    time.sleep(.4)
    opened = subprocess.run(
        [str(WRAPPER), f"-s={SESSION}", "open", "http://127.0.0.1:18769/tests/fixtures/ui-kit-async-button.html"],
        cwd=ROOT, capture_output=True, text=True, timeout=60,
    )
    if opened.returncode:
        raise RuntimeError(opened.stdout + opened.stderr)
    function = r"""async page => {
      const button = page.locator('[data-dwrt-component="async-button"]');
      await page.waitForFunction(() => document.querySelector('.dwrt-kit-button'));
      const idle = await button.evaluate(node => ({
        busy: node.getAttribute('aria-busy'), disabled: node.getAttribute('aria-disabled'), loading: node.classList.contains('is-loading')
      }));
      await button.evaluate(node => { node.dataset.dwrtState = 'loading'; });
      await page.waitForTimeout(50);
      const loading = await button.evaluate(node => ({
        busy: node.getAttribute('aria-busy'), disabled: node.getAttribute('aria-disabled'), loading: node.classList.contains('is-loading')
      }));
      const timerAdvanced = await page.evaluate(() => new Promise(resolve => setTimeout(() => resolve(true), 40)));
      await button.evaluate(node => { node.dataset.dwrtState = 'idle'; });
      await page.waitForTimeout(50);
      const settled = await button.evaluate(node => ({
        busy: node.getAttribute('aria-busy'), disabled: node.getAttribute('aria-disabled'), loading: node.classList.contains('is-loading')
      }));
      return { idle, loading, timerAdvanced, settled };
    }"""
    completed = subprocess.run(
        [str(WRAPPER), "--raw", f"-s={SESSION}", "run-code", function],
        cwd=ROOT, capture_output=True, text=True, timeout=30,
    )
    if completed.returncode:
        raise RuntimeError(completed.stdout + completed.stderr)
    data = json.loads(completed.stdout)
    assert data["idle"] == {"busy": "false", "disabled": None, "loading": False}, data
    assert data["loading"] == {"busy": "true", "disabled": "true", "loading": True}, data
    assert data["timerAdvanced"] is True, data
    assert data["settled"] == {"busy": "false", "disabled": None, "loading": False}, data
    print("ok: async-button state observer is idempotent and does not starve the event loop")
finally:
    subprocess.run([str(WRAPPER), f"-s={SESSION}", "close"], cwd=ROOT, capture_output=True, text=True)
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
