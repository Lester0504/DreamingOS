#!/usr/bin/env python3
import json
import os
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "skills/playwright/scripts/playwright_cli.sh"
SESSION = "dwrt-logs-legacy-fixture"


if not WRAPPER.is_file():
    raise SystemExit(f"Playwright CLI wrapper not found: {WRAPPER}")


server = subprocess.Popen(
    ["python3", "-m", "http.server", "18768", "--bind", "127.0.0.1"],
    cwd=ROOT,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    time.sleep(.4)
    opened = subprocess.run(
        [str(WRAPPER), f"-s={SESSION}", "open", "http://127.0.0.1:18768/tests/fixtures/logs-phase2.html"],
        cwd=ROOT, capture_output=True, text=True, timeout=60,
    )
    if opened.returncode:
        raise RuntimeError(opened.stdout + opened.stderr)
    function = r"""async page => {
      await page.waitForFunction(() => window.LOGS_FIXTURE_READY === true);
      const result = { viewports: [], behavior: {}, lifecycle: {} };
      const search = page.locator('[data-log-search]');
      await search.fill('Fixture');
      await page.waitForTimeout(800);
      const tableScroll = page.locator('.log-center-table-scroll');
      const scroll = await tableScroll.evaluate(node => {
        node.scrollTop = Math.min(320, node.scrollHeight - node.clientHeight);
        node.dispatchEvent(new Event('scroll'));
        return { top: node.scrollTop, scrollHeight: node.scrollHeight, clientHeight: node.clientHeight };
      });
      const firstRow = page.locator('[data-log-row]').first();
      await firstRow.click();
      await page.waitForTimeout(120);
      result.behavior = {
        shell: await page.locator('[data-log-center-shell]').count(),
        filter: await page.locator('.log-center-filter').count(),
        main: await page.locator('.log-center-main').count(),
        rows: await page.locator('[data-log-row]').count(),
        searchValue: await search.inputValue(),
        scroll,
        drawerOpen: await page.locator('.log-center-drawer.is-open').count(),
        drawerText: await page.locator('.log-center-drawer.is-open').innerText(),
        requests: await page.evaluate(() => window.LOGS_FIXTURE.requests())
      };
      await page.locator('[data-log-close-drawer]').click();
      result.behavior.drawerClosed = await page.locator('.log-center-drawer.is-open').count() === 0;

      for (const viewport of [{ width: 1440, height: 1000 }, { width: 1024, height: 768 }, { width: 390, height: 844 }]) {
        await page.setViewportSize(viewport);
        await page.evaluate(() => window.LOGS_FIXTURE.mount());
        await page.waitForTimeout(150);
        result.viewports.push(await page.evaluate(viewport => {
          const root = document.getElementById('routePreview');
          const shell = root.querySelector('[data-log-center-shell]');
          return {
            ...viewport,
            shell: Boolean(shell),
            filter: Boolean(root.querySelector('.log-center-filter')),
            table: Boolean(root.querySelector('.log-center-table-card')),
            rows: root.querySelectorAll('[data-log-row]').length,
            pageOverflow: document.documentElement.scrollWidth > innerWidth + 1,
            tableScrollWidth: root.querySelector('.log-center-table-scroll')?.scrollWidth || 0,
            tableClientWidth: root.querySelector('.log-center-table-scroll')?.clientWidth || 0
          };
        }, viewport));
      }
      result.lifecycle = await page.evaluate(() => window.LOGS_FIXTURE.unmount());
      return result;
    }"""
    completed = subprocess.run(
        [str(WRAPPER), "--raw", f"-s={SESSION}", "run-code", function],
        cwd=ROOT, capture_output=True, text=True, timeout=90,
    )
    if completed.returncode:
        raise RuntimeError(completed.stdout + completed.stderr)
    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"logs fixture returned invalid JSON: {completed.stdout[:1200]!r}; stderr={completed.stderr!r}") from error
    behavior = data["behavior"]
    assert behavior["shell"] == behavior["filter"] == behavior["main"] == 1, behavior
    assert behavior["rows"] == 25 and behavior["searchValue"] == "Fixture", behavior
    assert behavior["scroll"]["scrollHeight"] >= behavior["scroll"]["clientHeight"], behavior
    assert behavior["drawerOpen"] == 1 and "Fixture 旧版日志" in behavior["drawerText"], behavior
    assert behavior["drawerClosed"] is True and behavior["requests"] >= 1, behavior
    assert len(data["viewports"]) == 3
    assert all(item["shell"] and item["filter"] and item["table"] and item["rows"] == 25 for item in data["viewports"]), data["viewports"]
    assert all(not item["pageOverflow"] for item in data["viewports"]), data["viewports"]
    assert all(item["tableScrollWidth"] >= item["tableClientWidth"] for item in data["viewports"]), data["viewports"]
    assert data["lifecycle"] == {"children": 0}, data["lifecycle"]
    print("ok: restored legacy logs pass layout, search, table scrolling, detail drawer, lifecycle, and three viewports")
finally:
    subprocess.run([str(WRAPPER), f"-s={SESSION}", "close"], cwd=ROOT, capture_output=True, text=True)
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
