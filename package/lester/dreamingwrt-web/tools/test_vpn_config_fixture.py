#!/usr/bin/env python3
"""Browser fixture for VPN empty-state, guided forms, and responsive bounds."""

import json
import os
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "skills/playwright/scripts/playwright_cli.sh"
SESSION = "dwrt-vpn-config-fixture"

if not WRAPPER.is_file():
    raise SystemExit(f"Playwright CLI wrapper not found: {WRAPPER}")

server = subprocess.Popen(
    ["python3", "-m", "http.server", "18771", "--bind", "127.0.0.1"],
    cwd=ROOT,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.PIPE,
    text=True,
)

try:
    time.sleep(.4)
    if server.poll() is not None:
        raise RuntimeError(f"fixture server failed: {(server.stderr.read() if server.stderr else '').strip()}")
    opened = subprocess.run(
        [str(WRAPPER), f"-s={SESSION}", "open", "http://127.0.0.1:18771/tests/fixtures/vpn-config.html"],
        cwd=ROOT, capture_output=True, text=True, timeout=60,
    )
    if opened.returncode:
        raise RuntimeError(opened.stdout + opened.stderr)
    function = r"""async page => {
      const consoleErrors = [];
      page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });
      page.on('pageerror', error => consoleErrors.push(error.message));
      const viewports = [{width:1440,height:1000},{width:1024,height:768},{width:390,height:844}];
      const results = [];
      for (const viewport of viewports) {
        await page.setViewportSize(viewport);
        await page.reload({ waitUntil: 'domcontentloaded' });
        await page.waitForFunction(() => window.VPN_FIXTURE);
        await page.evaluate(() => window.VPN_FIXTURE.ready());
        const home = await page.evaluate(() => {
          const root = document.querySelector('#routePreview');
          const visible = element => {
            const rect = element.getBoundingClientRect();
            const style = getComputedStyle(element);
            return rect.width > 0 && rect.height > 0 && style.display !== 'none' && style.visibility !== 'hidden';
          };
          const controls = Array.from(root.querySelectorAll('button,input,select')).filter(visible);
          const unnamed = controls.filter(element => !(element.getAttribute('aria-label') || element.closest('label') || element.textContent?.trim())).length;
          return {
            sections: Array.from(root.querySelectorAll('.vpn-section-copy > strong')).map(node => node.textContent.trim()),
            rows: root.querySelectorAll('.vpn-table tbody tr').length,
            unavailable: root.querySelectorAll('.vpn-empty-state[data-dwrt-state="unavailable"]').length,
            postRequests: window.VPN_FIXTURE.requests.filter(request => request.method !== 'GET').length,
            overflow: document.documentElement.scrollWidth > innerWidth + 1 || root.scrollWidth > root.clientWidth + 1,
            unnamed
          };
        });
        const inspectDrawer = async (action, protocol, expectedText) => {
          await page.locator(`[data-vpn-action="${action}"]`).click();
          await page.waitForTimeout(700);
          if (protocol) {
            await page.locator(`[data-vpn-protocol="${protocol}"]`).click();
            await page.waitForTimeout(80);
          }
          const result = await page.evaluate(expectedText => {
            const sheet = document.querySelector('.vpn-config-sheet.is-open');
            const rect = sheet.getBoundingClientRect();
            const text = sheet.textContent;
            return {
              open: Boolean(sheet),
              expected: text.includes(expectedText),
              gated: text.includes('后端写入接口未开放'),
              saveDisabled: Boolean(sheet.querySelector('[data-vpn-action="save"]:disabled')),
              right: Math.abs(innerWidth - rect.right),
              leftInside: rect.left >= -1,
              overflow: sheet.scrollWidth > sheet.clientWidth + 1
            };
          }, expectedText);
          await page.locator('[data-vpn-action="close"]').last().click();
          await page.waitForTimeout(60);
          return result;
        };
        const server = await inspectDrawer('create-server', 'wireguard', 'IPv6 网关 / 子网');
        const client = await inspectDrawer('create-client', 'openvpn', '内容向导');
        const site = await inspectDrawer('create-site', 'ipsec', 'ESP 生存期');
        results.push({ viewport, home, server, client, site });
      }
      return { results, consoleErrors };
    }"""
    result = subprocess.run(
        [str(WRAPPER), "--raw", f"-s={SESSION}", "run-code", function],
        cwd=ROOT, capture_output=True, text=True, timeout=90,
    )
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    data = json.loads(result.stdout)
    assert not data["consoleErrors"], data
    for result in data["results"]:
        home = result["home"]
        assert home["sections"] == ["Teleport", "VPN 服务器", "VPN 客户端", "站点到站点 VPN"], result
        assert home["rows"] == 0 and home["unavailable"] == 3, result
        assert home["postRequests"] == 0 and not home["overflow"] and home["unnamed"] == 0, result
        for key in ("server", "client", "site"):
            drawer = result[key]
            assert drawer["open"] and drawer["expected"] and drawer["gated"] and drawer["saveDisabled"], result
            assert drawer["right"] <= 1 and drawer["leftInside"] and not drawer["overflow"], result
    print("vpn config fixture passed at 1440, 1024, and 390 pixels")
finally:
    if WRAPPER.is_file():
        subprocess.run([str(WRAPPER), f"-s={SESSION}", "close"], cwd=ROOT, capture_output=True, text=True)
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
