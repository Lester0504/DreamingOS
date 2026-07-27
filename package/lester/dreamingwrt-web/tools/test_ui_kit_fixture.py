#!/usr/bin/env python3
import json
import os
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "skills/playwright/scripts/playwright_cli.sh"
SESSION = "dwrt-ui-kit-fixture"


if not WRAPPER.is_file():
    raise SystemExit(f"Playwright CLI wrapper not found: {WRAPPER}")


server = subprocess.Popen(
    ["python3", "-m", "http.server", "18765", "--bind", "127.0.0.1"],
    cwd=ROOT,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.PIPE,
    text=True,
)
try:
    time.sleep(.4)
    if server.poll() is not None:
        raise RuntimeError(f"fixture server failed to start: {(server.stderr.read() if server.stderr else '').strip()}")
    opened = subprocess.run(
        [str(WRAPPER), f"-s={SESSION}", "open", "http://127.0.0.1:18765/tests/fixtures/ui-kit-phase1.html"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if opened.returncode:
        raise RuntimeError(opened.stdout + opened.stderr)
    function = r"""async page => {
      const cdp = await page.context().newCDPSession(page);
      const tabs = page.locator('[data-dwrt-component="tabs"] .dwrt-kit-tab');
      await tabs.first().focus();
      await page.keyboard.press('ArrowRight');
      const selectedTab = await page.locator('[data-dwrt-component="tabs"] .dwrt-kit-tab[aria-selected="true"]').textContent();
      const switchInput = page.locator('[data-dwrt-component="switch"] input');
      const dependencyPanel = page.locator('[data-dwrt-dependency-panel]');
      const hiddenBefore = await dependencyPanel.evaluate(node => node.hidden);
      await switchInput.check();
      const hiddenAfter = await dependencyPanel.evaluate(node => node.hidden);
      const disclosure = page.locator('[data-dwrt-disclosure-trigger]');
      await disclosure.click();
      const disclosureOpen = await disclosure.getAttribute('aria-expanded');
      await page.locator('th[data-sort-key="name"]').click();
      const sort = await page.locator('th[data-sort-key="name"]').getAttribute('aria-sort');
      const interactions = {
        selectedTab,
        hiddenBefore,
        hiddenAfter,
        switchRole: await switchInput.getAttribute('role'),
        switchChecked: await switchInput.getAttribute('aria-checked'),
        disclosureOpen,
        sort,
        stateRole: await page.locator('[data-dwrt-component="state-panel"]').getAttribute('role'),
        fieldAssociated: await page.locator('input[type="number"]').evaluate(node => Boolean(node.getAttribute('aria-label') || node.getAttribute('aria-labelledby') || node.closest('label') || (node.id && document.querySelector(`label[for="${CSS.escape(node.id)}"]`)))),
        iconName: await page.locator('[data-dwrt-component="icon-button"]').getAttribute('aria-label'),
        smallTargets: await page.locator('[data-dwrt-component="button"], [data-dwrt-component="icon-button"], [data-dwrt-component="async-button"]').evaluateAll(nodes => nodes.filter(node => { const r=node.getBoundingClientRect(); return r.width < 44 || r.height < 44; }).length)
      };
      const sheetTrigger = page.locator('#sheetTrigger');
      await sheetTrigger.click();
      await page.waitForTimeout(260);
      interactions.sheetVariant = await page.locator('#fixtureSheet').getAttribute('data-dwrt-sheet-variant');
      interactions.sheetWallpaperLayers = await page.locator('#fixtureSheet > .dwrt-kit-sheet-wallpaper, #fixtureSheet > .dwrt-kit-sheet-material').count();
      interactions.sheetCanvasLayers = await page.locator('#fixtureSheet > canvas').count();
      await sheetTrigger.focus();
      interactions.sheetFocusOutsideBeforeEscape = await sheetTrigger.evaluate(node => document.activeElement === node);
      await page.keyboard.press('Escape');
      await page.waitForTimeout(700);
      interactions.sheetClosedFromOutsideFocus = await page.locator('#fixtureSheet.is-open').count() === 0;
      interactions.sheetFocusRestored = await sheetTrigger.evaluate(node => document.activeElement === node);
      await page.setViewportSize({ width: 390, height: 844 });
      await page.evaluate(() => window.openFullFixtureSheet());
      await page.waitForTimeout(260);
      interactions.fullSheetVariant = await page.locator('#fullFixtureSheet').getAttribute('data-dwrt-sheet-variant');
      interactions.fullSheetMaterialLayers = await page.locator('#fullFixtureSheet > .dwrt-kit-sheet-wallpaper, #fullFixtureSheet > .dwrt-kit-sheet-material').count();
      await page.locator('#fullSheetClose').click();
      await page.waitForTimeout(700);

      const scenarios = [];
      const audit = async ({ width, height, theme, wallpaper, foreground, reducedTransparency = false }) => {
        await page.setViewportSize({ width, height });
        await cdp.send('Emulation.setEmulatedMedia', {
          media: '',
          features: [{ name: 'prefers-reduced-transparency', value: reducedTransparency ? 'reduce' : 'no-preference' }]
        });
        await page.evaluate(({ theme, wallpaper, foreground }) => {
          document.documentElement.dataset.themeResolved = theme;
          document.body.dataset.wallpaper = wallpaper;
          const shell = document.querySelector('[data-dwrt-component="page-shell"]');
          shell.dataset.adaptiveRegion = foreground;
        }, { theme, wallpaper, foreground });
        await page.waitForTimeout(80);
        scenarios.push(await page.evaluate(({ width, height, theme, wallpaper, foreground, reducedTransparency }) => {
          const shell = document.querySelector('[data-dwrt-component="page-shell"]');
          const table = document.querySelector('[data-dwrt-component="data-table"]');
          const field = document.querySelector('input[type="number"]');
          const shellStyle = getComputedStyle(shell);
          const tableStyle = getComputedStyle(table);
          const shellRect = shell.getBoundingClientRect();
          return {
            width,
            height,
            theme,
            wallpaper,
            foreground,
            reducedTransparency,
            pageOverflow: document.documentElement.scrollWidth > innerWidth + 1,
            shellOverflow: shellRect.left < -1 || shellRect.right > innerWidth + 1,
            shellSurface: shell.dataset.dwrtSurface,
            tableSurface: table.dataset.dwrtSurface,
            shellColor: shellStyle.color,
            shellBackdrop: shellStyle.backdropFilter || shellStyle.webkitBackdropFilter,
            tableBackground: tableStyle.backgroundColor,
            fieldFontSize: parseFloat(getComputedStyle(field).fontSize),
            smallTargetDetails: Array.from(document.querySelectorAll('button, input, select, a[href]')).filter(node => {
              if (node.closest('[hidden]')) return false;
              const rect = node.getBoundingClientRect();
              const inViewport = rect.right > 0 && rect.bottom > 0 && rect.left < innerWidth && rect.top < innerHeight;
              return inViewport && rect.width > 0 && rect.height > 0 && (rect.width < 44 || rect.height < 44);
            }).map(node => { const rect = node.getBoundingClientRect(); const sheet = node.closest('.dwrt-kit-sheet'); return `${node.tagName.toLowerCase()}[${node.getAttribute('aria-label') || node.type || ''}]@${Math.round(rect.left)},${Math.round(rect.top)}:${Math.round(rect.width)}x${Math.round(rect.height)}:sheet=${sheet?.id || '-'}:${sheet?.className || '-'}`; }),
            smallTargets: Array.from(document.querySelectorAll('button, input, select, a[href]')).filter(node => {
              if (node.closest('[hidden]')) return false;
              const rect = node.getBoundingClientRect();
              const inViewport = rect.right > 0 && rect.bottom > 0 && rect.left < innerWidth && rect.top < innerHeight;
              return inViewport && rect.width > 0 && rect.height > 0 && (rect.width < 44 || rect.height < 44);
            }).length
          };
        }, { width, height, theme, wallpaper, foreground, reducedTransparency }));
      };

      await audit({ width: 1440, height: 1000, theme: 'dark', wallpaper: 'dark', foreground: 'light' });
      await audit({ width: 1024, height: 768, theme: 'light', wallpaper: 'bright', foreground: 'dark' });
      await audit({ width: 390, height: 844, theme: 'dark', wallpaper: 'dark', foreground: 'light' });
      await audit({ width: 390, height: 844, theme: 'light', wallpaper: 'bright', foreground: 'dark', reducedTransparency: true });
      return { interactions, scenarios };
    }"""
    result = subprocess.run(
        [str(WRAPPER), "--raw", f"-s={SESSION}", "run-code", function],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    data = json.loads(result.stdout)
    assert data["interactions"] == {
        "selectedTab": "视图二",
        "hiddenBefore": True,
        "hiddenAfter": False,
        "switchRole": "switch",
        "switchChecked": "true",
        "disclosureOpen": "true",
        "sort": "ascending",
        "stateRole": "alert",
        "fieldAssociated": True,
        "iconName": "刷新",
        "smallTargets": 0,
        "sheetFocusOutsideBeforeEscape": True,
        "sheetClosedFromOutsideFocus": True,
        "sheetFocusRestored": True,
        "sheetVariant": "copilot",
        "sheetWallpaperLayers": 2,
        "sheetCanvasLayers": 0,
        "fullSheetVariant": "fullscreen",
        "fullSheetMaterialLayers": 0,
    }
    scenarios = data["scenarios"]
    assert len(scenarios) == 4
    assert all(not scenario["pageOverflow"] and not scenario["shellOverflow"] for scenario in scenarios), scenarios
    assert all(scenario["shellSurface"] == "stable-glass" for scenario in scenarios)
    assert all(scenario["tableSurface"] == "dense-surface" for scenario in scenarios)
    assert all(scenario["smallTargets"] == 0 for scenario in scenarios), scenarios
    assert all(scenario["fieldFontSize"] >= 16 for scenario in scenarios if scenario["width"] < 768)
    dark_ink = next(item for item in scenarios if item["foreground"] == "dark" and not item["reducedTransparency"])
    light_ink = next(item for item in scenarios if item["foreground"] == "light" and item["width"] == 1440)
    color_channels = lambda value: [int(part) for part in __import__('re').findall(r'\d+', value)[:3]]
    assert max(color_channels(dark_ink["shellColor"])) < 40, scenarios
    assert min(color_channels(light_ink["shellColor"])) > 230, scenarios
    assert any("0.78" in item["tableBackground"] or "0.86" in item["tableBackground"] for item in scenarios if not item["reducedTransparency"]), scenarios
    normal = next(item for item in scenarios if not item["reducedTransparency"] and item["width"] == 1440)
    reduced = next(item for item in scenarios if item["reducedTransparency"])
    assert normal["shellBackdrop"] != "none"
    assert reduced["shellBackdrop"] == "none"
    print("ok: UI Kit fixture passes keyboard/ARIA plus theme, wallpaper, mobile, and reduced-transparency contracts")
finally:
    if WRAPPER.is_file():
        subprocess.run([str(WRAPPER), f"-s={SESSION}", "close"], cwd=ROOT, capture_output=True, text=True)
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
