#!/usr/bin/env python3
import json
import os
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "skills/playwright/scripts/playwright_cli.sh"
SESSION = "dwrt-appearance-phase2-fixture"
SCREENSHOTS = ROOT / "output/redesign/phase2-appearance-fixture-screenshots"


if not WRAPPER.is_file():
    raise SystemExit(f"Playwright CLI wrapper not found: {WRAPPER}")


server = subprocess.Popen(
    ["python3", "-m", "http.server", "18771", "--bind", "127.0.0.1"],
    cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
)
try:
    time.sleep(.4)
    if server.poll() is not None:
        raise RuntimeError(f"fixture server failed to start: {(server.stderr.read() if server.stderr else '').strip()}")
    opened = subprocess.run(
        [str(WRAPPER), f"-s={SESSION}", "open", "http://127.0.0.1:18771/tests/fixtures/appearance-phase2.html"],
        cwd=ROOT, capture_output=True, text=True, timeout=60,
    )
    if opened.returncode:
        raise RuntimeError(opened.stdout + opened.stderr)
    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    function = r"""async page => {
      await page.waitForFunction(() => window.APPEARANCE_FIXTURE_READY === true);
      const result = { states: {}, lazy: {}, interactions: {}, save: {}, themes: [], previewTones: {}, viewports: [], lifecycle: {}, errors: [] };
      page.on('console', message => { if (message.type() === 'error') result.errors.push(message.text()); });
      page.on('pageerror', error => result.errors.push(error.message));
      const mount = async (name = 'ready', options = {}) => {
        const contract = await page.evaluate(({ name, options }) => window.APPEARANCE_FIXTURE.mountScenario(name, options), { name, options });
        await page.waitForTimeout(40);
        return contract;
      };
      for (const [name, expected] of [
        ['loading', 'loading'], ['error', 'error'], ['forbidden', 'forbidden'], ['unavailable', 'unavailable']
      ]) {
        const contract = await mount(name);
        result.states[name] = await page.evaluate(contract => ({
          state: document.querySelector('[data-dwrt-component="state-panel"]')?.dataset.dwrtState || '',
          text: document.getElementById('routePreview').innerText,
          requests: contract.requests
        }), contract);
        result.states[name].expected = expected;
      }
      const capability = await mount('ready', { capabilities: { appearance: false } });
      result.states.capability = await page.evaluate(contract => ({
        state: document.querySelector('[data-dwrt-component="state-panel"]')?.dataset.dwrtState || '',
        text: document.getElementById('routePreview').innerText,
        requests: contract.requests
      }), capability);
      await mount('stale');
      result.states.stale = await page.evaluate(() => ({
        shell: Boolean(document.querySelector('.appearance-page-shell')),
        status: document.querySelector('[data-appearance-status]')?.textContent || ''
      }));

      await mount('ready');
      result.lazy.before = await page.evaluate(() => window.APPEARANCE_FIXTURE.requests());
      const wallpaper = page.locator('[data-appearance-disclosure="wallpaper"] [data-dwrt-disclosure-trigger]');
      await wallpaper.click();
      await page.waitForTimeout(70);
      result.lazy.after = await page.evaluate(() => window.APPEARANCE_FIXTURE.requests());
      result.lazy.options = await page.locator('[data-appearance-media-select] option').count();

      await mount('ready');
      await page.locator('[data-appearance-disclosure="readability"] [data-dwrt-disclosure-trigger]').click();
      const slider = page.locator('[data-dwrt-component="slider"] input');
      await slider.focus();
      result.interactions.slider = await slider.evaluate(node => {
        window.__appearanceSlider = node;
        node.focus();
        const focusedBefore = document.activeElement === node;
        node.value = '2';
        node.dispatchEvent(new Event('input', { bubbles: true }));
        return {
          nodeStable: window.__appearanceSlider === document.querySelector('[data-dwrt-component="slider"] input'),
          disabled: node.disabled,
          tabIndex: node.tabIndex,
          focusedBefore,
          focusedAfter: document.activeElement === node
        };
      });
      result.interactions.savebar = await page.locator('[data-dwrt-savebar]:not(.is-hidden)').count();
      result.interactions.level = await page.locator('[data-appearance-preview-level]').innerText();
      await page.locator('[data-dwrt-savebar-discard]').click();
      result.interactions.discarded = await page.locator('[data-dwrt-savebar].is-hidden').count();
      result.interactions.rollback = await page.evaluate(() => window.APPEARANCE_FIXTURE.previews().some(item => item.action === 'rollback'));

      await mount('ready', { saveMode: 'applied' });
      await page.locator('[data-appearance-accent="emerald"]').click();
      await page.locator('[data-dwrt-savebar-save]').click();
      await page.waitForTimeout(90);
      result.save.applied = {
        feedback: await page.locator('[data-appearance-feedback]').innerText(),
        hiddenBar: await page.locator('[data-dwrt-savebar].is-hidden').count(),
        commit: await page.evaluate(() => window.APPEARANCE_FIXTURE.previews().some(item => item.action === 'commit'))
      };
      await mount('ready', { saveMode: 'unconfirmed' });
      await page.locator('[data-appearance-accent="emerald"]').click();
      await page.locator('[data-dwrt-savebar-save]').click();
      await page.waitForTimeout(90);
      result.save.unconfirmed = await page.locator('[data-appearance-feedback]').innerText();

      for (const theme of ['dark', 'light']) {
        for (const wallpaperTone of ['dark', 'bright']) {
          await page.evaluate(({ theme, wallpaperTone }) => {
            document.documentElement.dataset.themeResolved = theme;
            document.body.dataset.wallpaper = wallpaperTone;
            document.documentElement.dataset.adaptiveForeground = wallpaperTone === 'bright' ? 'dark' : 'light';
          }, { theme, wallpaperTone });
          await mount('ready');
          result.themes.push(await page.evaluate(({ theme, wallpaperTone }) => {
            const shell = document.querySelector('.appearance-page-shell');
            const title = document.querySelector('.appearance-page-header h1');
            const muted = document.querySelector('.appearance-page-header p');
            return {
              theme, wallpaperTone, shellColor: getComputedStyle(shell).color,
              titleColor: getComputedStyle(title).color, mutedColor: getComputedStyle(muted).color,
              surface: shell.dataset.dwrtSurface
            };
          }, { theme, wallpaperTone }));
        }
      }

      await mount('ready');
      result.previewTones.dark = await page.evaluate(() => window.APPEARANCE_FIXTURE.previewTone('dark'));
      result.previewTones.bright = await page.evaluate(() => window.APPEARANCE_FIXTURE.previewTone('bright'));

      const screenshotRoot = """ + json.dumps(str(SCREENSHOTS.resolve())) + r""";
      for (const viewport of [{ width: 1440, height: 1000 }, { width: 1024, height: 768 }, { width: 390, height: 844 }]) {
        await page.setViewportSize(viewport);
        await mount('ready');
        result.viewports.push(await page.evaluate(viewport => {
          const visible = node => node.getClientRects().length && !node.closest('[hidden]') && getComputedStyle(node).visibility !== 'hidden';
          const controls = [...document.querySelectorAll('#routePreview button, #routePreview input, #routePreview select, #routePreview textarea, #routePreview a[href]')].filter(visible);
          const unnamed = controls.filter(node => !node.matches('button') && !node.getAttribute('aria-label') && !node.getAttribute('aria-labelledby') && !node.closest('label')).length;
          const unnamedButtons = controls.filter(node => node.matches('button') && !node.innerText.trim() && !node.getAttribute('aria-label') && !node.getAttribute('aria-labelledby')).length;
          const small = controls.filter(node => { const rect = node.getBoundingClientRect(); return rect.width < 44 || rect.height < 44; }).length;
          const root = document.getElementById('routePreview');
          return {
            ...viewport, pageOverflow: document.documentElement.scrollWidth > innerWidth + 1,
            rootOverflow: root.scrollWidth > root.clientWidth + 1, unnamed, small,
            surface: document.querySelector('.appearance-page-shell')?.dataset.dwrtSurface || '',
            nodes: root.querySelectorAll('*').length
          };
        }, viewport));
        await page.screenshot({ path: screenshotRoot + '/' + viewport.width + 'x' + viewport.height + '.png', fullPage: false });
      }
      await mount('ready');
      result.lifecycle = await page.evaluate(() => {
        const contract = window.APPEARANCE_FIXTURE.unmount();
        return { ...contract, rootChildren: document.getElementById('routePreview').childElementCount };
      });
      return result;
    }"""
    completed = subprocess.run(
        [str(WRAPPER), "--raw", f"-s={SESSION}", "run-code", function],
        cwd=ROOT, capture_output=True, text=True, timeout=150,
    )
    if completed.returncode:
        raise RuntimeError(completed.stdout + completed.stderr)
    data = json.loads(completed.stdout)
    for name in ("loading", "error", "forbidden", "unavailable"):
        assert data["states"][name]["state"] == data["states"][name]["expected"], data["states"][name]
        assert data["states"][name]["requests"] == {"appearance.settings": 1}
    assert data["states"]["capability"]["state"] == "unavailable"
    assert data["states"]["stale"] == {"shell": True, "status": "使用最近一次配置"}
    assert data["lazy"]["before"] == {"appearance.settings": 1}
    assert data["lazy"]["after"] == {"appearance.settings": 1, "appearance.media": 1}
    assert data["lazy"]["options"] >= 2
    assert data["interactions"] == {
        "slider": {"nodeStable": True, "disabled": False, "tabIndex": 0, "focusedBefore": True, "focusedAfter": True},
        "savebar": 1, "level": "清晰", "discarded": 1, "rollback": True
    }, data["interactions"]
    assert data["save"]["applied"] == {"feedback": "已保存并完成回读", "hiddenBar": 1, "commit": True}
    assert data["save"]["unconfirmed"] == "已保存，运行态未确认"
    assert len(data["themes"]) == 4
    assert all(item["surface"] == "stable-glass" and item["titleColor"] and item["mutedColor"] for item in data["themes"])
    assert data["previewTones"]["dark"]["region"] == "light", data["previewTones"]
    assert data["previewTones"]["bright"]["region"] == "dark", data["previewTones"]
    assert min(int(part) for part in __import__('re').findall(r'\d+', data["previewTones"]["dark"]["color"])[:3]) > 230, data["previewTones"]
    assert max(int(part) for part in __import__('re').findall(r'\d+', data["previewTones"]["bright"]["color"])[:3]) < 40, data["previewTones"]
    assert len(data["viewports"]) == 3
    assert all(not item["pageOverflow"] and not item["rootOverflow"] for item in data["viewports"]), data["viewports"]
    assert all(item["unnamed"] == 0 and item["small"] == 0 for item in data["viewports"]), data["viewports"]
    assert all(item["surface"] == "stable-glass" and item["nodes"] < 220 for item in data["viewports"]), data["viewports"]
    assert data["lifecycle"]["subscriptions"] == 0
    assert data["lifecycle"]["listeners"] == 0
    assert data["lifecycle"]["rootChildren"] == 0
    assert data["errors"] == [], data["errors"]
    print("ok: appearance fixture passes states, lazy media, stable input, rollback/readback, themes, three viewports, and lifecycle")
finally:
    subprocess.run([str(WRAPPER), f"-s={SESSION}", "close"], cwd=ROOT, capture_output=True, text=True)
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
