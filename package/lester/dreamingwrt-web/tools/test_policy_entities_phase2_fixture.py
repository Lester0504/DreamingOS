#!/usr/bin/env python3
import json
import os
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "skills/playwright/scripts/playwright_cli.sh"
SESSION = "dwrt-policy-entities-phase2-fixture"


if not WRAPPER.is_file():
    raise SystemExit(f"Playwright CLI wrapper not found: {WRAPPER}")
if subprocess.run(["sh", "-c", "command -v npx >/dev/null 2>&1"]).returncode:
    raise SystemExit("npx is required by the Playwright CLI wrapper")


server = subprocess.Popen(
    ["python3", "-m", "http.server", "18769", "--bind", "127.0.0.1"],
    cwd=ROOT,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    time.sleep(.4)
    opened = subprocess.run(
        [str(WRAPPER), f"-s={SESSION}", "open", "http://127.0.0.1:18769/tests/fixtures/policy-entities-phase2.html"],
        cwd=ROOT, capture_output=True, text=True, timeout=60,
    )
    if opened.returncode:
        raise RuntimeError(opened.stdout + opened.stderr)
    function = r"""async page => {
      await page.waitForFunction(() => window.POLICY_ENTITIES_FIXTURE_READY === true);
      const result = { states: { objects: {}, regions: {} }, requests: {}, keyboard: {}, write: {}, viewports: [], lifecycle: {} };
      const mount = async (kind, scenario) => {
        const contract = await page.evaluate(({ kind, scenario }) => window.POLICY_ENTITIES_FIXTURE.mount(kind, scenario), { kind, scenario });
        await page.waitForTimeout(100);
        return contract;
      };
      for (const kind of ['objects', 'regions']) {
        for (const scenario of ['ready', 'stale', 'empty', 'loading', 'error', 'forbidden', 'unavailable']) {
          const contract = await mount(kind, scenario);
          result.states[kind][scenario] = await page.evaluate(contract => ({
            text: document.getElementById('routePreview').innerText,
            states: [...document.querySelectorAll('[data-dwrt-state]')].map(node => node.dataset.dwrtState),
            rows: document.querySelectorAll('.policy-entity-table tbody tr').length,
            cells: document.querySelectorAll('[data-region-pair]').length,
            inputs: document.querySelectorAll('.policy-objects-page input, .policy-objects-page select, .policy-objects-page textarea').length,
            disabledAdd: [...document.querySelectorAll('.policy-objects-page button:disabled')].filter(node => /添加|创建/.test(node.innerText)).length,
            requests: contract.requests,
            subscriptions: contract.subscriptions,
            stale: document.body.innerText.includes('正在显示上次可用快照')
          }), contract);
        }
      }

      await mount('objects', 'ready');
      const objectTrigger = page.locator('[data-object-detail]').first();
      const objectId = await objectTrigger.getAttribute('data-object-detail');
      await objectTrigger.click();
      await page.waitForTimeout(120);
      result.keyboard.objectSheet = await page.locator('.policy-entity-sheet').isVisible();
      result.keyboard.objectMainStable = await objectTrigger.evaluate((node, id) => node === document.querySelector(`[data-object-detail="${CSS.escape(id)}"]`), objectId);
      await page.keyboard.press('Escape');
      await page.waitForTimeout(900);
      result.keyboard.objectFocusReturned = await page.evaluate(id => document.activeElement?.dataset.objectDetail === id, objectId);

      await mount('regions', 'ready');
      const firstCell = page.locator('[data-region-pair]').first();
      await firstCell.focus();
      await page.keyboard.press('ArrowRight');
      result.keyboard.gridMoved = await page.evaluate(() => document.activeElement?.dataset.dwrtGridColumn === '2');
      const pairId = await page.evaluate(() => document.activeElement?.dataset.regionPair || '');
      await page.keyboard.press('Enter');
      await page.waitForTimeout(120);
      result.keyboard.pairSheet = await page.locator('.policy-region-sheet').isVisible();
      result.keyboard.pairMainStable = await page.evaluate(id => Boolean(document.querySelector(`[data-region-pair="${CSS.escape(id)}"]`)), pairId);
      await page.keyboard.press('Escape');
      await page.waitForTimeout(900);
      result.keyboard.pairFocusReturned = await page.evaluate(id => document.activeElement?.dataset.regionPair === id, pairId);

      const create = page.locator('[data-region-create]');
      await create.click();
      await page.waitForTimeout(120);
      result.keyboard.createSheet = await page.locator('.policy-region-sheet').isVisible();
      result.keyboard.createFocusInside = await page.locator('.policy-region-sheet').evaluate(node => node.contains(document.activeElement));
      await page.locator('[data-region-field="name"]').fill('lab');
      await page.locator('[data-dwrt-combobox-trigger]').click();
      result.write.memberUniqueness = await page.locator('[data-dwrt-combobox-option][data-value="guest"]').isDisabled();
      await page.locator('[data-dwrt-combobox-option][data-value="labnet"]').click();
      await page.evaluate(() => window.POLICY_ENTITIES_FIXTURE.setConflict(true));
      await page.locator('[data-region-save]').click();
      await page.waitForTimeout(180);
      result.write.conflict = await page.evaluate(() => ({
        text: document.querySelector('.policy-entity-overlay-host')?.innerText || '',
        contract: window.POLICY_ENTITIES_FIXTURE.contract()
      }));
      await page.evaluate(() => window.POLICY_ENTITIES_FIXTURE.setConflict(false));
      await page.locator('[data-region-save]').click();
      await page.waitForTimeout(250);
      result.write.success = await page.evaluate(() => window.POLICY_ENTITIES_FIXTURE.contract());

      for (const viewport of [{ width: 1440, height: 1000 }, { width: 1024, height: 768 }, { width: 390, height: 844 }]) {
        await page.setViewportSize(viewport);
        await mount('regions', 'large');
        result.viewports.push(await page.evaluate(viewport => {
          const visible = node => node.getClientRects().length && !node.closest('[hidden]');
          const controls = [...document.querySelectorAll('#routePreview button, #routePreview input, #routePreview select, #routePreview textarea, #routePreview a[href], #routePreview [tabindex="0"]')].filter(visible);
          const unlabeled = controls.filter(node => !node.getAttribute('aria-label') && !node.getAttribute('aria-labelledby') && !node.closest('label') && !node.textContent.trim()).length;
          const small = controls.filter(node => { const rect = node.getBoundingClientRect(); return rect.width < 44 || rect.height < 44; }).length;
          const root = document.getElementById('routePreview');
          const matrixScroll = document.querySelector('.policy-region-matrix-scroll');
          const rootRect = root.getBoundingClientRect();
          const visibleOverflow = [...root.querySelectorAll('*')].filter(visible).filter(node => {
            if (node.closest('.policy-region-matrix-scroll, .dwrt-kit-table-scroll')) return false;
            const rect = node.getBoundingClientRect();
            return rect.right > rootRect.right + 1 || rect.left < rootRect.left - 1;
          }).length;
          return {
            ...viewport,
            pageOverflow: document.documentElement.scrollWidth > innerWidth + 1,
            rootOverflow: root.scrollWidth > root.clientWidth + 1,
            visibleOverflow,
            matrixScrollable: matrixScroll.scrollWidth > matrixScroll.clientWidth,
            unlabeled, small,
            nodes: document.querySelectorAll('#routePreview *').length,
            cells: document.querySelectorAll('[data-region-pair]').length,
            surface: document.querySelector('[data-dwrt-component="page-shell"]')?.dataset.dwrtSurface
          };
        }, viewport));
      }
      result.lifecycle = await page.evaluate(() => window.POLICY_ENTITIES_FIXTURE.unmount());
      return result;
    }"""
    completed = subprocess.run(
        [str(WRAPPER), "--raw", f"-s={SESSION}", "run-code", function],
        cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    if completed.returncode:
        raise RuntimeError(completed.stdout + completed.stderr)
    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"policy entities fixture returned invalid JSON: {completed.stdout[:1400]!r}; stderr={completed.stderr!r}") from error

    object_requests = {"policy.objects": 1}
    region_requests = {"policy.regions": 1, "policy.zoneMatrix": 1, "policy.table": 1, "network.lans": 1, "network.wans": 1}
    for name, state in data["states"]["objects"].items():
        assert state["requests"] == object_requests and state["subscriptions"] == 1, (name, state)
        assert state["inputs"] == 0 and state["disabledAdd"] == 0, (name, state)
    for name, state in data["states"]["regions"].items():
        assert state["requests"] == region_requests and state["subscriptions"] == 5, (name, state)
    assert data["states"]["objects"]["ready"]["rows"] == 3
    assert data["states"]["objects"]["stale"]["stale"] is True
    assert "empty" in data["states"]["objects"]["empty"]["states"]
    assert "loading" in data["states"]["objects"]["loading"]["states"]
    for name in ("error", "forbidden", "unavailable"):
        assert name in data["states"]["objects"][name]["states"], data["states"]["objects"][name]
        assert name in data["states"]["regions"][name]["states"], data["states"]["regions"][name]
    assert data["states"]["regions"]["ready"]["rows"] == 5
    assert data["states"]["regions"]["ready"]["cells"] == 25
    assert data["states"]["regions"]["stale"]["stale"] is True
    assert data["states"]["regions"]["empty"]["states"].count("empty") >= 2
    assert "loading" in data["states"]["regions"]["loading"]["states"]

    assert all(data["keyboard"].values()), data["keyboard"]
    assert "网络成员已属于其他区域" in data["write"]["conflict"]["text"]
    conflict_calls = data["write"]["conflict"]["contract"]["apiCalls"]
    assert conflict_calls[-1]["method"] == "POST"
    assert conflict_calls[-1]["body"]["name"] == "lab"
    assert data["write"]["memberUniqueness"] is True
    assert "labnet" in conflict_calls[-1]["body"]["members"]
    success = data["write"]["success"]
    assert len(success["apiCalls"]) == 2 and success["apiCalls"][-1]["method"] == "POST", success
    assert success["invalidations"] == ["policy.regions", "policy.zoneMatrix", "policy.table"], success
    assert success["requests"] == {key: 2 for key in region_requests}, success

    assert len(data["viewports"]) == 3
    assert all(not item["pageOverflow"] and not item["rootOverflow"] and item["visibleOverflow"] == 0 for item in data["viewports"]), data["viewports"]
    assert data["viewports"][0]["matrixScrollable"] is False, data["viewports"]
    assert all(item["matrixScrollable"] for item in data["viewports"][1:]), data["viewports"]
    assert all(item["unlabeled"] == 0 and item["small"] == 0 for item in data["viewports"]), data["viewports"]
    assert all(item["nodes"] < 1000 and item["cells"] == 64 and item["surface"] == "stable-glass" for item in data["viewports"]), data["viewports"]
    assert data["lifecycle"] == {"subscriptions": 0, "children": 0}
    print("ok: policy entities fixture passes states, scoped requests, stable sheets, DataGrid keyboard, mocked 409/write readback, lifecycle, and three-viewport contracts")
finally:
    if WRAPPER.is_file():
        subprocess.run([str(WRAPPER), f"-s={SESSION}", "close"], cwd=ROOT, capture_output=True, text=True)
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
