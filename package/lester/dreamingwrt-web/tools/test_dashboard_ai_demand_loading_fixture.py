#!/usr/bin/env python3
import json
import os
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = ROOT / "files/www/dreamingwrt"
WRAPPER = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "skills/playwright/scripts/playwright_cli.sh"
SESSION = "dwrt-dashboard-ai-demand-loading-fixture"
PORT = 18770


if not WRAPPER.is_file():
    raise SystemExit(f"Playwright CLI wrapper not found: {WRAPPER}")
if subprocess.run(["sh", "-c", "command -v npx >/dev/null 2>&1"]).returncode:
    raise SystemExit("npx is required by the Playwright CLI wrapper")


menu = json.loads((WEB_ROOT / "static/menu/main.json").read_text(encoding="utf-8"))
config = json.dumps({
    "baseUrl": f"http://127.0.0.1:{PORT}",
    "menu": menu,
    "viewports": [
        {"width": 1440, "height": 1000},
        {"width": 1024, "height": 768},
        {"width": 390, "height": 844},
    ],
}, ensure_ascii=False)


server = subprocess.Popen(
    ["python3", "-m", "http.server", str(PORT), "--bind", "127.0.0.1"],
    cwd=WEB_ROOT,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    time.sleep(.4)
    opened = subprocess.run(
        [str(WRAPPER), f"-s={SESSION}", "open", "about:blank"],
        cwd=ROOT, capture_output=True, text=True, timeout=60,
    )
    if opened.returncode:
        raise RuntimeError(opened.stdout + opened.stderr)

    function = f"""async seedPage => {{
      const config = {config};
      const fixtureWan = (id, name, ifname, down, up) => ({{
        id, name, ifname, interface: ifname, device: ifname, carrier: name,
        connected: true, status: 'up', public_ip: id === 'wan' ? '198.51.100.2' : '203.0.113.2',
        gateway: id === 'wan' ? '198.51.100.1' : '203.0.113.1', latency: id === 'wan' ? 11 : 22,
        down_rate: down, up_rate: up, uptime: id === 'wan' ? 3600 : 2400
      }});
      const wans = [
        fixtureWan('wan', '中国联通', 'eth1', 2400000, 420000),
        fixtureWan('wan2', '中国移动', 'eth2', 900000, 160000)
      ];
      const points = Array.from({{ length: 12 }}, (_, index) => ({{
        ts: 1784640000 + index * 60,
        down_rate: 1000000 + index * 12000,
        up_rate: 240000 + index * 4000,
        latency_ms: 16,
        connections: 120 + index
      }}));
      const jsonResponse = data => ({{ status: 200, contentType: 'application/json', body: JSON.stringify({{ ok: true, data }}) }});
      const requestPath = value => String(value).replace(/^https?:\\/\\/[^/]+/, '').split('?')[0];
      const queryValue = (value, key) => {{
        const match = String(value).match(new RegExp(`[?&]${{key}}=([^&]*)`));
        return match ? decodeURIComponent(match[1].replace(/\\+/g, ' ')) : '';
      }};
      const apiPayload = url => {{
        const path = requestPath(url);
        if (path === '/api/v1/bootstrap') return {{ capabilities: {{ realtime_ws: false, ai: true }}, device: {{ wifi_supported: false }} }};
        if (path === '/api/v1/dashboard/snapshot') return {{
          system: {{ hostname: 'DreamingWrt', model: 'Fixture Router', uptime: 7200, version: '7.2-RC3', build_date: 'Build202607180016', connections: 128 }},
          wans, traffic: {{ down_rate: 3300000, up_rate: 580000, latency: 16, connections: 128 }},
          clients: [], apps: [], active_urls: [], ranks: []
        }};
        if (path === '/api/v1/system/status') return {{ hostname: 'DreamingWrt', model: 'Fixture Router', uptime: 7200, version: '7.2-RC3', build_date: 'Build202607180016', connections: 128 }};
        if (path === '/api/v1/network/overview') return {{ wans: {{ wans }}, lans: {{ lans: [{{ id: 'lan', name: 'LAN', ifname: 'br-lan', ip: '192.168.30.1' }}] }} }};
        if (path === '/api/v1/network/wans') return {{ wans }};
        if (path === '/api/v1/network/ports') return {{ ports: [
          {{ id: 'eth0', label: 'eth0', ifname: 'eth0', role: 'lan', active: true, speed: '1 Gbps' }},
          {{ id: 'eth1', label: 'eth1', ifname: 'eth1', role: 'wan', active: true, speed: '1 Gbps' }},
          {{ id: 'eth2', label: 'eth2', ifname: 'eth2', role: 'wan', active: true, speed: '1 Gbps' }}
        ] }};
        if (path === '/api/v1/clients') return {{ clients: [], total: 0 }};
        if (path === '/api/v1/dashboard/traffic/history') {{
          return {{ range: queryValue(url, 'range') || '1h', wan_id: queryValue(url, 'wan_id'), points }};
        }}
        if (path === '/api/v1/ai/config') return {{ enabled: true, provider: 'openai', model: 'gpt-4o', auth_mode: 'api_key', api_key_configured: true, capabilities: {{ oauth: {{ available: false }} }} }};
        if (path === '/api/v1/ai/models') return {{ models: ['gpt-4o'] }};
        if (path === '/api/v1/ai/history') return {{ items: [], total: 0 }};
        return {{}};
      }};
      const prepare = async page => {{
        const requests = [];
        const errors = [];
        page.on('request', request => requests.push({{ url: request.url(), method: request.method(), type: request.resourceType() }}));
        page.on('console', message => {{ if (message.type() === 'error') errors.push(message.text()); }});
        page.on('pageerror', error => errors.push(error.message));
        await page.addInitScript(() => {{
          localStorage.setItem('dreamingwrt.web.accessToken', 'fixture-access');
          localStorage.setItem('dreamingwrt.web.refreshToken', 'fixture-refresh');
          localStorage.setItem('dreamingwrt.web.expiresAt', String(Date.now() + 3600000));
          localStorage.setItem('dreamingwrt.web.username', 'Lester');
          localStorage.setItem('dreamingwrt.web.role', 'admin');
          sessionStorage.clear();
        }});
        await page.route('**/dynamic/menu/1.json*', route => route.fulfill({{ status: 200, contentType: 'application/json', body: JSON.stringify(config.menu) }}));
        await page.route('**/api/v1/**', route => route.fulfill(jsonResponse(apiPayload(route.request().url()))));
        return {{ requests, errors }};
      }};
      const historyRequests = requests => requests.filter(item => requestPath(item.url) === '/api/v1/dashboard/traffic/history');
      const aiAssets = requests => requests.filter(item => /\\/(?:plugins\\/native\\/ai-assistant\\.js|static\\/css\\/ai-assistant\\.css)(?:\\?|$)/.test(item.url));
      const aiApi = requests => requests.filter(item => requestPath(item.url).startsWith('/api/v1/ai/'));
      const result = {{ dashboard: [], ai: null, llm: null }};

      for (const viewport of config.viewports) {{
        const page = await seedPage.context().newPage();
        await page.setViewportSize(viewport);
        const log = await prepare(page);
        await page.goto(`${{config.baseUrl}}/app/#/dashboard`, {{ waitUntil: 'domcontentloaded', timeout: 20000 }});
        await page.locator('[data-dashboard-range="1h"]').waitFor({{ state: 'visible', timeout: 12000 }});
        await page.waitForTimeout(1400);
        const beforeIntent = historyRequests(log.requests).length;
        const bootstrapStyle = await page.locator('#aiBootstrap').evaluate(node => {{
          const style = getComputedStyle(node);
          const rect = node.getBoundingClientRect();
          return {{ position: style.position, width: rect.width, height: rect.height, visible: Boolean(rect.width && rect.height) }};
        }});

        await page.locator('[data-dashboard-range="1h"]').click();
        await page.waitForFunction(() => document.querySelector('[data-dashboard-range="1h"]')?.classList.contains('is-active'));
        await page.waitForTimeout(180);
        const afterAll = historyRequests(log.requests).map(item => item.url);
        await page.locator('[data-dashboard-wan="wan"]').click();
        await page.waitForFunction(() => document.querySelector('[data-dashboard-wan="wan"]')?.classList.contains('is-active'));
        await page.waitForTimeout(180);
        const afterWan = historyRequests(log.requests).map(item => item.url);
        await page.locator('[data-dashboard-range="realtime"]').click();
        await page.waitForTimeout(240);
        const afterRealtime = historyRequests(log.requests).map(item => item.url);
        const layout = await page.evaluate(() => ({{
          pageOverflow: document.documentElement.scrollWidth > innerWidth + 1,
          dashboardVisible: !document.getElementById('dashboardWorkspace').hidden,
          range: document.querySelector('[data-dashboard-range].is-active')?.dataset.dashboardRange || '',
          wan: document.querySelector('[data-dashboard-wan].is-active')?.dataset.dashboardWan || ''
        }}));
        result.dashboard.push({{ viewport, beforeIntent, afterAll, afterWan, afterRealtime, bootstrapStyle, layout, errors: log.errors }});

        if (viewport.width === 1440) {{
          const aiBefore = {{ assets: aiAssets(log.requests).length, api: aiApi(log.requests).length }};
          await page.locator('#aiBootstrap').click();
          await page.locator('.ai-global-layer.is-open').waitFor({{ state: 'visible', timeout: 12000 }});
          await page.waitForTimeout(180);
          result.ai = {{
            before: aiBefore,
            assets: aiAssets(log.requests).map(item => item.url),
            api: aiApi(log.requests).map(item => item.url),
            open: await page.locator('.ai-copilot-drawer').isVisible(),
            bootstrapRemoved: await page.locator('#aiBootstrap').count() === 0
          }};
        }}
        await page.close();
      }}

      const llmPage = await seedPage.context().newPage();
      await llmPage.setViewportSize({{ width: 1440, height: 1000 }});
      const llmLog = await prepare(llmPage);
      await llmPage.goto(`${{config.baseUrl}}/app/#/system/llm-settings`, {{ waitUntil: 'domcontentloaded', timeout: 20000 }});
      await llmPage.waitForTimeout(2200);
      result.llm = {{
        styleLink: await llmPage.locator('link[data-dwrt-page-style*="/static/css/ai-assistant.css"]').count(),
        settings: await llmPage.locator('.ai-settings-route-shell').count() > 0 && await llmPage.locator('.ai-settings-route-shell').isVisible(),
        assets: aiAssets(llmLog.requests).map(item => item.url),
        api: aiApi(llmLog.requests).map(item => item.url),
        historyRequests: aiApi(llmLog.requests).filter(item => requestPath(item.url) === '/api/v1/ai/history').length,
        errors: llmLog.errors,
        hash: await llmPage.evaluate(() => location.hash),
        routeText: await llmPage.locator('#routePreview').innerText(),
        routeHtml: (await llmPage.locator('#routePreview').innerHTML()).slice(0, 1000),
        moduleRequests: llmLog.requests.filter(item => /ai-assistant|main\\.json|dynamic\\/menu/.test(item.url)).map(item => item.url)
      }};
      await llmPage.close();
      return result;
    }}"""
    completed = subprocess.run(
        [str(WRAPPER), "--raw", f"-s={SESSION}", "run-code", function],
        cwd=ROOT, capture_output=True, text=True, timeout=180,
    )
    if completed.returncode:
        raise RuntimeError(completed.stdout + completed.stderr)
    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"demand-loading fixture returned invalid JSON: {completed.stdout[:1600]!r}; stderr={completed.stderr!r}") from error

    assert len(data["dashboard"]) == 3
    for sample in data["dashboard"]:
        assert sample["beforeIntent"] == 0, sample
        assert len(sample["afterAll"]) == 1, sample
        all_url = sample["afterAll"][0]
        assert "range=1h" in all_url and "wan_id=" not in all_url, sample
        assert len(sample["afterWan"]) == 2, sample
        wan_url = sample["afterWan"][-1]
        assert "range=1h" in wan_url and "wan_id=wan" in wan_url, sample
        assert sample["afterRealtime"] == sample["afterWan"], sample
        assert sample["bootstrapStyle"] == {"position": "fixed", "width": 58, "height": 58, "visible": True}, sample
        assert sample["layout"]["dashboardVisible"] is True and sample["layout"]["range"] == "realtime", sample
        assert sample["layout"]["wan"] == "wan" and sample["layout"]["pageOverflow"] is False, sample
        assert not sample["errors"], sample

    ai = data["ai"]
    assert ai["before"] == {"assets": 0, "api": 0}, ai
    assert sum("/static/css/ai-assistant.css" in url for url in ai["assets"]) == 1, ai
    assert sum("/plugins/native/ai-assistant.js" in url for url in ai["assets"]) == 1, ai
    assert ai["open"] is True and ai["bootstrapRemoved"] is True, ai
    assert {Path(url.split("?", 1)[0]).name for url in ai["api"]} >= {"config", "models", "history"}, ai

    llm = data["llm"]
    assert llm["styleLink"] == 1 and llm["settings"] is True, llm
    assert any("/static/css/ai-assistant.css" in url for url in llm["assets"]), llm
    assert any("/plugins/native/ai-assistant.js" in url for url in llm["assets"]), llm
    assert llm["historyRequests"] == 0 and not llm["errors"], llm
    print("ok: Dashboard history and global/route AI assets load only after the selected user intent across three viewports")
finally:
    if WRAPPER.is_file():
        subprocess.run([str(WRAPPER), f"-s={SESSION}", "close"], cwd=ROOT, capture_output=True, text=True)
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
