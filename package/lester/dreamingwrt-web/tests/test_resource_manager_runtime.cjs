const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require('playwright');
const sharp = require('sharp');

const root = path.resolve(__dirname, '../files/www/dreamingwrt');
const out = process.env.RM_TEST_OUTPUT || '/tmp/dreamingos-resource-manager-test';
const cpu = { aggregate_percent: 12, per_core: [8, 12, 16, 12], core_count: 4,
  cur_freq_khz: 1800000, max_freq_khz: 2500000, board_model: 'Test device', arch: 'aarch64' };
const system = { hostname: 'test-router', uptime: 86400, temperature: 42,
  mem_total: 4 * 1024 ** 3, mem_used: 1024 ** 3 };
const fixtures = {
  '/api/v1/system/cpu': cpu,
  '/api/v1/system/status': { system },
  '/api/v1/dashboard/live': { 'dashboard.metrics': { system: {
    ...system, cpu_percent: 12, memory_total: system.mem_total, memory_used: system.mem_used
  } } },
  '/api/v1/system/interfaces': { interfaces: [
    { name: 'eth0', virtual: false, carrier: true, rx_bps: 1024, tx_bps: 2048 },
    { name: 'eth1', virtual: false, carrier: false, rx_bps: 0, tx_bps: 0 },
    { name: 'br-lan', virtual: true, carrier: true, rx_bps: 90000, tx_bps: 90000 }
  ] },
  '/api/v1/storage/overview': { summary: { disk_count: 1 }, disks: [
    { name: 'mmcblk0', model: 'Test storage', total_bytes: 8 * 1024 ** 3,
      temperature_c: null, read_bps: 512, write_bps: 0, smart_status: 'UNSUPPORTED' }
  ] },
  '/api/v1/system/processes': { processes: [{ pid: 100, name: 'test-process', cpu_percent: 1 }] },
  '/api/v1/system/startup': { items: [{ name: 'test-service', enabled: true, start_order: 10 }] },
  '/api/v1/system/services': { services: [] }
};

(async () => {
  await fs.mkdir(out, { recursive: true });
  const browser = await chromium.launch({ headless: true, channel: process.env.PW_CHANNEL || 'chrome' });
  try {
    const context = await browser.newContext({ viewport: { width: 1100, height: 720 } });
    let fail = false, cpuReady = false;
    const calls = {}, errors = [], methods = [];
    await context.route('https://resource-manager.test/**', async route => {
      const url = new URL(route.request().url());
      if (url.pathname === '/test-host') return route.fulfill({ contentType: 'text/html', body: `<!doctype html>
        <html data-theme-family="frosted-glass" data-theme-resolved="light"><head><meta charset="utf-8">
        <link rel="stylesheet" href="/static/css/dwrt-theme.css">
        <link rel="stylesheet" href="/static/css/theme-families.css">
        <link rel="stylesheet" href="/static/desktop/dwrt-desktop.css">
        </head><body><div class="desktop-wallpaper"><img src="/static/images/dwrt-default-bg.jpg"></div>
        <article class="desktop-window is-active" style="left:6%;top:6%;width:88%;height:88%">
        <header class="desktop-window-head"><img class="window-icon" src="/static/desktop/assets/resource-manager.png">
        <strong>资源管理器</strong></header><div class="desktop-window-body">
        <iframe aria-label="资源管理器" src="/app/resource-manager.html"></iframe></div></article></body></html>` });
      if (url.pathname.startsWith('/api/')) {
        methods.push(route.request().method());
        calls[url.pathname] = (calls[url.pathname] || 0) + 1;
        return route.fulfill({ status: fail ? 503 : 200, contentType: 'application/json',
          body: JSON.stringify(fail ? { ok: false } : {
            data: url.pathname.endsWith('/cpu') && !cpuReady ? { available: false } : fixtures[url.pathname]
          }) });
      }
      if (/dwrt-(session-gate|realtime)\.js$/.test(url.pathname))
        return route.fulfill({ contentType: 'application/javascript', body: '' });
      try { return await route.fulfill({ path: path.join(root, url.pathname) }); }
      catch (_) { return route.fulfill({ status: 404, body: '' }); }
    });
    await context.addInitScript(() => {
      window.__subs = 0;
      window.DWRTRealtime = {
        cadence: () => 1000,
        subscribe: (_, handler) => {
          window.__subs++;
          window.__push = handler;
          return () => { window.__subs--; window.__push = null; };
        }
      };
    });
    const page = await context.newPage();
    page.on('pageerror', e => errors.push(e.message));
    await page.clock.install();
    await page.goto('https://resource-manager.test/app/resource-manager.html');
    await page.waitForFunction(() => document.querySelector('[data-stat="hostname"]').textContent === 'test-router');
    assert.equal(await page.locator('.rm-nav-item').count(), 6);
    assert.equal(await page.locator('.rm-brand').count(), 0);
    assert.equal(await page.locator('.rm-subtab').count(), 4);
    assert.equal(await page.locator('.rm-card').count(), 4);
    assert.match(await page.locator('#rmOverviewDisks').innerText(), /mmcblk0/);

    await page.getByRole('tab', { name: 'CPU', exact: true }).click();
    assert.equal(await page.locator('#rmCoreList .rm-core').count(), 0);
    cpuReady = true;
    await page.clock.runFor(2100);
    await page.waitForFunction(() => document.querySelectorAll('#rmCoreList .rm-core').length === 4);
    await page.getByRole('tab', { name: '内存', exact: true }).click();
    assert.match(await page.locator('#rmSubMem').innerText(), /虚拟内存 · Swap/);
    assert.match(await page.locator('#rmSubMem').innerText(), /交换空间数据未上报/);
    assert.equal(await page.locator('#rmSubMem [data-stat="memAvail"]').innerText(), '3.00 GB');
    const liveBefore = calls['/api/v1/dashboard/live'] || 0;
    for (let n = 0; n < 3; n++) {
      await page.evaluate(n => window.__push({ ts: Math.floor(Date.now() / 1000) + 1, system: { cpu_percent: 35 + n,
        memory_total: 4 * 1024 ** 3, memory_used: 2 * 1024 ** 3 } }), n);
      await page.clock.runFor(1000);
    }
    assert.equal(await page.locator('#rmFootText').innerText(), '推送已连接');
    assert.equal(await page.locator('#rmSubMem [data-stat="memPct"]').innerText(), '50%');
    assert.equal(calls['/api/v1/dashboard/live'] || 0, liveBefore);
    await page.evaluate(() => window.__push({ ts: 1, system: {
      cpu_percent: 99, memory_total: 4 * 1024 ** 3, memory_used: 3 * 1024 ** 3
    } }));
    assert.equal(await page.locator('#rmSubMem [data-stat="memPct"]').innerText(), '50%');
    assert.equal(await page.locator('#rmSubCpu [data-stat="cpuPct"]').innerText(), '12%');
    assert.ok(await page.locator('#rmSubMem .rm-chart-line').getAttribute('d'));
    await page.getByRole('tab', { name: '网络', exact: true }).click();
    assert.match(await page.locator('#rmNicList').innerText(), /eth0/);
    assert.doesNotMatch(await page.locator('#rmNicList').innerText(), /br-lan/);
    assert.equal(await page.locator('#rmSubNet [data-stat="netDown"]').innerText(), '1.0 KB/s');
    await page.getByRole('tab', { name: '网络', exact: true }).press('Home');
    assert.equal(await page.getByRole('tab', { name: '总览' }).getAttribute('aria-selected'), 'true');
    await page.clock.runFor(250);

    for (const theme of ['light', 'dark']) {
      for (const family of ['frosted-glass', 'liquid-glass', 'traditional']) {
        await page.evaluate(({theme,family}) => {
          document.documentElement.dataset.themeResolved = theme;
          document.documentElement.dataset.themeFamily = family;
        }, { theme, family });
        await page.screenshot({ path: path.join(out, `overview-${theme}-${family}.png`), animations: 'disabled' });
        assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), 'rgba(0, 0, 0, 0)');
      }
    }
    for (const width of [1440, 900, 390, 320]) {
      await page.setViewportSize({ width, height: 800 });
      for (const sub of ['总览', 'CPU', '内存', '网络']) {
        await page.getByRole('tab', { name: sub, exact: true }).click();
        const fit = await page.evaluate(() => {
          const panel = document.querySelector('.rm-subpanel.is-active');
          return { outer: document.documentElement.scrollWidth <= innerWidth,
            panel: panel.scrollWidth <= panel.clientWidth,
            tabs: document.querySelector('#rmSubtabs').scrollWidth <= document.querySelector('#rmSubtabs').clientWidth };
        });
        assert.deepEqual(fit, { outer: true, panel: true, tabs: true }, `${width}/${sub}`);
      }
      await page.getByRole('tab', { name: '总览', exact: true }).click();
      await page.clock.runFor(250);
      await page.screenshot({ path: path.join(out, `overview-${width}.png`), animations: 'disabled' });
    }
    await page.setViewportSize({ width: 1100, height: 720 });
    for (const tab of ['进程', '启动', '服务', '硬件', '详情']) {
      await page.getByRole('button', { name: tab, exact: true }).click();
      assert.equal(await page.locator('.rm-view.is-active').count(), 1);
    }
    await page.getByRole('button', { name: '进程', exact: true }).click();
    assert.equal(await page.evaluate(() => window.__subs), 0);
    await page.getByRole('button', { name: '运行状态', exact: true }).click();
    assert.equal(await page.evaluate(() => window.__subs), 1);
    await page.getByRole('button', { name: '服务', exact: true }).click();
    await page.getByText('服务目录暂不可用', { exact: true }).waitFor();
    assert.doesNotMatch(await page.locator('#rmViewServices').innerText(), /用户托管|不在此列/);
    fixtures['/api/v1/system/services'] = { degraded: true, services: [
      { name: 'dreamingwrt-core', desc: 'Core service', critical: true,
        running: true, running_known: true, runtime_state: 'running', enabled: true, enabled_known: true },
      { name: 'dreamingwrt-authd', desc: 'Authentication', protected: true,
        running: false, running_known: true, runtime_state: 'stopped', enabled: true, enabled_known: true },
      { name: 'unknown', running: false, running_known: false, runtime_state: 'unknown',
        enabled: false, enabled_known: false }
    ] };
    await page.getByRole('button', { name: '刷新服务', exact: true }).click();
    await page.locator('.rm-services-table').waitFor();
    const serviceRows = page.locator('.rm-services-table tbody tr');
    assert.equal(await serviceRows.count(), 3);
    assert.match(await serviceRows.nth(0).innerText(), /Core service.*运行中.*已启用.*受保护/s);
    assert.match(await serviceRows.nth(1).innerText(), /已停止.*已启用.*受保护/s);
    assert.match(await serviceRows.nth(2).innerText(), /未知.*未知/s);
    assert.match(await page.locator('#rmViewServices').innerText(), /服务目录不完整/);
    assert.equal(await page.getByRole('button', { name: /停止|杀|重启/ }).count(), 0);
    await page.screenshot({ path: path.join(out, 'services-contract.png'), animations: 'disabled' });
    await page.getByRole('button', { name: '运行状态', exact: true }).click();

    fail = true;
    await page.clock.runFor(9000);
    await page.waitForFunction(() => document.querySelector('#rmFootText').textContent.includes('中断'));
    assert.ok((calls['/api/v1/dashboard/live'] || 0) > liveBefore);
    await page.evaluate(() => window.dispatchEvent(new Event('pagehide')));
    assert.equal(await page.evaluate(() => window.__subs), 0);
    const stopped = Object.values(calls).reduce((a,b) => a+b, 0);
    await page.clock.runFor(10000);
    assert.equal(Object.values(calls).reduce((a,b) => a+b, 0), stopped);
    fail = false;
    await page.evaluate(() => window.dispatchEvent(new Event('pageshow')));
    await page.waitForFunction(() => document.querySelector('#rmFootText').textContent === '轮询更新');
    assert.equal(await page.evaluate(() => window.__subs), 1);
    assert.deepEqual(errors, []);
    assert.ok(methods.every(m => m === 'GET'));
    await page.goto('https://resource-manager.test/test-host');
    const frame = page.frameLocator('iframe');
    await frame.locator('[data-stat="hostname"]').filter({ hasText: 'test-router' }).waitFor();
    const materials = [];
    for (const theme of ['light', 'dark']) {
      for (const family of ['frosted-glass', 'liquid-glass', 'traditional']) {
        await page.evaluate(({ theme, family }) => {
          localStorage.setItem('dreamingwrt.web.themePref', theme);
          localStorage.setItem('dreamingwrt.web.themeFamily', family);
          document.documentElement.dataset.themeResolved = theme;
          document.documentElement.dataset.themeFamily = family;
        }, { theme, family });
        await frame.locator('html').evaluate((el, { theme, family }) => {
          el.dataset.themeResolved = theme; el.dataset.themeFamily = family;
        }, { theme, family });
        await page.clock.runFor(250);
        await page.screenshot({ path: path.join(out, `host-${theme}-${family}.png`), animations: 'disabled' });
        materials.push(await page.locator('.desktop-window').evaluate(el => ({
          family: document.documentElement.dataset.themeFamily,
          theme: document.documentElement.dataset.themeResolved,
          background: getComputedStyle(el).backgroundColor,
          backdrop: getComputedStyle(el).backdropFilter
        })));
      }
    }
    for (const sub of ['CPU', '内存', '网络']) {
      await frame.getByRole('tab', { name: sub, exact: true }).click();
      await page.screenshot({ path: path.join(out, `host-${sub}.png`), animations: 'disabled' });
    }
    assert.notEqual(materials[0].backdrop, 'none');
    assert.equal(materials[2].backdrop, 'none');
    await frame.getByRole('tab', { name: '总览', exact: true }).click();
    await page.evaluate(() => {
      document.documentElement.dataset.themeFamily = 'frosted-glass';
      document.documentElement.dataset.themeResolved = 'dark';
    });
    await frame.locator('html').evaluate(el => {
      el.dataset.themeFamily = 'frosted-glass'; el.dataset.themeResolved = 'dark';
    });
    const contrastResults = [];
    for (const wallpaper of ['bright', 'dark', 'mixed']) {
      await page.evaluate(kind => {
        const c = document.createElement('canvas'); c.width = 1100; c.height = 720;
        const ctx = c.getContext('2d');
        ctx.fillStyle = kind === 'dark' ? '#111820' : '#e2edf3'; ctx.fillRect(0, 0, 1100, 720);
        if (kind === 'mixed') { ctx.fillStyle = '#111820'; ctx.fillRect(0, 0, 470, 720); }
        document.querySelector('.desktop-wallpaper img').src = c.toDataURL();
      }, wallpaper);
      await page.locator('.desktop-wallpaper img').evaluate(img => img.decode());
      await page.clock.runFor(500);
      const selectors = ['.rm-nav-item[data-tab="status"] span', '.rm-nav-item[data-tab="services"] span',
        '#rmFootText', '.rm-subtab[data-sub="overview"]', '[data-stat="hostname"]',
        '#rmSubOverview [data-stat="board"]', '.rm-card-title',
        '#rmSubOverview [data-stat="cpuPct"]', '#rmSubOverview [data-stat="netUp"]',
        '#rmOverviewDisks td:first-child b'];
      const texts = await frame.locator('body').evaluate((_, selectors) => selectors.map(selector => {
        const el = document.querySelector(selector);
        const range = document.createRange(); range.selectNodeContents(el);
        const r = range.getBoundingClientRect();
        const fr = window.frameElement.getBoundingClientRect();
        return { selector, color: getComputedStyle(el).color, x: r.x + fr.x, y: r.y + fr.y,
          width: r.width, height: r.height };
      }), selectors);
      await page.screenshot({ path: path.join(out, `contrast-${wallpaper}.png`), animations: 'disabled' });
      const mask = await frame.locator('head').evaluateHandle(el => {
        const mask = document.createElement('style');
        mask.textContent = '* { color: transparent !important; text-shadow: none !important; } svg { visibility: hidden !important; }';
        el.append(mask); return mask;
      });
      const raw = await sharp(await page.screenshot({ animations: 'disabled' })).removeAlpha().raw()
        .toBuffer({ resolveWithObject: true });
      await mask.evaluate(el => el.remove());
      const luma = rgb => rgb.reduce((sum, value, i) => {
        const v = value / 255;
        return sum + [0.2126, 0.7152, 0.0722][i] * (v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4);
      }, 0);
      for (const text of texts) {
        const fg = text.color.match(/[\d.]+/g).map(Number), alpha = fg[3] ?? 1;
        let minimum = Infinity;
        for (const sx of [.2, .5, .8]) for (const sy of [.25, .5, .75]) {
          const x = Math.floor(text.x + text.width * sx), y = Math.floor(text.y + text.height * sy);
          const offset = (y * raw.info.width + x) * 3;
          const bg = [...raw.data.subarray(offset, offset + 3)];
          const a = luma(fg.slice(0, 3).map((v, i) => v * alpha + bg[i] * (1 - alpha))), b = luma(bg);
          minimum = Math.min(minimum, (Math.max(a, b) + .05) / (Math.min(a, b) + .05));
        }
        contrastResults.push({ wallpaper, selector: text.selector, color: text.color, contrast: minimum });
        assert.ok(minimum >= 4.5, `${wallpaper}/${text.selector}: contrast ${minimum}, ${text.color}`);
      }
      assert.equal(await frame.locator('body').evaluate(el => getComputedStyle(el).backgroundColor), 'rgba(0, 0, 0, 0)');
      assert.match(await page.locator('.desktop-window').evaluate(el => getComputedStyle(el).backdropFilter), /blur\(15px\)/);
    }
    await page.locator('.desktop-window').evaluate(el => { el.style.left = '1%'; el.style.width = '50%'; });
    await page.clock.runFor(500);
    await page.screenshot({ path: path.join(out, 'contrast-window-moved.png'), animations: 'disabled' });
    await page.setViewportSize({ width: 390, height: 800 });
    await page.locator('.desktop-window').evaluate(el => { el.style.left = '0'; el.style.width = '100%'; });
    await page.clock.runFor(500);
    await page.screenshot({ path: path.join(out, 'contrast-mobile.png'), animations: 'disabled' });
    assert.equal(await frame.locator('html').evaluate(el => el.scrollWidth <= innerWidth), true);
    assert.deepEqual(errors, []);
    const result = { passed: true, errors, calls, materials, contrastResults, screenshots: out };
    await fs.writeFile(path.join(out, 'result.json'), JSON.stringify(result, null, 2));
    console.log(JSON.stringify(result));
    await context.close();
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
