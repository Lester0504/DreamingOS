// Real desktop shell with local-only API fixtures; no device requests or writes.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require('playwright');

const web = path.resolve(__dirname, '../files/www/dreamingwrt');
const out = path.resolve(__dirname, '../output/playwright/file-manager-host');
const origin = 'http://file-manager.test';
const root = { id: 'fixture', label: 'TEST ONLY - Storage', path: '/fixture', read_only: false,
  total_bytes: 16 * 1024 ** 3, available_bytes: 10 * 1024 ** 3 };
const caps = { list: true, read: true, write: true, mkdir: true, create: true, search: true };
const entries = [
  { name: 'Documents', path: '/fixture/Documents', is_dir: true, kind: 'directory' },
  { name: 'notes.txt', path: '/fixture/notes.txt', kind: 'text', size_bytes: 32 },
  { name: 'archive.zip', path: '/fixture/archive.zip', kind: 'file', size_bytes: 1048576 },
  { name: 'image.png', path: '/fixture/image.png', kind: 'file', size_bytes: 4096 }
].map(entry => ({ modified_unix: 1790000000, mode: '-rw-r--r--', owner: 'fixture',
  group: 'fixture', is_dir: false, capabilities: caps, ...entry }));

(async () => {
  await fs.mkdir(out, { recursive: true });
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const errors = [], writes = [], materials = [];
  try {
    await context.addInitScript(() => {
      localStorage.setItem('dreamingwrt.web.accessToken', 'TEST-ONLY-FIXTURE');
      localStorage.setItem('dreamingwrt.web.role', 'admin');
      localStorage.setItem('dreamingwrt.web.username', 'TEST-ONLY-FIXTURE');
      localStorage.setItem('dreamingwrt.web.expiresAt', String(Date.now() + 3600000));
      localStorage.setItem('dreamingwrt.web.themeFamily', 'frosted-glass');
      localStorage.setItem('dreamingwrt.web.themePref', 'light');
    });
    await context.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url());
      if (url.origin !== origin) return route.abort('blockedbyclient');
      if (url.pathname === '/app/') return route.fulfill({
        contentType: 'text/html; charset=utf-8',
        body: url.searchParams.get('desktop') === 'router'
          ? `<script>parent.postMessage({type:'dwrt-desktop:menu',items:[
              {id:'storage-service',icon:'folder',children:[
                {label:'文件管理',path:'/app/#/storage/files'},
                {label:'存储空间',path:'/app/#/storage/volumes'},
                {label:'未开放工具',path:'/app/#/storage/disabled',disabled:true}
              ]}]},location.origin)</script>`
          : '<!doctype html><title>TEST ONLY storage tool</title><p>TEST ONLY storage tool</p>'
      });
      if (url.pathname.startsWith('/api/')) {
        if (request.method() !== 'GET') writes.push(`${request.method()} ${url.pathname}`);
        let data = {};
        if (url.pathname === '/api/v1/storage/files') data = {
          roots: [root], root_id: root.id, path: '/fixture', entries,
          capabilities: caps, limits: { max_text_read_bytes: 262144 }
        };
        if (url.pathname.endsWith('/content')) data = { content: 'TEST ONLY text\n', etag: 'fixture-1' };
        return route.fulfill({ contentType: 'application/json', body: JSON.stringify({ code: 2000, data }) });
      }
      try { return await route.fulfill({ path: path.join(web, url.pathname) }); }
      catch (_) { return route.fulfill({ status: 404, body: '' }); }
    });
    const page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(`${origin}/app/desktop.html`);
    await page.locator('#desktopRegistry[data-hydrated="true"]').waitFor({ state: 'attached' });
    await page.locator('#desktopCanvas [data-app-id="storage-service"]').click();
    const window = page.locator('.desktop-window[data-app-id="storage-service"]');
    const app = window.frameLocator('iframe');
    await app.locator('.fm-entry').first().waitFor();
    assert.equal(await window.locator('[data-route]').count(), 0);
    assert.equal(await app.locator('.fm-storage-tool').count(), 1);
    assert.equal(await app.locator('html').getAttribute('data-desktop-app'), 'true');
    await page.locator('#desktopDock [data-app-id="storage-service"]').click();
    assert.equal(await page.locator('.desktop-window[data-app-id="storage-service"]').count(), 1);
    assert.equal(await window.isVisible(), false);
    await page.locator('#desktopDock [data-app-id="storage-service"]').click();
    await window.locator('[data-window-action="minimize"]').click();
    assert.equal(await window.isVisible(), false);
    await page.locator('#desktopDock [data-app-id="storage-service"]').click();
    await window.waitFor({ state: 'visible' });
    for (const theme of ['light', 'dark']) {
      for (const family of ['frosted-glass', 'liquid-glass', 'traditional']) {
        await page.evaluate(({ theme, family }) => {
          document.documentElement.dataset.themeResolved = theme;
          document.documentElement.dataset.themeFamily = family;
        }, { theme, family });
        await app.locator(`html[data-theme-resolved="${theme}"][data-theme-family="${family}"]`).waitFor({ state: 'attached' });
        assert.equal(await app.locator('body').evaluate(el => getComputedStyle(el).backgroundColor), 'rgba(0, 0, 0, 0)');
        await page.screenshot({ path: path.join(out, `${theme}-${family}.png`) });
        await app.locator('[data-action="mkdir"]').click();
        await app.locator('.fm-sheet').evaluate(async el => {
          await new Promise(resolve => {
            const tick = () => Math.abs(new DOMMatrixReadOnly(getComputedStyle(el).transform).m41) < .01
              ? resolve() : requestAnimationFrame(tick);
            tick();
          });
        });
        await app.locator('.fm-sheet[data-dwrt-wallpaper-ready="true"]').waitFor();
        await page.screenshot({ path: path.join(out, `${theme}-${family}-sheet.png`) });
        materials.push({
          theme, family,
          window: await window.evaluate(el => ({ background: getComputedStyle(el).backgroundColor, backdrop: getComputedStyle(el).backdropFilter })),
          sheet: await app.locator('.fm-sheet').evaluate(el => ({
            ready: el.dataset.dwrtWallpaperReady,
            background: getComputedStyle(el.querySelector('.dwrt-kit-sheet-material') || el).backgroundColor,
            backdrop: getComputedStyle(el.querySelector('.dwrt-kit-sheet-material') || el).backdropFilter
          }))
        });
        await app.locator('.fm-sheet input').press('Escape');
        await app.locator('.fm-sheet').waitFor({ state: 'detached' });
      }
    }
    await app.locator('.fm-storage-tool').click();
    await app.locator('#fmToolFrame').waitFor({ state: 'visible' });
    assert.match(await app.locator('#fmToolFrame').getAttribute('src'), /#\/storage\/volumes$/);
    await app.locator('[data-action="files"]').click();
    await app.locator('[data-open="/fixture/notes.txt"]').click();
    await app.locator('textarea').fill('TEST ONLY unsaved text');
    await window.locator('[data-window-action="close"]').click();
    await page.locator('#desktopConfirm[open]').waitFor();
    await page.locator('#desktopConfirm button[value="cancel"]').click();
    assert.equal(await app.locator('textarea').inputValue(), 'TEST ONLY unsaved text');
    await app.locator('[data-dwrt-savebar-discard]').click();
    await app.locator('.fm-sheet [data-fm-close]').first().click();
    await app.locator('.fm-sheet').waitFor({ state: 'detached' });
    for (const width of [1280, 390, 320]) {
      await page.setViewportSize({ width, height: 800 });
      if (width === 1280) await window.locator('[data-window-action="maximize"]').click();
      await app.locator('[data-action="grid"]').click();
      const geometry = await window.evaluate(el => {
        const rect = el.getBoundingClientRect();
        return { left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom,
          viewport: innerWidth, outer: document.documentElement.scrollWidth };
      });
      assert.ok(geometry.left >= 0 && geometry.right <= width + 1, JSON.stringify(geometry));
      assert.ok(geometry.outer <= width);
      const fit = await app.locator('.fm-shell').evaluate(el => ({
        width: el.getBoundingClientRect().width, viewport: innerWidth, outer: document.documentElement.scrollWidth
      }));
      assert.ok(fit.width <= fit.viewport && fit.outer <= fit.viewport, JSON.stringify(fit));
      await page.screenshot({ path: path.join(out, `host-${width}.png`) });
    }
    assert.deepEqual(errors, []);
    assert.deepEqual(writes, []);
    await fs.writeFile(path.join(out, 'report.json'), JSON.stringify({ passed: true, fixtureOnly: true, errors, writes, materials }, null, 2));
    console.log(JSON.stringify({ passed: true, errors, writes, materials }));
  } finally {
    await context.close();
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
