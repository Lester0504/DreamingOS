// Run with playwright-cli run-code --filename tests/cloud-browser.browser.cjs.
async (page) => {
  const base = 'http://127.0.0.1:28797';
  if (!page.url().startsWith(base)) throw new Error('Isolated fixture server required');
  await page.unrouteAll({behavior: 'ignoreErrors'});
  let enabled = false, readOnly = false, failPreflight = false, revoking = false, last = '';
  const jobs = {}, writes = [], checks = [], errors = [];
  const assert = (ok, label) => { if (!ok) throw new Error(label); checks.push(label); };
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/api/v1/cloud/**', async route => {
    const request = route.request(), path = request.url().split('?')[0].replace(/^https?:\/\/[^/]+/, '');
    let data;
    const status = () => ({configured_enabled: enabled, state: revoking ? 'revoking' : enabled ? 'connected' : 'disabled',
      effective_enabled: enabled, ready: false, last_job_id: last});
    if (request.method() === 'POST') {
      const action = path.split('/').pop(), body = request.postDataJSON();
      writes.push({path, body});
      if (action === 'bind-code') data = {state: 'running'};
      else {
        last = String(Object.keys(jobs).length + 1).padStart(32, '0');
        if (action === 'enable') enabled = true;
        if (action === 'disable') enabled = false, revoking = true;
        jobs[last] = {job_id: last, action, state: action === 'disable' ? 'partial' : 'succeeded',
          error: action === 'disable' ? 'cloud_revocation_pending' : null,
          result: action === 'preflight' ? {enable_allowed: !failPreflight, expires_at: Date.now() / 1000 + 120,
            legacy_hostname: true, canonical_host: 'a-very-long-device-name-for-responsive-checks.dev.dreamingnet.com',
            cloud_id: 'a'.repeat(32), checks: {binding: {passed: true}, device_dns: {passed: !failPreflight, reason: failPreflight ? 'device_dns_not_local' : null}}} : status()};
        data = jobs[last];
      }
    } else if (path.endsWith('/capabilities')) data = {supported: true, can_write: !readOnly, reason: readOnly ? 'device_owner_required' : null};
    else if (path.endsWith('/local-domain')) data = {domain: null, passkey: {rp_id: 'lester.dev.dreamingnet.com'}};
    else if (path.endsWith('/bind-status')) data = {state: 'idle'};
    else if (path.includes('/jobs/')) data = jobs[path.split('/').pop()];
    else data = status();
    await route.fulfill({json: {ok: true, data}});
  });
  await page.goto(base + '/fixture');
  await page.getByRole('button', {name: '运行预检', exact: true}).waitFor();
  await page.getByRole('button', {name: '运行预检', exact: true}).click();
  await page.getByText('预检：已完成').waitFor();
  assert(writes.length === 1, 'preflight makes one write');
  await page.getByRole('checkbox', {name: '保留现有域名与 Passkey 身份'}).check();
  await page.getByRole('button', {name: '启用', exact: true}).click();
  assert(writes.length === 1, 'confirmation does not write');
  await page.locator('.dwrt-kit-confirmation-cancel').click();
  assert(writes.length === 1, 'cancel does not write');
  await page.getByRole('button', {name: '启用', exact: true}).click();
  await page.locator('[data-dwrt-confirm-accept]').click();
  await page.getByText('隧道已连接', {exact: false}).waitFor();
  assert(writes[1].body.legacy_hostname_ack === true && !!writes[1].body.preflight_id, 'enable uses preflight and explicit legacy ack');
  assert((await page.locator('main').innerText()).includes('浏览器入口尚未验证'), 'connected does not claim ready');
  await page.getByRole('button', {name: '重新连接', exact: true}).click();
  await page.getByText('重连：已完成').waitFor();
  await page.getByRole('switch', {name: '浏览器云访问', exact: true}).click();
  await page.locator('[data-dwrt-confirm-accept]').click();
  await page.getByText('关闭：部分完成', {exact: false}).waitFor();
  assert((await page.locator('main').innerText()).includes('云端撤销待同步'), 'partial retains revocation warning');
  revoking = false; jobs[last].state = 'succeeded'; jobs[last].error = null;
  await page.getByRole('button', {name: '刷新', exact: true}).click();
  await page.getByText('关闭：已完成').waitFor();
  assert(writes.every(w => w.path !== '/api/v1/cloud/disable'), 'browser never calls App disable');
  readOnly = true;
  await page.getByRole('button', {name: '刷新', exact: true}).click();
  await page.getByText('需要设备所有者权限').waitFor();
  assert(await page.getByRole('button', {name: '运行预检', exact: true}).isDisabled(), 'viewer cannot write');
  readOnly = false; failPreflight = true;
  await page.getByRole('button', {name: '刷新', exact: true}).click();
  await page.getByRole('button', {name: '运行预检', exact: true}).click();
  await page.getByText('设备域名未全部解析到本机').waitFor();
  assert(await page.getByRole('button', {name: '启用', exact: true}).isDisabled(), 'failed preflight cannot enable');
  for (const width of [1440, 1280, 390, 360]) {
    await page.setViewportSize({width, height: 960});
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `no overflow at ${width}`);
    await page.screenshot({path: `/tmp/cloud-ui-0928/device-${width}.png`, fullPage: true});
  }
  assert(errors.length === 0, 'no page errors');
  console.log(JSON.stringify({checks, writes: writes.map(w => w.path)}));
}
