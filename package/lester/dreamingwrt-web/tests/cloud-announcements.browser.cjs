// Run with playwright-cli run-code against the local static tree. Cloud data is
// intercepted in this browser only; router API access uses the read-only account.
async (page) => {
  const base = 'http://127.0.0.1:18849';
  const live = 'http://192.168.30.1';
  const checks = [];
  const check = (ok, label) => { if (!ok) throw new Error(label); checks.push(label); };
  const login = await page.request.post(`${live}/api/v1/session/login`, {
    data: { username: 'agent-ro', password: 'DwrtAcceptRO2026' }
  });
  if (!login.ok()) throw new Error(`Read-only login: ${login.status()}`);
  const auth = (await login.json()).data;
  await page.goto(base);
  await page.evaluate(() => localStorage.removeItem('dreamingwrt.cloud-announcements.v1.agent-ro'));
  await page.addInitScript((auth) => {
    localStorage.setItem('dreamingwrt.web.accessToken', auth.access_token);
    localStorage.setItem('dreamingwrt.web.refreshToken', auth.refresh_token);
    localStorage.setItem('dreamingwrt.web.expiresAt', String(Date.now() + 800000));
    localStorage.setItem('dreamingwrt.web.username', 'agent-ro');
    localStorage.setItem('dreamingwrt.web.role', 'viewer');
    window.EventSource = class extends EventTarget {
      constructor(url) { super(); this.url = url; window.__announcementStreams = [...(window.__announcementStreams || []), this]; }
      close() { this.closed = true; }
    };
  }, auth);
  await page.route(`${base}/api/**`, async (route) => {
    if (!['GET', 'HEAD'].includes(route.request().method()) && !route.request().url().endsWith('/session/refresh')) {
      await route.fulfill({ status: 403, body: '{}' }); return;
    }
    const response = await route.fetch({ url: route.request().url().replace(base, live) });
    await route.fulfill({ response });
  });
  let payload = { revision: 3, announcements: [
    { id: 'urgent', revision: 3, title: '电视与网络服务维护通知', content: '服务维护将在今晚进行。\n<script>plain text</script>\n' + '维护期间请保留当前设置。\n'.repeat(100), type: 'danger', targets: ['router', 'tv'], published: true },
    { id: 'warn', revision: 2, title: '部分服务临时维护', content: '第二条内容', type: 'warning', targets: ['router'], published: true },
    { id: 'info', revision: 1, title: '服务更新公告', content: '第三条内容', type: 'info', targets: ['router'], published: true },
  ] };
  let fail = false;
  await page.route('https://update-os.dreamingnet.com/v1/announcements?target=router', (route) =>
    route.fulfill({ status: fail ? 503 : 200, contentType: 'application/json', body: JSON.stringify({ ok: true, data: payload }) }));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${base}/app/#/dashboard`);
  await page.waitForFunction(() => window.DWRTCloudAnnouncements && document.querySelector('.cloud-announcements-bell')?.dataset.unread === 'true');
  const dialog = page.locator('.cloud-announcements');
  check(!await dialog.isVisible(), 'Inbox closed on arrival');
  check(await page.locator('.dwrt-notify--error').count() > 0, 'Urgent arrival uses existing toast');
  await page.getByRole('button', { name: '公告（3 条未读）', exact: true }).click();
  check(await dialog.getByRole('button', { name: /紧急 · 未读/ }).count() === 1, 'Three levels and unread labels');
  await page.screenshot({ path: 'dreamingwrt-web/output/playwright/announcements-web-desktop.png' });
  await dialog.getByRole('button', { name: /紧急 · 未读/ }).click();
  check(await dialog.locator('.cloud-announcements-content').textContent().then(t => t.includes('<script>plain text</script>')), 'Content remains plain text');
  await page.setViewportSize({ width: 320, height: 700 });
  await page.screenshot({ path: 'dreamingwrt-web/output/playwright/announcements-web-detail-320.png' });
  check(await dialog.evaluate(el => el.scrollHeight > el.clientHeight), 'Long detail scrolls');
  check(await dialog.evaluate(el => el.getBoundingClientRect().left >= 0 && el.getBoundingClientRect().right <= innerWidth), '320px detail contained');
  await dialog.getByRole('button', { name: '返回公告', exact: true }).click();
  await dialog.getByRole('button', { name: '关闭', exact: true }).click();
  await page.reload();
  await page.waitForFunction(() => document.querySelector('.cloud-announcements-bell')?.getAttribute('aria-label') === '公告（2 条未读）');
  check(true, 'Read version persists on reload');
  const send = async () => page.evaluate(value => {
    const streams = window.__announcementStreams.filter(s => !s.closed);
    streams.forEach(s => s.dispatchEvent(new MessageEvent('announcements', { data: JSON.stringify(value) })));
  }, payload);
  payload = { revision: 4, announcements: [{ ...payload.announcements[0], revision: 4, title: '编辑后的公告' }] };
  await send();
  await page.getByRole('button', { name: '公告（1 条未读）', exact: true }).click();
  await dialog.getByRole('button', { name: /编辑后的公告/ }).click();
  payload = { revision: 5, announcements: [] };
  await send();
  check(await dialog.getByText('暂无公告', { exact: true }).count() === 1, 'Withdrawal closes detail and clears list');
  check(await page.locator('.dwrt-notify--error').count() === 0, 'Withdrawal removes toast');
  payload = { revision: 6, announcements: [{ id: 'new', revision: 6, title: '保留内容', content: '正文', type: 'info', targets: ['router'], published: true }] };
  await send();
  fail = true;
  await page.evaluate(() => window.dispatchEvent(new Event('online')));
  await dialog.getByText('公告连接失败，保留上次内容').waitFor();
  check(await dialog.getByText('保留内容').count() === 1, 'Fetch error retains last list');
  fail = false;
  await dialog.getByRole('button', { name: '重试', exact: true }).click();
  await dialog.getByText('公告连接失败，保留上次内容').waitFor({ state: 'hidden' });
  await dialog.getByLabel('静音公告提醒').check();
  await dialog.getByRole('button', { name: '关闭', exact: true }).click();
  payload = { revision: 7, announcements: [{ ...payload.announcements[0], revision: 7, type: 'danger' }] };
  await send();
  check(await page.locator('.dwrt-notify--error').count() === 0, 'Mute suppresses urgent toast too');
  for (const width of [1440, 1024, 768, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    await page.evaluate(() => window.DWRTCloudAnnouncements.open());
    check(await dialog.evaluate(el => el.scrollWidth <= el.clientWidth), `Inbox horizontal layout ${width}`);
    await dialog.getByRole('button', { name: '关闭', exact: true }).click();
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${base}/app/desktop.html`);
  await page.waitForFunction(() => window.DWRTCloudAnnouncements && document.querySelector('[data-action="notifications"]'));
  await page.locator('[data-action="notifications"]:visible').first().click();
  await page.locator('.cloud-announcements-entry').waitFor();
  await page.locator('.cloud-announcements-entry').click();
  check(await dialog.getByText('保留内容').count() === 1, 'Desktop existing drawer opens cloud inbox');
  check(await page.evaluate(() => window.__announcementStreams.filter(s => !s.closed).length) === 1, 'Desktop host has one receiver');
  const embeddedReceivers = await Promise.all(page.frames().filter(f => f !== page.mainFrame()).map(f => f.evaluate(() => !!window.DWRTCloudAnnouncements).catch(() => false)));
  check(embeddedReceivers.every(v => !v), 'Embedded registry and apps have no duplicate receiver');
  await page.screenshot({ path: 'dreamingwrt-web/output/playwright/announcements-web-desktop-mode.png' });
  return { checks: checks.length, results: checks };
}
