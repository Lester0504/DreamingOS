// Private fixture: real UI Kit and DOM, mocked device API, real Chromium virtual Passkey.
async (page) => {
  const base = 'http://localhost:28797'; // WebAuthn requires a domain RP, not an IP RP.
  await page.unrouteAll({behavior: 'ignoreErrors'});
  const checks = [], writes = [], pageErrors = [];
  const assert = (ok, label) => { if (!ok) throw new Error(label); checks.push(label); };
  page.on('pageerror', e => pageErrors.push(e.message));
  const randomBytes = n => Buffer.from(crypto.getRandomValues(new Uint8Array(n)));
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const {authenticatorId} = await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true
  }});
  const credentialId = randomBytes(32);
  const {privateKey} = await crypto.subtle.generateKey({name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify']);
  await cdp.send('WebAuthn.addCredential', {authenticatorId, credential: {
    credentialId: credentialId.toString('base64'), isResidentCredential: true, rpId: 'localhost',
    privateKey: Buffer.from(await crypto.subtle.exportKey('pkcs8', privateKey)).toString('base64'),
    userHandle: Buffer.from('fixture-owner').toString('base64'), signCount: 0
  }});
  let writable = true, mode = 'gateway', revision = 'revision-1', outcome = 'partial', job = null, reads = 0, seq = 0;
  let passkeyChallenge;
  await page.route(base + '/api/v1/cloud/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname;
    let status = 200, data = {}, code = '';
    if (request.method() === 'POST') {
      const body = request.postDataJSON(); writes.push({path, body});
      if (!writable) { status = 403; code = 'permission_denied'; }
      else if (path.endsWith('/reauth/begin')) {
        passkeyChallenge = randomBytes(32).toString('base64url');
        data = {ok: true, publicKeyCredentialRequestOptions: {
          challenge: passkeyChallenge, rpId: 'localhost', timeout: 10000, userVerification: 'required',
          allowCredentials: [{id: credentialId.toString('base64url'), type: 'public-key'}]
        }};
        await route.fulfill({status, json: data}); return;
      } else if (path.endsWith('/apply') && body.revision !== revision) { status = 409; code = 'revision_conflict'; }
      else if (body.authentication?.method === 'password' && body.authentication.password !== 'fixture-password') { status = 401; code = 'invalid_password'; }
      else {
        job = {job_id: String(++seq).padStart(32, '0'), action: path.endsWith('/probe') ? 'local_domain_probe' : 'local_domain_apply', state: 'queued'};
        data = {...job}; status = 202; reads = 0;
      }
    } else if (path.includes('/local-domain/jobs/')) {
      if (!job) { status = 404; code = 'not_found'; }
      else {
        data = {...job, state: reads++ ? outcome : 'running'};
        if (data.state !== 'running') data.result = outcome === 'failed' ?
          {configured: false, rolled_back: true, error: 'dns_reload_failed'} : outcome === 'rollback-failed' ?
          {configured: false, rolled_back: false, rollback_error: 'dns_rollback_failed', backup: '/etc/dreamingwrt/cloud-domain-backups/fixture'} :
          {configured: true, reloaded: true, backup: '/etc/dreamingwrt/cloud-domain-backups/fixture', probe: {
            dns_server: '127.0.0.1', dns_matches: true, addresses: ['192.168.1.3'], tls_valid: outcome === 'succeeded',
            tls_error: outcome === 'succeeded' ? '' : 'Fixture certificate is not trusted', client_verified: false
          }};
        if (outcome === 'rollback-failed' && data.state !== 'running') data.state = 'failed';
        if (job.action === 'local_domain_probe' && data.result?.probe) data.result = data.result.probe;
      }
    } else if (path.endsWith('/local-domain')) data = {domain: 'localhost', passkey: {rp_id: 'localhost'}, apply_plan: {
      domain: 'localhost', work_mode: mode, can_write: writable, can_apply: mode === 'gateway', revision,
      reason: mode === 'side-router' ? 'external_dns_action_required' : null,
      records: [{host: 'localhost', address: '192.168.1.3', type: 'A'}, {host: 'localhost', address: 'fd00::1234:abcd:ef12:3456', type: 'AAAA'}]
    }};
    else if (path.endsWith('/capabilities')) data = {can_write: false, supported: false, service_crud: false};
    else if (path.endsWith('/services')) data = {revision: 's1', services: []};
    else data = {state: 'disabled', configured_enabled: false};
    await route.fulfill({status, json: code ? {ok: false, error: {code}} : {ok: true, data}});
  });
  await page.goto(base + '/fixture');
  await page.evaluate(() => sessionStorage.removeItem('dwrt-local-domain-job'));
  await page.reload();
  const open = () => page.getByRole('button', {name: '应用本地解析', exact: true});
  const password = () => page.getByLabel('当前账号密码', {exact: true});
  const submit = () => page.getByRole('button', {name: '用密码验证并应用', exact: true});
  await open().waitFor();
  assert(await open().isEnabled(), 'DNS independent of browser-cloud enable capability');
  await open().click(); await password().fill('draft-secret');
  await page.waitForTimeout(3200);
  assert(await password().inputValue() === 'draft-secret', 'polling preserves confirmation input');
  await page.getByRole('button', {name: '取消', exact: true}).click();
  assert(writes.length === 0, 'cancel performs no writes');
  await open().click(); assert(await password().inputValue() === '', 'cancel clears password');
  await password().fill('wrong'); await submit().click();
  await page.getByText('密码不正确，请重新输入', {exact: true}).waitFor();
  assert(await password().inputValue() === '', 'failed authentication clears password');
  await password().fill('fixture-password'); await submit().click();
  await page.getByText('配置已应用，检查未全部通过', {exact: true}).waitFor({timeout: 10000});
  assert(writes.at(-1).body.confirm === true && writes.at(-1).body.revision === 'revision-1', 'apply carries explicit confirmation and preview revision');
  assert(await page.getByText(/当前客户端仍需使用正确的 DNS/).isVisible(), 'partial does not imply client success');
  await page.reload();
  await page.getByText('配置已应用，检查未全部通过', {exact: true}).waitFor();
  assert(true, 'job id survives reload and result is fetched again');
  await open().click(); revision = 'revision-2'; await password().fill('fixture-password'); await submit().click();
  await page.getByText(/DNS 配置已变化/).waitFor();
  assert(await submit().isDisabled(), 'stale preview cannot overwrite configuration');
  await page.getByRole('button', {name: '取消', exact: true}).click();
  await page.getByRole('button', {name: '刷新', exact: true}).click();
  await page.waitForTimeout(250); await open().click();
  await page.evaluate(() => Object.defineProperty(navigator.credentials, 'get', {configurable: true,
    value: async () => { throw new DOMException('Cancelled by fixture', 'NotAllowedError'); }}));
  const appliesBeforeCancel = writes.filter(write => write.path.endsWith('/apply')).length;
  await page.getByRole('button', {name: '用 Passkey 验证并应用', exact: true}).click();
  await page.getByText('Passkey 验证已取消或超时，可重试。', {exact: true}).waitFor();
  assert(writes.filter(write => write.path.endsWith('/apply')).length === appliesBeforeCancel, 'cancelled Passkey never applies DNS');
  await page.evaluate(() => delete navigator.credentials.get);
  outcome = 'succeeded';
  await page.getByRole('button', {name: '用 Passkey 验证并应用', exact: true}).click();
  await page.getByText('设备侧检查通过', {exact: true}).waitFor({timeout: 10000});
  const assertion = writes.at(-1).body.authentication.assertion;
  const clientData = JSON.parse(Buffer.from(assertion.response.clientDataJSON, 'base64url').toString());
  assert(clientData.challenge === passkeyChallenge && clientData.type === 'webauthn.get', 'real browser assertion matches begin challenge');
  assert((Buffer.from(assertion.response.authenticatorData, 'base64url')[32] & 5) === 5, 'virtual authenticator returns UP and UV');
  assert(assertion.response.signature.length > 0 && !('password' in writes.at(-1).body.authentication), 'Passkey payload has signature and no password');
  for (const width of [1440, 390, 320]) {
    await page.setViewportSize({width, height: 900});
    await page.locator('.system-local-domain').scrollIntoViewIfNeeded();
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `DNS page fits ${width}`);
    await page.screenshot({path: `/tmp/hw-cloud-resume-1005/dns-page-${width}.png`, fullPage: true});
    await open().click();
    assert(await page.evaluate(() => { const r = document.querySelector('[role="dialog"]').getBoundingClientRect(); return r.left >= 0 && r.right <= innerWidth && r.bottom <= innerHeight; }), `confirmation fits ${width}`);
    await page.screenshot({path: `/tmp/hw-cloud-resume-1005/dns-confirm-${width}.png`, fullPage: true});
    await page.keyboard.press('Escape');
  }
  outcome = 'failed'; await open().click(); await password().fill('fixture-password'); await submit().click();
  await page.getByText('应用失败，原配置已恢复。', {exact: true}).waitFor({timeout: 10000});
  outcome = 'rollback-failed'; await open().click(); await password().fill('fixture-password'); await submit().click();
  await page.getByText('自动恢复失败，请按备份检查 DNS 配置', {exact: true}).waitFor({timeout: 10000});
  assert(true, 'rollback success and rollback failure are distinct');
  mode = 'side-router'; await page.getByRole('button', {name: '刷新', exact: true}).click();
  await page.getByText('请在客户端使用的网关或 DNS 服务器上配置以下记录。', {exact: true}).waitFor();
  assert(await open().count() === 0, 'side router exposes records without apply action');
  outcome = 'succeeded';
  await page.getByRole('button', {name: '检查解析', exact: true}).click();
  await page.getByText('设备侧检查通过', {exact: true}).waitFor({timeout: 10000});
  assert(writes.at(-1).path.endsWith('/probe') && Object.keys(writes.at(-1).body).length === 0, 'probe is independent and carries no credentials');
  writable = false; await page.getByRole('button', {name: '刷新', exact: true}).click();
  await page.getByText('需要设备所有者从局域网连接执行。', {exact: true}).waitFor();
  assert(await page.getByRole('button', {name: '检查解析', exact: true}).isDisabled(), 'read-only role cannot probe');
  const stored = await page.evaluate(() => JSON.stringify({local: {...localStorage}, session: {...sessionStorage}}));
  assert(!stored.includes('fixture-password') && !stored.includes('draft-secret'), 'passwords are not persisted');
  assert(!pageErrors.length, `no page errors: ${pageErrors.join('; ')}`);
  await cdp.send('WebAuthn.removeVirtualAuthenticator', {authenticatorId}); await cdp.detach();
  await page.unrouteAll({behavior: 'ignoreErrors'});
  return {checks, writes: writes.length};
}
