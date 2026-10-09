const BASE = '/api/v1/cloud/local-domain';
const JOB_KEY = 'dwrt-local-domain-job';
const payload = value => value?.data ?? value;
const active = job => ['queued', 'running'].includes(job?.state);
const errors = {
  local_domain_unconfigured: '尚未配置设备域名', lan_address_unavailable: '未读到可用的内网地址',
  work_mode_unavailable: '当前工作模式尚未就绪', identity_migration_required: '域名与 Passkey 身份不一致，需先完成迁移',
  external_dns_action_required: '请在客户端使用的网关或 DNS 服务器上配置以下记录。',
  dns_configuration_unavailable: '无法读取 DNS 配置', dns_service_unavailable: '本机 DNS 服务未启用',
  dns_pending_changes: 'DNS 有尚未提交的修改，请先处理后再应用',
  revision_conflict: 'DNS 配置已变化，请关闭确认框，刷新后重新核对记录。',
  password_required: '请输入当前账号密码', invalid_password: '密码不正确，请重新输入',
  authentication_required: '登录已过期，请重新登录', authentication_unavailable: '暂时无法验证账号',
  reauthentication_required: '请使用密码或 Passkey 再次验证', permission_denied: '需要设备所有者权限',
  local_confirmation_required: '请从设备局域网连接执行此操作', operation_busy: '已有 DNS 操作正在执行',
  dns_write_failed: 'DNS 配置写入失败', dns_readback_failed: 'DNS 配置读回失败',
  dns_reload_failed: 'DNS 重新加载失败', dns_rollback_failed: '自动恢复失败，请按备份检查 DNS 配置',
  job_interrupted: '操作被中断，请重新检查设备解析', job_unavailable: '无法启动操作',
  invalid_challenge: '验证请求已失效，请重试', no_credentials: '当前账号没有可用的 Passkey',
  user_verification_required: 'Passkey 需要完成指纹、面容或 PIN 验证',
  rate_limited: '验证过于频繁，请稍后重试'
};
const message = error => errors[error?.payload?.error?.code || error] || error?.payload?.error?.message || error?.message || String(error || '');
const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4-value.length%4)%4)), c => c.charCodeAt(0)).buffer;
const encode = buffer => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export function createLocalDomain({get, post, escapeHtml: esc, icon, render}) {
  let snapshot, job, jobId = '', dialog = null, busy = false, error = '', bindings, host, alive = true;
  let credentialRequest;
  try { jobId = sessionStorage.getItem(JOB_KEY) || ''; } catch {}
  const remember = id => { jobId = id; try { if (id) sessionStorage.setItem(JOB_KEY, id); else sessionStorage.removeItem(JOB_KEY); } catch {} };
  const allowed = () => snapshot?.apply_plan?.can_write === true && !busy && !active(job);
  const canApply = () => allowed() && snapshot?.apply_plan?.can_apply === true;
  const passkeyAvailable = () => window.isSecureContext && !!navigator.credentials?.get && !!window.PublicKeyCredential;
  const button = (action, label, disabled = false) => `<button type="button" class="system-demo-btn secondary compact-btn" data-domain-action="${action}" ${disabled ? 'disabled' : ''}>${label}</button>`;
  const records = plan => `<ul class="system-browser-checks">${(plan?.records || []).map(record => `<li><span><code>${esc(record.host)}</code> · ${esc(record.type)}</span><span><code>${esc(record.address)}</code></span></li>`).join('')}</ul>`;

  function markup() {
    const plan = snapshot?.apply_plan;
    const result = job?.result, probe = result?.probe || (job?.action === 'local_domain_probe' ? result : null);
    const states = {queued: '已排队', running: '检查中', succeeded: '设备侧检查通过', partial: '配置已应用，检查未全部通过', failed: '未完成'};
    return `<section class="system-browser-services system-local-domain" aria-label="本地域名解析" data-adaptive-region>
      <header class="system-browser-header"><h3>本地域名解析</h3></header>
      ${plan ? `<p>${plan.work_mode === 'side-router' ? '旁路由模式' : plan.work_mode === 'gateway' ? '主路由模式' : '工作模式不可用'}${plan.domain ? ` · ${esc(plan.domain)}` : ''}</p>
        ${records(plan)}${plan.reason ? `<p class="system-admin-access-note">${esc(message(plan.reason))}</p>` : ''}` : '<p class="system-admin-access-note">当前设备未提供本地解析操作。</p>'}
      <div class="system-browser-actions">${button('probe', '检查解析', !allowed() || !plan?.domain)}
        ${plan?.work_mode !== 'side-router' ? button('open', '应用本地解析', !canApply()) : ''}</div>
      ${plan && !plan.can_write ? '<p class="system-admin-access-note">需要设备所有者从局域网连接执行。</p>' : ''}
      ${error && !dialog ? `<p class="system-inline-error" role="alert">${esc(error)}</p>` : ''}
      ${job ? `<div role="status"><p>${esc(states[job.state] || job.state)}${job.error ? ` · ${esc(message(job.error))}` : ''}</p>
        ${result?.configured ? '<p>本机解析配置已读回，DNS 已重新加载。</p>' : ''}
        ${result?.rolled_back === true ? '<p>应用失败，原配置已恢复。</p>' : ''}
        ${result?.rollback_error ? `<p class="system-inline-error">${esc(message(result.rollback_error))}</p>` : ''}
        ${result?.backup ? `<p class="system-admin-access-note">设备备份：<code>${esc(result.backup)}</code></p>` : ''}
        ${probe ? `<ul class="system-browser-checks"><li><span>设备 DNS（${esc(probe.dns_server || '127.0.0.1')}）</span><span>${probe.dns_matches ? '匹配预期记录' : '未匹配预期记录'}</span></li>
          <li><span>设备 HTTPS</span><span>${probe.tls_valid ? '证书与连接检查通过' : '检查未通过'}</span></li></ul>
          ${probe.addresses?.length ? `<p>设备解析到：${esc(probe.addresses.join('、'))}</p>` : ''}
          ${probe.tls_error ? `<p class="system-admin-access-note">${esc(probe.tls_error)}</p>` : ''}` : ''}</div>` : ''}
      <p class="system-admin-access-note">检查由设备执行。当前客户端仍需使用正确的 DNS，并通过设备域名验证访问。</p>
    </section>`;
  }

  function modalMarkup() {
    if (!dialog) return '';
    return `<div class="dwrt-kit-modal-layer system-cloud-service-layer is-open" data-dwrt-component="modal">
      <button type="button" class="dwrt-kit-modal-backdrop" data-domain-action="cancel" aria-label="取消解析应用" ${busy ? 'disabled' : ''}></button>
      <section class="dwrt-kit-modal dwrt-kit-glass-surface" role="dialog" aria-modal="true" aria-labelledby="cloudDnsTitle">
        <header class="dwrt-kit-modal-header"><h2 id="cloudDnsTitle">确认应用本地解析</h2>
          <button class="dwrt-kit-modal-close" type="button" data-domain-action="cancel" aria-label="关闭" ${busy ? 'disabled' : ''}>${icon('close')}</button></header>
        <form data-domain-form><div class="dwrt-kit-modal-body system-cloud-service-fields">
          <p>将以下记录写入本机 DNS，备份现有配置后重新加载。请再次验证当前设备账号。</p>
          ${records(dialog)}
          ${error ? `<p class="system-inline-error" role="alert">${esc(error)}</p>` : ''}
          <label class="dwrt-kit-field"><span>当前账号密码</span><input class="system-glass-input" name="dns-current-password" type="password" autocomplete="current-password" maxlength="1024" ${busy ? 'disabled' : ''}></label>
          ${!passkeyAvailable() ? '<p class="system-admin-access-note">此连接无法使用 Passkey；可通过设备的 HTTPS 域名访问后重试。</p>' : ''}
          <p class="system-admin-access-note">域名与已有 Passkey 身份保持不变。浏览器云访问可继续保持关闭。</p>
        </div><footer class="dwrt-kit-modal-footer system-browser-actions">
          ${button('cancel', '取消', busy)}${button('passkey', busy ? '正在验证…' : '用 Passkey 验证并应用', busy || !passkeyAvailable() || dialog.stale)}
          <button type="submit" class="system-demo-btn secondary" ${busy || dialog.stale ? 'disabled' : ''}>${busy ? '正在提交…' : '用密码验证并应用'}</button>
        </footer></form></section></div>`;
  }

  async function poll() {
    if (!jobId || !snapshot?.apply_plan?.can_write) return;
    try {
      const next = payload(await get(`${BASE}/jobs/${encodeURIComponent(jobId)}`));
      if (alive) { job = next; error = ''; }
    } catch (e) {
      if (!alive) return;
      if (e.status === 404) { remember(''); job = null; }
      else error = message(e);
    }
  }

  function close() {
    if (busy) return;
    dialog = null; error = ''; render();
    host?.querySelector('[data-domain-action="open"]')?.focus();
  }

  async function submit(method) {
    if (!canApply() || !dialog || dialog.stale) return;
    const revision = dialog.revision;
    const input = host.querySelector('[name="dns-current-password"]');
    let password = input?.value || '';
    if (method === 'password' && !password) { error = errors.password_required; render(); return; }
    if (input) input.value = '';
    busy = true; error = ''; render();
    try {
      let authentication;
      if (method === 'password') authentication = {method, password};
      else {
        const options = payload(await post(`${BASE}/reauth/begin`, {revision})).publicKeyCredentialRequestOptions;
        if (!alive) return;
        credentialRequest = new AbortController();
        const credential = await navigator.credentials.get({signal: credentialRequest.signal, publicKey: {
          ...options, challenge: decode(options.challenge),
          allowCredentials: (options.allowCredentials || []).map(item => ({...item, id: decode(item.id)})),
          userVerification: 'required'
        }});
        if (!credential || !alive) return;
        const response = credential.response;
        authentication = {method, assertion: {id: credential.id, rawId: encode(credential.rawId), type: credential.type,
          response: {clientDataJSON: encode(response.clientDataJSON), authenticatorData: encode(response.authenticatorData),
            signature: encode(response.signature), ...(response.userHandle ? {userHandle: encode(response.userHandle)} : {})}}};
      }
      const next = payload(await post(`${BASE}/apply`, {revision, confirm: true, authentication}));
      if (!alive) return;
      job = next; remember(next.job_id); dialog = null;
      await poll();
    } catch (e) {
      if (!alive) return;
      error = ['NotAllowedError', 'AbortError'].includes(e.name) ? 'Passkey 验证已取消或超时，可重试。' : message(e);
      if (e.payload?.error?.code === 'revision_conflict' && dialog) dialog.stale = true;
    } finally { password = ''; credentialRequest = null; busy = false; if (alive) render(); }
  }

  function connect(element) {
    host = element; bindings?.abort(); bindings = new AbortController();
    const options = {signal: bindings.signal};
    host.addEventListener('click', event => {
      const target = event.target.closest('[data-domain-action]');
      if (!target || target.disabled) return;
      event.stopPropagation();
      const action = target.dataset.domainAction;
      if (action === 'cancel') close();
      else if (action === 'open' && canApply()) { dialog = structuredClone(snapshot.apply_plan); error = ''; render(); }
      else if (action === 'passkey') void submit('passkey');
      else if (action === 'probe' && allowed()) void (async () => {
        busy = true; error = ''; render();
        try {
          const next = payload(await post(`${BASE}/probe`, {}));
          if (!alive) return;
          job = next; remember(next.job_id); await poll();
        } catch (e) { if (alive) error = message(e); }
        finally { busy = false; if (alive) render(); }
      })();
    }, options);
    host.addEventListener('submit', event => {
      if (event.target.matches('[data-domain-form]')) { event.preventDefault(); event.stopPropagation(); void submit('password'); }
    }, options);
    host.addEventListener('keydown', event => { if (event.key === 'Escape' && dialog) close(); }, options);
  }

  return {markup, modalMarkup, connect, poll,
    get holdRender() { return !!dialog || busy; },
    get running() { return busy || active(job); },
    update(value) { snapshot = value; },
    dispose() { alive = false; credentialRequest?.abort(); bindings?.abort(); dialog = null; }
  };
}
