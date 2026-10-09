import { createLocalDomain } from './cloud-local-domain.js?v=20261005-dns-01';
const BASE = '/api/v1/cloud/web-access';
const STATES = {
  disabled: '已关闭', connected: '隧道已连接', connecting: '连接中', backoff: '等待重连',
  revoking: '设备已关闭，云端撤销中', queued: '已排队', running: '执行中',
  succeeded: '已完成', failed: '失败', partial: '部分完成'
};
const CHECKS = { binding: '云账号绑定', services: '管理服务', domain: '域名与 Passkey',
  device_dns: '设备侧解析', local_https: '本地 HTTPS', gateway_tls: '云隧道 TLS' };
const ERRORS = {
  cloud_component_unavailable: '设备 Cloud 服务不可用', device_owner_required: '需要设备所有者权限',
  cloud_host_missing: '尚未配置受信云服务', binding_unavailable: '未读到有效云绑定',
  invalid_binding_code: '绑定码无效', preflight_required: '请先完成预检',
  preflight_stale: '预检已失效，请重新检查', preflight_expired: '预检已过期，请重新检查',
  preflight_failed: '预检未通过', job_in_progress: '已有作业正在执行',
  cloud_revocation_pending: '设备已关闭，云端撤销待同步', daemon_restarted: '服务已重启，请重新检查状态',
  identity_migration_required: '实际域名与 Passkey 身份不一致，需先完成域名迁移',
  local_https_unavailable: '本地 HTTPS 校验未通过', gateway_unavailable: '云隧道 TLS 不可达',
  device_dns_not_local: '设备域名未全部解析到本机', publication_failed: '云端清单同步失败',
  not_found: '记录不存在或当前账号不可见', authentication_required: '登录已过期',
  revision_conflict: '配置已被修改。草稿已保留，请重新载入后核对。',
  invalid_target: '目标地址或证书格式无效', service_unreachable: '内网服务不可达',
  tls_validation_failed: '服务证书校验未通过', service_quota_exceeded: '已超过账号服务额度',
  connection_pending: '配置已保存，云端连接尚未确认', permission_denied: '需要设备所有者权限'
};
const text = value => ERRORS[value] || value || '';
const active = job => ['queued', 'running'].includes(job?.state);
const payload = result => result?.data ?? result;
const safeURL = value => {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password ? url.href : '';
  } catch { return ''; }
};

export function createBrowserAccess({ get, post, ui, escapeHtml: esc, icon }) {
  const state = { caps: null, status: null, domain: null, binding: null, job: null,
    preflight: null, busy: false, error: '', confirm: '', code: '', name: '', legacy: false, bindingExpanded: false,
    services: null, serviceError: '', serviceResults: {}, selectedService: '', editor: null, returnFocus: '' };
  let host, timer, alive = true, loading = false, bindings;
  const localDomain = createLocalDomain({get, post, escapeHtml: esc, icon, render});
  const canWrite = () => state.caps?.can_write === true && !state.busy && !active(state.job) && !localDomain.running;
  const preflightValid = () => state.preflight?.state === 'succeeded' &&
    state.preflight.result?.enable_allowed === true &&
    Number(state.preflight.result.expires_at) * 1000 > Date.now();
  const button = (action, label, symbol, disabled = false) =>
    `<button type="button" class="system-demo-btn secondary compact-btn" data-browser-action="${action}"
      ${disabled ? 'disabled' : ''}>${icon(symbol)}<span>${label}</span></button>`;
  const fact = (label, value) => `<div class="system-browser-fact" data-adaptive-region>
    <dt>${label}</dt><dd>${esc(value || '未返回')}</dd></div>`;
  const serviceWrite = () => canWrite() && state.caps?.service_crud === true && !!state.services?.revision;
  const findService = id => state.services?.services?.find(service => service.service_id === id);
  const serviceButton = (action, label, id, disabled = false) =>
    `<button type="button" class="system-demo-btn secondary compact-btn" data-browser-action="service-${action}"
      data-browser-service="${esc(id)}" ${disabled ? 'disabled' : ''}>${label}</button>`;

  function servicesMarkup() {
    if (!state.caps?.service_crud) return '';
    const quota = state.caps.account_quota || state.status?.account_quota;
    const limit = value => value == null ? '未知' : value === 0 ? '不限' : String(value);
    const usage = quota?.state === 'enforced' ?
      `账号已发布 ${quota.services ?? '未知'} 个服务 · 服务上限 ${limit(quota.service_limit)} · 并发上限 ${limit(quota.connection_limit)} · 带宽 ${quota.bandwidth_bps == null ? '未知' : quota.bandwidth_bps === 0 ? '不限' : `${quota.bandwidth_bps} bit/s`}` : '账号配额尚未取得';
    return `<section class="system-browser-services" aria-label="内网 Web 服务" data-adaptive-region>
      <header class="system-browser-header"><h3>内网 Web 服务</h3>${serviceButton('new', '添加服务', '', !serviceWrite())}</header>
      <p class="system-admin-access-note">${esc(usage)}</p>
      ${state.serviceError ? `<p class="system-inline-error" role="alert">${esc(state.serviceError)}</p>` : ''}
      <div class="dwrt-kit-table-wrap"><div class="dwrt-kit-table-scroll" data-system-scroll>
      <table class="dwrt-kit-table system-browser-service-table"><thead><tr><th>名称 / 目标</th><th>独立访问域名</th><th>配置</th><th>最近操作</th><th>操作</th></tr></thead>
      <tbody>${(state.services?.services || []).map(service => {
        const builtIn = service.kind === 'management', result = state.serviceResults[service.service_id];
        const target = service.target;
        return `<tr data-service-row="${esc(service.service_id)}"><td><strong>${esc(service.name)}</strong>
          <span>${builtIn ? '内置管理台' : esc(`${target?.scheme?.toUpperCase() || ''} · ${target?.host || ''}:${target?.port || ''}`)}</span>
          ${target?.tls_policy === 'pin' ? '<span>已固定服务证书公钥</span>' : ''}</td>
          <td><code>${esc(service.public_host || '尚未分配')}</code></td>
          <td>${service.valid === false ? '配置无效' : service.enabled ? '已启用' : '已停用'}</td>
          <td>${esc(result || '尚未在本页操作')}</td><td><div class="system-browser-service-actions">
          ${builtIn ? '<span>随浏览器云访问管理</span>' :
            serviceButton('edit', '编辑', service.service_id, !serviceWrite()) +
            serviceButton('probe', '探测', service.service_id, !serviceWrite()) +
            serviceButton(service.enabled ? 'disable' : 'enable', service.enabled ? '停用' : '启用', service.service_id, !serviceWrite() || service.valid === false) +
            serviceButton('delete', '删除', service.service_id, !serviceWrite())}</div></td></tr>`;
      }).join('') || '<tr><td colspan="5">尚未读到服务记录</td></tr>'}</tbody></table></div></div>
      <p class="system-admin-access-note">从云账号门户打开已发布应用。独立域名不代表公网入口已就绪；应用仍需自己的登录。</p>
    </section>`;
  }

  function editorMarkup() {
    const draft = state.editor;
    if (!draft) return '';
    const field = (key, label, attributes = '') => `<label class="dwrt-kit-field"><span>${label}</span>
      <input class="system-glass-input" data-browser-service-field="${key}" value="${esc(draft[key])}" ${attributes} ${state.busy ? 'disabled' : ''}></label>`;
    return `<div class="dwrt-kit-modal-layer system-cloud-service-layer is-open" data-dwrt-component="modal">
      <button type="button" class="dwrt-kit-modal-backdrop" data-browser-action="service-close" aria-label="关闭服务编辑器" ${state.busy ? 'disabled' : ''}></button>
      <section class="dwrt-kit-modal dwrt-kit-glass-surface" role="dialog" aria-modal="true" aria-labelledby="cloudServiceTitle">
        <header class="dwrt-kit-modal-header"><h2 id="cloudServiceTitle">${draft.id ? '编辑内网服务' : '添加内网服务'}</h2>
          <button type="button" class="dwrt-kit-modal-close" data-browser-action="service-close" aria-label="关闭" ${state.busy ? 'disabled' : ''}>${icon('close')}</button></header>
        <form data-browser-service-form>
          <div class="dwrt-kit-modal-body system-cloud-service-fields">
            ${state.serviceError ? `<p class="system-inline-error" role="alert">${esc(state.serviceError)}</p>` : ''}
            ${field('name', '服务名称', 'required maxlength="80"')}
            <label class="dwrt-kit-field"><span>协议</span><select class="system-glass-input" data-browser-service-field="scheme" ${state.busy ? 'disabled' : ''}>
              <option value="http" ${draft.scheme === 'http' ? 'selected' : ''}>HTTP</option><option value="https" ${draft.scheme === 'https' ? 'selected' : ''}>HTTPS</option></select></label>
            ${field('host', '内网地址或主机名', 'required maxlength="253" spellcheck="false"')}
            ${field('port', '端口', 'required type="number" min="1" max="65535"')}
            ${draft.scheme === 'https' ? `${field('server_name', '证书中的主机名（可选）', 'maxlength="253" spellcheck="false"')}
              <label class="dwrt-kit-field"><span>证书校验</span><select class="system-glass-input" data-browser-service-field="tls_policy" ${state.busy ? 'disabled' : ''}>
                <option value="verify" ${draft.tls_policy === 'verify' ? 'selected' : ''}>系统信任证书</option><option value="pin" ${draft.tls_policy === 'pin' ? 'selected' : ''}>指定服务证书并固定公钥</option></select></label>
              ${draft.tls_policy === 'pin' ? `<label class="dwrt-kit-field"><span>公开证书 PEM${draft.id ? '（更改目标时重新提供）' : ''}</span>
                <textarea class="system-glass-input" data-browser-service-field="certificate_pem" rows="6" maxlength="4096" spellcheck="false" ${state.busy ? 'disabled' : ''}>${esc(draft.certificate_pem)}</textarea></label>
                <p class="system-admin-access-note">仅粘贴此服务的公开证书，不含私钥。仍验证证书名称和有效期。</p>` : ''}` : ''}
            <p class="system-admin-access-note">${draft.id ? '更改目标或证书会停用服务，需重新探测并启用。修改已发布服务会重连本设备云隧道，中断现有云连接。' : '新服务默认停用；保存后探测，再确认启用。'}</p>
          </div><footer class="dwrt-kit-modal-footer system-browser-actions">
            ${draft.conflict ? serviceButton('reload', '重新载入', draft.id, state.busy) : ''}
            ${serviceButton('close', '取消', '', state.busy)}
            <button type="submit" class="system-demo-btn" ${!serviceWrite() || draft.conflict ? 'disabled' : ''}>${state.busy ? '正在保存…' : '保存服务'}</button>
          </footer></form></section></div>`;
  }

  function markup() {
    const status = state.status || {};
    const preflight = state.preflight?.result;
    const domain = preflight?.canonical_host || state.binding?.canonical_host || state.domain?.domain;
    const entry = safeURL(state.binding?.entry_url || (preflight?.cloud_id ?
      `https://dev.dreamingnet.com/${preflight.cloud_id}` : ''));
    const disabled = !canWrite();
    const checks = preflight?.checks || {};
    const confirmation = state.confirm && (ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup);
    const titles = { enable: '启用浏览器云访问？', disable: '关闭浏览器云访问？', bind: '绑定到此云账号？' };
    const descriptions = {
      enable: `将发布本机管理服务${domain ? `（${domain}）` : ''}。云网关能够接触浏览器访问内容；App 加密中继不受影响。${preflight?.legacy_hostname ? '保留现有域名与 Passkey 身份。' : ''}`,
      disable: '将中断浏览器远程连接，本页可能断线。局域网管理与 App 加密中继不受影响；可从局域网回读撤销进度。',
      bind: '将此设备归入绑定码所属云账号。不发送本机管理员密码，也不会自动启用远程访问。'
    };
    const selected = findService(state.selectedService);
    for (const [action, label] of Object.entries({enable: '启用', disable: '停用', delete: '删除'})) {
      titles[`service-${action}`] = `${label}“${selected?.name || '此服务'}”？`;
      descriptions[`service-${action}`] = action === 'enable' ?
        '设备会先探测目标，再发布服务。应用保留自身登录。更新发布清单会重连本设备云隧道，现有云连接将中断。' :
        '将撤销此服务入口并重连本设备云隧道，现有云连接将中断。局域网和 App 加密中继不受影响。';
    }
    return `<section class="system-browser-access" aria-label="浏览器云访问" data-adaptive-region>
      <header class="system-browser-header">
        <h3>${icon('globe')}<span>浏览器云访问</span></h3>
        <div class="system-browser-toggle"><span>${status.configured_enabled ? '已开启' : '未开启'}</span>
          <label class="system-ios-switch dwrt-kit-switch" data-dwrt-component="switch">
            <input type="checkbox" aria-label="浏览器云访问" data-browser-toggle
              ${status.configured_enabled ? 'checked' : ''} ${disabled || !state.status ? 'disabled' : ''}></label></div>
      </header>
      <p role="status">${esc(state.status ? STATES[status.state] || status.state : '正在读取状态')}
        ${status.effective_enabled && !status.ready ? ' · 浏览器入口尚未验证' : ''}</p>
      ${state.error ? `<p class="system-inline-error" role="alert">${esc(state.error)}</p>` : ''}
      ${state.caps?.reason ? `<p class="system-admin-access-note">${esc(text(state.caps.reason))}</p>` : ''}
      <dl class="system-browser-facts">
        ${fact('设备域名', domain)}
        ${fact('当前 Passkey RP', state.domain?.rp_id || state.domain?.passkey?.rp_id)}
        ${fact('客户端解析', '尚未在当前客户端确认')}
        ${status.last_error ? fact('最近错误', text(status.last_error)) : ''}
      </dl>
      ${entry ? `<div class="system-browser-entry"><a href="${esc(entry)}" target="_blank" rel="noopener noreferrer">${esc(entry)}</a>
        ${button('copy', '复制入口', 'copy')}</div>` : ''}
      <div class="system-browser-actions">
        ${button('refresh', '刷新', 'sync', state.busy)}
        ${button('preflight', '运行预检', 'shield', disabled)}
        ${button('enable', '启用', 'check', disabled || status.configured_enabled || !preflightValid())}
        ${button('reconnect', '重新连接', 'sync', disabled || !status.configured_enabled)}
      </div>
      ${Object.keys(checks).length ? `<ul class="system-browser-checks">${Object.entries(checks).map(([name, check]) =>
        `<li><span>${esc(CHECKS[name] || name)}</span><span>${check.passed ? '通过' : esc(text(check.reason) || '未通过')}</span></li>`).join('')}</ul>
        <p class="system-admin-access-note">请确保客户端使用的网关或 DNS 将此完整域名解析到设备内网 IP。</p>` : ''}
      ${preflight?.legacy_hostname && !status.configured_enabled ? `<label class="system-browser-legacy">
        <input type="checkbox" data-browser-legacy ${state.legacy ? 'checked' : ''}>保留现有域名与 Passkey 身份</label>` : ''}
      ${state.job ? `<p class="system-admin-access-note" role="status">${esc(
        `${({preflight: '预检', enable: '启用', disable: '关闭', reconnect: '重连'})[state.job.action] || '作业'}：${STATES[state.job.state] || state.job.state}`)}
        ${state.job.error ? ` · ${esc(text(state.job.error))}` : ''}</p>` : ''}
      <details class="system-browser-binding" ${state.bindingExpanded ? 'open' : ''}>
        <summary>云账号绑定</summary>
        <div class="system-browser-bind-fields">
          <label>设备显示名<input class="system-glass-input" data-browser-field="name"
            maxlength="64" value="${esc(state.name)}" ${disabled ? 'disabled' : ''}></label>
          <label>账号绑定码<input class="system-glass-input" data-browser-field="code" type="password"
            autocomplete="off" spellcheck="false" maxlength="24" value="${esc(state.code)}" ${disabled ? 'disabled' : ''}></label>
          ${button('bind', '绑定云账号', 'key', disabled)}
        </div>
        ${state.binding ? `<p role="status">${esc(STATES[state.binding.state] || state.binding.state)}
          ${state.binding.code && state.binding.state === 'failed' ? ` · ${esc(text(state.binding.code))}` : ''}</p>` : ''}
      </details>
    </section>${localDomain.markup()}${servicesMarkup()}${editorMarkup()}${localDomain.modalMarkup()}${confirmation ? confirmation({
      id: 'cloud-browser-confirmation', action: 'cloud-browser-confirm', tone: state.confirm === 'disable' ? 'warning' : 'neutral',
      title: titles[state.confirm], description: descriptions[state.confirm],
      cancelLabel: '取消', confirmLabel: '确认', disabled: state.busy
    }) : ''}`;
  }

  function render() {
    if (!alive || !host?.isConnected) return;
    const focused = host.contains(document.activeElement) ? document.activeElement : null;
    const field = focused?.dataset?.browserField;
    const selection = field ? [focused.selectionStart, focused.selectionEnd] : null;
    (ui.unmount || window.DWRT_UI_KIT?.unmount)?.(host);
    host.innerHTML = markup();
    ui.mountAll?.(host);
    localDomain.connect(host);
    if (field) {
      const target = host.querySelector(`[data-browser-field="${field}"]`);
      target?.focus();
      if (selection) target?.setSelectionRange(...selection);
    }
  }

  async function refresh() {
    if (!alive || loading) return;
    loading = true;
    try {
      const [caps, status, domain, binding, services] = await Promise.allSettled([
        get(`${BASE}/capabilities`), get(`${BASE}/status`),
        get('/api/v1/cloud/local-domain'), get('/api/v1/cloud/bind-status'), get(`${BASE}/services`)
      ]);
      if (!alive) return;
      state.caps = caps.status === 'fulfilled' ? payload(caps.value) : null;
      state.status = status.status === 'fulfilled' ? payload(status.value) : null;
      state.domain = domain.status === 'fulfilled' ? payload(domain.value) : null;
      localDomain.update(state.domain);
      await localDomain.poll();
      if (!alive) return;
      if (binding.status === 'fulfilled') state.binding = payload(binding.value)?.job || payload(binding.value);
      if (services.status === 'fulfilled') state.services = payload(services.value);
      else { state.services = null; if (state.caps?.service_crud) state.serviceError = text(services.reason?.payload?.error?.code || services.reason?.message); }
      if (status.status === 'rejected') state.error = text(status.reason?.payload?.error?.code || status.reason?.message);
      const id = state.job?.job_id || state.status?.last_job_id;
      if (id) {
        try {
          const job = payload(await get(`${BASE}/jobs/${encodeURIComponent(id)}`));
          if (!alive) return;
          state.job = job;
          if (job.action === 'preflight') state.preflight = job;
          if (job.action?.startsWith('service_') && state.selectedService) {
            const result = job.result?.probe || job.result;
            state.serviceResults[state.selectedService] = job.action === 'service_probe' && job.state === 'succeeded' ?
              `可达${result?.http_status ? ` · HTTP ${result.http_status}` : ''}（不代表应用已登录）` :
              `${STATES[job.state] || job.state}${job.error ? ` · ${text(job.error)}` : ''}`;
          }
        } catch (error) {
          if (error.status === 404) state.job = null;
          else state.error = error.message;
        }
      }
    } finally {
      loading = false;
      if (!state.confirm && !state.editor && !localDomain.holdRender) render();
    }
  }

  async function run(action) {
    if (!canWrite()) return;
    if (action.startsWith('service-')) { await runService(action.slice(8), state.selectedService); return; }
    if (action === 'enable' && !preflightValid()) { state.error = text('preflight_required'); render(); return; }
    if (action === 'enable' && state.preflight.result.legacy_hostname && !state.legacy) {
      state.error = '请先确认保留现有域名与 Passkey 身份。'; render(); return;
    }
    state.busy = true;
    state.error = '';
    render();
    try {
      if (action === 'bind') {
        state.binding = payload(await post('/api/v1/cloud/bind-code', {
          binding_code: state.code.trim(), display_name: state.name.trim(), confirm: true
        }));
        state.code = '';
      } else {
        const body = action === 'enable' ? {preflight_id: state.preflight.job_id, confirm: true,
          legacy_hostname_ack: state.legacy} : action === 'disable' ? {confirm: true} : {};
        state.job = payload(await post(`${BASE}/${action}`, body));
        if (action !== 'preflight') state.preflight = null;
      }
    } catch (error) {
      state.error = text(error.payload?.error?.code || error.message);
    } finally {
      state.busy = false;
      await refresh();
      render();
    }
  }

  function openEditor(id = '') {
    if (!serviceWrite()) return;
    const service = id ? findService(id) : null;
    if (id && (!service || service.kind === 'management')) return;
    const target = service?.target || {};
    state.returnFocus = id;
    state.serviceError = '';
    state.editor = {id, revision: state.services.revision, name: service?.name || '',
      scheme: target.scheme || 'http', host: target.host || '', port: target.port || 80,
      server_name: target.server_name || '', tls_policy: target.tls_policy || 'verify', certificate_pem: ''};
    state.editor.original = JSON.stringify(serviceTarget(state.editor));
    render();
    host.querySelector('[data-browser-service-field="name"]')?.focus();
  }

  function serviceTarget(draft) {
    return {host: draft.host.trim(), port: Number(draft.port), scheme: draft.scheme,
      server_name: draft.scheme === 'https' ? draft.server_name.trim() : '',
      tls_policy: draft.scheme === 'https' ? draft.tls_policy : 'verify'};
  }

  function closeEditor() {
    if (state.busy) return;
    state.editor = null;
    state.serviceError = '';
    render();
    const buttons = [...host.querySelectorAll('[data-browser-action="service-edit"]')];
    (buttons.find(button => button.dataset.browserService === state.returnFocus) ||
      host.querySelector('[data-browser-action="service-new"]'))?.focus();
  }

  async function runService(action, id = '') {
    if (!serviceWrite()) return;
    const service = id ? findService(id) : null;
    if (id && (!service || service.kind === 'management')) return;
    const draft = state.editor;
    let path = `${BASE}/services${id ? `/${encodeURIComponent(id)}` : ''}`;
    let method = id ? 'PATCH' : 'POST', body = {revision: draft?.revision || state.services.revision};
    if (action === 'save') {
      body.name = draft.name.trim();
      const target = serviceTarget(draft);
      if (!body.name || !target.host || !Number.isInteger(target.port) || target.port < 1 || target.port > 65535) return;
      if (!id || JSON.stringify(target) !== draft.original || draft.certificate_pem.trim()) {
        if (target.tls_policy === 'pin') {
          if (!draft.certificate_pem.trim()) { state.serviceError = '更改目标时请重新提供公开证书。'; render(); return; }
          target.certificate_pem = draft.certificate_pem.trim();
        }
        body.target = target;
      }
      if (!id) Object.assign(body, {kind: 'http', enabled: false, access_policy: 'owner'});
    } else if (action === 'probe') { path += '/probe'; method = 'POST'; }
    else if (action === 'delete') { method = 'DELETE'; body.confirm = true; }
    else body.enabled = action === 'enable';
    state.busy = true; state.serviceError = ''; state.selectedService = id; render();
    try {
      const result = payload(await (method === 'POST' ? post(path, body) : get(path, {
        method, headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)
      })));
      if (result.job_id) state.job = result;
      else if (result.service_id) state.serviceResults[result.service_id] = '已创建 · 尚未探测';
      state.preflight = null;
      if (action === 'save') state.editor = null;
    } catch (error) {
      state.serviceError = text(error.payload?.error?.code || error.message);
      if (error.status === 409 && state.editor && error.payload?.error?.code === 'revision_conflict') state.editor.conflict = true;
    } finally {
      state.busy = false;
      await refresh();
      render();
    }
  }

  function confirm(action) {
    if (!canWrite()) return;
    if (action === 'enable' && !preflightValid()) { state.error = text('preflight_required'); render(); return; }
    if (action === 'bind' && (!/^[a-fA-F0-9]{24}$/.test(state.code.trim()) || !state.name.trim())) {
      state.error = '请填写设备显示名及24位账号绑定码。'; render(); return;
    }
    state.confirm = action;
    render();
    host.querySelector('.dwrt-kit-confirmation-cancel')?.focus();
  }

  async function copyEntry(button) {
    const value = host.querySelector('.system-browser-entry a')?.href;
    if (!value) return;
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(value);
      else {
        const input = document.createElement('textarea');
        input.value = value; host.append(input); input.select();
        const copied = document.execCommand('copy'); input.remove();
        if (!copied) throw new Error('复制失败');
      }
      button.querySelector('span').textContent = '已复制';
    } catch { state.error = '复制失败，请选择入口地址复制。'; render(); }
  }

  function connect(next) {
    bindings?.abort();
    host = next;
    if (!host) return;
    bindings = new AbortController();
    const options = { signal: bindings.signal };
    host.addEventListener('click', event => {
      const cancel = event.target.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]');
      const accept = event.target.closest('[data-dwrt-confirm-accept]');
      if (state.confirm && (cancel || accept)) {
        event.stopPropagation();
        const action = state.confirm;
        state.confirm = '';
        if (accept) void run(action); else render();
        return;
      }
      const button = event.target.closest('[data-browser-action]');
      if (!button || button.disabled) return;
      event.stopPropagation();
      const action = button.dataset.browserAction;
      if (action.startsWith('service-')) {
        const id = button.dataset.browserService || '';
        if (action === 'service-close') closeEditor();
        else if (action === 'service-new' || action === 'service-edit' || action === 'service-reload') openEditor(id);
        else if (action === 'service-probe') void runService('probe', id);
        else if (serviceWrite() && findService(id)?.kind !== 'management') { state.selectedService = id; confirm(action); }
      } else if (action === 'refresh') { state.error = ''; state.serviceError = ''; void refresh(); }
      else if (action === 'copy') void copyEntry(button);
      else if (['bind', 'enable', 'disable'].includes(action)) confirm(action);
      else void run(action);
    }, options);
    host.addEventListener('input', event => {
      if (event.target.dataset.browserField) state[event.target.dataset.browserField] = event.target.value;
      if (event.target.dataset.browserServiceField && state.editor) state.editor[event.target.dataset.browserServiceField] = event.target.value;
    }, options);
    host.addEventListener('submit', event => {
      if (event.target.matches('[data-browser-service-form]')) { event.preventDefault(); void runService('save', state.editor?.id); }
    }, options);
    host.addEventListener('toggle', event => {
      if (event.target.matches('.system-browser-binding')) state.bindingExpanded = event.target.open;
    }, {...options, capture: true});
    host.addEventListener('change', event => {
      if (event.target.matches('select[data-browser-service-field]') && state.editor) render();
      if (event.target.matches('[data-browser-legacy]')) state.legacy = event.target.checked;
      if (event.target.matches('[data-browser-toggle]')) {
        const enable = event.target.checked;
        event.target.checked = state.status?.configured_enabled === true;
        confirm(enable ? 'enable' : 'disable');
      }
    }, options);
    host.addEventListener('keydown', event => {
      if (event.key === 'Escape' && state.confirm) { state.confirm = ''; render(); }
      else if (event.key === 'Escape' && state.editor) closeEditor();
    }, options);
    render();
    if (!timer) {
      void refresh();
      timer = setInterval(() => { if (host?.isConnected && !state.confirm && !state.busy && !localDomain.holdRender) void refresh(); }, 3000);
    }
  }
  return { connect, dispose() {
    alive = false; clearInterval(timer); bindings?.abort(); state.code = '';
    localDomain.dispose();
    if (host) (ui.unmount || window.DWRT_UI_KIT?.unmount)?.(host);
  } };
}
