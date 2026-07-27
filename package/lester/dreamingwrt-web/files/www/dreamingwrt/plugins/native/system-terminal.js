export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const VERSION = '20260719-02';
  const BASIC_ENDPOINT = '/api/v1/system/basic';
  const CONFIG_ENDPOINT = '/api/v1/system/ttyd';
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const stage = root?.closest('.console-stage');

  const state = {
    mounted: true,
    tab: 'terminal',
    loading: true,
    saving: false,
    error: '',
    notice: '',
    service: { enabled: false, running: false },
    capabilities: {},
    instances: [defaultInstance()],
    baseline: [],
    selectedId: 'ttyd',
    revision: '',
    terminalUrl: '',
    frameKey: 0,
    seq: 0
  };

  function defaultInstance(index = 0) {
    return {
      id: index ? `ttyd-${index + 1}` : 'ttyd',
      name: index ? `ttyd ${index + 1}` : 'ttyd',
      enable: true,
      unix_sock: false,
      port: 7681,
      interface: '@lan',
      unix_sock_path: '/var/run/ttyd.sock',
      credential: '',
      credential_configured: false,
      uid: '',
      gid: '',
      signal: 1,
      url_arg: false,
      readonly: false,
      client_option: [],
      terminal_type: 'xterm-256color',
      check_origin: false,
      max_clients: 0,
      once: false,
      index: '',
      ipv6: false,
      ssl: false,
      ssl_cert: '',
      ssl_key: '',
      ssl_ca: '',
      debug: '7',
      command: '/bin/login',
      url_override: '',
      terminal_url: ''
    };
  }

  function clone(value) {
    try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value || {})); }
  }

  function bool(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') return !['0', 'false', 'off', 'no', 'disabled'].includes(value.toLowerCase());
    return Boolean(value);
  }

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null || typeof value === 'object') continue;
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }

  function asArray(value, keys = []) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of [...keys, 'items', 'instances', 'rows', 'data']) if (Array.isArray(value[key])) return value[key];
    return [];
  }

  function authHeaders(extra = {}) {
    let token = '';
    try { token = localStorage.getItem('dreamingwrt.web.accessToken') || ''; } catch (_) {}
    return { Accept: 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}), ...extra };
  }

  async function requestJson(url, options = {}) {
    const response = await fetch(`${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`, {
      credentials: 'same-origin', cache: 'no-store', ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    const payload = json?.data ?? json;
    if (!response.ok || json?.ok === false || payload?.ok === false) {
      const error = new Error(firstText(payload?.message, payload?.error?.message, payload?.error, json?.message, `HTTP ${response.status}`));
      error.status = response.status;
      throw error;
    }
    return payload || {};
  }

  function normalizeInstance(source = {}, index = 0) {
    const fallback = defaultInstance(index);
    const options = Array.isArray(source.client_option)
      ? source.client_option
      : firstText(source.client_option).split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
    return {
      ...fallback,
      id: firstText(source.id, source.section, fallback.id),
      name: firstText(source.name, source.label, source.section, fallback.name),
      enable: bool(source.enable, true),
      unix_sock: bool(source.unix_sock),
      port: Number(source.port) >= 0 ? Number(source.port) : 7681,
      interface: firstText(source.interface, fallback.interface),
      unix_sock_path: firstText(source.unix_sock_path, source._unix_sock_path, source.unix_sock ? source.interface : '', fallback.unix_sock_path),
      credential: '',
      credential_configured: bool(source.credential_configured, Boolean(source.credential)),
      uid: firstText(source.uid),
      gid: firstText(source.gid),
      signal: Number.isFinite(Number(source.signal)) ? Number(source.signal) : 1,
      url_arg: bool(source.url_arg),
      readonly: bool(source.readonly),
      client_option: options,
      terminal_type: firstText(source.terminal_type, fallback.terminal_type),
      check_origin: bool(source.check_origin),
      max_clients: Number(source.max_clients) >= 0 ? Number(source.max_clients) : 0,
      once: bool(source.once),
      index: firstText(source.index),
      ipv6: bool(source.ipv6),
      ssl: bool(source.ssl),
      ssl_cert: firstText(source.ssl_cert),
      ssl_key: firstText(source.ssl_key),
      ssl_ca: firstText(source.ssl_ca),
      debug: firstText(source.debug, fallback.debug),
      command: firstText(source.command, fallback.command),
      url_override: firstText(source.url_override),
      terminal_url: firstText(source.terminal_url, source.proxy_url)
    };
  }

  function selected() {
    return state.instances.find((instance) => instance.id === state.selectedId) || state.instances[0] || defaultInstance();
  }

  function canReadConfig() {
    return bool(state.capabilities.system_ttyd_read ?? state.capabilities.ttyd_read);
  }

  function canWriteConfig() {
    return bool(state.capabilities.system_ttyd_write ?? state.capabilities.ttyd_write);
  }

  function stableInstances(instances = state.instances) {
    return instances.map((instance) => {
      const copy = { ...instance };
      delete copy.credential;
      delete copy.terminal_url;
      return copy;
    });
  }

  function dirty() {
    return JSON.stringify(stableInstances()) !== JSON.stringify(stableInstances(state.baseline));
  }

  function safeHttpUrl(value) {
    const text = firstText(value);
    if (!text) return '';
    try {
      const parsed = new URL(text, window.location.href);
      return ['http:', 'https:'].includes(parsed.protocol) ? parsed.href : '';
    } catch (_) { return ''; }
  }

  function terminalUrl(instance = selected()) {
    const explicit = safeHttpUrl(state.terminalUrl || instance.terminal_url || instance.url_override);
    if (explicit) return explicit;
    if (instance.unix_sock || Number(instance.port) === 0) return '';
    const scheme = instance.ssl ? 'https:' : 'http:';
    if (window.location.protocol === 'https:' && scheme === 'http:') return '';
    return `${scheme}//${window.location.hostname}:${Number(instance.port) || 7681}/`;
  }

  function icon(name) {
    const paths = {
      terminal: '<path d="M12 19h8"></path><path d="m4 17 6-6-6-6"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      external: '<path d="M14 3h7v7"></path><path d="M10 14 21 3"></path><path d="M21 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      trash: '<path d="M4 7h16M9 7V4h6v3m-9 0 1 13h10l1-13M10 11v5m4-5v5"></path>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.terminal}</svg>`;
  }

  function statusBadge() {
    const running = state.service.running && selected().enable;
    return ui.statusBadgeMarkup?.(running ? '运行中' : selected().enable ? '未运行' : '已停用', running ? 'success' : selected().enable ? 'error' : 'muted') || '';
  }

  function tabs() {
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs system-terminal-tabs" role="tablist" aria-label="终端">
      <span class="dwrt-kit-tab-pill" aria-hidden="true"></span>
      ${[['terminal', '终端'], ['settings', '设置']].map(([id, label]) => `<button class="dwrt-kit-tab ${state.tab === id ? 'is-active' : ''}" type="button" role="tab" aria-selected="${state.tab === id}" data-terminal-tab="${id}">${label}</button>`).join('')}
    </nav>`;
  }

  function terminalView() {
    const instance = selected();
    const url = terminalUrl(instance);
    const disabledReason = instance.unix_sock
      ? 'UNIX Socket 模式需要 webd 同源反向代理。'
      : Number(instance.port) === 0
        ? '随机端口无法嵌入 Web 壳，请配置固定端口。'
        : window.location.protocol === 'https:' && !instance.ssl
          ? 'HTTPS 控制台不能嵌入 HTTP ttyd，请启用 SSL 或配置 webd 同源代理。'
          : 'ttyd 地址不可用。';
    return `<section class="system-terminal-console dwrt-kit-glass-surface">
      <header class="system-terminal-console-bar">
        <div class="system-terminal-console-title">${icon('terminal')}<span><strong>${escapeHtml(instance.name)}</strong><small>${escapeHtml(instance.unix_sock ? instance.unix_sock_path : `${window.location.hostname}:${instance.port || 7681}`)}</small></span></div>
        <div class="system-terminal-console-actions">${statusBadge()}<button type="button" data-terminal-refresh aria-label="重新连接" data-dwrt-tooltip="重新连接">${icon('refresh')}</button><button type="button" data-terminal-open ${url ? '' : 'disabled'} aria-label="在新窗口打开" data-dwrt-tooltip="在新窗口打开">${icon('external')}</button></div>
      </header>
      <div class="system-terminal-frame-wrap">${url && instance.enable && state.service.running
        ? `<iframe data-frame-key="${state.frameKey}" class="system-terminal-frame" src="${escapeHtml(url)}" title="${escapeHtml(instance.name)}" allow="clipboard-read; clipboard-write" referrerpolicy="same-origin"></iframe>`
        : `<div class="system-terminal-unavailable">${icon('terminal')}<strong>终端不可用</strong><span>${escapeHtml(!state.service.running ? 'ttyd 服务未运行。' : disabledReason)}</span></div>`}
      </div>
    </section>`;
  }

  function switchField(label, key, checked, help = '') {
    return `<label class="system-terminal-switch-field"><span><strong>${escapeHtml(label)}</strong>${help ? `<small>${escapeHtml(help)}</small>` : ''}</span><input type="checkbox" data-terminal-field="${key}" ${checked ? 'checked' : ''} ${canWriteConfig() ? '' : 'disabled'}><i></i></label>`;
  }

  function inputField(label, key, value, options = {}) {
    const type = options.type || 'text';
    const disabled = !canWriteConfig() || options.disabled;
    const attributes = [
      `type="${type}"`, `data-terminal-field="${key}"`, `value="${escapeHtml(value)}"`,
      options.placeholder ? `placeholder="${escapeHtml(options.placeholder)}"` : '',
      options.min !== undefined ? `min="${options.min}"` : '', options.max !== undefined ? `max="${options.max}"` : '',
      options.autocomplete ? `autocomplete="${options.autocomplete}"` : '', disabled ? 'disabled' : ''
    ].filter(Boolean).join(' ');
    return `<label class="system-terminal-field ${options.wide ? 'is-wide' : ''}"><span>${escapeHtml(label)}</span><input ${attributes}>${options.help ? `<small>${escapeHtml(options.help)}</small>` : ''}</label>`;
  }

  function selectField(label, key, value, options) {
    return `<label class="system-terminal-field"><span>${escapeHtml(label)}</span><select data-terminal-field="${key}" ${canWriteConfig() ? '' : 'disabled'}>${options.map(([id, text]) => `<option value="${escapeHtml(id)}" ${String(value) === String(id) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select></label>`;
  }

  function settingsView() {
    const instance = selected();
    const write = canWriteConfig();
    return `<section class="system-terminal-settings">
      <aside class="system-terminal-instance-list dwrt-kit-glass-surface">
        <header><strong>实例</strong><button type="button" data-terminal-add ${write ? '' : 'disabled'} aria-label="添加实例">${icon('plus')}</button></header>
        <div>${state.instances.map((item) => `<button type="button" class="${item.id === instance.id ? 'is-active' : ''}" data-terminal-instance="${escapeHtml(item.id)}"><span><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.unix_sock ? item.unix_sock_path : `${item.interface || '全部接口'}:${item.port || 7681}`)}</small></span><i class="${item.enable ? 'is-on' : ''}"></i></button>`).join('')}</div>
      </aside>
      <main class="system-terminal-form dwrt-kit-glass-surface">
        <header><div><strong>${escapeHtml(instance.name)}</strong><span>${canReadConfig() ? 'ttyd 实例配置' : '等待 webd 配置接口'}</span></div><button type="button" class="system-terminal-delete" data-terminal-delete ${write && state.instances.length > 1 ? '' : 'disabled'} aria-label="删除实例">${icon('trash')}</button></header>
        ${!canReadConfig() ? '<div class="system-terminal-capability">当前 webd 尚未开放 ttyd 配置读取与保存接口。终端可直接使用，设置表单保持只读。</div>' : ''}
        <section class="system-terminal-form-section"><h3>监听</h3><div class="system-terminal-grid">
          ${switchField('启用实例', 'enable', instance.enable)}
          ${switchField('UNIX Socket', 'unix_sock', instance.unix_sock, '使用 UNIX 域套接字代替 TCP 端口')}
          ${instance.unix_sock
            ? inputField('UNIX Socket 路径', 'unix_sock_path', instance.unix_sock_path, { wide: true, placeholder: '/var/run/ttyd.sock' })
            : `${inputField('端口', 'port', instance.port, { type: 'number', min: 0, max: 65535, placeholder: '7681' })}${inputField('接口', 'interface', instance.interface, { placeholder: '@lan' })}`}
          ${switchField('IPv6', 'ipv6', instance.ipv6)}
          ${switchField('检查 Origin', 'check_origin', instance.check_origin, '拒绝来自其他 Origin 的 WebSocket')}
        </div></section>
        <section class="system-terminal-form-section"><h3>会话</h3><div class="system-terminal-grid">
          ${inputField('命令', 'command', instance.command, { wide: true, placeholder: '/bin/login' })}
          ${inputField('终端类型', 'terminal_type', instance.terminal_type, { placeholder: 'xterm-256color' })}
          ${inputField('最大客户端', 'max_clients', instance.max_clients, { type: 'number', min: 0, placeholder: '0' })}
          ${inputField('退出信号', 'signal', instance.signal, { type: 'number', min: 0, placeholder: '1' })}
          ${switchField('只读', 'readonly', instance.readonly)}
          ${switchField('仅接受一次连接', 'once', instance.once)}
          ${switchField('允许 URL 参数', 'url_arg', instance.url_arg)}
        </div></section>
        <section class="system-terminal-form-section"><h3>身份与权限</h3><div class="system-terminal-grid">
          ${inputField('Basic Auth 凭据', 'credential', instance.credential, { type: 'password', wide: true, autocomplete: 'new-password', placeholder: instance.credential_configured ? '已配置，留空则保留' : 'username:password' })}
          ${inputField('用户 ID', 'uid', instance.uid, { type: 'number', min: 0 })}
          ${inputField('用户组 ID', 'gid', instance.gid, { type: 'number', min: 0 })}
        </div></section>
        <section class="system-terminal-form-section"><h3>TLS</h3><div class="system-terminal-grid">
          ${switchField('启用 SSL', 'ssl', instance.ssl)}
          ${instance.ssl ? `${inputField('证书路径', 'ssl_cert', instance.ssl_cert, { wide: true })}${inputField('私钥路径', 'ssl_key', instance.ssl_key, { wide: true })}${inputField('CA 路径', 'ssl_ca', instance.ssl_ca, { wide: true })}` : ''}
        </div></section>
        <section class="system-terminal-form-section"><h3>高级</h3><div class="system-terminal-grid">
          ${selectField('日志级别', 'debug', instance.debug, [['1', '错误'], ['3', '警告'], ['7', '通知'], ['15', '信息']])}
          ${inputField('自定义 index.html', 'index', instance.index, { wide: true })}
          ${inputField('反向代理 URL', 'url_override', instance.url_override, { wide: true, placeholder: 'https://router.example/terminal/' })}
          <label class="system-terminal-field is-wide"><span>客户端选项</span><textarea data-terminal-field="client_option" ${write ? '' : 'disabled'} placeholder="每行一个 key=value">${escapeHtml(instance.client_option.join('\n'))}</textarea></label>
        </div></section>
        ${ui.floatingSavebarMarkup?.({ visible: dirty(), omitWhenHidden: true, busy: state.saving, disabled: !write, message: state.notice || (state.error && state.tab === 'settings' ? state.error : '终端配置已修改，请保存生效'), saveLabel: write ? '保存并重载' : '等待后端能力', busyLabel: '正在应用' }) || ''}
      </main>
    </section>`;
  }

  function render() {
    if (!root || !state.mounted) return;
    root.hidden = false;
    root.classList.add('route-workspace', 'system-terminal-route-host');
    root.innerHTML = `<section class="system-terminal-shell" data-system-terminal-version="${VERSION}"><header class="system-terminal-navigation">${tabs()}<div class="system-terminal-page-status">${statusBadge()}</div></header>${state.loading ? '<div class="system-terminal-loading dwrt-kit-glass-surface">正在连接 ttyd...</div>' : state.tab === 'terminal' ? terminalView() : settingsView()}</section>`;
    bindEvents();
    ui.mountAll?.(root);
    ui.scheduleAdaptiveForegroundSample?.(40, root);
  }

  function updateField(input) {
    const instance = selected();
    const key = input.dataset.terminalField;
    if (!key) return;
    if (input.type === 'checkbox') instance[key] = input.checked;
    else if (['port', 'signal', 'max_clients'].includes(key)) instance[key] = Number(input.value) || 0;
    else if (key === 'client_option') instance[key] = input.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
    else instance[key] = input.value;
  }

  function syncSaveButton() {
    const button = root.querySelector('[data-dwrt-savebar-save]');
    if (!button) return;
    button.disabled = !canWriteConfig() || !dirty() || state.saving;
  }

  function bindEvents() {
    root.querySelectorAll('[data-terminal-tab]').forEach((button) => button.addEventListener('click', () => { state.tab = button.dataset.terminalTab; state.notice = ''; render(); }));
    root.querySelectorAll('[data-terminal-instance]').forEach((button) => button.addEventListener('click', () => { state.selectedId = button.dataset.terminalInstance; render(); }));
    root.querySelectorAll('[data-terminal-field]').forEach((input) => {
      input.addEventListener('input', () => { updateField(input); syncSaveButton(); });
      input.addEventListener('change', () => { updateField(input); if (input.type === 'checkbox' || input.tagName === 'SELECT') render(); });
    });
    root.querySelector('[data-terminal-refresh]')?.addEventListener('click', () => { state.frameKey += 1; render(); });
    root.querySelector('[data-terminal-open]')?.addEventListener('click', () => { const url = terminalUrl(); if (url) window.open(url, '_blank', 'noopener,noreferrer'); });
    root.querySelector('[data-terminal-add]')?.addEventListener('click', () => {
      const instance = defaultInstance(state.instances.length);
      state.instances.push(instance); state.selectedId = instance.id; render();
    });
    root.querySelector('[data-terminal-delete]')?.addEventListener('click', () => {
      if (!canWriteConfig() || state.instances.length <= 1) return;
      state.instances = state.instances.filter((item) => item.id !== state.selectedId);
      state.selectedId = state.instances[0].id; render();
    });
    root.querySelector('[data-dwrt-savebar-save]')?.addEventListener('click', save);
    root.querySelector('[data-dwrt-savebar-discard]')?.addEventListener('click', () => {
      state.instances = clone(state.baseline);
      state.notice = '';
      render();
    });
  }

  async function load() {
    const seq = ++state.seq;
    state.loading = true; render();
    try {
      const basic = await requestJson(BASIC_ENDPOINT);
      if (!state.mounted || seq !== state.seq) return;
      const services = asArray(basic?.startup?.services);
      const service = services.find((item) => item.name === 'ttyd');
      state.service = service ? { enabled: bool(service.enabled), running: bool(service.running) } : state.service;
      state.capabilities = basic?.capabilities || {};
      if (canReadConfig()) {
        const config = await requestJson(CONFIG_ENDPOINT);
        const instances = asArray(config, ['instances']);
        if (instances.length) state.instances = instances.map(normalizeInstance);
        state.revision = firstText(config.revision);
        state.terminalUrl = firstText(config.terminal_url, config.proxy_url);
        state.selectedId = state.instances[0]?.id || 'ttyd';
      }
      state.baseline = clone(state.instances);
      state.error = '';
    } catch (error) {
      state.error = error.message || 'ttyd 状态读取失败';
      state.baseline = clone(state.instances);
    }
    state.loading = false;
    render();
  }

  async function save() {
    if (!canWriteConfig() || !dirty() || state.saving) return;
    state.saving = true; state.notice = ''; render();
    const instances = state.instances.map((instance) => ({
      ...instance,
      credential: instance.credential || undefined,
      preserve_credential: !instance.credential && instance.credential_configured,
      _unix_sock_path: instance.unix_sock_path
    }));
    try {
      const result = await requestJson(CONFIG_ENDPOINT, { method: 'PUT', body: JSON.stringify({ revision: state.revision, instances, confirm: true, reload: true }) });
      const rows = asArray(result, ['instances']);
      if (rows.length) state.instances = rows.map(normalizeInstance);
      state.revision = firstText(result.revision, state.revision);
      state.terminalUrl = firstText(result.terminal_url, result.proxy_url, state.terminalUrl);
      state.baseline = clone(state.instances);
      state.notice = 'ttyd 配置已保存并完成运行态回读。';
      state.frameKey += 1;
    } catch (error) {
      state.notice = error.message || 'ttyd 配置保存失败';
    }
    state.saving = false;
    render();
  }

  stage?.classList.add('is-system-terminal');
  render();
  load();

  return {
    unmount() {
      state.mounted = false;
      state.seq += 1;
      stage?.classList.remove('is-system-terminal');
      root?.classList.remove('route-workspace', 'system-terminal-route-host');
      root?.replaceChildren();
    }
  };
}

export default { mount };
