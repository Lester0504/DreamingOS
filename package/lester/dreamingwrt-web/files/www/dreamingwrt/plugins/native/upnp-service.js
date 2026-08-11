const VERSION = '20260810-front-release-01';

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || window.DWRT_UI_KIT || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const stage = root?.closest('.console-stage');
  const ENDPOINTS = {
    service: '/api/v1/services/upnp',
    acl: '/api/v1/services/upnp/acl',
    mappings: '/api/v1/services/upnp/mappings'
  };
  const TABS = [
    ['settings', '服务配置'],
    ['acl', '访问控制'],
    ['dynamic', '动态映射'],
    ['static', '静态映射']
  ];

  const state = {
    mounted: true,
    seq: 0,
    loading: true,
    refreshing: false,
    saving: false,
    tab: 'settings',
    expanded: 'protocol',
    query: '',
    error: '',
    notice: '',
    noticeTone: '',
    mappingsError: '',
    data: defaultData(),
    draft: defaultData(),
    initial: defaultData(),
    acl: [],
    dynamicMappings: [],
    staticMappings: [],
    dirty: false,
    drawer: '',
    editor: {},
    confirmDelete: false,
    pollTimer: 0
  };

  /*
   * 手动刷新按钮按用户第 9 条删除。映射表与 ACL 都是运行态数据，
   * 所以补一条可见性受控的轮询；有未保存草稿、抽屉或删除确认时跳过。
   */
  function startPolling() {
    stopPolling();
    state.pollTimer = window.setInterval(() => {
      if (!state.mounted) return;
      if (document.hidden) return;
      if (state.loading || state.refreshing || state.saving) return;
      if (state.dirty || state.drawer || state.confirmDelete) return;
      load(true);
    }, 15000);
  }

  function stopPolling() {
    if (!state.pollTimer) return;
    window.clearInterval(state.pollTimer);
    state.pollTimer = 0;
  }

  function defaultData() {
    return {
      enabled: false,
      natpmp_enabled: false,
      pcp: false,
      secure_mode: true,
      log_packets: false,
      system_uptime: true,
      force_forwarding: false,
      use_stun: false,
      external_iface: '',
      internal_ifaces: [],
      port_range: { start: 1024, end: 65535 },
      download_mbps: 0,
      upload_mbps: 0,
      notify_interval: 30,
      clean_interval: 600,
      stun_host: '',
      stun_port: 3478,
      stats: {},
      capabilities: {}
    };
  }

  function clone(value) {
    try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value || {})); }
  }

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (typeof value === 'object' && !Array.isArray(value)) {
        const nested = firstText(value.message, value.name, value.label, value.value, value.id);
        if (nested) return nested;
        continue;
      }
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }

  function firstNumber(...values) {
    for (const value of values) {
      if (value === '' || value === undefined || value === null) continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return 0;
  }

  function booleanValue(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') return !['0', 'false', 'off', 'no', 'disabled'].includes(value.toLowerCase());
    return Boolean(value);
  }

  function asArray(value, keys = []) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of [...keys, 'items', 'rows', 'list', 'data']) {
      if (Array.isArray(value[key])) return value[key];
    }
    return [];
  }

  function parseArray(value) {
    if (Array.isArray(value)) return value.map(String).map((item) => item.trim()).filter(Boolean);
    if (!value) return [];
    if (typeof value === 'string') {
      try {
        const parsed = JSON.parse(value);
        if (Array.isArray(parsed)) return parseArray(parsed);
      } catch (_) {}
      return value.split(/[;,]/).map((item) => item.trim()).filter(Boolean);
    }
    return [];
  }

  /*
   * 会话闸门适配器。此前这里是裸 fetch 直接读 localStorage 的 access token，token 过期时
   * 既不刷新也不重试，并发请求会集体拿 401（通知推送页就表现为 unauthorized 六连）。
   * 闸门内部处理 ensureFresh -> 401 -> refresh -> 单次重试，refreshPromise 单例会合并并发刷新。
   */
  function sessionFetch(url, init = {}) {
    return window.DWRT_REQUEST ? window.DWRT_REQUEST.fetch(url, init) : fetch(url, init);
  }

  function authHeaders(extra = {}) {
    let token = '';
    try { token = localStorage.getItem('dreamingwrt.web.accessToken') || ''; } catch (_) {}
    return {
      Accept: 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}),
      ...extra
    };
  }

  async function requestJson(url, options = {}) {
    const response = await sessionFetch(`${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`, {
      credentials: 'same-origin',
      cache: 'no-store',
      signal: context.signal,
      ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    const payload = json?.data ?? json?.body ?? json;
    const code = Number(json?.code);
    const payloadCode = Number(payload?.code);
    const businessFailed = (Number.isFinite(code) && ![0, 200, 2000].includes(code))
      || (Number.isFinite(payloadCode) && ![0, 200, 2000].includes(payloadCode));
    if (!response.ok || json?.ok === false || payload?.ok === false || businessFailed) {
      const error = new Error(firstText(payload?.message, payload?.error, json?.message, json?.error, `HTTP ${response.status}`));
      error.status = response.status;
      error.payload = json;
      throw error;
    }
    return payload || {};
  }

  function normalizeMapping(item = {}, index = 0, fallbackType = 'dynamic') {
    return {
      ...item,
      id: firstText(item.id, `${fallbackType}-${index + 1}`),
      enabled: item.enabled === undefined ? true : booleanValue(item.enabled),
      protocol: firstText(item.protocol, 'tcp').toLowerCase(),
      external_port: firstNumber(item.external_port),
      internal_ip: firstText(item.internal_ip),
      internal_port: firstNumber(item.internal_port),
      client: firstText(item.client),
      description: firstText(item.description),
      lease: firstNumber(item.lease, item.lease_seconds),
      packets: firstNumber(item.packets),
      mapping_type: firstText(item.mapping_type, fallbackType)
    };
  }

  function normalizeService(payload = {}) {
    const data = {
      ...defaultData(),
      ...payload,
      enabled: booleanValue(payload.enabled),
      natpmp_enabled: booleanValue(payload.natpmp_enabled),
      pcp: booleanValue(payload.pcp),
      secure_mode: booleanValue(payload.secure_mode, true),
      log_packets: booleanValue(payload.log_packets),
      system_uptime: booleanValue(payload.system_uptime, true),
      force_forwarding: booleanValue(payload.force_forwarding),
      use_stun: booleanValue(payload.use_stun),
      external_iface: firstText(payload.external_iface),
      internal_ifaces: parseArray(payload.internal_ifaces),
      port_range: {
        start: firstNumber(payload.port_range?.start, payload.port_start, 1024),
        end: firstNumber(payload.port_range?.end, payload.port_end, 65535)
      },
      download_mbps: firstNumber(payload.download_mbps),
      upload_mbps: firstNumber(payload.upload_mbps),
      notify_interval: firstNumber(payload.notify_interval, 30),
      clean_interval: firstNumber(payload.clean_interval, 600),
      stun_host: firstText(payload.stun_host),
      stun_port: firstNumber(payload.stun_port, 3478),
      stats: payload.stats || {},
      capabilities: payload.capabilities || {}
    };
    delete data.acl;
    delete data.mappings;
    return data;
  }

  async function load(background = false) {
    const seq = ++state.seq;
    state.error = '';
    state.mappingsError = '';
    if (background) state.refreshing = true;
    else state.loading = true;
    if (!background) render();
    try {
      const [serviceResult, mappingsResult] = await Promise.allSettled([
        requestJson(ENDPOINTS.service),
        requestJson(ENDPOINTS.mappings)
      ]);
      if (!state.mounted || seq !== state.seq) return;
      if (serviceResult.status !== 'fulfilled') throw serviceResult.reason;
      const servicePayload = serviceResult.value || {};
      const normalized = normalizeService(servicePayload);
      state.data = clone(normalized);
      state.draft = clone(normalized);
      state.initial = clone(normalized);
      state.acl = asArray(servicePayload.acl).map((item, index) => ({
        ...item,
        id: firstText(item.id, `acl-${index + 1}`),
        action: firstText(item.action, 'allow').toLowerCase(),
        external: firstText(item.external),
        internal: firstText(item.internal),
        internal_ports: firstText(item.internal_ports),
        remark: firstText(item.remark),
        enabled: item.enabled === undefined ? true : booleanValue(item.enabled),
        sort_order: firstNumber(item.sort_order, index)
      }));
      state.dynamicMappings = asArray(servicePayload.mappings)
        .map((item, index) => normalizeMapping(item, index, 'dynamic'))
        .filter((item) => item.mapping_type !== 'static');
      if (mappingsResult.status === 'fulfilled') {
        state.staticMappings = asArray(mappingsResult.value, ['mappings'])
          .map((item, index) => normalizeMapping(item, index, 'static'));
      } else {
        state.staticMappings = [];
        state.mappingsError = `静态映射读取失败：${firstText(mappingsResult.reason?.message, '接口不可用')}`;
      }
      state.dirty = false;
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.error = `读取失败：${firstText(error.message, 'UPnP 接口不可用')}`;
    } finally {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      state.saving = false;
      if (background) renderPreservingInteraction(); else render();
    }
  }

  function cap(name) {
    return state.draft.capabilities?.[name] === true;
  }

  function icon(name, size = 18) {
    const lucideName = {
      refresh: 'refresh-cw',
      plus: 'plus',
      edit: 'square-pen',
      search: 'search',
      chevronDown: 'chevron-down',
      shieldCheck: 'shield-check',
      router: 'router',
      activity: 'activity',
      clock: 'clock',
      lockKeyhole: 'lock-keyhole',
      network: 'chart-network',
      ethernetPort: 'ethernet-port'
    }[name] || name;
    const rendered = typeof ui.lucideIcon === 'function' ? ui.lucideIcon(lucideName, { size, strokeWidth: 1.8 }) : '';
    if (rendered) return rendered;
    const paths = {
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      edit: '<path d="m4 20 4.2-1 10.9-10.9a2 2 0 0 0-2.8-2.8L5.4 16.2 4 20Z"></path>',
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      chevronDown: '<path d="m6 9 6 6 6-6"></path>',
      shieldCheck: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"></path><path d="m9 12 2 2 4-5"></path>',
      router: '<rect x="3" y="11" width="18" height="8" rx="2"></rect><path d="M7 15h.01M11 15h.01M16 11V7m-3 1 3-3 3 3"></path>',
      activity: '<path d="M3 12h4l2-6 4 12 2-6h6"></path>',
      clock: '<circle cx="12" cy="12" r="9"></circle><path d="M12 7v5l3 2"></path>',
      lockKeyhole: '<circle cx="12" cy="16" r="1"></circle><rect x="5" y="10" width="14" height="11" rx="2"></rect><path d="M8 10V7a4 4 0 0 1 8 0v3"></path>',
      network: '<rect x="4" y="4" width="6" height="6" rx="1"></rect><rect x="14" y="14" width="6" height="6" rx="1"></rect><path d="M7 10v4a3 3 0 0 0 3 3h4"></path>',
      ethernetPort: '<rect x="3" y="8" width="18" height="12" rx="2"></rect><path d="M7 8V4h10v4"></path><path d="M8 12v3m4-3v3m4-3v3"></path>'
    };
    return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.network}</svg>`;
  }

  function statusBadge(label, tone = 'muted') {
    return ui.statusBadgeMarkup?.(label, tone) || `<span class="upnp-fallback-status is-${escapeHtml(tone)}">${escapeHtml(label)}</span>`;
  }

  function matchesQuery(values) {
    const query = state.query.trim().toLowerCase();
    return !query || values.flat().map((value) => firstText(value)).join(' ').toLowerCase().includes(query);
  }

  function formatLease(seconds) {
    const value = Number(seconds) || 0;
    if (!value) return '永久';
    if (value < 60) return `${value} 秒`;
    if (value < 3600) return `${Math.round(value / 60)} 分钟`;
    return `${Math.round(value / 3600)} 小时`;
  }

  function tabsMarkup() {
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs upnp-tabs" data-dwrt-component="tabs" data-dwrt-tabs-key="upnp-service" data-upnp-tabs aria-label="UPnP 服务视图"><span class="dwrt-kit-tab-pill" aria-hidden="true"></span>${TABS.map(([id, label]) => `<button class="dwrt-kit-tab ${state.tab === id ? 'is-active' : ''}" type="button" data-upnp-tab="${id}" data-value="${id}" aria-selected="${state.tab === id ? 'true' : 'false'}">${escapeHtml(label)}</button>`).join('')}</nav>`;
  }

  function searchMarkup(placeholder) {
    return `<label class="policy-search policy-search-main upnp-search" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-upnp-search value="${escapeHtml(state.query)}" placeholder="${escapeHtml(placeholder)}"></label>`;
  }

  function canCreateCurrent() {
    if (state.tab === 'acl') return cap('acl_create');
    if (state.tab === 'static') return cap('mapping_create') || cap('save_upnp_mapping');
    return false;
  }

  function toolbarMarkup() {
    const listTab = state.tab !== 'settings';
    const createLabel = state.tab === 'acl' ? '添加规则' : state.tab === 'static' ? '添加映射' : '';
    const placeholder = state.tab === 'acl' ? '搜索动作、端口、网段或备注' : state.tab === 'dynamic' ? '搜索协议、终端、地址或描述' : '搜索协议、地址、客户端或描述';
    return `<header class="upnp-page-toolbar"><div class="upnp-page-toolbar-main">${tabsMarkup()}</div><div class="upnp-page-actions">${listTab ? searchMarkup(placeholder) : ''}${createLabel ? `<button class="dwrt-kit-button upnp-primary-action" data-dwrt-component="button" data-variant="primary" type="button" data-upnp-create ${canCreateCurrent() ? '' : 'disabled'}>${icon('plus')}<span>${createLabel}</span></button>` : ''}</div></header>`;
  }

  function noticeMarkup() {
    const messages = [state.error, state.mappingsError, state.notice].filter(Boolean);
    if (!messages.length) return '';
    const tone = state.error || state.noticeTone === 'bad' ? 'is-error' : state.mappingsError ? 'is-warning' : 'is-success';
    return `<div class="upnp-notice ${tone}" role="status" data-adaptive-sample>${messages.map((message) => `<span>${escapeHtml(message)}</span>`).join('')}</div>`;
  }

  function switchControl(field, checked, options = {}) {
    const disabled = options.disabled === true;
    const attribute = options.editor ? 'data-upnp-editor-field' : 'data-upnp-field';
    const attributeValue = options.editor ? String(field).replace(/^editor\./, '') : field;
    return `<label class="upnp-switch dwrt-kit-switch ${disabled ? 'is-disabled' : ''}" data-dwrt-component="switch"><input type="checkbox" ${attribute}="${escapeHtml(attributeValue)}" aria-label="${escapeHtml(options.label || field)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}></label>`;
  }

  function switchRow(field, title, detail, options = {}) {
    const editor = field.startsWith('editor.');
    const value = Boolean(readPath(editor ? state : state.draft, field));
    return `<div class="upnp-switch-row ${options.dependent ? 'is-dependent' : ''} ${options.disabled ? 'is-disabled' : ''}" data-upnp-control="${escapeHtml(field)}"><span class="upnp-setting-copy"><strong>${escapeHtml(title)}</strong><small>${escapeHtml(detail)}</small></span><span class="upnp-setting-control">${options.disabled ? '<em>只读</em>' : ''}${switchControl(field, value, { disabled: options.disabled, label: title, editor })}</span></div>`;
  }

  function fieldMarkup(label, field, value, options = {}) {
    const disabled = options.disabled === true;
    const type = options.type || 'text';
    const unit = options.unit ? `<span class="upnp-field-unit">${escapeHtml(options.unit)}</span>` : '';
    return `<label class="upnp-field ${options.wide ? 'is-wide' : ''} ${disabled ? 'is-disabled' : ''}" data-dwrt-component="field"><span class="upnp-field-label" data-dwrt-field-label>${escapeHtml(label)}${disabled ? '<em>只读</em>' : ''}</span><span class="upnp-field-control"><input type="${type}" data-upnp-field="${escapeHtml(field)}" value="${escapeHtml(value ?? '')}" placeholder="${escapeHtml(options.placeholder || '')}" ${options.min !== undefined ? `min="${options.min}"` : ''} ${options.max !== undefined ? `max="${options.max}"` : ''} ${disabled ? 'disabled' : ''}>${unit}</span>${options.help ? `<small data-dwrt-field-description>${escapeHtml(options.help)}</small>` : ''}</label>`;
  }

  function editorField(label, field, value, options = {}) {
    const disabled = options.disabled === true;
    if (options.type === 'select') {
      return `<label class="upnp-field ${options.wide ? 'is-wide' : ''}" data-dwrt-component="field"><span class="upnp-field-label" data-dwrt-field-label>${escapeHtml(label)}</span><select class="dwrt-kit-select" data-dwrt-component="select" data-upnp-editor-field="${escapeHtml(field)}" ${disabled ? 'disabled' : ''}>${options.options.map(([key, text]) => `<option value="${escapeHtml(key)}" ${String(value) === String(key) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select></label>`;
    }
    return `<label class="upnp-field ${options.wide ? 'is-wide' : ''}" data-dwrt-component="field"><span class="upnp-field-label" data-dwrt-field-label>${escapeHtml(label)}</span><input type="${options.type || 'text'}" data-upnp-editor-field="${escapeHtml(field)}" value="${escapeHtml(value ?? '')}" placeholder="${escapeHtml(options.placeholder || '')}" ${options.min !== undefined ? `min="${options.min}"` : ''} ${options.max !== undefined ? `max="${options.max}"` : ''} ${disabled ? 'disabled' : ''}></label>`;
  }

  function capabilityDetails(items) {
    const unavailable = items.filter((item) => !cap(item.capability));
    if (!unavailable.length) return '';
    return `<details class="upnp-capability-details"><summary>${icon('lockKeyhole', 16)}<span>可用性说明</span><small>${unavailable.length} 项由后端保持只读</small></summary><ul>${unavailable.map((item) => `<li><strong>${escapeHtml(item.label)}</strong><span>${escapeHtml(item.reason)}</span></li>`).join('')}</ul></details>`;
  }

  function settingGroup(id, index, title, summary, count, body) {
    const expanded = state.expanded === id;
    return `<section class="upnp-setting-group ${expanded ? 'is-expanded' : ''}" data-upnp-group="${id}"><button class="upnp-setting-group-toggle" type="button" data-upnp-group-toggle="${id}" aria-expanded="${expanded ? 'true' : 'false'}" aria-controls="upnp-group-${id}"><span class="upnp-setting-group-index" aria-hidden="true">${escapeHtml(index)}</span><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(summary)}</small></span><em>${escapeHtml(count)}</em>${icon('chevronDown', 18)}</button><div class="upnp-setting-group-body" id="upnp-group-${id}" ${expanded ? '' : 'hidden'}>${body}</div></section>`;
  }

  function settingsMarkup() {
    const writable = cap('service_update');
    const protocolBody = `<div class="upnp-control-grid">
      ${switchRow('natpmp_enabled', 'NAT-PMP', '兼容 Apple 与传统 NAT-PMP 客户端', { disabled: !writable || !cap('natpmp') })}
      ${switchRow('pcp', 'PCP', '使用 Port Control Protocol', { disabled: !writable || !cap('pcp') })}
      ${switchRow('secure_mode', '安全模式', '限制客户端为其他主机创建映射', { disabled: !writable })}
      ${switchRow('use_stun', 'STUN', '探测外部 NAT 地址', { disabled: !writable || !cap('stun') })}
      ${switchRow('force_forwarding', '强制转发', '忽略接口当前的转发状态', { disabled: !writable || !cap('force_forwarding') })}
    </div>${capabilityDetails([
      { capability: 'pcp', label: 'PCP', reason: 'miniupnpd 运行配置尚未可靠消费 PCP。' },
      { capability: 'stun', label: 'STUN', reason: 'STUN 开关与运行态回读尚未闭环。' },
      { capability: 'force_forwarding', label: '强制转发', reason: '运行配置尚未可靠消费该字段。' }
    ])}`;
    const boundaryBody = `<div class="upnp-form-grid">
      ${fieldMarkup('外网接口', 'external_iface', state.draft.external_iface, { disabled: !writable, placeholder: 'wan' })}
      ${fieldMarkup('内网接口', 'internal_ifaces', state.draft.internal_ifaces.join(', '), { disabled: !writable, placeholder: 'lan, lan20' })}
      ${fieldMarkup('外部端口起始', 'port_range.start', state.draft.port_range.start, { type: 'number', min: 1, max: 65535, disabled: !writable || !cap('port_range') })}
      ${fieldMarkup('外部端口结束', 'port_range.end', state.draft.port_range.end, { type: 'number', min: 1, max: 65535, disabled: !writable || !cap('port_range') })}
      ${fieldMarkup('下行带宽', 'download_mbps', state.draft.download_mbps, { type: 'number', min: 0, disabled: !writable, unit: 'Mbps' })}
      ${fieldMarkup('上行带宽', 'upload_mbps', state.draft.upload_mbps, { type: 'number', min: 0, disabled: !writable, unit: 'Mbps' })}
    </div>${capabilityDetails([{ capability: 'port_range', label: '外部端口范围', reason: '后端尚未提供可靠的运行态应用与回读。' }])}`;
    const stunDisabled = !writable || !state.draft.use_stun || !cap('stun_host');
    const runtimeBody = `<div class="upnp-runtime-layout"><div class="upnp-control-grid is-runtime">
      ${switchRow('log_packets', '记录数据包', '记录 UPnP 相关流量', { disabled: !writable })}
      ${switchRow('system_uptime', '使用系统运行时间', '以系统运行时间报告服务状态', { disabled: !writable })}
    </div><div class="upnp-form-grid">
      ${fieldMarkup('通知间隔', 'notify_interval', state.draft.notify_interval, { type: 'number', min: 1, disabled: !writable, unit: '秒' })}
      ${fieldMarkup('清理间隔', 'clean_interval', state.draft.clean_interval, { type: 'number', min: 1, disabled: !writable || !cap('clean_interval'), unit: '秒' })}
      ${fieldMarkup('STUN 地址', 'stun_host', state.draft.stun_host, { disabled: stunDisabled, placeholder: 'stun.example.com' })}
      ${fieldMarkup('STUN 端口', 'stun_port', state.draft.stun_port, { type: 'number', min: 1, max: 65535, disabled: !writable || !state.draft.use_stun || !cap('stun_port') })}
    </div></div>${capabilityDetails([
      { capability: 'clean_interval', label: '清理间隔', reason: 'miniupnpd 配置尚未可靠消费该字段。' },
      { capability: 'stun_host', label: 'STUN 地址', reason: 'STUN 参数写入能力尚未开放。' },
      { capability: 'stun_port', label: 'STUN 端口', reason: 'STUN 参数写入能力尚未开放。' }
    ])}`;
    return `<section class="upnp-settings-surface" data-dwrt-component="surface" data-dwrt-surface="stable-glass" data-adaptive-sample>
      <header class="upnp-settings-head"><div><span class="upnp-settings-icon">${icon('router', 22)}</span><span><strong>UPnP 服务</strong><small>${escapeHtml(state.draft.external_iface || '未指定外网接口')} · ${state.draft.internal_ifaces.length ? escapeHtml(state.draft.internal_ifaces.join('、')) : '未指定内网接口'}</small></span></div><div>${statusBadge(state.draft.enabled ? '运行中' : '已关闭', state.draft.enabled ? 'success' : 'muted')}</div></header>
      <div class="upnp-service-primary" data-upnp-control="enabled"><span><strong>启用 UPnP IGD</strong><small>允许受信任终端动态申请端口映射</small></span>${switchControl('enabled', state.draft.enabled, { disabled: !writable, label: '启用 UPnP IGD' })}</div>
      <div class="upnp-setting-groups">
        ${settingGroup('protocol', '01', '协议与安全', '控制端口映射协议与跨主机保护', '5 项', protocolBody)}
        ${settingGroup('boundary', '02', '网络边界与端口范围', '指定外网、内网、端口边界与链路带宽', '6 项', boundaryBody)}
        ${settingGroup('runtime', '03', '运行参数', '管理日志、服务时间、通知、清理与 STUN 参数', '6 项', runtimeBody)}
      </div>
    </section>${dirtyBarMarkup()}`;
  }

  // Runtime status reads as a row of shared overview cards above the workbench, the
  // same shape DHCP and DNS use, so the numbers are scannable before the settings.
  function overviewMarkup() {
    const renderer = ui.overviewCardsMarkup || window.DWRT_UI_KIT?.overviewCardsMarkup;
    if (typeof renderer !== 'function') return '';
    const stats = state.draft.stats || {};
    const activeMappings = Math.max(firstNumber(stats.active_mappings), state.dynamicMappings.length);
    const denied = firstNumber(stats.denied_today);
    const interfaces = state.draft.internal_ifaces.length ? state.draft.internal_ifaces.join('、') : '未指定内网接口';
    return renderer([
      { key: 'service', label: 'UPnP IGD', value: state.draft.enabled ? '运行中' : '已关闭', detail: state.draft.external_iface || '未指定外网接口', tone: state.draft.enabled ? 'ok' : 'warn', icon: icon('router', 22) },
      { key: 'mappings', label: '当前映射', value: String(activeMappings), detail: `${state.staticMappings.length} 条静态映射`, tone: 'info', icon: icon('network', 22) },
      { key: 'requests', label: '今日请求', value: firstNumber(stats.requests_today).toLocaleString(), detail: `${denied.toLocaleString()} 次拒绝`, tone: denied ? 'warn' : 'neutral', icon: icon('activity', 22) },
      { key: 'security', label: '安全模式', value: state.draft.secure_mode ? '已启用' : '已关闭', detail: state.draft.natpmp_enabled ? 'NAT-PMP 已启用' : '仅 UPnP IGD', tone: state.draft.secure_mode ? 'ok' : 'warn', icon: icon('shieldCheck', 22) },
      { key: 'boundary', label: '内网接口', value: String(state.draft.internal_ifaces.length || 0), detail: interfaces, tone: 'neutral', icon: icon('ethernetPort', 22) }
    ], { className: 'upnp-overview', label: 'UPnP 运行状态' });
  }
  function tableShell(title, meta, headings, rows, empty, count = rows.length) {
    return `<section class="dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap upnp-table-card" data-dwrt-component="data-table" data-dwrt-surface="dense-surface" data-adaptive-sample><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(meta)}</span></div><span class="dwrt-kit-table-count">${count} 条</span></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table upnp-table"><thead><tr>${headings.map((heading) => `<th>${escapeHtml(heading)}</th>`).join('')}</tr></thead><tbody data-upnp-table-body>${state.loading ? `<tr><td colspan="${headings.length}" class="dwrt-kit-table-empty">正在读取配置</td></tr>` : rows.length ? rows.join('') : `<tr><td colspan="${headings.length}" class="dwrt-kit-table-empty">${escapeHtml(empty)}</td></tr>`}</tbody></table></div></section>`;
  }

  function aclMarkup() {
    const rows = state.acl.filter((item) => matchesQuery([item.action, item.external, item.internal, item.internal_ports, item.remark])).map((item) => {
      return `<tr><td>${statusBadge(item.action === 'deny' ? '拒绝' : '允许', item.action === 'deny' ? 'error' : 'success')}</td><td>${escapeHtml(item.external || '--')}</td><td>${escapeHtml(item.internal || '--')}</td><td>${escapeHtml(item.internal_ports || '--')}</td><td>${escapeHtml(item.remark || '--')}</td><td>${statusBadge(item.enabled === false ? '停用' : '启用', item.enabled === false ? 'muted' : 'success')}</td><td>${item.sort_order}</td><td><button class="dwrt-kit-button upnp-row-action" data-dwrt-component="button" data-variant="ghost" type="button" data-upnp-edit-acl="${escapeHtml(item.id)}" aria-label="查看或编辑访问控制规则">${icon('edit')}</button></td></tr>`;
    });
    const gate = cap('acl_create') && cap('acl_update') && cap('acl_delete') ? '' : capabilityBanner('ACL 的新建、编辑和删除分别按后端能力开放；不可用操作保持只读。');
    return `${gate}${tableShell('访问控制', 'miniupnpd 权限规则按优先级执行', ['动作', '外部端口', '内部网段', '内部端口', '备注', '状态', '顺序', '操作'], rows, '暂无访问控制规则', state.acl.length)}`;
  }

  function mappingRows(source, type) {
    return source.filter((item) => matchesQuery([item.protocol, item.external_port, item.internal_ip, item.internal_port, item.client, item.description])).map((item) => {
      const action = type === 'static' ? `<td><button class="dwrt-kit-button upnp-row-action" data-dwrt-component="button" data-variant="ghost" type="button" data-upnp-edit-mapping="${escapeHtml(item.id)}" aria-label="查看或编辑静态端口映射">${icon('edit')}</button></td>` : '';
      return `<tr><td><strong>${escapeHtml(item.protocol.toUpperCase())}</strong></td><td>${item.external_port || '--'}</td><td><span class="upnp-address"><strong>${escapeHtml(item.internal_ip || '--')}</strong><small>${item.internal_port ? `:${item.internal_port}` : ''}</small></span></td><td>${escapeHtml(item.client || '--')}</td><td>${escapeHtml(item.description || '--')}</td><td>${escapeHtml(formatLease(item.lease))}</td><td>${cap('live_packets') ? firstNumber(item.packets).toLocaleString() : '--'}</td>${type === 'static' ? `<td>${statusBadge(item.enabled ? '启用' : '停用', item.enabled ? 'success' : 'muted')}</td>` : ''}${action}</tr>`;
    });
  }

  function dynamicMarkup() {
    const rows = mappingRows(state.dynamicMappings, 'dynamic');
    const gate = cap('live_packets') ? '' : capabilityBanner('动态映射可实时读取；单条映射包数尚无可靠运行态来源，因此不显示伪造流量。');
    return `${gate}${tableShell('动态映射', '由 UPnP IGD、NAT-PMP 或 PCP 客户端申请', ['协议', '外部端口', '内部地址', '客户端', '描述', '租期', '包数'], rows, '当前没有动态端口映射', state.dynamicMappings.length)}`;
  }

  function staticMarkup() {
    const rows = mappingRows(state.staticMappings, 'static');
    const writable = cap('mapping_create') || cap('mapping_update') || cap('mapping_delete');
    const gate = writable && cap('static_mapping_apply') && cap('static_mapping_readback') ? '' : capabilityBanner('静态映射列表来自独立配置表；后端尚未完成 miniupnpd/防火墙应用与运行态回读时，写操作保持禁用。');
    return `${gate}${tableShell('静态映射', '长期保留的固定端口转发', ['协议', '外部端口', '内部地址', '客户端', '描述', '租期', '包数', '状态', '操作'], rows, state.mappingsError ? '静态映射接口不可用' : '暂无静态端口映射', state.staticMappings.length)}`;
  }

  function capabilityBanner(text) {
    return `<div class="upnp-capability-banner" data-adaptive-sample>${icon('lockKeyhole', 18)}<span><strong>能力受限</strong><small>${escapeHtml(text)}</small></span></div>`;
  }

  function dirtyBarMarkup() {
    if (!state.dirty) return '';
    return ui.floatingSavebarMarkup?.({ visible: true, busy: state.saving, message: 'UPnP 服务配置有未保存的变更', discardLabel: '复位', saveLabel: '保存并应用', busyLabel: '正在保存' }) || '';
  }

  function drawerBackdrop(label) {
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-upnp-close aria-label="${escapeHtml(label)}"></button>`;
  }

  function aclDrawer() {
    if (state.drawer !== 'acl') return '';
    const editor = state.editor;
    const writable = editor._new ? cap('acl_create') : cap('acl_update');
    return `${drawerBackdrop('关闭访问控制编辑')}<aside class="dwrt-kit-sheet dwrt-kit-glass-surface upnp-sheet is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" aria-label="${editor._new ? '添加访问控制规则' : '编辑访问控制规则'}"><header class="dwrt-kit-sheet-header"><div><span>UPNP ACCESS CONTROL</span><strong>${editor._new ? '添加访问控制规则' : '编辑访问控制规则'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-upnp-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body upnp-sheet-body"><div class="upnp-editor-switch">${switchRow('editor.enabled', '启用规则', '停用后保留规则但不写入运行配置', { disabled: !writable })}</div><div class="upnp-editor-form">${editorField('动作', 'action', editor.action, { type: 'select', options: [['allow', '允许'], ['deny', '拒绝']], disabled: !writable })}${editorField('外部端口', 'external', editor.external, { placeholder: '1024-65535', disabled: !writable })}${editorField('内部网段', 'internal', editor.internal, { wide: true, placeholder: '192.168.30.0/24', disabled: !writable })}${editorField('内部端口', 'internal_ports', editor.internal_ports, { placeholder: '1024-65535', disabled: !writable })}${editorField('执行顺序', 'sort_order', editor.sort_order, { type: 'number', disabled: !writable })}${editorField('备注', 'remark', editor.remark, { wide: true, disabled: !writable })}</div>${state.notice ? noticeMarkup() : ''}</div><footer class="dwrt-kit-sheet-footer upnp-sheet-footer">${!editor._new && cap('acl_delete') ? `<button class="dwrt-kit-button upnp-danger-action" data-dwrt-component="button" data-variant="danger" type="button" data-upnp-delete ${state.saving ? 'disabled' : ''}>删除</button>` : '<span></span>'}<div><button class="dwrt-kit-button" data-dwrt-component="button" data-variant="ghost" type="button" data-upnp-close>${writable ? '取消' : '关闭'}</button>${writable ? `<button class="dwrt-kit-button" data-dwrt-component="async-button" data-variant="primary" type="button" data-upnp-editor-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存并应用'}</button>` : ''}</div></footer></aside>`;
  }

  function mappingDrawer() {
    if (state.drawer !== 'mapping') return '';
    const editor = state.editor;
    const writable = editor._new ? (cap('mapping_create') || cap('save_upnp_mapping')) : (cap('mapping_update') || cap('save_upnp_mapping'));
    return `${drawerBackdrop('关闭静态映射编辑')}<aside class="dwrt-kit-sheet dwrt-kit-glass-surface upnp-sheet is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" aria-label="${editor._new ? '添加静态映射' : '编辑静态映射'}"><header class="dwrt-kit-sheet-header"><div><span>STATIC PORT MAPPING</span><strong>${editor._new ? '添加静态映射' : '编辑静态映射'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-upnp-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body upnp-sheet-body"><div class="upnp-editor-switch">${switchRow('editor.enabled', '启用映射', '保存到静态 UPnP 映射表', { disabled: !writable })}</div><div class="upnp-editor-form">${editorField('协议', 'protocol', editor.protocol, { type: 'select', options: [['tcp', 'TCP'], ['udp', 'UDP']], disabled: !writable })}${editorField('外部端口', 'external_port', editor.external_port, { type: 'number', min: 1, max: 65535, disabled: !writable })}${editorField('内部 IP', 'internal_ip', editor.internal_ip, { wide: true, placeholder: '192.168.30.100', disabled: !writable })}${editorField('内部端口', 'internal_port', editor.internal_port, { type: 'number', min: 1, max: 65535, disabled: !writable })}${editorField('租期', 'lease', editor.lease, { type: 'number', min: 0, disabled: !writable })}${editorField('客户端', 'client', editor.client, { wide: true, disabled: !writable })}${editorField('描述', 'description', editor.description, { wide: true, disabled: !writable })}</div>${!writable ? capabilityBanner('当前后端没有静态映射写入、运行态应用和回读能力。') : ''}${state.notice ? noticeMarkup() : ''}</div><footer class="dwrt-kit-sheet-footer upnp-sheet-footer">${!editor._new && (cap('mapping_delete') || cap('delete_upnp_mapping')) ? `<button class="dwrt-kit-button upnp-danger-action" data-dwrt-component="button" data-variant="danger" type="button" data-upnp-delete ${state.saving ? 'disabled' : ''}>删除</button>` : '<span></span>'}<div><button class="dwrt-kit-button" data-dwrt-component="button" data-variant="ghost" type="button" data-upnp-close>${writable ? '取消' : '关闭'}</button>${writable ? `<button class="dwrt-kit-button" data-dwrt-component="async-button" data-variant="primary" type="button" data-upnp-editor-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存并应用'}</button>` : ''}</div></footer></aside>`;
  }

  function deleteConfirmationMarkup() {
    if (!state.confirmDelete) return '';
    const deletingAcl = state.confirmDelete === 'acl';
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    return typeof renderer === 'function' ? renderer({
      id: 'upnp-delete-confirmation',
      action: deletingAcl ? 'delete-acl' : 'delete-static-mapping',
      tone: 'danger',
      title: deletingAcl ? '删除访问控制规则' : '删除静态端口映射',
      description: deletingAcl
        ? `规则“${firstText(state.editor.remark, state.editor.id, '未命名规则')}”将被删除并重新应用 UPnP 配置。`
        : `映射“${firstText(state.editor.description, state.editor.id, '未命名映射')}”将被删除并重新应用端口映射。`,
      cancelLabel: '取消',
      confirmLabel: state.saving ? '正在删除' : '确认删除',
      disabled: state.saving
    }) : '';
  }

  function renderContent() {
    if (state.tab === 'settings') return settingsMarkup();
    if (state.tab === 'acl') return aclMarkup();
    if (state.tab === 'dynamic') return dynamicMarkup();
    return staticMarkup();
  }

  /*
   * 轮询刷新走 kit 的共享保状态入口（Acceptance P0 单：30.1 实机 45 路由巡检，20 条路由在
   * 一个轮询周期里丢滚动 / 焦点 / 选区，根因是整树重绘）。用户主动操作仍走 render()：
   * 那时候 DOM 本来就应该变。
   *
   * render() 收一个可选目标：kit 会先让它渲进离屏容器，再按语义 key patch 回真实 DOM，
   * 未变化的节点不换身份。宿主级设置（hidden / class）仍作用在真实 root 上，因为那些是
   * 路由容器自身的状态，不属于本次要 patch 的内容。
   */
  function renderPreservingInteraction() {
    const preserve = ui.preserveInteractionState;
    if (typeof preserve === 'function' && preserve(root, render)) return;
    render();
  }

  function render(target = root) {
    if (!root) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'upnp-service-route-host');
    target.innerHTML = `<section class="upnp-service-shell" data-upnp-version="${VERSION}">${toolbarMarkup()}${overviewMarkup()}<main class="upnp-service-workbench">${noticeMarkup()}${renderContent()}</main>${aclDrawer()}${mappingDrawer()}${deleteConfirmationMarkup()}</section>`;
    ui.mountAll?.(target);
    ui.scheduleAdaptiveForegroundSample?.(20, target);
  }

  function readPath(object, path) {
    return String(path).split('.').reduce((value, part) => value?.[part], object);
  }

  function setPath(object, path, value) {
    const parts = String(path).split('.');
    let target = object;
    for (const part of parts.slice(0, -1)) {
      if (!target[part] || typeof target[part] !== 'object') target[part] = {};
      target = target[part];
    }
    target[parts.at(-1)] = value;
  }

  function patchSavebar() {
    const current = root?.querySelector('[data-dwrt-savebar]');
    const markup = dirtyBarMarkup();
    if (current && !markup) current.remove();
    else if (current && markup) current.outerHTML = markup;
    else if (markup) root?.querySelector('.upnp-service-workbench')?.insertAdjacentHTML('beforeend', markup);
  }

  function patchTable() {
    const oldCard = root?.querySelector('.upnp-table-card');
    if (!oldCard) return;
    const scroll = oldCard.querySelector('.dwrt-kit-table-scroll');
    const top = scroll?.scrollTop || 0;
    const left = scroll?.scrollLeft || 0;
    const template = document.createElement('template');
    template.innerHTML = renderContent();
    const nextCard = template.content.querySelector('.upnp-table-card');
    if (!nextCard) return;
    oldCard.replaceWith(nextCard);
    const nextScroll = nextCard.querySelector('.dwrt-kit-table-scroll');
    if (nextScroll) { nextScroll.scrollTop = top; nextScroll.scrollLeft = left; }
    ui.mountAll?.(nextCard);
    ui.scheduleAdaptiveForegroundSample?.(20, nextCard);
  }

  function resetDraft() {
    state.draft = clone(state.initial);
    state.dirty = false;
    state.notice = '未保存的变更已复位';
    state.noticeTone = 'ok';
    render();
  }

  function servicePayload() {
    const payload = clone(state.draft);
    delete payload.stats;
    delete payload.capabilities;
    delete payload.ts;
    delete payload.apply_state;
    return payload;
  }

  function validateService() {
    const start = firstNumber(state.draft.port_range?.start);
    const end = firstNumber(state.draft.port_range?.end);
    if (start < 1 || end > 65535 || end < start) return '外部端口范围必须位于 1-65535，且结束端口不能小于起始端口';
    if (state.draft.stun_port < 1 || state.draft.stun_port > 65535) return 'STUN 端口必须位于 1-65535';
    return '';
  }

  async function saveService() {
    if (state.saving || !state.dirty || !cap('service_update')) return;
    const validation = validateService();
    if (validation) { state.notice = validation; state.noticeTone = 'bad'; render(); return; }
    state.saving = true;
    state.notice = '';
    patchSavebar();
    try {
      await requestJson(ENDPOINTS.service, { method: 'PUT', body: JSON.stringify(servicePayload()) });
      state.notice = 'UPnP 服务配置已保存并应用';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `保存失败：${firstText(error.message, '后端未接受配置')}`;
      state.noticeTone = 'bad';
      render();
    }
  }

  function openAcl(id = '') {
    const item = state.acl.find((entry) => String(entry.id) === String(id));
    state.editor = clone(item || { id: `acl-${Date.now()}`, action: 'allow', external: '1024-65535', internal: '0.0.0.0/0', internal_ports: '1024-65535', remark: '', enabled: true, sort_order: 0 });
    state.editor._new = !item;
    state.drawer = 'acl';
    state.confirmDelete = false;
    state.notice = '';
    render();
  }

  function openMapping(id = '') {
    const item = state.staticMappings.find((entry) => String(entry.id) === String(id));
    state.editor = clone(item || { id: `mapping-${Date.now()}`, enabled: true, protocol: 'tcp', external_port: '', internal_ip: '', internal_port: '', client: '', description: '', lease: 0, packets: 0, mapping_type: 'static' });
    state.editor._new = !item;
    state.drawer = 'mapping';
    state.confirmDelete = false;
    state.notice = '';
    render();
  }

  function closeDrawer() {
    state.drawer = '';
    state.editor = {};
    state.confirmDelete = false;
    state.notice = '';
    render();
  }

  function validateAcl(editor) {
    if (!['allow', 'deny'].includes(editor.action)) return '请选择允许或拒绝动作';
    if (!String(editor.external || '').trim()) return '外部端口不能为空';
    if (!String(editor.internal || '').trim()) return '内部网段不能为空';
    if (!String(editor.internal_ports || '').trim()) return '内部端口不能为空';
    return '';
  }

  async function saveAcl() {
    const writable = state.editor._new ? cap('acl_create') : cap('acl_update');
    if (!writable || state.saving) return;
    const editor = clone(state.editor);
    delete editor._new;
    const validation = validateAcl(editor);
    if (validation) { state.notice = validation; state.noticeTone = 'bad'; render(); return; }
    state.saving = true;
    render();
    try {
      await requestJson(ENDPOINTS.acl, { method: 'PUT', body: JSON.stringify(editor) });
      state.notice = '访问控制规则已保存并应用';
      state.noticeTone = 'ok';
      state.drawer = '';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `保存失败：${firstText(error.message, '后端未接受访问控制规则')}`;
      state.noticeTone = 'bad';
      render();
    }
  }

  async function deleteAcl() {
    if (!cap('acl_delete') || state.saving) return;
    state.saving = true;
    render();
    try {
      await requestJson(`${ENDPOINTS.acl}/${encodeURIComponent(state.editor.id)}`, { method: 'DELETE' });
      state.notice = '访问控制规则已删除';
      state.noticeTone = 'ok';
      state.drawer = '';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `删除失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'bad';
      render();
    }
  }

  function validateMapping(editor) {
    if (!['tcp', 'udp'].includes(editor.protocol)) return '请选择 TCP 或 UDP';
    if (editor.external_port < 1 || editor.external_port > 65535) return '外部端口必须位于 1-65535';
    if (!String(editor.internal_ip || '').trim()) return '内部 IP 不能为空';
    if (editor.internal_port < 1 || editor.internal_port > 65535) return '内部端口必须位于 1-65535';
    return '';
  }

  async function saveMapping() {
    const writable = state.editor._new ? (cap('mapping_create') || cap('save_upnp_mapping')) : (cap('mapping_update') || cap('save_upnp_mapping'));
    if (!writable || state.saving) return;
    const editor = clone(state.editor);
    delete editor._new;
    const validation = validateMapping(editor);
    if (validation) { state.notice = validation; state.noticeTone = 'bad'; render(); return; }
    state.saving = true;
    render();
    try {
      await requestJson(ENDPOINTS.mappings, { method: 'PUT', body: JSON.stringify(editor) });
      state.notice = '静态映射已保存并应用';
      state.noticeTone = 'ok';
      state.drawer = '';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `保存失败：${firstText(error.message, '后端未接受静态映射')}`;
      state.noticeTone = 'bad';
      render();
    }
  }

  async function deleteMapping() {
    if (!(cap('mapping_delete') || cap('delete_upnp_mapping')) || state.saving) return;
    state.saving = true;
    render();
    try {
      await requestJson(`${ENDPOINTS.mappings}/${encodeURIComponent(state.editor.id)}`, { method: 'DELETE' });
      state.notice = '静态映射已删除';
      state.noticeTone = 'ok';
      state.drawer = '';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `删除失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'bad';
      render();
    }
  }

  function onClick(event) {
    const tab = event.target.closest('[data-upnp-tab]');
    if (tab) {
      const next = tab.dataset.upnpTab;
      if (!TABS.some(([id]) => id === next) || next === state.tab) return;
      state.tab = next;
      state.query = '';
      state.notice = '';
      state.drawer = '';
      render();
      return;
    }
    const group = event.target.closest('[data-upnp-group-toggle]');
    if (group) {
      const next = group.dataset.upnpGroupToggle;
      state.expanded = state.expanded === next ? '' : next;
      root.querySelectorAll('[data-upnp-group]').forEach((section) => {
        const open = section.dataset.upnpGroup === state.expanded;
        section.classList.toggle('is-expanded', open);
        section.querySelector('[data-upnp-group-toggle]')?.setAttribute('aria-expanded', String(open));
        const body = section.querySelector('.upnp-setting-group-body');
        if (body) body.hidden = !open;
      });
      return;
    }
    if (event.target.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]')) { state.confirmDelete = false; render(); return; }
    if (event.target.closest('[data-dwrt-confirm-accept]')) {
      const target = state.confirmDelete;
      state.confirmDelete = false;
      if (target === 'acl') deleteAcl();
      else if (target === 'mapping') deleteMapping();
      return;
    }
    if (event.target.closest('[data-upnp-close]')) { closeDrawer(); return; }
    if (event.target.closest('[data-dwrt-savebar-discard]')) { resetDraft(); return; }
    if (event.target.closest('[data-dwrt-savebar-save]')) { saveService(); return; }
    const acl = event.target.closest('[data-upnp-edit-acl]');
    if (acl) { openAcl(acl.dataset.upnpEditAcl); return; }
    const mapping = event.target.closest('[data-upnp-edit-mapping]');
    if (mapping) { openMapping(mapping.dataset.upnpEditMapping); return; }
    if (event.target.closest('[data-upnp-create]')) {
      if (state.tab === 'acl') openAcl();
      else if (state.tab === 'static') openMapping();
      return;
    }
    if (event.target.closest('[data-upnp-editor-save]')) {
      if (state.drawer === 'acl') saveAcl();
      else if (state.drawer === 'mapping') saveMapping();
      return;
    }
    if (event.target.closest('[data-upnp-delete]')) {
      if (state.drawer === 'acl' && cap('acl_delete')) state.confirmDelete = 'acl';
      else if (state.drawer === 'mapping' && (cap('mapping_delete') || cap('delete_upnp_mapping'))) state.confirmDelete = 'mapping';
      render();
    }
  }

  function inputValue(target) {
    if (target.type === 'checkbox') return target.checked;
    if (target.type === 'number') return target.value === '' ? 0 : Number(target.value);
    return target.value;
  }

  function updateSetting(target) {
    const field = target.dataset.upnpField;
    if (!field) return;
    setPath(state.draft, field, field === 'internal_ifaces' ? parseArray(target.value) : inputValue(target));
    state.dirty = true;
    state.notice = '';
    if (field === 'use_stun') {
      const body = root.querySelector('#upnp-group-runtime');
      if (body && state.expanded === 'runtime') {
        const template = document.createElement('template');
        template.innerHTML = settingsMarkup();
        const next = template.content.querySelector('#upnp-group-runtime');
        if (next) body.replaceWith(next);
        ui.mountAll?.(root.querySelector('#upnp-group-runtime'));
        ui.scheduleAdaptiveForegroundSample?.(20, root.querySelector('#upnp-group-runtime'));
      }
    }
    patchSavebar();
  }

  function onInput(event) {
    const search = event.target.closest('[data-upnp-search]');
    if (search) { state.query = search.value; patchTable(); return; }
    const field = event.target.closest('[data-upnp-field]');
    if (field && !['checkbox', 'radio'].includes(field.type) && field.tagName !== 'SELECT') updateSetting(field);
    const editorFieldTarget = event.target.closest('[data-upnp-editor-field]');
    if (editorFieldTarget && !['checkbox', 'radio'].includes(editorFieldTarget.type) && editorFieldTarget.tagName !== 'SELECT') setPath(state.editor, editorFieldTarget.dataset.upnpEditorField, inputValue(editorFieldTarget));
  }

  function onChange(event) {
    const field = event.target.closest('[data-upnp-field]');
    if (field) { updateSetting(field); return; }
    const editorFieldTarget = event.target.closest('[data-upnp-editor-field]');
    if (editorFieldTarget) setPath(state.editor, editorFieldTarget.dataset.upnpEditorField, inputValue(editorFieldTarget));
  }

  root?.addEventListener('click', onClick);
  root?.addEventListener('input', onInput);
  root?.addEventListener('change', onChange);
  stage?.classList.add('is-upnp-service');
  render();
  load();
  startPolling();

  return {
    refresh() { return load(true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      stopPolling();
      root?.removeEventListener('click', onClick);
      root?.removeEventListener('input', onInput);
      root?.removeEventListener('change', onChange);
      root?.replaceChildren();
      root?.classList.remove('route-workspace', 'upnp-service-route-host');
      stage?.classList.remove('is-upnp-service');
    }
  };
}

export default { mount };
