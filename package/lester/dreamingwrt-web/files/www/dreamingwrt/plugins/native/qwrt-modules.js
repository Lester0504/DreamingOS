export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  if (!root) return () => {};
  const stage = root.closest('.console-stage');
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const VERSION = '20260810-front-release-01';
  const TABS = [
    ['overview', '概览'],
    ['slots', '模组与拨号'],
    ['apn', 'APN 档案'],
    ['failover', '高可用与探测'],
    ['sms', '短信']
  ];
  const SUCCESS_CODES = new Set([0, 200, 2000]);
  const LABEL_MAX_CHARS = 22;
  const AUTH_TYPES = [['none', '无认证'], ['pap', 'PAP'], ['chap', 'CHAP'], ['both', 'PAP / CHAP']];
  const NETWORK_TYPES = [['auto', '自动'], ['lte', '4G / LTE'], ['nr5g', '5G NR'], ['wcdma', '3G / WCDMA'], ['gsm', '2G / GSM']];
  const FAILOVER_MODES = [['none', '不切换'], ['probe', '探测失败切换'], ['priority', '按优先级切换']];

  const state = {
    mounted: true,
    seq: 0,
    loading: true,
    refreshing: false,
    saving: false,
    tab: 'overview',
    data: null,
    draft: null,
    initial: null,
    runtime: null,
    runtimeError: '',
    sheet: null,
    dirty: false,
    error: '',
    notice: '',
    confirmation: null,
    lastUpdated: 0,
    pollTimer: 0
  };

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (typeof value === 'object' && !Array.isArray(value)) {
        const nested = firstText(value.message, value.error, value.reason, value.label, value.name, value.id);
        if (nested) return nested;
        continue;
      }
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }

  function bool(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') return !['0', 'false', 'off', 'no', 'disabled'].includes(value.toLowerCase());
    return Boolean(value);
  }

  function number(value, fallback = 0) {
    if (value === '' || value === null || value === undefined) return fallback;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
  }

  function clone(value) {
    try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value ?? null)); }
  }

  function array(value) {
    if (Array.isArray(value)) return value;
    if (!value) return [];
    if (typeof value === 'object') {
      for (const key of ['items', 'rows', 'list', 'data', 'slots', 'apn_profiles', 'sms']) if (Array.isArray(value[key])) return value[key];
    }
    return [];
  }

  // One shared cap for every operator/model/remark label on this route, so a long
  // carrier string cannot push an icon onto its own line or widen a table column.
  function clipLabel(value, max = LABEL_MAX_CHARS) {
    const text = String(value ?? '').trim();
    if (Array.from(text).length <= max) return text;
    return `${Array.from(text).slice(0, max - 1).join('').trimEnd()}…`;
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
    const code = json?.code;
    const payload = json?.data ?? json?.body ?? json;
    const businessFailed = code !== undefined && code !== null && !SUCCESS_CODES.has(Number(code));
    if (!response.ok || json?.ok === false || payload?.ok === false || businessFailed) {
      const error = new Error(firstText(payload?.reason, payload?.message, payload?.error, json?.message, json?.error, describeStatus(response.status)));
      error.status = response.status;
      error.payload = json;
      throw error;
    }
    return payload || {};
  }

  // Status classification is fixed by design.md: never blend "not implemented"
  // with "session expired" or "backend error" into one sentence.
  function describeStatus(status) {
    if (status === 401) return '会话已失效，请重新登录';
    if (status === 403) return '当前账号没有蜂窝配置权限';
    if ([404, 405, 501].includes(status)) return '当前固件没有实现该接口';
    if (status >= 500) return `后端返回错误 HTTP ${status}`;
    return `HTTP ${status}`;
  }

  function defaultGlobal() {
    return { enabled: true, default_slot: '', failover_mode: 'none', failover_threshold: 3, probe_interval: 60, probe_host: '8.8.8.8', updated_at: 0 };
  }

  function normalizeSlot(source = {}, index = 0) {
    return {
      id: firstText(source.id, `slot-${index + 1}`),
      name: firstText(source.name, `模组 ${index + 1}`),
      modem_path: firstText(source.modem_path),
      dev_type: firstText(source.dev_type, 'unknown'),
      enabled: bool(source.enabled, true),
      sim_id: firstText(source.sim_id),
      iccid: firstText(source.iccid),
      imei: firstText(source.imei),
      operator: firstText(source.operator),
      signal: number(source.signal),
      apn: firstText(source.apn),
      auth_type: firstText(source.auth_type, 'none'),
      username: firstText(source.username),
      password: firstText(source.password),
      pincode: firstText(source.pincode),
      network_type: firstText(source.network_type, 'auto'),
      roaming: bool(source.roaming),
      mTU: number(source.mTU ?? source.mtu, 1500),
      dial_num: firstText(source.dial_num, '*99#'),
      remark: firstText(source.remark),
      sort_order: number(source.sort_order, index),
      updated_at: number(source.updated_at)
    };
  }

  function normalizeProfile(source = {}, index = 0) {
    return {
      id: firstText(source.id, `apn-${index + 1}`),
      name: firstText(source.name, `APN ${index + 1}`),
      apn: firstText(source.apn),
      auth_type: firstText(source.auth_type, 'none'),
      username: firstText(source.username),
      password: firstText(source.password),
      dial_num: firstText(source.dial_num, '*99#'),
      network_type: firstText(source.network_type, 'auto'),
      remark: firstText(source.remark),
      updated_at: number(source.updated_at)
    };
  }

  function normalizeSms(source = {}, index = 0) {
    const direction = firstText(source.direction, 'inbox').toLowerCase();
    return {
      id: firstText(source.id, `sms-${index + 1}`),
      slot_id: firstText(source.slot_id),
      direction: ['outbox', 'sent', 'out'].includes(direction) ? 'outbox' : 'inbox',
      phone: firstText(source.phone, '--'),
      content: firstText(source.content),
      timestamp: number(source.timestamp),
      read_flag: bool(source.read_flag),
      updated_at: number(source.updated_at)
    };
  }

  function normalizeService(source = {}) {
    return {
      global: { ...defaultGlobal(), ...(source.global && typeof source.global === 'object' ? source.global : {}), enabled: bool(source.global?.enabled, true), failover_threshold: number(source.global?.failover_threshold, 3), probe_interval: number(source.global?.probe_interval, 60), failover_mode: firstText(source.global?.failover_mode, 'none'), probe_host: firstText(source.global?.probe_host, '8.8.8.8'), default_slot: firstText(source.global?.default_slot) },
      slots: array(source.slots).map(normalizeSlot),
      apn_profiles: array(source.apn_profiles).map(normalizeProfile),
      sms: array(source.sms).map(normalizeSms)
    };
  }

  function normalizeRuntime(source = {}) {
    return {
      modemmanager: firstText(source.modemmanager, 'unknown'),
      mmcli: bool(source.mmcli),
      runtime: firstText(source.runtime, 'unknown'),
      at_write: firstText(source.at_write, 'unknown')
    };
  }

  async function load(refreshing = false) {
    const seq = ++state.seq;
    state.loading = !state.data;
    state.refreshing = refreshing;
    state.error = '';
    render();
    const results = await Promise.allSettled([
      requestJson('/api/v1/services/cellular'),
      requestJson('/api/v1/services/cellular/status')
    ]);
    if (!state.mounted || seq !== state.seq) return;
    const service = results[0];
    if (service.status !== 'fulfilled') {
      state.loading = false;
      state.refreshing = false;
      state.error = firstText(service.reason?.message, '无法读取蜂窝模组配置');
      render();
      return;
    }
    state.data = normalizeService(service.value);
    if (!state.dirty) {
      state.draft = clone(state.data);
      state.initial = clone(state.data);
    } else {
      state.draft.slots = clone(state.data.slots);
      state.draft.apn_profiles = clone(state.data.apn_profiles);
      state.draft.sms = clone(state.data.sms);
    }
    if (results[1].status === 'fulfilled') {
      state.runtime = normalizeRuntime(results[1].value);
      state.runtimeError = '';
    } else {
      state.runtime = null;
      state.runtimeError = firstText(results[1].reason?.message, '运行态接口未响应');
    }
    state.loading = false;
    state.refreshing = false;
    state.lastUpdated = Date.now();
    if (refreshing) renderPreservingInteraction(); else render();
  }

  function icon(name, size = 18) {
    const lucideName = {
      tower: 'radio-tower',
      sim: 'credit-card',
      signal: 'signal',
      sms: 'message-square',
      refresh: 'refresh-cw',
      plus: 'plus',
      trash: 'trash-2',
      edit: 'pencil',
      warning: 'triangle-alert',
      info: 'info',
      close: 'x',
      shield: 'shield-check',
      gauge: 'gauge'
    }[name] || name;
    const rendered = typeof ui.lucideIcon === 'function' ? ui.lucideIcon(lucideName, { size, strokeWidth: 1.8 }) : '';
    if (rendered) return rendered;
    const paths = {
      tower: '<path d="M7 20h10"></path><path d="M12 20V9"></path><path d="m9 9 3-5 3 5"></path><path d="M8 12a5 5 0 0 0 8 0"></path><path d="M5 9a9 9 0 0 0 14 0"></path>',
      sim: '<path d="M7 3h7l4 4v14H7z"></path><path d="M10 13h4"></path><path d="M10 17h1"></path><path d="M14 17h1"></path>',
      signal: '<path d="M4 20V16"></path><path d="M9 20v-7"></path><path d="M14 20V9"></path><path d="M19 20V5"></path>',
      sms: '<path d="M4 5h16v11H8l-4 4z"></path><path d="M8 9h8"></path><path d="M8 13h5"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      trash: '<path d="M4 7h16M9 7V4h6v3m-9 0 1 13h10l1-13M10 11v5m4-5v5"></path>',
      edit: '<path d="M12 20h9"></path><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"></path>',
      warning: '<path d="M12 9v4M12 17h.01"></path><path d="M10.3 3.4 2.7 17a2 2 0 0 0 1.8 3h15a2 2 0 0 0 1.8-3L13.7 3.4a2 2 0 0 0-3.4 0Z"></path>',
      info: '<circle cx="12" cy="12" r="9"></circle><path d="M12 8h.01M11 12h1v4h1"></path>',
      close: '<path d="M6 6l12 12M18 6 6 18"></path>',
      shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"></path>',
      gauge: '<path d="m12 14 4-4"></path><path d="M3.34 19a10 10 0 1 1 17.32 0"></path>'
    };
    return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.tower}</svg>`;
  }

  function formatTime(value) {
    if (!value) return '--';
    const numeric = Number(value);
    const date = Number.isFinite(numeric) ? new Date(numeric < 100000000000 ? numeric * 1000 : numeric) : new Date(value);
    if (Number.isNaN(date.getTime())) return '--';
    return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(date);
  }

  function statusBadge(label, tone = 'neutral') {
    return ui.statusBadgeMarkup?.(label, tone, { dot: tone === 'success' }) || `<span>${escapeHtml(label)}</span>`;
  }

  function labelOf(pairs, value, fallback = '--') {
    const hit = pairs.find(([key]) => String(key) === String(value ?? ''));
    return hit ? hit[1] : firstText(value, fallback);
  }

  function signalLabel(value) {
    const percent = number(value);
    if (!percent) return '--';
    return `${Math.max(0, Math.min(100, percent))}%`;
  }

  function runtimeReady() {
    return state.runtime?.mmcli === true;
  }

  // The write endpoints for global/slots/apn-profiles are registered
  // unconditionally by the backend, so the page must not pretend they are
  // gated. Only ModemManager-backed runtime verification is uncertain.
  function canWrite() {
    return Boolean(state.data);
  }

  function modemPathValid(value) {
    const text = String(value ?? '').trim();
    if (!text) return true;
    if (/^\d+$/.test(text)) return true;
    return /^\/org\/freedesktop\/ModemManager1\/(Modem|SIM)\/\d+$/.test(text);
  }

  function tabsMarkup() {
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs qwrt-tabs" data-dwrt-component="tabs" role="tablist" data-dwrt-tabs-key="qwrt-modules" aria-label="QWRT 模组管理视图"><span class="dwrt-kit-tab-pill" aria-hidden="true"></span>${TABS.map(([id, label]) => `<button class="dwrt-kit-tab ${state.tab === id ? 'is-active' : ''}" type="button" role="tab" data-qwrt-tab="${id}" data-value="${id}" aria-selected="${state.tab === id ? 'true' : 'false'}">${escapeHtml(label)}</button>`).join('')}</nav>`;
  }

  function pageToolbar() {
    return `<header class="qwrt-page-header">${tabsMarkup()}<div class="qwrt-page-actions"></div></header>`;
  }

  function noticeMarkup() {
    if (!state.error && !state.notice) return '';
    return `<div class="qwrt-notice ${state.error ? 'is-error' : ''}" role="${state.error ? 'alert' : 'status'}">${escapeHtml(state.error || state.notice)}</div>`;
  }

  function overviewCardsRow() {
    const renderer = ui.overviewCardsMarkup || window.DWRT_UI_KIT?.overviewCardsMarkup;
    if (typeof renderer !== 'function' || !state.draft) return '';
    const data = state.draft;
    const enabledSlots = data.slots.filter((item) => item.enabled).length;
    const registered = data.slots.filter((item) => item.enabled && item.operator).length;
    const unread = data.sms.filter((item) => item.direction === 'inbox' && !item.read_flag).length;
    const runtimeText = state.runtime ? (state.runtime.mmcli ? '可探测' : 'ModemManager 缺失') : '运行态未确认';
    const runtimeTone = state.runtime ? (state.runtime.mmcli ? 'ok' : 'warn') : 'neutral';
    return renderer([
      { key: 'service', label: '蜂窝服务', value: data.global.enabled ? '已启用' : '已关闭', detail: `切换策略：${labelOf(FAILOVER_MODES, data.global.failover_mode, '不切换')}`, tone: data.global.enabled ? 'ok' : 'neutral', icon: icon('tower', 22) },
      { key: 'slots', label: '模组槽位', value: `${enabledSlots} / ${data.slots.length}`, detail: data.slots.length ? `${registered} 个已登记运营商` : '尚未登记模组', tone: data.slots.length ? 'info' : 'neutral', icon: icon('sim', 22) },
      { key: 'runtime', label: '运行态探测', value: runtimeText, detail: state.runtime ? `AT 写入：${state.runtime.at_write === 'disabled_until_whitelist' ? '白名单未开放' : state.runtime.at_write}` : escapeHtml(state.runtimeError || '状态接口未响应'), tone: runtimeTone, icon: icon('signal', 22) },
      { key: 'sms', label: '短信', value: `${unread} 未读`, detail: `共 ${data.sms.length} 条记录`, tone: unread ? 'warn' : 'neutral', icon: icon('sms', 22) }
    ], { className: 'qwrt-overview', label: 'QWRT 模组概览' });
  }

  function tableShell(title, detail, headings, rows, empty, className = '', actions = '') {
    return `<section class="qwrt-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap ${className}" data-dwrt-component="data-table" data-dwrt-surface="dense-surface"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(detail)}</span></div><div class="dwrt-kit-table-toolbar-actions qwrt-table-actions"><span class="dwrt-kit-table-count">${rows.length} 条</span>${actions}</div></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table"><thead><tr>${headings.map((heading) => `<th>${escapeHtml(heading)}</th>`).join('')}</tr></thead><tbody>${state.loading ? `<tr><td class="dwrt-kit-table-empty" colspan="${headings.length}">正在读取蜂窝配置</td></tr>` : rows.length ? rows.join('') : `<tr><td class="dwrt-kit-table-empty" colspan="${headings.length}">${escapeHtml(empty)}</td></tr>`}</tbody></table></div></section>`;
  }

  function settingsSurface(content, extraClass = '') {
    return `<section class="qwrt-settings-surface ${extraClass}" data-dwrt-component="surface" data-dwrt-surface="stable-glass" data-adaptive-sample><header class="qwrt-surface-header">${statusBadge(canWrite() ? '可配置' : '只读', canWrite() ? 'success' : 'warning')}</header><div class="qwrt-surface-body">${content}</div></section>`;
  }

  function runtimePanel() {
    if (!state.runtime) {
      return `<div class="qwrt-capability" role="status">${icon('warning')}<span><strong>运行态未确认</strong><small>${escapeHtml(state.runtimeError || '运行态接口未响应')}。这不代表蜂窝功能不存在，只说明本次没有拿到探测结果。</small></span></div>`;
    }
    if (!state.runtime.mmcli) {
      return `<div class="qwrt-capability" role="status">${icon('warning')}<span><strong>ModemManager 未安装</strong><small>后端回报 <code>${escapeHtml(state.runtime.modemmanager)}</code> / <code>${escapeHtml(state.runtime.runtime)}</code>。配置可以保存并写入 UCI，但运营商、IMEI、ICCID 和信号强度无法探测回填，拨号是否真正建立也无法验证。</small></span></div>`;
    }
    return '';
  }

  function field(label, path, value, options = {}) {
    const disabled = options.disabled || !canWrite();
    const attrs = `${disabled ? 'disabled' : ''} ${options.min !== undefined ? `min="${options.min}"` : ''} ${options.max !== undefined ? `max="${options.max}"` : ''}`;
    const description = options.description ? `<span data-dwrt-field-description>${escapeHtml(options.description)}</span>` : '';
    if (options.type === 'select') {
      return `<label class="dwrt-kit-field ${options.wide ? 'is-wide' : ''}" data-dwrt-component="field"><span data-dwrt-field-label>${escapeHtml(label)}</span><select class="dwrt-kit-select" data-qwrt-field="${escapeHtml(path)}" ${attrs}>${options.items.map(([key, text]) => `<option value="${escapeHtml(key)}" ${String(value ?? '') === String(key) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select>${description}</label>`;
    }
    return `<label class="dwrt-kit-field ${options.wide ? 'is-wide' : ''}" data-dwrt-component="field"><span data-dwrt-field-label>${escapeHtml(label)}</span><input type="${options.type || 'text'}" data-qwrt-field="${escapeHtml(path)}" value="${escapeHtml(value ?? '')}" placeholder="${escapeHtml(options.placeholder || '')}" ${attrs}>${description}</label>`;
  }

  function dependencySwitch(path, title, description, checked, dependentMarkup = '', disabled = false) {
    const inactive = !checked;
    return `<section class="qwrt-dependency ${inactive ? 'is-inactive' : ''}" data-dwrt-component="dependency-group"><label class="dwrt-kit-switch qwrt-master-switch"><input type="checkbox" data-qwrt-field="${escapeHtml(path)}" ${checked ? 'checked' : ''} ${disabled || !canWrite() ? 'disabled' : ''}><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(description)}</small></span></label>${dependentMarkup ? `<div class="qwrt-dependency-fields" ${inactive ? 'aria-disabled="true"' : ''}>${dependentMarkup}</div>` : ''}</section>`;
  }

  function slotCard(slot) {
    const tone = !slot.enabled ? 'muted' : slot.operator ? 'success' : 'warning';
    const label = !slot.enabled ? '已停用' : slot.operator ? '已登记' : '待探测';
    return `<article class="qwrt-slot-card" data-qwrt-slot-card="${escapeHtml(slot.id)}"><header><span class="qwrt-slot-icon" aria-hidden="true">${icon('sim', 20)}</span><span class="qwrt-slot-title"><strong${slot.name !== clipLabel(slot.name) ? ` title="${escapeHtml(slot.name)}"` : ''}>${escapeHtml(clipLabel(slot.name))}</strong><small>${escapeHtml(clipLabel(slot.dev_type || 'unknown'))}</small></span>${statusBadge(label, tone)}</header><dl><div><dt>运营商</dt><dd${slot.operator && slot.operator !== clipLabel(slot.operator) ? ` title="${escapeHtml(slot.operator)}"` : ''}>${escapeHtml(clipLabel(slot.operator) || '--')}</dd></div><div><dt>信号</dt><dd>${escapeHtml(signalLabel(slot.signal))}</dd></div><div><dt>APN</dt><dd>${escapeHtml(clipLabel(slot.apn) || '--')}</dd></div><div><dt>制式</dt><dd>${escapeHtml(labelOf(NETWORK_TYPES, slot.network_type))}</dd></div><div><dt>IMEI</dt><dd>${escapeHtml(slot.imei || '--')}</dd></div><div><dt>ICCID</dt><dd>${escapeHtml(slot.iccid || '--')}</dd></div></dl><footer><span>${escapeHtml(slot.modem_path || '未绑定 ModemManager 路径')}</span><button class="dwrt-kit-button dwrt-kit-icon-button" type="button" data-qwrt-slot-edit="${escapeHtml(slot.id)}" aria-label="编辑 ${escapeHtml(slot.name)}" data-dwrt-tooltip="编辑">${icon('edit')}</button></footer></article>`;
  }

  function overviewPanel() {
    const slots = state.draft?.slots || [];
    const cards = slots.length
      ? `<div class="qwrt-slot-grid">${slots.map(slotCard).join('')}</div>`
      : `<div class="qwrt-empty-block dwrt-kit-state-panel" data-dwrt-component="state-panel" data-dwrt-state="empty">${icon('info')}<span><strong>尚未登记蜂窝模组</strong><small>后端返回的槽位列表为空。这是正常的空态：在“模组与拨号”里新增槽位后，这里会显示每个模组的 SIM、运营商与信号。</small></span></div>`;
    return settingsSurface(`${runtimePanel()}${cards}${runtimeFactsTable()}`);
  }

  function runtimeFactsTable() {
    if (!state.runtime) return '';
    const rows = [
      ['ModemManager', state.runtime.modemmanager, '蜂窝探测依赖的系统组件'],
      ['mmcli', state.runtime.mmcli ? '可用' : '不可用', '缺失时无法回填运营商与信号'],
      ['运行态', state.runtime.runtime, '后端自报的蜂窝运行阶段'],
      ['AT 写入', state.runtime.at_write, '危险命令由后端白名单控制']
    ].map(([name, value, detail]) => `<tr><td><strong>${escapeHtml(name)}</strong></td><td>${escapeHtml(String(value))}</td><td>${escapeHtml(detail)}</td></tr>`);
    return tableShell('后端运行态回读', state.lastUpdated ? `观测于 ${formatTime(state.lastUpdated)}` : '等待后端运行态', ['项目', '取值', '说明'], rows, '运行态接口未返回内容', 'qwrt-runtime-table');
  }

  function slotRow(slot) {
    const tone = !slot.enabled ? 'muted' : slot.operator ? 'success' : 'warning';
    const label = !slot.enabled ? '已停用' : slot.operator ? '已登记' : '待探测';
    return `<tr><td>${statusBadge(label, tone)}</td><td><strong${slot.name !== clipLabel(slot.name) ? ` title="${escapeHtml(slot.name)}"` : ''}>${escapeHtml(clipLabel(slot.name))}</strong></td><td>${escapeHtml(clipLabel(slot.dev_type || 'unknown'))}</td><td>${escapeHtml(clipLabel(slot.apn) || '--')}</td><td>${escapeHtml(labelOf(AUTH_TYPES, slot.auth_type))}</td><td>${escapeHtml(labelOf(NETWORK_TYPES, slot.network_type))}</td><td>${escapeHtml(slot.dial_num || '--')}</td><td data-type="number">${slot.mTU}</td><td>${slot.roaming ? '允许' : '禁止'}</td><td data-type="number">${slot.sort_order}</td><td class="qwrt-row-actions"><button class="dwrt-kit-button dwrt-kit-icon-button" type="button" data-qwrt-slot-edit="${escapeHtml(slot.id)}" aria-label="编辑 ${escapeHtml(slot.name)}" data-dwrt-tooltip="编辑" ${!canWrite() ? 'disabled' : ''}>${icon('edit')}</button><button class="dwrt-kit-button dwrt-kit-icon-button" type="button" data-qwrt-slot-delete="${escapeHtml(slot.id)}" aria-label="删除 ${escapeHtml(slot.name)}" data-dwrt-tooltip="删除" ${!canWrite() ? 'disabled' : ''}>${icon('trash')}</button></td></tr>`;
  }

  function slotsPanel() {
    const slots = state.draft?.slots || [];
    const rows = slots.map(slotRow);
    const action = `<button class="dwrt-kit-button qwrt-add-button" data-dwrt-component="button" data-variant="primary" type="button" data-qwrt-slot-new ${!canWrite() ? 'disabled' : ''}>${icon('plus')}<span>新增槽位</span></button>`;
    return settingsSurface(`${runtimePanel()}${tableShell('槽位列表', `${slots.filter((item) => item.enabled).length} 个已启用，保存后立即写入 UCI`, ['状态', '名称', '接口类型', 'APN', '认证', '制式', '拨号串', 'MTU', '漫游', '排序', '操作'], rows, '尚未登记蜂窝槽位', 'qwrt-slot-table', action)}`);
  }

  function profileRow(profile) {
    return `<tr><td><strong${profile.name !== clipLabel(profile.name) ? ` title="${escapeHtml(profile.name)}"` : ''}>${escapeHtml(clipLabel(profile.name))}</strong></td><td>${escapeHtml(clipLabel(profile.apn) || '--')}</td><td>${escapeHtml(labelOf(AUTH_TYPES, profile.auth_type))}</td><td>${escapeHtml(profile.username || '--')}</td><td>${escapeHtml(profile.dial_num || '--')}</td><td>${escapeHtml(labelOf(NETWORK_TYPES, profile.network_type))}</td><td${profile.remark && profile.remark !== clipLabel(profile.remark) ? ` title="${escapeHtml(profile.remark)}"` : ''}>${escapeHtml(clipLabel(profile.remark) || '--')}</td><td>${escapeHtml(formatTime(profile.updated_at))}</td><td class="qwrt-row-actions"><button class="dwrt-kit-button dwrt-kit-icon-button" type="button" data-qwrt-apn-edit="${escapeHtml(profile.id)}" aria-label="编辑 ${escapeHtml(profile.name)}" data-dwrt-tooltip="编辑" ${!canWrite() ? 'disabled' : ''}>${icon('edit')}</button><button class="dwrt-kit-button dwrt-kit-icon-button" type="button" data-qwrt-apn-delete="${escapeHtml(profile.id)}" aria-label="删除 ${escapeHtml(profile.name)}" data-dwrt-tooltip="删除" ${!canWrite() ? 'disabled' : ''}>${icon('trash')}</button></td></tr>`;
  }

  function apnPanel() {
    const profiles = state.draft?.apn_profiles || [];
    const rows = profiles.map(profileRow);
    const action = `<button class="dwrt-kit-button qwrt-add-button" data-dwrt-component="button" data-variant="primary" type="button" data-qwrt-apn-new ${!canWrite() ? 'disabled' : ''}>${icon('plus')}<span>新增档案</span></button>`;
    return settingsSurface(`${tableShell('档案列表', `${profiles.length} 个档案，可在槽位编辑里直接套用`, ['名称', 'APN', '认证', '用户名', '拨号串', '制式', '备注', '更新时间', '操作'], rows, '尚未创建 APN 档案', 'qwrt-apn-table', action)}`);
  }

  function failoverPanel() {
    const global = state.draft?.global || defaultGlobal();
    const slotItems = [['', '不指定'], ...(state.draft?.slots || []).map((slot) => [slot.id, slot.name])];
    const probeFields = `<div class="qwrt-field-grid">${field('探测目标', 'global.probe_host', global.probe_host, { placeholder: '8.8.8.8', description: '用于判断蜂窝链路是否可用的探测地址' })}${field('探测间隔 (秒)', 'global.probe_interval', global.probe_interval, { type: 'number', min: 5, max: 3600 })}${field('失败判定次数', 'global.failover_threshold', global.failover_threshold, { type: 'number', min: 1, max: 30, description: '连续失败达到该次数后触发切换' })}</div>`;
    const fields = `<div class="qwrt-field-grid">${field('默认槽位', 'global.default_slot', global.default_slot, { type: 'select', items: slotItems, description: '优先使用的蜂窝槽位' })}${field('切换策略', 'global.failover_mode', global.failover_mode, { type: 'select', items: FAILOVER_MODES })}</div>${global.failover_mode === 'probe' ? probeFields : ''}`;
    return settingsSurface(`${runtimePanel()}${dependencySwitch('global.enabled', '蜂窝服务', '总开关。关闭后所有槽位都不会参与拨号。', global.enabled, fields)}`);
  }

  function smsRow(item) {
    return `<tr><td>${statusBadge(item.direction === 'inbox' ? '收件' : '发件', item.direction === 'inbox' ? 'info' : 'muted')}</td><td>${escapeHtml(item.phone)}</td><td class="qwrt-sms-content"${item.content && item.content !== clipLabel(item.content, 48) ? ` title="${escapeHtml(item.content)}"` : ''}>${escapeHtml(clipLabel(item.content, 48) || '--')}</td><td>${escapeHtml(item.slot_id || '--')}</td><td>${item.read_flag ? '已读' : '未读'}</td><td>${escapeHtml(formatTime(item.timestamp))}</td></tr>`;
  }

  function smsPanel() {
    const messages = state.draft?.sms || [];
    const rows = messages.map(smsRow);
    const gap = `<div class="qwrt-capability" role="status">${icon('info')}<span><strong>短信当前只读</strong><small>后端已经落库短信记录，但只为删除提供了 ubus 方法，没有开放 HTTP 路由，也没有发送接口。因此这里只展示真实记录，发送与删除保持禁用，不做假按钮。</small></span></div>`;
    return settingsSurface(`${gap}${tableShell('短信记录', messages.length ? `最近 ${messages.length} 条` : '后端按时间倒序返回最近 200 条', ['方向', '号码', '内容', '槽位', '状态', '时间'], rows, '暂无短信记录', 'qwrt-sms-table')}`);
  }

  function sheetField(label, name, value, options = {}) {
    const disabled = options.disabled || !canWrite();
    const attrs = `${disabled ? 'disabled' : ''} ${options.min !== undefined ? `min="${options.min}"` : ''} ${options.max !== undefined ? `max="${options.max}"` : ''}`;
    const help = options.help ? `<span data-dwrt-field-description>${escapeHtml(options.help)}</span>` : '';
    if (options.items) {
      return `<label class="dwrt-kit-field ${options.wide ? 'is-wide' : ''}" data-dwrt-component="field"><span data-dwrt-field-label>${escapeHtml(label)}</span><select class="dwrt-kit-select" data-qwrt-sheet-field="${escapeHtml(name)}" ${attrs}>${options.items.map(([key, text]) => `<option value="${escapeHtml(key)}" ${String(value ?? '') === String(key) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select>${help}</label>`;
    }
    if (options.type === 'switch') {
      return `<label class="dwrt-kit-switch qwrt-sheet-switch"><input type="checkbox" data-qwrt-sheet-field="${escapeHtml(name)}" ${value ? 'checked' : ''} ${disabled ? 'disabled' : ''}><span><strong>${escapeHtml(label)}</strong>${options.help ? `<small>${escapeHtml(options.help)}</small>` : ''}</span></label>`;
    }
    return `<label class="dwrt-kit-field ${options.wide ? 'is-wide' : ''}" data-dwrt-component="field"><span data-dwrt-field-label>${escapeHtml(label)}</span><input type="${options.type || 'text'}" data-qwrt-sheet-field="${escapeHtml(name)}" value="${escapeHtml(value ?? '')}" placeholder="${escapeHtml(options.placeholder || '')}" ${attrs}>${help}</label>`;
  }

  function slotSheetMarkup() {
    const draft = state.sheet.draft;
    const isNew = state.sheet.isNew;
    const pathBroken = !modemPathValid(draft.modem_path);
    const apnItems = [['', '手动填写'], ...(state.draft?.apn_profiles || []).map((profile) => [profile.id, `${profile.name} · ${profile.apn || '未填 APN'}`])];
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-qwrt-sheet-close aria-label="关闭槽位编辑"></button><aside class="dwrt-kit-sheet qwrt-sheet is-open" data-dwrt-component="sheet" data-dwrt-surface="stable-glass" data-dwrt-sheet-variant="copilot" data-dwrt-sheet-motion="settled" aria-label="${isNew ? '新增槽位' : '编辑槽位'}"><header class="dwrt-kit-sheet-header"><div><strong>${isNew ? '新增蜂窝槽位' : '编辑蜂窝槽位'}</strong><small>${escapeHtml(clipLabel(draft.name) || '填写 SIM 与拨号参数')}</small></div><button class="dwrt-kit-sheet-close" type="button" data-qwrt-sheet-close aria-label="关闭">${icon('close')}</button></header><div class="dwrt-kit-sheet-body qwrt-sheet-body">${runtimeReady() ? '' : `<div class="qwrt-inline-warning">${icon('info')}<span>ModemManager 缺失，保存会写入配置但不会探测回填运营商、IMEI 与信号。</span></div>`}<section><h3>基本</h3><div class="qwrt-sheet-fields">${sheetField('槽位名称', 'name', draft.name, { wide: true, placeholder: '例如 主卡' })}${sheetField('接口类型', 'dev_type', draft.dev_type, { items: [['unknown', '未指定'], ['pcie', 'PCIe'], ['usb', 'USB'], ['builtin', '板载']] })}${sheetField('排序', 'sort_order', draft.sort_order, { type: 'number', min: 0, max: 999 })}${sheetField('ModemManager 路径', 'modem_path', draft.modem_path, { wide: true, placeholder: '/org/freedesktop/ModemManager1/Modem/0 或 0', help: pathBroken ? '格式无效：只能填 ModemManager 对象路径或纯数字索引，否则后端会拒绝保存。' : '留空则不绑定具体模组，后端不会执行探测。' })}</div>${sheetField('启用该槽位', 'enabled', draft.enabled, { type: 'switch', help: '关闭后该槽位不参与拨号，也不会写入运行配置。' })}</section><section><h3>拨号</h3><div class="qwrt-sheet-fields">${sheetField('套用 APN 档案', '__apply_profile', '', { items: apnItems, help: '选择后会把档案里的 APN、认证与拨号串填入下面的字段。' })}${sheetField('APN', 'apn', draft.apn, { placeholder: '例如 cmnet' })}${sheetField('认证方式', 'auth_type', draft.auth_type, { items: AUTH_TYPES })}${sheetField('用户名', 'username', draft.username)}${sheetField('密码', 'password', draft.password, { type: 'password' })}${sheetField('拨号串', 'dial_num', draft.dial_num, { placeholder: '*99#' })}${sheetField('网络制式', 'network_type', draft.network_type, { items: NETWORK_TYPES })}${sheetField('MTU', 'mTU', draft.mTU, { type: 'number', min: 576, max: 9000 })}${sheetField('SIM PIN', 'pincode', draft.pincode, { type: 'password', placeholder: '无 PIN 可留空' })}${sheetField('备注', 'remark', draft.remark, { wide: true })}</div>${sheetField('允许数据漫游', 'roaming', draft.roaming, { type: 'switch', help: '漫游状态下继续拨号可能产生额外资费。' })}</section></div><footer class="dwrt-kit-sheet-footer"><button class="dwrt-kit-button" data-dwrt-component="button" data-variant="ghost" type="button" data-qwrt-sheet-close>取消</button><button class="dwrt-kit-button" data-dwrt-component="button" data-variant="primary" type="button" data-qwrt-sheet-save ${canWrite() && draft.name.trim() && !pathBroken ? '' : 'disabled'}>${state.saving ? '正在保存' : '保存并应用'}</button></footer></aside>`;
  }

  function apnSheetMarkup() {
    const draft = state.sheet.draft;
    const isNew = state.sheet.isNew;
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-qwrt-sheet-close aria-label="关闭档案编辑"></button><aside class="dwrt-kit-sheet qwrt-sheet is-compact is-open" data-dwrt-component="sheet" data-dwrt-surface="stable-glass" data-dwrt-sheet-variant="copilot" data-dwrt-sheet-motion="settled" aria-label="${isNew ? '新增 APN 档案' : '编辑 APN 档案'}"><header class="dwrt-kit-sheet-header"><div><strong>${isNew ? '新增 APN 档案' : '编辑 APN 档案'}</strong><small>${escapeHtml(clipLabel(draft.name) || '可复用的运营商参数')}</small></div><button class="dwrt-kit-sheet-close" type="button" data-qwrt-sheet-close aria-label="关闭">${icon('close')}</button></header><div class="dwrt-kit-sheet-body qwrt-sheet-body"><section><h3>档案</h3><div class="qwrt-sheet-fields">${sheetField('档案名称', 'name', draft.name, { wide: true, placeholder: '例如 移动 cmnet' })}${sheetField('APN', 'apn', draft.apn, { placeholder: 'cmnet' })}${sheetField('认证方式', 'auth_type', draft.auth_type, { items: AUTH_TYPES })}${sheetField('用户名', 'username', draft.username)}${sheetField('密码', 'password', draft.password, { type: 'password' })}${sheetField('拨号串', 'dial_num', draft.dial_num, { placeholder: '*99#' })}${sheetField('网络制式', 'network_type', draft.network_type, { items: NETWORK_TYPES })}${sheetField('备注', 'remark', draft.remark, { wide: true })}</div></section></div><footer class="dwrt-kit-sheet-footer"><button class="dwrt-kit-button" data-dwrt-component="button" data-variant="ghost" type="button" data-qwrt-sheet-close>取消</button><button class="dwrt-kit-button" data-dwrt-component="button" data-variant="primary" type="button" data-qwrt-sheet-save ${canWrite() && draft.name.trim() ? '' : 'disabled'}>${state.saving ? '正在保存' : '保存档案'}</button></footer></aside>`;
  }

  function sheetMarkup() {
    if (!state.sheet) return '';
    return state.sheet.kind === 'slot' ? slotSheetMarkup() : apnSheetMarkup();
  }

  function panelMarkup() {
    if (state.loading && !state.draft) return `<section class="dwrt-kit-state-panel" data-dwrt-component="state-panel" data-dwrt-state="loading" aria-busy="true"><strong>正在读取蜂窝模组</strong><p>页面结构已就绪，正在读取配置与运行状态。</p></section>`;
    if (!state.draft) return `<section class="dwrt-kit-state-panel" data-dwrt-component="state-panel" data-dwrt-state="error"><strong>无法显示 QWRT 模组管理</strong><p>${escapeHtml(state.error || '后端未返回蜂窝服务配置。')}</p><button class="dwrt-kit-button" type="button" data-qwrt-retry>重试</button></section>`;
    if (state.tab === 'slots') return slotsPanel();
    if (state.tab === 'apn') return apnPanel();
    if (state.tab === 'failover') return failoverPanel();
    if (state.tab === 'sms') return smsPanel();
    return overviewPanel();
  }

  function globalPayload(source) {
    const global = source || state.draft?.global || defaultGlobal();
    return {
      enabled: bool(global.enabled),
      default_slot: firstText(global.default_slot),
      failover_mode: firstText(global.failover_mode, 'none'),
      failover_threshold: number(global.failover_threshold, 3),
      probe_interval: number(global.probe_interval, 60),
      probe_host: firstText(global.probe_host, '8.8.8.8')
    };
  }

  function savebarMarkup() {
    if (!state.dirty) return '';
    const renderer = ui.floatingSavebarMarkup || window.DWRT_UI_KIT?.floatingSavebarMarkup;
    const markup = typeof renderer === 'function' ? renderer({
      visible: true,
      omitWhenHidden: true,
      busy: state.saving,
      disabled: !canWrite() || state.saving,
      message: '蜂窝总控有未保存的更改',
      discardLabel: '放弃',
      saveLabel: '保存并应用',
      busyLabel: '正在保存'
    }) : '';
    return markup.replace('dwrt-kit-savebar', 'dwrt-kit-savebar qwrt-savebar');
  }

  function syncSavebar() {
    const shell = root.querySelector('.qwrt-modules-shell');
    if (!shell) return;
    const current = shell.querySelector('.qwrt-savebar');
    if (!state.dirty) {
      current?.remove();
      return;
    }
    if (!current) shell.insertAdjacentHTML('beforeend', savebarMarkup());
  }

  function confirmationMarkup() {
    if (!state.confirmation) return '';
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    return typeof renderer === 'function' ? renderer({
      id: 'qwrt-confirm',
      action: state.confirmation.action,
      tone: 'warning',
      title: state.confirmation.title,
      description: state.confirmation.description,
      cancelLabel: '取消',
      confirmLabel: state.saving ? '正在执行' : state.confirmation.confirmLabel,
      disabled: state.saving,
      icon: icon('warning')
    }) : '';
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
    if (!root || !state.mounted) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'qwrt-modules-route-host');
    target.innerHTML = `<section class="qwrt-modules-shell" data-qwrt-version="${VERSION}">${pageToolbar()}${overviewCardsRow()}<main class="qwrt-modules-main">${noticeMarkup()}${panelMarkup()}</main>${savebarMarkup()}${sheetMarkup()}${confirmationMarkup()}</section>`;
    ui.mountAll?.(target);
    ui.scheduleAdaptiveForegroundSample?.(20, target);
  }

  function markDirty() {
    state.dirty = JSON.stringify(globalPayload()) !== JSON.stringify(globalPayload(state.initial?.global));
    state.notice = '';
  }

  function setPath(path, value) {
    const parts = String(path).split('.');
    let target = state.draft;
    for (let index = 0; index < parts.length - 1; index += 1) target = target[parts[index]];
    const fieldName = parts.at(-1);
    if (fieldName === 'enabled') target[fieldName] = bool(value);
    else if (['failover_threshold', 'probe_interval'].includes(fieldName)) target[fieldName] = number(value);
    else target[fieldName] = value;
  }

  async function saveGlobal() {
    if (!canWrite() || !state.dirty || state.saving) return;
    const payload = globalPayload();
    if (payload.failover_mode === 'probe' && !payload.probe_host.trim()) {
      state.error = '选择探测切换时必须填写探测目标';
      render();
      return;
    }
    if (payload.probe_interval < 5 || payload.probe_interval > 3600) {
      state.error = '探测间隔必须在 5 到 3600 秒之间';
      render();
      return;
    }
    state.saving = true;
    state.error = '';
    render();
    try {
      const result = await requestJson('/api/v1/services/cellular', { method: 'PUT', body: JSON.stringify(payload) });
      state.notice = result?.applied === false ? '配置已保存，但后端回报应用未成功，请复查运行态。' : '蜂窝总控已保存并写入运行配置。';
      state.dirty = false;
      state.initial = clone(state.draft);
      await load(true);
    } catch (error) {
      state.error = firstText(error?.message, '保存蜂窝总控失败');
    } finally {
      state.saving = false;
      render();
    }
  }

  async function saveSheet() {
    if (!state.sheet || !canWrite() || state.saving) return;
    const draft = state.sheet.draft;
    if (!String(draft.name || '').trim()) {
      state.error = '名称不能为空';
      render();
      return;
    }
    const slotMode = state.sheet.kind === 'slot';
    if (slotMode && !modemPathValid(draft.modem_path)) {
      state.error = 'ModemManager 路径格式无效，后端会拒绝保存';
      render();
      return;
    }
    state.saving = true;
    state.error = '';
    render();
    try {
      const url = slotMode ? '/api/v1/services/cellular/slots' : '/api/v1/services/cellular/apn-profiles';
      const body = slotMode ? {
        ...(state.sheet.isNew ? {} : { id: draft.id }),
        name: String(draft.name).trim(),
        modem_path: String(draft.modem_path || '').trim(),
        dev_type: draft.dev_type || 'unknown',
        enabled: bool(draft.enabled),
        apn: draft.apn || '',
        auth_type: draft.auth_type || 'none',
        username: draft.username || '',
        password: draft.password || '',
        pincode: draft.pincode || '',
        network_type: draft.network_type || 'auto',
        roaming: bool(draft.roaming),
        mTU: number(draft.mTU, 1500),
        dial_num: draft.dial_num || '*99#',
        remark: draft.remark || '',
        sort_order: number(draft.sort_order)
      } : {
        ...(state.sheet.isNew ? {} : { id: draft.id }),
        name: String(draft.name).trim(),
        apn: draft.apn || '',
        auth_type: draft.auth_type || 'none',
        username: draft.username || '',
        password: draft.password || '',
        dial_num: draft.dial_num || '*99#',
        network_type: draft.network_type || 'auto',
        remark: draft.remark || ''
      };
      const result = await requestJson(url, { method: 'PUT', body: JSON.stringify(body) });
      state.notice = slotMode
        ? (result?.applied === false ? '槽位已保存，但后端回报应用未成功，请复查运行态。' : '槽位已保存并写入运行配置。')
        : 'APN 档案已保存。档案本身不触发运行配置应用。';
      state.sheet = null;
      await load(true);
    } catch (error) {
      state.error = firstText(error?.message, '保存失败');
    } finally {
      state.saving = false;
      render();
    }
  }

  async function runDelete() {
    const target = state.confirmation;
    if (!target || !canWrite() || state.saving) return;
    state.saving = true;
    state.error = '';
    render();
    try {
      const url = target.kind === 'slot'
        ? `/api/v1/services/cellular/slots/${encodeURIComponent(target.id)}`
        : `/api/v1/services/cellular/apn-profiles/${encodeURIComponent(target.id)}`;
      await requestJson(url, { method: 'DELETE' });
      state.notice = target.kind === 'slot' ? '槽位已删除并重新写入运行配置。' : 'APN 档案已删除。';
      state.confirmation = null;
      await load(true);
    } catch (error) {
      state.error = firstText(error?.message, '删除失败');
    } finally {
      state.saving = false;
      render();
    }
  }

  function newSlotDraft() {
    const slots = state.draft?.slots || [];
    return { id: '', name: `模组 ${slots.length + 1}`, modem_path: '', dev_type: 'unknown', enabled: true, apn: '', auth_type: 'none', username: '', password: '', pincode: '', network_type: 'auto', roaming: false, mTU: 1500, dial_num: '*99#', remark: '', sort_order: slots.length };
  }

  function newProfileDraft() {
    return { id: '', name: '', apn: '', auth_type: 'none', username: '', password: '', dial_num: '*99#', network_type: 'auto', remark: '' };
  }

  function onClick(event) {
    if (event.target.closest('[data-qwrt-retry]')) { load(true); return; }
    const tab = event.target.closest('[data-qwrt-tab]');
    if (tab) {
      state.tab = tab.dataset.qwrtTab;
      state.error = '';
      render();
      return;
    }
    if (event.target.closest('[data-dwrt-savebar-discard]')) {
      state.draft.global = clone(state.initial?.global || defaultGlobal());
      state.dirty = false;
      state.error = '';
      state.notice = '';
      render();
      return;
    }
    if (event.target.closest('[data-dwrt-savebar-save]')) { saveGlobal(); return; }
    if (event.target.closest('[data-qwrt-slot-new]')) {
      state.sheet = { kind: 'slot', isNew: true, draft: newSlotDraft() };
      render();
      return;
    }
    if (event.target.closest('[data-qwrt-apn-new]')) {
      state.sheet = { kind: 'apn', isNew: true, draft: newProfileDraft() };
      render();
      return;
    }
    const slotEdit = event.target.closest('[data-qwrt-slot-edit]');
    if (slotEdit) {
      const slot = (state.draft?.slots || []).find((item) => item.id === slotEdit.dataset.qwrtSlotEdit);
      if (slot) {
        state.sheet = { kind: 'slot', isNew: false, draft: clone(slot) };
        render();
      }
      return;
    }
    const apnEdit = event.target.closest('[data-qwrt-apn-edit]');
    if (apnEdit) {
      const profile = (state.draft?.apn_profiles || []).find((item) => item.id === apnEdit.dataset.qwrtApnEdit);
      if (profile) {
        state.sheet = { kind: 'apn', isNew: false, draft: clone(profile) };
        render();
      }
      return;
    }
    const slotDelete = event.target.closest('[data-qwrt-slot-delete]');
    if (slotDelete) {
      const slot = (state.draft?.slots || []).find((item) => item.id === slotDelete.dataset.qwrtSlotDelete);
      if (slot) {
        state.confirmation = { action: 'delete', kind: 'slot', id: slot.id, title: `删除槽位「${slot.name}」`, description: '删除后该槽位的 SIM 与拨号参数会从数据库移除，后端会立即重写蜂窝运行配置。此操作不可撤销。', confirmLabel: '确认删除' };
        render();
      }
      return;
    }
    const apnDelete = event.target.closest('[data-qwrt-apn-delete]');
    if (apnDelete) {
      const profile = (state.draft?.apn_profiles || []).find((item) => item.id === apnDelete.dataset.qwrtApnDelete);
      if (profile) {
        state.confirmation = { action: 'delete', kind: 'apn', id: profile.id, title: `删除档案「${profile.name}」`, description: '删除后该 APN 档案不再可供槽位套用。已经写入槽位的参数不受影响。', confirmLabel: '确认删除' };
        render();
      }
      return;
    }
    if (event.target.closest('[data-qwrt-sheet-close]')) {
      state.sheet = null;
      state.error = '';
      render();
      return;
    }
    if (event.target.closest('[data-qwrt-sheet-save]')) { saveSheet(); return; }
    if (event.target.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]')) {
      state.confirmation = null;
      render();
      return;
    }
    if (event.target.closest('[data-dwrt-confirm-accept]') && state.confirmation?.action === 'delete') runDelete();
  }

  function applyProfileToSheet(profileId) {
    const profile = (state.draft?.apn_profiles || []).find((item) => item.id === profileId);
    if (!profile || !state.sheet) return;
    Object.assign(state.sheet.draft, {
      apn: profile.apn,
      auth_type: profile.auth_type,
      username: profile.username,
      password: profile.password,
      dial_num: profile.dial_num,
      network_type: profile.network_type
    });
    render();
  }

  function onChange(event) {
    const sheetControl = event.target.closest('[data-qwrt-sheet-field]');
    if (sheetControl && state.sheet) {
      const key = sheetControl.dataset.qwrtSheetField;
      if (key === '__apply_profile') {
        if (sheetControl.value) applyProfileToSheet(sheetControl.value);
        return;
      }
      state.sheet.draft[key] = sheetControl.type === 'checkbox'
        ? sheetControl.checked
        : ['mTU', 'sort_order'].includes(key) ? number(sheetControl.value) : sheetControl.value;
      render();
      return;
    }
    const fieldControl = event.target.closest('[data-qwrt-field]');
    if (fieldControl) {
      setPath(fieldControl.dataset.qwrtField, fieldControl.type === 'checkbox' ? fieldControl.checked : fieldControl.value);
      markDirty();
      render();
    }
  }

  function onInput(event) {
    const control = event.target.closest('input[data-qwrt-field], input[data-qwrt-sheet-field]');
    if (!control || control.type === 'checkbox' || control.type === 'number') return;
    if (control.dataset.qwrtSheetField && state.sheet) {
      state.sheet.draft[control.dataset.qwrtSheetField] = control.value;
      return;
    }
    if (control.dataset.qwrtField) {
      setPath(control.dataset.qwrtField, control.value);
      markDirty();
      syncSavebar();
    }
  }

  root.addEventListener('click', onClick);
  root.addEventListener('change', onChange);
  root.addEventListener('input', onInput);
  stage?.classList.add('is-qwrt-modules');
  if (context.signal) context.signal.addEventListener('abort', () => { state.mounted = false; state.seq += 1; }, { once: true });
  render();
  load();

  /*
   * 手动刷新按钮按用户第 9 条删除，补一条可见性受控的轮询代替；
   * 有未保存草稿、抽屉或确认弹窗时跳过，避免刷掉用户填的内容。
   */
  state.pollTimer = window.setInterval(() => {
    if (!state.mounted || document.hidden) return;
    if (state.loading || state.refreshing || state.saving) return;
    if (state.dirty || state.sheet || state.confirmation) return;
    load(true);
  }, 15000);

  return () => {
    state.mounted = false;
    state.seq += 1;
    window.clearInterval(state.pollTimer);
    root.removeEventListener('click', onClick);
    root.removeEventListener('change', onChange);
    root.removeEventListener('input', onInput);
    root.classList.remove('qwrt-modules-route-host');
    stage?.classList.remove('is-qwrt-modules');
    const savebar = root.querySelector('.qwrt-savebar');
    if (savebar) savebar.remove();
  };
}
