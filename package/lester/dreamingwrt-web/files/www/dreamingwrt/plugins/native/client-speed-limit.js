export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const VERSION = '20260802-ui-batch-01';
  const stage = root?.closest('.console-stage');
  const WEEKDAYS = ['一', '二', '三', '四', '五', '六', '日'];

  const state = {
    mounted: true,
    seq: 0,
    pollTimer: 0,
    loading: true,
    refreshing: false,
    saving: false,
    clients: [],
    capabilities: {},
    rules: [],
    query: '',
    filter: 'all',
    error: '',
    notice: '',
    noticeTone: '',
    drawer: false,
    editor: {},
    confirmDelete: false
  };

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

  function bool(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') return !['0', 'false', 'off', 'no', 'disabled'].includes(value.toLowerCase());
    return Boolean(value);
  }

  function asArray(value) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of ['clients', 'rules', 'control_rules', 'items', 'rows', 'list', 'results']) if (Array.isArray(value[key])) return value[key];
    return [];
  }

  function unwrap(value) {
    let current = value;
    for (let depth = 0; depth < 4; depth += 1) {
      if (!current || typeof current !== 'object' || Array.isArray(current)) break;
      if (current.data && typeof current.data === 'object') current = current.data;
      else if (current.body && typeof current.body === 'object') current = current.body;
      else break;
    }
    return current || {};
  }

  function clone(value) {
    try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value || {})); }
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
    const payload = unwrap(json);
    const code = Number(json?.code);
    const businessFailed = Number.isFinite(code) && ![0, 200, 2000].includes(code);
    if (!response.ok || json?.ok === false || payload?.ok === false || businessFailed) {
      const error = new Error(firstText(payload?.message, payload?.error, json?.message, json?.error, `HTTP ${response.status}`));
      error.status = response.status;
      error.payload = json;
      throw error;
    }
    return payload;
  }

  function normalizeMac(value) {
    const compact = String(value || '').trim().replace(/[^0-9a-f]/gi, '').toUpperCase();
    return compact.length === 12 ? compact.match(/.{2}/g).join(':') : '';
  }

  function normalizeClient(item = {}, index = 0) {
    const fingerprint = item.fingerprint && typeof item.fingerprint === 'object' ? item.fingerprint : {};
    const mac = normalizeMac(firstText(item.mac, item.client_mac, item.hwaddr));
    return {
      ...item,
      id: firstText(item.id, item.client_id, mac, `client-${index + 1}`),
      mac,
      name: firstText(item.display_name, item.alias, item.name, item.hostname, fingerprint.model, mac, '未命名终端'),
      ip: firstText(item.ip, item.ipv4, item.ipaddr, item.client_ip),
      online: bool(item.online, bool(item.active, false))
    };
  }

  function daysFromRule(rule = {}) {
    const candidate = rule.days_array || rule.days || rule.days_text || rule.days_json;
    if (Array.isArray(candidate)) return candidate.map(firstText).filter(Boolean);
    const text = firstText(candidate);
    if (text.startsWith('[')) {
      try {
        const parsed = JSON.parse(text);
        if (Array.isArray(parsed)) return parsed.map(firstText).filter(Boolean);
      } catch (_) {}
    }
    return text ? text.split(/[\s,，、;；|]+/).map((item) => item.trim()).filter(Boolean) : WEEKDAYS.slice();
  }

  function writableCapabilities(capabilities = {}) {
    return capabilities.control_rule_crud === true
      && capabilities.client_control_rule_api === true
      && capabilities.client_control_fail_closed === true
      && capabilities.client_control_rate_limit === true;
  }

  function normalizeRule(rule = {}, client = {}, capabilities = {}, index = 0) {
    const id = firstText(rule.id, rule.rule_id, rule.uuid, `${client.mac}-${index}`);
    return {
      ...rule,
      id,
      mac: normalizeMac(firstText(rule.mac, rule.client_mac, client.mac)),
      clientName: client.name,
      clientIp: client.ip,
      enabled: bool(rule.enabled, true),
      name: firstText(rule.name, rule.rule_name, id),
      control_type: firstText(rule.control_type, rule.type, 'IP限速'),
      schedule_mode: firstText(rule.schedule_mode, 'week'),
      days: daysFromRule(rule),
      start_time: firstText(rule.start_time, '00:00'),
      end_time: firstText(rule.end_time, '23:59'),
      limit_mode: firstText(rule.limit_mode, '独立限速'),
      up_limit: Number(rule.up_limit ?? 0),
      up_unit: firstText(rule.up_unit, 'KB/s'),
      down_limit: Number(rule.down_limit ?? 0),
      down_unit: firstText(rule.down_unit, 'KB/s'),
      line: firstText(rule.line),
      protocol: firstText(rule.protocol, '任意'),
      note: firstText(rule.note, rule.remark),
      runtime_apply: bool(rule.runtime_apply, bool(rule.runtime_applied, false)),
      apply_state: firstText(rule.apply_state, 'unknown'),
      apply_reason: firstText(rule.apply_reason, rule.runtime_reason),
      runtime_warning: firstText(rule.runtime_warning),
      runtime_precision: firstText(rule.runtime_match_precision, rule.runtime_precision, rule.precision),
      writable: writableCapabilities(capabilities)
    };
  }

  function icon(name) {
    const paths = {
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      edit: '<path d="m4 20 4.2-1 10.9-10.9a2 2 0 0 0-2.8-2.8L5.4 16.2 4 20Z"></path>',
      trash: '<path d="M4 7h16M9 7V4h6v3m-9 0 1 13h10l1-13M10 11v5m4-5v5"></path>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.edit}</svg>`;
  }

  function statusBadge(label, tone) {
    return ui.statusBadgeMarkup?.(label, tone) || `<span class="client-speed-status is-${escapeHtml(tone)}">${escapeHtml(label)}</span>`;
  }

  function runtimeStatus(rule) {
    if (!rule.enabled) return { label: '已停用', tone: 'error', detail: '规则保留但不进入运行态' };
    if (rule.runtime_apply) return { label: '运行中', tone: 'success', detail: firstText(rule.runtime_precision, 'client_mac_exact') };
    if (/fail|error|rollback/i.test(rule.apply_state)) return { label: '应用失败', tone: 'error', detail: firstText(rule.apply_reason, '后端未返回原因') };
    if (/queue|pending|draft|schedule/i.test(`${rule.apply_state} ${rule.apply_reason}`)) return { label: '等待调度', tone: 'warning', detail: firstText(rule.apply_reason, '等待计划窗口') };
    return { label: '未应用', tone: 'warning', detail: firstText(rule.apply_reason, '无运行态证明') };
  }

  function rateText(value, unit) {
    const number = Number(value) || 0;
    return number > 0 ? `${number} ${firstText(unit, 'KB/s')}` : '不限';
  }

  function scheduleText(rule) {
    const mode = String(rule.schedule_mode || '').toLowerCase();
    if (['always', 'all'].includes(mode) || rule.schedule_mode === '永久') return '始终';
    const dayText = mode === 'daily' || rule.schedule_mode === '每天' ? '每天' : (rule.days || []).join('、') || '每天';
    return `${dayText} ${rule.start_time}-${rule.end_time}`;
  }

  function filteredRules() {
    const query = state.query.trim().toLowerCase();
    return state.rules.filter((rule) => {
      const runtime = runtimeStatus(rule);
      if (state.filter === 'enabled' && !rule.enabled) return false;
      if (state.filter === 'disabled' && rule.enabled) return false;
      if (state.filter === 'attention' && runtime.tone === 'success') return false;
      if (!query) return true;
      return [rule.name, rule.mac, rule.clientName, rule.clientIp, rule.protocol, rule.note, rule.apply_reason]
        .filter(Boolean).join(' ').toLowerCase().includes(query);
    });
  }

  function toolbarMarkup() {
    const canCreate = writableCapabilities(state.capabilities) && state.clients.length > 0;
    const filters = [['all', '全部'], ['enabled', '已启用'], ['disabled', '已停用'], ['attention', '需关注']];
    return `<header class="policy-toolbar user-auth-toolbar client-speed-toolbar"><div class="user-auth-toolbar-leading"><div class="user-auth-segmented">${filters.map(([id, label]) => `<button type="button" data-client-speed-filter="${id}" class="${state.filter === id ? 'is-active' : ''}">${label}</button>`).join('')}</div><label class="policy-search policy-search-main" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-client-speed-search value="${escapeHtml(state.query)}" placeholder="搜索终端、MAC、规则或备注"></label></div><div class="policy-toolbar-actions"><button class="policy-create-button" type="button" data-client-speed-create ${canCreate ? '' : 'disabled'}>${icon('plus')}<span>新建限速</span></button></div></header>`;
  }

  function tableMarkup() {
    const rows = filteredRules();
    const body = state.loading
      ? '<tr><td colspan="8" class="dwrt-kit-table-empty">正在读取终端限速规则</td></tr>'
      : rows.length ? rows.map((rule) => {
        const runtime = runtimeStatus(rule);
        return `<tr data-client-speed-rule="${escapeHtml(rule.id)}"><td><div class="client-speed-client"><strong>${escapeHtml(rule.clientName || '未命名终端')}</strong><span>${escapeHtml(rule.clientIp || '--')} · <code>${escapeHtml(rule.mac)}</code></span></div></td><td><strong>${escapeHtml(rule.name)}</strong>${rule.note ? `<small>${escapeHtml(rule.note)}</small>` : ''}</td><td>${escapeHtml(scheduleText(rule))}</td><td>${escapeHtml(rateText(rule.up_limit, rule.up_unit))}</td><td>${escapeHtml(rateText(rule.down_limit, rule.down_unit))}</td><td>${escapeHtml(rule.protocol || '任意')}</td><td><div class="client-speed-runtime">${statusBadge(runtime.label, runtime.tone)}<small title="${escapeHtml(runtime.detail)}">${escapeHtml(runtime.detail)}</small></div></td><td><div class="user-auth-row-actions"><button class="user-auth-icon-button" type="button" data-client-speed-toggle="${escapeHtml(rule.id)}" ${rule.writable && !state.saving ? '' : 'disabled'} aria-label="${rule.enabled ? '停用' : '启用'}" data-dwrt-tooltip="${rule.enabled ? '停用' : '启用'}">${rule.enabled ? 'Ⅱ' : '▶'}</button><button class="user-auth-icon-button" type="button" data-client-speed-edit="${escapeHtml(rule.id)}" ${rule.writable && !state.saving ? '' : 'disabled'} aria-label="编辑" data-dwrt-tooltip="编辑">${icon('edit')}</button><button class="user-auth-icon-button danger" type="button" data-client-speed-delete="${escapeHtml(rule.id)}" ${rule.writable && !state.saving ? '' : 'disabled'} aria-label="删除" data-dwrt-tooltip="删除">${icon('trash')}</button></div></td></tr>`;
      }).join('') : '<tr><td colspan="8" class="dwrt-kit-table-empty">暂无终端限速规则</td></tr>';
    return `<section class="user-auth-main-surface user-auth-table-card client-speed-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface" data-client-speed-table><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>终端限速规则</strong><span>按终端 MAC 在 LAN 桥接数据面执行独立限速</span></div><span class="dwrt-kit-table-count">${rows.length} 条</span></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table user-auth-table client-speed-table"><thead><tr><th>终端</th><th>规则</th><th>计划</th><th>上行</th><th>下行</th><th>协议</th><th>运行状态</th><th>操作</th></tr></thead><tbody>${body}</tbody></table></div></section>`;
  }

  function noticeMarkup() {
    const message = state.notice || state.error;
    if (!message) return '';
    return `<div class="user-auth-notice is-${escapeHtml(state.notice ? state.noticeTone || 'ok' : 'warning')}" data-client-speed-notice>${escapeHtml(message)}</div>`;
  }

  function editorField(label, name, value, options = {}) {
    const disabled = options.disabled ? 'disabled' : '';
    let control = '';
    if (options.type === 'select') {
      control = `<select data-client-speed-field="${name}" ${disabled}>${(options.options || []).map(([id, text]) => `<option value="${escapeHtml(id)}" ${String(value) === String(id) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select>`;
    } else if (options.type === 'textarea') {
      control = `<textarea data-client-speed-field="${name}" ${disabled}>${escapeHtml(value || '')}</textarea>`;
    } else {
      control = `<input data-client-speed-field="${name}" type="${escapeHtml(options.type || 'text')}" value="${escapeHtml(value ?? '')}" ${options.min !== undefined ? `min="${options.min}"` : ''} ${options.max !== undefined ? `max="${options.max}"` : ''} ${disabled}>`;
    }
    return `<label class="user-auth-field ${options.wide ? 'is-wide' : ''}"><span>${escapeHtml(label)}</span>${control}${options.help ? `<small>${escapeHtml(options.help)}</small>` : ''}</label>`;
  }

  function clientOptions() {
    if (!writableCapabilities(state.capabilities)) return [];
    return state.clients.map((client) => [client.mac, `${client.name} · ${client.ip || client.mac}`]);
  }

  function drawerMarkup() {
    if (!state.drawer) return '';
    const editor = state.editor;
    const editing = Boolean(editor.id);
    const selectedDays = new Set(editor.days || WEEKDAYS);
    const showDays = !['always', 'all', 'daily'].includes(String(editor.schedule_mode || '').toLowerCase());
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-client-speed-close aria-label="关闭终端限速编辑"></button><aside class="user-auth-drawer client-speed-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" aria-label="${editing ? '编辑终端限速' : '新建终端限速'}"><header class="dwrt-kit-sheet-header"><div><span>CLIENT RATE LIMIT</span><strong>${editing ? '编辑终端限速' : '新建终端限速'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-client-speed-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body user-auth-drawer-body"><div class="user-auth-drawer-section"><strong>规则状态</strong><label class="user-auth-setting-row"><span><strong>启用规则</strong><small>保存后由终端管控调度器应用并回读运行状态</small></span><span class="user-auth-switch"><input type="checkbox" data-client-speed-field="enabled" ${editor.enabled !== false ? 'checked' : ''}><i></i></span></label></div><div class="user-auth-form-grid">${editorField('终端', 'mac', editor.mac, { type: 'select', options: clientOptions(), disabled: editing, wide: true })}${editorField('规则名称', 'name', editor.name, { wide: true })}${editorField('计划模式', 'schedule_mode', editor.schedule_mode, { type: 'select', options: [['always', '始终'], ['daily', '每天'], ['week', '按周循环'], ['range', '指定星期与时间段']] })}${editorField('协议', 'protocol', editor.protocol, { type: 'select', options: [['任意', '任意'], ['TCP', 'TCP'], ['UDP', 'UDP'], ['ICMP', 'ICMP'], ['ICMPv6', 'ICMPv6']] })}</div>${showDays ? `<div class="client-speed-weekdays"><span>生效星期</span><div>${WEEKDAYS.map((day) => `<label class="${selectedDays.has(day) ? 'is-active' : ''}"><input type="checkbox" data-client-speed-day="${day}" ${selectedDays.has(day) ? 'checked' : ''}>${day}</label>`).join('')}</div></div>` : ''}<div class="user-auth-form-grid">${editor.schedule_mode !== 'always' ? `${editorField('开始时间', 'start_time', editor.start_time, { type: 'time' })}${editorField('结束时间', 'end_time', editor.end_time, { type: 'time' })}` : ''}${editorField('上行限速', 'up_limit', editor.up_limit, { type: 'number', min: 0, help: '0 表示不限制' })}${editorField('上行单位', 'up_unit', editor.up_unit, { type: 'select', options: [['KB/s', 'KB/s'], ['MB/s', 'MB/s'], ['Kbps', 'Kbps'], ['Mbps', 'Mbps']] })}${editorField('下行限速', 'down_limit', editor.down_limit, { type: 'number', min: 0, help: '0 表示不限制' })}${editorField('下行单位', 'down_unit', editor.down_unit, { type: 'select', options: [['KB/s', 'KB/s'], ['MB/s', 'MB/s'], ['Kbps', 'Kbps'], ['Mbps', 'Mbps']] })}${editorField('备注', 'note', editor.note, { type: 'textarea', wide: true })}</div><div class="user-auth-capability">运行范围为终端 MAC + 可选 L4 协议，当前统一作用于 LAN 桥接流量。线路维度、共享限速和应用级管控没有数据面合同，因此本页不提供这些选项。</div>${state.notice ? noticeMarkup() : ''}</div><footer class="dwrt-kit-sheet-footer user-auth-drawer-footer"><span></span><div><button class="policy-secondary" type="button" data-client-speed-close>取消</button><button class="policy-primary" type="button" data-client-speed-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存规则'}</button></div></footer></aside>`;
  }

  function confirmationMarkup() {
    if (!state.confirmDelete) return '';
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    return typeof renderer === 'function' ? renderer({
      id: 'client-speed-delete-confirmation',
      action: 'delete-client-speed-rule',
      tone: 'danger',
      title: '删除终端限速规则',
      description: `规则“${firstText(state.confirmDelete.name, state.confirmDelete.id)}”将从配置与终端运行态中删除。`,
      cancelLabel: '取消',
      confirmLabel: state.saving ? '正在删除' : '确认删除',
      disabled: state.saving
    }) : '';
  }

  function render() {
    if (!root) return;
    root.hidden = false;
    root.classList.add('route-workspace', 'user-authentication-route-host', 'client-speed-limit-route-host');
    root.innerHTML = `<section class="user-auth-shell client-speed-shell" data-client-speed-version="${VERSION}">${toolbarMarkup()}<main class="user-auth-workbench">${noticeMarkup()}${tableMarkup()}</main>${drawerMarkup()}${confirmationMarkup()}</section>`;
    ui.mountAll?.(root);
  }

  function patchTable() {
    const current = root?.querySelector('[data-client-speed-table]');
    if (!current) { render(); return; }
    const scroll = current.querySelector('.dwrt-kit-table-scroll');
    const position = { top: scroll?.scrollTop || 0, left: scroll?.scrollLeft || 0 };
    const template = document.createElement('template');
    template.innerHTML = tableMarkup();
    current.replaceWith(template.content.firstElementChild);
    const next = root.querySelector('[data-client-speed-table] .dwrt-kit-table-scroll');
    if (next) { next.scrollTop = position.top; next.scrollLeft = position.left; }
    ui.mountAll?.(root.querySelector('[data-client-speed-table]'));
  }

  async function load(background = false) {
    const seq = ++state.seq;
    state.error = '';
    state.notice = '';
    state.loading = !background;
    state.refreshing = background;
    render();
    try {
      const [rulesResult, clientsResult] = await Promise.allSettled([
        requestJson('/api/v1/client_control_rules'),
        requestJson('/api/v1/clients')
      ]);
      if (!state.mounted || seq !== state.seq) return;
      if (rulesResult.status === 'rejected') throw rulesResult.reason;
      const rulesPayload = rulesResult.value || {};
      const rawRules = asArray(rulesPayload);
      state.clients = clientsResult.status === 'fulfilled'
        ? asArray(clientsResult.value).map(normalizeClient).filter((client) => client.mac)
        : [];
      const clientsByMac = new Map(state.clients.map((client) => [client.mac, client]));
      state.capabilities = rulesPayload.capabilities && typeof rulesPayload.capabilities === 'object'
        ? rulesPayload.capabilities
        : (rawRules.find((rule) => rule?.capabilities)?.capabilities || {});
      state.rules = rawRules.map((rule, index) => {
        const mac = normalizeMac(firstText(rule.mac, rule.client_mac));
        const client = clientsByMac.get(mac) || {
          mac,
          name: firstText(rule.client_name, rule.display_name, rule.hostname, mac, '未命名终端'),
          ip: firstText(rule.client_ip, rule.ip, rule.ipv4)
        };
        return normalizeRule(rule, client, state.capabilities, index);
      });
      state.loading = false;
      state.refreshing = false;
      if (clientsResult.status === 'rejected') {
        state.notice = '终端身份列表读取失败，现有规则暂按 MAC 显示。';
        state.noticeTone = 'warning';
      }
      render();
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      state.capabilities = {};
      state.rules = [];
      state.error = [404, 405].includes(Number(error.status))
        ? '终端限速规则列表接口未开放。后端需提供 GET /api/v1/client_control_rules；页面不会逐台读取终端详情。'
        : `读取终端限速规则失败：${firstText(error.message, '未知错误')}`;
      render();
    }
  }

  function newEditor(rule = null) {
    const firstClient = clientOptions()[0]?.[0] || '';
    state.editor = rule ? clone(rule) : {
      id: '', mac: firstClient, enabled: true, control_type: 'IP限速', name: '', schedule_mode: 'week',
      days: WEEKDAYS.slice(), start_time: '00:00', end_time: '23:59', limit_mode: '独立限速',
      up_limit: 0, up_unit: 'KB/s', down_limit: 0, down_unit: 'KB/s', line: '', protocol: '任意', note: ''
    };
    state.drawer = true;
    state.notice = '';
    render();
  }

  function editorPayload() {
    const editor = clone(state.editor);
    return {
      ...(editor.id ? { id: editor.id } : {}),
      mac: normalizeMac(editor.mac),
      enabled: editor.enabled !== false,
      control_type: 'IP限速',
      name: firstText(editor.name),
      schedule_mode: firstText(editor.schedule_mode, 'week'),
      days: ['always', 'daily'].includes(editor.schedule_mode) ? WEEKDAYS.slice() : (editor.days || []),
      start_time: editor.schedule_mode === 'always' ? '00:00' : firstText(editor.start_time, '00:00'),
      end_time: editor.schedule_mode === 'always' ? '23:59' : firstText(editor.end_time, '23:59'),
      limit_mode: '独立限速',
      up_limit: Number(editor.up_limit || 0),
      up_unit: firstText(editor.up_unit, 'KB/s'),
      down_limit: Number(editor.down_limit || 0),
      down_unit: firstText(editor.down_unit, 'KB/s'),
      line: '',
      protocol: firstText(editor.protocol, '任意'),
      note: firstText(editor.note)
    };
  }

  function validation(payload) {
    if (!payload.mac) return '请选择具有终端管控能力的终端。';
    if (!payload.name) return '请输入规则名称。';
    if (!['IP限速'].includes(payload.control_type) || payload.limit_mode !== '独立限速' || payload.line) return '当前只支持终端 MAC 独立限速。';
    if (!['任意', 'TCP', 'UDP', 'ICMP', 'ICMPv6'].includes(payload.protocol)) return '请选择后端支持的协议。';
    if (payload.up_limit < 0 || payload.down_limit < 0) return '限速值不能小于 0。';
    if (!payload.days.length) return '请至少选择一个生效星期。';
    return '';
  }

  async function saveRule() {
    if (state.saving) return;
    const payload = editorPayload();
    const message = validation(payload);
    if (message) { state.notice = message; state.noticeTone = 'warning'; render(); return; }
    state.saving = true;
    render();
    try {
      await requestJson(payload.id ? '/api/v1/client_control_rule/update' : '/api/v1/client_control_rule', { method: 'POST', body: JSON.stringify(payload) });
      state.saving = false;
      state.drawer = false;
      state.notice = '规则已保存，运行状态将按后端回读结果显示。';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `保存失败：${firstText(error.message, '后端未接受规则')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  async function toggleRule(rule) {
    if (!rule?.writable || state.saving) return;
    state.saving = true;
    render();
    try {
      await requestJson('/api/v1/client_control_rule/toggle', { method: 'POST', body: JSON.stringify({ id: rule.id, mac: rule.mac, enabled: !rule.enabled }) });
      state.saving = false;
      state.notice = rule.enabled ? '规则已停用。' : '规则已启用，运行状态将按调度结果显示。';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `操作失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  async function deleteRule() {
    const rule = state.confirmDelete;
    if (!rule?.writable || state.saving) return;
    state.saving = true;
    render();
    try {
      await requestJson('/api/v1/client_control_rule/delete', { method: 'POST', body: JSON.stringify({ id: rule.id, mac: rule.mac }) });
      state.saving = false;
      state.confirmDelete = false;
      state.notice = '终端限速规则已删除。';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `删除失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  function findRule(id) {
    return state.rules.find((rule) => String(rule.id) === String(id));
  }

  function onClick(event) {
    if (event.target.closest('[data-client-speed-close]')) { state.drawer = false; state.editor = {}; state.notice = ''; render(); return; }
    if (event.target.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]')) { state.confirmDelete = false; render(); return; }
    if (event.target.closest('[data-dwrt-confirm-accept]')) { deleteRule(); return; }
    if (event.target.closest('[data-client-speed-create]')) { newEditor(); return; }
    if (event.target.closest('[data-client-speed-save]')) { saveRule(); return; }
    const filter = event.target.closest('[data-client-speed-filter]');
    if (filter) { state.filter = filter.dataset.clientSpeedFilter; patchTable(); root.querySelectorAll('[data-client-speed-filter]').forEach((button) => button.classList.toggle('is-active', button === filter)); return; }
    const toggle = event.target.closest('[data-client-speed-toggle]');
    if (toggle) { toggleRule(findRule(toggle.dataset.clientSpeedToggle)); return; }
    const edit = event.target.closest('[data-client-speed-edit]');
    if (edit) { newEditor(findRule(edit.dataset.clientSpeedEdit)); return; }
    const remove = event.target.closest('[data-client-speed-delete]');
    if (remove) { state.confirmDelete = findRule(remove.dataset.clientSpeedDelete) || false; render(); }
  }

  function updateEditor(target) {
    const key = target.dataset.clientSpeedField;
    if (!key) return;
    state.editor[key] = target.type === 'checkbox' ? target.checked : target.type === 'number' ? Number(target.value || 0) : target.value;
    if (key === 'schedule_mode') render();
  }

  function onInput(event) {
    const search = event.target.closest('[data-client-speed-search]');
    if (search) { state.query = search.value; patchTable(); return; }
    const field = event.target.closest('[data-client-speed-field]');
    if (field && !['checkbox', 'radio'].includes(field.type) && field.tagName !== 'SELECT') updateEditor(field);
  }

  function onChange(event) {
    const day = event.target.closest('[data-client-speed-day]');
    if (day) {
      const days = new Set(state.editor.days || []);
      if (day.checked) days.add(day.dataset.clientSpeedDay); else days.delete(day.dataset.clientSpeedDay);
      state.editor.days = WEEKDAYS.filter((value) => days.has(value));
      day.closest('label')?.classList.toggle('is-active', day.checked);
      return;
    }
    const field = event.target.closest('[data-client-speed-field]');
    if (field) updateEditor(field);
  }

  function onKeyDown(event) {
    if (event.key !== 'Escape') return;
    if (state.confirmDelete) state.confirmDelete = false;
    else if (state.drawer) { state.drawer = false; state.editor = {}; }
    else return;
    render();
  }

  root?.addEventListener('click', onClick);
  root?.addEventListener('input', onInput);
  root?.addEventListener('change', onChange);
  document.addEventListener('keydown', onKeyDown);
  stage?.classList.add('is-user-authentication');
  render();
  load();

  /*
   * 手动刷新按钮按用户第 9 条删除，补一条可见性受控的轮询代替；
   * 有未保存草稿、抽屉或确认弹窗时跳过，避免刷掉用户填的内容。
   */
  state.pollTimer = window.setInterval(() => {
    if (!state.mounted || document.hidden) return;
    if (state.loading || state.refreshing || state.saving) return;
    if (state.drawer || state.confirmDelete) return;
    load(true);
  }, 15000);

  return {
    refresh() { return load(true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      window.clearInterval(state.pollTimer);
      root?.removeEventListener('click', onClick);
      root?.removeEventListener('input', onInput);
      root?.removeEventListener('change', onChange);
      document.removeEventListener('keydown', onKeyDown);
      root?.replaceChildren();
      root?.classList.remove('route-workspace', 'user-authentication-route-host', 'client-speed-limit-route-host');
      stage?.classList.remove('is-user-authentication');
    }
  };
}

export default { mount };
