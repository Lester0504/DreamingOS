export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const VERSION = '20260810-front-release-01';
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
    /*
     * 「MAC 限速」/「IP 限速」两个 tab（用户要求参照 31.1 爱快的 mac_qos / simple_qos）。
     *
     * 默认停在 mac：那是当前**唯一真正能用**的维度。后端 `client_control_rules` 表
     * 只有 `mac` 列（jmx_netconfig_db.c:803-829，无 ip_addr / target_kind），
     * 运行态回读也明确写着 `runtime_match_precision: "client_mac_exact"`、
     * `runtime_match_scope: "client_mac_on_lan_bridge"`。
     * 所以 IP tab 只做能力门占位，不放任何可提交的表单。
     */
    tab: 'mac',
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
      trash: '<path d="M4 7h16M9 7V4h6v3m-9 0 1 13h10l1-13M10 11v5m4-5v5"></path>',
      /* 启停原来用 `Ⅱ` / `▶` 两个文本字符。它们的字形宽度不同，切换状态时
         按钮内容宽度变化，整行动作区跟着位移 —— 用户说的「点一下他就跳」。
         换成同一 24 视框的 SVG，几何固定，也和同排的编辑/删除图标风格一致。 */
      pause: '<path d="M9 5v14M15 5v14"></path>',
      play: '<path d="M8 5.5v13l11-6.5-11-6.5Z"></path>',
      info: '<circle cx="12" cy="12" r="9"></circle><path d="M12 11v5M12 8h.01"></path>'
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

  /*
   * 筛选、搜索与「新建限速」放进表格卡自己的 kit 工具栏，不再是浮在卡片外面的
   * 独立 header —— design.md「Tables」要求表格卡是数据页的主表面，计数与操作
   * 都在 `.dwrt-kit-table-toolbar` 里。实测这页原先按钮全在卡片之外。
   */
  function toolbarControls() {
    const canCreate = writableCapabilities(state.capabilities) && state.clients.length > 0;
    const filters = [['all', '全部'], ['enabled', '已启用'], ['disabled', '已停用'], ['attention', '需关注']];
    return `<div class="user-auth-table-controls client-speed-table-controls"><div class="user-auth-toolbar-leading"><div class="user-auth-segmented">${filters.map(([id, label]) => `<button type="button" data-client-speed-filter="${id}" class="${state.filter === id ? 'is-active' : ''}">${label}</button>`).join('')}</div><label class="policy-search policy-search-main" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-client-speed-search value="${escapeHtml(state.query)}" placeholder="搜索终端、MAC、规则或备注"></label></div><div class="policy-toolbar-actions"><button class="policy-create-button" type="button" data-client-speed-create ${canCreate ? '' : 'disabled'}>${icon('plus')}<span>新建限速</span></button></div></div>`;
  }

  /*
   * 两个 tab 参照 31.1 爱快的 `mac_qos` / `simple_qos` 两张表。
   * 用兄弟页（网址浏览控制）同一套 `.user-auth-segmented`，不引入第二种分段控件。
   */
  function tabsMarkup() {
    const tabs = [['mac', 'MAC 限速'], ['ip', 'IP 限速']];
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs client-speed-tabs" data-dwrt-component="tabs" role="tablist" aria-label="终端限速">`
      + `<span class="dwrt-kit-tab-pill" aria-hidden="true"></span>`
      + `${tabs.map(([id, label]) => `<button class="dwrt-kit-tab ${state.tab === id ? 'is-active' : ''}" type="button" role="tab" aria-selected="${state.tab === id ? 'true' : 'false'}" data-value="${id}" data-client-speed-tab="${id}">${escapeHtml(label)}</button>`).join('')}`
      + `</nav>`;
  }

  /*
   * IP 限速占位。**刻意不放任何可提交的控件。**
   *
   * 后端现状（2026-08-04 实测 + 源码）：`client_control_rules` 没有 IP 列，
   * 写入路径 `jmx_app_api.c:13663` 又要求 `control_type == 'IP限速'` 才放行 ——
   * 也就是说那个名字已经被 MAC 维度占用了。真做 IP 限速需要后端先加
   * `ip_addr` + `target_kind`（或另建表）并给出数据面。路由缺口已单独提给后端：
   * `Acceptance-to-Backend-network-control-no-http-route-ip-and-line-rate-limit.md`。
   *
   * 在那之前放一个表单只有两种下场：把 IP 写进 `mac` 列污染数据，
   * 或者做个存不进去的空壳。所以这里只放中性的「即将开放」说明。
   *
   * 文案约束（用户明确要求，2026-08-08）：**不要论证 MAC 维度比 IP 更好**，
   * 也不要写「填了也无处保存」这类内部实现口径 —— 客户不接受这种答复。
   */
  function ipPlaceholderMarkup() {
    return `<section class="user-auth-main-surface client-speed-ip-card dwrt-kit-glass-surface">
      <div class="client-speed-ip-body">
        ${icon('info')}
        <strong>IP 限速即将开放</strong>
        <p>按 IP 或网段限速的能力正在开发中，当前固件版本尚未开放这个维度，因此这里暂不提供表单。</p>
        <p class="client-speed-ip-hint">在此期间，可以在「MAC 限速」中按终端添加限速规则。</p>
      </div>
    </section>`;
  }

  function tableMarkup() {
    return macTableMarkup();
  }

  function bodyMarkup() {
    return state.tab === 'ip' ? ipPlaceholderMarkup() : macTableMarkup();
  }

  function macTableMarkup() {
    const rows = filteredRules();
    const body = state.loading
      ? '<tr><td colspan="8" class="dwrt-kit-table-empty">正在读取终端限速规则</td></tr>'
      : rows.length ? rows.map((rule) => {
        const runtime = runtimeStatus(rule);
        return `<tr data-client-speed-rule="${escapeHtml(rule.id)}"><td><div class="client-speed-client"><strong>${escapeHtml(rule.clientName || '未命名终端')}</strong><span>${escapeHtml(rule.clientIp || '--')} · <code>${escapeHtml(rule.mac)}</code></span></div></td><td><strong>${escapeHtml(rule.name)}</strong>${rule.note ? `<small>${escapeHtml(rule.note)}</small>` : ''}</td><td>${escapeHtml(scheduleText(rule))}</td><td>${escapeHtml(rateText(rule.up_limit, rule.up_unit))}</td><td>${escapeHtml(rateText(rule.down_limit, rule.down_unit))}</td><td>${escapeHtml(rule.protocol || '任意')}</td><td><div class="client-speed-runtime">${statusBadge(runtime.label, runtime.tone)}<small title="${escapeHtml(runtime.detail)}">${escapeHtml(runtime.detail)}</small></div></td><td><div class="user-auth-row-actions"><button class="user-auth-icon-button" type="button" data-client-speed-toggle="${escapeHtml(rule.id)}" ${rule.writable && !state.saving ? '' : 'disabled'} aria-label="${rule.enabled ? '停用' : '启用'}" data-dwrt-tooltip="${rule.enabled ? '停用' : '启用'}">${icon(rule.enabled ? 'pause' : 'play')}</button><button class="user-auth-icon-button" type="button" data-client-speed-edit="${escapeHtml(rule.id)}" ${rule.writable && !state.saving ? '' : 'disabled'} aria-label="编辑" data-dwrt-tooltip="编辑">${icon('edit')}</button><button class="user-auth-icon-button danger" type="button" data-client-speed-delete="${escapeHtml(rule.id)}" ${rule.writable && !state.saving ? '' : 'disabled'} aria-label="删除" data-dwrt-tooltip="删除">${icon('trash')}</button></div></td></tr>`;
      }).join('') : '<tr><td colspan="8" class="dwrt-kit-table-empty">暂无终端限速规则</td></tr>';
    return `<section class="user-auth-main-surface user-auth-table-card client-speed-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface" data-client-speed-table><div class="dwrt-kit-table-toolbar user-auth-table-toolbar-rich"><div class="dwrt-kit-table-title"><strong>MAC 限速规则</strong><span>按终端 MAC 精确匹配，在 LAN 桥接数据面执行独立限速；换 IP 后规则依然生效</span></div><span class="dwrt-kit-table-count">${rows.length} 条</span>${toolbarControls()}</div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table user-auth-table client-speed-table"><thead><tr><th>终端</th><th>规则</th><th>计划</th><th>上行</th><th>下行</th><th>协议</th><th>运行状态</th><th>操作</th></tr></thead><tbody>${body}</tbody></table></div></section>`;
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
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-client-speed-close aria-label="关闭终端限速编辑"></button><aside class="user-auth-drawer client-speed-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" aria-label="${editing ? '编辑终端限速' : '新建终端限速'}"><header class="dwrt-kit-sheet-header"><div><span>CLIENT RATE LIMIT</span><strong>${editing ? '编辑终端限速' : '新建终端限速'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-client-speed-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body user-auth-drawer-body"><div class="user-auth-drawer-section"><strong>规则状态</strong><label class="user-auth-setting-row"><span><strong>启用规则</strong><small>保存后由终端管控调度器应用并回读运行状态</small></span><span class="dwrt-kit-switch" data-dwrt-component="switch"><input type="checkbox" data-client-speed-field="enabled" ${editor.enabled !== false ? 'checked' : ''}></span></label></div><div class="user-auth-form-grid">${editorField('终端', 'mac', editor.mac, { type: 'select', options: clientOptions(), disabled: editing, wide: true })}${editorField('规则名称', 'name', editor.name, { wide: true })}${editorField('计划模式', 'schedule_mode', editor.schedule_mode, { type: 'select', options: [['always', '始终'], ['daily', '每天'], ['week', '按周循环'], ['range', '指定星期与时间段']] })}${editorField('协议', 'protocol', editor.protocol, { type: 'select', options: [['任意', '任意'], ['TCP', 'TCP'], ['UDP', 'UDP'], ['ICMP', 'ICMP'], ['ICMPv6', 'ICMPv6']] })}</div>${showDays ? `<div class="client-speed-weekdays"><span>生效星期</span><div>${WEEKDAYS.map((day) => `<label class="${selectedDays.has(day) ? 'is-active' : ''}"><input type="checkbox" data-client-speed-day="${day}" ${selectedDays.has(day) ? 'checked' : ''}>${day}</label>`).join('')}</div></div>` : ''}<div class="user-auth-form-grid">${editor.schedule_mode !== 'always' ? `${editorField('开始时间', 'start_time', editor.start_time, { type: 'time' })}${editorField('结束时间', 'end_time', editor.end_time, { type: 'time' })}` : ''}${editorField('上行限速', 'up_limit', editor.up_limit, { type: 'number', min: 0, help: '填 0 表示不限速（后端回读 zero_limit_means_unlimited）' })}${editorField('上行单位', 'up_unit', editor.up_unit, { type: 'select', options: [['KB/s', 'KB/s'], ['MB/s', 'MB/s'], ['Kbps', 'Kbps'], ['Mbps', 'Mbps']] })}${editorField('下行限速', 'down_limit', editor.down_limit, { type: 'number', min: 0, help: '填 0 表示不限速（后端回读 zero_limit_means_unlimited）' })}${editorField('下行单位', 'down_unit', editor.down_unit, { type: 'select', options: [['KB/s', 'KB/s'], ['MB/s', 'MB/s'], ['Kbps', 'Kbps'], ['Mbps', 'Mbps']] })}${editorField('备注', 'note', editor.note, { type: 'textarea', wide: true })}</div><div class="user-auth-capability">运行范围为终端 MAC + 可选 L4 协议，当前统一作用于 LAN 桥接流量。线路维度、共享限速与应用级管控即将开放，当前固件版本尚未提供这些选项。</div>${state.notice ? noticeMarkup() : ''}</div><footer class="dwrt-kit-sheet-footer user-auth-drawer-footer"><span></span><div><button class="policy-secondary" type="button" data-client-speed-close>取消</button><button class="policy-primary" type="button" data-client-speed-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存规则'}</button></div></footer></aside>`;
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

  /*
   * 抽屉打开时不得整体重建 DOM。
   *
   * `render()` 用 `innerHTML` 重写整个 shell，抽屉是它的一部分。而 `load()`
   * 一进门就 render 一次、数据回来后再 render 一次，轮询的守卫只在**发起时**
   * 检查 `state.drawer`，所以"请求已在飞行中 → 用户点新建 → 请求返回"这条
   * 时序会把刚打开的抽屉连着用户填的内容一起抹掉重建：焦点丢失、输入清空，
   * 表现就是抽屉一闪就没了。实测把 `client_control_rules` 延迟 6s 再点新建，
   * 抽屉在 200ms 内就被覆盖掉，一次都没能留住。
   *
   * 所以数据刷新只更新表格与提示条，抽屉与确认弹窗原地保留。用户主动开关抽屉
   * 时走 `renderShell()`，那时重建是他要求的。
   */
  function renderShell() {
    if (!root) return;
    root.hidden = false;
    root.classList.add('route-workspace', 'user-authentication-route-host', 'client-speed-limit-route-host');
    /*
     * 抽屉与确认弹窗放在**独立的挂载容器**里，不和 `<main>` 混在同一次
     * innerHTML 重写中。这样开关抽屉只动那个容器，表格与工具栏不被重建；
     * 更要紧的是 kit 把抽屉搬进 portal 后会记一个"宿主存活探针"，探针取的是
     * 宿主里除抽屉外的第一个子节点 —— 如果抽屉和 `<main>` 是兄弟，那么每次
     * 重绘换掉 `<main>` 都会让探针失效，抽屉被当成孤儿销毁。给它一个专属
     * 容器，探针就落在容器内部，不受页面重绘影响。
     */
    root.innerHTML = `<section class="user-auth-shell client-speed-shell" data-client-speed-version="${VERSION}"><header class="user-auth-header client-speed-header">${tabsMarkup()}</header><main class="user-auth-workbench">${noticeMarkup()}${bodyMarkup()}</main><div class="client-speed-overlay-host" data-client-speed-overlays></div></section>`;
    renderOverlays();
    ui.mountAll?.(root);
  }

  /*
   * 只重绘覆盖层容器。容器本身保持不变，所以它内部始终有一个稳定的锚点，
   * 抽屉打开后不会因为页面别处刷新而被回收。
   */
  function renderOverlays() {
    const host = root?.querySelector('[data-client-speed-overlays]');
    if (!host) return;
    const markup = `${drawerMarkup()}${confirmationMarkup()}`;
    if (host.dataset.clientSpeedOverlayMarkup === markup) return;
    host.dataset.clientSpeedOverlayMarkup = markup;
    /*
     * 清空容器**关不掉抽屉**：kit 已经把它搬到 body 级的 sheet portal，容器里其实是空的
     * （实测关闭时 sheet 数 1 → 1）。必须先让 kit 卸载搬走的那份，它会连遮罩一起回收。
     * kit 的 `unmount(host)` 现在按 portalHome 反查得到传送出去的抽屉，本页不再需要自备
     * 一份 portal 清理代码（同一个缺陷曾被 5 个页面各抄一遍）。
     */
    window.DWRT_UI_KIT?.unmount?.(host);
    host.innerHTML = markup;
    ui.mountAll?.(host);
  }

  function render() {
    if (!root) return;
    /*
     * 只有**首次挂载**或结构性变化才整页重建。
     *
     * 原先的判据是「没有抽屉打开就 renderShell()」，于是每次轮询（`load()` 首尾各
     * 调一次 render）都把整个 shell 用 innerHTML 重写一遍 —— 实测停在页面上 20s
     * 内 shell 被重建 2 次，肉眼是周期性闪烁，切到 IP tab 也一样。
     * 我在 patchTable() 里加的那道 IP 短路根本到不了，因为流程在上面就走掉了。
     *
     * 现在：已挂载就走局部 patch（工具栏 / 提示条 / 主体 / 抽屉各自更新），
     * 只有确实没挂载时才 renderShell()。切 tab 由点击处显式调 renderShell()，
     * 那是结构性变化，重建是必要的。
     */
    const mounted = root.querySelector('[data-client-speed-version]');
    if (!mounted) {
      renderShell();
      return;
    }
    patchTabs();
    patchToolbar();
    patchNotice();
    patchBody();
    renderOverlays();
  }

  function patchTabs() {
    root?.querySelectorAll('[data-client-speed-tab]').forEach((button) => {
      button.classList.toggle('is-active', button.dataset.clientSpeedTab === state.tab);
    });
  }

  /*
   * 主体按当前 tab 局部更新。IP tab 的占位是静态文本，没有需要刷新的运行态，
   * 直接跳过 —— 既避免无谓重绘，也避免把它替换成表格。
   */
  function patchBody() {
    if (state.tab === 'ip') {
      if (!root?.querySelector('.client-speed-ip-card')) renderShell();
      return;
    }
    if (!root?.querySelector('[data-client-speed-table]')) { renderShell(); return; }
    patchTable();
  }

  function patchToolbar() {
    const current = root?.querySelector('.client-speed-table-controls');
    if (!current) return;
    const template = document.createElement('template');
    template.innerHTML = toolbarControls();
    const next = template.content.firstElementChild;
    if (!next) return;
    // 搜索框正被输入时不要替换它，否则每次刷新都会打断输入并丢焦点。
    if (current.contains(document.activeElement)) return;
    current.replaceWith(next);
    ui.mountAll?.(root.querySelector('.client-speed-table-controls'));
  }

  function patchNotice() {
    const workbench = root?.querySelector('.user-auth-workbench');
    if (!workbench) return;
    const existing = workbench.querySelector('.user-auth-notice, [data-client-speed-notice]');
    const markup = noticeMarkup();
    if (!markup) { existing?.remove(); return; }
    const template = document.createElement('template');
    template.innerHTML = markup;
    const next = template.content.firstElementChild;
    if (!next) return;
    if (existing) existing.replaceWith(next);
    else workbench.insertBefore(next, workbench.firstChild);
  }

  function patchTable() {
    /*
     * IP tab 没有表格。这里必须先短路返回：否则轮询每拍都发现取不到
     * `[data-client-speed-table]`，走下面那句 `render()` 把整页重建一次 ——
     * 表现就是停在 IP tab 上页面每 17s 闪一下。
     */
    if (state.tab === 'ip') return;
    const current = root?.querySelector('[data-client-speed-table]');
    if (!current) { render(); return; }
    /*
     * 走 kit 的共享保状态入口（Acceptance P0 单：本页实测丢焦点）。
     *
     * 原来是 `current.replaceWith(...)` 再复位 scrollTop：滚动能救，焦点与选区不能。
     * tableMarkup() 返回的就是这张卡，所以把卡的属性与内容一起交给 morph 配对。
     */
    const preserve = ui.preserveInteractionState;
    if (typeof preserve === 'function' && preserve(current, (target) => {
      const staging = document.createElement('template');
      staging.innerHTML = tableMarkup();
      const fresh = staging.content.firstElementChild;
      if (fresh) {
        Array.from(fresh.attributes).forEach((attribute) => target.setAttribute(attribute.name, attribute.value));
        target.innerHTML = fresh.innerHTML;
      }
    })) return;
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
    renderOverlays();
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
    if (message) { state.notice = message; state.noticeTone = 'warning'; renderOverlays(); return; }
    state.saving = true;
    renderOverlays();
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
      renderOverlays();
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
    renderOverlays();
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
      renderOverlays();
    }
  }

  function findRule(id) {
    return state.rules.find((rule) => String(rule.id) === String(id));
  }

  function onClick(event) {
    if (event.target.closest('[data-client-speed-close]')) { state.drawer = false; state.editor = {}; state.notice = ''; renderOverlays(); patchNotice(); return; }
    if (event.target.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]')) { state.confirmDelete = false; renderOverlays(); return; }
    if (event.target.closest('[data-dwrt-confirm-accept]')) { deleteRule(); return; }
    if (event.target.closest('[data-client-speed-create]')) { newEditor(); return; }
    if (event.target.closest('[data-client-speed-save]')) { saveRule(); return; }
    const tab = event.target.closest('[data-client-speed-tab]');
    if (tab) {
      const next = tab.dataset.clientSpeedTab;
      if (next === state.tab) return;
      state.tab = next;
      /*
       * 切 tab 只换主体，不动抽屉容器：整页 renderShell() 会重建 `<main>`，
       * 而 kit 的抽屉存活探针挂在 overlay 容器里，重建主体不影响它。
       * 这里仍走 renderShell() 是因为两个 tab 的主体结构完全不同（表格 vs 占位卡），
       * 局部 patch 反而更容易出错；抽屉此时通常是关着的。
       */
      renderShell();
      return;
    }
    const filter = event.target.closest('[data-client-speed-filter]');
    if (filter) { state.filter = filter.dataset.clientSpeedFilter; patchTable(); root.querySelectorAll('[data-client-speed-filter]').forEach((button) => button.classList.toggle('is-active', button === filter)); return; }
    const toggle = event.target.closest('[data-client-speed-toggle]');
    if (toggle) { toggleRule(findRule(toggle.dataset.clientSpeedToggle)); return; }
    const edit = event.target.closest('[data-client-speed-edit]');
    if (edit) { newEditor(findRule(edit.dataset.clientSpeedEdit)); return; }
    const remove = event.target.closest('[data-client-speed-delete]');
    if (remove) { state.confirmDelete = findRule(remove.dataset.clientSpeedDelete) || false; renderOverlays(); }
  }

  function updateEditor(target) {
    const key = target.dataset.clientSpeedField;
    if (!key) return;
    state.editor[key] = target.type === 'checkbox' ? target.checked : target.type === 'number' ? Number(target.value || 0) : target.value;
    // 计划模式会增删抽屉内的星期与时间字段，必须重画抽屉本身（只动覆盖层）。
    if (key === 'schedule_mode') renderOverlays();
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
