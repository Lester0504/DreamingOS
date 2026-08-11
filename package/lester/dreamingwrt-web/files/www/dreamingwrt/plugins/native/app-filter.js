/*
 * APP 过滤（#/authentication/app-filter）
 *
 * 后端契约来自 jmxd 源码实读，不是猜的：
 *   GET    /api/v1/aegis/app-blocks           裸调即可，无必填参数（30.1 实测 200）
 *   POST   /api/v1/aegis/app-blocks/validate  预检，返回 revision 与 capabilities
 *   POST   /api/v1/aegis/app-blocks           新建，必须带 confirm:true + revision
 *   PUT    /api/v1/aegis/app-blocks/<id>      修改，同上
 *   DELETE /api/v1/aegis/app-blocks/<id>      删除，同样要 confirm + revision
 *
 * `nc_aegis_app_block_normalize()` 对 body 是白名单校验，多一个字段就整条 400：
 * 允许的键只有 id/name/enabled/source/app_ids/schedule/action/filter_quic/
 * preview/confirm/revision。其中 action 必须是 "block"，filter_quic 必须是
 * false（capabilities.filter_quic_supported 为 0，传 true 直接被拒），
 * app_ids 必须是正整数数组，source 是 "any" 或单个 MAC。
 *
 * 应用清单不用 /api/v1/audit/apps —— 那是「当前网络里跑过什么」，只有 5 条真应用，
 * 且协议兜底值（https、tcp/11881）的 app_id 全是 0，根本不能下规则。
 * 可选应用库是 /api/v1/policy-engine/catalog：5873 个应用，带 app_id、分类与图标，
 * 支持 app_q 服务端搜索（上限 500 条/次），所以搜索走后端而不是前端过滤全量。
 */
export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const VERSION = '20260810-front-release-01';
  const stage = root?.closest('.console-stage');
  /* 后端 weekdays 用 0=周日..6=周六，展示按中国习惯从周一起排。 */
  const WEEKDAY_ORDER = [1, 2, 3, 4, 5, 6, 0];
  const WEEKDAY_LABELS = { 0: '日', 1: '一', 2: '二', 3: '三', 4: '四', 5: '五', 6: '六' };
  const ENDPOINTS = {
    blocks: '/api/v1/aegis/app-blocks',
    validate: '/api/v1/aegis/app-blocks/validate',
    catalog: '/api/v1/policy-engine/catalog',
    clients: '/api/v1/clients'
  };

  const state = {
    mounted: true,
    seq: 0,
    pollTimer: 0,
    catalogTimer: 0,
    loading: true,
    refreshing: false,
    saving: false,
    readOnly: false,
    blocks: { items: [], capabilities: {}, revision: 0 },
    clients: [],
    catalog: [],
    catalogTotal: 0,
    catalogTruncated: false,
    catalogLoading: false,
    catalogError: '',
    coverage: null,
    query: '',
    filter: 'all',
    appQuery: '',
    error: '',
    errorTone: '',
    notice: '',
    noticeTone: '',
    drawer: false,
    draft: null,
    confirm: null
  };

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (typeof value === 'object' && !Array.isArray(value)) {
        const nested = firstText(value.message, value.error, value.name, value.label, value.value, value.id);
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

  function asArray(value, keys = []) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of [...keys, 'items', 'rows', 'list', 'results', 'clients', 'applications']) {
      if (Array.isArray(value[key])) return value[key];
    }
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

  function formatNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number.toLocaleString('zh-CN') : '0';
  }

  function formatTime(seconds) {
    const value = Number(seconds);
    if (!Number.isFinite(value) || value <= 0) return '';
    return new Date(value * 1000).toLocaleString('zh-CN', { hour12: false });
  }

  function slug(prefix) {
    /* 后端 id 走 nc_valid_name()，只接受字母数字与有限符号，不能塞中文规则名。 */
    const random = Math.random().toString(36).slice(2, 8);
    return `${prefix}-${Date.now().toString(36)}${random}`;
  }

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
      const error = new Error(firstText(payload?.error, payload?.message, json?.message, json?.error, `HTTP ${response.status}`));
      error.status = response.status;
      error.code = firstText(payload?.error, json?.error);
      error.field = firstText(payload?.field);
      error.revision = Number(payload?.revision);
      throw error;
    }
    return payload;
  }

  function normalizeMac(value) {
    const compact = String(value || '').trim().replace(/[^0-9a-f]/gi, '').toUpperCase();
    return compact.length === 12 ? compact.match(/.{2}/g).join(':') : '';
  }

  function macEqual(left, right) {
    return Boolean(left) && normalizeMac(left) === normalizeMac(right);
  }

  function clientByMac(mac) {
    return state.clients.find((client) => macEqual(client.mac, mac)) || null;
  }

  function clientLabel(client) {
    if (!client) return '';
    return firstText(client.name, client.mac);
  }

  function sourceLabel(source) {
    if (!source || source === 'any') return '全部设备';
    const client = clientByMac(source);
    return client ? `${clientLabel(client)} · ${normalizeMac(source)}` : normalizeMac(source) || source;
  }

  /* ---------------- 契约与能力 ---------------- */

  function capabilities() {
    return state.blocks?.capabilities && typeof state.blocks.capabilities === 'object' ? state.blocks.capabilities : {};
  }

  function supported() {
    return bool(capabilities().supported);
  }

  function maxRules() {
    const value = Number(capabilities().max_rules);
    return Number.isFinite(value) && value > 0 ? value : 64;
  }

  function maxAppIds() {
    const value = Number(capabilities().max_app_ids_per_rule);
    return Number.isFinite(value) && value > 0 ? value : 1024;
  }

  /*
   * 时段与 MAC 作用对象都由 capabilities 声明，不是前端假定的：
   * schedule_modes 含 weekday_time_ranges 才给时段控件，source_modes 含 mac
   * 才给设备选择。后端不支持就不放控件——「能设但不生效」是明确要避免的。
   */
  function scheduleSupported() {
    return asArray(capabilities().schedule_modes).includes('weekday_time_ranges');
  }

  function macSourceSupported() {
    return asArray(capabilities().source_modes).includes('mac');
  }

  function blocks() {
    return asArray(state.blocks, ['items']);
  }

  function currentRevision() {
    const value = Number(state.blocks?.revision);
    return Number.isFinite(value) && value > 0 ? value : 0;
  }

  function canWrite() {
    return supported() && !state.readOnly;
  }

  function appById(id) {
    return state.catalog.find((app) => Number(app.app_id) === Number(id)) || null;
  }

  function appLabel(id) {
    const app = appById(id);
    return app ? firstText(app.label, `#${id}`) : `#${id}`;
  }

  /* ---------------- 规则行运行态 ---------------- */

  /*
   * 运行态一律取后端回读字段，不在前端另立一套推断。后端区分得很细：
   * runtime_readback_supported 为假时它自己都不知道内核里是什么，
   * 这种情况必须说「无法回读」，不能显示成「已生效」。
   */
  function runtimeStatus(rule) {
    if (!bool(rule.enabled)) return { label: '已停用', tone: 'error', detail: '规则保留在配置中，不下发到内核' };
    if (!bool(rule.runtime_readback_supported, true)) {
      return { label: '无法回读', tone: 'warning', detail: reasonText(rule.reason) || '内核运行态不可回读' };
    }
    if (bool(rule.active)) return { label: '运行中', tone: 'success', detail: `内核已装载 ${formatNumber(rule.runtime_app_count)} 个应用标识` };
    if (bool(rule.applied)) return { label: '已同步', tone: 'success', detail: '配置与内核一致，当前不在生效时段' };
    return { label: '待同步', tone: 'warning', detail: reasonText(rule.reason) || '内核尚未装载该规则' };
  }

  function reasonText(reason) {
    const map = {
      appfilter_global_disabled: 'APP 过滤总开关已关闭，规则不会下发',
      appfilter_global_state_unavailable: '无法读取 APP 过滤总开关状态',
      kernel_runtime_readback_invalid: '内核运行态回读内容无效',
      kernel_rule_config_mismatch: '内核里的规则内容与配置不一致',
      kernel_rule_presence_mismatch: '内核里缺少该规则或多了该规则',
      runtime_readback_unavailable_apply_pending: '运行态不可回读，等待应用',
      rulesd_reinit_signal_failed: '已写入配置，但通知 rulesd 重载失败',
      invalid_persisted_schedule: '已保存的时段格式无效，请重新编辑',
      one_or_more_rules_not_applied: '有规则尚未同步到内核'
    };
    return map[String(reason || '')] || '';
  }

  function errorText(error) {
    const code = firstText(error?.code);
    const map = {
      validation_failed: `规则校验未通过${error?.field ? `：字段 ${error.field} 不合法` : ''}`,
      revision_conflict: '配置已被他处修改，请刷新后重新提交',
      revision_required: '缺少配置版本号，请刷新页面重试',
      confirmation_required: '该操作需要二次确认',
      rule_limit_reached: `规则数量已达上限 ${maxRules()} 条`,
      rule_type_conflict: '该规则 ID 已被其他类型的管控规则占用',
      rule_not_found: '规则不存在，可能已被删除',
      runtime_rule_id_unavailable: '内核规则槽位已用尽',
      database_read_failed: '后端读取配置库失败',
      database_write_failed: '后端写入配置库失败'
    };
    if (map[code]) return map[code];
    if (Number(error?.status) === 403) return '当前账号没有修改 APP 过滤规则的权限';
    if (Number(error?.status) === 401) return '会话已失效，请重新登录';
    if ([404, 405, 501].includes(Number(error?.status))) return 'APP 过滤接口未在当前固件注册';
    return firstText(error?.message, '未知错误');
  }

  function scheduleText(rule) {
    const schedule = rule?.schedule;
    if (schedule === 'always' || !schedule) return '始终';
    if (schedule === 'invalid') return '时段无效';
    const ranges = asArray(schedule);
    if (!ranges.length) return '始终';
    return ranges.map((range) => {
      const days = asArray(range?.weekdays).map(Number);
      const label = days.length === 7 ? '每天' : WEEKDAY_ORDER.filter((day) => days.includes(day)).map((day) => WEEKDAY_LABELS[day]).join('');
      return `${label} ${firstText(range?.start_time, '00:00')}-${firstText(range?.end_time, '23:59')}`;
    }).join('；');
  }

  function filteredRules() {
    const query = state.query.trim().toLowerCase();
    return blocks().filter((rule) => {
      const runtime = runtimeStatus(rule);
      if (state.filter === 'enabled' && !bool(rule.enabled)) return false;
      if (state.filter === 'disabled' && bool(rule.enabled)) return false;
      if (state.filter === 'attention' && runtime.tone === 'success') return false;
      if (!query) return true;
      const apps = asArray(rule.app_ids).map((id) => appLabel(id)).join(' ');
      return [rule.name, rule.id, sourceLabel(rule.source), apps].filter(Boolean).join(' ').toLowerCase().includes(query);
    });
  }

  /* ---------------- 图标 ---------------- */

  function icon(name) {
    const paths = {
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      edit: '<path d="m4 20 4.2-1 10.9-10.9a2 2 0 0 0-2.8-2.8L5.4 16.2 4 20Z"></path>',
      trash: '<path d="M4 7h16M9 7V4h6v3m-9 0 1 13h10l1-13M10 11v5m4-5v5"></path>',
      pause: '<path d="M9 5v14M15 5v14"></path>',
      play: '<path d="M8 5.5v13l11-6.5-11-6.5Z"></path>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.edit}</svg>`;
  }

  function statusBadge(label, tone) {
    return ui.statusBadgeMarkup?.(label, tone) || `<span class="app-filter-status is-${escapeHtml(tone)}">${escapeHtml(label)}</span>`;
  }

  /* ---------------- 渲染 ---------------- */

  function noticeMarkup() {
    const message = state.notice || state.error;
    if (!message) return '';
    const tone = state.notice ? state.noticeTone || 'ok' : state.errorTone || 'warning';
    return `<div class="user-auth-notice is-${escapeHtml(tone)}" data-app-filter-notice>${escapeHtml(message)}</div>`;
  }

  /*
   * 识别覆盖率如实呈现。分母是 audit/apps 返回的全部条目，分子只算 is_application
   * 为真的；协议兜底值单独列出来，不混进「应用」。数据读不到就不画这张卡，
   * 不用 0 或 100% 假装有结论。
   */
  function coverageMarkup() {
    const coverage = state.coverage;
    if (!coverage) return '';
    const { identified, fallback, total } = coverage;
    const percent = total > 0 ? Math.round((identified / total) * 100) : 0;
    return `<section class="app-filter-coverage dwrt-kit-glass-surface">
      <div class="app-filter-coverage-head"><strong>应用识别覆盖率</strong><span>当前网络活跃条目中被识别为具体应用的比例</span></div>
      <div class="app-filter-coverage-metrics">
        <div><b>${percent}%</b><span>识别为应用</span></div>
        <div><b>${formatNumber(identified)}</b><span>真实应用</span></div>
        <div><b>${formatNumber(fallback)}</b><span>仅协议/端口</span></div>
        <div><b>${formatNumber(state.catalogTotal)}</b><span>可选应用库</span></div>
      </div>
      <p class="app-filter-coverage-note">识别依赖端口、SNI 与特征库。走 TLS/QUIC 且不暴露 SNI 的流量只能识别到协议，无法归属到具体应用，因此拉黑不能保证覆盖全部流量。上表中「仅协议/端口」的 ${formatNumber(fallback)} 条就属于这一类，它们不可作为拉黑对象。</p>
    </section>`;
  }

  function toolbarControls() {
    const filters = [['all', '全部'], ['enabled', '已启用'], ['disabled', '已停用'], ['attention', '需关注']];
    const full = blocks().length >= maxRules();
    return `<div class="user-auth-table-controls app-filter-table-controls"><div class="user-auth-toolbar-leading"><div class="user-auth-segmented">${filters.map(([id, label]) => `<button type="button" data-app-filter-filter="${id}" class="${state.filter === id ? 'is-active' : ''}">${label}</button>`).join('')}</div><label class="policy-search policy-search-main" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-app-filter-search value="${escapeHtml(state.query)}" placeholder="搜索规则、应用或作用对象"></label></div><div class="policy-toolbar-actions"><button class="policy-create-button" type="button" data-app-filter-create ${canWrite() && !full ? '' : 'disabled'} ${full ? `data-dwrt-tooltip="规则数量已达上限 ${maxRules()} 条"` : ''}>${icon('plus')}<span>新建规则</span></button></div></div>`;
  }

  function appCellMarkup(rule) {
    const ids = asArray(rule.app_ids).map(Number).filter((id) => id > 0);
    if (!ids.length) return '<span class="app-filter-app-empty">未指定应用</span>';
    const shown = ids.slice(0, 3);
    const rest = ids.length - shown.length;
    const full = ids.map((id) => appLabel(id)).join('、');
    return `<div class="app-filter-apps" title="${escapeHtml(full)}">${shown.map((id) => {
      const app = appById(id);
      return `<span class="app-filter-app-chip">${app?.icon ? `<img src="${escapeHtml(app.icon)}" alt="" loading="lazy" onerror="this.hidden=true">` : ''}<b>${escapeHtml(appLabel(id))}</b></span>`;
    }).join('')}${rest > 0 ? `<span class="app-filter-app-more">+${rest}</span>` : ''}</div>`;
  }

  function tableMarkup() {
    const rows = filteredRules();
    const writable = canWrite();
    const body = state.loading
      ? '<tr><td colspan="7" class="dwrt-kit-table-empty">正在读取 APP 过滤规则</td></tr>'
      : rows.length ? rows.map((rule) => {
        const runtime = runtimeStatus(rule);
        const id = firstText(rule.id);
        return `<tr data-app-filter-rule="${escapeHtml(id)}"><td><div class="app-filter-cell"><strong>${escapeHtml(firstText(rule.name, id))}</strong><span>${escapeHtml(id)}</span></div></td><td>${appCellMarkup(rule)}</td><td><div class="app-filter-cell"><strong>${escapeHtml(sourceLabel(rule.source))}</strong>${rule.source && rule.source !== 'any' ? '<span>按 MAC 限定</span>' : '<span>不限设备</span>'}</div></td><td>${escapeHtml(scheduleText(rule))}</td><td><div class="app-filter-cell"><strong>${formatNumber(rule.hits)} 次</strong><span>${escapeHtml(formatTime(rule.last_hit_s) || '尚无命中')}</span></div></td><td><div class="app-filter-runtime">${statusBadge(runtime.label, runtime.tone)}<small title="${escapeHtml(runtime.detail)}">${escapeHtml(runtime.detail)}</small></div></td><td><div class="user-auth-row-actions"><button class="user-auth-icon-button" type="button" data-app-filter-toggle="${escapeHtml(id)}" ${writable && !state.saving ? '' : 'disabled'} aria-label="${bool(rule.enabled) ? '停用' : '启用'}" data-dwrt-tooltip="${bool(rule.enabled) ? '停用' : '启用'}">${icon(bool(rule.enabled) ? 'pause' : 'play')}</button><button class="user-auth-icon-button" type="button" data-app-filter-edit="${escapeHtml(id)}" ${writable && !state.saving ? '' : 'disabled'} aria-label="编辑" data-dwrt-tooltip="编辑">${icon('edit')}</button><button class="user-auth-icon-button danger" type="button" data-app-filter-delete="${escapeHtml(id)}" ${writable && !state.saving ? '' : 'disabled'} aria-label="删除" data-dwrt-tooltip="删除">${icon('trash')}</button></div></td></tr>`;
      }).join('') : `<tr><td colspan="7" class="dwrt-kit-table-empty">${state.query.trim() ? '没有匹配的规则' : '尚未创建 APP 过滤规则。识别到的应用需要你手动选择后才会被拉黑。'}</td></tr>`;
    return `<section class="user-auth-main-surface user-auth-table-card app-filter-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface" data-app-filter-table><div class="dwrt-kit-table-toolbar user-auth-table-toolbar-rich"><div class="dwrt-kit-table-title"><strong>APP 过滤规则</strong><span>按应用标识与设备 MAC 阻止，由 rulesd 下发内核 ${blocks().length}/${maxRules()} 条</span></div><span class="dwrt-kit-table-count">${rows.length} 条</span>${toolbarControls()}</div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table user-auth-table app-filter-table"><thead><tr><th>规则</th><th>应用</th><th>作用对象</th><th>生效时段</th><th>命中</th><th>运行状态</th><th>操作</th></tr></thead><tbody>${body}</tbody></table></div></section>`;
  }

  /* ---------------- 抽屉 ---------------- */

  function defaultDraft(item = null) {
    const ranges = asArray(item?.schedule).map((range) => ({
      weekdays: asArray(range?.weekdays).map(Number).filter((day) => day >= 0 && day <= 6),
      start_time: firstText(range?.start_time, '00:00'),
      end_time: firstText(range?.end_time, '23:59')
    })).filter((range) => range.weekdays.length);
    const everyDay = ranges.length === 1 && ranges[0].weekdays.length === 7;
    return {
      id: firstText(item?.id) || slug('appblk'),
      name: firstText(item?.name),
      enabled: item ? bool(item.enabled, true) : true,
      source: firstText(item?.source, 'any'),
      app_ids: asArray(item?.app_ids).map(Number).filter((id) => id > 0),
      schedule_mode: !ranges.length ? 'always' : everyDay ? 'daily' : 'custom',
      ranges: ranges.length ? ranges : [{ weekdays: [1, 2, 3, 4, 5], start_time: '09:00', end_time: '18:00' }],
      existing: Boolean(item?.id)
    };
  }

  function draftRanges(draft = state.draft) {
    if (!draft || draft.schedule_mode === 'always') return [];
    if (draft.schedule_mode === 'daily') return [{ ...draft.ranges[0], weekdays: [0, 1, 2, 3, 4, 5, 6] }];
    return draft.ranges;
  }

  function draftProblem(draft = state.draft) {
    if (!draft) return '规则草稿缺失';
    if (!draft.name.trim()) return '请填写规则名称';
    if (!draft.app_ids.length) return '请至少选择一个要拉黑的应用';
    if (draft.app_ids.length > maxAppIds()) return `单条规则最多 ${maxAppIds()} 个应用`;
    if (draft.source !== 'any' && !normalizeMac(draft.source)) return '请选择或填写合法的设备 MAC';
    if (draftRanges(draft).some((range) => !range.weekdays.length)) return '每个时段至少要选一天';
    if (draftRanges(draft).some((range) => !range.start_time || !range.end_time)) return '请填写完整的起止时间';
    return '';
  }

  function selectedAppsMarkup(draft) {
    if (!draft.app_ids.length) return '<div class="app-filter-selected-empty">尚未选择应用。你必须自己选，页面不会预设任何黑名单。</div>';
    return `<div class="app-filter-selected-list">${draft.app_ids.map((id) => {
      const app = appById(id);
      return `<span class="app-filter-selected-chip">${app?.icon ? `<img src="${escapeHtml(app.icon)}" alt="" loading="lazy" onerror="this.hidden=true">` : ''}<b>${escapeHtml(appLabel(id))}</b><button type="button" data-app-filter-app-remove="${id}" aria-label="移除 ${escapeHtml(appLabel(id))}">×</button></span>`;
    }).join('')}</div>`;
  }

  function catalogMarkup(draft) {
    if (state.catalogError) {
      return `<div class="app-filter-catalog-empty">应用库读取失败：${escapeHtml(state.catalogError)}</div>`;
    }
    if (state.catalogLoading && !state.catalog.length) {
      return '<div class="app-filter-catalog-empty">正在读取应用库</div>';
    }
    if (!state.catalog.length) {
      return `<div class="app-filter-catalog-empty">${state.appQuery.trim() ? '没有匹配的应用，换个关键词试试' : '应用库为空'}</div>`;
    }
    return `<div class="app-filter-catalog">${state.catalog.map((app) => {
      const id = Number(app.app_id ?? app.value);
      const checked = draft.app_ids.includes(id);
      return `<label class="${checked ? 'is-active' : ''}"><input type="checkbox" data-app-filter-app="${id}" ${checked ? 'checked' : ''}><span class="app-filter-checkmark"></span>${app.icon ? `<img src="${escapeHtml(app.icon)}" alt="" loading="lazy" onerror="this.hidden=true">` : '<i class="app-filter-app-placeholder"></i>'}<b>${escapeHtml(firstText(app.label, `#${id}`))}</b><small>${escapeHtml(firstText(app.category, '未分类'))}</small></label>`;
    }).join('')}</div>`;
  }

  function rangeRowsMarkup(draft) {
    const ranges = draftRanges(draft);
    if (!ranges.length) return '';
    const multi = draft.schedule_mode === 'custom';
    return `<div class="app-filter-ranges">${ranges.map((range, index) => `<div class="app-filter-range" data-app-filter-range="${index}">
      ${draft.schedule_mode === 'daily' ? '' : `<div class="app-filter-weekdays">${WEEKDAY_ORDER.map((day) => `<label class="${range.weekdays.includes(day) ? 'is-active' : ''}"><input type="checkbox" data-app-filter-day="${day}" data-app-filter-range-index="${index}" ${range.weekdays.includes(day) ? 'checked' : ''}>${WEEKDAY_LABELS[day]}</label>`).join('')}</div>`}
      <div class="app-filter-range-times"><label class="user-auth-field" data-dwrt-component="field"><span>开始</span><input type="time" data-app-filter-range-field="start_time" data-app-filter-range-index="${index}" value="${escapeHtml(range.start_time)}"></label><label class="user-auth-field" data-dwrt-component="field"><span>结束</span><input type="time" data-app-filter-range-field="end_time" data-app-filter-range-index="${index}" value="${escapeHtml(range.end_time)}"></label>${multi && ranges.length > 1 ? `<button type="button" class="app-filter-range-remove" data-app-filter-range-remove="${index}" aria-label="删除该时段">×</button>` : ''}</div>
    </div>`).join('')}${multi ? '<button type="button" class="app-filter-range-add" data-app-filter-range-add>+ 增加时段</button>' : ''}</div>`;
  }

  function deviceFieldMarkup(draft) {
    if (!macSourceSupported()) {
      return '<div class="user-auth-capability">后端当前只支持对全部设备生效，因此不提供按设备限定的控件。</div>';
    }
    const known = state.clients.filter((client) => client.mac);
    const isManual = draft.source !== 'any' && !clientByMac(draft.source);
    return `<label class="user-auth-field is-wide" data-dwrt-component="field"><span>作用对象</span><select data-app-filter-field="source">
      <option value="any" ${draft.source === 'any' ? 'selected' : ''}>全部设备</option>
      ${known.map((client) => `<option value="${escapeHtml(client.mac)}" ${macEqual(client.mac, draft.source) ? 'selected' : ''}>${escapeHtml(clientLabel(client))} · ${escapeHtml(client.mac)}</option>`).join('')}
      ${isManual ? `<option value="${escapeHtml(draft.source)}" selected>${escapeHtml(normalizeMac(draft.source) || draft.source)}（不在当前终端列表）</option>` : ''}
    </select><small>后端一条规则只支持一个 MAC。需要覆盖多台设备时请分别建规则。</small></label>`;
  }

  function drawerMarkup() {
    if (!state.drawer || !state.draft) return '';
    const draft = state.draft;
    const editing = draft.existing;
    const problem = draftProblem(draft);
    const scheduleModes = scheduleSupported()
      ? [['always', '始终生效'], ['daily', '每天固定时段'], ['custom', '按星期与时段']]
      : [['always', '始终生效']];
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-app-filter-close aria-label="关闭 APP 过滤编辑"></button><aside class="user-auth-drawer app-filter-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" aria-label="${editing ? '编辑 APP 过滤规则' : '新建 APP 过滤规则'}">
      <header class="dwrt-kit-sheet-header"><div><span>APP FILTER</span><strong>${editing ? '编辑 APP 过滤规则' : '新建 APP 过滤规则'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-app-filter-close aria-label="关闭">×</button></header>
      <div class="dwrt-kit-sheet-body user-auth-drawer-body">
        <div class="user-auth-drawer-section"><strong>规则状态</strong><label class="user-auth-setting-row"><span><strong>启用规则</strong><small>保存后由 rulesd 下发内核，运行状态按回读结果显示</small></span><span class="dwrt-kit-switch" data-dwrt-component="switch"><input type="checkbox" data-app-filter-field="enabled" ${draft.enabled ? 'checked' : ''}></span></label></div>
        <div class="user-auth-form-grid"><label class="user-auth-field is-wide" data-dwrt-component="field"><span>规则名称</span><input type="text" maxlength="64" data-app-filter-field="name" value="${escapeHtml(draft.name)}" placeholder="例如 孩子设备禁用短视频"></label>${deviceFieldMarkup(draft)}</div>
        <div class="app-filter-drawer-section"><div class="app-filter-drawer-section-head"><strong>选择要拉黑的应用</strong><small>只列出特征库里可下规则的应用；协议与端口兜底值（https、tcp/11881 这类）不是应用，不在此列。</small></div>
          <label class="app-filter-inline-search" data-dwrt-component="field">${icon('search')}<input type="search" data-app-filter-app-search value="${escapeHtml(state.appQuery)}" placeholder="搜索应用名称、分类或特征族" aria-label="搜索应用"></label>
          <div class="app-filter-catalog-meta">${state.catalogLoading ? '正在检索' : `匹配 ${formatNumber(state.catalogTotal)} 个${state.catalogTruncated ? `，已显示前 ${state.catalog.length} 个，请用搜索缩小范围` : ''}`}</div>
          ${catalogMarkup(draft)}
          <div class="app-filter-selected"><div class="app-filter-selected-head"><strong>已选 ${draft.app_ids.length} 个应用</strong><span>上限 ${formatNumber(maxAppIds())} 个</span></div>${selectedAppsMarkup(draft)}</div>
        </div>
        <div class="app-filter-drawer-section"><div class="app-filter-drawer-section-head"><strong>生效时段</strong>${scheduleSupported() ? '<small>后端按星期与时间范围判定，超出时段时规则不生效。</small>' : '<small>后端未声明时段能力，因此只提供「始终生效」。</small>'}</div>
          <div class="user-auth-form-grid"><label class="user-auth-field is-wide" data-dwrt-component="field"><span>时段模式</span><select data-app-filter-field="schedule_mode">${scheduleModes.map(([value, label]) => `<option value="${value}" ${draft.schedule_mode === value ? 'selected' : ''}>${label}</option>`).join('')}</select></label></div>
          ${rangeRowsMarkup(draft)}
        </div>
        <div class="user-auth-capability">动作固定为阻止（后端只接受 <code>block</code>）。QUIC 过滤后端声明为未支持，因此不提供该开关：走 QUIC 或不暴露 SNI 的加密流量可能识别不到，规则无法保证拦住全部流量。保存前会先调用后端校验接口，并需要你二次确认。</div>
        ${problem ? `<div class="user-auth-notice is-warning">${escapeHtml(problem)}</div>` : ''}
        ${state.notice ? noticeMarkup() : ''}
      </div>
      <footer class="dwrt-kit-sheet-footer user-auth-drawer-footer"><span></span><div><button class="policy-secondary" type="button" data-app-filter-close>取消</button><button class="policy-primary" type="button" data-app-filter-save ${state.saving || problem ? 'disabled' : ''}>${state.saving ? '正在校验' : '校验并保存'}</button></div></footer>
    </aside>`;
  }

  function confirmationMarkup() {
    if (!state.confirm) return '';
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    if (typeof renderer !== 'function') return '';
    return renderer({
      id: 'app-filter-confirmation',
      action: state.confirm.action,
      tone: state.confirm.tone || 'warning',
      title: state.confirm.title,
      description: state.confirm.description,
      cancelLabel: '取消',
      confirmLabel: state.saving ? '正在提交' : state.confirm.confirmLabel,
      disabled: state.saving
    });
  }

  /*
   * 与 client-speed-limit 同一套结构：覆盖层单独挂容器，轮询只 patch 表格，
   * 避免抽屉被后台刷新连着用户填的内容一起抹掉。
   */
  function renderShell() {
    if (!root) return;
    root.hidden = false;
    root.classList.add('route-workspace', 'user-authentication-route-host', 'app-filter-route-host');
    root.innerHTML = `<section class="user-auth-shell app-filter-shell" data-app-filter-version="${VERSION}"><main class="user-auth-workbench">${noticeMarkup()}${coverageMarkup()}${tableMarkup()}</main><div class="app-filter-overlay-host" data-app-filter-overlays></div></section>`;
    renderOverlays();
    ui.mountAll?.(root);
  }

  function renderOverlays() {
    const host = root?.querySelector('[data-app-filter-overlays]');
    if (!host) return;
    const markup = `${drawerMarkup()}${confirmationMarkup()}`;
    if (host.dataset.appFilterOverlayMarkup === markup) return;
    host.dataset.appFilterOverlayMarkup = markup;
    /*
     * 抽屉已被 kit 搬到 body 级 portal，清空本容器关不掉它。kit 的 `unmount(host)` 现在
     * 按 portalHome 反查回收传送出去的抽屉与遮罩，本页不再自备 portal 清理代码。
     */
    window.DWRT_UI_KIT?.unmount?.(host);
    host.innerHTML = markup;
    ui.mountAll?.(host);
  }

  function render() {
    if (!root) return;
    const overlayOpen = Boolean(state.drawer || state.confirm);
    const mounted = root.querySelector('[data-app-filter-version]');
    if (!overlayOpen || !mounted || !root.querySelector('.dwrt-kit-sheet, [data-dwrt-component="modal"]')) {
      renderShell();
      return;
    }
    patchToolbar();
    patchNotice();
    patchTable();
    renderOverlays();
  }

  function patchToolbar() {
    const current = root?.querySelector('.app-filter-table-controls');
    if (!current) return;
    if (current.contains(document.activeElement)) return;
    const template = document.createElement('template');
    template.innerHTML = toolbarControls();
    const next = template.content.firstElementChild;
    if (!next) return;
    current.replaceWith(next);
    ui.mountAll?.(root.querySelector('.app-filter-table-controls'));
  }

  function patchNotice() {
    const workbench = root?.querySelector('.user-auth-workbench');
    if (!workbench) return;
    const existing = workbench.querySelector('[data-app-filter-notice]');
    const markup = noticeMarkup();
    if (!markup) { existing?.remove(); return; }
    const template = document.createElement('template');
    template.innerHTML = markup;
    const next = template.content.firstElementChild;
    if (!next) return;
    if (existing) existing.replaceWith(next);
    else workbench.insertBefore(next, workbench.firstChild);
  }

  /*
   * 表格重画走 kit 的共享保状态入口（Acceptance P0 单）。
   *
   * 原来是 `current.replaceWith(...)` 再把 scrollTop 复位：节点换了身份，滚动靠事后补救，
   * 焦点与选区直接丢。交给 kit 按语义 key patch 之后三样都留着。
   */
  function patchTable() {
    const current = root?.querySelector('[data-app-filter-table]');
    if (!current) { renderShell(); return; }
    /*
     * 直接在表格卡上 patch。tableMarkup() 返回的就是这张卡，所以渲染进 staging 之后
     * 取它的首个元素，把卡的属性与内容一起交给 morph 配对。
     *
     * 不要在父容器上做：`.app-filter-workbench` 里还挂着提示条、模式块与能力说明，
     * 只写 tableMarkup() 会把那些兄弟节点当成"新树里没有"而删掉。
     */
    const preserve = ui.preserveInteractionState;
    if (typeof preserve === 'function' && preserve(current, (target) => {
      const template = document.createElement('template');
      template.innerHTML = tableMarkup();
      const fresh = template.content.firstElementChild;
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
    const next = root.querySelector('[data-app-filter-table] .dwrt-kit-table-scroll');
    if (next) { next.scrollTop = position.top; next.scrollLeft = position.left; }
    ui.mountAll?.(root.querySelector('[data-app-filter-table]'));
  }

  /* 只重画抽屉里的应用库区域，避免搜索时丢焦点。 */
  function patchCatalog() {
    const host = document.querySelector('.app-filter-drawer');
    if (!host || !state.draft) { renderOverlays(); return; }
    const meta = host.querySelector('.app-filter-catalog-meta');
    if (meta) {
      meta.textContent = state.catalogLoading
        ? '正在检索'
        : `匹配 ${formatNumber(state.catalogTotal)} 个${state.catalogTruncated ? `，已显示前 ${state.catalog.length} 个，请用搜索缩小范围` : ''}`;
    }
    const list = host.querySelector('.app-filter-catalog, .app-filter-catalog-empty');
    if (list) {
      const template = document.createElement('template');
      template.innerHTML = catalogMarkup(state.draft);
      const next = template.content.firstElementChild;
      if (next) list.replaceWith(next);
    }
    patchSelected();
  }

  function patchSelected() {
    const host = document.querySelector('.app-filter-drawer');
    if (!host || !state.draft) return;
    const head = host.querySelector('.app-filter-selected-head strong');
    if (head) head.textContent = `已选 ${state.draft.app_ids.length} 个应用`;
    const list = host.querySelector('.app-filter-selected-list, .app-filter-selected-empty');
    if (list) {
      const template = document.createElement('template');
      template.innerHTML = selectedAppsMarkup(state.draft);
      const next = template.content.firstElementChild;
      if (next) list.replaceWith(next);
    }
    const save = host.querySelector('[data-app-filter-save]');
    if (save) save.disabled = Boolean(state.saving || draftProblem());
  }

  /* ---------------- 数据 ---------------- */

  /*
   * 覆盖率来自 audit/apps，是「当前网络活跃条目」的识别情况，与可选应用库无关。
   * 这个接口失败不算致命：规则列表本身不依赖它，所以只是不画那张卡。
   */
  function coverageFrom(payload) {
    const items = asArray(payload, ['app_records', 'apps', 'records']);
    if (!items.length) return null;
    let identified = 0;
    items.forEach((item) => {
      const real = bool(item.is_application) && bool(item.app_identified) && !bool(item.application_name_is_fallback);
      if (real) identified += 1;
    });
    return { total: items.length, identified, fallback: items.length - identified };
  }

  async function load(background = false) {
    const seq = ++state.seq;
    state.loading = !background;
    state.refreshing = background;
    if (!background) { state.error = ''; state.notice = ''; }
    render();
    try {
      const [blocksResult, clientsResult, appsResult] = await Promise.allSettled([
        requestJson(ENDPOINTS.blocks),
        requestJson(ENDPOINTS.clients),
        requestJson('/api/v1/audit/apps')
      ]);
      if (!state.mounted || seq !== state.seq) return;
      if (blocksResult.status === 'rejected') throw blocksResult.reason;
      state.blocks = blocksResult.value || { items: [], capabilities: {} };
      state.clients = clientsResult.status === 'fulfilled'
        ? asArray(clientsResult.value, ['clients']).map((client) => ({
          ...client,
          mac: normalizeMac(firstText(client.mac, client.client_mac, client.hwaddr)),
          name: firstText(client.display_name, client.alias, client.name, client.hostname, '未命名终端')
        })).filter((client) => client.mac)
        : [];
      state.coverage = appsResult.status === 'fulfilled' ? coverageFrom(appsResult.value) : null;
      state.loading = false;
      state.refreshing = false;
      state.error = '';
      if (!supported()) {
        state.error = ' 后端声明 APP 过滤不受支持，页面进入只读态。';
        state.errorTone = 'warning';
      }
      render();
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      state.blocks = { items: [], capabilities: {}, revision: 0 };
      state.error = `读取 APP 过滤规则失败：${errorText(error)}`;
      state.errorTone = 'warning';
      if (Number(error.status) === 403) state.readOnly = true;
      render();
    }
  }

  async function loadCatalog() {
    const seq = state.seq;
    state.catalogLoading = true;
    state.catalogError = '';
    patchCatalog();
    try {
      const query = state.appQuery.trim();
      const url = `${ENDPOINTS.catalog}?app_limit=200${query ? `&app_q=${encodeURIComponent(query)}` : ''}`;
      const payload = await requestJson(url);
      if (!state.mounted) return;
      const source = payload?.sources?.applications || {};
      state.catalog = asArray(payload, ['applications']).map((app) => ({
        app_id: Number(app.app_id ?? app.value),
        label: firstText(app.label),
        category: firstText(app.category),
        family: firstText(app.family),
        icon: firstText(app.icon)
      })).filter((app) => app.app_id > 0);
      state.catalogTotal = Number(source.total) || state.catalog.length;
      state.catalogTruncated = bool(source.truncated);
      state.catalogLoading = false;
      if (seq === state.seq) patchCatalog();
    } catch (error) {
      if (!state.mounted) return;
      state.catalogLoading = false;
      state.catalogError = errorText(error);
      patchCatalog();
    }
  }

  /*
   * 应用名要能在规则列表里显示，而列表里的 app_ids 可能不在当前搜索结果里。
   * 所以进页面先拉一批目录做名字映射，抽屉搜索再按需替换。
   */
  async function primeCatalog() {
    if (state.catalog.length) return;
    await loadCatalog();
    if (state.mounted && !state.drawer) render();
  }

  /* ---------------- 写路径 ---------------- */

  function payloadFromDraft() {
    const draft = state.draft;
    const schedule = draft.schedule_mode === 'always'
      ? 'always'
      : draftRanges(draft).map((range) => ({
        weekdays: [...new Set(range.weekdays.map(Number))].sort((a, b) => a - b),
        start_time: range.start_time,
        end_time: range.end_time
      }));
    /*
     * 字段集必须与后端白名单完全一致，多一个键就整条 validation_failed。
     * filter_quic 固定 false：capabilities.filter_quic_supported 为 0，传 true 会被拒。
     */
    return {
      id: draft.id,
      name: draft.name.trim(),
      enabled: draft.enabled !== false,
      source: draft.source === 'any' ? 'any' : normalizeMac(draft.source),
      app_ids: [...new Set(draft.app_ids.map(Number).filter((id) => id > 0))],
      schedule,
      action: 'block',
      filter_quic: false
    };
  }

  async function validateAndConfirm() {
    if (state.saving) return;
    const problem = draftProblem();
    if (problem) { state.notice = problem; state.noticeTone = 'warning'; renderOverlays(); return; }
    const payload = payloadFromDraft();
    const editing = state.draft.existing;
    state.saving = true;
    state.notice = '';
    renderOverlays();
    try {
      /* 先预检，把后端的字段级错误就地显示，而不是把 400 丢给用户。 */
      const validation = await requestJson(ENDPOINTS.validate, { method: 'POST', body: JSON.stringify(payload) });
      if (!bool(validation.valid ?? validation.ok)) throw new Error(firstText(validation.error, '规则校验未通过'));
      const revision = Number(validation.revision ?? currentRevision());
      state.saving = false;
      state.drawer = false;
      const names = payload.app_ids.slice(0, 3).map((id) => appLabel(id)).join('、');
      const rest = payload.app_ids.length > 3 ? ` 等 ${payload.app_ids.length} 个应用` : '';
      state.confirm = {
        action: 'app-filter-save',
        tone: 'warning',
        title: editing ? '保存 APP 过滤规则？' : '创建 APP 过滤规则？',
        description: `将对「${sourceLabel(payload.source)}」阻止 ${names}${rest}，并请求 rulesd 同步到内核。识别依赖特征库与 SNI，加密流量可能无法完全覆盖。`,
        confirmLabel: '确认并保存',
        payload,
        revision,
        editing
      };
      renderOverlays();
    } catch (error) {
      state.saving = false;
      state.notice = `校验失败：${errorText(error)}`;
      state.noticeTone = 'error';
      renderOverlays();
    }
  }

  async function commitSave() {
    const request = state.confirm;
    if (!request) return;
    state.confirm = null;
    state.saving = true;
    render();
    try {
      await requestJson(request.editing ? `${ENDPOINTS.blocks}/${encodeURIComponent(request.payload.id)}` : ENDPOINTS.blocks, {
        method: request.editing ? 'PUT' : 'POST',
        body: JSON.stringify({ ...request.payload, confirm: true, revision: request.revision })
      });
      state.saving = false;
      state.draft = null;
      state.notice = '规则已保存，运行状态按内核回读结果显示。';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      /* 409 是乐观锁冲突：明确提示刷新，绝不静默重试覆盖别人的修改。 */
      const conflict = Number(error.status) === 409 || error.code === 'revision_conflict';
      state.notice = conflict
        ? '配置已被他处修改（版本冲突），你的修改未保存。页面已刷新到最新配置，请重新编辑后再提交。'
        : `保存失败：${errorText(error)}`;
      state.noticeTone = conflict ? 'warning' : 'error';
      if (Number(error.status) === 403) state.readOnly = true;
      await load(true);
    }
  }

  function requestToggle(rule) {
    if (!canWrite() || state.saving || !rule) return;
    state.draft = defaultDraft(rule);
    state.draft.enabled = !bool(rule.enabled);
    state.confirm = {
      action: 'app-filter-save',
      tone: 'warning',
      title: bool(rule.enabled) ? '停用该规则？' : '启用该规则？',
      description: bool(rule.enabled)
        ? `「${firstText(rule.name, rule.id)}」将从内核撤下，规则保留在配置中。`
        : `「${firstText(rule.name, rule.id)}」将重新下发到内核。`,
      confirmLabel: '确认',
      payload: payloadFromDraft(),
      revision: currentRevision(),
      editing: true
    };
    renderOverlays();
  }

  function requestDelete(rule) {
    if (!canWrite() || state.saving || !rule) return;
    state.confirm = {
      action: 'app-filter-delete',
      tone: 'danger',
      title: '删除 APP 过滤规则',
      description: `规则「${firstText(rule.name, rule.id)}」将从配置与内核运行态中删除。`,
      confirmLabel: '确认删除',
      ruleId: firstText(rule.id),
      revision: currentRevision()
    };
    renderOverlays();
  }

  async function commitDelete() {
    const request = state.confirm;
    if (!request?.ruleId) return;
    state.confirm = null;
    state.saving = true;
    render();
    try {
      await requestJson(`${ENDPOINTS.blocks}/${encodeURIComponent(request.ruleId)}`, {
        method: 'DELETE',
        body: JSON.stringify({ id: request.ruleId, confirm: true, revision: request.revision })
      });
      state.saving = false;
      state.notice = 'APP 过滤规则已删除。';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      const conflict = Number(error.status) === 409 || error.code === 'revision_conflict';
      state.notice = conflict
        ? '配置已被他处修改（版本冲突），删除未执行。页面已刷新到最新配置。'
        : `删除失败：${errorText(error)}`;
      state.noticeTone = conflict ? 'warning' : 'error';
      if (Number(error.status) === 403) state.readOnly = true;
      await load(true);
    }
  }

  /* ---------------- 事件 ---------------- */

  function findRule(id) {
    return blocks().find((rule) => String(rule.id) === String(id)) || null;
  }

  function openDrawer(rule = null) {
    state.draft = defaultDraft(rule);
    state.drawer = true;
    state.appQuery = '';
    state.notice = '';
    renderOverlays();
    loadCatalog();
  }

  function closeDrawer() {
    state.drawer = false;
    state.draft = null;
    state.notice = '';
    renderOverlays();
    patchNotice();
  }

  function scheduleCatalogSearch() {
    window.clearTimeout(state.catalogTimer);
    state.catalogTimer = window.setTimeout(() => loadCatalog(), 260);
  }

  function onClick(event) {
    if (event.target.closest('[data-app-filter-close]')) { closeDrawer(); return; }
    if (event.target.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]')) {
      const pending = state.confirm;
      state.confirm = null;
      /* 从抽屉走过来的确认被取消时，把抽屉还给用户，别丢掉他填的内容。 */
      if (pending?.action === 'app-filter-save' && state.draft && !pending.ruleId) state.drawer = true;
      renderOverlays();
      return;
    }
    if (event.target.closest('[data-dwrt-confirm-accept]')) {
      if (state.confirm?.action === 'app-filter-delete') commitDelete();
      else commitSave();
      return;
    }
    if (event.target.closest('[data-app-filter-create]')) { openDrawer(); return; }
    if (event.target.closest('[data-app-filter-save]')) { validateAndConfirm(); return; }

    const filter = event.target.closest('[data-app-filter-filter]');
    if (filter) {
      state.filter = filter.dataset.appFilterFilter;
      patchTable();
      root.querySelectorAll('[data-app-filter-filter]').forEach((button) => button.classList.toggle('is-active', button.dataset.appFilterFilter === state.filter));
      return;
    }
    const edit = event.target.closest('[data-app-filter-edit]');
    if (edit) { openDrawer(findRule(edit.dataset.appFilterEdit)); return; }
    const toggle = event.target.closest('[data-app-filter-toggle]');
    if (toggle) { requestToggle(findRule(toggle.dataset.appFilterToggle)); return; }
    const remove = event.target.closest('[data-app-filter-delete]');
    if (remove) { requestDelete(findRule(remove.dataset.appFilterDelete)); return; }

    const dropApp = event.target.closest('[data-app-filter-app-remove]');
    if (dropApp && state.draft) {
      const id = Number(dropApp.dataset.appFilterAppRemove);
      state.draft.app_ids = state.draft.app_ids.filter((value) => value !== id);
      const box = document.querySelector(`[data-app-filter-app="${id}"]`);
      if (box) { box.checked = false; box.closest('label')?.classList.remove('is-active'); }
      patchSelected();
      return;
    }
    const addRange = event.target.closest('[data-app-filter-range-add]');
    if (addRange && state.draft) {
      state.draft.ranges = [...draftRanges(state.draft), { weekdays: [1, 2, 3, 4, 5], start_time: '09:00', end_time: '18:00' }];
      renderOverlays();
      return;
    }
    const dropRange = event.target.closest('[data-app-filter-range-remove]');
    if (dropRange && state.draft) {
      const index = Number(dropRange.dataset.appFilterRangeRemove);
      state.draft.ranges = draftRanges(state.draft).filter((_, position) => position !== index);
      if (!state.draft.ranges.length) state.draft.ranges = [{ weekdays: [1, 2, 3, 4, 5], start_time: '09:00', end_time: '18:00' }];
      renderOverlays();
    }
  }

  function onInput(event) {
    const search = event.target.closest('[data-app-filter-search]');
    if (search) { state.query = search.value; patchTable(); return; }
    const appSearch = event.target.closest('[data-app-filter-app-search]');
    if (appSearch) { state.appQuery = appSearch.value; scheduleCatalogSearch(); return; }
    const field = event.target.closest('[data-app-filter-field]');
    if (field && !['checkbox', 'radio'].includes(field.type) && field.tagName !== 'SELECT') {
      updateDraftField(field);
    }
  }

  function updateDraftField(target) {
    if (!state.draft) return;
    const key = target.dataset.appFilterField;
    if (!key) return;
    state.draft[key] = target.type === 'checkbox' ? target.checked : target.value;
    if (key === 'schedule_mode') { renderOverlays(); return; }
    if (key === 'name') patchSelected();
  }

  function onChange(event) {
    const appBox = event.target.closest('[data-app-filter-app]');
    if (appBox && state.draft) {
      const id = Number(appBox.dataset.appFilterApp);
      const selected = new Set(state.draft.app_ids);
      if (appBox.checked) {
        if (selected.size >= maxAppIds()) {
          appBox.checked = false;
          state.notice = `单条规则最多 ${maxAppIds()} 个应用`;
          state.noticeTone = 'warning';
          renderOverlays();
          return;
        }
        selected.add(id);
      } else selected.delete(id);
      state.draft.app_ids = [...selected];
      appBox.closest('label')?.classList.toggle('is-active', appBox.checked);
      patchSelected();
      return;
    }
    const day = event.target.closest('[data-app-filter-day]');
    if (day && state.draft) {
      const index = Number(day.dataset.appFilterRangeIndex);
      const ranges = draftRanges(state.draft).map((range) => ({ ...range, weekdays: [...range.weekdays] }));
      const range = ranges[index];
      if (range) {
        const value = Number(day.dataset.appFilterDay);
        const days = new Set(range.weekdays);
        if (day.checked) days.add(value); else days.delete(value);
        range.weekdays = WEEKDAY_ORDER.filter((entry) => days.has(entry));
        state.draft.ranges = ranges;
        day.closest('label')?.classList.toggle('is-active', day.checked);
        patchSelected();
      }
      return;
    }
    const rangeField = event.target.closest('[data-app-filter-range-field]');
    if (rangeField && state.draft) {
      const index = Number(rangeField.dataset.appFilterRangeIndex);
      const ranges = draftRanges(state.draft).map((range) => ({ ...range, weekdays: [...range.weekdays] }));
      if (ranges[index]) {
        ranges[index][rangeField.dataset.appFilterRangeField] = rangeField.value;
        state.draft.ranges = ranges;
        patchSelected();
      }
      return;
    }
    const field = event.target.closest('[data-app-filter-field]');
    if (field) updateDraftField(field);
  }

  function onKeyDown(event) {
    if (event.key !== 'Escape') return;
    if (state.confirm) { state.confirm = null; if (state.draft && !state.drawer) state.drawer = true; }
    else if (state.drawer) { state.drawer = false; state.draft = null; }
    else return;
    render();
  }

  root?.addEventListener('click', onClick);
  root?.addEventListener('input', onInput);
  root?.addEventListener('change', onChange);
  document.addEventListener('keydown', onKeyDown);
  stage?.classList.add('is-user-authentication');
  render();
  load().then(primeCatalog);

  state.pollTimer = window.setInterval(() => {
    if (!state.mounted || document.hidden) return;
    if (state.loading || state.refreshing || state.saving) return;
    if (state.drawer || state.confirm) return;
    load(true);
  }, 20000);

  return {
    refresh() { return load(true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      window.clearInterval(state.pollTimer);
      window.clearTimeout(state.catalogTimer);
      root?.removeEventListener('click', onClick);
      root?.removeEventListener('input', onInput);
      root?.removeEventListener('change', onChange);
      document.removeEventListener('keydown', onKeyDown);
      /* 路由离开：让 kit 回收本页传送到 portal 的抽屉与遮罩，别把遮罩留给下一页 */
      window.DWRT_UI_KIT?.unmount?.(root);
      root?.replaceChildren();
      root?.classList.remove('route-workspace', 'user-authentication-route-host', 'app-filter-route-host');
      stage?.classList.remove('is-user-authentication');
    }
  };
}

export default { mount };
