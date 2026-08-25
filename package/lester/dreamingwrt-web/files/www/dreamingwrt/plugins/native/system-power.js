export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const VERSION = '20260819-system-power-savebar-01';
  const MODULE_CLASS = 'system-power-route-host';
  const stage = root?.closest('.console-stage');
  const ENDPOINTS = {
    power: '/api/v1/system/power',
    basic: '/api/v1/system/basic',
    dashboardStatus: '/api/v1/dashboard/status',
    reboot: '/api/v1/system/reboot',
    shutdown: '/api/v1/system/shutdown',
    schedules: '/api/v1/system/power/schedules'
  };
  const state = {
    mounted: true,
    seq: 0,
    tab: 'overview',
    loading: true,
    refreshing: false,
    saving: false,
    error: '',
    notice: '',
    uptime: null,
    uptimeMeasuredAt: 0,
    schedulesKnown: false,
    schedules: [],
    scheduleEnabledBaseline: new Map(),
    scheduleEnabledDraft: new Map(),
    saveResults: [],
    capabilities: emptyCapabilities(),
    drawer: '',
    selected: null,
    draft: newDraft(),
    confirm: '',
    confirmDelete: '',
    timer: 0,
    pollTimer: 0
  };

  function emptyCapabilities() {
    return { reboot: false, shutdown: false, scheduleCreate: false, scheduleUpdate: false, scheduleDelete: false };
  }

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }

  function finite(...values) {
    for (const value of values) {
      if (value === undefined || value === null || value === '') continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return null;
  }

  function asArray(value, keys = []) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of [...keys, 'items', 'rows', 'list', 'data']) if (Array.isArray(value[key])) return value[key];
    return [];
  }

  function unwrap(value) {
    let current = value?.data ?? value ?? {};
    for (let index = 0; index < 3; index += 1) {
      if (!current || typeof current !== 'object' || Array.isArray(current) || !current.data || typeof current.data !== 'object') break;
      current = current.data;
    }
    return current || {};
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
    return { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}), ...extra };
  }

  async function requestJson(url, options = {}) {
    const response = await sessionFetch(`${url}${url.includes('?') ? '&' : '?'}v=${encodeURIComponent(VERSION)}`, {
      credentials: 'same-origin',
      cache: 'no-store',
      ...options,
      headers: authHeaders({ Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    if (!response.ok || json?.ok === false) {
      const error = new Error(firstText(json?.error?.message, json?.error?.code, json?.message, json?.code, `HTTP ${response.status}`));
      error.status = response.status;
      throw error;
    }
    return unwrap(json);
  }

  function boolCapability(caps, ...keys) {
    return keys.some((key) => caps?.[key] === true || caps?.[key] === 1 || String(caps?.[key]).toLowerCase() === 'true');
  }

  // Distinguish "not implemented" from session, permission and backend faults so the
  // page never reports a delivered capability as missing.
  function unavailabilityMessage(error, subject) {
    const status = Number(error?.status) || 0;
    if (status === 404 || status === 405 || status === 501) return `${subject}接口未实现（HTTP ${status}）。`;
    if (status === 401) return '会话已失效，请重新登录后查看电源计划。';
    if (status === 403) return '当前账号没有查看电源计划的权限。';
    if (status >= 500) return `${subject}读取失败：后端错误 HTTP ${status}。`;
    if (status) return `${subject}读取失败：HTTP ${status}。`;
    return `${subject}读取失败：${firstText(error?.message, '网络不可用')}。`;
  }

  function normalizeCapabilities(payload = {}) {
    const caps = payload.capabilities && typeof payload.capabilities === 'object' ? payload.capabilities : {};
    return {
      reboot: boolCapability(caps, 'reboot', 'system_reboot'),
      shutdown: boolCapability(caps, 'shutdown', 'poweroff', 'system_shutdown'),
      scheduleCreate: boolCapability(caps, 'schedule_create', 'power_schedule_create'),
      scheduleUpdate: boolCapability(caps, 'schedule_update', 'power_schedule_update'),
      scheduleDelete: boolCapability(caps, 'schedule_delete', 'power_schedule_delete')
    };
  }

  function normalizeTimestamp(...values) {
    const value = finite(...values);
    if (value === null || value <= 0) return null;
    return value < 100000000000 ? value * 1000 : value;
  }

  function normalizeSchedule(item = {}, index = 0) {
    const period = firstText(item.period, item.cycle, item.frequency, item.schedule_type, 'once').toLowerCase();
    const weekdays = asArray(item.weekdays || item.days_of_week).map(Number).filter((value) => Number.isInteger(value) && value >= 0 && value <= 6);
    return {
      id: firstText(item.id, item.uuid, item.schedule_id, `schedule-${index + 1}`),
      name: firstText(item.name, item.label, `计划 ${index + 1}`),
      event: firstText(item.event, item.action, 'reboot').toLowerCase(),
      period,
      date: firstText(item.date, item.run_date),
      time: firstText(item.time, item.run_time, '00:00').slice(0, 5),
      weekdays,
      monthDay: finite(item.month_day, item.day_of_month),
      note: firstText(item.note, item.remark, item.description),
      enabled: item.enabled !== false && item.enabled !== 0 && String(item.status).toLowerCase() !== 'disabled',
      nextRun: normalizeTimestamp(item.next_run_at, item.next_execution, item.next_run),
      raw: item
    };
  }

  function findUptime(payload = {}) {
    const system = payload.system && typeof payload.system === 'object' ? payload.system : {};
    const nestedSystem = system.system && typeof system.system === 'object' ? system.system : {};
    const status = payload.status && typeof payload.status === 'object' ? payload.status : {};
    const uptime = finite(payload.uptime, payload.uptime_seconds, system.uptime, system.uptime_seconds, nestedSystem.uptime, nestedSystem.uptime_seconds, status.uptime, status.uptime_seconds);
    if (uptime !== null && uptime >= 0) return uptime;
    const boot = normalizeTimestamp(payload.boot_time, payload.booted_at, system.boot_time, system.booted_at, nestedSystem.boot_time, nestedSystem.booted_at);
    return boot === null ? null : Math.max(0, (Date.now() - boot) / 1000);
  }

  function applyPowerPayload(payload = {}) {
    state.capabilities = normalizeCapabilities(payload);
    const uptime = findUptime(payload);
    if (uptime !== null) {
      state.uptime = uptime;
      state.uptimeMeasuredAt = performance.now();
    }
    const declaredSchedules = Array.isArray(payload.schedules)
      ? payload.schedules
      : Array.isArray(payload.power_schedules)
        ? payload.power_schedules
        : null;
    if (declaredSchedules) {
      state.schedulesKnown = true;
      state.schedules = declaredSchedules.map(normalizeSchedule);
      const baseline = new Map(state.schedules.map((schedule) => [schedule.id, Boolean(schedule.enabled)]));
      state.scheduleEnabledBaseline = baseline;
      Array.from(state.scheduleEnabledDraft.entries()).forEach(([id, enabled]) => {
        if (!baseline.has(id) || baseline.get(id) === enabled) state.scheduleEnabledDraft.delete(id);
      });
    }
  }

  function scheduleEnabled(schedule) {
    return state.scheduleEnabledDraft.has(schedule.id)
      ? state.scheduleEnabledDraft.get(schedule.id)
      : Boolean(schedule.enabled);
  }

  function scheduleEnabledChanges() {
    return Array.from(state.scheduleEnabledDraft.entries()).filter(([id, enabled]) => state.scheduleEnabledBaseline.get(id) !== enabled);
  }

  async function load(background = false) {
    const seq = ++state.seq;
    if (background) state.refreshing = true; else state.loading = true;
    state.error = '';
    const results = await Promise.allSettled([
      requestJson(ENDPOINTS.basic),
      requestJson(ENDPOINTS.dashboardStatus)
    ]);
    if (!state.mounted || seq !== state.seq) return;
    const [basicResult, dashboardStatusResult] = results;
    const fallbackPayloads = [basicResult, dashboardStatusResult].filter((result) => result.status === 'fulfilled').map((result) => result.value);
    let dashboardUptime = dashboardStatusResult.status === 'fulfilled' ? findUptime(dashboardStatusResult.value) : null;
    if (dashboardUptime === null) {
      try {
        const retryPayload = await requestJson(ENDPOINTS.dashboardStatus);
        if (!state.mounted || seq !== state.seq) return;
        dashboardUptime = findUptime(retryPayload);
      } catch (_) {}
    }
    const basicUptime = basicResult.status === 'fulfilled' ? findUptime(basicResult.value) : null;
    const uptime = dashboardUptime !== null ? dashboardUptime : basicUptime;
    if (uptime !== null) {
      state.uptime = uptime;
      state.uptimeMeasuredAt = performance.now();
    }
    // `/api/v1/system/power` owns the authoritative power capabilities and the
    // `schedules` array, so it is requested unconditionally. Gating it behind the
    // `system/basic` auth-state capabilities used to hide a delivered feature
    // whenever that batch was absent.
    let powerReachable = false;
    try {
      const powerPayload = await requestJson(ENDPOINTS.power);
      if (!state.mounted || seq !== state.seq) return;
      applyPowerPayload(powerPayload);
      powerReachable = true;
    } catch (error) {
      state.capabilities = emptyCapabilities();
      state.schedulesKnown = false;
      state.schedules = [];
      state.error = unavailabilityMessage(error, '电源计划');
    }
    if (!powerReachable && fallbackPayloads.length === 0) state.error = '系统状态与电源计划接口均不可用。';
    state.loading = false;
    state.refreshing = false;
    if (background) renderPreservingInteraction(); else render();
  }

  function icon(name) {
    if (name === 'restart') return '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0056d6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-rotate-ccw-icon lucide-rotate-ccw" aria-hidden="true"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"></path><path d="M3 3v5h5"></path></svg>';
    const paths = {
      power: '<path d="M12 2v10"></path><path d="M18.4 6.6a9 9 0 1 1-12.77.04"></path>',
      clock: '<circle cx="12" cy="12" r="9"></circle><path d="M12 7v5l3 2"></path>',
      calendar: '<rect x="3" y="5" width="18" height="16" rx="2"></rect><path d="M16 3v4M8 3v4M3 10h18"></path>',
      list: '<path d="M8 6h13M8 12h13M8 18h13"></path><path d="M3 6h.01M3 12h.01M3 18h.01"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      edit: '<path d="M12 20h9"></path><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L8 18l-4 1 1-4Z"></path>',
      trash: '<path d="M3 6h18M8 6V4h8v2M19 6l-1 15H6L5 6M10 11v6M14 11v6"></path>',
      close: '<path d="m6 6 12 12M18 6 6 18"></path>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.power}</svg>`;
  }

  function currentUptime() {
    if (state.uptime === null) return null;
    return Math.max(0, state.uptime + (performance.now() - state.uptimeMeasuredAt) / 1000);
  }

  function formatUptime(value) {
    if (value === null || !Number.isFinite(value)) return '--';
    const seconds = Math.max(0, Math.floor(value));
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor(seconds % 86400 / 3600);
    const minutes = Math.floor(seconds % 3600 / 60);
    const remainder = seconds % 60;
    if (days) return `${days}天 ${hours}小时`;
    if (hours) return `${hours}小时 ${minutes}分`;
    return `${minutes}分 ${remainder}秒`;
  }

  function formatDateTime(value) {
    if (!value) return '--';
    const date = new Date(value);
    if (!Number.isFinite(date.getTime())) return '--';
    return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).format(date);
  }

  function nextSchedule() {
    return state.schedules.filter((item) => scheduleEnabled(item) && item.nextRun).sort((left, right) => left.nextRun - right.nextRun)[0] || null;
  }

  function summaryMarkup() {
    const renderer = ui.overviewCardsMarkup || window.DWRT_UI_KIT?.overviewCardsMarkup;
    const next = nextSchedule();
    const cards = [
      { key: 'uptime', label: '运行时间', value: formatUptime(currentUptime()), detail: state.uptime === null ? '等待系统状态接口' : '自本次系统启动', tone: 'info', icon: icon('clock') },
      { key: 'schedule-count', label: '计划条数', value: state.schedulesKnown ? String(state.schedules.length) : '--', detail: state.schedulesKnown ? `${state.schedules.filter((item) => scheduleEnabled(item)).length} 条已启用` : firstText(state.error, '电源计划读取失败'), tone: 'ok', icon: icon('list') },
      { key: 'next-run', label: '下次执行', value: next ? formatDateTime(next.nextRun) : '--', detail: next ? `${eventLabel(next.event)} · ${next.name}` : state.schedulesKnown ? '暂无待执行计划' : firstText(state.error, '电源计划读取失败'), tone: 'warn', icon: icon('calendar') }
    ];
    return typeof renderer === 'function'
      ? renderer(cards, { label: '电源状态概览', className: 'system-power-summary' })
      : `<section class="dwrt-kit-overview-grid system-power-summary">${cards.map((card) => `<article class="dwrt-kit-overview-card is-${card.tone}"><div class="dwrt-kit-overview-content"><span class="dwrt-kit-overview-label">${card.label}</span><strong>${card.value}</strong><small>${card.detail}</small></div><span class="dwrt-kit-overview-icon">${card.icon}</span></article>`).join('')}</section>`;
  }

  function eventLabel(value) {
    return value === 'shutdown' || value === 'poweroff' ? '关机' : '重启';
  }

  function periodLabel(schedule) {
    if (schedule.period === 'daily') return '每天';
    if (schedule.period === 'weekly') return '每周';
    if (schedule.period === 'monthly') return '每月';
    return '一次';
  }

  function dateLabel(schedule) {
    if (schedule.period === 'weekly') {
      const labels = ['周日', '周一', '周二', '周三', '周四', '周五', '周六'];
      return schedule.weekdays.map((day) => labels[day]).join('、') || '--';
    }
    if (schedule.period === 'monthly') return schedule.monthDay ? `每月 ${schedule.monthDay} 日` : '--';
    if (schedule.period === 'daily') return '每天';
    return schedule.date || '--';
  }

  function actionButton(action, label, enabled, iconName) {
    const reason = enabled ? `${label}，需要再次确认` : '等待后端开放对应电源能力';
    return `<button class="system-power-action is-${action}" type="button" data-power-action="${action}" ${enabled && !state.saving ? '' : 'disabled'} title="${reason}">${icon(iconName)}<span>${label}</span></button>`;
  }

  /*
   * 计划页的「添加计划」是控制表格的控件，按用户第 9 条移进表格工具条；
   * 手动刷新按钮删除，改由 startSchedulePolling() 的轮询与写操作后的读回驱动。
   */
  function tabsMarkup() {
    const overviewActions = `<div class="system-power-tab-actions">${actionButton('shutdown', '立即关机', state.capabilities.shutdown, 'power')}${actionButton('reboot', '立即重启', state.capabilities.reboot, 'restart')}</div>`;
    return `<header class="system-power-navigation"><div class="dwrt-kit-tabs dwrt-kit-page-tabs" role="tablist" aria-label="关机和重启页面"><button class="dwrt-kit-tab ${state.tab === 'overview' ? 'is-active' : ''}" type="button" data-power-tab="overview" aria-selected="${state.tab === 'overview'}">概览</button><button class="dwrt-kit-tab ${state.tab === 'schedules' ? 'is-active' : ''}" type="button" data-power-tab="schedules" aria-selected="${state.tab === 'schedules'}">计划</button></div>${state.tab === 'overview' ? overviewActions : ''}</header>`;
  }

  function noticeMarkup() {
    const text = state.notice || state.error;
    if (!text) return '';
    return `<div class="system-power-notice ${state.notice ? 'is-result' : ''}">${escapeHtml(text)}</div>`;
  }

  function overviewMarkup() {
    return `<main class="system-power-overview">${summaryMarkup()}</main>`;
  }

  function scheduleRow(schedule) {
    const enabled = scheduleEnabled(schedule);
    return `<tr><td class="system-power-check-cell"><input type="checkbox" aria-label="选择 ${escapeHtml(schedule.name)}"></td><td><button class="system-power-name" type="button" data-power-edit="${escapeHtml(schedule.id)}">${escapeHtml(schedule.name)}</button></td><td><span class="system-power-event is-${schedule.event === 'shutdown' ? 'shutdown' : 'reboot'}">${eventLabel(schedule.event)}</span></td><td>${periodLabel(schedule)}</td><td>${escapeHtml(dateLabel(schedule))}</td><td><code>${escapeHtml(schedule.time || '--')}</code></td><td class="system-power-note">${escapeHtml(schedule.note || '--')}</td><td><label class="system-power-switch dwrt-kit-switch" data-dwrt-component="switch"><input type="checkbox" data-power-toggle="${escapeHtml(schedule.id)}" ${enabled ? 'checked' : ''} ${state.capabilities.scheduleUpdate && !state.saving ? '' : 'disabled'}><span>${enabled ? '启用' : '停用'}</span></label></td><td><div class="system-power-row-actions"><button type="button" data-power-edit="${escapeHtml(schedule.id)}" title="编辑计划">${icon('edit')}</button><button class="is-danger" type="button" data-power-delete="${escapeHtml(schedule.id)}" title="删除计划" ${state.capabilities.scheduleDelete && !state.saving ? '' : 'disabled'}>${icon('trash')}</button></div></td></tr>`;
  }

  function savebarMarkup() {
    const changes = scheduleEnabledChanges();
    return ui.floatingSavebarMarkup?.({
      visible: changes.length > 0 || state.saving,
      message: state.saving ? '正在保存电源计划状态…' : `${changes.length} 条电源计划状态待保存`,
      busy: state.saving,
      disabled: !changes.length || !state.capabilities.scheduleUpdate,
      discardLabel: '撤销更改',
      saveLabel: '保存并应用'
    }) || '';
  }

  function schedulesMarkup() {
    let body = '';
    if (state.loading) body = '<tr><td colspan="9" class="dwrt-kit-table-empty">正在读取电源计划</td></tr>';
    else if (!state.schedulesKnown) body = `<tr><td colspan="9" class="dwrt-kit-table-empty">${escapeHtml(firstText(state.error, '电源计划读取失败'))}</td></tr>`;
    else if (!state.schedules.length) body = '<tr><td colspan="9" class="dwrt-kit-table-empty">暂无关机或重启计划</td></tr>';
    else body = state.schedules.map(scheduleRow).join('');
    return `<main class="system-power-schedules"><section class="system-power-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><span class="dwrt-kit-table-count">${state.schedulesKnown ? `${state.schedules.length} 条` : '--'}</span></div><div class="system-power-tab-actions"><button class="policy-create-button" type="button" data-power-add>${icon('plus')}<span>添加计划</span></button></div></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table system-power-table"><thead><tr><th class="system-power-check-cell"><input type="checkbox" aria-label="全选计划"></th><th>名称</th><th>计划事件</th><th>周期</th><th>日期</th><th>时间</th><th>备注</th><th>状态</th><th>操作</th></tr></thead><tbody>${body}</tbody></table></div></section></main>`;
  }

  function todayValue() {
    const date = new Date();
    date.setDate(date.getDate() + 1);
    return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
  }

  function newDraft() {
    return { name: '', event: 'reboot', period: 'once', date: todayValue(), time: '00:00', weekdays: [1], month_day: 1, note: '', enabled: true };
  }

  function draftFromSchedule(schedule) {
    return { name: schedule.name, event: schedule.event, period: schedule.period, date: schedule.date || todayValue(), time: schedule.time || '00:00', weekdays: [...schedule.weekdays], month_day: schedule.monthDay || 1, note: schedule.note, enabled: schedule.enabled };
  }

  function field(label, name, value, options = {}) {
    const required = options.required ? '<b>*</b>' : '';
    const wide = options.wide ? ' is-wide' : '';
    if (options.options) return `<label class="system-power-field${wide}"><span>${label}${required}</span><select data-power-draft="${name}">${options.options.map(([id, text]) => `<option value="${id}" ${String(value) === id ? 'selected' : ''}>${text}</option>`).join('')}</select></label>`;
    if (options.textarea) return `<label class="system-power-field${wide}"><span>${label}${required}<small data-power-note-count>${String(value || '').length} / 64</small></span><textarea data-power-draft="${name}" maxlength="64">${escapeHtml(value)}</textarea></label>`;
    return `<label class="system-power-field${wide}"><span>${label}${required}</span><input data-power-draft="${name}" type="${options.type || 'text'}" value="${escapeHtml(value)}" ${options.min ? `min="${options.min}"` : ''} ${options.max ? `max="${options.max}"` : ''}></label>`;
  }

  function dynamicDateFields() {
    if (state.draft.period === 'weekly') {
      const labels = ['日', '一', '二', '三', '四', '五', '六'];
      return `<fieldset class="system-power-weekdays"><legend>星期 <b>*</b></legend><div>${labels.map((label, day) => `<label><input type="checkbox" data-power-weekday="${day}" ${state.draft.weekdays.includes(day) ? 'checked' : ''}><span>周${label}</span></label>`).join('')}</div></fieldset>`;
    }
    if (state.draft.period === 'monthly') return field('日期', 'month_day', state.draft.month_day, { type: 'number', min: 1, max: 31, required: true });
    if (state.draft.period === 'once') return field('日期', 'date', state.draft.date, { type: 'date', required: true });
    return '';
  }

  function drawerMarkup() {
    if (!state.drawer) return '';
    const editing = Boolean(state.selected);
    const writable = editing ? state.capabilities.scheduleUpdate : state.capabilities.scheduleCreate;
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-power-close aria-label="关闭计划面板"></button><aside class="system-power-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" aria-label="${editing ? '编辑' : '添加'}电源计划"><header class="dwrt-kit-sheet-header"><div><span>POWER SCHEDULE</span><strong>${editing ? '编辑电源计划' : '添加电源计划'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-power-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body system-power-drawer-body"><div class="system-power-form">${field('名称', 'name', state.draft.name, { required: true, wide: true })}${field('计划事件', 'event', state.draft.event, { required: true, options: [['reboot', '重启'], ['shutdown', '关机']], wide: true })}${field('周期', 'period', state.draft.period, { required: true, options: [['once', '一次'], ['daily', '每天'], ['weekly', '每周'], ['monthly', '每月']], wide: true })}${dynamicDateFields()}${field('时间', 'time', state.draft.time, { type: 'time', required: true })}${field('备注', 'note', state.draft.note, { textarea: true, wide: true })}<label class="system-power-enabled dwrt-kit-switch" data-dwrt-component="switch"><span><strong>启用计划</strong><small>保存后进入系统调度队列</small></span><input type="checkbox" data-power-draft="enabled" ${state.draft.enabled ? 'checked' : ''}></label>${!writable ? '<div class="system-power-capability">后端写入能力尚未开放。表单已经就绪，但不会把计划保存到浏览器或原始 crontab。</div>' : ''}${state.notice ? `<div class="system-power-form-notice">${escapeHtml(state.notice)}</div>` : ''}</div></div><footer class="dwrt-kit-sheet-footer"><span></span><div><button class="policy-secondary" type="button" data-power-close>取消</button><button class="policy-primary" type="button" data-power-save ${writable && !state.saving ? '' : 'disabled'}>${state.saving ? '正在保存' : writable ? '保存计划' : '等待后端能力'}</button></div></footer></aside>`;
  }

  function confirmMarkup() {
    if (!state.confirm && !state.confirmDelete) return '';
    const deleting = Boolean(state.confirmDelete);
    const action = deleting ? 'delete' : state.confirm;
    const schedule = deleting ? state.schedules.find((item) => item.id === state.confirmDelete) : null;
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    const options = {
      id: 'system-power-confirm',
      action,
      tone: action === 'reboot' ? 'reboot' : 'danger',
      title: deleting ? '删除电源计划' : state.confirm === 'shutdown' ? '确认立即关机' : '确认立即重启',
      description: deleting ? `计划“${schedule?.name || ''}”将从系统调度器中移除，删除后无法恢复。` : state.confirm === 'shutdown' ? '关机将立即断开当前连接，设备需要通过物理或虚拟化平台重新启动。' : '重启将立即中断当前连接，管理服务会在系统启动完成后恢复。',
      cancelLabel: '取消',
      confirmLabel: state.saving ? '正在提交' : deleting ? '确认删除' : state.confirm === 'shutdown' ? '确认关机' : '确认重启',
      disabled: state.saving,
      icon: icon(deleting ? 'trash' : action === 'shutdown' ? 'power' : 'restart')
    };
    return typeof renderer === 'function' ? renderer(options) : '';
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
    const hasNotice = Boolean(state.notice || state.error);
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', MODULE_CLASS);
    target.innerHTML = `<section class="system-power-shell ${hasNotice ? 'has-notice' : ''}">${tabsMarkup()}${noticeMarkup()}${state.tab === 'overview' ? overviewMarkup() : schedulesMarkup()}${drawerMarkup()}${confirmMarkup()}${savebarMarkup()}</section>`;
    ui.mountAll?.(target);
    patchUptime();
  }

  function patchUptime() {
    const value = root?.querySelector('[data-dwrt-overview-value="uptime"]');
    if (value) value.textContent = formatUptime(currentUptime());
  }

  /* 删掉刷新按钮的前提是数据会自己更新，所以补一条可见性受控的轮询。 */
  function startPolling() {
    stopPolling();
    state.pollTimer = window.setInterval(() => {
      if (!state.mounted) return;
      if (document.hidden) return;
      if (state.loading || state.refreshing || state.saving) return;
      if (state.drawer || state.confirm || state.confirmDelete) return;
      load(true);
    }, 20000);
  }

  function stopPolling() {
    if (!state.pollTimer) return;
    window.clearInterval(state.pollTimer);
    state.pollTimer = 0;
  }

  function openDrawer(schedule = null) {
    state.selected = schedule;
    state.draft = schedule ? draftFromSchedule(schedule) : newDraft();
    state.drawer = schedule ? 'edit' : 'create';
    state.notice = '';
    render();
  }

  function closeTransient() {
    state.drawer = '';
    state.selected = null;
    state.confirm = '';
    state.confirmDelete = '';
    state.notice = '';
    render();
  }

  function validateDraft() {
    if (!firstText(state.draft.name)) return '名称不能为空';
    if (!/^\d{2}:\d{2}$/.test(firstText(state.draft.time))) return '请选择执行时间';
    if (state.draft.period === 'once' && !firstText(state.draft.date)) return '请选择执行日期';
    if (state.draft.period === 'weekly' && !state.draft.weekdays.length) return '请至少选择一个星期';
    const monthDay = Number(state.draft.month_day);
    if (state.draft.period === 'monthly' && (!Number.isInteger(monthDay) || monthDay < 1 || monthDay > 31)) return '每月日期必须是 1 至 31';
    return '';
  }

  function schedulePayload() {
    return {
      name: firstText(state.draft.name),
      event: state.draft.event,
      period: state.draft.period,
      date: state.draft.period === 'once' ? state.draft.date : null,
      time: state.draft.time,
      weekdays: state.draft.period === 'weekly' ? state.draft.weekdays : [],
      month_day: state.draft.period === 'monthly' ? Number(state.draft.month_day) : null,
      note: firstText(state.draft.note).slice(0, 64),
      enabled: Boolean(state.draft.enabled)
    };
  }

  async function saveSchedule() {
    const writable = state.selected ? state.capabilities.scheduleUpdate : state.capabilities.scheduleCreate;
    if (!writable || state.saving) return;
    const validation = validateDraft();
    if (validation) { state.notice = validation; render(); return; }
    state.saving = true;
    state.notice = '';
    render();
    try {
      const url = state.selected ? `${ENDPOINTS.schedules}/${encodeURIComponent(state.selected.id)}` : ENDPOINTS.schedules;
      await requestJson(url, { method: state.selected ? 'PUT' : 'POST', body: JSON.stringify(schedulePayload()) });
      if (!state.mounted) return;
      state.drawer = '';
      state.selected = null;
      state.notice = '电源计划已保存。';
      await load(true);
    } catch (error) {
      if (!state.mounted) return;
      state.notice = `保存失败：${firstText(error.message, 'unknown')}`;
    } finally {
      if (!state.mounted) return;
      state.saving = false;
      render();
    }
  }

  async function saveScheduleToggles() {
    const changes = scheduleEnabledChanges();
    if (!state.capabilities.scheduleUpdate || state.saving || !changes.length) return;
    state.saving = true;
    state.notice = '';
    state.saveResults = [];
    renderPreservingInteraction();
    for (const [id, enabled] of changes) {
      const schedule = state.schedules.find((item) => item.id === id);
      if (!schedule) continue;
      try {
        await requestJson(`${ENDPOINTS.schedules}/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify({ ...schedulePayloadFrom(schedule), enabled }) });
        state.saveResults.push({ id, name: schedule.name, enabled, ok: true });
      } catch (error) {
        state.saveResults.push({ id, name: schedule.name, enabled, ok: false, error: firstText(error.message, 'unknown') });
      }
    }
    await load(true);
    state.saveResults.forEach((result) => {
      if (result.ok && state.scheduleEnabledBaseline.get(result.id) !== result.enabled) {
        result.ok = false;
        result.error = '保存后回读与草稿不一致';
      }
    });
    const failed = state.saveResults.filter((item) => !item.ok);
    state.notice = failed.length
      ? `${state.saveResults.length - failed.length} 条已保存，${failed.length} 条失败并保留草稿：${failed.map((item) => `${item.name}（${item.error}）`).join('、')}`
      : `${state.saveResults.length} 条电源计划状态已保存。`;
    state.saving = false;
    renderPreservingInteraction();
  }

  function schedulePayloadFrom(schedule) {
    return { name: schedule.name, event: schedule.event, period: schedule.period, date: schedule.date || null, time: schedule.time, weekdays: schedule.weekdays, month_day: schedule.monthDay, note: schedule.note, enabled: schedule.enabled };
  }

  async function executeConfirmed() {
    if (state.saving) return;
    if (state.confirmDelete) {
      if (!state.capabilities.scheduleDelete) return;
      state.saving = true;
      render();
      try {
        await requestJson(`${ENDPOINTS.schedules}/${encodeURIComponent(state.confirmDelete)}`, { method: 'DELETE' });
        state.confirmDelete = '';
        state.notice = '电源计划已删除。';
        await load(true);
      } catch (error) {
        state.notice = `删除失败：${firstText(error.message, 'unknown')}`;
      } finally {
        state.saving = false;
        render();
      }
      return;
    }
    const action = state.confirm;
    if (!action || !state.capabilities[action]) return;
    state.saving = true;
    render();
    try {
      await requestJson(ENDPOINTS[action], { method: 'POST', body: JSON.stringify({ confirm: true }) });
      state.notice = action === 'shutdown' ? '关机指令已提交。' : '重启指令已提交。';
      state.confirm = '';
    } catch (error) {
      state.notice = `提交失败：${firstText(error.message, 'unknown')}`;
    } finally {
      state.saving = false;
      render();
    }
  }

  function onClick(event) {
    const tab = event.target.closest('[data-power-tab]');
    if (tab) { state.tab = tab.dataset.powerTab; state.drawer = ''; state.notice = ''; render(); return; }
    if (event.target.closest('[data-power-add]')) { openDrawer(); return; }
    const action = event.target.closest('[data-power-action]');
    if (action && !action.disabled && state.capabilities[action.dataset.powerAction]) { state.confirm = action.dataset.powerAction; render(); return; }
    const edit = event.target.closest('[data-power-edit]');
    if (edit) { const schedule = state.schedules.find((item) => item.id === edit.dataset.powerEdit); if (schedule) openDrawer(schedule); return; }
    const remove = event.target.closest('[data-power-delete]');
    if (remove && !remove.disabled) { state.confirmDelete = remove.dataset.powerDelete; render(); return; }
    if (event.target.closest('[data-power-close], [data-dwrt-confirm-cancel]')) { closeTransient(); return; }
    if (event.target.closest('[data-power-save]')) { saveSchedule(); return; }
    if (event.target.closest('[data-dwrt-savebar-discard]')) { state.scheduleEnabledDraft.clear(); state.saveResults = []; state.notice = ''; renderPreservingInteraction(); return; }
    if (event.target.closest('[data-dwrt-savebar-save]')) { saveScheduleToggles(); return; }
    if (event.target.closest('[data-dwrt-confirm-accept]')) { executeConfirmed(); return; }
  }

  function onInput(event) {
    const draft = event.target.closest('[data-power-draft]');
    if (!draft) return;
    const key = draft.dataset.powerDraft;
    state.draft[key] = draft.type === 'checkbox' ? draft.checked : draft.value;
    if (key === 'note') {
      const count = root?.querySelector('[data-power-note-count]');
      if (count) count.textContent = `${draft.value.length} / 64`;
    }
  }

  function onChange(event) {
    const draft = event.target.closest('[data-power-draft]');
    if (draft?.dataset.powerDraft === 'period') { state.draft.period = draft.value; render(); return; }
    const weekday = event.target.closest('[data-power-weekday]');
    if (weekday) {
      const day = Number(weekday.dataset.powerWeekday);
      if (weekday.checked && !state.draft.weekdays.includes(day)) state.draft.weekdays.push(day);
      if (!weekday.checked) state.draft.weekdays = state.draft.weekdays.filter((value) => value !== day);
      state.draft.weekdays.sort((left, right) => left - right);
      return;
    }
    const toggle = event.target.closest('[data-power-toggle]');
    if (toggle) {
      const schedule = state.schedules.find((item) => item.id === toggle.dataset.powerToggle);
      if (schedule) {
        const baseline = state.scheduleEnabledBaseline.get(schedule.id);
        if (toggle.checked === baseline) state.scheduleEnabledDraft.delete(schedule.id);
        else state.scheduleEnabledDraft.set(schedule.id, toggle.checked);
        state.saveResults = [];
        state.notice = '';
        renderPreservingInteraction();
      }
    }
  }

  root?.addEventListener('click', onClick);
  root?.addEventListener('input', onInput);
  root?.addEventListener('change', onChange);
  stage?.classList.add('is-system-power');
  render();
  load();
  state.timer = window.setInterval(patchUptime, 1000);
  startPolling();

  return {
    refresh() { return load(true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      window.clearInterval(state.timer);
      stopPolling();
      root?.removeEventListener('click', onClick);
      root?.removeEventListener('input', onInput);
      root?.removeEventListener('change', onChange);
      root?.replaceChildren();
      root?.classList.remove('route-workspace', MODULE_CLASS);
      stage?.classList.remove('is-system-power');
    }
  };
}
