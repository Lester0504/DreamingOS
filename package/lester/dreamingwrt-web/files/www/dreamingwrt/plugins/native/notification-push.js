export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));
  const VERSION = '20260722-overlay-01';
  const MODULE_CLASS = 'notification-push-route-host';
  const ENDPOINTS = {
    status: '/api/v1/notifyd/status',
    settings: '/api/v1/notifyd/settings',
    channels: '/api/v1/notifyd/channels',
    routes: '/api/v1/notifyd/routes',
    outbox: '/api/v1/notifyd/outbox',
    retry: '/api/v1/notifyd/outbox/retry',
    test: '/api/v1/notifyd/test-send',
    events: '/api/v1/notifyd/events'
  };
  const TABS = [
    { id: 'overview', label: '概览' },
    { id: 'channels', label: '推送通道' },
    { id: 'routes', label: '路由规则' },
    { id: 'outbox', label: '投递记录' },
    { id: 'settings', label: '基本设置' }
  ];
  const SEVERITY_OPTIONS = [
    { id: 'debug', label: '调试' },
    { id: 'info', label: '信息' },
    { id: 'notice', label: '提醒' },
    { id: 'warning', label: '警告' },
    { id: 'error', label: '错误' },
    { id: 'critical', label: '严重' }
  ];
  const ROUTE_EVENT_GROUPS = [
    {
      id: 'SYSTEM', label: '系统', events: [
        { id: 'SYSTEM_RESOURCE_THRESHOLD', label: '系统资源超过阈值', severity: 'warning' },
        { id: 'SYSTEM_LOG', label: '系统日志', severity: 'info' },
        { id: 'CALLBACKS_SUPPRESSED', label: '重复事件已被抑制', severity: 'notice' },
        { id: 'PACKET_CAPTURE_STARTED', label: '数据包捕获已开始', severity: 'notice' },
        { id: 'PACKET_CAPTURE_STOPPED', label: '数据包捕获已停止', severity: 'notice' },
        { id: 'PACKET_CAPTURE_FINISHED', label: '数据包捕获已完成', severity: 'notice' },
        { id: 'PACKET_CAPTURE_DELETED', label: '数据包捕获已删除', severity: 'notice' }
      ]
    },
    {
      id: 'INTERNET_AND_WAN', label: '互联网与 WAN', events: [
        { id: 'WAN_EVENT', label: 'WAN 状态变化', severity: 'warning' },
        { id: 'PPPOE_EVENT', label: 'PPPoE 状态变化', severity: 'warning' },
        { id: 'PORT_LINK_DOWN', label: '端口链路断开', severity: 'warning' },
        { id: 'PORT_LINK_UP', label: '端口链路恢复', severity: 'notice' },
        { id: 'PORT_EVENT', label: '端口状态变化', severity: 'notice' }
      ]
    },
    {
      id: 'CLIENT_DEVICES', label: '客户端设备', events: [
        { id: 'CLIENT_CONNECTED_WIRED', label: '有线客户端已连接', severity: 'notice' },
        { id: 'CLIENT_DISCONNECTED', label: '客户端已断开', severity: 'notice' },
        { id: 'DHCP_EVENT', label: 'DHCP 租约变化', severity: 'info' }
      ]
    },
    {
      id: 'ADMIN', label: '管理员', events: [
        { id: 'ADMIN_AUTH_EVENT', label: '管理员认证活动', severity: 'warning' }
      ]
    }
  ];
  // Static Chinese labels/severities kept only as a decoration source over
  // the backend event catalog (labels there are English). The catalog is
  // authoritative for which events exist and which are available.
  const EVENT_LABEL_ZH = new Map(ROUTE_EVENT_GROUPS.flatMap((group) => group.events.map((event) => [event.id, { label: event.label, severity: event.severity }])));
  const CATEGORY_LABEL_ZH = new Map(ROUTE_EVENT_GROUPS.map((group) => [group.id, group.label]));

  // Build the route groups from the backend event_catalog when loaded
  // (GET /api/v1/notifyd/events); fall back to the static preset offline.
  // Events carry available/reason so the drawer can gate pending producers.
  function routeGroups() {
    const catalog = state.events && Array.isArray(state.events.events) ? state.events.events : null;
    const categories = state.events && Array.isArray(state.events.categories) ? state.events.categories : null;
    if (!catalog || !categories || !catalog.length) return ROUTE_EVENT_GROUPS;
    return categories.map((category) => ({
      id: category.id,
      label: CATEGORY_LABEL_ZH.get(category.id) || category.label || category.id,
      events: catalog.filter((event) => event.category === category.id).map((event) => {
        const zh = EVENT_LABEL_ZH.get(event.id);
        return {
          id: event.id,
          label: (zh && zh.label) || event.label || event.id,
          severity: (zh && zh.severity) || event.default_severity || 'warning',
          available: event.available !== false,
          reason: event.reason || ''
        };
      })
    })).filter((group) => group.events.length);
  }
  function routeCategoriesMap() { return new Map(routeGroups().map((group) => [group.id, group])); }
  function routeEventsMap() { return new Map(routeGroups().flatMap((group) => group.events.map((event) => [event.id, { ...event, category: group.id, categoryLabel: group.label }]))); }

  const state = {
    mounted: true,
    loading: true,
    error: '',
    status: {},
    settings: {},
    channels: [],
    routes: [],
    outbox: [],
    events: null,
    tab: tabFromLocation(),
    query: '',
    outboxState: 'all',
    drawer: '',
    draft: {},
    saving: false,
    workingId: '',
    notice: '',
    configLoaded: false,
    seq: 0,
    liveSeq: 0,
    timer: 0
  };

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (typeof value === 'object' && !Array.isArray(value)) {
        const nested = firstText(value.name, value.label, value.value, value.id);
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
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return 0;
  }

  function asArray(value, keys = []) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of [...keys, 'items', 'rows', 'data']) {
      if (Array.isArray(value[key])) return value[key];
    }
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

  function authHeaders(extra = {}) {
    let token = '';
    try { token = localStorage.getItem('dreamingwrt.web.accessToken') || ''; } catch (_) {}
    return { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}), ...extra };
  }

  async function requestJson(url, options = {}) {
    const response = await fetch(`${url}${url.includes('?') ? '&' : '?'}v=${encodeURIComponent(VERSION)}`, {
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
      const error = new Error(firstText(json?.error?.message, json?.error?.code, json?.error, json?.message, json?.code, `${response.status}`));
      error.status = response.status;
      error.payload = json;
      throw error;
    }
    return unwrap(json);
  }

  function tabFromLocation() {
    try {
      const fromHash = (window.location.hash.match(/[?&]notifytab=([^&]+)/) || [])[1];
      const value = decodeURIComponent(fromHash || 'overview');
      return TABS.some((tab) => tab.id === value) ? value : 'overview';
    } catch (_) { return 'overview'; }
  }

  function setTab(value) {
    state.tab = TABS.some((tab) => tab.id === value) ? value : 'overview';
  }

  function normalizeChannel(value = {}, index = 0) {
    const options = value.options && typeof value.options === 'object' ? value.options : {};
    const hasStoredHeaders = Boolean(options.headers && typeof options.headers === 'object' && Object.keys(options.headers).length);
    return {
      id: firstText(value.id, value.channel_id, `channel-${index + 1}`),
      name: firstText(value.name, value.label, value.id, `通道 ${index + 1}`),
      type: firstText(value.type, 'noop').toLowerCase(),
      enabled: value.enabled !== false && value.enabled !== 0,
      options: { ...options, headers: undefined },
      hasStoredHeaders,
      updatedAt: firstNumber(value.updated_at)
    };
  }

  function normalizeRoute(value = {}, index = 0) {
    return {
      id: firstText(value.id, value.route_id, `route-${index + 1}`),
      name: firstText(value.name, value.label, value.id, `规则 ${index + 1}`),
      enabled: value.enabled !== false && value.enabled !== 0,
      channelId: firstText(value.channel_id, 'local'),
      minSeverity: firstText(value.min_severity, 'warning'),
      category: firstText(value.category),
      event: firstText(value.event),
      source: firstText(value.source),
      options: value.options && typeof value.options === 'object' ? value.options : {},
      updatedAt: firstNumber(value.updated_at),
      raw: value
    };
  }

  function categoryLabel(value) {
    if (!value) return '全部分类';
    return routeCategoriesMap().get(value)?.label || ({ SECURITY: '安全', VPN: 'VPN' })[value] || value;
  }

  function eventLabel(value) {
    if (!value) return '全部事件';
    return routeEventsMap().get(value)?.label || value;
  }

  function severityLabel(value) {
    return SEVERITY_OPTIONS.find((item) => item.id === value)?.label || value || '--';
  }

  function normalizeOutbox(value = {}, index = 0) {
    return {
      id: firstText(value.id, value.outbox_id, `outbox-${index + 1}`),
      createdAt: firstNumber(value.created_at),
      updatedAt: firstNumber(value.updated_at),
      nextAttemptAt: firstNumber(value.next_attempt_at),
      channelId: firstText(value.channel_id),
      routeId: firstText(value.route_id),
      severity: firstText(value.severity, 'info'),
      category: firstText(value.category),
      event: firstText(value.event),
      source: firstText(value.source),
      title: firstText(value.title, value.event, '通知'),
      state: firstText(value.state, 'pending').toLowerCase(),
      attempts: firstNumber(value.attempts),
      maxAttempts: firstNumber(value.max_attempts),
      lastError: firstText(value.last_error),
      httpStatus: firstNumber(value.last_http_status),
      count: Math.max(1, firstNumber(value.count, 1)),
      raw: value
    };
  }

  async function load(options = {}) {
    const seq = ++state.seq;
    if (!options.silent) { state.loading = true; state.error = ''; render(); }
    const results = await Promise.allSettled([
      requestJson(ENDPOINTS.status),
      requestJson(ENDPOINTS.settings),
      requestJson(ENDPOINTS.channels),
      requestJson(ENDPOINTS.routes),
      requestJson(`${ENDPOINTS.outbox}?limit=200`),
      requestJson(ENDPOINTS.events)
    ]);
    if (!state.mounted || seq !== state.seq) return;
    const [status, settings, channels, routes, outbox, events] = results;
    if (status.status === 'fulfilled') state.status = status.value;
    if (settings.status === 'fulfilled') state.settings = settings.value;
    if (channels.status === 'fulfilled') state.channels = asArray(channels.value.channels || channels.value, ['channels']).map(normalizeChannel);
    if (routes.status === 'fulfilled') state.routes = asArray(routes.value.routes || routes.value, ['routes']).map(normalizeRoute);
    if (outbox.status === 'fulfilled') state.outbox = asArray(outbox.value.items || outbox.value, ['items']).map(normalizeOutbox);
    if (events.status === 'fulfilled') { const ev = events.value && events.value.data ? events.value.data : events.value; if (ev && Array.isArray(ev.events)) state.events = ev; }
    const failures = results.filter((result) => result.status === 'rejected').map((result) => firstText(result.reason?.message));
    state.configLoaded = settings.status === 'fulfilled' && channels.status === 'fulfilled' && routes.status === 'fulfilled';
    state.error = failures.length ? `部分数据读取失败：${failures.join(' · ')}` : '';
    state.loading = false;
    if (document.activeElement?.matches('[data-notify-search]')) patchSearchResults();
    else if (!options.silent || failures.length) render();
    else patchLiveSummary();
  }

  async function refreshLive() {
    if (!state.mounted || state.drawer) return;
    if (!state.configLoaded) {
      await load();
      return;
    }
    const seq = ++state.liveSeq;
    const hadError = Boolean(state.error);
    const results = await Promise.allSettled([
      requestJson(ENDPOINTS.status),
      requestJson(`${ENDPOINTS.outbox}?limit=200`)
    ]);
    if (!state.mounted || seq !== state.liveSeq) return;
    const [status, outbox] = results;
    if (status.status === 'fulfilled') state.status = status.value;
    if (outbox.status === 'fulfilled') state.outbox = asArray(outbox.value.items || outbox.value, ['items']).map(normalizeOutbox);
    const failures = results.filter((result) => result.status === 'rejected').map((result) => firstText(result.reason?.message));
    state.error = failures.length ? `实时状态读取失败：${failures.join(' · ')}` : '';
    if (hadError !== Boolean(state.error)) {
      if (document.activeElement?.matches('[data-notify-search]')) patchSearchResults();
      else render();
    }
    else patchLiveSummary();
  }

  function icon(name) {
    const paths = {
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      send: '<path d="m22 2-7 20-4-9-9-4 20-7Z"></path><path d="M22 2 11 13"></path>',
      edit: '<path d="m4 20 4.3-1 10.8-10.8a2 2 0 0 0-2.8-2.8L5.5 16.2 4 20Z"></path>',
      retry: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      service: '<path d="M12 3v9"></path><path d="M7.1 5.7a8 8 0 1 0 9.8 0"></path>',
      channels: '<path d="M4 7a3 3 0 1 1 3 3H4V7Z"></path><path d="M20 17a3 3 0 1 0-3-3h3v3Z"></path><path d="M7 7h10v7"></path>',
      delivered: '<path d="M4 12.5 9 17l11-12"></path>',
      failed: '<path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.7 2.5 17.2A2 2 0 0 0 4.2 20h15.6a2 2 0 0 0 1.7-2.8L13.7 3.7a2 2 0 0 0-3.4 0Z"></path>',
      mail: '<rect x="3" y="5" width="18" height="14" rx="2"></rect><path d="m3 7 9 6 9-6"></path>'
    };
    return `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.bell}</svg>`;
  }

  function formatTime(value) {
    const raw = Number(value) || 0;
    if (!raw) return '--';
    const timestamp = raw < 100000000000 ? raw * 1000 : raw;
    return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(timestamp);
  }

  function overviewCards() {
    const status = state.status || {};
    const activeChannels = firstNumber(status.active_channels, state.channels.filter((item) => item.enabled).length);
    const activeRoutes = firstNumber(status.active_routes, state.routes.filter((item) => item.enabled).length);
    const pending = firstNumber(status.pending) + firstNumber(status.retry);
    const failed = firstNumber(status.failed);
    const latestFailure = state.outbox.find((item) => item.state === 'failed' && item.lastError);
    const defaultChannel = state.channels.find((item) => item.id === state.settings.default_channel_id);
    return [
      { key: 'service', label: '通知服务', value: status.enabled === false ? '已停用' : '运行中', detail: `${activeRoutes} 条有效路由`, tone: status.enabled === false ? 'warn' : 'ok', icon: icon('service') },
      { key: 'channels', label: '推送通道', value: `${activeChannels} / ${state.channels.length}`, detail: `默认：${firstText(defaultChannel?.name, state.settings.default_channel_id, '--')}`, tone: activeChannels ? 'info' : 'warn', icon: icon('channels') },
      { key: 'delivered', label: '已送达', value: firstNumber(status.delivered), detail: pending ? `${pending} 条等待投递` : '队列无积压', tone: pending ? 'warn' : 'ok', icon: icon('delivered') },
      { key: 'failed', label: '投递失败', value: failed, detail: latestFailure?.lastError || '最近没有投递错误', tone: failed ? 'bad' : 'neutral', icon: icon('failed') }
    ];
  }

  function renderSummary(force = false) {
    if (!force) return '';
    const renderer = ui.overviewCardsMarkup || window.DWRT_UI_KIT?.overviewCardsMarkup;
    if (typeof renderer === 'function') return renderer(overviewCards(), { className: 'notification-push-summary', label: '通知推送概览' });
    return '';
  }

  function filteredChannels() {
    const query = state.query.trim().toLowerCase();
    return state.channels.filter((item) => !query || [item.name, item.id, item.type, item.options.url, asArray(item.options.user_ids).join(' '), asArray(item.options.recipients).join(' ')].join(' ').toLowerCase().includes(query));
  }

  function filteredRoutes() {
    const query = state.query.trim().toLowerCase();
    return state.routes.filter((item) => !query || [item.name, item.id, item.channelId, item.minSeverity, item.category, item.event, item.source].join(' ').toLowerCase().includes(query));
  }

  function filteredOutbox() {
    const query = state.query.trim().toLowerCase();
    return state.outbox.filter((item) => (state.outboxState === 'all' || item.state === state.outboxState) && (!query || [item.title, item.id, item.channelId, item.routeId, item.severity, item.category, item.event, item.source, item.lastError].join(' ').toLowerCase().includes(query)));
  }

  function stateLabel(value) {
    return ({ pending: '待处理', retry: '重试中', failed: '失败', delivered: '已送达' })[value] || value || '--';
  }

  function channelTypeLabel(type) {
    return ({ noop: '本地队列', webhook: 'Webhook', email: '邮件' })[type] || type || '--';
  }

  function channelLabel(id) {
    return state.channels.find((channel) => channel.id === id)?.name || id || '--';
  }

  function channelTarget(item) {
    if (item.type === 'webhook') return firstText(item.options.url, '--');
    if (item.type === 'email') {
      const users = asArray(item.options.user_ids || item.options.users).length;
      const recipients = asArray(item.options.recipients || item.options.to).length;
      return users || recipients ? `${users} 位用户 · ${recipients} 个额外地址` : '用户邮箱';
    }
    return '本地队列';
  }

  function emailSupported() {
    const types = asArray(state.status?.capabilities?.channel_types || state.status?.channel_types).map((value) => firstText(value).toLowerCase());
    return types.includes('email');
  }

  function renderToolbar() {
    if (state.tab === 'overview' || state.tab === 'settings') {
      return `<div class="policy-toolbar notification-push-toolbar is-compact"><div class="policy-toolbar-actions notification-push-actions"><button class="policy-filter-button" type="button" data-notify-refresh>${icon('refresh')}<span>刷新</span></button></div></div>`;
    }
    const createLabel = state.tab === 'channels' ? '新建通道' : state.tab === 'routes' ? '新建规则' : '';
    return `<div class="policy-toolbar notification-push-toolbar"><label class="policy-search policy-search-main" data-dwrt-component="expand-search">${icon('search')}<input type="search" data-notify-search placeholder="搜索当前视图" value="${escapeHtml(state.query)}"></label><div class="policy-toolbar-actions notification-push-actions">${state.tab === 'outbox' ? `<label class="notification-push-filter"><span>状态</span><select data-notify-state><option value="all">全部</option>${['pending','retry','failed','delivered'].map((value) => `<option value="${value}" ${state.outboxState === value ? 'selected' : ''}>${stateLabel(value)}</option>`).join('')}</select></label>` : ''}<button class="policy-filter-button" type="button" data-notify-refresh>${icon('refresh')}<span>刷新</span></button>${createLabel ? `<button class="policy-create-button" type="button" data-notify-create="${escapeHtml(state.tab)}">${icon('plus')}<span>${createLabel}</span></button>` : ''}</div></div>`;
  }

  function channelTable() {
    const rows = filteredChannels();
    return `<section class="notification-push-table-card dwrt-kit-table-wrap dwrt-kit-datatable-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>推送通道</strong><span>本地队列、Webhook 与邮件投递</span></div><span class="dwrt-kit-table-count">${rows.length} 个通道</span></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-datatable notification-channel-table"><thead><tr><th>名称</th><th>类型</th><th>状态</th><th>目标</th><th>更新时间</th><th>操作</th></tr></thead><tbody>${rows.length ? rows.map((item) => `<tr><td><button class="notification-name-button" type="button" data-notify-edit-channel="${escapeHtml(item.id)}"><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.id)}</small></button></td><td>${escapeHtml(channelTypeLabel(item.type))}</td><td>${ui.statusBadgeMarkup?.(item.enabled ? '启用' : '停用', item.enabled ? 'success' : 'error') || ''}</td><td><span class="notification-target">${escapeHtml(channelTarget(item))}</span></td><td><time>${escapeHtml(formatTime(item.updatedAt))}</time></td><td><div class="notification-row-actions"><button type="button" data-notify-test="${escapeHtml(item.id)}" aria-label="测试发送">${icon('send')}</button><button type="button" data-notify-edit-channel="${escapeHtml(item.id)}" aria-label="编辑">${icon('edit')}</button></div></td></tr>`).join('') : '<tr><td colspan="6" class="dwrt-kit-table-empty">暂无推送通道</td></tr>'}</tbody></table></div></section>`;
  }

  function routeTable() {
    const rows = filteredRoutes();
    return `<section class="notification-push-table-card dwrt-kit-table-wrap dwrt-kit-datatable-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>路由规则</strong><span>按事件类型和严重级别将通知送往指定通道</span></div><span class="dwrt-kit-table-count">${rows.length} 条规则</span></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-datatable notification-route-table"><thead><tr><th>名称</th><th>状态</th><th>通道</th><th>最低级别</th><th>分类</th><th>事件</th><th>来源</th><th>操作</th></tr></thead><tbody>${rows.length ? rows.map((item) => `<tr><td><button class="notification-name-button" type="button" data-notify-edit-route="${escapeHtml(item.id)}"><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.id)}</small></button></td><td>${ui.statusBadgeMarkup?.(item.enabled ? '启用' : '停用', item.enabled ? 'success' : 'error') || ''}</td><td>${escapeHtml(channelLabel(item.channelId))}</td><td><span class="notification-severity is-${escapeHtml(item.minSeverity)}">${escapeHtml(severityLabel(item.minSeverity))}</span></td><td>${escapeHtml(categoryLabel(item.category))}</td><td>${escapeHtml(eventLabel(item.event))}</td><td>${escapeHtml(item.source || '全部来源')}</td><td><div class="notification-row-actions"><button type="button" data-notify-edit-route="${escapeHtml(item.id)}" aria-label="编辑">${icon('edit')}</button></div></td></tr>`).join('') : '<tr><td colspan="8" class="dwrt-kit-table-empty">暂无路由规则</td></tr>'}</tbody></table></div></section>`;
  }

  function outboxTable() {
    const rows = filteredOutbox();
    return `<section class="notification-push-table-card dwrt-kit-table-wrap dwrt-kit-datatable-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>投递记录</strong><span>失败记录可重新进入投递队列</span></div><span class="dwrt-kit-table-count">${rows.length} 条记录</span></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-datatable notification-outbox-table"><thead><tr><th>时间</th><th>通知</th><th>状态</th><th>通道 / 规则</th><th>尝试</th><th>HTTP</th><th>错误</th><th>操作</th></tr></thead><tbody>${rows.length ? rows.map((item) => { const tone = item.state === 'delivered' ? 'success' : item.state === 'failed' ? 'error' : item.state === 'retry' ? 'warning' : 'info'; return `<tr><td><time>${escapeHtml(formatTime(item.createdAt))}</time></td><td><span class="notification-outbox-title"><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml([item.severity, item.category, item.event].filter(Boolean).join(' · '))}</small></span></td><td>${ui.statusBadgeMarkup?.(stateLabel(item.state), tone) || ''}</td><td>${escapeHtml([item.channelId, item.routeId].filter(Boolean).join(' · ') || '--')}</td><td>${item.attempts} / ${item.maxAttempts || '--'}${item.count > 1 ? ` · ×${item.count}` : ''}</td><td>${item.httpStatus || '--'}</td><td><span class="notification-target">${escapeHtml(item.lastError || '--')}</span></td><td><div class="notification-row-actions"><button type="button" data-notify-retry="${escapeHtml(item.id)}" ${['failed','retry'].includes(item.state) && state.workingId !== item.id ? '' : 'disabled'} aria-label="重试">${icon('retry')}</button></div></td></tr>`; }).join('') : '<tr><td colspan="8" class="dwrt-kit-table-empty">暂无投递记录</td></tr>'}</tbody></table></div></section>`;
  }

  function settingsPanel() {
    const settings = state.settings || {};
    const smtp = settings.smtp && typeof settings.smtp === 'object' ? settings.smtp : {};
    const canEmail = emailSupported();
    return `<form class="notification-settings-stack" data-notify-settings-form>
      <section class="notification-settings-panel dwrt-kit-glass-surface"><header><div><strong>投递设置</strong><span>控制通知服务与失败重试节奏</span></div>${ui.statusBadgeMarkup?.(settings.enabled !== false ? '启用' : '停用', settings.enabled !== false ? 'success' : 'error') || ''}</header><div class="notification-settings-grid"><label class="notification-switch-field"><span><strong>启用通知推送</strong><small>关闭后保留配置，但不再分发新通知</small></span><input type="checkbox" data-notify-setting="enabled" ${settings.enabled !== false ? 'checked' : ''}><i></i></label><label><span>默认通道</span><select data-notify-setting="default_channel_id">${state.channels.map((channel) => `<option value="${escapeHtml(channel.id)}" ${settings.default_channel_id === channel.id ? 'selected' : ''}>${escapeHtml(channel.name)}</option>`).join('')}</select></label><label><span>最大尝试次数</span><input type="number" min="1" max="20" data-notify-setting="max_attempts" value="${escapeHtml(firstNumber(settings.max_attempts, 3))}"></label><label><span>首次重试间隔（秒）</span><input type="number" min="1" max="86400" data-notify-setting="retry_base_s" value="${escapeHtml(firstNumber(settings.retry_base_s, 60))}"></label><label><span>最大重试间隔（秒）</span><input type="number" min="1" max="86400" data-notify-setting="retry_max_s" value="${escapeHtml(firstNumber(settings.retry_max_s, 3600))}"></label></div></section>
      <section class="notification-settings-panel notification-mail-settings dwrt-kit-glass-surface"><header><div><strong>邮件发件</strong><span>向用户资料中的邮箱或额外收件地址投递</span></div><span class="notification-capability ${canEmail ? 'is-ready' : ''}">${canEmail ? '可用' : '后端待接入'}</span></header><div class="notification-settings-grid"><label><span>SMTP 服务器</span><input type="text" data-notify-setting="smtp_host" value="${escapeHtml(firstText(smtp.host))}" placeholder="smtp.example.com" ${canEmail ? '' : 'disabled'}></label><label><span>端口</span><input type="number" min="1" max="65535" data-notify-setting="smtp_port" value="${escapeHtml(firstNumber(smtp.port, 465))}" ${canEmail ? '' : 'disabled'}></label><label><span>加密方式</span><select data-notify-setting="smtp_security" ${canEmail ? '' : 'disabled'}>${['ssl','starttls','none'].map((value) => `<option value="${value}" ${firstText(smtp.security, 'ssl') === value ? 'selected' : ''}>${value === 'ssl' ? 'SSL/TLS' : value === 'starttls' ? 'STARTTLS' : '无'}</option>`).join('')}</select></label><label><span>发件地址</span><input type="email" data-notify-setting="smtp_from" value="${escapeHtml(firstText(smtp.from))}" placeholder="router@example.com" ${canEmail ? '' : 'disabled'}></label><label><span>用户名</span><input type="text" data-notify-setting="smtp_username" value="${escapeHtml(firstText(smtp.username))}" autocomplete="off" ${canEmail ? '' : 'disabled'}></label><label><span>密码</span><input type="password" data-notify-setting="smtp_password" value="" placeholder="${smtp.password_present ? '已保存，留空保持不变' : 'SMTP 密码'}" autocomplete="new-password" ${canEmail ? '' : 'disabled'}></label></div><div class="notification-mail-note">邮件通道以用户 ID 绑定收件人，实际地址由后端读取用户目录；Outbox 与日志不得保存 SMTP 密码或完整邮件正文。</div></section>
      <footer class="notification-settings-actions"><span>${escapeHtml(state.notice || '')}</span><button class="policy-primary" type="button" data-notify-save-settings ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存设置'}</button></footer>
    </form>`;
  }

  function overviewPanel() {
    const status = state.status || {};
    const recent = state.outbox.slice().sort((left, right) => right.createdAt - left.createdAt).slice(0, 6);
    const defaultChannel = state.channels.find((item) => item.id === state.settings.default_channel_id);
    return `<div class="notification-overview">${renderSummary(true)}<div class="notification-overview-lower">
      <section class="notification-overview-panel dwrt-kit-glass-surface"><header><div><strong>最近投递</strong><span>最新六条通知状态</span></div><button type="button" data-notify-jump="outbox">查看全部</button></header><div class="notification-recent-list" data-notify-recent-signature="${escapeHtml(recent.map((item) => `${item.id}:${item.state}:${item.updatedAt}`).join('|'))}">${recentMarkup(recent)}</div></section>
      <section class="notification-overview-panel dwrt-kit-glass-surface"><header><div><strong>当前策略</strong><span>通知进入队列后的默认行为</span></div><button type="button" data-notify-jump="settings">管理</button></header><dl class="notification-policy-summary"><div><dt>默认通道</dt><dd>${escapeHtml(firstText(defaultChannel?.name, state.settings.default_channel_id, '--'))}</dd></div><div><dt>有效规则</dt><dd>${escapeHtml(firstNumber(status.active_routes, state.routes.filter((item) => item.enabled).length))} 条</dd></div><div><dt>最大尝试</dt><dd>${escapeHtml(firstNumber(state.settings.max_attempts, 3))} 次</dd></div><div><dt>重试间隔</dt><dd>${escapeHtml(firstNumber(state.settings.retry_base_s, 60))} - ${escapeHtml(firstNumber(state.settings.retry_max_s, 3600))} 秒</dd></div><div><dt>邮件投递</dt><dd>${emailSupported() ? '可用' : '后端待接入'}</dd></div></dl></section>
    </div></div>`;
  }

  function recentMarkup(items) {
    return items.length ? items.map((item) => {
      const tone = item.state === 'delivered' ? 'success' : item.state === 'failed' ? 'error' : ['pending', 'retry'].includes(item.state) ? 'warning' : 'info';
      return `<div><span><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml([formatTime(item.createdAt), channelTypeLabel(state.channels.find((channel) => channel.id === item.channelId)?.type), item.channelId].filter(Boolean).join(' · '))}</small></span>${ui.statusBadgeMarkup?.(stateLabel(item.state), tone) || `<span>${escapeHtml(stateLabel(item.state))}</span>`}</div>`;
    }).join('') : '<div class="notification-overview-empty">暂无投递记录</div>';
  }

  function contentMarkup() {
    if (state.loading) return '<section class="notification-push-table-card dwrt-kit-table-wrap dwrt-kit-glass-surface"><div class="notification-loading">正在读取通知推送配置</div></section>';
    if (state.tab === 'overview') return overviewPanel();
    if (state.tab === 'routes') return routeTable();
    if (state.tab === 'outbox') return outboxTable();
    if (state.tab === 'settings') return settingsPanel();
    return channelTable();
  }

  function channelDrawer() {
    const draft = state.draft || {};
    const type = draft.type || 'noop';
    const webhook = type === 'webhook';
    const email = type === 'email';
    const canEmail = emailSupported();
    return `<button class="policy-drawer-backdrop dwrt-kit-sheet-overlay is-open" type="button" data-notify-close aria-label="关闭通道面板"></button><aside class="notification-push-drawer dwrt-kit-sheet policy-stable-glass is-open" aria-label="推送通道"><header class="dwrt-kit-sheet-header"><div><span>CHANNEL</span><strong>${draft.editing ? '编辑推送通道' : '新建推送通道'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-notify-close>×</button></header><div class="dwrt-kit-sheet-body notification-push-drawer-body"><div class="notification-form"><label><span>通道 ID</span><input data-notify-draft="id" value="${escapeHtml(draft.id || '')}" ${draft.editing ? 'disabled' : ''} placeholder="例如 alert-webhook"></label><label><span>名称</span><input data-notify-draft="name" value="${escapeHtml(draft.name || '')}" placeholder="告警 Webhook"></label><label><span>类型</span><select data-notify-draft="type"><option value="noop" ${(draft.type || 'noop') === 'noop' ? 'selected' : ''}>本地队列</option><option value="webhook" ${webhook ? 'selected' : ''}>Webhook</option></select></label><label class="notification-switch-field is-compact"><span><strong>启用</strong></span><input type="checkbox" data-notify-draft="enabled" ${draft.enabled !== false ? 'checked' : ''}><i></i></label>${webhook ? `<label class="is-wide"><span>Webhook URL</span><input data-notify-draft="url" value="${escapeHtml(draft.url || '')}" placeholder="https://example.com/webhook"></label><label><span>请求方法</span><select data-notify-draft="method">${['POST','PUT','PATCH'].map((method) => `<option value="${method}" ${(draft.method || 'POST') === method ? 'selected' : ''}>${method}</option>`).join('')}</select></label><label><span>超时（毫秒）</span><input type="number" min="1000" max="60000" data-notify-draft="timeout_ms" value="${escapeHtml(firstNumber(draft.timeout_ms, 10000))}"></label><label class="is-wide"><span>替换请求头（JSON）</span><textarea data-notify-draft="headers" placeholder="留空则保留已有请求头；后端应对敏感值做脱敏">${escapeHtml(draft.headers || '')}</textarea><small>${draft.hasStoredHeaders ? '已有请求头已隐藏；留空保存时继续保留。' : '例如 {\"Authorization\":\"Bearer ...\"}'}</small></label>` : ''}</div>${state.notice ? `<div class="notification-form-notice">${escapeHtml(state.notice)}</div>` : ''}</div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-notify-close>取消</button><button class="policy-primary" type="button" data-notify-save-channel ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存通道'}</button></footer></aside>`;
  }

  function routeDrawer() {
    const draft = state.draft || {};
    const selectedCategory = draft.category || routeEventsMap().get(draft.event)?.category || '';
    const eventOptions = selectedCategory ? routeCategoriesMap().get(selectedCategory)?.events || [] : [];
    const customEvent = Boolean(draft.event && !routeEventsMap().has(draft.event));
    const advanced = draft.advanced || customEvent || Boolean(draft.source);
    return `<button class="policy-drawer-backdrop dwrt-kit-sheet-overlay is-open" type="button" data-notify-close aria-label="关闭规则面板"></button><aside class="notification-push-drawer notification-route-drawer dwrt-kit-sheet policy-stable-glass is-open" aria-label="路由规则"><header class="dwrt-kit-sheet-header"><div><span>路由规则</span><strong>${draft.editing ? '编辑路由规则' : '新建路由规则'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-notify-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body notification-push-drawer-body"><div class="notification-route-intro"><strong>选择需要通知的事件</strong><span>按照 UniFi 的事件分类方式配置。每条规则可发送到本地队列、Webhook 或邮件通道。</span></div><div class="notification-form"><label><span>规则 ID</span><input data-notify-draft="id" value="${escapeHtml(draft.id || '')}" ${draft.editing ? 'disabled' : ''} placeholder="例如 wan-status-email"></label><label><span>名称</span><input data-notify-draft="name" value="${escapeHtml(draft.name || '')}" placeholder="例如 WAN 状态邮件提醒"></label><label><span>事件分类</span><select data-notify-draft="category"><option value="">全部分类</option>${routeGroups().map((group) => `<option value="${group.id}" ${selectedCategory === group.id ? 'selected' : ''}>${escapeHtml(group.label)}</option>`).join('')}</select></label><label><span>事件</span><select data-notify-draft="event" ${selectedCategory ? '' : 'disabled'}><option value="">${selectedCategory ? '该分类的全部事件' : '请先选择事件分类'}</option>${eventOptions.map((event) => `<option value="${event.id}" ${event.available === false ? 'disabled' : ''} ${draft.event === event.id ? 'selected' : ''}>${escapeHtml(event.label)}${event.available === false ? '（后端待接入）' : ''}</option>`).join('')}${customEvent ? `<option value="${escapeHtml(draft.event)}" selected>${escapeHtml(draft.event)}（自定义）</option>` : ''}</select></label><label><span>投递通道</span><select data-notify-draft="channelId">${state.channels.map((channel) => `<option value="${escapeHtml(channel.id)}" ${(draft.channelId || state.settings.default_channel_id || 'local') === channel.id ? 'selected' : ''}>${escapeHtml(channel.name)} · ${escapeHtml(channelTypeLabel(channel.type))}</option>`).join('')}</select></label><label><span>最低严重级别</span><select data-notify-draft="minSeverity">${SEVERITY_OPTIONS.map((level) => `<option value="${level.id}" ${(draft.minSeverity || 'warning') === level.id ? 'selected' : ''}>${escapeHtml(level.label)}</option>`).join('')}</select></label><label class="notification-switch-field is-compact"><span><strong>启用规则</strong><small>停用后保留配置，但不再匹配新事件</small></span><input type="checkbox" data-notify-draft="enabled" ${draft.enabled !== false ? 'checked' : ''}><i></i></label><label class="notification-switch-field is-compact"><span><strong>高级匹配</strong><small>按底层来源进一步限制规则</small></span><input type="checkbox" data-notify-draft="advanced" ${advanced ? 'checked' : ''}><i></i></label>${advanced ? `<label class="is-wide"><span>事件来源</span><input data-notify-draft="source" value="${escapeHtml(draft.source || '')}" placeholder="留空匹配全部来源"><small>仅在需要匹配特定组件或接口时填写。</small></label>${customEvent ? `<label class="is-wide"><span>自定义事件标识</span><input data-notify-draft="event" value="${escapeHtml(draft.event)}"><small>该事件不在当前预设中，保留原始标识以兼容已有规则。</small></label>` : ''}` : ''}</div>${state.notice ? `<div class="notification-form-notice">${escapeHtml(state.notice)}</div>` : ''}</div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-notify-close>取消</button><button class="policy-primary" type="button" data-notify-save-route ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存规则'}</button></footer></aside>`;
  }

  function renderDrawer() {
    if (state.drawer === 'channel') return channelDrawer();
    if (state.drawer === 'route') return routeDrawer();
    return '';
  }

  function emailChannelFields() {
    const draft = state.draft || {};
    const canEmail = emailSupported();
    return `<label class="is-wide"><span>用户 ID</span><input data-notify-draft="user_ids" value="${escapeHtml(draft.user_ids || '')}" placeholder="Lester, operator"><small>后端从用户目录读取这些用户的邮箱，多个 ID 用逗号分隔。</small></label><label class="is-wide"><span>额外收件地址</span><input data-notify-draft="recipients" value="${escapeHtml(draft.recipients || '')}" placeholder="noc@example.com, admin@example.com"><small>仅用于不属于本机用户目录的收件人。</small></label><label><span>邮件主题前缀</span><input data-notify-draft="subject_prefix" value="${escapeHtml(draft.subject_prefix || '[Dreaming OS]')}"></label><label><span>回复地址</span><input type="email" data-notify-draft="reply_to" value="${escapeHtml(draft.reply_to || '')}"></label><div class="notification-form-notice is-wide ${canEmail ? 'is-ready' : ''}">${canEmail ? '后端已声明邮件通道能力。' : '邮件前端协议已就绪；后端补齐 email 通道和 SMTP 能力后才能保存。'}</div>`;
  }

  function enhanceChannelDrawer() {
    if (state.drawer !== 'channel') return;
    const typeSelect = root.querySelector('[data-notify-draft="type"]');
    if (!typeSelect) return;
    if (!typeSelect.querySelector('option[value="email"]')) {
      const option = document.createElement('option');
      option.value = 'email';
      option.textContent = `邮件${emailSupported() ? '' : '（后端待接入）'}`;
      typeSelect.append(option);
    }
    typeSelect.value = state.draft.type || 'noop';
    if ((state.draft.type || 'noop') === 'email') {
      root.querySelector('.notification-form')?.insertAdjacentHTML('beforeend', emailChannelFields());
      if (!emailSupported()) root.querySelector('[data-notify-save-channel]')?.setAttribute('disabled', '');
    }
  }

  function enhanceRouteDrawer() {
    if (state.drawer !== 'route' || !state.draft.category || routeCategoriesMap().has(state.draft.category)) return;
    const select = root.querySelector('[data-notify-draft="category"]');
    if (!select) return;
    const option = document.createElement('option');
    option.value = state.draft.category;
    option.textContent = `${state.draft.category}（自定义）`;
    option.selected = true;
    select.append(option);
  }

  function render() {
    if (!root || !state.mounted) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'policy-table-route-host', MODULE_CLASS);
    root.innerHTML = `<section class="policy-table-shell notification-push-shell"><header class="notification-push-page-header"><nav class="dwrt-kit-tabs dwrt-kit-page-tabs notification-push-tabs" role="tablist" aria-label="通知推送视图"><span class="dwrt-kit-tab-pill" aria-hidden="true"></span>${TABS.map((tab) => `<button class="dwrt-kit-tab ${state.tab === tab.id ? 'is-active' : ''}" type="button" role="tab" data-value="${tab.id}" data-notify-tab="${tab.id}" aria-selected="${state.tab === tab.id ? 'true' : 'false'}">${escapeHtml(tab.label)}</button>`).join('')}</nav>${renderToolbar()}</header><div class="notification-push-view">${state.error ? `<div class="notification-form-notice is-error">${escapeHtml(state.error)}</div>` : ''}${contentMarkup()}</div>${renderDrawer()}</section>`;
    enhanceChannelDrawer();
    enhanceRouteDrawer();
    bindEvents();
    ui.mountAll?.(root);
    ui.scheduleGlassCardsRender?.(120);
  }

  function patchLiveSummary() {
    const summary = root.querySelector('.notification-push-summary');
    if (summary) {
      overviewCards().forEach((item) => {
        const key = String(item.key || '').replace(/[^A-Za-z0-9_-]/g, '');
        const card = summary.querySelector(`[data-dwrt-overview-card="${key}"]`);
        const value = summary.querySelector(`[data-dwrt-overview-value="${key}"]`);
        const detail = summary.querySelector(`[data-dwrt-overview-detail="${key}"]`);
        if (value && value.textContent !== String(item.value)) value.textContent = item.value;
        if (detail && detail.textContent !== String(item.detail)) detail.textContent = item.detail;
        if (card) {
          ['neutral','info','ok','warn','bad'].forEach((tone) => card.classList.toggle(`is-${tone}`, tone === item.tone));
        }
      });
      const recent = state.outbox.slice().sort((left, right) => right.createdAt - left.createdAt).slice(0, 6);
      const list = root.querySelector('.notification-recent-list');
      const signature = recent.map((item) => `${item.id}:${item.state}:${item.updatedAt}`).join('|');
      if (list && list.dataset.notifyRecentSignature !== signature) {
        list.dataset.notifyRecentSignature = signature;
        list.innerHTML = recentMarkup(recent);
      }
    }
    if (state.tab === 'outbox' && !state.drawer) {
      const scroll = root.querySelector('.notification-push-table-card .dwrt-kit-table-scroll');
      const keep = { top: scroll?.scrollTop || 0, left: scroll?.scrollLeft || 0 };
      const card = root.querySelector('.notification-push-table-card');
      if (card) card.outerHTML = outboxTable();
      const next = root.querySelector('.notification-push-table-card .dwrt-kit-table-scroll');
      if (next) { next.scrollTop = keep.top; next.scrollLeft = keep.left; }
      bindRowActions();
    }
  }

  function closeDrawer() { state.drawer = ''; state.draft = {}; state.notice = ''; state.saving = false; render(); }

  function openChannel(channel = null) {
    const options = channel?.options || {};
    state.drawer = 'channel';
    state.notice = '';
    state.draft = channel ? { editing: true, id: channel.id, name: channel.name, type: channel.type, enabled: channel.enabled, url: options.url || '', method: options.method || 'POST', timeout_ms: firstNumber(options.timeout_ms, 10000), headers: '', hasStoredHeaders: channel.hasStoredHeaders, user_ids: asArray(options.user_ids || options.users).join(', '), recipients: asArray(options.recipients || options.to).join(', '), subject_prefix: firstText(options.subject_prefix, '[Dreaming OS]'), reply_to: firstText(options.reply_to) } : { editing: false, id: '', name: '', type: 'noop', enabled: true, method: 'POST', timeout_ms: 10000, hasStoredHeaders: false, user_ids: '', recipients: '', subject_prefix: '[Dreaming OS]', reply_to: '' };
    render();
  }

  function openRoute(route = null) {
    state.drawer = 'route';
    state.notice = '';
    state.draft = route ? { editing: true, advanced: Boolean(route.source || (route.event && !routeEventsMap().has(route.event))), ...route } : { editing: false, id: '', name: '', enabled: true, channelId: state.settings.default_channel_id || state.channels[0]?.id || 'local', minSeverity: 'warning', category: '', event: '', source: '', advanced: false };
    render();
  }

  function bindRowActions() {
    root.querySelectorAll('[data-notify-edit-channel]').forEach((button) => button.addEventListener('click', () => openChannel(state.channels.find((item) => item.id === button.dataset.notifyEditChannel))));
    root.querySelectorAll('[data-notify-edit-route]').forEach((button) => button.addEventListener('click', () => openRoute(state.routes.find((item) => item.id === button.dataset.notifyEditRoute))));
    root.querySelectorAll('[data-notify-test]').forEach((button) => button.addEventListener('click', () => testChannel(button.dataset.notifyTest)));
    root.querySelectorAll('[data-notify-retry]').forEach((button) => button.addEventListener('click', () => retryOutbox(button.dataset.notifyRetry)));
  }

  function patchSearchResults() {
    const card = root.querySelector('.notification-push-table-card');
    if (!card) return render();
    const scroll = card.querySelector('.dwrt-kit-table-scroll');
    const scrollTop = scroll?.scrollTop || 0;
    const scrollLeft = scroll?.scrollLeft || 0;
    card.outerHTML = state.tab === 'routes' ? routeTable() : state.tab === 'outbox' ? outboxTable() : channelTable();
    const nextScroll = root.querySelector('.notification-push-table-card .dwrt-kit-table-scroll');
    if (nextScroll) {
      nextScroll.scrollTop = scrollTop;
      nextScroll.scrollLeft = scrollLeft;
    }
    bindRowActions();
  }

  function bindEvents() {
    root.querySelector('[data-notify-settings-form]')?.addEventListener('submit', (event) => event.preventDefault());
    root.querySelectorAll('[data-notify-tab]').forEach((button) => button.addEventListener('click', () => { setTab(button.dataset.notifyTab); state.query = ''; render(); }));
    root.querySelectorAll('[data-notify-jump]').forEach((button) => button.addEventListener('click', () => { setTab(button.dataset.notifyJump); state.query = ''; render(); }));
    root.querySelector('[data-notify-search]')?.addEventListener('input', (event) => { state.query = event.target.value || ''; const card = root.querySelector('.notification-push-table-card'); if (card) card.outerHTML = state.tab === 'routes' ? routeTable() : state.tab === 'outbox' ? outboxTable() : channelTable(); bindRowActions(); });
    root.querySelector('[data-notify-state]')?.addEventListener('change', (event) => { state.outboxState = event.target.value || 'all'; const card = root.querySelector('.notification-push-table-card'); if (card) card.outerHTML = outboxTable(); bindRowActions(); });
    root.querySelector('[data-notify-refresh]')?.addEventListener('click', () => load());
    root.querySelector('[data-notify-create="channels"]')?.addEventListener('click', () => openChannel());
    root.querySelector('[data-notify-create="routes"]')?.addEventListener('click', () => openRoute());
    root.querySelectorAll('[data-notify-close]').forEach((button) => button.addEventListener('click', closeDrawer));
    root.querySelectorAll('[data-notify-draft]').forEach((input) => {
      const eventName = input.matches('select,input[type="checkbox"]') ? 'change' : 'input';
      input.addEventListener(eventName, (event) => {
        const key = event.target.dataset.notifyDraft;
        state.draft[key] = event.target.type === 'checkbox' ? event.target.checked : event.target.value;
        if (key === 'type' || key === 'advanced') render();
        if (key === 'category') {
          state.draft.event = '';
          render();
        }
        if (key === 'event' && routeEventsMap().has(state.draft.event)) {
          const preset = routeEventsMap().get(state.draft.event);
          state.draft.category = preset.category;
          if (!state.draft.editing || !state.draft.name) state.draft.name = preset.label;
          if (!state.draft.editing) state.draft.minSeverity = preset.severity;
          if (!state.draft.editing && !state.draft.id) state.draft.id = `${preset.category.toLowerCase().replace(/_/g, '-')}-${preset.id.toLowerCase().replace(/_/g, '-')}`;
          render();
        }
      });
    });
    root.querySelector('[data-notify-save-channel]')?.addEventListener('click', saveChannel);
    root.querySelector('[data-notify-save-route]')?.addEventListener('click', saveRoute);
    root.querySelector('[data-notify-save-settings]')?.addEventListener('click', saveSettings);
    bindRowActions();
  }

  async function saveChannel() {
    if (state.saving) return;
    const draft = state.draft;
    if (!draft.id || !draft.name) { state.notice = '通道 ID 和名称不能为空。'; render(); return; }
    if (draft.type === 'email' && !emailSupported()) { state.notice = '后端尚未声明 email 通道能力，当前不能保存邮件通道。'; render(); return; }
    let headers = {};
    if (draft.headers?.trim()) {
      try { headers = JSON.parse(draft.headers); } catch (_) { state.notice = '请求头必须是有效 JSON 对象。'; render(); return; }
    } else if (draft.type === 'webhook' && draft.hasStoredHeaders) {
      state.notice = '后端尚未支持脱敏保留语义；为避免把密钥留在前端状态中，编辑此通道时需要重新填写请求头。';
      render();
      return;
    }
    const options = draft.type === 'webhook'
      ? { url: draft.url || '', method: draft.method || 'POST', timeout_ms: Math.max(1000, Math.min(60000, firstNumber(draft.timeout_ms, 10000))), headers }
      : draft.type === 'email'
        ? { user_ids: String(draft.user_ids || '').split(',').map((value) => value.trim()).filter(Boolean), recipients: String(draft.recipients || '').split(',').map((value) => value.trim()).filter(Boolean), subject_prefix: draft.subject_prefix || '[Dreaming OS]', reply_to: draft.reply_to || '' }
        : {};
    state.saving = true; render();
    try {
      await requestJson(ENDPOINTS.channels, { method: 'PUT', body: JSON.stringify({ id: draft.id, name: draft.name, type: draft.type || 'noop', enabled: draft.enabled !== false, options }) });
      state.drawer = ''; state.draft = {}; state.saving = false; await load(); window.DreamingWrtNotify?.success('推送通道已保存');
    } catch (error) { state.saving = false; state.notice = `保存失败：${firstText(error.message, 'unknown')}`; render(); }
  }

  async function saveRoute() {
    if (state.saving) return;
    const draft = state.draft;
    if (!draft.id || !draft.name || !draft.channelId) { state.notice = '规则 ID、名称和通道不能为空。'; render(); return; }
    state.saving = true; render();
    try {
      await requestJson(ENDPOINTS.routes, { method: 'PUT', body: JSON.stringify({ id: draft.id, name: draft.name, enabled: draft.enabled !== false, channel_id: draft.channelId, min_severity: draft.minSeverity || 'warning', category: draft.category || '', event: draft.event || '', source: draft.source || '', options: draft.options || {} }) });
      state.drawer = ''; state.draft = {}; state.saving = false; await load(); window.DreamingWrtNotify?.success('路由规则已保存');
    } catch (error) { state.saving = false; state.notice = `保存失败：${firstText(error.message, 'unknown')}`; render(); }
  }

  async function saveSettings() {
    if (state.saving) return;
    const value = (key) => root.querySelector(`[data-notify-setting="${key}"]`);
    const payload = { enabled: Boolean(value('enabled')?.checked), default_channel_id: value('default_channel_id')?.value || 'local', max_attempts: firstNumber(value('max_attempts')?.value, 3), retry_base_s: firstNumber(value('retry_base_s')?.value, 60), retry_max_s: firstNumber(value('retry_max_s')?.value, 3600) };
    if (emailSupported()) {
      payload.smtp = { host: value('smtp_host')?.value || '', port: firstNumber(value('smtp_port')?.value, 465), security: value('smtp_security')?.value || 'ssl', from: value('smtp_from')?.value || '', username: value('smtp_username')?.value || '' };
      if (value('smtp_password')?.value) payload.smtp.password_replace = value('smtp_password').value;
    }
    state.saving = true; state.notice = ''; render();
    try { await requestJson(ENDPOINTS.settings, { method: 'PUT', body: JSON.stringify(payload) }); state.saving = false; await load(); state.notice = '设置已保存'; render(); window.DreamingWrtNotify?.success('通知设置已保存'); }
    catch (error) { state.saving = false; state.notice = `保存失败：${firstText(error.message, 'unknown')}`; render(); }
  }

  async function testChannel(id) {
    if (!id || state.workingId) return;
    state.workingId = id;
    try { await requestJson(ENDPOINTS.test, { method: 'POST', body: JSON.stringify({ channel_id: id, title: 'Dreaming OS 通知测试', message: `通道 ${id} 测试发送`, severity: 'notice' }) }); window.DreamingWrtNotify?.success('测试通知已送达', id); await refreshLive(); }
    catch (error) { window.DreamingWrtNotify?.error('测试发送失败', firstText(error.message, 'unknown')); }
    finally { state.workingId = ''; }
  }

  async function retryOutbox(id) {
    if (!id || state.workingId) return;
    state.workingId = id; render();
    try { await requestJson(ENDPOINTS.retry, { method: 'POST', body: JSON.stringify({ id }) }); await load(); window.DreamingWrtNotify?.success('记录已重新进入投递队列'); }
    catch (error) { state.workingId = ''; render(); window.DreamingWrtNotify?.error('重试失败', firstText(error.message, 'unknown')); }
  }

  render();
  load();
  state.timer = window.setInterval(() => { if (state.mounted && !state.drawer && document.visibilityState === 'visible') refreshLive(); }, 10000);
  return { unmount() { state.mounted = false; state.seq += 1; state.liveSeq += 1; window.clearInterval(state.timer); root?.replaceChildren(); root?.classList.remove(MODULE_CLASS, 'policy-table-route-host', 'route-workspace'); } };
}

export default { mount };
