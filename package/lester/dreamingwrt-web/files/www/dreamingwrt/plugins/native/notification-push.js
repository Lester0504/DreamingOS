export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));
  const VERSION = '20260817-notification-center-workbench-07';
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
    query: '',
    outboxState: 'all',
    ruleFilters: { search: '', categories: [], severities: [], channels: [], events: [], actions: [], enabled: 'all', triggered: 'all' },
    selectedRouteIds: [],
    drawer: '',
    drawerRouteId: '',
    columnMenuOpen: false,
    ruleColumns: ['rule', 'category', 'action', 'hits', 'latest', 'createdBy', 'method', 'timing', 'status'],
    confirmation: null,
    draft: {},
    utilityReturnDrawer: '',
    utilityReturnDraft: null,
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
      const error = new Error(firstText(json?.error?.message, json?.error?.code, json?.error, json?.message, json?.code, `${response.status}`));
      error.status = response.status;
      error.payload = json;
      throw error;
    }
    return unwrap(json);
  }

  function currentTableKind() {
    if (state.drawer === 'channel-manager') return 'channels';
    if (state.drawer === 'outbox') return 'outbox';
    return 'rules';
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
      action: firstText(value.action, value.action_type, value.options?.action),
      notificationMethod: firstText(value.notification_method, value.notificationMethod, value.options?.notification_method, value.options?.delivery_mode),
      createdBy: firstText(value.created_by, value.owner, value.author),
      sendWindow: firstText(value.when_to_send, value.send_window, value.options?.when_to_send, value.options?.schedule),
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
      pause: '<path d="M8 5v14M16 5v14"></path>',
      play: '<path d="m8 5 10 7-10 7V5Z"></path>',
      more: '<circle cx="5" cy="12" r="1"></circle><circle cx="12" cy="12" r="1"></circle><circle cx="19" cy="12" r="1"></circle>',
      chevron: '<path d="m6 9 6 6 6-6"></path>',
      service: '<path d="M12 3v9"></path><path d="M7.1 5.7a8 8 0 1 0 9.8 0"></path>',
      channels: '<path d="M4 7a3 3 0 1 1 3 3H4V7Z"></path><path d="M20 17a3 3 0 1 0-3-3h3v3Z"></path><path d="M7 7h10v7"></path>',
      delivered: '<path d="M4 12.5 9 17l11-12"></path>',
      failed: '<path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.7 2.5 17.2A2 2 0 0 0 4.2 20h15.6a2 2 0 0 0 1.7-2.8L13.7 3.7a2 2 0 0 0-3.4 0Z"></path>',
      mail: '<rect x="3" y="5" width="18" height="14" rx="2"></rect><path d="m3 7 9 6 9-6"></path>',
      /* 兜底图形，此前 paths.bell 未定义，任何未知名称都会把字符串 undefined 画进 svg。 */
      bell: '<path d="M18 9a6 6 0 1 0-12 0c0 5-2 6-2 6h16s-2-1-2-6"></path><path d="M10.3 20a2 2 0 0 0 3.4 0"></path>'
    };
    return `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.bell}</svg>`;
  }

  function alarmBellIcon() {
    return `<svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M10 2a.5.5 0 0 0-.5.5v1a.5.5 0 0 0 1 0v-1A.5.5 0 0 0 10 2Z"></path><path fill-rule="evenodd" clip-rule="evenodd" d="M10 5a5 5 0 0 0-5 5v4.09c0 .503.407.91.91.91h8.181a.91.91 0 0 0 .91-.91V10a5 5 0 0 0-5-5Zm4 9v-4a4 4 0 0 0-8 0v4h8Z"></path><path d="M3 17.5a.5.5 0 0 1 .5-.5h13a.5.5 0 0 1 0 1h-13a.5.5 0 0 1 0-1Zm14.5-8a.5.5 0 0 1 0 1h-1a.5.5 0 0 1 0-1h1ZM2 10a.5.5 0 0 0 .5.5h1a.5.5 0 0 0 0-1h-1a.5.5 0 0 0-.5-.5Zm12.951-5.656a.5.5 0 0 1 .707.707l-.707.707a.5.5 0 1 1-.707-.707l.707-.707Zm-10.608 0a.5.5 0 0 0 0 .707l.707.707a.5.5 0 1 0 .707-.707l-.707-.707a.5.5 0 0 0-.707 0Z"></path></svg>`;
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
    const filters = state.ruleFilters || {};
    const categories = Array.isArray(filters.categories) ? filters.categories : [];
    const severities = Array.isArray(filters.severities) ? filters.severities : [];
    const channels = Array.isArray(filters.channels) ? filters.channels : [];
    const events = Array.isArray(filters.events) ? filters.events : [];
    const actions = Array.isArray(filters.actions) ? filters.actions : [];
    return state.routes.filter((item) => {
      const matchesQuery = !query || [item.name, item.id, item.channelId, item.minSeverity, item.category, item.event, item.source].join(' ').toLowerCase().includes(query);
      const matchesCategory = !categories.length || categories.includes(item.category || 'uncategorized');
      const matchesSeverity = !severities.length || severities.includes(item.minSeverity);
      const matchesChannel = !channels.length || channels.includes(item.channelId);
      const matchesEvent = !events.length || events.includes(item.event || 'all');
      const matchesAction = !actions.length || actions.includes(item.action || 'notify');
      const latest = routeDeliveryStats(item.id).latest;
      const age = latest ? Date.now() - (latest < 100000000000 ? latest * 1000 : latest) : Infinity;
      const triggeredWindow = ({ '5m': 5, '30m': 30, '1h': 60, '1d': 1440, '1w': 10080, '1m': 43200 })[filters.triggered];
      const matchesTriggered = filters.triggered === 'all' || (Number.isFinite(age) && age <= triggeredWindow * 60 * 1000);
      const matchesEnabled = filters.enabled === 'all' || (filters.enabled === 'enabled' ? item.enabled : !item.enabled);
      return matchesQuery && matchesCategory && matchesSeverity && matchesChannel && matchesEvent && matchesAction && matchesTriggered && matchesEnabled;
    });
  }

  function routeDeliveryStats(routeId) {
    const rows = state.outbox.filter((item) => item.routeId === routeId);
    return { count: rows.reduce((total, item) => total + Math.max(1, item.count || 1), 0), latest: rows.reduce((latest, item) => Math.max(latest, item.createdAt || 0), 0) };
  }

  function routeFilterValues() {
    const categories = new Map();
    const events = new Map();
    state.routes.forEach((route) => {
      const key = route.category || 'uncategorized';
      categories.set(key, (categories.get(key) || 0) + 1);
      const eventKey = route.event || 'all';
      events.set(eventKey, (events.get(eventKey) || 0) + 1);
    });
    return {
      categories: [...categories.entries()].map(([id, count]) => ({ id, label: id === 'uncategorized' ? '未分类' : categoryLabel(id), count })),
      events: [...events.entries()].map(([id, count]) => ({ id, label: id === 'all' ? '全部事件' : eventLabel(id), count })),
      severities: SEVERITY_OPTIONS.filter((option) => state.routes.some((route) => route.minSeverity === option.id)),
      channels: state.channels.map((channel) => ({ id: channel.id, label: channel.name, count: state.routes.filter((route) => route.channelId === channel.id).length })),
      actions: [{ id: 'notify', label: '通知', count: state.routes.length }]
    };
  }

  const RULE_COLUMN_DEFS = [
    { id: 'rule', label: '规则 / 触发器' },
    { id: 'category', label: '分类' },
    { id: 'action', label: '动作与通道' },
    { id: 'hits', label: '命中' },
    { id: 'latest', label: '最近触发' },
    { id: 'createdBy', label: '创建者' },
    { id: 'method', label: '通知方式' },
    { id: 'timing', label: '发送时机' },
    { id: 'status', label: '状态 / 操作' }
  ];

  function ruleColumnVisible(id) {
    return state.ruleColumns.includes(id);
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

  /*
   * 表格控件全部收进 dwrt-kit-table-toolbar（用户第 9 条）：页头不再摆散落的搜索框与
   * 按钮，手动刷新按钮删除，数据由 10 秒轮询（见 mount 里的 state.timer）维持。
   */
  function tableToolbarActions(view = 'rules') {
    const createLabel = view === 'channels' ? '新建通道' : view === 'rules' ? '新建规则' : '';
    const stateFilter = view === 'outbox'
      ? `<label class="notification-push-filter" data-dwrt-component="field"><select class="dwrt-kit-select" data-dwrt-component="select" data-notify-state aria-label="筛选投递状态"><option value="all">全部状态</option>${['pending','retry','failed','delivered'].map((value) => `<option value="${value}" ${state.outboxState === value ? 'selected' : ''}>${stateLabel(value)}</option>`).join('')}</select></label>`
      : '';
    const bulk = view === 'rules' && state.selectedRouteIds.length
      ? `<span class="notification-selection-count">已选 ${state.selectedRouteIds.length} 条</span><button class="dwrt-kit-button notification-bulk-button" type="button" data-notify-bulk="enable">启用</button><button class="dwrt-kit-button notification-bulk-button" type="button" data-notify-bulk="disable">暂停</button>`
      : '';
    const columns = '';
    const searchCreate = view === 'rules' ? '' : `<label class="dwrt-kit-expand-search notification-push-search" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-notify-search placeholder="搜索当前视图" value="${escapeHtml(state.query)}" aria-label="搜索当前视图"></label>${createLabel ? `<button class="dwrt-kit-button is-primary notification-create-button" type="button" data-notify-create="${escapeHtml(view)}">${icon('plus')}<span>${escapeHtml(createLabel)}</span></button>` : ''}`;
    return `<div class="notification-toolbar-actions">${bulk}${stateFilter}${columns}${searchCreate}</div>`;
  }

  function tableCountText(count, view = 'rules') {
    const unit = view === 'channels' ? '个通道' : view === 'rules' ? '条规则' : '条记录';
    return `${count} ${unit}`;
  }

  function channelRowsMarkup(rows) {
    return `${rows.length ? rows.map((item) => `<tr><td><button class="notification-name-button" type="button" data-notify-edit-channel="${escapeHtml(item.id)}"><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.id)}</small></button></td><td>${escapeHtml(channelTypeLabel(item.type))}</td><td>${ui.statusBadgeMarkup?.(item.enabled ? '启用' : '停用', item.enabled ? 'success' : 'error') || ''}</td><td><span class="notification-target">${escapeHtml(channelTarget(item))}</span></td><td><time>${escapeHtml(formatTime(item.updatedAt))}</time></td><td><div class="notification-row-actions"><button type="button" data-notify-test="${escapeHtml(item.id)}" aria-label="测试发送">${icon('send')}</button><button type="button" data-notify-edit-channel="${escapeHtml(item.id)}" aria-label="编辑">${icon('edit')}</button></div></td></tr>`).join('') : '<tr><td colspan="6" class="dwrt-kit-table-empty">暂无推送通道</td></tr>'}`;
  }

  function routeRowsMarkup(rows) {
    return `${rows.length ? rows.map((item) => { const stats = routeDeliveryStats(item.id); const selected = state.selectedRouteIds.includes(item.id); const cells = { rule: `<td><button class="notification-name-button" type="button" data-notify-route-detail="${escapeHtml(item.id)}"><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.event ? eventLabel(item.event) : '全部事件')} · ${escapeHtml(item.source || '全部来源')}</small></button></td>`, category: `<td><span class="notification-category-label">${escapeHtml(categoryLabel(item.category))}</span></td>`, action: `<td><span class="notification-action-label">${icon('bell')} ${escapeHtml(channelLabel(item.channelId))}</span><small class="notification-rule-subline">${escapeHtml(severityLabel(item.minSeverity))} 起通知</small></td>`, hits: `<td><strong class="notification-hit-count">${escapeHtml(stats.count)}</strong></td>`, latest: `<td><time>${escapeHtml(formatTime(stats.latest))}</time></td>`, createdBy: `<td><span class="notification-route-meta">${escapeHtml(item.createdBy || '--')}</span></td>`, method: `<td><span class="notification-route-meta">${escapeHtml(item.notificationMethod || channelTypeLabel(state.channels.find((channel) => channel.id === item.channelId)?.type) || '--')}</span></td>`, timing: `<td><span class="notification-route-meta">${escapeHtml(item.sendWindow || '--')}</span></td>`, status: `<td>${ui.statusBadgeMarkup?.(item.enabled ? '启用' : '已暂停', item.enabled ? 'success' : 'neutral') || ''}<div class="notification-row-actions"><button type="button" data-notify-toggle-route="${escapeHtml(item.id)}" aria-label="${item.enabled ? '暂停' : '启用'}">${icon(item.enabled ? 'pause' : 'play')}</button><button type="button" data-notify-edit-route="${escapeHtml(item.id)}" aria-label="编辑">${icon('edit')}</button><button type="button" data-notify-route-menu="${escapeHtml(item.id)}" aria-label="更多操作">${icon('more')}</button></div></td>` }; return `<tr class="notification-rule-row ${selected ? 'is-selected' : ''}" data-notify-route-row="${escapeHtml(item.id)}"><td class="notification-rule-check"><input type="checkbox" data-notify-select-route="${escapeHtml(item.id)}" ${selected ? 'checked' : ''} aria-label="选择 ${escapeHtml(item.name)}"></td>${RULE_COLUMN_DEFS.filter((column) => ruleColumnVisible(column.id)).map((column) => cells[column.id]).join('')}</tr>`; }).join('') : `<tr><td colspan="${1 + state.ruleColumns.length}" class="dwrt-kit-table-empty">暂无通知规则</td></tr>`}`;
  }

  function outboxRowsMarkup(rows) {
    return `${rows.length ? rows.map((item) => { const tone = item.state === 'delivered' ? 'success' : item.state === 'failed' ? 'error' : item.state === 'retry' ? 'warning' : 'info'; return `<tr><td><time>${escapeHtml(formatTime(item.createdAt))}</time></td><td><span class="notification-outbox-title"><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml([item.severity, item.category, item.event].filter(Boolean).join(' · '))}</small></span></td><td>${ui.statusBadgeMarkup?.(stateLabel(item.state), tone) || ''}</td><td>${escapeHtml([item.channelId, item.routeId].filter(Boolean).join(' · ') || '--')}</td><td>${item.attempts} / ${item.maxAttempts || '--'}${item.count > 1 ? ` · ×${item.count}` : ''}</td><td>${item.httpStatus || '--'}</td><td><span class="notification-target">${escapeHtml(item.lastError || '--')}</span></td><td><div class="notification-row-actions"><button type="button" data-notify-retry="${escapeHtml(item.id)}" ${['failed','retry'].includes(item.state) && state.workingId !== item.id ? '' : 'disabled'} aria-label="重试">${icon('retry')}</button></div></td></tr>`; }).join('') : '<tr><td colspan="8" class="dwrt-kit-table-empty">暂无投递记录</td></tr>'}`;
  }

  function channelTable() {
    const rows = filteredChannels();
    return `<section class="notification-push-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar notification-push-table-toolbar" data-dwrt-component="toolbar"><div class="dwrt-kit-table-title"><strong>推送通道</strong><span>本地队列、Webhook 与邮件投递 · <em data-notify-table-count>${tableCountText(rows.length, 'channels')}</em></span></div>${tableToolbarActions('channels')}</div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table notification-channel-table"><thead><tr><th>名称</th><th>类型</th><th>状态</th><th>目标</th><th>更新时间</th><th>操作</th></tr></thead><tbody data-notify-rows>${channelRowsMarkup(rows)}</tbody></table></div></section>`;
  }

  function routeFilterSidebar() {
    const filters = state.ruleFilters || {};
    const values = routeFilterValues();
    const checked = (key, id) => Array.isArray(filters[key]) && filters[key].includes(id) ? 'checked' : '';
    const checkboxList = (name, items) => items.length ? items.map((item) => `<label class="notification-filter-option"><input type="checkbox" data-notify-filter="${name}" value="${escapeHtml(item.id)}" ${checked(name, item.id)}><span>${escapeHtml(item.label)}</span><em>${escapeHtml(item.count ?? '')}</em></label>`).join('') : '<span class="notification-filter-empty">暂无选项</span>';
    const hasFilters = state.query || state.ruleFilters.categories.length || state.ruleFilters.severities.length || state.ruleFilters.channels.length || state.ruleFilters.events.length || state.ruleFilters.actions.length || state.ruleFilters.enabled !== 'all' || state.ruleFilters.triggered !== 'all';
    const search = `<label class="dwrt-kit-expand-search notification-filter-search" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-notify-search placeholder="搜索规则" value="${escapeHtml(state.query)}" aria-label="搜索规则"></label>`;
    const create = `<button class="dwrt-kit-button notification-filter-create" type="button" data-notify-create="rules">${alarmBellIcon()}<span>新建规则</span></button>`;
    return `<aside class="notification-rule-filters" aria-label="通知规则筛选"><div class="notification-filter-tools">${search}${create}</div><section class="notification-filter-section"><button type="button" class="notification-filter-section-title" data-notify-filter-fold="enabled"><span>触发活动</span>${icon('chevron')}</button><div class="notification-filter-options"><label class="notification-filter-option is-radio"><input type="radio" name="notify-enabled" data-notify-enabled="all" ${filters.enabled === 'all' ? 'checked' : ''}><span>全部规则</span></label><label class="notification-filter-option is-radio"><input type="radio" name="notify-enabled" data-notify-enabled="enabled" ${filters.enabled === 'enabled' ? 'checked' : ''}><span>仅启用</span></label><label class="notification-filter-option is-radio"><input type="radio" name="notify-enabled" data-notify-enabled="disabled" ${filters.enabled === 'disabled' ? 'checked' : ''}><span>已暂停</span></label></div></section><section class="notification-filter-section"><button type="button" class="notification-filter-section-title" data-notify-filter-fold="channels"><span>通知</span>${icon('chevron')}</button><div class="notification-filter-options">${checkboxList('channels', values.channels)}</div></section><section class="notification-filter-section"><button type="button" class="notification-filter-section-title" data-notify-filter-fold="triggered"><span>最近触发</span>${icon('chevron')}</button><div class="notification-filter-options notification-filter-segments">${[['all','全部时间'],['5m','5 分钟'],['30m','30 分钟'],['1h','1 小时'],['1d','1 天'],['1w','1 周'],['1m','1 个月']].map(([id,label]) => `<label class="notification-filter-option is-radio"><input type="radio" name="notify-triggered" data-notify-triggered="${id}" ${filters.triggered === id ? 'checked' : ''}><span>${label}</span></label>`).join('')}</div></section><section class="notification-filter-section"><button type="button" class="notification-filter-section-title" data-notify-filter-fold="events"><span>触发器</span>${icon('chevron')}</button><div class="notification-filter-options">${checkboxList('events', values.events)}</div></section><section class="notification-filter-section"><button type="button" class="notification-filter-section-title" data-notify-filter-fold="categories"><span>分类</span>${icon('chevron')}</button><div class="notification-filter-options">${checkboxList('categories', values.categories)}</div></section><section class="notification-filter-section"><button type="button" class="notification-filter-section-title" data-notify-filter-fold="actions"><span>动作</span>${icon('chevron')}</button><div class="notification-filter-options">${checkboxList('actions', values.actions)}</div></section><section class="notification-filter-section"><button type="button" class="notification-filter-section-title" data-notify-filter-fold="severities"><span>最低级别</span>${icon('chevron')}</button><div class="notification-filter-options">${checkboxList('severities', values.severities)}</div></section><footer class="notification-filter-footer"><button type="button" class="notification-filter-link" data-notify-filter-reset ${hasFilters ? '' : 'disabled'}>${icon('retry')}<span>重置</span></button><button type="button" class="notification-filter-link" data-notify-clear-filters ${hasFilters ? '' : 'disabled'}>${icon('retry')}<span>清除筛选条件</span></button><button type="button" class="notification-filter-link" data-notify-columns-toggle aria-expanded="${state.columnMenuOpen ? 'true' : 'false'}">${icon('more')}<span>自定义列</span></button>${state.columnMenuOpen ? `<div class="notification-column-menu is-rail" role="menu" aria-label="自定义列">${RULE_COLUMN_DEFS.map((column) => `<label><input type="checkbox" data-notify-column-toggle="${column.id}" ${ruleColumnVisible(column.id) ? 'checked' : ''} ${state.ruleColumns.length <= 1 && ruleColumnVisible(column.id) ? 'disabled' : ''}><span>${escapeHtml(column.label)}</span></label>`).join('')}</div>` : ''}</footer></aside>`;
  }

  function routeTable() {
    const rows = filteredRoutes();
    const visibleColumns = RULE_COLUMN_DEFS.filter((column) => ruleColumnVisible(column.id));
    const headers = visibleColumns.map((column) => `<th>${escapeHtml(column.label)}</th>`).join('');
    return `<div class="notification-rule-workbench">${routeFilterSidebar()}<section class="notification-push-table-card notification-rule-table-card"><div class="dwrt-kit-table-toolbar notification-push-table-toolbar" data-dwrt-component="toolbar"><div class="dwrt-kit-table-title"><strong>通知规则</strong><span>事件 → 动作 → 通道 · <em data-notify-table-count>${tableCountText(rows.length, 'rules')}</em></span></div><div class="notification-toolbar-actions"><button class="dwrt-kit-button notification-utility-button" type="button" data-notify-open-utility="channels">${icon('channels')}<span>通道</span></button><button class="dwrt-kit-button notification-utility-button" type="button" data-notify-open-utility="outbox">${icon('delivered')}<span>投递记录</span></button><button class="dwrt-kit-button notification-utility-button" type="button" data-notify-open-utility="settings">${icon('service')}<span>设置</span></button>${tableToolbarActions('rules')}</div></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table notification-route-table"><thead><tr><th class="notification-rule-check"><input type="checkbox" data-notify-select-all aria-label="选择全部规则" ${rows.length && rows.every((item) => state.selectedRouteIds.includes(item.id)) ? 'checked' : ''}></th>${headers}</tr></thead><tbody data-notify-rows>${routeRowsMarkup(rows)}</tbody></table></div></section></div>`;
  }

  function outboxTable() {
    const rows = filteredOutbox();
    return `<section class="notification-push-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar notification-push-table-toolbar" data-dwrt-component="toolbar"><div class="dwrt-kit-table-title"><strong>投递记录</strong><span>失败记录可重新进入投递队列 · <em data-notify-table-count>${tableCountText(rows.length, 'outbox')}</em></span></div>${tableToolbarActions('outbox')}</div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table notification-outbox-table"><thead><tr><th>时间</th><th>通知</th><th>状态</th><th>通道 / 规则</th><th>尝试</th><th>HTTP</th><th>错误</th><th>操作</th></tr></thead><tbody data-notify-rows>${outboxRowsMarkup(rows)}</tbody></table></div></section>`;
  }

  function settingsPanel() {
    const settings = state.settings || {};
    const smtp = settings.smtp && typeof settings.smtp === 'object' ? settings.smtp : {};
    const canEmail = emailSupported();
    return `<form class="notification-settings-stack" data-notify-settings-form>
      <section class="notification-settings-panel dwrt-kit-glass-surface"><header><div><strong>投递设置</strong><span>控制通知服务与失败重试节奏</span></div>${ui.statusBadgeMarkup?.(settings.enabled !== false ? '启用' : '停用', settings.enabled !== false ? 'success' : 'error') || ''}</header><div class="notification-settings-body"><label class="notification-master-card ${settings.enabled !== false ? 'is-active' : ''}"><span class="notification-master-icon" aria-hidden="true">${icon('bell')}</span><strong>启用通知推送</strong><em>关闭后保留配置，但不再分发新通知</em><span class="notification-master-switch dwrt-kit-switch" data-dwrt-component="switch"><input type="checkbox" data-notify-setting="enabled" ${settings.enabled !== false ? 'checked' : ''}></span></label><div class="notification-settings-grid"><label><span>默认通道</span><select data-notify-setting="default_channel_id">${state.channels.map((channel) => `<option value="${escapeHtml(channel.id)}" ${settings.default_channel_id === channel.id ? 'selected' : ''}>${escapeHtml(channel.name)}</option>`).join('')}</select></label><label><span>最大尝试次数</span><input type="number" min="1" max="20" data-notify-setting="max_attempts" value="${escapeHtml(firstNumber(settings.max_attempts, 3))}"></label><label><span>首次重试间隔（秒）</span><input type="number" min="1" max="86400" data-notify-setting="retry_base_s" value="${escapeHtml(firstNumber(settings.retry_base_s, 60))}"></label><label><span>最大重试间隔（秒）</span><input type="number" min="1" max="86400" data-notify-setting="retry_max_s" value="${escapeHtml(firstNumber(settings.retry_max_s, 3600))}"></label></div></div></section>
      <section class="notification-settings-panel notification-mail-settings dwrt-kit-glass-surface"><header><div><strong>邮件发件</strong><span>向用户资料中的邮箱或额外收件地址投递</span></div><span class="notification-capability ${canEmail ? 'is-ready' : ''}">${canEmail ? '可用' : '后端待接入'}</span></header><div class="notification-settings-grid"><label><span>SMTP 服务器</span><input type="text" data-notify-setting="smtp_host" value="${escapeHtml(firstText(smtp.host))}" placeholder="smtp.example.com" ${canEmail ? '' : 'disabled'}></label><label><span>端口</span><input type="number" min="1" max="65535" data-notify-setting="smtp_port" value="${escapeHtml(firstNumber(smtp.port, 465))}" ${canEmail ? '' : 'disabled'}></label><label><span>加密方式</span><select data-notify-setting="smtp_security" ${canEmail ? '' : 'disabled'}>${['ssl','starttls','none'].map((value) => `<option value="${value}" ${firstText(smtp.security, 'ssl') === value ? 'selected' : ''}>${value === 'ssl' ? 'SSL/TLS' : value === 'starttls' ? 'STARTTLS' : '无'}</option>`).join('')}</select></label><label><span>发件地址</span><input type="email" data-notify-setting="smtp_from" value="${escapeHtml(firstText(smtp.from))}" placeholder="router@example.com" ${canEmail ? '' : 'disabled'}></label><label><span>用户名</span><input type="text" data-notify-setting="smtp_username" value="${escapeHtml(firstText(smtp.username))}" autocomplete="off" ${canEmail ? '' : 'disabled'}></label><label><span>密码</span><input type="password" data-notify-setting="smtp_password" value="" placeholder="${smtp.password_present ? '已保存，留空保持不变' : 'SMTP 密码'}" autocomplete="new-password" ${canEmail ? '' : 'disabled'}></label></div><div class="notification-mail-note">邮件通道以用户 ID 绑定收件人，实际地址由后端读取用户目录；Outbox 与日志不得保存 SMTP 密码或完整邮件正文。</div></section>
      <footer class="notification-settings-actions"><span>${escapeHtml(state.notice || '')}</span><button class="policy-primary" type="button" data-notify-save-settings ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存设置'}</button></footer>
    </form>`;
  }

  function contentMarkup() {
    if (state.loading) return '<section class="notification-push-table-card dwrt-kit-table-wrap dwrt-kit-glass-surface"><div class="notification-loading">正在读取通知推送配置</div></section>';
    return routeTable();
  }

  function routeDetailDrawer() {
    const route = state.routes.find((item) => item.id === state.drawerRouteId);
    if (!route) return '';
    const stats = routeDeliveryStats(route.id);
    const event = route.event ? eventLabel(route.event) : '全部事件';
    return `<button class="policy-drawer-backdrop dwrt-kit-sheet-overlay is-open" type="button" data-notify-close aria-label="关闭规则详情"></button><aside class="notification-push-drawer notification-route-detail-drawer dwrt-kit-sheet policy-stable-glass is-open" aria-label="通知规则详情"><header class="dwrt-kit-sheet-header"><div><span>通知规则</span><strong>${escapeHtml(route.name)}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-notify-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body notification-detail-body"><div class="notification-detail-flow"><div><span class="notification-detail-icon">${icon('service')}</span><strong>${escapeHtml(categoryLabel(route.category))}</strong><small>${escapeHtml(event)}</small></div><span class="notification-detail-arrow">→</span><div><span class="notification-detail-icon is-accent">${icon('bell')}</span><strong>${escapeHtml(channelLabel(route.channelId))}</strong><small>${escapeHtml(severityLabel(route.minSeverity))} 起通知</small></div></div><dl class="notification-detail-list"><div><dt>状态</dt><dd>${ui.statusBadgeMarkup?.(route.enabled ? '启用' : '已暂停', route.enabled ? 'success' : 'neutral') || escapeHtml(route.enabled ? '启用' : '已暂停')}</dd></div><div><dt>事件来源</dt><dd>${escapeHtml(route.source || '全部来源')}</dd></div><div><dt>命中次数</dt><dd>${escapeHtml(stats.count)}</dd></div><div><dt>最近触发</dt><dd>${escapeHtml(formatTime(stats.latest))}</dd></div><div><dt>规则 ID</dt><dd><code>${escapeHtml(route.id)}</code></dd></div></dl>${state.notice ? `<div class="notification-form-notice ${state.notice.startsWith('操作失败') ? 'is-error' : 'is-ready'}">${escapeHtml(state.notice)}</div>` : ''}</div><footer class="notification-detail-actions"><button type="button" class="notification-detail-action" data-notify-toggle-detail>${icon(route.enabled ? 'pause' : 'play')}<span>${route.enabled ? '暂停规则' : '启用规则'}</span></button><button type="button" class="notification-detail-action" data-notify-duplicate-route>${icon('plus')}<span>复制规则</span></button><button type="button" class="notification-detail-action is-danger" data-notify-delete-route>${icon('failed')}<span>删除规则</span></button><button type="button" class="policy-primary notification-detail-edit" data-notify-detail-edit>编辑规则</button></footer></aside>`;
  }

  function channelDrawer() {
    const draft = state.draft || {};
    const type = draft.type || 'noop';
    const webhook = type === 'webhook';
    const email = type === 'email';
    const canEmail = emailSupported();
    return `<button class="policy-drawer-backdrop dwrt-kit-sheet-overlay is-open" type="button" data-notify-close aria-label="关闭通道面板"></button><aside class="notification-push-drawer dwrt-kit-sheet policy-stable-glass is-open" aria-label="推送通道"><header class="dwrt-kit-sheet-header"><div><span>CHANNEL</span><strong>${draft.editing ? '编辑推送通道' : '新建推送通道'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-notify-close>×</button></header><div class="dwrt-kit-sheet-body notification-push-drawer-body"><div class="notification-form"><label><span>通道 ID</span><input data-notify-draft="id" value="${escapeHtml(draft.id || '')}" ${draft.editing ? 'disabled' : ''} placeholder="例如 alert-webhook"></label><label><span>名称</span><input data-notify-draft="name" value="${escapeHtml(draft.name || '')}" placeholder="告警 Webhook"></label><label><span>类型</span><select data-notify-draft="type"><option value="noop" ${(draft.type || 'noop') === 'noop' ? 'selected' : ''}>本地队列</option><option value="webhook" ${webhook ? 'selected' : ''}>Webhook</option></select></label><label class="notification-switch-field is-compact dwrt-kit-switch" data-dwrt-component="switch"><span><strong>启用</strong></span><input type="checkbox" data-notify-draft="enabled" ${draft.enabled !== false ? 'checked' : ''}></label>${webhook ? `<label class="is-wide"><span>Webhook URL</span><input data-notify-draft="url" value="${escapeHtml(draft.url || '')}" placeholder="https://example.com/webhook"></label><label><span>请求方法</span><select data-notify-draft="method">${['POST','PUT','PATCH'].map((method) => `<option value="${method}" ${(draft.method || 'POST') === method ? 'selected' : ''}>${method}</option>`).join('')}</select></label><label><span>超时（毫秒）</span><input type="number" min="1000" max="60000" data-notify-draft="timeout_ms" value="${escapeHtml(firstNumber(draft.timeout_ms, 10000))}"></label><label class="is-wide"><span>替换请求头（JSON）</span><textarea data-notify-draft="headers" placeholder="留空则保留已有请求头；后端应对敏感值做脱敏">${escapeHtml(draft.headers || '')}</textarea><small>${draft.hasStoredHeaders ? '已有请求头已隐藏；留空保存时继续保留。' : '例如 {\"Authorization\":\"Bearer ...\"}'}</small></label>` : ''}</div>${state.notice ? `<div class="notification-form-notice">${escapeHtml(state.notice)}</div>` : ''}</div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-notify-close>取消</button><button class="policy-primary" type="button" data-notify-save-channel ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存通道'}</button></footer></aside>`;
  }

  function routeDrawer() {
    const draft = state.draft || {};
    const selectedCategory = draft.category || routeEventsMap().get(draft.event)?.category || '';
    const eventOptions = selectedCategory ? routeCategoriesMap().get(selectedCategory)?.events || [] : [];
    const customEvent = Boolean(draft.event && !routeEventsMap().has(draft.event));
    const advanced = draft.advanced || customEvent || Boolean(draft.source);
    const selectedChannels = Array.isArray(draft.channelIds) && draft.channelIds.length ? draft.channelIds : [draft.channelId || state.settings.default_channel_id || state.channels[0]?.id || 'local'];
    const unsupportedNote = 'Schedule、多个动作、收件人、内容模板和重复抑制尚未有 notifyd 正式字段；当前不写入浏览器或伪造保存状态。';
    return `<button class="policy-drawer-backdrop dwrt-kit-sheet-overlay is-open" type="button" data-notify-close aria-label="关闭规则面板"></button><aside class="notification-push-drawer notification-route-drawer dwrt-kit-sheet policy-stable-glass is-open" aria-label="${draft.editing ? '编辑通知规则' : '新建通知规则'}"><header class="dwrt-kit-sheet-header"><div><span>通知规则</span><strong>${draft.editing ? '编辑通知规则' : '新建通知规则'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-notify-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body notification-push-drawer-body notification-rule-create-body"><div class="notification-route-intro"><strong>按 Scope → Schedule → Action 配置</strong><span>参考 UniFi 的新建 Alarm 流程；保存只提交当前 notifyd 合同中的真实字段。</span></div><section class="notification-create-section"><header><strong>Scope</strong><span>选择事件分类与触发器</span></header><div class="notification-form"><label><span>规则 ID</span><input data-notify-draft="id" value="${escapeHtml(draft.id || '')}" ${draft.editing ? 'disabled' : ''} placeholder="例如 wan-status-email"></label><label><span>名称</span><input data-notify-draft="name" value="${escapeHtml(draft.name || '')}" placeholder="例如 WAN 状态邮件提醒"></label><label><span>事件分类</span><select data-notify-draft="category"><option value="">全部分类</option>${routeGroups().map((group) => `<option value="${group.id}" ${selectedCategory === group.id ? 'selected' : ''}>${escapeHtml(group.label)}</option>`).join('')}</select></label><label><span>事件</span><select data-notify-draft="event" ${selectedCategory ? '' : 'disabled'}><option value="">${selectedCategory ? '该分类的全部事件' : '请先选择事件分类'}</option>${eventOptions.map((event) => `<option value="${event.id}" ${event.available === false ? 'disabled' : ''} ${draft.event === event.id ? 'selected' : ''}>${escapeHtml(event.label)}${event.available === false ? '（后端待接入）' : ''}</option>`).join('')}${customEvent ? `<option value="${escapeHtml(draft.event)}" selected>${escapeHtml(draft.event)}（自定义）</option>` : ''}</select></label><label class="notification-switch-field is-compact dwrt-kit-switch" data-dwrt-component="switch"><span><strong>高级匹配</strong><small>按事件来源进一步限制规则</small></span><input type="checkbox" data-notify-draft="advanced" ${advanced ? 'checked' : ''}></label>${advanced ? `<label class="is-wide"><span>事件来源</span><input data-notify-draft="source" value="${escapeHtml(draft.source || '')}" placeholder="留空匹配全部来源"></label>` : ''}</div></section><section class="notification-create-section"><header><strong>Schedule</strong><span>UniFi 交互保留，当前后端合同待补</span></header><div class="notification-choice-row"><label class="notification-choice is-selected"><input type="radio" name="notify-schedule" checked disabled><span>Always</span></label><label class="notification-choice"><input type="radio" name="notify-schedule" disabled><span>Custom</span></label></div><div class="notification-capability-note">${unsupportedNote}</div></section><section class="notification-create-section"><header><strong>Action</strong><span>当前真实动作是 notify</span></header><div class="notification-action-grid"><label class="notification-choice is-selected"><input type="checkbox" checked disabled><span>Notify</span></label><label class="notification-choice"><input type="checkbox" disabled><span>Webhook</span><small>请先创建 Webhook 通道</small></label><label class="notification-choice is-disabled"><input type="checkbox" disabled><span>Power</span><small>后端未提供动作合同</small></label></div><div class="notification-form"><label><span>通知通道</span><select data-notify-draft="channelId">${state.channels.map((channel) => `<option value="${escapeHtml(channel.id)}" ${selectedChannels[0] === channel.id ? 'selected' : ''}>${escapeHtml(channel.name)} · ${escapeHtml(channelTypeLabel(channel.type))}</option>`).join('')}</select><small>当前 notifyd route 只接受一个 channel_id；多通道需后端扩展。</small></label><label><span>最低严重级别</span><select data-notify-draft="minSeverity">${SEVERITY_OPTIONS.map((level) => `<option value="${level.id}" ${(draft.minSeverity || 'warning') === level.id ? 'selected' : ''}>${escapeHtml(level.label)}</option>`).join('')}</select></label></div></section><section class="notification-create-section"><header><strong>Notification Channels & Receivers</strong><span>通道配置在同一工作台工具 Sheet 中维护</span></header><div class="notification-channel-summary">${selectedChannels.map((id) => `<span>${icon('bell')}<strong>${escapeHtml(channelLabel(id))}</strong><small>${escapeHtml(channelTypeLabel(state.channels.find((channel) => channel.id === id)?.type || 'noop'))}</small></span>`).join('')}<button class="dwrt-kit-button" type="button" data-notify-open-utility="channels">${icon('channels')}<span>管理通道</span></button></div><div class="notification-form-notice">Receivers 当前由所选通道的 options 管理；notifyd 没有规则级 recipients 字段。</div></section><section class="notification-create-section"><header><strong>Content</strong><span>默认内容由事件与 notifyd 生成</span></header><div class="notification-choice-row"><label class="notification-choice is-selected"><input type="radio" name="notify-content" checked disabled><span>Default Content</span></label><label class="notification-choice"><input type="radio" name="notify-content" disabled><span>Custom Content</span></label></div><div class="notification-capability-note">自定义标题/正文目前没有规则字段，避免本地保存或发送与后端不一致的数据。</div></section><section class="notification-create-section"><header><strong>Rule State</strong><span>保存后可在详情抽屉中启停</span></header><label class="notification-switch-field is-compact dwrt-kit-switch" data-dwrt-component="switch"><span><strong>启用规则</strong><small>停用后保留配置，但不再匹配新事件</small></span><input type="checkbox" data-notify-draft="enabled" ${draft.enabled !== false ? 'checked' : ''}></label><div class="notification-capability-note">Ignore Repeated Alarms 的 dedupe 窗口目前由事件生产者提供，不是 rule 合同字段。</div></section>${state.notice ? `<div class="notification-form-notice">${escapeHtml(state.notice)}</div>` : ''}</div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-notify-close>取消</button><button class="policy-primary" type="button" data-notify-save-route ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存规则'}</button></footer></aside>`;
  }

  function renderDrawer() {
    if (state.drawer === 'channel') return channelDrawer();
    if (state.drawer === 'route') return routeDrawer();
    if (state.drawer === 'route-detail') return routeDetailDrawer();
    if (state.drawer === 'channel-manager') return utilityDrawer('channels', channelTable());
    if (state.drawer === 'outbox') return utilityDrawer('outbox', outboxTable());
    if (state.drawer === 'settings') return utilityDrawer('settings', settingsPanel());
    return '';
  }

  function utilityDrawer(kind, content) {
    const labels = { channels: '推送通道', outbox: '投递记录', settings: '通知设置' };
    return `<button class="policy-drawer-backdrop dwrt-kit-sheet-overlay is-open" type="button" data-notify-utility-close aria-label="关闭${labels[kind]}"></button><aside class="notification-push-utility-drawer dwrt-kit-sheet policy-stable-glass is-open" aria-label="${labels[kind]}"><header class="dwrt-kit-sheet-header"><div><span>通知中心</span><strong>${labels[kind]}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-notify-utility-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body notification-utility-drawer-body">${content}</div></aside>`;
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

    root.innerHTML = `<section class="policy-table-shell notification-push-shell notification-center-shell"><div class="notification-center-surface dwrt-kit-glass-surface"><div class="notification-push-view">${state.error ? `<div class="notification-form-notice is-error">${escapeHtml(state.error)}</div>` : ''}${contentMarkup()}</div></div>${renderDrawer()}${confirmationMarkup()}</section>`;
    enhanceChannelDrawer();
    enhanceRouteDrawer();
    bindEvents();
    ui.mountAll?.(root);
    ui.scheduleGlassCardsRender?.(120);
  }

  function patchLiveSummary() {
    if (!state.drawer) syncTableRows();
  }

  function closeDrawer() {
    if (state.utilityReturnDrawer) {
      state.drawer = state.utilityReturnDrawer;
      state.draft = state.utilityReturnDraft || state.draft || {};
      state.utilityReturnDrawer = '';
      state.utilityReturnDraft = null;
      state.notice = '';
      state.saving = false;
      render();
      return;
    }
    state.drawer = '';
    state.drawerRouteId = '';
    state.draft = {};
    state.confirmation = null;
    state.notice = '';
    state.saving = false;
    render();
  }

  function closeUtilityDrawer() {
    const returnDrawer = state.utilityReturnDrawer;
    const returnDraft = state.utilityReturnDraft;
    state.utilityReturnDrawer = '';
    state.utilityReturnDraft = null;
    state.drawer = returnDrawer || '';
    state.draft = returnDrawer === 'route' && returnDraft ? returnDraft : {};
    state.notice = '';
    render();
  }

  function confirmationMarkup() {
    if (!state.confirmation) return '';
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    if (typeof renderer !== 'function') return '';
    const route = state.routes.find((item) => item.id === state.confirmation.id);
    return renderer({
      id: 'notification-route-delete-confirmation',
      action: 'delete-notification-route',
      tone: 'danger',
      title: `删除规则「${route?.name || state.confirmation.id}」`,
      description: '删除后这条通知规则及其匹配配置将从 notifyd 配置库移除，且无法撤销。',
      cancelLabel: '取消',
      confirmLabel: state.saving ? '正在删除' : '确认删除',
      disabled: state.saving
    });
  }

  function openChannel(channel = null) {
    const options = channel?.options || {};
    state.drawer = 'channel';
    state.confirmation = null;
    state.notice = '';
    state.draft = channel ? { editing: true, id: channel.id, name: channel.name, type: channel.type, enabled: channel.enabled, url: options.url || '', method: options.method || 'POST', timeout_ms: firstNumber(options.timeout_ms, 10000), headers: '', hasStoredHeaders: channel.hasStoredHeaders, user_ids: asArray(options.user_ids || options.users).join(', '), recipients: asArray(options.recipients || options.to).join(', '), subject_prefix: firstText(options.subject_prefix, '[Dreaming OS]'), reply_to: firstText(options.reply_to) } : { editing: false, id: '', name: '', type: 'noop', enabled: true, method: 'POST', timeout_ms: 10000, hasStoredHeaders: false, user_ids: '', recipients: '', subject_prefix: '[Dreaming OS]', reply_to: '' };
    render();
  }

  function openRoute(route = null) {
    state.utilityReturnDrawer = '';
    state.utilityReturnDraft = null;
    state.drawer = 'route';
    state.confirmation = null;
    state.notice = '';
    state.draft = route ? { editing: true, advanced: Boolean(route.source || (route.event && !routeEventsMap().has(route.event))), ...route } : { editing: false, id: '', name: '', enabled: true, channelId: state.settings.default_channel_id || state.channels[0]?.id || 'local', minSeverity: 'warning', category: '', event: '', source: '', advanced: false };
    render();
  }

  function openRouteDetail(route) {
    if (!route) return;
    state.drawer = 'route-detail';
    state.confirmation = null;
    state.drawerRouteId = route.id;
    state.notice = '';
    render();
  }

  function bindRowActions() {
    root.querySelectorAll('[data-notify-edit-channel]').forEach((button) => button.addEventListener('click', () => openChannel(state.channels.find((item) => item.id === button.dataset.notifyEditChannel))));
    root.querySelectorAll('[data-notify-edit-route]').forEach((button) => button.addEventListener('click', () => openRoute(state.routes.find((item) => item.id === button.dataset.notifyEditRoute))));
    root.querySelectorAll('[data-notify-route-detail]').forEach((button) => button.addEventListener('click', () => openRouteDetail(state.routes.find((item) => item.id === button.dataset.notifyRouteDetail))));
    root.querySelectorAll('[data-notify-route-row]').forEach((row) => row.addEventListener('click', (event) => { if (event.target.closest('button,input,a')) return; openRouteDetail(state.routes.find((item) => item.id === row.dataset.notifyRouteRow)); }));
    root.querySelectorAll('[data-notify-toggle-route]').forEach((button) => button.addEventListener('click', () => toggleRoute(button.dataset.notifyToggleRoute)));
    root.querySelectorAll('[data-notify-route-menu]').forEach((button) => button.addEventListener('click', () => openRouteDetail(state.routes.find((item) => item.id === button.dataset.notifyRouteMenu))));
    root.querySelectorAll('[data-notify-test]').forEach((button) => button.addEventListener('click', () => testChannel(button.dataset.notifyTest)));
    root.querySelectorAll('[data-notify-retry]').forEach((button) => button.addEventListener('click', () => retryOutbox(button.dataset.notifyRetry)));
    root.querySelectorAll('[data-notify-select-route]').forEach((input) => input.addEventListener('change', () => {
      const id = input.dataset.notifySelectRoute;
      state.selectedRouteIds = input.checked ? [...new Set([...state.selectedRouteIds, id])] : state.selectedRouteIds.filter((value) => value !== id);
      render();
    }));
    root.querySelector('[data-notify-select-all]')?.addEventListener('change', (event) => {
      const ids = filteredRoutes().map((route) => route.id);
      state.selectedRouteIds = event.target.checked ? [...new Set([...state.selectedRouteIds, ...ids])] : state.selectedRouteIds.filter((id) => !ids.includes(id));
      render();
    });
    root.querySelector('[data-notify-toggle-detail]')?.addEventListener('click', () => toggleRoute(state.drawerRouteId));
    root.querySelector('[data-notify-detail-edit]')?.addEventListener('click', () => openRoute(state.routes.find((item) => item.id === state.drawerRouteId)));
    root.querySelector('[data-notify-duplicate-route]')?.addEventListener('click', () => duplicateRoute(state.drawerRouteId));
    root.querySelector('[data-notify-delete-route]')?.addEventListener('click', () => { if (!state.saving) { state.confirmation = { id: state.drawerRouteId }; render(); } });
    root.querySelectorAll('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]').forEach((button) => button.addEventListener('click', () => { if (!state.saving) { state.confirmation = null; render(); } }));
    root.querySelectorAll('[data-dwrt-confirm-accept]').forEach((button) => button.addEventListener('click', () => deleteRoute(state.confirmation?.id)));
  }

  function patchSearchResults() {
    const card = root.querySelector(state.drawer ? '.notification-push-utility-drawer .notification-push-table-card' : '.notification-rule-table-card');
    if (!card) return render();
    const scroll = card.querySelector('.dwrt-kit-table-scroll');
    const scrollTop = scroll?.scrollTop || 0;
    const scrollLeft = scroll?.scrollLeft || 0;
    const view = currentTableKind();
    card.outerHTML = view === 'channels' ? channelTable() : view === 'outbox' ? outboxTable() : routeTable();
    const nextScroll = card.parentElement?.querySelector('.notification-push-table-card .dwrt-kit-table-scroll') || root.querySelector('.notification-push-table-card .dwrt-kit-table-scroll');
    if (nextScroll) {
      nextScroll.scrollTop = scrollTop;
      nextScroll.scrollLeft = scrollLeft;
    }
    bindRowActions();
  }

  /*
   * 搜索与筛选只重绘 tbody。搜索框现在在表格工具栏里，整卡 outerHTML 替换会连同
   * 正在输入的 input 一起销毁，光标随第一个字符丢失。
   */
  function syncTableRows() {
    const tableRoot = state.drawer ? root.querySelector('.notification-push-utility-drawer') : root;
    const tbody = tableRoot?.querySelector('.notification-push-table-card [data-notify-rows]');
    if (!tbody) return;
    const view = currentTableKind();
    const rows = view === 'channels' ? filteredChannels() : view === 'outbox' ? filteredOutbox() : filteredRoutes();
    tbody.innerHTML = view === 'channels' ? channelRowsMarkup(rows) : view === 'outbox' ? outboxRowsMarkup(rows) : routeRowsMarkup(rows);
    const count = tableRoot.querySelector('.notification-push-table-card [data-notify-table-count]');
    if (count) count.textContent = tableCountText(rows.length, view);
    bindRowActions();
  }

  function bindEvents() {
    root.querySelector('[data-notify-settings-form]')?.addEventListener('submit', (event) => event.preventDefault());
    root.querySelector('[data-notify-search]')?.addEventListener('input', (event) => { state.query = event.target.value || ''; syncTableRows(); });
    root.querySelector('[data-notify-state]')?.addEventListener('change', (event) => { state.outboxState = event.target.value || 'all'; syncTableRows(); });
    root.querySelector('[data-notify-create="channels"]')?.addEventListener('click', () => openChannel());
    root.querySelectorAll('[data-notify-create="rules"]').forEach((button) => button.addEventListener('click', () => openRoute()));
    root.querySelectorAll('[data-notify-filter]').forEach((input) => input.addEventListener('change', () => {
      const key = input.dataset.notifyFilter;
      const values = Array.isArray(state.ruleFilters[key]) ? state.ruleFilters[key].slice() : [];
      state.ruleFilters[key] = input.checked ? [...new Set([...values, input.value])] : values.filter((value) => value !== input.value);
      state.selectedRouteIds = [];
      render();
    }));
    root.querySelectorAll('[data-notify-enabled]').forEach((input) => input.addEventListener('change', () => { state.ruleFilters.enabled = input.dataset.notifyEnabled; state.selectedRouteIds = []; render(); }));
    root.querySelectorAll('[data-notify-triggered]').forEach((input) => input.addEventListener('change', () => { state.ruleFilters.triggered = input.dataset.notifyTriggered; state.selectedRouteIds = []; render(); }));
    root.querySelector('[data-notify-filter-reset]')?.addEventListener('click', () => { state.ruleFilters = { search: '', categories: [], severities: [], channels: [], events: [], actions: [], enabled: 'all', triggered: 'all' }; state.query = ''; state.selectedRouteIds = []; render(); });
    root.querySelector('[data-notify-clear-filters]')?.addEventListener('click', () => { state.ruleFilters = { search: '', categories: [], severities: [], channels: [], events: [], actions: [], enabled: 'all', triggered: 'all' }; state.query = ''; state.selectedRouteIds = []; render(); });
    root.querySelector('[data-notify-columns-toggle]')?.addEventListener('click', () => { state.columnMenuOpen = !state.columnMenuOpen; render(); });
    root.querySelectorAll('[data-notify-column-toggle]').forEach((input) => input.addEventListener('change', () => {
      const id = input.dataset.notifyColumnToggle;
      if (input.checked) state.ruleColumns = [...new Set([...state.ruleColumns, id])];
      else if (state.ruleColumns.length > 1) state.ruleColumns = state.ruleColumns.filter((value) => value !== id);
      render();
    }));
    root.querySelectorAll('[data-notify-filter-fold]').forEach((button) => button.addEventListener('click', () => button.closest('.notification-filter-section')?.classList.toggle('is-collapsed')));
    root.querySelectorAll('[data-notify-bulk]').forEach((button) => button.addEventListener('click', () => bulkToggleRoutes(button.dataset.notifyBulk === 'enable')));
    root.querySelectorAll('[data-notify-utility-close]').forEach((button) => button.addEventListener('click', () => { state.confirmation = null; closeUtilityDrawer(); }));
    root.querySelectorAll('[data-notify-close]').forEach((button) => button.addEventListener('click', () => { state.confirmation = null; closeDrawer(); }));
    root.querySelectorAll('[data-notify-open-utility]').forEach((button) => button.addEventListener('click', () => {
      if (state.drawer === 'route') {
        state.utilityReturnDrawer = 'route';
        state.utilityReturnDraft = { ...state.draft };
      }
      state.drawer = button.dataset.notifyOpenUtility === 'channels' ? 'channel-manager' : button.dataset.notifyOpenUtility;
      state.query = '';
      render();
    }));
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
      const returnDrawer = state.utilityReturnDrawer;
      const returnDraft = state.utilityReturnDraft;
      state.drawer = returnDrawer || '';
      state.draft = returnDrawer === 'route' && returnDraft ? returnDraft : {};
      state.utilityReturnDrawer = '';
      state.utilityReturnDraft = null;
      state.saving = false; await load(); window.DreamingWrtNotify?.success('推送通道已保存');
    } catch (error) { state.saving = false; state.notice = `保存失败：${firstText(error.message, 'unknown')}`; render(); }
  }

  async function saveRoute() {
    if (state.saving) return;
    const draft = state.draft;
    if (!draft.id || !draft.name || !draft.channelId) { state.notice = '规则 ID、名称和通道不能为空。'; render(); return; }
    state.saving = true; render();
    try {
      await requestJson(ENDPOINTS.routes, { method: 'PUT', body: JSON.stringify({ id: draft.id, name: draft.name, enabled: draft.enabled !== false, channel_id: draft.channelId, min_severity: draft.minSeverity || 'warning', category: draft.category || '', event: draft.event || '', source: draft.source || '', options: draft.options || {} }) });
      state.drawer = ''; state.drawerRouteId = ''; state.draft = {}; state.confirmation = null; state.saving = false; await load(); window.DreamingWrtNotify?.success('通知规则已保存');
    } catch (error) { state.saving = false; state.notice = `保存失败：${firstText(error.message, 'unknown')}`; render(); }
  }

  async function updateRoute(route, enabled) {
    if (!route || state.workingId) return false;
    state.workingId = route.id;
    try {
      await requestJson(ENDPOINTS.routes, { method: 'PUT', body: JSON.stringify({ id: route.id, name: route.name, enabled, channel_id: route.channelId, min_severity: route.minSeverity || 'warning', category: route.category || '', event: route.event || '', source: route.source || '', options: route.options || {}, expected_updated_at: route.updatedAt || undefined }) });
      return true;
    } catch (error) {
      state.notice = `操作失败：${firstText(error.message, 'unknown')}`;
      window.DreamingWrtNotify?.error('通知规则操作失败', firstText(error.message, 'unknown'));
      return false;
    } finally { state.workingId = ''; }
  }

  async function toggleRoute(id) {
    const route = state.routes.find((item) => item.id === id);
    if (!route) return;
    const ok = await updateRoute(route, !route.enabled);
    if (ok) { state.notice = ''; await load(); if (state.drawer === 'route-detail') render(); window.DreamingWrtNotify?.success(route.enabled ? '规则已启用' : '规则已暂停'); }
    else render();
  }

  async function bulkToggleRoutes(enabled) {
    const targets = state.routes.filter((route) => state.selectedRouteIds.includes(route.id));
    if (!targets.length || state.workingId) return;
    state.saving = true; render();
    const results = [];
    for (const route of targets) results.push(await updateRoute(route, enabled));
    state.saving = false;
    state.selectedRouteIds = [];
    if (results.every(Boolean)) { state.notice = ''; await load(); window.DreamingWrtNotify?.success(enabled ? '已启用所选规则' : '已暂停所选规则'); }
    else render();
  }

  async function duplicateRoute(id) {
    const route = state.routes.find((item) => item.id === id);
    if (!route || state.saving) return;
    const used = new Set(state.routes.map((item) => item.id));
    let nextId = `${route.id}-copy`;
    let suffix = 2;
    while (used.has(nextId)) nextId = `${route.id}-copy-${suffix++}`;
    state.saving = true;
    try {
      await requestJson(ENDPOINTS.routes, { method: 'PUT', body: JSON.stringify({ id: nextId, name: `${route.name} 副本`, enabled: false, channel_id: route.channelId, min_severity: route.minSeverity || 'warning', category: route.category || '', event: route.event || '', source: route.source || '', options: route.options || {} }) });
      state.saving = false; state.drawer = ''; state.drawerRouteId = ''; await load(); window.DreamingWrtNotify?.success('规则副本已创建，默认暂停');
    } catch (error) { state.saving = false; state.notice = `操作失败：${firstText(error.message, 'unknown')}`; render(); }
  }

  async function deleteRoute(id) {
    if (!id || state.saving) return;
    state.saving = true; render();
    try {
      await requestJson(`${ENDPOINTS.routes}/${encodeURIComponent(id)}`, { method: 'DELETE' });
      state.saving = false; state.confirmation = null; state.drawer = ''; state.drawerRouteId = ''; await load(); window.DreamingWrtNotify?.success('规则已删除');
    } catch (error) { state.saving = false; state.confirmation = null; state.notice = `操作失败：${firstText(error.message, 'unknown')}`; render(); }
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
