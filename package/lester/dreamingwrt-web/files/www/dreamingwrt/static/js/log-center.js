(() => {
  'use strict';

  const VERSION = '20260804-native-plugin-menu-merge-01';
  const REFRESH_MS = 30000;
  const SEARCH_DEBOUNCE_MS = 650;
  const DEFAULT_PAGE_SIZE = 25;
  // 表格描述列的截断长度，超出后折叠为「…」，点击展开。
  const MESSAGE_CLAMP_CHARS = 120;
  const ENDPOINTS = {
    settings: '/api/v1/logs/settings',
    filters: '/api/v1/logs/filter-data',
    count: '/api/v1/logs/count',
    search: '/api/v1/logs/search',
    query: '/api/v1/logs/query',
    export: '/api/v1/logs/export',
    aiAnalyze: '/api/v1/ai/logs/analyze',
    eventSearch: '/api/v1/logs/events/search',
    legacy: '/api/v1/logs'
  };
  const PERIODS = {
    day: { label: '1 天', ms: 86400000 },
    threeDays: { label: '3 天', ms: 259200000 },
    week: { label: '1 周', ms: 604800000 },
    twoWeeks: { label: '2 周', ms: 1209600000 },
    month: { label: '1 月', ms: 2592000000 },
    custom: { label: '自定义', ms: 86400000 }
  };
  const SEVERITIES = [
    { id: 'LOW', label: '低', bars: 'low' },
    { id: 'MEDIUM', label: '可疑', bars: 'medium' },
    { id: 'HIGH', label: '高', bars: 'high' },
    { id: 'VERY_HIGH', label: '严重', bars: 'critical' }
  ];
  const GENERAL_CATEGORIES = [
    ['SYSTEM', '系统'],
    ['GENERAL', '常规'],
    ['ADMIN', '管理员'],
    ['AUDIT', '审计'],
    ['KERNEL', '内核'],
    ['NOTIFICATION', '通知'],
    ['SECURITY', '安全'],
    ['POWER', '电源'],
    ['INTERNET_AND_WAN', '互联网与 WAN'],
    ['CLIENT_DEVICES', '客户端设备'],
    ['SOFTWARE_UPDATES', '软件更新'],
    ['VPN', 'VPN'],
    ['HOST', '主机']
  ];
  const GENERAL_EVENTS = [
    ['CLIENT_DISCONNECTED_WIRED', '有线客户端断开'],
    ['CLIENT_CONNECTED_WIRED', '有线客户端连接'],
    ['DEVICE_COMMIT_ERROR', '网关配置变更失败'],
    ['MODEM_RESTARTED', '调制解调器已重启'],
    ['PORT_TRANSMISSION_ERRORS', '端口传输错误'],
    ['PORT_LINK_FLAPPING', '端口链路抖动'],
    ['PORT_DROPPING_TRAFFIC', '端口丢弃流量'],
    ['MULTIPLE_INTERNET_DISCONNECTIONS', '互联网多次断开'],
    ['MULTIPLE_DEVICE_RECONNECTIONS', '多台设备反复重连'],
    ['MULTIPLE_AP_UPDATES_REQUIRED', '多个接入点需要更新'],
    ['MULTIPLE_DEVICE_UPDATES_AVAILABLE', '多台设备有可用更新'],
    ['MULTIPLE_DEVICES_OFFLINE', '多台设备离线']
  ];
  const AUDIT_EVENTS = [
    ['CONFIG_CREATED', '创建配置'],
    ['CONFIG_MODIFIED', '修改配置'],
    ['CONFIG_REMOVED', '删除配置'],
    ['NETWORK_ACCESSED', '访问网络'],
    ['CONFIG_RESUMED', '恢复配置'],
    ['CONFIG_PAUSED', '暂停配置']
  ];
  const LOG_SOURCE_FILTERS = [
    { id: 'general', label: '常规', sections: ['function', 'system', 'syslog'], modes: ['GENERAL'] },
    { id: 'audit', label: '审计 / 用户', sections: ['user'], modes: ['AUDIT'] },
    { id: 'kernel', label: '内核日志', sections: ['kernel'], modes: ['GENERAL'] },
    { id: 'notification', label: '通知', sections: ['message'], modes: ['GENERAL'] },
    { id: 'alarm', label: '告警信息', sections: ['warning'], modes: ['GENERAL'], severities: ['MEDIUM', 'HIGH', 'VERY_HIGH'] },
    { id: 'syslog', label: '原始 Syslog', sections: ['syslog'], modes: ['GENERAL'], categories: ['HOST'] }
  ];
  // 每个 tab 只允许勾选属于自己的来源，避免勾选来源反过来改写 tab。
  const SOURCES_BY_MODE = {
    GENERAL: LOG_SOURCE_FILTERS.filter((item) => item.modes.includes('GENERAL')).map((item) => item.id),
    AUDIT: LOG_SOURCE_FILTERS.filter((item) => item.modes.includes('AUDIT')).map((item) => item.id)
  };
  const DEFAULT_SOURCE_BY_MODE = { GENERAL: 'general', AUDIT: 'audit' };
  // 30.1 实测：后端 logs/search 只认 severities / categories / events，
  // 完全忽略 type 与 sources。审计日志实际落在 ADMIN 分类与
  // ADMIN_AUTH_EVENT 事件里，因此「审计」tab 必须靠分类维度取数，
  // 否则两个 tab 会拿回同一批系统日志。
  const AUDIT_CATEGORY_IDS = ['ADMIN', 'AUDIT'];
  const AUDIT_EVENT_IDS = ['ADMIN_AUTH_EVENT'];
  const SOURCE_BY_SECTION = {
    user: 'audit',
    audit: 'audit',
    function: 'general',
    system: 'general',
    general: 'general',
    kernel: 'kernel',
    dmesg: 'kernel',
    message: 'notification',
    notification: 'notification',
    notifications: 'notification',
    warning: 'alarm',
    alarm: 'alarm',
    alert: 'alarm',
    syslog: 'syslog',
    raw_syslog: 'syslog'
  };
  const PROGRAM_LABELS = {
    openclash: 'OpenClash',
    clash: 'Clash',
    mihomo: 'Mihomo',
    nikki: 'Nikki',
    passwall: 'PassWall',
    homeproxy: 'HomeProxy',
    'sing-box': 'sing-box',
    mosdns: 'MosDNS',
    adguardhome: 'AdGuard Home',
    tailscale: 'Tailscale',
    zerotier: 'ZeroTier',
    dockerd: 'Docker',
    docker: 'Docker',
    samba: 'Samba',
    nlbwmon: '流量统计',
    mwan3: 'MWAN3',
    pbr: '策略路由',
    sqm: 'SQM',
    dnsmasq: 'DNSMasq',
    odhcpd: 'ODHCPd',
    netifd: '网络接口',
    firewall: '防火墙',
    dropbear: 'SSH',
    sshd: 'SSH',
    cron: '计划任务',
    crond: '计划任务',
    tor: 'Tor',
    netdata: 'Netdata',
    kernel: '内核'
  };
  const EVENT_LABELS = {
    SYSTEM_LOG: '系统日志',
    LOG_EVENT: '日志事件',
    AUDIT_LOG: '审计日志',
    KERNEL_LOG: '内核日志',
    USER_LOG: '用户日志',
    FUNCTION_LOG: '功能日志',
    NOTIFICATION: '通知',
    WARNING: '告警',
    SYSTEM_RESOURCE_THRESHOLD: '系统资源阈值',
    CLIENT_CONNECTED: '客户端连接',
    CLIENT_DISCONNECTED: '客户端断开',
    PORT_LINK_UP: '端口链路上线',
    PORT_LINK_DOWN: '端口链路下线',
    PORT_EVENT: '端口事件',
    WAN_EVENT: 'WAN 事件',
    PPPOE_EVENT: 'PPPoE 事件',
    ADMIN_AUTH_EVENT: '管理员认证事件',
    PACKET_CAPTURE_STARTED: '开始抓包',
    PACKET_CAPTURE_STOPPED: '停止抓包',
    KERNEL: '内核日志'
  };

  function fallbackEscape(value) {
    return String(value === undefined || value === null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function textFromUnknown(value, depth = 0) {
    if (value === undefined || value === null) return '';
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value).trim();
    if (Array.isArray(value)) {
      for (const item of value) {
        const text = textFromUnknown(item, depth + 1);
        if (text) return text;
      }
      return '';
    }
    if (typeof value === 'object' && depth < 2) {
      for (const key of ['title', 'label', 'name', 'display_name', 'hostname', 'username', 'event', 'message', 'detail', 'description', 'value', 'id']) {
        if (Object.prototype.hasOwnProperty.call(value, key)) {
          const text = textFromUnknown(value[key], depth + 1);
          if (text) return text;
        }
      }
    }
    return '';
  }

  function fallbackText(...values) {
    for (const value of values) {
      const text = textFromUnknown(value);
      if (text) return text;
    }
    return '';
  }

  function fallbackNumber(...values) {
    for (const value of values) {
      const num = Number(value);
      if (Number.isFinite(num)) return num;
    }
    return 0;
  }

  function create(options = {}) {
    const root = options.routePreview || document.getElementById('routePreview');
    const escapeHtml = options.escapeHtml || fallbackEscape;
    const firstText = options.firstText || fallbackText;
    const firstNumber = options.firstNumber || fallbackNumber;
    const formatInteger = options.formatInteger || ((value) => Number(value || 0).toLocaleString('zh-CN'));
    const fetchApiResource = options.fetchApiResource || (async (name) => ({ name, ok: false, data: {}, error: new Error(`${name}: fetch unavailable`) }));
    const mountUiKit = options.mountUiKit || ((target) => window.DWRT_UI_KIT?.mountAll(target));
    const scheduleGlassCardsRender = options.scheduleGlassCardsRender || (() => {});
    const routeTo = options.routeTo || ((path) => { window.location.href = path; });

    const state = {
      mode: 'GENERAL',
      sources: new Set(['general']),
      view: 'logs',
      period: 'day',
      customRange: null,
      search: '',
      eventSearch: '',
      severities: new Set(SEVERITIES.map((item) => item.id)),
      categories: new Set(),
      events: new Set(),
      deviceMacs: new Set(),
      clientDeviceMacs: new Set(),
      adminIds: new Set(),
      programs: new Set(),
      selectedRows: new Set(),
      collapsed: new Set(['events', 'devices', 'clients', 'admins']),
      expandedMessages: new Set(),
      filterLocallyEnforced: false,
      rows: [],
      allRows: [],
      total: 0,
      pageNumber: 0,
      pageSize: DEFAULT_PAGE_SIZE,
      filterData: null,
      settings: null,
      selectedId: '',
      selectedRow: null,
      loading: false,
      source: '',
      error: '',
      notice: '',
      exportResult: null,
      refreshTimer: 0,
      refreshSeq: 0,
      searchTimer: 0,
      newProtocolUnavailableUntil: 0,
      newProtocolAvailable: false,
      aiLoading: false,
      aiResult: null,
      pendingRefreshOptions: null,
      bound: false
    };

    const html = (value) => escapeHtml(value);
    const asArray = (value) => Array.isArray(value) ? value : [];
    const cssEscape = (value) => {
      if (window.CSS && typeof window.CSS.escape === 'function') return window.CSS.escape(String(value));
      return String(value).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
    };

    function authHeaders(extra = {}) {
      if (typeof options.authHeaders === 'function') return options.authHeaders(extra);
      let token = '';
      try { token = localStorage.getItem('dreamingwrt.web.accessToken') || ''; } catch (_) {}
      return token ? { ...extra, Authorization: `Bearer ${token}` } : extra;
    }

    function unwrapApiData(payload) {
      if (!payload || typeof payload !== 'object') return {};
      // webd 对该组接口返回 { ok, data: { ok, data: [...] } } 双层包裹，
      // 只剥一层会拿不到 total/分页字段，这里剥到真正的载荷为止。
      let current = payload;
      for (let depth = 0; depth < 4; depth += 1) {
        if (!current || typeof current !== 'object' || Array.isArray(current)) break;
        const next = current.data && typeof current.data === 'object'
          ? current.data
          : (current.body && typeof current.body === 'object' ? current.body : null);
        if (!next) break;
        // 内层若已是数组或不再是 {ok,data} 包裹，则本层即为载荷宿主。
        current = next;
        if (Array.isArray(current)) break;
      }
      return current || {};
    }

    async function requestJson(name, url, init = {}) {
      const hasBody = init.body !== undefined;
      const response = await fetch(url, {
        method: init.method || (hasBody ? 'POST' : 'GET'),
        credentials: 'same-origin',
        cache: 'no-store',
        headers: authHeaders({
          Accept: 'application/json',
          ...(hasBody ? { 'Content-Type': 'application/json' } : {}),
          ...(init.headers || {})
        }),
        body: hasBody ? JSON.stringify(init.body || {}) : undefined
      });
      const text = await response.text();
      let json = {};
      if (text) {
        try { json = JSON.parse(text); } catch (_) { throw new Error(`${name}: invalid json`); }
      }
      if (!response.ok || json && json.ok === false) {
        const message = json && (json.message || json.error && (json.error.message || json.error.code) || json.error) || `${response.status}`;
        const error = new Error(`${name}: ${message}`);
        error.status = response.status;
        error.payload = json;
        throw error;
      }
      return unwrapApiData(json);
    }

    function sourceMeta(id) {
      return LOG_SOURCE_FILTERS.find((item) => item.id === id) || null;
    }

    function applyInitialRoute(params = {}) {
      const raw = String(params.section || params.id || params.item && (params.item.id || params.item.func_name) || '').trim();
      const route = String(params.route || params.path || window.location.hash || '');
      const match = route.match(/\/logs(?:\/([^/?#]+))?/);
      const legacy = raw || (match && match[1]) || '';
      const sourceFromLegacy = {
        'log-user': 'audit',
        user: 'audit',
        'log-function': 'general',
        function: 'general',
        'log-system': 'general',
        system: 'general',
        'log-kernel': 'kernel',
        kernel: 'kernel',
        'log-message': 'notification',
        message: 'notification',
        'log-warning': 'alarm',
        warning: 'alarm',
        'log-syslog': 'syslog',
        syslog: 'syslog',
        'log-center': 'general',
        logs: 'general',
        'log-settings': 'general',
        settings: 'general'
      }[legacy] || 'general';
      state.view = legacy === 'log-settings' || legacy === 'settings' ? 'settings' : 'logs';
      state.sources = new Set([sourceFromLegacy]);
      const meta = sourceMeta(sourceFromLegacy);
      state.mode = meta && meta.modes && meta.modes.includes('AUDIT') ? 'AUDIT' : 'GENERAL';
      state.pageNumber = 0;
      state.selectedId = '';
      state.selectedRow = null;
      state.categories.clear();
      state.events.clear();
      state.deviceMacs.clear();
      state.clientDeviceMacs.clear();
      state.adminIds.clear();
      state.programs.clear();
      state.selectedRows.clear();
      state.severities = new Set(SEVERITIES.map((item) => item.id));
      state.eventSearch = '';
      if (sourceFromLegacy === 'alarm') state.severities = new Set(['HIGH', 'VERY_HIGH', 'MEDIUM']);
      if (sourceFromLegacy === 'syslog') state.categories.add('HOST');
    }

    function nowRange() {
      return currentRange();
    }

    function defaultSourceForMode(mode = state.mode) {
      return DEFAULT_SOURCE_BY_MODE[mode] || 'general';
    }

    function sourcesForMode(mode = state.mode) {
      return SOURCES_BY_MODE[mode] || SOURCES_BY_MODE.GENERAL;
    }

    function modeSourceFilters(mode = state.mode) {
      return LOG_SOURCE_FILTERS.filter((item) => item.modes.includes(mode));
    }

    // 「常规」是路由器自身日志，「审计」是 Web/用户操作日志。
    // 两者必须是互斥的行集合，否则两个 tab 会显示一模一样的内容。
    function modeAllowsSource(sourceId, mode = state.mode) {
      if (!sourceId) return true;
      return sourcesForMode(mode).includes(sourceId);
    }

    // 判定一行是否属于「审计」语义：后端 source_id 恒为 general，
    // 只能靠分类/事件识别管理员与用户操作。
    function isAuditRow(row) {
      const category = String(row.category || '').toUpperCase();
      const event = String(row.event || '').toUpperCase();
      if (AUDIT_CATEGORY_IDS.includes(category)) return true;
      if (AUDIT_EVENT_IDS.includes(event)) return true;
      if (row.sourceId === 'audit') return true;
      if (AUDIT_EVENTS.some(([id]) => id === event)) return true;
      return Boolean(row.admin && (row.admin.id || row.admin.name));
    }

    // tab 归属判定：审计 tab 只显示审计行，常规 tab 排除审计行。
    function modeAllowsRow(row, mode = state.mode) {
      return mode === 'AUDIT' ? isAuditRow(row) : !isAuditRow(row);
    }

    function currentRange() {
      if (state.period === 'custom' && state.customRange) {
        return {
          timestampFrom: state.customRange.start,
          timestampTo: state.customRange.end
        };
      }
      const end = Date.now();
      const period = PERIODS[state.period] || PERIODS.day;
      return { timestampFrom: end - period.ms, timestampTo: end };
    }

    function requestBody() {
      const range = currentRange();
      // 只提交属于当前 tab 的来源，避免后端把两个 tab 当成同一次查询。
      const sourceIds = Array.from(state.sources).filter((id) => modeAllowsSource(id));
      const effectiveSources = sourceIds.length ? sourceIds : [defaultSourceForMode()];
      const sourceSections = sourceIds.flatMap((id) => sourceMeta(id)?.sections || []);
      // 审计模式下若用户没有手选分类，则用后端真正认的 ADMIN 分类兜底，
      // 让「审计」tab 拿到的是用户/管理员操作日志而不是系统日志。
      const categories = Array.from(state.categories);
      const effectiveCategories = categories.length
        ? categories
        : (state.mode === 'AUDIT' ? AUDIT_CATEGORY_IDS.slice() : []);
      return {
        type: state.mode,
        searchText: state.search,
        severities: Array.from(state.severities),
        sources: effectiveSources,
        sections: sourceSections.length ? sourceSections : (sourceMeta(defaultSourceForMode())?.sections || []),
        logSources: effectiveSources,
        timestampFrom: range.timestampFrom,
        timestampTo: range.timestampTo,
        pageNumber: state.pageNumber,
        pageSize: state.pageSize,
        categories: effectiveCategories,
        events: Array.from(state.events),
        deviceMacs: Array.from(state.deviceMacs),
        clientDeviceMacs: Array.from(state.clientDeviceMacs),
        adminIds: Array.from(state.adminIds),
        programs: Array.from(state.programs)
      };
    }

    function settingNumber(key, fallback) {
      return firstNumber(state.settings && state.settings[key], fallback);
    }

    function syslogSettings() {
      return state.settings && state.settings.syslog && typeof state.settings.syslog === 'object'
        ? state.settings.syslog
        : {};
    }

    function listFrom(payload, keys = ['items', 'data', 'rows', 'records', 'results', 'logs']) {
      if (Array.isArray(payload)) return payload;
      if (!payload || typeof payload !== 'object') return [];
      for (const key of keys) {
        if (Array.isArray(payload[key])) return payload[key];
      }
      return [];
    }

    function severityKey(...values) {
      const text = firstText(...values).toUpperCase().replace(/[\s-]+/g, '_');
      if (/VERY|CRITICAL|FATAL|EMERG|ALERT|ERROR|ERR|严重|紧急/.test(text)) return 'VERY_HIGH';
      if (/HIGH|WARN|WARNING|ALARM|ACTIVE|高|警告|告警/.test(text)) return 'HIGH';
      if (/MEDIUM|NOTICE|SUSPICIOUS|中|可疑/.test(text)) return 'MEDIUM';
      if (/LOW|INFO|SUCCESS|DEBUG|低|普通|成功/.test(text)) return 'LOW';
      return 'LOW';
    }

    function severityLabel(key) {
      return (SEVERITIES.find((item) => item.id === key) || SEVERITIES[0]).label;
    }

    function inferSourceId(item = {}, fallback = '') {
      const direct = firstText(item.source_id, item.sourceId, item.log_source, item.logSource, item.section, item.log_type, item.logType, item.kind);
      const directKey = SOURCE_BY_SECTION[direct.toLowerCase && direct.toLowerCase()] || SOURCE_BY_SECTION[direct] || '';
      if (directKey && directKey !== 'general') return directKey;
      const typeText = [
        item.type,
        item.category,
        item.source,
        item.facility,
        item.module,
        item.title,
        item.event,
        item.message,
        item.description,
        item.detail
      ].map((value) => firstText(value)).filter(Boolean).join(' ').toLowerCase();
      if (/kernel|kern\.|dmesg|内核/.test(typeText)) return 'kernel';
      if (/audit|user|admin|login|auth\.|sshd|dropbear|审计|用户|登录/.test(typeText)) return 'audit';
      if (/notification|notice|message|通知/.test(typeText)) return 'notification';
      if (/alarm|alert|warn|warning|告警|警告/.test(typeText)) return 'alarm';
      if (/syslog|logread|raw/.test(typeText)) return 'syslog';
      return directKey || fallback || (state.mode === 'AUDIT' ? 'audit' : 'general');
    }

    function sourceLabelFor(id) {
      return sourceMeta(id)?.label || '常规';
    }

    function programIdentity(item = {}, parsed = {}, raw = '') {
      const candidates = [
        item.program,
        item.program_name,
        item.process,
        item.process_name,
        item.service,
        item.service_name,
        item.daemon,
        item.package,
        item.package_name,
        item.module,
        parsed.module
      ].map((value) => firstText(value)).filter(Boolean);
      const evidence = [...candidates, raw].join(' ').toLowerCase();
      const known = Object.keys(PROGRAM_LABELS).find((key) => evidence.includes(key));
      let id = known || candidates
        .map((value) => value.toLowerCase().replace(/^.*\//, '').replace(/\[\d+\]$/, '').replace(/[^a-z0-9_.@-]+/g, '-').replace(/^-+|-+$/g, ''))
        .find((value) => value && !/^(system|general|host|logread|syslog|daemon|user|message|warning|function)$/.test(value));
      if (!id || id.length > 48) return { id: '', label: '' };
      const label = PROGRAM_LABELS[id]
        || candidates.find((value) => value.toLowerCase().includes(id))?.replace(/\[\d+\]$/, '')
        || id.replace(/[-_]+/g, ' ');
      return { id, label };
    }

    function categoryLabel(key) {
      const direct = GENERAL_CATEGORIES.find(([id]) => id === key);
      if (direct) return direct[1];
      return firstText(key).replace(/_/g, ' ') || '--';
    }

    function eventLabel(key) {
      const normalizedKey = String(key || '').toUpperCase();
      if (EVENT_LABELS[normalizedKey]) return EVENT_LABELS[normalizedKey];
      const source = state.mode === 'AUDIT' ? AUDIT_EVENTS : GENERAL_EVENTS;
      const direct = source.find(([id]) => id === key);
      if (direct) return direct[1];
      return firstText(key).replace(/_/g, ' ') || '--';
    }

    function legacyCategoryFor(item = {}, sourceHint = '') {
      const type = String(firstText(item.type, sourceHint)).toLowerCase();
      if (/user|audit|用户/.test(type)) return 'AUDIT';
      if (/function|功能/.test(type)) return 'CLIENT_DEVICES';
      if (/kernel|内核/.test(type)) return 'HOST';
      if (/message|notice|通知/.test(type)) return 'HOST';
      if (/warning|alarm|告警/.test(type)) return 'SECURITY';
      if (/syslog/.test(type)) return 'HOST';
      return 'HOST';
    }

    function legacyEventTitle(item = {}) {
      const explicit = firstText(item.title);
      if (explicit) return explicit;
      const raw = firstText(item.event, item.message, item.detail);
      if (!raw) return '日志事件';
      const parsed = parseLegacyLogLine(raw);
      if (parsed.message) return parsed.message.slice(0, 120);
      const colon = raw.lastIndexOf(': ');
      const tail = colon >= 0 ? raw.slice(colon + 2) : raw;
      return tail.replace(/\[[^\]]+\]\s*/g, '').trim().slice(0, 120) || raw.slice(0, 120);
    }

    const MONTH_INDEX = {
      jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
      jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11
    };

    function legacyDateMs(month, day, hour, minute, second, year) {
      const monthIndex = MONTH_INDEX[String(month || '').slice(0, 3).toLowerCase()];
      const y = Number(year) || new Date().getFullYear();
      const d = Number(day);
      const h = Number(hour);
      const m = Number(minute);
      const s = Number(second);
      if (!Number.isFinite(monthIndex) || !Number.isFinite(d) || !Number.isFinite(h) || !Number.isFinite(m) || !Number.isFinite(s)) return 0;
      const date = new Date(y, monthIndex, d, h, m, s, 0);
      return Number.isFinite(date.getTime()) ? date.getTime() : 0;
    }

    function parseLegacyLogLine(value) {
      const text = firstText(value);
      if (!text) return {};
      const withYear = text.match(/^(?:[A-Z][a-z]{2}\s+)?([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\s+(\S+)\s+([^:]+):\s*([\s\S]*)$/);
      if (withYear) {
        return {
          timestamp: legacyDateMs(withYear[1], withYear[2], withYear[3], withYear[4], withYear[5], withYear[6]),
          facility: withYear[7],
          module: withYear[8],
          message: withYear[9] || ''
        };
      }
      const withoutYear = text.match(/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(?:(\S+)\s+)?([^:]+):\s*([\s\S]*)$/);
      if (withoutYear) {
        return {
          timestamp: legacyDateMs(withoutYear[1], withoutYear[2], withoutYear[3], withoutYear[4], withoutYear[5], new Date().getFullYear()),
          facility: withoutYear[6] || '',
          module: withoutYear[7],
          message: withoutYear[8] || ''
        };
      }
      return {};
    }

    function timeMs(value) {
      const raw = Number(value);
      if (!Number.isFinite(raw) || raw <= 0) return 0;
      return raw > 100000000000 ? raw : raw * 1000;
    }

    function formatTime(value) {
      const ms = timeMs(value);
      if (!ms) return '--';
      const date = new Date(ms);
      if (!Number.isFinite(date.getTime())) return '--';
      return new Intl.DateTimeFormat('zh-CN', {
        hour12: false,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      }).format(date);
    }

    function normalizeLogItem(item = {}, index = 0, sourceHint = '') {
      const params = item.parameters && typeof item.parameters === 'object' ? item.parameters : {};
      const rawParams = params.RAW && typeof params.RAW === 'object' ? params.RAW : {};
      const rawDetail = rawParams.detail_json && typeof rawParams.detail_json === 'object' ? rawParams.detail_json : {};
      const device = params.DEVICE || params.device || item.device || {};
      const client = params.CLIENT || params.client || item.client || {};
      const admin = params.ADMIN || params.admin || item.admin || {};
      const severity = severityKey(item.severity, item.level, item.priority, item.status, item.type);
      const category = firstText(item.category, item.category_key, item.type === 'audit' ? 'AUDIT' : '', sourceHint);
      const event = firstText(item.event, item.key, item.event_key, item.action, item.title_raw, item.title, item.message_type);
      const message = firstText(item.message, item.message_raw, item.description, item.detail, item.title, item.title_raw, item.event, item.action);
      const timestamp = timeMs(firstNumber(item.timestamp, item.ts, item.time, item.created_at, item.date));
      const sourceEvidence = {
        ...item,
        source_id: firstText(item.source_id, rawParams.source),
        category: firstText(item.raw_category, rawParams.category, item.category),
        facility: firstText(item.facility, rawDetail.facility),
        module: firstText(item.module, rawDetail.module, rawDetail.collector),
        message: firstText(item.message, rawDetail.line, item.title),
        kernel: rawDetail.kernel
      };
      const sourceId = rawDetail.kernel === true || /^(?:kernel|kernel_log)$/i.test(firstText(item.raw_category, rawParams.category, rawParams.source))
        ? 'kernel'
        : inferSourceId(sourceEvidence);
      const rawText = firstText(item.raw_log, item.raw, rawDetail.line, item.message, item.event, item.title);
      const parsed = parseLegacyLogLine(rawText);
      const program = sourceId === 'kernel'
        ? { id: 'kernel', label: '内核' }
        : programIdentity(sourceEvidence, parsed, rawText);
      const sourceLabel = program.label || sourceLabelFor(sourceId);
      return {
        id: firstText(item.id, item.external_id, item.uuid, `${sourceHint || 'log'}-${timestamp || Date.now()}-${index}`),
        externalId: firstText(item.external_id, item.uuid),
        category: category || (state.mode === 'AUDIT' ? 'AUDIT' : 'HOST'),
        categoryLabel: categoryLabel(category || (state.mode === 'AUDIT' ? 'AUDIT' : 'HOST')),
        event: event || 'LOG_EVENT',
        eventLabel: firstText(item.title, item.title_raw, eventLabel(event), event, '日志事件'),
        message,
        severity,
        severityLabel: severityLabel(severity),
        status: firstText(item.status, ''),
        target: firstText(item.target, item.target_type, ''),
        type: firstText(item.type, sourceHint),
        timestamp,
        source: firstText(item.source, item.facility, item.module, sourceHint),
        sourceId,
        sourceLabel,
        programId: program.id,
        programLabel: program.label,
        device: {
          name: firstText(device.name, item.device_name, item.hostname, ''),
          ip: firstText(device.ip, item.device_ip, item.ip, ''),
          mac: firstText(device.mac, device.id, item.device_mac, item.mac, ''),
          model: firstText(device.model, item.model, ''),
          version: firstText(device.version, item.version, '')
        },
        client: {
          name: firstText(client.name, client.hostname, item.client_name, item.username, ''),
          ip: firstText(client.ip, item.client_ip, item.auth_ip, ''),
          mac: firstText(client.mac, item.client_mac, item.identity, '')
        },
        admin: {
          id: firstText(admin.id, item.admin_id, item.actor_id, item.username, ''),
          name: firstText(admin.name, item.admin_name, item.actor, item.username, item.user, '')
        },
        raw: item,
        cef: firstText(item.cef, item.syslog, item.raw_log, item.raw)
      };
    }

    function normalizeLegacyLogItem(item = {}, index = 0, sourceHint = '', sourceId = '') {
      const row = normalizeLogItem(item, index, sourceHint);
      const category = firstText(item.category) || legacyCategoryFor(item, sourceHint);
      const raw = firstText(item.message, item.message_raw, item.description, item.detail, item.event, item.title);
      const parsed = parseLegacyLogLine(raw);
      const title = firstText(item.title && item.title !== raw ? item.title : '', parsed.message, legacyEventTitle(item));
      const inferredSourceId = sourceId === 'general'
        ? inferSourceId({ ...item, message: raw, source: parsed.facility, module: parsed.module }, sourceId)
        : sourceId;
      const program = programIdentity(item, parsed, raw);
      return {
        ...row,
        category,
        categoryLabel: program.label || sourceLabelFor(inferredSourceId) || sourceHint || categoryLabel(category),
        event: firstText(item.key, item.event_key, item.action, parsed.module, title, 'LOG_EVENT'),
        eventLabel: title,
        message: raw || row.message,
        timestamp: parsed.timestamp || row.timestamp,
        source: firstText(item.source, parsed.facility, parsed.module, item.facility, item.module, row.source, sourceHint),
        sourceId: inferredSourceId,
        sourceLabel: program.label || sourceLabelFor(inferredSourceId) || sourceHint,
        programId: program.id,
        programLabel: program.label,
        device: {
          ...row.device,
          name: firstText(row.device.name, parsed.module)
        },
        cef: firstText(row.cef, raw)
      };
    }

    function normalizeSearchPayload(payload) {
      const list = listFrom(payload);
      const meta = Array.isArray(payload) ? {} : (payload || {});
      const rows = list.map((item, index) => normalizeLogItem(item, index, 'logs/search'));
      const total = firstNumber(meta.total_element_count, meta.total_count, meta.total, meta.count, rows.length);
      return {
        rows,
        total,
        pageNumber: firstNumber(meta.page_number, meta.pageNumber, state.pageNumber),
        pageSize: firstNumber(meta.page_size, meta.pageSize, state.pageSize)
      };
    }

    function legacySourceEntries(payload) {
      const data = payload || {};
      const syslog = data.syslog && typeof data.syslog === 'object' ? data.syslog : {};
      return [
        { id: 'audit', label: '审计 / 用户', rows: listFrom(data.user_logs || data.users || data.audit || data.audit_logs) },
        { id: 'general', label: '功能日志', rows: listFrom(data.function_logs || data.functions) },
        { id: 'general', label: '系统日志', rows: listFrom(data.system_logs || data.system) },
        { id: 'kernel', label: '内核日志', rows: listFrom(data.kernel_logs || data.kernel || data.dmesg) },
        { id: 'notification', label: '通知', rows: listFrom(data.notifications || data.messages) },
        { id: 'alarm', label: '告警信息', rows: listFrom(data.warnings || data.warning_logs) },
        { id: 'syslog', label: '原始 Syslog', rows: listFrom(syslog.events || data.syslog_events) }
      ];
    }

    function legacyRows(payload) {
      return legacySourceEntries(payload)
        .flatMap((entry) => entry.rows.map((item, index) => normalizeLegacyLogItem(item, index, entry.label, entry.id)));
    }

    function rowSearchText(row) {
      return [
        row.categoryLabel,
        row.category,
        row.sourceLabel,
        row.sourceId,
        row.eventLabel,
        row.event,
        row.message,
        row.severityLabel,
        row.source,
        row.programLabel,
        row.programId,
        row.device.name,
        row.device.ip,
        row.device.mac,
        row.client.name,
        row.client.ip,
        row.client.mac,
        row.admin.name,
        row.admin.id
      ].join(' ').toLowerCase();
    }

    function applyLocalFilters(rows) {
      const search = state.search.trim().toLowerCase();
      return rows.filter((row) => {
        // 先按 tab 归属裁剪：常规=设备/系统侧，审计=用户操作侧。
        // 后端忽略 type/sources，这一层是「两个 tab 不能一样」的真实保障。
        if (!modeAllowsRow(row)) return false;
        // 来源勾选只在后端真的给出可区分 source_id 时生效，
        // 否则（全部为 general）不参与裁剪，避免把列表清空。
        if (state.sources.size && row.sourceId && sourceFilteringMeaningful() && !state.sources.has(row.sourceId)) return false;
        if (state.severities.size && !state.severities.has(row.severity)) return false;
        if (state.categories.size && !state.categories.has(row.category)) return false;
        if (state.events.size && !state.events.has(row.event)) return false;
        if (state.deviceMacs.size && !state.deviceMacs.has(row.device.mac)) return false;
        if (state.clientDeviceMacs.size && !state.clientDeviceMacs.has(row.client.mac)) return false;
        if (state.adminIds.size && !state.adminIds.has(row.admin.id || row.admin.name)) return false;
        if (state.programs.size && !state.programs.has(row.programId)) return false;
        return !search || rowSearchText(row).includes(search);
      });
    }

    // 当整批数据的 source_id 只有一种取值时，来源勾选没有区分能力。
    function sourceFilteringMeaningful() {
      const seen = new Set();
      for (const row of state.allRows) {
        if (row.sourceId) seen.add(row.sourceId);
        if (seen.size > 1) return true;
      }
      return false;
    }

    function pruneSelectedRow() {
      const availableIds = new Set(state.allRows.map((item) => item.id));
      state.selectedRows = new Set(Array.from(state.selectedRows).filter((id) => availableIds.has(id)));
      if (!state.selectedId) return;
      const row = state.rows.find((item) => item.id === state.selectedId) || state.allRows.find((item) => item.id === state.selectedId);
      state.selectedRow = row || null;
      state.selectedId = row ? row.id : '';
    }

    function paginate(rows) {
      const start = state.pageNumber * state.pageSize;
      return rows.slice(start, start + state.pageSize);
    }

    function countMap(rows, getter) {
      const map = new Map();
      rows.forEach((row) => {
        const key = getter(row);
        if (!key) return;
        const current = map.get(key) || { id: key, label: key, count: 0 };
        current.count += 1;
        map.set(key, current);
      });
      return map;
    }

    function filterDataFromRows(rows, legacyPayload = {}) {
      const categories = countMap(rows, (row) => row.category);
      const events = countMap(rows, (row) => row.event);
      const devices = countMap(rows, (row) => row.device.mac);
      const clients = countMap(rows, (row) => row.client.mac);
      const admins = countMap(rows, (row) => row.admin.id || row.admin.name);
      const sources = countMap(rows, (row) => row.sourceId);
      const programs = countMap(rows, (row) => row.programId);
      const syslog = legacyPayload.syslog && typeof legacyPayload.syslog === 'object' ? legacyPayload.syslog : {};

      GENERAL_CATEGORIES.forEach(([id, label]) => {
        const item = categories.get(id) || { id, label, count: 0 };
        item.label = label;
        categories.set(id, item);
      });
      (state.mode === 'AUDIT' ? AUDIT_EVENTS : GENERAL_EVENTS).forEach(([id, label]) => {
        const item = events.get(id) || { id, label, count: 0 };
        item.label = label;
        events.set(id, item);
      });
      asArray(syslog.categories).forEach((id) => {
        const key = String(id || '').trim();
        if (!key) return;
        const item = categories.get(key) || { id: key, label: key, count: 0 };
        categories.set(key, item);
      });
      rows.forEach((row) => {
        if (row.sourceId && sources.has(row.sourceId)) sources.get(row.sourceId).label = firstText(row.sourceLabel, row.sourceId);
        if (row.programId && programs.has(row.programId)) programs.get(row.programId).label = firstText(row.programLabel, row.programId);
        if (row.device.mac && devices.has(row.device.mac)) devices.get(row.device.mac).label = firstText(row.device.name, row.device.ip, row.device.mac);
        if (row.client.mac && clients.has(row.client.mac)) clients.get(row.client.mac).label = firstText(row.client.name, row.client.ip, row.client.mac);
        const adminKey = row.admin.id || row.admin.name;
        if (adminKey && admins.has(adminKey)) admins.get(adminKey).label = firstText(row.admin.name, row.admin.id);
      });
      return {
        sources: Array.from(sources.values()),
        programs: Array.from(programs.values()),
        categories: Array.from(categories.values()),
        events: Array.from(events.values()),
        deviceFilters: Array.from(devices.values()).map((item) => ({ mac: item.id, name: item.label, count: item.count })),
        clientFilters: Array.from(clients.values()).map((item) => ({ mac: item.id, name: item.label, count: item.count })),
        adminFilters: Array.from(admins.values()).map((item) => ({ id: item.id, name: item.label, count: item.count }))
      };
    }

    function normalizeFilterList(payload, key, fallback = []) {
      const value = payload && payload[key];
      const list = Array.isArray(value) ? value : fallback;
      return list.map((item) => {
        if (Array.isArray(item)) return { id: item[0], label: item[1], count: 0 };
        if (typeof item === 'string') return { id: item, label: item, count: 0 };
        return {
          id: firstText(item.id, item.key, item.value, item.category, item.event, item.mac, item.name),
          label: firstText(item.label, item.name, item.title, item.event, item.category, item.mac, item.id),
          count: firstNumber(item.count, item.total, 0),
          ...item
        };
      }).filter((item) => item.id);
    }

    function normalizeFilterData(payload) {
      const fallbackEvents = state.mode === 'AUDIT' ? AUDIT_EVENTS : GENERAL_EVENTS;
      return {
        sources: normalizeFilterList(payload, 'sources', LOG_SOURCE_FILTERS).filter((item) => !/^unifi/i.test(item.id)),
        categories: normalizeFilterList(payload, 'categories', GENERAL_CATEGORIES).filter((item) => !/^UNIFI_/i.test(item.id)).map((item) => ({ ...item, label: categoryLabel(item.id) })),
        events: normalizeFilterList(payload, 'events', fallbackEvents).map((item) => ({ ...item, label: eventLabel(item.id) })),
        programs: normalizeFilterList(payload, 'programs', []),
        deviceFilters: asArray(payload && (payload.deviceFilters || payload.devices || payload.device_filters)),
        clientFilters: asArray(payload && (payload.clientFilters || payload.clients || payload.client_filters)),
        adminFilters: asArray(payload && (payload.adminFilters || payload.admins || payload.admin_filters))
      };
    }

    function hasLogSearchCapability(payload = {}) {
      const data = payload && typeof payload === 'object' ? payload : {};
      const settings = data.settings && typeof data.settings === 'object' ? data.settings : {};
      const capabilities = {
        ...(data.capabilities && typeof data.capabilities === 'object' ? data.capabilities : {}),
        ...(settings.capabilities && typeof settings.capabilities === 'object' ? settings.capabilities : {}),
        ...(data.logs_capabilities && typeof data.logs_capabilities === 'object' ? data.logs_capabilities : {})
      };
      return capabilities.search === true
        || capabilities.pagination === true
        || capabilities.filter_data === true
        || capabilities.unifi_style_logs === true
        || capabilities.log_center_v2 === true;
    }

    async function loadNewProtocol(seq) {
      const body = requestBody();
      const optional = (promise) => promise.catch(() => null);
      const settingsPromise = state.settings
        ? Promise.resolve(state.settings)
        : optional(requestJson('logs.settings', ENDPOINTS.settings, { method: 'GET' }));
      const [searchPayload, filterPayload, countPayload, settingsPayload] = await Promise.all([
        requestJson('logs.search', ENDPOINTS.search, { method: 'POST', body }),
        optional(requestJson('logs.filter-data', ENDPOINTS.filters, { method: 'POST', body })),
        optional(requestJson('logs.count', ENDPOINTS.count, { method: 'POST', body })),
        settingsPromise
      ]);
      if (seq !== state.refreshSeq) return false;
      const search = normalizeSearchPayload(searchPayload);
      state.allRows = search.rows;
      // 30.1 实测后端只认 severities/categories/events，忽略 type 与 sources，
      // 所以这里必须本地再裁一层，保证「风险」按钮和两个 tab 都有真实效果。
      const constrained = applyLocalFilters(search.rows);
      const locallyReduced = constrained.length !== search.rows.length;
      state.rows = locallyReduced ? paginate(constrained) : search.rows;
      state.total = locallyReduced
        ? constrained.length
        : firstNumber(countPayload && countPayload.total, countPayload && countPayload.total_count, search.total, search.rows.length);
      state.filterLocallyEnforced = locallyReduced;
      state.filterData = filterPayload ? normalizeFilterData(filterPayload) : filterDataFromRows(search.rows);
      if (settingsPayload) state.settings = settingsPayload;
      pruneSelectedRow();
      state.newProtocolAvailable = true;
      state.source = 'logs/search';
      state.error = '';
      state.notice = '';
      return true;
    }

    async function loadLegacy(seq, reason = '') {
      const result = await fetchApiResource('logs', `${ENDPOINTS.legacy}?logCenter=${encodeURIComponent(VERSION)}`);
      if (seq !== state.refreshSeq) return false;
      if (!result || !result.ok) {
        const message = result && result.error && result.error.message || reason || '日志接口不可用';
        throw new Error(message);
      }
      const payload = result.data || {};
      state.settings = {
        ...(payload.settings || {}),
        syslog: payload.syslog && typeof payload.syslog === 'object' ? payload.syslog : {},
        capabilities: {
          ...((payload.settings || {}).capabilities || {}),
          ...(payload.capabilities || {})
        }
      };
      state.exportResult = state.view === 'settings' ? state.exportResult : null;
      state.newProtocolAvailable = hasLogSearchCapability(payload);
      const normalizedRows = legacyRows(payload);
      const filtered = applyLocalFilters(normalizedRows);
      state.allRows = normalizedRows;
      state.total = filtered.length;
      state.rows = paginate(filtered);
      state.filterData = filterDataFromRows(normalizedRows, payload);
      pruneSelectedRow();
      state.source = 'logs';
      state.error = '';
      state.notice = '';
      return true;
    }

    async function postEndpoint(name, url, body) {
      return requestJson(name, url, { method: 'POST', body });
    }

    async function saveSettings(form) {
      const payload = {
        retention_days: firstNumber(form.retention_days, settingNumber('retention_days', 30)),
        kernel_retention_days: firstNumber(form.kernel_retention_days, settingNumber('kernel_retention_days', 7)),
        max_size_mb: firstNumber(form.max_size_mb, settingNumber('max_size_mb', 128)),
        auto_cleanup: Boolean(form.auto_cleanup),
        archive_compress: Boolean(form.archive_compress)
      };
      state.loading = true;
      state.error = '';
      render();
      try {
        await postEndpoint('logs.settings.save', ENDPOINTS.settings, payload);
        state.settings = { ...(state.settings || {}), ...payload };
        state.notice = '日志保留设置已保存。';
      } catch (error) {
        state.error = error && error.message || '保存日志设置失败';
      } finally {
        state.loading = false;
        render();
      }
    }

    async function exportLogs(form) {
      const payload = {
        type: form.export_type || '',
        range: form.export_range || '1w',
        level: form.export_level || '',
        format: form.export_format || 'json',
        query: form.export_query || '',
        limit: firstNumber(form.export_limit, 1000)
      };
      state.loading = true;
      state.error = '';
      render();
      try {
        state.exportResult = await postEndpoint('logs.export', ENDPOINTS.export, payload);
        state.notice = '日志导出任务已完成。';
      } catch (error) {
        state.error = error && error.message || '导出日志失败';
      } finally {
        state.loading = false;
        render();
      }
    }

    async function refresh(options = {}) {
      if (!root) return;
      if (state.loading) {
        state.pendingRefreshOptions = { ...(state.pendingRefreshOptions || {}), ...options };
        return;
      }
      if (options.resetPage) state.pageNumber = 0;
      const seq = ++state.refreshSeq;
      state.loading = true;
      state.error = '';
      renderRefreshState();
      const canTryNewProtocol = state.newProtocolAvailable && Date.now() >= state.newProtocolUnavailableUntil;
      if (!canTryNewProtocol) {
        try {
          await loadLegacy(seq);
        } catch (legacyError) {
          if (seq === state.refreshSeq) {
            state.rows = [];
            state.allRows = [];
            state.total = 0;
            state.filterData = filterDataFromRows([]);
            state.source = '';
            state.error = legacyError && legacyError.message || '日志接口不可用';
          }
        } finally {
          if (seq === state.refreshSeq) {
            finishRefresh();
          }
        }
        return;
      }
      try {
        await loadNewProtocol(seq);
      } catch (newProtocolError) {
        const status = Number(newProtocolError && newProtocolError.status);
        const message = newProtocolError && newProtocolError.message || '';
        if (status === 404 || status === 405 || status === 501 || /not found|unsupported|unavailable/i.test(message)) {
          state.newProtocolUnavailableUntil = Date.now() + 60000;
          state.newProtocolAvailable = false;
        }
        try {
          await loadLegacy(seq, canTryNewProtocol ? message : '');
        } catch (legacyError) {
          if (seq === state.refreshSeq) {
            state.rows = [];
            state.allRows = [];
            state.total = 0;
            state.filterData = filterDataFromRows([]);
            state.source = '';
            state.error = legacyError && legacyError.message || message || '日志接口不可用';
          }
        }
      } finally {
        if (seq === state.refreshSeq) {
          finishRefresh();
        }
      }
    }

  function finishRefresh() {
      state.loading = false;
      renderRefreshState();
      const pending = state.pendingRefreshOptions;
      state.pendingRefreshOptions = null;
      if (pending) {
        window.setTimeout(() => refresh(pending), 0);
        return;
      }
      scheduleNextRefresh();
    }

    function scheduleNextRefresh() {
      window.clearTimeout(state.refreshTimer);
      state.refreshTimer = window.setTimeout(() => refresh(), REFRESH_MS);
    }

    function clearFilters() {
      state.search = '';
      state.eventSearch = '';
      state.severities = new Set(SEVERITIES.map((item) => item.id));
      state.sources = new Set([defaultSourceForMode()]);
      state.categories.clear();
      state.events.clear();
      state.deviceMacs.clear();
      state.clientDeviceMacs.clear();
      state.adminIds.clear();
      state.programs.clear();
      state.selectedRows.clear();
      state.pageNumber = 0;
      refresh({ resetPage: true });
    }

    function activeFilterCount() {
      const severityChanged = state.severities.size !== SEVERITIES.length;
      const sourceChanged = state.sources.size !== 1 || !state.sources.has(defaultSourceForMode());
      return [
        sourceChanged,
        severityChanged,
        state.search,
        state.mode !== 'GENERAL',
        state.categories.size,
        state.events.size,
        state.deviceMacs.size,
        state.clientDeviceMacs.size,
        state.adminIds.size,
        state.programs.size
      ].filter(Boolean).length;
    }

    function severityBarsMarkup(key) {
      const meta = SEVERITIES.find((item) => item.id === key) || SEVERITIES[0];
      return `<span class="dwrt-risk-bars log-severity-bars ${html(meta.bars)}" aria-hidden="true"><i></i><i></i><i></i><i></i></span>`;
    }

    function modeTabsMarkup() {
      return `<div class="dwrt-kit-tabs log-center-mode-tabs" data-dwrt-tabs aria-label="日志模式">
        <span class="dwrt-kit-tab-pill" aria-hidden="true"></span>
        <button type="button" class="dwrt-kit-tab ${state.mode === 'GENERAL' ? 'is-active' : ''}" aria-selected="${state.mode === 'GENERAL'}" data-log-mode="GENERAL">常规</button>
        <button type="button" class="dwrt-kit-tab ${state.mode === 'AUDIT' ? 'is-active' : ''}" aria-selected="${state.mode === 'AUDIT'}" data-log-mode="AUDIT">审计</button>
      </div>`;
    }

    /*
     * 搜索按用户第 9 条移到表格工具条，左侧筛选栏不再自带搜索行；
     * 手动刷新按钮删除，页面本来就有 REFRESH_MS 的自动轮询（:1133）。
     */
    function searchMarkup() {
      return `<label class="dwrt-kit-expand-search log-center-search" data-dwrt-component="expand-search">
        <span class="dwrt-kit-expand-search-original-icon"><svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M9 3a6 6 0 1 0 3.65 10.76l2.8 2.8a.5.5 0 1 0 .7-.72l-2.78-2.78A6 6 0 0 0 9 3Zm-5 6a5 5 0 1 1 10 0A5 5 0 0 1 4 9Z"></path></svg></span>
        <input type="search" value="${html(state.search)}" data-log-search placeholder="搜索日志、对象、IP、MAC">
      </label>`;
    }

    function periodMarkup() {
      return `<section class="log-filter-group log-filter-range-section" data-log-filter-group="period">
        <div class="log-center-periods" role="tablist" aria-label="时间范围">
          ${Object.entries(PERIODS).filter(([id]) => id !== 'custom').map(([id, item]) => `<button type="button" class="${state.period === id ? 'is-active' : ''}" data-log-period="${html(id)}" aria-selected="${state.period === id}">${html(item.label)}</button>`).join('')}
          <button type="button" class="${state.period === 'custom' ? 'is-active' : ''}" data-log-calendar aria-label="选择自定义时间范围" title="日历" aria-selected="${state.period === 'custom'}">
            <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M6 2.5a.5.5 0 0 1 1 0V4h6V2.5a.5.5 0 0 1 1 0V4h1a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h1V2.5ZM4 8h12V6a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v2Zm0 1v6a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V9H4Z"></path></svg>
          </button>
        </div>
      </section>`;
    }

    function severityMarkup() {
      return `<section class="log-filter-group ${state.collapsed.has('severity') ? 'is-collapsed' : ''}" data-log-filter-group="severity">
        <button type="button" class="log-filter-trigger" data-log-collapse="severity" aria-expanded="${state.collapsed.has('severity') ? 'false' : 'true'}">
          <span>风险</span>
          <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M6.15 7.65a.5.5 0 0 1 .7 0L10 10.79l3.15-3.14a.5.5 0 0 1 .7.7l-3.5 3.5a.5.5 0 0 1-.7 0l-3.5-3.5a.5.5 0 0 1 0-.7Z"></path></svg>
        </button>
        <div class="log-filter-body">
          <div class="log-center-severity-strip" aria-label="严重等级">
            ${SEVERITIES.map((item) => `<button type="button" class="dwrt-risk-meter ${state.severities.has(item.id) ? 'is-active' : ''}" data-log-severity="${html(item.id)}" aria-pressed="${state.severities.has(item.id)}" aria-label="${html(item.label)}" title="${html(item.label)}">
              ${severityBarsMarkup(item.id)}
              <span>${html(item.label)}</span>
            </button>`).join('')}
          </div>
        </div>
      </section>`;
    }

    function itemCountText(item) {
      const count = Number(item && item.count);
      return Number.isFinite(count) ? formatInteger(count) : '0';
    }

    function checkboxRow(kind, item, selected) {
      const id = firstText(item.id, item.key, item.value, item.mac, item.name);
      const label = firstText(item.label, item.name, item.title, item.mac, id);
      const disabled = Number(item.count || 0) <= 0 && !selected.has(id);
      return `<label class="log-filter-row ${disabled ? 'is-disabled' : ''}">
        <input type="checkbox" data-log-filter-check="${html(kind)}" value="${html(id)}" ${selected.has(id) ? 'checked' : ''} ${disabled ? 'disabled' : ''}>
        <span class="log-filter-check" aria-hidden="true"></span>
        <span class="log-filter-label">${html(label)}</span>
        <em>${html(itemCountText(item))}</em>
      </label>`;
    }

    function sourceRow(item, countMap) {
      const countItem = countMap.get(item.id);
      const count = countItem ? countItem.count : 0;
      const checked = state.sources.has(item.id);
      return `<label class="log-filter-row">
        <input type="checkbox" data-log-filter-check="sources" value="${html(item.id)}" ${checked ? 'checked' : ''}>
        <span class="log-filter-check" aria-hidden="true"></span>
        <span class="log-filter-label">${html(item.label)}</span>
        <em>${html(formatInteger(count))}</em>
      </label>`;
    }

    function identityRow(kind, item, selected, idKey = 'id') {
      const id = firstText(item[idKey], item.id, item.mac, item.name);
      const label = firstText(item.name, item.label, item.hostname, item.mac, id);
      const disabled = Number(item.count || 0) <= 0 && !selected.has(id);
      return `<label class="log-filter-row log-filter-row--identity ${disabled ? 'is-disabled' : ''}">
        <input type="checkbox" data-log-filter-check="${html(kind)}" value="${html(id)}" ${selected.has(id) ? 'checked' : ''} ${disabled ? 'disabled' : ''}>
        <span class="log-filter-avatar" aria-hidden="true">${html(label.slice(0, 1).toUpperCase() || 'L')}</span>
        <span class="log-filter-label">${html(label)}</span>
        <em>${html(itemCountText(item))}</em>
      </label>`;
    }

    function filterGroup(id, title, body, options = {}) {
      const collapsed = state.collapsed.has(id);
      return `<section class="log-filter-group ${collapsed ? 'is-collapsed' : ''}" data-log-filter-group="${html(id)}">
        <button type="button" class="log-filter-trigger" data-log-collapse="${html(id)}" aria-expanded="${collapsed ? 'false' : 'true'}">
          <span>${html(title)}</span>
          ${options.count !== undefined ? `<em>${html(formatInteger(options.count))}</em>` : ''}
          <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M6.15 7.65a.5.5 0 0 1 .7 0L10 10.79l3.15-3.14a.5.5 0 0 1 .7.7l-3.5 3.5a.5.5 0 0 1-.7 0l-3.5-3.5a.5.5 0 0 1 0-.7Z"></path></svg>
        </button>
        <div class="log-filter-body">${body}</div>
      </section>`;
    }

    function filtersMarkup() {
      const filterData = state.filterData || filterDataFromRows(state.allRows);
      const sourceCounts = countMap(state.allRows, (row) => row.sourceId || '');
      const categories = normalizeFilterList(filterData, 'categories', GENERAL_CATEGORIES);
      const eventsBase = normalizeFilterList(filterData, 'events', state.mode === 'AUDIT' ? AUDIT_EVENTS : GENERAL_EVENTS);
      const eventQuery = state.eventSearch.trim().toLowerCase();
      const events = eventQuery
        ? eventsBase.filter((item) => [item.label, item.id].join(' ').toLowerCase().includes(eventQuery))
        : eventsBase;
      const devices = asArray(filterData.deviceFilters || filterData.devices);
      const clients = asArray(filterData.clientFilters || filterData.clients);
      const admins = asArray(filterData.adminFilters || filterData.admins);
      const programMap = new Map();
      normalizeFilterList(filterData, 'programs', []).forEach((item) => programMap.set(item.id, item));
      (filterDataFromRows(state.allRows).programs || []).forEach((item) => {
        const current = programMap.get(item.id);
        programMap.set(item.id, current && Number(current.count) > 0 ? current : item);
      });
      const programs = Array.from(programMap.values()).sort((left, right) => Number(right.count || 0) - Number(left.count || 0));
      if (state.mode === 'AUDIT') {
        return `<div class="log-filter-scroll">
          ${severityMarkup()}
          ${periodMarkup()}
          ${filterGroup('sources', '日志来源', modeSourceFilters().map((item) => sourceRow(item, sourceCounts)).join(''), { count: modeSourceFilters().length })}
          ${filterGroup('admins', '管理员', admins.map((item) => identityRow('adminIds', item, state.adminIds, 'id')).join('') || '<p class="log-filter-empty">暂无管理员筛选项</p>', { count: admins.length })}
          ${filterGroup('events', '事件', `
            <label class="log-filter-local-search">
              <input type="search" value="${html(state.eventSearch)}" data-log-event-search placeholder="搜索事件">
            </label>
            ${events.map((item) => checkboxRow('events', item, state.events)).join('')}
          `, { count: eventsBase.length })}
        </div>`;
      }
      return `<div class="log-filter-scroll">
        ${severityMarkup()}
        ${periodMarkup()}
        ${filterGroup('sources', '日志来源', modeSourceFilters().map((item) => sourceRow(item, sourceCounts)).join(''), { count: modeSourceFilters().length })}
        ${programs.length ? filterGroup('programs', '程序 / 插件', programs.map((item) => checkboxRow('programs', item, state.programs)).join(''), { count: programs.length }) : ''}
        ${filterGroup('categories', '日志分类', categories.map((item) => checkboxRow('categories', item, state.categories)).join(''), { count: categories.length })}
        ${filterGroup('events', '事件', `
          <label class="log-filter-local-search">
            <input type="search" value="${html(state.eventSearch)}" data-log-event-search placeholder="搜索事件">
          </label>
          ${events.map((item) => checkboxRow('events', item, state.events)).join('')}
        `, { count: eventsBase.length })}
        ${filterGroup('clients', '客户端', clients.map((item) => identityRow('clientDeviceMacs', item, state.clientDeviceMacs, 'mac')).join('') || '<p class="log-filter-empty">暂无客户端筛选项</p>', { count: clients.length })}
      </div>`;
    }

    function filterFooterMarkup() {
      const count = activeFilterCount();
      return `<footer class="log-filter-footer">
        <button type="button" data-log-clear ${count ? '' : 'disabled'}>清除筛选条件</button>
        <button type="button" data-log-action="notifications">推送通知设置</button>
        <button type="button" data-log-action="siem">导出到 SIEM 服务器</button>
        <button type="button" data-log-action="settings">保留 / 导出</button>
      </footer>`;
    }

    function inputMarkup(name, label, value, attrs = '') {
      return `<label class="log-settings-field">
        <span>${html(label)}</span>
        <input name="${html(name)}" value="${html(value)}" ${attrs}>
      </label>`;
    }

    function selectMarkup(name, label, value, options) {
      return `<label class="log-settings-field">
        <span>${html(label)}</span>
        <select name="${html(name)}">
          ${options.map(([id, title]) => `<option value="${html(id)}" ${String(value) === String(id) ? 'selected' : ''}>${html(title)}</option>`).join('')}
        </select>
      </label>`;
    }

    function switchMarkup(name, label, checked) {
      return `<label class="log-settings-switch">
        <input type="checkbox" name="${html(name)}" ${checked ? 'checked' : ''}>
        <span aria-hidden="true"></span>
        <strong>${html(label)}</strong>
      </label>`;
    }

    function settingsMarkup() {
      const settings = state.settings || {};
      const syslog = syslogSettings();
      const exportResult = state.exportResult || {};
      return `<section class="log-settings-page" aria-label="日志保留与导出">
        <section class="log-settings-card dwrt-glass-card insights-stable-glass">
          <header>
            <div>
              <strong>保留策略</strong>
            <span>控制常规日志、内核日志和归档文件的保留策略。</span>
            </div>
            <button type="submit" form="logRetentionForm" ${state.loading ? 'disabled' : ''}>保存</button>
          </header>
          <form id="logRetentionForm" class="log-settings-grid" data-log-settings-form>
            ${inputMarkup('retention_days', '常规日志保留', settingNumber('retention_days', 30), 'type="number" min="1" max="365" inputmode="numeric"')}
            ${inputMarkup('kernel_retention_days', '内核日志保留', settingNumber('kernel_retention_days', 7), 'type="number" min="1" max="90" inputmode="numeric"')}
            ${inputMarkup('max_size_mb', '最大占用', settingNumber('max_size_mb', 128), 'type="number" min="32" max="1024" inputmode="numeric"')}
            <div class="log-settings-switches">
              ${switchMarkup('auto_cleanup', '自动清理过期日志', settings.auto_cleanup !== false)}
              ${switchMarkup('archive_compress', '导出归档压缩', settings.archive_compress !== false)}
            </div>
          </form>
        </section>
        <section class="log-settings-card dwrt-glass-card insights-stable-glass">
          <header>
            <div>
              <strong>导出</strong>
            <span>按来源、时间范围、等级和关键词生成排障文件。</span>
            </div>
            <button type="submit" form="logExportForm" ${state.loading ? 'disabled' : ''}>导出</button>
          </header>
          <form id="logExportForm" class="log-settings-grid" data-log-export-form>
            ${selectMarkup('export_type', '类型', '', [['', '全部'], ['system', '系统'], ['kernel', '内核'], ['user', '用户'], ['function', '功能'], ['message', '通知'], ['warning', '告警'], ['syslog', 'Syslog']])}
            ${selectMarkup('export_range', '范围', '1w', [['1d', '1 天'], ['3d', '3 天'], ['1w', '1 周'], ['2w', '2 周'], ['1m', '1 月']])}
            ${selectMarkup('export_level', '等级', '', [['', '全部'], ['info', '信息'], ['notice', '注意'], ['warning', '警告'], ['error', '错误']])}
            ${selectMarkup('export_format', '格式', 'json', [['json', 'JSON'], ['csv', 'CSV']])}
            ${inputMarkup('export_query', '关键词', '', 'type="search" placeholder="可选"')}
            ${inputMarkup('export_limit', '最大条数', '1000', 'type="number" min="1" max="1000" inputmode="numeric"')}
          </form>
          ${exportResult.path ? `<div class="log-export-result">
            <strong>${html(exportResult.path)}</strong>
            <span>${html(exportResult.format || '')} · ${html(formatInteger(exportResult.count || 0))} 条</span>
          </div>` : ''}
        </section>
        <section class="log-settings-card dwrt-glass-card insights-stable-glass">
          <header>
            <div>
              <strong>SIEM / Syslog 转发</strong>
              <span>用于把日志转发到 SIEM 或外部 Syslog 服务器。</span>
            </div>
          </header>
          <div class="log-settings-summary">
            <div><span>状态</span><strong>${syslog.enabled ? '已启用' : '未启用'}</strong></div>
            <div><span>服务器</span><strong>${html(syslog.server || '--')}</strong></div>
            <div><span>端口</span><strong>${html(syslog.port || 514)}</strong></div>
            <div><span>协议</span><strong>${html(syslog.protocol || 'udp')}</strong></div>
            <div><span>Facility</span><strong>${html(syslog.facility || 'local7')}</strong></div>
            <div><span>最低等级</span><strong>${html(syslog.min_level || 'notice')}</strong></div>
          </div>
        </section>
        ${state.error ? `<p class="log-settings-error">${html(state.error)}</p>` : ''}
        ${state.notice ? `<p class="log-settings-notice">${html(state.notice)}</p>` : ''}
      </section>`;
    }

    function rowMarkup(row) {
      const selected = state.selectedId && row.id === state.selectedId;
      const checked = state.selectedRows.has(row.id);
      const message = row.message || '--';
      const expanded = state.expandedMessages.has(row.id);
      const truncatable = message.length > MESSAGE_CLAMP_CHARS;
      return `<tr class="${selected ? 'is-selected' : ''} ${checked ? 'is-ai-selected' : ''}" data-log-row="${html(row.id)}">
        <td class="log-table-select-cell"><label class="log-table-select" title="选择此日志"><input type="checkbox" data-log-row-select="${html(row.id)}" ${checked ? 'checked' : ''}><span aria-hidden="true"></span></label></td>
        <td><span class="log-table-category">${html(row.sourceLabel || row.categoryLabel)}</span></td>
        <td><strong>${html(row.eventLabel)}</strong></td>
        <td class="log-table-desc-cell">
          <span class="log-table-desc ${expanded ? 'is-expanded' : ''}" title="${html(message)}">${html(expanded || !truncatable ? message : `${message.slice(0, MESSAGE_CLAMP_CHARS).trimEnd()}…`)}</span>
          ${truncatable ? `<button type="button" class="log-table-desc-toggle" data-log-desc-toggle="${html(row.id)}" aria-expanded="${expanded}" title="${expanded ? '收起完整描述' : '展开完整描述'}">${expanded ? '收起' : '…'}</button>` : ''}
        </td>
        <td><span class="log-table-severity">${severityBarsMarkup(row.severity)}<em>${html(row.severityLabel)}</em></span></td>
        <td class="num">${html(formatTime(row.timestamp))}</td>
      </tr>`;
    }

    function tableMarkup() {
      const totalPages = Math.max(1, Math.ceil(state.total / state.pageSize));
      const start = state.total ? state.pageNumber * state.pageSize + 1 : 0;
      const end = Math.min(state.total, (state.pageNumber + 1) * state.pageSize);
      const visibleIds = state.rows.map((row) => row.id);
      const allVisibleSelected = visibleIds.length > 0 && visibleIds.every((id) => state.selectedRows.has(id));
      const body = state.loading
        ? `<tr><td colspan="6"><div class="log-table-empty">正在读取日志</div></td></tr>`
        : state.rows.length
          ? state.rows.map(rowMarkup).join('')
          : `<tr><td colspan="6"><div class="log-table-empty">${html(state.error || '当前筛选条件下没有日志。')}</div></td></tr>`;
      return `<section class="log-center-table-card dwrt-kit-table-wrap insights-stable-glass ${state.aiResult ? 'has-ai-result' : ''}">
        <div class="dwrt-kit-table-toolbar log-center-toolbar">
          <div class="dwrt-kit-table-title">
            <strong>日志中心</strong>
            <span>${html(state.loading ? '正在读取' : '日志列表')}</span>
          </div>
          <div class="log-center-toolbar-actions">
            ${state.notice ? `<span class="log-center-notice">${html(state.notice)}</span>` : ''}
            ${searchMarkup()}
            <button type="button" class="log-ai-button" data-log-ask-ai ${state.selectedRows.size && !state.aiLoading ? '' : 'disabled'} aria-label="让 AI 分析选中的日志">
              <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M10 2.5c.27 0 .49.2.55.46a4.3 4.3 0 0 0 3.2 3.2c.26.06.45.29.45.55s-.19.49-.45.55a4.3 4.3 0 0 0-3.2 3.2.56.56 0 0 1-1.1 0 4.3 4.3 0 0 0-3.2-3.2.56.56 0 0 1 0-1.1 4.3 4.3 0 0 0 3.2-3.2c.06-.26.28-.46.55-.46Zm5.2 8.8c.22 0 .4.16.45.37a2.64 2.64 0 0 0 1.98 1.98.46.46 0 0 1 0 .9 2.64 2.64 0 0 0-1.98 1.98.46.46 0 0 1-.9 0 2.64 2.64 0 0 0-1.98-1.98.46.46 0 0 1 0-.9 2.64 2.64 0 0 0 1.98-1.98.46.46 0 0 1 .45-.37Z"></path></svg>
              ${html(state.aiLoading ? '分析中' : `问 AI${state.selectedRows.size ? ` (${state.selectedRows.size})` : ''}`)}
            </button>
            <span class="dwrt-kit-table-count">${html(formatInteger(state.total))} 条</span>
          </div>
        </div>
        ${state.aiResult ? `<section class="log-ai-result" aria-live="polite"><strong>AI 分析</strong><p>${html(state.aiResult)}</p><button type="button" data-log-ai-dismiss aria-label="关闭 AI 分析">关闭</button></section>` : ''}
        <div class="dwrt-kit-table-scroll log-center-table-scroll">
          <table class="dwrt-kit-table log-center-table" aria-label="日志列表">
            <thead><tr><th class="log-table-select-head"><label class="log-table-select" title="选择本页日志"><input type="checkbox" data-log-select-page ${allVisibleSelected ? 'checked' : ''}><span aria-hidden="true"></span></label></th><th>日志来源</th><th>事件</th><th>描述</th><th>级别</th><th class="num">日期 / 时间</th></tr></thead>
            <tbody>${body}</tbody>
          </table>
        </div>
        <footer class="log-center-pagination">
          <span>${html(`${start}-${end} 共 ${formatInteger(state.total)} 日志`)}</span>
          <label>每页
            <select data-log-page-size>
              ${[25, 50, 100].map((size) => `<option value="${size}" ${state.pageSize === size ? 'selected' : ''}>${size}</option>`).join('')}
            </select>
          </label>
          <div class="log-center-page-buttons">
            <button type="button" data-log-page="prev" ${state.pageNumber <= 0 ? 'disabled' : ''}>上一页</button>
            <button type="button" data-log-page="next" ${state.pageNumber >= totalPages - 1 ? 'disabled' : ''}>下一页</button>
          </div>
        </footer>
      </section>`;
    }

    function renderRefreshState() {
      // 刷新只影响表格与筛选计数，不重建整页，否则每次操作都会整页抖动。
      if (!root || !root.querySelector('[data-log-center-shell]')) {
        render();
        return;
      }
      renderTableRegion();
      renderFilterRegion();
      syncDrawer();
    }

    function detailRow(label, value) {
      const text = firstText(value);
      if (!text) return '';
      return `<div><dt>${html(label)}</dt><dd>${html(text)}</dd></div>`;
    }

    function rawLogText(row) {
      if (!row) return '';
      if (row.cef) return row.cef;
      try { return JSON.stringify(row.raw || row, null, 2); } catch (_) { return String(row.message || ''); }
    }

    function drawerMarkup() {
      const row = state.selectedRow;
      if (!row) return '';
      const raw = rawLogText(row);
      // 与 AI 抽屉同一套 kit 组件（copilot 变体），不再手搓玻璃层。
      return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-log-close-drawer aria-label="关闭日志详情"></button><aside class="log-center-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" aria-label="日志详情">
        <header class="dwrt-kit-sheet-header log-drawer-head">
          <div>
            <span>${html(formatTime(row.timestamp))}</span>
            <strong>${html(row.eventLabel)}</strong>
          </div>
          <button type="button" class="dwrt-kit-sheet-close" data-log-close-drawer aria-label="关闭日志详情">×</button>
        </header>
        <div class="dwrt-kit-sheet-body log-drawer-scroll">
          <section class="log-detail-section">
            <h3>事件</h3>
            <dl>
              ${detailRow('事件', row.eventLabel)}
              ${detailRow('级别', row.severityLabel)}
              ${detailRow('日志来源', row.sourceLabel)}
              ${detailRow('原始分类', row.categoryLabel)}
              ${detailRow('状态', row.status)}
              ${detailRow('目标', row.target)}
              ${detailRow('原始来源', row.source)}
            </dl>
          </section>
          <section class="log-detail-section">
            <h3>对象</h3>
            <dl>
              ${detailRow('设备', row.device.name)}
              ${detailRow('型号', row.device.model)}
              ${detailRow('IP 地址', row.device.ip || row.client.ip)}
              ${detailRow('MAC 地址', row.device.mac || row.client.mac)}
              ${detailRow('版本', row.device.version)}
              ${detailRow('管理员', row.admin.name || row.admin.id)}
            </dl>
          </section>
          <section class="log-detail-section">
            <h3>描述</h3>
            <p>${html(row.message || '当前日志没有结构化描述。')}</p>
          </section>
          <section class="log-detail-section log-detail-raw">
            <div class="log-detail-title-row">
              <h3>CEF / 原始日志</h3>
              <button type="button" data-log-copy="${html(row.id)}">复制</button>
            </div>
            <pre>${html(raw)}</pre>
          </section>
        </div>
      </aside>`;
    }

    function captureInteractionState() {
      if (!root) return null;
      const active = document.activeElement && root.contains(document.activeElement) ? document.activeElement : null;
      const focusKey = active?.matches('[data-log-search]') ? 'search'
        : active?.matches('[data-log-event-search]') ? 'event-search'
          : active?.dataset.logCollapse ? `collapse:${active.dataset.logCollapse}` : '';
      return {
        focusKey,
        selectionStart: typeof active?.selectionStart === 'number' ? active.selectionStart : null,
        selectionEnd: typeof active?.selectionEnd === 'number' ? active.selectionEnd : null,
        filterTop: root.querySelector('.log-filter-scroll')?.scrollTop || 0,
        filterLeft: root.querySelector('.log-filter-scroll')?.scrollLeft || 0,
        tableTop: root.querySelector('.log-center-table-scroll')?.scrollTop || 0,
        tableLeft: root.querySelector('.log-center-table-scroll')?.scrollLeft || 0,
        drawerTop: root.querySelector('.log-drawer-scroll')?.scrollTop || 0,
        settingsTop: root.querySelector('.log-settings-page')?.scrollTop || 0
      };
    }

    function restoreInteractionState(snapshot) {
      if (!snapshot) return;
      const restoreScroll = (selector, top, left = 0) => {
        const element = root.querySelector(selector);
        if (!element) return;
        element.scrollTop = top;
        element.scrollLeft = left;
      };
      restoreScroll('.log-filter-scroll', snapshot.filterTop, snapshot.filterLeft);
      restoreScroll('.log-center-table-scroll', snapshot.tableTop, snapshot.tableLeft);
      restoreScroll('.log-drawer-scroll', snapshot.drawerTop);
      restoreScroll('.log-settings-page', snapshot.settingsTop);
      let focusTarget = null;
      if (snapshot.focusKey === 'search') focusTarget = root.querySelector('[data-log-search]');
      else if (snapshot.focusKey === 'event-search') focusTarget = root.querySelector('[data-log-event-search]');
      else if (snapshot.focusKey.startsWith('collapse:')) focusTarget = root.querySelector(`[data-log-collapse="${cssEscape(snapshot.focusKey.slice(9))}"]`);
      if (!focusTarget) return;
      focusTarget.focus({ preventScroll: true });
      if (snapshot.selectionStart !== null && typeof focusTarget.setSelectionRange === 'function') {
        focusTarget.setSelectionRange(snapshot.selectionStart, snapshot.selectionEnd ?? snapshot.selectionStart);
      }
      restoreScroll('.log-filter-scroll', snapshot.filterTop, snapshot.filterLeft);
    }

    function render() {
      if (!root) return;
      const interaction = captureInteractionState();
      root.classList.add('route-workspace', 'route-log-center-host');
      root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home');
      root.hidden = false;
      root.innerHTML = `<section class="log-center-shell ${state.selectedRow ? 'is-drawer-open' : ''}" data-log-center-shell>
        <aside class="log-center-filter dwrt-glass-card insights-stable-glass" aria-label="日志筛选">
          <div class="log-filter-head">
            ${modeTabsMarkup()}
          </div>
          ${filtersMarkup()}
          ${filterFooterMarkup()}
        </aside>
        <main class="log-center-main">
          ${state.view === 'settings' ? settingsMarkup() : tableMarkup()}
        </main>
        <div class="log-center-drawer-host" data-log-drawer-host>${state.view === 'settings' ? '' : drawerMarkup()}</div>
      </section>`;
      mountUiKit(root);
      scheduleGlassCardsRender(160);
      restoreInteractionState(interaction);
    }

    // 抽屉独立挂载：开关抽屉不再改变表格所在的 grid 结构。
    function syncDrawer() {
      const host = root && root.querySelector('[data-log-drawer-host]');
      if (!host) {
        render();
        return;
      }
      const shell = root.querySelector('[data-log-center-shell]');
      const shouldOpen = Boolean(state.selectedRow) && state.view !== 'settings';
      if (shell) shell.classList.toggle('is-drawer-open', shouldOpen);
      const openId = host.getAttribute('data-log-drawer-id') || '';
      const nextId = shouldOpen ? String(state.selectedRow.id) : '';
      if (openId === nextId) return;
      host.setAttribute('data-log-drawer-id', nextId);
      host.innerHTML = shouldOpen ? drawerMarkup() : '';
      if (shouldOpen) {
        mountUiKit(host);
        scheduleGlassCardsRender(120);
      }
    }

    function selectedSetFor(kind) {
      return setForKind(kind);
    }

    function setForKind(kind) {
      return {
        categories: state.categories,
        sources: state.sources,
        programs: state.programs,
        events: state.events,
        deviceMacs: state.deviceMacs,
        clientDeviceMacs: state.clientDeviceMacs,
        adminIds: state.adminIds
      }[kind] || null;
    }

    // 只重绘单行，避免为了一个「…」把整页 innerHTML 重建。
    function patchRow(id) {
      const row = state.rows.find((item) => item.id === id);
      const node = root && root.querySelector(`[data-log-row="${cssEscape(id)}"]`);
      if (!row || !node) {
        renderTableRegion();
        return;
      }
      node.outerHTML = rowMarkup(row);
    }

    // 局部重绘：表格区域。筛选栏与抽屉保持原节点，不参与重排。
    function renderTableRegion() {
      const main = root && root.querySelector('.log-center-main');
      if (!main) {
        render();
        return;
      }
      const scroll = main.querySelector('.log-center-table-scroll');
      const scrollTop = scroll ? scroll.scrollTop : 0;
      const scrollLeft = scroll ? scroll.scrollLeft : 0;
      main.innerHTML = state.view === 'settings' ? settingsMarkup() : tableMarkup();
      const nextScroll = main.querySelector('.log-center-table-scroll');
      if (nextScroll) {
        nextScroll.scrollTop = scrollTop;
        nextScroll.scrollLeft = scrollLeft;
      }
      mountUiKit(main);
    }

    // 局部重绘：筛选栏。表格与抽屉保持原节点。
    function renderFilterRegion() {
      const aside = root && root.querySelector('.log-center-filter');
      if (!aside) {
        render();
        return;
      }
      const interaction = captureInteractionState();
      const scroll = aside.querySelector('.log-filter-scroll');
      const scrollTop = scroll ? scroll.scrollTop : 0;
      aside.innerHTML = `<div class="log-filter-head">${modeTabsMarkup()}</div>${filtersMarkup()}${filterFooterMarkup()}`;
      const nextScroll = aside.querySelector('.log-filter-scroll');
      if (nextScroll) nextScroll.scrollTop = scrollTop;
      mountUiKit(aside);
      restoreInteractionState(interaction);
    }

    // 最轻量更新：只刷工具栏（选中计数、提示、AI 按钮可用性）。
    function syncToolbar() {
      const toolbar = root && root.querySelector('.log-center-toolbar');
      if (!toolbar) {
        renderTableRegion();
        return;
      }
      const askButton = toolbar.querySelector('[data-log-ask-ai]');
      if (askButton) {
        askButton.disabled = !(state.selectedRows.size && !state.aiLoading);
        const label = askButton.querySelector('span, em');
        const text = state.aiLoading ? '分析中' : `问 AI${state.selectedRows.size ? ` (${state.selectedRows.size})` : ''}`;
        if (label) label.textContent = text;
        else askButton.setAttribute('aria-label', text);
      }
      const selectPage = root.querySelector('[data-log-select-page]');
      if (selectPage) {
        const visibleIds = state.rows.map((row) => row.id);
        selectPage.checked = visibleIds.length > 0 && visibleIds.every((id) => state.selectedRows.has(id));
      }
    }

    function toggleSetValue(set, value, checked) {
      if (!set || !value) return;
      if (checked) set.add(value);
      else set.delete(value);
      state.pageNumber = 0;
      refresh({ resetPage: true });
    }

    function selectRow(id) {
      const row = state.rows.find((item) => item.id === id) || state.allRows.find((item) => item.id === id);
      const previousId = state.selectedId;
      state.selectedId = row ? row.id : '';
      state.selectedRow = row || null;
      // 只切换选中高亮 + 抽屉，不整页重绘。
      if (previousId) patchRow(previousId);
      if (state.selectedId) patchRow(state.selectedId);
      syncDrawer();
    }

    async function openCalendar(event) {
      const picker = window.DWRT_UI_KIT && window.DWRT_UI_KIT.openDateRangePicker;
      if (typeof picker !== 'function') return;
      const result = await picker({
        anchor: event && event.currentTarget,
        range: state.period === 'custom' && state.customRange
          ? { start: state.customRange.timestampFrom || state.customRange.start, end: state.customRange.timestampTo || state.customRange.end }
          : { start: nowRange().timestampFrom, end: nowRange().timestampTo }
      });
      if (!result) return;
      state.customRange = { start: result.start, end: result.end };
      state.period = 'custom';
      state.pageNumber = 0;
      refresh({ resetPage: true });
    }

    function copySelectedRaw(id) {
      const row = state.selectedRow && state.selectedRow.id === id ? state.selectedRow : null;
      if (!row) return;
      const text = rawLogText(row);
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(() => {});
      }
    }

    function aiResponseText(payload = {}) {
      return firstText(
        payload.summary,
        payload.answer,
        payload.analysis,
        payload.message,
        payload.result && (payload.result.summary || payload.result.answer || payload.result.analysis)
      );
    }

    async function askAiAboutSelection() {
      if (!state.selectedRows.size || state.aiLoading) return;
      const rows = state.allRows.filter((row) => state.selectedRows.has(row.id));
      if (!rows.length) return;
      const capabilities = state.settings && state.settings.capabilities || {};
      if (capabilities.ai_analysis !== true && capabilities.log_ai_analysis !== true) {
        state.notice = '后端尚未提供日志 AI 分析能力。';
        syncToolbar();
        return;
      }
      state.aiLoading = true;
      state.aiResult = null;
      state.notice = '';
      renderTableRegion();
      try {
        const payload = await postEndpoint('logs.ai.analyze', ENDPOINTS.aiAnalyze, {
          log_ids: rows.map((row) => row.id),
          logs: rows.map((row) => ({
            id: row.id,
            timestamp: row.timestamp,
            severity: row.severity,
            source_id: row.sourceId,
            source_label: row.sourceLabel,
            program: row.programId,
            category: row.category,
            event: row.event,
            message: row.message,
            raw: rawLogText(row)
          })),
          locale: 'zh-CN',
          task: 'diagnose_logs'
        });
        state.aiResult = aiResponseText(payload) || 'AI 已完成分析，但没有返回可显示的摘要。';
      } catch (error) {
        const unavailable = [404, 405, 501].includes(Number(error && error.status));
        state.notice = unavailable ? '后端尚未提供日志 AI 分析接口。' : (error && error.message || '日志 AI 分析失败');
      } finally {
        state.aiLoading = false;
        renderTableRegion();
      }
    }

    function onClick(event) {
      if (event.target.closest('[data-log-row-select], [data-log-select-page]')) return;
      const descToggle = event.target.closest('[data-log-desc-toggle]');
      if (descToggle) {
        // 展开/收起描述属于行内显示，不应打开详情抽屉，也不应重排整页。
        event.preventDefault();
        event.stopPropagation();
        const id = descToggle.dataset.logDescToggle;
        if (state.expandedMessages.has(id)) state.expandedMessages.delete(id);
        else state.expandedMessages.add(id);
        patchRow(id);
        return;
      }
      if (event.target.closest('[data-log-ask-ai]')) {
        askAiAboutSelection();
        return;
      }
      if (event.target.closest('[data-log-ai-dismiss]')) {
        state.aiResult = null;
        renderTableRegion();
        return;
      }
      const modeButton = event.target.closest('[data-log-mode]');
      if (modeButton) {
        const nextMode = modeButton.dataset.logMode === 'AUDIT' ? 'AUDIT' : 'GENERAL';
        if (nextMode === state.mode) return;
        state.mode = nextMode;
        state.sources = new Set([defaultSourceForMode(nextMode)]);
        state.view = 'logs';
        state.pageNumber = 0;
        state.selectedId = '';
        state.selectedRow = null;
        state.events.clear();
        state.categories.clear();
        state.deviceMacs.clear();
        state.clientDeviceMacs.clear();
        state.adminIds.clear();
        state.programs.clear();
        state.selectedRows.clear();
        refresh({ resetPage: true });
        return;
      }
      const periodButton = event.target.closest('[data-log-period]');
      if (periodButton) {
        state.period = periodButton.dataset.logPeriod || 'day';
        state.customRange = null;
        state.pageNumber = 0;
        refresh({ resetPage: true });
        return;
      }
      const calendarButton = event.target.closest('[data-log-calendar]');
      if (calendarButton) {
        openCalendar({ currentTarget: calendarButton });
        return;
      }
      const severityButton = event.target.closest('[data-log-severity]');
      if (severityButton) {
        const id = severityButton.dataset.logSeverity;
        if (state.severities.has(id)) state.severities.delete(id);
        else state.severities.add(id);
        state.pageNumber = 0;
        refresh({ resetPage: true });
        return;
      }
      const collapseButton = event.target.closest('[data-log-collapse]');
      if (collapseButton) {
        const id = collapseButton.dataset.logCollapse;
        if (state.collapsed.has(id)) state.collapsed.delete(id);
        else state.collapsed.add(id);
        const group = collapseButton.closest('[data-log-filter-group]');
        const collapsed = state.collapsed.has(id);
        group?.classList.toggle('is-collapsed', collapsed);
        collapseButton.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
        return;
      }
      const pageButton = event.target.closest('[data-log-page]');
      if (pageButton) {
        const direction = pageButton.dataset.logPage;
        const totalPages = Math.max(1, Math.ceil(state.total / state.pageSize));
        if (direction === 'prev') state.pageNumber = Math.max(0, state.pageNumber - 1);
        if (direction === 'next') state.pageNumber = Math.min(totalPages - 1, state.pageNumber + 1);
        refresh();
        return;
      }
      const row = event.target.closest('[data-log-row]');
      if (row) {
        selectRow(row.dataset.logRow);
        return;
      }
      if (event.target.closest('[data-log-close-drawer]')) {
        const previousId = state.selectedId;
        state.selectedId = '';
        state.selectedRow = null;
        if (previousId) patchRow(previousId);
        syncDrawer();
        return;
      }
      const copyButton = event.target.closest('[data-log-copy]');
      if (copyButton) {
        copySelectedRaw(copyButton.dataset.logCopy);
        return;
      }
      if (event.target.closest('[data-log-clear]')) {
        clearFilters();
        return;
      }
      const actionButton = event.target.closest('[data-log-action]');
      if (actionButton) {
        const action = actionButton.dataset.logAction;
        if (action === 'settings' || action === 'siem') {
          state.view = 'settings';
          state.selectedId = '';
          state.selectedRow = null;
          renderTableRegion();
          syncDrawer();
          return;
        }
        if (action === 'notifications') {
          window.location.hash = '#/system/notifications';
          return;
        }
      }
    }

    function onInput(event) {
      if (event.target.matches('[data-log-search]')) {
        state.search = event.target.value || '';
        window.clearTimeout(state.searchTimer);
        state.searchTimer = window.setTimeout(() => refresh({ resetPage: true }), SEARCH_DEBOUNCE_MS);
      }
      if (event.target.matches('[data-log-event-search]')) {
        state.eventSearch = event.target.value || '';
        renderFilterRegion();
      }
    }

    function onChange(event) {
      const rowSelect = event.target.closest('[data-log-row-select]');
      if (rowSelect) {
        const id = rowSelect.dataset.logRowSelect;
        if (rowSelect.checked) state.selectedRows.add(id);
        else state.selectedRows.delete(id);
        patchRow(id);
        syncToolbar();
        return;
      }
      if (event.target.matches('[data-log-select-page]')) {
        state.rows.forEach((row) => {
          if (event.target.checked) state.selectedRows.add(row.id);
          else state.selectedRows.delete(row.id);
        });
        renderTableRegion();
        return;
      }
      const check = event.target.closest('[data-log-filter-check]');
      if (check) {
        if (check.dataset.logFilterCheck === 'sources') {
          // 勾选来源只影响来源集合；tab（mode）由 tab 自己决定，
          // 否则在「审计」下勾任何 GENERAL 来源都会把用户弹回「常规」。
          if (check.checked) state.sources.add(check.value);
          else state.sources.delete(check.value);
          if (!state.sources.size) state.sources.add(defaultSourceForMode());
          state.view = 'logs';
          state.pageNumber = 0;
          refresh({ resetPage: true });
          return;
        }
        toggleSetValue(selectedSetFor(check.dataset.logFilterCheck), check.value, check.checked);
        return;
      }
      if (event.target.matches('[data-log-page-size]')) {
        state.pageSize = Number(event.target.value) || DEFAULT_PAGE_SIZE;
        state.pageNumber = 0;
        refresh({ resetPage: true });
      }
    }

    function formDataObject(form) {
      const data = {};
      if (!form) return data;
      Array.from(form.elements || []).forEach((field) => {
        if (!field.name) return;
        if (field.type === 'checkbox') data[field.name] = field.checked;
        else data[field.name] = field.value;
      });
      return data;
    }

    function onSubmit(event) {
      const settingsForm = event.target.closest('[data-log-settings-form]');
      if (settingsForm) {
        event.preventDefault();
        saveSettings(formDataObject(settingsForm));
        return;
      }
      const exportForm = event.target.closest('[data-log-export-form]');
      if (exportForm) {
        event.preventDefault();
        exportLogs(formDataObject(exportForm));
      }
    }

    function bind() {
      if (!root || state.bound) return;
      root.addEventListener('click', onClick);
      root.addEventListener('input', onInput);
      root.addEventListener('change', onChange);
      root.addEventListener('submit', onSubmit);
      state.bound = true;
    }

    function unbind() {
      if (!root || !state.bound) return;
      root.removeEventListener('click', onClick);
      root.removeEventListener('input', onInput);
      root.removeEventListener('change', onChange);
      root.removeEventListener('submit', onSubmit);
      state.bound = false;
    }

    function mount(params = {}) {
      if (!root) return { unmount() {} };
      window.clearTimeout(state.refreshTimer);
      window.clearTimeout(state.searchTimer);
      const alreadyMounted = state.bound && Boolean(root.querySelector('[data-log-center-shell]'));
      applyInitialRoute(params);
      bind();
      if (!alreadyMounted) render();
      refresh({ resetPage: true });
      return { unmount };
    }

    function unmount() {
      window.clearTimeout(state.refreshTimer);
      window.clearTimeout(state.searchTimer);
      state.refreshTimer = 0;
      state.searchTimer = 0;
      state.pendingRefreshOptions = null;
      state.refreshSeq += 1;
      state.loading = false;
      state.selectedId = '';
      state.selectedRow = null;
      unbind();
      if (root) root.classList.remove('route-log-center-host');
    }

    return { mount, unmount, refresh };
  }

  window.DWRTLogCenter = { create, version: VERSION };
})();
