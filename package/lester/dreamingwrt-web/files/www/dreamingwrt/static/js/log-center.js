(() => {
  'use strict';

  const VERSION = '20261006-log-center-workbench-06';
  const REFRESH_MS = 30000;
  const SEARCH_DEBOUNCE_MS = 650;
  const DEFAULT_PAGE_SIZE = 25;
  // 表格描述列的截断长度，超出后折叠为「…」，点击展开。
  const MESSAGE_CLAMP_CHARS = 120;
  const ENDPOINTS = {
    audit: '/api/v1/audit/records',
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
    { id: 'LOW', label: '信息', bars: 'low' },
    { id: 'MEDIUM', label: '警告', bars: 'medium' },
    { id: 'HIGH', label: '错误', bars: 'high' },
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
  const AUDIT_EVENT_LABELS = {
    'auth.login.success': 'Web 登录成功',
    'auth.login.failed': 'Web 登录失败',
    'auth.logout': '退出登录',
    'network.dhcp.reservation.create': '添加 DHCP 静态分配',
    'network.dhcp.reservation.update': '修改 DHCP 静态分配',
    'network.dhcp.reservation.delete': '删除 DHCP 静态分配',
    'network.dhcp.apply.failed': '应用 DHCP 配置失败',
    'network.dhcp.apply': '应用 DHCP 配置',
    'system.users.create': '创建用户',
    'system.users.update': '修改用户',
    'system.users.delete': '删除用户',
    'network.wan.update': '修改 WAN 配置',
    'system.ota.apply': '安装系统更新',
    'client.block': '阻止终端联网'
  };
  const AUDIT_RESULT_LABELS = {
    unknown: '未知结果',
    ok: '成功',
    success: '成功',
    applied: '已应用',
    denied: '被拒绝',
    failed: '失败',
    partial: '部分完成',
    cancelled: '已取消',
    dry_run: '仅演练',
    accepted: '已受理',
    dispatched: '已调度',
    observed: '已观察',
    removed: '已移除',
    recovered: '已恢复',
    read_only: '已转只读',
    retrying: '重试中',
    rolled_back: '已回滚'
  };
  const AUDIT_CHANNEL_LABELS = {
    web: 'Web',
    app: 'App',
    api_key: 'API Key',
    cloud: 'Cloud',
    setup: 'Setup',
    system: 'System',
    automation: 'Automation',
    control: 'Control',
    unknown: '未提供'
  };
  const AUDIT_RISK_LABELS = {
    low: '低',
    medium: '中',
    high: '高',
    critical: '严重',
    blocked: '禁止'
  };
  const AUDIT_FAILURE_LABELS = {
    dhcp_apply_failed_rolled_back: '应用失败，已回滚',
    dhcp_apply_failed_rollback_failed: '应用失败，回滚也失败',
    dnsmasq_reload_failed: 'dnsmasq 重载失败',
    dhcp_access_readback_failed: 'DHCP 准入回读失败',
    odhcpd_reload_failed: 'odhcpd 重载失败',
    dhcpv6_readback_failed: 'DHCPv6 回读失败',
    invalid_credentials: '用户名或密码错误',
    login_backend_unavailable: '登录服务不可用'
  };
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
  // 来源仍用于后端查询；审计归属以响应中的显式 AUDIT/source_id 契约为准，
  // 不再用 ADMIN 分类或 auth/login 文本猜测程序日志的语义。
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
    const formatDateTime = options.formatDateTime || ((value) => new Date(timeMs(value)).toLocaleString('zh-CN', { hour12: false }));
    const fetchApiResource = options.fetchApiResource || (async (name) => ({ name, ok: false, data: {}, error: new Error(`${name}: fetch unavailable`) }));
    const mountUiKit = options.mountUiKit || ((target) => window.DWRT_UI_KIT?.mountAll(target));
    const scheduleGlassCardsRender = options.scheduleGlassCardsRender || (() => {});
    const routeTo = options.routeTo || ((path) => { window.location.href = path; });

    const desktop = document.documentElement?.dataset.desktopEmbedded === 'true';
    const requests = new Set();
    const modeStates = {};
    let resizeObserver;
    let filterSheetNode = null;
    let composingSearch = false;
    const state = {
      mode: 'GENERAL',
      sources: new Set(),
      semantic: 'BUSINESS',
      domain: '',
      origin: 'ALL',
      collector: '',
      auditFilters: { actor: '', action: '', channel: '', result: '', risk: '', domain: '' },
      capabilities: {},
      filterOpen: false,
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
      newProtocolAvailable: true,
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
        if (Array.isArray(next)) break;
        current = next;
      }
      return current || {};
    }

    async function requestJson(name, url, init = {}) {
      const hasBody = init.body !== undefined;
      const controller = new AbortController();
      requests.add(controller);
      try {
      const response = await fetch(url, {
        signal: controller.signal,
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
      const payload = unwrapApiData(json);
      if (payload.ok === false) { const error = new Error(`${name}: ${payload.error || '请求失败'}`); error.status = 503; throw error; }
      return payload;
      } finally { requests.delete(controller); }
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

    // 管理审计只认后端的显式类型或结构化 web_audit 标记；程序名和分类文本
    // 不再参与猜测，避免 nginx/dropbear 等常规日志混进操作账本。
    function isAuditRow(row) {
      return String(row.type || '').toUpperCase() === 'AUDIT'
        || row.audit && row.audit.structured === true;
    }

    // tab 归属判定：审计 tab 只显示审计行，常规 tab 排除审计行。
    function modeAllowsRow(row, mode = state.mode) {
      return mode === 'AUDIT' ? isAuditRow(row) && !isAuditReadNoise(row) : !isAuditRow(row);
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
      return {
        type: state.mode, searchText: state.search,
        severities: Array.from(state.severities), sources: Array.from(state.sources),
        ...currentRange(), pageNumber: state.pageNumber, pageSize: state.pageSize,
        categories: Array.from(state.categories), events: Array.from(state.events),
        deviceMacs: Array.from(state.deviceMacs), clientDeviceMacs: Array.from(state.clientDeviceMacs),
        adminIds: Array.from(state.adminIds), programs: Array.from(state.programs),
        ...(state.domain ? { domain: state.domain } : {}),
        ...(state.capabilities.semantic_filter ? { semantic: state.semantic } : {}),
        ...(state.capabilities.origin_filter ? { origin: state.origin } : {}),
        ...(state.collector ? { collectors: [state.collector] } : {})
      };
    }

    function auditQuery() {
      const range = currentRange();
      return new URLSearchParams({ ...state.auditFilters, q: state.search,
        from: Math.floor(range.timestampFrom / 1000), to: Math.floor(range.timestampTo / 1000),
        page: state.pageNumber + 1, page_size: state.pageSize });
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

    function auditEventLabel(key) {
      const code = firstText(key);
      if (!code) return '未提供';
      return AUDIT_EVENT_LABELS[code] || `${code}（未翻译事件）`;
    }

    function eventLabel(key) {
      if (state.mode === 'AUDIT') return auditEventLabel(key);
      const normalizedKey = String(key || '').toUpperCase();
      if (EVENT_LABELS[normalizedKey]) return EVENT_LABELS[normalizedKey];
      const source = state.mode === 'AUDIT' ? AUDIT_EVENTS : GENERAL_EVENTS;
      const direct = source.find(([id]) => id === key);
      if (direct) return direct[1];
      return firstText(key).replace(/_/g, ' ') || '--';
    }

    function objectValue(...values) {
      for (const value of values) {
        if (value && typeof value === 'object' && !Array.isArray(value)) return value;
        if (typeof value !== 'string' || !value.trim().startsWith('{')) continue;
        try {
          const parsed = JSON.parse(value);
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
        } catch (_) {}
      }
      return {};
    }

    function booleanValue(...values) {
      for (const value of values) {
        if (typeof value === 'boolean') return value;
        if (value === 1 || value === '1' || value === 'true') return true;
        if (value === 0 || value === '0' || value === 'false') return false;
      }
      return null;
    }

    function auditChannelLabel(value) {
      const channel = firstText(value).toLowerCase();
      return AUDIT_CHANNEL_LABELS[channel] || (channel ? channel : '未提供');
    }

    function auditResultLabel(value) {
      const result = firstText(value).toLowerCase();
      return AUDIT_RESULT_LABELS[result] || (result ? result : '未提供');
    }

    function auditRiskLabel(value) {
      const risk = firstText(value).toLowerCase();
      return AUDIT_RISK_LABELS[risk] || (risk ? risk : '未提供');
    }

    function auditFailureLabel(value) {
      const reason = firstText(value);
      return AUDIT_FAILURE_LABELS[reason] || reason;
    }

    function actorNameFromRaw(value) {
      const actor = firstText(value);
      return /^(?:web|app):/i.test(actor) ? actor.slice(actor.indexOf(':') + 1) : actor;
    }

    function auditDetailText(row) {
      const admin = firstText(row.admin && row.admin.name, row.admin && row.admin.id, '未知管理员');
      const channel = firstText(row.audit && row.audit.channelLabel, '未提供');
      const clientIp = firstText(row.client && row.client.ip, '未提供');
      const deviceName = firstText(row.device && row.device.name, '本机');
      if (row.event === 'auth.login.success') {
        return `${admin} 使用 ${channel} 登录了 DreamingOS（${deviceName}）。源 IP：${clientIp}`;
      }
      if (row.event === 'auth.login.failed') {
        const reason = firstText(row.audit && row.audit.failureLabel, '未提供原因');
        return `${admin} 使用 ${channel} 登录 DreamingOS（${deviceName}）失败。源 IP：${clientIp}。原因：${reason}`;
      }
      if (row.event === 'auth.logout') {
        return `${admin} 通过 ${channel} 退出了 DreamingOS（${deviceName}）。源 IP：${clientIp}`;
      }
      const object = firstText(row.audit && row.audit.objectName, row.target);
      const result = firstText(row.audit && row.audit.resultLabel);
      const risk = firstText(row.audit && row.audit.riskLabel);
      const failure = firstText(row.audit && row.audit.failureLabel);
      const rollback = row.audit && row.audit.runtimeRolledBack === true ? '，运行态已回滚' : '';
      const stage = firstText(row.audit && row.audit.failureStage);
      const parts = [`${admin} 通过 ${channel} 执行“${row.eventLabel}”`];
      if (object) parts.push(`对象：${object}`);
      if (result) parts.push(`结果：${result}${rollback}`);
      if (risk) parts.push(`风险：${risk}`);
      if (stage) parts.push(`阶段：${stage}`);
      if (failure) parts.push(`原因：${failure}`);
      if (clientIp) parts.push(`源 IP：${clientIp}`);
      return `${parts.shift()}。${parts.join('；')}${parts.length ? '。' : ''}`;
    }

    function isAuditReadNoise(row) {
      const operation = firstText(row.audit && row.audit.operationType).toLowerCase();
      const code = firstText(row.event, row.audit && row.audit.action).toLowerCase();
      if (['read', 'get', 'list', 'search', 'count', 'filter_data', 'filter-data', 'poll', 'query'].includes(operation)) return true;
      return /^\/api\/v1\/logs\/(?:search|query|count|filter-data)(?:$|[/?])/.test(code)
        || /(?:^|\.)(?:search|count|filter_data|poll|query)$/.test(code);
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
      return ms ? formatDateTime(ms, { includeSeconds: true }) : '--';
    }

    function normalizeLogItem(item = {}, index = 0, sourceHint = '') {
      const params = item.parameters && typeof item.parameters === 'object' ? item.parameters : {};
      const rawParams = params.RAW && typeof params.RAW === 'object' ? params.RAW : {};
      const rawDetail = objectValue(rawParams.detail_json, item.detail_json);
      const auditParams = params.AUDIT && typeof params.AUDIT === 'object' ? params.AUDIT : {};
      const device = params.DEVICE || params.device || item.device || {};
      const client = params.CLIENT || params.client || item.client || {};
      const admin = params.ADMIN || params.admin || item.admin || {};
      const actor = objectValue(item.actor_detail, item.actor_identity, item.actor);
      const sourceContext = objectValue(item.source_context, item.source_detail);
      const auditObject = objectValue(item.object, item.target_object, rawDetail.object_detail);
      const severity = severityKey(item.severity, item.level, item.priority, item.status, item.type);
      const category = firstText(item.domain, item.category, item.category_key, item.type === 'audit' ? 'AUDIT' : '', sourceHint);
      const event = firstText(item.event_code, item.event, item.action, auditParams.action, rawDetail.action, item.key, item.event_key, item.message_type);
      const message = firstText(item.presentation?.description, item.message, item.message_raw, item.description, item.detail, item.title, item.title_raw, item.event, item.action);
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
      const actorRaw = firstText(actor.id, admin.actor, rawDetail.actor, item.actor);
      const adminName = firstText(admin.name, rawDetail.admin_name, actor.name, item.admin_name, actorNameFromRaw(actorRaw), item.username, item.user);
      const adminId = firstText(actor.id, admin.id, rawDetail.admin_id, item.admin_id, item.actor_id, adminName);
      const channel = firstText(actor.channel, rawDetail.actor_channel, auditParams.channel, item.actor_channel, item.channel);
      const clientIp = firstText(sourceContext.client_ip, item.source_ip, item.client_ip, auditParams.client_ip, rawDetail.client_ip, client.ip, item.auth_ip);
      const objectName = firstText(auditObject.name, item.object_name, auditParams.object, rawDetail.object, item.object, item.target, device.name);
      const objectId = firstText(auditObject.id, item.object_id, rawDetail.object_id);
      const objectType = firstText(auditObject.type, item.object_type, rawDetail.object_type, item.target_type);
      const result = firstText(item.result, auditParams.result, rawDetail.result);
      const failureReason = firstText(item.failure_reason, auditParams.failure_reason, rawDetail.failure_reason);
      const risk = firstText(item.risk, auditParams.risk, rawDetail.risk);
      const changes = Array.isArray(item.changes) ? item.changes
        : (Array.isArray(rawDetail.changes) ? rawDetail.changes : []);
      const row = {
        id: firstText(item.id, item.external_id, item.uuid, `${sourceHint || 'log'}-${timestamp || Date.now()}-${index}`),
        externalId: firstText(item.external_id, item.uuid),
        category: category || (state.mode === 'AUDIT' ? 'AUDIT' : 'HOST'),
        categoryLabel: firstText(item.domain_label, state.filterData?.domain_catalog?.find(x => x.id === category)?.label, categoryLabel(category || 'SYSTEM')),
        event: event || 'LOG_EVENT',
        eventLabel: state.mode === 'AUDIT'
          ? firstText(item.action_label, item.presentation?.title, auditEventLabel(event))
          : firstText(item.presentation?.title, item.title, item.title_raw, eventLabel(event), event, '日志事件'),
        message,
        severity,
        severityLabel: severityLabel(severity),
        status: firstText(item.status, ''),
        target: firstText(item.message_args?.object_name, item.message_args?.object_id, item.message_args?.disk_id, item.target, item.target_type, ''),
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
          ip: clientIp,
          mac: firstText(client.mac, item.client_mac, item.identity, '')
        },
        admin: {
          id: adminId,
          name: adminName,
          type: firstText(actor.type, rawDetail.actor_type, item.actor_type)
        },
        audit: {
          structured: String(item.type || '').toUpperCase() === 'AUDIT'
            || rawDetail.web_audit === true
            || firstText(item.source_id, rawParams.source).toLowerCase() === 'audit',
          action: event,
          operationType: firstText(item.operation_type, auditParams.operation_type, rawDetail.operation_type),
          channel,
          channelLabel: auditChannelLabel(channel),
          clientIp,
          peerIp: firstText(sourceContext.peer_ip, rawDetail.peer_ip, item.peer_ip),
          ipSource: firstText(sourceContext.ip_source, rawDetail.ip_source, item.ip_source),
          userAgent: firstText(sourceContext.user_agent, rawDetail.user_agent, item.user_agent),
          objectName,
          objectId,
          objectType,
          result,
          resultLabel: auditResultLabel(result),
          risk,
          riskLabel: auditRiskLabel(risk),
          failureReason,
          failureLabel: auditFailureLabel(failureReason),
          failureStage: firstText(item.failure_stage, auditParams.failure_stage, rawDetail.failure_stage),
          applyState: firstText(item.apply_state, auditParams.apply_state, rawDetail.apply_state),
          runtimeRolledBack: booleanValue(item.runtime_rolled_back, auditParams.runtime_rolled_back, rawDetail.runtime_rolled_back),
          scope: firstText(item.scope, auditParams.scope, rawDetail.scope),
          beforeValue: firstText(item.before_value, auditParams.before_value, rawDetail.before_value),
          afterValue: firstText(item.after_value, auditParams.after_value, rawDetail.after_value),
          readback: item.readback || auditParams.readback || rawDetail.readback || null,
          beforeHash: firstText(item.before_hash), afterHash: firstText(item.after_hash),
          requestId: firstText(item.request_id, rawDetail.request_id), taskId: firstText(item.task_id, rawDetail.task_id),
          changes
        },
        raw: item,
        cef: firstText(item.cef, item.syslog, item.raw_log, item.raw)
      };
      if (isAuditRow(row)) row.message = auditDetailText(row);
      return row;
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
      const normalized = {
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
      if (sourceId === 'audit') normalized.audit.structured = true;
      if (state.mode === 'AUDIT' && isAuditRow(normalized)) {
        normalized.eventLabel = firstText(item.action_label, item.presentation?.title, auditEventLabel(normalized.event));
        normalized.message = auditDetailText(normalized);
      }
      return normalized;
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
      const data = unwrapApiData(payload);
      if (Array.isArray(data)) {
        return data.map((item, index) => normalizeLogItem(item, index, 'logs'));
      }
      const sectionRows = legacySourceEntries(data)
        .flatMap((entry) => entry.rows.map((item, index) => normalizeLegacyLogItem(item, index, entry.label, entry.id)));
      if (sectionRows.length) return sectionRows;
      return listFrom(data).map((item, index) => normalizeLogItem(item, index, 'logs'));
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
        row.admin.id,
        row.audit && row.audit.channelLabel,
        row.audit && row.audit.objectName,
        row.audit && row.audit.objectId,
        row.audit && row.audit.resultLabel,
        row.audit && row.audit.riskLabel,
        row.audit && row.audit.failureLabel,
        row.audit && row.audit.scope
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
      (state.mode === 'AUDIT' ? Object.entries(AUDIT_EVENT_LABELS) : GENERAL_EVENTS).forEach(([id, label]) => {
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
      const fallbackEvents = state.mode === 'AUDIT' ? Object.entries(AUDIT_EVENT_LABELS) : GENERAL_EVENTS;
      return {
        domain_catalog: asArray(payload?.domain_catalog),
        domains: normalizeFilterList(payload, 'domains'),
        collectors: normalizeFilterList(payload, 'collectors'),
        origins: normalizeFilterList(payload, 'origins'),
        semantics: normalizeFilterList(payload, 'semantics'),
        sources: normalizeFilterList(payload, 'sources').filter((item) => !/^unifi/i.test(item.id)),
        categories: normalizeFilterList(payload, 'categories').filter((item) => !/^UNIFI_/i.test(item.id)).map((item) => ({ ...item, label: categoryLabel(item.id) })),
        events: normalizeFilterList(payload, 'events').map((item) => ({ ...item, label: eventLabel(item.id) })),
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
      if (state.mode === 'AUDIT') {
        const payload = await requestJson('audit.records', `${ENDPOINTS.audit}?${auditQuery()}`);
        if (seq !== state.refreshSeq) return false;
        state.rows = asArray(payload.items).map((item, i) => normalizeLogItem({ ...item, type: 'AUDIT' }, i));
        state.allRows = state.rows;
        state.total = firstNumber(payload.page?.total);
        state.filterData = { auditFacets: payload.facets || {} };
        state.source = 'audit/records';
        state.notice = '';
      } else {
        const body = requestBody();
        // logd processes ubus requests serially. Search already returns the
        // exact total, so avoid a duplicate count and queue facets after it.
        const payload = await requestJson('logs.search', ENDPOINTS.search, { method: 'POST', body });
        if (seq !== state.refreshSeq) return false;
        const filters = await requestJson('logs.filter-data', ENDPOINTS.filters, { method: 'POST', body });
        if (seq !== state.refreshSeq) return false;
        const hadSemantic = state.capabilities.semantic_filter;
        state.capabilities = { ...state.capabilities, ...payload.capabilities, ...filters.capabilities };
        if (!hadSemantic && state.capabilities.semantic_filter && state.semantic !== 'ALL') return loadNewProtocol(seq);
        state.filterData = normalizeFilterData(filters);
        const search = normalizeSearchPayload(payload);
        state.rows = search.rows;
        state.allRows = search.rows;
        state.total = search.total;
        state.filterData = normalizeFilterData(filters);
        state.source = 'logs/search';
        state.notice = state.capabilities.semantic_filter ? '' : '当前服务未提供语义筛选，显示全部记录。';
      }
      state.filterLocallyEnforced = false;
      pruneSelectedRow();
      state.error = '';
      return true;
    }

    async function loadLegacy(seq, reason = '') {
      const result = await fetchApiResource('logs', `${ENDPOINTS.legacy}?logCenter=${encodeURIComponent(VERSION)}`);
      if (seq !== state.refreshSeq) return false;
      if (!result || !result.ok) {
        const message = result && result.error && result.error.message || reason || '日志接口不可用';
        throw new Error(message);
      }
      const payload = unwrapApiData(result.data || result);
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
        if (state.bound) render();
      }
    }

    async function exportCurrent() {
      const mode=state.mode;
      try {
        if (state.total > 50000) throw new Error('当前结果超过 50,000 条，请缩小时间或筛选范围后导出。');
        let blob;
        if (state.mode === 'AUDIT') {
          const query = auditQuery(); query.set('page_size','200');
          const records=[]; let page=1, total=Infinity;
          while (records.length < total && records.length < 50000) {
            query.set('page',String(page++));
            const data = await requestJson('audit.export', `${ENDPOINTS.audit}?${query}`);
            total=Number(data.page.total); records.push(...data.items);
            if (!data.items.length) break;
          }
          const keys=['id','ts','actor','channel','domain','action','target','result','risk','source_ip','failure_stage','failure_reason','request_id','task_id','before_hash','after_hash'];
          const cell=v=>'"'+String(v ?? '').replaceAll('"','""')+'"';
          blob=new Blob([keys.join(',')+'\n'+records.map(x=>keys.map(k=>cell(x[k])).join(',')).join('\n')],{type:'text/csv;charset=utf-8'});
        } else {
          const out=await requestJson('logs.export',ENDPOINTS.export,{method:'POST',body:{...requestBody(),format:'csv',limit:50000}});
          const controller=new AbortController(); requests.add(controller);
          try {
            const response=await fetch(out.download_url,{signal:controller.signal,headers:authHeaders(),credentials:'same-origin'});
            if (!response.ok) throw new Error(`导出失败 (${response.status})`);
            blob=await response.blob();
          } finally { requests.delete(controller); }
        }
        if(!state.bound || state.mode!==mode)return;
        const href=URL.createObjectURL(blob), a=document.createElement('a'); a.href=href;
        a.download=mode==='AUDIT'?'audit.csv':'logs.csv'; a.click(); setTimeout(()=>URL.revokeObjectURL(href),1000);
      } catch(error) { if(state.bound && error.name!=='AbortError') {state.error=error.message;renderRefreshState();} }
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
        if (state.bound) render();
      }
    }

    async function refresh(options = {}) {
      if (!root || !state.bound) return;
      if (state.loading) { state.pendingRefreshOptions = { ...state.pendingRefreshOptions, ...options }; return; }
      if (options.resetPage) state.pageNumber = 0;
      const seq = ++state.refreshSeq;
      state.loading = true; state.error = '';
      renderRefreshState();
      try {
        await loadNewProtocol(seq);
      } catch (error) {
        if (seq !== state.refreshSeq || error.name === 'AbortError') return;
        if ([404, 405, 501].includes(Number(error.status)) && state.mode === 'GENERAL') {
          try { await loadLegacy(seq); state.notice = '当前服务使用旧日志接口，仅显示可读取的记录。'; }
          catch (fallback) { state.error = fallback.message; }
        } else {
          state.error = Number(error.status) === 403 ? '无权查看此日志。' :
            Number(error.status) === 503 ? '日志服务或数据库不可用，请稍后重试。' : error.message;
        }
      } finally {
        if (seq === state.refreshSeq && state.bound) {
          state.loading = false;
          renderRefreshState();
          const pending = state.pendingRefreshOptions; state.pendingRefreshOptions = null;
          window.clearTimeout(state.refreshTimer);
          state.refreshTimer = window.setTimeout(() => refresh(pending || {}), pending ? 0 : REFRESH_MS);
        }
      }
    }

    function clearFilters() {
      state.search = '';
      state.eventSearch = '';
      state.severities = new Set(SEVERITIES.map((item) => item.id));
      state.sources = new Set();
      state.semantic = 'BUSINESS'; state.domain = ''; state.origin = 'ALL'; state.collector = '';
      state.auditFilters = { actor: '', action: '', channel: '', result: '', risk: '', domain: '' };
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

    function filterChips() {
      const chips=[];
      if(state.search) chips.push(['search',state.search]);
      if(state.period!=='day') chips.push(['period',PERIODS[state.period]?.label || '自定义时间']);
      if(state.mode==='AUDIT') Object.entries(state.auditFilters).forEach(([k,v])=>{if(v)chips.push(['audit:'+k,v]);});
      else {
        if(state.domain) chips.push(['domain',state.filterData?.domains?.find(x=>x.id===state.domain)?.label || state.domain]);
        if(state.origin!=='ALL')chips.push(['origin',state.origin==='RAW'?'本机采集':'结构化来源']);
        if(state.semantic!=='BUSINESS')chips.push(['semantic',state.semantic==='ALL'?'全部记录':'原始日志']);
        if(state.collector)chips.push(['collector',state.collector]);
        ['events','programs','clientDeviceMacs','categories'].forEach(k=>state[k].forEach(v=>chips.push([k+':'+v,v])));
        if(state.severities.size!==SEVERITIES.length)chips.push(['severities','已选等级']);
      }
      return chips;
    }
    function activeFilterCount() { return filterChips().length; }
    function filterSummaryMarkup() {
      return `<div class="log-filter-summary">${filterChips().map(([k,v])=>`<button type="button" data-log-remove-filter="${html(k)}" aria-label="移除筛选 ${html(v)}">${html(v)} ×</button>`).join('')}</div>`;
    }

    function severityBarsMarkup(key) {
      const meta = SEVERITIES.find((item) => item.id === key) || SEVERITIES[0];
      return `<span class="dwrt-risk-bars log-severity-bars ${html(meta.bars)}" aria-hidden="true"><i></i><i></i><i></i><i></i></span>`;
    }

    function modeTabsMarkup() {
      return `<div class="dwrt-kit-tabs log-center-mode-tabs dwrt-kit-page-tabs" data-dwrt-tabs aria-label="日志模式">
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
          <span>日志级别</span>
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
      const data = state.filterData || {};
      const select = (key, label, values, current, attr = 'data-log-query') => `<label class="dwrt-kit-field log-filter-select"><span>${html(label)}</span><select ${attr}="${html(key)}"><option value="">全部</option>${values.map(item => `<option value="${html(item.id || item.value)}" ${current === (item.id || item.value) ? 'selected' : ''}>${html(item.label || item.value || item.id)}${item.count !== undefined ? ` (${item.count})` : ''}</option>`).join('')}</select></label>`;
      if (state.mode === 'AUDIT') {
        const facets = data.auditFacets || {};
        return `<div class="log-filter-scroll">${periodMarkup()}${['actor','channel','action','result','risk','domain'].map((key,i) => select(key,['操作者','渠道','动作','执行结果','操作风险','业务类型'][i],asArray(facets[key]).map(x => ({...x,label: key === 'result' ? auditResultLabel(x.value) : key === 'risk' ? auditRiskLabel(x.value) : x.label || x.value})),state.auditFilters[key],'data-log-audit-filter')).join('')}</div>`;
      }
      return `<div class="log-filter-scroll">${periodMarkup()}${severityMarkup()}
        <label class="dwrt-kit-field log-filter-select"><span>记录范围</span><select data-log-query="semantic" ${state.capabilities.semantic_filter ? '' : 'disabled'}>${[['BUSINESS','业务事件'],['UNCLASSIFIED','未解释的原始日志'],['ALL','全部记录']].map(([id,label])=>`<option value="${id}" ${state.semantic===id?'selected':''}>${label}</option>`).join('')}</select></label>
        ${select('domain','业务类型',asArray(data.domains),state.domain)}
        ${select('origin','采集来源',[{id:'RAW',label:'本机系统 / 内核采集'},{id:'STRUCTURED',label:'应用与结构化采集'}],state.origin)}
        ${select('collector','采集器',asArray(data.collectors),state.collector)}
        ${filterGroup('programs','程序 / 插件',asArray(data.programs).map(x=>checkboxRow('programs',x,state.programs)).join('') || '<p class="log-filter-empty">当前范围无程序记录</p>')}
        ${filterGroup('events','事件',asArray(data.events).map(x=>checkboxRow('events',x,state.events)).join('') || '<p class="log-filter-empty">当前范围无事件记录</p>')}
        ${filterGroup('clients','对象 / 客户端',asArray(data.clientFilters).map(x=>identityRow('clientDeviceMacs',x,state.clientDeviceMacs,'mac')).join('') || '<p class="log-filter-empty">当前范围无对象记录</p>')}
        <details class="log-integration"><summary>领域接入情况</summary>${asArray(data.domain_catalog).map(x=>`<p>${html(x.label)}：${html(x.device_support === 'unsupported' ? '设备不支持' : x.integration_status === 'not_integrated' ? '生产者尚未接入' : '已声明生产者；设备支持情况未确认')}</p>`).join('')}</details>
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
      return `<label class="log-settings-switch dwrt-kit-switch" data-dwrt-component="switch">
        <input type="checkbox" name="${html(name)}" ${checked ? 'checked' : ''}>
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
      if (state.mode === 'AUDIT') return auditRowMarkup(row);
      const selected = state.selectedId && row.id === state.selectedId;
      const checked = state.selectedRows.has(row.id);
      const message = row.message || '--';
      const expanded = state.expandedMessages.has(row.id);
      const truncatable = message.length > MESSAGE_CLAMP_CHARS;
      return `<tr class="${selected ? 'is-selected' : ''} ${checked ? 'is-ai-selected' : ''}" data-log-row="${html(row.id)}">
        <td class="log-table-select-cell"><label class="log-table-select" title="选择此日志"><input type="checkbox" data-log-row-select="${html(row.id)}" ${checked ? 'checked' : ''}><span aria-hidden="true"></span></label></td>
        <td><span class="log-table-category">${html(row.categoryLabel)}</span></td>
        <td><button type="button" class="log-detail-trigger" data-log-detail="${html(row.id)}">${html(row.eventLabel)}</button></td>
        <td class="log-table-desc-cell">
          <span class="log-table-desc ${expanded ? 'is-expanded' : ''}" title="${html(message)}">${html(expanded || !truncatable ? message : `${message.slice(0, MESSAGE_CLAMP_CHARS).trimEnd()}…`)}</span>
          ${truncatable ? `<button type="button" class="log-table-desc-toggle" data-log-desc-toggle="${html(row.id)}" aria-expanded="${expanded}" title="${expanded ? '收起完整描述' : '展开完整描述'}">${expanded ? '收起' : '…'}</button>` : ''}
        </td>
        <td><span class="log-table-severity">${severityBarsMarkup(row.severity)}<em>${html(row.severityLabel)}</em></span></td>
        <td class="num">${html(formatTime(row.timestamp))}</td>
      </tr>`;
    }

    function auditRowMarkup(row) {
      const selected = state.selectedId && row.id === state.selectedId;
      const checked = state.selectedRows.has(row.id);
      const message = row.message || '未提供';
      const expanded = state.expandedMessages.has(row.id);
      const truncatable = message.length > MESSAGE_CLAMP_CHARS;
      return `<tr class="log-audit-row ${selected ? 'is-selected' : ''} ${checked ? 'is-ai-selected' : ''}" data-log-row="${html(row.id)}">
        <td class="log-table-select-cell"><label class="log-table-select" title="选择此日志"><input type="checkbox" data-log-row-select="${html(row.id)}" ${checked ? 'checked' : ''}><span aria-hidden="true"></span></label></td>
        <td data-log-label="操作者"><span class="log-audit-category">${html(row.admin.name || row.admin.id || "未记录身份")}</span><small>${html(row.audit.channelLabel)}</small></td>
        <td data-log-label="事件"><button type="button" class="log-detail-trigger log-audit-event" data-log-detail="${html(row.id)}">${html(row.eventLabel)}</button></td>
        <td class="log-table-desc-cell log-audit-detail-cell" data-log-label="详情">
          <span class="log-table-desc ${expanded ? 'is-expanded' : ''}" title="${html(message)}">${html(expanded || !truncatable ? message : `${message.slice(0, MESSAGE_CLAMP_CHARS).trimEnd()}…`)}</span>
          ${truncatable ? `<button type="button" class="log-table-desc-toggle" data-log-desc-toggle="${html(row.id)}" aria-expanded="${expanded}" title="${expanded ? '收起完整详情' : '展开完整详情'}">${expanded ? '收起' : '…'}</button>` : ''}
        </td>
        <td data-log-label="结果 / 风险"><strong>${html(row.audit.resultLabel || "未知结果")}</strong><small>风险：${html(row.audit.riskLabel || "未知")}</small></td>
        <td class="num" data-log-label="日期 / 时间">${html(formatTime(row.timestamp))}</td>
      </tr>`;
    }

    function tableMarkup() {
      const totalPages = Math.max(1, Math.ceil(state.total / state.pageSize));
      const start = state.total ? state.pageNumber * state.pageSize + 1 : 0;
      const end = Math.min(state.total, (state.pageNumber + 1) * state.pageSize);
      const visibleIds = state.rows.map((row) => row.id);
      const allVisibleSelected = visibleIds.length > 0 && visibleIds.every((id) => state.selectedRows.has(id));
      const body = state.loading && !state.rows.length
        ? `<tr><td colspan="6"><div class="log-table-empty">正在读取日志</div></td></tr>`
        : state.rows.length
          ? state.rows.map(rowMarkup).join('')
          : `<tr><td colspan="6"><div class="log-table-empty">${html(state.error || '当前筛选条件下没有日志。')}</div></td></tr>`;
      const auditMode = state.mode === 'AUDIT';
      return `<section class="log-center-table-card dwrt-kit-table-wrap insights-stable-glass ${auditMode ? 'is-audit-mode' : ''} ${state.aiResult ? 'has-ai-result' : ''}">
        <div class="dwrt-kit-table-toolbar log-center-toolbar">
          <div class="dwrt-kit-table-title">
            <strong>${auditMode ? '操作审计' : '日志中心'}</strong>
            <span>${html(state.loading ? '正在读取' : (auditMode ? '管理员与系统管理操作' : '日志列表'))}</span>
          </div>
          <div class="log-center-toolbar-actions">
            <span class="log-center-notice" ${state.error || state.notice ? '' : 'hidden'}>${html(state.error || state.notice)}</span>
            ${filterSummaryMarkup()}
            ${searchMarkup()}
            <button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-log-open-filter>筛选</button>
            <button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-log-export-current>导出</button>
            <button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-log-action="settings">设置</button>
            <button type="button" class="log-ai-button" data-log-ask-ai ${state.selectedRows.size && !state.aiLoading ? '' : 'disabled'} aria-label="让 AI 分析选中的日志">
              <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M10 2.5c.27 0 .49.2.55.46a4.3 4.3 0 0 0 3.2 3.2c.26.06.45.29.45.55s-.19.49-.45.55a4.3 4.3 0 0 0-3.2 3.2.56.56 0 0 1-1.1 0 4.3 4.3 0 0 0-3.2-3.2.56.56 0 0 1 0-1.1 4.3 4.3 0 0 0 3.2-3.2c.06-.26.28-.46.55-.46Zm5.2 8.8c.22 0 .4.16.45.37a2.64 2.64 0 0 0 1.98 1.98.46.46 0 0 1 0 .9 2.64 2.64 0 0 0-1.98 1.98.46.46 0 0 1-.9 0 2.64 2.64 0 0 0-1.98-1.98.46.46 0 0 1 0-.9 2.64 2.64 0 0 0 1.98-1.98.46.46 0 0 1 .45-.37Z"></path></svg>
              ${html(state.aiLoading ? '分析中' : `问 AI${state.selectedRows.size ? ` (${state.selectedRows.size})` : ''}`)}
            </button>
            <span class="dwrt-kit-table-count">${html(formatInteger(state.total))} 条</span>
          </div>
        </div>
        ${state.aiResult ? `<section class="log-ai-result" aria-live="polite"><strong>AI 分析</strong><p>${html(state.aiResult)}</p><button type="button" data-log-ai-dismiss aria-label="关闭 AI 分析">关闭</button></section>` : ''}
        <div class="dwrt-kit-table-scroll log-center-table-scroll">
          <table class="dwrt-kit-table log-center-table" aria-label="${auditMode ? '操作审计列表' : '日志列表'}">
            <thead><tr><th class="log-table-select-head"><label class="log-table-select" title="选择本页日志"><input type="checkbox" data-log-select-page ${allVisibleSelected ? 'checked' : ''}><span aria-hidden="true"></span></label></th><th>${auditMode ? '操作者 / 渠道' : '业务类型'}</th><th>事件</th><th>${auditMode ? '详情' : '描述'}</th><th>${auditMode ? '结果 / 风险' : '级别'}</th><th class="num">日期 / 时间</th></tr></thead>
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

    function detailJsonValue(value) {
      if (value === undefined || value === null || value === '') return '';
      if (typeof value === 'string') return value;
      try { return JSON.stringify(value, null, 2); } catch (_) { return String(value); }
    }

    function auditChangesMarkup(row) {
      const audit = row.audit || {};
      if (audit.changes && audit.changes.length) {
        return audit.changes.map((change) => {
          const path = firstText(change.path, change.field, change.name, '字段');
          const hidden = change.redacted === true || change.changed === true && !('old' in change) && !('new' in change);
          const value = hidden
            ? '已更改，内容已隐藏'
            : `${detailJsonValue(change.old ?? change.before ?? '未提供')} → ${detailJsonValue(change.new ?? change.after ?? '未提供')}`;
          return detailRow(path, value);
        }).join('');
      }
      if (audit.beforeHash || audit.afterHash) return `${detailRow('信息范围', '仅记录前后哈希，未提供字段差异')}${detailRow('修改前哈希', audit.beforeHash)}${detailRow('修改后哈希', audit.afterHash)}`;
      return `${detailRow('修改前', audit.beforeValue)}${detailRow('修改后', audit.afterValue)}`;
    }

    function auditDrawerMarkup(row, raw) {
      const audit = row.audit || {};
      return `<header class="dwrt-kit-sheet-header log-drawer-head">
          <div>
            <span>${html(formatTime(row.timestamp))}</span>
            <strong>${html(row.eventLabel)}</strong>
          </div>
          <button type="button" class="dwrt-kit-sheet-close" data-log-close-drawer aria-label="关闭日志详情">×</button>
        </header>
        <div class="dwrt-kit-sheet-body log-drawer-scroll">
          <section class="log-detail-section log-audit-primary-detail">
            <h3>操作详情</h3>
            <dl>
              ${detailRow('事件', row.eventLabel)}
              ${detailRow('操作风险', audit.riskLabel || '未知')}
              ${detailRow('管理员名称', row.admin.name || row.admin.id || '未提供')}
              ${detailRow('访问方式', audit.channelLabel || '未提供')}
              ${detailRow('源 IP 地址', audit.clientIp || row.client.ip || '未提供')}
              ${detailRow('详情', row.message || '未提供')}
            </dl>
          </section>
          <section class="log-detail-section">
            <h3>结果与对象</h3>
            <dl>
              ${detailRow('结果', audit.resultLabel)}
              ${detailRow('风险', audit.riskLabel)}
              ${detailRow('失败原因', audit.failureLabel)}
              ${detailRow('失败阶段', audit.failureStage)}
              ${detailRow('应用状态', audit.applyState)}
              ${detailRow('运行态回滚', audit.runtimeRolledBack === null ? '' : (audit.runtimeRolledBack ? '是' : '否'))}
              ${detailRow('对象', audit.objectName)}
              ${detailRow('对象类型', audit.objectType)}
              ${detailRow('对象标识', audit.objectId)}
              ${detailRow('作用域', audit.scope)}
              ${detailRow('请求 ID', audit.requestId)}
              ${detailRow('任务 ID', audit.taskId)}
              ${detailRow('账本记录 ID', row.raw.audit_record_id || row.raw.id)}
            </dl>
          </section>
          ${auditChangesMarkup(row) ? `<section class="log-detail-section"><h3>字段变更</h3><dl>${auditChangesMarkup(row)}</dl></section>` : ''}
          ${audit.readback ? `<section class="log-detail-section"><h3>运行态回读</h3><pre class="log-detail-json">${html(detailJsonValue(audit.readback))}</pre></section>` : ''}
          <details class="log-detail-section log-detail-raw">
            <summary>CEF 日志（高级）</summary>
            <div class="log-detail-title-row">
              <span>原始安全事件证据</span>
              <button type="button" data-log-copy="${html(row.id)}">复制</button>
            </div>
            <pre>${html(raw)}</pre>
          </details>
        </div>`;
    }

    function drawerMarkup() {
      const row = state.selectedRow;
      if (!row) return '';
      const raw = rawLogText(row);
      const content = state.mode === 'AUDIT' ? auditDrawerMarkup(row, raw) : `<header class="dwrt-kit-sheet-header log-drawer-head">
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
              ${detailRow('业务类型', row.categoryLabel)}
              ${detailRow('执行结果', auditResultLabel(row.raw.result))}
              ${detailRow('首次 / 末次', `${formatTime(row.raw.first_seen)} / ${formatTime(row.raw.last_seen)}`)}
              ${detailRow('重复次数', row.raw.count)}
              ${detailRow('任务', row.audit.taskId || row.raw.message_args?.task_id)}
              ${detailRow('呈现状态', row.raw.presentation?.render_status)}
              ${detailRow('状态', row.status)}
              ${detailRow('目标', row.target)}
              ${detailRow('原始来源', row.source)}
              ${detailRow('来源程序', row.programLabel || row.programId)}
              ${detailRow('协议', row.raw.message_args?.protocol || row.raw.message_args?.service || row.raw.protocol)}
              ${detailRow('操作者', row.raw.message_args?.actor || row.raw.username)}
              ${detailRow('来源 IP', row.raw.source_ip)}
              ${detailRow('失败阶段', row.raw.message_args?.failure_stage)}
              ${detailRow('失败原因', row.raw.message_args?.failure_reason)}
              ${detailRow('触发方式', row.raw.message_args?.trigger)}
              ${detailRow('文件大小（字节）', row.raw.message_args?.size_bytes || row.raw.message_args?.bytes)}
              ${detailRow('校验摘要', row.raw.message_args?.checksum)}
              ${detailRow('系统启动时间', row.raw.message_args?.boot_time ? formatTime(row.raw.message_args.boot_time) : '')}
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
          <details class="log-detail-section log-detail-raw">
            <summary>原始日志证据</summary>
            <div class="log-detail-title-row">
              <button type="button" data-log-copy="${html(row.id)}">复制</button>
            </div>
            <pre>${html(raw)}</pre>
          </details>
        </div>`;
      // 与 AI 抽屉同一套 kit 组件（copilot 变体），不再手搓玻璃层。
      return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-log-close-drawer aria-label="关闭日志详情"></button><aside class="log-center-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" aria-label="日志详情">
        ${content}
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

    function railMarkup() {
      return `<nav class="dwrt-rail log-center-rail" aria-label="日志视图"><div class="dwrt-rail-list">${[['GENERAL','常规日志'],['AUDIT','审计日志']].map(([id,label])=>`<button type="button" class="dwrt-rail-item ${state.mode===id?'is-active':''}" data-log-mode="${id}" title="${label}" aria-label="${label}" aria-current="${state.mode===id?'page':'false'}"><span class="dwrt-rail-item-icon"><img src="/static/desktop/assets/log-center.png" alt=""></span><span class="dwrt-rail-item-text"><span class="dwrt-rail-item-title">${label}</span></span></button>`).join('')}</div></nav>`;
    }

    function filterSheetMarkup() {
      if (!state.filterOpen) return '';
      return `<button type="button" class="dwrt-kit-sheet-overlay is-open" data-log-close-filter aria-label="关闭筛选"></button><aside class="dwrt-kit-sheet dwrt-kit-glass-surface is-open log-filter-sheet" data-dwrt-component="sheet" aria-label="日志筛选"><header class="dwrt-kit-sheet-header"><strong>筛选日志</strong><button type="button" class="dwrt-kit-sheet-close" data-log-close-filter aria-label="关闭筛选">×</button></header><div class="dwrt-kit-sheet-body log-center-filter">${filtersMarkup()}${filterFooterMarkup()}</div></aside>`;
    }

    function syncFilterSheet() {
      const host = root.querySelector('[data-log-filter-host]');
      if (!host) return;
      window.DWRT_UI_KIT?.unmount?.(host);
      host.innerHTML = filterSheetMarkup();
      filterSheetNode = host.querySelector('.log-filter-sheet');
      mountUiKit(host);
    }

    function render() {
      if (!root) return;
      const interaction = captureInteractionState();
      window.DWRT_UI_KIT?.unmount?.(root);
      root.classList.add('route-workspace', 'route-log-center-host');
      root.hidden = false;
      root.innerHTML = `<section class="log-center-shell ${desktop?'is-desktop':'is-console dwrt-kit-page-surface'}" data-log-center-shell>
        ${desktop ? railMarkup() : modeTabsMarkup()}
        <main class="log-center-main">${state.view === 'settings' ? settingsMarkup() : tableMarkup()}</main>
        <div data-log-filter-host>${filterSheetMarkup()}</div>
        <div class="log-center-drawer-host" data-log-drawer-host>${state.view === 'settings' ? '' : drawerMarkup()}</div>
      </section>`;
      filterSheetNode = root.querySelector('.log-filter-sheet');
      mountUiKit(root); scheduleGlassCardsRender(160); restoreInteractionState(interaction);
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
      window.DWRT_UI_KIT?.unmount?.(host);
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
      const main = root?.querySelector('.log-center-main');
      if (!state.bound) return;
      if (!main) { render(); return; }
      if (state.view === 'settings') return;
      const card = main.querySelector('.log-center-table-card');
      if (!card) { main.innerHTML = tableMarkup(); mountUiKit(main); return; }
      const template = document.createElement('template'); template.innerHTML = tableMarkup();
      const next = template.content;
      const scroll = card.querySelector('.log-center-table-scroll');
      const top = scroll.scrollTop, left = scroll.scrollLeft;
      card.querySelector('tbody').innerHTML = next.querySelector('tbody').innerHTML;
      card.querySelector('.log-center-pagination').replaceWith(next.querySelector('.log-center-pagination'));
      card.querySelector('.dwrt-kit-table-count').textContent = state.error ? '读取失败' : `${formatInteger(state.total)} 条`;
      const notice = card.querySelector('.log-center-notice');
      notice.textContent = state.error || state.notice; notice.hidden = !notice.textContent;
      card.setAttribute('aria-busy', String(state.loading));
      scroll.scrollTop = top; scroll.scrollLeft = left;
      card.querySelector('.log-ai-result')?.remove();
      const ai = next.querySelector('.log-ai-result');
      if (ai) card.querySelector('.log-center-table-scroll').before(ai);
      card.classList.toggle('has-ai-result', Boolean(ai));
      syncToolbar();
    }

    function renderFilterRegion() {
      if (!state.filterOpen || !filterSheetNode?.isConnected) return;
      const body = filterSheetNode.querySelector('.log-center-filter');
      if (!body) return;
      const paint = (target) => { target.innerHTML = filtersMarkup() + filterFooterMarkup(); };
      if (window.DWRT_UI_KIT?.preserveInteractionState) {
        window.DWRT_UI_KIT.preserveInteractionState(body, paint, { skipWhileInteracting: true });
      } else if (!body.contains(document.activeElement)) paint(body);
    }

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

    function closeDrawer() {
      const previousId = state.selectedId;
      state.selectedId = '';
      state.selectedRow = null;
      if (previousId) patchRow(previousId);
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
      const mode=state.mode;
      if (!state.selectedRows.size || state.aiLoading) return;
      const rows = state.allRows.filter((row) => state.selectedRows.has(row.id));
      if (!rows.length) return;
      if (!state.settings) {
        try { state.settings = await requestJson('logs.settings', ENDPOINTS.settings); }
        catch (error) { if (state.bound && error.name !== 'AbortError') { state.notice = error.message; syncToolbar(); } return; }
        if (!state.bound || state.mode !== mode) return;
      }
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
        if(!state.bound || mode!==state.mode)return;
        state.aiResult = aiResponseText(payload) || 'AI 已完成分析，但没有返回可显示的摘要。';
      } catch (error) {
        if(!state.bound || mode!==state.mode || error.name==='AbortError')return;
        const unavailable = [404, 405, 501].includes(Number(error && error.status));
        state.notice = unavailable ? '后端尚未提供日志 AI 分析接口。' : (error && error.message || '日志 AI 分析失败');
      } finally {
        state.aiLoading = false;
        renderTableRegion();
      }
    }

    function onClick(event) {
      const remove=event.target.closest('[data-log-remove-filter]');
      if(remove) {
        const key=remove.dataset.logRemoveFilter, [group,...tail]=key.split(':'), value=tail.join(':');
        if(group==='audit')state.auditFilters[value]='';
        else if(state[group] instanceof Set) { if(group==='severities')state.severities=new Set(SEVERITIES.map(x=>x.id)); else state[group].delete(value); }
        else state[group]=group==='period'?'day':group==='semantic'?'BUSINESS':group==='origin'?'ALL':'';
        refresh({resetPage:true}); return;
      }

      if (event.target.closest('[data-log-open-filter]')) { state.filterOpen = true; syncFilterSheet(); return; }
      if (event.target.closest('[data-log-close-filter]')) { state.filterOpen = false; syncFilterSheet(); return; }
      if (event.target.closest('[data-log-detail]')) { selectRow(event.target.closest('[data-log-detail]').dataset.logDetail); return; }
      if (event.target.closest('[data-log-export-current]')) { exportCurrent(); return; }

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
        if (nextMode === state.mode && state.view === 'logs') return;
        const keys = ['sources','semantic','domain','origin','collector','auditFilters','search','period','customRange','severities','categories','events','deviceMacs','clientDeviceMacs','adminIds','programs','pageNumber','rows','allRows','total','filterData'];
        modeStates[state.mode] = Object.fromEntries(keys.map(k=>[k,state[k]]));
        requests.forEach(c=>c.abort()); state.refreshSeq++; state.loading=false;
        window.clearTimeout(state.searchTimer); window.clearTimeout(state.refreshTimer); state.pendingRefreshOptions=null;
        state.aiLoading=false; state.aiResult=null; state.error=''; state.notice='';
        state.mode = nextMode;
        const saved = modeStates[nextMode];
        if (saved) Object.assign(state,saved);
        else { state.search=''; state.period='day'; state.customRange=null; state.pageNumber=0; state.rows=[]; state.allRows=[]; state.total=0; state.filterData=null;
          state.semantic='BUSINESS'; state.domain=''; state.origin='ALL'; state.collector='';
          state.auditFilters={actor:'',action:'',channel:'',result:'',risk:'',domain:''};
          state.severities=new Set(SEVERITIES.map(x=>x.id));
          ['sources','categories','events','deviceMacs','clientDeviceMacs','adminIds','programs'].forEach(k=>state[k]=new Set()); }
        state.view='logs'; state.selectedId=''; state.selectedRow=null; state.selectedRows.clear(); state.filterOpen=false;
        render(); refresh();
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
        closeDrawer();
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
          state.filterOpen = false;
          if (!state.settings) requestJson('logs.settings', ENDPOINTS.settings).then(x => { if(!state.bound)return; state.settings=x; if(state.view==='settings') render(); }).catch(e=>{if(!state.bound || e.name==='AbortError')return; state.error=e.message;render();});
          state.selectedId = '';
          state.selectedRow = null;
          render();
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
        if (composingSearch || event.isComposing) return;
        state.searchTimer = window.setTimeout(() => refresh({ resetPage: true }), SEARCH_DEBOUNCE_MS);
      }
      if (event.target.matches('[data-log-event-search]')) {
        state.eventSearch = event.target.value || '';
        renderFilterRegion();
      }
    }

    function onChange(event) {
      if (event.target.matches('[data-log-query], [data-log-audit-filter]')) {
        if (event.target.dataset.logAuditFilter) state.auditFilters[event.target.dataset.logAuditFilter] = event.target.value;
        else state[event.target.dataset.logQuery] = event.target.value || (event.target.dataset.logQuery === 'origin' ? 'ALL' : '');
        refresh({ resetPage:true }); return;
      }

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

    function onCompositionStart(event) {
      if (!event.target.matches('[data-log-search]')) return;
      composingSearch = true;
      window.clearTimeout(state.searchTimer);
    }

    function onCompositionEnd(event) {
      if (!event.target.matches('[data-log-search]')) return;
      composingSearch = false;
      onInput(event);
    }

    function bind() {
      if (!root || state.bound) return;
      root.addEventListener('click', onClick);
      root.addEventListener('input', onInput);
      root.addEventListener('change', onChange);
      root.addEventListener('submit', onSubmit);
      root.addEventListener('compositionstart', onCompositionStart);
      root.addEventListener('compositionend', onCompositionEnd);
      state.bound = true;
    }

    function unbind() {
      if (!root || !state.bound) return;
      root.removeEventListener('click', onClick);
      root.removeEventListener('input', onInput);
      root.removeEventListener('change', onChange);
      root.removeEventListener('submit', onSubmit);
      root.removeEventListener('compositionstart', onCompositionStart);
      root.removeEventListener('compositionend', onCompositionEnd);
      state.bound = false;
    }

    function mount(params = {}) {
      if (!root) return { unmount() {} };
      window.clearTimeout(state.refreshTimer);
      window.clearTimeout(state.searchTimer);
      const alreadyMounted = state.bound && Boolean(root.querySelector('[data-log-center-shell]'));
      applyInitialRoute(params);
      bind();
      resizeObserver?.disconnect();
      resizeObserver = new ResizeObserver(entries => root.classList.toggle('log-compact', entries[0].contentRect.width <= 720));
      resizeObserver.observe(root);
      if (!alreadyMounted) render();
      refresh({ resetPage: true });
      return { unmount };
    }

    function unmount() {
      window.DWRT_UI_KIT?.unmount?.(root);
      filterSheetNode = null;
      composingSearch = false;
      resizeObserver?.disconnect();
      requests.forEach(c=>c.abort());
      requests.clear();
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

    return {
      mount,
      unmount,
      refresh,
      __test: {
        setMode(mode) { state.mode = mode === 'AUDIT' ? 'AUDIT' : 'GENERAL'; },
        normalizeLogItem,
        auditDrawerMarkup(row) { return auditDrawerMarkup(row, rawLogText(row)); },
        isAuditReadNoise
      }
    };
  }

  window.DWRTLogCenter = { create, version: VERSION };
})();
