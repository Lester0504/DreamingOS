(() => {
  'use strict';

  const REFRESH_MS = 5000;
  const STATUS_KEY = 'dreamingwrt.web.clientDetails.status';
  const IPV6_KEY = 'dreamingwrt.web.clientDetails.showIpv6';
  const SORT_KEY = 'dreamingwrt.web.clientDetails.sort';
  const FILTER_KEY = 'dreamingwrt.web.clientDetails.filters';
  const CLIENT_COLUMN_ORDER_KEY = 'dreamingwrt.web.clientDetails.columnOrder';
  const FILTER_TAB_KEY = 'dreamingwrt.web.clientDetails.filterTab';
  const CONNECTION_FILTER_KEY = 'dreamingwrt.web.clientDetails.connectionFilters';
  const CONNECTION_COLUMN_KEY = 'dreamingwrt.web.clientDetails.connectionColumns';
  const CONNECTION_OPTION_TAB_KEY = 'dreamingwrt.web.clientDetails.connectionOptionTab';
  const CONNECTION_AUTO_KEY = 'dreamingwrt.web.clientDetails.connectionAutoRefresh';
  const RATE_HOLD_MS = 9000;
  const PROTOCOL_CHART_MODE_KEY = 'dreamingwrt.web.clientDetails.protocolChartMode';
  const PROTOCOL_LEGEND_KEY = 'dreamingwrt.web.clientDetails.protocolLegend';
  const OVERVIEW_LEGEND_KEY = 'dreamingwrt.web.clientDetails.overviewLegend';
  const OVERVIEW_BUCKET_SECONDS = 5;
  const OVERVIEW_WINDOW_SECONDS = 5 * 60;
  const ECHARTS_VENDOR_URL = '/static/vendor/echarts.min.js';
  const CLIENT_COLUMN_FILTERS = {
    upRate: { label: '上行速率', unit: 'rate', metric: 'upRate' },
    downRate: { label: '下行速率', unit: 'rate', metric: 'downRate' },
    connections: { label: '连接数', unit: 'count', metric: 'connections' },
    upTotal: { label: '累计上行', unit: 'bytes', metric: 'upBytes' },
    downTotal: { label: '累计下行', unit: 'bytes', metric: 'downBytes' }
  };
  const CLIENT_TABLE_COLUMNS = [
    { key: 'name', label: '备注', className: 'client-name-col' },
    { key: 'vendorType', label: '厂商/类型' },
    { key: 'ip', label: 'IP 地址', className: 'client-ip-col' },
    { key: 'mac', label: 'MAC 地址' },
    { key: 'upRate', label: '上行速率', numeric: true, tone: 'up' },
    { key: 'downRate', label: '下行速率', numeric: true, tone: 'down' },
    { key: 'connections', label: '连接数', numeric: true },
    { key: 'upTotal', label: '累计上行', numeric: true, tone: 'up' },
    { key: 'downTotal', label: '累计下行', numeric: true, tone: 'down' },
    { key: 'onlineTime', label: '在线时间', numeric: true }
  ];
  const CLIENT_TABLE_COLUMN_KEYS = CLIENT_TABLE_COLUMNS.map((column) => column.key);
  const CONNECTION_COLUMNS = [
    { key: 'app', label: '应用' },
    { key: 'proto', label: '协议' },
    { key: 'line', label: '线路' },
    { key: 'externalIp', label: '外网地址' },
    { key: 'domain', label: '域名' },
    { key: 'srcPort', label: '源端口' },
    { key: 'dstIp', label: '目的地址' },
    { key: 'dstPort', label: '目的端口' },
    { key: 'upBytes', label: '累计上行' },
    { key: 'downBytes', label: '累计下行' },
    { key: 'upRate', label: '上行速率' },
    { key: 'downRate', label: '下行速率' },
    { key: 'status', label: '连接状态' },
    { key: 'action', label: '操作' }
  ];
  const CONNECTION_DEFAULT_COLUMNS = CONNECTION_COLUMNS.map((column) => column.key);
  const DETAIL_TABS = [
    ['overview', '数据概览'],
    ['control', '管控详情'],
    ['info', '信息详情'],
    ['protocol', '协议详情'],
    ['connection', '连接详情'],
    ['custom', '自定义']
  ];
  const PROTOCOL_CATEGORIES = [
    { key: 'download', label: '传输下载', color: '#3f7df6', match: /下载|传输|cdn|download|torrent|bt|p2p|文件|资源/i },
    { key: 'leisure', label: '休闲娱乐', color: '#5ed6a2', match: /休闲|娱乐|视频|音乐|直播|bili|youtube|netflix|media|video|audio|stream/i },
    { key: 'game', label: '网络游戏', color: '#e37b43', match: /游戏|game|steam|xbox|playstation|epic|riot|battle/i },
    { key: 'life', label: '生活服务', color: '#c873ee', match: /生活|服务|地图|外卖|购物|支付|travel|shop|map|weather|生活服务/i },
    { key: 'network', label: '网络协议', color: '#7c64df', match: /网络协议|协议|dns|http|https|quic|ntp|icmp|tcp|udp|ssl|tls|dhcp|mqtt|ssh|vpn/i },
    { key: 'efficiency', label: '效率工具', color: '#9ccd32', match: /效率|工具|同步|云盘|drive|dropbox|icloud|onedrive|github|git|download tools/i },
    { key: 'finance', label: '金融理财', color: '#e96fb7', match: /金融|理财|银行|证券|支付|finance|bank|stock|alipay|wechat pay/i },
    { key: 'study', label: '学习教育', color: '#4ca4ae', match: /学习|教育|课程|文档|wiki|edu|course|school|study/i },
    { key: 'social', label: '社交通讯', color: '#54bf3e', match: /社交|通讯|微信|qq|telegram|discord|whatsapp|message|im|mail|push/i },
    { key: 'office', label: '办公协作', color: '#76a0e8', match: /办公|协作|会议|文档|office|work|teams|zoom|slack|notion|docs/i },
    { key: 'unknown', label: '未知应用', color: '#d219dc', match: /未知|unknown|other|其它|其他/i }
  ];
  const BRAND_LOGO_BASE = '/static/images/logo/';
  const BRAND_LOGO_SLUGS = new Set([
    'acer', 'amazon', 'apple', 'avm', 'bose', 'debian', 'dell', 'epson', 'fedora',
    'freebsd', 'freenas', 'gldotinet', 'google', 'haiku', 'home-assistant', 'honeywell',
    'huawei', 'ibm', 'intel', 'irobot', 'jbl', 'lg', 'linksys', 'linux', 'meizu',
    'microsoft', 'mikrotik', 'msi', 'nintendo', 'nokia', 'openbsd', 'oppo', 'plex',
    'proxmox', 'qnap', 'red-hat', 'ring', 'samsung', 'sony-group', 'synology',
    'tecno', 'tesla', 'tp-link', 'truenas', 'ubiquiti', 'ubuntu', 'unraid', 'valve',
    'vivo', 'xiaomi', 'zte', 'ikuai'
  ]);
  const BRAND_ALIASES = [
    [/\b(ikuai|ikuaios|i-kuai)\b|爱快/i, 'ikuai'],
    [/\b(apple|iphone|ipad|macbook|macintosh)\b/i, 'apple'],
    [/\b(synology|diskstation|dsm)\b/i, 'synology'],
    [/\bproxmox\b/i, 'proxmox'],
    [/\b(gldotinet|gl[-\s.]?inet)\b|golden\s*dot/i, 'gldotinet'],
    [/\b(ubiquiti|unifi)\b/i, 'ubiquiti'],
    [/\b(xiaomi|redmi)\b|小米/i, 'xiaomi'],
    [/\b(huawei|honor)\b|华为|荣耀/i, 'huawei'],
    [/\b(samsung|galaxy)\b|三星/i, 'samsung'],
    [/\b(google|pixel|chromecast)\b/i, 'google'],
    [/\b(microsoft|windows|xbox)\b/i, 'microsoft'],
    [/\btp[-\s]?link\b|\btplink\b/i, 'tp-link'],
    [/\bqnap\b/i, 'qnap'],
    [/\btruenas\b/i, 'truenas'],
    [/\bfreenas\b/i, 'freenas'],
    [/\bunraid\b/i, 'unraid'],
    [/\bmikrotik\b/i, 'mikrotik'],
    [/\b(nintendo|gamecube|wii)\b/i, 'nintendo'],
    [/\boppo\b/i, 'oppo'],
    [/\bvivo\b/i, 'vivo'],
    [/\bzte\b|中兴/i, 'zte'],
    [/\b(dell|alienware)\b/i, 'dell'],
    [/\bacer\b/i, 'acer'],
    [/\bintel\b/i, 'intel'],
    [/\blinux\b/i, 'linux'],
    [/\bubuntu\b/i, 'ubuntu'],
    [/\bdebian\b/i, 'debian'],
    [/\bfedora\b/i, 'fedora'],
    [/\bfreebsd\b/i, 'freebsd'],
    [/\bopenbsd\b/i, 'openbsd'],
    [/\bred\s*hat\b|\bredhat\b/i, 'red-hat'],
    [/\bhome\s*assistant\b/i, 'home-assistant'],
    [/\bplex\b/i, 'plex'],
    [/\btesla\b/i, 'tesla'],
    [/\b(amazon|kindle|echo)\b|\bfire\s*tv\b/i, 'amazon'],
    [/\bnokia\b/i, 'nokia'],
    [/\bmeizu\b|魅族/i, 'meizu'],
    [/\blg\b|\blg electronics\b/i, 'lg'],
    [/\blinksys\b/i, 'linksys'],
    [/\bepson\b/i, 'epson'],
    [/\bbose\b/i, 'bose'],
    [/\bjbl\b/i, 'jbl'],
    [/\bhoneywell\b/i, 'honeywell'],
    [/\b(irobot|roomba)\b/i, 'irobot'],
    [/\bring\b/i, 'ring'],
    [/\bvalve\b|steam deck/i, 'valve'],
    [/\bmsi\b|micro-star/i, 'msi'],
    [/\bibm\b/i, 'ibm'],
    [/\b(avm|fritz)\b/i, 'avm'],
    [/\btecno\b/i, 'tecno'],
    [/\btrue\s*nas\b/i, 'truenas'],
    [/\bfree\s*nas\b/i, 'freenas'],
    [/\bsony\b(?:\s*(group|corp|corporation))?|\b(playstation|bravia)\b/i, 'sony-group']
  ];

  function fallbackEscape(value) {
    return String(value === undefined || value === null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function fallbackText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (Array.isArray(value)) {
        const nested = fallbackText(...value);
        if (nested) return nested;
        continue;
      }
      if (typeof value === 'object') {
        const nested = fallbackText(value.remark, value.nickname, value.display_name, value.hostname, value.name, value.label, value.value);
        if (nested) return nested;
        continue;
      }
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }

  function fallbackNumber(...values) {
    for (const value of values) {
      if (value === undefined || value === null || value === '') continue;
      const num = Number(value);
      if (Number.isFinite(num)) return num;
    }
    return 0;
  }

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function create(context = {}) {
    const root = context.routePreview || document.getElementById('routePreview');
    const escapeHtml = context.escapeHtml || fallbackEscape;
    const firstText = context.firstText || fallbackText;
    const firstNumber = context.firstNumber || fallbackNumber;
    const fetchApiResource = context.fetchApiResource || (async (name) => ({ name, ok: false, data: {}, error: new Error(`${name}: fetch unavailable`) }));
    const formatRate = context.formatRate || ((bytes) => `${Math.max(0, Number(bytes) || 0)} B/s`);
    const formatBytes = context.formatBytes || ((bytes) => `${Math.max(0, Number(bytes) || 0)} B`);
    const formatInteger = context.formatInteger || ((value) => Number(value || 0).toLocaleString());
    const formatUptime = context.formatUptime || ((seconds) => {
      const total = Math.max(0, Math.floor(Number(seconds) || 0));
      if (!total) return '--';
      const days = Math.floor(total / 86400);
      const hours = Math.floor(total % 86400 / 3600);
      const mins = Math.floor(total % 3600 / 60);
      if (days) return `${days}天 ${hours}小时`;
      if (hours) return `${hours}小时 ${mins}分钟`;
      return `${mins}分钟`;
    });
    const mountUiKit = context.mountUiKit || ((target) => window.DWRT_UI_KIT?.mountAll(target));
    const statusBadgeMarkup = (...args) => window.DWRT_UI_KIT?.statusBadgeMarkup?.(...args) || '';
    const scheduleGlassCardsRender = context.scheduleGlassCardsRender || (() => {});
    const shouldDeferRender = context.shouldDeferRender || (() => false);
    const realtime = context.realtime || window.DWRTRealtime;

    let echartsLoadingPromise = null;

    function loadECharts() {
      if (window.echarts) return Promise.resolve(window.echarts);
      if (echartsLoadingPromise) return echartsLoadingPromise;
      echartsLoadingPromise = new Promise((resolve, reject) => {
        const existing = document.querySelector(`script[src="${ECHARTS_VENDOR_URL}"]`);
        const script = existing || document.createElement('script');
        const done = () => window.echarts ? resolve(window.echarts) : reject(new Error('echarts unavailable'));
        script.addEventListener('load', done, { once: true });
        script.addEventListener('error', () => reject(new Error('echarts load failed')), { once: true });
        if (!existing) {
          script.src = ECHARTS_VENDOR_URL;
          script.async = true;
          document.head.appendChild(script);
        } else if (window.echarts) {
          done();
        }
      });
      return echartsLoadingPromise;
    }

    let page = null;

    function authHeaders(headers = {}) {
      let token = '';
      try { token = localStorage.getItem('dreamingwrt.web.accessToken') || ''; } catch (_) {}
      return token ? { ...headers, Authorization: `Bearer ${token}` } : headers;
    }

    async function postApiResource(name, url, payload) {
      try {
        const response = await fetch(url, {
          method: 'POST',
          credentials: 'same-origin',
          cache: 'no-store',
          headers: authHeaders({ 'Content-Type': 'application/json', Accept: 'application/json' }),
          body: JSON.stringify(payload || {})
        });
        const text = await response.text();
        let json = {};
        if (text) {
          try { json = JSON.parse(text); } catch (_) { throw new Error(`${name}: invalid json`); }
        }
        if (!response.ok || json && json.ok === false) {
          const message = json && (json.message || json.error && (json.error.message || json.error.code) || json.error) || `${response.status}`;
          throw new Error(`${name}: ${message}`);
        }
        return { ok: true, data: json && json.data && typeof json.data === 'object' ? json.data : json };
      } catch (error) {
        return { ok: false, error };
      }
    }

    function shouldHoldRender() {
      const active = document.activeElement;
      if (!active || !root || !root.contains(active)) return false;
      return Boolean(active.closest('input, textarea, select, [contenteditable="true"]'));
    }

    function detailRenderKey() {
      if (!page || !page.active) return '';
      const fingerprint = page.fingerprint && page.fingerprint.open ? page.fingerprint : null;
      const detail = page.detail && page.detail.open ? page.detail : null;
      return [
        `list:${page.status || 'online'}:${page.showIpv6 ? 'ipv6' : 'ipv4'}:${page.sort && page.sort.key || 'name'}:${page.sort && page.sort.direction || 'asc'}:${firstText(page.filters && page.filters.keyword, page.search)}`,
        detail ? String(detail.mac || '').toLowerCase() : 'detail:closed',
        detail ? detail.tab || 'overview' : 'overview',
        page.connectionOptionsOpen ? `options:${page.connectionOptionTab || 'filter'}` : 'options:closed',
        fingerprint ? `fingerprint:${fingerprint.category || ''}:${fingerprint.vendor || ''}:${fingerprint.query || ''}` : 'fingerprint:closed'
      ].join('|');
    }

    const SCROLL_SELECTORS = [
      ['drawer', '.client-detail-drawer-body'],
      ['stage', '.client-detail-stage'],
      ['clientTable', '.client-table-wrap .dwrt-kit-table-scroll'],
      ['connectionTable', '.client-connection-table-scroll'],
      ['protocolTable', '.client-protocol-table-scroll'],
      ['connectionOptions', '.client-connection-options-body'],
      ['controlForm', '.client-control-form'],
      ['fingerprintContent', '.client-fingerprint-content'],
      ['fingerprintGrid', '.client-fingerprint-grid']
    ];

    const SCROLL_SELECTOR_MAP = Object.fromEntries(SCROLL_SELECTORS);

    function captureDetailScrollState() {
      if (!root) return null;
      const state = {};
      SCROLL_SELECTORS.forEach(([key, selector]) => {
        const node = root.querySelector(selector);
        if (!node) return;
        state[key] = { top: node.scrollTop || 0, left: node.scrollLeft || 0 };
      });
      return Object.keys(state).length ? state : null;
    }

    function rememberScrollState(key = detailRenderKey(), state = captureDetailScrollState()) {
      if (!page || !key || !state) return;
      if (!page.scrollState) page.scrollState = {};
      page.scrollState[key] = state;
    }

    function restoreDetailScrollState(state) {
      if (!state || !root || !page) return;
      const restoreToken = page.scrollRestoreToken || 0;
      const apply = () => {
        if (!page || page.scrollRestoreToken !== restoreToken) return;
        Object.entries(state).forEach(([key, value]) => {
          const node = root.querySelector(SCROLL_SELECTOR_MAP[key]);
          if (!node || !value) return;
          const maxTop = Math.max(0, node.scrollHeight - node.clientHeight);
          const maxLeft = Math.max(0, node.scrollWidth - node.clientWidth);
          node.scrollTop = Math.min(maxTop, Math.max(0, value.top || 0));
          node.scrollLeft = Math.min(maxLeft, Math.max(0, value.left || 0));
        });
      };
      window.requestAnimationFrame(() => {
        apply();
        window.setTimeout(apply, 0);
        window.setTimeout(apply, 80);
        window.setTimeout(apply, 180);
        window.setTimeout(apply, 360);
      });
    }


    function readStored(key, fallback) {
      try {
        const value = localStorage.getItem(key);
        return value === null ? fallback : value;
      } catch (_) {
        return fallback;
      }
    }

    function writeStored(key, value) {
      try { localStorage.setItem(key, value); } catch (_) {}
    }

    function parseClientColumnOrder() {
      try {
        const raw = JSON.parse(readStored(CLIENT_COLUMN_ORDER_KEY, '[]') || '[]');
        if (Array.isArray(raw) && raw.length) {
          const known = new Set(CLIENT_TABLE_COLUMN_KEYS);
          const ordered = raw.map((key) => firstText(key)).filter((key) => known.has(key));
          CLIENT_TABLE_COLUMN_KEYS.forEach((key) => { if (!ordered.includes(key)) ordered.push(key); });
          return ordered;
        }
      } catch (_) {}
      return CLIENT_TABLE_COLUMN_KEYS.slice();
    }

    function saveClientColumnOrder() {
      if (!page || !Array.isArray(page.columnOrder)) return;
      writeStored(CLIENT_COLUMN_ORDER_KEY, JSON.stringify(page.columnOrder));
    }

    function orderedClientColumns() {
      const known = new Set(CLIENT_TABLE_COLUMN_KEYS);
      const byKey = new Map(CLIENT_TABLE_COLUMNS.map((column) => [column.key, column]));
      const order = Array.isArray(page && page.columnOrder) ? page.columnOrder : CLIENT_TABLE_COLUMN_KEYS;
      const keys = order.map((key) => firstText(key)).filter((key) => known.has(key));
      CLIENT_TABLE_COLUMN_KEYS.forEach((key) => { if (!keys.includes(key)) keys.push(key); });
      return keys.map((key) => byKey.get(key)).filter(Boolean);
    }

    function clientColumnByKey(key) {
      return CLIENT_TABLE_COLUMNS.find((column) => column.key === key) || null;
    }

    function parseOverviewLegend() {
      let parsed = null;
      try { parsed = JSON.parse(readStored(OVERVIEW_LEGEND_KEY, '{}') || '{}'); } catch (_) { parsed = {}; }
      return {
        up: parsed.up !== false,
        down: parsed.down !== false,
        connections: parsed.connections !== false
      };
    }

    function saveOverviewLegend() {
      if (!page || !page.overviewLegend) return;
      writeStored(OVERVIEW_LEGEND_KEY, JSON.stringify(page.overviewLegend));
    }

    function parseProtocolLegend() {
      let parsed = null;
      try { parsed = JSON.parse(readStored(PROTOCOL_LEGEND_KEY, '{}') || '{}'); } catch (_) { parsed = {}; }
      const state = {};
      PROTOCOL_CATEGORIES.forEach((category) => {
        state[category.key] = parsed[category.key] !== false;
      });
      return state;
    }

    function saveProtocolLegend() {
      if (!page || !page.protocolLegend) return;
      writeStored(PROTOCOL_LEGEND_KEY, JSON.stringify(page.protocolLegend));
    }

    function parseSort() {
      try {
        const raw = JSON.parse(readStored(SORT_KEY, ''));
        if (raw && raw.key) return raw;
      } catch (_) {}
      return { key: 'name', direction: 'asc' };
    }

    function normalizeClientColumnFilters(raw) {
      const source = raw && typeof raw === 'object' ? raw : {};
      const next = {};
      Object.keys(CLIENT_COLUMN_FILTERS).forEach((key) => {
        const item = source[key];
        if (!item || typeof item !== 'object') return;
        const value = Number(item.value);
        if (!Number.isFinite(value) || value < 0) return;
        const mode = item.mode === 'exclude' ? 'exclude' : 'include';
        const op = ['gte', 'lte', 'eq', 'gt', 'lt'].includes(item.op) ? item.op : 'gte';
        const unit = firstText(item.unit);
        next[key] = { mode, op, value, unit };
      });
      return next;
    }

    function parseFilters() {
      try {
        const raw = JSON.parse(readStored(FILTER_KEY, ''));
        if (raw && typeof raw === 'object') {
          return {
            deviceTypes: Array.isArray(raw.deviceTypes) ? raw.deviceTypes.map(String) : [],
            ip: firstText(raw.ip),
            ipExclude: Boolean(raw.ipExclude),
            keyword: firstText(raw.keyword),
            vendor: firstText(raw.vendor),
            vlan: firstText(raw.vlan),
            ipVersion: firstText(raw.ipVersion),
            minConnections: firstNumber(raw.minConnections),
            minUpGb: firstNumber(raw.minUpGb),
            minDownGb: firstNumber(raw.minDownGb),
            columnFilters: normalizeClientColumnFilters(raw.columnFilters),
            showOnline: raw.showOnline !== false,
            showOffline: raw.showOffline !== false
          };
        }
      } catch (_) {}
      return { deviceTypes: [], ip: '', ipExclude: false, keyword: '', vendor: '', vlan: '', ipVersion: '', minConnections: 0, minUpGb: 0, minDownGb: 0, columnFilters: {}, showOnline: true, showOffline: true };
    }

    function saveFilters() {
      writeStored(FILTER_KEY, JSON.stringify(page.filters));
    }

    function parseConnectionFilters() {
      try {
        const raw = JSON.parse(readStored(CONNECTION_FILTER_KEY, ''));
        if (raw && typeof raw === 'object') {
          return {
            proto: firstText(raw.proto, 'all').toLowerCase() || 'all',
            line: firstText(raw.line, 'all') || 'all'
          };
        }
      } catch (_) {}
      return { proto: 'all', line: 'all' };
    }

    function saveConnectionFilters() {
      writeStored(CONNECTION_FILTER_KEY, JSON.stringify(page.connectionFilters || { proto: 'all', line: 'all' }));
    }

    function parseConnectionColumns() {
      try {
        const raw = JSON.parse(readStored(CONNECTION_COLUMN_KEY, ''));
        if (Array.isArray(raw)) {
          const allowed = new Set(CONNECTION_COLUMNS.map((column) => column.key));
          const columns = raw.map(String).filter((key) => allowed.has(key));
          if (columns.length) return columns;
        }
      } catch (_) {}
      return CONNECTION_DEFAULT_COLUMNS.slice();
    }

    function saveConnectionColumns() {
      const columns = Array.isArray(page.connectionColumns) && page.connectionColumns.length ? page.connectionColumns : CONNECTION_DEFAULT_COLUMNS;
      writeStored(CONNECTION_COLUMN_KEY, JSON.stringify(columns));
    }

    function listFrom(payload) {
      if (Array.isArray(payload)) return payload;
      if (!payload || typeof payload !== 'object') return [];
      for (const key of ['clients', 'users', 'active_users', 'items', 'rows', 'list', 'records', 'data']) {
        if (Array.isArray(payload[key])) return payload[key];
      }
      return [];
    }

    function isOnline(client) {
      const value = client && client.online;
      if (value === false || value === 0 || value === '0') return false;
      const status = String(firstText(client && client.status, client && client.state)).toLowerCase();
      const neighborState = String(firstText(client && client.neighbor_state, client && client.neigh_state, client && client.arp_state, client && client.ipv6_neighbor_state)).toLowerCase();
      if (['offline', 'down', 'inactive', '离线', 'failed', 'fail', 'incomplete'].includes(status)) return false;
      if (['failed', 'fail', 'incomplete'].includes(neighborState)) return false;
      const now = Math.floor(Date.now() / 1000);
      const lastSeen = firstNumber(client && client.last_seen, client && client.lastSeen, client && client.last_seen_ts, client && client.updated_at);
      const hasRuntime = Number(client && (client.up_rate || client.down_rate || client.tx_rate || client.rx_rate || client.connections || client.conn_count || client.active_connections)) > 0;
      if (value === true || value === 1 || value === '1' || ['online', 'up', 'active', '在线', 'connected'].includes(status)) {
        if (lastSeen > 0 && now - lastSeen > 240 && !hasRuntime) return false;
        return true;
      }
      return hasRuntime;
    }

    function userName(client = {}) {
      return firstText(client.remark, client.nickname, client.custom_name, client.display_name, client.hostname, client.name, client.ip, client.ipv4, client.mac, '--');
    }

    function usefulInfoText(...values) {
      const text = firstText(...values);
      if (!text) return '';
      const normalized = String(text).trim().toLowerCase();
      return ['--', '-', '--/--', 'null', 'undefined', 'n/a', 'na'].includes(normalized) ? '' : text;
    }

    function sameInfoText(a, b) {
      const left = usefulInfoText(a).replace(/\s+/g, ' ').trim().toLowerCase();
      const right = usefulInfoText(b).replace(/\s+/g, ' ').trim().toLowerCase();
      return Boolean(left && right && left === right);
    }

    function deviceType(client = {}) {
      return firstText(client.type, client.device_type, client.category, client.link_type, client.os_name, '');
    }

    function vendorType(client = {}) {
      const fingerprint = client.fingerprint && typeof client.fingerprint === 'object' ? client.fingerprint : {};
      const vendor = firstText(client.vendor_name, client.vendor, client.manufacturer, client.brand, fingerprint.vendor, '--');
      const model = firstText(client.model, client.device_model, client.device_name, client.model_name, fingerprint.model, '');
      const type = firstText(deviceType(client), model, fingerprint.device_type, '--');
      return `${vendor}/${type}`;
    }

    function brandSlugFromText(...values) {
      const text = values.map((value) => firstText(value)).filter(Boolean).join(' ').trim();
      if (!text) return '';
      for (const [pattern, slug] of BRAND_ALIASES) {
        if (pattern.test(text) && BRAND_LOGO_SLUGS.has(slug)) return slug;
      }
      const normalized = text
        .normalize('NFKD')
        .replace(/[\u0300-\u036f]/g, '')
        .toLowerCase()
        .replace(/&/g, ' and ')
        .replace(/\b(incorporated|inc|corporation|corp|company|co|ltd|limited|group|technology|technologies|communication|communications|electronics|computer|systems|solutions|gmbh|llc|plc)\b/g, ' ')
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
      if (!normalized) return '';
      if (BRAND_LOGO_SLUGS.has(normalized)) return normalized;
      const compacted = normalized.replace(/-/g, '');
      for (const slug of BRAND_LOGO_SLUGS) {
        if (slug.replace(/-/g, '') === compacted) return slug;
      }
      return '';
    }

    function brandLogoUrl(...values) {
      const shared = window.DWRT_DEVICE_IMAGES;
      if (shared && typeof shared.brandSlug === 'function') {
        const slug = shared.brandSlug(...values);
        if (slug) return `${BRAND_LOGO_BASE}${slug}.svg`;
      }
      const slug = brandSlugFromText(...values);
      return slug ? `${BRAND_LOGO_BASE}${slug}.svg` : '';
    }

    function plainObject(value) {
      return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
    }

    function macKey(...values) {
      return String(firstText(...values)).trim().toLowerCase();
    }

    function trimRealtimeList(list, max = 96) {
      return asArray(list).slice(-max);
    }

    function mergeListUniqueBySignature(existing = [], incoming = [], max = 240) {
      const merged = [];
      const seen = new Set();
      const push = (item) => {
        if (item === undefined || item === null || item === '') return;
        const signature = typeof item === 'object'
          ? JSON.stringify(item, Object.keys(item).sort())
          : String(item);
        if (seen.has(signature)) return;
        seen.add(signature);
        merged.push(item);
      };
      asArray(existing).forEach(push);
      asArray(incoming).forEach(push);
      return merged.slice(-max);
    }

    function fingerprintPickerOpen() {
      return Boolean(page && page.fingerprint && page.fingerprint.open);
    }

    function renderOrDefer(reason = '') {
      if (!page || !page.active) return;
      if (String(reason || '').startsWith('protocol-') && patchProtocolDetailPanel()) return;
      if (fingerprintPickerOpen()) {
        if (reason === 'fingerprint' && patchFingerprintPicker()) return;
        if (reason !== 'fingerprint') {
          page.renderAfterFingerprint = true;
          return;
        }
      }
      if (page.controlEditorOpen && !String(reason || '').startsWith('control-')) {
        page.renderAfterControl = true;
        return;
      }
      render();
    }

    function patchDetailChrome() {
      if (!root || !page || !page.detail || !page.detail.open) return false;
      const layer = root.querySelector('.client-detail-layer');
      const context = currentDetailContext();
      if (!layer || !context) return false;
      const name = userName(context.merged);
      const type = vendorType(context.merged);
      setTextIfChanged(layer.querySelector('.client-detail-modal-head span'), name);
      setTextIfChanged(layer.querySelector('.client-detail-identity strong'), name);
      setTextIfChanged(layer.querySelector('.client-detail-identity span'), type);
      const status = layer.querySelector('[data-client-online-status]');
      if (status) {
        const next = statusBadgeMarkup(context.merged.online ? '在线' : '离线', context.merged.online ? 'success' : 'error', { className: 'client-online-status' });
        const nextMarkup = next.replace('class="', 'data-client-online-status class="');
        if (next && status.outerHTML !== nextMarkup) status.outerHTML = nextMarkup;
      }
      return true;
    }

    function rateCacheKey(mac, direction) {
      return `${String(mac || '').toLowerCase()}:${direction}`;
    }

    function heldRate(mac, direction, incoming, fallback = 0) {
      const value = Number(incoming);
      const now = Date.now();
      const cache = page.rateHoldCache || (page.rateHoldCache = new Map());
      const key = rateCacheKey(mac, direction);
      if (Number.isFinite(value) && value > 0) {
        cache.set(key, { value, at: now });
        return value;
      }
      const previous = cache.get(key);
      if (previous && now - previous.at <= RATE_HOLD_MS) return previous.value;
      return Number(fallback) || 0;
    }

    function heldClientRate(client, row, direction) {
      const mac = firstText(row && (row.mac || row.client_mac || row.id || row.node_id), client && client.mac);
      const incoming = direction === 'up'
        ? firstNumber(row && row.up_rate, row && row.tx_rate, row && row.rate_up, row && row['tx_bytes-r'])
        : firstNumber(row && row.down_rate, row && row.rx_rate, row && row.rate_down, row && row['rx_bytes-r']);
      const fallback = direction === 'up' ? client && client.upRate : client && client.downRate;
      return heldRate(mac, direction, incoming, fallback);
    }


    function metricNumber(...values) {
      for (const value of values) {
        if (value === undefined || value === null || value === '') continue;
        const num = Number(value);
        if (Number.isFinite(num)) return num;
      }
      return 0;
    }

    function columnFilterFactor(unit, kind) {
      const raw = firstText(unit).trim();
      const normalized = raw.toLowerCase();
      if (kind === 'count') return 1;
      if (kind === 'rate') {
        if (raw === 'GB/s') return 1024 * 1024 * 1024;
        if (raw === 'MB/s') return 1024 * 1024;
        if (raw === 'KB/s') return 1024;
        if (raw === 'B/s') return 1;
        if (normalized === 'gbps') return 1000 * 1000 * 1000 / 8;
        if (normalized === 'mbps') return 1000 * 1000 / 8;
        if (normalized === 'kbps') return 1000 / 8;
        if (normalized === 'bps') return 1 / 8;
        return 1;
      }
      if (normalized === 'tb') return 1024 * 1024 * 1024 * 1024;
      if (normalized === 'gb') return 1024 * 1024 * 1024;
      if (normalized === 'mb') return 1024 * 1024;
      if (normalized === 'kb') return 1024;
      return 1;
    }

    function columnFilterThreshold(filter = {}, config = {}) {
      return Math.max(0, Number(filter.value) || 0) * columnFilterFactor(filter.unit, config.unit);
    }

    function compareColumnFilterValue(actual, filter = {}, config = {}) {
      const value = Math.max(0, Number(actual) || 0);
      const threshold = columnFilterThreshold(filter, config);
      const epsilon = Math.max(1e-9, threshold * 0.000001);
      if (filter.op === 'lte') return value <= threshold + epsilon;
      if (filter.op === 'eq') return Math.abs(value - threshold) <= epsilon;
      if (filter.op === 'gt') return value > threshold;
      if (filter.op === 'lt') return value < threshold;
      return value >= threshold;
    }

    function clientColumnFilterValue(client = {}, key = '') {
      const config = CLIENT_COLUMN_FILTERS[key];
      if (!config) return 0;
      return familyMetric(client, 'ipv4', config.metric);
    }

    function clientMatchesColumnFilters(client = {}) {
      const filters = page && page.filters && page.filters.columnFilters || {};
      return Object.entries(filters).every(([key, filter]) => {
        const config = CLIENT_COLUMN_FILTERS[key];
        if (!config || !filter) return true;
        const hit = compareColumnFilterValue(clientColumnFilterValue(client, key), filter, config);
        return filter.mode === 'exclude' ? !hit : hit;
      });
    }

    function familyMetric(client = {}, family = 'ipv4', metric = 'upRate') {
      if (family === 'ipv6') {
        if (metric === 'upRate') return metricNumber(client.ipv6_up_rate, client.up_rate_ipv6, client.v6_up_rate, client.up_rate_v6, client.ip6_up_rate, client.tx_rate_ipv6, client.ipv6_tx_rate, client.v6_tx_rate, client.ipv6_upload_rate, client.upload_rate_ipv6);
        if (metric === 'downRate') return metricNumber(client.ipv6_down_rate, client.down_rate_ipv6, client.v6_down_rate, client.down_rate_v6, client.ip6_down_rate, client.rx_rate_ipv6, client.ipv6_rx_rate, client.v6_rx_rate, client.ipv6_download_rate, client.download_rate_ipv6);
        if (metric === 'connections') return metricNumber(client.ipv6_connections, client.connections_ipv6, client.v6_connections, client.connections_v6, client.ip6_connections, client.ipv6_conn_count, client.conn_count_ipv6, client.v6_conn_count, client.ipv6_conntrack_count, client.conntrack_count_ipv6);
        if (metric === 'upBytes') return metricNumber(client.ipv6_up_bytes, client.up_bytes_ipv6, client.v6_up_bytes, client.up_bytes_v6, client.ip6_up_bytes, client.ipv6_tx_bytes, client.tx_bytes_ipv6, client.ipv6_today_up_bytes, client.today_up_ipv6);
        if (metric === 'downBytes') return metricNumber(client.ipv6_down_bytes, client.down_bytes_ipv6, client.v6_down_bytes, client.down_bytes_v6, client.ip6_down_bytes, client.ipv6_rx_bytes, client.rx_bytes_ipv6, client.ipv6_today_down_bytes, client.today_down_ipv6);
        return 0;
      }
      if (metric === 'upRate') return metricNumber(client.ipv4_up_rate, client.up_rate_ipv4, client.v4_up_rate, client.upRate, client.up_rate, client.tx_rate, client.rate_up, client.upload_rate, client['tx_bytes-r'], client.tx_bytes_r, client.up_bytes_per_sec);
      if (metric === 'downRate') return metricNumber(client.ipv4_down_rate, client.down_rate_ipv4, client.v4_down_rate, client.downRate, client.down_rate, client.rx_rate, client.rate_down, client.download_rate, client['rx_bytes-r'], client.rx_bytes_r, client.down_bytes_per_sec);
      if (metric === 'connections') return metricNumber(client.ipv4_connections, client.connections_ipv4, client.v4_connections, client.connections, client.conn_count, client.conntrack_count, client.active_connections);
      if (metric === 'upBytes') return metricNumber(client.ipv4_up_bytes, client.up_bytes_ipv4, client.v4_up_bytes, client.upBytes, client.up_bytes, client.today_up_bytes, client.today_up, client.tx_bytes);
      if (metric === 'downBytes') return metricNumber(client.ipv4_down_bytes, client.down_bytes_ipv4, client.v4_down_bytes, client.downBytes, client.down_bytes, client.today_down_bytes, client.today_down, client.rx_bytes);
      return 0;
    }

    function runtimeFamilyPatch(row = {}) {
      const patch = {};
      const ipv6UpRate = metricNumber(row.ipv6_up_rate, row.up_rate_ipv6, row.v6_up_rate, row.up_rate_v6, row.ip6_up_rate, row.tx_rate_ipv6, row.ipv6_tx_rate, row.v6_tx_rate);
      const ipv6DownRate = metricNumber(row.ipv6_down_rate, row.down_rate_ipv6, row.v6_down_rate, row.down_rate_v6, row.ip6_down_rate, row.rx_rate_ipv6, row.ipv6_rx_rate, row.v6_rx_rate);
      const ipv6Connections = metricNumber(row.ipv6_connections, row.connections_ipv6, row.v6_connections, row.connections_v6, row.ip6_connections, row.ipv6_conn_count, row.conn_count_ipv6, row.v6_conn_count);
      const ipv6UpBytes = metricNumber(row.ipv6_up_bytes, row.up_bytes_ipv6, row.v6_up_bytes, row.up_bytes_v6, row.ip6_up_bytes, row.ipv6_tx_bytes, row.tx_bytes_ipv6);
      const ipv6DownBytes = metricNumber(row.ipv6_down_bytes, row.down_bytes_ipv6, row.v6_down_bytes, row.down_bytes_v6, row.ip6_down_bytes, row.ipv6_rx_bytes, row.rx_bytes_ipv6);
      if (ipv6UpRate) patch.ipv6_up_rate = ipv6UpRate;
      if (ipv6DownRate) patch.ipv6_down_rate = ipv6DownRate;
      if (ipv6Connections) patch.ipv6_connections = ipv6Connections;
      if (ipv6UpBytes) patch.ipv6_up_bytes = ipv6UpBytes;
      if (ipv6DownBytes) patch.ipv6_down_bytes = ipv6DownBytes;
      return patch;
    }

    function normalizeOnlineSeconds(value, hint = 'duration') {
      const raw = Number(value);
      if (!Number.isFinite(raw) || raw <= 0) return 0;
      const now = Math.floor(Date.now() / 1000);
      const seconds = raw > 100000000000 ? Math.floor(raw / 1000) : Math.floor(raw);
      const unix = seconds >= 946684800 && seconds <= now + 2592000;
      if (unix || hint === 'time') return Math.max(0, now - seconds);
      return seconds > 5 * 365 * 86400 ? 0 : seconds;
    }

    function onlineDuration(client = {}) {
      for (const key of ['online_duration', 'online_seconds', 'connected_seconds', 'session_duration', 'duration']) {
        const value = normalizeOnlineSeconds(client[key], 'duration');
        if (value > 0) return value;
      }
      for (const key of ['online_time', 'assoc_time']) {
        const value = normalizeOnlineSeconds(client[key], 'duration');
        if (value > 0) return value;
      }
      if (!isOnline(client)) return 0;
      for (const key of ['online_since', 'connected_at', 'session_started_at', 'lease_started_at', 'start_time']) {
        const value = normalizeOnlineSeconds(client[key], 'time');
        if (value > 0) return value;
      }
      return 0;
    }

    function onlineDurationLabel(client = {}) {
      if (!client || !client.online) return '离线';
      return client.onlineDuration > 0 ? formatUptime(client.onlineDuration) : '--';
    }

    function compact(value, max = 24) {
      const text = firstText(value);
      if (!text || text.length <= max) return text;
      const head = Math.max(8, Math.floor(max * 0.55));
      const tail = Math.max(5, max - head - 1);
      return `${text.slice(0, head)}…${text.slice(-tail)}`;
    }

    function ipv6Expand(addr) {
      const text = firstText(addr).split('%')[0].toLowerCase();
      if (!text || !text.includes(':')) return [];
      const parts = text.split('::');
      if (parts.length > 2) return [];
      const left = parts[0] ? parts[0].split(':').filter(Boolean) : [];
      const right = parts[1] ? parts[1].split(':').filter(Boolean) : [];
      const fill = Math.max(0, 8 - left.length - right.length);
      const groups = [...left, ...Array(fill).fill('0'), ...right];
      if (groups.length !== 8) return [];
      return groups.map((part) => Number.parseInt(part || '0', 16)).filter((num) => Number.isFinite(num));
    }

    function ipv6InPrefix(addr, prefix) {
      const [base, bitsRaw] = firstText(prefix).split('/');
      const bits = Math.max(0, Math.min(128, Number(bitsRaw) || 0));
      if (!base || !bits) return false;
      const a = ipv6Expand(addr);
      const b = ipv6Expand(base);
      if (a.length !== 8 || b.length !== 8) return false;
      let remain = bits;
      for (let i = 0; i < 8; i += 1) {
        if (remain <= 0) return true;
        const check = Math.min(16, remain);
        const mask = check === 16 ? 0xffff : (0xffff << (16 - check)) & 0xffff;
        if ((a[i] & mask) !== (b[i] & mask)) return false;
        remain -= check;
      }
      return true;
    }

    function ipv6Parts(client = {}) {
      const addresses = []
        .concat(asArray(client.ipv6_addrs))
        .concat(asArray(client.ipv6_addresses))
        .concat(asArray(client.ip6_addrs))
        .concat(asArray(client.ipv6_list))
        .filter(Boolean);
      const explicitGlobal = firstText(client.ipv6_global, client.global_ipv6, client.public_ipv6, client.wan_ipv6);
      const rawLocal = firstText(client.local_ipv6, client.ipv6_local);
      const linkLocal = firstText(
        client.ipv6_link_local,
        client.link_local_ipv6,
        client.ip6_link_local,
        /^fe80:/i.test(rawLocal) ? rawLocal : '',
        addresses.find((addr) => /^fe80:/i.test(String(addr)))
      );
      const nonLink = addresses.filter((addr) => !/^fe80:/i.test(String(addr)));
      const prefix = firstText(client.ipv6_prefix, client.delegated_prefix, client.lan_ipv6_prefix, client.prefix_ipv6);
      const inferredFromPrefix = prefix ? nonLink.find((addr) => ipv6InPrefix(addr, prefix)) : '';
      const lan = firstText(
        client.ipv6_lan,
        client.lan_ipv6,
        /^fe80:/i.test(rawLocal) ? '' : rawLocal,
        inferredFromPrefix,
        explicitGlobal ? nonLink.find((addr) => String(addr) !== String(explicitGlobal)) : nonLink[0]
      );
      const global = firstText(
        explicitGlobal,
        client.ipv6,
        client.ip6,
        client.ipv6_addr,
        client.ipv6_address,
        addresses.find((addr) => !/^fe80:/i.test(String(addr)) && String(addr) !== String(lan))
      );
      return { local: firstText(linkLocal, rawLocal, lan), linkLocal, lan, global };
    }

    function totalUp(client = {}) {
      return firstNumber(client.up_bytes, client.today_up_bytes, client.today_up, client.tx_bytes);
    }

    function totalDown(client = {}) {
      return firstNumber(client.down_bytes, client.today_down_bytes, client.today_down, client.rx_bytes);
    }

    function deviceTypeIconKey(client = {}) {
      const text = [
        deviceType(client),
        client.type,
        client.device_type,
        client.client_type,
        client.model,
        client.device_model,
        client.device_name,
        client.name,
        client.hostname,
        client.fingerprint && client.fingerprint.device_type
      ].map((value) => firstText(value).toLowerCase()).filter(Boolean).join(' ');
      if (/router|gateway|firewall|access point|\bap\b|switch|network|路由|网关|交换机/.test(text)) return 'router';
      if (/nas|storage|synology|qnap|truenas|freenas|unraid|存储/.test(text)) return 'nas';
      if (/phone|iphone|android|smartphone|手机/.test(text)) return 'phone';
      if (/tablet|ipad|平板/.test(text)) return 'tablet';
      if (/watch|wearable|手表|可穿戴/.test(text)) return 'wearable';
      if (/tv|television|电视/.test(text)) return 'tv';
      if (/printer|打印/.test(text)) return 'printer';
      if (/camera|摄像/.test(text)) return 'camera';
      if (/game|xbox|playstation|switch/.test(text)) return 'game';
      if (/computer|pc|desktop|laptop|macbook|windows|电脑/.test(text)) return 'computer';
      return 'unknown';
    }

    function deviceTypeIcon(client = {}) {
      const key = deviceTypeIconKey(client);
      if (key === 'router') {
        return `<span class="client-device-type-icon is-router" aria-hidden="true"><svg viewBox="0 0 48 48"><path d="M10 17c8-7 20-7 28 0"/><path d="M15.5 23c5-4.2 12-4.2 17 0"/><path d="M21 29c2-1.6 4-1.6 6 0"/><circle cx="24" cy="35" r="2.4"/></svg></span>`;
      }
      if (key === 'nas') {
        return `<span class="client-device-type-icon is-nas" aria-hidden="true"><svg viewBox="0 0 48 48"><rect x="11" y="8" width="26" height="32" rx="4"/><path d="M16 17h16M16 24h16"/><circle cx="18" cy="33" r="2"/><circle cx="30" cy="33" r="2"/></svg></span>`;
      }
      if (key === 'computer') {
        return `<span class="client-device-type-icon is-computer" aria-hidden="true"><svg viewBox="0 0 48 48"><rect x="8" y="11" width="32" height="22" rx="3"/><path d="M19 38h10M24 33v5"/></svg></span>`;
      }
      return `<span class="client-device-fallback">${escapeHtml(userName(client).charAt(0).toUpperCase())}</span>`;
    }

    function explicitClientImageSource(client = {}) {
      const fingerprint = client.fingerprint && typeof client.fingerprint === 'object' ? client.fingerprint : {};
      const custom = firstText(
        client.custom_image_path,
        client.custom_icon,
        client.override_image,
        client.override_icon,
        fingerprint.custom_image_path
      );
      return custom ? { src: custom, priority: 100 } : null;
    }

    function brandClientImageSource(client = {}) {
      const fingerprint = client.fingerprint && typeof client.fingerprint === 'object' ? client.fingerprint : {};
      const src = brandLogoUrl(
        client.vendor_name, client.vendor, client.manufacturer, client.brand,
        client.model, client.device_name, client.name, client.hostname,
        fingerprint.vendor_name, fingerprint.vendor, fingerprint.manufacturer
      );
      return src ? { src, priority: 60 } : null;
    }

    function clientImageSignature(client = {}) {
      const shared = window.DWRT_DEVICE_IMAGES;
      if (shared && typeof shared.resolve === 'function') {
        const resolved = shared.resolve(client);
        if (resolved && resolved.src) {
          return { kind: 'image', value: resolved.src, priority: resolved.priority || 50 };
        }
      }
      const explicit = explicitClientImageSource(client);
      if (explicit && explicit.src) return { kind: 'image', value: explicit.src, priority: explicit.priority };
      const brand = brandClientImageSource(client);
      if (brand && brand.src) return { kind: 'image', value: brand.src, priority: brand.priority };
      return { kind: 'type', value: deviceTypeIconKey(client), priority: 10 };
    }

    function stableClientImageSignature(client = {}) {
      const mac = macKey(client.mac, client.client_mac, client.hwaddr);
      const signature = clientImageSignature(client);
      const cache = page && (page.clientImageCache || (page.clientImageCache = new Map()));
      if (!mac || !cache) return signature;
      const cached = cache.get(mac);
      if (!cached || Number(signature.priority || 0) > Number(cached.priority || 0) || (
        Number(signature.priority || 0) === Number(cached.priority || 0) &&
        (signature.kind !== cached.kind || signature.value !== cached.value)
      )) {
        cache.set(mac, signature);
        return signature;
      }
      return cached;
    }

    function setClientImageOverride(mac, src) {
      const key = macKey(mac);
      const value = firstText(src);
      if (!key || !value) return;
      const cache = page && (page.clientImageCache || (page.clientImageCache = new Map()));
      if (cache) cache.set(key, { kind: 'image', value, priority: 120 });
      if (window.DWRT_DEVICE_IMAGES && typeof window.DWRT_DEVICE_IMAGES.setOverride === 'function') {
        window.DWRT_DEVICE_IMAGES.setOverride(key, value);
      }
    }

    function clientImage(client = {}) {
      const stable = stableClientImageSignature(client);
      if (stable.kind === 'image' && stable.value) {
        return `<img class="client-device-photo" src="${escapeHtml(stable.value)}" alt="">`;
      }
      return deviceTypeIcon({ ...client, type: stable.value, device_type: stable.value });
    }

    function profileClient(client = {}, profile = {}) {
      const current = profile.current && typeof profile.current === 'object' ? profile.current : {};
      const basic = profile.basic && typeof profile.basic === 'object' ? profile.basic : {};
      const override = profile.override && typeof profile.override === 'object' ? profile.override : {};
      const custom = profile.custom && typeof profile.custom === 'object' ? profile.custom : {};
      const fingerprint = profile.fingerprint && typeof profile.fingerprint === 'object' ? profile.fingerprint : {};
      const draft = customDraftFor(client);
      return normalizeClient({ ...client, ...basic, ...current, ...fingerprint, ...override, ...custom, ...draft });
    }

    function normalizeClient(client = {}, index = 0) {
      const fingerprint = client.fingerprint && typeof client.fingerprint === 'object' ? client.fingerprint : {};
      const mac = firstText(client.mac, client.client_mac, client.hwaddr, `client-${index + 1}`);
      const normalized = {
        ...client,
        fingerprint,
        id: firstText(client.id, client.client_id, mac),
        mac,
        name: userName(client),
        ip: firstText(client.ip, client.ipv4, client.ipaddr, client.client_ip),
        ipv6_addrs: asArray(client.ipv6_addrs).length ? client.ipv6_addrs : asArray(client.ipv6_addresses),
        ipv6_global: firstText(client.ipv6_global, client.global_ipv6, client.public_ipv6, client.wan_ipv6, client.ipv6, client.ipv6_addr, client.ipv6_address, inferIpv6FromMac(mac)),
        global_ipv6: firstText(client.global_ipv6, client.ipv6_global, client.public_ipv6, client.wan_ipv6, client.ipv6, client.ipv6_addr, client.ipv6_address, inferIpv6FromMac(mac)),
        ipv6_lan: firstText(client.ipv6_lan, client.lan_ipv6, client.local_ipv6),
        lan_ipv6: firstText(client.lan_ipv6, client.ipv6_lan, client.local_ipv6),
        local_ipv6: firstText(client.local_ipv6, client.ipv6_lan, client.lan_ipv6, client.ipv6_link_local),
        ipv6_link_local: firstText(client.ipv6_link_local, client.link_local_ipv6, client.ip6_link_local),
        link_local_ipv6: firstText(client.link_local_ipv6, client.ipv6_link_local, client.ip6_link_local),
        ipv6_prefix: firstText(client.ipv6_prefix, client.delegated_prefix, client.lan_ipv6_prefix, client.prefix_ipv6),
        vendorType: vendorType(client),
        type: firstText(deviceType(client), fingerprint.device_type),
        upRate: heldRate(mac, 'up', firstNumber(client.up_rate, client.tx_rate, client.rate_up, client.upload_rate, client['tx_bytes-r'], client.tx_bytes_r, client.up_bytes_per_sec), client.upRate),
        downRate: heldRate(mac, 'down', firstNumber(client.down_rate, client.rx_rate, client.rate_down, client.download_rate, client['rx_bytes-r'], client.rx_bytes_r, client.down_bytes_per_sec), client.downRate),
        ipv6_up_rate: metricNumber(client.ipv6_up_rate, client.up_rate_ipv6, client.v6_up_rate, client.up_rate_v6, client.ip6_up_rate, client.tx_rate_ipv6, client.ipv6_tx_rate, client.v6_tx_rate),
        ipv6_down_rate: metricNumber(client.ipv6_down_rate, client.down_rate_ipv6, client.v6_down_rate, client.down_rate_v6, client.ip6_down_rate, client.rx_rate_ipv6, client.ipv6_rx_rate, client.v6_rx_rate),
        ipv6_connections: metricNumber(client.ipv6_connections, client.connections_ipv6, client.v6_connections, client.connections_v6, client.ip6_connections, client.ipv6_conn_count, client.conn_count_ipv6, client.v6_conn_count),
        ipv6_up_bytes: metricNumber(client.ipv6_up_bytes, client.up_bytes_ipv6, client.v6_up_bytes, client.up_bytes_v6, client.ip6_up_bytes, client.ipv6_tx_bytes, client.tx_bytes_ipv6, client.ipv6_today_up_bytes, client.today_up_ipv6),
        ipv6_down_bytes: metricNumber(client.ipv6_down_bytes, client.down_bytes_ipv6, client.v6_down_bytes, client.down_bytes_v6, client.ip6_down_bytes, client.ipv6_rx_bytes, client.rx_bytes_ipv6, client.ipv6_today_down_bytes, client.today_down_ipv6),
        connections: firstNumber(client.connections, client.conn_count, client.conntrack_count, client.active_connections),
        upBytes: totalUp(client),
        downBytes: totalDown(client),
        onlineDuration: onlineDuration(client),
        online: isOnline(client)
      };
      return normalized;
    }

    function filteredClients() {
      const search = firstText(page.search, page.filters.keyword).trim().toLowerCase();
      const ipFilter = page.filters.ip.trim().toLowerCase();
      const vendorFilter = firstText(page.filters.vendor).trim().toLowerCase();
      const vlanFilter = firstText(page.filters.vlan).trim().toLowerCase();
      const ipVersion = firstText(page.filters.ipVersion).trim().toLowerCase();
      const minConnections = Number(page.filters.minConnections) || 0;
      const minUpBytes = (Number(page.filters.minUpGb) || 0) * 1024 * 1024 * 1024;
      const minDownBytes = (Number(page.filters.minDownGb) || 0) * 1024 * 1024 * 1024;
      const rows = page.clients
        .filter((client) => {
          if (page.status === 'online') return client.online;
          if (page.status === 'offline') return !client.online;
          return client.online ? page.filters.showOnline !== false : page.filters.showOffline !== false;
        })
        .filter((client) => !page.filters.deviceTypes.length || page.filters.deviceTypes.includes(firstText(client.type, deviceType(client), 'unknown')))
        .filter((client) => {
          if (!ipFilter) return true;
          const text = [client.ip, client.ipv4, ipv6Parts(client).local, ipv6Parts(client).global].filter(Boolean).join(' ').toLowerCase();
          const hit = text.includes(ipFilter);
          return page.filters.ipExclude ? !hit : hit;
        })
        .filter((client) => {
          if (!vendorFilter) return true;
          return [client.vendorType, client.vendor, client.vendor_name, client.manufacturer, client.brand].filter(Boolean).join(' ').toLowerCase().includes(vendorFilter);
        })
        .filter((client) => {
          if (!vlanFilter) return true;
          return [client.vlan, client.vlan_id, client.vid, client.network].filter(Boolean).join(' ').toLowerCase().includes(vlanFilter);
        })
        .filter((client) => !minConnections || Number(client.connections || 0) >= minConnections)
        .filter((client) => !minUpBytes || Number(client.upBytes || 0) >= minUpBytes)
        .filter((client) => !minDownBytes || Number(client.downBytes || 0) >= minDownBytes)
        .filter(clientMatchesColumnFilters)
        .filter((client) => {
          if (ipVersion === 'ipv4') return Boolean(client.ip);
          if (ipVersion === 'ipv6') {
            const parts = ipv6Parts(client);
            return Boolean(parts.local || parts.global);
          }
          return true;
        })
        .filter((client) => {
          if (!search) return true;
          return [
            client.name,
            client.ip,
            client.mac,
            client.vendorType,
            client.type,
            client.hostname,
            client.model,
            client.ssid,
            client.interface
          ].filter(Boolean).join(' ').toLowerCase().includes(search);
        });
      rows.sort(compareClients);
      return rows;
    }

    function availableDeviceTypes() {
      return [...new Set(page.clients.map((client) => firstText(client.type, deviceType(client), 'unknown')).filter(Boolean))]
        .sort((a, b) => a.localeCompare(b, 'zh-Hans-CN', { numeric: true }));
    }

    function sortValue(client, key) {
      const values = {
        name: client.name,
        vendorType: client.vendorType,
        ip: client.ip,
        mac: client.mac,
        upRate: firstNumber(client.upRate, client.up_rate, client.tx_rate),
        downRate: firstNumber(client.downRate, client.down_rate, client.rx_rate),
        connections: client.connections,
        upTotal: client.upBytes,
        downTotal: client.downBytes,
        onlineTime: client.onlineDuration
      };
      return values[key] ?? values.name;
    }

    function compareClients(a, b) {
      const sort = page.sort || { key: 'name', direction: 'asc' };
      const av = sortValue(a, sort.key);
      const bv = sortValue(b, sort.key);
      let result = 0;
      if (typeof av === 'number' || typeof bv === 'number') result = (Number(av) || 0) - (Number(bv) || 0);
      else result = String(av || '').localeCompare(String(bv || ''), 'zh-Hans-CN', { numeric: true, sensitivity: 'base' });
      return sort.direction === 'desc' ? -result : result;
    }

    function sortHeader(column) {
      const key = firstText(column && column.key);
      const label = firstText(column && column.label, key);
      const active = page.sort.key === key;
      const direction = active ? page.sort.direction : 'none';
      const filterActive = Boolean(page.filters && page.filters.columnFilters && page.filters.columnFilters[key]);
      const filterConfig = CLIENT_COLUMN_FILTERS[key];
      const classes = [
        active ? `is-sorted sort-${escapeHtml(direction)}` : '',
        column && column.numeric ? 'is-numeric' : '',
        column && column.tone ? `is-${escapeHtml(column.tone)}` : '',
        filterActive ? 'has-column-filter' : ''
      ].filter(Boolean).join(' ');
      return `<th class="${classes}" data-column="${escapeHtml(key)}" draggable="true" data-client-column-drag="${escapeHtml(key)}" title="拖动可调整列顺序">
        <div class="client-header-cell">
          <button class="client-sort" type="button" data-client-sort="${escapeHtml(key)}" data-sort-direction="${escapeHtml(direction)}">
            <span>${escapeHtml(label)}</span>
            <i aria-hidden="true"></i>
          </button>
          ${filterConfig ? `<button class="client-column-filter-button ${filterActive ? 'is-active' : ''}" type="button" data-client-column-filter-open="${escapeHtml(key)}" aria-label="筛选 ${escapeHtml(label)}">
            <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M13.75 2.4H2.25c-.38 0-.62.42-.43.75l3.63 6.18v3.76c0 .28.22.5.5.5h4.1c.28 0 .5-.22.5-.5V9.33l3.63-6.18c.19-.33-.05-.75-.43-.75ZM9.43 12.47H6.57v-2.44h2.86v2.44ZM9.58 8.77l-.15.26H6.57l-.15-.26-3.1-5.24h9.36L9.58 8.77Z"></path></svg>
          </button>` : ''}
        </div>
      </th>`;
    }

    function copyToken(display, title, lines = null) {
      const primary = firstText(title, display, '--');
      const copyLines = Array.isArray(lines) && lines.length ? lines : [{ label: '值', value: primary }];
      return `<button class="client-copy-token" type="button" data-client-copy-value="${escapeHtml(primary)}" data-client-copy-lines="${escapeHtml(JSON.stringify(copyLines))}" aria-label="复制 ${escapeHtml(primary)}">
        <span class="client-copy-token-text">${escapeHtml(display || '--')}</span>
        <span class="client-copy-popover" role="tooltip">
          ${copyLines.map((line) => `<span><em>${escapeHtml(line.label)}</em><strong>${escapeHtml(line.value)}</strong></span>`).join('')}
        </span>
      </button>`;
    }

    function familyIpSignature(client = {}, family = 'ipv4') {
      if (family === 'ipv6') {
        const parts = ipv6Parts(client);
        return `ipv6:${parts.local || '--'}|${parts.global || '--'}`;
      }
      return `ipv4:${client.ip || '--'}`;
    }

    function familyIpCellMarkup(client = {}, family = 'ipv4') {
      if (family === 'ipv6') return ipv6Cell(ipv6Parts(client));
      return copyToken(client.ip || '--', client.ip || '--', [{ label: 'IPv4', value: client.ip || '--' }]);
    }

    function ipv6Cell(parts) {
      const lines = [
        { label: '内网', value: parts.local || '--' },
        { label: '外网', value: parts.global || '--' }
      ];
      return `<span class="client-ipv6-pair">
        ${copyToken(compact(parts.local || '--', 18), parts.local || '--', lines)}
        <span>/</span>
        ${copyToken(compact(parts.global || '--', 18), parts.global || '--', lines.slice().reverse())}
      </span>`;
    }

    function rateCell(value, className) {
      const num = Number(value) || 0;
      return `<span class="client-rate-value ${className} ${num > 0 ? 'is-active' : 'is-idle'}">${escapeHtml(formatRate(num))}</span>`;
    }

    function clientColumnCell(client, family, column) {
      const key = firstText(column && column.key);
      const isIpv6 = family === 'ipv6';
      const cellClasses = [];
      if (key === 'name') cellClasses.push('client-name-cell');
      if (key === 'ip') cellClasses.push('client-ip-cell');
      if (column && column.numeric) cellClasses.push('num');
      if (column && column.tone === 'up') cellClasses.push('rate-up');
      if (column && column.tone === 'down') cellClasses.push('rate-down');
      if (key === 'upTotal') cellClasses.push('total-up');
      if (key === 'downTotal') cellClasses.push('total-down');
      let html = '--';
      if (key === 'name') {
        html = `<span class="client-device-art ${isIpv6 ? 'is-ipv6-art' : ''}">${clientImage(client)}</span>
          <span class="client-name-stack">
            <strong>${escapeHtml(client.name)}</strong>
            ${isIpv6 ? '<em class="client-ipv6-badge">IPv6</em>' : ''}
          </span>`;
      } else if (key === 'vendorType') {
        html = escapeHtml(client.vendorType || '--');
      } else if (key === 'ip') {
        html = familyIpCellMarkup(client, family);
      } else if (key === 'mac') {
        html = copyToken(client.mac || '--', client.mac || '--', [{ label: 'MAC', value: client.mac || '--' }]);
      } else if (key === 'upRate') {
        html = rateCell(familyMetric(client, family, 'upRate'), 'rate-up');
      } else if (key === 'downRate') {
        html = rateCell(familyMetric(client, family, 'downRate'), 'rate-down');
      } else if (key === 'connections') {
        html = escapeHtml(formatInteger(familyMetric(client, family, 'connections')));
      } else if (key === 'upTotal') {
        html = escapeHtml(formatBytes(familyMetric(client, family, 'upBytes')));
      } else if (key === 'downTotal') {
        html = escapeHtml(formatBytes(familyMetric(client, family, 'downBytes')));
      } else if (key === 'onlineTime') {
        html = escapeHtml(onlineDurationLabel(client));
      }
      return `<td class="${cellClasses.join(' ')}" data-column="${escapeHtml(key)}">${html}</td>`;
    }

    function clientRow(client, family = 'ipv4') {
      const ipv6 = ipv6Parts(client);
      const isIpv6 = family === 'ipv6';
      const rowClass = `client-row client-row-${family}${client.online ? '' : ' is-offline'}`;
      const ipSignature = familyIpSignature(client, family);
      const cells = orderedClientColumns().map((column) => clientColumnCell(client, family, column)).join('');
      return `<tr class="${rowClass}" data-client-mac="${escapeHtml(client.mac)}" data-client-family="${escapeHtml(family)}" data-client-ip-signature="${escapeHtml(ipSignature)}">${cells}</tr>`;
    }

    function clientDeviceRows(client) {
      const ipv6 = ipv6Parts(client);
      const hasIpv6 = page.showIpv6 && (ipv6.local || ipv6.global);
      return `<tbody class="client-device ${hasIpv6 ? 'has-ipv6' : ''}" data-client-mac="${escapeHtml(client.mac)}">
        ${clientRow(client, 'ipv4')}
        ${hasIpv6 ? clientRow(client, 'ipv6') : ''}
      </tbody>`;
    }

    function tableMarkup(rows, errorText = '') {
      if (!rows.length) {
        return `<div class="client-empty">${escapeHtml(errorText || '没有匹配的终端。')}</div>`;
      }
      return `<div class="dwrt-kit-table-wrap client-table-wrap">
        <div class="dwrt-kit-table-scroll">
          <table class="dwrt-kit-table client-table-core">
            <thead>
              <tr>
                ${orderedClientColumns().map(sortHeader).join('')}
              </tr>
            </thead>
            ${rows.map(clientDeviceRows).join('')}
          </table>
        </div>
      </div>`;
    }

    function tableStructureSignature(rows = filteredClients()) {
      return rows.map((client) => {
        const ipv6 = ipv6Parts(client);
        const hasIpv6 = page.showIpv6 && (ipv6.local || ipv6.global);
        return [
          client.mac,
          client.name,
          client.vendorType,
          hasIpv6 ? 'v6' : 'v4',
          client.online ? 'online' : 'offline'
        ].map((item) => String(item || '')).join('\u001f');
      }).join('\u001e');
    }

    function clientTablePanel() {
      return root && root.querySelector('.client-table-panel');
    }

    function tableInteractionActive() {
      if (!page || !root) return false;
      const panel = clientTablePanel();
      if (!panel) return false;
      if (page.tablePointerInside) return true;
      const active = document.activeElement;
      return Boolean(active && panel.contains(active));
    }

    function queueTableRender(delay = 180) {
      if (!page || !page.active) return;
      page.tableRenderPending = true;
      window.clearTimeout(page.tableRenderTimer);
      page.tableRenderTimer = window.setTimeout(() => {
        if (!page || !page.active) return;
        if (tableInteractionActive()) {
          queueTableRender(220);
          return;
        }
        page.tableRenderPending = false;
        renderTableOnly({ force: true });
      }, delay);
    }

    function setTextIfChanged(node, text) {
      if (!node) return false;
      const next = String(text);
      if (node.textContent === next) return false;
      if (node.childNodes.length === 1 && node.firstChild && node.firstChild.nodeType === Node.TEXT_NODE) {
        node.firstChild.nodeValue = next;
      } else {
        node.textContent = next;
      }
      return true;
    }

    function patchRateNode(row, selector, value) {
      const node = row && row.querySelector(selector);
      if (!node) return false;
      const num = Number(value) || 0;
      let changed = setTextIfChanged(node, formatRate(num));
      const active = num > 0;
      if (node.classList.contains('is-active') !== active) {
        node.classList.toggle('is-active', active);
        node.classList.toggle('is-idle', !active);
        changed = true;
      }
      return changed;
    }

    function patchClientRowMetrics(row, client, family = 'ipv4') {
      if (!row || !client) return false;
      let changed = false;
      const upRate = familyMetric(client, family, 'upRate');
      const downRate = familyMetric(client, family, 'downRate');
      const connections = familyMetric(client, family, 'connections');
      const upBytes = familyMetric(client, family, 'upBytes');
      const downBytes = familyMetric(client, family, 'downBytes');
      changed = patchRateNode(row, '[data-column="upRate"] .client-rate-value.rate-up', upRate) || changed;
      changed = patchRateNode(row, '[data-column="downRate"] .client-rate-value.rate-down', downRate) || changed;
      const ipSignature = familyIpSignature(client, family);
      if (row.dataset.clientIpSignature !== ipSignature) {
        const ipCell = row.querySelector('[data-column="ip"]');
        if (ipCell) {
          ipCell.innerHTML = familyIpCellMarkup(client, family);
          row.dataset.clientIpSignature = ipSignature;
          changed = true;
        }
      }
      changed = setTextIfChanged(row.querySelector('[data-column="connections"]'), formatInteger(connections)) || changed;
      changed = setTextIfChanged(row.querySelector('[data-column="upTotal"]'), formatBytes(upBytes)) || changed;
      changed = setTextIfChanged(row.querySelector('[data-column="downTotal"]'), formatBytes(downBytes)) || changed;
      changed = setTextIfChanged(row.querySelector('[data-column="onlineTime"]'), onlineDurationLabel(client)) || changed;
      if (row.classList.contains('is-offline') === Boolean(client.online)) {
        row.classList.toggle('is-offline', !client.online);
        changed = true;
      }
      return changed;
    }

    function patchTableMetricsOnly(rows = filteredClients()) {
      if (!root || !page || !page.active || !page.lastTableStructureSignature) return false;
      const table = root.querySelector('.client-table-core');
      if (!table) return false;
      const signature = tableStructureSignature(rows);
      if (signature !== page.lastTableStructureSignature) return false;
      const domRows = Array.from(table.querySelectorAll('tbody.client-device tr.client-row'));
      const rowMap = new Map();
      domRows.forEach((row) => rowMap.set(`${String(row.dataset.clientMac || '').toLowerCase()}|${row.dataset.clientFamily || 'ipv4'}`, row));
      let expected = 0;
      for (const client of rows) {
        const mac = String(client.mac || '').toLowerCase();
        if (!mac) return false;
        const ipv6 = ipv6Parts(client);
        const families = ['ipv4'];
        if (page.showIpv6 && (ipv6.local || ipv6.global)) families.push('ipv6');
        expected += families.length;
        for (const family of families) {
          const row = rowMap.get(`${mac}|${family}`);
          if (!row) return false;
          patchClientRowMetrics(row, client, family);
        }
      }
      return domRows.length === expected;
    }

    function refreshTableFromData() {
      if (patchTableMetricsOnly()) return;
      renderTableOnly();
    }

    function renderTableOnly(options = {}) {
      if (!root || !page || !page.active) return;
      if (fingerprintPickerOpen()) {
        page.renderAfterFingerprint = true;
        return;
      }
      const panel = root.querySelector('.client-table-panel');
      if (!panel) return;
      const rows = filteredClients();
      if (!options.force && tableInteractionActive()) {
        patchTableMetricsOnly(rows);
        queueTableRender();
        return;
      }
      const scroll = panel.querySelector('.client-table-wrap .dwrt-kit-table-scroll');
      const left = scroll ? scroll.scrollLeft : 0;
      const top = scroll ? scroll.scrollTop : 0;
      page.lastTableStructureSignature = tableStructureSignature(rows);
      page.tableRenderPending = false;
      window.clearTimeout(page.tableRenderTimer);
      panel.innerHTML = tableMarkup(rows, page.error);
      const next = panel.querySelector('.client-table-wrap .dwrt-kit-table-scroll');
      if (next) {
        next.scrollLeft = left;
        next.scrollTop = top;
        window.requestAnimationFrame(() => {
          next.scrollLeft = left;
          next.scrollTop = top;
        });
      }
      mountUiKit(panel);
      scheduleGlassCardsRender(120);
    }

    function detailValue(value, fallback = '--') {
      if (value === undefined || value === null || value === '') return fallback;
      if (Array.isArray(value)) return value.map((item) => detailValue(item, '')).filter(Boolean).join('、') || fallback;
      if (typeof value !== 'object') return String(value);
      return firstText(value.label, value.name, value.title, value.app_name, value.app, value.domain, value.host, value.url, value.ip, value.value, value.id, fallback);
    }

    function detailMetric(label, value) {
      return `<div class="client-detail-meta-item"><span>${escapeHtml(label)}</span><strong>${escapeHtml(detailValue(value))}</strong></div>`;
    }

    function rawList(value) {
      if (Array.isArray(value)) return value;
      if (value && typeof value === 'object') {
        for (const key of ['items', 'rows', 'list', 'records', 'connections', 'protocols', 'rules']) {
          if (Array.isArray(value[key])) return value[key];
        }
      }
      return [];
    }

    function keyValueGrid(items) {
      return `<div class="client-detail-grid">${items.map(([label, value]) => detailMetric(label, value)).join('')}</div>`;
    }

    function listPanel(title, list, empty) {
      const rows = rawList(list);
      return `<section class="client-detail-card">
        <div class="client-detail-card-head"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(rows.length ? `${rows.length} 项` : empty)}</span></div>
        ${rows.length ? `<div class="client-detail-list">${rows.slice(0, 40).map((item) => {
          if (typeof item !== 'object') return `<div><strong>${escapeHtml(detailValue(item))}</strong></div>`;
          const main = detailValue(item.name || item.label || item.protocol || item.app || item.dst || item.destination || item.url || item.domain || item.ip || item.remote || item.local);
          const note = Object.entries(item).filter(([, value]) => value !== undefined && value !== null && value !== '' && typeof value !== 'object').slice(0, 4).map(([key, value]) => `${key}: ${value}`).join(' · ');
          return `<div><strong>${escapeHtml(main)}</strong><span>${escapeHtml(note || '--')}</span></div>`;
        }).join('')}</div>` : ''}
        </section>`;
    }

    function detailStat(label, value) {
      return `<div class="client-detail-stat"><span>${escapeHtml(label)}</span><strong>${escapeHtml(detailValue(value))}</strong></div>`;
    }

    function numericValue(value) {
      if (value === undefined || value === null || value === '') return 0;
      if (typeof value === 'number') return Number.isFinite(value) ? value : 0;
      const text = String(value).trim().replace(/,/g, '');
      if (!text) return 0;
      const match = text.match(/^(-?\d+(?:\.\d+)?)\s*([kmgt]?)(?:i?b)?(?:ps|\/s)?$/i);
      if (match) {
        const base = Number(match[1]);
        if (!Number.isFinite(base)) return 0;
        const unit = match[2].toLowerCase();
        const map = { k: 1024, m: 1024 * 1024, g: 1024 * 1024 * 1024, t: 1024 * 1024 * 1024 * 1024 };
        return base * (map[unit] || 1);
      }
      const num = Number(text);
      return Number.isFinite(num) ? num : 0;
    }

    function sampleTimestamp(item, fallback) {
      const raw = firstNumber(
        item && item.timestamp,
        item && item.ts,
        item && item.time,
        item && item.created_at,
        item && item.sample_time,
        fallback
      );
      if (!raw) return fallback;
      return raw > 1e12 ? Math.floor(raw / 1000) : Math.floor(raw);
    }

    function historyCandidates(profile = {}) {
      const sources = [
        profile.overview_history,
        profile.realtime_history,
        profile.rate_history,
        profile.traffic_rate_history,
        profile.traffic_history_rate,
        profile.bandwidth_history,
        profile.client_history,
        profile.history,
        profile.samples,
        profile.stream_collect,
        profile.terminal_stream_collect,
        profile.current && profile.current.overview_history,
        profile.current && profile.current.rate_history,
        profile.current && profile.current.terminal_stream_collect,
        profile.realtime && profile.realtime.points,
        profile.realtime && profile.realtime.items,
        profile.bandwidth_history && profile.bandwidth_history.points,
        profile.rate_history && profile.rate_history.points
      ];
      for (const source of sources) {
        const rows = rawList(source);
        if (rows.length) return rows;
      }
      return [];
    }

    function normalizeOverviewSample(item = {}, index = 0, length = 1) {
      const fallbackTs = Math.floor(Date.now() / 1000) - Math.max(0, length - index - 1) * 5;
      return {
        ts: sampleTimestamp(item, fallbackTs),
        up: Math.max(0, numericValue(firstText(
          item.up_rate, item.rate_up, item.tx_rate, item.upload_rate, item.upload,
          item['tx_byte-r'], item.tx_bps, item.up_bps, item.up_bytes_per_sec, item.upload_bytes_per_sec
        ))),
        down: Math.max(0, numericValue(firstText(
          item.down_rate, item.rate_down, item.rx_rate, item.download_rate, item.download,
          item['rx_byte-r'], item.rx_bps, item.down_bps, item.down_bytes_per_sec, item.download_bytes_per_sec
        ))),
        connections: Math.max(0, numericValue(firstText(
          item.connections, item.conn_count, item.conntrack_count, item.active_connections,
          item.connection_count, item.conn_num, item.connect_num
        )))
      };
    }

    function sampleKey(mac) {
      return String(mac || '').trim().toLowerCase();
    }

    function pushClientOverviewSample(client = {}) {
      if (!page || !client || !client.mac) return;
      const key = sampleKey(client.mac);
      if (!key) return;
      const now = Math.floor(Date.now() / 1000);
      const sample = {
        ts: now,
        up: Math.max(0, Number(client.upRate) || 0),
        down: Math.max(0, Number(client.downRate) || 0),
        connections: Math.max(0, Number(client.connections) || 0)
      };
      const store = page.clientOverviewSamples || (page.clientOverviewSamples = {});
      const list = store[key] || [];
      const last = list[list.length - 1];
      if (!last || Math.abs(now - last.ts) >= 2 || last.up !== sample.up || last.down !== sample.down || last.connections !== sample.connections) {
        list.push(sample);
      }
      const minTs = now - 5 * 60;
      store[key] = list.filter((point) => point.ts >= minTs).slice(-96);
    }

    function overviewSeries(client, profile, merged) {
      const raw = historyCandidates(profile);
      let samples = raw.map((item, index) => normalizeOverviewSample(item, index, raw.length))
        .filter((point) => Number.isFinite(point.ts))
        .sort((a, b) => a.ts - b.ts);
      const key = sampleKey((merged || client || {}).mac);
      const live = key && page && page.clientOverviewSamples ? asArray(page.clientOverviewSamples[key]) : [];
      if (live.length) {
        const byTs = new Map(samples.map((point) => [point.ts, point]));
        live.forEach((point) => byTs.set(point.ts, point));
        samples = Array.from(byTs.values()).sort((a, b) => a.ts - b.ts);
      }
      const now = Math.floor(Date.now() / 1000);
      if (!samples.length) {
        const base = normalizeOverviewSample({
          up_rate: merged && merged.upRate,
          down_rate: merged && merged.downRate,
          connections: merged && merged.connections
        }, 0, 1);
        samples = Array.from({ length: 30 }, (_, index) => ({
          ts: now - (29 - index) * 5,
          up: base.up,
          down: base.down,
          connections: Math.round(base.connections)
        }));
      } else if (samples.length === 1) {
        const base = samples[0];
        samples = Array.from({ length: 30 }, (_, index) => ({
          ts: now - (29 - index) * 5,
          up: base.up,
          down: base.down,
          connections: Math.round(base.connections)
        }));
      }
      return bucketOverviewSamples(samples);
    }

    function bucketOverviewSamples(samples = []) {
      const points = asArray(samples)
        .filter((point) => point && Number.isFinite(Number(point.ts)))
        .sort((a, b) => Number(a.ts) - Number(b.ts));
      const latest = points.length ? Number(points[points.length - 1].ts) : Math.floor(Date.now() / 1000);
      const end = Math.floor(Math.max(0, latest) / OVERVIEW_BUCKET_SECONDS) * OVERVIEW_BUCKET_SECONDS;
      const count = Math.floor(OVERVIEW_WINDOW_SECONDS / OVERVIEW_BUCKET_SECONDS) + 1;
      const start = end - (count - 1) * OVERVIEW_BUCKET_SECONDS;
      const buckets = new Map();
      points.forEach((point) => {
        const bucket = Math.floor(Number(point.ts) / OVERVIEW_BUCKET_SECONDS) * OVERVIEW_BUCKET_SECONDS;
        if (bucket < start - OVERVIEW_BUCKET_SECONDS || bucket > end + OVERVIEW_BUCKET_SECONDS) return;
        buckets.set(bucket, {
          ts: bucket,
          up: Math.max(0, Number(point.up) || 0),
          down: Math.max(0, Number(point.down) || 0),
          connections: Math.max(0, Number(point.connections) || 0)
        });
      });
      let carry = null;
      return Array.from({ length: count }, (_, index) => {
        const ts = start + index * OVERVIEW_BUCKET_SECONDS;
        const exact = buckets.get(ts);
        if (exact) {
          carry = exact;
          return exact;
        }
        const canCarry = carry && ts - carry.ts <= OVERVIEW_BUCKET_SECONDS * 3;
        return {
          ts,
          up: canCarry ? carry.up : 0,
          down: canCarry ? carry.down : 0,
          connections: canCarry ? carry.connections : 0
        };
      });
    }

    function niceMax(value) {
      const raw = Math.max(1, Number(value) || 1);
      const exp = Math.floor(Math.log10(raw));
      const base = Math.pow(10, exp);
      const ratio = raw / base;
      const nice = ratio <= 1 ? 1 : ratio <= 2 ? 2 : ratio <= 5 ? 5 : 10;
      return nice * base;
    }

    function formatChartBytes(value) {
      const bytes = Math.max(0, Number(value) || 0);
      if (bytes < 1024) return `${Math.round(bytes)} B`;
      if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
      if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
      return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
    }

    function chartTimeLabel(ts) {
      const date = new Date((Number(ts) || 0) * 1000);
      if (!Number.isFinite(date.getTime())) return '--';
      const hh = String(date.getHours()).padStart(2, '0');
      const mm = String(date.getMinutes()).padStart(2, '0');
      const ss = String(date.getSeconds()).padStart(2, '0');
      return `${hh}:${mm}:${ss}`;
    }

    function overviewChartLabelStep(samples) {
      const points = asArray(samples).filter((point) => Number.isFinite(Number(point && point.ts)));
      if (points.length < 2) return 10;
      const span = Math.max(1, Number(points[points.length - 1].ts) - Number(points[0].ts));
      if (span <= 5 * 60) return 10;
      if (span <= 12 * 60) return 20;
      if (span <= 35 * 60) return 60;
      return 5 * 60;
    }

    function overviewChartVisibleLabelIndices(samples) {
      const points = asArray(samples);
      const visible = new Set();
      if (!points.length) return visible;
      const step = overviewChartLabelStep(points);
      let next = Number(points[0].ts) || 0;
      points.forEach((point, index) => {
        const ts = Number(point && point.ts) || 0;
        if (!index || ts >= next || index === points.length - 1) {
          visible.add(index);
          next = ts + step;
        }
      });
      const maxLabels = 32;
      if (visible.size > maxLabels) {
        const ordered = Array.from(visible).sort((a, b) => a - b);
        const every = Math.ceil(ordered.length / maxLabels);
        visible.clear();
        ordered.forEach((index, order) => {
          if (order % every === 0 || index === points.length - 1) visible.add(index);
        });
      }
      return visible;
    }

    function chartPath(points, key, dims, maxValue) {
      if (!points.length) return '';
      const { width, height, pad } = dims;
      const minTs = Math.min(...points.map((point) => point.ts));
      const maxTs = Math.max(...points.map((point) => point.ts));
      const span = Math.max(1, maxTs - minTs);
      const plotW = width - pad.left - pad.right;
      const plotH = height - pad.top - pad.bottom;
      const coords = points.map((point) => {
        const x = pad.left + ((point.ts - minTs) / span) * plotW;
        const y = pad.top + (1 - Math.min(1, Math.max(0, (Number(point[key]) || 0) / maxValue))) * plotH;
        return [x, y];
      });
      if (coords.length === 1) return `M ${coords[0][0].toFixed(1)} ${coords[0][1].toFixed(1)}`;
      return coords.map((point, index) => {
        if (!index) return `M ${point[0].toFixed(1)} ${point[1].toFixed(1)}`;
        const prev = coords[index - 1];
        const next = coords[index + 1] || point;
        const before = coords[index - 2] || prev;
        const cp1x = prev[0] + (point[0] - before[0]) / 6;
        const cp1y = prev[1] + (point[1] - before[1]) / 6;
        const cp2x = point[0] - (next[0] - prev[0]) / 6;
        const cp2y = point[1] - (next[1] - prev[1]) / 6;
        return `C ${cp1x.toFixed(1)} ${cp1y.toFixed(1)} ${cp2x.toFixed(1)} ${cp2y.toFixed(1)} ${point[0].toFixed(1)} ${point[1].toFixed(1)}`;
      }).join(' ');
    }

    function overviewChartPayload({ title, samples, series, mode }) {
      const active = page && page.overviewLegend ? page.overviewLegend : { up: true, down: true, connections: true };
      const visibleSeries = series.filter((item) => active[item.key] !== false);
      return {
        title,
        mode,
        samples: samples.map((point) => ({
          ts: Number(point.ts) || 0,
          up: Number(point.up) || 0,
          down: Number(point.down) || 0,
          connections: Number(point.connections) || 0
        })),
        series: visibleSeries,
        seriesAll: series,
        legend: series.map((item) => ({ key: item.key, label: item.label, className: item.className, active: active[item.key] !== false }))
      };
    }

    function overviewLineChart({ title, samples, series, mode }) {
      const payload = overviewChartPayload({ title, samples, series, mode });
      const hasData = payload.samples.some((point) => payload.series.some((item) => Number(point[item.key]) > 0));
      return `<section class="client-overview-chart-card client-detail-card" data-client-overview-card="${escapeHtml(mode)}">
        <div class="client-overview-chart-title">${escapeHtml(title)}</div>
        <div class="client-overview-chart" data-client-overview-chart="${escapeHtml(mode)}" data-chart-payload="${escapeHtml(JSON.stringify(payload))}">
          <div class="client-overview-echart" aria-label="${escapeHtml(title)}"></div>
          ${hasData ? '' : `<div class="client-chart-empty">等待终端实时采样</div>`}
        </div>
        <div class="client-chart-legend" role="group" aria-label="${escapeHtml(title)}图例">
          ${payload.legend.map((item) => `<button class="client-chart-legend-button ${item.active ? 'is-active' : 'is-muted'}" type="button" data-client-overview-legend="${escapeHtml(item.key)}" aria-pressed="${item.active ? 'true' : 'false'}"><i class="${escapeHtml(item.className)}"></i>${escapeHtml(item.label)}</button>`).join('')}
        </div>
      </section>`;
    }

    function overviewChartDefinitions(client, profile, merged) {
      const samples = overviewSeries(client, profile, merged);
      return [
        {
          title: '带宽详情',
          samples,
          mode: 'rate',
          series: [
            { key: 'up', label: '上行速率', className: 'is-up' },
            { key: 'down', label: '下行速率', className: 'is-down' }
          ]
        },
        {
          title: '连接详情',
          samples,
          mode: 'connections',
          series: [
            { key: 'connections', label: '连接数', className: 'is-conn' }
          ]
        }
      ];
    }

    function overviewCharts(client, profile, merged) {
      return `<div class="client-overview-charts">
        ${overviewChartDefinitions(client, profile, merged).map(overviewLineChart).join('')}
      </div>`;
    }

    function echartsPalette(source) {
      const sampled = source && source.closest ? source.closest('[data-adaptive-region]') : null;
      const target = sampled || source || document.documentElement;
      const styles = getComputedStyle(target);
      const mode = sampled?.dataset.adaptiveRegion || document.documentElement.dataset.adaptiveForeground || '';
      return {
        key: mode || 'default',
        text: (styles.getPropertyValue('--app-text-muted') || 'rgba(220,226,238,.72)').trim(),
        split: mode === 'dark' ? 'rgba(8,13,21,.18)' : 'rgba(245,249,255,.18)'
      };
    }

    function overviewChartColor(key) {
      if (key === 'up') return '#535d9f';
      if (key === 'down') return '#1f7a33';
      return '#5b8dff';
    }

    function overviewChartYAxisMax(mode, rawMax) {
      const max = Math.max(0, Number(rawMax) || 0);
      if (!page) return max > 0 ? max : undefined;
      const store = page.overviewAxisMax || (page.overviewAxisMax = {});
      const key = mode || 'rate';
      const now = Date.now();
      const current = store[key] || { value: 0, at: 0 };
      if (max <= 0) {
        store[key] = { value: 0, at: now };
        return undefined;
      }
      const next = Math.max(max, 1);
      if (!current.value || next > current.value * 1.06) {
        store[key] = { value: next, at: now };
        return next;
      }
      if (next < current.value * 0.58 && now - current.at > 14000) {
        store[key] = { value: next, at: now };
        return next;
      }
      return current.value;
    }

    function formatAxisRate(bytesPerSecond) {
      const bits = Math.max(0, Number(bytesPerSecond) || 0) * 8;
      if (bits <= 0) return '0';
      const units = ['bps', 'K', 'M', 'G', 'T'];
      let value = bits;
      let index = 0;
      while (value >= 1000 && index < units.length - 1) {
        value /= 1000;
        index += 1;
      }
      const digits = value >= 100 || index === 0 ? 0 : value >= 10 ? 1 : 2;
      return `${value.toFixed(digits).replace(/\.0+$/, '')}${units[index]}`;
    }

    function buildOverviewChartOption(payload, source) {
      const samples = asArray(payload.samples);
      const mode = payload.mode === 'connections' ? 'connections' : 'rate';
      const palette = echartsPalette(source);
      const textColor = palette.text;
      const splitColor = palette.split;
      const categories = samples.map((point) => chartTimeLabel(Number(point.ts) || 0));
      const visibleLabelIndices = overviewChartVisibleLabelIndices(samples);
      const activeSeries = new Set(asArray(payload.series).map((item) => item.label));
      const maxValue = Math.max(0, ...asArray(payload.series).flatMap((item) => samples.map((point) => Number(point[item.key]) || 0)));
      const yMax = overviewChartYAxisMax(mode, maxValue);
      return {
        animation: false,
        animationDuration: 0,
        animationDurationUpdate: 0,
        backgroundColor: 'transparent',
        grid: { left: 92, right: 24, top: 24, bottom: 78, containLabel: false },
        tooltip: {
          trigger: 'axis',
          appendToBody: true,
          confine: true,
          backgroundColor: 'rgba(16,22,33,.90)',
          borderColor: 'rgba(255,255,255,.14)',
          borderWidth: 1,
          textStyle: { color: '#edf3ff', fontSize: 12, fontWeight: 600 },
          axisPointer: { type: 'line', lineStyle: { color: 'rgba(150,170,220,.42)', width: 1 } },
          formatter(params) {
            const list = Array.isArray(params) ? params : [];
            const title = list[0] && list[0].axisValue || '--';
            return [`<strong>${escapeHtml(title)}</strong>`].concat(list.map((item) => {
              const raw = item && item.data !== undefined ? Number(item.data) || 0 : 0;
              const value = mode === 'connections' ? `${formatInteger(Math.round(raw))}` : `${formatChartBytes(raw)}/s`;
              return `${item.marker}${escapeHtml(item.seriesName)}：${escapeHtml(value)}`;
            })).join('<br>');
          }
        },
        legend: {
          show: false,
          data: asArray(payload.legend).map((item) => item.label),
          selected: Object.fromEntries(asArray(payload.legend).map((item) => [item.label, item.active !== false]))
        },
        xAxis: {
          type: 'category',
          boundaryGap: false,
          data: categories,
          axisLine: { show: false },
          axisTick: { show: false },
          splitLine: { show: false },
          axisLabel: {
            interval: 0,
            rotate: 45,
            align: 'right',
            verticalAlign: 'middle',
            color: textColor,
            fontSize: 12,
            fontWeight: 650,
            margin: 20,
            formatter(value, index) { return visibleLabelIndices.has(index) ? value : ''; }
          }
        },
        yAxis: {
          type: 'value',
          min: 0,
          max: yMax,
          interval: yMax ? yMax / 5 : undefined,
          scale: false,
          splitNumber: 5,
          axisLine: { show: false },
          axisTick: { show: false },
          splitLine: { lineStyle: { color: splitColor, type: 'dashed', width: 1 } },
          axisLabel: {
            color: textColor,
            fontSize: 12,
            fontWeight: 650,
            margin: 14,
            formatter(value) { return mode === 'connections' ? formatInteger(Math.round(Number(value) || 0)) : formatChartBytes(Number(value) || 0); }
          }
        },
        series: asArray(payload.legend).map((legendItem) => {
          const item = asArray(payload.seriesAll || payload.series).find((seriesItem) => seriesItem.key === legendItem.key) || legendItem;
          return {
            name: legendItem.label,
            type: 'line',
            showSymbol: false,
            smooth: 0.36,
            connectNulls: true,
            clip: true,
            lineStyle: { width: mode === 'connections' ? 2.2 : 2.4, color: overviewChartColor(item.key), opacity: activeSeries.has(legendItem.label) ? 1 : 0 },
            itemStyle: { color: overviewChartColor(item.key) },
            animation: false,
            animationDuration: 0,
            animationDurationUpdate: 0,
            emphasis: { focus: 'series', lineStyle: { width: mode === 'connections' ? 2.8 : 3 } },
            data: activeSeries.has(legendItem.label) ? samples.map((point) => Math.max(0, Number(point[item.key]) || 0)) : []
          };
        })
      };
    }

    function disposeOverviewCharts() {
      if (!page || !page.overviewCharts) return;
      page.overviewCharts.forEach((entry) => {
        const chart = entry && entry.chart ? entry.chart : entry;
        try { chart && chart.dispose && chart.dispose(); } catch (_) {}
      });
      page.overviewCharts = new Map();
    }

    function updateOverviewChartSetOption(chart, option) {
      try {
        chart.setOption(option, { notMerge: false, lazyUpdate: true, silent: true });
      } catch (_) {
        try { chart.setOption(option, false, true); } catch (__) { chart.setOption(option); }
      }
    }

    function updateProtocolChartSetOption(chart, option) {
      updateOverviewChartSetOption(chart, option);
    }

    function renderOverviewCharts() {
      if (!root || !page || !page.active) return;
      const nodes = Array.from(root.querySelectorAll('[data-client-overview-chart]'));
      if (!nodes.length) {
        disposeOverviewCharts();
        return;
      }
      loadECharts().then((echarts) => {
        if (!page || !page.active || !root) return;
        const activeModes = new Set(nodes.map((node) => node.dataset.clientOverviewChart || 'default'));
        page.overviewCharts = page.overviewCharts || new Map();
        page.overviewCharts.forEach((entry, mode) => {
          const chart = entry && entry.chart ? entry.chart : entry;
          if (!activeModes.has(mode) || !entry.host || !document.contains(entry.host)) {
            try { chart && chart.dispose && chart.dispose(); } catch (_) {}
            page.overviewCharts.delete(mode);
          }
        });
        nodes.forEach((node) => {
          const mode = node.dataset.clientOverviewChart || 'default';
          const host = node.querySelector('.client-overview-echart');
          if (!host) return;
          let payload = null;
          try { payload = JSON.parse(node.dataset.chartPayload || '{}'); } catch (_) { payload = null; }
          if (!payload || !Array.isArray(payload.samples)) return;
          let entry = page.overviewCharts.get(mode);
          let chart = entry && entry.chart;
          if (!entry || entry.host !== host || !chart || chart.isDisposed && chart.isDisposed()) {
            if (chart) { try { chart.dispose(); } catch (_) {} }
            chart = echarts.init(host, null, { renderer: 'canvas' });
            entry = { chart, host, width: 0, height: 0, optionKey: '' };
            page.overviewCharts.set(mode, entry);
          }
          const paletteKey = echartsPalette(node).key;
          const optionKey = `${node.dataset.chartPayload || ''}|${paletteKey}`;
          if (entry.optionKey !== optionKey) {
            updateOverviewChartSetOption(chart, buildOverviewChartOption(payload, node));
            entry.optionKey = optionKey;
          }
          const rect = host.getBoundingClientRect();
          const width = Math.round(rect.width || 0);
          const height = Math.round(rect.height || 0);
          if (width && height && (entry.width !== width || entry.height !== height)) {
            entry.width = width;
            entry.height = height;
            window.requestAnimationFrame(() => {
              try { chart.resize({ width, height, silent: true }); } catch (_) { chart.resize(); }
            });
          }
        });
      }).catch(() => {
        root.querySelectorAll('.client-overview-echart').forEach((node) => {
          node.innerHTML = '<div class="client-chart-empty is-error">图表组件加载失败</div>';
        });
      });
    }

    function disposeProtocolCharts() {
      if (!page || !page.protocolCharts) return;
      page.protocolCharts.forEach((entry) => {
        const chart = entry && entry.chart ? entry.chart : entry;
        try { chart && chart.dispose && chart.dispose(); } catch (_) {}
      });
      page.protocolCharts = new Map();
    }

    function renderProtocolCharts() {
      if (!root || !page || !page.active) return;
      const nodes = Array.from(root.querySelectorAll('[data-client-protocol-chart]'));
      if (!nodes.length) {
        disposeProtocolCharts();
        return;
      }
      loadECharts().then((echarts) => {
        if (!page || !page.active || !root) return;
        const activeModes = new Set(nodes.map((node) => node.dataset.clientProtocolChart || 'default'));
        page.protocolCharts = page.protocolCharts || new Map();
        page.protocolCharts.forEach((entry, mode) => {
          const chart = entry && entry.chart ? entry.chart : entry;
          if (!activeModes.has(mode) || !entry.host || !document.contains(entry.host)) {
            try { chart && chart.dispose && chart.dispose(); } catch (_) {}
            page.protocolCharts.delete(mode);
          }
        });
        nodes.forEach((node) => {
          const mode = node.dataset.clientProtocolChart || 'default';
          const host = node.querySelector('.client-protocol-echart');
          if (!host) return;
          let payload = null;
          try { payload = JSON.parse(node.dataset.chartPayload || '{}'); } catch (_) { payload = null; }
          if (!payload || !Array.isArray(payload.samples)) return;
          let entry = page.protocolCharts.get(mode);
          let chart = entry && entry.chart;
          if (!entry || entry.host !== host || !chart || chart.isDisposed && chart.isDisposed()) {
            if (chart) { try { chart.dispose(); } catch (_) {} }
            chart = echarts.init(host, null, { renderer: 'canvas' });
            entry = { chart, host, width: 0, height: 0, optionKey: '' };
            page.protocolCharts.set(mode, entry);
          }
          const paletteKey = echartsPalette(node).key;
          const optionKey = `${node.dataset.chartPayload || ''}|${paletteKey}`;
          if (entry.optionKey !== optionKey) {
            updateProtocolChartSetOption(chart, buildProtocolRateChartOption(payload, node));
            entry.optionKey = optionKey;
          }
          const rect = host.getBoundingClientRect();
          const width = Math.round(rect.width || 0);
          const height = Math.round(rect.height || 0);
          if (width && height && (entry.width !== width || entry.height !== height)) {
            entry.width = width;
            entry.height = height;
            window.requestAnimationFrame(() => {
              try { chart.resize({ width, height, silent: true }); } catch (_) { chart.resize(); }
            });
          }
        });
      }).catch(() => {
        root.querySelectorAll('.client-protocol-echart').forEach((node) => {
          node.innerHTML = '<div class="client-chart-empty is-error">图表组件加载失败</div>';
        });
      });
    }

    function currentDetailContext() {
      if (!page || !page.detail || !page.detail.open) return null;
      const client = page.clients.find((item) => String(item.mac).toLowerCase() === String(page.detail.mac).toLowerCase()) || {};
      const profile = page.detail.profile || {};
      const merged = profileClient(client, profile);
      return { client, profile, merged };
    }

    function patchOverviewDetailPanel() {
      if (!root || !page || !page.detail || !page.detail.open || page.detail.loading || page.detail.tab !== 'overview') return false;
      const chartsRoot = root.querySelector('.client-detail-overview .client-overview-charts');
      if (!chartsRoot) return false;
      const context = currentDetailContext();
      if (!context) return false;
      let patched = true;
      overviewChartDefinitions(context.client, context.profile, context.merged).forEach((definition) => {
        const payload = overviewChartPayload(definition);
        payload.seriesAll = definition.series;
        const node = chartsRoot.querySelector(`[data-client-overview-chart="${definition.mode}"]`);
        if (!node) {
          patched = false;
          return;
        }
        node.dataset.chartPayload = JSON.stringify(payload);
        const hasData = payload.samples.some((point) => payload.series.some((item) => Number(point[item.key]) > 0));
        let empty = node.querySelector('.client-chart-empty');
        if (hasData && empty) empty.remove();
        if (!hasData && !empty) node.insertAdjacentHTML('beforeend', '<div class="client-chart-empty">等待终端实时采样</div>');
        const card = node.closest('[data-client-overview-card]');
        if (card) {
          const title = card.querySelector('.client-overview-chart-title');
          if (title && title.textContent !== definition.title) title.textContent = definition.title;
          payload.legend.forEach((item) => {
            const button = card.querySelector(`[data-client-overview-legend="${item.key}"]`);
            if (!button) return;
            button.classList.toggle('is-active', item.active);
            button.classList.toggle('is-muted', !item.active);
            button.setAttribute('aria-pressed', item.active ? 'true' : 'false');
          });
        }
      });
      if (!patched) return false;
      scheduleOverviewChartsRender(180);
      return true;
    }

    function patchConnectionDetailPanel() {
      if (!root || !page || !page.detail || !page.detail.open || page.detail.loading || page.detail.tab !== 'connection') return false;
      const panel = root.querySelector('.client-connection-panel');
      if (!panel) return false;
      const context = currentDetailContext();
      if (!context) return false;
      const state = connectionPanelState(context.client, context.profile, context.merged);
      const count = panel.querySelector('.client-connection-count');
      if (count) {
        count.innerHTML = `<strong>共 ${escapeHtml(formatInteger(state.filtered.length))} 条</strong>${state.rows.length !== state.filtered.length ? `<span>已从 ${escapeHtml(formatInteger(state.rows.length))} 条筛选</span>` : ''}${state.notice ? `<em>${escapeHtml(state.notice)}</em>` : ''}`;
      }
      const host = panel.querySelector('.client-connection-table-host');
      if (!host) return false;
      const scroll = host.querySelector('.client-connection-table-scroll');
      const scrollTop = scroll ? scroll.scrollTop : 0;
      const scrollLeft = scroll ? scroll.scrollLeft : 0;
      const nextMarkup = state.filtered.length
        ? connectionTableMarkup(state.filtered, state.columns)
        : detailEmpty(state.rows.length ? '当前筛选条件下没有连接。' : '后端暂未返回该终端的连接明细。');
      const nextSignature = connectionStructureSignature(state.filtered, state.columns);
      const nextColumnsSignature = connectionColumnsSignature(state.columns);
      if (state.filtered.length && host.querySelector('.client-connection-table') && host.dataset.clientConnectionColumns === nextColumnsSignature) {
        patchConnectionTableRows(host, state.filtered, state.columns);
        host.dataset.clientConnectionSignature = nextSignature;
      } else if (host.dataset.clientConnectionSignature !== nextSignature || host.dataset.clientConnectionColumns !== nextColumnsSignature) {
        host.innerHTML = nextMarkup;
        host.dataset.clientConnectionSignature = nextSignature;
        host.dataset.clientConnectionColumns = nextColumnsSignature;
        const nextScroll = host.querySelector('.client-connection-table-scroll');
        if (nextScroll) {
          nextScroll.scrollTop = scrollTop;
          nextScroll.scrollLeft = scrollLeft;
          window.requestAnimationFrame(() => {
            nextScroll.scrollTop = scrollTop;
            nextScroll.scrollLeft = scrollLeft;
          });
        }
      }
      return true;
    }

    function patchProtocolDetailPanel() {
      if (!root || !page || !page.detail || !page.detail.open || page.detail.loading || page.detail.tab !== 'protocol') return false;
      const panel = root.querySelector('.client-protocol-panel');
      if (!panel) return false;
      const context = currentDetailContext();
      if (!context) return false;
      const rows = protocolRows(context.profile, context.merged || context.client);
      const mode = page.protocolChartMode === 'curve' ? 'curve' : 'stacked';
      const samples = protocolRateSamples(context.profile, rows);
      let patched = true;
      [['up', '上行速率'], ['down', '下行速率']].forEach(([direction, title]) => {
        const node = panel.querySelector(`[data-client-protocol-chart="${direction}"]`);
        if (!node) {
          patched = false;
          return;
        }
        const payload = protocolRatePayload(title, samples, direction, mode);
        node.dataset.chartPayload = JSON.stringify(payload);
        const hasData = payload.samples.some((point) => payload.legend.some((item) => item.active !== false && Number(point.values && point.values[item.key]) > 0));
        let empty = node.querySelector('.client-chart-empty');
        if (hasData && empty) empty.remove();
        if (!hasData && !empty) node.insertAdjacentHTML('beforeend', '<div class="client-chart-empty">等待协议实时采样</div>');
      });
      panel.querySelectorAll('[data-client-protocol-category]').forEach((button) => {
        const key = button.dataset.clientProtocolCategory;
        const active = !page.protocolLegend || page.protocolLegend[key] !== false;
        button.classList.toggle('is-active', active);
        button.classList.toggle('is-muted', !active);
        button.setAttribute('aria-pressed', active ? 'true' : 'false');
      });
      const notice = firstText(page.protocolControlNotice);
      const title = panel.querySelector('[data-client-protocol-list-title]');
      if (title) {
        let noticeNode = title.querySelector('em');
        if (notice && !noticeNode) {
          title.insertAdjacentHTML('beforeend', `<em>${escapeHtml(notice)}</em>`);
        } else if (noticeNode && notice) {
          noticeNode.textContent = notice;
        } else if (noticeNode) {
          noticeNode.remove();
        }
      }
      if (!patched) return false;
      renderProtocolCharts();
      return true;
    }

    function scheduleOverviewChartsRender(delay = 0) {
      if (!page || !page.active) return;
      window.clearTimeout(page.overviewChartTimer);
      page.overviewChartTimer = window.setTimeout(renderOverviewCharts, delay);
    }

    function scheduleProtocolChartsRender(delay = 0) {
      if (!page || !page.active) return;
      window.clearTimeout(page.protocolChartTimer);
      page.protocolChartTimer = window.setTimeout(renderProtocolCharts, delay);
    }

    function detailEmpty(text) {
      return `<div class="client-detail-empty">${escapeHtml(text)}</div>`;
    }

    const FINGERPRINT_CATEGORY_FALLBACK = [
      { key: 'all', label: '全部品牌', apiCategory: 'all' },
      { key: 'unknown', label: '未知设备', apiCategory: 'unknown' },
      { key: 'phone', label: '手机', apiCategory: 'phone' },
      { key: 'tablet', label: '平板', apiCategory: 'tablet' },
      { key: 'computer', label: '电脑', apiCategory: 'computer' },
      { key: 'router', label: '网络/路由', apiCategory: 'router' },
      { key: 'nas', label: 'NAS/存储', apiCategory: 'nas' },
      { key: 'speaker', label: '音箱/音频', apiCategory: 'speaker' },
      { key: 'media', label: '电视/媒体', apiCategory: 'iot', queryHint: 'tv' },
      { key: 'printer', label: '打印机', apiCategory: 'iot', queryHint: 'printer' },
      { key: 'camera', label: '摄像头', apiCategory: 'iot', queryHint: 'camera' },
      { key: 'watch', label: '可穿戴', apiCategory: 'watch', queryHint: 'watch wearable band' },
      { key: 'game', label: '游戏机', apiCategory: 'game' },
      { key: 'iot', label: '智能家居', apiCategory: 'iot' },
      { key: 'server', label: '虚拟化/服务器', apiCategory: 'server' }
    ];

    function normalizeFingerprintCategory(item) {
      if (!item) return null;
      let key = '';
      let label = '';
      let apiCategory = '';
      let queryHint = '';
      if (Array.isArray(item)) {
        key = firstText(item[0]).toLowerCase();
        label = firstText(item[1], item[0]);
      } else {
        key = firstText(item.key, item.value, item.category, item.id).toLowerCase();
        label = firstText(item.label, item.name, item.title, key);
        apiCategory = firstText(item.apiCategory, item.api_category, item.backend_category, item.category, key);
        queryHint = firstText(item.queryHint, item.query_hint, item.filter, '');
      }
      if (key === 'wearable') key = 'watch';
      if (!key || !label) return null;
      if (key === 'watch') label = '可穿戴';
      return {
        key,
        label,
        apiCategory: firstText(apiCategory, key),
        queryHint
      };
    }

    function fingerprintCategoryObjects() {
      const source = page && page.fingerprint && Array.isArray(page.fingerprint.categories) && page.fingerprint.categories.length
        ? page.fingerprint.categories
        : [];
      const byKey = new Map();
      [...FINGERPRINT_CATEGORY_FALLBACK, ...source].forEach((item) => {
        const normalized = normalizeFingerprintCategory(item);
        if (!normalized) return;
        const fallback = FINGERPRINT_CATEGORY_FALLBACK.find((entry) => entry.key === normalized.key) || {};
        const previous = byKey.get(normalized.key) || {};
        byKey.set(normalized.key, { ...fallback, ...previous, ...normalized });
      });
      return [...byKey.values()];
    }

    function fingerprintCategories() {
      return fingerprintCategoryObjects().map((item) => [item.key, item.label]);
    }

    function fingerprintCategoryConfig(key) {
      const text = String(key || '').toLowerCase();
      return fingerprintCategoryObjects().find((item) => item.key === text)
        || FINGERPRINT_CATEGORY_FALLBACK.find((item) => item.key === text)
        || { key: text || 'unknown', label: '未知设备', apiCategory: text || 'unknown' };
    }

    function fingerprintCategoryFromType(value) {
      const text = String(value || '').toLowerCase();
      if (/smartphone|phone|iphone|android/.test(text)) return 'phone';
      if (/tablet|ipad/.test(text)) return 'tablet';
      if (/nas|storage|diskstation|rackstation/.test(text)) return 'nas';
      if (/router|gateway|firewall|access point|\bap\b|switch|network/.test(text)) return 'router';
      if (/speaker|audio|soundbar|homepod/.test(text)) return 'speaker';
      if (/media|\btv\b|television|set[ -]?top|ipod|player/.test(text)) return 'media';
      if (/printer/.test(text)) return 'printer';
      if (/camera|nvr|dvr|doorbell/.test(text)) return 'camera';
      if (/watch|wearable|band|bracelet|wear\s*os|fitbit|garmin|mi\s*band|amazfit|手表|手环|穿戴/.test(text)) return 'watch';
      if (/computer|desktop|laptop|pc|mac|windows|linux/.test(text)) return 'computer';
      if (/game|console|xbox|playstation|nintendo/.test(text)) return 'game';
      if (/hypervisor|server|virtual|vm|esxi|vcenter/.test(text)) return 'server';
      if (/iot|smart|sensor|thermostat|lighting|home/.test(text)) return 'iot';
      return 'unknown';
    }

    function formDeviceTypeFromFingerprint(item = {}) {
      const text = `${item.device_type || ''} ${item.raw_device_type || ''} ${item.category || ''} ${item.family || ''} ${item.device_name || ''} ${item.os_class || ''} ${item.os_name || ''}`.toLowerCase();
      if (/smartphone|phone|iphone|android/.test(text)) return 'smartphone';
      if (/tablet|ipad/.test(text)) return 'tablet';
      if (/game|console|xbox|playstation|nintendo/.test(text)) return 'game_console';
      if (/hypervisor|server|virtual|vm|esxi|vcenter/.test(text)) return 'hypervisor';
      if (/nas|storage|diskstation|rackstation/.test(text)) return 'nas';
      if (/router|gateway|network|access point|switch|firewall/.test(text)) return 'router';
      if (/printer/.test(text)) return 'printer';
      if (/camera|nvr|dvr|doorbell/.test(text)) return 'camera';
      if (/speaker|audio|soundbar|homepod/.test(text)) return 'speaker';
      if (/media|\btv\b|television|set[ -]?top|ipod|player/.test(text)) return 'media_player';
      if (/watch|wearable|band|bracelet|wear\s*os|fitbit|garmin|mi\s*band|amazfit|手表|手环|穿戴/.test(text)) return 'watch';
      if (/desktop|laptop|computer|pc|macbook|windows|linux/.test(text)) return 'computer';
      if (/iot|smart|sensor|thermostat|lighting|home/.test(text)) return 'iot';
      return item.device_type || item.category || 'unknown';
    }

    function categoryLabel(key) {
      return fingerprintCategoryConfig(key).label || '未知设备';
    }

    function visitRows(profile) {
      return rawList(profile.visits || profile.visit_list || profile.protocols || profile.apps || profile.active_apps);
    }

    function sessionRows(profile) {
      return rawList(profile.sessions || profile.flows || profile.connections || profile.conntrack);
    }

    function recordRows(profile) {
      return rawList(profile.records || profile.online_records || profile.history || profile.events);
    }

    function normalizeProtocolKey(value) {
      const text = firstText(value).trim().toLowerCase();
      if (!text) return '';
      if (text === '6') return 'tcp';
      if (text === '17') return 'udp';
      if (text === '1') return 'icmp';
      if (text.includes('tcp')) return 'tcp';
      if (text.includes('udp')) return 'udp';
      if (text.includes('icmp')) return 'icmp';
      return text;
    }

    function normalizeAppLabel(value, proto = '') {
      const text = firstText(value).trim();
      if (!text) return '';
      const lowered = text.toLowerCase();
      if (proto && lowered === proto) return '';
      if (['tcp', 'udp', 'icmp', 'ipv4', 'ipv6', 'ip'].includes(lowered)) return '';
      if (/^(proto|protocol|unknown|--|-)$/.test(lowered)) return '';
      return text;
    }

    function guessAppName(item = {}, proto = '') {
      const explicit = [
        item.app_name, item.appname, item.application_name, item.application, item.app,
        item.service_name, item.service, item.category_name, item.app_category,
        item.process_name, item.program, item.package_name
      ];
      for (const value of explicit) {
        const label = normalizeAppLabel(value, proto);
        if (label) return label;
      }
      const domain = firstText(item.domain, item.host, item.hostname, item.sni, item.server_name, item.fqdn);
      if (domain) return domain;
      const port = Number(firstText(item.dst_port, item.dport, item.destination_port, item.remote_port, item.port)) || 0;
      if (port === 443) return proto === 'udp' ? 'QUIC' : 'HTTPS';
      const map = { 53: 'DNS', 80: 'HTTP', 123: 'NTP', 5223: 'Apple Push', 1883: 'MQTT', 8883: 'MQTT TLS' };
      if (map[port]) return map[port];
      if (proto === 'icmp') return 'ICMP';
      return '--';
    }

    function protocolCategoryFor(item = {}, appName = '', proto = '') {
      const explicitKey = firstText(item.category_key, item.app_category_key, item.group_key, item.class_key).trim().toLowerCase();
      if (explicitKey) {
        const byKey = PROTOCOL_CATEGORIES.find((category) => category.key === explicitKey);
        if (byKey) return byKey;
      }
      const explicit = firstText(
        item.category_label, item.category_name, item.app_category_name, item.app_category,
        item.group_label, item.group_name, item.group, item.type_label, item.type_name, item.class_name,
        item.category, item.type, explicitKey
      );
      const cleanExplicit = normalizeAppLabel(explicit, proto);
      if (cleanExplicit) {
        const byLabel = PROTOCOL_CATEGORIES.find((category) => category.label === cleanExplicit || cleanExplicit.includes(category.label));
        if (byLabel) return byLabel;
      }
      const text = [cleanExplicit, explicitKey, appName, proto, item.protocol_name, item.name, item.domain, item.host, item.remark, item.desc, item.description]
        .filter(Boolean).join(' ');
      const matched = PROTOCOL_CATEGORIES.find((category) => category.match.test(text));
      if (matched) return matched;
      return PROTOCOL_CATEGORIES[PROTOCOL_CATEGORIES.length - 1];
    }

    function protocolName(item = {}, proto = '') {
      const fields = [
        item.protocol_name, item.protocolName, item.app_name, item.appname, item.application_name,
        item.application, item.app, item.name, item.service_name, item.service, item.tagname,
        item.domain, item.host, item.hostname, item.sni, item.fqdn, item.url_host
      ];
      for (const value of fields) {
        const label = normalizeAppLabel(value, proto);
        if (label) return label;
      }
      const guessed = guessAppName(item, proto);
      return guessed && guessed !== '--' ? guessed : firstText(proto ? proto.toUpperCase() : '', '--');
    }

    function protocolRateValue(item = {}, direction = 'up') {
      const keys = direction === 'up'
        ? ['up_rate', 'rate_up', 'tx_rate', 'upload_rate', 'upload_speed', 'upload_bps', 'up_bps', 'tx_bps', 'upload_per_second', 'up_bytes_per_sec', 'upload_bytes_per_sec', 'up']
        : ['down_rate', 'rate_down', 'rx_rate', 'download_rate', 'download_speed', 'download_bps', 'down_bps', 'rx_bps', 'download_per_second', 'down_bytes_per_sec', 'download_bytes_per_sec', 'down'];
      for (const key of keys) {
        if (item[key] === undefined || item[key] === null || item[key] === '') continue;
        return Math.max(0, numericValue(item[key]));
      }
      return 0;
    }

    function protocolByteValue(item = {}, direction = '') {
      const keys = direction === 'up'
        ? ['up_bytes', 'upload_bytes', 'bytes_up', 'tx_bytes', 'sent_bytes', 'total_up', 'upload_total']
        : direction === 'down'
          ? ['down_bytes', 'download_bytes', 'bytes_down', 'rx_bytes', 'received_bytes', 'total_down', 'download_total']
          : ['total_bytes', 'total_traffic', 'traffic', 'bytes', 'flow_bytes', 'total', 'sum_bytes'];
      for (const key of keys) {
        if (item[key] === undefined || item[key] === null || item[key] === '') continue;
        return Math.max(0, numericValue(item[key]));
      }
      return 0;
    }

    function normalizeProtocolRow(item = {}, index = 0) {
      if (typeof item !== 'object' || !item) item = { name: firstText(item, '--') };
      const proto = normalizeProtocolKey(firstText(item.proto, item.protocol, item.l4_proto, item.ip_proto, item.transport, item.protocol_type));
      const name = protocolName(item, proto);
      const category = protocolCategoryFor(item, name, proto);
      const upBytes = protocolByteValue(item, 'up');
      const downBytes = protocolByteValue(item, 'down');
      const totalBytes = protocolByteValue(item) || upBytes + downBytes;
      const connections = Math.max(0, firstNumber(
        item.connections, item.conn_count, item.conn_cnt, item.connection_count, item.connect_num,
        item.conn_num, item.sessions, item.session_count, item.flow_count, item.flows, item.total_connections
      ));
      return {
        index,
        raw: item,
        key: firstText(item.key, item.id, item.appid, `${category.key}-${name}-${proto || index}`),
        name,
        type: firstText(category.label, item.type_name, item.category_name, '--'),
        categoryKey: category.key,
        categoryLabel: category.label,
        color: category.color,
        proto: proto || firstText(item.proto, item.protocol, '--'),
        connections,
        upRate: protocolRateValue(item, 'up'),
        downRate: protocolRateValue(item, 'down'),
        upBytes,
        downBytes,
        totalBytes,
        domain: firstText(item.domain, item.host, item.hostname, item.sni, item.fqdn, item.url, '')
      };
    }

    function aggregateProtocolRows(rows) {
      const byKey = new Map();
      rows.forEach((row) => {
        const key = [row.name, row.categoryKey, row.proto].join('|').toLowerCase();
        const current = byKey.get(key);
        if (!current) {
          byKey.set(key, { ...row });
          return;
        }
        current.connections += Number(row.connections) || 0;
        current.upRate += Number(row.upRate) || 0;
        current.downRate += Number(row.downRate) || 0;
        current.upBytes += Number(row.upBytes) || 0;
        current.downBytes += Number(row.downBytes) || 0;
        current.totalBytes += Number(row.totalBytes) || 0;
        if (!current.domain && row.domain) current.domain = row.domain;
      });
      return Array.from(byKey.values()).sort((a, b) => {
        const trafficDelta = (Number(b.totalBytes) || 0) - (Number(a.totalBytes) || 0);
        if (trafficDelta) return trafficDelta;
        const connDelta = (Number(b.connections) || 0) - (Number(a.connections) || 0);
        if (connDelta) return connDelta;
        return String(a.name).localeCompare(String(b.name), 'zh-Hans-CN', { numeric: true, sensitivity: 'base' });
      });
    }

    function protocolSourceRows(profile = {}) {
      const sources = [
        profile.protocols, profile.protocol_list, profile.protocol_details, profile.protocol_stats,
        profile.apps, profile.applications, profile.app_stats, profile.active_apps, profile.visits, profile.visit_list,
        profile.protocol_summary && profile.protocol_summary.items,
        profile.protocol_summary && profile.protocol_summary.protocols,
        profile.protocol_summary && profile.protocol_summary.rows,
        profile.current && profile.current.protocols,
        profile.current && profile.current.protocol_stats,
        profile.current && profile.current.apps
      ];
      const rows = [];
      sources.forEach((source) => rows.push(...rawList(source)));
      return rows;
    }

    function protocolRows(profile = {}, client = {}) {
      let rows = protocolSourceRows(profile).map(normalizeProtocolRow).filter((row) => row.name && row.name !== '--');
      if (!rows.length) {
        rows = connectionRows(profile, client).map((connection, index) => normalizeProtocolRow({
          key: `conn-${index}`,
          app: connection.app,
          app_name: connection.app,
          proto: connection.proto,
          domain: connection.domain && connection.domain !== '--' ? connection.domain : '',
          dst_port: connection.dstPort,
          up_bytes: connection.upBytes,
          down_bytes: connection.downBytes,
          connections: 1,
          type: connection.protoKey === 'icmp' ? '网络协议' : ''
        }, index));
      }
      return aggregateProtocolRows(rows);
    }

    function protocolBuckets(rows, metric = 'traffic') {
      const buckets = PROTOCOL_CATEGORIES.map((category) => ({ ...category, value: 0 }));
      const byKey = new Map(buckets.map((bucket) => [bucket.key, bucket]));
      rows.forEach((row) => {
        const bucket = byKey.get(row.categoryKey) || byKey.get('unknown');
        if (!bucket) return;
        bucket.value += metric === 'connections'
          ? Math.max(0, Number(row.connections) || 0)
          : Math.max(0, Number(row.totalBytes) || Number(row.upBytes || 0) + Number(row.downBytes || 0));
      });
      return buckets;
    }

    function percentLabel(value, total) {
      if (!total) return '0.00%';
      return `${((Number(value) || 0) / total * 100).toFixed(2)}%`;
    }

    function donutSegments(buckets, total) {
      const radius = 58;
      const circumference = 2 * Math.PI * radius;
      let offset = 0;
      return buckets.filter((bucket) => bucket.value > 0 && total > 0).map((bucket) => {
        const rawLength = Math.max(0, (bucket.value / total) * circumference);
        const length = Math.max(0, rawLength - 2.4);
        const segment = `<circle class="client-protocol-donut-segment" cx="90" cy="90" r="${radius}" stroke="${escapeHtml(bucket.color)}" stroke-dasharray="${length.toFixed(2)} ${Math.max(0, circumference - length).toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}"></circle>`;
        offset += rawLength;
        return segment;
      }).join('');
    }

    function protocolDonutCard(title, centerLabel, buckets, metric) {
      const total = buckets.reduce((sum, bucket) => sum + (Number(bucket.value) || 0), 0);
      const centerValue = metric === 'connections' ? formatInteger(total) : formatBytes(total);
      return `<section class="client-protocol-donut-card client-detail-card">
        <div class="client-protocol-card-title">${escapeHtml(title)}</div>
        <div class="client-protocol-donut-layout">
          <div class="client-protocol-donut" role="img" aria-label="${escapeHtml(title)}">
            <svg viewBox="0 0 180 180" aria-hidden="true">
              <circle class="client-protocol-donut-track" cx="90" cy="90" r="58"></circle>
              <g transform="rotate(-90 90 90)">${donutSegments(buckets, total)}</g>
            </svg>
            <div class="client-protocol-donut-center"><span>${escapeHtml(centerLabel)}</span><strong>${escapeHtml(centerValue)}</strong></div>
          </div>
          <div class="client-protocol-donut-legend">
            ${buckets.map((bucket) => `<div class="client-protocol-legend-row" title="${escapeHtml(bucket.label)} ${escapeHtml(percentLabel(bucket.value, total))}">
              <i style="--protocol-color:${escapeHtml(bucket.value ? bucket.color : 'rgba(255,255,255,0.12)')}"></i>
              <span>${escapeHtml(bucket.label)}</span>
              <strong>${escapeHtml(percentLabel(bucket.value, total))}</strong>
            </div>`).join('')}
          </div>
        </div>
      </section>`;
    }

    function protocolHistoryRows(profile = {}) {
      const sources = [
        profile.protocol_rate_history, profile.protocol_history, profile.app_rate_history,
        profile.protocol_summary && profile.protocol_summary.rate_history,
        profile.protocol_summary && profile.protocol_summary.history,
        profile.current && profile.current.protocol_rate_history,
        profile.current && profile.current.protocol_history
      ];
      for (const source of sources) {
        const rows = rawList(source);
        if (rows.length) return rows;
      }
      return [];
    }

    function blankProtocolPoint(ts) {
      const values = {};
      PROTOCOL_CATEGORIES.forEach((category) => { values[category.key] = { up: 0, down: 0 }; });
      return { ts, values };
    }

    function addProtocolPointValue(point, row) {
      const key = row.categoryKey || 'unknown';
      if (!point.values[key]) point.values[key] = { up: 0, down: 0 };
      point.values[key].up += Math.max(0, Number(row.upRate) || 0);
      point.values[key].down += Math.max(0, Number(row.downRate) || 0);
    }

    function normalizeProtocolHistorySample(item = {}, index = 0, length = 1) {
      const point = blankProtocolPoint(sampleTimestamp(item, Math.floor(Date.now() / 1000) - Math.max(0, length - index - 1) * 5));
      const candidates = rawList(item.items || item.rows || item.list || item.protocols || item.apps || item.categories);
      if (candidates.length) {
        candidates.map(normalizeProtocolRow).forEach((row) => addProtocolPointValue(point, row));
        return point;
      }
      const categoryMap = item.categories && typeof item.categories === 'object' && !Array.isArray(item.categories) ? item.categories : null;
      if (categoryMap) {
        Object.entries(categoryMap).forEach(([key, value]) => {
          const category = PROTOCOL_CATEGORIES.find((item) => item.key === key || item.label === key) || protocolCategoryFor({ category: key }, key, '');
          const obj = value && typeof value === 'object' ? value : { value };
          if (!point.values[category.key]) point.values[category.key] = { up: 0, down: 0 };
          point.values[category.key].up += protocolRateValue(obj, 'up') || numericValue(obj.upload || obj.up || obj.value || 0);
          point.values[category.key].down += protocolRateValue(obj, 'down') || numericValue(obj.download || obj.down || obj.value || 0);
        });
        return point;
      }
      addProtocolPointValue(point, normalizeProtocolRow(item, index));
      return point;
    }

    function protocolRateSamples(profile = {}, rows = []) {
      const raw = protocolHistoryRows(profile);
      let samples = raw.map((item, index) => normalizeProtocolHistorySample(item, index, raw.length))
        .filter((point) => Number.isFinite(point.ts))
        .sort((a, b) => a.ts - b.ts);
      const now = Math.floor(Date.now() / 1000);
      if (!samples.length) {
        const base = blankProtocolPoint(now);
        rows.forEach((row) => addProtocolPointValue(base, row));
        samples = Array.from({ length: 36 }, (_, index) => {
          const point = blankProtocolPoint(now - (35 - index) * 5);
          PROTOCOL_CATEGORIES.forEach((category) => {
            point.values[category.key].up = base.values[category.key].up;
            point.values[category.key].down = base.values[category.key].down;
          });
          return point;
        });
      }
      return samples.slice(-72);
    }

    function protocolRatePayload(title, samples, direction, mode) {
      const legendState = page && page.protocolLegend ? page.protocolLegend : parseProtocolLegend();
      const normalized = asArray(samples).map((sample) => {
        const values = {};
        PROTOCOL_CATEGORIES.forEach((category) => {
          values[category.key] = Math.max(0, Number(sample.values && sample.values[category.key] && sample.values[category.key][direction]) || 0);
        });
        return { ts: Number(sample.ts) || 0, values };
      });
      return {
        title,
        direction,
        mode: mode === 'curve' ? 'curve' : 'stacked',
        samples: normalized,
        legend: PROTOCOL_CATEGORIES.map((category) => ({
          key: category.key,
          label: category.label,
          color: category.color,
          active: legendState[category.key] !== false
        }))
      };
    }

    function protocolChartYAxisMax(direction, mode, rawMax) {
      const max = Math.max(0, Number(rawMax) || 0);
      if (!page) return max > 0 ? niceMax(max) : undefined;
      const store = page.protocolAxisMax || (page.protocolAxisMax = {});
      const key = `${direction || 'rate'}:${mode || 'stacked'}`;
      const now = Date.now();
      const current = store[key] || { value: 0, at: 0 };
      if (max <= 0) {
        store[key] = { value: 0, at: now };
        return undefined;
      }
      const next = niceMax(max);
      if (!current.value || next > current.value * 1.04) {
        store[key] = { value: next, at: now };
        return next;
      }
      if (next < current.value * 0.52 && now - current.at > 14000) {
        store[key] = { value: next, at: now };
        return next;
      }
      return current.value;
    }

    function buildProtocolRateChartOption(payload, source) {
      const samples = asArray(payload.samples);
      const legend = asArray(payload.legend);
      const active = legend.filter((item) => item.active !== false);
      const mode = payload.mode === 'curve' ? 'curve' : 'stacked';
      const palette = echartsPalette(source);
      const textColor = palette.text;
      const splitColor = palette.split;
      const categories = samples.map((point) => chartTimeLabel(Number(point.ts) || 0));
      const visibleLabelIndices = overviewChartVisibleLabelIndices(samples);
      const valueOf = (point, key) => Math.max(0, Number(point.values && point.values[key]) || 0);
      const rawMax = Math.max(0, ...samples.map((point) => {
        if (!active.length) return 0;
        if (mode === 'stacked') return active.reduce((sum, item) => sum + valueOf(point, item.key), 0);
        return Math.max(...active.map((item) => valueOf(point, item.key)));
      }));
      const yMax = protocolChartYAxisMax(payload.direction, mode, rawMax);
      return {
        animation: false,
        animationDuration: 0,
        animationDurationUpdate: 0,
        backgroundColor: 'transparent',
        color: legend.map((item) => item.color),
        grid: { left: 8, right: 18, top: 22, bottom: 8, containLabel: true },
        tooltip: {
          trigger: 'axis',
          appendToBody: true,
          confine: true,
          backgroundColor: 'rgba(16,22,33,.92)',
          borderColor: 'rgba(255,255,255,.14)',
          borderWidth: 1,
          textStyle: { color: '#edf3ff', fontSize: 12, fontWeight: 600 },
          axisPointer: { type: 'line', lineStyle: { color: 'rgba(150,170,220,.42)', width: 1 } },
          formatter(params) {
            const list = Array.isArray(params) ? params.filter((item) => item && Number(item.data) > 0) : [];
            const title = (Array.isArray(params) && params[0] && params[0].axisValue) || '--';
            if (!list.length) return `<strong>${escapeHtml(title)}</strong><br>无流量`;
            return [`<strong>${escapeHtml(title)}</strong>`].concat(list.map((item) => {
              const raw = item && item.data !== undefined ? Number(item.data) || 0 : 0;
              return `${item.marker}${escapeHtml(item.seriesName)}：${escapeHtml(formatRate(raw))}`;
            })).join('<br>');
          }
        },
        legend: {
          show: false,
          data: legend.map((item) => item.label),
          selected: Object.fromEntries(legend.map((item) => [item.label, item.active !== false]))
        },
        xAxis: {
          type: 'category',
          boundaryGap: false,
          data: categories,
          axisLine: { show: false },
          axisTick: { show: false },
          splitLine: { show: false },
          axisLabel: {
            interval: 0,
            rotate: 0,
            color: textColor,
            fontSize: 11,
            fontWeight: 650,
            margin: 12,
            formatter(value, index) { return visibleLabelIndices.has(index) ? String(value).slice(0, 5) : ''; }
          }
        },
        yAxis: {
          type: 'value',
          min: 0,
          max: yMax,
          interval: yMax ? yMax / 4 : undefined,
          scale: false,
          splitNumber: 4,
          axisLine: { show: false },
          axisTick: { show: false },
          splitLine: { lineStyle: { color: splitColor, type: 'dashed', width: 1 } },
          axisLabel: {
            color: textColor,
            fontSize: 11,
            fontWeight: 650,
            margin: 10,
            formatter(value) { return formatRate(Number(value) || 0); }
          }
        },
        series: legend.map((item) => {
          const on = item.active !== false;
          return {
            name: item.label,
            type: 'line',
            stack: mode === 'stacked' && on ? 'protocol-total' : undefined,
            showSymbol: false,
            smooth: 0.28,
            connectNulls: true,
            clip: true,
            lineStyle: { width: mode === 'stacked' ? 1.25 : 2.1, color: item.color, opacity: on ? 0.96 : 0 },
            itemStyle: { color: item.color },
            areaStyle: on ? { color: item.color, opacity: mode === 'stacked' ? 0.18 : 0.07 } : undefined,
            emphasis: { focus: 'series', lineStyle: { width: 2.8 } },
            data: on ? samples.map((point) => valueOf(point, item.key)) : []
          };
        })
      };
    }

    function protocolRateChart(title, samples, direction, mode) {
      const payload = protocolRatePayload(title, samples, direction, mode);
      const hasData = payload.samples.some((point) => payload.legend.some((item) => item.active !== false && Number(point.values && point.values[item.key]) > 0));
      return `<div class="client-protocol-rate-chart" data-client-protocol-chart="${escapeHtml(direction)}" data-chart-payload="${escapeHtml(JSON.stringify(payload))}">
        <div class="client-protocol-rate-title">${escapeHtml(title)}</div>
        <div class="client-protocol-echart" aria-label="${escapeHtml(title)}"></div>
        ${hasData ? '' : `<div class="client-chart-empty">等待协议实时采样</div>`}
      </div>`;
    }

    function protocolRateSection(samples, mode) {
      const legend = page && page.protocolLegend ? page.protocolLegend : parseProtocolLegend();
      return `<section class="client-protocol-rate-card client-detail-card">
        <div class="client-protocol-line-wrap">
          ${protocolRateChart('上行速率', samples, 'up', mode)}
          ${protocolRateChart('下行速率', samples, 'down', mode)}
        </div>
        <div class="client-protocol-slider" aria-hidden="true"><span></span><i class="is-left"></i><i class="is-right"></i></div>
        <div class="client-protocol-chart-legend" role="group" aria-label="协议速率图例">
          ${PROTOCOL_CATEGORIES.map((category) => {
            const active = legend[category.key] !== false;
            return `<button class="${active ? 'is-active' : 'is-muted'}" type="button" data-client-protocol-category="${escapeHtml(category.key)}" aria-pressed="${active ? 'true' : 'false'}"><i style="--protocol-color:${escapeHtml(category.color)}"></i><span>${escapeHtml(category.label)}</span></button>`;
          }).join('')}
        </div>
      </section>`;
    }

    function protocolListTable(rows) {
      const total = rows.reduce((sum, row) => sum + Math.max(0, Number(row.totalBytes) || 0), 0);
      if (!rows.length) return detailEmpty('后端暂未返回协议明细；前端也没有可聚合的连接记录。');
      return `<div class="client-protocol-table-scroll">
        <table class="client-protocol-table">
          <thead><tr><th>协议名称</th><th>类型</th><th>连接数</th><th>上行速率</th><th>下行速率</th><th>累计流量</th><th>操作</th></tr></thead>
          <tbody>${rows.slice(0, 80).map((row) => {
            const share = total ? Math.max(0, Number(row.totalBytes) || 0) / total * 100 : 0;
            return `<tr>
              <td><span class="client-protocol-name"><strong>${escapeHtml(row.name)}</strong>${row.domain ? `<small>${escapeHtml(row.domain)}</small>` : ''}</span></td>
              <td>${escapeHtml(row.type || row.categoryLabel || '--')}</td>
              <td>${escapeHtml(formatInteger(row.connections))}</td>
              <td class="rate-up">${escapeHtml(formatRate(row.upRate))}</td>
              <td class="rate-down">${escapeHtml(formatRate(row.downRate))}</td>
              <td><span class="client-protocol-traffic"><strong>${escapeHtml(percentLabel(row.totalBytes, total))}（${escapeHtml(formatBytes(row.totalBytes))}）</strong><i><b style="width:${share.toFixed(2)}%"></b></i></span></td>
              <td><button type="button" data-client-protocol-control="${escapeHtml(row.key)}">添加协议控制</button></td>
            </tr>`;
          }).join('')}</tbody>
        </table>
      </div>`;
    }

    function protocolPanel(client, profile, merged) {
      const rows = protocolRows(profile, merged || client);
      const trafficBuckets = protocolBuckets(rows, 'traffic');
      const connectionBuckets = protocolBuckets(rows, 'connections');
      const mode = page.protocolChartMode === 'curve' ? 'curve' : 'stacked';
      const nextLabel = mode === 'stacked' ? '曲线图' : '堆叠图';
      const samples = protocolRateSamples(profile, rows);
      const notice = firstText(page.protocolControlNotice);
      return `<div class="client-protocol-panel">
        <div class="client-protocol-section-title"><span>协议流量/连接数分布</span></div>
        <div class="client-protocol-overview">
          ${protocolDonutCard('协议分类流量', '总流量', trafficBuckets, 'traffic')}
          ${protocolDonutCard('协议分类连接数', '总连接数', connectionBuckets, 'connections')}
        </div>
        <div class="client-protocol-section-title"><span>协议速率</span><button type="button" data-client-protocol-chart-mode="${escapeHtml(mode === 'stacked' ? 'curve' : 'stacked')}"><svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 13c2.4-6 4.6-6 7 0s4.6 6 7 0M4 7h12"></path></svg>${escapeHtml(nextLabel)}</button></div>
        ${protocolRateSection(samples, mode)}
        <div class="client-protocol-section-title" data-client-protocol-list-title><span>协议列表</span>${notice ? `<em>${escapeHtml(notice)}</em>` : ''}</div>
        ${protocolListTable(rows)}
      </div>`;
    }

    function connectionByteValue(item, keys) {
      for (const key of keys) {
        const value = item && item[key];
        if (value === undefined || value === null || value === '') continue;
        const numeric = typeof value === 'number' ? value : Number(String(value).replace(/,/g, ''));
        if (Number.isFinite(numeric)) return Math.max(0, numeric);
        const text = firstText(value);
        if (text) return text;
      }
      return 0;
    }

    function formatConnectionBytes(value) {
      if (typeof value === 'number') return formatBytes(value);
      const text = firstText(value);
      return text || '--';
    }

    function statusInfo(item = {}) {
      const raw = firstText(item.status, item.state, item.conn_state, item.tcp_state, item.connection_state, item.connected);
      const lowered = String(raw).toLowerCase();
      const connected = item.connected === true || item.online === true || ['established', 'connected', 'assured', 'seen_reply', 'syn_recv', 'syn_sent', 'time_wait', 'close_wait', '已连接'].includes(lowered);
      if (connected) return { label: '已连接', connected: true };
      if (raw && !['0', 'false', 'none', 'unknown'].includes(lowered)) return { label: raw, connected: false };
      return { label: '--', connected: false };
    }

    function normalizeConnection(item = {}, index = 0, client = {}) {
      const proto = normalizeProtocolKey(firstText(item.proto, item.protocol, item.l4_proto, item.ip_proto, item.transport, item.type));
      const status = statusInfo(item);
      const externalIp = firstText(
        item.external_ip, item.wan_ip, item.src_nat_ip, item.snat_ip, item.public_ip,
        item.nat_ip, item.outer_ip, item.src_ip, item.source_ip, item.local_ip, item.client_ip,
        client.ip
      );
      const line = firstText(
        item.line_label, item.line_name, item.wan_label, item.wan_name, item.line, item.wan,
        item.iface_name, item.ifname, item.interface, item.out_iface, item.egress_if,
        item.dev, item.device,
        '--'
      );
      const row = {
        index,
        raw: item,
        id: firstText(item.id, item.conn_id, item.connection_id, item.flow_id, item.uuid, item.ct_id, item.handle, item.key),
        app: guessAppName(item, proto),
        proto: proto || '--',
        protoKey: proto || 'other',
        line,
        lineKey: line,
        externalIp: externalIp || '--',
        domain: firstText(item.domain, item.host, item.hostname, item.sni, item.server_name, item.fqdn, item.url, '--'),
        srcPort: firstText(item.src_port, item.sport, item.source_port, item.local_port, item.orig_sport, '--'),
        dstIp: firstText(item.dst_ip, item.destination_ip, item.dest_ip, item.dst, item.destination, item.remote_ip, item.server_ip, item.ip, '--'),
        dstPort: firstText(item.dst_port, item.dport, item.destination_port, item.remote_port, item.port, '--'),
        upBytes: connectionByteValue(item, ['up_bytes', 'tx_bytes', 'upload_bytes', 'upload', 'bytes_up', 'orig_bytes', 'sent_bytes']),
        downBytes: connectionByteValue(item, ['down_bytes', 'rx_bytes', 'download_bytes', 'download', 'bytes_down', 'reply_bytes', 'received_bytes']),
        upRate: protocolRateValue(item, 'up'),
        downRate: protocolRateValue(item, 'down'),
        status: status.label,
        connected: status.connected
      };
      row.signature = connectionSignature(row);
      return row;
    }

    function connectionSignature(row = {}) {
      const tuple = [
        row.protoKey || row.proto,
        row.externalIp,
        row.srcPort,
        row.dstIp,
        row.dstPort
      ].map((item) => String(item || '').trim()).join('|');
      const hasTuple = [row.protoKey || row.proto, row.srcPort, row.dstIp, row.dstPort].some((item) => firstText(item));
      if (hasTuple) return tuple;
      const id = firstText(row.id);
      if (id) return `id:${id}`;
      return [row.index, row.protoKey || row.proto, row.lineKey || row.line, row.externalIp, row.domain, row.app]
        .map((item) => String(item || '').trim()).join('|');
    }

    function connectionRows(profile, client = {}) {
      const rows = [];
      const sources = [
        profile.connections, profile.connection_rows, profile.connection_details,
        profile.sessions, profile.flows, profile.conntrack,
        profile.current && profile.current.connections,
        profile.current && profile.current.sessions,
        profile.current && profile.current.flows
      ];
      for (const source of sources) {
        const list = rawList(source);
        if (list.length) rows.push(...list);
      }
      const seen = new Set();
      return rows.map((item, index) => normalizeConnection(item, index, client)).filter((row) => {
        const key = row.signature || connectionSignature(row);
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    }

    function connectionDefaultLines(profile = {}) {
      const options = [];
      const pushOption = (value, label = value) => {
        const key = firstText(value, label);
        if (!key || options.some((item) => item.value === key)) return;
        options.push({ value: key, label: firstText(label, key) });
      };
      for (const source of [profile.lines, profile.wans, profile.wan_list, profile.interfaces]) {
        rawList(source).forEach((item) => {
          if (typeof item === 'string') pushOption(item, item);
          else {
            const value = firstText(item.ifname, item.interface, item.line, item.name, item.id);
            const label = firstText(item.label, item.display_name, item.remark, item.name, value);
            pushOption(value, label);
          }
        });
      }
      pushOption('lan1', 'lan1');
      pushOption('wan1', 'wan1(联通-1)');
      pushOption('wan2', 'wan2(移动-1)');
      pushOption('wan3', 'wan3(联通-2)');
      pushOption('wan4', 'wan4(移动-2)');
      return options;
    }

    function connectionOptions(rows, profile) {
      const protoCounts = rows.reduce((acc, row) => {
        const key = normalizeProtocolKey(row.proto) || 'other';
        acc[key] = (acc[key] || 0) + 1;
        return acc;
      }, {});
      const lineCounts = rows.reduce((acc, row) => {
        const key = row.lineKey || row.line || '--';
        acc[key] = (acc[key] || 0) + 1;
        return acc;
      }, {});
      const lineOptions = connectionDefaultLines(profile);
      Object.keys(lineCounts).forEach((line) => {
        if (!lineOptions.some((item) => item.value === line)) lineOptions.push({ value: line, label: line });
      });
      return {
        protocols: [
          ['all', '全部', rows.length],
          ['tcp', 'TCP', protoCounts.tcp || 0],
          ['udp', 'UDP', protoCounts.udp || 0],
          ['icmp', 'ICMP', protoCounts.icmp || 0]
        ],
        lines: [['all', '全部', rows.length], ...lineOptions.map((item) => [item.value, item.label, lineCounts[item.value] || 0])]
      };
    }

    function filteredConnectionRows(rows) {
      const filters = page.connectionFilters || { proto: 'all', line: 'all' };
      return rows.filter((row) => {
        if (filters.proto && filters.proto !== 'all' && row.protoKey !== filters.proto) return false;
        if (filters.line && filters.line !== 'all' && row.lineKey !== filters.line) return false;
        return true;
      });
    }

    function visibleConnectionColumns() {
      const selected = new Set(Array.isArray(page.connectionColumns) && page.connectionColumns.length ? page.connectionColumns : CONNECTION_DEFAULT_COLUMNS);
      selected.add('action');
      const columns = CONNECTION_COLUMNS.filter((column) => selected.has(column.key));
      return columns.length ? columns : CONNECTION_COLUMNS;
    }

    function connectionCellText(row, key) {
      if (key === 'upBytes') return formatConnectionBytes(row.upBytes);
      if (key === 'downBytes') return formatConnectionBytes(row.downBytes);
      if (key === 'upRate') return formatRate(row.upRate || 0);
      if (key === 'downRate') return formatRate(row.downRate || 0);
      if (key === 'status') return row.status || '--';
      return detailValue(row[key], '--');
    }

    function connectionCell(row, key) {
      if (key === 'upBytes') return `<span class="rate-up">${escapeHtml(connectionCellText(row, key))}</span>`;
      if (key === 'downBytes') return `<span class="rate-down">${escapeHtml(connectionCellText(row, key))}</span>`;
      if (key === 'upRate') return `<span class="rate-up">${escapeHtml(connectionCellText(row, key))}</span>`;
      if (key === 'downRate') return `<span class="rate-down">${escapeHtml(connectionCellText(row, key))}</span>`;
      if (key === 'status') return `<span class="client-connection-status ${row.connected ? 'is-connected' : ''}">${escapeHtml(connectionCellText(row, key))}</span>`;
      if (key === 'action') {
        const payload = connectionClosePayload(row);
        return `<button class="client-connection-close-one" type="button" data-client-connection-close-one="${escapeHtml(row.signature || connectionSignature(row))}" data-client-connection-close-payload="${escapeHtml(JSON.stringify(payload))}" aria-label="关闭连接">关闭</button>`;
      }
      const value = connectionCellText(row, key);
      return `<span title="${escapeHtml(value)}">${escapeHtml(value)}</span>`;
    }

    function connectionClosePayload(row = {}) {
      return {
        mac: page && page.detail && page.detail.mac || '',
        id: firstText(row.id),
        proto: firstText(row.protoKey, row.proto),
        line: firstText(row.lineKey, row.line),
        external_ip: firstText(row.externalIp),
        src_port: firstText(row.srcPort),
        dst_ip: firstText(row.dstIp),
        dst_port: firstText(row.dstPort),
        domain: firstText(row.domain),
        app: firstText(row.app),
        signature: firstText(row.signature, connectionSignature(row))
      };
    }

    function connectionColumnsSignature(columns) {
      return columns.map((column) => column.key).join('|');
    }

    function connectionRowMarkup(row, columns) {
      return `<tr data-client-connection-row="${escapeHtml(row.signature || connectionSignature(row))}">${columns.map((column) => `<td data-column="${escapeHtml(column.key)}">${connectionCell(row, column.key)}</td>`).join('')}</tr>`;
    }

    function createConnectionRowNode(row, columns) {
      const template = document.createElement('template');
      template.innerHTML = connectionRowMarkup(row, columns).trim();
      return template.content.firstElementChild;
    }

    function connectionTableMarkup(filtered, columns) {
      const minWidth = Math.max(1120, columns.length * 142);
      return `<div class="client-connection-table-scroll">
        <table class="client-connection-table" style="min-width:${minWidth}px">
          <thead><tr>${columns.map((column) => `<th data-column="${escapeHtml(column.key)}">${escapeHtml(column.label)}</th>`).join('')}</tr></thead>
          <tbody>${filtered.map((row) => connectionRowMarkup(row, columns)).join('')}</tbody>
        </table>
      </div>`;
    }

    function connectionStructureSignature(filtered, columns) {
      return JSON.stringify({
        columns: columns.map((column) => column.key),
        rows: filtered.map((row) => row.signature || connectionSignature(row))
      });
    }

    function patchConnectionTableCells(host, filtered, columns) {
      const table = host && host.querySelector('.client-connection-table');
      if (!table) return false;
      let changed = false;
      const rowMap = new Map();
      table.querySelectorAll('[data-client-connection-row]').forEach((rowNode) => {
        rowMap.set(rowNode.dataset.clientConnectionRow || '', rowNode);
      });
      filtered.forEach((row) => {
        const signature = row.signature || connectionSignature(row);
        const rowNode = rowMap.get(signature);
        if (!rowNode) return;
        columns.forEach((column) => {
          const cell = rowNode.querySelector(`td[data-column="${column.key}"]`);
          if (!cell) return;
          const next = connectionCell(row, column.key);
          if (cell.innerHTML !== next) {
            cell.innerHTML = next;
            changed = true;
          }
        });
      });
      return changed;
    }

    function patchConnectionTableCell(cell, row, key) {
      if (!cell) return false;
      if (key === 'action') {
        const signature = row.signature || connectionSignature(row);
        const payload = JSON.stringify(connectionClosePayload(row));
        let button = cell.querySelector('[data-client-connection-close-one]');
        if (!button) {
          cell.innerHTML = connectionCell(row, key);
          return true;
        }
        button.dataset.clientConnectionCloseOne = signature;
        button.dataset.clientConnectionClosePayload = payload;
        if (button.textContent !== '关闭') button.textContent = '关闭';
        return false;
      }
      const text = connectionCellText(row, key);
      let span = cell.querySelector(':scope > span');
      if (!span) {
        cell.innerHTML = connectionCell(row, key);
        return true;
      }
      if (key === 'status') {
        span.classList.toggle('is-connected', Boolean(row.connected));
      }
      const titleKeys = new Set(['app', 'proto', 'line', 'externalIp', 'domain', 'srcPort', 'dstIp', 'dstPort']);
      if (titleKeys.has(key) && span.getAttribute('title') !== text) span.setAttribute('title', text);
      if (span.textContent !== text) {
        setTextIfChanged(span, text);
        return true;
      }
      return false;
    }

    function patchConnectionTableRows(host, filtered, columns) {
      const table = host && host.querySelector('.client-connection-table');
      const tbody = table && table.querySelector('tbody');
      if (!table || !tbody) return false;
      table.style.minWidth = `${Math.max(1120, columns.length * 142)}px`;
      const desiredKeys = new Set(filtered.map((row) => row.signature || connectionSignature(row)));
      Array.from(tbody.querySelectorAll('[data-client-connection-row]')).forEach((rowNode) => {
        if (!desiredKeys.has(rowNode.dataset.clientConnectionRow || '')) rowNode.remove();
      });
      const existing = new Map();
      tbody.querySelectorAll('[data-client-connection-row]').forEach((rowNode) => {
        existing.set(rowNode.dataset.clientConnectionRow || '', rowNode);
      });
      filtered.forEach((row) => {
        const key = row.signature || connectionSignature(row);
        let rowNode = existing.get(key);
        if (!rowNode) {
          rowNode = createConnectionRowNode(row, columns);
          tbody.appendChild(rowNode);
          existing.set(key, rowNode);
        }
        columns.forEach((column) => {
          const cell = rowNode.querySelector(`td[data-column="${column.key}"]`);
          patchConnectionTableCell(cell, row, column.key);
        });
      });
      return true;
    }

    function connectionPanelState(client, profile, merged) {
      const rows = connectionRows(profile, merged || client);
      const filtered = filteredConnectionRows(rows);
      const columns = visibleConnectionColumns();
      const notice = firstText(page.connectionNotice);
      return { rows, filtered, columns, notice };
    }

    function connectionOptionsModal(rows, profile) {
      if (!page.connectionOptionsOpen) return '';
      const tab = page.connectionOptionTab === 'columns' ? 'columns' : 'filter';
      const options = connectionOptions(rows, profile);
      const selectedColumns = new Set(Array.isArray(page.connectionColumns) ? page.connectionColumns : CONNECTION_DEFAULT_COLUMNS);
      const allChecked = CONNECTION_COLUMNS.every((column) => selectedColumns.has(column.key));
      const filterButton = (kind, value, label, count) => {
        const active = kind === 'proto' ? (page.connectionFilters.proto || 'all') === value : (page.connectionFilters.line || 'all') === value;
        return `<button class="client-connection-option-row ${active ? 'is-active' : ''}" type="button" data-client-connection-filter-${kind}="${escapeHtml(value)}">
          <span aria-hidden="true"></span><strong>${escapeHtml(label)}</strong><em>${escapeHtml(formatInteger(count))}</em>
        </button>`;
      };
      return `<div class="client-connection-options-layer is-side-drawer" role="dialog" aria-modal="true" aria-label="显示选项">
        <button class="client-connection-options-overlay dwrt-kit-sheet-overlay" type="button" data-client-connection-options-close aria-label="关闭显示选项"></button>
        <aside class="client-connection-options-modal dwrt-kit-sheet client-stable-glass is-open" aria-label="连接详情显示选项">
          <header class="client-connection-options-head dwrt-kit-sheet-header">
            <div><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M7 12h10M10 17h4"></path></svg><strong>显示选项</strong></div>
            <button class="dwrt-kit-sheet-close" type="button" data-client-connection-options-close aria-label="关闭">×</button>
          </header>
          <div class="client-connection-options-body dwrt-kit-sheet-body">
            <nav class="client-connection-options-tabs" aria-label="显示选项标签">
              <button class="${tab === 'filter' ? 'is-active' : ''}" type="button" data-client-connection-options-tab="filter">筛选器</button>
              <button class="${tab === 'columns' ? 'is-active' : ''}" type="button" data-client-connection-options-tab="columns">列</button>
            </nav>
            <section class="client-connection-options-section ${tab === 'filter' ? 'is-active' : ''}">
              <div class="client-connection-filter-card"><header><strong>协议</strong><span>⌄</span></header>${options.protocols.map(([value, label, count]) => filterButton('proto', value, label, count)).join('')}</div>
              <div class="client-connection-filter-card"><header><strong>线路</strong><span>⌄</span></header>${options.lines.map(([value, label, count]) => filterButton('line', value, label, count)).join('')}</div>
            </section>
            <section class="client-connection-options-section ${tab === 'columns' ? 'is-active' : ''}">
              <label class="client-connection-column-row is-all ${allChecked ? 'is-active' : ''}">
                <input type="checkbox" data-client-connection-column-all ${allChecked ? 'checked' : ''}>
                <span aria-hidden="true"></span><strong>全选</strong>
              </label>
              ${CONNECTION_COLUMNS.map((column) => `<label class="client-connection-column-row ${selectedColumns.has(column.key) ? 'is-active' : ''}">
                <input type="checkbox" data-client-connection-column="${escapeHtml(column.key)}" ${selectedColumns.has(column.key) ? 'checked' : ''}>
                <span aria-hidden="true"></span><strong>${escapeHtml(column.label)}</strong>
              </label>`).join('')}
            </section>
          </div>
        </aside>
      </div>`;
    }

    function listFromControlSource(...sources) {
      const rows = [];
      sources.forEach((source) => rawList(source).forEach((item) => rows.push(item)));
      return rows;
    }

    function normalizeControlRule(item = {}, index = 0) {
      if (typeof item === 'string') item = { name: item };
      const enabledRaw = firstText(item.enabled, item.enable, item.status, item.state, item.active);
      const enabled = enabledRaw === '' ? true : !/^(0|false|disabled|off|关闭|停用)$/i.test(String(enabledRaw));
      const type = firstText(item.control_type, item.type, item.policy_type, item.kind, item.category, item.qos_type, 'IP限速');
      const name = firstText(item.name, item.rule_name, item.policy_name, item.title, item.id, `规则${index + 1}`);
      const days = firstText(item.days, item.weekdays, item.week, item.period_days, '一 二 三 四 五 六 日');
      const start = firstText(item.start_time, item.start, item.time_start, item.begin, '00:00');
      const end = firstText(item.end_time, item.end, item.time_end, item.finish, '23:59');
      const content = firstText(item.content, item.schedule, item.period, item.time_range, `周: ${days}\n${start} ~ ${end}`);
      return {
        id: firstText(item.id, item.rule_id, item.uuid, name, index),
        name,
        type,
        content,
        note: firstText(item.note, item.remark, item.comment, '--'),
        enabled,
        raw: item
      };
    }

    function controlRules(profile = {}, client = {}) {
      const rows = listFromControlSource(
        profile.control_rules, profile.controls, profile.policies, profile.policy_rules,
        profile.qos_rules, profile.limit_rules, profile.parental_rules,
        profile.current && profile.current.control_rules,
        client.control_rules, client.controls, client.policies
      );
      return rows.map(normalizeControlRule).filter((row) => row.name || row.type);
    }

    function controlRuleContent(rule) {
      const lines = String(firstText(rule.content, '--')).split(/\n+/).filter(Boolean);
      return lines.map((line) => `<span>${escapeHtml(line)}</span>`).join('') || '<span>--</span>';
    }

    function controlEmptyState(client) {
      return `<div class="client-control-empty">
        <div class="client-control-empty-illustration" aria-hidden="true"><span></span><i></i></div>
        <div class="client-control-empty-copy">
          <strong>暂无对此终端的管控</strong>
          <span>如需配置可 <button type="button" data-client-control-add>快速新增</button></span>
        </div>
      </div>`;
    }

    function controlDrawer(client, profile) {
      if (!page.controlEditorOpen) return '';
      const draft = page.controlDraft || {};
      const weekdays = ['一', '二', '三', '四', '五', '六', '日'];
      const selectedDays = new Set(asArray(draft.days).length ? draft.days : weekdays);
      const notice = firstText(page.controlNotice);
      const editing = Boolean(firstText(draft.id));
      const editorTitle = editing ? '编辑' : '新增';
      return `<div class="client-control-editor-layer" role="dialog" aria-modal="true" aria-label="${editorTitle}管控规则">
        <button class="client-control-editor-overlay dwrt-kit-sheet-overlay" type="button" data-client-control-close aria-label="关闭${editorTitle}管控"></button>
        <aside class="client-control-editor dwrt-kit-sheet client-stable-glass is-open">
          <header class="client-control-editor-head dwrt-kit-sheet-header"><strong>${editorTitle}</strong><button class="dwrt-kit-sheet-close" type="button" data-client-control-close aria-label="关闭">×</button></header>
          <form id="client-control-form" class="client-control-form dwrt-kit-sheet-body" data-client-control-form>
            <input type="hidden" name="mac" value="${escapeHtml(firstText(client.mac, page.detail && page.detail.mac))}">
            ${editing ? `<input type="hidden" name="id" value="${escapeHtml(draft.id)}">` : ''}
            <section class="client-control-form-card">
              <label class="client-control-field"><span>管控类型 <em>*</em></span><select name="control_type"><option value="IP限速" ${draft.control_type === 'IP限速' ? 'selected' : ''}>IP限速</option><option value="应用管控" ${draft.control_type === '应用管控' ? 'selected' : ''}>应用管控</option><option value="访问控制" ${draft.control_type === '访问控制' ? 'selected' : ''}>访问控制</option><option value="时间管控" ${draft.control_type === '时间管控' ? 'selected' : ''}>时间管控</option></select></label>
              <label class="client-control-field"><span>名称 <em>*</em></span><input name="name" value="${escapeHtml(firstText(draft.name))}" placeholder="请输入名称"></label>
              <div class="client-control-field"><span>生效时间 <em>*</em></span><div class="client-control-radio-row"><label><input type="radio" name="schedule_mode" value="plan" ${draft.schedule_mode === 'plan' ? 'checked' : ''}><i></i>时间计划</label><label><input type="radio" name="schedule_mode" value="week" ${draft.schedule_mode !== 'plan' && draft.schedule_mode !== 'range' ? 'checked' : ''}><i></i>按周循环</label><label><input type="radio" name="schedule_mode" value="range" ${draft.schedule_mode === 'range' ? 'checked' : ''}><i></i>时间段</label></div></div>
              <div class="client-control-field"><span>周期</span><div class="client-control-weekdays">${weekdays.map((day) => `<label class="${selectedDays.has(day) ? 'is-active' : ''}"><input type="checkbox" name="days" value="${day}" ${selectedDays.has(day) ? 'checked' : ''}>${day}</label>`).join('')}</div></div>
              <div class="client-control-time-range"><input name="start_time" value="${escapeHtml(firstText(draft.start_time, '00:00'))}" placeholder="00:00"><span>→</span><input name="end_time" value="${escapeHtml(firstText(draft.end_time, '23:59'))}" placeholder="23:59"><button type="button" data-client-control-time-clear>×</button></div>
              <label class="client-control-field"><span>限速模式 <em>*</em></span><select name="limit_mode"><option value="独立限速" ${draft.limit_mode !== '共享限速' ? 'selected' : ''}>独立限速</option><option value="共享限速" ${draft.limit_mode === '共享限速' ? 'selected' : ''}>共享限速</option></select></label>
              <label class="client-control-field"><span>上行限速 <em>*</em></span><div class="client-control-input-unit"><input name="up_limit" inputmode="decimal" value="${escapeHtml(firstText(draft.up_limit, '0'))}"><select name="up_unit"><option ${firstText(draft.up_unit, 'KB/s') === 'KB/s' ? 'selected' : ''}>KB/s</option><option ${firstText(draft.up_unit) === 'MB/s' ? 'selected' : ''}>MB/s</option><option ${firstText(draft.up_unit) === 'Kbps' ? 'selected' : ''}>Kbps</option><option ${firstText(draft.up_unit) === 'Mbps' ? 'selected' : ''}>Mbps</option></select></div><small>默认0为不限额</small></label>
              <label class="client-control-field"><span>下行限速 <em>*</em></span><div class="client-control-input-unit"><input name="down_limit" inputmode="decimal" value="${escapeHtml(firstText(draft.down_limit, '0'))}"><select name="down_unit"><option ${firstText(draft.down_unit, 'KB/s') === 'KB/s' ? 'selected' : ''}>KB/s</option><option ${firstText(draft.down_unit) === 'MB/s' ? 'selected' : ''}>MB/s</option><option ${firstText(draft.down_unit) === 'Kbps' ? 'selected' : ''}>Kbps</option><option ${firstText(draft.down_unit) === 'Mbps' ? 'selected' : ''}>Mbps</option></select></div><small>默认0为不限额</small></label>
              <label class="client-control-field"><span>线路</span><select name="line"><option value="">任意</option>${connectionDefaultLines(profile).map((line) => `<option value="${escapeHtml(line.value)}" ${draft.line === line.value ? 'selected' : ''}>${escapeHtml(line.label)}</option>`).join('')}</select></label>
              <label class="client-control-field"><span>协议 <em>*</em></span><select name="protocol"><option value="任意">任意</option><option>TCP</option><option>UDP</option><option>ICMP</option></select></label>
              <label class="client-control-field"><span>备注</span><textarea name="note" rows="4">${escapeHtml(firstText(draft.note))}</textarea></label>
            </section>
          </form>
          <footer class="client-control-editor-actions dwrt-kit-sheet-footer"><button class="is-primary" type="submit" form="client-control-form">保存</button><button type="button" data-client-control-close>取消</button>${notice ? `<span>${escapeHtml(notice)}</span>` : ''}</footer>
        </aside>
      </div>`;
    }

    function controlPanel(client, profile, merged) {
      const rows = controlRules(profile, merged || client);
      const notice = firstText(page.controlNotice);
      return `<section class="client-control-panel client-detail-card ${page.controlEditorOpen ? 'is-editor-open' : ''}">
        <div class="client-control-toolbar">
          <div>${rows.length ? `<strong>共 ${escapeHtml(formatInteger(rows.length))} 条</strong>` : '<strong>管控规则</strong>'}${notice && !page.controlEditorOpen ? `<span>${escapeHtml(notice)}</span>` : ''}</div>
          <div><button class="client-control-add-button" type="button" data-client-control-add>新增</button><button class="client-control-auto-button" type="button" data-client-control-refresh>自动刷新</button><button class="client-control-icon-button" type="button" data-client-control-refresh aria-label="刷新管控详情">A</button></div>
        </div>
        ${rows.length ? `<div class="client-control-table-scroll"><table class="client-control-table"><thead><tr><th>名称</th><th>管控类型</th><th>内容</th><th>备注</th><th>操作</th></tr></thead><tbody>${rows.map((rule) => `<tr data-client-control-rule="${escapeHtml(rule.id)}"><td><span class="client-control-state ${rule.enabled ? 'is-on' : 'is-off'}">▶</span><strong>${escapeHtml(rule.name)}</strong></td><td>${escapeHtml(rule.type)}</td><td class="client-control-content">${controlRuleContent(rule)}</td><td>${escapeHtml(rule.note || '--')}</td><td><button type="button" data-client-control-toggle="${escapeHtml(rule.id)}">${rule.enabled ? '关闭' : '开启'}</button><button type="button" data-client-control-action="${escapeHtml(rule.id)}">管控控制</button><button type="button" data-client-control-delete="${escapeHtml(rule.id)}">删除</button></td></tr>`).join('')}</tbody></table></div>` : controlEmptyState(merged)}
        ${controlDrawer(merged, profile)}
      </section>`;
    }

    function connectionPanel(client, profile, merged) {
      const state = connectionPanelState(client, profile, merged);
      const { rows, filtered, columns, notice } = state;
      const auto = page.connectionAutoRefresh !== false;
      return `<section class="client-connection-panel client-detail-card">
        <div class="client-connection-toolbar">
          <div class="client-connection-count"><strong>共 ${escapeHtml(formatInteger(filtered.length))} 条</strong>${rows.length !== filtered.length ? `<span>已从 ${escapeHtml(formatInteger(rows.length))} 条筛选</span>` : ''}${notice ? `<em>${escapeHtml(notice)}</em>` : ''}</div>
          <div class="client-connection-actions">
            <button type="button" data-client-connection-clear>清除连接</button>
            <button type="button" data-client-connection-autorefresh>${auto ? '自动刷新' : '手动刷新'}</button>
            <button class="client-connection-icon-button" type="button" data-client-connection-refresh aria-label="刷新连接详情"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 12a8 8 0 0 1-13.66 5.66M4 12A8 8 0 0 1 17.66 6.34M17 3v4h4M7 21v-4H3"></path></svg></button>
            <button class="client-connection-icon-button is-options" type="button" data-client-connection-options aria-label="显示选项"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M7 12h10M10 17h4"></path></svg></button>
          </div>
        </div>
        <div class="client-connection-table-host" data-client-connection-signature="${escapeHtml(connectionStructureSignature(filtered, columns))}" data-client-connection-columns="${escapeHtml(connectionColumnsSignature(columns))}">${filtered.length ? connectionTableMarkup(filtered, columns) : detailEmpty(rows.length ? '当前筛选条件下没有连接。' : '后端暂未返回该终端的连接明细。')}</div>
        ${connectionOptionsModal(rows, profile)}
      </section>`;
    }

    function detailPanel(tab, client, profile) {
      const merged = profileClient(client, profile);
      const ipv6 = ipv6Parts(merged);
      if (tab === 'control') {
        return controlPanel(client, profile, merged);
      }
      if (tab === 'info') {
        const displayName = usefulInfoText(userName(merged)) || '--';
        const hostname = usefulInfoText(merged.hostname);
        const nickname = usefulInfoText(merged.nickname, merged.remark);
        const model = usefulInfoText(merged.model, merged.device_model);
        const infoRows = [
          ['名称', displayName],
          ...(hostname && !sameInfoText(hostname, displayName) ? [['主机名', hostname]] : []),
          ...(nickname && !sameInfoText(nickname, displayName) && !sameInfoText(nickname, hostname) ? [['备注/昵称', nickname]] : []),
          ['IPv4', usefulInfoText(merged.ip) || '--'],
          ['IPv6 内网', usefulInfoText(ipv6.local) || '--'],
          ['IPv6 外网', usefulInfoText(ipv6.global) || '--'],
          ['MAC', usefulInfoText(merged.mac) || '--'],
          ['厂商/类型', usefulInfoText(merged.vendorType) || '--'],
          ...(model && !sameInfoText(model, displayName) ? [['型号', model]] : []),
          ['操作系统', usefulInfoText(merged.os_name, merged.os) || '--'],
          ['接入方式', usefulInfoText(merged.link_type, merged.interface, merged.network, merged.ssid) || '--'],
          ['识别置信度', usefulInfoText(merged.fingerprint_confidence, profile.confidence) || '--']
        ];
        return `<section class="client-detail-card">
          <div class="client-detail-card-head"><strong>信息详情</strong><span>DHCP、邻居表、指纹和用户覆盖信息</span></div>
          <div class="client-detail-list client-detail-list-grid">
            ${infoRows.map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join('')}
          </div>
        </section>`;
      }
      if (tab === 'protocol') {
        return protocolPanel(client, profile, merged);
      }
      if (tab === 'connection') {
        return connectionPanel(client, profile, merged);
      }
      if (tab === 'custom') {
        return `<section class="client-detail-card">
          <div class="client-detail-card-head"><strong>自定义识别</strong><span>保存后固定使用用户指定信息，优先级高于自动识别</span></div>
          <form class="client-custom-form" data-client-custom-form>
            <input type="hidden" name="mac" value="${escapeHtml(merged.mac || '')}">
            <button class="client-custom-preview" type="button" data-client-open-fingerprint>
              ${clientImage(merged)}
              <em>从图库选择</em>
            </button>
            <div class="client-custom-fields">
              <label><span>设备类型</span><select name="device_type">
                ${[
                  ['unknown', '未知'], ['smartphone', '手机'], ['tablet', '平板'], ['computer', '电脑'], ['router', '路由器'],
                  ['nas', 'NAS'], ['iot', 'IoT'], ['speaker', '音箱'], ['tv', '电视'], ['printer', '打印机'],
                  ['camera', '摄像头'], ['game_console', '游戏主机'], ['hypervisor', '虚拟化']
                ].map(([value, label]) => `<option value="${escapeHtml(value)}" ${String(deviceType(merged) || '').toLowerCase() === value ? 'selected' : ''}>${escapeHtml(label)}</option>`).join('')}
              </select></label>
              <label><span>设备品牌</span><input name="vendor_name" value="${escapeHtml(firstText(merged.vendor_name, merged.vendor, merged.manufacturer, ''))}" placeholder="例如 Apple / Xiaomi"></label>
              <label><span>设备型号/颜色</span><input name="device_name" value="${escapeHtml(firstText(merged.model, merged.device_model, merged.device_name, ''))}" placeholder="例如 iPhone 15 Pro"></label>
              <label><span>设备图片</span><div class="client-image-input-row"><input name="custom_image_path" value="${escapeHtml(firstText(merged.custom_image_path, merged.custom_icon, merged.image, merged.fingerprint_image, ''))}" placeholder="/static/..."><button type="button" data-client-open-fingerprint>图库</button></div></label>
              <label class="span-2"><span>显示名称</span><input name="nickname" value="${escapeHtml(firstText(merged.nickname, merged.custom_name, merged.remark, ''))}" placeholder="留空则使用主机名或识别名称"></label>
            </div>
            <div class="client-custom-actions"><span data-client-custom-status>提交到 /api/v1/client_override，失败会保留当前页面状态。</span><button type="submit">保存自定义</button></div>
          </form>
        </section>`;
      }
      return `<div class="client-detail-overview">
        ${overviewCharts(client, profile, merged)}
      </div>`;
    }

    function detailDrawer() {
      if (!page.detail.open) return '';
      const client = page.clients.find((item) => String(item.mac).toLowerCase() === String(page.detail.mac).toLowerCase()) || {};
      const profile = page.detail.profile || {};
      const merged = profileClient(client, profile);
      const tab = page.detail.tab || 'overview';
      const onlineStatus = statusBadgeMarkup(merged.online ? '在线' : '离线', merged.online ? 'success' : 'error', { className: 'client-online-status' });
      return `<div class="dwrt-kit-modal-layer client-detail-layer is-open" data-dwrt-component="modal" style="--dwrt-kit-modal-z:88">
        <button class="dwrt-kit-modal-backdrop" type="button" data-dwrt-modal-close data-client-detail-close aria-label="关闭终端详情"></button>
        <section class="dwrt-kit-modal client-detail-drawer" data-dwrt-modal-variant="copilot" role="dialog" aria-modal="true" aria-label="终端详情">
          <header class="dwrt-kit-modal-header client-detail-drawer-head client-detail-modal-head">
            <div><strong>终端详情</strong><span>${escapeHtml(userName(merged))}</span></div>
            <button type="button" class="dwrt-kit-modal-close client-detail-close-button" data-dwrt-modal-close data-client-detail-close aria-label="关闭">×</button>
          </header>
          <div class="dwrt-kit-modal-body client-detail-drawer-body client-detail-modal-body">
            <section class="client-detail-hero">
              <div class="client-detail-device-art">${clientImage(merged)}</div>
              <div class="client-detail-identity">
                <strong>${escapeHtml(userName(merged))}</strong>
                <span>${escapeHtml(vendorType(merged))}</span>
              </div>
              ${onlineStatus.replace('class="', 'data-client-online-status class="')}
            </section>
            <nav class="dwrt-kit-tabs client-detail-tabs" aria-label="终端详情标签页">
              <span class="dwrt-kit-tab-pill" aria-hidden="true"></span>
              ${DETAIL_TABS.map(([key, label]) => `<button class="dwrt-kit-tab ${tab === key ? 'is-active' : ''}" type="button" data-value="${escapeHtml(key)}" aria-selected="${tab === key ? 'true' : 'false'}">${escapeHtml(label)}</button>`).join('')}
            </nav>
            <section class="client-detail-stage">
              ${page.detail.loading ? '<div class="client-empty">正在加载终端详情...</div>' : detailPanel(tab, client, profile)}
            </section>
          </div>
        </section>
      </div>`;
    }

    function columnFilterUnits(config = {}) {
      if (config.unit === 'rate') return ['B/s', 'KB/s', 'MB/s', 'Kbps', 'Mbps', 'Gbps'];
      if (config.unit === 'bytes') return ['B', 'KB', 'MB', 'GB', 'TB'];
      return ['个'];
    }

    function columnFilterOperatorOptions() {
      return [
        ['gte', '大于等于'],
        ['lte', '小于等于'],
        ['eq', '等于'],
        ['gt', '大于'],
        ['lt', '小于']
      ];
    }

    function columnFilterPopover() {
      const key = firstText(page && page.columnFilterOpen);
      const config = CLIENT_COLUMN_FILTERS[key];
      if (!key || !config) return '';
      const filter = page.filters && page.filters.columnFilters && page.filters.columnFilters[key] || {};
      const mode = filter.mode === 'exclude' ? 'exclude' : 'include';
      const op = ['gte', 'lte', 'eq', 'gt', 'lt'].includes(filter.op) ? filter.op : 'gte';
      const units = columnFilterUnits(config);
      const unit = units.includes(filter.unit) ? filter.unit : units[0];
      return `<div class="client-column-filter-layer" role="dialog" aria-modal="true" aria-label="筛选 ${escapeHtml(config.label)}">
        <button class="client-column-filter-backdrop" type="button" data-client-column-filter-cancel aria-label="关闭筛选"></button>
        <section class="client-column-filter-card client-stable-glass" data-client-column-filter-card data-column="${escapeHtml(key)}">
          <header>
            <strong>${escapeHtml(config.label)}</strong>
            <span>按当前列数值筛选</span>
          </header>
          <div class="client-column-filter-modes">
            <label><input type="radio" name="client-column-filter-mode" value="include" ${mode === 'include' ? 'checked' : ''}> <span>包含</span></label>
            <label><input type="radio" name="client-column-filter-mode" value="exclude" ${mode === 'exclude' ? 'checked' : ''}> <span>排除</span></label>
          </div>
          <div class="client-column-filter-value">
            <input type="number" min="0" step="any" value="${escapeHtml(filter.value ?? '')}" placeholder="请输入数值" data-client-column-filter-value>
            <select data-client-column-filter-unit>
              ${units.map((item) => `<option value="${escapeHtml(item)}" ${item === unit ? 'selected' : ''}>${escapeHtml(item)}</option>`).join('')}
            </select>
          </div>
          <div class="client-column-filter-ops">
            ${columnFilterOperatorOptions().map(([value, label]) => `<label><input type="radio" name="client-column-filter-op" value="${escapeHtml(value)}" ${op === value ? 'checked' : ''}> <span>${escapeHtml(label)}</span></label>`).join('')}
          </div>
          <footer>
            <button type="button" data-client-column-filter-reset>重置</button>
            <button type="button" data-client-column-filter-cancel>取消</button>
            <button type="button" class="is-primary" data-client-column-filter-save>保存</button>
          </footer>
        </section>
      </div>`;
    }

    function filterDrawer() {
      if (!page.filterOpen) return '';
      const types = availableDeviceTypes();
      const activeTab = page.filterTab === 'display' ? 'display' : 'filter';
      return `<button class="client-filter-overlay dwrt-kit-sheet-overlay" type="button" data-client-filter-close aria-label="关闭终端筛选"></button>
      <aside class="client-filter-drawer dwrt-kit-sheet dwrt-glass-card is-open" aria-label="终端筛选">
        <header class="client-filter-head dwrt-kit-sheet-header">
          <div><strong>筛选终端</strong><span>设备类型、IP 与显示选项</span></div>
          <button class="dwrt-kit-sheet-close" type="button" data-client-filter-close aria-label="关闭">×</button>
        </header>
        <div class="client-filter-body dwrt-kit-sheet-body">
          <nav class="client-filter-tabs" aria-label="筛选抽屉标签页">
            <button class="${activeTab === 'filter' ? 'is-active' : ''}" type="button" data-client-filter-tab="filter">筛选</button>
            <button class="${activeTab === 'display' ? 'is-active' : ''}" type="button" data-client-filter-tab="display">显示</button>
          </nav>
          <section class="client-filter-section ${activeTab === 'filter' ? 'is-active' : ''}" data-client-filter-panel="filter">
            <strong>设备类型</strong>
            <div class="client-filter-checks">
              ${types.length ? types.map((type) => `<label>
                <input type="checkbox" data-client-filter-type value="${escapeHtml(type)}" ${page.filters.deviceTypes.includes(type) ? 'checked' : ''}>
                <span>${escapeHtml(type)}</span>
              </label>`).join('') : '<em>暂无可选类型</em>'}
            </div>
          </section>
          <section class="client-filter-section ${activeTab === 'filter' ? 'is-active' : ''}" data-client-filter-panel="filter">
            <strong>关键字</strong>
            <input data-client-filter-keyword value="${escapeHtml(firstText(page.filters.keyword, page.search))}" placeholder="名称 / MAC / 厂商 / 型号">
          </section>
          <section class="client-filter-section ${activeTab === 'filter' ? 'is-active' : ''}" data-client-filter-panel="filter">
            <strong>IP 地址</strong>
            <input data-client-filter-ip value="${escapeHtml(page.filters.ip)}" placeholder="例如 192.168.30 或 2408">
            <label class="client-filter-inline">
              <input type="checkbox" data-client-filter-ip-exclude ${page.filters.ipExclude ? 'checked' : ''}>
              <span>排除匹配 IP</span>
            </label>
          </section>
          <section class="client-filter-section ${activeTab === 'filter' ? 'is-active' : ''}" data-client-filter-panel="filter">
            <strong>高级条件</strong>
            <div class="client-filter-grid">
              <label><span>连接数</span><input type="number" min="0" data-client-filter-min-connections value="${escapeHtml(page.filters.minConnections || '')}" placeholder="大于等于"></label>
              <label><span>VLAN</span><input data-client-filter-vlan value="${escapeHtml(page.filters.vlan || '')}" placeholder="VLAN ID"></label>
              <label><span>累计上行 GB</span><input type="number" min="0" data-client-filter-min-up value="${escapeHtml(page.filters.minUpGb || '')}" placeholder="大于等于"></label>
              <label><span>累计下行 GB</span><input type="number" min="0" data-client-filter-min-down value="${escapeHtml(page.filters.minDownGb || '')}" placeholder="大于等于"></label>
              <label><span>协议版本</span><select data-client-filter-ip-version>
                <option value="" ${!page.filters.ipVersion ? 'selected' : ''}>全部</option>
                <option value="ipv4" ${page.filters.ipVersion === 'ipv4' ? 'selected' : ''}>仅 IPv4</option>
                <option value="ipv6" ${page.filters.ipVersion === 'ipv6' ? 'selected' : ''}>有 IPv6</option>
              </select></label>
              <label><span>厂商</span><input data-client-filter-vendor value="${escapeHtml(page.filters.vendor || '')}" placeholder="Apple / Synology"></label>
            </div>
          </section>
          <section class="client-filter-section ${activeTab === 'display' ? 'is-active' : ''}" data-client-filter-panel="display">
            <strong>在线状态</strong>
            <div class="client-filter-checks">
              <label>
                <input type="checkbox" data-client-filter-show-online ${page.filters.showOnline !== false ? 'checked' : ''}>
                <span>显示在线终端</span>
              </label>
              <label>
                <input type="checkbox" data-client-filter-show-offline ${page.filters.showOffline !== false ? 'checked' : ''}>
                <span>显示离线终端</span>
              </label>
            </div>
          </section>
          <section class="client-filter-section ${activeTab === 'display' ? 'is-active' : ''}" data-client-filter-panel="display">
            <strong>显示</strong>
            <label class="client-filter-inline">
              <input type="checkbox" data-client-filter-show-ipv6 ${page.showIpv6 ? 'checked' : ''}>
              <span>显示 IPv6 子行</span>
            </label>
            <p>列显示开关旧版已有静态 UI，新 web 会在列配置契约补齐后接入；当前保留排序、状态分组和 IPv6 展开。</p>
          </section>
        </div>
        <footer class="client-filter-actions dwrt-kit-sheet-footer">
          <button type="button" data-client-filter-reset>重置</button>
          <button type="button" data-client-filter-apply>应用</button>
        </footer>
      </aside>`;
    }

    function fingerprintLogoUrl(item = {}) {
      return firstText(
        item.logo,
        item.logo_url,
        item.brand_logo,
        item.vendor_logo,
        item.web_logo,
        item.vendor_icon,
        item.icon_url,
        brandLogoUrl(item.vendor_name, item.vendor, item.name, item.label, item.display_name)
      );
    }

    function fingerprintMonogram(name) {
      const text = firstText(name).replace(/[,，.。]/g, ' ').trim();
      if (!text) return '?';
      const words = text.split(/\s+/).filter(Boolean);
      if (words.length >= 2) return `${words[0].charAt(0)}${words[1].charAt(0)}`.toUpperCase();
      return text.slice(0, 2).toUpperCase();
    }

    function fingerprintVendorName(item = {}) {
      return firstText(item.vendor_name, item.vendor, item.manufacturer, item.brand, item.family, item.company, item.name, item.label);
    }

    function fingerprintDeviceVendorName(item = {}) {
      return firstText(item.vendor_name, item.vendor, item.manufacturer, item.brand, item.family, item.company);
    }

    function fingerprintVendorKey(...values) {
      const text = firstText(...values)
        .toLowerCase()
        .replace(/&/g, ' and ')
        .replace(/\b(incorporated|inc|corporation|corp|company|co|ltd|limited|llc|plc|gmbh|ag|sa|s\.a\.|pte|technology|technologies|electronics|group)\b/g, ' ')
        .replace(/[()\[\]{}.,，。·:：'"’‘`]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
      return text;
    }

    function fingerprintScopedVendorCounts() {
      const picker = page && page.fingerprint;
      const counts = new Map();
      if (!picker || picker.vendor || picker.query) return counts;
      asArray(picker.devices).forEach((device) => {
        const key = fingerprintVendorKey(fingerprintDeviceVendorName(device));
        if (!key) return;
        counts.set(key, (counts.get(key) || 0) + 1);
      });
      return counts;
    }

    function fingerprintVendorScopedCount(item = {}, scopedCounts = new Map()) {
      const key = fingerprintVendorKey(fingerprintVendorName(item));
      const scoped = key ? scopedCounts.get(key) : 0;
      if (scoped > 0) return scoped;
      const categoryCount = firstNumber(item.category_device_count, item.filtered_device_count, item.scoped_device_count, item.category_count, item.match_count);
      if (categoryCount > 0) return categoryCount;
      if (scopedCounts.size) return 0;
      return 0;
    }

    function fingerprintGridMode(picker = page && page.fingerprint) {
      return picker && (picker.vendor || picker.query) ? 'is-device-grid' : 'is-vendor-grid';
    }

    function fingerprintSidebarMarkup() {
      const picker = page && page.fingerprint;
      if (!picker) return '';
      return fingerprintCategories().map(([key, label]) => `<button class="${picker.category === key ? 'is-active' : ''}" type="button" data-client-fingerprint-category="${escapeHtml(key)}">${escapeHtml(label)}</button>`).join('');
    }

    function fingerprintPathMarkup() {
      const picker = page && page.fingerprint;
      if (!picker) return '';
      return `<span>${escapeHtml(picker.query ? '全部图库' : categoryLabel(picker.category))}</span><strong>${escapeHtml(picker.vendor || '选择品牌')}</strong>`;
    }

    function fingerprintGridMarkup() {
      const picker = page.fingerprint;
      if (!picker) return '';
      if (picker.loading) return '<div class="client-fingerprint-empty">正在读取图库...</div>';
      if (picker.error) return `<div class="client-fingerprint-empty">${escapeHtml(picker.error)}</div>`;
      if (!picker.vendor && !picker.query) {
        const scopedCounts = fingerprintScopedVendorCounts();
        return picker.vendors.map((item) => {
          const name = fingerprintVendorName(item);
          if (!name) return '';
          const logo = fingerprintLogoUrl(item);
          const count = fingerprintVendorScopedCount(item, scopedCounts);
          return `<button class="client-fingerprint-tile client-fingerprint-vendor" type="button" data-client-fingerprint-vendor="${escapeHtml(name)}" title="${escapeHtml(name)}">
            ${logo ? `<img src="${escapeHtml(logo)}" alt="${escapeHtml(name)}">` : `<span>${escapeHtml(fingerprintMonogram(name))}</span>`}
            <strong>${escapeHtml(name)}</strong>
            ${count > 0 ? `<em>${escapeHtml(count)} 个型号</em>` : ''}
          </button>`;
        }).join('') || '<div class="client-fingerprint-empty">暂无品牌索引，可直接上传自定义图片。</div>';
      }
      return picker.devices.map((item, index) => {
        const image = firstText(item.web_image, item.image, item.icon, item.custom_image_path);
        const name = firstText(item.device_name, item.name, item.model, '--');
        const vendor = firstText(item.vendor_name, item.vendor, item.family, item.category, '');
        return `<button class="client-fingerprint-tile client-fingerprint-device ${index === 0 ? 'is-active' : ''}" type="button" data-client-fingerprint-device="${index}" title="${escapeHtml(`${name}${vendor ? ` · ${vendor}` : ''}`)}">
          ${image ? `<img src="${escapeHtml(image)}" alt="${escapeHtml(name)}">` : `<span>${escapeHtml(fingerprintMonogram(firstText(vendor, name, '?')))}</span>`}
          <strong>${escapeHtml(name)}</strong>
          <em>${escapeHtml(vendor)}</em>
        </button>`;
      }).join('') || '<div class="client-fingerprint-empty">图库里没找到匹配项，可直接上传自定义图片。</div>';
    }

    function fingerprintPreviewMarkup() {
      const picker = page && page.fingerprint;
      if (!picker) return '';
      const selected = picker.devices && picker.devices[0] || null;
      const selectedImage = selected ? firstText(selected.web_image, selected.image, selected.icon) : '';
      return `${selected ? `<img src="${escapeHtml(selectedImage)}" alt=""><span>${escapeHtml(firstText(selected.device_name, selected.name, ''))}</span>` : `<button type="button" data-client-fingerprint-upload-placeholder>+</button><span>${escapeHtml(picker.uploading ? '正在上传图片...' : '图库未匹配时可上传图片')}</span>`}
        <input class="client-fingerprint-file" type="file" accept="image/png,image/jpeg,image/webp,image/gif,image/svg+xml,.svg" data-client-fingerprint-file>`;
    }

    function patchFingerprintPicker() {
      if (!root || !page || !page.fingerprint || !page.fingerprint.open) return false;
      const layer = root.querySelector('.client-fingerprint-layer');
      if (!layer) return false;
      const picker = page.fingerprint;
      const sidebar = layer.querySelector('.client-fingerprint-sidebar');
      if (sidebar) sidebar.innerHTML = fingerprintSidebarMarkup();
      const path = layer.querySelector('.client-fingerprint-path');
      if (path) path.innerHTML = fingerprintPathMarkup();
      const grid = layer.querySelector('.client-fingerprint-grid');
      if (grid) {
        grid.className = `client-fingerprint-grid ${fingerprintGridMode(picker)} ${picker.loading ? 'is-loading' : ''}`;
        grid.innerHTML = fingerprintGridMarkup();
      }
      const preview = layer.querySelector('.client-fingerprint-preview');
      if (preview) preview.innerHTML = fingerprintPreviewMarkup();
      const uploadAction = layer.querySelector('.client-fingerprint-upload-action');
      if (uploadAction) uploadAction.textContent = picker.uploading ? '正在上传…' : '上传图片';
      const apply = layer.querySelector('[data-client-apply-fingerprint]');
      if (apply) apply.disabled = !(picker.devices && picker.devices[0]);
      const input = layer.querySelector('[data-client-fingerprint-search]');
      if (input && document.activeElement !== input && input.value !== firstText(picker.query)) input.value = firstText(picker.query);
      return true;
    }

    function fingerprintModal() {
      const picker = page && page.fingerprint;
      if (!picker || !picker.open) return '';
      const selected = picker.devices[0] || null;
      return `<div class="client-fingerprint-layer" role="dialog" aria-modal="true" aria-label="选择设备识别">
        <button class="client-fingerprint-overlay" type="button" data-client-close-fingerprint aria-label="关闭图库"></button>
        <section class="client-fingerprint-modal client-stable-glass">
          <aside class="client-fingerprint-sidebar">${fingerprintSidebarMarkup()}</aside>
          <div class="client-fingerprint-main">
            <header class="client-fingerprint-head">
              <input type="search" value="${escapeHtml(picker.query || '')}" placeholder="搜索品牌或型号，例如 iPhone" data-client-fingerprint-search>
              <button type="button" data-client-close-fingerprint aria-label="关闭">×</button>
            </header>
            <div class="client-fingerprint-path">${fingerprintPathMarkup()}</div>
            <div class="client-fingerprint-content">
              <div class="client-fingerprint-grid ${fingerprintGridMode(picker)} ${picker.loading ? 'is-loading' : ''}">${fingerprintGridMarkup()}</div>
            </div>
            <footer class="client-fingerprint-footer">
              <div class="client-fingerprint-preview">${fingerprintPreviewMarkup()}</div>
              <button class="client-fingerprint-upload-action" type="button" data-client-fingerprint-upload-placeholder>${picker.uploading ? '正在上传…' : '上传图片'}</button>
              <button class="client-fingerprint-apply" type="button" data-client-apply-fingerprint ${selected ? '' : 'disabled'}>使用当前选择</button>
            </footer>
          </div>
        </section>
      </div>`;
    }

    function render() {
      if (!page || !page.active || !root) return;
      if (shouldDeferRender(root)) {
        page.renderPending = true;
        window.clearTimeout(page.deferTimer);
        page.deferTimer = window.setTimeout(render, 500);
        return;
      }
      page.renderPending = false;
      const beforeDetailKey = detailRenderKey();
      const liveScrollState = beforeDetailKey && beforeDetailKey === page.lastDetailRenderKey ? captureDetailScrollState() : null;
      const scrollState = liveScrollState || (page.scrollState && page.scrollState[beforeDetailKey]) || null;
      rememberScrollState(beforeDetailKey, liveScrollState);
      page.scrollRestoreToken = (page.scrollRestoreToken || 0) + 1;
      const rows = filteredClients();
      page.lastTableStructureSignature = tableStructureSignature(rows);
      window.DWRT_UI_KIT?.unmount?.(root);
      root.innerHTML = `<section class="route-workspace route-client-details">
        <header class="client-toolbar">
          <nav class="dwrt-kit-tabs client-status-tabs" aria-label="终端在线状态">
            <span class="dwrt-kit-tab-pill" aria-hidden="true"></span>
            <button class="dwrt-kit-tab ${page.status === 'online' ? 'is-active' : ''}" type="button" data-value="online" aria-selected="${page.status === 'online' ? 'true' : 'false'}">在线</button>
            <button class="dwrt-kit-tab ${page.status === 'offline' ? 'is-active' : ''}" type="button" data-value="offline" aria-selected="${page.status === 'offline' ? 'true' : 'false'}">离线</button>
          </nav>
          <div class="client-toolbar-right">
            <label class="client-search-field" aria-label="搜索终端"><input type="search" data-client-search value="${escapeHtml(firstText(page.filters.keyword, page.search))}" placeholder="搜索终端"></label>
            <label class="client-ipv6-toggle"><input type="checkbox" data-client-ipv6 ${page.showIpv6 ? 'checked' : ''}><span aria-hidden="true"><svg viewBox="0 0 20 20"><path d="M4 10.4 8.1 14 16 5.8"></path></svg></span><strong>显示IPv6</strong></label>
            <button class="client-filter-button" type="button" data-client-filter-open aria-label="筛选终端">
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M7 12h10M10 17h4"></path></svg>
            </button>
          </div>
        </header>
        <section class="client-table-panel">
          ${tableMarkup(rows, page.error)}
        </section>
        ${detailDrawer()}
        ${filterDrawer()}
        ${columnFilterPopover()}
        ${fingerprintModal()}
      </section>`;
      mountUiKit(root);
      scheduleGlassCardsRender(160);
      scheduleOverviewChartsRender(80);
      scheduleProtocolChartsRender(80);
      restoreDetailScrollState(scrollState);
      page.lastDetailRenderKey = detailRenderKey();
    }

    function ipv6PrefixBase(prefix) {
      const text = firstText(prefix);
      if (!text.includes('/')) return '';
      const [addr, bitsRaw] = text.split('/');
      const bits = Number(bitsRaw) || 0;
      if (bits <= 0 || bits > 64) return '';
      const groups = ipv6Expand(addr);
      if (groups.length !== 8) return '';
      return groups.slice(0, 4).map((part) => part.toString(16)).join(':');
    }

    function macToEui64Host(mac) {
      const hex = firstText(mac).replace(/[^0-9a-f]/gi, '').toLowerCase();
      if (hex.length !== 12) return '';
      const bytes = [];
      for (let i = 0; i < 12; i += 2) bytes.push(Number.parseInt(hex.slice(i, i + 2), 16));
      if (bytes.some((num) => !Number.isFinite(num))) return '';
      bytes[0] ^= 0x02;
      const eui = [bytes[0], bytes[1], bytes[2], 0xff, 0xfe, bytes[3], bytes[4], bytes[5]];
      const groups = [];
      for (let i = 0; i < eui.length; i += 2) groups.push(((eui[i] << 8) | eui[i + 1]).toString(16));
      return groups.join(':');
    }

    function inferIpv6FromMac(mac) {
      const prefixes = page && Array.isArray(page.ipv6Prefixes) ? page.ipv6Prefixes : [];
      const host = macToEui64Host(mac);
      if (!prefixes.length || !host) return '';
      for (const prefix of prefixes) {
        const base = ipv6PrefixBase(prefix);
        if (base) return `${base}:${host}`;
      }
      return '';
    }

    function applyCachedRuntimeRows() {
      if (!page || !page.runtimeRows || !page.runtimeRows.size) return false;
      const now = Date.now();
      const rows = [];
      page.runtimeRows.forEach((row, mac) => {
        if (!row || now - (row._runtimeAt || 0) > 6500) {
          page.runtimeRows.delete(mac);
          return;
        }
        rows.push(row);
      });
      return mergeRuntimeRows(rows, { cache: false });
    }

    function listFromAny(...values) {
      for (const value of values) {
        const list = listFrom(value);
        if (list.length) return list;
      }
      return [];
    }

    function mergeRuntimeRows(rows = [], options = {}) {
      if (!page || !Array.isArray(rows) || !rows.length) return false;
      const byMac = new Map();
      rows.forEach((row) => {
        const mac = firstText(row && (row.mac || row.client_mac || row.id || row.node_id)).toLowerCase();
        if (!mac) return;
        const cached = { ...row, _runtimeAt: row._runtimeAt || Date.now() };
        byMac.set(mac, cached);
        if (options.cache !== false) {
          if (!page.runtimeRows) page.runtimeRows = new Map();
          page.runtimeRows.set(mac, cached);
        }
      });
      if (!byMac.size) return false;
      let changed = false;
      page.clients = page.clients.map((client) => {
        const row = byMac.get(String(client.mac || '').toLowerCase());
        if (!row) return client;
        changed = true;
        return normalizeClient({
          ...client,
          up_rate: heldClientRate(client, row, 'up'),
          down_rate: heldClientRate(client, row, 'down'),
          connections: firstNumber(row.connections, row.conn_count, client.connections),
          ...runtimeFamilyPatch(row),
          online: row.online !== undefined ? row.online : client.online,
          status: firstText(row.state, row.status, client.status),
          ip: firstText(row.client_ip, row.ip, client.ip),
          ipv6_addrs: asArray(row.ipv6_addrs).length ? row.ipv6_addrs : client.ipv6_addrs,
          ipv6_global: firstText(row.ipv6_global, row.global_ipv6, row.public_ipv6, row.ipv6, client.ipv6_global),
          ipv6_lan: firstText(row.ipv6_lan, row.lan_ipv6, row.local_ipv6, client.ipv6_lan),
          ipv6_link_local: firstText(row.ipv6_link_local, row.link_local_ipv6, client.ipv6_link_local)
        });
      });
      return changed;
    }

    function mergeIpv6FromNeighborRows(rows = []) {
      if (!page || !Array.isArray(rows) || !rows.length) return false;
      const byMac = new Map();
      rows.forEach((row) => {
        const mac = firstText(row && (row.mac || row.lladdr || row.client_mac)).toLowerCase();
        const addr = firstText(row && (row.ipv6 || row.ip || row.addr || row.address));
        if (!mac || !addr || !addr.includes(':')) return;
        const current = byMac.get(mac) || [];
        current.push(addr);
        byMac.set(mac, current);
      });
      if (!byMac.size) return false;
      let changed = false;
      page.clients = page.clients.map((client) => {
        const addrs = byMac.get(String(client.mac || '').toLowerCase());
        if (!addrs || !addrs.length) return client;
        const merged = Array.from(new Set([].concat(asArray(client.ipv6_addrs), asArray(client.ipv6_addresses), addrs).filter(Boolean).map(String)));
        changed = true;
        return normalizeClient({ ...client, ipv6_addrs: merged });
      });
      return changed;
    }

    function realtimeRowsFromPayload(payload = {}) {
      const data = payload && payload.data && typeof payload.data === 'object' ? payload.data : payload;
      return listFromAny(data && data.clients, data && data.flows, data && data.nodes, data && data.node_totals, data && data.items, data && data.list, data);
    }

    function detailMacFromPayload(payload = {}) {
      const data = payload && payload.data && typeof payload.data === 'object' ? payload.data : payload;
      return macKey(
        data.mac, data.client_mac, data.hwaddr,
        data.client && data.client.mac,
        data.basic && data.basic.mac,
        data.current && data.current.mac,
        data.profile && data.profile.mac
      );
    }

    function currentDetailMac() {
      return page && page.detail && page.detail.open ? macKey(page.detail.mac) : '';
    }

    function appendOverviewRealtimeSample(patch = {}) {
      const mac = macKey(patch.mac, patch.client_mac, patch.basic && patch.basic.mac, page && page.detail && page.detail.mac);
      if (!page || !mac) return;
      const current = plainObject(patch.current);
      const store = page.clientOverviewSamples || (page.clientOverviewSamples = {});
      const list = store[mac] || [];
      const last = list[list.length - 1];
      const rawUp = numericValue(firstText(patch.up_rate, patch.rate_up, patch.tx_rate, patch.upload_rate, current.up_rate, current.tx_rate, current.rate_up));
      const rawDown = numericValue(firstText(patch.down_rate, patch.rate_down, patch.rx_rate, patch.download_rate, current.down_rate, current.rx_rate, current.rate_down));
      const sample = normalizeOverviewSample({
        ts: firstNumber(patch.ts, patch.timestamp, patch.generated_at, current.ts, current.timestamp, Math.floor(Date.now() / 1000)),
        up_rate: heldRate(mac, 'up', rawUp, last ? last.up : 0),
        down_rate: heldRate(mac, 'down', rawDown, last ? last.down : 0),
        connections: firstText(patch.connections, patch.conn_count, patch.active_connections, current.connections, current.conn_count, current.active_connections)
      }, 0, 1);
      if (!last || last.ts !== sample.ts || last.up !== sample.up || last.down !== sample.down || last.connections !== sample.connections) list.push(sample);
      const minTs = Math.floor(Date.now() / 1000) - 5 * 60;
      store[mac] = list.filter((point) => point.ts >= minTs).slice(-96);
    }

    function profilePatchFromRealtime(topic, payload = {}) {
      const data = payload && payload.data && typeof payload.data === 'object' ? payload.data : payload;
      const source = data.profile && typeof data.profile === 'object' ? { ...data.profile, ...data } : { ...data };
      delete source.profile;
      const patch = {};
      const current = { ...plainObject(source.current) };
      ['online', 'up_rate', 'down_rate', 'tx_rate', 'rx_rate', 'rate_up', 'rate_down', 'connections', 'conn_count', 'active_connections', 'today_up_bytes', 'today_down_bytes', 'visiting_app_name', 'visiting_url'].forEach((key) => {
        if (source[key] !== undefined) current[key] = source[key];
      });
      if (Object.keys(current).length) patch.current = current;

      const basic = { ...plainObject(source.basic) };
      ['mac', 'ip', 'ipv4', 'ipv6', 'ipv6_addrs', 'ipv6_global', 'global_ipv6', 'ipv6_lan', 'ipv6_link_local', 'hostname', 'name', 'nickname', 'vendor_name', 'vendor', 'manufacturer', 'model', 'device_model', 'device_name', 'device_type'].forEach((key) => {
        if (source[key] !== undefined) basic[key] = source[key];
      });
      if (Object.keys(basic).length) patch.basic = basic;

      const overview = listFromAny(source.overview_history, source.realtime_history, source.rate_history, source.traffic_history, source.history, source.samples, source.points);
      if (overview.length) patch.overview_history = trimRealtimeList(overview, 96);

      const protocolRows = listFromAny(source.protocols, source.protocol_list, source.protocol_details, source.protocol_stats, source.apps, source.applications, source.items, source.rows, source.protocol_summary && source.protocol_summary.protocols, source.protocol_summary && source.protocol_summary.items, source.protocol_summary && source.protocol_summary.rows);
      const protocolHistory = listFromAny(source.protocol_rate_history, source.protocol_history, source.app_rate_history, source.protocol_summary && source.protocol_summary.rate_history, source.protocol_summary && source.protocol_summary.history);
      if (protocolRows.length || protocolHistory.length || source.protocol_summary) {
        patch.protocol_summary = {
          ...plainObject(source.protocol_summary),
          ...(protocolRows.length ? { protocols: protocolRows } : {}),
          ...(protocolHistory.length ? { rate_history: trimRealtimeList(protocolHistory, 96) } : {})
        };
      }

      const connections = listFromAny(source.connections, source.connection_rows, source.connection_details, source.sessions, source.flows, source.conntrack);
      if (connections.length || /connections|conntrack/i.test(topic)) patch.connections = connections;

      ['visits', 'visit_list', 'app_history', 'records', 'online_history', 'lines', 'policies', 'diagnostics', 'capabilities', 'source'].forEach((key) => {
        if (source[key] !== undefined) patch[key] = source[key];
      });
      if (!patch.mac) patch.mac = firstText(source.mac, source.client_mac, source.hwaddr, source.basic && source.basic.mac, source.current && source.current.mac);
      return patch;
    }

    function mergeDetailProfilePatch(patch = {}) {
      if (!page || !page.detail || !page.detail.open || !patch || typeof patch !== 'object') return false;
      const wanted = currentDetailMac();
      const patchMac = macKey(patch.mac, patch.client_mac, patch.basic && patch.basic.mac, patch.current && patch.current.mac);
      if (patchMac && wanted && patchMac !== wanted) return false;
      const profile = page.detail.profile && typeof page.detail.profile === 'object' ? page.detail.profile : {};
      const merged = { ...profile };
      if (patch.current) merged.current = { ...plainObject(profile.current), ...plainObject(patch.current) };
      if (patch.basic) merged.basic = { ...plainObject(profile.basic), ...plainObject(patch.basic) };
      if (patch.overview_history) merged.overview_history = trimRealtimeList(mergeListUniqueBySignature(profile.overview_history, patch.overview_history, 96), 96);
      if (patch.protocol_summary) {
        const prev = plainObject(profile.protocol_summary);
        merged.protocol_summary = { ...prev, ...plainObject(patch.protocol_summary) };
        if (patch.protocol_summary.protocols) merged.protocol_summary.protocols = patch.protocol_summary.protocols;
        if (patch.protocol_summary.items) merged.protocol_summary.items = patch.protocol_summary.items;
        if (patch.protocol_summary.rows) merged.protocol_summary.rows = patch.protocol_summary.rows;
        if (patch.protocol_summary.rate_history) merged.protocol_summary.rate_history = trimRealtimeList(mergeListUniqueBySignature(prev.rate_history, patch.protocol_summary.rate_history, 96), 96);
        if (patch.protocol_summary.history) merged.protocol_summary.history = trimRealtimeList(mergeListUniqueBySignature(prev.history, patch.protocol_summary.history, 96), 96);
      }
      if (patch.connections) merged.connections = patch.connections;
      ['visits', 'visit_list', 'app_history', 'records', 'online_history', 'lines', 'policies'].forEach((key) => {
        if (patch[key] !== undefined) merged[key] = Array.isArray(patch[key]) ? patch[key] : patch[key];
      });
      ['diagnostics', 'capabilities'].forEach((key) => {
        if (patch[key] !== undefined) merged[key] = { ...plainObject(profile[key]), ...plainObject(patch[key]) };
      });
      if (patch.source !== undefined) merged.source = patch.source;
      if (patch.mac || patchMac) merged.mac = firstText(patch.mac, patchMac, profile.mac, page.detail.mac);
      page.detail.profile = merged;
      const target = currentDetailMac();
      page.clients = page.clients.map((client) => macKey(client.mac) === target ? profileClient(client, merged) : client);
      return true;
    }

    function scheduleDetailRealtimeRender() {
      if (!page || !page.active) return;
      if (page.detailRealtimeTimer) return;
      page.detailRealtimeTimer = window.setTimeout(() => {
        if (!page || !page.active) return;
        page.detailRealtimeTimer = 0;
        patchDetailChrome();
        if (page.detail.loading) return;
        if (page.detail.tab === 'overview') patchOverviewDetailPanel();
        else if (page.detail.tab === 'protocol') patchProtocolDetailPanel();
        else if (page.detail.tab === 'connection') patchConnectionDetailPanel();
      }, document.hidden ? 220 : 80);
    }

    function detailRuntimePatchFromRows(rows = []) {
      const target = currentDetailMac();
      if (!target || !Array.isArray(rows) || !rows.length) return null;
      const matched = rows.find((row) => macKey(row && (row.mac || row.client_mac || row.hwaddr || row.id || row.node_id)) === target);
      if (!matched) return null;
      return {
        mac: target,
        current: {
          up_rate: heldRate(target, 'up', firstNumber(matched.up_rate, matched.tx_rate, matched.rate_up, matched['tx_bytes-r'])),
          down_rate: heldRate(target, 'down', firstNumber(matched.down_rate, matched.rx_rate, matched.rate_down, matched['rx_bytes-r'])),
          connections: firstNumber(matched.connections, matched.conn_count, matched.active_connections),
          ...runtimeFamilyPatch(matched),
          online: matched.online,
          status: firstText(matched.state, matched.status)
        },
        basic: {
          mac: target,
          ip: firstText(matched.client_ip, matched.ip),
          ipv6_addrs: asArray(matched.ipv6_addrs).length ? matched.ipv6_addrs : undefined,
          ipv6_global: firstText(matched.ipv6_global, matched.global_ipv6, matched.public_ipv6, matched.ipv6),
          ipv6_lan: firstText(matched.ipv6_lan, matched.lan_ipv6, matched.local_ipv6),
          ipv6_link_local: firstText(matched.ipv6_link_local, matched.link_local_ipv6)
        }
      };
    }

    function applyClientDetailRealtime(topic, payload) {
      if (!page || !page.active || !page.detail || !page.detail.open) return false;
      const data = payload && payload.data && typeof payload.data === 'object' ? payload.data : payload;
      let patch = profilePatchFromRealtime(topic, data);
      const target = currentDetailMac();
      const patchMac = macKey(patch.mac, patch.client_mac, patch.basic && patch.basic.mac, patch.current && patch.current.mac);
      if (!patchMac && /^(clients\.metrics|topology\.flow)$/.test(topic)) {
        patch = detailRuntimePatchFromRows(realtimeRowsFromPayload(data)) || {};
      }
      if (!patch || !Object.keys(patch).length) return false;
      const finalMac = macKey(patch.mac, patch.client_mac, patch.basic && patch.basic.mac, patch.current && patch.current.mac);
      if (finalMac && target && finalMac !== target) return false;
      if (!finalMac) return false;
      appendOverviewRealtimeSample(patch);
      const changed = mergeDetailProfilePatch(patch);
      if (changed) {
        page.detailRealtimeLastAt = Date.now();
        if (/client\.(detail|protocols|connections|conntrack)/.test(topic)) page.detailRealtimeDataLastAt = Date.now();
        scheduleDetailRealtimeRender();
      }
      return changed;
    }

    function applyClientRealtime(topic, payload) {
      if (!page || !page.active) return;
      const data = payload && payload.data && typeof payload.data === 'object' ? payload.data : payload;
      const rows = realtimeRowsFromPayload(data);
      const changed = mergeRuntimeRows(rows);
      if (changed) {
        rows.forEach(pushClientOverviewSample);
        refreshTableFromData();
      }
      applyClientDetailRealtime(topic, data);
    }

    function subscribeClientRealtime() {
      if (!page || page.realtimeUnsubscribers || !realtime || typeof realtime.subscribe !== 'function') return;
      const topics = [
        'clients.metrics',
        'topology.flow',
        'client.detail',
        'client.overview',
        'client.protocols',
        'client.connections',
        'client.conntrack'
      ];
      page.realtimeUnsubscribers = topics.map((topic) => realtime.subscribe(topic, (data) => applyClientRealtime(topic, data)));
    }

    function unsubscribeClientRealtime() {
      if (!page || !Array.isArray(page.realtimeUnsubscribers)) return;
      page.realtimeUnsubscribers.forEach((fn) => fn && fn());
      page.realtimeUnsubscribers = null;
    }

    async function loadTopologyFlowRuntime() {
      if (!page || !page.active) return;
      const result = await fetchApiResource('topology_flow', '/api/v1/topology/flow');
      if (!page || !page.active || !result.ok) return;
      const data = result.data || {};
      if (mergeRuntimeRows([].concat(listFrom(data.flows), listFrom(data.nodes)))) refreshTableFromData();
    }

    function collectIpv6Prefixes(value, out = new Set()) {
      if (!value) return out;
      if (Array.isArray(value)) {
        value.forEach((item) => collectIpv6Prefixes(item, out));
        return out;
      }
      if (typeof value !== 'object') return out;
      ['ipv6_prefix', 'delegated_prefix', 'prefix', 'lan_ipv6_prefix'].forEach((key) => {
        const prefix = firstText(value[key]);
        if (prefix && prefix.includes(':') && prefix.includes('/')) out.add(prefix);
      });
      Object.values(value).forEach((item) => {
        if (item && typeof item === 'object') collectIpv6Prefixes(item, out);
      });
      return out;
    }

    async function loadIpv6Context() {
      if (!page || !page.active || !page.showIpv6) return;
      if (page.ipv6ContextLoading) return;
      page.ipv6ContextLoading = true;
      try {
        const result = await fetchApiResource('network_wans', '/api/v1/network/wans');
        if (!page || !page.active) return;
        if (result.ok) {
          const prefixes = Array.from(collectIpv6Prefixes(result.data));
          if (prefixes.length) {
            page.ipv6Prefixes = prefixes;
            page.clients = page.clients.map((client) => normalizeClient(client));
            renderTableOnly();
          }
        }
      } finally {
        if (page) page.ipv6ContextLoading = false;
      }
    }

    async function loadIpv6Neighbors() {
      if (!page || !page.active || !page.showIpv6) return;
      if (!page.ipv6Prefixes || !page.ipv6Prefixes.length) loadIpv6Context();
      const result = await fetchApiResource('ipv6_load', '/api/v1/monitor/ipv6-load');
      if (!page || !page.active || !result.ok) return;
      const data = result.data || {};
      const rows = listFromAny(data.neighbors, data.clients, data.items);
      if (mergeIpv6FromNeighborRows(rows)) renderTableOnly();
    }

    async function loadClients() {
      if (!page || !page.active || page.loading) return;
      if (shouldHoldRender()) return;
      page.loading = true;
      const result = await fetchApiResource('clients', '/api/v1/clients');
      if (!page || !page.active) return;
      page.loading = false;
      if (result.ok) {
        page.clients = listFrom(result.data).map(normalizeClient);
        applyCachedRuntimeRows();
        page.clients.forEach(pushClientOverviewSample);
        page.error = '';
        loadTopologyFlowRuntime();
        loadIpv6Neighbors();
      } else {
        const message = result.error && result.error.message ? result.error.message : '读取终端详情失败';
        page.error = /invalid json/i.test(message) ? '终端接口返回了非 JSON 错误，请查看后端 /api/v1/clients' : message;
      }
      if (result.ok && root.querySelector('.client-table-panel')) refreshTableFromData();
      else renderOrDefer('load-clients');
      const detailWsFresh = page.detailRealtimeDataLastAt && Date.now() - page.detailRealtimeDataLastAt < 12000;
      if (page.detail && page.detail.open && ['connection', 'protocol'].includes(page.detail.tab) && page.connectionAutoRefresh !== false && !detailWsFresh) {
        loadProfile(page.detail.mac, { preserve: true });
      }
    }

    async function loadProfile(mac, options = {}) {
      if (!page || !page.active || !mac) return;
      const preserve = Boolean(options && options.preserve);
      if (preserve && page.detail.profileRefreshing) return;
      page.detail.profileRefreshing = true;
      if (!preserve) {
        page.detail.loading = true;
        page.detail.profile = {};
        renderOrDefer('profile-loading');
      }
      const result = await fetchApiResource('client_profile', `/api/v1/client_profile?mac=${encodeURIComponent(mac)}`);
      if (!page || !page.active || String(page.detail.mac).toLowerCase() !== String(mac).toLowerCase()) return;
      page.detail.loading = false;
      page.detail.profileRefreshing = false;
      const profileData = result.ok ? result.data || {} : { error: result.error && result.error.message };
      page.detail.profile = profileData;
      if (result.ok) {
        const target = String(mac || '').toLowerCase();
        page.clients = page.clients.map((client) => String(client.mac || '').toLowerCase() === target ? profileClient(client, profileData) : client);
      }
      if (!(preserve && (patchOverviewDetailPanel() || patchProtocolDetailPanel() || patchConnectionDetailPanel()))) renderOrDefer('profile-loaded');
    }

    async function clearConnections() {
      if (!page || !page.detail || !page.detail.open || !page.detail.mac) return;
      const mac = page.detail.mac;
      page.connectionNotice = '正在清除连接…';
      renderOrDefer('connection-notice');
      const result = await postApiResource('client_connections_clear', '/api/v1/client_connections/clear', { mac });
      if (!page || !page.active) return;
      if (result.ok) {
        page.connectionNotice = '已提交清除连接';
        loadProfile(mac, { preserve: true });
      } else {
        const msg = result.error && result.error.message ? result.error.message : 'unknown';
        page.connectionNotice = /404|not found/i.test(msg) ? '清除连接接口未就绪' : `清除失败：${msg}`;
      }
      renderOrDefer('connection-notice');
      window.clearTimeout(page.connectionNoticeTimer);
      page.connectionNoticeTimer = window.setTimeout(() => {
        if (!page) return;
        page.connectionNotice = '';
        renderOrDefer('connection-notice');
      }, 2600);
    }

    async function closeOneConnection(button) {
      if (!page || !page.detail || !page.detail.open || !button) return;
      let payload = {};
      try { payload = JSON.parse(button.dataset.clientConnectionClosePayload || '{}'); } catch (_) { payload = {}; }
      payload.mac = firstText(payload.mac, page.detail.mac);
      page.connectionNotice = '正在关闭连接…';
      patchConnectionDetailPanel() || renderOrDefer('connection-close-one');
      button.disabled = true;
      button.classList.add('is-working');
      const result = await postApiResource('client_connection_close', '/api/v1/client_connections/close', payload);
      if (!page || !page.active) return;
      if (result.ok) {
        page.connectionNotice = '已提交关闭连接';
        loadProfile(page.detail.mac, { preserve: true });
      } else {
        const msg = result.error && result.error.message ? result.error.message : 'unknown';
        page.connectionNotice = /404|not found/i.test(msg) ? '关闭单条连接接口未就绪' : `关闭失败：${msg}`;
      }
      patchConnectionDetailPanel() || renderOrDefer('connection-close-one-result');
      window.clearTimeout(page.connectionNoticeTimer);
      page.connectionNoticeTimer = window.setTimeout(() => {
        if (!page) return;
        page.connectionNotice = '';
        patchConnectionDetailPanel() || renderOrDefer('connection-close-one-clear');
      }, 2600);
    }

    function fallbackCopyText(value) {
      const text = String(value || '');
      if (!text) return false;
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.setAttribute('readonly', '');
      textarea.setAttribute('aria-hidden', 'true');
      textarea.style.position = 'fixed';
      textarea.style.left = '-9999px';
      textarea.style.top = '0';
      textarea.style.width = '1px';
      textarea.style.height = '1px';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      const selection = document.getSelection ? document.getSelection() : null;
      const ranges = [];
      if (selection) {
        for (let index = 0; index < selection.rangeCount; index += 1) ranges.push(selection.getRangeAt(index));
      }
      textarea.focus({ preventScroll: true });
      textarea.select();
      textarea.setSelectionRange(0, textarea.value.length);
      let ok = false;
      try { ok = document.execCommand && document.execCommand('copy'); } catch (_) { ok = false; }
      document.body.removeChild(textarea);
      if (selection) {
        selection.removeAllRanges();
        ranges.forEach((range) => selection.addRange(range));
      }
      return Boolean(ok);
    }

    function flashCopyState(button, ok) {
      if (!button) return;
      button.classList.remove('is-copied', 'is-copy-failed');
      void button.offsetWidth;
      button.classList.add(ok ? 'is-copied' : 'is-copy-failed');
      window.setTimeout(() => button.classList.remove('is-copied', 'is-copy-failed'), ok ? 1100 : 1300);
    }

    async function copyValue(button) {
      const value = button && button.dataset.clientCopyValue || '';
      if (!value || value === '--') return;
      let ok = false;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(value);
          ok = true;
        }
      } catch (_) {
        ok = false;
      }
      if (!ok) ok = fallbackCopyText(value);
      flashCopyState(button, ok);
    }

    function currentCustomForm() {
      return root.querySelector('[data-client-custom-form]');
    }

    function readCustomDraft(form = currentCustomForm()) {
      if (!form) return null;
      return {
        mac: firstText(form.elements.mac && form.elements.mac.value, page && page.detail && page.detail.mac),
        nickname: firstText(form.elements.nickname && form.elements.nickname.value),
        vendor_name: firstText(form.elements.vendor_name && form.elements.vendor_name.value),
        device_type: firstText(form.elements.device_type && form.elements.device_type.value, 'unknown'),
        device_name: firstText(form.elements.device_name && form.elements.device_name.value),
        custom_image_path: firstText(form.elements.custom_image_path && form.elements.custom_image_path.value)
      };
    }

    function updateCustomDraft(form = currentCustomForm()) {
      const draft = readCustomDraft(form);
      if (draft && draft.mac) page.customDraft = draft;
      return draft;
    }

    function clientOverridePayload(form = currentCustomForm()) {
      const draft = readCustomDraft(form) || {};
      return {
        mac: firstText(draft.mac),
        nickname: firstText(draft.nickname),
        custom_name: firstText(draft.nickname),
        vendor_name: firstText(draft.vendor_name),
        custom_vendor: firstText(draft.vendor_name),
        device_type: firstText(draft.device_type, 'unknown'),
        custom_device_type: firstText(draft.device_type, 'unknown'),
        device_name: firstText(draft.device_name),
        model: firstText(draft.device_name),
        custom_image_path: firstText(draft.custom_image_path),
        custom_icon: firstText(draft.custom_image_path),
        note: 'user-custom'
      };
    }

    function applyClientOverride(payload = {}) {
      const target = macKey(payload.mac);
      if (!target) return;
      if (payload.custom_image_path) setClientImageOverride(target, payload.custom_image_path);
      page.customDraft = {
        mac: payload.mac,
        nickname: payload.nickname,
        vendor_name: payload.vendor_name,
        device_type: payload.device_type,
        device_name: payload.device_name,
        custom_image_path: payload.custom_image_path
      };
      page.clients = page.clients.map((client) => macKey(client.mac) === target ? normalizeClient({
        ...client,
        nickname: payload.nickname || client.nickname,
        custom_name: payload.custom_name || client.custom_name,
        vendor: payload.vendor_name || client.vendor,
        vendor_name: payload.vendor_name || client.vendor_name,
        manufacturer: payload.vendor_name || client.manufacturer,
        type: payload.device_type || client.type,
        device_type: payload.device_type || client.device_type,
        model: payload.device_name || client.model,
        device_model: payload.device_name || client.device_model,
        device_name: payload.device_name || client.device_name,
        image: payload.custom_image_path || client.image,
        custom_icon: payload.custom_icon || client.custom_icon,
        custom_image_path: payload.custom_image_path || client.custom_image_path,
        fingerprint_confidence: 100,
        fingerprint_source: 'override'
      }) : client);
      window.dispatchEvent(new CustomEvent('dwrt:client-image-updated', {
        detail: { mac: target, src: payload.custom_image_path || '' }
      }));
    }

    async function saveClientOverride(form = currentCustomForm(), options = {}) {
      const status = form && form.querySelector('[data-client-custom-status]');
      const payload = clientOverridePayload(form);
      if (!payload.mac) {
        if (status) status.textContent = '缺少 MAC，无法保存';
        return { ok: false, error: new Error('missing_mac') };
      }
      if (status) status.textContent = options.upload ? '正在保存设备图片...' : '保存中...';
      if (form) form.classList.add('is-saving');
      const result = await postApiResource('client_override', '/api/v1/client_override', payload);
      if (form) form.classList.remove('is-saving');
      if (!result.ok) {
        if (status) status.textContent = `保存失败：${result.error && result.error.message ? result.error.message : 'unknown'}`;
        return result;
      }
      applyClientOverride(payload);
      if (status) status.textContent = options.upload ? '设备图片已上传并保存' : '已保存';
      return { ...result, payload };
    }

    function customDraftFor(client) {
      const draft = page && page.customDraft;
      if (!draft || !client) return {};
      return String(draft.mac || '').toLowerCase() === String(client.mac || '').toLowerCase() ? draft : {};
    }

    async function openFingerprintPicker(form = currentCustomForm()) {
      if (!page || !form) return;
      const draft = updateCustomDraft(form) || {};
      const deviceTypeValue = draft.device_type || 'unknown';
      page.fingerprint = {
        open: true,
        category: fingerprintCategoryFromType(deviceTypeValue),
        vendor: firstText(draft.vendor_name),
        query: firstText(draft.device_name),
        loading: false,
        uploading: false,
        devices: [],
        vendors: [],
        categories: FINGERPRINT_CATEGORY_FALLBACK,
        error: ''
      };
      renderOrDefer('fingerprint');
      await loadFingerprintCandidates();
    }

    function closeFingerprintPicker() {
      if (!page || !page.fingerprint) return;
      page.fingerprint.open = false;
      const pending = page.renderAfterFingerprint;
      page.renderAfterFingerprint = false;
      render();
      if (pending) window.setTimeout(() => { if (page && page.active) render(); }, 0);
    }

    async function loadFingerprintCandidates() {
      if (!page || !page.fingerprint || !page.fingerprint.open) return;
      const picker = page.fingerprint;
      const requestCategory = firstText(picker.category);
      const requestVendor = firstText(picker.vendor);
      const requestQuery = firstText(picker.query);
      const requestSeq = (picker.requestSeq || 0) + 1;
      picker.requestSeq = requestSeq;
      picker.loading = true;
      picker.error = '';
      renderOrDefer('fingerprint');
      const params = new URLSearchParams();
      const categoryConfig = fingerprintCategoryConfig(picker.category || 'phone');
      const userQuery = requestQuery;
      const queryHint = !userQuery ? firstText(categoryConfig.queryHint) : '';
      params.set('category', userQuery ? 'all' : firstText(categoryConfig.apiCategory, picker.category, 'phone'));
      params.set('ui_category', firstText(picker.category, categoryConfig.key, 'unknown'));
      params.set('scope', 'category');
      params.set('limit', picker.vendor || userQuery ? '120' : '120');
      if (userQuery) params.set('q', userQuery);
      else if (queryHint && firstText(categoryConfig.apiCategory) !== firstText(picker.category)) params.set('q', queryHint);
      if (picker.vendor && !userQuery) params.set('vendor', picker.vendor);
      const result = await fetchApiResource('fingerprint_index', `/api/v1/fingerprint_index?${params.toString()}`);
      if (!page || !page.fingerprint || !page.fingerprint.open) return;
      if (page.fingerprint.requestSeq !== requestSeq || firstText(page.fingerprint.category) !== requestCategory || firstText(page.fingerprint.vendor) !== requestVendor || firstText(page.fingerprint.query) !== requestQuery) return;
      page.fingerprint.loading = false;
      if (result.ok) {
        const data = result.data || {};
        page.fingerprint.devices = Array.isArray(data.devices) ? data.devices : [];
        page.fingerprint.vendors = Array.isArray(data.vendors) ? data.vendors : [];
        if (Array.isArray(data.categories) && data.categories.length) {
          page.fingerprint.categories = data.categories.map(normalizeFingerprintCategory).filter(Boolean);
        }
        page.fingerprint.error = '';
      } else {
        page.fingerprint.devices = [];
        page.fingerprint.vendors = [];
        const message = result.error && result.error.message ? result.error.message : 'unknown';
        page.fingerprint.error = /not found|404/i.test(message)
          ? '设备图库接口未就绪：webd 缺少 /api/v1/fingerprint_index'
          : `图库读取失败：${message}`;
      }
      renderOrDefer('fingerprint');
    }

    function applyFingerprintSelection(index = 0) {
      if (!page || !page.fingerprint) return;
      const item = page.fingerprint.devices[Number(index) || 0];
      const form = currentCustomForm();
      if (!item || !form) return;
      const image = firstText(item.web_image, item.image, item.icon);
      if (form.elements.device_type) form.elements.device_type.value = formDeviceTypeFromFingerprint(item);
      if (form.elements.vendor_name) form.elements.vendor_name.value = firstText(item.vendor_name, item.vendor, '');
      if (form.elements.device_name) form.elements.device_name.value = firstText(item.device_name, item.name, item.model, '');
      if (form.elements.custom_image_path) form.elements.custom_image_path.value = image;
      if (form.elements.nickname && !form.elements.nickname.value) form.elements.nickname.value = firstText(item.device_name, item.name, '');
      updateCustomDraft(form);
      page.fingerprint.open = false;
      renderOrDefer('fingerprint');
    }

    function isSupportedFingerprintImageFile(file) {
      if (!file) return false;
      const type = firstText(file.type).toLowerCase();
      const name = firstText(file.name).toLowerCase();
      if (/^image\/(png|jpeg|jpg|webp|gif|svg\+xml)$/i.test(type)) return true;
      return /\.(png|jpe?g|webp|gif|svg)$/i.test(name);
    }

    function fingerprintImageDataUrl(file) {
      if (!file) return Promise.reject(new Error('missing_file'));
      const name = firstText(file.name).toLowerCase();
      const type = firstText(file.type).toLowerCase();
      const isSvg = type === 'image/svg+xml' || /\.svg$/i.test(name);
      if (!isSvg) {
        return new Promise((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = () => resolve(String(reader.result || ''));
          reader.onerror = () => reject(new Error('读取图片失败'));
          reader.readAsDataURL(file);
        });
      }
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
          const svgText = String(reader.result || '').trim();
          if (!/<svg[\s>]/i.test(svgText)) {
            reject(new Error('SVG 内容无效'));
            return;
          }
          const bytes = new TextEncoder().encode(svgText);
          let binary = '';
          bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
          resolve(`data:image/svg+xml;base64,${btoa(binary)}`);
        };
        reader.onerror = () => reject(new Error('读取 SVG 失败'));
        reader.readAsText(file);
      });
    }

    async function uploadFingerprintImage(file) {
      const form = currentCustomForm();
      const picker = page && page.fingerprint;
      if (!file || !form || !picker) return;
      if (!isSupportedFingerprintImageFile(file)) {
        picker.error = '仅支持 PNG / JPG / WebP / GIF / SVG';
        renderOrDefer('fingerprint');
        return;
      }
      if (file.size > 2 * 1024 * 1024) {
        picker.error = '图片不能超过 2 MiB';
        renderOrDefer('fingerprint');
        return;
      }
      const mac = firstText(form.elements.mac && form.elements.mac.value, page.detail.mac);
      if (!mac) {
        picker.error = '缺少 MAC，无法保存图片';
        renderOrDefer('fingerprint');
        return;
      }
      picker.uploading = true;
      picker.error = '';
      renderOrDefer('fingerprint');
      try {
        const imageDataUrl = await fingerprintImageDataUrl(file);
        const result = await postApiResource('fingerprint_upload', '/api/v1/fingerprint_upload', {
          mac,
          filename: file.name || 'client-image',
          image_data_url: imageDataUrl
        });
        if (!result.ok) throw result.error || new Error('upload_failed');
        const url = firstText(result.data && result.data.url, result.data && result.data.path, result.data && result.data.web_image);
        if (!url) throw new Error('missing_upload_url');
        if (form.elements.custom_image_path) form.elements.custom_image_path.value = url;
        updateCustomDraft(form);
        const saved = await saveClientOverride(form, { upload: true });
        if (!saved.ok) throw saved.error || new Error('override_save_failed');
        picker.open = false;
        window.setTimeout(() => {
          if (page && page.active) loadProfile(mac, { preserve: true });
        }, 0);
      } catch (error) {
        picker.error = `上传失败：${error && error.message ? error.message : 'unknown'}`;
      } finally {
        picker.uploading = false;
        renderOrDefer('fingerprint');
      }
    }

    function setStatus(status) {
      page.status = status === 'offline' ? 'offline' : 'online';
      writeStored(STATUS_KEY, page.status);
      render();
    }

    function setSort(key) {
      if (page.sort.key === key) page.sort.direction = page.sort.direction === 'asc' ? 'desc' : 'asc';
      else page.sort = { key, direction: 'asc' };
      writeStored(SORT_KEY, JSON.stringify(page.sort));
      render();
    }

    function saveColumnFilterFromCard(card) {
      const key = firstText(card && card.dataset && card.dataset.column, page && page.columnFilterOpen);
      const config = CLIENT_COLUMN_FILTERS[key];
      if (!key || !config) return;
      const value = Number(card.querySelector('[data-client-column-filter-value]')?.value);
      const mode = card.querySelector('input[name="client-column-filter-mode"]:checked')?.value === 'exclude' ? 'exclude' : 'include';
      const op = card.querySelector('input[name="client-column-filter-op"]:checked')?.value || 'gte';
      const unit = card.querySelector('[data-client-column-filter-unit]')?.value || columnFilterUnits(config)[0];
      if (!page.filters.columnFilters || typeof page.filters.columnFilters !== 'object') page.filters.columnFilters = {};
      if (Number.isFinite(value) && value >= 0) {
        page.filters.columnFilters[key] = { mode, op: ['gte', 'lte', 'eq', 'gt', 'lt'].includes(op) ? op : 'gte', value, unit };
      } else {
        delete page.filters.columnFilters[key];
      }
      saveFilters();
      page.columnFilterOpen = '';
      render();
    }

    function resetColumnFilter(key = page && page.columnFilterOpen) {
      const columnKey = firstText(key);
      if (!columnKey) return;
      if (!page.filters.columnFilters || typeof page.filters.columnFilters !== 'object') page.filters.columnFilters = {};
      delete page.filters.columnFilters[columnKey];
      saveFilters();
      page.columnFilterOpen = '';
      render();
    }

    function moveClientColumn(sourceKey, targetKey) {
      const from = firstText(sourceKey);
      const to = firstText(targetKey);
      if (!from || !to || from === to) return false;
      const order = (Array.isArray(page.columnOrder) ? page.columnOrder : parseClientColumnOrder()).filter((key) => CLIENT_TABLE_COLUMN_KEYS.includes(key));
      CLIENT_TABLE_COLUMN_KEYS.forEach((key) => { if (!order.includes(key)) order.push(key); });
      const sourceIndex = order.indexOf(from);
      const targetIndex = order.indexOf(to);
      if (sourceIndex < 0 || targetIndex < 0) return false;
      const [item] = order.splice(sourceIndex, 1);
      order.splice(targetIndex, 0, item);
      page.columnOrder = order;
      saveClientColumnOrder();
      renderTableOnly({ force: true });
      return true;
    }

    function handleColumnDragStart(event) {
      const handle = event.target.closest('[data-client-column-drag]');
      if (!handle || !root || !root.contains(handle)) return;
      const key = handle.dataset.clientColumnDrag;
      if (!CLIENT_TABLE_COLUMN_KEYS.includes(key)) return;
      page.dragColumnKey = key;
      handle.classList.add('is-dragging');
      if (event.dataTransfer) {
        event.dataTransfer.effectAllowed = 'move';
        event.dataTransfer.setData('text/plain', key);
      }
    }

    function handleColumnDragOver(event) {
      const handle = event.target.closest('[data-client-column-drag]');
      if (!handle || !page.dragColumnKey) return;
      event.preventDefault();
      if (event.dataTransfer) event.dataTransfer.dropEffect = 'move';
      root.querySelectorAll('[data-client-column-drag].is-drag-over').forEach((node) => node.classList.remove('is-drag-over'));
      handle.classList.add('is-drag-over');
    }

    function handleColumnDrop(event) {
      const handle = event.target.closest('[data-client-column-drag]');
      if (!handle || !page.dragColumnKey) return;
      event.preventDefault();
      const source = page.dragColumnKey || event.dataTransfer && event.dataTransfer.getData('text/plain');
      const target = handle.dataset.clientColumnDrag;
      page.dragColumnKey = '';
      root.querySelectorAll('[data-client-column-drag].is-dragging, [data-client-column-drag].is-drag-over').forEach((node) => node.classList.remove('is-dragging', 'is-drag-over'));
      moveClientColumn(source, target);
    }

    function handleColumnDragEnd() {
      if (!page) return;
      page.dragColumnKey = '';
      if (root) root.querySelectorAll('[data-client-column-drag].is-dragging, [data-client-column-drag].is-drag-over').forEach((node) => node.classList.remove('is-dragging', 'is-drag-over'));
    }

    function handleClick(event) {
      const copy = event.target.closest('[data-client-copy-value]');
      if (copy) {
        copyValue(copy);
        return;
      }
      const statusTab = event.target.closest('.client-status-tabs .dwrt-kit-tab');
      if (statusTab) {
        setStatus(statusTab.dataset.value);
        return;
      }
      const columnFilterOpen = event.target.closest('[data-client-column-filter-open]');
      if (columnFilterOpen) {
        page.columnFilterOpen = columnFilterOpen.dataset.clientColumnFilterOpen || '';
        render();
        return;
      }
      if (event.target.closest('[data-client-column-filter-cancel]')) {
        page.columnFilterOpen = '';
        render();
        return;
      }
      const columnFilterReset = event.target.closest('[data-client-column-filter-reset]');
      if (columnFilterReset) {
        const card = event.target.closest('[data-client-column-filter-card]');
        resetColumnFilter(card && card.dataset && card.dataset.column);
        return;
      }
      const columnFilterSave = event.target.closest('[data-client-column-filter-save]');
      if (columnFilterSave) {
        const card = event.target.closest('[data-client-column-filter-card]');
        if (card) saveColumnFilterFromCard(card);
        return;
      }
      const sort = event.target.closest('[data-client-sort]');
      if (sort) {
        setSort(sort.dataset.clientSort);
        return;
      }
      const close = event.target.closest('[data-client-detail-close]');
      if (close) {
        page.detail.open = false;
        render();
        return;
      }
      if (event.target.closest('[data-client-filter-open]')) {
        page.filterOpen = true;
        page.columnFilterOpen = '';
        render();
        return;
      }
      if (event.target.closest('[data-client-filter-close]')) {
        page.filterOpen = false;
        render();
        return;
      }
      if (event.target.closest('[data-client-connection-options]')) {
        page.connectionOptionsOpen = true;
        render();
        return;
      }
      if (event.target.closest('[data-client-connection-options-close]')) {
        page.connectionOptionsOpen = false;
        render();
        return;
      }
      const connectionOptionTab = event.target.closest('[data-client-connection-options-tab]');
      if (connectionOptionTab) {
        page.connectionOptionTab = connectionOptionTab.dataset.clientConnectionOptionsTab === 'columns' ? 'columns' : 'filter';
        writeStored(CONNECTION_OPTION_TAB_KEY, page.connectionOptionTab);
        render();
        return;
      }
      if (event.target.closest('[data-client-control-add]')) {
        page.controlEditorOpen = true;
        page.controlNotice = '';
        page.controlDraft = {
          control_type: 'IP限速',
          name: '',
          schedule_mode: 'week',
          days: ['一', '二', '三', '四', '五', '六', '日'],
          start_time: '00:00',
          end_time: '23:59',
          limit_mode: '独立限速',
          up_limit: '0',
          down_limit: '0',
          protocol: '任意'
        };
        render();
        return;
      }
      if (event.target.closest('[data-client-control-close]')) {
        page.controlEditorOpen = false;
        page.controlNotice = '';
        const pending = page.renderAfterControl;
        page.renderAfterControl = false;
        render();
        if (pending) window.setTimeout(() => { if (page && page.active) render(); }, 0);
        return;
      }
      if (event.target.closest('[data-client-control-time-clear]')) {
        const form = event.target.closest('[data-client-control-form]');
        if (form) {
          if (form.elements.start_time) form.elements.start_time.value = '00:00';
          if (form.elements.end_time) form.elements.end_time.value = '23:59';
        }
        return;
      }
      if (event.target.closest('[data-client-control-refresh]')) {
        if (page.detail && page.detail.mac) loadProfile(page.detail.mac, { preserve: true });
        return;
      }
      const controlToggle = event.target.closest('[data-client-control-toggle]');
      if (controlToggle) {
        const rule = currentControlRule(controlToggle.dataset.clientControlToggle);
        if (rule) void toggleControlRule(rule);
        return;
      }
      const controlEdit = event.target.closest('[data-client-control-action]');
      if (controlEdit) {
        const rule = currentControlRule(controlEdit.dataset.clientControlAction);
        if (rule) editControlRule(rule);
        return;
      }
      const controlDelete = event.target.closest('[data-client-control-delete]');
      if (controlDelete) {
        const rule = currentControlRule(controlDelete.dataset.clientControlDelete);
        if (rule) void deleteControlRule(rule);
        return;
      }
      const overviewLegend = event.target.closest('[data-client-overview-legend]');
      if (overviewLegend) {
        const key = overviewLegend.dataset.clientOverviewLegend;
        if (key) {
          page.overviewLegend = page.overviewLegend || parseOverviewLegend();
          page.overviewLegend[key] = page.overviewLegend[key] === false;
          saveOverviewLegend();
          if (!patchOverviewDetailPanel()) render();
        }
        return;
      }
      const closeConnection = event.target.closest('[data-client-connection-close-one]');
      if (closeConnection) {
        closeOneConnection(closeConnection);
        return;
      }
      const connectionProto = event.target.closest('[data-client-connection-filter-proto]');
      if (connectionProto) {
        page.connectionFilters.proto = connectionProto.dataset.clientConnectionFilterProto || 'all';
        saveConnectionFilters();
        render();
        return;
      }
      const connectionLine = event.target.closest('[data-client-connection-filter-line]');
      if (connectionLine) {
        page.connectionFilters.line = connectionLine.dataset.clientConnectionFilterLine || 'all';
        saveConnectionFilters();
        render();
        return;
      }
      if (event.target.closest('[data-client-connection-refresh]')) {
        if (page.detail && page.detail.mac) loadProfile(page.detail.mac, { preserve: true });
        return;
      }
      if (event.target.closest('[data-client-connection-autorefresh]')) {
        page.connectionAutoRefresh = page.connectionAutoRefresh === false;
        writeStored(CONNECTION_AUTO_KEY, page.connectionAutoRefresh === false ? '0' : '1');
        render();
        return;
      }
      if (event.target.closest('[data-client-connection-clear]')) {
        clearConnections();
        return;
      }
      const protocolChartMode = event.target.closest('[data-client-protocol-chart-mode]');
      if (protocolChartMode) {
        page.protocolChartMode = protocolChartMode.dataset.clientProtocolChartMode === 'curve' ? 'curve' : 'stacked';
        writeStored(PROTOCOL_CHART_MODE_KEY, page.protocolChartMode);
        render();
        return;
      }
      const protocolCategory = event.target.closest('[data-client-protocol-category]');
      if (protocolCategory) {
        const key = protocolCategory.dataset.clientProtocolCategory;
        if (key) {
          page.protocolLegend = page.protocolLegend || parseProtocolLegend();
          page.protocolLegend[key] = page.protocolLegend[key] === false;
          saveProtocolLegend();
          renderOrDefer('protocol-legend');
        }
        return;
      }
      const protocolControl = event.target.closest('[data-client-protocol-control]');
      if (protocolControl) {
        page.protocolControlNotice = '协议控制接口待后端接入';
        renderOrDefer('protocol-notice');
        window.clearTimeout(page.protocolControlNoticeTimer);
        page.protocolControlNoticeTimer = window.setTimeout(() => {
          if (!page) return;
          page.protocolControlNotice = '';
          renderOrDefer('protocol-notice');
        }, 2600);
        return;
      }
      const filterTab = event.target.closest('[data-client-filter-tab]');
      if (filterTab) {
        page.filterTab = filterTab.dataset.clientFilterTab === 'display' ? 'display' : 'filter';
        writeStored(FILTER_TAB_KEY, page.filterTab);
        render();
        return;
      }
      if (event.target.closest('[data-client-open-fingerprint]')) {
        openFingerprintPicker();
        return;
      }
      if (event.target.closest('[data-client-close-fingerprint]')) {
        closeFingerprintPicker();
        return;
      }
      const fingerprintCategory = event.target.closest('[data-client-fingerprint-category]');
      if (fingerprintCategory && page.fingerprint) {
        page.fingerprint.category = fingerprintCategory.dataset.clientFingerprintCategory || 'unknown';
        page.fingerprint.vendor = '';
        page.fingerprint.query = '';
        loadFingerprintCandidates();
        return;
      }
      const fingerprintVendor = event.target.closest('[data-client-fingerprint-vendor]');
      if (fingerprintVendor && page.fingerprint) {
        page.fingerprint.vendor = fingerprintVendor.dataset.clientFingerprintVendor || '';
        page.fingerprint.query = '';
        loadFingerprintCandidates();
        return;
      }
      const fingerprintDevice = event.target.closest('[data-client-fingerprint-device]');
      if (fingerprintDevice) {
        applyFingerprintSelection(fingerprintDevice.dataset.clientFingerprintDevice);
        return;
      }
      if (event.target.closest('[data-client-apply-fingerprint]')) {
        applyFingerprintSelection(0);
        return;
      }
      const uploadPlaceholder = event.target.closest('[data-client-fingerprint-upload-placeholder]');
      if (uploadPlaceholder) {
        const input = root.querySelector('[data-client-fingerprint-file]');
        if (input) input.click();
        return;
      }
      if (event.target.closest('[data-client-filter-reset]')) {
        page.filters = parseFilters();
        page.filters.deviceTypes = [];
        page.filters.ip = '';
        page.filters.ipExclude = false;
        page.filters.keyword = '';
        page.filters.vendor = '';
        page.filters.vlan = '';
        page.filters.ipVersion = '';
        page.filters.minConnections = 0;
        page.filters.minUpGb = 0;
        page.filters.minDownGb = 0;
        page.filters.columnFilters = {};
        page.filters.showOnline = true;
        page.filters.showOffline = true;
        page.search = '';
        saveFilters();
        render();
        return;
      }
      if (event.target.closest('[data-client-filter-apply]')) {
        page.filters.deviceTypes = [...root.querySelectorAll('[data-client-filter-type]:checked')].map((input) => input.value);
        page.filters.keyword = root.querySelector('[data-client-filter-keyword]')?.value || '';
        page.filters.ip = root.querySelector('[data-client-filter-ip]')?.value || '';
        page.filters.ipExclude = Boolean(root.querySelector('[data-client-filter-ip-exclude]')?.checked);
        page.filters.vendor = root.querySelector('[data-client-filter-vendor]')?.value || '';
        page.filters.vlan = root.querySelector('[data-client-filter-vlan]')?.value || '';
        page.filters.ipVersion = root.querySelector('[data-client-filter-ip-version]')?.value || '';
        page.filters.minConnections = Number(root.querySelector('[data-client-filter-min-connections]')?.value) || 0;
        page.filters.minUpGb = Number(root.querySelector('[data-client-filter-min-up]')?.value) || 0;
        page.filters.minDownGb = Number(root.querySelector('[data-client-filter-min-down]')?.value) || 0;
        page.filters.showOnline = Boolean(root.querySelector('[data-client-filter-show-online]')?.checked);
        page.filters.showOffline = Boolean(root.querySelector('[data-client-filter-show-offline]')?.checked);
        page.search = page.filters.keyword;
        const showIpv6 = root.querySelector('[data-client-filter-show-ipv6]');
        if (showIpv6) {
          page.showIpv6 = Boolean(showIpv6.checked);
          writeStored(IPV6_KEY, page.showIpv6 ? '1' : '0');
        }
        saveFilters();
        page.filterOpen = false;
        render();
        return;
      }
      const detailTab = event.target.closest('.client-detail-tabs .dwrt-kit-tab');
      if (detailTab) {
        page.detail.tab = detailTab.dataset.value || 'overview';
        page.connectionOptionsOpen = false;
        render();
        if (['connection', 'protocol'].includes(page.detail.tab) && page.detail.mac) loadProfile(page.detail.mac, { preserve: true });
        return;
      }
      if (event.target.closest('button, input, label, a, select')) return;
      const row = event.target.closest('[data-client-mac]');
      if (row && row.dataset.clientMac) {
        page.detail = { open: true, mac: row.dataset.clientMac, tab: 'overview', loading: false, profile: {} };
        loadProfile(row.dataset.clientMac);
      }
    }

    function handleInput(event) {
      const clientSearch = event.target.closest('[data-client-search]');
      if (clientSearch) {
        page.search = clientSearch.value || '';
        page.filters.keyword = page.search;
        saveFilters();
        renderTableOnly();
        return;
      }
      const fingerprintSearch = event.target.closest('[data-client-fingerprint-search]');
      if (fingerprintSearch && page.fingerprint) {
        page.fingerprint.query = fingerprintSearch.value;
        page.fingerprint.vendor = '';
        window.clearTimeout(page.fingerprintSearchTimer);
        page.fingerprintSearchTimer = window.setTimeout(loadFingerprintCandidates, 260);
      }
    }

    function handleChange(event) {
      const ipv6 = event.target.closest('[data-client-ipv6]');
      if (ipv6) {
        page.showIpv6 = Boolean(ipv6.checked);
        writeStored(IPV6_KEY, page.showIpv6 ? '1' : '0');
        render();
        loadIpv6Context();
        loadIpv6Neighbors();
        return;
      }
      const allColumns = event.target.closest('[data-client-connection-column-all]');
      if (allColumns) {
        page.connectionColumns = allColumns.checked ? CONNECTION_DEFAULT_COLUMNS.slice() : ['app', 'proto', 'line', 'externalIp', 'dstIp', 'status'];
        saveConnectionColumns();
        render();
        return;
      }
      const connectionColumn = event.target.closest('[data-client-connection-column]');
      if (connectionColumn) {
        const key = connectionColumn.dataset.clientConnectionColumn;
        const selected = new Set(Array.isArray(page.connectionColumns) ? page.connectionColumns : CONNECTION_DEFAULT_COLUMNS);
        if (connectionColumn.checked) selected.add(key);
        else selected.delete(key);
        if (!selected.size) selected.add('app');
        page.connectionColumns = CONNECTION_COLUMNS.map((column) => column.key).filter((columnKey) => selected.has(columnKey));
        saveConnectionColumns();
        render();
        return;
      }
      const fingerprintFile = event.target.closest('[data-client-fingerprint-file]');
      if (fingerprintFile && fingerprintFile.files && fingerprintFile.files[0]) {
        uploadFingerprintImage(fingerprintFile.files[0]);
      }
    }

    function handleScroll(event) {
      if (!page || !page.active || !root || !root.contains(event.target)) return;
      const target = event.target;
      if (!SCROLL_SELECTORS.some(([, selector]) => target.matches && target.matches(selector))) return;
      page.scrollRestoreToken = (page.scrollRestoreToken || 0) + 1;
      rememberScrollState();
    }

    function handlePointerOver(event) {
      if (!page || !page.active) return;
      if (event.target && event.target.closest && event.target.closest('.client-table-panel')) {
        page.tablePointerInside = true;
      }
    }

    function handlePointerOut(event) {
      if (!page || !page.active) return;
      const panel = event.target && event.target.closest ? event.target.closest('.client-table-panel') : null;
      if (!panel) return;
      if (event.relatedTarget && panel.contains(event.relatedTarget)) return;
      page.tablePointerInside = false;
      if (page.tableRenderPending) queueTableRender(40);
    }

    function handleFocusOut(event) {
      if (!page || !page.active || !page.tableRenderPending) return;
      const panel = event.target && event.target.closest ? event.target.closest('.client-table-panel') : null;
      if (!panel) return;
      window.setTimeout(() => {
        if (page && page.active && page.tableRenderPending && !tableInteractionActive()) queueTableRender(40);
      }, 0);
    }

    function currentDetailClient() {
      if (!page || !page.detail || !page.detail.open) return {};
      const target = String(page.detail.mac || '').toLowerCase();
      return page.clients.find((item) => String(item.mac || '').toLowerCase() === target) || {};
    }

    function currentControlRules() {
      if (!page || !page.detail || !page.detail.open) return [];
      return controlRules(page.detail.profile || {}, currentDetailClient());
    }

    function currentControlRule(id) {
      const key = firstText(id);
      if (!key) return null;
      return currentControlRules().find((rule) => String(rule.id) === key) || null;
    }

    function controlDaysFromValue(...values) {
      for (const value of values) {
        if (Array.isArray(value) && value.length) return value.map((item) => firstText(item)).filter(Boolean);
        const text = firstText(value);
        if (!text) continue;
        if (/^\s*\[/.test(text)) {
          try {
            const parsed = JSON.parse(text);
            if (Array.isArray(parsed) && parsed.length) return parsed.map((item) => firstText(item)).filter(Boolean);
          } catch (_) {}
        }
        const parts = text.split(/[\s,，、;；|]+/).map((item) => item.trim()).filter(Boolean);
        if (parts.length) return parts;
      }
      return ['一', '二', '三', '四', '五', '六', '日'];
    }

    function controlDraftFromRule(rule) {
      const raw = rule && rule.raw && typeof rule.raw === 'object' ? rule.raw : {};
      return {
        id: firstText(rule && rule.id, raw.id, raw.rule_id, raw.uuid),
        mac: firstText(raw.mac, raw.client_mac, page && page.detail && page.detail.mac),
        control_type: firstText(raw.control_type, raw.type, rule && rule.type, 'IP限速'),
        name: firstText(raw.name, raw.rule_name, rule && rule.name),
        schedule_mode: firstText(raw.schedule_mode, raw.schedule_type, 'week'),
        days: controlDaysFromValue(raw.days, raw.days_array, raw.days_json, raw.days_text, rule && rule.days),
        start_time: firstText(raw.start_time, raw.start, raw.begin, rule && rule.start_time, '00:00'),
        end_time: firstText(raw.end_time, raw.end, raw.finish, rule && rule.end_time, '23:59'),
        limit_mode: firstText(raw.limit_mode, raw.speed_mode, '独立限速'),
        up_limit: firstText(raw.up_limit, raw.upload_limit, raw.upload_mbps, '0'),
        up_unit: firstText(raw.up_unit, raw.upload_unit, 'KB/s'),
        down_limit: firstText(raw.down_limit, raw.download_limit, raw.download_mbps, '0'),
        down_unit: firstText(raw.down_unit, raw.download_unit, 'KB/s'),
        line: firstText(raw.line, raw.wan, raw.interface, ''),
        protocol: firstText(raw.protocol, raw.proto, '任意'),
        note: firstText(raw.note, raw.remark, raw.comment, rule && rule.note)
      };
    }

    function clearControlNoticeSoon() {
      window.clearTimeout(page.controlNoticeTimer);
      page.controlNoticeTimer = window.setTimeout(() => {
        if (!page) return;
        page.controlNotice = '';
        renderOrDefer('control-notice-clear');
      }, 2600);
    }

    function editControlRule(rule) {
      if (!rule) return;
      page.controlDraft = controlDraftFromRule(rule);
      page.controlEditorOpen = true;
      page.controlNotice = '';
      render();
    }

    async function toggleControlRule(rule) {
      if (!rule) return;
      const payload = {
        mac: firstText(rule.raw && rule.raw.mac, page && page.detail && page.detail.mac),
        id: firstText(rule.id, rule.raw && rule.raw.id),
        enabled: !rule.enabled
      };
      if (!payload.mac || !payload.id) return;
      page.controlNotice = payload.enabled ? '正在开启…' : '正在关闭…';
      renderOrDefer('control-toggle');
      const result = await postApiResource('client_control_rule_toggle', '/api/v1/client_control_rule/toggle', payload);
      if (!page || !page.active) return;
      if (result.ok) {
        page.controlNotice = payload.enabled ? '已开启' : '已关闭';
        loadProfile(payload.mac, { preserve: true });
      } else {
        const message = result.error && result.error.message ? result.error.message : 'unknown';
        page.controlNotice = /404|not found/i.test(message) ? '管控开关接口未就绪' : `操作失败：${message}`;
      }
      renderOrDefer('control-toggle-result');
      clearControlNoticeSoon();
    }

    async function deleteControlRule(rule) {
      if (!rule) return;
      const payload = {
        mac: firstText(rule.raw && rule.raw.mac, page && page.detail && page.detail.mac),
        id: firstText(rule.id, rule.raw && rule.raw.id)
      };
      if (!payload.mac || !payload.id) return;
      if (window.confirm && !window.confirm(`删除管控规则「${firstText(rule.name, payload.id)}」？`)) return;
      page.controlNotice = '正在删除…';
      renderOrDefer('control-delete');
      const result = await postApiResource('client_control_rule_delete', '/api/v1/client_control_rule/delete', payload);
      if (!page || !page.active) return;
      if (result.ok) {
        page.controlNotice = '已删除';
        loadProfile(payload.mac, { preserve: true });
      } else {
        const message = result.error && result.error.message ? result.error.message : 'unknown';
        page.controlNotice = /404|not found/i.test(message) ? '管控删除接口未就绪' : `删除失败：${message}`;
      }
      renderOrDefer('control-delete-result');
      clearControlNoticeSoon();
    }

    function readControlDraft(form) {
      const data = new FormData(form);
      return {
        id: firstText(data.get('id'), page && page.controlDraft && page.controlDraft.id),
        mac: firstText(data.get('mac'), page && page.detail && page.detail.mac),
        control_type: firstText(data.get('control_type'), 'IP限速'),
        name: firstText(data.get('name')),
        schedule_mode: firstText(data.get('schedule_mode'), 'week'),
        days: data.getAll('days').map((item) => firstText(item)).filter(Boolean),
        start_time: firstText(data.get('start_time'), '00:00'),
        end_time: firstText(data.get('end_time'), '23:59'),
        limit_mode: firstText(data.get('limit_mode'), '独立限速'),
        up_limit: firstText(data.get('up_limit'), '0'),
        up_unit: firstText(data.get('up_unit'), 'KB/s'),
        down_limit: firstText(data.get('down_limit'), '0'),
        down_unit: firstText(data.get('down_unit'), 'KB/s'),
        line: firstText(data.get('line')),
        protocol: firstText(data.get('protocol'), '任意'),
        note: firstText(data.get('note'))
      };
    }

    async function submitControlRule(form) {
      const payload = readControlDraft(form);
      page.controlDraft = payload;
      if (!payload.mac) {
        page.controlNotice = '缺少 MAC，无法保存';
        renderOrDefer('control-notice');
        return;
      }
      if (!payload.name) {
        page.controlNotice = '请输入名称';
        renderOrDefer('control-notice');
        return;
      }
      page.controlNotice = '保存中...';
      renderOrDefer('control-notice');
      const updating = Boolean(payload.id);
      const result = await postApiResource(
        updating ? 'client_control_rule_update' : 'client_control_rule',
        updating ? '/api/v1/client_control_rule/update' : '/api/v1/client_control_rule',
        payload
      );
      if (!page || !page.active) return;
      if (result.ok) {
        page.controlNotice = updating ? '已更新' : '已保存';
        page.controlEditorOpen = false;
        page.controlDraft = null;
        renderOrDefer('control-saved');
        loadProfile(payload.mac, { preserve: true });
      } else {
        const message = result.error && result.error.message ? result.error.message : 'unknown';
        page.controlNotice = /404|not found/i.test(message) ? '管控保存接口未就绪' : `保存失败：${message}`;
        renderOrDefer('control-error');
      }
    }

    async function handleSubmit(event) {
      const controlForm = event.target.closest('[data-client-control-form]');
      if (controlForm) {
        event.preventDefault();
        await submitControlRule(controlForm);
        return;
      }
      const form = event.target.closest('[data-client-custom-form]');
      if (!form) return;
      event.preventDefault();
      const result = await saveClientOverride(form);
      if (!page || !page.active) return;
      if (!result.ok) return;
      renderOrDefer('custom-saved');
      loadProfile(result.payload.mac);
    }

    function mount() {
      if (!root) return { unmount() {} };
      root.hidden = false;
      root.classList.remove('route-line-status', 'route-data-page');
      root.classList.add('route-workspace', 'route-client-details-host');
      page = {
        active: true,
        status: readStored(STATUS_KEY, 'online') === 'offline' ? 'offline' : 'online',
        showIpv6: readStored(IPV6_KEY, '1') !== '0',
        sort: parseSort(),
        filters: parseFilters(),
        filterTab: readStored(FILTER_TAB_KEY, 'filter') === 'display' ? 'display' : 'filter',
        filterOpen: false,
        columnFilterOpen: '',
        columnOrder: parseClientColumnOrder(),
        dragColumnKey: '',
        connectionOptionsOpen: false,
        connectionOptionTab: readStored(CONNECTION_OPTION_TAB_KEY, 'filter') === 'columns' ? 'columns' : 'filter',
        connectionFilters: parseConnectionFilters(),
        connectionColumns: parseConnectionColumns(),
        connectionAutoRefresh: readStored(CONNECTION_AUTO_KEY, '1') !== '0',
        connectionNotice: '',
        controlEditorOpen: false,
        controlDraft: null,
        controlNotice: '',
        protocolChartMode: readStored(PROTOCOL_CHART_MODE_KEY, 'stacked') === 'curve' ? 'curve' : 'stacked',
        protocolLegend: parseProtocolLegend(),
        overviewLegend: parseOverviewLegend(),
        overviewCharts: new Map(),
        protocolCharts: new Map(),
        protocolControlNotice: '',
        lastDetailRenderKey: '',
        search: '',
        clients: [],
        runtimeRows: new Map(),
        ipv6Prefixes: [],
        ipv6ContextLoading: false,
        clientOverviewSamples: {},
        scrollState: {},
        scrollRestoreToken: 0,
        error: '',
        loading: false,
        detail: { open: false, mac: '', tab: 'overview', loading: false, profile: {}, profileRefreshing: false },
        realtimeUnsubscribers: null,
        timer: window.setInterval(loadClients, REFRESH_MS),
        flowTimer: window.setInterval(loadTopologyFlowRuntime, 2000),
        ipv6Timer: window.setInterval(loadIpv6Neighbors, 8000)
      };
      page.search = firstText(page.filters.keyword);
      page.foregroundObserver = typeof MutationObserver === 'function' ? new MutationObserver((records) => {
        if (!records.some((record) => record.target instanceof Element && record.target.closest('.client-detail-layer'))) return;
        scheduleOverviewChartsRender(0);
        scheduleProtocolChartsRender(0);
      }) : null;
      page.foregroundObserver?.observe(root, { subtree: true, attributes: true, attributeFilter: ['data-adaptive-region'] });
      let initialDetailMac = '';
      try {
        initialDetailMac = firstText(sessionStorage.getItem('dreamingwrt.clientDetails.initialMac'));
        sessionStorage.removeItem('dreamingwrt.clientDetails.initialMac');
      } catch (_) {}
      if (initialDetailMac) page.detail = { open: true, mac: initialDetailMac, tab: 'overview', loading: false, profile: {} };
      page.onOpenClientDetail = (event) => {
        const mac = firstText(event?.detail?.mac);
        if (!page || !page.active || !mac) return;
        try { sessionStorage.removeItem('dreamingwrt.clientDetails.initialMac'); } catch (_) {}
        page.detail = { open: true, mac, tab: 'overview', loading: false, profile: {} };
        render();
        loadProfile(mac);
      };
      window.addEventListener('dwrt:open-client-detail', page.onOpenClientDetail);
      root.addEventListener('click', handleClick);
      root.addEventListener('input', handleInput);
      root.addEventListener('change', handleChange);
      root.addEventListener('submit', handleSubmit);
      root.addEventListener('scroll', handleScroll, true);
      root.addEventListener('pointerover', handlePointerOver);
      root.addEventListener('pointerout', handlePointerOut);
      root.addEventListener('focusout', handleFocusOut);
      root.addEventListener('dragstart', handleColumnDragStart);
      root.addEventListener('dragover', handleColumnDragOver);
      root.addEventListener('drop', handleColumnDrop);
      root.addEventListener('dragend', handleColumnDragEnd);
      render();
      subscribeClientRealtime();
      if (!(page.detail && page.detail.open && page.detail.mac === 'demo-mac')) loadClients();
      if (initialDetailMac) loadProfile(initialDetailMac);
      loadTopologyFlowRuntime();
      loadIpv6Context();
      loadIpv6Neighbors();
      return {
        unmount() {
          if (!page) return;
          page.active = false;
          window.removeEventListener('dwrt:open-client-detail', page.onOpenClientDetail);
          window.clearInterval(page.timer);
          window.clearInterval(page.flowTimer);
          window.clearInterval(page.ipv6Timer);
          unsubscribeClientRealtime();
          disposeOverviewCharts();
          disposeProtocolCharts();
          window.clearTimeout(page.overviewChartTimer);
          window.clearTimeout(page.protocolChartTimer);
          window.clearTimeout(page.deferTimer);
          window.clearTimeout(page.searchTimer);
          window.clearTimeout(page.connectionNoticeTimer);
          window.clearTimeout(page.protocolControlNoticeTimer);
          window.clearTimeout(page.detailRealtimeTimer);
          window.clearTimeout(page.tableRenderTimer);
          page.foregroundObserver?.disconnect();
          root.removeEventListener('click', handleClick);
          root.removeEventListener('input', handleInput);
          root.removeEventListener('change', handleChange);
          root.removeEventListener('submit', handleSubmit);
          root.removeEventListener('scroll', handleScroll, true);
          root.removeEventListener('pointerover', handlePointerOver);
          root.removeEventListener('pointerout', handlePointerOut);
          root.removeEventListener('focusout', handleFocusOut);
          root.removeEventListener('dragstart', handleColumnDragStart);
          root.removeEventListener('dragover', handleColumnDragOver);
          root.removeEventListener('drop', handleColumnDrop);
          root.removeEventListener('dragend', handleColumnDragEnd);
          root.classList.remove('route-client-details-host');
          page = null;
        }
      };

    }

    return { mount };
  }

  window.DWRTClientDetails = { create };
})();
