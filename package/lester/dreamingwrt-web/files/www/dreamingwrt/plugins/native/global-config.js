import { mount as mountNetworkInterfaceConfig } from './network-interface-config.js?v=20260805-drawer-standard-portal-01';

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));
  const VERSION = '20260805-drawer-standard-portal-02';
  const MODULE_CLASS = 'global-config-route-host';
  const ENDPOINTS = {
    overview: '/api/v1/network/overview',
    settingsOverview: '/api/v1/network/settings-overview',
    global: '/api/v1/network/global',
    lans: '/api/v1/network/lans',
    wans: '/api/v1/network/wans',
    ports: '/api/v1/network/ports',
    preferences: '/api/v1/network/ports/preferences',
    topologyPorts: '/api/v1/topology/node/ports',
    profiles: '/api/v1/topology/port-profiles',
    radius: '/api/v1/services/radius',
    preview: '/api/v1/topology/node/ports/preview',
    apply: '/api/v1/topology/node/ports/apply',
    gatewayApply: '/api/v1/network/gateway-ports/apply'
  };
  const COLUMNS = [
    { key: 'select', label: '', width: 44, fixed: true },
    { key: 'port', label: '端口', width: 82, fixed: true },
    { key: 'name', label: '名称', width: 118 },
    { key: 'anomaly', label: '异常', width: 64 },
    { key: 'stp', label: 'STP', width: 62 },
    { key: 'connection', label: '连接', width: 118 },
    { key: 'network', label: '网络', width: 118 },
    { key: 'speed', label: '速度', width: 82 },
    { key: 'duplex', label: '双工', width: 68 },
    { key: 'mac', label: 'MAC', width: 138 },
    { key: 'ip', label: 'IP', width: 120 },
    { key: 'profile', label: '配置文件', width: 106 },
    { key: 'vlan', label: '原生 VLAN', width: 82 },
    { key: 'poe', label: 'PoE', width: 86 },
    { key: 'pro_av', label: 'Pro AV', width: 94 },
    { key: 'tagged_vlan', label: '标记的 VLAN', width: 126 },
    { key: 'activity', label: '活动', width: 84 },
    { key: 'tx_total', label: 'Tx 总和', width: 92 },
    { key: 'rx_total', label: 'Rx 总和', width: 92 },
    { key: 'tx_packets', label: 'Tx 数据包', width: 112 },
    { key: 'rx_packets', label: 'Rx 数据包', width: 112 },
    { key: 'tx_multicast', label: 'Tx 组播', width: 106 },
    { key: 'rx_multicast', label: 'Rx 组播', width: 106 },
    { key: 'tx_broadcast', label: 'Tx 广播', width: 106 },
    { key: 'rx_broadcast', label: 'Rx 广播', width: 106 },
    { key: 'tx_errors', label: 'Tx 错误', width: 100 },
    { key: 'rx_errors', label: 'Rx 错误', width: 100 },
    { key: 'tx_dropped', label: 'Tx 丢弃', width: 100 },
    { key: 'rx_dropped', label: 'Rx 丢弃', width: 100 },
    { key: 'tx_rate', label: 'Tx 速率', width: 92 },
    { key: 'rx_rate', label: 'Rx 速率', width: 92 },
    { key: 'lag_id', label: 'LAG ID', width: 94 },
    { key: 'media', label: '介质', width: 94 },
    { key: 'multicast_router', label: '多播 Router', width: 126 },
    { key: 'actions', label: '操作', width: 72, fixed: true }
  ];
  const DEFAULT_COLUMNS = ['select', 'port', 'name', 'anomaly', 'stp', 'connection', 'actions', 'speed', 'mac', 'ip', 'profile', 'vlan', 'activity', 'tx_total', 'rx_total', 'tx_rate', 'rx_rate'];
  const state = {
    mounted: true, loading: true, refreshing: false, seq: 0, error: '', source: '',
    overview: {}, settingsOverview: {}, capabilities: {}, capabilitiesKnown: false, capabilitiesError: '', global: {}, globalDraft: {}, ports: [], profiles: [], lans: [], wans: [],
    radius: [], radiusKnown: false, radiusError: '',
    query: '', status: 'all', kind: 'all', speed: 'all', poe: 'all', vlan: 'all', anomalyMin: 0, anomalyMax: 100, statistics: true,
    visibleColumns: new Set(DEFAULT_COLUMNS), sortKey: 'port', sortDirection: 'asc',
    pageTab: 'global', drawer: '', selectedId: '', selectedPorts: new Set(), portDraft: {}, portInitial: {}, portPreview: null,
    gatewayDraft: {}, gatewayInitial: {}, gatewayPreview: null, gatewayNotice: '',
    globalTab: 'internet',
    bulkDraft: { speed: 0, duplex: 'full', autoneg: true }, bulkInitial: { speed: 0, duplex: 'full', autoneg: true }, bulkPreview: null,
    saving: false, notice: '', globalNotice: '', timer: 0, statsTimer: 0, statsRefreshing: false, preferencesLoaded: false,
    advancedOpen: new Set(['wan-policy']), pollTimer: 0
  };
  let searchTimer = 0;
  let interfaceInstances = new Map();
  let interfacePayloads = { lan: {}, wan: {}, ports: {} };

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (Array.isArray(value)) {
        const text = value.map((item) => firstText(item)).filter(Boolean).join(', ');
        if (text) return text;
        continue;
      }
      if (typeof value === 'object') {
        const text = firstText(value.label, value.name, value.value, value.address, value.id);
        if (text) return text;
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
  function asArray(value) {
    if (Array.isArray(value)) return value;
    for (const key of ['items', 'ports', 'profiles', 'rows', 'data']) if (Array.isArray(value?.[key])) return value[key];
    return [];
  }
  function formatBytes(value) {
    if (value === null || value === undefined || value === '') return '--';
    const number = Number(value);
    if (!Number.isFinite(number) || number < 0) return '--';
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let current = number;
    let index = 0;
    while (current >= 1024 && index < units.length - 1) { current /= 1024; index += 1; }
    const digits = current >= 100 || index === 0 ? 0 : current >= 10 ? 1 : 2;
    return `${current.toFixed(digits).replace(/\.0+$/, '')} ${units[index]}`;
  }
  function formatRate(value) {
    if (value === null || value === undefined || value === '') return '--';
    const number = Number(value);
    if (!Number.isFinite(number) || number < 0) return '--';
    const units = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
    let current = number * 8;
    let index = 0;
    while (current >= 1000 && index < units.length - 1) { current /= 1000; index += 1; }
    const digits = current >= 100 || index === 0 ? 0 : current >= 10 ? 1 : 2;
    return `${current.toFixed(digits).replace(/\.0+$/, '')} ${units[index]}`;
  }
  function formatCount(value) {
    if (value === null || value === undefined || value === '') return '--';
    const number = Number(value);
    return Number.isFinite(number) && number >= 0 ? number.toLocaleString('zh-CN') : '--';
  }
  function formatDuration(value) {
    if (value === null || value === undefined || value === '') return '--';
    const seconds = Number(value);
    if (!Number.isFinite(seconds) || seconds < 0) return '--';
    if (seconds < 60) return `${Math.round(seconds)} 秒`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时 ${Math.floor(seconds % 3600 / 60)} 分钟`;
    return `${Math.floor(seconds / 86400)} 天 ${Math.floor(seconds % 86400 / 3600)} 小时`;
  }
  function normalizeKey(value) { return String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_'); }
  function normalizeMac(value) {
    const text = String(value || '').trim().toLowerCase().replace(/-/g, ':');
    return /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(text) ? text : '';
  }
  function firstMac(...values) {
    for (const value of values) {
      const mac = normalizeMac(value);
      if (mac) return mac;
    }
    return '';
  }
  function validAddress(value) {
    const text = String(value || '').trim();
    return text && !['--', '0.0.0.0', '::'].includes(text) ? text : '';
  }
  function firstGlobalIpv6(...values) {
    const candidates = values.flatMap((value) => Array.isArray(value) ? value : [value]);
    for (const value of candidates) {
      const text = firstText(value).trim();
      const address = text.toLowerCase().split('%')[0].split('/')[0];
      if (/^[23][0-9a-f]{0,3}:/.test(address)) return text;
    }
    return '';
  }
  function clone(value) { try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value || {})); } }
  function optionalNumber(...values) {
    for (const value of values) {
      if (value === null || value === undefined || value === '') continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return null;
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
    return { Accept: 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}), ...extra };
  }
  async function requestJson(url, options = {}) {
    const response = await sessionFetch(`${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`, {
      credentials: 'same-origin', cache: 'no-store', ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    const payload = json?.data ?? json;
    if (!response.ok || json?.ok === false || payload?.ok === false) throw new Error(firstText(payload?.message, payload?.error, json?.message, json?.error, response.status));
    return payload || {};
  }
  function icon(name) {
    const paths = {
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      filter: '<path d="M4 5h16l-6.2 7.1V18l-3.6 1v-6.9L4 5Z"></path>',
      columns: '<path d="M4 5h16v14H4zM10 5v14m5-14v14"></path>',
      settings: '<path d="M9.7 4.1a2.3 2.3 0 0 1 4.6 0 2.3 2.3 0 0 0 3.3 1.9 2.3 2.3 0 0 1 2.3 4 2.3 2.3 0 0 0 0 3.8 2.3 2.3 0 0 1-2.3 4 2.3 2.3 0 0 0-3.3 1.9 2.3 2.3 0 0 1-4.6 0 2.3 2.3 0 0 0-3.3-1.9 2.3 2.3 0 0 1-2.3-4 2.3 2.3 0 0 0 0-3.8 2.3 2.3 0 0 1 2.3-4 2.3 2.3 0 0 0 3.3-1.9"></path><circle cx="12" cy="12" r="3"></circle>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      edit: '<path d="m4 20 4.2-1 10.9-10.9a2 2 0 0 0-2.8-2.8L5.4 16.2 4 20Z"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      table: '<rect x="4" y="5" width="16" height="14" rx="2"></rect><path d="M4 10h16M9 5v14"></path>',
      batch: '<rect x="5" y="4" width="14" height="16" rx="2"></rect><path d="M9 9h6M9 13h6"></path>',
      chevron: '<path d="m8 10 4 4 4-4"></path>',
      ports: '<rect x="4" y="4" width="6" height="6" rx="1"></rect><rect x="14" y="4" width="6" height="6" rx="1"></rect><rect x="4" y="14" width="6" height="6" rx="1"></rect><rect x="14" y="14" width="6" height="6" rx="1"></rect>',
      network: '<path d="M12 3v6m0 6v6M3 12h6m6 0h6"></path><circle cx="12" cy="12" r="3"></circle><circle cx="12" cy="3" r="1"></circle><circle cx="12" cy="21" r="1"></circle><circle cx="3" cy="12" r="1"></circle><circle cx="21" cy="12" r="1"></circle>',
      internet: '<circle cx="12" cy="12" r="9"></circle><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"></path>',
      shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"></path><path d="m9 12 2 2 4-5"></path>',
      route: '<circle cx="6" cy="18" r="2"></circle><circle cx="18" cy="6" r="2"></circle><path d="M8 18h4a4 4 0 0 0 4-4V8"></path>',
      system: '<rect x="4" y="5" width="16" height="14" rx="2"></rect><path d="M8 9h8M8 13h5"></path>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.settings}</svg>`;
  }

  function unwrap(result) { return result?.data ?? result?.raw?.data ?? result?.raw ?? result ?? {}; }
  async function fetchResource(name, url) {
    if (typeof api.fetch === 'function') {
      const result = await api.fetch(name, `${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`);
      if (result?.ok === false) throw result.error || new Error(`${name} unavailable`);
      return unwrap(result);
    }
    return requestJson(url);
  }
  function networkRows(container, key) {
    const value = container?.[key];
    return asArray(value?.[key] || value);
  }
  function listRows(container, keys) {
    for (const key of keys) {
      const direct = container?.[key];
      const rows = asArray(direct?.[key] || direct);
      if (rows.length) return rows;
    }
    return asArray(container);
  }
  function networkMap(lans, wans) {
    const map = new Map();
    const add = (kind, item) => {
      const runtime = item.runtime || {};
      const aliases = [
        item.id, item.name, item.ifname, item.interface, item.device, item.physicalIfname,
        item.physical_ifname, item.runtime_device, runtime.ifname, runtime.device,
        ...asArray(item.ports), ...asArray(item.members), ...asArray(runtime.ports)
      ]
        .map((value) => firstText(value))
        .filter(Boolean);
      aliases.forEach((alias) => map.set(`${kind}:${alias}`, item));
    };
    lans.forEach((item) => add('lan', item));
    wans.forEach((item) => add('wan', item));
    return map;
  }
  function detailMap(items) {
    const map = new Map();
    asArray(items).forEach((item) => {
      const key = firstText(item.ifname, item.name, item.id, item.port_id);
      if (key) map.set(key, item);
    });
    return map;
  }
  function normalizeNeighbor(detail = {}) {
    const neighbors = asArray(detail.neighbors || detail.connected_devices || detail.clients);
    const validNeighbors = neighbors.filter((item) => {
      const type = normalizeKey(firstText(item.type, item.role));
      if (type === 'isp' || type === 'internet') return false;
      return firstMac(item.mac, item.hwaddr) || validAddress(firstText(item.ip, item.ipv4, asArray(item.remote_mgmt_ips)[0]));
    });
    const neighbor = validNeighbors[0] || {};
    return {
      name: firstText(neighbor.name, neighbor.hostname, neighbor.model),
      mac: firstMac(neighbor.mac, neighbor.hwaddr, neighbor.address),
      ip: validAddress(firstText(neighbor.ip, neighbor.ipv4, asArray(neighbor.remote_mgmt_ips)[0])),
      all: validNeighbors
    };
  }
  function logicalPortName(value, ifname) {
    const text = firstText(value);
    const physical = firstText(ifname);
    if (!text || !physical || text === physical) return text;
    if (text.endsWith(physical)) {
      const logical = text.slice(0, -physical.length).replace(/[\s._:/-]+$/, '');
      if (logical) return logical;
    }
    return text;
  }
  function normalizePort(port = {}, index = 0, detail = {}, networks = new Map()) {
    const config = { ...(port.config || {}), ...(detail.config || {}) };
    const runtime = { ...(port.runtime || {}), ...(detail.runtime || {}) };
    const poe = { ...(port.poe || {}), ...(detail.poe || {}) };
    const ifname = firstText(port.ifname, port.name, detail.ifname, detail.name, port.id) || `port-${index + 1}`;
    const ownerType = normalizeKey(firstText(port.owner_type, detail.owner_type, port.kind, detail.kind));
    let kind = ownerType === 'wan' ? 'wan' : ownerType === 'lan' ? 'lan' : normalizeKey(firstText(port.kind, detail.kind, 'other'));
    const ownerId = firstText(port.owner_id, detail.owner_id, port.network, detail.network);
    let owner = networks.get(`${kind}:${ownerId}`) || networks.get(`${kind}:${ifname}`) || {};
    if (!firstText(owner.id)) {
      const inferredKind = networks.has(`wan:${ifname}`) ? 'wan' : networks.has(`lan:${ifname}`) ? 'lan' : '';
      if (inferredKind) { kind = inferredKind; owner = networks.get(`${kind}:${ifname}`) || {}; }
    }
    const status = normalizeKey(firstText(runtime.status, port.status, detail.status, port.state, detail.state));
    const linkDetected = runtime.link_detected ?? port.link_detected ?? detail.link_detected;
    const connected = linkDetected === true || ['up', 'online', 'connected', 'active'].includes(status);
    const neighbor = normalizeNeighbor(detail);
    const speedMbps = firstNumber(runtime.link_speed_mbps, runtime.speed_mbps, port.link_speed_mbps, port.speed_mbps, detail.speed_mbps);
    const speedLabel = firstText(runtime.speed_label, port.speed_label, detail.speed_label, speedMbps ? `${speedMbps >= 1000 ? `${speedMbps / 1000} G` : speedMbps}bE` : '', connected ? '自动' : '--');
    const profile = config.profile && typeof config.profile === 'object' ? config.profile : {};
    const profileId = firstText(config.profile_id, port.profile_id, detail.profile_id);
    const vlan = firstNumber(config.native_vlan, port.native_vlan, detail.native_vlan);
    const poeCapable = Boolean(poe.capable ?? poe.supported ?? poe.available);
    const poeEnabled = poe.enabled ?? config.poe_enabled;
    const anomaly = Number(detail.anomaly_score ?? port.anomaly_score);
    const ownerEnabled = Object.prototype.hasOwnProperty.call(owner, 'enabled') ? owner.enabled !== false : null;
    const explicitLabel = [
      port.display_name, port.alias, port.configured_display_name, config.display_name,
      detail.display_name, detail.alias, detail.configured_display_name, port.label, detail.label
    ].map((value) => firstText(value)).find((value) => value && value.toLowerCase() !== ifname.toLowerCase()) || '';
    const ownerName = firstText(owner.name, owner.label, ownerId);
    const displayName = logicalPortName(firstText(kind === 'wan' ? owner.id : '', explicitLabel, kind === 'lan' ? owner.device : '', ifname), ifname);
    const localMac = firstMac(port.local_mac, port.mac, port.hwaddr, port.address, runtime.local_mac, runtime.mac, runtime.hwaddr, runtime.address, detail.local_mac);
    const portRuntime = port.runtime || {};
    const detailRuntime = detail.runtime || {};
    const metricSources = [
      port.statistics, port.stats, portRuntime.statistics, portRuntime.stats, portRuntime, port,
      detail.statistics, detail.stats, detailRuntime.statistics, detailRuntime.stats, detailRuntime, detail
    ].filter((source) => source && typeof source === 'object');
    const metric = (...keys) => {
      for (const source of metricSources) {
        for (const key of keys) {
          const raw = source?.[key];
          if (raw === null || raw === undefined || raw === '') continue;
          const value = Number(raw);
          if (Number.isFinite(value) && value >= 0) return value;
        }
      }
      return null;
    };
    const rateMetric = (...keys) => {
      const groups = [
        { root: port, sources: [port.statistics, port.stats, portRuntime.statistics, portRuntime.stats, portRuntime, port] },
        { root: detail, sources: [detail.statistics, detail.stats, detailRuntime.statistics, detailRuntime.stats, detailRuntime, detail] }
      ];
      for (const group of groups) {
        const invalid = group.root?.sample_valid === false
          || group.root?.statistics?.sample_valid === false
          || group.root?.runtime?.sample_valid === false
          || group.root?.runtime?.statistics?.sample_valid === false;
        if (invalid) continue;
        for (const source of group.sources) {
          if (!source || source.sample_valid === false) continue;
          for (const key of keys) {
            const raw = source[key];
            if (raw === null || raw === undefined || raw === '') continue;
            const value = Number(raw);
            if (Number.isFinite(value) && value >= 0) return value;
          }
        }
      }
      return null;
    };
    const wanOwner = kind === 'wan' ? owner : null;
    const displayConnection = wanOwner
      ? firstText(wanOwner.carrierName, wanOwner.carrier_name, wanOwner.carrier, wanOwner.isp, wanOwner.name, '互联网')
      : neighbor.name || (connected ? firstText(detail.connection_name, detail.remote_name, '--') : '--');
    const displayMac = wanOwner ? localMac : neighbor.mac;
    const displayIp = wanOwner ? validAddress(firstText(wanOwner.ipv4, wanOwner.ip, wanOwner.ipaddr, wanOwner.runtime?.ipv4)) : neighbor.ip;
    return {
      id: ifname, ifname, portNumber: optionalNumber(port.port_number, detail.port_number),
      name: displayName, kind, ownerType, ownerId,
      networkName: firstText(ownerName, kind === 'wan' ? '互联网' : kind === 'lan' ? 'LAN' : '--'),
      ownerEnabled, status, connected, speedMbps, speedLabel, duplex: firstText(runtime.duplex, port.duplex, detail.duplex, '--'),
      autoneg: runtime.autoneg ?? port.autoneg ?? detail.autoneg, supportedSpeeds: asArray(runtime.supported_speeds || port.supported_speeds || detail.supported_speeds).map(Number).filter(Boolean),
      supportedDuplex: asArray(runtime.supported_duplex || port.supported_duplex || detail.supported_duplex).map(String).filter(Boolean),
      connection: displayConnection || '--',
      mac: displayMac || '--', localMac: localMac || '--', ip: displayIp || '--', neighbors: neighbor.all, wanOwner,
      profileId, profileName: firstText(profile.name, profile.label, profileId, '--'), vlan, taggedVlans: asArray(config.tagged_vlans),
      poeCapable, poeEnabled: poeCapable ? Boolean(poeEnabled) : null, poeMode: firstText(poe.mode, config.poe_mode, '--'),
      anomaly: Number.isFinite(anomaly) ? anomaly : null, stp: firstText(detail.stp_state, detail.stp, '--'),
      activitySeconds: metric('activity_seconds', 'link_uptime', 'link_up_seconds'),
      txBytes: metric('tx_bytes', 'transmit_bytes', 'bytes_sent'), rxBytes: metric('rx_bytes', 'receive_bytes', 'bytes_received'),
      txRate: rateMetric('tx_rate', 'up_rate', 'tx_bytes_per_second', 'tx_bps'), rxRate: rateMetric('rx_rate', 'down_rate', 'rx_bytes_per_second', 'rx_bps'),
      txPackets: metric('tx_packets', 'transmit_packets'), rxPackets: metric('rx_packets', 'receive_packets'),
      txMulticast: metric('tx_multicast', 'multicast_tx'), rxMulticast: metric('rx_multicast', 'multicast_rx'),
      txBroadcast: metric('tx_broadcast', 'broadcast_tx'), rxBroadcast: metric('rx_broadcast', 'broadcast_rx'),
      txErrors: metric('tx_errors', 'transmit_errors'), rxErrors: metric('rx_errors', 'receive_errors'),
      txDropped: metric('tx_dropped', 'tx_drop', 'transmit_dropped'), rxDropped: metric('rx_dropped', 'rx_drop', 'receive_dropped'),
      lagId: firstText(config.lag_id, runtime.lag_id, detail.lag_id, port.lag_id, '--'), media: firstText(runtime.port_type, detail.media_type, port.media_type, '--'),
      multicastRouter: firstText(runtime.multicast_router, detail.multicast_router, '--'),
      config, runtime, poe, capabilities: detail.capabilities || runtime.capabilities || {}, raw: { ...port, ...detail }
    };
  }
  function normalizeLan(item = {}, index = 0) {
    const runtime = item.runtime || {};
    const addresses = asArray(item.addresses || item.ipv4_addresses);
    const primary = addresses.find((entry) => entry?.is_primary) || addresses[0] || {};
    const ip = firstText(primary.ip, item.ip, item.ipv4, item.ipaddr, item.address, item.gateway);
    const prefix = firstNumber(primary.prefix, item.prefix, item.cidr, item.netmask_prefix);
    return {
      ...item,
      id: firstText(item.id, item.name, item.ifname, `lan-${index + 1}`),
      name: firstText(item.display_name, item.name, item.id, `网络 ${index + 1}`),
      device: firstText(item.device, runtime.device, item.bridge, item.ifname, '--'),
      router: firstText(item.router_name, item.router, item.gateway_name, item.device, '--'),
      subnet: firstText(item.subnet, item.ipv4_subnet, ip && prefix ? `${ip}/${prefix}` : ip, '--'),
      ipv6: firstText(item.ipv6_subnet, item.ipv6_prefix, item.ipv6, '--'),
      dhcp: firstText(item.dhcp_mode, item.dhcp_role, item.dhcp?.mode, item.dhcp_enabled === false ? '关闭' : item.dhcp_enabled === true ? '服务器' : '--'),
      leases: optionalNumber(item.active_leases, item.lease_count, item.dhcp?.active_leases),
      capacity: optionalNumber(item.dhcp_pool_size, item.lease_capacity, item.dhcp?.pool_size),
      available: optionalNumber(item.available_ips, item.available_addresses, item.dhcp?.available)
    };
  }
  function normalizeWan(item = {}, index = 0) {
    const runtime = item.runtime || {};
    const carrierKey = normalizeKey(firstText(item.carrier, item.carrier_name, item.isp, item.isp_name, runtime.carrier, runtime.isp));
    const carrierName = carrierKey.includes('unicom') || carrierKey.includes('联通') ? '中国联通'
      : carrierKey.includes('telecom') || carrierKey.includes('电信') ? '中国电信'
        : carrierKey.includes('mobile') || carrierKey.includes('移动') ? '中国移动'
          : carrierKey.includes('broadnet') || carrierKey.includes('广电') ? '中国广电'
            : firstText(item.carrier_name, item.isp_name, item.carrier, item.isp, runtime.carrier_name, runtime.isp, '互联网');
    const rawName = firstText(item.display_name, item.alias, item.label, item.name);
    const explicitName = rawName && !/^(?:wan|internet|互联网)(?:\s*\d+)?$/i.test(rawName) ? rawName : '';
    return {
      ...item,
      id: firstText(item.id, item.name, item.ifname, `wan-${index + 1}`),
      name: explicitName || carrierName,
      explicitName,
      carrierName,
      ifname: firstText(item.interface, item.ifname, item.device, runtime.ifname, '--'),
      physicalIfname: firstText(item.device, runtime.device, item.physical_ifname, runtime.physical_ifname, '--'),
      isp: carrierName,
      ipv4: firstText(item.ipv4, item.ip, item.ipaddr, item.public_ip, runtime.ipv4, runtime.ip, '--'),
      ipv6: firstGlobalIpv6(
        item.ipv6_global,
        item.global_ipv6,
        item.public_ipv6,
        item.ipv6_addrs,
        runtime.ipv6_global,
        runtime.global_ipv6,
        runtime.public_ipv6,
        item.ipv6,
        item.ipv6_addr,
        runtime.ipv6
      ) || '--',
      port: firstText(item.port_number, item.physical_port, item.device_port, item.device, runtime.device, '--'),
      connected: item.enabled !== false && ['up', 'online', 'connected', 'active', 'ok', 'healthy'].includes(normalizeKey(firstText(item.status, runtime.status, item.state)))
    };
  }
  function normalizeWans(rows) {
    const normalized = rows.map(normalizeWan);
    const totals = new Map();
    normalized.forEach((item) => {
      if (!item.explicitName) totals.set(item.carrierName, (totals.get(item.carrierName) || 0) + 1);
    });
    const positions = new Map();
    normalized.forEach((item) => {
      if (item.explicitName || (totals.get(item.carrierName) || 0) < 2) return;
      const position = (positions.get(item.carrierName) || 0) + 1;
      positions.set(item.carrierName, position);
      item.name = `${item.carrierName} ${position}`;
    });
    return normalized;
  }
  // Write capabilities for gateway port assignment ride on the
  // /api/v1/topology/node/ports response. When that request fails we must not
  // report "the backend does not implement it": the capability is simply unknown.
  function capabilityProbeError(result) {
    if (result?.status === 'fulfilled') return '';
    const status = Number(result?.reason?.status) || 0;
    if (status === 404 || status === 405 || status === 501) return `端口能力接口未实现（HTTP ${status}）`;
    if (status === 401) return '会话已失效，请重新登录后读取端口写入能力';
    if (status === 403) return '当前账号没有读取端口写入能力的权限';
    if (status >= 500) return `端口能力读取失败：后端错误 HTTP ${status}`;
    if (status) return `端口能力读取失败：HTTP ${status}`;
    return `端口能力读取失败：${firstText(result?.reason?.message, '网络不可用')}`;
  }
  // The RADIUS list endpoint is the authority for both the rows and its own
  // availability. Secrets stay server-side: the backend returns `secret_ref`, never a
  // plaintext secret, and the UI only ever displays that reference.
  function applyRadius(result) {
    if (result?.status === 'fulfilled') {
      const payload = result.value || {};
      state.radius = asArray(payload.servers || payload.items || payload).map(normalizeRadiusServer);
      state.radiusKnown = true;
      state.radiusError = '';
      return;
    }
    const status = Number(result?.reason?.status) || 0;
    state.radius = [];
    state.radiusKnown = false;
    if (status === 404 || status === 405 || status === 501) state.radiusError = `RADIUS 接口未实现（HTTP ${status}）`;
    else if (status === 401) state.radiusError = '会话已失效，请重新登录后查看 RADIUS 服务器';
    else if (status === 403) state.radiusError = '当前账号没有查看 RADIUS 服务器的权限';
    else if (status >= 500) state.radiusError = `RADIUS 读取失败：后端错误 HTTP ${status}`;
    else if (status) state.radiusError = `RADIUS 读取失败：HTTP ${status}`;
    else state.radiusError = `RADIUS 读取失败：${firstText(result?.reason?.message, '网络不可用')}`;
  }

  function normalizeRadiusServer(item = {}, index = 0) {
    const authPort = Number(item.auth_port);
    const acctPort = Number(item.accounting_port);
    return {
      id: firstText(item.id, item.uuid, `radius-${index + 1}`),
      name: firstText(item.name, item.label, `RADIUS ${index + 1}`),
      authAddr: firstText(item.auth_addr, item.address, item.host),
      authPort: Number.isFinite(authPort) && authPort > 0 ? authPort : null,
      acctAddr: firstText(item.accounting_addr, item.acct_addr),
      acctPort: Number.isFinite(acctPort) && acctPort > 0 ? acctPort : null,
      secretRef: firstText(item.secret_ref),
      enabled: item.enabled !== false && item.enabled !== 0
    };
  }

  function mergeData(overview, settingsOverview, globalData, lansData, wansData, portsData, detailData, profileData, preferencesData) {
    const lanRows = listRows(lansData, ['lans', 'networks']);
    const wanRows = listRows(wansData, ['wans', 'interfaces']);
    const lans = (lanRows.length ? lanRows : networkRows(overview, 'lans')).map(normalizeLan);
    const wans = normalizeWans(wanRows.length ? wanRows : networkRows(overview, 'wans'));
    const networks = networkMap(lans, wans);
    const details = detailMap(detailData.ports || detailData.items || detailData);
    const ports = asArray(portsData.ports || portsData.items || portsData)
      .map((port, index) => normalizePort(port, index, details.get(firstText(port.ifname, port.name, port.id)) || {}, networks))
      .filter((port) => !/^(lo|ifb|docker|br-|pppoe-|wan6|dummy|teql)/.test(port.ifname));
    const preserveGlobalDraft = (state.drawer === 'global' || state.pageTab === 'advanced') && globalDirty();
    state.overview = overview;
    state.settingsOverview = settingsOverview;
    state.capabilities = { ...(overview.capabilities || {}), ...(globalData.capabilities || {}), ...(globalData.global?.capabilities || {}), ...(detailData.capabilities || {}) };
    state.capabilitiesKnown = Object.keys(state.capabilities).length > 0;
    state.global = clone(globalData.global || globalData || overview.global?.global || overview.global || {});
    if (!preserveGlobalDraft) state.globalDraft = clone(state.global);
    state.ports = ports;
    state.lans = lans;
    state.wans = wans;
    state.profiles = asArray(profileData.profiles || profileData.items || profileData);
    interfacePayloads = { lan: lansData || {}, wan: wansData || {}, ports: portsData || {} };
    interfaceInstances.forEach((instance, key) => {
      const kind = key.startsWith('lan') ? 'lan' : 'wan';
      instance?.setData?.(interfacePayloads[kind], interfacePayloads.ports,
        state.wans.map((wan) => firstText(wan.id, wan.name)).filter(Boolean));
    });
    if (!gatewayDirty()) {
      const assignments = Object.fromEntries(ports.filter((port) => port.kind === 'wan' && gatewayOwnerId(port)).map((port) => [gatewayOwnerId(port), port.id]));
      state.gatewayInitial = assignments;
      state.gatewayDraft = clone(assignments);
    }
    const preferences = preferencesData?.visible_columns ? preferencesData : preferencesData?.data || {};
    if (!state.preferencesLoaded && preferences.saved === true && Array.isArray(preferences.visible_columns) && preferences.visible_columns.length) {
      const supported = new Set(COLUMNS.map((column) => column.key));
      state.visibleColumns = new Set(preferences.visible_columns.map((key) => key === 'native_vlan' ? 'vlan' : key).filter((key) => supported.has(key)));
      state.visibleColumns.add('select');
      state.visibleColumns.add('port');
      state.visibleColumns.add('actions');
      if (COLUMNS.some((column) => column.key === preferences.sort_key)) state.sortKey = preferences.sort_key;
      if (preferences.sort_direction === 'asc' || preferences.sort_direction === 'desc') state.sortDirection = preferences.sort_direction;
      state.preferencesLoaded = true;
    }
    state.preferencesLoaded = true;
    state.source = firstText(detailData.source, portsData.source, 'network/ports');
  }
  async function load(silent = false) {
    const seq = ++state.seq;
    if (silent) state.refreshing = true; else state.loading = true;
    state.error = '';
    patchMain();
    const results = await Promise.allSettled([
      fetchResource('global-overview', ENDPOINTS.overview),
      fetchResource('settings-overview', ENDPOINTS.settingsOverview),
      fetchResource('global-settings', ENDPOINTS.global),
      fetchResource('global-lans', ENDPOINTS.lans),
      fetchResource('global-wans', ENDPOINTS.wans),
      fetchResource('global-ports', ENDPOINTS.ports),
      fetchResource('global-topology-ports', ENDPOINTS.topologyPorts),
      fetchResource('global-port-profiles', ENDPOINTS.profiles),
      fetchResource('global-port-preferences', `${ENDPOINTS.preferences}?view=network.global.ports`),
      fetchResource('global-radius', ENDPOINTS.radius)
    ]);
    if (!state.mounted || seq !== state.seq) return;
    const value = (index) => results[index].status === 'fulfilled' ? results[index].value : {};
    mergeData(value(0), value(1), value(2), value(3), value(4), value(5), value(6), value(7), value(8));
    state.capabilitiesError = capabilityProbeError(results[6]);
    applyRadius(results[9]);
    const failed = results.map((result, index) => result.status === 'rejected' && ![1,3,4,8,9].includes(index) ? ['网络概览', '设置摘要', '全局设置', '网络列表', '互联网列表', '端口状态', '端口邻居', '配置文件', '列偏好', 'RADIUS'][index] : '').filter(Boolean);
    state.error = failed.length ? `${failed.join('、')}读取失败` : '';
    state.loading = false;
    state.refreshing = false;
    patchMain();
  }

  async function refreshPortStatistics() {
    if (!state.mounted || state.loading || state.refreshing || state.statsRefreshing || state.pageTab !== 'global') return;
    state.statsRefreshing = true;
    try {
      const portsData = await fetchResource('global-ports-live', ENDPOINTS.ports);
      if (!state.mounted || state.pageTab !== 'global') return;
      const portRows = listRows(portsData, ['ports', 'items', 'interfaces']);
      const currentById = new Map(state.ports.map((port) => [port.id, port]));
      const networks = networkMap(state.lans, state.wans);
      const next = portRows.map((port, index) => {
        const key = firstText(port.ifname, port.name, port.id, port.port_id);
        return normalizePort(port, index, currentById.get(key)?.raw || {}, networks);
      });
      const byId = new Map(next.map((port) => [port.id, port]));
      state.ports = state.ports.map((port) => byId.get(port.id) || port);
      patchPortStatistics();
    } catch (_) {
    } finally {
      state.statsRefreshing = false;
    }
  }

  function patchPortStatistics() {
    const rows = new Map(state.ports.map((port) => [port.id, port]));
    root?.querySelectorAll('[data-global-port-id]').forEach((row) => {
      const port = rows.get(row.dataset.globalPortId);
      if (!port) return;
      for (const key of ['activity', 'tx_total', 'rx_total', 'tx_rate', 'rx_rate']) {
        const node = row.querySelector(`td.is-${key}`);
        if (!node) continue;
        const next = cell(port, key);
        if (node.innerHTML !== next) node.innerHTML = next;
      }
    });
  }

  function resourceStatus(active) { return `<i class="global-resource-status ${active ? 'is-up' : ''}"></i>`; }
  const STAT_COLUMNS = new Set(['activity','tx_total','rx_total','tx_packets','rx_packets','tx_multicast','rx_multicast','tx_broadcast','rx_broadcast','tx_errors','rx_errors','tx_dropped','rx_dropped','tx_rate','rx_rate']);
  const PREFERENCE_KEYS = new Set(['port','name','connection','speed','duplex','stp','profile','poe','media','anomaly']);
  const PAGE_TABS = [['global', '全局'], ['wan', 'WAN 配置'], ['lan', 'LAN 配置'], ['advanced', '高级设置']];
  function filterCount() { return ['status', 'kind', 'speed', 'poe', 'vlan'].reduce((count, key) => count + (state[key] !== 'all' ? 1 : 0), 0) + (state.anomalyMin > 0 || state.anomalyMax < 100 ? 1 : 0); }
  function renderPageTabs() {
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs dwrt-kit-glass-surface global-page-tabs" role="tablist" aria-label="全局配置视图" data-global-page-tabs data-dwrt-tabs-key="network-global-config"><span class="dwrt-kit-tab-pill" aria-hidden="true"></span>${PAGE_TABS.map(([id, label]) => `<button class="dwrt-kit-tab ${state.pageTab === id ? 'is-active' : ''}" type="button" role="tab" data-global-page-tab="${id}" data-value="${id}" aria-selected="${state.pageTab === id ? 'true' : 'false'}">${label}</button>`).join('')}</nav>`;
  }
  function renderPageActions() {
    if (state.pageTab === 'global') {
      return `<div class="global-page-actions"><label class="policy-search policy-search-main global-search" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-global-search placeholder="搜索端口、MAC 或 IP" value="${escapeHtml(state.query)}"></label><button class="policy-filter-button ${state.statistics?'is-active':''}" type="button" data-global-statistics>${icon('batch')}<span>统计</span></button><button class="policy-filter-button" type="button" data-global-filter>${icon('filter')}<span>筛选</span>${filterCount() ? `<span class="policy-count-badge">${filterCount()}</span>` : ''}</button><button class="policy-filter-button" type="button" data-global-columns>${icon('columns')}<span>列</span></button></div>`;
    }
    if (state.pageTab === 'wan' || state.pageTab === 'lan') {
      const kind = state.pageTab;
      return `<div class="global-page-actions global-interface-page-actions"><label class="policy-search policy-search-main global-search" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-global-interface-search="${kind}" placeholder="搜索名称、接口、地址或运营商" value="${escapeHtml(state.query)}"></label><button class="policy-create-button" type="button" data-global-interface-create="${kind}">${icon('plus')}<span>新建 ${kind.toUpperCase()}</span></button></div>`;
    }
    return '';
  }
  function renderPageHeader() {
    return `<header class="global-page-header">${renderPageTabs()}${renderPageActions()}</header>`;
  }
  function filteredPorts() {
    const query = state.query.trim().toLowerCase();
    const rows = state.ports.filter((port) => {
      if (state.status === 'connected' && !port.connected) return false;
      if (state.status === 'disconnected' && port.connected) return false;
      if (state.kind !== 'all' && port.kind !== state.kind) return false;
      if (state.speed !== 'all' && speedKey(port) !== state.speed) return false;
      if (state.poe === 'yes' && !port.poeCapable) return false;
      if (state.poe === 'no' && port.poeCapable) return false;
      if (state.vlan === 'default' && port.vlan > 1) return false;
      if (state.vlan === 'tagged' && port.vlan <= 1 && !port.taggedVlans.length) return false;
      if (port.anomaly !== null && (port.anomaly < state.anomalyMin || port.anomaly > state.anomalyMax)) return false;
      return !query || [port.ifname, port.name, port.connection, port.networkName, port.mac, port.ip, port.profileName, port.speedLabel].join(' ').toLowerCase().includes(query);
    });
    const direction = state.sortDirection === 'desc' ? -1 : 1;
    const sortValue = (port, key) => ({
      port: port.portNumber ?? port.ifname,
      name: port.name,
      connection: port.connection,
      network: port.networkName,
      speed: port.speedMbps,
      profile: port.profileName,
      vlan: port.vlan,
      poe: port.poeEnabled,
      tagged_vlan: port.taggedVlans.join(','),
      activity: port.activitySeconds,
      tx_total: port.txBytes,
      rx_total: port.rxBytes,
      tx_rate: port.txRate,
      rx_rate: port.rxRate,
      media: port.media,
      multicast_router: port.multicastRouter
    }[key] ?? port[key]);
    return rows.sort((a, b) => {
      const av = sortValue(a, state.sortKey); const bv = sortValue(b, state.sortKey);
      const aNumber = Number(av); const bNumber = Number(bv);
      let result = Number.isFinite(aNumber) && Number.isFinite(bNumber)
        ? aNumber - bNumber
        : String(av ?? '').localeCompare(String(bv ?? ''), 'zh-CN', { numeric: true });
      if (!result) result = String(a.ifname).localeCompare(String(b.ifname), 'zh-CN', { numeric: true });
      return result * direction;
    });
  }
  function speedKey(port) {
    const speed = Number(port.speedMbps || 0);
    if (speed >= 10000) return '10g';
    if (speed >= 2500) return '2.5g';
    if (speed >= 1000) return '1g';
    if (speed > 0) return 'sub1g';
    return 'auto';
  }
  function sortIndicator(key) { return state.sortKey === key ? `<span class="global-sort is-${state.sortDirection}">${icon('chevron')}</span>` : ''; }
  function cell(port, key) {
    if (key === 'select') return `<label class="global-row-select" aria-label="选择 ${escapeHtml(port.name)}"><input type="checkbox" data-global-port-select="${escapeHtml(port.id)}" ${state.selectedPorts.has(port.id) ? 'checked' : ''}><span></span></label>`;
    if (key === 'port') return `<button class="global-port-id" type="button" data-global-port="${escapeHtml(port.id)}"><i class="is-${port.kind} ${port.connected ? 'is-up' : ''}"></i><strong>${escapeHtml(String(port.portNumber || port.ifname))}</strong></button>`;
    if (key === 'name') return `<span class="global-cell-stack"><strong>${escapeHtml(port.name)}</strong></span>`;
    if (key === 'anomaly') return port.anomaly === null ? '--' : `<span class="global-anomaly ${port.anomaly >= 70 ? 'is-bad' : port.anomaly >= 30 ? 'is-warn' : 'is-ok'}">${Math.round(port.anomaly)}</span>`;
    if (key === 'stp') return escapeHtml(port.stp);
    if (key === 'connection') {
      if (port.kind === 'wan') return carrierLogo(port.wanOwner || {}) || `<span class="global-cell-ellipsis" data-dwrt-tooltip="${escapeHtml(port.connection)}">${icon('internet')}</span>`;
      return `<span class="global-cell-ellipsis" data-dwrt-tooltip="${escapeHtml(port.connection)}">${escapeHtml(port.connection)}</span>`;
    }
    if (key === 'network') return `<span class="global-network-pill is-${port.kind}">${escapeHtml(port.networkName)}</span>`;
    if (key === 'speed') return `<span class="global-speed ${port.connected ? 'is-up' : ''}">${escapeHtml(port.speedLabel)}</span>`;
    if (key === 'duplex') return escapeHtml(port.duplex);
    if (key === 'mac') return `<code>${escapeHtml(port.mac)}</code>`;
    if (key === 'ip') return `<code>${escapeHtml(port.ip)}</code>`;
    if (key === 'profile') return `<span class="global-cell-ellipsis" title="${escapeHtml(port.profileName)}">${escapeHtml(port.profileName)}</span>`;
    if (key === 'vlan') return port.vlan ? String(port.vlan) : 'Default';
    if (key === 'poe') return port.poeCapable ? (port.poeEnabled ? '开启' : '关闭') : '无';
    if (key === 'pro_av') return firstText(port.raw?.pro_av, port.config?.pro_av, '--');
    if (key === 'tagged_vlan') return port.taggedVlans.length ? escapeHtml(port.taggedVlans.join(', ')) : '--';
    if (key === 'activity') return formatDuration(port.activitySeconds);
    if (key === 'tx_total') return formatBytes(port.txBytes);
    if (key === 'rx_total') return formatBytes(port.rxBytes);
    if (key === 'tx_packets') return formatCount(port.txPackets);
    if (key === 'rx_packets') return formatCount(port.rxPackets);
    if (key === 'tx_multicast') return formatCount(port.txMulticast);
    if (key === 'rx_multicast') return formatCount(port.rxMulticast);
    if (key === 'tx_broadcast') return formatCount(port.txBroadcast);
    if (key === 'rx_broadcast') return formatCount(port.rxBroadcast);
    if (key === 'tx_errors') return formatCount(port.txErrors);
    if (key === 'rx_errors') return formatCount(port.rxErrors);
    if (key === 'tx_dropped') return formatCount(port.txDropped);
    if (key === 'rx_dropped') return formatCount(port.rxDropped);
    if (key === 'tx_rate') return `<span class="global-rate is-up">${formatRate(port.txRate)}</span>`;
    if (key === 'rx_rate') return `<span class="global-rate is-down">${formatRate(port.rxRate)}</span>`;
    if (key === 'lag_id') return escapeHtml(port.lagId);
    if (key === 'media') return escapeHtml(port.media);
    if (key === 'multicast_router') return escapeHtml(port.multicastRouter);
    if (key === 'actions') return `<button class="global-row-action" type="button" data-global-port="${escapeHtml(port.id)}" aria-label="查看 ${escapeHtml(port.name)}">${icon('edit')}</button>`;
    return '--';
  }
  function renderTable() {
    const rows = filteredPorts();
    const columns = COLUMNS.filter((column) => (column.fixed || state.visibleColumns.has(column.key)) && (state.statistics || !STAT_COLUMNS.has(column.key)));
    const tableWidth = columns.reduce((total, column) => total + column.width, 0);
    const subtitle = state.error || `${state.ports.filter((port) => port.connected).length} 个使用中 · ${state.ports.length - state.ports.filter((port) => port.connected).length} 个未连接`;
    const allSelected = rows.length > 0 && rows.every((port) => state.selectedPorts.has(port.id));
    return `<section class="global-port-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface" data-dwrt-component="data-table" data-global-table><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>所有端口</strong><span class="${state.error ? 'is-warning' : ''}">${escapeHtml(subtitle)}</span></div><div class="global-table-meta">${state.selectedPorts.size ? `<button class="global-bulk-button" type="button" data-global-bulk>${icon('batch')}批量配置 ${state.selectedPorts.size}</button>` : ''}<span class="dwrt-kit-table-count">${rows.length}/${state.ports.length} 个端口</span></div></div><div class="dwrt-kit-table-scroll global-port-table-scroll" data-global-scroll><table class="dwrt-kit-table dwrt-kit-ikuai-table global-port-table" style="--global-port-table-width:${tableWidth}px"><thead><tr>${columns.map((column) => `<th style="width:${column.width}px;min-width:${column.width}px">${column.key === 'select' ? `<label class="global-row-select" aria-label="选择当前结果"><input type="checkbox" data-global-select-all ${allSelected ? 'checked' : ''}><span></span></label>` : `<button type="button" data-global-sort="${column.key}" ${column.key === 'actions' ? 'disabled' : ''}>${escapeHtml(column.label)}${sortIndicator(column.key)}</button>`}</th>`).join('')}</tr></thead><tbody>${state.loading ? `<tr><td colspan="${columns.length}" class="dwrt-kit-table-empty">正在读取端口状态</td></tr>` : rows.length ? rows.map((port) => `<tr data-global-port-id="${escapeHtml(port.id)}" class="${port.connected ? 'is-connected' : 'is-disconnected'} ${state.selectedPorts.has(port.id) ? 'is-selected' : ''}">${columns.map((column) => `<td class="is-${column.key}">${cell(port, column.key)}</td>`).join('')}</tr>`).join('') : `<tr><td colspan="${columns.length}" class="dwrt-kit-table-empty">${escapeHtml(state.error || '没有匹配的端口')}</td></tr>`}</tbody></table></div></section>`;
  }
  function gatewayPorts() {
    return [...state.ports].sort((a, b) => {
      const av = a.portNumber ?? Number.MAX_SAFE_INTEGER;
      const bv = b.portNumber ?? Number.MAX_SAFE_INTEGER;
      return av - bv || a.ifname.localeCompare(b.ifname, 'zh-CN', { numeric: true });
    });
  }
  function gatewayWans() {
    return [...state.wans].sort((a, b) => String(a.id).localeCompare(String(b.id), 'zh-CN', { numeric: true }));
  }
  function gatewayOwnerId(port) {
    return firstText(port.ownerId, state.wans.find((wan) => [wan.id, wan.ifname, wan.physicalIfname].includes(port.id) || [wan.id, wan.ifname, wan.physicalIfname].includes(port.ifname))?.id);
  }
  function wanAssignmentLabel(id) {
    const index = gatewayWans().findIndex((wan) => wan.id === id);
    return index >= 0 ? `WAN${index + 1}` : String(id || '');
  }
  function assignedWan(portId, assignments = state.gatewayDraft) {
    return Object.entries(assignments || {}).find(([, id]) => id === portId)?.[0] || '';
  }
  function gatewayDirty() {
    return JSON.stringify(state.gatewayDraft || {}) !== JSON.stringify(state.gatewayInitial || {});
  }
  function gatewayPortTone(port) {
    if (!port.connected) return 'is-disconnected';
    const speed = Number(port.speedMbps || 0);
    if (speed >= 10000) return 'is-10g';
    if (speed >= 2500) return 'is-2-5g';
    if (speed >= 1000) return 'is-1g';
    return 'is-sub-gig';
  }
  function gatewaySpeedLabel(port) {
    if (!port.connected) return '自动';
    const speed = Number(port.speedMbps || 0);
    if (!speed) return firstText(port.speedLabel, '自动');
    if (speed >= 1000) return `${Number.isInteger(speed / 1000) ? speed / 1000 : (speed / 1000).toFixed(1)} GbE`;
    return `${speed} MbE`;
  }
  function gatewayPortName(port) {
    if (port.kind === 'lan') {
      const lan = state.lans.find((item) => item.id === port.ownerId || asArray(item.ports).includes(port.ifname));
      return logicalPortName(firstText(lan?.device, lan?.name, port.name, `Port ${port.portNumber || port.ifname}`), port.ifname);
    }
    if (port.kind === 'wan') {
      const owner = gatewayOwnerId(port);
      const wan = state.wans.find((item) => item.id === owner || [item.ifname, item.physicalIfname].includes(port.ifname));
      return logicalPortName(firstText(wan?.id, port.name, `Port ${port.portNumber || port.ifname}`), port.ifname);
    }
    return logicalPortName(firstText(port.raw?.display_name, port.name, port.raw?.label, `Port ${port.portNumber || port.ifname}`), port.ifname);
  }
  function gatewayAssignmentControl(port) {
    const owner = assignedWan(port.id);
    const primary = gatewayWans()[0]?.id || '';
    const aggregate = Number(port.raw?.aggregate_members?.length || port.raw?.aggregated_by || port.raw?.lag_idx || 0) > 0;
    return `<label class="gateway-assignment-control"><select data-dwrt-component="select" data-gateway-assignment="${escapeHtml(port.id)}" aria-label="${escapeHtml(`${gatewayPortName(port)} 的角色分配`)}" ${aggregate ? 'disabled' : ''}>
      ${owner === primary ? '' : `<option value="" ${owner ? '' : 'selected'}>${port.kind === 'lan' ? 'LAN' : '未分配'}</option>`}
      ${gatewayWans().map((wan) => `<option value="${escapeHtml(wan.id)}" ${owner === wan.id ? 'selected' : ''}>${escapeHtml(wanAssignmentLabel(wan.id))}</option>`).join('')}
    </select></label>`;
  }
  function gatewayPortTile(port) {
    const owner = assignedWan(port.id);
    const media = normalizeKey(firstText(port.media, port.raw?.media_type));
    const role = owner ? wanAssignmentLabel(owner) : port.kind === 'lan' ? firstText(port.networkName, 'LAN') : '未分配';
    return `<button class="gateway-port-tile ${gatewayPortTone(port)} ${owner ? 'is-wan' : ''}" type="button" data-gateway-port="${escapeHtml(port.id)}" data-dwrt-tooltip="${escapeHtml([gatewayPortName(port), role, gatewaySpeedLabel(port)].join(' · '))}">
      <span>${owner ? icon('internet') : media.includes('sfp') ? 'SFP' : ''}</span><strong>${escapeHtml(String(port.portNumber || port.ifname))}</strong>
    </button>`;
  }
  function gatewayDiagramMarkup() {
    const ports = gatewayPorts();
    const halfway = Math.ceil(ports.length / 2);
    const columns = Math.max(1, halfway);
    return `<div class="gateway-port-diagram" style="--gateway-port-columns:${columns}">${ports.map(gatewayPortTile).join('')}</div>`;
  }
  function gatewayLegendMarkup() {
    const tones = new Map();
    gatewayPorts().forEach((port) => {
      const tone = gatewayPortTone(port);
      const label = tone === 'is-10g' ? '10 GbE' : tone === 'is-2-5g' ? '2.5 GbE' : tone === 'is-1g' ? 'GbE' : tone === 'is-sub-gig' ? '低于 GbE' : '已断开连接';
      tones.set(tone, label);
    });
    return `<div class="gateway-port-legend">${[...tones].map(([tone, label]) => `<span><i class="${tone}"></i>${label}</span>`).join('')}</div>`;
  }
  function gatewayConnection(port) {
    const owner = assignedWan(port.id);
    if (!port.connected) return '--';
    if (owner) {
      const wan = state.wans.find((item) => item.id === owner);
      return firstText(wan?.name, wan?.carrierName, port.networkName, wanAssignmentLabel(owner));
    }
    return firstText(port.connection, '--');
  }
  function carrierLogo(wan = {}) {
    const key = normalizeKey(firstText(wan.carrier, wan.carrier_key, wan.carrierName, wan.isp, wan.name));
    const file = key.includes('unicom') || key.includes('联通') ? 'china-unicom.svg'
      : key.includes('telecom') || key.includes('电信') ? 'china-telecom.svg'
        : key.includes('mobile') || key.includes('移动') ? 'china-mobile.svg'
          : key.includes('cernet') || key.includes('教育') ? 'china-cernet.svg' : '';
    if (!file) return '';
    const label = firstText(wan.carrierName, wan.name, wan.id, '运营商');
    return `<img class="gateway-carrier-logo" src="/static/images/logo/${file}" alt="${escapeHtml(label)}" data-dwrt-tooltip="${escapeHtml(label)}">`;
  }
  function gatewayConnectionMarkup(port) {
    const owner = assignedWan(port.id);
    if (owner) {
      const wan = state.wans.find((item) => item.id === owner) || {};
      return carrierLogo(wan) || `<span>${escapeHtml(gatewayConnection(port))}</span>`;
    }
    return `<span>${escapeHtml(gatewayConnection(port))}</span>`;
  }
  function gatewayTableMarkup() {
    const ports = gatewayPorts();
    return `<div class="gateway-port-table-scroll"><table class="gateway-port-table"><thead><tr><th>端口</th><th>名称</th><th>角色分配</th><th>速度</th><th>连接</th></tr></thead><tbody>${ports.length ? ports.map((port) => { const name = gatewayPortName(port); return `<tr><td><span class="gateway-port-cell"><i class="${gatewayPortTone(port)} ${assignedWan(port.id) ? 'is-wan' : ''}">${assignedWan(port.id) ? icon('internet') : ''}</i>${escapeHtml(String(port.portNumber || port.ifname))}</span></td><td><span class="global-cell-stack"><strong>${escapeHtml(name)}</strong></span></td><td>${gatewayAssignmentControl(port)}</td><td><span class="gateway-speed ${gatewayPortTone(port)}">${escapeHtml(gatewaySpeedLabel(port))}</span></td><td><span class="gateway-connection">${gatewayConnectionMarkup(port)}</span></td></tr>`; }).join('') : '<tr><td colspan="5" class="dwrt-kit-table-empty">后端未返回 Gateway 物理端口</td></tr>'}</tbody></table></div>`;
  }
  function gatewayChangeSummary() {
    return gatewayWans().flatMap((wan) => {
      const before = state.gatewayInitial[wan.id] || '';
      const after = state.gatewayDraft[wan.id] || '';
      if (before === after) return [];
      const from = state.ports.find((port) => port.id === before);
      const to = state.ports.find((port) => port.id === after);
      return [{ wan, before, after, from, to }];
    });
  }
  function gatewayMigrationSteps() {
    const defaultLan = firstText(state.lans[0]?.id, 'lan');
    return gatewayPorts().flatMap((port) => {
      const nextWan = assignedWan(port.id);
      const nextType = nextWan ? 'wan' : port.kind === 'wan' ? 'lan' : port.kind;
      const nextId = nextWan || (port.kind === 'wan' ? defaultLan : port.ownerId);
      if (!nextType || !nextId || (nextType === port.kind && nextId === port.ownerId)) return [];
      return [{ ifname: port.ifname, portId: port.id, target_owner_type: nextType, target_owner_id: nextId }];
    });
  }
  function gatewayPreviewMarkup() {
    if (!state.gatewayPreview) return '';
    const changes = gatewayChangeSummary();
    const atomicApply = strictCap('gateway_port_assignment_atomic_apply');
    const applySupported = atomicApply && state.gatewayPreview.failed === 0;
    const requiresConfirm = strictCap('gateway_port_assignment_requires_confirm');
    return `<section class="gateway-change-preview" role="status"><header><div><strong>待应用变更</strong><span>${changes.length} 条角色分配 · ${state.gatewayPreview.ok}/${state.gatewayPreview.total} 个迁移步骤通过预检</span></div><span class="${applySupported ? 'is-ready' : 'is-blocked'}">${applySupported ? '可应用' : '仅可预览'}</span></header><div>${changes.map(({ wan, from, to }) => `<article><strong>${escapeHtml(wanAssignmentLabel(wan.id))}</strong><span>${escapeHtml(from ? `${gatewayPortName(from)} → ` : '未分配 → ')}${escapeHtml(to ? gatewayPortName(to) : '未分配（原端口回归 LAN）')}</span></article>`).join('')}</div><p>${escapeHtml(gatewayApplyExplanation(atomicApply, requiresConfirm, state.gatewayPreview.failed))}</p></section>`;
  }
  // Three distinct outcomes: capability true, capability explicitly false, and
  // capability unknown because its source request failed. They must never share copy.
  function gatewayApplyExplanation(atomicApply, requiresConfirm, failed) {
    if (atomicApply) {
      if (failed) return '部分迁移步骤预检未通过，请先解决失败项再提交；应用时后端会作为一个原子事务执行。';
      return requiresConfirm
        ? '提交需二次确认，由后端作为一个原子事务执行，并在管理可达性异常时自动回滚。'
        : '提交时由后端作为一个原子事务执行，并在管理可达性异常时自动回滚。';
    }
    if (!state.capabilitiesKnown) return `${firstText(state.capabilitiesError, '端口写入能力未知')}；能力未确认前只展示真实预检结果，不会伪造保存。`;
    return '当前设备报告不支持 Gateway 端口分配的原子应用；只展示真实预检结果，不会伪造保存。';
  }
  function renderGatewayPorts() {
    const canApply = state.gatewayPreview && state.gatewayPreview.failed === 0 && strictCap('gateway_port_assignment_atomic_apply');
    const noticeError = /失败|不支持|未实现|未知|无法|必须/.test(state.gatewayNotice);
    return `<section class="gateway-ports-card dwrt-kit-glass-surface" data-global-gateway><header><div><strong>Gateway 端口</strong><span>查看链路状态并分配 WAN 角色</span></div></header><div class="gateway-ports-body"><div class="gateway-port-map">${gatewayDiagramMarkup()}${gatewayLegendMarkup()}</div>${gatewayTableMarkup()}${gatewayPreviewMarkup()}${state.gatewayNotice ? `<div class="global-notice ${noticeError ? 'is-error' : ''}">${escapeHtml(state.gatewayNotice)}</div>` : ''}</div>${gatewayDirty() ? `<footer><button class="policy-secondary" type="button" data-gateway-reset>取消</button>${canApply ? `<button class="policy-primary" type="button" data-gateway-apply ${state.saving ? 'disabled' : ''}>${state.saving ? '正在应用' : '确认应用'}</button>` : `<button class="policy-primary" type="button" data-gateway-preview ${state.saving ? 'disabled' : ''}>${state.saving ? '正在检查' : state.gatewayPreview ? '重新检查' : '应用更改'}</button>`}</footer>` : ''}</section>`;
  }
  function radio(name, value, label, count, checked) { return `<label class="policy-filter-row"><input type="radio" name="${name}" value="${value}" ${checked ? 'checked' : ''}><span class="policy-control-dot"></span><span class="policy-filter-label">${escapeHtml(label)}</span><span class="policy-filter-count">${count}</span></label>`; }
  function renderFilterDrawer() {
    if (state.drawer !== 'filter') return '';
    const count = (predicate) => state.ports.filter(predicate).length;
    return `${backdrop('关闭筛选')}<aside class="global-drawer global-filter-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open"><header class="dwrt-kit-sheet-header"><div><span>FILTER</span><strong>筛选端口</strong></div><button class="dwrt-kit-sheet-close" type="button" data-global-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body global-drawer-body">
      <section class="global-filter-section"><h3>24 小时 AI 异常评分</h3><div class="global-anomaly-range"><label><span>最低</span><input type="range" min="0" max="100" value="${state.anomalyMin}" data-global-anomaly="min"><b>${state.anomalyMin}</b></label><label><span>最高</span><input type="range" min="0" max="100" value="${state.anomalyMax}" data-global-anomaly="max"><b>${state.anomalyMax}</b></label></div></section>
      <section class="global-filter-section"><h3>状态</h3>${radio('global-status','all','所有状态',state.ports.length,state.status==='all')}${radio('global-status','connected','使用中',count((p)=>p.connected),state.status==='connected')}${radio('global-status','disconnected','未连接',count((p)=>!p.connected),state.status==='disconnected')}</section>
      <section class="global-filter-section"><h3>端口类型</h3>${radio('global-kind','all','全部类型',state.ports.length,state.kind==='all')}${radio('global-kind','wan','WAN',count((p)=>p.kind==='wan'),state.kind==='wan')}${radio('global-kind','lan','LAN',count((p)=>p.kind==='lan'),state.kind==='lan')}</section>
      <section class="global-filter-section"><h3>PoE</h3>${radio('global-poe','all','全部',state.ports.length,state.poe==='all')}${radio('global-poe','yes','支持 PoE',count((p)=>p.poeCapable),state.poe==='yes')}${radio('global-poe','no','无 PoE',count((p)=>!p.poeCapable),state.poe==='no')}</section>
      <section class="global-filter-section"><h3>链路速度</h3>${[['all','全部'],['10g','10 GbE'],['2.5g','2.5 GbE'],['1g','GbE'],['sub1g','低于 GbE'],['auto','自动 / 未连接']].map(([value,label])=>radio('global-speed',value,label,value==='all'?state.ports.length:count((p)=>speedKey(p)===value),state.speed===value)).join('')}</section>
      <section class="global-filter-section"><h3>原生 VLAN</h3>${radio('global-vlan','all','全部',state.ports.length,state.vlan==='all')}${radio('global-vlan','default','Default',count((p)=>p.vlan<=1),state.vlan==='default')}${radio('global-vlan','tagged','已配置 VLAN',count((p)=>p.vlan>1||p.taggedVlans.length),state.vlan==='tagged')}</section>
    </div><footer class="dwrt-kit-sheet-footer"><button class="policy-text-button" type="button" data-global-clear-filter ${filterCount() ? '' : 'disabled'}>清除筛选条件</button><button class="policy-primary" type="button" data-global-close>完成</button></footer></aside>`;
  }
  function renderColumnsDrawer() {
    if (state.drawer !== 'columns') return '';
    return `${backdrop('关闭列设置')}<aside class="global-drawer global-columns-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open"><header class="dwrt-kit-sheet-header"><div><span>COLUMNS</span><strong>自定义列</strong></div><button class="dwrt-kit-sheet-close" type="button" data-global-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body global-drawer-body"><div class="global-column-list">${COLUMNS.filter((column)=>!column.fixed).map((column)=>`<label><input type="checkbox" data-global-column="${column.key}" ${state.visibleColumns.has(column.key)?'checked':''}><span></span><strong>${escapeHtml(column.label)}</strong></label>`).join('')}</div></div><footer class="dwrt-kit-sheet-footer"><button class="policy-text-button" type="button" data-global-columns-reset>恢复默认</button><button class="policy-primary" type="button" data-global-columns-done>完成</button></footer></aside>`;
  }
  function globalField(label, control, hint = '') { return `<label class="global-setting-row"><span><strong>${escapeHtml(label)}</strong>${hint ? `<small>${escapeHtml(hint)}</small>` : ''}</span>${control}</label>`; }
  function globalSelect(key, value, options, enabled = true) { return `<select data-dwrt-component="select" data-global-setting="${key}" ${enabled ? '' : 'disabled'}>${options.map(([id,label])=>`<option value="${escapeHtml(id)}" ${String(value)===String(id)?'selected':''}>${escapeHtml(label)}</option>`).join('')}</select>`; }
  function globalSwitch(key, checked, enabled = true, attributes = '') { return `<span class="global-switch"><input type="checkbox" data-global-setting="${key}" ${checked?'checked':''} ${enabled?'':'disabled'} ${attributes}><i></i></span>`; }
  function cap(key) { return state.capabilities[key] !== false; }
  function strictCap(key) { return state.capabilities[key] === true; }
  function globalDirty() { return JSON.stringify(state.globalDraft) !== JSON.stringify(state.global); }
  function internetSettingsMarkup() {
    const policyWritable = strictCap('wan_policy_write') || strictCap('wan_load_balance_write');
    const mode = firstText(state.global.wan_mode, state.settingsOverview.wan_mode, 'failover');
    return `<section class="global-settings-section"><h3>WAN 模式</h3><div class="global-mode-options">
      <label><input type="radio" name="global-wan-mode" value="failover" ${mode !== 'load_balance' ? 'checked' : ''} ${policyWritable ? '' : 'disabled'}><span><strong>仅故障转移</strong><small>主线路故障时切换到备用线路</small></span></label>
      <label><input type="radio" name="global-wan-mode" value="load_balance" ${mode === 'load_balance' ? 'checked' : ''} ${policyWritable ? '' : 'disabled'}><span><strong>负载均衡</strong><small>按线路权重分配新连接</small></span></label>
    </div>${policyWritable ? '' : '<div class="global-contract-note">当前后端尚未提供 WAN 模式、优先级与权重的事务合同，因此只展示真实线路，不模拟保存。</div>'}</section>
    <section class="global-settings-section"><div class="global-section-heading"><h3>互联网线路</h3><span>${state.wans.length} 条</span></div><div class="global-wan-policy-list">${state.wans.length ? state.wans.map((wan, index) => {
      const role = firstText(wan.role, wan.advanced?.failover ? 'failover' : index === 0 ? 'primary' : 'backup');
      const priority = firstNumber(wan.priority, wan.metric, index + 1);
      const weight = optionalNumber(wan.weight, wan.load_balance_weight);
      return `<article><span>${resourceStatus(wan.connected)}<strong>${escapeHtml(wan.name)}</strong><small>${escapeHtml([wan.id, wan.ifname, wan.physicalIfname].filter((value) => value && value !== '--').join(' · ') || '--')}</small></span><span><b>${escapeHtml(role === 'primary' ? '主线路' : role === 'backup' ? '备用线路' : role === 'failover' ? '故障转移' : role)}</b><small>${mode === 'load_balance' ? `权重 ${weight === null ? '--' : `${weight}%`}` : `优先级 ${priority || '--'}`}</small></span></article>`;
    }).join('') : '<div class="dwrt-kit-table-empty">暂无 WAN 线路</div>'}</div></section>
    <section class="global-settings-section"><h3>线路服务</h3>
      ${globalField('流量控制', globalSwitch('wan_traffic_control', Boolean(state.global.wan_traffic_control), strictCap('wan_traffic_control_write')), '按线路限制或整形互联网流量')}
      ${globalField('自动速度测试', globalSwitch('wan_auto_speed_test', Boolean(state.global.wan_auto_speed_test), strictCap('wan_auto_speed_test_write')), '定期校准线路可用带宽')}
      ${globalField('Gateway 端口分配', '<button class="global-inline-action" type="button" disabled>管理端口</button>', '将物理网口重新分配为 WAN，需要受保护事务')}
    </section>
    <section class="global-settings-section"><div class="global-section-heading"><div><h3>WAN SLA</h3><small>为线路配置延迟、丢包和可用性目标</small></div><button class="global-inline-action" type="button" ${strictCap('wan_sla_write') ? '' : 'disabled'}>${icon('plus')}新建</button></div><div class="global-contract-note">当前没有可用的 WAN SLA 列表与 CRUD 合同；后端补齐前不生成占位 SLA。</div></section>`;
  }
  function networkSettingsMarkup() {
    const g = state.globalDraft;
    return `<section class="global-settings-section"><h3>网络行为</h3>${globalField('默认安全策略',globalSelect('default_posture',g.default_posture||'allow',[['allow','允许全部'],['deny','全部阻止']]),'未命中显式策略时的默认处理')}${globalField('Gateway mDNS 代理',globalSelect('mdns_proxy',g.mdns_proxy||'auto',[['auto','自动'],['enabled','自定义'],['disabled','关']],cap('mdns_proxy')),'跨网段发现 Bonjour / mDNS 服务')}${globalField('IGMP 监听',globalSwitch('igmp_snooping',Boolean(g.igmp_snooping),cap('igmp_snooping')),'优化网络内组播转发')}${globalField('流量控制',globalSwitch('flow_control',Boolean(g.flow_control),cap('flow_control')),'以太网 PAUSE 帧')}</section>
      <section class="global-settings-section"><h3>全局 Switch 设置</h3>${globalField('生成树',globalSwitch('bridge_stp',g.bridge_stp!==false,cap('stp')),'防止二层环路')}${globalField('生成树协议',globalSelect('stp_mode',g.stp_mode||'rstp',[['rstp','RSTP'],['stp','STP'],['disabled','已禁用']],cap('stp_mode')))}${globalField('转发延迟',`<input type="number" min="1" max="30" data-global-setting="bridge_forward_delay" value="${escapeHtml(g.bridge_forward_delay ?? 2)}" ${cap('stp')?'':'disabled'}>`, '秒')}${globalField('恶意 DHCP 服务器检测',globalSwitch('rogue_dhcp_detection',Boolean(g.rogue_dhcp_detection),cap('rogue_dhcp_detection')),'发现非授权 DHCP 服务')}${globalField('巨型帧',globalSwitch('jumbo_frames',Boolean(g.jumbo_frames),cap('jumbo_frames')),'使用大于 1500 字节的帧')}${globalField('802.1X 控制',globalSwitch('dot1x',Boolean(g.dot1x),cap('dot1x')),'端口级身份认证')}</section>
      <section class="global-settings-section"><div class="global-section-heading"><div><h3>RADIUS 服务器</h3><small>本地凭据与外部认证服务器</small></div></div>${radiusListMarkup()}</section>
      <section class="global-settings-section"><div class="global-section-heading"><div><h3>端口配置文件</h3><small>复用 VLAN、PoE 和链路设置</small></div><button class="global-inline-action" type="button" ${strictCap('port_profile_write') ? '' : 'disabled'}>${icon('plus')}新建</button></div><div class="global-profile-list">${state.profiles.length ? state.profiles.slice(0, 8).map((profile) => `<article><strong>${escapeHtml(firstText(profile.name, profile.label, profile.id))}</strong><small>${escapeHtml(firstText(profile.description, profile.native_vlan ? `原生 VLAN ${profile.native_vlan}` : '端口配置文件'))}</small></article>`).join('') : '<div class="dwrt-kit-table-empty">暂无端口配置文件</div>'}</div></section>`;
  }
  function advancedAvailabilityNote(message) {
    return `<details class="global-advanced-availability"><summary>可用性说明</summary><p>${escapeHtml(message)}</p></details>`;
  }
  function advancedActionRow(label, hint, actionLabel, enabled = false) {
    return `<div class="global-setting-row global-advanced-action-row"><span><strong>${escapeHtml(label)}</strong><small>${escapeHtml(hint)}</small></span><button class="global-inline-action" type="button" ${enabled ? '' : 'disabled'}>${icon('plus')}<span>${escapeHtml(actionLabel)}</span></button></div>`;
  }
  function advancedGroup(id, iconName, title, summary, body) {
    const open = state.advancedOpen.has(id);
    const triggerId = `global-advanced-${id}-trigger`;
    const panelId = `global-advanced-${id}-panel`;
    return `<section class="global-advanced-module ${open ? 'is-open' : ''}" data-global-advanced-group="${escapeHtml(id)}">
      <h3 class="global-advanced-module-heading">
        <button id="${triggerId}" type="button" data-global-advanced-toggle="${escapeHtml(id)}" aria-expanded="${open ? 'true' : 'false'}" aria-controls="${panelId}">
          <span class="global-advanced-module-icon">${icon(iconName)}</span>
          <span class="global-advanced-module-copy"><strong>${escapeHtml(title)}</strong><small>${escapeHtml(summary)}</small></span>
          <span class="global-advanced-module-chevron">${icon('chevron')}</span>
        </button>
      </h3>
      <div id="${panelId}" class="global-advanced-module-body" role="region" aria-labelledby="${triggerId}" ${open ? '' : 'hidden'}>${body}</div>
    </section>`;
  }
  function advancedWanPolicyMarkup() {
    const policyWritable = strictCap('wan_policy_write') || strictCap('wan_load_balance_write');
    const mode = firstText(state.globalDraft.wan_mode, state.global.wan_mode, state.settingsOverview.wan_mode, 'failover');
    return `<fieldset class="global-advanced-choice"><legend>WAN 模式</legend><div class="global-mode-options global-advanced-mode-options">
      <label><input type="radio" name="advanced-wan-mode" value="failover" data-global-wan-mode ${mode !== 'load_balance' ? 'checked' : ''} ${policyWritable ? '' : 'disabled'}><span><strong>仅故障转移</strong><small>主线路不可用时切换线路</small></span></label>
      <label><input type="radio" name="advanced-wan-mode" value="load_balance" data-global-wan-mode ${mode === 'load_balance' ? 'checked' : ''} ${policyWritable ? '' : 'disabled'}><span><strong>负载均衡</strong><small>按权重分配新连接</small></span></label>
    </div></fieldset>
    <div class="global-advanced-subsection"><div class="global-section-heading"><h4>线路顺序</h4><span>${state.wans.length} 条</span></div><div class="global-wan-policy-list global-advanced-line-list">${state.wans.length ? state.wans.map((wan, index) => {
      const role = firstText(wan.role, wan.advanced?.failover ? 'failover' : index === 0 ? 'primary' : 'backup');
      const priority = firstNumber(wan.priority, wan.metric, index + 1);
      const weight = optionalNumber(wan.weight, wan.load_balance_weight);
      return `<article><span>${resourceStatus(wan.connected)}<strong>${escapeHtml(wan.name)}</strong><small>${escapeHtml([wan.id, wan.ifname, wan.physicalIfname].filter((value) => value && value !== '--').join(' · ') || '--')}</small></span><span><b>${escapeHtml(role === 'primary' ? '主线路' : role === 'backup' ? '备用线路' : role === 'failover' ? '故障转移' : role)}</b><small>${mode === 'load_balance' ? `权重 ${weight === null ? '--' : `${weight}%`}` : `优先级 ${priority || '--'}`}</small></span></article>`;
    }).join('') : '<div class="dwrt-kit-table-empty">暂无 WAN 线路</div>'}</div></div>
    ${policyWritable ? '' : advancedAvailabilityNote('当前后端尚未提供 WAN 模式、优先级与权重的事务合同，因此只展示真实线路，不模拟保存。')}`;
  }
  function advancedLineServicesMarkup() {
    return `<div class="global-advanced-fields">
      ${globalField('流量控制', globalSwitch('wan_traffic_control', Boolean(state.globalDraft.wan_traffic_control), strictCap('wan_traffic_control_write')), '按线路限制或整形互联网流量')}
      ${globalField('自动速度测试', globalSwitch('wan_auto_speed_test', Boolean(state.globalDraft.wan_auto_speed_test), strictCap('wan_auto_speed_test_write')), '定期校准线路可用带宽')}
      ${advancedActionRow('Gateway 端口分配', '重新分配物理网口的 WAN 角色', '管理端口')}
      ${advancedActionRow('WAN SLA', '设置延迟、丢包与可用性目标', '新建', strictCap('wan_sla_write'))}
    </div>${advancedAvailabilityNote('Gateway 端口分配为受保护事务，提交前需通过预检并二次确认；WAN SLA 尚未提供完整列表与 CRUD 合同。')}`;
  }
  function advancedNetworkBehaviorMarkup() {
    const g = state.globalDraft;
    return `<div class="global-advanced-fields">
      ${globalField('默认安全策略', globalSelect('default_posture', g.default_posture || 'allow', [['allow','允许全部'],['deny','全部阻止']]), '未命中显式策略时的处理')}
      ${globalField('Gateway mDNS 代理', globalSelect('mdns_proxy', g.mdns_proxy || 'auto', [['auto','自动'],['enabled','自定义'],['disabled','关']], cap('mdns_proxy')), '跨网段发现 Bonjour / mDNS 服务')}
      ${globalField('IGMP 监听', globalSwitch('igmp_snooping', Boolean(g.igmp_snooping), cap('igmp_snooping')), '优化网络内组播转发')}
      ${globalField('流量控制', globalSwitch('flow_control', Boolean(g.flow_control), cap('flow_control')), '使用以太网 PAUSE 帧')}
    </div>`;
  }
  function advancedSwitchingMarkup() {
    const g = state.globalDraft;
    const stpEnabled = g.bridge_stp !== false;
    return `<div class="global-advanced-fields">
      ${globalField('生成树', globalSwitch('bridge_stp', stpEnabled, cap('stp'), 'aria-controls="global-stp-options" aria-expanded="' + (stpEnabled ? 'true' : 'false') + '"'), '防止二层环路')}
      <div id="global-stp-options" class="global-advanced-dependent ${stpEnabled ? 'is-open' : ''}" data-global-dependent="bridge_stp" ${stpEnabled ? '' : 'hidden'}>
        ${globalField('生成树协议', globalSelect('stp_mode', g.stp_mode || 'rstp', [['rstp','RSTP'],['stp','STP'],['disabled','已禁用']], cap('stp_mode')))}
        ${globalField('转发延迟', `<span class="global-number-control"><input type="number" min="1" max="30" data-global-setting="bridge_forward_delay" value="${escapeHtml(g.bridge_forward_delay ?? 2)}" ${cap('stp') ? '' : 'disabled'}><em>秒</em></span>`)}
      </div>
      ${globalField('恶意 DHCP 服务器检测', globalSwitch('rogue_dhcp_detection', Boolean(g.rogue_dhcp_detection), cap('rogue_dhcp_detection')), '发现非授权 DHCP 服务')}
      ${globalField('巨型帧', globalSwitch('jumbo_frames', Boolean(g.jumbo_frames), cap('jumbo_frames')), '使用大于 1500 字节的帧')}
      ${globalField('802.1X 控制', globalSwitch('dot1x', Boolean(g.dot1x), cap('dot1x')), '启用端口级身份认证')}
    </div>`;
  }
  function advancedRadiusMarkup() {
    return `<div class="global-advanced-fields">${radiusListMarkup()}</div>${advancedAvailabilityNote('本页当前支持查看 RADIUS 服务器。凭据以后端 secret_ref 引用形式返回，页面不收集也不展示明文 secret。')}`;
  }

  function radiusListMarkup() {
    if (!state.radiusKnown) return `<div class="global-contract-note">${escapeHtml(firstText(state.radiusError, 'RADIUS 读取失败'))}</div>`;
    if (!state.radius.length) return '<div class="dwrt-kit-table-empty">暂无 RADIUS 服务器</div>';
    return `<div class="global-profile-list global-radius-list">${state.radius.map((server) => {
      const auth = server.authAddr ? `${server.authAddr}${server.authPort ? `:${server.authPort}` : ''}` : '未配置认证地址';
      const acct = server.acctAddr ? `${server.acctAddr}${server.acctPort ? `:${server.acctPort}` : ''}` : '';
      const detail = [auth, acct ? `计费 ${acct}` : '', server.secretRef ? `凭据 ${server.secretRef}` : '未绑定凭据', server.enabled ? '已启用' : '已停用'].filter(Boolean).join(' · ');
      return `<article><strong>${escapeHtml(server.name)}</strong><small>${escapeHtml(detail)}</small></article>`;
    }).join('')}</div>`;
  }
  function advancedProfilesMarkup() {
    return `<div class="global-advanced-fields">${advancedActionRow('端口配置文件', '复用 VLAN、PoE 和链路设置', '新建', strictCap('port_profile_write'))}</div><div class="global-profile-list global-advanced-profile-list">${state.profiles.length ? state.profiles.slice(0, 8).map((profile) => `<article><strong>${escapeHtml(firstText(profile.name, profile.label, profile.id))}</strong><small>${escapeHtml(firstText(profile.description, profile.native_vlan ? `原生 VLAN ${profile.native_vlan}` : '端口配置文件'))}</small></article>`).join('') : '<div class="dwrt-kit-table-empty">暂无端口配置文件</div>'}</div>`;
  }
  function advancedSettingsMarkup() {
    return `<div class="global-advanced-settings">
      <section class="global-advanced-panel dwrt-kit-glass-surface">
        <header class="global-advanced-panel-header"><div><span>${icon('settings')}</span><strong>高级网络设置</strong></div><small data-global-save-state>${globalDirty() ? '存在尚未保存的更改' : '当前配置已同步'}</small></header>
        <div class="global-advanced-modules">
          ${advancedGroup('wan-policy', 'internet', 'WAN 策略', `${state.wans.length} 条线路`, advancedWanPolicyMarkup())}
          ${advancedGroup('line-services', 'route', '线路服务', '流量、测速与 SLA', advancedLineServicesMarkup())}
          ${advancedGroup('network-behavior', 'network', '网络行为', '安全、发现与组播', advancedNetworkBehaviorMarkup())}
          ${advancedGroup('switching', 'ports', '交换与环路保护', 'STP 与端口能力', advancedSwitchingMarkup())}
          ${advancedGroup('authentication', 'shield', '网络认证', 'RADIUS', advancedRadiusMarkup())}
          ${advancedGroup('port-profiles', 'system', '端口配置文件', `${state.profiles.length} 个`, advancedProfilesMarkup())}
        </div>
        <footer class="global-advanced-savebar"><span><strong>全局网络配置</strong><small>${globalDirty() ? '存在尚未保存的更改' : '当前配置已同步'}</small></span><div><button class="policy-secondary" type="button" data-global-settings-reset ${globalDirty() && !state.saving ? '' : 'disabled'}>复位</button><button class="policy-primary" type="button" data-global-save ${globalDirty() && !state.saving ? '' : 'disabled'}>${state.saving ? '正在应用' : '保存并应用'}</button></div></footer>
      </section>
      ${state.globalNotice ? `<div class="global-notice ${/失败|错误/.test(state.globalNotice) ? 'is-error' : ''}" role="status">${escapeHtml(state.globalNotice)}</div>` : ''}
    </div>`;
  }
  function renderGlobalDrawer() {
    if (state.drawer !== 'global') return '';
    const networkTab = state.globalTab === 'network';
    return `${backdrop('关闭全局设置')}<aside class="global-drawer global-settings-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open"><header class="dwrt-kit-sheet-header"><div><span>GLOBAL NETWORK</span><strong>全局网络设置</strong></div><button class="dwrt-kit-sheet-close" type="button" data-global-close aria-label="关闭">×</button></header><nav class="global-settings-tabs dwrt-kit-tabs" role="tablist"><button type="button" role="tab" data-global-settings-tab="internet" data-value="internet" class="dwrt-kit-tab ${networkTab ? '' : 'is-active'}" aria-selected="${networkTab ? 'false' : 'true'}">互联网</button><button type="button" role="tab" data-global-settings-tab="network" data-value="network" class="dwrt-kit-tab ${networkTab ? 'is-active' : ''}" aria-selected="${networkTab ? 'true' : 'false'}">网络</button></nav><div class="dwrt-kit-sheet-body global-drawer-body">${networkTab ? networkSettingsMarkup() : internetSettingsMarkup()}${state.globalNotice?`<div class="global-notice ${/失败|错误/.test(state.globalNotice)?'is-error':''}">${escapeHtml(state.globalNotice)}</div>`:''}</div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-global-close>${networkTab ? '取消' : '关闭'}</button>${networkTab ? `<button class="policy-primary" type="button" data-global-save ${globalDirty()&&!state.saving?'':'disabled'}>${state.saving?'正在应用':'保存并应用'}</button>` : ''}</footer></aside>`;
  }
  function selectedPort() { return state.ports.find((port)=>port.id===state.selectedId) || null; }
  function portCapabilities(port) { return { ...state.capabilities, ...(port?.capabilities || {}) }; }
  function initPortDraft(port) {
    const configuredSpeed = firstNumber(port.config.configured_speed_mbps);
    const configuredDuplex = firstText(port.config.configured_duplex, port.duplex);
    const configuredAutoneg = port.config.autoneg_configured ?? (Number(port.config.configured_autoneg) >= 0 ? Boolean(Number(port.config.configured_autoneg)) : port.autoneg !== false);
    const draft = { speed: configuredSpeed || 0, duplex: configuredDuplex || 'full', autoneg: configuredAutoneg !== false, enabled: port.ownerEnabled };
    state.portInitial = clone(draft); state.portDraft = clone(draft); state.portPreview = null; state.notice = '';
  }
  function portDirty() { return JSON.stringify(state.portDraft) !== JSON.stringify(state.portInitial); }
  function portPayload(port, confirm = false) {
    const payload = { ifname: port.ifname, confirm };
    if (state.portDraft.speed !== state.portInitial.speed) {
      if (Number(state.portDraft.speed) > 0) payload.speed_mbps = Number(state.portDraft.speed);
      else payload.autoneg = true;
    }
    if (state.portDraft.duplex !== state.portInitial.duplex && Number(state.portDraft.speed) > 0) payload.duplex = state.portDraft.duplex;
    if (state.portDraft.autoneg !== state.portInitial.autoneg) payload.autoneg = Boolean(state.portDraft.autoneg);
    if (state.portInitial.enabled !== null && state.portDraft.enabled !== state.portInitial.enabled) payload.enabled = Boolean(state.portDraft.enabled);
    return payload;
  }
  function detailValue(label, value) { return `<span><small>${escapeHtml(label)}</small><strong>${escapeHtml(firstText(value,'--'))}</strong></span>`; }
  function renderPortDrawer() {
    if (state.drawer !== 'port') return '';
    const port = selectedPort(); if (!port) return '';
    const caps = portCapabilities(port);
    const speedOptions = [...new Set([0,...port.supportedSpeeds,port.speedMbps].filter((value,index)=>index===0||value>0))].sort((a,b)=>a-b);
    const canEdit = caps.write === true && (caps.speed_config === true || caps.duplex_config === true || caps.autoneg_config === true || caps.port_enable === true);
    const preview = state.portPreview?.plan || state.portPreview?.preview || state.portPreview;
    return `${backdrop('关闭端口详情')}<aside class="global-drawer global-port-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open"><header class="dwrt-kit-sheet-header"><div><span>PORT DETAILS</span><strong>${escapeHtml(port.name)}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-global-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body global-drawer-body"><section class="global-port-summary"><div class="global-port-summary-icon is-${port.kind} ${port.connected?'is-up':''}">${icon('ports')}</div><div><strong>${escapeHtml(port.ifname)}</strong><span>${escapeHtml(port.networkName)} · ${port.connected?'已连接':'未连接'}</span></div></section><div class="global-detail-grid">${detailValue('链路速度',port.speedLabel)}${detailValue('双工',port.duplex)}${detailValue('连接设备',port.connection)}${detailValue('MAC',port.mac)}${detailValue('IP',port.ip)}${detailValue('配置文件',port.profileName)}${detailValue('原生 VLAN',port.vlan||'Default')}${detailValue('PoE',port.poeCapable?(port.poeEnabled?'开启':'关闭'):'无')}</div>${port.neighbors.length?`<section class="global-neighbor-list"><h3>已连接设备</h3>${port.neighbors.map((item)=>`<article><span><strong>${escapeHtml(firstText(item.name,item.hostname,item.mac,'未知设备'))}</strong><small>${escapeHtml([firstText(item.ip,item.ipv4),firstText(item.mac)].filter(Boolean).join(' · ')||'--')}</small></span><em>${escapeHtml(firstText(item.relationship_source,item.type,'运行态发现'))}</em></article>`).join('')}</section>`:''}<section class="global-port-config"><h3>端口配置</h3><label><span>链路速度</span><select data-dwrt-component="select" data-port-draft="speed" ${caps.speed_config===true?'':'disabled'}>${speedOptions.map((speed)=>`<option value="${speed}" ${Number(state.portDraft.speed)===speed?'selected':''}>${speed?`${speed>=1000?speed/1000+' G':speed+' M'}bps`:'自动协商'}</option>`).join('')}</select></label><label><span>双工模式</span><select data-dwrt-component="select" data-port-draft="duplex" ${caps.duplex_config===true?'':'disabled'}>${[...new Set(['full','half',...port.supportedDuplex])].map((value)=>`<option value="${escapeHtml(value)}" ${state.portDraft.duplex===value?'selected':''}>${value==='full'?'全双工':value==='half'?'半双工':escapeHtml(value)}</option>`).join('')}</select></label><label class="is-switch"><span><strong>自动协商</strong><small>由端口与对端协商速度和双工</small></span>${globalSwitch('port-autoneg',Boolean(state.portDraft.autoneg),caps.autoneg_config===true)}</label>${state.portInitial.enabled!==null?`<label class="is-switch is-risk"><span><strong>所属${port.kind==='wan'?'线路':'网络'}启用</strong><small>关闭会中断该网络上的连接</small></span>${globalSwitch('port-enabled',Boolean(state.portDraft.enabled),caps.port_enable===true)}</label>`:''}</section>${preview?`<section class="global-port-preview"><strong>${preview.can_apply===false?'后端拒绝该变更':'预览已通过'}</strong><span>${escapeHtml(asArray(preview.warnings).join(' · ')||firstText(preview.operation,'配置可应用'))}</span></section>`:''}${state.notice?`<div class="global-notice ${/失败|拒绝|不支持/.test(state.notice)?'is-error':''}">${escapeHtml(state.notice)}</div>`:''}</div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-global-close>关闭</button>${canEdit?state.portPreview&&preview?.can_apply!==false?`<button class="policy-primary" type="button" data-port-apply ${state.saving?'disabled':''}>${state.saving?'正在应用':'确认应用'}</button>`:`<button class="policy-primary" type="button" data-port-preview ${portDirty()&&!state.saving?'':'disabled'}>${state.saving?'正在预览':'预览更改'}</button>`:''}</footer></aside>`;
  }
  function renderBulkDrawer() {
    if (state.drawer !== 'bulk') return '';
    const ports = state.ports.filter((port) => state.selectedPorts.has(port.id));
    const canEdit = ports.length && ports.every((port) => portCapabilities(port).write === true);
    return `${backdrop('关闭批量配置')}<aside class="global-drawer global-port-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open"><header class="dwrt-kit-sheet-header"><div><span>BULK PORT CONFIG</span><strong>批量配置 ${ports.length} 个端口</strong></div><button class="dwrt-kit-sheet-close" type="button" data-global-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body global-drawer-body"><section class="global-bulk-ports">${ports.map((port) => `<span><i class="${port.connected?'is-up':''}"></i>${escapeHtml(port.name)}<small>${escapeHtml(port.ifname)}</small></span>`).join('')}</section><section class="global-port-config"><h3>共同配置</h3><label><span>链路速度</span><select data-dwrt-component="select" data-bulk-field="speed" ${canEdit?'':'disabled'}><option value="0">自动协商</option><option value="100">100 Mbps</option><option value="1000">1 Gbps</option><option value="2500">2.5 Gbps</option><option value="10000">10 Gbps</option></select></label><label><span>双工模式</span><select data-dwrt-component="select" data-bulk-field="duplex" ${canEdit?'':'disabled'}><option value="full">全双工</option><option value="half">半双工</option></select></label><label class="is-switch"><span><strong>自动协商</strong><small>应用到全部选中端口</small></span>${globalSwitch('bulk-autoneg',Boolean(state.bulkDraft.autoneg),Boolean(canEdit))}</label></section>${state.bulkPreview ? `<section class="global-port-preview"><strong>${state.bulkPreview.failed ? `${state.bulkPreview.failed} 个端口预览失败` : '全部预览已通过'}</strong><span>${state.bulkPreview.ok || 0}/${ports.length} 个端口可应用</span></section>` : ''}${state.notice ? `<div class="global-notice ${/失败|拒绝/.test(state.notice)?'is-error':''}">${escapeHtml(state.notice)}</div>` : ''}</div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-global-close>关闭</button>${state.bulkPreview && !state.bulkPreview.failed ? `<button class="policy-primary" type="button" data-bulk-apply ${state.saving?'disabled':''}>${state.saving?'正在应用':'确认应用'}</button>` : `<button class="policy-primary" type="button" data-bulk-preview ${canEdit&&!state.saving?'':'disabled'}>${state.saving?'正在预览':'预览更改'}</button>`}</footer></aside>`;
  }
  function backdrop(label) { return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-global-close aria-label="${escapeHtml(label)}"></button>`; }
  function renderDrawers() { return `${renderFilterDrawer()}${renderColumnsDrawer()}${renderGlobalDrawer()}${renderPortDrawer()}${renderBulkDrawer()}`; }
  function interfaceHost(kind, mode) {
    const key = `${kind}-${mode}`;
    return `<section class="global-interface-section is-${kind} is-${mode}"><div data-global-interface-host="${key}"></div></section>`;
  }
  function mountInterfaceWorkbenches() {
    root.querySelectorAll('[data-global-interface-host]').forEach((host) => {
      const key = host.dataset.globalInterfaceHost;
      if (interfaceInstances.has(key)) return;
      const [kind, mode] = key.split('-');
      if (!host) return null;
      const instance = mountNetworkInterfaceConfig({
        ...context, root: host, embedded: true, query: state.query, showHeading: false,
        showToolbar: false, showOverview: mode === 'overview', showTable: mode === 'table', showDrawers: mode === 'table',
        item: { id: `${kind}-config`, func_name: `${kind}_config`, path: `/app/#/network/${kind}-config` },
        deferLoad: true,
        initialDataReady: !state.loading,
        initialData: { config: interfacePayloads[kind], ports: interfacePayloads.ports },
        /* LAN 实例只加载 LAN 数据，拿不到 WAN 名单；宿主同时持有两边，喂给它做
           IPv6 上游 WAN 下拉的候选。 */
        wanNames: state.wans.map((wan) => firstText(wan.id, wan.name)).filter(Boolean),
        onDataChange(payload) {
          if (payload.kind === 'lan') state.lans = payload.rows.map(normalizeLan);
          if (payload.kind === 'wan') state.wans = normalizeWans(payload.rows);
        },
        onCommitted() { load(true); }
      });
      interfaceInstances.set(key, instance);
    });
    interfaceInstances.forEach((instance, key) => {
      if (!root.querySelector(`[data-global-interface-host="${key}"]`)) {
        instance?.unmount?.();
        interfaceInstances.delete(key);
      }
    });
  }
  function renderTabContent() {
    if (state.pageTab === 'global') return `<div class="global-overview-stack">${interfaceHost('lan', 'overview')}${interfaceHost('wan', 'overview')}</div>${renderGatewayPorts()}${renderTable()}`;
    if (state.pageTab === 'wan') return interfaceHost('wan', 'table');
    if (state.pageTab === 'lan') return interfaceHost('lan', 'table');
    return advancedSettingsMarkup();
  }
  function render() {
    if (!root) return;
    const drawerScroll = root.querySelector('.global-drawer .dwrt-kit-sheet-body')?.scrollTop || 0;
    const drawerMode = state.drawer;
    const preservedHosts = new Map();
    root.querySelectorAll('[data-global-interface-host]').forEach((host) => preservedHosts.set(host.dataset.globalInterfaceHost, host));
    root.hidden = false;
    root.className = root.className.split(/\s+/).filter((name)=>name&&!['policy-table-route-host','routing-table-route-host',MODULE_CLASS].includes(name)).join(' ');
    root.classList.add('route-workspace', MODULE_CLASS);
    root.innerHTML = `<section class="global-config-shell">${renderPageHeader()}<main class="global-config-workbench is-${state.pageTab}">${renderTabContent()}</main>${renderDrawers()}</section>`;
    preservedHosts.forEach((host, kind) => root.querySelector(`[data-global-interface-host="${kind}"]`)?.replaceWith(host));
    bindEvents(); ui.mountAll?.(root); ui.scheduleGlassCardsRender?.(180);
    mountInterfaceWorkbenches();
    const nextDrawer = root.querySelector('.global-drawer .dwrt-kit-sheet-body');
    if (nextDrawer && drawerMode === state.drawer) nextDrawer.scrollTop = drawerScroll;
  }
  function patchMain() {
    if (!root?.querySelector('.global-config-shell') || state.drawer) { render(); return; }
    if (state.pageTab !== 'global') { render(); return; }
    const gateway = root.querySelector('[data-global-gateway]');
    const gatewayScroll = gateway?.querySelector('.gateway-ports-body');
    const gatewayTop = gatewayScroll?.scrollTop || 0;
    if (gateway) {
      const template = document.createElement('template');
      template.innerHTML = renderGatewayPorts();
      const freshGateway = template.content.firstElementChild;
      if (freshGateway) {
        gateway.replaceWith(freshGateway);
        ui.mountAll?.(freshGateway);
      }
    }
    const nextGatewayScroll = root.querySelector('[data-global-gateway] .gateway-ports-body');
    if (nextGatewayScroll) nextGatewayScroll.scrollTop = gatewayTop;
    const table = root.querySelector('[data-global-table]');
    const scroll = table?.querySelector('[data-global-scroll]');
    const top = scroll?.scrollTop || 0; const left = scroll?.scrollLeft || 0;
    if (table) {
      const template = document.createElement('template');
      template.innerHTML = renderTable();
      const fresh = template.content.firstElementChild;
      const oldToolbar = table.querySelector(':scope > .dwrt-kit-table-toolbar');
      const oldTable = table.querySelector('.global-port-table');
      const freshToolbar = fresh?.querySelector(':scope > .dwrt-kit-table-toolbar');
      const freshTable = fresh?.querySelector('.global-port-table');
      if (oldToolbar && freshToolbar) oldToolbar.replaceWith(freshToolbar);
      if (oldTable && freshTable) oldTable.replaceWith(freshTable);
    }
    const next = root.querySelector('[data-global-scroll]'); if (next) { next.scrollTop=top; next.scrollLeft=left; }
    const statistics = root.querySelector('[data-global-statistics]');
    statistics?.classList.toggle('is-active', state.statistics);
    bindMainEvents();
  }
  function openPort(id) { const port=state.ports.find((item)=>item.id===id); if(!port)return; state.selectedId=id; initPortDraft(port); state.drawer='port'; render(); }
  function closeDrawer() { state.drawer=''; state.selectedId=''; state.notice=''; state.globalNotice=''; state.saving=false; state.portPreview=null; render(); }
  function openGlobalSettings() { state.globalDraft=clone(state.global); state.globalNotice=''; state.globalTab='internet'; state.drawer='global'; render(); }
  function refreshGlobalSaveButton() {
    const button = root?.querySelector('[data-global-save]');
    if (button) button.disabled = !globalDirty() || state.saving;
    root?.querySelectorAll('[data-global-save-state], .global-advanced-savebar small').forEach((label) => {
      label.textContent = globalDirty() ? '存在尚未保存的更改' : '当前配置已同步';
    });
  }
  function refreshPortPreviewButton() {
    const preview = root?.querySelector('[data-port-preview]');
    if (preview) preview.disabled = !portDirty() || state.saving;
  }
  async function saveGlobal() {
    if (!globalDirty() || state.saving) return;
    state.saving=true; state.globalNotice=''; render();
    try { await requestJson(ENDPOINTS.global,{method:'POST',body:JSON.stringify(state.globalDraft)}); await requestJson(`${ENDPOINTS.global}/apply`,{method:'POST',body:'{}'}); state.global=clone(state.globalDraft); state.saving=false; state.globalNotice='已保存并应用'; await load(true); }
    catch(error){state.saving=false;state.globalNotice=`保存失败：${firstText(error.message,'unknown')}`;render();}
  }
  async function previewPort() {
    const port=selectedPort(); if(!port||!portDirty()||state.saving)return;
    state.saving=true;state.notice='';render();
    try{state.portPreview=await requestJson(ENDPOINTS.preview,{method:'POST',body:JSON.stringify(portPayload(port,false))});state.saving=false;render();}
    catch(error){state.saving=false;state.notice=`预览失败：${firstText(error.message,'unknown')}`;render();}
  }
  async function applyPort() {
    const port=selectedPort(); if(!port||!state.portPreview||state.saving)return;
    state.saving=true;state.notice='';render();
    try{const result=await requestJson(ENDPOINTS.apply,{method:'POST',body:JSON.stringify(portPayload(port,true))});state.saving=false;state.notice=result.applied===false?'后端未执行运行态变更':'端口配置已应用';state.portPreview=null;await load(true);state.selectedId=port.id;const fresh=selectedPort();if(fresh)initPortDraft(fresh);state.drawer='port';render();}
    catch(error){state.saving=false;state.notice=`应用失败：${firstText(error.message,'unknown')}`;render();}
  }
  async function savePreferences() {
    try {
      const visible = [...state.visibleColumns].filter((key) => PREFERENCE_KEYS.has(key));
      const sortKey = PREFERENCE_KEYS.has(state.sortKey) ? state.sortKey : 'port';
      await requestJson(ENDPOINTS.preferences, { method: 'PUT', body: JSON.stringify({ view: 'network.global.ports', visible_columns: visible, sort_key: sortKey, sort_direction: state.sortDirection }) });
    } catch (_) {}
  }
  function bulkPortPayload(port, confirm = false) {
    return { ifname: port.ifname, speed_mbps: Number(state.bulkDraft.speed) || 0, duplex: state.bulkDraft.duplex, autoneg: Boolean(state.bulkDraft.autoneg), confirm };
  }
  async function previewBulk() {
    const ports = state.ports.filter((port) => state.selectedPorts.has(port.id));
    if (!ports.length || state.saving) return;
    state.saving = true; state.notice = ''; render();
    const results = await Promise.allSettled(ports.map((port) => requestJson(ENDPOINTS.preview, { method: 'POST', body: JSON.stringify(bulkPortPayload(port, false)) })));
    state.saving = false;
    state.bulkPreview = { ok: results.filter((result) => result.status === 'fulfilled' && (result.value?.plan?.can_apply ?? result.value?.can_apply) !== false).length, failed: results.filter((result) => result.status === 'rejected' || (result.value?.plan?.can_apply ?? result.value?.can_apply) === false).length, results };
    render();
  }
  async function applyBulk() {
    const ports = state.ports.filter((port) => state.selectedPorts.has(port.id));
    if (!ports.length || !state.bulkPreview || state.bulkPreview.failed || state.saving) return;
    state.saving = true; state.notice = ''; render();
    const results = await Promise.allSettled(ports.map((port) => requestJson(ENDPOINTS.apply, { method: 'POST', body: JSON.stringify(bulkPortPayload(port, true)) })));
    const failed = results.filter((result) => result.status === 'rejected' || result.value?.applied === false).length;
    state.saving = false; state.bulkPreview = null;
    if (failed) { state.notice = `${failed} 个端口应用失败`; render(); return; }
    state.selectedPorts.clear(); state.drawer = ''; await load(true);
  }
  function setGatewayAssignment(portId, wanId) {
    const next = { ...state.gatewayDraft };
    const currentWan = assignedWan(portId, next);
    if (currentWan) delete next[currentWan];
    if (wanId) {
      const previousPort = next[wanId];
      Object.keys(next).forEach((id) => { if (id !== wanId && next[id] === portId) delete next[id]; });
      next[wanId] = portId;
      if (previousPort && previousPort !== portId) {
        const displacedWan = assignedWan(previousPort, state.gatewayDraft);
        if (displacedWan && displacedWan !== wanId) next[displacedWan] = previousPort;
      }
    }
    state.gatewayDraft = next;
    state.gatewayPreview = null;
    state.gatewayNotice = '';
    render();
  }
  async function previewGatewayAssignments() {
    const steps = gatewayMigrationSteps();
    if (!gatewayDirty() || !steps.length || state.saving) return;
    const primary = gatewayWans()[0]?.id || '';
    if (primary && !state.gatewayDraft[primary]) {
      state.gatewayPreview = null;
      state.gatewayNotice = `${wanAssignmentLabel(primary)} 是主互联网来源，必须先为它分配一个 Gateway 端口。`;
      render();
      return;
    }
    state.saving = true; state.gatewayNotice = ''; state.gatewayPreview = null; render();
    const results = await Promise.allSettled(steps.map((step) => requestJson(ENDPOINTS.preview, { method: 'POST', body: JSON.stringify({ ifname: step.ifname, target_owner_type: step.target_owner_type, target_owner_id: step.target_owner_id }) })));
    const ok = results.filter((result) => result.status === 'fulfilled').length;
    state.saving = false;
    state.gatewayPreview = { total: steps.length, ok, failed: results.length - ok, results };
    if (strictCap('gateway_port_assignment_atomic_apply')) {
      if (state.gatewayPreview.failed) state.gatewayNotice = `预检完成：${state.gatewayPreview.failed}/${state.gatewayPreview.total} 个迁移步骤未通过，暂不能应用。`;
      else if (strictCap('gateway_port_assignment_requires_confirm')) state.gatewayNotice = '预检全部通过；再次点击确认应用即提交原子事务，管理可达性异常时后端会自动回滚。';
    } else if (!state.capabilitiesKnown) {
      state.gatewayNotice = `预检已完成；${firstText(state.capabilitiesError, '端口写入能力未知')}，无法确认能否应用。`;
    } else {
      state.gatewayNotice = '预检已完成；当前设备报告不支持 Gateway 端口分配的原子应用。';
    }
    render();
  }
  async function applyGatewayAssignments() {
    if (!state.gatewayPreview || state.gatewayPreview.failed || !strictCap('gateway_port_assignment_atomic_apply') || state.saving) return;
    state.saving = true; state.gatewayNotice = ''; render();
    try {
      const result = await requestJson(ENDPOINTS.gatewayApply, { method: 'POST', body: JSON.stringify({ assignments: state.gatewayDraft, migrations: gatewayMigrationSteps(), confirm: true }) });
      state.saving = false;
      if (result.applied !== true) throw new Error(firstText(result.reason, '后端未确认应用'));
      state.gatewayNotice = 'Gateway 端口分配已应用';
      state.gatewayPreview = null;
      await load(true);
    } catch (error) {
      state.saving = false;
      state.gatewayNotice = `应用失败：${firstText(error.message, 'unknown')}`;
      render();
    }
  }
  function bindTableEvents() {
    root.querySelectorAll('[data-global-port]').forEach((button)=>button.addEventListener('click',()=>openPort(button.dataset.globalPort)));
    root.querySelectorAll('[data-global-sort]').forEach((button)=>button.addEventListener('click',()=>{const key=button.dataset.globalSort;if(!key||key==='actions')return;if(state.sortKey===key)state.sortDirection=state.sortDirection==='asc'?'desc':'asc';else{state.sortKey=key;state.sortDirection='asc';}patchMain();}));
    root.querySelectorAll('[data-global-port-select]').forEach((input)=>input.addEventListener('change',()=>{if(input.checked)state.selectedPorts.add(input.dataset.globalPortSelect);else state.selectedPorts.delete(input.dataset.globalPortSelect);patchMain();}));
    root.querySelectorAll('[data-global-select-all]').forEach((input)=>input.addEventListener('change',()=>{filteredPorts().forEach((port)=>{if(input.checked)state.selectedPorts.add(port.id);else state.selectedPorts.delete(port.id);});patchMain();}));
    root.querySelectorAll('[data-global-bulk]').forEach((button)=>button.addEventListener('click',()=>{state.bulkDraft=clone(state.bulkInitial);state.bulkPreview=null;state.notice='';state.drawer='bulk';render();}));
  }
  function bindMainEvents() {
    bindTableEvents();
    root.querySelectorAll('[data-global-settings]').forEach((button)=>{button.onclick=openGlobalSettings;});
  }
  function bindEvents() {
    bindMainEvents();
    root.querySelectorAll('[data-global-page-tab]').forEach((button) => button.addEventListener('click', () => {
      const next = button.dataset.globalPageTab;
      if (!PAGE_TABS.some(([id]) => id === next) || next === state.pageTab) return;
      state.pageTab = next;
      state.drawer = '';
      state.query = '';
      if (next === 'advanced') state.globalDraft = clone(state.global);
      render();
    }));
    root.querySelectorAll('[data-global-interface-search]').forEach((input) => input.addEventListener('input', () => {
      state.query = input.value;
      interfaceInstances.get(`${input.dataset.globalInterfaceSearch}-table`)?.setQuery?.(state.query);
    }));
    root.querySelectorAll('[data-global-interface-create]').forEach((button) => button.addEventListener('click', () => interfaceInstances.get(`${button.dataset.globalInterfaceCreate}-table`)?.openCreate?.()));
    root.querySelectorAll('[data-gateway-assignment]').forEach((select) => select.addEventListener('change', () => setGatewayAssignment(select.dataset.gatewayAssignment, select.value)));
    root.querySelectorAll('[data-gateway-port]').forEach((button) => button.addEventListener('click', () => {
      const select = root.querySelector(`[data-gateway-assignment="${CSS.escape(button.dataset.gatewayPort)}"]`);
      select?.focus({ preventScroll: true });
    }));
    root.querySelectorAll('[data-gateway-reset]').forEach((button) => button.addEventListener('click', () => { state.gatewayDraft = clone(state.gatewayInitial); state.gatewayPreview = null; state.gatewayNotice = ''; render(); }));
    root.querySelectorAll('[data-gateway-preview]').forEach((button) => button.addEventListener('click', previewGatewayAssignments));
    root.querySelectorAll('[data-gateway-apply]').forEach((button) => button.addEventListener('click', applyGatewayAssignments));
    root.querySelectorAll('[data-global-filter]').forEach((button)=>button.addEventListener('click',()=>{state.drawer='filter';render();}));
    root.querySelectorAll('[data-global-columns]').forEach((button)=>button.addEventListener('click',()=>{state.drawer='columns';render();}));
    root.querySelectorAll('[data-global-close]').forEach((button)=>button.addEventListener('click',closeDrawer));
    root.querySelectorAll('[data-global-statistics]').forEach((button)=>button.addEventListener('click',()=>{state.statistics=!state.statistics;patchMain();}));
    root.querySelectorAll('[data-global-clear-filter]').forEach((button)=>button.addEventListener('click',()=>{state.status=state.kind=state.speed=state.poe=state.vlan='all';state.anomalyMin=0;state.anomalyMax=100;render();}));
    ['status','kind','speed','poe','vlan'].forEach((key)=>root.querySelectorAll(`input[name="global-${key}"]`).forEach((input)=>input.addEventListener('change',()=>{state[key]=input.value;render();})));
    root.querySelectorAll('[data-global-anomaly]').forEach((input)=>input.addEventListener('input',()=>{const key=input.dataset.globalAnomaly==='min'?'anomalyMin':'anomalyMax';state[key]=Number(input.value);if(state.anomalyMin>state.anomalyMax){if(key==='anomalyMin')state.anomalyMax=state.anomalyMin;else state.anomalyMin=state.anomalyMax;}render();}));
    root.querySelectorAll('[data-global-column]').forEach((input)=>input.addEventListener('change',()=>{if(input.checked)state.visibleColumns.add(input.dataset.globalColumn);else state.visibleColumns.delete(input.dataset.globalColumn);render();}));
    root.querySelectorAll('[data-global-columns-reset]').forEach((button)=>button.addEventListener('click',()=>{state.visibleColumns=new Set(DEFAULT_COLUMNS);render();}));
    root.querySelectorAll('[data-global-columns-done]').forEach((button)=>button.addEventListener('click',async()=>{await savePreferences();closeDrawer();}));
    root.querySelectorAll('[data-global-search]').forEach((input)=>input.addEventListener('input',()=>{window.clearTimeout(searchTimer);const value=input.value;searchTimer=window.setTimeout(()=>{state.query=value;interfaceInstances.forEach((instance)=>instance.setQuery?.(value));patchMain();},100);}));
    root.querySelectorAll('[data-global-settings-tab]').forEach((button)=>button.addEventListener('click',()=>{
      const next = button.dataset.globalSettingsTab;
      if (!['internet','network'].includes(next) || next === state.globalTab) return;
      state.globalTab = next;
      state.globalNotice = '';
      render();
    }));
    root.querySelectorAll('[data-global-advanced-toggle]').forEach((button)=>button.addEventListener('click',()=>{
      const id = button.dataset.globalAdvancedToggle;
      const open = !state.advancedOpen.has(id);
      state.advancedOpen = open ? new Set([id]) : new Set();
      root.querySelectorAll('[data-global-advanced-group]').forEach((group) => {
        const active = open && group.dataset.globalAdvancedGroup === id;
        const trigger = group.querySelector('[data-global-advanced-toggle]');
        const panel = group.querySelector('.global-advanced-module-body');
        group.classList.toggle('is-open', active);
        trigger?.setAttribute('aria-expanded', String(active));
        if (panel) panel.hidden = !active;
      });
    }));
    root.querySelectorAll('[data-global-wan-mode]').forEach((input)=>input.addEventListener('change',()=>{
      state.globalDraft.wan_mode = input.value;
      state.globalNotice = '';
      refreshGlobalSaveButton();
    }));
    root.querySelectorAll('[data-global-setting]').forEach((input)=>input.addEventListener('change',()=>{const key=input.dataset.globalSetting;if(key==='port-autoneg'){state.portDraft.autoneg=input.checked;state.portPreview=null;refreshPortPreviewButton();}else if(key==='port-enabled'){state.portDraft.enabled=input.checked;state.portPreview=null;refreshPortPreviewButton();}else if(key==='bulk-autoneg'){state.bulkDraft.autoneg=input.checked;state.bulkPreview=null;}else{state.globalDraft[key]=input.type==='checkbox'?input.checked:input.type==='number'?Number(input.value):input.value;state.globalNotice='';if(key==='bridge_stp'&&state.pageTab==='advanced'){const dependent=root.querySelector('[data-global-dependent="bridge_stp"]');if(dependent){dependent.hidden=!input.checked;dependent.classList.toggle('is-open',input.checked);}input.setAttribute('aria-expanded',String(input.checked));}refreshGlobalSaveButton();}}));
    root.querySelectorAll('[data-port-draft]').forEach((input)=>input.addEventListener('change',()=>{state.portDraft[input.dataset.portDraft]=input.dataset.portDraft==='speed'?Number(input.value):input.value;state.portPreview=null;refreshPortPreviewButton();}));
    root.querySelectorAll('[data-bulk-field]').forEach((input)=>input.addEventListener('change',()=>{state.bulkDraft[input.dataset.bulkField]=input.dataset.bulkField==='speed'?Number(input.value):input.value;state.bulkPreview=null;}));
    root.querySelectorAll('[data-bulk-preview]').forEach((button)=>button.addEventListener('click',previewBulk));
    root.querySelectorAll('[data-bulk-apply]').forEach((button)=>button.addEventListener('click',applyBulk));
    root.querySelectorAll('[data-global-save]').forEach((button)=>button.addEventListener('click',saveGlobal));
    root.querySelectorAll('[data-global-settings-reset]').forEach((button)=>button.addEventListener('click',()=>{state.globalDraft=clone(state.global);state.globalNotice='';render();}));
    root.querySelectorAll('[data-port-preview]').forEach((button)=>button.addEventListener('click',previewPort));
    root.querySelectorAll('[data-port-apply]').forEach((button)=>button.addEventListener('click',applyPort));
  }

  render();
  load();
  state.statsTimer = window.setInterval(refreshPortStatistics, 2000);
  /*
   * 手动刷新按钮（Gateway 端口卡片、内嵌 LAN/WAN 工具栏）按用户第 9 条删除。
   * 已有的 statsTimer 只补端口速率，配置本体不动，所以再加一条慢轮询；
   * 有草稿、抽屉、批量选择或正在保存时跳过，避免刷掉用户填的内容。
   */
  state.pollTimer = window.setInterval(() => {
    if (!state.mounted || document.hidden) return;
    if (state.loading || state.refreshing || state.saving) return;
    if (state.drawer || state.selectedPorts.size) return;
    load(true);
  }, 20000);
  return { unmount(){state.mounted=false;state.seq+=1;window.clearTimeout(searchTimer);window.clearInterval(state.statsTimer);window.clearInterval(state.pollTimer);interfaceInstances.forEach((instance)=>instance.unmount?.());interfaceInstances.clear();root?.replaceChildren();root?.classList.remove(MODULE_CLASS,'route-workspace');} };
}

export default { mount };
