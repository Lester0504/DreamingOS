export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const item = context.item || {};
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));
  const VERSION = '20260802-ui-batch-01';
  const kind = /(?:^|[-_/])wan(?:$|[-_/])/.test(`${item.id || ''} ${item.func_name || ''} ${item.path || ''}`) ? 'wan' : 'lan';
  const isWan = kind === 'wan';
  const embedded = context.embedded === true;
  const showToolbar = context.showToolbar !== false;
  const showHeading = context.showHeading !== false;
  const showOverview = context.showOverview !== false;
  const showTable = context.showTable !== false;
  const showDrawers = context.showDrawers !== false;
  const ENDPOINT = `/api/v1/network/${isWan ? 'wans' : 'lans'}`;
  const state = {
    mounted: true,
    loading: true,
    refreshing: false,
    saving: false,
    rows: [],
    ports: [],
    capabilities: {},
    query: firstText(context.query),
    selectedId: '',
    drawer: '',
    draft: {},
    initial: {},
    notice: '',
    noticeTone: '',
    fieldErrors: {},
    seq: 0,
    returnFocus: null,
    editorOpen: isWan ? 'identity' : 'identity',
    pollTimer: 0
  };

  /*
   * 手动刷新按钮按用户第 9 条删除。这里只在独立路由下自轮询：内嵌进全局配置时
   * 数据由宿主页喂进来（deferLoad + setData），再自己拉一遍就会打断宿主的节奏。
   * 抽屉打开、正在保存或用户输入了筛选词时跳过。
   */
  function startPolling() {
    if (context.embedded || context.deferLoad === true) return;
    stopPolling();
    state.pollTimer = window.setInterval(() => {
      if (!state.mounted) return;
      if (document.hidden) return;
      if (state.loading || state.refreshing || state.saving) return;
      if (state.drawer) return;
      load(true);
    }, 15000);
  }

  function stopPolling() {
    if (!state.pollTimer) return;
    window.clearInterval(state.pollTimer);
    state.pollTimer = 0;
  }

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (Array.isArray(value)) {
        const text = value.map((entry) => firstText(entry)).filter(Boolean).join(', ');
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
      if (value === '' || value === null || value === undefined) continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return 0;
  }

  function asArray(value, keys = []) {
    if (Array.isArray(value)) return value;
    for (const key of keys) if (Array.isArray(value?.[key])) return value[key];
    return [];
  }

  function clone(value) {
    try { return structuredClone(value); }
    catch (_) { return JSON.parse(JSON.stringify(value || {})); }
  }

  function parseJsonValue(value, fallback) {
    if (value === undefined || value === null || value === '') return clone(fallback);
    if (typeof value !== 'string') return value;
    let current = value;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const parsed = JSON.parse(current);
        if (typeof parsed === 'string') current = parsed;
        else return parsed;
      } catch (_) { break; }
    }
    return clone(fallback);
  }

  function booleanValue(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') return !['0', 'false', 'off', 'no', 'disabled', 'down'].includes(value.toLowerCase());
    return Boolean(value);
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
      ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); }
      catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    const payload = json?.data ?? json;
    if (!response.ok || json?.ok === false || payload?.ok === false) {
      const error = new Error(firstText(payload?.message, payload?.error, json?.message, json?.error, `HTTP ${response.status}`));
      error.details = payload?.errors || json?.errors || [];
      throw error;
    }
    return payload || {};
  }

  async function fetchResource(name, url) {
    if (typeof api.fetch === 'function') {
      const result = await api.fetch(name, `${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`);
      if (result?.ok === false) throw result.error || new Error(`${name} unavailable`);
      return result?.data?.data ?? result?.data ?? result?.raw?.data ?? result?.raw ?? {};
    }
    return requestJson(url);
  }

  function icon(name) {
    const paths = {
      plus: '<path d="M12 5v14M5 12h14"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      edit: '<path d="m4 20 4.2-1 10.9-10.9a2 2 0 0 0-2.8-2.8L5.4 16.2 4 20Z"></path>',
      trash: '<path d="M4 7h16M9 7V4h6v3m3 0-1 13H7L6 7m4 4v5m4-5v5"></path>',
      ports: '<rect x="4" y="7" width="16" height="11" rx="2"></rect><path d="M8 7V4h8v3M8 18v2m8-2v2m-6-8h4"></path>',
      network: '<rect x="4" y="4" width="6" height="6" rx="1"></rect><rect x="14" y="4" width="6" height="6" rx="1"></rect><rect x="9" y="14" width="6" height="6" rx="1"></rect><path d="M10 7h4m-2 3v4"></path>',
      internet: '<circle cx="12" cy="12" r="9"></circle><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"></path>',
      dhcp: '<rect x="4" y="4" width="6" height="6" rx="1"></rect><rect x="14" y="14" width="6" height="6" rx="1"></rect><path d="M7 10v4a3 3 0 0 0 3 3h4"></path>',
      globe: '<circle cx="12" cy="12" r="9"></circle><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"></path>',
      activity: '<path d="M4 13h3l2-6 4 12 2-6h5"></path>',
      shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"></path><path d="m9 12 2 2 4-5"></path>',
      speed: '<path d="M5 19a8 8 0 1 1 14 0"></path><path d="m12 13 4-4M8 19h8"></path>',
      close: '<path d="m6 6 12 12M18 6 6 18"></path>',
      warning: '<path d="M12 3 2.8 20h18.4L12 3Z"></path><path d="M12 9v5m0 3h.01"></path>',
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      chevron: '<path d="m8 10 4 4 4-4"></path>',
      route: '<circle cx="6" cy="18" r="2"></circle><circle cx="18" cy="6" r="2"></circle><path d="M8 18h4a4 4 0 0 0 4-4V8"></path>',
      layers: '<path d="m12 3-9 5 9 5 9-5-9-5Z"></path><path d="m3 12 9 5 9-5M3 16l9 5 9-5"></path>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.network}</svg>`;
  }

  function ipv4Prefix(ip) {
    const parts = String(ip || '').split('.');
    return parts.length === 4 ? parts.slice(0, 3).join('.') : '';
  }

  function poolEndpoint(value, gateway, fallback) {
    const text = firstText(value);
    if (text.includes('.')) return text;
    const prefix = ipv4Prefix(gateway);
    return prefix && /^\d{1,3}$/.test(text) ? `${prefix}.${text}` : fallback;
  }

  function splitPool(value, gateway) {
    const text = firstText(value);
    const parts = text.split('-').map((entry) => entry.trim()).filter(Boolean);
    return {
      start: poolEndpoint(parts[0], gateway, ipv4Prefix(gateway) ? `${ipv4Prefix(gateway)}.100` : ''),
      end: poolEndpoint(parts[1], gateway, ipv4Prefix(gateway) ? `${ipv4Prefix(gateway)}.249` : '')
    };
  }

  function normalizeLan(row = {}, index = 0) {
    const dhcpRaw = row.dhcp && typeof row.dhcp === 'object' ? row.dhcp : {};
    const ipv6Raw = row.ipv6 && typeof row.ipv6 === 'object' ? row.ipv6 : {};
    const ip = firstText(row.ipaddr, row.ip, row.ipv4, asArray(row.addresses)[0]?.ip);
    const prefix = String(firstNumber(row.cidr, asArray(row.addresses)[0]?.prefix, 24) || 24);
    const pool = splitPool(firstText(dhcpRaw.pool, `${dhcpRaw.pool_start || ''}-${dhcpRaw.pool_end || ''}`), ip);
    const dns = asArray(parseJsonValue(dhcpRaw.dns, parseJsonValue(dhcpRaw.dns_json, []))).filter(Boolean);
    const dns6 = asArray(parseJsonValue(ipv6Raw.dns6, parseJsonValue(ipv6Raw.dns_json, []))).filter(Boolean);
    const parentWans = asArray(parseJsonValue(ipv6Raw.parent_wans, parseJsonValue(ipv6Raw.parent_json, []))).filter(Boolean);
    return {
      ...row,
      id: firstText(row.id, row.ifname, `lan${index || ''}`),
      name: firstText(row.name, row.id, `LAN ${index + 1}`),
      note: firstText(row.note),
      ifname: firstText(row.ifname, row.id),
      device: firstText(row.device, 'br-lan'),
      mode: ['bridge', 'access', 'trunk'].includes(firstText(row.mode)) ? firstText(row.mode) : 'bridge',
      parent: firstText(row.parent, row.parent_lan_id),
      vlan_id: firstText(row.vlan_id),
      enabled: booleanValue(row.enabled, row.status !== 'down'),
      lan_visit: booleanValue(row.lan_visit, true),
      ports: asArray(row.ports).map(String),
      ipaddr: ip,
      cidr: prefix,
      extra_ips: asArray(row.extra_ips).map(String),
      dhcp: {
        ...dhcpRaw,
        enabled: booleanValue(dhcpRaw.enabled ?? dhcpRaw.enable, true),
        pool_start: pool.start,
        pool_end: pool.end,
        gateway: firstText(dhcpRaw.gateway, ip),
        dns,
        lease: firstNumber(dhcpRaw.lease, dhcpRaw.lease_minutes, dhcpRaw.leasetime, 120) || 120
      },
      ipv6: {
        ...ipv6Raw,
        enabled: booleanValue(ipv6Raw.enabled, false),
        parent_wans: parentWans,
        mode: firstText(ipv6Raw.mode, 'dhcp'),
        dhcpv6: booleanValue(ipv6Raw.dhcpv6, true),
        addr: firstText(ipv6Raw.addr, ipv6Raw.static_addr),
        use_dns6: booleanValue(ipv6Raw.use_dns6, false),
        dns6,
        prefix_len: firstText(ipv6Raw.prefix_len, 'auto'),
        ra_flags: firstText(ipv6Raw.ra_flags, '1'),
        ra_static: booleanValue(ipv6Raw.ra_static, false),
        ra_mtu_set: booleanValue(ipv6Raw.ra_mtu_set, false),
        ra_mtu: firstNumber(ipv6Raw.ra_mtu, 1480) || 1480,
        leasetime: firstNumber(ipv6Raw.leasetime, ipv6Raw.lease_minutes, 120) || 120
      }
    };
  }

  function normalizeWan(row = {}, index = 0) {
    const runtime = row.runtime && typeof row.runtime === 'object' ? row.runtime : {};
    const advanced = row.advanced && typeof row.advanced === 'object' ? clone(row.advanced) : {};
    const dnsConfigured = asArray(parseJsonValue(row.dns_json, [])).filter(Boolean);
    const dnsRuntime = asArray(row.dns || runtime.dns).filter(Boolean);
    const addresses = asArray(row.addresses).map((address, addressIndex) => ({
      ip: firstText(address.ip, address.address),
      prefix: firstNumber(address.prefix, 24) || 24,
      primary: booleanValue(address.primary ?? address.is_primary, addressIndex === 0),
      is_primary: booleanValue(address.is_primary ?? address.primary, addressIndex === 0)
    }));
    const mode = firstText(row.access_mode, row.proto, runtime.proto, 'dhcp').toLowerCase();
    return {
      ...row,
      id: firstText(row.id, row.ifname, `wan${index || ''}`),
      name: firstText(row.name, row.id, `WAN ${index + 1}`),
      note: firstText(row.note),
      carrier: firstText(row.carrier, row.carrier_key),
      carrier_name: firstText(row.carrier_name, row.carrier),
      ifname: firstText(row.ifname, row.id),
      device: firstText(row.device, runtime.device, row.runtime_device),
      access_mode: ['dhcp', 'static', 'pppoe', 'bridge', 'hybrid_macvlan', 'hybrid_vlan'].includes(mode) ? mode : 'dhcp',
      enabled: booleanValue(row.enabled, true),
      addresses,
      ipv4: firstText(row.ipv4, row.ipaddr, row.ip, row.public_ip, runtime.ipv4),
      gateway: firstText(row.gateway, runtime.gateway),
      dns: dnsConfigured.length ? dnsConfigured : dnsRuntime,
      username: firstText(row.username),
      password_ref: firstText(row.password_ref, row.password),
      password_input: '',
      ipv6_mode: firstText(row.ipv6_mode, 'disabled'),
      ipv6_addr: firstText(row.ipv6_addr, row.ipv6, runtime.ipv6),
      delegated_prefix: firstText(row.delegated_prefix),
      vlan_enabled: booleanValue(row.vlan_enabled, Boolean(row.vlan_id)),
      vlan_id: firstText(row.vlan_id),
      mtu: firstNumber(row.mtu, mode === 'pppoe' ? 1492 : 1500),
      metric: firstNumber(row.metric, (index + 1) * 10),
      role: firstText(row.role, index ? 'failover' : 'primary'),
      expected_down_mbps: firstNumber(row.expected_down_mbps),
      expected_up_mbps: firstNumber(row.expected_up_mbps),
      smart_queue: booleanValue(row.smart_queue, false),
      upnp: booleanValue(row.upnp, false),
      ddns: booleanValue(row.ddns, false),
      advanced: {
        default_route: booleanValue(advanced.default_route, index === 0),
        failover: booleanValue(advanced.failover, true),
        link_time: firstText(advanced.link_time, '00:00-23:59'),
        health_check: {
          enabled: booleanValue(advanced.health_check?.enabled, true),
          mode: firstText(advanced.health_check?.mode, 'ping'),
          targets_json: firstText(advanced.health_check?.targets_json, '[]')
        },
        dhcp: {
          hostname: firstText(advanced.dhcp?.hostname),
          vendor_class: firstText(advanced.dhcp?.vendor_class),
          client_id: firstText(advanced.dhcp?.client_id)
        },
        pppoe: {
          timing_restart: booleanValue(advanced.pppoe?.timing_restart, false),
          restart_week: firstText(advanced.pppoe?.restart_week, '1234567'),
          restart_time: firstText(advanced.pppoe?.restart_time, '04:00'),
          ac: firstText(advanced.pppoe?.ac),
          ac_mac: firstText(advanced.pppoe?.ac_mac),
          service: firstText(advanced.pppoe?.service),
          abnormal_ip_check: booleanValue(advanced.pppoe?.abnormal_ip_check, false),
          abnormal_ip_prefixes: firstText(advanced.pppoe?.abnormal_ip_prefixes, '10,172,192.168')
        }
      },
      pppoe_multi: row.pppoe_multi && typeof row.pppoe_multi === 'object' ? clone(row.pppoe_multi) : {},
      bond: row.bond && typeof row.bond === 'object' ? clone(row.bond) : {},
      hybrid_lines: asArray(row.hybrid_lines).map((line) => clone(line)),
      runtime,
      online: booleanValue(runtime.online, ['ok', 'up', 'online'].includes(firstText(row.status).toLowerCase())),
      uptime: firstNumber(row.connected_seconds, row.online_seconds, row.uptime, runtime.connected_seconds, runtime.uptime),
      latency: firstNumber(row.latency_ms, runtime.latency_ms),
      loss: firstNumber(row.loss_pct, runtime.loss_pct),
      up_rate: firstNumber(row.up_rate, runtime.up_rate),
      down_rate: firstNumber(row.down_rate, runtime.down_rate)
    };
  }

  function normalizeRows(payload) {
    const rows = asArray(payload, [isWan ? 'wans' : 'lans', 'interfaces', 'items', 'list']);
    state.capabilities = payload?.capabilities && typeof payload.capabilities === 'object' ? payload.capabilities : state.capabilities;
    return rows.map((row, index) => isWan ? normalizeWan(row, index) : normalizeLan(row, index));
  }

  function normalizePorts(payload) {
    return asArray(payload, ['ports', 'items', 'list']).map((port) => ({
      name: firstText(port.name, port.ifname),
      label: firstText(port.display_name, port.label, port.name, port.ifname),
      ownerType: firstText(port.owner_type),
      ownerId: firstText(port.owner_id),
      status: firstText(port.status, port.runtime?.status),
      speed: firstText(port.speed_label, port.runtime?.speed_label, port.link_speed_mbps ? `${port.link_speed_mbps}M` : ''),
      localMac: firstText(port.local_mac)
    })).filter((port) => port.name);
  }

  function applyData(config, ports) {
    state.rows = normalizeRows(config || {});
    state.ports = normalizePorts(ports || {});
    state.loading = false;
    state.refreshing = false;
    render();
    if (typeof context.onDataChange === 'function') {
      context.onDataChange({ kind, rows: state.rows, ports: state.ports, capabilities: state.capabilities });
    }
  }

  function assignablePorts(ownerId = '') {
    return state.ports.filter((port) => {
      const ownerType = firstText(port.ownerType).toLowerCase();
      const currentOwner = firstText(port.ownerId);
      if (!ownerType || !currentOwner) return true;
      return ownerType === kind && currentOwner === ownerId;
    });
  }

  function nextId() {
    const ids = new Set(state.rows.map((row) => row.id));
    const base = kind;
    if (!ids.has(base)) return base;
    let index = 2;
    while (ids.has(`${base}${index}`)) index += 1;
    return `${base}${index}`;
  }

  function blankLan() {
    const id = nextId();
    return normalizeLan({
      id, name: id, ifname: id, device: `br-${id}`, mode: 'bridge', enabled: true, lan_visit: true,
      addresses: [{ ip: '', prefix: 24, primary: true, is_primary: true }],
      ipaddr: '', cidr: 24, ports: [],
      dhcp: { enabled: false, pool: '', gateway: '', dns: [], lease: 120 },
      ipv6: { enabled: false, mode: 'dhcp', dhcpv6: true, prefix_len: 'auto', ra_flags: '1', ra_mtu: 1480, leasetime: 120 }
    }, state.rows.length);
  }

  function blankWan() {
    const id = nextId();
    return normalizeWan({
      id, name: id.toUpperCase(), ifname: id, device: '', access_mode: 'dhcp', enabled: true,
      mtu: 1500, metric: (state.rows.length + 1) * 10, role: state.rows.length ? 'failover' : 'primary',
      advanced: { default_route: state.rows.length === 0, failover: true, health_check: { enabled: true, mode: 'ping', targets_json: '[]' } }
    }, state.rows.length);
  }

  function filteredRows() {
    const query = state.query.trim().toLowerCase();
    if (!query) return state.rows;
    return state.rows.filter((row) => [row.id, row.name, row.note, row.ifname, row.device, row.ipaddr, row.ipv4, row.gateway, row.carrier, row.carrier_name, row.vlan_id, row.ports, row.dns]
      .flat().map((value) => firstText(value).toLowerCase()).some((value) => value.includes(query)));
  }

  function formatRate(value) {
    if (typeof utils.formatRate === 'function') return utils.formatRate(value);
    const number = Number(value);
    if (!Number.isFinite(number) || number < 0) return '--';
    const units = ['bps', 'Kbps', 'Mbps', 'Gbps'];
    let current = number * 8;
    let unit = 0;
    while (current >= 1000 && unit < units.length - 1) { current /= 1000; unit += 1; }
    return `${current >= 100 ? current.toFixed(0) : current.toFixed(1)} ${units[unit]}`;
  }

  function formatDuration(value) {
    const seconds = Number(value);
    if (!Number.isFinite(seconds) || seconds < 0) return '--';
    if (seconds < 60) return `${Math.round(seconds)} 秒`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时 ${Math.floor(seconds % 3600 / 60)} 分钟`;
    return `${Math.floor(seconds / 86400)} 天 ${Math.floor(seconds % 86400 / 3600)} 小时`;
  }

  function carrierLabel(row) {
    const raw = firstText(row.carrier_name, row.carrier, '--');
    const key = raw.toLowerCase().replace(/[\s_-]+/g, '');
    if (['unicom', 'chinaunicom', 'cucc'].includes(key)) return '中国联通';
    if (['mobile', 'chinamobile', 'cmcc'].includes(key)) return '中国移动';
    if (['telecom', 'chinatelecom', 'ctcc'].includes(key)) return '中国电信';
    if (['cernet', 'edu', 'education'].includes(key)) return '教育网';
    return raw;
  }

  function carrierLogo(row) {
    const label = carrierLabel(row);
    const key = `${firstText(row.carrier, row.carrier_name)} ${label}`.toLowerCase();
    const file = /unicom|cucc|联通/.test(key) ? 'china-unicom.svg'
      : /mobile|cmcc|移动/.test(key) ? 'china-mobile.svg'
        : /telecom|ctcc|电信/.test(key) ? 'china-telecom.svg'
          : /cernet|edu|教育/.test(key) ? 'china-cernet.svg' : '';
    if (!file) return `<span class="network-interface-carrier-fallback" data-dwrt-tooltip="${escapeHtml(label)}">${icon('globe')}</span>`;
    return `<img class="network-interface-carrier-logo" src="/static/images/logo/${file}" alt="${escapeHtml(label)}" data-dwrt-tooltip="${escapeHtml(label)}">`;
  }

  function statusMarkup(row) {
    const active = isWan ? row.enabled && row.online : row.enabled;
    const label = !row.enabled ? '已停用' : isWan ? (row.online ? '在线' : '离线') : '已启用';
    return ui.statusBadgeMarkup?.(label, active ? 'success' : row.enabled ? 'error' : 'muted') || `<span>${label}</span>`;
  }

  function overviewMarkup() {
    if (state.loading) return '';
    const renderer = ui.overviewCardsMarkup || window.DWRT_UI_KIT?.overviewCardsMarkup;
    if (typeof renderer !== 'function') return '';
    if (isWan) {
      const online = state.rows.filter((row) => row.enabled && row.online).length;
      const down = state.rows.reduce((sum, row) => sum + row.down_rate, 0);
      const up = state.rows.reduce((sum, row) => sum + row.up_rate, 0);
      const pppoe = state.rows.filter((row) => row.access_mode === 'pppoe').length;
      return renderer([
        { key: 'wan-count', label: 'WAN 线路', value: `${online}/${state.rows.length}`, detail: '在线 / 已配置', tone: online === state.rows.length ? 'ok' : 'warn', icon: icon('internet') },
        { key: 'wan-down', label: '实时下行', value: formatRate(down), detail: '全部 WAN 汇总', tone: 'info', icon: icon('activity') },
        { key: 'wan-up', label: '实时上行', value: formatRate(up), detail: '全部 WAN 汇总', tone: 'info', icon: icon('speed') },
        { key: 'wan-access', label: '拨号线路', value: String(pppoe), detail: 'PPPoE 接入', tone: 'neutral', icon: icon('globe') }
      ], { label: 'WAN 配置概览', className: 'network-interface-overview' });
    }
    const enabled = state.rows.filter((row) => row.enabled).length;
    const dhcp = state.rows.filter((row) => row.dhcp.enabled).length;
    const ipv6 = state.rows.filter((row) => row.ipv6.enabled).length;
    const ports = new Set(state.rows.flatMap((row) => row.ports)).size;
    return renderer([
      { key: 'lan-count', label: 'LAN 网络', value: `${enabled}/${state.rows.length}`, detail: '启用 / 已配置', tone: enabled === state.rows.length ? 'ok' : 'warn', icon: icon('network') },
      { key: 'lan-dhcp', label: 'DHCP 服务', value: String(dhcp), detail: '启用地址分配', tone: 'info', icon: icon('dhcp') },
      { key: 'lan-ipv6', label: 'IPv6 网络', value: String(ipv6), detail: '启用 RA / DHCPv6', tone: 'neutral', icon: icon('globe') },
      { key: 'lan-ports', label: '成员端口', value: String(ports), detail: '物理端口归属', tone: 'neutral', icon: icon('ports') }
    ], { label: 'LAN 配置概览', className: 'network-interface-overview' });
  }

  function toolbarMarkup() {
    if (!showToolbar) return '';
    if (embedded) {
      return `<header class="network-interface-toolbar is-embedded">
        ${showHeading ? `<div class="network-interface-heading"><span>${isWan ? icon('internet') : icon('network')}</span><div><strong>${isWan ? 'WAN 配置' : 'LAN 配置'}</strong><small>${isWan ? '外网线路、接入方式与链路参数' : '本地网络、地址分配与端口成员'}</small></div></div>` : ''}
        <div class="network-interface-toolbar-actions">
          ${showTable ? `<label class="network-interface-search" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-interface-search placeholder="搜索名称、接口或地址" value="${escapeHtml(state.query)}"></label>` : ''}
          <button class="policy-primary" type="button" data-interface-create>${icon('plus')}<span>新建${isWan ? ' WAN' : ' LAN'}</span></button>
        </div>
      </header>`;
    }
    return `<header class="network-interface-toolbar">
      <div class="network-interface-heading"><span>${isWan ? icon('internet') : icon('network')}</span><div><strong>${isWan ? 'WAN 配置' : 'LAN 配置'}</strong><small>${isWan ? '外网线路、接入方式与链路参数' : '本地网络、地址分配与端口成员'}</small></div></div>
      <div class="network-interface-toolbar-actions">
        <label class="network-interface-search" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-interface-search placeholder="搜索名称、接口或地址" value="${escapeHtml(state.query)}"></label>
        <button class="policy-primary" type="button" data-interface-create>${icon('plus')}<span>新建${isWan ? ' WAN' : ' LAN'}</span></button>
      </div>
    </header>`;
  }

  function lanTableRow(row) {
    const subnet = row.ipaddr ? `${row.ipaddr}/${row.cidr}` : '--';
    const modeLabel = row.mode === 'access' ? 'VLAN 接入' : row.mode === 'trunk' ? 'VLAN Trunk' : '桥接';
    const ports = row.ports.length ? row.ports.join(', ') : '--';
    const identity = firstText(row.name).toLowerCase() === firstText(row.id).toLowerCase() ? '' : row.id;
    return `<tr data-interface-row="${escapeHtml(row.id)}">
      <td>${statusMarkup(row)}</td>
      <td><span class="network-interface-name"><strong>${escapeHtml(row.name)}</strong>${identity ? `<small>${escapeHtml(identity)}</small>` : ''}</span></td>
      <td><code>${escapeHtml(row.device || row.ifname || '--')}</code></td>
      <td>${escapeHtml(modeLabel)}</td>
      <td>${escapeHtml(row.vlan_id || '--')}</td>
      <td><code>${escapeHtml(subnet)}</code></td>
      <td>${row.dhcp.enabled ? '服务器' : '关闭'}</td>
      <td>${row.ipv6.enabled ? escapeHtml(row.ipv6.mode === 'static' ? firstText(row.ipv6.addr, '静态') : '自动') : '关闭'}</td>
      <td><span class="network-interface-ellipsis" data-dwrt-tooltip="${escapeHtml(ports)}">${escapeHtml(ports)}</span></td>
      <td>${rowActions(row)}</td>
    </tr>`;
  }

  function wanTableRow(row) {
    const access = { dhcp: 'DHCP', static: '静态', pppoe: 'PPPoE', bridge: 'Bridge' }[row.access_mode] || row.access_mode;
    const dns = row.dns.length ? row.dns.join(', ') : '--';
    const identity = firstText(row.name).toLowerCase() === firstText(row.id).toLowerCase() ? '' : row.id;
    return `<tr data-interface-row="${escapeHtml(row.id)}">
      <td>${statusMarkup(row)}</td>
      <td><span class="network-interface-name"><strong>${escapeHtml(row.name)}</strong>${identity ? `<small>${escapeHtml(identity)}</small>` : ''}</span></td>
      <td><code>${escapeHtml(row.device || '--')}</code></td>
      <td class="network-interface-carrier-cell">${carrierLogo(row)}</td>
      <td>${escapeHtml(access)}</td>
      <td><code>${escapeHtml(row.ipv4 || '--')}</code></td>
      <td><code>${escapeHtml(row.gateway || '--')}</code></td>
      <td><span class="network-interface-ellipsis" data-dwrt-tooltip="${escapeHtml(dns)}">${escapeHtml(dns)}</span></td>
      <td>${escapeHtml(formatDuration(row.uptime))}</td>
      <td>${rowActions(row)}</td>
    </tr>`;
  }

  function rowActions(row) {
    return `<span class="network-interface-row-actions">
      <button type="button" data-interface-edit="${escapeHtml(row.id)}" aria-label="编辑 ${escapeHtml(row.name)}" data-dwrt-tooltip="编辑">${icon('edit')}</button>
      <button type="button" class="is-danger" data-interface-delete="${escapeHtml(row.id)}" aria-label="删除 ${escapeHtml(row.name)}" data-dwrt-tooltip="删除">${icon('trash')}</button>
    </span>`;
  }

  function tableMarkup() {
    const rows = filteredRows();
    const headers = isWan
      ? ['状态', '名称', '物理接口', '运营商', '接入方式', 'IPv4', '网关', 'DNS', '连接时间', '操作']
      : ['状态', '名称', '设备 / 网桥', '模式', 'VLAN', 'IPv4 网关', 'DHCP', 'IPv6', '成员端口', '操作'];
    return `<section class="network-interface-table-card dwrt-kit-table-wrap dwrt-kit-glass-surface dwrt-kit-ikuai-table-wrap" style="--network-interface-row-count:${Math.max(1, rows.length)}">
      <div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>${isWan ? 'WAN 线路' : 'LAN / VLAN 网络'}</strong><span>读取当前真实配置与运行状态</span></div><span class="dwrt-kit-table-count">${rows.length} / ${state.rows.length}</span></div>
      <div class="dwrt-kit-table-scroll network-interface-table-scroll" data-interface-scroll>
        <table class="dwrt-kit-table dwrt-kit-ikuai-table network-interface-table is-${kind}"><thead><tr>${headers.map((header) => `<th>${header}</th>`).join('')}</tr></thead>
          <tbody>${rows.length ? rows.map((row) => isWan ? wanTableRow(row) : lanTableRow(row)).join('') : `<tr><td class="dwrt-kit-table-empty" colspan="10">${state.loading ? '正在读取配置' : state.query ? '没有匹配的配置' : `暂无 ${kind.toUpperCase()} 配置`}</td></tr>`}</tbody>
        </table>
      </div>
    </section>`;
  }

  function formField(label, control, detail = '', modifier = '') {
    return `<label class="network-interface-field ${modifier}"><span>${escapeHtml(label)}</span>${control}${detail ? `<small>${escapeHtml(detail)}</small>` : ''}</label>`;
  }

  function inputField(field, value, options = {}) {
    const type = options.type || 'text';
    return `<input type="${type}" data-interface-field="${escapeHtml(field)}" value="${escapeHtml(value ?? '')}" ${options.placeholder ? `placeholder="${escapeHtml(options.placeholder)}"` : ''} ${options.min !== undefined ? `min="${options.min}"` : ''} ${options.max !== undefined ? `max="${options.max}"` : ''} ${options.disabled ? 'disabled' : ''}>`;
  }

  function selectField(field, value, options = [], attributes = {}) {
    return `<select data-interface-field="${escapeHtml(field)}" ${attributes.disabled ? 'disabled' : ''}>${options.map(([key, label, disabled]) => `<option value="${escapeHtml(key)}" ${String(value) === String(key) ? 'selected' : ''} ${disabled ? 'disabled' : ''}>${escapeHtml(label)}</option>`).join('')}</select>`;
  }

  function switchField(field, checked, title, detail = '') {
    return `<label class="network-interface-switch-row"><span><strong>${escapeHtml(title)}</strong>${detail ? `<small>${escapeHtml(detail)}</small>` : ''}</span><input type="checkbox" data-interface-field="${escapeHtml(field)}" ${checked ? 'checked' : ''}><i></i></label>`;
  }

  function segmentedField(field, value, options, label) {
    return `<fieldset class="network-interface-segmented"><legend>${escapeHtml(label)}</legend><div>${options.map(([key, title, detail, disabled]) => `<label class="${String(value) === String(key) ? 'is-selected' : ''} ${disabled ? 'is-disabled' : ''}"><input type="radio" name="${escapeHtml(field)}" value="${escapeHtml(key)}" data-interface-field="${escapeHtml(field)}" ${String(value) === String(key) ? 'checked' : ''} ${disabled ? 'disabled' : ''}><span><strong>${escapeHtml(title)}</strong>${detail ? `<small>${escapeHtml(detail)}</small>` : ''}</span></label>`).join('')}</div></fieldset>`;
  }

  function dependentMarkup(body, modifier = '') {
    return `<div class="network-interface-dependent ${modifier}"><div class="network-interface-form-grid">${body}</div></div>`;
  }

  function wanAddressFields(draft) {
    const addresses = asArray(draft.addresses).length ? asArray(draft.addresses) : [{ ip: draft.ipv4 || '', prefix: 24, primary: true, is_primary: true }];
    return `<div class="network-interface-address-list">${addresses.map((address, index) => `<div class="network-interface-address-row"><span>${index === 0 ? '主地址' : `扩展 ${index}`}</span>${formField('IPv4 地址', `<input type="text" value="${escapeHtml(address.ip || '')}" placeholder="203.0.113.2" data-interface-address-index="${index}" data-interface-address-field="ip">`)}${formField('子网前缀', `<input type="number" min="1" max="32" value="${escapeHtml(address.prefix || 24)}" data-interface-address-index="${index}" data-interface-address-field="prefix">`)}${index ? `<button type="button" data-interface-address-remove="${index}" aria-label="删除扩展地址">${icon('trash')}</button>` : '<i></i>'}</div>`).join('')}<button class="network-interface-inline-add" type="button" data-interface-address-add>${icon('plus')}<span>添加扩展 IP</span></button></div>`;
  }

  function editorGroup(id, title, description, iconName, body, options = {}) {
    const open = state.editorOpen === id;
    const triggerId = `network-interface-${kind}-${id}-trigger`;
    const panelId = `network-interface-${kind}-${id}-panel`;
    return `<section class="network-interface-editor-group ${open ? 'is-open' : ''} ${options.disabled ? 'is-disabled' : ''}" data-interface-editor-group="${escapeHtml(id)}">
      <h3><button type="button" id="${triggerId}" data-interface-editor-toggle="${escapeHtml(id)}" aria-expanded="${open ? 'true' : 'false'}" aria-controls="${panelId}"><span class="network-interface-editor-icon">${icon(iconName)}</span><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(description)}</small></span>${options.badge ? `<em>${escapeHtml(options.badge)}</em>` : ''}<i>${icon('chevron')}</i></button></h3>
      <div id="${panelId}" class="network-interface-editor-group-body" role="region" aria-labelledby="${triggerId}" ${open ? '' : 'hidden'}>${body}</div>
    </section>`;
  }

  function availabilityMarkup(text) {
    return `<details class="network-interface-availability"><summary>可用性说明</summary><p>${escapeHtml(text)}</p></details>`;
  }

  function inlinePortPicker(draft) {
    const selected = new Set(isWan ? [draft.device].filter(Boolean) : draft.ports || []);
    const available = assignablePorts(draft.id);
    return `<div class="network-interface-port-picker is-inline"><p>${isWan ? '选择承载此线路的物理网卡。端口变更将随本次配置保存。' : '选择加入此本地网络的成员端口。'}</p><div>${available.length ? available.map((port) => `<label class="${selected.has(port.name) ? 'is-selected' : ''}"><input type="${isWan ? 'radio' : 'checkbox'}" name="network-interface-${kind}-port" value="${escapeHtml(port.name)}" ${selected.has(port.name) ? 'checked' : ''} data-interface-port><span>${icon('ports')}<strong>${escapeHtml(port.label)}</strong><small>${escapeHtml([port.status, port.speed, port.localMac].filter(Boolean).join(' · ') || '未提供运行状态')}</small></span></label>`).join('') : '<div class="dwrt-kit-table-empty">后端未返回可用物理端口</div>'}</div></div>`;
  }

  function hybridCapabilityMarkup(lines, writeEnabled) {
    const line = lines[0] || {};
    return `<fieldset ${writeEnabled ? '' : 'disabled'}><legend>混合 WAN 子线路</legend><div class="network-interface-form-grid">
      ${formField('宿主模式', selectField('access_mode', state.draft.access_mode?.startsWith('hybrid_') ? state.draft.access_mode : 'hybrid_macvlan', [['hybrid_macvlan', '基于物理网卡'], ['hybrid_vlan', '基于 VLAN']], { disabled: !writeEnabled }))}
      ${formField('子线路数量', inputField('hybrid_line_count', lines.length, { type: 'number', disabled: true }))}
      ${formField('名称', inputField('hybrid_lines.0.name', firstText(line.name), { disabled: !writeEnabled }))}
      ${formField('备注', inputField('hybrid_lines.0.comment', firstText(line.comment), { disabled: !writeEnabled }))}
      ${formField('VLAN ID', inputField('hybrid_lines.0.vlan_id', firstText(line.vlan_id), { type: 'number', min: 1, max: 4094, disabled: !writeEnabled }))}
      ${formField('MAC', inputField('hybrid_lines.0.mac', firstText(line.mac), { disabled: !writeEnabled, placeholder: '留空自动生成' }))}
      ${formField('接入方式', selectField('hybrid_lines.0.proto', firstText(line.proto, 'dhcp'), [['dhcp', 'DHCP'], ['static', '静态 IP'], ['pppoe', 'PPPoE']], { disabled: !writeEnabled }))}
      ${formField('IP 地址', inputField('hybrid_lines.0.ipv4', firstText(line.ipv4), { disabled: !writeEnabled }))}
      ${formField('网关', inputField('hybrid_lines.0.gateway', firstText(line.gateway), { disabled: !writeEnabled }))}
      ${formField('PPPoE 账号', inputField('hybrid_lines.0.username', firstText(line.username), { disabled: !writeEnabled }))}
      ${formField('PPPoE 密码', inputField('hybrid_lines.0.password_input', '', { type: 'password', disabled: !writeEnabled, placeholder: '留空保持当前密码' }))}
      ${formField('AC 名称', inputField('hybrid_lines.0.pppoe_ac', firstText(line.pppoe_ac), { disabled: !writeEnabled }))}
      ${formField('AC MAC', inputField('hybrid_lines.0.pppoe_ac_mac', firstText(line.pppoe_ac_mac), { disabled: !writeEnabled }))}
      ${formField('服务名称', inputField('hybrid_lines.0.pppoe_service', firstText(line.pppoe_service), { disabled: !writeEnabled }))}
      ${formField('MTU', inputField('hybrid_lines.0.mtu', firstNumber(line.mtu, 1492), { type: 'number', disabled: !writeEnabled }))}
      ${formField('MRU', inputField('hybrid_lines.0.mru', firstNumber(line.mru, 1492), { type: 'number', disabled: !writeEnabled }))}
      ${formField('健康检测目标', inputField('hybrid_lines.0.check_host', firstText(line.check_host), { disabled: !writeEnabled }))}
      ${formField('预期下行（Mbps）', inputField('hybrid_lines.0.download', firstNumber(line.download), { type: 'number', disabled: !writeEnabled }))}
      ${switchField('hybrid_lines.0.enabled', Boolean(line.enabled), '启用子线路')}
      ${switchField('hybrid_lines.0.default_route', Boolean(line.default_route), '默认路由候选')}
      ${switchField('hybrid_lines.0.failover', Boolean(line.failover), '故障转移')}
    </div></fieldset>${availabilityMarkup('这些维度与 LuCI 版本保持一致，但必须由子线路事务统一保存和应用，不能拆成前端本地状态。')}`;
  }

  function multiDialCapabilityMarkup(multi, writeEnabled) {
    return `<fieldset ${writeEnabled ? '' : 'disabled'}><legend>PPPoE 多拨</legend><div class="network-interface-form-grid">
      ${switchField('pppoe_multi.enabled', Boolean(multi.enabled), '启用多拨助手')}
      ${formField('多拨总数', inputField('pppoe_multi.total', firstNumber(multi.total, 1), { type: 'number', min: 1, max: 100, disabled: !writeEnabled }))}
      ${formField('检测间隔（分钟）', inputField('pppoe_multi.check_interval_min', firstNumber(multi.check_interval_min), { type: 'number', min: 0, max: 60, disabled: !writeEnabled }))}
      ${switchField('pppoe_multi.abnormal_ip_check', Boolean(multi.abnormal_ip_check), '异常 IP 检测')}
      ${formField('异常 IP 前缀', inputField('pppoe_multi.abnormal_ip_prefixes', firstText(multi.abnormal_ip_prefixes, '10,172,192.168'), { disabled: !writeEnabled }))}
      ${switchField('pppoe_multi.drop_restart', Boolean(multi.drop_restart), '掉线整组重拨')}
      ${formField('检测星期', inputField('pppoe_multi.check_week_text', asArray(multi.check_week).join(''), { disabled: !writeEnabled, placeholder: '1234567' }))}
      ${formField('组重拨时段', inputField('pppoe_multi.check_time', firstText(multi.check_time, '00:00-08:00'), { disabled: !writeEnabled }))}
      ${formField('掉线数量阈值', inputField('pppoe_multi.drop_threshold', firstNumber(multi.drop_threshold, 1), { type: 'number', min: 1, max: 100, disabled: !writeEnabled }))}
      ${switchField('pppoe_multi.no_individual_persist', Boolean(multi.no_individual_persist), '禁止单线自动重拨')}
    </div></fieldset>${availabilityMarkup('多拨写入需要子线路组管理、检测周期、异常 IP 判定、星期/时段、掉线阈值和整组重拨的 apply/readback/rollback；当前 capability 为 pppoe_multi_write=false。')}`;
  }

  function bondingCapabilityMarkup(bond, writeEnabled) {
    return `<fieldset ${writeEnabled ? '' : 'disabled'}><legend>WAN 链路聚合</legend><div class="network-interface-form-grid">
      ${switchField('bond.enabled', Boolean(bond.enabled), '启用链路聚合')}
      ${formField('聚合名称', inputField('bond.bond_name', firstText(bond.bond_name), { disabled: !writeEnabled, placeholder: 'bond0' }))}
      ${formField('聚合模式', selectField('bond.mode', firstText(bond.mode, '802.3ad'), [['802.3ad', '802.3ad / LACP'], ['active-backup', 'Active Backup'], ['balance-xor', 'Balance XOR']], { disabled: !writeEnabled }))}
      ${formField('哈希策略', selectField('bond.hash_policy', firstText(bond.hash_policy, 'layer3+4'), [['layer2', 'Layer 2'], ['layer2+3', 'Layer 2+3'], ['layer3+4', 'Layer 3+4']], { disabled: !writeEnabled }))}
      ${formField('成员端口', inputField('bond.members_text', asArray(parseJsonValue(bond.members_json, [])).join(', '), { disabled: !writeEnabled }))}
    </div></fieldset>${availabilityMarkup(`链路聚合需要成员冲突检查、LACP/运行态应用、readback 和断网回滚；当前 capability 为 wan_bonding_write=false${state.capabilities.wan_bonding_write_reason ? `：${state.capabilities.wan_bonding_write_reason}` : '。'}`)}`;
  }

  function lanEditorMarkup(draft) {
    const dhcp = draft.dhcp || {};
    const ipv6 = draft.ipv6 || {};
    const identity = `${switchField('enabled', draft.enabled, '启用网络', '停用后保留配置与地址分配')}
      <div class="network-interface-form-grid">${formField('网络名称', inputField('name', draft.name, { placeholder: '例如 IoT' }))}${formField('网络 ID', inputField('id', draft.id, { disabled: state.drawer === 'edit' }), '保存后的稳定标识')}${formField('备注', inputField('note', draft.note, { placeholder: '可选' }))}${formField('设备 / 网桥', inputField('device', draft.device, { placeholder: 'br-lan' }))}${formField('逻辑接口', inputField('ifname', draft.ifname, { placeholder: draft.id }))}</div>
      ${segmentedField('mode', draft.mode, [['bridge', '桥接', '普通本地网络'], ['access', 'VLAN 接入', '单个 VLAN'], ['trunk', 'VLAN Trunk', '承载多个 VLAN']], '网络模式')}
      ${draft.mode !== 'bridge' ? dependentMarkup(formField('VLAN ID', inputField('vlan_id', draft.vlan_id, { type: 'number', min: 1, max: 4094 }), '1-4094')) : ''}${inlinePortPicker(draft)}`;
    const addressing = `<div class="network-interface-form-grid">${formField('网关地址', inputField('ipaddr', draft.ipaddr, { placeholder: '192.168.30.1' }))}${formField('子网前缀', inputField('cidr', draft.cidr, { type: 'number', min: 1, max: 30 }), 'CIDR 前缀')}${formField('扩展 IP', inputField('extra_ips_text', asArray(draft.extra_ips).join(', '), { placeholder: '192.168.50.1/24, 192.168.60.1/24' }), '多个地址使用逗号分隔')}</div>`;
    const dhcpBody = `${switchField('dhcp.enabled', dhcp.enabled, 'DHCP 服务器', '向该网络内终端自动分配地址')}${dhcp.enabled ? dependentMarkup(`${formField('地址池起始', inputField('dhcp.pool_start', dhcp.pool_start))}${formField('地址池结束', inputField('dhcp.pool_end', dhcp.pool_end))}${formField('租期（分钟）', inputField('dhcp.lease', dhcp.lease, { type: 'number', min: 1 }))}${formField('DHCP 网关', inputField('dhcp.gateway', dhcp.gateway))}${formField('DNS 服务器', inputField('dhcp.dns_text', dhcp.dns.join(', ')), '多个地址使用逗号分隔')}`) : ''}`;
    const ipv6Body = `${switchField('ipv6.enabled', ipv6.enabled, '启用 IPv6', '配置地址委派、RA 与 DHCPv6')}${ipv6.enabled ? dependentMarkup(`${formField('地址模式', selectField('ipv6.mode', ipv6.mode, [['dhcp', '自动 / 委派'], ['static', '静态']]))}${formField('上游 WAN', inputField('ipv6.parent_text', ipv6.parent_wans.join(', '), { placeholder: 'wan, wan2' }), '多个接口使用逗号分隔')}${formField('静态地址', inputField('ipv6.addr', ipv6.addr, { placeholder: '2001:db8::1/64' }))}${formField('前缀长度', inputField('ipv6.prefix_len', ipv6.prefix_len, { placeholder: 'auto' }))}${formField('IPv6 租期（分钟）', inputField('ipv6.leasetime', ipv6.leasetime, { type: 'number', min: 1 }))}${formField('RA 标志', selectField('ipv6.ra_flags', ipv6.ra_flags, [['1', 'Managed + Other'], ['2', 'Managed'], ['3', 'Other'], ['0', '无状态']]))}${switchField('ipv6.dhcpv6', ipv6.dhcpv6, 'DHCPv6 服务')}${switchField('ipv6.ra_static', ipv6.ra_static, '静态 RA', '使用固定前缀通告')}${switchField('ipv6.use_dns6', ipv6.use_dns6, '下发 IPv6 DNS')}${ipv6.use_dns6 ? formField('IPv6 DNS', inputField('ipv6.dns_text', ipv6.dns6.join(', ')), '多个地址使用逗号分隔') : ''}${switchField('ipv6.ra_mtu_set', ipv6.ra_mtu_set, '自定义 RA MTU')}${ipv6.ra_mtu_set ? formField('RA MTU', inputField('ipv6.ra_mtu', ipv6.ra_mtu, { type: 'number', min: 1280, max: 9000 })) : ''}`) : ''}`;
    const link = `<div class="network-interface-form-grid">${switchField('lan_visit', draft.lan_visit, '允许 LAN 互访', '关闭后阻止其他本地网络主动访问此网络')}${formField('MAC 克隆', inputField('mac_clone', draft.mac_clone, { placeholder: '留空使用设备地址' }))}${formField('端口速率', selectField('speed', draft.speed, [['0', '自动协商'], ['100', '100 Mbps'], ['1000', '1 Gbps'], ['2500', '2.5 Gbps'], ['10000', '10 Gbps']]))}${formField('双工模式', selectField('duplex', draft.duplex, [['0', '自动'], ['full', '全双工'], ['half', '半双工']]))}</div>`;
    return `<div class="network-interface-editor-panel">${editorGroup('identity', '身份与端口', '名称、网络模式和成员端口', 'network', identity)}${editorGroup('addressing', 'IPv4 地址', '网关、子网与扩展地址', 'globe', addressing)}${editorGroup('dhcp', 'DHCP', dhcp.enabled ? '已启用地址分配' : '当前关闭', 'dhcp', dhcpBody)}${editorGroup('ipv6', 'IPv6', ipv6.enabled ? 'RA 与 DHCPv6 已启用' : '当前关闭', 'internet', ipv6Body)}${editorGroup('link', '访问与链路', '互访策略、MAC 与物理参数', 'shield', link)}</div>`;
  }

  function wanEditorMarkup(draft) {
    const mode = draft.access_mode;
    const advanced = draft.advanced || {};
    const health = advanced.health_check || {};
    const dhcp = advanced.dhcp || {};
    const pppoe = advanced.pppoe || {};
    const hybridWrite = state.capabilities.hybrid_wan_write === true;
    const multiWrite = state.capabilities.pppoe_multi_write === true;
    const bondWrite = state.capabilities.wan_bonding_write === true;
    const identity = `${switchField('enabled', draft.enabled, '启用线路', '停用后保留线路配置')}
      <div class="network-interface-form-grid">${formField('线路名称', inputField('name', draft.name, { placeholder: '例如 中国联通' }))}${formField('WAN ID', inputField('id', draft.id, { disabled: state.drawer === 'edit' }), '保存后的稳定标识')}${formField('备注', inputField('note', draft.note, { placeholder: '可选' }))}${formField('运营商标识', inputField('carrier', draft.carrier, { placeholder: 'unicom / mobile / telecom' }))}${formField('逻辑接口', inputField('ifname', draft.ifname, { placeholder: draft.id }))}</div>${inlinePortPicker(draft)}`;
    const accessOptions = [['dhcp', 'DHCP', '自动获取地址'], ['static', '静态 IP', '固定地址与网关'], ['pppoe', 'PPPoE', '宽带账号拨号'], ['bridge', 'Bridge', '仅桥接上游'], ['hybrid_macvlan', '物理混合', '虚拟 MAC 子线路', !hybridWrite], ['hybrid_vlan', 'VLAN 混合', 'VLAN 子线路', !hybridWrite]];
    let accessFields = '';
    if (mode === 'static') accessFields = `<div class="network-interface-span-full">${wanAddressFields(draft)}</div>${formField('网关', inputField('gateway', draft.gateway, { placeholder: '203.0.113.1' }))}${formField('DNS 服务器', inputField('dns_text', draft.dns.join(', ')), '多个地址使用逗号分隔')}`;
    if (mode === 'dhcp') accessFields = `${formField('自定义 DNS', inputField('dns_text', draft.dns.join(', ')), '留空使用运营商下发 DNS')}`;
    if (mode === 'pppoe') accessFields = `${formField('宽带账号', inputField('username', draft.username, { placeholder: 'PPPoE 用户名' }))}${formField('宽带密码', inputField('password_input', draft.password_input, { type: 'password', placeholder: '留空保持当前密码' }), '密码不会在页面中回显')}`;
    if (mode === 'bridge') accessFields = '<p class="network-interface-inline-note">Bridge 模式不在本接口配置 IPv4 地址，地址由下游设备管理。</p>';
    const access = `${segmentedField('access_mode', mode, accessOptions, '上网方式')}${accessFields ? dependentMarkup(accessFields, 'is-access-method') : ''}${!hybridWrite ? availabilityMarkup('物理网卡混合模式与 VLAN 混合模式需要后端提供子线路存储、运行态应用、readback 与失败回滚；当前 capability 为 hybrid_wan_write=false。') : ''}`;
    const ipv6 = `${segmentedField('ipv6_mode', draft.ipv6_mode, [['disabled', '关闭', '不配置 IPv6'], ['auto', '自动', '跟随上游'], ['dhcpv6', 'DHCPv6', '请求地址与前缀'], ['static', '静态', '手动指定地址']], 'IPv6 模式')}${draft.ipv6_mode !== 'disabled' ? dependentMarkup(`${formField('IPv6 地址', inputField('ipv6_addr', draft.ipv6_addr, { placeholder: '2001:db8::2/64' }))}${formField('委派前缀', inputField('delegated_prefix', draft.delegated_prefix, { placeholder: '2001:db8:1::/56' }))}`) : ''}`;
    const routing = `<div class="network-interface-form-grid">${formField('MTU', inputField('mtu', draft.mtu, { type: 'number', min: 576, max: 9000 }))}${formField('路由 Metric', inputField('metric', draft.metric, { type: 'number', min: 0, max: 65535 }))}${formField('线路角色', selectField('role', draft.role, [['primary', '主线路'], ['failover', '故障转移'], ['backup', '备用线路']]))}${formField('预计下行（Mbps）', inputField('expected_down_mbps', draft.expected_down_mbps, { type: 'number', min: 0 }))}${formField('预计上行（Mbps）', inputField('expected_up_mbps', draft.expected_up_mbps, { type: 'number', min: 0 }))}${formField('上线时间段', inputField('advanced.link_time', advanced.link_time, { placeholder: '00:00-23:59' }))}${switchField('advanced.default_route', advanced.default_route, '默认路由', '优先作为默认出口')}${switchField('advanced.failover', advanced.failover, '参与故障转移', '线路异常时参与切换策略')}${switchField('advanced.health_check.enabled', health.enabled, '线路健康检查', '按目标持续验证可用性')}${health.enabled ? dependentMarkup(`${formField('探测方式', selectField('advanced.health_check.mode', health.mode, [['ping', 'Ping'], ['dns', 'DNS'], ['http', 'HTTP']]))}${formField('探测目标', inputField('advanced.health_check.targets_text', asArray(parseJsonValue(health.targets_json, [])).join(', ')), '多个目标使用逗号分隔')}`) : ''}${switchField('smart_queue', draft.smart_queue, '智能队列')}${switchField('upnp', draft.upnp, 'UPnP')}${switchField('ddns', draft.ddns, '动态 DNS')}</div>`;
    const protocol = `${switchField('vlan_enabled', draft.vlan_enabled, 'WAN VLAN', '在物理接口上绑定运营商 VLAN')}${draft.vlan_enabled ? dependentMarkup(formField('VLAN ID', inputField('vlan_id', draft.vlan_id, { type: 'number', min: 1, max: 4094 }))) : ''}${mode === 'dhcp' ? dependentMarkup(`${formField('Hostname / Option 12', inputField('advanced.dhcp.hostname', dhcp.hostname))}${formField('Vendor Class / Option 60', inputField('advanced.dhcp.vendor_class', dhcp.vendor_class))}${formField('Client ID / Option 61', inputField('advanced.dhcp.client_id', dhcp.client_id))}`, 'is-protocol-options') : ''}${mode === 'pppoe' ? dependentMarkup(`${formField('AC 名称', inputField('advanced.pppoe.ac', pppoe.ac))}${formField('AC MAC', inputField('advanced.pppoe.ac_mac', pppoe.ac_mac))}${formField('服务名称', inputField('advanced.pppoe.service', pppoe.service))}${switchField('advanced.pppoe.timing_restart', pppoe.timing_restart, '定时重拨')}${pppoe.timing_restart ? `${formField('重拨时间', inputField('advanced.pppoe.restart_time', pppoe.restart_time, { placeholder: '04:00' }))}${formField('重拨星期', inputField('advanced.pppoe.restart_week', pppoe.restart_week, { placeholder: '1234567' }))}` : ''}${switchField('advanced.pppoe.abnormal_ip_check', pppoe.abnormal_ip_check, '异常 IP 检测')}${pppoe.abnormal_ip_check ? formField('异常地址前缀', inputField('advanced.pppoe.abnormal_ip_prefixes', pppoe.abnormal_ip_prefixes)) : ''}`, 'is-protocol-options') : ''}`;
    const lines = asArray(draft.hybrid_lines);
    const multi = draft.pppoe_multi || {};
    const bond = draft.bond || {};
    const unsupported = `<div class="network-interface-capability-stack">${hybridCapabilityMarkup(lines, hybridWrite)}${multiDialCapabilityMarkup(multi, multiWrite)}${bondingCapabilityMarkup(bond, bondWrite)}</div>`;
    return `<div class="network-interface-editor-panel">${editorGroup('identity', '身份与物理接入', '线路名称、运营商和物理网卡', 'internet', identity)}${editorGroup('access', '上网方式', 'DHCP、静态、PPPoE 或混合模式', 'globe', access)}${editorGroup('ipv6', 'IPv6', draft.ipv6_mode === 'disabled' ? '当前关闭' : draft.ipv6_mode, 'internet', ipv6)}${editorGroup('routing', '路由与健康', '优先级、带宽、故障转移与检测', 'route', routing)}${editorGroup('protocol', '高级协议选项', 'VLAN、DHCP Option 与 PPPoE 高级参数', 'activity', protocol)}${editorGroup('hybrid', '混合、多拨与聚合', 'LuCI 扩展能力与后端可用性', 'layers', unsupported, { badge: hybridWrite || multiWrite || bondWrite ? '部分可用' : '只读' })}</div>`;
  }

  function portsDrawerMarkup(row) {
    const selected = new Set(isWan ? [state.draft.device].filter(Boolean) : state.draft.ports || []);
    const available = assignablePorts(row.id);
    return `<section class="network-interface-port-picker">
      <p>${isWan ? '为该 WAN 选择一个物理接口。' : '选择加入该 LAN 网桥的物理端口。'}</p>
      <div>${available.length ? available.map((port) => `<label class="${selected.has(port.name) ? 'is-selected' : ''}"><input type="${isWan ? 'radio' : 'checkbox'}" name="network-interface-port" value="${escapeHtml(port.name)}" ${selected.has(port.name) ? 'checked' : ''} data-interface-port><span>${icon('ports')}<strong>${escapeHtml(port.label)}</strong><small>${escapeHtml([port.ownerId, port.status, port.speed, port.localMac].filter(Boolean).join(' · ') || '未提供运行状态')}</small></span></label>`).join('') : '<div class="dwrt-kit-table-empty">后端未返回可用物理端口</div>'}</div>
    </section>`;
  }

  function deleteConfirmationMarkup(row) {
    const protectedLan = !isWan && row.id === 'lan';
    const unavailable = !isWan;
    const canDelete = isWan && row.id && state.rows.length > 1;
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    if (typeof renderer !== 'function') return '';
    return renderer({
      id: 'network-interface-delete-confirm',
      action: `delete-${kind}`,
      tone: 'danger',
      title: `删除 ${row.name || kind.toUpperCase()}`,
      description: protectedLan
        ? '默认 LAN 是当前管理网络，不能从此页面删除。'
        : unavailable
          ? '当前 Web API 尚未提供 LAN 删除路由，此操作不会伪造成成功。'
          : state.rows.length <= 1
            ? '至少需要保留一条 WAN，当前线路不能删除。'
            : '删除后会移除该线路及其关联配置，此操作不可撤销。',
      cancelLabel: '取消',
      confirmLabel: state.saving ? '正在删除' : '确认删除',
      disabled: !canDelete || state.saving,
      icon: icon('warning')
    });
  }

  function drawerMarkup() {
    if (!showDrawers || !state.drawer) return '';
    const row = state.rows.find((entry) => entry.id === state.selectedId) || state.draft;
    if (state.drawer === 'delete') return deleteConfirmationMarkup(row);
    const editing = ['edit', 'create'].includes(state.drawer);
    const title = state.drawer === 'create' ? `新建 ${kind.toUpperCase()}` : state.drawer === 'ports' ? '物理接口' : `编辑 ${row.name || kind.toUpperCase()}`;
    const body = editing ? (isWan ? wanEditorMarkup(state.draft) : lanEditorMarkup(state.draft)) : portsDrawerMarkup(row);
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-interface-close aria-label="关闭配置面板"></button>
      <aside class="network-interface-drawer dwrt-kit-sheet is-open" aria-label="${escapeHtml(title)}">
        <header class="dwrt-kit-sheet-header"><div><span>${isWan ? '外网线路配置' : '本地网络配置'}</span><strong>${escapeHtml(title)}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-interface-close aria-label="关闭">${icon('close')}</button></header>
        <div class="dwrt-kit-sheet-body network-interface-drawer-body" data-interface-drawer-scroll>${body}${state.notice ? `<div class="network-interface-notice is-${escapeHtml(state.noticeTone || 'info')}">${escapeHtml(state.notice)}</div>` : ''}</div>
        <footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-interface-close>取消</button>
          ${editing ? `<button class="policy-primary" type="button" data-interface-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存'}</button>` : ''}
          ${state.drawer === 'ports' ? `<button class="policy-primary" type="button" data-interface-save-ports ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存端口'}</button>` : ''}
        </footer>
      </aside>`;
  }

  function render() {
    if (!root) return;
    const tableScroll = root.querySelector('[data-interface-scroll]');
    const tableTop = tableScroll?.scrollTop || 0;
    const tableLeft = tableScroll?.scrollLeft || 0;
    const drawerScroll = root.querySelector('[data-interface-drawer-scroll]')?.scrollTop || 0;
    root.hidden = false;
    root.className = root.className.split(/\s+/).filter((name) => name && !['policy-table-route-host', 'routing-table-route-host', 'global-config-route-host', 'network-interface-route-host', 'is-lan', 'is-wan'].includes(name)).join(' ');
    root.classList.add('route-workspace', 'network-interface-route-host', `is-${kind}`);
    root.classList.toggle('is-embedded', embedded);
    const pageNotice = state.notice && !state.drawer
      ? `<div class="network-interface-notice is-${escapeHtml(state.noticeTone || 'info')}" role="status">${escapeHtml(state.notice)}</div>`
      : '';
    root.innerHTML = `<section class="network-interface-shell ${embedded ? 'is-embedded' : ''} ${showOverview && !showTable ? 'is-overview-only' : ''} ${showTable && !showOverview ? 'is-table-only' : ''}">${toolbarMarkup()}${pageNotice}${showOverview ? overviewMarkup() : ''}${showTable ? tableMarkup() : ''}${drawerMarkup()}</section>`;
    const nextTable = root.querySelector('[data-interface-scroll]');
    if (nextTable) { nextTable.scrollTop = tableTop; nextTable.scrollLeft = tableLeft; }
    const nextDrawer = root.querySelector('[data-interface-drawer-scroll]');
    if (nextDrawer) nextDrawer.scrollTop = drawerScroll;
    ui.mountAll?.(root);
    ui.scheduleGlassCardsRender?.(180);
  }

  function patchSearchResults() {
    if (!showTable) return;
    const table = root?.querySelector('.network-interface-table-card');
    if (!table) { render(); return; }
    const template = document.createElement('template');
    template.innerHTML = tableMarkup();
    const fresh = template.content.firstElementChild;
    const scroll = table.querySelector('[data-interface-scroll]');
    const top = scroll?.scrollTop || 0;
    const left = scroll?.scrollLeft || 0;
    table.replaceWith(fresh);
    const next = root.querySelector('[data-interface-scroll]');
    if (next) { next.scrollTop = top; next.scrollLeft = left; }
    ui.mountAll?.(root);
  }

  function patchDrawerContents(returnField = '') {
    const drawer = root?.querySelector('.network-interface-drawer');
    if (!drawer) { render(); return; }
    const scrollTop = drawer.querySelector('[data-interface-drawer-scroll]')?.scrollTop || 0;
    const template = document.createElement('template');
    template.innerHTML = drawerMarkup();
    const fresh = template.content.querySelector('.network-interface-drawer');
    const nextBody = fresh?.querySelector('.network-interface-drawer-body');
    const nextFooter = fresh?.querySelector('.dwrt-kit-sheet-footer');
    const body = drawer.querySelector('.network-interface-drawer-body');
    const footer = drawer.querySelector('.dwrt-kit-sheet-footer');
    if (!fresh || !nextBody || !nextFooter || !body || !footer) { render(); return; }
    body.replaceWith(nextBody);
    footer.replaceWith(nextFooter);
    nextBody.scrollTop = scrollTop;
    ui.mountAll?.(drawer);
    if (returnField) {
      requestAnimationFrame(() => {
        const field = drawer.querySelector(`[data-interface-field="${CSS.escape(returnField)}"]`);
        if (field instanceof HTMLElement) field.focus({ preventScroll: true });
      });
    }
  }

  function openDrawer(mode, id = '') {
    state.returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    state.drawer = mode;
    state.selectedId = id;
    state.notice = '';
    state.noticeTone = '';
    state.fieldErrors = {};
    state.editorOpen = 'identity';
    const row = state.rows.find((entry) => entry.id === id);
    if (mode === 'create') state.draft = isWan ? blankWan() : blankLan();
    else if (row) state.draft = clone(row);
    state.initial = clone(state.draft);
    render();
  }

  function closeDrawer() {
    const returnFocus = state.returnFocus;
    state.drawer = '';
    state.selectedId = '';
    state.draft = {};
    state.initial = {};
    state.notice = '';
    state.noticeTone = '';
    state.saving = false;
    state.returnFocus = null;
    render();
    requestAnimationFrame(() => {
      if (returnFocus?.isConnected) returnFocus.focus({ preventScroll: true });
    });
  }

  function setDeep(target, path, value) {
    const parts = String(path).split('.');
    let cursor = target;
    while (parts.length > 1) {
      const part = parts.shift();
      if (!cursor[part] || typeof cursor[part] !== 'object') cursor[part] = {};
      cursor = cursor[part];
    }
    cursor[parts[0]] = value;
  }

  function patchDraft(field, input) {
    let value = input.type === 'checkbox' ? input.checked : input.type === 'number' ? (input.value === '' ? '' : Number(input.value)) : input.value;
    if (field === 'extra_ips_text') {
      state.draft.extra_ips = String(value).split(',').map((entry) => entry.trim()).filter(Boolean);
      return;
    }
    if (['dns_text', 'dhcp.dns_text', 'ipv6.dns_text', 'ipv6.parent_text', 'advanced.health_check.targets_text', 'pppoe_multi.check_week_text', 'bond.members_text'].includes(field)) {
      const list = String(value).split(',').map((entry) => entry.trim()).filter(Boolean);
      if (field === 'dns_text') state.draft.dns = list;
      else if (field === 'dhcp.dns_text') state.draft.dhcp.dns = list;
      else if (field === 'ipv6.dns_text') state.draft.ipv6.dns6 = list;
      else if (field === 'ipv6.parent_text') state.draft.ipv6.parent_wans = list;
      else if (field === 'pppoe_multi.check_week_text') state.draft.pppoe_multi.check_week = String(value).split('').filter(Boolean);
      else if (field === 'bond.members_text') state.draft.bond.members_json = JSON.stringify(list);
      else state.draft.advanced.health_check.targets_json = JSON.stringify(list);
      return;
    }
    if (field === 'address.ip' || field === 'address.prefix') {
      const address = state.draft.addresses[0] || { primary: true, is_primary: true };
      address[field.endsWith('.ip') ? 'ip' : 'prefix'] = value;
      state.draft.addresses = [address];
      return;
    }
    setDeep(state.draft, field, value);
    if (!isWan && field === 'ipaddr') {
      if (!state.draft.dhcp.gateway || state.draft.dhcp.gateway === state.initial.ipaddr) state.draft.dhcp.gateway = value;
    }
  }

  function lanPayload() {
    const draft = clone(state.draft);
    const ip = firstText(draft.ipaddr);
    const prefix = firstNumber(draft.cidr, 24) || 24;
    const extra = asArray(draft.extra_ips).map(String).filter(Boolean);
    return {
      id: firstText(draft.id),
      name: firstText(draft.name, draft.id),
      note: firstText(draft.note),
      ifname: firstText(draft.ifname, draft.id),
      device: firstText(draft.device, `br-${draft.id}`),
      mode: firstText(draft.mode, 'bridge'),
      parent: firstText(draft.parent),
      vlan_id: draft.mode === 'bridge' ? '' : firstText(draft.vlan_id),
      mac_clone: firstText(draft.mac_clone),
      speed: String(draft.speed ?? '0'),
      duplex: String(draft.duplex ?? '0'),
      lan_visit: Boolean(draft.lan_visit),
      enabled: Boolean(draft.enabled),
      ports: asArray(draft.ports).map(String),
      addresses: [{ ip, prefix, primary: true, is_primary: true }, ...extra.map((entry) => {
        const [extraIp, extraPrefix] = entry.split('/');
        return { ip: extraIp, prefix: firstNumber(extraPrefix, prefix), primary: false, is_primary: false };
      })],
      dhcp: {
        enabled: Boolean(draft.dhcp.enabled),
        pool: `${firstText(draft.dhcp.pool_start)}-${firstText(draft.dhcp.pool_end)}`,
        pool_start: firstText(draft.dhcp.pool_start),
        pool_end: firstText(draft.dhcp.pool_end),
        gateway: firstText(draft.dhcp.gateway, ip),
        dns: asArray(draft.dhcp.dns).filter(Boolean),
        dns_json: JSON.stringify(asArray(draft.dhcp.dns).filter(Boolean)),
        lease: firstNumber(draft.dhcp.lease, 120) || 120
      },
      ipv6: {
        enabled: Boolean(draft.ipv6.enabled),
        parent_wans: asArray(draft.ipv6.parent_wans).filter(Boolean),
        parent_json: JSON.stringify(asArray(draft.ipv6.parent_wans).filter(Boolean)),
        mode: firstText(draft.ipv6.mode, 'dhcp'),
        dhcpv6: Boolean(draft.ipv6.dhcpv6),
        addr: firstText(draft.ipv6.addr),
        use_dns6: Boolean(draft.ipv6.use_dns6),
        dns6: asArray(draft.ipv6.dns6).filter(Boolean),
        dns_json: JSON.stringify(asArray(draft.ipv6.dns6).filter(Boolean)),
        prefix_len: firstText(draft.ipv6.prefix_len, 'auto'),
        ra_flags: firstText(draft.ipv6.ra_flags, '1'),
        ra_static: Boolean(draft.ipv6.ra_static),
        ra_mtu_set: Boolean(draft.ipv6.ra_mtu_set),
        ra_mtu: firstNumber(draft.ipv6.ra_mtu, 1480) || 1480,
        leasetime: firstNumber(draft.ipv6.leasetime, 120) || 120
      }
    };
  }

  function wanPayload() {
    const draft = clone(state.draft);
    const dns = asArray(draft.dns).filter(Boolean);
    const password = firstText(draft.password_input);
    const addresses = draft.access_mode === 'static' ? asArray(draft.addresses).filter((address) => firstText(address.ip)).map((address, index) => ({
      ip: firstText(address.ip),
      prefix: firstNumber(address.prefix, 24) || 24,
      primary: index === 0,
      is_primary: index === 0
    })) : [];
    const advanced = clone(draft.advanced || {});
    advanced.health_check.targets_json = firstText(advanced.health_check?.targets_json, '[]');
    return {
      id: firstText(draft.id),
      name: firstText(draft.name, draft.id),
      note: firstText(draft.note),
      carrier: firstText(draft.carrier),
      ifname: firstText(draft.ifname, draft.id),
      device: firstText(draft.device),
      port_label: firstText(draft.port_label),
      access_mode: firstText(draft.access_mode, 'dhcp'),
      gateway: draft.access_mode === 'static' ? firstText(draft.gateway) : '',
      dns_json: JSON.stringify(dns),
      addresses,
      ipv6_mode: firstText(draft.ipv6_mode, 'disabled'),
      ipv6_addr: firstText(draft.ipv6_addr),
      delegated_prefix: firstText(draft.delegated_prefix),
      vlan_enabled: Boolean(draft.vlan_enabled),
      vlan_id: draft.vlan_enabled ? firstText(draft.vlan_id) : '',
      mtu: firstNumber(draft.mtu, draft.access_mode === 'pppoe' ? 1492 : 1500),
      metric: firstNumber(draft.metric, 10),
      role: firstText(draft.role, 'primary'),
      expected_down_mbps: firstNumber(draft.expected_down_mbps),
      expected_up_mbps: firstNumber(draft.expected_up_mbps),
      smart_queue: Boolean(draft.smart_queue),
      upnp: Boolean(draft.upnp),
      ddns: Boolean(draft.ddns),
      enabled: Boolean(draft.enabled),
      username: draft.access_mode === 'pppoe' ? firstText(draft.username) : '',
      password_ref: draft.access_mode === 'pppoe' ? firstText(password, draft.password_ref) : '',
      ...(state.capabilities.hybrid_wan_write === true ? { hybrid_lines: asArray(draft.hybrid_lines) } : {}),
      ...(state.capabilities.pppoe_multi_write === true ? { pppoe_multi: clone(draft.pppoe_multi || {}) } : {}),
      ...(state.capabilities.wan_bonding_write === true ? { bond: clone(draft.bond || {}) } : {}),
      advanced
    };
  }

  function validationMessage(error) {
    const details = asArray(error?.details);
    if (!details.length) return firstText(error?.message, '后端未接受配置');
    return details.map((entry) => firstText(entry.message, entry.error, entry.field)).filter(Boolean).join('；');
  }

  function notifyCommitted() {
    if (typeof context.onCommitted === 'function') context.onCommitted({ kind });
  }

  async function saveDraft() {
    if (state.saving) return;
    state.saving = true;
    state.notice = '';
    patchDrawerContents();
    try {
      const payload = isWan ? wanPayload() : lanPayload();
      const result = await requestJson(ENDPOINT, { method: state.drawer === 'create' ? 'POST' : 'PUT', body: JSON.stringify(payload) });
      state.saving = false;
      state.drawer = '';
      await load(true);
      state.notice = result.applied === true ? '配置已保存并应用' : '配置已保存；后端未返回运行态应用结果';
      state.noticeTone = result.applied === true ? 'ok' : 'warn';
      render();
      notifyCommitted();
    } catch (error) {
      state.saving = false;
      state.notice = `保存失败：${validationMessage(error)}`;
      state.noticeTone = 'bad';
      patchDrawerContents();
    }
  }

  async function savePorts() {
    if (state.saving) return;
    state.saving = true;
    state.notice = '';
    patchDrawerContents();
    try {
      const payload = isWan ? wanPayload() : lanPayload();
      const result = await requestJson(ENDPOINT, { method: 'PUT', body: JSON.stringify(payload) });
      state.saving = false;
      state.drawer = '';
      await load(true);
      state.notice = result.applied === true ? '物理接口已保存并应用' : '物理接口已保存；后端未返回运行态应用结果';
      state.noticeTone = result.applied === true ? 'ok' : 'warn';
      render();
      notifyCommitted();
    } catch (error) {
      state.saving = false;
      state.notice = `端口保存失败：${validationMessage(error)}`;
      state.noticeTone = 'bad';
      patchDrawerContents();
    }
  }

  async function deleteWan() {
    if (!isWan || state.saving || state.rows.length <= 1 || !state.selectedId) return;
    state.saving = true;
    patchDrawerContents();
    try {
      await requestJson(`${ENDPOINT}/${encodeURIComponent(state.selectedId)}`, { method: 'DELETE' });
      state.saving = false;
      state.drawer = '';
      await load(true);
      state.notice = 'WAN 已删除';
      state.noticeTone = 'ok';
      render();
      notifyCommitted();
    } catch (error) {
      state.saving = false;
      state.notice = `删除失败：${validationMessage(error)}`;
      state.noticeTone = 'bad';
      patchDrawerContents();
    }
  }

  async function load(background = false) {
    const seq = ++state.seq;
    if (background) state.refreshing = true;
    else state.loading = true;
    if (!background) render();
    try {
      const [config, ports] = await Promise.all([
        fetchResource(`network_${kind}s`, ENDPOINT),
        fetchResource('network_ports', '/api/v1/network/ports').catch(() => ({}))
      ]);
      if (!state.mounted || seq !== state.seq) return;
      applyData(config, ports);
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      state.notice = `读取失败：${firstText(error?.message, '接口不可用')}`;
      state.noticeTone = 'bad';
      render();
    }
  }

  function onClick(event) {
    const create = event.target.closest('[data-interface-create]');
    if (create) { openDrawer('create'); return; }
    const close = event.target.closest('[data-interface-close], [data-dwrt-confirm-cancel]');
    if (close) { closeDrawer(); return; }
    const edit = event.target.closest('[data-interface-edit]');
    if (edit) { openDrawer('edit', edit.dataset.interfaceEdit); return; }
    const editorToggle = event.target.closest('[data-interface-editor-toggle]');
    if (editorToggle) {
      const next = editorToggle.dataset.interfaceEditorToggle;
      state.editorOpen = state.editorOpen === next ? '' : next;
      root.querySelectorAll('[data-interface-editor-group]').forEach((group) => {
        const trigger = group.querySelector('[data-interface-editor-toggle]');
        const groupId = trigger?.dataset.interfaceEditorToggle || '';
        const panelId = trigger?.getAttribute('aria-controls') || '';
        const panel = panelId ? root.querySelector(`#${CSS.escape(panelId)}`) : null;
        const open = state.editorOpen === groupId;
        trigger?.setAttribute('aria-expanded', String(open));
        group.classList.toggle('is-open', open);
        if (panel) panel.hidden = !open;
      });
      return;
    }
    const addAddress = event.target.closest('[data-interface-address-add]');
    if (addAddress) {
      state.draft.addresses = [...asArray(state.draft.addresses), { ip: '', prefix: 24, primary: false, is_primary: false }];
      patchDrawerContents();
      return;
    }
    const removeAddress = event.target.closest('[data-interface-address-remove]');
    if (removeAddress) {
      const index = Number(removeAddress.dataset.interfaceAddressRemove);
      state.draft.addresses = asArray(state.draft.addresses).filter((_, addressIndex) => addressIndex !== index).map((address, addressIndex) => ({ ...address, primary: addressIndex === 0, is_primary: addressIndex === 0 }));
      patchDrawerContents();
      return;
    }
    const remove = event.target.closest('[data-interface-delete]');
    if (remove) { openDrawer('delete', remove.dataset.interfaceDelete); return; }
    if (event.target.closest('[data-interface-save]')) { saveDraft(); return; }
    if (event.target.closest('[data-interface-save-ports]')) { savePorts(); return; }
    if (event.target.closest('[data-dwrt-confirm-accept]')) { deleteWan(); }
  }

  function onInput(event) {
    const search = event.target.closest('[data-interface-search]');
    if (search) {
      state.query = search.value;
      patchSearchResults();
      return;
    }
    const addressField = event.target.closest('[data-interface-address-field]');
    if (addressField) {
      const index = Number(addressField.dataset.interfaceAddressIndex);
      const addresses = asArray(state.draft.addresses);
      if (!addresses[index]) return;
      addresses[index][addressField.dataset.interfaceAddressField] = addressField.type === 'number' ? Number(addressField.value || 0) : addressField.value;
      state.draft.addresses = addresses;
      return;
    }
    const field = event.target.closest('[data-interface-field]');
    if (!field || ['checkbox', 'radio'].includes(field.type) || field.tagName === 'SELECT') return;
    patchDraft(field.dataset.interfaceField, field);
  }

  function onChange(event) {
    const port = event.target.closest('[data-interface-port]');
    if (port) {
      if (isWan) state.draft.device = port.value;
      else {
        const selected = new Set(state.draft.ports || []);
        if (port.checked) selected.add(port.value); else selected.delete(port.value);
        state.draft.ports = [...selected];
      }
      port.closest('label')?.classList.toggle('is-selected', port.checked);
      if (isWan) {
        root.querySelectorAll('[data-interface-port]').forEach((entry) => {
          entry.closest('label')?.classList.toggle('is-selected', entry.checked);
        });
      }
      return;
    }
    const field = event.target.closest('[data-interface-field]');
    if (!field) return;
    patchDraft(field.dataset.interfaceField, field);
    const conditional = ['access_mode', 'mode', 'dhcp.enabled', 'ipv6.enabled', 'ipv6.use_dns6', 'ipv6.ra_mtu_set', 'ipv6_mode', 'advanced.health_check.enabled', 'advanced.pppoe.timing_restart', 'advanced.pppoe.abnormal_ip_check', 'vlan_enabled'].includes(field.dataset.interfaceField);
    if (conditional) patchDrawerContents(field.dataset.interfaceField);
  }

  root.addEventListener('click', onClick);
  root.addEventListener('input', onInput);
  root.addEventListener('change', onChange);
  render();
  if (context.initialDataReady && context.initialData) applyData(context.initialData.config, context.initialData.ports);
  else if (context.deferLoad === true) render();
  else load();
  startPolling();

  return {
    setQuery(value) {
      const next = String(value || '');
      if (next === state.query) return;
      state.query = next;
      patchSearchResults();
    },
    refresh() {
      return load(true);
    },
    openCreate() {
      openDrawer('create');
    },
    setData(config, ports) {
      applyData(config, ports);
    },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      stopPolling();
      root.removeEventListener('click', onClick);
      root.removeEventListener('input', onInput);
      root.removeEventListener('change', onChange);
      root.replaceChildren();
      root.classList.remove('network-interface-route-host', 'is-lan', 'is-wan', 'route-workspace', 'is-embedded');
    }
  };
}

export default { mount };
