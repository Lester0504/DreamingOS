export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const item = context.item || {};
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));
  const VERSION = '20260806-lan-delete-gate-01';
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
    /* 正在重连的 WAN id，用于给该行一个进行态（拨号可能十几秒）。 */
    reconnecting: '',
    seq: 0,
    returnFocus: null,
    editorOpen: isWan ? 'identity' : 'identity',
    tableStale: false,
    /* 宿主（全局配置页）喂进来的真实 WAN 名单，供 IPv6 上游 WAN 下拉使用。 */
    wanNames: asArray(context.wanNames),
    pollTimer: 0
  };

  /* 区分同页并存的 LAN / WAN 实例，供 document 层事件归属判断与抽屉标记使用。 */
  const instanceId = `${kind}-${Math.random().toString(36).slice(2, 8)}`;

  /*
   * 抽屉可能已经被 kit 搬进 body 下的 portal，所以查它不能只看 root。先在 root 内找
   * （尚未 mountAll 的那一帧），再按 owner 标记去整个文档里找本实例的那一个。
   */
  function drawerNode() {
    return root?.querySelector('.network-interface-drawer')
      || document.querySelector(`.network-interface-drawer[data-interface-owner="${instanceId}"]`)
      || null;
  }

  function drawerQuery(selector) {
    return root?.querySelector(selector) || drawerNode()?.querySelector(selector) || null;
  }

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
      /* 错误码单独留一份：删除被拒时要靠它翻成人话，只看 message 拿到的是原始字面量。 */
      error.code = firstText(payload?.error, payload?.code, json?.error, json?.code);
      error.status = response.status;
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
    /*
     * 抽屉开着时不许重绘。render() 是 root.innerHTML 整页重建，会连抽屉一起
     * 换掉：手风琴的展开态、正在输入的字段、焦点和光标全部丢失。内嵌进全局配置
     * 时宿主每 20s 喂一次 setData()，宿主只检查自己的 state.drawer、看不到内嵌
     * 实例的抽屉，于是用户点开编辑 LAN 停留超过 20s 就必然被打断一次 —— 这正是
     * “点一下里面的东西整个抽屉重新加载”和周期性闪烁的来源。
     * 抽屉打开期间只让新数据落进 state.rows / state.ports（端口选择器下一次
     * patchDrawerContents() 会用到），底表留到抽屉关闭时再补。
     */
    if (state.drawer) {
      state.tableStale = true;
    } else {
      render();
    }
    if (typeof context.onDataChange === 'function') {
      context.onDataChange({ kind, rows: state.rows, ports: state.ports, capabilities: state.capabilities });
    }
  }

  /*
   * 物理口候选。这里原来把「已被别人占用」的口直接 filter 掉，结果新建 WAN 时四个口
   * 全部归属已有 WAN，列表渲染成「后端未返回可用物理端口」—— 用户既选不到口，也看不出
   * 为什么，最后提交一个 device 为空的 payload，被后端 wan.device=missing 拒掉，
   * 表现就是用户报的那个不明所以的保存失败。
   * 现在改为全部返回并带上归属信息：自己的口可选，别人的口保留在列表里但禁用并写清
   * 占用者，让「为什么不能选」这件事显示在界面上而不是靠猜。
   */
  function annotatedPorts(ownerId = '') {
    const self = firstText(ownerId);
    return state.ports.map((port) => {
      const ownerType = firstText(port.ownerType).toLowerCase();
      const currentOwner = firstText(port.ownerId);
      const free = !ownerType || !currentOwner;
      const mine = ownerType === kind && currentOwner === self && Boolean(self);
      return { ...port, free, mine, takenBy: free || mine ? '' : currentOwner, takenByType: free || mine ? '' : ownerType };
    });
  }

  function assignablePorts(ownerId = '') {
    return annotatedPorts(ownerId).filter((port) => port.free || port.mine);
  }

  /*
   * 同一块物理网卡被两个接口同时声明时，界面必须说出来。现实里已经出现过：uci 里
   * 已无 lan2，但 network/lans 仍返回 lan2 占着 eth3，而 eth3 在 network/ports 与
   * network/wans 里都归 wan3。静默二选一显示会让用户以为删掉的网络又回来了。
   * 判据只用后端自己给的两份数据：ports 的 owner_type/owner_id 与本页 rows 的引用。
   */
  function portConflicts() {
    const claims = new Map();
    const claim = (portName, holder, holderType) => {
      const name = firstText(portName);
      if (!name) return;
      if (!claims.has(name)) claims.set(name, []);
      const list = claims.get(name);
      const label = `${holderType}:${holder}`;
      if (!list.includes(label)) list.push(label);
    };
    state.ports.forEach((port) => {
      if (firstText(port.ownerId)) claim(port.name, firstText(port.ownerId), firstText(port.ownerType) || 'port');
    });
    state.rows.forEach((row) => {
      if (isWan) claim(row.device, firstText(row.id), 'wan');
      else asArray(row.ports).forEach((name) => claim(name, firstText(row.id), 'lan'));
    });
    return [...claims.entries()]
      .filter(([, holders]) => holders.length > 1)
      .map(([name, holders]) => ({ port: name, holders }));
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

  /*
   * 重连能力开关。后端还没有这条路由，所以只认 capability，不做「先打过去试试」——
   * 未注册的写路由会被权限层以 403 挡下（jmx_app_perms.c 的 fail-closed 默认），
   * 那个 403 和「有路由但无权限」长得一模一样，用它判断能力会得出错误结论。
   */
  function reconnectEnabled() {
    return state.capabilities.wan_reconnect === true;
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
      <td>${escapeHtml(row.vlan_id || '默认')}</td>
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
    /*
     * 重连入口。后端目前没有 POST /api/v1/network/wans/{id}/reconnect（源码里 WAN 的
    /*
     * 重连入口。后端目前没有 POST /api/v1/network/wans/{id}/reconnect（源码里 WAN 的
     * 子路由只有 /dns-policy），所以按钮在 capability 出现之前保持禁用并说明原因 ——
     * 放一个点了没反应、或者假装成功的按钮，比没有按钮更糟。
     * 后端交付后只要 capabilities.wan_reconnect 为 true，这里自动变可用，无需再改。
     */
    const reconnect = isWan
      ? `<button type="button" class="${state.reconnecting === row.id ? 'is-busy' : ''}" data-interface-reconnect="${escapeHtml(row.id)}" ${reconnectEnabled() && row.enabled && state.reconnecting !== row.id ? '' : 'disabled'} aria-label="重连 ${escapeHtml(row.name)}" data-dwrt-tooltip="${reconnectEnabled() ? (row.enabled ? '断线重连' : '线路已停用，无法重连') : '后端尚未提供 WAN 重连接口（capability wan_reconnect 未开启）'}">${icon(state.reconnecting === row.id ? 'activity' : 'refresh')}</button>`
      : '';
    return `<span class="network-interface-row-actions">
      ${reconnect}
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

  /*
   * 字段级错误。后端 wan_config_validate / lan_config_validate 早就返回
   * errors[{field,reason,message}]（field 形如 "wan.device"、"lan.ipaddr"、
   * "wan.dns[0]"），requestJson 也已经把它接进 error.details，但此前只被
   * validationMessage 拼成一句话丢进抽屉底部的通知里 —— 用户看到的就是一句
   * 不指明位置的失败。这里把 field 映射回表单控件的 data-interface-field 路径，
   * 直接标在出错的那一项上。
   */
  const FIELD_ERROR_ALIASES = {
    device: 'device',
    ipaddr: 'ipaddr',
    dns: 'dns_text',
    'dhcp.dns': 'dhcp.dns_text',
    'health_check.targets': 'advanced.health_check.targets_text'
  };

  /*
   * 后端 reason 是稳定的机器码，message 是英文。页面其余部分是中文，直接把英文原文
   * 贴到字段旁边会很突兀，所以按 reason 给中文说法，认不出的 reason 才退回后端原文
   * （宁可显示英文，也不要吞掉一个我们没预料到的校验失败）。
   */
  const FIELD_ERROR_TEXT = {
    missing: '此项为必填',
    invalid: '取值不在允许范围内',
    invalid_ip: '需要填写合法的 IPv4 地址',
    invalid_uci_section: '只能使用字母、数字或下划线',
    out_of_range: '数值超出允许范围',
    invalid_range: '地址池范围不合法',
    outside_subnet: '地址不在本网段内',
    no_primary: '至少需要一个主地址',
    multiple_primary: '只能有一个主地址',
    unsupported_write: '后端当前不支持写入此项'
  };

  function fieldErrorText(entry) {
    const reason = firstText(entry?.reason);
    return firstText(FIELD_ERROR_TEXT[reason], entry?.message, entry?.error, '该项未被后端接受');
  }

  /*
   * 把 error.details 摊成 { 表单字段路径: 中文说明 }。同一字段多条只留第一条 ——
   * 字段旁边塞两行反而看不清该改什么。返回未能落到具体字段的条目，交给顶部通知兜住，
   * 否则一条认不出 field 的错误会被完全丢掉。
   */
  function collectFieldErrors(details) {
    const mapped = {};
    const orphans = [];
    asArray(details).forEach((entry) => {
      const key = fieldErrorKey(entry?.field);
      const text = fieldErrorText(entry);
      if (!key) { orphans.push(text); return; }
      if (!mapped[key]) mapped[key] = text;
    });
    return { mapped, orphans };
  }

  /* 出错的字段可能折在没展开的分组里，保存失败后要把第一处错误所在的分组打开。 */
  const FIELD_GROUP_HINTS = isWan
    ? [
      [/^(id|name|note|carrier|carrier_custom|ifname|device)/, 'identity'],
      [/^(access_mode|username|password_input|gateway|dns_text|addresses)/, 'access'],
      [/^(ipv6)/, 'ipv6'],
      [/^(mtu|metric|role|expected_|advanced\.link_time|advanced\.default_route|advanced\.failover|advanced\.health_check|smart_queue|upnp|ddns)/, 'routing'],
      [/^(vlan_|advanced\.dhcp|advanced\.pppoe)/, 'protocol'],
      [/^(hybrid_lines|pppoe_multi|bond)/, 'hybrid']
    ]
    : [
      [/^(id|name|note|device|ifname|mode|vlan_|ports)/, 'identity'],
      [/^(ipaddr|cidr|extra_ips|addresses)/, 'addressing'],
      [/^(dhcp)/, 'dhcp'],
      [/^(ipv6)/, 'ipv6'],
      [/^(lan_visit|mac|mtu)/, 'link']
    ];

  function groupForField(field) {
    const hit = FIELD_GROUP_HINTS.find(([pattern]) => pattern.test(field));
    return hit ? hit[1] : '';
  }

  function fieldErrorKey(field) {
    /* 去掉 "wan." / "lan." 前缀和数组下标，落到表单里真实存在的那个字段路径。 */
    const raw = firstText(field).replace(/^(wan|lan)\./, '').replace(/\[\d+\]$/, '');
    return FIELD_ERROR_ALIASES[raw] || raw;
  }

  function fieldError(field) {
    return state.fieldErrors[field] || '';
  }

  function formField(label, control, detail = '', modifier = '') {
    const match = /data-interface-field="([^"]+)"/.exec(control);
    const error = match ? fieldError(match[1]) : '';
    return `<label class="network-interface-field ${modifier} ${error ? 'is-invalid' : ''}"><span>${escapeHtml(label)}</span>${control}${error ? `<em class="network-interface-field-error" role="alert">${escapeHtml(error)}</em>` : ''}${detail ? `<small>${escapeHtml(detail)}</small>` : ''}</label>`;
  }

  function inputField(field, value, options = {}) {
    const type = options.type || 'text';
    return `<input type="${type}" data-interface-field="${escapeHtml(field)}" value="${escapeHtml(value ?? '')}" ${options.placeholder ? `placeholder="${escapeHtml(options.placeholder)}"` : ''} ${options.min !== undefined ? `min="${options.min}"` : ''} ${options.max !== undefined ? `max="${options.max}"` : ''} ${options.disabled ? 'disabled' : ''}>`;
  }

  function selectField(field, value, options = [], attributes = {}) {
    return `<select data-interface-field="${escapeHtml(field)}" ${attributes.disabled ? 'disabled' : ''}>${options.map(([key, label, disabled]) => `<option value="${escapeHtml(key)}" ${String(value) === String(key) ? 'selected' : ''} ${disabled ? 'disabled' : ''}>${escapeHtml(label)}</option>`).join('')}</select>`;
  }

  /*
   * 逻辑接口是 UCI 的 network 段名，取值范围由现有配置和物理口决定，让用户手打
   * 只会打错（写成不存在的名字、和别的接口撞名、大小写空格出入）。后端
   * `network/<kind>s/capabilities` 目前是空对象，没有下发候选集，所以候选从已知
   * 事实拼：本接口当前值 + 自身 id（新建时后端就是拿 id 兜底的，见 lanPayload/
   * wanPayload 的 `firstText(draft.ifname, draft.id)`）+ 同类接口已用的名字（标记
   * 已占用，不可选）。
   *
   * 物理口名此前也被塞进这个下拉，于是 eth1/eth2 和 wan/wan2 混在一起，用户根本
   * 分不清该选哪个 —— 那是交接单第一条点名的问题。物理口现在由上方独立的物理网卡
   * 选择器负责，这里只留 UCI 段名。
   */
  function ifnameOptions(draft) {
    const current = firstText(draft.ifname);
    const selfId = firstText(draft.id);
    const takenBy = new Map();
    state.rows.forEach((row) => {
      const name = firstText(row.ifname, row.id);
      if (!name || row.id === selfId) return;
      takenBy.set(name, firstText(row.name, row.id));
    });
    const seen = new Set();
    const options = [];
    const push = (value, label, disabled = false) => {
      const key = firstText(value);
      if (!key || seen.has(key)) return;
      seen.add(key);
      options.push([key, label, disabled]);
    };
    if (current) push(current, `${current}（当前）`);
    push(selfId, `${selfId}（跟随${isWan ? '线路' : '网络'} ID）`);
    state.rows.forEach((row) => {
      const name = firstText(row.ifname, row.id);
      if (!name) return;
      const owner = takenBy.get(name);
      push(name, owner ? `${name}（已被 ${owner} 占用）` : name, Boolean(owner));
    });
    return options;
  }

  function switchField(field, checked, title, detail = '') {
    return `<label class="network-interface-switch-row"><span><strong>${escapeHtml(title)}</strong>${detail ? `<small>${escapeHtml(detail)}</small>` : ''}</span><input type="checkbox" data-interface-field="${escapeHtml(field)}" ${checked ? 'checked' : ''}><i></i></label>`;
  }

  /*
   * 运营商改成选择而不是填写。用户填错拼写只会在保存后换来一句看不懂的失败。
   * 取值集合与本页 carrierLabel()/carrierLogo() 已经识别的那套 key 对齐（unicom /
   * cmcc / ctcc / cernet），这样选完立刻能拿到正确的中文名与图标。
   * 后端 wan.carrier 是自由 TEXT、无枚举约束（jmx_netconfig_db.c 建表处），所以
   * 保留「其他」+ 自由输入，避免把用户真实存在的小运营商挡在外面 —— 交接单要求的
   * 「未就绪前至少有客户端校验与合法值提示」在这里由固定选项本身完成。
   */
  const CARRIER_OPTIONS = [
    ['', '未指定'],
    ['unicom', '中国联通'],
    ['cmcc', '中国移动'],
    ['ctcc', '中国电信'],
    ['cernet', '教育网'],
    ['__custom__', '其他（手动填写）']
  ];

  /*
   * 已保存的值可能是 mobile/telecom 这类别名，归一到下拉里真实存在的那个 option。
   * `carrier_custom` 是纯界面状态：用户刚选「其他」时 carrier 还是空的，只看值会把
   * 它读回「未指定」，自由输入框就永远出不来，所以选择意图要单独记一笔。
   */
  function carrierSelectValue(draft) {
    const raw = firstText(draft.carrier);
    if (draft.carrier_custom === true) return '__custom__';
    if (!raw) return '';
    const key = raw.toLowerCase().replace(/[\s_-]+/g, '');
    if (['unicom', 'chinaunicom', 'cucc'].includes(key)) return 'unicom';
    if (['mobile', 'chinamobile', 'cmcc'].includes(key)) return 'cmcc';
    if (['telecom', 'chinatelecom', 'ctcc'].includes(key)) return 'ctcc';
    if (['cernet', 'edu', 'education'].includes(key)) return 'cernet';
    return '__custom__';
  }

  function carrierField(draft) {
    const selected = carrierSelectValue(draft);
    const custom = selected === '__custom__';
    return `${formField('运营商', selectField('carrier_select', selected, CARRIER_OPTIONS), custom ? '' : '用于线路标识与运营商策略')}${custom ? formField('运营商名称', inputField('carrier', draft.carrier, { placeholder: '例如 广电 / 长城宽带' }), '自定义标识按原样保存') : ''}`;
  }

  /*
   * 上游 WAN 是「从现有 WAN 里挑」，不是自由文本：手打会写出不存在的接口名，
   * 而且后端存的是 JSON 数组（parent_json），本来就有明确的取值集合。
   * 用 <select multiple> 而不是单选，因为 IPv6 委派可以指向多条上游。
   */
  function multiSelectField(field, values, options, attributes = {}) {
    const selected = new Set(asArray(values).map(String));
    const size = Math.min(Math.max(options.length, 2), 5);
    return `<select data-interface-field="${escapeHtml(field)}" data-interface-multi multiple size="${size}" ${attributes.disabled ? 'disabled' : ''}>${options.map(([key, label]) => `<option value="${escapeHtml(key)}" ${selected.has(String(key)) ? 'selected' : ''}>${escapeHtml(label)}</option>`).join('')}</select>`;
  }

  /*
   * WAN 候选优先用宿主喂进来的真实 WAN 列表（全局配置页同时持有两边数据）。
   * 独立路由下没有宿主，退回从端口的 owner_id 推导 —— 只能发现绑了物理口的 WAN，
   * 所以把当前已选值一并并入，避免已配置的上游因为没绑口而从列表里消失。
   */
  function upstreamWanOptions(selectedValues) {
    const names = [];
    const push = (value) => {
      const name = firstText(value);
      if (name && !names.includes(name)) names.push(name);
    };
    asArray(state.wanNames).forEach(push);
    if (!names.length) {
      state.ports.forEach((port) => {
        if (firstText(port.ownerType).toLowerCase() === 'wan') push(port.ownerId);
      });
    }
    asArray(selectedValues).forEach(push);
    return names.map((name) => [name, name]);
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

  /*
   * 归属冲突横幅。只在真的检测到一口多主时出现，并把双方都点出来，而不是替用户
   * 挑一个显示。文案里不作根因判断（前端看不到 uci），只说明现象和处置方向。
   */
  function conflictMarkup() {
    const conflicts = portConflicts();
    if (!conflicts.length) return '';
    const lines = conflicts.map((entry) => `${entry.port} → ${entry.holders.join(' / ')}`).join('；');
    return `<div class="network-interface-notice is-warn network-interface-conflict" role="status">
      <strong>物理口归属冲突</strong>
      <span>${escapeHtml(lines)}</span>
      <small>同一块网卡被多个接口声明，后端两份数据不一致。界面不替你二选一：请核对实际归属后再改，必要时让后端复核该接口是否已残留。</small>
    </div>`;
  }

  /*
   * 端口卡片的说明行按「速率 · 状态 · 归属」排，速率放最前是因为用户挑口时先看 2500M
   * 还是千兆；归属只在被别人占用时才出现，避免每张卡片都重复自己的名字。
   */
  function portCardDetail(port) {
    const parts = [port.speed, port.status].filter(Boolean);
    if (port.takenBy) parts.push(`已被 ${port.takenBy} 占用`);
    else if (port.mine) parts.push('当前占用');
    return parts.join(' · ') || '未提供运行状态';
  }

  function portCardMarkup(port, selected) {
    const disabled = Boolean(port.takenBy);
    return `<label class="${selected ? 'is-selected' : ''} ${disabled ? 'is-taken' : ''}" ${disabled ? `data-dwrt-tooltip="该口已归 ${escapeHtml(port.takenBy)}，请先在对应接口上释放"` : ''}><input type="${isWan ? 'radio' : 'checkbox'}" name="network-interface-${kind}-port" value="${escapeHtml(port.name)}" ${selected ? 'checked' : ''} ${disabled ? 'disabled' : ''} data-interface-port><span>${icon('ports')}<strong>${escapeHtml(port.label)}</strong><small>${escapeHtml(portCardDetail(port))}</small></span></label>`;
  }

  function inlinePortPicker(draft) {
    const selected = new Set(isWan ? [draft.device].filter(Boolean) : asArray(draft.ports));
    const ports = annotatedPorts(draft.id);
    const free = ports.filter((port) => port.free || port.mine);
    const hint = isWan
      ? '选择承载此线路的物理网卡（必填）。端口变更将随本次配置保存。'
      : '选择加入此本地网络的成员端口。';
    const exhausted = isWan && !free.length && ports.length
      ? '<p class="network-interface-inline-note">所有物理口都已被现有线路占用。新建 WAN 需要一块空闲网卡：请先在占用它的线路上释放，或改用 VLAN 混合模式复用同一块口。</p>'
      : '';
    return `<div class="network-interface-port-picker is-inline"><p>${hint}</p>${exhausted}<div>${ports.length ? ports.map((port) => portCardMarkup(port, selected.has(port.name))).join('') : '<div class="dwrt-kit-table-empty">后端未返回可用物理端口</div>'}</div></div>`;
  }

  /*
   * 交接单第一条：物理口和逻辑接口名此前挤在同一个「逻辑接口」下拉里，eth1/eth2 和
   * wan/wan2 混着排，用户分不清该选哪个。它们是两层概念 —— device 是物理网卡，
   * ifname 是 UCI 段名 —— 所以拆成两块带小标题的区域，各自说清自己是什么。
   */
  function subsectionMarkup(title, description, body) {
    return `<section class="network-interface-subsection">
      <header><strong>${escapeHtml(title)}</strong><small>${escapeHtml(description)}</small></header>
      ${body}
    </section>`;
  }

  function physicalPortSection(draft) {
    const error = fieldError('device');
    return subsectionMarkup(
      isWan ? '物理网卡' : '成员端口',
      isWan ? '这条线路的网线插在哪块口上' : '加入此网桥的物理口',
      `${error ? `<div class="network-interface-field-error is-block" role="alert">${escapeHtml(error)}</div>` : ''}${inlinePortPicker(draft)}`
    );
  }

  function logicalNameSection(draft) {
    return subsectionMarkup(
      '逻辑接口名',
      'UCI network 段名，不是物理口；一般保持与 ID 一致即可',
      `<div class="network-interface-form-grid">${formField('接口段名', selectField('ifname', firstText(draft.ifname, draft.id), ifnameOptions(draft)))}</div>`
    );
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
      <div class="network-interface-form-grid">${formField('网络名称', inputField('name', draft.name, { placeholder: '例如 IoT' }), '显示用名称，可随时修改')}${formField('网络 ID', inputField('id', draft.id, { disabled: state.drawer === 'edit' }), '保存后的稳定标识')}${formField('备注', inputField('note', draft.note, { placeholder: '可选' }))}${formField('网桥设备', inputField('device', draft.device, { placeholder: 'br-lan' }), '内核里的网桥名，通常为 br-<ID>')}</div>
      ${conflictMarkup()}
      ${segmentedField('mode', draft.mode, [['bridge', '桥接', '普通本地网络'], ['access', 'VLAN 接入', '单个 VLAN'], ['trunk', 'VLAN Trunk', '承载多个 VLAN']], '网络模式')}
      ${draft.mode !== 'bridge' ? dependentMarkup(formField('VLAN ID', inputField('vlan_id', draft.vlan_id, { type: 'number', min: 1, max: 4094 }), '1-4094')) : ''}
      ${physicalPortSection(draft)}
      ${logicalNameSection(draft)}`;
    const addressing = `<div class="network-interface-form-grid">${formField('网关地址', inputField('ipaddr', draft.ipaddr, { placeholder: '192.168.30.1' }))}${formField('子网前缀', inputField('cidr', draft.cidr, { type: 'number', min: 1, max: 30 }), 'CIDR 前缀')}${formField('扩展 IP', inputField('extra_ips_text', asArray(draft.extra_ips).join(', '), { placeholder: '192.168.50.1/24, 192.168.60.1/24' }), '多个地址使用逗号分隔')}</div>`;
    const dhcpBody = `${switchField('dhcp.enabled', dhcp.enabled, 'DHCP 服务器', '向该网络内终端自动分配地址')}${dhcp.enabled ? dependentMarkup(`${formField('地址池起始', inputField('dhcp.pool_start', dhcp.pool_start))}${formField('地址池结束', inputField('dhcp.pool_end', dhcp.pool_end))}${formField('租期（分钟）', inputField('dhcp.lease', dhcp.lease, { type: 'number', min: 1 }))}${formField('DHCP 网关', inputField('dhcp.gateway', dhcp.gateway))}${formField('DNS 服务器', inputField('dhcp.dns_text', dhcp.dns.join(', ')), '多个地址使用逗号分隔')}`) : ''}`;
    const ipv6Body = `${switchField('ipv6.enabled', ipv6.enabled, '启用 IPv6', '配置地址委派、RA 与 DHCPv6')}${ipv6.enabled ? dependentMarkup(`${formField('地址模式', selectField('ipv6.mode', ipv6.mode, [['dhcp', '自动 / 委派'], ['static', '静态']]))}${formField('上游 WAN', multiSelectField('ipv6.parent_wans', ipv6.parent_wans, upstreamWanOptions(ipv6.parent_wans)), '按住 Cmd / Ctrl 可多选')}${formField('静态地址', inputField('ipv6.addr', ipv6.addr, { placeholder: '2001:db8::1/64' }))}${formField('前缀长度', inputField('ipv6.prefix_len', ipv6.prefix_len, { placeholder: 'auto' }))}${formField('IPv6 租期（分钟）', inputField('ipv6.leasetime', ipv6.leasetime, { type: 'number', min: 1 }))}${formField('RA 标志', selectField('ipv6.ra_flags', ipv6.ra_flags, [['1', 'Managed + Other'], ['2', 'Managed'], ['3', 'Other'], ['0', '无状态']]))}${switchField('ipv6.dhcpv6', ipv6.dhcpv6, 'DHCPv6 服务')}${switchField('ipv6.ra_static', ipv6.ra_static, '静态 RA', '使用固定前缀通告')}${switchField('ipv6.use_dns6', ipv6.use_dns6, '下发 IPv6 DNS')}${ipv6.use_dns6 ? formField('IPv6 DNS', inputField('ipv6.dns_text', ipv6.dns6.join(', ')), '多个地址使用逗号分隔') : ''}${switchField('ipv6.ra_mtu_set', ipv6.ra_mtu_set, '自定义 RA MTU')}${ipv6.ra_mtu_set ? formField('RA MTU', inputField('ipv6.ra_mtu', ipv6.ra_mtu, { type: 'number', min: 1280, max: 9000 })) : ''}`) : ''}`;
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
      <div class="network-interface-form-grid">${formField('线路名称', inputField('name', draft.name, { placeholder: '例如 中国联通' }), '显示用名称，可随时修改')}${formField('WAN ID', inputField('id', draft.id, { disabled: state.drawer === 'edit' }), '保存后的稳定标识')}${formField('备注', inputField('note', draft.note, { placeholder: '可选' }))}${carrierField(draft)}</div>
      ${conflictMarkup()}
      ${physicalPortSection(draft)}
      ${logicalNameSection(draft)}`;
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
    const selected = new Set(isWan ? [state.draft.device].filter(Boolean) : asArray(state.draft.ports));
    const ports = annotatedPorts(row.id);
    return `<section class="network-interface-port-picker">
      <p>${isWan ? '为该 WAN 选择一个物理接口。' : '选择加入该 LAN 网桥的物理端口。'}</p>
      ${conflictMarkup()}
      <div>${ports.length ? ports.map((port) => portCardMarkup(port, selected.has(port.name))).join('') : '<div class="dwrt-kit-table-empty">后端未返回可用物理端口</div>'}</div>
    </section>`;
  }

  function deleteConfirmationMarkup(row) {
    /*
     * 默认 lan 是当前管理网络，从此页删掉会把自己关在门外，这一支的保护是对的。
     * 但原先还有一句 `const unavailable = !isWan`，把「前端没接线」说成
     * 「后端尚未提供 LAN 删除路由」—— 后端 DELETE /api/v1/network/lans/<id> 一直存在
     * （webd 与 core 的 lan_delete 字面量都在，core 里还带 lan_ports_attached 这类
     * 拒绝原因），于是任何非默认 LAN 的删除按钮都是灰的且配一句错误解释，
     * 用户据此以为无解，只能手改 /etc/config/network。
     *
     * 现在只保留两条真实约束：默认 lan 受保护；WAN 至少留一条。
     * LAN 能否真的删掉由后端裁定，被拒时如实转述它给的原因。
     */
    const protectedLan = !isWan && row.id === 'lan';
    const lastWan = isWan && state.rows.length <= 1;
    const canDelete = Boolean(row.id) && !protectedLan && !lastWan;
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    if (typeof renderer !== 'function') return '';
    return renderer({
      id: 'network-interface-delete-confirm',
      action: `delete-${kind}`,
      tone: 'danger',
      title: `删除 ${row.name || kind.toUpperCase()}`,
      description: protectedLan
        ? '默认 LAN 是当前管理网络，不能从此页面删除。'
        : lastWan
          ? '至少需要保留一条 WAN，当前线路不能删除。'
          : isWan
            ? '删除后会移除该线路及其关联配置，此操作不可撤销。'
            : '删除后会移除该 LAN 及其网桥配置，此操作不可撤销。若仍有物理端口挂在它上面，后端会拒绝并说明原因。',
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
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-interface-close data-interface-owner="${escapeHtml(instanceId)}" aria-label="关闭配置面板"></button>
      <aside class="network-interface-drawer dwrt-kit-sheet is-open" data-interface-owner="${escapeHtml(instanceId)}" aria-label="${escapeHtml(title)}">
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
    const drawerScroll = drawerQuery('[data-interface-drawer-scroll]')?.scrollTop || 0;
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
    const nextDrawer = drawerQuery('[data-interface-drawer-scroll]');
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
    const drawer = drawerNode();
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
    state.fieldErrors = {};
    state.saving = false;
    state.returnFocus = null;
    /* 抽屉期间被推迟的后台数据已经落在 state 里，这次整页重绘一并补上。 */
    state.tableStale = false;
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
    /* 用户开始改这一项，就撤掉它上一次的错误标注，别让红字留在已经改对的字段上。 */
    if (state.fieldErrors[field]) {
      const next = { ...state.fieldErrors };
      delete next[field];
      state.fieldErrors = next;
    }
    /*
     * 多选 select 的 `.value` 只给出第一个选中项，会把多上游静默截断成一个。
     * 这里改读 selectedOptions，并直接落进数组字段。
     */
    if (input.multiple || input.hasAttribute?.('data-interface-multi')) {
      setDeep(state.draft, field, [...input.selectedOptions].map((option) => option.value).filter(Boolean));
      return;
    }
    /*
     * 运营商下拉是展示层的字段，真正保存的仍是 draft.carrier。选到固定运营商就直接
     * 写入对应 key；选「其他」时不要清掉用户已有的值，只在它本来就是固定项时才清空，
     * 否则编辑一条已有线路时切一下下拉就把原来的自定义名字弄丢了。
     */
    if (field === 'carrier_select') {
      if (value === '__custom__') {
        /* 原本是固定运营商才清空；本来就是自定义名字的要留着，别让切一下下拉就丢。 */
        const wasCustom = carrierSelectValue(state.draft) === '__custom__';
        state.draft.carrier_custom = true;
        if (!wasCustom) state.draft.carrier = '';
      } else {
        state.draft.carrier_custom = false;
        state.draft.carrier = value;
      }
      return;
    }
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

  /*
   * 删除被拒时后端回的是错误码。原样显示 lan_ports_attached 这种字面量等于没解释，
   * 所以这里把已知的几个翻成人话；未知码仍如实透出原文，不猜、不吞。
   * 取值来自 dreamingwrt-core 的字面量（lan_ports_attached / lan_delete_failed）。
   */
  const DELETE_ERROR_TEXT = {
    lan_ports_attached: '该 LAN 仍有物理端口挂在它的网桥上，后端拒绝删除。请先在「物理接口」里把端口移出，再重试。',
    lan_delete_failed: '后端执行删除失败，配置未改动。',
    lan_not_found: '后端找不到这个 LAN，可能已被其他会话删除，刷新后再看。',
    lan_is_default: '这是默认管理网络，后端不允许删除。'
  };

  function deleteErrorText(error) {
    const code = firstText(error?.code, error?.payload?.error, error?.payload?.code);
    if (DELETE_ERROR_TEXT[code]) return DELETE_ERROR_TEXT[code];
    /* 有些路径把码直接塞进 message，这里再兜一层，免得用户看到裸字面量。 */
    const message = firstText(error?.message);
    const hit = Object.keys(DELETE_ERROR_TEXT).find((key) => message === key || message.includes(key));
    return hit ? DELETE_ERROR_TEXT[hit] : '';
  }

  function validationMessage(error) {
    const details = asArray(error?.details);
    if (!details.length) return firstText(deleteErrorText(error), error?.message, '后端未接受配置');
    return details.map((entry) => firstText(entry.message, entry.error, entry.field)).filter(Boolean).join('；');
  }

  /*
   * 提交前的本地必填检查。后端会拒（wan.device=missing / wan.id=missing），但那要走一
   * 个来回才告诉用户，而且此前只弹一句 invalid_request。能在本地判定的就地标注。
   * 这里只做「后端明确会拒且判据在前端就成立」的项，不自己发明规则。
   */
  function localFieldErrors() {
    const draft = state.draft || {};
    const errors = {};
    if (!firstText(draft.id)) errors.id = '此项为必填';
    else if (!/^[A-Za-z0-9_]+$/.test(firstText(draft.id))) errors.id = '只能使用字母、数字或下划线';
    if (isWan && !firstText(draft.device)) errors.device = '请选择承载此线路的物理网卡';
    if (!isWan && !firstText(draft.device)) errors.device = '请填写网桥设备名';
    return errors;
  }

  /* 出错项可能折在收起的分组里，展开第一处，否则标注在看不见的地方等于没标。 */
  function focusFirstError() {
    const keys = Object.keys(state.fieldErrors);
    if (!keys.length) return;
    const group = keys.map(groupForField).find(Boolean);
    if (group) state.editorOpen = group;
  }

  /*
   * 后端可能对当前界面上不存在的字段报错：比如 access_mode=dhcp 时报 wan.gateway ——
   * 网关输入框只在静态模式下渲染，标注无处可去。这种条目必须写进顶部通知，
   * 否则「3 项未通过」却只看到 2 处红字，用户会以为剩下那条自己消失了。
   */
  function applyValidationError(error, prefix) {
    const { mapped, orphans } = collectFieldErrors(error?.details);
    state.fieldErrors = mapped;
    focusFirstError();
    const shown = Object.keys(mapped).filter((key) => renderedFields().has(key));
    const hidden = Object.keys(mapped)
      .filter((key) => !renderedFields().has(key))
      .map((key) => `${key}：${mapped[key]}`);
    const extras = [...orphans, ...hidden];
    if (!shown.length) {
      state.notice = `${prefix}：${extras.length ? extras.join('；') : firstText(error?.message, '后端未接受配置')}`;
    } else {
      state.notice = `${prefix}：${shown.length} 项已在对应表单项标出${extras.length ? `；另有 ${extras.join('；')}` : ''}`;
    }
    state.noticeTone = 'bad';
  }

  /* 当前抽屉里实际渲染出来的字段集合，用于判断某条错误能否就地标注。 */
  function renderedFields() {
    const scope = drawerNode();
    if (!scope) return new Set();
    return new Set([...scope.querySelectorAll('[data-interface-field]')].map((el) => el.dataset.interfaceField));
  }

  function notifyCommitted() {
    if (typeof context.onCommitted === 'function') context.onCommitted({ kind });
  }

  async function saveDraft() {
    if (state.saving) return;
    const local = localFieldErrors();
    if (Object.keys(local).length) {
      state.fieldErrors = local;
      focusFirstError();
      state.notice = `请先补全 ${Object.keys(local).length} 项必填内容，已在对应表单项标出`;
      state.noticeTone = 'bad';
      patchDrawerContents();
      return;
    }
    state.saving = true;
    state.notice = '';
    state.fieldErrors = {};
    patchDrawerContents();
    try {
      const payload = isWan ? wanPayload() : lanPayload();
      const result = await requestJson(ENDPOINT, { method: state.drawer === 'create' ? 'POST' : 'PUT', body: JSON.stringify(payload) });
      state.saving = false;
      state.drawer = '';
      state.fieldErrors = {};
      await load(true);
      state.notice = result.applied === true ? '配置已保存并应用' : '配置已保存；后端未返回运行态应用结果';
      state.noticeTone = result.applied === true ? 'ok' : 'warn';
      render();
      notifyCommitted();
    } catch (error) {
      state.saving = false;
      applyValidationError(error, '保存失败');
      patchDrawerContents();
    }
  }

  async function savePorts() {
    if (state.saving) return;
    state.saving = true;
    state.notice = '';
    state.fieldErrors = {};
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
      applyValidationError(error, '端口保存失败');
      patchDrawerContents();
    }
  }

  /*
   * WAN 与 LAN 共用这条删除路径。原先第一行是 `if (!isWan || ...) return`，
   * 所以 LAN 不只是按钮灰 —— 就算点到了也会在这里静默返回，前端根本没有 LAN 的
   * 提交通路。ENDPOINT 本身早就按 kind 切到 /api/v1/network/lans 了。
   *
   * 两条不能删的情况分别拦：默认 lan 是管理网络，WAN 要至少留一条。
   */
  async function deleteRow() {
    if (state.saving || !state.selectedId) return;
    if (!isWan && state.selectedId === 'lan') return;
    if (isWan && state.rows.length <= 1) return;
    const label = isWan ? 'WAN' : 'LAN';
    state.saving = true;
    patchDrawerContents();
    try {
      await requestJson(`${ENDPOINT}/${encodeURIComponent(state.selectedId)}`, { method: 'DELETE' });
      state.saving = false;
      state.drawer = '';
      await load(true);
      state.notice = `${label} 已删除`;
      state.noticeTone = 'ok';
      render();
      notifyCommitted();
    } catch (error) {
      state.saving = false;
      state.notice = `删除失败：${validationMessage(error)}`;
      state.noticeTone = 'bad';
      /*
       * 失败时必须收掉确认卡再重绘。页面级提示的渲染条件是 `!state.drawer`，而删除确认
       * 又不是 sheet —— patchDrawerContents() 找不到 .network-interface-drawer 会退回
       * render()，于是提示两处都落不下来，用户看到的是「点了确认什么都没发生」。
       */
      state.drawer = '';
      render();
    }
  }

  /*
   * WAN 断线重连。拨号可能十几秒，所以整个过程给该行一个进行态，结束后重新拉一次
   * 数据再报结果 —— 不按超时猜成功。后端返回 ok 但没说明运行态时也如实说明，
   * 不把「已下发」写成「已连上」。
   */
  async function reconnectWan(id) {
    if (!isWan || !reconnectEnabled() || state.reconnecting || !id) return;
    state.reconnecting = id;
    state.notice = `正在重连 ${id}，拨号可能需要十几秒`;
    state.noticeTone = 'info';
    render();
    try {
      const result = await requestJson(`${ENDPOINT}/${encodeURIComponent(id)}/reconnect`, { method: 'POST' });
      state.reconnecting = '';
      await load(true);
      const row = state.rows.find((entry) => entry.id === id);
      if (row?.online) {
        state.notice = `${id} 已重新连接`;
        state.noticeTone = 'ok';
      } else {
        state.notice = result?.applied === true
          ? `${id} 重连指令已执行，但线路当前仍未在线`
          : `${id} 重连指令已下发；后端未返回运行态结果，请稍后查看线路状态`;
        state.noticeTone = 'warn';
      }
      render();
    } catch (error) {
      state.reconnecting = '';
      state.notice = `${id} 重连失败：${validationMessage(error)}`;
      state.noticeTone = 'bad';
      render();
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
      /* 手风琴住在抽屉里，抽屉可能已被搬进 portal，所以从抽屉节点往下找而不是从 root。 */
      const scope = editorToggle.closest('.network-interface-drawer') || drawerNode() || root;
      scope.querySelectorAll('[data-interface-editor-group]').forEach((group) => {
        const trigger = group.querySelector('[data-interface-editor-toggle]');
        const groupId = trigger?.dataset.interfaceEditorToggle || '';
        const panel = group.querySelector('.network-interface-editor-group-body');
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
    const reconnect = event.target.closest('[data-interface-reconnect]');
    if (reconnect) { reconnectWan(reconnect.dataset.interfaceReconnect); return; }
    if (event.target.closest('[data-interface-save]')) { saveDraft(); return; }
    if (event.target.closest('[data-interface-save-ports]')) { savePorts(); return; }
    if (event.target.closest('[data-dwrt-confirm-accept]')) { deleteRow(); }
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
        /*
         * 单选口切换要清掉上一个卡片的选中态。查询范围必须覆盖抽屉：抽屉被 kit 搬进
         * body 下的 portal 后就不再是 root 的后代，只查 root 会一个也找不到，于是旧卡片
         * 的高亮留在原处，看起来像同时选中了两块网卡。
         */
        (drawerNode() || root).querySelectorAll('[data-interface-port]').forEach((entry) => {
          entry.closest('label')?.classList.toggle('is-selected', entry.checked);
        });
      }
      /* 选了口就等于填上了 device，撤掉它的必填标注。 */
      if (isWan && state.fieldErrors.device) {
        const next = { ...state.fieldErrors };
        delete next.device;
        state.fieldErrors = next;
        patchDrawerContents();
      }
      return;
    }
    const field = event.target.closest('[data-interface-field]');
    if (!field) return;
    patchDraft(field.dataset.interfaceField, field);
    /* carrier_select 会决定「运营商名称」自由输入框是否出现，所以也要重绘抽屉内容。 */
    const conditional = ['access_mode', 'mode', 'dhcp.enabled', 'ipv6.enabled', 'ipv6.use_dns6', 'ipv6.ra_mtu_set', 'ipv6_mode', 'advanced.health_check.enabled', 'advanced.pppoe.timing_restart', 'advanced.pppoe.abnormal_ip_check', 'vlan_enabled', 'carrier_select'].includes(field.dataset.interfaceField);
    if (conditional) patchDrawerContents(field.dataset.interfaceField);
  }

  /*
   * 监听必须挂在 document 上，不能挂 root。
   *
   * kit 的 mountAll() 会把 `.dwrt-kit-sheet` 连同遮罩搬到 body 直属的
   * #dwrtKitSheetPortal（见 dwrt-ui-kit.js 的“抽屉传送门”注释：祖先链上的
   * transform/filter/contain 会让 position:fixed 重新锚定，所以抽屉必须离开路由宿主）。
   * 抽屉一旦搬走就不再是 root 的后代，绑在 root 上的委派监听收不到抽屉里的任何事件 ——
   * 手风琴点了没反应、字段改了不生效都是这一个原因。aegisx 之类的页面没犯这病，
   * 是因为它们逐元素直绑而不是委派。
   *
   * 全局配置页同时挂 LAN 与 WAN 两个实例，所以在 document 层要按归属过滤：
   * 事件目标要么在本实例的 root 里，要么在本实例打了 data-interface-owner 的抽屉里。
   * 删除确认由 kit 渲染、拿不到 owner 标记，用 state.drawer 兜住 —— 同一时刻只有
   * 打开了删除确认的那个实例会认领它。
   */
  function ownsEvent(event) {
    const target = event.target;
    if (!(target instanceof Element)) return false;
    if (root.contains(target)) return true;
    const owner = target.closest('[data-interface-owner]');
    if (owner) return owner.dataset.interfaceOwner === instanceId;
    if (target.closest('[data-dwrt-confirmation]')) return state.drawer === 'delete';
    return false;
  }

  const onDocumentClick = (event) => { if (ownsEvent(event)) onClick(event); };
  const onDocumentInput = (event) => { if (ownsEvent(event)) onInput(event); };
  const onDocumentChange = (event) => { if (ownsEvent(event)) onChange(event); };
  document.addEventListener('click', onDocumentClick);
  document.addEventListener('input', onDocumentInput);
  document.addEventListener('change', onDocumentChange);
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
    setData(config, ports, wanNames) {
      /* WAN 名单随每次喂数据更新：挂载那一刻宿主可能还没读到 WAN，
         只在 mount 时取一次会让 IPv6 上游下拉长期为空。 */
      if (Array.isArray(wanNames)) state.wanNames = wanNames.filter(Boolean);
      applyData(config, ports);
    },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      stopPolling();
      document.removeEventListener('click', onDocumentClick);
      document.removeEventListener('input', onDocumentInput);
      document.removeEventListener('change', onDocumentChange);
      root.replaceChildren();
      root.classList.remove('network-interface-route-host', 'is-lan', 'is-wan', 'route-workspace', 'is-embedded');
    }
  };
}

export default { mount };
