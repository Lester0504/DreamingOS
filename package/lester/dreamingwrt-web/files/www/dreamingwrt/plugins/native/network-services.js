export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const VERSION = '20260724-dns-01';
  const service = ({ 'dhcp-service': 'dhcp', 'dns-service': 'dns', 'upnp-service': 'upnp' })[context.item?.id] || 'dhcp';
  const MODULE_CLASS = `is-${service}`;
  const stage = root?.closest('.console-stage');
  const ENDPOINTS = {
    dhcp: '/api/v1/services/dhcp',
    lans: '/api/v1/network/lans',
    dns: '/api/v1/services/dns',
    dnsPolicy: '/api/v1/services/dns/wan-policy',
    wans: '/api/v1/network/wans',
    upnp: '/api/v1/services/upnp',
    upnpMappings: '/api/v1/services/upnp/mappings'
  };
  const TABS = {
    dhcp: [['overview', 'DHCP 概览'], ['reservations', 'DHCP 静态分配'], ['access', 'DHCP 黑白名单'], ['clients', 'DHCP 客户端'], ['prefixes', 'DHCPv6 前缀静态分配']],
    dns: [['overview', '概览'], ['upstreams', '上游 DNS'], ['forwarding', 'DNS 转发'], ['rules', '域名规则'], ['split', 'DNS 分流']],
    upnp: [['overview', '概览'], ['mappings', '端口映射'], ['access', '访问控制']]
  };
  function defaultData() {
    if (service === 'dhcp') return { scopes: [], blacklist: [], whitelist: [], prefixes: [], capabilities: {}, independentApi: false, source: '' };
    if (service === 'dns') return {
      enabled: false, mode: 'proxy', listen_interfaces: [], listen_port: 53, cache_enabled: true, cache_size: 4096,
      local_domain: '', rebind_protection: true, hijack_protection: true, edns_client_subnet: false, ipv6_dns: true,
      upstreams: [], rules: [], wanPolicies: [], stats: {}, capabilities: {}, supported_protocols: ['udp', 'tcp']
    };
    return {
      enabled: false, natpmp_enabled: false, pcp: false, secure_mode: true, log_packets: false, system_uptime: true,
      force_forwarding: false, use_stun: false, external_iface: '', internal_ifaces: [], port_range: { start: 1024, end: 65535 },
      download_mbps: 0, upload_mbps: 0, notify_interval: 30, clean_interval: 600, stun_host: '', stun_port: 3478,
      acl: [], mappings: [], stats: {}, capabilities: {}
    };
  }

  const state = {
    mounted: true,
    seq: 0,
    loading: true,
    refreshing: false,
    saving: false,
    error: '',
    notice: '',
    noticeTone: '',
    tab: 'overview',
    query: '',
    data: defaultData(),
    draft: defaultData(),
    initial: defaultData(),
    wans: [],
    dirty: false,
    dirtyPolicies: new Set(),
    drawer: '',
    selected: null,
    editor: {},
    confirmDelete: false,
    policyReadback: false,
    dnsGroup: 'core'
  };

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (typeof value === 'object' && !Array.isArray(value)) {
        const nested = firstText(value.message, value.name, value.label, value.value, value.id);
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
      if (value === '' || value === null || value === undefined) continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return 0;
  }

  function booleanValue(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') return !['0', 'false', 'off', 'no', 'disabled'].includes(value.toLowerCase());
    return Boolean(value);
  }

  function asArray(value, keys = []) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of [...keys, 'items', 'rows', 'list', 'data']) if (Array.isArray(value[key])) return value[key];
    return [];
  }

  function clone(value) {
    try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value || {})); }
  }

  function parseArray(value) {
    if (Array.isArray(value)) return value;
    if (!value) return [];
    if (typeof value === 'string') {
      try {
        const parsed = JSON.parse(value);
        if (Array.isArray(parsed)) return parsed;
        if (typeof parsed === 'string') return parseArray(parsed);
      } catch (_) {}
      return value.split(/[;,]/).map((item) => item.trim()).filter(Boolean);
    }
    return [];
  }

  function authHeaders(extra = {}) {
    let token = '';
    try { token = localStorage.getItem('dreamingwrt.web.accessToken') || ''; } catch (_) {}
    return { Accept: 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}), ...extra };
  }

  async function requestJson(url, options = {}) {
    const response = await fetch(`${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`, {
      credentials: 'same-origin', cache: 'no-store', signal: context.signal, ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    const payload = json?.data ?? json?.body ?? json;
    const code = Number(json?.code);
    const payloadCode = Number(payload?.code);
    const businessFailed = (Number.isFinite(code) && ![0, 200, 2000].includes(code))
      || (Number.isFinite(payloadCode) && ![0, 200, 2000].includes(payloadCode));
    if (!response.ok || json?.ok === false || payload?.ok === false || businessFailed) {
      const error = new Error(firstText(payload?.message, payload?.error, json?.message, json?.error, `HTTP ${response.status}`));
      error.status = response.status;
      error.payload = json;
      throw error;
    }
    return payload || {};
  }

  function icon(name) {
    const paths = {
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      edit: '<path d="m4 20 4.2-1 10.9-10.9a2 2 0 0 0-2.8-2.8L5.4 16.2 4 20Z"></path>',
      network: '<rect x="4" y="4" width="6" height="6" rx="1"></rect><rect x="14" y="14" width="6" height="6" rx="1"></rect><path d="M7 10v4a3 3 0 0 0 3 3h4"></path>',
      lease: '<path d="M7 7h10v10H7z"></path><path d="M4 12h3m10 0h3M12 4v3m0 10v3"></path>',
      pin: '<path d="M6 4h12v16l-6-3-6 3z"></path><path d="M9 9h6m-6 4h4"></path>',
      shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"></path><path d="m9 12 2 2 4-5"></path>',
      server: '<rect x="3" y="4" width="18" height="7" rx="2"></rect><rect x="3" y="13" width="18" height="7" rx="2"></rect><path d="M7 7.5h.01M7 16.5h.01M11 7.5h6M11 16.5h6"></path>',
      cache: '<ellipse cx="12" cy="5" rx="8" ry="3"></ellipse><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"></path>',
      route: '<circle cx="6" cy="18" r="2"></circle><circle cx="18" cy="6" r="2"></circle><path d="M8 18h4a4 4 0 0 0 4-4V8"></path>',
      gateway: '<rect x="3" y="5" width="18" height="14" rx="3"></rect><path d="M8 15h.01M12 15h.01M16 15h.01M8 9h8"></path>',
      mapping: '<path d="M4 6h6v6H4zM14 12h6v6h-6z"></path><path d="M10 9h3a3 3 0 0 1 3 3"></path>',
      activity: '<path d="M3 12h4l2-6 4 12 2-6h6"></path>',
      clock: '<circle cx="12" cy="12" r="9"></circle><path d="M12 7v5l3 2"></path>',
      trash: '<path d="M4 7h16M9 7V4h6v3m-9 0 1 13h10l1-13M10 11v5m4-5v5"></path>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.network}</svg>`;
  }

  function status(value, enabled = true) {
    return ui.statusBadgeMarkup?.(value, enabled ? 'success' : 'error') || `<span>${escapeHtml(value)}</span>`;
  }

  function statusTone(value, tone = 'info') {
    const semantic = ({ ok: 'success', warn: 'warning', bad: 'error', info: 'info', neutral: 'muted' })[tone] || tone;
    return ui.statusBadgeMarkup?.(value, semantic) || `<span>${escapeHtml(value)}</span>`;
  }

  function formatTime(value) {
    const raw = Number(value) || 0;
    if (!raw) return '--';
    const timestamp = raw < 100000000000 ? raw * 1000 : raw;
    return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(timestamp);
  }

  function formatLease(seconds) {
    const value = Number(seconds) || 0;
    if (!value) return '永久';
    if (value < 60) return `${value} 秒`;
    if (value < 3600) return `${Math.round(value / 60)} 分钟`;
    return `${Math.round(value / 3600)} 小时`;
  }

  function ipv4Number(value) {
    const parts = String(value || '').split('.').map(Number);
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
    return parts.reduce((total, part) => total * 256 + part, 0);
  }

  function normalizePool(pool, gateway = '') {
    const text = firstText(pool);
    if (!text) return '';
    const [start, end] = text.split('-').map((item) => item.trim());
    if (!end || start.includes('.')) return text;
    const prefix = firstText(gateway).split('.').slice(0, 3).join('.');
    return prefix ? `${prefix}.${start}-${prefix}.${end}` : text;
  }

  function poolSize(pool) {
    const [start, end] = String(pool || '').split('-').map(ipv4Number);
    return start !== null && end !== null && end >= start ? end - start + 1 : null;
  }

  function normalizeDhcpScope(source = {}, index = 0) {
    const rawDhcp = source.dhcp && typeof source.dhcp === 'object' ? source.dhcp : source;
    const gateway = firstText(rawDhcp.gateway, source.ipaddr, source.ip);
    const dns = parseArray(rawDhcp.dns || rawDhcp.dns_json);
    const pool = normalizePool(firstText(rawDhcp.pool, [rawDhcp.pool_start, rawDhcp.pool_end].filter(Boolean).join('-')), gateway);
    return {
      id: firstText(rawDhcp.id, source.id, source.lan_id, `lan-${index + 1}`),
      lanId: firstText(source.lan_id, source.id, rawDhcp.lan_id),
      name: firstText(source.name, source.note, source.id, `LAN ${index + 1}`),
      interface: firstText(source.interface, source.device, source.ifname, source.id),
      enabled: booleanValue(rawDhcp.enabled, true),
      gateway,
      netmask: firstText(rawDhcp.netmask, source.netmask),
      pool,
      excludePool: firstText(rawDhcp.exclude_pool).replace(/^"|"$/g, '').replace(/^\[\]$/, ''),
      dns1: firstText(rawDhcp.dns1, dns[0]),
      dns2: firstText(rawDhcp.dns2, dns[1]),
      lease: firstNumber(rawDhcp.lease, rawDhcp.lease_minutes, rawDhcp.leasetime),
      domain: firstText(rawDhcp.domain),
      options: asArray(rawDhcp.options),
      reservations: asArray(rawDhcp.reservations || rawDhcp.static_leases).map((item, itemIndex) => ({ ...item, id: firstText(item.id, item.mac, `reservation-${itemIndex + 1}`) })),
      leases: asArray(rawDhcp.leases),
      raw: source
    };
  }

  function normalizeDhcp(payload = {}, fallback = false) {
    const scopes = fallback
      ? asArray(payload, ['lans']).map(normalizeDhcpScope)
      : asArray(payload, ['scopes']).map(normalizeDhcpScope);
    return {
      scopes,
      selected: firstText(payload.selected, scopes[0]?.id),
      blacklist: asArray(payload.blacklist),
      whitelist: asArray(payload.whitelist),
      prefixes: asArray(payload.prefix_reservations),
      capabilities: payload.capabilities || {},
      source: fallback ? 'network/lans · DHCP 基础配置' : firstText(payload.source, 'config.db:dhcp_scope + 运行态租约'),
      independentApi: !fallback
    };
  }

  function normalizeDns(payload = {}) {
    return {
      ...payload,
      enabled: booleanValue(payload.enabled, false),
      mode: firstText(payload.mode, 'proxy'),
      listen_interfaces: parseArray(payload.listen_interfaces),
      listen_port: firstNumber(payload.listen_port, 53),
      cache_enabled: booleanValue(payload.cache_enabled, true),
      cache_size: firstNumber(payload.cache_size, 4096),
      local_domain: firstText(payload.local_domain),
      rebind_protection: booleanValue(payload.rebind_protection, true),
      hijack_protection: booleanValue(payload.hijack_protection, true),
      edns_client_subnet: booleanValue(payload.edns_client_subnet, false),
      ipv6_dns: booleanValue(payload.ipv6_dns, true),
      upstreams: asArray(payload.upstreams).map((item, index) => ({
        id: firstText(item.id, `dns-${index + 1}`), name: firstText(item.name, item.address, `DNS ${index + 1}`),
        address: firstText(item.address, item.ip, item.url), port: firstNumber(item.port, ['doh', 'dot'].includes(item.protocol) ? 443 : 53),
        protocol: firstText(item.protocol, 'udp').toLowerCase(), group: firstText(item.group, '默认'), enabled: booleanValue(item.enabled, true), latency: firstNumber(item.latency, item.rtt)
      })),
      rules: asArray(payload.rules).map((item, index) => ({
        id: firstText(item.id, `rule-${index + 1}`), domain: firstText(item.domain, item.host), type: firstText(item.type, 'host'),
        target: firstText(item.target, item.address, item.server), remark: firstText(item.remark, item.note), enabled: booleanValue(item.enabled, true)
      })),
      stats: payload.stats || {}, capabilities: payload.capabilities || {}, supported_protocols: asArray(payload.supported_protocols)
    };
  }

  function normalizeWanPolicyRows(payload = {}) {
    const policies = asArray(payload, ['policies']);
    return state.wans.map((wan, index) => {
      const policy = policies.find((item) => firstText(item.wan_id) === wan.id) || {};
      const servers = parseArray(policy.dns_servers);
      const runtimeDns = parseArray(wan.dns || wan.dns_json);
      return {
        id: firstText(policy.id, wan.id, `wan-${index + 1}`), wan_id: wan.id,
        name: firstText(wan.carrier_name, wan.name, wan.id), ifname: firstText(wan.ifname, wan.id),
        mode: firstText(policy.mode, 'auto'), enabled: policy.enabled === undefined ? true : booleanValue(policy.enabled),
        dns_servers: servers, runtimeDns, upstream_id: firstText(policy.upstream_id), domains: parseArray(policy.domains), sort_order: firstNumber(policy.sort_order, index)
      };
    });
  }

  function normalizeUpnp(payload = {}, mappingsPayload = {}) {
    const mappings = asArray(mappingsPayload, ['mappings']);
    return {
      ...payload,
      enabled: booleanValue(payload.enabled, false), natpmp_enabled: booleanValue(payload.natpmp_enabled, false), pcp: booleanValue(payload.pcp, false),
      secure_mode: booleanValue(payload.secure_mode, true), log_packets: booleanValue(payload.log_packets, false), system_uptime: booleanValue(payload.system_uptime, true),
      force_forwarding: booleanValue(payload.force_forwarding, false), use_stun: booleanValue(payload.use_stun, false),
      internal_ifaces: parseArray(payload.internal_ifaces), port_range: payload.port_range || { start: 1024, end: 65535 },
      acl: asArray(payload.acl), mappings: mappings.length ? mappings : asArray(payload.mappings), stats: payload.stats || {}, capabilities: payload.capabilities || {}
    };
  }

  function setData(data) {
    state.data = clone(data);
    state.draft = clone(data);
    state.initial = clone(data);
    state.dirty = false;
    state.dirtyPolicies.clear();
  }

  async function load(background = false) {
    const seq = ++state.seq;
    state.error = '';
    if (background) state.refreshing = true; else state.loading = true;
    if (!background) render(); else patchRefreshButton();
    try {
      if (service === 'dhcp') {
        let standaloneDhcp = true;
        let payload;
        try { payload = await requestJson(ENDPOINTS.dhcp); }
        catch (error) {
          if (error.status !== 404) throw error;
          standaloneDhcp = false;
          payload = await requestJson(ENDPOINTS.lans);
        }
        if (!state.mounted || seq !== state.seq) return;
        setData(normalizeDhcp(payload, !standaloneDhcp));
      } else if (service === 'dns') {
        const [dns, wans] = await Promise.all([requestJson(ENDPOINTS.dns), requestJson(ENDPOINTS.wans).catch(() => ({}))]);
        if (!state.mounted || seq !== state.seq) return;
        state.wans = asArray(wans, ['wans']).map((wan, index) => ({ ...wan, id: firstText(wan.id, wan.ifname, `wan${index + 1}`) }));
        const policyResults = await Promise.all(state.wans.map((wan) => requestJson(`${ENDPOINTS.dnsPolicy}?wan_id=${encodeURIComponent(wan.id)}`).catch(() => ({}))));
        if (!state.mounted || seq !== state.seq) return;
        const policy = {
          policies: policyResults.flatMap((item) => asArray(item, ['policies'])),
          capabilities: policyResults.reduce((result, item) => ({ ...result, ...(item.capabilities || {}) }), {})
        };
        const normalized = normalizeDns(dns);
        normalized.wanPolicies = normalizeWanPolicyRows(policy);
        state.policyReadback = state.wans.length === 0 || policyResults.length === state.wans.length
          && policyResults.every((item) => item.capabilities?.read_by_wan === true || item.capabilities?.read_all === true);
        setData(normalized);
      } else {
        const [upnp, mappings] = await Promise.all([requestJson(ENDPOINTS.upnp), requestJson(ENDPOINTS.upnpMappings).catch(() => ({}))]);
        if (!state.mounted || seq !== state.seq) return;
        setData(normalizeUpnp(upnp, mappings));
      }
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.error = `读取失败：${firstText(error.message, '接口不可用')}`;
    } finally {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      render();
    }
  }

  function rendererCards(items, label) {
    const renderer = ui.overviewCardsMarkup || window.DWRT_UI_KIT?.overviewCardsMarkup;
    return typeof renderer === 'function' ? renderer(items, { className: 'network-service-overview', label }) : '';
  }

  function tabsMarkup() {
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs network-service-tabs" data-network-service-tabs data-dwrt-tabs-key="network-${service}" aria-label="${service.toUpperCase()} 服务视图"><span class="dwrt-kit-tab-pill" aria-hidden="true"></span>${TABS[service].map(([id, label]) => `<button class="dwrt-kit-tab ${state.tab === id ? 'is-active' : ''}" type="button" data-value="${id}" aria-selected="${state.tab === id ? 'true' : 'false'}">${escapeHtml(label)}</button>`).join('')}</nav>`;
  }

  function toolbarMarkup(options = {}) {
    const search = options.search !== false;
    return `<div class="network-service-toolbar">${search ? `<label class="policy-search policy-search-main" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-network-service-search value="${escapeHtml(state.query)}" placeholder="${escapeHtml(options.placeholder || '搜索当前列表')}"></label>` : ''}<div class="policy-toolbar-actions"><button class="policy-filter-button network-service-refresh" type="button" data-network-service-refresh ${state.refreshing ? 'disabled' : ''}>${icon('refresh')}<span>${state.refreshing ? '正在刷新' : '刷新'}</span></button>${options.create ? `<button class="policy-create-button" type="button" data-network-service-create ${options.disabled ? 'disabled' : ''}>${icon('plus')}<span>${escapeHtml(options.create)}</span></button>` : ''}</div></div>`;
  }

  function currentToolbarOptions() {
    const capabilities = state.draft.capabilities || {};
    if (service === 'dhcp') {
      if (state.tab === 'overview') return { placeholder: '搜索网络、接口、地址池或 DNS' };
      if (state.tab === 'reservations') return { placeholder: '搜索名称、MAC、IP 或作用域', create: '添加静态分配', disabled: capabilities.service_update !== true || capabilities.static_reservations !== true };
      if (state.tab === 'access') return { placeholder: '搜索名单、终端或 MAC', create: '添加规则', disabled: capabilities.allow_deny_list !== true };
      if (state.tab === 'clients') return { placeholder: '搜索终端、MAC、IP 或作用域' };
      return { placeholder: '搜索名称、DUID、前缀或作用域', create: '添加前缀', disabled: capabilities.dhcpv6_static_prefix !== true };
    }
    if (service === 'dns') {
      if (state.tab === 'overview') return { search: false };
      if (state.tab === 'upstreams') return { placeholder: '搜索名称、地址、协议或分组', create: '添加上游', disabled: capabilities.service_update !== true };
      if (state.tab === 'forwarding') return { placeholder: '搜索域名、类型、目标或备注', create: '新建转发', disabled: capabilities.service_update !== true };
      if (state.tab === 'rules') return { placeholder: '搜索域名、类型、目标或备注', create: '新建规则', disabled: capabilities.service_update !== true };
      return { placeholder: '搜索线路、接口、模式或 DNS' };
    }
    if (state.tab === 'overview') return { search: false };
    if (state.tab === 'mappings') return { placeholder: '搜索协议、端口、内部地址、客户端或描述', create: '新建映射', disabled: capabilities.mapping_create !== true };
    return { placeholder: '搜索动作、端口、网段或备注', create: '新建 ACL', disabled: capabilities.acl_create !== true };
  }

  function pageHeaderMarkup() {
    return `<header class="network-service-page-header">${tabsMarkup()}${toolbarMarkup(currentToolbarOptions())}</header>`;
  }

  function noticeMarkup() {
    if (!state.error && !state.notice) return '';
    return `<div class="network-service-notice ${state.error || state.noticeTone === 'bad' ? 'is-error' : state.noticeTone === 'warn' ? 'is-warning' : ''}">${escapeHtml(state.error || state.notice)}</div>`;
  }

  function tableShell(title, meta, headings, rows, options = {}) {
    return `<section class="network-service-table-card dwrt-kit-table-wrap dwrt-kit-datatable-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(meta)}</span></div><span class="dwrt-kit-table-count">${options.count ?? rows.length} 条</span></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-datatable network-service-table ${options.className || ''}"><thead><tr>${headings.map((heading) => `<th>${escapeHtml(heading)}</th>`).join('')}</tr></thead><tbody>${state.loading ? `<tr><td colspan="${headings.length}" class="dwrt-kit-table-empty">正在读取配置</td></tr>` : rows.length ? rows.join('') : `<tr><td colspan="${headings.length}" class="dwrt-kit-table-empty">${escapeHtml(options.empty || '暂无数据')}</td></tr>`}</tbody></table></div></section>`;
  }

  function matchesQuery(values) {
    const query = state.query.trim().toLowerCase();
    return !query || values.flat().map((value) => firstText(value)).join(' ').toLowerCase().includes(query);
  }

  function switchControl(field, checked, disabled = false, scope = '') {
    return `<label class="network-service-switch ${disabled ? 'is-disabled' : ''}"><input type="checkbox" data-service-field="${escapeHtml(field)}" ${scope ? `data-service-scope="${escapeHtml(scope)}"` : ''} ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}><i></i></label>`;
  }

  function fieldMarkup(label, field, value, options = {}) {
    const disabled = options.disabled ? 'disabled' : '';
    const wide = options.wide ? ' is-wide' : '';
    const adaptive = options.adaptive ? ' data-adaptive-region' : '';
    if (options.type === 'select') return `<label class="network-service-field${wide}"${adaptive}><span>${escapeHtml(label)}</span><select data-service-field="${escapeHtml(field)}" ${disabled}>${options.options.map(([key, text]) => `<option value="${escapeHtml(key)}" ${String(value) === String(key) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select>${options.help ? `<small>${escapeHtml(options.help)}</small>` : ''}</label>`;
    return `<label class="network-service-field${wide}"${adaptive}><span>${escapeHtml(label)}</span><input type="${options.type || 'text'}" data-service-field="${escapeHtml(field)}" value="${escapeHtml(value ?? '')}" placeholder="${escapeHtml(options.placeholder || '')}" ${disabled}>${options.help ? `<small>${escapeHtml(options.help)}</small>` : ''}</label>`;
  }

  function capabilityNotice(text) {
    return `<div class="network-service-capability">${icon('shield')}<span><strong>当前为只读</strong><small>${escapeHtml(text)}</small></span></div>`;
  }

  function renderDhcp() {
    const data = state.draft;
    const scopes = data.scopes || [];
    if (state.tab === 'overview') {
      const leases = scopes.reduce((total, item) => total + item.leases.length, 0);
      const reservations = scopes.reduce((total, item) => total + item.reservations.length, 0);
      const cards = rendererCards([
        { key: 'scopes', label: 'DHCP 作用域', value: `${scopes.filter((item) => item.enabled).length} / ${scopes.length}`, detail: '启用 / 已配置', tone: 'info', icon: icon('network') },
        { key: 'leases', label: '当前租约', value: String(leases), detail: data.capabilities?.lease_read ? '运行态客户端' : '独立租约接口未开放', tone: data.capabilities?.lease_read ? 'ok' : 'neutral', icon: icon('lease') },
        { key: 'reservations', label: '静态分配', value: String(reservations), detail: '固定 MAC 与 IP', tone: reservations ? 'info' : 'neutral', icon: icon('pin') },
        { key: 'access', label: '黑白名单', value: String((data.blacklist?.length || 0) + (data.whitelist?.length || 0)), detail: '终端准入规则', tone: 'neutral', icon: icon('shield') }
      ], 'DHCP 概览');
      const rows = scopes.filter((scope) => matchesQuery([scope.name, scope.interface, scope.pool, scope.gateway, scope.dns1, scope.dns2])).map((scope) => {
        const size = poolSize(scope.pool);
        const used = scope.leases.length + scope.reservations.length;
        return `<tr><td><button class="network-service-name" type="button" data-dhcp-detail="${escapeHtml(scope.id)}"><span>${icon('network')}</span><span><strong>${escapeHtml(scope.name)}</strong><small>${escapeHtml(scope.interface || scope.lanId)}</small></span></button></td><td>${status(scope.enabled ? '启用' : '关闭', scope.enabled)}</td><td>${escapeHtml(scope.pool || '--')}</td><td>${escapeHtml(scope.excludePool || '--')}</td><td>${escapeHtml(scope.gateway || '--')}</td><td>${escapeHtml([scope.dns1, scope.dns2].filter(Boolean).join('、') || '--')}</td><td>${scope.lease ? `${scope.lease} 分钟` : '--'}</td><td>${scope.reservations.length}</td><td>${size === null ? '--' : Math.max(0, size - used)}</td></tr>`;
      });
      return `${cards}${data.capabilities?.service_update === true ? '' : capabilityNotice(data.independentApi ? '当前版本未声明 DHCP 写能力。' : '独立 DHCP 接口尚未开放；页面由真实 LAN 配置生成。')}${tableShell('DHCP 作用域', data.source, ['名称', '状态', '地址池', '排除地址', '网关', 'DNS', '租期', '静态分配', '剩余地址'], rows, { empty: '没有匹配的 DHCP 作用域' })}`;
    }
    if (state.tab === 'reservations') {
      const source = scopes.flatMap((scope) => scope.reservations.map((item) => ({ ...item, scope })));
      const rows = source.filter((item) => matchesQuery([item.name, item.mac, item.ip, item.remark, item.scope.name])).map((item) => `<tr><td><strong>${escapeHtml(firstText(item.name, item.hostname, '--'))}</strong></td><td>${escapeHtml(item.mac || '--')}</td><td>${escapeHtml(item.ip || '--')}</td><td>${escapeHtml(item.scope.name)}</td><td>${escapeHtml(item.remark || '--')}</td><td>${status(item.enabled === false ? '停用' : '启用', item.enabled !== false)}</td><td><button class="network-service-icon-button" type="button" data-dhcp-reservation="${escapeHtml(item.id)}" data-dhcp-reservation-scope="${escapeHtml(item.scope.id)}" aria-label="编辑静态分配">${icon('edit')}</button></td></tr>`);
      return `${data.capabilities?.static_reservations === true ? '' : capabilityNotice('后端尚未提供静态分配能力。')}${tableShell('DHCP 静态分配', '固定终端地址', ['名称', 'MAC', 'IP', '作用域', '备注', '状态', '操作'], rows, { empty: '暂无静态分配' })}`;
    }
    if (state.tab === 'access') {
      const source = [...(data.whitelist || []).map((item) => ({ ...item, kind: '白名单' })), ...(data.blacklist || []).map((item) => ({ ...item, kind: '黑名单' }))];
      const rows = source.filter((item) => matchesQuery([item.kind, item.name, item.hostname, item.mac, item.note, item.reason])).map((item) => `<tr><td>${status(item.kind, item.kind === '白名单')}</td><td><strong>${escapeHtml(firstText(item.name, item.hostname, item.mac, '--'))}</strong></td><td>${escapeHtml(item.mac || '--')}</td><td>${escapeHtml(firstText(item.note, item.reason, '--'))}</td></tr>`);
      return `${data.capabilities?.allow_deny_list === true ? '' : capabilityNotice('后端尚未返回 DHCP 黑白名单能力和数据契约。')}${tableShell('DHCP 黑白名单', '终端准入控制', ['类型', '名称', 'MAC', '备注'], rows, { empty: '后端尚未提供黑白名单数据' })}`;
    }
    if (state.tab === 'clients') {
      const source = scopes.flatMap((scope) => scope.leases.map((item) => ({ ...item, scope })));
      const rows = source.filter((item) => matchesQuery([item.hostname, item.name, item.mac, item.ip, item.scope.name])).map((item) => `<tr><td><strong>${escapeHtml(firstText(item.hostname, item.name, '--'))}</strong></td><td>${escapeHtml(item.mac || '--')}</td><td>${escapeHtml(item.ip || '--')}</td><td>${escapeHtml(item.scope.name)}</td><td>${status(item.online === false ? '离线' : '在线', item.online !== false)}</td><td>${escapeHtml(formatTime(item.expires))}</td></tr>`);
      return `${!data.capabilities?.lease_read ? capabilityNotice('独立 DHCP 接口未开放，当前 LAN 接口不包含实时租约。') : ''}${tableShell('DHCP 客户端', data.capabilities?.lease_read ? 'dnsmasq 运行态租约' : '等待租约读取能力', ['终端', 'MAC', 'IP', '作用域', '状态', '到期'], rows, { empty: data.capabilities?.lease_read ? '暂无 DHCP 客户端' : '后端尚未提供运行态租约' })}`;
    }
    const rows = (data.prefixes || []).filter((item) => matchesQuery([item.name, item.duid, item.prefix, item.scope, item.remark])).map((item) => `<tr><td><strong>${escapeHtml(firstText(item.name, '--'))}</strong></td><td>${escapeHtml(item.duid || '--')}</td><td>${escapeHtml(item.prefix || '--')}</td><td>${escapeHtml(firstText(item.scope, item.lan_id, '--'))}</td><td>${escapeHtml(item.remark || '--')}</td><td>${status(item.enabled === false ? '停用' : '启用', item.enabled !== false)}</td></tr>`);
    return `${data.capabilities?.dhcpv6_static_prefix === true ? '' : capabilityNotice('后端尚未提供 DHCPv6 前缀静态分配的读取和写入契约。')}${tableShell('DHCPv6 前缀静态分配', '按 DUID 固定委派前缀', ['名称', 'DUID', 'IPv6 前缀', '作用域', '备注', '状态'], rows, { empty: '后端尚未提供 DHCPv6 前缀数据' })}`;
  }

  function dnsRuleTypeLabel(type) {
    return ({ host: '本地域名', forward: '域名转发', block: '拦截', upstream: '指定上游' })[type] || type || '--';
  }

  function dnsWritable() {
    return state.draft.capabilities?.service_update === true;
  }

  function dnsServiceState(data = state.draft) {
    const validPort = Number.isInteger(Number(data.listen_port)) && Number(data.listen_port) >= 1 && Number(data.listen_port) <= 65535;
    const complete = Boolean(data.listen_interfaces?.length) && validPort;
    if (!data.enabled) return { label: '已关闭', detail: '保留当前配置，停止接管 LAN 查询', tone: 'neutral', complete: true };
    if (!complete || data.valid === false) return { label: '配置不完整', detail: data.runtime_reason || '请选择监听 LAN 并检查端口', tone: 'warn', complete: false };
    if (data.degraded === true) return { label: '降级运行', detail: data.runtime_reason || '部分能力未应用', tone: 'warn', complete: true };
    if (data.running === false) return { label: '未运行', detail: data.runtime_reason || '配置已启用，但运行服务未就绪', tone: 'bad', complete: true };
    if (data.applied === true && data.running === true) return { label: '运行中', detail: '配置与运行态已确认', tone: 'ok', complete: true };
    return { label: '等待确认', detail: '配置已启用，后端未确认运行态', tone: 'info', complete: true };
  }

  function dnsGroupMarkup(id, title, summary, body, options = {}) {
    const active = state.dnsGroup === id;
    const locked = options.locked === true;
    return `<section class="dns-control-group ${active ? 'is-open' : ''} ${locked ? 'is-locked' : ''}" data-dns-group="${escapeHtml(id)}" data-adaptive-region><button class="dns-control-group-trigger" type="button" data-dns-group-toggle="${escapeHtml(id)}" aria-expanded="${active ? 'true' : 'false'}" ${locked ? 'disabled' : ''}><span class="dns-control-group-index">${escapeHtml(options.index || '')}</span><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(summary)}</small></span><span class="dns-control-group-chevron" aria-hidden="true">${icon('route')}</span></button>${active && !locked ? `<div class="dns-control-group-body" data-adaptive-region>${body}</div>` : ''}</section>`;
  }

  function dnsOverviewSettings(data) {
    const writable = dnsWritable();
    const serviceState = dnsServiceState(data);
    const enabledUpstreams = data.upstreams.filter((item) => item.enabled).length;
    const activeRules = data.rules.filter((item) => item.enabled).length;
    const modeOptions = [...new Set(['proxy', data.mode].filter(Boolean))].map((mode) => [mode, mode === 'proxy' ? 'DNS 代理' : mode]);
    const core = `<div class="dns-core-status" data-adaptive-region><div><span class="dns-control-kicker">CORE SERVICE</span><strong>DNS 代理</strong><small>${escapeHtml(serviceState.detail)}</small></div><div class="dns-core-action">${statusTone(serviceState.label, serviceState.tone)} ${switchControl('enabled', data.enabled, !writable)}</div></div><div class="dns-core-mode">${fieldMarkup('工作模式', 'mode', data.mode, { type: 'select', options: modeOptions, disabled: !writable, adaptive: true, help: '当前后端只开放实际声明的解析模式。' })}</div><dl class="dns-inline-facts" data-adaptive-region><div><dt>配置状态</dt><dd>${escapeHtml(data.configured === false ? '未配置' : data.enabled ? '已启用' : '已停用')}</dd></div><div><dt>运行状态</dt><dd>${escapeHtml(data.running === true ? '运行中' : data.running === false ? '未运行' : '未回读')}</dd></div><div><dt>应用状态</dt><dd>${escapeHtml(data.apply_state || (data.applied === true ? 'applied' : '未确认'))}</dd></div></dl>`;
    const listen = `<div class="dns-field-grid">${fieldMarkup('监听接口', 'listen_interfaces', data.listen_interfaces.join(', '), { wide: true, placeholder: 'lan, lan20', disabled: !writable, adaptive: true, help: '多个 LAN 使用逗号分隔；启用服务前至少选择一个监听接口。' })}${fieldMarkup('监听端口', 'listen_port', data.listen_port, { type: 'number', disabled: !writable, adaptive: true })}${fieldMarkup('本地域名', 'local_domain', data.local_domain, { placeholder: 'lan', disabled: !writable, adaptive: true })}</div><label class="dns-inline-switch" data-adaptive-region><span><strong>DNS 缓存</strong><small>缓存重复查询，减少上游往返</small></span>${switchControl('cache_enabled', data.cache_enabled, !writable)}</label>${data.cache_enabled ? `<div class="dns-dependent-fields">${fieldMarkup('缓存容量', 'cache_size', data.cache_size, { type: 'number', disabled: !writable, adaptive: true, help: '可保留的 DNS 记录条目数。' })}</div>` : ''}`;
    const security = `<div class="dns-switch-grid">${[['rebind_protection', 'Rebind 防护', '阻止公网域名解析至内网地址'], ['hijack_protection', '劫持防护', '拦截异常解析与污染结果'], ['ipv6_dns', 'IPv6 DNS', '允许 AAAA 记录与 IPv6 上游'], ['edns_client_subnet', 'EDNS Client Subnet', '向上游携带客户端网段，可能降低隐私']].map(([field, title, detail]) => `<label class="dns-inline-switch" data-adaptive-region><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(detail)}</small></span>${switchControl(field, data[field], !writable)}</label>`).join('')}</div>`;
    const routing = `<div class="dns-routing-summary" data-adaptive-region><div><span>${icon('server')}</span><strong>${enabledUpstreams} / ${data.upstreams.length}</strong><small>启用 / 已配置上游</small></div><div><span>${icon('shield')}</span><strong>${activeRules}</strong><small>条启用规则</small></div><div><span>${icon('route')}</span><strong>${data.wanPolicies?.length || 0}</strong><small>条 WAN 线路</small></div></div><div class="dns-routing-actions"><button class="policy-secondary" type="button" data-dns-open-tab="upstreams">管理上游</button><button class="policy-secondary" type="button" data-dns-open-tab="forwarding">DNS 转发</button><button class="policy-secondary" type="button" data-dns-open-tab="rules">域名规则</button><button class="policy-secondary" type="button" data-dns-open-tab="split">线路分流</button></div>`;
    const groups = [
      dnsGroupMarkup('core', '核心服务', serviceState.label, core, { index: '01' }),
      dnsGroupMarkup('listen', '监听与缓存', data.enabled ? `${data.listen_interfaces.join('、') || '未选择监听接口'} · :${data.listen_port}` : '服务关闭时保留现有监听配置', listen, { index: '02', locked: !data.enabled }),
      dnsGroupMarkup('security', '安全与隐私', `${[data.rebind_protection, data.hijack_protection, data.ipv6_dns, data.edns_client_subnet].filter(Boolean).length} / 4 已启用`, security, { index: '03', locked: !data.enabled }),
      dnsGroupMarkup('routing', '上游与路由', `${enabledUpstreams} 个上游 · ${activeRules} 条规则`, routing, { index: '04', locked: !data.enabled })
    ].join('');
    return `${!writable ? capabilityNotice('后端未声明 DNS 完整快照保存与应用能力，当前配置保持只读。') : ''}<section class="dns-control-surface dwrt-kit-glass-surface" data-adaptive-region><header class="dns-control-heading" data-adaptive-region><div><span>DNS CONTROL PLANE</span><strong>解析服务</strong><small>按依赖关系配置核心服务、监听范围、安全策略和解析路径。</small></div><span class="dns-control-health is-${escapeHtml(serviceState.tone)}">${escapeHtml(serviceState.label)}</span></header><div class="dns-control-groups">${groups}</div></section>`;
  }

  function renderDns() {
    const data = state.draft;
    if (state.tab === 'overview') {
      const stats = data.stats || {};
      const serviceState = dnsServiceState(data);
      const cards = rendererCards([
        { key: 'service', label: 'DNS 代理', value: serviceState.label, detail: serviceState.detail, tone: serviceState.tone, icon: icon('server') },
        { key: 'upstreams', label: '上游 DNS', value: String(data.upstreams.filter((item) => item.enabled).length), detail: `${data.upstreams.length} 个已配置`, tone: 'info', icon: icon('route') },
        { key: 'cache', label: '缓存命中', value: `${Math.round(firstNumber(stats.cache_hit_rate))}%`, detail: `${firstNumber(stats.queries_today).toLocaleString()} 次查询`, tone: 'neutral', icon: icon('cache') },
        { key: 'protection', label: '安全防护', value: data.hijack_protection && data.rebind_protection ? '已启用' : '未完全启用', detail: `${firstNumber(stats.blocked_today).toLocaleString()} 次拦截`, tone: data.hijack_protection && data.rebind_protection ? 'ok' : 'warn', icon: icon('shield') }
      ], 'DNS 概览');
      return `${cards}${dnsOverviewSettings(data)}${dirtyBar()}`;
    }
    if (state.tab === 'upstreams') {
      const rows = data.upstreams.filter((item) => matchesQuery([item.name, item.address, item.protocol, item.group])).map((item) => `<tr data-adaptive-region><td><button class="network-service-name" type="button" data-dns-edit-upstream="${escapeHtml(item.id)}"><span>${icon('server')}</span><span><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.group)}</small></span></button></td><td>${status(item.enabled ? '启用' : '停用', item.enabled)}</td><td>${escapeHtml(item.address || '--')}</td><td>${escapeHtml(item.protocol.toUpperCase())}</td><td>${item.port || '--'}</td><td>${escapeHtml(item.group || '默认')}</td><td>${item.latency ? `${Math.round(item.latency)} ms` : '--'}</td><td><button class="network-service-icon-button" type="button" data-dns-edit-upstream="${escapeHtml(item.id)}" aria-label="编辑上游 DNS">${icon('edit')}</button></td></tr>`);
      return `${tableShell('上游 DNS', `${data.upstreams.filter((item) => item.enabled).length} 个启用`, ['名称', '状态', '地址', '协议', '端口', '分组', '延迟', '操作'], rows, { empty: '暂无上游 DNS' })}${dirtyBar()}`;
    }
    if (state.tab === 'forwarding' || state.tab === 'rules') {
      const forwarding = state.tab === 'forwarding';
      const source = data.rules.filter((item) => forwarding ? ['forward', 'upstream'].includes(item.type) : !['forward', 'upstream'].includes(item.type));
      const rows = source.filter((item) => matchesQuery([item.domain, item.type, item.target, item.remark])).map((item) => `<tr data-adaptive-region><td><button class="network-service-link" type="button" data-dns-edit-rule="${escapeHtml(item.id)}"><strong>${escapeHtml(item.domain || '--')}</strong></button></td><td>${escapeHtml(dnsRuleTypeLabel(item.type))}</td><td>${escapeHtml(item.target || '--')}</td><td>${escapeHtml(item.remark || '--')}</td><td>${status(item.enabled ? '启用' : '停用', item.enabled)}</td><td><button class="network-service-icon-button" type="button" data-dns-edit-rule="${escapeHtml(item.id)}" aria-label="编辑 DNS 规则">${icon('edit')}</button></td></tr>`);
      return `${tableShell(forwarding ? 'DNS 转发' : '域名规则', `${source.filter((item) => item.enabled).length} 条启用`, ['域名', '类型', forwarding ? '目标 DNS' : '目标', '备注', '状态', '操作'], rows, { empty: forwarding ? '暂无 DNS 转发' : '暂无域名规则' })}${dirtyBar()}`;
    }
    const rows = (data.wanPolicies || []).filter((item) => matchesQuery([item.name, item.ifname, item.mode, item.dns_servers, item.runtimeDns])).map((item, index) => {
      const displayDns = item.dns_servers.length ? item.dns_servers : item.runtimeDns;
      const disabled = state.policyReadback ? '' : 'disabled';
      const domainsDisabled = state.policyReadback && data.capabilities?.wan_policy_domains === true ? '' : 'disabled';
      return `<tr data-adaptive-region><td><span class="network-service-line"><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.ifname)}</small></span></td><td>${status(item.enabled ? '启用' : '停用', item.enabled)}</td><td><select data-dns-policy-index="${index}" data-dns-policy-field="mode" ${disabled}><option value="auto" ${item.mode === 'auto' ? 'selected' : ''}>跟随线路</option><option value="custom" ${item.mode === 'custom' ? 'selected' : ''}>自定义</option><option value="upstream" ${item.mode === 'upstream' ? 'selected' : ''}>指定上游</option><option value="disabled" ${item.mode === 'disabled' ? 'selected' : ''}>不接管</option></select></td><td><input data-dns-policy-index="${index}" data-dns-policy-field="dns_servers" value="${escapeHtml(displayDns[0] || '')}" placeholder="首选 DNS" ${disabled}></td><td><input data-dns-policy-index="${index}" data-dns-policy-field="dns_secondary" value="${escapeHtml(displayDns[1] || '')}" placeholder="备用 DNS" ${disabled}></td><td><input data-dns-policy-index="${index}" data-dns-policy-field="domains" value="${escapeHtml(item.domains.join(', '))}" placeholder="后端暂不支持域名拆分" ${domainsDisabled}></td></tr>`;
    });
    return `${state.policyReadback ? '' : capabilityNotice('分线路策略无法按 WAN 读取；为避免覆盖现有配置，当前只显示线路运行 DNS。')}${tableShell('DNS 分流', '按 WAN 线路选择解析策略', ['线路', '状态', '模式', '首选 DNS', '备用 DNS', '匹配域名'], rows, { empty: '暂无可配置的 WAN 线路', className: 'dns-policy-table' })}${dirtyBar()}`;
  }

  function upnpSettingsMarkup() {
    const data = state.draft;
    const writable = data.capabilities?.service_update === true;
    const toggles = [
      ['enabled', 'UPnP IGD', '允许终端动态申请端口映射'], ['natpmp_enabled', 'NAT-PMP', '兼容 Apple 与传统 NAT-PMP 客户端'],
      ['pcp', 'PCP', '使用 Port Control Protocol'], ['use_stun', 'STUN', '探测外部 NAT 地址'],
      ['secure_mode', '安全模式', '限制客户端映射其他主机'], ['log_packets', '记录数据包', '记录 UPnP 相关流量'],
      ['system_uptime', '使用系统运行时间', '以系统运行时间报告服务状态'], ['force_forwarding', '强制转发', '忽略接口转发状态']
    ];
    return `<section class="network-service-settings dwrt-kit-glass-surface"><div class="network-service-setting-list is-compact">${toggles.map(([field, title, detail]) => {
      const supported = !['pcp', 'use_stun', 'force_forwarding'].includes(field) || data.capabilities?.[field === 'use_stun' ? 'stun' : field] === true;
      return `<label class="network-service-setting-row"><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(detail)}</small></span>${switchControl(field, data[field], !writable || !supported)}</label>`;
    }).join('')}</div><div class="network-service-form">${fieldMarkup('外网接口', 'external_iface', data.external_iface, { disabled: !writable })}${fieldMarkup('内网接口', 'internal_ifaces', data.internal_ifaces.join(', '), { disabled: !writable })}${fieldMarkup('外部端口起始', 'port_range.start', data.port_range.start, { type: 'number', disabled: !writable || data.capabilities?.port_range !== true })}${fieldMarkup('外部端口结束', 'port_range.end', data.port_range.end, { type: 'number', disabled: !writable || data.capabilities?.port_range !== true })}${fieldMarkup('下行带宽（Mbps）', 'download_mbps', data.download_mbps, { type: 'number', disabled: !writable })}${fieldMarkup('上行带宽（Mbps）', 'upload_mbps', data.upload_mbps, { type: 'number', disabled: !writable })}${fieldMarkup('通知间隔（秒）', 'notify_interval', data.notify_interval, { type: 'number', disabled: !writable })}${fieldMarkup('清理间隔（秒）', 'clean_interval', data.clean_interval, { type: 'number', disabled: !writable || data.capabilities?.clean_interval !== true })}${fieldMarkup('STUN 地址', 'stun_host', data.stun_host, { disabled: !writable || data.capabilities?.stun_host !== true })}${fieldMarkup('STUN 端口', 'stun_port', data.stun_port, { type: 'number', disabled: !writable || data.capabilities?.stun_port !== true })}</div></section>`;
  }

  function renderUpnp() {
    const data = state.draft;
    if (state.tab === 'overview') {
      const stats = data.stats || {};
      const cards = rendererCards([
        { key: 'service', label: 'UPnP IGD', value: data.enabled ? '运行中' : '已关闭', detail: data.external_iface || '未指定外网接口', tone: data.enabled ? 'ok' : 'warn', icon: icon('gateway') },
        { key: 'mappings', label: '当前映射', value: String(Math.max(firstNumber(stats.active_mappings), data.mappings.length)), detail: '动态与静态映射', tone: 'info', icon: icon('mapping') },
        { key: 'requests', label: '今日请求', value: firstNumber(stats.requests_today).toLocaleString(), detail: `${firstNumber(stats.denied_today)} 次拒绝`, tone: firstNumber(stats.denied_today) ? 'warn' : 'neutral', icon: icon('activity') },
        { key: 'security', label: '安全模式', value: data.secure_mode ? '已启用' : '已关闭', detail: data.natpmp_enabled ? 'NAT-PMP 已启用' : '仅 UPnP IGD', tone: data.secure_mode ? 'ok' : 'warn', icon: icon('shield') }
      ], 'UPnP 概览');
      return `${cards}${data.capabilities?.service_update === true ? '' : capabilityNotice('后端尚未开放 UPnP 服务设置保存入口。')}${upnpSettingsMarkup()}${dirtyBar()}`;
    }
    if (state.tab === 'mappings') {
      const writable = data.capabilities?.mapping_create === true || data.capabilities?.save_upnp_mapping === true;
      const rows = data.mappings.filter((item) => matchesQuery([item.protocol, item.external_port, item.internal_ip, item.internal_port, item.client, item.description])).map((item) => `<tr><td><strong>${escapeHtml(String(item.protocol || '--').toUpperCase())}</strong></td><td>${item.external_port || '--'}</td><td><span class="network-service-line"><strong>${escapeHtml(item.internal_ip || '--')}</strong><small>${item.internal_port ? `:${item.internal_port}` : ''}</small></span></td><td>${escapeHtml(item.client || '--')}</td><td>${escapeHtml(item.description || '--')}</td><td>${escapeHtml(formatLease(item.lease))}</td><td>${firstNumber(item.packets).toLocaleString()}</td><td><button class="network-service-icon-button" type="button" data-upnp-edit-mapping="${escapeHtml(item.id)}" aria-label="编辑端口映射">${icon('edit')}</button></td></tr>`);
      return `${writable ? '' : capabilityNotice('后端没有可靠的静态映射运行态应用与回读能力。')}${tableShell('端口映射', 'miniupnpd 映射与静态映射', ['协议', '外部端口', '内部地址', '客户端', '描述', '租期', '包数', '操作'], rows, { empty: '暂无端口映射' })}`;
    }
    const aclWritable = data.capabilities?.acl_create === true && data.capabilities?.acl_update === true;
    const rows = data.acl.filter((item) => matchesQuery([item.action, item.external, item.internal, item.internal_ports, item.remark])).map((item) => `<tr><td>${status(item.action === 'deny' ? '拒绝' : '允许', item.action !== 'deny')}</td><td>${escapeHtml(item.external || '--')}</td><td>${escapeHtml(item.internal || '--')}</td><td>${escapeHtml(item.internal_ports || '--')}</td><td>${escapeHtml(item.remark || '--')}</td><td>${status(item.enabled === false ? '停用' : '启用', item.enabled !== false)}</td><td><button class="network-service-icon-button" type="button" data-upnp-edit-acl="${escapeHtml(item.id)}" aria-label="编辑 ACL">${icon('edit')}</button></td></tr>`);
    return `${aclWritable ? '' : capabilityNotice('后端尚未提供完整的 ACL 新建、编辑和删除能力。')}${tableShell('访问控制', 'miniupnpd 权限规则', ['动作', '外部端口', '内部网段', '内部端口', '备注', '状态', '操作'], rows, { empty: '暂无访问控制规则' })}`;
  }

  function dirtyBar() {
    if (!state.dirty && !state.dirtyPolicies.size) return '';
    const message = state.dirtyPolicies.size ? `${state.dirtyPolicies.size} 条线路策略待保存` : '配置有未保存的变更';
    return ui.floatingSavebarMarkup?.({ visible: true, busy: state.saving, message, discardLabel: '复位', busyLabel: '正在保存' }) || '';
  }

  function drawerBackdrop(label) {
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-network-service-close aria-label="${escapeHtml(label)}"></button>`;
  }

  function detailDrawer() {
    if (service !== 'dhcp' || state.drawer !== 'dhcp-detail' || !state.selected) return '';
    const scope = state.selected;
    const editor = state.editor;
    const writable = state.draft.capabilities?.service_update === true;
    const values = [['接口', scope.interface], ['地址池', scope.pool], ['排除地址', scope.excludePool], ['网关', scope.gateway], ['子网掩码', scope.netmask], ['DNS', [scope.dns1, scope.dns2].filter(Boolean).join('、')], ['租期', scope.lease ? `${scope.lease} 分钟` : '--'], ['本地域名', scope.domain], ['DHCP Options', scope.options.join('；')], ['静态分配', `${scope.reservations.length} 条`], ['当前租约', `${scope.leases.length} 条`]];
    const content = writable
      ? `<label class="network-service-setting-row is-editor"><span><strong>启用 DHCP</strong><small>关闭后停止在该作用域分配地址</small></span>${switchControl('editor.enabled', editor.enabled)}</label><div class="network-service-form">${fieldMarkup('接口', 'editor.interface', editor.interface, { wide: true, disabled: true })}${fieldMarkup('地址池', 'editor.pool', editor.pool, { wide: true, placeholder: '192.168.1.100-192.168.1.249' })}${fieldMarkup('排除地址', 'editor.excludePool', editor.excludePool, { wide: true, placeholder: '逗号分隔' })}${fieldMarkup('网关', 'editor.gateway', editor.gateway, { wide: true })}${fieldMarkup('子网掩码', 'editor.netmask', editor.netmask, { wide: true })}${fieldMarkup('首选 DNS', 'editor.dns1', editor.dns1, { wide: true })}${fieldMarkup('备用 DNS', 'editor.dns2', editor.dns2, { wide: true })}${fieldMarkup('租期（分钟）', 'editor.lease', editor.lease, { type: 'number' })}${fieldMarkup('本地域名', 'editor.domain', editor.domain, { wide: true })}</div>`
      : `<dl class="network-service-detail-list">${values.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value || '--')}</dd></div>`).join('')}</dl>${capabilityNotice('后端未开放 DHCP 作用域写入。')}`;
    return `${drawerBackdrop('关闭 DHCP 详情')}<aside class="network-service-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open"><header class="dwrt-kit-sheet-header"><div><span>DHCP SCOPE</span><strong>${escapeHtml(scope.name)}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-network-service-close>×</button></header><div class="dwrt-kit-sheet-body network-service-drawer-body"><section class="network-service-drawer-hero"><span>${icon('network')}</span><div><strong>${escapeHtml(scope.pool || '地址池未配置')}</strong><small>${escapeHtml(scope.interface || scope.lanId)}</small></div>${status(scope.enabled ? '启用' : '关闭', scope.enabled)}</section>${content}${state.notice ? noticeMarkup() : ''}</div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-network-service-close>取消</button>${writable ? `<button class="policy-primary" type="button" data-dhcp-scope-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存并应用'}</button>` : ''}</footer></aside>`;
  }

  function dnsEditorDrawer() {
    if (service !== 'dns' || !['dns-upstream', 'dns-rule'].includes(state.drawer)) return '';
    const upstream = state.drawer === 'dns-upstream';
    const editor = state.editor;
    const writable = dnsWritable();
    const protocols = [...new Set([...(state.draft.supported_protocols || ['udp', 'tcp']), editor.protocol].filter(Boolean))];
    const fields = upstream
      ? `${fieldMarkup('名称', 'editor.name', editor.name, { wide: true, placeholder: '例如 AliDNS', disabled: !writable, adaptive: true })}${fieldMarkup('地址', 'editor.address', editor.address, { wide: true, placeholder: '223.5.5.5 或 DoH URL', disabled: !writable, adaptive: true })}${fieldMarkup('协议', 'editor.protocol', editor.protocol, { type: 'select', options: protocols.map((item) => [item, item.toUpperCase()]), disabled: !writable, adaptive: true })}${fieldMarkup('端口', 'editor.port', editor.port, { type: 'number', disabled: !writable, adaptive: true })}${fieldMarkup('分组', 'editor.group', editor.group, { wide: true, placeholder: '默认', disabled: !writable, adaptive: true })}`
      : `${fieldMarkup('域名', 'editor.domain', editor.domain, { wide: true, placeholder: 'nas.lan 或 example.com', disabled: !writable, adaptive: true })}${fieldMarkup('类型', 'editor.type', editor.type, { type: 'select', options: [['host', '本地域名'], ['forward', '域名转发'], ['block', '拦截'], ['upstream', '指定上游']], disabled: !writable, adaptive: true })}${fieldMarkup('目标', 'editor.target', editor.target, { wide: true, placeholder: 'IP、DNS 服务器或上游 ID', disabled: !writable, adaptive: true })}${fieldMarkup('备注', 'editor.remark', editor.remark, { wide: true, disabled: !writable, adaptive: true })}`;
    return `${drawerBackdrop('关闭 DNS 编辑')}<aside class="network-service-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open"><header class="dwrt-kit-sheet-header"><div><span>${upstream ? 'UPSTREAM DNS' : 'DNS RULE'}</span><strong>${escapeHtml(editor._new ? (upstream ? '添加上游 DNS' : '新建 DNS 规则') : (upstream ? '编辑上游 DNS' : '编辑 DNS 规则'))}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-network-service-close>×</button></header><div class="dwrt-kit-sheet-body network-service-drawer-body"><label class="network-service-setting-row is-editor" data-adaptive-region><span><strong>启用</strong><small>停用后保留配置但不参与解析</small></span>${switchControl('editor.enabled', editor.enabled, !writable)}</label><div class="network-service-form">${fields}</div>${!writable ? capabilityNotice('后端未声明 DNS 完整快照保存与应用能力。') : ''}${state.notice ? noticeMarkup() : ''}</div><footer class="dwrt-kit-sheet-footer network-service-editor-footer">${editor._new || !writable ? '<span></span>' : '<button class="policy-secondary danger" type="button" data-network-service-delete>删除</button>'}<div><button class="policy-secondary" type="button" data-network-service-close>取消</button><button class="policy-primary" type="button" data-network-service-editor-save ${!writable ? 'disabled' : ''}>保存到草稿</button></div></footer></aside>`;
  }

  function dnsDeleteConfirmationMarkup() {
    if (service !== 'dns' || state.confirmDelete !== 'dns') return '';
    const upstream = state.drawer === 'dns-upstream';
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    return typeof renderer === 'function' ? renderer({
      id: 'dns-delete-confirmation',
      action: upstream ? 'delete-dns-upstream' : 'delete-dns-rule',
      tone: 'danger',
      title: upstream ? '删除上游 DNS' : '删除 DNS 规则',
      description: `“${firstText(upstream ? state.editor.name : state.editor.domain, state.editor.id, '未命名项目')}”将从当前 DNS 配置草稿中移除。`,
      cancelLabel: '取消',
      confirmLabel: '确认删除'
    }) : '';
  }

  function upnpMappingDrawer() {
    if (service !== 'upnp' || state.drawer !== 'upnp-mapping') return '';
    const editor = state.editor;
    return `${drawerBackdrop('关闭端口映射')}<aside class="network-service-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open"><header class="dwrt-kit-sheet-header"><div><span>PORT MAPPING</span><strong>${escapeHtml(editor._new ? '新建端口映射' : '编辑端口映射')}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-network-service-close>×</button></header><div class="dwrt-kit-sheet-body network-service-drawer-body"><label class="network-service-setting-row is-editor"><span><strong>启用映射</strong><small>保存到静态 UPnP 映射表</small></span>${switchControl('editor.enabled', editor.enabled)}</label><div class="network-service-form">${fieldMarkup('协议', 'editor.protocol', editor.protocol, { type: 'select', options: [['tcp', 'TCP'], ['udp', 'UDP']] })}${fieldMarkup('外部端口', 'editor.external_port', editor.external_port, { type: 'number' })}${fieldMarkup('内部 IP', 'editor.internal_ip', editor.internal_ip, { wide: true, placeholder: '192.168.1.100' })}${fieldMarkup('内部端口', 'editor.internal_port', editor.internal_port, { type: 'number' })}${fieldMarkup('租期（秒）', 'editor.lease', editor.lease, { type: 'number' })}${fieldMarkup('客户端', 'editor.client', editor.client, { wide: true })}${fieldMarkup('描述', 'editor.description', editor.description, { wide: true })}</div>${state.notice ? noticeMarkup() : ''}</div><footer class="dwrt-kit-sheet-footer network-service-editor-footer">${editor._new ? '<span></span>' : `<button class="policy-secondary danger" type="button" data-network-service-delete>${state.confirmDelete ? '再次点击删除' : '删除'}</button>`}<div><button class="policy-secondary" type="button" data-network-service-close>取消</button><button class="policy-primary" type="button" data-network-service-editor-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存映射'}</button></div></footer></aside>`;
  }

  function serviceEditorDrawer() {
    if (state.drawer === 'dhcp-reservation') {
      const editor = state.editor;
      const scope = state.draft.scopes.find((item) => item.id === editor.scope_id) || state.draft.scopes[0];
      return `${drawerBackdrop('关闭静态分配编辑')}<aside class="network-service-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open"><header class="dwrt-kit-sheet-header"><div><span>DHCP RESERVATION</span><strong>${escapeHtml(editor._new ? '添加静态分配' : '编辑静态分配')}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-network-service-close>×</button></header><div class="dwrt-kit-sheet-body network-service-drawer-body"><label class="network-service-setting-row is-editor"><span><strong>启用</strong><small>启用后由 dnsmasq 固定分配地址</small></span>${switchControl('editor.enabled', editor.enabled)}</label><div class="network-service-form">${fieldMarkup('名称', 'editor.name', editor.name, { wide: true })}${fieldMarkup('MAC', 'editor.mac', editor.mac, { wide: true, placeholder: 'aa:bb:cc:dd:ee:ff' })}${fieldMarkup('IP', 'editor.ip', editor.ip, { wide: true, placeholder: '192.168.1.100' })}${fieldMarkup('作用域', 'editor.scope_id', scope?.id || '', { type: 'select', options: state.draft.scopes.map((item) => [item.id, item.name]) })}${fieldMarkup('备注', 'editor.remark', editor.remark, { wide: true })}</div>${state.notice ? noticeMarkup() : ''}</div><footer class="dwrt-kit-sheet-footer network-service-editor-footer">${editor._new || state.draft.capabilities?.reservation_delete !== true ? '<span></span>' : `<button class="policy-secondary danger" type="button" data-network-service-delete>${state.confirmDelete ? '再次点击删除' : '删除'}</button>`}<div><button class="policy-secondary" type="button" data-network-service-close>取消</button><button class="policy-primary" type="button" data-network-service-editor-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存并应用'}</button></div></footer></aside>`;
    }
    if (state.drawer === 'upnp-acl') {
      const editor = state.editor;
      return `${drawerBackdrop('关闭 ACL 编辑')}<aside class="network-service-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open"><header class="dwrt-kit-sheet-header"><div><span>UPNP ACL</span><strong>${escapeHtml(editor._new ? '新建 ACL' : '编辑 ACL')}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-network-service-close>×</button></header><div class="dwrt-kit-sheet-body network-service-drawer-body"><label class="network-service-setting-row is-editor"><span><strong>启用</strong><small>停用后保留规则但不写入 miniupnpd</small></span>${switchControl('editor.enabled', editor.enabled)}</label><div class="network-service-form">${fieldMarkup('动作', 'editor.action', editor.action, { type: 'select', options: [['allow', '允许'], ['deny', '拒绝']] })}${fieldMarkup('外部端口', 'editor.external', editor.external, { wide: true, placeholder: '1024-65535' })}${fieldMarkup('内部网段', 'editor.internal', editor.internal, { wide: true, placeholder: '192.168.1.0/24' })}${fieldMarkup('内部端口', 'editor.internal_ports', editor.internal_ports, { wide: true, placeholder: '1024-65535' })}${fieldMarkup('排序', 'editor.sort_order', editor.sort_order, { type: 'number' })}${fieldMarkup('备注', 'editor.remark', editor.remark, { wide: true })}</div>${state.notice ? noticeMarkup() : ''}</div><footer class="dwrt-kit-sheet-footer network-service-editor-footer">${editor._new || state.draft.capabilities?.acl_delete !== true ? '<span></span>' : `<button class="policy-secondary danger" type="button" data-network-service-delete>${state.confirmDelete ? '再次点击删除' : '删除'}</button>`}<div><button class="policy-secondary" type="button" data-network-service-close>取消</button><button class="policy-primary" type="button" data-network-service-editor-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存并应用'}</button></div></footer></aside>`;
    }
    return '';
  }

  function render() {
    if (!root) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.remove('is-dhcp', 'is-dns', 'is-upnp');
    root.classList.add('route-workspace', 'policy-table-route-host', 'network-service-route-host', MODULE_CLASS);
    const content = service === 'dhcp' ? renderDhcp() : service === 'dns' ? renderDns() : renderUpnp();
    root.innerHTML = `<section class="network-service-shell">${pageHeaderMarkup()}<main class="network-service-workbench">${noticeMarkup()}${content}</main>${detailDrawer()}${dnsEditorDrawer()}${upnpMappingDrawer()}${serviceEditorDrawer()}${dnsDeleteConfirmationMarkup()}</section>`;
    ui.mountAll?.(root);
    ui.scheduleAdaptiveForegroundSample?.(20, root);
  }

  function patchDnsOverview() {
    if (service !== 'dns' || state.tab !== 'overview') return;
    const workbench = root?.querySelector('.network-service-workbench');
    if (!workbench) { render(); return; }
    const scrollTop = workbench.scrollTop;
    const template = document.createElement('template');
    template.innerHTML = `${noticeMarkup()}${renderDns()}`;
    workbench.replaceChildren(template.content);
    workbench.scrollTop = scrollTop;
    ui.mountAll?.(workbench);
    ui.scheduleAdaptiveForegroundSample?.(20, workbench);
  }

  function patchRefreshButton() {
    const button = root?.querySelector('[data-network-service-refresh]');
    if (!button) return;
    button.disabled = state.refreshing;
    const span = button.querySelector('span');
    if (span) span.textContent = state.refreshing ? '正在刷新' : '刷新';
  }

  function patchList() {
    const workbench = root?.querySelector('.network-service-workbench');
    if (!workbench) { render(); return; }
    const card = workbench.querySelector('.network-service-table-card');
    if (!card) { render(); return; }
    const scroll = card.querySelector('.dwrt-kit-table-scroll');
    const top = scroll?.scrollTop || 0;
    const left = scroll?.scrollLeft || 0;
    const template = document.createElement('template');
    template.innerHTML = service === 'dhcp' ? renderDhcp() : service === 'dns' ? renderDns() : renderUpnp();
    const nextCard = template.content.querySelector('.network-service-table-card');
    if (!nextCard) return;
    card.replaceWith(nextCard);
    const next = nextCard.querySelector('.dwrt-kit-table-scroll');
    if (next) { next.scrollTop = top; next.scrollLeft = left; }
    ui.mountAll?.(nextCard);
  }

  function setPath(object, path, value) {
    const parts = String(path).split('.');
    let target = object;
    parts.slice(0, -1).forEach((part) => { if (!target[part] || typeof target[part] !== 'object') target[part] = {}; target = target[part]; });
    target[parts.at(-1)] = value;
  }

  function patchDirtyBar() {
    const existing = root?.querySelector('[data-dwrt-savebar]');
    const markup = dirtyBar();
    if (!existing && markup) root?.querySelector('.network-service-workbench')?.insertAdjacentHTML('beforeend', markup);
    else if (existing && markup) existing.outerHTML = markup;
    else existing?.remove();
  }

  function closeDrawer() {
    state.drawer = '';
    state.selected = null;
    state.editor = {};
    state.confirmDelete = false;
    state.notice = '';
    render();
  }

  function openDnsEditor(kind, id = '') {
    const upstream = kind === 'upstream';
    const source = upstream ? state.draft.upstreams : state.draft.rules;
    const item = source.find((entry) => entry.id === id);
    state.editor = clone(item || (upstream
      ? { id: `dns-${Date.now()}`, name: '', address: '', protocol: 'udp', port: 53, group: '默认', enabled: true }
      : { id: `rule-${Date.now()}`, domain: '', type: state.tab === 'forwarding' ? 'forward' : 'host', target: '', remark: '', enabled: true }));
    state.editor._new = !item;
    state.drawer = upstream ? 'dns-upstream' : 'dns-rule';
    state.confirmDelete = false;
    state.notice = '';
    render();
  }

  function saveDnsEditor() {
    if (!dnsWritable()) return;
    const upstream = state.drawer === 'dns-upstream';
    const editor = clone(state.editor);
    delete editor._new;
    if (upstream && (!editor.name || !editor.address)) { state.notice = '名称和地址不能为空'; state.noticeTone = 'bad'; render(); return; }
    if (!upstream && (!editor.domain || !editor.target)) { state.notice = '域名和目标不能为空'; state.noticeTone = 'bad'; render(); return; }
    const bucket = upstream ? state.draft.upstreams : state.draft.rules;
    const index = bucket.findIndex((entry) => entry.id === editor.id);
    if (index >= 0) bucket[index] = editor; else bucket.push(editor);
    state.dirty = true;
    state.drawer = '';
    state.editor = {};
    state.notice = '';
    render();
  }

  function deleteDnsEditor() {
    if (!dnsWritable()) return;
    state.confirmDelete = 'dns';
    render();
  }

  function confirmDnsDelete() {
    if (!dnsWritable() || state.confirmDelete !== 'dns') return;
    const upstream = state.drawer === 'dns-upstream';
    const key = upstream ? 'upstreams' : 'rules';
    state.draft[key] = state.draft[key].filter((entry) => entry.id !== state.editor.id);
    state.dirty = true;
    state.drawer = '';
    state.editor = {};
    state.confirmDelete = false;
    render();
  }

  function openUpnpMapping(id = '') {
    const item = state.draft.mappings.find((entry) => String(entry.id) === String(id));
    state.editor = clone(item || { id: `mapping-${Date.now()}`, enabled: true, protocol: 'tcp', external_port: '', internal_ip: '', internal_port: '', client: '', description: '', lease: 3600, packets: 0 });
    state.editor._new = !item;
    state.drawer = 'upnp-mapping';
    state.confirmDelete = false;
    state.notice = '';
    render();
  }

  function openDhcpReservation(id = '', scopeId = '') {
    const scope = state.draft.scopes.find((item) => item.id === scopeId) || state.draft.scopes[0];
    const item = scope?.reservations.find((entry) => String(entry.id) === String(id));
    state.editor = clone(item || { id: `dhcp-${Date.now()}`, name: '', mac: '', ip: '', remark: '', enabled: true });
    state.editor.scope_id = scope?.id || '';
    state.editor._new = !item;
    state.drawer = 'dhcp-reservation';
    state.confirmDelete = false;
    state.notice = '';
    render();
  }

  async function saveDhcpScope() {
    const scope = state.selected;
    const editor = clone(state.editor);
    if (!scope || state.saving) return;
    state.saving = true;
    render();
    try {
      await requestJson(ENDPOINTS.dhcp, { method: 'PUT', body: JSON.stringify({ lan_id: scope.lanId || scope.id, dhcp: { id: scope.id, enabled: editor.enabled, pool: editor.pool, exclude_pool: editor.excludePool, gateway: editor.gateway, netmask: editor.netmask, dns1: editor.dns1, dns2: editor.dns2, lease: editor.lease, domain: editor.domain, options: scope.options, reservations: scope.reservations } }) });
      state.saving = false;
      state.drawer = '';
      state.selected = null;
      state.notice = 'DHCP 作用域已保存并应用';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `保存失败：${firstText(error.message, '后端未接受 DHCP 配置')}`;
      state.noticeTone = 'bad';
      render();
    }
  }

  function openUpnpAcl(id = '') {
    const item = state.draft.acl.find((entry) => String(entry.id) === String(id));
    state.editor = clone(item || { id: `acl-${Date.now()}`, action: 'allow', external: '1024-65535', internal: '0.0.0.0/0', internal_ports: '1024-65535', remark: '', enabled: true, sort_order: 0 });
    state.editor._new = !item;
    state.drawer = 'upnp-acl';
    state.confirmDelete = false;
    state.notice = '';
    render();
  }

  async function saveDhcpReservation() {
    const editor = clone(state.editor);
    delete editor._new;
    const scope = state.draft.scopes.find((item) => item.id === editor.scope_id);
    if (!scope || !editor.name || !editor.mac || !editor.ip) { state.notice = '名称、MAC、IP 和作用域不能为空'; state.noticeTone = 'bad'; render(); return; }
    const reservations = scope.reservations.filter((item) => item.id !== editor.id);
    reservations.push(editor);
    state.saving = true;
    render();
    try {
      await requestJson(ENDPOINTS.dhcp, { method: 'PUT', body: JSON.stringify({ lan_id: scope.lanId || scope.id, dhcp: { ...scope.raw, id: scope.id, enabled: scope.enabled, pool: scope.pool, exclude_pool: scope.excludePool, gateway: scope.gateway, netmask: scope.netmask, dns1: scope.dns1, dns2: scope.dns2, lease: scope.lease, domain: scope.domain, options: scope.options, reservations } }) });
      state.saving = false;
      state.drawer = '';
      state.notice = '静态分配已保存并应用';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `保存失败：${firstText(error.message, '后端未接受配置')}`;
      state.noticeTone = 'bad';
      render();
    }
  }

  async function deleteDhcpReservation() {
    if (!state.confirmDelete) { state.confirmDelete = true; render(); return; }
    state.saving = true;
    render();
    try {
      await requestJson(`${ENDPOINTS.dhcp}/reservations/${encodeURIComponent(state.editor.id)}`, { method: 'DELETE' });
      state.saving = false;
      state.drawer = '';
      state.notice = '静态分配已删除';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `删除失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'bad';
      render();
    }
  }

  async function saveUpnpAcl() {
    const editor = clone(state.editor);
    delete editor._new;
    state.saving = true;
    render();
    try {
      await requestJson(`${ENDPOINTS.upnp}/acl`, { method: 'PUT', body: JSON.stringify(editor) });
      state.saving = false;
      state.drawer = '';
      state.notice = 'ACL 已保存并应用';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `保存失败：${firstText(error.message, '后端未接受 ACL')}`;
      state.noticeTone = 'bad';
      render();
    }
  }

  async function deleteUpnpAcl() {
    if (!state.confirmDelete) { state.confirmDelete = true; render(); return; }
    state.saving = true;
    render();
    try {
      await requestJson(`${ENDPOINTS.upnp}/acl/${encodeURIComponent(state.editor.id)}`, { method: 'DELETE' });
      state.saving = false;
      state.drawer = '';
      state.notice = 'ACL 已删除';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `删除失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'bad';
      render();
    }
  }

  async function saveUpnpMapping() {
    const editor = clone(state.editor);
    delete editor._new;
    if (!editor.external_port || !editor.internal_ip || !editor.internal_port) { state.notice = '外部端口、内部 IP 和内部端口不能为空'; state.noticeTone = 'bad'; render(); return; }
    state.saving = true;
    render();
    try {
      await requestJson(ENDPOINTS.upnpMappings, { method: 'PUT', body: JSON.stringify(editor) });
      state.saving = false;
      state.drawer = '';
      state.notice = '端口映射已保存';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `保存失败：${firstText(error.message, '后端未接受配置')}`;
      state.noticeTone = 'bad';
      render();
    }
  }

  async function deleteUpnpMapping() {
    if (!state.confirmDelete) { state.confirmDelete = true; render(); return; }
    state.saving = true;
    render();
    try {
      await requestJson(`${ENDPOINTS.upnpMappings}/${encodeURIComponent(state.editor.id)}`, { method: 'DELETE' });
      state.saving = false;
      state.drawer = '';
      state.notice = '端口映射已删除';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `删除失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'bad';
      render();
    }
  }

  function dnsPayload() {
    const source = clone(state.draft);
    delete source.wanPolicies;
    delete source.stats;
    delete source.capabilities;
    delete source.supported_protocols;
    delete source.ts;
    delete source.apply_state;
    return { ...source, apply: true };
  }

  function upnpPayload() {
    const source = clone(state.draft);
    delete source.acl;
    delete source.mappings;
    delete source.stats;
    delete source.capabilities;
    delete source.ts;
    delete source.apply_state;
    return source;
  }

  async function saveUpnp() {
    if (state.saving || state.draft.capabilities?.service_update !== true) return;
    state.saving = true;
    state.notice = '';
    patchDirtyBar();
    try {
      await requestJson(ENDPOINTS.upnp, { method: 'PUT', body: JSON.stringify(upnpPayload()) });
      state.saving = false;
      state.notice = 'UPnP 配置已保存并应用';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `保存失败：${firstText(error.message, '后端未接受配置')}`;
      state.noticeTone = 'bad';
      render();
    }
  }

  async function saveDns() {
    if (state.saving || (!state.dirty && !state.dirtyPolicies.size)) return;
    if (state.dirty && !dnsWritable()) {
      state.notice = '保存已阻止：后端未声明 DNS 完整快照写入能力';
      state.noticeTone = 'bad';
      render();
      return;
    }
    const validationError = dnsValidationError();
    if (validationError) {
      state.notice = `保存已阻止：${validationError}`;
      state.noticeTone = 'bad';
      render();
      return;
    }
    state.saving = true;
    state.notice = '';
    patchDirtyBar();
    try {
      let serviceResult = null;
      if (state.dirty) serviceResult = await requestJson(ENDPOINTS.dns, { method: 'PUT', body: JSON.stringify(dnsPayload()) });
      for (const wanId of state.dirtyPolicies) {
        const policy = state.draft.wanPolicies.find((item) => item.wan_id === wanId);
        if (!policy) continue;
        await requestJson(ENDPOINTS.dnsPolicy, {
          method: 'PUT', body: JSON.stringify({ wan_id: wanId, policies: [{
            upstream_id: policy.upstream_id || '', mode: policy.mode || 'auto', dns_servers: policy.dns_servers || [],
            domains: policy.domains || [], enabled: policy.mode !== 'disabled' && policy.enabled !== false, sort_order: policy.sort_order || 0
          }] })
        });
      }
      state.saving = false;
      const applied = !serviceResult || serviceResult.applied === true || serviceResult.apply_state === 'applied';
      const readback = !serviceResult || serviceResult.readback || serviceResult.runtime_readback === true;
      state.notice = applied && readback ? 'DNS 配置已保存，运行态已确认' : 'DNS 配置已保存，但运行态尚未确认';
      state.noticeTone = applied && readback ? 'ok' : 'warn';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `保存失败：${firstText(error.message, '后端未接受配置')}`;
      state.noticeTone = 'bad';
      render();
    }
  }

  function dnsValidationError() {
    if (service !== 'dns') return '';
    const data = state.draft;
    if (data.enabled && !data.listen_interfaces.length) return '启用 DNS 代理前至少选择一个监听接口';
    if (!Number.isInteger(Number(data.listen_port)) || Number(data.listen_port) < 1 || Number(data.listen_port) > 65535) return '监听端口必须在 1 到 65535 之间';
    if (data.cache_enabled && (!Number.isInteger(Number(data.cache_size)) || Number(data.cache_size) < 1)) return '缓存容量必须是大于 0 的整数';
    const invalidUpstream = data.upstreams.find((item) => !item.id || !item.name || !item.address || Number(item.port) < 1 || Number(item.port) > 65535);
    if (invalidUpstream) return `上游 DNS“${invalidUpstream.name || invalidUpstream.id || '未命名'}”配置不完整`;
    const invalidRule = data.rules.find((item) => !item.id || !item.domain || !item.target);
    if (invalidRule) return `域名规则“${invalidRule.domain || invalidRule.id || '未命名'}”配置不完整`;
    return '';
  }

  function resetDraft() {
    state.draft = clone(state.initial);
    state.dirty = false;
    state.dirtyPolicies.clear();
    state.notice = '未保存的变更已复位';
    state.noticeTone = 'ok';
    render();
  }

  function onClick(event) {
    if (event.target.closest('[data-network-service-refresh]')) { load(true); return; }
    if (event.target.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]')) { state.confirmDelete = false; render(); return; }
    if (event.target.closest('[data-dwrt-confirm-accept]') && state.confirmDelete === 'dns') { confirmDnsDelete(); return; }
    const dnsGroup = event.target.closest('[data-dns-group-toggle]');
    if (dnsGroup && service === 'dns') {
      state.dnsGroup = dnsGroup.dataset.dnsGroupToggle;
      patchDnsOverview();
      return;
    }
    const dnsTab = event.target.closest('[data-dns-open-tab]');
    if (dnsTab && service === 'dns') {
      state.tab = dnsTab.dataset.dnsOpenTab;
      state.query = '';
      render();
      return;
    }
    if (event.target.closest('[data-network-service-close]')) { closeDrawer(); return; }
    if (event.target.closest('[data-dwrt-savebar-discard]')) { resetDraft(); return; }
    if (event.target.closest('[data-dhcp-scope-save]')) { saveDhcpScope(); return; }
    if (event.target.closest('[data-dwrt-savebar-save]')) {
      if (service === 'dns') saveDns();
      else if (service === 'upnp') saveUpnp();
      return;
    }
    const detail = event.target.closest('[data-dhcp-detail]');
    if (detail) { state.selected = state.draft.scopes.find((item) => item.id === detail.dataset.dhcpDetail); state.editor = clone(state.selected || {}); state.drawer = 'dhcp-detail'; render(); return; }
    const upstream = event.target.closest('[data-dns-edit-upstream]');
    if (upstream) { openDnsEditor('upstream', upstream.dataset.dnsEditUpstream); return; }
    const rule = event.target.closest('[data-dns-edit-rule]');
    if (rule) { openDnsEditor('rule', rule.dataset.dnsEditRule); return; }
    const mapping = event.target.closest('[data-upnp-edit-mapping]');
    if (mapping) { openUpnpMapping(mapping.dataset.upnpEditMapping); return; }
    const reservation = event.target.closest('[data-dhcp-reservation]');
    if (reservation) { openDhcpReservation(reservation.dataset.dhcpReservation, reservation.dataset.dhcpReservationScope); return; }
    const acl = event.target.closest('[data-upnp-edit-acl]');
    if (acl) { openUpnpAcl(acl.dataset.upnpEditAcl); return; }
    if (event.target.closest('[data-network-service-create]')) {
      if (service === 'dns') openDnsEditor(state.tab === 'upstreams' ? 'upstream' : 'rule');
      else if (service === 'dhcp' && state.tab === 'reservations') openDhcpReservation();
      else if (service === 'upnp' && state.tab === 'access') openUpnpAcl();
      else if (service === 'upnp') openUpnpMapping();
      return;
    }
    if (event.target.closest('[data-network-service-editor-save]')) {
      if (state.drawer === 'dhcp-reservation') saveDhcpReservation();
      else if (state.drawer === 'upnp-acl') saveUpnpAcl();
      else if (service === 'dns') saveDnsEditor();
      else if (service === 'upnp') saveUpnpMapping();
      return;
    }
    if (event.target.closest('[data-network-service-delete]')) {
      if (state.drawer === 'dhcp-reservation') deleteDhcpReservation();
      else if (state.drawer === 'upnp-acl') deleteUpnpAcl();
      else if (service === 'dns') deleteDnsEditor();
      else if (service === 'upnp') deleteUpnpMapping();
    }
  }

  function onInput(event) {
    const search = event.target.closest('[data-network-service-search]');
    if (search) { state.query = search.value; patchList(); return; }
    const policy = event.target.closest('[data-dns-policy-index]');
    if (policy) {
      const index = Number(policy.dataset.dnsPolicyIndex);
      const row = state.draft.wanPolicies[index];
      if (!row) return;
      const field = policy.dataset.dnsPolicyField;
      if (field === 'dns_servers') row.dns_servers[0] = policy.value.trim();
      else if (field === 'dns_secondary') row.dns_servers[1] = policy.value.trim();
      else if (field === 'domains') row.domains = policy.value.split(/[;,]/).map((item) => item.trim()).filter(Boolean);
      state.dirtyPolicies.add(row.wan_id);
      patchDirtyBar();
      return;
    }
    const field = event.target.closest('[data-service-field]');
    if (!field || ['checkbox', 'radio'].includes(field.type) || field.tagName === 'SELECT') return;
    const path = field.dataset.serviceField;
    if (path.startsWith('editor.')) setPath(state, path, field.type === 'number' ? Number(field.value || 0) : field.value);
    else {
      const value = ['listen_interfaces', 'internal_ifaces'].includes(path) ? field.value.split(/[;,]/).map((item) => item.trim()).filter(Boolean) : field.type === 'number' ? Number(field.value || 0) : field.value;
      setPath(state.draft, path, value);
      state.dirty = true;
      patchDirtyBar();
    }
  }

  function onChange(event) {
    const policy = event.target.closest('[data-dns-policy-index]');
    if (policy) {
      const row = state.draft.wanPolicies[Number(policy.dataset.dnsPolicyIndex)];
      if (!row) return;
      row[policy.dataset.dnsPolicyField] = policy.value;
      row.enabled = policy.value !== 'disabled';
      state.dirtyPolicies.add(row.wan_id);
      patchDirtyBar();
      return;
    }
    const field = event.target.closest('[data-service-field]');
    if (!field) return;
    const path = field.dataset.serviceField;
    const value = field.type === 'checkbox' ? field.checked : field.type === 'number' ? Number(field.value || 0) : field.value;
    if (path.startsWith('editor.')) setPath(state, path, value);
    else {
      setPath(state.draft, path, value);
      state.dirty = true;
      if (service === 'dns' && state.tab === 'overview' && ['enabled', 'cache_enabled'].includes(path)) {
        if (path === 'enabled' && value && state.dnsGroup === 'core') state.dnsGroup = 'listen';
        if (path === 'enabled' && !value) state.dnsGroup = 'core';
        patchDnsOverview();
      } else patchDirtyBar();
    }
  }

  function onTabChange(event) {
    const tabs = event.target.closest('[data-network-service-tabs]');
    if (!tabs) return;
    const next = event.detail?.value;
    if (!TABS[service].some(([id]) => id === next) || next === state.tab) return;
    state.tab = next;
    state.query = '';
    state.drawer = '';
    state.selected = null;
    render();
  }

  root.addEventListener('click', onClick);
  root.addEventListener('input', onInput);
  root.addEventListener('change', onChange);
  root.addEventListener('dwrt-tab-change', onTabChange);
  stage?.classList.add('is-network-services');
  render();
  load();

  return {
    refresh() { return load(true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      root.removeEventListener('click', onClick);
      root.removeEventListener('input', onInput);
      root.removeEventListener('change', onChange);
      root.removeEventListener('dwrt-tab-change', onTabChange);
      root.replaceChildren();
      root.classList.remove('route-workspace', 'policy-table-route-host', 'network-service-route-host', 'is-dhcp', 'is-dns', 'is-upnp');
      stage?.classList.remove('is-network-services');
    }
  };
}

export default { mount };
