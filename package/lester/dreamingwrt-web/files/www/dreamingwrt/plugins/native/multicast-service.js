export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  if (!root) return () => {};
  const stage = root.closest('.console-stage');
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const VERSION = '20260725-multicast-workbench-04';
  const TABS = [
    ['overview', '总览'],
    ['igmp', 'IGMP / MLD 代理'],
    ['iptv', 'IPTV 透传'],
    ['udpxy', 'UDPXY'],
    ['discovery', '局域发现']
  ];
  const SUCCESS_CODES = new Set([0, 200, 2000]);
  const state = {
    mounted: true,
    seq: 0,
    loading: true,
    refreshing: false,
    saving: false,
    tab: 'overview',
    data: null,
    draft: null,
    initial: null,
    wans: [],
    lans: [],
    ports: [],
    dirty: false,
    error: '',
    notice: '',
    confirmation: null,
    lastUpdated: 0
  };

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (typeof value === 'object' && !Array.isArray(value)) {
        const nested = firstText(value.message, value.error, value.reason, value.label, value.name, value.id);
        if (nested) return nested;
        continue;
      }
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }

  function bool(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') return !['0', 'false', 'off', 'no', 'disabled'].includes(value.toLowerCase());
    return Boolean(value);
  }

  function number(value, fallback = 0) {
    if (value === '' || value === null || value === undefined) return fallback;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
  }

  function clone(value) {
    try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value ?? null)); }
  }

  function array(value) {
    if (Array.isArray(value)) return value;
    if (!value) return [];
    if (typeof value === 'string') return value.split(/[;,]/).map((item) => item.trim()).filter(Boolean);
    if (typeof value === 'object') {
      for (const key of ['items', 'rows', 'list', 'data', 'interfaces', 'wans', 'lans', 'ports']) if (Array.isArray(value[key])) return value[key];
    }
    return [];
  }

  function idValue(value, fallback = '') {
    if (value && typeof value === 'object') return firstText(value.id, value.name, value.interface, value.ifname, value.device, fallback);
    return firstText(value, fallback);
  }

  function listValues(value) {
    return array(value).map((item) => idValue(item)).filter(Boolean);
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
    const response = await fetch(`${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`, {
      credentials: 'same-origin',
      cache: 'no-store',
      signal: context.signal,
      ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    const code = json?.code;
    const payload = json?.data ?? json?.body ?? json;
    const businessFailed = code !== undefined && code !== null && !SUCCESS_CODES.has(Number(code));
    if (!response.ok || json?.ok === false || payload?.ok === false || businessFailed) {
      const error = new Error(firstText(payload?.message, payload?.error, payload?.reason, json?.message, json?.error, `HTTP ${response.status}`));
      error.status = response.status;
      error.payload = json;
      throw error;
    }
    return payload || {};
  }

  function defaultService() {
    return {
      igmp_proxy: { enabled: false, version: '3', quick_leave: true, upstream: '', downstreams: [], alt_subnets: ['0.0.0.0/0'] },
      iptv_passthrough: { enabled: false, wan_iface: '', lan_iface: '', vlan_id: '', stb_ports: [], mode: 'bridge', keep_internet: true },
      udpxy: { enabled: false, listen_iface: '', listen_port: 4022, source_iface: '', clients: 0, buffer_kb: 2048, max_clients: 64, status: 'unknown', instances: [] },
      discovery: { mdns_reflector: false, ssdp_relay: false, igmp_snooping: false, mld_snooping: false, querier: false, query_interval: 125, allowed_groups: [] },
      status: { groups: 0, subscribers: 0, rx_rate: 0, tx_rate: 0, dropped: 0 },
      group_state: [],
      capabilities: {},
      runtime: {}
    };
  }

  function normalizeService(source = {}) {
    const base = defaultService();
    const igmp = source.igmp_proxy || source.igmp || {};
    const iptv = source.iptv_passthrough || source.iptv || {};
    const udpxy = source.udpxy || {};
    const discovery = source.discovery || {};
    const groups = array(source.group_state || source.groups);
    return {
      ...base,
      ...source,
      igmp_proxy: {
        ...base.igmp_proxy,
        ...igmp,
        enabled: bool(igmp.enabled),
        version: String(firstText(igmp.version, igmp.igmp_version, '3')).replace(/^IGMPv?/i, ''),
        quick_leave: bool(igmp.quick_leave, true),
        upstream: idValue(igmp.upstream || igmp.upstream_iface || igmp.uplink),
        downstreams: listValues(igmp.downstreams || igmp.downstream),
        alt_subnets: listValues(igmp.alt_subnets).length ? listValues(igmp.alt_subnets) : ['0.0.0.0/0']
      },
      iptv_passthrough: {
        ...base.iptv_passthrough,
        ...iptv,
        enabled: bool(iptv.enabled),
        wan_iface: idValue(iptv.wan_iface || iptv.wan),
        lan_iface: idValue(iptv.lan_iface || iptv.lan),
        vlan_id: firstText(iptv.vlan_id, iptv.vid),
        stb_ports: listValues(iptv.stb_ports || iptv.ports),
        mode: firstText(iptv.mode, 'bridge'),
        keep_internet: bool(iptv.keep_internet, true)
      },
      udpxy: {
        ...base.udpxy,
        ...udpxy,
        enabled: bool(udpxy.enabled),
        listen_iface: idValue(udpxy.listen_iface || udpxy.bind_iface),
        listen_port: number(udpxy.listen_port ?? udpxy.port, 4022),
        source_iface: idValue(udpxy.source_iface || udpxy.upstream),
        clients: number(udpxy.clients),
        buffer_kb: number(udpxy.buffer_kb ?? udpxy.buffer, 2048),
        max_clients: number(udpxy.max_clients, 64),
        status: firstText(udpxy.status, 'unknown'),
        instances: array(udpxy.instances || source.udpxy_instances).map((item, index) => ({
          id: firstText(item.id, `udpxy-${index + 1}`),
          name: firstText(item.name, item.comment, `UDPXY ${index + 1}`),
          source_iface: idValue(item.source_iface || item.upstream || item.iface),
          listen_iface: idValue(item.listen_iface || item.bind_iface || item.lan_iface),
          listen_port: number(item.listen_port ?? item.port, 4022 + index),
          subscribe_interval: number(item.subscribe_interval ?? item.renew_interval ?? item.interval, 30),
          external_access: bool(item.external_access),
          enabled: bool(item.enabled, true),
          clients: number(item.clients),
          status: firstText(item.status, 'unknown')
        }))
      },
      discovery: {
        ...base.discovery,
        ...discovery,
        mdns_reflector: bool(discovery.mdns_reflector),
        ssdp_relay: bool(discovery.ssdp_relay),
        igmp_snooping: bool(discovery.igmp_snooping),
        mld_snooping: bool(discovery.mld_snooping),
        querier: bool(discovery.querier),
        query_interval: number(discovery.query_interval, 125),
        allowed_groups: array(discovery.allowed_groups || source.allowed_groups).map((item, index) => ({
          id: firstText(item.id, `allow-${index + 1}`),
          group: firstText(item.group, item.addr),
          source: firstText(item.source, item.src, '0.0.0.0/0'),
          downstream: idValue(item.downstream || item.iface),
          remark: firstText(item.remark, item.note),
          enabled: bool(item.enabled, true)
        }))
      },
      status: {
        groups: number(source.status?.groups ?? source.group_count, groups.length),
        subscribers: number(source.status?.subscribers ?? source.subscribers),
        rx_rate: number(source.status?.rx_rate ?? source.rx_rate),
        tx_rate: number(source.status?.tx_rate ?? source.tx_rate),
        dropped: number(source.status?.dropped ?? source.dropped),
        last_change: number(source.status?.last_change ?? source.last_change)
      },
      group_state: groups.map((item, index) => ({
        id: firstText(item.id, `${firstText(item.group, 'group')}-${index}`),
        group: firstText(item.group, item.addr, '--'),
        source: firstText(item.source, item.src, '--'),
        upstream: idValue(item.upstream || item.upstream_iface || item.wan, '--'),
        downstream: idValue(item.downstream || item.downstream_iface || item.lan, '--'),
        subscribers: number(item.subscribers ?? item.clients),
        rate: number(item.rate ?? item.rx_rate ?? item.tx_rate),
        last_seen: item.last_seen ?? item.ts ?? null,
        client: firstText(item.client, item.host, item.device)
      })),
      capabilities: source.capabilities && typeof source.capabilities === 'object' ? source.capabilities : {},
      runtime: source.runtime && typeof source.runtime === 'object' ? source.runtime : {}
    };
  }

  function normalizeInterfaces(payload, kind) {
    return array(payload).map((item, index) => ({
      id: firstText(item.id, item.name, item.interface, item.ifname, item.device, `${kind}-${index + 1}`),
      label: firstText(item.display_name, item.label, item.isp_name, item.operator_name, item.name, item.id, item.interface, item.device),
      device: firstText(item.l3_device, item.device, item.ifname, item.interface),
      owner: firstText(item.owner, item.role, item.network)
    })).filter((item) => item.id);
  }

  async function load(refreshing = false) {
    const seq = ++state.seq;
    state.loading = !state.data;
    state.refreshing = refreshing;
    state.error = '';
    render();
    const results = await Promise.allSettled([
      requestJson('/api/v1/services/multicast'),
      requestJson('/api/v1/network/wans'),
      requestJson('/api/v1/network/lans'),
      requestJson('/api/v1/network/ports')
    ]);
    if (!state.mounted || seq !== state.seq) return;
    const multicast = results[0];
    if (multicast.status !== 'fulfilled') {
      state.loading = false;
      state.refreshing = false;
      state.error = multicast.reason?.message || '无法读取组播服务配置';
      render();
      return;
    }
    state.data = normalizeService(multicast.value);
    if (!state.dirty) {
      state.draft = clone(state.data);
      state.initial = clone(state.data);
    } else {
      state.draft.status = clone(state.data.status);
      state.draft.group_state = clone(state.data.group_state);
      state.draft.runtime = clone(state.data.runtime);
    }
    state.wans = results[1].status === 'fulfilled' ? normalizeInterfaces(results[1].value, 'wan') : state.wans;
    state.lans = results[2].status === 'fulfilled' ? normalizeInterfaces(results[2].value, 'lan') : state.lans;
    state.ports = results[3].status === 'fulfilled' ? normalizeInterfaces(results[3].value, 'port') : state.ports;
    state.loading = false;
    state.refreshing = false;
    state.lastUpdated = Date.now();
    render();
  }

  function configPayload() {
    const draft = state.draft || defaultService();
    return {
      igmp_proxy: clone(draft.igmp_proxy),
      iptv_passthrough: clone(draft.iptv_passthrough),
      udpxy: clone(draft.udpxy),
      discovery: clone(draft.discovery)
    };
  }

  function externalAccessNewlyEnabled() {
    const before = new Map(array(state.initial?.udpxy?.instances).map((item) => [item.id, bool(item.external_access)]));
    return array(state.draft?.udpxy?.instances).some((item) => bool(item.external_access) && !before.get(item.id));
  }

  function validateDraft() {
    const draft = state.draft;
    if (!draft) return '配置尚未加载';
    if (!['2', '3'].includes(String(draft.igmp_proxy.version))) return 'IGMP 版本必须为 2 或 3';
    if (draft.igmp_proxy.enabled && (!draft.igmp_proxy.upstream || !draft.igmp_proxy.downstreams.length)) return '启用 IGMP 代理后必须选择上联 WAN 和至少一个下联 LAN';
    if (draft.iptv_passthrough.enabled && (!draft.iptv_passthrough.wan_iface || !draft.iptv_passthrough.lan_iface)) return '启用 IPTV 透传后必须选择上联 WAN 和目标 LAN';
    if (draft.iptv_passthrough.vlan_id && (number(draft.iptv_passthrough.vlan_id) < 1 || number(draft.iptv_passthrough.vlan_id) > 4094)) return 'IPTV VLAN 必须在 1 到 4094 之间';
    const endpoints = new Set();
    for (const instance of draft.udpxy.instances) {
      if (instance.listen_port < 1 || instance.listen_port > 65535) return `UDPXY 实例“${instance.name}”端口无效`;
      const key = `${instance.listen_iface}:${instance.listen_port}`;
      if (endpoints.has(key)) return `UDPXY 监听地址重复：${key}`;
      endpoints.add(key);
    }
    if (draft.discovery.query_interval < 10 || draft.discovery.query_interval > 3600) return '查询间隔必须在 10 到 3600 秒之间';
    return '';
  }

  async function save() {
    if (!canWrite() || !state.dirty || state.saving) return;
    const validation = validateDraft();
    if (validation) {
      state.error = validation;
      render();
      return;
    }
    if (externalAccessNewlyEnabled() && !state.confirmation) {
      state.confirmation = {
        action: 'save-external',
        title: '确认开放 UDPXY 外网访问',
        description: '外网客户端将能够访问选中实例。请确认防火墙范围和访问来源已经受控。',
        confirmLabel: '确认并保存'
      };
      render();
      return;
    }
    state.saving = true;
    state.error = '';
    render();
    try {
      await requestJson('/api/v1/services/multicast', { method: 'PUT', body: JSON.stringify(configPayload()) });
      const applied = await requestJson('/api/v1/services/multicast/apply', { method: 'POST', body: JSON.stringify({ dry_run: false }) });
      state.notice = firstText(applied.message, applied.result, '配置已保存。运行状态以后端实时回读为准。');
      state.dirty = false;
      state.confirmation = null;
      state.initial = clone(state.draft);
      await load(true);
    } catch (error) {
      state.error = error?.message || '保存组播服务失败';
    } finally {
      state.saving = false;
      render();
    }
  }

  function discard() {
    state.draft = clone(state.initial || state.data || defaultService());
    state.dirty = false;
    state.error = '';
    state.notice = '';
    render();
  }

  function icon(name) {
    const paths = {
      network: '<rect x="3" y="4" width="18" height="16" rx="3"></rect><path d="M7 9h10M7 13h6M17 13h.01"></path>',
      users: '<circle cx="8" cy="9" r="3"></circle><circle cx="16" cy="9" r="3"></circle><path d="M3 20c.8-3 2.6-5 5-5s4.2 2 5 5M11 20c.8-3 2.6-5 5-5 2 0 3.6 1.4 4.6 3.7"></path>',
      activity: '<path d="M3 12h4l2-6 4 12 2-6h6"></path>',
      shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      trash: '<path d="M4 7h16M9 7V4h6v3m-9 0 1 13h10l1-13M10 11v5m4-5v5"></path>',
      warning: '<path d="M12 9v4M12 17h.01"></path><path d="M10.3 3.4 2.7 17a2 2 0 0 0 1.8 3h15a2 2 0 0 0 1.8-3L13.7 3.4a2 2 0 0 0-3.4 0Z"></path>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.network}</svg>`;
  }

  function formatRate(value) {
    const bytes = Math.max(0, number(value));
    if (bytes >= 125000000) return `${(bytes * 8 / 1000000000).toFixed(2)} Gbps`;
    if (bytes >= 125000) return `${(bytes * 8 / 1000000).toFixed(2)} Mbps`;
    if (bytes >= 125) return `${(bytes * 8 / 1000).toFixed(1)} Kbps`;
    return `${Math.round(bytes * 8)} bps`;
  }

  function formatTime(value) {
    if (!value) return '--';
    const numeric = Number(value);
    const date = Number.isFinite(numeric) ? new Date(numeric < 100000000000 ? numeric * 1000 : numeric) : new Date(value);
    if (Number.isNaN(date.getTime())) return '--';
    return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(date);
  }

  function statusBadge(label, tone = 'neutral') {
    return ui.statusBadgeMarkup?.(label, tone, { dot: tone === 'success' }) || `<span>${escapeHtml(label)}</span>`;
  }

  function capability(name, fallback = false) {
    const caps = state.draft?.capabilities || state.data?.capabilities || {};
    if (caps[name] !== undefined) return bool(caps[name]);
    return fallback;
  }

  function canWrite() {
    const caps = state.draft?.capabilities || state.data?.capabilities || {};
    const update = ['service_update', 'config_update', 'multicast_update', 'write'].some((key) => caps[key] === true || caps[key] === 1 || caps[key] === 'true');
    const apply = ['service_apply', 'config_apply', 'multicast_apply', 'apply'].some((key) => caps[key] === true || caps[key] === 1 || caps[key] === 'true');
    return update && apply;
  }

  function tabsMarkup() {
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs multicast-tabs" role="tablist" data-dwrt-tabs-key="multicast-service" aria-label="组播服务视图"><span class="dwrt-kit-tab-pill" aria-hidden="true"></span>${TABS.map(([id, label]) => `<button class="dwrt-kit-tab ${state.tab === id ? 'is-active' : ''}" type="button" role="tab" data-multicast-tab="${id}" data-value="${id}" aria-selected="${state.tab === id ? 'true' : 'false'}">${escapeHtml(label)}</button>`).join('')}</nav>`;
  }

  function pageToolbar() {
    return `<header class="multicast-page-header">${tabsMarkup()}<button class="dwrt-kit-button multicast-refresh" type="button" data-multicast-refresh ${state.refreshing ? 'disabled' : ''}>${icon('refresh')}<span>${state.refreshing ? '正在刷新' : '刷新'}</span></button></header>`;
  }

  function noticeMarkup() {
    if (!state.error && !state.notice) return '';
    return `<div class="multicast-notice ${state.error ? 'is-error' : ''}" role="${state.error ? 'alert' : 'status'}">${escapeHtml(state.error || state.notice)}</div>`;
  }

  function overviewSummaryMarkup() {
    const data = state.draft || defaultService();
    const status = data.status;
    const configured = data.igmp_proxy.enabled || data.iptv_passthrough.enabled || data.udpxy.enabled || data.discovery.mdns_reflector || data.discovery.ssdp_relay;
    const runtimeVerified = data.runtime?.verified === true || data.runtime?.applied === true || data.runtime?.state === 'running';
    const instances = data.udpxy.instances.filter((item) => item.enabled).length;
    return `<dl class="multicast-runtime-summary" aria-label="组播服务概览"><div><dt>服务配置</dt><dd>${configured ? '已配置' : '未启用'}<small>${runtimeVerified ? '运行态已验证' : '尚无运行态验证'}</small></dd></div><div><dt>组播订阅</dt><dd>${status.groups}<small>${status.subscribers} 个订阅端</small></dd></div><div><dt>转发速率</dt><dd>${escapeHtml(formatRate(status.rx_rate + status.tx_rate))}<small>丢弃 ${status.dropped}</small></dd></div><div><dt>UDPXY</dt><dd>${instances} / ${data.udpxy.instances.length}<small>${data.udpxy.status === 'unknown' ? '运行状态未知' : `后端状态：${escapeHtml(data.udpxy.status)}`}</small></dd></div></dl>`;
  }

  function tableShell(title, detail, headings, rows, empty, className = '') {
    return `<section class="multicast-table dwrt-kit-table-wrap dwrt-kit-datatable-wrap ${className}"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(detail)}</span></div><span class="dwrt-kit-table-count">${rows.length} 条</span></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-datatable"><thead><tr>${headings.map((heading) => `<th>${escapeHtml(heading)}</th>`).join('')}</tr></thead><tbody>${state.loading ? `<tr><td class="dwrt-kit-table-empty" colspan="${headings.length}">正在读取运行状态</td></tr>` : rows.length ? rows.join('') : `<tr><td class="dwrt-kit-table-empty" colspan="${headings.length}">${escapeHtml(empty)}</td></tr>`}</tbody></table></div></section>`;
  }

  function runtimeTable() {
    const groups = state.draft?.group_state || [];
    const rows = groups.map((item) => `<tr><td><strong>${escapeHtml(item.group)}</strong></td><td>${escapeHtml(item.source)}</td><td>${escapeHtml(item.upstream)}</td><td>${escapeHtml(item.downstream)}</td><td data-type="number">${item.subscribers}</td><td data-type="number">${escapeHtml(formatRate(item.rate))}</td><td>${escapeHtml(formatTime(item.last_seen))}</td><td>${escapeHtml(item.client || '--')}</td></tr>`);
    return tableShell('运行订阅', state.lastUpdated ? `观测于 ${formatTime(state.lastUpdated)}` : '等待后端运行态', ['组地址', '源地址', '上联', '下联', '订阅', '速率', '最近观测', '客户端'], rows, state.draft?.status?.groups ? '后端只返回组数，没有返回可核验的组明细' : '当前没有可核验的组播订阅', 'multicast-runtime-table');
  }

  function capabilityPanel() {
    const runtimeVerified = state.draft?.runtime?.verified === true || state.draft?.runtime?.applied === true || state.draft?.runtime?.state === 'running';
    if (runtimeVerified && canWrite()) return '';
    if (!canWrite()) {
      return `<div class="multicast-capability" role="status">${icon('warning')}<span><strong>当前为只读</strong><small>后端未声明组播配置写入与应用能力；页面只展示真实配置和运行态，不会把已配置冒充已应用。</small></span></div>`;
    }
    return `<div class="multicast-capability" role="status">${icon('warning')}<span><strong>运行状态尚未完整验证</strong><small>当前后端可以保存配置，但 IGMP、IPTV、UDPXY 与局域发现是否真正生效，必须以后端运行态回读为准。</small></span></div>`;
  }

  function field(label, path, value, options = {}) {
    const disabled = options.disabled || !canWrite();
    const attrs = `${disabled ? 'disabled' : ''} ${options.min !== undefined ? `min="${options.min}"` : ''} ${options.max !== undefined ? `max="${options.max}"` : ''}`;
    const description = options.description ? `<span data-dwrt-field-description>${escapeHtml(options.description)}</span>` : '';
    if (options.type === 'select') {
      return `<label class="dwrt-kit-field ${options.wide ? 'is-wide' : ''}" data-dwrt-component="field"><span data-dwrt-field-label>${escapeHtml(label)}</span><select class="dwrt-kit-select" data-multicast-field="${escapeHtml(path)}" ${attrs}>${options.items.map(([key, text]) => `<option value="${escapeHtml(key)}" ${String(value) === String(key) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select>${description}</label>`;
    }
    return `<label class="dwrt-kit-field ${options.wide ? 'is-wide' : ''}" data-dwrt-component="field"><span data-dwrt-field-label>${escapeHtml(label)}</span><input type="${options.type || 'text'}" data-multicast-field="${escapeHtml(path)}" value="${escapeHtml(value ?? '')}" placeholder="${escapeHtml(options.placeholder || '')}" ${attrs}>${description}</label>`;
  }

  function interfaceOptions(kind, current = '') {
    const source = kind === 'wan' ? state.wans : kind === 'lan' ? state.lans : state.ports;
    const rows = source.slice();
    if (current && !rows.some((item) => item.id === current)) rows.unshift({ id: current, label: current, device: '' });
    return [['', '请选择'], ...rows.map((item) => [item.id, item.device && item.device !== item.id ? `${item.label || item.id} (${item.device})` : item.label || item.id])];
  }

  function multiSelectField(label, path, selected, kind, description = '') {
    const values = new Set(selected || []);
    const options = kind === 'port' ? state.ports : state.lans;
    return `<fieldset class="multicast-multiselect dwrt-kit-field" data-dwrt-component="field-group"><legend>${escapeHtml(label)}</legend><div>${options.length ? options.map((item) => `<label><input type="checkbox" data-multicast-list-field="${escapeHtml(path)}" value="${escapeHtml(item.id)}" ${values.has(item.id) ? 'checked' : ''} ${!canWrite() ? 'disabled' : ''}><span>${escapeHtml(item.label || item.id)}${item.device && item.device !== item.id ? `<small>${escapeHtml(item.device)}</small>` : ''}</span></label>`).join('') : '<span class="multicast-empty-choice">未读取到可选接口</span>'}</div>${description ? `<small>${escapeHtml(description)}</small>` : ''}</fieldset>`;
  }

  function dependencySwitch(path, title, description, checked, dependentMarkup = '', disabled = false) {
    const inactive = !checked;
    return `<section class="multicast-dependency ${inactive ? 'is-inactive' : ''}" data-dwrt-component="dependency-group"><label class="dwrt-kit-switch multicast-master-switch"><input type="checkbox" data-multicast-field="${escapeHtml(path)}" ${checked ? 'checked' : ''} ${disabled || !canWrite() ? 'disabled' : ''}><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(description)}</small></span></label>${dependentMarkup ? `<div class="multicast-dependency-fields" ${inactive ? 'aria-disabled="true"' : ''}>${dependentMarkup}</div>` : ''}</section>`;
  }

  function settingsSurface(title, detail, content) {
    return `<section class="multicast-settings-surface dwrt-kit-glass-surface" data-dwrt-surface="stable-glass"><header class="multicast-surface-header"><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(detail)}</small></span>${statusBadge(canWrite() ? '可配置' : '只读', canWrite() ? 'success' : 'warning')}</header>${capabilityPanel()}<div class="multicast-surface-body">${content}</div></section>`;
  }

  function igmpPanel() {
    const data = state.draft || defaultService();
    const igmp = data.igmp_proxy;
    const proxyFields = `<div class="multicast-field-grid">${field('IGMP 版本', 'igmp_proxy.version', igmp.version, { type: 'select', items: [['2', 'IGMPv2'], ['3', 'IGMPv3']] })}${field('上联接口', 'igmp_proxy.upstream', igmp.upstream, { type: 'select', items: interfaceOptions('wan', igmp.upstream) })}${multiSelectField('下联网络', 'igmp_proxy.downstreams', igmp.downstreams, 'lan')}${field('允许源网段', 'igmp_proxy.alt_subnets', igmp.alt_subnets.join(', '), { wide: true, placeholder: '0.0.0.0/0', description: '多个网段以逗号分隔' })}</div>${dependencySwitch('igmp_proxy.quick_leave', '快速离组', '最后一个客户端离开时立即退订上游组播。', igmp.quick_leave)}`;
    const mldFields = dependencySwitch('discovery.mld_snooping', 'MLD 侦听', '按 IPv6 订阅关系转发组播，减少局域网泛洪。', data.discovery.mld_snooping);
    return settingsSurface('IGMP / MLD 代理', '配置 IPv4 与 IPv6 组播订阅转发。', `${dependencySwitch('igmp_proxy.enabled', 'IGMP 代理', '在选定 WAN 与 LAN 之间代理运营商组播。', igmp.enabled, proxyFields)}${mldFields}`);
  }

  function iptvPanel() {
    const data = state.draft || defaultService();
    const iptv = data.iptv_passthrough;
    const fields = `<div class="multicast-field-grid">${field('IPTV 上联', 'iptv_passthrough.wan_iface', iptv.wan_iface, { type: 'select', items: interfaceOptions('wan', iptv.wan_iface) })}${field('目标 LAN', 'iptv_passthrough.lan_iface', iptv.lan_iface, { type: 'select', items: interfaceOptions('lan', iptv.lan_iface) })}${field('VLAN ID', 'iptv_passthrough.vlan_id', iptv.vlan_id, { type: 'number', min: 1, max: 4094, placeholder: '可留空' })}${field('透传模式', 'iptv_passthrough.mode', iptv.mode, { type: 'select', items: [['bridge', '桥接透传'], ['route', '路由代理'], ['hybrid', '混合模式']] })}${multiSelectField('机顶盒端口', 'iptv_passthrough.stb_ports', iptv.stb_ports, 'port', '仅选择实际连接机顶盒的物理端口。')}</div>${dependencySwitch('iptv_passthrough.keep_internet', '保留互联网访问', '机顶盒在接收 IPTV 的同时继续允许普通上网。', iptv.keep_internet)}${dependencySwitch('discovery.igmp_snooping', 'IGMP 侦听', '按订阅关系转发 IPTV 流量，避免在 LAN 内泛洪。', data.discovery.igmp_snooping)}`;
    return settingsSurface('IPTV 透传', '设置运营商上联、目标网络与机顶盒端口。', dependencySwitch('iptv_passthrough.enabled', 'IPTV 透传', '为运营商 IPTV 建立专用桥接或代理路径。', iptv.enabled, fields));
  }

  function udpxyRow(item, index) {
    return `<tr><td><label class="dwrt-kit-switch multicast-row-switch"><input type="checkbox" data-multicast-instance="${index}" data-instance-field="enabled" ${item.enabled ? 'checked' : ''} ${!canWrite() ? 'disabled' : ''}><span>${item.enabled ? '启用' : '关闭'}</span></label></td><td><input aria-label="实例名称" type="text" value="${escapeHtml(item.name)}" data-multicast-instance="${index}" data-instance-field="name" ${!canWrite() ? 'disabled' : ''}></td><td><select aria-label="信号源接口" data-multicast-instance="${index}" data-instance-field="source_iface" ${!canWrite() ? 'disabled' : ''}>${interfaceOptions('wan', item.source_iface).map(([key, text]) => `<option value="${escapeHtml(key)}" ${key === item.source_iface ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select></td><td><select aria-label="监听接口" data-multicast-instance="${index}" data-instance-field="listen_iface" ${!canWrite() ? 'disabled' : ''}>${interfaceOptions('lan', item.listen_iface).map(([key, text]) => `<option value="${escapeHtml(key)}" ${key === item.listen_iface ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select></td><td><input aria-label="监听端口" type="number" min="1" max="65535" value="${item.listen_port}" data-multicast-instance="${index}" data-instance-field="listen_port" ${!canWrite() ? 'disabled' : ''}></td><td><input aria-label="订阅周期" type="number" min="1" value="${item.subscribe_interval}" data-multicast-instance="${index}" data-instance-field="subscribe_interval" ${!canWrite() ? 'disabled' : ''}></td><td><label class="dwrt-kit-switch multicast-row-switch"><input type="checkbox" data-multicast-instance="${index}" data-instance-field="external_access" ${item.external_access ? 'checked' : ''} ${!canWrite() ? 'disabled' : ''}><span>${item.external_access ? '允许' : '拒绝'}</span></label></td><td>${statusBadge(item.status === 'running' ? '运行中' : item.status === 'stopped' ? '已停止' : '未验证', item.status === 'running' ? 'success' : item.status === 'stopped' ? 'error' : 'warning')}</td><td><button class="dwrt-kit-button dwrt-kit-icon-button" type="button" data-remove-instance="${index}" aria-label="删除 ${escapeHtml(item.name)}" ${!canWrite() ? 'disabled' : ''}>${icon('trash')}</button></td></tr>`;
  }

  function udpxyPanel() {
    const data = state.draft || defaultService();
    const udpxy = data.udpxy;
    const globalFields = `<div class="multicast-field-grid">${field('默认监听接口', 'udpxy.listen_iface', udpxy.listen_iface, { type: 'select', items: interfaceOptions('lan', udpxy.listen_iface) })}${field('默认监听端口', 'udpxy.listen_port', udpxy.listen_port, { type: 'number', min: 1, max: 65535 })}${field('默认信号源', 'udpxy.source_iface', udpxy.source_iface, { type: 'select', items: interfaceOptions('wan', udpxy.source_iface) })}${field('最大客户端', 'udpxy.max_clients', udpxy.max_clients, { type: 'number', min: 1 })}${field('缓冲区 (KB)', 'udpxy.buffer_kb', udpxy.buffer_kb, { type: 'number', min: 64 })}</div>`;
    const rows = udpxy.instances.map(udpxyRow);
    const instanceTable = `<section class="multicast-inline-table"><div class="multicast-section-heading"><span><strong>UDPXY 实例</strong><small>每个监听地址与端口组合必须唯一</small></span><button class="dwrt-kit-button" type="button" data-add-instance ${!canWrite() ? 'disabled' : ''}>${icon('plus')}<span>添加实例</span></button></div>${tableShell('实例列表', `${udpxy.instances.filter((item) => item.enabled).length} 个已启用`, ['启用', '名称', '信号源', '监听网络', '端口', '订阅周期', '外网访问', '状态', '操作'], rows, '尚未创建 UDPXY 实例', 'multicast-udpxy-table')}</section>`;
    return settingsSurface('UDPXY', '管理组播转单播服务及监听实例。', `${dependencySwitch('udpxy.enabled', 'UDPXY 服务', '将 UDP 组播流转换为 HTTP 单播，供不支持组播的播放器使用。', udpxy.enabled, `${globalFields}${instanceTable}`)}`);
  }

  function allowedRow(item, index) {
    return `<tr><td><label class="dwrt-kit-switch multicast-row-switch"><input type="checkbox" data-multicast-allow="${index}" data-allow-field="enabled" ${item.enabled ? 'checked' : ''} ${!canWrite() ? 'disabled' : ''}><span>${item.enabled ? '启用' : '关闭'}</span></label></td><td><input aria-label="组地址" type="text" value="${escapeHtml(item.group)}" placeholder="239.0.0.0/8" data-multicast-allow="${index}" data-allow-field="group" ${!canWrite() ? 'disabled' : ''}></td><td><input aria-label="源地址" type="text" value="${escapeHtml(item.source)}" placeholder="0.0.0.0/0" data-multicast-allow="${index}" data-allow-field="source" ${!canWrite() ? 'disabled' : ''}></td><td><select aria-label="下联接口" data-multicast-allow="${index}" data-allow-field="downstream" ${!canWrite() ? 'disabled' : ''}>${interfaceOptions('lan', item.downstream).map(([key, text]) => `<option value="${escapeHtml(key)}" ${key === item.downstream ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select></td><td><input aria-label="备注" type="text" value="${escapeHtml(item.remark)}" data-multicast-allow="${index}" data-allow-field="remark" ${!canWrite() ? 'disabled' : ''}></td><td><button class="dwrt-kit-button dwrt-kit-icon-button" type="button" data-remove-allow="${index}" aria-label="删除允许组 ${escapeHtml(item.group || String(index + 1))}" ${!canWrite() ? 'disabled' : ''}>${icon('trash')}</button></td></tr>`;
  }

  function discoveryPanel() {
    const data = state.draft || defaultService();
    const discovery = data.discovery;
    const allowedRows = discovery.allowed_groups.map(allowedRow);
    return settingsSurface('局域发现', '管理跨网络发现、侦听、查询器与允许组。', `${dependencySwitch('discovery.mdns_reflector', 'mDNS 反射', '让 AirPlay、HomeKit 与 Chromecast 等设备跨网络发现。', discovery.mdns_reflector)}${dependencySwitch('discovery.ssdp_relay', 'SSDP 中继', '让 DLNA 与 UPnP 设备跨网络发现。', discovery.ssdp_relay)}${dependencySwitch('discovery.igmp_snooping', 'IGMP 侦听', '按 IPv4 订阅关系转发组播，减少桥接泛洪。', discovery.igmp_snooping)}${dependencySwitch('discovery.mld_snooping', 'MLD 侦听', '按 IPv6 订阅关系转发组播。', discovery.mld_snooping)}${dependencySwitch('discovery.querier', '组播查询器', 'LAN 内没有其他查询器时，由网关维护订阅关系。', discovery.querier, `<div class="multicast-field-grid">${field('查询间隔 (秒)', 'discovery.query_interval', discovery.query_interval, { type: 'number', min: 10, max: 3600 })}</div>`)}<section class="multicast-inline-table"><div class="multicast-section-heading"><span><strong>允许组播组</strong><small>限制可通过网关转发的组播范围</small></span><button class="dwrt-kit-button" type="button" data-add-allow ${!canWrite() ? 'disabled' : ''}>${icon('plus')}<span>添加规则</span></button></div>${tableShell('允许规则', 'IPv4 组地址与源网段', ['启用', '组地址', '源地址', '下联网络', '备注', '操作'], allowedRows, '未限制允许组播组', 'multicast-allow-table')}</section>`);
  }

  function overviewPanel() {
    return settingsSurface('组播服务', '查看当前配置、订阅和转发状态。', `${overviewSummaryMarkup()}${runtimeTable()}`);
  }

  function panelMarkup() {
    if (state.loading && !state.draft) return `<section class="dwrt-kit-state-panel" data-dwrt-component="state-panel" data-dwrt-state="loading" aria-busy="true"><strong>正在读取组播服务</strong><p>页面结构已就绪，正在读取配置与运行状态。</p></section>`;
    if (!state.draft) return `<section class="dwrt-kit-state-panel" data-dwrt-component="state-panel" data-dwrt-state="error"><strong>无法显示组播服务</strong><p>${escapeHtml(state.error || '后端未返回组播服务配置。')}</p><button class="dwrt-kit-button" type="button" data-multicast-refresh>重试</button></section>`;
    if (state.tab === 'igmp') return igmpPanel();
    if (state.tab === 'iptv') return iptvPanel();
    if (state.tab === 'udpxy') return udpxyPanel();
    if (state.tab === 'discovery') return discoveryPanel();
    return overviewPanel();
  }

  function savebarMarkup() {
    if (!state.dirty) return '';
    const renderer = ui.floatingSavebarMarkup || window.DWRT_UI_KIT?.floatingSavebarMarkup;
    const markup = typeof renderer === 'function' ? renderer({
      visible: true,
      omitWhenHidden: true,
      busy: state.saving,
      disabled: !canWrite() || state.saving,
      message: canWrite() ? '组播服务有未保存的更改' : '后端未声明组播配置写入与应用能力',
      discardLabel: '放弃',
      saveLabel: canWrite() ? '保存并应用' : '等待后端能力',
      busyLabel: '正在保存'
    }) : '';
    return markup.replace('dwrt-kit-savebar', 'dwrt-kit-savebar multicast-savebar');
  }

  function syncSavebar() {
    const shell = root.querySelector('.multicast-service-shell');
    if (!shell) return;
    const current = shell.querySelector('.multicast-savebar');
    if (!state.dirty) {
      current?.remove();
      return;
    }
    if (!current) shell.insertAdjacentHTML('beforeend', savebarMarkup());
  }

  function confirmationMarkup() {
    if (!state.confirmation) return '';
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    return typeof renderer === 'function' ? renderer({
      id: 'multicast-confirm',
      action: state.confirmation.action,
      tone: 'warning',
      title: state.confirmation.title,
      description: state.confirmation.description,
      cancelLabel: '取消',
      confirmLabel: state.saving ? '正在保存' : state.confirmation.confirmLabel,
      disabled: state.saving,
      icon: icon('warning')
    }) : '';
  }

  function render() {
    if (!root || !state.mounted) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'multicast-service-route-host');
    root.innerHTML = `<section class="multicast-service-shell" data-multicast-version="${VERSION}" data-dwrt-component="page-shell" data-dwrt-page-shell="settings-workbench">${pageToolbar()}${noticeMarkup()}<main class="multicast-service-main">${panelMarkup()}</main>${savebarMarkup()}${confirmationMarkup()}</section>`;
    ui.mountAll?.(root);
    ui.scheduleAdaptiveForegroundSample?.(20, root);
  }

  function markDirty() {
    state.dirty = JSON.stringify(configPayload()) !== JSON.stringify((() => {
      const current = state.initial || defaultService();
      return { igmp_proxy: current.igmp_proxy, iptv_passthrough: current.iptv_passthrough, udpxy: current.udpxy, discovery: current.discovery };
    })());
    state.notice = '';
  }

  function setPath(path, value) {
    const parts = String(path).split('.');
    let target = state.draft;
    for (let index = 0; index < parts.length - 1; index += 1) target = target[parts[index]];
    const fieldName = parts.at(-1);
    if (['enabled', 'quick_leave', 'keep_internet', 'mdns_reflector', 'ssdp_relay', 'igmp_snooping', 'mld_snooping', 'querier'].includes(fieldName)) target[fieldName] = bool(value);
    else if (['listen_port', 'buffer_kb', 'max_clients', 'query_interval'].includes(fieldName)) target[fieldName] = number(value);
    else if (['alt_subnets'].includes(fieldName)) target[fieldName] = array(value);
    else target[fieldName] = value;
  }

  function onClick(event) {
    const tab = event.target.closest('[data-multicast-tab]');
    if (tab) {
      state.tab = tab.dataset.multicastTab;
      state.error = '';
      render();
      return;
    }
    if (event.target.closest('[data-multicast-refresh]')) { load(true); return; }
    if (event.target.closest('[data-multicast-discard], [data-dwrt-savebar-discard]')) { discard(); return; }
    if (event.target.closest('[data-multicast-save], [data-dwrt-savebar-save]')) { save(); return; }
    if (event.target.closest('[data-add-instance]')) {
      const instances = state.draft.udpxy.instances;
      instances.push({ id: `udpxy-${Date.now()}`, name: `UDPXY ${instances.length + 1}`, source_iface: state.draft.udpxy.source_iface || state.wans[0]?.id || '', listen_iface: state.draft.udpxy.listen_iface || state.lans[0]?.id || '', listen_port: number(state.draft.udpxy.listen_port, 4022) + instances.length, subscribe_interval: 30, external_access: false, enabled: true, clients: 0, status: 'unknown' });
      markDirty();
      render();
      return;
    }
    const removeInstance = event.target.closest('[data-remove-instance]');
    if (removeInstance) {
      state.draft.udpxy.instances.splice(number(removeInstance.dataset.removeInstance), 1);
      markDirty();
      render();
      return;
    }
    if (event.target.closest('[data-add-allow]')) {
      state.draft.discovery.allowed_groups.push({ id: `allow-${Date.now()}`, group: '', source: '0.0.0.0/0', downstream: state.lans[0]?.id || '', remark: '', enabled: true });
      markDirty();
      render();
      return;
    }
    const removeAllow = event.target.closest('[data-remove-allow]');
    if (removeAllow) {
      state.draft.discovery.allowed_groups.splice(number(removeAllow.dataset.removeAllow), 1);
      markDirty();
      render();
      return;
    }
    if (event.target.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]')) {
      state.confirmation = null;
      render();
      return;
    }
    if (event.target.closest('[data-dwrt-confirm-accept]') && state.confirmation?.action === 'save-external') save();
  }

  function onChange(event) {
    const fieldControl = event.target.closest('[data-multicast-field]');
    if (fieldControl) {
      setPath(fieldControl.dataset.multicastField, fieldControl.type === 'checkbox' ? fieldControl.checked : fieldControl.value);
      markDirty();
      render();
      return;
    }
    const listControl = event.target.closest('[data-multicast-list-field]');
    if (listControl) {
      const values = [...root.querySelectorAll(`[data-multicast-list-field="${CSS.escape(listControl.dataset.multicastListField)}"]:checked`)].map((control) => control.value);
      setPath(listControl.dataset.multicastListField, values);
      markDirty();
      render();
      return;
    }
    const instanceControl = event.target.closest('[data-multicast-instance]');
    if (instanceControl) {
      const item = state.draft.udpxy.instances[number(instanceControl.dataset.multicastInstance)];
      const key = instanceControl.dataset.instanceField;
      item[key] = instanceControl.type === 'checkbox' ? instanceControl.checked : ['listen_port', 'subscribe_interval'].includes(key) ? number(instanceControl.value) : instanceControl.value;
      markDirty();
      render();
      return;
    }
    const allowControl = event.target.closest('[data-multicast-allow]');
    if (allowControl) {
      state.draft.discovery.allowed_groups[number(allowControl.dataset.multicastAllow)][allowControl.dataset.allowField] = allowControl.type === 'checkbox' ? allowControl.checked : allowControl.value;
      markDirty();
      render();
    }
  }

  function onInput(event) {
    const control = event.target.closest('input[data-multicast-field], input[data-multicast-instance], input[data-multicast-allow]');
    if (!control || control.type === 'checkbox' || control.type === 'number') return;
    if (control.dataset.multicastField) setPath(control.dataset.multicastField, control.value);
    else if (control.dataset.multicastInstance !== undefined) state.draft.udpxy.instances[number(control.dataset.multicastInstance)][control.dataset.instanceField] = control.value;
    else if (control.dataset.multicastAllow !== undefined) state.draft.discovery.allowed_groups[number(control.dataset.multicastAllow)][control.dataset.allowField] = control.value;
    markDirty();
    syncSavebar();
  }

  root.addEventListener('click', onClick);
  root.addEventListener('change', onChange);
  root.addEventListener('input', onInput);
  stage?.classList.add('is-multicast-service');
  if (context.signal) context.signal.addEventListener('abort', () => { state.mounted = false; state.seq += 1; }, { once: true });
  render();
  load();

  return () => {
    state.mounted = false;
    state.seq += 1;
    root.removeEventListener('click', onClick);
    root.removeEventListener('change', onChange);
    root.removeEventListener('input', onInput);
    root.classList.remove('multicast-service-route-host');
    stage?.classList.remove('is-multicast-service');
    const savebar = root.querySelector('.multicast-savebar');
    if (savebar) savebar.remove();
  };
}
