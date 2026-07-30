export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const utils = context.utils || {};
  const ui = context.ui || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));
  const fetchApi = api.fetch || (async (name, url) => {
    const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store', headers: authHeaders() });
    const json = await response.json().catch(() => ({}));
    return { name, ok: response.ok && json?.ok !== false, data: json?.data ?? json, raw: json };
  });

  const VERSION = '20260722-overlay-01';
  const ENDPOINT = '/api/v1/policy-engine/policy-table';
  const CATALOG_ENDPOINT = '/api/v1/policy-engine/catalog';
  const ROUTING_ENDPOINT = '/api/v1/routing';
  const MODULE_CLASS = 'routing-table-route-host';
  const COLUMNS = [
    { key: 'status', label: '状态', width: 86 },
    { key: 'type', label: '类型', width: 126 },
    { key: 'name', label: '名称', width: 210 },
    { key: 'source', label: '源', width: 154 },
    { key: 'destination', label: '目标网络', width: 170 },
    { key: 'target', label: '下一跳 / 目标', width: 164 },
    { key: 'interface', label: '接口', width: 112 },
    { key: 'table', label: '路由表', width: 108 },
    { key: 'priority', label: '跃点 / 优先级', width: 126 },
    { key: 'hits', label: '命中', width: 92 },
    { key: 'lastHit', label: '最后命中', width: 136 },
    { key: 'actions', label: '操作', width: 92, fixed: true }
  ];
  const state = {
    rows: [], tables: [], interfaces: [], wans: [], capabilities: {}, source: '', loading: true, error: '', query: '', type: 'all', status: 'all',
    drawer: '', selected: null, draft: {}, saving: false, notice: '', confirmDelete: false,
    visibleColumns: new Set(COLUMNS.map((column) => column.key)), sortKey: 'type', sortDirection: 'asc', seq: 0, mounted: true
  };
  let searchTimer = 0;

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
  function normalizeKey(value) { return String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_'); }
  function asArray(value) {
    if (Array.isArray(value)) return value;
    for (const key of ['rows', 'items', 'policies', 'data']) if (Array.isArray(value?.[key])) return value[key];
    return [];
  }
  function authHeaders(extra = {}) {
    let token = '';
    try { token = localStorage.getItem('dreamingwrt.web.accessToken') || ''; } catch (_) {}
    return { Accept: 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}), ...extra };
  }
  async function requestJson(url, options = {}) {
    const response = await fetch(url, {
      credentials: 'same-origin', cache: 'no-store', ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    const payload = json?.data ?? json;
    if (!response.ok || json?.ok === false || payload?.ok === false) throw new Error(firstText(payload?.message, payload?.error, json?.message, json?.error, response.status));
    return payload;
  }
  function routeType(row = {}) {
    const key = normalizeKey(row.policy_type || row.type_key || row.kind || row.type);
    if (key === 'static_route' || key === 'route' || key === 'route6' || key.includes('static_route')) return 'static_route';
    if (key === 'pbr' || key.includes('policy_route') || key.includes('traffic_route') || key.includes('mwan')) return 'pbr';
    return '';
  }
  function rawValue(row, ...keys) {
    const raw = row?.raw && typeof row.raw === 'object' ? row.raw : {};
    const options = raw.options && typeof raw.options === 'object' ? raw.options : {};
    for (const key of keys) {
      const value = options[key] ?? raw[key] ?? row[key];
      if (value !== undefined && value !== null && String(value).trim() !== '') return value;
    }
    return '';
  }
  function ipv4Prefix(mask) {
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(String(mask || ''))) return '';
    const bits = String(mask).split('.').map(Number).map((octet) => Math.max(0, Math.min(255, octet)).toString(2).padStart(8, '0')).join('');
    if (!/^1*0*$/.test(bits)) return '';
    return String(bits.indexOf('0') < 0 ? 32 : bits.indexOf('0'));
  }
  function staticDestination(raw = {}, fallback = '') {
    const target = firstText(raw.target, raw.destination, raw.dest_addr);
    if (!target) return firstText(fallback, '任意');
    if (target.includes('/')) return target;
    const prefix = ipv4Prefix(raw.netmask);
    return prefix ? `${target}/${prefix}` : target;
  }
  function normalizeRow(row = {}, index = 0) {
    const type = routeType(row);
    if (!type) return null;
    const rawBase = row.raw && typeof row.raw === 'object' ? row.raw : row;
    const raw = { ...rawBase, ...(rawBase.options && typeof rawBase.options === 'object' ? rawBase.options : {}) };
    const destination = type === 'static_route'
      ? staticDestination(raw, firstText(row.destination_label, row.destination_name, row.destination))
      : (firstText(row.destination_label, row.destination_name, row.destination, raw.dest_object, raw.dest_ip) || '任意');
    const source = type === 'pbr'
      ? (firstText(row.source_label, row.source, raw.source_object, raw.src_ip) || '全部终端')
      : (firstText(rawBase.options?.source, raw.source_prefix) || '--');
    const target = type === 'pbr'
      ? (firstText(raw.target, raw.wan, raw.route_table, raw.table, row.interface) || '--')
      : (firstText(raw.gateway, raw.gw, raw.next_hop) || (firstText(row.interface, raw.interface) ? '直连' : '--'));
    const routeTable = firstText(raw.route_table, raw.table, raw.routing_table) || (type === 'static_route' ? 'main' : target);
    const priority = firstNumber(raw.priority, raw.metric, row.priority, row.metric, row.index);
    const hitCount = firstNumber(raw.hit_count, raw.hits, row.hit_count, row.hits);
    const lastHit = firstNumber(raw.last_hit, raw.last_hit_at, row.last_hit);
    const actionKey = normalizeKey(firstText(raw.action, row.action_key, row.action));
    const routeAction = ['main', 'drop', 'mark', 'route_group'].includes(actionKey) ? actionKey : 'route_table';
    const id = firstText(row.id, row._id, row.uuid, raw.id, raw.section) || `route-${index}`;
    return {
      id, type, typeLabel: type === 'pbr' ? '策略路由' : '静态路由',
      name: firstText(row.name, row.label, raw.name, raw.comment, destination) || `路由 ${index + 1}`,
      source, destination, target, interface: firstText(row.interface, raw.interface, raw.iface, raw.network) || '--',
      table: routeTable, priority, hits: hitCount, lastHit, enabled: row.enabled !== false && raw.enabled !== false && raw.disabled !== '1',
      routeTarget: firstText(raw.target, raw.destination, raw.dest_addr), netmask: firstText(raw.netmask),
      protocol: firstText(row.protocol, raw.proto, raw.protocol) || 'all', ports: firstText(row.destination_port, raw.ports, raw.dest_port) || 'any',
      family: firstText(raw.family, raw.ip_version) || (raw.section_type === 'route6' || /[:]/.test(destination) ? 'ipv6' : 'ipv4'),
      schedule: firstText(raw.schedule) || 'always', routeAction, comment: firstText(raw.comment, raw.remark, row.description), raw: { ...raw, ...row }
    };
  }
  function capabilityFor(type, action) {
    const prefix = type === 'pbr' ? 'pbr' : 'static_route';
    const explicit = state.capabilities[`${prefix}_${action}`];
    if (typeof explicit === 'boolean') return explicit;
    const supported = asArray(state.capabilities.write_supported_policy_types).map(normalizeKey);
    return supported.includes(type) && state.capabilities[action] !== false;
  }
  function formatNumber(value) { return new Intl.NumberFormat('zh-CN').format(Number(value) || 0); }
  function formatTime(value) {
    const raw = Number(value) || 0;
    if (!raw) return '--';
    const timestamp = raw < 100000000000 ? raw * 1000 : raw;
    return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(timestamp);
  }
  function icon(name) {
    const paths = {
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      filter: '<path d="M4 5h16l-6.2 7.1V18l-3.6 1v-6.9L4 5Z"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      columns: '<path d="M4 5h16v14H4zM10 5v14m5-14v14"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      edit: '<path d="m4 20 4.2-1 10.9-10.9a2 2 0 0 0-2.8-2.8L5.4 16.2 4 20Z"></path>',
      chevron: '<path d="m8 10 4 4 4-4"></path>'
    };
    return `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.edit}</svg>`;
  }
  function unwrapResult(result) { return result?.data ?? result?.raw?.data ?? result?.raw ?? result ?? {}; }
  async function load() {
    const seq = ++state.seq;
    state.loading = true;
    state.error = '';
    patchTable();
    const [policyResult, routingResult, catalogResult] = await Promise.allSettled([
      fetchApi('routing-policy-table', `${ENDPOINT}?include_default=0`),
      fetchApi('advanced-routing-catalog', ROUTING_ENDPOINT),
      fetchApi('policy-engine-catalog', CATALOG_ENDPOINT)
    ]);
    if (!state.mounted || seq !== state.seq) return;
    if (policyResult.status === 'fulfilled' && policyResult.value?.ok !== false) {
      const data = unwrapResult(policyResult.value);
      state.rows = asArray(data.rows || data.items || data.policies || data).map(normalizeRow).filter(Boolean);
      state.capabilities = data.capabilities || policyResult.value?.raw?.data?.capabilities || {};
      state.source = firstText(data.source, policyResult.value?.raw?.meta?.source, 'policy-engine');
    } else {
      state.rows = [];
      state.error = '路由数据读取失败；当前不展示演示数据。';
    }
    if (routingResult.status === 'fulfilled' && routingResult.value?.ok !== false) {
      const data = unwrapResult(routingResult.value);
      state.tables = asArray(data.tables).map((item) => ({ id: firstText(item.id, item.name), name: firstText(item.name, item.id), tableId: firstNumber(item.table_id), enabled: item.enabled !== false })).filter((item) => item.id);
    }
    if (catalogResult.status === 'fulfilled' && catalogResult.value?.ok !== false) {
      const data = unwrapResult(catalogResult.value);
      const normalizeOption = (item) => ({ value: firstText(item.value, item.id, item.name), label: firstText(item.label, item.name, item.value, item.id) });
      state.interfaces = asArray(data.interfaces).map(normalizeOption).filter((item) => item.value);
      state.wans = asArray(data.wans).map(normalizeOption).filter((item) => item.value);
    }
    state.loading = false;
    patchView();
  }
  function filteredRows() {
    const query = state.query.trim().toLowerCase();
    const rows = state.rows.filter((row) => {
      if (state.type !== 'all' && row.type !== state.type) return false;
      if (state.status === 'enabled' && !row.enabled) return false;
      if (state.status === 'disabled' && row.enabled) return false;
      return !query || [row.name, row.typeLabel, row.source, row.destination, row.target, row.interface, row.table, row.protocol, row.ports].join(' ').toLowerCase().includes(query);
    });
    const direction = state.sortDirection === 'desc' ? -1 : 1;
    return rows.sort((a, b) => {
      const av = a[state.sortKey];
      const bv = b[state.sortKey];
      if (typeof av === 'number' || typeof bv === 'number') return (Number(av) - Number(bv)) * direction;
      return String(av ?? '').localeCompare(String(bv ?? ''), 'zh-CN', { numeric: true }) * direction;
    });
  }
  function filterCount() { return (state.type !== 'all' ? 1 : 0) + (state.status !== 'all' ? 1 : 0); }
  function renderToolbar() {
    return `<header class="policy-toolbar routing-toolbar">
      <label class="policy-search policy-search-main" data-dwrt-component="expand-search">${icon('search')}<input type="search" data-route-search placeholder="搜索路由名称、IP、接口或路由表" value="${escapeHtml(state.query)}"></label>
      <div class="policy-toolbar-actions routing-toolbar-actions">
        <button class="policy-filter-button" type="button" data-route-filter>${icon('filter')}<span>筛选</span>${filterCount() ? `<span class="policy-count-badge">${filterCount()}</span>` : ''}</button>
        <button class="policy-filter-button routing-columns-button" type="button" data-route-columns>${icon('columns')}<span>列</span></button>
        <button class="policy-create-button" type="button" data-route-create>${icon('plus')}<span>创建路由</span></button>
      </div>
    </header>`;
  }
  function sortIndicator(key) { return state.sortKey === key ? `<span class="routing-sort is-${state.sortDirection}">${icon('chevron')}</span>` : ''; }
  function cellMarkup(row, key) {
    if (key === 'status') return ui.statusBadgeMarkup?.(row.enabled ? '启用' : '停用', row.enabled ? 'success' : 'error') || `<span>${row.enabled ? '启用' : '停用'}</span>`;
    if (key === 'type') return `<span class="routing-type is-${row.type}">${escapeHtml(row.typeLabel)}</span>`;
    if (key === 'name') return `<button class="routing-name" type="button" data-route-open="${escapeHtml(row.id)}"><strong>${escapeHtml(row.name)}</strong>${row.comment ? `<small>${escapeHtml(row.comment)}</small>` : ''}</button>`;
    if (key === 'source') return `<span class="routing-cell-ellipsis" title="${escapeHtml(row.source)}">${escapeHtml(row.source)}</span>`;
    if (key === 'destination') return `<span class="routing-cell-ellipsis" title="${escapeHtml(row.destination)}">${escapeHtml(row.destination)}</span>`;
    if (key === 'target') return `<span class="routing-cell-ellipsis" title="${escapeHtml(row.target)}">${escapeHtml(row.target)}</span>`;
    if (key === 'interface') return escapeHtml(row.interface);
    if (key === 'table') return `<span class="routing-table-pill">${escapeHtml(row.table)}</span>`;
    if (key === 'priority') return row.priority ? formatNumber(row.priority) : '--';
    if (key === 'hits') return `<span class="routing-number">${formatNumber(row.hits)}</span>`;
    if (key === 'lastHit') return `<time>${escapeHtml(formatTime(row.lastHit))}</time>`;
    if (key === 'actions') return `<button class="routing-row-action" type="button" data-route-open="${escapeHtml(row.id)}" aria-label="编辑 ${escapeHtml(row.name)}">${icon('edit')}</button>`;
    return '--';
  }
  function renderTable() {
    const rows = filteredRows();
    const columns = COLUMNS.filter((column) => column.fixed || state.visibleColumns.has(column.key));
    const subtitle = state.error || (state.source ? `真实配置 · ${rows.length} 条路由` : `${rows.length} 条路由`);
    return `<section class="routing-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface">
      <div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>路由</strong><span class="${state.error ? 'is-warning' : ''}">${escapeHtml(subtitle)}</span></div><div class="routing-table-meta"><span class="dwrt-kit-table-count">静态 ${state.rows.filter((row) => row.type === 'static_route').length} · 策略 ${state.rows.filter((row) => row.type === 'pbr').length}</span><button type="button" data-route-refresh title="刷新" aria-label="刷新路由">${icon('refresh')}</button></div></div>
      <div class="dwrt-kit-table-scroll routing-table-scroll" data-routing-scroll><table class="dwrt-kit-table dwrt-kit-ikuai-table routing-table"><thead><tr>${columns.map((column) => `<th style="width:${column.width}px;min-width:${column.width}px"><button type="button" data-route-sort="${column.key}" ${column.key === 'actions' ? 'disabled' : ''}>${escapeHtml(column.label)}${sortIndicator(column.key)}</button></th>`).join('')}</tr></thead><tbody>${state.loading ? `<tr><td colspan="${columns.length}" class="dwrt-kit-table-empty">正在读取路由</td></tr>` : rows.length ? rows.map((row) => `<tr class="${row.enabled ? '' : 'is-disabled'}" data-route-id="${escapeHtml(row.id)}">${columns.map((column) => `<td class="is-${column.key}">${cellMarkup(row, column.key)}</td>`).join('')}</tr>`).join('') : `<tr><td colspan="${columns.length}" class="dwrt-kit-table-empty">${escapeHtml(state.error || '没有匹配的路由')}</td></tr>`}</tbody></table></div>
    </section>`;
  }
  function renderFilterDrawer() {
    if (state.drawer !== 'filter') return '';
    const typeCount = (type) => state.rows.filter((row) => type === 'all' || row.type === type).length;
    const statusCount = (status) => state.rows.filter((row) => status === 'all' || row.enabled === (status === 'enabled')).length;
    const radio = (name, value, label, count, checked) => `<label class="policy-filter-row"><input type="radio" name="${name}" value="${value}" ${checked ? 'checked' : ''}><span class="policy-control-dot"></span><span class="policy-filter-label">${label}</span><span class="policy-filter-count">${count}</span></label>`;
    return `${drawerBackdrop('关闭筛选')}<aside class="routing-drawer routing-filter-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open"><header class="dwrt-kit-sheet-header"><div><span>FILTER</span><strong>筛选路由</strong></div><button class="dwrt-kit-sheet-close" type="button" data-route-close>×</button></header><div class="dwrt-kit-sheet-body routing-drawer-body">
      <section class="policy-filter-section"><button class="policy-filter-section-head" type="button"><span>路由类型</span></button><div class="policy-filter-section-body">${radio('route-type', 'all', '所有路由', typeCount('all'), state.type === 'all')}${radio('route-type', 'static_route', '静态路由', typeCount('static_route'), state.type === 'static_route')}${radio('route-type', 'pbr', '策略路由', typeCount('pbr'), state.type === 'pbr')}</div></section>
      <section class="policy-filter-section"><button class="policy-filter-section-head" type="button"><span>状态</span></button><div class="policy-filter-section-body">${radio('route-status', 'all', '所有状态', statusCount('all'), state.status === 'all')}${radio('route-status', 'enabled', '启用', statusCount('enabled'), state.status === 'enabled')}${radio('route-status', 'disabled', '停用', statusCount('disabled'), state.status === 'disabled')}</div></section>
    </div><footer class="dwrt-kit-sheet-footer"><button class="policy-text-button" type="button" data-route-clear-filter ${filterCount() ? '' : 'disabled'}>清除筛选条件</button><button class="policy-primary" type="button" data-route-close>完成</button></footer></aside>`;
  }
  function renderColumnsDrawer() {
    if (state.drawer !== 'columns') return '';
    return `${drawerBackdrop('关闭列设置')}<aside class="routing-drawer routing-columns-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open"><header class="dwrt-kit-sheet-header"><div><span>COLUMNS</span><strong>自定义列</strong></div><button class="dwrt-kit-sheet-close" type="button" data-route-close>×</button></header><div class="dwrt-kit-sheet-body routing-drawer-body"><div class="routing-column-list">${COLUMNS.filter((column) => !column.fixed).map((column) => `<label><input type="checkbox" data-route-column="${column.key}" ${state.visibleColumns.has(column.key) ? 'checked' : ''}><span></span><strong>${escapeHtml(column.label)}</strong></label>`).join('')}</div></div><footer class="dwrt-kit-sheet-footer"><button class="policy-text-button" type="button" data-route-columns-reset>恢复默认</button><button class="policy-primary" type="button" data-route-close>完成</button></footer></aside>`;
  }
  function drawerBackdrop(label) { return `<button class="policy-drawer-backdrop dwrt-kit-sheet-overlay is-open" type="button" data-route-close aria-label="${label}"></button>`; }
  function newDraft(type = 'static_route') {
    return type === 'pbr'
      ? { type, enabled: true, name: '', source: 'any', destination: 'any', protocol: 'all', ports: 'any', action: 'route_table', target: '', table: '', priority: 1000, schedule: 'always', comment: '' }
      : { type, enabled: true, name: '', family: 'ipv4', destination: '', gateway: '', interface: '', table: 'main', metric: 0, mtu: 1500, routeKind: 'unicast', source: '', comment: '' };
  }
  function draftFromRow(row) {
    if (row.type === 'pbr') return { type: row.type, enabled: row.enabled, name: row.name, source: row.source === '全部终端' ? 'any' : row.source, destination: row.destination === '任意' ? 'any' : row.destination, protocol: row.protocol, ports: row.ports, action: row.routeAction || 'route_table', target: row.target === '--' ? '' : row.target, table: row.table === '--' ? '' : row.table, priority: row.priority || 1000, schedule: row.schedule, comment: row.comment };
    return { type: row.type, enabled: row.enabled, name: row.name, family: row.family, destination: row.routeTarget || (row.destination === '任意' ? '' : row.destination), netmask: row.netmask, gateway: row.target === '直连' || row.target === '--' ? '' : row.target, interface: row.interface === '--' ? '' : row.interface, table: row.table || 'main', metric: row.priority || 0, mtu: firstNumber(rawValue(row, 'mtu')) || 1500, routeKind: firstText(rawValue(row, 'route_kind', 'route_type', 'type'), 'unicast'), source: firstText(rawValue(row, 'source', 'source_prefix')) };
  }
  function field(label, control, wide = false) { return `<label class="routing-field ${wide ? 'is-wide' : ''}"><span>${label}</span>${control}</label>`; }
  function input(name, value, placeholder = '', type = 'text') { return `<input type="${type}" data-route-draft="${name}" value="${escapeHtml(value ?? '')}" placeholder="${escapeHtml(placeholder)}">`; }
  function select(name, value, options) { return `<select data-route-draft="${name}">${options.map(([key, label]) => `<option value="${escapeHtml(key)}" ${String(value) === String(key) ? 'selected' : ''}>${escapeHtml(label)}</option>`).join('')}</select>`; }
  function tableOptions(value) {
    const values = new Map([['main', 'main']]);
    state.tables.filter((item) => item.enabled).forEach((item) => values.set(item.id, item.tableId ? `${item.name} (${item.tableId})` : item.name));
    if (value && !values.has(value)) values.set(value, value);
    return [...values.entries()];
  }
  function datalist(id, options) {
    const values = new Map();
    options.forEach((item) => values.set(item.value, item.label));
    return `<datalist id="${id}">${[...values.entries()].map(([value, label]) => `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`).join('')}</datalist>`;
  }
  function listInput(name, value, list, placeholder = '') {
    return `<input type="text" data-route-draft="${name}" value="${escapeHtml(value ?? '')}" list="${list}" placeholder="${escapeHtml(placeholder)}">`;
  }
  function renderEditorFields() {
    const draft = state.draft;
    if (draft.type === 'pbr') return `${field('名称', input('name', draft.name, '例如 办公设备走 WAN2'), true)}${field('源对象 / 网段', input('source', draft.source, 'any 或 192.168.1.0/24'))}${field('目标对象 / 网段', input('destination', draft.destination, 'any 或目标网段'))}${field('协议', select('protocol', draft.protocol, [['all','全部'],['tcp','TCP'],['udp','UDP'],['icmp','ICMP']]))}${field('目标端口', input('ports', draft.ports, 'any、443 或 80,443'))}${field('动作', select('action', draft.action, [['route_table','指定路由表'],['route_group','出口策略组'],['main','主路由表'],['drop','丢弃'],['mark','标记']]))}${field('目标出口', listInput('target', draft.target, 'routing-wan-options', 'WAN、接口或策略组'))}${field('路由表', select('table', draft.table, [['', '跟随目标'], ...tableOptions(draft.table)]))}${field('优先级', input('priority', draft.priority, '', 'number'))}${field('计划', input('schedule', draft.schedule, 'always'))}${field('备注', input('comment', draft.comment, '可选'), true)}${datalist('routing-wan-options', [...state.wans, ...state.interfaces])}`;
    return `${field('地址族', select('family', draft.family, [['ipv4','IPv4'],['ipv6','IPv6']]))}${field('目标网络', input('destination', draft.destination, draft.family === 'ipv6' ? '2001:db8::/32' : '192.0.2.0/24'))}${draft.family === 'ipv4' && draft.netmask ? field('子网掩码', input('netmask', draft.netmask, '255.255.255.0')) : ''}${field('下一跳', input('gateway', draft.gateway, '可留空使用接口直连'))}${field('接口', listInput('interface', draft.interface, 'routing-interface-options', '例如 wan'))}${field('路由表', select('table', draft.table, tableOptions(draft.table)))}${field('跃点数', input('metric', draft.metric, '', 'number'))}${field('MTU', input('mtu', draft.mtu, '', 'number'))}${field('路由类型', select('routeKind', draft.routeKind, [['unicast','单播'],['blackhole','黑洞'],['unreachable','不可达'],['prohibit','禁止']]))}${field('源地址（可选）', input('source', draft.source, '源地址或前缀'))}${datalist('routing-interface-options', state.interfaces)}`;
  }
  function renderEditorDrawer() {
    if (!['create', 'edit'].includes(state.drawer)) return '';
    const editing = state.drawer === 'edit' && state.selected;
    const type = state.draft.type || 'static_route';
    const canSave = capabilityFor(type, editing ? 'update' : 'create');
    const canDelete = editing && capabilityFor(type, 'delete');
    return `${drawerBackdrop('关闭路由编辑')}<aside class="routing-drawer routing-editor-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open"><header class="dwrt-kit-sheet-header"><div><span>${editing ? 'ROUTE DETAILS' : 'CREATE ROUTE'}</span><strong>${editing ? escapeHtml(state.selected.name) : '创建路由'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-route-close>×</button></header><div class="dwrt-kit-sheet-body routing-drawer-body">
      ${editing ? '' : `<nav class="dwrt-kit-tabs routing-editor-tabs" aria-label="路由类型"><span class="dwrt-kit-tab-pill" aria-hidden="true"></span><button class="dwrt-kit-tab ${type === 'static_route' ? 'is-active' : ''}" type="button" data-route-draft-type="static_route">静态路由</button><button class="dwrt-kit-tab ${type === 'pbr' ? 'is-active' : ''}" type="button" data-route-draft-type="pbr">策略路由</button></nav>`}
      <label class="routing-enabled-field"><span><strong>启用路由</strong><small>保存后写入真实配置</small></span><input type="checkbox" data-route-draft-check="enabled" ${state.draft.enabled ? 'checked' : ''}><i></i></label>
      <div class="routing-form">${renderEditorFields()}</div>
      ${state.notice ? `<div class="routing-notice ${/失败|错误|不支持/.test(state.notice) ? 'is-error' : ''}">${escapeHtml(state.notice)}</div>` : ''}
    </div><footer class="dwrt-kit-sheet-footer routing-editor-footer">${editing ? `<button class="policy-secondary danger" type="button" data-route-delete ${canDelete && !state.saving ? '' : 'disabled'}>${state.confirmDelete ? '再次点击删除' : '删除'}</button>` : '<span></span>'}<div><button class="policy-secondary" type="button" data-route-close>取消</button><button class="policy-primary" type="button" data-route-save ${canSave && !state.saving ? '' : 'disabled'}>${state.saving ? '正在保存' : canSave ? '保存' : '后端未开放写入'}</button></div></footer></aside>`;
  }
  function render() {
    if (!root) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'policy-table-route-host', MODULE_CLASS);
    root.innerHTML = `<section class="policy-table-shell routing-table-shell">${renderToolbar()}${renderTable()}${renderFilterDrawer()}${renderColumnsDrawer()}${renderEditorDrawer()}</section>`;
    bindEvents();
    ui.mountAll?.(root);
  }
  function patchTable() {
    const card = root?.querySelector('.routing-table-card');
    if (!card) return;
    const scroll = card.querySelector('[data-routing-scroll]');
    const top = scroll?.scrollTop || 0;
    const left = scroll?.scrollLeft || 0;
    card.outerHTML = renderTable();
    const next = root.querySelector('[data-routing-scroll]');
    if (next) { next.scrollTop = top; next.scrollLeft = left; }
    bindTableEvents();
  }
  function patchView() {
    if (!root?.querySelector('.routing-table-shell') || state.drawer) render();
    else patchTable();
  }
  function openCreate() { state.selected = null; state.draft = newDraft('static_route'); state.notice = ''; state.confirmDelete = false; state.drawer = 'create'; render(); }
  function openRow(id) { const row = state.rows.find((item) => item.id === id); if (!row) return; state.selected = row; state.draft = draftFromRow(row); state.notice = ''; state.confirmDelete = false; state.drawer = 'edit'; render(); }
  function closeDrawer() { state.drawer = ''; state.selected = null; state.notice = ''; state.confirmDelete = false; render(); }
  function payloadFromDraft() {
    const draft = state.draft;
    if (draft.type === 'pbr') return { policy_type: 'pbr', name: draft.name, enabled: Boolean(draft.enabled), source_object: draft.source || 'any', dest_object: draft.destination || 'any', protocol: draft.protocol || 'all', ports: draft.ports || 'any', action: draft.action || 'route_table', target: draft.target, route_table: draft.table, priority: Number(draft.priority) || 1000, schedule: draft.schedule || 'always', comment: draft.comment || '', apply: true, reload_route: true };
    return { policy_type: 'static_route', enabled: Boolean(draft.enabled), family: draft.family || 'ipv4', target: draft.destination, destination: draft.destination, netmask: draft.netmask || '', gateway: draft.gateway, interface: draft.interface, table: draft.table || 'main', metric: Number(draft.metric) || 0, mtu: Number(draft.mtu) || 1500, route_kind: draft.routeKind || 'unicast', source: draft.source, apply: true, reload_network: false };
  }
  async function saveRoute() {
    const payload = payloadFromDraft();
    if (state.draft.type === 'pbr' && !state.draft.name.trim()) { state.notice = '请填写策略路由名称。'; render(); return; }
    if (state.draft.type === 'static_route' && !state.draft.destination.trim()) { state.notice = '请填写目标网络。'; render(); return; }
    if (state.draft.type === 'static_route' && !state.draft.gateway.trim() && !state.draft.interface.trim()) { state.notice = '下一跳和接口至少填写一项。'; render(); return; }
    if (state.draft.type === 'pbr' && state.draft.action !== 'main' && !state.draft.target.trim() && !state.draft.table.trim()) { state.notice = '请填写策略路由的目标出口或路由表。'; render(); return; }
    state.saving = true; state.notice = ''; render();
    try {
      if (state.selected) await requestJson(`${ENDPOINT}/${encodeURIComponent(state.selected.id)}?apply=true`, { method: 'PATCH', body: JSON.stringify(payload) });
      else await requestJson(`${ENDPOINT}?apply=true`, { method: 'POST', body: JSON.stringify(payload) });
      state.saving = false; state.drawer = ''; state.selected = null; await load();
    } catch (error) { state.saving = false; state.notice = `保存失败：${firstText(error.message, 'unknown')}`; render(); }
  }
  async function deleteRoute() {
    if (!state.selected) return;
    if (!state.confirmDelete) { state.confirmDelete = true; render(); return; }
    state.saving = true; render();
    try {
      await requestJson(`${ENDPOINT}/${encodeURIComponent(state.selected.id)}?apply=true`, { method: 'DELETE', body: JSON.stringify({ policy_type: state.selected.type, apply: true, reload_route: state.selected.type === 'pbr', reload_network: false }) });
      state.saving = false; state.drawer = ''; state.selected = null; await load();
    } catch (error) { state.saving = false; state.confirmDelete = false; state.notice = `删除失败：${firstText(error.message, 'unknown')}`; render(); }
  }
  function bindTableEvents() {
    root.querySelectorAll('[data-route-open]').forEach((button) => button.addEventListener('click', () => openRow(button.dataset.routeOpen)));
    root.querySelectorAll('[data-route-sort]').forEach((button) => button.addEventListener('click', () => {
      const key = button.dataset.routeSort;
      if (!key || key === 'actions') return;
      if (state.sortKey === key) state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc';
      else { state.sortKey = key; state.sortDirection = 'asc'; }
      patchTable();
    }));
  }
  function bindEvents() {
    bindTableEvents();
    root.querySelectorAll('[data-route-refresh]').forEach((button) => button.addEventListener('click', load));
    root.querySelectorAll('[data-route-filter]').forEach((button) => button.addEventListener('click', () => { state.drawer = 'filter'; render(); }));
    root.querySelectorAll('[data-route-create]').forEach((button) => button.addEventListener('click', openCreate));
    root.querySelectorAll('[data-route-close]').forEach((button) => button.addEventListener('click', closeDrawer));
    root.querySelectorAll('[data-route-columns]').forEach((button) => button.addEventListener('click', () => { state.drawer = 'columns'; render(); }));
    root.querySelectorAll('[data-route-column]').forEach((input) => input.addEventListener('change', () => { if (input.checked) state.visibleColumns.add(input.dataset.routeColumn); else state.visibleColumns.delete(input.dataset.routeColumn); render(); }));
    root.querySelectorAll('[data-route-columns-reset]').forEach((button) => button.addEventListener('click', () => { state.visibleColumns = new Set(COLUMNS.map((column) => column.key)); render(); }));
    root.querySelectorAll('input[name="route-type"]').forEach((input) => input.addEventListener('change', () => { state.type = input.value; render(); }));
    root.querySelectorAll('input[name="route-status"]').forEach((input) => input.addEventListener('change', () => { state.status = input.value; render(); }));
    root.querySelectorAll('[data-route-clear-filter]').forEach((button) => button.addEventListener('click', () => { state.type = 'all'; state.status = 'all'; render(); }));
    root.querySelectorAll('[data-route-draft-type]').forEach((button) => button.addEventListener('click', () => { state.draft = newDraft(button.dataset.routeDraftType); render(); }));
    root.querySelectorAll('[data-route-draft]').forEach((input) => input.addEventListener('input', () => { state.draft[input.dataset.routeDraft] = input.type === 'number' ? Number(input.value) : input.value; state.notice = ''; }));
    root.querySelectorAll('[data-route-draft-check]').forEach((input) => input.addEventListener('change', () => { state.draft[input.dataset.routeDraftCheck] = input.checked; }));
    root.querySelectorAll('[data-route-save]').forEach((button) => button.addEventListener('click', saveRoute));
    root.querySelectorAll('[data-route-delete]').forEach((button) => button.addEventListener('click', deleteRoute));
    root.querySelectorAll('[data-route-search]').forEach((input) => input.addEventListener('input', () => {
      window.clearTimeout(searchTimer);
      const value = input.value;
      searchTimer = window.setTimeout(() => { state.query = value; patchTable(); }, 100);
    }));
  }

  render();
  load();
  return { unmount() { state.mounted = false; state.seq += 1; window.clearTimeout(searchTimer); root?.replaceChildren(); root?.classList.remove(MODULE_CLASS, 'policy-table-route-host', 'route-workspace'); } };
}
