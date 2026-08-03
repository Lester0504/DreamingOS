export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const utils = context.utils || {};
  const ui = context.ui || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));
  const fetchApi = api.fetch || (async (name, url) => {
    const response = await sessionFetch(url, { credentials: 'same-origin', cache: 'no-store' });
    const json = await response.json().catch(() => ({}));
    return { name, ok: response.ok && json?.ok !== false, data: json?.data ?? json, raw: json };
  });

  const VERSION = '20260715-06';
  const ENDPOINT = '/api/v1/policy-engine/policy-table';
  const CATALOG_ENDPOINT = '/api/v1/policy-engine/catalog';
  const MODULE_CLASS = 'policy-table-route-host';
  const DEFAULT_COLUMNS = [
    { key: 'expand', label: '', fixed: true },
    { key: 'name', label: '名称', min: 240 },
    { key: 'type', label: '策略类型', min: 132 },
    { key: 'action', label: '操作', min: 100 },
    { key: 'protocol', label: '协议', min: 112 },
    { key: 'source_zone', label: '源区域', min: 116 },
    { key: 'source', label: '源', min: 156 },
    { key: 'destination_zone', label: '目标区域', min: 116 },
    { key: 'destination', label: '目标', min: 156 },
    { key: 'destination_port', label: '目标端口', min: 112 },
    { key: 'interface', label: '接口', min: 120 }
  ];
  const FALLBACK_FILTERS = {
    policy_type: [
      { value: 'all', label: '所有策略', count: 0 },
      { value: 'acl', label: 'ACL 规则', count: 0, disabled: true },
      { value: 'dns', label: 'DNS 记录', count: 0, disabled: true },
      { value: 'firewall', label: '防火墙', count: 0 },
      { value: 'nat', label: 'NAT 规则', count: 0 },
      { value: 'pbr', label: '基于策略的路由', count: 0, disabled: true },
      { value: 'port_forwarding', label: '端口转发', count: 0, disabled: true },
      { value: 'qos', label: 'QoS 规则', count: 0, disabled: true },
      { value: 'static_route', label: '静态路由', count: 0, disabled: true }
    ],
    action: [
      { value: 'convert', label: '转换', count: 0 },
      { value: 'allow', label: '允许', count: 0 },
      { value: 'block', label: '阻止', count: 0 },
      { value: 'reject', label: '拒绝', count: 0 }
    ],
    protocol: [],
    source: [],
    destination: [],
    interface: []
  };
  const EMPTY_CATALOG = {
    policy_types: [], actions: [], protocols: [], ip_versions: [], connection_states: [],
    source_zones: [], destination_zones: [], networks: [], interfaces: [], wans: [],
    devices: [], objects: [], applications: [], regions: [], schedules: []
  };
  const state = {
    rows: [],
    filters: structuredCloneSafe(FALLBACK_FILTERS),
    source: '',
    capabilities: {},
    catalog: structuredCloneSafe(EMPTY_CATALOG),
    catalogError: '',
    error: '',
    loading: true,
    drawerOpen: false,
    columnsOpen: false,
    createOpen: false,
    detailsOpen: false,
    selectedRow: null,
    draft: {},
    saving: false,
    notice: '',
    pickerOpen: '',
    bulkInputs: new Set(),
    confirmDelete: false,
    query: '',
    showDefault: true,
    type: 'all',
    selectedFilters: { action: new Set(), protocol: new Set(), source: new Set(), destination: new Set(), interface: new Set() },
    collapsed: new Set(),
    expandedRows: new Set(),
    visibleColumns: new Set(DEFAULT_COLUMNS.map((column) => column.key)),
    seq: 0,
    abort: null
  };

  let mounted = true;
  let searchTimer = 0;

  function structuredCloneSafe(value) {
    try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value)); }
  }
  function asArray(value) {
    if (Array.isArray(value)) return value;
    if (Array.isArray(value?.items)) return value.items;
    if (Array.isArray(value?.rows)) return value.rows;
    if (Array.isArray(value?.policies)) return value.policies;
    if (Array.isArray(value?.data)) return value.data;
    return [];
  }
  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (Array.isArray(value)) {
        const nested = value.map((item) => firstText(item)).filter(Boolean);
        if (nested.length) return nested.join(' ');
        continue;
      }
      if (typeof value === 'object') {
        const nested = firstText(value.label, value.name, value.display_name, value.value, value.id, value.key);
        if (nested) return nested;
        continue;
      }
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }
  function normalizeKey(value) {
    return String(value || '').trim().toLowerCase().replace(/[\s_-]+/g, '_');
  }
  function actionLabel(value) {
    const key = normalizeKey(value);
    if (['allow', 'accept', 'permit'].includes(key)) return '允许';
    if (['block', 'drop', 'deny'].includes(key)) return '阻止';
    if (['reject'].includes(key)) return '拒绝';
    if (['convert', 'translate', 'nat', 'masquerade'].includes(key)) return '转换';
    return firstText(value) || '--';
  }
  function actionKey(value) {
    const key = normalizeKey(value);
    if (['allow', 'accept', 'permit'].includes(key)) return 'allow';
    if (['block', 'drop', 'deny'].includes(key)) return 'block';
    if (['reject'].includes(key)) return 'reject';
    if (['convert', 'translate', 'nat', 'masquerade'].includes(key)) return 'convert';
    return key || 'unknown';
  }
  function routeFamilyKey(value) {
    const key = normalizeKey(value);
    if (!key) return '';
    if (key === 'static_route' || key === 'static_routes' || key === 'route' || key === 'route6' || key === 'staticroute' || key.includes('static_route') || key.includes('static-route')) return 'static_route';
    if (key === 'pbr' || key.includes('policy_based_route') || key.includes('policy_route') || key.includes('mwan')) return 'pbr';
    return '';
  }
  function typeLabel(value, row = {}) {
    const key = normalizeKey(value || row.policy_type || row.type_key || row.kind);
    const routeKey = routeFamilyKey(key);
    if (routeKey === 'static_route') return '静态路由';
    if (routeKey === 'pbr') return '基于策略的路由';
    if (key.includes('firewall')) return '防火墙';
    if (key.includes('nat')) return firstText(row.nat_type_label, row.nat_type) || '伪装 NAT';
    if (key.includes('acl')) return 'ACL 规则';
    if (key.includes('dns')) return 'DNS 记录';
    if (key.includes('qos')) return 'QoS 规则';
    if (key.includes('port')) return '端口转发';
    if (key.includes('route')) return '基于策略的路由';
    return firstText(value, row.type, row.policy_type) || '--';
  }
  function policyTypeKey(row = {}) {
    const key = normalizeKey(row.policy_type || row.type_key || row.kind || row.type);
    const routeKey = routeFamilyKey(key);
    if (routeKey) return routeKey;
    if (key.includes('firewall') || row.type === '防火墙') return 'firewall';
    if (key.includes('nat') || String(row.type || '').includes('NAT')) return 'nat';
    if (key.includes('acl')) return 'acl';
    if (key.includes('dns')) return 'dns';
    if (key.includes('qos')) return 'qos';
    if (key.includes('port')) return 'port_forwarding';
    if (key.includes('route')) return 'pbr';
    return key || 'unknown';
  }
  function valueList(value) {
    if (Array.isArray(value)) return value.map((item) => firstText(item)).filter(Boolean);
    const text = firstText(value);
    return text ? [text] : [];
  }
  function cellText(value, fallback = '--') {
    const list = valueList(value);
    if (!list.length) return fallback;
    return list.join(' ');
  }
  function compactValue(value) {
    const list = valueList(value);
    if (!list.length) return '<span class="policy-muted">--</span>';
    if (list.length > 1) return `<span class="policy-pill">多个</span>`;
    const text = list[0];
    if (text.length > 22) return `<span class="policy-pill" title="${escapeHtml(text)}">${escapeHtml(text.slice(0, 18))}…</span>`;
    if (/^(Default|Gateway|Internet|fe80|224\.|ff02|多个)$/i.test(text) || text.includes('::')) return `<span class="policy-pill">${escapeHtml(text)}</span>`;
    return escapeHtml(text);
  }
  function normalizeRow(row = {}, index = 0, fallbackType = '') {
    const source = row.source || {};
    const destination = row.destination || row.target || {};
    const normalized = {
      id: firstText(row.id, row._id, row.uuid, row.origin_id, row.name) || `policy-${index}`,
      name: firstText(row.name, row.label, row.description, row.rule_name) || `策略 ${index + 1}`,
      type: typeLabel(row.policy_type || row.type || fallbackType, row),
      policy_type: policyTypeKey({ ...row, policy_type: row.policy_type || fallbackType }),
      action: actionLabel(row.action || row.operation || row.rule_action),
      action_key: actionKey(row.action || row.operation || row.rule_action),
      protocol: firstText(row.protocol_label, row.protocol, row.ip_protocol, row.proto) || '全部',
      source_zone: firstText(row.source_zone, row.source_zone_name, source.zone, source.zone_name, row.source?.zone_id) || '-',
      source: firstText(row.source_label, row.source_name, row.source, source.matching_target, source.address, source.network, source.name) || '任何',
      destination_zone: firstText(row.destination_zone, row.destination_zone_name, destination.zone, destination.zone_name, destination.zone_id) || '-',
      destination: firstText(row.destination_label, row.destination_name, row.destination, destination.matching_target, destination.address, destination.network, destination.name) || '任何',
      destination_port: firstText(row.destination_port, row.dst_port, row.port, row.ports, destination.port, destination.ports) || '任何',
      interface: firstText(row.interface, row.interface_name, row.wan, row.wan_name, row.network, row.network_name) || '-',
      enabled: row.enabled !== false,
      predefined: row.predefined === true || row.default === true || row.is_default === true,
      children: asArray(row.children).map((child, childIndex) => normalizeRow(child, childIndex, fallbackType)),
      raw: row
    };
    if (normalized.policy_type === 'nat' && normalized.action_key === 'unknown') {
      normalized.action = '转换';
      normalized.action_key = 'convert';
    }
    return normalized;
  }
  function countBy(rows, field) {
    const map = new Map();
    rows.forEach((row) => {
      const value = row[field];
      const list = Array.isArray(value) ? value : [value];
      list.map((item) => firstText(item)).filter(Boolean).forEach((text) => map.set(text, (map.get(text) || 0) + 1));
    });
    return [...map.entries()].sort((a, b) => b[1] - a[1]).map(([label, count]) => ({ value: normalizeKey(label), label, count }));
  }
  function buildFilters(rows, serverFilters = {}) {
    const clone = structuredCloneSafe(FALLBACK_FILTERS);
    const typeCounts = new Map();
    const actionCounts = new Map();
    rows.forEach((row) => {
      typeCounts.set(row.policy_type, (typeCounts.get(row.policy_type) || 0) + 1);
      actionCounts.set(row.action_key, (actionCounts.get(row.action_key) || 0) + 1);
    });
    clone.policy_type = clone.policy_type.map((item) => ({ ...item, count: item.value === 'all' ? rows.length : (typeCounts.get(item.value) || 0), disabled: item.value !== 'all' && (typeCounts.get(item.value) || 0) === 0 }));
    clone.action = clone.action.map((item) => ({ ...item, count: actionCounts.get(item.value) || 0, disabled: (actionCounts.get(item.value) || 0) === 0 }));
    clone.protocol = countBy(rows, 'protocol');
    clone.source = countBy(rows, 'source');
    clone.destination = countBy(rows, 'destination');
    clone.interface = countBy(rows, 'interface');
    Object.entries(serverFilters || {}).forEach(([key, value]) => {
      if (!Array.isArray(value) || !value.length) return;
      if (key === 'policy_type') {
        const counts = new Map();
        value.forEach((item) => {
          const raw = normalizeKey(item && (item.value || item.key || item.id || item.label));
          const routeKey = routeFamilyKey(raw);
          const mapped = routeKey || (raw.includes('port') ? 'port_forwarding' : raw.includes('route') ? 'pbr' : raw);
          counts.set(mapped, Math.max(counts.get(mapped) || 0, Number(item && item.count) || 0));
        });
        clone.policy_type = clone.policy_type.map((item) => ({ ...item, count: item.value === 'all' ? rows.length : (counts.get(item.value) || typeCounts.get(item.value) || 0), disabled: item.value !== 'all' && (counts.get(item.value) || typeCounts.get(item.value) || 0) === 0 }));
        return;
      }
      clone[key] = value;
    });
    return clone;
  }
  function unwrapData(result) {
    const data = result?.data || {};
    return data.data && typeof data.data === 'object' ? data.data : data;
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
    const response = await sessionFetch(url, {
      credentials: 'same-origin', cache: 'no-store', ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    const payload = json?.data ?? json;
    if (!response.ok || json?.ok === false || payload?.ok === false) {
      const message = firstText(payload?.message, payload?.error?.message, payload?.error, json?.message, json?.error?.message, json?.error, `HTTP ${response.status}`);
      throw new Error(message);
    }
    return payload;
  }
  function optionList(value) {
    return asArray(value).map((item) => ({
      value: firstText(item?.value, item?.id, item?.name, item),
      label: firstText(item?.label, item?.name, item?.value, item?.id, item),
      raw: item && typeof item === 'object' ? item : { value: item }
    })).filter((item) => item.value);
  }
  function normalizeCatalog(data = {}) {
    const catalog = structuredCloneSafe(EMPTY_CATALOG);
    Object.keys(catalog).forEach((key) => { catalog[key] = optionList(data[key]); });
    return catalog;
  }
  async function load() {
    const seq = ++state.seq;
    state.loading = true;
    state.error = '';
    patchPolicyView();
    try {
      const [policyResult, catalogResult] = await Promise.allSettled([
        fetchApi('policy-table', `${ENDPOINT}?include_default=${state.showDefault ? 1 : 0}`),
        fetchApi('policy-catalog', CATALOG_ENDPOINT)
      ]);
      if (!mounted || seq !== state.seq) return;
      if (policyResult.status !== 'fulfilled' || !policyResult.value?.ok) throw policyResult.reason || policyResult.value?.error || new Error('policy table unavailable');
      const result = policyResult.value;
      if (!result?.ok) throw result?.error || new Error('policy table unavailable');
      const data = unwrapData(result);
      const rawRows = asArray(data.rows || data.items || data.policies || data);
      const rows = rawRows.map((row, index) => normalizeRow(row, index));
      state.rows = rows;
      state.filters = buildFilters(rows, data.filters || data.facets);
      state.source = firstText(data.source, result.raw?.meta?.source) || 'policy-engine';
      state.capabilities = data.capabilities || {};
      if (catalogResult.status === 'fulfilled' && catalogResult.value?.ok) {
        const catalogData = unwrapData(catalogResult.value);
        state.catalog = normalizeCatalog(catalogData);
        state.catalogError = '';
        if (!Object.keys(state.capabilities).length && catalogData.capabilities) state.capabilities = catalogData.capabilities;
      } else {
        state.catalog = structuredCloneSafe(EMPTY_CATALOG);
        state.catalogError = '创建目录读取失败';
      }
      state.loading = false;
    } catch (error) {
      if (!mounted || seq !== state.seq) return;
      state.rows = [];
      state.filters = buildFilters([]);
      state.source = 'backend-gap';
      state.capabilities = {};
      state.error = '后端策略表聚合接口未就绪，当前不展示假数据；后端缺口已落 MD。';
      state.loading = false;
    }
    patchPolicyView();
  }
  function rowMatches(row) {
    if (!state.showDefault && row.predefined) return false;
    if (state.type !== 'all' && row.policy_type !== state.type) return false;
    const query = state.query.trim().toLowerCase();
    if (query) {
      const haystack = [row.name, row.type, row.action, row.protocol, row.source_zone, cellText(row.source), row.destination_zone, cellText(row.destination), row.destination_port, row.interface].join(' ').toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    for (const key of ['action', 'protocol', 'source', 'destination', 'interface']) {
      const selected = state.selectedFilters[key];
      if (!selected || !selected.size) continue;
      const value = key === 'action' ? row.action_key : normalizeKey(cellText(row[key], ''));
      if (!selected.has(value)) return false;
    }
    return true;
  }
  function visibleRows() {
    return state.rows.filter(rowMatches);
  }
  function toggleSet(set, value) {
    if (set.has(value)) set.delete(value);
    else set.add(value);
  }
  function columnVisible(key) {
    return key === 'expand' || state.visibleColumns.has(key);
  }
  function renderStatus() {
    if (state.loading) return '正在读取策略表…';
    if (state.error) return state.error;
    return '';
  }
  function filterCount() {
    let count = 0;
    if (state.query.trim()) count += 1;
    if (!state.showDefault) count += 1;
    if (state.type !== 'all') count += 1;
    Object.values(state.selectedFilters).forEach((set) => { count += set.size; });
    return count;
  }
  function filterButtonCount() {
    const count = filterCount();
    return count ? `<span class="policy-count-badge">${count}</span>` : '';
  }
  function renderSearchIcon() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path></svg>';
  }
  function renderFilterIcon() {
    return '<svg viewBox="0 0 20 20" fill="currentColor"><path d="M3 4.5A.5.5 0 0 1 3.5 4h13a.5.5 0 0 1 .39.812L12 10.925V15a.5.5 0 0 1-.276.447l-3 1.5A.5.5 0 0 1 8 16.5v-5.575L3.11 4.812A.5.5 0 0 1 3 4.5Z"></path></svg>';
  }
  function renderPlusIcon() {
    return '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10 4v12M4 10h12"></path></svg>';
  }
  function renderFilterSection(title, key, items, type = 'checkbox') {
    const collapsed = state.collapsed.has(key);
    const controls = (items || []).map((item) => {
      const value = normalizeKey(item.value || item.label);
      const disabled = item.disabled ? ' disabled' : '';
      const checked = type === 'radio' ? (state.type === value ? ' checked' : '') : (state.selectedFilters[key]?.has(value) ? ' checked' : '');
      return `<label class="policy-filter-row${item.disabled ? ' is-disabled' : ''}">
        <input type="${type}" name="policy-${key}" data-filter-key="${escapeHtml(key)}" value="${escapeHtml(value)}"${checked}${disabled}>
        <span class="policy-control-dot"></span>
        <span class="policy-filter-label">${escapeHtml(item.label || item.value)}</span>
        <span class="policy-filter-count">${Number.isFinite(Number(item.count)) ? Number(item.count) : ''}</span>
      </label>`;
    }).join('') || '<div class="policy-empty-inline">暂无可用筛选项</div>';
    return `<section class="policy-filter-section${collapsed ? ' is-collapsed' : ''}" data-filter-section="${escapeHtml(key)}">
      <button class="policy-filter-section-head" type="button" data-toggle-section="${escapeHtml(key)}">
        <span>${escapeHtml(title)}</span>
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7"><path d="m5 8 5 5 5-5"></path></svg>
      </button>
      <div class="policy-filter-section-body">${controls}</div>
    </section>`;
  }
  function renderDrawer() {
    return `<aside class="policy-filter-drawer dwrt-kit-sheet dwrt-glass-card policy-stable-glass${state.drawerOpen ? ' is-open' : ''}" aria-hidden="${state.drawerOpen ? 'false' : 'true'}">
      <div class="policy-drawer-head dwrt-kit-sheet-header">
        <div><span>Filter</span><strong>筛选策略表</strong></div>
        <button class="policy-icon-button dwrt-kit-sheet-close" type="button" data-close-filter aria-label="关闭筛选">×</button>
      </div>
      <div class="policy-drawer-body dwrt-kit-sheet-body">
        <label class="policy-search policy-search-drawer">
          ${renderSearchIcon()}
          <input data-policy-search-drawer type="search" placeholder="搜索策略表" value="${escapeHtml(state.query)}">
        </label>
        <label class="policy-default-toggle">
          <input type="checkbox" data-show-default ${state.showDefault ? 'checked' : ''}>
          <span class="policy-control-box"></span>
          <span>查看默认策略 (${state.rows.filter((row) => row.predefined).length})</span>
        </label>
        ${renderFilterSection('策略类型', 'policy_type', state.filters.policy_type, 'radio')}
        ${renderFilterSection('操作', 'action', state.filters.action)}
        ${renderFilterSection('协议', 'protocol', state.filters.protocol)}
        ${renderFilterSection('源', 'source', state.filters.source)}
        ${renderFilterSection('目标', 'destination', state.filters.destination)}
        ${renderFilterSection('接口', 'interface', state.filters.interface)}
      </div>
      <footer class="policy-drawer-foot dwrt-kit-sheet-footer">
        <button type="button" class="policy-text-button" data-clear-filters ${filterCount() ? '' : 'disabled'}>清除筛选条件</button>
        <button type="button" class="policy-text-button" data-open-columns>自定义列</button>
      </footer>
    </aside>`;
  }
  function renderColumnsPanel() {
    if (!state.columnsOpen) return '';
    return `<div class="policy-popover policy-columns-popover dwrt-glass-card policy-stable-glass" data-columns-panel>
      <div class="policy-popover-head"><strong>自定义列</strong><button type="button" data-close-columns>×</button></div>
      <div class="policy-column-list">
        ${DEFAULT_COLUMNS.filter((column) => column.key !== 'expand').map((column) => `<label class="policy-filter-row"><input type="checkbox" data-column-toggle value="${escapeHtml(column.key)}" ${state.visibleColumns.has(column.key) ? 'checked' : ''}><span class="policy-control-box"></span><span>${escapeHtml(column.label)}</span></label>`).join('')}
      </div>
    </div>`;
  }
  function rawOptions(row = {}) {
    const envelope = row.raw && typeof row.raw === 'object' ? row.raw : {};
    const raw = envelope.raw && typeof envelope.raw === 'object' ? envelope.raw : envelope;
    const source = raw.raw && typeof raw.raw === 'object' ? raw.raw : raw;
    const options = source.options && typeof source.options === 'object' ? source.options : {};
    return { ...envelope, ...raw, ...source, ...options };
  }
  function rawValue(row, ...keys) {
    const raw = rawOptions(row);
    for (const key of keys) {
      const value = raw[key] ?? row?.[key];
      if (value !== undefined && value !== null && String(value).trim() !== '') return Array.isArray(value) ? value.join(' ') : value;
    }
    return '';
  }
  function writeTypes() {
    return new Set(asArray(state.capabilities.write_supported_policy_types).map(normalizeKey));
  }
  function capabilityFor(type, action) {
    const key = normalizeKey(type);
    const prefixes = { firewall: 'firewall_rule', port_forwarding: 'port_forwarding', dns: 'dns_record', nat: 'nat', static_route: 'static_route', qos: 'qos_sqm', pbr: 'pbr' };
    const explicit = state.capabilities[`${prefixes[key] || key}_${action}`];
    if (typeof explicit === 'boolean') return explicit;
    return writeTypes().has(key) && state.capabilities[action] !== false;
  }
  const CREATE_TYPES = [
    { value: 'firewall', label: '防火墙' },
    { value: 'route', label: '路由' },
    { value: 'qos', label: 'QoS' },
    { value: 'nat', label: 'NAT' },
    { value: 'dns', label: 'DNS' },
    { value: 'acl', label: 'ACL' },
    { value: 'port_forwarding', label: '端口转发' }
  ];
  const SERVICE_PORTS = [
    ['', '自定义'], ['179', 'BGP · 179'], ['68', 'DHCP Client · 68'], ['67', 'DHCP Server · 67'],
    ['53', 'DNS · 53'], ['853', 'DNS-TLS · 853'], ['21', 'FTP · 21'], ['80', 'HTTP · 80'],
    ['443', 'HTTPS · 443'], ['500', 'IKE · 500'], ['123', 'NTP · 123'], ['1194', 'OpenVPN · 1194'],
    ['3389', 'RDP · 3389'], ['554', 'RTSP · 554'], ['5060', 'SIP · 5060'], ['445', 'SMB · 445'],
    ['25', 'SMTP · 25'], ['161', 'SNMP · 161'], ['22', 'SSH · 22'], ['514', 'Syslog · 514'],
    ['23', 'Telnet · 23'], ['51820', 'WireGuard · 51820']
  ];
  const CUSTOM_PROTOCOLS = [['ah','AH'],['dccp','DCCP'],['esp','ESP'],['gre','GRE'],['icmp','ICMP'],['icmpv6','ICMPv6'],['igmp','IGMP'],['ipip','IPIP'],['ipv6','IPv6'],['l2tp','L2TP'],['ospf','OSPF'],['pim','PIM'],['sctp','SCTP'],['vrrp','VRRP']];
  function firstCatalogValue(key, fallback = '') {
    return state.catalog[key]?.[0]?.value || fallback;
  }
  function ipv4WanOptions() {
    return (state.catalog.wans || []).filter((item) => !/(^|[^a-z])dhcpv6([^a-z]|$)|\bwan6\b/i.test(`${item.value} ${item.label}`));
  }
  function editorType(type = state.draft.policy_type) {
    return ['pbr', 'static_route'].includes(type) ? 'route' : type;
  }
  function typeCanCreate(type) {
    if (type === 'route') return capabilityFor('pbr', 'create') || capabilityFor('static_route', 'create');
    return type !== 'acl' && capabilityFor(type, 'create');
  }
  function newDraft(type = 'firewall') {
    const firstWan = ipv4WanOptions()[0]?.value || state.catalog.wans[0]?.value || 'wan';
    const firstInterface = state.catalog.interfaces.find((item) => !['loopback', 'lan'].includes(item.value))?.value || firstWan;
    const common = { policy_type: type, name: '', enabled: true };
    if (type === 'firewall') return { ...common, action: 'block', protocol: 'all', custom_protocol: 'esp', source_zone: 'lan', destination_zone: 'wan', source_type: 'any', destination_type: 'any', source_match: 'specific', destination_match: 'specific', source_ip: '', destination_ip: '', source_port_mode: 'any', destination_port_mode: 'any', source_port: '', destination_port: '', source_port_service: '', destination_port_service: '', source_devices: [], source_networks: [], source_identities: [], destination_app_mode: 'specific', destination_applications: [], destination_regions: [], source_match_opposite: false, destination_match_opposite: false, source_match_mac: false, source_port_opposite: false, destination_port_opposite: false, family: '', connection_state: 'all', connection_states: [], match_ipsec: false, ipsec_mode: 'encrypted', syslog: false, schedule_mode: 'always', schedule_start: '09:00', schedule_end: '12:00', schedule_date: '', schedule_date_end: '', schedule_weekdays: [], schedule_all_day: false, description: '' };
    if (type === 'port_forwarding') return { ...common, protocol: 'tcp_udp', source_zone: firstWan, destination_zone: 'lan', external_port: '', internal_ip: '', internal_devices: [], internal_port: '', source_mode: 'any', source_ip: '', family: 'ipv4', syslog: false };
    if (type === 'dns') return { ...common, record_type: 'a', domain: '', ip: '', target: '', ttl_mode: 'auto', ttl: 300, mail_server: '', priority: 0, text: '', server: '', service: '', dns_protocol: '', port: '', weight: 0, dns_server: '' };
    if (type === 'nat') return { ...common, target: 'masquerade', interface: firstWan, protocol: 'all', custom_protocol: 'esp', source_type: 'any', destination_type: 'any', source_ip: '', destination_ip: '', source_port_mode: 'any', destination_port_mode: 'any', source_port: '', destination_port: '', translated_ip_mode: 'primary', translated_ip: '', translate_port: false, translated_port: '', family: 'ipv4', syslog: false, exclude: false };
    if (type === 'static_route') return { ...common, route_mode: 'static', family: 'ipv4', destination: '', gateway_mode: 'next_hop', gateway: '', interface: firstInterface, table: 'main', metric: 0, mtu: 1500, route_kind: 'unicast', source: '' };
    if (type === 'qos') return { ...common, qos_behavior: 'limit', interface: firstInterface, download_enabled: false, upload_enabled: false, download: 10, upload: 10, download_unit: 'mbps', upload_unit: 'mbps', download_burst: 'off', upload_burst: 'off', source_type: 'any', source_devices: [], source_networks: [], destination_type: 'any', destination_ip: '', destination_domain: '', destination_applications: [], destination_regions: [], destination_port_mode: 'any', destination_port: '', schedule_mode: 'always', qdisc: 'cake', script: 'piece_of_cake.qos', linklayer: 'none', overhead: '' };
    if (type === 'pbr') return { ...common, route_mode: 'policy', interface: firstWan, kill_switch: true, source_type: 'any', source_items: [], destination_type: 'any', destination: 'any', destination_regions: [], protocol: 'all', ports: 'any', action: 'route_table', target: firstWan, route_table: firstWan, priority: 1000, schedule_mode: 'always', comment: '' };
    if (type === 'acl') return { ...common, enabled: false };
    return common;
  }
  function draftFromRow(row) {
    const type = row.policy_type;
    const draft = newDraft(type);
    draft.name = row.name;
    draft.enabled = row.enabled;
    if (type === 'firewall') {
      const sourceIp = rawValue(row, 'src_ip');
      const destinationIp = rawValue(row, 'dest_ip');
      const sourcePort = rawValue(row, 'src_port');
      const destinationPort = rawValue(row, 'dest_port');
      return { ...draft, action: row.action_key, protocol: rawValue(row, 'proto', 'protocol') || 'all', source_zone: rawValue(row, 'src', 'source_zone') || 'lan', destination_zone: rawValue(row, 'dest', 'destination_zone') || 'wan', source_type: sourceIp ? 'ip' : 'any', destination_type: destinationIp ? 'ip' : 'any', source_ip: sourceIp, destination_ip: destinationIp, source_port_mode: sourcePort ? 'specific' : 'any', destination_port_mode: destinationPort ? 'specific' : 'any', source_port: sourcePort, destination_port: destinationPort, family: rawValue(row, 'family') };
    }
    if (type === 'port_forwarding') { const sourceIp=rawValue(row,'src_ip'); return { ...draft, protocol: rawValue(row, 'proto') || 'tcp_udp', source_zone: rawValue(row, 'src') || 'wan', destination_zone: rawValue(row, 'dest') || 'lan', external_port: rawValue(row, 'src_dport'), internal_ip: rawValue(row, 'dest_ip'), internal_port: rawValue(row, 'dest_port'), source_mode: sourceIp ? 'restricted' : 'any', source_ip: sourceIp, family: rawValue(row, 'family') || 'ipv4' }; }
    if (type === 'dns') {
      const sectionType = rawValue(row, 'section_type') || 'domain';
      const ip = rawValue(row, 'ip');
      return { ...draft, record_type: sectionType === 'cname' ? 'cname' : String(ip).includes(':') ? 'aaaa' : 'a', domain: rawValue(row, sectionType === 'cname' ? 'cname' : 'name', 'domain'), ip, target: rawValue(row, 'target') };
    }
    if (type === 'nat') { const sourcePort=rawValue(row,'src_port'), destinationPort=rawValue(row,'dest_port'), translatedIp=rawValue(row,'snat_ip'); return { ...draft, target: String(rawValue(row, 'target') || 'masquerade').toLowerCase(), protocol: rawValue(row, 'proto') || 'all', interface: rawValue(row, 'dest') || firstCatalogValue('wans','wan'), source_type: rawValue(row,'src_ip') ? 'ip' : 'any', destination_type: rawValue(row,'dest_ip') ? 'ip' : 'any', source_ip: rawValue(row, 'src_ip'), destination_ip: rawValue(row, 'dest_ip'), source_port_mode: sourcePort ? 'specific' : 'any', destination_port_mode: destinationPort ? 'specific' : 'any', source_port: sourcePort, destination_port: destinationPort, translated_ip_mode: translatedIp ? 'specific' : 'primary', translated_ip: translatedIp, translate_port: Boolean(rawValue(row,'snat_port')), translated_port: rawValue(row, 'snat_port'), family: rawValue(row, 'family') || 'ipv4' }; }
    if (type === 'static_route') return { ...draft, family: rawValue(row, 'section_type') === 'route6' ? 'ipv6' : (rawValue(row, 'family') || 'ipv4'), destination: rawValue(row, 'target', 'destination'), gateway: rawValue(row, 'gateway'), interface: rawValue(row, 'interface'), table: rawValue(row, 'table') || 'main', metric: Number(rawValue(row, 'metric')) || 0, mtu: Number(rawValue(row, 'mtu')) || 1500, route_kind: rawValue(row, 'type') || 'unicast', source: rawValue(row, 'source') };
    if (type === 'qos') { const download=Number(rawValue(row,'download'))||0, upload=Number(rawValue(row,'upload'))||0; return { ...draft, name: rawValue(row, 'name'), interface: rawValue(row, 'interface'), download_enabled: download>0, upload_enabled: upload>0, download: download>=1000 ? download/1000 : (download||10), upload: upload>=1000 ? upload/1000 : (upload||10), download_unit: download>=1000?'mbps':'kbps', upload_unit: upload>=1000?'mbps':'kbps', qdisc: rawValue(row, 'qdisc') || 'cake', script: rawValue(row, 'script') || 'piece_of_cake.qos', linklayer: rawValue(row, 'linklayer') || 'none', overhead: rawValue(row, 'overhead') }; }
    if (type === 'pbr') { const target=rawValue(row,'target','wan')||firstCatalogValue('wans','wan'), source=rawValue(row,'source_object','source')||'any', destination=rawValue(row,'dest_object','destination')||'any'; return { ...draft, interface: target, source_type: source==='any'?'any':'items', source_items: source==='any'?[]:[source], destination_type: destination==='any'?'any':'ip', destination, protocol: rawValue(row, 'proto', 'protocol') || 'all', ports: rawValue(row, 'ports') || 'any', action: rawValue(row, 'action') || 'route_table', target, route_table: rawValue(row, 'route_table', 'table')||target, priority: Number(rawValue(row, 'priority')) || 1000, schedule_mode: 'always', comment: rawValue(row, 'comment') }; }
    return draft;
  }
  function formField(label, control, wide = false) {
    return `<label class="policy-form-field${wide ? ' is-wide' : ''}"><span>${escapeHtml(label)}</span>${control}</label>`;
  }
  function formInput(name, value, placeholder = '', type = 'text', list = '') {
    return `<input type="${type}" data-policy-draft="${name}" value="${escapeHtml(value ?? '')}" placeholder="${escapeHtml(placeholder)}"${list ? ` list="${escapeHtml(list)}"` : ''}>`;
  }
  function formSelect(name, value, options) {
    const normalized = options.map((item) => ({ key: Array.isArray(item) ? item[0] : item.value, label: Array.isArray(item) ? item[1] : item.label }));
    if (value !== undefined && value !== null && String(value) && !normalized.some((item) => String(item.key) === String(value))) normalized.push({ key: value, label: value });
    return `<select data-policy-draft="${name}">${normalized.map((item) => `<option value="${escapeHtml(item.key)}" ${String(value) === String(item.key) ? 'selected' : ''}>${escapeHtml(item.label)}</option>`).join('')}</select>`;
  }
  function formDatalist(id, options) {
    return `<datalist id="${id}">${options.map((item) => `<option value="${escapeHtml(item.value)}">${escapeHtml(item.label)}</option>`).join('')}</datalist>`;
  }
  function zoneOptions(key, current) {
    const values = (state.catalog[key].length ? [...state.catalog[key]] : [{ value: 'lan', label: '内部' }, { value: 'wan', label: '外部' }]).filter((item) => normalizeKey(item.value) !== 'any');
    if (key === 'destination_zones' && !values.some((item) => normalizeKey(item.value) === 'gateway')) values.splice(Math.min(2, values.length), 0, { value: 'gateway', label: 'Gateway' });
    if (current && !values.some((item) => item.value === current)) return [...values, { value: current, label: current }];
    return values;
  }
  function section(title, body, className = '') {
    return `<section class="policy-editor-section ${className}">${title ? `<h3>${escapeHtml(title)}</h3>` : ''}<div class="policy-editor-section-body">${body}</div></section>`;
  }
  function editorField(label, control, hint = '') {
    return `<label class="policy-editor-field"><span>${escapeHtml(label)}</span>${control}${hint ? `<small>${escapeHtml(hint)}</small>` : ''}</label>`;
  }
  function radioGroup(field, value, options, label = field) {
    return `<div class="policy-choice-row" role="radiogroup" aria-label="${escapeHtml(label)}">${options.map(([key, text, disabled]) => `<label class="policy-choice${disabled ? ' is-disabled' : ''}"><input type="radio" name="policy-${escapeHtml(field)}" data-policy-radio="${escapeHtml(field)}" value="${escapeHtml(key)}" ${String(value) === String(key) ? 'checked' : ''} ${disabled ? 'disabled' : ''}><i></i><span>${escapeHtml(text)}</span></label>`).join('')}</div>`;
  }
  function editorCheck(field, checked, label, hint = '', disabled = false) {
    return `<label class="policy-editor-check${disabled ? ' is-disabled' : ''}"><input type="checkbox" data-policy-check="${escapeHtml(field)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}><i></i><span><strong>${escapeHtml(label)}</strong>${hint ? `<small>${escapeHtml(hint)}</small>` : ''}</span></label>`;
  }
  function editorSelect(field, value, options) {
    return formSelect(field, value, options);
  }
  function editorInput(field, value, placeholder = '', type = 'text') {
    return formInput(field, value, placeholder, type);
  }
  function arrayValue(field) {
    return Array.isArray(state.draft[field]) ? state.draft[field] : [];
  }
  function catalogPicker(field, catalogKey, label, emptyText = '暂无可用对象') {
    const selected = arrayValue(field);
    const options = state.catalog[catalogKey] || [];
    const open = state.pickerOpen === field;
    const summary = selected.length ? selected.map((value) => options.find((item) => item.value === value)?.label || value).join('、') : label;
    return `<div class="policy-object-picker"><button type="button" data-policy-picker="${escapeHtml(field)}"><span>${escapeHtml(summary)}</span><b>${selected.length || ''}</b></button>${open ? `<div class="policy-object-menu"><label class="policy-object-search">${renderSearchIcon()}<input type="search" data-policy-picker-search placeholder="搜索"></label><div>${options.length ? options.map((item) => `<label><input type="checkbox" data-policy-pick="${escapeHtml(field)}" value="${escapeHtml(item.value)}" ${selected.includes(item.value) ? 'checked' : ''}><i></i><span><strong>${escapeHtml(item.label)}</strong>${firstText(item.raw?.mac, item.raw?.address, item.raw?.subnet) ? `<small>${escapeHtml(firstText(item.raw?.mac, item.raw?.address, item.raw?.subnet))}</small>` : ''}</span></label>`).join('') : `<p>${escapeHtml(emptyText)}</p>`}</div>${options.length ? `<button type="button" data-policy-pick-all="${escapeHtml(field)}" data-catalog-key="${escapeHtml(catalogKey)}">全选</button>` : ''}</div>` : ''}</div>`;
  }
  function bulkEntry(field, placeholder) {
    const bulk = state.bulkInputs.has(field);
    return `<div class="policy-entry"><div>${bulk ? `<textarea data-policy-draft="${escapeHtml(field)}" placeholder="${escapeHtml(placeholder)}，每行一个">${escapeHtml(state.draft[field] || '')}</textarea>` : editorInput(field, state.draft[field], placeholder)}<button type="button" data-policy-bulk="${escapeHtml(field)}">${bulk ? '单项输入' : '添加多个'}</button></div></div>`;
  }
  function portEditor(prefix) {
    const modeField = `${prefix}_port_mode`;
    const portField = `${prefix}_port`;
    const serviceField = `${prefix}_port_service`;
    const oppositeField = `${prefix}_port_opposite`;
    const mode = state.draft[modeField] || 'any';
    return `<div class="policy-subfield"><span>端口</span>${radioGroup(modeField, mode, [['any','任何'],['specific','特定'],['list','列表']], `${prefix}端口`)}${mode === 'specific' ? `<div class="policy-port-specific">${editorSelect(serviceField, state.draft[serviceField] || '', SERVICE_PORTS)}${editorInput(portField, state.draft[portField], '例如 1-10,11')}</div>` : mode === 'list' ? catalogPicker(portField, 'objects', '选择端口列表', '尚无端口列表对象') : ''}${mode !== 'any' ? editorCheck(oppositeField, Boolean(state.draft[oppositeField]), '反向匹配端口') : ''}</div>`;
  }
  function scheduleEditor() {
    const d = state.draft;
    const mode = d.schedule_mode || 'always';
    let detail = '';
    if (mode === 'daily') detail = `<div class="policy-time-grid">${editorField('开始时间', editorInput('schedule_start', d.schedule_start, '', 'time'))}${editorField('结束时间', editorInput('schedule_end', d.schedule_end, '', 'time'))}</div>`;
    if (mode === 'weekly' || mode === 'custom') detail = `${mode === 'custom' ? `<div class="policy-time-grid">${editorField('开始日期', editorInput('schedule_date', d.schedule_date, '', 'date'))}${editorField('结束日期', editorInput('schedule_date_end', d.schedule_date_end, '', 'date'))}</div>` : ''}<div class="policy-weekdays">${['一','二','三','四','五','六','日'].map((day, index) => `<label><input type="checkbox" data-policy-array-check="schedule_weekdays" value="${index + 1}" ${arrayValue('schedule_weekdays').includes(String(index + 1)) ? 'checked' : ''}><span>${day}</span></label>`).join('')}</div>${editorCheck('schedule_all_day', Boolean(d.schedule_all_day), '全天')}${!d.schedule_all_day ? `<div class="policy-time-grid">${editorField('开始时间', editorInput('schedule_start', d.schedule_start, '', 'time'))}${editorField('结束时间', editorInput('schedule_end', d.schedule_end, '', 'time'))}</div>` : ''}`;
    if (mode === 'once') detail = `<div class="policy-time-grid">${editorField('日期', editorInput('schedule_date', d.schedule_date, '', 'date'))}${editorField('开始时间', editorInput('schedule_start', d.schedule_start, '', 'time'))}${editorField('结束时间', editorInput('schedule_end', d.schedule_end, '', 'time'))}</div>`;
    return `<div class="policy-subfield"><span>计划</span>${radioGroup('schedule_mode', mode, [['always','始终'],['daily','每天'],['weekly','每周'],['once','一次'],['custom','自定义']], '计划')}${detail}</div>`;
  }
  function addressTarget(prefix, isDestination = false) {
    const d = state.draft;
    const typeField = `${prefix}_type`;
    const type = d[typeField] || 'any';
    const options = isDestination ? [['any','任何'],['application','应用'],['ip','IP'],['domain','域'],['region','地区']] : [['any','任何'],['device','设备'],['network','网络'],['ip','IP'],['mac','MAC'],['identity','身份']];
    let control = '';
    if (type === 'device') control = catalogPicker(`${prefix}_devices`, 'devices', '选择设备', '暂无设备目录数据');
    if (type === 'network') control = `${catalogPicker(`${prefix}_networks`, 'networks', '选择网络', '暂无网络目录数据')}${editorCheck(`${prefix}_match_opposite`, Boolean(d[`${prefix}_match_opposite`]), '匹配相反')}${editorCheck(`${prefix}_match_mac`, Boolean(d[`${prefix}_match_mac`]), '匹配 MAC 地址')}`;
    if (type === 'identity') control = catalogPicker(`${prefix}_identities`, 'objects', '选择人员或角色', '暂无身份目录数据');
    if (type === 'ip') control = `${radioGroup(`${prefix}_match`, d[`${prefix}_match`] || 'specific', [['specific','特定'],['list','列表']], `${prefix} IP`)}${(d[`${prefix}_match`] || 'specific') === 'specific' ? bulkEntry(`${prefix}_ip`, 'IPv4/v6 地址、子网或范围') : catalogPicker(`${prefix}_ip_objects`, 'objects', '选择 IP 列表', '尚无 IP 列表对象')}${editorCheck(`${prefix}_match_opposite`, Boolean(d[`${prefix}_match_opposite`]), '匹配相反')}`;
    if (type === 'mac') control = bulkEntry(`${prefix}_mac`, '例如 ab:cd:ef:12:34:56');
    if (type === 'application') control = `${radioGroup(`${prefix}_app_mode`, d[`${prefix}_app_mode`] || 'specific', [['specific','特定'],['category','类别']], '应用匹配')}${catalogPicker(`${prefix}_applications`, 'applications', '选择应用', '暂无应用目录数据')}`;
    if (type === 'domain') control = bulkEntry(`${prefix}_domain`, 'example.com');
    if (type === 'region') control = catalogPicker(`${prefix}_regions`, 'regions', '选择地区', '暂无地区目录数据');
    return `${radioGroup(typeField, type, options, prefix)}${control}`;
  }
  function protocolEditor() {
    const d = state.draft;
    const protocol = d.protocol || 'all';
    return `<div class="policy-subfield"><span>协议</span>${radioGroup('protocol', protocol, [['all','全部'],['tcp_udp','TCP/UDP'],['tcp','TCP'],['udp','UDP'],['custom','自定义']], '协议')}${protocol === 'custom' ? `${editorSelect('custom_protocol', d.custom_protocol, CUSTOM_PROTOCOLS)}${editorCheck('protocol_opposite', Boolean(d.protocol_opposite), '匹配相反')}` : ''}</div>`;
  }
  function renderFirewallFields() {
    const d = state.draft;
    const autoReturnDisabled = ['wan', 'external', 'gateway'].includes(normalizeKey(d.destination_zone));
    return `${section('', editorField('名称', editorInput('name', d.name, '策略名称')))}
      ${section('源区域', `${editorSelect('source_zone', d.source_zone, zoneOptions('source_zones', d.source_zone))}${addressTarget('source')}${portEditor('source')}`)}
      ${section('操作', `${radioGroup('action', d.action, [['block','阻止'],['allow','允许'],['reject','拒绝']], '操作')}${d.action === 'allow' ? editorCheck('auto_return', Boolean(d.auto_return), '自动允许返回流量', autoReturnDisabled ? '当前区域组合不需要额外返回策略' : '自动创建与当前规则关联的返回流量策略', autoReturnDisabled) : ''}`)}
      ${section('目标区域', `${editorSelect('destination_zone', d.destination_zone, zoneOptions('destination_zones', d.destination_zone))}${addressTarget('destination', true)}${portEditor('destination')}`)}
      ${section('', `<div class="policy-subfield"><span>IP 版本</span>${radioGroup('family', d.family, [['','两者'],['ipv4','IPv4'],['ipv6','IPv6']], 'IP 版本')}</div>${protocolEditor()}<div class="policy-subfield"><span>连接状态</span>${radioGroup('connection_state', d.connection_state, [['all','全部'],['return','返回流量'],['custom','自定义']], '连接状态')}${d.connection_state === 'custom' ? `<div class="policy-state-grid">${['new','invalid','established','related'].map((value) => `<label><input type="checkbox" data-policy-array-check="connection_states" value="${value}" ${arrayValue('connection_states').includes(value) ? 'checked' : ''}><i></i><span>${{new:'新',invalid:'无效',established:'已建立',related:'相关'}[value]}</span></label>`).join('')}</div>` : ''}</div>${editorCheck('match_ipsec', d.match_ipsec, '匹配 IPsec')}${d.match_ipsec ? radioGroup('ipsec_mode', d.ipsec_mode, [['encrypted','已加密'],['unencrypted','未加密']], 'IPsec 匹配') : ''}${editorCheck('syslog', d.syslog, 'Syslog 日志')}${scheduleEditor()}${editorField('描述', `<textarea data-policy-draft="description" placeholder="可选">${escapeHtml(d.description || '')}</textarea>`)}`, 'policy-advanced-section')}`;
  }
  function renderRouteFields() {
    const d = state.draft;
    if (d.policy_type === 'static_route') return `${section('', editorField('名称', editorInput('name', d.name, '静态路由名称')))}${section('类型', `${radioGroup('route_mode', 'static', [['policy','基于策略'],['static','静态']], '路由类型')}<div class="policy-subfield"><span>设备</span>${radioGroup('route_device', 'gateway', [['gateway','Gateway'],['switch','Switch',true]], '设备')}</div>${editorField('Metric', editorInput('metric', d.metric, '0', 'number'))}${radioGroup('gateway_mode', d.gateway_mode, [['next_hop','下一跳'],['interface','接口'],['blackhole','黑洞']], '下一跳模式')}${d.gateway_mode === 'next_hop' ? editorInput('gateway', d.gateway, 'IPv4/v6 地址') : d.gateway_mode === 'interface' ? editorSelect('interface', d.interface, state.catalog.interfaces) : ''}`)}${section('目标', editorField('网络', editorInput('destination', d.destination, 'IPv4/v6 子网')))}`;
    return `${section('', editorField('名称', editorInput('name', d.name, '基于策略的路由名称')))}${section('类型', `${radioGroup('route_mode', 'policy', [['policy','基于策略'],['static','静态']], '路由类型')}${editorField('接口 / VPN 隧道', editorSelect('interface', d.interface, [...state.catalog.wans, ...state.catalog.interfaces]))}${editorCheck('kill_switch', d.kill_switch, '终止开关', '所选接口不可用时阻止匹配流量')}`)}${section('源', `${radioGroup('source_type', d.source_type, [['any','任何'],['items','设备 / 网络']], '源')}${d.source_type === 'items' ? catalogPicker('source_items', 'devices', '选择设备 / 网络', '设备目录尚未提供') : ''}`)}${section('目标', `${radioGroup('destination_type', d.destination_type, [['any','任何'],['ip','IP'],['domain','域'],['region','地区']], '目标')}${d.destination_type === 'ip' ? bulkEntry('destination', 'IPv4/v6 地址、子网或范围') : d.destination_type === 'domain' ? bulkEntry('destination', 'example.com') : d.destination_type === 'region' ? catalogPicker('destination_regions','regions','选择地区','暂无地区目录数据') : ''}`)}`;
  }
  function renderQosFields() {
    const d=state.draft;
    const showLimit=d.qos_behavior!=='prioritize';
    return `${section('', editorField('名称', editorInput('name',d.name,'QoS 策略名称')))}${section('QoS 行为', `${radioGroup('qos_behavior',d.qos_behavior,[['limit','限制'],['prioritize','优先'],['both','优先和限制']],'QoS 行为')}${editorField('接口',editorSelect('interface',d.interface,[{value:'all',label:'所有 WAN'},...state.catalog.wans]))}${showLimit ? `${editorCheck('download_enabled',d.download_enabled,'下载限制')}${d.download_enabled ? `<div class="policy-rate-row">${editorInput('download',d.download,'10','number')}${editorSelect('download_unit',d.download_unit,[['kbps','Kbps'],['mbps','Mbps']])}</div>${radioGroup('download_burst',d.download_burst,[['off','关'],['short','短'],['long','长']],'下载突发')}`:''}${editorCheck('upload_enabled',d.upload_enabled,'上传限制')}${d.upload_enabled ? `<div class="policy-rate-row">${editorInput('upload',d.upload,'10','number')}${editorSelect('upload_unit',d.upload_unit,[['kbps','Kbps'],['mbps','Mbps']])}</div>${radioGroup('upload_burst',d.upload_burst,[['off','关'],['short','短'],['long','长']],'上传突发')}`:''}` : ''}`)}${section('源', `${radioGroup('source_type',d.source_type,[['any','任何'],['device','设备'],['network','网络']],'源')}${d.source_type==='device'?catalogPicker('source_devices','devices','选择设备','暂无设备目录数据'):d.source_type==='network'?catalogPicker('source_networks','networks','选择网络','暂无网络目录数据'):''}`)}${section('目标', `${addressTarget('destination',true)}${portEditor('destination')}`)}${section('',scheduleEditor())}`;
  }
  function renderNatFields() {
    const d=state.draft;
    return `${section('',editorField('名称',editorInput('name',d.name,'NAT 策略名称')))}${section('类型',`${radioGroup('target',d.target,[['masquerade','伪装'],['snat','源 NAT'],['dnat','目标 NAT']],'NAT 类型')}${editorField('接口 / VPN 隧道',editorSelect('interface',d.interface,[...state.catalog.wans,...state.catalog.networks]))}${d.target==='snat'?`${radioGroup('translated_ip_mode',d.translated_ip_mode,[['primary','主要地址'],['specific','特定']],'转换的 IP 地址')}${d.translated_ip_mode==='specific'?editorInput('translated_ip',d.translated_ip,'IPv4 地址、子网或范围'):''}`:d.target==='dnat'?editorField('转换的 IP 地址',editorInput('translated_ip',d.translated_ip,'IPv4 地址、子网或范围')):''}${d.target!=='masquerade'&&['tcp_udp','tcp','udp'].includes(d.protocol)?editorCheck('translate_port',d.translate_port,'转换的端口'):''}${d.translate_port?editorField('转换的端口',editorInput('translated_port',d.translated_port,'例如 443')):''}<div class="policy-subfield"><span>IP 版本</span>${radioGroup('family',d.family,[['ipv4','IPv4'],['ipv6','IPv6']],'IP 版本')}</div>${protocolEditor()}`)}${section('源',`${radioGroup('source_type',d.source_type,[['any','任何'],['network','网络'],['ip','IP']],'源')}${d.source_type==='network'?catalogPicker('source_networks','networks','选择网络','暂无网络目录数据'):d.source_type==='ip'?bulkEntry('source_ip','IPv4/v6 地址、子网或范围'):''}${portEditor('source')}`)}${section('目标',`${radioGroup('destination_type',d.destination_type,[['any','任何'],['network','网络'],['ip','IP']],'目标')}${d.destination_type==='network'?catalogPicker('destination_networks','networks','选择网络','暂无网络目录数据'):d.destination_type==='ip'?bulkEntry('destination_ip','IPv4/v6 地址、子网或范围'):''}${portEditor('destination')}`)}${section('',`${editorCheck('syslog',d.syslog,'Syslog 日志')}${editorCheck('exclude',d.exclude,'排除')}`)}`;
  }
  function renderDnsFields() {
    const d=state.draft;
    const types=[['a','主机 (A)'],['aaaa','主机 (AAAA)'],['cname','别名 (CNAME)'],['mx','邮件 (MX)'],['txt','文本 (TXT)'],['srv','服务 (SRV)'],['forward','转发域']];
    let fields='';
    if(['a','aaaa'].includes(d.record_type)) fields=`${editorField('域名',editorInput('domain',d.domain,'host.example.com'))}${editorField('IP 地址',editorInput('ip',d.ip,d.record_type==='aaaa'?'IPv6 地址':'IPv4 地址'))}`;
    if(d.record_type==='cname') fields=`${editorField('别名域',editorInput('domain',d.domain,'alias.example.com'))}${editorField('目标域',editorInput('target',d.target,'host.example.com'))}`;
    if(d.record_type==='mx') fields=`${editorField('域名',editorInput('domain',d.domain,'example.com'))}${editorField('邮件服务器',editorInput('mail_server',d.mail_server,'server.example.com'))}${editorField('优先级',editorInput('priority',d.priority,'0','number'))}`;
    if(d.record_type==='txt') fields=`${editorField('域名',editorInput('domain',d.domain,'host.example.com'))}${editorField('文本',`<textarea data-policy-draft="text" placeholder="输入文本记录">${escapeHtml(d.text||'')}</textarea>`)}`;
    if(d.record_type==='srv') fields=`${editorField('域名',editorInput('domain',d.domain,'example.com'))}${editorField('服务器',editorInput('server',d.server,'server.example.com'))}${editorField('服务',editorInput('service',d.service,'例如 _ldap'))}${editorField('协议',editorInput('dns_protocol',d.dns_protocol,'例如 _tcp'))}${editorField('端口',editorInput('port',d.port,'例如 389','number'))}${editorField('优先级',editorInput('priority',d.priority,'0','number'))}${editorField('权重',editorInput('weight',d.weight,'0','number'))}`;
    if(d.record_type==='forward') fields=`<p class="policy-field-description">将特定域的所有查询转发到不同的 DNS 服务器。</p>${editorField('域名',editorInput('domain',d.domain,'example.com'))}${editorField('DNS 服务器',editorInput('dns_server',d.dns_server,'IPv4 或 IPv6 地址'))}`;
    const ttl=['a','aaaa','cname'].includes(d.record_type)?`${editorField('TTL',radioGroup('ttl_mode',d.ttl_mode,[['auto','自动'],['manual','手动']],'TTL'))}${d.ttl_mode==='manual'?editorField('TTL（秒）',editorInput('ttl',d.ttl,'300','number')):''}`:'';
    return `${section('',editorField('类型',editorSelect('record_type',d.record_type,types)))}${section('',`${fields}${ttl}`)}`;
  }
  function renderPortForwardFields() {
    const d=state.draft;
    const wans=ipv4WanOptions().length?ipv4WanOptions():[{value:'wan',label:'WAN1'}];
    const selectedWan=wans.find((item)=>item.value===d.source_zone);
    const wanIp=firstText(selectedWan?.raw?.public_ip,selectedWan?.raw?.ip,selectedWan?.raw?.address);
    return `${section('',editorField('名称',editorInput('name',d.name,'端口转发名称')))}${section('',`<div class="policy-subfield"><span>WAN 接口</span>${radioGroup('source_zone',d.source_zone,[...wans.map((item)=>[item.value,item.label]),['all','所有 WAN']],'WAN 接口')}</div>${editorField('WAN IP 地址',`<input type="text" value="${escapeHtml(wanIp||'后端未提供')}" disabled>`)}${editorField('WAN 端口',editorInput('external_port',d.external_port,'例如 1-10,11,12'))}<div class="policy-subfield"><span>从</span>${radioGroup('source_mode',d.source_mode,[['any','任意'],['restricted','受限']],'来源')}</div>${d.source_mode==='restricted'?`${radioGroup('source_match',d.source_match||'specific',[['specific','特定'],['list','列表']],'来源匹配')}${(d.source_match||'specific')==='specific'?bulkEntry('source_ip','IPv4 地址、子网或范围'):catalogPicker('source_ip_objects','objects','选择 IP 列表','尚无 IP 列表对象')}`:''}${editorField('转发 IP 地址',editorInput('internal_ip',d.internal_ip,'IPv4 地址'))}${catalogPicker('internal_devices','devices','选择设备','暂无设备目录数据')}${editorField('转发端口',editorInput('internal_port',d.internal_port,'例如 1-10,11,12'))}<div class="policy-subfield"><span>协议</span>${radioGroup('protocol',d.protocol,[['tcp_udp','TCP/UDP'],['tcp','TCP'],['udp','UDP']],'协议')}</div>`)}${section('',editorCheck('syslog',d.syslog,'Syslog 日志'))}`;
  }
  function unsupportedReasons() {
    const d=state.draft, reasons=[];
    if(d.policy_type==='acl') reasons.push('后端尚未开放 ACL 写入');
    if(d.policy_type==='firewall') {
      if(normalizeKey(d.destination_zone)==='gateway') reasons.push('Gateway 目标需要路由器本机策略链的稳定后端语义');
      if(!['any','ip'].includes(d.source_type)||!['any','ip'].includes(d.destination_type)) reasons.push('设备、网络、MAC、身份、应用、域和地区对象事务尚未实现');
      if(d.source_match==='list'||d.destination_match==='list'||d.source_port_mode==='list'||d.destination_port_mode==='list') reasons.push('对象列表引用尚未实现');
      if(d.source_match_opposite||d.destination_match_opposite||d.source_port_opposite||d.destination_port_opposite||d.source_match_mac) reasons.push('反向匹配与 MAC 匹配尚未进入写入合同');
      if(d.connection_state!=='all'||d.match_ipsec||d.syslog||d.schedule_mode!=='always'||d.description) reasons.push('连接状态、IPsec、Syslog、计划和描述字段尚未进入后端事务');
      if(d.auto_return) reasons.push('自动返回策略的关联创建与回滚事务尚未实现');
    }
    if(d.policy_type==='pbr') {
      if(d.source_type!=='any') reasons.push('PBR 设备/网络对象目录与原子写入尚未实现');
      if(d.destination_type==='region') reasons.push('PBR 地区对象写入尚未实现');
    }
    if(d.policy_type==='qos') {
      if(d.qos_behavior!=='limit') reasons.push('当前后端只有 SQM 限速，没有 UniFi DPI 优先级队列语义');
      if(d.source_type!=='any'||d.destination_type!=='any'||d.destination_port_mode!=='any') reasons.push('QoS 源、目标和端口对象匹配尚未实现');
      if(d.download_burst!=='off'||d.upload_burst!=='off'||d.schedule_mode!=='always') reasons.push('QoS 突发与计划尚未进入后端合同');
    }
    if(d.policy_type==='nat') {
      if(d.target==='dnat') reasons.push('DNAT 请使用端口转发；config nat 执行器尚未承载 UniFi 目标 NAT 合同');
      if(d.target==='snat'&&d.translated_ip_mode==='primary') reasons.push('后端尚未提供所选接口主要地址的稳定写入解析');
      if(!['any','ip'].includes(d.source_type)||!['any','ip'].includes(d.destination_type)) reasons.push('NAT 网络对象引用尚未实现');
      if(d.source_port_mode==='list'||d.destination_port_mode==='list'||d.syslog||d.exclude) reasons.push('NAT 对象端口、Syslog 或排除语义尚未实现');
    }
    if(d.policy_type==='dns'&&!['a','aaaa','cname'].includes(d.record_type)) reasons.push('后端 dnsmasq 执行器尚未支持 MX、TXT、SRV 和转发域');
    if(d.policy_type==='dns'&&d.ttl_mode==='manual') reasons.push('DNS TTL 尚未进入写入合同');
    if(d.policy_type==='port_forwarding'&&(d.source_match==='list'||d.source_zone==='all'||d.syslog||arrayValue('internal_devices').length)) reasons.push('端口转发的对象列表、设备引用、所有 WAN 或 Syslog 语义尚未实现');
    return [...new Set(reasons)];
  }
  function renderPolicyFields() {
    const type=state.draft.policy_type;
    if(type==='firewall') return renderFirewallFields();
    if(type==='pbr'||type==='static_route') return renderRouteFields();
    if(type==='qos') return renderQosFields();
    if(type==='nat') return renderNatFields();
    if(type==='dns') return renderDnsFields();
    if(type==='port_forwarding') return renderPortForwardFields();
    return section('', '<div class="policy-notice">ACL 后端写入尚未开放。</div>');
  }
  function renderCreatePanel() {
    if (!state.createOpen) return '';
    const editing = Boolean(state.selectedRow);
    const type = state.draft.policy_type || 'firewall';
    const reasons=unsupportedReasons();
    const canWrite = !state.selectedRow?.predefined && capabilityFor(type, editing ? 'update' : 'create');
    const canSave = canWrite && reasons.length === 0;
    return `<aside class="policy-side-panel policy-create-panel dwrt-kit-sheet policy-stable-glass is-open" data-create-panel>
      <div class="policy-side-head dwrt-kit-sheet-header"><div><strong>${editing ? escapeHtml(state.selectedRow.name) : '创建策略'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-close-create aria-label="关闭">×</button></div>
      <div class="policy-side-body dwrt-kit-sheet-body">
        ${editing ? '' : `<div class="policy-type-picker" role="radiogroup" aria-label="策略类型">${CREATE_TYPES.map((item) => `<label class="${editorType(type)===item.value?'is-active':''}${typeCanCreate(item.value)?'':' is-disabled'}"><input type="radio" data-policy-type="${escapeHtml(item.value)}" name="policy-create-type" ${editorType(type)===item.value?'checked':''} ${typeCanCreate(item.value)?'':'disabled'}><i></i><span>${escapeHtml(item.label)}</span></label>`).join('')}</div>`}
        <div class="policy-editor">${renderPolicyFields()}</div>
        ${reasons.length ? `<div class="policy-contract-gap"><strong>当前配置不能保存</strong>${reasons.map((reason)=>`<span>${escapeHtml(reason)}</span>`).join('')}</div>` : ''}
        ${state.catalogError ? `<div class="policy-notice">${escapeHtml(state.catalogError)}，部分候选项需手动填写。</div>` : ''}
        ${state.notice ? `<div class="policy-notice ${/失败|错误|不支持|请填写|必须/.test(state.notice) ? 'is-error' : ''}">${escapeHtml(state.notice)}</div>` : ''}
      </div>
      <footer class="dwrt-kit-sheet-footer"><button type="button" class="policy-secondary" data-close-create>取消</button><button type="button" class="policy-primary" data-policy-save ${canSave && !state.saving ? '' : 'disabled'}>${state.saving ? '正在保存' : canSave ? (editing?'保存':'添加策略') : reasons.length ? '等待后端能力' : '此类型不可写'}</button></footer>
    </aside>`;
  }
  function renderDetailsPanel() {
    if (!state.detailsOpen || !state.selectedRow) return '';
    const row = state.selectedRow;
    const pairs = [
      ['名称', row.name], ['策略类型', row.type], ['操作', row.action], ['协议', row.protocol], ['源区域', row.source_zone], ['源', cellText(row.source)], ['目标区域', row.destination_zone], ['目标', cellText(row.destination)], ['目标端口', row.destination_port], ['接口', row.interface], ['状态', row.enabled ? '启用' : '停用'], ['默认策略', row.predefined ? '是' : '否']
    ];
    const canUpdate = !row.predefined && capabilityFor(row.policy_type, 'update');
    const canDelete = !row.predefined && capabilityFor(row.policy_type, 'delete');
    const canToggle = !row.predefined && capabilityFor(row.policy_type, 'enable_disable');
    return `<aside class="policy-side-panel dwrt-kit-sheet dwrt-glass-card policy-stable-glass is-open" data-detail-panel>
      <div class="policy-side-head dwrt-kit-sheet-header"><div><span>Policy</span><strong>${escapeHtml(row.name)}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-close-detail>×</button></div>
      <div class="policy-side-body dwrt-kit-sheet-body"><dl class="policy-detail-list">${pairs.map(([k, v]) => `<div><dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v || '--')}</dd></div>`).join('')}</dl>${row.predefined ? '<div class="policy-notice">系统默认策略为只读。</div>' : ''}${state.notice ? `<div class="policy-notice ${/失败|错误/.test(state.notice) ? 'is-error' : ''}">${escapeHtml(state.notice)}</div>` : ''}</div>
      <footer class="dwrt-kit-sheet-footer policy-detail-footer"><button type="button" class="policy-secondary danger" data-policy-delete ${canDelete && !state.saving ? '' : 'disabled'}>${state.confirmDelete ? '再次点击删除' : '删除'}</button><div><button type="button" class="policy-secondary" data-policy-toggle ${canToggle && !state.saving ? '' : 'disabled'}>${row.enabled ? '停用' : '启用'}</button><button type="button" class="policy-primary" data-policy-edit ${canUpdate && !state.saving ? '' : 'disabled'}>编辑</button></div></footer>
    </aside>`;
  }

  function reloadFlags(type) {
    if (['firewall', 'port_forwarding', 'nat'].includes(type)) return { reload_firewall: true };
    if (type === 'dns') return { reload_dnsmasq: true };
    if (type === 'qos') return { reload_sqm: false };
    if (type === 'static_route') return { reload_network: false };
    if (type === 'pbr') return { reload_route: true };
    return {};
  }
  function payloadFromDraft() {
    const d = state.draft;
    const common = { policy_type: d.policy_type, enabled: Boolean(d.enabled), apply: true, ...reloadFlags(d.policy_type) };
    if (d.policy_type === 'firewall') return { ...common, name: d.name.trim(), action: d.action, protocol: d.protocol === 'custom' ? d.custom_protocol : d.protocol, source_zone: d.source_zone, destination_zone: d.destination_zone, source_ip: d.source_type === 'ip' ? String(d.source_ip || '').trim() : '', destination_ip: d.destination_type === 'ip' ? String(d.destination_ip || '').trim() : '', source_port: d.source_port_mode === 'specific' ? String(d.source_port || d.source_port_service || '').trim() : '', destination_port: d.destination_port_mode === 'specific' ? String(d.destination_port || d.destination_port_service || '').trim() : '', family: d.family };
    if (d.policy_type === 'port_forwarding') return { ...common, name: d.name.trim(), protocol: d.protocol, source_zone: d.source_zone, destination_zone: d.destination_zone, src_dport: d.external_port.trim(), dest_ip: d.internal_ip.trim(), dest_port: d.internal_port.trim(), src_ip: d.source_mode === 'restricted' ? String(d.source_ip || '').trim() : '', family: d.family };
    if (d.policy_type === 'dns') return { ...common, record_type: d.record_type === 'cname' ? 'cname' : 'domain', name: d.domain.trim(), domain: d.domain.trim(), cname: d.domain.trim(), target: String(d.target || '').trim(), ip: String(d.ip || '').trim() };
    if (d.policy_type === 'nat') return { ...common, name: d.name.trim(), target: d.target, protocol: d.protocol === 'custom' ? d.custom_protocol : d.protocol, source_zone: d.source_type === 'network' ? firstText(arrayValue('source_networks')[0]) : 'lan', destination_zone: d.interface || 'wan', source_ip: d.source_type === 'ip' ? String(d.source_ip || '').trim() : '', destination_ip: d.destination_type === 'ip' ? String(d.destination_ip || '').trim() : '', source_port: d.source_port_mode === 'specific' ? String(d.source_port || d.source_port_service || '').trim() : '', destination_port: d.destination_port_mode === 'specific' ? String(d.destination_port || d.destination_port_service || '').trim() : '', snat_ip: d.target === 'snat' ? String(d.translated_ip || '').trim() : '', snat_port: d.translate_port ? String(d.translated_port || '').trim() : '', family: d.family };
    if (d.policy_type === 'static_route') return { ...common, name: d.name.trim(), family: d.family, target: d.destination.trim(), destination: d.destination.trim(), gateway: d.gateway_mode === 'next_hop' ? d.gateway.trim() : '', interface: d.gateway_mode === 'interface' ? d.interface.trim() : '', table: d.table.trim() || 'main', metric: Number(d.metric) || 0, mtu: Number(d.mtu) || 1500, route_kind: d.gateway_mode === 'blackhole' ? 'blackhole' : (d.route_kind || 'unicast'), source: d.source.trim() };
    if (d.policy_type === 'qos') { const rate=(value,unit)=>String(Math.max(0,Number(value)||0)*(unit==='mbps'?1000:1)); return { ...common, name: d.name.trim(), interface: d.interface.trim(), download: d.download_enabled ? rate(d.download,d.download_unit) : '0', upload: d.upload_enabled ? rate(d.upload,d.upload_unit) : '0', qdisc: d.qdisc, script: d.script, linklayer: d.linklayer, overhead: String(d.overhead ?? '').trim() }; }
    if (d.policy_type === 'pbr') return { ...common, name: d.name.trim(), source_object: d.source_type === 'any' ? 'any' : firstText(arrayValue('source_items')[0]) || 'any', dest_object: d.destination_type === 'any' ? 'any' : String(d.destination || '').trim(), protocol: d.protocol, ports: String(d.ports || 'any').trim() || 'any', action: d.action, target: d.interface.trim(), route_table: d.interface.trim(), priority: Number(d.priority) || 1000, schedule: 'always', comment: d.comment.trim() };
    return common;
  }
  function validateDraft() {
    const d = state.draft;
    const unsupported = unsupportedReasons();
    if (unsupported.length) return unsupported[0] + '。';
    if (['firewall', 'port_forwarding', 'nat', 'pbr'].includes(d.policy_type) && !d.name.trim()) return '请填写策略名称。';
    if (d.policy_type === 'port_forwarding' && !d.external_port.trim()) return '请填写外部端口。';
    if (d.policy_type === 'port_forwarding' && !d.internal_ip.trim()) return '请填写内部 IP。';
    if (d.policy_type === 'dns' && !d.domain.trim()) return '请填写域名。';
    if (d.policy_type === 'dns' && d.record_type === 'cname' && !d.target.trim()) return '请填写 CNAME 目标域名。';
    if (d.policy_type === 'dns' && d.record_type !== 'cname' && !String(d.ip || '').trim()) return '请填写 IP 地址。';
    if (d.policy_type === 'nat' && d.target === 'snat' && d.translated_ip_mode === 'specific' && !String(d.translated_ip || '').trim()) return '源 NAT 必须填写转换后的 IP。';
    if (d.policy_type === 'static_route' && !d.destination.trim()) return '请填写目标网络。';
    if (d.policy_type === 'static_route' && !d.gateway.trim() && !d.interface.trim()) return '下一跳和接口至少填写一项。';
    if (d.policy_type === 'qos' && !d.name.trim()) return '请填写 QoS 策略名称。';
    if (d.policy_type === 'qos' && !d.interface.trim()) return '请选择 QoS 接口。';
    if (d.policy_type === 'qos' && !d.download_enabled && !d.upload_enabled) return '下载限制和上传限制至少启用一项。';
    if (d.policy_type === 'pbr' && d.action !== 'main' && !d.target.trim() && !d.route_table.trim()) return '请填写策略路由的目标出口或路由表。';
    return '';
  }
  async function savePolicy() {
    const error = validateDraft();
    if (error) { state.notice = error; render(); return; }
    const editing = Boolean(state.selectedRow);
    if (!capabilityFor(state.draft.policy_type, editing ? 'update' : 'create')) { state.notice = '后端未开放此策略类型的写入。'; render(); return; }
    state.saving = true;
    state.notice = '';
    render();
    try {
      const payload = payloadFromDraft();
      if (editing) await requestJson(`${ENDPOINT}/${encodeURIComponent(state.selectedRow.id)}?apply=true`, { method: 'PATCH', body: JSON.stringify(payload) });
      else await requestJson(`${ENDPOINT}?apply=true`, { method: 'POST', body: JSON.stringify(payload) });
      state.saving = false;
      state.createOpen = false;
      state.selectedRow = null;
      render();
      await load();
    } catch (errorValue) {
      state.saving = false;
      state.notice = `保存失败：${firstText(errorValue?.message, '未知错误')}`;
      render();
    }
  }
  async function deletePolicy() {
    const row = state.selectedRow;
    if (!row || row.predefined || !capabilityFor(row.policy_type, 'delete')) return;
    if (!state.confirmDelete) { state.confirmDelete = true; render(); return; }
    state.saving = true;
    state.notice = '';
    render();
    try {
      await requestJson(`${ENDPOINT}/${encodeURIComponent(row.id)}?apply=true`, { method: 'DELETE', body: JSON.stringify({ policy_type: row.policy_type, apply: true, ...reloadFlags(row.policy_type) }) });
      state.saving = false;
      state.detailsOpen = false;
      state.selectedRow = null;
      render();
      await load();
    } catch (errorValue) {
      state.saving = false;
      state.confirmDelete = false;
      state.notice = `删除失败：${firstText(errorValue?.message, '未知错误')}`;
      render();
    }
  }
  async function togglePolicy() {
    const row = state.selectedRow;
    if (!row || row.predefined || !capabilityFor(row.policy_type, 'enable_disable')) return;
    state.saving = true;
    state.notice = '';
    render();
    const operation = row.enabled ? 'disable' : 'enable';
    try {
      await requestJson(`${ENDPOINT}/${encodeURIComponent(row.id)}/${operation}?apply=true`, { method: 'POST', body: JSON.stringify({ policy_type: row.policy_type, apply: true, ...reloadFlags(row.policy_type) }) });
      state.saving = false;
      state.detailsOpen = false;
      state.selectedRow = null;
      render();
      await load();
    } catch (errorValue) {
      state.saving = false;
      state.notice = `${row.enabled ? '停用' : '启用'}失败：${firstText(errorValue?.message, '未知错误')}`;
      render();
    }
  }
  function renderCell(row, column) {
    switch (column.key) {
      case 'expand': return row.children?.length ? `<button type="button" class="policy-expand" data-expand-row="${escapeHtml(row.id)}" aria-label="展开"><span>${state.expandedRows.has(row.id) ? '−' : '+'}</span></button>` : '';
      case 'name': return `<button type="button" class="policy-name-button" data-open-row="${escapeHtml(row.id)}" title="${escapeHtml(row.name)}">${escapeHtml(row.name)}</button>`;
      case 'type': return escapeHtml(row.type);
      case 'action': return `<span class="policy-action policy-action-${escapeHtml(row.action_key)}">${escapeHtml(row.action)}</span>`;
      case 'protocol': return escapeHtml(row.protocol || '--');
      case 'source_zone': return compactValue(row.source_zone);
      case 'source': return compactValue(row.source);
      case 'destination_zone': return compactValue(row.destination_zone);
      case 'destination': return compactValue(row.destination);
      case 'destination_port': return escapeHtml(row.destination_port || '--');
      case 'interface': return compactValue(row.interface);
      default: return '';
    }
  }
  function renderRow(row, nested = false) {
    const classes = ['policy-row', nested ? 'is-child' : '', !row.enabled ? 'is-disabled' : ''].filter(Boolean).join(' ');
    const cols = DEFAULT_COLUMNS.filter((column) => columnVisible(column.key));
    const html = `<tr class="${classes}" data-row-id="${escapeHtml(row.id)}">${cols.map((column) => `<td class="policy-col-${escapeHtml(column.key)}">${renderCell(row, column)}</td>`).join('')}</tr>`;
    const children = !nested && state.expandedRows.has(row.id) ? (row.children || []).map((child) => renderRow(child, true)).join('') : '';
    return html + children;
  }
  function renderTable() {
    const rows = visibleRows();
    const cols = DEFAULT_COLUMNS.filter((column) => columnVisible(column.key));
    return `<section class="policy-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap policy-stable-glass">
      <div class="dwrt-kit-table-scroll policy-table-scroll" data-table-scroll>
        <table class="dwrt-kit-table dwrt-kit-ikuai-table policy-table">
          <thead><tr>${cols.map((column) => `<th style="min-width:${column.min || 42}px">${escapeHtml(column.label)}</th>`).join('')}</tr></thead>
          <tbody>${state.loading ? '<tr><td colspan="20" class="dwrt-kit-table-empty policy-empty-cell">正在读取策略表…</td></tr>' : rows.length ? rows.map((row) => renderRow(row)).join('') : '<tr><td colspan="20" class="dwrt-kit-table-empty policy-empty-cell">没有匹配的策略</td></tr>'}</tbody>
        </table>
      </div>
      <div class="policy-table-foot"><button type="button" data-reorder disabled>重新排序</button></div>
    </section>`;
  }
  function bindPolicyTableRows() {
    root.querySelectorAll('[data-expand-row]').forEach((button) => button.addEventListener('click', (event) => { event.stopPropagation(); toggleSet(state.expandedRows, button.dataset.expandRow); render(); }));
    root.querySelectorAll('[data-open-row]').forEach((button) => button.addEventListener('click', () => {
      const id = button.dataset.openRow;
      state.selectedRow = state.rows.find((row) => row.id === id) || null;
      state.detailsOpen = Boolean(state.selectedRow);
      state.createOpen = false;
      state.notice = '';
      state.confirmDelete = false;
      render();
    }));
  }
  function patchPolicyTable() {
    const tbody = root.querySelector('.policy-table tbody');
    if (!tbody) return render();
    const scroll = root.querySelector('[data-table-scroll]');
    const scrollTop = scroll?.scrollTop || 0;
    const scrollLeft = scroll?.scrollLeft || 0;
    const rows = visibleRows();
    tbody.innerHTML = state.loading
      ? '<tr><td colspan="20" class="dwrt-kit-table-empty policy-empty-cell">正在读取策略表…</td></tr>'
      : rows.length ? rows.map((row) => renderRow(row)).join('') : '<tr><td colspan="20" class="dwrt-kit-table-empty policy-empty-cell">没有匹配的策略</td></tr>';
    bindPolicyTableRows();
    if (scroll) {
      scroll.scrollTop = scrollTop;
      scroll.scrollLeft = scrollLeft;
    }
  }
  function patchPolicyStatus() {
    const shell = root.querySelector('.policy-table-shell');
    const table = root.querySelector('.policy-table-card');
    if (!shell || !table) return false;
    const status = renderStatus();
    let line = shell.querySelector(':scope > .policy-status-line');
    if (!status) {
      line?.remove();
      return true;
    }
    if (!line) {
      line = document.createElement('div');
      line.className = 'policy-status-line';
      shell.insertBefore(line, table);
    }
    line.classList.toggle('is-warning', Boolean(state.error));
    line.textContent = status;
    return true;
  }
  function patchPolicyToolbar() {
    const createButton = root.querySelector('[data-open-create]');
    if (!createButton) return;
    const enabled = !state.loading && state.capabilities.create === true;
    createButton.disabled = !enabled;
    const label = createButton.querySelector('span');
    if (label) label.textContent = state.loading ? '正在读取能力' : '创建新策略';
  }
  function patchPolicyView() {
    if (!root?.querySelector('.policy-table-shell')) return render();
    if (state.drawerOpen || state.columnsOpen || state.createOpen || state.detailsOpen) return render();
    patchPolicyToolbar();
    patchPolicyStatus();
    patchPolicyTable();
  }
  function render() {
    if (!root) return;
    const previousSideScroll = root.querySelector('.policy-side-body')?.scrollTop || 0;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', MODULE_CLASS);
    const drawerBackdrop = state.drawerOpen ? '<button type="button" class="policy-drawer-backdrop dwrt-kit-sheet-overlay" data-close-filter aria-label="关闭筛选"></button>' : '';
    const sideBackdrop = state.createOpen || state.detailsOpen ? '<button type="button" class="policy-drawer-backdrop dwrt-kit-sheet-overlay" data-close-side aria-label="关闭侧边面板"></button>' : '';
    const status = renderStatus();
    root.innerHTML = `<section class="policy-table-shell${state.drawerOpen ? ' is-filter-open' : ''}${state.createOpen || state.detailsOpen ? ' is-side-open' : ''}">
      <header class="policy-toolbar">
        <label class="policy-search policy-search-main" data-dwrt-component="expand-search">${renderSearchIcon()}<input data-policy-search type="search" placeholder="搜索策略表" value="${escapeHtml(state.query)}"></label>
        <div class="policy-toolbar-actions">
          <button type="button" class="policy-filter-button" data-open-filter>${renderFilterIcon()}<span>筛选</span>${filterButtonCount()}</button>
          <button type="button" class="policy-create-button" data-open-create ${state.loading || state.capabilities.create !== true ? 'disabled' : ''}>${renderPlusIcon()}<span>${state.loading ? '正在读取能力' : '创建新策略'}</span></button>
        </div>
      </header>
      ${status ? `<div class="policy-status-line${state.error ? ' is-warning' : ''}">${escapeHtml(status)}</div>` : ''}
      ${renderTable()}
      ${drawerBackdrop}${sideBackdrop}${renderDrawer()}${renderColumnsPanel()}${renderCreatePanel()}${renderDetailsPanel()}
    </section>`;
    bindEvents();
    ui.mountAll?.(root);
    const nextSideBody = root.querySelector('.policy-side-body');
    if (nextSideBody) nextSideBody.scrollTop = previousSideScroll;
  }
  function bindEvents() {
    root.querySelectorAll('[data-open-filter]').forEach((button) => button.addEventListener('click', () => { state.drawerOpen = true; render(); }));
    root.querySelectorAll('[data-close-filter]').forEach((button) => button.addEventListener('click', () => { state.drawerOpen = false; render(); }));
    root.querySelectorAll('[data-open-columns]').forEach((button) => button.addEventListener('click', () => { state.columnsOpen = true; render(); }));
    root.querySelectorAll('[data-close-columns]').forEach((button) => button.addEventListener('click', () => { state.columnsOpen = false; render(); }));
    root.querySelectorAll('[data-open-create]').forEach((button) => button.addEventListener('click', () => { state.createOpen = true; state.detailsOpen = false; state.selectedRow = null; state.draft = newDraft(writeTypes().has('firewall') ? 'firewall' : [...writeTypes()][0]); state.notice = ''; state.confirmDelete = false; render(); }));
    root.querySelectorAll('[data-close-create]').forEach((button) => button.addEventListener('click', () => { state.createOpen = false; state.selectedRow = null; state.notice = ''; render(); }));
    root.querySelectorAll('[data-close-detail]').forEach((button) => button.addEventListener('click', () => { state.detailsOpen = false; state.selectedRow = null; state.notice = ''; state.confirmDelete = false; render(); }));
    root.querySelectorAll('[data-close-side]').forEach((button) => button.addEventListener('click', () => { state.createOpen = false; state.detailsOpen = false; state.selectedRow = null; state.notice = ''; state.confirmDelete = false; render(); }));
    root.querySelectorAll('[data-policy-type]').forEach((input) => input.addEventListener('change', () => { state.draft = newDraft(input.dataset.policyType === 'route' ? 'pbr' : input.dataset.policyType); state.notice = ''; state.pickerOpen=''; render(); }));
    root.querySelectorAll('[data-policy-radio]').forEach((input) => input.addEventListener('change', () => {
      const field=input.dataset.policyRadio;
      if(field==='route_mode') {
        const name=state.draft.name;
        state.draft=newDraft(input.value==='static'?'static_route':'pbr');
        state.draft.name=name;
      } else state.draft[field]=input.value;
      state.notice=''; state.pickerOpen=''; render();
    }));
    root.querySelectorAll('[data-policy-check]').forEach((input) => input.addEventListener('change', () => { state.draft[input.dataset.policyCheck]=input.checked; state.notice=''; render(); }));
    root.querySelectorAll('[data-policy-array-check]').forEach((input) => input.addEventListener('change', () => {
      const field=input.dataset.policyArrayCheck;
      const values=new Set(arrayValue(field).map(String));
      if(input.checked) values.add(String(input.value)); else values.delete(String(input.value));
      state.draft[field]=[...values]; state.notice=''; render();
    }));
    root.querySelectorAll('[data-policy-picker]').forEach((button)=>button.addEventListener('click',()=>{state.pickerOpen=state.pickerOpen===button.dataset.policyPicker?'':button.dataset.policyPicker;render();}));
    root.querySelectorAll('[data-policy-pick]').forEach((input)=>input.addEventListener('change',()=>{
      const field=input.dataset.policyPick, values=new Set(arrayValue(field));
      if(input.checked)values.add(input.value);else values.delete(input.value);
      state.draft[field]=[...values]; state.notice=''; render();
    }));
    root.querySelectorAll('[data-policy-pick-all]').forEach((button)=>button.addEventListener('click',()=>{state.draft[button.dataset.policyPickAll]=(state.catalog[button.dataset.catalogKey]||[]).map((item)=>item.value);render();}));
    root.querySelectorAll('[data-policy-picker-search]').forEach((input)=>input.addEventListener('input',()=>{const query=input.value.trim().toLowerCase();input.closest('.policy-object-menu')?.querySelectorAll(':scope > div > label').forEach((row)=>{row.hidden=query&&!row.textContent.toLowerCase().includes(query);});}));
    root.querySelectorAll('[data-policy-bulk]').forEach((button)=>button.addEventListener('click',()=>{const field=button.dataset.policyBulk;if(state.bulkInputs.has(field))state.bulkInputs.delete(field);else state.bulkInputs.add(field);render();}));
    root.querySelectorAll('[data-policy-draft]').forEach((input) => input.addEventListener('input', () => {
      state.draft[input.dataset.policyDraft] = input.type === 'number' ? Number(input.value) : input.value;
      state.notice = '';
      if (input.tagName === 'SELECT' && ['record_type', 'target', 'protocol', 'ttl_mode', 'translated_ip_mode', 'download_unit', 'upload_unit'].includes(input.dataset.policyDraft)) render();
    }));
    root.querySelectorAll('[data-policy-draft-check]').forEach((input) => input.addEventListener('change', () => { state.draft[input.dataset.policyDraftCheck] = input.checked; }));
    root.querySelectorAll('[data-policy-save]').forEach((button) => button.addEventListener('click', savePolicy));
    root.querySelectorAll('[data-policy-edit]').forEach((button) => button.addEventListener('click', () => { if (!state.selectedRow) return; state.draft = draftFromRow(state.selectedRow); state.detailsOpen = false; state.createOpen = true; state.notice = ''; state.confirmDelete = false; render(); }));
    root.querySelectorAll('[data-policy-delete]').forEach((button) => button.addEventListener('click', deletePolicy));
    root.querySelectorAll('[data-policy-toggle]').forEach((button) => button.addEventListener('click', togglePolicy));
    root.querySelectorAll('[data-toggle-section]').forEach((button) => button.addEventListener('click', () => { toggleSet(state.collapsed, button.dataset.toggleSection); render(); }));
    root.querySelectorAll('[data-clear-filters]').forEach((button) => button.addEventListener('click', () => {
      state.query = '';
      state.showDefault = true;
      state.type = 'all';
      Object.values(state.selectedFilters).forEach((set) => set.clear());
      render();
    }));
    root.querySelectorAll('[data-show-default]').forEach((input) => input.addEventListener('change', () => { state.showDefault = input.checked; render(); }));
    root.querySelectorAll('[data-filter-key]').forEach((input) => input.addEventListener('change', () => {
      const key = input.dataset.filterKey;
      const value = normalizeKey(input.value);
      if (key === 'policy_type') state.type = value || 'all';
      else toggleSet(state.selectedFilters[key], value);
      render();
    }));
    root.querySelectorAll('[data-column-toggle]').forEach((input) => input.addEventListener('change', () => {
      if (input.checked) state.visibleColumns.add(input.value);
      else state.visibleColumns.delete(input.value);
      render();
    }));
    bindPolicyTableRows();
    root.querySelectorAll('[data-policy-search], [data-policy-search-drawer]').forEach((input) => input.addEventListener('input', () => {
      window.clearTimeout(searchTimer);
      const value = input.value;
      searchTimer = window.setTimeout(() => {
        state.query = value;
        if (input.matches('[data-policy-search]')) patchPolicyTable();
        else render();
      }, 120);
    }));
  }

  render();
  load();

  return {
    unmount() {
      mounted = false;
      window.clearTimeout(searchTimer);
      if (state.abort) state.abort.abort();
      if (root) root.replaceChildren();
      root?.classList.remove(MODULE_CLASS, 'route-workspace');
    }
  };
}

export default { mount };
