export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const utils = context.utils || {};
  const ui = context.ui || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character])));
  const fetchApi = api.fetch || (async (name, url) => {
    const response = await sessionFetch(url, { credentials: 'same-origin', cache: 'no-store', headers: authHeaders() });
    const json = await response.json().catch(() => ({}));
    return { name, ok: response.ok && json?.ok !== false, data: json?.data ?? json, raw: json };
  });

  const VERSION = '20260802-sheet-portal-scope-01';
  const POLICY_ENDPOINT = '/api/v1/policy-engine/policy-table';
  const ROUTING_ENDPOINT = '/api/v1/routing';
  const RESOURCE_ENDPOINTS = {
    tables: '/api/v1/routing/tables',
    objects: '/api/v1/routing/objects',
    cross: '/api/v1/routing/cross-services',
    runtime: '/api/v1/routing/runtime-resolve',
    external: '/api/v1/routing/external-policies'
  };
  const MODULE_CLASS = 'routing-table-route-host';
  const TABS = [
    ['policies', '路由策略'],
    ['tables', '路由表'],
    ['objects', '路由对象'],
    ['cross', '跨三层服务'],
    ['runtime', '运行解析']
  ];
  const state = {
    tab: 'policies',
    policies: [], tables: [], objects: [], crossServices: [], externalPolicies: [],
    capabilities: {}, source: '', revision: null,
    loading: true, errors: {}, notice: '', query: '',
    drawer: '', editorKind: '', editorMode: '', editor: {}, selected: null,
    confirmDelete: false, saving: false, resolving: false,
    resolveMode: 'table', resolveValue: '', resolution: null,
    mounted: true, seq: 0, pollTimer: 0
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
        const text = firstText(value.message, value.error, value.label, value.name, value.value, value.id);
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
  function asArray(value, keys = ['items', 'rows', 'data']) {
    if (Array.isArray(value)) return value;
    for (const key of keys) if (Array.isArray(value?.[key])) return value[key];
    return [];
  }
  function unwrapResult(result) { return result?.data ?? result?.raw?.data ?? result?.raw ?? result ?? {}; }
  function normalizeKey(value) { return String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_'); }
  function cap(name) { return state.capabilities?.[name] === true; }
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
      credentials: 'same-origin', cache: 'no-store', signal: context.signal, ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw Object.assign(new Error('后端返回了无效 JSON'), { status: response.status }); }
    }
    const payload = json?.data ?? json;
    if (!response.ok || json?.ok === false || payload?.ok === false) {
      throw Object.assign(new Error(firstText(payload?.message, payload?.error, json?.message, json?.error, `HTTP ${response.status}`)), { status: response.status, payload });
    }
    return payload;
  }
  function errorText(error, prefix = '') {
    const payload = error?.payload || {};
    const references = asArray(payload.references).map((item) => firstText(item.name, item.id, item.type)).filter(Boolean);
    const base = firstText(error?.message, payload.message, payload.error, 'unknown');
    return `${prefix}${base}${references.length ? `；仍被 ${references.join('、')} 引用` : ''}`;
  }
  function icon(name) {
    const paths = {
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      edit: '<path d="m4 20 4.2-1 10.9-10.9a2 2 0 0 0-2.8-2.8L5.4 16.2 4 20Z"></path>',
      eye: '<path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z"></path><circle cx="12" cy="12" r="2.5"></circle>',
      route: '<circle cx="6" cy="19" r="2"></circle><circle cx="18" cy="5" r="2"></circle><path d="M8 19h3a4 4 0 0 0 4-4V9m0 0-3 3m3-3 3 3"></path>'
    };
    return `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.edit}</svg>`;
  }
  function statusBadge(label, tone) {
    return ui.statusBadgeMarkup?.(label, tone) || window.DWRT_UI_KIT?.statusBadgeMarkup?.(label, tone) || `<span class="routing-fallback-status is-${escapeHtml(tone)}">${escapeHtml(label)}</span>`;
  }
  function routeType(row = {}) {
    const key = normalizeKey(row.policy_type || row.type_key || row.kind || row.type || row.section_type);
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
  function normalizePolicy(row = {}, index = 0) {
    const type = routeType(row);
    if (!type) return null;
    const rawBase = row.raw && typeof row.raw === 'object' ? row.raw : row;
    const raw = { ...rawBase, ...(rawBase.options && typeof rawBase.options === 'object' ? rawBase.options : {}) };
    const destination = firstText(row.destination_label, row.destination, raw.destination, raw.target, raw.dest_object, raw.dest_ip) || '任意';
    const source = type === 'pbr' ? (firstText(row.source_label, row.source, raw.source_object, raw.src_ip) || '全部终端') : '--';
    const target = type === 'pbr'
      ? firstText(raw.target, raw.wan, raw.route_table, raw.table, row.interface, '--')
      : firstText(raw.gateway, raw.gw, raw.next_hop, firstText(row.interface, raw.interface) ? '直连' : '--');
    return {
      id: firstText(row.id, row._id, row.uuid, raw.id, raw.section) || `route-${index}`,
      type, typeLabel: type === 'pbr' ? '策略路由' : '静态路由',
      name: firstText(row.name, row.label, raw.name, raw.comment, destination) || `路由 ${index + 1}`,
      source, destination, target,
      interface: firstText(row.interface, raw.interface, raw.iface, raw.network, '--'),
      table: firstText(raw.route_table, raw.table, raw.routing_table, type === 'static_route' ? 'main' : target, '--'),
      priority: firstNumber(raw.priority, raw.metric, row.priority, row.metric),
      hits: firstNumber(raw.hit_count, raw.hits, row.hit_count, row.hits),
      lastHit: firstNumber(raw.last_hit, raw.last_hit_at, row.last_hit),
      enabled: row.enabled !== false && raw.enabled !== false && raw.disabled !== '1',
      comment: firstText(raw.comment, raw.remark, row.description), raw: { ...raw, ...row }
    };
  }
  function normalizeTable(item = {}) {
    return { ...item, id: firstText(item.id), name: firstText(item.name, item.id), table_id: firstNumber(item.table_id), metric: firstNumber(item.metric), enabled: item.enabled === true, references: asArray(item.references), ref_count: firstNumber(item.ref_count) };
  }
  function normalizeObject(item = {}) {
    return { ...item, id: firstText(item.id), name: firstText(item.name, item.id), type: firstText(item.type, item.object_type, 'ip_group'), family: firstText(item.family, 'mixed'), enabled: item.enabled === true, members: asArray(item.members), references: asArray(item.references), ref_count: firstNumber(item.ref_count) };
  }
  function normalizeCross(item = {}) {
    return { ...item, id: firstText(item.id), name: firstText(item.name, item.id), service_type: firstText(item.service_type, 'snmp'), enabled: item.enabled === true, runtime_supported: item.runtime_supported === true };
  }
  function applyPayload(key, payload) {
    const data = unwrapResult(payload);
    if (data.capabilities && typeof data.capabilities === 'object') state.capabilities = { ...state.capabilities, ...data.capabilities };
    if (data.revision !== undefined) state.revision = data.revision;
    if (key === 'snapshot') {
      state.source = firstText(data.source, payload?.raw?.meta?.source);
      state.capabilities = data.capabilities && typeof data.capabilities === 'object' ? data.capabilities : {};
      state.revision = data.revision ?? null;
    } else if (key === 'policies') {
      state.policies = asArray(data, ['rows', 'items', 'policies', 'data']).map(normalizePolicy).filter(Boolean);
    } else if (key === 'tables') state.tables = asArray(data).map(normalizeTable).filter((item) => item.id);
    else if (key === 'objects') state.objects = asArray(data).map(normalizeObject).filter((item) => item.id);
    else if (key === 'cross') state.crossServices = asArray(data).map(normalizeCross).filter((item) => item.id);
    else if (key === 'external') state.externalPolicies = asArray(data).map((item) => ({ ...item, read_only: true }));
  }
  async function load() {
    const seq = ++state.seq;
    state.loading = true;
    state.errors = {};
    render();
    const requests = {
      snapshot: fetchApi('routing-snapshot', ROUTING_ENDPOINT),
      policies: fetchApi('routing-policy-table', `${POLICY_ENDPOINT}?include_default=0`),
      tables: fetchApi('routing-tables', RESOURCE_ENDPOINTS.tables),
      objects: fetchApi('routing-objects', RESOURCE_ENDPOINTS.objects),
      cross: fetchApi('routing-cross-services', RESOURCE_ENDPOINTS.cross),
      external: fetchApi('routing-external-policies', RESOURCE_ENDPOINTS.external)
    };
    const entries = Object.entries(requests);
    const results = await Promise.allSettled(entries.map(([, request]) => request));
    if (!state.mounted || seq !== state.seq) return;
    results.forEach((result, index) => {
      const key = entries[index][0];
      if (result.status === 'fulfilled' && result.value?.ok !== false) applyPayload(key, result.value);
      else state.errors[key] = result.status === 'rejected' ? firstText(result.reason?.message, '读取失败') : firstText(result.value?.raw?.message, result.value?.raw?.error, '读取失败');
    });
    state.loading = false;
    render();
  }
  function formatTime(value) {
    const raw = Number(value) || 0;
    if (!raw) return '--';
    const timestamp = raw < 100000000000 ? raw * 1000 : raw;
    return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(timestamp);
  }
  function matchesQuery(values) {
    const query = state.query.trim().toLowerCase();
    return !query || values.join(' ').toLowerCase().includes(query);
  }
  function tabsMarkup() {
    return `<nav class="routing-page-tabs dwrt-kit-tabs" data-dwrt-component="tabs" aria-label="路由管理视图"><span class="dwrt-kit-tab-pill" aria-hidden="true"></span>${TABS.map(([id, label]) => `<button class="dwrt-kit-tab ${state.tab === id ? 'is-active' : ''}" type="button" data-routing-tab="${id}" aria-selected="${state.tab === id}">${label}</button>`).join('')}</nav>`;
  }
  function toolbarMarkup() {
    const creatable = ['tables', 'objects', 'cross'].includes(state.tab);
    const labels = { tables: '新建路由表', objects: '新建路由对象', cross: '新建服务' };
    const capability = { tables: 'table_crud', objects: 'object_crud', cross: 'cross_service_config_crud' }[state.tab];
    return `<header class="routing-page-toolbar"><div class="routing-page-heading"><strong>路由表</strong><span>${state.revision === null ? '路由配置与解析' : `配置版本 ${escapeHtml(state.revision)}`}</span></div>${tabsMarkup()}<div class="routing-page-actions"><label class="routing-search" data-dwrt-component="expand-search">${icon('search')}<input type="search" data-routing-search value="${escapeHtml(state.query)}" placeholder="搜索当前视图" aria-label="搜索当前视图"></label>${creatable ? `<button class="dwrt-kit-button routing-create-button" data-dwrt-component="button" data-variant="primary" type="button" data-routing-create="${state.tab}" ${cap(capability) ? '' : 'disabled'}>${icon('plus')}<span>${labels[state.tab]}</span></button>` : ''}</div></header>`;
  }
  function noticeMarkup(message = state.notice, tone = 'warning') {
    if (!message) return '';
    return `<div class="routing-notice is-${tone}" role="status">${escapeHtml(message)}</div>`;
  }
  function capabilityBanner(message, tone = 'warning') {
    return `<section class="routing-capability-banner is-${tone}" data-dwrt-component="state-panel"><strong>${tone === 'danger' ? '功能不可用' : '能力说明'}</strong><span>${escapeHtml(message)}</span></section>`;
  }
  function tableShell(title, meta, headings, rows, empty, className = '') {
    return `<section class="routing-resource-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface ${className}" data-dwrt-component="data-table"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(meta)}</span></div></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table"><thead><tr>${headings.map((heading) => `<th>${escapeHtml(heading)}</th>`).join('')}</tr></thead><tbody>${state.loading ? `<tr><td class="dwrt-kit-table-empty" colspan="${headings.length}">正在读取真实配置</td></tr>` : rows.length ? rows.join('') : `<tr><td class="dwrt-kit-table-empty" colspan="${headings.length}">${escapeHtml(empty)}</td></tr>`}</tbody></table></div></section>`;
  }
  function actionButton(kind, item, readOnly = false) {
    return `<button class="routing-row-action" type="button" data-routing-open="${escapeHtml(kind)}" data-routing-id="${escapeHtml(item.id)}" aria-label="${readOnly ? '查看' : '编辑'} ${escapeHtml(item.name)}">${icon(readOnly ? 'eye' : 'edit')}</button>`;
  }
  function policiesMarkup() {
    const rows = state.policies.filter((item) => matchesQuery([item.name, item.typeLabel, item.source, item.destination, item.target, item.interface, item.table])).map((item) => `<tr class="${item.enabled ? '' : 'is-disabled'}"><td>${statusBadge(item.enabled ? '启用' : '停用', item.enabled ? 'success' : 'muted')}</td><td><span class="routing-kind is-${item.type}">${escapeHtml(item.typeLabel)}</span></td><td><strong>${escapeHtml(item.name)}</strong>${item.comment ? `<small>${escapeHtml(item.comment)}</small>` : ''}</td><td>${escapeHtml(item.source)}</td><td>${escapeHtml(item.destination)}</td><td>${escapeHtml(item.target)}</td><td>${escapeHtml(item.interface)}</td><td><span class="routing-table-pill">${escapeHtml(item.table)}</span></td><td>${item.priority || '--'}</td><td>${item.type === 'pbr' ? item.hits : '--'}</td><td>${item.type === 'pbr' ? escapeHtml(formatTime(item.lastHit)) : '--'}</td><td>${actionButton('policy', item, true)}</td></tr>`);
    return `${capabilityBanner('静态路由与 PBR 在此仅作统一索引；创建、修改和删除继续由“策略表”作为唯一写入口。', 'info')}${state.errors.policies ? capabilityBanner(`路由策略读取失败：${state.errors.policies}`, 'danger') : ''}${tableShell('路由策略', `${rows.length} 条 · 只读索引`, ['状态', '类型', '名称', '源', '目标网络', '下一跳 / 目标', '接口', '路由表', '跃点 / 优先级', '命中', '最后命中', '详情'], rows, state.errors.policies || '没有路由策略', 'is-policy-table')}`;
  }
  function tablesMarkup() {
    const writable = cap('table_crud');
    const items = state.tables.filter((item) => matchesQuery([item.id, item.name, item.role, item.gateway, item.table_id]));
    const rows = items.map((item) => `<tr class="${item.enabled ? '' : 'is-disabled'}"><td>${statusBadge(item.enabled ? '启用' : '停用', item.enabled ? 'success' : 'muted')}</td><td><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.id)}</small></td><td>${item.table_id}</td><td>${escapeHtml(item.role || '--')}</td><td>${escapeHtml(item.gateway || '--')}</td><td>${item.metric}</td><td>${item.ref_count}</td><td>${actionButton('table', item, !writable)}</td></tr>`);
    return `${!writable ? capabilityBanner('后端未明确声明 table_crud，路由表保持只读。', 'danger') : ''}${state.errors.tables ? capabilityBanner(`路由表读取失败：${state.errors.tables}`, 'danger') : ''}${tableShell('自定义路由表', `${items.length} 个 · ${writable ? '真实 CRUD' : '只读'}`, ['状态', '名称 / ID', 'Table ID', '角色', '网关', 'Metric', '引用', '操作'], rows, state.errors.tables || '没有自定义路由表')}`;
  }
  function objectsMarkup() {
    const writable = cap('object_crud');
    const items = state.objects.filter((item) => matchesQuery([item.id, item.name, item.type, item.family, item.value, item.comment, ...item.members.map((member) => firstText(member.value, member.label))]));
    const rows = items.map((item) => `<tr class="${item.enabled ? '' : 'is-disabled'}"><td>${statusBadge(item.enabled ? '启用' : '停用', item.enabled ? 'success' : 'muted')}</td><td><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.id)}</small></td><td>${escapeHtml(item.type)}</td><td>${escapeHtml(item.family)}</td><td><span class="routing-cell-ellipsis" title="${escapeHtml(item.value || '')}">${escapeHtml(item.value || '--')}</span></td><td>${item.members.length}</td><td>${item.ref_count}</td><td>${actionButton('object', item, !writable)}</td></tr>`);
    return `${capabilityBanner('这里的对象只属于路由子系统，不冒充跨防火墙、SQM 与 flowd 的通用策略对象。', 'info')}${!writable ? capabilityBanner('后端未明确声明 object_crud，路由对象保持只读。', 'danger') : ''}${state.errors.objects ? capabilityBanner(`路由对象读取失败：${state.errors.objects}`, 'danger') : ''}${tableShell('路由对象', `${items.length} 个 · ${writable ? '真实 CRUD' : '只读'}`, ['状态', '名称 / ID', '类型', '地址族', '值', '成员', '引用', '操作'], rows, state.errors.objects || '没有路由对象')}`;
  }
  function crossMarkup() {
    const writable = cap('cross_service_config_crud');
    const runtime = cap('cross_service_runtime');
    const reason = firstText(state.capabilities.cross_service_runtime_reason, 'runtime_consumer_not_implemented');
    const items = state.crossServices.filter((item) => matchesQuery([item.id, item.name, item.service_type, item.server_ip, item.scope, item.listen_port, item.version, item.remark]));
    const rows = items.map((item) => `<tr class="${item.enabled ? '' : 'is-disabled'}"><td>${statusBadge(item.enabled ? '启用' : '停用', item.enabled ? 'success' : 'muted')}</td><td><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.id)}</small></td><td>${escapeHtml(item.service_type)}</td><td>${escapeHtml(item.server_ip || '--')}</td><td>${escapeHtml(item.scope || '--')}</td><td>${escapeHtml(item.listen_port || '--')}</td><td>${runtime && item.runtime_supported ? statusBadge('运行已接入', 'success') : statusBadge('仅配置', 'warning')}</td><td>${actionButton('cross', item, !writable)}</td></tr>`);
    return `${!runtime ? capabilityBanner(`配置可以保存，但运行消费者尚未实现（${reason}）；页面不会把“保存成功”显示为服务已生效。`, 'warning') : ''}${!writable ? capabilityBanner('后端未明确声明 cross_service_config_crud，跨三层服务保持只读。', 'danger') : ''}${state.errors.cross ? capabilityBanner(`跨三层服务读取失败：${state.errors.cross}`, 'danger') : ''}${tableShell('跨三层服务', `${items.length} 项 · ${runtime ? '配置与运行' : '配置态'}`, ['状态', '名称 / ID', '服务类型', '服务器', '作用域', '监听端口', '运行态', '操作'], rows, state.errors.cross || '没有跨三层服务')}`;
  }
  function resolutionMarkup() {
    if (!state.resolution) return '<div class="routing-runtime-empty">选择路由表或策略规则后执行解析。</div>';
    const item = state.resolution;
    return `<dl class="routing-resolution-grid"><div><dt>解析结果</dt><dd>${statusBadge(item.resolved ? '已解析' : '未解析', item.resolved ? 'success' : 'error')}</dd></div><div><dt>动作</dt><dd>${escapeHtml(item.action || '--')}</dd></div><div><dt>路由表</dt><dd>${escapeHtml(item.route_table || '--')}</dd></div><div><dt>Table ID</dt><dd>${item.table_id || '--'}</dd></div><div><dt>网关</dt><dd>${escapeHtml(item.gateway || '--')}</dd></div><div><dt>接口</dt><dd>${escapeHtml(item.interface || '--')}</dd></div><div class="is-wide"><dt>解析原因</dt><dd>${escapeHtml(item.reason || '--')}</dd></div><div class="is-wide"><dt>验证边界</dt><dd>${escapeHtml(item.runtime_validation || '--')}</dd></div></dl>`;
  }
  function runtimeMarkup() {
    const canResolve = cap('runtime_resolve');
    const pbr = state.policies.filter((item) => item.type === 'pbr');
    const options = state.resolveMode === 'rule' ? pbr.map((item) => [item.id, item.name]) : [['main', 'main (254)'], ...state.tables.map((item) => [item.id, `${item.name} (${item.table_id})`])];
    const external = state.externalPolicies.filter((item) => matchesQuery([item.id, item.name, item.source, item.section_type, item.path]));
    const rows = external.map((item) => `<tr><td><strong>${escapeHtml(item.name || item.id)}</strong><small>${escapeHtml(item.id)}</small></td><td>${escapeHtml(item.source || '--')}</td><td>${escapeHtml(item.section_type || '--')}</td><td><span class="routing-cell-ellipsis" title="${escapeHtml(item.path || '')}">${escapeHtml(item.path || '--')}</span></td><td>${statusBadge('只读', 'muted')}</td></tr>`);
    return `<section class="routing-runtime-layout"><section class="routing-runtime-panel" data-dwrt-component="surface"><header><div><strong>运行解析</strong><span>验证配置如何解析到路由表</span></div>${statusBadge(canResolve ? '可用' : '不可用', canResolve ? 'success' : 'error')}</header>${!canResolve ? capabilityBanner('后端未明确声明 runtime_resolve，解析入口已关闭。', 'danger') : ''}<div class="routing-resolve-controls"><label><span>解析方式</span><select data-routing-resolve-mode ${canResolve ? '' : 'disabled'}><option value="table" ${state.resolveMode === 'table' ? 'selected' : ''}>按路由表</option><option value="rule" ${state.resolveMode === 'rule' ? 'selected' : ''}>按策略规则</option></select></label><label><span>${state.resolveMode === 'rule' ? '策略规则' : '路由表'}</span><select data-routing-resolve-value ${canResolve ? '' : 'disabled'}><option value="">请选择</option>${options.map(([value, label]) => `<option value="${escapeHtml(value)}" ${state.resolveValue === value ? 'selected' : ''}>${escapeHtml(label)}</option>`).join('')}</select></label><button class="dwrt-kit-button" data-dwrt-component="async-button" data-variant="primary" type="button" data-routing-resolve ${canResolve && state.resolveValue && !state.resolving ? '' : 'disabled'}>${state.resolving ? '正在解析' : '执行解析'}</button></div>${resolutionMarkup()}${capabilityBanner('解析结果是配置级解析，不代表逐 flow 的 conntrack 命中或实际选路证明。', 'info')}</section>${state.errors.external ? capabilityBanner(`外部策略读取失败：${state.errors.external}`, 'danger') : ''}${tableShell('外部策略', `${external.length} 条 · pbr / mwan3 只读发现`, ['名称 / ID', '来源', '类型', '配置路径', '权限'], rows, state.errors.external || '没有发现外部策略', 'is-external-table')}</section>`;
  }
  function contentMarkup() {
    if (state.tab === 'tables') return tablesMarkup();
    if (state.tab === 'objects') return objectsMarkup();
    if (state.tab === 'cross') return crossMarkup();
    if (state.tab === 'runtime') return runtimeMarkup();
    return policiesMarkup();
  }
  function field(label, name, value, options = {}) {
    const attributes = `${options.disabled ? 'disabled' : ''} ${options.required ? 'required' : ''}`;
    let control;
    if (options.type === 'select') control = `<select data-routing-field="${name}" ${attributes}>${options.options.map(([key, text]) => `<option value="${escapeHtml(key)}" ${String(value) === String(key) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select>`;
    else if (options.type === 'textarea') control = `<textarea data-routing-field="${name}" rows="${options.rows || 5}" placeholder="${escapeHtml(options.placeholder || '')}" ${attributes}>${escapeHtml(value ?? '')}</textarea>`;
    else control = `<input type="${options.type || 'text'}" data-routing-field="${name}" value="${escapeHtml(value ?? '')}" placeholder="${escapeHtml(options.placeholder || '')}" ${options.min !== undefined ? `min="${options.min}"` : ''} ${options.max !== undefined ? `max="${options.max}"` : ''} ${attributes}>`;
    return `<label class="routing-field ${options.wide ? 'is-wide' : ''}"><span>${escapeHtml(label)}</span>${control}</label>`;
  }
  function switchField(label, description, checked, disabled = false) {
    return `<label class="routing-switch" data-dwrt-component="switch"><span><strong>${escapeHtml(label)}</strong><small>${escapeHtml(description)}</small></span><input type="checkbox" data-routing-field-check="enabled" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}><i></i></label>`;
  }
  function editorFieldsMarkup() {
    const editor = state.editor;
    const editing = state.editorMode === 'edit';
    if (state.editorKind === 'table') return `${switchField('启用路由表', '保存后触发 route_reload，并回读事务结果', editor.enabled)}<div class="routing-form">${field('资源 ID', 'id', editor.id, { required: true, disabled: editing, placeholder: '例如 wan2_table' })}${field('显示名称', 'name', editor.name, { required: true })}${field('Table ID', 'table_id', editor.table_id, { type: 'number', min: 1, max: 32767, required: true })}${field('角色', 'role', editor.role, { placeholder: 'wan / vpn / custom' })}${field('默认网关', 'gateway', editor.gateway, { placeholder: '可留空' })}${field('Metric', 'metric', editor.metric, { type: 'number' })}</div>`;
    if (state.editorKind === 'object') return `${switchField('启用路由对象', '对象仅供 routed 子系统引用', editor.enabled)}<div class="routing-form">${field('资源 ID', 'id', editor.id, { required: true, disabled: editing, placeholder: '例如 office_targets' })}${field('显示名称', 'name', editor.name, { required: true })}${field('类型', 'type', editor.type, { type: 'select', options: [['ip_group', 'IP / CIDR 组'], ['domain_group', '域名组'], ['interface_group', '接口组'], ['custom', '自定义']] })}${field('地址族', 'family', editor.family, { type: 'select', options: [['ipv4', 'IPv4'], ['ipv6', 'IPv6'], ['mixed', '混合']] })}${field('主值', 'value', editor.value, { wide: true, placeholder: '单个值或摘要，可留空' })}${field('成员（每行一个）', 'membersText', editor.membersText, { type: 'textarea', rows: 7, wide: true, placeholder: '192.0.2.0/24\n198.51.100.10' })}${field('备注', 'comment', editor.comment, { wide: true })}</div>`;
    const multicast = ['mdns', 'ssdp'].includes(normalizeKey(editor.service_type));
    return `${switchField('启用配置', '保存配置不等于运行服务已生效', editor.enabled)}${!cap('cross_service_runtime') ? capabilityBanner('运行消费者未实现；本编辑器只维护配置。', 'warning') : ''}${multicast ? capabilityBanner('mDNS / SSDP 的实际组播运行配置由“组播服务”拥有，此处仅保存跨三层引用配置。', 'info') : ''}<div class="routing-form">${field('资源 ID', 'id', editor.id, { required: true, disabled: editing, placeholder: '例如 office_snmp' })}${field('显示名称', 'name', editor.name, { required: true })}${field('服务类型', 'service_type', editor.service_type, { type: 'select', options: [['snmp', 'SNMP'], ['mdns', 'mDNS 引用'], ['ssdp', 'SSDP 引用'], ['custom', '自定义']] })}${field('服务器 IP', 'server_ip', editor.server_ip, { placeholder: '可按服务类型留空' })}${field('作用域', 'scope', editor.scope, { wide: true, placeholder: '网段、区域或接口范围' })}${field('监听端口', 'listen_port', editor.listen_port)}${field('版本', 'version', editor.version)}${field('访问频率', 'access_rate', editor.access_rate)}${field('备注', 'remark', editor.remark, { wide: true })}</div>`;
  }
  function drawerTitle() {
    const labels = { table: '路由表', object: '路由对象', cross: '跨三层服务', policy: '路由策略详情' };
    return `${state.editorMode === 'create' ? '新建' : state.editorKind === 'policy' ? '' : '编辑'}${labels[state.editorKind] || ''}`;
  }
  function drawerMarkup() {
    if (!state.drawer) return '';
    const readOnly = state.editorKind === 'policy' || !editorWritable();
    return `${drawerBackdrop('关闭编辑器')}<aside class="routing-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" aria-label="${escapeHtml(drawerTitle())}"><header class="dwrt-kit-sheet-header"><div><span>ROUTING</span><strong>${escapeHtml(drawerTitle())}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-routing-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body routing-drawer-body">${state.editorKind === 'policy' ? policyDetailMarkup() : editorFieldsMarkup()}${state.notice ? noticeMarkup(state.notice, /失败|冲突|引用|错误/.test(state.notice) ? 'danger' : 'warning') : ''}${readOnly && state.editorKind !== 'policy' ? capabilityBanner('写能力未由后端明确开放，当前详情保持只读。', 'danger') : ''}</div><footer class="dwrt-kit-sheet-footer routing-sheet-footer">${state.editorMode === 'edit' && state.editorKind !== 'policy' && !readOnly ? `<button class="dwrt-kit-button routing-danger-button" data-dwrt-component="button" data-variant="danger" type="button" data-routing-delete ${state.saving ? 'disabled' : ''}>删除</button>` : '<span></span>'}<div><button class="dwrt-kit-button" data-dwrt-component="button" data-variant="ghost" type="button" data-routing-close>${readOnly ? '关闭' : '取消'}</button>${!readOnly ? `<button class="dwrt-kit-button" data-dwrt-component="async-button" data-variant="primary" type="button" data-routing-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存'}</button>` : ''}</div></footer></aside>`;
  }
  function policyDetailMarkup() {
    const item = state.selected || {};
    return `${capabilityBanner('此处仅展示统一路由索引。请在“策略表”中修改或删除该路由，避免双写。', 'info')}<dl class="routing-detail-list"><div><dt>名称</dt><dd>${escapeHtml(item.name || '--')}</dd></div><div><dt>类型</dt><dd>${escapeHtml(item.typeLabel || '--')}</dd></div><div><dt>状态</dt><dd>${item.enabled ? '启用' : '停用'}</dd></div><div><dt>源</dt><dd>${escapeHtml(item.source || '--')}</dd></div><div><dt>目标</dt><dd>${escapeHtml(item.destination || '--')}</dd></div><div><dt>下一跳 / 目标</dt><dd>${escapeHtml(item.target || '--')}</dd></div><div><dt>接口</dt><dd>${escapeHtml(item.interface || '--')}</dd></div><div><dt>路由表</dt><dd>${escapeHtml(item.table || '--')}</dd></div></dl>`;
  }
  function drawerBackdrop(label) { return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-routing-close aria-label="${escapeHtml(label)}"></button>`; }
  function editorWritable() {
    return (state.editorKind === 'table' && cap('table_crud')) || (state.editorKind === 'object' && cap('object_crud')) || (state.editorKind === 'cross' && cap('cross_service_config_crud'));
  }
  function confirmationMarkup() {
    if (!state.confirmDelete || !state.selected) return '';
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    if (typeof renderer !== 'function') return '';
    const references = asArray(state.selected.references);
    const label = { table: '路由表', object: '路由对象', cross: '跨三层服务' }[state.editorKind] || '资源';
    return renderer({
      id: 'routing-delete-confirmation', action: 'delete-routing-resource', tone: 'danger',
      title: `删除${label}`,
      description: references.length ? `${label}“${state.selected.name}”仍有 ${references.length} 个已知引用；后端将执行最终冲突校验。` : `${label}“${state.selected.name}”将被永久删除。`,
      cancelLabel: '取消', confirmLabel: state.saving ? '正在删除' : '确认删除', disabled: state.saving
    });
  }
  function render() {
    if (!root) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', MODULE_CLASS);
    root.innerHTML = `<section class="routing-table-shell" data-routing-version="${VERSION}">${toolbarMarkup()}<main class="routing-workbench">${state.notice && !state.drawer ? noticeMarkup() : ''}${contentMarkup()}</main>${drawerMarkup()}${confirmationMarkup()}</section>`;
    bindEvents();
    ui.mountAll?.(root);
  }
  function defaultEditor(kind) {
    if (kind === 'table') return { id: '', name: '', table_id: '', role: '', gateway: '', metric: 0, enabled: true };
    if (kind === 'object') return { id: '', name: '', type: 'ip_group', family: 'mixed', value: '', membersText: '', comment: '', enabled: true };
    return { id: '', name: '', service_type: 'snmp', server_ip: '', scope: '', listen_port: '161', version: 'V2', access_rate: '', remark: '', enabled: true };
  }
  function editorFromItem(kind, item) {
    if (kind === 'object') return { ...item, membersText: item.members.map((member) => firstText(member.value, member.label)).join('\n') };
    return { ...item };
  }
  function openCreate(kind) {
    const map = { tables: 'table', objects: 'object', cross: 'cross' };
    const editorKind = map[kind];
    if (!editorKind) return;
    state.drawer = 'editor'; state.editorKind = editorKind; state.editorMode = 'create'; state.selected = null; state.editor = defaultEditor(editorKind); state.notice = ''; render();
  }
  function openItem(kind, id) {
    const source = kind === 'policy' ? state.policies : kind === 'table' ? state.tables : kind === 'object' ? state.objects : state.crossServices;
    const item = source.find((entry) => entry.id === id);
    if (!item) return;
    state.drawer = 'editor'; state.editorKind = kind; state.editorMode = 'edit'; state.selected = item; state.editor = editorFromItem(kind, item); state.notice = ''; render();
  }
  function closeDrawer() {
    state.drawer = ''; state.editorKind = ''; state.editorMode = ''; state.editor = {}; state.selected = null; state.confirmDelete = false; state.notice = ''; render();
  }
  function validateEditor() {
    const editor = state.editor;
    if (!String(editor.id || '').trim() || !String(editor.name || '').trim()) return '资源 ID 和显示名称不能为空。';
    if (state.editorKind === 'table') {
      const tableId = Number(editor.table_id);
      if (!Number.isInteger(tableId) || tableId < 1 || tableId > 32767 || [253, 254, 255].includes(tableId)) return 'Table ID 必须为 1..32767 的自定义编号，且不能使用 253、254、255。';
    }
    if (state.editorKind === 'object' && !['ipv4', 'ipv6', 'mixed'].includes(editor.family)) return '请选择有效的地址族。';
    return '';
  }
  function editorPayload() {
    const editor = state.editor;
    if (state.editorKind === 'table') return { id: String(editor.id).trim(), name: String(editor.name).trim(), table_id: Number(editor.table_id), role: String(editor.role || '').trim(), gateway: String(editor.gateway || '').trim(), metric: Number(editor.metric) || 0, enabled: Boolean(editor.enabled) };
    if (state.editorKind === 'object') return { id: String(editor.id).trim(), name: String(editor.name).trim(), type: editor.type || 'ip_group', family: editor.family || 'mixed', value: String(editor.value || '').trim(), members: String(editor.membersText || '').split(/\r?\n/).map((value) => value.trim()).filter(Boolean).map((value) => ({ value, label: value })), comment: String(editor.comment || '').trim(), enabled: Boolean(editor.enabled) };
    return { id: String(editor.id).trim(), name: String(editor.name).trim(), service_type: editor.service_type || 'snmp', server_ip: String(editor.server_ip || '').trim(), scope: String(editor.scope || '').trim(), listen_port: String(editor.listen_port || '').trim(), version: String(editor.version || '').trim(), access_rate: String(editor.access_rate || '').trim(), remark: String(editor.remark || '').trim(), enabled: Boolean(editor.enabled) };
  }
  async function saveEditor() {
    if (!editorWritable() || state.saving) return;
    const validation = validateEditor();
    if (validation) { state.notice = validation; render(); return; }
    const endpoint = state.editorKind === 'table' ? RESOURCE_ENDPOINTS.tables : state.editorKind === 'object' ? RESOURCE_ENDPOINTS.objects : RESOURCE_ENDPOINTS.cross;
    state.saving = true; state.notice = ''; render();
    try {
      await requestJson(endpoint, { method: state.editorMode === 'create' ? 'POST' : 'PUT', body: JSON.stringify(editorPayload()) });
      state.saving = false; state.drawer = ''; state.editorKind = ''; state.selected = null; state.notice = '配置已保存，并以后端返回的事务结果为准。';
      await load();
    } catch (error) {
      state.saving = false; state.notice = errorText(error, '保存失败：'); render();
    }
  }
  async function deleteEditor() {
    if (!state.selected || !editorWritable() || state.saving || !state.confirmDelete) return;
    const endpoint = state.editorKind === 'table' ? RESOURCE_ENDPOINTS.tables : state.editorKind === 'object' ? RESOURCE_ENDPOINTS.objects : RESOURCE_ENDPOINTS.cross;
    state.saving = true; render();
    try {
      await requestJson(`${endpoint}/${encodeURIComponent(state.selected.id)}`, { method: 'DELETE' });
      state.saving = false; state.confirmDelete = false; state.drawer = ''; state.editorKind = ''; state.selected = null; state.notice = '资源已删除。';
      await load();
    } catch (error) {
      state.saving = false; state.confirmDelete = false; state.notice = errorText(error, '删除失败：'); render();
    }
  }
  async function resolveRuntime() {
    if (!cap('runtime_resolve') || !state.resolveValue || state.resolving) return;
    state.resolving = true; state.notice = ''; render();
    try {
      state.resolution = await requestJson(RESOURCE_ENDPOINTS.runtime, { method: 'POST', body: JSON.stringify(state.resolveMode === 'rule' ? { rule_id: state.resolveValue } : { route_table: state.resolveValue }) });
      state.resolving = false; render();
    } catch (error) {
      state.resolving = false; state.resolution = null; state.notice = errorText(error, '解析失败：'); render();
    }
  }
  function bindEvents() {
    root.querySelectorAll('[data-routing-tab]').forEach((button) => button.addEventListener('click', () => { state.tab = button.dataset.routingTab; state.query = ''; state.notice = ''; render(); }));
    root.querySelectorAll('[data-routing-create]').forEach((button) => button.addEventListener('click', () => openCreate(button.dataset.routingCreate)));
    root.querySelectorAll('[data-routing-open]').forEach((button) => button.addEventListener('click', () => openItem(button.dataset.routingOpen, button.dataset.routingId)));
    root.querySelectorAll('[data-routing-close]').forEach((button) => button.addEventListener('click', closeDrawer));
    root.querySelectorAll('[data-routing-field]').forEach((input) => input.addEventListener('input', () => { state.editor[input.dataset.routingField] = input.type === 'number' ? Number(input.value) : input.value; state.notice = ''; }));
    root.querySelectorAll('[data-routing-field-check]').forEach((input) => input.addEventListener('change', () => { state.editor[input.dataset.routingFieldCheck] = input.checked; }));
    root.querySelectorAll('[data-routing-save]').forEach((button) => button.addEventListener('click', saveEditor));
    root.querySelectorAll('[data-routing-delete]').forEach((button) => button.addEventListener('click', () => { state.confirmDelete = true; render(); }));
    root.querySelectorAll('[data-dwrt-confirm-cancel]').forEach((button) => button.addEventListener('click', () => { state.confirmDelete = false; render(); }));
    root.querySelectorAll('[data-dwrt-confirm-accept]').forEach((button) => button.addEventListener('click', deleteEditor));
    root.querySelectorAll('[data-routing-resolve-mode]').forEach((select) => select.addEventListener('change', () => { state.resolveMode = select.value; state.resolveValue = ''; state.resolution = null; render(); }));
    root.querySelectorAll('[data-routing-resolve-value]').forEach((select) => select.addEventListener('change', () => { state.resolveValue = select.value; state.resolution = null; render(); }));
    root.querySelectorAll('[data-routing-resolve]').forEach((button) => button.addEventListener('click', resolveRuntime));
    root.querySelectorAll('[data-routing-search]').forEach((input) => input.addEventListener('input', () => {
      window.clearTimeout(searchTimer);
      const value = input.value;
      searchTimer = window.setTimeout(() => { state.query = value; render(); root.querySelector('[data-routing-search]')?.focus(); }, 100);
    }));
  }

  render();
  load();

  /*
   * 手动刷新按钮按用户第 9 条删除，补一条可见性受控的轮询代替；
   * 抽屉打开、正在保存或有未提交草稿时跳过，避免刷掉用户填的内容。
   */
  state.pollTimer = window.setInterval(() => {
    if (!state.mounted || document.hidden) return;
    if (state.loading || state.saving || state.resolving) return;
    if (state.drawer) return;
    load();
  }, 20000);
  return {
    unmount() {
      state.mounted = false; state.seq += 1; window.clearTimeout(searchTimer); window.clearInterval(state.pollTimer);
      root?.replaceChildren(); root?.classList.remove(MODULE_CLASS, 'route-workspace');
    }
  };
}
