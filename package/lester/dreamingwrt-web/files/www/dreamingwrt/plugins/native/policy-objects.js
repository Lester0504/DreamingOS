const SOURCE_TABS = [
  ['composite', '复合策略对象'],
  ['routing', '路由对象'],
  ['flowObjects', '流量对象'],
  ['flowd', '自定义协议']
];

const sourceList = (value, keys = []) => {
  if (Array.isArray(value)) return value;
  for (const key of keys) {
    if (Array.isArray(value?.[key])) return value[key];
  }
  return [];
};

const sourceText = (...values) => values.map((value) => String(value ?? '').trim()).find(Boolean) || '';

export function normalizePolicyObjects(payload = {}) {
  const normalize = (item = {}, index = 0, legacy = false) => ({
    id: sourceText(item.id, `${legacy ? 'legacy' : 'object'}-${index + 1}`),
    name: sourceText(item.name, item.label, `对象 ${index + 1}`),
    type: sourceText(item.object_type, item.type, legacy ? 'route_object' : 'composite'),
    family: sourceText(item.family, 'mixed'),
    value: sourceText(item.value),
    comment: sourceText(item.comment),
    enabled: item.enabled !== false,
    updatedAt: Number(item.updated_at) || 0,
    legacy
  });
  const capabilities = payload.capabilities && typeof payload.capabilities === 'object' ? payload.capabilities : {};
  return {
    items: sourceList(payload.items).map((item, index) => normalize(item, index)),
    legacy: sourceList(payload.legacy_route_objects).map((item, index) => normalize(item, index, true)),
    blockedBy: sourceList(payload.blocked_by).map(String),
    readOnly: payload.read_only === true || capabilities.objects_crud !== true || capabilities.objects_atomic_apply !== true,
    capabilities,
    source: sourceText(payload.source, 'webd.policy_engine.objects')
  };
}

export function normalizeRoutingObjects(payload = {}) {
  const data = payload?.data && typeof payload.data === 'object' ? payload.data : payload;
  const capabilities = data?.capabilities && typeof data.capabilities === 'object' ? data.capabilities : {};
  return {
    items: sourceList(data, ['items', 'route_objects']).map((item = {}, index) => ({
      id: sourceText(item.id, `route-object-${index + 1}`),
      name: sourceText(item.name, item.label, `路由对象 ${index + 1}`),
      type: sourceText(item.type, item.object_type, 'ip_group'),
      family: sourceText(item.family, 'mixed'),
      value: sourceText(item.value),
      comment: sourceText(item.comment),
      enabled: item.enabled !== false,
      updatedAt: Number(item.updated_at) || 0,
      members: sourceList(item.members).map((member) => ({
        value: sourceText(member?.value, member),
        label: sourceText(member?.label)
      })).filter((member) => member.value),
      refCount: Number(item.ref_count) || 0,
      references: sourceList(item.references)
    })),
    source: sourceText(data?.source, 'dreamingwrt.routed'),
    revision: Number(data?.revision) || 0,
    capabilities,
    readOnly: true
  };
}

export function normalizeFlowdCustomProtocols(payload = {}) {
  const data = payload?.data && typeof payload.data === 'object' ? payload.data : payload;
  return {
    items: sourceList(data, ['protocols']).map((item = {}, index) => ({
      id: sourceText(item.id, `custom-protocol-${index + 1}`),
      name: sourceText(item.name, `自定义协议 ${index + 1}`),
      kind: sourceText(item.kind, 'l4'),
      proto: sourceText(item.proto, 'any'),
      srcPort: sourceText(item.src_port),
      dstPort: sourceText(item.dst_port),
      match: item.match && typeof item.match === 'object' ? item.match : {},
      tags: sourceList(item.tags).map(String),
      remark: sourceText(item.remark),
      priority: Number(item.priority) || 0,
      enabled: item.enabled !== false,
      updatedAt: Number(item.updated_at) || 0
    })),
    source: sourceText(data?.source, 'dreamingwrt.flowd'),
    total: Number(data?.total) || sourceList(data, ['protocols']).length,
    readOnly: true
  };
}

export function normalizeFlowdObjects(payload = {}) {
  const data = payload?.data && typeof payload.data === 'object' ? payload.data : payload;
  return {
    items: sourceList(data, ['objects']).map((item = {}, index) => ({
      id: sourceText(item.id, `flow-object-${index + 1}`),
      name: sourceText(item.name, `流量对象 ${index + 1}`),
      type: sourceText(item.type, 'object'),
      enabled: item.enabled !== false,
      value: item.value ?? [],
      valueCount: Number(item.value_count) || 0,
      runtimeKind: sourceText(item.runtime_kind, 'object_set'),
      remark: sourceText(item.remark),
      updatedAt: Number(item.updated_at) || 0,
      refCount: Number(item.reference_count) || 0,
      deleteLocked: item.delete_locked === true,
      references: sourceList(item.referenced_by).map((reference = {}) => ({
        kind: sourceText(reference.kind, 'rule'),
        id: sourceText(reference.id),
        name: sourceText(reference.name, reference.id, '未命名引用'),
        field: sourceText(reference.field),
        enabled: reference.enabled !== false
      }))
    })),
    source: sourceText(data?.source, 'dreamingwrt.flowd'),
    total: Number(data?.total) || sourceList(data, ['objects']).length,
    readOnly: true
  };
}

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const registry = context.registry;
  const api = context.api || {};
  const ui = context.ui || {};
  const signal = context.signal;
  const escapeHtml = context.utils?.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const state = {
    mounted: true,
    tab: 'composite',
    snapshot: null,
    composite: null,
    refreshing: false,
    refreshQueued: false,
    refreshPromise: null,
    detail: null,
    source: {
      routing: { status: 'loading', data: null, error: null },
      flowObjects: { status: 'loading', data: null, error: null },
      flowd: { status: 'loading', data: null, error: null }
    }
  };
  const pageHost = document.createElement('div');
  const overlayHost = document.createElement('div');
  pageHost.className = 'policy-entity-page-host';
  overlayHost.className = 'policy-entity-overlay-host';
  const icon = (name) => window.DWRT_UI_KIT?.lucideIcon?.(name, { size: 18, strokeWidth: 1.8 }) || '';
  const statusBadge = (label, tone = 'muted') => ui.statusBadgeMarkup?.(label, tone) || `<span>${escapeHtml(label)}</span>`;
  const statePanel = (name, title, detail) => `<section data-dwrt-component="state-panel" data-dwrt-state="${name}"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(detail)}</p></section>`;
  const button = (label, attributes = '', variant = 'secondary', iconName = '') => `<button type="button" data-dwrt-component="button" data-variant="${variant}" ${attributes}>${iconName ? icon(iconName) : ''}<span>${escapeHtml(label)}</span></button>`;

  function compositeBlockReason() {
    const reason = state.composite?.capabilities?.objects_write_blocked_reason || state.composite?.blockedBy?.[0] || '';
    const labels = {
      composite_object_schema_pending: '复合对象的数据模型尚未完成',
      cross_component_firewall_pbr_sqm_flowd_transaction_pending: '跨防火墙、路由、QoS 与流量引擎的原子事务尚未闭环'
    };
    return labels[reason] || '后端尚未开放复合对象的原子写入能力';
  }

  function compositeTerminal() {
    const snapshot = state.snapshot;
    if (!registry) return { name: 'unavailable', title: '复合对象合同不可用', detail: '当前页面没有获得共享 DataRegistry。' };
    if (!snapshot || (['empty', 'loading'].includes(snapshot.status) && snapshot.value === undefined)) return { name: 'loading', title: '正在读取复合对象', detail: '等待策略对象权威快照。' };
    if (snapshot.status === 'forbidden' && snapshot.value === undefined) return { name: 'forbidden', title: '无权读取复合对象', detail: '当前账号没有策略对象的读取权限。' };
    if (['error', 'unavailable'].includes(snapshot.status) && snapshot.value === undefined) return { name: snapshot.status, title: '无法读取复合对象', detail: snapshot.error?.message || '对象接口当前不可用。' };
    if (!state.composite) return { name: 'loading', title: '正在读取复合对象', detail: '策略对象快照尚未包含可确认的数据。' };
    return null;
  }

  function sourceTerminal(key) {
    const source = state.source[key];
    const label = key === 'routing' ? '路由对象' : key === 'flowObjects' ? '流量对象' : '自定义协议';
    if (source.data) return null;
    if (source.status === 'loading') return { name: 'loading', title: `正在读取${label}`, detail: `等待${label}权威来源返回。` };
    if (source.status === 'forbidden') return { name: 'forbidden', title: `无权读取${label}`, detail: source.error || `当前账号没有${label}读取权限。` };
    if (source.status === 'unavailable') return { name: 'unavailable', title: `${label}来源不可用`, detail: source.error || '后端没有提供可确认的只读快照。' };
    if (source.status === 'error') return { name: 'error', title: `无法读取${label}`, detail: source.error || `${label}接口当前不可用。` };
    return null;
  }

  function tabsMarkup() {
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs policy-object-tabs" data-dwrt-component="tabs" data-object-tabs aria-label="对象可信来源"><span class="dwrt-kit-tab-pill" aria-hidden="true"></span>${SOURCE_TABS.map(([id, label]) => `<button class="dwrt-kit-tab ${state.tab === id ? 'is-active' : ''}" type="button" role="tab" data-object-tab="${id}" data-value="${id}" aria-selected="${state.tab === id ? 'true' : 'false'}">${label}</button>`).join('')}</nav>`;
  }

  function overviewMarkup() {
    const composite = state.composite?.items.length ?? 0;
    const routing = state.source.routing.data?.items.length ?? 0;
    const flowObjects = state.source.flowObjects.data?.items.length ?? 0;
    const flowd = state.source.flowd.data?.items.length ?? 0;
    const cards = [
      { key: 'composite', label: '复合策略对象', value: String(composite), detail: '策略引擎合同 · 只读', tone: 'info', icon: icon('boxes') },
      { key: 'routing', label: '路由对象', value: state.source.routing.status === 'ready' ? String(routing) : '--', detail: '由“路由表”管理', tone: 'neutral', icon: icon('route') },
      { key: 'flow-objects', label: '流量对象', value: state.source.flowObjects.status === 'ready' ? String(flowObjects) : '--', detail: 'flowd 配置态 · 只读', tone: 'neutral', icon: icon('braces') },
      { key: 'flowd', label: '自定义协议', value: state.source.flowd.status === 'ready' ? String(flowd) : '--', detail: 'flowd 独立资源 · 只读', tone: 'neutral', icon: icon('scan-search') }
    ];
    const renderer = ui.overviewCardsMarkup || window.DWRT_UI_KIT?.overviewCardsMarkup;
    return typeof renderer === 'function' ? renderer(cards, { className: 'policy-object-overview', label: '对象来源概览' }) : '';
  }

  function tableMarkup({ title, description, rows, columns, empty, kind }) {
    return `<section data-dwrt-component="data-table" class="policy-entity-table policy-object-table policy-object-table-${kind} dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(description)}</span></div><span class="dwrt-kit-table-count">${rows.length} 个</span></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table"><thead><tr>${columns.map((column) => `<th>${escapeHtml(column)}</th>`).join('')}<th><span class="policy-entity-visually-hidden">详情</span></th></tr></thead><tbody>${rows.length ? rows.map((item) => rowMarkup(kind, item)).join('') : `<tr><td class="dwrt-kit-table-empty" colspan="${columns.length + 1}">${escapeHtml(empty)}</td></tr>`}</tbody></table></div></section>`;
  }

  function rowMarkup(kind, item) {
    const detail = `<td><button type="button" data-dwrt-component="icon-button" data-object-detail="${escapeHtml(`${kind}:${item.id}`)}" aria-label="查看 ${escapeHtml(item.name)}">${icon('chevron-right')}</button></td>`;
    if (kind === 'flowd') {
      const ports = [item.srcPort && `源 ${item.srcPort}`, item.dstPort && `目标 ${item.dstPort}`].filter(Boolean).join(' · ') || '任意';
      return `<tr><td><strong>${escapeHtml(item.name)}</strong>${item.remark ? `<small>${escapeHtml(item.remark)}</small>` : ''}</td><td>${escapeHtml(item.kind.toUpperCase())}</td><td>${escapeHtml(item.proto.toUpperCase())}</td><td>${escapeHtml(ports)}</td><td>${statusBadge(item.enabled ? '启用' : '停用', item.enabled ? 'success' : 'muted')}</td>${detail}</tr>`;
    }
    if (kind === 'flowObjects') {
      const reference = item.refCount ? `${item.refCount} 条引用` : '未引用';
      return `<tr><td><strong>${escapeHtml(item.name)}</strong>${item.remark ? `<small>${escapeHtml(item.remark)}</small>` : ''}</td><td>${escapeHtml(item.type)}</td><td>${escapeHtml(String(item.valueCount))}</td><td>${escapeHtml(reference)}</td><td>${statusBadge(item.enabled ? '启用' : '停用', item.enabled ? 'success' : 'muted')}</td>${detail}</tr>`;
    }
    const type = kind === 'routing' ? item.type : item.type;
    const owner = kind === 'routing' ? '路由表' : '策略引擎';
    return `<tr><td><strong>${escapeHtml(item.name)}</strong>${item.comment ? `<small>${escapeHtml(item.comment)}</small>` : ''}</td><td>${escapeHtml(type)}</td><td>${escapeHtml(item.family || '--')}</td><td>${escapeHtml(owner)}</td><td>${statusBadge(item.enabled ? '启用' : '停用', item.enabled ? 'success' : 'muted')}</td>${detail}</tr>`;
  }

  function compositeMarkup() {
    const terminal = compositeTerminal();
    if (terminal) return statePanel(terminal.name, terminal.title, terminal.detail);
    const stale = state.snapshot?.stale ? `<div class="policy-entity-alert is-warning" role="status"><strong>正在显示上次可用快照</strong><span>复合对象刷新失败，当前列表已保留。</span></div>` : '';
    const readOnly = state.composite.readOnly ? `<div class="policy-entity-alert is-warning" role="status"><strong>复合策略对象暂为只读</strong><span>${escapeHtml(compositeBlockReason())}。页面不会展示无法提交的名称、成员或模块开关。</span></div>` : '';
    return `${stale}${readOnly}${tableMarkup({ title: '复合策略对象', description: '权威来源：/api/v1/policy-engine/objects；不包含路由对象或系统应用目录', rows: state.composite.items, columns: ['名称', '类型', '地址族', '归属', '状态'], empty: '尚未创建复合策略对象', kind: 'composite' })}`;
  }

  function routingMarkup() {
    const terminal = sourceTerminal('routing');
    if (terminal) return statePanel(terminal.name, terminal.title, terminal.detail);
    const data = state.source.routing.data;
    const stale = state.source.routing.status === 'ready' ? '' : `<div class="policy-entity-alert is-warning" role="status"><strong>正在显示上次可用快照</strong><span>${escapeHtml(state.source.routing.error || '路由对象刷新失败。')}</span></div>`;
    return `${stale}<div class="policy-entity-alert" role="status"><strong>独立路由资源</strong><span>此处仅查看 routed 返回的路由对象；新增、编辑与删除归“策略引擎 → 路由表”所有，本页不会复制写入口。</span></div>${tableMarkup({ title: '路由对象', description: `权威来源：/api/v1/routing/objects · ${data.source}`, rows: data.items, columns: ['名称', '类型', '地址族', '归属', '状态'], empty: '路由表尚未配置路由对象', kind: 'routing' })}`;
  }

  function flowdMarkup() {
    const terminal = sourceTerminal('flowd');
    if (terminal) return statePanel(terminal.name, terminal.title, terminal.detail);
    const data = state.source.flowd.data;
    const stale = state.source.flowd.status === 'ready' ? '' : `<div class="policy-entity-alert is-warning" role="status"><strong>正在显示上次可用快照</strong><span>${escapeHtml(state.source.flowd.error || '自定义协议刷新失败。')}</span></div>`;
    return `${stale}<div class="policy-entity-alert" role="status"><strong>独立协议资源</strong><span>仅展示 flowd 用户自定义协议，不包含系统 catalog、内置应用签名或协议目录；本页保持只读。</span></div>${tableMarkup({ title: 'flowd 自定义协议', description: `权威来源：/api/v1/flowd/custom-protocols · ${data.source}`, rows: data.items, columns: ['名称', '层级', '协议', '端口', '状态'], empty: 'flowd 尚未配置自定义协议', kind: 'flowd' })}`;
  }

  function flowObjectsMarkup() {
    const terminal = sourceTerminal('flowObjects');
    if (terminal) return statePanel(terminal.name, terminal.title, terminal.detail);
    const data = state.source.flowObjects.data;
    const stale = state.source.flowObjects.status === 'ready' ? '' : `<div class="policy-entity-alert is-warning" role="status"><strong>正在显示上次可用快照</strong><span>${escapeHtml(state.source.flowObjects.error || '流量对象刷新失败。')}</span></div>`;
    return `${stale}<div class="policy-entity-alert is-warning" role="status"><strong>配置态对象</strong><span>引用关系仅覆盖 flowd 内部规则；runtime_kind 表示计划产物类型，不代表已经应用到数据面。</span></div>${tableMarkup({ title: 'flowd 流量对象', description: `权威来源：/api/v1/flowd/objects · ${data.source}`, rows: data.items, columns: ['名称', '类型', '值数量', '引用', '状态'], empty: 'flowd 尚未配置流量对象', kind: 'flowObjects' })}`;
  }

  function activeSourceMarkup() {
    if (state.tab === 'routing') return routingMarkup();
    if (state.tab === 'flowObjects') return flowObjectsMarkup();
    if (state.tab === 'flowd') return flowdMarkup();
    return compositeMarkup();
  }

  function workbenchMarkup() {
    return `<section class="policy-entity-page policy-objects-page"><header class="policy-object-toolbar" data-adaptive-sample>${tabsMarkup()}<div class="policy-entity-header-actions"><span class="policy-object-readonly-status">${statusBadge('只读分类', 'warning')}</span>${button(state.refreshing ? '正在刷新' : '刷新', `data-object-refresh aria-label="刷新对象来源" data-dwrt-tooltip="刷新" ${state.refreshing ? 'disabled' : ''}`, 'ghost', 'refresh-cw')}</div></header><main class="policy-object-workbench">${overviewMarkup()}<section class="policy-object-source-view" data-object-source-view="${state.tab}">${activeSourceMarkup()}</section></main></section>`;
  }

  function detailData() {
    const detail = state.detail;
    if (!detail) return null;
    if (detail.kind === 'routing') return state.source.routing.data?.items.find((item) => item.id === detail.id) ? { kind: detail.kind, item: state.source.routing.data.items.find((item) => item.id === detail.id) } : null;
    if (detail.kind === 'flowObjects') return state.source.flowObjects.data?.items.find((item) => item.id === detail.id) ? { kind: detail.kind, item: state.source.flowObjects.data.items.find((item) => item.id === detail.id) } : null;
    if (detail.kind === 'flowd') return state.source.flowd.data?.items.find((item) => item.id === detail.id) ? { kind: detail.kind, item: state.source.flowd.data.items.find((item) => item.id === detail.id) } : null;
    return state.composite?.items.find((item) => item.id === detail.id) ? { kind: 'composite', item: state.composite.items.find((item) => item.id === detail.id) } : null;
  }

  function detailMarkup() {
    const selected = detailData();
    if (!selected) return '';
    const { kind, item } = selected;
    const title = kind === 'routing' ? '路由对象' : kind === 'flowObjects' ? 'flowd 流量对象' : kind === 'flowd' ? 'flowd 自定义协议' : '复合策略对象';
    const owner = kind === 'routing' ? '策略引擎 → 路由表' : kind === 'flowObjects' || kind === 'flowd' ? 'dreamingwrt.flowd' : '策略引擎对象合同';
    const fields = kind === 'flowd'
      ? [['对象标识', item.id], ['归属', owner], ['层级', item.kind.toUpperCase()], ['协议', item.proto.toUpperCase()], ['源端口', item.srcPort || '任意'], ['目标端口', item.dstPort || '任意'], ['优先级', String(item.priority)], ['标签', item.tags.join('、') || '--'], ['状态', item.enabled ? '启用' : '停用']]
      : kind === 'flowObjects'
        ? [['对象标识', item.id], ['归属', owner], ['类型', item.type], ['配置值', formatFlowObjectValue(item.value)], ['值数量', String(item.valueCount)], ['计划产物', item.runtimeKind], ['flowd 内部引用', String(item.refCount)], ['删除锁定', item.deleteLocked ? '是' : '否'], ['状态', item.enabled ? '启用' : '停用']]
      : [['对象标识', item.id], ['归属', owner], ['类型', item.type], ['地址族', item.family || '--'], ['值', item.value || '--'], ['成员', kind === 'routing' ? item.members.map((member) => member.label ? `${member.label} (${member.value})` : member.value).join('、') || '--' : '--'], ['引用数', kind === 'routing' ? String(item.refCount) : '--'], ['状态', item.enabled ? '启用' : '停用']];
    const referenceMarkup = kind === 'flowObjects' ? flowObjectReferencesMarkup(item) : '';
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-object-detail-close aria-label="关闭对象详情"></button><aside data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" class="dwrt-kit-sheet policy-entity-sheet is-open"><header class="dwrt-kit-sheet-header"><div><span>${escapeHtml(title)}</span><strong>${escapeHtml(item.name)}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-object-detail-close aria-label="关闭">${icon('x')}</button></header><div class="dwrt-kit-sheet-body policy-entity-sheet-body"><dl class="policy-entity-detail-list">${fields.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`).join('')}</dl>${referenceMarkup}${statePanel('unavailable', '此来源在对象页只读', kind === 'routing' ? '路由对象由“策略引擎 → 路由表”管理。' : kind === 'flowObjects' ? '当前只确认 flowd 配置存储与内部引用；数据面仍为 plan-only，未提供运行态应用证明。' : kind === 'flowd' ? '自定义协议属于 flowd 独立资源，本页不提供写操作。' : '复合对象写入需要跨组件原子事务，能力未开放前保持 fail-closed。')}</div><footer class="dwrt-kit-sheet-footer"><span></span>${button('关闭', 'data-object-detail-close', 'primary')}</footer></aside>`;
  }

  function formatFlowObjectValue(value) {
    if (Array.isArray(value)) return value.map((entry) => typeof entry === 'string' ? entry : JSON.stringify(entry)).join('、') || '--';
    if (value && typeof value === 'object') return JSON.stringify(value);
    return sourceText(value, '--');
  }

  function flowObjectReferencesMarkup(item) {
    if (!item.references.length) return `<section class="policy-object-reference-list"><h3>flowd 内部引用</h3>${statePanel('empty', '当前没有引用', '此结论仅覆盖 flowd 自身规则，不代表跨 routed、firewall 或 SQM 的统一 used-by。')}</section>`;
    return `<section class="policy-object-reference-list"><h3>flowd 内部引用</h3>${item.references.map((reference) => `<article><span><strong>${escapeHtml(reference.name)}</strong><small>${escapeHtml([reference.kind, reference.field, reference.id].filter(Boolean).join(' · '))}</small></span>${statusBadge(reference.enabled ? '启用' : '停用', reference.enabled ? 'success' : 'muted')}</article>`).join('')}</section>`;
  }

  function replaceMarkup(host, markup) {
    window.DWRT_UI_KIT?.unmount?.(host);
    host.replaceChildren(document.createRange().createContextualFragment(markup));
    ui.mountAll?.(host);
  }

  function renderPage() {
    if (!root || !state.mounted) return;
    replaceMarkup(pageHost, workbenchMarkup());
    const selectedTab = pageHost.querySelector('[data-object-tab][aria-selected="true"]');
    selectedTab?.scrollIntoView?.({ block: 'nearest', inline: 'center' });
  }

  function renderOverlay() {
    if (!root || !state.mounted) return;
    replaceMarkup(overlayHost, detailMarkup());
  }

  function hydrate(snapshot) {
    state.snapshot = snapshot;
    if (snapshot?.value) state.composite = normalizePolicyObjects(snapshot.value);
    renderPage();
  }

  async function loadSource(key) {
    const source = state.source[key];
    const endpoint = key === 'routing' ? '/api/v1/routing/objects' : key === 'flowObjects' ? '/api/v1/flowd/objects' : '/api/v1/flowd/custom-protocols';
    const normalize = key === 'routing' ? normalizeRoutingObjects : key === 'flowObjects' ? normalizeFlowdObjects : normalizeFlowdCustomProtocols;
    if (typeof api.request !== 'function') {
      source.status = 'unavailable';
      source.error = '页面没有获得只读 API 请求能力。';
      return;
    }
    source.status = source.data ? 'ready' : 'loading';
    source.error = null;
    try {
      const payload = await api.request(`policy-object-${key}-list`, endpoint, { method: 'GET' });
      const data = payload?.data && typeof payload.data === 'object' ? payload.data : payload;
      const valid = key === 'routing'
        ? Array.isArray(data?.items) || Array.isArray(data?.route_objects)
        : key === 'flowObjects' ? Array.isArray(data?.objects) : Array.isArray(data?.protocols);
      if (!valid) throw new Error(`${endpoint} 返回的列表合同无效`);
      if (!state.mounted) return;
      source.data = normalize(payload);
      source.status = 'ready';
    } catch (error) {
      if (!state.mounted || signal?.aborted) return;
      source.status = error?.status === 403 ? 'forbidden' : error?.status === 404 ? 'unavailable' : 'error';
      source.error = error?.message || `${endpoint} 请求失败`;
    }
  }

  function refresh() {
    if (state.refreshPromise) {
      state.refreshQueued = true;
      return state.refreshPromise;
    }
    state.refreshPromise = (async () => {
      do {
        state.refreshQueued = false;
        state.refreshing = true;
        renderPage();
        await Promise.allSettled([
          registry ? registry.request('policy.objects', { signal, force: true }) : Promise.resolve(),
          loadSource('routing'),
          loadSource('flowObjects'),
          loadSource('flowd')
        ]);
      } while (state.mounted && state.refreshQueued);
      if (!state.mounted) return;
      state.refreshing = false;
      renderPage();
    })().finally(() => {
      state.refreshPromise = null;
      if (state.mounted && state.refreshing) {
        state.refreshing = false;
        renderPage();
      }
    });
    return state.refreshPromise;
  }

  function onClick(event) {
    const tab = event.target.closest('[data-object-tab]');
    if (tab) {
      state.tab = SOURCE_TABS.some(([id]) => id === tab.dataset.objectTab) ? tab.dataset.objectTab : 'composite';
      state.detail = null;
      renderPage();
      renderOverlay();
      return;
    }
    if (event.target.closest('[data-object-refresh]')) return void refresh();
    const open = event.target.closest('[data-object-detail]');
    if (open) {
      const splitAt = String(open.dataset.objectDetail || '').indexOf(':');
      state.detail = splitAt > 0 ? { kind: open.dataset.objectDetail.slice(0, splitAt), id: open.dataset.objectDetail.slice(splitAt + 1) } : null;
      renderOverlay();
      return;
    }
    if (event.target.closest('[data-object-detail-close]')) {
      state.detail = null;
      renderOverlay();
    }
  }

  root.hidden = false;
  root.className = 'route-preview route-workspace policy-objects-route-host';
  root.replaceChildren(pageHost, overlayHost);
  root.addEventListener('click', onClick);
  const unsubscribe = registry?.subscribe?.('policy.objects', hydrate) || null;
  renderPage();
  renderOverlay();
  if (registry) registry.request('policy.objects', { signal });
  Promise.allSettled([loadSource('routing'), loadSource('flowObjects'), loadSource('flowd')]).then(() => { if (state.mounted) renderPage(); });

  return {
    refresh,
    unmount() {
      state.mounted = false;
      unsubscribe?.();
      root.removeEventListener('click', onClick);
      window.DWRT_UI_KIT?.unmount?.(root);
      root.replaceChildren();
      root.classList.remove('route-workspace', 'policy-objects-route-host');
    }
  };
}

export default { mount };
