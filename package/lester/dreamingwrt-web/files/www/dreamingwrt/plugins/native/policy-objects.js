const VERSION = '20260814-policy-custom-protocol-crud-01';

const SOURCE_TABS = [
  ['overview', '概览'],
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

/*
 * flowd 的两类资源都把「配置态可写」与「运行态是否已应用」分成两位下发：
 * runtime_apply 恒为 false，原因串恒为 flowd_apply_mode_plan_only
 * （flowd_db_init() 会主动把 apply_mode 拽回 plan-only）。
 * 所以写入落库成功不等于已应用到数据面，两件事必须分开呈现，不能被 CRUD 位盖掉。
 */
const runtimeApplyState = (capabilities) => ({
  runtimeApply: capabilities?.runtime_apply === true,
  runtimeApplyKnown: typeof capabilities?.runtime_apply === 'boolean',
  runtimeApplyReason: sourceText(capabilities?.runtime_apply_reason)
});

const RUNTIME_APPLY_REASONS = {
  flowd_apply_mode_plan_only: 'flowd 的 apply_mode 恒为 plan-only，配置只落库不下发数据面'
};

export function runtimeApplyReasonText(reason) {
  const key = sourceText(reason);
  if (!key) return '';
  return RUNTIME_APPLY_REASONS[key] || key;
}

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
    /*
     * 只读判据取后端自述，不再写死。routed 在同一份载荷里给出 object_crud
     * 与写入端点（30.1 实测 object_crud=true、
     * object_crud_write_endpoint=/api/v1/routing/objects），策略引擎侧还另有
     * legacy_route_objects_read_only=false 指同一件事。写死 true 会把一个真实
     * 可写的资源说成后端不支持。
     *
     * 能力键缺失时保持只读：那是「能力未知」，不是「可写」，前端不替后端假设。
     */
    readOnly: capabilities.object_crud !== true,
    writeEndpoint: sourceText(capabilities.object_crud_write_endpoint, '/api/v1/routing/objects')
  };
}

export function normalizeFlowdCustomProtocols(payload = {}) {
  const data = payload?.data && typeof payload.data === 'object' ? payload.data : payload;
  const capabilities = data?.capabilities && typeof data.capabilities === 'object' ? data.capabilities : null;
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
    /*
     * flowd 的 custom_protocols_get 现在会下发 capabilities（2026-08-09 30.1 实测：
     * custom_protocol_crud=true、object_crud_scope=flowd:custom_protocol，
     * 另有按资源命名的别名键 custom_protocol_crud_write_endpoint /
     * custom_protocol_delete_endpoint）。判据仍只取目标端点自身的 capabilities
     * （design.md「Capability truth」第 1 条），并保持三态：
     *   capabilityKnown=false → 能力未确认，不得断言后端不支持；
     *   custom_protocol_crud=false → 后端明确为否；
     *   custom_protocol_crud=true → 解开只读。
     * 端点一律取能力位下发值，兜底串只在能力缺失时才生效，不作为可写判据。
     */
    capabilities: capabilities || {},
    capabilityKnown: capabilities !== null,
    readOnly: capabilities?.custom_protocol_crud !== true,
    writeEndpoint: sourceText(capabilities?.custom_protocol_crud_write_endpoint, capabilities?.object_crud_write_endpoint, '/api/v1/flowd/custom-protocols'),
    deleteEndpoint: sourceText(capabilities?.custom_protocol_delete_endpoint, capabilities?.object_delete_endpoint, '/api/v1/flowd/custom-protocols/delete'),
    ...runtimeApplyState(capabilities)
  };
}

export function normalizeFlowdObjects(payload = {}) {
  const data = payload?.data && typeof payload.data === 'object' ? payload.data : payload;
  const capabilities = data?.capabilities && typeof data.capabilities === 'object' ? data.capabilities : null;
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
    /*
     * 这里的 readOnly 只描述「除 country / time 之外的类型能不能写」。
     * country 与 time 已由 FLOW_OBJECT_EDITABLE_TYPES 开放真实写入面，
     * 不受这一位影响 —— 那两类的写入已在 30.1 实测通过。
     *
     * objects_get 现在会下发 capabilities（2026-08-09 30.1 实测：object_crud=true、
     * object_crud_scope=flowd:object、写入/删除端点齐备），所以 readOnly 已按能力位解开。
     * 但「写通道开放」不等于本页会给所有类型放表单：ipv4 / domain / app_set 等类型的
     * 取值语义仍没有校验落点，给了输入框等于放行乱值，因此本页开放的类型集合仍由
     * FLOW_OBJECT_EDITABLE_TYPES 决定，与 object_crud 是两个独立的门。
     * 另外 runtime_apply=false 表示配置落库 ≠ 已应用到数据面，单独呈现，不被 CRUD 位盖掉。
     */
    capabilities: capabilities || {},
    capabilityKnown: capabilities !== null,
    readOnly: capabilities?.object_crud !== true,
    writeEndpoint: sourceText(capabilities?.object_crud_write_endpoint, '/api/v1/flowd/objects'),
    deleteEndpoint: sourceText(capabilities?.object_delete_endpoint, '/api/v1/flowd/objects/delete'),
    ...runtimeApplyState(capabilities)
  };
}

/*
 * 地区目录（策略表的「地区」选择器）唯一的数据来源就是 country 类型的 flowd
 * 流量对象，计划目录同理来自 time 类型 —— webd 的 catalog 按 type 把 flowd
 * 对象分流成 regions / schedules（jmx_app_api.c:35646）。在此之前全站没有任何
 * 页面会发 `POST /api/v1/flowd/objects`，于是选择器恒空且用户无从下手。
 * 这两类由本页承担写入面，其余类型（ipv4/domain/app_set 等）仍不在本页范围内。
 */
export const FLOW_OBJECT_EDITABLE_TYPES = ['country', 'time'];

/*
 * 国家码取值走后端权威清单，不在前端自造。/api/v1/firewall/geo-block 的
 * `countries[]` 是 aegisxd 的官方目录（实测 249 条，带中文名与所属洲），
 * aegisx 页的区域拦截用的就是它。这里只读它当候选项，不写它的任何状态。
 */
export function normalizeCountryCatalog(payload = {}) {
  const data = payload?.data && typeof payload.data === 'object' ? payload.data : payload;
  const items = sourceList(data, ['countries']).map((item = {}) => {
    const code = sourceText(item.code, item.id).toUpperCase();
    return {
      code,
      name: sourceText(item.name_zh, item.name, item.name_en, code),
      continent: sourceText(item.continent)
    };
  }).filter((item) => /^[A-Za-z]{2}$/.test(item.code));
  const seen = new Set();
  return items.filter((item) => {
    if (seen.has(item.code)) return false;
    seen.add(item.code);
    return true;
  });
}

const WEEKDAY_LABELS = [['1', '一'], ['2', '二'], ['3', '三'], ['4', '四'], ['5', '五'], ['6', '六'], ['7', '日']];

/*
 * flowd 对 `time` 对象的 value 只做「能存进 FLOWD_MAX_JSON 的 JSON」这一层校验
 * （flowd_db.c:3298 起，country 才有专门的 normalize），没有规定条目结构。
 * 所以形状由前端定，取一个自洽且可读的最小结构：一段时间窗加生效星期。
 */
export function flowTimeValueFromDraft(draft = {}) {
  const start = sourceText(draft.start);
  const end = sourceText(draft.end);
  const days = Array.isArray(draft.days) ? draft.days.map(String).filter((day) => WEEKDAY_LABELS.some(([key]) => key === day)) : [];
  if (!/^\d{2}:\d{2}$/.test(start) || !/^\d{2}:\d{2}$/.test(end)) return null;
  if (start === end) return null;
  return [{ start, end, days: days.length ? days : WEEKDAY_LABELS.map(([key]) => key) }];
}

export function flowTimeDraftFromValue(value) {
  const entry = Array.isArray(value) ? value[0] : value;
  if (!entry || typeof entry !== 'object') return { start: '09:00', end: '18:00', days: WEEKDAY_LABELS.map(([key]) => key) };
  const days = Array.isArray(entry.days) ? entry.days.map(String) : [];
  return {
    start: /^\d{2}:\d{2}$/.test(sourceText(entry.start)) ? sourceText(entry.start) : '09:00',
    end: /^\d{2}:\d{2}$/.test(sourceText(entry.end)) ? sourceText(entry.end) : '18:00',
    days: days.length ? days : WEEKDAY_LABELS.map(([key]) => key)
  };
}

/* flowd_id_ok() → flowd_token_ok()：字母数字与 _-.:/ ，长度受 FLOWD_MAX_ID 限制。 */
export function flowObjectIdFromName(type, name, taken = []) {
  const slug = String(name ?? '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
  const base = `${type}-${slug || 'object'}`;
  let candidate = base;
  let serial = 2;
  while (taken.includes(candidate)) {
    candidate = `${base}-${serial}`;
    serial += 1;
  }
  return candidate;
}

export { WEEKDAY_LABELS };

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const registry = context.registry;
  const api = context.api || {};
  const ui = context.ui || {};
  const signal = context.signal;
  const escapeHtml = context.utils?.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const state = {
    mounted: true,
    /* 概览是第一页，进页面先看汇总，再按来源分页细看。 */
    tab: 'overview',
    snapshot: null,
    composite: null,
    refreshing: false,
    refreshQueued: false,
    refreshPromise: null,
    pollTimer: 0,
    detail: null,
    /* country / time 的编辑抽屉：null 表示未打开。 */
    editor: null,
    /* 自定义协议使用独立草稿，避免与 country / time 的字段语义互相污染。 */
    protocolEditor: null,
    /* 删除确认，走 kit 的 confirmationMarkup（design.md 规则 17）。 */
    removing: null,
    saving: false,
    notice: '',
    protocolNotice: '',
    countries: { status: 'idle', items: [], error: '' },
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
      { key: 'routing', label: '路由对象', value: state.source.routing.status === 'ready' ? String(routing) : '--', detail: state.source.routing.data && !state.source.routing.data.readOnly ? '可写 · 写入面在路由表' : '由“路由表”管理', tone: 'neutral', icon: icon('route') },
      { key: 'flow-objects', label: '流量对象', value: state.source.flowObjects.status === 'ready' ? String(flowObjects) : '--', detail: 'flowd 配置态 · 地区/计划可写', tone: 'neutral', icon: icon('braces') },
      { key: 'flowd', label: '自定义协议', value: state.source.flowd.status === 'ready' ? String(flowd) : '--', detail: `flowd 独立资源 · ${flowdCardWritability()}`, tone: 'neutral', icon: icon('scan-search') }
    ];
    const renderer = ui.overviewCardsMarkup || window.DWRT_UI_KIT?.overviewCardsMarkup;
    return typeof renderer === 'function' ? renderer(cards, { className: 'policy-object-overview', label: '对象来源概览' }) : '';
  }

  /* 概览卡片一行字的可写性，判据与徽章、说明列同源，避免三处各说一套。 */
  function flowdCardWritability() {
    const data = state.source.flowd.data;
    if (!data) return '读取中';
    if (!data.readOnly) return '可新增、编辑与删除';
    return data.capabilityKnown ? '只读' : '可写性未确认';
  }

  function tableMarkup({ title, description, rows, columns, empty, kind, actions = '' }) {
    return `<section data-dwrt-component="data-table" class="policy-entity-table policy-object-table policy-object-table-${kind} dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(description)}</span></div><div class="policy-object-table-toolbar-end"><span class="dwrt-kit-table-count">${rows.length} 个</span>${actions}</div></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table"><thead><tr>${columns.map((column) => `<th>${escapeHtml(column)}</th>`).join('')}<th><span class="policy-entity-visually-hidden">操作</span></th></tr></thead><tbody>${rows.length ? rows.map((item) => rowMarkup(kind, item)).join('') : `<tr><td class="dwrt-kit-table-empty" colspan="${columns.length + 1}">${escapeHtml(empty)}</td></tr>`}</tbody></table></div></section>`;
  }

  function rowMarkup(kind, item) {
    const detail = `<td><button type="button" data-dwrt-component="icon-button" data-object-detail="${escapeHtml(`${kind}:${item.id}`)}" aria-label="查看 ${escapeHtml(item.name)}">${icon('chevron-right')}</button></td>`;
    if (kind === 'flowd') {
      const ports = [item.srcPort && `源 ${item.srcPort}`, item.dstPort && `目标 ${item.dstPort}`].filter(Boolean).join(' · ') || '任意';
      const writable = state.source.flowd.data?.readOnly === false;
      const actions = writable
        ? `<div class="policy-object-row-actions"><button type="button" data-dwrt-component="icon-button" data-protocol-edit="${escapeHtml(item.id)}" aria-label="编辑 ${escapeHtml(item.name)}" title="编辑">${icon('pencil')}</button><button type="button" data-dwrt-component="icon-button" data-protocol-remove="${escapeHtml(item.id)}" aria-label="删除 ${escapeHtml(item.name)}" title="删除">${icon('trash-2')}</button><button type="button" data-dwrt-component="icon-button" data-object-detail="${escapeHtml(`${kind}:${item.id}`)}" aria-label="查看 ${escapeHtml(item.name)}" title="详情">${icon('chevron-right')}</button></div>`
        : `<div class="policy-object-row-actions"><button type="button" data-dwrt-component="icon-button" data-object-detail="${escapeHtml(`${kind}:${item.id}`)}" aria-label="查看 ${escapeHtml(item.name)}" title="详情">${icon('chevron-right')}</button></div>`;
      return `<tr><td><strong>${escapeHtml(item.name)}</strong>${item.remark ? `<small>${escapeHtml(item.remark)}</small>` : ''}</td><td>${escapeHtml(item.kind.toUpperCase())}</td><td>${escapeHtml(item.proto.toUpperCase())}</td><td>${escapeHtml(ports)}</td><td>${statusBadge(item.enabled ? '启用' : '停用', item.enabled ? 'success' : 'muted')}</td><td>${actions}</td></tr>`;
    }
    if (kind === 'flowObjects') {
      const reference = item.refCount ? `${item.refCount} 条引用` : '未引用';
      const typeText = EDITABLE_TYPE_LABELS[item.type] ? `${EDITABLE_TYPE_LABELS[item.type]}（${item.type}）` : item.type;
      /*
       * 删除锁定由后端 reference_count 判定：被引用时 flowd 会以
       * reference_conflict 拒绝，所以按钮直接禁用并说明原因，而不是让用户点一次
       * 再吃一个报错。
       */
      const rowActions = isEditableFlowObject(item)
        ? `<div class="policy-object-row-actions"><button type="button" data-dwrt-component="icon-button" data-object-edit="${escapeHtml(item.id)}" aria-label="编辑 ${escapeHtml(item.name)}" title="编辑">${icon('pencil')}</button><button type="button" data-dwrt-component="icon-button" data-object-remove="${escapeHtml(item.id)}" aria-label="删除 ${escapeHtml(item.name)}" title="${item.deleteLocked ? '被规则引用，无法删除' : '删除'}" ${item.deleteLocked ? 'disabled' : ''}>${icon('trash-2')}</button><button type="button" data-dwrt-component="icon-button" data-object-detail="${escapeHtml(`${kind}:${item.id}`)}" aria-label="查看 ${escapeHtml(item.name)}" title="详情">${icon('chevron-right')}</button></div>`
        : `<div class="policy-object-row-actions"><button type="button" data-dwrt-component="icon-button" data-object-detail="${escapeHtml(`${kind}:${item.id}`)}" aria-label="查看 ${escapeHtml(item.name)}" title="详情">${icon('chevron-right')}</button></div>`;
      return `<tr><td><strong>${escapeHtml(item.name)}</strong>${item.remark ? `<small>${escapeHtml(item.remark)}</small>` : ''}</td><td>${escapeHtml(typeText)}</td><td>${escapeHtml(String(item.valueCount))}</td><td>${escapeHtml(reference)}</td><td>${statusBadge(item.enabled ? '启用' : '停用', item.enabled ? 'success' : 'muted')}</td><td>${rowActions}</td></tr>`;
    }
    const type = kind === 'routing' ? item.type : item.type;
    const owner = kind === 'routing' ? '路由表' : '策略引擎';
    return `<tr><td><strong>${escapeHtml(item.name)}</strong>${item.comment ? `<small>${escapeHtml(item.comment)}</small>` : ''}</td><td>${escapeHtml(type)}</td><td>${escapeHtml(item.family || '--')}</td><td>${escapeHtml(owner)}</td><td>${statusBadge(item.enabled ? '启用' : '停用', item.enabled ? 'success' : 'muted')}</td>${detail}</tr>`;
  }

  function compositeMarkup() {
    /*
     * 判 snapshot.error，而不是 snapshot.stale。
     *
     * registry 在真正 fetch 之前就按龄期置 stale（dwrt-data-registry.js 的
     * request()：`entry.stale = hasValue && age > ttlMs`），与请求成败无关，所以
     * 后端全程 200 时每个刷新窗口也会误报一次「刷新失败」。status === 'stale'
     * 同样不行：中断（换页、卸载，AbortError）走的也是 stale，但 error 为 null，
     * 那是正常取消。Boolean(snapshot.error) 是唯一能分离三种情形的信号。
     */
    function staleMarkup() {
      if (!state.snapshot?.error) return '';
      return `<div class="policy-entity-alert is-warning" role="status"><strong>正在显示上次可用快照</strong><span>复合对象（/api/v1/policy-engine/objects）刷新失败，页面仍保留最后一次成功数据。</span></div>`;
    }

    const terminal = compositeTerminal();
    if (terminal) return statePanel(terminal.name, terminal.title, terminal.detail);
    const stale = staleMarkup();
    const readOnly = state.composite.readOnly ? `<div class="policy-entity-alert is-warning" role="status"><strong>复合策略对象暂为只读</strong><span>${escapeHtml(compositeBlockReason())}。页面不会展示无法提交的名称、成员或模块开关。</span></div>` : '';
    return `${stale}${readOnly}${tableMarkup({ title: '复合策略对象', description: '权威来源：/api/v1/policy-engine/objects；不包含路由对象或系统应用目录', rows: state.composite.items, columns: ['名称', '类型', '地址族', '归属', '状态'], empty: '尚未创建复合策略对象', kind: 'composite' })}`;
  }

  function routingMarkup() {
    const terminal = sourceTerminal('routing');
    if (terminal) return statePanel(terminal.name, terminal.title, terminal.detail);
    const data = state.source.routing.data;
    const stale = state.source.routing.status === 'ready' ? '' : `<div class="policy-entity-alert is-warning" role="status"><strong>正在显示上次可用快照</strong><span>${escapeHtml(state.source.routing.error || '路由对象刷新失败。')}</span></div>`;
    /*
     * 写入归属与「后端是否支持写」是两件事，原文案把它们说成了一件。
     *
     * routed 声明 object_crud=true 时，路由对象是真实可写的，只是写入面在
     * 「策略引擎 → 路由表」那一页（routing-table.js 的路由对象 tab 已按同一个
     * 能力位开门）。此处给出可点入口即可，不在本页复制第二份表单。
     * 能力位为假或缺失时才说明写入不可用，并区分这两种情形。
     */
    const notice = data.readOnly
      ? `<div class="policy-entity-alert is-warning" role="status"><strong>路由对象当前不可写</strong><span>${escapeHtml(data.capabilities?.object_crud === false ? 'routed 声明 object_crud=false，写入通道未开放。' : 'routed 本次未声明 object_crud，可写性未确认；这不代表功能缺失。')}此处仍可查看 routed 返回的配置态列表。</span></div>`
      : `<div class="policy-entity-alert" role="status"><strong>可写资源，写入面在路由表</strong><span>routed 已声明 <code>object_crud</code>，路由对象可新增、编辑与删除；写入面归“策略引擎 → 路由表”，本页只做查看，不复制第二份表单。<a class="policy-entity-alert-link" href="#/policy-engine/routes">前往路由表管理路由对象</a></span></div>`;
    return `${stale}${notice}${tableMarkup({ title: '路由对象', description: `权威来源：${escapeHtml(data.writeEndpoint)} · ${data.source}`, rows: data.items, columns: ['名称', '类型', '地址族', '归属', '状态'], empty: '路由表尚未配置路由对象', kind: 'routing' })}`;
  }

  /*
   * 运行态与配置态分开说。flowd 的 apply_mode 恒为 plan-only，所以写入落库成功
   * 之后必须明确「还没应用到数据面」，否则用户会把保存成功读成已生效。
   * 判据是 runtime_apply 这个布尔位：为真才说已应用，未下发时只说未确认。
   */
  function runtimeApplyMarkup(data, extra = '') {
    if (!data?.runtimeApplyKnown) return '';
    if (data.runtimeApply) return `<div class="policy-entity-alert is-success" role="status"><strong>配置态与运行态一致</strong><span>flowd 声明 <code>runtime_apply=true</code>，保存后的配置会应用到数据面。${extra}</span></div>`;
    const reason = runtimeApplyReasonText(data.runtimeApplyReason);
    return `<div class="policy-entity-alert is-warning" role="status"><strong>配置态已保存，运行态未应用</strong><span>flowd 声明 <code>runtime_apply=false</code>${reason ? `：${escapeHtml(reason)}` : ''}。写入成功只表示配置落进 flowd 配置库，数据面尚未生效，本页不提供运行态应用证明。${extra}</span></div>`;
  }

  function flowdMarkup() {
    const terminal = sourceTerminal('flowd');
    if (terminal) return statePanel(terminal.name, terminal.title, terminal.detail);
    const data = state.source.flowd.data;
    const stale = state.source.flowd.status === 'ready' ? '' : `<div class="policy-entity-alert is-warning" role="status"><strong>正在显示上次可用快照</strong><span>${escapeHtml(state.source.flowd.error || '自定义协议刷新失败。')}</span></div>`;
    const notice = state.protocolNotice
      ? `<div class="policy-entity-alert ${data.runtimeApplyKnown && !data.runtimeApply ? 'is-warning' : 'is-success'}" role="status"><strong>${data.runtimeApplyKnown && !data.runtimeApply ? '配置已保存，运行态未应用' : '已保存'}</strong><span>${escapeHtml(state.protocolNotice)}</span></div>`
      : '';
    const capability = !data.readOnly
      ? `<div class="policy-entity-alert" role="status"><strong>自定义协议可写</strong><span>flowd 已声明 <code>custom_protocol_crud=true</code>。新增与编辑使用 <code>${escapeHtml(data.writeEndpoint)}</code>，删除使用 <code>${escapeHtml(data.deleteEndpoint)}</code>；运行态是否应用仍以独立能力位为准。</span></div>`
      : data.capabilityKnown
        ? `<div class="policy-entity-alert is-warning" role="status"><strong>写入能力为否</strong><span>flowd 声明 <code>custom_protocol_crud=false</code>，本页保持只读。</span></div>`
        : `<div class="policy-entity-alert is-warning" role="status"><strong>写入能力未确认，本页暂不提供编辑</strong><span>本次 <code>custom_protocols</code> 载荷里没有可写能力位，因此本页不放出编辑入口；这不等于后端没有实现 —— 写入端点 <code>/api/v1/flowd/custom-protocols</code> 已注册。能力位到位后本页会自动解开。</span></div>`;
    const actions = data.readOnly ? '' : `<div class="policy-object-table-actions">${button('新建自定义协议', 'data-protocol-create', 'primary', 'plus')}</div>`;
    return `${stale}${notice}<div class="policy-entity-alert" role="status"><strong>独立协议资源</strong><span>本表只列 flowd 用户自定义协议，不含系统内置应用签名与协议目录；那两类属于 <code>/api/v1/policy-engine/catalog</code>，由策略表的匹配条件直接引用。</span></div>${capability}${runtimeApplyMarkup(data)}${tableMarkup({ title: 'flowd 自定义协议', description: `权威来源：${escapeHtml(data.writeEndpoint)} · ${data.source}`, rows: data.items, columns: ['名称', '层级', '协议', '端口', '状态'], empty: data.readOnly ? 'flowd 尚未配置自定义协议' : 'flowd 尚未配置自定义协议，可以新建第一条', kind: 'flowd', actions })}`;
  }

  function flowObjectsMarkup() {
    const terminal = sourceTerminal('flowObjects');
    if (terminal) return statePanel(terminal.name, terminal.title, terminal.detail);
    const data = state.source.flowObjects.data;
    const stale = state.source.flowObjects.status === 'ready' ? '' : `<div class="policy-entity-alert is-warning" role="status"><strong>正在显示上次可用快照</strong><span>${escapeHtml(state.source.flowObjects.error || '流量对象刷新失败。')}</span></div>`;
    /*
     * 地区目录只由 country 类型对象喂养，所以这张表是「地区」选择器的唯一入口。
     * 建 / 改 / 删只对 country 与 time 开放，其余类型（ipv4、domain、app_set…）
     * 本页仍只读 —— 它们各自的取值语义没有校验落点，给了输入框等于放行乱值。
     */
    const editable = data.items.filter(isEditableFlowObject).length;
    const notice = state.notice ? `<div class="policy-entity-alert is-success" role="status"><strong>已生效</strong><span>${escapeHtml(state.notice)}</span></div>` : '';
    /*
     * 类型范围与 object_crud 是两个门，分开说：能力位为真只表示写通道开放，
     * 其余类型缺的是取值校验落点，不是后端能力。
     */
    const scope = data.readOnly
      ? `<div class="policy-entity-alert is-warning" role="status"><strong>其余类型写入能力${data.capabilityKnown ? '为否' : '未确认'}</strong><span>${data.capabilityKnown ? `flowd 声明 <code>object_crud=false</code>` : '本次载荷未声明 <code>object_crud</code>'}，${EDITABLE_TYPE_LABELS.country} 与 ${EDITABLE_TYPE_LABELS.time} 之外的类型保持只读。</span></div>`
      : `<div class="policy-entity-alert" role="status"><strong>写入通道已开放，本页开放的类型仍是两类</strong><span>flowd 已声明 <code>object_crud=true</code>，写入端点 <code>${escapeHtml(data.writeEndpoint)}</code>、删除端点 <code>${escapeHtml(data.deleteEndpoint)}</code>。本页仍只放出 ${EDITABLE_TYPE_LABELS.country} 与 ${EDITABLE_TYPE_LABELS.time} 的表单：<code>ipv4</code> / <code>domain</code> / <code>app_set</code> 等类型的取值语义还没有校验落点，给输入框等于放行乱值。这是前端表单缺口，不是后端能力缺口。</span></div>`;
    /*
     * 运行态那条与旧的「配置态对象」提示说的是同一件事，合成一条 ——
     * 四条提示条叠在表格上面，读者会直接跳过它们。
     * runtime_apply 缺失（旧后端）时仍要保留原来那条独立说明，否则这层结论会整块消失。
     */
    const configNote = '引用关系仅覆盖 flowd 内部规则；runtime_kind 表示计划产物类型，不代表已经应用到数据面。';
    const runtime = runtimeApplyMarkup(data, configNote)
      || `<div class="policy-entity-alert is-warning" role="status"><strong>配置态对象</strong><span>${configNote}</span></div>`;
    return `${stale}${notice}<div class="policy-entity-alert" role="status"><strong>地区与计划对象在此创建</strong><span>策略表的「地区」候选项就是这里的 <code>country</code> 类型对象，建好即可在 QoS / PBR 里选到；<code>time</code> 类型写入 flowd 的 schedule_set。<a class="policy-entity-alert-link" href="#/policy-engine/table">前往策略表使用它们</a></span></div>${scope}${runtime}${tableMarkup({ title: 'flowd 流量对象', description: `权威来源：${escapeHtml(data.writeEndpoint)} · ${data.source} · 可编辑 ${editable} 个`, rows: data.items, columns: ['名称', '类型', '值数量', '引用', '状态'], empty: 'flowd 尚未配置流量对象，先新建一个地区对象让「地区」选择器可用', kind: 'flowObjects', actions: flowObjectCreateActions() })}`;
  }

  function flowObjectCreateActions() {
    return `<div class="policy-object-table-actions">${button('新建地区对象', 'data-object-create="country"', 'primary', 'globe')}${button('新建计划对象', 'data-object-create="time"', 'secondary', 'clock')}</div>`;
  }

  /*
   * 徽章必须逐 tab 说实话：固定挂「只读分类」会对可写来源撒谎。
   * 路由对象在 routed 声明 object_crud 时是可写的（写入面在路由表），
   * 流量对象已开放 country / time，复合对象确实只读，
   * 自定义协议属于「能力未确认」而不是「后端不支持」。
   */
  function headerBadge() {
    if (state.tab === 'flowObjects') return statusBadge('地区 / 计划可写', 'success');
    if (state.tab === 'composite') return statusBadge('只读分类', 'warning');
    if (state.tab === 'routing') {
      const routing = state.source.routing.data;
      if (!routing) return statusBadge('读取中', 'muted');
      if (!routing.readOnly) return statusBadge('可写 · 写入面在路由表', 'success');
      return statusBadge(routing.capabilities?.object_crud === false ? '只读分类' : '可写性未确认', 'warning');
    }
    if (state.tab === 'flowd') {
      const flowd = state.source.flowd.data;
      if (!flowd) return statusBadge('读取中', 'muted');
      /* 能力位为真时不得再挂只读徽章 —— 页面同时说着「已开放」和「只读」会自相矛盾。 */
      if (!flowd.readOnly) return statusBadge('可写', 'success');
      return statusBadge(flowd.capabilityKnown ? '只读分类' : '可写性未确认', 'warning');
    }
    return statusBadge('多来源混合', 'muted');
  }

  /* 概览「说明」列用的一句话可写性，判据与各 tab 徽章保持同源。 */
  function sourceWritability(key) {
    if (key === 'composite') return '只读 · 复合对象写入未开放';
    if (key === 'routing') {
      const routing = state.source.routing.data;
      if (!routing) return '只读快照';
      return routing.readOnly ? '可写性未确认 · 当前只读' : '可写 · 写入面在路由表';
    }
    if (key === 'flowObjects') return '地区 / 计划可写，其余类型只读';
    const flowd = state.source.flowd.data;
    if (!flowd) return '只读快照';
    if (!flowd.readOnly) return '可新增、编辑与删除';
    return flowd.capabilityKnown ? '只读 · flowd 声明不可写' : '可写性未确认 · 当前只读';
  }

  function activeSourceMarkup() {
    if (state.tab === 'overview') return overviewSourcesMarkup();
    if (state.tab === 'routing') return routingMarkup();
    if (state.tab === 'flowObjects') return flowObjectsMarkup();
    if (state.tab === 'flowd') return flowdMarkup();
    return compositeMarkup();
  }

  /*
   * 概览页除了四张卡片，还列出每个来源的读取状态。只放卡片会让这一页除了
   * 四个数字之外没有信息量；而「某个来源为什么显示 --」恰好是看概览时最想
   * 知道的事，它原先只在切到对应 tab 之后才看得到。
   */
  function overviewSourcesMarkup() {
    /* 说明列按各来源真实可写性分述，不再一律写「只读快照」。 */
    const rows = [
      ['composite', '复合策略对象', '/api/v1/policy-engine/objects'],
      ['routing', '路由对象', '/api/v1/routing/objects'],
      ['flowObjects', '流量对象', '/api/v1/flowd/objects'],
      ['flowd', '自定义协议', '/api/v1/flowd/custom-protocols']
    ].map(([key, label, endpoint]) => {
      const problem = key === 'composite' ? null : sourceTerminal(key);
      const count = key === 'composite'
        ? (state.composite?.items.length ?? 0)
        : (state.source[key]?.data?.items.length ?? null);
      const tone = problem ? (problem.name === 'loading' ? 'muted' : 'warning') : 'success';
      const stateText = problem ? problem.title : '已读取';
      return `<tr><td><strong>${escapeHtml(label)}</strong><small>${escapeHtml(endpoint)}</small></td><td>${escapeHtml(count === null ? '--' : String(count))}</td><td>${statusBadge(stateText, tone)}</td><td>${escapeHtml(problem?.detail || sourceWritability(key))}</td></tr>`;
    }).join('');
    return `<section class="policy-entity-table policy-object-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>来源读取状态</strong><span>四类对象各自的权威接口与当前可读性</span></div><span class="dwrt-kit-table-count">4 个来源</span></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table"><thead><tr><th>来源</th><th>数量</th><th>状态</th><th>说明</th></tr></thead><tbody>${rows}</tbody></table></div></section>`;
  }

  function workbenchMarkup() {
    /*
     * 四张状态卡片只属于「概览」这一页。原先它们在每个 tab 上都重复出现，
     * 于是看「路由对象」时还要先跳过一排跟当前视图无关的汇总数字，
     * 而那排数字里正好有一张就是当前 tab 自己的条数。
     */
    const overview = state.tab === 'overview' ? overviewMarkup() : '';
    const sourceView = `<section class="policy-object-source-view" data-object-source-view="${state.tab}">${activeSourceMarkup()}</section>`;
    /*
     * 页头徽章按当前 tab 判定，不再固定写「只读分类」。
     *
     * 流量对象页已经可以建 / 改 / 删 country 与 time，固定挂只读徽章会直接跟同一页
     * 上的「新建」按钮打对台。其余三个 tab 的只读结论没有变化，仍照原样呈现 ——
     * 路由对象与自定义协议的只读是否也该解开，属另一份交接单
     * （Acceptance-to-Front-policy-objects-hardcoded-readonly-hides-real-writes.md），
     * 本单不越界处理。
     */
    const badge = headerBadge();
    return `<section class="policy-entity-page policy-objects-page"><header class="policy-object-toolbar" data-adaptive-sample>${tabsMarkup()}<div class="policy-entity-header-actions"><span class="policy-object-readonly-status">${badge}</span></div></header><main class="policy-object-workbench">${overview}${sourceView}</main></section>`;
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
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-object-detail-close aria-label="关闭对象详情"></button><aside data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" class="dwrt-kit-sheet policy-entity-sheet is-open"><header class="dwrt-kit-sheet-header"><div><span>${escapeHtml(title)}</span><strong>${escapeHtml(item.name)}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-object-detail-close aria-label="关闭">${icon('x')}</button></header><div class="dwrt-kit-sheet-body policy-entity-sheet-body"><dl class="policy-entity-detail-list">${fields.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`).join('')}</dl>${referenceMarkup}${detailWritabilityPanel(kind, item)}</div><footer class="dwrt-kit-sheet-footer"><span></span>${button('关闭', 'data-object-detail-close', 'primary')}</footer></aside>`;
  }

  /*
   * 详情抽屉底部那块可写性说明。原先是三层嵌套三元，flowd 那支写死「尚未声明可写
   * 能力位」，能力位到位后就成了假陈述。拆开按来源分述，判据一律取当前载荷。
   */
  function detailWritabilityPanel(kind, item) {
    const runtimeNote = (data) => {
      if (!data?.runtimeApplyKnown || data.runtimeApply) return '';
      const reason = runtimeApplyReasonText(data.runtimeApplyReason);
      return `配置落库后运行态仍未应用（<code>runtime_apply=false</code>${reason ? `：${reason}` : ''}）。`;
    };
    if (kind === 'flowObjects') {
      const data = state.source.flowObjects.data;
      if (isEditableFlowObject(item)) return statePanel('empty', '此对象可在本页编辑', `配置写入 flowd 配置库。${runtimeNote(data) || '当前只确认 flowd 配置存储与内部引用，未提供运行态应用证明。'}`);
      const gate = data && !data.readOnly
        ? `flowd 已声明 object_crud=true，写通道开放；本页尚未为该类型建表单，因为它的取值语义还没有校验落点。`
        : `本页只开放 ${EDITABLE_TYPE_LABELS.country} 与 ${EDITABLE_TYPE_LABELS.time} 两类对象的写入，其余类型仍只读。`;
      return statePanel('unavailable', '此类型在本页只读', `${gate}${runtimeNote(data)}`);
    }
    if (kind === 'routing') {
      const routing = state.source.routing.data;
      if (routing && !routing.readOnly) return statePanel('unavailable', '此对象可写，写入面在路由表', 'routed 已声明 object_crud，路由对象可增删改；写入面在“策略引擎 → 路由表”，本页只做查看。');
      return statePanel('unavailable', '此来源在对象页只读', '路由对象由“策略引擎 → 路由表”管理；routed 本次未声明 object_crud，可写性未确认。');
    }
    if (kind === 'flowd') {
      const data = state.source.flowd.data;
      if (data && !data.readOnly) return statePanel('empty', '此协议可在本页编辑', `配置写入 flowd 配置库。${runtimeNote(data) || '运行态是否应用以 flowd 返回的能力位为准。'}`);
      if (data?.capabilityKnown) return statePanel('unavailable', '此来源在对象页只读', 'flowd 声明 custom_protocol_crud=false，写入通道未开放。');
      return statePanel('unavailable', '写入能力未确认', '自定义协议的写入端点已在后端注册，但本次载荷未声明可写能力位，因此本页暂不放出编辑入口；这不等于后端不支持。');
    }
    return statePanel('unavailable', '此来源在对象页只读', '复合对象写入需要跨组件原子事务，能力未开放前保持 fail-closed。');
  }

  function formatFlowObjectValue(value) {
    if (Array.isArray(value)) return value.map((entry) => typeof entry === 'string' ? entry : JSON.stringify(entry)).join('、') || '--';
    if (value && typeof value === 'object') return JSON.stringify(value);
    return sourceText(value, '--');
  }

  const EDITABLE_TYPE_LABELS = { country: '地区', time: '计划' };

  function isEditableFlowObject(item) {
    return Boolean(item) && FLOW_OBJECT_EDITABLE_TYPES.includes(item.type);
  }

  /*
   * 地区对象的取值必须是国家码，候选项来自后端目录。目录没读到时不放行保存 ——
   * 前端自造一份国家码列表就等于绕开 flowd_countries_normalize() 的权威判据。
   */
  async function loadCountryCatalog() {
    if (state.countries.status === 'loading' || state.countries.status === 'ready') return;
    if (typeof api.request !== 'function') {
      state.countries = { status: 'unavailable', items: [], error: '页面没有获得 API 请求能力。' };
      return;
    }
    state.countries = { status: 'loading', items: [], error: '' };
    renderOverlay();
    try {
      const payload = await api.request('policy-object-country-catalog', '/api/v1/firewall/geo-block', { method: 'GET' });
      const items = normalizeCountryCatalog(payload);
      if (!state.mounted) return;
      state.countries = items.length
        ? { status: 'ready', items, error: '' }
        : { status: 'unavailable', items: [], error: '后端国家或地区目录为空。' };
    } catch (error) {
      if (!state.mounted || signal?.aborted) return;
      state.countries = {
        status: error?.status === 403 ? 'forbidden' : 'error',
        items: [],
        error: error?.status === 403 ? '当前账号没有读取国家或地区目录的权限。' : (error?.message || '国家或地区目录读取失败。')
      };
    }
    renderOverlay();
  }

  function openEditor(type, item = null) {
    if (!EDITABLE_TYPE_LABELS[type]) return;
    state.detail = null;
    state.notice = '';
    state.editor = item
      ? {
        mode: 'edit',
        type: item.type,
        id: item.id,
        name: item.name,
        remark: item.remark,
        enabled: item.enabled,
        codes: item.type === 'country' ? (Array.isArray(item.value) ? item.value.map((code) => String(code).toUpperCase()) : []) : [],
        time: item.type === 'time' ? flowTimeDraftFromValue(item.value) : flowTimeDraftFromValue(null),
        search: '',
        error: ''
      }
      : {
        mode: 'create',
        type,
        id: '',
        name: '',
        remark: '',
        enabled: true,
        codes: [],
        time: flowTimeDraftFromValue(null),
        search: '',
        error: ''
      };
    renderPage();
    renderOverlay();
    if (type === 'country') loadCountryCatalog();
  }

  function closeEditor() {
    state.editor = null;
    renderPage();
    renderOverlay();
  }

  const PROTOCOL_KIND_OPTIONS = [['l3', 'L3'], ['l4', 'L4'], ['l7', 'L7'], ['dpi', 'DPI']];
  const PROTOCOL_OPTIONS = [
    ['any', '任意'], ['all', '全部'], ['tcp', 'TCP'], ['udp', 'UDP'],
    ['icmp', 'ICMP'], ['icmpv6', 'ICMPv6'], ['gre', 'GRE'], ['esp', 'ESP'], ['ah', 'AH']
  ];

  function utf8Size(value) {
    const text = String(value ?? '');
    if (typeof TextEncoder === 'function') return new TextEncoder().encode(text).length;
    return encodeURIComponent(text).replace(/%[0-9A-F]{2}|./gi, 'x').length;
  }

  function protocolDraftFromItem(item = null) {
    const protoText = sourceText(item?.proto, 'tcp').toLowerCase();
    const knownProto = PROTOCOL_OPTIONS.some(([value]) => value === protoText);
    return {
      mode: item ? 'edit' : 'create',
      id: sourceText(item?.id),
      name: sourceText(item?.name),
      enabled: item?.enabled !== false,
      priority: String(Number.isInteger(item?.priority) ? item.priority : 1000),
      kind: PROTOCOL_KIND_OPTIONS.some(([value]) => value === item?.kind) ? item.kind : 'l4',
      protoMode: knownProto ? protoText : 'number',
      protoNumber: knownProto ? '' : protoText,
      srcPort: sourceText(item?.srcPort),
      dstPort: sourceText(item?.dstPort),
      matchJson: JSON.stringify(item?.match && typeof item.match === 'object' && !Array.isArray(item.match) ? item.match : {}, null, 2),
      tagsText: Array.isArray(item?.tags) ? item.tags.join(', ') : '',
      remark: sourceText(item?.remark),
      error: ''
    };
  }

  function openProtocolEditor(item = null) {
    const data = state.source.flowd.data;
    if (!data || data.readOnly) return;
    state.detail = null;
    state.editor = null;
    state.protocolNotice = '';
    state.protocolEditor = protocolDraftFromItem(item);
    renderPage();
    renderOverlay();
  }

  function closeProtocolEditor() {
    state.protocolEditor = null;
    renderPage();
    renderOverlay();
  }

  function protocolPortError(label, value) {
    const text = sourceText(value).toLowerCase();
    if (!text || text === 'any') return '';
    if (text.includes(',')) return `${label}不支持逗号列表；多个端口请拆成多条协议。`;
    const match = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(text);
    if (!match) return `${label}只支持单端口、起止范围或 any。`;
    const start = Number(match[1]);
    const end = Number(match[2] || match[1]);
    if (start < 1 || start > 65535 || end < 1 || end > 65535) return `${label}必须在 1 到 65535 之间。`;
    if (start > end) return `${label}的起始端口不能大于结束端口。`;
    return '';
  }

  function protocolEditorPayload() {
    const draft = state.protocolEditor;
    if (!draft) return { error: '编辑状态已丢失。' };
    const name = sourceText(draft.name);
    if (!name) return { error: '请填写名称。' };
    if (utf8Size(name) > 128) return { error: '名称不能超过 128 字节。' };
    const remark = sourceText(draft.remark);
    if (utf8Size(remark) > 256) return { error: '备注不能超过 256 字节。' };
    const priority = Number(draft.priority);
    if (!Number.isInteger(priority) || priority < 0 || priority > 1000000) return { error: '优先级必须是 0 到 1000000 之间的整数。' };
    if (!PROTOCOL_KIND_OPTIONS.some(([value]) => value === draft.kind)) return { error: '请选择有效的协议层级。' };
    let proto = draft.protoMode;
    if (draft.protoMode === 'number') {
      const protocolNumber = Number(draft.protoNumber);
      if (!Number.isInteger(protocolNumber) || protocolNumber < 0 || protocolNumber > 255) return { error: '协议号必须是 0 到 255 之间的整数。' };
      proto = protocolNumber;
    } else if (!PROTOCOL_OPTIONS.some(([value]) => value === draft.protoMode)) {
      return { error: '请选择有效的协议。' };
    }
    const srcPortError = protocolPortError('源端口', draft.srcPort);
    if (srcPortError) return { error: srcPortError };
    const dstPortError = protocolPortError('目标端口', draft.dstPort);
    if (dstPortError) return { error: dstPortError };
    let match;
    try {
      match = JSON.parse(sourceText(draft.matchJson, '{}'));
    } catch {
      return { error: '匹配条件必须是有效的 JSON 对象。' };
    }
    if (!match || typeof match !== 'object' || Array.isArray(match)) return { error: '匹配条件必须是 JSON 对象，不能是数组或基础值。' };
    if (utf8Size(JSON.stringify(match)) > 8192) return { error: '匹配条件不能超过 8192 字节。' };
    const tags = String(draft.tagsText || '').split(/[\n,]/).map((tag) => tag.trim()).filter(Boolean);
    if (utf8Size(JSON.stringify(tags)) > 8192) return { error: '标签列表不能超过 8192 字节。' };
    const body = {
      name,
      enabled: draft.enabled !== false,
      priority,
      kind: draft.kind,
      proto,
      src_port: sourceText(draft.srcPort).toLowerCase(),
      dst_port: sourceText(draft.dstPort).toLowerCase(),
      match,
      tags: [...new Set(tags)],
      remark
    };
    if (draft.mode === 'edit') body.id = draft.id;
    return { body };
  }

  async function submitProtocolEditor() {
    if (state.saving || !state.protocolEditor) return;
    const data = state.source.flowd.data;
    if (!data || data.readOnly) {
      state.protocolEditor.error = 'flowd 未声明自定义协议写入能力。';
      renderOverlay();
      return;
    }
    const prepared = protocolEditorPayload();
    if (prepared.error) {
      state.protocolEditor.error = prepared.error;
      renderOverlay();
      return;
    }
    if (typeof api.request !== 'function') {
      state.protocolEditor.error = '页面没有获得 API 请求能力。';
      renderOverlay();
      return;
    }
    const creating = state.protocolEditor.mode === 'create';
    state.saving = true;
    state.protocolEditor.error = '';
    renderOverlay();
    try {
      await api.request('policy-object-custom-protocol-save', '/api/v1/flowd/custom-protocols', { method: 'POST', body: prepared.body });
      if (!state.mounted) return;
      state.saving = false;
      state.protocolEditor = null;
      state.protocolNotice = `${creating ? '已创建' : '已保存'}自定义协议「${prepared.body.name}」${data.runtimeApplyKnown && !data.runtimeApply ? '，配置已落库，数据面尚未应用。' : '。'}`;
      renderPage();
      renderOverlay();
      await refresh();
    } catch (error) {
      if (!state.mounted || signal?.aborted) return;
      state.saving = false;
      if (state.protocolEditor) state.protocolEditor.error = protocolWriteErrorText(error);
      renderOverlay();
    }
  }

  function editorPayload() {
    const draft = state.editor;
    if (!draft) return { error: '编辑状态已丢失。' };
    const name = sourceText(draft.name);
    if (!name) return { error: '请填写名称。' };
    if (name.length > 128) return { error: '名称不能超过 128 个字符。' };
    if (sourceText(draft.remark).length > 256) return { error: '备注不能超过 256 个字符。' };
    let value;
    if (draft.type === 'country') {
      if (state.countries.status !== 'ready') return { error: '国家或地区目录尚不可用，无法校验取值。' };
      if (!draft.codes.length) return { error: '请至少选择一个国家或地区。' };
      value = draft.codes.map((code) => String(code).toUpperCase());
    } else {
      value = flowTimeValueFromDraft(draft.time);
      if (!value) return { error: '请填写有效的开始与结束时间，且两者不能相同。' };
      if (!draft.time.days.length) return { error: '请至少选择一个生效日。' };
    }
    const taken = (state.source.flowObjects.data?.items || []).map((item) => item.id);
    const id = draft.mode === 'edit' ? draft.id : flowObjectIdFromName(draft.type, name, taken);
    return {
      body: {
        id,
        type: draft.type,
        name,
        remark: sourceText(draft.remark),
        enabled: draft.enabled !== false,
        value
      }
    };
  }

  async function submitEditor() {
    if (state.saving || !state.editor) return;
    const prepared = editorPayload();
    if (prepared.error) {
      state.editor.error = prepared.error;
      renderOverlay();
      return;
    }
    if (typeof api.request !== 'function') {
      state.editor.error = '页面没有获得 API 请求能力。';
      renderOverlay();
      return;
    }
    const label = EDITABLE_TYPE_LABELS[state.editor.type];
    const creating = state.editor.mode === 'create';
    state.saving = true;
    state.editor.error = '';
    renderOverlay();
    try {
      /*
       * 这里保持字面量端点，不改成 data.writeEndpoint。
       * test_policy_entities_phase2_contract.mjs 靠静态扫描这两个字面量把本页的写调用
       * 框在 flowd 流量对象上（「不得顺手写别的资源」），改成表达式会让那道护栏失效。
       * 能力位下发的端点与此一致（30.1 实测 object_crud_write_endpoint=/api/v1/flowd/objects），
       * 且已用于文案展示；真要改成动态取值，得先替换那条护栏的判据，属另一份交接单。
       */
      await api.request('policy-object-flow-save', '/api/v1/flowd/objects', { method: 'POST', body: prepared.body });
      if (!state.mounted) return;
      state.saving = false;
      state.editor = null;
      state.notice = `${creating ? '已创建' : '已保存'}${label}对象「${prepared.body.name}」。`;
      renderPage();
      renderOverlay();
      await refresh();
    } catch (error) {
      if (!state.mounted || signal?.aborted) return;
      state.saving = false;
      if (state.editor) state.editor.error = flowWriteErrorText(error);
      renderOverlay();
    }
  }

  async function submitRemove() {
    const target = state.removing;
    if (state.saving || !target) return;
    if (typeof api.request !== 'function') {
      state.removing = { ...target, error: '页面没有获得 API 请求能力。' };
      renderOverlay();
      return;
    }
    state.saving = true;
    renderOverlay();
    try {
      if (target.resource === 'protocol') {
        await api.request('policy-object-custom-protocol-delete', '/api/v1/flowd/custom-protocols/delete', { method: 'POST', body: { id: target.id } });
      } else {
        await api.request('policy-object-flow-delete', '/api/v1/flowd/objects/delete', { method: 'POST', body: { id: target.id } });
      }
      if (!state.mounted) return;
      state.saving = false;
      state.removing = null;
      if (target.resource === 'protocol') {
        const data = state.source.flowd.data;
        state.protocolNotice = `已删除自定义协议「${target.name}」${data?.runtimeApplyKnown && !data.runtimeApply ? '，配置已更新，数据面尚未应用。' : '。'}`;
      } else {
        state.notice = `已删除对象「${target.name}」。`;
      }
      renderPage();
      renderOverlay();
      await refresh();
    } catch (error) {
      if (!state.mounted || signal?.aborted) return;
      state.saving = false;
      state.removing = { ...target, error: target.resource === 'protocol' ? protocolWriteErrorText(error) : flowWriteErrorText(error) };
      renderOverlay();
    }
  }

  /*
   * flowd 的写入失败原样呈现后端判据，不吞掉改说成成功。`reference_conflict`
   * 是删除被引用对象时的正常拒绝（flowd_db.c 里先查引用再决定），要说清原因。
   */
  function flowWriteErrorText(error) {
    const code = sourceText(error?.payload?.error?.code, error?.payload?.code);
    const known = {
      reference_conflict: '该对象正被 flowd 规则引用，先解除引用再删除。',
      not_found: '该对象已不存在，请刷新列表。',
      invalid_id: '对象标识不合法。',
      invalid_type: '对象类型不合法。',
      invalid_request: '请求体不合法，后端拒绝了本次写入。',
      partial_or_failed_save: '后端未能保存该对象，取值可能未通过校验。',
      storage_error: 'flowd 配置库当前不可写。'
    };
    if (known[code]) return known[code];
    if (error?.status === 403) return '当前账号没有写入 flowd 流量对象的权限。';
    return error?.message || '写入失败。';
  }

  function protocolWriteErrorText(error) {
    const code = sourceText(error?.payload?.error?.code, error?.payload?.error, error?.payload?.code);
    const known = {
      invalid_id: '协议标识不合法。',
      not_found: '该自定义协议已不存在，请刷新列表。',
      invalid_request: '请求体不合法，后端拒绝了本次写入。',
      partial_or_failed_save: 'flowd 未能保存该协议。请检查名称、优先级、层级、协议号、端口、匹配条件和标签。',
      storage_error: 'flowd 配置库当前不可写。'
    };
    if (known[code]) return known[code];
    if (error?.status === 403) return '当前账号没有写入自定义协议的权限。';
    return error?.message || '自定义协议写入失败。';
  }

  function flowObjectReferencesMarkup(item) {
    if (!item.references.length) return `<section class="policy-object-reference-list"><h3>flowd 内部引用</h3>${statePanel('empty', '当前没有引用', '此结论仅覆盖 flowd 自身规则，不代表跨 routed、firewall 或 SQM 的统一 used-by。')}</section>`;
    return `<section class="policy-object-reference-list"><h3>flowd 内部引用</h3>${item.references.map((reference) => `<article><span><strong>${escapeHtml(reference.name)}</strong><small>${escapeHtml([reference.kind, reference.field, reference.id].filter(Boolean).join(' · '))}</small></span>${statusBadge(reference.enabled ? '启用' : '停用', reference.enabled ? 'success' : 'muted')}</article>`).join('')}</section>`;
  }

  function editorField(label, control, description = '') {
    return `<div data-dwrt-component="field" class="dwrt-kit-field"><span>${escapeHtml(label)}</span>${control}${description ? `<small data-dwrt-field-description>${escapeHtml(description)}</small>` : ''}</div>`;
  }

  function countryRowMarkup(item, codes) {
    const meta = [item.code, item.continent].filter(Boolean).join(' · ');
    return `<label class="policy-object-pick"><input type="checkbox" data-object-country="${escapeHtml(item.code)}" ${codes.includes(item.code) ? 'checked' : ''}><span><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(meta)}</small></span></label>`;
  }

  function countryPickerMarkup(draft) {
    const catalog = state.countries;
    if (catalog.status === 'loading') return statePanel('loading', '正在读取国家或地区目录', '候选项来自后端权威目录，读取完成后才可勾选。');
    if (catalog.status !== 'ready') {
      return statePanel(catalog.status === 'forbidden' ? 'forbidden' : 'unavailable', '国家或地区目录不可用',
        `${catalog.error || '目录读取失败。'}取值必须由后端目录提供，页面不会自造国家码列表，因此当前无法保存地区对象。`);
    }
    const query = sourceText(draft.search).toLowerCase();
    const options = catalog.items.filter((item) => !query
      || item.code.toLowerCase().includes(query)
      || item.name.toLowerCase().includes(query)
      || item.continent.toLowerCase().includes(query));
    const rows = options.map((item) => countryRowMarkup(item, draft.codes)).join('');
    return `<div class="policy-object-picker-field"><div class="policy-object-picker-toolbar"><label class="policy-object-picker-search" data-dwrt-component="field">${icon('search')}<input type="search" data-object-country-search value="${escapeHtml(draft.search)}" placeholder="搜索国家或地区" aria-label="搜索国家或地区"></label><span>已选 ${draft.codes.length} / 可选 ${catalog.items.length}</span></div><div class="policy-object-pick-list">${rows || statePanel('empty', '没有匹配的国家或地区', '换一个关键词再试。')}</div></div>`;
  }

  function timeEditorMarkup(draft) {
    const time = draft.time;
    return `<div class="policy-object-time-grid">${editorField('开始时间', `<input type="time" data-object-time="start" value="${escapeHtml(time.start)}">`)}${editorField('结束时间', `<input type="time" data-object-time="end" value="${escapeHtml(time.end)}">`)}</div>${editorField('生效日', `<div class="policy-object-weekdays">${WEEKDAY_LABELS.map(([key, label]) => `<label class="policy-object-weekday"><input type="checkbox" data-object-weekday="${escapeHtml(key)}" ${time.days.includes(key) ? 'checked' : ''}><span>${escapeHtml(label)}</span></label>`).join('')}</div>`, '结束时间早于开始时间表示跨零点的窗口。')}`;
  }

  function protocolEditorMarkup() {
    const draft = state.protocolEditor;
    if (!draft) return '';
    const title = `${draft.mode === 'create' ? '新建' : '编辑'}自定义协议`;
    const protoOptions = `${PROTOCOL_OPTIONS.map(([value, label]) => `<option value="${escapeHtml(value)}" ${draft.protoMode === value ? 'selected' : ''}>${escapeHtml(label)}</option>`).join('')}<option value="number" ${draft.protoMode === 'number' ? 'selected' : ''}>协议号</option>`;
    const errorMarkup = draft.error ? `<div class="policy-entity-alert is-warning" role="alert"><strong>无法保存</strong><span>${escapeHtml(draft.error)}</span></div>` : '';
    const idField = draft.mode === 'edit'
      ? editorField('协议标识', `<input type="text" value="${escapeHtml(draft.id)}" disabled>`, '标识创建后不可更改。')
      : '';
    const protoNumberField = draft.protoMode === 'number'
      ? editorField('协议号', `<input type="number" min="0" max="255" step="1" data-protocol-draft="protoNumber" value="${escapeHtml(draft.protoNumber)}" placeholder="0 - 255">`)
      : '';
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-protocol-editor-close aria-label="关闭编辑"></button><aside data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" class="dwrt-kit-sheet policy-entity-sheet policy-object-editor-sheet policy-protocol-editor-sheet is-open"><header class="dwrt-kit-sheet-header"><div><span>flowd 自定义协议</span><strong>${escapeHtml(title)}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-protocol-editor-close aria-label="关闭">${icon('x')}</button></header><div class="dwrt-kit-sheet-body policy-entity-sheet-body">${errorMarkup}<div class="policy-entity-alert" role="status"><strong>配置写入 flowd</strong><span>端口只接受单端口、起止范围或 any；多个端口请拆成多条协议。保存成功不代表已经应用到数据面。</span></div>${editorField('名称', `<input type="text" data-protocol-draft="name" value="${escapeHtml(draft.name)}" placeholder="例如 内网 RTSP" maxlength="128">`)}${idField}<div class="policy-protocol-grid">${editorField('层级', `<select class="dwrt-kit-select" data-dwrt-component="select" data-protocol-draft="kind">${PROTOCOL_KIND_OPTIONS.map(([value, label]) => `<option value="${value}" ${draft.kind === value ? 'selected' : ''}>${label}</option>`).join('')}</select>`)}${editorField('协议', `<select class="dwrt-kit-select" data-dwrt-component="select" data-protocol-draft="protoMode">${protoOptions}</select>`)}${protoNumberField}${editorField('优先级', `<input type="number" min="0" max="1000000" step="1" data-protocol-draft="priority" value="${escapeHtml(draft.priority)}">`, '数值越小越先匹配。')}</div><div class="policy-protocol-grid">${editorField('源端口', `<input type="text" inputmode="numeric" data-protocol-draft="srcPort" value="${escapeHtml(draft.srcPort)}" placeholder="any、443 或 1000-2000">`)}${editorField('目标端口', `<input type="text" inputmode="numeric" data-protocol-draft="dstPort" value="${escapeHtml(draft.dstPort)}" placeholder="any、554 或 8000-8999">`)}</div>${editorField('匹配条件', `<textarea class="policy-protocol-json" data-protocol-draft="matchJson" rows="6" spellcheck="false" placeholder="{}">${escapeHtml(draft.matchJson)}</textarea>`, '必须是 JSON 对象，不能是数组。')}${editorField('标签', `<textarea data-protocol-draft="tagsText" rows="2" placeholder="media, camera">${escapeHtml(draft.tagsText)}</textarea>`, '使用逗号或换行分隔，保存时去重。')}${editorField('备注', `<textarea data-protocol-draft="remark" rows="2" maxlength="256" placeholder="可选">${escapeHtml(draft.remark)}</textarea>`)}<label class="policy-object-enable-check"><input type="checkbox" data-protocol-enabled ${draft.enabled ? 'checked' : ''}><span><strong>启用</strong><small>停用后保留配置，但不参与匹配。</small></span></label></div><footer class="dwrt-kit-sheet-footer"><span></span><div>${button('取消', 'data-protocol-editor-close', 'secondary')}${button(state.saving ? '保存中…' : '保存', `data-protocol-editor-submit ${state.saving ? 'disabled' : ''}`, 'primary')}</div></footer></aside>`;
  }

  function editorMarkup() {
    const draft = state.editor;
    if (!draft) return '';
    const label = EDITABLE_TYPE_LABELS[draft.type];
    const title = `${draft.mode === 'create' ? '新建' : '编辑'}${label}对象`;
    const body = draft.type === 'country'
      ? `${editorField('国家或地区', countryPickerMarkup(draft), '取值由 flowd 归一化校验，非法国家码后端会直接拒绝。')}`
      : timeEditorMarkup(draft);
    const idField = draft.mode === 'edit'
      ? editorField('对象标识', `<input type="text" value="${escapeHtml(draft.id)}" disabled>`, '标识创建后不可更改。')
      : '';
    const errorMarkup = draft.error ? `<div class="policy-entity-alert is-warning" role="alert"><strong>无法保存</strong><span>${escapeHtml(draft.error)}</span></div>` : '';
    const hint = draft.type === 'country'
      ? '保存后即可在策略表的「地区」选择器里选到它。'
      : '保存后成为 flowd 的 schedule_set 计划对象。当前策略表的「计划」用的是内置时间控件，不读这份目录。';
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-object-editor-close aria-label="关闭编辑"></button><aside data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" class="dwrt-kit-sheet policy-entity-sheet policy-object-editor-sheet is-open"><header class="dwrt-kit-sheet-header"><div><span>flowd 流量对象</span><strong>${escapeHtml(title)}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-object-editor-close aria-label="关闭">${icon('x')}</button></header><div class="dwrt-kit-sheet-body policy-entity-sheet-body">${errorMarkup}<div class="policy-entity-alert" role="status"><strong>写入 flowd 配置库</strong><span>${escapeHtml(hint)}</span></div>${editorField('名称', `<input type="text" data-object-draft="name" value="${escapeHtml(draft.name)}" placeholder="${escapeHtml(draft.type === 'country' ? '例如 海外常用地区' : '例如 工作时段')}" maxlength="128">`)}${idField}${body}${editorField('备注', `<textarea data-object-draft="remark" rows="2" maxlength="256" placeholder="可选">${escapeHtml(draft.remark)}</textarea>`)}<label class="policy-object-enable-check"><input type="checkbox" data-object-draft-enabled ${draft.enabled ? 'checked' : ''}><span><strong>启用</strong><small>停用的对象仍保留在配置里，但不参与规则匹配。</small></span></label></div><footer class="dwrt-kit-sheet-footer"><span></span><div>${button('取消', 'data-object-editor-close', 'secondary')}${button(state.saving ? '保存中…' : '保存', `data-object-editor-submit ${state.saving ? 'disabled' : ''}`, 'primary')}</div></footer></aside>`;
  }

  function removeMarkup() {
    const target = state.removing;
    if (!target) return '';
    const description = target.error
      ? target.error
      : target.resource === 'protocol'
        ? `将从 flowd 配置库删除自定义协议「${target.name}」。后端当前没有引用保护，引用这条协议的规则也不会阻止删除；删除后不可撤销。`
        : `将从 flowd 配置库删除「${target.name}」。引用它的规则会失去这个匹配条件，删除后不可撤销。`;
    return ui.confirmationMarkup?.({
      id: 'policy-object-remove',
      action: 'policy-object-remove',
      tone: 'danger',
      title: `${target.resource === 'protocol' ? '删除自定义协议' : '删除对象'}「${target.name}」`,
      description,
      confirmLabel: state.saving ? '删除中…' : '删除',
      cancelLabel: '取消',
      disabled: state.saving
    }) || '';
  }

  function replaceMarkup(host, markup) {
    /*
     * 先把已被搬进传送门的抽屉收回来，再交给 kit 卸载。
     *
     * kit 的 mountAll() 会把 `.dwrt-kit-sheet` 连同遮罩搬到 body 直属的
     * #dwrtKitSheetPortal，而 kit 的 unmount(host) 只在 host 子树内查找抽屉。
     * 抽屉搬走后 host 里空无一物，unmountSheet() 不会执行，抽屉和那层 `is-open`
     * 遮罩就永久留在传送门里：关闭后遮罩仍盖住页面吞掉所有点击，必须刷新才能继续。
     * 实测每开关一轮传送门多出 2 个节点，第二轮起抽屉的 left 还会错位到视口之外。
     */
    reclaimPortaledSheets(host);
    window.DWRT_UI_KIT?.unmount?.(host);
    host.replaceChildren(document.createRange().createContextualFragment(markup));
    /* 打归属标记：抽屉一旦被搬进传送门，只能靠这个标记认回自己的节点。 */
    host.querySelectorAll('.dwrt-kit-sheet, .dwrt-kit-sheet-overlay')
      .forEach((node) => { node.dataset.objectOverlayOwned = ''; });
    ui.mountAll?.(host);
  }

  /* 把本宿主搬出去的抽屉与遮罩接回来，让 kit 的 unmount 能够看到它们。 */
  function reclaimPortaledSheets(host) {
    const portal = document.getElementById('dwrtKitSheetPortal');
    if (!portal) return;
    portal.querySelectorAll('.dwrt-kit-sheet, .dwrt-kit-sheet-overlay').forEach((node) => {
      if (node.dataset.objectOverlayOwned === undefined) return;
      host.append(node);
    });
  }

  function renderPage() {
    if (!root || !state.mounted) return;
    replaceMarkup(pageHost, workbenchMarkup());
    const selectedTab = pageHost.querySelector('[data-object-tab][aria-selected="true"]');
    selectedTab?.scrollIntoView?.({ block: 'nearest', inline: 'center' });
  }

  /*
   * 轮询刷新走 kit 的共享保状态入口（Acceptance P0 单）。
   *
   * 只有页面主体走这条路：抽屉宿主仍用 replaceMarkup()，因为抽屉会被 kit 搬进传送门，
   * 归属标记与回收逻辑都挂在整块替换那条路径上，morph 一棵被搬走的子树只会两头都错。
   */
  function renderPagePreservingInteraction() {
    const preserve = ui.preserveInteractionState;
    if (typeof preserve === 'function' && preserve(pageHost, (target) => {
      target.replaceChildren(document.createRange().createContextualFragment(workbenchMarkup()));
    })) {
      ui.mountAll?.(pageHost);
      return;
    }
    renderPage();
  }

  function renderOverlay() {
    if (!root || !state.mounted) return;
    /*
     * 三层叠加各自独立：编辑抽屉与删除确认优先于详情抽屉，同一时刻只渲染一个，
     * 否则两张 sheet 会同时被 kit 搬进传送门、抢同一个遮罩。
     */
    replaceMarkup(overlayHost, state.removing ? removeMarkup() : state.protocolEditor ? protocolEditorMarkup() : state.editor ? editorMarkup() : detailMarkup());
  }

  function hydrate(snapshot) {
    state.snapshot = snapshot;
    if (snapshot?.value) state.composite = normalizePolicyObjects(snapshot.value);
    renderPagePreservingInteraction();
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
      renderPagePreservingInteraction();
    })().finally(() => {
      state.refreshPromise = null;
      if (state.mounted && state.refreshing) {
        state.refreshing = false;
        renderPagePreservingInteraction();
      }
    });
    return state.refreshPromise;
  }

  /*
   * 手动刷新按钮按用户第 9 条删除。registry 只按 TTL 缓存、不自轮询，
   * 三个附加来源更是纯手动拉取，所以这里补一条可见性受控的轮询；
   * 详情抽屉打开时跳过，避免正在看的那一行被整页重绘顶掉。
   */
  function startPolling() {
    stopPolling();
    state.pollTimer = window.setInterval(() => {
      if (!state.mounted) return;
      if (document.hidden) return;
      if (state.refreshing || state.refreshPromise) return;
      /* 编辑抽屉与删除确认打开时不轮询：整页重绘会把正在填的草稿顶掉。 */
      if (state.detail || state.editor || state.protocolEditor || state.removing || state.saving) return;
      refresh();
    }, 20000);
  }

  function stopPolling() {
    if (!state.pollTimer) return;
    window.clearInterval(state.pollTimer);
    state.pollTimer = 0;
  }

  /*
   * 抽屉会被 kit 的 elevateSheet() 搬到 body 直属的 #dwrtKitSheetPortal，
   * 从此不在 root 子树内。kit 的 bindSheetDelegation() 会把 click/input/change/
   * keydown 重放回路由根，所以监听仍然挂在 root 上；但重放事件的 target 是
   * 传送门里的真实节点，`root.contains(target)` 对它是 false。
   * 因此判归属要额外认 replaceMarkup() 打过 `data-object-overlay-owned` 的搬迁节点，
   * 否则抽屉里的每一次交互都会被当成别人的事件丢掉。
   */
  function ownsEvent(target) {
    if (!(target instanceof Node)) return false;
    if (root.contains(target)) return true;
    const node = target instanceof Element ? target : target.parentElement;
    return Boolean(node?.closest?.('[data-object-overlay-owned]'));
  }

  function onClick(event) {
    if (!ownsEvent(event.target)) return;
    const tab = event.target.closest('[data-object-tab]');
    if (tab) {
      state.tab = SOURCE_TABS.some(([id]) => id === tab.dataset.objectTab) ? tab.dataset.objectTab : 'overview';
      state.detail = null;
      renderPage();
      renderOverlay();
      return;
    }
    const create = event.target.closest('[data-object-create]');
    if (create) {
      openEditor(create.dataset.objectCreate);
      return;
    }
    if (event.target.closest('[data-protocol-create]')) {
      openProtocolEditor();
      return;
    }
    const protocolEdit = event.target.closest('[data-protocol-edit]');
    if (protocolEdit) {
      const item = state.source.flowd.data?.items.find((entry) => entry.id === protocolEdit.dataset.protocolEdit);
      if (item) openProtocolEditor(item);
      return;
    }
    const protocolRemove = event.target.closest('[data-protocol-remove]');
    if (protocolRemove) {
      const item = state.source.flowd.data?.items.find((entry) => entry.id === protocolRemove.dataset.protocolRemove);
      if (!item) return;
      state.detail = null;
      state.protocolNotice = '';
      state.removing = { resource: 'protocol', id: item.id, name: item.name, error: '' };
      renderPage();
      renderOverlay();
      return;
    }
    const edit = event.target.closest('[data-object-edit]');
    if (edit) {
      const item = state.source.flowObjects.data?.items.find((entry) => entry.id === edit.dataset.objectEdit);
      if (item) openEditor(item.type, item);
      return;
    }
    const remove = event.target.closest('[data-object-remove]');
    if (remove) {
      if (remove.disabled) return;
      const item = state.source.flowObjects.data?.items.find((entry) => entry.id === remove.dataset.objectRemove);
      if (!item) return;
      state.detail = null;
      state.notice = '';
      state.removing = { id: item.id, name: item.name, error: '' };
      renderPage();
      renderOverlay();
      return;
    }
    if (event.target.closest('[data-object-editor-close]')) {
      if (state.saving) return;
      closeEditor();
      return;
    }
    if (event.target.closest('[data-object-editor-submit]')) {
      submitEditor();
      return;
    }
    if (event.target.closest('[data-protocol-editor-close]')) {
      if (state.saving) return;
      closeProtocolEditor();
      return;
    }
    if (event.target.closest('[data-protocol-editor-submit]')) {
      submitProtocolEditor();
      return;
    }
    if (event.target.closest('[data-dwrt-confirm-accept]')) {
      submitRemove();
      return;
    }
    if (event.target.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]')) {
      if (state.saving) return;
      state.removing = null;
      renderOverlay();
      return;
    }
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

  /*
   * 文本与时间输入只更新 state，不重绘 —— 抽屉一旦整块 replaceMarkup，
   * 正在输入的框就会失焦，中文输入法还会把未上屏的候选字丢掉。
   * 需要改变可见结构的只有国家搜索（要过滤列表）和勾选（要更新计数）。
   */
  function onInput(event) {
    const protocolDraft = state.protocolEditor;
    if (protocolDraft && ownsEvent(event.target)) {
      const protocolField = event.target.closest('[data-protocol-draft]');
      if (protocolField) {
        protocolDraft[protocolField.dataset.protocolDraft] = protocolField.value;
        return;
      }
    }
    const draft = state.editor;
    if (!draft) return;
    if (!ownsEvent(event.target)) return;
    const field = event.target.closest('[data-object-draft]');
    if (field) {
      draft[field.dataset.objectDraft] = field.value;
      return;
    }
    const time = event.target.closest('[data-object-time]');
    if (time) {
      draft.time = { ...draft.time, [time.dataset.objectTime]: time.value };
      return;
    }
    const search = event.target.closest('[data-object-country-search]');
    if (search) {
      draft.search = search.value;
      patchCountryList();
    }
  }

  function onChange(event) {
    const protocolDraft = state.protocolEditor;
    if (protocolDraft && ownsEvent(event.target)) {
      const enabled = event.target.closest('[data-protocol-enabled]');
      if (enabled) {
        protocolDraft.enabled = enabled.checked;
        return;
      }
      const field = event.target.closest('[data-protocol-draft]');
      if (field) {
        const key = field.dataset.protocolDraft;
        protocolDraft[key] = field.value;
        if (key === 'protoMode') renderOverlay();
        return;
      }
    }
    const draft = state.editor;
    if (!draft) return;
    if (!ownsEvent(event.target)) return;
    const enabled = event.target.closest('[data-object-draft-enabled]');
    if (enabled) {
      draft.enabled = enabled.checked;
      return;
    }
    const country = event.target.closest('[data-object-country]');
    if (country) {
      const code = country.dataset.objectCountry;
      draft.codes = country.checked
        ? [...new Set([...draft.codes, code])]
        : draft.codes.filter((entry) => entry !== code);
      patchCountryCount();
      return;
    }
    const weekday = event.target.closest('[data-object-weekday]');
    if (weekday) {
      const key = weekday.dataset.objectWeekday;
      const days = weekday.checked
        ? [...new Set([...draft.time.days, key])]
        : draft.time.days.filter((entry) => entry !== key);
      draft.time = { ...draft.time, days };
    }
  }

  /* 抽屉可能已被搬进传送门，所以按归属标记全局找，而不是只在 overlayHost 里找。 */
  function editorNode(selector) {
    const local = overlayHost.querySelector(selector);
    if (local) return local;
    for (const owned of document.querySelectorAll('[data-object-overlay-owned]')) {
      if (owned.matches?.(selector)) return owned;
      const found = owned.querySelector?.(selector);
      if (found) return found;
    }
    return null;
  }

  /* 只换列表本体与计数，保住搜索框的焦点与光标位置。 */
  function patchCountryList() {
    const draft = state.editor;
    const list = editorNode('.policy-object-pick-list');
    if (!draft || !list || state.countries.status !== 'ready') return;
    const query = sourceText(draft.search).toLowerCase();
    const options = state.countries.items.filter((item) => !query
      || item.code.toLowerCase().includes(query)
      || item.name.toLowerCase().includes(query)
      || item.continent.toLowerCase().includes(query));
    /* 与本页其它替换保持同一写法：不用 innerHTML。 */
    const markup = options.length
      ? options.map((item) => countryRowMarkup(item, draft.codes)).join('')
      : statePanel('empty', '没有匹配的国家或地区', '换一个关键词再试。');
    list.replaceChildren(document.createRange().createContextualFragment(markup));
  }

  function patchCountryCount() {
    const draft = state.editor;
    const counter = editorNode('.policy-object-picker-toolbar > span');
    if (!draft || !counter || state.countries.status !== 'ready') return;
    counter.textContent = `已选 ${draft.codes.length} / 可选 ${state.countries.items.length}`;
  }

  function onKeydown(event) {
    if (event.key !== 'Escape') return;
    if (state.saving) return;
    if (!state.editor && !state.protocolEditor && !state.removing) return;
    if (state.removing) {
      state.removing = null;
      renderOverlay();
      return;
    }
    if (state.protocolEditor) {
      closeProtocolEditor();
      return;
    }
    if (state.editor) closeEditor();
  }

  root.hidden = false;
  root.className = 'route-preview route-workspace policy-objects-route-host';
  root.replaceChildren(pageHost, overlayHost);
  root.addEventListener('click', onClick);
  root.addEventListener('input', onInput);
  root.addEventListener('change', onChange);
  root.addEventListener('keydown', onKeydown);
  const unsubscribe = registry?.subscribe?.('policy.objects', hydrate) || null;
  renderPage();
  renderOverlay();
  if (registry) registry.request('policy.objects', { signal });
  Promise.allSettled([loadSource('routing'), loadSource('flowObjects'), loadSource('flowd')]).then(() => { if (state.mounted) renderPage(); });
  startPolling();

  return {
    refresh,
    unmount() {
      state.mounted = false;
      stopPolling();
      unsubscribe?.();
      root.removeEventListener('click', onClick);
      root.removeEventListener('input', onInput);
      root.removeEventListener('change', onChange);
      root.removeEventListener('keydown', onKeydown);
      window.DWRT_UI_KIT?.unmount?.(root);
      root.replaceChildren();
      root.classList.remove('route-workspace', 'policy-objects-route-host');
    }
  };
}

export default { mount };
