export function normalizePolicyRegions(payload = {}) {
  const list = (value) => Array.isArray(value) ? value : [];
  const text = (...values) => values.map((value) => String(value ?? '').trim()).find(Boolean) || '';
  const normalize = (zone = {}, index = 0, virtual = false) => ({
    id: text(zone.id, zone.name, `${virtual ? 'virtual' : 'zone'}-${index + 1}`),
    sectionId: text(zone.section_id),
    name: text(zone.name, zone.id),
    label: text(zone.display_name, zone.label, zone.name, `区域 ${index + 1}`),
    type: text(zone.type, virtual ? 'virtual' : 'custom'),
    members: list(zone.members).map(String).filter(Boolean),
    defaultActions: zone.default_actions && typeof zone.default_actions === 'object' ? zone.default_actions : {},
    locked: zone.locked === true || virtual,
    deleteLocked: zone.delete_locked === true || virtual,
    lockedFields: list(zone.locked_fields).map(String),
    ruleCount: Number(zone.rule_count) || 0,
    forwardingCount: Number(zone.forwarding_count) || 0,
    referenceCount: Number(zone.reference_count) || 0,
    virtual,
    raw: zone
  });
  const zones = list(payload.zones).map((zone, index) => normalize(zone, index));
  const virtualZones = list(payload.virtual_zones).map((zone, index) => normalize(zone, index, true));
  return {
    zones: [...zones, ...virtualZones],
    writableZones: zones,
    capabilities: payload.capabilities && typeof payload.capabilities === 'object' ? payload.capabilities : {},
    membershipUnique: payload.network_membership_unique === true,
    source: text(payload.source)
  };
}

export function normalizeZoneMatrix(payload = {}) {
  const list = (value) => Array.isArray(value) ? value : [];
  return {
    zoneIds: list(payload.zones).map(String).filter(Boolean),
    pairs: list(payload.pairs).map((pair = {}) => ({
      sourceId: String(pair.source_zone_id || ''),
      destinationId: String(pair.destination_zone_id || ''),
      action: String(pair.effective_action || 'block').toLowerCase(),
      returnAction: String(pair.return_action || 'allow_return'),
      forwarding: pair.forwarding_enabled === true,
      policyCount: Number(pair.policy_count) || 0,
      ipv4Count: Number(pair.ipv4_policy_count) || 0,
      ipv6Count: Number(pair.ipv6_policy_count) || 0,
      ruleIds: list(pair.rule_ids).map(String).filter(Boolean)
    })),
    capabilities: payload.capabilities && typeof payload.capabilities === 'object' ? payload.capabilities : {},
    source: String(payload.source || '')
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
    snapshots: { regions: null, matrix: null, policies: null, lans: null, wans: null },
    regions: null,
    matrix: null,
    policies: [],
    lans: [],
    wans: [],
    refreshing: false,
    refreshQueued: false,
    refreshPromise: null,
    sheet: null,
    draft: null,
    saving: false,
    feedback: '',
    feedbackTone: 'neutral',
    confirmDelete: false
  };
  const pageHost = document.createElement('div');
  const overlayHost = document.createElement('div');
  pageHost.className = 'policy-entity-page-host';
  overlayHost.className = 'policy-entity-overlay-host';
  const icon = (name) => window.DWRT_UI_KIT?.lucideIcon?.(name, { size: 18, strokeWidth: 1.8 }) || '';
  const list = (value, key = '') => Array.isArray(value) ? value : value && key && Array.isArray(value[key]) ? value[key] : [];
  const text = (...values) => values.map((value) => String(value ?? '').trim()).find(Boolean) || '';
  const clone = (value) => { try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value ?? null)); } };
  const statusBadge = (label, tone = 'muted') => ui.statusBadgeMarkup?.(label, tone) || `<span>${escapeHtml(label)}</span>`;
  const button = (label, attributes = '', variant = 'secondary', iconName = '') => `<button type="button" data-dwrt-component="button" data-variant="${variant}" ${attributes}>${iconName ? icon(iconName) : ''}<span>${escapeHtml(label)}</span></button>`;
  const statePanel = (name, title, detail) => `<section data-dwrt-component="state-panel" data-dwrt-state="${name}"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(detail)}</p></section>`;

  function normalizePolicies(payload = {}) {
    return list(payload, 'rows').map((row = {}, index) => ({
      id: text(row.id, `policy-${index + 1}`),
      name: text(row.name, `策略 ${index + 1}`),
      action: text(row.action, row.action_key, '--'),
      sourceZone: text(row.source_zone, row.raw?.src),
      destinationZone: text(row.destination_zone, row.raw?.dest),
      protocol: text(row.protocol, row.raw?.proto, '全部'),
      family: text(row.ip_version, row.family, row.raw?.family, '两者'),
      predefined: row.predefined === true
    }));
  }

  function normalizeNetworks(payload = {}, key, kind) {
    return list(payload, key).map((item = {}, index) => ({
      id: text(item.id, item.name, item.ifname, `${kind}-${index + 1}`),
      name: text(item.note, item.name, item.id, `${kind.toUpperCase()} ${index + 1}`),
      device: text(item.device, item.ifname),
      kind
    })).filter((item) => item.id);
  }

  function hydrate() {
    if (state.snapshots.regions?.value) state.regions = normalizePolicyRegions(state.snapshots.regions.value);
    if (state.snapshots.matrix?.value) state.matrix = normalizeZoneMatrix(state.snapshots.matrix.value);
    if (state.snapshots.policies?.value) state.policies = normalizePolicies(state.snapshots.policies.value);
    if (state.snapshots.lans?.value) state.lans = normalizeNetworks(state.snapshots.lans.value, 'lans', 'lan');
    if (state.snapshots.wans?.value) state.wans = normalizeNetworks(state.snapshots.wans.value, 'wans', 'wan');
  }

  function pageState() {
    if (!registry) return { name: 'unavailable', title: '区域数据合同不可用', detail: '当前页面没有获得共享 DataRegistry。' };
    const required = [state.snapshots.regions, state.snapshots.matrix];
    const terminal = required.find((snapshot) => ['forbidden', 'error', 'unavailable'].includes(snapshot?.status) && snapshot.value === undefined);
    if (terminal) {
      if (terminal.status === 'forbidden') return { name: 'forbidden', title: '无权读取区域', detail: '当前账号没有区域或矩阵的读取权限。' };
      return { name: terminal.status, title: '无法读取区域', detail: terminal.error?.message || '区域权威接口当前不可用。' };
    }
    if (!state.regions || !state.matrix) return { name: 'loading', title: '正在读取区域', detail: '页面骨架已就绪，等待区域和关系矩阵快照。' };
    return null;
  }

  function zoneLabel(id) {
    return state.regions?.zones.find((zone) => zone.id === id || zone.name === id)?.label || id;
  }

  function canWrite() {
    return state.regions?.capabilities?.zones_crud === true;
  }

  function availableNetworks() {
    const map = new Map([...state.lans, ...state.wans].map((item) => [item.id, item]));
    state.regions?.writableZones.forEach((zone) => zone.members.forEach((id) => {
      if (!map.has(id)) map.set(id, { id, name: id, device: '', kind: 'network' });
    }));
    return [...map.values()];
  }

  function memberOwner(id, currentId = '') {
    return state.regions?.writableZones.find((zone) => zone.id !== currentId && zone.members.includes(id)) || null;
  }

  function openZone(id = '') {
    const creating = !id;
    const zone = creating ? null : state.regions?.zones.find((item) => item.id === id);
    if (!creating && !zone) return;
    state.sheet = { kind: 'zone', id: zone?.id || '', creating };
    state.draft = {
      name: zone?.name || '',
      members: [...(zone?.members || [])],
      input: text(zone?.defaultActions?.input, 'REJECT').toUpperCase(),
      output: text(zone?.defaultActions?.output, 'ACCEPT').toUpperCase(),
      forward: text(zone?.defaultActions?.forward, 'REJECT').toUpperCase(),
      masq: zone?.defaultActions?.masq === true,
      mtu_fix: zone?.defaultActions?.mtu_fix === true
    };
    state.feedback = '';
    renderOverlay();
  }

  function openPair(pair) {
    state.sheet = { kind: 'pair', pair };
    state.draft = null;
    renderOverlay();
  }

  function closeSheet() {
    state.sheet = null;
    state.draft = null;
    state.feedback = '';
    state.confirmDelete = false;
    renderOverlay();
  }

  function pairPolicies(pair) {
    const ids = new Set(pair.ruleIds);
    return state.policies.filter((policy) => ids.has(policy.id) || (
      [pair.sourceId, zoneLabel(pair.sourceId)].includes(policy.sourceZone)
      && [pair.destinationId, zoneLabel(pair.destinationId)].includes(policy.destinationZone)
    ));
  }

  function zonesTableMarkup() {
    const zones = state.regions.zones;
    const content = zones.length
      ? `<div data-dwrt-component="data-table" data-dwrt-surface="dense-surface" class="policy-entity-table"><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table"><thead><tr><th>区域</th><th>网络 / 接口</th><th>引用</th><th>默认转发</th><th><span class="policy-entity-visually-hidden">详情</span></th></tr></thead><tbody>${zones.map((zone) => `<tr><td><strong>${escapeHtml(zone.label)}</strong><small>${escapeHtml(zone.virtual ? '虚拟区域' : zone.name)}</small></td><td>${zone.members.length ? `<div class="policy-region-members">${zone.members.map((member) => `<span>${escapeHtml(member)}</span>`).join('')}</div>` : '<span class="policy-entity-muted">未分配</span>'}</td><td>${zone.referenceCount}</td><td>${statusBadge(text(zone.defaultActions.forward, zone.virtual ? '--' : 'REJECT'), text(zone.defaultActions.forward).toUpperCase() === 'ACCEPT' ? 'success' : 'warning')}</td><td><button type="button" data-dwrt-component="icon-button" data-region-open="${escapeHtml(zone.id)}" aria-label="查看 ${escapeHtml(zone.label)}">${icon('chevron-right')}</button></td></tr>`).join('')}</tbody></table></div></div>`
      : statePanel('empty', '尚未定义区域', '区域接口已就绪，但当前没有可展示的真实或虚拟区域。');
    return `<section class="policy-entity-section policy-region-list"><header><div><h2>区域</h2><p>网络只能属于一个区域；锁定字段由后端合同决定。</p></div>${canWrite() ? button('创建区域', 'data-region-create', 'primary', 'plus') : ''}</header>${content}</section>`;
  }

  function matrixMarkup() {
    const ids = state.matrix.zoneIds;
    if (!ids.length) return `<section class="policy-entity-section policy-region-matrix-section"><header><div><h2>区域关系</h2><p>选择任意单元查看有效动作、地址族统计和关联规则。</p></div></header>${statePanel('empty', '没有区域关系', '至少存在两个参与策略的区域后，关系矩阵才会显示。')}</section>`;
    const pairMap = new Map(state.matrix.pairs.map((pair) => [`${pair.sourceId}|${pair.destinationId}`, pair]));
    const action = (pair) => pair.action === 'allow' ? ['允许', 'success'] : pair.action === 'block' ? ['阻止', 'danger'] : [pair.action, 'muted'];
    return `<section class="policy-entity-section policy-region-matrix-section"><header><div><h2>区域关系</h2><p>选择任意单元查看有效动作、地址族统计和关联规则。</p></div><span class="policy-entity-count">${state.matrix.pairs.length} 个关系</span></header><div class="policy-region-matrix-scroll"><div data-dwrt-component="data-grid" class="policy-region-matrix" role="grid" aria-label="源区域到目标区域关系矩阵" aria-rowcount="${ids.length + 1}" aria-colcount="${ids.length + 1}" style="--policy-region-count:${ids.length}"><div class="policy-region-matrix-corner" role="columnheader">源 / 目标</div>${ids.map((id) => `<div class="policy-region-matrix-column" role="columnheader">${escapeHtml(zoneLabel(id))}</div>`).join('')}${ids.map((sourceId, rowIndex) => `<div class="policy-region-matrix-row" role="rowheader">${escapeHtml(zoneLabel(sourceId))}</div>${ids.map((destinationId, columnIndex) => { const pair = pairMap.get(`${sourceId}|${destinationId}`) || { sourceId, destinationId, action: 'block', policyCount: 0, ipv4Count: 0, ipv6Count: 0, ruleIds: [] }; const [label, tone] = action(pair); return `<div role="gridcell" data-dwrt-grid-cell data-dwrt-grid-row="${rowIndex + 1}" data-dwrt-grid-column="${columnIndex + 1}" data-region-pair="${escapeHtml(`${sourceId}|${destinationId}`)}" tabindex="${rowIndex === 0 && columnIndex === 0 ? '0' : '-1'}" class="policy-region-matrix-cell is-${tone}" aria-label="${escapeHtml(`${zoneLabel(sourceId)} 到 ${zoneLabel(destinationId)}：${label}，${pair.policyCount} 条策略`)}"><strong>${escapeHtml(label)}</strong><small>${pair.policyCount ? `${pair.policyCount} 条策略` : '默认动作'}</small></div>`; }).join('')}`).join('')}</div></div></section>`;
  }

  function feedbackMarkup() {
    return state.feedback ? `<div class="policy-entity-alert is-${state.feedbackTone}" role="${state.feedbackTone === 'error' ? 'alert' : 'status'}"><strong>${state.feedbackTone === 'error' ? '操作未完成' : '区域已更新'}</strong><span>${escapeHtml(state.feedback)}</span></div>` : '';
  }

  function zoneSheetMarkup() {
    const sheet = state.sheet;
    const draft = state.draft;
    const zone = sheet.creating ? null : state.regions.zones.find((item) => item.id === sheet.id);
    const editable = canWrite() && !zone?.virtual;
    const nameLocked = !sheet.creating;
    const networks = availableNetworks();
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-region-close aria-label="关闭区域详情"></button><aside data-dwrt-component="sheet" data-dwrt-surface="stable-glass" class="dwrt-kit-sheet policy-entity-sheet policy-region-sheet is-open"><header class="dwrt-kit-sheet-header"><div><span>${sheet.creating ? '新区域' : zone?.type || '区域'}</span><strong>${escapeHtml(sheet.creating ? '创建区域' : zone?.label || '区域详情')}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-region-close aria-label="关闭">${icon('x')}</button></header><div class="dwrt-kit-sheet-body policy-entity-sheet-body">${feedbackMarkup()}${zone?.virtual ? statePanel('unavailable', '虚拟区域为只读', 'Gateway 由路由器自身提供，不对应可修改的 UCI firewall zone。') : ''}<div class="policy-region-form"><label data-dwrt-component="field"><span data-dwrt-field-label>区域标识</span><input type="text" data-region-field="name" value="${escapeHtml(draft.name)}" pattern="[A-Za-z0-9_]+" ${nameLocked || !editable ? 'disabled' : ''}><small data-dwrt-field-description>${sheet.creating ? '使用稳定标识，例如 iot 或 office。创建后不可改名。' : '稳定标识由策略和防火墙规则引用。'}</small></label><div data-dwrt-component="field" class="policy-region-members-field"><span data-dwrt-field-label>网络 / 接口</span><div data-dwrt-component="combobox" data-dwrt-multiple="true" data-dwrt-placeholder="选择网络" data-region-members><button class="dwrt-kit-combobox-trigger" type="button" data-dwrt-combobox-trigger ${editable ? '' : 'disabled'}><span data-dwrt-combobox-value></span></button><div class="dwrt-kit-combobox-popover" data-dwrt-combobox-popover hidden>${networks.length > 6 ? '<input class="dwrt-kit-combobox-search" type="search" data-dwrt-combobox-search aria-label="搜索网络" placeholder="搜索网络">' : ''}<div class="dwrt-kit-combobox-listbox" data-dwrt-combobox-listbox>${networks.map((network) => { const owner = memberOwner(network.id, zone?.id); const selected = draft.members.includes(network.id); return `<button data-dwrt-combobox-option data-value="${escapeHtml(network.id)}" data-label="${escapeHtml(network.name)}" data-selected="${selected}" ${owner ? 'disabled' : ''}><span><strong>${escapeHtml(network.name)}</strong><small>${escapeHtml(owner ? `已属于 ${owner.label}` : [network.device, network.id].filter(Boolean).join(' · '))}</small></span></button>`; }).join('')}</div></div></div><small data-dwrt-field-description>服务端会再次校验成员唯一性，冲突不会覆盖其他区域。</small></div><div class="policy-region-action-grid">${['input', 'output', 'forward'].map((field) => `<label data-dwrt-component="field"><span data-dwrt-field-label>${field === 'input' ? '进入路由器' : field === 'output' ? '路由器发出' : '区域转发'}</span><select data-dwrt-component="select" data-region-field="${field}" ${editable ? '' : 'disabled'}><option value="ACCEPT" ${draft[field] === 'ACCEPT' ? 'selected' : ''}>允许</option><option value="REJECT" ${draft[field] === 'REJECT' ? 'selected' : ''}>拒绝</option><option value="DROP" ${draft[field] === 'DROP' ? 'selected' : ''}>丢弃</option></select></label>`).join('')}</div></div></div><footer class="dwrt-kit-sheet-footer">${zone && !zone.deleteLocked && editable ? button('删除', 'data-region-delete', 'danger', 'trash-2') : '<span></span>'}<div>${button('关闭', 'data-region-close', 'ghost')}${editable ? button(state.saving ? '正在应用' : sheet.creating ? '创建并应用' : '保存并应用', `data-region-save ${state.saving ? 'disabled' : ''}`, 'primary') : ''}</div></footer></aside>`;
  }

  function pairSheetMarkup() {
    const pair = state.sheet.pair;
    const policies = pairPolicies(pair);
    const allowed = pair.action === 'allow';
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-region-close aria-label="关闭关系详情"></button><aside data-dwrt-component="sheet" data-dwrt-surface="stable-glass" class="dwrt-kit-sheet policy-entity-sheet policy-region-sheet is-open"><header class="dwrt-kit-sheet-header"><div><span>区域关系</span><strong>${escapeHtml(zoneLabel(pair.sourceId))} → ${escapeHtml(zoneLabel(pair.destinationId))}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-region-close aria-label="关闭">${icon('x')}</button></header><div class="dwrt-kit-sheet-body policy-entity-sheet-body"><section class="policy-region-pair-summary"><div>${statusBadge(allowed ? '允许' : '阻止', allowed ? 'success' : 'danger')}<strong>${pair.forwarding ? '已建立区域转发' : '使用规则或默认动作'}</strong></div><dl><div><dt>IPv4 策略</dt><dd>${pair.ipv4Count}</dd></div><div><dt>IPv6 策略</dt><dd>${pair.ipv6Count}</dd></div><div><dt>规则总数</dt><dd>${pair.policyCount}</dd></div></dl></section><section class="policy-region-pair-policies"><h3>关联规则</h3>${policies.length ? policies.map((policy) => `<article><span><strong>${escapeHtml(policy.name)}</strong><small>${escapeHtml(`${policy.protocol} · ${policy.family}`)}</small></span>${statusBadge(policy.action, /允许|allow/i.test(policy.action) ? 'success' : /阻止|拒绝|block|reject/i.test(policy.action) ? 'danger' : 'muted')}</article>`).join('') : statePanel('empty', '没有显式规则', '当前关系由区域转发或默认阻止语义决定。')}</section></div><footer class="dwrt-kit-sheet-footer"><span></span>${button('关闭', 'data-region-close', 'primary')}</footer></aside>`;
  }

  function confirmationMarkup() {
    if (!state.confirmDelete || state.sheet?.kind !== 'zone') return '';
    const zone = state.regions.zones.find((item) => item.id === state.sheet.id);
    return window.DWRT_UI_KIT?.confirmationMarkup?.({
      id: 'policy-region-delete', action: 'policy-region-delete', tone: 'danger',
      title: `删除区域“${zone?.label || zone?.id || ''}”？`,
      description: '只有未被防火墙条目引用的非默认区域才能删除；服务端会验证并在失败时回滚。',
      confirmLabel: state.saving ? '正在删除' : '删除区域', disabled: state.saving
    }) || '';
  }

  function sheetMarkup() {
    if (!state.sheet) return '';
    return state.sheet.kind === 'pair' ? pairSheetMarkup() : zoneSheetMarkup();
  }

  function workbenchMarkup() {
    const stale = Object.values(state.snapshots).some((snapshot) => snapshot?.stale)
      ? `<div class="policy-entity-alert is-warning" role="status"><strong>正在显示上次可用快照</strong><span>部分刷新失败，区域和矩阵仍保留最后一次成功数据。</span></div>` : '';
    return `<section data-dwrt-component="page-shell" data-dwrt-page-shell="master-detail" data-dwrt-surface="stable-glass" class="policy-entity-page policy-regions-page"><header class="policy-entity-header"><div><h1 data-dwrt-page-title>区域</h1><p>查看网络成员与区域之间的真实有效访问关系。</p></div><div class="policy-entity-header-actions">${statusBadge(canWrite() ? '事务写入可用' : '只读', canWrite() ? 'success' : 'warning')}${button(state.refreshing ? '正在刷新' : '刷新', `data-region-refresh ${state.refreshing ? 'disabled' : ''}`, 'ghost', 'refresh-cw')}</div></header>${stale}${feedbackMarkup()}${zonesTableMarkup()}${matrixMarkup()}</section>`;
  }

  function replaceMarkup(host, markup) {
    window.DWRT_UI_KIT?.unmount?.(host);
    host.replaceChildren(document.createRange().createContextualFragment(markup));
    ui.mountAll?.(host);
  }

  function renderPage() {
    if (!root || !state.mounted) return;
    const terminal = pageState();
    replaceMarkup(pageHost, terminal
      ? `<section data-dwrt-component="page-shell" data-dwrt-page-shell="master-detail" data-dwrt-surface="stable-glass" class="policy-entity-page policy-regions-page"><header class="policy-entity-header"><div><h1 data-dwrt-page-title>区域</h1><p>查看网络成员与区域之间的真实有效访问关系。</p></div></header>${statePanel(terminal.name, terminal.title, terminal.detail)}</section>`
      : workbenchMarkup());
  }

  function renderOverlay() {
    if (!root || !state.mounted) return;
    replaceMarkup(overlayHost, `${sheetMarkup()}${confirmationMarkup()}`);
  }

  function render() {
    renderPage();
    renderOverlay();
  }

  function refresh(force = true) {
    if (!registry) return Promise.resolve();
    if (state.refreshPromise) {
      state.refreshQueued = state.refreshQueued || force;
      return state.refreshPromise;
    }
    state.refreshPromise = (async () => {
      let nextForce = force;
      do {
        state.refreshQueued = false;
        state.refreshing = true;
        renderPage();
        await Promise.allSettled([
          registry.request('policy.regions', { signal, force: nextForce }),
          registry.request('policy.zoneMatrix', { signal, force: nextForce }),
          registry.request('policy.table', { signal, force: nextForce }),
          registry.request('network.lans', { signal, force: nextForce }),
          registry.request('network.wans', { signal, force: nextForce })
        ]);
        hydrate();
        nextForce = state.refreshQueued;
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

  async function saveZone() {
    if (!state.draft || state.saving || state.sheet?.kind !== 'zone') return;
    const creating = state.sheet.creating;
    if (creating && !/^[A-Za-z0-9_]+$/.test(state.draft.name)) {
      state.feedback = '区域标识只能包含字母、数字和下划线。';
      state.feedbackTone = 'error';
      renderOverlay();
      return;
    }
    state.saving = true;
    state.feedback = '';
    renderOverlay();
    try {
      const endpoint = creating ? '/api/v1/policy-engine/zones' : `/api/v1/policy-engine/zones/${encodeURIComponent(state.sheet.id)}`;
      await api.request?.('policy-region-save', endpoint, { method: creating ? 'POST' : 'PUT', body: clone(state.draft) });
      state.sheet = null;
      state.draft = null;
      state.feedback = '事务已应用并通过运行态回读。';
      state.feedbackTone = 'success';
      renderOverlay();
      ['policy.regions', 'policy.zoneMatrix', 'policy.table'].forEach((key) => registry.invalidate(key));
      await refresh(true);
    } catch (error) {
      const payload = error?.payload?.data || error?.payload || {};
      state.feedback = text(payload.message, payload.error, error?.message, '区域写入失败，系统已保留原配置。');
      if (payload.conflicting_network) state.feedback += ` 冲突网络：${payload.conflicting_network}。`;
      state.feedbackTone = 'error';
      renderOverlay();
    } finally {
      if (state.mounted) { state.saving = false; renderPage(); renderOverlay(); }
    }
  }

  async function deleteZone() {
    if (state.saving || state.sheet?.kind !== 'zone') return;
    state.saving = true;
    renderOverlay();
    try {
      await api.request?.('policy-region-delete', `/api/v1/policy-engine/zones/${encodeURIComponent(state.sheet.id)}`, { method: 'DELETE', body: {} });
      state.sheet = null;
      state.draft = null;
      state.confirmDelete = false;
      state.feedback = '区域已删除，防火墙运行态已重新加载。';
      state.feedbackTone = 'success';
      renderOverlay();
      ['policy.regions', 'policy.zoneMatrix', 'policy.table'].forEach((key) => registry.invalidate(key));
      await refresh(true);
    } catch (error) {
      const payload = error?.payload?.data || error?.payload || {};
      state.confirmDelete = false;
      state.feedback = text(payload.message, payload.error, error?.message, '区域删除失败。');
      state.feedbackTone = 'error';
      renderOverlay();
    } finally {
      if (state.mounted) { state.saving = false; renderPage(); renderOverlay(); }
    }
  }

  function selectPair(element) {
    const [sourceId, destinationId] = String(element?.dataset.regionPair || '').split('|');
    const pair = state.matrix?.pairs.find((item) => item.sourceId === sourceId && item.destinationId === destinationId);
    if (pair) openPair(pair);
  }

  function onClick(event) {
    if (event.target.closest('[data-region-refresh]')) return void refresh(true);
    if (event.target.closest('[data-region-create]')) return openZone();
    const open = event.target.closest('[data-region-open]');
    if (open) return openZone(open.dataset.regionOpen);
    if (event.target.closest('[data-region-close]')) return closeSheet();
    if (event.target.closest('[data-region-save]')) return void saveZone();
    if (event.target.closest('[data-region-delete]')) { state.confirmDelete = true; renderOverlay(); return; }
    if (event.target.closest('[data-dwrt-confirm-cancel]')) { state.confirmDelete = false; renderOverlay(); return; }
    if (event.target.closest('[data-dwrt-confirm-accept]')) return void deleteZone();
  }

  function onChange(event) {
    const field = event.target.closest('[data-region-field]');
    if (field && state.draft) state.draft[field.dataset.regionField] = field.type === 'checkbox' ? field.checked : field.value;
  }

  function onComboboxChange(event) {
    if (event.target.closest('[data-region-members]') && state.draft) state.draft.members = [...event.detail.values];
  }

  function onGridSelect(event) { selectPair(event.detail?.cell); }
  function onGridActivate(event) { selectPair(event.detail?.cell); }

  function subscribe(key, slot) {
    return registry?.subscribe?.(key, (snapshot) => {
      if (!state.mounted) return;
      state.snapshots[slot] = snapshot;
      hydrate();
      renderPage();
    });
  }

  root.hidden = false;
  root.className = 'route-preview route-workspace policy-regions-route-host';
  root.replaceChildren(pageHost, overlayHost);
  root.addEventListener('click', onClick);
  root.addEventListener('change', onChange);
  root.addEventListener('dwrt-combobox-change', onComboboxChange);
  root.addEventListener('dwrt-grid-select', onGridSelect);
  root.addEventListener('dwrt-grid-activate', onGridActivate);
  const unsubscribers = [
    subscribe('policy.regions', 'regions'),
    subscribe('policy.zoneMatrix', 'matrix'),
    subscribe('policy.table', 'policies'),
    subscribe('network.lans', 'lans'),
    subscribe('network.wans', 'wans')
  ].filter(Boolean);
  render();
  if (registry) Promise.allSettled([
    registry.request('policy.regions', { signal }),
    registry.request('policy.zoneMatrix', { signal }),
    registry.request('policy.table', { signal }),
    registry.request('network.lans', { signal }),
    registry.request('network.wans', { signal })
  ]).then(() => { if (state.mounted) { hydrate(); renderPage(); } });

  return {
    refresh,
    unmount() {
      state.mounted = false;
      unsubscribers.forEach((unsubscribe) => unsubscribe());
      root.removeEventListener('click', onClick);
      root.removeEventListener('change', onChange);
      root.removeEventListener('dwrt-combobox-change', onComboboxChange);
      root.removeEventListener('dwrt-grid-select', onGridSelect);
      root.removeEventListener('dwrt-grid-activate', onGridActivate);
      window.DWRT_UI_KIT?.unmount?.(root);
      root.replaceChildren();
      root.classList.remove('route-workspace', 'policy-regions-route-host');
    }
  };
}

export default { mount };
