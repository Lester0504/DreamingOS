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
    confirmDelete: false,
    sheetFocusPending: false,
    sheetReturnFocus: null,
    selectedPair: null,
    policyQuery: '',
    policyFamilies: new Set(['ipv4', 'ipv6']),
    pollTimer: 0
  };

  /*
   * 手动刷新按钮按用户第 9 条删除。这一页虽然订阅了 registry，但 registry 只按 TTL
   * 缓存、不自轮询，所以补一条可见性受控的轮询；抽屉打开或正在保存时跳过。
   */
  function startPolling() {
    stopPolling();
    state.pollTimer = window.setInterval(() => {
      if (!state.mounted) return;
      if (document.hidden) return;
      if (state.refreshing || state.refreshPromise || state.saving) return;
      if (state.sheet || state.confirmDelete) return;
      refresh(true);
    }, 20000);
  }

  function stopPolling() {
    if (!state.pollTimer) return;
    window.clearInterval(state.pollTimer);
    state.pollTimer = 0;
  }
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
    const cellText = (value, fallback = '任何') => {
      if (Array.isArray(value)) return value.map((item) => text(item?.label, item?.name, item?.value, item)).filter(Boolean).join('、') || fallback;
      if (value && typeof value === 'object') return text(value.label, value.name, value.address, value.value, value.matching_target, fallback);
      return text(value, fallback);
    };
    return list(payload, 'rows').map((row = {}, index) => ({
      id: text(row.id, row._id, row.origin_id, `policy-${index + 1}`),
      aliases: [row.id, row._id, row.origin_id, row.section_id, row.raw?.section].map((value) => text(value)).filter(Boolean),
      name: text(row.name, `策略 ${index + 1}`),
      policyType: text(row.policy_type, row.type, 'firewall').toLowerCase(),
      rawSourceZone: text(row.raw?.options?.src, row.raw?.src),
      rawDestinationZone: text(row.raw?.options?.dest, row.raw?.dest),
      action: text(row.action, row.action_key, '--'),
      sourceZone: text(row.source_zone, row.raw?.src),
      source: cellText(row.source_label || row.source_name || row.source || row.raw?.src_ip),
      sourcePort: cellText(row.source_port || row.src_port || row.raw?.src_port || row.raw?.options?.src_port),
      destinationZone: text(row.destination_zone, row.raw?.dest),
      destination: cellText(row.destination_label || row.destination_name || row.destination || row.raw?.dest_ip),
      destinationPort: cellText(row.destination_port || row.dst_port || row.raw?.dest_port),
      protocol: text(row.protocol, row.raw?.proto, '全部'),
      family: text(row.ip_version, row.family, row.raw?.family, row.raw?.options?.family, '两者'),
      predefined: row.predefined === true,
      enabled: row.enabled !== false
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

  function openZone(id = '', trigger = document.activeElement) {
    const creating = !id;
    const zone = creating ? null : state.regions?.zones.find((item) => item.id === id);
    if (!creating && !zone) return;
    state.sheet = { kind: 'zone', id: zone?.id || '', creating };
    state.sheetFocusPending = true;
    state.sheetReturnFocus = trigger instanceof HTMLElement ? trigger : null;
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

  function openPair(pair, trigger = document.activeElement) {
    state.sheet = { kind: 'pair', pair };
    state.sheetFocusPending = true;
    state.sheetReturnFocus = trigger instanceof HTMLElement ? trigger : null;
    state.draft = null;
    renderOverlay();
  }

  function closeSheet() {
    const returnFocus = state.sheetReturnFocus;
    state.sheet = null;
    state.draft = null;
    state.feedback = '';
    state.confirmDelete = false;
    state.sheetFocusPending = false;
    state.sheetReturnFocus = null;
    renderOverlay();
    if (returnFocus?.isConnected) returnFocus.focus({ preventScroll: true });
  }

  function pairPolicies(pair) {
    return firewallPolicies().filter((policy) => policyMatchesPair(policy, pair));
  }

  function firewallPolicies() {
    return state.policies.filter((policy) => policy.policyType === 'firewall' || policy.policyType.includes('防火墙'));
  }

  function policyZoneMatches(value, id) {
    const normalized = text(value).toLowerCase();
    return !normalized || ['-', '*', 'any', '任何', '多个'].includes(normalized)
      || [String(id).toLowerCase(), zoneLabel(id).toLowerCase()].includes(normalized);
  }

  function policyMatchesPair(policy, pair) {
    if (pair.ruleIds.length) return policy.aliases.some((id) => pair.ruleIds.includes(id));
    const source = policy.rawSourceZone || policy.sourceZone;
    const destination = policy.rawDestinationZone || policy.destinationZone;
    if (source && !policyZoneMatches(source, pair.sourceId)) return false;
    if (destination && !policyZoneMatches(destination, pair.destinationId)) return false;
    return Boolean(source || destination);
  }

  function zoneKey(zone) {
    return `${zone?.id || ''} ${zone?.name || ''} ${zone?.label || ''} ${zone?.type || ''}`.toLowerCase();
  }

  function topologyMarkup() {
    const zones = state.regions.zones;
    const take = (pattern) => zones.find((zone) => pattern.test(zoneKey(zone))) || null;
    const assigned = new Set();
    const claim = (zone) => {
      if (!zone || assigned.has(zone.id)) return null;
      assigned.add(zone.id);
      return zone;
    };
    const semantic = {
      vpn: claim(take(/(^|\s)vpn($|\s)|隧道/)),
      dmz: claim(take(/(^|\s)dmz($|\s)|隔离区/)),
      external: claim(take(/(^|\s)(wan|external)($|\s)|外部|互联网/)),
      gateway: claim(zones.find((zone) => zone.virtual || /gateway|网关/.test(zoneKey(zone)))),
      internal: claim(take(/(^|\s)(lan|internal)($|\s)|内部|内网/)),
      hotspot: claim(take(/hotspot|guest|访客/))
    };
    const custom = zones.filter((zone) => !assigned.has(zone.id) && !/^任何$/.test(zone.label)).slice(0, 3);
    const node = (zone, kind, fallback) => {
      if (!zone) return `<div class="policy-region-flow-slot is-empty" aria-label="${escapeHtml(fallback)}未配置"><span>${escapeHtml(fallback)}</span><small>未配置</small></div>`;
      const members = zone.members.length ? zone.members.join('、') : zone.virtual ? '路由器本机' : '未分配网络';
      return `<article class="policy-region-flow-node is-${kind}" data-adaptive-sample><span>${icon(kind === 'external' ? 'globe-2' : kind === 'gateway' ? 'router' : kind === 'vpn' ? 'shield' : kind === 'hotspot' ? 'users' : kind === 'dmz' ? 'server' : 'network')}</span><div><strong>${escapeHtml(zone.label)}</strong><small>${escapeHtml(members)}</small></div></article>`;
    };
    const customNodes = custom.length
      ? `<div class="policy-region-flow-custom" aria-label="自定义区域">${custom.map((zone) => node(zone, 'custom', '自定义区域')).join('')}</div>`
      : '';
    return `<section class="policy-region-flow dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface" data-adaptive-sample><div class="policy-region-flow-map"><div class="policy-region-flow-upper">${node(semantic.vpn, 'vpn', 'VPN')}${node(semantic.dmz, 'dmz', 'DMZ')}</div><div class="policy-region-flow-main">${node(semantic.external, 'external', '外部')}<span class="policy-region-flow-link" aria-hidden="true">${icon('arrow-right')}</span>${node(semantic.gateway, 'gateway', 'Gateway')}<span class="policy-region-flow-link" aria-hidden="true">${icon('arrow-right')}</span>${node(semantic.internal, 'internal', '内部')}<span class="policy-region-flow-link" aria-hidden="true">${icon('arrow-right')}</span>${node(semantic.hotspot, 'hotspot', 'Hotspot')}</div>${customNodes}</div><p>区域将网络和接口归组后用于策略匹配。矩阵展示源区域到目标区域的有效动作，并可直接筛选下方防火墙策略。</p></section>`;
  }

  function zonesTableMarkup() {
    const zones = state.regions.zones;
    const content = zones.length
      ? `<div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table"><thead><tr><th>区域名称</th><th>网络 / 接口</th><th><span class="policy-entity-visually-hidden">详情</span></th></tr></thead><tbody>${zones.map((zone) => `<tr class="policy-region-zone-row" data-region-open="${escapeHtml(zone.id)}"><td><strong>${escapeHtml(zone.label)}</strong><small>${escapeHtml(zone.virtual ? '虚拟区域' : zone.name)}</small></td><td>${zone.members.length ? `<div class="policy-region-members">${zone.members.map((member) => `<span>${escapeHtml(member)}</span>`).join('')}</div>` : '<span class="policy-entity-muted">-</span>'}</td><td><button type="button" data-dwrt-component="icon-button" aria-label="查看 ${escapeHtml(zone.label)}">${icon('chevron-right')}</button></td></tr>`).join('')}</tbody></table></div>`
      : statePanel('empty', '尚未定义区域', '区域接口已就绪，但当前没有可展示的真实或虚拟区域。');
    return `<section class="policy-entity-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface policy-region-zone-table" data-dwrt-component="data-table"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>区域</strong><span>每个网络只能属于一个区域</span></div><div class="dwrt-kit-table-toolbar-actions">${statusBadge(canWrite() ? '事务写入可用' : '只读', canWrite() ? 'success' : 'warning')}<span class="dwrt-kit-table-count">${zones.length} 个区域</span></div></div>${content}${canWrite() ? `<footer class="policy-region-zone-footer">${button('创建区域', 'data-region-create', 'ghost', 'plus')}</footer>` : ''}</section>`;
  }

  function actionPresentation(pair) {
    if (!pair.forwarding && pair.returnAction === 'allow_return' && pair.policyCount > 0 && pair.action === 'allow') return ['允许返回', 'return'];
    if (pair.action === 'allow') return ['全部允许', 'success'];
    if (pair.action === 'block' || /drop|reject|deny/.test(pair.action)) return ['全部阻止', 'danger'];
    return [pair.action || '默认动作', 'muted'];
  }

  function matrixMarkup() {
    const ids = state.matrix.zoneIds;
    if (!ids.length) return `<section class="policy-entity-section policy-region-matrix-section"><header><div><h2>区域关系</h2><p>选择任意单元查看有效动作、地址族统计和关联规则。</p></div></header>${statePanel('empty', '没有区域关系', '至少存在两个参与策略的区域后，关系矩阵才会显示。')}</section>`;
    const pairMap = new Map(state.matrix.pairs.map((pair) => [`${pair.sourceId}|${pair.destinationId}`, pair]));
    const selectedKey = state.selectedPair ? `${state.selectedPair.sourceId}|${state.selectedPair.destinationId}` : '';
    return `<section class="policy-entity-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface policy-region-matrix-section" data-dwrt-component="data-table"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>区域矩阵</strong><span>单击任意区域对以筛选下面的防火墙策略</span></div><span class="dwrt-kit-table-count">${state.matrix.pairs.length} 个关系</span></div><div class="policy-region-matrix-axis">目标</div><div class="policy-region-matrix-scroll"><div data-dwrt-component="data-grid" class="policy-region-matrix" role="grid" aria-label="源区域到目标区域关系矩阵" aria-rowcount="${ids.length + 1}" aria-colcount="${ids.length + 1}" style="--policy-region-count:${ids.length}"><button type="button" class="policy-region-matrix-corner ${selectedKey ? '' : 'is-selected'}" data-region-pair-all role="columnheader"><strong>全部策略</strong><small>${firewallPolicies().length} 条</small></button>${ids.map((id) => `<div class="policy-region-matrix-column" role="columnheader">${escapeHtml(zoneLabel(id))}</div>`).join('')}${ids.map((sourceId, rowIndex) => `<div class="policy-region-matrix-row" role="rowheader">${escapeHtml(zoneLabel(sourceId))}</div>${ids.map((destinationId, columnIndex) => { const pair = pairMap.get(`${sourceId}|${destinationId}`) || { sourceId, destinationId, action: 'block', policyCount: 0, ipv4Count: 0, ipv6Count: 0, ruleIds: [] }; const key = `${sourceId}|${destinationId}`; const [label, tone] = actionPresentation(pair); return `<button type="button" role="gridcell" data-dwrt-grid-cell data-dwrt-grid-row="${rowIndex + 1}" data-dwrt-grid-column="${columnIndex + 1}" data-region-pair="${escapeHtml(key)}" tabindex="${rowIndex === 0 && columnIndex === 0 ? '0' : '-1'}" class="policy-region-matrix-cell is-${tone} ${selectedKey === key ? 'is-selected' : ''}" aria-selected="${selectedKey === key ? 'true' : 'false'}" aria-label="${escapeHtml(`${zoneLabel(sourceId)} 到 ${zoneLabel(destinationId)}：${label}，${pair.policyCount} 条策略`)}"><strong>${escapeHtml(label)}</strong><small>${pair.policyCount ? `(${pair.policyCount})` : ''}</small></button>`; }).join('')}`).join('')}</div></div></section>`;
  }

  function familyMatches(policy) {
    const family = policy.family.toLowerCase();
    const both = !family || /两者|both|any|all|dual/.test(family);
    return both ? state.policyFamilies.size > 0
      : (state.policyFamilies.has('ipv4') && /4|ipv4/.test(family))
        || (state.policyFamilies.has('ipv6') && /6|ipv6/.test(family));
  }

  function selectedPairMatches(policy) {
    const pair = state.selectedPair;
    if (!pair) return true;
    return policyMatchesPair(policy, pair);
  }

  function visiblePolicies() {
    const query = state.policyQuery.trim().toLowerCase();
    return firewallPolicies().filter((policy) => selectedPairMatches(policy) && familyMatches(policy) && (!query || [
      policy.name, policy.action, policy.family, policy.protocol, policy.sourceZone, policy.source,
      policy.sourcePort, policy.destinationZone, policy.destination, policy.destinationPort
    ].join(' ').toLowerCase().includes(query)));
  }

  function policyRowMarkup(policy) {
    const allowed = /允许|accept|allow/i.test(policy.action);
    const blocked = /阻止|拒绝|block|reject|drop|deny/i.test(policy.action);
    return `<tr><td><strong>${escapeHtml(policy.name)}</strong>${policy.predefined ? '<small>系统策略</small>' : ''}</td><td>${statusBadge(policy.action, allowed ? 'success' : blocked ? 'danger' : 'muted')}</td><td>${escapeHtml(policy.family)}</td><td>${escapeHtml(policy.protocol)}</td><td>${escapeHtml(zoneLabel(policy.sourceZone))}</td><td>${escapeHtml(policy.source)}</td><td>${escapeHtml(policy.sourcePort)}</td><td>${escapeHtml(zoneLabel(policy.destinationZone))}</td><td>${escapeHtml(policy.destination)}</td><td>${escapeHtml(policy.destinationPort)}</td></tr>`;
  }

  function policiesMarkup() {
    const policies = visiblePolicies();
    const pair = state.selectedPair;
    const scope = pair ? `${zoneLabel(pair.sourceId)} → ${zoneLabel(pair.destinationId)}` : '全部区域关系';
    return `<section class="policy-entity-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface policy-region-policy-section" data-dwrt-component="data-table"><div class="dwrt-kit-table-toolbar policy-region-policy-toolbar"><div class="dwrt-kit-table-title"><strong>防火墙策略</strong><span>${escapeHtml(scope)}</span></div><div class="policy-region-policy-controls"><label><input type="checkbox" data-region-family="ipv4" ${state.policyFamilies.has('ipv4') ? 'checked' : ''}><span>IPv4</span></label><label><input type="checkbox" data-region-family="ipv6" ${state.policyFamilies.has('ipv6') ? 'checked' : ''}><span>IPv6</span></label>${pair ? button('关系详情', 'data-region-pair-detail', 'ghost', 'panel-right') : ''}<label class="policy-region-policy-search" data-dwrt-component="expand-search">${icon('search')}<input type="search" data-region-policy-search value="${escapeHtml(state.policyQuery)}" placeholder="搜索策略" aria-label="搜索防火墙策略"></label></div></div><div class="dwrt-kit-table-scroll policy-region-policy-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table"><thead><tr><th>名称</th><th>操作</th><th>IP 版本</th><th>协议</th><th>源区域</th><th>源</th><th>源端口</th><th>目标区域</th><th>目标</th><th>目标端口</th></tr></thead><tbody data-region-policy-rows>${policies.length ? policies.map(policyRowMarkup).join('') : '<tr><td class="dwrt-kit-table-empty" colspan="10">没有匹配的防火墙策略</td></tr>'}</tbody></table></div><footer class="policy-region-policy-footer"><span data-region-policy-count>${policies.length} / ${firewallPolicies().length} 条</span>${button('管理策略', 'data-region-manage-policies', 'primary', 'list-filter')}</footer></section>`;
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
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-region-close aria-label="关闭区域详情"></button><aside data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" class="dwrt-kit-sheet policy-entity-sheet policy-region-sheet is-open"><header class="dwrt-kit-sheet-header"><div><span>${sheet.creating ? '新区域' : zone?.type || '区域'}</span><strong>${escapeHtml(sheet.creating ? '创建区域' : zone?.label || '区域详情')}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-region-close aria-label="关闭">${icon('x')}</button></header><div class="dwrt-kit-sheet-body policy-entity-sheet-body">${feedbackMarkup()}${zone?.virtual ? statePanel('unavailable', '虚拟区域为只读', 'Gateway 由路由器自身提供，不对应可修改的 UCI firewall zone。') : ''}<div class="policy-region-form"><label data-dwrt-component="field"><span data-dwrt-field-label>区域标识</span><input type="text" data-region-field="name" value="${escapeHtml(draft.name)}" pattern="[A-Za-z0-9_]+" ${nameLocked || !editable ? 'disabled' : ''}><small data-dwrt-field-description>${sheet.creating ? '使用稳定标识，例如 iot 或 office。创建后不可改名。' : '稳定标识由策略和防火墙规则引用。'}</small></label><div data-dwrt-component="field" class="policy-region-members-field"><span data-dwrt-field-label>网络 / 接口</span><div data-dwrt-component="combobox" data-dwrt-multiple="true" data-dwrt-placeholder="选择网络" data-region-members><button class="dwrt-kit-combobox-trigger" type="button" data-dwrt-combobox-trigger ${editable ? '' : 'disabled'}><span data-dwrt-combobox-value></span></button><div class="dwrt-kit-combobox-popover" data-dwrt-combobox-popover hidden>${networks.length > 6 ? '<input class="dwrt-kit-combobox-search" type="search" data-dwrt-combobox-search aria-label="搜索网络" placeholder="搜索网络">' : ''}<div class="dwrt-kit-combobox-listbox" data-dwrt-combobox-listbox>${networks.map((network) => { const owner = memberOwner(network.id, zone?.id); const selected = draft.members.includes(network.id); return `<button data-dwrt-combobox-option data-value="${escapeHtml(network.id)}" data-label="${escapeHtml(network.name)}" data-selected="${selected}" ${owner ? 'disabled' : ''}><span><strong>${escapeHtml(network.name)}</strong><small>${escapeHtml(owner ? `已属于 ${owner.label}` : [network.device, network.id].filter(Boolean).join(' · '))}</small></span></button>`; }).join('')}</div></div></div><small data-dwrt-field-description>服务端会再次校验成员唯一性，冲突不会覆盖其他区域。</small></div><div class="policy-region-action-grid">${['input', 'output', 'forward'].map((field) => `<label data-dwrt-component="field"><span data-dwrt-field-label>${field === 'input' ? '进入路由器' : field === 'output' ? '路由器发出' : '区域转发'}</span><select data-dwrt-component="select" data-region-field="${field}" ${editable ? '' : 'disabled'}><option value="ACCEPT" ${draft[field] === 'ACCEPT' ? 'selected' : ''}>允许</option><option value="REJECT" ${draft[field] === 'REJECT' ? 'selected' : ''}>拒绝</option><option value="DROP" ${draft[field] === 'DROP' ? 'selected' : ''}>丢弃</option></select></label>`).join('')}</div></div></div><footer class="dwrt-kit-sheet-footer">${zone && !zone.deleteLocked && editable ? button('删除', 'data-region-delete', 'danger', 'trash-2') : '<span></span>'}<div>${button('关闭', 'data-region-close', 'ghost')}${editable ? button(state.saving ? '正在应用' : sheet.creating ? '创建并应用' : '保存并应用', `data-region-save ${state.saving ? 'disabled' : ''}`, 'primary') : ''}</div></footer></aside>`;
  }

  function pairSheetMarkup() {
    const pair = state.sheet.pair;
    const policies = pairPolicies(pair);
    const allowed = pair.action === 'allow';
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-region-close aria-label="关闭关系详情"></button><aside data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" class="dwrt-kit-sheet policy-entity-sheet policy-region-sheet is-open"><header class="dwrt-kit-sheet-header"><div><span>区域关系</span><strong>${escapeHtml(zoneLabel(pair.sourceId))} → ${escapeHtml(zoneLabel(pair.destinationId))}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-region-close aria-label="关闭">${icon('x')}</button></header><div class="dwrt-kit-sheet-body policy-entity-sheet-body"><section class="policy-region-pair-summary"><div>${statusBadge(allowed ? '允许' : '阻止', allowed ? 'success' : 'danger')}<strong>${pair.forwarding ? '已建立区域转发' : '使用规则或默认动作'}</strong></div><dl><div><dt>IPv4 策略</dt><dd>${pair.ipv4Count}</dd></div><div><dt>IPv6 策略</dt><dd>${pair.ipv6Count}</dd></div><div><dt>规则总数</dt><dd>${pair.policyCount}</dd></div></dl></section><section class="policy-region-pair-policies"><h3>关联规则</h3>${policies.length ? policies.map((policy) => `<article><span><strong>${escapeHtml(policy.name)}</strong><small>${escapeHtml(`${policy.protocol} · ${policy.family}`)}</small></span>${statusBadge(policy.action, /允许|allow/i.test(policy.action) ? 'success' : /阻止|拒绝|block|reject/i.test(policy.action) ? 'danger' : 'muted')}</article>`).join('') : statePanel('empty', '没有显式规则', '当前关系由区域转发或默认阻止语义决定。')}</section></div><footer class="dwrt-kit-sheet-footer"><span></span>${button('关闭', 'data-region-close', 'primary')}</footer></aside>`;
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

  const SNAPSHOT_LABELS = {
    regions: '区域', matrix: '关系矩阵', policies: '策略表', lans: 'LAN', wans: 'WAN'
  };

  /*
   * 只有 snapshot.error 才代表这一次刷新真的失败了。
   *
   * 不能判 snapshot.stale：registry 在发请求之前就按龄期把 stale 置真
   * （dwrt-data-registry.js 的 request()，`entry.stale = hasValue && age > ttlMs`），
   * 与成败无关。本页 TTL 5000ms 而轮询周期 20000ms，龄期恒大于 TTL，于是后端全程
   * 200 时每 20 秒也会闪一次「刷新失败」——把健康系统显示成故障，还会掩盖真故障。
   *
   * 也不能判 status === 'stale'：中断（换页、卸载）走的同样是 stale，但 error 为
   * null，那属于正常取消而不是失败。
   */
  function refreshFailureMarkup() {
    const failed = Object.entries(state.snapshots)
      .filter(([, snapshot]) => snapshot?.error)
      .map(([slot]) => SNAPSHOT_LABELS[slot] || slot);
    if (!failed.length) return '';
    return `<div class="policy-entity-alert is-warning" role="status"><strong>正在显示上次可用快照</strong><span>${escapeHtml(failed.join('、'))}刷新失败，页面仍保留最后一次成功数据。</span></div>`;
  }

  function workbenchMarkup() {
    return `<section class="policy-entity-page policy-regions-page"><div class="policy-region-workbench">${refreshFailureMarkup()}${feedbackMarkup()}${topologyMarkup()}${zonesTableMarkup()}${matrixMarkup()}${policiesMarkup()}</div></section>`;
  }

  function replaceMarkup(host, markup) {
    /*
     * 先把已经被搬进传送门的抽屉收回来，再交给 kit 卸载。
     *
     * kit 的 mountAll() 会把 `.dwrt-kit-sheet` 连同遮罩搬到 body 直属的
     * #dwrtKitSheetPortal，而 kit 的 unmount(host) 只在 host 内部查找抽屉。
     * 抽屉搬走之后 host 里空无一物，unmountSheet() 永远不会执行，于是抽屉和那层
     * `is-open` 遮罩永久留在传送门里 —— 关闭抽屉后遮罩仍盖在页面上吞掉所有点击，
     * 用户必须刷新才能继续操作。实测关闭后 `elementFromPoint(700,450)` 返回的
     * 就是 `dwrt-kit-sheet-overlay is-open`。
     */
    reclaimPortaledSheets(host);
    window.DWRT_UI_KIT?.unmount?.(host);
    host.replaceChildren(document.createRange().createContextualFragment(markup));
    /* 打归属标记：抽屉一旦被搬进传送门，就只能靠这个标记认回自己的那几个节点。 */
    host.querySelectorAll('.dwrt-kit-sheet, .dwrt-kit-sheet-overlay')
      .forEach((node) => { node.dataset.regionOverlayOwned = ''; });
    ui.mountAll?.(host);
  }

  /* 把本宿主搬出去的抽屉与遮罩接回来，让 kit 的 unmount 能够看到它们。 */
  function reclaimPortaledSheets(host) {
    const portal = document.getElementById('dwrtKitSheetPortal');
    if (!portal) return;
    portal.querySelectorAll('.dwrt-kit-sheet, .dwrt-kit-sheet-overlay').forEach((node) => {
      if (node.dataset.regionOverlayOwned === undefined) return;
      host.append(node);
    });
  }

  function renderPage() {
    if (!root || !state.mounted) return;
    const workbench = pageHost.querySelector('.policy-region-workbench');
    const scrollTop = workbench?.scrollTop || 0;
    const scrollLeft = workbench?.scrollLeft || 0;
    const terminal = pageState();
    replaceMarkup(pageHost, terminal
      ? `<section class="policy-entity-page policy-regions-page"><div class="policy-region-workbench">${statePanel(terminal.name, terminal.title, terminal.detail)}</div></section>`
      : workbenchMarkup());
    const nextWorkbench = pageHost.querySelector('.policy-region-workbench');
    if (nextWorkbench) {
      nextWorkbench.scrollTop = scrollTop;
      nextWorkbench.scrollLeft = scrollLeft;
    }
  }

  /*
   * 轮询刷新走 kit 的共享保状态入口（Acceptance P0 单：本页实测丢焦点与内层滚动位置）。
   *
   * renderPage() 现有的做法是整块替换 pageHost 再复位 workbench 的滚动位置：滚动能救回来，
   * 焦点与选区不能。只有页面主体走 morph；叠加层宿主仍整块替换，抽屉被 kit 搬进传送门后
   * morph 一棵已不在本宿主下的子树只会两头都错。
   */
  function renderPagePreservingInteraction() {
    const preserve = ui.preserveInteractionState;
    if (typeof preserve === 'function' && preserve(pageHost, (target) => {
      const terminal = pageState();
      target.replaceChildren(document.createRange().createContextualFragment(terminal
        ? `<section class="policy-entity-page policy-regions-page"><div class="policy-region-workbench">${statePanel(terminal.name, terminal.title, terminal.detail)}</div></section>`
        : workbenchMarkup()));
    })) {
      ui.mountAll?.(pageHost);
      return;
    }
    renderPage();
  }

  function renderOverlay() {
    if (!root || !state.mounted) return;
    replaceMarkup(overlayHost, `${sheetMarkup()}${confirmationMarkup()}`);
    if (!state.sheetFocusPending) return;
    state.sheetFocusPending = false;
    const sheet = overlayHost.querySelector('.policy-region-sheet');
    const focusTarget = sheet?.querySelector('[autofocus], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), button:not(:disabled)');
    if (focusTarget instanceof HTMLElement) focusTarget.focus({ preventScroll: true });
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
    if (!pair) return;
    state.selectedPair = pair;
    renderPage();
  }

  function patchPolicyRows() {
    const body = pageHost.querySelector('[data-region-policy-rows]');
    const count = pageHost.querySelector('[data-region-policy-count]');
    if (!body) return renderPage();
    const policies = visiblePolicies();
    body.replaceChildren(document.createRange().createContextualFragment(policies.length
      ? policies.map(policyRowMarkup).join('')
      : '<tr><td class="dwrt-kit-table-empty" colspan="10">没有匹配的防火墙策略</td></tr>'));
    if (count) count.textContent = `${policies.length} / ${firewallPolicies().length} 条`;
  }

  function onClick(event) {
    const create = event.target.closest('[data-region-create]');
    if (create) return openZone('', create);
    if (event.target.closest('[data-region-pair-all]')) { state.selectedPair = null; renderPage(); return; }
    const pairDetail = event.target.closest('[data-region-pair-detail]');
    if (pairDetail && state.selectedPair) return openPair(state.selectedPair, pairDetail);
    if (event.target.closest('[data-region-manage-policies]')) { window.location.hash = '/policy-engine/table'; return; }
    const open = event.target.closest('[data-region-open]');
    if (open) return openZone(open.dataset.regionOpen, open);
    if (event.target.closest('[data-region-close]')) return closeSheet();
    if (event.target.closest('[data-region-save]')) return void saveZone();
    if (event.target.closest('[data-region-delete]')) { state.confirmDelete = true; renderOverlay(); return; }
    if (event.target.closest('[data-dwrt-confirm-cancel]')) { state.confirmDelete = false; renderOverlay(); return; }
    if (event.target.closest('[data-dwrt-confirm-accept]')) return void deleteZone();
  }

  function onChange(event) {
    const family = event.target.closest('[data-region-family]');
    if (family) {
      if (family.checked) state.policyFamilies.add(family.dataset.regionFamily);
      else state.policyFamilies.delete(family.dataset.regionFamily);
      patchPolicyRows();
      return;
    }
    const field = event.target.closest('[data-region-field]');
    if (field && state.draft) state.draft[field.dataset.regionField] = field.type === 'checkbox' ? field.checked : field.value;
  }

  function onInput(event) {
    const search = event.target.closest('[data-region-policy-search]');
    if (!search) return;
    state.policyQuery = search.value;
    patchPolicyRows();
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
  root.addEventListener('input', onInput);
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
  startPolling();

  return {
    refresh,
    unmount() {
      state.mounted = false;
      stopPolling();
      unsubscribers.forEach((unsubscribe) => unsubscribe());
      root.removeEventListener('click', onClick);
      root.removeEventListener('change', onChange);
      root.removeEventListener('input', onInput);
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
