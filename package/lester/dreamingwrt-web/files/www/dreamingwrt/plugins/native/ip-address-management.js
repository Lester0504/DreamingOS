export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const registry = context.registry || window.DWRT_DATA_REGISTRY;
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character])));
  const signal = context.signal;
  const stage = root?.closest('.console-stage');
  const VERSION = '20260810-front-release-01';

  const state = {
    mounted: true,
    snapshot: null,
    inventory: null,
    network: '',
    status: 'all',
    source: 'all',
    query: '',
    selectedId: '',
    refreshPromise: null,
    pollTimer: 0
  };

  /*
   * 手动刷新按钮按用户第 9 条删除。registry 只按 TTL 缓存、不自轮询，
   * 所以补一条可见性受控的轮询；详情抽屉打开或用户正在输入筛选时跳过。
   */
  function startPolling() {
    stopPolling();
    state.pollTimer = window.setInterval(() => {
      if (!state.mounted) return;
      if (document.hidden) return;
      if (state.refreshPromise) return;
      if (state.selectedId) return;
      refresh();
    }, 15000);
  }

  function stopPolling() {
    if (!state.pollTimer) return;
    window.clearInterval(state.pollTimer);
    state.pollTimer = 0;
  }

  const pageHost = document.createElement('div');
  pageHost.className = 'ipam-page-host';
  const overlayHost = document.createElement('div');
  overlayHost.className = 'ipam-overlay-host';

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (typeof value === 'object' && !Array.isArray(value)) {
        const nested = firstText(value.label, value.name, value.id, value.value, value.message);
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
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return 0;
  }

  function asArray(value, keys = ['items', 'rows', 'data']) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of keys) if (Array.isArray(value[key])) return value[key];
    return [];
  }

  function bool(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') return !['0', 'false', 'off', 'no', 'disabled'].includes(value.toLowerCase());
    return Boolean(value);
  }

  function normalizeKey(value) {
    return String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  }

  function normalizeMac(value) {
    const compact = String(value || '').trim().replace(/[^0-9a-f]/gi, '').toUpperCase();
    return compact.length === 12 ? compact.match(/.{2}/g).join(':') : '';
  }

  function normalizeAddress(row = {}, network = {}, index = 0) {
    const statusKey = normalizeKey(firstText(row.status, row.state, 'unknown'));
    const conflict = bool(row.conflict, false)
      || firstNumber(row.conflicts, row.conflict_count) > 0
      || ['conflict', 'duplicated', 'duplicate'].includes(statusKey);
    const ip = firstText(row.ip, row.address, row.ip_address);
    const mac = normalizeMac(firstText(row.mac, row.hwaddr, row.mac_address));
    return {
      raw: row,
      id: firstText(row.id, `${network.id || 'network'}_${ip || index}_${mac || index}`),
      networkId: network.id,
      networkName: network.name,
      subnet: network.subnet,
      gateway: network.gateway,
      dhcpPool: network.dhcpPool,
      ip,
      mac,
      hostname: firstText(row.hostname, row.host, row.device_name),
      owner: firstText(row.owner, row.assignee, row.client),
      type: normalizeKey(firstText(row.type, row.kind, 'unknown')),
      source: normalizeKey(firstText(row.source, row.origin, 'unknown')),
      status: conflict ? 'conflict' : statusKey,
      conflict,
      note: firstText(row.note, row.remark, row.description),
      lastSeen: firstNumber(row.last_seen, row.lastSeen, row.seen_at, row.updated_at)
    };
  }

  function normalizeNetwork(row = {}, index = 0) {
    const id = firstText(row.id, row.network_id, row.name, `network-${index + 1}`);
    const network = {
      raw: row,
      id,
      name: firstText(row.name, row.label, id),
      subnet: firstText(row.subnet, row.cidr, row.prefix),
      gateway: firstText(row.gateway, row.router),
      dhcpPool: firstText(row.dhcp_pool, row.pool),
      total: firstNumber(row.total, row.capacity),
      used: firstNumber(row.used, row.allocated),
      reserved: firstNumber(row.reserved),
      conflicts: firstNumber(row.conflicts, row.conflict_count),
      addresses: []
    };
    network.addresses = asArray(row.addresses, ['addresses', 'items', 'rows']).map((address, addressIndex) => normalizeAddress(address, network, addressIndex));
    return network;
  }

  function normalizeInventory(payload = {}) {
    const value = payload?.data && typeof payload.data === 'object' && !Array.isArray(payload.data) ? payload.data : payload;
    const networks = asArray(value?.networks, ['networks', 'items']).map(normalizeNetwork).filter((network) => network.id);
    const requested = firstText(value?.selected_network, value?.selectedNetwork);
    const selectedNetwork = networks.some((network) => network.id === requested) ? requested : firstText(networks[0]?.id);
    return {
      observedAt: firstNumber(value?.ts, value?.observed_at, value?.generated_at),
      selectedNetwork,
      networks,
      importJobs: asArray(value?.import_jobs, ['import_jobs', 'jobs'])
    };
  }

  function icon(name) {
    return `<i data-lucide="${escapeHtml(name)}" aria-hidden="true"></i>`;
  }

  function statusBadge(label, tone, options = {}) {
    return ui.statusBadgeMarkup?.(label, tone, options)
      || window.DWRT_UI_KIT?.statusBadgeMarkup?.(label, tone, options)
      || `<span class="ipam-fallback-status is-${escapeHtml(tone)}">${escapeHtml(label)}</span>`;
  }

  function sourceLabel(value) {
    const labels = {
      interface: '接口',
      dhcp: 'DHCP',
      arp: 'ARP / 邻居表',
      static: '静态绑定',
      import: '导入',
      scan: '扫描',
      unknown: '其他'
    };
    return labels[normalizeKey(value)] || firstText(value, '其他');
  }

  function typeLabel(value) {
    const labels = {
      gateway: '网关',
      host: '主机',
      client: '终端',
      server: '服务器',
      infrastructure: '基础设施',
      unknown: '未分类'
    };
    return labels[normalizeKey(value)] || firstText(value, '未分类');
  }

  function addressStatus(address) {
    if (address.conflict) return { key: 'conflict', label: '冲突', tone: 'error' };
    const key = normalizeKey(address.status);
    if (['used', 'active', 'online', 'assigned'].includes(key)) return { key: 'used', label: '已使用', tone: 'success' };
    if (['reserved', 'static', 'held'].includes(key)) return { key: 'reserved', label: '已保留', tone: 'info' };
    if (['free', 'available', 'unused'].includes(key)) return { key: 'free', label: '可用', tone: 'muted' };
    return { key: 'unknown', label: '未知', tone: 'warning' };
  }

  function ipv4Value(value) {
    const parts = String(value || '').split('.').map(Number);
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return Number.MAX_SAFE_INTEGER;
    return (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]);
  }

  function formatTime(value) {
    const number = Number(value);
    if (!Number.isFinite(number) || number <= 0) return '--';
    const milliseconds = number < 1e12 ? number * 1000 : number;
    try {
      return new Intl.DateTimeFormat('zh-CN', {
        month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false
      }).format(new Date(milliseconds));
    } catch (_) {
      return '--';
    }
  }

  function allAddresses() {
    return (state.inventory?.networks || []).flatMap((network) => network.addresses || []);
  }

  function availableNetworks() {
    return state.inventory?.networks || [];
  }

  function filteredAddresses() {
    const query = state.query.trim().toLowerCase();
    return allAddresses().filter((address) => {
      if (state.network && state.network !== 'all' && address.networkId !== state.network) return false;
      const status = addressStatus(address).key;
      if (state.status !== 'all' && status !== state.status) return false;
      if (state.source !== 'all' && address.source !== state.source) return false;
      if (!query) return true;
      return [address.ip, address.mac, address.hostname, address.owner, address.type, address.note, address.networkName, sourceLabel(address.source)]
        .some((value) => String(value || '').toLowerCase().includes(query));
    }).sort((left, right) => ipv4Value(left.ip) - ipv4Value(right.ip) || left.ip.localeCompare(right.ip));
  }

  function summary() {
    const networks = state.network && state.network !== 'all'
      ? availableNetworks().filter((network) => network.id === state.network)
      : availableNetworks();
    return networks.reduce((result, network) => ({
      total: result.total + network.total,
      used: result.used + network.used,
      reserved: result.reserved + network.reserved,
      conflicts: result.conflicts + network.conflicts,
      observed: result.observed + network.addresses.length
    }), { total: 0, used: 0, reserved: 0, conflicts: 0, observed: 0 });
  }

  function addressesForSelectedNetwork() {
    return allAddresses().filter((address) => !state.network || state.network === 'all' || address.networkId === state.network);
  }

  function statusCounts() {
    return addressesForSelectedNetwork().reduce((counts, address) => {
      const key = addressStatus(address).key;
      counts.all += 1;
      counts[key] = (counts[key] || 0) + 1;
      return counts;
    }, { all: 0, used: 0, reserved: 0, free: 0, conflict: 0, unknown: 0 });
  }

  function networkOptions() {
    const networks = availableNetworks();
    return `<option value="all" ${state.network === 'all' ? 'selected' : ''}>全部网络</option>${networks.map((network) => `<option value="${escapeHtml(network.id)}" ${state.network === network.id ? 'selected' : ''}>${escapeHtml(network.name)}${network.subnet ? ` · ${escapeHtml(network.subnet)}` : ''}</option>`).join('')}`;
  }

  function sourceOptions() {
    const values = Array.from(new Set(allAddresses().map((address) => address.source).filter(Boolean))).sort();
    return `<option value="all" ${state.source === 'all' ? 'selected' : ''}>全部来源</option>${values.map((value) => `<option value="${escapeHtml(value)}" ${state.source === value ? 'selected' : ''}>${escapeHtml(sourceLabel(value))}</option>`).join('')}`;
  }

  function snapshotState() {
    const snapshot = state.snapshot;
    if (!registry) return { key: 'unavailable', detail: '共享 DataRegistry 未注册，地址读取合同没有挂载。' };
    if (!snapshot || (['empty', 'loading'].includes(snapshot.status) && !snapshot.value)) return { key: 'loading', detail: '正在读取地址、租约与邻居表。' };
    if (snapshot.status === 'forbidden' && !snapshot.value) return { key: 'forbidden', detail: '当前账号没有 IP 地址盘点读取权限。' };
    if (['error', 'unavailable'].includes(snapshot.status) && !snapshot.value) return { key: 'error', detail: snapshot.error?.message || 'IP 地址读取接口当前没有返回有效结果。' };
    if (snapshot.status === 'stale') return { key: 'stale', detail: `刷新失败，正在显示最近一次结果${snapshot.observed_at ? ` · ${formatTime(snapshot.observed_at)}` : ''}。` };
    if (snapshot.status === 'refreshing') return { key: 'refreshing', detail: '正在刷新，当前列表保持可用。' };
    return { key: 'ready', detail: state.inventory?.observedAt ? `观测时间 ${formatTime(state.inventory.observedAt)}` : '已读取真实地址盘点。' };
  }

  function pageToolbarMarkup() {
    const viewState = snapshotState();
    const readTone = viewState.key === 'error' || viewState.key === 'forbidden' ? 'error' : viewState.key === 'stale' ? 'warning' : 'muted';
    return `<header class="ipam-page-toolbar" data-dwrt-component="toolbar">
      <label class="ipam-network-control" data-dwrt-component="field">
        <span data-dwrt-field-label>网络</span>
        <select class="dwrt-kit-select ipam-select" data-dwrt-component="select" data-ipam-network aria-label="筛选网络">${networkOptions()}</select>
      </label>
      <div class="ipam-read-state is-${escapeHtml(readTone)}" data-ipam-read-state>
        ${statusBadge('只读', 'muted', { dot: false })}
        <span>${escapeHtml(viewState.detail)}</span>
      </div>
    </header>`;
  }

  function summaryMarkup() {
    const totals = summary();
    const metrics = [
      ['observed', '已观测', totals.observed],
      ['used', '已使用', totals.used],
      ['reserved', '已保留', totals.reserved],
      ['conflicts', '冲突', totals.conflicts],
      ['total', '地址容量', totals.total]
    ];
    return `<dl class="ipam-summary" data-ipam-summary>${metrics.map(([key, label, value]) => `<div class="${key === 'conflicts' && value ? 'is-alert' : ''}"><dt>${label}</dt><dd data-ipam-summary-value="${key}">${value}</dd></div>`).join('')}</dl>`;
  }

  function statusOptions() {
    const counts = statusCounts();
    const options = [
      ['all', '全部状态'],
      ['used', '已使用'],
      ['reserved', '已保留'],
      ['free', '可用'],
      ['conflict', '冲突'],
      ['unknown', '未知']
    ];
    return options.map(([key, label]) => `<option value="${key}" data-ipam-status-option="${key}" ${state.status === key ? 'selected' : ''}>${label} (${counts[key] || 0})</option>`).join('');
  }

  function inventoryToolbarMarkup() {
    const rows = filteredAddresses();
    return `<div class="dwrt-kit-table-toolbar ipam-inventory-toolbar" data-dwrt-component="toolbar">
      <div class="dwrt-kit-table-title">
        <strong>地址库存</strong>
        <span data-ipam-count>显示 ${rows.length} / 共 ${allAddresses().length}</span>
      </div>
      <div class="ipam-inventory-actions">
        <label class="ipam-filter-field" data-dwrt-component="field"><select class="dwrt-kit-select ipam-select" data-dwrt-component="select" data-ipam-status aria-label="筛选状态">${statusOptions()}</select></label>
        <label class="ipam-filter-field" data-dwrt-component="field"><select class="dwrt-kit-select ipam-select" data-dwrt-component="select" data-ipam-source aria-label="筛选来源">${sourceOptions()}</select></label>
        <label class="dwrt-kit-expand-search ipam-search" data-dwrt-component="expand-search">
          <span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span>
          <input type="search" data-ipam-search value="${escapeHtml(state.query)}" placeholder="搜索 IP、MAC、主机名、归属或备注" aria-label="搜索 IP 地址">
        </label>
      </div>
    </div>`;
  }

  function rowMarkup(address) {
    const status = addressStatus(address);
    const identity = firstText(address.hostname, address.owner, '--');
    const identityNote = address.hostname && address.owner ? address.owner : address.note;
    return `<tr class="ipam-address-row${address.conflict ? ' is-conflict' : ''}" tabindex="0" role="button" aria-label="查看 ${escapeHtml(address.ip || '地址')} 详情" data-ipam-detail="${escapeHtml(address.id)}">
      <td class="ipam-address-cell" data-label="IP 地址"><strong>${escapeHtml(address.ip || '--')}</strong><small>${escapeHtml(address.networkName || address.networkId || '--')}</small></td>
      <td class="ipam-status-cell" data-label="状态">${statusBadge(status.label, status.tone, { dot: status.tone === 'success' })}</td>
      <td class="ipam-identity-cell" data-label="主机 / 归属"><strong>${escapeHtml(identity)}</strong><small>${escapeHtml(identityNote || '--')}</small></td>
      <td class="ipam-mac-cell ipam-monospace" data-label="MAC 地址">${escapeHtml(address.mac || '--')}</td>
      <td class="ipam-source-cell" data-label="来源 / 类型"><strong>${escapeHtml(sourceLabel(address.source))}</strong><small>${escapeHtml(typeLabel(address.type))}</small></td>
      <td class="ipam-seen-cell" data-label="最近看到">${escapeHtml(formatTime(address.lastSeen))}</td>
    </tr>`;
  }

  function bodyMarkup() {
    const viewState = snapshotState();
    const rows = filteredAddresses();
    if (viewState.key === 'loading') return `<tr><td class="dwrt-kit-table-empty" colspan="6" data-dwrt-component="state-panel" data-dwrt-state="loading">${escapeHtml(viewState.detail)}</td></tr>`;
    if (['error', 'forbidden', 'unavailable'].includes(viewState.key)) return `<tr><td class="dwrt-kit-table-empty" colspan="6" data-dwrt-component="state-panel" data-dwrt-state="${escapeHtml(viewState.key)}">${escapeHtml(viewState.detail)}</td></tr>`;
    if (!rows.length) return '<tr><td class="dwrt-kit-table-empty" colspan="6">没有符合当前筛选条件的地址记录</td></tr>';
    return rows.map(rowMarkup).join('');
  }

  function workbenchMarkup() {
    return `<section class="ipam-workbench" data-dwrt-page-shell="data-workbench" data-ipam-version="${VERSION}">
      ${pageToolbarMarkup()}
      <section class="dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface ipam-table" data-dwrt-component="data-table" data-dwrt-surface="dense-surface">
        ${inventoryToolbarMarkup()}
        <div class="ipam-inventory-head">
          ${summaryMarkup()}
        </div>
        <div class="dwrt-kit-table-scroll ipam-table-scroll">
          <table class="dwrt-kit-table dwrt-kit-ikuai-table" aria-label="IP 地址清单">
            <thead><tr><th>IP 地址</th><th>状态</th><th>主机 / 归属</th><th>MAC 地址</th><th>来源 / 类型</th><th>最近看到</th></tr></thead>
            <tbody data-ipam-rows>${bodyMarkup()}</tbody>
          </table>
        </div>
      </section>
    </section>`;
  }

  function selectedAddress() {
    return allAddresses().find((address) => address.id === state.selectedId) || null;
  }

  function detailField(label, value) {
    return `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(firstText(value, '--'))}</dd></div>`;
  }

  function detailMarkup() {
    const address = selectedAddress();
    if (!address) return '';
    const status = addressStatus(address);
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-ipam-detail-close aria-label="关闭地址详情"></button>
      <aside class="dwrt-kit-sheet ipam-detail-sheet is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" aria-label="IP 地址详情">
        <header class="dwrt-kit-sheet-header"><div><span>地址详情</span><strong>${escapeHtml(address.ip || '--')}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-ipam-detail-close aria-label="关闭">${icon('x')}</button></header>
        <div class="dwrt-kit-sheet-body ipam-detail-body">
          <div class="ipam-detail-status">${statusBadge(status.label, status.tone, { dot: status.tone === 'success' })}<span>${escapeHtml(sourceLabel(address.source))}</span></div>
          <dl class="ipam-detail-list">
            ${detailField('网络', address.networkName || address.networkId)}
            ${detailField('子网', address.subnet)}
            ${detailField('网关', address.gateway)}
            ${detailField('DHCP 地址池', address.dhcpPool)}
            ${detailField('MAC 地址', address.mac)}
            ${detailField('主机名', address.hostname)}
            ${detailField('归属', address.owner)}
            ${detailField('类型', typeLabel(address.type))}
            ${detailField('来源', sourceLabel(address.source))}
            ${detailField('最近看到', formatTime(address.lastSeen))}
            ${detailField('备注', address.note)}
          </dl>
          <section class="ipam-readonly-note" data-dwrt-component="state-panel" data-dwrt-state="unavailable"><strong>当前为只读盘点</strong><span>数据来自 IP 地址盘点接口，本页不会修改地址配置。</span></section>
        </div>
      </aside>`;
  }

  function replaceMarkup(host, markup) {
    /*
     * 先回收传送门里的抽屉，再交给 kit 卸载。kit 的 unmount(host) 只走 host 子树，
     * 而 mountAll() 已经把 `.dwrt-kit-sheet` 与遮罩搬去 #dwrtKitSheetPortal，
     * 于是卸载扫不到它们，关闭后遮罩留在页面上吞掉全部点击。详见 policy-objects.js。
     */
    reclaimPortaledSheets(host);
    window.DWRT_UI_KIT?.unmount?.(host);
    host.replaceChildren(document.createRange().createContextualFragment(markup));
    host.querySelectorAll('.dwrt-kit-sheet, .dwrt-kit-sheet-overlay')
      .forEach((node) => { node.dataset.ipamOverlayOwned = ''; });
    ui.mountAll?.(host);
  }

  /* 把本宿主搬出去的抽屉与遮罩接回来，让 kit 的 unmount 能够看到它们。 */
  function reclaimPortaledSheets(host) {
    const portal = document.getElementById('dwrtKitSheetPortal');
    if (!portal) return;
    portal.querySelectorAll('.dwrt-kit-sheet, .dwrt-kit-sheet-overlay').forEach((node) => {
      if (node.dataset.ipamOverlayOwned === undefined) return;
      host.append(node);
    });
  }

  function renderPage() {
    if (!state.mounted) return;
    replaceMarkup(pageHost, workbenchMarkup());
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
    if (!state.mounted) return;
    replaceMarkup(overlayHost, detailMarkup());
  }

  function syncFilteredRows() {
    const tbody = pageHost.querySelector('[data-ipam-rows]');
    if (!tbody) return renderPage();
    tbody.innerHTML = bodyMarkup();
    const rows = filteredAddresses();
    const count = pageHost.querySelector('[data-ipam-count]');
    if (count) count.textContent = `显示 ${rows.length} / 共 ${allAddresses().length}`;
    const readState = pageHost.querySelector('[data-ipam-read-state] > span:last-child');
    if (readState) readState.textContent = snapshotState().detail;
    const totals = summary();
    Object.entries({ observed: totals.observed, used: totals.used, reserved: totals.reserved, conflicts: totals.conflicts, total: totals.total }).forEach(([key, value]) => {
      const node = pageHost.querySelector(`[data-ipam-summary-value="${key}"]`);
      if (node) node.textContent = String(value);
    });
    const conflictMetric = pageHost.querySelector('[data-ipam-summary-value="conflicts"]')?.parentElement;
    conflictMetric?.classList.toggle('is-alert', totals.conflicts > 0);
    const counts = statusCounts();
    const labels = { all: '全部状态', used: '已使用', reserved: '已保留', free: '可用', conflict: '冲突', unknown: '未知' };
    pageHost.querySelectorAll('[data-ipam-status-option]').forEach((option) => {
      const key = option.dataset.ipamStatusOption;
      option.textContent = `${labels[key] || key} (${counts[key] || 0})`;
    });
    ui.mountAll?.(tbody);
  }

  function hydrate(snapshot) {
    state.snapshot = snapshot;
    if (snapshot?.value) {
      state.inventory = normalizeInventory(snapshot.value);
      const ids = new Set(availableNetworks().map((network) => network.id));
      if (!state.network || (state.network !== 'all' && !ids.has(state.network))) state.network = state.inventory.selectedNetwork || 'all';
      const sources = new Set(allAddresses().map((address) => address.source));
      if (state.source !== 'all' && !sources.has(state.source)) state.source = 'all';
      if (state.selectedId && !selectedAddress()) state.selectedId = '';
    }
    renderPagePreservingInteraction();
    renderOverlay();
  }

  function refresh() {
    if (!registry || state.refreshPromise) return state.refreshPromise;
    registry.invalidate?.('network.ipam', { abort: false });
    state.refreshPromise = registry.request('network.ipam', { force: true, signal })
      .finally(() => {
        state.refreshPromise = null;
        if (state.mounted) renderPage();
      });
    renderPage();
    return state.refreshPromise;
  }

  function onClick(event) {
    const detail = event.target.closest('[data-ipam-detail]');
    if (detail) {
      state.selectedId = detail.dataset.ipamDetail || '';
      renderOverlay();
      return;
    }
    if (event.target.closest('[data-ipam-detail-close]')) {
      state.selectedId = '';
      renderOverlay();
    }
  }

  function onKeydown(event) {
    const detail = event.target.closest('[data-ipam-detail]');
    if (!detail || !['Enter', ' '].includes(event.key)) return;
    event.preventDefault();
    state.selectedId = detail.dataset.ipamDetail || '';
    renderOverlay();
  }

  function onInput(event) {
    if (!event.target.matches('[data-ipam-search]')) return;
    state.query = event.target.value;
    syncFilteredRows();
  }

  function onChange(event) {
    if (event.target.matches('[data-ipam-network]')) state.network = event.target.value;
    else if (event.target.matches('[data-ipam-status]')) state.status = event.target.value;
    else if (event.target.matches('[data-ipam-source]')) state.source = event.target.value;
    else return;
    syncFilteredRows();
  }

  root.hidden = false;
  root.className = 'route-preview route-workspace ip-address-management-route-host';
  root.replaceChildren(pageHost, overlayHost);
  root.addEventListener('click', onClick);
  root.addEventListener('keydown', onKeydown);
  root.addEventListener('input', onInput);
  root.addEventListener('change', onChange);
  stage?.classList.add('is-ip-address-management');
  const unsubscribe = registry?.subscribe?.('network.ipam', hydrate) || null;
  renderPage();
  renderOverlay();
  registry?.request?.('network.ipam', { signal });
  startPolling();

  return {
    refresh,
    unmount() {
      state.mounted = false;
      stopPolling();
      unsubscribe?.();
      root.removeEventListener('click', onClick);
      root.removeEventListener('keydown', onKeydown);
      root.removeEventListener('input', onInput);
      root.removeEventListener('change', onChange);
      window.DWRT_UI_KIT?.unmount?.(root);
      root.replaceChildren();
      root.classList.remove('route-workspace', 'ip-address-management-route-host');
      stage?.classList.remove('is-ip-address-management');
    }
  };
}

export default { mount };
