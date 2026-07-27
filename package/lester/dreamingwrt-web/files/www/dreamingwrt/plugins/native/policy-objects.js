export function normalizePolicyObjects(payload = {}) {
  const list = (value) => Array.isArray(value) ? value : [];
  const text = (...values) => values.map((value) => String(value ?? '').trim()).find(Boolean) || '';
  const normalize = (item = {}, index = 0, legacy = false) => ({
    id: text(item.id, `${legacy ? 'legacy' : 'object'}-${index + 1}`),
    name: text(item.name, item.label, `对象 ${index + 1}`),
    type: text(item.object_type, item.type, legacy ? 'route_object' : 'composite'),
    family: text(item.family, 'mixed'),
    value: text(item.value),
    comment: text(item.comment),
    enabled: item.enabled !== false,
    updatedAt: Number(item.updated_at) || 0,
    legacy
  });
  const capabilities = payload.capabilities && typeof payload.capabilities === 'object' ? payload.capabilities : {};
  return {
    items: list(payload.items).map((item, index) => normalize(item, index)),
    legacy: list(payload.legacy_route_objects).map((item, index) => normalize(item, index, true)),
    blockedBy: list(payload.blocked_by).map(String),
    readOnly: payload.read_only === true || capabilities.objects_crud !== true || capabilities.objects_atomic_apply !== true,
    capabilities,
    source: text(payload.source)
  };
}

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const registry = context.registry;
  const ui = context.ui || {};
  const signal = context.signal;
  const escapeHtml = context.utils?.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const state = { mounted: true, snapshot: null, data: null, refreshing: false, refreshQueued: false, refreshPromise: null, detail: null };
  const pageHost = document.createElement('div');
  const overlayHost = document.createElement('div');
  pageHost.className = 'policy-entity-page-host';
  overlayHost.className = 'policy-entity-overlay-host';
  const icon = (name) => window.DWRT_UI_KIT?.lucideIcon?.(name, { size: 18, strokeWidth: 1.8 }) || '';
  const statusBadge = (label, tone = 'muted') => ui.statusBadgeMarkup?.(label, tone) || `<span>${escapeHtml(label)}</span>`;
  const statePanel = (name, title, detail) => `<section data-dwrt-component="state-panel" data-dwrt-state="${name}"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(detail)}</p></section>`;
  const button = (label, attributes = '', variant = 'secondary', iconName = '') => `<button type="button" data-dwrt-component="button" data-variant="${variant}" ${attributes}>${iconName ? icon(iconName) : ''}<span>${escapeHtml(label)}</span></button>`;

  function blockReason() {
    const reason = state.data?.capabilities?.objects_write_blocked_reason || state.data?.blockedBy?.[0] || '';
    const labels = {
      composite_object_schema_pending: '复合对象的数据模型尚未完成',
      cross_component_firewall_pbr_sqm_flowd_transaction_pending: '跨防火墙、路由、QoS 与流量引擎的原子事务尚未闭环'
    };
    return labels[reason] || '后端尚未开放复合对象的原子写入能力';
  }

  function pageState() {
    const snapshot = state.snapshot;
    if (!registry) return { name: 'unavailable', title: '对象数据合同不可用', detail: '当前页面没有获得共享 DataRegistry。' };
    if (!snapshot || (['empty', 'loading'].includes(snapshot.status) && snapshot.value === undefined)) return { name: 'loading', title: '正在读取对象', detail: '页面骨架已就绪，等待策略对象权威快照。' };
    if (snapshot.status === 'forbidden' && snapshot.value === undefined) return { name: 'forbidden', title: '无权读取对象', detail: '当前账号没有策略对象的读取权限。' };
    if (['error', 'unavailable'].includes(snapshot.status) && snapshot.value === undefined) return { name: snapshot.status, title: '无法读取对象', detail: snapshot.error?.message || '对象接口当前不可用。' };
    return null;
  }

  function rowsMarkup(rows, legacy = false) {
    if (!rows.length) return statePanel('empty', legacy ? '没有兼容路由对象' : '尚未创建复合对象', legacy ? '旧路由对象目录为空。' : '写入能力开放后，可按目标和意图创建复合对象。');
    return `<div data-dwrt-component="data-table" data-dwrt-surface="dense-surface" class="policy-entity-table"><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table"><thead><tr><th>名称</th><th>类型</th><th>地址族</th><th>状态</th><th><span class="policy-entity-visually-hidden">详情</span></th></tr></thead><tbody>${rows.map((item) => `<tr><td><strong>${escapeHtml(item.name)}</strong>${item.comment ? `<small>${escapeHtml(item.comment)}</small>` : ''}</td><td>${escapeHtml(legacy ? '路由对象' : item.type)}</td><td>${escapeHtml(item.family || '--')}</td><td>${statusBadge(item.enabled ? '启用' : '停用', item.enabled ? 'success' : 'muted')}</td><td><button type="button" data-dwrt-component="icon-button" data-object-detail="${escapeHtml(`${legacy ? 'legacy:' : 'object:'}${item.id}`)}" aria-label="查看 ${escapeHtml(item.name)}">${icon('chevron-right')}</button></td></tr>`).join('')}</tbody></table></div></div>`;
  }

  function detailMarkup() {
    const item = state.detail;
    if (!item) return '';
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-object-detail-close aria-label="关闭对象详情"></button><aside data-dwrt-component="sheet" data-dwrt-surface="stable-glass" class="dwrt-kit-sheet policy-entity-sheet is-open"><header class="dwrt-kit-sheet-header"><div><span>${item.legacy ? '兼容路由对象' : '复合对象'}</span><strong>${escapeHtml(item.name)}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-object-detail-close aria-label="关闭">${icon('x')}</button></header><div class="dwrt-kit-sheet-body policy-entity-sheet-body"><dl class="policy-entity-detail-list"><div><dt>对象标识</dt><dd>${escapeHtml(item.id)}</dd></div><div><dt>类型</dt><dd>${escapeHtml(item.type)}</dd></div><div><dt>地址族</dt><dd>${escapeHtml(item.family || '--')}</dd></div><div><dt>值</dt><dd>${escapeHtml(item.value || '--')}</dd></div><div><dt>状态</dt><dd>${escapeHtml(item.enabled ? '启用' : '停用')}</dd></div></dl>${item.legacy ? statePanel('unavailable', '兼容对象保持只读', '它属于路由对象合同，不等同于可同时生成安全、路由和 QoS 策略的复合对象。') : ''}</div><footer class="dwrt-kit-sheet-footer"><span></span>${button('关闭', 'data-object-detail-close', 'primary')}</footer></aside>`;
  }

  function workbenchMarkup() {
    const data = state.data;
    const stale = state.snapshot?.stale ? `<div class="policy-entity-alert is-warning" role="status"><strong>正在显示上次可用快照</strong><span>刷新失败，当前对象列表已保留。</span></div>` : '';
    const readOnly = data.readOnly ? statePanel('unavailable', '复合对象暂为只读', `${blockReason()}。页面不会展示无法提交的名称、成员或模块开关。`) : '';
    return `<section data-dwrt-component="page-shell" data-dwrt-page-shell="data-workbench" data-dwrt-surface="stable-glass" class="policy-entity-page policy-objects-page"><header class="policy-entity-header"><div><h1 data-dwrt-page-title>对象</h1><p>集中查看可被策略引用的复合对象与兼容路由对象。</p></div><div class="policy-entity-header-actions">${statusBadge(data.readOnly ? '只读' : '可编辑', data.readOnly ? 'warning' : 'success')}${button(state.refreshing ? '正在刷新' : '刷新', `data-object-refresh ${state.refreshing ? 'disabled' : ''}`, 'ghost', 'refresh-cw')}</div></header>${stale}<section class="policy-entity-summary" aria-label="对象概览"><div><span>复合对象</span><strong>${data.items.length}</strong><small>安全、路由与 QoS 的统一目标</small></div><div><span>兼容对象</span><strong>${data.legacy.length}</strong><small>仅供现有路由规则引用</small></div><div><span>写入合同</span><strong>${data.readOnly ? '未开放' : '已开放'}</strong><small>${escapeHtml(data.source || '策略引擎')}</small></div></section>${readOnly}<section class="policy-entity-section"><header><div><h2>复合对象</h2><p>对象只出现一次，具体策略通过引用建立关系。</p></div></header>${rowsMarkup(data.items)}</section>${data.legacy.length ? `<section class="policy-entity-section"><header><div><h2>兼容路由对象</h2><p>保留旧配置语义，不混入复合对象编辑流程。</p></div></header>${rowsMarkup(data.legacy, true)}</section>` : ''}</section>`;
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
      ? `<section data-dwrt-component="page-shell" data-dwrt-page-shell="data-workbench" data-dwrt-surface="stable-glass" class="policy-entity-page policy-objects-page"><header class="policy-entity-header"><div><h1 data-dwrt-page-title>对象</h1><p>集中查看可被策略引用的复合对象与兼容路由对象。</p></div></header>${statePanel(terminal.name, terminal.title, terminal.detail)}</section>`
      : workbenchMarkup());
  }

  function renderOverlay() {
    if (!root || !state.mounted) return;
    replaceMarkup(overlayHost, detailMarkup());
  }

  function render() {
    renderPage();
    renderOverlay();
  }

  function hydrate(snapshot) {
    state.snapshot = snapshot;
    if (snapshot?.value) state.data = normalizePolicyObjects(snapshot.value);
    renderPage();
  }

  function refresh() {
    if (!registry) return Promise.resolve();
    if (state.refreshPromise) {
      state.refreshQueued = true;
      return state.refreshPromise;
    }
    state.refreshPromise = (async () => {
      do {
        state.refreshQueued = false;
        state.refreshing = true;
        renderPage();
        await registry.request('policy.objects', { signal, force: true });
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
    if (event.target.closest('[data-object-refresh]')) return void refresh();
    const open = event.target.closest('[data-object-detail]');
    if (open) {
      const [kind, id] = String(open.dataset.objectDetail || '').split(':');
      state.detail = (kind === 'legacy' ? state.data?.legacy : state.data?.items)?.find((item) => item.id === id) || null;
      renderOverlay();
      return;
    }
    if (event.target.closest('[data-object-detail-close]')) { state.detail = null; renderOverlay(); }
  }

  root.hidden = false;
  root.className = 'route-preview route-workspace policy-objects-route-host';
  root.replaceChildren(pageHost, overlayHost);
  root.addEventListener('click', onClick);
  const unsubscribe = registry?.subscribe?.('policy.objects', hydrate) || null;
  render();
  registry?.request?.('policy.objects', { signal });

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
