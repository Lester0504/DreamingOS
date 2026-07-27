export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));
  const formatInteger = utils.formatInteger || ((value) => new Intl.NumberFormat('zh-CN').format(Number(value) || 0));
  const VERSION = '20260710-02';
  const MODULE_CLASS = 'terminal-groups-route-host';
  const ENDPOINT = '/api/v1/policy-engine/terminal-groups';
  const CLIENTS_ENDPOINT = '/api/v1/clients';

  const state = {
    mounted: true,
    available: false,
    loading: true,
    clientsLoading: true,
    groups: [],
    clients: [],
    capabilities: {},
    source: '',
    error: '',
    clientsError: '',
    query: '',
    drawerOpen: false,
    drawerMode: 'create',
    draft: emptyDraft(),
    memberQuery: '',
    memberKind: 'all',
    saving: false,
    deleting: false,
    confirmDelete: false,
    importPreview: null,
    importMode: 'merge',
    notice: '',
    seq: 0
  };

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (typeof value === 'object' && !Array.isArray(value)) {
        const nested = firstText(value.name, value.label, value.value, value.id);
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

  function asArray(value) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of ['groups', 'items', 'rows', 'clients', 'members', 'data']) {
      if (Array.isArray(value[key])) return value[key];
    }
    return [];
  }

  function unwrap(value) {
    let current = value?.data ?? value ?? {};
    for (let index = 0; index < 3; index += 1) {
      if (!current || typeof current !== 'object' || Array.isArray(current) || !current.data || typeof current.data !== 'object') break;
      current = current.data;
    }
    return current || {};
  }

  function macKey(value) {
    return firstText(value).toLowerCase().replace(/-/g, ':');
  }

  function emptyDraft() {
    return { id: '', name: '', description: '', members: new Map() };
  }

  function normalizeMember(value = {}, index = 0) {
    if (typeof value === 'string') value = value.includes(':') ? { mac: value } : { ip: value };
    return {
      mac: macKey(value.mac || value.client_mac || value.hwaddr),
      ip: firstText(value.ip, value.ipv4, value.address),
      name: firstText(value.name, value.display_name, value.hostname, value.nickname),
      added_at: firstNumber(value.added_at, value.created_at),
      order: firstNumber(value.order, value.position, index)
    };
  }

  function memberKey(value = {}) {
    return macKey(value.mac) || (value.ip ? `ip:${value.ip}` : '');
  }

  function normalizeGroup(value = {}, index = 0) {
    const members = asArray(value.members || value.clients || value.terminals).map(normalizeMember).filter((item) => memberKey(item));
    return {
      id: firstText(value.id, value.uuid, value.group_id, value.name) || `group-${index}`,
      name: firstText(value.name, value.label, value.group_name) || `终端分组 ${index + 1}`,
      description: firstText(value.description, value.remark, value.note),
      color: firstText(value.color),
      members,
      member_count: Math.max(members.length, firstNumber(value.member_count, value.client_count, value.count)),
      policy_count: firstNumber(value.policy_count, value.rule_count),
      created_at: firstNumber(value.created_at),
      updated_at: firstNumber(value.updated_at, value.created_at),
      raw: value
    };
  }

  function normalizeClient(value = {}, index = 0) {
    const mac = macKey(value.mac || value.client_mac || value.hwaddr);
    return {
      key: mac || `ip:${firstText(value.ip, value.ipv4)}` || `client-${index}`,
      mac,
      ip: firstText(value.ip, value.ipv4),
      ipv6: firstText(value.ipv6_global, value.global_ipv6, value.ipv6),
      name: firstText(value.display_name, value.custom_name, value.nickname, value.hostname, value.name, value.ip, mac, '未命名终端'),
      vendor: firstText(value.vendor_name, value.vendor, value.manufacturer),
      online: value.online === true || value.online === 1 || value.online === '1' || /online|active|up|在线/i.test(firstText(value.status, value.state)),
      raw: value
    };
  }

  function authHeaders(extra = {}) {
    let token = '';
    try { token = localStorage.getItem('dreamingwrt.web.accessToken') || ''; } catch (_) {}
    return { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}), ...extra };
  }

  async function requestJson(url, options = {}) {
    const response = await fetch(`${url}${url.includes('?') ? '&' : '?'}v=${encodeURIComponent(VERSION)}`, {
      credentials: 'same-origin',
      cache: 'no-store',
      ...options,
      headers: authHeaders({ Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    if (!response.ok || json?.ok === false) {
      const error = new Error(firstText(json?.error?.message, json?.error?.code, json?.message, json?.code, `${response.status}`));
      error.status = response.status;
      error.payload = json;
      throw error;
    }
    return json;
  }

  function normalizeCapabilities(data = {}) {
    const caps = data.capabilities && typeof data.capabilities === 'object' ? data.capabilities : {};
    const writable = data.writable === true || caps.write === true || caps.writable === true;
    return {
      create: caps.create === true || writable,
      update: caps.update === true || writable,
      delete: caps.delete === true || writable,
      import: caps.import === true || writable,
      replace_import: caps.replace_import === true,
      export: caps.export !== false
    };
  }

  async function load() {
    const seq = ++state.seq;
    state.loading = true;
    state.clientsLoading = true;
    render();
    const [groupResult, clientResult] = await Promise.allSettled([
      requestJson(`${ENDPOINT}?include_members=1`),
      requestJson(CLIENTS_ENDPOINT)
    ]);
    if (!state.mounted || seq !== state.seq) return;
    if (groupResult.status === 'fulfilled') {
      const data = unwrap(groupResult.value);
      state.groups = asArray(data.groups || data.items || data).map(normalizeGroup);
      state.capabilities = normalizeCapabilities(data);
      state.source = firstText(data.source, groupResult.value?.meta?.source, 'config.db:terminal_groups');
      state.available = true;
      state.error = '';
    } else {
      state.groups = [];
      state.capabilities = {};
      state.available = false;
      const status = groupResult.reason?.status;
      state.error = status === 404
        ? '终端分组后端尚未接入，等待 config.db 分组接口。'
        : `终端分组读取失败：${firstText(groupResult.reason?.message, 'unknown')}`;
    }
    if (clientResult.status === 'fulfilled') {
      const data = unwrap(clientResult.value);
      state.clients = asArray(data.clients || data.items || data).map(normalizeClient).filter((item) => item.mac || item.ip);
      state.clientsError = '';
    } else {
      state.clients = [];
      state.clientsError = `终端列表读取失败：${firstText(clientResult.reason?.message, 'unknown')}`;
    }
    state.loading = false;
    state.clientsLoading = false;
    if (document.activeElement?.matches('[data-terminal-group-search]')) patchLoadedTable();
    else render();
  }

  function can(action) {
    return state.available && state.capabilities[action] === true;
  }

  function filteredGroups() {
    const query = state.query.trim().toLowerCase();
    if (!query) return state.groups;
    return state.groups.filter((group) => [group.name, group.description, ...group.members.flatMap((member) => [member.name, member.ip, member.mac])].join(' ').toLowerCase().includes(query));
  }

  function icon(name) {
    const paths = {
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      upload: '<path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5"></path><path d="M5 14v5h14v-5"></path>',
      download: '<path d="M12 4v12m0 0 4.5-4.5M12 16l-4.5-4.5"></path><path d="M5 19h14"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      edit: '<path d="m4 20 4.3-1 10.8-10.8a2 2 0 0 0-2.8-2.8L5.5 16.2 4 20Z"></path>',
      trash: '<path d="M4 7h16M9 7V4h6v3m3 0-1 13H7L6 7m4 4v5m4-5v5"></path>',
      user: '<circle cx="12" cy="8" r="3.5"></circle><path d="M5 20a7 7 0 0 1 14 0"></path>',
      check: '<path d="m5 12 4 4L19 6"></path>',
      close: '<path d="m6 6 12 12M18 6 6 18"></path>'
    };
    return `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.user}</svg>`;
  }

  function formatTime(value) {
    const raw = Number(value) || 0;
    if (!raw) return '--';
    const timestamp = raw < 100000000000 ? raw * 1000 : raw;
    return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(timestamp);
  }

  function renderToolbar() {
    const importDisabled = state.clientsLoading ? 'disabled' : '';
    const exportDisabled = state.groups.length ? '' : 'disabled';
    return `<header class="policy-toolbar terminal-group-toolbar">
      <label class="policy-search policy-search-main" data-dwrt-component="expand-search">${icon('search')}<input type="search" data-terminal-group-search placeholder="搜索分组、终端、IP 或 MAC" value="${escapeHtml(state.query)}"></label>
      <div class="policy-toolbar-actions terminal-group-toolbar-actions">
        <button class="policy-filter-button" type="button" data-terminal-group-import ${importDisabled}>${icon('upload')}<span>导入</span></button>
        <button class="policy-filter-button" type="button" data-terminal-group-export="json" ${exportDisabled}>${icon('download')}<span>导出 JSON</span></button>
        <button class="policy-filter-button terminal-group-export-csv" type="button" data-terminal-group-export="csv" ${exportDisabled}>CSV</button>
        <button class="policy-create-button" type="button" data-terminal-group-create>${icon('plus')}<span>创建分组</span></button>
      </div>
      <input type="file" data-terminal-group-import-file accept=".json,.csv,application/json,text/csv" hidden>
    </header>`;
  }

  function groupRow(group) {
    const memberNames = group.members.slice(0, 3).map((member) => member.name || member.ip || member.mac).filter(Boolean);
    const summary = memberNames.length ? `${memberNames.join('、')}${group.member_count > memberNames.length ? ` 等 ${group.member_count} 个` : ''}` : `${formatInteger(group.member_count)} 个终端`;
    return `<tr data-terminal-group-id="${escapeHtml(group.id)}">
      <td><button class="terminal-group-name" type="button" data-terminal-group-edit="${escapeHtml(group.id)}"><strong>${escapeHtml(group.name)}</strong><span>${escapeHtml(group.description || '未填写说明')}</span></button></td>
      <td class="num"><strong>${escapeHtml(formatInteger(group.member_count))}</strong></td>
      <td><span class="terminal-group-member-summary" title="${escapeHtml(summary)}">${escapeHtml(summary)}</span></td>
      <td class="num">${escapeHtml(formatInteger(group.policy_count))}</td>
      <td><time>${escapeHtml(formatTime(group.updated_at))}</time></td>
      <td class="terminal-group-actions">
        <button type="button" data-terminal-group-edit="${escapeHtml(group.id)}" title="编辑分组" aria-label="编辑 ${escapeHtml(group.name)}">${icon('edit')}</button>
      </td>
    </tr>`;
  }

  function renderTable() {
    const groups = filteredGroups();
    const subtitle = state.loading ? '正在读取 config.db 分组' : state.error || (state.source ? `数据源：${state.source}` : '按终端身份维护策略对象');
    return `<section class="terminal-group-table-card dwrt-kit-table-wrap dwrt-kit-datatable-wrap dwrt-kit-glass-surface">
      <div class="dwrt-kit-table-toolbar terminal-group-table-toolbar">
        <div class="dwrt-kit-table-title"><strong>终端分组</strong><span class="${state.error ? 'is-warning' : ''}">${escapeHtml(subtitle)}</span></div>
        <div class="terminal-group-table-meta"><span class="dwrt-kit-table-count">${escapeHtml(formatInteger(groups.length))} 个分组 · ${escapeHtml(formatInteger(groups.reduce((sum, item) => sum + item.member_count, 0)))} 个成员</span><button type="button" data-terminal-group-refresh title="刷新" aria-label="刷新终端分组">${icon('refresh')}</button></div>
      </div>
      <div class="dwrt-kit-table-scroll terminal-group-table-scroll">
        <table class="dwrt-kit-table dwrt-kit-datatable terminal-group-table">
          <thead><tr><th>分组名称</th><th class="num">成员</th><th>终端摘要</th><th class="num">关联策略</th><th>更新时间</th><th>操作</th></tr></thead>
          <tbody>${state.loading ? '<tr><td colspan="6" class="dwrt-kit-table-empty">正在读取终端分组</td></tr>' : groups.length ? groups.map(groupRow).join('') : `<tr><td colspan="6" class="dwrt-kit-table-empty">${escapeHtml(state.query ? '没有匹配的终端分组' : state.error || '暂无终端分组')}</td></tr>`}</tbody>
        </table>
      </div>
    </section>`;
  }

  function patchLoadedTable() {
    const card = root.querySelector('.terminal-group-table-card');
    if (!card) return render();
    const scroll = card.querySelector('.terminal-group-table-scroll');
    const scrollTop = scroll?.scrollTop || 0;
    const scrollLeft = scroll?.scrollLeft || 0;
    card.outerHTML = renderTable();
    const nextScroll = root.querySelector('.terminal-group-table-scroll');
    if (nextScroll) {
      nextScroll.scrollTop = scrollTop;
      nextScroll.scrollLeft = scrollLeft;
    }
    const importButton = root.querySelector('[data-terminal-group-import]');
    if (importButton) importButton.disabled = state.clientsLoading;
    root.querySelectorAll('[data-terminal-group-export]').forEach((button) => { button.disabled = !state.groups.length; });
    bindTableActions();
  }

  function currentDraftMembers() {
    return state.draft.members instanceof Map ? state.draft.members : new Map();
  }

  function filteredClients() {
    const query = state.memberQuery.trim().toLowerCase();
    return state.clients.filter((client) => {
      if (state.memberKind === 'ip' && !client.ip.toLowerCase().includes(query)) return false;
      if (state.memberKind === 'mac' && !client.mac.toLowerCase().includes(query)) return false;
      if (state.memberKind === 'all' && query && ![client.name, client.vendor, client.ip, client.ipv6, client.mac].join(' ').toLowerCase().includes(query)) return false;
      if (state.memberKind !== 'all' && !query) return true;
      return true;
    });
  }

  function clientMemberRow(client, selected = false) {
    return `<button class="terminal-group-member-row ${selected ? 'is-selected' : ''}" type="button" data-terminal-group-member="${escapeHtml(client.key)}">
      <span class="terminal-group-member-icon">${selected ? icon('check') : icon('user')}</span>
      <span><strong>${escapeHtml(client.name)}</strong><small>${escapeHtml([client.ip, client.mac].filter(Boolean).join(' · ') || '--')}</small></span>
      <em>${client.online ? '在线' : '离线'}</em>
    </button>`;
  }

  function selectedMemberRow(member) {
    const client = state.clients.find((item) => (member.mac && item.mac === member.mac) || (!member.mac && member.ip && item.ip === member.ip));
    const value = client || { ...member, key: memberKey(member), online: false, vendor: '' };
    return `<div class="terminal-group-member-row is-selected">
      <span class="terminal-group-member-icon">${icon('check')}</span>
      <span><strong>${escapeHtml(value.name || value.ip || value.mac || '未命名终端')}</strong><small>${escapeHtml([value.ip, value.mac].filter(Boolean).join(' · ') || '--')}</small></span>
      <button type="button" data-terminal-group-member-remove="${escapeHtml(memberKey(member))}" aria-label="移除成员">${icon('close')}</button>
    </div>`;
  }

  function memberPickerMarkup() {
    const selected = currentDraftMembers();
    const clients = filteredClients();
    return `<section class="terminal-group-member-picker">
      <div class="terminal-group-member-pane">
        <header><strong>选择终端</strong><span data-terminal-group-available-count>${escapeHtml(formatInteger(clients.length))} 个可选</span></header>
        <label class="terminal-group-member-search">${icon('search')}<input data-terminal-group-member-search type="search" value="${escapeHtml(state.memberQuery)}" placeholder="搜索终端"></label>
        <nav class="dwrt-kit-tabs terminal-group-member-tabs" aria-label="成员搜索类型">
          <span class="dwrt-kit-tab-pill" aria-hidden="true"></span>
          ${[['all', '全部'], ['ip', 'IP'], ['mac', 'MAC']].map(([key, label]) => `<button class="dwrt-kit-tab ${state.memberKind === key ? 'is-active' : ''}" type="button" data-terminal-group-member-kind="${key}" aria-selected="${state.memberKind === key ? 'true' : 'false'}">${label}</button>`).join('')}
        </nav>
        <div class="terminal-group-member-list" data-terminal-group-available>${state.clientsLoading ? '<div class="terminal-group-member-empty">正在读取终端</div>' : clients.length ? clients.map((client) => clientMemberRow(client, selected.has(client.key))).join('') : `<div class="terminal-group-member-empty">${escapeHtml(state.clientsError || '没有匹配的终端')}</div>`}</div>
      </div>
      <div class="terminal-group-member-pane is-selected-pane">
        <header><strong data-terminal-group-selected-count>已选 ${escapeHtml(formatInteger(selected.size))} 个</strong><button type="button" data-terminal-group-members-clear ${selected.size ? '' : 'disabled'}>清空</button></header>
        <div class="terminal-group-member-list" data-terminal-group-selected>${selected.size ? [...selected.values()].map(selectedMemberRow).join('') : '<div class="terminal-group-member-empty">暂未选择终端</div>'}</div>
      </div>
    </section>`;
  }

  function importPreviewMarkup() {
    const preview = state.importPreview;
    if (!preview) return '<div class="terminal-group-member-empty">选择 JSON 或 CSV 文件后将在这里预览。</div>';
    const members = preview.groups.reduce((sum, group) => sum + group.members.length, 0);
    return `<section class="terminal-group-import-preview">
      <div><strong>${escapeHtml(preview.fileName)}</strong><span>${escapeHtml(formatInteger(preview.groups.length))} 个分组 · ${escapeHtml(formatInteger(members))} 个成员</span></div>
      <label><span>导入方式</span><select data-terminal-group-import-mode><option value="merge" ${state.importMode === 'merge' ? 'selected' : ''}>合并，按 ID / 名称更新</option><option value="replace" ${state.importMode === 'replace' ? 'selected' : ''} ${state.capabilities.replace_import ? '' : 'disabled'}>替换全部现有分组</option></select></label>
      <div class="terminal-group-import-list">${preview.groups.map((group) => `<div><strong>${escapeHtml(group.name)}</strong><span>${escapeHtml(formatInteger(group.members.length))} 个成员${group.description ? ` · ${escapeHtml(group.description)}` : ''}</span></div>`).join('')}</div>
      ${preview.errors.length ? `<div class="terminal-group-import-errors">${preview.errors.map((error) => `<span>${escapeHtml(error)}</span>`).join('')}</div>` : ''}
    </section>`;
  }

  function renderDrawer() {
    if (!state.drawerOpen) return '';
    const importing = state.drawerMode === 'import';
    const editing = state.drawerMode === 'edit';
    const title = importing ? '导入终端分组' : editing ? '编辑终端分组' : '创建终端分组';
    const saveAllowed = importing ? can('import') && state.importPreview && !state.importPreview.errors.length : can(editing ? 'update' : 'create') && state.draft.name.trim();
    return `<button class="policy-drawer-backdrop dwrt-kit-sheet-overlay is-open" type="button" data-terminal-group-close aria-label="关闭终端分组面板"></button>
      <aside class="terminal-group-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" aria-label="${escapeHtml(title)}">
        <header class="dwrt-kit-sheet-header terminal-group-drawer-head"><div><span>TERMINAL GROUP</span><strong>${escapeHtml(title)}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-terminal-group-close aria-label="关闭">×</button></header>
        <div class="dwrt-kit-sheet-body terminal-group-drawer-body">
          ${importing ? importPreviewMarkup() : `<div class="terminal-group-fields">
            <label class="terminal-group-field"><span>分组名称</span><input data-terminal-group-name maxlength="80" value="${escapeHtml(state.draft.name)}" placeholder="例如 家庭设备"></label>
            <label class="terminal-group-field"><span>说明</span><input data-terminal-group-description maxlength="240" value="${escapeHtml(state.draft.description)}" placeholder="可选"></label>
          </div>${memberPickerMarkup()}`}
          ${state.notice ? `<div class="terminal-group-notice ${/失败|未接入|错误/.test(state.notice) ? 'is-error' : ''}">${escapeHtml(state.notice)}</div>` : ''}
        </div>
        <footer class="dwrt-kit-sheet-footer terminal-group-drawer-footer">
          ${editing ? `<button class="policy-secondary danger" type="button" data-terminal-group-delete ${can('delete') && !state.deleting ? '' : 'disabled'}>${state.confirmDelete ? '再次点击删除' : '删除分组'}</button>` : '<span></span>'}
          <div><button class="policy-secondary" type="button" data-terminal-group-close>取消</button><button class="policy-primary" type="button" data-terminal-group-save ${saveAllowed && !state.saving ? '' : 'disabled'}>${state.saving ? '正在保存' : importing ? '确认导入' : '保存分组'}</button></div>
        </footer>
      </aside>`;
  }

  function render() {
    if (!root || !state.mounted) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'policy-table-route-host', MODULE_CLASS);
    root.innerHTML = `<section class="policy-table-shell terminal-group-shell">${renderToolbar()}${renderTable()}${renderDrawer()}</section>`;
    bindEvents();
    ui.mountAll?.(root);
  }

  function draftFromGroup(group) {
    const members = new Map();
    group.members.forEach((member) => members.set(memberKey(member), { ...member }));
    return { id: group.id, name: group.name, description: group.description, members };
  }

  function openDrawer(mode, group = null) {
    state.drawerMode = mode;
    state.drawerOpen = true;
    state.notice = '';
    state.confirmDelete = false;
    state.memberQuery = '';
    state.memberKind = 'all';
    state.importPreview = null;
    state.draft = group ? draftFromGroup(group) : emptyDraft();
    render();
  }

  function closeDrawer() {
    state.drawerOpen = false;
    state.notice = '';
    state.confirmDelete = false;
    state.importPreview = null;
    render();
  }

  function patchMemberPicker() {
    const host = root.querySelector('.terminal-group-member-picker');
    if (!host) return render();
    const selected = currentDraftMembers();
    const clients = filteredClients();
    const available = host.querySelector('[data-terminal-group-available]');
    const selectedHost = host.querySelector('[data-terminal-group-selected]');
    const availableScroll = available ? { top: available.scrollTop, left: available.scrollLeft } : null;
    const selectedScroll = selectedHost ? { top: selectedHost.scrollTop, left: selectedHost.scrollLeft } : null;
    const availableCount = host.querySelector('[data-terminal-group-available-count]');
    const selectedCount = host.querySelector('[data-terminal-group-selected-count]');
    const clear = host.querySelector('[data-terminal-group-members-clear]');
    if (availableCount) availableCount.textContent = `${formatInteger(clients.length)} 个可选`;
    if (selectedCount) selectedCount.textContent = `已选 ${formatInteger(selected.size)} 个`;
    if (clear) clear.disabled = !selected.size;
    host.querySelectorAll('[data-terminal-group-member-kind]').forEach((button) => {
      const active = button.dataset.terminalGroupMemberKind === state.memberKind;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    if (available) {
      available.innerHTML = state.clientsLoading
        ? '<div class="terminal-group-member-empty">正在读取终端</div>'
        : clients.length
          ? clients.map((client) => clientMemberRow(client, selected.has(client.key))).join('')
          : `<div class="terminal-group-member-empty">${escapeHtml(state.clientsError || '没有匹配的终端')}</div>`;
      available.scrollTop = availableScroll.top;
      available.scrollLeft = availableScroll.left;
    }
    if (selectedHost) {
      selectedHost.innerHTML = selected.size
        ? [...selected.values()].map(selectedMemberRow).join('')
        : '<div class="terminal-group-member-empty">暂未选择终端</div>';
      selectedHost.scrollTop = selectedScroll.top;
      selectedHost.scrollLeft = selectedScroll.left;
    }
  }

  function bindMemberEvents() {
    const picker = root.querySelector('.terminal-group-member-picker');
    if (!picker) return;
    picker.querySelector('[data-terminal-group-member-search]')?.addEventListener('input', (event) => {
      state.memberQuery = event.target.value || '';
      patchMemberPicker();
    });
    picker.addEventListener('click', (event) => {
      const button = event.target.closest('button');
      if (!button || !picker.contains(button)) return;
      if (button.matches('[data-terminal-group-member-kind]')) {
        state.memberKind = button.dataset.terminalGroupMemberKind || 'all';
      } else if (button.matches('[data-terminal-group-member]')) {
        const client = state.clients.find((item) => item.key === button.dataset.terminalGroupMember);
        if (!client) return;
        const members = currentDraftMembers();
        if (members.has(client.key)) members.delete(client.key);
        else members.set(client.key, normalizeMember(client));
      } else if (button.matches('[data-terminal-group-member-remove]')) {
        currentDraftMembers().delete(button.dataset.terminalGroupMemberRemove);
      } else if (button.matches('[data-terminal-group-members-clear]')) {
        currentDraftMembers().clear();
      } else {
        return;
      }
      patchMemberPicker();
    });
  }

  function bindEvents() {
    root.querySelector('[data-terminal-group-search]')?.addEventListener('input', (event) => {
      state.query = event.target.value || '';
      const tbody = root.querySelector('.terminal-group-table tbody');
      const count = root.querySelector('.terminal-group-table-meta .dwrt-kit-table-count');
      const groups = filteredGroups();
      if (tbody) tbody.innerHTML = groups.length ? groups.map(groupRow).join('') : `<tr><td colspan="6" class="dwrt-kit-table-empty">${escapeHtml(state.query ? '没有匹配的终端分组' : state.error || '暂无终端分组')}</td></tr>`;
      if (count) count.textContent = `${formatInteger(groups.length)} 个分组 · ${formatInteger(groups.reduce((sum, item) => sum + item.member_count, 0))} 个成员`;
      bindTableActions();
    });
    bindTableActions();
    root.querySelector('[data-terminal-group-create]')?.addEventListener('click', () => openDrawer('create'));
    root.querySelectorAll('[data-terminal-group-close]').forEach((button) => button.addEventListener('click', closeDrawer));
    root.querySelector('[data-terminal-group-refresh]')?.addEventListener('click', load);
    root.querySelector('[data-terminal-group-import]')?.addEventListener('click', () => root.querySelector('[data-terminal-group-import-file]')?.click());
    root.querySelector('[data-terminal-group-import-file]')?.addEventListener('change', handleImportFile);
    root.querySelectorAll('[data-terminal-group-export]').forEach((button) => button.addEventListener('click', () => exportGroups(button.dataset.terminalGroupExport)));
    root.querySelector('[data-terminal-group-name]')?.addEventListener('input', (event) => { state.draft.name = event.target.value || ''; updateSaveButton(); });
    root.querySelector('[data-terminal-group-description]')?.addEventListener('input', (event) => { state.draft.description = event.target.value || ''; });
    root.querySelector('[data-terminal-group-import-mode]')?.addEventListener('change', (event) => { state.importMode = event.target.value === 'replace' ? 'replace' : 'merge'; });
    root.querySelector('[data-terminal-group-save]')?.addEventListener('click', saveCurrent);
    root.querySelector('[data-terminal-group-delete]')?.addEventListener('click', deleteCurrent);
    bindMemberEvents();
  }

  function bindTableActions() {
    root.querySelectorAll('[data-terminal-group-edit]').forEach((button) => button.addEventListener('click', () => {
      const group = state.groups.find((item) => item.id === button.dataset.terminalGroupEdit);
      if (group) openDrawer('edit', group);
    }));
  }

  function updateSaveButton() {
    const button = root.querySelector('[data-terminal-group-save]');
    if (!button || state.drawerMode === 'import') return;
    button.disabled = !can(state.drawerMode === 'edit' ? 'update' : 'create') || !state.draft.name.trim() || state.saving;
  }

  function draftPayload() {
    return {
      ...(state.draft.id ? { id: state.draft.id } : {}),
      name: state.draft.name.trim(),
      description: state.draft.description.trim(),
      members: [...currentDraftMembers().values()].map((member, index) => ({ mac: member.mac || '', ip: member.ip || '', name: member.name || '', order: index }))
    };
  }

  async function saveCurrent() {
    if (state.saving) return;
    const importing = state.drawerMode === 'import';
    const action = importing ? 'import' : state.drawerMode === 'edit' ? 'update' : 'create';
    if (!can(action)) {
      state.notice = '后端写入接口尚未接入，不能把分组伪存到浏览器。';
      render();
      return;
    }
    state.saving = true;
    state.notice = '';
    render();
    try {
      if (importing) {
        await requestJson(`${ENDPOINT}/import`, { method: 'POST', body: JSON.stringify({ mode: state.importMode, groups: state.importPreview.groups }) });
      } else {
        const payload = draftPayload();
        const url = state.drawerMode === 'edit' ? `${ENDPOINT}/${encodeURIComponent(state.draft.id)}` : ENDPOINT;
        await requestJson(url, { method: state.drawerMode === 'edit' ? 'PATCH' : 'POST', body: JSON.stringify(payload) });
      }
      state.drawerOpen = false;
      await load();
    } catch (error) {
      state.saving = false;
      state.notice = `保存失败：${firstText(error.message, 'unknown')}`;
      render();
    }
  }

  async function deleteCurrent() {
    if (!can('delete') || !state.draft.id || state.deleting) return;
    if (!state.confirmDelete) {
      state.confirmDelete = true;
      render();
      return;
    }
    state.deleting = true;
    render();
    try {
      await requestJson(`${ENDPOINT}/${encodeURIComponent(state.draft.id)}`, { method: 'DELETE' });
      state.drawerOpen = false;
      await load();
    } catch (error) {
      state.deleting = false;
      state.confirmDelete = false;
      state.notice = `删除失败：${firstText(error.message, 'unknown')}`;
      render();
    }
  }

  async function handleImportFile(event) {
    const file = event.target.files && event.target.files[0];
    event.target.value = '';
    if (!file) return;
    try {
      const text = await file.text();
      const groups = file.name.toLowerCase().endsWith('.csv') ? parseCsvImport(text) : parseJsonImport(text);
      const errors = validateImport(groups);
      state.drawerOpen = true;
      state.drawerMode = 'import';
      state.importPreview = { fileName: file.name, groups, errors };
      state.notice = can('import') ? '' : '已完成本地校验；后端导入接口未接入，确认按钮暂不可用。';
      render();
    } catch (error) {
      state.drawerOpen = true;
      state.drawerMode = 'import';
      state.importPreview = null;
      state.notice = `导入文件解析失败：${firstText(error.message, 'unknown')}`;
      render();
    }
  }

  function parseJsonImport(text) {
    const parsed = JSON.parse(text);
    const groups = Array.isArray(parsed) ? parsed : asArray(parsed.groups || parsed.items || parsed);
    return groups.map((group, index) => {
      const normalized = normalizeGroup(group, index);
      return { id: normalized.id.startsWith('group-') ? '' : normalized.id, name: normalized.name, description: normalized.description, members: normalized.members };
    });
  }

  function csvRows(text) {
    const rows = [];
    let row = [];
    let value = '';
    let quoted = false;
    for (let index = 0; index < text.length; index += 1) {
      const char = text[index];
      if (char === '"') {
        if (quoted && text[index + 1] === '"') { value += '"'; index += 1; }
        else quoted = !quoted;
      } else if (char === ',' && !quoted) { row.push(value); value = ''; }
      else if ((char === '\n' || char === '\r') && !quoted) {
        if (char === '\r' && text[index + 1] === '\n') index += 1;
        row.push(value); value = '';
        if (row.some((item) => item !== '')) rows.push(row);
        row = [];
      } else value += char;
    }
    row.push(value);
    if (row.some((item) => item !== '')) rows.push(row);
    return rows;
  }

  function parseCsvImport(text) {
    const rows = csvRows(text.replace(/^\uFEFF/, ''));
    if (rows.length < 2) return [];
    const headers = rows.shift().map((item) => item.trim().toLowerCase());
    const find = (record, names) => {
      const index = headers.findIndex((header) => names.includes(header));
      return index >= 0 ? firstText(record[index]) : '';
    };
    const groups = new Map();
    rows.forEach((record) => {
      const name = find(record, ['group_name', 'group', 'name', '分组名称', '分组']);
      if (!name) return;
      const id = find(record, ['group_id', 'id']);
      const key = id || name.toLowerCase();
      if (!groups.has(key)) groups.set(key, { id, name, description: find(record, ['description', 'remark', 'note', '说明', '备注']), members: [] });
      const member = normalizeMember({
        mac: find(record, ['mac', 'client_mac', '终端mac']),
        ip: find(record, ['ip', 'ipv4', '终端ip']),
        name: find(record, ['member_name', 'client_name', 'terminal_name', '终端名称'])
      });
      if (memberKey(member) && !groups.get(key).members.some((item) => memberKey(item) === memberKey(member))) groups.get(key).members.push(member);
    });
    return [...groups.values()];
  }

  function validateImport(groups) {
    const errors = [];
    if (!groups.length) errors.push('文件中没有可导入的分组。');
    const names = new Set();
    groups.forEach((group, index) => {
      if (!group.name || !group.name.trim()) errors.push(`第 ${index + 1} 个分组缺少名称。`);
      const key = (group.name || '').trim().toLowerCase();
      if (key && names.has(key)) errors.push(`分组名称重复：${group.name}`);
      names.add(key);
      group.members.forEach((member) => {
        if (!member.mac && !member.ip) errors.push(`${group.name || `第 ${index + 1} 个分组`}存在缺少 MAC/IP 的成员。`);
      });
    });
    return errors.slice(0, 20);
  }

  function csvEscape(value) {
    const text = String(value ?? '');
    return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  }

  function exportGroups(format = 'json') {
    if (!state.groups.length) return;
    const stamp = new Date().toISOString().slice(0, 10);
    let body;
    let type;
    let extension;
    if (format === 'csv') {
      const rows = [['group_id', 'group_name', 'description', 'member_name', 'mac', 'ip']];
      state.groups.forEach((group) => {
        const members = group.members.length ? group.members : [{}];
        members.forEach((member) => rows.push([group.id, group.name, group.description, member.name || '', member.mac || '', member.ip || '']));
      });
      body = rows.map((row) => row.map(csvEscape).join(',')).join('\r\n');
      type = 'text/csv;charset=utf-8';
      extension = 'csv';
    } else {
      body = JSON.stringify({ schema: 'dreamingwrt-terminal-groups-v1', exported_at: new Date().toISOString(), groups: state.groups.map((group) => ({ id: group.id, name: group.name, description: group.description, members: group.members })) }, null, 2);
      type = 'application/json;charset=utf-8';
      extension = 'json';
    }
    const url = URL.createObjectURL(new Blob([body], { type }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `dreamingwrt-terminal-groups-${stamp}.${extension}`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  render();
  load();

  return {
    unmount() {
      state.mounted = false;
      state.seq += 1;
      if (root) root.replaceChildren();
      root?.classList.remove(MODULE_CLASS, 'policy-table-route-host', 'route-workspace');
    }
  };
}

export default { mount };
