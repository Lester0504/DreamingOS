export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));
  const VERSION = '20260710-02';
  const USERS_ENDPOINT = '/api/v1/system/users';
  const GROUPS_ENDPOINT = '/api/v1/system/user-groups';
  const ROLES_ENDPOINT = '/api/v1/system/user-roles';
  const BASIC_ENDPOINT = '/api/v1/system/basic';
  const MODULE_CLASS = 'system-users-route-host';

  const state = {
    mounted: true,
    loading: true,
    error: '',
    source: '',
    users: [],
    groups: [],
    roles: [],
    capabilities: {},
    query: '',
    permission: 'all',
    createMenu: false,
    drawer: '',
    selected: null,
    draft: {},
    importRows: [],
    importName: '',
    importErrors: [],
    saving: false,
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

  function asArray(value, keys = []) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of [...keys, 'items', 'rows', 'data']) {
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
    return unwrap(json);
  }

  function normalizePermissions(value) {
    if (Array.isArray(value)) return value.map((item) => firstText(item)).filter(Boolean);
    if (value && typeof value === 'object') return Object.entries(value).filter(([, enabled]) => Boolean(enabled)).map(([key]) => key);
    return firstText(value).split(/[;,]/).map((item) => item.trim()).filter(Boolean);
  }

  function normalizeUser(value = {}, index = 0) {
    const username = firstText(value.username, value.name, value.display_name, value.id, `user-${index + 1}`);
    const permissions = normalizePermissions(value.permissions || value.permissions_json || value.permission);
    const groupValues = asArray(value.groups || value.user_groups).map((group) => firstText(group)).filter(Boolean);
    return {
      id: firstText(value.id, value.uuid, username),
      username,
      displayName: firstText(value.display_name, value.full_name, value.name, username),
      email: firstText(value.email),
      status: firstText(value.status, value.state, value.enabled === false ? 'disabled' : 'active').toLowerCase(),
      role: firstText(value.role, value.role_name, 'admin'),
      permissions,
      groups: groupValues,
      assignments: asArray(value.assignments || value.sites || value.resources).map((item) => firstText(item)).filter(Boolean),
      credentials: asArray(value.credentials || value.auth_methods).map((item) => firstText(item)).filter(Boolean),
      twofa: Boolean(value.twofa_enabled || value.two_factor || value.otp_enabled),
      createdAt: firstNumber(value.created_at, value.added_at),
      updatedAt: firstNumber(value.updated_at),
      lastActivity: firstNumber(value.last_activity, value.last_login_at, value.last_seen),
      raw: value
    };
  }

  function normalizeGroup(value = {}, index = 0) {
    const users = asArray(value.users || value.members).map((item) => firstText(item.username, item.name, item.id, item)).filter(Boolean);
    return {
      id: firstText(value.id, value.uuid, value.name, `group-${index + 1}`),
      name: firstText(value.name, value.label, `用户组 ${index + 1}`),
      users,
      userCount: Math.max(users.length, firstNumber(value.user_count, value.count)),
      raw: value
    };
  }

  function normalizeCapabilities(data = {}) {
    const caps = data.capabilities && typeof data.capabilities === 'object' ? data.capabilities : {};
    const writable = data.writable === true || caps.write === true || caps.writable === true;
    return {
      create: writable || caps.create === true,
      update: writable || caps.update === true,
      delete: writable || caps.delete === true,
      import: writable || caps.import === true,
      export: caps.export === true,
      groups: caps.groups === true || caps.group_read === true,
      groupCreate: writable || caps.group_create === true,
      groupUpdate: writable || caps.group_update === true
    };
  }

  function fallbackUser(data = {}) {
    const admin = data.admin && typeof data.admin === 'object' ? data.admin : {};
    const twofa = data.twofa && typeof data.twofa === 'object' ? data.twofa : {};
    return normalizeUser({
      username: firstText(admin.username, twofa.username, localStorage.getItem('dreamingwrt.web.username'), 'root'),
      display_name: firstText(admin.display_name, admin.username, twofa.username, 'root'),
      role: firstText(admin.role, localStorage.getItem('dreamingwrt.web.role'), 'admin'),
      status: 'active',
      twofa_enabled: Boolean(twofa.twofa_enabled || admin.two_factor),
      last_login_at: admin.last_login_at,
      created_at: admin.created_at,
      permissions: admin.permissions || []
    });
  }

  async function load() {
    const seq = ++state.seq;
    state.loading = true;
    state.error = '';
    render();
    try {
      const basic = await requestJson(BASIC_ENDPOINT);
      if (!state.mounted || seq !== state.seq) return;
      const basicCapabilities = basic.capabilities && typeof basic.capabilities === 'object' ? basic.capabilities : {};
      const directoryAdvertised = ['system_users', 'system_users_read', 'user_directory', 'user_management', 'web_users_crud']
        .some((key) => basicCapabilities[key] === true);
      if (!directoryAdvertised) {
        state.users = [fallbackUser(basic)];
        state.groups = [];
        state.roles = [];
        state.capabilities = normalizeCapabilities({});
        state.source = 'system/basic · 当前登录用户';
        state.error = '用户目录管理协议尚未接入，当前只显示真实登录用户。';
        return;
      }
      const usersData = await requestJson(USERS_ENDPOINT);
      if (!state.mounted || seq !== state.seq) return;
      state.users = asArray(usersData.users || usersData, ['users']).map(normalizeUser);
      state.capabilities = normalizeCapabilities(usersData);
      state.source = firstText(usersData.source, 'config.db:web_users');
      const [groupsResult, rolesResult] = await Promise.allSettled([requestJson(GROUPS_ENDPOINT), requestJson(ROLES_ENDPOINT)]);
      if (!state.mounted || seq !== state.seq) return;
      if (groupsResult.status === 'fulfilled') {
        state.groups = asArray(groupsResult.value.groups || groupsResult.value, ['groups']).map(normalizeGroup);
        state.capabilities.groups = true;
      }
      if (rolesResult.status === 'fulfilled') state.roles = asArray(rolesResult.value.roles || rolesResult.value, ['roles']);
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.users = [];
      state.error = `读取用户失败：${firstText(error.message, 'unknown')}`;
    } finally {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      if (document.activeElement?.matches('[data-system-user-search]')) patchLoadedUsers();
      else render();
    }
  }

  function icon(name) {
    const paths = {
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      upload: '<path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5"></path><path d="M5 14v5h14v-5"></path>',
      users: '<circle cx="9" cy="8" r="3"></circle><path d="M3.5 19a5.5 5.5 0 0 1 11 0M15 6.5a2.5 2.5 0 0 1 0 5M16 14a4.5 4.5 0 0 1 4.5 4.5"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      chevron: '<path d="m8 10 4 4 4-4"></path>',
      close: '<path d="m6 6 12 12M18 6 6 18"></path>'
    };
    return `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.users}</svg>`;
  }

  function formatTime(value) {
    const raw = Number(value) || 0;
    if (!raw) return '--';
    const timestamp = raw < 100000000000 ? raw * 1000 : raw;
    return new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(timestamp);
  }

  function statusLabel(user) {
    return /disabled|inactive|locked|off/.test(user.status) ? '已停用' : '活跃';
  }

  function statusMarkup(user) {
    const active = statusLabel(user) === '活跃';
    return ui.statusBadgeMarkup?.(active ? '活跃' : '已停用', active ? 'success' : 'error') || escapeHtml(active ? '活跃' : '已停用');
  }

  function permissionLabel(user) {
    return user.permissions.length ? user.permissions.join('、') : user.role === 'owner' ? '全部权限' : '--';
  }

  function permissionOptions() {
    return [...new Set(state.users.flatMap((user) => user.permissions).filter(Boolean))].sort();
  }

  function filteredUsers() {
    const query = state.query.trim().toLowerCase();
    return state.users.filter((user) => {
      if (state.permission !== 'all' && !user.permissions.includes(state.permission)) return false;
      if (!query) return true;
      return [user.displayName, user.username, user.email, user.role, ...user.permissions, ...user.groups].join(' ').toLowerCase().includes(query);
    });
  }

  function userRow(user) {
    return `<tr data-system-user-id="${escapeHtml(user.id)}">
      <td><button class="system-user-name" type="button" data-system-user-detail="${escapeHtml(user.id)}"><span class="system-user-avatar">${escapeHtml((user.displayName || user.username).slice(0, 1).toUpperCase())}</span><span><strong>${escapeHtml(user.displayName)}</strong><small>${escapeHtml(user.username)}</small></span></button></td>
      <td>${statusMarkup(user)}</td>
      <td>${escapeHtml(user.email || '--')}</td>
      <td><time>${escapeHtml(formatTime(user.lastActivity))}</time></td>
      <td>${escapeHtml(user.assignments.length ? user.assignments.join('、') : '--')}</td>
      <td>${escapeHtml(user.role || '--')}</td>
      <td><span class="system-user-permissions">${escapeHtml(permissionLabel(user))}</span></td>
    </tr>`;
  }

  function renderToolbar() {
    const permissions = permissionOptions();
    return `<header class="policy-toolbar system-users-toolbar">
      <label class="policy-search policy-search-main" data-dwrt-component="expand-search">${icon('search')}<input type="search" data-system-user-search placeholder="搜索姓名、邮箱、角色或权限" value="${escapeHtml(state.query)}"></label>
      <div class="policy-toolbar-actions system-users-toolbar-actions">
        <label class="system-users-filter"><span>管理员权限</span><select data-system-user-permission><option value="all">全部权限</option>${permissions.map((item) => `<option value="${escapeHtml(item)}" ${state.permission === item ? 'selected' : ''}>${escapeHtml(item)}</option>`).join('')}</select></label>
        <button class="policy-filter-button" type="button" data-system-user-groups>${icon('users')}<span>管理组</span></button>
        <div class="system-users-create-wrap">
          <button class="policy-create-button" type="button" data-system-user-create-menu aria-expanded="${state.createMenu ? 'true' : 'false'}">${icon('plus')}<span>新建</span>${icon('chevron')}</button>
          <div class="system-users-create-menu" ${state.createMenu ? '' : 'hidden'}>
            <button type="button" data-system-user-create ${state.capabilities.create ? '' : 'disabled'}>${icon('plus')}<span><strong>创建新用户</strong><small>添加本地管理用户</small></span></button>
            <button type="button" data-system-user-import ${state.capabilities.import ? '' : 'disabled'}>${icon('upload')}<span><strong>从 CSV 导入用户</strong><small>先校验，再由后端写入</small></span></button>
          </div>
        </div>
        <input type="file" data-system-user-import-file accept=".csv,text/csv" hidden>
      </div>
    </header>`;
  }

  function renderTable() {
    const users = filteredUsers();
    return `<section class="system-users-table-card dwrt-kit-table-wrap dwrt-kit-datatable-wrap dwrt-kit-glass-surface">
      <div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>用户</strong><span class="${state.error ? 'is-warning' : ''}">${escapeHtml(state.loading ? '正在读取用户目录' : state.error || `数据源：${state.source}`)}</span></div><div class="system-users-table-meta"><span class="dwrt-kit-table-count">${users.length} / ${state.users.length} 位用户</span><button type="button" data-system-user-refresh aria-label="刷新">${icon('refresh')}</button></div></div>
      <div class="dwrt-kit-table-scroll system-users-table-scroll">
        <table class="dwrt-kit-table dwrt-kit-datatable system-users-table"><thead><tr><th>姓名</th><th>状态</th><th>邮箱</th><th>最后活动</th><th>分配</th><th>角色</th><th>权限</th></tr></thead><tbody>${state.loading ? '<tr><td colspan="7" class="dwrt-kit-table-empty">正在读取用户</td></tr>' : users.length ? users.map(userRow).join('') : `<tr><td colspan="7" class="dwrt-kit-table-empty">${escapeHtml(state.query || state.permission !== 'all' ? '没有匹配的用户' : state.error || '暂无用户')}</td></tr>`}</tbody></table>
      </div>
    </section>`;
  }

  function detailDrawer(user) {
    const sections = [
      ['邮箱', user.email || '--'],
      ['角色', user.role || '--'],
      ['权限', permissionLabel(user)],
      ['用户组', user.groups.length ? user.groups.join('、') : '--'],
      ['凭据', [...user.credentials, ...(user.twofa ? ['OTP'] : [])].join('、') || '--'],
      ['分配', user.assignments.length ? user.assignments.join('、') : '--'],
      ['添加时间', formatTime(user.createdAt)],
      ['最后活动', formatTime(user.lastActivity)]
    ];
    return `<button class="policy-drawer-backdrop dwrt-kit-sheet-overlay is-open" type="button" data-system-user-close aria-label="关闭用户详情"></button><aside class="system-users-drawer dwrt-kit-sheet policy-stable-glass is-open" aria-label="用户详情"><header class="dwrt-kit-sheet-header"><div><span>USER</span><strong>${escapeHtml(user.displayName)}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-system-user-close>×</button></header><div class="dwrt-kit-sheet-body system-users-drawer-body"><section class="system-user-profile"><span class="system-user-avatar is-large">${escapeHtml((user.displayName || user.username).slice(0, 1).toUpperCase())}</span><div><strong>${escapeHtml(user.displayName)}</strong><span>${escapeHtml(user.username)} · ${escapeHtml(statusLabel(user))}</span></div></section><div class="system-user-detail-list">${sections.map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join('')}</div>${state.error ? `<div class="system-users-notice">${escapeHtml(state.error)}</div>` : ''}</div></aside>`;
  }

  function createDrawer() {
    const roles = state.roles.length ? state.roles.map((role) => firstText(role.id, role.name, role)) : ['admin', 'operator', 'viewer'];
    return `<button class="policy-drawer-backdrop dwrt-kit-sheet-overlay is-open" type="button" data-system-user-close aria-label="关闭创建用户"></button><aside class="system-users-drawer dwrt-kit-sheet policy-stable-glass is-open" aria-label="创建用户"><header class="dwrt-kit-sheet-header"><div><span>CREATE USER</span><strong>创建新用户</strong></div><button class="dwrt-kit-sheet-close" type="button" data-system-user-close>×</button></header><div class="dwrt-kit-sheet-body system-users-drawer-body"><div class="system-users-form"><label><span>用户名</span><input data-user-draft="username" value="${escapeHtml(state.draft.username || '')}" autocomplete="off"></label><label><span>显示名称</span><input data-user-draft="display_name" value="${escapeHtml(state.draft.display_name || '')}"></label><label><span>邮箱</span><input data-user-draft="email" type="email" value="${escapeHtml(state.draft.email || '')}"></label><label><span>角色</span><select data-user-draft="role">${roles.map((role) => `<option value="${escapeHtml(role)}" ${(state.draft.role || 'admin') === role ? 'selected' : ''}>${escapeHtml(role)}</option>`).join('')}</select></label><label class="is-wide"><span>初始密码</span><input data-user-draft="password" type="password" value="${escapeHtml(state.draft.password || '')}" autocomplete="new-password"></label></div>${state.notice ? `<div class="system-users-notice">${escapeHtml(state.notice)}</div>` : ''}</div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-system-user-close>取消</button><button class="policy-primary" type="button" data-system-user-save ${state.capabilities.create && state.draft.username && state.draft.password && !state.saving ? '' : 'disabled'}>${state.saving ? '正在保存' : '创建用户'}</button></footer></aside>`;
  }

  function groupsDrawer() {
    return `<button class="policy-drawer-backdrop dwrt-kit-sheet-overlay is-open" type="button" data-system-user-close aria-label="关闭用户组"></button><aside class="system-users-drawer dwrt-kit-sheet policy-stable-glass is-open" aria-label="管理用户组"><header class="dwrt-kit-sheet-header"><div><span>USER GROUPS</span><strong>管理组</strong></div><button class="dwrt-kit-sheet-close" type="button" data-system-user-close>×</button></header><div class="dwrt-kit-sheet-body system-users-drawer-body"><div class="system-user-group-list">${state.groups.length ? state.groups.map((group) => `<div><span class="system-user-avatar">${escapeHtml(group.name.slice(0, 1).toUpperCase())}</span><span><strong>${escapeHtml(group.name)}</strong><small>${group.userCount} 位用户</small></span></div>`).join('') : `<div class="system-users-empty">${escapeHtml(state.capabilities.groups ? '暂无用户组' : '后端用户组协议尚未接入')}</div>`}</div></div><footer class="dwrt-kit-sheet-footer"><button class="policy-primary" type="button" disabled>创建组</button></footer></aside>`;
  }

  function importDrawer() {
    return `<button class="policy-drawer-backdrop dwrt-kit-sheet-overlay is-open" type="button" data-system-user-close aria-label="关闭导入"></button><aside class="system-users-drawer dwrt-kit-sheet policy-stable-glass is-open" aria-label="导入用户"><header class="dwrt-kit-sheet-header"><div><span>CSV IMPORT</span><strong>导入用户</strong></div><button class="dwrt-kit-sheet-close" type="button" data-system-user-close>×</button></header><div class="dwrt-kit-sheet-body system-users-drawer-body"><div class="system-users-import-summary"><strong>${escapeHtml(state.importName || '未选择文件')}</strong><span>${state.importRows.length} 位用户 · ${state.importErrors.length ? `${state.importErrors.length} 个错误` : '校验通过'}</span></div>${state.importErrors.length ? `<div class="system-users-notice">${state.importErrors.map(escapeHtml).join('<br>')}</div>` : ''}<div class="system-users-import-list">${state.importRows.slice(0, 40).map((row) => `<div><strong>${escapeHtml(row.username)}</strong><span>${escapeHtml([row.email, row.role].filter(Boolean).join(' · '))}</span></div>`).join('')}</div></div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-system-user-close>取消</button><button class="policy-primary" type="button" data-system-user-import-save ${state.capabilities.import && state.importRows.length && !state.importErrors.length && !state.saving ? '' : 'disabled'}>${state.saving ? '正在导入' : '确认导入'}</button></footer></aside>`;
  }

  function renderDrawer() {
    if (state.drawer === 'detail' && state.selected) return detailDrawer(state.selected);
    if (state.drawer === 'create') return createDrawer();
    if (state.drawer === 'groups') return groupsDrawer();
    if (state.drawer === 'import') return importDrawer();
    return '';
  }

  function render() {
    if (!root || !state.mounted) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'policy-table-route-host', MODULE_CLASS);
    root.innerHTML = `<section class="policy-table-shell system-users-shell">${renderToolbar()}${renderTable()}${renderDrawer()}</section>`;
    bindEvents();
    ui.mountAll?.(root);
    ui.scheduleGlassCardsRender?.(120);
  }

  function patchTable() {
    const tbody = root.querySelector('.system-users-table tbody');
    const count = root.querySelector('.system-users-table-meta .dwrt-kit-table-count');
    const users = filteredUsers();
    if (tbody) tbody.innerHTML = users.length ? users.map(userRow).join('') : '<tr><td colspan="7" class="dwrt-kit-table-empty">没有匹配的用户</td></tr>';
    if (count) count.textContent = `${users.length} / ${state.users.length} 位用户`;
    bindDetailActions();
  }

  function patchLoadedUsers() {
    const card = root.querySelector('.system-users-table-card');
    if (!card) return render();
    const scroll = card.querySelector('.system-users-table-scroll');
    const scrollTop = scroll?.scrollTop || 0;
    const scrollLeft = scroll?.scrollLeft || 0;
    card.outerHTML = renderTable();
    const nextScroll = root.querySelector('.system-users-table-scroll');
    if (nextScroll) {
      nextScroll.scrollTop = scrollTop;
      nextScroll.scrollLeft = scrollLeft;
    }
    const permission = root.querySelector('[data-system-user-permission]');
    if (permission) {
      permission.innerHTML = `<option value="all">全部权限</option>${permissionOptions().map((item) => `<option value="${escapeHtml(item)}" ${state.permission === item ? 'selected' : ''}>${escapeHtml(item)}</option>`).join('')}`;
    }
    root.querySelector('[data-system-user-create]')?.toggleAttribute('disabled', !state.capabilities.create);
    root.querySelector('[data-system-user-import]')?.toggleAttribute('disabled', !state.capabilities.import);
    bindDetailActions();
  }

  function closeDrawer() {
    state.drawer = '';
    state.selected = null;
    state.notice = '';
    render();
  }

  function bindDetailActions() {
    root.querySelectorAll('[data-system-user-detail]').forEach((button) => button.addEventListener('click', () => {
      state.selected = state.users.find((user) => user.id === button.dataset.systemUserDetail) || null;
      if (state.selected) state.drawer = 'detail';
      render();
    }));
  }

  function bindEvents() {
    root.querySelector('[data-system-user-search]')?.addEventListener('input', (event) => { state.query = event.target.value || ''; patchTable(); });
    root.querySelector('[data-system-user-permission]')?.addEventListener('change', (event) => { state.permission = event.target.value || 'all'; patchTable(); });
    root.querySelector('[data-system-user-refresh]')?.addEventListener('click', load);
    root.querySelector('[data-system-user-create-menu]')?.addEventListener('click', () => { state.createMenu = !state.createMenu; const menu = root.querySelector('.system-users-create-menu'); if (menu) menu.hidden = !state.createMenu; });
    root.querySelector('[data-system-user-create]')?.addEventListener('click', () => { state.createMenu = false; state.drawer = 'create'; state.draft = { role: 'admin' }; state.notice = ''; render(); });
    root.querySelector('[data-system-user-groups]')?.addEventListener('click', () => { state.drawer = 'groups'; render(); });
    root.querySelector('[data-system-user-import]')?.addEventListener('click', () => root.querySelector('[data-system-user-import-file]')?.click());
    root.querySelector('[data-system-user-import-file]')?.addEventListener('change', handleImportFile);
    root.querySelectorAll('[data-system-user-close]').forEach((button) => button.addEventListener('click', closeDrawer));
    root.querySelectorAll('[data-user-draft]').forEach((input) => input.addEventListener('input', (event) => { state.draft[event.target.dataset.userDraft] = event.target.value || ''; const save = root.querySelector('[data-system-user-save]'); if (save) save.disabled = !(state.capabilities.create && state.draft.username && state.draft.password) || state.saving; }));
    root.querySelector('[data-user-draft="role"]')?.addEventListener('change', (event) => { state.draft.role = event.target.value || 'admin'; });
    root.querySelector('[data-system-user-save]')?.addEventListener('click', saveUser);
    root.querySelector('[data-system-user-import-save]')?.addEventListener('click', importUsers);
    bindDetailActions();
  }

  function parseCsv(text) {
    const rows = [];
    let row = [];
    let value = '';
    let quoted = false;
    const source = String(text || '').replace(/^\uFEFF/, '');
    for (let index = 0; index < source.length; index += 1) {
      const char = source[index];
      if (char === '"') {
        if (quoted && source[index + 1] === '"') { value += '"'; index += 1; } else quoted = !quoted;
      } else if (char === ',' && !quoted) { row.push(value); value = ''; }
      else if ((char === '\n' || char === '\r') && !quoted) { if (char === '\r' && source[index + 1] === '\n') index += 1; row.push(value); value = ''; if (row.some(Boolean)) rows.push(row); row = []; }
      else value += char;
    }
    row.push(value);
    if (row.some(Boolean)) rows.push(row);
    if (!rows.length) return [];
    const headers = rows.shift().map((item) => item.trim().toLowerCase());
    const at = (record, names) => { const index = headers.findIndex((header) => names.includes(header)); return index >= 0 ? firstText(record[index]) : ''; };
    return rows.map((record) => ({ username: at(record, ['username', 'user', '用户名']), display_name: at(record, ['display_name', 'name', '显示名称', '姓名']), email: at(record, ['email', '邮箱']), role: at(record, ['role', '角色']) || 'viewer', password: at(record, ['password', '初始密码']) }));
  }

  async function handleImportFile(event) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    const rows = parseCsv(await file.text());
    const seen = new Set();
    const errors = [];
    rows.forEach((row, index) => {
      if (!row.username) errors.push(`第 ${index + 2} 行缺少用户名`);
      if (row.username && seen.has(row.username.toLowerCase())) errors.push(`用户名重复：${row.username}`);
      if (row.username) seen.add(row.username.toLowerCase());
    });
    if (!rows.length) errors.push('CSV 中没有可导入的用户');
    state.importRows = rows;
    state.importName = file.name;
    state.importErrors = errors.slice(0, 20);
    state.drawer = 'import';
    render();
  }

  async function saveUser() {
    if (!state.capabilities.create || state.saving) return;
    state.saving = true;
    state.notice = '';
    render();
    try {
      await requestJson(USERS_ENDPOINT, { method: 'POST', body: JSON.stringify(state.draft) });
      state.drawer = '';
      state.saving = false;
      await load();
      window.DreamingWrtNotify?.success('用户已创建');
    } catch (error) {
      state.saving = false;
      state.notice = `创建失败：${firstText(error.message, 'unknown')}`;
      render();
    }
  }

  async function importUsers() {
    if (!state.capabilities.import || state.saving || state.importErrors.length) return;
    state.saving = true;
    render();
    try {
      const dryRun = await requestJson(`${USERS_ENDPOINT}/import`, { method: 'POST', body: JSON.stringify({ users: state.importRows, confirm: false }) });
      const dryErrors = asArray(dryRun.errors || [], ['errors']);
      if (dryRun.valid === false || dryErrors.length) {
        state.saving = false;
        state.importErrors = dryErrors.map((item) => `第 ${firstNumber(item.row) || '?'} 行：${firstText(item.message, item.code, '校验失败')}`);
        render();
        return;
      }
      await requestJson(`${USERS_ENDPOINT}/import`, { method: 'POST', body: JSON.stringify({ users: state.importRows, confirm: true }) });
      state.drawer = '';
      state.saving = false;
      await load();
      window.DreamingWrtNotify?.success('用户已导入');
    } catch (error) {
      state.saving = false;
      state.importErrors = [`导入失败：${firstText(error.message, 'unknown')}`];
      render();
    }
  }

  render();
  load();
  return { unmount() { state.mounted = false; state.seq += 1; root?.replaceChildren(); root?.classList.remove(MODULE_CLASS, 'policy-table-route-host', 'route-workspace'); } };
}

export default { mount };
