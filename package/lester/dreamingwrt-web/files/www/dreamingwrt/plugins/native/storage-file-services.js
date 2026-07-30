export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const VERSION = '20260722-overlay-01';
  const MODULE_CLASS = 'storage-file-services-route-host';
  const stage = root?.closest('.console-stage');
  const TABS = [['nfs', 'NFS'], ['samba', 'Samba'], ['webdav', 'WebDAV'], ['ftp', 'FTP']];
  const ENDPOINTS = {
    aggregate: '/api/v1/storage/file-services',
    nfs: '/api/v1/services/nfs',
    samba: '/api/v1/services/samba',
    webdav: '/api/v1/services/webdav',
    ftp: '/api/v1/services/ftp'
  };

  function emptyServiceData() {
    return {
      capabilities: {},
      nfs: { available: false, running: null, exports: [], mounts: [], capabilities: {} },
      samba: {
        available: false, running: null, enabled: false, workgroup: 'WORKGROUP', server_description: 'Dreaming OS',
        interfaces: ['lan'], min_protocol: 'SMB2', max_protocol: 'SMB3', guest_access: false, shares: [], capabilities: {}
      },
      webdav: {
        available: false, running: null, enabled: false, listen_port: 5005, username: '', has_password: false,
        root_dir: '/mnt', read_only: false, open_firewall: false, ssl: false, cert_file: '', key_file: '', capabilities: {}
      },
      ftp: {
        available: false, running: null, enabled: false, listen_port: 21, root_dir: '/mnt', anonymous: false,
        local_users: true, write_enable: false, open_firewall: false, tls: false, cert_file: '', key_file: '',
        passive_mode: true, passive_port_min: 50000, passive_port_max: 50100, max_clients: 10,
        idle_timeout: 300, users: [], capabilities: {}
      }
    };
  }

  const state = {
    mounted: true,
    seq: 0,
    loading: true,
    refreshing: false,
    saving: false,
    loaded: false,
    error: '',
    notice: '',
    noticeTone: '',
    tab: 'nfs',
    nfsView: 'exports',
    sambaView: 'shares',
    ftpView: 'settings',
    query: '',
    data: emptyServiceData(),
    drawer: '',
    editor: {},
    confirmDelete: false
  };

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (typeof value === 'object' && !Array.isArray(value)) {
        const nested = firstText(value.message, value.name, value.label, value.value, value.id);
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
      if (value === '' || value === null || value === undefined) continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return 0;
  }

  function bool(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') return !['0', 'false', 'off', 'no', 'disabled'].includes(value.toLowerCase());
    return Boolean(value);
  }

  function asArray(value, keys = []) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of [...keys, 'items', 'rows', 'list', 'data']) if (Array.isArray(value[key])) return value[key];
    return [];
  }

  function clone(value) {
    try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value || {})); }
  }

  function authHeaders(extra = {}) {
    let token = '';
    try { token = localStorage.getItem('dreamingwrt.web.accessToken') || ''; } catch (_) {}
    return {
      Accept: 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}),
      ...extra
    };
  }

  async function requestJson(url, options = {}) {
    if ((!options.method || options.method === 'GET') && typeof api.fetch === 'function') {
      const result = await api.fetch(`fileService:${url}`, url);
      if (!result?.ok) throw result?.error || new Error('文件服务 API 不可用');
      return result.data || {};
    }
    const response = await fetch(`${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`, {
      credentials: 'same-origin', cache: 'no-store', ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    const payload = json?.data ?? json?.body ?? json;
    if (!response.ok || json?.ok === false || payload?.ok === false) {
      const error = new Error(firstText(payload?.message, payload?.error, json?.message, json?.error, `HTTP ${response.status}`));
      error.status = response.status;
      throw error;
    }
    return payload || {};
  }

  function normalizeNfs(payload = {}) {
    return {
      ...payload,
      available: bool(payload.available, true),
      running: payload.running === undefined ? null : bool(payload.running),
      exports: asArray(payload.exports, ['shares']).map((item, index) => ({
        ...item,
        id: firstText(item.id, item.uuid, `export-${index + 1}`),
        enabled: bool(item.enabled, true),
        path: firstText(item.path, item.directory),
        clients: firstText(item.clients, item.allowed_clients, '*'),
        options: firstText(item.options)
      })),
      mounts: asArray(payload.mounts, ['remote_mounts']).map((item, index) => ({
        ...item,
        id: firstText(item.id, item.uuid, `mount-${index + 1}`),
        enabled: bool(item.enabled, true),
        source: firstText(item.source, item.source_dir, item.remote),
        target: firstText(item.target, item.mount_point, item.mount_to),
        options: firstText(item.options),
        delay: firstNumber(item.delay, item.delay_seconds)
      })),
      capabilities: payload.capabilities || {}
    };
  }

  function normalizeWebdav(payload = {}) {
    return {
      ...payload,
      available: bool(payload.available, true),
      running: payload.running === undefined ? null : bool(payload.running),
      enabled: bool(payload.enabled),
      listen_port: firstNumber(payload.listen_port, payload.port, 5005),
      username: firstText(payload.username),
      has_password: bool(payload.has_password, Boolean(payload.password_set)),
      root_dir: firstText(payload.root_dir, payload.directory, '/mnt'),
      read_only: bool(payload.read_only, payload.readonly),
      open_firewall: bool(payload.open_firewall, payload.firewall),
      ssl: bool(payload.ssl, payload.enable_ssl),
      cert_file: firstText(payload.cert_file, payload.cert_cer, payload.certificate),
      key_file: firstText(payload.key_file, payload.cert_key, payload.private_key),
      registry_download_available: bool(payload.registry_download_available),
      capabilities: payload.capabilities || {}
    };
  }

  function normalizeSamba(payload = {}) {
    return {
      ...payload,
      available: bool(payload.available, true),
      running: payload.running === undefined ? null : bool(payload.running),
      enabled: bool(payload.enabled),
      workgroup: firstText(payload.workgroup, 'WORKGROUP'),
      server_description: firstText(payload.server_description, payload.description, payload.server_string, 'Dreaming OS'),
      interfaces: asArray(payload.interfaces).map(String),
      min_protocol: firstText(payload.min_protocol, payload.server_min_protocol, 'SMB2'),
      max_protocol: firstText(payload.max_protocol, payload.server_max_protocol, 'SMB3'),
      guest_access: bool(payload.guest_access, payload.map_to_guest),
      shares: asArray(payload.shares, ['exports']).map((item, index) => ({
        ...item,
        id: firstText(item.id, item.uuid, item.name, `samba-share-${index + 1}`),
        name: firstText(item.name, item.share_name),
        path: firstText(item.path, item.directory),
        enabled: bool(item.enabled, true),
        read_only: bool(item.read_only, item.readonly),
        browseable: bool(item.browseable, item.browsable, true),
        guest_access: bool(item.guest_access, item.guest_ok),
        allowed_users: asArray(item.allowed_users, ['users']).map(String),
        note: firstText(item.note, item.description)
      })),
      capabilities: payload.capabilities || {}
    };
  }

  function normalizeFtp(payload = {}) {
    return {
      ...payload,
      available: bool(payload.available, true),
      running: payload.running === undefined ? null : bool(payload.running),
      enabled: bool(payload.enabled),
      listen_port: firstNumber(payload.listen_port, payload.port, 21),
      root_dir: firstText(payload.root_dir, payload.directory, '/mnt'),
      anonymous: bool(payload.anonymous, payload.anonymous_enable),
      local_users: bool(payload.local_users, payload.local_enable === undefined ? true : payload.local_enable),
      write_enable: bool(payload.write_enable, payload.writable),
      open_firewall: bool(payload.open_firewall, payload.firewall),
      tls: bool(payload.tls, payload.ssl_enable),
      cert_file: firstText(payload.cert_file, payload.certificate),
      key_file: firstText(payload.key_file, payload.private_key),
      passive_mode: bool(payload.passive_mode, true),
      passive_port_min: firstNumber(payload.passive_port_min, payload.pasv_min_port, 50000),
      passive_port_max: firstNumber(payload.passive_port_max, payload.pasv_max_port, 50100),
      max_clients: firstNumber(payload.max_clients, 10),
      idle_timeout: firstNumber(payload.idle_timeout, payload.idle_session_timeout, 300),
      users: asArray(payload.users, ['accounts']).map((item, index) => ({
        ...item,
        id: firstText(item.id, item.username, `ftp-user-${index + 1}`),
        username: firstText(item.username, item.name),
        root_dir: firstText(item.root_dir, item.home, '/mnt'),
        enabled: bool(item.enabled, true),
        read_only: bool(item.read_only, item.readonly),
        has_password: bool(item.has_password, Boolean(item.password_set))
      })),
      capabilities: payload.capabilities || {}
    };
  }

  function normalizeAggregate(payload = {}) {
    const source = payload.file_services && typeof payload.file_services === 'object' ? payload.file_services : payload;
    const fallback = emptyServiceData();
    return {
      capabilities: source.capabilities || {},
      nfs: source.nfs && typeof source.nfs === 'object' ? normalizeNfs(source.nfs) : fallback.nfs,
      samba: source.samba && typeof source.samba === 'object' ? normalizeSamba(source.samba) : fallback.samba,
      webdav: source.webdav && typeof source.webdav === 'object' ? normalizeWebdav(source.webdav) : fallback.webdav,
      ftp: source.ftp && typeof source.ftp === 'object' ? normalizeFtp(source.ftp) : fallback.ftp
    };
  }

  async function load(background = false) {
    const seq = ++state.seq;
    state.error = '';
    if (background) state.refreshing = true; else state.loading = true;
    render();
    try {
      let payload;
      try {
        payload = normalizeAggregate(await requestJson(ENDPOINTS.aggregate));
      } catch (aggregateError) {
        const settled = await Promise.allSettled([
          requestJson(ENDPOINTS.nfs), requestJson(ENDPOINTS.samba), requestJson(ENDPOINTS.webdav), requestJson(ENDPOINTS.ftp)
        ]);
        if (!settled.some((result) => result.status === 'fulfilled')) throw aggregateError;
        payload = emptyServiceData();
        if (settled[0].status === 'fulfilled') payload.nfs = normalizeNfs(settled[0].value);
        if (settled[1].status === 'fulfilled') payload.samba = normalizeSamba(settled[1].value);
        if (settled[2].status === 'fulfilled') payload.webdav = normalizeWebdav(settled[2].value);
        if (settled[3].status === 'fulfilled') payload.ftp = normalizeFtp(settled[3].value);
      }
      if (!state.mounted || seq !== state.seq) return;
      state.data = payload;
      state.loaded = true;
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.error = '文件服务后端接口尚未开放，当前显示可配置项与交互结构，不会使用浏览器本地数据伪造配置。';
    } finally {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      render();
    }
  }

  function capability(service, action) {
    const local = state.data[service]?.capabilities || {};
    const global = state.data.capabilities || {};
    return local[action] === true || local[`write_${action}`] === true || local.write === true
      || global[`${service}_${action}`] === true || global[service]?.[action] === true || global[service]?.write === true;
  }

  function icon(name) {
    const paths = {
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      edit: '<path d="m4 20 4.2-1 10.9-10.9a2 2 0 0 0-2.8-2.8L5.4 16.2 4 20Z"></path>',
      server: '<rect x="3" y="4" width="18" height="7" rx="2"></rect><rect x="3" y="13" width="18" height="7" rx="2"></rect><path d="M7 7.5h.01M7 16.5h.01M11 7.5h6M11 16.5h6"></path>',
      folder: '<path d="M3 6h7l2 2h9v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"></path>',
      shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"></path><path d="m9 12 2 2 4-5"></path>',
      lock: '<rect x="5" y="10" width="14" height="11" rx="2"></rect><path d="M8 10V7a4 4 0 0 1 8 0v3"></path>',
      download: '<path d="M12 3v12m-5-5 5 5 5-5"></path><path d="M5 21h14"></path>',
      trash: '<path d="M4 7h16M9 7V4h6v3m-9 0 1 13h10l1-13M10 11v5m4-5v5"></path>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.server}</svg>`;
  }

  function serviceStatus(service) {
    if (state.loading && !state.loaded) return ui.statusBadgeMarkup?.('正在读取', 'info') || '';
    if (!service.available) return ui.statusBadgeMarkup?.('组件未安装', 'warning') || '';
    if (service.running === true) return ui.statusBadgeMarkup?.('运行中', 'success') || '';
    if (service.running === false) return ui.statusBadgeMarkup?.('未运行', 'error') || '';
    return ui.statusBadgeMarkup?.('状态未知', 'muted') || '';
  }

  function tabsMarkup() {
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs file-service-tabs" data-file-tabs data-dwrt-tabs-key="storage-file-services" aria-label="文件服务"><span class="dwrt-kit-tab-pill" aria-hidden="true"></span>${TABS.map(([id, label]) => `<button class="dwrt-kit-tab ${state.tab === id ? 'is-active' : ''}" type="button" data-value="${id}" aria-selected="${state.tab === id ? 'true' : 'false'}">${label}</button>`).join('')}</nav>`;
  }

  function segmentedMarkup() {
    if (state.tab === 'nfs') {
      return `<div class="file-service-segmented" role="group" aria-label="NFS 数据类型"><button type="button" class="${state.nfsView === 'exports' ? 'is-active' : ''}" data-file-view="exports">共享目录</button><button type="button" class="${state.nfsView === 'mounts' ? 'is-active' : ''}" data-file-view="mounts">远程挂载</button></div>`;
    }
    if (state.tab === 'samba') {
      return `<div class="file-service-segmented" role="group" aria-label="Samba 数据类型"><button type="button" class="${state.sambaView === 'shares' ? 'is-active' : ''}" data-file-view="shares">共享目录</button><button type="button" class="${state.sambaView === 'settings' ? 'is-active' : ''}" data-file-view="settings">服务设置</button></div>`;
    }
    if (state.tab === 'ftp') {
      return `<div class="file-service-segmented" role="group" aria-label="FTP 数据类型"><button type="button" class="${state.ftpView === 'settings' ? 'is-active' : ''}" data-file-view="settings">服务设置</button><button type="button" class="${state.ftpView === 'users' ? 'is-active' : ''}" data-file-view="users">用户</button></div>`;
    }
    return '<span></span>';
  }

  function toolbarMarkup() {
    const searchable = state.tab === 'nfs' || (state.tab === 'samba' && state.sambaView === 'shares') || (state.tab === 'ftp' && state.ftpView === 'users');
    const createLabel = state.tab === 'nfs' ? (state.nfsView === 'exports' ? '添加共享' : '添加挂载') : state.tab === 'samba' && state.sambaView === 'shares' ? '添加共享' : state.tab === 'ftp' && state.ftpView === 'users' ? '新建用户' : '';
    const settingsLabel = state.tab === 'webdav' || (state.tab === 'samba' && state.sambaView === 'settings') || (state.tab === 'ftp' && state.ftpView === 'settings') ? '编辑设置' : '';
    const placeholder = state.tab === 'nfs' ? '搜索路径、客户端或选项' : state.tab === 'samba' ? '搜索共享名称、路径、用户或备注' : '搜索用户名或目录';
    return `<header class="policy-toolbar file-service-toolbar"><div class="file-service-toolbar-leading">${segmentedMarkup()}${searchable ? `<label class="policy-search policy-search-main" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-file-search value="${escapeHtml(state.query)}" placeholder="${placeholder}"></label>` : ''}</div><div class="policy-toolbar-actions"><button class="policy-filter-button" type="button" data-file-refresh ${state.refreshing ? 'disabled' : ''}>${icon('refresh')}<span>${state.refreshing ? '正在刷新' : '刷新'}</span></button>${settingsLabel ? `<button class="policy-create-button" type="button" data-file-settings="${state.tab}">${icon('edit')}<span>${settingsLabel}</span></button>` : ''}${createLabel ? `<button class="policy-create-button" type="button" data-file-create>${icon('plus')}<span>${createLabel}</span></button>` : ''}</div></header>`;
  }

  function noticeMarkup() {
    const message = state.notice || state.error;
    if (!message) return '';
    const tone = state.notice ? state.noticeTone : 'warning';
    return `<div class="file-service-notice is-${escapeHtml(tone || 'info')}">${escapeHtml(message)}</div>`;
  }

  function matchesQuery(values) {
    const query = state.query.trim().toLowerCase();
    return !query || values.some((value) => String(value || '').toLowerCase().includes(query));
  }

  function rowAction(kind, item) {
    return `<button class="file-service-icon-button" type="button" data-file-edit="${escapeHtml(kind)}" data-file-id="${escapeHtml(item.id)}" aria-label="编辑" data-dwrt-tooltip="编辑">${icon('edit')}</button>`;
  }

  function entryStatus(enabled) {
    return ui.statusBadgeMarkup?.(enabled ? '启用' : '停用', enabled ? 'success' : 'error') || `<span>${enabled ? '启用' : '停用'}</span>`;
  }

  function tableMarkup(title, subtitle, headings, rows, empty) {
    return `<section class="file-service-main-surface file-service-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(subtitle)}</span></div><span class="dwrt-kit-table-count">${rows.length} 条</span></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table file-service-table"><thead><tr>${headings.map((heading) => `<th>${escapeHtml(heading)}</th>`).join('')}</tr></thead><tbody>${state.loading && !state.loaded ? `<tr><td colspan="${headings.length}" class="dwrt-kit-table-empty">正在读取文件服务配置</td></tr>` : rows.length ? rows.join('') : `<tr><td colspan="${headings.length}" class="dwrt-kit-table-empty">${escapeHtml(empty)}</td></tr>`}</tbody></table></div></section>`;
  }

  function renderNfs() {
    const service = state.data.nfs;
    if (state.nfsView === 'mounts') {
      const items = service.mounts.filter((item) => matchesQuery([item.source, item.target, item.options, item.delay]));
      const rows = items.map((item) => `<tr><td>${entryStatus(item.enabled)}</td><td><code>${escapeHtml(item.source || '--')}</code></td><td><code>${escapeHtml(item.target || '--')}</code></td><td><span class="file-service-ellipsis" data-dwrt-tooltip="${escapeHtml(item.options || '--')}">${escapeHtml(item.options || '--')}</span></td><td>${item.delay ? `${item.delay} 秒` : '立即'}</td><td>${rowAction('nfs-mount', item)}</td></tr>`);
      return tableMarkup('已挂载的目录', `远程 NFS 目录挂载到本机 · ${serviceStatusText(service)}`, ['状态', '源目录', '挂载到', '选项', '延迟时间', '操作'], rows, '尚无远程 NFS 挂载配置');
    }
    const items = service.exports.filter((item) => matchesQuery([item.path, item.clients, item.options]));
    const rows = items.map((item) => `<tr><td>${entryStatus(item.enabled)}</td><td><code>${escapeHtml(item.path || '--')}</code></td><td>${escapeHtml(item.clients || '*')}</td><td><span class="file-service-ellipsis" data-dwrt-tooltip="${escapeHtml(item.options || '--')}">${escapeHtml(item.options || '--')}</span></td><td>${rowAction('nfs-export', item)}</td></tr>`);
    return tableMarkup('共享目录', `NFS 导出目录与客户端访问范围 · ${serviceStatusText(service)}`, ['状态', '路径', '允许的客户端', '导出选项', '操作'], rows, '尚无 NFS 共享目录');
  }

  function serviceStatusText(service) {
    if (!service.available) return '组件未安装';
    if (service.running === true) return '运行中';
    if (service.running === false) return '未运行';
    return '状态未知';
  }

  function detailRow(label, value, options = {}) {
    return `<div class="file-service-detail-row"><dt>${escapeHtml(label)}</dt><dd class="${options.code ? 'is-code' : ''}">${options.status ? value : escapeHtml(value || '--')}</dd></div>`;
  }

  function settingsSurface(serviceName, description, status, rows, footer = '') {
    return `<section class="file-service-main-surface file-service-settings-surface dwrt-kit-glass-surface"><header class="file-service-surface-header"><div class="file-service-surface-icon">${icon(serviceName === 'FTP' ? 'folder' : serviceName === 'WebDAV' ? 'lock' : 'server')}</div><div><strong>${escapeHtml(serviceName)}</strong><span>${escapeHtml(description)}</span></div>${status}</header><dl class="file-service-detail-list">${rows.join('')}</dl>${footer}</section>`;
  }

  function renderSamba() {
    const service = state.data.samba;
    if (state.sambaView === 'settings') {
      return settingsSurface('Samba', '为 Windows、macOS 与 Linux 客户端提供 SMB 文件共享。', serviceStatus(service), [
        detailRow('服务开关', service.enabled ? '启用' : '停用'),
        detailRow('工作组', service.workgroup),
        detailRow('服务器描述', service.server_description),
        detailRow('监听接口', service.interfaces.join('、') || '自动'),
        detailRow('最低协议', service.min_protocol),
        detailRow('最高协议', service.max_protocol),
        detailRow('访客访问', service.guest_access ? '允许' : '禁止'),
        detailRow('共享数量', `${service.shares.length} 个`)
      ]);
    }
    const items = service.shares.filter((item) => matchesQuery([item.name, item.path, item.allowed_users.join(' '), item.note]));
    const rows = items.map((item) => `<tr><td>${entryStatus(item.enabled)}</td><td><strong>${escapeHtml(item.name || '--')}</strong></td><td><code>${escapeHtml(item.path || '--')}</code></td><td>${item.read_only ? '只读' : '读写'}</td><td>${item.browseable ? '可发现' : '隐藏'}</td><td>${item.guest_access ? '允许' : '禁止'}</td><td>${escapeHtml(item.allowed_users.join('、') || '所有已授权用户')}</td><td>${escapeHtml(item.note || '--')}</td><td>${rowAction('samba-share', item)}</td></tr>`);
    return tableMarkup('Samba 共享', `SMB 共享目录与访问权限 · ${serviceStatusText(service)}`, ['状态', '共享名称', '路径', '权限', '网络发现', '访客', '允许用户', '备注', '操作'], rows, '尚无 Samba 共享目录');
  }

  function renderWebdav() {
    const service = state.data.webdav;
    const auth = service.username || service.has_password ? (service.username || '已配置身份验证') : '未启用';
    const protocol = service.ssl ? 'HTTPS' : 'HTTP';
    return settingsSurface('WebDAV', '基于 NGINX 实现的轻量 WebDAV 文件访问服务。', serviceStatus(service), [
      detailRow('服务开关', service.enabled ? '启用' : '停用'),
      detailRow('访问地址', `${protocol} · ${service.listen_port || 5005}`),
      detailRow('身份验证', auth),
      detailRow('WebDAV 目录', service.root_dir, { code: true }),
      detailRow('访问模式', service.read_only ? '只读' : '读写'),
      detailRow('防火墙端口', service.open_firewall ? '自动放行' : '不自动放行'),
      detailRow('TLS', service.ssl ? '已启用' : '未启用'),
      ...(service.ssl ? [detailRow('SSL 证书', service.cert_file, { code: true }), detailRow('SSL 密钥', service.key_file, { code: true })] : [])
    ], `<footer class="file-service-surface-footer"><span>Windows 使用 HTTP 鉴权时需要导入注册表配置并重启。</span><button class="policy-secondary" type="button" data-webdav-registry ${service.registry_download_available && capability('webdav', 'download_registry') ? '' : 'disabled'}>${icon('download')}<span>下载注册表文件</span></button></footer>`);
  }

  function renderFtp() {
    const service = state.data.ftp;
    if (state.ftpView === 'users') {
      const items = service.users.filter((item) => matchesQuery([item.username, item.root_dir]));
      const rows = items.map((item) => `<tr><td>${entryStatus(item.enabled)}</td><td><strong>${escapeHtml(item.username || '--')}</strong></td><td><code>${escapeHtml(item.root_dir || '--')}</code></td><td>${item.read_only ? '只读' : '读写'}</td><td>${item.has_password ? '已设置' : '未设置'}</td><td>${rowAction('ftp-user', item)}</td></tr>`);
      return tableMarkup('FTP 用户', `独立用户目录与读写权限 · ${serviceStatusText(service)}`, ['状态', '用户名', '根目录', '权限', '密码', '操作'], rows, '尚无 FTP 用户');
    }
    return settingsSurface('FTP', '面向局域网文件交换的标准传输服务，可独立控制用户、写入和被动端口。', serviceStatus(service), [
      detailRow('服务开关', service.enabled ? '启用' : '停用'),
      detailRow('监听端口', service.listen_port),
      detailRow('根目录', service.root_dir, { code: true }),
      detailRow('本地用户', service.local_users ? '允许' : '禁止'),
      detailRow('匿名访问', service.anonymous ? '允许' : '禁止'),
      detailRow('写入权限', service.write_enable ? '允许' : '只读'),
      detailRow('被动模式', service.passive_mode ? `${service.passive_port_min}-${service.passive_port_max}` : '关闭'),
      detailRow('客户端上限', service.max_clients),
      detailRow('空闲超时', `${service.idle_timeout} 秒`),
      detailRow('TLS', service.tls ? '已启用' : '未启用'),
      detailRow('防火墙端口', service.open_firewall ? '自动放行' : '不自动放行')
    ]);
  }

  function mainSurfaceMarkup() {
    if (state.tab === 'nfs') return renderNfs();
    if (state.tab === 'samba') return renderSamba();
    if (state.tab === 'webdav') return renderWebdav();
    return renderFtp();
  }

  function switchField(label, description, path, checked) {
    return `<label class="file-service-switch-row"><span><strong>${escapeHtml(label)}</strong><small>${escapeHtml(description)}</small></span><span class="file-service-switch"><input type="checkbox" data-file-draft="${escapeHtml(path)}" ${checked ? 'checked' : ''}><i></i></span></label>`;
  }

  function field(label, path, value, options = {}) {
    const type = options.type || 'text';
    const input = options.options
      ? `<select data-file-draft="${escapeHtml(path)}">${options.options.map(([id, text]) => `<option value="${escapeHtml(id)}" ${String(value) === String(id) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select>`
      : `<input type="${escapeHtml(type)}" data-file-draft="${escapeHtml(path)}" value="${type === 'password' ? '' : escapeHtml(value ?? '')}" placeholder="${escapeHtml(options.placeholder || '')}" ${options.min !== undefined ? `min="${escapeHtml(options.min)}"` : ''} ${options.max !== undefined ? `max="${escapeHtml(options.max)}"` : ''}>`;
    return `<label class="file-service-field ${options.wide ? 'is-wide' : ''}"><span>${escapeHtml(label)}</span>${input}${options.help ? `<small>${escapeHtml(options.help)}</small>` : ''}</label>`;
  }

  function editorCapability() {
    const map = {
      'nfs-export': ['nfs', 'exports'],
      'nfs-mount': ['nfs', 'mounts'],
      samba: ['samba', 'settings'],
      'samba-share': ['samba', 'shares'],
      webdav: ['webdav', 'settings'],
      ftp: ['ftp', 'settings'],
      'ftp-user': ['ftp', 'users']
    };
    const [service, action] = map[state.drawer] || ['', ''];
    return service ? capability(service, action) : false;
  }

  function drawerTitle() {
    if (state.drawer === 'nfs-export') return state.editor._new ? '添加 NFS 共享' : '编辑 NFS 共享';
    if (state.drawer === 'nfs-mount') return state.editor._new ? '添加远程挂载' : '编辑远程挂载';
    if (state.drawer === 'samba') return 'Samba 设置';
    if (state.drawer === 'samba-share') return state.editor._new ? '添加 Samba 共享' : '编辑 Samba 共享';
    if (state.drawer === 'webdav') return 'WebDAV 设置';
    if (state.drawer === 'ftp') return 'FTP 设置';
    if (state.drawer === 'ftp-user') return state.editor._new ? '新建 FTP 用户' : '编辑 FTP 用户';
    return '';
  }

  function drawerFields() {
    const editor = state.editor;
    if (state.drawer === 'nfs-export') return `${switchField('启用共享', '停用后保留配置，但不再导出目录', 'enabled', editor.enabled)}<div class="file-service-form">${field('共享路径', 'path', editor.path, { wide: true, placeholder: '/mnt/storage' })}${field('允许的客户端', 'clients', editor.clients, { wide: true, placeholder: '192.168.30.0/24 或 *', help: '支持主机、网段或 *；多个范围由后端按 NFS 规则解析。' })}${field('导出选项', 'options', editor.options, { wide: true, placeholder: 'rw,sync,root_squash,no_subtree_check', help: '原样保存 NFS 导出选项，不在前端擅自改写。' })}</div>`;
    if (state.drawer === 'nfs-mount') return `${switchField('启用挂载', '启用后按配置挂载远程 NFS 目录', 'enabled', editor.enabled)}<div class="file-service-form">${field('源目录', 'source', editor.source, { wide: true, placeholder: '192.168.30.3:/volume1/share' })}${field('挂载到', 'target', editor.target, { wide: true, placeholder: '/mnt/remote-share' })}${field('挂载选项', 'options', editor.options, { wide: true, placeholder: 'rw,soft,timeo=30' })}${field('延迟时间（秒）', 'delay', editor.delay, { type: 'number', min: 0, max: 3600 })}</div>`;
    if (state.drawer === 'samba') return `${switchField('启用 Samba', '启动 SMB 文件共享服务', 'enabled', editor.enabled)}${switchField('允许访客访问', '允许未提供账号的客户端访问明确开放的共享', 'guest_access', editor.guest_access)}<div class="file-service-form">${field('工作组', 'workgroup', editor.workgroup, { placeholder: 'WORKGROUP' })}${field('服务器描述', 'server_description', editor.server_description, { placeholder: 'Dreaming OS' })}${field('监听接口', 'interfaces', asArray(editor.interfaces).join(', '), { wide: true, placeholder: 'lan, guest', help: '多个接口使用逗号分隔。' })}${field('最低 SMB 协议', 'min_protocol', editor.min_protocol, { options: [['SMB2','SMB2'],['SMB2_10','SMB 2.1'],['SMB3','SMB3']] })}${field('最高 SMB 协议', 'max_protocol', editor.max_protocol, { options: [['SMB2','SMB2'],['SMB2_10','SMB 2.1'],['SMB3','SMB3'],['SMB3_11','SMB 3.11']] })}</div>`;
    if (state.drawer === 'samba-share') return `${switchField('启用共享', '停用后保留配置，但不发布该共享', 'enabled', editor.enabled)}${switchField('只读', '禁止客户端上传、修改和删除文件', 'read_only', editor.read_only)}${switchField('网络发现', '允许客户端浏览到该共享', 'browseable', editor.browseable)}${switchField('访客访问', '允许未登录客户端访问该共享', 'guest_access', editor.guest_access)}<div class="file-service-form">${field('共享名称', 'name', editor.name, { wide: true, placeholder: '例如 Public' })}${field('共享路径', 'path', editor.path, { wide: true, placeholder: '/mnt/storage/public' })}${field('允许用户', 'allowed_users', asArray(editor.allowed_users).join(', '), { wide: true, placeholder: 'lester, backup', help: '留空表示所有已授权用户；多个用户使用逗号分隔。' })}${field('备注', 'note', editor.note, { wide: true })}</div>`;
    if (state.drawer === 'webdav') return `${switchField('启用 WebDAV', '启动基于 NGINX 的 WebDAV 服务', 'enabled', editor.enabled)}${switchField('只读模式', '禁止客户端上传、修改和删除文件', 'read_only', editor.read_only)}${switchField('打开防火墙端口', '自动放行所配置的监听端口', 'open_firewall', editor.open_firewall)}${switchField('启用 SSL', '使用证书提供 HTTPS 访问', 'ssl', editor.ssl)}<div class="file-service-form">${field('监听端口', 'listen_port', editor.listen_port, { type: 'number', min: 1, max: 65535 })}${field('用户名', 'username', editor.username, { placeholder: '留空禁用身份验证' })}${field('密码', 'password', '', { type: 'password', placeholder: editor.has_password ? '留空保持现有密码' : '留空禁用身份验证', help: '后端不得回显已保存密码。' })}${field('WebDAV 目录', 'root_dir', editor.root_dir, { wide: true, placeholder: '/mnt' })}${editor.ssl ? `${field('SSL 证书', 'cert_file', editor.cert_file, { wide: true, placeholder: '/etc/ssl/certs/webdav.crt' })}${field('SSL 密钥', 'key_file', editor.key_file, { wide: true, placeholder: '/etc/ssl/private/webdav.key' })}` : ''}</div>`;
    if (state.drawer === 'ftp') return `${switchField('启用 FTP', '启动 FTP 文件传输服务', 'enabled', editor.enabled)}${switchField('允许本地用户', '允许已配置的 FTP 用户登录', 'local_users', editor.local_users)}${switchField('允许匿名访问', '匿名访问仅应授予最小权限', 'anonymous', editor.anonymous)}${switchField('允许写入', '允许上传、修改和删除文件', 'write_enable', editor.write_enable)}${switchField('打开防火墙端口', '自动放行控制端口和被动端口范围', 'open_firewall', editor.open_firewall)}${switchField('启用 TLS', '加密 FTP 身份验证和数据传输', 'tls', editor.tls)}${switchField('被动模式', '通过受控端口范围建立数据连接', 'passive_mode', editor.passive_mode)}<div class="file-service-form">${field('监听端口', 'listen_port', editor.listen_port, { type: 'number', min: 1, max: 65535 })}${field('根目录', 'root_dir', editor.root_dir, { wide: true, placeholder: '/mnt' })}${editor.passive_mode ? `${field('被动端口起始', 'passive_port_min', editor.passive_port_min, { type: 'number', min: 1024, max: 65535 })}${field('被动端口结束', 'passive_port_max', editor.passive_port_max, { type: 'number', min: 1024, max: 65535 })}` : ''}${field('客户端上限', 'max_clients', editor.max_clients, { type: 'number', min: 1, max: 1000 })}${field('空闲超时（秒）', 'idle_timeout', editor.idle_timeout, { type: 'number', min: 30, max: 86400 })}${editor.tls ? `${field('TLS 证书', 'cert_file', editor.cert_file, { wide: true })}${field('TLS 密钥', 'key_file', editor.key_file, { wide: true })}` : ''}</div>`;
    if (state.drawer === 'ftp-user') return `${switchField('启用用户', '停用后保留用户配置，但禁止登录', 'enabled', editor.enabled)}${switchField('只读权限', '用户只能下载和浏览文件', 'read_only', editor.read_only)}<div class="file-service-form">${field('用户名', 'username', editor.username, { wide: true, placeholder: '例如 backup' })}${field('根目录', 'root_dir', editor.root_dir, { wide: true, placeholder: '/mnt/ftp/backup' })}${field('密码', 'password', '', { type: 'password', wide: true, placeholder: editor.has_password ? '留空保持现有密码' : '设置登录密码', help: '密码只能写入，后端不得返回明文或散列。' })}</div>`;
    return '';
  }

  function drawerMarkup() {
    if (!state.drawer) return '';
    const writable = editorCapability();
    const canDelete = !state.editor._new && ['nfs-export', 'nfs-mount', 'samba-share', 'ftp-user'].includes(state.drawer) && writable;
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-file-close aria-label="关闭文件服务设置"></button><aside class="file-service-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" aria-label="${escapeHtml(drawerTitle())}"><header class="dwrt-kit-sheet-header"><div><span>FILE SERVICES</span><strong>${escapeHtml(drawerTitle())}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-file-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body file-service-drawer-body">${drawerFields()}${!writable ? '<div class="file-service-capability">后端写能力尚未开放。可以查看完整配置项，但不会把未保存配置写入浏览器或 /etc/config。</div>' : ''}${state.notice ? noticeMarkup() : ''}</div><footer class="dwrt-kit-sheet-footer file-service-drawer-footer">${canDelete ? `<button class="policy-secondary danger" type="button" data-file-delete ${state.saving ? 'disabled' : ''}>${state.confirmDelete ? '再次点击删除' : '删除'}</button>` : '<span></span>'}<div><button class="policy-secondary" type="button" data-file-close>取消</button><button class="policy-primary" type="button" data-file-save ${writable && !state.saving ? '' : 'disabled'}>${state.saving ? '正在保存' : writable ? '保存并应用' : '等待后端能力'}</button></div></footer></aside>`;
  }

  function render() {
    if (!root) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'policy-table-route-host', MODULE_CLASS);
    root.innerHTML = `<section class="file-service-shell">${tabsMarkup()}${noticeMarkup()}<main class="file-service-workbench">${toolbarMarkup()}${mainSurfaceMarkup()}</main>${drawerMarkup()}</section>`;
    ui.mountAll?.(root);
  }

  function patchMainSurface() {
    const current = root?.querySelector('.file-service-main-surface');
    if (!current) { render(); return; }
    const scroll = current.querySelector('.dwrt-kit-table-scroll');
    const top = scroll?.scrollTop || 0;
    const left = scroll?.scrollLeft || 0;
    const template = document.createElement('template');
    template.innerHTML = mainSurfaceMarkup();
    const next = template.content.firstElementChild;
    if (!next) return;
    current.replaceWith(next);
    const nextScroll = next.querySelector('.dwrt-kit-table-scroll');
    if (nextScroll) { nextScroll.scrollTop = top; nextScroll.scrollLeft = left; }
    ui.mountAll?.(next);
  }

  function setEditorField(path, value) {
    state.editor[path] = value;
  }

  function closeDrawer() {
    state.drawer = '';
    state.editor = {};
    state.notice = '';
    state.noticeTone = '';
    state.confirmDelete = false;
    render();
  }

  function openCreate() {
    state.notice = '';
    state.confirmDelete = false;
    if (state.tab === 'nfs' && state.nfsView === 'exports') {
      state.drawer = 'nfs-export';
      state.editor = { _new: true, enabled: true, path: '', clients: '*', options: 'rw,sync,root_squash,no_subtree_check' };
    } else if (state.tab === 'nfs') {
      state.drawer = 'nfs-mount';
      state.editor = { _new: true, enabled: true, source: '', target: '', options: 'rw', delay: 0 };
    } else if (state.tab === 'samba') {
      state.drawer = 'samba-share';
      state.editor = { _new: true, enabled: true, name: '', path: '/mnt', read_only: false, browseable: true, guest_access: false, allowed_users: [], note: '' };
    } else if (state.tab === 'ftp') {
      state.drawer = 'ftp-user';
      state.editor = { _new: true, enabled: true, username: '', root_dir: '/mnt', read_only: true, password: '', has_password: false };
    }
    render();
  }

  function openSettings(service) {
    state.drawer = service;
    state.editor = clone(state.data[service]);
    state.editor.password = '';
    state.confirmDelete = false;
    state.notice = '';
    render();
  }

  function openEditor(kind, id) {
    let item;
    if (kind === 'nfs-export') item = state.data.nfs.exports.find((entry) => entry.id === id);
    if (kind === 'nfs-mount') item = state.data.nfs.mounts.find((entry) => entry.id === id);
    if (kind === 'samba-share') item = state.data.samba.shares.find((entry) => entry.id === id);
    if (kind === 'ftp-user') item = state.data.ftp.users.find((entry) => entry.id === id);
    if (!item) return;
    state.drawer = kind;
    state.editor = { ...clone(item), _new: false, password: '' };
    state.confirmDelete = false;
    state.notice = '';
    render();
  }

  function editorEndpoint() {
    const editor = state.editor;
    if (state.drawer === 'webdav') return ENDPOINTS.webdav;
    if (state.drawer === 'samba') return ENDPOINTS.samba;
    if (state.drawer === 'samba-share') return `${ENDPOINTS.samba}/shares${editor._new ? '' : `/${encodeURIComponent(editor.id)}`}`;
    if (state.drawer === 'ftp') return ENDPOINTS.ftp;
    if (state.drawer === 'nfs-export') return `${ENDPOINTS.nfs}/exports${editor._new ? '' : `/${encodeURIComponent(editor.id)}`}`;
    if (state.drawer === 'nfs-mount') return `${ENDPOINTS.nfs}/mounts${editor._new ? '' : `/${encodeURIComponent(editor.id)}`}`;
    if (state.drawer === 'ftp-user') return `${ENDPOINTS.ftp}/users${editor._new ? '' : `/${encodeURIComponent(editor.id)}`}`;
    return '';
  }

  function cleanPayload() {
    const payload = clone(state.editor);
    delete payload._new;
    delete payload.capabilities;
    delete payload.available;
    delete payload.running;
    delete payload.users;
    delete payload.shares;
    delete payload.exports;
    delete payload.mounts;
    delete payload.has_password;
    if (state.drawer === 'samba') payload.interfaces = String(payload.interfaces || '').split(',').map((value) => value.trim()).filter(Boolean);
    if (state.drawer === 'samba-share') payload.allowed_users = String(payload.allowed_users || '').split(',').map((value) => value.trim()).filter(Boolean);
    if (!payload.password) delete payload.password;
    payload.apply = true;
    return payload;
  }

  function validateEditor() {
    if (state.drawer === 'nfs-export' && !firstText(state.editor.path)) return '共享路径不能为空';
    if (state.drawer === 'nfs-mount' && (!firstText(state.editor.source) || !firstText(state.editor.target))) return '源目录和挂载点不能为空';
    if (state.drawer === 'samba-share' && (!firstText(state.editor.name) || !firstText(state.editor.path))) return '共享名称和共享路径不能为空';
    if (state.drawer === 'ftp-user' && !firstText(state.editor.username)) return '用户名不能为空';
    if (state.drawer === 'ftp' && state.editor.passive_mode && Number(state.editor.passive_port_min) > Number(state.editor.passive_port_max)) return '被动端口起始值不能大于结束值';
    return '';
  }

  async function saveEditor() {
    if (!editorCapability() || state.saving) return;
    const validation = validateEditor();
    if (validation) { state.notice = validation; state.noticeTone = 'error'; render(); return; }
    state.saving = true;
    state.notice = '';
    render();
    try {
      const method = state.editor._new ? 'POST' : 'PUT';
      await requestJson(editorEndpoint(), { method, body: JSON.stringify(cleanPayload()) });
      if (!state.mounted) return;
      state.saving = false;
      state.drawer = '';
      state.editor = {};
      state.notice = '配置已保存并应用';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      if (!state.mounted) return;
      state.saving = false;
      state.notice = `保存失败：${firstText(error.message, '后端未接受配置')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  async function deleteEditor() {
    if (!editorCapability() || state.editor._new || state.saving) return;
    if (!state.confirmDelete) { state.confirmDelete = true; render(); return; }
    state.saving = true;
    render();
    try {
      await requestJson(editorEndpoint(), { method: 'DELETE' });
      if (!state.mounted) return;
      state.saving = false;
      state.drawer = '';
      state.editor = {};
      state.notice = '配置已删除';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      if (!state.mounted) return;
      state.saving = false;
      state.notice = `删除失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  async function downloadRegistry() {
    if (!capability('webdav', 'download_registry')) return;
    try {
      const response = await fetch(`${ENDPOINTS.webdav}/registry?v=${VERSION}`, { credentials: 'same-origin', cache: 'no-store', headers: authHeaders() });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'DreamingOS-WebDAV-HTTP-Auth.reg';
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      state.notice = `下载失败：${firstText(error.message)}`;
      state.noticeTone = 'error';
      render();
    }
  }

  function onClick(event) {
    if (event.target.closest('[data-file-close]')) { closeDrawer(); return; }
    if (event.target.closest('[data-file-refresh]')) { load(true); return; }
    if (event.target.closest('[data-file-create]')) { openCreate(); return; }
    if (event.target.closest('[data-file-save]')) { saveEditor(); return; }
    if (event.target.closest('[data-file-delete]')) { deleteEditor(); return; }
    if (event.target.closest('[data-webdav-registry]')) { downloadRegistry(); return; }
    const settings = event.target.closest('[data-file-settings]');
    if (settings) { openSettings(settings.dataset.fileSettings); return; }
    const edit = event.target.closest('[data-file-edit]');
    if (edit) { openEditor(edit.dataset.fileEdit, edit.dataset.fileId); return; }
    const view = event.target.closest('[data-file-view]');
    if (view) {
      if (state.tab === 'nfs') state.nfsView = view.dataset.fileView;
      if (state.tab === 'samba') state.sambaView = view.dataset.fileView;
      if (state.tab === 'ftp') state.ftpView = view.dataset.fileView;
      state.query = '';
      render();
    }
  }

  function onInput(event) {
    const search = event.target.closest('[data-file-search]');
    if (search) { state.query = search.value; patchMainSurface(); return; }
    const fieldInput = event.target.closest('[data-file-draft]');
    if (!fieldInput || ['checkbox', 'radio'].includes(fieldInput.type) || fieldInput.tagName === 'SELECT') return;
    setEditorField(fieldInput.dataset.fileDraft, fieldInput.type === 'number' ? Number(fieldInput.value || 0) : fieldInput.value);
  }

  function onChange(event) {
    const fieldInput = event.target.closest('[data-file-draft]');
    if (!fieldInput) return;
    const value = fieldInput.type === 'checkbox' ? fieldInput.checked : fieldInput.type === 'number' ? Number(fieldInput.value || 0) : fieldInput.value;
    setEditorField(fieldInput.dataset.fileDraft, value);
    if (['ssl', 'tls', 'passive_mode'].includes(fieldInput.dataset.fileDraft)) render();
  }

  function onTabChange(event) {
    if (!event.target.closest('[data-file-tabs]')) return;
    const next = event.detail?.value;
    if (!TABS.some(([id]) => id === next) || next === state.tab) return;
    state.tab = next;
    state.query = '';
    state.drawer = '';
    state.notice = '';
    render();
  }

  function onKeyDown(event) {
    if (event.key === 'Escape' && state.drawer) closeDrawer();
  }

  root?.addEventListener('click', onClick);
  root?.addEventListener('input', onInput);
  root?.addEventListener('change', onChange);
  root?.addEventListener('dwrt-tab-change', onTabChange);
  document.addEventListener('keydown', onKeyDown);
  stage?.classList.add('is-storage-file-services');
  render();
  load();

  return {
    refresh() { return load(true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      root?.removeEventListener('click', onClick);
      root?.removeEventListener('input', onInput);
      root?.removeEventListener('change', onChange);
      root?.removeEventListener('dwrt-tab-change', onTabChange);
      document.removeEventListener('keydown', onKeyDown);
      root?.replaceChildren();
      root?.classList.remove('route-workspace', 'policy-table-route-host', MODULE_CLASS);
      stage?.classList.remove('is-storage-file-services');
    }
  };
}

export default { mount };
