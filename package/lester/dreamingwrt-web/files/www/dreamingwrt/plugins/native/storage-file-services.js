export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const VERSION = '20261005-remote-share-ftp-01';
  const standalone = context.remoteShare === true;
  const MODULE_CLASS = 'storage-file-services-route-host';
  const stage = root?.closest('.console-stage');
  const TABS = [['nfs', 'NFS'], ['samba', 'Samba'], ['webdav', 'WebDAV'], ['ftp', 'FTP']];
  const LATER_PROTOCOLS = [['sftp', 'SFTP'], ['dlna', 'DLNA'], ['afp', 'AFP']];
  const ENDPOINTS = {
    aggregate: '/api/v1/storage/file-services',
    nfs: '/api/v1/services/nfs',
    samba: '/api/v1/services/samba',
    webdav: '/api/v1/services/webdav',
    ftp: '/api/v1/services/ftp',
    accounts: '/api/v1/services/file-sharing/accounts',
    operations: '/api/v1/services/file-sharing/operations'
  };

  /*
   * 后端 capability_reasons 的原因码 -> 用户可读措辞。判据始终是能力位布尔值本身，
   * reason 只用于「不支持」时陈述后端原话；未知原因码原样透出，不猜、不改写语义。
   */
  const REASON_TEXT = {
    nfs_mount_manager_pending: '远程挂载管理尚未提供',
    service_settings_apply_pending: '服务设置下发尚未提供',
    secret_encryption_apply_pending: '凭据加密下发尚未提供',
    runtime_not_installed: '组件未安装',
    webdav_preflight_failed: 'WebDAV 配置或证书预检失败',
    webdav_preflight_timeout: 'WebDAV 配置预检超时',
    directory_binding_changed: '目录挂载或身份已变化，请核实后重新绑定',
    port_in_use: '监听地址或端口已被占用',
    webdav_listener_not_ready: 'WebDAV 未能建立监听',
    nginx_dav_ext_update_required: 'WebDAV 组件需要更新后才能管理共享',
    webdav_sandbox_runtime_missing: '独立 WebDAV 运行组件未安装完整',
    shared_nginx_transaction_and_acl_pending: '独立应用与逐共享授权尚未提供',
    ftp_managed_config_pending: 'FTP 受管配置尚未提供',
    managed_ftp_runtime_missing: '受管 FTP 组件未安装完整',
    protocol_operation_in_progress: '当前协议操作尚未结束，请稍后重试',
    ftp_settings_validation_failed: '请检查 FTP 监听地址、端口及证书设置'
  };

  /* 抽屉标题里的能力主体名。禁写说明必须指名道姓，不得用一句话否认整个服务。 */
  const CAPABILITY_SUBJECT = {
    'nfs-export': 'NFS 共享目录',
    'nfs-mount': 'NFS 远程挂载',
    nfs: 'NFS 新建默认策略',
    samba: 'Samba 服务设置',
    'samba-share': 'Samba 共享目录',
    'webdav-share': 'WebDAV 共享目录',
    webdav: 'WebDAV 服务设置',
    ftp: 'FTP 服务设置',
    'ftp-share': 'FTP 共享目录',
    'share-account': '共享账号'
  };

  function emptyServiceData() {
    return {
      capabilities: {},
      capability_reasons: {},
      accounts: {items: [], capabilities: {}, source: 'unavailable'},
      operations: {capabilities:{}},
      sftp: {available:null, running:null, capabilities:{}},
      dlna: {available:null, running:null, capabilities:{}},
      afp: {available:null, running:null, capabilities:{}},
      nfs: { available: null, running: null, exports: [], mounts: [], capabilities: {} },
      samba: {
        available: null, running: null, enabled: false, workgroup: 'WORKGROUP', server_description: 'Dreaming OS',
        interfaces: ['lan'], min_protocol: 'SMB2', max_protocol: 'SMB3', guest_access: false, shares: [], capabilities: {}
      },
      webdav: {
        available: null, running: null, enabled: false, listen_port: 5005, username: '', has_password: false,
        root_dir: '/mnt', read_only: false, open_firewall: false, ssl: false, cert_file: '', key_file: '', capabilities: {}
      },
      ftp: { available: null, running: null, enabled: null, settings: null, shares: [], capabilities: {} }
    };
  }

  const state = {
    mounted: true,
    seq: 0,
    pollTimer: 0,
    loading: true,
    refreshing: false,
    saving: false,
    loaded: false,
    error: '',
    notice: '',
    noticeTone: '',
    page: 'shares',
    accountsView: false,
    batchRequest: null, batchResult: null, operationHistory: [],
    filter: 'all',
    errors: {},
    baseline: {},
    conflict: null,
    pendingWrite: null,
    actionBusy: false,
    picker: null,
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
      const data = result.data || {};
      if (data.ok === false || data.data?.ok === false || data.code === 4000) {
        const detail = data.data || data;
        throw Object.assign(new Error(firstText(detail.message, detail.error, '读取失败')), { detail });
      }
      return data;
    }
    const response = await sessionFetch(`${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`, {
      credentials: 'same-origin', cache: 'no-store', ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    let payload = json?.data ?? json?.body ?? json;
    if (payload?.code === 2000 || payload?.code === 4000) payload = payload.data || payload;
    if (!response.ok || json?.ok === false || json?.code === 4000 || payload?.ok === false) {
      const error = new Error(firstText(payload?.message, payload?.error, json?.message, json?.error, `HTTP ${response.status}`));
      error.status = response.status;
      error.detail = payload;
      throw error;
    }
    return payload || {};
  }

  function normalizeNfs(payload = {}) {
    return {
      ...payload,
      available: payload.available == null ? null : bool(payload.available),
      running: payload.running == null ? null : bool(payload.running),
      exports: asArray(payload.exports, ['shares']).map((item, index) => ({
        ...item,
        id: firstText(item.id, item.uuid),
        enabled: bool(item.enabled, true),
        path: firstText(item.path, item.directory),
        clients: firstText(item.clients, item.allowed_clients),
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
      available: payload.available == null ? null : bool(payload.available),
      running: payload.running == null ? null : bool(payload.running),
      enabled: payload.enabled == null ? null : bool(payload.enabled),
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
      shares: asArray(payload.shares),
      capabilities: payload.capabilities || {}
    };
  }

  function normalizeSamba(payload = {}) {
    return {
      ...payload,
      available: payload.available == null ? null : bool(payload.available),
      running: payload.running == null ? null : bool(payload.running),
      enabled: payload.enabled == null ? null : bool(payload.enabled),
      workgroup: firstText(payload.workgroup, 'WORKGROUP'),
      server_description: firstText(payload.server_description, payload.description, payload.server_string, 'Dreaming OS'),
      interfaces: asArray(payload.interfaces).map(String),
      min_protocol: firstText(payload.min_protocol, payload.server_min_protocol, 'SMB2'),
      max_protocol: firstText(payload.max_protocol, payload.server_max_protocol, 'SMB3'),
      guest_access: bool(payload.guest_access, payload.map_to_guest),
      shares: asArray(payload.shares, ['exports']).map((item, index) => ({
        ...item,
        id: firstText(item.id, item.uuid),
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
    const settings = payload.settings && typeof payload.settings === 'object' ? payload.settings : null;
    return {
      ...payload,
      listen_address: '', listen_port: 21, passive_min_port: 50000, passive_max_port: 50009,
      passive_address: '', tls: false, cert_file: '', key_file: '',
      ...(settings || {}), settings,
      available: payload.available == null ? null : bool(payload.available),
      running: payload.running == null ? null : bool(payload.running),
      enabled: payload.enabled == null ? null : bool(payload.enabled),
      requested_running: payload.requested_running == null ? null : bool(payload.requested_running),
      shares: asArray(payload.shares),
      capabilities: payload.capabilities || {}
    };
  }

  function normalizeAccounts(payload = {}) {
    return {...payload, items: asArray(payload.items), capabilities: payload.capabilities || {}};
  }

  function normalizeAggregate(payload = {}) {
    const source = payload.file_services && typeof payload.file_services === 'object' ? payload.file_services : payload;
    const fallback = emptyServiceData();
    return {
      capabilities: source.capabilities || {},
      capability_reasons: source.capability_reasons || {},
      accounts: source.accounts ? normalizeAccounts(source.accounts) : fallback.accounts,
      operations: source.operations || fallback.operations,
      sftp: source.sftp || fallback.sftp,
      dlna: source.dlna || fallback.dlna,
      afp: source.afp || fallback.afp,
      nfs: source.nfs && typeof source.nfs === 'object' ? normalizeNfs(source.nfs) : fallback.nfs,
      samba: source.samba && typeof source.samba === 'object' ? normalizeSamba(source.samba) : fallback.samba,
      webdav: source.webdav && typeof source.webdav === 'object' ? normalizeWebdav(source.webdav) : fallback.webdav,
      ftp: source.ftp && typeof source.ftp === 'object' ? normalizeFtp(source.ftp) : fallback.ftp
    };
  }

  async function load(background = false) {
    const seq = ++state.seq;
    state.error = '';
    if (state.actionBusy) return;
    if (background) state.refreshing = true; else state.loading = true;
    if (!background) render();
    try {
      let payload;
      const errors = {};
      try {
        const source = await requestJson(ENDPOINTS.aggregate);
        payload = normalizeAggregate(source);
        for (const [service] of TABS) if (!(source.file_services || source)[service]) {
          payload[service] = state.data[service];
          errors[service] = '响应缺少该协议的数据';
        }
      } catch (aggregateError) {
        const settled = await Promise.allSettled([
          requestJson(ENDPOINTS.nfs), requestJson(ENDPOINTS.samba), requestJson(ENDPOINTS.webdav), requestJson(ENDPOINTS.ftp)
        ]);
        if (!settled.some((result) => result.status === 'fulfilled')) throw aggregateError;
        payload = clone(state.data);
        const normalizers = [normalizeNfs, normalizeSamba, normalizeWebdav, normalizeFtp];
        TABS.forEach(([service], index) => {
          if (settled[index].status === 'fulfilled') payload[service] = normalizers[index](settled[index].value);
          else errors[service] = firstText(settled[index].reason?.message, '读取失败');
        });
      }
      if (!payload.accounts || payload.accounts.source === 'unavailable') {
        try { payload.accounts = normalizeAccounts(await requestJson(ENDPOINTS.accounts)); }
        catch (error) { errors.accounts = firstText(error.message, '共享账号读取失败'); payload.accounts = state.data.accounts; }
      }
      if (!state.mounted || seq !== state.seq) return;
      state.data = payload;
      state.errors = errors;
      state.loaded = true;
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.error = `读取失败：${firstText(error.message, '文件服务 API 不可用')}。已有数据显示为上次读取结果。`;
      state.errors = Object.fromEntries(TABS.map(([service]) => [service, firstText(error.message, '读取失败')]));
    } finally {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      if (background) renderPreservingInteraction(); else render();
    }
  }

  function capability(service, action) {
    if (state.errors[service]) return false;
    const role = window.DWRT_SESSION?.tokens?.().role;
    if (service === 'accounts' && role !== 'owner') return false;
    if (role && !['owner', 'admin'].includes(role)) return false;
    const local = state.data[service]?.capabilities || {};
    const global = state.data.capabilities || {};
    if (typeof local[action] === 'boolean') return local[action];
    return local[action] === true || local[`write_${action}`] === true || local.write === true
      || global[`${service}_${action}`] === true || global[service]?.[action] === true || global[service]?.write === true;
  }

  /*
   * 取某个能力位的后端原因码。聚合端点把 reasons 按服务分组下发，单服务端点是平铺的，
   * 两种形状都要认。返回空串表示后端没给原因，此时不得据此推断能力缺失。
   */
  function capabilityReason(service, action) {
    const local = state.data[service]?.capability_reasons || {};
    const global = state.data.capability_reasons || {};
    const code = firstText(local[action], global[service]?.[action]);
    if (!code) return '';
    return REASON_TEXT[code] || code;
  }

  /*
   * 能力未就绪时的说明文案：只否认这一个子功能，并带上后端原因码的可读措辞。
   * 调用方自行补后半句上下文，避免同一段里出现两句重复的解释。
   */
  function capabilityNotice(subject, service, action) {
    const reason = capabilityReason(service, action);
    return `${subject}尚未提供写入接口${reason ? `（后端原因：${reason}）` : ''}。`;
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
    if (state.errors[service.service]) return ui.statusBadgeMarkup?.('读取失败', 'warning') || '读取失败';
    if (service.available === false) return ui.statusBadgeMarkup?.('组件未安装', 'warning') || '';
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
      return `<div class="file-service-segmented" role="group" aria-label="FTP 数据类型"><button type="button" class="${state.ftpView === 'settings' ? 'is-active' : ''}" data-file-view="settings">服务设置</button><button type="button" class="${state.ftpView === 'shares' ? 'is-active' : ''}" data-file-view="shares">共享目录</button></div>`;
    }
    return '<span></span>';
  }

  /* 视图切换（导出/挂载、共享/设置）属于导航，留在页面级；动作按钮进表格工具栏。 */
  function viewSwitchMarkup() {
    const seg = segmentedMarkup();
    return seg ? `<header class="policy-toolbar file-service-toolbar"><div class="file-service-toolbar-leading">${seg}</div></header>` : '';
  }

  function toolbarMarkup() {
    /* 当前视图的「新建」会打开哪个抽屉，与 openCreate() 保持一致。 */
    function createDrawerKind() {
      if (state.tab === 'nfs') return state.nfsView === 'exports' ? 'nfs-export' : 'nfs-mount';
      if (state.tab === 'samba' && state.sambaView === 'shares') return 'samba-share';
      if (state.tab === 'ftp' && state.ftpView === 'shares') return 'ftp-share';
      return '';
    }
    function createCapabilityPath() {
      const map = {
        'nfs-export': ['nfs', 'exports'],
        'nfs-mount': ['nfs', 'mounts'],
        'samba-share': ['samba', 'shares'],
      'webdav-share': ['webdav', 'shares'],
        'ftp-share': ['ftp', 'shares'],
      'share-account': ['accounts', 'manage']
      };
      return map[createDrawerKind()] || ['', ''];
    }
    const searchable = state.tab === 'nfs' || (state.tab === 'samba' && state.sambaView === 'shares') || (state.tab === 'ftp' && state.ftpView === 'shares');
    const createLabel = state.tab === 'nfs' ? (state.nfsView === 'exports' ? '添加共享' : '添加挂载') : state.tab === 'samba' && state.sambaView === 'shares' ? '添加共享' : state.tab === 'ftp' && state.ftpView === 'shares' ? '添加共享' : '';
    const settingsLabel = state.tab === 'webdav' || (state.tab === 'samba' && state.sambaView === 'settings') || (state.tab === 'ftp' && state.ftpView === 'settings') ? '编辑设置' : '';
    const placeholder = state.tab === 'nfs' ? '搜索路径、客户端或选项' : state.tab === 'samba' ? '搜索共享名称、路径、用户或备注' : '搜索用户名或目录';
    /* 新建入口按当前视图自己的能力位放开：导出可写不代表挂载可写，反之亦然。 */
    const [createService, createAction] = createCapabilityPath();
    const canCreate = createService ? capability(createService, createAction) : true;
    const createHint = canCreate ? '' : capabilityNotice(CAPABILITY_SUBJECT[createDrawerKind()] || '该配置', createService, createAction);
    return `<div class="file-service-table-actions">${searchable ? `<label class="policy-search policy-search-main" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-file-search value="${escapeHtml(state.query)}" placeholder="${placeholder}"></label>` : ''}<div class="policy-toolbar-actions">${settingsLabel ? `<button class="policy-create-button" type="button" data-file-settings="${state.tab}">${icon('edit')}<span>${settingsLabel}</span></button>` : ''}${createLabel ? `<button class="policy-create-button" type="button" data-file-create ${canCreate ? '' : `disabled data-dwrt-tooltip="${escapeHtml(createHint)}"`}>${icon('plus')}<span>${createLabel}</span></button>` : ''}</div></div>`;
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
    return `<button class="file-service-icon-button" type="button" data-file-edit="${escapeHtml(kind)}" data-file-id="${escapeHtml(item.id)}" aria-label="编辑" data-dwrt-tooltip="编辑" ${item.id ? '' : 'disabled'}>${icon('edit')}</button>`;
  }

  function entryStatus(enabled) {
    return ui.statusBadgeMarkup?.(enabled ? '启用' : '停用', enabled ? 'success' : 'error') || `<span>${enabled ? '启用' : '停用'}</span>`;
  }

  function tableMarkup(title, subtitle, headings, rows, empty, options = {}) {
    const scopeNotice = options.capabilityNotice
      ? `<div class="file-service-capability is-inline" role="status">${escapeHtml(options.capabilityNotice)}</div>`
      : '';
    return `<section class="file-service-main-surface file-service-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>${escapeHtml(title)}</strong></div><span class="dwrt-kit-table-count">${rows.length} 条</span>${toolbarMarkup()}</div>${scopeNotice}<div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table file-service-table"><thead><tr>${headings.map((heading) => `<th>${escapeHtml(heading)}</th>`).join('')}</tr></thead><tbody>${state.loading && !state.loaded ? `<tr><td colspan="${headings.length}" class="dwrt-kit-table-empty">正在读取文件服务配置</td></tr>` : rows.length ? rows.join('') : `<tr><td colspan="${headings.length}" class="dwrt-kit-table-empty">${escapeHtml(empty)}</td></tr>`}</tbody></table></div></section>`;
  }

  function renderNfs() {
    const service = state.data.nfs;
    if (state.nfsView === 'mounts') {
      const items = service.mounts.filter((item) => matchesQuery([item.source, item.target, item.options, item.delay]));
      const rows = items.map((item) => `<tr><td>${entryStatus(item.enabled)}</td><td><code>${escapeHtml(item.source || '--')}</code></td><td><code>${escapeHtml(item.target || '--')}</code></td><td><span class="file-service-ellipsis" data-dwrt-tooltip="${escapeHtml(item.options || '--')}">${escapeHtml(item.options || '--')}</span></td><td>${item.delay ? `${item.delay} 秒` : '立即'}</td><td>${rowAction('nfs-mount', item)}</td></tr>`);
      /*
       * 远程挂载单独判 capabilities.mounts。导出可写时不得因为这一位为 false 就否认整个 NFS，
       * 两种空态也要分开说：能力未提供 vs 确实没有配置。
       */
      const mountWritable = capability('nfs', 'mounts');
      return tableMarkup('已挂载的目录', `远程 NFS 目录挂载到本机 · ${serviceStatusText(service)}`, ['状态', '源目录', '挂载到', '选项', '延迟时间', '操作'], rows,
        mountWritable ? '尚无远程 NFS 挂载配置' : '远程挂载管理尚未提供，后端未下发挂载配置',
        { capabilityNotice: mountWritable ? '' : `${capabilityNotice('NFS 远程挂载', 'nfs', 'mounts')}NFS 共享目录不受影响，可正常新增与修改。` });
    }
    const items = service.exports.filter((item) => matchesQuery([item.path, item.clients, item.options]));
    const rows = items.map((item) => `<tr><td>${entryStatus(item.enabled)}</td><td><code>${escapeHtml(item.path || '--')}</code></td><td>${escapeHtml(item.clients || '*')}</td><td><span class="file-service-ellipsis" data-dwrt-tooltip="${escapeHtml(item.options || '--')}">${escapeHtml(item.options || '--')}</span></td><td>${rowAction('nfs-export', item)}</td></tr>`);
    return tableMarkup('共享目录', `NFS 导出目录与客户端访问范围 · ${serviceStatusText(service)}`, ['状态', '路径', '允许的客户端', '导出选项', '操作'], rows, '尚无 NFS 共享目录');
  }

  function serviceStatusText(service) {
    if (service.available === false) return '组件未安装';
    if (service.running === true) return '运行中';
    if (service.running === false) return '未运行';
    return '状态未知';
  }

  function navigationMarkup() {
    const pages = [['shares', '共享目录', 'folder'], ['services', '协议服务', 'server']];
    if (standalone) return `<aside class="file-service-rail dwrt-rail"><div class="dwrt-rail-brand"><img src="/static/images/logo-wide.png" alt="DreamingOS"></div><nav class="dwrt-rail-list" aria-label="远程共享">${pages.map(([id, label, glyph]) => `<button type="button" class="dwrt-rail-item ${state.page === id ? 'is-active' : ''}" data-file-page="${id}" aria-label="${label}" aria-current="${state.page === id ? 'page' : 'false'}"><span class="dwrt-rail-item-icon">${icon(glyph)}</span><span class="dwrt-rail-item-text">${label}</span></button>`).join('')}</nav></aside>`;
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs" aria-label="远程共享">${pages.map(([id, label]) => `<button class="dwrt-kit-tab ${state.page === id ? 'is-active' : ''}" type="button" data-file-page="${id}" aria-selected="${state.page === id}">${label}</button>`).join('')}</nav>`;
  }

  function connection(item, service) {
    const data = state.data[service];
    if (state.errors[service]) return { reason: '状态读取失败' };
    if (!item.enabled) return { reason: '共享已停用' };
    if (['webdav', 'ftp'].includes(service)) return data.running === true && item.running && item.path_available === true && item.url ? {address:item.url} : {reason:item.path_available === false ? '目录失联或磁盘已更换，暂停发布' : data.running !== true ? '服务尚未运行' : '监听尚未就绪'};
    if (data.running !== true) return { reason: '服务尚未运行' };
    const hosts = (data.listeners || []).filter((entry) => entry.address && !['0.0.0.0', '::'].includes(entry.address));
    const host = data.connection_host || hosts[0]?.address;
    if (!host) return { reason: '尚未返回可连接的监听地址' };
    if (item.path_available === false) return { reason: '目录失联或磁盘已更换，暂停发布' };
    if (item.published === false) return { reason: '发布目录尚未就绪' };
    if (service === 'samba') return { address: `smb://${host.includes(':') ? `[${host}]` : host}/${encodeURIComponent(item.name)}`, extra: host.includes(':') ? '' : `\\\\${host}\\${item.name}` };
    const published = item.publish_path || item.path;
    return { address: `${host.includes(':') ? `[${host}]` : host}:${published}`, extra: `mount -t nfs '${host.includes(':') ? `[${host}]` : host}:${published.replace(/'/g, "'\\''")}' /本地挂载点` };
  }

  function sharedDirectoryMarkup() {
    const entries = [
      ...state.data.samba.shares.map((item) => ({ item, protocol: 'samba', kind: 'samba-share' })),
      ...state.data.nfs.exports.map((item) => ({ item, protocol: 'nfs', kind: 'nfs-export' })),
      ...(state.data.webdav.shares || []).map((item) => ({item, protocol:'webdav',kind:'webdav-share'})),
      ...state.data.ftp.shares.map((item) => ({item, protocol:'ftp',kind:'ftp-share'}))
    ].filter(({ item, protocol }) => (state.filter === 'all' || state.filter === protocol) && matchesQuery([item.name, item.path, item.clients, item.note, (item.allowed_users || []).join(' ')]));
    const rows = entries.map(({ item, protocol, kind }) => {
      const nfs = protocol === 'nfs';
      const link = connection(item, protocol);
      const readOnly = nfs ? /(^|,)ro(,|$)/.test(item.options) : item.read_only;
      return `<tr data-file-row="${escapeHtml(`${protocol}:${item.id}`)}"><td><strong>${escapeHtml(item.name || item.path.split('/').filter(Boolean).pop() || item.path)}</strong><small class="file-service-path">${escapeHtml(item.path)}</small></td><td>${nfs ? 'NFS' : protocol === 'webdav' ? 'WebDAV' : protocol === 'ftp' ? 'FTP' : 'SMB'}</td><td>${entryStatus(item.enabled)}<small class="file-service-path">${escapeHtml(state.errors[protocol] ? '上次读取结果' : protocol === 'ftp' ? item.path_available === false ? '目录不可用，暂停发布' : item.running ? '运行中' : '未发布' : serviceStatusText(state.data[protocol]))}</small></td><td>${readOnly ? '只读' : '读写'}<small class="file-service-path">${escapeHtml(nfs ? (item.clients === '*' ? '所有客户端（*）' : item.clients || '未返回访问范围') : (item.guest_access ? '允许访客' : (['webdav','ftp'].includes(protocol) ? (item.users || []).map(u=>state.data.accounts.items.find(a=>a.id===u.account_id)?.login || u.account_id).join('、') : (item.allowed_users.join('、') || '已认证协议用户'))))}</small></td><td>${link.address ? `<button type="button" class="policy-secondary" data-file-copy="${escapeHtml(link.address)}">复制地址</button><code class="file-service-path">${escapeHtml(link.address)}</code>${link.extra ? `<button class="file-service-link" type="button" data-file-copy="${escapeHtml(link.extra)}">${nfs ? '复制挂载命令' : '复制 Windows 地址'}</button>` : ''}` : escapeHtml(link.reason)}</td><td>${rowAction(kind, item)}</td></tr>`;
    });
    const failures = ['samba', 'nfs', 'webdav', 'ftp'].filter((service) => state.errors[service]).map((service) => `${service.toUpperCase()}：${state.errors[service]}`).join('；');
    return `<section class="file-service-main-surface file-service-table-card dwrt-kit-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar"><strong>共享目录</strong><span class="dwrt-kit-table-count">${rows.length} 条</span><div class="file-service-table-actions"><label><span class="file-service-sr-only">筛选协议</span><select data-file-filter><option value="all" ${state.filter === 'all' ? 'selected' : ''}>全部协议</option><option value="samba" ${state.filter === 'samba' ? 'selected' : ''}>SMB</option><option value="nfs" ${state.filter === 'nfs' ? 'selected' : ''}>NFS</option><option value="webdav" ${state.filter === 'webdav' ? 'selected' : ''}>WebDAV</option><option value="ftp" ${state.filter === 'ftp' ? 'selected' : ''}>FTP</option></select></label><input type="search" data-file-search value="${escapeHtml(state.query)}" aria-label="搜索共享" placeholder="搜索名称或路径"><button class="policy-secondary" type="button" data-file-refresh ${state.refreshing ? 'disabled' : ''}>刷新</button><button class="policy-primary" type="button" data-file-new="samba" ${capability('samba', 'shares') ? '' : 'disabled'}>新建 SMB</button><button class="policy-secondary" type="button" data-file-new="nfs" ${capability('nfs', 'exports') ? '' : 'disabled'}>新建 NFS</button><button class="policy-secondary" type="button" data-file-new="webdav" ${capability('webdav','shares') ? '' : 'disabled'}>新建 WebDAV</button><button class="policy-secondary" type="button" data-file-new="ftp" ${capability('ftp','shares') ? '' : 'disabled'}>新建 FTP</button>${state.data.operations.capabilities?.manage ? `<button class="policy-secondary" type="button" data-file-batch-new ${capability('operations','manage') ? '' : 'disabled'}>多协议共享</button><button class="policy-secondary" type="button" data-file-operation-history>操作记录</button>` : ''}</div></div>${failures ? `<div class="file-service-capability is-inline" role="status">${escapeHtml(failures)}；其余协议仍可查看。</div>` : ''}<div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table file-service-table file-service-unified-table"><thead><tr>${['名称与目录', '协议', '状态', '访问权限', '连接', '操作'].map((title) => `<th>${title}</th>`).join('')}</tr></thead><tbody>${rows.join('') || `<tr><td colspan="6" class="dwrt-kit-table-empty">${state.loading && !state.loaded ? '正在读取共享' : failures ? '部分协议读取失败，不能判断完整共享列表' : state.query ? '没有匹配的共享' : '尚未配置共享目录'}</td></tr>`}</tbody></table></div></section>`;
  }

  function protocolServiceMarkup() {
    return `<div class="file-service-protocols"><div class="file-service-protocol-list">${[...TABS, ...LATER_PROTOCOLS].map(([id, label]) => {
      const service = state.data[id];
      const configured = service.source && !['safe_defaults', 'unconfigured'].includes(service.source);
      return `<button data-dwrt-component="button" class="dwrt-kit-button ${state.tab === id && !state.accountsView ? 'is-active' : ''}" type="button" data-file-protocol="${id}"><strong>${label}</strong><span>${escapeHtml(state.errors[id] ? '读取失败' : serviceStatusText(service))}</span><small>${configured ? `自启：${service.enabled == null ? '未知' : service.enabled ? '开启' : '关闭'}` : '尚未配置'}</small></button>`;
    }).join('')}<button data-dwrt-component="button" class="dwrt-kit-button ${state.accountsView ? 'is-active' : ''}" type="button" data-file-accounts><strong>共享账号</strong><span>${state.errors.accounts ? '读取失败' : `${state.data.accounts.items.length} 个账号`}</span><small>独立于管理账号</small></button></div>${state.accountsView ? accountsMarkup() : `${state.errors[state.tab] ? `<div class="file-service-capability">${escapeHtml(state.errors[state.tab])}；以下为上次读取结果。</div>` : ''}${['safe_defaults', 'unconfigured'].includes(state.data[state.tab].source) ? '<div class="file-service-capability">尚未配置：以下仅为默认建议值，不代表已保存或正在运行的设置。</div>' : ''}<div class="file-service-protocol-toolbar">${segmentedMarkup()}<button class="policy-secondary" type="button" data-file-refresh>刷新</button>${(['samba', 'nfs', 'ftp'].includes(state.tab) || (state.tab==='webdav' && state.data.webdav.config_source!=='config_db')) ? `<button class="policy-secondary" type="button" data-file-settings="${state.tab}">查看设置</button>` : ''}</div>${serviceControlsMarkup()}<div class="file-service-protocol-detail">${LATER_PROTOCOLS.some(([id]) => id === state.tab) ? optionalProtocolMarkup() : state.tab === 'nfs' ? renderNfs() : state.tab === 'samba' ? renderSamba() : state.tab === 'webdav' ? renderWebdav() : renderFtp()}</div>`}</div>`;
  }

  function optionalProtocolMarkup() {
    const data = state.data[state.tab];
    const descriptions = {sftp:'受限共享身份与根目录隔离尚未接入。SSH 运行状态不代表共享可用。', dlna:'媒体目录、类型与重扫管理尚未接入；DLNA 不使用用户密码授权。', afp:'AFP 目录同步与权限管理尚未接入。'};
    return `<section class="file-service-settings-surface dwrt-kit-glass-surface"><p class="file-service-path">${state.tab.toUpperCase()} 组件：${data.available == null ? '未能读取' : data.available ? '已安装' : '未安装'}</p><p class="file-service-path">依赖进程：${data.dependency_running == null ? '未知' : data.dependency_running ? '已探测到' : '未探测到'}</p><p class="file-service-path">${descriptions[state.tab]}</p></section>`;
  }

  function accountsMarkup() {
    const data = state.data.accounts;
    const rows = data.items.filter((item) => matchesQuery([item.username, item.label, item.login])).map((item) => `<tr><td><strong>${escapeHtml(item.label || item.username)}</strong><small class="file-service-path">${escapeHtml(item.username)}</small></td><td><code>${escapeHtml(item.login)}</code></td><td>${entryStatus(item.enabled)}<small class="file-service-path">${item.identity_ready ? '身份就绪' : '系统身份待修复'}</small></td><td>${item.samba_account_present === true ? 'SMB 账号已配置' : item.samba_account_present === false ? 'SMB 账号缺失' : 'SMB 状态未知'}</td><td>${escapeHtml((item.references || []).map((ref) => ref.name || ref.id).join('、') || '未引用')}</td><td>${rowAction('share-account', item)}</td></tr>`);
    return `<section class="file-service-main-surface file-service-accounts-card file-service-table-card dwrt-kit-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar"><strong>共享账号</strong><span class="dwrt-kit-table-count">${rows.length} 个</span><div class="file-service-table-actions"><input type="search" data-file-search aria-label="搜索共享账号" placeholder="搜索账号" value="${escapeHtml(state.query)}"><button class="policy-secondary" type="button" data-file-refresh>刷新</button><button class="policy-primary" type="button" data-file-account-new ${capability('accounts', 'manage') ? '' : 'disabled'}>新建账号</button></div></div><div class="file-service-account-note">共享账号仅用于文件访问；SMB、受管 WebDAV 与 FTP 共用专用账号凭据。客户端使用“登录名”，共享目录另行授权。${capability('accounts', 'manage') ? '' : '账号管理需要设备所有者权限和账号组件。'}${state.errors.accounts ? `<p>${escapeHtml(state.errors.accounts)}</p>` : ''}</div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table file-service-table"><thead><tr><th>账号</th><th>登录名</th><th>状态</th><th>协议凭据</th><th>引用共享</th><th>操作</th></tr></thead><tbody>${rows.join('') || `<tr><td colspan="6" class="dwrt-kit-table-empty">${state.errors.accounts ? '无法确认账号列表' : '尚无专用共享账号'}</td></tr>`}</tbody></table></div></section>`;
  }

  function shareSubjectsMarkup() {
    const selected = String(state.editor.allowed_users || '').split(',').map((v) => v.trim());
    return `<div class="file-service-form">${state.data.accounts.items.map((item) => `<label class="file-service-field is-wide"><span><input type="checkbox" data-file-subject="${escapeHtml(item.login)}" ${selected.includes(item.login) ? 'checked' : ''}> ${escapeHtml(item.label || item.username)} · ${escapeHtml(item.login)}</span><small>${item.enabled ? '已启用' : '已停用'} · ${item.identity_ready && item.samba_account_present ? 'SMB 凭据已配置' : '凭据或身份待确认'}</small></label>`).join('')}</div>`;
  }

  function serviceControlsMarkup() {
    const service = state.data[state.tab];
    if (!['samba', 'nfs', 'webdav', 'ftp'].includes(state.tab) || (state.tab==='webdav' && !service.capabilities?.actions)) return '';
    const writable = capability(state.tab, 'actions') && Number.isSafeInteger(service.control_revision);
    const disabled = !writable || state.actionBusy || Boolean(state.drawer);
    const listeners = (service.listeners || []).map((item) => `${item.address}:${item.port}/${item.transport}`).join('、');
    const actions = [['start','启动'],['stop','停止'],['restart','重启']];
    return `<section class="file-service-control" aria-label="服务控制"><div class="file-service-protocol-toolbar">${actions.map(([action,label]) => `<button type="button" class="policy-secondary" data-file-action="${action}" ${disabled ? 'disabled' : ''}>${label}</button>`).join('')}<span>开机自启：${service.enabled == null ? '未知' : service.enabled ? '开启' : '关闭'}</span><button type="button" class="policy-secondary" data-file-action="${service.enabled ? 'disable' : 'enable'}" ${disabled || !capability(state.tab, 'autostart') || service.enabled == null ? 'disabled' : ''}>${service.enabled ? '关闭自启' : '开启自启'}</button></div><small class="file-service-path">${escapeHtml(listeners || (service.listeners_known ? '未检测到监听' : '监听地址尚未确认'))} · 启停不改变开机自启</small>${service.last_error ? `<p role="status">${escapeHtml(REASON_TEXT[service.last_error] || service.last_error)}</p>` : ''}${!writable ? '<small class="file-service-path">当前会话或后端未开放服务控制</small>' : ''}</section>`;
  }

  async function serviceAction(action) {
    const service = state.tab, current = state.data[service];
    if (state.actionBusy || state.drawer || !capability(service, 'actions')) return;
    if (['stop', 'restart'].includes(action) && !window.confirm(`${action === 'stop' ? '停止' : '重启'} ${service.toUpperCase()} 会中断此协议的文件连接，继续？`)) return;
    state.actionBusy = true; state.notice = ''; render();
    try {
      const result = await requestJson(`${ENDPOINTS[service]}/actions`, {method: 'POST', body: JSON.stringify({confirm: true, expected_revision: current.control_revision, action})});
      const canonical = await canonicalRecord(service, service);
      const key = ['enable','disable'].includes(action) ? 'enabled' : 'running';
      const expected = !['stop','disable'].includes(action);
      const waitingForDirectory = service === 'ftp' && ['start','restart'].includes(action) && canonical.requested_running === true && canonical.running === false;
      if (result.applied !== true || (canonical[key] !== expected && !waitingForDirectory)) throw new Error('操作已受理，但回读状态尚未确认');
      if (waitingForDirectory) { state.notice = 'FTP 已请求启动，等待可发布目录；当前未监听'; state.noticeTone = 'warning'; return; }
      state.notice = `${service.toUpperCase()} ${ {start:'已启动',stop:'已停止',restart:'已重启',enable:'已开启自启',disable:'已关闭自启'}[action] }，回读一致`;
      state.noticeTone = 'ok';
    } catch (error) {
      state.notice = `操作未完成：${errorMessage(error)}`; state.noticeTone = 'error';
      try { await canonicalRecord(service, service); } catch (_) {}
    } finally { if (state.mounted) { state.actionBusy = false; render(); } }
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
        detailRow('开机自启', service.enabled == null ? '未知' : service.enabled ? '开启' : '关闭'),
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
    if (service.config_source === 'config_db') return `<section class="file-service-main-surface"><div class="file-service-protocol-toolbar"><strong>WebDAV 共享</strong><button class="policy-primary" type="button" data-file-new="webdav" ${capability('webdav','shares')?'':'disabled'}>添加共享</button></div><p>每个共享使用独立地址和账号授权。服务停止时，保存配置后需点击启动。</p>${!capability('webdav','shares')?`<p class="file-service-capability">${escapeHtml(capabilityNotice('WebDAV 共享目录','webdav','shares'))}</p>`:''}<div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table"><thead><tr><th>名称与目录</th><th>访问</th><th>连接</th><th>操作</th></tr></thead><tbody>${(service.shares || []).map(item=>{const link=connection(item,'webdav');return `<tr><td>${escapeHtml(item.name)}<small class="file-service-path">${escapeHtml(item.path)}</small></td><td>${item.read_only?'只读':'读写'} · ${item.running?'运行中':'未运行'}</td><td>${escapeHtml(link.address || link.reason)}</td><td>${rowAction('webdav-share',item)}</td></tr>`;}).join('') || '<tr><td colspan="4">尚未配置 WebDAV 共享</td></tr>'}</tbody></table></div></section>`;
    const auth = service.username || service.has_password ? (service.username || '已配置身份验证') : '未启用';
    const protocol = service.ssl ? 'HTTPS' : 'HTTP';
    return settingsSurface('WebDAV', '基于 NGINX 实现的轻量 WebDAV 文件访问服务。', serviceStatus(service), [
      detailRow('开机自启', service.enabled == null ? '未知' : service.enabled ? '开启' : '关闭'),
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
    if (state.ftpView === 'shares') {
      const rows = service.shares.filter(item => matchesQuery([item.name, item.path, item.note])).map(item => {
        const link = connection(item, 'ftp');
        return `<tr><td>${entryStatus(item.enabled)}</td><td><strong>${escapeHtml(item.name)}</strong><small class="file-service-path">${escapeHtml(item.path)}</small></td><td>${item.read_only ? '只读' : '读写'}</td><td>${escapeHtml(link.address || link.reason)}<small class="file-service-path">${item.tls_mode === 'explicit_required' ? '显式 FTPS，控制与数据加密' : 'FTP'}</small></td><td>${rowAction('ftp-share', item)}</td></tr>`;
      });
      return tableMarkup('FTP 共享目录', '每个账号只能访问获授权目录；共享只读优先于账号写权限。', ['状态', '名称与目录', '权限', '连接', '操作'], rows, '尚无 FTP 共享目录');
    }
    return settingsSurface('FTP', '使用独立共享账号和逐用户目录。匿名与普通系统账号登录固定关闭。', serviceStatus(service), [
      detailRow('配置', service.settings ? '已保存' : '尚未配置'),
      detailRow('本机监听地址', service.settings ? `${service.listen_address}:${service.listen_port}` : '未配置', {code:true}),
      detailRow('被动端口', service.settings ? `${service.passive_min_port}–${service.passive_max_port}` : '未配置'),
      detailRow('被动地址', service.settings ? service.passive_address || '使用本机监听地址' : '未配置'),
      detailRow('访问账号', '独立共享账号，目录内逐项授权'),
      detailRow('TLS', service.settings ? service.tls ? '显式 FTPS，强制控制与数据加密' : '未启用' : '未配置'),
      ...(service.settings && service.tls ? [detailRow('证书路径', service.cert_file, {code:true}), detailRow('私钥路径', service.key_file, {code:true})] : []),
      detailRow('本次运行意图', service.requested_running == null ? '未知' : service.requested_running ? service.running ? '已启动' : '等待可发布目录' : '已停止')
    ]);
  }

  function mainSurfaceMarkup() {
    return state.page === 'shares' ? sharedDirectoryMarkup() : protocolServiceMarkup();
  }

  function switchField(label, description, path, checked) {
    return `<label class="file-service-switch-row"><span><strong>${escapeHtml(label)}</strong><small>${escapeHtml(description)}</small></span><span class="file-service-switch dwrt-kit-switch" data-dwrt-component="switch"><input type="checkbox" data-file-draft="${escapeHtml(path)}" ${checked ? 'checked' : ''}></span></label>`;
  }

  function field(label, path, value, options = {}) {
    const type = options.type || 'text';
    const input = options.options
      ? `<select data-file-draft="${escapeHtml(path)}">${options.options.map(([id, text]) => `<option value="${escapeHtml(id)}" ${String(value) === String(id) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select>`
      : `<input type="${escapeHtml(type)}" data-file-draft="${escapeHtml(path)}" value="${type === 'password' ? '' : escapeHtml(value ?? '')}" placeholder="${escapeHtml(options.placeholder || '')}" ${options.min !== undefined ? `min="${escapeHtml(options.min)}"` : ''} ${options.max !== undefined ? `max="${escapeHtml(options.max)}"` : ''}>`;
    return `<label class="file-service-field ${options.wide ? 'is-wide' : ''}"><span>${escapeHtml(label)}</span>${input}${options.help ? `<small>${escapeHtml(options.help)}</small>` : ''}</label>`;
  }

  function editorCapability() {
    const [service, action] = editorCapabilityPath();
    return service ? capability(service, action) && (!['samba','nfs'].includes(state.drawer) || Array.isArray(state.data[state.drawer].settings_fields)) : false;
  }

  /* 抽屉 -> 能力位。每个抽屉只认自己那一位，绝不用一个能力位控制整页禁写。 */
  function editorCapabilityPath() {
    const map = {
      'share-account': ['accounts', 'manage'],
      'share-batch': ['operations', 'manage'],
      'nfs-export': ['nfs', 'exports'],
      'nfs-mount': ['nfs', 'mounts'],
      nfs: ['nfs', 'settings'],
      samba: ['samba', 'settings'],
      'samba-share': ['samba', 'shares'],
      'webdav-share': ['webdav', 'shares'],
      webdav: ['webdav', 'settings'],
      ftp: ['ftp', 'settings'],
      'ftp-share': ['ftp', 'shares']
    };
    return map[state.drawer] || ['', ''];
  }

  function editorCapabilityNotice() {
    const [service, action] = editorCapabilityPath();
    if (!service) return '';
    return capabilityNotice(CAPABILITY_SUBJECT[state.drawer] || '该配置', service, action);
  }

  function drawerTitle() {
    if (state.drawer === 'share-batch') return '多协议共享';
    if (state.drawer === 'share-history') return '多协议操作记录';
    if (state.drawer === 'share-account') return state.editor._new ? '新建共享账号' : '编辑共享账号';
    if (state.drawer === 'nfs-export') return state.editor._new ? '添加 NFS 共享' : '编辑 NFS 共享';
    if (state.drawer === 'nfs-mount') return state.editor._new ? '添加远程挂载' : '编辑远程挂载';
    if (state.drawer === 'nfs') return 'NFS 新建默认策略';
    if (state.drawer === 'samba') return 'Samba 设置';
    if (state.drawer === 'samba-share') return state.editor._new ? '添加 Samba 共享' : '编辑 Samba 共享';
    if (state.drawer === 'webdav-share') return state.editor._new ? '添加 WebDAV 共享' : '编辑 WebDAV 共享';
    if (state.drawer === 'webdav') return 'WebDAV 设置';
    if (state.drawer === 'ftp') return 'FTP 设置';
    if (state.drawer === 'ftp-share') return state.editor._new ? '添加 FTP 共享' : '编辑 FTP 共享';
    return '';
  }

  function bindingFields(editor) {
    if (editor._new) return '';
    const address = state.drawer === 'nfs-export' && editor.publish_path ? `<p class="file-service-path">客户端发布路径：${escapeHtml(editor.publish_path)}。旧挂载地址需更新。</p>` : '';
    return address + (editor.path_available === false ? switchField('使用当前磁盘重新绑定', '确认当前磁盘和目录正确后勾选；也可停用或删除共享，目录内文件会保留。', 'rebind', editor.rebind) : '');
  }

  function drawerFields() {
    const editor = state.editor;
    if (state.drawer === 'share-account') return `${switchField('启用账号', '停用会撤销 SMB、WebDAV 和 FTP 授权并重建相关连接', 'enabled', editor.enabled)}<div class="file-service-form">${editor._new ? field('账号名称', 'username', editor.username, {wide:true,help:'1–24 位小写字母、数字或下划线，以字母开头；登录名会加 dwshare_ 前缀。'}) : `<p class="file-service-path">登录名：${escapeHtml(editor.login)}（不可更改）</p>`}${field('显示名称', 'label', editor.label, {wide:true})}${field('密码', 'password', '', {type:'password',wide:true,placeholder:editor._new ? '设置密码' : '留空保持原密码',help:'12–128 字节；不会回显保存的密码。'})}</div><p class="file-service-path">${escapeHtml((editor.references || []).map((ref) => ref.name || ref.id).join('、') || '尚未被共享引用')}。删除账号前需先移除共享授权；改密或禁用会重置 SMB、WebDAV 和 FTP 连接。</p>`;
    if (state.drawer === 'nfs-export') return `${bindingFields(editor)}${switchField('启用共享', '停用后保留配置，但不再导出目录', 'enabled', editor.enabled)}<div class="file-service-form">${field('共享路径', 'path', editor.path, { wide: true, placeholder: '/mnt/storage' })}${field('允许的客户端', 'clients', editor.clients, { wide: true, placeholder: '192.168.30.0/24 或 *', help: '支持主机、网段或 *；多个范围由后端按 NFS 规则解析。' })}${field('导出选项', 'options', editor.options, { wide: true, placeholder: 'rw,sync,root_squash,no_subtree_check', help: '原样保留高级选项；ro/rw 控制读写，root_squash 控制远端 root 映射。' })}${field('备注', 'note', editor.note, { wide: true })}</div>`;
    if (state.drawer === 'nfs-mount') return `${switchField('启用挂载', '启用后按配置挂载远程 NFS 目录', 'enabled', editor.enabled)}<div class="file-service-form">${field('源目录', 'source', editor.source, { wide: true, placeholder: '192.168.30.3:/volume1/share' })}${field('挂载到', 'target', editor.target, { wide: true, placeholder: '/mnt/remote-share' })}${field('挂载选项', 'options', editor.options, { wide: true, placeholder: 'rw,soft,timeo=30' })}${field('延迟时间（秒）', 'delay', editor.delay, { type: 'number', min: 0, max: 3600 })}</div>`;
    if (state.drawer === 'nfs') return `<p class="file-service-capability">仅预填下次新建 NFS 共享的表单。已配置的 ${state.data.nfs.exports.length} 个导出及正在运行的服务保持原配置。</p><div class="file-service-form">${field('默认客户端范围','default_clients',editor.default_clients,{wide:true,help:'留空时每次新建需填写；* 代表所有客户端。'})}${field('默认导出选项','default_options',editor.default_options,{wide:true,help:'支持现有高级选项；新建前仍可逐项修改。'})}</div>`;
    if (state.drawer === 'samba') return `<p class="file-service-capability">此设置影响 ${state.data.samba.shares.length} 个共享。保存会应用到当前运行的服务；服务停止时只保存配置。开机自启在协议服务页单独操作。</p><div class="file-service-form">${field('工作组', 'workgroup', editor.workgroup, {placeholder:'WORKGROUP'})}${field('服务器描述', 'server_description', editor.server_description)}${field('监听接口', 'interfaces', Array.isArray(editor.interfaces) ? editor.interfaces.join(', ') : editor.interfaces, {wide:true,help:'明确填写 OpenWrt 逻辑接口，多个接口用逗号分隔。'})}${['min_protocol','max_protocol'].every(k=>state.data.samba.settings_fields?.includes(k)) ? ['min_protocol','max_protocol'].map((key,i)=>field(i?'最高 SMB 协议':'最低 SMB 协议',key,editor[key],{options:['SMB2','SMB2_02','SMB2_10','SMB3','SMB3_00','SMB3_02','SMB3_11'].map(v=>[v,v])})).join('') : '<p>当前组件仅支持 SMB2+ 基线，协议版本不可编辑。</p>'}</div>${state.data.samba.settings_fields?.includes('guest_access')?switchField('允许来宾（全局）','关闭会拒绝所有共享的来宾访问；开启后仍需逐共享允许','guest_access',editor.guest_access):''}`;
    if (state.drawer === 'share-history') return '';
    if (state.drawer === 'share-batch') return batchFields();
    if (state.drawer === 'webdav-share') return bindingFields(editor) + webdavFields();
    if (state.drawer === 'samba-share') return `${bindingFields(editor)}${switchField('启用共享', '停用后保留配置，但不发布该共享', 'enabled', editor.enabled)}${switchField('只读', '禁止客户端上传、修改和删除文件', 'read_only', editor.read_only)}${switchField('可浏览', '允许客户端枚举该共享', 'browseable', editor.browseable)}${switchField('网络发现', '发布共享发现信息', 'network_discovery', editor.network_discovery)}${switchField('访客访问', '允许未登录客户端访问该共享', 'guest_access', editor.guest_access)}<div class="file-service-form">${field('共享名称', 'name', editor.name, { wide: true, placeholder: '例如 Public' })}${field('共享路径', 'path', editor.path, { wide: true, placeholder: '/mnt/storage/public' })}${field('允许用户', 'allowed_users', Array.isArray(editor.allowed_users) ? editor.allowed_users.join(', ') : editor.allowed_users, { wide: true, placeholder: 'lester, backup', help: '选择下方专用账号或填写已有 SMB 登录名；私有共享必须明确授权用户。'  })}${field('只读用户', 'read_only_users', Array.isArray(editor.read_only_users) ? editor.read_only_users.join(', ') : editor.read_only_users, {wide:true,help:'填写允许用户中的登录名；这些用户始终只读。共享的只读开关对所有用户优先生效。'})}${field('备注', 'note', editor.note, { wide: true })}</div><p class="file-service-path">${escapeHtml(state.data.samba.subjects_known ? `SMB 账户记录：${(state.data.samba.subjects || []).map((entry) => entry.username).join('、') || '无'}。账户存在不代表密码有效或已启用。` : '共享账户状态未能读取；请先确认现有系统用户的 SMB 凭据。')}</p>${shareSubjectsMarkup()}`;
    if (state.drawer === 'webdav') return `${switchField('启用 WebDAV', '启动基于 NGINX 的 WebDAV 服务', 'enabled', editor.enabled)}${switchField('只读模式', '禁止客户端上传、修改和删除文件', 'read_only', editor.read_only)}${switchField('打开防火墙端口', '自动放行所配置的监听端口', 'open_firewall', editor.open_firewall)}${switchField('启用 SSL', '使用证书提供 HTTPS 访问', 'ssl', editor.ssl)}<div class="file-service-form">${field('监听端口', 'listen_port', editor.listen_port, { type: 'number', min: 1, max: 65535 })}${field('用户名', 'username', editor.username, { placeholder: '留空禁用身份验证' })}${field('密码', 'password', '', { type: 'password', placeholder: editor.has_password ? '留空保持现有密码' : '留空禁用身份验证', help: '后端不得回显已保存密码。' })}${field('WebDAV 目录', 'root_dir', editor.root_dir, { wide: true, placeholder: '/mnt' })}${editor.ssl ? `${field('SSL 证书', 'cert_file', editor.cert_file, { wide: true, placeholder: '/etc/ssl/certs/webdav.crt' })}${field('SSL 密钥', 'key_file', editor.key_file, { wide: true, placeholder: '/etc/ssl/private/webdav.key' })}` : ''}</div>`;
    if (state.drawer === 'ftp') return ftpSettingsFields();
    if (state.drawer === 'ftp-share') return bindingFields(editor) + ftpShareFields();
    return '';
  }

  function nfsChoicesMarkup() {
    const options = String(state.editor.options || '').split(',');
    return `<div class="file-service-form">${[['access','读写',['ro','rw']],['sync','写入确认',['sync','async']],['root','远端 root',['root_squash','no_root_squash']]].map(([id,label,choices]) => `<label class="file-service-field"><span>${label}</span><select data-file-nfs-choice="${id}"><option value="">保留当前选项</option>${choices.map((value) => `<option value="${value}" ${options.includes(value) ? 'selected' : ''}>${value}</option>`).join('')}</select></label>`).join('')}</div>`;
  }

  function directoryPickerMarkup() {
    if (!['samba-share', 'nfs-export', 'webdav-share', 'ftp-share', 'share-batch'].includes(state.drawer)) return '';
    const p = state.picker;
    if (!p) return '<button class="policy-secondary" type="button" data-file-directory-open>浏览本机目录</button>';
    const base = p.roots?.find((root) => root.id === p.rootId)?.path || '/';
    const parent = p.path?.replace(/\/[^/]+\/?$/, '') || '/';
    const entries = (p.entries || []).filter((entry) => (entry.is_dir || ['directory','dir'].includes(entry.kind || entry.type)) && !entry.is_symlink);
    return `<section class="file-service-picker" aria-label="选择共享目录"><div class="file-service-protocol-toolbar"><select aria-label="存储根目录" data-file-directory-root ${p.loading ? 'disabled' : ''}>${(p.roots || []).map((root) => `<option value="${escapeHtml(root.id)}" ${root.id === p.rootId ? 'selected' : ''}>${escapeHtml(root.label || root.path)}</option>`).join('')}</select><button type="button" class="policy-secondary" data-file-directory-path="${escapeHtml(parent)}" ${p.loading || p.path === base ? 'disabled' : ''}>上级</button><button type="button" class="policy-secondary" data-file-directory-close>收起</button></div><code>${escapeHtml(p.path || '')}</code><div class="file-service-picker-list">${p.loading ? '正在读取目录' : p.error ? escapeHtml(p.error) : entries.map((entry) => `<button type="button" class="file-service-link" data-file-directory-path="${escapeHtml(entry.path)}">${escapeHtml(entry.name)}</button>`).join('') || '没有子目录'}</div><button type="button" class="policy-secondary" data-file-directory-use ${p.loading || p.error || !p.path || p.path === '/' ? 'disabled' : ''}>选择此目录</button></section>`;
  }

  async function browseDirectory(path = '/', rootId = '') {
    const previous = state.picker || {}, roots = previous.roots || [];
    const root = roots.find((item) => item.id === rootId);
    const target = root?.path === '/' && path !== '/' ? `//${path.replace(/^\/+/, '')}` : path;
    const pending = {path, rootId, roots, entries: [], loading: true};
    state.picker = pending; renderDrawer();
    try {
      const payload = await requestJson(`/api/v1/storage/files?path=${encodeURIComponent(target)}${rootId ? `&root_id=${encodeURIComponent(rootId)}` : ''}`);
      if (!state.mounted || state.picker !== pending || !state.drawer) return;
      const data = payload.files || payload;
      Object.assign(pending, {path: String(data.path || path).replace(/\/+/g, '/'), rootId: data.root_id || rootId, roots: data.roots || roots, entries: data.entries || []});
    } catch (error) { if (state.picker === pending) pending.error = errorMessage(error); }
    finally { if (state.mounted && state.picker === pending && state.drawer) { pending.loading = false; renderDrawer(); } }
  }

  function dirty() {
    return Boolean(state.drawer) && (state.pendingWrite || JSON.stringify(state.editor) !== JSON.stringify(state.baseline));
  }

  function savebarMarkup() {
    return (ui.floatingSavebarMarkup || window.DWRT_UI_KIT?.floatingSavebarMarkup)?.({
      visible: Boolean(dirty()) && editorCapability() && !state.batchResult, busy: state.saving,
      message: state.pendingWrite ? '写入已接受，等待回读确认' : '共享配置有未保存的更改',
      saveLabel: state.pendingWrite ? '重新回读' : (state.drawer === 'nfs' || (state.drawer === 'samba' && state.data.samba.running !== true) || (state.drawer === 'webdav-share' && state.data.webdav.running !== true) || (['ftp', 'ftp-share'].includes(state.drawer) && state.data.ftp.running !== true)) ? '保存配置' : '保存并应用'
    }) || '';
  }

  function syncSavebar() {
    const slot = layer.querySelector('[data-file-savebar]') || document.querySelector('[data-file-overlay-owned] [data-file-savebar]');
    if (slot) slot.innerHTML = savebarMarkup();
  }

  function drawerMarkup() {
    if (!state.drawer) return '';
    const writable = editorCapability();
    const canDelete = !state.editor._new && ['nfs-export', 'nfs-mount', 'samba-share', 'webdav-share', 'ftp-share', 'share-account'].includes(state.drawer) && writable;
    return `<button class="dwrt-kit-sheet-overlay is-open" data-file-overlay-owned type="button" data-file-close aria-label="关闭文件服务设置"></button><aside data-file-overlay-owned data-dwrt-component="sheet" class="file-service-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" aria-label="${escapeHtml(drawerTitle())}"><header class="dwrt-kit-sheet-header"><div><span>FILE SERVICES</span><strong>${escapeHtml(drawerTitle())}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-file-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body file-service-drawer-body"><fieldset class="file-service-fields" ${writable && !state.saving && !state.pendingWrite && !state.batchRequest ? '' : 'disabled'}>${drawerFields()}${state.drawer === 'nfs-export' ? nfsChoicesMarkup() : ''}${directoryPickerMarkup()}</fieldset>${state.drawer === 'share-batch' && state.batchResult ? operationResultMarkup(state.batchResult) : ''}${state.drawer === 'share-history' ? state.operationHistory.map(operationResultMarkup).join('') || '<p>暂无多协议操作记录</p>' : ''}${state.conflict ? `<div class="file-service-capability">服务器版本 ${escapeHtml(state.conflict.revision || '未知')} 已变化；草稿与原版本保留。<button type="button" class="policy-secondary" data-file-use-current>放弃草稿并载入当前版本</button><pre>${escapeHtml(JSON.stringify(state.conflict, null, 2))}</pre></div>` : ''}${state.confirmDelete ? `<div class="file-service-capability">${state.drawer === 'share-account' ? '删除专用账号及其协议凭据；有共享引用时会拒绝删除。目录和文件保留。' : '仅撤销本协议的共享配置，目录和文件会保留。'}</div>` : ''}${!writable && state.drawer !== 'share-history' ? `<div class="file-service-capability">${escapeHtml(editorCapabilityNotice())}可以查看完整配置项，但不会把未保存配置写入浏览器或 /etc/config。</div>` : ''}${state.notice ? noticeMarkup() : ''}</div><footer class="dwrt-kit-sheet-footer file-service-drawer-footer">${canDelete ? `<button class="policy-secondary danger" type="button" data-file-delete ${state.saving ? 'disabled' : ''}>${state.confirmDelete ? '再次点击删除' : '删除'}</button>` : '<span></span>'}<div><button class="policy-secondary" type="button" data-file-close>取消</button></div></footer><div data-file-savebar>${savebarMarkup()}</div></aside>`;
  }

  /*
   * 轮询刷新走 kit 的共享保状态入口（Acceptance P0 单：30.1 实机 45 路由巡检，20 条路由在
   * 一个轮询周期里丢滚动 / 焦点 / 选区，根因是整树重绘）。用户主动操作仍走 render()：
   * 那时候 DOM 本来就应该变。
   *
   * render() 收一个可选目标：kit 会先让它渲进离屏容器，再按语义 key patch 回真实 DOM，
   * 未变化的节点不换身份。宿主级设置（hidden / class）仍作用在真实 root 上，因为那些是
   * 路由容器自身的状态，不属于本次要 patch 的内容。
   */
  const layer = document.createElement('div');
  layer.className = 'storage-file-services-route-host file-service-layer';
  document.body.appendChild(layer);
  let sheetKind = '';
  function clearSheet() {
    document.querySelectorAll('[data-file-overlay-owned]').forEach((node) => layer.appendChild(node));
    window.DWRT_UI_KIT?.unmount?.(layer);
    layer.replaceChildren();
    sheetKind = '';
  }
  function renderDrawer() {
    if (!state.drawer) { clearSheet(); return; }
    const sheet = document.querySelector('aside[data-file-overlay-owned]');
    const markup = document.createElement('template');
    markup.innerHTML = drawerMarkup();
    if (sheet && sheetKind === state.drawer) {
      const next = markup.content.querySelector('aside');
      const body = sheet.querySelector('.dwrt-kit-sheet-body');
      const scroll = body.scrollTop;
      body.innerHTML = next.querySelector('.dwrt-kit-sheet-body').innerHTML;
      body.scrollTop = scroll;
      sheet.querySelector('footer').innerHTML = next.querySelector('footer').innerHTML;
      sheet.querySelector('[data-file-savebar]').innerHTML = savebarMarkup();
      ui.mountAll?.(body);
    } else {
      clearSheet();
      layer.appendChild(markup.content);
      sheetKind = state.drawer;
      ui.mountAll?.(layer);
    }
    const passwordInput = document.querySelector('aside[data-file-overlay-owned] input[type="password"]');
    if (passwordInput && state.editor.password) passwordInput.value = state.editor.password;
  }
  function renderPreservingInteraction() {
    if (state.drawer) return;
    const active = document.activeElement;
    if (root.contains(active) && active.matches('input,select,textarea')) return;
    const selected = window.getSelection();
    if (selected?.toString() && root.contains(selected.anchorNode)) return;
    const positions = [...root.querySelectorAll('.dwrt-kit-table-scroll,.file-service-protocols')].map((el) => [el.scrollTop, el.scrollLeft]);
    render();
    root.querySelectorAll('.dwrt-kit-table-scroll,.file-service-protocols').forEach((el, index) => {
      if (positions[index]) [el.scrollTop, el.scrollLeft] = positions[index];
    });
  }

  function render() {
    if (!root) return;
    root.hidden = false;
    root.classList.add('route-workspace', 'policy-table-route-host', MODULE_CLASS);
    root.innerHTML = `<section class="file-service-shell ${standalone ? 'is-standalone' : ''}">${navigationMarkup()}<div class="file-service-content">${noticeMarkup()}<main class="file-service-workbench">${mainSurfaceMarkup()}</main></div></section>`;
    ui.mountAll?.(root);
    renderDrawer();
  }

  function patchMainSurface() {
    const current = root?.querySelector('.file-service-workbench');
    if (!current) { render(); return; }
    const search = current.querySelector('[data-file-search]');
    const focused = document.activeElement === search;
    const start = search?.selectionStart, end = search?.selectionEnd;
    const scroll = current.querySelector('.dwrt-kit-table-scroll');
    const offsets = [scroll?.scrollTop || 0, scroll?.scrollLeft || 0];
    current.innerHTML = mainSurfaceMarkup();
    const nextScroll = current.querySelector('.dwrt-kit-table-scroll');
    if (nextScroll) [nextScroll.scrollTop, nextScroll.scrollLeft] = offsets;
    if (focused) {
      const next = current.querySelector('[data-file-search]');
      next?.focus({ preventScroll: true });
      if (start !== null && start !== undefined) next?.setSelectionRange(start, end);
    }
    ui.mountAll?.(current);
  }

  function setEditorField(path, value) {
    if (state.editor[path] === value) return;
    state.editor[path] = value;
    syncSavebar();
  }

  function closeDrawer(force = false) {
    if (state.saving) return false;
    if (!force && dirty() && !window.confirm('有未保存或尚未确认的更改，放弃并关闭？')) return false;
    state.pendingWrite = null;
    state.batchRequest = null; state.batchResult = null;
    state.picker = null;
    state.conflict = null;
    state.drawer = '';
    state.editor = {};
    state.notice = '';
    state.noticeTone = '';
    state.confirmDelete = false;
    render();
    return true;
  }

  function openCreate() {
    state.notice = '';
    state.confirmDelete = false;
    if (state.tab === 'nfs' && state.nfsView === 'exports') {
      state.drawer = 'nfs-export';
      state.editor = { _new: true, enabled: true, path: '', clients: state.data.nfs.default_clients || '', options: state.data.nfs.default_options || 'ro,sync,root_squash,no_subtree_check', note: '' };
    } else if (state.tab === 'nfs') {
      state.drawer = 'nfs-mount';
      state.editor = { _new: true, enabled: true, source: '', target: '', options: 'rw', delay: 0 };
    } else if (state.tab === 'samba') {
      state.drawer = 'samba-share';
      state.editor = { _new: true, enabled: true, name: '', path: '', read_only: true, browseable: true, network_discovery: true, guest_access: false, allowed_users: [], read_only_users: [], note: '' };
    } else if (state.tab === 'webdav') {
      state.drawer='webdav-share';
      state.editor={_new:true,enabled:true,name:'',path:'',read_only:true,tls:false,listen_address:'',listen_port:5005,cert_file:'',key_file:'',users:[],note:''};
    } else if (state.tab === 'ftp') {
      state.drawer = 'ftp-share';
      state.editor = { _new: true, enabled: true, name: '', path: '', read_only: true, users: [], note: '' };
    }
    state.baseline = clone(state.editor);
    render();
  }

  function accountAccessFields(key = 'users') {
    return `<div class="file-service-form">${state.data.accounts.items.map(account => {
      const access = (state.editor[key] || []).find(item => item.account_id === account.id);
      return `<label class="file-service-field"><span>${escapeHtml(account.label || account.username)} · ${escapeHtml(account.login)}${account.enabled ? '' : '（已停用）'}</span><select data-file-account-access="${escapeHtml(account.id)}" data-file-access-field="${key}"><option value="none" ${!access ? 'selected' : ''}>不允许</option><option value="ro" ${access?.read_only ? 'selected' : ''}>只读</option><option value="rw" ${access && !access.read_only ? 'selected' : ''}>读写</option></select></label>`;
    }).join('') || '<p>请先由设备所有者在协议服务中创建共享账号。</p>'}</div>`;
  }

  function ftpShareFields() {
    const e = state.editor;
    return `${switchField('启用共享','服务运行且目录可用时发布','enabled',e.enabled)}${switchField('只读','优先于账号写权限；不会更改源目录权限','read_only',e.read_only)}<div class="file-service-form">${field('共享名称','name',e.name,{wide:true,help:'1–64位字母、数字、下划线或连字符；作为客户端根目录下的目录名。'})}${field('目录','path',e.path,{wide:true,help:'目录须已有相应读写权限；删除共享会保留文件。'})}${field('备注','note',e.note,{wide:true})}</div>${accountAccessFields()}<p>客户端使用共享账号登录名。只会看到获授权的目录，停用账号会撤销现有连接。</p>`;
  }

  function ftpSettingsFields() {
    const e = state.editor;
    return `<p class="file-service-capability">此设置影响 ${state.data.ftp.shares.length} 个 FTP 共享。保存不启动已停止的服务；匿名与普通系统账号登录固定关闭。</p>${switchField('启用显式 FTPS','强制控制与数据加密；客户端需选择显式 FTP over TLS','tls',e.tls)}<div class="file-service-form">${field('本机监听地址','listen_address',e.listen_address,{wide:true,help:'填写设备已有的 IPv4 地址。'})}${field('控制端口','listen_port',e.listen_port,{type:'number',min:1,max:65535})}${field('被动端口起始','passive_min_port',e.passive_min_port,{type:'number',min:1024,max:65535})}${field('被动端口结束','passive_max_port',e.passive_max_port,{type:'number',min:1024,max:65535,help:'连续1–64个端口，不包含控制端口。'})}${field('被动地址（可选）','passive_address',e.passive_address,{wide:true,help:'留空使用本机监听地址；填写 IPv4 地址。'})}${e.tls ? `${field('证书路径','cert_file',e.cert_file,{wide:true})}${field('私钥路径','key_file',e.key_file,{wide:true})}` : ''}</div>`;
  }

  function webdavFields() {
    const e=state.editor;
    return `${switchField('启用共享','服务运行时发布此目录','enabled',e.enabled)}${switchField('只读','此限制优先于各账号的写权限','read_only',e.read_only)}${switchField('使用 HTTPS','加载设备上已有的证书和私钥','tls',e.tls)}<div class="file-service-form">${field('共享名称','name',e.name,{wide:true})}${field('目录','path',e.path,{wide:true,help:'目录须已允许共享服务读取；写共享还须允许写入。'})}${field('本机监听地址','listen_address',e.listen_address,{help:'填写设备已有的 IPv4 地址。'})}${field('端口','listen_port',e.listen_port,{type:'number',min:1024,max:65535})}${e.tls?`${field('证书路径','cert_file',e.cert_file,{wide:true})}${field('私钥路径','key_file',e.key_file,{wide:true})}`:''}${field('备注','note',e.note,{wide:true})}</div><div class="file-service-form">${state.data.accounts.items.map(a=>{const access=(e.users || []).find(u=>u.account_id===a.id);return `<label class="file-service-field"><span>${escapeHtml(a.login)}${a.enabled?'':'（已停用）'}</span><select data-file-dav-account="${escapeHtml(a.id)}"><option value="none" ${!access?'selected':''}>不允许</option><option value="ro" ${access?.read_only?'selected':''}>只读</option><option value="rw" ${access && !access.read_only?'selected':''}>读写</option></select></label>`;}).join('') || '<p>请先在协议服务中创建共享账号。</p>'}</div><p>保存会重载正在运行的 WebDAV 共享，现有连接可能中断。端口需由你现有的网络访问规则允许连接。</p>`;
  }

  function batchFields() {
    const e=state.editor;
    return `${switchField('SMB', '使用共享账号授权', 'samba', e.samba)}${switchField('NFS', '使用客户端范围授权', 'nfs', e.nfs)}${capability('webdav','shares')?switchField('WebDAV','使用独立地址和共享账号','webdav',e.webdav):''}${capability('ftp','shares')?switchField('FTP','使用服务监听设置和独立账号授权','ftp',e.ftp):''}${switchField('只读', '应用到本次选择的协议', 'read_only', e.read_only)}<div class="file-service-form">${field('共享名称','name',e.name,{wide:true})}${field('共享目录','path',e.path,{wide:true})}${field('SMB 允许用户','allowed_users',e.allowed_users,{wide:true,help:'填写已配置协议凭据的登录名，逗号分隔。'})}${field('SMB 只读用户','read_only_users',e.read_only_users,{wide:true})}${field('NFS 允许客户端','clients',e.clients,{wide:true,help:'明确填写 IP 或网段；* 表示所有客户端。'})}${field('备注','note',e.note,{wide:true})}</div>${e.webdav?`<div class="file-service-form">${field('WebDAV 监听地址','listen_address',e.listen_address)}${field('WebDAV 端口','listen_port',e.listen_port,{type:'number',min:1024,max:65535})}${state.data.accounts.items.map(a=>{const access=(e.users || []).find(u=>u.account_id===a.id);return `<label class="file-service-field"><span>${escapeHtml(a.login)}</span><select data-file-dav-account="${escapeHtml(a.id)}"><option value="none" ${!access?'selected':''}>不允许</option><option value="ro" ${access?.read_only?'selected':''}>只读</option><option value="rw" ${access && !access.read_only?'selected':''}>读写</option></select></label>`;}).join('')}</div>`:''}${e.ftp?`<h3>FTP 访问账号</h3>${accountAccessFields('ftp_users')}`:''}<p>各协议独立保存和应用；某项失败时，已成功的共享保留。WebDAV 停止时仅保存配置，可在协议服务中启动；HTTPS 可在共享编辑器中配置。</p>`;
  }

  function openBatch() {
    if(!capability('operations','manage'))return;
    state.drawer='share-batch';state.batchRequest=null;state.batchResult=null;
    state.editor={_new:true,samba:true,nfs:true,webdav:false,ftp:false,ftp_users:[],listen_address:'',listen_port:5005,users:[],name:'',path:'',allowed_users:'',read_only_users:'',clients:'',read_only:true,note:''};
    state.baseline=clone(state.editor);state.notice='';render();
  }

  function operationResultMarkup(op) {
    const labels={success:'已完成',partial:'部分完成',failed:'失败',pending:'待执行'};
    return `<section class="file-service-operation-result"><strong>${labels[op.state] || '状态未知'}</strong><small class="file-service-path">${escapeHtml(op.operation_id)}</small>${(op.results || []).map(row=>`<p><b>${escapeHtml(row.protocol.toUpperCase())}</b> · ${row.state==='success' && row.result?.applied===false ? '已保存，服务未运行' : labels[row.state] || '未知'}<small class="file-service-path">${escapeHtml(row.result?.error ? errorMessage({detail:row.result}) : row.result?.id || '')}</small></p>`).join('')}${op.retry_allowed && capability('operations','manage') ? `<button class="policy-secondary" type="button" data-file-operation-retry="${escapeHtml(op.operation_id)}" ${state.saving ? 'disabled' : ''}>重试未成功的协议</button>` : ''}${(op.results || []).some(row=>row.result?.rollback_failed) ? '<p>恢复失败，需先核实服务状态；未开放直接重试。</p>' : ''}</section>`;
  }

  async function openOperationHistory() {
    if(state.drawer && !closeDrawer())return;
    state.drawer='share-history';state.editor={};state.baseline={};state.operationHistory=[];state.notice='正在读取操作记录';render();
    try { const data=await requestJson(ENDPOINTS.operations);state.operationHistory=asArray(data.items);state.notice=''; }
    catch(error){state.notice=errorMessage(error);state.noticeTone='error';}
    if(state.mounted)render();
  }

  async function saveBatch() {
    if(!state.batchRequest) {
      const e=state.editor,users=value=>String(value || '').split(',').map(x=>x.trim()).filter(Boolean);
      if(!e.path || !(e.samba || e.nfs || e.webdav || e.ftp) || (e.webdav && (!e.name || !e.listen_address || !e.users?.length)) || (e.ftp && (!/^[A-Za-z0-9_-]{1,64}$/.test(e.name) || !e.ftp_users?.length)) || (e.samba && (!e.name || !users(e.allowed_users).length)) || (e.nfs && !e.clients)) {
        state.notice='请填写目录、选定协议及各协议的访问范围';state.noticeTone='error';renderDrawer();return;
      }
      if(!window.confirm('创建所选协议共享？部分失败时会保留已成功的共享。'))return;
      const items=[];
      if(e.samba)items.push({protocol:'samba',action:'create',body:{name:e.name,path:e.path,read_only:e.read_only,allowed_users:users(e.allowed_users),read_only_users:users(e.read_only_users),note:e.note}});
      if(e.nfs)items.push({protocol:'nfs',action:'create',body:{path:e.path,clients:e.clients,options:`${e.read_only?'ro':'rw'},sync,root_squash,no_subtree_check`,note:e.note}});
      if(e.webdav)items.push({protocol:'webdav',action:'create',body:{name:e.name,path:e.path,read_only:e.read_only,listen_address:e.listen_address,listen_port:e.listen_port,users:e.users,note:e.note}});
      if(e.ftp)items.push({protocol:'ftp',action:'create',body:{name:e.name,path:e.path,read_only:e.read_only,users:e.ftp_users,note:e.note}});
      state.batchRequest={confirm:true,request_id:crypto.randomUUID(),items};
    }
    state.saving=true;state.notice='';renderDrawer();
    try {
      await requestJson(ENDPOINTS.operations,{method:'POST',body:JSON.stringify(state.batchRequest)});
      state.batchResult=await requestJson(`${ENDPOINTS.operations}/${encodeURIComponent(state.batchRequest.request_id)}`);
      if(state.batchResult.state==='success')state.baseline=clone(state.editor);
      await load(true);
    } catch(error){state.notice=`操作未确认：${errorMessage(error)}；再次保存会查询同一操作，不会重复创建`;state.noticeTone='error';}
    finally{if(state.mounted){state.saving=false;render();}}
  }

  async function retryBatch(id) {
    if(state.saving || !capability('operations','manage') || !window.confirm('重试未成功的协议？已成功项保持不变。'))return;
    state.saving=true;state.notice='';renderDrawer();
    try {
      await requestJson(`${ENDPOINTS.operations}/${encodeURIComponent(id)}/retry`,{method:'POST',body:JSON.stringify({confirm:true})});
      const result=await requestJson(`${ENDPOINTS.operations}/${encodeURIComponent(id)}`);
      if(state.drawer==='share-batch'){state.batchResult=result;if(result.state==='success')state.baseline=clone(state.editor);}
      else state.operationHistory=state.operationHistory.map(op=>op.operation_id===id?result:op);
      await load(true);
    }catch(error){state.notice=errorMessage(error);state.noticeTone='error';}
    finally{if(state.mounted){state.saving=false;render();}}
  }

  function openAccountCreate() {
    if (!capability('accounts', 'manage')) return;
    state.drawer = 'share-account';
    state.editor = {_new:true, username:'', label:'', enabled:true, password:''};
    state.baseline = clone(state.editor); state.notice = ''; state.confirmDelete = false; render();
  }

  function openSettings(service) {
    state.drawer = service;
    state.editor = clone(state.data[service]);
    state.editor.password = '';
    state.baseline = clone(state.editor);
    state.confirmDelete = false;
    state.notice = '';
    render();
  }

  function openEditor(kind, id) {
    let item;
    if (kind === 'share-account') item = state.data.accounts.items.find((entry) => entry.id === id);
    if (kind === 'nfs-export') item = state.data.nfs.exports.find((entry) => entry.id === id);
    if (kind === 'nfs-mount') item = state.data.nfs.mounts.find((entry) => entry.id === id);
    if (kind === 'samba-share') item = state.data.samba.shares.find((entry) => entry.id === id);
    if (kind === 'webdav-share') item = (state.data.webdav.shares || []).find(entry=>entry.id===id);
    if (kind === 'ftp-share') item = state.data.ftp.shares.find((entry) => entry.id === id);
    if (!item) return;
    state.drawer = kind;
    state.editor = { ...clone(item), _new: false, password: '' };
    state.baseline = clone(state.editor);
    state.conflict = null;
    state.confirmDelete = false;
    state.notice = '';
    render();
  }

  function editorEndpoint() {
    const editor = state.editor;
    if (state.drawer === 'share-account') return `${ENDPOINTS.accounts}${editor._new ? '' : `/${encodeURIComponent(editor.id)}`}`;
    if (state.drawer === 'webdav-share') return `${ENDPOINTS.webdav}/shares${editor._new ? '' : `/${encodeURIComponent(editor.id)}`}`;
    if (state.drawer === 'webdav') return ENDPOINTS.webdav;
    if (state.drawer === 'nfs') return ENDPOINTS.nfs;
    if (state.drawer === 'samba') return ENDPOINTS.samba;
    if (state.drawer === 'samba-share') return `${ENDPOINTS.samba}/shares${editor._new ? '' : `/${encodeURIComponent(editor.id)}`}`;
    if (state.drawer === 'ftp') return ENDPOINTS.ftp;
    if (state.drawer === 'nfs-export') return `${ENDPOINTS.nfs}/exports${editor._new ? '' : `/${encodeURIComponent(editor.id)}`}`;
    if (state.drawer === 'nfs-mount') return `${ENDPOINTS.nfs}/mounts${editor._new ? '' : `/${encodeURIComponent(editor.id)}`}`;
    if (state.drawer === 'ftp-share') return `${ENDPOINTS.ftp}/shares${editor._new ? '' : `/${encodeURIComponent(editor.id)}`}`;
    return '';
  }

  const writableFields = {
    'webdav-share': ['name','path','enabled','read_only','listen_address','listen_port','tls','cert_file','key_file','users','note','rebind'],
    'share-account': ['username', 'label', 'enabled', 'password'],
    'samba-share': ['name', 'path', 'enabled', 'read_only', 'browseable', 'network_discovery', 'guest_access', 'allowed_users', 'read_only_users', 'note', 'rebind'],
    'nfs-export': ['path', 'enabled', 'clients', 'options', 'note', 'rebind'],
    'nfs-mount': ['enabled', 'source', 'target', 'options', 'delay'],
    nfs: ['default_clients','default_options'],
    samba: ['workgroup', 'server_description', 'interfaces','min_protocol','max_protocol','guest_access'],
    webdav: ['enabled', 'listen_port', 'username', 'password', 'root_dir', 'read_only', 'ssl', 'cert_file', 'key_file'],
    ftp: ['listen_address', 'listen_port', 'passive_min_port', 'passive_max_port', 'passive_address', 'tls', 'cert_file', 'key_file'],
    'ftp-share': ['name', 'path', 'enabled', 'read_only', 'users', 'note', 'rebind']
  };
  function cleanPayload() {
    const payload = {};
    const fields = ['samba','nfs'].includes(state.drawer) ? (state.data[state.drawer].settings_fields || []).filter((key) => writableFields[state.drawer].includes(key)) : writableFields[state.drawer] || [];
    for (const key of fields) if (state.editor[key] !== undefined) payload[key] = clone(state.editor[key]);
    for (const key of ['interfaces', 'allowed_users', 'read_only_users']) if (key in payload) payload[key] = String(payload[key] || '').split(',').map((value) => value.trim()).filter(Boolean);
    if (!payload.password) delete payload.password;
    if (!payload.rebind) delete payload.rebind;
    if (!state.editor._new) {
      const revision = Number(state.baseline.revision);
      if (!Number.isSafeInteger(revision) || revision < (state.drawer === 'ftp' ? 0 : 1)) throw new Error('缺少真实版本号，请重新读取配置后编辑');
      payload.expected_revision = revision;
    }
    payload.confirm = true;
    return payload;
  }

  function errorMessage(error) {
    const detail = error.detail || error.payload?.data || {};
    return [firstText(error.message, detail.error, '请求失败'), REASON_TEXT[detail.reason] || detail.reason,
      detail.rolled_back ? '旧配置已恢复' : '', detail.rollback_failed ? '恢复失败，请检查服务实际状态' : '',
      detail.config_restored === false ? '配置文件未恢复' : '', detail.db_rolled_back === false ? '数据库未恢复' : ''
    ].filter(Boolean).join('；');
  }

  async function canonicalRecord(service, kind, id) {
    const raw = await requestJson(ENDPOINTS[service]);
    const normalizers = { accounts: normalizeAccounts, samba: normalizeSamba, nfs: normalizeNfs, webdav: normalizeWebdav, ftp: normalizeFtp };
    const value = normalizers[service](raw);
    state.data[service] = value;
    delete state.errors[service];
    const collection = { 'share-account': 'items', 'samba-share': 'shares', 'webdav-share':'shares', 'nfs-export': 'exports', 'nfs-mount': 'mounts', 'ftp-share': 'shares' }[kind];
    return collection ? value[collection].find((entry) => entry.id === id) : value;
  }

  async function verifySaved() {
    const pending = state.pendingWrite;
    const current = await canonicalRecord(pending.service, pending.kind, pending.id);
    if (!current || Object.entries(pending.payload).some(([key, value]) => !['confirm', 'expected_revision', 'password', 'rebind'].includes(key) && JSON.stringify(current[key]) !== JSON.stringify(value))) {
      throw new Error('写入已接受，但回读尚未与草稿一致；请保留草稿并重新回读');
    }
    state.pendingWrite = null;
    state.drawer = '';
    state.editor = {};
    state.conflict = null;
    state.notice = pending.kind === 'nfs' ? '新建默认策略已保存，既有导出保持原配置' : pending.result.applied === true ? '配置已保存并应用，回读一致' : '配置已保存，运行态尚未确认应用';
    state.noticeTone = pending.result.applied === true ? 'ok' : 'warning';
  }

  function validateEditor() {
    if (state.drawer === 'share-account') {
      if (!/^[a-z][a-z0-9_]{0,23}$/.test(state.editor.username)) return '账号名称格式不正确';
      const password = state.editor.password || '';
      const length = new TextEncoder().encode(password).length;
      if ((state.editor._new || password) && (length < 12 || length > 128 || /[\r\n\0]/.test(password))) return '密码须为 12–128 字节，且不含换行';
    }
    if (state.drawer === 'webdav-share' && (!state.editor.name || !state.editor.path || !state.editor.listen_address || !state.editor.users?.length)) return '请填写名称、目录、本机监听地址，并选择允许访问的账号';
    if (state.drawer === 'nfs-export' && !firstText(state.editor.clients)) return '请明确填写允许的客户端范围；* 表示允许所有客户端';
    if (state.drawer === 'nfs-export' && !firstText(state.editor.path)) return '共享路径不能为空';
    if (state.drawer === 'nfs-mount' && (!firstText(state.editor.source) || !firstText(state.editor.target))) return '源目录和挂载点不能为空';
    if (state.drawer === 'samba-share' && (!firstText(state.editor.name) || !firstText(state.editor.path))) return '共享名称和共享路径不能为空';
    if (state.drawer === 'ftp-share' && (!/^[A-Za-z0-9_-]{1,64}$/.test(state.editor.name) || !state.editor.path || !state.editor.users?.length)) return '请填写1–64位字母、数字、下划线或连字符的共享名称、目录，并选择访问账号';
    if (state.drawer === 'ftp') {
      const e = state.editor, first = Number(e.passive_min_port), last = Number(e.passive_max_port), port = Number(e.listen_port);
      if (!e.listen_address || !Number.isInteger(port) || port < 1 || port > 65535) return '请填写本机 IPv4 地址和有效监听端口';
      if (![first,last].every(Number.isInteger) || first < 1024 || last > 65535 || first > last || last-first >= 64 || (port >= first && port <= last)) return '被动端口须为1024–65535中的连续1–64个端口，且不包含控制端口';
      if (e.tls && (!e.cert_file || !e.key_file)) return '启用显式 FTPS 需要填写证书与私钥路径';
    }
    return '';
  }

  async function saveEditor() {
    if (!editorCapability() || state.saving) return;
    if (state.drawer === 'share-batch') { await saveBatch(); return; }
    const validation = validateEditor();
    if (validation) { state.notice = validation; state.noticeTone = 'error'; renderDrawer(); return; }
    if (state.drawer === 'share-account' && !state.pendingWrite && !window.confirm(state.editor._new ? `创建共享登录名 dwshare_${state.editor.username}？` : '保存账号更改？改密或启停账号会重置 SMB、WebDAV 和 FTP 连接。')) return;
    state.saving = true;
    state.notice = '';
    renderDrawer();
    try {
      if (!state.pendingWrite) {
        const payload = cleanPayload();
        const result = await requestJson(editorEndpoint(), { method: state.editor._new ? 'POST' : 'PUT', body: JSON.stringify(payload) });
        if (!state.mounted) return;
        const [service] = editorCapabilityPath();
        state.pendingWrite = { service, kind: state.drawer, id: result.id || state.editor.id, payload, result };
      }
      await verifySaved();
    } catch (error) {
      if (!state.mounted) return;
      state.notice = `保存未完成：${errorMessage(error)}`;
      state.noticeTone = 'error';
      if (error.detail?.error === 'revision_conflict' || /revision_conflict/.test(error.message)) {
        try { state.conflict = await canonicalRecord(editorCapabilityPath()[0], state.drawer, state.editor.id); }
        catch (_) { state.notice += '；当前版本读取失败，原草稿仍保留'; }
      }
    } finally {
      if (state.mounted) { state.saving = false; render(); }
    }
  }

  async function deleteEditor() {
    if (!editorCapability() || state.editor._new || state.saving || state.pendingWrite) return;
    if (!state.confirmDelete) { state.confirmDelete = true; renderDrawer(); return; }
    const revision = Number(state.baseline.revision);
    if (!Number.isSafeInteger(revision) || revision < 1) { state.notice = '缺少版本号，不能删除'; state.noticeTone = 'error'; renderDrawer(); return; }
    state.saving = true;
    renderDrawer();
    try {
      await requestJson(editorEndpoint(), { method: 'DELETE', body: JSON.stringify({ confirm: true, expected_revision: revision }) });
      if (!state.mounted) return;
      const current = await canonicalRecord(editorCapabilityPath()[0], state.drawer, state.editor.id);
      if (current) throw new Error('删除请求已接受，但回读仍有该记录');
      const account = state.drawer === 'share-account';
      state.drawer = '';
      state.editor = {};
      state.notice = account ? '共享账号已删除，目录和文件保留' : '共享配置已删除，目录和文件保留';
      state.noticeTone = 'ok';
    } catch (error) {
      if (!state.mounted) return;
      state.notice = `删除未完成：${errorMessage(error)}`;
      state.noticeTone = 'error';
    } finally {
      if (state.mounted) { state.saving = false; render(); }
    }
  }

  async function downloadRegistry() {
    if (!capability('webdav', 'download_registry')) return;
    try {
      const response = await sessionFetch(`${ENDPOINTS.webdav}/registry?v=${VERSION}`, { credentials: 'same-origin', cache: 'no-store', headers: authHeaders() });
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
    if (event.target.closest('button:disabled')) return;
    if (event.target.closest('[data-file-batch-new]')) { openBatch(); return; }
    if (event.target.closest('[data-file-operation-history]')) { openOperationHistory(); return; }
    const retryOperation=event.target.closest('[data-file-operation-retry]');
    if (retryOperation) { retryBatch(retryOperation.dataset.fileOperationRetry); return; }
    if (event.target.closest('[data-file-directory-open]')) { browseDirectory(); return; }
    if (event.target.closest('[data-file-directory-close]')) { state.picker = null; renderDrawer(); return; }
    if (event.target.closest('[data-file-directory-use]') && state.picker && !state.picker.loading && !state.picker.error) { setEditorField('path', state.picker.path); state.picker = null; renderDrawer(); return; }
    const directory = event.target.closest('[data-file-directory-path]');
    if (directory) { browseDirectory(directory.dataset.fileDirectoryPath, state.picker?.rootId); return; }
    const action = event.target.closest('[data-file-action]');
    if (action) { serviceAction(action.dataset.fileAction); return; }
    if (event.target.closest('[data-file-refresh]')) { load(true); return; }
    if (event.target.closest('[data-dwrt-savebar-save]')) { saveEditor(); return; }
    if (event.target.closest('[data-dwrt-savebar-discard]')) {
      if (state.pendingWrite) return;
      state.editor = clone(state.baseline); state.notice = ''; renderDrawer(); return;
    }
    if (event.target.closest('[data-file-use-current]') && state.conflict) {
      state.editor = { ...clone(state.conflict), _new: false, password: '' };
      state.baseline = clone(state.editor); state.conflict = null; state.notice = ''; renderDrawer(); return;
    }
    const page = event.target.closest('[data-file-page]');
    if (page) { if (state.drawer && !closeDrawer()) return; state.page = page.dataset.filePage; state.query = ''; render(); return; }
    if (event.target.closest('[data-file-accounts]')) { state.accountsView = true; state.query = ''; render(); return; }
    if (event.target.closest('[data-file-account-new]')) { openAccountCreate(); return; }
    const protocol = event.target.closest('[data-file-protocol]');
    if (protocol) { state.accountsView = false; state.tab = protocol.dataset.fileProtocol; state.query = ''; render(); return; }
    const create = event.target.closest('[data-file-new]');
    if (create) { state.tab = create.dataset.fileNew; state.nfsView = 'exports'; state.sambaView = 'shares'; openCreate(); return; }
    const copy = event.target.closest('[data-file-copy]');
    if (copy) { navigator.clipboard.writeText(copy.dataset.fileCopy).then(() => { copy.textContent = '已复制'; }).catch(() => { state.notice = '复制失败，请选择地址手动复制'; render(); }); return; }
    if (event.target.closest('[data-file-close]')) { closeDrawer(); return; }
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
    const subject = event.target.closest('[data-file-subject]');
    if (subject) {
      const names = String(state.editor.allowed_users || '').split(',').map((v) => v.trim()).filter(Boolean);
      const next = names.filter((v) => v !== subject.dataset.fileSubject);
      if (subject.checked) next.push(subject.dataset.fileSubject);
      setEditorField('allowed_users', next); renderDrawer(); return;
    }
    const access = event.target.closest('[data-file-account-access]');
    if (access) { const key = access.dataset.fileAccessField; const users = (state.editor[key] || []).filter(u => u.account_id !== access.dataset.fileAccountAccess); if (access.value !== 'none') users.push({account_id:access.dataset.fileAccountAccess,read_only:access.value === 'ro'}); setEditorField(key, users); return; }
    const davAccount=event.target.closest('[data-file-dav-account]');
    if(davAccount){const users=(state.editor.users || []).filter(u=>u.account_id!==davAccount.dataset.fileDavAccount);if(davAccount.value!=='none')users.push({account_id:davAccount.dataset.fileDavAccount,read_only:davAccount.value==='ro'});setEditorField('users',users);return;}
    const storageRoot = event.target.closest('[data-file-directory-root]');
    if (storageRoot) { const root = state.picker?.roots.find((item) => item.id === storageRoot.value); if (root) browseDirectory(root.path, root.id); return; }
    const choice = event.target.closest('[data-file-nfs-choice]');
    if (choice) {
      if (!choice.value) return;
      const group = {access:['ro','rw'],sync:['sync','async'],root:['root_squash','no_root_squash']}[choice.dataset.fileNfsChoice];
      if (!group?.includes(choice.value)) return;
      setEditorField('options', String(state.editor.options || '').split(',').filter((item) => item && !group.includes(item.trim())).concat(choice.value).join(','));
      renderDrawer(); return;
    }
    const filter = event.target.closest('[data-file-filter]');
    if (filter) { state.filter = filter.value; patchMainSurface(); return; }
    const fieldInput = event.target.closest('[data-file-draft]');
    if (!fieldInput) return;
    const value = fieldInput.type === 'checkbox' ? fieldInput.checked : fieldInput.type === 'number' ? Number(fieldInput.value || 0) : fieldInput.value;
    setEditorField(fieldInput.dataset.fileDraft, value);
    if (['ssl', 'tls', 'webdav', 'ftp'].includes(fieldInput.dataset.fileDraft)) renderDrawer();
  }

  function onTabChange(event) {
    if (!event.target.closest('[data-file-tabs]')) return;
    const next = event.detail?.value;
    if (!TABS.some(([id]) => id === next) || next === state.tab) return;
    if (state.drawer && !closeDrawer()) return;
    state.tab = next;
    state.query = '';
    state.drawer = '';
    state.notice = '';
    render();
  }

  function onKeyDown(event) {
    if (event.key === 'Escape' && state.drawer) closeDrawer();
  }

  // Kit portals sheets outside the route. Follow the owned sheet after portalization.
  function onSheetClick(event) {
    if (!event.target.closest('[data-file-overlay-owned]')) return;
    if (event.target.closest('[data-file-close]')) {
      event.preventDefault(); event.stopImmediatePropagation(); closeDrawer(); return;
    }
    onClick(event);
  }
  function onSheetInput(event) { if (event.target.closest('[data-file-overlay-owned]')) onInput(event); }
  function onSheetChange(event) { if (event.target.closest('[data-file-overlay-owned]')) onChange(event); }

  function beforeUnload(event) { if (dirty() || state.saving) { event.preventDefault(); event.returnValue = ''; } }
  let previousHash = location.hash;
  function beforeHashChange(event) {
    if ((dirty() || state.saving) && !window.confirm('有未保存的共享配置，放弃并离开？')) {
      history.replaceState(null, '', previousHash); event.stopImmediatePropagation();
    } else previousHash = location.hash;
  }
  window.addEventListener('beforeunload', beforeUnload);
  window.addEventListener('hashchange', beforeHashChange, true);
  document.addEventListener('click', onSheetClick, true);
  document.addEventListener('input', onSheetInput);
  document.addEventListener('change', onSheetChange);
  root?.addEventListener('click', onClick);
  root?.addEventListener('input', onInput);
  root?.addEventListener('change', onChange);
  root?.addEventListener('dwrt-tab-change', onTabChange);
  document.addEventListener('keydown', onKeyDown);
  stage?.classList.add('is-storage-file-services');
  render();
  load();

  /*
   * 手动刷新按钮按用户第 9 条删除，补一条可见性受控的轮询代替；
   * 抽屉打开、正在保存或有未提交草稿时跳过，避免刷掉用户填的内容。
   */
  state.pollTimer = window.setInterval(() => {
    if (!state.mounted || document.hidden) return;
    if (state.loading || state.refreshing || state.saving || state.actionBusy) return;
    if (state.drawer) return;
    load(true);
  }, 15000);

  return {
    refresh() { return load(true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      window.clearInterval(state.pollTimer);
      root?.removeEventListener('click', onClick);
      root?.removeEventListener('input', onInput);
      root?.removeEventListener('change', onChange);
      root?.removeEventListener('dwrt-tab-change', onTabChange);
      document.removeEventListener('keydown', onKeyDown);
      document.removeEventListener('click', onSheetClick, true);
      document.removeEventListener('input', onSheetInput);
      document.removeEventListener('change', onSheetChange);
      window.removeEventListener('beforeunload', beforeUnload);
      window.removeEventListener('hashchange', beforeHashChange, true);
      clearSheet();
      layer.remove();
      root?.replaceChildren();
      root?.classList.remove('route-workspace', 'policy-table-route-host', MODULE_CLASS);
      stage?.classList.remove('is-storage-file-services');
    }
  };
}

export default { mount };
