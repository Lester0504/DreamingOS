export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const item = context.item || {};
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const VERSION = '20260802-ui-batch-01';
  const MODULE_CLASS = 'user-authentication-route-host';
  const stage = root?.closest('.console-stage');
  const PAGE_BY_ID = {
    'authentication-web': 'web',
    'authentication-online-users': 'online',
    'authentication-accounts': 'accounts',
    'authentication-delegated': 'delegated',
    'authentication-notifications': 'notifications'
  };
  const page = PAGE_BY_ID[item.id] || 'web';
  const ENDPOINT = '/api/v1/authentication';
  const TABS = {
    accounts: [['packages', '套餐管理'], ['accounts', '账号管理'], ['password', '自助密码管理'], ['ledger', '总账管理'], ['vouchers', '上网码']],
    delegated: [['services', '代拨账号管理'], ['online', '在线账号列表']],
    notifications: [['realtime', '实时通知'], ['periodic', '定期通知'], ['expiry', '到期通知'], ['expired', '拨号用户过期通知']]
  };

  function emptyData() {
    return {
      source: 'config.db:user_authentication + runtime',
      capabilities: {},
      web: {
        enabled: false, networks: [], auth_methods: ['none'], default_expiration: 480, expiration_unit: 'minutes',
        idle_timeout: 60, redirect_enabled: false, redirect_url: '', secure_portal: true, portal_hostname: '',
        password_enabled: false, voucher_enabled: false, radius_enabled: false, external_api_enabled: false,
        payment_enabled: false, google_enabled: false, free_access_enabled: false, terms_required: false,
        has_guest_password: false, guest_password: '', voucher_default_package_id: '',
        radius_profile_id: '', radius_auth_type: 'chap', radius_disconnect_enabled: false, radius_disconnect_port: 3799,
        external_api_url: '', external_api_auth_url: '', google_client_id: '', google_domain: '',
        payment_provider: '', payment_currency: 'CNY', payment_package_ids: [],
        pre_authorization: [], post_authorization: [], restricted_dns_enabled: false, restricted_dns_servers: [],
        portal: {
          title: '访客网络', welcome_text: '欢迎使用访客网络', authentication_text: '请选择认证方式以继续访问网络',
          success_text: '认证成功，正在连接网络', button_text: '连接', languages: ['zh-CN'],
          background_type: 'color', background_color: '#111827', background_image_enabled: false, background_image_url: '', background_tile: false,
          box_color: '#0f172a', box_opacity: 78, box_radius: 12, text_color: '#ffffff', link_color: '#7dd3fc',
          button_color: '#2563eb', button_text_color: '#ffffff', logo_enabled: true, logo_url: '/static/images/dreamingwrt.png',
          logo_position: 'top', logo_size: 72, welcome_position: 'center', terms_enabled: false, terms_text: ''
        }
      },
      online_users: [],
      account_management: {
        packages: [], accounts: [], ledger: [], vouchers: [],
        password_policy: { enabled: false, pppoe: true, l2tp: true, pptp: true, openvpn: true, web_change: true, web_logout: true }
      },
      delegated: { services: [], online: [] },
      notifications: {
        realtime: { content: '', redirect_url: '', dial_users: true, lan_users: false, targets: [], groups: [], countdown: 60 },
        periodic: [],
        expiry: { enabled: false, content: '', redirect_url: '', days_before: 5, times: ['08:00', '16:00'], countdown: 60 },
        expired: { content: '', public_ip_allowlist: [], domain_allowlist: [] }
      }
    };
  }

  const state = {
    mounted: true,
    seq: 0,
    pollTimer: 0,
    loading: true,
    loaded: false,
    refreshing: false,
    saving: false,
    error: '',
    notice: '',
    noticeTone: '',
    page,
    tab: TABS[page]?.[0]?.[0] || '',
    query: '',
    statusFilter: 'all',
    selected: new Set(),
    drawer: '',
    editor: {},
    preview: false,
    confirmDelete: false,
    deleteTarget: null,
    notificationDraft: null,
    webDraft: null,
    data: emptyData()
  };
  if (state.page === 'notifications') state.notificationDraft = clone(state.data.notifications[state.tab] || {});

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

  function setNested(target, path, value) {
    const keys = String(path).split('.');
    let cursor = target;
    keys.slice(0, -1).forEach((key) => {
      if (!cursor[key] || typeof cursor[key] !== 'object') cursor[key] = {};
      cursor = cursor[key];
    });
    cursor[keys.at(-1)] = value;
  }

  function normalizeData(payload = {}) {
    const base = emptyData();
    const source = payload.authentication && typeof payload.authentication === 'object' ? payload.authentication : payload;
    return {
      ...base,
      ...source,
      capabilities: source.capabilities || {},
      web: { ...base.web, ...(source.web || {}), portal: { ...base.web.portal, ...(source.web?.portal || source.portal || {}) } },
      online_users: asArray(source.online_users, ['sessions', 'guests']),
      account_management: {
        ...base.account_management,
        ...(source.account_management || source.accounts || {}),
        packages: asArray(source.account_management?.packages || source.packages),
        accounts: asArray(source.account_management?.accounts || source.accounts?.items || source.users),
        ledger: asArray(source.account_management?.ledger || source.ledger),
        vouchers: asArray(source.account_management?.vouchers || source.vouchers),
        password_policy: { ...base.account_management.password_policy, ...(source.account_management?.password_policy || source.password_policy || {}) }
      },
      delegated: {
        ...base.delegated,
        ...(source.delegated || {}),
        services: asArray(source.delegated?.services || source.delegated_services),
        online: asArray(source.delegated?.online || source.delegated_online)
      },
      notifications: {
        ...base.notifications,
        ...(source.notifications || {}),
        realtime: { ...base.notifications.realtime, ...(source.notifications?.realtime || {}) },
        periodic: asArray(source.notifications?.periodic || source.periodic_notifications),
        expiry: { ...base.notifications.expiry, ...(source.notifications?.expiry || {}) },
        expired: { ...base.notifications.expired, ...(source.notifications?.expired || {}) }
      }
    };
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
    return { Accept: 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}), ...extra };
  }

  async function requestJson(url, options = {}) {
    const isFormData = typeof FormData !== 'undefined' && options.body instanceof FormData;
    const response = await sessionFetch(`${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`, {
      credentials: 'same-origin', cache: 'no-store', ...options,
      headers: authHeaders({ ...(options.body && !isFormData ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
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

  async function load(background = false) {
    const seq = ++state.seq;
    if (background) state.refreshing = true; else state.loading = true;
    state.error = '';
    if (!background && !root?.querySelector('.user-auth-shell')) render();
    try {
      const payload = await requestJson(ENDPOINT);
      if (!state.mounted || seq !== state.seq) return;
      state.data = normalizeData(payload);
      if (state.page === 'web') state.webDraft = clone(state.data.web);
      if (state.page === 'notifications') state.notificationDraft = clone(state.data.notifications[state.tab] || {});
      state.loaded = true;
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.error = error.status === 404
        ? '用户认证后端合同尚未接入。页面保留完整配置与操作结构，所有会改变运行状态的操作均已禁用。'
        : `读取用户认证数据失败：${firstText(error.message, '未知错误')}`;
    } finally {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      if (background) patchWorkbench(); else render();
    }
  }

  function capability(action) {
    const caps = state.data.capabilities || {};
    const local = caps[state.page] || {};
    return caps.write === true || caps[action] === true || caps[`${state.page}_${action}`] === true || local.write === true || local[action] === true;
  }

  function icon(name) {
    const paths = {
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      edit: '<path d="m4 20 4.2-1 10.9-10.9a2 2 0 0 0-2.8-2.8L5.4 16.2 4 20Z"></path>',
      export: '<path d="M12 3v12m-5-5 5 5 5-5"></path><path d="M5 21h14"></path>',
      import: '<path d="M12 21V9m-5 5 5-5 5 5"></path><path d="M5 3h14"></path>',
      disconnect: '<path d="M9 12h6"></path><circle cx="12" cy="12" r="9"></circle>',
      preview: '<path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z"></path><circle cx="12" cy="12" r="2.5"></circle>',
      trash: '<path d="M4 7h16M9 7V4h6v3m-9 0 1 13h10l1-13M10 11v5m4-5v5"></path>',
      more: '<circle cx="5" cy="12" r="1"></circle><circle cx="12" cy="12" r="1"></circle><circle cx="19" cy="12" r="1"></circle>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.more}</svg>`;
  }

  function tabsMarkup() {
    if (state.page === 'web') return '';
    const tabs = TABS[state.page];
    if (!tabs) return '';
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs user-auth-tabs" data-user-auth-tabs data-dwrt-tabs-key="user-auth-${state.page}" aria-label="${escapeHtml(item.label || '用户认证')}"><span class="dwrt-kit-tab-pill" aria-hidden="true"></span>${tabs.map(([id, label]) => `<button class="dwrt-kit-tab ${state.tab === id ? 'is-active' : ''}" type="button" data-value="${id}" aria-selected="${state.tab === id ? 'true' : 'false'}">${label}</button>`).join('')}</nav>`;
  }

  function noticeMarkup() {
    const message = state.notice || state.error;
    if (!message) return '';
    return `<div class="user-auth-notice is-${escapeHtml(state.notice ? state.noticeTone || 'ok' : 'warning')}">${escapeHtml(message)}</div>`;
  }

  function searchMarkup(placeholder = '搜索当前列表') {
    return `<label class="policy-search policy-search-main" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-user-auth-search value="${escapeHtml(state.query)}" placeholder="${escapeHtml(placeholder)}"></label>`;
  }

  function actionButton(label, action, iconName, options = {}) {
    const cls = options.primary ? 'policy-create-button' : 'policy-filter-button';
    return `<button class="${cls}" type="button" data-user-auth-action="${escapeHtml(action)}" ${options.disabled ? 'disabled' : ''}>${icon(iconName)}<span>${escapeHtml(label)}</span></button>`;
  }

  function toolbarMarkup(options = {}) {
    return `<header class="policy-toolbar user-auth-toolbar"><div class="user-auth-toolbar-leading">${options.leading || (options.search === false ? '' : searchMarkup(options.placeholder))}</div><div class="policy-toolbar-actions">${options.actions || ''}</div></header>`;
  }

  function statusPill(label, active = false, warning = false) {
    return ui.statusBadgeMarkup?.(label, warning ? 'warning' : active ? 'success' : 'error') || `<span>${escapeHtml(label)}</span>`;
  }

  function switchField(label, help, path, checked, disabled = false) {
    return `<label class="user-auth-setting-row"><span><strong>${escapeHtml(label)}</strong><small>${escapeHtml(help)}</small></span><span class="user-auth-switch"><input type="checkbox" data-user-auth-draft="${escapeHtml(path)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}><i></i></span></label>`;
  }

  function field(label, path, value, options = {}) {
    const tag = options.tag || 'input';
    const attrs = `${options.disabled ? 'disabled' : ''} ${options.required ? 'required' : ''}`;
    const control = tag === 'textarea'
      ? `<textarea data-user-auth-draft="${escapeHtml(path)}" placeholder="${escapeHtml(options.placeholder || '')}" ${attrs}>${escapeHtml(value || '')}</textarea>`
      : tag === 'select'
        ? `<select data-user-auth-draft="${escapeHtml(path)}" ${attrs}>${(options.options || []).map(([id, text]) => `<option value="${escapeHtml(id)}" ${String(value) === String(id) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select>`
        : `<input data-user-auth-draft="${escapeHtml(path)}" type="${escapeHtml(options.type || 'text')}" value="${escapeHtml(value ?? '')}" placeholder="${escapeHtml(options.placeholder || '')}" ${options.min !== undefined ? `min="${options.min}"` : ''} ${options.max !== undefined ? `max="${options.max}"` : ''} ${attrs}>`;
    return `<label class="user-auth-field ${options.wide ? 'is-wide' : ''}"><span>${escapeHtml(label)}</span>${control}${options.help ? `<small>${escapeHtml(options.help)}</small>` : ''}</label>`;
  }

  function tableMarkup(title, subtitle, headings, rows, empty = '暂无内容', options = {}) {
    return `<section class="user-auth-main-surface user-auth-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface" data-user-auth-list><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(subtitle)}</span></div><span class="dwrt-kit-table-count">${rows.length} 条</span></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table user-auth-table"><thead><tr>${options.select ? '<th><input type="checkbox" data-user-auth-select-all aria-label="全选"></th>' : ''}${headings.map((heading) => `<th>${escapeHtml(heading)}</th>`).join('')}</tr></thead><tbody>${state.loading && !state.loaded ? `<tr><td colspan="${headings.length + (options.select ? 1 : 0)}" class="dwrt-kit-table-empty">正在读取用户认证数据</td></tr>` : rows.length ? rows.join('') : `<tr><td colspan="${headings.length + (options.select ? 1 : 0)}" class="dwrt-kit-table-empty">${escapeHtml(empty)}</td></tr>`}</tbody></table></div></section>`;
  }

  function matchesQuery(values) {
    const query = state.query.trim().toLowerCase();
    return !query || values.some((value) => String(value || '').toLowerCase().includes(query));
  }

  function selectedCell(id) {
    return `<td><input type="checkbox" data-user-auth-select="${escapeHtml(id)}" ${state.selected.has(String(id)) ? 'checked' : ''} aria-label="选择"></td>`;
  }

  function webToolbar() {
    const canSave = capability('update_web');
    return toolbarMarkup({ search: false, actions: `${actionButton('预览门户', 'preview-portal', 'preview')}${actionButton('编辑当前设置', 'edit-web', 'edit', { primary: true, disabled: !canSave })}` });
  }

  function renderWebService() {
    const web = state.data.web;
    return `<div class="user-auth-settings-grid"><section class="user-auth-settings-panel dwrt-kit-glass-surface"><header><div><span>HOTSPOT SERVICE</span><strong>WEB 认证服务</strong></div>${statusPill(web.enabled ? '已启用' : '未启用', web.enabled)}</header><div class="user-auth-setting-list">${switchField('启用 WEB 认证', '将未授权访客重定向到门户页面', 'enabled', web.enabled, true)}${switchField('安全门户', '使用 HTTPS 提供认证与成功页面', 'secure_portal', web.secure_portal, true)}${switchField('认证后跳转', '认证成功后跳转到自定义网址', 'redirect_enabled', web.redirect_enabled, true)}</div></section><section class="user-auth-settings-panel dwrt-kit-glass-surface"><header><div><span>SESSION POLICY</span><strong>访客会话</strong></div></header><dl class="user-auth-detail-list"><div><dt>应用网络</dt><dd>${escapeHtml(asArray(web.networks).map((network) => firstText(network.name, network.id, network)).join('、') || '未选择')}</dd></div><div><dt>默认授权时长</dt><dd>${firstNumber(web.default_expiration)} ${web.expiration_unit === 'hours' ? '小时' : '分钟'}</dd></div><div><dt>空闲超时</dt><dd>${firstNumber(web.idle_timeout)} 分钟</dd></div><div><dt>门户域名</dt><dd>${escapeHtml(web.portal_hostname || '自动')}</dd></div><div><dt>成功跳转</dt><dd>${escapeHtml(web.redirect_enabled ? web.redirect_url || '自定义页面' : '显示成功信息')}</dd></div></dl></section></div>`;
  }

  function authMethodRows() {
    const web = state.data.web;
    const methods = [
      ['free_access_enabled', '无认证 / 免费访问', '访客确认条款后直接授权'],
      ['password_enabled', '访客密码', '使用共享密码完成认证'],
      ['voucher_enabled', '上网码 / 代金券', '按券码时长、次数和速率授权'],
      ['radius_enabled', 'RADIUS', '通过 RADIUS 账号认证并支持 Disconnect'],
      ['external_api_enabled', '外部 API', '将认证交给外部门户或业务系统'],
      ['payment_enabled', '支付认证', '完成套餐支付后获得网络访问权限'],
      ['google_enabled', 'Google 登录', '限制 Google 域并按邮箱授权']
    ];
    return methods.map(([key, label, description]) => `<article class="user-auth-method"><span class="user-auth-method-icon">${icon(key === 'radius_enabled' ? 'disconnect' : 'preview')}</span><div><strong>${label}</strong><small>${description}</small></div>${statusPill(web[key] ? '启用' : '停用', web[key])}</article>`).join('');
  }

  function renderWebMethods() {
    const web = state.data.web;
    return `<div class="user-auth-method-layout"><section class="user-auth-method-list dwrt-kit-glass-surface">${authMethodRows()}</section>${web.radius_enabled ? `<section class="user-auth-settings-panel dwrt-kit-glass-surface"><header><div><span>RADIUS</span><strong>RADIUS 参数</strong></div></header><dl class="user-auth-detail-list"><div><dt>认证配置</dt><dd>${escapeHtml(web.radius_profile_id || '未选择')}</dd></div><div><dt>认证协议</dt><dd>${escapeHtml(String(web.radius_auth_type || 'chap').toUpperCase())}</dd></div><div><dt>Disconnect Request</dt><dd>${web.radius_disconnect_enabled ? `UDP ${firstNumber(web.radius_disconnect_port, 3799)}` : '停用'}</dd></div></dl></section>` : ''}</div>`;
  }

  function portalPreview(portal = state.data.web.portal) {
    const style = `--portal-bg:${escapeHtml(portal.background_color)};--portal-box:${escapeHtml(portal.box_color)};--portal-opacity:${Math.max(0, Math.min(100, firstNumber(portal.box_opacity, 78))) / 100};--portal-radius:${firstNumber(portal.box_radius, 12)}px;--portal-text:${escapeHtml(portal.text_color)};--portal-link:${escapeHtml(portal.link_color)};--portal-button:${escapeHtml(portal.button_color)};--portal-button-text:${escapeHtml(portal.button_text_color)}`;
    const backgroundUrl = escapeHtml(JSON.stringify(String(portal.background_image_url || '')));
    return `<div class="user-auth-portal-preview" style="${style}" ${portal.background_image_enabled && portal.background_image_url ? `data-background="image"` : ''}><div class="user-auth-portal-background" ${portal.background_image_enabled && portal.background_image_url ? `style="background-image:url(${backgroundUrl})"` : ''}></div><section><div class="user-auth-portal-box">${portal.logo_enabled ? `<img src="${escapeHtml(portal.logo_url || '/static/images/dreamingos.svg?v=20260725-dreaming-os-01')}" alt="Dreaming OS" style="width:${Math.max(24, Math.min(240, firstNumber(portal.logo_size, 72)))}px;height:${Math.max(24, Math.min(240, firstNumber(portal.logo_size, 72)))}px">` : ''}<h3>${escapeHtml(portal.title)}</h3>${portal.welcome_text_enabled !== false ? `<p>${escapeHtml(portal.welcome_text)}</p>` : ''}<small>${escapeHtml(portal.authentication_text)}</small><input aria-label="访客密码" placeholder="密码或上网码" disabled><button type="button" disabled>${escapeHtml(portal.button_text || '连接')}</button>${portal.terms_enabled ? `<a>${escapeHtml(portal.terms_text || '使用条款')}</a>` : ''}</div></section></div>`;
  }

  function renderWebPortal() {
    const portal = state.data.web.portal;
    return `<div class="user-auth-portal-layout"><section class="user-auth-portal-properties dwrt-kit-glass-surface"><header><div><span>LANDING PAGE</span><strong>门户页面</strong></div><button class="policy-primary" type="button" data-user-auth-action="edit-portal" ${capability('update_web') ? '' : 'disabled'}>${icon('edit')}<span>编辑门户</span></button></header><dl class="user-auth-detail-list"><div><dt>标题</dt><dd>${escapeHtml(portal.title)}</dd></div><div><dt>语言</dt><dd>${escapeHtml(asArray(portal.languages).join('、') || 'zh-CN')}</dd></div><div><dt>背景</dt><dd>${escapeHtml(portal.background_type === 'image' || portal.background_image_enabled ? '图片' : '纯色')}</dd></div><div><dt>认证框</dt><dd>${firstNumber(portal.box_opacity)}% · ${firstNumber(portal.box_radius)}px</dd></div><div><dt>徽标</dt><dd>${portal.logo_enabled ? `${firstNumber(portal.logo_size)}px · ${escapeHtml(portal.logo_position)}` : '停用'}</dd></div><div><dt>条款</dt><dd>${portal.terms_enabled ? '必须确认' : '不要求'}</dd></div></dl></section>${portalPreview(portal)}</div>`;
  }

  function renderWebAccess() {
    const web = state.data.web;
    const rows = [
      ...asArray(web.pre_authorization).map((value, index) => ({ id: `pre-${index}`, scope: '认证前放行', value: firstText(value.value, value.cidr, value.domain, value), type: firstText(value.type, 'IP / 域名') })),
      ...asArray(web.post_authorization).map((value, index) => ({ id: `post-${index}`, scope: '认证后限制', value: firstText(value.value, value.cidr, value.domain, value), type: firstText(value.type, '网段') })),
      ...asArray(web.restricted_dns_servers).map((value, index) => ({ id: `dns-${index}`, scope: '受限 DNS', value: firstText(value), type: 'DNS 服务器' }))
    ].filter((row) => matchesQuery([row.scope, row.value, row.type]));
    return `${toolbarMarkup({ placeholder: '搜索网段、域名或 DNS', actions: actionButton('添加规则', 'add-access', 'plus', { primary: true, disabled: !capability('update_web') }) })}${tableMarkup('访问控制', '认证前放行、认证后限制与受限 DNS', ['范围', '类型', '地址 / 域名', '操作'], rows.map((row) => `<tr><td>${escapeHtml(row.scope)}</td><td>${escapeHtml(row.type)}</td><td><code>${escapeHtml(row.value)}</code></td><td><button class="user-auth-icon-button" type="button" data-user-auth-edit="access" data-user-auth-id="${escapeHtml(row.id)}" disabled aria-label="编辑">${icon('edit')}</button></td></tr>`), '暂无访问控制规则')}`;
  }

  function renderWeb() {
    const web = state.webDraft || state.data.web;
    const portal = web.portal || state.data.web.portal;
    const writable = capability('update_web');
    const switchControl = (path, checked, disabled = false) => `<span class="user-auth-switch"><input type="checkbox" data-user-auth-web="${escapeHtml(path)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}><i></i></span>`;
    const optionRow = (path, title, description, checked, disabled = false) => `<label class="user-auth-web-option"><span class="user-auth-web-checkbox">${switchControl(path, checked, disabled)}</span><span>${icon(path.includes('external') ? 'disconnect' : 'preview')}<strong>${escapeHtml(title)}</strong><small>${escapeHtml(description)}</small></span></label>`;
    const value = (path, fallback = '') => path.split('.').reduce((current, key) => current?.[key], web) ?? fallback;
    const inputValue = (path, fallback = '') => {
      const current = value(path, fallback);
      return Array.isArray(current) ? current.join(', ') : current;
    };
    const textInput = (label, path, options = {}) => `<label class="user-auth-web-field"><span>${escapeHtml(label)}</span><input type="${options.type || 'text'}" data-user-auth-web="${escapeHtml(path)}" value="${escapeHtml(inputValue(path, options.fallback || ''))}" ${options.min !== undefined ? `min="${options.min}"` : ''} ${options.max !== undefined ? `max="${options.max}"` : ''} ${options.disabled ? 'disabled' : ''}></label>`;
    const colorInput = (label, path) => `<label class="user-auth-web-color"><span>${escapeHtml(label)}</span><input type="color" data-user-auth-web="${escapeHtml(path)}" value="${escapeHtml(value(path, '#ffffff'))}" ${writable ? '' : 'disabled'}><code>${escapeHtml(value(path, '#ffffff'))}</code></label>`;
    const accessRows = [
      ...asArray(web.pre_authorization).map((item, index) => ({ id: `pre-${index}`, scope: '认证前允许', value: firstText(item.value, item.cidr, item.domain, item) })),
      ...asArray(web.post_authorization).map((item, index) => ({ id: `post-${index}`, scope: '认证后限制', value: firstText(item.value, item.cidr, item.domain, item) }))
    ];
    const methodSection = `<section class="user-auth-web-section"><header><strong>身份验证方法</strong></header><div class="user-auth-web-options">${optionRow('password_enabled', '密码', '使用共享访客密码进行验证', web.password_enabled, !writable)}${optionRow('payment_enabled', '付款', '购买套餐后获得网络访问权限', web.payment_enabled, !writable)}${optionRow('voucher_enabled', '凭证', '使用一次性或限次上网码', web.voucher_enabled, !writable)}${optionRow('radius_enabled', 'RADIUS', '通过 RADIUS 账号与记账服务验证', web.radius_enabled, !writable || !state.data.capabilities.radius_accounting)}</div></section>`;
    const oneWaySection = `<section class="user-auth-web-section"><header><strong>单向方法</strong></header><div class="user-auth-web-options">${optionRow('external_api_enabled', '外部门户服务器', '把访客重定向到外部认证门户', web.external_api_enabled, !writable)}</div></section>`;
    const designerSection = `<section class="user-auth-web-section"><header><strong>登录页设计器</strong></header><div class="user-auth-web-form">${textInput('标题', 'portal.title', { disabled: !writable })}${textInput('欢迎文本', 'portal.welcome_text', { disabled: !writable })}${textInput('按钮文本', 'portal.button_text', { disabled: !writable })}<label class="user-auth-web-checkline">${switchControl('portal.terms_enabled', portal.terms_enabled, !writable)}<span>服务条款</span></label><label class="user-auth-web-range"><span>徽标大小 <output>${firstNumber(portal.logo_size, 72)} px</output></span><input type="range" min="24" max="240" data-user-auth-web="portal.logo_size" value="${firstNumber(portal.logo_size, 72)}" ${writable ? '' : 'disabled'}></label>${textInput('更改徽标', 'portal.logo_url', { disabled: !writable })}<div class="user-auth-web-choice"><span>位置</span><div>${[['left','左'],['center','中'],['right','右']].map(([id, label]) => `<label><input type="radio" name="portal-logo-position" data-user-auth-web="portal.logo_position" value="${id}" ${firstText(portal.logo_position, 'center') === id ? 'checked' : ''} ${writable ? '' : 'disabled'}><span>${label}</span></label>`).join('')}</div></div><div class="user-auth-web-choice"><span>背景</span><div>${[['color','颜色'],['image','图片'],['gallery','图库']].map(([id, label]) => `<label><input type="radio" name="portal-background" data-user-auth-web="portal.background_type" value="${id}" ${firstText(portal.background_type, 'color') === id ? 'checked' : ''} ${writable && (id !== 'gallery' || state.data.capabilities.portal_gallery === true) ? '' : 'disabled'}><span>${label}</span></label>`).join('')}</div></div><div class="user-auth-web-colors">${colorInput('背景颜色', 'portal.background_color')}${colorInput('框颜色', 'portal.box_color')}${colorInput('文本颜色', 'portal.text_color')}${colorInput('按钮颜色', 'portal.button_color')}${colorInput('按钮文本颜色', 'portal.button_text_color')}${colorInput('链接颜色', 'portal.link_color')}</div><label class="user-auth-web-range"><span>框透明度 <output>${firstNumber(portal.box_opacity, 78)}%</output></span><input type="range" min="0" max="100" data-user-auth-web="portal.box_opacity" value="${firstNumber(portal.box_opacity, 78)}" ${writable ? '' : 'disabled'}></label><label class="user-auth-web-range"><span>框圆角半径 <output>${firstNumber(portal.box_radius, 12)} px</output></span><input type="range" min="0" max="64" data-user-auth-web="portal.box_radius" value="${firstNumber(portal.box_radius, 12)}" ${writable ? '' : 'disabled'}></label></div></section>`;
    const loginSection = `<section class="user-auth-web-section"><header><strong>登录页设置</strong></header><div class="user-auth-web-form"><label class="user-auth-web-field"><span>默认到期</span><select data-user-auth-web="default_expiration" ${writable ? '' : 'disabled'}>${[[480,'8 小时'],[1440,'24 小时'],[2880,'2 天'],[4320,'3 天'],[5760,'4 天'],[10080,'7 天']].map(([minutes, label]) => `<option value="${minutes}" ${firstNumber(web.default_expiration) === minutes ? 'selected' : ''}>${label}</option>`).join('')}</select></label>${textInput('语言', 'portal.languages', { disabled: !writable, fallback: 'zh-CN' })}${optionRow('enabled', '显示登录页', '向未授权客户端显示访客门户', web.enabled, !writable)}${optionRow('secure_portal', 'HTTPS 重定向支持', '通过 HTTPS 提供认证与成功页面', web.secure_portal, !writable)}${optionRow('encrypted_url', '加密 URL', '对门户重定向参数进行签名与加密', web.encrypted_url, !writable || state.data.capabilities.encrypted_portal_url !== true)}${optionRow('portal_domain_enabled', '域', '使用自定义门户域名', web.portal_domain_enabled, !writable || state.data.capabilities.portal_domain !== true)}</div></section>`;
    const accessSection = `<section class="user-auth-web-section"><header><strong>授权访问</strong></header><div class="user-auth-web-access"><div><span>授权前允许</span>${accessRows.filter((row) => row.scope === '认证前允许').map((row) => `<label><input value="${escapeHtml(row.value)}" disabled><button type="button" disabled aria-label="删除">${icon('trash')}</button></label>`).join('')}<button type="button" data-user-auth-action="add-access" ${writable ? '' : 'disabled'}>${icon('plus')}添加主机名、IP 或子网</button></div><div><span>认证后限制</span>${accessRows.filter((row) => row.scope === '认证后限制').map((row) => `<label><input value="${escapeHtml(row.value)}" disabled><button type="button" disabled aria-label="删除">${icon('trash')}</button></label>`).join('') || '<small>暂无限制</small>'}<button type="button" data-user-auth-action="add-access" ${writable ? '' : 'disabled'}>${icon('plus')}添加主机名、IP 或子网</button></div></div></section>`;
    const successSection = `<section class="user-auth-web-section"><header><strong>成功登录页</strong></header><div class="user-auth-web-form"><div class="user-auth-web-choice"><span>登录后</span><div>${[['message','成功消息'],['url','自定义 URL']].map(([id, label]) => `<label><input type="radio" name="portal-success-mode" data-user-auth-web="redirect_enabled" value="${id === 'url'}" ${(id === 'url') === Boolean(web.redirect_enabled) ? 'checked' : ''} ${writable ? '' : 'disabled'}><span>${label}</span></label>`).join('')}</div></div>${web.redirect_enabled ? textInput('自定义 URL', 'redirect_url', { disabled: !writable }) : textInput('成功文本', 'portal.success_text', { disabled: !writable })}</div></section>`;
    return `<div class="user-auth-web-designer dwrt-kit-glass-surface"><aside class="user-auth-web-controls">${methodSection}${oneWaySection}${designerSection}${loginSection}${accessSection}${successSection}<footer class="user-auth-web-savebar"><span><strong>WEB 认证</strong><small>${JSON.stringify(web) === JSON.stringify(state.data.web) ? '当前配置已同步' : '存在尚未保存的更改'}</small></span><div><button class="policy-secondary" type="button" data-user-auth-web-reset>复位</button><button class="policy-primary" type="button" data-user-auth-web-save ${writable && JSON.stringify(web) !== JSON.stringify(state.data.web) && !state.saving ? '' : 'disabled'}>${state.saving ? '正在保存' : writable ? '保存并应用' : '等待后端能力'}</button></div></footer></aside><main class="user-auth-web-preview-pane" data-user-auth-web-preview>${portalDevicePreview(portal)}</main></div>`;
  }

  function portalDevicePreview(portal = state.data.web.portal) {
    return `<div class="user-auth-device-frame"><div class="user-auth-device-camera"></div><div class="user-auth-device-screen">${portalPreview(portal)}</div></div>`;
  }

  function onlineRows() {
    return asArray(state.data.online_users).filter((user) => matchesQuery([user.account, user.username, user.name, user.auth_type, user.ip, user.mac, user.phone, user.interface, user.delegated_account, user.note])).map((user, index) => {
      const id = firstText(user.id, user.session_id, user.mac, user.ip, `online-${index}`);
      return `<tr>${selectedCell(id)}<td><strong>${escapeHtml(firstText(user.account, user.username, '--'))}</strong></td><td>${escapeHtml(firstText(user.name, '--'))}</td><td>${escapeHtml(firstText(user.auth_type, user.authentication_method, '--'))}</td><td><code>${escapeHtml(firstText(user.ip, '--'))}</code></td><td><code>${escapeHtml(firstText(user.mac, user.address, '--'))}</code></td><td>${escapeHtml(firstText(user.online_time, user.auth_time, '--'))}</td><td>${escapeHtml(firstText(user.phone, user.contact, '--'))}</td><td>${escapeHtml(firstText(user.interface, user.ifname, '--'))}</td><td>${escapeHtml(firstText(user.delegated_account, '--'))}</td><td>${escapeHtml(firstText(user.note, '--'))}</td><td><div class="user-auth-row-actions"><button class="user-auth-icon-button" type="button" data-user-auth-extend="${escapeHtml(id)}" ${capability('extend_session') ? '' : 'disabled'} aria-label="延长授权" data-dwrt-tooltip="延长授权">${icon('edit')}</button><button class="user-auth-icon-button danger" type="button" data-user-auth-disconnect="${escapeHtml(id)}" ${capability('disconnect') ? '' : 'disabled'} aria-label="下线" data-dwrt-tooltip="强制下线">${icon('disconnect')}</button></div></td></tr>`;
    });
  }

  function renderOnline() {
    const actions = `${actionButton('导出', 'export-online', 'export')}${actionButton(state.selected.size ? `延长 ${state.selected.size} 人` : '延长授权', 'extend-selected', 'edit', { disabled: !state.selected.size || !capability('extend_session') })}${actionButton(state.selected.size ? `下线 ${state.selected.size} 人` : '批量下线', 'disconnect-selected', 'disconnect', { primary: true, disabled: !state.selected.size || !capability('disconnect') })}`;
    return `${toolbarMarkup({ placeholder: '搜索账号、姓名、IP、MAC 或接口', actions })}${tableMarkup('在线用户', '当前已通过认证或拨号接入的用户', ['账号', '姓名', '认证类型', 'IP 地址', 'MAC / 地址', '上线时间', '联系方式', '接口', '代拨账号', '备注', '操作'], onlineRows(), '暂无在线认证用户', { select: true })}`;
  }

  function accountCollection() {
    const data = state.data.account_management;
    if (state.tab === 'packages') return data.packages;
    if (state.tab === 'accounts') return data.accounts;
    if (state.tab === 'ledger') return data.ledger;
    if (state.tab === 'vouchers') return data.vouchers;
    return [];
  }

  function accountRows() {
    const rows = accountCollection().filter((row) => {
      if (!matchesQuery(Object.values(row || {}))) return false;
      if (state.statusFilter === 'all') return true;
      if (state.tab === 'accounts') {
        if (state.statusFilter === 'expired') return bool(row.expired, false);
        if (state.statusFilter === 'disabled') return row.enabled === false && !bool(row.expired, false);
        if (state.statusFilter === 'enabled') return row.enabled !== false && !bool(row.expired, false);
      }
      if (state.tab === 'vouchers') {
        if (state.statusFilter === 'expired') return bool(row.expired, false);
        if (state.statusFilter === 'used') return bool(row.used, false);
        if (state.statusFilter === 'unused') return !bool(row.used, false) && !bool(row.expired, false);
      }
      return true;
    });
    if (state.tab === 'packages') return rows.map((row, index) => { const id = firstText(row.id, row.name, `package-${index}`); return `<tr>${selectedCell(id)}<td><strong>${escapeHtml(firstText(row.name, '--'))}</strong></td><td>${escapeHtml(firstText(row.validity, row.duration, '--'))}</td><td>${escapeHtml(firstText(row.price, row.fee, '--'))}</td><td>${escapeHtml(firstText(row.up_rate, row.upload, '--'))}</td><td>${escapeHtml(firstText(row.down_rate, row.download, '--'))}</td><td>${escapeHtml(firstText(row.note, '--'))}</td><td>${rowActions('package', id)}</td></tr>`; });
    if (state.tab === 'accounts') return rows.map((row, index) => { const id = firstText(row.id, row.account, row.username, `account-${index}`); return `<tr>${selectedCell(id)}<td><strong>${escapeHtml(firstText(row.account, row.username, '--'))}</strong></td><td>${escapeHtml(firstText(row.name, '--'))}</td><td>${escapeHtml(firstText(row.auth_type, row.type, '--'))}</td><td>${escapeHtml(firstText(row.package_name, row.package, '--'))}</td><td>${escapeHtml(firstText(row.expires_at, row.expiry, '--'))}</td><td>${escapeHtml(firstText(row.online_duration, row.duration, '--'))}</td><td>${statusPill(row.enabled === false ? '停用' : row.expired ? '过期' : '启用', row.enabled !== false && !row.expired, row.expired)}</td><td>${escapeHtml(firstText(row.note, '--'))}</td><td>${rowActions('account', id)}</td></tr>`; });
    if (state.tab === 'ledger') return rows.map((row, index) => { const id = firstText(row.id, `ledger-${index}`); return `<tr>${selectedCell(id)}<td>${escapeHtml(firstText(row.account, '--'))}</td><td>${escapeHtml(firstText(row.name, '--'))}</td><td>${escapeHtml(firstText(row.charged_at, row.time, '--'))}</td><td>${escapeHtml(firstText(row.operator, '--'))}</td><td>${escapeHtml(firstText(row.description, '--'))}</td><td>${escapeHtml(firstText(row.amount, '--'))}</td><td>${escapeHtml(firstText(row.note, '--'))}</td><td>${rowActions('ledger', id)}</td></tr>`; });
    return rows.map((row, index) => { const id = firstText(row.id, row.code, `voucher-${index}`); return `<tr>${selectedCell(id)}<td><code>${escapeHtml(firstText(row.code, '--'))}</code></td><td>${escapeHtml(firstText(row.expires_at, row.expiry, '--'))}</td><td>${escapeHtml(firstText(row.duration, '--'))}</td><td>${escapeHtml(firstText(row.used_by, row.usage, '未使用'))}</td><td>${statusPill(row.used ? '已使用' : row.expired ? '已过期' : '未使用', !row.used && !row.expired, row.expired)}</td><td>${escapeHtml(firstText(row.note, '--'))}</td><td>${rowActions('voucher', id)}</td></tr>`; });
  }

  function rowActions(kind, id) {
    const action = kind === 'delegated' ? 'write_delegated' : kind === 'periodic' ? 'write_notifications' : 'write_accounts';
    const writable = capability(action);
    return `<div class="user-auth-row-actions"><button class="user-auth-icon-button" type="button" data-user-auth-edit="${escapeHtml(kind)}" data-user-auth-id="${escapeHtml(id)}" ${writable ? '' : 'disabled'} aria-label="编辑">${icon('edit')}</button><button class="user-auth-icon-button danger" type="button" data-user-auth-delete="${escapeHtml(kind)}" data-user-auth-id="${escapeHtml(id)}" ${writable ? '' : 'disabled'} aria-label="删除">${icon('trash')}</button></div>`;
  }

  function renderPasswordPolicy() {
    const policy = state.data.account_management.password_policy;
    return `<section class="user-auth-settings-panel user-auth-password-panel dwrt-kit-glass-surface"><header><div><span>SELF SERVICE</span><strong>自助密码管理</strong></div>${statusPill(policy.enabled ? '已启用' : '已关闭', policy.enabled)}</header><div class="user-auth-setting-list">${switchField('启用自助密码管理', '认证用户可打开自助页面修改密码', 'enabled', policy.enabled, true)}${switchField('允许 PPPoE 用户修改密码', '适用于 PPPoE 认证账号', 'pppoe', policy.pppoe, true)}${switchField('允许 L2TP 用户修改密码', '适用于 L2TP 认证账号', 'l2tp', policy.l2tp, true)}${switchField('允许 PPTP 用户修改密码', '适用于 PPTP 认证账号', 'pptp', policy.pptp, true)}${switchField('允许 OpenVPN 用户修改密码', '适用于 OpenVPN 认证账号', 'openvpn', policy.openvpn, true)}${switchField('允许 WEB 认证用户修改密码', '门户认证用户可自助修改密码', 'web_change', policy.web_change, true)}${switchField('允许 WEB 认证用户退出登录', '门户提供主动退出入口', 'web_logout', policy.web_logout, true)}</div><footer><button class="policy-primary" type="button" data-user-auth-action="edit-password-policy" ${capability('write_accounts') ? '' : 'disabled'}>编辑设置</button></footer></section>`;
  }

  function renderAccounts() {
    if (state.tab === 'password') return `${toolbarMarkup({ search: false })}${renderPasswordPolicy()}`;
    const labels = {
      packages: ['套餐管理', '认证账号可使用的有效期、价格和速率套餐', ['套餐名称', '有效期', '套餐价格', '上行带宽', '下行带宽', '备注', '操作']],
      accounts: ['账号管理', 'WEB、PPPoE 与 VPN 认证账号', ['账号', '用户姓名', '认证类型', '当前套餐', '到期时间', '在线 / 离线时长', '状态', '备注', '操作']],
      ledger: ['总账管理', '账号收费与续费记录', ['账号', '用户姓名', '收费时间', '收费人员', '描述', '收费金额（元）', '备注', '操作']],
      vouchers: ['上网码', '用于访客门户的一次性或限时凭证', ['上网码', '过期时间', '限时', '使用记录', '状态', '备注', '操作']]
    };
    const [title, subtitle, headings] = labels[state.tab];
    const createLabel = state.tab === 'vouchers' ? '批量生成' : state.tab === 'ledger' ? '' : '添加';
    const voucherActions = state.tab === 'vouchers' ? `${actionButton('打印', 'print-vouchers', 'preview')}${actionButton('清理失效', 'clean-vouchers', 'trash', { disabled: !capability('write_accounts') })}` : '';
    const batchActions = state.tab === 'accounts' ? `${actionButton(state.selected.size ? `启用 ${state.selected.size} 项` : '批量启用', 'enable-selected', 'preview', { disabled: !state.selected.size || !capability('write_accounts') })}${actionButton(state.selected.size ? `停用 ${state.selected.size} 项` : '批量停用', 'disable-selected', 'disconnect', { disabled: !state.selected.size || !capability('write_accounts') })}` : '';
    const actions = `${batchActions}${voucherActions}${state.tab !== 'ledger' ? actionButton('导入', 'import-accounts', 'import', { disabled: !capability('write_accounts') }) : ''}${actionButton('导出', 'export-accounts', 'export')}${createLabel ? actionButton(createLabel, `add-${state.tab}`, 'plus', { primary: true, disabled: !capability('write_accounts') }) : ''}`;
    const leading = state.tab === 'accounts' || state.tab === 'vouchers' ? `<div class="user-auth-segmented">${(state.tab === 'accounts' ? [['all','全部'],['enabled','已启用'],['disabled','已停用'],['expired','已过期']] : [['all','全部'],['used','已使用'],['unused','未使用'],['expired','已过期']]).map(([id, label]) => `<button type="button" data-user-auth-filter="${id}" class="${state.statusFilter === id ? 'is-active' : ''}">${label}</button>`).join('')}</div>${searchMarkup(state.tab === 'accounts' ? '搜索账号、姓名或备注' : '搜索上网码或备注')}` : searchMarkup(state.tab === 'packages' ? '套餐名称 / 备注' : '搜索账号、人员或描述');
    return `${toolbarMarkup({ leading, actions })}${tableMarkup(title, subtitle, headings, accountRows(), '暂无内容', { select: true })}`;
  }

  function delegatedRows() {
    const collection = state.tab === 'online' ? state.data.delegated.online : state.data.delegated.services;
    return asArray(collection).filter((row) => matchesQuery(Object.values(row || {}))).map((row, index) => {
      const id = firstText(row.id, row.account, `delegated-${index}`);
      if (state.tab === 'online') return `<tr><td><strong>${escapeHtml(firstText(row.account, '--'))}</strong></td><td><code>${escapeHtml(firstText(row.ip, row.pppoe_ip_addr, '--'))}</code></td><td><code>${escapeHtml(firstText(row.netmask, row.pppoe_netmask, '--'))}</code></td><td><code>${escapeHtml(firstText(row.gateway, row.pppoe_gateway, '--'))}</code></td><td>${escapeHtml(firstText(row.delegated_account, '--'))}</td><td>${escapeHtml(firstText(row.note, '--'))}</td></tr>`;
      return `<tr>${selectedCell(id)}<td><strong>${escapeHtml(firstText(row.name, row.line_name, '--'))}</strong></td><td>${escapeHtml(firstText(row.account, '--'))}</td><td>${row.has_password ? '••••••••' : '--'}</td><td>${escapeHtml(firstText(row.interface, '--'))}</td><td>${escapeHtml(firstText(row.delegated_account, '--'))}</td><td>${statusPill(row.enabled === false ? '停用' : '启用', row.enabled !== false)}</td><td>${escapeHtml(firstText(row.note, '--'))}</td><td>${rowActions('delegated', id)}</td></tr>`;
    });
  }

  function renderDelegated() {
    const online = state.tab === 'online';
    const actions = `${!online ? actionButton('导入', 'import-delegated', 'import', { disabled: !capability('write_delegated') }) : ''}${actionButton('导出', 'export-delegated', 'export')}${!online ? actionButton('添加', 'add-delegated', 'plus', { primary: true, disabled: !capability('write_delegated') }) : ''}`;
    return `${toolbarMarkup({ placeholder: online ? '代拨账号 / 备注' : '搜索线路、账号、接口或备注', actions })}${online ? tableMarkup('在线账号列表', '当前代拨连接获得的地址与网关', ['代拨账号', 'IP 地址', '子网掩码', '网关', '被代拨账号', '备注'], delegatedRows(), '暂无在线代拨账号') : tableMarkup('代拨账号管理', '上游拨号账号与下游被代拨账号映射', ['代拨线路名称', '代拨账号', '代拨密码', '代拨接口', '被代拨账号', '状态', '备注', '操作'], delegatedRows(), '暂无代拨服务', { select: true })}`;
  }

  function richEditor(value, key) {
    return `<div class="user-auth-rich-editor"><div class="user-auth-rich-toolbar" role="toolbar" aria-label="通知格式"><button type="button" data-user-auth-format="bold"><strong>B</strong></button><button type="button" data-user-auth-format="italic"><i>I</i></button><button type="button" data-user-auth-format="underline"><u>U</u></button><select data-user-auth-format-select="block"><option value="p">段落</option><option value="h2">标题</option><option value="h3">小标题</option></select><select data-user-auth-format-select="size"><option value="3">字号</option><option value="2">小</option><option value="4">大</option></select><button type="button" data-user-auth-format="insertUnorderedList">• 列表</button><button type="button" data-user-auth-format="insertOrderedList">1. 列表</button></div><div class="user-auth-rich-content" contenteditable="true" data-user-auth-rich="${escapeHtml(key)}">${sanitizeRichHtml(value)}</div></div>`;
  }

  function sanitizeRichHtml(value) {
    const template = document.createElement('template');
    template.innerHTML = String(value || '');
    const allowed = new Set(['P', 'BR', 'STRONG', 'B', 'EM', 'I', 'U', 'UL', 'OL', 'LI', 'H2', 'H3', 'A']);
    Array.from(template.content.querySelectorAll('*')).forEach((node) => {
      if (!allowed.has(node.tagName)) { node.replaceWith(...node.childNodes); return; }
      Array.from(node.attributes).forEach((attribute) => {
        if (node.tagName === 'A' && attribute.name === 'href' && /^(https?:|\/)/i.test(attribute.value)) return;
        node.removeAttribute(attribute.name);
      });
      if (node.tagName === 'A') node.setAttribute('rel', 'noopener noreferrer');
    });
    return template.innerHTML;
  }

  function notificationForm(kind) {
    const data = state.notificationDraft || clone(state.data.notifications[kind] || {});
    if (!state.notificationDraft) state.notificationDraft = data;
    if (kind === 'realtime') return `<section class="user-auth-notification-form dwrt-kit-glass-surface"><header><div><span>REALTIME NOTICE</span><strong>实时通知</strong></div></header>${richEditor(data.content, 'content')}<div class="user-auth-form-grid">${field('跳转页面', 'redirect_url', data.redirect_url, { wide: true, placeholder: 'https://example.com' })}${field('显示倒计时（秒）', 'countdown', data.countdown, { type: 'number', min: 0, max: 86400 })}${switchField('拨号用户', '向所有在线拨号用户推送', 'dial_users', data.dial_users)}${switchField('指定内网用户', '向 IP 列表或 IP 分组推送', 'lan_users', data.lan_users)}${field('IP 设置', 'targets', asArray(data.targets).join('\n'), { tag: 'textarea', wide: true, placeholder: '192.168.30.10\n192.168.30.0/24' })}${field('IP 分组', 'groups', asArray(data.groups).join(', '), { wide: true })}</div>${notificationFooter(kind)}</section>`;
    if (kind === 'expiry') return `<section class="user-auth-notification-form dwrt-kit-glass-surface"><header><div><span>EXPIRY NOTICE</span><strong>到期通知</strong></div>${statusPill(data.enabled ? '已启用' : '未启用', data.enabled)}</header>${richEditor(data.content, 'content')}<div class="user-auth-form-grid">${switchField('到期提醒', '在账号到期前按计划推送提醒', 'enabled', data.enabled)}${field('跳转页面', 'redirect_url', data.redirect_url, { wide: true })}${field('提前到期提醒（天）', 'days_before', data.days_before, { type: 'number', min: 1, max: 365 })}${field('定时提醒', 'times', asArray(data.times).join(', '), { placeholder: '08:00, 16:00' })}${field('显示倒计时（秒）', 'countdown', data.countdown, { type: 'number', min: 0, max: 86400 })}</div>${notificationFooter(kind)}</section>`;
    return `<section class="user-auth-notification-form dwrt-kit-glass-surface"><header><div><span>EXPIRED USER NOTICE</span><strong>拨号用户过期通知</strong></div></header>${richEditor(data.content, 'content')}<div class="user-auth-form-grid">${field('白名单公网 IP', 'public_ip_allowlist', asArray(data.public_ip_allowlist).join('\n'), { tag: 'textarea', wide: true, placeholder: '203.0.113.0/24', help: '每行一个地址或网段，单次最多 1000 条。' })}${field('白名单域名', 'domain_allowlist', asArray(data.domain_allowlist).join('\n'), { tag: 'textarea', wide: true, placeholder: 'example.com', help: '每行一个域名，单次最多 1000 条。' })}</div>${notificationFooter(kind)}</section>`;
  }

  function notificationFooter(kind) {
    return `<footer class="user-auth-form-footer"><button class="policy-secondary" type="button" data-user-auth-action="preview-notification">${icon('preview')}<span>通知预览</span></button><button class="policy-primary" type="button" data-user-auth-action="save-notification" data-kind="${kind}" ${capability('write_notifications') ? '' : 'disabled'}>保存</button></footer>`;
  }

  function periodicRows() {
    return asArray(state.data.notifications.periodic).filter((row) => matchesQuery(Object.values(row || {}))).map((row, index) => { const id = firstText(row.id, row.name, `periodic-${index}`); return `<tr>${selectedCell(id)}<td><strong>${escapeHtml(firstText(row.name, '--'))}</strong></td><td>${escapeHtml(firstText(row.recipients, row.targets, '--'))}</td><td>${escapeHtml(firstText(row.schedule, row.period, '--'))}</td><td>${escapeHtml(firstText(row.time, '--'))}</td><td>${statusPill(row.enabled === false ? '停用' : '启用', row.enabled !== false)}</td><td>${escapeHtml(firstText(row.note, '--'))}</td><td>${rowActions('periodic', id)}</td></tr>`; });
  }

  function renderNotifications() {
    if (state.tab !== 'periodic') return `${toolbarMarkup({ search: false })}${notificationForm(state.tab)}`;
    const actions = actionButton('添加', 'add-periodic', 'plus', { primary: true, disabled: !capability('write_notifications') });
    return `${toolbarMarkup({ placeholder: '搜索名称、接收对象或备注', actions })}${tableMarkup('定期通知', '按周期和指定时间向认证用户推送页面通知', ['名称', '接收对象', '推送周期', '推送时间', '状态', '备注', '操作'], periodicRows(), '暂无定期通知', { select: true })}`;
  }

  function mainMarkup() {
    if (state.page === 'web') return renderWeb();
    if (state.page === 'online') return renderOnline();
    if (state.page === 'accounts') return renderAccounts();
    if (state.page === 'delegated') return renderDelegated();
    return renderNotifications();
  }

  function findEditorItem(kind, id) {
    const collection = kind === 'package' ? state.data.account_management.packages
      : kind === 'account' ? state.data.account_management.accounts
        : kind === 'ledger' ? state.data.account_management.ledger
          : kind === 'voucher' ? state.data.account_management.vouchers
            : kind === 'delegated' ? state.data.delegated.services
              : kind === 'periodic' ? state.data.notifications.periodic : [];
    return asArray(collection).find((row, index) => firstText(row.id, row.name, row.account, row.username, row.code, `${kind}-${index}`) === id) || {};
  }

  function openEditor(kind, id = '') {
    state.drawer = kind;
    state.confirmDelete = false;
    if (kind === 'web') state.editor = clone(state.data.web);
    else if (kind === 'portal') state.editor = clone(state.data.web.portal);
    else if (kind === 'password-policy') state.editor = clone(state.data.account_management.password_policy);
    else if (kind === 'access') state.editor = { _new: true, scope: 'pre_authorization', type: 'cidr', value: '' };
    else if (kind === 'voucher-print') state.editor = { scope: state.selected.size ? 'selected' : 'unused', batch: '' };
    else state.editor = { ...clone(findEditorItem(kind, id)), _new: !id, _id: id };
    render();
  }

  function drawerTitle() {
    const labels = { web: '编辑 WEB 认证设置', portal: '编辑门户页面', 'password-policy': '编辑自助密码设置', access: '添加访问控制规则', package: '认证套餐', account: '认证账号', voucher: '上网码', 'voucher-print': '打印上网码', delegated: '代拨账号', periodic: '定期通知', ledger: '账目记录', 'import-accounts': '导入账号数据', 'import-delegated': '导入代拨账号' };
    return `${state.editor._new ? '新建' : '编辑'}${labels[state.drawer] || '配置'}`.replace('新建编辑', '编辑').replace('编辑编辑', '编辑');
  }

  function editorFields() {
    const editor = state.editor;
    if (state.drawer === 'web') return `<div class="user-auth-drawer-section"><strong>服务设置</strong>${switchField('启用 WEB 认证', '将未授权客户端重定向至门户', 'enabled', editor.enabled)}${switchField('安全门户', '启用 HTTPS 门户', 'secure_portal', editor.secure_portal)}${switchField('认证后跳转', '认证成功后跳转到自定义网址', 'redirect_enabled', editor.redirect_enabled)}</div><div class="user-auth-form-grid">${field('应用网络', 'networks', asArray(editor.networks).map((value) => firstText(value.name, value.id, value)).join(', '), { wide: true, placeholder: '访客网络, Hotspot' })}${field('默认授权时长', 'default_expiration', editor.default_expiration, { type: 'number', min: 1 })}${field('时长单位', 'expiration_unit', editor.expiration_unit, { tag: 'select', options: [['minutes','分钟'],['hours','小时'],['days','天']] })}${field('空闲超时（分钟）', 'idle_timeout', editor.idle_timeout, { type: 'number', min: 0 })}${field('门户域名', 'portal_hostname', editor.portal_hostname, { placeholder: 'guest.example.com' })}${editor.redirect_enabled ? field('成功跳转 URL', 'redirect_url', editor.redirect_url, { wide: true, placeholder: 'https://example.com' }) : ''}</div><div class="user-auth-drawer-section"><strong>认证方式</strong>${switchField('免费访问', '无需账号直接授权', 'free_access_enabled', editor.free_access_enabled)}${switchField('访客密码', '共享密码认证', 'password_enabled', editor.password_enabled)}${switchField('上网码', '券码认证', 'voucher_enabled', editor.voucher_enabled)}${switchField('RADIUS', 'RADIUS 账号认证', 'radius_enabled', editor.radius_enabled)}${switchField('外部 API', '外部认证服务', 'external_api_enabled', editor.external_api_enabled)}${switchField('支付认证', '支付套餐后授权', 'payment_enabled', editor.payment_enabled)}${switchField('Google 登录', '使用 Google 账号授权', 'google_enabled', editor.google_enabled)}</div><div class="user-auth-form-grid">${editor.password_enabled ? field('访客密码', 'guest_password', '', { type: 'password', wide: true, placeholder: editor.has_guest_password ? '留空保持现有密码' : '设置共享访客密码' }) : ''}${editor.voucher_enabled ? field('上网码默认套餐', 'voucher_default_package_id', editor.voucher_default_package_id, { wide: true }) : ''}${editor.radius_enabled ? `${field('RADIUS Profile', 'radius_profile_id', editor.radius_profile_id, { required: true })}${field('认证协议', 'radius_auth_type', editor.radius_auth_type, { tag: 'select', options: [['chap','CHAP'],['pap','PAP'],['mschapv2','MS-CHAPv2']] })}${switchField('接收 Disconnect Request', '允许 RADIUS 服务器主动断开会话', 'radius_disconnect_enabled', editor.radius_disconnect_enabled)}${field('Disconnect 端口', 'radius_disconnect_port', editor.radius_disconnect_port, { type: 'number', min: 1, max: 65535 })}` : ''}${editor.external_api_enabled ? `${field('外部认证页面 URL', 'external_api_url', editor.external_api_url, { wide: true, placeholder: 'https://portal.example.com' })}${field('外部授权 API URL', 'external_api_auth_url', editor.external_api_auth_url, { wide: true, placeholder: 'https://api.example.com/authorize' })}` : ''}${editor.google_enabled ? `${field('Google Client ID', 'google_client_id', editor.google_client_id, { wide: true })}${field('允许的 Google 域', 'google_domain', editor.google_domain, { wide: true, placeholder: 'example.com' })}` : ''}${editor.payment_enabled ? `${field('支付提供方', 'payment_provider', editor.payment_provider, { placeholder: 'stripe / alipay' })}${field('结算货币', 'payment_currency', editor.payment_currency, { placeholder: 'CNY' })}${field('可购买套餐', 'payment_package_ids', asArray(editor.payment_package_ids).join(', '), { wide: true })}` : ''}</div>`;
    if (state.drawer === 'portal') return `<div class="user-auth-form-grid">${field('页面标题', 'title', editor.title, { wide: true, required: true })}${field('欢迎语', 'welcome_text', editor.welcome_text, { tag: 'textarea', wide: true })}${field('认证提示', 'authentication_text', editor.authentication_text, { tag: 'textarea', wide: true })}${field('成功提示', 'success_text', editor.success_text, { tag: 'textarea', wide: true })}${field('按钮文字', 'button_text', editor.button_text)}${field('语言', 'languages', asArray(editor.languages).join(', '), { placeholder: 'zh-CN, en-US' })}${field('背景类型', 'background_type', editor.background_type, { tag: 'select', options: [['color','纯色'],['image','背景图片']] })}${field('背景颜色', 'background_color', editor.background_color, { type: 'color' })}${editor.background_type === 'image' ? `${field('背景图片 URL', 'background_image_url', editor.background_image_url, { wide: true })}${switchField('平铺背景图片', '以原始尺寸重复背景图片', 'background_tile', editor.background_tile)}` : ''}${field('认证框颜色', 'box_color', editor.box_color, { type: 'color' })}${field('认证框透明度', 'box_opacity', editor.box_opacity, { type: 'number', min: 0, max: 100 })}${field('认证框圆角', 'box_radius', editor.box_radius, { type: 'number', min: 0, max: 64 })}${field('文字颜色', 'text_color', editor.text_color, { type: 'color' })}${field('链接颜色', 'link_color', editor.link_color, { type: 'color' })}${field('按钮颜色', 'button_color', editor.button_color, { type: 'color' })}${field('按钮文字颜色', 'button_text_color', editor.button_text_color, { type: 'color' })}</div><div class="user-auth-drawer-section"><strong>徽标与条款</strong>${switchField('显示徽标', '在门户认证框中显示品牌徽标', 'logo_enabled', editor.logo_enabled)}${editor.logo_enabled ? `<div class="user-auth-form-grid">${field('徽标 URL', 'logo_url', editor.logo_url, { wide: true })}${field('徽标位置', 'logo_position', editor.logo_position, { tag: 'select', options: [['top','顶部'],['center','居中'],['bottom','底部']] })}${field('徽标尺寸', 'logo_size', editor.logo_size, { type: 'number', min: 24, max: 320 })}</div>` : ''}${switchField('要求接受条款', '授权前必须确认门户条款', 'terms_enabled', editor.terms_enabled)}${editor.terms_enabled ? field('条款内容', 'terms_text', editor.terms_text, { tag: 'textarea', wide: true }) : ''}</div>`;
    if (state.drawer === 'password-policy') return `<div class="user-auth-drawer-section">${switchField('启用自助密码管理', '开放用户自助修改与退出能力', 'enabled', editor.enabled)}${switchField('PPPoE 修改密码', '允许 PPPoE 用户修改', 'pppoe', editor.pppoe)}${switchField('L2TP 修改密码', '允许 L2TP 用户修改', 'l2tp', editor.l2tp)}${switchField('PPTP 修改密码', '允许 PPTP 用户修改', 'pptp', editor.pptp)}${switchField('OpenVPN 修改密码', '允许 OpenVPN 用户修改', 'openvpn', editor.openvpn)}${switchField('WEB 修改密码', '允许 WEB 用户修改', 'web_change', editor.web_change)}${switchField('WEB 退出登录', '允许 WEB 用户退出', 'web_logout', editor.web_logout)}</div>`;
    if (state.drawer === 'access') return `<div class="user-auth-form-grid">${field('规则范围', 'scope', editor.scope, { tag: 'select', options: [['pre_authorization','认证前放行'],['post_authorization','认证后限制'],['restricted_dns','受限 DNS']] })}${field('地址类型', 'type', editor.type, { tag: 'select', options: [['cidr','IP / 网段'],['domain','域名'],['dns','DNS 服务器']] })}${field('地址 / 域名', 'value', editor.value, { wide: true, required: true, placeholder: '192.168.30.0/24 或 example.com' })}</div>`;
    if (state.drawer === 'package') return `<div class="user-auth-form-grid">${field('套餐名称', 'name', editor.name, { wide: true, required: true })}${field('有效期', 'validity', editor.validity, { placeholder: '30 天' })}${field('套餐价格', 'price', editor.price, { type: 'number', min: 0 })}${field('上行带宽', 'up_rate', editor.up_rate, { placeholder: '10 Mbps' })}${field('下行带宽', 'down_rate', editor.down_rate, { placeholder: '100 Mbps' })}${field('备注', 'note', editor.note, { tag: 'textarea', wide: true })}</div>`;
    if (state.drawer === 'account') return `<div class="user-auth-form-grid">${field('账号', 'account', editor.account, { wide: true, required: true })}${field('用户姓名', 'name', editor.name)}${field('认证类型', 'auth_type', editor.auth_type || 'web_account', { tag: 'select', options: [['web_account','WEB 账号'],['pppoe','PPPoE'],['pppoe_relay','PPPoE 透传'],['l2tp','L2TP'],['pptp','PPTP'],['openvpn','OpenVPN']] })}${field('密码', 'password', '', { type: 'password', placeholder: editor._new ? '设置密码' : '留空保持现有密码' })}${field('当前套餐', 'package_id', editor.package_id)}${field('到期时间', 'expires_at', editor.expires_at, { type: 'datetime-local' })}${field('绑定 MAC', 'mac', editor.mac, { placeholder: 'AA:BB:CC:DD:EE:FF' })}${field('允许地址', 'source_addresses', asArray(editor.source_addresses).join('\n'), { tag: 'textarea', wide: true })}${field('联系方式', 'phone', editor.phone)}${field('备注', 'note', editor.note, { tag: 'textarea', wide: true })}</div>`;
    if (state.drawer === 'voucher') return `<div class="user-auth-form-grid">${field('上网码', 'code', editor.code, { wide: true, placeholder: '留空由后端生成' })}${field('生成数量', 'count', editor.count || 1, { type: 'number', min: 1, max: 10000 })}${field('码长度', 'length', editor.length || 12, { type: 'number', min: 6, max: 64 })}${field('过期时间', 'expires_at', editor.expires_at, { type: 'datetime-local' })}${field('限时', 'duration', editor.duration, { placeholder: '8 小时' })}${field('使用次数', 'quota', editor.quota || 1, { type: 'number', min: 1 })}${field('上行带宽', 'up_rate', editor.up_rate)}${field('下行带宽', 'down_rate', editor.down_rate)}${field('备注', 'note', editor.note, { tag: 'textarea', wide: true })}</div>`;
    if (state.drawer === 'voucher-print') return `<div class="user-auth-form-grid">${field('打印范围', 'scope', editor.scope, { tag: 'select', wide: true, options: [['selected','当前选择'],['unused','全部未使用'],['all','全部上网码'],['batch','指定批次']] })}${editor.scope === 'batch' ? field('批次标识', 'batch', editor.batch, { wide: true, required: true }) : ''}</div><div class="user-auth-capability">打印使用当前已加载的数据生成独立打印页，不会修改上网码状态。</div>`;
    if (state.drawer === 'import-accounts' || state.drawer === 'import-delegated') {
      const rows = asArray(editor.rows);
      return `<div class="user-auth-import-summary"><strong>${escapeHtml(editor.file_name || '导入文件')}</strong><span>${rows.length} 条记录</span></div>${asArray(editor.errors).length ? `<div class="user-auth-import-errors">${editor.errors.map((error) => `<span>${escapeHtml(error)}</span>`).join('')}</div>` : `<div class="user-auth-import-preview">${rows.slice(0, 8).map((row) => `<div><strong>${escapeHtml(firstText(row.account, row.code, row.name, '--'))}</strong><span>${escapeHtml(firstText(row.auth_type, row.interface, row.note, '待导入'))}</span></div>`).join('')}${rows.length > 8 ? `<small>另有 ${rows.length - 8} 条记录</small>` : ''}</div>`}`;
    }
    if (state.drawer === 'delegated') return `<div class="user-auth-drawer-section">${switchField('启用代拨', '允许下游账号使用该上游拨号连接', 'enabled', editor.enabled !== false)}</div><div class="user-auth-form-grid">${field('代拨线路名称', 'name', editor.name, { wide: true, required: true })}${field('代拨账号', 'account', editor.account, { required: true })}${field('代拨密码', 'password', '', { type: 'password', placeholder: editor._new ? '输入密码' : '留空保持现有密码' })}${field('代拨接口', 'interface', editor.interface, { placeholder: 'wan' })}${field('被代拨账号', 'delegated_account', editor.delegated_account, { wide: true })}${field('备注', 'note', editor.note, { tag: 'textarea', wide: true })}</div>`;
    if (state.drawer === 'periodic') return `<div class="user-auth-drawer-section">${switchField('启用通知', '按设定周期推送页面通知', 'enabled', editor.enabled !== false)}</div><div class="user-auth-form-grid">${field('名称', 'name', editor.name, { wide: true, required: true })}${field('接收对象', 'recipients', editor.recipients, { wide: true, placeholder: '拨号用户、IP 分组或地址列表' })}${field('推送周期', 'schedule', editor.schedule, { placeholder: '每天 / 每周一' })}${field('推送时间', 'time', editor.time, { type: 'time' })}${field('跳转页面', 'redirect_url', editor.redirect_url, { wide: true })}${field('倒计时（秒）', 'countdown', editor.countdown || 60, { type: 'number', min: 0 })}${field('通知内容', 'content', editor.content, { tag: 'textarea', wide: true })}${field('备注', 'note', editor.note, { tag: 'textarea', wide: true })}</div>`;
    return '';
  }

  function drawerMarkup() {
    if (!state.drawer) return '';
    const writeAction = ['web', 'portal', 'access'].includes(state.drawer) ? 'update_web' : state.drawer === 'password-policy' ? 'write_accounts' : state.drawer === 'delegated' ? 'write_delegated' : state.drawer === 'periodic' ? 'write_notifications' : state.drawer === 'import-delegated' ? 'write_delegated' : 'write_accounts';
    const localAction = state.drawer === 'voucher-print';
    const writable = (localAction || capability(writeAction)) && !asArray(state.editor.errors).length;
    const canDelete = !state.editor._new && ['package', 'account', 'voucher', 'delegated', 'periodic', 'ledger'].includes(state.drawer);
    const saveLabel = state.drawer === 'voucher-print' ? '打开打印页' : state.drawer.startsWith('import-') ? '确认导入' : '保存并应用';
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-user-auth-close aria-label="关闭设置"></button><aside class="user-auth-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" aria-label="${escapeHtml(drawerTitle())}"><header class="dwrt-kit-sheet-header"><div><span>USER AUTHENTICATION</span><strong>${escapeHtml(drawerTitle())}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-user-auth-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body user-auth-drawer-body">${editorFields()}${!writable ? '<div class="user-auth-capability">后端写入合同尚未开放。当前可以核对完整字段，但不会把配置写入浏览器、localStorage 或 /etc/config。</div>' : ''}${state.notice ? noticeMarkup() : ''}</div><footer class="dwrt-kit-sheet-footer user-auth-drawer-footer">${canDelete ? `<button class="policy-secondary danger" type="button" data-user-auth-delete-editor ${state.saving ? 'disabled' : ''}>${state.confirmDelete ? '再次点击确认删除' : '删除'}</button>` : '<span></span>'}<div><button class="policy-secondary" type="button" data-user-auth-close>取消</button><button class="policy-primary" type="button" data-user-auth-save ${writable && !state.saving ? '' : 'disabled'}>${state.saving ? '正在处理' : writable ? saveLabel : '等待后端能力'}</button></div></footer></aside>`;
  }

  function previewMarkup() {
    if (!state.preview) return '';
    const content = state.page === 'web' ? portalPreview(state.data.web.portal) : `<div class="user-auth-notice-preview"><header>Dreaming OS 网络通知</header><div>${sanitizeRichHtml(state.notificationDraft?.content || '通知内容预览')}</div><button type="button">确定</button></div>`;
    return `<button class="user-auth-preview-overlay" type="button" data-user-auth-preview-close aria-label="关闭预览"></button><section class="user-auth-preview-dialog dwrt-kit-glass-surface" role="dialog" aria-modal="true"><header><strong>${state.page === 'web' ? '门户页面预览' : '认证通知预览'}</strong><button type="button" data-user-auth-preview-close aria-label="关闭">×</button></header>${content}</section>`;
  }

  function render() {
    if (!root) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'policy-table-route-host', MODULE_CLASS);
    const tabs = tabsMarkup();
    // 「在线用户」等页面没有二级 tab，此前 header 直接不渲染，
    // 导致 alignPageToolbar() 找不到宿主、工具栏留在 workbench 内，
    // 页面顶部出现一整条空白带。只要该页有工具栏就必须建出 header。
    const needsHeader = Boolean(tabs) || state.page !== 'web';
    root.innerHTML = `<section class="user-auth-shell is-${state.page}">${needsHeader ? `<header class="user-auth-page-header${tabs ? '' : ' is-toolbar-only'}">${tabs}</header>` : ''}${noticeMarkup()}<main class="user-auth-workbench">${mainMarkup()}</main>${drawerMarkup()}${previewMarkup()}<input type="file" data-user-auth-import-file accept=".json,.csv,application/json,text/csv" hidden></section>`;
    alignPageToolbar();
    ui.mountAll?.(root);
  }

  function alignPageToolbar() {
    const header = root?.querySelector('.user-auth-page-header');
    const toolbar = root?.querySelector('.user-auth-workbench > .user-auth-toolbar');
    if (!header) return;
    header.querySelectorAll(':scope > .user-auth-toolbar').forEach((node) => node.remove());
    if (toolbar) header.appendChild(toolbar);
    // 没有 tab 也没有工具栏时不要留下一个空的 header 占位。
    if (!header.children.length) header.remove();
  }

  function patchWorkbench() {
    const current = root?.querySelector('.user-auth-workbench');
    if (!current) { render(); return; }
    current.innerHTML = mainMarkup();
    const oldNotice = root.querySelector(':scope .user-auth-shell > .user-auth-notice');
    oldNotice?.remove();
    const notice = noticeMarkup();
    if (notice) current.insertAdjacentHTML('beforebegin', notice);
    alignPageToolbar();
    ui.mountAll?.(root);
  }

  function webDirty() {
    return JSON.stringify(state.webDraft || state.data.web) !== JSON.stringify(state.data.web);
  }

  function patchWebDesigner() {
    const preview = root?.querySelector('[data-user-auth-web-preview]');
    if (preview) preview.innerHTML = portalDevicePreview((state.webDraft || state.data.web).portal);
    root?.querySelectorAll('.user-auth-web-range').forEach((row) => {
      const input = row.querySelector('[data-user-auth-web]');
      const output = row.querySelector('output');
      if (!input || !output) return;
      output.textContent = `${input.value}${input.dataset.userAuthWeb.includes('opacity') ? '%' : ' px'}`;
    });
    root?.querySelectorAll('.user-auth-web-color').forEach((row) => {
      const input = row.querySelector('input[type="color"][data-user-auth-web]');
      const code = row.querySelector('code');
      if (input && code) code.textContent = input.value.toUpperCase();
    });
    const status = root?.querySelector('.user-auth-web-savebar small');
    if (status) status.textContent = webDirty() ? '存在尚未保存的更改' : '当前配置已同步';
    const save = root?.querySelector('[data-user-auth-web-save]');
    if (save) save.disabled = !capability('update_web') || !webDirty() || state.saving;
  }

  function rerenderWebDesigner() {
    const current = root?.querySelector('.user-auth-web-designer');
    if (!current) { render(); return; }
    const top = current.querySelector('.user-auth-web-controls')?.scrollTop || 0;
    const template = document.createElement('template');
    template.innerHTML = renderWeb();
    const next = template.content.firstElementChild;
    if (!next) return;
    current.replaceWith(next);
    const controls = next.querySelector('.user-auth-web-controls');
    if (controls) controls.scrollTop = top;
    ui.mountAll?.(next);
  }

  async function saveWebDesigner() {
    if (!capability('update_web') || !webDirty() || state.saving) return;
    state.saving = true;
    patchWebDesigner();
    try {
      await requestJson(`${ENDPOINT}/web`, { method: 'PUT', body: JSON.stringify(state.webDraft) });
      state.notice = 'WEB 认证配置已保存并应用';
      state.noticeTone = 'ok';
      state.saving = false;
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `保存失败：${firstText(error.message, '后端未接受 WEB 认证配置')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  function patchList() {
    const current = root?.querySelector('[data-user-auth-list]');
    if (!current) { patchWorkbench(); return; }
    const template = document.createElement('template');
    template.innerHTML = mainMarkup();
    const next = template.content.querySelector('[data-user-auth-list]');
    if (!next) return;
    current.replaceWith(next);
    ui.mountAll?.(next);
    patchSelectionActions();
  }

  function patchSelectionActions() {
    const count = state.selected.size;
    const labels = {
      'disconnect-selected': count ? `下线 ${count} 人` : '批量下线',
      'extend-selected': count ? `延长 ${count} 人` : '延长授权',
      'enable-selected': count ? `启用 ${count} 项` : '批量启用',
      'disable-selected': count ? `停用 ${count} 项` : '批量停用'
    };
    Object.entries(labels).forEach(([action, label]) => {
      const button = root?.querySelector(`[data-user-auth-action="${action}"]`);
      if (!button) return;
      const text = button.querySelector('span');
      if (text) text.textContent = label;
      const cap = action === 'disconnect-selected' ? capability('disconnect') : action === 'extend-selected' ? capability('extend_session') : capability('write_accounts');
      button.disabled = !count || !cap;
    });
  }

  function currentEndpoint() {
    if (state.drawer === 'web') return `${ENDPOINT}/web`;
    if (state.drawer === 'portal') return `${ENDPOINT}/web/portal`;
    if (state.drawer === 'password-policy') return `${ENDPOINT}/accounts/password-policy`;
    if (state.drawer === 'access') return `${ENDPOINT}/web/access-rules`;
    if (state.drawer === 'package') return `${ENDPOINT}/packages${state.editor._new ? '' : `/${encodeURIComponent(state.editor._id)}`}`;
    if (state.drawer === 'account') return `${ENDPOINT}/accounts${state.editor._new ? '' : `/${encodeURIComponent(state.editor._id)}`}`;
    if (state.drawer === 'voucher') return `${ENDPOINT}/vouchers${state.editor._new ? '' : `/${encodeURIComponent(state.editor._id)}`}`;
    if (state.drawer === 'delegated') return `${ENDPOINT}/delegated-services${state.editor._new ? '' : `/${encodeURIComponent(state.editor._id)}`}`;
    if (state.drawer === 'periodic') return `${ENDPOINT}/notifications/periodic${state.editor._new ? '' : `/${encodeURIComponent(state.editor._id)}`}`;
    if (state.drawer === 'import-accounts') return `${ENDPOINT}/accounts/import`;
    if (state.drawer === 'import-delegated') return `${ENDPOINT}/delegated-services/import`;
    return ENDPOINT;
  }

  function cleanEditorPayload() {
    if (state.drawer === 'import-accounts') return { type: state.editor.type, rows: asArray(state.editor.rows), confirm: true };
    if (state.drawer === 'import-delegated') return { rows: asArray(state.editor.rows), confirm: true };
    const payload = clone(state.editor);
    delete payload._new;
    delete payload._id;
    if (!payload.password) delete payload.password;
    ['targets', 'groups', 'networks', 'source_addresses', 'languages', 'payment_package_ids'].forEach((key) => {
      if (typeof payload[key] === 'string') payload[key] = payload[key].split(/[\n,]/).map((value) => value.trim()).filter(Boolean);
    });
    return payload;
  }

  async function saveEditor() {
    if (state.saving || !state.drawer) return;
    if (state.drawer === 'voucher-print') { printVouchers(); return; }
    state.saving = true;
    render();
    try {
      await requestJson(currentEndpoint(), { method: state.editor._new ? 'POST' : 'PUT', body: JSON.stringify(cleanEditorPayload()) });
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
    if (state.saving || state.editor._new) return;
    if (!state.confirmDelete) { state.confirmDelete = true; state.notice = '删除后运行配置将立即更新。请再次点击确认删除。'; state.noticeTone = 'warning'; render(); return; }
    state.saving = true;
    render();
    try {
      await requestJson(currentEndpoint(), { method: 'DELETE' });
      state.drawer = '';
      state.editor = {};
      state.confirmDelete = false;
      state.saving = false;
      state.notice = '项目已删除';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `删除失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  function printVouchers() {
    const all = asArray(state.data.account_management.vouchers);
    const selected = state.selected;
    const rows = all.filter((row, index) => {
      const id = firstText(row.id, row.code, `voucher-${index}`);
      if (state.editor.scope === 'selected') return selected.has(String(id));
      if (state.editor.scope === 'unused') return !bool(row.used, false) && !bool(row.expired, false);
      if (state.editor.scope === 'batch') return firstText(row.batch, row.batch_id) === firstText(state.editor.batch);
      return true;
    });
    const popup = window.open('', '_blank');
    if (!popup) { state.notice = '浏览器阻止了打印窗口，请允许本站打开弹出窗口。'; state.noticeTone = 'warning'; render(); return; }
    try { popup.opener = null; } catch (_) {}
    const cards = rows.map((row) => `<article><strong>${escapeHtml(firstText(row.code, '--'))}</strong><span>${escapeHtml(firstText(row.duration, '按门户默认时长'))}</span><small>${escapeHtml(firstText(row.expires_at, row.expiry, '不过期'))}</small></article>`).join('');
    popup.document.write(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>Dreaming OS 上网码</title><style>body{font-family:system-ui,sans-serif;margin:24px;color:#111}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}article{border:1px dashed #777;padding:18px;text-align:center;break-inside:avoid}strong,span,small{display:block}strong{font:700 20px ui-monospace,monospace;letter-spacing:2px}span{margin:8px 0;font-size:12px}small{color:#666}@media print{body{margin:10mm}}</style><div class="grid">${cards || '<p>当前范围没有可打印的上网码。</p>'}</div><script>addEventListener('load',()=>print())<\/script></html>`);
    popup.document.close();
    state.drawer = '';
    state.editor = {};
    render();
  }

  function exportRows(kind) {
    let rows = [];
    if (kind === 'online') rows = state.data.online_users;
    else if (kind === 'accounts') rows = accountCollection();
    else rows = state.tab === 'online' ? state.data.delegated.online : state.data.delegated.services;
    const blob = new Blob([JSON.stringify({ schema: 'dreamingwrt-user-authentication-v1', type: `${state.page}:${state.tab}`, exported_at: new Date().toISOString(), rows }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `dreamingwrt-authentication-${state.page}-${state.tab || 'list'}.json`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function disconnect(ids) {
    if (!ids.length || !capability('disconnect')) return;
    try {
      await requestJson(`${ENDPOINT}/online-users/disconnect`, { method: 'POST', body: JSON.stringify({ ids }) });
      state.selected.clear();
      state.notice = '下线指令已提交';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.notice = `下线失败：${firstText(error.message)}`;
      state.noticeTone = 'error';
      render();
    }
  }

  async function extendSessions(ids) {
    if (!ids.length || !capability('extend_session')) return;
    const duration = window.prompt('延长授权时长（分钟）', '60');
    if (duration === null) return;
    const minutes = Number(duration);
    if (!Number.isFinite(minutes) || minutes <= 0) {
      state.notice = '授权时长必须是大于 0 的分钟数。';
      state.noticeTone = 'warning';
      render();
      return;
    }
    try {
      await requestJson(`${ENDPOINT}/online-users/extend`, { method: 'POST', body: JSON.stringify({ ids, minutes }) });
      state.selected.clear();
      state.notice = `已延长授权 ${minutes} 分钟`;
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.notice = `延长授权失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  async function submitBatch(enabled) {
    const ids = Array.from(state.selected);
    if (!ids.length || !capability('write_accounts')) return;
    try {
      await requestJson(`${ENDPOINT}/accounts/bulk`, { method: 'POST', body: JSON.stringify({ ids, enabled }) });
      state.selected.clear();
      state.notice = enabled ? '已启用所选账号' : '已停用所选账号';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.notice = `批量操作失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  async function cleanExpiredVouchers() {
    if (!capability('write_accounts')) return;
    try {
      await requestJson(`${ENDPOINT}/vouchers/expired`, { method: 'DELETE' });
      state.notice = '失效上网码已清理';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.notice = `清理失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  function notificationPayload() {
    const payload = clone(state.notificationDraft || {});
    ['targets', 'groups', 'times', 'public_ip_allowlist', 'domain_allowlist'].forEach((key) => {
      if (typeof payload[key] === 'string') payload[key] = payload[key].split(/[\n,]/).map((value) => value.trim()).filter(Boolean);
    });
    payload.content = sanitizeRichHtml(payload.content || '');
    return payload;
  }

  async function saveNotification() {
    if (state.saving || !capability('write_notifications')) return;
    state.saving = true;
    patchWorkbench();
    try {
      await requestJson(`${ENDPOINT}/notifications/${encodeURIComponent(state.tab)}`, { method: 'PUT', body: JSON.stringify(notificationPayload()) });
      state.saving = false;
      state.notice = '认证通知已保存';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `保存失败：${firstText(error.message, '后端未接受配置')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  function csvRows(text) {
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
      else if ((char === '\n' || char === '\r') && !quoted) {
        if (char === '\r' && source[index + 1] === '\n') index += 1;
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
    const records = csvRows(text);
    if (records.length < 2) return [];
    const headers = records.shift().map((value) => value.trim().toLowerCase());
    const aliases = {
      account: ['account', 'username', '账号', '用户名'], name: ['name', '姓名', '名称', '线路名'], auth_type: ['auth_type', 'type', '认证类型'],
      package_id: ['package_id', 'package', '套餐'], expires_at: ['expires_at', 'expiry', '到期时间'], phone: ['phone', 'contact', '联系方式'],
      validity: ['validity', 'duration', '有效期'], price: ['price', 'fee', '价格'], up_rate: ['up_rate', 'upload', '上行带宽'], down_rate: ['down_rate', 'download', '下行带宽'],
      code: ['code', 'voucher', '上网码'], quota: ['quota', 'uses', '使用次数'], interface: ['interface', 'ifname', '接口'], delegated_account: ['delegated_account', '被代拨账号'],
      password: ['password', '密码'], note: ['note', 'remark', '备注']
    };
    return records.map((record) => Object.fromEntries(Object.entries(aliases).map(([key, names]) => {
      const index = headers.findIndex((header) => names.includes(header));
      return [key, index >= 0 ? firstText(record[index]) : ''];
    }).filter(([, value]) => value !== '')));
  }

  async function handleImportFile(event) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    let rows = [];
    const errors = [];
    try {
      const text = await file.text();
      if (/\.json$/i.test(file.name) || file.type === 'application/json') {
        const parsed = JSON.parse(text);
        rows = asArray(parsed, ['rows', 'items', 'accounts', 'packages', 'vouchers', 'services']);
      } else rows = parseCsvImport(text);
    } catch (error) { errors.push(`无法解析文件：${firstText(error.message, '格式错误')}`); }
    if (!rows.length) errors.push('文件中没有可导入的记录。');
    rows.forEach((row, index) => { if (!firstText(row.account, row.name, row.code)) errors.push(`第 ${index + 2} 行缺少账号、名称或上网码。`); });
    state.drawer = state.page === 'delegated' ? 'import-delegated' : 'import-accounts';
    state.editor = { _new: true, type: state.tab, file_name: file.name, rows, errors: errors.slice(0, 20) };
    state.notice = '';
    render();
  }

  function updateEditorField(path, value) {
    state.editor[path] = value;
  }

  function onClick(event) {
    if (event.target.closest('[data-user-auth-web-reset]')) { state.webDraft = clone(state.data.web); rerenderWebDesigner(); return; }
    if (event.target.closest('[data-user-auth-web-save]')) { saveWebDesigner(); return; }
    if (event.target.closest('[data-user-auth-close]')) { state.drawer = ''; state.editor = {}; state.notice = ''; render(); return; }
    if (event.target.closest('[data-user-auth-preview-close]')) { state.preview = false; render(); return; }
    if (event.target.closest('[data-user-auth-save]')) { saveEditor(); return; }
    if (event.target.closest('[data-user-auth-delete-editor]')) { deleteEditor(); return; }
    const edit = event.target.closest('[data-user-auth-edit]');
    if (edit) { openEditor(edit.dataset.userAuthEdit, edit.dataset.userAuthId || ''); return; }
    const remove = event.target.closest('[data-user-auth-delete]');
    if (remove) { openEditor(remove.dataset.userAuthDelete, remove.dataset.userAuthId || ''); state.confirmDelete = true; state.notice = '请核对项目后再次点击删除。'; state.noticeTone = 'warning'; render(); return; }
    const disconnectButton = event.target.closest('[data-user-auth-disconnect]');
    if (disconnectButton) { disconnect([disconnectButton.dataset.userAuthDisconnect]); return; }
    const extendButton = event.target.closest('[data-user-auth-extend]');
    if (extendButton) { extendSessions([extendButton.dataset.userAuthExtend]); return; }
    const filter = event.target.closest('[data-user-auth-filter]');
    if (filter) {
      state.statusFilter = filter.dataset.userAuthFilter;
      root.querySelectorAll('[data-user-auth-filter]').forEach((button) => button.classList.toggle('is-active', button === filter));
      patchList();
      return;
    }
    const format = event.target.closest('[data-user-auth-format]');
    if (format) { document.execCommand(format.dataset.userAuthFormat, false); return; }
    const action = event.target.closest('[data-user-auth-action]')?.dataset.userAuthAction;
    if (!action) return;
    else if (action === 'preview-portal' || action === 'preview-notification') { state.preview = true; render(); }
    else if (action === 'edit-web') openEditor('web');
    else if (action === 'edit-portal') openEditor('portal');
    else if (action === 'edit-password-policy') openEditor('password-policy');
    else if (action === 'add-access') openEditor('access');
    else if (action === 'disconnect-selected') disconnect(Array.from(state.selected));
    else if (action === 'extend-selected') extendSessions(Array.from(state.selected));
    else if (action === 'export-online') exportRows('online');
    else if (action === 'export-accounts') exportRows('accounts');
    else if (action === 'export-delegated') exportRows('delegated');
    else if (action === 'import-accounts' || action === 'import-delegated') root.querySelector('[data-user-auth-import-file]')?.click();
    else if (action === 'add-packages') openEditor('package');
    else if (action === 'add-accounts') openEditor('account');
    else if (action === 'add-vouchers') openEditor('voucher');
    else if (action === 'add-delegated') openEditor('delegated');
    else if (action === 'add-periodic') openEditor('periodic');
    else if (action === 'print-vouchers') openEditor('voucher-print');
    else if (action === 'clean-vouchers') cleanExpiredVouchers();
    else if (action === 'enable-selected') submitBatch(true);
    else if (action === 'disable-selected') submitBatch(false);
    else if (action === 'save-notification') saveNotification();
  }

  function onInput(event) {
    const webField = event.target.closest('[data-user-auth-web]');
    if (webField && !['checkbox', 'radio'].includes(webField.type) && webField.tagName !== 'SELECT') {
      const value = ['number', 'range'].includes(webField.type) ? Number(webField.value || 0) : webField.value;
      setNested(state.webDraft ||= clone(state.data.web), webField.dataset.userAuthWeb, value);
      patchWebDesigner();
      return;
    }
    const search = event.target.closest('[data-user-auth-search]');
    if (search) { state.query = search.value; patchList(); return; }
    const rich = event.target.closest('[data-user-auth-rich]');
    if (rich) {
      const target = state.notificationDraft;
      if (target) target[rich.dataset.userAuthRich] = rich.innerHTML;
      return;
    }
    const fieldInput = event.target.closest('[data-user-auth-draft]');
    if (!fieldInput || ['checkbox', 'radio'].includes(fieldInput.type) || fieldInput.tagName === 'SELECT') return;
    const target = state.page === 'notifications' && !state.drawer
      ? (state.notificationDraft ||= clone(state.data.notifications[state.tab] || {}))
      : state.editor;
    target[fieldInput.dataset.userAuthDraft] = fieldInput.type === 'number' ? Number(fieldInput.value || 0) : fieldInput.value;
  }

  function onChange(event) {
    const webField = event.target.closest('[data-user-auth-web]');
    if (webField) {
      let value = webField.type === 'checkbox' ? webField.checked : ['number', 'range'].includes(webField.type) ? Number(webField.value || 0) : webField.value;
      if (webField.dataset.userAuthWeb === 'redirect_enabled') value = value === true || value === 'true';
      if (webField.dataset.userAuthWeb === 'portal.languages') value = String(value).split(',').map((item) => item.trim()).filter(Boolean);
      setNested(state.webDraft ||= clone(state.data.web), webField.dataset.userAuthWeb, value);
      if (webField.dataset.userAuthWeb === 'redirect_enabled') rerenderWebDesigner(); else patchWebDesigner();
      return;
    }
    const selectAll = event.target.closest('[data-user-auth-select-all]');
    if (selectAll) {
      root.querySelectorAll('[data-user-auth-select]').forEach((checkbox) => { checkbox.checked = selectAll.checked; if (selectAll.checked) state.selected.add(checkbox.dataset.userAuthSelect); else state.selected.delete(checkbox.dataset.userAuthSelect); });
      patchSelectionActions();
      return;
    }
    const select = event.target.closest('[data-user-auth-select]');
    if (select) { if (select.checked) state.selected.add(select.dataset.userAuthSelect); else state.selected.delete(select.dataset.userAuthSelect); patchSelectionActions(); return; }
    const formatSelect = event.target.closest('[data-user-auth-format-select]');
    if (formatSelect) { document.execCommand(formatSelect.dataset.userAuthFormatSelect === 'block' ? 'formatBlock' : 'fontSize', false, formatSelect.value); return; }
    const fieldInput = event.target.closest('[data-user-auth-draft]');
    if (!fieldInput) return;
    const target = state.page === 'notifications' && !state.drawer
      ? (state.notificationDraft ||= clone(state.data.notifications[state.tab] || {}))
      : state.editor;
    target[fieldInput.dataset.userAuthDraft] = fieldInput.type === 'checkbox' ? fieldInput.checked : fieldInput.type === 'number' ? Number(fieldInput.value || 0) : fieldInput.value;
    if (state.drawer === 'web' || state.drawer === 'portal' || state.drawer === 'voucher-print') render();
  }

  function onTabChange(event) {
    if (!event.target.closest('[data-user-auth-tabs]')) return;
    const next = event.detail?.value;
    if (!TABS[state.page]?.some(([id]) => id === next) || next === state.tab) return;
    state.tab = next;
    state.query = '';
    state.statusFilter = 'all';
    state.selected.clear();
    state.drawer = '';
    state.notice = '';
    state.notificationDraft = state.page === 'notifications' ? clone(state.data.notifications[next] || {}) : null;
    render();
  }

  function onKeyDown(event) {
    if (event.key === 'Escape' && (state.drawer || state.preview)) { state.drawer = ''; state.preview = false; render(); }
  }

  root?.addEventListener('click', onClick);
  root?.addEventListener('input', onInput);
  root?.addEventListener('change', onChange);
  root?.addEventListener('change', (event) => { if (event.target.matches('[data-user-auth-import-file]')) handleImportFile(event); });
  root?.addEventListener('dwrt-tab-change', onTabChange);
  document.addEventListener('keydown', onKeyDown);
  stage?.classList.add('is-user-authentication');
  stage?.classList.toggle('is-user-auth-web', state.page === 'web');
  render();
  load();

  /*
   * 手动刷新按钮按用户第 9 条删除，补一条可见性受控的轮询代替；
   * 抽屉打开或正在保存时跳过，避免刷掉用户填的内容。
   */
  state.pollTimer = window.setInterval(() => {
    if (!state.mounted || document.hidden) return;
    if (state.loading || state.refreshing || state.saving) return;
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
      root?.replaceChildren();
      root?.classList.remove('route-workspace', 'policy-table-route-host', MODULE_CLASS);
      stage?.classList.remove('is-user-authentication');
      stage?.classList.remove('is-user-auth-web');
    }
  };
}

export default { mount };
