export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const stage = root?.closest('.console-stage');
  const api = context.api || {};
  const utils = context.utils || {};
  const ui = context.ui || {};
  const VERSION = '20260730-aegisx-ux-08';
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));
  const ENDPOINTS = {
    status: '/api/v1/aegis/status',
    runtime: '/api/v1/aegis/runtime',
    stats: '/api/v1/aegis/stats',
    health: '/api/v1/aegis/health',
    events: '/api/v1/aegis/events/recent',
    geo: '/api/v1/firewall/geo-block',
    honeypot: '/api/v1/aegis/honeypot',
    honeypotEvents: '/api/v1/aegis/honeypot/events?limit=50&offset=0',
    honeypotValidate: '/api/v1/aegis/honeypot/validate',
    honeypotConfig: '/api/v1/aegis/honeypot/config',
    content: '/api/v1/aegis/content-policy',
    contentValidate: '/api/v1/aegis/content-policy/validate',
    overrides: '/api/v1/aegis/domain-overrides',
    identification: '/api/v1/aegis/identification',
    trafficHistoryClear: '/api/v1/aegis/traffic-history/clear',
    appBlocks: '/api/v1/aegis/app-blocks',
    appBlockValidate: '/api/v1/aegis/app-blocks/validate',
    appCatalog: '/api/v1/policy-engine/catalog?app_limit=500',
    pcdn: '/api/v1/aegis/content-policy/pcdn',
    pcdnValidate: '/api/v1/aegis/content-policy/pcdn/validate',
    pcdnSync: '/api/v1/aegis/content-policy/pcdn/sync',
    feeds: '/api/v1/aegis/feeds',
    feedStatus: '/api/v1/aegis/feed-status',
    feedUpdate: '/api/v1/aegis/feed-update/start',
    feedImport: '/api/v1/aegis/feed-import/start',
    feedImportStatus: '/api/v1/aegis/feed-import/status',
    signatureCategories: '/api/v1/aegis/signature-categories',
    signaturePolicies: '/api/v1/aegis/signatures/policies',
    signatureSuppress: '/api/v1/aegis/signatures/suppress',
    signatureUnsuppress: '/api/v1/aegis/signatures/unsuppress',
    logSettings: '/api/v1/logs/settings',
    lans: '/api/v1/network/lans',
    clients: '/api/v1/clients'
  };
  const TABS = [
    { id: 'protect', label: '保护' },
    { id: 'content', label: '内容过滤器' },
    { id: 'logging', label: '流量日志' }
  ];
  const ACTIVE_TAB_KEY = 'dreamingwrt.aegisx.activeTab.v1';
  const COUNTRY_NAMES = {
    CN: '中国', RU: '俄罗斯', US: '美国', IN: '印度', BR: '巴西', DE: '德国', GB: '英国', FR: '法国', JP: '日本', KR: '韩国',
    AU: '澳大利亚', CA: '加拿大', NL: '荷兰', SE: '瑞典', SG: '新加坡', HK: '中国香港', TW: '中国台湾', ID: '印度尼西亚', TH: '泰国',
    VN: '越南', MY: '马来西亚', PH: '菲律宾', PK: '巴基斯坦', BD: '孟加拉国', NG: '尼日利亚', ZA: '南非', EG: '埃及', KE: '肯尼亚',
    MX: '墨西哥', AR: '阿根廷', CL: '智利', CO: '哥伦比亚', PE: '秘鲁', IT: '意大利', ES: '西班牙', PL: '波兰', UA: '乌克兰',
    TR: '土耳其', IR: '伊朗', IL: '以色列', SA: '沙特阿拉伯', AE: '阿联酋', NZ: '新西兰', IE: '爱尔兰', CH: '瑞士', AT: '奥地利',
    BE: '比利时', FI: '芬兰', NO: '挪威', DK: '丹麦', CZ: '捷克'
  };
  const ERROR_TEXT = {
    invalid_content_policy_id: '策略标识无效', invalid_content_policy_name: '请输入策略名称', invalid_content_policy_mode: '过滤模式无效',
    content_scope_not_supported: '当前后端仅支持全部网络范围', safe_search_not_supported: '当前后端尚未支持安全搜索',
    content_schedule_not_supported: '当前后端仅支持始终生效', invalid_domain: '请输入有效域名', invalid_domain_override_action: '域名规则动作无效',
    domain_override_conflict: '该域名已经存在规则', invalid_network_id: '请选择网络', honeypot_network_not_found: '找不到所选网络',
    invalid_honeypot_profile: '蜜罐类型无效', invalid_honeypot_id: '蜜罐标识无效', address_reserved_or_leased: '该地址已保留或已租用',
    address_in_use: '该地址正在使用', honeypot_address_conflict: '该地址已用于其他蜜罐', honeypot_network_address_limit_reached: '该网络的蜜罐地址已达到上限',
    honeypotd_binary_missing: '设备缺少蜜罐运行程序', invalid_services: '至少选择一项蜜罐服务', unsupported_honeypot_service: '包含后端不支持的蜜罐服务',
    job_already_running: '已有 Aegisx 后台任务正在运行', aegis_job_running: '已有 Aegisx 后台任务正在运行',
    pcdn_revision_conflict: 'PCDN 配置已被其他会话修改', pcdn_rules_not_ready: '请先同步 PCDN 规则',
    pcdn_apply_failed: 'PCDN 应用失败，旧配置已保留', signature_revision_mismatch: '签名规则已更新，请重新核对',
    revision_conflict: '配置已被其他会话修改', revision_required: '缺少配置修订号', signature_not_found: '找不到该签名规则'
  };
  function initialTab() {
    try {
      const value = sessionStorage.getItem(ACTIVE_TAB_KEY) || '';
      if (TABS.some((tab) => tab.id === value)) return value;
    } catch (_) {}
    return 'protect';
  }
  function rememberTab(value) {
    if (!TABS.some((tab) => tab.id === value)) return;
    try { sessionStorage.setItem(ACTIVE_TAB_KEY, value); } catch (_) {}
  }
  const state = {
    tab: initialTab(), loading: true, error: '', notice: '', saving: false, drawer: '', confirm: null,
    status: {}, runtime: {}, stats: {}, health: {}, events: [], geo: { countries: [], rules: [], feeds: [], events: [] },
    honeypot: { items: [], runtime: {}, capabilities: {} }, honeypotEvents: [], content: { items: [], runtime: {}, capabilities: {} },
    overrides: [], identification: {}, appBlocks: { items: [], capabilities: {} }, appCatalog: [], pcdn: {}, logSettings: {}, lans: [], clients: [],
    feeds: {}, feedStatus: {}, feedImportStatus: {}, signatureCategories: {}, signaturePolicies: { items: [], counts: {}, total: 0, limit: 50, offset: 0 },
    contentDraft: null, appBlockDraft: null, honeypotDraft: null, signatureDraft: null, pcdnSyncPreview: null, pcdnPendingIntent: null, pcdnJobId: '', feedPreview: null,
    geoQuery: '', geoDraftEnabled: null, appQuery: '', eventQuery: '', signatureQuery: '', signaturePage: 0, jobPollAttempts: 0, mounted: true, seq: 0
  };
  let portal = null;
  let jobPollTimer = 0;

  function authHeaders(extra = {}) {
    let token = '';
    try { token = localStorage.getItem('dreamingwrt.web.accessToken') || ''; } catch (_) {}
    return { Accept: 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}), ...extra };
  }
  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null || typeof value === 'object') continue;
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }
  function asArray(value, keys = ['items', 'rows', 'data']) {
    if (Array.isArray(value)) return value;
    for (const key of keys) if (Array.isArray(value?.[key])) return value[key];
    return [];
  }
  function unwrap(value) { return value?.data ?? value?.raw?.data ?? value?.raw ?? value ?? {}; }
  function message(error, fallback = '操作失败') {
    const key = firstText(error?.error, error?.message, error?.code, error);
    return ERROR_TEXT[key] || key || fallback;
  }
  async function requestJson(url, options = {}) {
    if (typeof api.fetch === 'function' && !options.method) {
      const result = await api.fetch(`aegisx-${url}`, url);
      if (result?.ok === false) throw new Error(message(result?.data || result?.raw, '读取失败'));
      return unwrap(result);
    }
    const response = await fetch(url, {
      credentials: 'same-origin', cache: 'no-store', ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const json = await response.json().catch(() => ({}));
    const payload = json?.data ?? json;
    if (!response.ok || json?.ok === false || payload?.ok === false) {
      const detail = payload?.error || payload?.message || json?.error || response.status;
      const error = new Error(message(detail));
      error.code = firstText(payload?.error, payload?.code, json?.error, json?.code);
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    return payload;
  }
  function runtime() { return state.runtime?.runtime || state.runtime || state.status?.runtime || {}; }
  function capabilities() { return state.status?.capabilities || {}; }
  function bool(value) { return value === true || value === 1 || value === '1' || value === 'true' || value === 'enabled' || value === 'active' || value === 'running'; }
  function active(value) { return !['', 'off', 'stopped', 'disabled', 'inactive', 'false', '0'].includes(String(value ?? '').toLowerCase()); }
  function slug(prefix = 'resource') { return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`; }
  function formatTime(value) {
    const number = Number(value);
    if (!Number.isFinite(number) || number <= 0) return '--';
    const date = new Date(number > 1e12 ? number : number * 1000);
    return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(date);
  }
  function formatNumber(value) { return new Intl.NumberFormat('zh-CN').format(Number(value) || 0); }
  function lanSubnet(lan) {
    const ipaddr = firstText(lan?.ipaddr);
    const cidr = firstText(lan?.cidr);
    if (cidr.includes('/')) return cidr;
    if (ipaddr && cidr) return `${ipaddr}/${cidr}`;
    return firstText(lan?.subnet, ipaddr, lan?.device);
  }
  function icon(name) {
    const paths = {
      globe: '<circle cx="12" cy="12" r="9"></circle><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"></path>',
      shield: '<path d="M12 3 5 6v5c0 4.5 2.8 8.1 7 10 4.2-1.9 7-5.5 7-10V6l-7-3Z"></path><path d="m9 12 2 2 4-5"></path>',
      alert: '<path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.4 2.7 17a2 2 0 0 0 1.8 3h15a2 2 0 0 0 1.8-3L13.7 3.4a2 2 0 0 0-3.4 0Z"></path>',
      trap: '<path d="M4 5h16M6 5l1 15h10l1-15M9 9v7M15 9v7"></path>',
      filter: '<path d="M4 5h16l-6 7v6l-4 2v-8L4 5Z"></path>',
      activity: '<path d="M3 12h4l2-6 4 12 2-6h6"></path>',
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      close: '<path d="m6 6 12 12M18 6 6 18"></path>',
      ban: '<circle cx="12" cy="12" r="9"></circle><path d="m5.6 5.6 12.8 12.8"></path>',
      checkCircle: '<circle cx="12" cy="12" r="9"></circle><path d="m8 12 2.6 2.6L16.5 9"></path>',
      shieldBan: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"></path><path d="m4.243 5.21 14.39 12.472"></path>',
      shieldCheck: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"></path><path d="m9 12 2 2 4-4"></path>',
      edit: '<path d="M12 20h9"></path><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4Z"></path>',
      trash: '<path d="M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13M10 11v5M14 11v5"></path>'
    };
    const strokeWidth = name === 'shieldBan' || name === 'shieldCheck' ? 2 : 1.8;
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${strokeWidth}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.shield}</svg>`;
  }
  function info(text) {
    return `<span class="aegisx-info" tabindex="0" aria-label="${escapeHtml(text)}" data-dwrt-tooltip="${escapeHtml(text)}"><span aria-hidden="true">i</span></span>`;
  }
  function stateBadge(label, tone = 'neutral') {
    return ui.statusBadgeMarkup?.(label, tone) || `<span>${escapeHtml(label)}</span>`;
  }
  function switchControl(name, checked, enabled = false, label = '') {
    return `<label class="dwrt-kit-switch aegisx-switch ${enabled ? '' : 'is-disabled'}" data-dwrt-component="switch" ${enabled ? '' : `data-dwrt-tooltip="${escapeHtml(label || '后端未开放写入')}"`}><input type="checkbox" data-aegis-toggle="${name}" ${checked ? 'checked' : ''} ${enabled ? '' : 'disabled'} aria-label="${escapeHtml(label || name)}"></label>`;
  }
  function radio(name, value, checked, label, enabled = false, reason = '') {
    return `<label class="aegisx-radio ${enabled ? '' : 'is-disabled'}" ${reason ? `data-dwrt-tooltip="${escapeHtml(reason)}"` : ''}><input type="radio" name="${name}" value="${value}" ${checked ? 'checked' : ''} ${enabled ? '' : 'disabled'}><i></i><span>${escapeHtml(label)}</span></label>`;
  }
  function actionButton(label, action, enabled = false, options = {}) {
    return `<button class="aegisx-link-button ${options.primary ? 'is-primary' : ''}" type="button" data-aegis-action="${action}" ${options.value ? `data-aegis-value="${escapeHtml(options.value)}"` : ''} ${enabled ? '' : 'disabled'}>${options.icon ? icon(options.icon) : ''}${escapeHtml(label)}</button>`;
  }
  function row(label, help, control, options = {}) {
    return `<div class="aegisx-setting-row ${options.detail ? 'has-detail' : ''}"><div class="aegisx-setting-label"><span>${escapeHtml(label)}</span>${help ? info(help) : ''}</div><div class="aegisx-setting-control">${control}${options.detail || ''}</div></div>`;
  }
  function scheduleAdaptive(delay = 40) { ui.scheduleAdaptiveForegroundSample?.(delay, root); }

  async function load(options = {}) {
    const seq = ++state.seq;
    if (!options.silent) { state.loading = true; state.error = ''; render(); }
    const requests = [
      ['status', ENDPOINTS.status], ['runtime', ENDPOINTS.runtime], ['stats', ENDPOINTS.stats], ['health', ENDPOINTS.health],
      ['events', ENDPOINTS.events], ['geo', ENDPOINTS.geo], ['honeypot', ENDPOINTS.honeypot], ['honeypotEvents', ENDPOINTS.honeypotEvents],
      ['content', ENDPOINTS.content], ['overrides', ENDPOINTS.overrides], ['identification', ENDPOINTS.identification],
      ['appBlocks', ENDPOINTS.appBlocks], ['appCatalog', ENDPOINTS.appCatalog], ['pcdn', ENDPOINTS.pcdn],
      ['logSettings', ENDPOINTS.logSettings], ['lans', ENDPOINTS.lans], ['clients', ENDPOINTS.clients]
    ];
    const results = await Promise.allSettled(requests.map(([, url]) => requestJson(url)));
    if (!state.mounted || seq !== state.seq) return;
    results.forEach((result, index) => {
      if (result.status !== 'fulfilled') return;
      const [key] = requests[index];
      const value = result.value;
      if (key === 'events') state.events = asArray(value, ['events', 'items']);
      else if (key === 'geo') state.geo = value?.data || value || state.geo;
      else if (key === 'honeypotEvents') state.honeypotEvents = asArray(value, ['items', 'events']);
      else if (key === 'overrides') state.overrides = asArray(value, ['items']);
      else if (key === 'identification') state.identification = value?.data || value || {};
      else if (key === 'appBlocks') state.appBlocks = value?.data || value || state.appBlocks;
      else if (key === 'appCatalog') state.appCatalog = asArray(value?.data || value, ['applications', 'items']);
      else if (key === 'pcdn') state.pcdn = value?.data || value || {};
      else if (key === 'logSettings') state.logSettings = value?.data || value || {};
      else if (key === 'lans') state.lans = asArray(value?.data || value, ['lans', 'items']);
      else if (key === 'clients') state.clients = asArray(value?.data || value, ['clients', 'items']);
      else state[key] = value;
    });
    const optionalKeys = new Set(['appBlocks', 'appCatalog', 'pcdn', 'logSettings', 'clients']);
    const failures = results.map((item, index) => ({ item, key: requests[index][0] }))
      .filter(({ item, key }) => item.status === 'rejected' && !optionalKeys.has(key))
      .map(({ item }) => message(item.reason)).filter(Boolean);
    state.error = failures.length ? `部分状态读取失败：${[...new Set(failures)].join(' · ')}` : '';
    state.loading = false;
    render();
  }
  async function loadIntrusion(options = {}) {
    const sid = Number.parseInt(state.signatureQuery.trim(), 10);
    const limit = 50;
    const offset = Math.max(0, state.signaturePage) * limit;
    const query = Number.isInteger(sid) && sid > 0 ? `?sid=${sid}&limit=${limit}&offset=0` : `?limit=${limit}&offset=${offset}`;
    if (!options.silent) { state.saving = true; state.error = ''; render(); }
    const requests = [
      ['feeds', ENDPOINTS.feeds], ['feedStatus', ENDPOINTS.feedStatus], ['feedImportStatus', ENDPOINTS.feedImportStatus],
      ['signatureCategories', ENDPOINTS.signatureCategories], ['signaturePolicies', `${ENDPOINTS.signaturePolicies}${query}`]
    ];
    const results = await Promise.allSettled(requests.map(([, url]) => requestJson(url)));
    if (!state.mounted) return;
    results.forEach((result, index) => {
      if (result.status === 'fulfilled') state[requests[index][0]] = result.value?.data || result.value || {};
    });
    const failures = results.filter((item) => item.status === 'rejected').map((item) => message(item.reason)).filter(Boolean);
    state.saving = false;
    if (failures.length) state.error = `规则管理部分状态读取失败：${[...new Set(failures)].join(' · ')}`;
    render();
    scheduleJobPoll();
  }

  function renderTabs() {
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs aegisx-tabs" data-dwrt-component="tabs" data-dwrt-tabs-key="aegisx-main" role="tablist" aria-label="Aegisx 设置">
      <span class="dwrt-kit-tab-pill" aria-hidden="true"></span>
      ${TABS.map((tab) => `<button class="dwrt-kit-tab ${state.tab === tab.id ? 'is-active' : ''}" type="button" role="tab" aria-selected="${state.tab === tab.id}" data-value="${tab.id}" data-aegis-tab="${tab.id}">${tab.label}</button>`).join('')}
    </nav>`;
  }
  function geoCountries() { return asArray(state.geo?.countries); }
  function selectedCountries() { return geoCountries().filter((country) => bool(country.enabled)); }
  function geoRules() { return asArray(state.geo?.rules); }
  function geoRule() {
    return geoRules()[0] || {
      id: 'aegisx-region-default', name: '区域拦截', action: 'block', direction: 'both',
      src_zone: 'wan', dst_zone: '', enabled: false
    };
  }
  function updateGeoRule(patch) {
    const next = { ...geoRule(), ...patch };
    if (geoRules().length) state.geo.rules[0] = next;
    else state.geo.rules = [next];
    return next;
  }
  function geoConfiguredEnabled() {
    return bool(geoRule().enabled) && selectedCountries().length > 0;
  }
  function geoControlEnabled() {
    return state.geoDraftEnabled === null ? geoConfiguredEnabled() : state.geoDraftEnabled;
  }
  function countryFlag(country) {
    const code = firstText(country?.code, country?.id).toLowerCase().replace(/[^a-z-]/g, '');
    return code ? `<img src="/static/images/flags/${code}.svg" alt="" loading="lazy" decoding="async" onerror="this.hidden=true">` : '';
  }
  function honeypots() { return asArray(state.honeypot, ['items']); }
  function contentPolicies() { return asArray(state.content, ['items']); }
  function contentCaps() { return state.content?.capabilities || capabilities(); }
  function honeypotCaps() { return state.honeypot?.capabilities || capabilities(); }
  function appBlocks() { return asArray(state.appBlocks, ['items']); }
  function appBlockCaps() { return state.appBlocks?.capabilities || {}; }
  function appBlockSupported() { return bool(appBlockCaps().supported); }
  function appById(id) { return state.appCatalog.find((app) => Number(app.app_id ?? app.value) === Number(id)); }
  function appNames(ids = []) { return asArray(ids).map((id) => firstText(appById(id)?.label, id)).join('、'); }
  function clientMac(client) { return firstText(client?.mac, client?.client_mac).toUpperCase(); }
  function clientLabel(client) { return firstText(client?.display_name, client?.nickname, client?.hostname, client?.name, clientMac(client), client?.ip); }
  function clientByMac(mac) { return state.clients.find((client) => clientMac(client) === firstText(mac).toUpperCase()); }
  function pcdnSettings() { return state.pcdn?.settings || state.pcdn || {}; }
  function pcdnCaps() { return state.pcdn?.capabilities || {}; }
  function pcdnSupported() { return bool(pcdnCaps().pcdn_filter_supported ?? pcdnCaps().supported ?? capabilities().pcdn_filter_supported); }
  function pcdnStatus() {
    const settings = pcdnSettings();
    if (bool(settings.effective_blocking)) return { label: '阻止中', tone: 'ok' };
    if (settings.apply_state === 'pending' || (bool(settings.enabled) && !bool(settings.effective_blocking))) return { label: '等待应用', tone: 'warn' };
    if (settings.sync_state === 'failed') return { label: '同步失败', tone: 'warn' };
    if (bool(settings.rules_ready)) return { label: '规则已就绪', tone: 'info' };
    return { label: '尚未同步', tone: 'neutral' };
  }
  function identification() { return state.identification || {}; }
  function identificationCaps() { return identification().capabilities || {}; }
  function identificationSupported() {
    return bool(identificationCaps().identification_mode ?? identificationCaps().identification_mode_supported ?? capabilities().identification_mode_supported);
  }
  function trafficHistoryClearSupported() {
    return bool(identificationCaps().traffic_history_clear_supported ?? capabilities().traffic_history_clear_supported);
  }
  function identificationMode() {
    const mode = firstText(identification().mode);
    if (mode === 'device_and_traffic' || mode === 'traffic_only' || mode === 'disabled') return mode;
    if (bool(identification().device_identification_enabled)) return 'device_and_traffic';
    if (bool(identification().traffic_identification_enabled)) return 'traffic_only';
    return 'disabled';
  }
  function identificationBadge() {
    if (!identificationSupported()) return stateBadge('后端未开放', 'neutral');
    const mode = identificationMode();
    if (mode === 'disabled') return stateBadge('已禁用', 'neutral');
    if (bool(identification().applied) || identification().apply_state === 'active') return stateBadge('运行中', 'ok');
    return stateBadge('待运行态回读', 'warn');
  }
  function feedJobs() { return asArray(state.feedStatus, ['jobs']); }
  function runningFeedJob() { return feedJobs().find((job) => job.state === 'running'); }
  function pcdnJobs() { return asArray(state.pcdn, ['jobs']); }
  function activePcdnJob() {
    return pcdnJobs().find((job) => job.job_id === state.pcdnJobId) || pcdnJobs().find((job) => job.op === 'pcdn_sync' && job.state === 'running');
  }
  function scheduleJobPoll() {
    window.clearTimeout(jobPollTimer);
    if (!state.mounted) return;
    const intrusionRunning = state.drawer === 'intrusion' && bool(state.feedStatus?.running ?? runningFeedJob());
    const pcdnRunning = Boolean(state.pcdnJobId) || bool(activePcdnJob());
    if (!intrusionRunning && !pcdnRunning) return;
    if (state.jobPollAttempts >= 180) {
      state.error = '后台任务状态轮询已停止，请稍后手动刷新核对结果。';
      state.pcdnJobId = '';
      render();
      return;
    }
    state.jobPollAttempts += 1;
    jobPollTimer = window.setTimeout(async () => {
      if (!state.mounted) return;
      if (pcdnRunning) {
        try {
          state.pcdn = await requestJson(ENDPOINTS.pcdn);
          const job = activePcdnJob();
          if (job && ['done', 'error'].includes(job.state)) {
            state.notice = job.state === 'done' && bool(job.result?.ok ?? true)
              ? 'PCDN 规则同步完成；若状态为等待应用，请重新应用当前设置。'
              : `PCDN 规则同步失败：${firstText(job.last_error, job.result?.error, job.result?.message, '未知错误')}`;
            state.pcdnJobId = '';
          }
        } catch (error) { state.error = message(error, 'PCDN 同步状态读取失败'); state.pcdnJobId = ''; }
      }
      if (intrusionRunning) await loadIntrusion({ silent: true });
      else { render(); scheduleJobPoll(); }
    }, 2200);
  }
  function feedItems() { return asArray(state.feeds, ['feeds']); }
  function signatureItems() { return asArray(state.signaturePolicies, ['items']); }
  function signatureCounts() { return state.signaturePolicies?.counts || {}; }
  function idsManagementAvailable() {
    return feedItems().length > 0 || bool(state.signatureCategories?.available) || Number(state.signaturePolicies?.total) > 0;
  }
  function renderProtect() {
    const rt = runtime();
    const idsSupported = bool(capabilities().ids_ips_supported);
    const idsActive = bool(rt.ids_ips_production_active) || bool(state.status.ids_ips_production_active);
    const idsReason = firstText(rt.suricata_reason, capabilities().suricata_apply_reason, idsActive ? '' : '运行组件未就绪');
    const geoSelected = selectedCountries();
    const regionRule = geoRule();
    const regionEnabled = geoControlEnabled();
    const hpItems = honeypots();
    const hpRuntime = state.honeypot?.runtime || rt.honeypot_runtime || {};
    const hpSupported = bool(honeypotCaps().config ?? capabilities().honeypot_config_supported);
    const appItems = appBlocks();
    const appSupported = appBlockSupported();
    return `<section class="aegisx-panel dwrt-kit-glass-surface" aria-label="保护设置">
      ${row('简单应用阻止', '按全部终端或指定设备阻止签名库中的应用，并读取内核规则状态和命中计数。', `${actionButton('新建', 'app-block-new', appSupported)}${appItems.length ? actionButton('管理', 'app-block', appSupported) : ''}`)}
      ${row('区域拦截', '根据国家或地区以及流量方向阻止或允许连接。', `<div class="aegisx-region-config">
        ${switchControl('geo-enabled', regionEnabled, !state.saving, '启用区域拦截')}
        ${regionEnabled ? `<div class="aegisx-region-dependent">
          <div class="aegisx-region-actions" role="group" aria-label="区域规则动作">
            <button type="button" class="${regionRule.action !== 'allow' ? 'is-active' : ''}" data-geo-action="block" ${state.saving ? 'disabled' : ''}>${icon('shieldBan')}<span>阻止</span></button>
            <button type="button" class="${regionRule.action === 'allow' ? 'is-active' : ''}" data-geo-action="allow" ${state.saving ? 'disabled' : ''}>${icon('shieldCheck')}<span>允许</span></button>
          </div>
          <div class="aegisx-region-directions">${radio('geo-direction', 'both', !['outbound', 'inbound'].includes(regionRule.direction), '双向', true)}${radio('geo-direction', 'outbound', regionRule.direction === 'outbound', '传出', true)}${radio('geo-direction', 'inbound', regionRule.direction === 'inbound', '传入', true)}</div>
          <div class="aegisx-region-country-action">${actionButton('选择国家或地区', 'geo-block', geoCountries().length > 0)}<small>${geoSelected.length ? `已选 ${geoSelected.length} 个国家或地区` : '尚未选择国家或地区'}</small></div>
        </div>` : ''}
      </div>`)}
      ${row('蜜罐', '检测并记录对指定 IPv4 地址的请求，以发现网络中的异常客户端。', `<div class="aegisx-honeypot-row">${hpItems.length ? `<div class="aegisx-inline-summary"><strong>${hpItems.length} 个蜜罐</strong><small>${bool(hpRuntime.active) ? `运行中 · ${formatNumber(hpRuntime.hits)} 次命中` : '当前未运行'}</small></div>${actionButton('管理', 'honeypot', hpSupported)}` : ''}${actionButton('新建', 'honeypot-new', hpSupported)}</div>`)}
      ${row('识别', '识别设备类型和网关流量。', `<div class="aegisx-choice-row">${radio('identification', 'disabled', identificationMode() === 'disabled', '已禁用', identificationSupported() && !state.saving)}${radio('identification', 'device_traffic', identificationMode() === 'device_and_traffic', '设备和流量', identificationSupported() && !state.saving)}${radio('identification', 'traffic', identificationMode() === 'traffic_only', '仅流量', identificationSupported() && !state.saving)}</div>${identificationBadge()}`)}
      ${row('拦截页面', '为内容过滤命中的网站显示解释页面。', `${switchControl('block-page', false, false, 'SSL 检查与证书接口尚未实现')}<span class="aegisx-certificate">Aegisx SSL Certificate</span>${stateBadge('后端未开放', 'neutral')}`, { detail: '<p class="aegisx-explanation">证书生成、下载和终端分发接口尚未实现，因此不会伪造可用开关。</p>' })}
      ${row('入侵防御', '通过特征更新和深度数据包检测来检测和阻止威胁。', `<div class="aegisx-segment" aria-label="入侵防御"><button type="button" class="${idsActive ? '' : 'is-active'}" disabled>关</button><button type="button" class="${idsActive ? 'is-active' : ''}" disabled>开</button></div>${stateBadge(idsActive ? '生产防护已启用' : idsSupported ? '运行组件未就绪' : '后端未开放', idsActive ? 'ok' : 'warn')}<small class="aegisx-reason">${escapeHtml(idsReason)}</small>${actionButton('规则管理', 'intrusion', true)}`)}
    </section>`;
  }

  function defaultContentDraft(item = null) {
    return {
      id: item?.id || slug('content'), name: item?.name || '', enabled: item?.enabled !== false,
      mode: item?.mode || 'basic', scope: item?.scope || { type: 'all', devices: [], networks: [] }, ad_block: bool(item?.ad_block),
      safe_search: item?.safe_search || { google: false, bing: false, youtube: false }, categories: asArray(item?.categories),
      schedule: item?.schedule || { type: 'always' }
    };
  }
  function overridesFor(policyId, action) { return state.overrides.filter((item) => item.policy_id === policyId && item.action === action); }
  function renderDomainList(policy, action) {
    const label = action === 'allow' ? '允许列表' : '阻止列表';
    const help = action === 'allow' ? '这些域名不会被内容策略拦截。' : '这些域名会被显式拦截。';
    const items = overridesFor(policy.id, action);
    return `<div class="aegisx-domain-block"><header><span>${label} ${info(help)}</span></header><div class="aegisx-domain-add"><input type="text" data-domain-input="${action}" data-policy-id="${escapeHtml(policy.id)}" placeholder="example.com"><button type="button" data-domain-add="${action}" data-policy-id="${escapeHtml(policy.id)}">添加</button></div>${items.length ? `<div class="aegisx-domain-chips">${items.map((item) => `<span>${escapeHtml(item.domain)}<button type="button" data-domain-delete="${escapeHtml(item.id)}" aria-label="删除 ${escapeHtml(item.domain)}">×</button></span>`).join('')}</div>` : '<small class="aegisx-empty-hint">暂无域名</small>'}</div>`;
  }
  function renderContent() {
    const caps = contentCaps();
    const policies = contentPolicies();
    const writable = bool(caps.content_policy_supported ?? capabilities().content_policy_crud_supported);
    const pcdn = pcdnSettings();
    const pcdnAvailable = pcdnSupported();
    const pcdnState = pcdnStatus();
    const pcdnJob = activePcdnJob();
    return `<section class="aegisx-content-workspace">
      ${policies.length ? `<div class="aegisx-content-toolbar">${actionButton('新建策略', 'content-new', writable, { primary: true })}</div>` : ''}
      ${policies.length ? `<div class="aegisx-policy-list">${policies.map((policy) => `<article class="aegisx-resource-card dwrt-kit-glass-surface">
        <header><div><strong>${escapeHtml(policy.name)}</strong><span>${escapeHtml(policy.id)}</span></div>${stateBadge(policy.enabled === false || policy.mode === 'off' ? '已停用' : policy.apply_state === 'active' ? '已应用' : '待应用', policy.apply_state === 'active' ? 'ok' : policy.apply_state === 'pending' ? 'warn' : 'neutral')}</header>
        <div class="aegisx-resource-meta"><span>过滤级别 <b>${policy.mode === 'enhanced' ? '增强' : policy.mode === 'off' ? '关闭' : '基础'}</b></span><span>广告拦截 <b>${policy.ad_block ? '开启' : '关闭'}</b></span><span>范围 <b>全部网络</b></span><span>计划 <b>始终</b></span></div>
        <div class="aegisx-domain-grid">${renderDomainList(policy, 'allow')}${renderDomainList(policy, 'block')}</div>
        <footer>${actionButton('编辑', 'content-edit', writable, { value: policy.id, icon: 'edit' })}<button class="aegisx-icon-action is-danger" type="button" data-content-delete="${escapeHtml(policy.id)}" aria-label="删除 ${escapeHtml(policy.name)}">${icon('trash')}</button></footer>
      </article>`).join('')}</div>` : `<div class="aegisx-empty dwrt-kit-glass-surface">${icon('filter')}<strong>尚未创建内容过滤策略</strong><span>可配置基础或增强过滤、广告拦截、安全搜索及域名允许/阻止规则。</span>${actionButton('新建策略', 'content-new', writable, { primary: true })}</div>`}
      ${pcdnAvailable ? `<section class="aegisx-panel aegisx-pcdn-panel dwrt-kit-glass-surface" aria-label="PCDN 屏蔽">
        ${row('PCDN 屏蔽', '使用已审计的 OpenHosts PCDN 域名源，通过 DNS 数据面阻止 PCDN 域名。', `${switchControl('pcdn-enabled', bool(pcdn.enabled), !state.saving && !pcdnJob && (bool(pcdn.enabled) || bool(pcdn.rules_ready)), '启用 PCDN 屏蔽')}${stateBadge(pcdnJob ? '同步中' : pcdnState.label, pcdnJob ? 'info' : pcdnState.tone)}${actionButton(pcdnJob ? '同步中' : bool(pcdn.rules_ready) ? '更新规则' : '同步规则', 'pcdn-sync', !state.saving && !pcdnJob)}${pcdn.apply_state === 'pending' ? actionButton('应用更新', 'pcdn-apply-current', !state.saving && !pcdnJob) : ''}${state.pcdnPendingIntent !== null ? actionButton('重新校验', 'pcdn-retry', !state.saving && !pcdnJob) : ''}`, { detail: `<p class="aegisx-explanation">${formatNumber(pcdn.rule_count)} 条规则 · 最近同步 ${escapeHtml(formatTime(pcdn.last_sync_at))}${pcdn.sync_error ? ` · ${escapeHtml(pcdn.sync_error)}` : ''}${state.pcdnPendingIntent !== null ? ` · 待重新确认${state.pcdnPendingIntent ? '启用' : '停用'}` : ''}</p>` })}
      </section>` : ''}
    </section>`;
  }

  function filteredEvents() {
    const query = state.eventQuery.trim().toLowerCase();
    return state.events.filter((event) => !query || [event.event_type, event.action, event.policy_name, event.source_ip, event.destination_host, event.source, event.risk].join(' ').toLowerCase().includes(query));
  }
  function eventLabel(value) {
    const labels = { policy_route_match: '路由策略命中', dns_block: 'DNS 拦截', reputation_block: '信誉拦截', suricata_alert: '入侵告警', honeypot_hit: '蜜罐命中' };
    return labels[value] || value || '安全事件';
  }
  function overviewCards(items, label) {
    const renderer = ui.overviewCardsMarkup || window.DWRT_UI_KIT?.overviewCardsMarkup;
    return typeof renderer === 'function' ? renderer(items, { className: 'aegisx-overview-cards', label }) : '';
  }
  function syslogSettings() {
    const settings = state.logSettings?.settings || state.logSettings || {};
    return settings.syslog && typeof settings.syslog === 'object' ? settings.syslog : {};
  }
  function logRetentionDays() {
    return Number(state.logSettings?.retention_days ?? state.logSettings?.settings?.retention_days) || 0;
  }
  function renderLogging() {
    const events = filteredEvents();
    const stats = state.stats || {};
    const syslog = syslogSettings();
    const syslogLoaded = Object.keys(state.logSettings || {}).length > 0;
    const clearSupported = trafficHistoryClearSupported();
    return `<section class="aegisx-logging-workspace">
      ${overviewCards([
        { key: 'events', label: '安全事件', value: formatNumber(stats.events), detail: '近期事件总量', tone: 'info', icon: icon('alert') },
        { key: 'blocks', label: '拦截', value: formatNumber(stats.blocks), detail: 'DNS 与信誉拦截', tone: 'bad', icon: icon('ban') },
        { key: 'routes', label: '路由策略命中', value: formatNumber(stats.route_policy_hits), detail: '已验证生产事件', tone: 'ok', icon: icon('checkCircle') },
        { key: 'honeypot', label: '蜜罐命中', value: formatNumber(stats.honeypot_hits), detail: '诱捕服务事件', tone: 'warn', icon: icon('trap') }
      ], 'Aegisx 流量日志概览')}
      <section class="aegisx-panel aegisx-unsupported-panel dwrt-kit-glass-surface">
        ${row('NetFlow (IPFIX)', '捕获流量信息并导出到收集器。', `${switchControl('netflow', false)}${stateBadge('后端未开放', 'neutral')}`)}
        ${row('流量日志', '选择记录所有安全流量或仅记录被阻止流量，并可附加 DNS、服务和设备管理事件。', `${radio('traffic-logging', 'all', true, '所有流量', false, '后端缺少独立采集范围合同')}${radio('traffic-logging', 'blocked', false, '仅阻止的流量', false, '后端缺少独立采集范围合同')}${stateBadge('后端未开放', 'neutral')}`, { detail: '<p class="aegisx-explanation">Gateway DNS、Aegisx 服务和设备管理三类额外流量仍缺独立设置与回读。</p>' })}
        ${row('活动日志 (Syslog)', '将活动日志保存在本机，或使用日志中心转发到 SIEM / Syslog 服务器。', `${radio('syslog', 'off', false, '关', false)}${radio('syslog', 'internal', syslogLoaded && !bool(syslog.enabled), '内部存储', false)}${radio('syslog', 'siem', bool(syslog.enabled), 'SIEM 服务器', false)}${stateBadge(syslogLoaded ? bool(syslog.enabled) ? '转发已启用' : '内部存储' : '状态不可用', syslogLoaded ? bool(syslog.enabled) ? 'ok' : 'info' : 'warn')}${actionButton('管理', 'log-center', syslogLoaded)}`, { detail: `<p class="aegisx-explanation">${bool(syslog.enabled) ? `${escapeHtml(firstText(syslog.server, '--'))}:${escapeHtml(firstText(syslog.port, 514))} · ${escapeHtml(firstText(syslog.protocol, 'udp').toUpperCase())}` : '日志保留、转发协议、TLS/mTLS、队列和测试统一由日志中心管理。'}</p>` })}
        ${row('数据保留', '控制本机日志保留，并清除设备与流量识别产生的历史数据。', `${stateBadge(logRetentionDays() ? `保留 ${logRetentionDays()} 天` : '自动', 'info')}${actionButton('保留设置', 'log-center', syslogLoaded)}${actionButton('清除流量历史', 'traffic-clear', clearSupported, { icon: 'trash' })}`)}
        ${row('SNMP 监控', '允许监控工具使用 SNMP 收集网络信息。', `${stateBadge('后端未开放', 'neutral')}`)}
        ${row('日志级别', '按设备、管理、远程访问和系统分别控制日志详细程度。', `${stateBadge('后端未开放', 'neutral')}`)}
      </section>
      <section class="aegisx-events-card dwrt-kit-glass-surface"><header><div><strong>近期活动</strong><span>来自 Aegisx 真实事件接口，最多显示最近 100 条。</span></div><label class="aegisx-event-search">${icon('search')}<input type="search" data-event-search value="${escapeHtml(state.eventQuery)}" placeholder="搜索事件"></label></header>
        <div class="dwrt-kit-table-wrap"><table class="dwrt-kit-table aegisx-events-table"><thead><tr><th>时间</th><th>事件</th><th>动作</th><th>策略 / 来源</th><th>终端 / 目标</th><th>状态</th></tr></thead><tbody>${events.length ? events.map((event) => `<tr><td>${escapeHtml(formatTime(event.ts))}</td><td><strong>${escapeHtml(eventLabel(event.event_type))}</strong><small>${escapeHtml(event.risk || event.level || '')}</small></td><td>${escapeHtml(event.action || '--')}</td><td><strong>${escapeHtml(event.policy_name || event.rule_name || '--')}</strong><small>${escapeHtml(event.source || '')}</small></td><td><strong>${escapeHtml(event.source_ip || event.source_mac || '--')}</strong><small>${escapeHtml(event.destination_host || event.destination_ip || '')}</small></td><td>${stateBadge(event.production_event === false ? '测试事件' : '生产事件', event.production_event === false ? 'warn' : 'ok')}</td></tr>`).join('') : '<tr><td colspan="6" class="aegisx-table-empty">没有匹配的安全事件</td></tr>'}</tbody></table></div>
      </section>
    </section>`;
  }

  function renderGeoDrawer() {
    const query = state.geoQuery.trim().toLowerCase();
    const countries = geoCountries().filter((country) => !query || [country.code, country.id, country.name, COUNTRY_NAMES[country.code || country.id], country.continent].join(' ').toLowerCase().includes(query));
    const selected = selectedCountries().length;
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-aegis-close aria-label="关闭区域拦截配置"></button><aside class="aegisx-drawer aegisx-geo-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot">
      <header class="dwrt-kit-sheet-header"><div><span>REGION BLOCKING</span><strong>选择国家或地区</strong></div><button class="dwrt-kit-sheet-close" type="button" data-aegis-close>×</button></header>
      <div class="dwrt-kit-sheet-body aegisx-drawer-body"><div class="aegisx-drawer-intro">所选国家或地区将使用保护页设置的动作和流量方向。后端已提供 nftables preview、apply、disable 与 rollback；当前仍缺逐国家、逐规则命中计数和事件回读。</div><div class="aegisx-drawer-toolbar"><label>${icon('search')}<input type="search" data-geo-search value="${escapeHtml(state.geoQuery)}" placeholder="搜索国家或地区"></label><span>已选 ${selected} / 可配置 ${geoCountries().length}</span></div><div class="aegisx-country-list">${countries.map((country) => `<label><input type="checkbox" data-geo-country="${escapeHtml(country.id || country.code)}" ${country.enabled ? 'checked' : ''}><span class="aegisx-checkmark"></span>${countryFlag(country)}<b>${escapeHtml(COUNTRY_NAMES[country.code || country.id] || country.name || country.id)}</b><small>${escapeHtml(country.code || country.id)} · ${escapeHtml(country.continent || '')}</small></label>`).join('')}</div></div>
      <footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-aegis-close>取消</button><button class="policy-primary" type="button" data-geo-save ${state.saving || !selected ? 'disabled' : ''}>${state.saving ? '正在保存' : selected ? '保存配置' : '请先选择国家或地区'}</button></footer>
    </aside>`;
  }
  function defaultHoneypotDraft(item = null) {
    const services = asArray(item?.services).map((entry) => firstText(entry?.name, entry));
    return {
      id: item?.id || slug('honeypot'), name: item?.name || '蜜罐', enabled: item?.enabled !== false,
      network_id: item?.network_id || firstText(state.lans[0]?.id, state.lans[0]?.name), address: item?.address || '', profile: item?.profile || 'linux_server',
      services: services.length ? services : ['ssh', 'http', 'ftp', 'dns']
    };
  }
  function renderHoneypotModal() {
    const items = honeypots();
    const draft = state.honeypotDraft;
    if (draft) {
      const editing = items.some((item) => item.id === draft.id);
      return `<div class="dwrt-kit-modal-layer aegisx-honeypot-modal-layer is-open" data-dwrt-component="modal"><button class="dwrt-kit-modal-backdrop" type="button" data-aegis-close aria-label="关闭蜜罐配置"></button><section class="dwrt-kit-modal aegisx-honeypot-modal dwrt-kit-glass-surface" data-dwrt-modal-variant="copilot" data-adaptive-sample role="dialog" aria-modal="true" aria-labelledby="aegisx-honeypot-title"><header class="dwrt-kit-modal-header"><div><h2 id="aegisx-honeypot-title">${editing ? '编辑蜜罐' : '创建蜜罐'}</h2></div><button class="dwrt-kit-modal-close" type="button" data-aegis-close aria-label="关闭">${icon('close')}</button></header><div class="dwrt-kit-modal-body aegisx-drawer-body aegisx-honeypot-modal-body">
        <label><span>网络</span><select data-honeypot-field="network_id">${state.lans.map((lan) => `<option value="${escapeHtml(firstText(lan.id, lan.name))}" ${firstText(lan.id, lan.name) === draft.network_id ? 'selected' : ''}>${escapeHtml(firstText(lan.name, lan.id))} · ${escapeHtml(lanSubnet(lan))}</option>`).join('')}</select></label>
        <label><span>蜜罐 IPv4 地址</span><input type="text" inputmode="decimal" data-honeypot-field="address" value="${escapeHtml(draft.address)}" placeholder="192.168.30.250"></label>
      </div><footer class="dwrt-kit-modal-footer"><button class="policy-secondary" type="button" data-aegis-close>取消</button><button class="policy-primary" type="button" data-honeypot-save ${state.saving || !draft.network_id || !draft.address.trim() ? 'disabled' : ''}>${state.saving ? '正在创建' : editing ? '保存' : '创建'}</button></footer></section></div>`;
    }
    return `<div class="dwrt-kit-modal-layer aegisx-honeypot-modal-layer is-open" data-dwrt-component="modal"><button class="dwrt-kit-modal-backdrop" type="button" data-aegis-close aria-label="关闭蜜罐管理"></button><section class="dwrt-kit-modal aegisx-honeypot-modal aegisx-honeypot-manager dwrt-kit-glass-surface" data-dwrt-modal-variant="copilot" data-adaptive-sample role="dialog" aria-modal="true" aria-labelledby="aegisx-honeypot-manager-title"><header class="dwrt-kit-modal-header"><div><h2 id="aegisx-honeypot-manager-title">蜜罐</h2></div><button class="dwrt-kit-modal-close" type="button" data-aegis-close aria-label="关闭">${icon('close')}</button></header><div class="dwrt-kit-modal-body aegisx-drawer-body"><div class="aegisx-honeypot-list">${items.map((item) => `<article><div><strong>${escapeHtml(item.name)}</strong><span>${escapeHtml(item.address)} · ${escapeHtml(item.network_id)}</span></div>${stateBadge(item.apply_state === 'active' ? '运行中' : item.enabled === false ? '已停用' : '未运行', item.apply_state === 'active' ? 'ok' : 'warn')}<div><button type="button" data-honeypot-edit="${escapeHtml(item.id)}">编辑</button><button type="button" data-honeypot-delete="${escapeHtml(item.id)}">删除</button></div></article>`).join('')}</div>${state.honeypotEvents.length ? `<section class="aegisx-honeypot-events"><strong>近期命中</strong>${state.honeypotEvents.slice(0, 8).map((event) => `<span><b>${escapeHtml(firstText(event.source_ip, event.source_mac, '未知终端'))}</b><small>${escapeHtml(formatTime(event.ts || event.last_seen))}</small></span>`).join('')}</section>` : ''}</div><footer class="dwrt-kit-modal-footer"><button class="policy-secondary" type="button" data-aegis-close>关闭</button><button class="policy-primary" type="button" data-honeypot-new>新建</button></footer></section></div>`;
  }
  function defaultAppBlockDraft(item = null) {
    const schedule = asArray(item?.schedule).map((range) => ({
      weekdays: asArray(range?.weekdays).map(Number).filter((day) => day >= 0 && day <= 6),
      start_time: firstText(range?.start_time, '00:00'), end_time: firstText(range?.end_time, '23:59')
    }));
    const firstRange = schedule[0] || { weekdays: [1, 2, 3, 4, 5], start_time: '09:00', end_time: '18:00' };
    const allDays = schedule.length === 1 && firstRange.weekdays.length === 7;
    const knownClient = clientByMac(item?.source);
    return {
      id: item?.id || slug('app-block'), name: item?.name || '', enabled: item?.enabled !== false,
      source: item?.source || 'any', source_mode: item?.source && item.source !== 'any' ? knownClient ? 'client' : 'manual' : 'any',
      app_ids: asArray(item?.app_ids).map(Number).filter((id) => id > 0),
      schedule_mode: !schedule.length ? 'always' : allDays ? 'daily' : schedule.length === 1 ? 'weekly' : 'custom',
      schedule_ranges: schedule.length ? schedule : [firstRange]
    };
  }
  function appBlockRanges(draft = state.appBlockDraft) {
    if (!draft || draft.schedule_mode === 'always') return [];
    const ranges = draft.schedule_ranges.length ? draft.schedule_ranges : [{ weekdays: [1, 2, 3, 4, 5], start_time: '09:00', end_time: '18:00' }];
    if (draft.schedule_mode === 'daily') return [{ ...ranges[0], weekdays: [0, 1, 2, 3, 4, 5, 6] }];
    return draft.schedule_mode === 'weekly' ? ranges.slice(0, 1) : ranges;
  }
  function appBlockDraftReady() {
    const draft = state.appBlockDraft;
    return Boolean(draft && draft.name.trim() && draft.app_ids.length &&
      (draft.source === 'any' || draft.source.trim()) &&
      appBlockRanges(draft).every((range) => range.weekdays.length && range.start_time && range.end_time));
  }
  function updateAppBlockSaveState() {
    const button = query('[data-app-block-save]');
    if (button) button.disabled = state.saving || !appBlockDraftReady();
  }
  function renderAppBlockDrawer() {
    const items = appBlocks();
    const draft = state.appBlockDraft;
    if (!draft) {
      return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-aegis-close aria-label="关闭应用阻止管理"></button><aside class="aegisx-drawer aegisx-app-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot"><header class="dwrt-kit-sheet-header"><div><span>APP BLOCKING</span><strong>应用阻止</strong></div><button class="dwrt-kit-sheet-close" type="button" data-aegis-close>×</button></header><div class="dwrt-kit-sheet-body aegisx-drawer-body"><div class="aegisx-app-rule-list">${items.length ? items.map((item) => `<article><div><strong>${escapeHtml(item.name)}</strong><span>${escapeHtml(item.source === 'any' ? '全部设备' : clientLabel(clientByMac(item.source)) || item.source)} · ${escapeHtml(appNames(item.app_ids) || `${asArray(item.app_ids).length} 个应用`)}</span><small>${formatNumber(item.hits)} 次命中${item.last_hit_s ? ` · ${escapeHtml(formatTime(item.last_hit_s))}` : ''}</small></div>${stateBadge(bool(item.applied) ? bool(item.active) ? '运行中' : '已同步' : '待同步', bool(item.applied) ? 'ok' : 'warn')}<div><button type="button" data-app-block-edit="${escapeHtml(item.id)}">编辑</button><button type="button" class="is-danger" data-app-block-delete="${escapeHtml(item.id)}">删除</button></div></article>`).join('') : '<div class="aegisx-drawer-empty">尚未创建应用阻止规则</div>'}</div></div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-aegis-close>关闭</button><button class="policy-primary" type="button" data-app-block-new>新建</button></footer></aside>`;
    }
    const query = state.appQuery.trim().toLowerCase();
    const catalog = state.appCatalog.filter((app) => !query || [app.label, app.category, app.family, app.app_id].join(' ').toLowerCase().includes(query));
    const editing = items.some((item) => item.id === draft.id);
    const weekdays = [1, 2, 3, 4, 5, 6, 0];
    const weekdayLabels = ['一', '二', '三', '四', '五', '六', '日'];
    const ranges = appBlockRanges(draft);
    const deviceOptions = state.clients.filter((client) => clientMac(client)).map((client) => `<option value="${escapeHtml(clientMac(client))}" ${clientMac(client) === draft.source ? 'selected' : ''}>${escapeHtml(clientLabel(client))} · ${escapeHtml(clientMac(client))}</option>`).join('');
    const rangeFields = (range, index, options = {}) => `<div class="aegisx-schedule-range" data-app-range="${index}">${options.showDays === false ? '' : `<div class="aegisx-weekdays">${weekdays.map((day, dayIndex) => `<label><input type="checkbox" data-app-range-weekday="${index}" value="${day}" ${range.weekdays.includes(day) ? 'checked' : ''}><span>${weekdayLabels[dayIndex]}</span></label>`).join('')}</div>`}<div class="aegisx-time-range"><label><span>开始</span><input type="time" data-app-range-field="start_time" data-app-range-index="${index}" value="${escapeHtml(range.start_time)}"></label><label><span>结束</span><input type="time" data-app-range-field="end_time" data-app-range-index="${index}" value="${escapeHtml(range.end_time)}"></label>${options.removable ? `<button type="button" data-app-range-remove="${index}" aria-label="删除时间段">${icon('trash')}</button>` : ''}</div></div>`;
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-aegis-close aria-label="关闭应用阻止编辑器"></button><aside class="aegisx-drawer aegisx-app-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot"><header class="dwrt-kit-sheet-header"><div><span>APP BLOCKING</span><strong>${editing ? '编辑应用阻止' : '新建应用阻止'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-aegis-close>×</button></header><div class="dwrt-kit-sheet-body aegisx-drawer-body">
      <label><span>名称</span><input type="text" data-app-block-field="name" value="${escapeHtml(draft.name)}" placeholder="访客网络应用限制"></label>
      <div class="aegisx-drawer-field"><span>启用</span>${switchControl('app-block-enabled', draft.enabled, true, '启用应用阻止规则')}</div>
      <div class="aegisx-drawer-field"><span>应用对象</span><div class="aegisx-choice-row">${radio('app-block-source-mode', 'any', draft.source_mode === 'any', '全部设备', true)}${radio('app-block-source-mode', 'specific', draft.source_mode !== 'any', '指定设备', true)}</div>${draft.source_mode === 'any' ? '' : `<select data-app-device-select><option value="">选择设备</option>${deviceOptions}<option value="manual" ${draft.source_mode === 'manual' ? 'selected' : ''}>手动输入 MAC 地址</option></select>${draft.source_mode === 'manual' ? `<input type="text" data-app-block-field="source" value="${escapeHtml(draft.source)}" placeholder="AA:BB:CC:DD:EE:FF">` : ''}`}</div>
      <div class="aegisx-drawer-field"><span>应用</span><small>当前后端支持按具体应用阻止；分类阻止尚未开放。</small><label class="aegisx-app-search">${icon('search')}<input type="search" data-app-search value="${escapeHtml(state.appQuery)}" placeholder="搜索应用、分类或 App ID"></label><div class="aegisx-app-catalog">${catalog.length ? catalog.map((app) => { const id = Number(app.app_id ?? app.value); return `<label><input type="checkbox" data-app-id="${id}" ${draft.app_ids.includes(id) ? 'checked' : ''}><span class="aegisx-checkmark"></span>${app.icon ? `<img src="${escapeHtml(app.icon)}" alt="" loading="lazy" onerror="this.hidden=true">` : ''}<b>${escapeHtml(app.label || id)}</b><small>${escapeHtml([app.category, app.family].filter(Boolean).join(' · '))}</small></label>`; }).join('') : '<div class="aegisx-drawer-empty">没有匹配的应用</div>'}</div><small data-app-selected-count>已选 ${draft.app_ids.length} 个应用</small></div>
      <div class="aegisx-drawer-field"><span>计划</span><div class="aegisx-choice-row aegisx-schedule-modes">${radio('app-block-schedule', 'always', draft.schedule_mode === 'always', '始终', true)}${radio('app-block-schedule', 'daily', draft.schedule_mode === 'daily', '每天', true)}${radio('app-block-schedule', 'weekly', draft.schedule_mode === 'weekly', '每周', true)}${radio('app-block-schedule', 'custom', draft.schedule_mode === 'custom', '自定义', true)}</div>${draft.schedule_mode === 'daily' ? rangeFields(ranges[0], 0, { showDays: false }) : draft.schedule_mode === 'weekly' ? rangeFields(ranges[0], 0) : draft.schedule_mode === 'custom' ? `<div class="aegisx-schedule-ranges">${ranges.map((range, index) => rangeFields(range, index, { removable: ranges.length > 1 })).join('')}</div><button class="aegisx-link-button aegisx-add-range" type="button" data-app-range-add>添加时间段</button>` : ''}</div>
    </div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-aegis-close>取消</button><button class="policy-primary" type="button" data-app-block-save ${state.saving || !appBlockDraftReady() ? 'disabled' : ''}>${state.saving ? '正在校验' : '校验并保存'}</button></footer></aside>`;
  }
  function renderIntrusionDrawer() {
    const categories = asArray(state.signatureCategories, ['categories']);
    const signatures = signatureItems();
    const counts = signatureCounts();
    const feedStatus = state.feedStatus || {};
    const importStatus = state.feedImportStatus || {};
    const running = runningFeedJob();
    const total = Number(state.signaturePolicies?.total) || 0;
    const pages = Math.max(1, Math.ceil(total / 50));
    const runtimeReady = bool(runtime().suricata_runtime_available ?? runtime().ids_ips_production_active ?? state.status.ids_ips_production_active);
    const importCounts = importStatus.counts || {};
    const draft = state.signatureDraft;
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-aegis-close aria-label="关闭入侵防御规则管理"></button><aside class="aegisx-drawer aegisx-intrusion-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open"><header class="dwrt-kit-sheet-header"><div><span>INTRUSION PREVENTION</span><strong>规则管理</strong></div><button class="dwrt-kit-sheet-close" type="button" data-aegis-close>×</button></header><div class="dwrt-kit-sheet-body aegisx-drawer-body">
      <div class="aegisx-drawer-intro">规则源、分类和签名策略均来自 Aegisx 后端。${runtimeReady ? 'Suricata 运行组件可用，生产状态仍以后端读回为准。' : '当前 Suricata 生产运行组件不可用；策略修改只会持久化为等待应用，不会显示为已生效。'}</div>
      ${draft ? `<section class="aegisx-intrusion-section aegisx-signature-editor"><header><div><strong>编辑 SID ${escapeHtml(draft.sid)}</strong><span>${escapeHtml(draft.msg || '')} · 目标规则 rev ${escapeHtml(draft.target_rev)}</span></div><button type="button" class="aegisx-link-button" data-signature-edit-cancel>取消</button></header><div class="aegisx-signature-editor-grid"><label><span>启用覆盖</span><select data-signature-field="enabled_override"><option value="-1" ${draft.enabled_override === -1 ? 'selected' : ''}>继承规则默认值</option><option value="1" ${draft.enabled_override === 1 ? 'selected' : ''}>强制启用</option><option value="0" ${draft.enabled_override === 0 ? 'selected' : ''}>强制停用</option></select></label><label><span>动作覆盖</span><select data-signature-field="action">${['inherit', 'alert', 'drop', 'reject', 'pass'].map((value) => `<option value="${value}" ${draft.action === value ? 'selected' : ''}>${{ inherit: '继承', alert: '告警', drop: '丢弃', reject: '拒绝', pass: '放行' }[value]}</option>`).join('')}</select></label></div><label><span>变更备注</span><input type="text" maxlength="480" data-signature-field="reason" value="${escapeHtml(draft.reason)}" placeholder="记录调整原因"></label><div class="aegisx-signature-editor-actions"><button type="button" class="policy-primary" data-signature-save ${state.saving ? 'disabled' : ''}>保存控制面策略</button></div></section>` : ''}
      <section class="aegisx-intrusion-section"><header><div><strong>规则源</strong><span>${formatNumber(feedItems().length)} 个内置源 · 最近成功 ${escapeHtml(formatTime(feedStatus.last_success_at))}</span></div><div>${actionButton(running ? '任务运行中' : '更新全部', 'feed-update', !state.saving && !running)}${actionButton('刷新', 'intrusion-refresh', !state.saving)}</div></header>
        ${state.feedPreview ? `<div class="aegisx-feed-preview"><strong>将更新 ${escapeHtml(state.feedPreview.name || state.feedPreview.feed_id || '全部规则源')}</strong><span>${escapeHtml(state.feedPreview.url || '由后端内置清单提供来源')} · ${escapeHtml(state.feedPreview.format || '多种格式')}</span><div><button type="button" class="policy-secondary" data-feed-preview-cancel>取消</button><button type="button" class="policy-primary" data-feed-preview-confirm>确认更新</button></div></div>` : ''}
        <div class="aegisx-feed-list">${feedItems().length ? feedItems().map((feed) => `<article><div><strong>${escapeHtml(feed.name || feed.feed_id)}</strong><span>${escapeHtml(feed.kind || feed.format || '')}</span><small>${formatNumber(feed.item_count)} 条 · ${escapeHtml(formatTime(feed.last_success_at))}${feed.last_error ? ` · ${escapeHtml(feed.last_error)}` : ''}</small></div>${stateBadge(feed.last_error ? '异常' : feed.last_success_at ? '已同步' : '未同步', feed.last_error ? 'warn' : feed.last_success_at ? 'ok' : 'neutral')}<button type="button" data-feed-update="${escapeHtml(feed.feed_id)}" ${state.saving || running ? 'disabled' : ''}>更新</button></article>`).join('') : '<div class="aegisx-drawer-empty">当前设备未返回规则源</div>'}</div>
        ${running ? `<div class="aegisx-job-state">${stateBadge('后台任务运行中', 'info')}<span>${escapeHtml(running.op || 'feed job')} · ${escapeHtml(running.feed_id || '全部规则源')}</span></div>` : ''}
      </section>
      <section class="aegisx-intrusion-section"><header><div><strong>导入状态</strong><span>规则源更新成功后会自动导入；也可从已校验 artifact 手动重建数据库。导入不会自动启用生产 IDS/IPS。</span></div><div>${actionButton('重新导入', 'feed-import', !state.saving && !running && feedItems().length > 0)}</div></header><div class="aegisx-import-counts"><span>Suricata 规则<b>${formatNumber(importCounts.suricata_rules)}</b></span><span>签名元数据<b>${formatNumber(importCounts.signature_metadata)}</b></span><span>域名分类<b>${formatNumber(importCounts.domain_categories)}</b></span><span>信誉项<b>${formatNumber(importCounts.reputation_items)}</b></span></div></section>
      <section class="aegisx-intrusion-section"><header><div><strong>签名分类</strong><span>${formatNumber(state.signatureCategories?.total)} 条已导入签名</span></div></header><div class="aegisx-signature-categories">${categories.length ? categories.slice(0, 18).map((item) => `<span><b>${escapeHtml(item.category || '未分类')}</b><small>${formatNumber(item.count)}</small></span>`).join('') : '<div class="aegisx-drawer-empty">尚未导入 Suricata 规则</div>'}</div></section>
      <section class="aegisx-intrusion-section"><header><div><strong>签名策略</strong><span>${formatNumber(total)} 条 · ${formatNumber(counts.suppressed)} 条已抑制 · ${formatNumber(counts.apply_required)} 条等待应用</span></div></header><label class="aegisx-app-search"><span class="sr-only">按 SID 查找签名</span>${icon('search')}<input type="search" inputmode="numeric" data-signature-search value="${escapeHtml(state.signatureQuery)}" placeholder="输入完整 SID 查找"></label>
        <div class="aegisx-signature-list">${signatures.length ? signatures.map((item) => { const override = item.override || {}; const suppressed = bool(override.suppressed); const revision = Number(override.revision) || 0; return `<article><div><strong>${escapeHtml(item.msg || `SID ${item.sid}`)}</strong><span>SID ${escapeHtml(item.sid)} · rev ${escapeHtml(item.rev)} · ${escapeHtml(item.category || '未分类')}</span><small>${escapeHtml(item.protocol || '')} · 严重度 ${escapeHtml(item.severity ?? '--')} · ${escapeHtml(item.effective_action || item.default_action || 'alert')}</small></div>${stateBadge(item.stale ? '规则已更新' : suppressed ? '已抑制' : bool(item.effective_enabled) ? runtimeReady ? '已启用' : '待数据面' : '已停用', item.stale ? 'warn' : suppressed ? 'neutral' : bool(item.effective_enabled) && runtimeReady ? 'ok' : 'warn')}<div><button type="button" data-signature-edit="${escapeHtml(item.sid)}" ${state.saving || item.stale ? 'disabled' : ''}>编辑</button><button type="button" data-signature-suppress="${escapeHtml(item.sid)}" data-signature-rev="${escapeHtml(item.rev)}" data-signature-revision="${revision}" data-signature-suppressed="${suppressed ? '1' : '0'}" ${state.saving || item.stale ? 'disabled' : ''}>${suppressed ? '取消抑制' : '抑制'}</button></div></article>`; }).join('') : '<div class="aegisx-drawer-empty">没有匹配的签名</div>'}</div>
        <div class="aegisx-pagination"><button type="button" data-signature-page="prev" ${state.signaturePage <= 0 || state.saving || state.signatureQuery ? 'disabled' : ''}>上一页</button><span>第 ${Math.min(state.signaturePage + 1, pages)} / ${pages} 页</span><button type="button" data-signature-page="next" ${(state.signaturePage + 1) >= pages || state.saving || state.signatureQuery ? 'disabled' : ''}>下一页</button></div>
      </section>
    </div><footer class="dwrt-kit-sheet-footer"><span class="aegisx-sheet-footnote">${runtimeReady ? '生产状态以后端运行态回读为准' : '控制面可写，生产 Suricata 数据面尚未就绪'}</span><button class="policy-secondary" type="button" data-aegis-close>关闭</button></footer></aside>`;
  }
  function renderContentDrawer() {
    const draft = state.contentDraft || defaultContentDraft();
    const caps = contentCaps();
    const safeSearchSupported = bool(caps.safe_search_supported ?? caps.content_filter_safe_search_supported ?? capabilities().content_filter_safe_search_supported);
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-aegis-close aria-label="关闭内容策略编辑器"></button><aside class="aegisx-drawer aegisx-content-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot"><header class="dwrt-kit-sheet-header"><div><span>CONTENT FILTER</span><strong>${contentPolicies().some((item) => item.id === draft.id) ? '编辑内容策略' : '新建内容策略'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-aegis-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body aegisx-drawer-body aegisx-content-drawer-body">
      <section class="aegisx-content-form-section" aria-labelledby="aegisx-content-basic"><h3 id="aegisx-content-basic">基本设置</h3><div class="aegisx-content-form-rows">
        <label class="aegisx-content-form-row"><span>名称</span><input type="text" data-content-field="name" value="${escapeHtml(draft.name)}" placeholder="家庭内容过滤"></label>
        <div class="aegisx-content-form-row"><span>启用</span><div>${switchControl('content-enabled', draft.enabled, true, '启用内容策略')}</div></div>
        <div class="aegisx-content-form-row"><span>源 ${info('当前后端仅支持全部网络。')}</span><strong>全部网络</strong></div>
      </div></section>
      <section class="aegisx-content-form-section" aria-labelledby="aegisx-content-filtering"><h3 id="aegisx-content-filtering">过滤</h3><div class="aegisx-content-form-rows">
        <div class="aegisx-content-form-row"><span>过滤级别</span><div class="aegisx-choice-row">${radio('content-mode', 'off', draft.mode === 'off', '关', true)}${radio('content-mode', 'basic', draft.mode === 'basic', '基础', true)}${radio('content-mode', 'enhanced', draft.mode === 'enhanced', '增强', true)}</div></div>
        <div class="aegisx-content-form-row"><span>广告拦截</span><div>${switchControl('content-ad-block', draft.ad_block, bool(caps.ad_block_supported ?? capabilities().content_filter_ad_block_supported), '广告拦截')}</div></div>
        <div class="aegisx-content-form-row is-top-aligned"><span>安全搜索 ${info('通过 DNS 规则强制 Google、Bing 和 YouTube 使用安全搜索。')}</span><div><div class="aegisx-check-row"><label><input type="checkbox" data-content-safe-search="google" ${bool(draft.safe_search?.google) ? 'checked' : ''} ${safeSearchSupported ? '' : 'disabled'}><i></i>Google</label><label><input type="checkbox" data-content-safe-search="bing" ${bool(draft.safe_search?.bing) ? 'checked' : ''} ${safeSearchSupported ? '' : 'disabled'}><i></i>Bing</label><label><input type="checkbox" data-content-safe-search="youtube" ${bool(draft.safe_search?.youtube) ? 'checked' : ''} ${safeSearchSupported ? '' : 'disabled'}><i></i>YouTube</label></div>${safeSearchSupported ? '' : '<small>当前设备未返回安全搜索能力</small>'}</div></div>
      </div></section>
      <section class="aegisx-content-form-section" aria-labelledby="aegisx-content-schedule"><h3 id="aegisx-content-schedule">计划</h3><div class="aegisx-content-form-rows"><div class="aegisx-content-form-row"><span>生效时间</span><div class="aegisx-choice-row">${radio('content-schedule', 'always', true, '始终', true)}${radio('content-schedule', 'daily', false, '每天', false, '后端尚未支持计划')}${radio('content-schedule', 'weekly', false, '每周', false, '后端尚未支持计划')}</div></div></div></section>
    </div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-aegis-close>取消</button><button class="policy-primary" type="button" data-content-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在校验' : '校验并应用'}</button></footer></aside>`;
  }
  function renderDrawer() {
    if (state.drawer === 'geo-block') return renderGeoDrawer();
    if (state.drawer === 'honeypot') return renderHoneypotModal();
    if (state.drawer === 'app-block') return renderAppBlockDrawer();
    if (state.drawer === 'intrusion') return renderIntrusionDrawer();
    if (state.drawer === 'content') return renderContentDrawer();
    return '';
  }
  function renderConfirmation() {
    if (!state.confirm) return '';
    const markup = window.DWRT_UI_KIT?.confirmationMarkup?.({
      id: 'aegisx-confirm', action: state.confirm.action, tone: state.confirm.tone || 'warning',
      title: state.confirm.title, description: state.confirm.description, confirmLabel: state.confirm.confirmLabel || '确认并应用'
    });
    return markup || '';
  }
  function renderPortal() {
    const markup = `${renderDrawer()}${renderConfirmation()}`;
    if (!markup) {
      portal?.remove();
      portal = null;
      return;
    }
    if (!portal?.isConnected) {
      portal = document.createElement('div');
      portal.className = 'aegisx-portal';
      portal.dataset.aegisxPortal = VERSION;
      document.body.append(portal);
    }
    portal.innerHTML = markup;
  }
  function query(selector) { return root.querySelector(selector) || portal?.querySelector(selector) || null; }
  function queryAll(selector) { return [...root.querySelectorAll(selector), ...(portal ? portal.querySelectorAll(selector) : [])]; }
  function rerenderWithFocus(selector, value) {
    render();
    const input = query(selector);
    if (!(input instanceof HTMLInputElement)) return;
    input.focus({ preventScroll: true });
    input.setSelectionRange(value.length, value.length);
  }
  function render() {
    if (!root) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'policy-table-route-host', 'aegisx-route-host');
    root.innerHTML = `<section class="policy-table-shell aegisx-shell" data-aegisx-version="${VERSION}">${renderTabs()}<div class="aegisx-view">${state.error ? `<div class="aegisx-notice is-error">${escapeHtml(state.error)}</div>` : ''}${state.notice ? `<div class="aegisx-notice">${escapeHtml(state.notice)}</div>` : ''}${state.loading ? '<div class="aegisx-loading dwrt-kit-glass-surface">正在读取 Aegisx 状态...</div>' : state.tab === 'protect' ? renderProtect() : state.tab === 'content' ? renderContent() : renderLogging()}</div></section>`;
    renderPortal();
    bindEvents();
    ui.mountAll?.(root);
    if (portal) ui.mountAll?.(portal);
    scheduleAdaptive(30);
    if (portal) ui.scheduleAdaptiveForegroundSample?.(40, portal);
  }

  function closeDrawer() { state.drawer = ''; state.contentDraft = null; state.appBlockDraft = null; state.honeypotDraft = null; render(); }
  async function saveGeo(options = {}) {
    state.saving = true; state.error = ''; render();
    try {
      const rules = geoRules().length ? geoRules() : [geoRule()];
      await requestJson(ENDPOINTS.geo, { method: 'PUT', body: JSON.stringify({
        countries: geoCountries().map((item) => ({ id: item.id || item.code, enabled: bool(item.enabled) })),
        rules: rules.map((item) => ({
          id: item.id || 'aegisx-region-default', name: item.name || '区域拦截',
          action: item.action === 'allow' ? 'allow' : 'block',
          direction: ['outbound', 'inbound'].includes(item.direction) ? item.direction : 'both',
          src_zone: item.src_zone || 'wan', dst_zone: item.dst_zone || '', enabled: bool(item.enabled)
        }))
      }) });
      state.notice = '区域配置已保存。生产拦截数据面仍以后端运行态为准。';
      state.saving = false;
      state.geoDraftEnabled = null;
      if (options.closeDrawer !== false) state.drawer = '';
      await load({ silent: true });
    } catch (error) { state.error = message(error, '区域配置保存失败'); state.saving = false; state.geoDraftEnabled = null; await load({ silent: true }); }
  }
  async function saveIdentification(mode) {
    const normalized = mode === 'device_traffic' ? 'device_and_traffic' : mode === 'traffic' ? 'traffic_only' : mode;
    if (!['disabled', 'device_and_traffic', 'traffic_only'].includes(normalized)) return;
    state.saving = true; state.error = ''; render();
    try {
      const result = await requestJson(ENDPOINTS.identification, { method: 'POST', body: JSON.stringify({ mode: normalized }) });
      state.identification = result?.data || result || state.identification;
      state.notice = normalized === 'disabled' ? '已关闭设备与流量识别。' : normalized === 'traffic_only' ? '已切换为仅流量识别。' : '已切换为设备和流量识别。';
      state.saving = false;
      await load({ silent: true });
    } catch (error) { state.error = message(error, '识别模式切换失败'); state.saving = false; await load({ silent: true }); }
  }
  function contentPayload() {
    const draft = state.contentDraft || defaultContentDraft();
    return {
      ...draft, enabled: draft.enabled !== false, scope: { type: 'all', devices: [], networks: [] },
      safe_search: {
        google: bool(draft.safe_search?.google), bing: bool(draft.safe_search?.bing), youtube: bool(draft.safe_search?.youtube)
      }, schedule: { type: 'always' }
    };
  }
  async function validateContent() {
    const payload = contentPayload();
    state.saving = true; state.error = ''; render();
    try {
      const validation = await requestJson(ENDPOINTS.contentValidate, { method: 'POST', body: JSON.stringify(payload) });
      if (!bool(validation.valid ?? validation.ok)) throw new Error(asArray(validation.blockers).map((item) => ERROR_TEXT[item] || item).join('、') || message(validation));
      state.saving = false;
      state.confirm = { action: 'content-save', tone: 'warning', title: '应用内容过滤策略？', description: `将保存“${payload.name}”并更新 DNS 过滤数据面。失败时后端会回滚到原配置。`, confirmLabel: '保存并应用', payload };
      render();
    } catch (error) { state.error = message(error, '内容策略校验失败'); state.saving = false; render(); }
  }
  async function commitContent(payload) {
    state.confirm = null; state.saving = true; render();
    try {
      await requestJson(ENDPOINTS.content, { method: 'PUT', body: JSON.stringify({ ...payload, confirm: true, apply: true }) });
      state.notice = '内容过滤策略已保存并完成运行态回读。'; state.drawer = ''; state.contentDraft = null; state.saving = false; await load({ silent: true });
    } catch (error) { state.error = message(error, '内容策略应用失败'); state.saving = false; render(); }
  }
  function appBlockPayload() {
    const draft = state.appBlockDraft || defaultAppBlockDraft();
    const schedule = draft.schedule_mode === 'always' ? 'always' : appBlockRanges(draft).map((range) => ({
      weekdays: [...new Set(range.weekdays.map(Number))], start_time: range.start_time, end_time: range.end_time
    }));
    return {
      id: draft.id, name: draft.name.trim(), enabled: draft.enabled !== false,
      source: draft.source === 'any' ? 'any' : draft.source.trim(),
      app_ids: [...new Set(draft.app_ids.map(Number).filter((id) => id > 0))],
      schedule, action: 'block', filter_quic: false
    };
  }
  async function validateAppBlock() {
    const payload = appBlockPayload();
    state.saving = true; state.error = ''; render();
    try {
      const validation = await requestJson(ENDPOINTS.appBlockValidate, { method: 'POST', body: JSON.stringify(payload) });
      if (!bool(validation.valid ?? validation.ok)) throw new Error(message(validation, '应用阻止规则校验失败'));
      state.saving = false;
      state.confirm = {
        action: 'app-block-save', tone: 'warning', title: '应用阻止规则？',
        description: `将保存“${payload.name}”，并请求 rulesd 向内核同步 ${payload.app_ids.length} 个应用标识。`,
        confirmLabel: '保存并同步', payload, revision: Number(validation.revision ?? state.appBlocks?.revision)
      };
      render();
    } catch (error) { state.error = message(error, '应用阻止规则校验失败'); state.saving = false; render(); }
  }
  async function commitAppBlock(payload, revision) {
    state.confirm = null; state.saving = true; render();
    const editing = appBlocks().some((item) => item.id === payload.id);
    try {
      await requestJson(editing ? `${ENDPOINTS.appBlocks}/${encodeURIComponent(payload.id)}` : ENDPOINTS.appBlocks, {
        method: editing ? 'PUT' : 'POST', body: JSON.stringify({ ...payload, confirm: true, revision })
      });
      state.notice = '应用阻止规则已保存，内核运行态将由最新回读确认。';
      state.drawer = ''; state.appBlockDraft = null; state.saving = false; await load({ silent: true });
    } catch (error) { state.error = message(error, '应用阻止规则保存失败'); state.saving = false; render(); }
  }
  async function previewPcdnSync() {
    state.saving = true; state.error = ''; render();
    try {
      const preview = await requestJson(ENDPOINTS.pcdnSync, { method: 'POST', body: JSON.stringify({ confirm: false }) });
      const source = preview.source || asArray(state.pcdn?.sources)[0] || {};
      state.saving = false;
      state.confirm = {
        action: 'pcdn-sync', tone: 'warning', title: '同步 PCDN 规则？',
        description: `${firstText(source.name, source.id, 'OpenHosts PCDN domains')} · ${firstText(source.license, '许可证由数据源声明')}。同步只更新已校验规则，不会自动改变当前 DNS 数据面。`,
        confirmLabel: '开始同步'
      };
      render();
    } catch (error) { state.error = message(error, 'PCDN 同步预览失败'); state.saving = false; render(); }
  }
  async function commitPcdnSync() {
    state.confirm = null; state.saving = true; state.error = ''; render();
    try {
      const result = await requestJson(ENDPOINTS.pcdnSync, { method: 'POST', body: JSON.stringify({ confirm: true }) });
      state.pcdnJobId = firstText(result.job_id);
      state.jobPollAttempts = 0;
      state.notice = state.pcdnJobId ? 'PCDN 规则同步任务已启动。' : 'PCDN 规则同步请求已提交。';
      state.saving = false;
      state.pcdn = await requestJson(ENDPOINTS.pcdn);
      render(); scheduleJobPoll();
    } catch (error) { state.error = message(error, 'PCDN 规则同步失败'); state.saving = false; render(); }
  }
  async function validatePcdn(enabled) {
    const current = pcdnSettings();
    state.saving = true; state.error = ''; render();
    try {
      const validation = await requestJson(ENDPOINTS.pcdnValidate, { method: 'POST', body: JSON.stringify({
        enabled, mode: 'block', source_id: current.source_id || 'openhosts-pcdn'
      }) });
      if (!bool(validation.valid ?? validation.ok)) throw new Error(asArray(validation.blockers).map((item) => ERROR_TEXT[item] || item).join('、') || message(validation));
      state.saving = false;
      state.confirm = {
        action: 'pcdn-save', tone: 'warning', title: enabled ? '启用 PCDN 屏蔽？' : '停用 PCDN 屏蔽？',
        description: enabled ? '将把已校验的 PCDN 域名规则应用到 DNS 数据面。' : '将撤销 PCDN DNS 阻止规则。',
        confirmLabel: enabled ? '启用' : '停用', enabled
      };
      render();
    } catch (error) { state.error = message(error, 'PCDN 配置校验失败'); state.saving = false; render(); }
  }
  async function commitPcdn(enabled) {
    const current = pcdnSettings();
    state.confirm = null; state.saving = true; render();
    try {
      const result = await requestJson(ENDPOINTS.pcdn, { method: 'PUT', body: JSON.stringify({
        enabled, mode: 'block', source_id: current.source_id || 'openhosts-pcdn',
        revision: Number(current.revision), confirm: true, apply: true
      }) });
      state.pcdn = result?.data || result || state.pcdn;
      state.pcdnPendingIntent = null;
      const applied = pcdnSettings();
      state.notice = enabled
        ? bool(applied.effective_blocking) ? 'PCDN 域名阻止已启用并完成数据面回读。' : 'PCDN 设置已保存，但数据面尚未确认生效。'
        : !bool(applied.effective_blocking) && applied.apply_state === 'disabled' ? 'PCDN 域名阻止已停用。' : 'PCDN 停用请求已保存，等待数据面回读。';
      state.saving = false; render();
    } catch (error) {
      if (error.code === 'pcdn_revision_conflict') {
        state.pcdnPendingIntent = enabled;
        try { state.pcdn = await requestJson(ENDPOINTS.pcdn); } catch (_) {}
        state.error = 'PCDN 配置已被其他会话修改，已重新读取最新状态；请核对后再次校验。';
      } else state.error = message(error, 'PCDN 配置保存失败');
      state.saving = false; render();
    }
  }
  function previewFeedUpdate(feedId = '') {
    const feed = feedItems().find((item) => item.feed_id === feedId);
    state.feedPreview = feed || { feed_id: '', name: '全部规则源', format: '后端内置清单' };
    render();
  }
  async function startFeedUpdate() {
    const feedId = firstText(state.feedPreview?.feed_id);
    state.feedPreview = null; state.saving = true; state.error = ''; render();
    try {
      await requestJson(ENDPOINTS.feedUpdate, { method: 'POST', body: JSON.stringify({ feed_id: feedId, dry_run: false, background: true }) });
      state.jobPollAttempts = 0;
      state.notice = feedId ? '规则源后台更新已启动。' : '全部规则源后台更新已启动。';
      state.saving = false; await loadIntrusion({ silent: true });
    } catch (error) { state.error = message(error, '规则源更新失败'); state.saving = false; render(); }
  }
  async function startFeedImport() {
    state.confirm = null; state.saving = true; state.error = ''; render();
    try {
      await requestJson(ENDPOINTS.feedImport, { method: 'POST', body: JSON.stringify({ background: true }) });
      state.jobPollAttempts = 0;
      state.notice = '规则导入后台任务已启动。'; state.saving = false; await loadIntrusion({ silent: true });
    } catch (error) { state.error = message(error, '规则导入失败'); state.saving = false; render(); }
  }
  async function setSignatureSuppressed(item) {
    state.confirm = null; state.saving = true; state.error = ''; render();
    const endpoint = item.suppressed ? ENDPOINTS.signatureUnsuppress : ENDPOINTS.signatureSuppress;
    try {
      const result = await requestJson(endpoint, { method: 'POST', body: JSON.stringify({
        gid: 1, sid: item.sid, target_rev: item.targetRev, revision: item.revision,
        reason: item.suppressed ? 'restored_from_aegisx_ui' : 'suppressed_from_aegisx_ui'
      }) });
      state.notice = bool(result.runtime_available)
        ? `签名 SID ${item.sid} 已保存，等待 Suricata 应用。`
        : `签名 SID ${item.sid} 已持久化；当前缺少 Suricata 生产运行组件。`;
      state.saving = false; await loadIntrusion({ silent: true });
    } catch (error) {
      state.error = ['revision_conflict', 'signature_revision_mismatch'].includes(error.code)
        ? '签名策略或规则版本已变化，已重新读取，请核对后再次操作。'
        : message(error, '签名策略保存失败');
      state.saving = false; await loadIntrusion({ silent: true });
    }
  }
  function editSignature(sid) {
    const item = signatureItems().find((entry) => Number(entry.sid) === Number(sid));
    if (!item) return;
    const override = item.override || {};
    state.signatureDraft = {
      gid: 1, sid: Number(item.sid), target_rev: Number(item.rev), revision: Number(override.revision) || 0,
      enabled_override: Number.isInteger(Number(override.enabled_override)) ? Number(override.enabled_override) : -1,
      action: firstText(override.action, 'inherit'), suppressed: bool(override.suppressed), reason: firstText(override.reason), msg: firstText(item.msg)
    };
    render();
  }
  async function saveSignaturePolicy() {
    const draft = state.signatureDraft;
    if (!draft) return;
    state.saving = true; state.error = ''; render();
    try {
      const result = await requestJson(ENDPOINTS.signaturePolicies, { method: 'PUT', body: JSON.stringify({
        gid: draft.gid, sid: draft.sid, target_rev: draft.target_rev, revision: draft.revision,
        enabled_override: Number(draft.enabled_override), action: draft.action, suppressed: draft.suppressed, reason: draft.reason
      }) });
      state.signatureDraft = null;
      state.notice = bool(result.runtime_available)
        ? `签名 SID ${draft.sid} 的策略已保存，等待 Suricata 应用。`
        : `签名 SID ${draft.sid} 的策略已持久化；当前缺少 Suricata 生产运行组件。`;
      state.saving = false; await loadIntrusion({ silent: true });
    } catch (error) {
      state.error = ['revision_conflict', 'signature_revision_mismatch'].includes(error.code)
        ? '签名策略或规则版本已变化，已重新读取；原编辑内容未自动覆盖。'
        : message(error, '签名策略保存失败');
      state.saving = false; await loadIntrusion({ silent: true });
    }
  }
  async function clearTrafficHistory() {
    state.confirm = null; state.saving = true; render();
    try {
      const result = await requestJson(ENDPOINTS.trafficHistoryClear, { method: 'POST', body: JSON.stringify({ confirm: true }) });
      const before = result?.before || result?.rows_before || {};
      const count = Object.values(before).reduce((sum, value) => sum + (Number(value) || 0), 0);
      state.notice = count ? `已清除 ${formatNumber(count)} 条设备与流量历史记录。` : '设备与流量历史已清除。';
      state.saving = false; await load({ silent: true });
    } catch (error) { state.error = message(error, '流量历史清理失败'); state.saving = false; render(); }
  }
  async function addDomain(policyId, action, domain) {
    if (!domain.trim()) { state.error = '请输入域名'; render(); return; }
    state.saving = true; render();
    const payload = { policy_id: policyId, domain: domain.trim(), action, enabled: true, note: '', confirm: true, apply: true };
    try {
      await requestJson(ENDPOINTS.overrides, { method: 'POST', body: JSON.stringify(payload) });
      state.notice = `${action === 'allow' ? '允许' : '阻止'}域名已添加并应用。`; state.saving = false; await load({ silent: true });
    } catch (error) { state.error = message(error, '域名规则添加失败'); state.saving = false; render(); }
  }
  async function deleteResource(kind, id) {
    state.confirm = null; state.saving = true; render();
    const url = kind === 'content' ? `${ENDPOINTS.content}/${encodeURIComponent(id)}` : kind === 'domain' ? `${ENDPOINTS.overrides}/${encodeURIComponent(id)}` : kind === 'app-block' ? `${ENDPOINTS.appBlocks}/${encodeURIComponent(id)}` : `${ENDPOINTS.honeypotConfig}/${encodeURIComponent(id)}`;
    const payload = kind === 'honeypot' ? { confirm: true } : kind === 'app-block' ? { confirm: true, revision: Number(state.appBlocks?.revision) } : { confirm: true, apply: true };
    try {
      await requestJson(url, { method: 'DELETE', body: JSON.stringify(payload) });
      state.notice = kind === 'app-block' ? '应用阻止规则已删除，内核运行态已刷新。' : '资源已删除，运行态已刷新。'; state.saving = false; await load({ silent: true });
    } catch (error) { state.error = message(error, '删除失败'); state.saving = false; render(); }
  }
  function honeypotPayload() {
    const draft = state.honeypotDraft || defaultHoneypotDraft();
    return { ...draft, enabled: draft.enabled !== false, services: draft.services, max_connections: 128, max_per_source: 8, capture_bytes: 4096, idle_timeout: 20, session_timeout: 60 };
  }
  async function validateHoneypot() {
    const payload = honeypotPayload();
    state.saving = true; state.error = ''; render();
    try {
      const validation = await requestJson(ENDPOINTS.honeypotValidate, { method: 'POST', body: JSON.stringify(payload) });
      if (!bool(validation.valid ?? validation.ok)) throw new Error(asArray(validation.blockers).map((item) => ERROR_TEXT[item] || item).join('、') || message(validation));
      state.saving = false;
      await commitHoneypot(payload);
    } catch (error) { state.error = message(error, '蜜罐校验失败'); state.saving = false; render(); }
  }
  async function commitHoneypot(payload) {
    state.confirm = null; state.saving = true; render();
    try {
      await requestJson(ENDPOINTS.honeypotConfig, { method: 'PUT', body: JSON.stringify({ ...payload, confirm: true }) });
      state.notice = '蜜罐配置已创建并完成运行态回读。'; state.drawer = ''; state.honeypotDraft = null; state.saving = false; await load({ silent: true });
    } catch (error) { state.error = message(error, '蜜罐创建失败'); state.saving = false; render(); }
  }
  function bindEvents() {
    queryAll('[data-aegis-tab]').forEach((button) => button.addEventListener('click', () => { state.tab = button.dataset.aegisTab; rememberTab(state.tab); state.drawer = ''; state.notice = ''; render(); }));
    queryAll('[data-aegis-close], [data-dwrt-confirm-cancel]').forEach((button) => button.addEventListener('click', () => { if (button.closest('[data-dwrt-confirmation]')) state.confirm = null; else { state.drawer = ''; state.contentDraft = null; state.appBlockDraft = null; state.honeypotDraft = null; state.signatureDraft = null; state.feedPreview = null; window.clearTimeout(jobPollTimer); } render(); }));
    queryAll('[data-aegis-action]').forEach((button) => button.addEventListener('click', () => {
      if (button.disabled) return;
      const action = button.dataset.aegisAction;
      if (action === 'content-new') { state.contentDraft = defaultContentDraft(); state.drawer = 'content'; }
      else if (action === 'content-edit') { state.contentDraft = defaultContentDraft(contentPolicies().find((item) => item.id === button.dataset.aegisValue)); state.drawer = 'content'; }
      else if (action === 'app-block-new') { state.appBlockDraft = defaultAppBlockDraft(); state.drawer = 'app-block'; }
      else if (action === 'honeypot-new') { state.honeypotDraft = defaultHoneypotDraft(); state.drawer = 'honeypot'; }
      else if (action === 'pcdn-sync') { previewPcdnSync(); return; }
      else if (action === 'pcdn-apply-current') { validatePcdn(bool(pcdnSettings().enabled)); return; }
      else if (action === 'pcdn-retry') { validatePcdn(Boolean(state.pcdnPendingIntent)); return; }
      else if (action === 'intrusion') { state.drawer = 'intrusion'; render(); loadIntrusion({ silent: true }); return; }
      else if (action === 'intrusion-refresh') { loadIntrusion(); return; }
      else if (action === 'feed-update') { previewFeedUpdate(); return; }
      else if (action === 'feed-import') { state.confirm = { action: 'feed-import', tone: 'warning', title: '重新导入规则？', description: '将从已下载并校验的 artifact 后台重建签名、域名分类和信誉数据库；不会自动启用生产 IDS/IPS。', confirmLabel: '开始导入' }; render(); return; }
      else if (action === 'log-center') { window.location.hash = '#/logs'; return; }
      else if (action === 'traffic-clear') { state.confirm = { action: 'traffic-clear', tone: 'danger', title: '清除流量历史？', description: '将永久清除设备与流量识别产生的日汇总、明细和客户端快照。安全事件日志不受影响。', confirmLabel: '清除历史' }; render(); return; }
      else state.drawer = action;
      render();
    }));
    query('[data-aegis-toggle="geo-enabled"]')?.addEventListener('change', (event) => {
      const enabled = event.target.checked;
      state.geoDraftEnabled = enabled;
      updateGeoRule({ enabled });
      if (enabled) render();
      else saveGeo({ closeDrawer: false });
    });
    queryAll('[data-geo-action]').forEach((button) => button.addEventListener('click', () => { updateGeoRule({ action: button.dataset.geoAction }); if (selectedCountries().length) saveGeo({ closeDrawer: false }); else render(); }));
    queryAll('input[name="geo-direction"]').forEach((input) => input.addEventListener('change', () => { updateGeoRule({ direction: input.value }); if (selectedCountries().length) saveGeo({ closeDrawer: false }); else render(); }));
    queryAll('input[name="identification"]').forEach((input) => input.addEventListener('change', () => { if (input.checked) saveIdentification(input.value); }));
    query('[data-geo-search]')?.addEventListener('input', (event) => { state.geoQuery = event.target.value; rerenderWithFocus('[data-geo-search]', state.geoQuery); });
    queryAll('[data-geo-country]').forEach((input) => input.addEventListener('change', () => {
      const item = geoCountries().find((country) => firstText(country.id, country.code) === input.dataset.geoCountry);
      if (item) item.enabled = input.checked;
      const count = query('.aegisx-drawer-toolbar > span');
      if (count) count.textContent = `已选 ${selectedCountries().length} / 可配置 ${geoCountries().length}`;
    }));
    query('[data-geo-save]')?.addEventListener('click', saveGeo);
    query('[data-event-search]')?.addEventListener('input', (event) => { state.eventQuery = event.target.value; rerenderWithFocus('[data-event-search]', state.eventQuery); });
    queryAll('[data-content-field]').forEach((input) => input.addEventListener('input', () => { state.contentDraft[input.dataset.contentField] = input.value; }));
    query('[data-aegis-toggle="content-enabled"]')?.addEventListener('change', (event) => { state.contentDraft.enabled = event.target.checked; });
    query('[data-aegis-toggle="content-ad-block"]')?.addEventListener('change', (event) => { state.contentDraft.ad_block = event.target.checked; });
    queryAll('[data-content-safe-search]').forEach((input) => input.addEventListener('change', () => { state.contentDraft.safe_search[input.dataset.contentSafeSearch] = input.checked; }));
    queryAll('input[name="content-mode"]').forEach((input) => input.addEventListener('change', () => { state.contentDraft.mode = input.value; }));
    query('[data-content-save]')?.addEventListener('click', validateContent);
    query('[data-aegis-toggle="pcdn-enabled"]')?.addEventListener('change', (event) => { const enabled = event.target.checked; event.target.checked = !enabled; validatePcdn(enabled); });
    queryAll('[data-feed-update]').forEach((button) => button.addEventListener('click', () => previewFeedUpdate(button.dataset.feedUpdate)));
    query('[data-feed-preview-cancel]')?.addEventListener('click', () => { state.feedPreview = null; render(); });
    query('[data-feed-preview-confirm]')?.addEventListener('click', startFeedUpdate);
    query('[data-signature-search]')?.addEventListener('input', (event) => { state.signatureQuery = event.target.value.replace(/[^0-9]/g, ''); state.signaturePage = 0; window.clearTimeout(jobPollTimer); jobPollTimer = window.setTimeout(() => loadIntrusion({ silent: true }), 320); });
    queryAll('[data-signature-page]').forEach((button) => button.addEventListener('click', () => { state.signaturePage = Math.max(0, state.signaturePage + (button.dataset.signaturePage === 'next' ? 1 : -1)); loadIntrusion(); }));
    queryAll('[data-signature-edit]').forEach((button) => button.addEventListener('click', () => editSignature(button.dataset.signatureEdit)));
    query('[data-signature-edit-cancel]')?.addEventListener('click', () => { state.signatureDraft = null; render(); });
    queryAll('[data-signature-field]').forEach((input) => input.addEventListener('input', () => { if (state.signatureDraft) state.signatureDraft[input.dataset.signatureField] = input.dataset.signatureField === 'enabled_override' ? Number(input.value) : input.value; }));
    query('[data-signature-save]')?.addEventListener('click', saveSignaturePolicy);
    queryAll('[data-signature-suppress]').forEach((button) => button.addEventListener('click', () => {
      const item = { sid: Number(button.dataset.signatureSuppress), targetRev: Number(button.dataset.signatureRev), revision: Number(button.dataset.signatureRevision), suppressed: button.dataset.signatureSuppressed === '1' };
      state.confirm = { action: 'signature-suppress', tone: 'warning', title: item.suppressed ? '取消抑制此签名？' : '抑制此签名？', description: `将修改 SID ${item.sid} 的控制面策略。当前 Suricata 数据面未就绪时只会持久化为等待应用。`, confirmLabel: item.suppressed ? '取消抑制' : '确认抑制', signature: item }; render();
    }));
    query('[data-app-block-new]')?.addEventListener('click', () => { state.appBlockDraft = defaultAppBlockDraft(); render(); });
    queryAll('[data-app-block-edit]').forEach((button) => button.addEventListener('click', () => { state.appBlockDraft = defaultAppBlockDraft(appBlocks().find((item) => item.id === button.dataset.appBlockEdit)); render(); }));
    queryAll('[data-app-block-delete]').forEach((button) => button.addEventListener('click', () => { const item = appBlocks().find((entry) => entry.id === button.dataset.appBlockDelete); state.confirm = { action: 'app-block-delete', tone: 'danger', title: '删除应用阻止规则？', description: `将删除“${item?.name || button.dataset.appBlockDelete}”，并请求 rulesd 撤销对应内核规则。`, confirmLabel: '删除规则', resourceId: button.dataset.appBlockDelete, resourceKind: 'app-block' }; render(); }));
    queryAll('[data-app-block-field]').forEach((input) => input.addEventListener('input', () => { state.appBlockDraft[input.dataset.appBlockField] = input.value; updateAppBlockSaveState(); }));
    query('[data-aegis-toggle="app-block-enabled"]')?.addEventListener('change', (event) => { state.appBlockDraft.enabled = event.target.checked; });
    queryAll('input[name="app-block-source-mode"]').forEach((input) => input.addEventListener('change', () => { state.appBlockDraft.source_mode = input.value === 'any' ? 'any' : state.clients.some((client) => clientMac(client)) ? 'client' : 'manual'; state.appBlockDraft.source = input.value === 'any' ? 'any' : state.appBlockDraft.source === 'any' ? '' : state.appBlockDraft.source; render(); }));
    query('[data-app-device-select]')?.addEventListener('change', (event) => { state.appBlockDraft.source_mode = event.target.value === 'manual' ? 'manual' : 'client'; state.appBlockDraft.source = event.target.value === 'manual' ? '' : event.target.value; render(); });
    queryAll('input[name="app-block-schedule"]').forEach((input) => input.addEventListener('change', () => { state.appBlockDraft.schedule_mode = input.value; if (!state.appBlockDraft.schedule_ranges.length) state.appBlockDraft.schedule_ranges = [{ weekdays: [1, 2, 3, 4, 5], start_time: '09:00', end_time: '18:00' }]; render(); }));
    queryAll('[data-app-id]').forEach((input) => input.addEventListener('change', () => { const id = Number(input.dataset.appId); state.appBlockDraft.app_ids = input.checked ? [...new Set([...state.appBlockDraft.app_ids, id])] : state.appBlockDraft.app_ids.filter((item) => item !== id); const count = query('[data-app-selected-count]'); if (count) count.textContent = `已选 ${state.appBlockDraft.app_ids.length} 个应用`; updateAppBlockSaveState(); }));
    queryAll('[data-app-range-weekday]').forEach((input) => input.addEventListener('change', () => { const range = state.appBlockDraft.schedule_ranges[Number(input.dataset.appRangeWeekday)]; const day = Number(input.value); range.weekdays = input.checked ? [...new Set([...range.weekdays, day])] : range.weekdays.filter((item) => item !== day); updateAppBlockSaveState(); }));
    queryAll('[data-app-range-field]').forEach((input) => input.addEventListener('input', () => { state.appBlockDraft.schedule_ranges[Number(input.dataset.appRangeIndex)][input.dataset.appRangeField] = input.value; updateAppBlockSaveState(); }));
    query('[data-app-range-add]')?.addEventListener('click', () => { state.appBlockDraft.schedule_ranges.push({ weekdays: [1, 2, 3, 4, 5], start_time: '09:00', end_time: '18:00' }); render(); });
    queryAll('[data-app-range-remove]').forEach((button) => button.addEventListener('click', () => { state.appBlockDraft.schedule_ranges.splice(Number(button.dataset.appRangeRemove), 1); render(); }));
    query('[data-app-search]')?.addEventListener('input', (event) => { state.appQuery = event.target.value; rerenderWithFocus('[data-app-search]', state.appQuery); });
    query('[data-app-block-save]')?.addEventListener('click', validateAppBlock);
    queryAll('[data-domain-add]').forEach((button) => button.addEventListener('click', () => { const input = query(`[data-domain-input="${button.dataset.domainAdd}"][data-policy-id="${CSS.escape(button.dataset.policyId)}"]`); addDomain(button.dataset.policyId, button.dataset.domainAdd, input?.value || ''); }));
    queryAll('[data-domain-delete]').forEach((button) => button.addEventListener('click', () => { const item = state.overrides.find((entry) => entry.id === button.dataset.domainDelete); state.confirm = { action: 'domain-delete', tone: 'danger', title: '删除域名规则？', description: `将删除 ${item?.domain || button.dataset.domainDelete} 并立即更新 DNS 过滤数据面。`, confirmLabel: '删除并应用', resourceId: button.dataset.domainDelete, resourceKind: 'domain' }; render(); }));
    queryAll('[data-content-delete]').forEach((button) => button.addEventListener('click', () => { const item = contentPolicies().find((entry) => entry.id === button.dataset.contentDelete); state.confirm = { action: 'content-delete', tone: 'danger', title: '删除内容过滤策略？', description: `将删除“${item?.name || button.dataset.contentDelete}”及其关联域名规则，并更新 DNS 过滤数据面。`, confirmLabel: '删除并应用', resourceId: button.dataset.contentDelete, resourceKind: 'content' }; render(); }));
    query('[data-honeypot-new]')?.addEventListener('click', () => { state.honeypotDraft = defaultHoneypotDraft(); render(); });
    queryAll('[data-honeypot-edit]').forEach((button) => button.addEventListener('click', () => { state.honeypotDraft = defaultHoneypotDraft(honeypots().find((item) => item.id === button.dataset.honeypotEdit)); render(); }));
    queryAll('[data-honeypot-delete]').forEach((button) => button.addEventListener('click', () => { const item = honeypots().find((entry) => entry.id === button.dataset.honeypotDelete); state.confirm = { action: 'honeypot-delete', tone: 'danger', title: '删除蜜罐？', description: `将删除“${item?.name || button.dataset.honeypotDelete}”并撤销对应运行态规则。`, confirmLabel: '删除蜜罐', resourceId: button.dataset.honeypotDelete, resourceKind: 'honeypot' }; render(); }));
    queryAll('[data-honeypot-field]').forEach((input) => input.addEventListener('input', () => { state.honeypotDraft[input.dataset.honeypotField] = input.value; }));
    queryAll('[data-honeypot-service]').forEach((input) => input.addEventListener('change', () => { const service = input.dataset.honeypotService; state.honeypotDraft.services = input.checked ? [...new Set([...state.honeypotDraft.services, service])] : state.honeypotDraft.services.filter((item) => item !== service); }));
    query('[data-honeypot-save]')?.addEventListener('click', validateHoneypot);
    query('[data-dwrt-confirm-accept]')?.addEventListener('click', () => { const confirm = state.confirm; if (!confirm) return; if (confirm.action === 'content-save') commitContent(confirm.payload); else if (confirm.action === 'app-block-save') commitAppBlock(confirm.payload, confirm.revision); else if (confirm.action === 'pcdn-save') commitPcdn(confirm.enabled); else if (confirm.action === 'pcdn-sync') commitPcdnSync(); else if (confirm.action === 'feed-import') startFeedImport(); else if (confirm.action === 'signature-suppress') setSignatureSuppressed(confirm.signature); else if (confirm.action === 'traffic-clear') clearTrafficHistory(); else if (confirm.action === 'honeypot-save') commitHoneypot(confirm.payload); else deleteResource(confirm.resourceKind, confirm.resourceId); });
  }

  stage?.classList.add('is-aegisx');
  render();
  load();
  return { unmount() { state.mounted = false; state.seq += 1; window.clearTimeout(jobPollTimer); portal?.remove(); portal = null; stage?.classList.remove('is-aegisx'); root?.replaceChildren(); root?.classList.remove('aegisx-route-host', 'policy-table-route-host', 'route-workspace'); } };
}
