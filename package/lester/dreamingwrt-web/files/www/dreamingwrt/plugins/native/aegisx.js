export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const utils = context.utils || {};
  const ui = context.ui || {};
  const VERSION = '20260719-13';
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
    lans: '/api/v1/network/lans'
  };
  const TABS = [
    { id: 'protect', label: '保护' },
    { id: 'content', label: '内容过滤器' },
    { id: 'logging', label: '流量日志' }
  ];
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
    honeypotd_binary_missing: '设备缺少蜜罐运行程序', invalid_services: '至少选择一项蜜罐服务', unsupported_honeypot_service: '包含后端不支持的蜜罐服务'
  };
  const state = {
    tab: 'protect', loading: true, error: '', notice: '', saving: false, drawer: '', confirm: null,
    status: {}, runtime: {}, stats: {}, health: {}, events: [], geo: { countries: [], rules: [], feeds: [], events: [] },
    honeypot: { items: [], runtime: {}, capabilities: {} }, honeypotEvents: [], content: { items: [], runtime: {}, capabilities: {} },
    overrides: [], lans: [], contentDraft: null, honeypotDraft: null, geoQuery: '', eventQuery: '', mounted: true, seq: 0
  };
  let portal = null;

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
    if (!response.ok || json?.ok === false || payload?.ok === false) throw new Error(message(payload?.error || payload?.message || json?.error || response.status));
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
      edit: '<path d="M12 20h9"></path><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4Z"></path>',
      trash: '<path d="M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13M10 11v5M14 11v5"></path>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.shield}</svg>`;
  }
  function info(text) {
    return `<span class="aegisx-info" tabindex="0" aria-label="${escapeHtml(text)}" data-dwrt-tooltip="${escapeHtml(text)}"><span aria-hidden="true">i</span></span>`;
  }
  function stateBadge(label, tone = 'neutral') {
    return ui.statusBadgeMarkup?.(label, tone) || `<span>${escapeHtml(label)}</span>`;
  }
  function switchControl(name, checked, enabled = false, label = '') {
    return `<label class="aegisx-switch ${enabled ? '' : 'is-disabled'}" ${enabled ? '' : `data-dwrt-tooltip="${escapeHtml(label || '后端未开放写入')}"`}><input type="checkbox" data-aegis-toggle="${name}" ${checked ? 'checked' : ''} ${enabled ? '' : 'disabled'} aria-label="${escapeHtml(label || name)}"><i></i></label>`;
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
      ['content', ENDPOINTS.content], ['overrides', ENDPOINTS.overrides], ['lans', ENDPOINTS.lans]
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
      else if (key === 'lans') state.lans = asArray(value?.data || value, ['lans', 'items']);
      else state[key] = value;
    });
    const failures = results.filter((item) => item.status === 'rejected').map((item) => message(item.reason)).filter(Boolean);
    state.error = failures.length ? `部分状态读取失败：${[...new Set(failures)].join(' · ')}` : '';
    state.loading = false;
    render();
  }

  function renderTabs() {
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs aegisx-tabs" role="tablist" aria-label="Aegisx 设置">
      <span class="dwrt-kit-tab-pill" aria-hidden="true"></span>
      ${TABS.map((tab) => `<button class="dwrt-kit-tab ${state.tab === tab.id ? 'is-active' : ''}" type="button" role="tab" aria-selected="${state.tab === tab.id}" data-aegis-tab="${tab.id}">${tab.label}</button>`).join('')}
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
  function countryFlag(country) {
    const code = firstText(country?.code, country?.id).toLowerCase().replace(/[^a-z-]/g, '');
    return code ? `<img src="/static/images/flags/${code}.svg" alt="" loading="lazy" decoding="async" onerror="this.hidden=true">` : '';
  }
  function honeypots() { return asArray(state.honeypot, ['items']); }
  function contentPolicies() { return asArray(state.content, ['items']); }
  function contentCaps() { return state.content?.capabilities || capabilities(); }
  function honeypotCaps() { return state.honeypot?.capabilities || capabilities(); }
  function renderProtect() {
    const rt = runtime();
    const idsSupported = bool(capabilities().ids_ips_supported);
    const idsActive = bool(rt.ids_ips_production_active) || bool(state.status.ids_ips_production_active);
    const idsReason = firstText(rt.suricata_reason, capabilities().suricata_apply_reason, idsActive ? '' : '运行组件未就绪');
    const geoSelected = selectedCountries();
    const regionRule = geoRule();
    const hpItems = honeypots();
    const hpRuntime = state.honeypot?.runtime || rt.honeypot_runtime || {};
    const hpSupported = bool(honeypotCaps().config ?? capabilities().honeypot_config_supported);
    const appBlockSupported = false;
    return `<section class="aegisx-panel dwrt-kit-glass-surface" aria-label="保护设置">
      ${row('简单应用阻止', '为内部和访客区域中的设备或网络阻止应用。', `${actionButton('新建', 'app-block', appBlockSupported)}${stateBadge('后端未开放', 'neutral')}`)}
      ${row('区域拦截', '根据国家或地区以及流量方向阻止或允许连接。', `<div class="aegisx-region-config">
        <label class="aegisx-region-enabled"><input type="checkbox" data-aegis-toggle="geo-enabled" ${bool(regionRule.enabled) ? 'checked' : ''} ${state.saving ? 'disabled' : ''} aria-label="启用区域拦截"><i></i></label>
        <div class="aegisx-region-actions" role="group" aria-label="区域规则动作">
          <button type="button" class="${regionRule.action !== 'allow' ? 'is-active' : ''}" data-geo-action="block" ${state.saving ? 'disabled' : ''}>${icon('ban')}<span>阻止</span></button>
          <button type="button" class="${regionRule.action === 'allow' ? 'is-active' : ''}" data-geo-action="allow" ${state.saving ? 'disabled' : ''}>${icon('checkCircle')}<span>允许</span></button>
        </div>
        <div class="aegisx-region-directions">${radio('geo-direction', 'both', !['outbound', 'inbound'].includes(regionRule.direction), '双向', true)}${radio('geo-direction', 'outbound', regionRule.direction === 'outbound', '传出', true)}${radio('geo-direction', 'inbound', regionRule.direction === 'inbound', '传入', true)}</div>
        <div class="aegisx-region-country-action">${actionButton('选择国家或地区', 'geo-block', geoCountries().length > 0)}<small>${geoSelected.length ? `已选 ${geoSelected.length} 个国家或地区` : '尚未选择国家或地区'}</small></div>
      </div>`)}
      ${row('蜜罐', '检测并记录对指定 IPv4 地址的请求，以发现网络中的异常客户端。', `<div class="aegisx-honeypot-row">${hpItems.length ? `<div class="aegisx-inline-summary"><strong>${hpItems.length} 个蜜罐</strong><small>${bool(hpRuntime.active) ? `运行中 · ${formatNumber(hpRuntime.hits)} 次命中` : '当前未运行'}</small></div>${actionButton('管理', 'honeypot', hpSupported)}` : ''}${actionButton('新建', 'honeypot-new', hpSupported)}</div>`)}
      ${row('识别', '识别设备类型和网关流量。', `<div class="aegisx-choice-row">${radio('identification', 'disabled', false, '已禁用')}${radio('identification', 'device_traffic', false, '设备和流量')}${radio('identification', 'traffic', false, '仅流量')}</div>${stateBadge('后端未开放', 'neutral')}`)}
      ${row('拦截页面', '为内容过滤命中的网站显示解释页面。', `${switchControl('block-page', false, false, 'SSL 检查与证书接口尚未实现')}<span class="aegisx-certificate">Aegisx SSL Certificate</span>${stateBadge('后端未开放', 'neutral')}`, { detail: '<p class="aegisx-explanation">证书生成、下载和终端分发接口尚未实现，因此不会伪造可用开关。</p>' })}
      ${row('入侵防御', '通过特征更新和深度数据包检测来检测和阻止威胁。', `<div class="aegisx-segment" aria-label="入侵防御"><button type="button" class="${idsActive ? '' : 'is-active'}" disabled>关</button><button type="button" class="${idsActive ? 'is-active' : ''}" disabled>开</button></div>${stateBadge(idsActive ? '生产防护已启用' : idsSupported ? '运行组件未就绪' : '后端未开放', idsActive ? 'ok' : 'warn')}<small class="aegisx-reason">${escapeHtml(idsReason)}</small>`)}
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
    const runtimeState = state.content?.runtime || runtime().content_filter || {};
    return `<section class="aegisx-content-workspace">
      <header class="aegisx-section-header dwrt-kit-glass-surface"><div><strong>内容过滤策略</strong><span>${bool(runtimeState.active) ? '数据面已应用' : bool(runtimeState.managed) ? '配置待应用' : '当前沿用旧版规则'}</span></div>${actionButton('新建策略', 'content-new', writable, { primary: true })}</header>
      ${policies.length ? `<div class="aegisx-policy-list">${policies.map((policy) => `<article class="aegisx-resource-card dwrt-kit-glass-surface">
        <header><div><strong>${escapeHtml(policy.name)}</strong><span>${escapeHtml(policy.id)}</span></div>${stateBadge(policy.enabled === false || policy.mode === 'off' ? '已停用' : policy.apply_state === 'active' ? '已应用' : '待应用', policy.apply_state === 'active' ? 'ok' : policy.apply_state === 'pending' ? 'warn' : 'neutral')}</header>
        <div class="aegisx-resource-meta"><span>过滤级别 <b>${policy.mode === 'enhanced' ? '增强' : policy.mode === 'off' ? '关闭' : '基础'}</b></span><span>广告拦截 <b>${policy.ad_block ? '开启' : '关闭'}</b></span><span>范围 <b>全部网络</b></span><span>计划 <b>始终</b></span></div>
        <div class="aegisx-domain-grid">${renderDomainList(policy, 'allow')}${renderDomainList(policy, 'block')}</div>
        <footer>${actionButton('编辑', 'content-edit', writable, { value: policy.id, icon: 'edit' })}<button class="aegisx-icon-action is-danger" type="button" data-content-delete="${escapeHtml(policy.id)}" aria-label="删除 ${escapeHtml(policy.name)}">${icon('trash')}</button></footer>
      </article>`).join('')}</div>` : `<div class="aegisx-empty dwrt-kit-glass-surface">${icon('filter')}<strong>尚未创建内容过滤策略</strong><span>后端已支持基础、增强、广告拦截、全局范围和域名允许/阻止规则。</span>${actionButton('新建策略', 'content-new', writable, { primary: true })}</div>`}
      <aside class="aegisx-capability-note dwrt-kit-glass-surface"><strong>当前能力边界</strong><span>安全搜索、按设备/网络作用域以及定时计划仍由后端明确标记为不支持，控件保持禁用。</span></aside>
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
  function renderLogging() {
    const events = filteredEvents();
    const stats = state.stats || {};
    return `<section class="aegisx-logging-workspace">
      <div class="aegisx-stat-grid">
        <article class="dwrt-kit-glass-surface"><span>安全事件</span><strong>${formatNumber(stats.events)}</strong><small>近期事件总量</small></article>
        <article class="dwrt-kit-glass-surface"><span>拦截</span><strong>${formatNumber(stats.blocks)}</strong><small>DNS 与信誉拦截</small></article>
        <article class="dwrt-kit-glass-surface"><span>路由策略命中</span><strong>${formatNumber(stats.route_policy_hits)}</strong><small>已验证生产事件</small></article>
        <article class="dwrt-kit-glass-surface"><span>蜜罐命中</span><strong>${formatNumber(stats.honeypot_hits)}</strong><small>诱捕服务事件</small></article>
      </div>
      <section class="aegisx-events-card dwrt-kit-glass-surface"><header><div><strong>近期活动</strong><span>来自 Aegisx 真实事件接口，最多显示最近 100 条。</span></div><label class="aegisx-event-search">${icon('search')}<input type="search" data-event-search value="${escapeHtml(state.eventQuery)}" placeholder="搜索事件"></label></header>
        <div class="dwrt-kit-table-wrap"><table class="dwrt-kit-table aegisx-events-table"><thead><tr><th>时间</th><th>事件</th><th>动作</th><th>策略 / 来源</th><th>终端 / 目标</th><th>状态</th></tr></thead><tbody>${events.length ? events.map((event) => `<tr><td>${escapeHtml(formatTime(event.ts))}</td><td><strong>${escapeHtml(eventLabel(event.event_type))}</strong><small>${escapeHtml(event.risk || event.level || '')}</small></td><td>${escapeHtml(event.action || '--')}</td><td><strong>${escapeHtml(event.policy_name || event.rule_name || '--')}</strong><small>${escapeHtml(event.source || '')}</small></td><td><strong>${escapeHtml(event.source_ip || event.source_mac || '--')}</strong><small>${escapeHtml(event.destination_host || event.destination_ip || '')}</small></td><td>${stateBadge(event.production_event === false ? '测试事件' : '生产事件', event.production_event === false ? 'warn' : 'ok')}</td></tr>`).join('') : '<tr><td colspan="6" class="aegisx-table-empty">没有匹配的安全事件</td></tr>'}</tbody></table></div>
      </section>
      <section class="aegisx-panel aegisx-unsupported-panel dwrt-kit-glass-surface">
        ${row('NetFlow (IPFIX)', '捕获流量信息并导出到收集器。', `${switchControl('netflow', false)}${stateBadge('后端未开放', 'neutral')}`)}
        ${row('Syslog / SIEM', '将活动日志发送到内部存储或 SIEM 服务器。', `${radio('syslog', 'off', true, '关')}${radio('syslog', 'internal', false, '内部存储')}${radio('syslog', 'siem', false, 'SIEM 服务器')}${stateBadge('后端未开放', 'neutral')}`)}
        ${row('SNMP 监控', '允许监控工具使用 SNMP 收集网络信息。', `${stateBadge('后端未开放', 'neutral')}`)}
      </section>
    </section>`;
  }

  function renderGeoDrawer() {
    const query = state.geoQuery.trim().toLowerCase();
    const countries = geoCountries().filter((country) => !query || [country.code, country.id, country.name, COUNTRY_NAMES[country.code || country.id], country.continent].join(' ').toLowerCase().includes(query));
    const selected = selectedCountries().length;
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-aegis-close aria-label="关闭区域拦截配置"></button><aside class="aegisx-drawer aegisx-geo-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open">
      <header class="dwrt-kit-sheet-header"><div><span>REGION BLOCKING</span><strong>选择国家或地区</strong></div><button class="dwrt-kit-sheet-close" type="button" data-aegis-close>×</button></header>
      <div class="dwrt-kit-sheet-body aegisx-drawer-body"><div class="aegisx-drawer-intro">所选国家或地区将使用保护页设置的动作和流量方向。当前接口会保存配置；生产 nftables 应用与命中回读仍等待后端补齐。</div><div class="aegisx-drawer-toolbar"><label>${icon('search')}<input type="search" data-geo-search value="${escapeHtml(state.geoQuery)}" placeholder="搜索国家或地区"></label><span>已选 ${selected} / 可配置 ${geoCountries().length}</span></div><div class="aegisx-country-list">${countries.map((country) => `<label><input type="checkbox" data-geo-country="${escapeHtml(country.id || country.code)}" ${country.enabled ? 'checked' : ''}><span class="aegisx-checkmark"></span>${countryFlag(country)}<b>${escapeHtml(COUNTRY_NAMES[country.code || country.id] || country.name || country.id)}</b><small>${escapeHtml(country.code || country.id)} · ${escapeHtml(country.continent || '')}</small></label>`).join('')}</div></div>
      <footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-aegis-close>取消</button><button class="policy-primary" type="button" data-geo-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存配置'}</button></footer>
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
      return `<div class="dwrt-kit-modal-layer aegisx-honeypot-modal-layer is-open"><button class="dwrt-kit-modal-backdrop" type="button" data-aegis-close aria-label="关闭蜜罐配置"></button><section class="dwrt-kit-modal aegisx-honeypot-modal dwrt-kit-glass-surface" role="dialog" aria-modal="true" aria-labelledby="aegisx-honeypot-title"><header class="dwrt-kit-modal-header"><div><h2 id="aegisx-honeypot-title">${editing ? '编辑蜜罐' : '创建蜜罐'}</h2></div><button class="dwrt-kit-modal-close" type="button" data-aegis-close aria-label="关闭">${icon('close')}</button></header><div class="dwrt-kit-modal-body aegisx-drawer-body aegisx-honeypot-modal-body">
        <label><span>网络</span><select data-honeypot-field="network_id">${state.lans.map((lan) => `<option value="${escapeHtml(firstText(lan.id, lan.name))}" ${firstText(lan.id, lan.name) === draft.network_id ? 'selected' : ''}>${escapeHtml(firstText(lan.name, lan.id))} · ${escapeHtml(lanSubnet(lan))}</option>`).join('')}</select></label>
        <label><span>蜜罐 IPv4 地址</span><input type="text" inputmode="decimal" data-honeypot-field="address" value="${escapeHtml(draft.address)}" placeholder="192.168.1.250"></label>
      </div><footer class="dwrt-kit-modal-footer"><button class="policy-secondary" type="button" data-aegis-close>取消</button><button class="policy-primary" type="button" data-honeypot-save ${state.saving || !draft.network_id || !draft.address.trim() ? 'disabled' : ''}>${state.saving ? '正在创建' : editing ? '保存' : '创建'}</button></footer></section></div>`;
    }
    return `<div class="dwrt-kit-modal-layer aegisx-honeypot-modal-layer is-open"><button class="dwrt-kit-modal-backdrop" type="button" data-aegis-close aria-label="关闭蜜罐管理"></button><section class="dwrt-kit-modal aegisx-honeypot-modal aegisx-honeypot-manager dwrt-kit-glass-surface" role="dialog" aria-modal="true" aria-labelledby="aegisx-honeypot-manager-title"><header class="dwrt-kit-modal-header"><div><h2 id="aegisx-honeypot-manager-title">蜜罐</h2></div><button class="dwrt-kit-modal-close" type="button" data-aegis-close aria-label="关闭">${icon('close')}</button></header><div class="dwrt-kit-modal-body aegisx-drawer-body"><div class="aegisx-honeypot-list">${items.map((item) => `<article><div><strong>${escapeHtml(item.name)}</strong><span>${escapeHtml(item.address)} · ${escapeHtml(item.network_id)}</span></div>${stateBadge(item.apply_state === 'active' ? '运行中' : item.enabled === false ? '已停用' : '未运行', item.apply_state === 'active' ? 'ok' : 'warn')}<div><button type="button" data-honeypot-edit="${escapeHtml(item.id)}">编辑</button><button type="button" data-honeypot-delete="${escapeHtml(item.id)}">删除</button></div></article>`).join('')}</div>${state.honeypotEvents.length ? `<section class="aegisx-honeypot-events"><strong>近期命中</strong>${state.honeypotEvents.slice(0, 8).map((event) => `<span><b>${escapeHtml(firstText(event.source_ip, event.source_mac, '未知终端'))}</b><small>${escapeHtml(formatTime(event.ts || event.last_seen))}</small></span>`).join('')}</section>` : ''}</div><footer class="dwrt-kit-modal-footer"><button class="policy-secondary" type="button" data-aegis-close>关闭</button><button class="policy-primary" type="button" data-honeypot-new>新建</button></footer></section></div>`;
  }
  function renderContentDrawer() {
    const draft = state.contentDraft || defaultContentDraft();
    const caps = contentCaps();
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-aegis-close aria-label="关闭内容策略编辑器"></button><aside class="aegisx-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open"><header class="dwrt-kit-sheet-header"><div><span>CONTENT FILTER</span><strong>${contentPolicies().some((item) => item.id === draft.id) ? '编辑内容策略' : '新建内容策略'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-aegis-close>×</button></header><div class="dwrt-kit-sheet-body aegisx-drawer-body">
      <label><span>名称</span><input type="text" data-content-field="name" value="${escapeHtml(draft.name)}" placeholder="家庭内容过滤"></label>
      <div class="aegisx-drawer-field"><span>启用</span>${switchControl('content-enabled', draft.enabled, true, '启用内容策略')}</div>
      <div class="aegisx-drawer-field"><span>过滤级别</span><div class="aegisx-choice-row">${radio('content-mode', 'off', draft.mode === 'off', '关', true)}${radio('content-mode', 'basic', draft.mode === 'basic', '基础', true)}${radio('content-mode', 'enhanced', draft.mode === 'enhanced', '增强', true)}</div></div>
      <div class="aegisx-drawer-field"><span>源 ${info('当前后端仅支持全部网络。')}</span><strong>全部网络</strong></div>
      <div class="aegisx-drawer-field"><span>广告拦截</span>${switchControl('content-ad-block', draft.ad_block, bool(caps.ad_block_supported ?? capabilities().content_filter_ad_block_supported), '广告拦截')}</div>
      <div class="aegisx-drawer-field"><span>安全搜索 ${info('过滤搜索结果中的露骨内容。')}</span><div class="aegisx-check-row"><label><input type="checkbox" disabled><i></i>Google</label><label><input type="checkbox" disabled><i></i>Bing</label><label><input type="checkbox" disabled><i></i>YouTube</label></div><small>后端未开放</small></div>
      <div class="aegisx-drawer-field"><span>计划</span><div class="aegisx-choice-row">${radio('content-schedule', 'always', true, '始终', true)}${radio('content-schedule', 'daily', false, '每天', false, '后端尚未支持计划')}${radio('content-schedule', 'weekly', false, '每周', false, '后端尚未支持计划')}</div></div>
    </div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-aegis-close>取消</button><button class="policy-primary" type="button" data-content-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在校验' : '校验并应用'}</button></footer></aside>`;
  }
  function renderDrawer() {
    if (state.drawer === 'geo-block') return renderGeoDrawer();
    if (state.drawer === 'honeypot') return renderHoneypotModal();
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

  function closeDrawer() { state.drawer = ''; state.contentDraft = null; state.honeypotDraft = null; render(); }
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
      if (options.closeDrawer !== false) state.drawer = '';
      await load({ silent: true });
    } catch (error) { state.error = message(error, '区域配置保存失败'); state.saving = false; await load({ silent: true }); }
  }
  function contentPayload() {
    const draft = state.contentDraft || defaultContentDraft();
    return { ...draft, enabled: draft.enabled !== false, scope: { type: 'all', devices: [], networks: [] }, safe_search: { google: false, bing: false, youtube: false }, schedule: { type: 'always' } };
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
    const url = kind === 'content' ? `${ENDPOINTS.content}/${encodeURIComponent(id)}` : kind === 'domain' ? `${ENDPOINTS.overrides}/${encodeURIComponent(id)}` : `${ENDPOINTS.honeypotConfig}/${encodeURIComponent(id)}`;
    const payload = kind === 'honeypot' ? { confirm: true } : { confirm: true, apply: true };
    try {
      await requestJson(url, { method: 'DELETE', body: JSON.stringify(payload) });
      state.notice = '资源已删除，运行态已刷新。'; state.saving = false; await load({ silent: true });
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
    queryAll('[data-aegis-tab]').forEach((button) => button.addEventListener('click', () => { state.tab = button.dataset.aegisTab; state.drawer = ''; state.notice = ''; render(); }));
    queryAll('[data-aegis-close], [data-dwrt-confirm-cancel]').forEach((button) => button.addEventListener('click', () => { if (button.closest('[data-dwrt-confirmation]')) state.confirm = null; else { state.drawer = ''; state.contentDraft = null; state.honeypotDraft = null; } render(); }));
    queryAll('[data-aegis-action]').forEach((button) => button.addEventListener('click', () => {
      if (button.disabled) return;
      const action = button.dataset.aegisAction;
      if (action === 'content-new') { state.contentDraft = defaultContentDraft(); state.drawer = 'content'; }
      else if (action === 'content-edit') { state.contentDraft = defaultContentDraft(contentPolicies().find((item) => item.id === button.dataset.aegisValue)); state.drawer = 'content'; }
      else if (action === 'honeypot-new') { state.honeypotDraft = defaultHoneypotDraft(); state.drawer = 'honeypot'; }
      else state.drawer = action;
      render();
    }));
    query('[data-aegis-toggle="geo-enabled"]')?.addEventListener('change', (event) => { updateGeoRule({ enabled: event.target.checked }); saveGeo({ closeDrawer: false }); });
    queryAll('[data-geo-action]').forEach((button) => button.addEventListener('click', () => { updateGeoRule({ action: button.dataset.geoAction }); saveGeo({ closeDrawer: false }); }));
    queryAll('input[name="geo-direction"]').forEach((input) => input.addEventListener('change', () => { updateGeoRule({ direction: input.value }); saveGeo({ closeDrawer: false }); }));
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
    queryAll('input[name="content-mode"]').forEach((input) => input.addEventListener('change', () => { state.contentDraft.mode = input.value; }));
    query('[data-content-save]')?.addEventListener('click', validateContent);
    queryAll('[data-domain-add]').forEach((button) => button.addEventListener('click', () => { const input = query(`[data-domain-input="${button.dataset.domainAdd}"][data-policy-id="${CSS.escape(button.dataset.policyId)}"]`); addDomain(button.dataset.policyId, button.dataset.domainAdd, input?.value || ''); }));
    queryAll('[data-domain-delete]').forEach((button) => button.addEventListener('click', () => { const item = state.overrides.find((entry) => entry.id === button.dataset.domainDelete); state.confirm = { action: 'domain-delete', tone: 'danger', title: '删除域名规则？', description: `将删除 ${item?.domain || button.dataset.domainDelete} 并立即更新 DNS 过滤数据面。`, confirmLabel: '删除并应用', resourceId: button.dataset.domainDelete, resourceKind: 'domain' }; render(); }));
    queryAll('[data-content-delete]').forEach((button) => button.addEventListener('click', () => { const item = contentPolicies().find((entry) => entry.id === button.dataset.contentDelete); state.confirm = { action: 'content-delete', tone: 'danger', title: '删除内容过滤策略？', description: `将删除“${item?.name || button.dataset.contentDelete}”及其关联域名规则，并更新 DNS 过滤数据面。`, confirmLabel: '删除并应用', resourceId: button.dataset.contentDelete, resourceKind: 'content' }; render(); }));
    query('[data-honeypot-new]')?.addEventListener('click', () => { state.honeypotDraft = defaultHoneypotDraft(); render(); });
    queryAll('[data-honeypot-edit]').forEach((button) => button.addEventListener('click', () => { state.honeypotDraft = defaultHoneypotDraft(honeypots().find((item) => item.id === button.dataset.honeypotEdit)); render(); }));
    queryAll('[data-honeypot-delete]').forEach((button) => button.addEventListener('click', () => { const item = honeypots().find((entry) => entry.id === button.dataset.honeypotDelete); state.confirm = { action: 'honeypot-delete', tone: 'danger', title: '删除蜜罐？', description: `将删除“${item?.name || button.dataset.honeypotDelete}”并撤销对应运行态规则。`, confirmLabel: '删除蜜罐', resourceId: button.dataset.honeypotDelete, resourceKind: 'honeypot' }; render(); }));
    queryAll('[data-honeypot-field]').forEach((input) => input.addEventListener('input', () => { state.honeypotDraft[input.dataset.honeypotField] = input.value; }));
    queryAll('[data-honeypot-service]').forEach((input) => input.addEventListener('change', () => { const service = input.dataset.honeypotService; state.honeypotDraft.services = input.checked ? [...new Set([...state.honeypotDraft.services, service])] : state.honeypotDraft.services.filter((item) => item !== service); }));
    query('[data-honeypot-save]')?.addEventListener('click', validateHoneypot);
    query('[data-dwrt-confirm-accept]')?.addEventListener('click', () => { const confirm = state.confirm; if (!confirm) return; if (confirm.action === 'content-save') commitContent(confirm.payload); else if (confirm.action === 'honeypot-save') commitHoneypot(confirm.payload); else deleteResource(confirm.resourceKind, confirm.resourceId); });
  }

  render();
  load();
  return { unmount() { state.mounted = false; state.seq += 1; portal?.remove(); portal = null; root?.replaceChildren(); root?.classList.remove('aegisx-route-host', 'policy-table-route-host', 'route-workspace'); } };
}
