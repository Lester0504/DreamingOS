/*
 * 网址浏览控制。
 *
 * 后端底座是 aegis 的 content-policy + domain-overrides，不是爱快那张 url_black 表。
 * 两处能力差异直接决定了本页不放什么控件（`content_capabilities()`，
 * jmxd/src/aegisxd/aegisxd_content.c）：
 *
 *   device_scope_supported  = false  -> 不做「作用对象」选择器
 *   network_scope_supported = false
 *   schedule_supported      = false  -> 不做「生效时段」控件
 *
 * `content_canonical_object()` 对这两项是硬拒绝而不是静默忽略：scope 只接受
 * {"type":"all",devices:[],networks:[]}，否则回 `content_scope_not_supported`；
 * schedule 只接受 {"type":"always"}，否则回 `content_schedule_not_supported`。
 * 因此放出这两个控件等于给用户一个存不进去的输入框 —— design.md「Capability truth」
 * 第 10 条明确禁止。缺口已另开单给 Backend，不在本页伪装成可用。
 *
 * 写路径都要 `confirm:true`（缺了只回 dry_run），`apply:true` 才落数据面。
 */
export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const VERSION = '20260804-speed-limit-two-tabs-02';
  const stage = root?.closest('.console-stage');
  const POLICY_ID = 'web-access-control';
  const POLICY_NAME = '网址浏览控制';

  const state = {
    mounted: true,
    seq: 0,
    pollTimer: 0,
    loading: true,
    refreshing: false,
    saving: false,
    tab: 'rules',
    policy: null,
    policyMissing: false,
    categories: [],
    categoriesTotal: 0,
    categoriesAvailable: null,
    categoriesError: '',
    overrides: [],
    runtime: {},
    capabilities: {},
    capabilitiesKnown: false,
    query: '',
    filter: 'all',
    readOnly: false,
    readOnlyReason: '',
    error: '',
    notice: '',
    noticeTone: '',
    drawer: false,
    editor: {},
    confirmDelete: false,
    confirmMode: false
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

  function bool(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') return !['0', 'false', 'off', 'no', 'disabled'].includes(value.toLowerCase());
    return Boolean(value);
  }

  function asArray(value, keys = ['items', 'categories', 'rows', 'list', 'results']) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of keys) if (Array.isArray(value[key])) return value[key];
    return [];
  }

  function unwrap(value) {
    let current = value;
    for (let depth = 0; depth < 4; depth += 1) {
      if (!current || typeof current !== 'object' || Array.isArray(current)) break;
      if (current.data && typeof current.data === 'object') current = current.data;
      else if (current.body && typeof current.body === 'object') current = current.body;
      else break;
    }
    return current || {};
  }

  function clone(value) {
    try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value || {})); }
  }

  /* 会话闸门：token 过期时由闸门统一 refresh + 单次重试，页面不自己读 localStorage 重放。 */
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
    const response = await sessionFetch(`${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`, {
      credentials: 'same-origin',
      cache: 'no-store',
      signal: context.signal,
      ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    const payload = unwrap(json);
    const code = Number(json?.code);
    const businessFailed = Number.isFinite(code) && ![0, 200, 2000].includes(code);
    if (!response.ok || json?.ok === false || payload?.ok === false || businessFailed) {
      const error = new Error(firstText(payload?.message, payload?.error, json?.message, json?.error, `HTTP ${response.status}`));
      error.status = response.status;
      error.code = firstText(payload?.error, json?.error, payload?.code === undefined ? '' : '');
      error.payload = json;
      throw error;
    }
    return payload;
  }

  /*
   * 失败分类按 design.md「Capability truth」第 3 条：状态码与后端 error code 都要覆盖，
   * 同一件事在不同构建下可能用不同状态码表达。
   */
  function failureText(error, subject) {
    const status = Number(error?.status);
    const code = firstText(error?.code);
    if (code === 'method_not_registered') return `${subject}能力尚未接入当前固件。`;
    if (code === 'source_unavailable') return `${subject}服务暂时不可用，请稍后重试。`;
    if ([404, 405, 501].includes(status)) return `${subject}接口未实现（HTTP ${status}）。`;
    if (status === 401) return '会话已失效，请重新登录。';
    if (status === 403) return `当前账号无权修改${subject}，页面已切换为只读。`;
    if (status >= 500) return `${subject}后端错误（HTTP ${status}）：${firstText(error?.message, '未知错误')}`;
    if (!Number.isFinite(status)) return `网络不可用，${subject}读取失败。`;
    return `${subject}读取失败：${firstText(error?.message, '未知错误')}`;
  }

  function normalizeDomain(value) {
    let text = String(value || '').trim().toLowerCase();
    text = text.replace(/^https?:\/\//, '');
    text = text.replace(/^www\./, '');
    text = text.split('/')[0].split('?')[0].split('#')[0];
    text = text.replace(/:\d+$/, '');
    text = text.replace(/^\.+/, '').replace(/\.+$/, '');
    return text;
  }

  /* 与后端 content_domain_ok() 同判据：仅 a-z0-9-.，需含点，标签不以 - 收尾，长度 <= 253。 */
  function domainValid(domain) {
    if (!domain || domain.length > 253) return false;
    if (!domain.includes('.')) return false;
    return domain.split('.').every((label) => label.length > 0 && label.length <= 63
      && /^[a-z0-9-]+$/.test(label) && !label.startsWith('-') && !label.endsWith('-'));
  }

  function parseDomainInput(text) {
    const seen = new Set();
    const valid = [];
    const invalid = [];
    String(text || '').split(/[\s,，、;；]+/).forEach((raw) => {
      const trimmed = String(raw || '').trim();
      if (!trimmed) return;
      const domain = normalizeDomain(trimmed);
      if (!domainValid(domain)) { invalid.push(trimmed); return; }
      if (seen.has(domain)) return;
      seen.add(domain);
      valid.push(domain);
    });
    return { valid, invalid };
  }

  function writable() {
    if (state.readOnly) return false;
    return state.capabilities.content_policy_supported === true;
  }

  function overridesWritable() {
    if (state.readOnly) return false;
    return state.capabilities.domain_overrides_supported === true;
  }

  function icon(name) {
    const paths = {
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      edit: '<path d="m4 20 4.2-1 10.9-10.9a2 2 0 0 0-2.8-2.8L5.4 16.2 4 20Z"></path>',
      trash: '<path d="M4 7h16M9 7V4h6v3m-9 0 1 13h10l1-13M10 11v5m4-5v5"></path>',
      pause: '<path d="M9 5v14M15 5v14"></path>',
      play: '<path d="M8 5.5v13l11-6.5-11-6.5Z"></path>',
      shield: '<path d="M12 3l7 3v6c0 4.2-2.9 7.4-7 9-4.1-1.6-7-4.8-7-9V6l7-3Z"></path>',
      block: '<circle cx="12" cy="12" r="9"></circle><path d="m6 18 12-12"></path>',
      allow: '<circle cx="12" cy="12" r="9"></circle><path d="m8 12 2.5 2.5L16 9"></path>',
      layers: '<path d="m12 3 9 5-9 5-9-5 9-5Z"></path><path d="m3 13 9 5 9-5"></path>',
      shieldCheck: '<path d="M12 3l7 3v6c0 4.2-2.9 7.4-7 9-4.1-1.6-7-4.8-7-9V6l7-3Z"></path><path d="m9 12 2 2 4-4"></path>',
      activity: '<path d="M3 12h4l2.5-7 4 14 2.5-7h5"></path>',
      globe: '<circle cx="12" cy="12" r="9"></circle><path d="M3 12h18"></path><path d="M12 3a15 15 0 0 1 4 9 15 15 0 0 1-4 9 15 15 0 0 1-4-9 15 15 0 0 1 4-9"></path>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.edit}</svg>`;
  }

  function statusBadge(label, tone) {
    return ui.statusBadgeMarkup?.(label, tone) || `<span class="web-access-status is-${escapeHtml(tone)}">${escapeHtml(label)}</span>`;
  }

  function formatCount(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return '--';
    return number.toLocaleString('zh-CN');
  }

  function emptyPolicy() {
    return {
      id: POLICY_ID,
      name: POLICY_NAME,
      enabled: false,
      mode: 'off',
      ad_block: false,
      safe_search: { google: false, bing: false, youtube: false },
      categories: [],
      revision: 0,
      apply_state: 'unconfigured',
      last_error: ''
    };
  }

  function normalizePolicy(raw) {
    const safe = raw?.safe_search && typeof raw.safe_search === 'object' ? raw.safe_search : {};
    return {
      ...raw,
      id: firstText(raw?.id, POLICY_ID),
      name: firstText(raw?.name, POLICY_NAME),
      enabled: bool(raw?.enabled, false),
      mode: firstText(raw?.mode, 'off'),
      ad_block: bool(raw?.ad_block, false),
      safe_search: {
        google: bool(safe.google, false),
        bing: bool(safe.bing, false),
        youtube: bool(safe.youtube, false)
      },
      categories: Array.isArray(raw?.categories) ? raw.categories.map(firstText).filter(Boolean) : [],
      revision: Number(raw?.revision ?? 0),
      apply_state: firstText(raw?.apply_state, 'pending'),
      last_error: firstText(raw?.last_error)
    };
  }

  function normalizeOverride(raw = {}, index = 0) {
    return {
      ...raw,
      id: firstText(raw.id, `override-${index + 1}`),
      domain: firstText(raw.domain),
      action: firstText(raw.action) === 'allow' ? 'allow' : 'block',
      enabled: bool(raw.enabled, true),
      note: firstText(raw.note),
      apply_state: firstText(raw.apply_state, 'pending'),
      last_error: firstText(raw.last_error)
    };
  }

  function runtimeStatus(entry) {
    if (!entry.enabled) return { label: '已停用', tone: 'error', detail: '规则保留但不进入运行态' };
    const applyState = String(entry.apply_state || '');
    if (/^applied|^active|^ok$/i.test(applyState)) return { label: '运行中', tone: 'success', detail: applyState };
    if (/fail|error|rollback/i.test(applyState)) return { label: '应用失败', tone: 'error', detail: firstText(entry.last_error, '后端未返回原因') };
    if (/applying|pending/i.test(applyState)) return { label: '等待应用', tone: 'warning', detail: applyState };
    return { label: '未应用', tone: 'warning', detail: firstText(entry.last_error, applyState || '无运行态证明') };
  }

  function overviewMarkup() {
    const policy = state.policy || emptyPolicy();
    const renderer = ui.overviewCardsMarkup || window.DWRT_UI_KIT?.overviewCardsMarkup;
    if (typeof renderer !== 'function') return '';
    const blocked = state.overrides.filter((item) => item.action === 'block' && item.enabled).length;
    const allowed = state.overrides.filter((item) => item.action === 'allow' && item.enabled).length;
    const managed = bool(state.runtime.managed, false);
    const applyState = firstText(state.runtime.apply_state, 'unknown');
    const cards = [
      {
        key: 'policy',
        label: '管控状态',
        value: state.policyMissing ? '未配置' : (policy.enabled ? '已启用' : '已停用'),
        detail: state.policyMissing ? '尚未创建管控策略' : `模式 ${policy.mode} · 修订 ${policy.revision}`,
        tone: state.policyMissing ? 'neutral' : (policy.enabled ? 'ok' : 'warn'),
        icon: icon('shieldCheck')
      },
      {
        key: 'runtime',
        label: '数据面',
        value: managed ? '已接管' : '未接管',
        detail: `apply_state ${applyState}`,
        tone: managed ? 'ok' : 'warn',
        icon: icon('activity')
      },
      {
        key: 'categories',
        label: '已选分类',
        value: `${policy.categories.length} / ${state.categories.length || '--'}`,
        detail: state.categoriesAvailable === false
          ? '分类库未就绪'
          : `分类库 ${formatCount(state.categoriesTotal)} 条域名`,
        tone: policy.categories.length ? 'ok' : 'neutral',
        icon: icon('layers')
      },
      {
        key: 'overrides',
        label: '自定义域名',
        value: `${blocked} 拦 / ${allowed} 放`,
        detail: `共 ${state.overrides.length} 条，放行优先于拦截`,
        tone: blocked || allowed ? 'ok' : 'neutral',
        icon: icon('globe')
      }
    ];
    return renderer(cards, { className: 'web-access-overview', label: '网址浏览控制概览' });
  }

  function noticeMarkup() {
    const message = state.notice || state.error;
    if (!message) return '';
    const tone = state.notice ? (state.noticeTone || 'ok') : 'warning';
    return `<div class="user-auth-notice is-${escapeHtml(tone)}" data-web-access-notice>${escapeHtml(message)}</div>`;
  }

  function tabsMarkup() {
    const tabs = [['rules', '自定义域名'], ['categories', '分类管控'], ['protection', '全局防护']];
    return `<div class="user-auth-segmented web-access-tabs">${tabs.map(([id, label]) => `<button type="button" data-web-access-tab="${id}" class="${state.tab === id ? 'is-active' : ''}">${escapeHtml(label)}</button>`).join('')}</div>`;
  }

  function capabilityNoteMarkup() {
    if (!state.capabilitiesKnown) return '';
    const missing = [];
    if (state.capabilities.device_scope_supported !== true) missing.push('作用终端');
    if (state.capabilities.schedule_supported !== true) missing.push('生效时段');
    if (!missing.length) return '';
    return `<div class="user-auth-capability web-access-capability">后端当前只支持全局生效的域名管控：${escapeHtml(missing.join('、'))}未提供写入合同（<code>content_scope_not_supported</code> / <code>content_schedule_not_supported</code>），因此本页不提供这些控件，避免出现设了却不生效的开关。缺口已提交后端。</div>`;
  }

  function filteredOverrides() {
    const query = state.query.trim().toLowerCase();
    return state.overrides.filter((item) => {
      if (state.filter === 'block' && item.action !== 'block') return false;
      if (state.filter === 'allow' && item.action !== 'allow') return false;
      if (state.filter === 'disabled' && item.enabled) return false;
      if (!query) return true;
      return [item.domain, item.note, item.action].filter(Boolean).join(' ').toLowerCase().includes(query);
    });
  }

  function rulesTableMarkup() {
    const rows = filteredOverrides();
    const canWrite = overridesWritable();
    const filters = [['all', '全部'], ['block', '拦截'], ['allow', '放行'], ['disabled', '已停用']];
    const body = state.loading
      ? '<tr><td colspan="6" class="dwrt-kit-table-empty">正在读取域名规则</td></tr>'
      : rows.length ? rows.map((item) => {
        const runtime = runtimeStatus(item);
        return `<tr data-web-access-row="${escapeHtml(item.id)}"><td><code class="web-access-domain">${escapeHtml(item.domain)}</code></td><td><span class="web-access-action is-${escapeHtml(item.action)}">${item.action === 'allow' ? '放行' : '拦截'}</span></td><td>${escapeHtml(item.note || '--')}</td><td><div class="web-access-runtime">${statusBadge(runtime.label, runtime.tone)}<small title="${escapeHtml(runtime.detail)}">${escapeHtml(runtime.detail)}</small></div></td><td>${item.enabled ? '已启用' : '已停用'}</td><td><div class="user-auth-row-actions"><button class="user-auth-icon-button" type="button" data-web-access-toggle="${escapeHtml(item.id)}" ${canWrite && !state.saving ? '' : 'disabled'} aria-label="${item.enabled ? '停用' : '启用'}" data-dwrt-tooltip="${item.enabled ? '停用' : '启用'}">${icon(item.enabled ? 'pause' : 'play')}</button><button class="user-auth-icon-button" type="button" data-web-access-edit="${escapeHtml(item.id)}" ${canWrite && !state.saving ? '' : 'disabled'} aria-label="编辑" data-dwrt-tooltip="编辑">${icon('edit')}</button><button class="user-auth-icon-button danger" type="button" data-web-access-delete="${escapeHtml(item.id)}" ${canWrite && !state.saving ? '' : 'disabled'} aria-label="删除" data-dwrt-tooltip="删除">${icon('trash')}</button></div></td></tr>`;
      }).join('')
        : `<tr><td colspan="6" class="dwrt-kit-table-empty">${state.overrides.length ? '没有符合筛选条件的域名规则' : '暂无自定义域名规则，点击「拉黑域名」手动添加'}</td></tr>`;
    return `<section class="dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface web-access-table-card" data-web-access-table><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>自定义域名</strong><span>放行优先于拦截，规则全局生效</span></div><span class="dwrt-kit-table-count">${rows.length} 条</span><div class="user-auth-table-controls web-access-table-controls"><div class="user-auth-toolbar-leading"><div class="user-auth-segmented">${filters.map(([id, label]) => `<button type="button" data-web-access-filter="${id}" class="${state.filter === id ? 'is-active' : ''}">${escapeHtml(label)}</button>`).join('')}</div><label class="policy-search policy-search-main" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-web-access-search value="${escapeHtml(state.query)}" placeholder="搜索域名或备注"></label></div><div class="policy-toolbar-actions"><button class="policy-create-button" type="button" data-web-access-create ${canWrite && !state.saving ? '' : 'disabled'}>${icon('plus')}<span>拉黑域名</span></button></div></div></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table web-access-table"><thead><tr><th>域名</th><th>动作</th><th>备注</th><th>运行状态</th><th>状态</th><th>操作</th></tr></thead><tbody>${body}</tbody></table></div></section>`;
  }

  function categoriesMarkup() {
    const policy = state.policy || emptyPolicy();
    const selected = new Set(policy.categories);
    const canWrite = writable();
    let body = '';
    if (state.loading) body = '<p class="web-access-hint">正在读取分类库</p>';
    else if (state.categoriesError) body = `<p class="web-access-hint is-warning">${escapeHtml(state.categoriesError)}</p>`;
    else if (state.categoriesAvailable === false) body = '<p class="web-access-hint is-warning">分类库未就绪，后端 <code>available</code> 为 false，因此不提供分类勾选。</p>';
    else if (!state.categories.length) body = '<p class="web-access-hint">分类库为空，暂无可勾选的分类。</p>';
    else {
      body = `<div class="web-access-category-grid">${state.categories.map((item) => {
        const id = firstText(item.category, item.id, item.name);
        const count = Number(item.count);
        return `<label class="web-access-category ${selected.has(id) ? 'is-active' : ''}"><span class="web-access-switch"><input type="checkbox" data-web-access-category="${escapeHtml(id)}" ${selected.has(id) ? 'checked' : ''} ${canWrite && !state.saving ? '' : 'disabled'}><i></i></span><span class="web-access-category-text"><strong>${escapeHtml(id)}</strong><small>${Number.isFinite(count) ? `${formatCount(count)} 条域名` : '条目数未知'}</small></span></label>`;
      }).join('')}</div><footer class="web-access-section-footer"><span>勾选后需点击保存才会写入策略。</span><button class="policy-primary" type="button" data-web-access-save-policy ${canWrite && !state.saving ? '' : 'disabled'}>${state.saving ? '正在保存' : '保存分类管控'}</button></footer>`;
    }
    return `<section class="dwrt-kit-table-wrap dwrt-kit-glass-surface web-access-panel"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>分类管控</strong><span>按整类拦截，条目数来自分类库</span></div><span class="dwrt-kit-table-count">${state.categories.length} 类 · ${formatCount(state.categoriesTotal)} 条</span></div><div class="web-access-panel-body">${body}</div></section>`;
  }

  function protectionMarkup() {
    const policy = state.policy || emptyPolicy();
    const canWrite = writable();
    const safe = policy.safe_search || {};
    const disabled = canWrite && !state.saving ? '' : 'disabled';
    const row = (key, title, detail, checked, field) => `<label class="user-auth-setting-row web-access-setting-row"><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(detail)}</small></span><span class="web-access-switch"><input type="checkbox" data-web-access-${field}="${escapeHtml(key)}" ${checked ? 'checked' : ''} ${disabled}><i></i></span></label>`;
    const runtimeSafe = state.runtime?.safe_search || {};
    const installed = bool(runtimeSafe.installed, false);
    return `<section class="dwrt-kit-table-wrap dwrt-kit-glass-surface web-access-panel"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>全局防护</strong><span>策略级开关，作用于全部客户端</span></div></div><div class="web-access-panel-body"><div class="web-access-setting-group">${row('enabled', '启用网址浏览控制', state.policyMissing ? '首次保存将创建管控策略' : `当前修订 ${policy.revision}`, policy.enabled, 'policy-flag')}${row('ad_block', '广告与追踪拦截', '后端 ad_block，作用于 DNS 过滤层', policy.ad_block, 'policy-flag')}</div><div class="web-access-setting-group"><strong class="web-access-group-title">安全搜索</strong>${row('google', 'Google 安全搜索', '强制 forcesafesearch 主机', bool(safe.google, false), 'safe-search')}${row('bing', 'Bing 安全搜索', '强制 strict.bing.com', bool(safe.bing, false), 'safe-search')}${row('youtube', 'YouTube 限制模式', '强制 restrict 主机', bool(safe.youtube, false), 'safe-search')}<p class="web-access-hint">运行态回读：${installed ? '已下发到数据面' : '尚未下发到数据面'}（来源 ${escapeHtml(firstText(runtimeSafe.readback_source, '未提供'))}）。</p></div>${capabilityNoteMarkup()}<footer class="web-access-section-footer"><span>保存后立即应用到数据面。</span><button class="policy-primary" type="button" data-web-access-save-policy ${disabled}>${state.saving ? '正在保存' : '保存并应用'}</button></footer></div></section>`;
  }

  function workbenchMarkup() {
    if (state.tab === 'categories') return categoriesMarkup();
    if (state.tab === 'protection') return protectionMarkup();
    return rulesTableMarkup();
  }

  function drawerMarkup() {
    if (!state.drawer) return '';
    const editor = state.editor;
    const editing = Boolean(editor.id);
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-web-access-close aria-label="关闭域名规则编辑"></button><aside class="user-auth-drawer web-access-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" aria-label="${editing ? '编辑域名规则' : '新增域名规则'}"><header class="dwrt-kit-sheet-header"><div><span>WEB ACCESS CONTROL</span><strong>${editing ? '编辑域名规则' : '手动拉黑域名'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-web-access-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body user-auth-drawer-body"><div class="user-auth-drawer-section"><strong>规则状态</strong><label class="user-auth-setting-row"><span><strong>启用规则</strong><small>停用后规则保留但不进入运行态</small></span><span class="web-access-switch"><input type="checkbox" data-web-access-field="enabled" ${editor.enabled !== false ? 'checked' : ''}><i></i></span></label></div><div class="user-auth-form-grid"><label class="user-auth-field is-wide"><span>动作</span><span class="user-auth-segmented web-access-action-switch"><button type="button" data-web-access-action="block" class="${editor.action !== 'allow' ? 'is-active' : ''}">拦截</button><button type="button" data-web-access-action="allow" class="${editor.action === 'allow' ? 'is-active' : ''}">放行</button></span><small>放行优先于拦截，用于纠正误拦。</small></label><label class="user-auth-field is-wide" data-dwrt-component="field"><span>域名${editing ? '' : '（每行一个，可批量粘贴）'}</span>${editing
      ? `<input data-web-access-field="domain" type="text" value="${escapeHtml(editor.domain || '')}">`
      : `<textarea data-web-access-field="domains" rows="6" placeholder="example.com&#10;ads.example.net">${escapeHtml(editor.domains || '')}</textarea>`}<small>自动去掉协议、路径与 www 前缀；不支持通配符与 IP。</small></label><label class="user-auth-field is-wide" data-dwrt-component="field"><span>备注</span><input data-web-access-field="note" type="text" value="${escapeHtml(editor.note || '')}" maxlength="256"></label></div><div class="user-auth-capability">规则全局生效。后端未提供按终端或时段限定的写入合同，因此这里没有作用对象与生效时段控件。</div>${state.notice ? noticeMarkup() : ''}</div><footer class="dwrt-kit-sheet-footer user-auth-drawer-footer"><span></span><div><button class="policy-secondary" type="button" data-web-access-close>取消</button><button class="policy-primary" type="button" data-web-access-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存规则'}</button></div></footer></aside>`;
  }

  function confirmationMarkup() {
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    if (typeof renderer !== 'function') return '';
    if (state.confirmDelete) {
      return renderer({
        id: 'web-access-delete-confirmation',
        action: 'delete-web-access-override',
        tone: 'danger',
        title: '删除域名规则',
        description: `域名“${firstText(state.confirmDelete.domain, state.confirmDelete.id)}”的${state.confirmDelete.action === 'allow' ? '放行' : '拦截'}规则将从配置与运行态中删除。`,
        cancelLabel: '取消',
        confirmLabel: state.saving ? '正在删除' : '确认删除',
        disabled: state.saving
      });
    }
    return '';
  }

  function renderShell() {
    if (!root) return;
    root.hidden = false;
    root.classList.add('route-workspace', 'user-authentication-route-host', 'web-access-control-route-host');
    root.innerHTML = `<section class="user-auth-shell web-access-shell" data-web-access-version="${VERSION}"><div class="user-auth-page-header is-toolbar-only web-access-header">${tabsMarkup()}</div>${overviewMarkup()}<main class="user-auth-workbench web-access-workbench">${noticeMarkup()}${workbenchMarkup()}</main><div class="web-access-overlay-host" data-web-access-overlays></div></section>`;
    renderOverlays();
    ui.mountAll?.(root);
  }

  function releasePortaledOverlays() {
    const portal = document.querySelector('.dwrt-kit-sheet-portal');
    if (!portal) return;
    portal.querySelectorAll('.web-access-drawer').forEach((node) => {
      ui.unmount?.(node);
      node.remove();
    });
    portal.querySelectorAll('.dwrt-kit-sheet-overlay').forEach((node) => {
      if (!portal.querySelector('.dwrt-kit-sheet')) node.remove();
    });
  }

  function renderOverlays() {
    const host = root?.querySelector('[data-web-access-overlays]');
    if (!host) return;
    const markup = `${drawerMarkup()}${confirmationMarkup()}`;
    if (host.dataset.webAccessOverlayMarkup === markup) return;
    host.dataset.webAccessOverlayMarkup = markup;
    releasePortaledOverlays();
    host.innerHTML = markup;
    ui.mountAll?.(host);
  }

  function render() {
    renderShell();
  }

  /* 轮询只换工作区与概览，抽屉留在自己的容器里不被重建。 */
  function patchWorkbench() {
    const main = root?.querySelector('.web-access-workbench');
    if (!main) { render(); return; }
    const scroll = main.querySelector('.dwrt-kit-table-scroll');
    const position = { top: scroll?.scrollTop || 0, left: scroll?.scrollLeft || 0 };
    main.innerHTML = `${noticeMarkup()}${workbenchMarkup()}`;
    const next = main.querySelector('.dwrt-kit-table-scroll');
    if (next) { next.scrollTop = position.top; next.scrollLeft = position.left; }
    const overview = root?.querySelector('.web-access-overview');
    if (overview) {
      const template = document.createElement('template');
      template.innerHTML = overviewMarkup();
      const replacement = template.content.firstElementChild;
      if (replacement) overview.replaceWith(replacement);
    }
    ui.mountAll?.(root);
  }

  async function load(background = false) {
    const seq = ++state.seq;
    state.error = '';
    if (!background) state.notice = '';
    state.loading = !background;
    state.refreshing = background;
    if (!background) render();
    try {
      const [policyResult, overridesResult, categoriesResult] = await Promise.allSettled([
        requestJson('/api/v1/aegis/content-policy'),
        requestJson('/api/v1/aegis/domain-overrides'),
        requestJson('/api/v1/aegis/categories')
      ]);
      if (!state.mounted || seq !== state.seq) return;
      if (policyResult.status === 'rejected') throw policyResult.reason;
      const policyPayload = policyResult.value || {};
      state.capabilities = policyPayload.capabilities && typeof policyPayload.capabilities === 'object' ? policyPayload.capabilities : {};
      state.capabilitiesKnown = Boolean(policyPayload.capabilities);
      state.runtime = policyPayload.runtime && typeof policyPayload.runtime === 'object' ? policyPayload.runtime : {};
      const items = asArray(policyPayload, ['items']);
      const existing = items.find((item) => firstText(item?.id) === POLICY_ID) || items[0] || null;
      state.policyMissing = !existing;
      state.policy = existing ? normalizePolicy(existing) : emptyPolicy();

      if (overridesResult.status === 'fulfilled') {
        state.overrides = asArray(overridesResult.value, ['items']).map(normalizeOverride);
      } else {
        state.overrides = [];
        state.notice = failureText(overridesResult.reason, '自定义域名列表');
        state.noticeTone = 'warning';
      }

      if (categoriesResult.status === 'fulfilled') {
        const payload = categoriesResult.value || {};
        state.categories = asArray(payload, ['categories', 'items']).filter((item) => firstText(item?.category, item?.id, item?.name));
        state.categoriesTotal = Number(payload.total ?? 0);
        state.categoriesAvailable = payload.available === undefined ? null : bool(payload.available, false);
        state.categoriesError = '';
      } else {
        state.categories = [];
        state.categoriesTotal = 0;
        state.categoriesAvailable = null;
        state.categoriesError = failureText(categoriesResult.reason, '分类库');
      }

      state.loading = false;
      state.refreshing = false;
      if (background) patchWorkbench(); else render();
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      if (Number(error.status) === 403) { state.readOnly = true; state.readOnlyReason = '当前账号为只读角色'; }
      state.capabilities = {};
      state.capabilitiesKnown = false;
      state.policy = emptyPolicy();
      state.policyMissing = true;
      state.overrides = [];
      state.error = failureText(error, '网址浏览控制策略');
      render();
    }
  }

  function policyPayload(overrides = {}) {
    const policy = { ...(state.policy || emptyPolicy()), ...overrides };
    const categories = Array.isArray(policy.categories) ? policy.categories.slice(0, 64) : [];
    const enabled = policy.enabled !== false;
    /*
     * mode 只接受 off/basic/enhanced。启用但没勾任何分类时用 basic，
     * 勾了分类才升到 enhanced；停用统一落 off，避免留下一个「启用但什么都不管」的状态。
     */
    const mode = !enabled ? 'off' : (categories.length ? 'enhanced' : 'basic');
    return {
      id: POLICY_ID,
      name: firstText(policy.name, POLICY_NAME),
      enabled,
      mode,
      ad_block: policy.ad_block === true,
      safe_search: {
        google: bool(policy.safe_search?.google, false),
        bing: bool(policy.safe_search?.bing, false),
        youtube: bool(policy.safe_search?.youtube, false)
      },
      categories,
      /* 后端只接受这两个字面量，其它形态会被 content_canonical_object() 直接拒。 */
      scope: { type: 'all', devices: [], networks: [] },
      schedule: { type: 'always' },
      confirm: true,
      apply: true
    };
  }

  async function savePolicy() {
    if (!writable() || state.saving) return;
    state.saving = true;
    patchWorkbench();
    try {
      const response = await requestJson('/api/v1/aegis/content-policy', {
        method: 'POST',
        body: JSON.stringify(policyPayload())
      });
      state.saving = false;
      if (response?.valid === false || bool(response?.confirm_required, false) && !bool(response?.changed, false)) {
        const blockers = asArray(response, ['blockers']).map(firstText).filter(Boolean);
        state.notice = `后端未接受策略：${blockers.join('、') || firstText(response?.error, '未返回原因')}`;
        state.noticeTone = 'error';
        patchWorkbench();
        return;
      }
      state.notice = bool(response?.dataplane_changed, false) ? '策略已保存并下发到数据面。' : '策略已保存，数据面状态按后端回读显示。';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      if (Number(error.status) === 403) { state.readOnly = true; state.readOnlyReason = '当前账号为只读角色'; }
      state.notice = `保存失败：${firstText(error.message, '后端未接受策略')}`;
      state.noticeTone = 'error';
      patchWorkbench();
    }
  }

  function newEditor(entry = null) {
    state.editor = entry
      ? { ...clone(entry), domains: '' }
      : { id: '', domain: '', domains: '', action: 'block', enabled: true, note: '' };
    state.drawer = true;
    state.notice = '';
    renderOverlays();
  }

  async function saveOverride() {
    if (!overridesWritable() || state.saving) return;
    const editor = state.editor || {};
    const editing = Boolean(editor.id);
    const note = firstText(editor.note);
    if (note.length > 256) {
      state.notice = '备注不能超过 256 个字符。';
      state.noticeTone = 'warning';
      renderOverlays();
      return;
    }
    let domains = [];
    if (editing) {
      const domain = normalizeDomain(editor.domain);
      if (!domainValid(domain)) {
        state.notice = `域名「${firstText(editor.domain, '空')}」格式不合法，请填写形如 example.com 的域名。`;
        state.noticeTone = 'warning';
        renderOverlays();
        return;
      }
      domains = [domain];
    } else {
      const parsed = parseDomainInput(editor.domains);
      if (parsed.invalid.length) {
        state.notice = `以下输入不是合法域名，请修正后再保存：${parsed.invalid.slice(0, 5).join('、')}${parsed.invalid.length > 5 ? ` 等 ${parsed.invalid.length} 条` : ''}`;
        state.noticeTone = 'warning';
        renderOverlays();
        return;
      }
      if (!parsed.valid.length) {
        state.notice = '请至少填写一个域名。';
        state.noticeTone = 'warning';
        renderOverlays();
        return;
      }
      domains = parsed.valid;
    }

    state.saving = true;
    renderOverlays();
    const failures = [];
    for (const domain of domains) {
      try {
        await requestJson('/api/v1/aegis/domain-overrides', {
          method: 'POST',
          body: JSON.stringify({
            ...(editing && editor.id ? { id: editor.id } : {}),
            policy_id: POLICY_ID,
            domain,
            action: editor.action === 'allow' ? 'allow' : 'block',
            enabled: editor.enabled !== false,
            note,
            confirm: true,
            apply: true
          })
        });
      } catch (error) {
        if (Number(error.status) === 403) { state.readOnly = true; state.readOnlyReason = '当前账号为只读角色'; }
        failures.push(`${domain}（${firstText(error.message, '未知错误')}）`);
      }
    }
    state.saving = false;
    if (failures.length) {
      state.notice = `${domains.length - failures.length}/${domains.length} 条已保存，失败：${failures.slice(0, 3).join('；')}${failures.length > 3 ? ` 等 ${failures.length} 条` : ''}`;
      state.noticeTone = failures.length === domains.length ? 'error' : 'warning';
      renderOverlays();
      if (failures.length < domains.length) await load(true);
      return;
    }
    state.drawer = false;
    state.editor = {};
    state.notice = `${domains.length} 条域名规则已保存。`;
    state.noticeTone = 'ok';
    render();
    await load(true);
  }

  async function toggleOverride(entry) {
    if (!entry || !overridesWritable() || state.saving) return;
    state.saving = true;
    patchWorkbench();
    try {
      await requestJson('/api/v1/aegis/domain-overrides', {
        method: 'POST',
        body: JSON.stringify({
          id: entry.id,
          policy_id: POLICY_ID,
          domain: entry.domain,
          action: entry.action,
          enabled: !entry.enabled,
          note: entry.note,
          confirm: true,
          apply: true
        })
      });
      state.saving = false;
      state.notice = entry.enabled ? '规则已停用。' : '规则已启用。';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      if (Number(error.status) === 403) { state.readOnly = true; state.readOnlyReason = '当前账号为只读角色'; }
      state.notice = `操作失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      patchWorkbench();
    }
  }

  async function deleteOverride() {
    const entry = state.confirmDelete;
    if (!entry || !overridesWritable() || state.saving) return;
    state.saving = true;
    renderOverlays();
    try {
      await requestJson('/api/v1/aegis/domain-overrides/delete', {
        method: 'POST',
        body: JSON.stringify({ id: entry.id, confirm: true, apply: true })
      });
      state.saving = false;
      state.confirmDelete = false;
      state.notice = '域名规则已删除。';
      state.noticeTone = 'ok';
      render();
      await load(true);
    } catch (error) {
      state.saving = false;
      if (Number(error.status) === 403) { state.readOnly = true; state.readOnlyReason = '当前账号为只读角色'; }
      state.notice = `删除失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      renderOverlays();
    }
  }

  function findOverride(id) {
    return state.overrides.find((item) => String(item.id) === String(id));
  }

  function onClick(event) {
    if (event.target.closest('[data-web-access-close]')) { state.drawer = false; state.editor = {}; state.notice = ''; render(); return; }
    if (event.target.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]')) { state.confirmDelete = false; renderOverlays(); return; }
    if (event.target.closest('[data-dwrt-confirm-accept]')) { deleteOverride(); return; }
    if (event.target.closest('[data-web-access-create]')) { newEditor(); return; }
    if (event.target.closest('[data-web-access-save]')) { saveOverride(); return; }
    if (event.target.closest('[data-web-access-save-policy]')) { savePolicy(); return; }
    const tab = event.target.closest('[data-web-access-tab]');
    if (tab) { state.tab = tab.dataset.webAccessTab; render(); return; }
    const action = event.target.closest('[data-web-access-action]');
    if (action) {
      state.editor.action = action.dataset.webAccessAction === 'allow' ? 'allow' : 'block';
      renderOverlays();
      return;
    }
    const filter = event.target.closest('[data-web-access-filter]');
    if (filter) {
      state.filter = filter.dataset.webAccessFilter;
      patchWorkbench();
      return;
    }
    const toggle = event.target.closest('[data-web-access-toggle]');
    if (toggle) { toggleOverride(findOverride(toggle.dataset.webAccessToggle)); return; }
    const edit = event.target.closest('[data-web-access-edit]');
    if (edit) { newEditor(findOverride(edit.dataset.webAccessEdit)); return; }
    const remove = event.target.closest('[data-web-access-delete]');
    if (remove) { state.confirmDelete = findOverride(remove.dataset.webAccessDelete) || false; renderOverlays(); }
  }

  function onInput(event) {
    const search = event.target.closest('[data-web-access-search]');
    if (search) { state.query = search.value; patchWorkbench(); return; }
    const field = event.target.closest('[data-web-access-field]');
    if (field && !['checkbox', 'radio'].includes(field.type)) {
      state.editor[field.dataset.webAccessField] = field.value;
    }
  }

  function onChange(event) {
    const field = event.target.closest('[data-web-access-field]');
    if (field) {
      state.editor[field.dataset.webAccessField] = field.type === 'checkbox' ? field.checked : field.value;
      return;
    }
    const category = event.target.closest('[data-web-access-category]');
    if (category) {
      const id = category.dataset.webAccessCategory;
      const selected = new Set(state.policy?.categories || []);
      if (category.checked) selected.add(id); else selected.delete(id);
      if (selected.size > 64) {
        selected.delete(id);
        category.checked = false;
        state.notice = '后端最多接受 64 个分类。';
        state.noticeTone = 'warning';
        patchWorkbench();
        return;
      }
      state.policy = { ...(state.policy || emptyPolicy()), categories: Array.from(selected) };
      category.closest('.web-access-category')?.classList.toggle('is-active', category.checked);
      return;
    }
    const flag = event.target.closest('[data-web-access-policy-flag]');
    if (flag) {
      state.policy = { ...(state.policy || emptyPolicy()), [flag.dataset.webAccessPolicyFlag]: flag.checked };
      return;
    }
    const safe = event.target.closest('[data-web-access-safe-search]');
    if (safe) {
      const policy = state.policy || emptyPolicy();
      state.policy = {
        ...policy,
        safe_search: { ...(policy.safe_search || {}), [safe.dataset.webAccessSafeSearch]: safe.checked }
      };
    }
  }

  function onKeyDown(event) {
    if (event.key !== 'Escape') return;
    if (state.confirmDelete) state.confirmDelete = false;
    else if (state.drawer) { state.drawer = false; state.editor = {}; }
    else return;
    render();
  }

  root?.addEventListener('click', onClick);
  root?.addEventListener('input', onInput);
  root?.addEventListener('change', onChange);
  document.addEventListener('keydown', onKeyDown);
  stage?.classList.add('is-user-authentication');
  render();
  load();

  state.pollTimer = window.setInterval(() => {
    if (!state.mounted || document.hidden) return;
    if (state.loading || state.refreshing || state.saving) return;
    if (state.drawer || state.confirmDelete) return;
    load(true);
  }, 20000);

  return {
    refresh() { return load(true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      window.clearInterval(state.pollTimer);
      releasePortaledOverlays();
      root?.removeEventListener('click', onClick);
      root?.removeEventListener('input', onInput);
      root?.removeEventListener('change', onChange);
      document.removeEventListener('keydown', onKeyDown);
      root?.replaceChildren();
      root?.classList.remove('route-workspace', 'user-authentication-route-host', 'web-access-control-route-host');
      stage?.classList.remove('is-user-authentication');
    }
  };
}

export default { mount };
