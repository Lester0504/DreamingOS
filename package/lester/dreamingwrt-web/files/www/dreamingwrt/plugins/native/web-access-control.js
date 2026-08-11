/*
 * 网址浏览控制。
 *
 * 后端底座是 aegis 的 content-policy + domain-overrides，不是爱快那张 url_black 表。
 * 「作用对象」与「生效时段」两个控件**按能力位渲染，不写死**（`content_capabilities()`，
 * jmxd/src/aegisxd/aegisxd_content.c）：
 *
 *   device_scope_supported  -> 作用对象选择器（按 MAC，上限 device_scope_max_devices）
 *   schedule_supported      -> 生效时段控件（schedule_mode=always_or_single_window）
 *   network_scope_supported = false 恒为假，按网段限定没有渲染路径
 *
 * `content_canonical_object()` 对不支持的形态是硬拒绝而不是静默忽略，所以能力位为假时
 * 必须退回 {"type":"all",devices:[],networks:[]} / {"type":"always"}，否则整条策略被
 * `content_scope_not_supported` / `content_schedule_not_supported` 拒掉。旧固件上两位
 * 都是 false，页面自动退回原来的「全局生效」说明 —— design.md「Capability truth」
 * 第 10 条要求的就是这个方向：能力位驱动，不给用户存不进去的输入框。
 *
 * 两处与全局路径的**语义差异**必须在 UI 上说清楚（后端 2026-08-09 交接单）：
 *   1. 安全搜索靠改写 provider 域名生效，对全网一视同仁，后端只统计「全局 + 常开」
 *      策略的 safe_search。带 scope/schedule 时这三个开关不会按设备生效。
 *   2. 全局拦截改写 DNS 应答；设备级拦截是 dnsmasq nftset + nft ether saddr
 *      （device_scope_runtime 自述），命中按**解析出的地址**判定，共享 IP 的 CDN 会被
 *      一并挡住，地址集合有老化时间。
 *
 * 写路径都要 `confirm:true`（缺了只回 dry_run），`apply:true` 才落数据面。
 */
export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const VERSION = '20260810-front-release-01';
  const stage = root?.closest('.console-stage');
  const POLICY_ID = 'web-access-control';
  const POLICY_NAME = '网址浏览控制';
  /* 后端 weekdays 是 0-6 且 0=周日。策略表通用 scheduleEditor() 用的是 1-7，
   * 直接复用会把周日写成 7 被后端拒掉（design.md 第 19 条），所以这里自己按 0-6 排。 */
  const WEEKDAY_LABELS = ['日', '一', '二', '三', '四', '五', '六'];
  const DEFAULT_SCOPE_DEVICE_MAX = 64;

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
    clients: [],
    clientsError: '',
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
    scopePicker: false,
    scopeQuery: '',
    /* 用户改过 scope/schedule 但还没保存：轮询回读时不覆盖这两项。 */
    policyDirty: false,
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
    const contract = contractErrorText(code);
    if (contract) return contract;
    if (code === 'method_not_registered') return `${subject}能力尚未接入当前固件。`;
    if (code === 'source_unavailable') return `${subject}服务暂时不可用，请稍后重试。`;
    if ([404, 405, 501].includes(status)) return `${subject}接口未实现（HTTP ${status}）。`;
    if (status === 401) return '会话已失效，请重新登录。';
    if (status === 403) return `当前账号无权修改${subject}，页面已切换为只读。`;
    if (status >= 500) return `${subject}后端错误（HTTP ${status}）：${firstText(error?.message, '未知错误')}`;
    if (!Number.isFinite(status)) return `网络不可用，${subject}读取失败。`;
    return `${subject}读取失败：${firstText(error?.message, '未知错误')}`;
  }

  /*
   * scope/schedule 的拒绝码翻译。后端这些分支都是「返回即拒绝，不落库」，
   * 所以文案要说清楚这次没保存成功，而不是含糊成一句"未接受"。
   */
  function contractErrorText(code) {
    const table = {
      content_scope_devices_required: '未保存：选择了按终端限定，但没有勾选任何终端。',
      content_network_scope_not_supported: '未保存：当前固件不支持按网段限定（network_scope_supported=false）。',
      invalid_content_scope_device: '未保存：终端 MAC 不合法（不接受组播地址与全零地址）。',
      content_scope_devices_too_many: `未保存：限定终端数超过上限（最多 ${scopeDeviceMax()} 台）。`,
      content_schedule_single_window_required: '未保存：一条策略只能有一个时间窗，需要多个时段请分别建策略。',
      invalid_content_schedule_time: '未保存：生效时段的时间需填写为 HH:MM。',
      invalid_content_schedule_window: '未保存：时间窗不合法（起止时间不能相同，那样永远不会命中）。',
      invalid_content_schedule_weekdays: '未保存：生效星期不合法（取值 0-6，0 表示周日）。',
      content_scope_not_supported: '未保存：当前固件不支持按终端限定，策略只能全局生效。',
      content_schedule_not_supported: '未保存：当前固件不支持生效时段，策略只能始终生效。'
    };
    return table[code] || '';
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

  /*
   * MAC 规范化与后端 content_mac_normalize() 同判据：大小写、`:` 与 `-` 分隔都收，
   * 统一成小写冒号形式。组播位与全零 MAC 后端直接拒（invalid_content_scope_device），
   * 那种规则写下去永远匹配不到东西，所以这里先挡住而不是等 400。
   */
  function normalizeMac(value) {
    const hex = String(value || '').trim().toLowerCase().replace(/[^0-9a-f]/g, '');
    if (hex.length !== 12) return '';
    return hex.match(/.{2}/g).join(':');
  }

  function macUsable(mac) {
    if (!/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(mac)) return false;
    const bytes = mac.split(':').map((part) => parseInt(part, 16));
    if (bytes[0] & 0x01) return false;                    /* 组播/广播 */
    if (bytes.every((byte) => byte === 0)) return false;  /* 全零 */
    return true;
  }

  /*
   * 本地管理位（bit1）是随机 MAC 的标志。这类终端换一次 MAC 就不再命中按 MAC 限定的
   * 规则，与 MAC ACL 页同判据，选中时必须标出来，否则用户会以为规则失效了。
   */
  function isRandomizedMac(mac) {
    const head = parseInt(String(mac || '').slice(0, 2), 16);
    return Number.isFinite(head) ? Boolean(head & 0x02) : false;
  }

  function hhmmOk(value) {
    return /^([01]\d|2[0-3]):[0-5]\d$/.test(String(value || ''));
  }

  function scopeDeviceMax() {
    const limit = Number(state.capabilities.device_scope_max_devices);
    return Number.isFinite(limit) && limit > 0 ? limit : DEFAULT_SCOPE_DEVICE_MAX;
  }

  function deviceScopeOn() {
    return state.capabilities.device_scope_supported === true;
  }

  function scheduleOn() {
    return state.capabilities.schedule_supported === true;
  }

  function weekdaysOn() {
    return state.capabilities.schedule_weekdays_supported === true;
  }

  /* 回读：后端 echo 的是 canonical 形态，但旧固件与错误分支可能给别的，所以两边都容错。 */
  function parseScope(raw) {
    const type = firstText(raw?.type, 'all');
    const devices = Array.isArray(raw?.devices)
      ? Array.from(new Set(raw.devices.map(normalizeMac).filter(macUsable)))
      : [];
    if (type !== 'devices') return { type: 'all', devices: [] };
    return { type: 'devices', devices };
  }

  function parseSchedule(raw) {
    const type = firstText(raw?.type, 'always');
    const fallback = { type: 'always', start: '18:00', end: '22:00', weekdays: [] };
    if (type !== 'window') return fallback;
    const entry = Array.isArray(raw?.windows) ? raw.windows[0] : null;
    if (!entry || typeof entry !== 'object') return fallback;
    const weekdays = Array.isArray(entry.weekdays)
      ? Array.from(new Set(entry.weekdays.map(Number).filter((day) => Number.isInteger(day) && day >= 0 && day <= 6))).sort((left, right) => left - right)
      : [];
    return {
      type: 'window',
      start: hhmmOk(entry.start_time) ? entry.start_time : fallback.start,
      end: hhmmOk(entry.end_time) ? entry.end_time : fallback.end,
      weekdays
    };
  }

  /* 反向：编辑器结构 -> 后端接受的形态。能力位为假时一律退回 all/always。 */
  function scopePayload(policy) {
    const scope = policy.scope || { type: 'all', devices: [] };
    if (!deviceScopeOn() || scope.type !== 'devices') return { type: 'all', devices: [], networks: [] };
    const devices = Array.from(new Set((scope.devices || []).map(normalizeMac).filter(macUsable))).slice(0, scopeDeviceMax());
    return { type: 'devices', devices, networks: [] };
  }

  function schedulePayload(policy) {
    const schedule = policy.schedule || { type: 'always' };
    if (!scheduleOn() || schedule.type !== 'window') return { type: 'always' };
    const weekdays = Array.from(new Set((schedule.weekdays || []).map(Number).filter((day) => Number.isInteger(day) && day >= 0 && day <= 6))).sort((left, right) => left - right);
    const entry = { start_time: schedule.start, end_time: schedule.end };
    /* 不选或全选都表示每天；后端对空 weekdays 会自己补齐 0-6，两种写法等价。 */
    if (weekdays.length && weekdays.length < 7) entry.weekdays = weekdays;
    return { type: 'window', windows: [entry] };
  }

  function scopeText(policy) {
    const scope = policy.scope || { type: 'all', devices: [] };
    if (scope.type !== 'devices') return '全部终端';
    if (!scope.devices.length) return '未选择终端';
    return `${scope.devices.length} 台终端`;
  }

  function scheduleText(policy) {
    const schedule = policy.schedule || { type: 'always' };
    if (schedule.type !== 'window') return '始终生效';
    const days = schedule.weekdays.length && schedule.weekdays.length < 7
      ? `周${schedule.weekdays.map((day) => WEEKDAY_LABELS[day]).join('、')}`
      : '每天';
    return `${days} ${schedule.start}-${schedule.end}`;
  }

  function clientLabel(mac) {
    const client = state.clients.find((item) => item.mac === mac);
    return client ? firstText(client.name, mac) : mac;
  }

  /*
   * 保存前自查，判据与后端校验分支一一对应，目的是把错误挡在请求之前而不是
   * 让用户去读一串 content_* 错误码。
   */
  function policyBlocker(policy) {
    const scope = policy.scope || { type: 'all', devices: [] };
    if (deviceScopeOn() && scope.type === 'devices') {
      if (!scope.devices.length) return '「作用对象」选了指定终端但没有勾选任何终端，请至少选择一台，或改回全部终端。';
      if (scope.devices.length > scopeDeviceMax()) return `一条策略最多限定 ${scopeDeviceMax()} 台终端，当前选了 ${scope.devices.length} 台。`;
      const bad = scope.devices.find((mac) => !macUsable(mac));
      if (bad) return `终端 MAC「${bad}」不合法（不接受组播地址与全零地址）。`;
    }
    const schedule = policy.schedule || { type: 'always' };
    if (scheduleOn() && schedule.type === 'window') {
      if (!hhmmOk(schedule.start) || !hhmmOk(schedule.end)) return '生效时段的开始与结束时间需填写为 HH:MM。';
      if (schedule.start === schedule.end) return '生效时段的开始与结束时间不能相同，否则这个时间窗永远不会匹配。';
    }
    return '';
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
      scope: { type: 'all', devices: [] },
      schedule: { type: 'always', start: '18:00', end: '22:00', weekdays: [] },
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
      scope: parseScope(raw?.scope),
      schedule: parseSchedule(raw?.schedule),
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

  function normalizeClient(item = {}, index = 0) {
    const fingerprint = item.fingerprint && typeof item.fingerprint === 'object' ? item.fingerprint : {};
    const mac = normalizeMac(firstText(item.mac, item.client_mac, item.hwaddr));
    const ipv4 = firstText(item.ip, item.ipv4, item.ipaddr);
    return {
      mac,
      name: firstText(item.custom_name, item.display_name, item.device_name, item.name, item.hostname, fingerprint.model, item.model, mac, '未命名终端'),
      vendor: firstText(item.vendor, item.vendor_name, item.oui),
      /* `0.0.0.0` 与空串都表示没有 IPv4 租约，仍要能选中：作用对象匹配的是 MAC。 */
      ipv4: ipv4 && ipv4 !== '0.0.0.0' ? ipv4 : '',
      online: bool(item.online, bool(item.active, false)),
      randomized: isRandomizedMac(mac),
      id: firstText(item.id, mac, `client-${index + 1}`)
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
    const tabs = [['rules', '自定义域名'], ['categories', '分类管控'], ['protection', protectionTabName()]];
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs web-access-tabs" data-dwrt-component="tabs" role="tablist" aria-label="网址浏览控制">`
      + `<span class="dwrt-kit-tab-pill" aria-hidden="true"></span>`
      + `${tabs.map(([id, label]) => `<button class="dwrt-kit-tab ${state.tab === id ? 'is-active' : ''}" type="button" role="tab" aria-selected="${state.tab === id ? 'true' : 'false'}" data-value="${id}" data-web-access-tab="${id}">${escapeHtml(label)}</button>`).join('')}`
      + `</nav>`;
  }

  function capabilityNoteMarkup() {
    if (!state.capabilitiesKnown) return '';
    const missing = [];
    if (state.capabilities.device_scope_supported !== true) missing.push('作用终端');
    if (state.capabilities.schedule_supported !== true) missing.push('生效时段');
    if (!missing.length) return '';
    return `<div class="user-auth-capability web-access-capability">当前固件只支持全局生效的域名管控：${escapeHtml(missing.join('、'))}未提供写入合同（<code>content_scope_not_supported</code> / <code>content_schedule_not_supported</code>），因此本页不提供这些控件，避免出现设了却不生效的开关。升级到支持该能力的固件后，控件会自动出现。</div>`;
  }

  /*
   * 作用对象。能力位为假时整块不渲染（旧固件上后端会硬拒 devices 形态）。
   * 终端列表来自 /api/v1/clients，读不到时仍允许手填 MAC，不把功能锁死。
   */
  function scopeSectionMarkup() {
    if (!deviceScopeOn()) return '';
    const policy = state.policy || emptyPolicy();
    const scope = policy.scope || { type: 'all', devices: [] };
    const scoped = scope.type === 'devices';
    const canWrite = writable() && !state.saving;
    const max = scopeDeviceMax();
    const query = state.scopeQuery.trim().toLowerCase();
    const selected = new Set(scope.devices);
    const rows = state.clients.filter((client) => {
      if (!query) return true;
      return [client.name, client.mac, client.ipv4, client.vendor].filter(Boolean).join(' ').toLowerCase().includes(query);
    });
    /* 已选但不在当前在线列表里的 MAC 也要能看见并能取消，否则会变成删不掉的隐形选择。 */
    const orphans = scope.devices.filter((mac) => !state.clients.some((client) => client.mac === mac));
    const list = scoped
      ? `<div class="web-access-scope-picker">
        <label class="web-access-scope-search" data-dwrt-component="field"><span class="web-access-scope-search-icon">${icon('search')}</span><input type="search" data-web-access-scope-search value="${escapeHtml(state.scopeQuery)}" placeholder="搜索终端名称、MAC 或 IP"></label>
        <div class="web-access-scope-list">${rows.length || orphans.length
          ? [...rows.map((client) => {
            const on = selected.has(client.mac);
            return `<label class="web-access-scope-item ${on ? 'is-active' : ''}"><input type="checkbox" data-web-access-scope-device="${escapeHtml(client.mac)}" ${on ? 'checked' : ''} ${canWrite ? '' : 'disabled'}><span><strong>${escapeHtml(client.name)}</strong><small>${escapeHtml([client.mac, client.ipv4].filter(Boolean).join(' · '))}${client.online ? '' : ' · 离线'}${client.randomized ? ' · 随机 MAC' : ''}</small></span></label>`;
          }), ...orphans.map((mac) => `<label class="web-access-scope-item is-active is-orphan"><input type="checkbox" data-web-access-scope-device="${escapeHtml(mac)}" checked ${canWrite ? '' : 'disabled'}><span><strong>${escapeHtml(mac)}</strong><small>不在当前终端列表中，仍会写入规则</small></span></label>`)].join('')
          : `<p class="web-access-hint${state.clientsError ? ' is-warning' : ''}">${escapeHtml(state.clientsError || (state.clients.length ? '没有符合搜索条件的终端' : '未读到终端列表'))}</p>`}</div>
        <div class="web-access-scope-foot"><span>已选 ${scope.devices.length} / ${max} 台</span>${scope.devices.length ? `<button type="button" class="policy-secondary" data-web-access-scope-clear ${canWrite ? '' : 'disabled'}>清空</button>` : ''}</div>
      </div>`
      : '';
    return `<div class="web-access-setting-group web-access-scope-section"><strong class="web-access-group-title">作用对象</strong>
      <div class="web-access-mode-switch" role="group" aria-label="作用对象">
        <button type="button" data-web-access-scope-mode="all" class="${scoped ? '' : 'is-active'}" ${canWrite ? '' : 'disabled'}>全部终端</button>
        <button type="button" data-web-access-scope-mode="devices" class="${scoped ? 'is-active' : ''}" ${canWrite ? '' : 'disabled'}>指定终端</button>
      </div>${list}
      <p class="web-access-hint">${escapeHtml(`按 MAC 限定（device_scope_match=${firstText(state.capabilities.device_scope_match, 'mac')}），一条策略最多 ${max} 台。${state.capabilities.network_scope_supported === true ? '' : '按网段限定当前固件不支持。'}`)}</p>
      ${scoped && scope.devices.some(isRandomizedMac) ? `<p class="web-access-hint is-warning">已选终端中有使用随机 MAC 的设备（${escapeHtml(scope.devices.filter(isRandomizedMac).map(clientLabel).join('、'))}）。这类设备换一次 MAC 就不再命中本规则，需要在设备上把该网络的私有地址关掉，规则才稳定。</p>` : ''}
      ${scoped ? deviceRuntimeNoteMarkup() : ''}</div>`;
  }

  /*
   * 设备级拦截与全局拦截的执行点不同，这件事必须写在界面上：命中是按解析出的地址
   * 判定的，共享 IP 的 CDN 会被一并挡住。后端用 device_scope_runtime 自述这条。
   */
  function deviceRuntimeNoteMarkup() {
    const runtime = firstText(state.capabilities.device_scope_runtime);
    if (!runtime) return '';
    return `<div class="user-auth-capability web-access-capability">指定终端的拦截与全局拦截执行点不同（<code>${escapeHtml(runtime)}</code>）：全局拦截改写 DNS 应答，指定终端是按<strong>解析出的地址</strong>拦截。因此同一 IP 上的其他域名可能被一并挡住，共享 IP 的 CDN 尤其明显；地址集合有老化时间，改完规则后可能需要等一会儿或让终端重新解析才会完全生效。</div>`;
  }

  /* 生效时段。与 MAC ACL 的 always_or_single_window 同构，weekdays 用 0-6（0=周日）。 */
  function scheduleSectionMarkup() {
    if (!scheduleOn()) return '';
    const policy = state.policy || emptyPolicy();
    const schedule = policy.schedule || { type: 'always' };
    const windowMode = schedule.type === 'window';
    const canWrite = writable() && !state.saving;
    const days = Array.isArray(schedule.weekdays) ? schedule.weekdays : [];
    const maxWindows = Number(state.capabilities.schedule_max_windows ?? 1);
    const basis = firstText(state.capabilities.schedule_time_basis, 'device_local_time') === 'device_local_time'
      ? '时间以设备本地时间为准，不随浏览器时区变化'
      : `时基：${firstText(state.capabilities.schedule_time_basis)}`;
    const field = (label, key, value) => `<label class="user-auth-field" data-dwrt-component="field"><span>${escapeHtml(label)}</span><input type="time" data-web-access-schedule-field="${key}" value="${escapeHtml(value || '')}" ${canWrite ? '' : 'disabled'}></label>`;
    return `<div class="web-access-setting-group web-access-schedule-section"><strong class="web-access-group-title">生效时段</strong>
      <div class="web-access-mode-switch" role="group" aria-label="生效时段">
        <button type="button" data-web-access-schedule-mode="always" class="${windowMode ? '' : 'is-active'}" ${canWrite ? '' : 'disabled'}>始终生效</button>
        <button type="button" data-web-access-schedule-mode="window" class="${windowMode ? 'is-active' : ''}" ${canWrite ? '' : 'disabled'}>按时间段生效</button>
      </div>
      ${windowMode ? `<div class="web-access-schedule-grid">${field('开始时间', 'start', schedule.start)}${field('结束时间', 'end', schedule.end)}</div>
      ${weekdaysOn() ? `<div class="web-access-weekdays"><span>生效星期</span><div>${WEEKDAY_LABELS.map((label, index) => `<label class="${days.includes(index) ? 'is-active' : ''}"><input type="checkbox" data-web-access-weekday="${index}" ${days.includes(index) ? 'checked' : ''} ${canWrite ? '' : 'disabled'}>${escapeHtml(label)}</label>`).join('')}</div><small>不选或全选表示每天生效</small></div>` : ''}
      <p class="web-access-hint">${escapeHtml(`一条策略只支持一个时间窗（schedule_max_windows=${maxWindows}）；需要多个时间段请分别建策略。${basis}。时段外自动放行。`)}</p>` : ''}</div>`;
  }

  /*
   * 安全搜索靠改写各家 provider 域名生效，对全网一视同仁，后端只统计
   * 「全局 + 常开」策略的 safe_search。带 scope/schedule 时必须说明它不按设备生效，
   * 否则用户会以为设了却没效果。
   */
  function safeSearchScopeNoteMarkup() {
    const policy = state.policy || emptyPolicy();
    const scoped = deviceScopeOn() && policy.scope?.type === 'devices';
    const windowed = scheduleOn() && policy.schedule?.type === 'window';
    if (!scoped && !windowed) return '';
    const reason = [scoped ? '作用对象' : '', windowed ? '生效时段' : ''].filter(Boolean).join('与');
    return `<div class="user-auth-capability web-access-capability">本策略设置了${escapeHtml(reason)}，但<strong>安全搜索三项开关不会按此范围生效</strong>：它靠改写各家 provider 域名实现，对全网一视同仁，后端只统计「全局且常开」策略的安全搜索。需要按终端或按时段限制，请改用上面的分类管控与自定义域名。</div>`;
  }

  /*
   * 自定义域名的作用范围**跟随所属策略**：后端把带 policy_id 的 override 挂到该策略上，
   * 只有 policy_id 为空的才是全局的。所以这里的文案必须读策略当前的 scope/schedule，
   * 不能再写死「全局生效」。
   */
  function policyRangeText() {
    const policy = state.policy || emptyPolicy();
    const scoped = deviceScopeOn() && policy.scope?.type === 'devices';
    const windowed = scheduleOn() && policy.schedule?.type === 'window';
    if (!scoped && !windowed) return '';
    return [scoped ? scopeText(policy) : '全部终端', windowed ? scheduleText(policy) : '始终生效'].join(' · ');
  }

  function overridesScopeSubtitle() {
    const range = policyRangeText();
    return range ? `放行优先于拦截 · 生效范围 ${range}` : '放行优先于拦截，规则全局生效';
  }

  /* 页签标题随能力位改名，引用它的文案必须跟着改，否则会指向一个页面上不存在的名字。 */
  function protectionTabName() {
    return deviceScopeOn() || scheduleOn() ? '策略与防护' : '全局防护';
  }

  function drawerScopeNote() {
    const range = policyRangeText();
    if (!range) {
      if (deviceScopeOn() || scheduleOn()) return `规则挂在本页策略下，当前策略为全部终端、始终生效。作用对象与生效时段在「${protectionTabName()}」页签设置，改动对本页所有域名规则同时生效。`;
      return '规则全局生效。当前固件未提供按终端或时段限定的写入合同，因此这里没有作用对象与生效时段控件。';
    }
    return `规则挂在本页策略下，生效范围为 ${range}。作用对象与生效时段在「${protectionTabName()}」页签设置，改动对本页所有域名规则同时生效。`;
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
    return `<section class="dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface web-access-table-card" data-web-access-table><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>自定义域名</strong><span>${escapeHtml(overridesScopeSubtitle())}</span></div><span class="dwrt-kit-table-count">${rows.length} 条</span><div class="user-auth-table-controls web-access-table-controls"><div class="user-auth-toolbar-leading"><div class="user-auth-segmented">${filters.map(([id, label]) => `<button type="button" data-web-access-filter="${id}" class="${state.filter === id ? 'is-active' : ''}">${escapeHtml(label)}</button>`).join('')}</div><label class="policy-search policy-search-main" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-web-access-search value="${escapeHtml(state.query)}" placeholder="搜索域名或备注"></label></div><div class="policy-toolbar-actions"><button class="policy-create-button" type="button" data-web-access-create ${canWrite && !state.saving ? '' : 'disabled'}>${icon('plus')}<span>拉黑域名</span></button></div></div></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table web-access-table"><thead><tr><th>域名</th><th>动作</th><th>备注</th><th>运行状态</th><th>状态</th><th>操作</th></tr></thead><tbody>${body}</tbody></table></div></section>`;
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
        return `<label class="web-access-category ${selected.has(id) ? 'is-active' : ''}"><span class="web-access-checkbox"><input type="checkbox" data-web-access-category="${escapeHtml(id)}" ${selected.has(id) ? 'checked' : ''} ${canWrite && !state.saving ? '' : 'disabled'}><i aria-hidden="true"></i></span><span class="web-access-category-text"><strong>${escapeHtml(id)}</strong><small>${Number.isFinite(count) ? `${formatCount(count)} 条域名` : '条目数未知'}</small></span></label>`;
      }).join('')}</div><footer class="web-access-section-footer"><span>勾选后需点击保存才会写入策略。</span><button class="policy-primary" type="button" data-web-access-save-policy ${canWrite && !state.saving ? '' : 'disabled'}>${state.saving ? '正在保存' : '保存分类管控'}</button></footer>`;
    }
    return `<section class="dwrt-kit-table-wrap dwrt-kit-glass-surface web-access-panel"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>分类管控</strong><span>按整类拦截，条目数来自分类库</span></div><span class="dwrt-kit-table-count">${state.categories.length} 类 · ${formatCount(state.categoriesTotal)} 条</span></div><div class="web-access-panel-body">${body}</div></section>`;
  }

  function protectionMarkup() {
    const policy = state.policy || emptyPolicy();
    const canWrite = writable();
    const safe = policy.safe_search || {};
    const disabled = canWrite && !state.saving ? '' : 'disabled';
    const row = (key, title, detail, checked, field) => `<label class="user-auth-setting-row web-access-setting-row"><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(detail)}</small></span><span class="web-access-switch dwrt-kit-switch" data-dwrt-component="switch"><input type="checkbox" data-web-access-${field}="${escapeHtml(key)}" ${checked ? 'checked' : ''} ${disabled}></span></label>`;
    const runtimeSafe = state.runtime?.safe_search || {};
    const installed = bool(runtimeSafe.installed, false);
    /* 标题随能力位改口径：能限定范围之后，「作用于全部客户端」就不再总是成立。 */
    const scoped = deviceScopeOn() || scheduleOn();
    const subtitle = scoped
      ? `策略级开关 · ${scopeText(policy)} · ${scheduleText(policy)}`
      : '策略级开关，作用于全部客户端';
    return `<section class="dwrt-kit-table-wrap dwrt-kit-glass-surface web-access-panel"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>${escapeHtml(protectionTabName())}</strong><span>${escapeHtml(subtitle)}</span></div></div><div class="web-access-panel-body"><div class="web-access-setting-group">${row('enabled', '启用网址浏览控制', state.policyMissing ? '首次保存将创建管控策略' : `当前修订 ${policy.revision}`, policy.enabled, 'policy-flag')}${row('ad_block', '广告与追踪拦截', '后端 ad_block，作用于 DNS 过滤层', policy.ad_block, 'policy-flag')}</div>${scopeSectionMarkup()}${scheduleSectionMarkup()}<div class="web-access-setting-group"><strong class="web-access-group-title">安全搜索</strong>${row('google', 'Google 安全搜索', '强制 forcesafesearch 主机', bool(safe.google, false), 'safe-search')}${row('bing', 'Bing 安全搜索', '强制 strict.bing.com', bool(safe.bing, false), 'safe-search')}${row('youtube', 'YouTube 限制模式', '强制 restrict 主机', bool(safe.youtube, false), 'safe-search')}<p class="web-access-hint">运行态回读：${installed ? '已下发到数据面' : '尚未下发到数据面'}（来源 ${escapeHtml(firstText(runtimeSafe.readback_source, '未提供'))}）。</p>${safeSearchScopeNoteMarkup()}</div>${capabilityNoteMarkup()}<footer class="web-access-section-footer"><span>保存后立即应用到数据面。</span><button class="policy-primary" type="button" data-web-access-save-policy ${disabled}>${state.saving ? '正在保存' : '保存并应用'}</button></footer></div></section>`;
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
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-web-access-close aria-label="关闭域名规则编辑"></button><aside class="user-auth-drawer web-access-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" aria-label="${editing ? '编辑域名规则' : '新增域名规则'}"><header class="dwrt-kit-sheet-header"><div><span>WEB ACCESS CONTROL</span><strong>${editing ? '编辑域名规则' : '手动拉黑域名'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-web-access-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body user-auth-drawer-body"><div class="user-auth-drawer-section"><strong>规则状态</strong><label class="user-auth-setting-row"><span><strong>启用规则</strong><small>停用后规则保留但不进入运行态</small></span><span class="web-access-switch dwrt-kit-switch" data-dwrt-component="switch"><input type="checkbox" data-web-access-field="enabled" ${editor.enabled !== false ? 'checked' : ''}></span></label></div><div class="user-auth-form-grid"><label class="user-auth-field is-wide"><span>动作</span><span class="user-auth-segmented web-access-action-switch"><button type="button" data-web-access-action="block" class="${editor.action !== 'allow' ? 'is-active' : ''}">拦截</button><button type="button" data-web-access-action="allow" class="${editor.action === 'allow' ? 'is-active' : ''}">放行</button></span><small>放行优先于拦截，用于纠正误拦。</small></label><label class="user-auth-field is-wide" data-dwrt-component="field"><span>域名${editing ? '' : '（每行一个，可批量粘贴）'}</span>${editing
      ? `<input data-web-access-field="domain" type="text" value="${escapeHtml(editor.domain || '')}">`
      : `<textarea data-web-access-field="domains" rows="6" placeholder="example.com&#10;ads.example.net">${escapeHtml(editor.domains || '')}</textarea>`}<small>自动去掉协议、路径与 www 前缀；不支持通配符与 IP。</small></label><label class="user-auth-field is-wide" data-dwrt-component="field"><span>备注</span><input data-web-access-field="note" type="text" value="${escapeHtml(editor.note || '')}" maxlength="256"></label></div><div class="user-auth-capability web-access-capability">${drawerScopeNote()}</div>${state.notice ? noticeMarkup() : ''}</div><footer class="dwrt-kit-sheet-footer user-auth-drawer-footer"><span></span><div><button class="policy-secondary" type="button" data-web-access-close>取消</button><button class="policy-primary" type="button" data-web-access-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存规则'}</button></div></footer></aside>`;
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

  function renderOverlays() {
    const host = root?.querySelector('[data-web-access-overlays]');
    if (!host) return;
    const markup = `${drawerMarkup()}${confirmationMarkup()}`;
    if (host.dataset.webAccessOverlayMarkup === markup) return;
    host.dataset.webAccessOverlayMarkup = markup;
    /*
     * 抽屉已被 kit 搬到 body 级 portal，清空本容器关不掉它。kit 的 `unmount(host)` 现在
     * 按 portalHome 反查回收传送出去的抽屉与遮罩，本页不再自备 portal 清理代码。
     */
    window.DWRT_UI_KIT?.unmount?.(host);
    host.innerHTML = markup;
    ui.mountAll?.(host);
  }

  function render() {
    renderShell();
  }

  /* 轮询只换工作区与概览，抽屉留在自己的容器里不被重建。 */
  /*
   * 后台刷新的重绘入口（Acceptance P0 单：本页实测丢焦点与内层滚动位置）。
   *
   * 原来是「整块重写 innerHTML + 事后复位 scrollTop」：滚动位置能救回来，焦点和选区不能。
   * 工作台容器本身稳定，交给 kit 按语义 key patch，滚动与焦点都不需要救。
   */
  function patchWorkbench() {
    const main = root?.querySelector('.web-access-workbench');
    if (!main) { render(); return; }
    const preserve = ui.preserveInteractionState;
    if (typeof preserve === 'function') {
      preserve(main, (target) => { target.innerHTML = `${noticeMarkup()}${workbenchMarkup()}`; });
    } else {
      const scroll = main.querySelector('.dwrt-kit-table-scroll');
      const position = { top: scroll?.scrollTop || 0, left: scroll?.scrollLeft || 0 };
      main.innerHTML = `${noticeMarkup()}${workbenchMarkup()}`;
      const next = main.querySelector('.dwrt-kit-table-scroll');
      if (next) { next.scrollTop = position.top; next.scrollLeft = position.left; }
    }
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
    /* 终端列表失败不影响主流程：作用对象仍可保留已选 MAC，只是没有可勾选的清单。 */
    async function loadClients() {
      try {
        const payload = await requestJson('/api/v1/clients');
        const rows = asArray(payload, ['clients', 'items', 'rows', 'list', 'results']);
        state.clients = rows.map(normalizeClient).filter((client) => macUsable(client.mac))
          .sort((left, right) => (Number(right.online) - Number(left.online)) || left.name.localeCompare(right.name, 'zh-CN'));
        state.clientsError = '';
      } catch (error) {
        state.clients = [];
        state.clientsError = failureText(error, '终端列表');
      }
    }

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
      const fetched = existing ? normalizePolicy(existing) : emptyPolicy();
      /*
       * 20 秒轮询会把 state.policy 整个换掉。作用对象与生效时段是多步操作（勾几台
       * 终端、填起止时间），一次轮询打断就等于白填，所以未保存时保留用户手上的这两项，
       * 其余字段照常跟随后端回读。
       */
      state.policy = state.policyDirty && state.policy
        ? { ...fetched, scope: state.policy.scope, schedule: state.policy.schedule }
        : fetched;

      /*
       * 终端列表只在按终端限定可用时才拉：旧固件上这张表没有用处，
       * 白拉一次 /api/v1/clients 只是给设备加负担。
       */
      if (deviceScopeOn()) await loadClients();
      else { state.clients = []; state.clientsError = ''; }

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
      /* 能力位为假时退回 all/always，否则 content_canonical_object() 会整条拒掉。 */
      scope: scopePayload(policy),
      schedule: schedulePayload(policy),
      confirm: true,
      apply: true
    };
  }

  async function savePolicy() {
    if (!writable() || state.saving) return;
    const blocker = policyBlocker(state.policy || emptyPolicy());
    if (blocker) {
      state.notice = blocker;
      state.noticeTone = 'warning';
      patchWorkbench();
      return;
    }
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
        /* blockers 里可能就是 content_* 错误码，能翻译就翻译成人话再显示。 */
        const translated = blockers.map((code) => contractErrorText(code) || code);
        state.notice = `后端未接受策略：${translated.join('、') || contractErrorText(firstText(response?.error)) || firstText(response?.error, '未返回原因')}`;
        state.noticeTone = 'error';
        patchWorkbench();
        return;
      }
      /* 只有真正落库了才清脏标记，否则轮询会把用户没保存成功的输入抹掉。 */
      state.policyDirty = false;
      state.notice = bool(response?.dataplane_changed, false) ? '策略已保存并下发到数据面。' : '策略已保存，数据面状态按后端回读显示。';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      if (Number(error.status) === 403) { state.readOnly = true; state.readOnlyReason = '当前账号为只读角色'; }
      const contract = contractErrorText(firstText(error.code)) || contractErrorText(firstText(error.message));
      state.notice = contract || `保存失败：${firstText(error.message, '后端未接受策略')}`;
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
    const scopeMode = event.target.closest('[data-web-access-scope-mode]');
    if (scopeMode) {
      const policy = state.policy || emptyPolicy();
      const next = scopeMode.dataset.webAccessScopeMode === 'devices' ? 'devices' : 'all';
      /* 切回「全部终端」保留已选 MAC，用户来回切换时不至于白选一遍。 */
      state.policy = { ...policy, scope: { type: next, devices: policy.scope?.devices || [] } };
      state.policyDirty = true;
      patchWorkbench();
      return;
    }
    if (event.target.closest('[data-web-access-scope-clear]')) {
      const policy = state.policy || emptyPolicy();
      state.policy = { ...policy, scope: { ...(policy.scope || { type: 'devices' }), devices: [] } };
      state.policyDirty = true;
      patchWorkbench();
      return;
    }
    const scheduleMode = event.target.closest('[data-web-access-schedule-mode]');
    if (scheduleMode) {
      const policy = state.policy || emptyPolicy();
      const schedule = policy.schedule || { type: 'always', start: '18:00', end: '22:00', weekdays: [] };
      state.policy = { ...policy, schedule: { ...schedule, type: scheduleMode.dataset.webAccessScheduleMode === 'window' ? 'window' : 'always' } };
      state.policyDirty = true;
      patchWorkbench();
      return;
    }
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
    const scopeSearch = event.target.closest('[data-web-access-scope-search]');
    if (scopeSearch) {
      state.scopeQuery = scopeSearch.value;
      const caret = scopeSearch.selectionStart;
      patchWorkbench();
      /* 重建工作区会丢焦点，搜索框必须自己找回来，否则打第二个字就断了。 */
      const next = root?.querySelector('[data-web-access-scope-search]');
      if (next) { next.focus(); try { next.setSelectionRange(caret, caret); } catch (_) {} }
      return;
    }
    const time = event.target.closest('[data-web-access-schedule-field]');
    if (time) {
      const policy = state.policy || emptyPolicy();
      state.policy = { ...policy, schedule: { ...(policy.schedule || { type: 'window' }), [time.dataset.webAccessScheduleField]: time.value } };
      state.policyDirty = true;
      return;
    }
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
    const scopeDevice = event.target.closest('[data-web-access-scope-device]');
    if (scopeDevice) {
      const policy = state.policy || emptyPolicy();
      const mac = normalizeMac(scopeDevice.dataset.webAccessScopeDevice);
      const devices = new Set(policy.scope?.devices || []);
      if (scopeDevice.checked) {
        if (!macUsable(mac)) {
          scopeDevice.checked = false;
          state.notice = `终端 MAC「${scopeDevice.dataset.webAccessScopeDevice}」不合法，无法作为作用对象。`;
          state.noticeTone = 'warning';
          patchWorkbench();
          return;
        }
        if (devices.size >= scopeDeviceMax() && !devices.has(mac)) {
          scopeDevice.checked = false;
          state.notice = `一条策略最多限定 ${scopeDeviceMax()} 台终端（device_scope_max_devices）。`;
          state.noticeTone = 'warning';
          patchWorkbench();
          return;
        }
        devices.add(mac);
      } else {
        devices.delete(mac);
      }
      state.policy = { ...policy, scope: { type: 'devices', devices: Array.from(devices) } };
      state.policyDirty = true;
      patchWorkbench();
      return;
    }
    const weekday = event.target.closest('[data-web-access-weekday]');
    if (weekday) {
      const policy = state.policy || emptyPolicy();
      const day = Number(weekday.dataset.webAccessWeekday);
      const days = new Set(policy.schedule?.weekdays || []);
      if (weekday.checked) days.add(day); else days.delete(day);
      state.policy = { ...policy, schedule: { ...(policy.schedule || { type: 'window' }), weekdays: Array.from(days).sort((left, right) => left - right) } };
      state.policyDirty = true;
      patchWorkbench();
      return;
    }
    const scheduleField = event.target.closest('[data-web-access-schedule-field]');
    if (scheduleField) {
      const policy = state.policy || emptyPolicy();
      state.policy = { ...policy, schedule: { ...(policy.schedule || { type: 'window' }), [scheduleField.dataset.webAccessScheduleField]: scheduleField.value } };
      state.policyDirty = true;
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
      /* 路由离开：让 kit 回收本页传送到 portal 的抽屉与遮罩，别把遮罩留给下一页 */
      window.DWRT_UI_KIT?.unmount?.(root);
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
