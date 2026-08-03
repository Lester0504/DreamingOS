const VERSION = '20260802-sheet-portal-scope-01';

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || window.DWRT_UI_KIT || {};
  const escapeHtml = context.utils?.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const stage = root?.closest('.console-stage');
  const ENDPOINT = '/api/v1/network/gateway-shadow';
  const TABS = [['status', '运行状态'], ['config', '配置'], ['pairing', '设备配对']];
  const DEFAULT_CONFIG = Object.freeze({
    enabled: false, role: 'primary', lan_interface: 'br-lan', management_ipv4: '',
    heartbeat_interface: '', heartbeat_local_ip: '', heartbeat_peer_ip: '',
    heartbeat_prefix_length: 30, virtual_ipv4: '', virtual_router_id: 51,
    priority: 150, advert_interval_seconds: 1, preempt: false, connection_sync: true
  });
  const state = {
    mounted: true, loading: true, refreshing: false, busy: '', tab: 'status',
    error: '', notice: '', noticeTone: '', config: { ...DEFAULT_CONFIG },
    draft: { ...DEFAULT_CONFIG }, peer: {}, capabilities: {}, status: {},
    preflight: null, dirty: false, availabilityOpen: false, confirmation: '', pollTimer: 0,
    pairing: { code: '', offer: '', acceptance: '', confirmation: '', inputOffer: '', inputCode: '', inputAcceptance: '', inputConfirmation: '' }
  };

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      const text = typeof value === 'object' ? firstText(value.message, value.error, value.reason, value.code) : String(value).trim();
      if (text) return text;
    }
    return '';
  }

  function bool(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') return !['0', 'false', 'off', 'no', 'disabled'].includes(value.toLowerCase());
    return Boolean(value);
  }

  function number(value, fallback) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
  }

  function clone(value) {
    try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value || {})); }
  }

  function normalizedConfig(value = {}) {
    return {
      ...DEFAULT_CONFIG, ...value,
      enabled: bool(value.enabled), preempt: false, connection_sync: bool(value.connection_sync, true),
      heartbeat_prefix_length: number(value.heartbeat_prefix_length, 30),
      virtual_router_id: number(value.virtual_router_id, 51),
      priority: number(value.priority, 150),
      advert_interval_seconds: number(value.advert_interval_seconds, 1)
    };
  }

  function currentRole() {
    try { return String(localStorage.getItem('dreamingwrt.web.role') || '').toLowerCase(); } catch (_) { return ''; }
  }

  function ownerWriteAllowed() { return currentRole() === 'owner'; }
  function capability(name) { return state.capabilities?.[name] === true; }
  function reason() { return firstText(state.capabilities?.reason, state.preflight?.reason, state.status?.last_error); }
  function writeAllowed(name) { return ownerWriteAllowed() && capability(name); }

  /*
   * 会话闸门适配器。此前这里是裸 fetch 直接读 localStorage 的 access token，token 过期时
   * 既不刷新也不重试，并发请求会集体拿 401（通知推送页就表现为 unauthorized 六连）。
   * 闸门内部处理 ensureFresh -> 401 -> refresh -> 单次重试，refreshPromise 单例会合并并发刷新。
   */
  function sessionFetch(url, init = {}) {
    return window.DWRT_REQUEST ? window.DWRT_REQUEST.fetch(url, init) : fetch(url, init);
  }

  function authHeaders(extra = {}) {
    return { Accept: 'application/json', ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}), ...extra };
  }

  async function requestJson(path, options = {}) {
    const response = await sessionFetch(`${ENDPOINT}${path}${path.includes('?') ? '&' : '?'}v=${VERSION}`, {
      credentials: 'same-origin', cache: 'no-store', signal: context.signal, ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    const data = json?.data ?? json?.body ?? json;
    const code = Number(json?.code);
    const dataCode = Number(data?.code);
    const failed = !response.ok || json?.ok === false || data?.ok === false
      || (Number.isFinite(code) && ![0, 200, 2000].includes(code))
      || (Number.isFinite(dataCode) && ![0, 200, 2000].includes(dataCode));
    if (failed) {
      const error = new Error(firstText(data?.message, data?.error, data?.reason, json?.message, json?.error, `HTTP ${response.status}`));
      error.payload = data; error.status = response.status; throw error;
    }
    return data || {};
  }

  function clearPairingSecrets() {
    state.pairing.code = '';
    state.pairing.inputCode = '';
    state.pairing.inputOffer = '';
    state.pairing.inputAcceptance = '';
    state.pairing.inputConfirmation = '';
  }

  async function load(background = false) {
    if (background) state.refreshing = true; else state.loading = true;
    state.error = '';
    if (!background) render();
    try {
      const [config, status] = await Promise.all([requestJson(''), requestJson('/status')]);
      if (!state.mounted) return;
      state.config = normalizedConfig(config.config);
      if (!state.dirty) state.draft = clone(state.config);
      state.peer = config.peer || {};
      state.capabilities = { ...(config.capabilities || {}), ...(status.capabilities || {}) };
      state.status = status || {};
    } catch (error) {
      if (state.mounted) state.error = `读取失败：${firstText(error.message, '高可用性接口不可用')}`;
    } finally {
      state.loading = false; state.refreshing = false; render();
    }
  }

  function validateDraft() {
    const required = [['lan_interface', 'LAN 接口'], ['management_ipv4', '管理地址'], ['heartbeat_interface', '心跳接口'], ['heartbeat_local_ip', '本机心跳地址'], ['heartbeat_peer_ip', '对端心跳地址'], ['virtual_ipv4', '虚拟 IPv4']];
    for (const [key, label] of required) if (!String(state.draft[key] || '').trim()) return `${label}不能为空`;
    if (!['primary', 'secondary'].includes(state.draft.role)) return '请选择主或备配置角色';
    if (state.draft.heartbeat_prefix_length < 1 || state.draft.heartbeat_prefix_length > 32) return '心跳前缀长度必须位于 1-32';
    if (state.draft.virtual_router_id < 1 || state.draft.virtual_router_id > 255) return 'VRID 必须位于 1-255';
    if (state.draft.priority < 1 || state.draft.priority > 254) return '优先级必须位于 1-254';
    if (state.draft.advert_interval_seconds < 1 || state.draft.advert_interval_seconds > 60) return '通告间隔必须位于 1-60 秒';
    return '';
  }

  function configPayload(includeSecret = false) {
    const config = clone(state.draft);
    config.preempt = false;
    if (includeSecret) {
      const input = root?.querySelector('[data-shadow-field="auth_key"]');
      const secret = String(input?.value || '');
      if (secret) config.auth_key = secret;
      if (input) input.value = '';
    }
    return { config };
  }

  async function saveConfig() {
    if (state.busy || !state.dirty || !writeAllowed('save')) return;
    const validation = validateDraft();
    if (validation) { state.notice = validation; state.noticeTone = 'bad'; render(); return; }
    const payload = configPayload(true);
    state.busy = 'save'; state.notice = ''; render();
    try {
      await requestJson('/save', { method: 'POST', body: JSON.stringify(payload) });
      state.preflight = null; state.dirty = false; state.notice = '配置已保存为草稿，尚未应用'; state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.notice = `保存失败：${firstText(error.message, '后端未接受配置')}`; state.noticeTone = 'bad';
    } finally { state.busy = ''; render(); }
  }

  async function runPreflight() {
    if (state.busy || state.dirty || !writeAllowed('preflight')) return;
    state.busy = 'preflight'; state.notice = ''; render();
    try {
      state.preflight = await requestJson('/preflight', { method: 'POST', body: '{}' });
      state.capabilities = { ...state.capabilities, ...(state.preflight.capabilities || {}) };
      state.notice = state.preflight.ready ? '预检通过，可以应用' : `预检未通过：${reasonLabel(state.preflight.reason)}`;
      state.noticeTone = state.preflight.ready ? 'ok' : 'bad';
    } catch (error) {
      state.preflight = error.payload || null; state.notice = `预检失败：${firstText(error.message, '后端未返回预检结果')}`; state.noticeTone = 'bad';
    } finally { state.busy = ''; render(); }
  }

  async function applyConfig() {
    if (state.busy || state.confirmation !== 'apply' || !state.preflight?.ready || state.dirty || !writeAllowed('apply_supported')) return;
    state.busy = 'apply'; state.confirmation = ''; render();
    try {
      const result = await requestJson('/apply', { method: 'POST', body: '{}' });
      if (result.applied !== true) throw new Error(firstText(result.reason, '后端未确认应用'));
      state.notice = '高可用性配置已应用'; state.noticeTone = 'ok'; state.preflight = null; await load(true);
    } catch (error) { state.notice = `应用失败：${firstText(error.message, '后端未确认应用')}`; state.noticeTone = 'bad'; }
    finally { state.busy = ''; render(); }
  }

  async function disableShadow() {
    if (state.busy || state.confirmation !== 'disable' || !writeAllowed('disable_supported')) return;
    state.busy = 'disable'; state.confirmation = ''; render();
    try {
      const result = await requestJson('/disable', { method: 'POST', body: '{}' });
      if (result.applied !== true) throw new Error(firstText(result.reason, '后端未确认禁用'));
      state.notice = '高可用性已禁用'; state.noticeTone = 'ok'; state.preflight = null; state.dirty = false; await load(true);
    } catch (error) { state.notice = `禁用失败：${firstText(error.message, '后端未确认禁用')}`; state.noticeTone = 'bad'; }
    finally { state.busy = ''; render(); }
  }

  function parseExchange(raw, label) {
    try { const value = JSON.parse(raw); if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(); return value; }
    catch (_) { throw new Error(`${label}必须是 JSON 对象`); }
  }

  async function pairingRequest(path, payload, success) {
    if (state.busy || !writeAllowed('pairing_supported')) return null;
    state.busy = 'pairing'; state.notice = ''; render();
    try { const result = await requestJson(path, { method: 'POST', body: JSON.stringify(payload) }); state.notice = success; state.noticeTone = 'ok'; return result; }
    catch (error) { state.notice = `配对失败：${firstText(error.message, '后端拒绝配对材料')}`; state.noticeTone = 'bad'; return null; }
    finally { state.busy = ''; }
  }

  async function startPairing() {
    const result = await pairingRequest('/pairing/start', { action: 'start', ...configPayload(false) }, '配对邀请已创建，请立即交给对端');
    if (result) { state.pairing.code = firstText(result.pairing_code); state.pairing.offer = JSON.stringify(result.offer || {}, null, 2); }
    render();
  }

  async function approvePairing() {
    try {
      const offer = parseExchange(state.pairing.inputOffer, '配对邀请');
      const code = state.pairing.inputCode.trim();
      if (!/^\d{8}$/.test(code)) throw new Error('配对码必须是 8 位数字');
      const result = await pairingRequest('/pairing/approve', { action: 'approve', offer, pairing_code: code, ...configPayload(false) }, '邀请已核验，请将接受材料交回发起端');
      state.pairing.inputCode = ''; state.pairing.inputOffer = '';
      if (result) state.pairing.acceptance = JSON.stringify(result.acceptance || {}, null, 2);
    } catch (error) { state.notice = firstText(error.message); state.noticeTone = 'bad'; }
    render();
  }

  async function finalizePairing() {
    try {
      const acceptance = parseExchange(state.pairing.inputAcceptance, '接受材料');
      const result = await pairingRequest('/pairing/start', { action: 'finalize', acceptance }, '发起端已建立信任，请将确认材料交回对端');
      state.pairing.inputAcceptance = ''; state.pairing.code = '';
      if (result) state.pairing.confirmation = JSON.stringify(result.confirmation || {}, null, 2);
    } catch (error) { state.notice = firstText(error.message); state.noticeTone = 'bad'; }
    render();
  }

  async function confirmPairing() {
    try {
      const confirmation = parseExchange(state.pairing.inputConfirmation, '确认材料');
      const result = await pairingRequest('/pairing/approve', { action: 'confirm', confirmation }, '双向信任已建立');
      state.pairing.inputConfirmation = '';
      if (result?.paired) await load(true);
    } catch (error) { state.notice = firstText(error.message); state.noticeTone = 'bad'; }
    render();
  }

  function reasonLabel(value) {
    const key = firstText(value);
    return ({
      pairing_runtime_unavailable: '配对运行时不可用', mutual_authenticated_peer_pairing_pending: '等待双向认证配对',
      keepalived_not_installed: '未安装 keepalived', conntrackd_not_installed: '未安装 conntrackd',
      configuration_invalid: '配置校验失败', preflight_failed: '预检未通过', gateway_shadow_disabled: '功能尚未启用',
      lan_interface_not_found: 'LAN 接口不存在', heartbeat_interface_not_found: '心跳接口不存在'
    })[key] || key || '后端未提供原因';
  }

  function runtimeRoleLabel(value) {
    const key = firstText(value).toUpperCase();
    return ({ MASTER: 'MASTER', BACKUP: 'BACKUP', FAULT: 'FAULT', DISABLED: 'DISABLED', UNKNOWN: 'UNKNOWN' })[key] || key || 'UNKNOWN';
  }

  function icon(name) { return `<i data-lucide="${escapeHtml(name)}" aria-hidden="true"></i>`; }

  /*
   * 概览卡片的图标必须是真实 SVG：Kit 的 normalizeOverviewIcon() 只重写 <svg> 标签，
   * 传 <i data-lucide> 进去会原样落到卡片里、等 lucide 后置替换，卡片首帧是空的。
   * 按 design.md 的约定同时给 lucide 名与内置 path，未命中不静默兜底。
   */
  function cardIcon(name, size = 22) {
    const lucideName = {
      role: 'server-cog', peer: 'link', session: 'activity', guard: 'shield-alert',
      keepalived: 'heart-pulse', conntrackd: 'arrow-left-right'
    }[name] || name;
    const rendered = typeof ui.lucideIcon === 'function' ? ui.lucideIcon(lucideName, { size, strokeWidth: 1.8 }) : '';
    if (rendered) return rendered;
    const paths = {
      role: '<path d="M4 5h16v5H4zM4 14h9v5H4z"></path><circle cx="18" cy="16.5" r="2.5"></circle><path d="M18 12.8v.9m0 5.6v.9m3.2-3.7h-.9m-4.6 0h-.9"></path>',
      peer: '<path d="M9 15 5.6 18.4a3.5 3.5 0 0 0 4.9 4.9"></path><path d="M15 9l3.4-3.4a3.5 3.5 0 0 0-4.9-4.9"></path><path d="m9.5 14.5 5-5"></path>',
      session: '<path d="M3 12h4l2-6 4 12 2-6h6"></path>',
      guard: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"></path><path d="M12 8v4"></path><path d="M12 16h.01"></path>',
      keepalived: '<path d="M3 12h3l2-4 2.5 8 2-6 1.5 3h6"></path><path d="M20.5 6.5a3.2 3.2 0 0 0-4.5 0L15 7.5"></path>',
      conntrackd: '<path d="m8 7-4 4 4 4"></path><path d="M4 11h16"></path><path d="m16 17 4-4-4-4"></path>'
    };
    return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.role}</svg>`;
  }

  function badge(label, tone = 'neutral') { return `<span class="shadow-badge is-${tone}">${escapeHtml(label)}</span>`; }
  function stateTone(value) { return ['active', 'master', 'backup'].includes(String(value).toLowerCase()) ? 'success' : ['blocked', 'error', 'fault'].includes(String(value).toLowerCase()) ? 'danger' : 'neutral'; }
  function triState(value) { return value === true ? '可达' : value === false ? '不可达' : '未知'; }
  function valueOrDash(value) { return value === undefined || value === null || value === '' ? '--' : String(value); }

  function noticeMarkup() {
    const text = state.error || state.notice; if (!text) return '';
    const tone = state.error || state.noticeTone === 'bad' ? 'danger' : 'success';
    return `<div class="shadow-notice is-${tone}" role="status" data-adaptive-sample>${icon(tone === 'danger' ? 'triangle-alert' : 'circle-check')}<span>${escapeHtml(text)}</span></div>`;
  }

  function toolbarMarkup() {
    return `<header class="shadow-toolbar"><nav class="dwrt-kit-tabs dwrt-kit-page-tabs shadow-tabs" data-dwrt-component="tabs" role="tablist" aria-label="高可用性视图"><span class="dwrt-kit-tab-pill" aria-hidden="true"></span>${TABS.map(([id, label]) => `<button class="dwrt-kit-tab ${state.tab === id ? 'is-active' : ''}" type="button" role="tab" data-shadow-tab="${id}" data-value="${id}" aria-selected="${state.tab === id}">${label}</button>`).join('')}</nav></header>`;
  }

  function availabilityMarkup() {
    const available = ownerWriteAllowed();
    return `<section class="shadow-availability dwrt-kit-glass-surface" data-dwrt-component="surface" data-dwrt-surface="stable-glass" data-adaptive-sample><button type="button" data-shadow-availability aria-expanded="${state.availabilityOpen}"><span>${icon('shield-check')}<span><strong>可用性说明</strong><small>${available ? reasonLabel(reason()) : '当前账号不是 owner，页面保持只读'}</small></span></span>${icon('chevron-down')}</button>${state.availabilityOpen ? `<div><dl><div><dt>配对</dt><dd>${capability('pairing_supported') ? '可用' : reasonLabel(reason())}</dd></div><div><dt>VRRP</dt><dd>${capability('vrrp_supported') ? 'keepalived 可用' : 'keepalived 缺失'}</dd></div><div><dt>连接同步</dt><dd>${capability('connection_sync_supported') ? 'conntrackd 可用' : 'conntrackd 缺失'}</dd></div><div><dt>会话连续性</dt><dd>best effort</dd></div></dl><p>高可用性不能保证所有连接无损迁移。对端状态未知或链路分区时存在 split-brain 风险，必须先完成预检。</p></div>` : ''}</section>`;
  }

  /*
   * 运行状态按用户第 1 条重构：四项关键运行指标提成顶部一排共享概览卡，
   * 守护组件（keepalived / conntrackd）放进一条深井，告警与边界说明各自成条。
   * 原先那张八宫格 <dl> 把角色、对端、组件、VIP 混在一起，扫读代价高。
   * 卡片用 Kit 的 overviewCardsMarkup()，不复制 demo 的私有卡片材质。
   */
  function statusOverviewCards() {
    const renderer = ui.overviewCardsMarkup || window.DWRT_UI_KIT?.overviewCardsMarkup;
    if (typeof renderer !== 'function') return '';
    const runtimeState = firstText(state.status.state, 'unknown').toLowerCase();
    const configuredRole = firstText(state.status.configured_role);
    const runtimeRole = runtimeRoleLabel(firstText(state.status.vrrp_state, state.status.runtime_role, 'unknown'));
    const enabled = state.config.enabled === true;
    const paired = state.status.paired === true;
    const blocked = ['blocked', 'error', 'fault'].includes(runtimeState) || !enabled;
    const syncSupported = capability('connection_sync_supported');
    const syncOn = state.config.connection_sync === true && syncSupported;
    return renderer([
      {
        key: 'role',
        label: '节点角色',
        value: configuredRole ? (configuredRole === 'secondary' ? '备网关' : '主网关') : '未配置',
        detail: `运行角色 ${runtimeRole} · 虚拟 IP ${state.status.virtual_ipv4_present ? '已绑定' : '未绑定'}`,
        tone: enabled ? (runtimeRole === 'MASTER' ? 'ok' : runtimeRole === 'BACKUP' ? 'info' : 'warn') : 'bad',
        icon: cardIcon('role')
      },
      {
        key: 'peer',
        label: '对端互信',
        value: paired ? '已配对' : '未配对',
        detail: `对端可达性 ${triState(state.status.peer_reachable)}`,
        tone: paired ? (state.status.peer_reachable === true ? 'ok' : 'warn') : 'warn',
        icon: cardIcon('peer')
      },
      {
        key: 'session',
        label: '会话连续性',
        value: syncOn ? '尽力而为' : '未启用',
        detail: syncSupported ? '不支持完全无损迁移' : 'conntrackd 不可用',
        tone: syncOn ? 'info' : 'neutral',
        icon: cardIcon('session')
      },
      {
        key: 'guard',
        label: '集群防护',
        value: blocked ? '已阻断' : '已放行',
        detail: blocked ? reasonLabel(firstText(state.status.last_error, reason(), enabled ? '' : 'gateway_shadow_disabled')) : 'VRRP 协议栈运行中',
        tone: blocked ? 'bad' : 'ok',
        icon: cardIcon('guard')
      }
    ], { className: 'shadow-overview', label: '高可用性运行状态' });
  }

  function daemonRow(name, title, description, available, running) {
    const label = available ? (running ? '运行中' : '可用 / 未运行') : '未安装';
    const tone = available ? (running ? 'success' : 'warning') : 'danger';
    return `<div class="shadow-daemon-item"><span class="shadow-daemon-copy">${cardIcon(name, 18)}<span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(description)}</small></span></span>${badge(label, tone)}</div>`;
  }

  function daemonsMarkup() {
    return `<section class="shadow-daemons dwrt-kit-glass-surface" data-dwrt-component="surface" data-dwrt-surface="stable-glass" data-adaptive-sample>
      ${daemonRow('keepalived', 'keepalived', 'VRRP 网关冗余与 VIP 漂移守护进程', state.status.keepalived_available === true, state.status.keepalived_running === true)}
      ${daemonRow('conntrackd', 'conntrackd', '连接跟踪表双向同步服务', state.status.conntrackd_available === true, state.status.conntrackd_running === true)}
    </section>`;
  }

  function runtimeErrorMarkup() {
    const text = firstText(state.status.last_error);
    if (!text) return '';
    return `<section class="shadow-runtime-error dwrt-kit-glass-surface" data-dwrt-component="surface" data-dwrt-surface="stable-glass" role="status" data-adaptive-sample>${icon('triangle-alert')}<span><strong>最近错误</strong><small>${escapeHtml(reasonLabel(text))}</small></span></section>`;
  }

  function statusMarkup() {
    return `${statusOverviewCards()}${daemonsMarkup()}${runtimeErrorMarkup()}${riskMarkup()}${preflightMarkup()}${availabilityMarkup()}`;
  }

  function riskMarkup() {
    return `<section class="shadow-risk dwrt-kit-glass-surface" data-dwrt-component="surface" data-dwrt-surface="stable-glass" data-adaptive-sample>${icon('shield-alert')}<span><strong>高可用边界</strong><small>对端可达性为 ${triState(state.status.peer_reachable)}。链路分区仍可能产生 split-brain；会话连续性仅为 best effort，不等同于无损迁移。</small></span></section>`;
  }

  function preflightMarkup() {
    if (!state.preflight) return '';
    const checks = Array.isArray(state.preflight.checks) ? state.preflight.checks : [];
    const errors = Array.isArray(state.preflight.errors) ? state.preflight.errors : [];
    return `<section class="shadow-preflight dwrt-kit-glass-surface" data-dwrt-component="surface" data-dwrt-surface="stable-glass" data-adaptive-sample><header><span>${icon(state.preflight.ready ? 'circle-check' : 'circle-x')}<span><strong>最近一次预检${state.preflight.ready ? '通过' : '未通过'}</strong><small>${state.preflight.ready ? '配置可以进入应用确认' : reasonLabel(state.preflight.reason)}</small></span></span></header><ul>${checks.map((check) => `<li class="${check.passed ? 'is-pass' : 'is-fail'}">${icon(check.passed ? 'check' : 'x')}<span><strong>${escapeHtml(reasonLabel(check.name))}</strong>${check.reason ? `<small>${escapeHtml(reasonLabel(check.reason))}</small>` : ''}</span></li>`).join('')}</ul>${errors.length ? `<div class="shadow-field-errors">${errors.map((error) => `<span>${escapeHtml(reasonLabel(error))}</span>`).join('')}</div>` : ''}</section>`;
  }

  function field(label, name, options = {}) {
    const value = state.draft[name]; const disabled = !writeAllowed('save');
    const attrs = `data-shadow-field="${name}" ${disabled ? 'disabled' : ''}`;
    let control;
    if (options.options) control = `<select ${attrs}>${options.options.map(([id, text]) => `<option value="${id}" ${String(value) === id ? 'selected' : ''}>${text}</option>`).join('')}</select>`;
    else control = `<input type="${options.type || 'text'}" value="${escapeHtml(valueOrDash(value) === '--' ? '' : value)}" ${attrs} ${options.min !== undefined ? `min="${options.min}"` : ''} ${options.max !== undefined ? `max="${options.max}"` : ''} ${options.placeholder ? `placeholder="${escapeHtml(options.placeholder)}"` : ''}>`;
    // 单位后缀贴在控件右侧（demo 的 input-unit），所以控件要包一层定位容器。
    const body = options.unit
      ? `<span class="shadow-field-unit-wrap">${control}<em class="shadow-field-unit">${escapeHtml(options.unit)}</em></span>`
      : control;
    return `<label class="shadow-field ${options.wide ? 'is-wide' : ''}"><span>${label}</span>${body}${options.help ? `<small>${options.help}</small>` : ''}</label>`;
  }

  function switchField(label, name, help) {
    const disabled = !writeAllowed('save');
    return `<label class="shadow-switch-row"><span><strong>${label}</strong><small>${help}</small></span><span class="dwrt-kit-switch" data-dwrt-component="switch"><input type="checkbox" data-shadow-field="${name}" ${state.draft[name] ? 'checked' : ''} ${disabled ? 'disabled' : ''}><span aria-hidden="true"></span></span></label>`;
  }

  /*
   * 角色是二选一的枚举，用分段控件比下拉更直观（demo 的 pill-switcher 同理），
   * 材质走 Kit 的 segmented，不自绘药丸。
   */
  function roleSegmentedField() {
    const disabled = !writeAllowed('save');
    const options = [['primary', '主网关 Master'], ['secondary', '备网关 Backup']];
    // Kit 的 segmented 契约是 [data-dwrt-segment] + data-value，并自带键盘导航与
    // dwrt-segment-change 事件；这里只提供选项，不自己实现激活态切换。
    return `<div class="shadow-field"><span>配置角色</span><div class="dwrt-kit-segmented shadow-role-segmented" data-dwrt-component="segmented" data-shadow-role-group role="radiogroup" aria-label="配置角色" data-dwrt-value="${escapeHtml(state.draft.role || 'primary')}">${options.map(([id, label]) => `<button class="${state.draft.role === id ? 'is-active' : ''}" type="button" role="radio" aria-checked="${state.draft.role === id}" data-dwrt-segment data-value="${id}" ${disabled ? 'disabled' : ''}>${escapeHtml(label)}</button>`).join('')}</div></div>`;
  }

  function chamber(iconName, title, hint, body) {
    return `<section class="shadow-chamber dwrt-kit-glass-surface" data-dwrt-component="surface" data-dwrt-surface="stable-glass" data-adaptive-sample>
      <header class="shadow-chamber-head"><span>${icon(iconName)}<strong>${escapeHtml(title)}</strong></span>${hint ? `<small>${escapeHtml(hint)}</small>` : ''}</header>
      <div class="shadow-chamber-body">${body}</div>
    </section>`;
  }

  /*
   * 配置页按用户第 2 条重构成 demo 的分舱结构：顶部主控卡承载总开关与同步状态，
   * 下面三个玻璃舱分别是集群角色与 VIP、心跳链路、VRRP 协议参数，
   * 底部一条动作条收纳保存 / 预检 / 应用 / 禁用。
   * 原先是一张长卡片里塞 12 个字段的三列网格，字段之间没有语义分组。
   */
  function configMarkup() {
    const canSave = writeAllowed('save');
    const masterCard = `<section class="shadow-master-card dwrt-kit-glass-surface" data-dwrt-component="surface" data-dwrt-surface="stable-glass" data-adaptive-sample>
      <div class="shadow-master-copy">
        <strong>${icon('server-cog')}<span>启用高可用冗余 VRRP</span>${badge(state.dirty ? '未保存' : '已同步', state.dirty ? 'warning' : 'success')}</strong>
        <small>先保存配置草稿，完成系统预检无误后再应用规则</small>
      </div>
      <span class="dwrt-kit-switch" data-dwrt-component="switch"><input type="checkbox" data-shadow-field="enabled" ${state.draft.enabled ? 'checked' : ''} ${canSave ? '' : 'disabled'}><span aria-hidden="true"></span></span>
    </section>`;

    const clusterChamber = chamber('globe', '集群角色与虚拟 IP', '对外广播的共享虚拟网关', `
      <div class="shadow-grid-2">${roleSegmentedField()}${field('绑定 LAN 接口', 'lan_interface', { placeholder: 'br-lan' })}</div>
      <div class="shadow-grid-2">${field('虚拟 IPv4（VIP 网关）', 'virtual_ipv4', { placeholder: '192.168.30.1/24' })}${field('本机管理 IPv4', 'management_ipv4', { placeholder: '192.168.30.2/24' })}</div>
    `);

    const heartbeatChamber = chamber('heart-pulse', '心跳与节点链路', '节点间 keepalive 探测私有通道', `
      <div class="shadow-grid-2">${field('心跳接口', 'heartbeat_interface', { placeholder: 'eth1' })}${field('心跳掩码前缀', 'heartbeat_prefix_length', { type: 'number', min: 1, max: 32, unit: 'CIDR' })}</div>
      <div class="shadow-grid-2">${field('本机心跳地址', 'heartbeat_local_ip', { placeholder: '169.254.30.1' })}${field('对端心跳地址', 'heartbeat_peer_ip', { placeholder: '169.254.30.2' })}</div>
    `);

    const protocolChamber = chamber('settings-2', 'VRRP 协议参数', '', `
      <div class="shadow-grid-3">${field('虚拟路由 ID', 'virtual_router_id', { type: 'number', min: 1, max: 255, unit: 'VRID' })}${field('节点优先级', 'priority', { type: 'number', min: 1, max: 254, unit: 'PRIO' })}${field('通告间隔', 'advert_interval_seconds', { type: 'number', min: 1, max: 60, unit: 'SEC' })}</div>
      <div class="shadow-grid-2">${field('认证密钥', 'auth_key', { type: 'password', placeholder: '留空表示保持现有密钥', help: '只写字段，16-128 个字符；提交后立即清空且不会回填。' })}<div class="shadow-field"><span>抢占模式</span><div class="shadow-fixed-value">${badge('关闭', 'neutral')}<small>阶段一固定为关闭，避免产生未验证的强制主切换。</small></div></div></div>
      ${switchField('连接状态同步', 'connection_sync', capability('connection_sync_supported') ? '由 conntrackd 提供 best effort 会话同步。' : 'conntrackd 不可用，启用后预检将失败。')}
    `);

    const actionBar = `<section class="shadow-operation-bar dwrt-kit-glass-surface" data-dwrt-component="surface" data-dwrt-surface="stable-glass" data-adaptive-sample>
      <div><small>${escapeHtml(state.dirty ? '先保存当前配置草稿' : state.preflight?.ready ? '预检已通过，等待确认应用' : '应用前必须先通过运行预检')}</small></div>
      <div>
        <button class="dwrt-kit-button" data-dwrt-component="button" data-variant="ghost" type="button" data-shadow-reset ${!state.dirty || state.busy ? 'disabled' : ''}>复位</button>
        <button class="dwrt-kit-button" data-dwrt-component="async-button" data-variant="primary" type="button" data-shadow-save ${!state.dirty || !canSave || state.busy ? 'disabled' : ''}>${state.busy === 'save' ? '正在保存' : '保存草稿'}</button>
        <button class="dwrt-kit-button" data-dwrt-component="async-button" data-variant="ghost" type="button" data-shadow-preflight ${state.dirty || !writeAllowed('preflight') || state.busy ? 'disabled' : ''}>${icon('list-checks')}<span>${state.busy === 'preflight' ? '正在预检' : '运行预检'}</span></button>
        <button class="dwrt-kit-button" data-dwrt-component="button" data-variant="primary" type="button" data-shadow-confirm="apply" ${state.dirty || !state.preflight?.ready || !writeAllowed('apply_supported') || state.busy ? 'disabled' : ''}>${icon('play')}<span>应用配置</span></button>
        <button class="dwrt-kit-button shadow-danger" data-dwrt-component="button" data-variant="danger" type="button" data-shadow-confirm="disable" ${!writeAllowed('disable_supported') || state.busy ? 'disabled' : ''}>${icon('power')}<span>禁用服务</span></button>
      </div>
    </section>`;

    const readonlyNote = canSave ? '' : `<div class="shadow-readonly">${icon('lock-keyhole')}<span>${ownerWriteAllowed() ? reasonLabel(reason()) : '仅 owner 可以修改高可用性配置'}</span></div>`;
    return `${masterCard}${clusterChamber}${heartbeatChamber}${protocolChamber}${readonlyNote}${actionBar}${preflightMarkup()}${availabilityMarkup()}`;
  }

  function exchangeField(label, key, options = {}) {
    const value = state.pairing[key] || '';
    return `<label class="shadow-exchange-field"><span>${label}</span>${options.code ? `<input type="password" inputmode="numeric" maxlength="8" autocomplete="off" data-shadow-pair-input="${key}" value="${escapeHtml(value)}" placeholder="8 位配对码">` : `<textarea data-shadow-pair-input="${key}" ${options.readonly ? 'readonly' : ''} spellcheck="false" placeholder="${escapeHtml(options.placeholder || '')}">${escapeHtml(value)}</textarea>`}${options.help ? `<small>${options.help}</small>` : ''}</label>`;
  }

  function pairingMarkup() {
    const writable = writeAllowed('pairing_supported');
    return `<section class="shadow-pairing-grid"><article class="shadow-surface shadow-pair-card dwrt-kit-glass-surface" data-dwrt-component="surface" data-dwrt-surface="stable-glass" data-adaptive-sample><header><span>${icon('send')}<span><strong>发起端</strong><small>创建邀请并完成确认</small></span></span>${badge(state.peer?.trust_state === 'paired' ? '已配对' : '未配对', state.peer?.trust_state === 'paired' ? 'success' : 'neutral')}</header><div class="shadow-pair-step"><strong>1. 创建邀请</strong><button class="dwrt-kit-button" data-dwrt-component="async-button" data-variant="primary" type="button" data-shadow-pair="start" ${!writable || state.busy ? 'disabled' : ''}>创建配对邀请</button></div>${state.pairing.code ? `<div class="shadow-one-time-code" role="status"><span>一次性配对码</span><strong>${escapeHtml(state.pairing.code)}</strong><small>仅在当前页面显示；离开页面后无法恢复。</small></div>` : ''}${state.pairing.offer ? exchangeField('邀请材料', 'offer', { readonly: true, help: '将完整 JSON 交给对端，不要通过不可信渠道发送。' }) : ''}<div class="shadow-pair-step"><strong>2. 核验接受材料</strong>${exchangeField('对端接受材料', 'inputAcceptance', { placeholder: '粘贴 acceptance JSON' })}<button class="dwrt-kit-button" data-dwrt-component="async-button" data-variant="primary" type="button" data-shadow-pair="finalize" ${!writable || state.busy ? 'disabled' : ''}>核验并生成确认</button></div>${state.pairing.confirmation ? exchangeField('确认材料', 'confirmation', { readonly: true }) : ''}</article><article class="shadow-surface shadow-pair-card dwrt-kit-glass-surface" data-dwrt-component="surface" data-dwrt-surface="stable-glass" data-adaptive-sample><header><span>${icon('scan-line')}<span><strong>响应端</strong><small>核验邀请并建立双向信任</small></span></span></header><div class="shadow-pair-step"><strong>1. 核验邀请</strong>${exchangeField('发起端邀请材料', 'inputOffer', { placeholder: '粘贴 offer JSON' })}${exchangeField('配对码', 'inputCode', { code: true, help: '提交后立即清空，不写入浏览器存储。' })}<button class="dwrt-kit-button" data-dwrt-component="async-button" data-variant="primary" type="button" data-shadow-pair="approve" ${!writable || state.busy ? 'disabled' : ''}>核验并生成接受材料</button></div>${state.pairing.acceptance ? exchangeField('接受材料', 'acceptance', { readonly: true }) : ''}<div class="shadow-pair-step"><strong>2. 完成双向信任</strong>${exchangeField('发起端确认材料', 'inputConfirmation', { placeholder: '粘贴 confirmation JSON' })}<button class="dwrt-kit-button" data-dwrt-component="async-button" data-variant="primary" type="button" data-shadow-pair="confirm" ${!writable || state.busy ? 'disabled' : ''}>完成配对</button></div></article></section>${!writable ? `<div class="shadow-readonly">${icon('lock-keyhole')}<span>${ownerWriteAllowed() ? reasonLabel(reason()) : '仅 owner 可以执行设备配对'}</span></div>` : ''}${riskMarkup()}${availabilityMarkup()}`;
  }

  function confirmationMarkup() {
    if (!state.confirmation) return '';
    const applying = state.confirmation === 'apply';
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    return typeof renderer === 'function' ? renderer({ id: 'gateway-shadow-confirmation', action: state.confirmation, tone: 'danger', title: applying ? '应用高可用性配置' : '禁用高可用性', description: applying ? '将启动或重载 keepalived，并可能启动 conntrackd。请确认主备配置、对端信任和预检结果均正确。' : '将停止此控制面管理的 keepalived/conntrackd，并撤销高可用性运行状态。', cancelLabel: '取消', confirmLabel: applying ? '确认应用' : '确认禁用', disabled: Boolean(state.busy) }) : '';
  }

  function renderContent() {
    if (state.loading) return '<section class="shadow-loading" role="status">正在读取高可用性配置...</section>';
    if (state.tab === 'config') return configMarkup();
    if (state.tab === 'pairing') return pairingMarkup();
    return statusMarkup();
  }

  function render() {
    if (!root || !state.mounted) return;
    root.hidden = false; root.className = 'route-preview route-workspace gateway-shadow-route-host';
    root.innerHTML = `<section class="gateway-shadow-shell" data-shadow-version="${VERSION}">${toolbarMarkup()}<main class="gateway-shadow-workbench">${noticeMarkup()}${renderContent()}</main>${confirmationMarkup()}</section>`;
    ui.mountAll?.(root); ui.scheduleAdaptiveForegroundSample?.(20, root);
  }

  function updateField(target) {
    const key = target.dataset.shadowField; if (!key || key === 'auth_key') return;
    const value = target.type === 'checkbox' ? target.checked : target.type === 'number' ? number(target.value, state.draft[key]) : target.value;
    state.draft[key] = value; state.dirty = JSON.stringify(state.draft) !== JSON.stringify(state.config); state.preflight = null;
    syncActionButtons();
  }

  function handleInput(event) {
    const pair = event.target.closest('[data-shadow-pair-input]');
    if (pair) { state.pairing[pair.dataset.shadowPairInput] = pair.value; return; }
    const fieldTarget = event.target.closest('[data-shadow-field]'); if (fieldTarget) updateField(fieldTarget);
  }

  /*
   * 角色分段控件由 Kit 托管激活态，页面只消费它的 change 事件写草稿。
   * 不重绘整页：重绘会把 Kit 刚设置的焦点与 tabIndex 一起丢掉。
   */
  function handleSegmentChange(event) {
    const group = event.target.closest('[data-shadow-role-group]');
    if (!group) return;
    const next = String(event.detail?.value || '');
    if (!next || next === state.draft.role || !writeAllowed('save')) return;
    state.draft.role = next;
    state.dirty = JSON.stringify(state.draft) !== JSON.stringify(state.config);
    state.preflight = null;
    syncActionButtons();
  }

  function syncActionButtons() {
    const apply = root?.querySelector('[data-shadow-confirm="apply"]');
    const preflight = root?.querySelector('[data-shadow-preflight]');
    const save = root?.querySelector('[data-shadow-save]');
    const reset = root?.querySelector('[data-shadow-reset]');
    if (apply) apply.disabled = true;
    if (preflight) preflight.disabled = state.dirty || !writeAllowed('preflight');
    if (save) save.disabled = !state.dirty || !writeAllowed('save');
    if (reset) reset.disabled = !state.dirty;
  }

  async function handleClick(event) {
    const tab = event.target.closest('[data-shadow-tab]'); if (tab) { state.tab = tab.dataset.shadowTab; render(); return; }
    if (event.target.closest('[data-shadow-availability]')) { state.availabilityOpen = !state.availabilityOpen; render(); return; }
    if (event.target.closest('[data-shadow-reset]')) { state.draft = clone(state.config); state.dirty = false; state.preflight = null; render(); return; }
    if (event.target.closest('[data-shadow-save]')) { await saveConfig(); return; }
    if (event.target.closest('[data-shadow-preflight]')) { await runPreflight(); return; }
    const confirm = event.target.closest('[data-shadow-confirm]'); if (confirm) { state.confirmation = confirm.dataset.shadowConfirm; render(); return; }
    if (event.target.closest('[data-dwrt-confirm-accept]')) { const action = state.confirmation; if (action === 'apply') await applyConfig(); else if (action === 'disable') await disableShadow(); return; }
    if (event.target.closest('[data-dwrt-confirm-cancel]')) { state.confirmation = ''; render(); return; }
    const pairing = event.target.closest('[data-shadow-pair]');
    if (pairing) { const action = pairing.dataset.shadowPair; if (action === 'start') await startPairing(); else if (action === 'approve') await approvePairing(); else if (action === 'finalize') await finalizePairing(); else if (action === 'confirm') await confirmPairing(); }
  }

  /*
   * 手动刷新按钮已按用户第 9 条删除，这里补一条可见性受控的轮询：
   * 有草稿改动、预检结果或确认弹窗时跳过，避免把用户正在填的内容刷掉。
   */
  function startPolling() {
    stopPolling();
    state.pollTimer = window.setInterval(() => {
      if (!state.mounted) return;
      if (document.hidden) return;
      if (state.loading || state.refreshing || state.busy) return;
      if (state.dirty || state.preflight || state.confirmation) return;
      load(true);
    }, 15000);
  }

  function stopPolling() {
    if (!state.pollTimer) return;
    window.clearInterval(state.pollTimer);
    state.pollTimer = 0;
  }

  root?.addEventListener('input', handleInput); root?.addEventListener('change', handleInput); root?.addEventListener('click', handleClick);
  root?.addEventListener('dwrt-segment-change', handleSegmentChange);
  stage?.classList.add('is-gateway-shadow'); render(); load(); startPolling();

  return { unmount() { state.mounted = false; stopPolling(); clearPairingSecrets(); state.pairing.offer = ''; state.pairing.acceptance = ''; state.pairing.confirmation = ''; root?.removeEventListener('input', handleInput); root?.removeEventListener('change', handleInput); root?.removeEventListener('click', handleClick); root?.removeEventListener('dwrt-segment-change', handleSegmentChange); stage?.classList.remove('is-gateway-shadow'); root?.classList.remove('gateway-shadow-route-host'); } };
}
