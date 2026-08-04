/*
 * 终端联网控制（MAC 断网管控）
 *
 * 数据面事实（已在 30.1 实测，勿凭页面命名猜测）：
 *   - 真身是 config.db `network_control_rule` + `network_control_mac_rule`，运行态是
 *     **nftables**，不是 DHCP 拒绝。所以对静态 IP、以及不走 DHCP 的 IPv6-only 终端同样有效。
 *   - REST 入口是 Policy Engine 的策略表：`/api/v1/policy-engine/policy-table`，
 *     写入需 `policy_type=acl` + `acl_type=mac`，且必须显式 `apply=true`
 *     （后端 `dry_run_default=true`，不带 apply 只回 409 预览，不改任何东西）。
 *   - `authentication/web/access-rules` 是 WEB 认证门户的放行规则，与本页无关，不要接。
 *
 * 后端明确不支持、因此本页不做假控件的三项（capability 原文见 renderShell 里的说明区）：
 *   - 白名单模式：`acl_mac_allow_supported=false`
 *   - 生效时段：`acl_schedule_supported=false`，且写入时 schedule 必须为 always
 *   - 到期时间：`network_control_mac_rule` 没有 expires 字段
 *
 * 安全默认：新建规则一律 `enabled=false`。用户的原话是「我要亲自拉黑」，
 * 所以填完不断网，必须回列表再手动启用一次。
 */
export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const VERSION = '20260804-mac-network-control-01';
  const stage = root?.closest('.console-stage');
  const POLICY_TABLE = '/api/v1/policy-engine/policy-table';
  const MAC_ID_PREFIX = 'network_control.mac.';

  const state = {
    mounted: true,
    seq: 0,
    pollTimer: 0,
    loading: true,
    refreshing: false,
    saving: false,
    clients: [],
    capabilities: {},
    rules: [],
    query: '',
    filter: 'all',
    error: '',
    notice: '',
    noticeTone: '',
    drawer: false,
    editor: {},
    confirm: null
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

  function asArray(value) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of ['clients', 'rows', 'items', 'list', 'results']) if (Array.isArray(value[key])) return value[key];
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

  /* 会话闸门：内部处理 ensureFresh -> 401 -> refresh -> 单次重试，避免 token 过期时并发 401。 */
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
      error.payload = json;
      throw error;
    }
    return payload;
  }

  function normalizeMac(value) {
    const compact = String(value || '').trim().replace(/[^0-9a-f]/gi, '').toUpperCase();
    return compact.length === 12 ? compact.match(/.{2}/g).join(':') : '';
  }

  /* 随机化 MAC：第一字节的本地管理位（bit 1）置位。这类终端厂商字段通常为空，需在选择器里标出来。 */
  function isRandomizedMac(mac) {
    const head = parseInt(String(mac || '').slice(0, 2), 16);
    return Number.isFinite(head) ? Boolean(head & 0x02) : false;
  }

  function normalizeClient(item = {}, index = 0) {
    const fingerprint = item.fingerprint && typeof item.fingerprint === 'object' ? item.fingerprint : {};
    const mac = normalizeMac(firstText(item.mac, item.client_mac, item.hwaddr));
    const ipv4 = firstText(item.ip, item.ipv4, item.ipaddr);
    /* `0.0.0.0` 与空串都表示没有 IPv4 租约；IPv6-only 终端就是这种，仍要能选中。 */
    const hasIpv4 = Boolean(ipv4) && ipv4 !== '0.0.0.0';
    const ipv6 = firstText(item.ipv6, item.global_ipv6, item.ipv6_global, item.lan_ipv6);
    return {
      mac,
      id: firstText(item.id, mac, `client-${index + 1}`),
      name: firstText(item.custom_name, item.display_name, item.device_name, item.name, item.hostname, fingerprint.model, item.model, mac, '未命名终端'),
      vendor: firstText(item.vendor, item.vendor_name, item.oui),
      ipv4: hasIpv4 ? ipv4 : '',
      ipv6,
      online: bool(item.online, bool(item.active, false)),
      randomized: isRandomizedMac(mac)
    };
  }

  /* 终端定位文本。IPv4 缺失时退到 IPv6，两者都无时说明原因，不要显示 0.0.0.0。 */
  function clientLocator(client = {}) {
    if (client.ipv4) return client.ipv4;
    if (client.ipv6) return `${client.ipv6}（仅 IPv6）`;
    return '无 IP 租约';
  }

  function canWriteMac(capabilities = {}) {
    return capabilities.acl_write === true
      && Array.isArray(capabilities.acl_write_supported_types)
      && capabilities.acl_write_supported_types.includes('mac');
  }

  function whitelistBlockedReason(capabilities = {}) {
    if (capabilities.acl_mac_allow_supported === true) return '';
    return firstText(capabilities.acl_mac_allow_reason, '后端未声明 MAC 放行能力');
  }

  function scheduleBlockedReason(capabilities = {}) {
    if (capabilities.acl_schedule_supported === true) return '';
    return `后端 acl_schedule_mode=${firstText(capabilities.acl_schedule_mode, 'always')}，规则只能始终生效`;
  }

  function rawIdOf(policyId) {
    const text = String(policyId || '');
    return text.startsWith(MAC_ID_PREFIX) ? text.slice(MAC_ID_PREFIX.length) : '';
  }

  function normalizeRule(row = {}, clientsByMac, index = 0) {
    const raw = row.raw && typeof row.raw === 'object' ? row.raw : {};
    const policyId = firstText(row.id, raw.id);
    const rawId = rawIdOf(policyId) || firstText(raw.id, `mac-${index + 1}`);
    const mac = normalizeMac(firstText(raw.mac, raw.source_mac, raw.source, row.source));
    const client = clientsByMac.get(mac) || null;
    return {
      policyId,
      rawId,
      mac,
      client,
      clientName: firstText(raw.terminal_name, client?.name, mac, '未知终端'),
      clientLocator: client ? clientLocator(client) : '不在当前终端列表',
      online: client ? client.online : null,
      name: firstText(raw.name, row.name, rawId),
      remark: firstText(raw.remark, raw.comment),
      enabled: bool(raw.enabled, bool(row.enabled, false)),
      priority: Number(raw.priority ?? 1000),
      mode: firstText(raw.mode, 'deny'),
      hits: Number(raw.hits ?? 0),
      lastHit: Number(raw.last_hit ?? 0)
    };
  }

  function icon(name) {
    const paths = {
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      edit: '<path d="m4 20 4.2-1 10.9-10.9a2 2 0 0 0-2.8-2.8L5.4 16.2 4 20Z"></path>',
      trash: '<path d="M4 7h16M9 7V4h6v3m-9 0 1 13h10l1-13M10 11v5m4-5v5"></path>',
      /* 启停两态用同一 24 视框的几何图形，宽度固定，切换时整行动作区不位移。 */
      pause: '<path d="M9 5v14M15 5v14"></path>',
      play: '<path d="M8 5l11 7-11 7Z"></path>',
      shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6Z"></path><path d="m9 12 2 2 4-4"></path>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.edit}</svg>`;
  }

  function statusBadge(label, tone) {
    return ui.statusBadgeMarkup?.(label, tone) || `<span class="cnc-status is-${escapeHtml(tone)}">${escapeHtml(label)}</span>`;
  }

  function ruleStatus(rule) {
    if (rule.enabled) return { label: '断网中', tone: 'error', detail: 'nftables 已丢弃该 MAC 流量' };
    return { label: '未启用', tone: 'warning', detail: '规则已保存，尚未进入运行态' };
  }

  function lastHitText(rule) {
    if (!rule.lastHit) return '暂无命中';
    const date = new Date(rule.lastHit * 1000);
    if (Number.isNaN(date.getTime())) return '暂无命中';
    const pad = (value) => String(value).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  function filteredRules() {
    const query = state.query.trim().toLowerCase();
    return state.rules.filter((rule) => {
      if (state.filter === 'enabled' && !rule.enabled) return false;
      if (state.filter === 'disabled' && rule.enabled) return false;
      if (state.filter === 'offlist' && rule.client) return false;
      if (!query) return true;
      return [rule.name, rule.mac, rule.clientName, rule.clientLocator, rule.remark]
        .filter(Boolean).join(' ').toLowerCase().includes(query);
    });
  }

  function modeMarkup() {
    const blocked = whitelistBlockedReason(state.capabilities);
    return `<section class="user-auth-main-surface cnc-mode-card dwrt-kit-glass-surface">
      <header class="cnc-mode-head"><span class="cnc-mode-icon" aria-hidden="true">${icon('shield')}</span><div><strong>管控模式</strong><small>规则按 MAC 匹配，运行态为 nftables 丢弃，对静态 IP 与不走 DHCP 的 IPv6 终端同样生效</small></div></header>
      <div class="cnc-mode-options" role="radiogroup" aria-label="管控模式">
        <label class="cnc-mode-option is-active"><input type="radio" name="cnc-mode" value="black" checked><span><strong>黑名单模式</strong><small>仅列出的终端禁止联网，其余终端不受影响</small></span></label>
        <label class="cnc-mode-option is-disabled"><input type="radio" name="cnc-mode" value="white" disabled><span><strong>白名单模式</strong><small>后端不支持，原因：${escapeHtml(blocked || '未声明')}</small></span></label>
      </div>
    </section>`;
  }

  function toolbarControls() {
    const canCreate = canWriteMac(state.capabilities) && !state.loading;
    const filters = [['all', '全部'], ['enabled', '断网中'], ['disabled', '未启用'], ['offlist', '不在终端列表']];
    return `<div class="user-auth-table-controls cnc-table-controls"><div class="user-auth-toolbar-leading"><div class="user-auth-segmented">${filters.map(([id, label]) => `<button type="button" data-cnc-filter="${id}" class="${state.filter === id ? 'is-active' : ''}">${label}</button>`).join('')}</div><label class="policy-search policy-search-main" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-cnc-search value="${escapeHtml(state.query)}" placeholder="搜索终端、MAC、规则或备注"></label></div><div class="policy-toolbar-actions"><button class="policy-create-button" type="button" data-cnc-create ${canCreate ? '' : 'disabled'}>${icon('plus')}<span>新建断网规则</span></button></div></div>`;
  }

  function rowMarkup(rule) {
    const status = ruleStatus(rule);
    const writable = canWriteMac(state.capabilities);
    const onlineText = rule.online === null ? '' : (rule.online ? '在线' : '离线');
    return `<tr>
      <td><span class="cnc-stack">${statusBadge(status.label, status.tone)}<small>${escapeHtml(status.detail)}</small></span></td>
      <td class="cnc-client"><span class="cnc-stack"><strong>${escapeHtml(rule.clientName)}</strong><code>${escapeHtml(rule.mac || '—')}</code><span>${escapeHtml([rule.clientLocator, onlineText].filter(Boolean).join(' · '))}</span></span></td>
      <td class="cnc-remark">${escapeHtml(rule.remark || '—')}</td>
      <td><span class="cnc-stack"><strong>${escapeHtml(String(rule.hits))}</strong><small>${escapeHtml(lastHitText(rule))}</small></span></td>
      <td class="cnc-actions"><span class="cnc-actions-inner">
        <button type="button" class="user-auth-icon-button" data-cnc-toggle="${escapeHtml(rule.policyId)}" title="${rule.enabled ? '停用规则（恢复联网）' : '启用规则（立即断网）'}" aria-label="${rule.enabled ? '停用规则' : '启用规则'}" ${writable ? '' : 'disabled'}>${icon(rule.enabled ? 'pause' : 'play')}</button>
        <button type="button" class="user-auth-icon-button" data-cnc-edit="${escapeHtml(rule.policyId)}" title="编辑规则" aria-label="编辑规则" ${writable ? '' : 'disabled'}>${icon('edit')}</button>
        <button type="button" class="user-auth-icon-button is-danger" data-cnc-delete="${escapeHtml(rule.policyId)}" title="删除规则" aria-label="删除规则" ${writable ? '' : 'disabled'}>${icon('trash')}</button>
      </span></td>
    </tr>`;
  }

  function tableMarkup() {
    const rows = filteredRules();
    const body = state.loading
      ? '<tr><td colspan="5" class="dwrt-kit-table-empty">正在读取终端联网控制规则</td></tr>'
      : state.error
        ? `<tr><td colspan="5" class="dwrt-kit-table-empty">${escapeHtml(state.error)}</td></tr>`
        : rows.length
          ? rows.map(rowMarkup).join('')
          : `<tr><td colspan="5" class="dwrt-kit-table-empty">${state.rules.length ? '没有符合当前筛选的规则' : '当前没有任何断网规则，所有终端均可联网'}</td></tr>`;
    return `<section class="user-auth-main-surface user-auth-table-card cnc-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface" data-cnc-table><div class="dwrt-kit-table-toolbar user-auth-table-toolbar-rich"><div class="dwrt-kit-table-title"><strong>断网规则</strong><span>新建的规则默认不启用，需要回列表手动启用后才会断网</span></div><span class="dwrt-kit-table-count">${rows.length} 条</span>${toolbarControls()}</div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table user-auth-table cnc-table"><thead><tr><th>状态</th><th>终端</th><th>备注</th><th>命中</th><th>操作</th></tr></thead><tbody>${body}</tbody></table></div></section>`;
  }

  function capabilityMarkup() {
    const schedule = scheduleBlockedReason(state.capabilities);
    const whitelist = whitelistBlockedReason(state.capabilities);
    const items = [];
    if (whitelist) items.push(`白名单模式不可用：${whitelist}`);
    if (schedule) items.push(`生效时段不可用：${schedule}`);
    items.push('到期时间不可用：network_control_mac_rule 没有 expires 字段，后端无法自动失效');
    items.push('终端分组不可用：MAC 规则的 source 字段写入时会被覆盖为单个 MAC，后端没有分组到规则的绑定合同');
    items.push('本页无法判断哪台终端是你正在使用的设备：后端未提供请求来源 IP/MAC 回显，因此每次启用都会完整列出目标终端供你自己核对');
    return `<section class="user-auth-main-surface cnc-capability-card dwrt-kit-glass-surface"><strong>当前固件的能力边界</strong><ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul></section>`;
  }

  function noticeMarkup() {
    if (!state.notice) return '';
    const tone = ['ok', 'warning', 'error'].includes(state.noticeTone) ? state.noticeTone : 'ok';
    return `<div class="user-auth-notice is-${tone}" data-cnc-notice>${escapeHtml(state.notice)}</div>`;
  }

  function editorField(label, name, value, options = {}) {
    const disabled = options.disabled ? 'disabled' : '';
    let control;
    if (options.type === 'select') {
      const list = options.options || [];
      control = `<select data-cnc-field="${name}" ${disabled}>${list.length ? list.map(([id, text]) => `<option value="${escapeHtml(id)}" ${String(value) === String(id) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('') : '<option value="">没有可选终端</option>'}</select>`;
    } else if (options.type === 'textarea') {
      control = `<textarea data-cnc-field="${name}" rows="2" ${disabled}>${escapeHtml(value ?? '')}</textarea>`;
    } else {
      control = `<input data-cnc-field="${name}" type="${escapeHtml(options.type || 'text')}" value="${escapeHtml(value ?? '')}" ${options.placeholder ? `placeholder="${escapeHtml(options.placeholder)}"` : ''} ${options.min !== undefined ? `min="${options.min}"` : ''} ${options.max !== undefined ? `max="${options.max}"` : ''} ${disabled}>`;
    }
    return `<label class="user-auth-field ${options.wide ? 'is-wide' : ''}"><span>${escapeHtml(label)}</span>${control}${options.help ? `<small>${escapeHtml(options.help)}</small>` : ''}</label>`;
  }

  /* 设备选择器：在线优先，标注厂商/随机化 MAC/无租约，避免用户手抄 MAC。 */
  function clientOptions() {
    const ordered = state.clients.slice().sort((left, right) => {
      if (left.online !== right.online) return left.online ? -1 : 1;
      return left.name.localeCompare(right.name, 'zh-Hans-CN');
    });
    return ordered.map((client) => {
      const tags = [client.online ? '在线' : '离线'];
      if (client.vendor) tags.push(client.vendor);
      if (client.randomized) tags.push('随机 MAC');
      return [client.mac, `${client.name} · ${clientLocator(client)} · ${tags.join('/')}`];
    });
  }

  function drawerMarkup() {
    if (!state.drawer) return '';
    const editor = state.editor;
    const editing = Boolean(editor.policyId);
    const options = clientOptions();
    const manual = editor.source === 'manual' || !options.length;
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-cnc-close aria-label="关闭断网规则编辑"></button><aside class="user-auth-drawer cnc-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" aria-label="${editing ? '编辑断网规则' : '新建断网规则'}"><header class="dwrt-kit-sheet-header"><div><span>CLIENT NETWORK CONTROL</span><strong>${editing ? '编辑断网规则' : '新建断网规则'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-cnc-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body user-auth-drawer-body">
      <div class="user-auth-drawer-section"><strong>规则状态</strong><label class="user-auth-setting-row"><span><strong>立即启用</strong><small>${editing ? '关闭后规则保留但不再断网' : '默认关闭。保存后回列表手动启用，避免填完就把终端断网'}</small></span><span class="user-auth-switch"><input type="checkbox" data-cnc-field="enabled" ${editor.enabled === true ? 'checked' : ''}><i></i></span></label></div>
      ${editing ? '' : `<div class="cnc-source-switch" role="group" aria-label="终端来源"><button type="button" data-cnc-source="list" class="${manual ? '' : 'is-active'}">从终端列表选择</button><button type="button" data-cnc-source="manual" class="${manual ? 'is-active' : ''}">手动填写 MAC</button></div>`}
      <div class="user-auth-form-grid">
        ${editing
          ? editorField('终端 MAC', 'mac', editor.mac, { disabled: true, wide: true, help: 'MAC 是规则身份，编辑时不可更改。需要换终端请新建规则。' })
          : manual
            ? editorField('终端 MAC', 'mac', editor.mac, { wide: true, placeholder: 'AA:BB:CC:DD:EE:FF', help: '支持冒号、连字符或无分隔写法' })
            : editorField('终端', 'mac', editor.mac, { type: 'select', options, wide: true, help: '含离线、随机化 MAC 与仅 IPv6 终端' })}
        ${editorField('规则名称', 'name', editor.name, { wide: true, help: '留空时使用规则 ID' })}
        ${editorField('优先级', 'priority', editor.priority, { type: 'number', min: 1, max: 65535, help: '数值越小越先匹配' })}
        ${editorField('备注', 'remark', editor.remark, { type: 'textarea', wide: true })}
      </div>
      <div class="user-auth-capability">动作固定为拒绝（后端 acl_mac_supported_actions=["deny"]）。生效时段与到期时间当前固件不支持，因此本页不提供这两个控件，规则一经启用即持续生效，直到你手动停用或删除。</div>
      ${state.notice ? noticeMarkup() : ''}
    </div><footer class="dwrt-kit-sheet-footer user-auth-drawer-footer"><span></span><div><button class="policy-secondary" type="button" data-cnc-close>取消</button><button class="policy-primary" type="button" data-cnc-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存规则'}</button></div></footer></aside>`;
  }

  function confirmationMarkup() {
    if (!state.confirm) return '';
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    if (typeof renderer !== 'function') return '';
    return renderer({
      id: 'cnc-confirmation',
      action: 'cnc-confirm',
      tone: state.confirm.tone || 'danger',
      title: state.confirm.title,
      description: state.confirm.description,
      cancelLabel: '取消',
      confirmLabel: state.saving ? '正在执行' : state.confirm.confirmLabel,
      disabled: state.saving
    });
  }

  /*
   * 抽屉与确认弹窗放在独立挂载容器里，不和 <main> 同批 innerHTML 重写：
   * kit 把抽屉搬进 portal 后会记一个宿主存活探针，探针落在容器内部才不会被
   * 页面重绘误判成孤儿而销毁，用户填的内容也就不会被刷掉。
   */
  function renderShell() {
    if (!root) return;
    root.hidden = false;
    root.classList.add('route-workspace', 'user-authentication-route-host', 'client-network-control-route-host');
    root.innerHTML = `<section class="user-auth-shell cnc-shell" data-cnc-version="${VERSION}"><main class="user-auth-workbench cnc-workbench">${noticeMarkup()}${modeMarkup()}${tableMarkup()}${capabilityMarkup()}</main><div class="cnc-overlay-host" data-cnc-overlays></div></section>`;
    renderOverlays();
    ui.mountAll?.(root);
  }

  function renderOverlays() {
    const host = root?.querySelector('[data-cnc-overlays]');
    if (!host) return;
    const markup = `${drawerMarkup()}${confirmationMarkup()}`;
    if (host.dataset.cncOverlayMarkup === markup) return;
    host.dataset.cncOverlayMarkup = markup;
    /* 清空容器关不掉抽屉：kit 已把它搬到 body 级 portal，必须先让 kit 卸载搬走的那份。 */
    releasePortaledOverlays();
    host.innerHTML = markup;
    ui.mountAll?.(host);
  }

  function releasePortaledOverlays() {
    const portal = document.getElementById('dwrtKitSheetPortal');
    if (!portal) return;
    Array.from(portal.children).forEach((node) => {
      if (!node.classList?.contains('dwrt-kit-sheet')) return;
      if (!node.classList.contains('cnc-drawer')) return;
      const overlay = node.previousElementSibling?.classList?.contains('dwrt-kit-sheet-overlay')
        ? node.previousElementSibling
        : null;
      const shim = document.createElement('div');
      portal.insertBefore(shim, node);
      shim.appendChild(node);
      ui.unmount?.(shim);
      shim.remove();
      overlay?.remove();
    });
  }

  function render() {
    if (!root) return;
    const overlayOpen = Boolean(state.drawer || state.confirm);
    const mounted = root.querySelector('[data-cnc-version]');
    if (!overlayOpen || !mounted || !root.querySelector('.dwrt-kit-sheet, [data-dwrt-component="modal"]')) {
      renderShell();
      return;
    }
    patchToolbar();
    patchNotice();
    patchTable();
    renderOverlays();
  }

  function patchToolbar() {
    const current = root?.querySelector('.cnc-table-controls');
    if (!current) return;
    const template = document.createElement('template');
    template.innerHTML = toolbarControls();
    const next = template.content.firstElementChild;
    if (!next) return;
    /* 搜索框正被输入时不要替换它，否则每次刷新都会打断输入并丢焦点。 */
    if (current.contains(document.activeElement)) return;
    current.replaceWith(next);
    ui.mountAll?.(root.querySelector('.cnc-table-controls'));
  }

  function patchNotice() {
    const workbench = root?.querySelector('.cnc-workbench');
    if (!workbench) return;
    const existing = workbench.querySelector('[data-cnc-notice]');
    const markup = noticeMarkup();
    if (!markup) { existing?.remove(); return; }
    const template = document.createElement('template');
    template.innerHTML = markup;
    const next = template.content.firstElementChild;
    if (!next) return;
    if (existing) existing.replaceWith(next);
    else workbench.insertBefore(next, workbench.firstChild);
  }

  function patchTable() {
    const current = root?.querySelector('[data-cnc-table]');
    if (!current) { renderShell(); return; }
    const scroll = current.querySelector('.dwrt-kit-table-scroll');
    const position = { top: scroll?.scrollTop || 0, left: scroll?.scrollLeft || 0 };
    const template = document.createElement('template');
    template.innerHTML = tableMarkup();
    current.replaceWith(template.content.firstElementChild);
    const next = root.querySelector('[data-cnc-table] .dwrt-kit-table-scroll');
    if (next) { next.scrollTop = position.top; next.scrollLeft = position.left; }
    ui.mountAll?.(root.querySelector('[data-cnc-table]'));
  }

  async function load(background = false) {
    const seq = ++state.seq;
    state.error = '';
    if (!background) state.notice = '';
    state.loading = !background;
    state.refreshing = background;
    render();
    try {
      const [policyResult, clientsResult] = await Promise.allSettled([
        requestJson(POLICY_TABLE),
        requestJson('/api/v1/clients')
      ]);
      if (!state.mounted || seq !== state.seq) return;
      if (policyResult.status === 'rejected') throw policyResult.reason;
      const payload = policyResult.value || {};
      state.capabilities = payload.capabilities && typeof payload.capabilities === 'object' ? payload.capabilities : {};
      state.clients = clientsResult.status === 'fulfilled'
        ? asArray(clientsResult.value).map(normalizeClient).filter((client) => client.mac)
        : [];
      const clientsByMac = new Map(state.clients.map((client) => [client.mac, client]));
      const rows = Array.isArray(payload.rows) ? payload.rows : [];
      state.rules = rows
        .filter((row) => String(row?.id || '').startsWith(MAC_ID_PREFIX))
        .map((row, index) => normalizeRule(row, clientsByMac, index));
      state.loading = false;
      state.refreshing = false;
      if (clientsResult.status === 'rejected') {
        state.notice = '终端列表读取失败，现有规则暂按 MAC 显示，设备选择器不可用。';
        state.noticeTone = 'warning';
      } else if (!canWriteMac(state.capabilities)) {
        state.notice = '后端未声明 MAC ACL 写入能力，本页当前只能查看规则。';
        state.noticeTone = 'warning';
      }
      render();
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      state.capabilities = {};
      state.rules = [];
      state.error = [401, 403].includes(Number(error.status))
        ? '当前账号没有读取策略表的权限，无法显示终端联网控制规则。'
        : `读取终端联网控制规则失败：${firstText(error.message, '未知错误')}`;
      render();
    }
  }

  function newEditor(rule = null) {
    const options = clientOptions();
    state.editor = rule
      ? { policyId: rule.policyId, rawId: rule.rawId, mac: rule.mac, name: rule.name, remark: rule.remark, priority: rule.priority, enabled: rule.enabled, source: 'list' }
      : { policyId: '', rawId: '', mac: options[0]?.[0] || '', name: '', remark: '', priority: 1000, enabled: false, source: options.length ? 'list' : 'manual' };
    state.drawer = true;
    state.notice = '';
    renderOverlays();
  }

  function editorPayload() {
    const editor = clone(state.editor);
    return {
      policyId: firstText(editor.policyId),
      mac: normalizeMac(editor.mac),
      name: firstText(editor.name),
      remark: firstText(editor.remark),
      priority: Number(editor.priority) || 1000,
      enabled: editor.enabled === true
    };
  }

  function validation(payload) {
    if (!payload.mac) return 'MAC 地址无效。请从终端列表选择，或填写 12 位十六进制 MAC。';
    if (payload.priority < 1 || payload.priority > 65535) return '优先级需在 1 到 65535 之间。';
    /* MAC 唯一：后端只按规则 ID 判重，同一 MAC 建两条会都写进去且都生效，所以在前端拦住并定位到已有那条。 */
    if (!payload.policyId) {
      const existing = state.rules.find((rule) => rule.mac === payload.mac);
      if (existing) return `该 MAC 已有断网规则「${existing.name}」（${existing.enabled ? '断网中' : '未启用'}）。请直接编辑那一条，不要重复添加。`;
    }
    return '';
  }

  function describeTarget(mac) {
    const client = state.clients.find((item) => item.mac === mac);
    if (!client) return `${mac}（不在当前终端列表，可能已离线或从未接入）`;
    return `${client.name}（${mac}，${clientLocator(client)}，${client.online ? '在线' : '离线'}）`;
  }

  /*
   * 启用即断网，属于不可逆的用户可感知动作，一律走强确认。
   * 后端没有请求来源回显，本页无法判断目标是否就是用户当前这台设备，
   * 所以确认文案把目标终端完整念出来，让用户自己核对。
   */
  function requestEnable(rule) {
    state.confirm = {
      kind: 'enable',
      policyId: rule.policyId,
      tone: 'danger',
      title: '确认让这台终端断网',
      description: `启用后 ${describeTarget(rule.mac)} 将立即无法联网，直到你手动停用或删除这条规则。请先确认这不是你正在使用的设备。`,
      confirmLabel: '确认断网'
    };
    renderOverlays();
  }

  function requestDelete(rule) {
    state.confirm = {
      kind: 'delete',
      policyId: rule.policyId,
      tone: 'danger',
      title: '删除断网规则',
      description: `规则「${rule.name}」将从配置与 nftables 运行态中删除，${describeTarget(rule.mac)} 随后可以正常联网。`,
      confirmLabel: '确认删除'
    };
    renderOverlays();
  }

  /* 写入必须显式 apply=true：后端 dry_run_default=true，不带 apply 只回 409 预览。 */
  function writeBody(extra = {}) {
    return JSON.stringify({ policy_type: 'acl', acl_type: 'mac', apply: true, ...extra });
  }

  async function saveRule() {
    if (state.saving) return;
    const payload = editorPayload();
    const message = validation(payload);
    if (message) { state.notice = message; state.noticeTone = 'warning'; renderOverlays(); return; }
    /* 新建时若直接勾了启用，先强确认再落规则。 */
    if (!payload.policyId && payload.enabled) {
      state.confirm = {
        kind: 'create-enabled',
        tone: 'danger',
        title: '确认保存并立即断网',
        description: `保存后 ${describeTarget(payload.mac)} 会立即无法联网。请先确认这不是你正在使用的设备。`,
        confirmLabel: '确认保存并断网'
      };
      renderOverlays();
      return;
    }
    await commitSave(payload);
  }

  async function commitSave(payload) {
    state.saving = true;
    renderOverlays();
    try {
      const fields = {
        mac: payload.mac,
        name: payload.name || undefined,
        remark: payload.remark,
        priority: payload.priority,
        enabled: payload.enabled,
        action: 'deny'
      };
      if (payload.policyId) {
        await requestJson(`${POLICY_TABLE}/${encodeURIComponent(payload.policyId)}`, { method: 'PATCH', body: writeBody({ operation: 'update', ...fields }) });
      } else {
        await requestJson(POLICY_TABLE, { method: 'POST', body: writeBody({ operation: 'create', ...fields }) });
      }
      state.saving = false;
      state.drawer = false;
      state.confirm = null;
      state.editor = {};
      state.notice = payload.enabled
        ? '规则已保存并启用，该终端现在无法联网。'
        : '规则已保存，当前未启用。需要断网请在列表里手动启用。';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.confirm = null;
      state.notice = `保存失败：${firstText(error.message, '后端未接受规则')}`;
      state.noticeTone = 'error';
      renderOverlays();
      patchNotice();
    }
  }

  async function toggleRule(rule, skipConfirm = false) {
    if (!rule || state.saving || !canWriteMac(state.capabilities)) return;
    if (rule.enabled === false && !skipConfirm) { requestEnable(rule); return; }
    state.saving = true;
    render();
    try {
      await requestJson(`${POLICY_TABLE}/${encodeURIComponent(rule.policyId)}`, {
        method: 'PATCH',
        body: writeBody({ operation: rule.enabled ? 'disable' : 'enable' })
      });
      state.saving = false;
      state.confirm = null;
      state.notice = rule.enabled ? '规则已停用，该终端恢复联网。' : '规则已启用，该终端现在无法联网。';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.confirm = null;
      state.notice = `操作失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  async function deleteRule(rule) {
    if (!rule || state.saving || !canWriteMac(state.capabilities)) return;
    state.saving = true;
    renderOverlays();
    try {
      /* 用 <id>/delete 子路径而不是 DELETE 动词：webd 只对带 body 的写方法解析请求体，
         而 apply=true 必须放在 body 里，否则会落到 dry-run 预览而什么都没删。 */
      await requestJson(`${POLICY_TABLE}/${encodeURIComponent(rule.policyId)}/delete`, {
        method: 'POST',
        body: writeBody({ operation: 'delete' })
      });
      state.saving = false;
      state.confirm = null;
      state.notice = '断网规则已删除，该终端恢复联网。';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.confirm = null;
      state.notice = `删除失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  function findRule(policyId) {
    return state.rules.find((rule) => String(rule.policyId) === String(policyId));
  }

  function acceptConfirmation() {
    const request = state.confirm;
    if (!request) return;
    if (request.kind === 'create-enabled') { commitSave(editorPayload()); return; }
    const rule = findRule(request.policyId);
    if (!rule) { state.confirm = null; renderOverlays(); return; }
    if (request.kind === 'enable') { toggleRule(rule, true); return; }
    if (request.kind === 'delete') { deleteRule(rule); }
  }

  function onClick(event) {
    if (event.target.closest('[data-cnc-close]')) { state.drawer = false; state.editor = {}; state.notice = ''; renderOverlays(); patchNotice(); return; }
    if (event.target.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]')) { state.confirm = null; renderOverlays(); return; }
    if (event.target.closest('[data-dwrt-confirm-accept]')) { acceptConfirmation(); return; }
    if (event.target.closest('[data-cnc-create]')) { newEditor(); return; }
    if (event.target.closest('[data-cnc-save]')) { saveRule(); return; }
    const source = event.target.closest('[data-cnc-source]');
    if (source) { state.editor.source = source.dataset.cncSource; if (state.editor.source === 'manual') state.editor.mac = ''; else state.editor.mac = clientOptions()[0]?.[0] || ''; renderOverlays(); return; }
    const filter = event.target.closest('[data-cnc-filter]');
    if (filter) { state.filter = filter.dataset.cncFilter; patchTable(); return; }
    const toggle = event.target.closest('[data-cnc-toggle]');
    if (toggle) { toggleRule(findRule(toggle.dataset.cncToggle)); return; }
    const edit = event.target.closest('[data-cnc-edit]');
    if (edit) { newEditor(findRule(edit.dataset.cncEdit)); return; }
    const remove = event.target.closest('[data-cnc-delete]');
    if (remove) { const rule = findRule(remove.dataset.cncDelete); if (rule) requestDelete(rule); }
  }

  function updateEditor(target) {
    const key = target.dataset.cncField;
    if (!key) return;
    state.editor[key] = target.type === 'checkbox' ? target.checked : target.type === 'number' ? Number(target.value || 0) : target.value;
  }

  function onInput(event) {
    const search = event.target.closest('[data-cnc-search]');
    if (search) { state.query = search.value; patchTable(); return; }
    const field = event.target.closest('[data-cnc-field]');
    if (field && !['checkbox', 'radio'].includes(field.type) && field.tagName !== 'SELECT') updateEditor(field);
  }

  function onChange(event) {
    const field = event.target.closest('[data-cnc-field]');
    if (field) updateEditor(field);
  }

  function onKeyDown(event) {
    if (event.key !== 'Escape') return;
    if (state.confirm) state.confirm = null;
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

  /* 可见性受控的轮询；有抽屉、确认弹窗或正在保存时跳过，避免刷掉用户填的内容。 */
  state.pollTimer = window.setInterval(() => {
    if (!state.mounted || document.hidden) return;
    if (state.loading || state.refreshing || state.saving) return;
    if (state.drawer || state.confirm) return;
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
      root?.classList.remove('route-workspace', 'user-authentication-route-host', 'client-network-control-route-host');
      stage?.classList.remove('is-user-authentication');
    }
  };
}

export default { mount };
