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
 * 生效时段（2026-08-08 复核，能力位与源码一致，30.1 实测同）：
 *   - `acl_schedule_supported=true`、`acl_schedule_mode=always_or_single_window`，
 *     `acl_schedule_max_windows=1`，星期可选，时基是**设备本地时间**（不是浏览器时区）。
 *   - 存储与写入格式都是 JSON 字符串：
 *     `[{"weekdays":[1,2,3,4,5],"start_time":"18:00","end_time":"22:00"}]`，
 *     或 `"always"`。校验（`jmx_app_api.c` webd_policy_acl_schedule_ok）严格对齐 nft
 *     生成器能表达的范围，能存进去的就一定生效，所以本页做真控件。
 *   - 起止相同会被拒（空窗口永不匹配）；一条规则只能有一个时间窗。
 *
 * 到期时间（expires）：读写都已打通（后端 2026-08-09 补齐写侧，本页同日接上控件）。
 *   - 读侧：`network_control_rule.expires`（父表，不在 mac 子表上）随行回读，并附
 *     `expired` 布尔；nft 生成器按 `expires=0 OR expires>now` 过滤，过期规则保留行、
 *     停止生效（`acl_expires_retains_rule=true`）。
 *   - 写侧：`expires` 已进入 `webd_policy_acl_copy_body_fields()` 白名单，放在请求体
 *     **顶层**（与 `schedule` 平级，不在 mac 子对象里），单位是**绝对 Unix 秒**，
 *     `0` 表示永不过期（`acl_expires_unit=absolute_unix_seconds`）。
 *   - 「过去的时间戳」只对本次请求体显式传入的值报 400；已过期规则继承的旧值不再重新
 *     校验，所以对 `expired:true` 的规则点启用/停用/改备注都不会被拒。
 *   - 写入成功的响应带 `expires`/`expired`，且 `expires<=now` 时附 `expires_warning`：
 *     这表示**存进去了但生成器仍会跳过它**，只看 `applied` 会误判成已生效，因此本页
 *     把这种情况按警告文案展示。
 *   - 时基是**设备本地时间**：控件里填的墙上时间按设备时区（`/api/v1/system/basic`
 *     的 `general.timezone`）换算成 Unix 秒，不用浏览器时区，否则跨时区会差几个小时。
 *   - 到期**不会自动恢复联网**：生成器过滤是对的，但没有周期性 ruleset 重建，要等下一次
 *     apply 才真正放行。缺陷已提给后端
 *     （`HandoffWorker-to-Backend-acl-expires-no-periodic-ruleset-rebuild.md`），
 *     所以本页文案不承诺「到点自动恢复」。
 *
 * 白名单模式（2026-08-18）：
 *   - `acl_mac_allow_supported=true` 时使用真实的 `network_control_whitelist(kind='mac')`。
 *   - 成员通过 `/api/v1/network-control/mac-allowlist/members` 整体替换；模式启用期间成员
 *     只读，需先停用再编辑，避免普通成员操作直接改变整个 LAN 的可达性。
 *   - 启用 `/api/v1/network-control/mac-allowlist` 后必须在倒计时内调用 `/confirm`，
 *     否则后端自动回滚；空名单禁止启用，当前管理会话来源由后端自动加入名单。
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
  const VERSION = '20260822-terminal-policy-savebar-24';
  const embedded = context.embedded === true;
  const parentDraftController = context.enabledDraftController || null;
  const stage = root?.closest('.console-stage');
  const modeHost = context.modeHost || null;
  const POLICY_TABLE = '/api/v1/policy-engine/policy-table';
  const ALLOWLIST = '/api/v1/network-control/mac-allowlist';
  const ALLOWLIST_MEMBERS = `${ALLOWLIST}/members`;
  const ALLOWLIST_CONFIRM = `${ALLOWLIST}/confirm`;
  const MAC_ID_PREFIX = 'network_control.mac.';

  const state = {
    mounted: true,
    seq: 0,
    pollTimer: 0,
    countdownTimer: 0,
    loading: true,
    refreshing: false,
    saving: false,
    clients: [],
    capabilities: {},
    rules: [],
    mode: 'black',
    allowlist: {},
    allowlistMembers: [],
    allowlistDraft: [],
    allowlistDirty: false,
    allowlistLoaded: false,
    requestOrigin: null,
    deviceTimezone: '',
    query: '',
    filter: 'all',
    error: '',
    notice: '',
    noticeTone: '',
    drawer: false,
    editor: {},
    confirm: null
  };
  const localEnabledBaseline = new Map();
  const localEnabledDraft = new Map();

  function ruleEnabled(rule) {
    return parentDraftController
      ? parentDraftController.value('network', rule.policyId, rule.enabled)
      : localEnabledDraft.has(rule.policyId) ? localEnabledDraft.get(rule.policyId) : Boolean(rule.enabled);
  }

  function enabledDirty(rule) {
    return parentDraftController
      ? parentDraftController.dirty('network', rule.policyId)
      : localEnabledDraft.has(rule.policyId);
  }

  function localEnabledChanges() {
    return Array.from(localEnabledDraft.entries()).filter(([id, enabled]) => localEnabledBaseline.get(id) !== enabled);
  }

  function localSavebarMarkup() {
    if (parentDraftController || embedded) return '';
    const changes = localEnabledChanges();
    return ui.floatingSavebarMarkup?.({
      visible: changes.length > 0 || state.saving,
      message: state.saving ? '正在保存 MAC 断网状态…' : `${changes.length} 条断网规则状态待保存`,
      busy: state.saving,
      disabled: !changes.length,
      discardLabel: '撤销更改',
      saveLabel: '保存并应用'
    }) || '';
  }

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

  function allowlistSupported() {
    return !whitelistBlockedReason(state.capabilities);
  }

  function normalizeAllowlist(payload = {}) {
    const source = payload.mac_allowlist && typeof payload.mac_allowlist === 'object'
      ? payload.mac_allowlist : {};
    return {
      enabled: bool(source.enabled, false),
      confirmed: bool(source.confirmed, false),
      confirmDeadline: Number(source.confirm_deadline || 0),
      confirmSecondsRemaining: Number(source.confirm_seconds_remaining || 0),
      elementCount: Number(source.element_count || 0),
      adminMac: normalizeMac(source.admin_mac),
      lastReason: firstText(source.last_reason),
      mode: firstText(source.mode, 'ether_saddr_not_in_set_drop'),
      enforcementHook: firstText(source.enforcement_hook, 'forward_lan_ingress_only'),
      enforcementIfname: firstText(source.enforcement_iifname, 'br-lan')
    };
  }

  function normalizeAllowlistMembers(payload = {}) {
    const items = Array.isArray(payload.members) ? payload.members : [];
    return Array.from(new Set(items.map(normalizeMac).filter(Boolean))).sort();
  }

  function allowlistPending() {
    return state.allowlist.enabled === true && state.allowlist.confirmed !== true;
  }

  function allowlistSecondsRemaining() {
    const deadline = Number(state.allowlist.confirmDeadline || 0);
    if (!allowlistPending()) return 0;
    if (deadline > 0) return Math.max(0, deadline - Math.floor(Date.now() / 1000));
    return Math.max(0, Number(state.allowlist.confirmSecondsRemaining || 0));
  }

  function allowlistMemberClient(mac) {
    return state.clients.find((client) => client.mac === mac) || null;
  }

  function scheduleBlockedReason(capabilities = {}) {
    if (capabilities.acl_schedule_supported === true) return '';
    return `后端 acl_schedule_mode=${firstText(capabilities.acl_schedule_mode, 'always')}，规则只能始终生效`;
  }

  /*
   * 到期时间能力位。读写共用同一个位：后端补齐写侧时没有新增第二个能力位，
   * 单位由 acl_expires_unit 声明，只有确认是绝对 Unix 秒才给输入框；若以后改成
   * 别的语义（比如相对秒数），这里自动退回只读展示，不猜。
   */
  function expiresReadable(capabilities = {}) {
    return capabilities.acl_expires_supported === true;
  }
  function expiresWritable(capabilities = {}) {
    return expiresReadable(capabilities)
      && canWriteMac(capabilities)
      && firstText(capabilities.acl_expires_unit, 'absolute_unix_seconds') === 'absolute_unix_seconds';
  }

  /*
   * 设备时区换算。到期时间的时基是设备本地时间，而 <input type="datetime-local">
   * 给出的是一串没有时区的墙上时间，直接 new Date() 会按**浏览器**时区解释：
   * 在 UTC+0 的机器上给一台 UTC+8 的路由器填 22:00，会写成设备的次日 06:00。
   * 所以显式用设备时区（/api/v1/system/basic 的 general.timezone）换算。
   */
  function deviceTimezone() {
    return firstText(state.deviceTimezone);
  }

  /* 某个瞬间在指定时区下的 UTC 偏移（秒）。时区名不被 Intl 认识时返回 null。 */
  function zoneOffsetSeconds(timeZone, date) {
    try {
      const parts = new Intl.DateTimeFormat('en-US', {
        timeZone, hour12: false,
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit'
      }).formatToParts(date).reduce((acc, part) => {
        if (part.type !== 'literal') acc[part.type] = Number(part.value);
        return acc;
      }, {});
      if (!Number.isFinite(parts.year) || !Number.isFinite(parts.hour)) return null;
      /* hour12:false 在部分实现里把零点给成 24，Date.UTC 接受它并进位到次日，语义一致。 */
      const asUtc = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second);
      return Math.round((asUtc - date.getTime()) / 1000);
    } catch (_) {
      return null;
    }
  }

  /*
   * "YYYY-MM-DDTHH:MM"（设备墙上时间）-> Unix 秒。
   * 偏移本身随时刻变化（夏令时），所以先用墙上时间当 UTC 求一个候选瞬间，再用该瞬间的
   * 真实偏移复算；两轮足够收敛，DST 跳变边界上也不会偏出一小时以上。
   * 拿不到设备时区时退回浏览器时区，并由 UI 文案说明这一降级。
   */
  function localInputToEpoch(text) {
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(String(text || '').trim());
    if (!match) return 0;
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    const wallAsUtc = Date.UTC(year, month - 1, day, hour, minute, 0);
    if (!Number.isFinite(wallAsUtc)) return 0;
    const zone = deviceTimezone();
    if (!zone) {
      const local = new Date(year, month - 1, day, hour, minute, 0);
      return Number.isNaN(local.getTime()) ? 0 : Math.floor(local.getTime() / 1000);
    }
    let epochMs = wallAsUtc;
    for (let pass = 0; pass < 2; pass += 1) {
      const offset = zoneOffsetSeconds(zone, new Date(epochMs));
      if (offset === null) return Math.floor(wallAsUtc / 1000);
      epochMs = wallAsUtc - offset * 1000;
    }
    return Math.floor(epochMs / 1000);
  }

  /* 反向：Unix 秒 -> 设备墙上时间 "YYYY-MM-DDTHH:MM"，供 datetime-local 回填。 */
  function epochToLocalInput(seconds) {
    const value = Number(seconds) || 0;
    if (value <= 0) return '';
    const date = new Date(value * 1000);
    if (Number.isNaN(date.getTime())) return '';
    const zone = deviceTimezone();
    const offset = zone ? zoneOffsetSeconds(zone, date) : null;
    const shifted = offset === null
      ? new Date(date.getTime() - date.getTimezoneOffset() * 60000)
      : new Date(date.getTime() + offset * 1000);
    return Number.isNaN(shifted.getTime()) ? '' : shifted.toISOString().slice(0, 16);
  }

  /*
   * 分组绑定：后端把 source_kind:"group" + source_ref:<terminal_group_id> 在应用时
   * 展开成每个成员 MAC。能力位在后端部署到设备之前查不到，所以这里一律按能力位判断，
   * 不硬编码「已支持」。
   */
  function groupBindingSupported(capabilities = {}) {
    return capabilities.acl_mac_group_binding_supported === true
      && Array.isArray(capabilities.acl_mac_source_kinds)
      && capabilities.acl_mac_source_kinds.includes('group');
  }
  /*
   * 成员变化不会立刻重新拦截，要等下一次 apply/reload_rules（acl_mac_group_recompute）。
   * 文案不能暗示「改完组就已经拦上了」。
   */
  function groupRecomputeHint(capabilities = {}) {
    return firstText(capabilities.acl_mac_group_recompute, 'network_control_apply_or_reload_rules') === 'network_control_apply_or_reload_rules'
      ? '分组成员变化在下一次应用规则后生效'
      : `分组成员变化的重算时机：${firstText(capabilities.acl_mac_group_recompute)}`;
  }
  /*
   * 一条「拦不到任何设备」的分组规则，在列表里和一条正常生效的规则长得一模一样。
   * 不显式提示就会被读成已生效，所以这两种状态必须出文案。
   */
  const GROUP_RUNTIME_WARNINGS = {
    terminal_group_has_no_member_mac_rule_blocks_nothing: '该分组当前没有成员，这条规则拦不到任何设备',
    bound_terminal_group_missing_rule_blocks_nothing: '绑定的分组已被删除，这条规则拦不到任何设备'
  };
  function groupRuleWarning(rule) {
    if (rule.sourceKind !== 'group') return '';
    const mapped = GROUP_RUNTIME_WARNINGS[rule.runtimeWarning];
    if (mapped) return mapped;
    if (rule.groupExists === false) return '绑定的分组已被删除，这条规则拦不到任何设备';
    if (Number(rule.groupMemberMacs) === 0) return '该分组当前没有成员，这条规则拦不到任何设备';
    return '';
  }

  /*
   * 自锁防护：只有后端明确声明 self_lockout_check_supported 且解析出了 MAC 时才算可用。
   */
  function selfDeviceCheckSupported() {
    const origin = state.requestOrigin;
    return Boolean(origin)
      && origin.self_lockout_check_supported === true
      && origin.client_mac_resolved === true
      && Boolean(firstText(origin.client_mac));
  }
  /*
   * 判据必须用 self_lockout_match_field 指定的 peer_ip：client_ip 在 TCP peer 为回环
   * （经 nginx 反代）时会被 X-Forwarded-For 顶掉，拿它做自锁防护会让防护本身变成绕过
   * 路径。后端把这件事写在 self_lockout_match_reason 里。
   */
  function isSelfDevice(mac) {
    if (!selfDeviceCheckSupported()) return false;
    const origin = state.requestOrigin;
    if (firstText(origin.self_lockout_match_field, 'peer_ip') !== 'peer_ip') return false;
    const target = normalizeMac(mac);
    return Boolean(target) && normalizeMac(origin.client_mac) === target;
  }

  const WEEKDAY_LABELS = ['日', '一', '二', '三', '四', '五', '六'];

  function hhmmOk(value) {
    const text = String(value || '');
    if (!/^\d{2}:\d{2}$/.test(text)) return false;
    const hour = Number(text.slice(0, 2));
    const minute = Number(text.slice(3, 5));
    if (hour === 24) return minute === 0;
    return hour <= 23 && minute <= 59;
  }

  /*
   * schedule 在后端是字符串：`"always"` 或单窗口 JSON 数组。回读时两种都可能出现
   * （历史行也可能是空串），统一解析成编辑器用的扁平结构。
   */
  function parseSchedule(value) {
    const text = String(value ?? '').trim();
    if (!text || text === 'always') return { mode: 'always', start: '22:00', end: '23:00', weekdays: [] };
    let parsed = null;
    try { parsed = JSON.parse(text); } catch (_) { parsed = null; }
    const entry = Array.isArray(parsed) ? parsed[0] : null;
    if (!entry || typeof entry !== 'object') return { mode: 'always', start: '22:00', end: '23:00', weekdays: [], invalid: text };
    const weekdays = Array.isArray(entry.weekdays)
      ? entry.weekdays.map((day) => Number(day)).filter((day) => Number.isInteger(day) && day >= 0 && day <= 6)
      : [];
    return {
      mode: 'window',
      start: hhmmOk(entry.start_time) ? String(entry.start_time) : '22:00',
      end: hhmmOk(entry.end_time) ? String(entry.end_time) : '23:00',
      weekdays: Array.from(new Set(weekdays)).sort((left, right) => left - right)
    };
  }

  /* 反向：编辑器结构 -> 后端接受的 schedule 字符串。 */
  function formatSchedule(editor = {}) {
    if (editor.scheduleMode !== 'window') return 'always';
    const weekdays = Array.isArray(editor.scheduleDays)
      ? Array.from(new Set(editor.scheduleDays.map((day) => Number(day)).filter((day) => Number.isInteger(day) && day >= 0 && day <= 6))).sort((left, right) => left - right)
      : [];
    const entry = { start_time: editor.scheduleStart, end_time: editor.scheduleEnd };
    /* 七天全选等于没有星期限制，后端也会忽略，省掉这个字段让存储更干净。 */
    if (weekdays.length && weekdays.length < 7) entry.weekdays = weekdays;
    return JSON.stringify([entry]);
  }

  /* 时间窗人话化。跨零点由 nft 的 meta hour 区间语义决定，这里如实标出来。 */
  function scheduleText(rule) {
    const schedule = rule.schedule || { mode: 'always' };
    if (schedule.mode !== 'window') return '始终生效';
    const days = schedule.weekdays.length && schedule.weekdays.length < 7
      ? `周${schedule.weekdays.map((day) => WEEKDAY_LABELS[day]).join('、')}`
      : '每天';
    return `${days} ${schedule.start}-${schedule.end}`;
  }

  function expiresText(rule) {
    if (!rule.expires) return '永不过期';
    /* 到期时间按设备本地时间显示，与写入时的时基一致；否则同一条规则读写两个时刻。 */
    const stamp = epochToLocalInput(rule.expires).replace('T', ' ');
    if (!stamp) return '永不过期';
    return rule.expired ? `已于 ${stamp} 失效` : `${stamp} 到期`;
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
      lastHit: Number(raw.last_hit ?? 0),
      schedule: parseSchedule(raw.schedule),
      /*
       * 分组绑定的回显。source_kind 缺失时按 'mac' 处理：旧固件没有这个字段，
       * 不能把老规则当成分组规则。
       */
      sourceKind: firstText(raw.source_kind, 'mac'),
      sourceRef: firstText(raw.source_ref),
      groupExists: raw.group_exists === undefined ? null : bool(raw.group_exists, false),
      groupMemberMacs: raw.group_member_macs === undefined ? null : Number(raw.group_member_macs ?? 0),
      runtimeWarning: firstText(raw.runtime_warning),
      /* expires 在父表 network_control_rule 上，随策略表行回读，0 表示永不过期。 */
      expires: Number(raw.expires ?? 0) || 0,
      expired: bool(raw.expired, Number(raw.expires ?? 0) > 0 && Number(raw.expires) * 1000 <= Date.now())
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
    const enabled = ruleEnabled(rule);
    /*
     * 已启用但已过期的规则不再进入 nft（生成器按 expires 过滤），行还留着。
     * 必须和「断网中」区分开，否则用户会以为终端仍被拦着。
     */
    if (enabledDirty(rule)) return { label: enabled ? '待启用' : '待停用', tone: 'warning', detail: '尚未保存，不会立即改变终端联网状态' };
    if (enabled && rule.expired) return { label: '已失效', tone: 'warning', detail: '已到期，规则保留但不再拦截，可改期后重新启用' };
    if (enabled && rule.schedule.mode === 'window') return { label: '按时段断网', tone: 'error', detail: `仅 ${scheduleText(rule)} 拦截（设备本地时间）` };
    if (enabled) return { label: '断网中', tone: 'error', detail: 'nftables 已丢弃该 MAC 流量' };
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
      const enabled = ruleEnabled(rule);
      if (state.filter === 'enabled' && (!enabled || rule.expired)) return false;
      if (state.filter === 'disabled' && enabled) return false;
      if (state.filter === 'expired' && !rule.expired) return false;
      if (state.filter === 'offlist' && rule.client) return false;
      if (!query) return true;
      return [rule.name, rule.mac, rule.clientName, rule.clientLocator, rule.remark, scheduleText(rule)]
        .filter(Boolean).join(' ').toLowerCase().includes(query);
    });
  }

  function modeMarkup() {
    const blocked = whitelistBlockedReason(state.capabilities);
    return `<div class="cnc-mode-capsule" role="radiogroup" aria-label="MAC 管控模式"><button type="button" class="cnc-mode-pill ${state.mode === 'black' ? 'is-active' : ''}" data-cnc-mode="black" aria-checked="${state.mode === 'black' ? 'true' : 'false'}" data-dwrt-tooltip="仅列出的终端禁止联网"><span aria-hidden="true">${icon('shield')}</span>黑名单</button><button type="button" class="cnc-mode-pill ${state.mode === 'white' ? 'is-active' : ''} ${blocked ? 'is-disabled' : ''}" data-cnc-mode="white" aria-checked="${state.mode === 'white' ? 'true' : 'false'}" ${blocked ? 'disabled' : ''} data-dwrt-tooltip="${escapeHtml(blocked || '仅名单内终端可访问互联网')}"><span aria-hidden="true">${icon('shield')}</span>白名单</button></div>`;
  }

  function toolbarControls() {
    const canCreate = canWriteMac(state.capabilities) && !state.loading;
    const filters = [['all', '全部'], ['enabled', '生效中'], ['disabled', '未启用'], ['expired', '已失效'], ['offlist', '不在终端列表']];
    return `<div class="user-auth-table-controls cnc-table-controls"><div class="user-auth-toolbar-leading"><div class="user-auth-segmented">${filters.map(([id, label]) => `<button type="button" data-cnc-filter="${id}" class="${state.filter === id ? 'is-active' : ''}">${label}</button>`).join('')}</div><label class="policy-search policy-search-main" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-cnc-search value="${escapeHtml(state.query)}" placeholder="搜索终端、MAC、规则或备注"></label></div><div class="policy-toolbar-actions"><button class="policy-create-button" type="button" data-cnc-create ${canCreate ? '' : 'disabled'}>${icon('plus')}<span>新建断网规则</span></button></div></div>`;
  }

  function rowMarkup(rule) {
    const status = ruleStatus(rule);
    const enabled = ruleEnabled(rule);
    const dirty = enabledDirty(rule);
    const writable = canWriteMac(state.capabilities);
    const onlineText = rule.online === null ? '' : (rule.online ? '在线' : '离线');
    /*
     * 分组规则不绑定单个 MAC，终端列显示组与成员数；拦不到设备时必须出警示，
     * 否则它和一条正常生效的规则在列表里没有区别。
     */
    const groupWarning = groupRuleWarning(rule);
    const isGroup = rule.sourceKind === 'group';
    const groupCell = `<span class="cnc-stack"><strong>${escapeHtml(`分组 ${firstText(rule.sourceRef, '未知分组')}`)}</strong><span>${escapeHtml(rule.groupMemberMacs === null ? '成员数未知' : `该组 ${rule.groupMemberMacs} 台设备`)}</span>${groupWarning ? `<small class="cnc-group-warning">${escapeHtml(groupWarning)}</small>` : ''}</span>`;
    const selfTag = isSelfDevice(rule.mac) ? '<small class="cnc-self-device">你正在使用的设备</small>' : '';
    return `<tr class="${dirty ? 'is-dirty' : ''}">
      <td><span class="cnc-stack">${statusBadge(status.label, status.tone)}<small>${escapeHtml(status.detail)}</small></span></td>
      <td class="cnc-client">${isGroup ? groupCell : `<span class="cnc-stack"><strong>${escapeHtml(rule.clientName)}</strong><code>${escapeHtml(rule.mac || '—')}</code><span>${escapeHtml([rule.clientLocator, onlineText].filter(Boolean).join(' · '))}</span>${selfTag}</span>`}</td>
      <td class="cnc-schedule"><span class="cnc-stack"><strong>${escapeHtml(scheduleText(rule))}</strong><small>${escapeHtml(expiresText(rule))}</small></span></td>
      <td class="cnc-remark">${escapeHtml(rule.remark || '—')}</td>
      <td><span class="cnc-stack"><strong>${escapeHtml(String(rule.hits))}</strong><small>${escapeHtml(lastHitText(rule))}</small></span></td>
      <td class="cnc-actions"><span class="cnc-actions-inner">
        <button type="button" class="user-auth-icon-button" data-cnc-toggle="${escapeHtml(rule.policyId)}" title="${enabled ? '暂存停用规则' : '暂存启用规则'}" aria-label="${enabled ? '暂存停用规则' : '暂存启用规则'}" ${writable ? '' : 'disabled'}>${icon(enabled ? 'pause' : 'play')}</button>
        <button type="button" class="user-auth-icon-button" data-cnc-edit="${escapeHtml(rule.policyId)}" title="编辑规则" aria-label="编辑规则" ${writable ? '' : 'disabled'}>${icon('edit')}</button>
        <button type="button" class="user-auth-icon-button is-danger" data-cnc-delete="${escapeHtml(rule.policyId)}" title="删除规则" aria-label="删除规则" ${writable ? '' : 'disabled'}>${icon('trash')}</button>
      </span></td>
    </tr>`;
  }

  function tableMarkup() {
    const rows = filteredRules();
    const body = state.loading
      ? '<tr><td colspan="6" class="dwrt-kit-table-empty">正在读取终端联网控制规则</td></tr>'
      : state.error
        ? `<tr><td colspan="6" class="dwrt-kit-table-empty">${escapeHtml(state.error)}</td></tr>`
        : rows.length
          ? rows.map(rowMarkup).join('')
          : `<tr><td colspan="6" class="dwrt-kit-table-empty">${state.rules.length ? '没有符合当前筛选的规则' : '当前没有任何断网规则，所有终端均可联网'}</td></tr>`;
    return `<section class="user-auth-main-surface user-auth-table-card cnc-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface" data-cnc-table><div class="dwrt-kit-table-toolbar user-auth-table-toolbar-rich"><div class="dwrt-kit-table-title"><strong>断网规则</strong></div><span class="dwrt-kit-table-count">${rows.length} 条</span>${toolbarControls()}</div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table user-auth-table cnc-table"><thead><tr><th>状态</th><th>终端</th><th>生效时段</th><th>备注</th><th>命中</th><th>操作</th></tr></thead><tbody>${body}</tbody></table></div></section>`;
  }

  function allowlistStatusMarkup() {
    const pending = allowlistPending();
    const remain = allowlistSecondsRemaining();
    const status = state.allowlist.enabled
      ? pending
        ? statusBadge(`待确认 ${remain}s`, 'warning')
        : statusBadge('白名单已启用', 'success')
      : statusBadge('白名单未启用', 'warning');
    const enableDisabled = state.saving || state.allowlistDirty || state.allowlistMembers.length === 0;
    return `<div class="cnc-allowlist-status"><span class="cnc-stack">${status}<small>${state.allowlist.enabled ? '名单外终端无法访问互联网' : state.allowlistDirty ? '名单有未保存的修改' : '当前不会按白名单限制终端'}</small></span><div class="cnc-allowlist-actions">${pending ? `<button type="button" class="policy-primary" data-cnc-allowlist-confirm ${state.saving ? 'disabled' : ''}>确认保持</button>` : ''}<button type="button" class="${state.allowlist.enabled ? 'policy-secondary' : 'policy-primary'}" data-cnc-allowlist-toggle ${state.allowlist.enabled || !enableDisabled ? '' : 'disabled'} ${state.saving ? 'disabled' : ''}>${state.allowlist.enabled ? '停用白名单' : '启用白名单'}</button></div></div>`;
  }

  function allowlistOptions() {
    const selected = new Set(state.allowlistDraft);
    return state.clients.slice().sort((left, right) => {
      if (left.online !== right.online) return left.online ? -1 : 1;
      return left.name.localeCompare(right.name, 'zh-Hans-CN');
    }).filter((client) => !selected.has(client.mac)).map((client) =>
      `<option value="${escapeHtml(client.mac)}">${escapeHtml(`${client.name} · ${clientLocator(client)} · ${client.online ? '在线' : '离线'}`)}</option>`
    ).join('');
  }

  function allowlistMemberMarkup(mac) {
    const client = allowlistMemberClient(mac);
    const detail = client ? `${clientLocator(client)} · ${client.online ? '在线' : '离线'}` : '不在当前终端列表';
    const admin = state.allowlist.adminMac === mac ? '<small class="cnc-self-device">当前管理终端</small>' : '';
    return `<tr><td><span class="cnc-stack"><strong>${escapeHtml(client?.name || mac)}</strong><code>${escapeHtml(mac)}</code>${admin}</span></td><td>${escapeHtml(detail)}</td><td class="cnc-actions"><button type="button" class="user-auth-icon-button is-danger" data-cnc-allowlist-remove="${escapeHtml(mac)}" title="移出白名单" aria-label="移出白名单" ${state.allowlist.enabled || state.saving ? 'disabled' : ''}>${icon('trash')}</button></td></tr>`;
  }

  function allowlistMarkup() {
    const members = state.allowlistDraft;
    const options = allowlistOptions();
    const body = members.length
      ? members.map(allowlistMemberMarkup).join('')
      : '<tr><td colspan="3" class="dwrt-kit-table-empty">白名单为空，至少添加一个终端后才能启用</td></tr>';
    return `<section class="user-auth-main-surface user-auth-table-card cnc-table-card cnc-allowlist-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface" data-cnc-table><div class="dwrt-kit-table-toolbar user-auth-table-toolbar-rich"><div class="dwrt-kit-table-title"><strong>联网白名单</strong></div><span class="dwrt-kit-table-count">${members.length} 台</span>${allowlistStatusMarkup()}${state.allowlist.enabled ? '' : `<div class="cnc-allowlist-editor"><select data-cnc-allowlist-client ${options ? '' : 'disabled'}><option value="">${options ? '选择终端' : '没有可添加的终端'}</option>${options}</select><button type="button" class="policy-secondary" data-cnc-allowlist-add ${options && !state.saving ? '' : 'disabled'}>${icon('plus')}<span>添加</span></button><button type="button" class="policy-primary" data-cnc-allowlist-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存名单'}</button></div>`}</div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table user-auth-table cnc-allowlist-table"><thead><tr><th>终端</th><th>状态</th><th>操作</th></tr></thead><tbody>${body}</tbody></table></div></section>`;
  }

  function contentMarkup() {
    return state.mode === 'white' ? allowlistMarkup() : tableMarkup();
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
      control = `<input data-cnc-field="${name}" type="${escapeHtml(options.type || 'text')}" value="${escapeHtml(value ?? '')}" ${options.placeholder ? `placeholder="${escapeHtml(options.placeholder)}"` : ''} ${options.min !== undefined ? `min="${escapeHtml(options.min)}"` : ''} ${options.max !== undefined ? `max="${escapeHtml(options.max)}"` : ''} ${disabled}>`;
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

  /*
   * 生效时段控件。按能力位开关，不写死：后端若把 acl_schedule_supported 关掉，
   * 这段整体不渲染，保存时也会退回 always。
   */
  function scheduleEditorMarkup(editor) {
    if (scheduleBlockedReason(state.capabilities)) return '';
    const windowMode = editor.scheduleMode === 'window';
    const days = Array.isArray(editor.scheduleDays) ? editor.scheduleDays : [];
    const weekdaysOn = state.capabilities.acl_schedule_weekdays_supported === true;
    const basis = firstText(state.capabilities.acl_schedule_time_basis, 'device_local_time') === 'device_local_time'
      ? '时间按路由器本地时间判断，不是你浏览器所在时区'
      : `时基：${firstText(state.capabilities.acl_schedule_time_basis)}`;
    return `<div class="user-auth-drawer-section cnc-schedule-section"><strong>生效时段</strong>
      <div class="cnc-schedule-switch" role="group" aria-label="生效时段模式"><button type="button" data-cnc-schedule-mode="always" class="${windowMode ? '' : 'is-active'}">始终生效</button><button type="button" data-cnc-schedule-mode="window" class="${windowMode ? 'is-active' : ''}">按时间段生效</button></div>
      ${windowMode ? `<div class="user-auth-form-grid">
        ${editorField('开始时间', 'scheduleStart', editor.scheduleStart, { type: 'time' })}
        ${editorField('结束时间', 'scheduleEnd', editor.scheduleEnd, { type: 'time' })}
      </div>
      ${weekdaysOn ? `<div class="cnc-weekdays"><span>生效星期</span><div>${WEEKDAY_LABELS.map((label, index) => `<label class="${days.includes(index) ? 'is-active' : ''}"><input type="checkbox" data-cnc-weekday="${index}" ${days.includes(index) ? 'checked' : ''}>${escapeHtml(label)}</label>`).join('')}</div><small>不选或全选表示每天生效</small></div>` : ''}
      <small class="cnc-schedule-hint">${escapeHtml(`一条规则只支持一个时间窗（acl_schedule_max_windows=${Number(state.capabilities.acl_schedule_max_windows ?? 1)}）；需要多个时间段请分别建规则。${basis}。`)}</small>` : ''}
    </div>`;
  }

  /*
   * 到期时间控件。按能力位开关：写侧不可用时整段不渲染，保存也不带 expires 字段，
   * 避免把后端不认的值送上去。
   *
   * 到期后不会自动放行（没有周期性 ruleset 重建，要等下一次 apply），所以文案只说
   * "停止拦截"的条件，不承诺"到点自动恢复联网"。
   */
  function expiresEditorMarkup(editor) {
    if (!expiresWritable(state.capabilities)) return '';
    const on = editor.expiresMode === 'at';
    const zone = deviceTimezone();
    const basis = zone
      ? `时间按路由器本地时间（${zone}）判断，不是你浏览器所在时区`
      : '读不到设备时区，暂按你浏览器所在时区换算，若两者不一致请核对到期时刻';
    /* min 用设备墙上时间的"现在"，把后端那条"过去时间戳报 400"提前挡在选择器里。 */
    const min = epochToLocalInput(Math.floor(Date.now() / 1000) + 60);
    const lapsed = on && editor.expiresAt && localInputToEpoch(editor.expiresAt) <= Math.floor(Date.now() / 1000);
    return `<div class="user-auth-drawer-section cnc-schedule-section cnc-expires-section"><strong>到期时间</strong>
      <div class="cnc-schedule-switch" role="group" aria-label="到期时间模式"><button type="button" data-cnc-expires-mode="never" class="${on ? '' : 'is-active'}">永不过期</button><button type="button" data-cnc-expires-mode="at" class="${on ? 'is-active' : ''}">到期自动停止拦截</button></div>
      ${on ? `<div class="user-auth-form-grid">
        ${editorField('到期时刻', 'expiresAt', editor.expiresAt, { type: 'datetime-local', wide: true, min })}
      </div>
      ${lapsed ? '<small class="cnc-expires-warning">这个时刻已经过去，后端会拒绝保存。请改成将来的时刻，或切回「永不过期」。</small>' : ''}
      <small class="cnc-schedule-hint">${escapeHtml(`到期后规则保留在列表里并标记为已失效，不再进入 nftables。${basis}。注意：到期不会立刻放行，需等下一次应用规则后该终端才真正恢复联网。`)}</small>` : `<small class="cnc-schedule-hint">规则一直有效，直到你手动停用或删除。</small>`}
    </div>`;
  }

  function sourceEditorMarkup(editor, editing) {
    const options = clientOptions();
    const manual = editor.source === 'manual' || !options.length;
    return `${editing ? '' : `<div class="cnc-source-switch" role="group" aria-label="终端来源"><button type="button" data-cnc-source="list" class="${manual ? '' : 'is-active'}">从终端列表选择</button><button type="button" data-cnc-source="manual" class="${manual ? 'is-active' : ''}">手动填写 MAC</button></div>`}${editing
      ? editorField('终端 MAC', 'mac', editor.mac, { disabled: true, wide: true, help: 'MAC 是规则身份，编辑时不可更改。需要换终端请新建规则。' })
      : manual
        ? editorField('终端 MAC', 'mac', editor.mac, { wide: true, placeholder: 'AA:BB:CC:DD:EE:FF', help: '支持冒号、连字符或无分隔写法' })
        : editorField('终端', 'mac', editor.mac, { type: 'select', options, wide: true, help: '含离线、随机化 MAC 与仅 IPv6 终端' })}`;
  }

  function ruleDetailsMarkup(editor) {
    return `${editorField('规则名称', 'name', editor.name, { wide: true, help: '留空时使用规则 ID' })}${editorField('优先级', 'priority', editor.priority, { type: 'number', min: 1, max: 65535, help: '数值越小越先匹配' })}`;
  }

  function drawerMarkup() {
    if (!state.drawer) return '';
    const editor = state.editor;
    const editing = Boolean(editor.policyId);
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-cnc-close aria-label="关闭断网规则编辑"></button><aside class="user-auth-drawer cnc-drawer dwrt-kit-sheet is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" data-dwrt-surface="stable-glass" data-dwrt-sheet-motion="settled" aria-label="${editing ? '编辑断网规则' : '新建断网规则'}"><header class="dwrt-kit-sheet-header"><div><strong>${editing ? '编辑终端拦截规则' : '新建终端拦截规则'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-cnc-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body user-auth-drawer-body cnc-drawer-body">
      <section class="cnc-drawer-chamber"><span class="cnc-drawer-chamber-label">拦截目标与状态 <small>Target &amp; Status</small></span><label class="user-auth-setting-row"><span><strong>启用规则</strong></span><span class="dwrt-kit-switch" data-dwrt-component="switch"><input type="checkbox" data-cnc-field="enabled" ${editor.enabled === true ? 'checked' : ''}></span></label><div class="cnc-target-field" data-cnc-target-editor>${sourceEditorMarkup(editor, editing)}</div></section>
      <section class="cnc-drawer-chamber"><span class="cnc-drawer-chamber-label">规则与优先级 <small>Policy Meta</small></span><div class="user-auth-form-grid">${ruleDetailsMarkup(editor)}</div></section>
      <div data-cnc-schedule-editor>${scheduleEditorMarkup(editor)}</div>
      <div data-cnc-expires-editor>${expiresEditorMarkup(editor)}</div>
      <section class="cnc-drawer-chamber cnc-drawer-note-chamber"><span class="cnc-drawer-chamber-label">备注 <small>Notes</small></span>${editorField('备注', 'remark', editor.remark, { type: 'textarea', wide: true })}</section>
      <div data-cnc-drawer-notice>${state.notice ? noticeMarkup() : ''}</div>
    </div><footer class="dwrt-kit-sheet-footer user-auth-drawer-footer"><span></span><div><button class="policy-secondary" type="button" data-cnc-close>取消</button><button class="policy-primary cnc-save-danger" type="button" data-cnc-save ${state.saving ? 'disabled' : ''}>${state.saving ? '正在保存' : '保存拦截规则'}</button></div></footer></aside>`;
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
    root.innerHTML = `<section class="user-auth-shell cnc-shell" data-cnc-version="${VERSION}"><main class="user-auth-workbench cnc-workbench">${noticeMarkup()}${modeHost ? '' : modeMarkup()}${contentMarkup()}</main><div data-cnc-savebar-host>${localSavebarMarkup()}</div><div class="cnc-overlay-host" data-cnc-sheet-host></div><div class="cnc-overlay-host" data-cnc-confirmation-host></div></section>`;
    renderModeSlot();
    renderOverlays();
    ui.mountAll?.(root);
  }

  function renderModeSlot() {
    if (!modeHost) return;
    modeHost.innerHTML = modeMarkup();
    modeHost.hidden = false;
  }

  function renderOverlays() {
    renderDrawerOverlay();
    renderConfirmationOverlay();
  }

  function renderDrawerOverlay() {
    const host = root?.querySelector('[data-cnc-sheet-host]');
    if (!host) return;
    const markup = drawerMarkup();
    if (host.dataset.cncDrawerMarkup === markup) return;
    host.dataset.cncDrawerMarkup = markup;
    const existingSheet = document.querySelector('#dwrtKitSheetPortal .cnc-drawer');
    if (state.drawer && existingSheet) {
      patchDrawerContent(existingSheet);
      return;
    }
    /*
     * 清空容器关不掉抽屉：kit 已把它搬到 body 级 portal，必须先让 kit 卸载搬走的那份。
     * `unmount(host)` 现在按 portalHome 反查得到传送出去的抽屉与遮罩，本页不再自备
     * portal 清理代码。
     */
    window.DWRT_UI_KIT?.unmount?.(host);
    host.innerHTML = markup;
    ui.mountAll?.(host);
  }

  function renderConfirmationOverlay() {
    const host = root?.querySelector('[data-cnc-confirmation-host]');
    if (!host) return;
    const markup = confirmationMarkup();
    if (host.dataset.cncConfirmationMarkup === markup) return;
    host.dataset.cncConfirmationMarkup = markup;
    window.DWRT_UI_KIT?.unmount?.(host);
    host.innerHTML = markup;
    ui.mountAll?.(host);
  }

  function rememberDrawerMarkup() {
    const host = root?.querySelector('[data-cnc-sheet-host]');
    if (host) host.dataset.cncDrawerMarkup = drawerMarkup();
  }

  function patchDrawerRegion(selector, markup) {
    const sheet = document.querySelector('#dwrtKitSheetPortal .cnc-drawer');
    const region = sheet?.querySelector(selector);
    if (!region) return false;
    const body = region.closest('.dwrt-kit-sheet-body');
    const scrollTop = body?.scrollTop || 0;
    region.innerHTML = markup;
    ui.mountAll?.(region);
    if (body) body.scrollTop = scrollTop;
    return true;
  }

  function patchDrawerContent(sheet) {
    const current = sheet.querySelector('.dwrt-kit-sheet-body');
    if (!current) return;
    const scrollTop = current.scrollTop;
    const active = document.activeElement;
    const focusKey = active?.getAttribute?.('data-cnc-field') || '';
    const template = document.createElement('template');
    template.innerHTML = drawerMarkup();
    const next = template.content.querySelector('.cnc-drawer');
    const nextBody = next?.querySelector('.dwrt-kit-sheet-body');
    const nextFooter = next?.querySelector('.dwrt-kit-sheet-footer');
    if (!nextBody || !nextFooter) return;
    current.innerHTML = nextBody.innerHTML;
    const footer = sheet.querySelector('.dwrt-kit-sheet-footer');
    if (footer) footer.innerHTML = nextFooter.innerHTML;
    current.scrollTop = scrollTop;
    ui.mountAll?.(current);
    if (footer) ui.mountAll?.(footer);
    if (focusKey) sheet.querySelector(`[data-cnc-field="${focusKey}"]`)?.focus({ preventScroll: true });
  }

  function render() {
    if (!root) return;
    const mounted = root.querySelector('[data-cnc-version]');
    if (!mounted) {
      renderShell();
      return;
    }
    patchPieces();
  }

  /*
   * 后台刷新的重绘入口（Acceptance P0 单：本页实测整棵路由 DOM 被替换）。
   *
   * render() 在没有抽屉时会走 renderShell() 整树重绘，轮询也落在这条路上。已经挂载过的
   * 页面按细粒度 patch 走即可：工具栏、提示条、表格各自原地更新，路由根不重建。
   */
  function renderPreservingInteraction() {
    if (!root?.querySelector('[data-cnc-version]')) { render(); return; }
    patchPieces();
  }

  function patchPieces() {
    renderModeSlot();
    if (state.mode === 'black') patchToolbar();
    patchNotice();
    patchTable();
    patchLocalSavebar();
    renderOverlays();
  }

  function patchLocalSavebar() {
    const host = root?.querySelector('[data-cnc-savebar-host]');
    if (!host) return;
    host.innerHTML = localSavebarMarkup();
    ui.mountAll?.(host);
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

  /*
   * 表格重画走 kit 的共享保状态入口（Acceptance P0 单）。
   *
   * 原来是 `current.replaceWith(...)` 再把 scrollTop 复位：节点换了身份，滚动靠事后补救，
   * 焦点与选区直接丢。交给 kit 按语义 key patch 之后三样都留着。
   */
  function patchTable() {
    const current = root?.querySelector('[data-cnc-table]');
    if (!current) { renderShell(); return; }
    /*
     * 直接在表格卡上 patch。tableMarkup() 返回的就是这张卡，所以渲染进 staging 之后
     * 取它的首个元素，把卡的属性与内容一起交给 morph 配对。
     *
     * 不要在父容器上做：`.cnc-workbench` 里还挂着提示条、模式块与能力说明，
     * 只写 tableMarkup() 会把那些兄弟节点当成"新树里没有"而删掉。
     */
    const preserve = ui.preserveInteractionState;
    if (typeof preserve === 'function' && preserve(current, (target) => {
      const template = document.createElement('template');
      template.innerHTML = contentMarkup();
      const fresh = template.content.firstElementChild;
      if (fresh) {
        Array.from(fresh.attributes).forEach((attribute) => target.setAttribute(attribute.name, attribute.value));
        target.innerHTML = fresh.innerHTML;
      }
    })) return;
    const scroll = current.querySelector('.dwrt-kit-table-scroll');
    const position = { top: scroll?.scrollTop || 0, left: scroll?.scrollLeft || 0 };
    const template = document.createElement('template');
    template.innerHTML = contentMarkup();
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
      /*
       * 请求来源回显（GET /api/v1/session 的 data.request_origin）用于「这是你正在
       * 使用的设备」标记，是可选增强：读失败只降级掉标记，不影响规则列表。
       */
      /*
       * 设备时区来自 /api/v1/system/basic 的 general.timezone，用于到期时间的墙上时间
       * 换算。和来源回显一样是可选增强：读失败只降级成浏览器时区并在控件上说明。
       */
      const [policyResult, clientsResult, sessionResult, basicResult, allowlistResult] = await Promise.allSettled([
        requestJson(POLICY_TABLE),
        requestJson('/api/v1/clients'),
        requestJson('/api/v1/session'),
        requestJson('/api/v1/system/basic'),
        requestJson(ALLOWLIST)
      ]);
      if (!state.mounted || seq !== state.seq) return;
      if (policyResult.status === 'rejected') throw policyResult.reason;
      const payload = policyResult.value || {};
      state.capabilities = payload.capabilities && typeof payload.capabilities === 'object' ? payload.capabilities : {};
      state.deviceTimezone = basicResult.status === 'fulfilled'
        ? firstText(basicResult.value?.general?.timezone, basicResult.value?.timezone)
        : '';
      state.requestOrigin = sessionResult.status === 'fulfilled'
        ? (sessionResult.value?.request_origin || sessionResult.value?.data?.request_origin || null)
        : null;
      state.clients = clientsResult.status === 'fulfilled'
        ? asArray(clientsResult.value).map(normalizeClient).filter((client) => client.mac)
        : [];
      const clientsByMac = new Map(state.clients.map((client) => [client.mac, client]));
      const rows = Array.isArray(payload.rows) ? payload.rows : [];
      state.rules = rows
        .filter((row) => String(row?.id || '').startsWith(MAC_ID_PREFIX))
        .map((row, index) => normalizeRule(row, clientsByMac, index));
      if (parentDraftController) {
        parentDraftController.register('network', state.rules, {
          id: (rule) => rule.policyId,
          enabled: (rule) => rule.enabled,
          canWrite: () => canWriteMac(state.capabilities),
          describe: (rule) => `${rule.clientName || rule.mac} · ${rule.name}`,
          render,
          refresh: () => load(true),
          save: saveEnabledCanonical
        });
      } else {
        state.rules.forEach((rule) => {
          localEnabledBaseline.set(rule.policyId, Boolean(rule.enabled));
          if (localEnabledDraft.has(rule.policyId) && localEnabledDraft.get(rule.policyId) === Boolean(rule.enabled)) localEnabledDraft.delete(rule.policyId);
        });
      }
      if (allowlistResult.status === 'fulfilled') {
        state.allowlist = normalizeAllowlist(allowlistResult.value);
        state.allowlistMembers = normalizeAllowlistMembers(allowlistResult.value);
        if (!background || !state.allowlistDirty)
          state.allowlistDraft = state.allowlistMembers.slice();
        if (!state.allowlistLoaded && state.allowlist.enabled) state.mode = 'white';
        state.allowlistLoaded = true;
      } else {
        state.allowlist = {};
        state.allowlistMembers = [];
        if (!state.allowlistDirty) state.allowlistDraft = [];
      }
      state.loading = false;
      state.refreshing = false;
      if (clientsResult.status === 'rejected') {
        state.notice = '终端列表读取失败，现有规则暂按 MAC 显示，设备选择器不可用。';
        state.noticeTone = 'warning';
      } else if (!canWriteMac(state.capabilities)) {
        state.notice = '后端未声明 MAC ACL 写入能力，本页当前只能查看规则。';
        state.noticeTone = 'warning';
      } else if (allowlistSupported() && allowlistResult.status === 'rejected') {
        state.notice = '白名单状态读取失败，白名单操作暂不可用。';
        state.noticeTone = 'warning';
      }
      if (background) renderPreservingInteraction(); else render();
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      state.capabilities = {};
      state.rules = [];
      state.allowlist = {};
      state.allowlistMembers = [];
      state.allowlistDraft = [];
      state.allowlistDirty = false;
      state.error = [401, 403].includes(Number(error.status))
        ? '当前账号没有读取策略表的权限，无法显示终端联网控制规则。'
        : `读取终端联网控制规则失败：${firstText(error.message, '未知错误')}`;
      render();
    }
  }

  function newEditor(rule = null) {
    const options = clientOptions();
    const schedule = rule ? rule.schedule : parseSchedule('always');
    state.editor = rule
      ? {
        policyId: rule.policyId, rawId: rule.rawId, mac: rule.mac, name: rule.name, remark: rule.remark,
        priority: rule.priority, enabled: rule.enabled, source: 'list',
        scheduleMode: schedule.mode, scheduleStart: schedule.start, scheduleEnd: schedule.end, scheduleDays: schedule.weekdays.slice(),
        /* 回填已存的到期时刻；0 表示永不过期。 */
        expiresMode: rule.expires > 0 ? 'at' : 'never', expiresAt: epochToLocalInput(rule.expires)
      }
      : {
        policyId: '', rawId: '', mac: options[0]?.[0] || '', name: '', remark: '', priority: 1000, enabled: false,
        source: options.length ? 'list' : 'manual',
        scheduleMode: 'always', scheduleStart: schedule.start, scheduleEnd: schedule.end, scheduleDays: [],
        expiresMode: 'never', expiresAt: ''
      };
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
      enabled: editor.enabled === true,
      scheduleMode: editor.scheduleMode === 'window' ? 'window' : 'always',
      scheduleStart: editor.scheduleStart,
      scheduleEnd: editor.scheduleEnd,
      scheduleDays: Array.isArray(editor.scheduleDays) ? editor.scheduleDays : [],
      /* 能力位关掉时一律退回 always，避免把后端不认的 schedule 送上去。 */
      schedule: scheduleBlockedReason(state.capabilities) ? 'always' : formatSchedule(editor),
      expiresMode: editor.expiresMode === 'at' ? 'at' : 'never',
      expiresAt: firstText(editor.expiresAt),
      /*
       * 绝对 Unix 秒，0 表示永不过期。写侧能力位关掉时给 null，由 commitSave 整字段
       * 省略，而不是送 0 —— 那会把一条已有到期时间的规则悄悄改成永不过期。
       */
      expires: expiresWritable(state.capabilities)
        ? (editor.expiresMode === 'at' ? localInputToEpoch(editor.expiresAt) : 0)
        : null
    };
  }

  function validation(payload) {
    if (!payload.mac) return 'MAC 地址无效。请从终端列表选择，或填写 12 位十六进制 MAC。';
    if (payload.priority < 1 || payload.priority > 65535) return '优先级需在 1 到 65535 之间。';
    if (payload.scheduleMode === 'window') {
      if (!hhmmOk(payload.scheduleStart) || !hhmmOk(payload.scheduleEnd)) return '生效时段的开始与结束时间需填写为 HH:MM。';
      /* 后端拒绝起止相同（空窗口永不匹配），在这里先说清楚，别让用户吃一个 400。 */
      if (payload.scheduleStart === payload.scheduleEnd) return '生效时段的开始与结束时间不能相同，否则这个时间窗永远不会匹配。';
    }
    /*
     * 到期时间：后端对"请求体里显式传入的过去时间戳"回 400，这里先拦一次，
     * 让用户看到的是选择器旁边的提示而不是一个保存失败。
     */
    if (payload.expires !== null && payload.expiresMode === 'at') {
      if (!payload.expires) return '请选择到期时刻，或切回「永不过期」。';
      if (payload.expires <= Math.floor(Date.now() / 1000)) {
        return `到期时刻已经过去${deviceTimezone() ? `（按设备时区 ${deviceTimezone()} 判断）` : ''}，后端会拒绝。请改成将来的时刻，或切回「永不过期」。`;
      }
    }
    /*
     * MAC 唯一：后端只按规则 ID 判重，同一 MAC 建两条会都写进去且都生效，所以在前端
     * 拦住并定位到已有那条。唯一性只约束单 MAC 规则（acl_mac_unique_applies_to_single_
     * mac_rules_only），分组规则不占 MAC 名额，不能拿它去挡。
     */
    if (!payload.policyId) {
      const existing = state.rules.find((rule) => rule.sourceKind !== 'group' && rule.mac === payload.mac);
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
   * 目标等于请求来源 MAC 时明确标出「这是你正在使用的设备」；来源回显不可用时
   * 退回原来的做法：把目标终端完整念出来让用户自己核对，而不是静默放过。
   */
  function selfDeviceWarning(mac) {
    if (isSelfDevice(mac)) return '注意：这就是你正在使用的设备，确认后你会立刻失去对本页面的访问，需要换一台设备或改用其他线路才能撤销。';
    if (!selfDeviceCheckSupported()) return '本页当前无法判断这是否是你正在使用的设备，请先自行核对。';
    return '';
  }
  function requestEnable(rule) {
    const selfWarning = selfDeviceWarning(rule.mac);
    state.confirm = {
      kind: 'enable',
      policyId: rule.policyId,
      tone: 'danger',
      title: isSelfDevice(rule.mac) ? '这是你正在使用的设备' : '确认让这台终端断网',
      description: `启用后 ${describeTarget(rule.mac)} 将立即无法联网，直到你手动停用或删除这条规则。${selfWarning}`,
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

  function switchMode(mode) {
    if (mode === 'white' && !allowlistSupported()) return;
    if (mode === 'black' && state.allowlist.enabled) {
      requestAllowlistToggle();
      return;
    }
    state.mode = mode === 'white' ? 'white' : 'black';
    state.notice = '';
    state.confirm = null;
    renderModeSlot();
    patchNotice();
    patchTable();
  }

  function addAllowlistMember() {
    if (state.allowlist.enabled || state.saving) return;
    const select = root?.querySelector('[data-cnc-allowlist-client]');
    const mac = normalizeMac(select?.value);
    if (!mac || state.allowlistDraft.includes(mac)) return;
    state.allowlistDraft = [...state.allowlistDraft, mac].sort();
    state.allowlistDirty = true;
    patchTable();
  }

  function removeAllowlistMember(mac) {
    if (state.allowlist.enabled || state.saving) return;
    const normalized = normalizeMac(mac);
    state.allowlistDraft = state.allowlistDraft.filter((item) => item !== normalized);
    state.allowlistDirty = true;
    patchTable();
  }

  async function saveAllowlistMembers() {
    if (state.allowlist.enabled || state.saving) return;
    state.saving = true;
    patchTable();
    try {
      const response = await requestJson(ALLOWLIST_MEMBERS, {
        method: 'PUT',
        body: JSON.stringify({ members: state.allowlistDraft })
      });
      state.allowlistMembers = normalizeAllowlistMembers(response);
      state.allowlistDraft = state.allowlistMembers.slice();
      state.allowlistDirty = false;
      state.notice = '白名单成员已保存。';
      state.noticeTone = 'ok';
    } catch (error) {
      state.notice = `保存白名单失败：${firstText(error.message, '后端未接受名单')}`;
      state.noticeTone = 'error';
    } finally {
      state.saving = false;
      patchNotice();
      patchTable();
    }
  }

  function requestAllowlistToggle() {
    if (state.saving) return;
    if (state.allowlist.enabled) {
      state.confirm = {
        kind: 'allowlist-disable',
        tone: 'warning',
        title: '停用白名单模式',
        description: '停用后，名单外终端将恢复互联网访问，白名单成员记录会保留。',
        confirmLabel: '确认停用'
      };
    } else {
      if (state.allowlistDirty) {
        state.notice = '请先保存白名单成员，再启用白名单模式。';
        state.noticeTone = 'warning';
        patchNotice();
        return;
      }
      if (state.allowlistMembers.length === 0) {
        state.notice = '至少添加并保存一个白名单终端后才能启用。';
        state.noticeTone = 'warning';
        patchNotice();
        return;
      }
      state.confirm = {
        kind: 'allowlist-enable',
        tone: 'danger',
        title: '启用 MAC 白名单',
        description: `启用后，除当前 ${state.allowlistMembers.length} 台白名单终端和后端自动加入的管理终端外，其余 LAN 终端都会失去互联网访问。操作后需在 180 秒内确认，否则系统自动回滚。`,
        confirmLabel: '启用并开始倒计时'
      };
    }
    renderOverlays();
  }

  async function setAllowlistEnabled(enabled) {
    if (state.saving) return;
    state.saving = true;
    renderOverlays();
    patchTable();
    try {
      const response = await requestJson(ALLOWLIST, {
        method: 'POST',
        body: JSON.stringify(enabled ? { enabled: true, confirm_timeout: 180 } : { enabled: false })
      });
      state.allowlist = normalizeAllowlist(response);
      state.allowlistMembers = normalizeAllowlistMembers(response).length
        ? normalizeAllowlistMembers(response) : state.allowlistMembers;
      state.allowlistDraft = state.allowlistMembers.slice();
      state.allowlistDirty = false;
      state.mode = enabled ? 'white' : 'black';
      const readback = await requestJson(ALLOWLIST);
      state.allowlist = normalizeAllowlist(readback);
      state.allowlistMembers = normalizeAllowlistMembers(readback);
      state.allowlistDraft = state.allowlistMembers.slice();
      state.notice = enabled
        ? '白名单已临时启用，请在倒计时结束前确认保持。'
        : '白名单模式已停用，名单外终端已恢复联网。';
      state.noticeTone = enabled ? 'warning' : 'ok';
    } catch (error) {
      state.notice = `${enabled ? '启用' : '停用'}白名单失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
    } finally {
      state.saving = false;
      state.confirm = null;
      patchNotice();
      patchTable();
      renderOverlays();
    }
  }

  async function confirmAllowlist() {
    if (!allowlistPending() || state.saving) return;
    state.saving = true;
    patchTable();
    try {
      const response = await requestJson(ALLOWLIST_CONFIRM, {
        method: 'POST', body: JSON.stringify({})
      });
      state.allowlist = normalizeAllowlist(response);
      state.notice = '白名单模式已确认保持。';
      state.noticeTone = 'ok';
    } catch (error) {
      state.notice = `确认白名单失败：${firstText(error.message, '确认窗口可能已结束')}`;
      state.noticeTone = 'error';
    } finally {
      state.saving = false;
      patchNotice();
      patchTable();
    }
  }

  /* 写入必须显式 apply=true：后端 dry_run_default=true，不带 apply 只回 409 预览。 */
  function writeBody(extra = {}) {
    return JSON.stringify({ policy_type: 'acl', acl_type: 'mac', apply: true, ...extra });
  }

  /*
   * 写入响应里的 expires_warning：后端在 expires<=now 时给出，含义是"行已落库，但
   * ruleset 生成器会跳过它"。响应本身仍是 ok:true/applied:true，所以不翻译成警告
   * 就会被读成已生效。原文是英文，这里换成中文并说清补救动作。
   */
  function expiresWarningText(response) {
    const body = response && typeof response === 'object' ? response : {};
    if (!firstText(body.expires_warning)) return '';
    const expires = Number(body.expires) || 0;
    const stamp = expires > 0 ? epochToLocalInput(expires).replace('T', ' ') : '';
    return `规则已保存，但${stamp ? `到期时刻（${stamp}）` : '到期时刻'}已经过去，因此当前不会拦截该终端。把到期时间改成将来的时刻，或切换为「永不过期」后才会真正生效。`;
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
        title: isSelfDevice(payload.mac) ? '这是你正在使用的设备' : '确认保存并立即断网',
        description: `保存后 ${describeTarget(payload.mac)} 会立即无法联网。${selfDeviceWarning(payload.mac)}`,
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
    let response = null;
    try {
      const fields = {
        mac: payload.mac,
        name: payload.name || undefined,
        remark: payload.remark,
        priority: payload.priority,
        enabled: payload.enabled,
        action: 'deny',
        /* schedule 是字符串："always" 或单窗口 JSON 数组，与存储格式一致。 */
        schedule: payload.schedule
      };
      /*
       * expires 放在请求体顶层，与 schedule 平级（不在 mac 子对象里）。
       * 写侧能力位关掉时整字段省略：送 0 会把已有到期时间悄悄清成永不过期。
       */
      if (payload.expires !== null) fields.expires = payload.expires;
      if (payload.policyId) {
        response = await requestJson(`${POLICY_TABLE}/${encodeURIComponent(payload.policyId)}`, { method: 'PATCH', body: writeBody({ operation: 'update', ...fields }) });
      } else {
        response = await requestJson(POLICY_TABLE, { method: 'POST', body: writeBody({ operation: 'create', ...fields }) });
      }
      state.saving = false;
      state.drawer = false;
      state.confirm = null;
      state.editor = {};
      /*
       * expires_warning 表示"存进去了，但生成器仍会跳过它"——只看 ok/applied 会得出
       * 「已生效」的错误结论，所以这种情况必须降级成警告并说明当前不拦截。
       */
      const warning = expiresWarningText(response);
      if (warning) {
        state.notice = warning;
        state.noticeTone = 'warning';
      } else {
        state.notice = payload.enabled
          ? '规则已保存并启用，该终端现在无法联网。'
          : '规则已保存，当前未启用。需要断网请在列表里手动启用。';
        state.noticeTone = 'ok';
      }
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

  function toggleRule(rule) {
    if (!rule || state.saving || !canWriteMac(state.capabilities)) return;
    const enabled = !ruleEnabled(rule);
    if (parentDraftController) parentDraftController.toggle('network', rule, enabled);
    else if (localEnabledBaseline.get(rule.policyId) === enabled) localEnabledDraft.delete(rule.policyId); else localEnabledDraft.set(rule.policyId, enabled);
    state.notice = '';
    render();
  }

  async function saveEnabledCanonical(rule, enabled) {
    await requestJson(`${POLICY_TABLE}/${encodeURIComponent(rule.policyId)}`, {
      method: 'PATCH',
      body: writeBody({ operation: enabled ? 'enable' : 'disable' })
    });
    const payload = await requestJson(POLICY_TABLE);
    const found = (Array.isArray(payload.rows) ? payload.rows : []).find((row) => firstText(row?.id, row?.raw?.id) === rule.policyId);
    if (!found) throw new Error('保存后回读找不到断网规则');
    return bool(found?.raw?.enabled, bool(found?.enabled, false));
  }

  async function saveLocalEnabledDrafts() {
    const changes = localEnabledChanges();
    if (!changes.length || state.saving) return;
    const risky = changes.filter(([, enabled]) => enabled).map(([id]) => state.rules.find((rule) => rule.policyId === id)).filter(Boolean);
    if (risky.length && window.confirm && !window.confirm(`以下规则启用后可能影响终端联网：\n\n${risky.map((rule) => `- ${rule.clientName || rule.mac} · ${rule.name}：停用 → 启用`).join('\n')}\n\n确认保存？`)) return;
    state.saving = true;
    render();
    const failed = [];
    for (const [id, enabled] of changes) {
      const rule = state.rules.find((item) => item.policyId === id);
      try {
        if (!rule || await saveEnabledCanonical(rule, enabled) !== enabled) throw new Error('保存后回读与草稿不一致');
        localEnabledDraft.delete(id);
      } catch (error) {
        failed.push(`${rule?.name || id}（${firstText(error.message, '保存失败')}）`);
      }
    }
    state.saving = false;
    state.notice = failed.length
      ? `${changes.length - failed.length} 条已保存，${failed.length} 条失败并保留草稿：${failed.join('、')}`
      : `${changes.length} 条断网规则状态已保存。`;
    state.noticeTone = failed.length ? 'warning' : 'ok';
    await load(true);
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
    if (request.kind === 'allowlist-enable') { setAllowlistEnabled(true); return; }
    if (request.kind === 'allowlist-disable') { setAllowlistEnabled(false); return; }
    if (request.kind === 'create-enabled') { commitSave(editorPayload()); return; }
    const rule = findRule(request.policyId);
    if (!rule) { state.confirm = null; renderOverlays(); return; }
    if (request.kind === 'enable') { state.confirm = null; toggleRule(rule); return; }
    if (request.kind === 'delete') { deleteRule(rule); }
  }

  function onClick(event) {
    if (event.target.closest('[data-dwrt-savebar-discard]')) { localEnabledDraft.clear(); state.notice = ''; render(); return; }
    if (event.target.closest('[data-dwrt-savebar-save]')) { saveLocalEnabledDrafts(); return; }
    if (event.target.closest('[data-cnc-close]')) { state.drawer = false; state.editor = {}; state.notice = ''; renderOverlays(); patchNotice(); return; }
    if (event.target.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]')) { state.confirm = null; renderOverlays(); return; }
    if (event.target.closest('[data-dwrt-confirm-accept]')) { acceptConfirmation(); return; }
    const mode = event.target.closest('[data-cnc-mode]');
    if (mode) { switchMode(mode.dataset.cncMode); return; }
    if (event.target.closest('[data-cnc-allowlist-add]')) { addAllowlistMember(); return; }
    if (event.target.closest('[data-cnc-allowlist-save]')) { saveAllowlistMembers(); return; }
    if (event.target.closest('[data-cnc-allowlist-toggle]')) { requestAllowlistToggle(); return; }
    if (event.target.closest('[data-cnc-allowlist-confirm]')) { confirmAllowlist(); return; }
    const allowlistRemove = event.target.closest('[data-cnc-allowlist-remove]');
    if (allowlistRemove) { removeAllowlistMember(allowlistRemove.dataset.cncAllowlistRemove); return; }
    if (event.target.closest('[data-cnc-create]')) { newEditor(); return; }
    if (event.target.closest('[data-cnc-save]')) { saveRule(); return; }
    const source = event.target.closest('[data-cnc-source]');
    if (source) {
      state.editor.source = source.dataset.cncSource;
      state.editor.mac = state.editor.source === 'manual' ? '' : clientOptions()[0]?.[0] || '';
      rememberDrawerMarkup();
      if (!patchDrawerRegion('[data-cnc-target-editor]', sourceEditorMarkup(state.editor, Boolean(state.editor.policyId)))) renderOverlays();
      return;
    }
    const scheduleMode = event.target.closest('[data-cnc-schedule-mode]');
    if (scheduleMode) {
      state.editor.scheduleMode = scheduleMode.dataset.cncScheduleMode === 'window' ? 'window' : 'always';
      rememberDrawerMarkup();
      const patched = patchDrawerRegion('[data-cnc-schedule-editor]', scheduleEditorMarkup(state.editor));
      if (!patched) renderOverlays();
      return;
    }
    const expiresMode = event.target.closest('[data-cnc-expires-mode]');
    if (expiresMode) {
      state.editor.expiresMode = expiresMode.dataset.cncExpiresMode === 'at' ? 'at' : 'never';
      /* 切到"到期"且还没填过时给一个默认值：明天此刻，省得用户从空控件里翻月份。 */
      if (state.editor.expiresMode === 'at' && !firstText(state.editor.expiresAt)) {
        state.editor.expiresAt = epochToLocalInput(Math.floor(Date.now() / 1000) + 86400);
      }
      rememberDrawerMarkup();
      if (!patchDrawerRegion('[data-cnc-expires-editor]', expiresEditorMarkup(state.editor))) renderOverlays();
      return;
    }
    const filter = event.target.closest('[data-cnc-filter]');
    if (filter) { state.filter = filter.dataset.cncFilter; patchTable(); return; }
    const toggle = event.target.closest('[data-cnc-toggle]');
    if (toggle) { toggleRule(findRule(toggle.dataset.cncToggle)); return; }
    const edit = event.target.closest('[data-cnc-edit]');
    if (edit) { newEditor(findRule(edit.dataset.cncEdit)); return; }
    const remove = event.target.closest('[data-cnc-delete]');
    if (remove) { const rule = findRule(remove.dataset.cncDelete); if (rule) requestDelete(rule); }
  }

  function onModeHostClick(event) {
    const mode = event.target.closest('[data-cnc-mode]');
    if (mode) switchMode(mode.dataset.cncMode);
  }

  function updateEditor(target) {
    const key = target.dataset.cncField;
    if (!key) return;
    state.editor[key] = target.type === 'checkbox' ? target.checked : target.type === 'number' ? Number(target.value || 0) : target.value;
    rememberDrawerMarkup();
  }

  function onInput(event) {
    const search = event.target.closest('[data-cnc-search]');
    if (search) { state.query = search.value; patchTable(); return; }
    const field = event.target.closest('[data-cnc-field]');
    if (field && !['checkbox', 'radio'].includes(field.type) && field.tagName !== 'SELECT') updateEditor(field);
  }

  function onChange(event) {
    const weekday = event.target.closest('[data-cnc-weekday]');
    if (weekday) {
      const day = Number(weekday.dataset.cncWeekday);
      const days = new Set(Array.isArray(state.editor.scheduleDays) ? state.editor.scheduleDays : []);
      if (weekday.checked) days.add(day); else days.delete(day);
      state.editor.scheduleDays = Array.from(days).sort((left, right) => left - right);
      weekday.closest('label')?.classList.toggle('is-active', weekday.checked);
      rememberDrawerMarkup();
      return;
    }
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
  modeHost?.addEventListener('click', onModeHostClick);
  stage?.classList.add('is-user-authentication');
  render();
  load();

  /* 可见性受控的轮询；有抽屉、确认弹窗或正在保存时跳过，避免刷掉用户填的内容。 */
  state.pollTimer = window.setInterval(() => {
    if (!state.mounted || document.hidden) return;
    if (state.loading || state.refreshing || state.saving) return;
    if (state.drawer || state.confirm) return;
    if (state.mode === 'white' && state.allowlistDirty) return;
    load(true);
  }, 20000);

  state.countdownTimer = window.setInterval(() => {
    if (!state.mounted || document.hidden || state.mode !== 'white' || !allowlistPending()) return;
    if (allowlistSecondsRemaining() > 0) {
      if (!state.saving) patchTable();
      return;
    }
    if (!state.loading && !state.refreshing && !state.saving) load(true);
  }, 1000);

  return {
    refresh() { return load(true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      window.clearInterval(state.pollTimer);
      window.clearInterval(state.countdownTimer);
      /* 路由离开：让 kit 回收本页传送到 portal 的抽屉与遮罩，别把遮罩留给下一页 */
      window.DWRT_UI_KIT?.unmount?.(root);
      root?.removeEventListener('click', onClick);
      root?.removeEventListener('input', onInput);
      root?.removeEventListener('change', onChange);
      document.removeEventListener('keydown', onKeyDown);
      modeHost?.removeEventListener('click', onModeHostClick);
      root?.replaceChildren();
      if (modeHost) { modeHost.replaceChildren(); modeHost.hidden = true; }
      root?.classList.remove('route-workspace', 'user-authentication-route-host', 'client-network-control-route-host');
      stage?.classList.remove('is-user-authentication');
    }
  };
}

export default { mount };
