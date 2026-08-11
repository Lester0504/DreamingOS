export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char])));
  const formatBytes = utils.formatBytes || ((value) => `${Math.max(0, Number(value) || 0)} B`);
  const formatRate = utils.formatRate || ((value) => `${Math.max(0, Number(value) || 0)} B/s`);
  const formatInteger = utils.formatInteger || ((value) => Math.round(Number(value) || 0).toLocaleString());
  const VERSION = '20260810-front-release-01';
  const REFRESH_MS = 5000;
  const WS_RECONCILE_MS = 30000;
  const ROUTE_STATUS_TOPIC = 'route.status';
  const WAN_METRICS_TOPIC = 'wan.metrics';
  const ROUTE_ENDPOINT = '/api/v1/route_status';
  const WANS_ENDPOINT = '/api/v1/network/wans';
  const FLOWS_ENDPOINT = '/api/v1/insights/flows/current?limit=1000';
  const POLICIES_ENDPOINT = '/api/v1/policy-engine/policy-table?include_default=0';
  const realtime = context.realtime || window.DWRTRealtime;

  const state = {
    mounted: true,
    loading: true,
    refreshing: false,
    routeEndpoint: 'unknown',
    route: {},
    wans: [],
    flows: [],
    flowMeta: {},
    policyRows: [],
    sourceReady: { wans: false, flows: false, policies: false },
    outletHistory: new Map(),
    data: null,
    query: '',
    action: '',
    path: '',
    sort: { key: 'active_flows', direction: 'desc' },
    outletKey: '',
    groupKey: '',
    ruleKey: '',
    timer: 0,
    seq: 0,
    lastWsAt: 0,
    wsUnsubscribes: []
  };

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (typeof value === 'object' && !Array.isArray(value)) {
        const nested = firstText(value.name, value.label, value.value, value.id);
        if (nested) return nested;
        continue;
      }
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }

  function optionalNumber(...values) {
    for (const value of values) {
      if (value === undefined || value === null || value === '') continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return null;
  }

  function number(...values) {
    return optionalNumber(...values) ?? 0;
  }

  function optionalBoolean(...values) {
    for (const value of values) {
      if (typeof value === 'boolean') return value;
      if (value === 1 || value === '1' || value === 'true') return true;
      if (value === 0 || value === '0' || value === 'false') return false;
    }
    return null;
  }

  function array(value, keys = []) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of [...keys, 'items', 'rows', 'data']) {
      if (Array.isArray(value[key])) return value[key];
    }
    return [];
  }

  function unwrap(value) {
    let current = value?.data ?? value ?? {};
    for (let index = 0; index < 3; index += 1) {
      if (!current || typeof current !== 'object' || Array.isArray(current) || !current.data || typeof current.data !== 'object') break;
      current = current.data;
    }
    return current || {};
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
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}),
      ...extra
    };
  }

  async function requestJson(url) {
    const response = await sessionFetch(`${url}${url.includes('?') ? '&' : '?'}v=${encodeURIComponent(VERSION)}`, {
      credentials: 'same-origin',
      cache: 'no-store',
      headers: authHeaders({ Accept: 'application/json' })
    });
    const text = await response.text();
    let json = {};
    try { json = text ? JSON.parse(text) : {}; } catch (_) { throw new Error('后端返回了无效 JSON'); }
    if (!response.ok || json?.ok === false) {
      const error = new Error(firstText(json?.error?.message, json?.message, `${response.status}`));
      error.status = response.status;
      throw error;
    }
    return unwrap(json);
  }

  function carrierLabel(value = {}) {
    const raw = firstText(value.carrier_name, value.isp, value.carrier, value.carrier_key).toLowerCase();
    if (/unicom|联通/.test(raw)) return '中国联通';
    if (/mobile|cmcc|移动/.test(raw)) return '中国移动';
    if (/telecom|ctcc|电信/.test(raw)) return '中国电信';
    if (/broadnet|广电/.test(raw)) return '中国广电';
    return firstText(value.carrier_name, value.isp, value.label, value.name, value.ifname, value.id, 'WAN');
  }

  function normalizeHealth(value = {}) {
    const runtime = value.runtime && typeof value.runtime === 'object' ? value.runtime : {};
    const text = firstText(value.status, value.state, runtime.status).toLowerCase();
    if (value.health === false || runtime.online === false || /down|offline|error|failed|bad/.test(text)) return 'bad';
    if (value.degraded === true || /warn|degraded|loss|busy/.test(text)) return 'warn';
    return 'good';
  }

  function flowWanId(flow = {}) {
    return firstText(flow.wan_id, flow.wan, flow.out_network_id, flow.wan_ifname, flow.out_interface, 'unknown');
  }

  function policyHit(flow = {}) {
    return flow.policy_verified === true || flow.policy_hit === true && flow.policy_match_exact !== false;
  }

  function rateSample(value) {
    if (!value || typeof value !== 'object') return optionalNumber(value);
    const direct = optionalNumber(value.value, value.total_rate, value.rate);
    if (direct !== null) return direct;
    const up = optionalNumber(value.up_rate, value.rate_up, value.tx_rate, value.up, value.tx);
    const down = optionalNumber(value.down_rate, value.rate_down, value.rx_rate, value.down, value.rx);
    return up === null && down === null ? null : number(up) + number(down);
  }

  function outletHistory(id, value, currentRate) {
    const supplied = [value.history, value.traffic, value.samples, value.rates]
      .find((items) => Array.isArray(items) && items.length);
    const suppliedValues = (supplied || []).map(rateSample).filter((item) => item !== null).slice(-20);
    if (suppliedValues.length >= 2) {
      state.outletHistory.set(id, suppliedValues);
      return suppliedValues;
    }
    const history = state.outletHistory.get(id) || [];
    history.push(Math.max(0, number(currentRate)));
    const next = history.slice(-20);
    state.outletHistory.set(id, next);
    return next;
  }

  function normalizeOutlets(route = {}) {
    const routeOutlets = [route.outlets, route.policy_outlets, route.wans].find((items) => Array.isArray(items) && items.length) || [];
    const source = routeOutlets.length ? routeOutlets : state.wans;
    const flowCounts = state.flows.reduce((counts, flow) => {
      const id = flowWanId(flow);
      counts.set(id, (counts.get(id) || 0) + 1);
      return counts;
    }, new Map());
    const seen = new Set();
    return source.map((value, index) => {
      const runtime = value.runtime && typeof value.runtime === 'object' ? value.runtime : {};
      const id = firstText(value.wan_id, value.ifname, value.id, value.name, `wan${index || ''}`);
      if (seen.has(id)) return null;
      seen.add(id);
      const connections = optionalNumber(value.connections, value.conn_count, value.active_flows, runtime.connections, flowCounts.get(id));
      const upRate = number(value.up_rate, value.rate_up, value.tx_rate, runtime.up_rate, runtime.tx_rate);
      const downRate = number(value.down_rate, value.rate_down, value.rx_rate, runtime.down_rate, runtime.rx_rate);
      return {
        id,
        name: carrierLabel(value),
        ifname: firstText(value.ifname, value.interface, value.name, id),
        ip: firstText(value.public_ip, value.ipv4, value.ip, runtime.ipv4, runtime.ip),
        health: normalizeHealth(value),
        up_rate: upRate,
        down_rate: downRate,
        up_bytes: number(value.up_bytes, value.tx_bytes, runtime.up_bytes, runtime.tx_bytes),
        down_bytes: number(value.down_bytes, value.rx_bytes, runtime.down_bytes, runtime.rx_bytes),
        connections,
        load: optionalNumber(value.load, runtime.load),
        history: outletHistory(id, value, upRate + downRate),
        raw: value
      };
    }).filter(Boolean);
  }

  function normalizeAction(value) {
    const text = firstText(value).toLowerCase();
    if (/vpn|tunnel/.test(text)) return 'vpn';
    if (/reject|drop|block|阻断|拒绝/.test(text)) return 'reject';
    if (/direct|bypass|直连|旁路/.test(text)) return 'direct';
    if (/balance|load|负载/.test(text)) return 'balance';
    if (/fallback|回退/.test(text)) return 'fallback';
    return 'route';
  }

  function normalizeRules(route = {}, outlets = []) {
    const routeRules = array(route.rules);
    const source = routeRules.length ? routeRules : state.policyRows.filter((row) => /pbr|policy.?route|策略路由/i.test(firstText(row.policy_type, row.type)));
    return source.map((value, index) => {
      const wanIds = firstText(value.wan_ids, value.wans);
      const target = firstText(value.target, value.path, value.interface, value.wan, wanIds, '--');
      const outlet = outlets.find((item) => item.id === target || item.ifname === target);
      const counterReady = optionalBoolean(value.counter_ready, value.counter_available);
      return {
        id: firstText(value.id, value.rule_id, value.name, `rule-${index}`),
        prio: optionalNumber(value.prio, value.priority),
        enabled: value.enabled !== false && value.disabled !== true,
        name: firstText(value.name, value.label, value.remark, `规则 ${index + 1}`),
        type: firstText(value.type, value.policy_type, 'policy'),
        match: firstText(value.match, value.matcher, value.source, value.destination, value.protocol, '--'),
        action: normalizeAction(firstText(value.action, value.target_type, value.mode)),
        target: outlet?.name || target,
        active_flows: optionalNumber(value.active_flows, value.steered_flows, value.connections, value.conn_count, value.flow_count),
        hit_count: counterReady === false ? null : optionalNumber(value.hit_count, value.hits, value.hit),
        last_hit: optionalNumber(value.last_hit, value.last_hit_at),
        counter_source: firstText(value.counter_source),
        counter_precision: firstText(value.counter_precision),
        counter_ready: counterReady,
        counter_verified: value.verified === true && value.policy_hit === true,
        up_rate: optionalNumber(value.up_rate, value.tx_rate),
        down_rate: optionalNumber(value.down_rate, value.rx_rate),
        remark: firstText(value.remark, value.comment),
        raw: value
      };
    });
  }

  function normalizeGroups(route = {}) {
    const source = array(route.policy_groups, ['groups']);
    return source.map((value, index) => ({
      id: firstText(value.id, value.name, `group-${index}`),
      name: firstText(value.name, value.label, `策略组 ${index + 1}`),
      mode: firstText(value.mode, value.type, 'route'),
      members: array(value.members),
      active_flows: optionalNumber(value.active_flows, value.steered_flows, value.connections, value.conn_count),
      hit_count: optionalNumber(value.hit_count, value.hits),
      up_rate: optionalNumber(value.up_rate, value.tx_rate),
      down_rate: optionalNumber(value.down_rate, value.rx_rate)
    }));
  }

  function normalizeData() {
    const route = state.route || {};
    const status = route.policy_status && typeof route.policy_status === 'object' ? route.policy_status : {};
    const outlets = normalizeOutlets(route);
    const rules = normalizeRules(route, outlets);
    const groups = normalizeGroups(route);
    const outletConnections = outlets.some((item) => item.connections !== null)
      ? outlets.reduce((sum, item) => sum + number(item.connections), 0)
      : null;
    const verifiedFlows = state.flows.filter(policyHit).length;
    const fullRuntime = state.routeEndpoint === 'available' && Boolean(route.policy_status);
    const flowPolicyEvidence = state.flowMeta.policy_hit_supported === true
      || state.flowMeta.capabilities?.policy_hit === true
      || state.flowMeta.capabilities?.policy_verified === true;
    const activeFlows = optionalNumber(
      status.active_flows,
      status.connections,
      route.active_flows,
      state.sourceReady.flows ? state.flowMeta.total : null,
      state.sourceReady.flows ? state.flowMeta.count : null,
      outletConnections
    );
    const steeredFlows = optionalNumber(
      status.steered_flows,
      status.steered_connections,
      route.steered_flows,
      flowPolicyEvidence ? verifiedFlows : null
    );
    const ruleCounterEvidence = rules.some((item) => item.hit_count !== null && item.counter_source);
    const counterSupported = optionalBoolean(status.counter_supported, route.counter_supported) ?? ruleCounterEvidence;
    const counterReady = optionalBoolean(status.counter_ready, route.counter_ready) ?? ruleCounterEvidence;
    const counterAvailable = counterSupported === true && counterReady === true;
    const runtimeRules = rules.map((item) => ({ ...item, hit_count: counterAvailable && item.counter_ready !== false ? item.hit_count : null }));
    const hitTotal = counterAvailable ? optionalNumber(status.hit_total, route.hit_total, runtimeRules.some((item) => item.hit_count !== null)
      ? runtimeRules.reduce((sum, item) => sum + number(item.hit_count), 0)
      : null) : null;
    const decisions = array(route.route_decisions, ['decisions']);
    const candidateDecisions = decisions.filter((item) => item.candidate === true && item.verified !== true && item.policy_hit !== true).length;
    const verifiedDecisions = decisions.filter((item) => item.verified === true && item.policy_hit === true).length;
    const lastHit = optionalNumber(status.last_hit_at, route.last_hit_at, ...runtimeRules.map((item) => item.last_hit));
    /*
     * 分流口径（Backend-to-Front-route-status-steering-fields.md）：
     * 后端现在把瞬时量与累计量分开并自描述，前端必须跟着分开，否则文案继续误导。
     *
     * 瞬时量（来自 conntrack fwmark）：active / steered / load_balance / bypass / unattributed
     * 累计量（core 推规则时会清零）：hit_total / kernel_cumulative_connections
     *
     * 两组**不可互为分母**。占比只能用瞬时量算，即 steered / active。
     *
     * 降级契约：conntrack 不可读时 steered/load_balance/bypass 是 `null` 而不是 0，
     * 必须显示「不可用」——显示 0 会又回到「看起来一条都没分流」的误导。
     * 所以下面一律用 optionalNumber 保留 null，不做 `|| 0` 兜底。
     */
    const steeredFlowsSupported = optionalBoolean(status.steered_flows_supported, route.steered_flows_supported);
    const loadBalanceFlows = optionalNumber(status.load_balance_flows, route.load_balance_flows);
    const unattributedFlows = optionalNumber(status.unattributed_flows, route.unattributed_flows);
    const bypassFlows = optionalNumber(status.bypass_flows, status.bypass_connections, route.bypass_flows);
    // 未分流 = bypass（后端直接给），旧固件没有该字段时才退回 active - steered。
    const unsteeredFlows = bypassFlows !== null
      ? bypassFlows
      : (activeFlows === null || steeredFlows === null ? null : Math.max(0, activeFlows - steeredFlows));
    return {
      available: fullRuntime ? route.available !== false : state.sourceReady.wans && outlets.length > 0,
      activeFlows,
      steeredFlows,
      // 瞬时 / 瞬时。分母用 hit_total 会得到无意义的比值。
      steerPercent: activeFlows && steeredFlows !== null ? steeredFlows / activeFlows * 100 : null,
      steeredFlowsSupported,
      steeredFlowsReason: firstText(status.steered_flows_reason, route.steered_flows_reason),
      loadBalanceFlows,
      unattributedFlows,
      flowCounterSource: firstText(status.flow_counter_source, route.flow_counter_source),
      kernelCumulativeConnections: optionalNumber(status.kernel_cumulative_connections, route.kernel_cumulative_connections),
      cumulativeCounterEpoch: firstText(status.cumulative_counter_epoch, route.cumulative_counter_epoch),
      unsteeredFlows,
      activeRules: optionalNumber(
        status.active_rules,
        route.rule_count,
        state.sourceReady.policies || fullRuntime ? runtimeRules.filter((item) => item.enabled).length : null
      ),
      bypassFlows,
      fallbackFlows: optionalNumber(status.fallback_flows, status.fallback_connections, route.fallback_flows),
      hitTotal,
      counterAvailable,
      counterSupported,
      counterReady,
      counterSource: firstText(status.counter_source, route.counter_source, ...runtimeRules.map((item) => item.counter_source)),
      counterPrecision: firstText(status.counter_precision, route.counter_precision, ...runtimeRules.map((item) => item.counter_precision)),
      counterReason: firstText(status.counter_reason, route.counter_reason, counterSupported === false ? 'counter_not_supported' : counterReady === false ? 'counter_not_ready' : ''),
      lastHit,
      candidateDecisions,
      verifiedDecisions,
      outlets,
      groups,
      rules: runtimeRules,
      fullRuntime
    };
  }

  function displayInteger(value) {
    return value === null || value === undefined ? '--' : formatInteger(value);
  }

  function displayPercent(value) {
    return value === null || value === undefined ? '--' : `${Number(value).toFixed(1)}%`;
  }

  function formatTimestamp(value) {
    const raw = Number(value) || 0;
    if (!raw) return '尚无命中';
    const timestamp = raw < 100000000000 ? raw * 1000 : raw;
    return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(timestamp);
  }

  function counterSourceLabel(value) {
    if (value === 'jmx_route_kernel') return 'jmx_route 内核计数';
    return value || '未声明来源';
  }

  function counterPrecisionLabel(value) {
    if (value === 'aggregate_rule_counter') return '规则级聚合计数';
    return value || '未声明精度';
  }

  function counterReasonLabel(value) {
    const labels = {
      no_route_rules: '当前没有可计数的路由规则',
      counter_not_supported: '当前固件不支持规则计数',
      counter_not_ready: '规则计数器尚未就绪'
    };
    return labels[value] || value || '后端未提供可验证的计数来源';
  }

  /* 瞬时分流计数的降级原因，来自 status.steered_flows_reason。 */
  function steeredReasonLabel(value) {
    const labels = {
      nf_conntrack_marks_unreadable: 'conntrack 标记不可读'
    };
    return labels[value] || value || '后端未说明原因';
  }

  function statusBadge(label, tone = 'muted') {
    return ui.statusBadgeMarkup?.(label, tone) || window.DWRT_UI_KIT?.statusBadgeMarkup?.(label, tone) || `<span class="policy-status-evidence-badge is-${escapeHtml(tone)}">${escapeHtml(label)}</span>`;
  }

  function icon(name) {
    const paths = {
      connections: '<circle cx="12" cy="12" r="9"></circle><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"></path>',
      target: '<circle cx="12" cy="12" r="8"></circle><circle cx="12" cy="12" r="3"></circle><path d="M12 2v3M12 19v3M2 12h3M19 12h3"></path>',
      rules: '<path d="M8 6h13M8 12h13M8 18h13"></path><path d="m3 6 .8.8L6 4.6M3 12l.8.8L6 10.6M3 18l.8.8L6 16.6"></path>',
      fallback: '<path d="M3 7h11a4 4 0 0 1 0 8H7"></path><path d="m7 11-4 4 4 4"></path><path d="M17 7l4 4-4 4"></path>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.connections}</svg>`;
  }

  function overviewMarkup(data) {
    /*
     * 分流卡片的副标题原本是一句话塞三个数：
     *   `N 条规则 · 当前 M 条 · 内核聚合 K 次`
     * 三个数里前两个是**瞬时值**（近 300 秒活跃流），第三个是**历史累计**
     * （各规则 hit_count 之和，来自内核计数器）。并列在同一行、量级又差几个数量级,
     * 读者无法分辨时间维度——用户就是这么问出「我选了按运营商分流，怎么可能是 0」的。
     *
     * 「内核聚合」描述的是实现机制（内核态计数器聚合），不是用户关心的事实,
     * 这个词在中文里既不指向"规则命中"也不指向"累计"。改为「累计命中」。
     *
     * 瞬时为 0 而累计命中很大，本身就是异常信号：规则明显生效过，但当前一条都没匹配。
     * 与其让用户自己怀疑，不如显式说出来。
     * （0.0% 的数据侧根因在后端把 `steered_flows` 写死为 0,
     *  见 Handoff/Acceptance-to-Backend-steered-flows-hardcoded-zero.md，非本卡片可修。）
     */

    return overviewCards(data);
  }

  /* 瞬时段与累计段分开写，累计段降级为脚注语气，并在两者矛盾时给出解释。 */
  function policyDetailText(data) {
    /*
     * conntrack 不可读时后端给 null 并附 steered_flows_reason。
     * 这一态必须说「不可用」，不能落到下面任何一条含数字的分支——
     * 显示 0 会让用户以为「一条都没分流」，而真实情况是「没量到」。
     */
    if (data.steeredFlowsSupported === false || data.steeredFlows === null) {
      const reason = steeredReasonLabel(data.steeredFlowsReason);
      return `${displayInteger(data.activeRules)} 条规则 · 分流计数不可用（${reason}）`;
    }
    const instant = `${displayInteger(data.activeRules)} 条规则 · 当前 ${displayInteger(data.steeredFlows)} 条活跃`;
    if (!data.counterAvailable) return `${instant} · 命中未采集`;
    const cumulative = `规则累计命中 ${displayInteger(data.hitTotal)} 次`;
    if (data.steeredFlows === 0 && number(data.hitTotal) > 0) {
      return `${instant}（当前无活跃分流连接，但${cumulative}）`;
    }
    return `${instant} · ${cumulative}`;
  }

  /* 瞬时 0 + 累计非 0 是需要用户注意的矛盾态，不能报成 ok 的绿色。 */
  function policyTone(data) {
    if (data.steeredFlowsSupported === false || data.steeredFlows === null) return 'warn';
    if (!data.counterAvailable) return 'warn';
    if (data.steeredFlows === 0 && number(data.hitTotal) > 0) return 'warn';
    return 'ok';
  }

  /*
   * 「未分流」= bypass_flows，即未被任何规则打标的连接。负载均衡命中的连接
   * 既不算显式分流也不算未分流，必须单独点出来，否则 30.1 上 683 条负载均衡
   * 连接完全看不见，用户只看到 65 条显式分流，会以为分流基本没生效。
   *
   * 与 policyDetailText 同理：这个函数必须同时被首次渲染和轮询补丁复用，
   * 只改一处会让下一个轮询周期把旧措辞写回 DOM。
   */
  function unsteeredDetailText(data) {
    if (data.loadBalanceFlows === null) return '当前未匹配显式分流';
    return `未匹配任何规则 · 负载均衡另计 ${displayInteger(data.loadBalanceFlows)} 条`;
  }

  function overviewCards(data) {
    const fallbackValue = data.bypassFlows === null && data.fallbackFlows === null
      ? '--'
      : `${displayInteger(data.bypassFlows)} / ${displayInteger(data.fallbackFlows)}`;
    const items = [
      { key: 'active', label: '活跃连接', value: displayInteger(data.activeFlows), detail: data.available ? '当前连接总数' : '未启用', tone: 'info', icon: icon('connections') },
      { key: 'policy', label: '策略分流', value: displayPercent(data.steerPercent), detail: policyDetailText(data), tone: policyTone(data), icon: icon('target') },
      { key: 'unsteered', label: '未分流连接', value: displayInteger(data.unsteeredFlows), detail: unsteeredDetailText(data), tone: 'neutral', icon: icon('rules') },
      { key: 'fallback', label: '旁路回退', value: fallbackValue, detail: data.fullRuntime ? '实时运行态' : '等待完整运行态', tone: 'warn', icon: icon('fallback') }
    ];
    if (typeof ui.overviewCardsMarkup === 'function') return ui.overviewCardsMarkup(items, { label: '分流状态概览', className: 'policy-status-summary' });
    return `<section class="dwrt-kit-overview-grid policy-status-summary" aria-label="分流状态概览">${items.map((item) => `<article class="dwrt-kit-overview-card is-${item.tone}"><div class="dwrt-kit-overview-content"><span class="dwrt-kit-overview-label">${escapeHtml(item.label)}</span><strong data-dwrt-overview-value="${item.key}">${escapeHtml(item.value)}</strong><small data-dwrt-overview-detail="${item.key}">${escapeHtml(item.detail)}</small></div><span class="dwrt-kit-overview-icon">${item.icon}</span></article>`).join('')}</section>`;
  }

  function outletCard(outlet) {
    const totalRate = outlet.up_rate + outlet.down_rate;
    const maxRate = Math.max(1, totalRate);
    const upWidth = Math.max(outlet.up_rate ? 2 : 0, Math.min(100, outlet.up_rate / maxRate * 100));
    const downWidth = Math.max(outlet.down_rate ? 2 : 0, Math.min(100, outlet.down_rate / maxRate * 100));
    return `<article class="policy-status-outlet dwrt-kit-glass-surface policy-status-glass is-${outlet.health}" data-policy-outlet="${escapeHtml(outlet.id)}">
      <header><div><span class="policy-status-dot"></span><strong>${escapeHtml(outlet.name)}</strong></div><span>#${escapeHtml(outlet.ifname || outlet.id)}</span></header>
      <div class="policy-status-rate"><strong data-outlet-total>${escapeHtml(formatRate(totalRate))}</strong><span>${escapeHtml(outlet.ip || '未获取公网 IP')}</span></div>
      <div class="policy-status-speed"><span>UP</span><i><b class="is-up" data-outlet-up-bar style="width:${upWidth}%"></b></i><em data-outlet-up>${escapeHtml(formatRate(outlet.up_rate))}</em></div>
      <div class="policy-status-speed"><span>DOWN</span><i><b class="is-down" data-outlet-down-bar style="width:${downWidth}%"></b></i><em data-outlet-down>${escapeHtml(formatRate(outlet.down_rate))}</em></div>
      <div class="policy-status-trend" data-outlet-trend>${trendMarkup(outlet)}</div>
      <footer><span data-outlet-connections>${displayInteger(outlet.connections)} 连接</span><span data-outlet-bytes>${escapeHtml(formatBytes(outlet.up_bytes + outlet.down_bytes))}</span></footer>
    </article>`;
  }

  function trendPath(values = []) {
    if (values.length < 2) return '';
    const width = 240;
    const top = 3;
    const bottom = 33;
    const min = Math.min(...values);
    const max = Math.max(...values);
    const spread = Math.max(1, max - min);
    const points = values.map((value, index) => ({
      x: index / Math.max(1, values.length - 1) * width,
      y: bottom - (value - min) / spread * (bottom - top)
    }));
    let path = `M ${points[0].x.toFixed(2)} ${points[0].y.toFixed(2)}`;
    for (let index = 1; index < points.length - 1; index += 1) {
      const point = points[index];
      const next = points[index + 1];
      path += ` Q ${point.x.toFixed(2)} ${point.y.toFixed(2)} ${((point.x + next.x) / 2).toFixed(2)} ${((point.y + next.y) / 2).toFixed(2)}`;
    }
    const last = points[points.length - 1];
    path += ` T ${last.x.toFixed(2)} ${last.y.toFixed(2)}`;
    return path;
  }

  function trendMarkup(outlet) {
    const values = Array.isArray(outlet.history) ? outlet.history : [];
    const path = trendPath(values);
    if (!path) return '<span>正在采样趋势</span>';
    return `<svg viewBox="0 0 240 36" preserveAspectRatio="none" aria-label="${escapeHtml(outlet.name)} 吞吐趋势"><path d="${path}"></path></svg>`;
  }

  function groupMode(value) {
    const text = firstText(value).toLowerCase();
    if (/weighted|balance/.test(text)) return '负载均衡';
    if (/backup|failover/.test(text)) return '主备';
    if (/vpn|tunnel/.test(text)) return 'VPN';
    return firstText(value, '--');
  }

  function groupCard(group) {
    const members = group.members;
    const totalWeight = Math.max(1, members.reduce((sum, item) => sum + number(item.weight), 0));
    return `<article class="policy-status-group dwrt-kit-glass-surface policy-status-glass" data-policy-group="${escapeHtml(group.id)}">
      <header><div><span>策略组</span><strong>${escapeHtml(group.name)}</strong></div><em>${escapeHtml(groupMode(group.mode))}</em></header>
      <div class="policy-status-group-track">${members.map((member, index) => `<span class="tone-${index % 4}" style="width:${Math.max(6, number(member.weight) / totalWeight * 100)}%">${escapeHtml(firstText(member.name, member.id, '--'))}</span>`).join('')}</div>
      <footer><span data-group-flows>${displayInteger(group.active_flows)} 分流连接</span><span data-group-hits>${displayInteger(group.hit_count)} 命中</span><span data-group-rate>${escapeHtml(formatRate(number(group.down_rate) + number(group.up_rate)))}</span></footer>
    </article>`;
  }

  function actionLabel(action) {
    return ({ route: '固定出口', balance: '负载均衡', vpn: 'VPN', direct: '直连', reject: '阻断', fallback: '回退' })[action] || action || '--';
  }

  function filteredRules() {
    const data = state.data || { rules: [] };
    const query = state.query.trim().toLowerCase();
    const direction = state.sort.direction === 'asc' ? 1 : -1;
    return data.rules.filter((rule) => {
      const text = `${rule.name} ${rule.match} ${rule.target} ${rule.remark}`.toLowerCase();
      if (query && !text.includes(query)) return false;
      if (state.action && rule.action !== state.action) return false;
      if (state.path && rule.target !== state.path) return false;
      return true;
    }).sort((left, right) => {
      const a = left[state.sort.key];
      const b = right[state.sort.key];
      if (typeof a === 'number' || typeof b === 'number') return (number(a) - number(b)) * direction;
      return String(a || '').localeCompare(String(b || '')) * direction;
    });
  }

  function sortButton(key, label) {
    const active = state.sort.key === key;
    return `<button type="button" data-policy-status-sort="${key}" class="${active ? 'is-active' : ''}">${escapeHtml(label)}<span>${active ? (state.sort.direction === 'asc' ? '↑' : '↓') : '↕'}</span></button>`;
  }

  function runtimeEvidenceMarkup(data = state.data || {}) {
    const candidateNote = data.candidateDecisions
      ? `当前另有 ${formatInteger(data.candidateDecisions)} 条未验证候选，不计入命中。`
      : '未验证候选不会计入命中。';
    if (!data.counterAvailable) {
      return `<div class="policy-status-runtime-evidence is-warning" data-policy-runtime-evidence role="status"><div>${statusBadge('命中未采集', 'warning')}<strong>${escapeHtml(counterReasonLabel(data.counterReason))}</strong></div><span>${escapeHtml(candidateNote)}</span></div>`;
    }
    return `<div class="policy-status-runtime-evidence" data-policy-runtime-evidence role="status"><div>${statusBadge('聚合计数', 'success')}<strong>${escapeHtml(counterSourceLabel(data.counterSource))}</strong></div><span>${escapeHtml(counterPrecisionLabel(data.counterPrecision))} · 最近命中 ${escapeHtml(formatTimestamp(data.lastHit))} · ${escapeHtml(candidateNote)}</span></div>`;
  }

  function ruleRows() {
    const rows = filteredRules();
    if (!rows.length) return '<tr><td colspan="6" class="dwrt-kit-table-empty">没有匹配的分流规则</td></tr>';
    return rows.map((rule) => `<tr data-policy-rule="${escapeHtml(rule.id)}" class="${rule.enabled ? '' : 'is-disabled'}">
      <td>${rule.prio === null ? '--' : formatInteger(rule.prio)}</td>
      <td><span class="policy-status-rule-name"><strong>${escapeHtml(rule.name)}</strong><small>${escapeHtml(rule.remark || rule.type)}</small></span></td>
      <td class="policy-status-matcher">${escapeHtml(rule.match)}</td>
      <td><span class="policy-status-action is-${escapeHtml(rule.action)}">${escapeHtml(actionLabel(rule.action))}</span><small>${escapeHtml(rule.target)}</small></td>
      <td><span class="policy-status-rule-rate"><strong data-rule-rate>${rule.down_rate === null && rule.up_rate === null ? '--' : escapeHtml(formatRate(number(rule.down_rate) + number(rule.up_rate)))}</strong><small data-rule-flows>${displayInteger(rule.active_flows)} 分流连接</small></span></td>
      <td><span class="policy-status-rule-hit"><strong class="policy-status-hit" data-rule-hits>${displayInteger(rule.hit_count)}</strong><small data-rule-last-hit>${rule.hit_count === null ? '未采集' : formatTimestamp(rule.last_hit)}</small></span></td>
    </tr>`).join('');
  }

  function rulesTable() {
    const paths = [...new Set((state.data?.rules || []).map((rule) => rule.target).filter((value) => value && value !== '--'))];
    return `<section class="policy-status-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap policy-status-glass">
      <div class="dwrt-kit-table-toolbar policy-status-toolbar">
        <div class="dwrt-kit-table-title"><strong>分流规则</strong><span data-policy-rule-count>${filteredRules().length} / ${state.data?.rules.length || 0} 条</span></div>
        <label class="policy-status-search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"></circle><path d="m20 20-3.5-3.5"></path></svg><input type="search" data-policy-status-search value="${escapeHtml(state.query)}" placeholder="搜索规则、匹配对象、出口" aria-label="搜索分流规则"></label>
        <label class="policy-status-filter dwrt-kit-field" data-dwrt-component="field"><select data-policy-status-filter="action" aria-label="筛选动作"><option value="">全部动作</option>${['route', 'balance', 'vpn', 'direct', 'reject', 'fallback'].map((action) => `<option value="${action}" ${state.action === action ? 'selected' : ''}>${actionLabel(action)}</option>`).join('')}</select></label>
        <label class="policy-status-filter dwrt-kit-field" data-dwrt-component="field"><select data-policy-status-filter="path" aria-label="筛选出口"><option value="">全部出口</option>${paths.map((path) => `<option value="${escapeHtml(path)}" ${state.path === path ? 'selected' : ''}>${escapeHtml(path)}</option>`).join('')}</select></label>
      </div>
      ${runtimeEvidenceMarkup()}
      <div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table"><thead><tr><th>${sortButton('prio', '优先级')}</th><th>${sortButton('name', '分流规则')}</th><th>匹配对象</th><th>出口通道</th><th>${sortButton('active_flows', '状态速率')}</th><th>${sortButton('hit_count', '聚合命中')}</th></tr></thead><tbody>${ruleRows()}</tbody></table></div>
    </section>`;
  }

  function renderStructure() {
    if (!root || !state.data) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'policy-status-route-host');
    root.innerHTML = `<section class="policy-status-shell">
      ${overviewMarkup(state.data)}
      <section class="policy-status-outlets" aria-label="出口状态">${state.data.outlets.map(outletCard).join('') || '<div class="policy-status-empty" data-dwrt-component="state-panel" data-dwrt-state="empty" data-dwrt-surface="stable-glass"><strong>暂无出口状态</strong></div>'}</section>
      <section class="policy-status-groups" aria-label="策略组状态">${state.data.groups.map(groupCard).join('') || '<div class="policy-status-empty" data-dwrt-component="state-panel" data-dwrt-state="empty" data-dwrt-surface="stable-glass"><strong>暂无策略组状态</strong><p>等待后端返回真实策略组运行态。</p></div>'}</section>
      ${rulesTable()}
    </section>`;
    bindEvents();
    ui.mountAll?.(root);
    state.outletKey = outletStructureKey();
    state.groupKey = groupStructureKey();
    state.ruleKey = ruleStructureKey();
  }

  function structureKey(items, fields) {
    return items.map((item) => fields.map((field) => {
      const value = typeof field === 'function' ? field(item) : item[field];
      return Array.isArray(value) ? JSON.stringify(value) : firstText(value);
    }).join('\u001f')).sort().join('\u001e');
  }

  function outletStructureKey() {
    return structureKey(state.data?.outlets || [], ['id', 'name', 'ifname', 'ip']);
  }

  function groupStructureKey() {
    return structureKey(state.data?.groups || [], [
      'id',
      'name',
      'mode',
      (item) => item.members.map((member) => [firstText(member.id, member.name), number(member.weight)])
    ]);
  }

  function ruleStructureKey() {
    return structureKey(state.data?.rules || [], ['id', 'prio', 'enabled', 'name', 'type', 'match', 'action', 'target', 'remark']);
  }

  function patchOverview() {
    const data = state.data;
    const fallback = data.bypassFlows === null && data.fallbackFlows === null ? '--' : `${displayInteger(data.bypassFlows)} / ${displayInteger(data.fallbackFlows)}`;
    const values = {
      active: [displayInteger(data.activeFlows), data.available ? '当前连接总数' : '未启用'],
      /* 轮询补丁必须复用同一个措辞函数。这里原本抄了一份 `overviewMarkup()` 的文案,
       * 只改渲染那一处的话，下一个轮询周期就会把旧措辞写回 DOM。 */
      policy: [displayPercent(data.steerPercent), policyDetailText(data)],
      unsteered: [displayInteger(data.unsteeredFlows), unsteeredDetailText(data)],
      fallback: [fallback, data.fullRuntime ? '实时运行态' : '等待完整运行态']
    };
    Object.entries(values).forEach(([key, pair]) => {
      const value = root.querySelector(`[data-dwrt-overview-value="${key}"]`);
      const detail = root.querySelector(`[data-dwrt-overview-detail="${key}"]`);
      if (value) value.textContent = pair[0];
      if (detail) detail.textContent = pair[1];
    });
    /* 语气必须跟着文案一起变。只改文字的话，矛盾态（瞬时 0 + 累计非 0）
     * 会在轮询后显示成一张绿色卡片配一句警示语。 */
    const policyCard = root.querySelector('[data-dwrt-overview-card="policy"]') ||
      root.querySelector('[data-dwrt-overview-detail="policy"]')?.closest('.dwrt-kit-overview-card');
    if (policyCard) {
      policyCard.classList.remove('is-neutral', 'is-info', 'is-ok', 'is-warn', 'is-bad');
      policyCard.classList.add(`is-${policyTone(state.data)}`);
    }
  }

  function patchDynamic(options = {}) {
    patchOverview();
    patchRuntimeEvidence();
    if (outletStructureKey() !== state.outletKey) renderOutlets();
    else patchOutlets();
    if (groupStructureKey() !== state.groupKey) renderGroups();
    else patchGroups();
    if (ruleStructureKey() !== state.ruleKey) renderRulesTable();
    else patchRuleRows();
  }

  function patchRuntimeEvidence() {
    const current = root.querySelector('[data-policy-runtime-evidence]');
    if (current) current.outerHTML = runtimeEvidenceMarkup();
  }

  function patchOutlets() {
    state.data.outlets.forEach((outlet) => {
      const card = root.querySelector(`[data-policy-outlet="${CSS.escape(outlet.id)}"]`);
      if (!card) return;
      card.classList.remove('is-good', 'is-warn', 'is-bad');
      card.classList.add(`is-${outlet.health}`);
      const total = outlet.up_rate + outlet.down_rate;
      const max = Math.max(1, total);
      const values = {
        '[data-outlet-total]': formatRate(total),
        '[data-outlet-up]': formatRate(outlet.up_rate),
        '[data-outlet-down]': formatRate(outlet.down_rate),
        '[data-outlet-connections]': `${displayInteger(outlet.connections)} 连接`,
        '[data-outlet-bytes]': formatBytes(outlet.up_bytes + outlet.down_bytes),
        '[data-outlet-trend]': trendMarkup(outlet)
      };
      Object.entries(values).forEach(([selector, value]) => {
        const node = card.querySelector(selector);
        if (!node) return;
        if (selector === '[data-outlet-trend]') node.innerHTML = value;
        else node.textContent = value;
      });
      const upBar = card.querySelector('[data-outlet-up-bar]');
      const downBar = card.querySelector('[data-outlet-down-bar]');
      if (upBar) upBar.style.width = `${Math.max(outlet.up_rate ? 2 : 0, Math.min(100, outlet.up_rate / max * 100))}%`;
      if (downBar) downBar.style.width = `${Math.max(outlet.down_rate ? 2 : 0, Math.min(100, outlet.down_rate / max * 100))}%`;
    });
  }

  function patchGroups() {
    state.data.groups.forEach((group) => {
      const card = root.querySelector(`[data-policy-group="${CSS.escape(group.id)}"]`);
      if (!card) return;
      const values = {
        '[data-group-flows]': `${displayInteger(group.active_flows)} 分流连接`,
        '[data-group-hits]': `${displayInteger(group.hit_count)} 命中`,
        '[data-group-rate]': formatRate(number(group.down_rate) + number(group.up_rate))
      };
      Object.entries(values).forEach(([selector, value]) => { const node = card.querySelector(selector); if (node) node.textContent = value; });
    });
  }

  function renderOutlets() {
    const section = root.querySelector('.policy-status-outlets');
    if (!section) return;
    section.innerHTML = state.data.outlets.map(outletCard).join('') || '<div class="policy-status-empty" data-dwrt-component="state-panel" data-dwrt-state="empty" data-dwrt-surface="stable-glass"><strong>暂无出口状态</strong></div>';
    state.outletKey = outletStructureKey();
    ui.mountAll?.(section);
  }

  function renderGroups() {
    const section = root.querySelector('.policy-status-groups');
    if (!section) return;
    section.innerHTML = state.data.groups.map(groupCard).join('') || '<div class="policy-status-empty" data-dwrt-component="state-panel" data-dwrt-state="empty" data-dwrt-surface="stable-glass"><strong>暂无策略组状态</strong><p>等待后端返回真实策略组运行态。</p></div>';
    state.groupKey = groupStructureKey();
    ui.mountAll?.(section);
  }

  function renderRulesTable() {
    const current = root.querySelector('.policy-status-table');
    if (!current) return;
    current.outerHTML = rulesTable();
    state.ruleKey = ruleStructureKey();
    const next = root.querySelector('.policy-status-table');
    bindRuleEvents();
    ui.mountAll?.(next);
  }

  function patchRuleRows() {
    const rules = new Map(state.data.rules.map((rule) => [rule.id, rule]));
    root.querySelectorAll('[data-policy-rule]').forEach((row) => {
      const rule = rules.get(row.dataset.policyRule);
      if (!rule) return;
      row.classList.toggle('is-disabled', !rule.enabled);
      const rate = row.querySelector('[data-rule-rate]');
      const flows = row.querySelector('[data-rule-flows]');
      const hits = row.querySelector('[data-rule-hits]');
      const lastHit = row.querySelector('[data-rule-last-hit]');
      if (rate) rate.textContent = rule.down_rate === null && rule.up_rate === null ? '--' : formatRate(number(rule.down_rate) + number(rule.up_rate));
      if (flows) flows.textContent = `${displayInteger(rule.active_flows)} 分流连接`;
      if (hits) hits.textContent = displayInteger(rule.hit_count);
      if (lastHit) lastHit.textContent = rule.hit_count === null ? '未采集' : formatTimestamp(rule.last_hit);
    });
    const count = root.querySelector('[data-policy-rule-count]');
    if (count) count.textContent = `${filteredRules().length} / ${state.data.rules.length} 条`;
  }

  function wanKey(value = {}, index = 0) {
    return firstText(value.wan_id, value.ifname, value.interface, value.name, value.id, `wan${index || ''}`);
  }

  function mergeWanRows(base = [], incoming = [], options = {}) {
    const live = new Map();
    array(incoming, ['wans', 'interfaces']).forEach((wan, index) => {
      const key = wanKey(wan, index);
      if (key) live.set(key, wan);
    });
    if (!live.size) return base;
    const used = new Set();
    const merged = array(base).map((wan, index) => {
      const key = wanKey(wan, index);
      const current = live.get(key);
      if (!current) return wan;
      used.add(key);
      const merged = {
        ...wan,
        ...current,
        runtime: {
          ...(wan.runtime && typeof wan.runtime === 'object' ? wan.runtime : {}),
          ...(current.runtime && typeof current.runtime === 'object' ? current.runtime : {})
        }
      };
      if (options.preserveConnections) {
        merged.connections = optionalNumber(wan.connections, wan.conn_count, wan.active_flows, wan.runtime?.connections);
        if (merged.runtime && typeof merged.runtime === 'object') {
          merged.runtime.connections = optionalNumber(wan.runtime?.connections, wan.connections, wan.conn_count, wan.active_flows);
        }
      }
      return merged;
    });
    live.forEach((wan, key) => { if (!used.has(key)) merged.push(wan); });
    return merged;
  }

  function commitRealtime() {
    state.lastWsAt = Date.now();
    state.data = normalizeData();
    if (state.loading) {
      state.loading = false;
      renderStructure();
    } else {
      patchDynamic();
    }
  }

  function applyRouteStatusRealtime(payload) {
    if (!state.mounted) return;
    const route = unwrap(payload);
    if (!route || typeof route !== 'object' || (!route.policy_status && !Array.isArray(route.wans))) return;
    state.route = {
      ...state.route,
      ...route,
      policy_status: route.policy_status && typeof route.policy_status === 'object'
        ? { ...(state.route?.policy_status || {}), ...route.policy_status }
        : state.route?.policy_status
    };
    state.routeEndpoint = 'available';
    if (Array.isArray(route.wans)) {
      state.wans = mergeWanRows(state.wans, route.wans);
      state.sourceReady.wans = true;
    }
    commitRealtime();
  }

  function applyWanMetricsRealtime(payload) {
    if (!state.mounted) return;
    const rows = array(unwrap(payload), ['wans', 'interfaces']);
    if (!rows.length) return;
    state.wans = mergeWanRows(state.wans, rows, { preserveConnections: true });
    state.sourceReady.wans = true;
    if (Array.isArray(state.route?.wans)) state.route = { ...state.route, wans: mergeWanRows(state.route.wans, rows, { preserveConnections: true }) };
    if (Array.isArray(state.route?.policy_groups)) {
      const rates = new Map(rows.map((wan, index) => [wanKey(wan, index), wan]));
      state.route = {
        ...state.route,
        policy_groups: state.route.policy_groups.map((group) => {
          const members = array(group.members).map((member, index) => {
            const live = rates.get(wanKey(member, index));
            return live ? { ...member, ...live } : member;
          });
          const liveMembers = members.filter((member, index) => rates.has(wanKey(member, index)));
          if (!liveMembers.length) return group;
          return {
            ...group,
            members,
            up_rate: liveMembers.reduce((sum, member) => sum + number(member.up_rate, member.tx_rate, member.runtime?.up_rate), 0),
            down_rate: liveMembers.reduce((sum, member) => sum + number(member.down_rate, member.rx_rate, member.runtime?.down_rate), 0)
          };
        })
      };
    }
    commitRealtime();
  }

  function subscribeRealtime() {
    if (!realtime || typeof realtime.subscribe !== 'function' || state.wsUnsubscribes.length) return;
    state.wsUnsubscribes = [
      realtime.subscribe(ROUTE_STATUS_TOPIC, applyRouteStatusRealtime),
      realtime.subscribe(WAN_METRICS_TOPIC, applyWanMetricsRealtime)
    ];
  }

  function unsubscribeRealtime() {
    state.wsUnsubscribes.splice(0).forEach((unsubscribe) => {
      try { unsubscribe(); } catch (_) {}
    });
  }

  function renderRuleBody() {
    const tbody = root.querySelector('.policy-status-table tbody');
    const count = root.querySelector('[data-policy-rule-count]');
    const rows = filteredRules();
    if (tbody) tbody.innerHTML = ruleRows();
    if (count) count.textContent = `${rows.length} / ${state.data?.rules.length || 0} 条`;
  }

  function bindEvents() {
    bindRuleEvents();
  }

  function bindRuleEvents() {
    const search = root.querySelector('[data-policy-status-search]');
    search?.addEventListener('input', () => { state.query = search.value; renderRuleBody(); });
    root.querySelectorAll('[data-policy-status-filter]').forEach((select) => select.addEventListener('change', () => {
      state[select.dataset.policyStatusFilter] = select.value;
      renderRuleBody();
    }));
    root.querySelectorAll('[data-policy-status-sort]').forEach((button) => button.addEventListener('click', () => {
      const key = button.dataset.policyStatusSort;
      state.sort = state.sort.key === key ? { key, direction: state.sort.direction === 'asc' ? 'desc' : 'asc' } : { key, direction: 'desc' };
      renderRulesTable();
    }));
  }

  async function loadRouteStatus() {
    if (state.routeEndpoint === 'missing') return {};
    try {
      const data = await requestJson(ROUTE_ENDPOINT);
      state.routeEndpoint = 'available';
      return data;
    } catch (error) {
      if (Number(error.status) === 404) {
        state.routeEndpoint = 'missing';
        return {};
      }
      throw error;
    }
  }

  async function refresh() {
    if (!state.mounted || state.refreshing) return;
    const wsFresh = state.lastWsAt && Date.now() - state.lastWsAt < WS_RECONCILE_MS;
    state.refreshing = true;
    const seq = ++state.seq;
    try {
      const [route] = await Promise.allSettled([loadRouteStatus()]);
      const routeValue = route.status === 'fulfilled' ? route.value : {};
      const hasStandardContract = Boolean(routeValue?.policy_status || Array.isArray(routeValue?.wans));
      const fallbackResults = hasStandardContract
        ? []
        : await Promise.allSettled([requestJson(WANS_ENDPOINT), requestJson(FLOWS_ENDPOINT), requestJson(POLICIES_ENDPOINT)]);
      const [wans, flows, policies] = fallbackResults;
      if (!state.mounted || seq !== state.seq) return;
      if (route.status === 'fulfilled') state.route = route.value;
      if (wans?.status === 'fulfilled') {
        state.wans = array(wans.value, ['wans', 'interfaces']);
        state.sourceReady.wans = true;
      }
      if (flows?.status === 'fulfilled') {
        state.flows = array(flows.value, ['flows', 'connections', 'items']);
        state.flowMeta = flows.value;
        state.sourceReady.flows = true;
      }
      if (policies?.status === 'fulfilled') {
        state.policyRows = array(policies.value, ['rows', 'items', 'policies']);
        state.sourceReady.policies = true;
      }
      state.data = normalizeData();
      if (state.loading) {
        state.loading = false;
        renderStructure();
      } else {
        patchDynamic();
      }
    } catch (error) {
      console.error('[policy-status] refresh failed', error);
      if (state.mounted && seq === state.seq && state.loading) {
        state.loading = false;
        state.data = normalizeData();
        renderStructure();
      }
    } finally {
      if (seq === state.seq) state.refreshing = false;
      if (state.mounted && seq === state.seq) {
        clearTimeout(state.timer);
        state.timer = window.setTimeout(refresh, wsFresh ? WS_RECONCILE_MS : REFRESH_MS);
      }
    }
  }

  root.hidden = false;
  root.classList.add('route-workspace', 'policy-status-route-host');
  root.innerHTML = '<section class="policy-status-shell"><div class="policy-status-loading">正在读取分流状态…</div></section>';
  subscribeRealtime();
  refresh();

  return {
    unmount() {
      state.mounted = false;
      state.seq += 1;
      clearTimeout(state.timer);
      unsubscribeRealtime();
      root?.replaceChildren();
      root?.classList.remove('policy-status-route-host', 'route-workspace');
    }
  };
}

export default { mount };
