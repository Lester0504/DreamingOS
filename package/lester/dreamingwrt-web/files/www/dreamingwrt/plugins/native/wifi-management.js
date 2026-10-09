import { channelAiSidebar, channelAiResults } from './wifi-channel-ai.js?v=20260905-channel-ai-01';
import { buildManagedMloPlan } from './wifi-mlo-write.js?v=20260906-mlo-write-01';

const VERSION = '20261007-operation-feedback-01';

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const item = context.item || {};
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const stage = root?.closest('.console-stage');
  const isStatus = item.id === 'wireless-status';
  const ENDPOINT = isStatus ? '/api/v1/wifi/status' : '/api/v1/wifi/config';
  const BANDS = [
    { id: '2g', label: '2.4 GHz', range: '2412-2484 MHz', widths: [20, 40], channels: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14] },
    { id: '5g', label: '5 GHz', range: '5180-5885 MHz', widths: [20, 40, 80, 160, 240], channels: [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165] },
    { id: '6g-low', band: '6g', label: '6 GHz', range: '5935-6515 MHz', widths: [20, 40, 80, 160, 320], channels: [1, 2, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125] },
    { id: '6g-high', band: '6g', label: '6 GHz', range: '6535-7115 MHz', widths: [20, 40, 80, 160, 320], channels: [129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189, 193, 197, 201, 205, 209, 213, 217, 221, 225, 229, 233] }
  ];
  const SECURITY = [
    ['open', '开放'], ['wpa2-personal', 'WPA2 Personal'], ['wpa2-wpa3', 'WPA2 / WPA3'],
    ['wpa3-personal', 'WPA3 Personal'], ['wpa2-enterprise', 'WPA2 Enterprise'],
    ['wpa2-wpa3-enterprise', 'WPA2 / WPA3 Enterprise'], ['wpa3-enterprise', 'WPA3 Enterprise']
  ];

  const state = {
    mounted: true,
    seq: 0,
    loading: true,
    loaded: false,
    refreshing: false,
    saving: false,
    scanning: false,
    error: '',
    notice: '',
    noticeTone: '',
    query: '',
    config: emptyConfig(),
    status: emptyStatus(),
    rawConfig: {},
    dirty: false,
    sheet: '',
    draft: null,
    configView: 'broadcasts',
    ssidManage: false,
    selectedSsids: new Set(),
    confirmSsidDelete: null,
    ssidBusy: false,
    selectedRadio: '',
    selectedRadios: new Set(),
    radioDrafts: new Map(),
    radioDirty: false,
    apSheetAp: '',
    apSheetTab: 'overview',
    statusView: 'radios',
    statusViewOffsets: new Map(),
    statusSidebarOffsets: new Map(),
    channelAi: {
      loading: false, loaded: false, data: null, error: '', seq: 0,
      band: '5g', stats: new Set(['retry', 'signal', 'clients', 'interference']),
      channelModes: new Set(), signalMin: -70
    },
    /*
     * AP 管理 Tab 的数据独立于 wifi/config：它走 /api/v1/ac/*（AC 控制面），
     * 与本页原有的 /api/v1/wifi/config 不是同一份契约，所以单独存一份状态，
     * 也单独走一次加载，避免切 Tab 时把 config 的 loading 语义搅在一起。
     */
    ac: {
      loading: false, loaded: false, error: '',
      aps: [], tokens: [], capabilities: {}, reasons: {}, observedAt: 0, seq: 0,
      discovery: { available: false, endpointAvailable: false, reason: '', items: [], observedAt: 0 }
    },
    apEditor: null,
    tokenDraft: null,
    tokenSecret: null,
    confirmToken: null,
    txpower: { loading: false, data: null, error: '', busy: false, confirmPending: false, apId: '' },
    discoveryCandidate: null,
    discoveryBusy: false,
    /*
     * 发现向导（demo 的 .wizard-modal）。它是 Kit 弹窗而不是第五种抽屉：
     * 抽屉会被 Kit 搬到 body 的传送门里，而向导要和确认弹窗叠在同一层序上。
     * scanning 只在 /api/v1/ac/discovery 这次只读 GET 在飞时为真，不是定时器动画。
     */
    apWizard: false,
    apWizardScanning: false,
    apWizardScannedAt: 0,
    adoption: {
      bindingId: '', candidateLabel: '', state: '', error: '', pollIntervalMs: 2000,
      polling: false, pollSeq: 0, pollTimer: 0, expiryTimer: 0,
      secret: null, command: '', secretClearedReason: '', copyFeedback: '', copyTone: ''
    },
    acBusy: false,
    roaming: {
      loading: false, loaded: false, saving: false, error: '', notice: '', noticeTone: '',
      domains: [], domainId: '', baseline: null, draft: null, dirty: false,
      writeDenied: false, conflict: false, seq: 0
    },
    filters: {
      ai: false, broadcast: 'all', aps: new Set(), bands: new Set(), mimo: new Set(), types: new Set(), status: new Set(),
      connectivityRange: 48, environmentAp: 'all', environmentBand: '', environmentRange: '1d', environmentWidths: new Set(), signalMin: -90, signalMax: -30
    },
    columns: {
      connectivity: new Set(['client', 'event', 'ap', 'result', 'signal', 'band', 'broadcast', 'time']),
      environment: new Set(['ap', 'name', 'signal', 'channel', 'width', 'standard', 'mac', 'security', 'vendor', 'nearest'])
    },
    columnEditor: '',
    statusFiltersReady: false,
    environmentHistory: { points: [], reason: 'not_loaded', resolution_seconds: 0, latest_received_at: 0, loading: false, error: '' },
    environmentHistorySeq: 0,
    connectivityEvents: { items: [], reason: 'not_loaded', loading: false, error: '' },
    connectivityEventsSeq: 0,
    scanJobs: new Map(),
    scanEpoch: 0,
    scanWaitResolve: null,
    scanTimer: 0,
    _enterpriseOpen: false,
    refreshTimer: 0
  };

  function formatUptimeSeconds(value) {
    const seconds = Number(value);
    if (!Number.isFinite(seconds) || seconds < 0) return '';
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (days > 0) return `${days} 天 ${hours} 小时`;
    if (hours > 0) return `${hours} 小时 ${minutes} 分钟`;
    return `${minutes} 分钟`;
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

  // One shared cap for every device/AP label in this route. CSS ellipsis alone
  // cannot bound a flex row whose text node has no element of its own, and a
  // per-name special case would drift the moment a longer model ships.
  const LABEL_MAX_CHARS = 22;

  function clipLabel(value, max = LABEL_MAX_CHARS) {
    const text = String(value ?? '').trim();
    if (Array.from(text).length <= max) return text;
    return `${Array.from(text).slice(0, max - 1).join('').trimEnd()}…`;
  }

  function firstNumber(...values) {
    for (const value of values) {
      if (value === '' || value === null || value === undefined) continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return 0;
  }

  function optionalNumber(...values) {
    for (const value of values) {
      if (value === '' || value === null || value === undefined) continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return null;
  }

  /* 与 optionalNumber 的区别只在 0：信道、频宽、发射功率这三处后端用 0
     表示"没有值"——ACS 的 channel 是 0，操作者从未设置过的 txpower 也是 0。
     optionalNumber 会把这个 0 当成一个真实读数往下传，于是 6 GHz 的信道渲染成
     "--"（`radio.channel || '--'`），未设置的功率渲染成一个货真价实的
     "0 dBm" 读回值。凡是 0 只意味着"未设置"的字段，都要用这个函数取值。 */
  function positiveNumber(...values) {
    for (const value of values) {
      if (value === '' || value === null || value === undefined) continue;
      const number = Number(value);
      if (Number.isFinite(number) && number > 0) return number;
    }
    return null;
  }

  /* 后端的平均值是未取整的浮点（avg_signal_dbm 会给 -42.666666666666664），
     直接落进表格会挤破列宽。null 仍然返回 null，交给调用方按 reason 呈现，
     绝不折叠成 0。 */
  /* 百分比一律两位小数（用户 2026-09-04 明确要求）。原来的写法把
     radio.utilization 原样插进模板字面量，于是印出 52.31828929%；随后改成
     「小于 1 给 4 位」，6 GHz 那行又变成 0.5093 %。
     两位以内表达不了的极小值（重试率常见 0.0075）不写成 "0 %"——那是把
     "几乎没有重试" 说成 "没有重试"——而是给 "<0.01 %"，仍然只有两位小数。 */
  function percentValue(value) {
    const number = optionalNumber(value);
    if (number === null) return null;
    if (number !== 0 && Math.abs(number) < 0.005) return `<0.01 %`;
    return metricValue(number, '%', 2);
  }

  function metricValue(value, unit = '', digits = 1) {
    if (value === null || value === undefined || value === '') return null;
    const number = Number(value);
    if (!Number.isFinite(number)) return null;
    const rounded = Number.isInteger(number) ? String(number) : String(Number(number.toFixed(digits)));
    return unit ? `${rounded} ${unit}`.trim() : rounded;
  }

  function bool(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') return !['0', 'false', 'off', 'no', 'disabled', 'down'].includes(value.toLowerCase());
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

  function emptyConfig() {
    return {
      ts: 0,
      capabilities: { wifi: false, bands: [], source: '', save_config: false, apply_config: false, scan: false },
      localWifi: { available: null, phy_count: null, wireless_present: null, role: '', reason: '', source: '' },
      managedWifi: { available: null, controller: '', ap_count: null, online_ap_count: null, reason: '', source: '' },
      runtimeDependencies: {},
      reasonScopes: {},
      regdomains: [],
      global: {
        enabled: true, country: 'CN', speed_profile: 'conservative', mesh: false, mesh_monitor: 'gateway', mesh_monitor_ip: '',
        auto_link: false, wifiman: false, band_steering: false, fast_roaming: false, mlo: false, dfs_enabled: false,
        roam_assist: false, roam_threshold: -75, multicast_enhance: false, airtime_fairness: false, isolated_guest: false,
        qca_rrm: false, qca_qbssload: false, mu_beamformer: false, doth: false, sae_pwe: false,
        channel_ai: false, widths: {}
      },
      radios: [], ssids: [], speed_limits: []
    };
  }

  function emptyStatus() {
    return {
      ts: 0,
      capabilities: { wifi: false, runtime_status: false, radio_runtime: false, radio_update: false, scan: false },
      localWifi: { available: null, phy_count: null, wireless_present: null, role: '', reason: '', source: '' },
      managedWifi: { available: null, controller: '', ap_count: null, online_ap_count: null, reason: '', source: '' },
      runtimeDependencies: {},
      reasonScopes: {},
      // Unknown is null, not 0: the backend distinguishes "no telemetry yet"
      // (null plus a *_reason) from a real zero, and seeding these at 0 made the
      // pre-load skeleton claim zero clients as if it were measured.
      summary: { clients: null, station_count: null, interface_count: null, phy_count: null, avg_signal: null, avg_utilization: null, avg_retry_rate: null, worst_noise: null },
      managedAps: [], radios: [], ssids: [], stations: [], interference: [], connectivityEvents: [],
      environment: { channelSurvey: { samples: [], reason: 'not_loaded' }, neighborScan: { samples: [], reason: 'not_loaded' }, spectralFft: { samples: [], reason: 'not_loaded' } },
      runtime: { available: false, reason: 'not_loaded' }
    };
  }

  function objectValue(value) {
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  }

  /*
   * 本机 PHY、受管 AP 和控制器来源是三条独立事实链。旧版只保留
   * capabilities.wifi，AC 请求失败时很容易把其中一条覆盖成 false；这里
   * 先把结构化字段归一，后续空态只读取 localWifi，而不读取 AC 数组长度。
   */
  function normalizeWifiFacts(source = {}, caps = {}, radios = []) {
    const localCandidate = source.local_wifi ?? caps.local_wifi;
    const managedCandidate = source.managed_wifi ?? caps.managed_wifi;
    const local = objectValue(localCandidate);
    const managed = objectValue(managedCandidate);
    const runtimeDependencies = objectValue(source.runtime_dependencies || caps.runtime_dependencies || source.runtime?.dependencies);
    const reasonScopes = objectValue(source.reason_scopes || caps.reason_scopes);
    const localAvailable = typeof localCandidate === 'boolean'
      ? localCandidate
      : typeof local.available === 'boolean' ? local.available : null;
    const phyCount = optionalNumber(
      local.phy_count, local.phyCount, local.radio_count, local.radioCount,
      runtimeDependencies.phy_count, runtimeDependencies.radio_count,
      source.phy_count, source.radio_count, source.runtime?.phy_count
    );
    const localReason = firstText(
      local.reason, local.status_reason, runtimeDependencies.reason,
      source.local_wifi_reason, source.runtime?.reason,
      reasonScopes.local_wifi, reasonScopes.local
    );
    const normalizedLocalAvailable = localAvailable !== null
      ? localAvailable
      : phyCount !== null ? phyCount > 0 : radios.length > 0 ? true : null;
    const managedAvailable = typeof managedCandidate === 'boolean'
      ? managedCandidate
      : typeof managed.available === 'boolean' ? managed.available : null;
    return {
      localWifi: {
        ...local,
        available: normalizedLocalAvailable,
        phy_count: phyCount,
        wireless_present: typeof local.wireless_present === 'boolean' ? local.wireless_present : phyCount !== null ? phyCount > 0 : null,
        role: firstText(local.role, local.device_role, source.device_role, source.role, caps.device_role),
        reason: localReason,
        source: firstText(local.source, runtimeDependencies.source, source.local_wifi_source)
      },
      managedWifi: {
        ...managed,
        available: managedAvailable,
        controller: firstText(managed.controller, managed.controller_name, source.controller),
        ap_count: optionalNumber(managed.ap_count, managed.count, source.managed_ap_count),
        online_ap_count: optionalNumber(managed.online_ap_count, managed.online_count, source.managed_ap_online),
        reason: firstText(managed.reason, reasonScopes.managed_wifi, reasonScopes.managed_ap),
        source: firstText(managed.source, source.managed_wifi_source)
      },
      runtimeDependencies,
      reasonScopes
    };
  }

  /*
   * 频段归一。认不出来的值一律返回空，**不原样透出**：
   * 30.1 的 capabilities.bands 实测是 ['3']、radios[].band 也出现 '3'（QSDK 数字编码），
   * 原先最后一行 `return text || ''` 会把 '3' 当成一个合法频段传下去，于是频段筛选器里
   * 冒出一个名为「3」的伪频段、编辑抽屉的复选框也会按它判定可用性。
   * 数字编码应由后端先归一（见配套后端单），前端这里只做保守判定：认识才认，不猜。
   */
  function normalizeBand(value) {
    const text = String(value || '').toLowerCase().replace(/\s/g, '');
    if (['2g', '2.4g', '2.4ghz', 'ng', '11ng', 'radio0'].includes(text) || text.includes('2.4')) return '2g';
    if (['5g', '5ghz', 'na', '11ac', '11ax', 'radio1'].includes(text) || text.startsWith('5')) return '5g';
    if (['6g', '6ghz', '11be', 'radio2'].includes(text) || text.startsWith('6')) return '6g';
    return '';
  }

  // Driver/regdb channel truth from the APD iw-phy channel_catalog.
  // disabled and no-IR channels cannot host an AP BSS -> unavailable;
  // radar/DFS-flagged channels -> dfs; the rest -> enabled. Nothing is
  // invented when the catalog is absent or incomplete.
  function catalogChannels(radio, kind) {
    const catalog = radio && radio.channel_catalog;
    if (!catalog || !bool(catalog.complete, false)) return [];
    return asArray(catalog.channels).filter((entry) => {
      const disabled = bool(entry.disabled, false);
      const noIr = bool(entry.no_ir, false);
      const dfs = bool(entry.radar_detection, false) || Boolean(entry.dfs_state);
      if (kind === 'unavailable') return disabled || noIr;
      if (kind === 'dfs') return !disabled && !noIr && dfs;
      return !disabled && !noIr && !dfs;
    }).map((entry) => Number(entry.channel)).filter(Boolean);
  }

  function localWriteId(item = {}, kind = '', fallback = '') {
    const explicit = firstText(item.local_id, item.id, item.section, item.ifname, item.name, fallback);
    const prefix = `local:${kind}:`;
    return explicit.startsWith(prefix) ? explicit.slice(prefix.length) : explicit;
  }

  /* AC 侧的复合 id 形如 `ap:<uuid>:radio:phy0r1`，而 normalizeRadio() 会把 Radio 的
     id 压成 local_id（`phy0r1`）。stations[].radio_id、station_events[].radio_id 两边
     用的形式并不一致（前者是复合 id，后者是裸 local_id），所以比较之前一律取末段。 */
  function radioIdTail(value) {
    const text = firstText(value);
    const marker = text.lastIndexOf(':radio:');
    return (marker >= 0 ? text.slice(marker + ':radio:'.length) : text).toLowerCase();
  }

  /* Radio 与某个 radio_id 是否同一个。phy 不能单独作为判据：mac80211 单 wiphy 多
     radio 的机型上 phy0 同时属于 phy0r0/r1/r2，250 实测 6 个 Radio 的 phy 全是 phy0。 */
  function radioMatchesId(radio = {}, radioId = '') {
    const target = radioIdTail(radioId);
    if (!target) return false;
    return radioIdTail(radio.local_id) === target ||
      radioIdTail(radio.id) === target ||
      firstText(radio.phy).toLowerCase() === target;
  }

  /*
   * UCI section names accept only [A-Za-z0-9_].  A hyphen is not a cosmetic
   * problem: `config wifi-iface 'wifi-1756700000000'` makes the whole
   * /etc/config/wireless fail to parse ("invalid character in name field"),
   * so every radio section disappears along with the SSID and the device ends
   * up with no wireless config at all.  Draft ids are generated here, so they
   * are sanitized here rather than hoping the backend rewrites them.
   */
  function uciSectionId(value, fallback = 'wifi') {
    const safe = String(value ?? '').replace(/[^A-Za-z0-9_]/g, '_').replace(/^_+/, '');
    const base = safe || String(fallback).replace(/[^A-Za-z0-9_]/g, '_') || 'wifi';
    return (/^[0-9]/.test(base) ? `w_${base}` : base).slice(0, 63);
  }

  function normalizeRadio(radio = {}, index = 0) {
    const runtime = radio.runtime && typeof radio.runtime === 'object' ? radio.runtime : {};
    const band = normalizeBand(firstText(radio.band, radio.radio, radio.frequency_band, runtime.band));
    const widths = asArray(
      radio.supported_widths || radio.supported_widths_mhz || radio.widths ||
      radio.channel_catalog?.supported_widths_mhz ||
      runtime.supported_widths || runtime.supported_widths_mhz ||
      runtime.channel_catalog?.supported_widths_mhz
    ).map(Number).filter(Boolean);
    const interfaces = asArray(radio.interfaces || runtime.interfaces);
    /* air_stats 里 obss_util_pct / self_bss_util_pct 一直是真实值（30.1: 9/8/4 与
       1/15/58），但从未被映射出来，页面上却挂着"驱动未上报 OBSS 干扰"。 */
    const airStats = radio.air_stats && typeof radio.air_stats === 'object'
      ? radio.air_stats
      : runtime.air_stats && typeof runtime.air_stats === 'object' ? runtime.air_stats : {};
    const apId = firstText(radio.ap_id, runtime.ap_id, radio.controller_device_id, radio.host_id);
    const apName = firstText(radio.ap_name, radio.ap, radio.device_name, radio.host, radio.site_name, radio.model, radio.product, apId ? `AP ${apId.slice(0, 8)}` : '', radio.phy, radio.device, radio.ifname, `Radio ${index + 1}`);
    /* 发射功率读回值。三条来源分开取，顺序有意义：
     *
     * 1. radio.tx_power_dbm —— webd 聚合层为受管 AP 写的真实读回值
     *    (wifi_decorate_radio_metrics 取自 iw dev，读不到就显式置 null)。
     *    这里用 optionalNumber，后端如果真的上报 0 dBm 就照实呈现。
     * 2. 本机运行值 —— netconfig 的 runtime_txpower，同样来自 iw dev。
     * 3. 期望值 —— txpower 列。这一项必须用 positiveNumber：0 表示操作者
     *    从未设置过功率，不是"读回 0 dBm"。此前整条链用 optionalNumber，
     *    于是 txpower=0 直接变成读回值，radioPowerCell() 渲染出
     *    "0 dBm / 调整能力待同步"——这就是用户看到的那一行。 */
    const txPowerRuntime = optionalNumber(
      radio.runtime_txpower, radio.runtime_tx_power_dbm,
      runtime.runtime_txpower, runtime.tx_power_dbm, runtime.tx_power, runtime.txpower_dbm,
      ...interfaces.map((item) => item.txpower_dbm)
    );
    const txPowerDesired = positiveNumber(radio.txpower, radio.txpower_dbm, radio.tx_power);
    const txPowerReadback = optionalNumber(radio.tx_power_dbm, txPowerRuntime, txPowerDesired);
    const txPowerContract = radio.radio_tx_power && typeof radio.radio_tx_power === 'object' ? radio.radio_tx_power
      : radio.capabilities?.radio_tx_power && typeof radio.capabilities.radio_tx_power === 'object' ? radio.capabilities.radio_tx_power
        : runtime.radio_tx_power && typeof runtime.radio_tx_power === 'object' ? runtime.radio_tx_power : {};
    const txPowerLimits = radio.tx_power_limits_dbm && typeof radio.tx_power_limits_dbm === 'object' ? radio.tx_power_limits_dbm
      : radio.txpower_limits_dbm && typeof radio.txpower_limits_dbm === 'object' ? radio.txpower_limits_dbm
        : runtime.tx_power_limits_dbm && typeof runtime.tx_power_limits_dbm === 'object' ? runtime.tx_power_limits_dbm : {};
    const txPowerModes = asArray(radio.supported_tx_power_modes || radio.tx_power_modes || runtime.supported_tx_power_modes);
    /* 期望值与运行值必须分开存放。
     *
     * channel / width 是 *期望* 配置：commitRadioDraftsToConfig() 会把
     * ['channel','width',...] 从规范化后的草稿抄回 state.config.radios，
     * saveConfig() 再把整个规范化对象摊进 PUT。所以一旦在这里把运行值折进
     * channel，6 GHz 的 ACS（后端 channel=0，即 UCI 的 channel='auto'）就会
     * 在下一次保存时被静默钉死在驱动当前选中的信道上——操作者从没选过它。
     * 这和 CLAUDE.md 里路由规则 enabled 的 read-modify-write 陷阱同形。
     *
     * 因此运行值只进独立的展示键（channel_operating / width_operating，以及
     * 供渲染直接使用的 channel_display / width_display），渲染处读展示键，
     * 写回路径继续读 channel / width。 */
    const channelDesired = positiveNumber(radio.channel, radio.channel_desired, radio.desired_channel);
    const channelOperating = positiveNumber(
      radio.runtime_channel, radio.operating_channel, radio.channel_operating,
      runtime.runtime_channel, runtime.operating_channel, runtime.channel,
      ...interfaces.map((item) => item.channel)
    );
    /* channel_auto 由后端按 channel<=0 判定并下发；后端没给时才自己推导，
       绝不用运行信道的存在与否去反推（ACS 选中了信道不代表不是 ACS）。 */
    const channelAuto = radio.channel_auto === undefined || radio.channel_auto === null
      ? channelDesired === null
      : bool(radio.channel_auto, channelDesired === null);
    const widthDesired = positiveNumber(radio.width, radio.width_mhz, radio.channel_width);
    const widthOperating = positiveNumber(
      radio.runtime_width, radio.operating_width, radio.width_operating,
      runtime.runtime_width, runtime.width, runtime.width_mhz, runtime.channel_width
    );
    const online = bool(radio.online ?? runtime.online, bool(radio.enabled ?? radio.configured_enabled, true));
    /* 受管 AP 的 Radio 必须保留 AC 的复合 id (`ap:<uuid>:radio:phy0r0`)。
       localWriteId() 会把它压成 local_id（`phy0r0`），而两台受管 AP 的 local_id
       逐字相同 —— 250 实测在线 AP 与离线 stale AP 各有一套 phy0r0/r1/r2。压掉
       ap_id 之后 state.selectedRadios 按 id 命中两条：点一行选中两个 Radio，
       写事务于是同时带上离线 AP 那个 target，AC 的逐目标闸门把整笔事务拒成
       target_write_capability_unavailable（前端只看到 409，文案却说"版本被推进"）。
       ssids[].radio_id 与 stations[].radio_id 用的也正是这个复合 id，保留它同时
       修好"按广播筛选"那条恒不命中的判据。本机 phy 仍走压缩后的 local id，
       saveConfig() 的 state.config.radios 匹配依赖它。 */
    const rawId = firstText(radio.id);
    const managedId = apId && rawId.startsWith(`ap:${apId}:radio:`) ? rawId : '';
    return {
      ...radio,
      id: managedId || localWriteId(radio, 'radio', `radio-${index}`),
      name: firstText(radio.name, radio.device_name, radio.phy, radio.device, radio.ifname, `Radio ${index + 1}`),
      ap_id: apId || firstText(radio.ap_name, radio.ap, radio.device_name, radio.host, radio.name, radio.phy, `ap-${index}`),
      ap: apName,
      model: firstText(radio.model, radio.product, radio.hardware, ''),
      image_url: firstText(radio.image_url, radio.web_image, radio.image, radio.icon_url, runtime.image_url, runtime.web_image),
      image_available: bool(radio.image_available ?? runtime.image_available, Boolean(firstText(radio.image_url, radio.web_image, radio.image, runtime.image_url))),
      image_source: firstText(radio.image_source, runtime.image_source),
      image_model_match: firstText(radio.image_model_match, runtime.image_model_match),
      band,
      /* 期望值，写回路径读这两个键，保持原样（ACS 就是 0）。
         这里刻意不把 width_mhz / runtime_width 掺进来：width_mhz 是运行值，
         受管 AP 那一路已由 webd 的 wifi_normalize_aliases() 决定要不要把它
         别名成 width，前端再兜一层就会把运行频宽写回成期望频宽。 */
      channel: firstNumber(radio.channel, runtime.channel),
      width: firstNumber(radio.width, radio.channel_width, runtime.width, runtime.channel_width),
      /* 展示用派生键，只读。channel_display 在 ACS 时给出驱动实际选中的信道，
         否则给出操作者设定的信道；两者都没有时为 null，由渲染处呈现 "--"。 */
      channel_desired: channelDesired,
      channel_operating: channelOperating,
      channel_auto: channelAuto,
      channel_display: channelAuto ? channelOperating : (channelDesired ?? channelOperating),
      width_desired: widthDesired,
      width_operating: widthOperating,
      width_display: widthDesired ?? widthOperating,
      tx_power: txPowerReadback,
      tx_power_dbm: txPowerReadback,
      /* 期望值与"是否自动"，只读展示键，写回路径读的是 txpower（随 ...radio 原样
         透传，这里刻意不合成，否则每次保存都会把当前读回值钉成固定功率——和上面
         channel 的 ACS 陷阱同形）。
         txPowerDesired 用 positiveNumber，所以 txpower=0/缺失都归为 null，
         而 0 正是后端定义的"监管上限/自动"（netifd 的 iw phy set txpower auto）。 */
      tx_power_desired: txPowerDesired,
      tx_power_auto: txPowerDesired === null,
      tx_power_source: firstText(radio.tx_power_source, radio.runtime_source, runtime.tx_power_source, ''),
      tx_power_mode: firstText(radio.tx_power_mode, radio.power_mode, runtime.tx_power_mode),
      tx_power_limits_dbm: {
        min: optionalNumber(txPowerLimits.min, txPowerLimits.minimum),
        /* 上限取自后端按频段从 iw phy 读出的监管天花板（max_txpower）。
           它曾是 txpower 列的第二份拷贝，恒等于期望值且未设置时为 0，
           已在 netconfig 侧删掉。 */
        max: optionalNumber(txPowerLimits.max, txPowerLimits.maximum,
          positiveNumber(radio.max_txpower, radio.max_txpower_dbm, runtime.max_txpower, runtime.max_txpower_dbm)),
        step: optionalNumber(txPowerLimits.step, txPowerLimits.increment) || 1
      },
      supported_tx_power_modes: txPowerModes.map((mode) => String(mode)).filter(Boolean),
      radio_tx_power: txPowerContract,
      clients: optionalNumber(radio.clients, radio.station_count, runtime.clients, runtime.station_count),
      // 后端发的是 channel_utilization / channel_utilization_pct（同为 0..100 百分数），
      // 以及 noise_dbm。此前只读 utilization / noise，两项在真机上恒为空。
      utilization: optionalNumber(radio.utilization, radio.channel_utilization, radio.channel_utilization_pct, radio.airtime, runtime.utilization, runtime.channel_utilization, runtime.channel_utilization_pct),
      utilization_reason: firstText(radio.channel_utilization_reason, radio.utilization_reason, runtime.channel_utilization_reason, ''),
      utilization_source: firstText(radio.channel_utilization_source, runtime.channel_utilization_source, ''),
      interference: firstNumber(radio.interference, radio.external_interference, runtime.interference),
      // 后端字段带单位后缀：avg_interference_pct（0..100）、avg_signal_dbm。
      // 此前只读无后缀名，真机上 AP 在线且有实数据时这两列仍恒为 "--"。
      avg_interference: optionalNumber(radio.avg_interference, radio.avg_interference_pct, radio.average_interference, runtime.avg_interference, runtime.avg_interference_pct, runtime.average_interference),
      avg_interference_source: firstText(radio.avg_interference_source, runtime.avg_interference_source, ''),
      avg_interference_reason: firstText(radio.avg_interference_reason, runtime.avg_interference_reason, ''),
      retry_rate: optionalNumber(radio.retry_rate, radio.tx_retry, runtime.retry_rate, radio.air_stats?.retry_rate_pct),
      noise: optionalNumber(radio.noise_dbm, radio.noise, radio.noise_floor, runtime.noise_dbm, runtime.noise, runtime.noise_floor),
      noise_reason: firstText(radio.noise_reason, runtime.noise_reason, ''),
      noise_source: firstText(radio.noise_source, runtime.noise_source, ''),
      tx_power_mode_reason: firstText(radio.tx_power_mode_reason, runtime.tx_power_mode_reason, ''),
      avg_signal: optionalNumber(radio.avg_signal, radio.avg_signal_dbm, radio.average_signal, radio.signal, runtime.avg_signal, runtime.avg_signal_dbm, runtime.average_signal),
      avg_signal_reason: firstText(radio.avg_signal_reason, runtime.avg_signal_reason, ''),
      avg_signal_source: firstText(radio.avg_signal_source, runtime.avg_signal_source, ''),
      /* history_24h 是**数组**（250 实测每条 137 个 {timestamp,value,...} 点）。
         原来把它掺进 firstText()，而 firstText() 只对普通对象做展开、对数组走
         String(value)，于是射频表「过去 24 小时」列印出 137 个
         "[object Object]"。文本来源只留真正是文本的那几个键，序列另存。 */
      past_24h: firstText(radio.past_24h, radio.last_24h, runtime.past_24h, runtime.last_24h),
      past_24h_points: asArray(radio.history_24h || radio.past_24h_points || runtime.history_24h),
      past_24h_reason: firstText(radio.history_24h_reason, radio.past_24h_reason, runtime.history_24h_reason, runtime.past_24h_reason, ''),
      mimo: firstText(radio.mimo, radio.spatial_streams, runtime.mimo, ''),
      type: firstText(radio.uplink_type, radio.connection_type, runtime.uplink_type, runtime.connection_type),
      enabled: bool(radio.enabled, true),
      online,
      excluded_channels: asArray(radio.excluded_channels).map(Number).filter(Boolean),
      dfs_channels: asArray(radio.dfs_channels || runtime.dfs_channels).map(Number).filter(Boolean)
        .concat(catalogChannels(radio, 'dfs')),
      unavailable_channels: asArray(radio.unavailable_channels || runtime.unavailable_channels).map(Number).filter(Boolean)
        .concat(catalogChannels(radio, 'unavailable')),
      supported_widths: widths,
      supported_channels: asArray(radio.supported_channels || radio.channels).map(Number).filter(Boolean)
        .concat(catalogChannels(radio, 'enabled')),
      country: firstText(radio.country, radio.country_code, radio.channel_catalog?.regdomain, ''),
      min_rssi_enabled: bool(radio.min_rssi_enabled ?? radio.minimum_rssi_enabled, false),
      min_rssi: optionalNumber(radio.min_rssi, radio.minimum_rssi, radio.min_rssi_dbm),
      tx_power_custom: optionalNumber(radio.tx_power_custom, radio.custom_tx_power, radio.tx_power_dbm),
      channel_history: asArray(radio.channel_history || radio.history?.channel || runtime.channel_history),
      signal_distribution: asArray(radio.signal_distribution || radio.client_signal_distribution || runtime.signal_distribution),
      standard: firstText(radio.standard, radio.wifi_standard, radio.protocol, runtime.standard, runtime.wifi_standard),
      tx_retry_history: asArray(radio.tx_retry_history || radio.retry_history || runtime.tx_retry_history),
      obss_utilization: optionalNumber(radio.obss_utilization, radio.obss_util_pct, airStats.obss_util_pct),
      obss_utilization_reason: firstText(radio.obss_utilization_reason, airStats.obss_reason, ''),
      self_bss_utilization: optionalNumber(radio.self_bss_utilization, radio.self_bss_util_pct, airStats.self_bss_util_pct),
      // 后端在 mimo / standard 缺失时另发 *_reason，此前只读值不读原因，缺失就成了空白格。
      mimo_reason: firstText(radio.mimo_reason, radio.spatial_streams_reason, runtime.mimo_reason, ''),
      standard_reason: firstText(radio.standard_reason, radio.wifi_standard_reason, runtime.standard_reason, ''),
      air_stats: airStats
    };
  }

  function radioInterfaceNames(radio = {}) {
    return asArray(radio.interfaces).map((item) => (
      typeof item === 'string'
        ? firstText(item)
        : firstText(item?.interface, item?.ifname, item?.name, item?.id)
    )).filter(Boolean);
  }

  function signalBucketIndex(value) {
    const signal = optionalNumber(value);
    if (signal === null) return -1;
    const thresholds = [-90, -75, -60, -45, -30];
    const clamped = Math.max(thresholds[0], signal);
    for (let index = thresholds.length - 1; index >= 0; index -= 1) {
      if (clamped >= thresholds[index]) return index;
    }
    return 0;
  }

  /*
   * WebD already maps station interfaces to radios for clients/avg_signal. Keep
   * the browser fallback equally strict: a station contributes only when its
   * interface identifies exactly one radio. Missing RSSI, unknown interfaces,
   * and ambiguous names stay out of every chart instead of being guessed into
   * the first radio.
   */
  function deriveStationSignalDistributions(radios = [], stations = []) {
    const rows = asArray(radios);
    const distributions = rows.map(() => ({
      counts: [0, 0, 0, 0, 0],
      sample_count: 0,
      matched_station_count: 0,
      missing_signal_count: 0,
      /* 全局量（每个 Radio 上写同一个值）：本次快照里一个 Radio 都归属不上的客户端数。
         radio.clients 是 webd 独立算出来的，和这里的归属互不相干，所以"在线数 > 样本数"
         必须能区分成"归属不了"和"归属到了但没上报 signal_dbm"两种，不能一律说成后者。 */
      unmapped_station_count: 0
    }));
    const interfaceOwners = new Map();
    const bssidOwners = new Map();
    const radioIdOwners = new Map();

    /* 归属键按 AP 分域。250 实测：一台受管 AP 掉线后 AC 仍保留它的 stale 记录，
       于是 radios[] 里出现两套 phy0r0/r1/r2 —— 接口名 `phy0.1-ap0`、BSSID
       `00:58:28:09:22:ba`、local_id `phy0r1` 在两个 ap_id 上逐字相同。不分域时每一级
       归属都是 2 个候选，`owners.length !== 1` 于是把唯一在线的客户端判成"归属不了"，
       页面写着"1 个客户端在线，但本次快照没有能唯一映射到该 Radio 的有效 signal_dbm"。
       客户端自己带 ap_id，把它算进键里，同名不同 AP 就不再互相干扰。 */
    function ownerKey(apId, value) {
      const normalized = String(value || '').trim().toLowerCase();
      if (!normalized) return '';
      return `${String(apId || '').trim().toLowerCase()}|${normalized}`;
    }

    function addOwner(map, apId, key, radioIndex) {
      const normalized = ownerKey(apId, key);
      if (!normalized) return;
      const owners = map.get(normalized) || [];
      if (!owners.includes(radioIndex)) owners.push(radioIndex);
      map.set(normalized, owners);
    }

    rows.forEach((radio, radioIndex) => {
      const apId = radio.ap_id;

      radioInterfaceNames(radio).forEach((interfaceName) => addOwner(interfaceOwners, apId, interfaceName, radioIndex));
      addOwner(radioIdOwners, apId, radio.phy, radioIndex);
      /* radio.id 已被 normalizeRadio() 压成 local_id（`phy0r1`），而客户端带的
         radio_id 是 AC 的复合 id `ap:<uuid>:radio:phy0r1`，所以两侧都取末段再比。 */
      addOwner(radioIdOwners, apId, radioIdTail(radio.id), radioIndex);
      addOwner(radioIdOwners, apId, radioIdTail(radio.local_id), radioIndex);
      addOwner(bssidOwners, apId, radio.bssid, radioIndex);
      addOwner(bssidOwners, apId, radio.mac, radioIndex);
      asArray(radio.interfaces).forEach((item) => {
        if (!item || typeof item !== 'object') return;
        addOwner(bssidOwners, apId, item.bssid, radioIndex);
        addOwner(bssidOwners, apId, item.mac, radioIndex);
      });
    });

    /* 归属顺序按证据强度：BSSID/MAC 最硬，radio_id/phy 次之，接口名精确匹配再次之，
       最后才是最长前缀 —— 30.1 上 6GHz radio 只枚举 ath2/ath21，2.4G/5G 各枚举 5 个，
       落在未枚举 VAP 上的客户端因此必然无家可归；ath25 截到 ath2 就能归位。截到 4 字符
       为止，'ath' 这类必然歧义的前缀不参与。每一级都要求唯一归属，宁可不归也不猜。 */
    function resolveStationOwners(station = {}) {
      const apId = station.ap_id;
      const bssid = ownerKey(apId, firstText(station.bssid, station.ap_bssid, station.radio_bssid, station.bss));
      if (bssid && bssidOwners.has(bssid)) return bssidOwners.get(bssid);
      const radioId = ownerKey(apId, radioIdTail(firstText(station.radio_id, station.phy, station.radio)));
      if (radioId && radioIdOwners.has(radioId)) return radioIdOwners.get(radioId);
      const rawInterface = firstText(station.interface, station.ifname, station.device).toLowerCase();
      const interfaceName = ownerKey(apId, rawInterface);
      if (!interfaceName) return [];
      if (interfaceOwners.has(interfaceName)) return interfaceOwners.get(interfaceName);
      for (let length = rawInterface.length - 1; length >= 4; length -= 1) {
        const owners = interfaceOwners.get(ownerKey(apId, rawInterface.slice(0, length)));
        if (owners) return owners;
      }
      return [];
    }

    let unmappedStations = 0;
    asArray(stations).forEach((station) => {
      const owners = resolveStationOwners(station || {});
      if (owners.length !== 1) {
        unmappedStations += 1;
        return;
      }
      const distribution = distributions[owners[0]];
      distribution.matched_station_count += 1;
      const bucketIndex = signalBucketIndex(station?.signal_dbm);
      if (bucketIndex < 0) {
        distribution.missing_signal_count += 1;
        return;
      }
      distribution.counts[bucketIndex] += 1;
      distribution.sample_count += 1;
    });

    distributions.forEach((distribution) => { distribution.unmapped_station_count = unmappedStations; });
    return distributions;
  }

  function normalizeAp(ap = {}, index = 0) {
    const runtime = ap.runtime && typeof ap.runtime === 'object' ? ap.runtime : {};
    const id = firstText(ap.ap_id, ap.id, ap.device_id, runtime.ap_id, `ap-${index}`);
    return {
      ...ap,
      id,
      name: firstText(ap.name, ap.device_name, ap.model, ap.product, `AP ${index + 1}`),
      model: firstText(ap.model, ap.product, ap.hardware, runtime.model),
      image_url: firstText(ap.image_url, ap.web_image, ap.image, runtime.image_url),
      online: bool(ap.online ?? runtime.online, false),
      connection: firstText(ap.connected_to, ap.parent_name, ap.uplink_name, ap.uplink?.name, runtime.connected_to),
      ip: firstText(ap.ip, ap.ip_address, ap.address, ap.management_ip, runtime.ip, runtime.ip_address),
      mac: firstText(ap.mac, ap.mac_address, ap.device_mac, runtime.mac, runtime.mac_address),
      version: firstText(ap.firmware_version, ap.device_version, ap.version, runtime.firmware_version),
      uptime: firstText(ap.uptime_text, ap.uptime, runtime.uptime_text, runtime.uptime,
        formatUptimeSeconds(ap.uptime_seconds ?? runtime.uptime_seconds)),
      tags: asArray(ap.tags || ap.device_tags),
      mesh_parent: firstText(ap.mesh_parent, ap.mesh?.parent, runtime.mesh_parent),
      ap_group: firstText(ap.ap_group, ap.group, ap.site_name, runtime.ap_group),
      ip_mode: firstText(ap.ip_mode, ap.addressing_mode, ap.network?.mode, runtime.ip_mode),
      led_enabled: ap.led_enabled ?? ap.led?.enabled ?? runtime.led_enabled
    };
  }

  /*
   * ── AP 管理（AC 控制面）──
   *
   * 与上面的 normalizeAp 分开：那个服务于 /api/v1/wifi/status 的射频视图，
   * 这里的字段来自 /api/v1/ac/aps，两份契约的键名与语义都不同。
   */

  function nowSeconds() { return Math.floor(Date.now() / 1000); }

  function relativeSeconds(value) {
    const stamp = Number(value);
    if (!Number.isFinite(stamp) || stamp <= 0) return '';
    const delta = nowSeconds() - stamp;
    if (delta < 0) return '刚刚';
    if (delta < 60) return `${delta} 秒前`;
    if (delta < 3600) return `${Math.floor(delta / 60)} 分钟前`;
    if (delta < 86400) return `${Math.floor(delta / 3600)} 小时前`;
    return `${Math.floor(delta / 86400)} 天前`;
  }

  function countdownSeconds(value) {
    const stamp = Number(value);
    if (!Number.isFinite(stamp) || stamp <= 0) return '';
    const delta = stamp - nowSeconds();
    if (delta <= 0) return '已过期';
    if (delta < 60) return `剩 ${delta} 秒`;
    if (delta < 3600) return `剩 ${Math.floor(delta / 60)} 分钟`;
    if (delta < 86400) return `剩 ${Math.floor(delta / 3600)} 小时`;
    return `剩 ${Math.floor(delta / 86400)} 天`;
  }

  function absoluteTime(value) {
    const stamp = Number(value);
    if (!Number.isFinite(stamp) || stamp <= 0) return '';
    return new Date(stamp * 1000).toLocaleString();
  }

  /*
   * 显示名兜底链由后端定稿（Handoff Acceptance-to-Backend-ap-management-tab-rest-layer-missing）：
   * name -> model -> board_name -> ap_id 前 8 位。
   * 不能只回退到 model：AC 侧的 model 本身是 model_override || reported_model，
   * 两者都空时 model 也是空串（model_available=false 的 AP 即如此），
   * 所以 board_name 必须留在链上，再兜一层 ap_id 防全空。
   */
  function acApLabel(ap = {}) {
    const named = firstText(ap.name, ap.model, ap.board_name);
    if (named) return named;
    const id = String(ap.ap_id || '');
    return id ? `AP ${id.slice(0, 8)}` : 'AP';
  }

  /*
   * 频段标签只认后端实际给的两种写法：现行快照是 "2.4GHz" / "5GHz" / "6GHz"，
   * 早期 ap-control 快照是 "2g" / "5g" / "6g"。认不出来就返回空串，上层据此
   * 把这条射频算作「未上报」而不是默认成某个频段 —— 实测 30.1 的 phy0
   * 就是 band 为 null 的一条，原先的
   * `band === '2g' ? '2.4G' : band === '5g' ? '5G' : '6G'` 会把它标成 6G。
   */
  function acRadioBandLabel(band) {
    const raw = String(band || '').trim().toLowerCase().replace(/[\s_-]/g, '');
    if (!raw) return '';
    if (raw.startsWith('2.4') || raw.startsWith('24') || raw === '2g') return '2.4G';
    if (raw.startsWith('5')) return '5G';
    if (raw.startsWith('6')) return '6G';
    return '';
  }

  /*
   * 计数字段缺失时返回 null，不返回 0。firstNumber() 的兜底值是 0，用它读
   * station_count 会把「这台 AP 没上报客户端数」和「这台 AP 真的一个客户端
   * 都没有」折叠成同一句话。0 是一个好成绩，缺失是不知道，界面上必须能分开。
   */
  function acCount(value) {
    if (value === undefined || value === null || value === '') return null;
    const number = Number(value);
    return Number.isFinite(number) && number >= 0 ? number : null;
  }

  /*
   * AP 运行态只做形状转换，不补默认值。
   *
   * 真实快照是 runtime.snapshot.station_count 与 runtime.snapshot.radios[]
   * （band 形如 "6GHz"，另带 channel / width_mhz），不是 runtime.client_count
   * 与 runtime.radios[]（band 形如 "5g"）—— 后者是清单卡片最初照 demo 写下的
   * 假设，实测 30.1 一条都对不上，于是射频胶囊恒为「射频离线」、全网接入
   * 客户端恒为 0，而同一台 AP 的快照里其实写着 station_count: 28。
   */
  function normalizeAcApRuntime(runtime = {}) {
    const snapshot = runtime.snapshot && typeof runtime.snapshot === 'object' ? runtime.snapshot : {};
    const radios = asArray(snapshot.radios).map((radio, index) => {
      const entry = radio && typeof radio === 'object' ? radio : {};
      const band = acRadioBandLabel(entry.band);
      const channel = acCount(entry.channel);
      return {
        id: firstText(entry.id, entry.phy, `radio-${index}`),
        band,
        channel: channel && channel > 0 ? channel : null,
        widthMhz: acCount(entry.width_mhz),
        /* 上报过频段才算这条射频可展示；未上报的只进计数，不冒充某个频段。 */
        reported: Boolean(band)
      };
    });
    const declared = acCount(snapshot.radio_count);
    return {
      radios,
      radioCount: declared === null ? radios.length : declared,
      clientCount: acCount(snapshot.station_count),
      ssidCount: acCount(snapshot.ssid_count),
      ip: firstText(snapshot.system && typeof snapshot.system === 'object' ? snapshot.system.ip : '')
    };
  }

  function normalizeAcAp(ap = {}, index = 0) {
    const runtime = ap.runtime && typeof ap.runtime === 'object' ? ap.runtime : {};
    return {
      ap_id: firstText(ap.ap_id, `ac-ap-${index}`),
      site_id: firstText(ap.site_id),
      name: typeof ap.name === 'string' ? ap.name : '',
      label: acApLabel(ap),
      named: Boolean(firstText(ap.name)),
      adoption_state: firstText(ap.adoption_state, 'unknown'),
      online: bool(ap.online, false),
      stale: bool(ap.stale, false),
      session_connected: bool(ap.session_connected, false),
      last_seen_at: firstNumber(ap.last_seen_at) || 0,
      model: firstText(ap.model),
      reported_model: firstText(ap.reported_model),
      model_override: typeof ap.model_override === 'string' ? ap.model_override : '',
      override_supported: bool(ap.override_supported, false),
      model_available: bool(ap.model_available, false),
      model_reason: firstText(ap.model_reason),
      model_source: firstText(ap.model_source),
      board_name: firstText(ap.board_name),
      control_protocol: firstText(ap.control_protocol),
      control_protocol_version: firstNumber(ap.control_protocol_version) || 0,
      scan_execution: bool(ap.scan_execution, false),
      capabilities: ap.capabilities && typeof ap.capabilities === 'object' ? ap.capabilities : {},
      runtime_available: bool(runtime.available, false),
      runtime_complete: bool(runtime.complete, false),
      runtime_stale: bool(runtime.stale, false),
      runtime_reason: firstText(runtime.reason),
      runtime: normalizeAcApRuntime(runtime)
    };
  }

  function normalizeDiscoveryCandidate(candidate = {}, index = 0) {
    return {
      ap_id: firstText(candidate.ap_id, `discovered-ap-${index}`),
      key_id: firstText(candidate.key_id, candidate.key_fingerprint),
      mac: firstText(candidate.mac),
      model: firstText(candidate.model, candidate.board_name),
      board_name: firstText(candidate.board_name),
      mgmt_ip: firstText(candidate.mgmt_ip),
      claimed_ip: firstText(candidate.claimed_ip),
      mgmt_port: firstNumber(candidate.mgmt_port) || 0,
      first_seen: firstNumber(candidate.first_seen) || 0,
      last_seen: firstNumber(candidate.last_seen) || 0,
      adopted_elsewhere: bool(candidate.adopted_elsewhere, false),
      adopted_controller_id: firstText(candidate.adopted_controller_id),
      trusted: bool(candidate.trusted, false),
      adoption_requires: firstText(candidate.adoption_requires),
      /*
       * 确认请求是后端签发的候选专用票据。前端既不从 AP ID/指纹拼 payload，
       * 也不猜测路由；只有完整票据同时出现时才允许请求纳管。
       */
      confirm_request: candidate.confirm_request && typeof candidate.confirm_request === 'object'
        ? {
            api: firstText(candidate.confirm_request.api, candidate.confirm_request.path),
            method: firstText(candidate.confirm_request.method, 'POST').toUpperCase(),
            body: candidate.confirm_request.body
          }
        : null
    };
  }

  function normalizeAcToken(token = {}, index = 0) {
    const expires = firstNumber(token.expires_at) || 0;
    const state = firstText(token.state, 'unknown');
    return {
      token_id: firstText(token.token_id, `token-${index}`),
      state,
      // 后端只记 expires_at，不把过期单独写进 state，所以过期判定放在前端。
      expired: state === 'active' && expires > 0 && expires <= nowSeconds(),
      site_id: firstText(token.site_id),
      hardware_bound: bool(token.hardware_bound, false),
      attempts: firstNumber(token.attempts) || 0,
      max_attempts: firstNumber(token.max_attempts) || 0,
      created_at: firstNumber(token.created_at) || 0,
      expires_at: expires,
      consumed_at: firstNumber(token.consumed_at) || 0,
      revoked_at: firstNumber(token.revoked_at) || 0
    };
  }

  function normalizeSsid(ssid = {}, index = 0) {
    /*
     * 后端现在给频段了。实测 GET /api/v1/wifi/config（30.1，2026-09-02）14 个 SSID
     * 每条都带 bands: ["2.4GHz"] 与标量 band: "2.4GHz"，一条 VAP 只属一个频段。
     * asArray() 对字符串返回 []，所以标量要显式包成数组，否则 band 这一路读不到。
     */
    const bandSource = ssid.bands || ssid.radio_bands || ssid.wlan_bands || (ssid.band ? [ssid.band] : []);
    const bands = asArray(bandSource).map(normalizeBand).filter(Boolean);
    const securityRaw = firstText(ssid.security, ssid.security_protocol, ssid.encryption, 'open').toLowerCase();
    const security = securityRaw.includes('wpa3') && securityRaw.includes('wpa2') ? 'wpa2-wpa3'
      : securityRaw.includes('enterprise') && securityRaw.includes('wpa3') ? 'wpa3-enterprise'
        : securityRaw.includes('enterprise') ? 'wpa2-enterprise'
          : securityRaw.includes('wpa3') || securityRaw.includes('sae') ? 'wpa3-personal'
            : securityRaw === 'none' || securityRaw.includes('open') ? 'open' : 'wpa2-personal';
    return {
      ...ssid,
      id: localWriteId(ssid, 'ssid', `wifi-${index}`),
      name: firstText(ssid.name, ssid.ssid, ssid.essid, '未命名 Wi-Fi'),
      radio_id: firstText(ssid.radio_id, ssid.runtime?.radio_id),
      ap_id: firstText(ssid.ap_id, ssid.runtime?.ap_id),
      bssid: firstText(ssid.bssid, ssid.mac, ssid.runtime?.bssid),
      network: firstText(ssid.network, ssid.lan, ssid.network_name, 'lan'),
      broadcast: firstText(ssid.broadcast, ssid.ap_group, ssid.broadcasting_aps, '全部 AP'),
      broadcast_mode: firstText(ssid.broadcast_mode, 'all'),
      /*
       * 后端没给频段就是空，绝不补默认值。原先这里写 `bands.length ? bands : ['2g','5g']`,
       * 于是 14 个 SSID 一律亮起「2.4 GHz + 5 GHz」两个徽章 —— 一个后端数据里毫无
       * 依据的双频事实，且与真实数据无法区分。
       *
       * 上面那条注释原先还说本端点根本不给 bands/radio_bands/wlan_bands、band 也是
       * null，因此频段只能永久留空。那已经不成立（见 bandSource 处的实测），所以
       * 「同名 SSID 跨频段（Xiaomi_DE23 同时有 2.4/5/6GHz 三条 VAP）只能各占一行」
       * 的结论也随之失效：现在每条 VAP 自己带频段，合并同名行不需要跨端点猜 id。
       */
      bands,
      /*
       * 客户端数缺失不是 0。firstNumber() 对缺失返回 0，而实测 14 个 SSID 的
       * clients 与 station_count 全是 null，于是表里整列显示 0 —— 与「真的没人连」
       * 无法区分，合并同名频段后还要相加，0 会被当成实数带进总和。
       * 写回不受影响：GET 给的本来就是 null，未编辑的 SSID 今天也原样带 null 回去。
       */
      clients: optionalNumber(ssid.clients, ssid.station_count),
      enabled: bool(ssid.enabled, false),
      security,
      password_present: bool(ssid.password_present, Boolean(ssid.key || ssid.password)),
      /*
       * Carry an explicitly supplied passphrase through instead of blanking it.
       * saveDraft() re-normalizes the sheet draft before committing it, so the
       * unconditional '' dropped the key the user just typed: the PUT then
       * described a psk2+ccmp SSID with no secret, hostapd refused to bring the
       * BSS up, and the page still reported a successful apply.  Read models
       * never carry `password`/`key` (only password_present), so this cannot
       * invent a secret out of a GET response.
       */
      password: firstText(ssid.password, ssid.key, ''),
      vlan: firstText(ssid.vlan, ssid.vlan_id, ''),
      protocol: firstText(ssid.protocol, ssid.wifi_protocol, 'auto'),
      encryption: firstText(ssid.encryption, security === 'open' ? 'none' : security === 'wpa3-personal' ? 'sae+ccmp' : 'psk2+ccmp'),
      pmf: firstText(ssid.pmf, security.includes('wpa3') ? 'required' : 'optional'),
      mlo: bool(ssid.mlo), ppsk: bool(ssid.ppsk || ssid.private_pre_shared_keys),
      band_steering: bool(ssid.band_steering), fast_roaming: bool(ssid.fast_roaming || ssid.ieee80211r),
      ieee80211r: bool(ssid.ieee80211r || ssid.ft), ieee80211k: bool(ssid.ieee80211k), ieee80211v: bool(ssid.ieee80211v),
      rrm: bool(ssid.rrm), qbssload: bool(ssid.qbssload),
      mobility_domain: firstText(ssid.mobility_domain, ''), nasid: firstText(ssid.nasid, ''),
      reassociation_deadline: firstNumber(ssid.reassociation_deadline, 1000), ft_over_ds: bool(ssid.ft_over_ds, true),
      ft_psk_generate_local: bool(ssid.ft_psk_generate_local, true), hidden: bool(ssid.hidden), isolate: bool(ssid.isolate || ssid.client_isolation),
      multicast_enhance: bool(ssid.multicast_enhance), multicast_control: bool(ssid.multicast_control), proxy_arp: bool(ssid.proxy_arp),
      radius_mac_auth: bool(ssid.radius_mac_auth), radius_profile: firstText(ssid.radius_profile, ''),
      mac_filter: firstText(ssid.mac_filter, 'off'), mac_addresses: asArray(ssid.mac_addresses),
      schedule_enabled: bool(ssid.schedule_enabled), schedule: firstText(ssid.schedule, ''),
      force_wifi4: bool(ssid.force_wifi4), speed_limit_id: firstText(ssid.speed_limit_id, 'default'), remark: firstText(ssid.remark, ssid.note, '')
    };
  }

  function normalizeConfig(payload = {}) {
    const source = payload.config && typeof payload.config === 'object' ? payload.config : payload;
    const base = emptyConfig();
    const caps = source.capabilities || {};
    const radios = asArray(source.radios, ['devices']).map(normalizeRadio);
    const bands = asArray(caps.bands).map(normalizeBand).filter(Boolean);
    const global = source.global && typeof source.global === 'object' ? source.global : {};
    const sourceWidths = objectValue(global.widths || global.channel_widths);
    const normalizedWidths = {};
    radios.forEach((radio) => {
      if (!radio.band || normalizedWidths[radio.band]) return;
      normalizedWidths[radio.band] = firstNumber(sourceWidths[radio.band], radio.width);
    });
    const wifiFacts = normalizeWifiFacts(source, caps, radios);
    return {
      ...base,
      ...source,
      ...wifiFacts,
      capabilities: {
        ...base.capabilities,
        ...caps,
        wifi: bool(caps.wifi, radios.length > 0),
        bands,
        save_config: bool(caps.save_config ?? caps.config_write ?? caps.update, false),
        apply_config: bool(caps.apply_config ?? caps.apply, false),
        /* 逐 scope 的原因（local / managed_ap 各一条），置灰提示要按 scope 说明，
           不能用一句笼统的"没有能力"盖掉两种不同原因。展开 ...caps 已经带进了这个键，
           这里显式保留是为了让契约可见、并挡住后续 normalize 覆盖。 */
        write_scopes: caps.write_scopes && typeof caps.write_scopes === 'object' ? caps.write_scopes : {},
        reasons: caps.reasons && typeof caps.reasons === 'object' ? caps.reasons : {},
        scan: bool(caps.scan ?? caps.airtime_scan, false)
      },
      regdomains: asArray(source.regdomains || source.regions),
      global: {
        ...base.global,
        ...global,
        widths: normalizedWidths
      },
      radios,
      ssids: asArray(source.ssids, ['wlans', 'networks']).map(normalizeSsid),
      speed_limits: asArray(source.speed_limits, ['speed_profiles', 'limits']).map((limit, index) => ({
        ...limit,
        id: firstText(limit.id, limit.name, `limit-${index}`),
        name: firstText(limit.name, `档案 ${index + 1}`),
        download_mbps: firstNumber(limit.download_mbps, limit.download),
        upload_mbps: firstNumber(limit.upload_mbps, limit.upload)
      }))
    };
  }

  function normalizeStatus(payload = {}) {
    const source = payload.status && typeof payload.status === 'object' ? payload.status : payload;
    const base = emptyStatus();
    const runtime = source.runtime && typeof source.runtime === 'object' ? source.runtime : {};
    const radios = asArray(source.runtime_radios || runtime.radios || source.radios).map(normalizeRadio);
    const caps = source.capabilities || {};
    const environment = source.environment && typeof source.environment === 'object' ? source.environment : {};
    const channelSurvey = environment.channel_survey && typeof environment.channel_survey === 'object' ? environment.channel_survey : {};
    const neighborScan = environment.neighbor_scan && typeof environment.neighbor_scan === 'object' ? environment.neighbor_scan : {};
    const spectralFft = environment.spectral_fft && typeof environment.spectral_fft === 'object' ? environment.spectral_fft : {};
    const neighborSamples = asArray(neighborScan.samples);
    const stations = asArray(source.stations || runtime.stations || source.clients);
    const stationSignalDistributions = deriveStationSignalDistributions(radios, stations);
    const wifiFacts = normalizeWifiFacts(source, caps, radios);
    return {
      ...base,
      ...source,
      ...wifiFacts,
      capabilities: { ...base.capabilities, ...caps, wifi: bool(caps.wifi, radios.length > 0), scan: bool(caps.scan ?? caps.airtime_scan, false) },
      summary: { ...base.summary, ...(source.summary || {}) },
      managedAps: asArray(source.managed_aps, ['items']).map(normalizeAp),
      radios: radios.map((radio, index) => ({
        ...radio,
        derived_signal_distribution: stationSignalDistributions[index]
      })),
      ssids: asArray(source.ssids, ['wlans']).map(normalizeSsid),
      stations,
      interference: asArray(source.interference || runtime.interference).length ? asArray(source.interference || runtime.interference) : neighborSamples,
      connectivityEvents: asArray(source.connectivity_events || source.events || runtime.connectivity_events || runtime.events),
      environment: {
        channelSurvey: { ...channelSurvey, samples: asArray(channelSurvey.samples) },
        neighborScan: { ...neighborScan, samples: neighborSamples },
        spectralFft: { ...spectralFft, samples: asArray(spectralFft.samples) }
      },
      runtime: { ...base.runtime, ...runtime }
    };
  }

  function environmentRangeSeconds(value = state.filters.environmentRange) {
    return ({ '30m': 1800, '1h': 3600, '1d': 86400, '1w': 604800, '1m': 2592000 })[value] || 86400;
  }

  async function loadEnvironmentHistory() {
    if (!isStatus || !state.mounted) return;
    const seq = ++state.environmentHistorySeq;
    const end = Math.floor(Date.now() / 1000);
    const seconds = environmentRangeSeconds();
    const query = new URLSearchParams({
      start: String(end - seconds),
      end: String(end),
      resolution: seconds > 86400 ? '3600' : '300',
      limit: '2048'
    });
    if (state.filters.environmentAp !== 'all') query.set('ap_id', state.filters.environmentAp);
    state.environmentHistory.loading = true;
    state.environmentHistory.error = '';
    patchLiveRegion();
    try {
      const payload = await requestJson(`/api/v1/wifi/environment/survey-history?${query}`, { cacheVersion: false });
      if (!state.mounted || seq !== state.environmentHistorySeq) return;
      state.environmentHistory = {
        points: asArray(payload.points),
        reason: firstText(payload.reason, asArray(payload.points).length ? 'available' : 'no_samples'),
        resolution_seconds: firstNumber(payload.resolution_seconds),
        /* 后端 ac_db_survey_history_json() 只统计**查询窗口内**命中行的最大
           last_received_at，窗口内没有行时它就是 null。所以这个值能回答"最近一次采集
           有多旧"，但不能回答"窗口外是否还存着更老的数据"——后者要另开一次更宽的查询，
           前端不假装知道。 */
        latest_received_at: firstNumber(payload.latest_received_at),
        loading: false,
        error: ''
      };
    } catch (error) {
      if (!state.mounted || seq !== state.environmentHistorySeq) return;
      state.environmentHistory = { points: [], reason: 'request_failed', resolution_seconds: 0, latest_received_at: 0, loading: false, error: firstText(error.message, '读取失败') };
    }
    patchLiveRegion();
  }

  function normalizeConnectivityEvent(event = {}) {
    const ap = state.status.managedAps.find((item) => item.id === event.ap_id);
    const radio = state.status.radios.find((item) => item.ap_id === event.ap_id &&
      radioMatchesId(item, event.radio_id));
    /* ssid_id 在 ac_station_events 里是裸接口名（250 实测 `phy0.2-ap0`），而聚合后的
       ssid.id 已被压成同一个裸 local_id，所以 endsWith(':'+id) 永远不成立。逐字比较
       末段，接口名兜底不变。 */
    const ssid = state.status.ssids.find((item) => item.ap_id === event.ap_id &&
      (radioIdTail(item.id) === String(event.ssid_id || '').toLowerCase() ||
       item.interface === event.interface));
    const signalValue = event.signal_dbm ?? event.previous_signal_dbm;
    return {
      ...event,
      client: firstText(event.station_mac, '--'),
      event_kind: firstText(event.event, ''),
      event: ({ connect: '连接', disconnect: '断开', roam: '漫游' })[event.event] || firstText(event.event, '--'),
      ap: firstText(ap?.name, ap?.model, event.ap_id),
      signal: signalValue === null || signalValue === undefined ? '' : `${signalValue} dBm`,
      band: firstText(radio?.band, ''),
      ssid: firstText(ssid?.name, event.interface, event.from_interface),
      date_time: event.observed_at ? new Date(event.observed_at * 1000).toLocaleString() : ''
    };
  }

  async function loadConnectivityEvents() {
    if (!isStatus || !state.mounted) return;
    if (!bool(state.status.capabilities.connectivity_events, false)) return;
    const seq = ++state.connectivityEventsSeq;
    const end = Math.floor(Date.now() / 1000);
    const query = new URLSearchParams({
      start: String(end - state.filters.connectivityRange * 3600),
      end: String(end),
      limit: '256'
    });
    state.connectivityEvents.loading = true;
    state.connectivityEvents.error = '';
    try {
      const payload = await requestJson(`/api/v1/wifi/connectivity/events?${query}`, { cacheVersion: false });
      if (!state.mounted || seq !== state.connectivityEventsSeq) return;
      const items = asArray(payload.items).map(normalizeConnectivityEvent).reverse();
      state.connectivityEvents = {
        items,
        reason: firstText(payload.reason, items.length ? 'available' : 'no_events'),
        loading: false,
        error: ''
      };
    } catch (error) {
      if (!state.mounted || seq !== state.connectivityEventsSeq) return;
      state.connectivityEvents = { items: [], reason: 'request_failed', loading: false, error: firstText(error.message, '读取失败') };
    }
    if (state.statusView === 'connectivity') render();
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
    const cacheVersion = options.cacheVersion !== false;
    const fetchOptions = { ...options };
    delete fetchOptions.cacheVersion;
    const response = await sessionFetch(cacheVersion ? `${url}${url.includes('?') ? '&' : '?'}v=${VERSION}` : url, {
      credentials: 'same-origin', cache: 'no-store', ...fetchOptions,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    const payload = json?.data ?? json?.body ?? json;
    if (!response.ok || json?.ok === false || payload?.ok === false) {
      const detail = objectValue(payload?.error || json?.error);
      const error = new Error(firstText(detail.message, payload?.message, json?.message, typeof payload?.error === 'string' ? payload.error : '', typeof json?.error === 'string' ? json.error : '', `HTTP ${response.status}`));
      error.status = response.status;
      error.code = firstText(detail.code, payload?.code, json?.code, typeof payload?.error === 'string' ? payload.error : '', typeof json?.error === 'string' ? json.error : '');
      error.reason = firstText(detail.reason, payload?.reason, json?.reason);
      throw error;
    }
    if (json?.resource && json?.contract === 'product-plane.v1' && (!options.method || options.method === 'GET')) {
      window.DWRT_DATA_REGISTRY?.accept(json.resource, json);
    }
    return payload || {};
  }

  // Called by action handlers only. Loading and rendering never emit operation feedback.
  function operationFailure(title, error) {
    const code = firstText(error?.code, error?.reason);
    const message = firstText(error?.message, '未知错误');
    const detail = code && !message.includes(code) ? `${message} (${code})` : message;
    window.DreamingWrtNotify?.error(title, detail);
    return `${title}：${detail}`;
  }

  async function load(background = false) {
    const seq = ++state.seq;
    if (background) state.refreshing = true; else state.loading = true;
    state.error = '';
    if (!background && !root.querySelector('.wifi-management-shell')) render();
    try {
      const payload = await requestJson(ENDPOINT);
      if (!state.mounted || seq !== state.seq) return;
      if (isStatus) {
        const keptDefaultFilters = state.statusFiltersReady && radioFiltersDefault();
        state.status = normalizeStatus(payload);
        if (state.status.channel_ai?.plan) {
          state.channelAi.data = state.status.channel_ai;
          state.channelAi.error = '';
          state.channelAi.loaded = true;
        } else if (state.statusView === 'channel-ai') loadChannelAi();
        if (state.statusView === 'connectivity' &&
            state.connectivityEvents.reason === 'not_loaded') loadConnectivityEvents();
        const apIds = Array.from(new Set(state.status.radios.map((radio) => radio.ap_id).filter(Boolean)));
        if (!apIds.includes(state.filters.environmentAp)) state.filters.environmentAp = apIds[0] || 'all';
        if (!state.statusFiltersReady || keptDefaultFilters) {
          state.filters.aps = new Set(state.status.radios.map((radio) => radio.ap_id).filter(Boolean));
          state.filters.bands = new Set(state.status.radios.map((radio) => radio.band).filter(Boolean));
          state.statusFiltersReady = true;
        }
      } else {
        state.rawConfig = clone(payload);
        state.config = normalizeConfig(payload);
        const liveIds = new Set(state.config.ssids.map((ssid) => ssid.id));
        state.selectedSsids.forEach((id) => { if (!liveIds.has(id)) state.selectedSsids.delete(id); });
      }
      state.loaded = true;
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.error = `${isStatus ? '读取无线运行状态' : '读取 Wi-Fi 配置'}失败：${firstText(error.message, '未知错误')}`;
    } finally {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      if (background) patchLiveRegion(); else render();
    }
  }

  /*
   * AP 管理 Tab 的数据加载。三个只读端点并发取：
   *   GET /api/v1/ac/aps            清单
   *   GET /api/v1/ac/capabilities   能力位（含 reasons）
   *   GET /api/v1/ac/pairing-tokens 配对令牌
   * 路径前缀由后端定稿为 /api/v1/ac/（不是 /api/v1/wifi/），不新增别名。
   *
   * 能力位只在运行时读，不缓存成常量：写死过一次探测结果就会在后端放开
   * 事务层之后继续显示"不可用"，这类漂移今天已经出现过四笔。
   */
  async function loadAc(background = false) {
    const seq = ++state.ac.seq;
    state.ac.loading = !background || !state.ac.loaded;
    if (!background) state.ac.error = '';
    if (!background) render();
    try {
      const [aps, caps, tokens] = await Promise.all([
        requestJson('/api/v1/ac/aps'),
        requestJson('/api/v1/ac/capabilities'),
        requestJson('/api/v1/ac/pairing-tokens')
      ]);
      if (!state.mounted || seq !== state.ac.seq) return;
      const capabilities = caps.capabilities && typeof caps.capabilities === 'object' ? caps.capabilities : {};
      state.ac.aps = asArray(aps.items || aps.aps).map(normalizeAcAp);
      state.ac.tokens = asArray(tokens.items || tokens.tokens).map(normalizeAcToken);
      state.ac.capabilities = capabilities;
      state.ac.reasons = capabilities.reasons && typeof capabilities.reasons === 'object' ? capabilities.reasons : {};
      state.ac.observedAt = firstNumber(aps.observed_at) || 0;
      state.ac.discovery = await loadAcDiscovery(capabilities);
      state.ac.loaded = true;
      state.ac.error = '';
      maybePromptDiscoveryCandidate();
    } catch (error) {
      if (!state.mounted || seq !== state.ac.seq) return;
      state.ac.error = `读取 AP 管理数据失败：${firstText(error.message, '未知错误')}`;
    } finally {
      if (!state.mounted || seq !== state.ac.seq) return;
      state.ac.loading = false;
      if (background && state.configView === 'aps' && !state.sheet) patchAcSections(); else render();
    }
  }

  const ROAMING_EDITABLE_FIELDS = [
    'steering_preference', 'weak_rssi_dbm', 'high_band_steer_enabled',
    'force_disassoc_on_reject', 'lower_band_block_enabled',
    'reassoc_block_enabled', 'reassoc_block_sec', 'reassoc_block_scope'
  ];

  function roamingDomain() {
    return state.roaming.domains.find((domain) => domain.domain_id === state.roaming.domainId) || null;
  }

  function roamingCoreCapabilities(domain = roamingDomain()) {
    return {
      neighborReport: bool(domain?.neighbor_report_enabled, false),
      bssTransition: bool(domain?.bss_transition_enabled, false),
      deauth: bool(domain?.deauth_enabled, false)
    };
  }

  function roamingPolicyCapabilityReason() {
    const domain = roamingDomain();
    const caps = roamingCoreCapabilities(domain);
    if (!state.roaming.domainId) return state.roaming.domains.length > 1 ? '请先选择一个漫游域。' : '尚未配置漫游域。';
    if (!caps.neighborReport) return '当前漫游域未启用 802.11k 邻居报告，无法根据其他 AP 的实测信号选择候选。';
    if (!caps.bssTransition) return '当前漫游域未启用 802.11v BSS Transition Management，无法下发漫游建议。';
    if (!canPerformMediumRisk()) return '当前账号没有执行漫游策略写入的权限。';
    if (state.roaming.writeDenied) return '后端拒绝了本次漫游策略写入，当前按只读状态保留。';
    return '';
  }

  function roamingPolicyWriteAllowed() {
    return Boolean(state.roaming.draft && state.roaming.domainId && !state.roaming.loading &&
      !state.roaming.saving && !roamingPolicyCapabilityReason());
  }

  function roamingErrorCopy(error) {
    if (error?.status === 401) return '会话已失效，请重新登录后再试。';
    if (error?.status === 403) return '当前账号没有执行漫游策略写入的权限。';
    if (error?.status === 409) return '配置版本已变化，请确认当前草稿后再次保存。';
    if (error?.status === 503) return 'AC 控制面当前不可用，请稍后重试。';
    if (error?.status === 400) return `AC 拒绝了漫游策略参数：${firstText(error.reason, error.code, error.message, '参数或能力不满足要求')}。`;
    return firstText(error?.message, error?.reason, '漫游策略不可用。');
  }

  function roamingDraftDirty() {
    return Boolean(state.roaming.baseline && state.roaming.draft &&
      JSON.stringify(state.roaming.baseline) !== JSON.stringify(state.roaming.draft));
  }

  function mergeRoamingDraftWithLatest(latest, preservedDraft) {
    const draft = clone(latest);
    ROAMING_EDITABLE_FIELDS.forEach((field) => {
      if (preservedDraft && Object.prototype.hasOwnProperty.call(preservedDraft, field)) draft[field] = clone(preservedDraft[field]);
    });
    draft.revision = latest.revision;
    return draft;
  }

  async function loadRoamingPolicy(domainId = '', options = {}) {
    const seq = ++state.roaming.seq;
    const preserveDraft = options.preserveDraft === true;
    const preservedDraft = preserveDraft ? clone(state.roaming.draft) : null;
    state.roaming.loading = true;
    state.roaming.error = '';
    if (!preserveDraft) state.roaming.notice = '';
    if (state.mounted && state.configView === 'extensions') render();
    try {
      const domainsResponse = await requestJson('/api/v1/ac/roaming-domains');
      const domains = asArray(domainsResponse.items || domainsResponse.domains).filter((domain) => domain && domain.domain_id);
      if (!state.mounted || seq !== state.roaming.seq) return;
      const requestedId = firstText(domainId, state.roaming.domainId);
      const selected = domains.find((domain) => domain.domain_id === requestedId) ||
        (domains.length === 1 ? domains[0] : null);
      state.roaming.domains = domains;
      state.roaming.domainId = selected?.domain_id || '';
      state.roaming.loaded = true;
      state.roaming.conflict = false;
      if (!state.roaming.domainId) {
        state.roaming.baseline = null;
        state.roaming.draft = null;
        state.roaming.dirty = false;
        return;
      }
      const response = await requestJson(`/api/v1/ac/roaming-policy?domain_id=${encodeURIComponent(state.roaming.domainId)}`);
      const policy = objectValue(response.policy);
      if (!state.mounted || seq !== state.roaming.seq) return;
      state.roaming.baseline = clone(policy);
      state.roaming.draft = preserveDraft ? mergeRoamingDraftWithLatest(policy, preservedDraft) : clone(policy);
      state.roaming.dirty = preserveDraft ? roamingDraftDirty() : false;
      state.roaming.writeDenied = false;
    } catch (error) {
      if (!state.mounted || seq !== state.roaming.seq) return;
      state.roaming.error = roamingErrorCopy(error);
      if (error?.status === 403) state.roaming.writeDenied = true;
    } finally {
      if (!state.mounted || seq !== state.roaming.seq) return;
      state.roaming.loading = false;
      if (state.mounted && state.configView === 'extensions') render();
    }
  }

  function roamingPolicyPayload() {
    const draft = state.roaming.draft || {};
    const domain = roamingDomain();
    const caps = roamingCoreCapabilities(domain);
    const preference = ['stability', 'performance'].includes(draft.steering_preference) ? draft.steering_preference : 'stability';
    const highBand = bool(draft.high_band_steer_enabled, false);
    const force = preference === 'performance' && bool(draft.force_disassoc_on_reject, false) && caps.deauth;
    const lower = force && highBand && bool(draft.lower_band_block_enabled, false);
    const numericFields = [
      'weak_rssi_dbm', 'minimum_candidate_gain_db', 'candidate_min_rssi_dbm',
      'decision_min_interval_sec', 'post_roam_cooldown_sec', 'max_btm_attempts_per_hour',
      'deauth_after_btm_failures', 'deauth_cooldown_sec', 'domain_action_rate_limit', 'reassoc_block_sec'
    ];
    for (const field of numericFields) {
      if (!Number.isFinite(Number(draft[field]))) throw new Error(`漫游策略字段 ${field} 缺少有效数值。`);
    }
    const reassocBlockSec = Number(draft.reassoc_block_sec);
    if (reassocBlockSec < 1 || reassocBlockSec > 30) throw new Error('重新关联拒绝租约必须是 1 到 30 秒。');
    if (Number(draft.weak_rssi_dbm) < -100 || Number(draft.weak_rssi_dbm) > -40) throw new Error('弱信号阈值必须在 -100 到 -40 dBm 之间。');
    return {
      domain_id: state.roaming.domainId,
      weak_rssi_dbm: Number(draft.weak_rssi_dbm),
      minimum_candidate_gain_db: Number(draft.minimum_candidate_gain_db),
      candidate_min_rssi_dbm: Number(draft.candidate_min_rssi_dbm),
      decision_min_interval_sec: Number(draft.decision_min_interval_sec),
      post_roam_cooldown_sec: Number(draft.post_roam_cooldown_sec),
      max_btm_attempts_per_hour: Number(draft.max_btm_attempts_per_hour),
      deauth_after_btm_failures: Number(draft.deauth_after_btm_failures),
      deauth_cooldown_sec: Number(draft.deauth_cooldown_sec),
      domain_action_rate_limit: Number(draft.domain_action_rate_limit),
      steering_preference: preference,
      high_band_steer_enabled: highBand,
      force_disassoc_on_reject: force,
      lower_band_block_enabled: lower,
      reassoc_block_enabled: lower,
      reassoc_block_sec: reassocBlockSec,
      reassoc_block_scope: lower ? 'lower' : firstText(draft.reassoc_block_scope, state.roaming.baseline?.reassoc_block_scope, 'ap'),
      base_revision: Number(state.roaming.baseline?.revision),
      updated_by: 'web-console'
    };
  }

  function roamingPolicyMatches(payload, policy) {
    const fields = ['steering_preference', 'weak_rssi_dbm', 'high_band_steer_enabled', 'force_disassoc_on_reject', 'lower_band_block_enabled', 'reassoc_block_enabled', 'reassoc_block_sec', 'reassoc_block_scope'];
    return fields.every((field) => {
      const left = typeof payload[field] === 'boolean' ? payload[field] : Number.isFinite(Number(payload[field])) ? Number(payload[field]) : payload[field];
      const right = typeof policy?.[field] === 'boolean' ? policy[field] : Number.isFinite(Number(policy?.[field])) ? Number(policy[field]) : policy?.[field];
      return left === right;
    });
  }

  async function saveRoamingPolicy() {
    if (!state.roaming.dirty || !state.roaming.draft || !state.roaming.domainId || state.roaming.saving) return false;
    state.roaming.saving = true;
    state.roaming.error = '';
    state.roaming.notice = '';
    state.roaming.conflict = false;
    render();
    let payload;
    try {
      payload = roamingPolicyPayload();
      await requestJson('/api/v1/ac/roaming-policy', { method: 'PUT', body: JSON.stringify(payload) });
      const readback = await requestJson(`/api/v1/ac/roaming-policy?domain_id=${encodeURIComponent(state.roaming.domainId)}`);
      const policy = objectValue(readback.policy);
      if (!roamingPolicyMatches(payload, policy)) throw new Error('后端回读与提交的漫游策略不一致，草稿仍保留。');
      state.roaming.baseline = clone(policy);
      state.roaming.draft = clone(policy);
      state.roaming.dirty = false;
      state.roaming.notice = '漫游策略已保存并完成回读。';
      state.roaming.noticeTone = 'ok';
      return true;
    } catch (error) {
      operationFailure('保存漫游策略失败', error);
      if (error?.status === 409) {
        try {
          const latestResponse = await requestJson(`/api/v1/ac/roaming-policy?domain_id=${encodeURIComponent(state.roaming.domainId)}`);
          const latest = objectValue(latestResponse.policy);
          state.roaming.baseline = clone(latest);
          state.roaming.draft = mergeRoamingDraftWithLatest(latest, state.roaming.draft);
          state.roaming.dirty = roamingDraftDirty();
          state.roaming.conflict = true;
          state.roaming.notice = '配置版本已变化，请确认当前草稿后再次保存。';
          state.roaming.noticeTone = 'warn';
        } catch (refreshError) {
          state.roaming.error = `版本冲突，且无法读取最新策略：${roamingErrorCopy(refreshError)}`;
        }
      } else {
        state.roaming.error = roamingErrorCopy(error);
        if (error?.status === 403) state.roaming.writeDenied = true;
      }
      return false;
    } finally {
      state.roaming.saving = false;
      render();
    }
  }

  function discardRoamingPolicy() {
    if (!state.roaming.baseline) return;
    state.roaming.draft = clone(state.roaming.baseline);
    state.roaming.dirty = false;
    state.roaming.error = '';
    state.roaming.notice = '';
    state.roaming.conflict = false;
  }

  function setRoamingDraftField(path, value) {
    if (!state.roaming.draft || !roamingPolicyWriteAllowed()) return;
    setPath(state.roaming.draft, path, value);
    const preference = firstText(state.roaming.draft.steering_preference, 'stability');
    const highBand = bool(state.roaming.draft.high_band_steer_enabled, false);
    const force = preference === 'performance' && bool(state.roaming.draft.force_disassoc_on_reject, false) && roamingCoreCapabilities().deauth;
    if (path === 'steering_preference' && preference !== 'performance') {
      state.roaming.draft.force_disassoc_on_reject = false;
      state.roaming.draft.lower_band_block_enabled = false;
      state.roaming.draft.reassoc_block_enabled = false;
    }
    if (path === 'high_band_steer_enabled' && !highBand) {
      state.roaming.draft.lower_band_block_enabled = false;
      state.roaming.draft.reassoc_block_enabled = false;
    }
    if (path === 'force_disassoc_on_reject' && !force) {
      state.roaming.draft.lower_band_block_enabled = false;
      state.roaming.draft.reassoc_block_enabled = false;
    }
    if (path === 'lower_band_block_enabled') {
      state.roaming.draft.reassoc_block_enabled = Boolean(value);
      if (value) state.roaming.draft.reassoc_block_scope = 'lower';
    }
    state.roaming.dirty = roamingDraftDirty();
    state.roaming.error = '';
    state.roaming.conflict = false;
  }

  function onRoamingSegmentChange(event) {
    if (!event.target.matches('[data-roaming-preference]')) return;
    setRoamingDraftField('steering_preference', event.detail.value);
    render();
  }

  function acCap(name) { return bool(state.ac.capabilities[name], false); }

  /* ── txpower-mode API ─────────────────────────────────────────────── */

  async function fetchTxpowerMode(apId, options = {}) {
    const url = `/api/v1/ac/aps/${encodeURIComponent(apId)}/txpower-mode`;
    const isPost = (options.method || 'GET').toUpperCase() === 'POST';
    const response = await sessionFetch(`${url}?v=${VERSION}`, {
      credentials: 'same-origin', cache: 'no-store', ...options,
      headers: authHeaders({ ...(isPost ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) try { json = JSON.parse(text); } catch (_) { /* ignore parse errors */ }
    const payload = json?.data ?? json?.body ?? json;
    const success = response.ok && json?.ok !== false && (!payload || payload.ok !== false);
    return {
      ok: success,
      status: response.status,
      data: payload || {},
      reason: firstText(payload?.reason, json?.reason),
      error: success ? '' : firstText(payload?.message, payload?.error, json?.message, json?.error, `HTTP ${response.status}`)
    };
  }

  async function loadTxpowerMode(apId) {
    if (!apId) return;
    const prev = state.txpower.apId;
    state.txpower.loading = true;
    state.txpower.error = '';
    state.txpower.apId = apId;
    state.txpower.data = null;
    state.txpower.confirmPending = false;
    render();
    try {
      const result = await fetchTxpowerMode(apId);
      if (state.apSheetAp !== apId) return;
      if (result.ok) {
        state.txpower.data = result.data;
      } else if (result.status === 504) {
        /* 504 是 webd 的 dependency_timeout：AC 受理了，但 AP 的 txpower 轮询
           挂在心跳节奏上（最坏 30 秒）。这不是"方法不存在"，落进
           apd_method_absent 会让页面谎报固件太旧。 */
        state.txpower.data = { ok: false, reason: 'dependency_timeout' };
      } else if (result.status === 503 || result.status === 501) {
        state.txpower.data = { ok: false, reason: 'apd_method_absent' };
      } else {
        state.txpower.data = result.data && result.data.reason ? result.data : { ok: false, reason: 'unknown_error' };
        state.txpower.error = result.error || '读取发射功率模式失败';
      }
    } catch (error) {
      if (state.apSheetAp !== apId) return;
      state.txpower.data = { ok: false, reason: 'transport_error' };
      state.txpower.error = operationFailure('设置发射功率失败', error);
    } finally {
      if (state.apSheetAp !== apId) return;
      state.txpower.loading = false;
      render();
    }
  }

  async function setTxpowerMode(apId, mode, confirm) {
    if (state.txpower.busy) return;
    state.txpower.busy = true;
    state.txpower.error = '';
    state.txpower.confirmPending = false;
    render();
    try {
      const body = { mode };
      if (confirm) body.confirm = true;
      const result = await fetchTxpowerMode(apId, { method: 'POST', body: JSON.stringify(body) });
      if (state.apSheetAp !== apId) return;
      if (result.ok) {
        state.txpower.data = result.data;
      } else if (result.reason === 'confirmation_required') {
        /* Backend says confirm is needed — show the dialog. */
        state.txpower.confirmPending = true;
      } else {
        state.txpower.error = operationFailure('设置发射功率失败', { code: result.reason, message: txpowerReasonText(result.reason) || result.error || '设置失败' });
        if (result.data && result.data.mode) state.txpower.data = result.data;
      }
    } catch (error) {
      if (state.apSheetAp !== apId) return;
      state.txpower.error = firstText(error.message, '网络错误');
    } finally {
      if (state.apSheetAp !== apId) return;
      state.txpower.busy = false;
      render();
    }
  }

  function txpowerReasonText(reason) {
    const map = {
      board_not_standard_power_capable: '此设备不支持高功率模式',
      driver_txpower_param_absent: '需要升级固件以支持高功率模式',
      apd_method_absent: '需要升级 AP 固件以支持高功率模式',
      confirmation_required: '操作需要确认',
      param_write_failed: '写入失败，请重试或查看日志',
      transport_error: 'AP 通信失败',
      /* webd 现在用 app_ubus_object_or_error_timeout() 调这两个方法，AP 没能
         在窗口内回应时给 dependency_timeout + HTTP 504。它和 503 的含义不同：
         控制器活着、请求已受理，只是 AP 还没轮询到，重试会成功。 */
      dependency_timeout: 'AP 未在等待窗口内回应发射功率模式，稍后重试',
      ap_transport_timeout: 'AP 未在等待窗口内回应发射功率模式，稍后重试',
      txpower_request_busy: '已有一笔发射功率模式请求在处理中',
      unknown_error: '未知错误'
    };
    return map[reason] || '';
  }

  function txpowerCanUse(data) {
    if (!data || data.ok === false) return false;
    return bool(data.supported, false) && bool(data.param_present, false);
  }

  async function loadAcDiscovery(capabilities = state.ac.capabilities) {
    const capabilityAvailable = bool(capabilities?.ap_discovery, false);
    const base = {
      available: capabilityAvailable,
      endpointAvailable: false,
      reason: firstText(capabilities?.reasons?.ap_discovery),
      items: [],
      observedAt: 0,
      confirmApi: firstText(capabilities?.ap_discovery_confirm_api),
      confirmAvailable: bool(capabilities?.ap_discovery_confirm, false)
    };
    if (!capabilityAvailable) return base;
    try {
      const payload = await requestJson('/api/v1/ac/discovery');
      return {
        ...base,
        available: bool(payload.available, capabilityAvailable),
        endpointAvailable: true,
        reason: firstText(payload.reason, base.reason),
        items: asArray(payload.items).map(normalizeDiscoveryCandidate),
        observedAt: firstNumber(payload.observed_at) || 0,
        confirmApi: firstText(payload.confirm_api, base.confirmApi),
        confirmAvailable: bool(payload.confirm_available, base.confirmAvailable)
      };
    } catch (error) {
      return { ...base, reason: firstText(error.message, 'discovery_endpoint_unavailable') };
    }
  }

  function discoveryConfirmRequest(candidate = {}) {
    const request = candidate.confirm_request;
    const api = firstText(request?.api);
    if (!request || typeof request.body !== 'object' || Array.isArray(request.body) || !api.startsWith('/api/v1/ac/') ||
        api.startsWith('//') || request.method !== 'POST') return null;
    return { api, body: request.body };
  }

  function canConfirmDiscoveryCandidate(candidate) {
    const discovery = state.ac.discovery || {};
    return discovery.endpointAvailable && discovery.confirmAvailable && Boolean(discoveryConfirmRequest(candidate));
  }

  function discoveryCandidateKey(candidate = {}) {
    return firstText(candidate.ap_id, candidate.key_id, candidate.mac);
  }

  function bootstrapBundleValid(bundle) {
    return Boolean(bundle && typeof bundle === 'object' && !Array.isArray(bundle) &&
      firstText(bundle.bootstrap_code) && firstText(bundle.ca_cert_pem) && firstNumber(bundle.expires_at) > 0);
  }

  function bootstrapBundleJson(bundle, pretty = false) {
    try { return JSON.stringify(bundle, null, pretty ? 2 : 0); } catch (_) { return ''; }
  }

  function shellQuote(value) {
    return `'${String(value ?? '').replace(/'/g, "'\\''")}'`;
  }

  function bootstrapCommand(bundle, nextStep = '') {
    const serialized = bootstrapBundleJson(bundle);
    const template = firstText(nextStep);
    if (template && /<json>/i.test(template)) return template.replace(/<json>/ig, serialized);
    return template || `jmctl ap pair --bundle ${shellQuote(serialized)}`;
  }

  function bootstrapStatusLabel(value) {
    const labels = {
      binding_requested: '已请求绑定',
      enrollment_pending: '等待 AP 纳管',
      adopted: '已纳管',
      failed: '纳管失败',
      expired: '已过期',
      cancelled: '已取消'
    };
    return labels[firstText(value)] || firstText(value, '状态未知');
  }

  function bootstrapErrorLabel(error) {
    const code = firstText(error?.code, error?.reason, 'binding_error');
    const labels = {
      invalid_qr: '绑定请求无效，请重新从发现列表发起确认。',
      ticket_expired: '确认票据已过期，请重新从发现列表发起确认。',
      ticket_consumed: '确认票据已使用，不能重复确认。',
      ticket_replayed: '确认票据已被拒绝重放，请重新发起确认。',
      ap_not_found: '候选 AP 已不在发现列表中。',
      ap_identity_mismatch: 'AP 指纹已变化，确认已停止。',
      ap_already_bound: '该 AP 已经被纳管。',
      enrollment_pending: '该 AP 已有进行中的纳管请求。',
      binding_not_found: '绑定记录不存在或已被清理。',
      bootstrap_unavailable: '后端暂时无法生成一次性配置包。',
      bootstrap_bundle_missing: '后端未返回一次性配置包，未显示任何 secret。',
      request_failed: '绑定状态暂时无法读取。'
    };
    return { code, text: labels[code] || 'AP 纳管请求失败，请稍后重试。' };
  }

  function clearBootstrapTimers() {
    if (state.adoption.pollTimer) clearTimeout(state.adoption.pollTimer);
    if (state.adoption.expiryTimer) clearTimeout(state.adoption.expiryTimer);
    state.adoption.pollTimer = 0;
    state.adoption.expiryTimer = 0;
  }

  function clearBootstrapBundle(reason = 'closed', rerender = true) {
    if (state.adoption.expiryTimer) clearTimeout(state.adoption.expiryTimer);
    state.adoption.expiryTimer = 0;
    state.adoption.secret = null;
    state.adoption.command = '';
    state.adoption.secretClearedReason = reason;
    state.adoption.copyFeedback = '';
    state.adoption.copyTone = '';
    if (rerender && state.mounted) render();
  }

  function scheduleBootstrapExpiry(bundle) {
    if (state.adoption.expiryTimer) clearTimeout(state.adoption.expiryTimer);
    const expiresAt = firstNumber(bundle?.expires_at);
    if (!expiresAt) return;
    const delay = Math.max(0, expiresAt * 1000 - Date.now());
    state.adoption.expiryTimer = window.setTimeout(() => {
      clearBootstrapBundle('expired');
    }, delay);
  }

  function adoptionTerminalState(value) {
    return ['adopted', 'failed', 'expired', 'cancelled'].includes(firstText(value));
  }

  function scheduleAdoptionStatusPoll(seq, delay) {
    if (!state.mounted || seq !== state.adoption.pollSeq || !state.adoption.bindingId || adoptionTerminalState(state.adoption.state)) return;
    if (state.adoption.pollTimer) clearTimeout(state.adoption.pollTimer);
    state.adoption.pollTimer = window.setTimeout(() => {
      state.adoption.pollTimer = 0;
      pollAdoptionStatus(seq);
    }, Math.max(500, Number(delay) || state.adoption.pollIntervalMs || 2000));
  }

  async function pollAdoptionStatus(seq = state.adoption.pollSeq) {
    const bindingId = state.adoption.bindingId;
    if (!bindingId || !state.mounted || seq !== state.adoption.pollSeq) return;
    state.adoption.polling = true;
    try {
      const payload = await requestJson(`/api/v1/ac/ap-bindings/${encodeURIComponent(bindingId)}`, { cacheVersion: false });
      if (!state.mounted || seq !== state.adoption.pollSeq) return;
      state.adoption.state = firstText(payload.state, payload.binding_state, payload.status, state.adoption.state);
      state.adoption.pollIntervalMs = Math.max(500, firstNumber(payload.poll_interval_ms) || state.adoption.pollIntervalMs || 2000);
      const statusError = payload.error && typeof payload.error === 'object' ? payload.error : null;
      state.adoption.error = statusError ? firstText(statusError.code, statusError.failure_code) : '';
      if (!adoptionTerminalState(state.adoption.state)) scheduleAdoptionStatusPoll(seq, state.adoption.pollIntervalMs);
    } catch (error) {
      if (!state.mounted || seq !== state.adoption.pollSeq) return;
      state.adoption.error = firstText(error.code, error.reason, 'request_failed');
      scheduleAdoptionStatusPoll(seq, state.adoption.pollIntervalMs);
    } finally {
      if (!state.mounted || seq !== state.adoption.pollSeq) return;
      state.adoption.polling = false;
      render();
    }
  }

  function startAdoptionStatusPoll(bindingId, initialState, pollIntervalMs) {
    clearBootstrapTimers();
    state.adoption.pollSeq += 1;
    state.adoption.bindingId = firstText(bindingId);
    state.adoption.state = firstText(initialState, 'enrollment_pending');
    state.adoption.pollIntervalMs = Math.max(500, firstNumber(pollIntervalMs) || 2000);
    state.adoption.error = '';
    state.adoption.polling = Boolean(state.adoption.bindingId);
    if (state.adoption.bindingId) pollAdoptionStatus(state.adoption.pollSeq);
  }

  async function copyBootstrapPart(kind) {
    const bundle = state.adoption.secret;
    if (!bundle || !['bundle', 'command'].includes(kind)) return;
    const value = kind === 'bundle' ? bootstrapBundleJson(bundle) : firstText(state.adoption.command, bootstrapCommand(bundle));
    try {
      if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') throw new Error('clipboard_unavailable');
      await navigator.clipboard.writeText(value);
      state.adoption.copyFeedback = kind === 'bundle' ? '完整 JSON bundle 已复制。' : '完整配对命令已复制。';
      state.adoption.copyTone = 'ok';
    } catch (_) {
      state.adoption.copyFeedback = '复制失败，请手动选择代码区域复制。';
      state.adoption.copyTone = 'error';
    }
    if (state.mounted) render();
  }

  function maybePromptDiscoveryCandidate() {
    if (isStatus || state.configView !== 'aps' || state.sheet || state.confirmToken || state.discoveryCandidate || state.adoption.bindingId) return;
    const discovery = state.ac.discovery || {};
    if (!Array.isArray(discovery.items)) return;
    const dismissed = state.discoveryDismissedCandidates || (state.discoveryDismissedCandidates = new Set());
    const candidate = discovery.items.find((item) => {
      const key = discoveryCandidateKey(item);
      return key && canConfirmDiscoveryCandidate(item) && !item.trusted && !item.adopted_elsewhere && !dismissed.has(key);
    });
    if (!candidate) return;
    state.discoveryCandidate = candidate;
  }

  /*
   * Kit 会把带 data-dwrt-component="sheet" 的抽屉搬到 document.body 下的传送门里
   * （dwrt-ui-kit.js:258 sheetPortal），所以抽屉内的节点用 root.querySelector 找不到。
   * Kit 只把事件回放到路由根，DOM 位置并不跟着回来，因此凡是要在抽屉里就地改按钮
   * 状态的地方都必须从 document 查。
   */
  function sheetQuery(selector) {
    return root?.querySelector(selector) || document.querySelector(`.dwrt-kit-sheet-portal ${selector}`) || document.querySelector(selector);
  }

  /*
   * 后台刷新只换清单这一块，不整页重建：整页 innerHTML 重写会把用户正在输入的搜索词
   * 连同焦点与光标位置一起抹掉（每 20 秒一次）。
   *
   * 页面上原来还有「发现到的 AP」与「配对码」两块要一起换；它们分别搬进了向导弹窗与
   * 配对码抽屉，两者都由 render() 从 state 重画，而轮询在弹窗/抽屉打开时本来就整段
   * 返回（见 pollTimer 的守卫），所以这里只剩清单。
   */
  function patchAcSections() {
    if (!root || !state.mounted) return;
    const active = document.activeElement;
    const searchFocused = Boolean(active && active.matches?.('[data-wifi-search]'));
    const caret = searchFocused ? active.selectionStart : null;
    /*
     * 选择器与函数名必须跟着清单改版走。清单从表格改成横条时，section 换成了
     * .wifi-ap-inventory-modern、apInventoryTable() 改名成 apInventoryStrips()，
     * 这里两处都没跟上：querySelector('.wifi-ap-inventory') 恒为 null，于是每 20 秒
     * 走一次 render() 整页重建 —— 正是上面注释要避免的那件事。
     */
    const inventory = root.querySelector('.wifi-ap-inventory-modern');
    if (!inventory) { render(); return; }
    inventory.outerHTML = apInventoryStrips();
    if (typeof ui.mountAll === 'function') ui.mountAll(root); else window.DWRT_UI_KIT?.mountAll?.(root);
    if (!searchFocused) return;
    const field = root.querySelector('[data-wifi-search]');
    if (!field) return;
    field.focus({ preventScroll: true });
    const end = caret === null ? field.value.length : caret;
    try { field.setSelectionRange(end, end); } catch (_) {}
  }

  function acReason(name) { return firstText(state.ac.reasons[name]); }

  function canEditAcAp() { return acCap('ap_inventory_edit'); }

  function canManageTokens() { return acCap('pairing_token_ipc') || acCap('pairing_token_security_base'); }

  function icon(name) {
    const icons = {
      plus: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg>',
      refresh: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11a8 8 0 1 0 2 5M20 4v7h-7"/></svg>',
      search: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>',
      wifi: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.6a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M12 20h.01M2 9a14 14 0 0 1 20 0"/></svg>',
      radio: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M15.165 12.598C14.135 14.152 12.66 15.5 10.5 15.5c-.825 0-1.673-.318-2.477-.782-.81-.467-1.614-1.105-2.363-1.8l.68-.734c.716.665 1.46 1.25 2.183 1.668.728.42 1.398.648 1.977.648 1.673 0 2.883-1.024 3.831-2.455l.834.553Z" fill="currentColor"/><path fill-rule="evenodd" clip-rule="evenodd" d="M10 2a8.002 8.002 0 0 0-7.908 6.782l-.003.003.002.003A8 8 0 1 0 10 2Zm6.885 9.269a7.045 7.045 0 0 0 .045-2.26c-.143.36-.3.744-.472 1.138l-.916-.4c.197-.452.374-.894.539-1.308l.067-.17c.123-.31.24-.607.352-.871A7.002 7.002 0 0 0 3.15 8.552c.348.481.784 1.042 1.28 1.624l-.762.648c-.236-.277-.46-.55-.668-.814 0 .357.028.707.08 1.05a4.013 4.013 0 0 0 1.002-.003c.803-.097 2.079-.447 4.194-1.504 3.947-1.973 7.018.435 8.61 1.716Zm-.28 1.056a22.738 22.738 0 0 1-.284-.225c-1.615-1.288-4.202-3.35-7.597-1.653-2.172 1.086-3.563 1.487-4.522 1.603a5.077 5.077 0 0 1-.886.034 7.003 7.003 0 0 0 13.289.241Z" fill="currentColor"/></svg>',
      connectivity: '<svg viewBox="0 0 20 20" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M14.14 12.856a.497.497 0 0 1 0-.697L16.278 10H3.719l2.136 2.159c.19.192.19.504 0 .697a.484.484 0 0 1-.69 0L2.3 9.959a.5.5 0 0 1-.3-.484.495.495 0 0 1 .142-.373l2.927-2.958c.19-.192.5-.192.69 0 .19.193.19.505 0 .698L3.622 9h12.752L14.24 6.842a.497.497 0 0 1 0-.698.485.485 0 0 1 .69 0l2.926 2.958c.19.193.19.505 0 .697l-3.024 3.057a.484.484 0 0 1-.69 0Z" fill="currentColor"/></svg>',
      environment: '<svg viewBox="0 0 20 20" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M13.348 3.025a.453.453 0 0 0-.307.004.376.376 0 0 0-.214.194l-2.58 5.808A1.002 1.002 0 0 0 9 10a1 1 0 1 0 1.984-.18L17.5 7.5c.193-.056.307-.231.265-.405-.22-.898-.641-1.446-1.471-2.232-.833-.79-1.88-1.465-2.946-1.838Z" fill="currentColor"/><path fill-rule="evenodd" clip-rule="evenodd" d="M10.54 5.447a.511.511 0 0 0-.498-.567h-.037A5.121 5.121 0 0 0 4.882 10a5.121 5.121 0 0 0 5.123 5.12 5.122 5.122 0 0 0 5.105-4.693.512.512 0 0 0-.519-.547c-.3 0-.529.242-.557.525a4.049 4.049 0 0 1-4.029 3.642 4.048 4.048 0 1 1 0-8.093.526.526 0 0 0 .531-.47l.004-.037Z" fill="currentColor"/><path fill-rule="evenodd" clip-rule="evenodd" d="M10.265 2.625c.29.01.55-.202.577-.498a.521.521 0 0 0-.494-.573 8.604 8.604 0 0 0-.343-.007C5.334 1.547 1.547 5.33 1.547 10s3.787 8.453 8.458 8.453a8.456 8.456 0 0 0 8.448-8.03.521.521 0 0 0-.527-.543.555.555 0 0 0-.548.53 7.383 7.383 0 0 1-7.373 6.97A7.382 7.382 0 0 1 2.621 10a7.382 7.382 0 0 1 7.644-7.375Z" fill="currentColor"/><path fill-rule="evenodd" clip-rule="evenodd" d="M10.005 11.787c.987 0 1.788-.8 1.788-1.787v-.03l5.886-1.96a.537.537 0 0 0 .356-.622c-.236-1.097-.925-2.223-1.799-3.168-.877-.95-1.983-1.766-3.113-2.218a.537.537 0 0 0-.7.304l-2.3 5.911a1.787 1.787 0 1 0-.118 3.57ZM10.553 10a.547.547 0 1 1-1.095 0 .547.547 0 0 1 1.095 0Zm6.3-2.847-5.4 1.8a1.797 1.797 0 0 0-.33-.347l2.095-5.382c.793.406 1.576 1.016 2.23 1.724.652.706 1.148 1.48 1.405 2.205Z" fill="currentColor"/></svg>',
      scan: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7V4h3M17 4h3v3M20 17v3h-3M7 20H4v-3M7 12h10"/></svg>',
      overview: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 13a8 8 0 0 1 16 0M7 13a5 5 0 0 1 10 0M10 13a2 2 0 0 1 4 0M5 18h14"/></svg>',
      insights: '<svg viewBox="0 0 20 20" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M11 3H9a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h2a1 1 0 0 0 1-1V4a1 1 0 0 0-1-1Zm0 1v10H9V4h2Zm3 2h2a1 1 0 0 1 1 1v7a1 1 0 0 1-1 1h-2a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1Zm2 8V7h-2v7h2ZM4 10h2a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1Zm2 4v-3H4v3h2Z" fill="currentColor"/><path d="M3.5 16h13a.5.5 0 0 1 0 1h-13a.5.5 0 0 1 0-1Z" fill="currentColor"/></svg>',
      settings: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2.86 2.86-.06-.06A1.7 1.7 0 0 0 15 19.4a1.7 1.7 0 0 0-1 .6 1.7 1.7 0 0 0-.4 1.1V21h-4v-.09A1.7 1.7 0 0 0 8.5 19.4a1.7 1.7 0 0 0-1.88.34l-.06.06-2.86-2.86.06-.06A1.7 1.7 0 0 0 4.1 15a1.7 1.7 0 0 0-1.51-1H2.5v-4h.09A1.7 1.7 0 0 0 4.1 9a1.7 1.7 0 0 0-.34-1.88l-.06-.06L6.56 4.2l.06.06A1.7 1.7 0 0 0 8.5 4.6a1.7 1.7 0 0 0 1-1.51V3h4v.09A1.7 1.7 0 0 0 15 4.6a1.7 1.7 0 0 0 1.88-.34l.06-.06 2.86 2.86-.06.06A1.7 1.7 0 0 0 19.4 9a1.7 1.7 0 0 0 1.51 1H21v4h-.09A1.7 1.7 0 0 0 19.4 15Z"/></svg>',
      close: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg>',
      chevron: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m9 18 6-6-6-6"/></svg>',
      info: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/></svg>',
      copy: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M15 9V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h3"/></svg>',
      sliders: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h10M18 7h2M4 17h2M10 17h10"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="17" r="2"/></svg>',
      key: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="8" cy="16" r="4"/><path d="m10.9 13.1 8.1-8.1M16.5 4.5 20 8M14 7l3 3"/></svg>',
      radar: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M12 12 19 5M4.9 4.9a10 10 0 1 0 14.2 14.2"/><path d="M7.8 7.8a6 6 0 1 0 8.4 8.4"/></svg>',
      bolt: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M13 2 4 14h6l-1 8 9-12h-6l1-8Z"/></svg>'
    };
    return icons[name] || icons.wifi;
  }

  /* 写能力按 scope 判定，判据取自当前页自己的端点。

     status 页（无线状态）与 config 页（Wi-Fi 管理）加载的是两个不同端点，
     `state.config` 在 status 页永远是 emptyConfig() 的空壳（save_config /
     apply_config 恒 false）。原来这里只读 state.config.capabilities，于是
     status 页上的每一处写判定恒为 false —— 这就是"设置全灰 + 一句未下发端点"
     的根因，而 31.250 的 status 端点里 write_scopes.managed_ap.supported 早就
     是 true。

     scope 语义：'local' 本机 phy 直写（走 PUT /wifi/config + apply），
     'managed' 受管 AP（走 POST /wifi/transactions）。不传则任一可写即可。 */
  function writeCapabilities() {
    const caps = isStatus ? state.status.capabilities : state.config.capabilities;
    return caps && typeof caps === 'object' ? caps : {};
  }

  function writeScope(scope) {
    const scopes = objectValue(writeCapabilities().write_scopes);
    return objectValue(scopes[scope === 'managed' ? 'managed_ap' : 'local']);
  }

  /* 本机直写：扁平位是历史契约（scope-agnostic），保持原判据不变，避免动到
     Wi-Fi 管理页那一整套已在用的本机写入判定。 */
  function localWriteSupported() {
    const caps = writeCapabilities();
    return bool(caps.wifi, false) && bool(caps.save_config, false) && bool(caps.apply_config, false);
  }

  /* 受管 AP 只有事务面这一条写入路径，判据就是它自己的 supported 位。
     端点由后端下发（capabilities.radio_update_endpoint 或
     write_scopes.managed_ap.transaction.endpoint），前端不写死。 */
  function managedWriteSupported() {
    const transaction = objectValue(writeScope('managed').transaction);
    if (bool(transaction.supported, false)) return Boolean(managedTransactionEndpoint());
    return false;
  }

  function managedTransactionEndpoint() {
    const transaction = objectValue(writeScope('managed').transaction);
    const caps = writeCapabilities();
    return firstText(transaction.endpoint, caps.radio_update_endpoint,
      state.status.links?.radio_update, state.status.endpoints?.radio_update);
  }

  function canConfigWrite(scope = 'local') {
    const registry = window.DWRT_DATA_REGISTRY;
    if (scope === 'local' && registry && (!registry.access('wifi.config', { capability: 'save_config', permission: 'wifi:write' }).allowed
      || !registry.hasCapability('wifi.config', 'apply_config'))) return false;
    return scope === 'managed' ? managedWriteSupported() : localWriteSupported();
  }

  /* 写入还有一道后端权限闸：无线写事务与扫描派发都是 JMX_RISK_MEDIUM，
     viewer 会被 webd 以 403 "role 'viewer' cannot perform 'medium' risk action"
     拒掉（jmx_app_perms.c）。这不是能力缺失，所以不混进 capabilities 判定，
     而是单独一条判据，并按 design.md 规则 21 在置灰处说明原因。 */
  function sessionRole() {
    let role = '';
    try {
      role = firstText(window.DWRT_SESSION?.tokens?.().role,
        localStorage.getItem('dreamingwrt.web.role'));
    } catch (_) { /* localStorage 不可用时按未知角色处理，不阻断 */ }
    return role.toLowerCase();
  }

  /* jmx_perm_check()：MEDIUM 只放 admin 与 owner，operator/user、viewer、
     ai-agent 一律拒。角色读不到时不预先封锁 —— 真正的判定在后端，前端只负责
     不误报，403 的中文文案在 writeErrorCopy() 里兜住。 */
  const MEDIUM_RISK_ROLES = new Set(['admin', 'owner']);

  function canPerformMediumRisk() {
    const role = sessionRole();
    return !role || MEDIUM_RISK_ROLES.has(role);
  }

  /* ── 受管 AP 写事务：候选摘要 ─────────────────────────────────────

     摘要算法与 AC 的 ac_config_candidate_digest()、APD 的
     apd_config_digest_hex_internal() 逐字节对齐：按 sections 顺序，每个 section
     先喂 "<section>\n"，operation 非 set 时再喂 "!<op>\n"，然后每个 option 喂
     "<key>=<value>\n"。SHA-256 十六进制，前缀 sha256:。摘要不对，AC 直接以
     candidate_digest_mismatch 拒收。

     crypto.subtle 只在安全上下文可用，而这套控制台常以明文 HTTP 访问
     （system-settings.js 的固件上传就是因为这个才不带 sha256），所以必须自带
     一份纯 JS 实现兜底，否则 HTTP 下每次保存都会在算摘要这步就失败。 */
  const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  function sha256HexLocal(bytes) {
    const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const length = bytes.length;
    const blocks = Math.ceil((length + 9) / 64);
    const padded = new Uint8Array(blocks * 64);
    padded.set(bytes);
    padded[length] = 0x80;
    const bits = length * 8;
    const view = new DataView(padded.buffer);
    view.setUint32(padded.length - 8, Math.floor(bits / 0x100000000));
    view.setUint32(padded.length - 4, bits >>> 0);
    const w = new Uint32Array(64);
    const rotr = (value, shift) => (value >>> shift) | (value << (32 - shift));
    for (let block = 0; block < blocks; block += 1) {
      const offset = block * 64;
      for (let i = 0; i < 16; i += 1) w[i] = view.getUint32(offset + i * 4);
      for (let i = 16; i < 64; i += 1) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i += 1) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        hh = g; g = f; f = e;
        e = (d + t1) >>> 0;
        d = c; c = b; b = a;
        a = (t1 + t2) >>> 0;
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
      h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
      h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }
    return Array.from(h).map((value) => value.toString(16).padStart(8, '0')).join('');
  }

  async function sha256Hex(text) {
    const bytes = new TextEncoder().encode(text);
    if (window.crypto?.subtle?.digest) {
      try {
        const buffer = await window.crypto.subtle.digest('SHA-256', bytes);
        return Array.from(new Uint8Array(buffer)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
      } catch (_) { /* 非安全上下文或算法不可用时落到本地实现 */ }
    }
    return sha256HexLocal(bytes);
  }

  async function candidateDigest(sections) {
    let text = '';
    sections.forEach((section) => {
      text += `${section.section}\n`;
      const operation = section.operation || 'set';
      if (operation !== 'set') text += `!${operation}\n`;
      Object.entries(section.options || {}).forEach(([key, value]) => { text += `${key}=${value}\n`; });
      Object.entries(section.list_options || {}).forEach(([key, values]) => {
        (values || []).forEach((value) => { text += `${key}=${value}\n`; });
      });
    });
    return `sha256:${await sha256Hex(text)}`;
  }

  function optionList(options, current) {
    return options.map(([value, label]) => `<option value="${escapeHtml(value)}" ${String(current) === String(value) ? 'selected' : ''}>${escapeHtml(label)}</option>`).join('');
  }

  function switchRow(path, title, detail, checked, disabled = false) {
    return `<label class="wifi-setting-row dwrt-kit-switch" data-dwrt-component="switch"><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(detail)}</small></span><input type="checkbox" role="switch" data-wifi-setting="${escapeHtml(path)}" aria-label="${escapeHtml(title)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}></label>`;
  }

  function setPath(target, path, value) {
    const keys = String(path).split('.');
    let cursor = target;
    keys.slice(0, -1).forEach((key) => { if (!cursor[key] || typeof cursor[key] !== 'object') cursor[key] = {}; cursor = cursor[key]; });
    cursor[keys[keys.length - 1]] = value;
  }

  function getPath(target, path, fallback = '') {
    let cursor = target;
    for (const key of String(path).split('.')) { if (!cursor || typeof cursor !== 'object' || !(key in cursor)) return fallback; cursor = cursor[key]; }
    return cursor;
  }

  function bandLabel(band) { return ({ '2g': '2.4 GHz', '5g': '5 GHz', '6g': '6 GHz' })[band] || band || '--'; }
  function securityLabel(value) { return SECURITY.find(([id]) => id === value)?.[1] || value || '--'; }
  /* 没有可靠频段来源时显示 --，让「后端没给」和「真的是某个频段」在界面上可区分。 */
  function bandPills(bands, links = null) {
    const list = (bands || []).filter(Boolean);
    if (!list.length) return '<span class="wifi-band-unknown">--</span>';
    return list.map((band) => {
      const label = escapeHtml(bandLabel(band));
      /*
       * 同名多频段合并成一行后，每个频段的胶囊要能单独进编辑抽屉 —— 一条 VAP 一份
       * 配置，合并只是显示层的事，不能把另外两个频段的入口一起并掉（要求 2：不删功能）。
       * 用 <button data-wifi-edit> 就够：onClick 的 closest('button, tr[data-wifi-edit], …)
       * 先命中按钮，:4280 的 data-wifi-edit 分支又排在选择行分支之前，无需改事件层。
       */
      const target = links instanceof Map ? links.get(band) : null;
      return target
        ? `<button class="wifi-band-pill is-${escapeHtml(band)} is-link" type="button" data-wifi-edit="${escapeHtml(target)}" title="编辑 ${label} 频段配置">${label}</button>`
        : `<span class="wifi-band-pill is-${escapeHtml(band)}">${label}</span>`;
    }).join('');
  }

  function deviceImage(device = {}, className = 'airview-device-image') {
    const shared = window.DWRT_DEVICE_IMAGES;
    const resolved = shared && typeof shared.resolve === 'function' ? shared.resolve(device) : null;
    const src = firstText(resolved?.src, device.image_url, device.web_image, device.image);
    return src
      ? `<span class="${className}"><img src="${escapeHtml(src)}" alt="" loading="lazy" decoding="async" onerror="this.hidden=true;this.nextElementSibling.hidden=false"><span hidden aria-hidden="true">${icon('radio')}</span></span>`
      : `<span class="${className} is-fallback" aria-hidden="true">${icon('radio')}</span>`;
  }

  /*
   * demo 的页头就是两颗胶囊（AP管理.html:305-308）：
   *   btn-glass 🔑 临时配对码      → openPairingDrawer()
   *   btn-blue  ＋ 添加新 AP (发现向导) → openAddApModal()
   * 配对码那颗保留原来的 data-wifi-token-create，所以既有 onClick 分支与
   * openTokenSheet() 一行不动；向导那颗是新的 Kit 弹窗。
   *
   * 向导按钮不随「后端没开放发现」消失 —— 两个按钮位都要在（要求 2 不删功能）。
   * 没有发现能力时弹窗里如实写明当前只能用配对码纳管，那是一段真话，不是一个
   * 点了不生效的控件。
   */
  /*
   * AP 横条的设备图。/api/v1/ac/aps 这条集合**一个图片字段都不带** —— 指纹图解析器
   * 只在 webd_wifi_aggregate_response() 里注入，所以真值在 /api/v1/wifi/config 的
   * managed_aps.items[]（image_url / image_available / image_source / image_model_match）。
   * 两条集合的主键都是 ap_id，而 load() 无论当前停在哪个 Tab 都会填好 state.config，
   * 所以这里是一次本地 join，不需要新请求；join 不中就退回 deviceImage() 自己的
   * is-fallback 分支（一个真的「没有图」，而不是画一个假机器）。
   */
  function apImageDevice(ap = {}) {
    const id = firstText(ap.ap_id, ap.id);
    const managed = Array.isArray(state.config?.managedAps) ? state.config.managedAps : [];
    const row = id ? managed.find((item) => firstText(item.ap_id, item.id) === id) : null;
    if (!row) return ap;
    /* ap 在后，因为清单侧的 label / model 已经过 acApLabel() 与型号覆盖处理。 */
    return { ...row, ...ap, image_url: firstText(row.image_url, ap.image_url) };
  }

  function apToolbar() {
    const tokensAllowed = canManageTokens();
    const tokenReason = tokensAllowed ? '' : firstText(acReason('pairing_token_ipc'), '后端未开放配对令牌能力');
    const tokenTitle = tokensAllowed ? '生成一次性配对码，交给待纳管的 AP' : tokenReason;
    return `<div class="wifi-page-toolbar wifi-ap-header-actions">
      <button class="wifi-btn-pill is-glass" type="button" data-wifi-token-create ${tokensAllowed && !state.acBusy ? '' : 'disabled'} title="${escapeHtml(tokenTitle)}">${icon('key')}<span>临时配对码</span></button>
      <button class="wifi-btn-pill is-blue" type="button" data-wifi-ap-wizard-open title="${escapeHtml(apWizardHint())}">${icon('plus')}<span>添加新 AP (发现向导)</span></button>
    </div>`;
  }

  /* 向导按钮与弹窗副标题共用同一句状态说明，避免两处各写一版。 */
  function apWizardHint() {
    const discovery = state.ac.discovery || {};
    if (!bool(discovery.available, false)) {
      return firstText(discovery.reason, acReason('ap_discovery'), '后端未提供设备发现能力');
    }
    if (!bool(discovery.endpointAvailable, false)) {
      return '发现服务已启用，但 Web 侧候选清单接口尚未开放';
    }
    return '自动扫描局域网广播接入的未绑定 AP 节点';
  }

  function localWifiFactsFor(scope = state.config) {
    const local = scope?.localWifi && typeof scope.localWifi === 'object' ? scope.localWifi : {};
    const caps = scope?.capabilities && typeof scope.capabilities === 'object' ? scope.capabilities : {};
    const dependencies = scope?.runtimeDependencies && typeof scope.runtimeDependencies === 'object' ? scope.runtimeDependencies : {};
    const radios = Array.isArray(scope?.radios) ? scope.radios : [];
    const phyCount = optionalNumber(local.phy_count, local.radio_count, dependencies.phy_count, dependencies.radio_count);
    const available = typeof local.available === 'boolean' ? local.available : null;
    const wirelessPresent = typeof local.wireless_present === 'boolean' ? local.wireless_present : null;
    const reason = firstText(local.reason, dependencies.reason, caps.reasons?.local_wifi, caps.reasons?.wifi);
    const explicitNoPhy = available === false || wirelessPresent === false || phyCount === 0 || reason === 'no_phy_detected' || reason === 'no_local_phy';
    const availableLocal = available === true || wirelessPresent === true || (phyCount !== null && phyCount > 0) || radios.length > 0;
    return { local, caps, dependencies, phyCount, available, wirelessPresent, reason, explicitNoPhy, availableLocal };
  }

  function hasLocalWifi() {
    return localWifiFactsFor().availableLocal;
  }

  function localWifiUnavailableCopy() {
    const facts = localWifiFactsFor();
    if (facts.explicitNoPhy) return '当前设备没有可用 PHY；受管 AP 与控制器状态不会改变这一事实。';
    if (facts.reason === 'partial_mac80211_runtime_sources' || facts.reason === 'partial_runtime_sources') {
      return '本机 PHY 已存在，但部分 mac80211 运行态数据源暂不可用；仍保留可用的本地无线入口。';
    }
    return '本机无线数据源当前不可用；控制器或受管 AP 数据不会被当成本地硬件。';
  }

  function controllerUnavailableCopy() {
    const facts = localWifiFactsFor();
    if (facts.explicitNoPhy) return '';
    const role = String(facts.local.role || '').toLowerCase();
    const apRole = ['ap', 'access_point', 'access-point', '无线接入点'].includes(role);
    const managed = state.config.managedWifi || {};
    const allManagedOffline = state.ac.loaded && state.ac.aps.length > 0 && state.ac.aps.every((ap) => !ap.online);
    const reason = firstText(
      allManagedOffline ? 'managed_ap_offline' : '',
      managed.reason, state.config.reasonScopes?.managed_wifi, state.config.reasonScopes?.managed_ap, state.ac.error
    );
    const unavailable = Boolean(state.ac.error)
      || managed.available === false
      || (managed.available === null && !state.ac.loaded)
      || ['source_unavailable', 'controller_unavailable', 'credentials_unavailable'].includes(reason);
    if (apRole && facts.availableLocal && unavailable) return '本机为 AP；本地无线设置与信道矩阵来自本机 PHY。AP 管理由控制器提供，当前未连接控制器。';
    if (reason === 'managed_ap_offline' || reason === 'managed_aps_offline_stale_or_without_snapshot') return '控制器已连接，但受管 AP 当前离线；本机无线能力仍按本地 PHY 事实显示。';
    if (unavailable && reason) return `AP 管理数据源当前不可用：${reason}。这不会改变本机无线硬件结论。`;
    return '';
  }

  function localWifiStateNotice() {
    const facts = localWifiFactsFor();
    const copy = controllerUnavailableCopy();
    const partial = ['partial_mac80211_runtime_sources', 'partial_runtime_sources'].includes(facts.reason);
    if (!copy && !partial) return '';
    const text = copy || '本机 PHY 已存在，但部分 mac80211 运行态数据源暂不可用；页面不会把它误报为无无线硬件。';
    return `<div class="wifi-notice is-warn" data-wifi-local-state-notice>${icon('info')}<span>${escapeHtml(text)}</span></div>`;
  }

  function configNavigation() {
    const tabs = [
      ['broadcasts', 'Wi-Fi 广播'],
      ['radios', 'Radio 与信道'],
      ['extensions', '扩展能力'],
      ['aps', 'AP 管理']
    ];
    const action = state.configView === 'aps' ? apToolbar() : '';
    return `<header class="wifi-config-navigation"><nav class="dwrt-kit-tabs dwrt-kit-page-tabs wifi-config-tabs" role="tablist" aria-label="Wi-Fi 配置视图"><span class="dwrt-kit-tab-pill" aria-hidden="true"></span>${tabs.map(([id, label]) => `<button class="dwrt-kit-tab ${state.configView === id ? 'is-active' : ''}" type="button" role="tab" data-wifi-config-tab="${id}" aria-selected="${state.configView === id ? 'true' : 'false'}">${label}</button>`).join('')}</nav>${action}</header>`;
  }

  function localSsidOperation(name) {
    const caps = state.config.capabilities || {};
    const scopes = caps.write_scopes && typeof caps.write_scopes === 'object' ? caps.write_scopes : {};
    const local = scopes.local && typeof scopes.local === 'object' ? scopes.local : {};
    const raw = local[name] ?? caps[name];
    const detail = raw && typeof raw === 'object' ? raw : {};
    const supported = typeof raw === 'object'
      ? bool(detail.supported ?? detail.available, false)
      : bool(raw, false);
    const operationReason = firstText(
      detail.reason,
      local.reasons?.[name],
      caps.reasons?.[name]
    );
    const scopeReason = firstText(local.reason);
    const scopeReady = ['available', 'supported', 'ready', 'ok'].includes(scopeReason.toLowerCase());
    const reason = firstText(operationReason, scopeReady ? '' : scopeReason, '后端未发布该操作能力');
    return { supported, reason, detail, local, caps };
  }

  function canSetSsidEnabled() {
    return canConfigWrite() && localSsidOperation('ssid_set_enabled').supported;
  }

  /* 删除必须是后端声明的本机原子批量命令。省略 ssids[] 项不会删除 SQLite 旧行，
     managed AC 的 wifi_ssid_delete 也不是这个页面可调用的本机 REST 合同。 */
  function ssidDeleteContract() {
    const operation = localSsidOperation('ssid_delete');
    const descriptor = operation.detail.request && typeof operation.detail.request === 'object'
      ? operation.detail.request
      : operation.local.ssid_delete_request && typeof operation.local.ssid_delete_request === 'object'
        ? operation.local.ssid_delete_request
        : operation.caps.ssid_delete_request && typeof operation.caps.ssid_delete_request === 'object'
          ? operation.caps.ssid_delete_request : {};
    const endpoint = firstText(descriptor.endpoint, descriptor.api);
    const method = firstText(descriptor.method).toUpperCase();
    const requestField = firstText(descriptor.request_field, descriptor.ids_field);
    const valid = operation.supported
      && endpoint.startsWith('/api/v1/wifi/') && !endpoint.startsWith('//')
      && ['POST', 'DELETE'].includes(method)
      && requestField === 'ssid_ids'
      && bool(descriptor.atomic_batch, false)
      && bool(descriptor.runtime_apply, false)
      && bool(descriptor.readback_verified, false);
    return { available: valid, endpoint, method, requestField, reason: valid ? '' : operation.reason };
  }

  function selectedSsidRows() {
    return state.config.ssids.filter((ssid) => state.selectedSsids.has(ssid.id));
  }

  function ssidManagementReason() {
    const reasons = [];
    const enabled = localSsidOperation('ssid_set_enabled');
    const deletion = ssidDeleteContract();
    if (!canSetSsidEnabled()) reasons.push(`暂停 / 恢复：${writeGateNote(enabled.reason)}`);
    if (state.dirty) reasons.push('移除：请先保存或放弃当前未应用更改');
    else if (!deletion.available) reasons.push(`移除：${writeGateNote(deletion.reason || '后端未提供本机原子删除接口')}`);
    return reasons.join('；');
  }

  /* `visible` 是合并后的行（分组），不是 SSID 条目 —— 这里只用它的条数决定「管理」
     是否可点。选中集仍然按成员 id 存，所以 selectedSsidRows() 返回的是 VAP。 */
  function ssidManagementFooter(visible) {
    if (!state.ssidManage) {
      return `<footer class="wifi-resource-footer"><div class="wifi-resource-actions"><button class="wifi-card-action" type="button" data-wifi-create ${canConfigWrite() ? '' : 'disabled'}>${icon('plus')}<span>新建</span></button><span class="wifi-resource-action-divider" aria-hidden="true"></span><button class="wifi-card-action" type="button" data-wifi-ssid-manage ${visible.length ? '' : 'disabled'}><span>管理</span></button></div></footer>`;
    }
    const selected = selectedSsidRows();
    const allPaused = selected.length > 0 && selected.every((ssid) => !ssid.enabled);
    const reason = selected.length ? ssidManagementReason() : '';
    return `<footer class="wifi-resource-footer is-managing"><div class="wifi-resource-actions">${selected.length ? `<button class="wifi-card-action" type="button" data-wifi-ssid-toggle="${allPaused ? 'enable' : 'disable'}" ${canSetSsidEnabled() && !state.ssidBusy ? '' : 'disabled'}><span>${allPaused ? '恢复' : '暂停'}</span></button><button class="wifi-card-action is-danger" type="button" data-wifi-ssid-remove ${ssidDeleteContract().available && !state.dirty && !state.ssidBusy ? '' : 'disabled'}><span>移除</span></button><span class="wifi-resource-action-divider" aria-hidden="true"></span>` : ''}<button class="wifi-card-action" type="button" data-wifi-ssid-manage-done><span>完成</span></button></div>${reason ? `<small class="wifi-resource-action-note">${escapeHtml(reason)}</small>` : ''}</footer>`;
  }

  const SSID_BAND_RANK = { '2g': 0, '5g': 1, '6g': 2 };
  function ssidBandRank(band) {
    const rank = SSID_BAND_RANK[band];
    return rank === undefined ? 9 : rank;
  }

  /*
   * 同名多频段合并成一条。分组键取「名称 + 网络 + 广播 AP」三者全同 —— 只按名称
   * 分组会把两个不同 LAN、或不同广播 AP 组下的同名广播并进一行，那三列的值就得
   * 编一个出来。三者相同时这行的每一格都还是真的。
   */
  function ssidGroupKey(ssid) {
    return [
      firstText(ssid?.name),
      firstText(ssid?.network, 'lan'),
      firstText(ssid?.broadcast, '全部 AP'),
    ].join(' ');
  }

  function ssidGroups(list = state.config.ssids) {
    const order = [];
    const byKey = new Map();
    (Array.isArray(list) ? list : []).forEach((ssid) => {
      const key = ssidGroupKey(ssid);
      if (!byKey.has(key)) { byKey.set(key, []); order.push(key); }
      byKey.get(key).push(ssid);
    });
    return order.map((key) => {
      const members = byKey.get(key).slice()
        .sort((a, b) => ssidBandRank((a.bands || [])[0]) - ssidBandRank((b.bands || [])[0]));
      const bands = [];
      /*
       * 频段 → 成员 id，取该频段第一个成员。合并行的行级 data-wifi-edit 只能指向
       * 一条 VAP（这里是频段最低的那条），胶囊按钮补齐其余频段的入口。
       */
      const bandLinks = new Map();
      members.forEach((member) => (member.bands || []).filter(Boolean).forEach((band) => {
        if (!bands.includes(band)) bands.push(band);
        if (!bandLinks.has(band)) bandLinks.set(band, member.id);
      }));
      bands.sort((a, b) => ssidBandRank(a) - ssidBandRank(b));
      const enabledCount = members.filter((member) => member.enabled).length;
      const reported = members.filter((member) => typeof member.clients === 'number');
      const securities = [];
      members.forEach((member) => { if (!securities.includes(member.security)) securities.push(member.security); });
      return {
        key,
        /* 行句柄是主成员 id，绝不序列化整组 id —— localWriteId() 会回落到名称，
           而名称里可以有空格（未命名 Wi-Fi），拼进 data-* 再切开就不可靠了。
           需要整组时一律用 ssidGroupFor(id) 在处理时重算。 */
        id: members[0].id,
        ids: members.map((member) => member.id),
        name: members[0].name,
        network: members[0].network,
        broadcast: members[0].broadcast,
        members,
        bands,
        bandLinks,
        enabled: enabledCount === members.length,
        partial: enabledCount > 0 && enabledCount < members.length,
        /* 一条成员都没上报就是 null（显示 --），不是 0。 */
        clients: reported.length ? reported.reduce((sum, member) => sum + member.clients, 0) : null,
        clientsPartial: reported.length > 0 && reported.length < members.length,
        securities,
      };
    });
  }

  function ssidGroupFor(id) {
    const target = state.config.ssids.find((ssid) => ssid.id === id);
    if (!target) return [];
    const key = ssidGroupKey(target);
    return state.config.ssids.filter((ssid) => ssidGroupKey(ssid) === key);
  }

  /* 搜索按这一行**显示出来的**文字匹配：合并后用户看到的是 "2.4 GHz"、
     "5 GHz"，短名 2g/5g 也一并收进来，避免改版把老的搜索词搜没了。 */
  function ssidGroupText(group) {
    return [
      group.name, group.network, group.broadcast,
      ...group.securities.map(securityLabel),
      ...group.bands, ...group.bands.map(bandLabel),
    ].join(' ').toLowerCase();
  }

  function filteredSsidGroups() {
    const query = state.query.trim().toLowerCase();
    const groups = ssidGroups();
    return query ? groups.filter((group) => ssidGroupText(group).includes(query)) : groups;
  }

  /* 各频段安全模式不一致时不挑一个显示：实测 Xiaomi_DE23 的 2.4/5G 是 sae+ccmp、
     6G 只报 ccmp，挑任一个都会把另外两条 VAP 描述错。列出全部并在 title 里给出
     逐频段明细。 */
  function ssidGroupSecurityCell(group) {
    const labels = group.securities.map(securityLabel);
    if (labels.length <= 1) return escapeHtml(labels[0] || '--');
    const detail = group.members
      .map((member) => `${bandLabel((member.bands || [])[0])}：${securityLabel(member.security)}`)
      .join('；');
    return `<span class="wifi-ssid-mixed" title="${escapeHtml(detail)}">${escapeHtml(labels.join(' / '))}<small>各频段不一致</small></span>`;
  }

  function ssidGroupClientsCell(group) {
    if (group.clients === null) {
      const why = group.members.length > 1 ? '各频段均未上报客户端数' : '后端未上报客户端数';
      return `<span class="wifi-ssid-unreported" title="${escapeHtml(why)}">--</span>`;
    }
    if (!group.clientsPartial) return String(group.clients);
    return `<span class="wifi-ssid-mixed" title="仅部分频段上报，合计只含已上报的频段">${group.clients}<small>部分频段</small></span>`;
  }

  function configTable() {
    const query = state.query.trim().toLowerCase();
    const groups = filteredSsidGroups();
    const emptyCopy = query
      ? '调整搜索条件后重试。'
      : hasLocalWifi() ? '使用“新建 Wi-Fi”创建第一个广播。' : localWifiUnavailableCopy();
    const allSelected = groups.length > 0 && groups.every((group) => group.ids.every((id) => state.selectedSsids.has(id)));
    const selectionHead = state.ssidManage ? `<th class="wifi-ssid-select-column"><input type="checkbox" data-wifi-ssid-select-all aria-label="选择全部 Wi-Fi" ${allSelected ? 'checked' : ''}></th>` : '';
    return `<section class="wifi-config-surface wifi-resource-card wifi-config-table dwrt-kit-table-wrap dwrt-kit-glass-surface" data-wifi-ssid-card><div class="wifi-table-scroll"><table class="dwrt-kit-table"><thead><tr>${selectionHead}<th>名称</th><th>网络</th><th>广播 AP</th><th>无线电频段</th><th>客户端</th><th>安全</th></tr></thead><tbody data-wifi-table-body>${groups.map((group) => {
      const selected = group.ids.some((id) => state.selectedSsids.has(id));
      const rowAttrs = state.ssidManage
        ? `data-wifi-ssid-select-row="${escapeHtml(group.id)}" class="${selected ? 'is-selected' : ''}"`
        : `data-wifi-edit="${escapeHtml(group.id)}"`;
      const selection = state.ssidManage ? `<td class="wifi-ssid-select-column"><input type="checkbox" data-wifi-ssid-select="${escapeHtml(group.id)}" aria-label="选择 ${escapeHtml(group.name)}（${group.members.length} 个频段）" ${selected ? 'checked' : ''}></td>` : '';
      /* 管理模式下胶囊不做按钮：那一行的点击语义是"选中/取消"，再塞一个跳转按钮
         会和整行选择打架（:4282 对 button 直接 return，点了会什么都不发生）。 */
      const links = state.ssidManage || group.members.length < 2 ? null : group.bandLinks;
      const dot = group.enabled ? 'is-on' : group.partial ? 'is-partial' : '';
      const dotTitle = group.partial ? ` title="${escapeHtml(`${group.members.length} 个频段中 ${group.members.filter((member) => member.enabled).length} 个在广播`)}"` : '';
      return `<tr ${rowAttrs} tabindex="0">${selection}<td><span class="wifi-name-cell"><i class="${dot}"${dotTitle}></i><strong>${escapeHtml(group.name)}</strong></span></td><td>${escapeHtml(group.network || '--')}</td><td>${escapeHtml(group.broadcast || '全部 AP')}</td><td><div class="wifi-band-list">${bandPills(group.bands, links)}</div></td><td>${ssidGroupClientsCell(group)}</td><td>${ssidGroupSecurityCell(group)}</td></tr>`;
    }).join('')}</tbody></table></div>${groups.length ? '' : `<div class="wifi-table-empty" data-dwrt-component="state-panel" data-dwrt-state="empty"><span>${icon('wifi')}</span><strong>${query ? '没有匹配的 Wi-Fi' : '尚未创建 Wi-Fi'}</strong><small>${emptyCopy}</small></div>`}${ssidManagementFooter(groups)}</section>`;
  }

  function radioSummary() {
    const radios = state.config.radios;
    if (!radios.length) {
      const facts = localWifiFactsFor();
      const title = facts.explicitNoPhy ? '未检测到 Radio' : facts.availableLocal ? '本机 PHY 已检测到' : '本机 Radio 数据暂不可用';
      const detail = facts.explicitNoPhy
        ? '当前设备没有可用 PHY，因此不构造信道矩阵；受管 AP 与控制器状态不会改变这一事实。'
        : facts.availableLocal
          ? '本机无线硬件已存在，但后端尚未返回可配置 Radio 明细；不会把数据源缺失误报为无无线硬件。'
          : '当前没有可验证的本机 Radio 事实；控制器数据源不可用时不会推断本机硬件状态。';
      return `<div class="wifi-radio-empty" data-dwrt-component="state-panel" data-dwrt-state="${facts.explicitNoPhy ? 'unavailable' : 'degraded'}"><strong>${title}</strong><p>${detail}</p></div>`;
    }
    return `<section class="wifi-panel-section wifi-radio-summary" data-wifi-radio-summary><header class="wifi-section-head"><div><strong>Radio 摘要</strong><small>${radios.length} 个无线电，先确认硬件、信道与发射功率，再调整全局策略。</small></div></header><div class="wifi-table-scroll"><table class="dwrt-kit-table"><thead><tr><th>Radio</th><th>频段</th><th>信道</th><th>宽度</th><th>发射功率</th><th>状态</th></tr></thead><tbody>${radios.map((radio) => `<tr><td><strong>${escapeHtml(radio.name)}</strong></td><td>${escapeHtml(bandLabel(radio.band))}</td><td>${escapeHtml(radioChannelText(radio))}</td><td>${escapeHtml(radioWidthText(radio))}</td><td>${radioPowerCell(radio)}</td><td><span class="dwrt-kit-status-badge is-${radio.online ? 'success' : 'error'}" data-dwrt-status="${radio.online ? 'success' : 'error'}"><i class="dwrt-kit-status-badge-dot" aria-hidden="true"></i><span>${radio.online ? '在线' : '离线'}</span></span></td></tr>`).join('')}</tbody></table></div></section>`;
  }

  /* 信道/频宽的统一呈现。normalizeRadio() 已经把"期望"和"运行"分成了两组键，
     这里只决定怎么写给人看：
       - ACS 且驱动已选定信道  -> "165 · 自动"
       - ACS 但还读不到运行值  -> "自动"
       - 固定信道              -> "36"
       - 两者皆无              -> "--"
     六处渲染点原先各自内联 `radio.channel || '--'`，于是 channel=0 的 6 GHz
     一律显示 "--"，把"自动选台"误报成"没有数据"。 */
  function radioChannelText(radio) {
    const display = optionalNumber(radio?.channel_display);
    if (radio?.channel_auto) return display === null ? '自动' : `${display} · 自动`;
    return display === null ? '--' : String(display);
  }

  function radioWidthText(radio, suffix = ' MHz') {
    const display = optionalNumber(radio?.width_display, radio?.width);
    return display === null ? '--' : `${display}${suffix}`;
  }

  function radioTxPowerContract(radio) {
    const globalContract = objectValue(state.config.capabilities?.radio_tx_power);
    return { ...globalContract, ...objectValue(radio?.radio_tx_power) };
  }

  function radioTxPowerCapability(radio) {
    const contract = radioTxPowerContract(radio);
    const limits = radio?.tx_power_limits_dbm || {};
    const hasCurrent = radio?.tx_power_dbm !== null && radio?.tx_power_dbm !== undefined;
    const hasLimits = Number.isFinite(Number(limits.min)) && Number.isFinite(Number(limits.max));
    const write = bool(contract.write, false);
    const apply = bool(contract.apply, false);
    const readback = bool(contract.readback, false);
    const available = canConfigWrite() && hasCurrent && hasLimits && write && apply && readback;
    const reason = firstText(contract.reason, state.config.capabilities?.reasons?.radio_tx_power, state.config.capabilities?.reasons?.radio_update, '发射功率调整能力待同步');
    /* 后端逐条声明设置在哪一层存活：persists_across_apply 为真表示每次应用都会
       重新下发（回读阶段的 iw dev set），persists_across_reboot 为假表示 UCI 承载
       不了这一档——MT7996 三个频段共用一个 wiphy，而 netifd 把 UCI option txpower
       当作 iw phy set txpower 下发，会把三个频段一起拖到同一个值，所以后端只在
       不会串味时才写 option txpower。默认值取 write：契约没给这两个键的旧后端，
       行为就是"能写就一直有效"。 */
    const persistsAcrossApply = bool(contract.persists_across_apply, write);
    const persistsAcrossReboot = bool(contract.persists_across_reboot, write);
    return {
      available, contract, limits, hasCurrent, hasLimits, write, apply, readback, reason,
      persistsAcrossApply, persistsAcrossReboot,
      persistenceReason: firstText(contract.persistence_reason, '')
    };
  }

  /* 自动档的提示文案。0 dBm 不是一个功率，而是"交给监管上限"，所以输入框留空表示
     自动，当前生效值移到输入框下方的注脚里报出——自动档下读回值就等于运行信道的
     天花板（实测 W1700K：5 GHz 频段上限 28 dBm，信道 36 只能到 23，自动档读回
     正是 23）。占位符只写"自动"：输入框宽 68px，长占位符会被裁掉。 */
  function radioTxPowerNote(radio, capability) {
    const current = Number(radio?.tx_power_dbm);
    const parts = [];
    if (Number.isFinite(current) && current > 0) parts.push(`当前 ${current} dBm`);
    if (!capability.persistsAcrossReboot) parts.push('重启后回到自动');
    return parts.join(' · ');
  }

  function radioPowerCell(radio) {
    const capability = radioTxPowerCapability(radio);
    const current = radio?.tx_power_dbm;
    if (capability.available) {
      const min = Number(capability.limits.min);
      const max = Number(capability.limits.max);
      const step = Number(capability.limits.step) || 1;
      /* 输入框编辑的是*期望值*，不是读回值：填 20 就是钉在 20 dBm，清空就是回到
         自动。此前这里回填 tx_power_dbm（读回值），于是自动档看起来像"已固定在
         23 dBm"，而 min=1 又让操作者没有任何手势能回到自动。 */
      const desired = Number(radio?.tx_power_desired);
      const value = Number.isFinite(desired) && desired > 0 ? String(desired) : '';
      const note = radioTxPowerNote(radio, capability);
      const tip = capability.persistsAcrossReboot ? `留空为自动，上限 ${max} dBm 取自 iw phy 报告的运行信道监管天花板。`
        : firstText(capability.persistenceReason, '') === 'uci_txpower_is_wiphy_wide_reapplied_on_apply'
          ? `留空为自动，上限 ${max} dBm 取自运行信道的监管天花板。本机三个频段共用一个射频，逐频段功率由每次应用重新下发，重启后回到自动。`
          : `留空为自动，上限 ${max} dBm 取自运行信道的监管天花板。该功率由每次应用重新下发，重启后回到自动。`;
      return `<span class="wifi-radio-power-edit"><label class="wifi-radio-power-input"><span class="sr-only">${escapeHtml(`${bandLabel(radio.band)} 发射功率`)}</span><input type="number" data-wifi-tx-power="${escapeHtml(radio.id)}" value="${escapeHtml(value)}" placeholder="自动" min="${min}" max="${max}" step="${step}" aria-label="${escapeHtml(`${bandLabel(radio.band)} 发射功率（dBm，留空为自动）`)}"><b>dBm</b></label>${note ? `<small class="wifi-radio-power-note" data-dwrt-tooltip="${escapeHtml(tip)}">${escapeHtml(note)}</small>` : ''}</span>`;
    }
    if (capability.hasCurrent) return `<span class="wifi-radio-power-readback"><strong>${escapeHtml(current)} dBm</strong><small data-dwrt-tooltip="${escapeHtml(capability.reason)}">调整能力待同步</small></span>`;
    return `<span class="wifi-radio-power-readback is-missing"><strong>--</strong><small data-dwrt-tooltip="${escapeHtml(capability.reason)}">功率未回读</small></span>`;
  }

  /* input 与 change 两条事件共用的写回路径。"留空 = 自动"只实现在其中一处的话，
     操作者清空输入框后不失焦就永远回不到自动，反之失焦前又看不到反馈。 */
  function commitRadioTxPowerInput(target) {
    const radio = state.config.radios.find((entry) => entry.id === target.dataset.wifiTxPower);
    const capability = radioTxPowerCapability(radio);
    if (!radio || !capability.available) return;
    const raw = String(target.value ?? '').trim();
    const min = Number(capability.limits.min);
    const max = Number(capability.limits.max);
    let next = 0;

    if (raw) {
      next = Number(raw);
      if (!Number.isFinite(next)) return;
      next = Math.round(next);
      /* 越界钳到边界并回写输入框，而不是静默丢弃这次输入。上限就是运行信道的监管
         天花板，驱动本身会把超限请求悄悄钳到它（rc=0），先在这里钳一次，"保存后
         读回值和我输入的不一样"就不会发生。 */
      if (next < min || next > max) {
        next = Math.min(Math.max(next, min), max);
        target.value = String(next);
      }
    }
    /* 写 txpower —— 后端 wifi_radios.txpower 的原名，也是 wifi_config_save 唯一
       认的键；tx_power_dbm / tx_power 是 normalizeRadio() 由读回值派生的展示键，
       一起更新只是为了本次渲染不显示旧值。 */
    radio.txpower = next;
    radio.tx_power_desired = next > 0 ? next : null;
    radio.tx_power_auto = next <= 0;
    if (next > 0) {
      radio.tx_power_dbm = next;
      radio.tx_power = next;
    }
    markDirty();
  }

  function radioForBand(band) { return state.config.radios.find((radio) => radio.band === band); }
  function channelCatalogEntry(radio, channel) {
    const catalog = radio?.channel_catalog;
    if (!catalog || !bool(catalog.complete, false)) return null;
    return asArray(catalog.channels).find((entry) => Number(entry?.channel) === Number(channel)) || null;
  }

  function channelCatalogFrequencyMHz(radio, channel) {
    return optionalNumber(channelCatalogEntry(radio, channel)?.frequency_mhz, channelCatalogEntry(radio, channel)?.frequency);
  }

  function channelAvailability(band, channel, radio = radioForBand(band)) {
    if (!radio) return 'unavailable';
    if (radio.excluded_channels.includes(Number(channel))) return 'excluded';
    if (radio.unavailable_channels.includes(Number(channel))) return 'unavailable';
    if (radio.dfs_channels.includes(Number(channel))) return 'dfs';
    const entry = channelCatalogEntry(radio, channel);
    if (entry) {
      if (bool(entry.disabled, false) || bool(entry.no_ir, false)) return 'unavailable';
      if (bool(entry.radar_detection, false) || Boolean(entry.dfs_state)) return 'dfs';
      return 'enabled';
    }
    if (radio.channel_catalog && bool(radio.channel_catalog.complete, false)) return 'unavailable';
    return 'unknown';
  }

  function channelFrequencyMHz(band, channel, radio = null) {
    const catalogFrequency = channelCatalogFrequencyMHz(radio, channel);
    if (catalogFrequency !== null) return catalogFrequency;
    const value = Number(channel);
    if (band === '2g') return value === 14 ? 2484 : 2407 + (value * 5);
    if (band === '5g') return 5000 + (value * 5);
    if (band === '6g') return 5950 + (value * 5);
    return 0;
  }

  function channelsAreContiguous(band, channels, radio = null) {
    return channels.length > 0 && channels.slice(1).every((channel, index) => {
      const previous = channels[index];
      const currentFrequency = channelFrequencyMHz(band, channel, radio);
      const previousFrequency = channelFrequencyMHz(band, previous, radio);
      if (!currentFrequency || !previousFrequency) return false;
      return band === '2g'
        ? Number(channel) - Number(previous) === 1
        : currentFrequency - previousFrequency === 20;
    });
  }

  function channelPlanWidths(def, radio) {
    const catalog = radio?.channel_catalog;
    const values = asArray(radio?.supported_widths).length ? radio.supported_widths
      : asArray(catalog?.supported_widths_mhz).length ? catalog.supported_widths_mhz
        : catalog && bool(catalog.complete, false) ? [] : def.widths;
    return Array.from(new Set(values.map(Number).filter((width) => Number.isFinite(width) && width > 0))).sort((left, right) => left - right);
  }

  function channelPlanChannels(def, radio) {
    const catalog = radio?.channel_catalog;
    if (!catalog || !bool(catalog.complete, false)) return def.channels;
    const entries = asArray(catalog.channels).map((entry) => ({
      channel: Number(entry?.channel),
      frequency: optionalNumber(entry?.frequency_mhz, entry?.frequency)
    })).filter((entry) => Number.isFinite(entry.channel) && entry.channel > 0);
    if (!entries.length) return [];
    const range = String(def.range || '').match(/(\d+)\s*-\s*(\d+)/);
    const start = range ? Number(range[1]) : 0;
    const end = range ? Number(range[2]) : 0;
    const inSegment = entries.filter((entry) => !entry.frequency || !start || (entry.frequency >= start && entry.frequency <= end));
    // A complete catalog is already ordered by the driver/regdb. Preserve that
    // order: 6 GHz has channel-number sequences that are not safe to reconstruct
    // from a generic formula, and UniFi's plan follows the actual frequency map.
    return Array.from(new Set(inSegment.map((entry) => entry.channel)));
  }

  function channelBlockState(radio, band, channels, width) {
    const statuses = channels.map((channel) => channelAvailability(band, channel, radio));
    if (radio && radio.channel && radio.width === width && channels.includes(Number(radio.channel))) return 'using';
    if (statuses.includes('unavailable')) return 'unavailable';
    if (statuses.includes('excluded')) return 'excluded';
    if (statuses.includes('dfs')) return 'dfs';
    if (statuses.every((status) => status === 'enabled')) return 'enabled';
    return 'unknown';
  }

  function channelBlockRow(def, radio, width) {
    const band = def.band || def.id;
    const span = Math.max(1, Math.round(Number(width) / 20));
    const cells = [];
    for (let index = 0; index < def.channels.length;) {
      const channels = def.channels.slice(index, index + span);
      if (channels.length === span && channelsAreContiguous(band, channels, radio)) {
        const status = channelBlockState(radio, band, channels, width);
        const disabled = !canConfigWrite() || !radio || ['unavailable', 'unknown'].includes(status);
        const title = `${def.label} · 信道 ${channels[0]}-${channels[channels.length - 1]} · ${width} MHz · ${status === 'using' ? '使用中' : status === 'enabled' ? '已启用' : status === 'dfs' ? 'DFS' : status === 'excluded' ? '已排除' : status === 'unavailable' ? '不可用' : '状态待同步'}`;
        cells.push(`<button type="button" class="wifi-channel-cell is-${status}" style="grid-column: span ${span}" data-wifi-channel="${channels[0]}" data-wifi-channel-values="${channels.join(',')}" data-wifi-channel-band="${band}" data-wifi-channel-width="${width}" ${disabled ? 'disabled' : ''} data-dwrt-tooltip="${escapeHtml(title)}" aria-label="${escapeHtml(title)}"></button>`);
        index += span;
      } else {
        cells.push('<span class="wifi-channel-slot is-gap" aria-hidden="true"></span>');
        index += 1;
      }
    }
    return `<div class="wifi-channel-row"><span class="wifi-channel-axis">${width} MHz</span>${cells.join('')}</div>`;
  }

  const SPEED_BAND_ORDER = ['2g', '5g', '6g'];
  const CONSERVATIVE_WIDTHS = { '2g': 20, '5g': 40, '6g': 160 };

  function speedProfileBands() {
    const present = new Set(state.config.radios.map((radio) => normalizeBand(radio.band)).filter(Boolean));
    return SPEED_BAND_ORDER.filter((band) => present.has(band));
  }

  function supportedWidthsForBand(band) {
    return Array.from(new Set(state.config.radios
      .filter((radio) => radio.band === band)
      .flatMap((radio) => asArray(radio.supported_widths))
      .map(Number)
      .filter((width) => Number.isFinite(width) && width > 0))).sort((left, right) => left - right);
  }

  function widthOptionsForBand(band) {
    return supportedWidthsForBand(band);
  }

  function currentWidthForBand(band) {
    return firstNumber(
      state.config.global.widths?.[band],
      ...state.config.radios.filter((radio) => radio.band === band).map((radio) => radio.width)
    );
  }

  function speedProfileCapability() {
    const caps = state.config.capabilities || {};
    const contract = objectValue(caps.radio_width_profile);
    const radios = state.config.radios.filter((radio) => SPEED_BAND_ORDER.includes(radio.band));
    const missing = radios.filter((radio) => !asArray(radio.supported_widths).length);
    const supportedProfiles = asArray(contract.supported_profiles).map((profile) => String(profile));
    const profilesReady = ['maximum', 'conservative', 'custom'].every((profile) => supportedProfiles.includes(profile));
    const write = bool(contract.write ?? caps.global_update, false);
    const apply = bool(contract.apply, false);
    const readback = bool(contract.readback, false);
    const widthsReady = radios.length > 0 && missing.length === 0;
    const available = canConfigWrite() && write && apply && readback && profilesReady && widthsReady;
    let reason = '';
    if (!widthsReady) reason = `后端尚未为 ${Array.from(new Set(missing.map((radio) => bandLabel(radio.band)))).join('、') || '当前 Radio'} 上报可选宽度`;
    else if (!write) reason = writeGateNote(firstText(contract.reason, caps.reasons?.global_update, 'radio_width_profile_write_pending'));
    else if (!apply) reason = '后端尚未开放 Radio 速度档位应用事务';
    else if (!readback) reason = '后端尚未开放 Radio 速度档位运行态回读';
    else if (!profilesReady) reason = '后端尚未发布完整的速度档位列表';
    else if (!canConfigWrite()) reason = configWriteGateNote() || '后端未开放 Wi-Fi 配置写入';
    return { available, widthsReady, missing, contract, reason };
  }

  function supportedProfileWidth(band, requested) {
    if (band === '2g') return 20;
    const supported = supportedWidthsForBand(band);
    if (!supported.length) return 0;
    if (supported.includes(requested)) return requested;
    const lower = supported.filter((width) => width <= requested);
    return lower.length ? lower[lower.length - 1] : supported[0];
  }

  function speedProfileWidths(profile) {
    const widths = {};
    speedProfileBands().forEach((band) => {
      const supported = supportedWidthsForBand(band);
      if (profile === 'maximum') {
        widths[band] = band === '2g' ? 20 : supported[supported.length - 1] || 0;
      } else if (profile === 'conservative') {
        widths[band] = supportedProfileWidth(band, CONSERVATIVE_WIDTHS[band]);
      }
    });
    return widths;
  }

  function applySpeedProfile(profile) {
    if (!['maximum', 'conservative', 'custom'].includes(profile)) return;
    state.config.global.speed_profile = profile;
    if (profile === 'custom') return;
    const widths = speedProfileWidths(profile);
    speedProfileBands().forEach((band) => {
      if (widths[band]) state.config.global.widths[band] = widths[band];
    });
    if (profile === 'conservative') state.config.global.dfs_enabled = false;
  }

  function channelPlanBand(def) {
    const band = def.band || def.id;
    const radio = radioForBand(band);
    const channels = channelPlanChannels(def, radio);
    const widths = channelPlanWidths(def, radio);
    const catalogMissing = !radio || !radio.channel_catalog || !bool(radio.channel_catalog.complete, false);
    if (!channels.length) return '';
    const definition = { ...def, channels };
    return `<div class="wifi-channel-band" data-wifi-channel-band-section="${band}"><header><strong>${def.label}</strong><span>${def.range}</span>${catalogMissing ? '<small class="wifi-channel-band-note">许可状态待同步</small>' : ''}</header><div class="wifi-channel-grid" style="--channel-count:${channels.length}"><div class="wifi-channel-row is-header"><span class="wifi-channel-axis">信道</span>${channels.map((channel) => `<span class="wifi-channel-number">${channel}</span>`).join('')}</div>${widths.map((width) => channelBlockRow(definition, radio, width)).join('')}</div></div>`;
  }

  function channelPlan() {
    const presentBands = new Set(state.config.radios.map((radio) => radio.band));
    const bands = BANDS.filter((def) => presentBands.has(def.band || def.id));
    return `<section class="wifi-panel-section" data-wifi-channel-plan><header class="wifi-section-head"><div><strong>信道计划</strong><small>${escapeHtml(canConfigWrite() ? '点击信道块以将其从使用中排除；不同频宽按真实占用范围跨列显示。' : `只读：${configWriteGateNote() || '后端未开放信道写入'}`)}</small></div></header><div class="wifi-channel-scroll">${bands.map(channelPlanBand).join('')}</div><div class="wifi-channel-legend"><span class="using">使用中</span><span class="enabled">已启用</span><span class="dfs">DFS</span><span class="unavailable">不可用</span><span class="excluded">已排除</span><span class="unknown">许可状态待同步</span></div><button class="wifi-link-button" type="button" data-wifi-reset-channels ${canConfigWrite() ? '' : 'disabled'}>恢复默认值</button></section>`;
  }

  function defaultSpeed() {
    const profile = state.config.global.speed_profile || 'conservative';
    const widths = state.config.global.widths || {};
    const capability = speedProfileCapability();
    const bands = speedProfileBands().map((band) => [band, bandLabel(band), widthOptionsForBand(band), currentWidthForBand(band)]);
    const profileOptions = [
      ['maximum', '最高速度', '2.4 GHz 固定使用 20 MHz，其他已检测频段使用后端上报的最大宽度。'],
      ['conservative', '保守', '密集环境优先使用较窄信道：2.4 GHz 20 MHz、5 GHz 40 MHz、6 GHz 160 MHz，并关闭 DFS。'],
      ['custom', '自定义', '逐频段选择后端确认支持的信道宽度。']
    ];
    const widthNotice = capability.widthsReady ? '' : `<div class="wifi-notice is-warn" data-wifi-width-capability-notice>${icon('info')}<span>${escapeHtml(`${capability.reason}；当前数字是配置回读值，不代表硬件只支持这一档。`)}</span></div>`;
    return `<section class="wifi-panel-section wifi-unifi-global" data-wifi-speed-policy><header class="wifi-section-head"><div><strong>默认 Wi-Fi 速度</strong><small>${escapeHtml(capability.available ? '按本机实际 Radio 能力设置默认信道宽度。' : `只读：${capability.reason || configWriteGateNote() || '后端未开放全局写入'}`)}</small></div></header><div class="wifi-speed-controls"><div class="wifi-speed-profile-row"><div class="wifi-speed-profile-options">${profileOptions.map(([value, label, detail]) => `<span class="wifi-speed-profile-choice"><label><input type="radio" name="wifi-speed-profile" value="${value}" data-wifi-setting="global.speed_profile" ${profile === value ? 'checked' : ''} ${capability.available ? '' : 'disabled'}><span>${label}</span></label>${value === 'custom' ? '' : `<button class="wifi-speed-profile-info" type="button" aria-label="${escapeHtml(`${label}说明`)}" data-dwrt-tooltip="${escapeHtml(detail)}">${icon('info')}</button>`}</span>`).join('')}</div><button class="wifi-link-button is-inline" type="button" data-wifi-apply-all ${capability.available ? '' : 'disabled'}>应用于所有 AP</button></div>${widthNotice}<div class="wifi-width-picker"><strong>信道宽度 (MHz)</strong><div style="--wifi-speed-band-count:${Math.max(1, bands.length)}">${bands.map(([band, label, options, current]) => `<fieldset data-wifi-width-group="${band}"><legend>${label}</legend>${options.length ? `<span>${options.map((width) => `<button type="button" class="${Number(widths[band]) === width ? 'is-active' : ''}" data-wifi-width-band="${band}" data-wifi-width="${width}" ${capability.available ? '' : 'disabled'}>${width}</button>`).join('')}</span>` : `<span class="wifi-width-current-only" data-wifi-width-current="${band}"><output>${current || '--'}</output><small>当前值 · 候选待同步</small></span>`}</fieldset>`).join('')}</div></div>${speedProfileBands().includes('5g') ? switchRow('global.dfs_enabled', '扩展 5 GHz 频谱 (DFS)', '允许自动信道使用 DFS 频段；选择“保守”会关闭此项。', state.config.global.dfs_enabled, !capability.available) : ''}</div></section>`;
  }

  function globalSettings() {
    const global = state.config.global;
    const disabled = !canConfigWrite();
    return `<section class="wifi-panel-section"><header class="wifi-section-head"><div><strong>控制器能力</strong><small>按依赖关系管理 Mesh、设备发现与信道优化入口。</small></div></header><div class="wifi-settings-list">${switchRow('global.mesh', '无线 Mesh', '允许 AP 通过无线回程互联并扩展覆盖。', global.mesh, disabled)}<div class="wifi-dependency-panel ${global.mesh ? 'is-active' : ''}" data-dwrt-component="dependency-group"><div class="wifi-inline-setting" data-dwrt-dependency-panel><span><strong>Mesh 监视器</strong><small>仅在 Mesh 启用后用于检测无线回程上行连通性。</small></span><div class="wifi-radio-options compact">${[['gateway', 'Gateway'], ['custom', '自定义 IP']].map(([value, label]) => `<label><input type="radio" name="mesh-monitor" value="${value}" data-wifi-setting="global.mesh_monitor" ${global.mesh_monitor === value ? 'checked' : ''} ${disabled || !global.mesh ? 'disabled' : ''}><span>${label}</span></label>`).join('')}</div></div>${global.mesh && global.mesh_monitor === 'custom' ? `<div class="wifi-inline-setting" data-dwrt-dependency-panel><span><strong>监视器 IP</strong><small>AP 用于连通性探测的地址。</small></span><input type="text" data-wifi-setting="global.mesh_monitor_ip" value="${escapeHtml(global.mesh_monitor_ip || '')}" ${disabled ? 'disabled' : ''}></div>` : ''}</div>${switchRow('global.auto_link', 'UniFi 自动链接', '自动关联兼容的无线摄像机和 IoT 设备。', global.auto_link, disabled)}${switchRow('global.wifiman', 'WiFiman 支持', '允许移动端进行本地发现和信号测绘。', global.wifiman, disabled)}<div class="wifi-inline-setting"><span><strong>信道 AI</strong><small>根据相邻 AP 和干扰优化信道分配。</small></span><a href="#/monitor/wireless-status">前往无线状态</a></div></div></section>`;
  }

  function speedLimits() {
    const rows = state.config.speed_limits;
    return `<section class="wifi-config-surface wifi-resource-card wifi-speed-limits dwrt-kit-table-wrap dwrt-kit-glass-surface" data-wifi-speed-card><header class="wifi-resource-card-header"><div><strong>速度限制档案</strong><small>供 Wi-Fi 广播按需引用，不改变未选择档案的网络。</small></div><button class="policy-create-button compact" type="button" data-wifi-speed-create>${icon('plus')}<span>新建</span></button></header><div class="wifi-table-scroll"><table class="dwrt-kit-table"><thead><tr><th>名称</th><th>下载</th><th>上传</th><th></th></tr></thead><tbody>${rows.map((limit) => `<tr data-wifi-speed-edit="${escapeHtml(limit.id)}"><td><strong>${escapeHtml(limit.name)}</strong></td><td>${limit.download_mbps ? `${limit.download_mbps} Mbps` : '无限制'}</td><td>${limit.upload_mbps ? `${limit.upload_mbps} Mbps` : '无限制'}</td><td><button class="wifi-row-button" type="button" aria-label="编辑 ${escapeHtml(limit.name)}">${icon('chevron')}</button></td></tr>`).join('')}</tbody></table></div>${rows.length ? '' : `<div class="wifi-compact-empty" data-dwrt-component="state-panel" data-dwrt-state="empty"><strong>没有速度限制档案</strong><p>新建档案后可在 Wi-Fi 编辑抽屉中选择。</p></div>`}</section>`;
  }

  function roamingCapabilityBadge(label, enabled) {
    return `<span class="dwrt-kit-status-badge is-${enabled ? 'success' : 'warning'}"><i class="dwrt-kit-status-badge-dot" aria-hidden="true"></i><span>${escapeHtml(label)}：${enabled ? '已启用' : '不可用'}</span></span>`;
  }

  function roamingSwitchRow(path, title, detail, checked, disabled = false) {
    return `<label class="wifi-setting-row dwrt-kit-switch" data-dwrt-component="switch"><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(detail)}</small></span><input type="checkbox" role="switch" data-roaming-setting="${escapeHtml(path)}" aria-label="${escapeHtml(title)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}></label>`;
  }

  function roamingPolicyMarkup() {
    const roaming = state.roaming;
    if (roaming.loading && !roaming.loaded) {
      return `<section class="wifi-panel-section wifi-roaming-policy" data-wifi-roaming-policy><div data-dwrt-component="state-panel" data-dwrt-state="loading"><strong>正在读取全屋漫游策略</strong><p>正在读取漫游域、邻居报告与 BSS Transition 能力。</p></div></section>`;
    }
    if (roaming.error && !roaming.loaded) {
      return `<section class="wifi-panel-section wifi-roaming-policy" data-wifi-roaming-policy><div data-dwrt-component="state-panel" data-dwrt-state="error"><strong>全屋漫游策略不可用</strong><p>${escapeHtml(roaming.error)}</p><button class="wifi-link-button" type="button" data-roaming-retry>重新读取</button></div></section>`;
    }
    const domain = roamingDomain();
    const caps = roamingCoreCapabilities(domain);
    const reason = roamingPolicyCapabilityReason();
    const writable = roamingPolicyWriteAllowed();
    const draft = roaming.draft;
    const domainOptions = `${roaming.domains.length > 1 && !roaming.domainId ? '<option value="" selected>请选择漫游域</option>' : ''}${roaming.domains.map((item) => `<option value="${escapeHtml(item.domain_id)}" ${item.domain_id === roaming.domainId ? 'selected' : ''}>${escapeHtml(firstText(item.name, item.domain_id))}</option>`).join('')}`;
    const domainPicker = `<label class="wifi-field dwrt-kit-field wifi-roaming-domain-field" data-dwrt-component="field"><span>漫游域</span><select data-roaming-domain ${roaming.domains.length <= 1 || roaming.dirty || roaming.loading ? 'disabled' : ''}>${roaming.domains.length ? domainOptions : '<option value="">没有可用漫游域</option>'}</select><small>${roaming.domains.length > 1 ? '多个域不会自动替你选择；切换域前请先保存或放弃当前草稿。' : '当前策略作用于该域内的所有受管 AP。'}</small></label>`;
    if (!roaming.domains.length) {
      return `<section class="wifi-panel-section wifi-roaming-policy" data-wifi-roaming-policy><header class="wifi-section-head"><div><strong>全屋漫游与频段引导</strong><small>AC 域级策略，与本机 Wi-Fi 扩展设置分开保存。</small></div></header>${domainPicker}<div class="wifi-roaming-empty" data-dwrt-component="state-panel" data-dwrt-state="empty"><strong>尚未配置漫游域</strong><p>先在 AC 控制面创建漫游域，页面才会显示 802.11k/v 和客户端实测信号策略。</p></div></section>`;
    }
    if (!draft) {
      return `<section class="wifi-panel-section wifi-roaming-policy" data-wifi-roaming-policy><header class="wifi-section-head"><div><strong>全屋漫游与频段引导</strong><small>AC 域级策略，与本机 Wi-Fi 扩展设置分开保存。</small></div></header>${domainPicker}<div class="wifi-roaming-empty" data-dwrt-component="state-panel" data-dwrt-state="idle"><strong>请选择漫游域</strong><p>选择一个域后读取该域的策略。</p></div></section>`;
    }
    const preference = firstText(draft.steering_preference, 'stability');
    const performance = preference === 'performance';
    const highBand = bool(draft.high_band_steer_enabled, false);
    const force = performance && bool(draft.force_disassoc_on_reject, false) && caps.deauth;
    const lower = performance && highBand && force && bool(draft.lower_band_block_enabled, false);
    const forceDisabled = !writable || !caps.deauth;
    const lowerDisabled = !writable || !performance || !highBand || !force;
    const capabilityNotice = reason ? `<div class="wifi-notice is-warn" data-roaming-capability-notice>${icon('info')}<span>${escapeHtml(reason)}</span></div>` : '';
    const errorNotice = roaming.error ? `<div class="wifi-notice is-error" data-roaming-error>${icon('info')}<span>${escapeHtml(roaming.error)}</span></div>` : '';
    const saveNotice = roaming.notice ? `<div class="wifi-notice ${roaming.noticeTone ? `is-${roaming.noticeTone}` : ''}" data-roaming-notice>${icon('info')}<span>${escapeHtml(roaming.notice)}</span></div>` : '';
    const forceDetail = caps.deauth
      ? (force ? 'BTM 被拒绝或终端不移动时，AC 可以短暂断开并重新引导。' : '关闭时只下发 advisory BTM，不保证终端移动。')
      : '当前漫游域未启用强制断开能力，只能使用 advisory BTM。';
    return `<section class="wifi-panel-section wifi-roaming-policy" data-wifi-roaming-policy>
      <header class="wifi-section-head"><div><strong>全屋漫游与频段引导</strong><small>AC 域级策略：使用各 AP 观察到的客户端实测信号，不依赖 iPhone 回报测量。</small></div></header>
      ${domainPicker}
      <div class="wifi-roaming-capabilities" aria-label="漫游能力"><span>当前域能力</span>${roamingCapabilityBadge('802.11k 邻居报告', caps.neighborReport)}${roamingCapabilityBadge('802.11v BTM', caps.bssTransition)}${roamingCapabilityBadge('强制断开', caps.deauth)}</div>
      ${capabilityNotice}${errorNotice}${saveNotice}
      <div class="wifi-roaming-settings">
        <div class="wifi-roaming-mode-row"><div><strong>漫游决策偏好</strong><small>${performance ? '有新鲜实测的更好候选 AP 时，可以提前引导，不必等当前 RSSI 跌破阈值。' : '只有当前连接信号跌破阈值后，才允许切换到更合适的候选 AP。'}</small></div><div class="dwrt-kit-segmented wifi-roaming-preference" data-dwrt-component="segmented" data-roaming-preference data-dwrt-value="${escapeHtml(preference)}" role="radiogroup" aria-label="漫游决策偏好">${[['stability', '稳定优先'], ['performance', '速率优先']].map(([value, label]) => `<button type="button" data-dwrt-segment data-value="${value}" role="radio" aria-checked="${preference === value ? 'true' : 'false'}" class="${preference === value ? 'is-active' : ''}" ${writable ? '' : 'disabled'}>${label}</button>`).join('')}</div></div>
        <label class="wifi-inline-setting wifi-roaming-number"><span><strong>弱信号阈值</strong><small>${performance ? '速率优先只把它作为弱信号参考；有新鲜更好候选时不必等待它。' : '稳定优先以此作为允许切换的门槛。'}</small></span><span class="wifi-field-unit"><input type="number" min="-100" max="-40" data-roaming-number="weak_rssi_dbm" value="${escapeHtml(String(draft.weak_rssi_dbm ?? ''))}" ${writable ? '' : 'disabled'}><b>dBm</b></span></label>
        ${roamingSwitchRow('high_band_steer_enabled', '优先高频段', '只会引导到该终端近期有实测信号的频段；不会因为 AP 存在 6 GHz 就假设 iPhone 支持 6 GHz。', highBand, !writable)}
        ${performance ? roamingSwitchRow('force_disassoc_on_reject', '客户端不听劝时允许强制切换', forceDetail, force, forceDisabled) : ''}
        ${performance && highBand && force ? roamingSwitchRow('lower_band_block_enabled', '强制切换时临时拒绝低频段重新关联', '仅创建短暂的重新关联拒绝租约，帮助终端完成目标 AP 关联，不是永久黑名单。', lower, lowerDisabled) : ''}
        <section class="wifi-roaming-advanced" data-dwrt-component="disclosure"><button type="button" data-dwrt-disclosure-trigger aria-expanded="false"><span><strong>高级：重新关联拒绝租约</strong><small>只在启用临时低频段拒绝时使用，范围由 AC 后端解释。</small></span>${icon('chevron-down')}</button><div data-dwrt-disclosure-panel hidden><label class="wifi-inline-setting wifi-roaming-number"><span><strong>租约时长</strong><small>短暂拒绝同一终端重新关联，后端限制为 1 到 30 秒。</small></span><span class="wifi-field-unit"><input type="number" min="1" max="30" data-roaming-number="reassoc_block_sec" value="${escapeHtml(String(draft.reassoc_block_sec ?? ''))}" ${writable ? '' : 'disabled'}><b>秒</b></span></label><div class="wifi-roaming-scope-note">当前保存范围：${escapeHtml(lower ? 'lower · 低频段' : firstText(draft.reassoc_block_scope, 'ap'))}</div></div></section>
      </div>
    </section>`;
  }

  function extendedSettings() {
    const global = state.config.global;
    const disabled = !canConfigWrite();
    const regions = state.config.regdomains.length ? state.config.regdomains : [{ code: global.country || 'CN', name: global.country || 'CN' }];
    return `<section class="wifi-panel-section"><header class="wifi-section-head"><div><strong>Dreaming OS 扩展设置 · 本机</strong><small>仅影响本机 OpenWrt、hostapd 与 QCA 驱动；不会替代上面的 AC 漫游域策略。</small></div></header><div class="wifi-extension-grid"><label class="wifi-field dwrt-kit-field" data-dwrt-component="field"><span>地区码</span><select data-wifi-setting="global.country" ${disabled ? 'disabled' : ''}>${regions.map((region) => `<option value="${escapeHtml(region.code)}" ${String(region.code) === String(global.country) ? 'selected' : ''}>${escapeHtml(`${region.code} · ${region.name || region.code}`)}</option>`).join('')}</select><small>最终合法信道以后端 regdb 与驱动裁剪结果为准。</small></label><label class="wifi-field dwrt-kit-field" data-dwrt-component="field"><span>本机 5 GHz 漫游阈值</span><div class="wifi-field-unit"><input type="number" min="-95" max="-45" data-wifi-setting="global.roam_threshold" value="${firstNumber(global.roam_threshold, -75)}" ${disabled ? 'disabled' : ''}><b>dBm</b></div></label></div><div class="wifi-settings-list two-columns">${switchRow('global.band_steering', '本机频段引导', '仅对本机配置中支持的终端提供高频段偏好。', global.band_steering, disabled)}${switchRow('global.fast_roaming', '快速漫游', '启用本机 802.11k/v 的全局默认值。', global.fast_roaming, disabled)}${switchRow('global.mlo', 'MLO', 'Wi-Fi 7 多链路操作，需至少两个 Radio。', global.mlo, disabled)}${switchRow('global.airtime_fairness', 'Airtime Fairness', '避免低速终端长期占用空口。', global.airtime_fairness, disabled)}${switchRow('global.multicast_enhance', '组播增强', '将部分无线组播转换为单播，降低空口占用。', global.multicast_enhance, disabled)}${switchRow('global.qca_rrm', 'RRM', '启用 QCA/OpenWrt 无线资源测量。', global.qca_rrm, disabled)}${switchRow('global.qca_qbssload', 'QBSS Load', '广播 BSS 负载辅助终端选择 AP。', global.qca_qbssload, disabled)}${switchRow('global.mu_beamformer', 'MU Beamformer', '启用支持硬件的多用户波束成形。', global.mu_beamformer, disabled)}${switchRow('global.doth', '802.11h / DFS', '启用频谱管理与雷达检测相关能力。', global.doth, disabled)}${switchRow('global.sae_pwe', 'SAE PWE', '使用 WPA3 SAE H2E/兼容模式。', global.sae_pwe, disabled)}${switchRow('global.roam_assist', '本机漫游辅助', '根据本机阈值辅助低信号终端重新关联。', global.roam_assist, disabled)}</div></section>`;
  }

  /*
   * ── AP 管理视图 ──
   *
   * 第一版只做后端已开放的能力：清单只读 + 显示名/型号覆盖编辑（ap_inventory_edit）
   * + 配对令牌生成与吊销。SSID 编辑、信道调整、AP 重启/定位依赖尚未落地的
   * validate/apply/readback/rollback 事务层，按 DESIGN 规则以禁用态呈现并写明原因，
   * 不做成"点了不生效"的控件。
   */
  function acStatusBadge(ap) {
    const [tone, label] = !ap.online
      ? ['error', '离线']
      : ap.stale
        ? ['warning', '心跳陈旧']
        : !ap.session_connected ? ['warning', '隧道未连接'] : ['success', '在线'];
    return `<span class="dwrt-kit-status-badge is-${tone}" data-dwrt-status="${tone}"><i class="dwrt-kit-status-badge-dot" aria-hidden="true"></i><span>${label}</span></span>`;
  }

  function tokenStateBadge(token) {
    const [tone, label] = token.revoked_at
      ? ['muted', '已吊销']
      : token.state === 'consumed'
        ? ['success', '已使用']
        : token.expired || token.state === 'expired'
          ? ['muted', '已过期']
          : token.state === 'active' ? ['info', '等待配对'] : ['muted', token.state];
    return `<span class="dwrt-kit-status-badge is-${tone}" data-dwrt-status="${tone}"><i class="dwrt-kit-status-badge-dot" aria-hidden="true"></i><span>${escapeHtml(label)}</span></span>`;
  }

  
  /*
   * 概览四张卡：值全部来自 AC 的真实响应。
   *
   * 两处曾经在说谎，改掉了：
   *  - 「全网接入客户端」按 runtime.client_count 求和，那个字段不存在，所以
   *    恒为 0；现在读 runtime.snapshot.station_count，并且在没有任何 AP 上报时
   *    显示 `--` 而不是 0 —— 0 台客户端是一个事实，无人上报是另一回事。
   *  - 「控制器协议」写死 ap-control.v3 + 「双向加密就绪」。协议号是每台 AP
   *    自己报的（control_protocol / control_protocol_version），版本不一致时
   *    写死会掩盖掉半数节点跑着旧协议；副标题也换成可核对的协商台数。
   *
   * 强调色走 .is-accent / .is-ok 类，不再内联 var(--dwrt-accent-blue,#0A84FF)：
   * 这两个 token 全树都没有定义，实际渲染出来是苹果原生蓝绿，与本页的
   * --wifi-accent / --wifi-ok 对不上。
   */
  function apManagementSummaryCards() {
    const aps = state.ac.aps || [];
    const onlineCount = aps.filter(ap => ap.online).length;
    const offlineCount = aps.length - onlineCount;
    const tokens = state.ac.tokens || [];
    const activeTokens = tokens.filter(t => t.state === 'active' && !t.expired && !t.revoked_at).length;

    const reporting = aps.filter(ap => ap.runtime_available && ap.runtime.clientCount !== null);
    const totalClients = reporting.reduce((sum, ap) => sum + ap.runtime.clientCount, 0);
    const clientValue = reporting.length ? `${totalClients} 台` : '--';
    const clientSub = !aps.length
      ? '尚未纳管 AP'
      : reporting.length === aps.length
        ? `${reporting.length} 台 AP 已上报关联数`
        : `${reporting.length}/${aps.length} 台 AP 已上报 · 其余未上报`;

    const protocols = [...new Set(aps.map(ap => firstText(ap.control_protocol)).filter(Boolean))];
    const protocolValue = protocols.length === 1 ? protocols[0] : protocols.length ? '版本不一致' : '--';
    const protocolSub = !aps.length
      ? '等待首台 AP 配对'
      : protocols.length === 1
        ? `${aps.length} 台节点均已按此协议协商`
        : protocols.length
          ? escapeHtml(protocols.join(' · '))
          : '节点未上报协议版本';

    return `<div class="wifi-ap-summary-grid">
      <div class="wifi-ap-summary-card dwrt-kit-glass-surface">
        <div class="wifi-ap-summary-content">
          <span class="wifi-ap-summary-label">已纳管无线 AP</span>
          <span class="wifi-ap-summary-value is-accent">${aps.length} 台</span>
          <span class="wifi-ap-summary-sub">${onlineCount} 台在线 · ${offlineCount} 台离线</span>
        </div>
        <div class="wifi-ap-summary-icon" aria-hidden="true">📡</div>
      </div>
      <div class="wifi-ap-summary-card dwrt-kit-glass-surface">
        <div class="wifi-ap-summary-content">
          <span class="wifi-ap-summary-label">全网接入客户端</span>
          <span class="wifi-ap-summary-value">${clientValue}</span>
          <span class="wifi-ap-summary-sub ${reporting.length && reporting.length === aps.length ? 'is-ok' : ''}">${clientSub}</span>
        </div>
        <div class="wifi-ap-summary-icon" aria-hidden="true">📱</div>
      </div>
      <div class="wifi-ap-summary-card dwrt-kit-glass-surface">
        <div class="wifi-ap-summary-content">
          <span class="wifi-ap-summary-label">控制器协议</span>
          <span class="wifi-ap-summary-value is-compact">${escapeHtml(protocolValue)}</span>
          <span class="wifi-ap-summary-sub">${protocolSub}</span>
        </div>
        <div class="wifi-ap-summary-icon" aria-hidden="true">🔒</div>
      </div>
      <div class="wifi-ap-summary-card dwrt-kit-glass-surface">
        <div class="wifi-ap-summary-content">
          <span class="wifi-ap-summary-label">配对令牌状态</span>
          <span class="wifi-ap-summary-value">${activeTokens} 个活跃</span>
          <span class="wifi-ap-summary-sub">共 ${tokens.length} 条配对记录</span>
        </div>
        <div class="wifi-ap-summary-icon" aria-hidden="true">🎫</div>
      </div>
    </div>`;
  }

  /*
   * 受管 AP 清单：一台一条横条，几何照 demo（identity / 射频 / 心跳 / 状态 / 操作
   * 五列固定网格），材质由每条自己挂的 .dwrt-kit-glass-surface 提供。
   *
   * 三种「没有射频信息」必须分开说，不能都写成「射频离线」：
   *  - AP 离线            → 射频离线
   *  - 在线但快照未到     → 射频未上报（runtime_reason 进 title）
   *  - 在线、快照到了但某条射频没报频段 → 计入「N 个射频未上报」，不冒充频段
   *
   * 客户端数同理：0 客户端与未上报是两句话。
   */
  function apInventoryStrips() {
    const query = state.query.trim().toLowerCase();
    const rows = state.ac.aps.filter((ap) => !query ||
      [ap.label, ap.name, ap.model, ap.board_name, ap.ap_id, ap.site_id, ap.runtime.ip]
        .join(' ').toLowerCase().includes(query));
    const editable = canEditAcAp();
    const editReason = editable ? '' : firstText(acReason('ap_inventory_edit'), '后端未开放清单编辑能力');
    /*
     * 解绑没有对应的后端能力位，也没有任何前端处理器 —— 保留 demo 的按钮位，
     * 但必须是禁用态并写明原因，否则就是本文件顶部注释禁止的「点了不生效」控件。
     */
    const releaseReason = firstText(acReason('ap_release'), acReason('ap_delete'), '后端未开放解绑 / 删除 AP 的能力');

    const stripList = rows.map((ap) => {
      const runtime = ap.runtime;
      const reported = runtime.radios.filter((radio) => radio.reported);
      const silent = runtime.radios.length - reported.length;

      const radioPills = reported.map((radio) => {
        const channel = radio.channel === null ? '信道未上报' : `Ch ${radio.channel}`;
        const width = radio.widthMhz === null ? '' : ` · ${radio.widthMhz}M`;
        return `<span class="wifi-ap-radio-tag">${escapeHtml(radio.band)}: ${escapeHtml(channel)}${escapeHtml(width)}</span>`;
      }).join('');
      const silentPill = silent > 0
        ? `<span class="wifi-ap-radio-tag is-muted">${silent} 个射频未上报</span>`
        : '';
      const clientPill = runtime.clientCount === null
        ? '<span class="wifi-ap-radio-tag is-muted">客户端未上报</span>'
        : `<span class="wifi-ap-radio-tag is-accent">${runtime.clientCount} 客户端</span>`;

      let radioInfo;
      if (!ap.online) {
        radioInfo = `<div class="wifi-ap-strip-radios"><span class="wifi-ap-strip-label">广播射频</span><div class="wifi-ap-radio-pills"><span class="wifi-ap-radio-tag is-muted">射频离线</span></div></div>`;
      } else if (!reported.length) {
        const reason = firstText(ap.runtime_reason, '控制器尚未收到该 AP 的射频快照');
        radioInfo = `<div class="wifi-ap-strip-radios"><span class="wifi-ap-strip-label">广播射频</span><div class="wifi-ap-radio-pills"><span class="wifi-ap-radio-tag is-muted" title="${escapeHtml(reason)}">射频未上报</span>${clientPill}</div></div>`;
      } else {
        radioInfo = `<div class="wifi-ap-strip-radios"><span class="wifi-ap-strip-label">广播射频与客户端</span><div class="wifi-ap-radio-pills">${radioPills}${silentPill}${clientPill}</div></div>`;
      }

      const identity = firstText(ap.model, ap.board_name) || '型号未上报';
      const locator = firstText(runtime.ip) || (ap.ap_id ? ap.ap_id.slice(0, 16) : '');
      return `<div class="wifi-ap-strip${ap.online ? '' : ' is-offline'}">
        <div class="wifi-ap-strip-identity">
          ${deviceImage(apImageDevice(ap), 'wifi-ap-strip-icon')}
          <div class="wifi-ap-strip-names">
            <strong>${escapeHtml(ap.label)}</strong>
            <span title="${escapeHtml(ap.ap_id || '')}">${escapeHtml(identity)}${locator ? ` · ${escapeHtml(locator)}` : ''}</span>
          </div>
        </div>
        ${radioInfo}
        <div class="wifi-ap-strip-seen"><span class="wifi-ap-strip-label">最后心跳</span><span class="wifi-ap-strip-value" title="${escapeHtml(absoluteTime(ap.last_seen_at) || '')}">${escapeHtml(relativeSeconds(ap.last_seen_at) || '--')}</span></div>
        <div class="wifi-ap-strip-status">${acStatusBadge(ap)}</div>
        <div class="wifi-ap-strip-actions">
          <button class="wifi-ap-strip-button" type="button" data-wifi-ap-edit="${escapeHtml(ap.ap_id)}" ${editable ? '' : 'disabled'} title="${escapeHtml(editable ? `配置 ${ap.label}` : editReason)}">✎ 配置</button>
          <button class="wifi-ap-strip-button is-danger" type="button" disabled title="${escapeHtml(releaseReason)}" aria-label="解绑 ${escapeHtml(ap.label)}（${escapeHtml(releaseReason)}）">🗑</button>
        </div>
      </div>`;
    }).join('');

    return `<section class="wifi-panel-section wifi-ap-inventory-modern dwrt-kit-glass-surface">
      <header class="wifi-panel-heading">
        <div><strong>📡 受管 AP 节点矩阵 (${rows.length} 台已绑定)</strong><small>实时监控节点无线负荷、信道分布与心跳响应状态</small></div>
        <label class="wifi-ap-search"><span class="sr-only">搜索 AP</span><input type="search" data-wifi-search placeholder="🔍 搜索 AP 别名、型号或 IP..." value="${escapeHtml(state.query)}"></label>
      </header>
      ${rows.length ? `<div class="wifi-ap-strip-list">${stripList}</div>` : ''}
      ${rows.length ? '' : `<div class="wifi-table-empty" data-dwrt-component="state-panel" data-dwrt-state="empty"><span>${icon('radio')}</span><strong>${query ? '没有匹配的 AP' : '尚未绑定 AP'}</strong><small>${query ? '调整搜索条件后重试。' : '用右上角“临时配对码”生成一次性凭据，或用“添加新 AP (发现向导)”查看已公告的设备。'}</small></div>`}
      ${apCapabilityFooter()}
    </section>`;
  }

  /*
   * 配对码的一次性码值与历史记录都搬进「临时配对码」抽屉了（demo 的页面上没有这张
   * 卡片，用户明确要求删掉）。删的是那张卡，不是功能：码值、倒计时、吊销、空态
   * 一条不少，只是换了容器。下面两段只被 tokenSheet() 调用。
   */
  function pairingSecretBlock() {
    if (!state.tokenSecret) return '';
    return `<div class="wifi-pairing-secret" role="status"><div><span>配对码（仅显示一次）</span><code>${escapeHtml(state.tokenSecret.token)}</code></div><div class="wifi-pairing-secret-meta"><span>有效期至 ${escapeHtml(absoluteTime(state.tokenSecret.expires_at) || '--')}</span><span>最多尝试 ${state.tokenSecret.max_attempts || '--'} 次</span></div><div class="wifi-pairing-secret-actions"><button class="policy-secondary" type="button" data-wifi-token-copy="${escapeHtml(state.tokenSecret.token)}">复制配对码</button><button class="policy-secondary" type="button" data-wifi-token-secret-dismiss>我已保存</button></div></div>`;
  }

  function pairingTokenRecords() {
    const allowed = canManageTokens();
    const reason = allowed ? '' : firstText(acReason('pairing_token_ipc'), '后端未开放配对令牌能力');
    const tokens = state.ac.tokens.slice().sort((left, right) => (right.created_at || 0) - (left.created_at || 0));
    const active = tokens.filter((token) => token.state === 'active' && !token.expired && !token.revoked_at);
    const rows = tokens.map((token) => {
      const revocable = allowed && token.state === 'active' && !token.expired && !token.revoked_at;
      return `<tr><td><code class="wifi-token-id">${escapeHtml(token.token_id.slice(0, 8))}</code>${token.hardware_bound ? '<small>已绑定硬件</small>' : ''}</td><td>${tokenStateBadge(token)}</td><td><span title="${escapeHtml(absoluteTime(token.expires_at))}">${escapeHtml(token.state === 'active' && !token.revoked_at ? (countdownSeconds(token.expires_at) || '--') : (absoluteTime(token.expires_at) || '--'))}</span></td><td>${token.attempts} / ${token.max_attempts || '--'}</td><td><button class="policy-secondary wifi-token-revoke" type="button" data-wifi-token-revoke="${escapeHtml(token.token_id)}" ${revocable && !state.acBusy ? '' : 'disabled'} ${!allowed && reason ? `title="${escapeHtml(reason)}"` : ''}>吊销</button></td></tr>`;
    }).join('');
    return `<section class="wifi-token-records"><div class="wifi-sheet-section-head"><strong>已发出的配对码</strong><small>${active.length} 个等待配对 · 共 ${tokens.length} 条记录</small></div>${tokens.length ? `<div class="dwrt-kit-table-scroll wifi-table-scroll"><table class="dwrt-kit-table"><thead><tr><th>令牌</th><th>状态</th><th>有效期</th><th>尝试次数</th><th><span class="sr-only">操作</span></th></tr></thead><tbody>${rows}</tbody></table></div>` : `<div class="wifi-table-empty" data-dwrt-component="state-panel" data-dwrt-state="empty"><span>${icon('info')}</span><strong>还没有配对码</strong><small>${allowed ? '填好上面的有效期与尝试次数，点“生成配对码”，码值会显示在这里。' : escapeHtml(reason)}</small></div>`}</section>`;
  }

  function adoptionBundleSection() {
    const adoption = state.adoption;
    const bundle = adoption.secret;
    const hasSecret = bootstrapBundleValid(bundle);
    const error = adoption.error ? bootstrapErrorLabel(adoption) : null;
    if (!adoption.bindingId && !hasSecret && !error) return '';
    const status = bootstrapStatusLabel(adoption.state);
    const json = hasSecret ? bootstrapBundleJson(bundle, true) : '';
    const command = hasSecret ? firstText(adoption.command, bootstrapCommand(bundle)) : '';
    const expiry = hasSecret ? absoluteTime(bundle.expires_at) : '';
    const feedback = adoption.copyFeedback
      ? `<div class="wifi-notice ${adoption.copyTone === 'ok' ? 'is-ok' : 'is-error'}" role="status">${icon(adoption.copyTone === 'ok' ? 'copy' : 'info')}<span>${escapeHtml(adoption.copyFeedback)}</span></div>`
      : '';
    const errorMarkup = error
      ? `<div class="wifi-notice is-error" role="alert">${icon('info')}<span>${escapeHtml(error.text)}</span></div>`
      : '';
    const secretMarkup = hasSecret
      ? `<div class="wifi-bootstrap-secret" data-wifi-bootstrap-secret><div class="wifi-bootstrap-field"><div class="wifi-bootstrap-field-heading"><strong>完整 JSON bundle</strong><span>仅显示一次 · 有效期至 ${escapeHtml(expiry || '--')}</span></div><textarea readonly data-wifi-bootstrap-value="bundle" aria-label="完整 JSON bundle">${escapeHtml(json)}</textarea><button class="policy-secondary" type="button" data-wifi-bootstrap-copy="bundle">${icon('copy')}<span>复制完整 bundle</span></button></div><div class="wifi-bootstrap-field"><div class="wifi-bootstrap-field-heading"><strong>交给 AP 侧执行的命令</strong><span>提示：jmctl ap pair --bundle '&lt;JSON&gt;'</span></div><textarea readonly data-wifi-bootstrap-value="command" aria-label="AP 配对命令">${escapeHtml(command)}</textarea><button class="policy-secondary" type="button" data-wifi-bootstrap-copy="command">${icon('copy')}<span>复制完整命令</span></button></div><div class="wifi-bootstrap-field"><div class="wifi-bootstrap-field-heading"><strong>CA 证书 PEM</strong><span>完整内容可手动选择复制</span></div><textarea readonly data-wifi-bootstrap-value="pem" aria-label="控制器 CA 证书 PEM">${escapeHtml(bundle.ca_cert_pem)}</textarea></div><footer class="wifi-bootstrap-actions"><button class="policy-secondary" type="button" data-wifi-bootstrap-close>${icon('close')}<span>关闭一次性 bundle</span></button></footer></div>`
      : adoption.secretClearedReason
        ? `<div class="wifi-notice is-warn" role="status">${icon('info')}<span>一次性 bundle 已${adoption.secretClearedReason === 'expired' ? '过期并清除' : '关闭并清除'}；页面不会再次回读 secret。</span></div>`
        : '';
    const pollingNote = adoption.bindingId && !adoptionTerminalState(adoption.state)
      ? '<small class="wifi-bootstrap-polling">绑定状态只读取非 secret 状态，不会再次请求 bundle。</small>'
      : '';
    return `<section class="wifi-panel-section wifi-adoption-section dwrt-kit-glass-surface" data-wifi-adoption-section><header class="wifi-panel-heading"><div><strong>AP 纳管</strong><small>${escapeHtml(adoption.candidateLabel || '已确认的 AP')} · ${escapeHtml(status)}${adoption.bindingId ? ` · 绑定 ID ${escapeHtml(adoption.bindingId)}` : ''}</small></div><span class="dwrt-kit-status-badge ${adoption.state === 'adopted' ? 'is-success' : adoption.state === 'failed' ? 'is-error' : 'is-warning'}" data-dwrt-status="${adoption.state === 'adopted' ? 'success' : adoption.state === 'failed' ? 'error' : 'warning'}"><span>${escapeHtml(status)}</span></span></header>${errorMarkup}${feedback}${secretMarkup}${pollingNote}</section>`;
  }

  function discoveryCandidateLabel(candidate = {}) {
    return firstText(candidate.model, candidate.board_name, candidate.ap_id ? `AP ${candidate.ap_id.slice(0, 8)}` : '新 AP');
  }

  /*
   * 「添加新 AP (发现向导)」——demo 的 .wizard-modal。用户要求删掉页面上那张常驻的
   * 「发现到的 AP」卡片，候选清单整块搬到这里；四道闸门（available /
   * endpointAvailable / confirmAvailable / canConfirmDiscoveryCandidate）一道不少。
   *
   * 三点与 demo 的差异，都是「不撒谎」压过「像 demo」：
   *  1. demo 的雷达是一个 1.2 s 的定时器，扫完必出一台设备。这里的 scanning 只在
   *     loadAcDiscovery() 这次只读 GET 在飞时为真，扫完是几台就是几台，一台都没有
   *     就明说没有。
   *  2. demo 把「绑定」按钮放在弹窗页脚。这里放在每张候选卡上：候选可以是 N 台，
   *     页脚那颗按钮说不清自己绑的是哪一台。页脚留 取消 / 重新扫描。
   *  3. demo 的别名输入框能改名。discoveryConfirmRequest() 只转发后端下发的
   *     confirm_request.{api, body}，没有别名字段，所以这里必须是 disabled 且写明
   *     原因 —— 一个会被静默丢掉的输入框正是本页禁止的「点了不生效」控件。
   */
  function apWizardMarkup() {
    if (!state.apWizard) return '';
    const discovery = state.ac.discovery || {};
    const candidates = Array.isArray(discovery.items) ? discovery.items : [];
    const available = bool(discovery.available, false);
    const endpointAvailable = bool(discovery.endpointAvailable, false);
    const confirmAvailable = bool(discovery.confirmAvailable, false);
    const reason = firstText(discovery.reason, acReason('ap_discovery'), '后端未提供设备发现能力');
    const scanning = state.apWizardScanning;

    let statusText;
    let blocked = '';
    if (scanning) {
      statusText = '正在局域网扫描新 AP...';
    } else if (!available) {
      statusText = '无法扫描：发现服务未启用';
      blocked = reason;
    } else if (!endpointAvailable) {
      statusText = '无法列出候选：Web 侧清单接口未开放';
      blocked = '发现服务已启用，但 Web 接口尚未开放候选清单。后端需要提供只读 discovery 路由与确认合同。';
    } else if (candidates.length) {
      statusText = '扫描完成，请确认命名并绑定';
    } else {
      statusText = state.apWizardScannedAt ? '扫描完成，没有发现未绑定的 AP' : '尚未扫描';
    }

    const aliasReason = '后端的确认票据里没有别名字段，改名请在绑定后用清单里的“配置”';
    const cards = candidates.map((candidate) => {
      const label = discoveryCandidateLabel(candidate);
      const locator = firstText(candidate.mgmt_ip, candidate.claimed_ip);
      const bindable = canConfirmDiscoveryCandidate(candidate) && !candidate.adopted_elsewhere && !state.adoption.bindingId && confirmAvailable;
      const bindTitle = state.adoption.bindingId
        ? '已有绑定请求，请先完成当前 AP 纳管'
        : candidate.adopted_elsewhere
        ? `已绑定到 ${candidate.adopted_controller_id || '另一台网关'}`
        : !confirmAvailable ? '后端尚未开放确认绑定接口'
        : !canConfirmDiscoveryCandidate(candidate) ? '后端尚未提供此设备的确认请求票据'
        : `核对指纹后绑定 ${label}`;
      const chip = candidate.adopted_elsewhere
        ? '<span class="wifi-discovered-chip is-warn">已被其他网关管理</span>'
        : `<span class="wifi-discovered-chip">${candidate.trusted ? '已验证 · 待绑定' : '待绑定'}</span>`;
      return `<div class="wifi-discovered-card${candidate.adopted_elsewhere ? ' is-taken' : ''}">
        <div class="wifi-discovered-top">
          <div class="wifi-discovered-names">
            <span class="wifi-discovered-kicker">${escapeHtml(candidate.adopted_elsewhere ? '发现设备，但已被占用' : '发现新设备就绪')}</span>
            <strong>${escapeHtml(label)}${locator ? `（IP: ${escapeHtml(locator)}${candidate.mgmt_port ? `:${escapeHtml(String(candidate.mgmt_port))}` : ''}）` : ''}</strong>
            <small>指纹 <code class="wifi-discovery-key">${escapeHtml(candidate.key_id || candidate.ap_id || '--')}</code> · 公告于 <span title="${escapeHtml(absoluteTime(candidate.last_seen) || '')}">${escapeHtml(relativeSeconds(candidate.last_seen) || '--')}</span></small>
          </div>
          ${chip}
        </div>
        <label class="wifi-discovered-alias"><span>为此 AP 设置个性化位置别名</span><input type="text" class="wifi-glass-input" placeholder="例如: 客厅 AP / 书房 AP" disabled title="${escapeHtml(aliasReason)}"><small>${escapeHtml(aliasReason)}</small></label>
        <div class="wifi-discovered-actions">
          <button class="wifi-btn-pill is-blue" type="button" data-wifi-discovery-confirm="${escapeHtml(candidate.ap_id)}" ${bindable ? '' : 'disabled'} title="${escapeHtml(bindTitle)}" aria-label="${escapeHtml(bindTitle)}">${icon('bolt')}<span>绑定并下发全屋配置</span></button>
        </div>
      </div>`;
    }).join('');

    return `<div class="dwrt-kit-modal-layer wifi-ap-wizard-layer is-open" data-dwrt-component="modal" data-wifi-ap-wizard-modal>
      <button class="dwrt-kit-modal-backdrop" type="button" data-dwrt-modal-close data-wifi-ap-wizard-close aria-label="关闭发现向导"></button>
      <section class="dwrt-kit-modal wifi-ap-wizard-modal" role="dialog" aria-modal="true" aria-labelledby="wifi-ap-wizard-title">
        <header class="dwrt-kit-modal-header">
          <div><strong id="wifi-ap-wizard-title">添加并纳管新无线 AP</strong><small>自动扫描局域网广播接入的未绑定 AP 节点</small></div>
          <button class="dwrt-kit-modal-close wifi-icon-button" type="button" data-dwrt-modal-close data-wifi-ap-wizard-close aria-label="关闭">${icon('close')}</button>
        </header>
        <div class="dwrt-kit-modal-body wifi-ap-wizard-body">
          <div class="wifi-scan-radar-box">
            <span class="wifi-radar-pulse-ring${scanning ? ' is-scanning' : ''}" aria-hidden="true">${icon('radar')}</span>
            <div class="wifi-scan-radar-text">
              <strong role="status">${escapeHtml(statusText)}</strong>
              <small>请确保新 AP 已通电并插入网线连接到本路由器 LAN 口。AP 会主动向网关公告自己；发现不等于绑定。</small>
            </div>
            ${blocked ? `<div class="wifi-notice is-warn">${icon('info')}<span>${escapeHtml(blocked)}</span></div>` : ''}
            ${cards}
          </div>
        </div>
        <footer class="dwrt-kit-modal-footer wifi-ap-wizard-foot">
          <button class="wifi-btn-pill is-glass" type="button" data-dwrt-modal-close data-wifi-ap-wizard-close>取消</button>
          <button class="wifi-btn-pill is-glass" type="button" data-wifi-ap-wizard-rescan ${available && endpointAvailable && !scanning ? '' : 'disabled'} title="${escapeHtml(available && endpointAvailable ? '重新读取一次候选清单（只读）' : blocked || reason)}">${icon('refresh')}<span>${scanning ? '正在扫描' : '重新扫描'}</span></button>
        </footer>
      </section>
    </div>`;
  }

  /*
   * 未开放能力如实呈现：读运行时 capabilities.reasons，不写死清单。
   * 后端放开某一项后这里会自然少一行，不需要改代码。
   *
   * 用户要求删掉「后端尚未开放的操作」那张独立卡片（demo 里没有这一块）。删的是卡片，
   * 不是这份真相 —— 它降级成清单腔体底部的**一行**脚注，材质由腔体提供，所以自己不挂
   * .dwrt-kit-glass-surface（挂了就是在玻璃上再叠一层玻璃）。
   *
   * 第一版把它做成「标题 + 每条一行的列表」，视觉上还是一整块，跟原来那张卡一样占地方，
   * 等于没删。所以名字并排排在一行里，后端给的原因码收进各自的 title —— 不丢事实，
   * 但也不再是页面上的第二个主体。
   *
   * 不能做成 <details>：patchAcSections() 每 20 s 换掉整个腔体的 outerHTML，展开与否
   * 是 DOM 上的局部状态，会被静默折回去 —— 那是一个自己会关上的抽屉。
   */
  function apCapabilityFooter() {
    const gated = [
      ['ssid_create', '新建 SSID'], ['ssid_update', '修改 SSID'], ['ssid_delete', '删除 SSID'],
      ['radio_update', '调整信道与功率'], ['ap_actions', 'AP 重启 / 定位闪灯'],
      ['password_rotation', '轮换 Wi-Fi 密码'], ['certificate_rotation', '轮换证书'],
      ['transactional_apply', '事务化下发'], ['automatic_rollback', '自动回滚']
    ].filter(([cap]) => cap in state.ac.capabilities && !acCap(cap));
    if (!gated.length) return '';
    const items = gated.map(([cap, label]) => {
      const reason = firstText(acReason(cap), '后端未说明原因');
      return `<span class="wifi-ap-gated-item" title="${escapeHtml(`${label}：${reason}`)}">${escapeHtml(label)}</span>`;
    }).join('<i aria-hidden="true">·</i>');
    return `<footer class="wifi-ap-gated">${icon('info')}<span class="wifi-ap-gated-copy">后端尚未开放的操作（${gated.length}）：本页因此不提供对应控件。</span>${items}</footer>`;
  }

  function apManagementContent() {
    /*
     * 状态面板在栈布局里要自带玻璃：外层 .wifi-ap-stack 只有几何，没有材质，
     * 裸的 state-panel 会浮在壁纸上没有底。
     */
    if (state.ac.loading && !state.ac.loaded) {
      return `<section class="wifi-panel-section wifi-ap-state dwrt-kit-glass-surface"><div data-dwrt-component="state-panel" data-dwrt-state="loading"><strong>正在读取 AP 管理数据</strong><p>清单、能力位与配对码并发拉取，返回后原位更新。</p></div></section>`;
    }
    if (!state.ac.loaded && state.ac.error) {
      return `<section class="wifi-panel-section wifi-ap-state dwrt-kit-glass-surface"><div data-dwrt-component="state-panel" data-dwrt-state="error"><strong>AP 管理暂不可用</strong><p>${escapeHtml(state.ac.error)}</p></div></section>`;
    }
    const banner = state.ac.error ? `<div class="wifi-notice is-error">${icon('info')}<span>${escapeHtml(state.ac.error)}</span></div>` : '';
    /*
     * demo 的页面上只有「概览四卡 + 受管 AP 矩阵」两块。发现清单进了向导弹窗、配对码
     * 进了抽屉、未开放能力进了矩阵页脚，所以这里只剩两块 —— 纳管进度条是绑定过程中
     * 才出现的临时块（adoptionBundleSection() 无事时返回空串），不算常驻版面。
     */
    return `${banner}${apManagementSummaryCards()}${adoptionBundleSection()}${apInventoryStrips()}`;
  }

  function configViewContent() {
    if (state.configView === 'aps') return apManagementContent();
    if (state.configView === 'radios') return state.config.radios.length ? `${radioSummary()}${defaultSpeed()}${channelPlan()}` : radioSummary();
    if (state.configView === 'extensions') return `${roamingPolicyMarkup()}${globalSettings()}${extendedSettings()}`;
    return `${configTable()}<div class="wifi-notice is-info">${icon('info')}<span>为了实现最佳的物联网互操作性，建议为 2.4 GHz 物联网设备创建专用网络。</span></div>${speedLimits()}`;
  }

  function configStatePanel() {
    /*
     * AP 管理 Tab 的数据源与 wifi/config 无关，所以不能被 config 的
     * loading / error / 无无线硬件 三种闸门挡住 —— 控制器就算本机没有 PHY
     * 也仍然可以管理远端 AP（capabilities.local_wifi_required=false）。
     *
     * 布局上它不再是一整块玻璃板：demo 要求概览四卡与节点矩阵各自成卡，
     * 所以这里换成与 .wifi-broadcast-stack 同构的 .wifi-ap-stack，玻璃材质
     * 由每张卡自己挂的 .dwrt-kit-glass-surface 提供（这样它们才会进入
     * menu-shell 的 PAGE_GLASS_SELECTOR 壁纸采样）。
     */
    if (state.configView === 'aps') return `<div class="wifi-ap-stack" role="tabpanel" aria-label="AP 管理">${configViewContent()}</div>`;
    if (state.loading && !state.loaded) return `<section class="wifi-config-surface dwrt-kit-table-wrap dwrt-kit-glass-surface"><div data-dwrt-component="state-panel" data-dwrt-state="loading"><strong>正在读取 Wi-Fi 配置</strong><p>页面结构已就绪，配置返回后会原位更新。</p></div></section>`;
    if (!state.loaded && state.error) return `<section class="wifi-config-surface dwrt-kit-table-wrap dwrt-kit-glass-surface"><div data-dwrt-component="state-panel" data-dwrt-state="error"><strong>Wi-Fi 配置暂不可用</strong><p>读取失败不会回退到示例数据或本地配置；后端恢复后重新进入页面即可更新。</p></div></section>`;
    const localFacts = localWifiFactsFor();
    if (state.loaded && localFacts.explicitNoPhy && !state.config.radios.length && !state.config.ssids.length) return `<section class="wifi-config-surface dwrt-kit-table-wrap dwrt-kit-glass-surface"><div data-dwrt-component="state-panel" data-dwrt-state="unavailable"><strong>未检测到无线硬件</strong><p>本机 PHY 数为 0（${escapeHtml(firstText(localFacts.reason, 'no_phy_detected'))}）；当前设备没有可用 PHY，因此不构造信道矩阵。受管 AP 或控制器数据源不会改变本机硬件结论。</p></div></section>`;
    if (state.configView === 'broadcasts') return `<div class="wifi-broadcast-stack" role="tabpanel" aria-label="Wi-Fi 广播">${configViewContent()}</div>`;
    return `<section class="wifi-config-surface dwrt-kit-table-wrap dwrt-kit-glass-surface" role="tabpanel" aria-label="${state.configView === 'radios' ? 'Radio 与信道' : '扩展能力'}">${configViewContent()}</section>`;
  }

  function ssidDeleteConfirmationMarkup() {
    if (!state.confirmSsidDelete) return '';
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    if (typeof renderer !== 'function') return '';
    const names = state.confirmSsidDelete.names || [];
    const label = names.length <= 3 ? names.join('、') : `${names.slice(0, 3).join('、')} 等 ${names.length} 个 Wi-Fi`;
    return renderer({
      id: 'wifi-ssid-delete-confirmation',
      action: 'delete-wifi-ssids',
      tone: 'danger',
      title: '移除 Wi-Fi 广播',
      description: `将从配置、无线接口和运行态中移除“${label}”。此操作必须由后端原子执行并完成回读。`,
      cancelLabel: '取消',
      confirmLabel: state.ssidBusy ? '正在移除' : '确认移除',
      disabled: state.ssidBusy
    });
  }

  function configPage() {
    const localDirty = state.dirty;
    const roamingDirty = state.roaming.dirty;
    const anyDirty = localDirty || roamingDirty;
    const message = localDirty && roamingDirty ? '本机 Wi-Fi 与漫游策略有未应用更改' : roamingDirty ? '漫游策略有未应用更改' : '有未应用的 Wi-Fi 更改';
    const savebar = ui.floatingSavebarMarkup?.({ visible: anyDirty, omitWhenHidden: true, busy: state.saving || state.roaming.saving, disabled: (localDirty && !canConfigWrite()) || (roamingDirty && !roamingPolicyWriteAllowed()), message, discardLabel: '放弃', busyLabel: '正在应用' }) || '';
    const pageError = state.configView === 'aps' ? '' : state.error;
    /*
     * 向导弹窗排在 discoveryConfirmationMarkup() **之前**：两者都是 Kit 的 z:72 弹层，
     * 同层里 DOM 靠后者盖在上面，而确认弹窗是从向导里点出来的，必须叠在向导之上。
     */
    return `<div class="wifi-management-shell wifi-config-shell">${configNavigation()}${pageError ? `<div class="wifi-notice is-error">${icon('info')}<span>${escapeHtml(pageError)}</span></div>` : ''}${state.notice ? `<div class="wifi-notice ${state.noticeTone ? `is-${state.noticeTone}` : ''}">${icon('info')}<span>${escapeHtml(state.notice)}</span></div>` : ''}${localWifiStateNotice()}${configStatePanel()}${savebar}${sheetMarkup()}${ssidDeleteConfirmationMarkup()}${apConfirmationMarkup()}${apWizardMarkup()}${discoveryConfirmationMarkup()}</div>`;
  }

  /* 后端 capabilities.bands 里被 normalizeBand 归一成 2g/5g/6g 的那些才可预选。
     30.1 实测该值是 ['3']（QSDK 数字编码），normalizeBand 无映射会原样返回 '3'，
     因此这里再过一道白名单，避免把 '3' 当成一个可勾选频段塞进草稿。 */
  function defaultDraftBands() {
    const known = ['2g', '5g', '6g'];
    return asArray(state.config?.capabilities?.bands).map(normalizeBand).filter((band) => known.includes(band));
  }

  function defaultDraft() {
    return normalizeSsid({
      /* Underscore, never a hyphen: this becomes a UCI section name. */
      id: `wifi_${Date.now()}`,
      /* 新建时的默认勾选取后端声明可用的频段，没有声明就不预选 —— 由用户明确选择，
         而不是替他假定这台设备有 2.4G 与 5G。这与「不编造已有 SSID 的频段」是同一条原则。 */
      name: '', network: 'lan', broadcast: '全部 AP', broadcast_mode: 'all', bands: defaultDraftBands(), enabled: true,
      security: 'wpa2-wpa3', pmf: 'optional', protocol: 'auto', encryption: 'psk2+ccmp', fast_roaming: false,
      reassociation_deadline: 1000, ft_over_ds: true, ft_psk_generate_local: true, speed_limit_id: 'default'
    });
  }

  function sheetField(label, path, value, options = {}) {
    const type = options.type || 'text';
    const help = options.help ? `<small>${escapeHtml(options.help)}</small>` : '';
    if (options.options) return `<label class="wifi-field dwrt-kit-field ${options.wide ? 'is-wide' : ''}" data-dwrt-component="field"><span>${escapeHtml(label)}</span><select data-wifi-draft="${escapeHtml(path)}" ${options.disabled ? 'disabled' : ''}>${optionList(options.options, value)}</select>${help}</label>`;
    return `<label class="wifi-field dwrt-kit-field ${options.wide ? 'is-wide' : ''}" data-dwrt-component="field"><span>${escapeHtml(label)}</span><input type="${type}" data-wifi-draft="${escapeHtml(path)}" value="${escapeHtml(value ?? '')}" ${options.placeholder ? `placeholder="${escapeHtml(options.placeholder)}"` : ''} ${options.min !== undefined ? `min="${options.min}"` : ''} ${options.max !== undefined ? `max="${options.max}"` : ''} ${options.disabled ? 'disabled' : ''}>${help}</label>`;
  }

  function draftToggle(path, title, detail, disabled = false) {
    return switchRow(path, title, detail, bool(getPath(state.draft, path)), disabled).replace('data-wifi-setting=', 'data-wifi-draft-toggle=');
  }

  function bandPill(band, active, disabled) {
    const desc = { '2g': '穿墙 · IoT', '5g': '高速 · 影音', '6g': '极速 · Wi-Fi 7' }[band] || '';
    return `<div class="wifi-band-pill ${active ? 'is-active' : ''}" data-wifi-draft-band="${band}" ${disabled ? 'style="opacity:.4;pointer-events:none;"' : ''}><b>${bandLabel(band)}</b><span>${desc}</span></div>`;
  }

  function toggleTile(path, title, detail, checked, disabled = false) {
    return `<div class="wifi-toggle-tile ${!disabled && checked ? 'is-highlight' : ''}" data-wifi-draft-toggle-tile="${escapeHtml(path)}"><div class="wifi-toggle-tile-info"><strong>${escapeHtml(title)}</strong><small>${escapeHtml(detail)}</small></div><div class="dwrt-kit-switch" data-dwrt-component="switch"><input type="checkbox" role="switch" data-wifi-draft-toggle="${escapeHtml(path)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}></div></div>`;
  }

  function syncSsidDraftDependencies() {
    const draft = state.draft;
    if (state.sheet !== 'ssid' || !draft) return;
    const bands = new Set(draft.bands || []);
    const multiBand = bands.size >= 2;
    if (!multiBand && draft.mlo) draft.mlo = false;
    const six = bands.has('6g');
    const forceWpa3 = six || draft.mlo;

    const security = sheetQuery('[data-wifi-draft="security"]');
    const pmf = sheetQuery('[data-wifi-draft="pmf"]');
    if (security) {
      security.disabled = forceWpa3;
      security.value = forceWpa3 ? 'wpa3-personal' : draft.security;
    }
    if (pmf) {
      pmf.disabled = forceWpa3;
      pmf.value = forceWpa3 ? 'required' : draft.pmf;
    }

    const syncTile = (path, disabled, detail) => {
      const tile = sheetQuery(`[data-wifi-draft-toggle-tile="${path}"]`);
      if (!tile) return;
      const input = tile.querySelector('input[type="checkbox"]');
      const checked = bool(getPath(draft, path));
      if (input) {
        input.disabled = disabled;
        input.checked = checked;
      }
      tile.classList.toggle('is-highlight', !disabled && checked);
      tile.style.opacity = disabled ? '0.4' : '';
      tile.style.pointerEvents = disabled ? 'none' : '';
      const copy = tile.querySelector('small');
      if (copy) copy.textContent = detail;
    };
    syncTile('mlo', !multiBand, multiBand ? '跨频段多路并发传输' : '至少需要选择两个频段');
    syncTile('fast_roaming', draft.mlo, '邻居报告 + BSS 引导 + FT 极速漫游');

    const ppsk = sheetQuery('[data-wifi-draft-toggle="ppsk"]');
    const ppskDisabled = six || draft.mlo || draft.security !== 'wpa2-personal';
    if (ppsk) ppsk.disabled = ppskDisabled;
    const radiusMacAuth = sheetQuery('[data-wifi-draft-toggle="radius_mac_auth"]');
    if (radiusMacAuth) radiusMacAuth.disabled = bool(draft.ppsk);

    const warningText = `${six ? '6 GHz' : 'MLO'} 要求 WPA3 与强制 PMF，保存时将按该组合提交。`;
    let warning = sheetQuery('.wifi-chamber.primary .wifi-inline-warning');
    if (forceWpa3 && !warning) {
      const primary = sheetQuery('.wifi-chamber.primary');
      if (primary) {
        warning = document.createElement('div');
        warning.className = 'wifi-inline-warning';
        warning.innerHTML = `${icon('info')}<span>${warningText}</span>`;
        primary.appendChild(warning);
      }
    } else if (!forceWpa3 && warning) {
      warning.remove();
    } else if (warning) {
      const copy = warning.querySelector('span');
      if (copy) copy.textContent = warningText;
    }

    const save = sheetQuery('[data-wifi-draft-save]');
    if (save) save.disabled = !canConfigWrite() || !String(draft.name || '').trim() || !bands.size;
  }

  function ssidSheet() {
    const draft = state.draft || defaultDraft();
    const isNew = !state.config.ssids.some((ssid) => ssid.id === draft.id);
    const writeGate = configWriteGateNote();
    const six = draft.bands.includes('6g');
    const multiBand = draft.bands.length >= 2;
    const forceWpa3 = six || draft.mlo;
    const ppskDisabled = six || draft.mlo || draft.security !== 'wpa2-personal';
    const caps = state.config.capabilities;
    const enterpriseOpen = state._enterpriseOpen;
    /* Chamber 1: 基础广播与凭据 — SSID / 频段 / 安全 */
    const chamberBasic = `<div class="wifi-chamber primary"><span class="wifi-chamber-label">基础广播与凭据</span>${sheetField('Wi-Fi 名称 (SSID)', 'name', draft.name, { wide: true, placeholder: '输入广播的 Wi-Fi 名称' })}<div class="wifi-band-pill-grid">${caps.bands.map((b) => bandPill(b, draft.bands.includes(b), !caps.bands.includes(b))).join('')}</div><div class="wifi-sheet-fields">${sheetField('安全加密协议', 'security', forceWpa3 ? 'wpa3-personal' : draft.security, { options: SECURITY.map(([value, label]) => [value, label]), disabled: forceWpa3 })}${sheetField('无线密码', 'password', '', { type: 'password', wide: true, placeholder: draft.password_present ? '已保存，留空保持不变' : '8-63 位字符' })}</div>${sheetField('PMF', 'pmf', forceWpa3 ? 'required' : draft.pmf, { options: [['disabled', '关闭'], ['optional', '可选'], ['required', '强制']], disabled: forceWpa3 })}${sheetField('Wi-Fi 协议', 'protocol', draft.protocol, { options: [['auto', '自动'], ['11n', 'Wi-Fi 4 / 802.11n'], ['11ac', 'Wi-Fi 5 / 802.11ac'], ['11ax', 'Wi-Fi 6 / 802.11ax'], ['11be', 'Wi-Fi 7 / 802.11be']] })}${sheetField('UCI 加密', 'encryption', draft.encryption, { options: [['sae+ccmp', 'sae+ccmp'], ['sae-mixed', 'sae-mixed'], ['psk2+ccmp', 'psk2+ccmp'], ['psk-mixed', 'psk-mixed'], ['none', 'none']] })}${forceWpa3 ? `<div class="wifi-inline-warning">${icon('info')}<span>${six ? '6 GHz' : 'MLO'} 要求 WPA3 与强制 PMF，保存时将按该组合提交。</span></div>` : ''}</div>`;
    /* Chamber 2: 接口与广播范围 */
    const chamberNetwork = `<div class="wifi-chamber"><span class="wifi-chamber-label">接口与广播范围</span><div class="wifi-sheet-fields">${sheetField('绑定网络接口', 'network', draft.network, { options: [['lan', 'LAN (主局域网)'], ['guest', '访客隔离网'], ['iot', 'IoT (智能家居网)']] })}${sheetField('广播 AP 节点', 'broadcast_mode', draft.broadcast_mode, { options: [['all', '全部 AP 节点 (全屋漫游)'], ['group', 'AP 组'], ['specific', '指定 AP']] })}${sheetField('VLAN ID', 'vlan', draft.vlan, { type: 'number', min: 1, max: 4094 })}</div></div>`;
    /* Chamber 3: 无缝漫游与 Wi-Fi 7 */
    const chamberRoaming = `<div class="wifi-chamber"><span class="wifi-chamber-label">无缝漫游与 Wi-Fi 7</span><div class="wifi-toggle-grid">${toggleTile('mlo', 'Wi-Fi 7 MLO 多链路聚合', multiBand ? '跨频段多路并发传输' : '至少需要选择两个频段', draft.mlo, !multiBand)}${toggleTile('fast_roaming', '802.11k/v/r 漫游套装', '邻居报告 + BSS 引导 + FT 极速漫游', draft.fast_roaming, draft.mlo)}${toggleTile('band_steering', '智能频段引导', '自动将支持设备推向 5G/6G 高频', draft.band_steering)}${toggleTile('hidden', '隐藏 Wi-Fi 名称', '不在 Beacon 广播帧中公开 SSID', draft.hidden)}</div><div class="wifi-settings-list">${draftToggle('ieee80211r', '802.11r Fast Transition', '启用 FT 漫游。')}${draftToggle('ieee80211k', '802.11k 邻居报告', '向终端提供候选 AP。')}${draftToggle('ieee80211v', '802.11v BSS Transition', '允许 AP 建议终端漫游。')}${draftToggle('ft_over_ds', 'FT over DS', '通过分布式系统完成 Fast Transition。')}${draftToggle('ft_psk_generate_local', '本地生成 FT PSK', '由本机生成 R0/R1 密钥材料。')}</div></div>`;
    /* Chamber 4: 空口优化与客户端控制 */
    const chamberAir = `<div class="wifi-chamber"><span class="wifi-chamber-label">空口优化与客户端控制</span><div class="wifi-toggle-grid">${toggleTile('isolate', '客户端设备隔离 (AP 隔离)', '阻止无线客户端之间互相通信', draft.isolate)}${toggleTile('multicast_enhance', '组播转单播优化', '将组播流量转为单播减少空口拥堵', draft.multicast_enhance)}${toggleTile('proxy_arp', 'Proxy ARP 广播代理', '由 AP 代答常见 ARP 广播降低唤醒', draft.proxy_arp)}${toggleTile('force_wifi4', '强制 Wi-Fi 4 (兼容旧 IoT)', '锁定旧协议保障老旧智能家居入网', draft.force_wifi4)}</div><div class="wifi-settings-list">${draftToggle('rrm', 'RRM', '启用无线资源测量。')}${draftToggle('qbssload', 'QBSS Load', '广播 BSS 负载。')}</div></div>`;
    /* Chamber 5: 进阶企业级参数 (折叠) */
    const chamberEnterprise = `<div class="wifi-enterprise-collapse"><div class="wifi-enterprise-header" data-wifi-enterprise-toggle><span>\u8fdb\u9636\u4f01\u4e1a\u7ea7\u53c2\u6570 (RADIUS / Mobility Domain)</span><span class="wifi-enterprise-toggle">${enterpriseOpen ? '\u6536\u8d77 \u2227' : '\u70b9\u51fb\u5c55\u5f00 \u2335'}</span></div><div class="wifi-enterprise-well ${enterpriseOpen ? 'is-open' : ''}"><div class="wifi-sheet-fields">${sheetField('Mobility Domain', 'mobility_domain', draft.mobility_domain, { placeholder: '4 \u4f4d\u5341\u516d\u8fdb\u5236' })}${sheetField('NAS ID', 'nasid', draft.nasid, { placeholder: '\u7559\u7a7a\u81ea\u52a8\u751f\u6210' })}${sheetField('\u91cd\u5173\u8054\u671f\u9650', 'reassociation_deadline', draft.reassociation_deadline, { type: 'number', min: 100, max: 20000 })}</div><div class="wifi-settings-list">${draftToggle('ppsk', '\u79c1\u6709\u9884\u5171\u4eab\u5bc6\u94a5', ppskDisabled ? '\u4ec5 WPA2 Personal \u4e14\u4e0d\u542b 6 GHz/MLO \u65f6\u53ef\u7528\u3002' : '\u4e0d\u540c\u5bc6\u7801\u53ef\u6620\u5c04\u5230\u4e0d\u540c\u7f51\u7edc\u6216 VLAN\u3002', ppskDisabled)}${draftToggle('radius_mac_auth', 'RADIUS MAC \u8ba4\u8bc1', '\u4f7f\u7528\u7ec8\u7aef MAC \u4f5c\u4e3a RADIUS \u51ed\u636e\u3002', draft.ppsk)}${draftToggle('schedule_enabled', 'Wi-Fi \u8ba1\u5212', '\u6307\u5b9a\u8be5 Wi-Fi \u505c\u6b62\u5e7f\u64ad\u7684\u65f6\u95f4\u3002')}</div><div class="wifi-sheet-fields">${sheetField('MAC \u5730\u5740\u7b5b\u9009', 'mac_filter', draft.mac_filter, { options: [['off', '\u5173\u95ed'], ['allow', '\u5141\u8bb8\u5217\u8868'], ['deny', '\u62d2\u7edd\u5217\u8868']] })}${sheetField('RADIUS Profile', 'radius_profile', draft.radius_profile, { placeholder: '\u672a\u914d\u7f6e' })}${sheetField('\u901f\u5ea6\u9650\u5236', 'speed_limit_id', draft.speed_limit_id, { options: state.config.speed_limits.map((limit) => [limit.id, limit.name]) })}${sheetField('\u8ba1\u5212', 'schedule', draft.schedule, { placeholder: '\u4f8b\u5982 \u5468\u4e00\u81f3\u5468\u4e94 08:00-20:00' })}</div></div></div>`;
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-wifi-sheet-close aria-label="关闭 Wi-Fi 编辑"></button><aside class="dwrt-kit-sheet wifi-sheet policy-stable-glass is-open" data-wifi-sheet-kind="ssid" aria-label="${isNew ? '新建 Wi-Fi' : '编辑 Wi-Fi'}"><header class="dwrt-kit-sheet-header"><div><strong>${isNew ? '新建 Wi-Fi' : '编辑 Wi-Fi'}</strong><small>${escapeHtml(draft.name || '配置无线广播')}</small></div><button class="dwrt-kit-sheet-close wifi-icon-button" type="button" data-wifi-sheet-close aria-label="关闭">${icon('close')}</button></header><div class="dwrt-kit-sheet-body wifi-sheet-body">${canConfigWrite() ? '' : `<div class="wifi-inline-warning">${icon('info')}<span>${escapeHtml(writeGate ? `当前无法保存 Wi-Fi 配置 —— ${writeGate}。可以查看和调整草稿，最终保存保持禁用。` : '当前设备没有可验证的 Wi-Fi 保存与应用能力。可以查看和调整草稿，最终保存保持禁用。')}</span></div>`}${chamberBasic}${chamberNetwork}${chamberRoaming}${chamberAir}${chamberEnterprise}<div class="wifi-chamber"><span class="wifi-chamber-label">备注</span><div class="wifi-sheet-fields">${sheetField('备注', 'remark', draft.remark, { wide: true })}</div></div></div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-wifi-sheet-close>取消</button><button class="policy-primary" type="button" data-wifi-draft-save ${canConfigWrite() && draft.name.trim() && draft.bands.length ? '' : 'disabled'}>保存 Wi-Fi</button></footer></aside>`;
  }

  function speedSheet() {
    const draft = state.draft || { id: `limit-${Date.now()}`, name: '', download_mbps: 0, upload_mbps: 0 };
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-wifi-sheet-close aria-label="关闭速度限制编辑"></button><aside class="dwrt-kit-sheet wifi-sheet compact policy-stable-glass is-open" aria-label="编辑速度限制"><header class="dwrt-kit-sheet-header"><div><strong>Wi-Fi 速度限制</strong><small>${escapeHtml(draft.name || '新建档案')}</small></div><button class="dwrt-kit-sheet-close wifi-icon-button" type="button" data-wifi-sheet-close aria-label="关闭">${icon('close')}</button></header><div class="dwrt-kit-sheet-body wifi-sheet-body"><section><div class="wifi-sheet-fields">${sheetField('名称', 'name', draft.name, { wide: true })}${sheetField('下载限制', 'download_mbps', draft.download_mbps, { type: 'number', min: 0, max: 100000, help: '0 表示无限制，单位 Mbps。' })}${sheetField('上传限制', 'upload_mbps', draft.upload_mbps, { type: 'number', min: 0, max: 100000, help: '0 表示无限制，单位 Mbps。' })}</div></section></div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-wifi-sheet-close>取消</button><button class="policy-primary" type="button" data-wifi-draft-save ${canConfigWrite() && draft.name.trim() ? '' : 'disabled'}>保存档案</button></footer></aside>`;
  }

  /*
   * AP 编辑抽屉。ap_update 的参数签名实测只有 ap_id / name / model_override，
   * 且 webd 会拒掉任何多余键（不是静默忽略），所以抽屉里也只放这两个字段。
   * 根节点写 dwrt-kit-sheet + 页面类并带 data-dwrt-component="sheet"，
   * 几何交给 Kit，不自建骨架（DESIGN 规则 19、21）。
   */
  function apSheet() {
    const editor = state.apEditor;
    if (!editor) return '';
    const overrideDisabled = !editor.override_supported;
    const dirty = editor.name !== editor.original_name || editor.model_override !== editor.original_model_override;
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-wifi-sheet-close aria-label="关闭 AP 编辑"></button><aside class="dwrt-kit-sheet wifi-sheet wifi-ap-sheet policy-stable-glass is-open" data-dwrt-component="sheet" aria-label="编辑 AP"><header class="dwrt-kit-sheet-header"><div><strong>编辑 AP</strong><small>${escapeHtml(editor.label)}</small></div><button class="dwrt-kit-sheet-close wifi-icon-button" type="button" data-wifi-sheet-close aria-label="关闭">${icon('close')}</button></header><div class="dwrt-kit-sheet-body wifi-sheet-body"><section><div class="wifi-sheet-fields">${sheetField('显示名', 'name', editor.name, { wide: true, help: '留空时列表按 型号 → 主板名 → AP ID 顺序回退显示。' })}${sheetField('型号覆盖', 'model_override', editor.model_override, { wide: true, disabled: overrideDisabled, help: overrideDisabled ? '该 AP 不支持型号覆盖。' : `留空则使用上报型号${editor.reported_model ? `（${editor.reported_model}）` : ''}。` })}</div></section><section class="wifi-ap-sheet-facts"><strong>只读信息</strong><dl><div><dt>AP ID</dt><dd><code>${escapeHtml(editor.ap_id)}</code></dd></div><div><dt>采纳状态</dt><dd>${escapeHtml(editor.adoption_state)}</dd></div><div><dt>主板名</dt><dd>${escapeHtml(editor.board_name || '--')}</dd></div><div><dt>型号来源</dt><dd>${escapeHtml(editor.model_source || '--')}</dd></div><div><dt>站点</dt><dd>${escapeHtml(editor.site_id || 'default')}</dd></div><div><dt>最后心跳</dt><dd>${escapeHtml(absoluteTime(editor.last_seen_at) || '--')}</dd></div></dl></section><div class="wifi-ap-sheet-note">仅显示名与型号覆盖可改，这两项只存在控制器清单里，不会下发到 AP。SSID、信道与重启类操作依赖尚未落地的事务层，因此不在此处提供。</div></div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-wifi-sheet-close>取消</button><button class="policy-primary" type="button" data-wifi-ap-save ${canEditAcAp() && dirty && !state.acBusy ? '' : 'disabled'}>${state.acBusy ? '正在保存' : '保存'}</button></footer></aside>`;
  }

  /*
   * 生成配对码抽屉。webd 侧校验 ttl_seconds 60~86400、max_attempts 1~10，
   * 前端同步用同一区间约束输入，避免拿一个模糊的 400 回来。
   *
   * 页面上那张「配对码」卡片按用户要求删掉了，它的三块内容全部收进这个抽屉：
   * 一次性码值（pairingSecretBlock）、已发出的记录与吊销（pairingTokenRecords）、
   * 以及生成表单本身。所以抽屉在生成成功后**不能关**，否则只显示一次的码值会跟着
   * 消失；createPairingToken() 因此保留 tokenDraft 并留在 'token' 上。
   */
  function tokenSheet() {
    const draft = state.tokenDraft;
    if (!draft) return '';
    const ttlValid = draft.ttl_seconds >= 60 && draft.ttl_seconds <= 86400;
    const attemptsValid = draft.max_attempts >= 1 && draft.max_attempts <= 10;
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-wifi-sheet-close aria-label="关闭配对码生成"></button><aside class="dwrt-kit-sheet wifi-sheet wifi-token-sheet policy-stable-glass is-open" data-dwrt-component="sheet" aria-label="临时配对码"><header class="dwrt-kit-sheet-header"><div><strong>临时配对码</strong><small>用于让一台新 AP 加入本控制器</small></div><button class="dwrt-kit-sheet-close wifi-icon-button" type="button" data-wifi-sheet-close aria-label="关闭">${icon('close')}</button></header><div class="dwrt-kit-sheet-body wifi-sheet-body">${pairingSecretBlock()}<section><div class="wifi-sheet-section-head"><strong>生成新的配对码</strong><small>码值只显示一次</small></div><div class="wifi-sheet-fields">${sheetField('有效期', 'ttl_seconds', draft.ttl_seconds, { type: 'number', min: 60, max: 86400, help: '单位秒，允许 60 ~ 86400（1 分钟 ~ 1 天）。' })}${sheetField('最大尝试次数', 'max_attempts', draft.max_attempts, { type: 'number', min: 1, max: 10, help: '允许 1 ~ 10 次。超过次数后该配对码失效。' })}${sheetField('站点', 'site_id', draft.site_id, { wide: true, help: '留空即 default 站点。' })}</div></section><div class="wifi-notice is-warn">${icon('info')}<span>生成配对码等于允许新设备接入本网络：它是一次性凭据，生成后只显示一次。请只把它交给你正在配对的那台 AP，用完或作废时及时吊销，不要转发或截图外发。</span></div>${pairingTokenRecords()}</div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-wifi-sheet-close>关闭</button><button class="policy-primary" type="button" data-wifi-token-save ${canManageTokens() && ttlValid && attemptsValid && !state.acBusy ? '' : 'disabled'}>${state.acBusy ? '正在生成' : '生成配对码'}</button></footer></aside>`;
  }

  /*
   * 吊销走 Kit 的统一确认弹窗（DESIGN 规则 17），不用原生 confirm。
   */
  function apConfirmationMarkup() {
    if (!state.confirmToken) return '';
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    if (typeof renderer !== 'function') return '';
    return renderer({
      id: 'wifi-pairing-token-revoke',
      action: 'revoke-pairing-token',
      tone: 'danger',
      title: '吊销配对码',
      description: `配对码 ${state.confirmToken.slice(0, 8)} 将立即失效，尚未完成配对的 AP 需要用新配对码重新配对。已完成配对的 AP 不受影响。`,
      cancelLabel: '取消',
      confirmLabel: state.acBusy ? '正在吊销' : '确认吊销',
      disabled: state.acBusy
    });
  }

  function discoveryConfirmationMarkup() {
    const candidate = state.discoveryCandidate;
    if (!candidate) return '';
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    if (typeof renderer !== 'function') return '';
    const name = discoveryCandidateLabel(candidate);
    const identity = firstText(candidate.key_id, candidate.ap_id, candidate.mac, '未提供');
    return renderer({
      id: 'wifi-discovery-adopt',
      action: 'adopt-discovered-ap',
      tone: 'warning',
      title: `绑定 ${name}`,
      description: `已发现但尚未验证。请核对设备指纹 ${identity}，确认后才会请求网关发起纳管；收到请求不代表已完成绑定。`,
      cancelLabel: '稍后处理',
      confirmLabel: state.discoveryBusy ? '正在请求' : '确认绑定',
      disabled: state.discoveryBusy
    });
  }

  function sheetMarkup() {
    if (state.sheet === 'ssid') return ssidSheet();
    if (state.sheet === 'speed') return speedSheet();
    if (state.sheet === 'ap') return apSheet();
    if (state.sheet === 'token') return tokenSheet();
    return '';
  }

  function statusToolbar() {
    const renderer = ui.sidebarTabsMarkup || window.DWRT_UI_KIT?.sidebarTabsMarkup;
    const views = [['radios', 'radio', '射频'], ['channel-ai', 'sparkles', '信道 AI'], ['connectivity', 'connectivity', '连接性'], ['environment', 'environment', '环境']];
    return `<header class="airview-topbar">${renderer({
      items: views.map(([value, glyph, label]) => ({ value, label, icon: glyph === 'sparkles' ? glyph : icon(glyph) })),
      value: state.statusView, label: '无线状态视图', className: 'airview-view-tabs', attribute: 'data-airview-view'
    })}</header>`;
  }

  function channelAiHelpers() {
    return { escapeHtml, icon, deviceImage, bandLabel, percentValue, metricValue, past24hCell };
  }

  async function loadChannelAi(plan = false) {
    const view = state.channelAi;
    if (!isStatus || view.loading || !state.mounted) return;
    const seq = ++view.seq;
    view.loading = true;
    view.error = '';
    patchStatusView();
    try {
      const data = await requestJson(`/api/v1/wifi/channel-ai/${plan ? 'plan' : 'status'}`, { cacheVersion: false });
      if (!state.mounted || seq !== view.seq) return;
      view.data = data;
      view.loaded = true;
    } catch (error) {
      if (!state.mounted || seq !== view.seq) return;
      view.data = null;
      view.loaded = true;
      view.error = error.status === 404 ? '当前设备尚未提供信道 AI 计划接口'
        : error.status === 401 ? '会话已失效，请重新登录'
          : `信道计划读取失败：${firstText(error.reason, error.message)}`;
    } finally {
      if (state.mounted && seq === view.seq) {
        view.loading = false;
        if (state.statusView === 'channel-ai') patchStatusView();
      }
    }
  }

  function patchStatusView() {
    const sidebar = root?.querySelector('.airview-sidebar-scroll');
    if (!sidebar) { render(); return; }
    const kit = window.DWRT_UI_KIT;
    const scrollTop = sidebar.scrollTop;
    const innerTop = sidebar.querySelector('.airview-channel-ai-sidebar')?.scrollTop || 0;
    const focusedBand = document.activeElement?.dataset?.channelAiBand;
    const disclosures = new Map(Array.from(sidebar.querySelectorAll('details')).map((node) => [node.querySelector('summary')?.textContent, node.open]));
    const template = document.createElement('template');
    template.innerHTML = airviewSidebar();
    kit?.unmount?.(sidebar);
    sidebar.replaceChildren(...template.content.querySelector('.airview-sidebar-scroll').childNodes);
    sidebar.querySelectorAll('details').forEach((node) => {
      const key = node.querySelector('summary')?.textContent;
      if (disclosures.has(key)) node.open = disclosures.get(key);
    });
    sidebar.scrollTop = scrollTop;
    const inner = sidebar.querySelector('.airview-channel-ai-sidebar');
    if (inner) inner.scrollTop = innerTop;
    (ui.mountAll || kit?.mountAll)?.(sidebar);
    if (focusedBand) sidebar.querySelector(`[data-channel-ai-band="${state.channelAi.band}"]`)?.focus({ preventScroll: true });
    patchLiveRegion();
  }

  function selectStatusView(view) {
    if (!['radios', 'channel-ai', 'connectivity', 'environment'].includes(view) || state.statusView === view) return;
    const results = root.querySelector('[data-airview-results]');
    const sidebar = root.querySelector('.airview-sidebar-scroll');
    state.statusViewOffsets.set(state.statusView, captureScrollOffsets(results));
    state.statusSidebarOffsets.set(state.statusView, {
      top: sidebar.scrollTop,
      innerTop: sidebar.querySelector('.airview-channel-ai-sidebar')?.scrollTop || 0,
      open: Array.from(sidebar.querySelectorAll('details')).map((node) => node.open)
    });
    state.statusView = view;
    patchStatusView();
    restoreScrollOffsets(results, state.statusViewOffsets.get(view) || []);
    const savedSidebar = state.statusSidebarOffsets.get(view);
    sidebar.scrollTop = savedSidebar?.top || 0;
    const inner = sidebar.querySelector('.airview-channel-ai-sidebar');
    if (inner) inner.scrollTop = savedSidebar?.innerTop || 0;
    sidebar.querySelectorAll('details').forEach((node, index) => { node.open = savedSidebar?.open[index] ?? true; });
    if (view === 'environment') loadEnvironmentHistory();
    if (view === 'connectivity') loadConnectivityEvents();
    if (view === 'channel-ai' && !state.channelAi.loaded) loadChannelAi();
  }

  function onStatusTabChange(event) {
    if (event.target.matches('.airview-view-tabs')) selectStatusView(event.detail.value);
  }

  function onChannelAiBandChange(event) {
    if (!event.target.matches('[data-channel-ai-bands]')) return;
    const band = event.detail.value;
    if (state.channelAi.band === band) return;
    state.channelAi.band = band;
    patchStatusView();
  }

  function filterCheckbox(group, value, label, checked = false, extra = '', disabled = false) {
    const text = String(label ?? '');
    const clipped = clipLabel(text);
    const title = clipped === text ? '' : ` title="${escapeHtml(text)}"`;
    return `<label class="airview-check ${disabled ? 'is-disabled' : ''}"${title}><input type="checkbox" data-airview-filter="${escapeHtml(group)}" value="${escapeHtml(value)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}><i></i><span>${extra}<span class="airview-check-label">${escapeHtml(clipped)}</span></span></label>`;
  }

  function miniChannelPlan() {
    const stateFor = (band, channel) => {
      const radios = state.status.radios.filter((radio) => radio.band === band);
      if (radios.some((radio) => radio.channel === channel)) return 'using';
      if (radios.some((radio) => radio.excluded_channels.includes(channel))) return 'excluded';
      if (radios.some((radio) => radio.dfs_channels.includes(channel))) return 'dfs';
      if (radios.some((radio) => radio.unavailable_channels.includes(channel))) return 'unavailable';
      if (radios.some((radio) => radio.supported_channels.includes(channel))) return 'enabled';
      return 'unknown';
    };
    const definitions = [BANDS[0], BANDS[1], BANDS[2]];
    const hasPlan = state.status.radios.some((radio) => radio.supported_channels.length || radio.dfs_channels.length || radio.unavailable_channels.length || radio.excluded_channels.length);
    return `<div class="airview-mini-plan ${hasPlan ? '' : 'is-partial'}">${definitions.map((def) => {
      const band = def.band || def.id;
      return `<div><span>${escapeHtml(def.label)}</span><b>${def.channels.slice(0, band === '2g' ? 14 : 18).map((channel) => `<i class="is-${stateFor(band, channel)}" data-dwrt-tooltip="${escapeHtml(`${def.label} · 信道 ${channel} · ${stateFor(band, channel) === 'using' ? '使用中' : stateFor(band, channel) === 'enabled' ? '已启用' : stateFor(band, channel) === 'dfs' ? 'DFS' : stateFor(band, channel) === 'unavailable' ? '不可用' : stateFor(band, channel) === 'excluded' ? '已排除' : '状态未提供'}`)}"></i>`).join('')}</b></div>`;
    }).join('')}<small><i class="is-using"></i>使用中 <i class="is-enabled"></i>已启用 <i class="is-dfs"></i>DFS <i class="is-unavailable"></i>不可用 <i class="is-excluded"></i>已排除${hasPlan ? '' : ' · 其余状态未提供'}</small></div>`;
  }

  function apInventory() {
    const inventory = new Map(state.status.managedAps.map((ap) => [ap.id, ap]));
    state.status.radios.forEach((radio) => {
      const current = inventory.get(radio.ap_id) || {};
      inventory.set(radio.ap_id, {
        ...current,
        id: radio.ap_id,
        name: firstText(current.name, radio.ap),
        model: firstText(current.model, radio.model),
        online: current.online ?? radio.online,
        image_url: firstText(current.image_url, radio.image_url),
        image_available: current.image_available ?? radio.image_available,
        image_source: firstText(current.image_source, radio.image_source),
        image_model_match: firstText(current.image_model_match, radio.image_model_match)
      });
    });
    return Array.from(inventory.values());
  }

  function apRadios(apId) {
    return state.status.radios
      .filter((radio) => radio.ap_id === apId)
      .sort((left, right) => ({ '2g': 0, '5g': 1, '6g': 2 }[left.band] ?? 9) - ({ '2g': 0, '5g': 1, '6g': 2 }[right.band] ?? 9));
  }

  function broadcastInventory() {
    const broadcasts = new Map();
    state.status.ssids.forEach((ssid) => {
      const key = ssid.name;
      if (!broadcasts.has(key)) broadcasts.set(key, { id: key, name: ssid.name, radioIds: new Set(), apIds: new Set() });
      if (ssid.radio_id) broadcasts.get(key).radioIds.add(ssid.radio_id);
      if (ssid.ap_id) broadcasts.get(key).apIds.add(ssid.ap_id);
    });
    return Array.from(broadcasts.values());
  }

  const COLUMN_DEFS = {
    connectivity: [['client', '客户端'], ['event', '事件'], ['ap', 'AP'], ['result', '结果'], ['signal', '信号'], ['band', '频段'], ['broadcast', 'WiFi 广播'], ['time', '日期/时间']],
    environment: [['ap', 'AP'], ['name', 'WiFi 名称'], ['signal', '信号'], ['channel', '信道'], ['width', '信道宽度'], ['standard', '标准'], ['mac', 'MAC 地址'], ['security', '安全'], ['vendor', '供应商'], ['nearest', '最近的 AP']]
  };

  function columnEditor(view) {
    const definitions = COLUMN_DEFS[view] || [];
    const selected = state.columns[view];
    if (state.columnEditor !== view) return `<button type="button" class="wifi-link-button" data-airview-columns="${view}">自定义列</button>`;
    return `<section class="airview-column-editor"><h2>自定义列</h2><label class="airview-check"><input type="checkbox" data-airview-column-all="${view}" ${selected.size === definitions.length ? 'checked' : ''}><i></i><span>全部</span></label>${definitions.map(([key, label]) => filterCheckbox(`columns.${view}`, key, label, selected.has(key))).join('')}<footer><button type="button" class="wifi-link-button" data-airview-columns-reset="${view}" ${selected.size === definitions.length ? 'disabled' : ''}>恢复</button><button type="button" class="policy-primary compact" data-airview-columns-done>完成</button></footer></section>`;
  }

  function radioFiltersDefault() {
    const aps = new Set(state.status.radios.map((radio) => radio.ap_id).filter(Boolean));
    const bands = new Set(state.status.radios.map((radio) => radio.band).filter(Boolean));
    return !state.filters.ai && state.filters.broadcast === 'all'
      && state.filters.aps.size === aps.size && Array.from(aps).every((value) => state.filters.aps.has(value))
      && state.filters.bands.size === bands.size && Array.from(bands).every((value) => state.filters.bands.has(value))
      && !state.filters.mimo.size && !state.filters.types.size && !state.filters.status.size;
  }

  function selectedEnvironmentAp(aps = apInventory()) {
    return aps.find((ap) => ap.id === state.filters.environmentAp) || aps[0] || null;
  }

  function environmentBands() {
    const order = { '2g': 0, '5g': 1, '6g': 2 };
    const bands = new Set();
    const ap = selectedEnvironmentAp();
    apRadios(ap ? ap.id : '').forEach((radio) => { if (radio.band) bands.add(radio.band); });
    if (!bands.size) state.status.radios.forEach((radio) => { if (radio.band) bands.add(radio.band); });
    state.status.interference.forEach((row) => { const band = normalizeBand(row.band); if (band) bands.add(band); });
    return Array.from(bands).sort((left, right) => (order[left] ?? 9) - (order[right] ?? 9));
  }

  function selectedEnvironmentBand() {
    const bands = environmentBands();
    if (!bands.length) return '5g';
    if (state.filters.environmentBand && bands.includes(state.filters.environmentBand)) return state.filters.environmentBand;
    return bands.includes('5g') ? '5g' : bands[0];
  }

  function scanStateLabel(value) {
    return ({ creating: '正在创建', queued: '排队中', leased: '等待 AP', running: '扫描中', completed: '已完成', failed: '失败', cancelled: '已取消', expired: '已超时' })[value] || firstText(value, '等待状态');
  }

  function scanJobPayload(payload = {}) {
    if (payload.item && typeof payload.item === 'object') return payload.item;
    if (payload.job && typeof payload.job === 'object') return payload.job;
    return payload;
  }

  function scanJobsPanel() {
    const jobs = Array.from(state.scanJobs.values()).sort((left, right) => ({ '2g': 0, '5g': 1, '6g': 2 }[left.band] ?? 9) - ({ '2g': 0, '5g': 1, '6g': 2 }[right.band] ?? 9));
    if (!jobs.length) return '';
    return `<section class="airview-scan-jobs" data-airview-scan-jobs aria-live="polite"><header><strong>邻居扫描</strong><span>${jobs.filter((job) => ['completed', 'failed', 'cancelled', 'expired'].includes(job.state)).length} / ${jobs.length}</span></header>${jobs.map((job) => {
      const tone = job.state === 'completed' ? 'success' : ['failed', 'expired'].includes(job.state) ? 'error' : job.state === 'cancelled' ? 'warning' : 'progress';
      const detail = job.error ? environmentReason(job.error) : job.state === 'completed' ? `${firstNumber(job.result_count)} 个广播` : scanStateLabel(job.state);
      return `<div class="is-${tone}"><i aria-hidden="true"></i><span><strong>${escapeHtml(bandLabel(job.band))}</strong><small>${escapeHtml(detail)}</small></span><b>${escapeHtml(scanStateLabel(job.state))}</b></div>`;
    }).join('')}</section>`;
  }

  function signalRangeControl() {
    const minPct = ((state.filters.signalMin + 100) / 80 * 100).toFixed(2);
    const maxPct = ((state.filters.signalMax + 100) / 80 * 100).toFixed(2);
    return `<div class="airview-signal-range" style="--signal-min:${minPct}%;--signal-max:${maxPct}%"><div><span class="airview-signal-track" aria-hidden="true"></span><input class="is-min" type="range" min="-100" max="-20" value="${state.filters.signalMin}" data-airview-signal="min" aria-label="最低信号"><input class="is-max" type="range" min="-100" max="-20" value="${state.filters.signalMax}" data-airview-signal="max" aria-label="最高信号"></div><span>${state.filters.signalMin}</span><span>${state.filters.signalMax}</span></div>`;
  }

  function environmentApPicker(aps) {
    const selected = selectedEnvironmentAp(aps);
    const selectedId = selected?.id || '';
    return `<div class="airview-ap-picker"><label class="airview-ap-select dwrt-kit-field" data-dwrt-component="field">${selected ? deviceImage(selected, 'airview-filter-device-image') : `<span class="airview-filter-device-image is-fallback">${icon('radio')}</span>`}<select data-airview-environment-ap aria-label="选择 Access Point">${aps.map((ap) => `<option value="${escapeHtml(ap.id)}" ${selectedId === ap.id ? 'selected' : ''}>${escapeHtml(ap.name)}</option>`).join('')}</select><span class="airview-ap-chevron" aria-hidden="true">${icon('chevron')}</span></label><button class="airview-ap-insights" type="button" data-airview-ap-details="${escapeHtml(selectedId)}" aria-label="打开 ${escapeHtml(selected?.name || 'AP')} 详情" ${selected ? '' : 'disabled'}>${icon('insights')}</button></div>`;
  }

  function airviewSidebar() {
    const aps = apInventory();
    const broadcasts = broadcastInventory();
    let body = '';
    if (state.statusView === 'channel-ai') {
      body = channelAiSidebar(state.status, state.channelAi, channelAiHelpers());
    } else if (state.statusView === 'connectivity') {
      body = `<div class="airview-range-picker" role="group" aria-label="连接性时间范围">${[6, 12, 24, 48].map((hours) => `<button type="button" data-airview-connectivity-range="${hours}" aria-pressed="${state.filters.connectivityRange === hours}">${hours} 小时</button>`).join('')}</div><div class="airview-link-actions"><button type="button" class="wifi-link-button" data-airview-clear ${state.filters.connectivityRange === 48 ? 'disabled' : ''}>清除筛选条件</button>${columnEditor('connectivity')}</div>`;
    } else if (state.statusView === 'environment') {
      const scannerAvailable = bool(state.status.capabilities.scan_execution || state.status.capabilities.scan, false);
      /* 派发扫描是 JMX_RISK_MEDIUM，viewer 会拿 403。按 design.md 规则 21，
         置灰必须说明原因，而不是让用户点了才看到一句英文报错。 */
      const scanBlocked = !scannerAvailable
        ? firstText(radioMetricNote(state.status.capabilities.reasons?.scan_execution),
          '后端未开放扫描执行能力')
        : !canPerformMediumRisk() ? radioWriteGateCopy([])
          : !aps.length ? '没有可扫描的 AP' : '';
      const envBands = environmentBands();
      const activeEnvBand = selectedEnvironmentBand();
      const bandSegment = envBands.length ? `<div class="airview-band-segment" role="group" aria-label="频段">${envBands.map((band) => `<button type="button" data-airview-environment-band="${band}" aria-pressed="${activeEnvBand === band}">${escapeHtml(bandLabel(band))}</button>`).join('')}</div>` : '';
      body = `${environmentApPicker(aps)}${bandSegment}<button type="button" class="policy-primary compact airview-scan-button" data-airview-scan ${scanBlocked || state.scanning ? 'disabled' : ''} title="${escapeHtml(scanBlocked || '对所选 AP 逐频段派发一次邻居扫描；扫描期间客户端可能短暂断开')}">${icon('scan')}<span>${state.scanning ? '扫描任务执行中' : '扫描环境'}</span></button>${scanBlocked ? `<small class="airview-filter-empty">${escapeHtml(scanBlocked)}</small>` : ''}${scanJobsPanel()}<details open><summary>时间范围</summary><div class="airview-range-picker compact">${[['30m','30 分钟'],['1h','1 小时'],['1d','1 天'],['1w','1 周'],['1m','1 月']].map(([value, label]) => `<button type="button" data-airview-environment-range="${value}" aria-pressed="${state.filters.environmentRange === value}">${label}</button>`).join('')}</div></details><details open><summary>信道宽度</summary><div class="airview-filter-list two-columns">${[20,40,80,160,240].map((width) => filterCheckbox('environmentWidths', width, String(width), state.filters.environmentWidths.has(String(width)))).join('')}</div></details><details open><summary>信号</summary>${signalRangeControl()}</details><div class="airview-link-actions">${columnEditor('environment')}<button type="button" class="wifi-link-button" data-airview-clear>清除筛选条件</button></div>`;
    } else {
      body = `<label class="airview-broadcast-select dwrt-kit-field" data-dwrt-component="field">${icon('search')}<select data-airview-broadcast><option value="all">所有 WiFi 广播 (${broadcasts.length})</option>${broadcasts.map((broadcast) => `<option value="${escapeHtml(broadcast.id)}" ${state.filters.broadcast === broadcast.id ? 'selected' : ''}>${escapeHtml(broadcast.name)}</option>`).join('')}</select></label><details open><summary>Access Point</summary><div class="airview-filter-list">${aps.length ? aps.map((ap) => filterCheckbox('aps', ap.id, ap.name, state.filters.aps.has(ap.id), deviceImage(ap, 'airview-filter-device-image'))).join('') : '<small class="airview-filter-empty">未检测到 AP</small>'}</div></details><details open><summary>频段</summary><div class="airview-filter-list">${['2g', '5g', '6g'].map((band) => filterCheckbox('bands', band, bandLabel(band), state.filters.bands.has(band))).join('')}</div></details><details open><summary>信道计划</summary>${miniChannelPlan()}</details><details open><summary>MIMO</summary><div class="airview-filter-list">${['1x1', '2x2', '3x3', '4x4'].map((mimo) => filterCheckbox('mimo', mimo, mimo, state.filters.mimo.has(mimo))).join('')}</div></details><details open><summary>类型</summary><div class="airview-filter-list">${[['wired', '有线'], ['meshed', '已 Mesh']].map(([value, label]) => filterCheckbox('types', value, label, state.filters.types.has(value))).join('')}</div></details><details open><summary>状态</summary><div class="airview-filter-list">${[['online', '在线'], ['offline', '离线']].map(([value, label]) => filterCheckbox('status', value, label, state.filters.status.has(value))).join('')}</div></details><button type="button" class="wifi-link-button" data-airview-clear ${radioFiltersDefault() ? 'disabled' : ''}>清除筛选条件</button>`;
    }
    return `<aside class="airview-sidebar topology-control-panel policy-stable-glass">${statusToolbar()}<div class="airview-sidebar-scroll">${body}</div></aside>`;
  }

  function filteredRadios() {
    const filters = state.filters;
    const aps = apInventory();
    const bands = new Set(state.status.radios.map((radio) => radio.band).filter(Boolean));
    return state.status.radios.filter((radio) => {
      if (aps.length && !filters.aps.has(radio.ap_id)) return false;
      if (bands.size && !filters.bands.has(radio.band)) return false;
      if (filters.mimo.size && !filters.mimo.has(radio.mimo)) return false;
      if (filters.types.size && !filters.types.has(String(radio.type).toLowerCase())) return false;
      if (filters.status.size && !filters.status.has(radio.online ? 'online' : 'offline')) return false;
      if (filters.broadcast !== 'all') {
        const broadcast = broadcastInventory().find((item) => item.id === filters.broadcast);
        if (!broadcast || !broadcast.radioIds.has(radio.id)) return false;
      }
      return true;
    }).sort((left, right) => {
      const apOrder = left.ap.localeCompare(right.ap, 'zh-CN');
      if (apOrder) return apOrder;
      return ({ '2g': 0, '5g': 1, '6g': 2 }[left.band] ?? 9) - ({ '2g': 0, '5g': 1, '6g': 2 }[right.band] ?? 9);
    });
  }

  function connectivityResults() {
    const supported = bool(state.status.capabilities.connectivity_events || state.status.capabilities.roaming_history, false);
    const remote = state.connectivityEvents;
    const events = supported ? remote.items : state.status.connectivityEvents;
    if (!events.length) {
      let title = '连接性历史不可用';
      let detail = '后端尚未提供漫游、断开、重连和 AP 切换事件历史。';
      if (supported && remote.error) {
        title = '连接性历史读取失败';
        detail = remote.error;
      } else if (supported && remote.loading) {
        title = '正在读取事件';
        detail = '正在从事件存储读取所选时间范围。';
      } else if (supported) {
        title = '无事件';
        detail = '所选时间范围内没有观测到连接、断开或漫游事件。事件来自周期快照差分 (ac_snapshot_diff)。';
      }
      return `<div class="airview-connectivity-empty"><strong>${title}</strong><span>${escapeHtml(detail)}</span></div>`;
    }
    const columns = state.columns.connectivity;
    const value = (event, key) => ({
      client: escapeHtml(firstText(event.client, event.name, event.mac, '--')),
      event: escapeHtml(firstText(event.event, event.type, event.message, '--')),
      ap: escapeHtml(firstText(event.ap, event.ap_name, '--')),
      result: escapeHtml(connectivityResultLabel(event)),
      signal: escapeHtml(firstText(event.signal, event.rssi, '--')),
      band: escapeHtml(connectivityBandLabel(event)),
      broadcast: escapeHtml(firstText(event.wifi_broadcast, event.broadcast, event.ssid, event.wifi_name, '--')),
      time: escapeHtml(firstText(event.date_time, event.occurred_at, event.time, event.timestamp, '--'))
    })[key];
    const visible = COLUMN_DEFS.connectivity.filter(([key]) => columns.has(key));
    return `<div class="airview-radio-table policy-stable-glass"><div class="wifi-table-scroll"><table><thead><tr>${visible.map(([, label]) => `<th>${label}</th>`).join('')}</tr></thead><tbody>${events.map((event) => `<tr>${visible.map(([key]) => `<td>${value(event, key)}</td>`).join('')}</tr>`).join('')}</tbody></table></div></div>`;
  }

  /* 频段过去在 normalizeConnectivityEvent() 里定格：切到「连接性」tab 会单独触发
     一次事件加载，事件响应可能先于 /wifi/status 到达，那时 state.status.radios 还是
     空数组，band 被写成空串并永久留在行里（后续状态刷新不会回填已normalize的行）。
     改为渲染时按 radio_id 现算，匹配不到就退回显示 radio_id 原值，绝不留空格。
     ac_station_events 本身没有 band 列（ac_db.c:2585），radio_id 是唯一线索。 */
  function connectivityBandLabel(event = {}) {
    const radioId = firstText(event.radio_id, event.from_radio_id, '');
    /* 匹配交给 radioMatchesId()：radio.id 已是裸 local_id（`phy0r2`），endsWith(':'+id)
       在这一代永远不成立，phy 又因单 wiphy 多 radio 而在三个 Radio 上重复。 */
    const radio = state.status.radios.find((item) => item.ap_id === event.ap_id &&
      radioMatchesId(item, radioId));
    const band = normalizeBand(firstText(radio?.band, event.band));
    if (band) return bandLabel(band);
    return radioId || '--';
  }

  /* 「结果」在后端没有任何对应列：ac_station_events 只有 event/station_mac/...，
     产生器明确"只记录观测到的在场变化，不编造关联原因"（ac_db.c:3626）。所以这一列
     只能由事件类型陈述观测结论，措辞要和后端一样保守 —— 不写"成功/失败"，因为快照
     差分看不到协商结果。后端哪天真给了 result/outcome，就优先用它。 */
  const CONNECTIVITY_RESULT_COPY = {
    connect: '已观测到关联',
    disconnect: '已观测到离线',
    roam: '已观测到漫游切换'
  };

  function connectivityResultLabel(event = {}) {
    const explicit = firstText(event.result, event.outcome, event.status, '');
    if (explicit) return explicit;
    const kind = String(firstText(event.event_kind, event.event, event.type, '')).trim().toLowerCase();
    return CONNECTIVITY_RESULT_COPY[kind] ||
      ({ 连接: '已观测到关联', 断开: '已观测到离线', 漫游: '已观测到漫游切换' })[kind] || '--';
  }

  function environmentRows() {
    const band = selectedEnvironmentBand();
    return state.status.interference.filter((row) => {
      if (state.filters.environmentAp !== 'all' && firstText(row.ap_id, row.nearest_ap_id) !== state.filters.environmentAp) return false;
      if (band && normalizeBand(row.band) !== band) return false;
      const width = String(firstNumber(row.width, row.channel_width));
      if (state.filters.environmentWidths.size && !state.filters.environmentWidths.has(width)) return false;
      const signal = firstNumber(row.signal, row.rssi, -100);
      return signal >= state.filters.signalMin && signal <= state.filters.signalMax;
    });
  }

  function environmentReason(reason) {
    return ({
      available: '可用', scan_not_yet_run: '尚未执行扫描', no_samples: '当前范围没有历史样本',
      iw_survey_samples_stale_or_incomplete: 'Radio 已上报，但驱动未返回完整 Survey 数值',
      iw_survey_failed_or_unsupported: '驱动不支持 Survey 或读取失败',
      iw_survey_unsupported: '驱动不支持 Survey', survey_history_source_unavailable: '历史存储当前没有样本',
      iw_neighbor_scan_failed_or_unsupported: '驱动不支持邻居扫描或扫描失败', scan_job_create_failed: '扫描任务创建失败',
      iw_neighbor_scan_not_supported: '驱动不支持邻居扫描 (EOPNOTSUPP)',
      iw_neighbor_scan_interface_busy: '接口忙,驱动拒绝离开工作信道 (EBUSY)',
      iw_neighbor_scan_interface_down: '扫描接口未启用 (ENETDOWN)',
      iw_neighbor_scan_permission_denied: '驱动拒绝扫描权限 (EPERM)',
      iw_neighbor_scan_driver_rejected: '驱动拒绝扫描参数 (EINVAL)',
      iw_neighbor_scan_interface_missing: '扫描接口不存在 (ENODEV)',
      iw_neighbor_scan_timeout: '扫描命令执行超时',
      scan_job_id_missing: '后端未返回任务 ID', scan_job_status_failed: '扫描任务状态读取失败', scan_status_timeout: '扫描任务状态等待超时',
      neighbor_bssid_scan_producer_pending: '邻居扫描执行器未开放', spectral_fft_driver_producer_pending: '驱动未提供频谱 FFT',
      wifi_connectivity_event_store_pending: '连接事件存储尚未实现', wifi_roaming_event_store_pending: '漫游历史存储尚未实现',
      request_failed: '历史接口读取失败', not_loaded: '尚未读取',
      /* 后端在这一层还会发下面这些码。它们此前一个都不在表里，兜底就把裸英文
         标识符印进「环境数据状态」和频谱空态里 —— 实测印出来的是
         available_with_truncated_samples（design.md 规则 21：置灰/降级必须说明
         原因，而不是把内部码丢给用户）。 */
      available_with_truncated_samples: '可用，本次样本被截断',
      scan_result_limited: '结果条数达到上限，已截断',
      scan_output_limited: '扫描输出超出上限，已截断',
      scan_output_parse_partial: '部分扫描条目无法解析，已跳过',
      iw_neighbor_scan_parse_failed: '扫描输出无法解析',
      neighbor_scan_execution_failed: '邻居扫描执行失败',
      survey_scan_execution_failed: 'Survey 采集执行失败',
      radio_job_mode_unsupported: 'AP 不支持该扫描模式',
      controller_cancelled: '控制器已取消该任务',
      scan_job_queued: '扫描任务排队中', scan_job_delivery_pending: '等待下发到 AP',
      scan_job_running: '扫描执行中', scan_job_state_available: '扫描任务已结束',
      scan_job_control_plane_unavailable: 'AP 控制面当前不可用',
      ap_control_v2_scan_execution_unavailable: '当前没有可执行扫描的在线 AP',
      ap_control_v2_scan_dispatch_unavailable: '控制器未开放扫描下发',
      iw_binary_unavailable: 'AP 上没有 iw 工具',
      iw_dev_failed: '读取 AP 无线接口清单失败',
      iw_dev_timeout: '读取 AP 无线接口清单超时',
      iw_dev_output_limited: 'AP 无线接口清单输出超出上限',
      radio_not_scannable: '该 Radio 没有可用于扫描的接口',
      radio_id_invalid: 'Radio 标识不合法',
      radio_mapping_unavailable: 'Radio 无法对应到 AP 上的接口',
      radio_sysfs_mapping_unavailable: 'AP 上找不到该 Radio 的 sysfs 映射',
      allocation_failed: 'AP 侧内存不足',
      iw_survey_sample_unavailable: '本次未取得 Survey 样本',
      iw_survey_unavailable: '本次未取得 Survey 样本',
      iw_survey_timeout: 'Survey 命令执行超时',
      iw_survey_current_frequency_unavailable: '驱动未上报当前频点',
      iw_survey_current_frequency_missing: '驱动未上报当前频点',
      iw_survey_ap_interface_unavailable: '该 Radio 没有可读 Survey 的 AP 接口',
      iw_survey_interface_invalid: 'Survey 接口名不合法',
      iw_survey_value_invalid: 'Survey 数值不合法',
      iw_survey_active_time_missing: '驱动未上报信道活跃时间',
      iw_survey_busy_time_missing: '驱动未上报信道忙时',
      iw_survey_busy_exceeds_active: '驱动上报的忙时超过活跃时间',
      iw_survey_bss_receive_time_missing: '驱动未上报本 BSS 接收时间',
      iw_survey_bss_receive_time_inconsistent: '驱动上报的本 BSS 接收时间自相矛盾',
      iw_survey_allocation_failed: 'AP 侧内存不足',
      survey_history_empty: '所选范围内没有 Survey 样本',
      survey_history_warming_up: '历史采集中，样本不足',
      survey_history_radio_mapping_unavailable: '历史样本无法对应到该 Radio',
      channel_survey_history_store_pending: '历史存储尚未开放'
    })[reason] || (typeof reason === 'string' &&
      reason.indexOf('iw_neighbor_scan_command_failed_exit_') === 0
        ? '扫描命令失败 (exit ' +
          reason.replace('iw_neighbor_scan_command_failed_exit_', '') + ')'
        : firstText(reason, '状态未知'));
  }

  function environmentCapabilitySummary() {
    const environment = state.status.environment;
    const survey = environment.channelSurvey;
    const neighbor = environment.neighborScan;
    const spectral = environment.spectralFft;
    const history = state.environmentHistory;
    const item = (label, ready, value, reason) => `<div class="${ready ? 'is-ready' : ''}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(environmentReason(reason))}</small></div>`;
    return `<section class="airview-environment-status" aria-label="环境数据状态">${item('邻居扫描', bool(neighbor.sample_available, false), `${asArray(neighbor.samples).length} 个广播`, neighbor.reason)}${item('实时 Survey', bool(survey.supported, false), `${firstNumber(survey.fresh_sample_count)} / ${firstNumber(survey.sample_count)} 新鲜`, survey.reason)}${item('Survey 历史', history.points.length > 1, `${history.points.length} 个点`, history.error ? 'request_failed' : history.reason)}${item('频谱 FFT', bool(spectral.supported, false), `${asArray(spectral.samples).length} 个样本`, spectral.reason)}</section>`;
  }

  function surveyHistoryChart() {
    const samples = state.environmentHistory.points;
    const points = linePoints(samples, 900, 210);
    /* 见 surveyHistoryFreshnessNote()：空态要区分"没采过"和"采过但都过期了"。 */
    if (!points) {
      const history = state.environmentHistory;
      /* 三态分开：读取中 / 读取失败 / 后端如实回了空。前两种不能说成"没有数据"，
         那会把一次失败的请求渲染成一个确定的业务结论（design.md「Capability truth」
         第 3、4 条）。 */
      if (history.loading) {
        return `<div class="airview-environment-history-empty"><strong>正在读取信道利用率历史</strong><span>${escapeHtml('正在请求所选时间范围的 Survey 历史。')}</span></div>`;
      }
      if (history.error) {
        return `<div class="airview-environment-history-empty"><strong>信道利用率历史读取失败</strong><span>${escapeHtml(`${history.error}。请求未成功，不能据此判断有无历史数据。`)}</span></div>`;
      }
      const copy = historyReasonCopy(history.reason);
      const freshness = surveyHistoryFreshnessNote();
      return `<div class="airview-environment-history-empty"><strong>${escapeHtml(copy.title)}</strong><span>${escapeHtml(freshness ? `${copy.detail}${freshness}` : copy.detail)}</span></div>`;
    }
    return `<svg class="airview-environment-history-line" viewBox="0 0 900 210" preserveAspectRatio="none" aria-label="信道利用率历史"><polyline points="${points}"></polyline></svg>`;
  }

  function environmentBandRange(band) {
    return ({
      '2g': { min: 2400, max: 2496, ticks: [[2412, '1'], [2437, '6'], [2462, '11'], [2484, '14']] },
      '5g': { min: 5150, max: 5895, ticks: [[5180, '36'], [5260, '52'], [5320, '64'], [5500, '100'], [5580, '116'], [5660, '132'], [5745, '149'], [5825, '165']] },
      '6g': { min: 5925, max: 7125, ticks: [[5955, '1'], [6135, '37'], [6335, '77'], [6535, '117'], [6735, '157'], [6935, '197'], [7115, '233']] }
    })[band] || { min: 2400, max: 2496, ticks: [] };
  }

  function channelToFrequency(band, channel) {
    const ch = Number(channel);
    if (!ch) return 0;
    if (band === '2g') return ch === 14 ? 2484 : 2407 + ch * 5;
    if (band === '5g') return 5000 + ch * 5;
    if (band === '6g') return 5950 + ch * 5;
    return 0;
  }

  // Neighbor spectrum: each AP is a bell centred on its channel, width by its
  // bandwidth, peak at its RSSI. Mirrors UniFi's WiFi scanner spectrum chart.
  function environmentSpectrumChart(rows, band) {
    const W = 900, H = 232, padL = 4, padR = 4, padT = 6, padB = 4;
    const plotW = W - padL - padR;
    const plotH = H - padT - padB;
    const range = environmentBandRange(band);
    const span = Math.max(1, range.max - range.min);
    const fx = (freq) => padL + Math.min(1, Math.max(0, (freq - range.min) / span)) * plotW;
    const fy = (dbm) => padT + Math.min(1, Math.max(0, Math.abs(dbm) / 100)) * plotH;
    const baseY = padT + plotH;
    const bells = rows.map((row, index) => {
      const freq = firstNumber(row.frequency_mhz) || channelToFrequency(band, firstNumber(row.channel));
      if (!freq) return '';
      const width = firstNumber(row.width_mhz, row.width, row.channel_width) || 20;
      const signal = firstNumber(row.signal, row.rssi_dbm, row.rssi, -95);
      const cx = fx(freq);
      const half = Math.max(9, (width / span * plotW) / 2);
      const peakY = fy(signal);
      const left = cx - half;
      const right = cx + half;
      const path = `M ${left.toFixed(1)} ${baseY.toFixed(1)} C ${(left + half * 0.6).toFixed(1)} ${baseY.toFixed(1)} ${(cx - half * 0.4).toFixed(1)} ${peakY.toFixed(1)} ${cx.toFixed(1)} ${peakY.toFixed(1)} C ${(cx + half * 0.4).toFixed(1)} ${peakY.toFixed(1)} ${(right - half * 0.6).toFixed(1)} ${baseY.toFixed(1)} ${right.toFixed(1)} ${baseY.toFixed(1)} Z`;
      const tone = index % 6;
      const tip = `${firstText(row.ssid, row.name, '隐藏网络')} · 信道 ${firstText(row.channel, '--')} · ${width} MHz · ${signal} dBm`;
      return `<path class="airview-bell tone-${tone}" d="${path}" data-dwrt-tooltip="${escapeHtml(tip)}"></path>`;
    }).join('');
    return `<svg class="airview-environment-spectrum" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-label="邻居广播频谱">${bells}</svg>`;
  }

  function environmentResults() {
    const band = selectedEnvironmentBand();
    const range = environmentBandRange(band);
    const rows = environmentRows();
    const titleBand = bandLabel(band);
    const neighbor = state.status.environment.neighborScan;
    const columns = state.columns.environment;
    const cell = (row, key) => ({
      ap: escapeHtml(firstText(row.ap, row.ap_name, '--')),
      name: escapeHtml(firstText(row.ssid, row.name, '--')),
      signal: escapeHtml(firstText(row.signal, row.rssi, '--')),
      channel: escapeHtml(firstText(row.channel, '--')),
      width: escapeHtml(firstText(row.width, row.channel_width, '--')),
      standard: escapeHtml(firstText(row.standard, row.protocol, '--')),
      mac: escapeHtml(firstText(row.mac, row.bssid, '--')),
      security: escapeHtml(firstText(row.security, '--')),
      vendor: escapeHtml(firstText(row.vendor, '--')),
      nearest: escapeHtml(firstText(row.nearest_ap, row.ap, '--'))
    })[key];
    const visible = COLUMN_DEFS.environment.filter(([key]) => columns.has(key));
    const emptyText = bool(neighbor.execution_available, false) && neighbor.reason === 'scan_not_yet_run' ? '尚未执行邻居扫描，点击左侧“扫描环境”获取附近广播。' : environmentReason(neighbor.reason);
    const chartBody = rows.length
      ? environmentSpectrumChart(rows, band)
      : `<div class="airview-environment-history-empty"><strong>暂无可绘制的邻居广播</strong><span>${escapeHtml(emptyText)}</span></div>`;
    return `<section class="airview-spectrum-view"><header>环境 · ${escapeHtml(titleBand)}<small>${rows.length} 个邻居广播</small></header>${environmentCapabilitySummary()}<div class="airview-spectrum-chart" role="img" aria-label="${escapeHtml(`${titleBand} 邻居广播频谱`)}"><div class="airview-spectrum-y">${[-30,-45,-60,-75,-90].map((value) => `<span>${value}</span>`).join('')}</div><div class="airview-spectrum-grid"><i></i><i></i><i></i><i></i></div><span class="airview-spectrum-db">dBm</span>${chartBody}<div class="airview-spectrum-x">${range.ticks.map(([, label]) => `<span>${label}</span>`).join('')}</div><span class="airview-spectrum-channel">信道</span></div><div class="airview-spectrum-table wifi-table-scroll"><table><thead><tr>${visible.map(([, label]) => `<th>${label}</th>`).join('')}</tr></thead><tbody>${rows.map((row) => `<tr>${visible.map(([key]) => `<td>${cell(row, key)}</td>`).join('')}</tr>`).join('')}</tbody></table>${rows.length ? '' : `<div class="airview-spectrum-empty">${icon('info')}<span>${escapeHtml(emptyText)}</span></div>`}</div></section>`;
  }

  function selectedRadioEntries() {
    return state.status.radios.filter((radio) => state.selectedRadios.has(radio.id));
  }

  function radioWidths(radio) {
    const definition = BANDS.find((item) => (item.band || item.id) === radio.band);
    const values = radio.supported_widths.length ? radio.supported_widths : (definition?.widths || []);
    return Array.from(new Set([...values, radio.width].map(Number).filter(Boolean))).sort((left, right) => left - right);
  }

  function radioChannels(radio) {
    const definition = BANDS.find((item) => (item.band || item.id) === radio.band);
    const values = radio.supported_channels.length ? radio.supported_channels : (definition?.channels || []);
    return Array.from(new Set([...values, radio.channel].map(Number).filter(Boolean))).sort((left, right) => left - right);
  }

  function radioDraft(radio) {
    if (!state.radioDrafts.has(radio.id)) state.radioDrafts.set(radio.id, clone(radio));
    return state.radioDrafts.get(radio.id);
  }

  /* Radio 的写入面分两条腿，各自的判据来自自己的 scope，不互相顶替：

     受管 AP  write_scopes.managed_ap.transaction.supported + endpoint
              → POST /api/v1/wifi/transactions（candidate + digest）
     本机 phy write_scopes.local / 扁平 save_config+apply_config
              → PUT /api/v1/wifi/config + POST /apply

     31.250 实测 transaction.supported=true、endpoint=/api/v1/wifi/transactions、
     base_revision 随每次 apply 递增，而本机 local.supported=false
     (no_local_phy_detected)。之前这里 `radio_update && canConfigWrite()` 里的
     canConfigWrite() 读的是 status 页那份空 config，恒 false，于是整页写入被自锁
     成"未下发端点"。 */
  /* 后端为每条 Radio 标了归属：source=managed_ap / scope=remote 是受管 AP，
     其余（source=local / scope=local）是本机 phy。两者都缺时按有没有
     config_id + ap_id 判断，受管 AP 的行一定带 config_id（radio0/1/2）。 */
  function radioWriteScopeOf(radio = {}) {
    const source = firstText(radio.source, radio.scope).toLowerCase();
    if (source === 'managed_ap' || source === 'remote') return 'managed';
    if (source === 'local') return 'local';
    return firstText(radio.ap_id) && firstText(radio.config_id) ? 'managed' : 'local';
  }

  function canRadioWrite(radios = null) {
    const list = radios === null ? selectedRadioEntries() : asArray(radios);
    if (!canPerformMediumRisk()) return false;
    if (!list.length) return canConfigWrite('managed') || canConfigWrite('local');
    return list.every((radio) => {
      const scope = radioWriteScopeOf(radio);
      if (!canConfigWrite(scope)) return false;
      return scope !== 'managed' || managedApWritable(radio.ap_id);
    });
  }

  /* 能力位说的是"控制器开了写事务"，不是"这台 AP 现在收得下"。AC 还有一道逐目标
     闸门（ac_db.c 的 ac_wifi_tx_target_gate_locked）：last_seen_at 在 45 秒内、
     session_connected、control_protocol_version 为 3、write_capable 非 0，四条全中
     才受理。一笔事务里只要混进一个不合闸的目标，AC 会把**整笔**拒成
     target_write_capability_unavailable，连在线 AP 的那份改动一起退回。
     250 上离线的那台 stale AP 正是这种目标，所以它的控件必须真的置灰。
     write_capable 当前不在 /wifi/status 的 managed_aps 里，读不到时按未知处理、
     不预先封锁（design.md 规则 14：判据是布尔能力位，缺位不等于 false）。 */
  function managedApWritable(apId) {
    const ap = state.status.managedAps.find((entry) => entry.id === apId);
    if (!ap) return false;
    if (bool(ap.write_capable, true) === false) return false;
    if (bool(ap.session_connected, true) === false) return false;
    if (ap.control_protocol_version !== undefined && ap.control_protocol_version !== null &&
        firstNumber(ap.control_protocol_version) < 3) return false;
    return bool(ap.online, false) && bool(ap.stale, false) === false;
  }

  /* 逐目标闸门没过时的原因。按 AC 的判据逐条查，命中第一条就说这一条，
     不把四种成因折叠成一句"不具备写入能力"。 */
  function managedApGateReason(apId) {
    const ap = state.status.managedAps.find((entry) => entry.id === apId);
    if (!ap) return '该 AP 不在本次运行态快照里';
    if (bool(ap.write_capable, true) === false) return '控制器会话未声明该 AP 的写入能力';
    if (bool(ap.session_connected, true) === false) return '该 AP 与控制器的会话已断开';
    if (ap.control_protocol_version !== undefined && ap.control_protocol_version !== null &&
        firstNumber(ap.control_protocol_version) < 3) {
      return `该 AP 的控制协议为 v${firstNumber(ap.control_protocol_version)}，写事务需要 v3`;
    }
    if (bool(ap.stale, false)) return '该 AP 的运行态已过期，控制器不再受理写入';
    if (!bool(ap.online, false)) return '该 AP 当前离线';
    return '';
  }

  function updateRadioDrafts(band, path, value) {
    selectedRadioEntries().filter((radio) => radio.band === band).forEach((radio) => setPath(radioDraft(radio), path, value));
    state.radioDirty = true;
  }

  function setRadioSelection(id, selected) {
    const radio = state.status.radios.find((entry) => entry.id === id);
    if (!radio) return;
    if (selected) {
      state.selectedRadios.add(id);
      radioDraft(radio);
    } else {
      state.selectedRadios.delete(id);
      state.radioDrafts.delete(id);
    }
    state.selectedRadio = state.selectedRadios.values().next().value || '';
    if (!state.selectedRadios.size) state.radioDirty = false;
    render();
  }

  function closeRadioSheet() {
    state.selectedRadios.clear();
    state.radioDrafts.clear();
    state.selectedRadio = '';
    state.radioDirty = false;
    render();
  }

  /* 把 sheet 的草稿并回 state.config.radios，然后交给 saveConfig()。
     原来这里 PATCH radioUpdateEndpoint()，而该端点后端从未提供，
     helper 返回空串后函数直接 return —— 既不报错也不生效，正是
     "把 5GHz 调成 160MHz 没有任何反应"的来源。saveConfig() 里的
     PUT + apply 事务是真实存在的写入路径，并且自带写前重读、
     空 Radio 列表拒写与 readback 判定，所以复用而不是另起一套。 */
  function commitRadioDraftsToConfig() {
    let changed = 0;
    selectedRadioEntries().forEach((radio) => {
      const draft = state.radioDrafts.get(radio.id);
      if (!draft) return;
      const index = state.config.radios.findIndex((item) => item.id === radio.id);
      if (index < 0) return;
      const target = state.config.radios[index];
      ['channel', 'width', 'tx_power_mode', 'tx_power_custom',
       'min_rssi_enabled', 'min_rssi'].forEach((key) => {
        if (draft[key] === undefined) return;
        if (target[key] === draft[key]) return;
        target[key] = clone(draft[key]);
        changed += 1;
      });
    });
    return changed;
  }

  /* ── 受管 AP 的 Radio 写入 ────────────────────────────────────────

     受管 AP 的改动只有一条落地路径：POST /api/v1/wifi/transactions，
     body 恰好四个字段，多一个键就是 400。candidate 是一个 JSON **字符串**，
     section 名必须用 status 侧的 config_id（radio0/1/2），不是 local_id
     （phy0r0/r1/r2）—— 后者在 UCI 里不存在，AC 会以 candidate_section_invalid
     拒收。option 值一律是字符串。

     31.250 实测（transaction 6 次全部 state=applied、readback.match=true）：
     channel / htmode / txpower 三项可写并能真实回读，min_rssi 不在后端白名单
     （apd_config_executor.c 的 apd_config_option_allowlist），所以页面上不再
     提供那个控件。 */

  /* 频宽写入的是 htmode，不是裸数字：31.251 的三条 radio 分别跑 EHT20 /
     EHT160 / EHT320，UCI 只认带世代前缀的形态。世代取自当前运行的 htmode，
     取不到时按上报的制式推导 —— 凭频段猜会把 802.11be 的 40 MHz 写成 VHT40，
     那是一次静默降级。 */
  function radioHtmodeGeneration(radio = {}) {
    const prefix = firstText(radio.htmode).toUpperCase().replace(/[\d+-]+$/, '');
    if (['EHT', 'HE', 'VHT', 'HT'].includes(prefix)) return prefix;
    const standard = firstText(radio.standard).toLowerCase();
    if (standard.includes('be')) return 'EHT';
    if (standard.includes('ax')) return 'HE';
    if (standard.includes('ac')) return 'VHT';
    return 'HT';
  }

  function radioHtmodeForWidth(radio, width) {
    const value = Number(width);
    if (!Number.isFinite(value) || value <= 0) return '';
    return `${radioHtmodeGeneration(radio)}${value}`;
  }

  /* UCI 侧的当前值，用来算差异。channel 用 desired_channel（ACS 就是字面量
     'auto'），不用运行信道 —— 那会把 ACS 选中的信道钉死成固定信道。 */
  function radioCurrentOptions(radio = {}) {
    const mode = firstText(radio.tx_power_mode).toLowerCase();
    return {
      channel: firstText(radio.desired_channel, radio.channel_auto ? 'auto' : radio.channel),
      htmode: firstText(radio.htmode),
      txpower: mode === 'custom' ? firstText(optionalNumber(radio.tx_power_dbm, radio.tx_power)) : '0'
    };
  }

  function radioDraftOptions(radio = {}, draft = {}) {
    const auto = draft.channel_auto === true || String(draft.channel) === 'auto';
    const channel = auto ? 'auto' : firstText(positiveNumber(draft.channel));
    const mode = firstText(draft.tx_power_mode).toLowerCase();
    const custom = positiveNumber(draft.tx_power_custom, draft.tx_power_dbm, draft.tx_power);
    return {
      channel,
      htmode: radioHtmodeForWidth(radio, draft.width),
      txpower: mode === 'custom' && custom !== null ? String(Math.round(custom)) : '0'
    };
  }

  /* 只把真正变了的 option 放进 candidate。写一份没有差异的配置会白跑一次
     apply/readback，并且把 desired_revision 往前推一格。 */
  function radioChangedOptions(radio) {
    const draft = state.radioDrafts.get(radio.id);
    if (!draft) return {};
    const current = radioCurrentOptions(radio);
    const next = radioDraftOptions(radio, draft);
    const options = {};
    ['channel', 'htmode', 'txpower'].forEach((key) => {
      if (!next[key]) return;
      if (next[key] === current[key]) return;
      options[key] = next[key];
    });
    return options;
  }

  const TRANSACTION_ERROR_REASONS = {
    revision_conflict: '配置版本已被其他改动推进，请刷新页面后重试',
    revision_conflict_after_dispatch: '下发过程中配置版本被推进，部分目标可能已应用，请刷新核对',
    revision_exhausted: '控制器的配置版本号已用尽',
    candidate_digest_mismatch: '候选配置摘要校验失败',
    candidate_option_not_allowed: '后端写入白名单不接受其中一个配置项',
    candidate_option_secret_not_supported: '该配置项属于密钥类，写事务不接受',
    candidate_options_bounds: '一次提交的配置项超出后端上限',
    candidate_invalid: '候选配置格式不合法',
    candidate_section_invalid: '候选配置的 section 名不被控制器认可',
    candidate_format_invalid: '候选配置格式版本不被控制器认可',
    target_write_capability_unavailable: '目标 AP 当前不具备写入能力',
    target_invalid: '目标 AP 不合法',
    target_duplicate: '同一个 AP 被重复提交',
    distributed_all_or_nothing_unsupported: '跨多台 AP 的全成全败事务尚未支持',
    ap_offline: 'AP 离线，改动未下发',
    apd_restarted_during_execution: 'AP 侧在执行期间重启，改动已回滚',
    cancelled_by_apd: 'AP 侧取消了本次作业',
    database_error: '控制器数据库写入失败',
    invalid_request: '请求未通过控制器校验',
    transaction_status_timeout: '事务已受理但在等待窗口内没有到达终态，请刷新核对',
    mlo_requires_multiple_radios: 'MLO 需至少两个 Radio，当前组只有一个',
    mlo_ap_id_unavailable: '无法确定 AP 归属，MLO 改动未提交',
    mlo_config_id_unavailable: '无法确定 UCI 段名，MLO 改动未提交',
    mlo_section_ambiguous: '同名段名冲突，MLO 改动未提交',
    mlo_identity_unavailable: 'SSID 缺少名称、安全配置或网络，MLO 无法启用',
    mlo_ap_mode_required: '仅 AP 模式的接口可参与 MLO',
    mlo_credentials_differ: '参与 MLO 的接口密钥必须相同',
    mlo_password_change_not_supported: 'MLO 模式下不支持修改密码',
    mlo_credentials_unverified: '无法确认所有接口密钥一致',
    mlo_radio_binding_unavailable: '无法解析 Radio 绑定，MLO 改动未提交',
    mlo_restore_members_unavailable: '无法恢复 MLO 前的接口配置，关闭未执行',
    mlo_restore_member_missing: '恢复配置缺失原始接口，关闭未执行',
    mlo_restore_members_invalid: '存储的 MLO 配置记录无效',
    mlo_restore_members_ambiguous: '多条 MLO 接口同时启用，无法确定恢复目标',
    mlo_intent_conflict: '同一接口组的 MLO 意图冲突',
    mlo_candidate_sections_limit: '单次 MLO 改动超出段数上限',
    candidate_option_not_allowed: '后端写入白名单不接受其中一个配置项 (MLO 功能可能需要升级 AC 二进制)',
  };

  /* 403 的原文是 "forbidden: role 'viewer' cannot perform 'medium' risk action"。
     写事务是 JMX_RISK_MEDIUM，viewer 拿不到，这不是能力缺失也不是参数错误，
     必须说成权限而不是"后端未开放"。 */
  function writeErrorCopy(error) {
    if (error?.status === 403) return '当前账号权限不足：无线写入属于中风险操作，仅管理员或所有者可执行';
    if (error?.status === 401) return '会话已失效，请重新登录后再试';
    /* reason 比 error 具体：AC 发的是 error=capability_unavailable +
       reason=target_write_capability_unavailable，先查 reason 才能说清是哪一种。 */
    for (const key of [firstText(error?.reason), firstText(error?.code)]) {
      if (key && TRANSACTION_ERROR_REASONS[key]) return TRANSACTION_ERROR_REASONS[key];
    }
    /* 409 同时承载两件不同的事：conflict（版本被推进）与 capability_unavailable
       （AC 的逐目标闸门拒了某个 AP）。按状态码统一写成"版本已被推进"会把后者
       完全说错，实测就是这样把一个离线 AP 的问题报成了刷新页面能解决的冲突。
       reason 才是判据，先查它；查不到再按 error 码分。 */
    if (firstText(error?.code) === 'capability_unavailable') {
      return '控制器拒绝了本次写入：其中一个目标 AP 当前不接受写事务';
    }
    if (error?.status === 409) return '控制器拒绝了本次写入：配置版本已被推进，请刷新页面后重试';
    return firstText(error?.message, '未知错误');
  }

  function transactionTargetError(target = {}) {
    const code = firstText(target.error_code, target.job_error_code, target.reason);
    if (!code) return '';
    return TRANSACTION_ERROR_REASONS[code] || code;
  }

  function transactionBaseRevision() {
    const transaction = objectValue(writeScope('managed').transaction);
    const revision = optionalNumber(transaction.base_revision,
      writeCapabilities().wifi_desired_revision);
    return revision === null ? 0 : Math.max(0, Math.trunc(revision));
  }

  function transactionStatusUrl(transactionId) {
    const transaction = objectValue(writeScope('managed').transaction);
    const base = firstText(transaction.status_endpoint, '/api/v1/wifi/transactions/');
    return `${base}${base.endsWith('/') ? '' : '/'}${encodeURIComponent(transactionId)}`;
  }

  /* 受管 AP 的写事务是异步的：apply 立刻返回 pending，AC 派发到 APD、写 UCI、
     重载、再回读，实测 15~25 秒到 applied。轮询到终态才算写成功，直接拿
     apply 的 200 当成功就会在页面上报"已保存"而设备上什么都没变。 */
  async function waitTransaction(transactionId) {
    const terminal = new Set(['applied', 'failed', 'rolled_back', 'cancelled', 'expired']);
    const deadline = Date.now() + 90000;
    let last = {};
    while (Date.now() < deadline) {
      await new Promise((resolve) => { window.setTimeout(resolve, 2000); });
      if (!state.mounted) return last;
      last = await requestJson(transactionStatusUrl(transactionId), { cacheVersion: false });
      if (terminal.has(firstText(last.state).toLowerCase())) return last;
    }
    return { ...last, state: 'timeout' };
  }

  async function saveManagedRadioDrafts(radios) {
    const byAp = new Map();
    radios.forEach((radio) => {
      const options = radioChangedOptions(radio);
      if (!Object.keys(options).length) return;
      const section = firstText(radio.config_id);
      if (!firstText(radio.ap_id) || !section) return;
      /* 不合 AC 逐目标闸门的 AP 一律不入事务：混进去会让整笔被拒。 */
      if (!managedApWritable(radio.ap_id)) return;
      if (!byAp.has(radio.ap_id)) byAp.set(radio.ap_id, []);
      byAp.get(radio.ap_id).push({ section, options });
    });
    if (!byAp.size) return { changed: 0 };
    const endpoint = managedTransactionEndpoint();
    const batch = Date.now().toString(36);
    const targets = [];
    for (const [apId, sections] of byAp.entries()) {
      const digest = await candidateDigest(sections);
      targets.push({
        ap_id: apId,
        candidate: JSON.stringify({
          format: firstText(objectValue(writeScope('managed').transaction).candidate_format,
            'uci-wireless-candidate.v1'),
          candidate_digest: digest,
          sections
        }),
        candidate_digest: digest
      });
    }
    const created = await requestJson(endpoint, {
      cacheVersion: false,
      method: firstText(objectValue(writeScope('managed').transaction).method, 'POST'),
      body: JSON.stringify({
        idempotency_key: `web.radio.${batch}`,
        consistency: 'per_target',
        base_revision: transactionBaseRevision(),
        targets
      })
    });
    const transactionId = firstText(created.transaction_id, created.id);
    if (!transactionId) throw new Error('控制器受理了写事务但没有返回事务号');
    const status = await waitTransaction(transactionId);
    const state_ = firstText(status.state).toLowerCase();
    const targetStates = asArray(status.targets);
    const mismatched = targetStates.filter((target) => (
      target.readback && bool(target.readback.match, true) === false
    ));
    if (state_ !== 'applied') {
      const detail = targetStates.map(transactionTargetError).filter(Boolean).join('；');
      const error = new Error(detail || TRANSACTION_ERROR_REASONS[state_] ||
        (state_ === 'timeout' ? TRANSACTION_ERROR_REASONS.transaction_status_timeout
          : `事务终态为 ${state_ || '未知'}`));
      error.code = firstText(targetStates[0]?.error_code, state_);
      throw error;
    }
    return {
      changed: targets.length,
      sections: Array.from(byAp.values()).reduce((total, list) => total + list.length, 0),
      mismatched: mismatched.length
    };
  }


  /* 受管 AP 的 MLO 写入：通过 AC 写事务直接下发，不走本机 /api/v1/wifi/config。
     本机无 PHY 时 PUT 必定 400（no_phy_detected），MLO 改动须绕开这条路。 */
  async function applyManagedMloChange(enabled) {
    if (!managedWriteSupported() || !canPerformMediumRisk()) {
      state.error = 'MLO 写入不可用：受管 AP 写事务未就绪或权限不足';
      render();
      return;
    }
    state.saving = true;
    state.error = '';
    state.notice = '正在下发 MLO 改动…';
    state.noticeTone = 'warn';
    render();
    try {
      const rawSsids = state.rawConfig?.ssids || [];
      const rawRadios = state.rawConfig?.radios || [];
      const plan = buildManagedMloPlan({
        rawSsids, rawRadios,
        ssids: state.config.ssids,
        globalMlo: enabled
      });
      if (!plan.changed) {
        state.notice = 'MLO 设置没有变化，未提交。';
        state.noticeTone = 'ok';
        state.saving = false;
        render();
        return;
      }
      if (plan.warnings.length && plan.warnings.some((w) =>
        w.reason === 'mlo_credentials_unverified')) {
        state.notice = 'MLO 已启用，但无法确认所有接口密钥一致，请人工核对。';
        state.noticeTone = 'warn';
      }
      const targets = [];
      for (const target of plan.byAp) {
        const digest = await candidateDigest(target.sections);
        targets.push({
          ap_id: target.ap_id,
          candidate: JSON.stringify({
            format: firstText(
              objectValue(writeScope('managed').transaction).candidate_format,
              'uci-wireless-candidate.v1'),
            candidate_digest: digest,
            sections: target.sections
          }),
          candidate_digest: digest
        });
      }
      const endpoint = managedTransactionEndpoint();
      const batch = Date.now().toString(36);
      const created = await requestJson(endpoint, {
        cacheVersion: false,
        method: firstText(
          objectValue(writeScope('managed').transaction).method, 'POST'),
        body: JSON.stringify({
          idempotency_key: `web.mlo.${batch}`,
          consistency: 'per_target',
          base_revision: transactionBaseRevision(),
          targets
        })
      });
      const transactionId = firstText(created.transaction_id, created.id);
      if (!transactionId) throw new Error('控制器受理了写事务但没有返回事务号');
      const status = await waitTransaction(transactionId);
      const state_ = firstText(status.state).toLowerCase();
      const targetStates = asArray(status.targets);
      const mismatched = targetStates.filter((t) =>
        t.readback && bool(t.readback.match, true) === false);
      if (state_ !== 'applied') {
        const detail = targetStates.map(transactionTargetError).filter(Boolean).join('；');
        const error = new Error(detail || TRANSACTION_ERROR_REASONS[state_] ||
          (state_ === 'timeout' ? TRANSACTION_ERROR_REASONS.transaction_status_timeout
            : `事务终态为 ${state_ || '未知'}`));
        error.code = firstText(targetStates[0]?.error_code, state_);
        throw error;
      }
      state.notice = mismatched
        ? 'MLO 已下发，但有目标的回读不一致，请核对。'
        : `MLO 配置已${enabled ? '启用' : '关闭'}，AP 回读一致。`;
      state.noticeTone = mismatched ? 'warn' : 'ok';
    } catch (error) {
      state.error = operationFailure('MLO 配置保存失败', error);
      state.notice = '';
    } finally {
      state.saving = false;
      render();
    }
    if (!state.error) await load(true);
  }

  async function saveRadioDrafts(radios = null) {
    const list = radios === null ? selectedRadioEntries() : asArray(radios);
    if (!list.length || state.saving) return;
    if (!canRadioWrite(list)) return;
    const managed = list.filter((radio) => radioWriteScopeOf(radio) === 'managed');
    const local = list.filter((radio) => radioWriteScopeOf(radio) !== 'managed');
    const closeSheet = radios === null;
    const managedPending = managed.filter((radio) => Object.keys(radioChangedOptions(radio)).length);
    /* 草稿与当前 UCI 值一致时不要发事务：那会写一份没有差异的配置，白跑一次
       apply/readback 并把 desired_revision 推前一格。 */
    if (!managedPending.length && !local.length) {
      state.notice = '无线电设置没有变化，未提交。';
      state.noticeTone = 'ok';
      state.radioDirty = false;
      if (closeSheet) closeRadioSheet(); else render();
      return;
    }
    state.saving = true;
    state.error = '';
    state.notice = managedPending.length ? '正在下发无线电改动并等待 AP 回读…' : '';
    state.noticeTone = 'warn';
    render();
    try {
      let applied = 0;
      let mismatched = 0;
      if (managedPending.length) {
        const result = await saveManagedRadioDrafts(managedPending);
        applied += firstNumber(result.sections);
        mismatched += firstNumber(result.mismatched);
      }
      if (local.length && commitRadioDraftsToConfig()) {
        state.dirty = true;
        state.saving = false;
        await saveConfig();
        state.saving = true;
        if (state.error) return; // saveConfig already reported the same failed request.
      }
      state.notice = mismatched
        ? `已下发 ${applied} 项改动，但有 ${mismatched} 个目标的回读与候选配置不一致，请核对。`
        : `已应用 ${applied} 项无线电改动，AP 回读一致。`;
      state.noticeTone = mismatched ? 'warn' : 'ok';
      state.radioDirty = false;
      state.radioDrafts.clear();
      if (closeSheet) closeRadioSheet();
    } catch (error) {
      state.error = operationFailure('保存无线电设置失败', error);
      state.notice = '';
    } finally {
      state.saving = false;
      render();
    }
    /* 写成功后必须重读：base_revision 已经前进一格，沿用旧值发下一笔事务会被
       AC 以 revision_conflict 拒掉。 */
    if (!state.error) await load(true);
  }

  function commonRadioValue(radios, key, fallback = '') {
    const values = radios.map((radio) => getPath(radioDraft(radio), key, fallback));
    return values.every((value) => String(value) === String(values[0])) ? values[0] : '';
  }

  function linePoints(samples, width = 560, height = 118) {
    const values = samples.map((sample) => optionalNumber(sample.value, sample.channel, sample.utilization, sample.count, sample.y)).filter((value) => value !== null);
    if (values.length < 2) return '';
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = Math.max(1, max - min);
    return values.map((value, index) => `${(index / (values.length - 1) * width).toFixed(1)},${(height - ((value - min) / span * (height - 12)) - 6).toFixed(1)}`).join(' ');
  }

  function radioHistory(radio) {
    const points = linePoints(radio.channel_history);
    const historyAvailable = bool(state.status.capabilities.airview_history, false) && points;
    /* 空态的原因先读这个 Radio 自己的，再退到全局能力位。

       250 实测：能力位 airview_history=true、reasons.airview_history='available'，
       而六个 Radio 里只有三个在线的有 267 个点，三个 stale 的是 0 点 +
       history_24h_reason='survey_history_empty'。只读全局 reason 时这三个空图一律
       写成"暂无可绘制的信道历史 / 后端已声明历史能力可用"，把"这个 AP 掉线了所以没
       样本"说成了一个查不出所以然的空。 */
    const empty = historyReasonCopy(firstText(
      radio.past_24h_reason, radio.history_24h_reason,
      state.status.capabilities.reasons?.airview_history));
    return `<div class="airview-radio-history" role="img" aria-label="${escapeHtml(`${radio.ap} ${bandLabel(radio.band)} 信道历史`)}"><div class="airview-radio-chart-grid" aria-hidden="true"></div>${historyAvailable ? `<svg viewBox="0 0 560 118" preserveAspectRatio="none" aria-hidden="true"><polyline points="${points}"></polyline></svg>` : `<div class="airview-radio-chart-empty"><strong>${escapeHtml(empty.title)}</strong><span>${escapeHtml(empty.detail)}</span></div>`}<div class="airview-radio-chart-axis"><span>12 小时前</span><span>8 小时前</span><span>4 小时前</span><span>现在</span></div></div>`;
  }

  function signalDistribution(radio) {
    const buckets = [-90, -75, -60, -45, -30];
    const labels = ['≤ -76', '-75~-61', '-60~-46', '-45~-31', '≥ -30'];
    const ranges = ['低于 -75 dBm', '-75 至低于 -60 dBm', '-60 至低于 -45 dBm', '-45 至低于 -30 dBm', '-30 dBm 及以上'];
    const distribution = signalDistributionData(radio, buckets);
    const max = Math.max(1, ...distribution.counts);
    const empty = signalDistributionEmptyCopy(radio, distribution);
    return `<div class="airview-signal-distribution"><div class="airview-signal-scale" aria-hidden="true">${buckets.map((value, index) => `<span style="--signal-tone:${index}"></span>`).join('')}</div><div class="airview-signal-labels">${labels.map((value) => `<span>${value}</span>`).join('')}</div><div class="airview-signal-bars" aria-label="${escapeHtml(`${radio.ap} 活动客户端信号分布`)}">${distribution.available ? distribution.counts.map((count, index) => `<i style="--bar:${Math.max(3, count / max * 100).toFixed(1)}%;--signal-tone:${index}" data-dwrt-tooltip="${escapeHtml(`${ranges[index]}：${count} 个客户端`)}"></i>`).join('') : `<div class="airview-radio-chart-empty compact"><strong>${escapeHtml(empty.title)}</strong><span>${escapeHtml(empty.detail)}</span></div>`}</div>${distribution.available ? `<p class="airview-signal-caption">${escapeHtml(signalDistributionCoverageCopy(radio, distribution))}</p>` : ''}</div>`;
  }

  /* 功率模式只列后端上报的那几个（31.250 实测 supported_tx_power_modes
     = ['auto','custom']）。原来这里写死 auto/high/medium/low/custom/disabled，
     而写事务的 txpower 只有两种语义：0=自动（netifd 跑 iw phy set txpower auto）
     与固定 dBm 值，high/medium/low 在后端没有任何对应，点了只会被静默忽略
     （design.md 规则 10）。 */
  const TX_POWER_MODE_LABELS = { auto: '自动', custom: '自定义', disabled: '已禁用' };

  function radioTxPowerModes(radios) {
    const modes = Array.from(new Set(radios.flatMap((radio) => radio.supported_tx_power_modes || [])));
    return (modes.length ? modes : ['auto', 'custom'])
      .filter((mode) => TX_POWER_MODE_LABELS[mode])
      .map((mode) => [mode, TX_POWER_MODE_LABELS[mode]]);
  }

  function radioTxPowerCeiling(radios) {
    const values = radios.map((radio) => optionalNumber(
      radio.tx_power_limits_dbm?.max,
      radio.channel_catalog?.tx_power_range_dbm?.max
    )).filter((value) => value !== null);
    return values.length ? Math.max(...values) : 30;
  }

  function radioBandSheet(band, radios) {
    const writable = canRadioWrite(radios);
    const width = commonRadioValue(radios, 'width');
    const channelAuto = commonRadioValue(radios, 'channel_auto', false) === true;
    const channel = commonRadioValue(radios, 'channel');
    const powerMode = commonRadioValue(radios, 'tx_power_mode');
    const widths = Array.from(new Set(radios.flatMap(radioWidths))).sort((left, right) => left - right);
    const channels = Array.from(new Set(radios.flatMap(radioChannels))).sort((left, right) => left - right);
    const powerModes = radioTxPowerModes(radios);
    const ceiling = radioTxPowerCeiling(radios);
    const customPower = commonRadioValue(radios, 'tx_power_custom');
    const metricRadio = radios[0];
    /* 频宽写的是 htmode，所以这里顺手把将要写下去的值显示出来 —— 「80」在
       802.11be 上落地成 EHT80，操作者应当看得到写的是哪一个。 */
    const widthNote = writable && positiveNumber(width) !== null
      ? `将写入 htmode=${radioHtmodeForWidth(metricRadio, width)}`
      : '';
    return `<section class="airview-radio-sheet-band"><header><strong>${escapeHtml(bandLabel(band))}</strong></header><div class="airview-selected-aps">${radios.map((radio) => `<button type="button" data-airview-radio-remove="${escapeHtml(radio.id)}" aria-label="移除 ${escapeHtml(radio.ap)} ${escapeHtml(bandLabel(radio.band))}">${deviceImage(radio, 'airview-chip-device-image')}<span>${escapeHtml(radio.ap)}</span>${icon('close')}</button>`).join('')}</div><div class="airview-radio-controls"><fieldset><legend>信道宽度</legend><div class="airview-segmented">${widths.map((value) => `<button type="button" data-airview-radio-width="${escapeHtml(band)}:${value}" aria-pressed="${Number(width) === value}" ${writable ? '' : 'disabled'}>${value}</button>`).join('')}</div>${widthNote ? `<small>${escapeHtml(widthNote)}</small>` : ''}</fieldset><label class="dwrt-kit-field" data-dwrt-component="field"><span>信道</span><select data-airview-radio-channel="${escapeHtml(band)}" ${writable ? '' : 'disabled'}><option value="auto" ${channelAuto ? 'selected' : ''}>自动 (ACS)</option>${channels.map((value) => `<option value="${value}" ${!channelAuto && Number(channel) === value ? 'selected' : ''}>${value}</option>`).join('')}</select></label></div><fieldset class="airview-radio-power"><legend>发射功率 ${icon('info')}</legend><div class="airview-segmented wrap">${powerModes.map(([value, label]) => `<button type="button" data-airview-radio-power="${escapeHtml(band)}:${value}" aria-pressed="${powerMode === value}" ${writable ? '' : 'disabled'}>${label}</button>`).join('')}</div>${powerMode ? '' : `<small>${escapeHtml(radioTxPowerModeNote(metricRadio || {}))}${radios.length > 1 ? `；各频段实测 ${radios.map((radio) => (radio.tx_power === null ? '--' : `${radio.tx_power} dBm`)).join(' / ')}` : ''}</small>`}${powerMode === 'custom' ? `<label class="airview-custom-power"><span>自定义功率</span><input type="number" min="1" max="${ceiling}" value="${escapeHtml(firstText(customPower, optionalNumber(metricRadio?.tx_power), ''))}" data-airview-radio-custom-power="${escapeHtml(band)}" ${writable ? '' : 'disabled'}><b>dBm</b></label><small>监管上限 ${ceiling} dBm；自动模式由驱动按监管域取值。</small>` : ''}</fieldset><details class="airview-radio-metrics" open><summary>关键指标</summary><div class="airview-radio-metric-device"><span>${deviceImage(metricRadio, 'airview-metric-device-image')}<strong>${escapeHtml(metricRadio.ap)}</strong></span><button type="button" data-airview-copy="${escapeHtml(metricRadio.ap)}" aria-label="复制 AP 名称">${icon('copy')}</button></div><p>信道: ${escapeHtml(radioChannelText(metricRadio))} (${escapeHtml(radioWidthText(metricRadio))})</p>${radioHistory(metricRadio)}<h4>活动客户端分布</h4>${signalDistribution(metricRadio)}</details></section>`;
  }

  function radioSheet() {
    const radios = selectedRadioEntries();
    if (!radios.length || state.statusView !== 'radios') return '';
    const groups = new Map();
    radios.forEach((radio) => {
      if (!groups.has(radio.band)) groups.set(radio.band, []);
      groups.get(radio.band).push(radio);
    });
    const writable = canRadioWrite(radios);
    /* 可写时 radioWriteGateCopy() 返回空串，那句"修改与保存保持禁用"就不该出现。
       原来这里无条件拼那句话，于是后端把事务面放开之后，页面仍然自称禁用。 */
    const reason = radioWriteGateCopy(radios);
    const gate = writable || !reason ? '' : `<div class="wifi-inline-warning">${icon('info')}<span>${escapeHtml(reason)}。当前展示真实运行值，修改与保存保持禁用。</span></div>`;
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-airview-radio-sheet-close aria-label="关闭无线电设置"></button><aside class="dwrt-kit-sheet airview-radio-sheet policy-stable-glass is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" data-dwrt-sheet-motion="settled" aria-label="无线电设置"><header class="dwrt-kit-sheet-header"><div><strong>无线电设置</strong><span>${radios.length} 个 Radio</span></div><button class="dwrt-kit-sheet-close wifi-icon-button" type="button" data-airview-radio-sheet-close aria-label="关闭">${icon('close')}</button></header><div class="dwrt-kit-sheet-body airview-radio-sheet-body">${gate}${Array.from(groups.entries()).sort((left, right) => ({'2g':0,'5g':1,'6g':2}[left[0]] ?? 9) - ({'2g':0,'5g':1,'6g':2}[right[0]] ?? 9)).map(([band, entries]) => radioBandSheet(band, entries)).join('')}</div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-airview-radio-sheet-close ${state.saving ? 'disabled' : ''}>取消</button><button class="policy-primary" type="button" data-airview-radio-save ${writable && state.radioDirty && !state.saving ? '' : 'disabled'}>${state.saving ? '正在下发' : '应用更改'}</button></footer></aside>`;
  }

  /* 30.1 实测：tx_power_mode 为 null、tx_power_mode_reason =
     tx_power_mode_not_exposed_by_driver_or_uci，而 tx_power_dbm 是真实值
     （phy1/2/3 分别 28/27/24）。只写"未上报模式"会让人以为功率也读不到。 */
  function radioTxPowerModeNote(radio = {}) {
    const note = radioMetricNote(firstText(radio.tx_power_mode_reason, 'tx_power_mode_not_exposed_by_driver_or_uci'));
    const power = metricValue(radio.tx_power, 'dBm', 1);
    return power ? `${note}；当前驱动实测 ${power}` : note;
  }

  /* 置灰文案。**可写时必须返回空串** —— 调用处据此决定要不要挂那条警示。
     每个 scope 报自己的原因，不互相覆盖（design.md 规则 21）；就绪标记
     `available` 由 positiveReason() 滤掉，不会被当成拒绝原因印出来。 */
  function radioWriteGateCopy(radios = null) {
    const list = radios === null ? selectedRadioEntries() : asArray(radios);
    if (!canPerformMediumRisk()) {
      const role = sessionRole();
      const label = { viewer: '只读', 'ai-agent': 'AI 代理', operator: '操作员', user: '操作员' }[role] || role;
      return `当前账号为${label}角色，无线写入属于中风险操作，仅管理员或所有者可执行`;
    }
    const scopes = list.length
      ? Array.from(new Set(list.map(radioWriteScopeOf)))
      : ['managed', 'local'];
    const labels = { local: '本机', managed: '受管 AP' };
    const parts = scopes.filter((scope) => !canConfigWrite(scope)).map((scope) => {
      const detail = scope === 'managed'
        ? firstText(objectValue(writeScope('managed').transaction).reason,
            writeScope('managed').write_reason, writeCapabilities().reasons?.radio_update)
        : firstText(writeScope('local').reason,
            writeCapabilities().reasons?.save_config, writeCapabilities().reasons?.apply_config);
      const note = writeGateNote(detail);
      return `${labels[scope]}：${note || '后端未说明原因'}`;
    });
    /* 能力位放开之后仍可能写不了：AC 的逐目标闸门会拒掉离线或会话断开的 AP。
       那不是"能力缺失"，所以要按 AP 逐台说明，而不是让上面那句 scope 级原因兜着。 */
    list.filter((radio) => radioWriteScopeOf(radio) === 'managed' && canConfigWrite('managed'))
      .forEach((radio) => {
        const reason = managedApGateReason(radio.ap_id);
        if (!reason) return;
        const line = `${clipLabel(firstText(radio.ap, radio.ap_id))}：${reason}`;
        if (!parts.includes(line)) parts.push(line);
      });
    if (!parts.length) return '';
    return parts.length === 1 ? parts[0].replace(/^[^：]+：/, '') : parts.join('；');
  }

  function apSheetMetric(label, value, note = '') {
    return `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(firstText(value, '--'))}</strong>${note ? `<small class="airview-kpi-note">${escapeHtml(note)}</small>` : ''}</div>`;
  }

  /* 驱动没暴露某项时后端会原样透出自己的 reason。这些是正常状态，不是错误，
     所以只在数值缺失时以浅色附注呈现，不走警示样式。 */
  /* webd 的 capabilities.reasons.* 是双用途字段：能力为 false 时写拒绝原因，
     能力为 true 时写一个"就绪"标记 —— 30.1 上有 20 多个键的值就是字面量
     `available`（webd_wifi_aggregate.c:3548 起把六个写能力的 reason 统一填成
     它）。三个文案函数都以 `MAP[key] || key` 收尾，于是这个标记被原样打印成
     "后端原因：available"、"available。当前设置仅用于核对字段与依赖关系。"。
     标记不是理由：先滤掉正向标记，再决定要不要陈述原因。 */
  const POSITIVE_REASONS = new Set([
    'available', 'ok', 'ready', 'supported', 'enabled', 'active',
    'latest_neighbor_scan_available'
  ]);

  function positiveReason(reason) {
    return POSITIVE_REASONS.has(String(reason || '').trim().toLowerCase());
  }

  const RADIO_METRIC_REASONS = {
    iw_survey_unsupported: '驱动不支持信道调查',
    iw_survey_failed_or_unsupported: '驱动未响应信道调查',
    iw_survey_current_frequency_unavailable: '驱动未上报当前频点',
    iw_survey_unavailable: '本次未取得信道调查',
    channel_survey_not_reported: 'AP 未上报信道调查',
    channel_utilization_not_sampled: '未采样信道利用率',
    noise_floor_not_reported_by_driver: '驱动未上报噪声底',
    tx_power_mode_not_exposed_by_driver_or_uci: '驱动与配置均未提供功率模式',
    // The backend deliberately returns null plus a reason instead of 0 so the UI
    // can tell "no data yet" apart from "genuinely zero clients". These two codes
    // arrive on summary.station_count / summary.clients when the managed AP has
    // not reported recently, which read as an unexplained blank before.
    telemetry_stale: '数据已过期，等待 AP 上报',
    managed_aps_offline_stale_or_without_snapshot: '受管 AP 离线，指标待其上线后恢复',
    no_phy_detected: '本机无无线网卡，仅作为控制器',
    // 射频表「过去 24 小时」「平均信号」列的缺值原因。后端在 AP 在线且有实数据时
    // 也可能只缺其中一项（例如历史序列未采集），逐列说明比整页一句话准确。
    radio_history_not_collected: '未采集 24 小时历史',
    radio_history_not_reported: 'AP 未上报历史序列',
    /* 历史类 reason 也会出现在射频表的「过去 24 小时」列上（后端把 AP 级
       history_24h_reason 直接挂到 radio 上）。HISTORY_REASON_COPY 只服务图表空态，
       这张表查不到就会把裸英文码印进单元格，实测印出的就是 survey_history_empty。 */
    survey_history_empty: '所选范围内没有 Survey 样本',
    no_samples: '所选范围内没有样本',
    warming_up: '历史采集中，样本不足',
    survey_history_warming_up: '历史采集中，样本不足',
    insufficient_complete_numeric_points: '完整数值样本少于 2 个',
    survey_history_source_unavailable: '历史存储当前不可用',
    survey_history_radio_mapping_unavailable: '历史样本无法对应到该 Radio',
    no_associated_station_signal_samples: '该 Radio 暂无关联客户端',
    obss_utilization_not_reported: '驱动未上报 OBSS 干扰',
    apstats_failed_or_unsupported: 'apstats 未返回数据',
    station_metrics_not_reported: 'AP 未上报客户端信号',
    spatial_streams_not_reported: 'AP 未上报空间流',
    partial_runtime_sources: '部分运行态数据源缺失',
    ap_uplink_not_reported: 'AP 未上报上行方式',
    channel_exclusion_producer_pending: '信道排除清单尚未产出',
    // 站点清单/指标的 scope 原因。后端本来就把它们当"状态"发（station_count 为
    // null + reason），但这些码不在本表里，radioMetricNote() 的兜底会把裸英文标识
    // 符直接显示出来，用户读成了报错。逐条译出，并保留 local / managed_ap 的区分。
    local_station_source_not_authoritative: '本机未提供权威的客户端清单来源',
    local_station_metrics_not_authoritative: '本机未提供权威的客户端信号来源',
    local_station_metrics_partial: '本机客户端信号仅部分可用',
    station_source_not_reported: '后端未声明客户端来源',
    managed_ap_station_source_unavailable: '受管 AP 未提供客户端清单',
    managed_ap_station_metrics_unavailable: '受管 AP 未提供客户端信号',
    managed_ap_offline: '受管 AP 离线',
    phy_present_no_configured_radios_and_no_managed_ap: '本机有网卡但未配置 Radio，且无受管 AP',
    no_local_phy_and_no_managed_ap_runtime: '本机无网卡，且无受管 AP 运行态',
    no_configured_radios: '本机尚未配置 Radio',
    phy_present_no_configured_radios: '本机有网卡但未配置 Radio',
    // 发射功率与运行信道的读取原因（netconfig/018_nc_wifi.c）。
    tx_power_read_from_iw_dev_write_transaction_unavailable: '功率取自驱动运行值，写入事务尚未开放',
    tx_power_range_and_runtime_readback_unavailable: '驱动未提供功率范围与运行回读',
    iw_dev_unavailable: '本机缺少 iw 运行态工具',
    band_not_in_iw_dev_output: '驱动运行态未列出该频段',
    iw_runtime_station_mapping_available: '运行态客户端映射可用',
    // 30.1 的 runtime_radios 里没有 standard/wifi_standard 字段，邻居扫描的 standard
    // 是"别人的 BSS"，不能当本机 Radio 的制式，所以这里只声明未上报，不做推断。
    wifi_standard_not_reported: 'AP 未上报本机制式（不由邻居扫描推断）',
    apstats_radio_unavailable: 'apstats 未提供该 Radio 的空口统计',
    /* 250/251（W1700K，mac80211-nl80211 后端）盘上既没有 apstats 也没有 wlanconfig，
       只有 iw，所以厂商空口计数这一整块是真的取不到。webd 过去把这里的 reason 留成
       空串，页面上就是一张全是 "--" 的表加一句没有下文的空白。 */
    vendor_airtime_counters_not_collected: '本机未采集厂商空口计数（驱动只提供 iw Survey）',
    vendor_airtime_counters_incomplete: '厂商空口计数返回了但不完整',
    /* 空间流缺失有两种来源：Radio 自身没上报，和"只能从关联客户端推断而客户端没报"。
       后者是 phy0r1 的实际情况，混成一句会让人以为是同一个驱动缺陷。 */
    station_spatial_streams_not_reported: 'AP 未上报客户端空间流，无法据此推断 MIMO',
    iw_station_dump_no_station_samples: '本次 station dump 没有取到样本',
    station_extended_capabilities_not_reported: 'AP 未上报客户端扩展能力',
    fingerprint_model_not_found: '指纹库中没有匹配的机型',
    fingerprint_model_unresolved: '指纹未能定位到具体机型'
  };

  function radioMetricNote(reason) {
    const key = String(reason || '').trim();
    if (!key || positiveReason(key)) return '';
    return RADIO_METRIC_REASONS[key] || key;
  }

  /* 写入闸门的原因文案。置灰本身是对的（后端 save_config / apply_config 恒为 false），
     但 30.1 上两种原因**同时存在**、含义不同，只写一句"没有能力"看不出差别：
       no_local_phy_detected          本机没有无线网卡，配置无处落地
       managed_ap_transaction_pending 受管 AP 的写事务与 readback 尚未开放
     另外 reasons.radio_update 原先是裸码直出，用户看到的是英文标识符。
     依据：Acceptance-to-Front-wireless-avg-signal-and-stale-data-honesty.md 第 3 节。 */
  const WRITE_GATE_REASONS = {
    no_local_phy_detected: '本机未检测到无线网卡，本地 Wi-Fi 配置无处落地',
    managed_ap_transaction_pending: '受管 AP 的写入事务与配置回读尚未开放',
    no_phy_detected: '本机无无线网卡，仅作为控制器',
    regdomain_driver_channel_catalog_pending: '驱动尚未提供监管域信道表',
    capability_disabled: '后端已停用该写入能力',
    resource_crud_pending: '本机 SSID 生命周期接口尚未完成',
    local_wifi_rest_write_disabled: '生产环境未开放本机 Wi-Fi 写入接口',
    ssid_enabled_readback_pending: '后端尚不能确认广播已真实暂停或恢复',
    ssid_delete_rest_pending: '后端尚未提供本机 SSID 原子删除接口',
    /* 写事务面自己的原因码（webd_wifi_aggregate.c 的 transaction.reason）。 */
    no_managed_ap_adopted: '尚未采纳任何受管 AP',
    ac_did_not_publish_transaction_endpoint: '控制器未下发写事务端点',
    ac_did_not_publish_desired_revision: '控制器未下发配置版本号',
    ac_capability_not_reported: '控制器未上报该写入能力',
    ac_capability_unreachable: '控制器能力位读取失败，写入能力未确认',
    local_write_capability_reported_false: '后端将本机写入能力报为不可用',
    managed_ssid_rest_proxy_pending: '受管 AP 的 SSID 代理接口尚未开放',
    /* AC 自己的闸门码（ac_protocol.c 的 ac_capability 第四参）。能力为真时这几个
       键会被填成 `available` 而被 positiveReason() 滤掉；为假时必须有中文，否则
       裸码直出。 */
    no_online_ap_control_v3_write_session: '当前没有已连接且支持写事务的受管 AP',
    no_online_ap_control_v3_secret_session: '当前没有能执行密钥轮换的受管 AP',
    no_online_ap_control_session: '当前没有与控制器保持会话的受管 AP',
    phase3_reconciliation_pending: '离线改动排队功能尚未开放',
    controller_does_not_require_local_phy: '控制器不要求本机具备无线网卡',
    ap_not_adopted_or_radio_not_current: '该 AP 未被采纳，或这个 Radio 不在当前运行态里',
    target_write_capability_unavailable: '目标 AP 当前不具备接收写事务的会话',
    transaction_scope_not_supported: '该改动不在写事务的作用范围内'
  };

  function writeGateNote(reason) {
    const key = String(reason || '').trim();
    if (!key || positiveReason(key)) return '';
    return WRITE_GATE_REASONS[key] || key;
  }

  /* 置灰原因合并成一句。两个 scope 各有自己的 reason，30.1 是两者同时不可写，
     所以逐个列出而不是让其中一个覆盖另一个（design.md「Capability truth」第 15 条：
     一句笼统的说法不得盖住一批各不相同的原因）。 */
  function configWriteGateNote() {
    const access = window.DWRT_DATA_REGISTRY?.access('wifi.config', { capability: 'save_config', permission: 'wifi:write' });
    if (access && !access.allowed) return access.reason;
    const caps = state.config.capabilities;
    const scopes = caps.write_scopes && typeof caps.write_scopes === 'object' ? caps.write_scopes : {};
    const labels = { local: '本机', managed_ap: '受管 AP' };
    const parts = ['local', 'managed_ap']
      .filter((scope) => scopes[scope] && typeof scopes[scope] === 'object' && bool(scopes[scope].supported, false) !== true)
      .map((scope) => `${labels[scope]}：${writeGateNote(firstText(scopes[scope].reason, '后端未说明原因'))}`);
    if (parts.length) return parts.join('；');
    const flat = firstText(caps.reasons?.save_config, caps.reasons?.apply_config);
    return flat ? writeGateNote(flat) : '';
  }

  /* 历史类空态的标题 + 说明。「暂无」这个词把"从未采集"和"采集停了/样本已过保留期"
     说成同一件事，排查方向会被带偏（验收单 Acceptance-to-Front-wireless-avg-signal-
     and-stale-data-honesty.md 第 2 节）。后端 reason 已经把两者分开了：
       no_samples / survey_history_empty          查询窗口内一条都没有
       warming_up                                 只有 1 个点，画线还差一个
       insufficient_complete_numeric_points       有点但 complete 数值不足 2 个
       survey_history_source_unavailable          历史存储本身取不到
       survey_history_radio_mapping_unavailable    有样本但对不上这个 Radio
     所以标题按语义分档，而不是所有情况都写"暂无"。 */
  const HISTORY_REASON_COPY = {
    no_samples: { title: '尚未采集信道历史', detail: '所选时间范围内没有 Survey 样本落库。' },
    survey_history_empty: { title: '尚未采集信道历史', detail: '所选时间范围内没有 Survey 样本落库。' },
    warming_up: { title: '信道历史采集中', detail: '目前只有 1 个样本，至少需要 2 个才能连成曲线。' },
    /* webd 发的是带前缀的那一个（webd_wifi_aggregate.c 的 survey_history_warming_up），
       裸 warming_up 是 AC 自己的状态名。两个都要收录，否则前缀那一版会被当未知码直出。 */
    survey_history_warming_up: { title: '信道历史采集中', detail: '完整的数值样本还不足 2 个，暂时连不成曲线。' },
    radio_history_not_collected: { title: '尚未采集该 Radio 的历史', detail: '后端还没有为这个 Radio 落下 24 小时序列。' },
    radio_history_not_reported: { title: 'AP 未上报历史序列', detail: '这个 Radio 的历史由 AP 上报，本次快照里没有。' },
    insufficient_complete_numeric_points: { title: '信道历史样本不足', detail: '已有样本，但完整的数值点少于 2 个，还画不出曲线。' },
    survey_history_source_unavailable: { title: '历史存储当前不可用', detail: '后端未能读到 Survey 历史存储。' },
    survey_history_radio_mapping_unavailable: { title: '历史样本无法对应到该 Radio', detail: '存储里有样本，但没有一条能匹配这个 Radio。' },
    request_failed: { title: '信道历史读取失败', detail: '历史接口请求未成功，不能据此判断有无数据。' },
    not_loaded: { title: '尚未读取信道历史', detail: '本次还没有请求历史接口。' }
  };

  function historyReasonCopy(reason) {
    const key = String(reason || '').trim();
    if (HISTORY_REASON_COPY[key]) return HISTORY_REASON_COPY[key];
    /* 能力就绪标记不是"不可用"的理由。走到这里说明能力位是 true 而曲线仍画不出，
       只能陈述这一次响应里没有足够的点，不得把标记当故障码转述。 */
    if (positiveReason(key)) {
      return {
        title: '暂无可绘制的信道历史',
        detail: '后端已声明历史能力可用，但本次响应的样本点不足以连成曲线。'
      };
    }
    /* 未收录的 reason 原样陈述，不套用"暂无"，避免把未知状态说成确定的空。 */
    if (key) return { title: '信道历史当前不可用', detail: `后端原因：${key}` };
    return { title: '信道历史状态未确认', detail: '后端未给出原因，能力位读取可能失败。' };
  }

  /* 把"从未采集"与"采集过但样本已过窗口"分开的唯一依据。
     后端 ac_db_survey_history_json() 的 latest_received_at 只统计**查询窗口内**命中行的
     最大 last_received_at：窗口内一条都没有时它是 null。所以有值才能说"最近一次采集在
     N 前"；为 null 时只能说"这个范围内没有样本"，不得升级成"从未采集过"——窗口外是否还
     存着更老的数据，这次请求答不了，前端不替后端下结论。
     保留期由后端裁剪（ac_db.c: 细粒度桶 48h / 小时桶 31 天），不在前端推算。 */
  function surveyHistoryFreshnessNote() {
    const latest = firstNumber(state.environmentHistory.latest_received_at);
    if (!latest) return '';
    const relative = relativeSeconds(latest);
    return relative ? `最近一次采集在${relative}，已不在当前所选范围内。` : '';
  }

  /* RSSI 分布空态。原先无条件把 reasons.station_metrics 当作"为什么是空"打印出来，
     但 30.1 实测该 reason 是 `available`（能力就绪），于是空图下面写着"available"
     这个裸码——既不是中文，也把一个就绪信号说成了故障原因。三态要分开：
     能力 false 才陈述后端原因；能力 true 而分布为空时，空的原因是没有关联客户端
     或该 Radio 未上报分布，与能力无关。 */
  function signalDistributionData(radio, buckets = [-90, -75, -60, -45, -30]) {
    if (radio.clients === 0) return { available: false, source: 'none', counts: buckets.map(() => 0), sample_count: 0 };
    const samples = asArray(radio.signal_distribution);
    if (samples.length) {
      const counts = buckets.map((threshold, index) => {
        const matched = samples.find((item) => Number(item?.threshold ?? item?.rssi ?? item?.min) === threshold);
        const sample = matched ?? samples[index];
        return Math.max(0, firstNumber(
          typeof sample === 'number' ? sample : undefined,
          sample?.count,
          sample?.clients,
          sample?.value
        ));
      });
      return {
        available: true,
        source: 'server',
        counts,
        sample_count: counts.reduce((sum, count) => sum + count, 0)
      };
    }
    const derived = radio.derived_signal_distribution && typeof radio.derived_signal_distribution === 'object'
      ? radio.derived_signal_distribution
      : {};
    const counts = asArray(derived.counts).slice(0, buckets.length).map((count) => Math.max(0, firstNumber(count)));
    while (counts.length < buckets.length) counts.push(0);
    const sampleCount = firstNumber(derived.sample_count, counts.reduce((sum, count) => sum + count, 0));
    return {
      available: sampleCount > 0,
      source: sampleCount > 0 ? 'stations' : 'none',
      counts,
      sample_count: sampleCount,
      matched_station_count: firstNumber(derived.matched_station_count),
      missing_signal_count: firstNumber(derived.missing_signal_count),
      unmapped_station_count: firstNumber(derived.unmapped_station_count)
    };
  }

  function signalDistributionCoverageCopy(radio, distribution) {
    const expected = optionalNumber(radio.clients);
    const sampleCount = firstNumber(distribution.sample_count);
    const source = distribution.source === 'server' ? '后端分桶' : 'Station RSSI 派生';
    if (expected !== null && expected !== sampleCount) {
      return `${source}，覆盖 ${sampleCount}/${expected} 个在线客户端；未覆盖样本未计入图表。`;
    }
    return `${source}，共 ${sampleCount} 个有效样本。`;
  }

  function signalDistributionEmptyCopy(radio, distribution) {
    const caps = state.status.capabilities;
    const ready = bool(caps.station_metrics, false);
    const reason = firstText(caps.reasons?.station_metrics);
    if (!ready) {
      return {
        title: '客户端信号分布不可用',
        detail: radioMetricNote(reason) ? `后端原因：${radioMetricNote(reason)}` : '后端未声明 Station RSSI 采集能力。'
      };
    }
    if (radio.clients === 0) {
      return { title: '该 Radio 暂无关联客户端', detail: '没有关联客户端，因此没有 RSSI 样本可分布。' };
    }
    if (!distribution.available && radio.clients) {
      const matched = firstNumber(distribution.matched_station_count);
      const missing = firstNumber(distribution.missing_signal_count);
      const unmapped = firstNumber(distribution.unmapped_station_count);
      /* 三种成因分开陈述：①归属到了但驱动没给 RSSI；②本次快照里有客户端归属不到任何
         Radio（多半是该 VAP 没被 Radio 枚举出来）；③清单本身没带 signal_dbm。原文一律
         写成"没有能唯一映射到该 Radio 的有效 signal_dbm"，只有 ① 才成立。 */
      if (matched && missing) {
        return {
          title: '尚无可用 RSSI 样本',
          detail: `已归属到该 Radio 的 ${matched} 个客户端中有 ${missing} 个未上报 signal_dbm。`
        };
      }
      if (unmapped) {
        return {
          title: '客户端无法归属到该 Radio',
          detail: `本次快照有 ${unmapped} 个客户端未能唯一归属到任一 Radio（其接口名与 BSSID 都不在任何 Radio 的 VAP 清单里），因此该 Radio 的 ${radio.clients} 个在线客户端暂无分布样本。`
        };
      }
      return {
        title: '尚无可用 RSSI 样本',
        detail: `${radio.clients} 个客户端在线，但本次快照未随带可用于分桶的 signal_dbm。`
      };
    }
    return { title: '暂无客户端信号样本', detail: '本次快照没有可分桶的 RSSI 样本。' };
  }

  function apRadioStandard(radio) {
    const standard = firstText(radio.standard).toLowerCase().replace(/^802\.11/, '').replace(/^11/, '');
    if (!standard) return '--';
    if (standard.includes('be')) return 'WiFi 7';
    if (standard.includes('ax')) return 'WiFi 6';
    if (standard.includes('ac')) return 'WiFi 5';
    if (standard === 'n' || standard.includes('ng')) return 'WiFi 4';
    return firstText(radio.standard);
  }

  function apOverview(ap, radios) {
    const has6g = radios.some((radio) => radio.band === '6g');
    /* TX 重试时间序列：本函数下方那句"后端尚未提供 TX 重试时间序列"是**临时写死**的
       文案，不是能力位判定。核对过后端源码，`tx_retry_history` 在 jmxd/src 下 0 命中
       （只有瞬时值 retry_rate / retry_rate_pct，没有时间序列采集），所以此刻这句为真。
       但它不会随后端实现自动变化 —— 后端补上采集后必须改成读能力位：
         判据字段  state.status.capabilities.tx_retry_history（待后端定名）
         原因字段  state.status.capabilities.reasons?.tx_retry_history
       归属确认见 Acceptance-to-Backend-metricsd-uloop-stalled-kills-periodic-
       collectors.md，以及本页对应单 Acceptance-to-Front-wireless-avg-signal-and-
       stale-data-honesty.md 第 2 节。届时按 design.md「Capability truth and failure
       classification」第 4 条写三态，不要保留这句写死的否认。 */
    const broadcasts6g = state.status.ssids.filter((ssid) => ssid.ap_id === ap.id && ssid.enabled && ssid.bands.includes('6g'));
    const retryPoints = radios.flatMap((radio) => radio.tx_retry_history);
    return `<div class="airview-ap-sheet-stack"><section class="airview-ap-summary-card">${deviceImage(ap, 'airview-ap-sheet-image')}<div class="airview-ap-summary-copy"><strong>${escapeHtml(firstText(ap.model, ap.name))}</strong><span>${ap.connection ? `已连接到 ${escapeHtml(ap.connection)}` : '连接对象 --'}</span></div><div class="airview-ap-radio-list">${radios.map((radio) => `<div><strong>信道 ${escapeHtml(radioChannelText(radio))} <span>(${escapeHtml(bandLabel(radio.band))}, ${escapeHtml(radioWidthText(radio))})</span></strong><span>${escapeHtml(firstText(percentValue(optionalNumber(radio.interference, radio.avg_interference)), '--'))}</span><span>${escapeHtml(apRadioStandard(radio))}</span><span class="airview-ap-clients">${icon('connectivity')}${radio.clients === null ? '--' : radio.clients}</span></div>`).join('')}</div>${has6g && !broadcasts6g.length ? `<div class="airview-ap-warning">${icon('info')}<span>当前没有 Wi-Fi 广播使用 6 GHz Radio。</span></div>` : ''}<footer><button type="button" class="policy-secondary" disabled>端口管理器</button><button type="button" class="policy-secondary" disabled>AirView</button></footer></section><section class="airview-ap-chart-card"><header><strong>TX 重试</strong><span>${retryPoints.length ? `${retryPoints.length} 个样本` : '--'}</span></header>${retryPoints.length > 1 ? radioHistory({ ...radios[0], channel_history: retryPoints, ap: ap.name }) : `<div class="airview-ap-empty-chart"><span>${
          !bool(state.status.capabilities.tx_n_history, false)
            ? firstText(state.status.capabilities.reasons?.tx_n_history, '后端尚未提供 TX 重试时间序列')
            : '样本不足，等待更多数据'
        }</span></div>`}</section><section class="airview-ap-facts">${apSheetMetric('型号', ap.model)}${apSheetMetric('IP 地址', ap.ip)}${apSheetMetric('MAC 地址', ap.mac)}${apSheetMetric('设备版本', ap.version)}${apSheetMetric('运行时间', ap.uptime)}</section><section class="airview-ap-table-card"><header><strong>空中统计</strong><span>按 Radio</span></header><div class="wifi-table-scroll"><table class="dwrt-kit-table"><thead><tr><th>频段</th><th>Tx 包</th><th>Tx 字节</th><th>Rx 包</th><th>Rx 字节</th><th>重试</th><th>丢弃</th></tr></thead><tbody>${radios.map((radio) => `<tr><td>${escapeHtml(bandLabel(radio.band))}</td><td>${escapeHtml(firstText(radio.air_stats.tx_packets, '--'))}</td><td>${escapeHtml(firstText(radio.air_stats.tx_bytes, '--'))}</td><td>${escapeHtml(firstText(radio.air_stats.rx_packets, '--'))}</td><td>${escapeHtml(firstText(radio.air_stats.rx_bytes, '--'))}</td><td>${escapeHtml(firstText(radio.air_stats.retries, '--'))}</td><td>${escapeHtml(firstText(radio.air_stats.dropped, '--'))}</td></tr>`).join('')}</tbody></table></div></section><section class="airview-ap-facts">${apSheetMetric('Mesh 父级', ap.mesh_parent)}${apSheetMetric('AP 组', ap.ap_group)}</section></div>`;
  }

  function apInsights(ap, radios) {
    return `<div class="airview-ap-sheet-stack">${radios.map((radio) => `<section class="airview-ap-insight-card"><header><div>${deviceImage(ap, 'airview-metric-device-image')}<span><strong>${escapeHtml(bandLabel(radio.band))}</strong><small>信道 ${escapeHtml(radioChannelText(radio))} · ${escapeHtml(radioWidthText(radio))}</small></span></div><b>${radio.clients === null ? '--' : radio.clients} 客户端</b></header><h4>关键指标</h4><div class="airview-ap-kpis">${apSheetMetric('发射功率', radio.tx_power ? `${radio.tx_power} dBm` : '--')}${apSheetMetric('平均信号', metricValue(radio.avg_signal, 'dBm'), radio.avg_signal === null ? radioMetricNote(radio.avg_signal_reason) : '')}${apSheetMetric('利用率', percentValue(radio.utilization), radio.utilization === null ? radioMetricNote(radio.utilization_reason) : '')}${apSheetMetric('重试率', percentValue(radio.retry_rate))}</div><h4>历史</h4>${radioHistory(radio)}<h4>活动客户端 RSSI 分布</h4>${signalDistribution(radio)}<h4>统计</h4><div class="airview-ap-kpis">${apSheetMetric('噪声', metricValue(radio.noise, 'dBm', 1), radio.noise === null ? radioMetricNote(firstText(radio.noise_reason, 'noise_floor_not_reported_by_driver')) : '')}${apSheetMetric('平均干扰', percentValue(radio.avg_interference), radio.avg_interference === null ? radioMetricNote(firstText(radio.avg_interference_reason, radio.utilization_reason)) : '')}${apSheetMetric('OBSS 干扰', percentValue(radio.obss_utilization), radio.obss_utilization === null ? radioMetricNote(firstText(radio.obss_utilization_reason, 'obss_utilization_not_reported')) : '')}${apSheetMetric('自身占用', percentValue(radio.self_bss_utilization))}${apSheetMetric('Wi-Fi 标准', apRadioStandard(radio), apRadioStandard(radio) === '--' ? radioMetricNote(firstText(radio.standard_reason, 'wifi_standard_not_reported')) : '')}${apSheetMetric('MIMO', firstText(radio.mimo, '--'), radio.mimo ? '' : radioMetricNote(firstText(radio.mimo_reason, 'spatial_streams_not_reported')))}</div></section>`).join('')}</div>`;
  }

  /* ── txpower-mode UI ──────────────────────────────────────────────── */

  function txpowerModeSection(apId) {
    const tp = state.txpower;
    const has6g = state.status.radios.some((r) => r.ap_id === apId && r.band === '6g');
    if (!has6g) return '';

    if (tp.loading && tp.apId === apId) {
      return `<section class="airview-ap-settings-card"><h3>6 GHz 高功率模式</h3><div class="wifi-settings-list"><span>正在读取发射功率模式…</span></div></section>`;
    }

    const data = tp.data;
    const isCurrentAp = tp.apId === apId;
    const usable = isCurrentAp && txpowerCanUse(data);
    const mode = isCurrentAp && data ? firstText(data.mode, 'calibrated') : 'calibrated';
    const isRegulatory = mode === 'regulatory';
    const ceiling = isCurrentAp && data ? data.ceiling_6ghz_dbm : null;

    let disabledReason = '';
    if (isCurrentAp && data && data.ok === false) {
      disabledReason = txpowerReasonText(firstText(data.reason, 'unknown_error'));
    } else if (isCurrentAp && data && !usable) {
      disabledReason = txpowerReasonText(firstText(data.reason, ''));
      if (!disabledReason) disabledReason = '此设备不支持高功率模式';
    } else if (!isCurrentAp || !data) {
      disabledReason = '暂不可用';
    }

    const disabled = !usable || tp.busy;
    const ceilingText = ceiling != null ? `当前天花板 ${metricValue(ceiling, 'dBm')}` : '';

    let detail = '';
    if (disabled && disabledReason) {
      detail = disabledReason;
    } else if (isRegulatory) {
      detail = `高功率模式已开启${ceilingText ? ' · ' + ceilingText : ''}。重启后将自动恢复为校准模式。`;
    } else {
      detail = `使用出厂校准值${ceilingText ? ' · ' + ceilingText : ''}。开启后天花板将由 regdb 决定。`;
    }

    const switchHtml = `<label class="wifi-setting-row dwrt-kit-switch" data-dwrt-component="switch">` +
      `<span><strong>6 GHz 高功率模式</strong><small>${escapeHtml(detail)}</small></span>` +
      `<input type="checkbox" role="switch" data-txpower-toggle="${escapeHtml(apId)}"` +
      ` aria-label="6 GHz 高功率模式" ${isRegulatory ? 'checked' : ''} ${disabled ? 'disabled' : ''}></label>`;

    const errorBanner = tp.error ? `<div class="wifi-inline-warning">${icon('info')}<span>${escapeHtml(tp.error)}</span></div>` : '';

    return `<section class="airview-ap-settings-card"><h3>6 GHz 高功率模式</h3><div class="wifi-settings-list">${switchHtml}</div>${errorBanner}</section>`;
  }

  function txpowerConfirmDialog() {
    if (!state.txpower.confirmPending) return '';
    const renderer = ui.confirmationMarkup || window.DWRT_UI_KIT?.confirmationMarkup;
    if (typeof renderer !== 'function') return '';
    return renderer({
      id: 'wifi-txpower-confirm',
      action: 'txpower-regulatory-confirm',
      tone: 'danger',
      title: '开启 6 GHz 高功率模式',
      description: '高功率模式将超出出厂校准值，功放可能长期工作在非线性区，存在退化或损坏风险，高阶 MCS 速率可能反而下降。此设置重启后自动恢复为校准模式。',
      cancelLabel: '取消',
      confirmLabel: state.txpower.busy ? '正在设置' : '确认开启',
      disabled: state.txpower.busy
    });
  }

  /* AP 详情 · 设置。

     这里原本是一整块硬编码 disabled 的 demo 表单（28 个控件），外加一句
     "当前设置仅用于核对字段与依赖关系"。受管 AP 的写事务已经可用，所以
     信道 / 信道宽度 / 发射功率三项改成真控件，走 saveRadioDrafts()。

     被删掉的入口都是后端没有契约的：Mesh Connect、Mesh 父级、上行链路优先级、
     IP 配置、LED、替换设备/加载配置/更新固件/定位/重启/禁用/移除，以及最小
     RSSI（min_rssi 不在 apd_config_option_allowlist 里，写下去会被静默忽略）。
     按 design.md 规则 18，给不出操作就不摆入口；这些字段的事实值在「概览」页
     已经有陈述。AP 改名归 Wi-Fi 管理页的 AP 清单（PATCH /api/v1/ac/aps/{id}）。 */
  function apRadioDraftValue(radio, key, fallback = '') {
    const draft = state.radioDrafts.get(radio.id);
    return draft ? getPath(draft, key, fallback) : getPath(radio, key, fallback);
  }

  function apRadioSettingsCard(radio) {
    const writable = canRadioWrite([radio]);
    const width = apRadioDraftValue(radio, 'width');
    const auto = apRadioDraftValue(radio, 'channel_auto', false) === true;
    const channel = apRadioDraftValue(radio, 'channel');
    const mode = firstText(apRadioDraftValue(radio, 'tx_power_mode'));
    const widths = radioWidths(radio);
    const channels = radioChannels(radio);
    const modes = radioTxPowerModes([radio]);
    const ceiling = radioTxPowerCeiling([radio]);
    const custom = apRadioDraftValue(radio, 'tx_power_custom');
    const id = escapeHtml(radio.id);
    return `<section class="airview-ap-settings-card"><header><strong>${escapeHtml(bandLabel(radio.band))}</strong><small>${escapeHtml(firstText(radio.config_id, radio.local_id, 'Radio'))}</small></header><div class="wifi-sheet-fields"><label class="wifi-field dwrt-kit-field" data-dwrt-component="field"><span>信道宽度</span><select data-airview-ap-radio-width="${id}" ${writable ? '' : 'disabled'}>${widths.map((value) => `<option value="${value}" ${Number(width) === value ? 'selected' : ''}>${value} MHz</option>`).join('')}</select></label><label class="wifi-field dwrt-kit-field" data-dwrt-component="field"><span>信道</span><select data-airview-ap-radio-channel="${id}" ${writable ? '' : 'disabled'}><option value="auto" ${auto ? 'selected' : ''}>自动 (ACS)</option>${channels.map((value) => `<option value="${value}" ${!auto && Number(channel) === value ? 'selected' : ''}>${value}</option>`).join('')}</select></label><label class="wifi-field dwrt-kit-field" data-dwrt-component="field"><span>发射功率</span><select data-airview-ap-radio-power="${id}" ${writable ? '' : 'disabled'}>${modes.map(([value, label]) => `<option value="${value}" ${mode === value ? 'selected' : ''}>${label}</option>`).join('')}</select></label>${mode === 'custom' ? `<label class="wifi-field dwrt-kit-field" data-dwrt-component="field"><span>功率值 (dBm)</span><input type="number" min="1" max="${ceiling}" value="${escapeHtml(firstText(custom, optionalNumber(radio.tx_power), ''))}" data-airview-ap-radio-custom-power="${id}" ${writable ? '' : 'disabled'}></label>` : ''}</div><p class="airview-kpi-note">运行值：信道 ${escapeHtml(radioChannelText(radio))} · ${escapeHtml(radioWidthText(radio))} · ${escapeHtml(firstText(metricValue(radio.tx_power, 'dBm', 1), '--'))}${mode === 'auto' ? '（自动，由驱动按监管域取值）' : ''}</p></section>`;
  }

  function apSettings(ap, radios) {
    const writable = canRadioWrite(radios);
    const gate = radioWriteGateCopy(radios);
    const notice = writable || !gate
      ? ''
      : `<div class="wifi-inline-warning">${icon('info')}<span>${escapeHtml(gate)}。当前设置仅用于核对字段与依赖关系。</span></div>`;
    const dirty = radios.some((radio) => Object.keys(radioChangedOptions(radio)).length);
    return `<div class="airview-ap-sheet-stack">${notice}${radios.map(apRadioSettingsCard).join('')}${txpowerModeSection(ap.id)}<footer class="airview-ap-settings-footer"><button class="policy-secondary" type="button" data-airview-ap-radio-reset="${escapeHtml(ap.id)}" ${dirty && !state.saving ? '' : 'disabled'}>放弃改动</button><button class="policy-primary" type="button" data-airview-ap-radio-save="${escapeHtml(ap.id)}" ${writable && dirty && !state.saving ? '' : 'disabled'}>${state.saving ? '正在下发' : '应用更改'}</button></footer></div>`;
  }

  function apDetailsSheet() {
    if (!state.apSheetAp || state.statusView !== 'environment') return '';
    const ap = apInventory().find((entry) => entry.id === state.apSheetAp);
    if (!ap) return '';
    const radios = apRadios(ap.id);
    const tabs = [['overview', '概览', 'overview'], ['insights', '洞察', 'insights'], ['settings', '设置', 'settings']];
    const body = state.apSheetTab === 'settings' ? apSettings(ap, radios) : state.apSheetTab === 'insights' ? apInsights(ap, radios) : apOverview(ap, radios);
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-airview-ap-sheet-close aria-label="关闭 AP 详情"></button><aside class="dwrt-kit-sheet airview-ap-sheet policy-stable-glass is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" data-dwrt-sheet-motion="settled" aria-label="${escapeHtml(ap.name)}"><header class="dwrt-kit-sheet-header"><div><strong>${escapeHtml(ap.name)}</strong></div><button class="dwrt-kit-sheet-close wifi-icon-button" type="button" data-airview-ap-sheet-close aria-label="关闭">${icon('close')}</button></header><nav class="airview-ap-sheet-tabs" role="tablist" aria-label="AP 详情视图">${tabs.map(([id, label, iconName]) => `<button type="button" role="tab" data-airview-ap-tab="${id}" aria-selected="${state.apSheetTab === id}" aria-label="${label}">${icon(iconName)}<span>${label}</span></button>`).join('')}</nav><div class="dwrt-kit-sheet-body airview-ap-sheet-body">${body}</div></aside>`;
  }

  /* Radio 表的功率列。后端把「模式」和「读回值」分开发：tx_power_mode 是 UCI
     里的意图（auto / custom），tx_power_dbm 是 iw dev 的实测值。原来这一列
     模式优先，于是三行全印成 "auto"，把一列真实功率读数换成了一个配置词。 */
  function radioPowerCellText(radio) {
    const power = metricValue(radio.tx_power, 'dBm', 1);
    const mode = firstText(radio.tx_power_mode).toLowerCase();
    const label = TX_POWER_MODE_LABELS[mode] || '';
    if (power && label) return `${power} · ${label}`;
    return firstText(power, label, '--');
  }

  /* 「过去 24 小时」列。后端发的 history_24h 是 137 个 {timestamp,value} 点，
     原来它被塞进 firstText()，数组走 String() 之后整列印出 137 个
     "[object Object]"。序列已在 normalizeRadio() 里另存为 past_24h_points，
     这里画一条迷你曲线并把利用率区间写进 tooltip；无序列时才落到后端 reason。 */
  function past24hCell(radio) {
    const points = asArray(radio.past_24h_points);
    const values = points.map((point) => optionalNumber(point?.value, point?.utilization))
      .filter((value) => value !== null);
    if (values.length < 2) {
      const text = firstText(radio.past_24h);
      if (text) return escapeHtml(text);
      const note = radioMetricNote(firstText(radio.past_24h_reason,
        values.length ? 'radio_history_not_collected' : ''));
      return note
        ? `<span class="airview-cell-reason" data-dwrt-tooltip="${escapeHtml(note)}">--<small>${escapeHtml(note)}</small></span>`
        : '--';
    }
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = Math.max(1, max - min);
    const line = values.map((value, index) => (
      `${(index / (values.length - 1) * 72).toFixed(1)},${(18 - ((value - min) / span * 14) - 2).toFixed(1)}`
    )).join(' ');
    const tip = `${values.length} 个样本，利用率 ${percentValue(min)} ~ ${percentValue(max)}`;
    return `<span class="airview-cell-spark" data-dwrt-tooltip="${escapeHtml(tip)}"><svg viewBox="0 0 72 18" preserveAspectRatio="none" aria-hidden="true" focusable="false"><polyline points="${line}"></polyline></svg><small>${escapeHtml(percentValue(values[values.length - 1]) || '--')}</small></span>`;
  }

  function radioResults() {
    const radios = filteredRadios();
    if (state.statusView === 'channel-ai') return channelAiResults(state.status, state.channelAi, channelAiHelpers());
    if (state.statusView === 'connectivity') return connectivityResults();
    if (state.statusView === 'environment') return environmentResults();
    if (!radios.length) {
      /* 空列表有三种成因，先前混成一句"未检测到无线 Radio + 后端运行态：
         no_local_phy_or_managed_ap_runtime"。31.250 是纯控制器（本机 phy 0）
         带两台受管 AP，扫描期间 AP 离开工作信道、快照过了新鲜窗口，radios 就
         会短暂为空 —— 那不是"没有无线硬件"，说成那样会把人引去查网卡。 */
      const managedCount = firstNumber(state.status.summary?.managed_ap_count,
        state.status.managedAps.length);
      const localPhy = firstNumber(state.status.summary?.local_phy_count,
        state.status.summary?.phy_count);
      const filtered = Boolean(state.status.radios.length);
      const reason = firstText(state.status.runtime.reason,
        state.status.capabilities.runtime_reason);
      if (filtered) {
        return `<div class="airview-empty"><span>${icon('radio')}</span><strong>未找到匹配项</strong><small>调整左侧显示选项，或清除筛选条件查看全部 AP。</small><button type="button" class="wifi-link-button" data-airview-clear>重置筛选</button></div>`;
      }
      if (managedCount > 0) {
        const detail = state.scanning
          ? '扫描期间 AP 会离开工作信道，运行态快照可能短暂缺失；扫描结束后会自动恢复。'
          : firstText(radioMetricNote(reason), '受管 AP 本次快照没有上报 Radio 运行态。') ;
        return `<div class="airview-empty"><span>${icon('radio')}</span><strong>本次快照没有 Radio 运行态</strong><small>已采纳 ${managedCount} 台受管 AP${localPhy > 0 ? '' : '（本机无无线网卡，仅作控制器）'}。${escapeHtml(detail)}</small><button type="button" class="wifi-link-button" data-airview-refresh>重新读取</button></div>`;
      }
      return `<div class="airview-empty"><span>${icon('radio')}</span><strong>未检测到无线 Radio</strong><small>本机无无线网卡，也没有已采纳的受管 AP${reason ? `（后端运行态：${escapeHtml(radioMetricNote(reason) || reason)}）` : ''}。页面不会生成模拟 AP、客户端或频谱数据。</small></div>`;
    }
    const selectedVisible = radios.filter((radio) => state.selectedRadios.has(radio.id));
    /* 缺值的单元格显示后端 reason，而不是一个无从解释的 "--"。
       有值时保留数值，null 时才落到 reason，两者不互相覆盖。 */
    const metricCell = (value, reason) => {
      if (value !== null) return escapeHtml(value);
      const note = radioMetricNote(reason);
      return note ? `<span class="airview-cell-reason" data-dwrt-tooltip="${escapeHtml(note)}">--<small>${escapeHtml(note)}</small></span>` : '--';
    };
    return `<div class="airview-radio-table policy-stable-glass" data-dwrt-component="data-table"><div class="wifi-table-scroll"><table><thead><tr><th class="airview-select-column"><input type="checkbox" data-airview-radio-select-all ${selectedVisible.length === radios.length ? 'checked' : ''} aria-label="选择全部射频"></th><th>名称</th><th>频段</th><th>信道</th><th>信道宽度</th><th>Tx 功率</th><th>客户端</th><th>平均信号</th><th>过去 24 小时</th><th>平均干扰</th></tr></thead><tbody>${radios.map((radio) => `<tr data-airview-radio-row="${escapeHtml(radio.id)}" class="${state.selectedRadios.has(radio.id) ? 'is-selected' : ''}" tabindex="0"><td class="airview-select-column"><input type="checkbox" data-airview-radio-select="${escapeHtml(radio.id)}" ${state.selectedRadios.has(radio.id) ? 'checked' : ''} aria-label="选择 ${escapeHtml(radio.ap)} ${escapeHtml(bandLabel(radio.band))}"></td><td><span class="airview-ap-cell">${deviceImage(radio)}<span><strong${radio.ap !== clipLabel(radio.ap) ? ` title="${escapeHtml(radio.ap)}"` : ''}>${escapeHtml(clipLabel(radio.ap))}</strong>${radio.model && radio.model !== radio.ap ? `<small${radio.model !== clipLabel(radio.model) ? ` title="${escapeHtml(radio.model)}"` : ''}>${escapeHtml(clipLabel(radio.model))}</small>` : ''}</span></span></td><td>${escapeHtml(bandLabel(radio.band))}</td><td>${escapeHtml(radioChannelText(radio))}</td><td>${escapeHtml(radioWidthText(radio, ''))}</td><td>${escapeHtml(radioPowerCellText(radio))}</td><td>${radio.clients === null ? '--' : radio.clients}</td><td>${metricCell(metricValue(radio.avg_signal, 'dBm'), firstText(radio.avg_signal_reason, state.status.capabilities.reasons?.station_metrics))}</td><td>${past24hCell(radio)}</td><td>${metricCell(percentValue(radio.avg_interference), firstText(radio.avg_interference_reason, radio.utilization_reason))}</td></tr>`).join('')}</tbody></table></div></div>`;
  }

  /* Client, signal and 24h columns come back blank whenever the managed AP has
     not reported, which looked like the backend was missing the feature. The
     payload already says why, so the cause is stated once at the top instead of
     leaving the user to guess from a table full of dashes. Ordered most specific
     first: no local radio at all, then AP offline, then merely stale telemetry. */
  function telemetryNotice() {
    const summary = state.status.summary || {};
    const runtime = state.status.runtime || {};
    const managed = state.status.managedAps || [];
    const onlineCount = managed.filter((ap) => ap && ap.online).length;
    const noLocalPhy = Number(summary.phy_count) === 0 && !state.status.radios.length;
    const apOffline = managed.length > 0 && onlineCount === 0;
    const stale = summary.station_count === null || summary.clients === null;
    let text = '';
    if (noLocalPhy && !managed.length) text = radioMetricNote('no_phy_detected');
    else if (apOffline) text = radioMetricNote('managed_aps_offline_stale_or_without_snapshot');
    else if (stale) text = radioMetricNote(firstText(summary.station_count_reason, summary.clients_reason, 'telemetry_stale'));
    else if (runtime.available === false && runtime.reason) text = radioMetricNote(runtime.reason);
    if (!text) return '';
    return `<div class="wifi-notice is-warn" data-wifi-telemetry-notice>${icon('info')}<span>${escapeHtml(text)}</span></div>`;
  }

  function statusPage() {
    return `<div class="wifi-management-shell airview-shell">${state.error ? `<div class="wifi-notice is-error">${icon('info')}<span>${escapeHtml(state.error)}</span></div>` : ''}${state.notice ? `<div class="wifi-notice ${state.noticeTone ? `is-${state.noticeTone}` : ''}">${icon('info')}<span>${escapeHtml(state.notice)}</span></div>` : ''}${telemetryNotice()}<div class="airview-layout">${airviewSidebar()}<main class="airview-results" data-airview-results>${radioResults()}</main></div>${radioSheet()}${apDetailsSheet()}${txpowerConfirmDialog()}</div>`;
  }

  function render() {
    if (!root || !state.mounted) return;
    root.className = `route-preview route-workspace policy-table-route-host wifi-management-route-host ${isStatus ? 'wireless-status-route-host' : 'wifi-config-route-host'}`;
    /*
     * The SSID sheet is portaled under document.body by the Kit. Replacing the
     * route shell while it is open invalidates the Kit's home anchor, so even a
     * background render disposes and recreates the entire drawer. Its dynamic
     * controls update locally; keep both the route shell and sheet identities.
     */
    if (!isStatus && state.sheet === 'ssid' && sheetQuery('aside[data-wifi-sheet-kind="ssid"].is-open')) return;
    const sidebarTabs = root.querySelector('.airview-view-tabs');
    if (sidebarTabs) window.DWRT_UI_KIT?.unmount?.(sidebarTabs);
    root.innerHTML = isStatus ? statusPage() : configPage();
    if (typeof ui.mountAll === 'function') ui.mountAll(root);
    else window.DWRT_UI_KIT?.mountAll?.(root);
    keepActiveTabVisible();
    syncTableScrollHints();
    if (resultsResizeObserver) {
      resultsResizeObserver.disconnect();
      const results = root.querySelector('[data-airview-results]');
      if (results) resultsResizeObserver.observe(results);
    }
  }

  /*
   * Tab 条在窄屏是横向滚动容器（390px 下 scrollWidth 460 > clientWidth 366），
   * 而 render() 用 innerHTML 重建整条 nav，scrollLeft 会归零。于是用户滚过去点中
   * 最后一个 Tab，重绘后那个 Tab 又被推出可视区，看起来像点了个不存在的东西。
   * 只横向移动 nav 自己的 scrollLeft，不用 scrollIntoView（那会连带滚动祖先与页面）。
   */
  function keepActiveTabVisible() {
    const nav = root?.querySelector('.wifi-config-tabs');
    const active = nav?.querySelector('.dwrt-kit-tab.is-active');
    if (!nav || !active || nav.scrollWidth <= nav.clientWidth) return;
    const navBox = nav.getBoundingClientRect();
    const box = active.getBoundingClientRect();
    if (box.right > navBox.right) nav.scrollLeft += box.right - navBox.right;
    else if (box.left < navBox.left) nav.scrollLeft -= navBox.left - box.left;
  }

  // Scroll containers are keyed by their DOM path inside the results region so
  // the offsets survive an innerHTML swap that replaces every node identity.
  function scrollAnchorKey(node, boundary) {
    if (!node || node === boundary || !boundary.contains(node)) return '';
    const parts = [];
    let current = node;
    while (current && current !== boundary) {
      const parent = current.parentElement;
      if (!parent) return '';
      parts.push(String(Array.prototype.indexOf.call(parent.children, current)));
      current = parent;
    }
    return parts.reverse().join('.');
  }

  function nodeFromAnchorKey(key, boundary) {
    if (!key) return null;
    let current = boundary;
    for (const part of key.split('.')) {
      const index = Number(part);
      if (!current || !Number.isFinite(index)) return null;
      current = current.children[index];
    }
    return current || null;
  }

  function captureScrollOffsets(boundary) {
    const offsets = [];
    boundary.querySelectorAll('.wifi-table-scroll, [data-airview-scroll], [data-channel-ai-scroll]').forEach((node) => {
      if (!node.scrollLeft && !node.scrollTop) return;
      const key = scrollAnchorKey(node, boundary);
      if (key) offsets.push({ key, left: node.scrollLeft, top: node.scrollTop });
    });
    if (boundary.scrollLeft || boundary.scrollTop) offsets.push({ key: '', left: boundary.scrollLeft, top: boundary.scrollTop });
    return offsets;
  }

  function restoreScrollOffsets(boundary, offsets) {
    offsets.forEach(({ key, left, top }) => {
      const node = key ? nodeFromAnchorKey(key, boundary) : boundary;
      if (!node) return;
      if (left) node.scrollLeft = left;
      if (top) node.scrollTop = top;
    });
  }

  function patchLiveRegion() {
    if (!root || !state.mounted) return;
    if (isStatus) {
      const results = root.querySelector('[data-airview-results]');
      if (results && root.querySelector(`[data-airview-view="${state.statusView}"][aria-selected="true"]`)) {
        // The 5s live refresh rebuilds this subtree, which resets every scroll
        // offset inside it. Carry the offsets across the swap so a horizontal
        // scroll in the AP or radio table is not yanked back on the next tick.
        const offsets = captureScrollOffsets(results);
        const activeKey = scrollAnchorKey(document.activeElement, results);
        window.DWRT_UI_KIT?.unmount?.(results);
        results.innerHTML = radioResults();
        (ui.mountAll || window.DWRT_UI_KIT?.mountAll)?.(results);
        restoreScrollOffsets(results, offsets);
        syncTableScrollHints(results);
        if (activeKey) {
          const next = nodeFromAnchorKey(activeKey, results);
          if (next && typeof next.focus === 'function') next.focus({ preventScroll: true });
        }
      } else render();
      return;
    }
    patchSsidCard();
  }

  function patchSsidCard() {
    const current = root?.querySelector('[data-wifi-ssid-card]');
    if (!current) { render(); return; }
    const template = document.createElement('template');
    template.innerHTML = configTable();
    const next = template.content.firstElementChild;
    if (!next) return;
    current.replaceWith(next);
    if (typeof ui.mountAll === 'function') ui.mountAll(next);
    else window.DWRT_UI_KIT?.mountAll?.(next);
  }

  function markDirty(forceRender = false) {
    state.dirty = true;
    if (forceRender || !root.querySelector('[data-dwrt-savebar]')) render();
  }

  function openSsid(id = '') {
    const existing = state.config.ssids.find((ssid) => ssid.id === id);
    state.sheet = 'ssid';
    state.draft = existing ? clone(existing) : defaultDraft();
    render();
  }

  function openSpeed(id = '') {
    const existing = state.config.speed_limits.find((limit) => limit.id === id);
    state.sheet = 'speed';
    state.draft = existing ? clone(existing) : { id: `limit-${Date.now()}`, name: '', download_mbps: 0, upload_mbps: 0 };
    render();
  }

  function closeSheet() { state.sheet = ''; state.draft = null; state.apEditor = null; state.tokenDraft = null; render(); }

  function setSsidManagement(enabled) {
    state.ssidManage = Boolean(enabled);
    state.selectedSsids.clear();
    patchSsidCard();
  }

  function setSsidSelection(id, selected) {
    if (!state.ssidManage) return;
    /*
     * 选择必须整组进出。合并后一个名字在表里只有一行，若只勾中主成员，「暂停」就只
     * 停掉 2.4G 那一条 VAP —— 界面上这行看着已暂停，另外两个频段还在广播，而表里
     * 再没有第二行能说明这件事。
     */
    const group = ssidGroupFor(id);
    if (!group.length) return;
    group.forEach((ssid) => {
      if (selected) state.selectedSsids.add(ssid.id); else state.selectedSsids.delete(ssid.id);
    });
    patchSsidCard();
  }

  function setSelectedSsidsEnabled(enabled) {
    const selected = selectedSsidRows();
    if (!selected.length || !canSetSsidEnabled()) return;
    selected.forEach((ssid) => { ssid.enabled = enabled; });
    state.dirty = true;
    state.notice = `${selected.length} 个 Wi-Fi 已加入${enabled ? '恢复' : '暂停'}草稿，保存并应用后才会生效。`;
    state.noticeTone = 'warn';
    render();
  }

  async function deleteSelectedSsids() {
    const confirmation = state.confirmSsidDelete;
    const contract = ssidDeleteContract();
    const ids = asArray(confirmation?.ids).map((value) => {
      const id = String(value || '');
      return id.startsWith('local:ssid:') ? id.slice('local:ssid:'.length) : id;
    }).filter(Boolean);
    if (!ids.length || !contract.available || state.ssidBusy) return;
    state.ssidBusy = true;
    state.error = '';
    render();
    try {
      await requestJson(contract.endpoint, {
        cacheVersion: false,
        method: contract.method,
        body: JSON.stringify({ ssid_ids: ids })
      });
      // A delete changes the read model immediately, but the browser may still
      // hold the previous GET response.  Force a one-shot uncached read before
      // deciding whether the backend actually removed the rows.
      const payload = await requestJson(`${ENDPOINT}?after_delete=${Date.now()}`, { cacheVersion: false });
      const next = normalizeConfig(payload);
      const remaining = new Set(next.ssids.map((ssid) => ssid.id));
      const stale = ids.filter((id) => remaining.has(id));
      if (stale.length) throw new Error(`删除回读不一致：${stale.join(', ')}`);
      state.rawConfig = clone(payload);
      state.config = next;
      state.selectedSsids.clear();
      state.ssidManage = false;
      state.confirmSsidDelete = null;
      state.notice = `${ids.length} 个 Wi-Fi 已移除并通过配置回读。`;
      state.noticeTone = 'ok';
      state.dirty = false;
    } catch (error) {
      state.error = operationFailure('移除 Wi-Fi 失败', error);
      state.confirmSsidDelete = null;
    } finally {
      state.ssidBusy = false;
      if (state.mounted) render();
    }
  }

  function openApEditor(apId) {
    const ap = state.ac.aps.find((item) => item.ap_id === apId);
    if (!ap || !canEditAcAp()) return;
    state.sheet = 'ap';
    state.draft = null;
    state.apEditor = {
      ap_id: ap.ap_id, label: ap.label, name: ap.name, model_override: ap.model_override,
      original_name: ap.name, original_model_override: ap.model_override,
      override_supported: ap.override_supported, reported_model: ap.reported_model,
      adoption_state: ap.adoption_state, board_name: ap.board_name,
      model_source: ap.model_source, site_id: ap.site_id, last_seen_at: ap.last_seen_at
    };
    render();
  }

  function openTokenSheet() {
    if (!canManageTokens()) return;
    state.sheet = 'token';
    state.draft = null;
    state.tokenDraft = { ttl_seconds: 600, max_attempts: 5, site_id: '' };
    render();
  }

  /*
   * 发现向导的开 / 关 / 重扫。扫描本身就是 loadAcDiscovery() 这一次只读 GET——它把
   * 自己的失败折进 reason 并正常返回，从不抛，所以这里不需要 try/catch，弹窗也不会
   * 卡死在「正在扫描」上。
   *
   * scanning 只在这次 GET 在飞时为真：demo 的雷达是个定时器，扫完必出一台设备；这里
   * 扫完是几台就是几台。scannedAt 用来分开「还没扫过」和「扫过但一台都没有」——这两句
   * 话在界面上不能混成一句。
   *
   * 打开不设能力闸门：能力没开时向导正是用来把原因讲清楚的地方，把按钮 disable 掉
   * 反而让用户无处可读。
   */
  async function scanApWizard() {
    if (!state.apWizard || state.apWizardScanning) return;
    state.apWizardScanning = true;
    render();
    const discovery = await loadAcDiscovery();
    if (!state.mounted || !state.apWizard) return;
    state.ac.discovery = discovery;
    state.apWizardScannedAt = Date.now();
    state.apWizardScanning = false;
    render();
  }

  function openApWizard() {
    state.apWizard = true;
    state.apWizardScannedAt = 0;
    scanApWizard();
  }

  function closeApWizard() {
    if (!state.apWizard) return;
    state.apWizard = false;
    state.apWizardScanning = false;
    render();
  }

  async function saveApEditor() {
    const editor = state.apEditor;
    if (!editor || !canEditAcAp() || state.acBusy) return;
    const body = {};
    if (editor.name !== editor.original_name) body.name = editor.name;
    if (editor.override_supported && editor.model_override !== editor.original_model_override) {
      body.model_override = editor.model_override;
    }
    // webd 要求 name / model_override 至少给一个，且拒绝任何多余键。
    if (!Object.keys(body).length) return;
    state.acBusy = true;
    render();
    try {
      await requestJson(`/api/v1/ac/aps/${encodeURIComponent(editor.ap_id)}`, {
        cacheVersion: false, method: 'PATCH', body: JSON.stringify(body)
      });
      state.notice = `AP“${firstText(body.name, editor.label)}”的清单信息已更新。`;
      state.noticeTone = 'ok';
      state.sheet = '';
      state.apEditor = null;
      state.acBusy = false;
      await loadAc(true);
    } catch (error) {
      state.ac.error = operationFailure('保存 AP 清单信息失败', error);
    } finally {
      state.acBusy = false;
      if (state.mounted) render();
    }
  }

  async function createPairingToken() {
    const draft = state.tokenDraft;
    if (!draft || !canManageTokens() || state.acBusy) return;
    state.acBusy = true;
    render();
    try {
      const body = { ttl_seconds: Number(draft.ttl_seconds), max_attempts: Number(draft.max_attempts) };
      if (String(draft.site_id || '').trim()) body.site_id = String(draft.site_id).trim();
      const payload = await requestJson('/api/v1/ac/pairing-tokens', {
        cacheVersion: false, method: 'POST', body: JSON.stringify(body)
      });
      // display_once：码值只在这一次响应里出现，之后 list 只返回 token_id。
      state.tokenSecret = {
        token: firstText(payload.token),
        token_id: firstText(payload.token_id),
        expires_at: firstNumber(payload.expires_at) || 0,
        max_attempts: firstNumber(payload.max_attempts) || Number(draft.max_attempts)
      };
      /*
       * 抽屉必须留在打开状态，草稿也必须留着：码值只在这一次响应里出现，而它
       * 现在显示在抽屉顶部（tokenSheet() 的 pairingSecretBlock）。tokenSheet() 开头
       * 是 `if (!draft) return ''`，所以一旦清掉 tokenDraft，刚拿到的一次性码值
       * 会连同抽屉一起消失，且无法再取回。清理交给 closeSheet()。
       */
      state.notice = '配对码已生成，请在抽屉顶部复制保存，它只显示一次。';
      state.noticeTone = 'warn';
      state.acBusy = false;
      await loadAc(true);
    } catch (error) {
      state.ac.error = operationFailure('生成配对码失败', error);
    } finally {
      state.acBusy = false;
      if (state.mounted) render();
    }
  }

  async function revokePairingToken() {
    const tokenId = state.confirmToken;
    if (!tokenId || !canManageTokens() || state.acBusy) return;
    state.acBusy = true;
    render();
    try {
      await requestJson(`/api/v1/ac/pairing-tokens/${encodeURIComponent(tokenId)}`, {
        cacheVersion: false, method: 'DELETE'
      });
      state.notice = `配对码 ${tokenId.slice(0, 8)} 已吊销。`;
      state.noticeTone = 'ok';
      state.confirmToken = null;
      if (state.tokenSecret && state.tokenSecret.token_id === tokenId) state.tokenSecret = null;
      state.acBusy = false;
      await loadAc(true);
    } catch (error) {
      state.ac.error = operationFailure('吊销配对码失败', error);
      state.confirmToken = null;
    } finally {
      state.acBusy = false;
      if (state.mounted) render();
    }
  }

  function dismissDiscoveryCandidate() {
    const candidate = state.discoveryCandidate;
    const key = discoveryCandidateKey(candidate);
    if (key) {
      const dismissed = state.discoveryDismissedCandidates || (state.discoveryDismissedCandidates = new Set());
      dismissed.add(key);
    }
    state.discoveryCandidate = null;
    render();
  }

  async function confirmDiscoveredAp() {
    const candidate = state.discoveryCandidate;
    const request = discoveryConfirmRequest(candidate);
    if (!candidate || !request || state.discoveryBusy) return;
    state.discoveryBusy = true;
    render();
    try {
      const payload = await requestJson(request.api, {
        cacheVersion: false, method: 'POST', body: JSON.stringify(request.body)
      });
      const bundle = payload.bootstrap_bundle;
      if (!bootstrapBundleValid(bundle)) {
        state.adoption.bindingId = firstText(payload.binding_id);
        state.adoption.candidateLabel = discoveryCandidateLabel(candidate);
        state.adoption.state = firstText(payload.binding_state, payload.state, payload.status, 'failed');
        state.adoption.error = 'bootstrap_bundle_missing';
        state.adoption.secret = null;
        state.adoption.secretClearedReason = '';
        throw Object.assign(new Error('bootstrap_bundle_missing'), { code: 'bootstrap_bundle_missing' });
      }
      state.adoption.bindingId = firstText(payload.binding_id);
      state.adoption.candidateLabel = discoveryCandidateLabel(candidate);
      state.adoption.secret = clone(bundle);
      state.adoption.command = bootstrapCommand(bundle, payload.next_step);
      state.adoption.secretClearedReason = '';
      state.adoption.copyFeedback = '';
      state.adoption.copyTone = '';
      state.adoption.error = '';
      state.notice = '一次性 bootstrap bundle 已准备好，请交给 AP 侧执行命令；页面不会再次请求 secret。';
      state.noticeTone = 'warn';
      startAdoptionStatusPoll(state.adoption.bindingId, firstText(payload.binding_state, payload.state, payload.status, 'enrollment_pending'), payload.poll_interval_ms);
      scheduleBootstrapExpiry(state.adoption.secret);
      const key = discoveryCandidateKey(candidate);
      if (key) {
        const dismissed = state.discoveryDismissedCandidates || (state.discoveryDismissedCandidates = new Set());
        dismissed.add(key);
      }
      state.discoveryCandidate = null;
      /* 绑定已受理，向导的活干完了：纳管进度改由页面上的 adoptionBundleSection() 承载。 */
      state.apWizard = false;
      state.apWizardScanning = false;
    } catch (error) {
      const failure = bootstrapErrorLabel(error);
      state.adoption.error = failure.code;
      state.adoption.state = firstText(state.adoption.state, 'failed');
      state.ac.error = operationFailure('请求绑定 AP 失败', { code: failure.code, message: failure.text });
    } finally {
      state.discoveryBusy = false;
      if (state.mounted) render();
    }
  }

  function saveDraft() {
    if (!state.draft || !canConfigWrite()) return;
    if (state.sheet === 'ssid') {
      const draft = normalizeSsid(state.draft);
      if (!draft.name.trim() || !draft.bands.length) return;
      if (draft.bands.includes('6g') || draft.mlo) { draft.security = 'wpa3-personal'; draft.pmf = 'required'; draft.ppsk = false; }
      const index = state.config.ssids.findIndex((ssid) => ssid.id === draft.id);
      if (index >= 0) state.config.ssids[index] = draft; else state.config.ssids.push(draft);
    } else if (state.sheet === 'speed') {
      const draft = clone(state.draft);
      const index = state.config.speed_limits.findIndex((limit) => limit.id === draft.id);
      if (index >= 0) state.config.speed_limits[index] = draft; else state.config.speed_limits.push(draft);
    }
    state.sheet = '';
    state.draft = null;
    state.dirty = true;
    render();
  }

  async function saveConfig() {
    if (!canConfigWrite() || state.saving) return;
    let operationTitle = '保存 Wi-Fi 配置失败';
    state.saving = true;
    state.error = '';
    render();
    try {
      // Refresh the canonical local read model before writing.  The aggregate
      // view can outlive a device reboot and contain synthetic local:* rows;
      // never replay those rows into the desired-state database.
      const livePayload = await requestJson(ENDPOINT);
      const liveConfig = normalizeConfig(livePayload);
      /*
       * A read that came back without radios is not evidence that the bands
       * have no radio.  When the local ubus read times out the aggregate is
       * published with radios[] empty and capabilities.wifi still true, and
       * treating that as truth is what produced "所选频段没有对应的 Radio" for
       * all three bands on a device whose three radios were up and beaconing.
       * Stop here and say the read failed, so nothing is written against a
       * view we know is incomplete.
       */
      if (!liveConfig.radios.length) {
        const localReason = firstText(livePayload?.local_wifi?.reason,
          livePayload?.sources?.local?.reason, livePayload?.capabilities?.reasons?.read_config, '');
        throw new Error(`未能读取到当前 Radio 列表，已放弃保存以避免写入不完整的配置${localReason ? `（后端原因：${localReason}）` : ''}。请稍后重试。`);
      }
      const liveRadioIds = new Set(liveConfig.radios.map((item) => item.id));
      const liveSsidIds = new Set(liveConfig.ssids.map((item) => item.id));
      const radios = liveConfig.radios.map((item) => {
        const edited = state.config.radios.find((candidate) => candidate.id === item.id);
        return edited ? { ...item, ...clone(edited), id: item.id } : item;
      });
      const ssids = liveConfig.ssids.map((item) => {
        const edited = state.config.ssids.find((candidate) => candidate.id === item.id);
        if (!edited) return item;
        const merged = { ...item, ...clone(edited), id: item.id };
        /* Follow a band change onto the real radio: the desired row owns one
         * wifi-iface, and leaving `device` behind would keep the SSID on the
         * radio it was first bound to. */
        const bands = asArray(merged.bands).map(normalizeBand).filter(Boolean);
        if (bands.length === 1) {
          const radio = liveConfig.radios.find((entry) => normalizeBand(entry.band) === bands[0]);
          if (radio) { merged.device = radio.id; merged.radio_id = radio.id; }
        }
        return merged;
      });
      // Preserve drafts created in this page. They are intentionally
      // unprefixed and therefore are not stale aggregate rows. The backend
      // may create them on this save; filtering them by live IDs silently
      // discarded a newly entered SSID after reporting success.
      const liveSsidIdSet = new Set(liveConfig.ssids.map((item) => item.id));
      const radioForBandId = (band) => liveConfig.radios.find((radio) => normalizeBand(radio.band) === band);
      /*
       * One desired SSID row becomes exactly one `config wifi-iface` bound to
       * exactly one radio, so a draft covering several bands has to be expanded
       * into one row per band with an explicit device.  A single row carrying
       * bands: ['2g','5g'] and no device landed on whatever the generator
       * defaulted to, which is how apply could report success with nothing
       * broadcasting on the other band.
       */
      const unboundBands = new Set();
      const newSsids = state.config.ssids
        .filter((item) => !liveSsidIdSet.has(item.id) && !String(item.id).startsWith('local:ssid:'))
        .flatMap((item) => {
          const base = uciSectionId(localWriteId(item, 'ssid', item.id), 'wifi');
          const bands = asArray(item.bands).map(normalizeBand).filter(Boolean);
          bands.filter((band) => !radioForBandId(band)).forEach((band) => unboundBands.add(band));
          const targets = bands.map((band) => ({ band, radio: radioForBandId(band) })).filter((entry) => entry.radio);
          return targets.map((entry) => ({
            ...clone(item),
            id: uciSectionId(targets.length > 1 ? `${base}_${entry.band}` : base, 'wifi'),
            bands: [entry.band],
            device: entry.radio.id,
            radio_id: entry.radio.id
          }));
        });
      if (unboundBands.size) {
        throw new Error(`所选频段没有对应的 Radio：${Array.from(unboundBands).map(bandLabel).join('、')}`);
      }
      if (state.config.ssids.length && !ssids.filter((item) => liveSsidIds.has(item.id)).length && !newSsids.length) {
        throw new Error('没有任何可写入的 SSID，已放弃保存以避免用空配置覆盖现有 Wi-Fi。');
      }
      const payload = {
        ...clone(livePayload),
        global: clone(state.config.global),
        radios: radios.filter((item) => liveRadioIds.has(item.id)),
        ssids: ssids.filter((item) => liveSsidIds.has(item.id)).concat(newSsids),
        speed_limits: clone(state.config.speed_limits)
      };
      /* MLO 改动走受管事务通道，不走本机 /api/v1/wifi/config。
         本机无 PHY 时 PUT 必定 400（no_phy_detected），MLO 改动须绕开。 */
      let mloApplied = false;
      try {
        const rawSsids = state.rawConfig?.ssids || [];
        const rawRadios = state.rawConfig?.radios || [];
        const mloPlan = buildManagedMloPlan({
          rawSsids, rawRadios,
          ssids: state.config.ssids,
          globalMlo: state.config.global.mlo
        });
        if (mloPlan.changed && managedWriteSupported()) {
          const mloTargets = [];
          for (const t of mloPlan.byAp) {
            const digest = await candidateDigest(t.sections);
            mloTargets.push({
              ap_id: t.ap_id,
              candidate: JSON.stringify({
                format: firstText(
                  objectValue(writeScope('managed').transaction).candidate_format,
                  'uci-wireless-candidate.v1'),
                candidate_digest: digest,
                sections: t.sections
              }),
              candidate_digest: digest
            });
          }
          const ep = managedTransactionEndpoint();
          const batch = Date.now().toString(36);
          const created = await requestJson(ep, {
            cacheVersion: false,
            method: firstText(
              objectValue(writeScope('managed').transaction).method, 'POST'),
            body: JSON.stringify({
              idempotency_key: `web.mlo.${batch}`,
              consistency: 'per_target',
              base_revision: transactionBaseRevision(),
              targets: mloTargets
            })
          });
          const txnId = firstText(created.transaction_id, created.id);
          if (txnId) {
            const txn = await waitTransaction(txnId);
            const txnState = firstText(txn.state).toLowerCase();
            if (txnState !== 'applied') {
              const detail = asArray(txn.targets).map(transactionTargetError).filter(Boolean).join('；');
              throw new Error(detail || TRANSACTION_ERROR_REASONS[txnState] || `MLO 事务终态为 ${txnState}`);
            }
            mloApplied = true;
          }
        }
      } catch (mloError) {
        state.error = operationFailure('MLO 配置保存失败', mloError);
        state.notice = '';
        return;
      }
      /* 本机无 PHY 时跳过 PUT，避免必现的 400。 */
      const localScopePresent = bool(writeScope('local').present, true);
      if (!localScopePresent) {
        state.notice = mloApplied ? 'MLO 配置已通过受管 AP 事务应用，本机无无线硬件，其余设置无法本地保存。' : '本机无无线硬件，设置无法保存。';
        state.noticeTone = mloApplied ? 'ok' : 'warn';
        state.dirty = false;
        await load(true);
        return;
      }
      await requestJson('/api/v1/wifi/config', { method: 'PUT', body: JSON.stringify(payload) });
      operationTitle = '应用 Wi-Fi 配置失败';
      const applied = await requestJson('/api/v1/wifi/config/apply', { method: 'POST', body: JSON.stringify({ reason: 'web_console_apply' }) });
      /*
       * Only the readback proves a beacon exists.  Reporting success off a 200
       * is what produced the "applied fine, no Wi-Fi" reports: the backend can
       * persist a draft, publish it, reload, and still fail its own runtime
       * check, and the page used to hide that behind an ok notice.
       */
      /*
       * One radio still running ACS is the exception.  6 GHz on `channel auto`
       * needs ~40s to pick a channel, which the apply handler cannot wait out,
       * so the backend answers applied + readback_pending instead of failing.
       * That is neither a green nor a red: the configuration is live and the
       * other bands are beaconing, and the page says so rather than claiming a
       * beacon it has not seen.
       */
      if (applied.readback_pending === true) {
        state.notice = `Wi-Fi 配置已应用，仍有 Radio 在自动选择信道（约 40 秒），完成后才会开始广播。原因：${firstText(applied.readback_pending_reason, applied.reason, 'radio_channel_selection_in_progress')}`;
        state.noticeTone = 'warn';
        state.dirty = false;
        await load(true);
        return;
      }
      if (applied.readback_verified === false || applied.applied === false) {
        const error = new Error('Wi-Fi 已保存但运行态未通过回读，草稿已保留');
        error.code = firstText(applied.error?.code, applied.reason, typeof applied.error === 'string' ? applied.error : '', 'apply_readback_failed');
        throw error;
      }
      state.notice = 'Wi-Fi 配置已保存并应用。';
      state.noticeTone = 'ok';
      state.dirty = false;
      await load(true);
    } catch (error) {
      state.error = operationFailure(operationTitle, error);
    } finally {
      state.saving = false;
      render();
    }
  }

  async function savePendingChanges() {
    if (state.saving || state.roaming.saving) return;
    const localPending = state.dirty;
    const roamingPending = state.roaming.dirty;
    if (localPending) {
      if (canConfigWrite()) await saveConfig();
      else state.error = `保存 Wi-Fi 配置失败：${configWriteGateNote() || '当前账号或后端不允许写入'}`;
    }
    if (roamingPending) {
      if (roamingPolicyWriteAllowed()) await saveRoamingPolicy();
      else state.roaming.error = roamingPolicyCapabilityReason() || '当前漫游策略不可写。';
    }
    render();
  }

  /* 后端报的是"ap_id, local phy radio_id, mode and idempotency_key are required"，
     要的是**本机 phy**（phyN）；页面持有的 radio.id 是 AC 侧复合 id
     `ap:<uuid>:radio:phyN`。30.1 的 /wifi/scan/jobs 里 128 条作业全是调度器建的裸
     phyN，web. 前缀的一条都没有 —— 复合 id 在这条路径上从未成功落地过。所以先按 phy
     提交，只有拿到 400（参数校验失败，不是鉴权也不是 5xx）才用复合 id 重试一次：
     两侧谁新谁旧都能成。重试沿用同一个 idempotency_key —— 400 是入库前就拒了，
     不会留下作业，这正是幂等键存在的意义。 */
  /* 取的是 AC 认的本机 radio id，有两种合法形态：`phyN`（一个 wiphy 一个 radio）与
     `phyNrM`（单 wiphy 多 radio，mac80211 机型；31.250/31.251 的 W1700K 就是
     phy0r0/phy0r1/phy0r2）。

     先读 local_id / id 再退到 phy，顺序不能反：这三个 Radio 的 phy 全是 `phy0`，
     以 phy 优先会把三条扫描请求都提到同一个 radio 上，而 AC 侧
     dreamingwrt_ap_radio_id_valid() 要的是能唯一定位的那一个。 */
  function localPhyId(radio = {}) {
    const candidate = radioIdTail(firstText(radio.local_id, radio.id, radio.local_radio_id, radio.phy));
    return /^phy\d+(r\d+)?$/.test(candidate) ? candidate : firstText(radio.phy, '').toLowerCase();
  }

  async function createScanJob(radio = {}, idempotencyKey = '') {
    const post = (radioId) => requestJson('/api/v1/wifi/scan', {
      cacheVersion: false,
      method: 'POST',
      body: JSON.stringify({ ap_id: radio.ap_id, radio_id: radioId, mode: 'neighbor', idempotency_key: idempotencyKey })
    });
    const phyId = localPhyId(radio);
    /* 复合 id 由 ap_id 与本机 id 现拼：normalizeRadio() 已经把 radio.id 压成裸
       local_id，直接拿 radio.id 当"另一种形态"重试等于把同一个请求发两遍。 */
    const compositeId = phyId && radio.ap_id ? `ap:${radio.ap_id}:radio:${phyId}` : '';
    if (!phyId) return post(firstText(radio.id));
    try {
      return await post(phyId);
    } catch (error) {
      if (error?.status !== 400 || !compositeId) throw error;
      return post(compositeId);
    }
  }

  /* 校验原文是英文裸串，直接插到"启动环境扫描失败：…"后面等于把后端语法抛给用户。 */
  const SCAN_ERROR_COPY = {
    'ap_id, local phy radio_id, mode and idempotency_key are required':
      '后端拒绝了扫描参数：它要的 radio_id 是 AP 本机形式（phyN 或 phyNrM）。若该 AP 上报的是 phyNrM，请确认 webd 已更新到接受这种形态的版本',
    invalid_payload: '扫描请求未通过后端参数校验',
    scan_job_create_failed: '后端未能创建扫描作业',
    scan_job_id_missing: '后端受理了请求但没有返回作业号',
    unauthorized: '会话已失效，请重新登录后再试',
    forbidden: '当前账号权限不足：启动扫描属于中风险操作，仅管理员或所有者可执行',
    source_unavailable: '控制器 (dreamingwrt.ac) 未在等待窗口内应答，扫描未派发；稍后重试',
    'ubus source is not available': '控制器 (dreamingwrt.ac) 未在等待窗口内应答，扫描未派发；稍后重试',
    dependency_timeout: '控制器已受理但未在等待窗口内应答，作业可能仍在派发中',
    controller_disabled: 'AC 控制器功能当前处于停用状态'
  };

  /* webd 把三件事都说成 "ubus source is not available"：没有 ubus socket、
     dreamingwrt.ac 未注册、以及调用超时（app_ubus_object_or_error() 把
     stage/rc 折叠掉了）。扫描派发这条路径 ubus 侧实测可用，用户看到这句时
     几乎总是 403 被上层文案吞掉，或者 AC 一时没答上来，所以说清是依赖侧
     而不是参数错误。 */
  function scanErrorCopy(error) {
    if (error?.status === 403) return '当前账号权限不足：启动扫描属于中风险操作，仅管理员或所有者可执行';
    if (error?.status === 401) return '会话已失效，请重新登录后再试';
    const raw = firstText(error?.message, '未知错误');
    const code = firstText(error?.code, error?.reason);
    return SCAN_ERROR_COPY[code] || SCAN_ERROR_COPY[raw] || SCAN_ERROR_COPY[raw.toLowerCase()] || raw;
  }

  async function scan() {
    if (!bool(state.status.capabilities.scan_execution || state.status.capabilities.scan, false) || !state.status.radios.length || state.scanning) return;
    const apId = state.filters.environmentAp === 'all' ? selectedEnvironmentAp()?.id : state.filters.environmentAp;
    const radios = state.status.radios
      .filter((radio) => !apId || radio.ap_id === apId)
      .sort((left, right) => ({ '2g': 0, '5g': 1, '6g': 2 }[left.band] ?? 9) - ({ '2g': 0, '5g': 1, '6g': 2 }[right.band] ?? 9));
    if (!radios.length) return;
    const epoch = ++state.scanEpoch;
    state.scanning = true;
    state.scanJobs = new Map(radios.map((radio) => [radio.id, { radio_id: radio.id, band: radio.band, state: 'creating', error: '', result_count: 0 }]));
    state.notice = `正在扫描 ${radios.length} 个 Radio，扫描期间客户端可能短暂断开。`;
    state.noticeTone = 'warn';
    render();
    try {
      const batch = Date.now().toString(36);
      const results = await Promise.allSettled(radios.map((radio, index) => (
        createScanJob(radio, `web.environment.${batch}.${index}`)
      )));
      if (!state.mounted || epoch !== state.scanEpoch) return;
      results.forEach((result, index) => {
        const radio = radios[index];
        const payload = result.status === 'fulfilled' ? result.value : {};
        const source = scanJobPayload(payload);
        const jobId = firstText(source.job_id, source.id, payload.job_id, payload.id);
        state.scanJobs.set(radio.id, {
          radio_id: radio.id,
          band: radio.band,
          job_id: jobId,
          state: result.status === 'fulfilled' && jobId ? firstText(source.state, source.status, 'queued').toLowerCase() : 'failed',
          error: result.status === 'rejected' ? firstText(result.reason?.message, 'scan_job_create_failed') : jobId ? firstText(source.error_code, source.error, source.reason) : 'scan_job_id_missing',
          result_count: firstNumber(source.result_count)
        });
      });
      const started = Array.from(state.scanJobs.values()).filter((job) => job.job_id).length;
      if (!started) throw results[0]?.reason || new Error('未能创建扫描任务');
      patchScanJobs();
      const terminal = new Set(['completed', 'failed', 'cancelled', 'expired']);
      const deadline = Date.now() + 180000;
      while (state.mounted && epoch === state.scanEpoch && Date.now() < deadline) {
        const pending = Array.from(state.scanJobs.entries()).filter(([, job]) => job.job_id && !terminal.has(job.state));
        if (!pending.length) break;
        await new Promise((resolve) => {
          state.scanWaitResolve = resolve;
          state.scanTimer = window.setTimeout(() => { state.scanWaitResolve = null; resolve(); }, 2000);
        });
        state.scanTimer = 0;
        if (!state.mounted || epoch !== state.scanEpoch) return;
        const updates = await Promise.allSettled(pending.map(([, job]) => requestJson(`/api/v1/wifi/scan/jobs/${encodeURIComponent(job.job_id)}`, { cacheVersion: false })));
        updates.forEach((result, index) => {
          const [key, previous] = pending[index];
          if (result.status === 'rejected') {
            state.scanJobs.set(key, { ...previous, poll_error: firstText(result.reason?.message, 'scan_job_status_failed') });
            return;
          }
          const payload = result.value;
          const source = scanJobPayload(payload);
          state.scanJobs.set(key, {
            ...previous,
            ...source,
            state: firstText(source.state, source.status, previous.state).toLowerCase(),
            error: firstText(source.error_code, source.error, source.reason, source.failure_reason),
            result_count: firstNumber(source.result_count, source.count, asArray(source.results).length)
          });
        });
        patchScanJobs();
      }
      Array.from(state.scanJobs.entries()).forEach(([key, job]) => {
        if (job.job_id && !terminal.has(job.state)) state.scanJobs.set(key, { ...job, state: 'expired', error: 'scan_status_timeout' });
      });
      const jobs = Array.from(state.scanJobs.values());
      const completed = jobs.filter((job) => job.state === 'completed').length;
      const failed = jobs.filter((job) => ['failed', 'expired'].includes(job.state)).length;
      state.notice = completed ? `${completed} 个 Radio 扫描完成${failed ? `，${failed} 个失败` : ''}。` : `${failed || jobs.length} 个 Radio 扫描失败，详情见左侧任务状态。`;
      state.noticeTone = completed && !failed ? 'ok' : 'warn';
      await load(true);
      await loadEnvironmentHistory();
    } catch (error) {
      state.error = operationFailure('启动环境扫描失败', error);
    } finally {
      if (epoch === state.scanEpoch) {
        state.scanning = false;
        render();
      }
    }
  }

  function patchScanJobs() {
    if (!root || !state.mounted) return;
    const current = root.querySelector('[data-airview-scan-jobs]');
    const holder = document.createElement('div');
    holder.innerHTML = scanJobsPanel();
    const next = holder.firstElementChild;
    if (current && next) current.replaceWith(next);
    const button = root.querySelector('[data-airview-scan]');
    if (button) {
      button.disabled = state.scanning;
      const label = button.querySelector('span');
      if (label) label.textContent = state.scanning ? '扫描任务执行中' : '扫描环境';
    }
  }

  function onClick(event) {
    const origin = event.target;
    /*
     * Kit 确认弹窗的取消/确认按钮先接住：它的取消键同时带 data-dwrt-modal-close，
     * 遮罩也是 button，若落到后面的通用分支会被当成普通按钮忽略掉。
     */
    if (state.confirmSsidDelete) {
      if (origin.closest('[data-dwrt-confirm-accept]')) { deleteSelectedSsids(); return; }
      if (origin.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]')) { state.confirmSsidDelete = null; render(); return; }
    }
    if (state.confirmToken) {
      if (origin.closest('[data-dwrt-confirm-accept]')) { revokePairingToken(); return; }
      if (origin.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]')) { state.confirmToken = null; render(); return; }
    }
    if (state.discoveryCandidate) {
      if (origin.closest('[data-dwrt-confirm-accept]')) { confirmDiscoveredAp(); return; }
      if (origin.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]')) { dismissDiscoveryCandidate(); return; }
    }
    if (state.txpower.confirmPending) {
      if (origin.closest('[data-dwrt-confirm-accept]')) { setTxpowerMode(state.txpower.apId, 'regulatory', true); return; }
      if (origin.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]')) { state.txpower.confirmPending = false; render(); return; }
    }
    /* Sheet-internal div handlers — enterprise collapse, band pills, toggle tiles.
       These sit before target narrowing because they target divs, not buttons/trs. */
    if (origin.closest('[data-wifi-enterprise-toggle]')) {
      state._enterpriseOpen = !state._enterpriseOpen;
      const well = sheetQuery('.wifi-enterprise-well');
      const toggle = sheetQuery('.wifi-enterprise-toggle');
      if (well) well.classList.toggle('is-open', state._enterpriseOpen);
      if (toggle) toggle.textContent = state._enterpriseOpen ? '收起 \u2227' : '点击展开 \u2335';
      return;
    }
    if (origin.closest('.wifi-band-pill[data-wifi-draft-band]')) {
      if (!state.draft) return;
      const bEl = origin.closest('.wifi-band-pill[data-wifi-draft-band]');
      const band = bEl.dataset.wifiDraftBand;
      if (!band || !state.config.capabilities.bands.includes(band)) return;
      const bands = new Set(state.draft.bands || []);
      if (bands.has(band)) bands.delete(band); else bands.add(band);
      state.draft.bands = Array.from(bands);
      bEl.classList.toggle('is-active', bands.has(band));
      syncSsidDraftDependencies();
      return;
    }
    if (origin.closest('.wifi-toggle-tile') && origin.tagName !== 'INPUT') {
      const tile = origin.closest('.wifi-toggle-tile');
      const inp = tile.querySelector('input[type="checkbox"]');
      if (inp && !inp.disabled && state.draft) {
        const next = !inp.checked;
        inp.checked = next;
        setPath(state.draft, inp.dataset.wifiDraftToggle, next);
        tile.classList.toggle('is-highlight', next);
        syncSsidDraftDependencies();
      }
      return;
    }
    const target = origin.closest('button, tr[data-wifi-edit], tr[data-wifi-ssid-select-row], tr[data-wifi-speed-edit], tr[data-airview-radio-row]');
    if (!target) return;
    if (target.matches('[data-wifi-config-tab]')) {
      const view = target.dataset.wifiConfigTab;
      if (!['broadcasts', 'radios', 'extensions', 'aps'].includes(view) || state.configView === view) return;
      state.configView = view;
      // 切到 AP 管理时按需拉一次 AC 数据；离开时清掉只对该 Tab 有意义的搜索词。
      state.query = '';
      if (view !== 'broadcasts') {
        state.ssidManage = false;
        state.selectedSsids.clear();
      }
      render();
      if (view === 'aps' && !state.ac.loaded && !state.ac.loading) loadAc();
      if (view === 'extensions' && !state.roaming.loaded && !state.roaming.loading) loadRoamingPolicy();
      return;
    }
    if (target.matches('[data-wifi-create]')) { openSsid(); return; }
    if (target.matches('[data-wifi-ssid-manage]')) { setSsidManagement(true); return; }
    if (target.matches('[data-wifi-ssid-manage-done]')) { setSsidManagement(false); return; }
    if (target.matches('[data-wifi-ssid-toggle]')) { setSelectedSsidsEnabled(target.dataset.wifiSsidToggle === 'enable'); return; }
    if (target.matches('[data-wifi-ssid-remove]')) {
      const selected = selectedSsidRows();
      if (!selected.length || state.dirty || !ssidDeleteContract().available) return;
      state.confirmSsidDelete = { ids: selected.map((ssid) => ssid.id), names: selected.map((ssid) => ssid.name) };
      render();
      return;
    }
    if (target.matches('[data-wifi-ap-edit]')) { openApEditor(target.dataset.wifiApEdit); return; }
    if (target.matches('[data-wifi-ap-save]')) { saveApEditor(); return; }
    if (target.matches('[data-wifi-token-create]')) { openTokenSheet(); return; }
    if (target.matches('[data-wifi-token-save]')) { createPairingToken(); return; }
    if (target.matches('[data-wifi-ap-wizard-open]')) { openApWizard(); return; }
    if (target.matches('[data-wifi-ap-wizard-close]')) { closeApWizard(); return; }
    if (target.matches('[data-wifi-ap-wizard-rescan]')) { scanApWizard(); return; }
    if (target.matches('[data-wifi-discovery-confirm]')) {
      const candidate = state.ac.discovery.items.find((item) => item.ap_id === target.dataset.wifiDiscoveryConfirm);
      if (!candidate || state.adoption.bindingId || !canConfirmDiscoveryCandidate(candidate) || candidate.adopted_elsewhere) return;
      state.discoveryCandidate = candidate;
      render();
      return;
    }
    if (target.matches('[data-wifi-bootstrap-copy]')) {
      copyBootstrapPart(target.dataset.wifiBootstrapCopy);
      return;
    }
    if (target.matches('[data-wifi-bootstrap-close]')) {
      clearBootstrapBundle('closed');
      return;
    }
    if (target.matches('[data-wifi-token-revoke]')) {
      if (!canManageTokens()) return;
      state.confirmToken = target.dataset.wifiTokenRevoke || null;
      render();
      return;
    }
    if (target.matches('[data-wifi-token-copy]')) {
      navigator.clipboard?.writeText(target.dataset.wifiTokenCopy || '').catch(() => {});
      return;
    }
    if (target.matches('[data-wifi-token-secret-dismiss]')) { state.tokenSecret = null; render(); return; }
    if (target.matches('[data-wifi-edit]')) { openSsid(target.dataset.wifiEdit); return; }
    if (target.matches('[data-wifi-ssid-select-row]')) {
      if (origin.closest('input, button, a, label')) return;
      const id = target.dataset.wifiSsidSelectRow;
      setSsidSelection(id, !state.selectedSsids.has(id));
      return;
    }
    if (target.matches('[data-wifi-speed-create]')) { openSpeed(); return; }
    if (target.matches('[data-wifi-speed-edit]')) { openSpeed(target.dataset.wifiSpeedEdit); return; }
    if (target.matches('[data-wifi-sheet-close]')) { closeSheet(); return; }
    if (target.matches('[data-wifi-draft-save]')) { saveDraft(); return; }
    if (target.matches('[data-roaming-retry]')) { loadRoamingPolicy(state.roaming.domainId); return; }
    if (target.matches('[data-dwrt-savebar-save]')) { savePendingChanges(); return; }
    if (target.matches('[data-dwrt-savebar-discard]')) {
      state.dirty = false;
      state.config = normalizeConfig(state.rawConfig);
      discardRoamingPolicy();
      render();
      return;
    }
    if (target.matches('[data-wifi-reset-channels]')) { state.config.radios.forEach((radio) => { radio.excluded_channels = []; }); markDirty(); return; }
    if (target.matches('[data-wifi-width]')) {
      const band = target.dataset.wifiWidthBand;
      const width = Number(target.dataset.wifiWidth);
      if (!speedProfileCapability().available || !['2g', '5g', '6g'].includes(band) || !width) return;
      state.config.global.widths[band] = width;
      state.config.global.speed_profile = 'custom';
      markDirty(true);
      return;
    }
    if (target.matches('[data-wifi-apply-all]')) {
      if (!speedProfileCapability().available) return;
      state.config.radios.forEach((radio) => {
        const desired = Number(state.config.global.widths[radio.band]);
        if (!desired) return;
        const supported = radio.supported_widths || [];
        radio.width = !supported.length || supported.includes(desired) ? desired : Math.max(...supported.filter((value) => value <= desired), supported[0] || desired);
      });
      state.notice = '默认信道宽度已应用到全部 AP 草稿。';
      state.noticeTone = 'ok';
      markDirty(true);
      return;
    }
    if (target.matches('[data-wifi-channel]')) {
      const radio = radioForBand(target.dataset.wifiChannelBand);
      if (!radio || !canConfigWrite()) return;
      const values = (target.dataset.wifiChannelValues || target.dataset.wifiChannel || '')
        .split(',').map(Number).filter((value) => Number.isFinite(value) && value > 0);
      if (!values.length) return;
      const set = new Set(radio.excluded_channels || []);
      const shouldExclude = !values.every((value) => set.has(value));
      values.forEach((value) => { if (shouldExclude) set.add(value); else set.delete(value); });
      radio.excluded_channels = Array.from(set).sort((a, b) => a - b);
      markDirty();
      return;
    }
    if (target.matches('[data-airview-radio-sheet-close]')) { closeRadioSheet(); return; }
    if (target.matches('[data-airview-ap-details]')) {
      if (!target.dataset.airviewApDetails) return;
      state.apSheetAp = target.dataset.airviewApDetails;
      state.apSheetTab = 'overview';
      render();
      loadTxpowerMode(state.apSheetAp);
      return;
    }
    if (target.matches('[data-airview-ap-sheet-close]')) { state.apSheetAp = ''; state.apSheetTab = 'overview'; render(); return; }
    if (target.matches('[data-airview-ap-tab]')) {
      state.apSheetTab = target.dataset.airviewApTab;
      render();
      if (target.dataset.airviewApTab === 'settings' && state.apSheetAp) {
        if (state.txpower.apId !== state.apSheetAp || !state.txpower.data) loadTxpowerMode(state.apSheetAp);
      }
      return;
    }
    if (target.matches('[data-txpower-toggle]')) {
      const apId = target.dataset.txpowerToggle;
      if (!apId || state.txpower.busy) return;
      if (target.checked) {
        state.txpower.confirmPending = true;
        render();
      } else {
        setTxpowerMode(apId, 'calibrated', false);
      }
      return;
    }
    if (target.matches('[data-airview-radio-remove]')) { setRadioSelection(target.dataset.airviewRadioRemove, false); return; }
    if (target.matches('[data-airview-radio-save]')) { saveRadioDrafts(); return; }
    if (target.matches('[data-airview-copy]')) {
      navigator.clipboard?.writeText(target.dataset.airviewCopy || '').catch(() => {});
      return;
    }
    if (target.matches('[data-airview-radio-width]')) {
      if (!canRadioWrite()) return;
      const [band, value] = target.dataset.airviewRadioWidth.split(':');
      updateRadioDrafts(band, 'width', Number(value));
      render();
      return;
    }
    if (target.matches('[data-airview-radio-power]')) {
      if (!canRadioWrite()) return;
      const [band, value] = target.dataset.airviewRadioPower.split(':');
      updateRadioDrafts(band, 'tx_power_mode', value);
      render();
      return;
    }
    if (target.matches('[data-airview-ap-radio-save]')) {
      saveRadioDrafts(apRadios(target.dataset.airviewApRadioSave));
      return;
    }
    if (target.matches('[data-airview-ap-radio-reset]')) {
      apRadios(target.dataset.airviewApRadioReset).forEach((radio) => state.radioDrafts.delete(radio.id));
      render();
      return;
    }
    if (target.matches('[data-airview-radio-row]')) {
      if (origin.closest('input, button, select, a, label')) return;
      const id = target.dataset.airviewRadioRow;
      setRadioSelection(id, !state.selectedRadios.has(id));
      return;
    }
    if (target.matches('[data-airview-view]')) {
      selectStatusView(target.dataset.airviewView);
      return;
    }
    if (target.matches('[data-channel-ai-band]')) {
      if (state.channelAi.band === target.dataset.channelAiBand) return;
      state.channelAi.band = target.dataset.channelAiBand;
      patchStatusView();
      return;
    }
    if (target.matches('[data-channel-ai-refresh]')) { loadChannelAi(true); return; }
    if (target.matches('[data-channel-ai-clear]')) {
      state.channelAi.signalMin = -70;
      state.channelAi.channelModes.clear();
      state.channelAi.stats = new Set(['retry', 'signal', 'clients', 'interference']);
      patchStatusView();
      return;
    }
    if (target.matches('[data-airview-connectivity-range]')) { state.filters.connectivityRange = Number(target.dataset.airviewConnectivityRange); render(); loadConnectivityEvents(); return; }
    if (target.matches('[data-airview-environment-range]')) { state.filters.environmentRange = target.dataset.airviewEnvironmentRange; render(); loadEnvironmentHistory(); return; }
    if (target.matches('[data-airview-environment-band]')) { state.filters.environmentBand = target.dataset.airviewEnvironmentBand; render(); return; }
    if (target.matches('[data-airview-columns]')) { state.columnEditor = target.dataset.airviewColumns; render(); return; }
    if (target.matches('[data-airview-columns-done]')) { state.columnEditor = ''; render(); return; }
    if (target.matches('[data-airview-columns-reset]')) {
      const view = target.dataset.airviewColumnsReset;
      state.columns[view] = new Set((COLUMN_DEFS[view] || []).map(([key]) => key));
      render();
      return;
    }
    if (target.matches('[data-airview-refresh]')) { load(false); return; }
    if (target.matches('[data-airview-clear]')) {
      if (state.statusView === 'connectivity' && state.filters.connectivityRange !== 48) {
        state.filters.connectivityRange = 48;
        loadConnectivityEvents();
      }
      state.filters.ai = false;
      state.filters.broadcast = 'all';
      state.filters.aps = new Set(state.status.radios.map((radio) => radio.ap_id).filter(Boolean));
      state.filters.bands = new Set(state.status.radios.map((radio) => radio.band).filter(Boolean));
      state.filters.mimo.clear();
      state.filters.types.clear();
      state.filters.status.clear();
      state.filters.environmentWidths.clear();
      state.filters.environmentAp = apInventory()[0]?.id || 'all';
      state.filters.environmentBand = '';
      render();
      return;
    }
    if (target.matches('[data-airview-scan]')) scan();
  }

  function onInput(event) {
    const target = event.target;
    if (target.matches('[data-channel-ai-signal-min]')) {
      state.channelAi.signalMin = Math.max(-70, Math.min(-30, Number(target.value)));
      target.setAttribute('aria-valuetext', `${state.channelAi.signalMin} dBm`);
      patchLiveRegion();
      return;
    }
    if (target.matches('[data-wifi-search]')) {
      state.query = target.value || '';
      if (state.configView === 'aps') {
        /* 同一处改名遗漏：旧选择器与旧函数名都已不存在，AP 搜索框因此只更新
         * state.query 而永远不重绘，过滤是死的。 */
        const inventory = root.querySelector('.wifi-ap-inventory-modern');
        if (inventory) inventory.outerHTML = apInventoryStrips();
        requestAnimationFrame(() => {
          const field = root.querySelector('[data-wifi-search]');
          if (!field) return;
          field.focus({ preventScroll: true });
          const end = field.value.length;
          try { field.setSelectionRange(end, end); } catch (_) {}
        });
        return;
      }
      if (root.querySelector('.wifi-config-table')) patchSsidCard();
      requestAnimationFrame(() => root.querySelector('[data-wifi-search]')?.focus({ preventScroll: true }));
      return;
    }
    if (target.matches('[data-wifi-draft]') && state.sheet === 'ap' && state.apEditor) {
      const path = target.dataset.wifiDraft;
      if (path === 'name' || path === 'model_override') state.apEditor[path] = target.value;
      const save = sheetQuery('[data-wifi-ap-save]');
      if (save) {
        const editor = state.apEditor;
        const dirty = editor.name !== editor.original_name || editor.model_override !== editor.original_model_override;
        save.disabled = !canEditAcAp() || !dirty || state.acBusy;
      }
      return;
    }
    if (target.matches('[data-wifi-draft]') && state.sheet === 'token' && state.tokenDraft) {
      const path = target.dataset.wifiDraft;
      if (path === 'site_id') state.tokenDraft.site_id = target.value;
      else if (path === 'ttl_seconds' || path === 'max_attempts') state.tokenDraft[path] = Number(target.value || 0);
      const save = sheetQuery('[data-wifi-token-save]');
      if (save) {
        const draft = state.tokenDraft;
        const valid = draft.ttl_seconds >= 60 && draft.ttl_seconds <= 86400 &&
          draft.max_attempts >= 1 && draft.max_attempts <= 10;
        save.disabled = !canManageTokens() || !valid || state.acBusy;
      }
      return;
    }
    if (target.matches('[data-wifi-draft]')) {
      const path = target.dataset.wifiDraft;
      const value = target.type === 'number' ? Number(target.value || 0) : target.value;
      setPath(state.draft, path, value);
      if (state.sheet === 'ssid') syncSsidDraftDependencies();
      /*
       * data-wifi-draft-save 渲染在 .dwrt-kit-sheet 里（wifiSheetMarkup / speedSheetMarkup），
       * mountAll 会把抽屉搬进传送门，root 就查不到它了。相邻的 ap/token 两个分支已经用
       * sheetQuery，这一支漏了：表现是在 Wi-Fi 或速度限制抽屉里输入名称后保存按钮不解禁。
       */
      const save = sheetQuery('[data-wifi-draft-save]');
      if (save) save.disabled = !canConfigWrite() || !String(state.draft.name || '').trim() || (state.sheet === 'ssid' && !state.draft.bands.length);
      return;
    }
    if (target.matches('[data-wifi-setting]') && !['checkbox', 'radio'].includes(target.type)) {
      setPath(state.config, target.dataset.wifiSetting, target.type === 'number' ? Number(target.value || 0) : target.value);
      markDirty();
      return;
    }
    if (target.matches('[data-wifi-tx-power]')) {
      commitRadioTxPowerInput(target);
      return;
    }
    if (target.matches('[data-airview-radio-custom-power]')) {
      if (!canRadioWrite()) return;
      updateRadioDrafts(target.dataset.airviewRadioCustomPower, 'tx_power_custom', Number(target.value || 0));
      return;
    }
    if (target.matches('[data-airview-ap-radio-custom-power]')) {
      const radio = state.status.radios.find((item) => item.id === target.dataset.airviewApRadioCustomPower);
      if (!radio || !canRadioWrite([radio])) return;
      setPath(radioDraft(radio), 'tx_power_custom', Number(target.value || 0));
      state.radioDirty = true;
    }
  }

  function onChange(event) {
    const target = event.target;
    if (target.matches('[data-roaming-domain]')) {
      if (state.roaming.dirty || state.roaming.loading) return;
      const domainId = target.value || '';
      state.roaming.domainId = domainId;
      state.roaming.loaded = false;
      loadRoamingPolicy(domainId);
      return;
    }
    if (target.matches('[data-roaming-number]')) {
      const value = Number(target.value);
      if (!Number.isFinite(value)) return;
      setRoamingDraftField(target.dataset.roamingNumber, value);
      render();
      return;
    }
    if (target.matches('[data-roaming-setting]')) {
      setRoamingDraftField(target.dataset.roamingSetting, target.type === 'checkbox' ? target.checked : target.value);
      render();
      return;
    }
    if (target.matches('[data-channel-ai-stat], [data-channel-ai-mode]')) {
      const selected = target.matches('[data-channel-ai-stat]') ? state.channelAi.stats : state.channelAi.channelModes;
      const value = target.dataset.channelAiStat || target.dataset.channelAiMode;
      if (target.checked) selected.add(value); else selected.delete(value);
      patchLiveRegion();
      return;
    }
    if (target.matches('[data-wifi-ssid-select-all]')) {
      /* 走同一个 filteredSsidGroups()，不再就地重抄一遍过滤条件 —— 抄一份就会有
         一天表里筛的和全选勾的不是同一批行。全选也按整组展开到成员 id。 */
      filteredSsidGroups().forEach((group) => group.ids.forEach((id) => {
        if (target.checked) state.selectedSsids.add(id); else state.selectedSsids.delete(id);
      }));
      patchSsidCard();
      return;
    }
    if (target.matches('[data-wifi-ssid-select]')) {
      setSsidSelection(target.dataset.wifiSsidSelect, target.checked);
      return;
    }
    if (target.matches('[data-airview-radio-select-all]')) {
      filteredRadios().forEach((radio) => {
        if (target.checked) {
          state.selectedRadios.add(radio.id);
          radioDraft(radio);
        } else {
          state.selectedRadios.delete(radio.id);
          state.radioDrafts.delete(radio.id);
        }
      });
      state.selectedRadio = state.selectedRadios.values().next().value || '';
      if (!state.selectedRadios.size) state.radioDirty = false;
      render();
      return;
    }
    if (target.matches('[data-airview-radio-select]')) {
      setRadioSelection(target.dataset.airviewRadioSelect, target.checked);
      return;
    }
    if (target.matches('[data-airview-radio-channel]')) {
      if (!canRadioWrite()) return;
      const band = target.dataset.airviewRadioChannel;
      const auto = target.value === 'auto';
      updateRadioDrafts(band, 'channel_auto', auto);
      updateRadioDrafts(band, 'channel', auto ? 0 : Number(target.value));
      render();
      return;
    }
    /* AP 详情 · 设置里的三个控件按单个 Radio 改草稿：那一页是按 radio 呈现的，
       不像射频 sheet 按频段成组。 */
    if (target.matches('[data-airview-ap-radio-width]') ||
        target.matches('[data-airview-ap-radio-channel]') ||
        target.matches('[data-airview-ap-radio-power]')) {
      const id = firstText(target.dataset.airviewApRadioWidth,
        target.dataset.airviewApRadioChannel, target.dataset.airviewApRadioPower);
      const radio = state.status.radios.find((item) => item.id === id);
      if (!radio || !canRadioWrite([radio])) return;
      const draft = radioDraft(radio);
      if (target.dataset.airviewApRadioWidth) setPath(draft, 'width', Number(target.value));
      else if (target.dataset.airviewApRadioChannel) {
        const auto = target.value === 'auto';
        setPath(draft, 'channel_auto', auto);
        setPath(draft, 'channel', auto ? 0 : Number(target.value));
      } else setPath(draft, 'tx_power_mode', target.value);
      state.radioDirty = true;
      render();
      return;
    }
    if (target.matches('[data-wifi-setting]')) {
      const value = target.type === 'checkbox' ? target.checked : target.type === 'number' ? Number(target.value || 0) : target.value;
      const path = target.dataset.wifiSetting;
      if (path === 'global.speed_profile') {
        if (!speedProfileCapability().available) return;
        applySpeedProfile(value);
        markDirty(true);
        return;
      }
      if (path === 'global.mlo') {
        setPath(state.config, 'global.mlo', value);
        if (managedWriteSupported()) {
          applyManagedMloChange(value);
          return;
        }
        markDirty();
        return;
      }
      setPath(state.config, path, value);
      if (path === 'global.dfs_enabled') state.config.global.speed_profile = 'custom';
      if (path === 'global.mesh' || path === 'global.mesh_monitor') {
        state.dirty = true;
        render();
        return;
      }
      markDirty();
      return;
    }
    if (target.matches('[data-wifi-tx-power]')) {
      commitRadioTxPowerInput(target);
      return;
    }
    if (target.matches('[data-wifi-draft-toggle]')) {
      const tile = target.closest('.wifi-toggle-tile');
      if (tile) tile.classList.toggle('is-highlight', target.checked);
      setPath(state.draft, target.dataset.wifiDraftToggle, target.checked);
      if (state.sheet === 'ssid') syncSsidDraftDependencies();
      return;
    }
    if (target.matches('[data-wifi-draft-band]')) {
      const bands = new Set(state.draft.bands || []);
      if (target.checked) bands.add(target.dataset.wifiDraftBand); else bands.delete(target.dataset.wifiDraftBand);
      state.draft.bands = Array.from(bands);
      return;
    }
    if (target.matches('[data-airview-ai]')) { state.filters.ai = target.checked; return; }
    if (target.matches('[data-airview-broadcast]')) { state.filters.broadcast = target.value; patchLiveRegion(); return; }
    if (target.matches('[data-airview-environment-ap]')) { state.filters.environmentAp = target.value; render(); loadEnvironmentHistory(); return; }
    if (target.matches('[data-airview-column-all]')) {
      const view = target.dataset.airviewColumnAll;
      state.columns[view] = target.checked ? new Set((COLUMN_DEFS[view] || []).map(([key]) => key)) : new Set();
      render();
      return;
    }
    if (target.matches('[data-airview-signal]')) {
      const value = Number(target.value);
      if (target.dataset.airviewSignal === 'min') state.filters.signalMin = Math.min(value, state.filters.signalMax);
      else state.filters.signalMax = Math.max(value, state.filters.signalMin);
      const control = target.closest('.airview-signal-range');
      if (control) {
        control.style.setProperty('--signal-min', `${(state.filters.signalMin + 100) / 80 * 100}%`);
        control.style.setProperty('--signal-max', `${(state.filters.signalMax + 100) / 80 * 100}%`);
        const labels = control.querySelectorAll(':scope > span');
        if (labels[0]) labels[0].textContent = String(state.filters.signalMin);
        if (labels[1]) labels[1].textContent = String(state.filters.signalMax);
      }
      patchLiveRegion();
      return;
    }
    if (target.matches('[data-airview-filter]')) {
      if (target.dataset.airviewFilter.startsWith('columns.')) {
        const view = target.dataset.airviewFilter.split('.')[1];
        const columns = state.columns[view];
        if (target.checked) columns.add(target.value); else columns.delete(target.value);
        render();
        return;
      }
      const set = state.filters[target.dataset.airviewFilter];
      if (!(set instanceof Set)) return;
      if (target.checked) set.add(target.value); else set.delete(target.value);
      patchLiveRegion();
    }
  }

  function onKeydown(event) {
    const ssidRow = event.target.closest('tr[data-wifi-ssid-select-row]');
    if (ssidRow && event.target === ssidRow && ['Enter', ' '].includes(event.key)) {
      event.preventDefault();
      const id = ssidRow.dataset.wifiSsidSelectRow;
      setSsidSelection(id, !state.selectedSsids.has(id));
      return;
    }
    const row = event.target.closest('tr[data-airview-radio-row]');
    if (!row || event.target !== row || !['Enter', ' '].includes(event.key)) return;
    event.preventDefault();
    const id = row.dataset.airviewRadioRow;
    setRadioSelection(id, !state.selectedRadios.has(id));
  }

  /* 射频表在窄容器里仍需横向滚动，而浮层滚动条会淡出、也不占高度，用户看不出
     右侧还有列（实测 1280 下最后一列在可见区外 140px）。这里给表卡标注滚动状态，
     CSS 据此在右缘画渐变提示：还能右滚时显示，滚到底淡出。
     用 data 属性而不是直接改样式，材质与几何仍然全部留在 CSS 里。 */
  function syncTableScrollHints(boundary = root) {
    if (!boundary) return;
    boundary.querySelectorAll('.airview-radio-table > .wifi-table-scroll').forEach((node) => {
      const card = node.parentElement;
      if (!card) return;
      const max = node.scrollWidth - node.clientWidth;
      if (max <= 1) { card.removeAttribute('data-scroll-x'); return; }
      card.dataset.scrollX = node.scrollLeft >= max - 1 ? 'end' : 'true';
    });
  }

  /* 容器变宽/变窄会改变是否溢出（1440 排得下、1280 需要滚），所以尺寸变化也要重算。
     5s 的局部刷新只换 .airview-results 的内容，不换它本身；render() 才会重建它，
     所以在 render() 里重新 observe 一次，避免观察一堆已被替换的滚动节点。 */
  const resultsResizeObserver = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(() => {
    if (state.mounted) syncTableScrollHints();
  });

  function onScroll(event) {
    const node = event.target;
    if (!(node instanceof HTMLElement) || !node.classList?.contains('wifi-table-scroll')) return;
    syncTableScrollHints(node.closest('.airview-results') || root);
  }

  root.addEventListener('click', onClick);
  root.addEventListener('input', onInput);
  root.addEventListener('change', onChange);
  root.addEventListener('keydown', onKeydown);
  root.addEventListener('dwrt-tab-change', onStatusTabChange);
  root.addEventListener('dwrt-segment-change', onChannelAiBandChange);
  root.addEventListener('dwrt-segment-change', onRoamingSegmentChange);
  // 滚动事件不冒泡，只能在捕获阶段拿到。
  root.addEventListener('scroll', onScroll, true);
  stage?.classList.add('is-wifi-management');
  render();
  load();
  state.refreshTimer = window.setInterval(() => {
    if (!state.mounted || document.hidden || state.refreshing || state.scanning) return;
    /*
     * 抽屉开着时不后台刷新。`state.sheet` 只覆盖配置侧那些抽屉，AP 详情抽屉走的是
     * `state.apSheetAp`（见 apDetailsSheet()），漏掉它意味着 5s 轮询会在详情抽屉开着时
     * 重绘宿主。重绘落在关闭动画的 480ms 内，就会把关闭按钮换掉，抽屉的第二拍丢失，
     * 遮罩留在 portal 里吞掉全部点击。kit 侧已经有兜底，这里把触发源一并堵上。
     */
    if (state.dirty || state.roaming.dirty || state.radioDirty || state.saving || state.roaming.saving || state.sheet || state.apSheetAp || state.confirmSsidDelete || state.ssidBusy) return;
    /*
     * AP 管理 Tab 走自己的端点，所以后台刷新也走 loadAc。
     * 确认弹窗打开或写请求在飞时不刷，避免把用户正在看的确认对话重建掉。
     * 发现向导同理：它是弹层，重建会把用户正在读的雷达状态与候选卡片换掉，而
     * loadAc(true) 里的 loadAcDiscovery() 又会覆盖向导刚扫到的那份候选清单。
     */
    if (!isStatus && state.configView === 'aps') {
      if (state.acBusy || state.apWizard || state.confirmToken || state.discoveryCandidate || state.discoveryBusy || state.adoption.bindingId || state.ac.loading) return;
      loadAc(true);
      return;
    }
    load(true);
  }, isStatus ? 5000 : 20000);

  return {
    refresh() { return load(true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      state.channelAi.seq += 1;
      state.ac.seq += 1;
      state.adoption.pollSeq += 1;
      clearBootstrapTimers();
      state.adoption.bindingId = '';
      state.adoption.secret = null;
      state.adoption.command = '';
      state.tokenSecret = null;
      state.confirmToken = null;
      state.confirmSsidDelete = null;
      state.discoveryCandidate = null;
      state.apWizard = false;
      state.apWizardScanning = false;
      state.apWizardScannedAt = 0;
      state.environmentHistorySeq += 1;
      state.scanEpoch += 1;
      if (state.refreshTimer) clearInterval(state.refreshTimer);
      if (state.scanTimer) clearTimeout(state.scanTimer);
      if (state.scanWaitResolve) state.scanWaitResolve();
      state.scanWaitResolve = null;
  root.removeEventListener('click', onClick);
      root.removeEventListener('input', onInput);
      root.removeEventListener('change', onChange);
      root.removeEventListener('keydown', onKeydown);
      root.removeEventListener('dwrt-tab-change', onStatusTabChange);
      root.removeEventListener('dwrt-segment-change', onChannelAiBandChange);
      root.removeEventListener('dwrt-segment-change', onRoamingSegmentChange);
      root.removeEventListener('scroll', onScroll, true);
      resultsResizeObserver?.disconnect();
      const sidebarTabs = root.querySelector('.airview-view-tabs');
      if (sidebarTabs) window.DWRT_UI_KIT?.unmount?.(sidebarTabs);
      root.replaceChildren();
      root.classList.remove('route-workspace', 'policy-table-route-host', 'wifi-management-route-host', 'wireless-status-route-host', 'wifi-config-route-host');
      stage?.classList.remove('is-wifi-management');
    }
  };
}

export default { mount };
