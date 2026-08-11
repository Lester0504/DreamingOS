(() => {
  'use strict';

  const VERSION = '20260810-insights-audit-poll-stability-02';
  const PERIODS = {
    hour: { label: '1 小时', api: 'hour', ms: 3600000 },
    day: { label: '1 天', api: 'day', ms: 86400000 },
    week: { label: '1 周', api: 'week', ms: 604800000 },
    month: { label: '1 月', api: 'month', ms: 2592000000 },
    custom: { label: '自定义', api: 'custom', ms: 86400000 }
  };
  const ACTIVITY_PERIODS = {
    halfHour: { label: '30 分钟', api: '30m', ms: 1800000 },
    hour: PERIODS.hour,
    day: PERIODS.day,
    week: PERIODS.week,
    month: PERIODS.month,
    custom: PERIODS.custom
  };
  const RISK_LEVELS = [
    { id: 'low', label: '低' },
    { id: 'suspicious', label: '可疑' },
    { id: 'concern', label: '令人担忧' }
  ];
  const FILTER_GROUPS = [
    ['source', '源'],
    ['source_zone', '源区域'],
    ['source_network', '源网络'],
    ['source_mac', '源 MAC'],
    ['source_ip', '源 IP'],
    ['source_port', '源端口'],
    ['source_region', '源地区'],
    ['destination', '目标'],
    ['destination_zone', '目标区域'],
    ['destination_network', '目标网络'],
    ['destination_mac', '目标 MAC'],
    ['destination_ip', '目标 IP'],
    ['destination_port', '目标端口'],
    ['destination_region', '目标地区'],
    ['service', '服务'],
    ['protocol', '协议'],
    ['in_interface', '传入接口'],
    ['out_interface', '传出接口'],
    ['policy', '策略'],
    ['policy_type', '策略类型']
  ];
  const DEFAULT_COLUMNS = [
    ['time', '时间'],
    ['risk', '风险'],
    ['action', '动作'],
    ['source', '源'],
    ['destination', '目标'],
    ['service', '服务'],
    ['protocol', '协议'],
    ['traffic', '流量'],
    ['policy', '策略']
  ];
  const ENDPOINTS = {
    summary: (period, range) => `/api/v1/insights/flows/summary?period=${encodeURIComponent(period)}&top=30${range ? `&timestampFrom=${encodeURIComponent(range.timestampFrom)}&timestampTo=${encodeURIComponent(range.timestampTo)}` : ''}`,
    flows: '/api/v1/insights/flows',
    filters: '/api/v1/insights/flows/filter-data?inputSize=10000&outputSize=1000&skipElements=0',
    geo: (period, range, scope = 'world') => `/api/v1/insights/flows/geo?period=${encodeURIComponent(period)}&scope=${encodeURIComponent(scope)}&map_scope=${encodeURIComponent(scope)}${range ? `&timestampFrom=${encodeURIComponent(range.timestampFrom)}&timestampTo=${encodeURIComponent(range.timestampTo)}` : ''}`,
    networkWans: '/api/v1/network/wans',
    activityTraffic: (from, to) => `/api/v1/insights/activity/traffic?start=${encodeURIComponent(from)}&end=${encodeURIComponent(to)}&includeUnidentified=true`,
    activityRate: (from, to) => `/api/v1/insights/activity/app-traffic-rate?start=${encodeURIComponent(from)}&end=${encodeURIComponent(to)}&includeUnidentified=true`,
    auditStatus: '/api/v1/audit/status',
    auditUrls: (params) => `/api/v1/audit/urls?${params}`,
    auditOnlineRecords: (params) => `/api/v1/audit/online-records?${params}`,
    auditImRecords: (params) => `/api/v1/audit/im-records?${params}`,
    auditProtocols: (params) => `/api/v1/audit/protocols?${params}`,
    auditApps: (params) => `/api/v1/audit/apps?${params}`
  };
  const LOCAL_MAP_ASSETS = {
    world: '/static/maps/world.json',
    china: '/static/maps/china.json'
  };
  const LOCAL_MAP_VERSION = 'fastmonitor-apache2-20260709';
  const CYBER_ROUTE_LIMIT = 18;
  /*
   * 地图的两个视觉通道必须各用一族颜色，绝不共用琥珀/红。
   *
   * 用户 2026-08-09：地图里的黄色被读成上方摘要的「可疑」，而地图的黄色其实是
   * 「入站」。同一屏用同一族颜色表达两套语义就必然被误读，所以这里把职责拆开：
   *   风险 → 颜色（未评级中性青 / 低绿 / 可疑琥珀 / 令人担忧红），与摘要三档同源
   *   方向 → 形状（弧的弯向 + 箭头符号 + 光点方向），不占用颜色
   *   流量 → 亮度/粗细/点径（同一色相的深浅），不借用风险语义色
   * 风险色刻意与 `.insights-console-dot` 的 `--dwrt-ok/warn/bad` 对齐，
   * 保证「地图上这一档的颜色」和「摘要里这一档的颜色」指的是同一件事。
   */
  const MAP_RISK_COLORS = {
    unknown: { line: '#39d9ff', packet: '#effbff', label: '未评级' },
    low: { line: '#30d158', packet: '#c9ffd9', label: '低' },
    suspicious: { line: '#ff9f0a', packet: '#ffe0ad', label: '可疑' },
    concern: { line: '#ff453a', packet: '#ffc9c5', label: '令人担忧' }
  };
  /* 本机出口不是一个「风险等级」，它是拓扑里的自己，用独立的青绿标识。 */
  const MAP_LOCAL_COLOR = '#27f0a8';

  /* 弧/点的风险档。后端 `flows/geo` 的每条 route 与每个 region 都带 `risk_level`
     与 `risk`（实测 30/30 条 `risk_supported: true`）。缺字段或 unknown 一律落到
     未评级——`risk_unknown_meaning` 自述为「目的地不在已加载情报源中，并非判定为
     安全」，所以未评级绝不能画成「低」。 */
  function mapRiskBucket(source) {
    if (!source || typeof source !== 'object') return 'unknown';
    const raw = source.risk_level !== undefined && source.risk_level !== null && source.risk_level !== ''
      ? source.risk_level
      : source.risk;
    const text = String(raw === undefined || raw === null ? '' : raw).toLowerCase();
    if (!text || text === 'unknown' || text === 'unrated' || text === 'none') return 'unknown';
    if (/concern|high|very|critical|severe|严重|高|令人/.test(text)) return 'concern';
    if (/suspicious|medium|moderate|可疑|中/.test(text)) return 'suspicious';
    if (/low|safe|clean|低/.test(text)) return 'low';
    return 'unknown';
  }

  function mapRiskPalette(bucket) {
    return MAP_RISK_COLORS[bucket] || MAP_RISK_COLORS.unknown;
  }

  /*
   * 合并后的弧只有一个颜色，取值必须保守：
   *   有任一条评到 concern/suspicious 就按最坏档画，否则一条高风险目的地会被
   *   一堆同坐标的普通流量「洗白」；
   *   「低 + 未评级」合成未评级而不是低 —— 未评级的含义是没查过，把它算进低
   *   等于替情报源下结论。
   */
  const MAP_RISK_ORDER = { unknown: 0, low: 1, suspicious: 2, concern: 3 };

  /* 发光色跟随点位色。写死一个青色阴影会让绿点/红点都带青边，档位之间反而更难分。 */
  function hexToRgba(hex, alpha) {
    const text = String(hex || '').trim().replace('#', '');
    const full = text.length === 3 ? text.split('').map((ch) => ch + ch).join('') : text;
    if (!/^[0-9a-fA-F]{6}$/.test(full)) return `rgba(57, 217, 255, ${alpha})`;
    const value = parseInt(full, 16);
    return `rgba(${(value >> 16) & 255}, ${(value >> 8) & 255}, ${value & 255}, ${alpha})`;
  }

  function mergeRiskBuckets(a, b) {
    const left = MAP_RISK_COLORS[a] ? a : 'unknown';
    const right = MAP_RISK_COLORS[b] ? b : 'unknown';
    if (left === right) return left;
    const worst = MAP_RISK_ORDER[left] >= MAP_RISK_ORDER[right] ? left : right;
    if (worst === 'low') return 'unknown';
    return worst;
  }
  /* The map does not need a 250ms refresh rate. Kept clear of the 420ms update
     animation so one animation finishes before the next render starts. */
  const MAP_RENDER_MIN_INTERVAL = 1000;
  const mapRender = { frame: 0, timer: 0, lastAt: 0 };

  const FILTER_BODY_KEYS = {
    source: 'source_host',
    source_zone: 'source_zone_id',
    source_network: 'source_network_id',
    source_mac: 'source_mac',
    source_ip: 'source_ip',
    source_port: 'source_port',
    source_region: 'source_region',
    destination: 'destination_host',
    destination_zone: 'destination_zone_id',
    destination_network: 'destination_network_id',
    destination_mac: 'destination_mac',
    destination_ip: 'destination_ip',
    destination_port: 'destination_port',
    destination_region: 'destination_region',
    service: 'service',
    protocol: 'protocol',
    in_interface: 'in_network_id',
    out_interface: 'out_network_id',
    policy: 'policy',
    policy_type: 'policy_type'
  };

  function create(options) {
    const {
      routePreview,
      fetchApiResource,
      scheduleGlassCardsRender,
      mountUiKit,
      escapeHtml = (value) => String(value ?? ''),
      asArray = (value) => Array.isArray(value) ? value : [],
      firstText = (...values) => values.find((value) => value !== undefined && value !== null && String(value) !== '') || '',
      firstNumber = (...values) => {
        for (const value of values) {
          const number = Number(value);
          if (Number.isFinite(number)) return number;
        }
        return 0;
      },
      formatBytes = (value) => String(value || 0),
      formatInteger = (value) => String(Math.round(Number(value) || 0)),
      formatRate = (value) => String(value || 0),
      realtime = window.DWRTRealtime,
      authHeaders = () => ({})
    } = options || {};

    const state = {
      mode: 'flows',
      period: 'day',
      summaryEnabled: true,
      mapEnabled: true,
      mapScope: 'world',
      /* Per-scope geo cache. Switching world/china used to null state.geo, so
         every switch was a cold start; a visited scope now renders from cache
         while it refreshes in the background. */
      geoByScope: { world: null, china: null },
      /* Geo fetch state for the map area only. The scope switch paints from
         cache immediately, which means a slow or failed geo request leaves no
         trace on screen: the old map just sits there looking current. This
         drives an indicator inside the map shell, so a stall reads as "still
         loading" rather than as fresh data. 'idle' | 'loading' | 'error'. */
      mapFetch: 'idle',
      mapFetchError: '',
      activityStatMetric: 'total',
      activityAnchor: 'client',
      activitySection: 'overview',
      /* The 统计 switch: off hides the traffic chart and leaves the table alone
         with the full board height. Mirrors mapEnabled on the flows tab. */
      activityChartEnabled: true,
      trafficKind: 'all',
      risks: new Set(),
      actions: new Set(),
      direction: '',
      search: '',
      filtersSelected: {},
      filterModes: {},
      filterSearch: {},
      filterSelectedOpen: {},
      customRange: null,
      collapsed: new Set(FILTER_GROUPS.map(([id]) => id)),
      columns: new Set(DEFAULT_COLUMNS.map(([id]) => id)),
      summary: null,
      flows: [],
      filters: null,
      filtersLoadedAt: 0,
      filtersLoading: false,
      filtersPromise: null,
      geo: null,
      networkWans: null,
      activityTraffic: null,
      activityRate: null,
      audit: {
        status: null,
        urls: null,
        onlineRecords: null,
        imRecords: null,
        protocols: null,
        apps: null,
        loading: false,
        errors: {},
        query: {}
      },
      loading: false,
      errors: [],
      notice: '',
      root: null,
      refreshTimer: 0,
      auditPollTimer: 0,
      refreshSeq: 0,
      realtimeUnsubscribers: [],
      realtimeTopicsKey: '',
      pendingRealtime: new Map(),
      realtimeFrameTimer: 0,
      lastWsAtByTopic: new Map(),
      realtimeStatus: null,
      mapViews: {},
      hydratedModes: new Set(),
      mounted: false
    };

    const html = (value) => escapeHtml(value);
    const cssEscape = (value) => {
      if (window.CSS && typeof window.CSS.escape === 'function') return window.CSS.escape(String(value));
      return String(value).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
    };
    const period = () => (state.mode === 'activity' ? ACTIVITY_PERIODS[state.period] : PERIODS[state.period]) || PERIODS.day;
    const nowRange = () => {
      const to = Date.now();
      if (state.period === 'custom' && state.customRange) {
        return { timestampFrom: state.customRange.start, timestampTo: state.customRange.end };
      }
      return { timestampFrom: to - period().ms, timestampTo: to };
    };
    const apiSecondsRange = (range) => ({
      timestampFrom: Math.floor(Number(range.timestampFrom) / 1000),
      timestampTo: Math.floor(Number(range.timestampTo) / 1000)
    });
    const apiPeriod = () => period().api;
    const queryPeriod = () => state.period === 'custom' ? 'day' : apiPeriod();
    const isAuditActivitySection = () => state.mode === 'activity' && state.activitySection && state.activitySection !== 'overview';

    function normalizePayload(result) {
      if (!result || !result.ok) return null;
      return result.data || result.raw && (result.raw.data || result.raw.body) || result.raw || {};
    }

    function unwrapRealtimePayload(data) {
      let payload = data;
      for (let index = 0; index < 4; index += 1) {
        if (!payload || typeof payload !== 'object' || Array.isArray(payload)) break;
        const next = payload.data ?? payload.body ?? payload.payload ?? payload.snapshot ?? null;
        if (!next || next === payload) break;
        payload = next;
      }
      return payload || {};
    }

    function asList(payload, keys = ['items', 'data', 'results', 'records', 'rows']) {
      if (Array.isArray(payload)) return payload;
      if (!payload || typeof payload !== 'object') return [];
      for (const key of keys) {
        if (Array.isArray(payload[key])) return payload[key];
      }
      return [];
    }

    function riskClass(value) {
      const text = String(value || '').toLowerCase();
      if (/concern|high|very|critical|严重|高|令人/.test(text)) return 'concern';
      if (/suspicious|medium|可疑|中/.test(text)) return 'suspicious';
      if (/low|低/.test(text)) return 'low';
      return '';
    }

    function riskLabel(value) {
      const cls = riskClass(value);
      if (cls === 'concern') return '令人担忧';
      if (cls === 'suspicious') return '可疑';
      if (cls === 'low') return '低';
      return firstText(value, '--');
    }

    function actionLabel(value) {
      const text = String(value || '').toLowerCase();
      if (/block|deny|drop|reject|拦截|阻止/.test(text)) return '已拦截';
      if (/allow|accept|pass|允许/.test(text)) return '允许';
      return firstText(value, '--');
    }

    function bytesOf(item) {
      /*
       * 后端给的 `bytes` 已经是双向合计，不是单向的。实测 30.1 `flows/summary`
       * 与 `flows/geo` 的每一条都满足 `bytes == rx_bytes + tx_bytes`
       * （目的地 30/30、客户端 4/4、应用 30/30、geo regions 20/20），
       * 所以旧写法 `bytes + tx_bytes` 把上行又加了一遍：114.114.114.114
       * 真实 94,016 被算成 130,953，down.debian7.com 33,146,677 被算成
       * 33,766,949。榜单里字节越大的条目虚高越多，合计也就永远对不上
       * `top_all_count_by_destination` 的字节合计。
       *
       * 正确取法：有显式合计就直接用，只有在没有合计字段时才用 rx + tx 拼。
       */
      const total = firstNumber(item.bytes, item.total_bytes, item.traffic_bytes);
      if (total) return total;
      return firstNumber(item.rx_bytes) + firstNumber(item.tx_bytes);
    }

    function countFromObject(map) {
      if (!map || typeof map !== 'object') return 0;
      return Object.values(map).reduce((sum, value) => sum + firstNumber(value), 0);
    }

    /*
     * firstNumber() returns the first *finite* value, and both Number(null) and
     * Number('') are 0, which is finite. So an absent-but-present key stops the
     * chain and later aliases never get a turn. presentNumber() skips values
     * that are not actually there, so a real 0 still counts while undefined /
     * null / '' fall through to the next candidate.
     */
    function presentNumber(...values) {
      for (const value of values) {
        if (value === undefined || value === null || value === '') continue;
        const number = Number(value);
        if (Number.isFinite(number)) return number;
      }
      return 0;
    }

    /* First scope that actually carries one of these keys. Prevents an empty
       earlier scope from resolving a bucket to 0 and hiding a populated one. */
    function scopeWith(scopes, keys) {
      for (const scope of scopes) {
        if (!scope || typeof scope !== 'object') continue;
        if (keys.some((key) => scope[key] !== undefined && scope[key] !== null && scope[key] !== '')) return scope;
      }
      return {};
    }

    const RISK_LOW_KEYS = ['low', 'LOW'];
    const RISK_SUSPICIOUS_KEYS = ['suspicious', 'SUSPICIOUS', 'medium', 'MEDIUM'];
    const RISK_SEVERE_KEYS = ['concerning_or_high', 'CONCERNING_OR_HIGH', 'concerning', 'CONCERNING',
      'concern', 'CONCERN', 'high', 'HIGH', 'very_high', 'VERY_HIGH'];

    const readRiskLow = (scope) => presentNumber(scope.low, scope.LOW);
    const readRiskSuspicious = (scope) => presentNumber(scope.suspicious, scope.SUSPICIOUS, scope.medium, scope.MEDIUM);
    /*
     * The third card is "concerning + high", not "whichever of them we see
     * first". Those are two distinct buckets, while `concern` is merely the
     * backend's alias for `concerning` and must not be added on top of it.
     * Prefer the backend's precomputed `concerning_or_high` (it cannot
     * double-count); fall back to summing the two sides explicitly, picking
     * each side's aliases by first-present. Reading these with a single
     * first-finite chain is what let concerning=0 shadow a real high count.
     */
    const readRiskSevere = (scope) => presentNumber(
      scope.concerning_or_high,
      scope.CONCERNING_OR_HIGH,
      presentNumber(scope.concerning, scope.CONCERNING, scope.concern, scope.CONCERN)
        + presentNumber(scope.high, scope.HIGH, scope.very_high, scope.VERY_HIGH)
    );

    function summaryCounts() {
      const data = state.summary || {};
      const allowed = data.allowed_count_by_risk || data.allowed || {};
      const blocked = data.blocked_count_by_risk || data.blocked || {};
      const all = data.all_count_by_risk || data.risk || data.risk_breakdown || {};
      /* Every risk source being absent is not the same as a real count of zero.
         Rendering 0 there claims "no risky traffic" when the truth is "the
         backend never sent this", so the card has to be able to say so. */
      const hasRiskSource = [data.all_count_by_risk, data.risk, data.risk_breakdown, data.allowed_count_by_risk, data.blocked_count_by_risk]
        .some((source) => source && typeof source === 'object')
        || [data.low, data.suspicious, data.medium, data.concern, data.high].some((value) => Number.isFinite(Number(value)) && value !== null && value !== '');
      const low = readRiskLow(scopeWith([data, all, allowed], RISK_LOW_KEYS)) + readRiskLow(blocked);
      const suspicious = readRiskSuspicious(scopeWith([data, all, allowed], RISK_SUSPICIOUS_KEYS)) + readRiskSuspicious(blocked);
      const concern = readRiskSevere(scopeWith([data, all, allowed], RISK_SEVERE_KEYS)) + readRiskSevere(blocked);
      const total = firstNumber(data.total, data.total_count, data.flow_count, countFromObject(data.all_count_by_region), countFromObject(allowed) + countFromObject(blocked), low + suspicious + concern, state.flows.length);
      return { total, low, suspicious, concern, supported: hasRiskSource };
    }

    function topList(keys) {
      const data = state.summary || {};
      for (const key of keys) {
        const value = data[key];
        if (Array.isArray(value)) return value;
      }
      return [];
    }

    function hasTrafficBytes(item) {
      if (!item || typeof item !== 'object') return false;
      return item.bytes !== undefined || item.rx_bytes !== undefined || item.tx_bytes !== undefined ||
        item.total_bytes !== undefined || item.traffic_bytes !== undefined || item.download_bytes !== undefined || item.upload_bytes !== undefined;
    }

    function topItemCount(item) {
      return firstNumber(item && item.count, item && item.flow_count, item && item.total, item && item.value, item && item.client_count, item && item.requests);
    }

    function topItemKey(item, kind) {
      if (!item || typeof item !== 'object') return '';
      if (kind === 'client') {
        return firstText(item.client_name, item.hostname, item.name, item.display_name, item.remark, item.label, item.mac, item.client_mac, item.source_mac, item.client_id, item.id, item.ip, item.client_ip).toLowerCase();
      }
      if (kind === 'destination') {
        return firstText(item.city, item.city_name, item.region_name, item.region, item.country_name, item.country, item.country_code, item.destination, item.destination_host, item.domain, item.host, item.ip, item.name, item.label).toLowerCase();
      }
      if (kind === 'application') {
        return firstText(item.application_id, item.app_id, item.application, item.app_name, item.app, item.name, item.label).toLowerCase();
      }
      return firstText(item.id, item.name, item.label).toLowerCase();
    }

    function dedupeTopItems(items, kind) {
      const grouped = new Map();
      (items || []).forEach((item) => {
        if (!item || typeof item !== 'object') return;
        const label = topItemName(item, kind);
        const key = topItemKey(item, kind) || String(label || '').toLowerCase();
        if (!key || key === '--') return;
        const current = grouped.get(key);
        if (!current) {
          grouped.set(key, { ...item, __top_label: label, __top_has_bytes: hasTrafficBytes(item) });
          return;
        }
        if (current.__top_has_bytes || hasTrafficBytes(item)) {
          current.bytes = bytesOf(current) + bytesOf(item);
          current.__top_has_bytes = true;
        }
        current.count = topItemCount(current) + topItemCount(item);
        current.flow_count = firstNumber(current.flow_count) + firstNumber(item.flow_count);
        current.total = firstNumber(current.total) + firstNumber(item.total);
        if (!current.__top_label || current.__top_label === '--') current.__top_label = label;
      });
      return Array.from(grouped.values()).sort((a, b) => {
        const bytesDelta = bytesOf(b) - bytesOf(a);
        if (bytesDelta) return bytesDelta;
        return topItemCount(b) - topItemCount(a);
      });
    }

    function geoDestinationLabel(point) {
      if (!point || typeof point !== 'object') return '';
      const city = firstText(point.city, point.city_name, point.cityName, point.locality);
      const province = firstText(point.province, point.province_name, point.region_name, point.subdivision, point.subdivision_name, point.state);
      const country = firstText(point.country_name, point.country, point.region, point.name, point.label);
      if (city && province && city !== province) return `${city} · ${province}`;
      return firstText(city, province, country, point.country_code, point.ip, point.public_ip);
    }

    /*
     * 「热门目的地」的地点名。用户 2026-08-04：「目的地应该是地方，例如美国洛杉矶」。
     *
     * 拼法是「国家 + 城市」，两者相同时不重复（香港 / 新加坡这类城邦实测
     * `country_name` 与 `city_name` 都是「香港」「新加坡」，拼出来会变成「香港香港」）。
     * 城市缺失时退到省/州，再退到只有国家 —— 实测美国那条就没有 city_name，
     * 只能显示「美国」，这是 GeoIP 库的粒度问题，不是这里少读了字段。
     */
    function geoPlaceLabel(point) {
      if (!point || typeof point !== 'object') return '';
      const country = firstText(point.country_name, point.country_cn, point.country);
      const city = firstText(point.city_name, point.city, point.cityName, point.locality);
      const area = firstText(point.province_name, point.region_name, point.subdivision_name, point.province);
      const local = firstText(city, area !== country ? area : '');
      if (country && local && local !== country) return `${country}${local}`;
      return firstText(country, local, point.country_code, '--');
    }

    /*
     * 「热门目的地」的字节只能来自摘要，不能来自 geo 点位。
     *
     * 原先这里还有一个 `geoDestinationItems()`，把 geo 点位包装成列表项。
     * 它已随本次修复一并删除：留着它，下一次「地图有数据就优先用地图」的三元表达式
     * 就会被重新写回来。geo 点位现在只服务地图渲染（`mapPoints()` / `mapDisplayPoints()`）。
     *
     * geo 点位的 bytes 是后端按 `history_sample_limit:100` 采样累加出来的
     * （实测 176 行样本 / 全窗口 300165 条 = 0.06%），响应里
     * `capabilities.byte_accounting_exact:false` 与 `exact_window_bytes:false`
     * 已明确声明这是采样值。实测同一时刻：geo 点位合计 2,024,295 字节，
     * 而 `top_all_count_by_destination` 合计 15,591,142（本轮复测 42,095,511）,
     * 所以旧写法把 15MB 显示成不到 2MB —— 用户原话「别告诉我这个路由器这么多天
     * 上网数据不到 1M」。
     *
     * 维度也不是一回事：geo 是国家/地区（CN、US、SG），摘要是目的主机
     * （ports.debian13.com、114.114.114.114）。卡片叫「热门目的地」就必须给主机维度。
     */
    function destinationTopItems() {
      /*
       * 用户 2026-08-04：「目的地应该是地方，例如美国洛杉矶」。
       * 所以这张卡是地理维度。口径**跟随后端的自述字段，而不是写死**：
       *
       * 后端 2026-08-05 已把 region 字节改成全窗口精确聚合，同一份响应里自己声明了
       * （30.1 实测）：
       *
       *   region_byte_source                 audit_flow_geo_summary_window_exact
       *   bytes_are_sample_only              false
       *   geo_region_bytes_window_exact      true
       *   capabilities.byte_accounting_exact true
       *   逐条 bytes_field_to_display        "bytes"      （另有 bytes_sampled 仅供诊断）
       *
       * 实测 regions 字节合计 75,093,167 对 window_bytes 75,454,736（差值是 unmappable
       * 的零头），已经不是当初那个 2,024,295 的采样值。所以精确时必须显示字节 —— 
       * 继续只报流数反而是另一种失真。
       *
       * 流数则相反：`flow_count` 是坐标采样行的条数（实测合计 192，
       * `coordinate_sample_rows: 176`），而 `window_flow_count` 才是全窗口
       * （合计 30,812 对 window_flow_rows 31,108）。旧写法把 60 条显示成美国一天的
       * 全部流量，同样是拿采样值冒充总量。排序与显示都改用窗口值，缺失时才退回采样值。
       */
      const regions = asArray((state.geo && (state.geo.regions || state.geo.points)) || []);
      if (!regions.length) return [];
      /* 精确性由后端说，不由前端假设；采样时不显示字节，只报流数并打标。 */
      const sampled = geoBytesAreSampled();
      const merged = new Map();
      regions.forEach((region) => {
        const label = geoPlaceLabel(region);
        if (!label || label === '--') return;
        const key = `${firstText(region.country_code)}|${label}`;
        const current = merged.get(key);
        /* 窗口流数优先；`window_flow_count` 缺失的条目（实测 20 条里有 6 条）
           才退回采样流数，此时它就是这条已知的全部。 */
        const count = firstNumber(region.window_flow_count, region.flow_count, region.count);
        const bytes = firstNumber(region.bytes, region.total_bytes);
        if (current) {
          current.flow_count += count;
          current.count = current.flow_count;
          current.bytes += bytes;
          return;
        }
        merged.set(key, {
          ...region,
          __top_label: label,
          /* 这个标记控制「是否禁止显示字节」，所以只在后端自述采样时才打。 */
          __geo_sampled: sampled,
          flow_count: count,
          count,
          bytes,
          /* 精确时按字节排名（与显示的指标一致，进度条才不会和列表顺序打架）。 */
          metric_type: sampled ? 'flow_count' : 'bytes'
        });
      });
      return Array.from(merged.values()).sort((left, right) => (
        sampled ? right.flow_count - left.flow_count : bytesOf(right) - bytesOf(left)
      ));
    }

    /* 主机维度不再占用「热门目的地」这张卡，但数据本身仍要能看见。 */
    function destinationHostTopItems() {
      /* `top_destinations` 已被后端移除（`capabilities.deprecated_response_keys`），
         留着是死候选，会让人以为后端还在发。排在最前的保留键必须留下：
         topList() 取第一个命中的候选，删错顺序就取不到值。 */
      return dedupeTopItems(topList(['top_all_count_by_destination', 'top_all_named_count_by_destination', 'destinations']), 'destination');
    }

    /*
     * geo 不可用时（没装 MMDB、或全是私网流量）不能让这张卡变空白 —— 那会比
     * 显示主机榜更糟。此时退回主机维度，指标口径也跟着回到摘要的精确字节。
     */
    function destinationCardItems() {
      const places = destinationTopItems();
      return places.length ? places : destinationHostTopItems();
    }

    /*
     * 卡片头部的口径徽标。三种情形各有各的说法，不能共用一句话：
     *
     *   地点榜 + 后端声明精确   不标（字节就是全窗口值，标「抽样」等于自我否定）
     *   地点榜 + 后端声明采样   标「抽样」，此时列表也只报流数不报字节
     *   主机回退               标「主机」，说明这一屏不是地点维度
     */
    function destinationCardNote() {
      if (destinationTopItems().length) return geoBytesAreSampled() ? '抽样' : '';
      return '';
    }

    /*
     * geo 字节是不是采样值，只能由后端自述决定。
     *
     * 判据要同时看两处：顶层（`bytes_are_sample_only` / `region_byte_source` /
     * `geo_region_bytes_window_exact`）和 `capabilities`。旧写法只读
     * `capabilities`，而 2026-08-05 之后后端把结论放在顶层，`capabilities` 里
     * 另有一组作用域不同的标记；只读一半就会把已经精确的数据继续当采样值。
     *
     * 三态而非两态：明确说采样 → 采样；明确说精确 → 精确；两者都没有 → 按采样处理。
     * 未知时保守，是因为把采样字节当成全窗口用量正是「不到 1M」那个缺陷的成因，
     * 反过来只是少显示一个字节数，代价小得多。
     */
    function geoBytesAreSampled() {
      const data = state.geo || {};
      const caps = data.capabilities || {};
      /* 任一处明确声明采样即为采样。 */
      if (data.bytes_are_sample_only === true || caps.bytes_are_sample_only === true) return true;
      if (data.region_bytes_sample_only === true || caps.region_bytes_sample_only === true) return true;
      if (caps.geo_region_bytes_are_sample_only === true) return true;
      /* 再看是否明确声明精确。`region_byte_source` 实测为
         `audit_flow_geo_summary_window_exact`。 */
      if (data.geo_region_bytes_window_exact === true || caps.geo_region_bytes_window_exact === true) return false;
      if (/window_exact/.test(String(data.region_byte_source || caps.geo_region_byte_source || ''))) return false;
      if (caps.byte_accounting_exact === true && caps.exact_window_bytes === true) return false;
      if (data.bytes_are_sample_only === false && caps.byte_accounting_exact !== false) return false;
      /* 未表态：按采样处理，不显示字节。 */
      return true;
    }

    function flowItems(payload) {
      if (!payload) return [];
      if (Array.isArray(payload)) return payload;
      for (const key of ['items', 'flows', 'data', 'results', 'records']) {
        if (Array.isArray(payload[key])) return payload[key];
      }
      return [];
    }

    function filterValues(groupId) {
      const data = state.filters || {};
      const source = data.source || {};
      const destination = data.destination || {};
      const keys = {
        source: [source.hosts, data.source_hosts],
        source_zone: [data.source_zones, data.zones],
        source_network: [data.source_networks, data.networks],
        source_mac: [source.macs, data.source_macs],
        source_ip: [source.ips, data.source_ips],
        source_port: [source.ports, data.source_ports],
        source_region: [data.source_regions, data.regions],
        destination: [destination.hosts, data.destination_hosts],
        destination_zone: [data.destination_zones, data.zones],
        destination_network: [data.destination_networks, data.networks],
        destination_mac: [destination.macs, data.destination_macs],
        destination_ip: [destination.ips, data.destination_ips],
        destination_port: [destination.ports, data.destination_ports],
        destination_region: [data.destination_regions, data.regions],
        service: [data.services, data.service],
        protocol: [data.protocols, data.protocol],
        in_interface: [data.in_interfaces, data.in_networks],
        out_interface: [data.out_interfaces, data.out_networks],
        policy: [data.policies, data.policy],
        policy_type: [data.policy_types, uniquePolicyTypes(data.policies)]
      }[groupId] || [];
      return dedupeFilterItems(keys.flatMap((value) => Array.isArray(value) ? value : []));
    }

    function mapPoints() {
      const data = state.geo || {};
      if (state.mapScope === 'china' && !geoPayloadMatchesScope(data, 'china')) return [];
      const points = asArray(data.points || data.regions || data.items || data.countries);
      if (points.length) {
        return points
          .filter(hasMappablePosition)
          .filter((point) => state.mapScope !== 'china' || isChinaScopedMapPoint(point));
      }
      if (state.mapScope === 'china') return [];
      const regionMap = (state.summary && state.summary.all_count_by_region) || {};
      return Object.entries(regionMap)
        .map(([region, count]) => ({ region, count }))
        .filter(hasMappablePosition);
    }

    function localMapPoint() {
      if (state.mapScope === 'china' && !geoPayloadMatchesScope(state.geo, 'china')) return null;
      const point = extractLocalMapPoint(state.geo, state.summary, state.networkWans, mapPoints());
      if (state.mapScope === 'china' && !isChinaScopedMapPoint(point)) return null;
      return point;
    }

    function mapDisplayPoints() {
      const local = localMapPoint();
      const seen = new Set();
      const result = [];
      if (local) {
        result.push(local);
        seen.add(mapPointIdentity(local));
      }
      mapPoints().forEach((point) => {
        const identity = mapPointIdentity(point);
        if (identity && seen.has(identity)) return;
        if (local && mapPositionsEqual(point, local)) return;
        if (identity) seen.add(identity);
        result.push(point);
      });
      return result;
    }

    function mapRouteItems() {
      const routes = buildMapRoutes(state.geo, state.mapScope === 'china' ? null : state.summary, mapPoints(), localMapPoint());
      const scoped = state.mapScope === 'china'
        ? routes.filter((route) => isChinaScopedMapPoint(route.from) && isChinaScopedMapPoint(route.to))
        : routes;
      /* 后端声明 `route_aggregation_supported` 时，聚合已经在服务端按语义键做完，
         前端只负责把同坐标的多条弧视觉上分开；否则退回本地的分桶 + 角距合并。 */
      return aggregateMapRoutes(
        scoped,
        state.mapScope === 'china' ? 'china' : 'world',
        { backendAggregated: routeAggregationSupported(state.geo) }
      );
    }

    function selectedValues(groupId) {
      const values = state.filtersSelected[groupId];
      return values instanceof Set ? Array.from(values) : [];
    }

    function filterMode(groupId) {
      return state.filterModes[groupId] === 'exclude' ? 'exclude' : 'include';
    }

    function filterSearch(groupId) {
      return String(state.filterSearch[groupId] || '');
    }

    function flowRequestBody() {
      const { timestampFrom, timestampTo } = nowRange();
      const risks = Array.from(state.risks);
      const actions = Array.from(state.actions);
      const kindAction = state.trafficKind === 'blocked' ? ['blocked'] : [];
      const kindRisk = state.trafficKind === 'threat' && risks.length === 0 ? ['suspicious', 'concern'] : [];
      const body = {
        timestampFrom,
        timestampTo,
        pageNumber: 0,
        search_text: state.search,
        pageSize: 100,
        skip_count: false
      };
      const riskFilter = [...new Set([...risks, ...kindRisk])];
      const actionFilter = [...new Set([...actions, ...kindAction])];
      if (riskFilter.length) body.risk = riskFilter;
      if (actionFilter.length) body.action = actionFilter;
      if (state.direction) body.direction = [state.direction];
      Object.entries(FILTER_BODY_KEYS).forEach(([groupId, bodyKey]) => {
        const values = selectedValues(groupId);
        if (!values.length) return;
        if (filterMode(groupId) === 'exclude') {
          if (!body.exclude || typeof body.exclude !== 'object') body.exclude = {};
          body.exclude[bodyKey] = values;
          body[`exclude_${bodyKey}`] = values;
          return;
        }
        body[bodyKey] = values;
      });
      return body;
    }

    async function postJson(name, url, body) {
      try {
        const response = await fetch(url, {
          method: 'POST',
          credentials: 'same-origin',
          cache: 'no-store',
          headers: {
            'Content-Type': 'application/json',
            ...authHeaders()
          },
          body: JSON.stringify(body)
        });
        const text = await response.text();
        let json = {};
        try { json = text ? JSON.parse(text) : {}; } catch (_) {}
        if (!response.ok || json.ok === false) {
          return { name, ok: false, status: response.status, error: new Error(json.message || json.error && (json.error.message || json.error.code) || `${response.status}`), raw: json };
        }
        return { name, ok: true, data: json.data || json.body || json, raw: json };
      } catch (error) {
        return { name, ok: false, error };
      }
    }

    async function fetchWithRetry(name, url, attempts = 2, delayMs = 450) {
      if (!fetchApiResource) return { name, ok: false, error: new Error('fetchApiResource unavailable') };
      let result = null;
      for (let attempt = 0; attempt < attempts; attempt += 1) {
        result = await fetchApiResource(name, url);
        if (result && result.ok) return result;
        const status = Number(result && result.status || result && result.error && result.error.status || 0);
        const message = String(result && result.error && result.error.message || '');
        const retryable = status === 0 || status === 503 || /timeout|service unavailable|temporarily/i.test(message);
        if (!retryable || attempt >= attempts - 1) return result || { name, ok: false, error: new Error('unavailable') };
        await new Promise((resolve) => window.setTimeout(resolve, delayMs * (attempt + 1)));
      }
      return result || { name, ok: false, error: new Error('unavailable') };
    }

    function hasPrecisionFilters() {
      if (state.search.trim() || state.direction || state.risks.size || state.actions.size) return true;
      if (state.trafficKind !== 'all') return true;
      return Object.values(state.filtersSelected).some((value) => value instanceof Set && value.size);
    }

    function periodAliases() {
      const aliases = new Set([String(state.period || '').toLowerCase(), String(apiPeriod() || '').toLowerCase()]);
      const known = {
        halfHour: ['half-hour', 'halfhour', '30m', '1800s'],
        '30m': ['halfHour', 'half-hour', 'halfhour', '1800s'],
        hour: ['1h', '60m', '3600s'],
        day: ['1d', '24h', '86400s'],
        week: ['1w', '7d', '604800s'],
        month: ['1m', '30d', '2592000s']
      };
      Array.from(aliases).forEach((key) => (known[key] || []).forEach((item) => aliases.add(String(item).toLowerCase())));
      return aliases;
    }

    function normalizeRealtimePeriod(value) {
      return String(value || '').trim().replace(/\s+/g, '').toLowerCase();
    }

    function realtimePayloadMatchesPeriod(payload) {
      if (state.period === 'custom') return false;
      const payloadPeriod = normalizeRealtimePeriod(payload.period || payload.range || payload.window || payload.time_range);
      if (payloadPeriod) return periodAliases().has(payloadPeriod);
      const from = firstNumber(payload.timestampFrom, payload.ts_from, payload.start, payload.from);
      const to = firstNumber(payload.timestampTo, payload.ts_to, payload.end, payload.to);
      if (!from || !to) return state.period === 'day';
      const spanMs = Math.abs((to - from) * (to > 1e12 || from > 1e12 ? 1 : 1000));
      const wantedMs = period().ms;
      return Math.abs(spanMs - wantedMs) <= Math.max(300000, wantedMs * 0.08);
    }

    function canApplyRealtimeTopic(topic, payload) {
      if (topic === 'insights.status') return true;
      if (topic.startsWith('insights.flows.')) {
        if (state.mode !== 'flows' || hasPrecisionFilters() || !realtimePayloadMatchesPeriod(payload)) return false;
        if (topic === 'insights.flows.geo' && state.mapScope === 'china') {
          return declaredGeoScope(payload) === 'china';
        }
        return true;
      }
      if (topic.startsWith('insights.activity.')) {
        return state.mode === 'activity' && !isAuditActivitySection() && realtimePayloadMatchesPeriod(payload);
      }
      return false;
    }

    function hasRealtimeSince(topic, timestamp) {
      return firstNumber(state.lastWsAtByTopic.get(topic)) > firstNumber(timestamp);
    }

    function insightsRealtimeTopics() {
      if (isAuditActivitySection()) return ['insights.status'];
      return state.mode === 'activity'
        ? ['insights.activity.rate', 'insights.activity.traffic', 'insights.status']
        : (state.mapEnabled ? ['insights.flows.summary', 'insights.flows.geo', 'insights.status'] : ['insights.flows.summary', 'insights.status']);
    }

    function applyInsightsRealtime(topic, data) {
      if (!state.root) return;
      const payload = unwrapRealtimePayload(data);
      if (!payload || typeof payload !== 'object') return;
      state.pendingRealtime.set(topic, payload);
      if (state.realtimeFrameTimer) return;
      state.realtimeFrameTimer = window.setTimeout(() => {
        state.realtimeFrameTimer = 0;
        flushInsightsRealtime();
      }, document.hidden ? 180 : 80);
    }

    function flushInsightsRealtime() {
      if (!state.root || !state.pendingRealtime.size) return;
      const focusState = captureFocusState();
      const entries = Array.from(state.pendingRealtime.entries());
      state.pendingRealtime.clear();
      let changed = false;
      let flowChanged = false;
      let activityChanged = false;
      entries.forEach(([topic, payload]) => {
        if (!canApplyRealtimeTopic(topic, payload)) return;
        state.lastWsAtByTopic.set(topic, Date.now());
        if (topic === 'insights.flows.summary') {
          state.summary = payload;
          changed = true;
          flowChanged = true;
        } else if (topic === 'insights.flows.geo') {
          state.geo = payload;
          // Keep the per-scope cache in step, otherwise switching away and back
          // would render a snapshot older than what is already on screen.
          state.geoByScope[state.mapScope] = payload;
          changed = true;
          flowChanged = true;
        } else if (topic === 'insights.activity.rate') {
          state.activityRate = payload;
          changed = true;
          activityChanged = true;
        } else if (topic === 'insights.activity.traffic') {
          state.activityTraffic = payload;
          changed = true;
          activityChanged = true;
        } else if (topic === 'insights.status') {
          state.realtimeStatus = payload;
        }
      });
      if (!changed) return;
      if (flowChanged && !activityChanged && state.mode === 'flows' && updateFlowsRealtimeDom()) {
        restoreFocusState(focusState);
        scheduleMapRender();
        return;
      }
      if (activityChanged && !flowChanged && state.mode === 'activity' && !isAuditActivitySection() && updateActivityRealtimeDom()) {
        restoreFocusState(focusState);
        return;
      }
      render();
      restoreFocusState(focusState);
      scheduleGlassCardsRender?.(180);
      scheduleMapRender();
    }

    function subscribeInsightsRealtime() {
      if (!realtime || typeof realtime.subscribe !== 'function') return;
      const topics = insightsRealtimeTopics();
      const key = topics.join('|');
      if (state.realtimeTopicsKey === key && state.realtimeUnsubscribers.length) return;
      unsubscribeInsightsRealtime();
      state.realtimeTopicsKey = key;
      state.realtimeUnsubscribers = topics.map((topic) => realtime.subscribe(topic, (data) => applyInsightsRealtime(topic, data)));
    }

    /*
     * 审计表只订阅 insights.status（见 insightsRealtimeTopics），表体不会自己更新。
     * 删掉手动刷新按钮前必须先把轮询补上，否则页面会变成打开一次就不再刷新的快照。
     */
    function stopAuditPolling() {
      window.clearInterval(state.auditPollTimer);
      state.auditPollTimer = 0;
    }

    function startAuditPolling() {
      stopAuditPolling();
      if (!isAuditActivitySection()) return;
      state.auditPollTimer = window.setInterval(() => {
        if (!state.mounted || !state.root) return stopAuditPolling();
        if (!isAuditActivitySection()) return stopAuditPolling();
        if (document.visibilityState !== 'visible') return;
        if (state.loading) return;
        refresh();
      }, 15000);
    }

    function unsubscribeInsightsRealtime() {
      state.realtimeUnsubscribers.forEach((unsubscribe) => {
        try { unsubscribe && unsubscribe(); } catch (_) {}
      });
      state.realtimeUnsubscribers = [];
      state.realtimeTopicsKey = '';
    }

    function filtersAreFresh() {
      return Boolean(state.filters) && Date.now() - Number(state.filtersLoadedAt || 0) < 180000;
    }

    function filtersRequest(force = false) {
      if (!fetchApiResource) return Promise.resolve({ ok: false, name: 'insights_filters' });
      if (!force && filtersAreFresh()) {
        return Promise.resolve({ ok: true, name: 'insights_filters', data: state.filters, cached: true });
      }
      return fetchWithRetry('insights_filters', ENDPOINTS.filters, 1, 300)
        .then((result) => ({ ...result, loadedAt: result && result.ok ? Date.now() : 0 }));
    }

    function shouldLoadFilters(options = {}) {
      if (state.mode !== 'flows') return false;
      if (options.forceFilters) return true;
      if (hasSelectedDictionaryFilters()) return true;
      return false;
    }

    function hasSelectedDictionaryFilters() {
      return Object.values(state.filtersSelected).some((value) => value instanceof Set && value.size);
    }

    function hasVisibleFilterDictionary() {
      return FILTER_GROUPS.some(([id]) => !state.collapsed.has(id));
    }

    async function ensureFiltersLoaded(force = false) {
      if (!fetchApiResource) return { ok: false, name: 'insights_filters' };
      if (!force && filtersAreFresh()) return { ok: true, name: 'insights_filters', data: state.filters, cached: true };
      if (state.filtersPromise && !force) return state.filtersPromise;
      state.filtersLoading = true;
      const request = filtersRequest(force).then((result) => {
        const nextFilters = normalizePayload(result);
        if (nextFilters) {
          state.filters = nextFilters;
          if (!result.cached && result.ok) state.filtersLoadedAt = result.loadedAt || Date.now();
        }
        return result;
      }).finally(() => {
        state.filtersLoading = false;
        if (state.filtersPromise === request) state.filtersPromise = null;
      });
      state.filtersPromise = request;
      return request;
    }

    function rememberErrors(results) {
      results.forEach((result) => {
        if (!result || result.ok) return;
        state.errors.push(`${result.name || 'api'}: ${result.status || ''} ${result.error ? result.error.message : 'unavailable'}`.trim());
      });
    }

    function applyMapResults(requestSeq, geo, requestStartedAt, scope) {
      if (!state.root || requestSeq !== state.refreshSeq || state.mode !== 'flows') return;
      const focusState = captureFocusState();
      const nextGeo = normalizePayload(geo);
      const requestScope = scope || state.mapScope;
      if (nextGeo) state.geoByScope[requestScope] = nextGeo;
      // A response for a scope the user has already left must not replace the map.
      if (nextGeo && requestScope === state.mapScope && !hasRealtimeSince('insights.flows.geo', requestStartedAt)) {
        state.geo = nextGeo;
      }
      rememberErrors([geo]);
      if (state.loading) return;
      if (updateFlowsRealtimeDom()) {
        restoreFocusState(focusState);
        scheduleMapRender();
        return;
      }
      render();
      restoreFocusState(focusState);
      scheduleGlassCardsRender?.(180);
      scheduleMapRender();
    }

    /* Scope switching only needs the geo endpoint. Routing it through refresh()
       made it wait on insights_summary, which is the 30s call, and refresh()
       silently returns while state.loading is set, so the click looked ignored. */
    /*
     * Map-area fetch status. Patches the existing node in place instead of
     * calling render(): a full re-render would tear down and re-init the ECharts
     * instance, which is the cost this whole change set exists to avoid.
     */
    function setMapFetchState(next, message = '') {
      if (state.mapFetch === next && state.mapFetchError === message) return;
      state.mapFetch = next;
      state.mapFetchError = next === 'error' ? message : '';
      updateMapStatusDom();
    }

    function mapStatusText() {
      if (state.mapFetch === 'loading') return '正在获取地理流量…';
      if (state.mapFetch === 'error') return state.mapFetchError || '地理流量获取失败';
      return '';
    }

    /*
     * design.md「请求失败必须按 HTTP 状态分类」：404/405/501 是接口未实现，
     * 401 会话失效，403 权限不足，5xx 后端错误，无状态码才是网络不可用。
     * 原始的 `Failed to fetch` 是浏览器内部字符串，对用户没有意义，不外显。
     */
    function geoFailureText(status, message) {
      if (status === 401) return '地理流量获取失败：会话已失效，请重新登录';
      if (status === 403) return '地理流量获取失败：当前账号无权读取';
      if (status === 404 || status === 405 || status === 501) return '地理流量接口尚未接入';
      if (status >= 500) return `地理流量获取失败：后端错误（${status}）`;
      if (status > 0) return `地理流量获取失败（${status}）`;
      if (/timeout|timed out/i.test(message)) return '地理流量获取超时，正在稍后重试';
      return '地理流量获取失败：网络不可用';
    }

    function updateMapStatusDom() {
      if (!state.root) return;
      state.root.querySelectorAll('[data-insights-map-shell]').forEach((shell) => {
        shell.classList.toggle('is-geo-pending', state.mapFetch === 'loading');
        shell.classList.toggle('is-geo-failed', state.mapFetch === 'error');
        const status = shell.querySelector('[data-insights-map-status]');
        if (!status) return;
        const text = state.mapFetch === 'loading'
          ? '正在获取地理流量…'
          : (state.mapFetch === 'error' ? (state.mapFetchError || '地理流量获取失败') : '');
        status.textContent = text;
        status.hidden = !text;
      });
    }

    async function refreshMapOnly() {
      if (!state.root || state.mode !== 'flows' || !state.mapEnabled) return;
      const requestSeq = state.refreshSeq;
      const requestStartedAt = Date.now();
      const scope = state.mapScope;
      /* Show the pending state in the map area only. Painting from cache first
         is what makes the switch feel instant, but it also means an unfinished
         request is invisible unless we say so here. */
      setMapFetchState('loading');
      const result = await fetchWithRetry('insights_geo', ENDPOINTS.geo(queryPeriod(), nowRange(), scope), 3, 550);
      if (!state.root || state.mapScope !== scope) return;
      if (result && result.ok) {
        setMapFetchState('idle');
      } else {
        const status = Number(result && result.status || 0);
        const message = String(result && result.error && result.error.message || '');
        setMapFetchState('error', geoFailureText(status, message));
      }
      applyMapResults(requestSeq, result, requestStartedAt, scope);
    }

    async function refresh(options = {}) {
      if (!state.root || state.loading) return;
      const focusState = captureFocusState();
      const requestSeq = ++state.refreshSeq;
      const requestStartedAt = Date.now();
      const forceFilters = Boolean(options && options.forceFilters);
      state.loading = true;
      state.errors = [];
      if (isAuditActivitySection()) {
        await refreshAuditSection(requestSeq);
        if (!state.root || requestSeq !== state.refreshSeq) return;
        state.loading = false;
        state.audit.loading = false;
        renderAuditPoll();
        restoreFocusState(focusState);
        scheduleGlassCardsRender?.(260);
        return;
      }
      const activeRange = nowRange();
      let geo = { ok: true, data: state.geo };
      let mapResultsSettled = false;
      if (state.mode === 'flows' && state.mapEnabled) {
        const geoScope = state.mapScope;
        fetchWithRetry('insights_geo', ENDPOINTS.geo(queryPeriod(), activeRange, geoScope), 3, 550)
          .then((nextGeoResult) => {
          geo = nextGeoResult;
          mapResultsSettled = true;
          applyMapResults(requestSeq, geo, requestStartedAt, geoScope);
          });
      }
      const summaryReq = state.mode === 'flows' && fetchApiResource
        ? fetchWithRetry('insights_summary', ENDPOINTS.summary(queryPeriod(), activeRange), 2, 650)
        : Promise.resolve({ ok: true, data: null });
      const filtersReq = shouldLoadFilters({ forceFilters })
        ? ensureFiltersLoaded(forceFilters)
        : Promise.resolve({ ok: true, name: 'insights_filters', data: state.filters, cached: true, skipped: true });
      const networkWansReq = state.mode === 'flows' && fetchApiResource
        ? fetchWithRetry('network_wans', ENDPOINTS.networkWans, 3, 500)
        : Promise.resolve({ ok: true, data: null });
      const flowsReq = state.mode === 'flows'
        ? Promise.resolve({ name: 'insights_flows', ok: true, data: { flows: [] } })
        : postJson('insights_flows', ENDPOINTS.flows, flowRequestBody());
      const { timestampFrom, timestampTo } = apiSecondsRange(activeRange);
      const activityTrafficReq = state.mode === 'activity' && fetchApiResource
        ? fetchApiResource('insights_activity_traffic', ENDPOINTS.activityTraffic(timestampFrom, timestampTo))
        : Promise.resolve({ ok: true, data: null });
      const activityRateReq = state.mode === 'activity'
        ? postJson('insights_activity_rate', ENDPOINTS.activityRate(timestampFrom, timestampTo), {})
        : Promise.resolve({ ok: true, data: null });
      const [summary, filters, networkWans, flows, activityTraffic, activityRate] = await Promise.all([
        summaryReq,
        filtersReq,
        networkWansReq,
        flowsReq,
        activityTrafficReq,
        activityRateReq
      ]);
      if (!state.root || requestSeq !== state.refreshSeq) return;
      const nextSummary = normalizePayload(summary);
      const nextFilters = normalizePayload(filters);
      const nextNetworkWans = normalizePayload(networkWans);
      if (nextSummary && !hasRealtimeSince('insights.flows.summary', requestStartedAt)) state.summary = nextSummary;
      if (nextFilters) {
        state.filters = nextFilters;
        if (!filters.cached && filters.ok) state.filtersLoadedAt = filters.loadedAt || Date.now();
      }
      if (nextNetworkWans) state.networkWans = nextNetworkWans;
      state.flows = flowItems(normalizePayload(flows));
      const nextActivityTraffic = normalizePayload(activityTraffic);
      const nextActivityRate = normalizePayload(activityRate);
      if (nextActivityTraffic && !hasRealtimeSince('insights.activity.traffic', requestStartedAt)) state.activityTraffic = nextActivityTraffic;
      if (nextActivityRate && !hasRealtimeSince('insights.activity.rate', requestStartedAt)) state.activityRate = nextActivityRate;
      rememberErrors([summary, filters, networkWans, flows, activityTraffic, activityRate]);
      if (mapResultsSettled) rememberErrors([geo]);
      state.loading = false;
      state.hydratedModes.add(state.mode);
      if (state.mode === 'flows' && updateFlowsRealtimeDom()) {
        restoreFocusState(focusState);
        scheduleMapRender();
        return;
      }
      if (state.mode === 'activity' && updateActivityRealtimeDom()) {
        restoreFocusState(focusState);
        return;
      }
      render();
      restoreFocusState(focusState);
      scheduleGlassCardsRender?.(260);
      scheduleMapRender();
    }

    function tabsMarkup() {
      return `
        <div class="insights-tabs dwrt-kit-tabs" data-insights-tabs>
          <button class="dwrt-kit-tab ${state.mode === 'flows' ? 'is-active' : ''}" data-value="flows" aria-selected="${state.mode === 'flows' ? 'true' : 'false'}" type="button">
            ${trafficTabSvg()} 流量
          </button>
          <button class="dwrt-kit-tab ${state.mode === 'activity' ? 'is-active' : ''}" data-value="activity" aria-selected="${state.mode === 'activity' ? 'true' : 'false'}" type="button">
            ${activityTabSvg()} 活动
          </button>
        </div>`;
    }

    function riskMarkup() {
      return `
        <section class="insights-filter-section" data-filter-section="risk">
          <button type="button" class="insights-section-trigger" data-insights-collapse="risk" aria-expanded="true">
            <span>风险</span>${chevronSvg()}
          </button>
          <div class="insights-section-body">
            <div class="insights-risk-row">
              ${RISK_LEVELS.map((risk) => `
                <button class="dwrt-risk-meter insights-risk-button ${state.risks.has(risk.id) ? 'is-active' : ''}" data-risk="${risk.id}" type="button" title="${html(risk.label)}" aria-label="${html(risk.label)}">
                  <span class="dwrt-risk-bars insights-risk-bars ${risk.id}" aria-hidden="true"><i></i><i></i><i></i><i></i></span>
                </button>`).join('')}
              <button class="insights-action-button ${state.actions.has('allow') ? 'is-active' : ''}" data-action-filter="allow" type="button" title="允许">${checkSvg()}</button>
              <button class="insights-action-button ${state.actions.has('blocked') ? 'is-active' : ''}" data-action-filter="blocked" type="button" title="已拦截">${xSvg()}</button>
            </div>
          </div>
        </section>`;
    }

    function rangeMarkup() {
      const ranges = state.mode === 'activity' ? ACTIVITY_PERIODS : PERIODS;
      return `
        <section class="insights-filter-section insights-range-section">
          <div class="insights-range-row" role="tablist" aria-label="时间范围">
            ${Object.entries(ranges).map(([id, item]) => `
              <button type="button" ${id === 'custom' ? 'data-date-range-trigger title="自定义时间范围"' : `data-period="${id}"`} class="${state.period === id ? 'is-active' : ''}" aria-selected="${state.period === id ? 'true' : 'false'}">${id === 'custom' ? calendarSvg() : html(item.label)}</button>
            `).join('')}
          </div>
        </section>`;
    }

    function activityRatePoints() {
      return asList(state.activityRate, ['items', 'data', 'results', 'records', 'rates']);
    }

    function activityTotals() {
      const points = activityRatePoints();
      const traffic = state.activityTraffic || {};
      const rows = activityRows();
      const pointDownload = points.reduce((sum, item) => sum + firstNumber(item.rx_bytes, item.rx_byte, item['rx_byte-r'], item.download, item.download_bytes), 0);
      const pointUpload = points.reduce((sum, item) => sum + firstNumber(item.tx_bytes, item.tx_byte, item['tx_byte-r'], item.upload, item.upload_bytes), 0);
      const rowDownload = rows.reduce((sum, item) => sum + firstNumber(item.download, item.download_bytes, item.rx_bytes, item.rx_byte, item.topAppBytesReceived), 0);
      const rowUpload = rows.reduce((sum, item) => sum + firstNumber(item.upload, item.upload_bytes, item.tx_bytes, item.tx_byte, item.topAppBytesTransmitted), 0);
      const download = firstNumber(traffic.download, traffic.download_bytes, traffic.rx_bytes, pointDownload, rowDownload);
      const upload = firstNumber(traffic.upload, traffic.upload_bytes, traffic.tx_bytes, pointUpload, rowUpload);
      const total = firstNumber(traffic.total, traffic.total_bytes, traffic.usage_bytes, download + upload, rows.reduce((sum, item) => sum + activityBytes(item), 0));
      return { total, download, upload };
    }

    function activityStatsMarkup() {
      const totals = activityTotals();
      const options = [
        ['total', '互联网活动', totals.total, activitySvg()],
        ['download', '下载', totals.download, '<span class="insights-activity-dot download"></span>'],
        ['upload', '上传', totals.upload, '<span class="insights-activity-dot upload"></span>']
      ];
      const selected = options.find(([id]) => id === state.activityStatMetric) || options[0];
      return `
        <section class="insights-filter-section insights-activity-stats">
          <label class="insights-switch-row">
            <span>统计</span>
            <span class="insights-switch dwrt-kit-switch" data-dwrt-component="switch">
              <input type="checkbox" data-activity-chart-toggle ${state.activityChartEnabled ? 'checked' : ''}>
            </span>
          </label>
          <details class="insights-activity-stat-select">
            <summary class="insights-activity-stat-main">
              <span class="insights-activity-stat-icon" aria-hidden="true">${selected[3]}</span>
              <span>${html(selected[1])}</span>
              <b data-activity-stat-value="${html(selected[0])}">${html(formatBytes(selected[2]))}</b>
              ${chevronSvg()}
            </summary>
            <div class="insights-activity-stat-menu">
              ${options.map(([id, label, value, icon]) => `
                <button class="${state.activityStatMetric === id ? 'is-selected' : ''}" data-activity-stat-metric="${id}" type="button">
                  <span class="insights-activity-stat-check" aria-hidden="true">${state.activityStatMetric === id ? checkOnlySvg() : ''}</span>
                  <span class="insights-activity-stat-icon" aria-hidden="true">${icon}</span>
                  <span>${html(label)}</span>
                  <b data-activity-stat-value="${html(id)}">${html(formatBytes(value))}</b>
                </button>
              `).join('')}
            </div>
          </details>
          <div class="insights-activity-stat-grid">
            <span>互联网活动</span><b data-activity-stat-value="total">${html(formatBytes(totals.total))}</b>
            <span>下载</span><b data-activity-stat-value="download">${html(formatBytes(totals.download))}</b>
            <span>上传</span><b data-activity-stat-value="upload">${html(formatBytes(totals.upload))}</b>
          </div>
        </section>`;
    }

    function activityAnchorMarkup() {
      return `
        <section class="insights-filter-section" data-filter-section="activity-anchor">
          <button type="button" class="insights-section-trigger" data-insights-collapse="activity-anchor" aria-expanded="true">
            <span>锚定方式</span>${chevronSvg()}
          </button>
          <div class="insights-section-body">
            <div class="insights-radio-inline">
              ${[
                ['application', '应用程序'],
                ['client', '客户端']
              ].map(([id, label]) => `
                <label class="insights-radio-row">
                  <input type="radio" name="insightsActivityAnchor" value="${id}" ${state.activityAnchor === id ? 'checked' : ''}>
                  <span>${label}</span>
                </label>`).join('')}
            </div>
          </div>
        </section>
        ${filterGroupMarkup('source', '客户端')}`;
    }

    function trafficMarkup() {
      return `
        <section class="insights-filter-section">
          <label class="insights-switch-row">
            <span>流量摘要</span>
            <span class="insights-switch dwrt-kit-switch" data-dwrt-component="switch">
              <input type="checkbox" data-summary-toggle ${state.summaryEnabled ? 'checked' : ''}>
            </span>
          </label>
        </section>
        <section class="insights-filter-section" data-filter-section="traffic">
          <button type="button" class="insights-section-trigger" data-insights-collapse="traffic" aria-expanded="true">
            <span>流量</span>${chevronSvg()}
          </button>
          <div class="insights-section-body">
            <div class="insights-radio-stack">
              ${[
                ['all', '所有流量'],
                ['blocked', '已拦截'],
                ['threat', '威胁']
              ].map(([id, label]) => `
                <label class="insights-radio-row">
                  <input type="radio" name="insightsTrafficKind" value="${id}" ${state.trafficKind === id ? 'checked' : ''}>
                  <span>${label}</span>
                </label>`).join('')}
            </div>
          </div>
        </section>`;
    }

    function mapMarkup() {
      const mapScopeSupported = state.mapScope === 'world' || geoPayloadMatchesScope(state.geo, 'china');
      return `
        <section class="insights-filter-section insights-map-toggle-section">
          <label class="insights-switch-row">
            <span>地图上的流量</span>
            <span class="insights-switch dwrt-kit-switch" data-dwrt-component="switch">
              <input type="checkbox" data-map-toggle ${state.mapEnabled ? 'checked' : ''}>
            </span>
          </label>
          ${state.mapEnabled ? `
            <div class="insights-map-scope-row" role="tablist" aria-label="地图范围">
              <button type="button" data-map-scope="world" class="${state.mapScope === 'world' ? 'is-active' : ''}" aria-selected="${state.mapScope === 'world' ? 'true' : 'false'}">世界</button>
              <button type="button" data-map-scope="china" class="${state.mapScope === 'china' ? 'is-active' : ''}" aria-selected="${state.mapScope === 'china' ? 'true' : 'false'}">中国</button>
            </div>
            ${state.mapScope === 'china' && !mapScopeSupported ? '<div class="insights-map-scope-note">等待后端返回中国省市级地理流量</div>' : ''}
          ` : '<div class="insights-map-off-note">已隐藏地图，保留摘要和筛选。</div>'}
        </section>
        <section class="insights-filter-section">
          <div class="insights-switch-row">
            <span>方向</span>
            <div class="insights-direction-row">
              ${[
                ['download', '↓'],
                ['upload', '↑'],
                ['both', '↔']
              ].map(([id, label]) => `<button class="insights-direction-button ${state.direction === id ? 'is-active' : ''}" data-direction="${id}" type="button">${label}</button>`).join('')}
            </div>
          </div>
        </section>`;
    }

    function filterGroupMarkup(id, label) {
      const collapsed = state.collapsed.has(id);
      const values = filterValues(id);
      const selected = state.filtersSelected[id] || new Set();
      const mode = filterMode(id);
      const query = filterSearch(id).trim().toLowerCase();
      const selectedItems = values.filter((item) => selected.has(filterItemValue(item)));
      const visibleValues = values
        .filter((item) => {
          if (!query) return true;
          return `${filterItemLabel(item)} ${filterItemValue(item)}`.toLowerCase().includes(query);
        })
        .slice(0, 80);
      const selectedOpen = state.filterSelectedOpen[id] !== false;
      const emptyLabel = state.filtersLoading
        ? '正在读取候选项'
        : values.length ? '无匹配项' : '展开后读取候选项';
      return `
        <section class="insights-filter-section ${collapsed ? 'is-collapsed' : ''}" data-filter-section="${html(id)}">
          <button type="button" class="insights-section-trigger" data-insights-collapse="${html(id)}" aria-expanded="${collapsed ? 'false' : 'true'}">
            <span>${html(label)}</span>${chevronSvg()}
          </button>
          <div class="insights-section-body">
            <div class="insights-filter-combo">
              <div class="insights-filter-mode" role="radiogroup" aria-label="${html(label)}匹配方式">
                <label class="insights-radio-row">
                  <input type="radio" name="insightsMode-${html(id)}" value="include" data-filter-mode="${html(id)}" ${mode === 'include' ? 'checked' : ''}>
                  <span>包含</span>
                </label>
                <label class="insights-radio-row">
                  <input type="radio" name="insightsMode-${html(id)}" value="exclude" data-filter-mode="${html(id)}" ${mode === 'exclude' ? 'checked' : ''}>
                  <span>排除</span>
                </label>
              </div>
              <label class="insights-filter-search">
                ${searchSvg()}
                <input type="search" placeholder="Search" value="${html(filterSearch(id))}" data-filter-search="${html(id)}" autocomplete="off" spellcheck="false">
              </label>
              <button type="button" class="insights-selected-trigger" data-filter-selected-toggle="${html(id)}" aria-expanded="${selectedOpen ? 'true' : 'false'}">
                <span>Selected (${selected.size})</span>${chevronSvg()}
              </button>
              <div class="insights-selected-list ${selectedOpen ? '' : 'is-collapsed'}">
                ${selected.size ? selectedItems.map((item) => {
                  const value = filterItemValue(item);
                  return `<button type="button" class="insights-selected-chip" data-filter-remove="${html(id)}" data-filter-value="${html(value)}"><span>${html(filterItemLabel(item))}</span><i aria-hidden="true">×</i></button>`;
                }).join('') : '<span class="insights-select-empty">暂无已选</span>'}
              </div>
              <div class="insights-select-list">
                ${visibleValues.length ? visibleValues.map((item) => {
                  const value = filterItemValue(item);
                  return `<label class="insights-select-row">
                    <input type="checkbox" data-filter-group="${html(id)}" value="${html(value)}" ${selected.has(value) ? 'checked' : ''}>
                    <span>${html(filterItemLabel(item))}</span>
                  </label>`;
                }).join('') : `<span class="insights-select-empty">${html(emptyLabel)}</span>`}
              </div>
              <div class="insights-filter-combo-footer">
                <button type="button" data-filter-select-all="${html(id)}" ${values.length ? '' : 'disabled'}>Select All</button>
                <button type="button" data-filter-clear-group="${html(id)}" ${selected.size ? '' : 'disabled'}>清空</button>
              </div>
            </div>
          </div>
        </section>`;
    }

    function filterMarkup() {
      const flowsContent = `
        <div class="insights-search-row">
          <label class="insights-search" data-dwrt-component="expand-search">
            ${searchSvg()}
            <input type="search" placeholder="搜索" value="${html(state.search)}" data-insights-search autocomplete="off" spellcheck="false">
          </label>
        </div>
        ${riskMarkup()}
        ${rangeMarkup()}
        ${trafficMarkup()}
        ${mapMarkup()}
        ${FILTER_GROUPS.map(([id, label]) => filterGroupMarkup(id, label)).join('')}`;
      const activityContent = `
        ${activityStatsMarkup()}
        ${rangeMarkup()}
        ${activityAnchorMarkup()}`;
      return `
        <aside class="insights-filter dwrt-glass-card insights-stable-glass" aria-label="洞察筛选">
          <div class="insights-filter-scroll">
            ${state.mode === 'activity' ? activityContent : flowsContent}
          </div>
          <footer class="insights-filter-footer">
            <button type="button" data-insights-clear>清除筛选条件</button>
            ${state.mode === 'flows' ? '<button type="button" data-insights-download>下载</button><button type="button" data-insights-columns>自定义列</button>' : ''}
            ${state.notice ? `<span class="insights-footer-notice">${html(state.notice)}</span>` : ''}
          </footer>
        </aside>`;
    }

    function summaryMarkup() {
      if (!state.summaryEnabled) return '';
      const counts = summaryCounts();
      const scope = riskCountScope();
      const totalRow = { id: 'total', label: '总计', value: counts.total, detail: '', icon: summaryTrafficSvg() };
      /*
       * 三档的措辞由两件事决定，顺序不能颠倒：
       *   1. 有没有风险源 —— 没有就说「后端未提供」，不能印三个 0。
       *   2. 统计范围覆没覆盖整窗口 —— 分子只覆盖抽样行时不得配全窗口分母，
       *      那个百分比的分子分母不同源，等于宣称整窗口已查清。
       * 覆盖率极低时 0 要读作「未检出」：0 是测量结果，未检出才是当前状态。
       */
      const pct = (value) => counts.total ? `${Math.round(value / counts.total * 1000) / 10}%` : '0%';
      const riskDetail = (value) => {
        if (!counts.supported) return '后端未提供';
        if (!value && scope.unmeasured) return '未检出';
        if (!scope.percentComparable) return formatInteger(value);
        return `${formatInteger(value)} (${pct(value)})`;
      };
      const riskRows = [
        { id: 'low', label: '低', value: counts.low, detail: riskDetail(counts.low) },
        { id: 'suspicious', label: '可疑', value: counts.suspicious, detail: riskDetail(counts.suspicious) },
        { id: 'concern', label: '令人担忧', value: counts.concern, detail: riskDetail(counts.concern) }
      ];
      /*
       * 摘要模块是通栏控制台的第一格，不再是一张独立玻璃卡。
       * `data-insights-overview-card="summary"` 必须保留：`updateFlowsRealtimeDom()`
       * 用它做增量 patch 的锚点，换掉钩子会让实时刷新静默失效。
       */
      return `
        <div class="insights-console-module insights-console-summary" data-insights-overview-card="summary">
          <div class="insights-card-content" data-insights-card-content>
            <div class="insights-console-head">
              <span class="insights-console-title">流量摘要</span>
              <span class="insights-console-count">${html(riskScopeBadge())}</span>
            </div>
            <div class="insights-console-body">
              <div class="insights-console-total">
                <span class="insights-console-total-mark" aria-hidden="true">${totalRow.icon}</span>
                <strong>${html(formatInteger(totalRow.value))}</strong>
                <span class="insights-console-total-unit">条流量</span>
              </div>
              <div class="insights-summary-list">
                ${riskRows.map((row) => `
                  <div class="insights-summary-row insights-summary-risk-entry ${row.id}">
                    <span class="insights-console-dot ${row.id}" aria-hidden="true"></span>
                    <span class="insights-summary-label">${html(row.label)}</span>
                    <strong>${html(row.detail)}</strong>
                  </div>
                `).join('')}
              </div>
              ${counts.supported && scope.note ? `
                <p class="insights-summary-scope" data-insights-risk-scope-note${scope.unmeasured ? ' data-risk-scope-unmeasured="on"' : ''}${scope.detail ? ` data-dwrt-tooltip="${escapeAttr(scope.detail)}" title="${escapeAttr(scope.detail)}" tabindex="0"` : ''}>${html(scope.note)}${scope.noteRatio ? ` <b>${html(scope.noteRatio)}</b>` : ''}</p>` : ''}
            </div>
          </div>
        </div>`;
    }

    /*
     * 三档风险数的**统计范围**。这里只回答一个问题：这三个数覆盖了窗口里的多少行，
     * 以及由此还能不能拿全窗口总数当分母。
     *
     * 两种口径都实测过，且不能只认一种：
     *   `risk_count_scope: "sampled_rows"`  — 抽样行。曾实测 `risk_count_sampled_rows: 1`
     *     对 `risk_count_window_rows: 300046`，覆盖率 3.3e-06。此时「令人担忧 0」的真实
     *     含义是「抽到的那 1 行不担忧，剩下 30 万行没看」。
     *   `risk_count_scope: "window_rows_by_host"` — 按目的主机回卷整窗口，
     *     `risk_count_is_window_total: true`。但 `is_window_total` 为真**不等于**全查清：
     *     实测同时有 `risk_count_uncounted_rows: 52428`（无可解析目的主机的行）
     *     与 `risk_graded_coverage_ratio: 0.0011`（真正拿到评级的只有 271 条流，
     *     其余 247483 条落在 unknown）。
     *
     * 所以百分比可比性看的是**分子分母同源**（`counted` 是否等于窗口行数），
     * 而不是 `is_window_total` 这个自述位；「未检出」看的是有没有真的评级过
     * （`risk_graded_flows` / 覆盖率），因为大量 unknown 下的 0 不是一个测量结果。
     */
    function riskCountScope() {
      const data = state.summary || {};
      const all = data.all_count_by_risk || data.risk || data.risk_breakdown || {};
      const windowRows = firstNumber(data.risk_count_window_rows, data.total, data.total_count);
      const counted = firstNumber(data.risk_count_sampled_rows, data.risk_count_total);
      const uncounted = firstNumber(data.risk_count_uncounted_rows);
      const graded = presentNumber(data.risk_graded_flows, data.risk_matched_count);
      const gradedRatio = presentNumber(data.risk_graded_coverage_ratio);
      const ungraded = presentNumber(data.risk_ungraded_flows, all.unknown, all.UNKNOWN);
      const hasGradedSignal = data.risk_graded_flows !== undefined || data.risk_matched_count !== undefined
        || data.risk_graded_coverage_ratio !== undefined;
      const scopeLabel = firstText(data.risk_count_scope);
      /* 分子只覆盖 counted 行，分母是 windowRows。两者不等（或明确有未计入的行）
         就不同源，此时百分比不成立。后端没给范围字段时不改变既有行为。 */
      const scopeKnown = windowRows > 0 && (counted > 0 || uncounted > 0 || scopeLabel !== '');
      const covered = counted > 0 ? Math.min(counted, windowRows) : Math.max(0, windowRows - uncounted);
      const partial = scopeKnown && (uncounted > 0 || (counted > 0 && counted < windowRows));
      /* 评级覆盖率极低：三档的 0 只说明「这几条没评上」，不是「窗口里没有」。 */
      const unmeasured = hasGradedSignal
        ? (graded <= 0 || (gradedRatio > 0 && gradedRatio < 0.01))
        : (partial && windowRows > 0 && covered / windowRows < 0.01);
      /*
       * 可见的一行只说一件事：**这三个数一共覆盖了窗口里的多少行**。
       * 用 `graded`（实测 271 = low 251 + high 20，正是三档之和）而不是
       * `risk_count_sampled_rows`（247,754，其中 247,483 条是 unknown）——后者会
       * 读成「82% 都查过了」，而真正拿到评级的只有千分之一。
       *
       * 长度是硬约束，不是排版偏好：摘要模块必须与其余三个模块等高
       * （design.md 洞察控制台第 3 条），1440px 下这一列只有约 190px 宽。
       * 早先写成两句完整叙述实测把模块顶到 308px（其余 207px），文字还溢出玻璃外，
       * 标题也被长角标挤成「流」。所以：可见文字压到一行，
       * `unknown` 的语义与未计入行数放进 tooltip，而不是删掉。
       */
      /* 覆盖数优先用「真正取得评级的流数」；后端没给这个字段时退回已统计行数，
         否则旧后端会被说成「一条都没覆盖」。 */
      const coverage = hasGradedSignal ? graded : covered;
      /* `ratio` 单独拿出来，渲染时套一层 nowrap：1440px 下摘要列只有约 170px，
         实测这个比例会断在斜杠处，分母被甩到下一行就又读成「覆盖 270 条」。 */
      const ratio = windowRows > 0 ? `${formatInteger(coverage)} / ${formatInteger(windowRows)} 条` : '';
      const note = !scopeKnown ? ''
        : coverage <= 0 ? `分档未覆盖任何流量，${formatInteger(windowRows)} 条均未评级`
        : partial || coverage < windowRows ? '分档仅覆盖'
          : '';
      const noteRatio = note === '分档仅覆盖' ? ratio : '';
      /*
       * tooltip 承载完整口径。`risk_unknown_meaning` 后端自述为「目的地不在已加载的
       * 情报源中，**并非判定为安全**」，所以 unknown 既不能静默丢弃，也不能并入「低」。
       *
       * 渲染时同时写 `data-dwrt-tooltip` 与原生 `title`：kit 的 tooltip 由
       * `mountUiKit()` 挂载，而摘要模块每次实时推送都走 `patchStableCard()` 的
       * `replaceChildren`，新节点没有再挂过。实测悬浮拿不到玻璃 tooltip
       * （`dwrt-kit-tooltip-trigger` 为 false），榜单名那一处同样如此——这是平台侧的
       * 既有缺陷，已另开 Front-to-Front 交接单，这里先用原生 title 保底，
       * 让完整口径无论挂载与否都读得到。`mountNativeTitleTooltip()` 会在挂载成功时
       * 把 title 收走，两条路径不会重复弹。
       */
      const detail = [
        note ? `风险分档只统计已取得情报评级的流量：${ratio}。` : '',
        uncounted > 0 ? `其中 ${formatInteger(uncounted)} 条无可解析的目的主机，未进入统计。` : '',
        ungraded > 0 ? `另有 ${formatInteger(ungraded)} 条目的地不在已加载的情报源中，属于未评级，而非判定为安全。` : ''
      ].filter(Boolean).join('');
      return {
        windowRows,
        counted,
        covered,
        graded,
        ungraded,
        partial,
        unmeasured,
        /* 分子分母同源才允许算百分比。 */
        percentComparable: !scopeKnown || !partial,
        /* 后端未表态时按采样处理（design.md 洞察控制台第 10 条的同一口径），
           这也是改动前的行为，不因新增判据而变。 */
        /* 角标留在标题行右端，只有 11px 且与标题争宽度，因此只放口径二字，
           具体行数交给三档下方那一行——那才是这个比例该出现的视觉层级。 */
        badge: !scopeKnown ? '抽样' : partial ? '抽样' : '全窗口',
        note,
        noteRatio,
        detail
      };
    }

    function riskScopeBadge() {
      return riskCountScope().badge;
    }

    /*
     * 榜单条目的图标。三个维度各有自己的真实来源，都不是前端凭空造的：
     *
     *   应用   后端在 `top_all_traffic_by_application` 里直接给了
     *          `icon_url` / `icon_file` / `icon_key`（实测 `百度智能云` →
     *          `/static/images/logo/baidu-smartcloud.svg`）。固件里 4694 个图标。
     *          纯服务条目（https、tcp/11881，`identity_kind: "service"`）没有图标，
     *          回落到协议字形，不硬塞一张不相干的图。
     *   客户端 走全局的 `DWRT_DEVICE_IMAGES.resolve()`，与仪表盘/终端列表同一套
     *          优先级（自定义 > 指纹 > 品牌 logo）。实测 `iKuaiOS router` 命中
     *          指纹图 `/luci-static/.../3797/257x257.png`。
     *   目的地 国旗，`/static/images/flags/<code>.svg`（固件里 258 面，
     *          与 aegisx 的 `countryFlag()` 同一批资源）。
     *
     * 图标一律 `loading="lazy"`，加载失败就隐藏自己并把首字母兜底显示出来，
     * 不让一个 404 在列表里留下破图占位。
     */
    function topItemIconMarkup(item, kind) {
      const fallback = topItemIconFallback(item, kind);
      const src = topItemIconSrc(item, kind);
      if (!src) return `<span class="insights-rank-icon is-glyph" aria-hidden="true">${fallback}</span>`;
      const shape = kind === 'destination' ? ' is-flag' : '';
      return `<span class="insights-rank-icon${shape}" aria-hidden="true">`
        + `<img src="${html(src)}" alt="" loading="lazy" decoding="async"`
        + ` onerror="this.hidden=true;this.parentElement.classList.add('is-glyph')">`
        + `<i>${fallback}</i></span>`;
    }

    function topItemIconSrc(item, kind) {
      if (!item || typeof item !== 'object') return '';
      if (kind === 'application') {
        /* 服务类条目（https、dot、tcp/21385）不是应用，没有品牌图标可用。 */
        if (item.identity_kind === 'service' && !firstText(item.icon_url, item.icon_file)) return '';
        const direct = firstText(item.icon_url, item.icon, item.logo_url, item.logo);
        if (direct) return normalizeIconUrl(direct);
        const file = firstText(item.icon_file, item.icon_key && `${item.icon_key}.svg`);
        return file ? `/static/images/logo/${encodeURIComponent(file)}` : '';
      }
      if (kind === 'client') {
        const images = globalThis.DWRT_DEVICE_IMAGES;
        if (images && typeof images.resolve === 'function') {
          const resolved = images.resolve(item);
          if (resolved && resolved.src) return resolved.src;
        }
        return normalizeIconUrl(firstText(item.icon_url, item.icon, item.image, item.image_url));
      }
      if (kind === 'destination') return countryFlagUrl(item);
      return '';
    }

    function normalizeIconUrl(value) {
      const source = firstText(value);
      if (!source) return '';
      const images = globalThis.DWRT_DEVICE_IMAGES;
      if (images && typeof images.normalizeUrl === 'function') return images.normalizeUrl(source);
      return source;
    }

    /* 国家代码 → 旗帜文件。只接受两位字母的 ISO 代码，其余一律不出图，
     * 避免把 `region_code: "28"` 这类行政区代码拼成一个不存在的路径。 */
    function countryFlagUrl(item) {
      const code = firstText(item && item.country_code, item && item.country, item && item.countryCode)
        .trim().toLowerCase();
      return /^[a-z]{2}$/.test(code) ? `/static/images/flags/${code}.svg` : '';
    }

    function topItemIconFallback(item, kind) {
      const name = topItemName(item, kind);
      const first = String(name || '').trim().slice(0, 1).toUpperCase();
      return html(first && first !== '-' ? first : '·');
    }

    function topItemName(item, kind) {
      if (item && item.__top_label) return item.__top_label;
      if (kind === 'destination') {
        /* 地点优先（用户：「目的地应该是地方，例如美国洛杉矶」）。
         * `__geo_sampled` 标记的条目来自 geo regions，直接用拼好的地点名；
         * 其余（geo 不可用时的兜底路径）仍按主机/域名显示。 */
        if (item && item.__geo_sampled) return geoPlaceLabel(item);
        return firstText(item.destination, item.destination_name, item.destination_host, item.domain, item.host, item.ip, geoPlaceLabel(item), item.region, item.country, item.name, item.label, '--');
      }
      if (kind === 'client') {
        return firstText(item.client_name, item.hostname, item.name, item.display_name, item.mac, item.ip, '--');
      }
      if (kind === 'application') {
        return firstText(item.application, item.app_name, item.app, item.name, item.label, '--');
      }
      return firstText(item.name, item.label, '--');
    }

    function topItemMetric(item) {
      /* 后端自述为采样的 geo 条目：字节与全窗口不可比，只报流数，
         口径由卡片头部的「抽样」徽标说明。 */
      if (item && item.__geo_sampled) return `${formatInteger(topItemCount(item))} 条`;
      if (hasTrafficBytes(item) || item.__top_has_bytes) {
        return formatBytes(bytesOf(item));
      }
      return formatInteger(firstNumber(item.count, item.flow_count, item.total, item.value));
    }

    /*
     * 进度条的长度必须用**该模块自己的排名指标**归一化。
     *
     * 后端在每个条目上给了 `metric_type` / `ranking_basis`：目的地与客户端是
     * `flow_count`（按流数排名），应用是 `bytes`（按字节排名）。若一律按 bytes
     * 算宽度，应用榜没问题，但目的地榜的条长顺序会和列表顺序对不上——实测
     * down.debian7.com 只有 146 条流却占 24MB，而 www.coway.com 有 672 条流
     * 却只占 6MB，按字节画就是第三名的条最长，看起来像排序坏了。
     */
    function topItemWeight(item) {
      const metric = firstText(item && item.metric_type, item && item.ranking_basis);
      const bytes = bytesOf(item);
      const count = topItemCount(item);
      if (/byte|traffic/i.test(metric)) return bytes || count;
      if (/count|hit|flow/i.test(metric)) return count || bytes;
      return (hasTrafficBytes(item) || item.__top_has_bytes) ? (bytes || count) : (count || bytes);
    }

    /*
     * `note` 是口径徽标，跟在计数徽标后面（如 `20 地区 · 抽样`）。
     * 采样数据源不得无标注地渲染，这条与「流量摘要」的 `riskScopeBadge()` 同一套做法。
     */
    function topCard(title, empty, items, kind, note) {
      const shown = items.slice(0, 5);
      const peak = shown.reduce((max, item) => Math.max(max, topItemWeight(item)), 0);
      const countText = items.length ? topCountLabel(items.length, kind) : empty;
      const headText = items.length && note ? `${countText} · ${note}` : countText;
      return `
        <div class="insights-console-module insights-console-rank is-${html(kind)}" data-insights-overview-card="${html(kind)}">
          <div class="insights-card-content" data-insights-card-content>
            <div class="insights-console-head">
              <span class="insights-console-title">${html(title)}</span>
              <span class="insights-console-count">${html(headText)}</span>
            </div>
            ${shown.length ? `
              <div class="insights-console-list">
                ${shown.map((item) => {
                  const name = topItemName(item, kind);
                  const weight = topItemWeight(item);
                  /* 榜首恒为 100%，其余按比例；peak 为 0 时全部给最小可见宽度，
                     否则一排空槽看起来像渲染失败。 */
                  const ratio = peak > 0 ? Math.max(4, Math.round(weight / peak * 100)) : 4;
                  return `
                  <div class="insights-console-rank-item">
                    <div class="insights-console-rank-info">
                      ${topItemIconMarkup(item, kind)}
                      <span class="insights-console-rank-name" data-dwrt-tooltip="${html(kind === 'application' && !activityIsRealApplication(item) ? `${name}\n${activityIdentityHint(item)}` : name)}">${html(name)}</span>
                      ${kind === 'application' && !activityIsRealApplication(item) ? '<em class="insights-console-rank-unidentified">未识别</em>' : ''}
                      <span class="insights-console-rank-metric">${html(topItemMetric(item))}</span>
                    </div>
                    <span class="insights-console-bar" aria-hidden="true"><i style="width:${ratio}%"></i></span>
                  </div>`;
                }).join('')}
              </div>` : `
              <div class="insights-empty insights-top-empty">
                <span class="insights-empty-icon ${html(kind)}" aria-hidden="true">${emptyStateSvg(kind)}</span>
                <strong>${html(empty)}</strong>
              </div>`}
          </div>
        </div>`;
    }

    /*
     * 计数徽标的单位必须跟随**这一屏真正的维度**。目的地卡有两种形态：
     * geo 可用时是地点榜（单位「地区」），geo 不可用时回退主机榜（单位「主机」）。
     * 写死「地区」会在回退时把 `ports.debian13.com` 这类主机名说成地区。
     */
    function topCountLabel(count, kind) {
      const unit = kind === 'destination'
        ? (destinationTopItems().length ? '地区' : '主机')
        : kind === 'client' ? '设备' : '应用';
      return `${formatInteger(count)} ${unit}`;
    }

    /*
     * 「热门应用」榜。`top_all_traffic_by_application` 里多数条目是 DPI 未命中的
     * 协议/端口兜底（`https`、`dot`、`tcp:NNNN`），而它们字节数最大，必然排在前面
     * ——30.1 实测 30 条里只有 6 条是真实应用，而前 5 名有 4 个不是应用。
     * 直接平铺会让用户把 `https` 读成一个应用。
     *
     * 这里复用活动页的 `activityIsRealApplication()`（同一判据，不写第三份）：
     * 真实应用优先排序，兜底条目降级到后面并如实标注，计数徽标给出识别口径。
     * 覆盖率分母是全部条目、分子只算真实应用，与 APP 过滤页读数一致。
     */
    function applicationTopCard() {
      const items = dedupeTopItems(topList(['top_all_traffic_by_application', 'top_applications', 'applications', 'apps']), 'application');
      const applications = items.filter(activityIsRealApplication);
      const services = items.filter((item) => !activityIsRealApplication(item));
      // 真实应用排前面，兜底条目仍保留（隐藏会让用户以为流量消失了），只是降级。
      const ordered = applications.concat(services);
      // 计数徽标形如「7 应用 · 6 识别」：分母是全部条目，分子只算真实应用。
      // 用户看到 6 < 7 就知道有条目没被识别，不必读文档。
      const note = items.length ? `${formatInteger(applications.length)} 识别` : '';
      return topCard('热门应用', '无受影响应用', ordered, 'application', note);
    }

    /*
     * 地图上方是一条通栏控制台，四个模块共享同一张玻璃并用竖分割线分隔
     * （用户给的 demo）。原来是四张各自加玻璃的卡片，等宽但高度各自为政
     * （1440px 实测 190 / 190 / 174 / 174），且在两列断点下折成 2x2。
     * 玻璃只加在外层容器一处，模块内部不再重复 `dwrt-glass-card`。
     */
    function overviewMarkup() {
      return `
        <section class="insights-overview-row insights-console dwrt-glass-card insights-stable-glass" aria-label="流量概览">
          ${summaryMarkup()}
          ${topCard('热门目的地', '无目的地', destinationCardItems(), 'destination', destinationCardNote())}
          ${topCard('热门客户端', '无受影响客户端', dedupeTopItems(topList(['top_all_count_by_client', 'clients']), 'client'), 'client')}
          ${applicationTopCard()}
        </section>`;
    }

    function mapPanelMarkup() {
      const points = mapDisplayPoints();
      const routes = mapRouteItems();
      const regionCount = mapPoints().length;
      const mapScopeSupported = state.mapScope === 'world' || geoPayloadMatchesScope(state.geo, 'china');
      return `
        <section class="insights-map-panel" aria-label="地图上的流量">
          <div class="insights-map-panel-head">
            <strong>地图上的流量</strong>
            <span>${html(regionCount ? `${regionCount} 个地区` : '等待地理流量数据')}</span>
          </div>
          <div class="insights-map-large ${state.mapScope === 'china' ? 'is-china-scope' : ''}" role="img" aria-label="${state.mapScope === 'china' ? '中国地图流量' : '世界地图流量'}" data-insights-map-shell>
            <div class="insights-echarts-map" data-insights-echarts-map data-map-role="main" aria-hidden="true"></div>
            <div class="insights-map-fallback insights-map-loader-fallback" data-insights-map-fallback>${cyberMapLoaderMarkup()}</div>
            ${mapRouteLayerMarkup(routes.slice(0, CYBER_ROUTE_LIMIT))}
            <div class="insights-map-point-layer">${points.slice(0, 32).map((point, index) => mapPointMarkup(point, index)).join('')}</div>
            ${state.mapScope === 'china' && !mapScopeSupported ? '<div class="insights-map-scope-empty">等待后端返回中国省市级地理流量</div>' : ''}
            <div class="insights-map-status" data-insights-map-status role="status" aria-live="polite"${mapStatusText() ? '' : ' hidden'}>${html(mapStatusText())}</div>
            ${mapLegendMarkup()}
            <div class="insights-map-controls" aria-label="地图控制">
              <button type="button" data-map-control="reset" title="重置视图">${targetSvg()}</button>
              <button type="button" data-map-control="zoom-in" title="放大">${zoomInSvg()}</button>
              <button type="button" data-map-control="zoom-out" title="缩小">${zoomOutSvg()}</button>
            </div>
          </div>
        </section>`;
    }

    /*
     * 地图图例。用户 2026-08-09 提出「地图里不同颜色代表什么」——此前地图一条图例
     * 都没有，唯一的琥珀图例在上方摘要里写着「可疑」，于是地图的琥珀（当时表示
     * 入站）被读成风险。图例是这次修复的主体，不是装饰。
     *
     * 三条口径：
     *   1. 只列这一屏真的画出来的档位。图例里出现图上没有的颜色，等于换一种方式
     *      让人猜。
     *   2. 「未评级」必须与「低」分开写明，并说清它不等于安全 —— 后端自述
     *      `risk_unknown_meaning` 是「目的地不在已加载情报源中，并非判定为安全」，
     *      实测 30/30 条路由都是 unknown，这一档是常态而不是边角情况。
     *   3. 方向与流量各自单独一行，明确它们由形状/粗细表达，不占用颜色。
     */
    /* 外壳常驻 DOM，内容由 updateMapDom() 重算：首次渲染时 geo 还没到，
       若外壳也按数据条件生成，后续增量更新就找不到挂载点。 */
    function mapLegendMarkup() {
      const inner = mapLegendInnerMarkup();
      return `<div class="insights-map-legend" data-insights-map-legend role="note" aria-label="地图图例"${inner ? '' : ' hidden'}>${inner}</div>`;
    }

    function mapLegendInnerMarkup() {
      const routes = mapRouteItems();
      const points = mapDisplayPoints();
      if (!routes.length && !points.length) return '';
      const buckets = new Set();
      routes.forEach((route) => buckets.add(mapRiskBucket(route)));
      points.forEach((point) => {
        if (point.is_local || point.local || point.role === 'local') return;
        buckets.add(mapRiskBucket(point));
      });
      const order = ['unknown', 'low', 'suspicious', 'concern'];
      const riskItems = order.filter((bucket) => buckets.has(bucket)).map((bucket) => {
        const palette = mapRiskPalette(bucket);
        const note = bucket === 'unknown' ? ' data-dwrt-tooltip="目的地不在已加载的情报源中，未做评级；这不等于判定为安全"' : '';
        return `<span class="insights-map-legend-item"${note}>`
          + `<i class="insights-map-legend-swatch" style="--legend-color:${palette.line}"></i>`
          + `${html(palette.label)}</span>`;
      }).join('');
      const hasLocal = points.some((point) => point.is_local || point.local || point.role === 'local');
      const directions = new Set(routes.map((route) => String(route.direction || '').toLowerCase() === 'inbound' ? 'inbound' : 'outbound'));
      const directionItems = [
        directions.has('outbound') ? `<span class="insights-map-legend-item"><i class="insights-map-legend-line is-outbound" aria-hidden="true"></i>出站</span>` : '',
        directions.has('inbound') ? `<span class="insights-map-legend-item"><i class="insights-map-legend-line is-inbound" aria-hidden="true"></i>入站</span>` : '',
        hasLocal ? `<span class="insights-map-legend-item"><i class="insights-map-legend-swatch is-local" style="--legend-color:${MAP_LOCAL_COLOR}"></i>本机出口</span>` : ''
      ].filter(Boolean).join('');
      return `
        ${riskItems ? `<div class="insights-map-legend-group"><span class="insights-map-legend-title">颜色 · 风险</span>${riskItems}</div>` : ''}
        ${directionItems ? `<div class="insights-map-legend-group"><span class="insights-map-legend-title">线型 · 方向</span>${directionItems}</div>` : ''}
        <div class="insights-map-legend-group"><span class="insights-map-legend-title">粗细 / 点径 · 流量</span><span class="insights-map-legend-item"><i class="insights-map-legend-scale" aria-hidden="true"></i><span class="insights-map-legend-scale-text">越粗越大代表流量越多</span><span class="insights-map-legend-scale-short" aria-hidden="true">流量</span></span></div>`;
    }

    function activityRows() {
      const traffic = state.activityTraffic || {};
      const total = asList(traffic.total_usage_by_app || traffic.total_usage_by_application || traffic.total_usage, ['items', 'data']);
      const byClient = asList(traffic.client_usage_by_app || traffic.client_usage || traffic.clients, ['items', 'data']);
      const direct = asList(traffic, ['items', 'rows', 'records', 'applications', 'apps']);
      if (state.activityAnchor === 'client') return byClient.length ? byClient : direct;
      return total.length ? total : direct;
    }

    function activityBytes(item) {
      if (!item || typeof item !== 'object') return 0;
      return firstNumber(
        item.total_bytes,
        item.totalBytes,
        item.bytes,
        item.usage_bytes,
        item.rx_bytes + item.tx_bytes,
        item.download_bytes + item.upload_bytes,
        item.topAppTotalBytes
      );
    }

    function activityName(item) {
      if (!item || typeof item !== 'object') return '--';
      const app = item.topApp || item.application || item.app || {};
      const client = item.client || item.topClient || {};
      return firstText(item.application_name, item.app_name, item.application, app.name, app.application, item.name, item.category, '--');
    }

    /*
     * 后端对每条用量都给了完整的识别标记，判据照抄插件页
     * `plugins/native/app-filter.js` 的 `coverageFrom()`：三个标记同时成立才算
     * 真实应用。DPI 特征库没命中时后端退化成「协议/端口」标识（`tcp/11881`、
     * `https`、`dot`），这是如实兜底，不是应用名，因此不能和真实应用平铺在
     * 同一个榜里。`identity_kind: "service"` 是后端给这类条目的分类。
     */
    function activityIsRealApplication(item) {
      if (!item || typeof item !== 'object') return false;
      return item.is_application === true
        && item.app_identified === true
        && item.application_name_is_fallback !== true;
    }

    /* 未识别原因是后端已返回但全仓库此前无人消费的字段。原样的
       `no_dpi_signature_match_proto_port_used` 对用户没有意义，翻成人话放进
       tooltip；出现未收录的取值时保留原文，不猜也不吞掉。 */
    const ACTIVITY_IDENTITY_REASONS = {
      no_dpi_signature_match_proto_port_used: '特征库未匹配，只能按协议/端口标识这段流量',
      no_dpi_signature_match: '特征库未匹配到具体应用',
      encrypted_no_sni: '流量加密且未暴露 SNI，无法归属到具体应用'
    };

    function activityIdentityHint(item) {
      if (!item || typeof item !== 'object') return '';
      const reason = firstText(item.identity_reason);
      const source = firstText(item.identity_source);
      const known = reason && ACTIVITY_IDENTITY_REASONS[reason];
      const lines = ['未识别为具体应用'];
      if (known) lines.push(known);
      else if (reason) lines.push(`后端给出的原因：${reason}`);
      if (source) lines.push(`标识来源：${source}`);
      return lines.join('\n');
    }

    /* 把一份用量列表按识别结果分成两段，并给出覆盖率口径。分母是全部条目、
       分子只算真实应用，与 app-filter.js 的覆盖率卡同一口径，两处读数才能对上。 */
    function activityIdentityGroups() {
      const rows = activityRows();
      const applications = [];
      const services = [];
      rows.forEach((item) => (activityIsRealApplication(item) ? applications : services).push(item));
      return {
        rows,
        applications,
        services,
        total: rows.length,
        identified: applications.length,
        percent: rows.length > 0 ? Math.round(applications.length / rows.length * 100) : 0
      };
    }

    function activityTopClient(item) {
      if (!item || typeof item !== 'object') return '--';
      const client = item.topClient || item.client || {};
      return firstText(item.top_client, item.topClientName, client.name, client.display_name, item.client_name, item.hostname, '--');
    }

    function activityRateSeries() {
      const points = activityRatePoints();
      const list = points.length ? points : Array.from({ length: 16 }, (_, index) => ({ timestamp: Date.now() - (15 - index) * 300000, total_bytes: 0, rx_bytes: 0, tx_bytes: 0 }));
      return list.map((item, index) => ({
        timestamp: firstNumber(item.timestamp, item.time, item.ts, Date.now() - (list.length - index - 1) * 300000),
        total: firstNumber(item.total_bytes, item.totalBytes, item.total, item.bytes, item['rx_byte-r'] + item['tx_byte-r']),
        download: firstNumber(item.rx_bytes, item.rx_byte, item['rx_byte-r'], item.download, item.download_bytes),
        upload: firstNumber(item.tx_bytes, item.tx_byte, item['tx_byte-r'], item.upload, item.upload_bytes)
      }));
    }

    function activityChartMarkup() {
      /* The chart was hand-drawn SVG scaled with preserveAspectRatio="none", so
         the 1000x310 viewBox was stretched to whatever the card measured and every
         glyph was scaled non-uniformly with it -- which is why the axis numbers
         read as squashed/stretched rather than mis-sized. Text cannot be excluded
         from a non-uniform viewBox scale, so there is no fix that keeps the raw
         SVG. It renders through ECharts instead, matching the system health cards
         (monitor/system-health), which also brings the hover tooltip the user
         asked for. The container is empty markup on purpose: the chart is mounted
         after layout so ECharts measures a real box. */
      return `
        <section class="insights-activity-chart dwrt-glass-card insights-stable-glass" aria-label="互联网活动趋势" data-insights-activity-card="chart">
          <div class="insights-card-content insights-activity-chart-content" data-insights-card-content>
            <div class="insights-activity-chart-canvas" data-insights-activity-chart aria-hidden="true"></div>
          </div>
        </section>`;
    }

    function activityTimeLabel(timestamp) {
      const value = Number(timestamp);
      const date = new Date(value > 1e12 ? value : value * 1000);
      if (!Number.isFinite(date.getTime())) return '--';
      return new Intl.DateTimeFormat('zh-CN', { hour: 'numeric', minute: '2-digit' }).format(date);
    }

    /* Axis and tooltip styling is taken from systemHealthChartOption() in
       menu-shell.js so the two pages read as one chart language: same axis
       colours, same dashed split lines, same 45-degree x labels, same glass
       tooltip. Values are bytes/sec on the wire and are shown as bit rates,
       which is what the old "Mbps" caption claimed. */
    function activityChartOption() {
      const series = activityRateSeries();
      const dark = document.documentElement.dataset.themeResolved === 'dark';
      const axisColor = dark ? 'rgba(216,226,240,0.72)' : 'rgba(92,105,124,0.76)';
      const splitColor = dark ? 'rgba(226,236,255,0.13)' : 'rgba(120,134,154,0.15)';
      const tooltipBg = dark ? 'rgba(12, 18, 30, 0.88)' : 'rgba(255, 255, 255, 0.86)';
      const tooltipBorder = dark ? 'rgba(255,255,255,0.14)' : 'rgba(255,255,255,0.58)';
      const rate = (bytesPerSecond) => formatRate(Math.max(0, Number(bytesPerSecond) || 0));
      const line = (name, key, color) => ({
        name,
        type: 'line',
        smooth: true,
        symbol: series.length <= 2 ? 'circle' : 'none',
        showSymbol: series.length <= 2,
        symbolSize: 4,
        lineStyle: { width: 1.45, color },
        itemStyle: { color },
        areaStyle: key === 'download' ? { color, opacity: 0.12 } : undefined,
        data: series.map((item) => Math.max(0, Number(item[key]) || 0))
      });
      return {
        animation: false,
        color: ['#7d62ff', '#46c6ff'],
        grid: { left: 64, right: 28, top: 18, bottom: 68 },
        tooltip: {
          trigger: 'axis',
          confine: true,
          appendToBody: true,
          backgroundColor: tooltipBg,
          borderColor: tooltipBorder,
          borderWidth: 1,
          textStyle: { color: dark ? 'rgba(248,251,255,0.94)' : 'rgba(24,31,42,0.92)', fontSize: 12 },
          extraCssText: 'border-radius:10px;box-shadow:0 14px 34px rgba(0,0,0,.18);backdrop-filter:blur(12px) saturate(135%);-webkit-backdrop-filter:blur(12px) saturate(135%);',
          formatter: (params) => {
            const list = Array.isArray(params) ? params : [params];
            if (!list.length) return '';
            const head = html(String(list[0].axisValueLabel || list[0].axisValue || ''));
            const rows = list.map((entry) => `<div style="display:flex;align-items:center;gap:8px"><span style="width:8px;height:8px;border-radius:50%;background:${entry.color}"></span><span style="flex:1 1 auto">${html(String(entry.seriesName))}</span><b>${html(rate(entry.value))}</b></div>`).join('');
            return `<div style="display:grid;gap:4px;min-width:150px"><strong>${head}</strong>${rows}</div>`;
          }
        },
        legend: {
          show: true,
          bottom: 0,
          left: 'center',
          icon: 'circle',
          itemWidth: 8,
          itemHeight: 8,
          itemGap: 18,
          textStyle: { color: axisColor, fontSize: 12, fontWeight: 500 }
        },
        xAxis: {
          type: 'category',
          boundaryGap: false,
          data: series.map((item) => activityTimeLabel(item.timestamp)),
          axisTick: { show: false },
          axisLine: { lineStyle: { color: dark ? 'rgba(226,236,255,0.16)' : 'rgba(128,143,163,0.24)' } },
          axisLabel: {
            color: axisColor,
            rotate: 45,
            margin: 14,
            fontSize: 12,
            fontWeight: 520,
            align: 'right',
            verticalAlign: 'middle',
            hideOverlap: true
          }
        },
        yAxis: {
          type: 'value',
          min: 0,
          splitLine: { lineStyle: { color: splitColor, type: 'dashed' } },
          axisLabel: { color: axisColor, fontSize: 12, formatter: (value) => rate(value) }
        },
        series: [line('下载', 'download', '#7d62ff'), line('上传', 'upload', '#46c6ff')]
      };
    }

    function disposeActivityChart(container) {
      if (!container) return;
      if (container.__dwrtActivityResizeObserver) {
        try { container.__dwrtActivityResizeObserver.disconnect(); } catch (_) {}
        container.__dwrtActivityResizeObserver = null;
      }
      if (container.__dwrtActivityChart) {
        try { container.__dwrtActivityChart.dispose(); } catch (_) {}
        container.__dwrtActivityChart = null;
      }
    }

    /* Mounted after the markup is in the DOM: ECharts sizes itself from the
       container, so initialising against a 0-height box paints nothing. A zero
       box is retried on the next frame rather than failing silently. */
    function renderActivityChart() {
      if (!state.root || state.mode !== 'activity' || isAuditActivitySection() || !state.activityChartEnabled) return;
      const container = state.root.querySelector('[data-insights-activity-chart]');
      if (!container || !container.isConnected) return;
      const rect = container.getBoundingClientRect();
      if (rect.width < 2 || rect.height < 2) {
        window.requestAnimationFrame(() => {
          if (container.isConnected) renderActivityChart();
        });
        return;
      }
      loadECharts()
        .then((echarts) => {
          if (!state.root || state.mode !== 'activity' || !container.isConnected || !state.activityChartEnabled) return;
          let chart = container.__dwrtActivityChart;
          if (!chart) {
            chart = echarts.init(container, null, { renderer: 'canvas' });
            container.__dwrtActivityChart = chart;
            if ('ResizeObserver' in window) {
              container.__dwrtActivityResizeObserver = new ResizeObserver(() => {
                if (!container.isConnected) return;
                const box = container.getBoundingClientRect();
                if (box.width < 2 || box.height < 2) return;
                chart.resize();
              });
              container.__dwrtActivityResizeObserver.observe(container);
            }
          }
          chart.setOption(activityChartOption(), true);
          chart.resize();
        })
        .catch(() => {});
    }

    function activityRateTick(bytesPerSecond) {
      const mbps = Math.max(0, Number(bytesPerSecond) || 0) * 8 / 1000000;
      if (mbps >= 10) return String(Math.round(mbps));
      return mbps.toFixed(1);
    }

    function activityTableMarkup() {
      const groups = activityIdentityGroups();
      const total = Math.max(1, groups.rows.reduce((sum, item) => sum + activityBytes(item), 0));
      const row = (item) => {
        const bytes = activityBytes(item);
        const download = firstNumber(item.download, item.download_bytes, item.rx_bytes, item.rx_byte, item.topAppBytesReceived);
        const upload = firstNumber(item.upload, item.upload_bytes, item.tx_bytes, item.tx_byte, item.topAppBytesTransmitted);
        const pct = bytes > 0 ? Math.max(0.1, bytes / total * 100).toFixed(1) : '0.0';
        const identified = activityIsRealApplication(item);
        const hint = identified ? '' : activityIdentityHint(item);
        const name = activityName(item);
        /* 兜底条目的名字就是它的协议/端口标识，不改写成假的应用名；旁边挂一枚
           「未识别」标记，并把后端给的原因放进 kit tooltip。 */
        /* 图标在前、名字在后（用户 2026-08-09 的要求）。图标用后端在这份用量里
           给的 `icon_url` / `icon_file` / `icon_key`（30.1 实测同一批字段各 19 处），
           服务条目没有品牌图标，出首字母字形，两组行的文字仍然对齐。 */
        const nameCell = identified
          ? `<span class="insights-activity-name">`
            + auditIconMarkup(auditAppIconSrc(item), name)
            + `<b>${html(name)}</b></span>`
          : `<span class="insights-activity-name is-service"${hint ? ` data-dwrt-tooltip="${escapeAttr(hint)}" tabindex="0"` : ''}>`
            + auditIconMarkup('', name)
            + `<code>${html(name)}</code><em>未识别</em></span>`;
        return `<tr class="${identified ? 'is-application' : 'is-service'}">
          <td>${nameCell}</td>
          <td>${html(formatBytes(bytes))} (${pct}%)</td>
          <td class="traffic-down">${html(formatBytes(download))}</td>
          <td class="traffic-up">${html(formatBytes(upload))}</td>
          <td>${html(activityTopClient(item))}</td>
          <td>${html(formatInteger(firstNumber(item.client_count, item.clients, item.clientCount, item.app_count, item.appCount)))}</td>
        </tr>`;
      };
      const groupHead = (label, count) => `
        <tr class="insights-activity-group">
          <th colspan="6" scope="colgroup">
            <span class="insights-activity-group-label">${html(label)}</span>
            <span class="insights-activity-group-count">${html(`${formatInteger(count)} 项`)}</span>
          </th>
        </tr>`;
      const body = groups.rows.length
        ? `${groups.applications.length ? `${groupHead('应用', groups.applications.length)}${groups.applications.map(row).join('')}` : ''}`
          + `${groups.services.length ? `${groupHead('未识别的协议 / 端口', groups.services.length)}${groups.services.map(row).join('')}` : ''}`
        : `
          <tr>
            <td colspan="6">
              <div class="insights-activity-empty">
                <span>${infoSvg()}</span>
                <strong>此网络上没有流量。</strong>
              </div>
            </td>
          </tr>`;
      return `
        <section class="insights-activity-table dwrt-glass-card insights-stable-glass" data-insights-activity-card="table">
          <div class="insights-card-content insights-activity-table-content" data-insights-card-content>
            ${activityCoverageMarkup(groups)}
            <div class="insights-activity-table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>应用程序 / 协议</th>
                    <th>总数据（流量 %）</th>
                    <th>下载</th>
                    <th>上传</th>
                    <th>主要客户端</th>
                    <th>客户端</th>
                  </tr>
                </thead>
                <tbody>${body}</tbody>
              </table>
            </div>
          </div>
        </section>`;
    }

    /*
     * 识别覆盖率如实呈现，口径与 APP 过滤页的覆盖率卡一致（分母为全部条目、
     * 分子只算 `is_application`）。没有数据就不画这条，不用 0% 或 100% 假装
     * 有结论。
     *
     * 三档数字自己就说清了口径（14 应用 / 466 仅协议/端口 / 480 合计），
     * 用户 2026-08-09 要求删掉底下那句解释性长句；未识别行仍在表内带
     * 「未识别」标记与原因 tooltip，信息没有丢。
     */
    function activityCoverageMarkup(groups) {
      if (!groups.total) return '';
      return `
        <div class="insights-activity-coverage">
          <div class="insights-activity-coverage-main">
            <b>${html(`${groups.percent}%`)}</b>
            <span>识别为应用</span>
          </div>
          <div class="insights-activity-coverage-split">
            <span><i>${html(formatInteger(groups.identified))}</i>应用</span>
            <span><i>${html(formatInteger(groups.services.length))}</i>仅协议/端口</span>
            <span><i>${html(formatInteger(groups.total))}</i>条目合计</span>
          </div>
        </div>`;
    }

    function flowCell(item, column) {
      if (column === 'time') {
        const ts = firstNumber(item.time, item.timestamp, item.ts, item.start_time);
        return ts ? new Date(ts > 1e12 ? ts : ts * 1000).toLocaleString() : '--';
      }
      if (column === 'risk') {
        const cls = riskClass(item.risk || item.severity);
        return `<span class="insights-risk-dot ${html(cls)}"></span>${html(riskLabel(item.risk || item.severity))}`;
      }
      if (column === 'action') return html(actionLabel(item.action || item.verdict));
      if (column === 'source') return html(firstText(item.source_name, item.source_host, item.source_ip, item.src_ip, item.source_mac, '--'));
      if (column === 'destination') return html(firstText(item.destination_name, item.destination_host, item.destination_ip, item.dst_ip, item.destination_region, '--'));
      if (column === 'service') return html(firstText(item.service, item.application, item.app_name, item.app, '--'));
      if (column === 'protocol') return html(firstText(item.protocol, item.proto, '--'));
      if (column === 'traffic') return html(formatBytes(bytesOf(item)));
      if (column === 'policy') return html(firstText(item.policy, item.policy_name, item.policy_type, '--'));
      return '--';
    }

    function tableMarkup() {
      const columns = DEFAULT_COLUMNS.filter(([id]) => state.columns.has(id));
      return `
        <section class="insights-table-card dwrt-kit-table-wrap dwrt-glass-card insights-stable-glass">
          <div class="dwrt-kit-table-toolbar">
            <div class="dwrt-kit-table-title">
              <strong>${state.mode === 'activity' ? '活动' : '流量'}</strong>
              <span>${state.errors.length ? '后端接口未完全就绪，已显示可用数据与空态' : '真实流量记录'}</span>
            </div>
            <span class="dwrt-kit-table-count">${html(state.loading ? '读取中' : `${state.flows.length} 条`)}</span>
          </div>
          <div class="dwrt-kit-table-scroll">
            <table class="dwrt-kit-table">
              <thead><tr>${columns.map(([, label]) => `<th>${html(label)}</th>`).join('')}</tr></thead>
              <tbody>
                ${state.flows.length ? state.flows.map((item) => `
                  <tr>${columns.map(([id]) => `<td>${flowCell(item, id)}</td>`).join('')}</tr>
                `).join('') : `
                  <tr><td colspan="${columns.length}">
                    <div class="insights-empty">
                      <strong>${state.errors.length ? '洞察后端未返回完整数据' : '无流量'}</strong>
                      <span>${html(state.errors[0] || '检测到流量后将在此处记录')}</span>
                    </div>
                  </td></tr>`}
              </tbody>
            </table>
          </div>
        </section>`;
    }

    /*
     * 「自定义列」用 kit 的 modal（Acceptance-to-Front P1 单：本页自建 `.insights-modal`，
     * 没有 Escape 处理、关闭后焦点也不回到触发按钮，键盘用户打开后出不来）。
     *
     * 结构按 kit 的 modal 契约给：`.dwrt-kit-modal-layer[data-dwrt-component="modal"]` 外层、
     * `.dwrt-kit-modal[role=dialog]` 面板、关闭控件带 `data-dwrt-modal-close`。kit 的
     * `mountModal()` 据此接管 Escape、Tab 焦点陷阱与 `returnFocus`，本页不再自备这些。
     *
     * 保留 `data-insights-modal` 与 `data-modal-close`：现有的开关逻辑按它们取节点。
     * 开合仍走 `hidden`（不是 kit 的 is-open），所以两边都留着 —— 换开合机制属于另一件事，
     * 本单要的是把焦点与键盘语义交给 kit。
     */
    function modalMarkup() {
      return `
        <div class="dwrt-kit-modal-layer insights-modal is-open" data-dwrt-component="modal" data-insights-modal hidden>
          <button class="dwrt-kit-modal-backdrop insights-modal-backdrop" data-dwrt-modal-close data-modal-close type="button" aria-label="关闭"></button>
          <section class="dwrt-kit-modal insights-modal-panel dwrt-glass-card insights-stable-glass" data-dwrt-modal-variant="copilot" role="dialog" aria-modal="true" aria-label="自定义列">
            <header class="dwrt-kit-modal-header">
              <h3>自定义列</h3>
              <button class="dwrt-kit-modal-close" type="button" data-dwrt-modal-close data-modal-close aria-label="关闭"><i data-lucide="x" aria-hidden="true"></i></button>
            </header>
            <div class="dwrt-kit-modal-body">
              <div class="insights-column-grid">
                ${DEFAULT_COLUMNS.map(([id, label]) => `
                  <label class="dwrt-kit-field" data-dwrt-component="field">
                    <input type="checkbox" data-column="${id}" ${state.columns.has(id) ? 'checked' : ''}>
                    <span>${html(label)}</span>
                  </label>`).join('')}
              </div>
            </div>
          </section>
        </div>`;
    }

    function activitySectionLabel(section) {
      return {
        'url-audit': 'URL 审计',
        'online-records': '终端在线',
        'im-records': 'IM 在线',
        'protocol-app': '协议与应用',
        'audit-status': '审计状态'
      }[section] || '活动';
    }

    function auditQuery(section = state.activitySection) {
      if (!state.audit.query[section]) {
        const base = { q: '', page: 0, pageSize: 50, sort: '' };
        if (section === 'url-audit') state.audit.query[section] = { ...base, view: 'records', action: '', category: '' };
        else if (section === 'online-records') state.audit.query[section] = { ...base, action: '', ifname: '' };
        else if (section === 'im-records') state.audit.query[section] = { ...base, app: '', state: '' };
        else if (section === 'protocol-app') state.audit.query[section] = { ...base, view: 'protocols', category: '', unknownFirst: false, sort: 'bytes' };
        else state.audit.query[section] = { ...base };
      }
      return state.audit.query[section];
    }

    function setAuditQuery(section, patch = {}) {
      const current = auditQuery(section);
      state.audit.query[section] = { ...current, ...patch };
    }

    function auditEndpointParams(section, extra = {}) {
      const query = auditQuery(section);
      const range = apiSecondsRange(nowRange());
      const params = new URLSearchParams();
      params.set('from', String(range.timestampFrom));
      params.set('to', String(range.timestampTo));
      params.set('page', String(Math.max(0, firstNumber(query.page))));
      params.set('pageSize', String(Math.max(10, firstNumber(query.pageSize, 50))));
      if (query.q) params.set('q', query.q);
      if (query.sort) params.set('sort', query.sort);
      Object.entries(extra).forEach(([key, value]) => {
        if (value !== undefined && value !== null && String(value) !== '') params.set(key, String(value));
      });
      return params.toString();
    }

    function auditErrorText(result, fallback = '') {
      if (!result || result.ok) return '';
      const raw = result.raw || result.error && result.error.payload || {};
      return firstText(
        raw && raw.error && raw.error.message,
        raw && raw.message,
        result.error && result.error.message,
        result.status ? `HTTP ${result.status}` : '',
        fallback,
        '接口不可用'
      );
    }

    async function refreshAuditSection(requestSeq) {
      const section = state.activitySection;
      const query = auditQuery(section);
      state.audit.loading = true;
      state.audit.errors = {};
      const statusReq = fetchWithRetry('audit_status', ENDPOINTS.auditStatus, 1, 250);
      let requests = [];
      if (section === 'url-audit') {
        const params = auditEndpointParams(section, { mode: query.view || 'records', action: query.action, category: query.category });
        requests = [statusReq, fetchWithRetry('audit_urls', ENDPOINTS.auditUrls(params), 1, 250)];
      } else if (section === 'online-records') {
        const params = auditEndpointParams(section, { action: query.action, ifname: query.ifname });
        requests = [statusReq, fetchWithRetry('audit_online_records', ENDPOINTS.auditOnlineRecords(params), 1, 250)];
      } else if (section === 'im-records') {
        const params = auditEndpointParams(section, { app: query.app, state: query.state });
        requests = [statusReq, fetchWithRetry('audit_im_records', ENDPOINTS.auditImRecords(params), 1, 250)];
      } else if (section === 'protocol-app') {
        const params = auditEndpointParams(section, { category: query.category, unknownFirst: query.unknownFirst ? '1' : '' });
        requests = [
          statusReq,
          fetchWithRetry('audit_protocols', ENDPOINTS.auditProtocols(params), 1, 250),
          fetchWithRetry('audit_apps', ENDPOINTS.auditApps(params), 1, 250)
        ];
      } else if (section === 'audit-status') {
        requests = [statusReq];
      } else {
        requests = [statusReq];
      }
      const results = await Promise.all(requests);
      if (!state.root || requestSeq !== state.refreshSeq) return false;
      const [status, first, second] = results;
      const nextStatus = normalizePayload(status);
      if (nextStatus) state.audit.status = nextStatus;
      if (section === 'url-audit') state.audit.urls = normalizePayload(first);
      if (section === 'online-records') state.audit.onlineRecords = normalizePayload(first);
      if (section === 'im-records') state.audit.imRecords = normalizePayload(first);
      if (section === 'protocol-app') {
        state.audit.protocols = normalizePayload(first);
        state.audit.apps = normalizePayload(second);
      }
      const errors = Array.from(new Set(results.map((result) => auditErrorText(result)).filter(Boolean)));
      if (errors.length) state.audit.errors[section] = errors.join('；');
      state.audit.loading = false;
      return true;
    }

    function auditPayload(key) {
      return state.audit[key] && typeof state.audit[key] === 'object' ? state.audit[key] : {};
    }

    function auditNested(payload, path) {
      let value = payload;
      for (const part of String(path || '').split('.')) {
        if (!part) continue;
        if (!value || typeof value !== 'object') return null;
        value = value[part];
      }
      return value;
    }

    function auditList(payload, paths) {
      if (Array.isArray(payload)) return payload;
      if (!payload || typeof payload !== 'object') return [];
      for (const path of paths) {
        const value = auditNested(payload, path);
        if (Array.isArray(value)) return value;
      }
      return [];
    }

    function auditCount(payload, rows) {
      return firstNumber(payload.total, payload.total_count, payload.count, payload.totalRows, payload.total_rows, rows.length);
    }

    function auditTimestamp(value) {
      const number = Number(value);
      if (!Number.isFinite(number) || number <= 0) return 0;
      return number > 1e12 ? Math.floor(number / 1000) : Math.floor(number);
    }

    function auditTime(value) {
      const ts = auditTimestamp(value);
      if (!ts) return '--';
      return new Date(ts * 1000).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    function auditDate(value) {
      const ts = auditTimestamp(value);
      if (!ts) return '--';
      return new Date(ts * 1000).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
    }

    function auditDuration(value) {
      const seconds = Math.max(0, Math.floor(Number(value) || 0));
      if (!seconds) return '--';
      const days = Math.floor(seconds / 86400);
      const hours = Math.floor((seconds % 86400) / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      if (days) return `${days}天 ${hours}小时`;
      if (hours) return `${hours}小时 ${minutes}分钟`;
      if (minutes) return `${minutes}分钟`;
      return `${seconds}秒`;
    }

    function auditPercent(value, digits = 1) {
      const number = Number(value);
      if (!Number.isFinite(number)) return '--';
      return `${number.toFixed(digits).replace(/\.0+$/, '')}%`;
    }

    function auditBytes(row) {
      return firstNumber(row.bytes, row.total_bytes, row.traffic_bytes) + firstNumber(row.up_bytes, row.tx_bytes, row.upload_bytes) + firstNumber(row.down_bytes, row.rx_bytes, row.download_bytes);
    }

    function auditActionLabel(value) {
      const text = String(value || '').toLowerCase();
      if (/block|deny|drop|reject|阻断|拦截|阻止/.test(text)) return '阻断';
      if (/review|watch|关注|审查/.test(text)) return '关注';
      if (/allow|accept|pass|放行|允许/.test(text)) return '放行';
      if (/online|上线|续期|renew/.test(text)) return firstText(value, '上线');
      if (/offline|下线|离线|disconnect/.test(text)) return firstText(value, '离线');
      return firstText(value, '--');
    }

    function auditTone(value) {
      const text = String(value || '').toLowerCase();
      if (/block|deny|drop|reject|阻断|拦截|离线|下线|offline|disconnect/.test(text)) return 'bad';
      if (/review|watch|关注|warn|漫游|roam|后台|away|idle/.test(text)) return 'warn';
      if (/allow|accept|pass|放行|允许|在线|上线|续期|online|active|renew/.test(text)) return 'good';
      return 'neutral';
    }

    function auditMainCell(title, subtitle = '') {
      /* Long values are truncated with an ellipsis and the full text is put on the
         kit tooltip, so a URL or MAC+IP pair no longer runs into the next column.
         The tooltip carries both lines because either one can be the clipped one. */
      /* 副标题与主标题逐字相同时不渲染第二行：后端在 `category` / `type` 上经常给同一个
         值（协议与应用页实测两列都是 `service`），重复一遍没有信息量，只是把行高撑高。 */
      const mainText = firstText(title);
      if (firstText(subtitle) === mainText) subtitle = '';
      const full = [mainText, firstText(subtitle)].filter(Boolean).join('\n');
      const tooltip = full ? ` data-dwrt-tooltip="${escapeAttr(full)}" tabindex="0"` : '';
      return `<span class="insights-audit-main-cell"${tooltip}><strong>${html(title || '--')}</strong>${subtitle ? `<small>${html(subtitle)}</small>` : ''}</span>`;
    }

    /*
     * 审计表格里的「图标在前、名字在后」两件事共用一套渲染。
     *
     * 图标来源都是后端已经给出的真实字段，不是前端猜的：
     *   应用  `/api/v1/audit/apps`、`/audit/urls`、`/audit/protocols` 的行上带
     *         `icon_url` / `icon_file` / `icon_key`（30.1 实测 `IOS更新` →
     *         `/static/images/logo/ios.svg`，`谷歌通用协议` → `google.svg`）。
     *         固件里 4694 张图标。
     *   设备  走全局 `DWRT_DEVICE_IMAGES.resolve()`，与仪表盘/终端列表同一套
     *         优先级（自定义 > 指纹 > 品牌 logo）。在线记录行带 `vendor`
     *         (`Synology`) / `model` (`Lester-Synology SA6400`) / `mac`，够它出图。
     *
     * 取不到图就退回首字母字形，不硬塞一张不相干的图；`onerror` 时隐藏 img 并
     * 让父元素切到字形，一个 404 不会在列里留下破图占位。
     */
    function auditIconMarkup(src, fallbackText, extraClass = '') {
      const fallback = html(String(firstText(fallbackText) || '').trim().slice(0, 1).toUpperCase() || '·');
      const cls = `insights-audit-cell-icon${extraClass ? ` ${extraClass}` : ''}`;
      if (!src) return `<span class="${cls} is-glyph" aria-hidden="true"><i>${fallback}</i></span>`;
      return `<span class="${cls}" aria-hidden="true">`
        + `<img src="${html(src)}" alt="" loading="lazy" decoding="async"`
        + ` onerror="this.hidden=true;this.parentElement.classList.add('is-glyph')">`
        + `<i>${fallback}</i></span>`;
    }

    /* 应用图标的真实来源。服务类条目（https、tcp/30164）不是应用，没有品牌图标，
       后端也不给 icon 字段，这时不出图，交给字形兜底。 */
    function auditAppIconSrc(row) {
      if (!row || typeof row !== 'object') return '';
      const direct = firstText(row.icon_url, row.icon, row.logo_url, row.logo);
      if (direct) return normalizeIconUrl(direct);
      const file = firstText(row.icon_file, row.icon_key && `${row.icon_key}.svg`);
      return file ? `/static/images/logo/${encodeURIComponent(file)}` : '';
    }

    function auditDeviceIconSrc(row) {
      if (!row || typeof row !== 'object') return '';
      const images = globalThis.DWRT_DEVICE_IMAGES;
      if (images && typeof images.resolve === 'function') {
        const resolved = images.resolve(row);
        if (resolved && resolved.src) return resolved.src;
      }
      return normalizeIconUrl(firstText(row.icon_url, row.icon, row.image, row.image_url));
    }

    /* 图标 + 主/副标题。图标在前、文字在后（用户 2026-08-09 的要求），
       tooltip 与纯文字版本保持一致，所以直接复用 auditMainCell 的输出。 */
    function auditIconCell(iconMarkup, body) {
      return `<span class="insights-audit-icon-cell">${iconMarkup}${body}</span>`;
    }

    /*
     * `evidence` 只有在真的是证据（域名、命中规则）时才配当副标题。
     *
     * 后端目前把这一行的口径自述原样写进 `evidence`，取值与同行的 `semantic` 完全相同
     * （30.1 实测 `/api/v1/audit/apps?limit=40` 四十行全部是
     * `top_applications_from_audit_flow_event_lifecycle_bytes`）。那串东西说明的是这份
     * 数据怎么聚合出来的，不是这一行的证据，每行还都一样，挂在应用名下面纯噪声。
     *
     * 判据用「与同行的口径字段逐字相等」，不用前缀黑名单：后端将来往 `evidence` 里写
     * 真正的域名或命中规则时，等值判断不会误伤，而 `top_applications_from_` 这类前缀
     * 匹配会把恰好同前缀的真实证据一起滤掉。
     */
    function auditEvidenceText(row) {
      const evidence = firstText(row && row.evidence);
      if (!evidence) return '';
      const selfDescribing = [
        row && row.semantic,
        row && row.count_semantics,
        row && row.ranking_basis,
        row && row.accounting_source
      ];
      if (selfDescribing.some((value) => firstText(value) === evidence)) return '';
      return evidence;
    }

    /*
     * 审计各页的「这一行是不是真的识别出应用了」判据。活动页/概览卡用的
     * `activityIsRealApplication()` 读 `is_application` / `app_identified`，但审计
     * BFF（`/api/v1/audit/apps`、`/audit/protocols`、`/audit/urls`）的行上这两个布尔
     * 并不总是存在——30.1 实测 `audit/protocols` 的行只有 `app_id` / `name_source` /
     * `category` / `identity_kind`，`audit/urls` 走的是另一套 `app_unresolved` /
     * `app_name_source`。所以这里按后端**实际给出的**标记逐层退让，不指定单一字段。
     *
     * 注意 `name_source` 的取值不是交接单里写的 `signature_app_id`：实测是
     * `audit_flow.destination_app`（已识别）与 `audit_flow.service`（仅服务），
     * URL 侧则是 `signature_host` / `signature_db` / `unresolved_app_id` /
     * `audit_url_event`。按 `signature_app_id` 精确匹配会把所有行判成未识别。
     */
    function auditRowIsIdentifiedApp(row) {
      if (!row || typeof row !== 'object') return false;
      // 后端已经算好结论时直接采信，不再自行推断。
      if (row.app_unresolved === true) return false;
      if (row.application_name_is_fallback === true) return false;
      if (row.is_application === true || row.app_identified === true) return true;
      const kind = String(firstText(row.identity_kind)).toLowerCase();
      if (kind) return kind === 'application';
      // 其次看 app_id：> 0 表示命中了特征库里的具体应用。
      const appId = firstNumber(row.app_id, row.appid, row.canonical_app_id);
      if (appId > 0) return true;
      const source = String(firstText(row.name_source, row.app_name_source)).toLowerCase();
      if (/service|unresolved|audit_url_event/.test(source)) return false;
      if (/app|signature/.test(source)) return true;
      // 最后才看分类：后端在 app_id <= 0 时把 category 写成 service/network_service。
      const category = String(firstText(row.category)).toLowerCase();
      if (/^(service|network_service)$/.test(category)) return false;
      return appId > 0;
    }

    /* 未识别行的说明文案。原始串（`no_dpi_signature_match_proto_port_used`、
       `service_or_protocol_fallback_not_app_id`）对用户没有意义，翻成人话；
       遇到未收录取值时保留原文，不猜也不吞掉。 */
    const AUDIT_IDENTITY_REASONS = {
      no_dpi_signature_match_proto_port_used: '特征库未匹配，只能按协议/端口标识这段流量',
      no_dpi_signature_match_hostname_used: '特征库未匹配，只能按目的主机名标识这段流量',
      no_dpi_signature_no_hostname: '特征库未匹配，且没有可用的主机名',
      no_dpi_signature_match: '特征库未匹配到具体应用',
      encrypted_no_sni: '流量加密且未暴露 SNI，无法归属到具体应用',
      service_or_protocol_fallback_not_app_id: '这是协议/端口标识，不是应用名',
      unresolved_app_id: '流量里带了应用编号，但特征库里查不到对应应用',
      audit_url_event: '这条记录没有携带应用识别结果'
    };

    function auditIdentityHint(row) {
      if (!row || typeof row !== 'object') return '';
      const raw = firstText(row.identity_reason, row.application_identity_precision, row.app_name_source);
      const known = raw && AUDIT_IDENTITY_REASONS[raw];
      const lines = ['未识别为具体应用'];
      if (known) lines.push(known);
      else if (raw) lines.push(`后端给出的原因：${raw}`);
      const label = firstText(row.service, row.app_proto, row.protocol, row.family);
      if (label) lines.push(`实际标识：${label}`);
      return lines.join('\n');
    }

    /*
     * 应用列的渲染。识别出应用才把名字放在主位；否则主位写「未识别」，把后端给的
     * 服务/端口标识降级到副标题，并把原因挂上 tooltip。这样信息一条都不丢，但
     * `tcp/10195` 不再冒充应用名。
     *
     * 后端在 `app_id <= 0` 时既可能给服务标识（`dw_audit_apply_app_identity`），也
     * 可能留空（URL 审计的 `unresolved_app_id` 分支把 `app_name` 清成 `""`），两种
     * 都要能渲染，所以标识为空时只显示「未识别」而不留一个空副标题。
     *
     * 识别出应用时图标在前、名字在后；未识别的条目没有品牌图标可用，出字形占位，
     * 这样两组行的文字仍然左对齐，不会因为有没有图而错开一列。
     */
    function auditAppCell(row, name) {
      const text = firstText(name, row && row.app, row && row.app_name, row && row.application);
      if (auditRowIsIdentifiedApp(row)) {
        return auditIconCell(
          auditIconMarkup(auditAppIconSrc(row), text),
          auditMainCell(text || '--', '')
        );
      }
      const fallback = firstText(text, row && row.service, row && row.app_proto, row && row.protocol);
      const hint = auditIdentityHint(row);
      const tooltip = hint ? ` data-dwrt-tooltip="${escapeAttr(hint)}" tabindex="0"` : '';
      return auditIconCell(
        auditIconMarkup('', fallback || '未识别'),
        `<span class="insights-audit-main-cell is-unidentified"${tooltip}>`
          + `<strong>未识别</strong>`
          + (fallback ? `<small>${html(fallback)}</small>` : '')
          + `</span>`
      );
    }

    function auditMetric(label, value, hint = '') {
      return `<div class="insights-audit-metric"><span>${html(label)}</span><strong>${html(value)}</strong>${hint ? `<em>${html(hint)}</em>` : ''}</div>`;
    }

    function auditStatusObject() {
      const status = auditPayload('status');
      const urls = auditPayload('urls');
      const nested = urls.url_audit && typeof urls.url_audit === 'object' ? urls.url_audit : {};
      return { ...nested, ...status };
    }

    function auditStatusStripMarkup() {
      const status = auditStatusObject();
      if (!Object.keys(status).length) return '';
      const enabled = status.enabled === false ? '未启用' : status.enabled === true ? '正在记录' : firstText(status.state, status.status, '--');
      const mode = firstText(status.mode, status.audit_mode, status.url_mode, '--');
      return `<section class="insights-audit-status-strip dwrt-glass-card insights-stable-glass">
        <div><span>审计引擎</span><strong>${html(enabled)}</strong><small>${html(mode)} · 保留 ${html(firstText(status.retention_days, status.retention, '--'))} 天 · ${html(firstText(status.storage, status.backend, '--'))}</small></div>
        <div class="insights-audit-status-metrics">
          ${auditMetric('队列', formatInteger(firstNumber(status.queue_depth, status.queue)), 'pending')}
          ${auditMetric('库体积', formatBytes(firstNumber(status.db_size_bytes, status.db_bytes)), 'audit.db')}
          ${auditMetric('容量上限', formatInteger(firstNumber(status.max_rows, status.row_limit)), 'rows')}
          ${auditMetric('丢弃', formatInteger(firstNumber(status.dropped_events, status.dropped)), firstNumber(status.dropped_events, status.dropped) ? 'warn' : 'good')}
          ${auditMetric('落盘', auditDate(firstNumber(status.last_flush_at, status.last_flush, status.updated_at)), 'flush')}
        </div>
      </section>`;
    }

    function auditSelectOptions(values, current, allLabel = '全部') {
      const unique = Array.from(new Set((values || []).map((value) => firstText(value)).filter(Boolean))).sort((a, b) => a.localeCompare(b, 'zh-Hans-CN'));
      return [`<option value="" ${!current ? 'selected' : ''}>${html(allLabel)}</option>`]
        .concat(unique.map((value) => `<option value="${html(value)}" ${String(current || '') === String(value) ? 'selected' : ''}>${html(value)}</option>`))
        .join('');
    }


    function auditActionOptions(current) {
      const options = [
        ['', '全部'],
        ['allow', '放行'],
        ['block', '阻断'],
        ['review', '关注']
      ];
      return options.map(([value, label]) => `<option value="${html(value)}" ${String(current || '') === value ? 'selected' : ''}>${html(label)}</option>`).join('');
    }

    /*
     * 审计页的全部控件收进表格工具条（用户第 11 条）：时间范围由平铺按钮排改为下拉，
     * 手动刷新按钮删除，数据由 startAuditPolling() 的轮询与筛选变更触发。
     */
    function auditRangeSelect() {
      const ranges = Object.entries(ACTIVITY_PERIODS).filter(([id]) => id !== 'month');
      const options = ranges.map(([id, item]) => (id === 'custom'
        ? `<option value="custom" ${state.period === 'custom' ? 'selected' : ''}>${html(customRangeLabel() || '自定义范围')}</option>`
        : `<option value="${html(id)}" ${state.period === id ? 'selected' : ''}>${html(item.label)}</option>`)).join('');
      return `<label class="insights-audit-select insights-audit-range-select" data-dwrt-component="field"><select class="dwrt-kit-select" data-dwrt-component="select" data-audit-range aria-label="审计时间范围">${options}</select></label>`;
    }

    function auditToolbarControls(section, controls = '') {
      const query = auditQuery(section);
      return `<div class="insights-audit-toolbar-controls">
        ${controls}
        ${auditRangeSelect()}
        <label class="dwrt-kit-expand-search insights-audit-search" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${searchSvg()}</span><input type="search" value="${html(query.q || '')}" placeholder="搜索" data-audit-search="${html(section)}" autocomplete="off" spellcheck="false" aria-label="搜索审计记录"></label>
        <button class="insights-audit-link" data-audit-export type="button">导出</button>
      </div>`;
    }

    function customRangeLabel() {
      if (!state.customRange) return '';
      const fmt = (value) => {
        const date = new Date(Number(value) || 0);
        if (!Number.isFinite(date.getTime())) return '';
        return `${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
      };
      const start = fmt(state.customRange.start);
      const end = fmt(state.customRange.end);
      return start && end ? `${start} → ${end}` : '';
    }

    /* 四张顶部状态卡片，用 kit 的概览卡组件，与其他页面一致。 */
    function auditOverviewCards(items = []) {
      const cards = (items || []).filter((item) => item && firstText(item.label) !== '');
      if (!cards.length) return '';
      const renderer = window.DWRT_UI_KIT && window.DWRT_UI_KIT.overviewCardsMarkup;
      const mapped = cards.map((item, index) => ({
        key: `audit-stat-${index + 1}`,
        label: item.label,
        value: item.value,
        detail: firstText(item.detail),
        icon: item.icon,
        tone: item.tone === 'good' ? 'ok' : item.tone === 'bad' ? 'bad' : item.tone === 'warn' ? 'warn' : 'neutral'
      }));
      if (typeof renderer === 'function') return renderer(mapped, { className: 'insights-audit-overview', label: '审计概览' });
      return `<section class="dwrt-kit-overview-grid insights-audit-overview" aria-label="审计概览">${mapped.map((item) => `<article class="dwrt-kit-overview-card is-${html(item.tone)}"><div class="dwrt-kit-overview-content"><span class="dwrt-kit-overview-label">${html(item.label)}</span><strong>${html(item.value)}</strong><small>${html(item.detail)}</small></div></article>`).join('')}</section>`;
    }

    function auditTabs(section, tabs) {
      const query = auditQuery(section);
      return `<div class="insights-audit-tabs dwrt-kit-tabs" role="tablist">
        ${tabs.map(([id, label]) => `<button class="dwrt-kit-tab ${query.view === id ? 'is-active' : ''}" data-audit-view="${html(section)}" data-value="${html(id)}" type="button" aria-selected="${query.view === id ? 'true' : 'false'}">${html(label)}</button>`).join('')}
      </div>`;
    }

    /*
     * 卡片内部不再写页面标题与说明，左侧菜单已经指明当前页面（用户第 11 条）。
     * 保留条数与接口异常提示，后者是真实状态，不能隐藏。
     */
    function auditTableMarkup(title, subtitle, count, columns, rows, empty, tableClass = '', options = {}) {
      const error = firstText(options.error);
      const loadingText = state.loading || state.audit.loading ? '读取中' : `${formatInteger(count)} 条`;
      return `<section class="insights-audit-table-card dwrt-kit-table-wrap dwrt-glass-card insights-stable-glass ${html(tableClass)}">
        <div class="dwrt-kit-table-toolbar insights-audit-table-toolbar" data-dwrt-component="toolbar">
          <div class="dwrt-kit-table-title">
            <span class="dwrt-kit-table-count">${html(loadingText)}</span>
            ${error ? `<span class="is-warning" title="${html(error)}">接口未完全就绪：${html(error)}</span>` : ''}
          </div>
          ${firstText(options.controls)}
        </div>
        <div class="dwrt-kit-table-scroll insights-audit-table-scroll">
          <table class="dwrt-kit-table insights-audit-table">
            <thead><tr>${columns.map((column) => `<th class="${html(column.className || '')}">${column.sort ? `<button type="button" data-audit-sort="${html(column.sort)}">${html(column.label)}</button>` : html(column.label)}</th>`).join('')}</tr></thead>
            <tbody>
              ${rows.length ? rows.map((row) => `<tr>${columns.map((column) => `<td class="${html(column.className || '')}">${column.render(row)}</td>`).join('')}</tr>`).join('') : `<tr><td colspan="${columns.length}"><div class="dwrt-kit-table-empty insights-audit-empty-state"><strong>${html(empty.title)}</strong><span>${html(empty.detail || '')}</span></div></td></tr>`}
            </tbody>
          </table>
        </div>
      </section>`;
    }

    function auditWorkbenchMarkup(section, inner) {
      const label = activitySectionLabel(section);
      return `<main class="insights-main insights-main-activity insights-main-audit" aria-label="${html(label)}">
        <div class="insights-audit-workbench" data-audit-section="${html(section)}">
          ${inner}
        </div>
      </main>`;
    }

    function urlAuditSource() {
      const payload = auditPayload('urls');
      return payload.url_audit && typeof payload.url_audit === 'object' ? payload.url_audit : payload;
    }

    function urlAuditRows() {
      const source = urlAuditSource();
      const rows = auditList(source, ['records', 'items', 'rows', 'data', 'results']).map((row, index) => ({
        id: firstText(row.id, row.key, `url-${index}`),
        ts: firstNumber(row.ts, row.time, row.timestamp, row.last_seen, row.first_seen),
        client: firstText(row.client, row.client_name, row.hostname, row.device, row.name),
        ip: firstText(row.ip, row.client_ip, row.src_ip, row.source_ip),
        mac: firstText(row.mac, row.client_mac, row.source_mac),
        account: firstText(row.account, row.user, row.username),
        host: firstText(row.host, row.domain, row.hostname, row.dst_host),
        url: firstText(row.url, row.uri, row.request_uri, row.path),
        path: firstText(row.path, row.uri_path),
        app: firstText(row.app, row.application, row.app_name),
        category: firstText(row.category, row.type, row.class),
        action: firstText(row.action, row.verdict, row.policy_action),
        /* 应用图标字段原样带下来。URL 审计的行在识别成功时带
           `icon_key` / `icon_file` / `icon_url`（30.1 实测 `谷歌通用协议` →
           `/static/images/logo/google.svg`），归一化时丢掉就再也拿不回来。 */
        icon_url: firstText(row.icon_url),
        icon_file: firstText(row.icon_file),
        icon_key: firstText(row.icon_key),
        /* 识别标记必须原样带下来，否则下游只剩一个 `app` 字符串，无法区分
           「应用名」和「协议/端口兜底标识」。URL 审计路径给的是
           `app_name_source` + `app_unresolved`（`jmx_dreamingwrt_api.c` 的
           audit_urls 分支），app/protocol 路径给的是 `name_source` /
           `identity_kind` / `app_id`，两套都收。 */
        app_id: firstNumber(row.app_id, row.appid, row.canonical_app_id),
        app_unresolved: row.app_unresolved === true,
        app_name_source: firstText(row.app_name_source),
        name_source: firstText(row.name_source),
        identity_kind: firstText(row.identity_kind),
        identity_reason: firstText(row.identity_reason),
        is_application: row.is_application === true,
        app_identified: row.app_identified === true,
        application_name_is_fallback: row.application_name_is_fallback === true,
        service: firstText(row.service),
        app_proto: firstText(row.app_proto),
        protocol: firstText(row.protocol),
        hits: firstNumber(row.hits, row.count, row.requests, 1),
        up_bytes: firstNumber(row.up_bytes, row.tx_bytes, row.upload_bytes),
        down_bytes: firstNumber(row.down_bytes, row.rx_bytes, row.download_bytes),
        wan: firstText(row.wan, row.ifname, row.interface),
        evidence: firstText(auditEvidenceText(row), row.reason, row.rule, row.source),
        method: firstText(row.method),
        status: firstText(row.status, row.status_code)
      }));
      return auditClientFilterRows(rows, ['client', 'ip', 'mac', 'account', 'host', 'url', 'app', 'category', 'evidence']);
    }

    function urlDomainRows() {
      const source = urlAuditSource();
      const direct = auditList(source, ['domains', 'domain_records', 'hosts']);
      const rows = direct.length ? direct : deriveUrlDomains(urlAuditRows());
      return rows.map((row, index) => ({
        id: firstText(row.id, row.host, row.domain, `domain-${index}`),
        host: firstText(row.host, row.domain, row.name),
        app: firstText(row.app, row.application, row.app_name),
        category: firstText(row.category, row.type),
        icon_url: firstText(row.icon_url),
        icon_file: firstText(row.icon_file),
        icon_key: firstText(row.icon_key),
        /* 与记录视图同一套识别标记，聚合时一并带过来（见 deriveUrlDomains）。 */
        app_id: firstNumber(row.app_id, row.appid, row.canonical_app_id),
        app_unresolved: row.app_unresolved === true,
        app_name_source: firstText(row.app_name_source),
        name_source: firstText(row.name_source),
        identity_kind: firstText(row.identity_kind),
        identity_reason: firstText(row.identity_reason),
        is_application: row.is_application === true,
        app_identified: row.app_identified === true,
        application_name_is_fallback: row.application_name_is_fallback === true,
        service: firstText(row.service),
        app_proto: firstText(row.app_proto),
        protocol: firstText(row.protocol),
        clients: firstNumber(row.clients, row.client_count, row.devices),
        hits: firstNumber(row.hits, row.count, row.requests),
        up_bytes: firstNumber(row.up_bytes, row.tx_bytes, row.upload_bytes),
        down_bytes: firstNumber(row.down_bytes, row.rx_bytes, row.download_bytes),
        first_seen: firstNumber(row.first_seen, row.start_time),
        last_seen: firstNumber(row.last_seen, row.ts, row.time),
        action: firstText(row.action, row.verdict)
      }));
    }

    function deriveUrlDomains(records) {
      const map = new Map();
      records.forEach((row) => {
        const host = row.host || row.url || '--';
        /* 聚合时把识别标记跟着第一条带过来。只留 `app` 字符串的话，域名视图会把
           `tcp/10195` 这类兜底标识当应用名显示在副标题里。 */
        const identity = {
          app_id: row.app_id,
          app_unresolved: row.app_unresolved,
          app_name_source: row.app_name_source,
          name_source: row.name_source,
          identity_kind: row.identity_kind,
          identity_reason: row.identity_reason,
          is_application: row.is_application,
          app_identified: row.app_identified,
          application_name_is_fallback: row.application_name_is_fallback,
          service: row.service,
          app_proto: row.app_proto,
          protocol: row.protocol,
          /* 图标跟着识别标记一起走。下面「先有应用名才换标记」的分支会整组覆盖，
             图标留在同一个对象里才不会出现「换了应用名却还挂着上一个图标」。 */
          icon_url: row.icon_url,
          icon_file: row.icon_file,
          icon_key: row.icon_key
        };
        const current = map.get(host) || { host, app: row.app, category: row.category, ...identity, clientsSet: new Set(), hits: 0, up_bytes: 0, down_bytes: 0, first_seen: row.ts, last_seen: row.ts, action: row.action };
        if (row.mac || row.ip || row.client) current.clientsSet.add(row.mac || row.ip || row.client);
        current.hits += firstNumber(row.hits, 1);
        current.up_bytes += firstNumber(row.up_bytes);
        current.down_bytes += firstNumber(row.down_bytes);
        current.first_seen = Math.min(auditTimestamp(current.first_seen) || auditTimestamp(row.ts), auditTimestamp(row.ts) || auditTimestamp(current.first_seen));
        current.last_seen = Math.max(auditTimestamp(current.last_seen), auditTimestamp(row.ts));
        /* 之前没有应用名、而这一条识别出了应用：整组识别标记一起换过来，
           否则会出现「有应用名但标记仍说未识别」的自相矛盾状态。 */
        if (!current.app && row.app) {
          current.app = row.app;
          Object.assign(current, identity);
        }
        if (!current.category) current.category = row.category;
        map.set(host, current);
      });
      return Array.from(map.values()).map((item) => ({ ...item, clients: item.clientsSet.size }));
    }

    function auditClientFilterRows(rows, keys) {
      const section = state.activitySection;
      const query = auditQuery(section);
      let output = rows || [];
      const q = String(query.q || '').trim().toLowerCase();
      if (q) output = output.filter((row) => keys.some((key) => String(row[key] || '').toLowerCase().includes(q)));
      if (section === 'url-audit') {
        if (query.action) output = output.filter((row) => String(row.action || '').toLowerCase().includes(String(query.action).toLowerCase()));
        if (query.category) output = output.filter((row) => row.category === query.category);
      }
      if (section === 'online-records') {
        if (query.action) output = output.filter((row) => row.action === query.action);
        if (query.ifname) output = output.filter((row) => row.ifname === query.ifname);
      }
      if (section === 'im-records') {
        if (query.app) output = output.filter((row) => row.app === query.app);
        if (query.state) output = output.filter((row) => row.state === query.state);
      }
      if (section === 'protocol-app') {
        if (query.category) output = output.filter((row) => row.category === query.category || String(row.type || '').startsWith(query.category));
        /* 「未知优先」与统计徽标必须用同一判据，否则按了按钮却什么都不动
           （文本匹配对 `tcp/8889` 恒为 false，实测 20 条协议行排序前后完全一致）。 */
        if (query.unknownFirst) output = output.slice().sort((a, b) => (auditEntityIsUnknown(b) ? 1 : 0) - (auditEntityIsUnknown(a) ? 1 : 0));
      }
      return output;
    }

    function auditSortRows(rows, key) {
      if (!key) return rows;
      const descKeys = new Set(['ts', 'last_seen', 'first_seen', 'hits', 'bytes', 'up_rate', 'down_rate', 'connections', 'clients', 'duration', 'heartbeat_count']);
      return rows.slice().sort((a, b) => {
        const av = a[key];
        const bv = b[key];
        const an = Number(av);
        const bn = Number(bv);
        const delta = Number.isFinite(an) && Number.isFinite(bn) ? an - bn : String(av || '').localeCompare(String(bv || ''), 'zh-Hans-CN');
        return descKeys.has(key) ? -delta : delta;
      });
    }

    function urlAuditMarkup() {
      const section = 'url-audit';
      const query = auditQuery(section);
      const records = auditSortRows(urlAuditRows(), query.sort || 'ts');
      const domains = auditSortRows(urlDomainRows(), query.sort || 'hits');
      const rows = query.view === 'domains' ? domains : records;
      const source = urlAuditSource();
      const categories = [
        ...auditList(source, ['categories']).map((item) => firstText(item.name, item.category, item)),
        ...records.map((row) => row.category).filter(Boolean)
      ];
      const controls = `${auditTabs(section, [['records', '记录'], ['domains', '域名']])}
        <label class="insights-audit-select"><span>动作</span><select data-audit-filter="${section}" data-key="action">${auditActionOptions(query.action)}</select></label>
        <label class="insights-audit-select"><span>分类</span><select data-audit-filter="${section}" data-key="category">${auditSelectOptions(categories, query.category)}</select></label>`;
      const totalBytes = records.reduce((sum, row) => sum + row.up_bytes + row.down_bytes, 0);
      const blocked = records.filter((row) => auditTone(row.action) === 'bad' || auditTone(row.action) === 'warn').length;
      const uniqueHosts = new Set(records.map((row) => row.host).filter(Boolean)).size || domains.length;
      const columns = query.view === 'domains' ? [
        /* 副标题原来是 `row.app || row.category`，未识别时会把 `tcp/10195` 挂在域名
           下面当应用名。识别出应用才写应用名，否则退回分类。 */
        { label: '域名', sort: 'host', render: (row) => auditMainCell(row.host, (auditRowIsIdentifiedApp(row) && row.app) || row.category || '') },
        { label: '分类', sort: 'category', render: (row) => html(row.category || '--') },
        { label: '终端', sort: 'clients', className: 'num', render: (row) => html(formatInteger(row.clients)) },
        { label: '次数', sort: 'hits', className: 'num', render: (row) => html(formatInteger(row.hits)) },
        { label: '流量', sort: 'bytes', className: 'num', render: (row) => html(formatBytes(row.up_bytes + row.down_bytes)) },
        { label: '最近访问', sort: 'last_seen', render: (row) => html(auditDate(row.last_seen)) },
        { label: '动作', sort: 'action', render: (row) => `<span class="insights-audit-pill ${auditTone(row.action)}">${html(auditActionLabel(row.action))}</span>` }
      ] : [
        { label: '时间', sort: 'ts', render: (row) => html(auditTime(row.ts)) },
        { label: '终端', sort: 'client', render: (row) => auditMainCell(row.client || row.ip || '--', [row.ip, row.mac, row.account].filter(Boolean).join(' · ')) },
        { label: '域名 / URL', sort: 'host', render: (row) => auditMainCell(row.host || '--', row.path || row.url || '') },
        { label: '应用', sort: 'app', render: (row) => auditAppCell(row, row.app) },
        { label: '分类', sort: 'category', render: (row) => html(row.category || '--') },
        { label: '动作', sort: 'action', render: (row) => `<span class="insights-audit-pill ${auditTone(row.action)}">${html(auditActionLabel(row.action))}</span>` },
        { label: '次数', sort: 'hits', className: 'num', render: (row) => html(formatInteger(row.hits)) },
        { label: '流量', sort: 'bytes', className: 'num', render: (row) => html(formatBytes(row.up_bytes + row.down_bytes)) },
        { label: '证据', render: (row) => html(firstText(row.evidence, row.wan, row.method, row.status, '--')) }
      ];
      const stats = [
        { label: 'URL 记录', value: formatInteger(records.length), icon: auditStatIcon('count') },
        { label: '独立域名', value: formatInteger(uniqueHosts), icon: auditStatIcon('protocol') },
        { label: '阻断/关注', value: formatInteger(blocked), tone: blocked ? 'warn' : '', icon: auditStatIcon('offline') },
        { label: '关联流量', value: formatBytes(totalBytes), icon: auditStatIcon('traffic') }
      ];
      return auditWorkbenchMarkup(section, `
        ${auditOverviewCards(stats)}
        ${auditTableMarkup('', '', auditCount(source, rows), columns, rows, { title: '没有 URL 审计记录', detail: state.audit.errors[section] ? '后端接口未返回可用数据。' : '当前筛选条件下没有记录。' }, 'url-audit-table', { stats, error: state.audit.errors[section], controls: auditToolbarControls(section, controls) })}`);
    }

    function onlineRecordRows() {
      const payload = auditPayload('onlineRecords');
      const rows = auditList(payload, ['online_records', 'records', 'items', 'rows', 'data', 'results']).map((row, index) => ({
        id: firstText(row.id, row.key, `online-${index}`),
        ts: firstNumber(row.ts, row.time, row.timestamp, row.last_seen),
        client: firstText(row.client, row.client_name, row.hostname, row.device, row.name),
        action: firstText(row.action, row.event, row.state),
        ip: firstText(row.ip, row.client_ip, row.ipv4, row.ipv6),
        mac: firstText(row.mac, row.client_mac),
        ifname: firstText(row.ifname, row.interface, row.port),
        network: firstText(row.network, row.ssid, row.vlan, row.network_name),
        connection: firstText(row.connection, row.link, row.media, row.radio),
        duration: firstNumber(row.duration, row.uptime, row.online_duration),
        lease_time: firstNumber(row.lease_time, row.lease, row.dhcp_lease_time),
        signal: firstNumber(row.signal, row.rssi),
        vendor: firstText(row.vendor, row.brand),
        device_type: firstText(row.device_type, row.type),
        os: firstText(row.os, row.os_name),
        /* `DWRT_DEVICE_IMAGES.resolve()` 按 vendor / model / hostname 匹配品牌
           logo，也认指纹图字段。归一化里丢掉 model 就等于把 `Lester-Synology
           SA6400` 这类型号扔了，品牌匹配会少一条线索，所以一并带下来。 */
        model: firstText(row.model, row.device_model),
        image_url: firstText(row.image_url, row.web_image),
        image: firstText(row.image),
        icon_url: firstText(row.icon_url),
        icon: firstText(row.icon),
        source: firstText(row.source, row.evidence),
        reason: firstText(row.reason, row.detail)
      }));
      return auditClientFilterRows(rows, ['client', 'ip', 'mac', 'ifname', 'network', 'vendor', 'device_type', 'os', 'source', 'reason']);
    }

    function onlineRecordsMarkup() {
      const section = 'online-records';
      const query = auditQuery(section);
      const rows = auditSortRows(onlineRecordRows(), query.sort || 'ts');
      const actions = rows.map((row) => row.action).filter(Boolean);
      const ifaces = rows.map((row) => row.ifname).filter(Boolean);
      const controls = `<label class="insights-audit-select"><span>动作</span><select data-audit-filter="${section}" data-key="action">${auditSelectOptions(actions, query.action)}</select></label>
        <label class="insights-audit-select"><span>接口</span><select data-audit-filter="${section}" data-key="ifname">${auditSelectOptions(ifaces, query.ifname)}</select></label>`;
      const online = rows.filter((row) => /上线|在线|续期|renew|online/i.test(row.action)).length;
      const offline = rows.filter((row) => /离线|下线|offline|disconnect/i.test(row.action)).length;
      const roam = rows.filter((row) => /漫游|roam/i.test(row.action)).length;
      const columns = [
        { label: '时间', sort: 'ts', render: (row) => html(auditTime(row.ts)) },
        /* 设备图在前、MAC 在后（用户 2026-08-09 的要求）。图走全局
           `DWRT_DEVICE_IMAGES.resolve()`，与仪表盘/终端列表同一套优先级；
           `client` 在这份数据里就是 MAC（后端未给主机名时的取值）。 */
        {
          label: '设备',
          sort: 'client',
          render: (row) => auditIconCell(
            auditIconMarkup(auditDeviceIconSrc(row), firstText(row.vendor, row.client), 'is-device'),
            auditMainCell(row.client || '--', [row.vendor, row.device_type, row.os].filter(Boolean).join(' / '))
          )
        },
        { label: '动作', sort: 'action', render: (row) => `<span class="insights-audit-pill ${auditTone(row.action)}">${html(auditActionLabel(row.action))}</span>` },
        { label: 'IP / MAC', sort: 'ip', render: (row) => auditMainCell(row.ip || '--', row.mac || '') },
        { label: '接口', sort: 'ifname', render: (row) => html(row.ifname || '--') },
        { label: '网络', sort: 'network', render: (row) => html(row.network || '--') },
        { label: '在线时长', sort: 'duration', className: 'num', render: (row) => html(auditDuration(row.duration)) },
        { label: '来源 / 原因', render: (row) => auditMainCell(row.source || '--', row.reason || row.connection || '') }
      ];
      const stats = [
        { label: '事件数', value: formatInteger(rows.length), icon: auditStatIcon('count') },
        { label: '上线/续期', value: formatInteger(online), tone: online ? 'good' : '', icon: auditStatIcon('online') },
        { label: '离线', value: formatInteger(offline), tone: offline ? 'bad' : '', icon: auditStatIcon('offline') },
        { label: '漫游', value: formatInteger(roam), tone: roam ? 'warn' : '', icon: auditStatIcon('roam') }
      ];
      return auditWorkbenchMarkup(section, `
        ${auditOverviewCards(stats)}
        ${auditTableMarkup('', '', auditCount(auditPayload('onlineRecords'), rows), columns, rows, { title: '没有终端在线记录', detail: state.audit.errors[section] ? '后端接口未返回可用数据。' : '当前筛选条件下没有记录。' }, 'online-record-table', { stats, error: state.audit.errors[section], controls: auditToolbarControls(section, controls) })}`);
    }

    function imRecordRows() {
      const payload = auditPayload('imRecords');
      const rows = auditList(payload, ['im_records', 'records', 'items', 'rows', 'data', 'results']).map((row, index) => ({
        id: firstText(row.id, row.key, `im-${index}`),
        ts: firstNumber(row.ts, row.time, row.timestamp, row.last_seen),
        first_seen: firstNumber(row.first_seen, row.start_time),
        client: firstText(row.client, row.client_name, row.hostname, row.device, row.name),
        app: firstText(row.app, row.application, row.app_name),
        account: firstText(row.account, row.user, row.username),
        state: firstText(row.state, row.status),
        ip: firstText(row.ip, row.client_ip),
        mac: firstText(row.mac, row.client_mac),
        device_type: firstText(row.device_type, row.type),
        os: firstText(row.os, row.os_name),
        wan: firstText(row.wan, row.ifname),
        confidence: firstNumber(row.confidence, row.score),
        heartbeat_count: firstNumber(row.heartbeat_count, row.heartbeats, row.count),
        duration: firstNumber(row.duration, row.online_duration),
        last_domain: firstText(row.last_domain, row.domain, row.host),
        evidence: firstText(auditEvidenceText(row), row.reason, row.rule),
        risk: firstText(row.risk, row.severity)
      }));
      return auditClientFilterRows(rows, ['client', 'app', 'account', 'state', 'ip', 'mac', 'device_type', 'os', 'last_domain', 'evidence']);
    }

    function imRecordsMarkup() {
      const section = 'im-records';
      const query = auditQuery(section);
      const rows = auditSortRows(imRecordRows(), query.sort || 'ts');
      const apps = rows.map((row) => row.app).filter(Boolean);
      const states = rows.map((row) => row.state).filter(Boolean);
      const controls = `<label class="insights-audit-select"><span>应用</span><select data-audit-filter="${section}" data-key="app">${auditSelectOptions(apps, query.app)}</select></label>
        <label class="insights-audit-select"><span>状态</span><select data-audit-filter="${section}" data-key="state">${auditSelectOptions(states, query.state)}</select></label>`;
      const online = rows.filter((row) => /在线|active|online|后台/i.test(row.state)).length;
      const away = rows.filter((row) => /离开|idle|away|后台/i.test(row.state)).length;
      const accounts = new Set(rows.map((row) => `${row.app}:${row.account || row.client}`).filter(Boolean)).size;
      const columns = [
        { label: '最近在线', sort: 'ts', render: (row) => html(auditTime(row.ts)) },
        { label: '应用', sort: 'app', render: (row) => auditMainCell(row.app || '--', firstText(row.last_domain) || auditEvidenceText(row) || '') },
        { label: '账号 / 状态', sort: 'account', render: (row) => auditMainCell(row.account || '--', `<span>${row.state || '--'}</span>`.replace(/<[^>]+>/g, '')) },
        { label: '终端', sort: 'client', render: (row) => auditMainCell(row.client || '--', [row.device_type, row.os].filter(Boolean).join(' / ')) },
        { label: 'IP / MAC', sort: 'ip', render: (row) => auditMainCell(row.ip || '--', row.mac || '') },
        { label: '心跳', sort: 'heartbeat_count', className: 'num', render: (row) => html(formatInteger(row.heartbeat_count)) },
        { label: '持续时间', sort: 'duration', className: 'num', render: (row) => html(auditDuration(row.duration)) },
        { label: '置信度', sort: 'confidence', className: 'num', render: (row) => html(row.confidence ? auditPercent(row.confidence, 0) : '--') }
      ];
      const stats = [
        { label: '记录数', value: formatInteger(rows.length), icon: auditStatIcon('count') },
        { label: '在线状态', value: formatInteger(online), tone: online ? 'good' : '', icon: auditStatIcon('presence') },
        { label: '后台/离开', value: formatInteger(away), tone: away ? 'warn' : '', icon: auditStatIcon('away') },
        { label: '账号数', value: formatInteger(accounts), icon: auditStatIcon('accounts') }
      ];
      return auditWorkbenchMarkup(section, `
        ${auditOverviewCards(stats)}
        ${auditTableMarkup('', '', auditCount(auditPayload('imRecords'), rows), columns, rows, { title: '没有 IM 在线记录', detail: state.audit.errors[section] ? '后端接口未返回可用数据。' : '当前筛选条件下没有记录。' }, 'im-record-table', { stats, error: state.audit.errors[section], controls: auditToolbarControls(section, controls) })}`);
    }

    function auditEntityRows(kind) {
      const payload = auditPayload(kind);
      const rows = auditList(payload, [kind === 'protocols' ? 'protocols' : 'app_records', 'records', 'items', 'rows', 'data', 'results', 'apps']).map((row, index) => {
        const type = firstText(row.type, row.category, row.class, '未分类');
        const parts = String(type).split('/');
        return {
          id: firstText(row.id, row.proto_id, row.app_id, `${kind}-${index}`),
          kind,
          name: firstText(row.name, row.app, row.protocol, row.application),
          type,
          /* `/audit/apps` 的行带 `icon_key` / `icon_file` / `icon_url`
             （30.1 实测 `IOS更新` → `/static/images/logo/ios.svg`）；
             `/audit/protocols` 的行只有一个空 `icon`，出不了图，走字形兜底。 */
          icon_url: firstText(row.icon_url),
          icon_file: firstText(row.icon_file),
          icon_key: firstText(row.icon_key),
          category: firstText(row.category, parts[0], type),
          subcategory: firstText(row.subcategory, parts.slice(1).join('/')),
          /* 识别标记原样带下来。30.1 实测 `audit/protocols` 的行带
             `app_id: 0` / `name_source: "audit_flow.service"` /
             `identity_kind: "service"`，`audit/apps` 的行还额外带
             `app_unresolved` 与 `application_identity_precision`。 */
          app_id: firstNumber(row.app_id, row.appid, row.canonical_app_id),
          app_unresolved: row.app_unresolved === true,
          name_source: firstText(row.name_source),
          identity_kind: firstText(row.identity_kind),
          identity_reason: firstText(row.identity_reason),
          application_identity_precision: firstText(row.application_identity_precision),
          is_application: row.is_application === true,
          app_identified: row.app_identified === true,
          application_name_is_fallback: row.application_name_is_fallback === true,
          service: firstText(row.service),
          app_proto: firstText(row.app_proto),
          protocol: firstText(row.protocol),
          family: firstText(row.family),
          connections: firstNumber(row.connections, row.conn_count, row.connection_count),
          up_rate: firstNumber(row.up_rate, row.tx_rate, row.rate_up),
          down_rate: firstNumber(row.down_rate, row.rx_rate, row.rate_down),
          bytes: firstNumber(row.bytes, row.total_bytes, row.traffic_bytes),
          clients: firstNumber(row.clients, row.client_count, row.devices),
          /* 在归一化处就把口径自述滤掉：归一化后的行不再带 `semantic`，
             等值判据只有在这里（还看得到原始行）才成立。 */
          evidence: firstText(auditEvidenceText(row), row.domain, row.host, row.rule),
          wan: firstText(row.wan, row.ifname, row.interface),
          last_seen: firstNumber(row.last_seen, row.ts, row.time),
          confidence: firstNumber(row.confidence, row.score),
          domains: Array.isArray(row.domains) ? row.domains.join(', ') : firstText(row.domains, row.domain),
          ports: Array.isArray(row.ports) ? row.ports.join(', ') : firstText(row.ports, row.port)
        };
      });
      return auditClientFilterRows(rows, ['name', 'type', 'category', 'subcategory', 'evidence', 'domains', 'ports', 'wan']);
    }

    /*
     * 「未知项」的判据。原来是 `/未知|unknown/i.test(row.name + row.type)` 的文本匹配，
     * 这个口径不成立：30.1 实测 20 条协议行里没有一条名字含「未知」，而其中 18 条是
     * `tcp/8889` 这类纯端口兜底 —— 恰恰全是未识别项，却一条都统计不到，「未知项 0」
     * 因此毫无意义。
     *
     * 两个 Tab 的口径必须分开，否则会反向做错：
     * - 「应用」页的行若 `identity_kind !== "application"`，那它就是未识别（实测 40 条
     *   里 26 条如此），这是这份交接单要修的主症状。
     * - 「协议」页的行**全部**是 `identity_kind: "service"`，因为那一栏展示的本来就是
     *   协议/服务。把它们一律算成未知会让「未知项」等于总数，同样读不出信息。这里只把
     *   连协议都没识别出来的算未知：裸 `tcp/12345` 端口标识，或后端明说 `unknown`。
     */
    function auditEntityIsUnknown(row) {
      if (!row || typeof row !== 'object') return false;
      const kind = String(firstText(row.identity_kind)).toLowerCase();
      if (kind === 'unknown') return true;
      if (row.kind === 'apps') return !auditRowIsIdentifiedApp(row);
      const name = String(firstText(row.name, row.service, row.app_proto));
      if (/^(tcp|udp|sctp)[:/]\d+$/i.test(name)) return true;
      if (!name) return true;
      /* 不回退到文本匹配。后端已经用 `identity_kind` 明确表过态，而名字里是否含
         「未知」二字与它是否被识别无关：实测 20 条协议行没有一条含这两个字。
         剩下的情况（有名字、非裸端口、后端未说 unknown）按已识别处理。 */
      return /^unknown$/i.test(name);
    }

    function protocolAppMarkup() {
      const section = 'protocol-app';
      const query = auditQuery(section);
      const protocols = auditEntityRows('protocols');
      const apps = auditEntityRows('apps');
      const selectedRows = query.view === 'apps' ? apps : protocols;
      const rows = auditSortRows(selectedRows, query.sort || 'bytes');
      const categories = [...protocols, ...apps].map((row) => row.category).filter(Boolean);
      const controls = `${auditTabs(section, [['protocols', '协议'], ['apps', '应用']])}
        <label class="insights-audit-select"><span>分类</span><select data-audit-filter="${section}" data-key="category">${auditSelectOptions(categories, query.category)}</select></label>
        <button class="insights-audit-link ${query.unknownFirst ? 'is-active' : ''}" data-audit-unknown type="button">未知优先</button>`;
      const totalBytes = rows.reduce((sum, row) => sum + row.bytes, 0);
      const totalConnections = rows.reduce((sum, row) => sum + row.connections, 0);
      const unknown = rows.filter(auditEntityIsUnknown).length;
      const columns = [
        /* 「应用」页的名称列必须区分应用名与协议/端口兜底标识：后端在
           `app_id <= 0` 时把 `tcp/10195` 写进 `app_name`，直接渲染就等于把端口号
           冒充成应用。「协议」页展示的本来就是协议名，照原样显示。 */
        {
          label: '名称',
          sort: 'name',
          render: (row) => (query.view === 'apps' && !auditRowIsIdentifiedApp(row)
            ? auditAppCell(row, row.name)
            /* 图标在前、名字在后。「应用」页用后端给的品牌图标；「协议」页
               的行不带 icon 字段，出首字母字形，列对齐仍然一致。 */
            : auditIconCell(
              auditIconMarkup(auditAppIconSrc(row), row.name),
              auditMainCell(row.name || '--', auditEvidenceText(row) || firstText(row.domains) || '')
            ))
        },
        { label: '分类', sort: 'category', render: (row) => auditMainCell(row.category || '--', row.subcategory || row.type || '') },
        { label: '连接数', sort: 'connections', className: 'num', render: (row) => html(formatInteger(row.connections)) },
        { label: '上行速率', sort: 'up_rate', className: 'num traffic-up', render: (row) => html(formatRate(row.up_rate)) },
        { label: '下行速率', sort: 'down_rate', className: 'num traffic-down', render: (row) => html(formatRate(row.down_rate)) },
        { label: '累计流量', sort: 'bytes', className: 'num', render: (row) => html(formatBytes(row.bytes)) },
        { label: '终端', sort: 'clients', className: 'num', render: (row) => html(formatInteger(row.clients)) },
        { label: '线路 / 端口', render: (row) => auditMainCell(row.wan || '--', row.ports || '') }
      ];
      const title = query.view === 'apps' ? '应用审计' : '协议审计';
      const stats = [
        { label: query.view === 'apps' ? '应用数' : '协议数', value: formatInteger(rows.length), icon: auditStatIcon('protocol') },
        { label: '连接数', value: formatInteger(totalConnections), icon: auditStatIcon('connections') },
        { label: '累计流量', value: formatBytes(totalBytes), icon: auditStatIcon('traffic') },
        { label: '未知项', value: formatInteger(unknown), tone: unknown ? 'warn' : '', icon: auditStatIcon('unknown') }
      ];
      return auditWorkbenchMarkup(section, `
        ${auditOverviewCards(stats)}
        ${auditTableMarkup('', '', rows.length, columns, rows, { title: `没有${query.view === 'apps' ? '应用' : '协议'}审计记录`, detail: state.audit.errors[section] ? '后端接口未返回可用数据。' : '当前筛选条件下没有记录。' }, 'protocol-app-table', { stats, error: state.audit.errors[section], controls: auditToolbarControls(section, controls) })}`);
    }

    function auditStatusMarkup() {
      const section = 'audit-status';
      const status = auditStatusObject();
      const caps = status.capabilities || status.support || status.flags || status;
      const rows = Object.entries(caps || {})
        .filter(([key, value]) => !['capabilities', 'support', 'flags'].includes(key) && typeof value !== 'object')
        .map(([key, value]) => ({ key, value }));
      const columns = [
        { label: '能力 / 配置', sort: 'key', render: (row) => auditMainCell(row.key, auditStatusHint(row.key)) },
        { label: '值', render: (row) => `<span class="insights-audit-pill ${row.value === true ? 'good' : row.value === false ? 'bad' : 'neutral'}">${html(String(row.value))}</span>` }
      ];
      const stats = [
        { label: '状态', value: status.enabled === false ? '未启用' : status.enabled === true ? '正在记录' : firstText(status.status, '--'), tone: status.enabled === false ? 'bad' : status.enabled === true ? 'good' : '', icon: auditStatIcon('status') },
        { label: '保留', value: `${firstText(status.retention_days, status.retention, '--')} 天`, icon: auditStatIcon('retention') },
        { label: '库体积', value: formatBytes(firstNumber(status.db_size_bytes, status.db_bytes)), icon: auditStatIcon('dbSize') },
        { label: '丢弃事件', value: formatInteger(firstNumber(status.dropped_events, status.dropped)), tone: firstNumber(status.dropped_events, status.dropped) ? 'warn' : '', icon: auditStatIcon('dropped') }
      ];
      return auditWorkbenchMarkup(section, `
        ${auditOverviewCards(stats)}
        ${auditTableMarkup('', '', rows.length, columns, rows, { title: '没有审计状态数据', detail: state.audit.errors[section] ? '后端接口未返回可用数据。' : '等待 /api/v1/audit/status 返回状态。' }, 'audit-status-table', { stats, error: state.audit.errors[section], controls: auditToolbarControls(section, '') })}`);
    }

    function auditStatusHint(key) {
      const hints = {
        enabled: '审计是否启用',
        mode: '留存模式',
        retention_days: '保留天数',
        max_rows: '最大行数',
        queue_depth: '写入队列',
        dropped_events: '丢弃事件',
        last_flush_at: '最近落盘',
        url_audit_supported: 'URL 审计',
        online_records_supported: '终端在线记录',
        im_records_supported: 'IM 在线记录',
        protocol_summary_supported: '协议聚合'
      };
      return hints[key] || '';
    }

    function activityAuditMarkup() {
      const section = state.activitySection;
      if (section === 'url-audit') return urlAuditMarkup();
      if (section === 'online-records') return onlineRecordsMarkup();
      if (section === 'im-records') return imRecordsMarkup();
      if (section === 'protocol-app') return protocolAppMarkup();
      if (section === 'audit-status') return auditStatusMarkup();
      return auditWorkbenchMarkup(section, `<div class="insights-audit-error"><strong>${html(activitySectionLabel(section))}</strong><span>未知审计页面。</span></div>`);
    }

    function mainMarkup() {
      if (state.mode === 'activity') {
        if (isAuditActivitySection()) return activityAuditMarkup();
        return `
          <main class="insights-main insights-main-activity" aria-label="活动内容">
            <div class="insights-activity-board ${state.activityChartEnabled ? '' : 'is-chart-hidden'}">
              ${state.activityChartEnabled ? activityChartMarkup() : ''}
              ${activityTableMarkup()}
            </div>
          </main>`;
      }
      return `
        <main class="insights-main insights-main-flows" aria-label="洞察内容">
          <div class="insights-main-grid ${state.mapEnabled ? '' : 'is-map-hidden'}">
            ${overviewMarkup()}
            ${state.mapEnabled ? mapPanelMarkup() : ''}
          </div>
      </main>`;
    }

    function preserveActiveSearch() {
      const input = document.activeElement;
      if (!input?.matches?.('[data-insights-search], [data-audit-search]') || !state.root?.contains(input)) return null;
      const selector = input.matches('[data-audit-search]')
        ? `[data-audit-search="${escapeAttr(input.dataset.auditSearch || '')}"]`
        : '[data-insights-search]';
      return { input, selector, host: input.closest('.dwrt-kit-expand-search') || input.closest('label') };
    }

    function restorePreservedSearch(snapshot) {
      if (!snapshot?.host) return null;
      const replacement = state.root.querySelector(snapshot.selector);
      const replacementHost = replacement?.closest('.dwrt-kit-expand-search') || replacement?.closest('label');
      if (!replacementHost) return null;
      replacementHost.replaceWith(snapshot.host);
      return snapshot.input;
    }

    function render(target) {
      target = target || state.root;
      if (!target) return;
      const liveRender = target === state.root;
      const preservedSearch = liveRender ? preserveActiveSearch() : null;
      if (liveRender && state.mounted) disposeRenderedMaps(target);
      const scrollState = liveRender ? captureUiScrollState() : null;
      target.classList.add('route-workspace', 'route-insights-host');
      target.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-home');
      target.hidden = false;
      const auditSection = isAuditActivitySection();
      target.innerHTML = `
        <div class="insights-shell ${auditSection ? 'is-audit-section' : ''}">
          ${auditSection ? '' : filterMarkup()}
          ${mainMarkup()}
        </div>
        ${modalMarkup()}`;
      const preservedInput = liveRender ? restorePreservedSearch(preservedSearch) : null;
      mountUiKit?.(target);
      bindDom(preservedInput, target);
      if (liveRender) {
        restoreUiScrollState(scrollState);
        scheduleMapRender();
        renderActivityChart();
      }
    }

    function renderAuditPoll() {
      const scrollState = captureUiScrollState();
      const preserve = window.DWRT_UI_KIT && window.DWRT_UI_KIT.preserveInteractionState;
      if (typeof preserve === 'function') {
        preserve(state.root, render);
      } else {
        render();
      }
      /* Kit restores immediately after morph. Audit rows can change the table's
         scroll geometry during that commit, and WebKit then clamps the same
         scroller to 0 on the next layout frame. Reapply the module's existing
         scroll snapshot after layout; node identity still comes from Kit. */
      restoreUiScrollState(scrollState);
    }

    function renderWithoutDisposingMaps() {
      if (!state.root) return;
      const preservedSearch = preserveActiveSearch();
      const scrollState = captureUiScrollState();
      state.root.classList.add('route-workspace', 'route-insights-host');
      state.root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-home');
      state.root.hidden = false;
      const auditSection = isAuditActivitySection();
      state.root.innerHTML = `
        <div class="insights-shell ${auditSection ? 'is-audit-section' : ''}">
          ${auditSection ? '' : filterMarkup()}
          ${mainMarkup()}
        </div>
        ${modalMarkup()}`;
      const preservedInput = restorePreservedSearch(preservedSearch);
      mountUiKit?.(state.root);
      bindDom(preservedInput);
      restoreUiScrollState(scrollState);
      scheduleMapRender();
      renderActivityChart();
    }

    function disposeRenderedMaps(root) {
      if (!root) return;
      root.querySelectorAll('[data-insights-echarts-map]').forEach((container) => disposeCyberMap(container));
      root.querySelectorAll('[data-insights-activity-chart]').forEach((container) => disposeActivityChart(container));
    }

    function replaceElementMarkup(target, markup) {
      if (!target) return false;
      const template = document.createElement('template');
      template.innerHTML = String(markup || '').trim();
      const next = template.content.firstElementChild;
      if (!next) return false;
      target.replaceWith(next);
      return true;
    }

    function patchElementContent(target, markup, selector) {
      if (!target) return false;
      const template = document.createElement('template');
      template.innerHTML = String(markup || '').trim();
      const next = selector ? template.content.querySelector(selector) : template.content.firstElementChild;
      if (!next) return false;
      target.replaceChildren(...Array.from(next.childNodes));
      /*
       * 增量刷新换掉的是从 <template> 搬来的裸节点，没有经过 mountUiKit()，
       * 所以 kit 的 tooltip / lucide 图标只在首帧活着，被第一次推送覆盖后就永久失效
       * （实测 `.insights-console-rank-name` 的 `dwrt-kit-tooltip-trigger` 为 false，
       * 悬浮弹不出玻璃 tooltip，而 design.md 洞察控制台第 7 条明文要求榜单名挂
       * tooltip 给全貌）。这里对刚替换进来的子树补挂一次。
       *
       * 重复调用是安全的：kit 的 mountTooltip() 以 tooltipState（WeakMap）去重，
       * 不会叠加监听；被替换掉的旧节点已从文档移除，WeakMap 会随节点一起回收。
       */
      mountUiKit?.(target);
      return true;
    }

    function patchStableCard(target, markup, selector) {
      const content = target && target.querySelector(':scope > [data-insights-card-content]');
      return patchElementContent(content, markup, `${selector} > [data-insights-card-content]`);
    }

    function updateMapDom() {
      if (!state.root) return;
      const points = mapDisplayPoints();
      const routes = mapRouteItems();
      const regionCount = mapPoints().length;
      const mapTitle = state.root.querySelector('.insights-map-panel-head span');
      if (mapTitle) mapTitle.textContent = regionCount ? `${regionCount} 个地区` : '等待地理流量数据';
      state.root.querySelectorAll('[data-insights-map-shell]').forEach((shell) => {
        const mapNode = shell.querySelector('[data-insights-echarts-map]');
        const role = mapNode && mapNode.dataset.mapRole === 'overview' ? 'overview' : 'main';
        const routeLayer = shell.querySelector('.insights-map-route-layer');
        if (routeLayer) {
          const limit = role === 'overview' ? 8 : CYBER_ROUTE_LIMIT;
          routeLayer.innerHTML = mapRouteLayerInnerMarkup(routes.slice(0, limit));
        }
        const layer = shell.querySelector('.insights-map-point-layer');
        if (layer) {
          const limit = role === 'overview' ? 16 : 32;
          layer.innerHTML = state.mapEnabled ? points.slice(0, limit).map((point, index) => mapPointMarkup(point, index)).join('') : '';
        }
        /*
         * 图例也必须走增量更新。首次 render() 时 geo 还没回来（routes / points 全空），
         * 图例算不出档位，此后所有刷新都走这条路径 —— 不在这里重建，图例就永远
         * 不出现（实测就是这样：shell 里只有 6 个子节点，没有 legend）。
         * 档位随数据变化，所以每次刷新都按当前数据重算，而不是只补一次。
         */
        const legend = shell.querySelector('[data-insights-map-legend]');
        if (legend && role !== 'overview') {
          legend.innerHTML = state.mapEnabled ? mapLegendInnerMarkup() : '';
          legend.hidden = !legend.innerHTML;
        }
      });
      /* render() rebuilds the shell from markup, so the pending/failed classes
         have to be re-applied rather than assumed to have survived. */
      updateMapStatusDom();
    }

    function updateFlowsRealtimeDom() {
      if (!state.root || state.mode !== 'flows') return false;
      const overview = state.root.querySelector('.insights-overview-row');
      let overviewUpdated = false;
      if (overview) {
        const nextMarkup = overviewMarkup();
        ['summary', 'destination', 'client', 'application'].forEach((kind) => {
          const target = overview.querySelector(`[data-insights-overview-card="${kind}"]`);
          overviewUpdated = patchStableCard(target, nextMarkup, `[data-insights-overview-card="${kind}"]`) || overviewUpdated;
        });
      }
      if (state.mapEnabled) updateMapDom();
      return overviewUpdated || (state.mapEnabled && Boolean(state.root.querySelector('[data-insights-map-shell]')));
    }

    function updateActivityStatsDom() {
      const totals = activityTotals();
      const values = {
        total: formatBytes(totals.total),
        download: formatBytes(totals.download),
        upload: formatBytes(totals.upload)
      };
      let updated = false;
      state.root?.querySelectorAll('[data-activity-stat-value]').forEach((node) => {
        const next = values[node.dataset.activityStatValue] || '';
        if (node.textContent !== next) node.textContent = next;
        updated = true;
      });
      return updated;
    }

    function updateActivityRealtimeDom() {
      if (!state.root || state.mode !== 'activity' || isAuditActivitySection()) return false;
      const chart = state.root.querySelector('[data-insights-activity-card="chart"]');
      const table = state.root.querySelector('[data-insights-activity-card="table"]');
      const tableScroll = table?.querySelector('.insights-activity-table-scroll');
      const scrollTop = tableScroll?.scrollTop || 0;
      const scrollLeft = tableScroll?.scrollLeft || 0;
      /* The chart is a live ECharts instance, so it is updated in place with a new
         option rather than having its markup replaced -- patching the container
         would throw away the canvas and the tooltip state on every push. */
      let chartUpdated = false;
      if (state.activityChartEnabled && chart) {
        renderActivityChart();
        chartUpdated = true;
      }
      const tableUpdated = patchStableCard(table, activityTableMarkup(), '[data-insights-activity-card="table"]');
      const nextTableScroll = table?.querySelector('.insights-activity-table-scroll');
      if (nextTableScroll) {
        nextTableScroll.scrollTop = scrollTop;
        nextTableScroll.scrollLeft = scrollLeft;
      }
      return updateActivityStatsDom() || chartUpdated || tableUpdated;
    }

    function preserveFilterScroll(update) {
      const scrollState = captureUiScrollState();
      update();
      restoreUiScrollState(scrollState);
    }

    function bindDom(preservedInput = null, root = state.root) {
      root.querySelector('[data-insights-tabs]')?.addEventListener('dwrt-tab-change', (event) => {
        const mode = event.detail && event.detail.value === 'activity' ? 'activity' : 'flows';
        if (mode === state.mode) return;
        state.mode = mode;
        state.activitySection = 'overview';
        if (state.mode === 'activity' && !ACTIVITY_PERIODS[state.period]) state.period = 'day';
        if (state.mode === 'flows' && !PERIODS[state.period]) state.period = 'day';
        state.refreshSeq += 1;
        state.loading = false;
        history.replaceState(null, '', `/app/#/insights/${mode === 'activity' ? 'activity' : 'flows'}`);
        subscribeInsightsRealtime();
        startAuditPolling();
        refresh();
      });
      const insightsSearch = root.querySelector('[data-insights-search]');
      if (insightsSearch && insightsSearch !== preservedInput) {
        insightsSearch.addEventListener('input', (event) => {
          state.search = event.target.value || '';
          window.clearTimeout(state.refreshTimer);
          state.refreshTimer = window.setTimeout(refresh, 320);
        });
      }
      root.querySelectorAll('[data-risk]').forEach((button) => button.addEventListener('click', () => {
        const value = button.dataset.risk;
        state.risks.has(value) ? state.risks.delete(value) : state.risks.add(value);
        refresh();
      }));
      root.querySelectorAll('[data-action-filter]').forEach((button) => button.addEventListener('click', () => {
        const value = button.dataset.actionFilter;
        state.actions.has(value) ? state.actions.delete(value) : state.actions.add(value);
        refresh();
      }));
      root.querySelectorAll('[data-period]').forEach((button) => button.addEventListener('click', () => {
        state.period = button.dataset.period || 'day';
        refresh();
      }));
      root.querySelector('[data-date-range-trigger]')?.addEventListener('click', async (event) => {
        const now = Date.now();
        const currentRange = state.customRange || {
          start: now - ((state.mode === 'flows' ? PERIODS[state.period] : ACTIVITY_PERIODS[state.period]) || PERIODS.day).ms,
          end: now
        };
        const picker = window.DWRT_UI_KIT && window.DWRT_UI_KIT.openDateRangePicker;
        if (typeof picker !== 'function') {
          state.notice = '日期选择器组件尚未加载。';
          render();
          return;
        }
        const result = await picker({
          anchor: event.currentTarget,
          range: currentRange,
          presets: true
        });
        if (!result) return;
        state.customRange = { start: result.start, end: result.end };
        state.period = 'custom';
        refresh();
      });
      root.querySelector('[data-summary-toggle]')?.addEventListener('change', (event) => {
        state.summaryEnabled = Boolean(event.target.checked);
        render();
      });
      root.querySelectorAll('input[name="insightsTrafficKind"]').forEach((input) => input.addEventListener('change', () => {
        state.trafficKind = input.value || 'all';
        refresh();
      }));
      root.querySelectorAll('input[name="insightsActivityAnchor"]').forEach((input) => input.addEventListener('change', () => {
        state.activityAnchor = input.value === 'application' ? 'application' : 'client';
        render();
      }));
      root.querySelectorAll('[data-activity-stat-metric]').forEach((button) => button.addEventListener('click', () => {
        state.activityStatMetric = button.dataset.activityStatMetric || 'total';
        render();
      }));
      root.querySelector('[data-activity-chart-toggle]')?.addEventListener('change', (event) => {
        state.activityChartEnabled = Boolean(event.target.checked);
        render();
      });
      root.querySelector('[data-map-toggle]')?.addEventListener('change', (event) => {
        state.mapEnabled = Boolean(event.target.checked);
        // Re-enabling the map reuses the cached snapshot for this scope so it
        // paints immediately instead of waiting on the fetch.
        state.geo = state.mapEnabled ? (state.geo || state.geoByScope[state.mapScope] || null) : null;
        // Hiding the map must not leave a stale failure notice behind for the
        // next time it is opened.
        if (!state.mapEnabled) { state.mapFetch = 'idle'; state.mapFetchError = ''; }
        subscribeInsightsRealtime();
        render();
        if (state.mapEnabled) refreshMapOnly();
      });
      root.querySelectorAll('[data-map-scope]').forEach((button) => button.addEventListener('click', () => {
        const next = button.dataset.mapScope === 'china' ? 'china' : 'world';
        if (next === state.mapScope) return;
        state.mapScope = next;
        /* Switching scope used to drop state.geo and run the full refresh, so a
           map-only change waited on insights_summary and network_wans. The
           highlight is painted first from cache, then only the geo endpoint is
           re-fetched. */
        state.geo = state.geoByScope[next] || null;
        render();
        scheduleMapRender();
        refreshMapOnly();
      }));
      root.querySelectorAll('[data-map-control]').forEach((button) => button.addEventListener('click', () => {
        const container = state.root && state.root.querySelector('[data-map-role="main"]');
        const action = button.dataset.mapControl;
        if (container && container.__dwrtCyberMap) {
          handleCyberMapControl(container, action);
          return;
        }
      }));
      root.querySelectorAll('[data-direction]').forEach((button) => button.addEventListener('click', () => {
        const value = button.dataset.direction || '';
        state.direction = state.direction === value ? '' : value;
        refresh();
      }));
      root.querySelectorAll('[data-insights-collapse]').forEach((button) => button.addEventListener('click', () => {
        const id = button.dataset.insightsCollapse;
        const willOpen = state.collapsed.has(id);
        preserveFilterScroll(() => {
          willOpen ? state.collapsed.delete(id) : state.collapsed.add(id);
          render();
        });
        if (willOpen && !filtersAreFresh()) {
          ensureFiltersLoaded(false).then(() => {
            if (!state.root || state.mode !== 'flows') return;
            preserveFilterScroll(render);
          });
        }
      }));
      root.querySelectorAll('[data-filter-group]').forEach((input) => input.addEventListener('change', () => {
        const group = input.dataset.filterGroup;
        if (!group) return;
        if (!(state.filtersSelected[group] instanceof Set)) state.filtersSelected[group] = new Set();
        input.checked ? state.filtersSelected[group].add(input.value) : state.filtersSelected[group].delete(input.value);
        refresh();
      }));
      root.querySelectorAll('[data-filter-mode]').forEach((input) => input.addEventListener('change', () => {
        const group = input.dataset.filterMode;
        if (!group || !input.checked) return;
        state.filterModes[group] = input.value === 'exclude' ? 'exclude' : 'include';
        refresh();
      }));
      root.querySelectorAll('[data-filter-search]').forEach((input) => input.addEventListener('input', () => {
        const group = input.dataset.filterSearch;
        if (!group) return;
        preserveFilterScroll(() => {
          state.filterSearch[group] = input.value || '';
          render();
        });
        if (!filtersAreFresh()) {
          ensureFiltersLoaded(false).then(() => {
            if (!state.root || state.mode !== 'flows') return;
            preserveFilterScroll(render);
          });
        }
        const next = state.root && state.root.querySelector(`[data-filter-search="${cssEscape(group)}"]`);
        if (next) {
          next.focus({ preventScroll: true });
          try { next.setSelectionRange(next.value.length, next.value.length); } catch (_) {}
        }
      }));
      root.querySelectorAll('[data-filter-selected-toggle]').forEach((button) => button.addEventListener('click', () => {
        const group = button.dataset.filterSelectedToggle;
        if (!group) return;
        preserveFilterScroll(() => {
          state.filterSelectedOpen[group] = state.filterSelectedOpen[group] === false;
          render();
        });
      }));
      root.querySelectorAll('[data-filter-remove]').forEach((button) => button.addEventListener('click', () => {
        const group = button.dataset.filterRemove;
        const value = button.dataset.filterValue;
        if (!group || value === undefined) return;
        if (state.filtersSelected[group] instanceof Set) state.filtersSelected[group].delete(value);
        refresh();
      }));
      root.querySelectorAll('[data-filter-select-all]').forEach((button) => button.addEventListener('click', () => {
        const group = button.dataset.filterSelectAll;
        if (!group) return;
        if (!filtersAreFresh()) {
          ensureFiltersLoaded(false).then(() => {
            if (!state.root || state.mode !== 'flows') return;
            state.filtersSelected[group] = new Set(filterValues(group).map(filterItemValue));
            refresh();
          });
          return;
        }
        state.filtersSelected[group] = new Set(filterValues(group).map(filterItemValue));
        refresh();
      }));
      root.querySelectorAll('[data-filter-clear-group]').forEach((button) => button.addEventListener('click', () => {
        const group = button.dataset.filterClearGroup;
        if (!group) return;
        state.filtersSelected[group] = new Set();
        refresh();
      }));
      root.querySelector('[data-insights-clear]')?.addEventListener('click', () => {
        state.risks.clear();
        state.actions.clear();
        state.direction = '';
        state.search = '';
        state.trafficKind = 'all';
        state.activityAnchor = 'client';
        state.filtersSelected = {};
        state.filterModes = {};
        state.filterSearch = {};
        state.filterSelectedOpen = {};
        state.notice = '';
        refresh();
      });
      root.querySelector('[data-insights-download]')?.addEventListener('click', downloadCsv);
      root.querySelector('[data-insights-columns]')?.addEventListener('click', () => {
        const modal = root.querySelector('[data-insights-modal]');
        if (modal) modal.hidden = false;
      });
      root.querySelector('[data-modal-close]')?.addEventListener('click', () => {
        const modal = root.querySelector('[data-insights-modal]');
        if (modal) modal.hidden = true;
      });
      root.querySelectorAll('[data-column]').forEach((input) => input.addEventListener('change', () => {
        input.checked ? state.columns.add(input.dataset.column) : state.columns.delete(input.dataset.column);
        if (!state.columns.size) state.columns.add('time');
        render();
        const modal = state.root.querySelector('[data-insights-modal]');
        if (modal) modal.hidden = false;
      }));
      bindAuditDom(root, preservedInput);
    }

    function bindAuditDom(root, preservedInput = null) {
      if (!isAuditActivitySection()) return;
      root.querySelectorAll('[data-audit-search]').forEach((input) => {
        if (input === preservedInput) return;
        input.addEventListener('input', () => {
        const section = input.dataset.auditSearch || state.activitySection;
        setAuditQuery(section, { q: input.value || '', page: 0 });
        window.clearTimeout(state.refreshTimer);
        state.refreshTimer = window.setTimeout(refresh, 260);
        });
      });
      root.querySelectorAll('[data-audit-filter]').forEach((select) => select.addEventListener('change', () => {
        const section = select.dataset.auditFilter || state.activitySection;
        const key = select.dataset.key;
        if (!key) return;
        setAuditQuery(section, { [key]: select.value || '', page: 0 });
        refresh();
      }));
      root.querySelectorAll('[data-audit-view]').forEach((button) => button.addEventListener('click', () => {
        const section = button.dataset.auditView || state.activitySection;
        const value = button.dataset.value || '';
        if (!value) return;
        setAuditQuery(section, { view: value, page: 0 });
        refresh();
      }));
      root.querySelectorAll('[data-audit-sort]').forEach((button) => button.addEventListener('click', () => {
        const key = button.dataset.auditSort || '';
        if (!key) return;
        setAuditQuery(state.activitySection, { sort: key, page: 0 });
        refresh();
      }));
      root.querySelector('[data-audit-unknown]')?.addEventListener('click', () => {
        const query = auditQuery('protocol-app');
        setAuditQuery('protocol-app', { unknownFirst: !query.unknownFirst, page: 0 });
        refresh();
      });
      root.querySelector('[data-audit-range]')?.addEventListener('change', async (event) => {
        const value = event.target.value || 'day';
        if (value !== 'custom') {
          state.period = value;
          refresh();
          return;
        }
        const now = Date.now();
        const currentRange = state.customRange || { start: now - ACTIVITY_PERIODS.day.ms, end: now };
        const picker = window.DWRT_UI_KIT && window.DWRT_UI_KIT.openDateRangePicker;
        if (typeof picker !== 'function') {
          state.notice = '日期选择器组件尚未加载。';
          render();
          return;
        }
        const result = await picker({ anchor: event.target, range: currentRange, presets: true });
        if (!result) {
          /* 取消时把下拉回弹到当前生效的范围，否则它会停在未生效的 custom 上。 */
          event.target.value = state.period;
          return;
        }
        state.customRange = { start: result.start, end: result.end };
        state.period = 'custom';
        refresh();
      });
      root.querySelector('[data-audit-export]')?.addEventListener('click', downloadAuditCsv);
    }

    function scheduleMapRender() {
      if (state.mode !== 'flows' || !state.root) return;
      /* Realtime pushes arrive as often as every 250ms while the update animation
         runs 420ms, so a bare rAF per message stacked several unfinished
         animations of the same arc on screen: the arcs read as duplicated copies
         fanning out. Renders are coalesced to one per frame, and pushes are
         additionally throttled so an animation can finish before the next one
         starts. The trailing call is always kept, so the final state still lands. */
      if (mapRender.frame) return;
      const wait = Math.max(0, MAP_RENDER_MIN_INTERVAL - (Date.now() - mapRender.lastAt));
      if (wait > 0) {
        if (mapRender.timer) return;
        mapRender.timer = window.setTimeout(() => {
          mapRender.timer = 0;
          scheduleMapRender();
        }, wait);
        return;
      }
      mapRender.frame = window.requestAnimationFrame(() => {
        mapRender.frame = 0;
        mapRender.lastAt = Date.now();
        renderVectorMap();
      });
    }

    function renderVectorMap() {
      if (!state.root || state.mode !== 'flows') return;
      if (!state.mapEnabled) {
        disposeRenderedMaps(state.root);
        return;
      }
      const cyberContainers = Array.from(state.root.querySelectorAll('[data-insights-echarts-map]'));
      cyberContainers.forEach((container) => renderCyberMapContainer(container));
    }

    function loadECharts() {
      if (window.echarts) return Promise.resolve(window.echarts);
      if (!window.__dwrtInsightsEChartsPromise) {
        window.__dwrtInsightsEChartsPromise = new Promise((resolve, reject) => {
          const existing = document.querySelector('script[src^="/static/vendor/echarts.min.js"]');
          const script = existing || document.createElement('script');
          const done = () => window.echarts ? resolve(window.echarts) : reject(new Error('echarts missing'));
          script.addEventListener('load', done, { once: true });
          script.addEventListener('error', () => {
            window.__dwrtInsightsEChartsPromise = null;
            reject(new Error('echarts load failed'));
          }, { once: true });
          if (!existing) {
            script.src = `/static/vendor/echarts.min.js?v=${encodeURIComponent(VERSION)}`;
            script.async = true;
            script.dataset.dwrtVendor = 'echarts';
            document.head.appendChild(script);
          } else if (window.echarts) {
            done();
          }
        });
      }
      return window.__dwrtInsightsEChartsPromise;
    }

    function localMapName(scope) {
      return `dwrt-${scope === 'china' ? 'china' : 'world'}-${LOCAL_MAP_VERSION}`;
    }

    function ensureLocalMapRegistered(echarts, scope) {
      const normalizedScope = scope === 'china' ? 'china' : 'world';
      const name = localMapName(normalizedScope);
      window.__dwrtLocalMapRegistry = window.__dwrtLocalMapRegistry || new Set();
      window.__dwrtLocalMapPromises = window.__dwrtLocalMapPromises || new Map();
      if (window.__dwrtLocalMapRegistry.has(name)) return Promise.resolve(name);
      if (window.__dwrtLocalMapPromises.has(name)) return window.__dwrtLocalMapPromises.get(name);
      const url = LOCAL_MAP_ASSETS[normalizedScope];
      const promise = fetch(`${url}?v=${encodeURIComponent(LOCAL_MAP_VERSION)}`, { cache: 'force-cache' })
        .then((response) => {
          if (!response.ok) throw new Error(`local map ${normalizedScope} ${response.status}`);
          return response.json();
        })
        .then((geoJson) => {
          echarts.registerMap(name, geoJson);
          window.__dwrtLocalMapRegistry.add(name);
          return name;
        });
      window.__dwrtLocalMapPromises.set(name, promise);
      return promise;
    }

    function renderCyberMapContainer(container) {
      const shell = container.closest('[data-insights-map-shell]');
      const fallback = shell && shell.querySelector('[data-insights-map-fallback]');
      if (!state.mapEnabled) {
        disposeCyberMap(container);
        shell?.classList.remove('has-vector-map', 'has-local-cyber-map', 'is-map-loading');
        if (fallback) fallback.hidden = false;
        return;
      }
      const role = container.dataset.mapRole || 'main';
      const scope = state.mapScope === 'china' ? 'china' : 'world';
      const rect = container.getBoundingClientRect();
      if (rect.width < 2 || rect.height < 2) {
        window.requestAnimationFrame(() => {
          if (container.isConnected) renderCyberMapContainer(container);
        });
        return;
      }
      shell?.classList.add('is-map-loading');
      if (fallback && !container.__dwrtCyberMap) fallback.hidden = false;
      loadECharts()
        .then((echarts) => ensureLocalMapRegistered(echarts, scope).then((mapName) => ({ echarts, mapName })))
        .then(({ echarts, mapName }) => {
          if (!state.root || state.mode !== 'flows' || !container.isConnected) return;
          let chart = container.__dwrtCyberMap;
          if (!chart) {
            chart = echarts.init(container, null, { renderer: 'canvas' });
            container.__dwrtCyberMap = chart;
            chart.on('click', (params) => {
              const info = params && params.data && params.data.dataInfo;
              if (!info) return;
              state.notice = firstText(info.label, info.name, info.ip, info.public_ip, '已选择地图节点');
              const footer = state.root && state.root.querySelector('.insights-footer-notice');
              if (footer) footer.textContent = state.notice;
            });
            chart.on('georoam', () => rememberCyberMapView(container));
            if ('ResizeObserver' in window) {
              container.__dwrtCyberResizeObserver = new ResizeObserver(() => {
                if (!container.isConnected) return;
                const rect = container.getBoundingClientRect();
                if (rect.width < 2 || rect.height < 2) return;
                chart.resize();
              });
              container.__dwrtCyberResizeObserver.observe(container);
            }
          }
          const nextKey = `${scope}|${role}`;
          const replace = container.__dwrtCyberKey !== nextKey;
          if (!replace) rememberCyberMapView(container);
          container.__dwrtCyberKey = nextKey;
          const mapView = storedCyberMapView(scope, role);
          container.__dwrtCyberZoom = mapView.zoom;
          /* Most pushes do not change the map topology. Re-running setOption for
             them replays the entrance animation for no reason, which is what made
             the arcs bloom, so an unchanged signature skips the update entirely. */
          const option = cyberMapOption(mapName, scope, role, mapView, { animateEntrance: replace });
          const signature = cyberMapSignature(scope, role, option);
          if (!replace && container.__dwrtCyberSignature === signature) {
            shell?.classList.remove('is-map-loading');
            shell?.classList.add('has-vector-map', 'has-local-cyber-map');
            if (fallback) fallback.hidden = true;
            return;
          }
          container.__dwrtCyberSignature = signature;
          chart.setOption(option, replace ? true : { notMerge: false, lazyUpdate: true });
          const currentRect = container.getBoundingClientRect();
          if (currentRect.width >= 2 && currentRect.height >= 2) chart.resize();
          shell?.classList.remove('is-map-loading');
          shell?.classList.add('has-vector-map', 'has-local-cyber-map');
          if (fallback) fallback.hidden = true;
        })
        .catch((error) => {
          shell?.classList.remove('has-vector-map', 'has-local-cyber-map', 'is-map-loading');
          if (fallback) {
            fallback.hidden = false;
            fallback.innerHTML = cyberMapUnavailableMarkup(error && error.message);
          }
        });
    }

    function cyberMapView(scope, role) {
      if (scope === 'china') {
        return role === 'overview'
          ? { center: [104.5, 35.5], zoom: 1.08, layoutSize: '91%', layoutCenter: ['50%', '52%'] }
          : { center: [104.5, 35.5], zoom: 1.18, layoutSize: '94%', layoutCenter: ['50%', '52%'] };
      }
      return role === 'overview'
        ? { center: [8, 22], zoom: 1.02, layoutSize: '116%', layoutCenter: ['50%', '53%'] }
        : { center: [8, 22], zoom: 1.08, layoutSize: '120%', layoutCenter: ['50%', '53%'] };
    }

    function cyberMapViewKey(scope, role) {
      return `${scope === 'china' ? 'china' : 'world'}|${role === 'overview' ? 'overview' : 'main'}`;
    }

    function storedCyberMapView(scope, role) {
      const defaults = cyberMapView(scope, role);
      const stored = state.mapViews[cyberMapViewKey(scope, role)] || {};
      return {
        ...defaults,
        center: Array.isArray(stored.center) && stored.center.length >= 2
          ? [Number(stored.center[0]), Number(stored.center[1])]
          : defaults.center,
        zoom: Number.isFinite(Number(stored.zoom)) ? Number(stored.zoom) : defaults.zoom
      };
    }

    function rememberCyberMapView(container) {
      const chart = container && container.__dwrtCyberMap;
      const key = container && container.__dwrtCyberKey;
      if (!chart || !key) return;
      const option = chart.getOption && chart.getOption();
      const geo = option && Array.isArray(option.geo) ? option.geo[0] : null;
      if (!geo) return;
      const center = Array.isArray(geo.center) && geo.center.length >= 2
        ? [Number(geo.center[0]), Number(geo.center[1])]
        : null;
      const zoom = Number(geo.zoom);
      const previous = state.mapViews[key] || {};
      state.mapViews[key] = {
        ...previous,
        ...(center && center.every(Number.isFinite) ? { center } : {}),
        ...(Number.isFinite(zoom) ? { zoom } : {})
      };
      if (Number.isFinite(zoom)) container.__dwrtCyberZoom = zoom;
    }

    function handleCyberMapControl(container, action) {
      const chart = container && container.__dwrtCyberMap;
      if (!chart) return;
      const role = container.dataset.mapRole || 'main';
      const scope = state.mapScope === 'china' ? 'china' : 'world';
      const view = cyberMapView(scope, role);
      if (action === 'reset') {
        state.mapViews[cyberMapViewKey(scope, role)] = { center: [...view.center], zoom: view.zoom };
        container.__dwrtCyberZoom = view.zoom;
        chart.setOption({ geo: { center: view.center, zoom: view.zoom, layoutCenter: view.layoutCenter, layoutSize: view.layoutSize } });
        return;
      }
      rememberCyberMapView(container);
      const currentView = storedCyberMapView(scope, role);
      const current = Number(currentView.zoom || view.zoom);
      const next = Math.max(0.72, Math.min(8, current * (action === 'zoom-in' ? 1.24 : 0.82)));
      state.mapViews[cyberMapViewKey(scope, role)] = { ...currentView, zoom: next };
      container.__dwrtCyberZoom = next;
      chart.setOption({ geo: { zoom: next } });
    }

    /* Signature over what the map actually draws: arc endpoints, direction and
       weight, plus the point set. Animation flags and the stored view are left
       out on purpose, so panning does not count as a data change. */
    function cyberMapSignature(scope, role, option) {
      const series = Array.isArray(option.series) ? option.series : [];
      const parts = series.map((entry) => {
        const data = Array.isArray(entry.data) ? entry.data : [];
        return `${entry.name || ''}:${data.map((item) => {
          const coords = Array.isArray(item.coords)
            ? item.coords.map((pair) => (Array.isArray(pair) ? pair.map((value) => Number(value).toFixed(2)).join(',') : '')).join('>')
            : Array.isArray(item.value) ? item.value.slice(0, 2).map((value) => Number(value).toFixed(2)).join(',') : '';
          const weight = Array.isArray(item.value) ? item.value[2] : item.value;
          return `${item.name || ''}@${coords}#${Number(weight) || 0}`;
        }).join('|')}`;
      });
      return `${scope}|${role}|${parts.join(';')}`;
    }

    function cyberMapOption(mapName, scope, role, mapView, options = {}) {
      const routes = cyberMapRoutes(role);
      const points = cyberMapPoints(routes);
      const maxPoint = Math.max(1, ...points.map((point) => point.metric));
      const maxRoute = Math.max(1, ...routes.map((route) => route.metric));
      const view = { ...cyberMapView(scope, role), ...(mapView || {}) };
      const localPoints = points.filter((point) => point.local);
      const remotePoints = points.filter((point) => !point.local);
      const routeData = routes.map((route, index) => cyberRouteSeriesItem(route, index, maxRoute));
      /* The 620ms entrance is for first paint and scope switches. On a realtime
         update it must not replay, or a redraw arriving before the previous
         animation ends leaves both on screen at once. */
      const animateEntrance = options.animateEntrance !== false;
      return {
        backgroundColor: 'transparent',
        animation: animateEntrance,
        animationDuration: animateEntrance ? 620 : 0,
        animationDurationUpdate: 0,
        animationEasingUpdate: 'cubicOut',
        tooltip: {
          trigger: 'item',
          confine: true,
          appendToBody: true,
          className: 'insights-cyber-map-tooltip',
          backgroundColor: 'rgba(8, 16, 30, 0.92)',
          borderColor: 'rgba(104, 220, 255, 0.32)',
          borderWidth: 1,
          padding: [9, 11],
          textStyle: { color: 'rgba(239, 247, 255, 0.94)', fontSize: 12 },
          formatter: (params) => cyberMapTooltip(params)
        },
        geo: {
          map: mapName,
          roam: role !== 'overview',
          silent: false,
          center: view.center,
          zoom: Number(view.zoom),
          layoutCenter: view.layoutCenter,
          layoutSize: view.layoutSize,
          scaleLimit: { min: 0.72, max: scope === 'china' ? 8 : 5 },
          itemStyle: {
            areaColor: 'rgba(17, 31, 52, 0.72)',
            borderColor: 'rgba(105, 225, 255, 0.28)',
            borderWidth: 0.68,
            shadowBlur: 14,
            shadowColor: 'rgba(0, 210, 255, 0.08)'
          },
          emphasis: {
            label: { show: false },
            itemStyle: {
              areaColor: 'rgba(27, 61, 92, 0.82)',
              borderColor: 'rgba(154, 239, 255, 0.48)',
              borderWidth: 0.9
            }
          },
          select: { disabled: true },
          label: { show: false }
        },
        series: [
          {
            id: 'dwrt-route-glow',
            name: 'route glow',
            type: 'lines',
            coordinateSystem: 'geo',
            zlevel: 2,
            silent: true,
            large: true,
            blendMode: 'lighter',
            lineStyle: { opacity: 0.15, width: 5.5, color: 'rgba(55, 211, 255, 0.50)' },
            data: routeData.map((item) => ({ ...item, lineStyle: { ...item.lineStyle, opacity: 0.13, width: item.lineStyle.width + 4.2 } }))
          },
          {
            id: 'dwrt-traffic-routes',
            name: 'traffic routes',
            type: 'lines',
            coordinateSystem: 'geo',
            zlevel: 3,
            silent: false,
            blendMode: 'lighter',
            effect: { show: false },
            lineStyle: { opacity: 0.46, width: 1.6, type: 'solid' },
            data: routeData
          },
          {
            id: 'dwrt-traffic-pulse',
            name: 'traffic pulse',
            type: 'lines',
            coordinateSystem: 'geo',
            zlevel: 4,
            silent: false,
            effect: {
              show: true,
              constantSpeed: role === 'overview' ? 42 : 58,
              /*
               * trailLength 必须是 0。任何 > 0 的值都会让 ZRender 把这一层切成
               * motionBlur 层（`lastFrameAlpha: 0.7`）——每帧保留上一帧的 70% 而不是清屏。
               * 再叠上 blendMode: 'lighter'（加色），保留的残影只会越叠越亮、永不衰减，
               * 于是一条弧上移动的光点把自己拖成一排等间距、形状完全相同的副本。
               * 这就是用户反复打回的「一条线被平移复制多次」的真因，
               * 与路由聚合、坐标去重、后端是否聚合都无关。
               *
               * 同理这一层不能用 blendMode: 'lighter'：加色混合在残影层上会累积到饱和。
               */
              trailLength: 0,
              symbol: 'circle',
              symbolSize: 5.2,
              color: '#effbff'
            },
            lineStyle: { opacity: 0.26, width: 1.1, color: 'rgba(90,220,255,0.52)' },
            data: routeData.map((item, index) => ({
              ...item,
              effect: {
                show: true,
                period: Math.max(2.2, 4.8 - Math.min(2.1, item.dataInfo.metric / maxRoute * 2.1)),
                delay: (index % 5) * 0.22,
                trailLength: 0,
                /* 方向靠符号说，不靠颜色说：出站是沿弧飞行的箭头，入站是实心圆点。
                   `rotate: auto` 由 lines series 的 effect 自行处理箭头朝向，
                   所以箭头始终指向流向的下游。 */
                symbol: item.dataInfo.direction === 'inbound' ? 'circle' : 'arrow',
                symbolSize: item.dataInfo.direction === 'inbound' ? 5.0 : [5.4, 7.2],
                color: item.dataInfo.packetColor
              }
            }))
          },
          {
            id: 'dwrt-destinations',
            name: 'destinations',
            type: 'effectScatter',
            coordinateSystem: 'geo',
            zlevel: 5,
            blendMode: 'lighter',
            showEffectOn: 'render',
            rippleEffect: { brushType: 'stroke', scale: 3.3, period: 3.1 },
            symbolSize: (value) => cyberPointSize(Number(value && value[2]), maxPoint, false),
            itemStyle: { color: '#39d9ff', shadowBlur: 16, shadowColor: 'rgba(57, 217, 255, 0.70)' },
            emphasis: { scale: 1.12 },
            data: remotePoints.map((point) => cyberPointSeriesItem(point, maxPoint))
          },
          {
            id: 'dwrt-local-origin',
            name: 'local origin',
            type: 'effectScatter',
            coordinateSystem: 'geo',
            zlevel: 6,
            blendMode: 'lighter',
            rippleEffect: { brushType: 'stroke', scale: 4.7, period: 2.4 },
            symbolSize: (value) => cyberPointSize(Number(value && value[2]), maxPoint, true),
            itemStyle: { color: '#27f0a8', shadowBlur: 22, shadowColor: 'rgba(39, 240, 168, 0.82)' },
            label: {
              show: role !== 'overview',
              formatter: (params) => params && params.data && params.data.dataInfo ? params.data.dataInfo.shortLabel : '本机',
              position: 'bottom',
              distance: 9,
              color: 'rgba(238, 249, 255, 0.92)',
              fontSize: 11,
              fontWeight: 700,
              backgroundColor: 'rgba(7, 16, 29, 0.42)',
              borderColor: 'rgba(255,255,255,0.13)',
              borderWidth: 1,
              borderRadius: 9,
              padding: [3, 7]
            },
            data: localPoints.map((point) => cyberPointSeriesItem(point, maxPoint))
          }
        ]
      };
    }

    function cyberMapPoints(routes) {
      const points = new Map();
      routes.forEach((route) => {
        addCyberRouteEndpoint(points, route, 'from');
        addCyberRouteEndpoint(points, route, 'to');
      });
      return Array.from(points.values())
        .sort((a, b) => Number(b.local) - Number(a.local) || b.metric - a.metric);
    }

    function addCyberRouteEndpoint(points, route, side) {
      const coords = side === 'from' ? route.from : route.to;
      const point = route.route && route.route[side] || {};
      if (!Array.isArray(coords) || coords.length < 2) return;
      const key = `${Number(coords[0]).toFixed(5)},${Number(coords[1]).toFixed(5)}`;
      const local = Boolean(point.is_local || point.local || point.role === 'local');
      const metric = Math.max(1, Number(route.metric) || 1);
      /*
       * 端点对象上没有 risk —— 实测 `flows/geo` 的 `routes[].from/to` 只有地理字段，
       * 风险挂在 route 自身（30/30 条带 `risk_level`）和 `regions[]` 上。所以点位的
       * 风险从落到它身上的弧继承，多条弧汇到同一点时取最坏档（mergeRiskBuckets）。
       * 不这样做的话点位会全部画成"未评级"，即使弧已经标红。
       */
      const routeRisk = mapRiskBucket(route.route);
      const current = points.get(key);
      if (current) {
        current.metric += metric;
        current.routeCount += 1;
        current.riskBucket = mergeRiskBuckets(current.riskBucket, routeRisk);
        if (local) {
          current.local = true;
          current.point = point;
          current.label = mapPointTitle(point);
          current.shortLabel = firstText(point.public_ip, point.ip, point.address, '本机');
        }
        return;
      }
      const label = mapPointTitle(point);
      points.set(key, {
        point,
        coords: [Number(coords[0]), Number(coords[1])],
        metric,
        routeCount: 1,
        label,
        local,
        riskBucket: routeRisk,
        shortLabel: local ? firstText(point.public_ip, point.ip, point.address, '本机') : label
      });
    }

    function cyberMapRoutes(role) {
      const limit = role === 'overview' ? 8 : CYBER_ROUTE_LIMIT;
      const normalized = mapRouteItems()
        .map((route) => {
          // mapRouteItems() 已按国家 / 省份聚合过，落点取该行政区划的标准坐标，
          // 城市级抖动不再影响弧的端点，否则合并后的弧会指向"先到的那座城市"
          const merged = Number(route.mergedCount || 1) > 1;
          const from = (merged ? aggregatedEndpoint(route.from) : null) || mapCoordinates(route.from);
          const to = (merged ? aggregatedEndpoint(route.to) : null) || mapCoordinates(route.to);
          if (!from || !to || coordinatesEqual(from, to)) return null;
          /* 权重用流数而非 bytes：实测 25/30 条 geo 路由的 bytes 为 0（采样所致），
             按 bytes 归一化会让绝大多数弧一起压到最细，粗细失去表达力。 */
          const metric = routeWeight(route);
          const direction = String(route.direction || '').toLowerCase() === 'inbound' ? 'inbound' : 'outbound';
          return {
            route,
            from,
            to,
            metric,
            direction,
            /* 未合并的单条弧同样要以远端命名，否则 inbound 会全部叫"本机 <公网 IP>"。 */
            label: firstText(route.label, mapPointTitle(remoteEndpointOf(route)), mapPointTitle(route.to), mapPointTitle(route.from), '流量路径')
          };
        })
        .filter(Boolean);
      const grouped = new Map();
      normalized.forEach((route) => {
        const key = `${route.direction}|${route.from.map((value) => Number(value).toFixed(2)).join(',')}|${route.to.map((value) => Number(value).toFixed(2)).join(',')}`;
        const existing = grouped.get(key);
        if (!existing) {
          grouped.set(key, { ...route, route: { ...route.route }, coincident: [route] });
          return;
        }
        /*
         * 后端已聚合时，落到同一坐标的两条路由是**不同的目的地**（GeoIP 把不同 IP
         * 解析到同一个省级中心点），不能再合并计数 —— 那会把「访问了 5 个不同服务」
         * 报成 1 个。这里只登记为同坐标同伴，由 curveness 错开，计数保持各自独立。
         */
        if (routeAggregationSupported(state.geo)) {
          existing.coincident.push(route);
          return;
        }
        // 未聚合时才按最终坐标再收一次（国家级估算与城市级并存的情况）
        existing.metric += route.metric;
        existing.route.bytes = firstNumber(existing.route.bytes) + firstNumber(route.route.bytes);
        existing.route.total_bytes = firstNumber(existing.route.total_bytes) + firstNumber(route.route.total_bytes);
        existing.route.count = firstNumber(existing.route.count, existing.route.flow_count, 1) + firstNumber(route.route.count, route.route.flow_count, 1);
        existing.route.flow_count = existing.route.count;
        /* 这一层也会合并成一条弧，风险同样取最坏档，不让高风险被普通流量洗白。 */
        existing.route.risk_level = mergeRiskBuckets(mapRiskBucket(existing.route), mapRiskBucket(route.route));
        existing.route.risk = existing.route.risk_level;
        existing.coincident.push(route);
      });
      /* 同坐标的多条弧展开成独立弧线，各自带 fanIndex/fanTotal 供曲率错开。
         排序按权重，但同坐标组内保持相邻，避免 slice 把一组截成半组。 */
      const out = [];
      Array.from(grouped.values())
        .sort((a, b) => b.metric - a.metric)
        .forEach((entry) => {
          const fan = Array.isArray(entry.coincident) && entry.coincident.length > 1
            ? entry.coincident.slice().sort((a, b) => b.metric - a.metric)
            : [entry];
          const total = fan.length;
          fan.forEach((item, index) => {
            out.push({
              ...item,
              from: entry.from,
              to: entry.to,
              route: total > 1 ? item.route : entry.route,
              metric: total > 1 ? item.metric : entry.metric,
              fanIndex: index,
              fanTotal: total,
              fanPeers: total > 1 ? fan.map((peer) => routeDestinationLabel(peer.route)).filter(Boolean) : []
            });
          });
        });
      return out.slice(0, limit);
    }

    function aggregatedEndpoint(point) {
      if (!point || typeof point !== 'object') return null;
      /* 本机端点绝不吸附到行政区划中心。本机与国内目的地同属 CN，一起吸到中国中心点
         会让弧的两端重合、被 coordinatesEqual() 整条丢掉，国内流量就从图上消失了。
         本机始终用它自己的坐标。 */
      if (point.is_local || point.local || point.role === 'local') return null;
      if (state.mapScope === 'china') {
        const province = provinceCodeOf(point);
        if (province && CHINA_PROVINCE_COORDINATES[province]) return CHINA_PROVINCE_COORDINATES[province];
      }
      const code = countryCodeOf(point);
      if (code && COUNTRY_COORDINATES[code]) return COUNTRY_COORDINATES[code];
      return null;
    }

    function cyberPointSeriesItem(point, maxPoint) {
      const value = [point.coords[0], point.coords[1], point.metric];
      /*
       * 点位颜色也归风险。以前用 cyberMetricColor() 按流量占比分档，于是「流量大」
       * 被画成琥珀/红，和摘要的「可疑 / 令人担忧」同色不同义。流量大小改由点径
       * （cyberPointSize）单独表达，颜色只说风险。
       */
      /* 点位风险优先用弧继承来的档（端点对象自身没有 risk 字段），
         没有弧的点位（regions 直接出图）再退回读它自己的 risk。 */
      const riskBucket = point.local
        ? 'local'
        : (MAP_RISK_COLORS[point.riskBucket] ? point.riskBucket : mapRiskBucket(point.point));
      const palette = mapRiskPalette(riskBucket);
      const color = point.local ? MAP_LOCAL_COLOR : palette.line;
      return {
        name: point.label,
        value,
        symbolSize: cyberPointSize(point.metric, maxPoint, point.local),
        itemStyle: {
          color,
          shadowBlur: point.local ? 24 : 16,
          shadowColor: point.local ? 'rgba(39,240,168,0.86)' : hexToRgba(color, 0.66),
          borderColor: 'rgba(238, 252, 255, 0.82)',
          borderWidth: 0.8
        },
        dataInfo: {
          type: 'point',
          local: point.local,
          label: point.label,
          shortLabel: point.shortLabel,
          metric: point.metric,
          bytes: firstNumber(point.point.bytes, point.point.total_bytes, point.point.traffic_bytes),
          count: firstNumber(point.point.count, point.point.flow_count, point.point.total, point.point.value),
          ip: firstText(point.point.public_ip, point.point.public_ipv4, point.point.ip, point.point.address),
          approximate: isApproximateMapPoint(point.point),
          riskBucket: point.local ? '' : riskBucket,
          riskLabel: point.local ? '' : palette.label,
          riskReason: point.local ? '' : firstText(point.point.risk_reason),
          riskUnknownCount: point.local ? 0 : firstNumber(point.point.risk_unknown)
        }
      };
    }

    function cyberRouteSeriesItem(route, index, maxRoute) {
      const inbound = route.direction === 'inbound';
      /*
       * 颜色 = 风险，形状 = 方向。旧写法用琥珀表示入站，与摘要「可疑」的琥珀
       * 撞车（用户 2026-08-09 直接读错了图），所以方向改由弯向 + 光点符号 +
       * 虚实表达，颜色腾出来给风险。
       */
      const riskBucket = mapRiskBucket(route.route);
      const palette = mapRiskPalette(riskBucket);
      const color = palette.line;
      const packetColor = palette.packet;
      const ratio = Math.max(0.08, Math.min(1, route.metric / maxRoute));
      /*
       * 同坐标的多条弧靠曲率错开，而不是合并掉。基础曲率 ±0.31 保持不变（单条弧
       * 的观感不受影响）。同组内的弧在 base 两侧的一段窄带内均匀分布：
       * 交替加减会在组内条数多时把偏移量累加到越过 0，使 outbound 的弧朝反方向
       * 弯（实测 10 条一组时出现 -0.115），看起来像入站。这里改为固定带宽内插值，
       * 保证同组每条弧的曲率互不相同、且符号与方向一致。
       */
      const fanTotal = Math.max(1, Number(route.fanTotal) || 1);
      const fanIndex = Math.min(Math.max(0, Number(route.fanIndex) || 0), fanTotal - 1);
      const base = inbound ? -0.31 : 0.31;
      /* 带宽 0.34：base 0.31 时曲率落在 0.14 ~ 0.48，始终同号，不会翻向。 */
      const band = 0.34;
      const offset = fanTotal > 1 ? (fanIndex / (fanTotal - 1) - 0.5) * band : 0;
      const curveness = base + (inbound ? -offset : offset);
      return {
        name: route.label,
        coords: [route.from, route.to],
        value: route.metric,
        lineStyle: {
          color,
          opacity: 0.38 + ratio * 0.30,
          width: 1.0 + ratio * 2.2,
          curveness,
          /* 入站画虚线：颜色已被风险占用，方向靠线型 + 弯向 + 箭头三重冗余表达，
             这样即使同一档风险的进出两条弧并排，也分得清谁进谁出。 */
          type: inbound ? 'dashed' : 'solid'
        },
        dataInfo: {
          type: 'route',
          label: route.label,
          metric: route.metric,
          bytes: firstNumber(route.route.bytes, route.route.total_bytes),
          count: firstNumber(route.route.count, route.route.flow_count),
          /* 聚合自述：tooltip 要能说清这条弧代表多少条连接、源端口为何不显示。 */
          aggregated: route.route.aggregated === true || firstPositive(route.route.aggregate_count) > 1,
          aggregateCount: firstPositive(route.route.aggregate_count, route.route.mergedCount),
          sourcePort: route.route.source_port,
          sourcePortSupported: route.route.source_port_supported,
          sourcePortReason: route.route.source_port_reason,
          service: route.route.service,
          protocol: route.route.protocol,
          dstPort: firstPositive(route.route.dst_port),
          /* 同坐标不同目的地的展开清单 */
          fanTotal: Math.max(1, Number(route.fanTotal) || 1),
          fanPeers: Array.isArray(route.fanPeers) ? route.fanPeers : [],
          direction: route.direction,
          packetColor,
          riskBucket,
          riskLabel: palette.label,
          riskSupported: route.route.risk_supported,
          riskSource: route.route.risk_source,
          index
        }
      };
    }

    function cyberPointSize(value, maxPoint, local) {
      /*
       * 用户 2026-08-04：「流量地图里的点小一点，太大了目前」。
       * 本机点 11-20px → 7-12px，远端点 6-18px → 4-10px；仍按 sqrt 归一化，
       * 保留大小差异，只是整体收一档，密集区域不再糊成一片。
       */
      const ratio = Math.sqrt(Math.max(1, Number(value) || 1) / Math.max(1, Number(maxPoint) || 1));
      return Math.max(local ? 7 : 4, Math.min(local ? 12 : 10, (local ? 7 : 4) + ratio * (local ? 5 : 6)));
    }

    /*
     * 流量占比的色阶。旧实现用 `#ff6f83` / `#ffb45f` 分档，把「流量大」画成了
     * 「令人担忧 / 可疑」的颜色（用户 2026-08-09 因此读错整张图）。流量不是风险，
     * 所以这一档只在同一色相里走深浅：浅青 → 亮蓝，越亮代表占比越高。
     * 点位当前按风险上色，此函数保留给需要"按量深浅"的图元使用。
     */
    function cyberMetricColor(value, maxValue) {
      const ratio = Math.max(0, Math.min(1, Number(value || 0) / Math.max(1, Number(maxValue) || 1)));
      if (ratio > 0.78) return '#8ef0ff';
      if (ratio > 0.54) return '#5ce2ff';
      if (ratio > 0.30) return '#39d9ff';
      return '#2bb8e8';
    }

    function cyberMapTooltip(params) {
      const info = params && params.data && params.data.dataInfo;
      if (!info) return '';
      if (info.type === 'route') {
        return cyberRouteTooltip(info);
      }
      const metric = info.bytes ? formatBytes(info.bytes) : `${formatInteger(info.count || info.metric)} 条`;
      return `<div class="insights-cyber-tip"><strong>${html(info.local ? '本机出口' : info.label)}</strong>${info.ip ? `<span>${html(info.ip)}</span>` : ''}<b>${html(metric)}</b>${info.approximate ? '<em>国家/省级坐标，等待 City GeoIP</em>' : ''}</div>`;
    }

    /*
     * 弧的 tooltip。三件事必须如实说：
     * 1. 流数与字节分开报。geo 的 bytes 是采样值且常为 0，把 0 说成"0 B 流量"会
     *    让用户以为没有流量，实际是没采到样本，所以 bytes 为 0 时不报字节。
     * 2. 聚合条目的源端口是 null，写"源端口 0"等于造出一条不存在的连接。
     *    未聚合条目上后端不下发 source_port_supported，故按缺键=支持处理。
     * 3. 同坐标的多个目的地在这里展开 —— 它们没有被合并，用户需要看到是哪几个。
     */
    function cyberRouteTooltip(info) {
      const title = info.direction === 'inbound' ? '入站路径' : '出站路径';
      const rows = [];
      const flows = firstPositive(info.count, info.metric);
      if (flows) rows.push(`${formatInteger(flows)} 条连接`);
      if (firstPositive(info.bytes)) rows.push(formatBytes(info.bytes));
      const service = firstText(info.service, '');
      const dstPort = firstPositive(info.dstPort);
      const serviceLine = [service, dstPort ? `:${dstPort}` : ''].filter(Boolean).join('');
      /*
       * 源端口有三种「没有值」的情形，都不能显示成 0：
       * - 聚合条目：后端给 null（多条连接的源端口本就不同，挑一个是假信息）
       * - ICMP / ICMPv6：协议本身没有端口概念，实测 30.1 的 30 条路由里有 14 条
       *   `source_port: 0` 全是 icmp/icmpv6。写「源端口：0」等于凭空造出一个端口。
       * - 缺键：未聚合条目上后端不下发 source_port_supported，按「支持」处理，
       *   所以判断不能写成 `=== false`。
       */
      const portless = /^icmp/i.test(String(info.protocol || ''));
      const portMissing = info.sourcePortSupported === false
        || info.sourcePort === null
        || info.sourcePort === undefined
        || Number(info.sourcePort) === 0;
      let portLine = '';
      /* 端口号不是数量，不能过千分位：formatInteger(4018) 输出 "4,018"，
         读起来像一个不存在的端口。实测浏览器里就是这样显示的，故直接取整。 */
      if (!portMissing) portLine = `源端口：${Math.trunc(Number(info.sourcePort))}`;
      else if (info.aggregated) portLine = '源端口：多条连接各不相同';
      else if (portless) portLine = `${String(info.protocol).toUpperCase()}：无端口`;
      const aggregateLine = info.aggregated && firstPositive(info.aggregateCount) > 1
        ? `已按目的地聚合 ${formatInteger(info.aggregateCount)} 条`
        : '';
      const peers = Array.isArray(info.fanPeers) ? info.fanPeers.filter(Boolean) : [];
      /* 同一坐标下的多个真实目的地。GeoIP 把不同 IP 落到同一个省级中心点，
         这些弧不合并，此处列出前几个，让用户知道这个点位后面不止一个目的地。

         必须去重：同一「目的地 IP + 服务」会因源端口不同在 routes[] 里出现多条，
         照原样列出会显示成「同坐标 2 个目的地：X、X」——实测浏览器里就是这样，
         看着像重复的脏数据，而它其实是两条不同连接打到同一个目的地。 */
      const uniquePeers = Array.from(new Set(peers));
      const coincidentLine = uniquePeers.length > 1
        ? `同坐标 ${uniquePeers.length} 个目的地：${uniquePeers.slice(0, 4).join('、')}${uniquePeers.length > 4 ? ` 等 ${uniquePeers.length} 个` : ''}`
        : '';
      return `<div class="insights-cyber-tip"><strong>${html(title)}</strong>`
        + `<span>${html(info.label)}</span>`
        + (serviceLine ? `<span>${html(serviceLine)}</span>` : '')
        + (rows.length ? `<b>${html(rows.join(' · '))}</b>` : '')
        + (aggregateLine ? `<em>${html(aggregateLine)}</em>` : '')
        + (portLine ? `<em>${html(portLine)}</em>` : '')
        + (coincidentLine ? `<em>${html(coincidentLine)}</em>` : '')
        + '</div>';
    }

    function disposeCyberMap(container) {
      if (!container) return;
      rememberCyberMapView(container);
      if (container.__dwrtCyberResizeObserver) {
        try { container.__dwrtCyberResizeObserver.disconnect(); } catch (_) {}
        container.__dwrtCyberResizeObserver = null;
      }
      if (container.__dwrtCyberMap) {
        try { container.__dwrtCyberMap.dispose(); } catch (_) {}
        container.__dwrtCyberMap = null;
      }
      delete container.__dwrtCyberKey;
      delete container.__dwrtCyberZoom;
    }

    function downloadCsv() {
      const columns = DEFAULT_COLUMNS.filter(([id]) => state.columns.has(id));
      const rows = [
        columns.map(([, label]) => label),
        ...state.flows.map((item) => columns.map(([id]) => String(flowCell(item, id)).replace(/<[^>]+>/g, '')))
      ];
      emitCsv(rows, `dreamingwrt-insights-${state.period}.csv`);
    }

    function emitCsv(rows, filename) {
      const csv = rows.map((row) => row.map((cell) => `"${String(cell ?? '').replace(/"/g, '""')}"`).join(',')).join('\n');
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = filename;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    }

    function downloadAuditCsv() {
      const table = state.root && state.root.querySelector('.insights-audit-table');
      if (!table) return;
      const rows = Array.from(table.querySelectorAll('tr')).map((tr) => Array.from(tr.children).map((cell) => cell.innerText.replace(/\s+/g, ' ').trim()));
      emitCsv(rows, `dreamingwrt-audit-${state.activitySection}-${state.period}.csv`);
    }

    function mount(params = {}) {
      state.mode = params.mode === 'activity' ? 'activity' : 'flows';
      state.activitySection = state.mode === 'activity' ? (params.section || 'overview') : 'overview';
      if (state.mode === 'activity' && !ACTIVITY_PERIODS[state.period]) state.period = 'day';
      if (state.mode === 'flows' && !PERIODS[state.period]) state.period = 'day';
      state.refreshSeq += 1;
      state.loading = false;
      state.root = routePreview;
      render();
      state.mounted = true;
      subscribeInsightsRealtime();
      startAuditPolling();
      refresh();
      return { unmount };
    }

    function unmount() {
      window.clearTimeout(state.refreshTimer);
      stopAuditPolling();
      window.clearTimeout(state.realtimeFrameTimer);
      state.refreshTimer = 0;
      state.realtimeFrameTimer = 0;
      state.refreshSeq += 1;
      state.loading = false;
      state.pendingRealtime.clear();
      unsubscribeInsightsRealtime();
      state.mounted = false;
      if (state.root) {
        state.root.querySelectorAll('[data-insights-echarts-map]').forEach((container) => disposeCyberMap(container));
        state.root.querySelectorAll('[data-insights-activity-chart]').forEach((container) => disposeActivityChart(container));
        state.root.classList.remove('route-insights-host');
        state.root = null;
      }
    }

    return { mount, unmount };
  }

  function mapPointMarkup(point) {
    const pos = mapPosition(point);
    if (!pos) return '';
    const { x, y } = pos;
    const count = Number(point.count || point.flow_count || point.bytes || 1);
    const size = Math.max(9, Math.min(24, 9 + Math.log10(Math.max(1, count)) * 5));
    const local = point.is_local || point.local || point.role === 'local';
    /* 兜底层与主图同源：点位颜色说风险，大小说流量。本机是拓扑身份，不参与风险分档。 */
    const riskBucket = local ? '' : mapRiskBucket(point);
    const classes = [
      'insights-map-point',
      local ? 'is-local' : '',
      riskBucket ? `risk-${riskBucket}` : '',
      isApproximateMapPoint(point) ? 'is-approximate' : ''
    ].filter(Boolean).join(' ');
    const title = mapPointTitle(point);
    const localLabel = local
      ? `<span class="insights-map-point-label">${escapeAttr(point.public_ip || point.ip || point.address || '本机')}</span>`
      : '';
    const pointColor = local ? MAP_LOCAL_COLOR : mapRiskPalette(riskBucket).line;
    return `<span class="${classes}" style="--point-x:${x}%;--point-y:${y}%;--point-size:${size}px;--point-color:${pointColor}" title="${escapeAttr(title)}"><i class="insights-map-point-halo"></i><i class="insights-map-point-core"></i>${localLabel}</span>`;
  }

  function mapRouteLayerMarkup(routes) {
    return `<svg class="insights-map-route-layer" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">${mapRouteLayerInnerMarkup(routes)}</svg>`;
  }

  /*
   * 弧的聚合粒度（SVG 兜底层与 ECharts 矢量层共用）。
   *
   * 后端在 GeoIP City 库命中时给出**城市级** `lat` / `lon`（`geo_precision: "city"`，
   * 见 `webd_insights_add_geo_city_json()`），同一国家的多座城市各自成为一条路由。
   * 这些路由共用同一个起点、弯曲度又是固定的 ±0.31，在世界地图缩放下终点彼此只差
   * 几像素——实测大阪与名古屋 6px、东京与名古屋 11px。于是五条同形状的弧叠成一把
   * 扇子，表现为「同一条抛物线在上方平移出很多条」。
   *
   * 这里按地图真正能分辨的粒度合并：世界视图同一国家一条弧，中国视图同一省份一条。
   * 城市级细节留给列表与 tooltip，地图不承担它分辨不了的精度。
   *
   * 国家码缺失时只能退回坐标分桶，桶宽见 COORD_BUCKET_*。之所以不能只靠分桶：
   * 桶边界两侧的两座城市仍可能落在相邻桶里、屏幕上却几乎重合，所以合并之后还要
   * 再按屏幕角距做一次去重（mergeAdjacentRoutes）。
   */
  /* 坐标退路的分桶角度。世界视图整张图约 360 度宽，12 度差不多是能看清的最小间隔；
     中国视图跨度小得多，用 4 度。 */
  const COORD_BUCKET_WORLD = 12;
  const COORD_BUCKET_CHINA = 4;
  /* 合并后仍然过近的弧按角距再收一次。世界视图 10 度、中国视图 3.5 度以内视为同一条。 */
  const ARC_MIN_SEPARATION_WORLD = 10;
  const ARC_MIN_SEPARATION_CHINA = 3.5;

  function aggregateMapRoutes(routes, scope, options) {
    if (!Array.isArray(routes) || !routes.length) return Array.isArray(routes) ? routes : [];
    /*
     * 后端已按语义键（`route_aggregation_key`）聚合过时，前端那套「同键合并」
     * 必须让位：两套合并叠在一起会二次合并 —— 后端按语义合过的条目再被按屏幕
     * 像素距离合一次，用户看到的弧线条数与 `aggregate_count` 对不上，且合并依据
     * 是像素而非语义。此时只标注同坐标关系，交给渲染层错开曲率。
     */
    if (options && options.backendAggregated) {
      return annotateCoincidentRoutes(routes.slice(), scope);
    }
    if (routes.length < 2) return annotateCoincidentRoutes(routes.slice(), scope);
    const grouped = new Map();
    routes.forEach((route) => {
      const key = `${String(route.direction || '').toLowerCase()}|${routeScopeKey(route.from, scope)}|${routeScopeKey(route.to, scope)}`;
      const existing = grouped.get(key);
      if (!existing) {
        grouped.set(key, { ...route, mergedCount: 1 });
        return;
      }
      existing.mergedCount += 1;
      existing.count = numberOr(existing.count) + numberOr(route.count);
      existing.bytes = numberOr(existing.bytes) + numberOr(route.bytes);
      /* 合并后的弧只有一个颜色，风险取最坏档（见 mergeRiskBuckets 注释）。 */
      existing.risk_level = mergeRiskBuckets(mapRiskBucket(existing), mapRiskBucket(route));
      existing.risk = existing.risk_level;
      existing.label = aggregatedRouteLabel(remoteEndpointOf(existing), existing.label, existing.mergedCount, scope);
    });
    return annotateCoincidentRoutes(mergeAdjacentRoutes(Array.from(grouped.values()), scope), scope);
  }

  /* 弧的名字要说远端是谁。inbound 的远端在 `from`（`to` 是本机 WAN），
     照搬 `to` 会把境外来源全部标成"本机 <公网 IP>"——实测 30.1 的 9 条 inbound
     就是这样被标成本机的。 */
  function remoteEndpointOf(route) {
    if (!route || typeof route !== 'object') return null;
    const from = route.from;
    const to = route.to;
    const isLocal = (point) => Boolean(point && typeof point === 'object'
      && (point.is_local || point.local || point.role === 'local'));
    if (isLocal(to) && !isLocal(from)) return from;
    return to;
  }

  /* 分桶只看绝对坐标，桶边界两侧的两点仍可能在屏幕上重合，而重合的弧因为曲率相同
     会呈现为"同一条线被平移复制"。这里按同向、同起点、终点角距过近再合并一次，
     所以无论后端给不给国家码，都不会画出两条肉眼分不开的弧。 */
  function mergeAdjacentRoutes(routes, scope) {
    if (!Array.isArray(routes) || routes.length < 2) return Array.isArray(routes) ? routes : [];
    const limit = scope === 'china' ? ARC_MIN_SEPARATION_CHINA : ARC_MIN_SEPARATION_WORLD;
    // 权重大的留作代表，合并进来的流量并入它，避免代表弧是条极小的流量
    const sorted = routes.slice().sort((a, b) => numberOr(b.bytes) + numberOr(b.count) - (numberOr(a.bytes) + numberOr(a.count)));
    const kept = [];
    sorted.forEach((route) => {
      const from = mapCoordinates(route.from);
      const to = mapCoordinates(route.to);
      const direction = String(route.direction || '').toLowerCase();
      const near = from && to ? kept.find((candidate) => {
        if (String(candidate.direction || '').toLowerCase() !== direction) return false;
        const candidateFrom = mapCoordinates(candidate.from);
        const candidateTo = mapCoordinates(candidate.to);
        if (!candidateFrom || !candidateTo) return false;
        return angularGap(candidateFrom, from) <= limit && angularGap(candidateTo, to) <= limit;
      }) : null;
      if (!near) {
        kept.push(route);
        return;
      }
      near.mergedCount = numberOr(near.mergedCount || 1) + numberOr(route.mergedCount || 1);
      near.count = numberOr(near.count) + numberOr(route.count);
      near.bytes = numberOr(near.bytes) + numberOr(route.bytes);
      near.risk_level = mergeRiskBuckets(mapRiskBucket(near), mapRiskBucket(route));
      near.risk = near.risk_level;
      // 同上：inbound 的远端在 from，用 to 会把境外来源标成本机所在国。
      near.label = aggregatedRouteLabel(remoteEndpointOf(near), near.label, near.mergedCount, scope);
    });
    return kept;
  }

  function angularGap(a, b) {
    if (!Array.isArray(a) || !Array.isArray(b)) return Infinity;
    // 经度跨 ±180 时取较短的一侧，否则太平洋两岸会被误判成相距 350 度
    let lonGap = Math.abs(Number(a[0]) - Number(b[0])) % 360;
    if (lonGap > 180) lonGap = 360 - lonGap;
    return Math.hypot(lonGap, Number(a[1]) - Number(b[1]));
  }

  function numberOr(value) {
    const n = Number(value);
    return Number.isFinite(n) ? n : 0;
  }

  function routeScopeKey(point, scope) {
    if (!point || typeof point !== 'object') return 'unknown';
    if (point.is_local || point.local || point.role === 'local') return 'local';
    if (scope === 'china') {
      const province = provinceCodeOf(point);
      if (province) return `cn:${province}`;
    }
    const code = countryCodeOf(point);
    if (code) return `country:${String(code).toLowerCase()}`;
    const coords = explicitCoordinates(point);
    /* 没有行政区划标识时只能退回坐标。1 度在世界视图下仍只有几个像素，24 条相邻城市
       路由会留下 9 条几乎重合、等间距的弧——正是"一条线被平移复制多次"的来源。
       这里按世界/中国视图各自能分辨的角度分桶（世界 12 度、中国 4 度），
       桶宽与下面的像素级去重互为兜底。 */
    if (!coords) return 'unknown';
    const bucket = scope === 'china' ? COORD_BUCKET_CHINA : COORD_BUCKET_WORLD;
    return coords.map((value) => Math.round(Number(value) / bucket)).join(',');
  }

  function aggregatedRouteLabel(point, fallback, mergedCount, scope) {
    if (!(mergedCount > 1) || !point || typeof point !== 'object') return fallback;
    const scoped = String(
      (scope === 'china' ? point.region_name : '')
      || point.country_name || point.country || point.country_code || ''
    ).trim();
    if (scoped) return `${scoped} · ${mergedCount} 个地点`;
    /* 没有行政区划名时（坐标退路）也不能只挂第一座城市的名字，那会把多地流量
       说成发生在一个点。退成"附近 N 个地点"，至少不误报。 */
    const base = String(fallback || '').trim();
    return base ? `${base} 附近 · ${mergedCount} 个地点` : `${mergedCount} 个地点`;
  }

  function mapRouteLayerInnerMarkup(routes) {
    if (!Array.isArray(routes) || !routes.length) return '';
    return routes.map((route, index) => mapRouteMarkup(route, index)).join('');
  }

  function mapRouteMarkup(route, index) {
    const from = mapPosition(route && route.from);
    const to = mapPosition(route && route.to);
    if (!from || !to) return '';
    if (Math.abs(from.x - to.x) < 0.1 && Math.abs(from.y - to.y) < 0.1) return '';
    const dx = to.x - from.x;
    const dy = to.y - from.y;
    const distance = Math.hypot(dx, dy);
    const bend = Math.max(7, Math.min(23, distance * 0.26));
    const inbound = route.direction === 'inbound';
    const sign = inbound ? 1 : -1;
    /* 同坐标的多条弧（GeoIP 同点位、不同目的地）在兜底层也要错开，否则会叠成一条。
       与 ECharts 层同源：按 fanIndex 交替正负偏移控制点。 */
    const fanTotal = Math.max(1, Number(route.fanTotal || route.coincidentTotal) || 1);
    const fanIndex = Math.max(0, Number(route.fanIndex ?? route.coincidentIndex) || 0);
    const fanOffset = fanTotal > 1
      ? (fanIndex % 2 === 0 ? 1 : -1) * Math.ceil(fanIndex / 2) * Math.min(6, bend * 0.34)
      : 0;
    const cx = clampPercent((from.x + to.x) / 2 + Math.sign(dx || 1) * Math.min(4, distance * 0.035));
    const cy = clampPercent((from.y + to.y) / 2 - (bend + fanOffset) * sign);
    const path = `M ${from.x.toFixed(2)} ${from.y.toFixed(2)} Q ${cx.toFixed(2)} ${cy.toFixed(2)} ${to.x.toFixed(2)} ${to.y.toFixed(2)}`;
    const delay = ((index % 7) * 0.24).toFixed(2);
    /* 与 ECharts 层同一口径：用流数，不让 bytes（25/30 条为 0）决定粗细。 */
    const metric = routeWeight(route);
    const width = Math.max(1.15, Math.min(3.2, 1.15 + Math.log10(metric) * 0.42));
    const duration = Math.max(2.4, Math.min(4.8, 4.8 - Math.log10(metric) * 0.34)).toFixed(2);
    /* 与 ECharts 主图同源：颜色说风险，方向由弯向 + 线型 + 光点符号表达。
       兜底层与主图必须用同一套色，否则同一条弧在两条渲染路径上颜色不同。 */
    const riskBucket = mapRiskBucket(route);
    const palette = mapRiskPalette(riskBucket);
    const color = palette.line;
    const accent = palette.packet;
    return `
      <path class="insights-map-route-glow ${inbound ? 'is-inbound' : 'is-outbound'} risk-${riskBucket}" d="${path}" pathLength="1" style="--route-width:${(width + 4).toFixed(2)};--route-color:${color};--route-delay:${delay}s"></path>
      <path class="insights-map-route-path ${inbound ? 'is-inbound' : 'is-outbound'} risk-${riskBucket}" d="${path}" pathLength="1" style="--route-width:${width.toFixed(2)};--route-color:${color};--route-delay:${delay}s"></path>
      <circle class="insights-map-route-packet primary ${inbound ? 'is-inbound' : 'is-outbound'}" r="1.08" style="--route-delay:${delay}s;--packet-color:${accent}">
        <animateMotion dur="${duration}s" begin="${delay}s" repeatCount="indefinite" path="${path}" rotate="auto"></animateMotion>
      </circle>
      <circle class="insights-map-route-packet secondary ${inbound ? 'is-inbound' : 'is-outbound'}" r="0.72" style="--route-delay:${delay}s;--packet-color:${color}">
        <animateMotion dur="${duration}s" begin="${(Number(delay) + Number(duration) / 2).toFixed(2)}s" repeatCount="indefinite" path="${path}" rotate="auto"></animateMotion>
      </circle>`;
  }

  function filterItemLabel(item) {
    if (item && typeof item === 'object') {
      return item.name || item.label || item.display_name || item.ip || item.mac || item.id || item.value || item.type || '';
    }
      return item;
  }

  function filterItemValue(item) {
    if (item && typeof item === 'object') {
      return String(item.id || item.value || item._id || item.internal_type || item.ips_category || item.type || item.ip || item.mac || item.name || item.label || '');
    }
    return String(item ?? '');
  }

  function dedupeFilterItems(items) {
    const seen = new Set();
    const result = [];
    items.forEach((item) => {
      const value = filterItemValue(item);
      if (!value || seen.has(value)) return;
      seen.add(value);
      result.push(item);
    });
    return result;
  }

  function hasMappablePosition(point) {
    return Boolean(mapPosition(point));
  }

  function geoPayloadMatchesScope(payload, scope) {
    if (scope !== 'china') return true;
    if (!payload || typeof payload !== 'object') return false;
    const declared = declaredGeoScope(payload);
    if (declared) return declared === 'china';
    const rows = []
      .concat(Array.isArray(payload.regions) ? payload.regions : [])
      .concat(Array.isArray(payload.items) ? payload.items : [])
      .concat(Array.isArray(payload.points) ? payload.points : [])
      .concat(routeEndpointItems(payload));
    return rows.some(hasChinaGeoDetail);
  }

  function declaredGeoScope(payload) {
    if (!payload || typeof payload !== 'object') return '';
    const raw = String(payload.scope || payload.map_scope || payload.geo_scope || payload.region_scope || '').trim().toLowerCase();
    if (raw === 'china' || raw === 'cn' || raw === 'domestic') return 'china';
    if (raw === 'world' || raw === 'global' || raw === 'international') return 'world';
    return '';
  }

  function mapCoordinates(point) {
    if (!point || typeof point !== 'object') return null;
    const coords = explicitCoordinates(point);
    if (coords) return coords;
    const province = provinceCodeOf(point);
    if (province && CHINA_PROVINCE_COORDINATES[province]) return CHINA_PROVINCE_COORDINATES[province];
    const code = countryCodeOf(point);
    if (code && COUNTRY_COORDINATES[code]) return COUNTRY_COORDINATES[code];
    const normalizedCode = code.replace(/^CN-|^CHINA\s*/, '');
    if (normalizedCode && COUNTRY_COORDINATES[normalizedCode]) return COUNTRY_COORDINATES[normalizedCode];
    return null;
  }

  function explicitCoordinates(point) {
    if (!point || typeof point !== 'object') return null;
    const location = point.location && typeof point.location === 'object' ? point.location : {};
    const geo = point.geo && typeof point.geo === 'object' ? point.geo : {};
    const geoip = point.geoip && typeof point.geoip === 'object' ? point.geoip : {};
    const city = point.city && typeof point.city === 'object' ? point.city : {};
    const coordinates = Array.isArray(point.coordinates)
      ? point.coordinates
      : Array.isArray(location.coordinates)
        ? location.coordinates
        : Array.isArray(geo.coordinates)
          ? geo.coordinates
          : Array.isArray(geoip.coordinates)
            ? geoip.coordinates
            : null;
    if (coordinates && coordinates.length >= 2) {
      const a = Number(coordinates[0]);
      const b = Number(coordinates[1]);
      if (Number.isFinite(a) && Number.isFinite(b)) {
        const lon = Math.abs(a) <= 90 && Math.abs(b) > 90 ? b : a;
        const lat = Math.abs(a) <= 90 && Math.abs(b) > 90 ? a : b;
        return [Math.max(-180, Math.min(180, lon)), Math.max(-85, Math.min(85, lat))];
      }
    }
    const lon = Number(point.lon ?? point.lng ?? point.longitude ?? point.map_lon ?? point.map_lng ?? point.geo_lon ?? point.geo_lng ?? location.lon ?? location.lng ?? location.longitude ?? geo.lon ?? geo.lng ?? geo.longitude ?? geoip.lon ?? geoip.lng ?? geoip.longitude ?? city.lon ?? city.lng ?? city.longitude);
    const lat = Number(point.lat ?? point.latitude ?? point.map_lat ?? point.geo_lat ?? location.lat ?? location.latitude ?? geo.lat ?? geo.latitude ?? geoip.lat ?? geoip.latitude ?? city.lat ?? city.latitude);
    if (Number.isFinite(lon) && Number.isFinite(lat)) return [Math.max(-180, Math.min(180, lon)), Math.max(-85, Math.min(85, lat))];
    return null;
  }

  function uniquePolicyTypes(policies) {
    if (!Array.isArray(policies)) return [];
    const seen = new Set();
    return policies
      .map((policy) => policy && policy.type)
      .filter((type) => {
        if (!type || seen.has(type)) return false;
        seen.add(type);
        return true;
      })
      .map((type) => ({ id: type, name: type }));
  }

  function mapPosition(point) {
    if (!point || typeof point !== 'object') return null;
    const explicitX = Number(point.x ?? point.map_x ?? point.percent_x);
    const explicitY = Number(point.y ?? point.map_y ?? point.percent_y);
    if (Number.isFinite(explicitX) && Number.isFinite(explicitY)) {
      return { x: clampPercent(explicitX), y: clampPercent(explicitY) };
    }
    const coords = explicitCoordinates(point);
    if (coords) {
      const [lon, lat] = coords;
      return {
        x: clampPercent(((lon + 180) / 360) * 100),
        y: clampPercent(((90 - lat) / 180) * 100)
      };
    }
    const code = countryCodeOf(point);
    const province = provinceCodeOf(point);
    if (province && CHINA_PROVINCE_POSITIONS[province]) return CHINA_PROVINCE_POSITIONS[province];
    return COUNTRY_POSITIONS[code] || COUNTRY_POSITIONS[code.replace(/^CN-|^CHINA\s*/, '')] || null;
  }

  function countryCodeOf(point) {
    if (!point || typeof point !== 'object') return '';
    const country = point.country && typeof point.country === 'object' ? point.country : {};
    const geo = point.geo && typeof point.geo === 'object' ? point.geo : {};
    const geoip = point.geoip && typeof point.geoip === 'object' ? point.geoip : {};
    const geoCountry = geo.country && typeof geo.country === 'object' ? geo.country : {};
    const geoipCountry = geoip.country && typeof geoip.country === 'object' ? geoip.country : {};
    const registeredCountry = point.registered_country && typeof point.registered_country === 'object' ? point.registered_country : {};
    const countryValue = point.country && typeof point.country === 'object'
      ? (country.iso_code || country.code || country.name || '')
      : point.country;
    return String(
      point.country_code ||
      point.countryCode ||
      point.iso_code ||
      point.iso2 ||
      country.iso_code ||
      country.code ||
      geoCountry.iso_code ||
      geoCountry.code ||
      geoipCountry.iso_code ||
      geoipCountry.code ||
      registeredCountry.iso_code ||
      registeredCountry.code ||
      countryValue ||
      point.region ||
      inferCountryCodeFromCarrier(point) ||
      ''
    ).trim().toUpperCase();
  }

  function provinceCodeOf(point) {
    if (!point || typeof point !== 'object') return '';
    const geo = point.geo && typeof point.geo === 'object' ? point.geo : {};
    const geoip = point.geoip && typeof point.geoip === 'object' ? point.geoip : {};
    const subdivision = point.subdivision && typeof point.subdivision === 'object' ? point.subdivision : {};
    const geoSubdivision = geo.subdivision && typeof geo.subdivision === 'object' ? geo.subdivision : {};
    const geoipSubdivision = geoip.subdivision && typeof geoip.subdivision === 'object' ? geoip.subdivision : {};
    const subdivisions = Array.isArray(point.subdivisions)
      ? point.subdivisions
      : Array.isArray(geo.subdivisions)
        ? geo.subdivisions
        : Array.isArray(geoip.subdivisions)
          ? geoip.subdivisions
          : [];
    const firstSubdivision = subdivisions.find((item) => item && typeof item === 'object') || {};
    const subdivisionName = localizedName(subdivision);
    const geoSubdivisionName = localizedName(geoSubdivision);
    const geoipSubdivisionName = localizedName(geoipSubdivision);
    const firstSubdivisionName = localizedName(firstSubdivision);
    const raw = String(
      point.province_code ||
      point.provinceCode ||
      point.admin1_code ||
      point.subdivision_code ||
      point.region_code ||
      subdivision.iso_code ||
      subdivision.code ||
      geoSubdivision.iso_code ||
      geoSubdivision.code ||
      geoipSubdivision.iso_code ||
      geoipSubdivision.code ||
      firstSubdivision.iso_code ||
      firstSubdivision.code ||
      point.province_name ||
      point.province ||
      point.admin1_name ||
      point.subdivision_name ||
      subdivision.name ||
      subdivisionName ||
      geoSubdivision.name ||
      geoSubdivisionName ||
      geoipSubdivision.name ||
      geoipSubdivisionName ||
      firstSubdivision.name ||
      firstSubdivisionName ||
      ''
    ).trim().toUpperCase();
    if (!raw) return '';
    if (CHINA_PROVINCE_COORDINATES[raw]) return raw;
    const normalized = raw
      .replace(/^CN[-_]/, '')
      .replace(/省|市|自治区|特别行政区|壮族|回族|维吾尔|地区|盟/g, '');
    if (CHINA_PROVINCE_COORDINATES[normalized]) return normalized;
    const alias = CHINA_PROVINCE_ALIASES[normalized] || CHINA_PROVINCE_ALIASES[raw];
    return alias || raw;
  }

  function cityNameOf(point) {
    if (!point || typeof point !== 'object') return '';
    const city = point.city && typeof point.city === 'object' ? point.city : {};
    const geo = point.geo && typeof point.geo === 'object' ? point.geo : {};
    const geoip = point.geoip && typeof point.geoip === 'object' ? point.geoip : {};
    const geoCity = geo.city && typeof geo.city === 'object' ? geo.city : {};
    const geoipCity = geoip.city && typeof geoip.city === 'object' ? geoip.city : {};
    const cityValue = point.city && typeof point.city === 'object' ? (city.name || '') : point.city;
    return String(
      point.city_name ||
      point.cityName ||
      cityValue ||
      localizedName(city) ||
      geoCity.name ||
      localizedName(geoCity) ||
      geoipCity.name ||
      localizedName(geoipCity) ||
      ''
    ).trim();
  }

  function localizedName(value) {
    if (!value || typeof value !== 'object') return '';
    const names = value.names && typeof value.names === 'object' ? value.names : {};
    return names['zh-CN'] || names.zh || names.en || names['en-US'] || '';
  }

  function hasChinaGeoDetail(point) {
    if (!point || typeof point !== 'object') return false;
    const scope = String(point.scope || point.map_scope || point.geo_scope || '').toLowerCase();
    if (scope === 'china' || scope === 'cn' || scope === 'domestic') return true;
    const province = provinceCodeOf(point);
    if (province && CHINA_PROVINCE_COORDINATES[province]) return true;
    const code = countryCodeOf(point);
    return (code === 'CN' || code === 'CHINA' || code === '中国') && Boolean(cityNameOf(point));
  }

  function isChinaScopedMapPoint(point) {
    if (!point || typeof point !== 'object') return false;
    const province = provinceCodeOf(point);
    if (province && CHINA_PROVINCE_COORDINATES[province]) return true;
    const scope = String(point.scope || point.map_scope || point.geo_scope || '').toLowerCase();
    const code = countryCodeOf(point);
    const coords = explicitCoordinates(point);
    const chinaCode = code === 'CN' || code === 'CHINA' || code === '中国' || /^CN[-_]/.test(code);
    if (code && !chinaCode) return false;
    if (coords) return coordinatesInChina(coords);
    if (chinaCode && (province || cityNameOf(point))) return true;
    if ((scope === 'china' || scope === 'cn' || scope === 'domestic') && chinaCode) return true;
    return false;
  }

  function coordinatesInChina(coords) {
    return Array.isArray(coords) && coords.length >= 2 &&
      Number(coords[0]) >= 73.5 && Number(coords[0]) <= 135.2 &&
      Number(coords[1]) >= 17.5 && Number(coords[1]) <= 53.8;
  }

  function routeEndpointItems(payload) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return [];
    const endpoints = [];
    ['routes', 'arcs', 'paths', 'links', 'connections', 'traffic_routes', 'traffic_arcs'].forEach((key) => {
      if (!Array.isArray(payload[key])) return;
      payload[key].forEach((route) => {
        if (!route || typeof route !== 'object') return;
        ['from', 'source', 'src', 'origin', 'local', 'a', 'to', 'destination', 'dst', 'target', 'remote', 'b'].forEach((endpointKey) => {
          const endpoint = route[endpointKey];
          if (endpoint && typeof endpoint === 'object' && !Array.isArray(endpoint)) endpoints.push(endpoint);
        });
      });
    });
    return endpoints;
  }

  function isApproximateMapPoint(point) {
    if (!point || typeof point !== 'object') return true;
    if (explicitCoordinates(point)) return false;
    const source = String(point.coordinate_source || point.location_source || point.geo_source || '').toLowerCase();
    if (/city|ip|mmdb_city|gps|manual|coordinate/.test(source) && !/country_code_only|country|fallback/.test(source)) return false;
    return true;
  }

  function mapPointTitle(point) {
    const label = String(point && (point.label || point.name || point.region_name || point.country_name || point.region || point.country || point.ip || point.public_ip) || '');
    if (point && (point.is_local || point.local || point.role === 'local')) {
      const ip = String(point.public_ip || point.ip || point.address || '').trim();
      return `本机${ip ? ` · ${ip}` : ''}${isApproximateMapPoint(point) ? ' · 国家级估算' : ''}`;
    }
    return `${label}${isApproximateMapPoint(point) ? ' · 国家级估算' : ''}`;
  }

  function mapPointIdentity(point) {
    if (!point || typeof point !== 'object') return '';
    const coords = explicitCoordinates(point);
    if (coords) return `coord:${coords[0].toFixed(3)},${coords[1].toFixed(3)}`;
    return String(point.id || point.country_code || point.country || point.region || point.name || point.ip || '').toLowerCase();
  }

  function extractLocalMapPoint(...payloads) {
    const candidates = [];
    payloads.forEach((payload) => collectLocalPointCandidates(payload, candidates));
    const explicit = candidates.find((item) => explicitCoordinates(item));
    if (explicit) return normalizeLocalPoint(explicit);
    const countryCandidate = candidates.find((item) => countryCodeOf(item));
    if (countryCandidate) return normalizeLocalPoint(countryCandidate);
    return null;
  }

  function collectLocalPointCandidates(payload, out) {
    if (!payload || typeof payload !== 'object') return;
    if (Array.isArray(payload)) return;
    [
      'local', 'home', 'origin', 'site', 'gateway', 'router', 'local_geo',
      'local_location', 'public_ip_geo', 'wan_geo', 'source_location'
    ].forEach((key) => {
      const value = payload[key];
      if (value && typeof value === 'object' && !Array.isArray(value)) out.push(value);
    });
    const ip = payload.public_ip || payload.public_ipv4 || payload.wan_ip || payload.local_public_ip;
    const code = payload.country_code || payload.local_country_code || payload.country || payload.region;
    if (ip || code || payload.lat || payload.lon || payload.latitude || payload.longitude) {
      out.push({
        ip,
        public_ip: ip,
        country_code: code,
        country: code,
        lat: payload.lat ?? payload.latitude,
        lon: payload.lon ?? payload.lng ?? payload.longitude,
        coordinate_source: payload.coordinate_source || payload.location_source || 'local_payload'
      });
    }
    ['wans', 'wan', 'interfaces', 'lines'].forEach((key) => {
      const list = Array.isArray(payload[key]) ? payload[key] : [];
      list.forEach((item) => {
        if (!item || typeof item !== 'object') return;
        const wanIp = item.public_ip || item.public_ipv4 || item.wan_ip || item.ip;
        const wanCode = item.country_code || item.local_country_code || item.country || item.region || inferCountryCodeFromCarrier(item);
        if (wanIp || wanCode || item.lat || item.lon || item.latitude || item.longitude) {
          out.push({
            ...item,
            ip: wanIp,
            public_ip: wanIp,
            country_code: wanCode,
            country: wanCode,
            coordinate_source: item.coordinate_source || item.location_source || 'wan_payload'
          });
        }
      });
    });
  }

  function normalizeLocalPoint(point) {
    if (!point || typeof point !== 'object') return null;
    return {
      ...point,
      id: point.id || 'local',
      role: 'local',
      is_local: true,
      local: true,
      name: point.name || point.label || '本机公网',
      label: point.label || point.name || '本机公网',
      count: point.count || 1
    };
  }

  function inferCountryCodeFromCarrier(point) {
    if (!point || typeof point !== 'object') return '';
    const text = String([
      point.carrier,
      point.carrier_key,
      point.carrier_name,
      point.isp,
      point.isp_name,
      point.operator,
      point.provider,
      point.public_ip
    ].filter(Boolean).join(' ')).toLowerCase();
    if (/china|unicom|mobile|telecom|cernet|中国|联通|移动|电信|教育网/.test(text)) return 'CN';
    return '';
  }

  function mapPositionsEqual(a, b) {
    const pa = mapPosition(a);
    const pb = mapPosition(b);
    return pa && pb && Math.abs(pa.x - pb.x) < 0.2 && Math.abs(pa.y - pb.y) < 0.2;
  }

  function buildMapRoutes(geo, summary, points, local) {
    const explicitRoutes = [];
    [geo, summary].forEach((payload) => collectRouteCandidates(payload, explicitRoutes));
    const normalized = explicitRoutes
      .map(normalizeMapRoute)
      .filter((route) => route && mapPosition(route.from) && mapPosition(route.to));
    if (normalized.length) return normalized;
    if (!local) return [];
    return points
      .filter((point) => mapPosition(point) && mapPointIdentity(point) !== mapPointIdentity(local))
      .sort((a, b) => Number(b.bytes || b.count || b.flow_count || 0) - Number(a.bytes || a.count || a.flow_count || 0))
      .slice(0, CYBER_ROUTE_LIMIT)
      .map((point) => {
        const direction = String(point.direction || '').toLowerCase();
        const inbound = /in|rx|download|remote_to_local/.test(direction);
        return {
          from: inbound ? point : local,
          to: inbound ? local : point,
          direction: inbound ? 'inbound' : 'outbound',
          count: point.count || point.flow_count || 1,
          bytes: point.bytes || 0,
          label: mapPointTitle(point)
        };
      });
  }

  function collectRouteCandidates(payload, out) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return;
    ['routes', 'arcs', 'paths', 'links', 'connections', 'traffic_routes', 'traffic_arcs'].forEach((key) => {
      if (Array.isArray(payload[key])) out.push(...payload[key]);
    });
  }

  function normalizeMapRoute(route) {
    if (!route || typeof route !== 'object') return null;
    const from = route.from || route.source || route.src || route.origin || route.local || route.a;
    const to = route.to || route.destination || route.dst || route.target || route.remote || route.b;
    if (!from || !to) return null;
    /* `count` 以前写作 `route.count || route.flow_count || route.bytes || 1`，
       bytes 会在流数缺失时冒充流数（单位不同的两个量），所以这里分开取。 */
    const aggregateCount = firstPositive(route.aggregate_count, route.aggregated_count);
    const flowCount = firstPositive(route.flow_count, route.count);
    return {
      from,
      to,
      direction: String(route.direction || route.flow_direction || '').toLowerCase(),
      count: flowCount || aggregateCount || 1,
      bytes: route.bytes || route.total_bytes || 0,
      label: route.label || route.name || '',
      /* 后端权威聚合字段。`route_key` 是判定「两条弧是否真的同一条」的唯一依据，
         比屏幕角距可靠，因此一路带到渲染层。 */
      route_key: firstFilled(route.route_key),
      aggregated: route.aggregated === true || aggregateCount > 1,
      aggregate_count: aggregateCount || 1,
      /* 聚合条目的源端口是 null（多条连接的源端口本就不同，挑一个是假信息）。
         这里保留 null/undefined 原样，绝不折成 0 —— 0 是一个合法端口号，
         显示成 0 等于凭空造出一条「从 0 端口发出」的连接。 */
      source_port: route.source_port,
      /* 未聚合条目上后端不下发这两个键（实测 30 条里只有 5 条聚合行带），
         所以缺键必须按「支持」处理，不能写 `=== false` 那种判断。 */
      source_port_supported: route.source_port_supported,
      source_port_reason: firstFilled(route.source_port_reason),
      service: firstFilled(route.service),
      protocol: firstFilled(route.protocol),
      dst_port: firstPositive(route.dst_port, route.destination_port, route.remote_port),
      /* 实测 routes[] 不含 remote_ip；保留读取只为兼容将来补上该键的情况，
         真正的远端地址来自 from/to 端点对象。 */
      remote_ip: firstFilled(route.remote_ip),
      client_ip: firstFilled(route.client_ip),
      /* 风险要一路带到渲染层，弧线按它上色。后端 30/30 条都给了这几个键，
         `risk_supported` 缺键时按支持处理（与 source_port_supported 同一口径）。 */
      risk: firstFilled(route.risk),
      risk_level: firstFilled(route.risk_level, route.risk),
      risk_matched: route.risk_matched,
      risk_source: firstFilled(route.risk_source),
      risk_supported: route.risk_supported
    };
  }

  /* `firstText()` 只存在于 create() 的参数默认值里，模块级取不到它。
     这些工具函数是模块级的，所以用本地实现，避免运行期 ReferenceError。 */
  function firstFilled(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      const text = String(value);
      if (text !== '') return text;
    }
    return '';
  }

  /* firstNumber() 返回第一个「有限」值，而 0 是有限的，所以它取不到
     「第一个有意义的正数」。弧的权重与端口号都需要后者。 */
  function firstPositive(...values) {
    for (const value of values) {
      const number = Number(value);
      if (Number.isFinite(number) && number > 0) return number;
    }
    return 0;
  }

  /* 弧的粗细权重。
   *
   * 实测 30.1 的 `flows/geo`：30 条路由里 25 条 `bytes` 为 0（geo 的字节来自
   * `nf_conntrack_polling_sample` 采样，短连接常常一个字节都没采到），只有 5 条非零。
   * 若按 bytes 定粗细，五分之四的弧会一起压到最细，地图上看不出任何差别。
   *
   * 所以权重用流数（`flow_count`，聚合后等于 `aggregate_count`）：它恒 ≥ 1、
   * 单位统一、且正是后端建议的两个表达量之一。bytes 不参与粗细，改在 tooltip 里
   * 如实报出（含 0），避免把两种单位混进同一个归一化尺度。 */
  function routeWeight(route) {
    if (!route || typeof route !== 'object') return 1;
    return Math.max(1, firstPositive(route.flow_count, route.count, route.aggregate_count, route.mergedCount));
  }

  /* 后端是否已按语义键聚合过。为真时前端不再用屏幕角距去猜聚合关系。 */
  function routeAggregationSupported(geo) {
    const caps = (geo && typeof geo === 'object' && geo.capabilities) || {};
    return caps.route_aggregation_supported === true;
  }

  /* 同一坐标对下的多条弧：不合并，给序号让渲染层错开曲率。
   *
   * GeoIP 城市库会把不同 IP 解析到同一个省级中心点，这类重合是真实的 ——
   * 按坐标合并会把「访问了 5 个不同服务」显示成「1 个」，是拿数据真实性换视觉整洁。
   * 正确做法是让它们视觉上可区分，所以这里只标注 `coincidentIndex` /
   * `coincidentTotal`，并把同点位的目的地清单挂上去供 tooltip 展开。 */
  function annotateCoincidentRoutes(routes, scope) {
    if (!Array.isArray(routes) || !routes.length) return Array.isArray(routes) ? routes : [];
    const groups = new Map();
    routes.forEach((route) => {
      const key = `${String(route.direction || '').toLowerCase()}|${routeScopeKey(route.from, scope)}|${routeScopeKey(route.to, scope)}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(route);
    });
    groups.forEach((group) => {
      const total = group.length;
      const peers = total > 1
        ? group.map((peer) => routeDestinationLabel(peer)).filter(Boolean)
        : [];
      group.forEach((route, index) => {
        route.coincidentIndex = index;
        route.coincidentTotal = total;
        route.coincidentPeers = peers;
      });
    });
    return routes;
  }

  /* 同点位展开清单里的一行：目的地 + 服务/端口，足以区分「同坐标不同目的」。 */
  function routeDestinationLabel(route) {
    if (!route || typeof route !== 'object') return '';
    const remote = remoteEndpointOf(route);
    /*
     * 远端标识取自端点对象，不要用 `route.remote_ip` —— 实测 `flows/geo` 的
     * routes[] **没有** 这个键（`'remote_ip' in row` 为 false），一律取到
     * undefined 后落到 `route.label`，于是同坐标的多个不同目的地会被显示成
     * 同一个名字（浏览器实测出现「同坐标 2 个目的地：X、X」）。
     * 真实的 IP 在 `to.ip` / `from.ip`（见 remoteEndpointOf），域名在 `.domain`。
     * 域名优先于 IP：它才是用户认得出的那一项；两者都给出时附上 IP 以便区分
     * 同域名的多个后端地址。
     */
    const ip = firstFilled(remote && (remote.ip || remote.public_ip || remote.address), route.remote_ip);
    const domain = firstFilled(remote && (remote.domain || remote.host));
    const place = firstFilled(remote && (remote.name || remote.label), route.label);
    const host = domain
      ? (ip && ip !== domain ? `${domain}（${ip}）` : domain)
      : firstFilled(ip, place);
    const service = firstFilled(route.service, route.protocol);
    const port = firstPositive(route.dst_port);
    const suffix = [service, port ? String(port) : ''].filter(Boolean).join(' ');
    if (!host) return suffix;
    return suffix ? `${host} · ${suffix}` : String(host);
  }

  function arcCoordinates(from, to, direction) {
    const [fromLon, fromLat] = from;
    const [toLon, toLat] = to;
    const steps = 36;
    const coords = [];
    const dx = toLon - fromLon;
    const dy = toLat - fromLat;
    const lift = Math.max(8, Math.min(28, Math.hypot(dx, dy) * 0.22)) * (direction === 'inbound' ? -1 : 1);
    for (let index = 0; index <= steps; index += 1) {
      const t = index / steps;
      const lon = fromLon + dx * t;
      const lat = fromLat + dy * t + Math.sin(Math.PI * t) * lift;
      coords.push([Math.max(-180, Math.min(180, lon)), Math.max(-85, Math.min(85, lat))]);
    }
    return coords;
  }

  function coordinatesEqual(a, b) {
    return Array.isArray(a) && Array.isArray(b) && Math.abs(a[0] - b[0]) < 0.01 && Math.abs(a[1] - b[1]) < 0.01;
  }

  function escapeAttr(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function clampPercent(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return 50;
    return Math.max(2, Math.min(98, number));
  }

  function captureFocusState() {
    const active = document.activeElement;
    if (!active || !active.matches || !active.matches('[data-insights-search], [data-audit-search]')) return null;
    return {
      selector: active.matches('[data-audit-search]') ? `[data-audit-search="${escapeAttr(active.dataset.auditSearch || '')}"]` : '[data-insights-search]',
      start: active.selectionStart,
      end: active.selectionEnd
    };
  }

  function restoreFocusState(focusState) {
    if (!focusState) return;
    window.requestAnimationFrame(() => {
      const input = document.querySelector(focusState.selector);
      if (!input) return;
      input.focus({ preventScroll: true });
      try {
        const end = Math.min(input.value.length, focusState.end ?? input.value.length);
        const start = Math.min(input.value.length, focusState.start ?? end);
        input.setSelectionRange(start, end);
      } catch (_) {}
    });
  }

  function captureUiScrollState() {
    const root = document.querySelector('.route-insights-host');
    if (!root) return null;
    return {
      filterTop: root.querySelector('.insights-filter-scroll')?.scrollTop || 0,
      auditTop: root.querySelector('.insights-main-audit')?.scrollTop || 0,
      auditTableLeft: Array.from(root.querySelectorAll('.insights-audit-table-scroll')).map((node) => node.scrollLeft || 0),
      auditTableTop: Array.from(root.querySelectorAll('.insights-audit-table-scroll')).map((node) => node.scrollTop || 0),
      rangeLeft: Array.from(root.querySelectorAll('.insights-range-row')).map((node) => node.scrollLeft || 0)
    };
  }

  function restoreUiScrollState(scrollState) {
    if (!scrollState) return;
    window.requestAnimationFrame(() => {
      const root = document.querySelector('.route-insights-host');
      if (!root) return;
      const filter = root.querySelector('.insights-filter-scroll');
      if (filter) filter.scrollTop = scrollState.filterTop || 0;
      const audit = root.querySelector('.insights-main-audit');
      if (audit) audit.scrollTop = scrollState.auditTop || 0;
      root.querySelectorAll('.insights-audit-table-scroll').forEach((node, index) => {
        node.scrollLeft = scrollState.auditTableLeft && scrollState.auditTableLeft[index] || 0;
        node.scrollTop = scrollState.auditTableTop && scrollState.auditTableTop[index] || 0;
      });
      root.querySelectorAll('.insights-range-row').forEach((node, index) => {
        node.scrollLeft = scrollState.rangeLeft && scrollState.rangeLeft[index] || 0;
      });
    });
  }

  const COUNTRY_POSITIONS = {
    CN: { x: 78.5, y: 44.5 },
    中国: { x: 78.5, y: 44.5 },
    CHINA: { x: 78.5, y: 44.5 },
    US: { x: 22.5, y: 42.5 },
    USA: { x: 22.5, y: 42.5 },
    JP: { x: 86.5, y: 43.5 },
    KR: { x: 83.5, y: 43.5 },
    SG: { x: 78.5, y: 63.5 },
    HK: { x: 80.5, y: 52.5 },
    TW: { x: 82.2, y: 51.6 },
    DE: { x: 52.5, y: 39.5 },
    FR: { x: 50.5, y: 41.5 },
    GB: { x: 48.5, y: 36.5 },
    UK: { x: 48.5, y: 36.5 },
    RU: { x: 66.5, y: 30.5 },
    IN: { x: 69.5, y: 55.5 },
    AU: { x: 84.5, y: 78.5 },
    BR: { x: 35.5, y: 69.5 },
    CA: { x: 21.5, y: 30.5 }
  };

  const COUNTRY_COORDINATES = {
    CN: [104.1954, 35.8617],
    中国: [104.1954, 35.8617],
    CHINA: [104.1954, 35.8617],
    US: [-95.7129, 37.0902],
    USA: [-95.7129, 37.0902],
    JP: [138.2529, 36.2048],
    KR: [127.7669, 35.9078],
    SG: [103.8198, 1.3521],
    HK: [114.1694, 22.3193],
    TW: [120.9605, 23.6978],
    DE: [10.4515, 51.1657],
    FR: [2.2137, 46.2276],
    GB: [-3.4360, 55.3781],
    UK: [-3.4360, 55.3781],
    RU: [105.3188, 61.5240],
    IN: [78.9629, 20.5937],
    AU: [133.7751, -25.2744],
    BR: [-51.9253, -14.2350],
    CA: [-106.3468, 56.1304]
  };

  const CHINA_PROVINCE_COORDINATES = {
    BJ: [116.4074, 39.9042], 北京: [116.4074, 39.9042],
    TJ: [117.2000, 39.1333], 天津: [117.2000, 39.1333],
    HE: [114.5149, 38.0428], 河北: [114.5149, 38.0428],
    SX: [112.5492, 37.8706], 山西: [112.5492, 37.8706],
    NM: [111.7510, 40.8415], 内蒙古: [111.7510, 40.8415],
    LN: [123.4315, 41.8057], 辽宁: [123.4315, 41.8057],
    JL: [125.3235, 43.8171], 吉林: [125.3235, 43.8171],
    HL: [126.5349, 45.8038], 黑龙江: [126.5349, 45.8038],
    SH: [121.4737, 31.2304], 上海: [121.4737, 31.2304],
    JS: [118.7969, 32.0603], 江苏: [118.7969, 32.0603],
    ZJ: [120.1551, 30.2741], 浙江: [120.1551, 30.2741],
    AH: [117.2272, 31.8206], 安徽: [117.2272, 31.8206],
    FJ: [119.2965, 26.0745], 福建: [119.2965, 26.0745],
    JX: [115.8582, 28.6829], 江西: [115.8582, 28.6829],
    SD: [117.1201, 36.6512], 山东: [117.1201, 36.6512],
    HA: [113.6254, 34.7466], 河南: [113.6254, 34.7466],
    HB: [114.3055, 30.5928], 湖北: [114.3055, 30.5928],
    HN: [112.9388, 28.2282], 湖南: [112.9388, 28.2282],
    GD: [113.2644, 23.1291], 广东: [113.2644, 23.1291],
    GX: [108.3669, 22.8170], 广西: [108.3669, 22.8170],
    HI: [110.3312, 20.0311], 海南: [110.3312, 20.0311],
    CQ: [106.5516, 29.5630], 重庆: [106.5516, 29.5630],
    SC: [104.0665, 30.5723], 四川: [104.0665, 30.5723],
    GZ: [106.6302, 26.6470], 贵州: [106.6302, 26.6470],
    YN: [102.8329, 24.8801], 云南: [102.8329, 24.8801],
    XZ: [91.1172, 29.6469], 西藏: [91.1172, 29.6469],
    SN: [108.9398, 34.3416], 陕西: [108.9398, 34.3416],
    GS: [103.8343, 36.0611], 甘肃: [103.8343, 36.0611],
    QH: [101.7782, 36.6171], 青海: [101.7782, 36.6171],
    NX: [106.2309, 38.4872], 宁夏: [106.2309, 38.4872],
    XJ: [87.6168, 43.8256], 新疆: [87.6168, 43.8256],
    HK: [114.1694, 22.3193], 香港: [114.1694, 22.3193],
    MO: [113.5439, 22.1987], 澳门: [113.5439, 22.1987],
    TW: [121.5654, 25.0330], 台湾: [121.5654, 25.0330]
  };

  const CHINA_PROVINCE_ALIASES = {
    BEIJING: 'BJ',
    TIANJIN: 'TJ',
    HEBEI: 'HE',
    SHANXI: 'SX',
    'INNER MONGOLIA': 'NM',
    INNERMONGOLIA: 'NM',
    NEIMENGGU: 'NM',
    LIAONING: 'LN',
    JILIN: 'JL',
    HEILONGJIANG: 'HL',
    SHANGHAI: 'SH',
    JIANGSU: 'JS',
    ZHEJIANG: 'ZJ',
    ANHUI: 'AH',
    FUJIAN: 'FJ',
    JIANGXI: 'JX',
    SHANDONG: 'SD',
    HENAN: 'HA',
    HUBEI: 'HB',
    HUNAN: 'HN',
    GUANGDONG: 'GD',
    GUANGXI: 'GX',
    HAINAN: 'HI',
    CHONGQING: 'CQ',
    SICHUAN: 'SC',
    GUIZHOU: 'GZ',
    YUNNAN: 'YN',
    TIBET: 'XZ',
    XIZANG: 'XZ',
    SHAANXI: 'SN',
    SHANXI2: 'SN',
    GANSU: 'GS',
    QINGHAI: 'QH',
    NINGXIA: 'NX',
    XINJIANG: 'XJ',
    HONGKONG: 'HK',
    'HONG KONG': 'HK',
    MACAU: 'MO',
    MACAO: 'MO',
    TAIWAN: 'TW'
  };

  const CHINA_PROVINCE_POSITIONS = Object.fromEntries(
    Object.entries(CHINA_PROVINCE_COORDINATES).map(([key, coord]) => [
      key,
      {
        x: clampPercent(((coord[0] + 180) / 360) * 100),
        y: clampPercent(((90 - coord[1]) / 180) * 100)
      }
    ])
  );

  /* The audit overview cards pass `icon` straight through to the kit, which renders
     whatever markup it is handed, so every stats array that omitted one left an
     empty icon slot on the page: 16 of them across the four activity sub-pages.
     Stroke icons keyed by role, on the same 24-box the kit normalises to. */
  const AUDIT_STAT_ICONS = {
    count: '<path d="M4 19V9M10 19V5M16 19v-7M22 19V3"></path>',
    online: '<path d="M5 12.5 9.5 17 19 7.5"></path>',
    offline: '<path d="M6 6l12 12M18 6 6 18"></path>',
    roam: '<path d="M4 12h10m0 0-3.5-3.5M14 12l-3.5 3.5"></path><circle cx="19" cy="12" r="2"></circle>',
    presence: '<circle cx="12" cy="8" r="3.4"></circle><path d="M5.5 20c0-3.6 2.9-6.5 6.5-6.5s6.5 2.9 6.5 6.5"></path>',
    away: '<circle cx="12" cy="12" r="8.5"></circle><path d="M12 7.5V12l3 2"></path>',
    accounts: '<circle cx="9" cy="8" r="3.2"></circle><path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6M16 6.2a3.2 3.2 0 0 1 0 6.1M18 20c0-2.2-.9-4.2-2.4-5.6"></path>',
    protocol: '<path d="M4 7h13m0 0-4-4m4 4-4 4M20 17H7m0 0 4 4m-4-4 4-4"></path>',
    connections: '<circle cx="6" cy="6" r="2.4"></circle><circle cx="18" cy="18" r="2.4"></circle><path d="M8 7.6 16 16.4"></path>',
    traffic: '<path d="M3 17.5 8.5 11l4 3.5L21 5"></path><path d="M21 10V5h-5"></path>',
    unknown: '<circle cx="12" cy="12" r="8.5"></circle><path d="M9.6 9.4a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.5v.4"></path><path d="M12 17h.01"></path>',
    status: '<circle cx="12" cy="12" r="8.5"></circle><path d="M12 8v4.2l2.8 1.6"></path>',
    retention: '<path d="M4 7c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3Z"></path><path d="M4 7v10c0 1.7 3.6 3 8 3s8-1.3 8-3V7"></path><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"></path>',
    dbSize: '<path d="M5 5h14v14H5z"></path><path d="M5 10h14M10 5v14"></path>',
    dropped: '<path d="M12 4v9"></path><path d="M8.5 9.5 12 13l3.5-3.5"></path><path d="M5 18h14"></path>'
  };

  function auditStatIcon(name) {
    const body = AUDIT_STAT_ICONS[name];
    if (!body) return '';
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
  }


  function chevronSvg() {
    return '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m5 8 5 5 5-5"/></svg>';
  }

  function trafficTabSvg() {
    return '<svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M9.644 8.596a.5.5 0 0 0 .707-.707L7.108 4.646a.5.5 0 0 0-.707 0L3.158 7.89a.5.5 0 0 0 .707.707l2.39-2.39v8.959c0 .185.224.335.5.335s.5-.15.5-.335V6.207l2.39 2.389Zm6.487 2.808a.5.5 0 0 1 .707.707l-3.243 3.243a.5.5 0 0 1-.707 0l-3.243-3.243a.5.5 0 0 1 .707-.707l2.39 2.39V4.836c0-.185.224-.335.5-.335s.5.15.5.335v8.958l2.39-2.389Z"/></svg>';
  }

  function activityTabSvg() {
    return '<svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M11 3H9a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h2a1 1 0 0 0 1-1V4a1 1 0 0 0-1-1Zm0 1v10H9V4h2Zm3 2h2a1 1 0 0 1 1 1v7a1 1 0 0 1-1 1h-2a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1Zm2 8V7h-2v7h2ZM4 10h2a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1Zm2 4v-3H4v3h2Z"/><path d="M3.5 16h13a.5.5 0 0 1 0 1h-13a.5.5 0 0 1 0-1Z"/></svg>';
  }

  function targetSvg() {
    return '<svg viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z"></path><path fill-rule="evenodd" clip-rule="evenodd" d="M11.5 3.5a.5.5 0 0 1 1 0v2.52a6.001 6.001 0 0 1 5.48 5.48h2.52a.5.5 0 0 1 0 1h-2.52a6.002 6.002 0 0 1-5.48 5.48v2.52a.5.5 0 0 1-1 0v-2.52a6.001 6.001 0 0 1-5.48-5.48H3.5a.5.5 0 0 1 0-1h2.52a6.001 6.001 0 0 1 5.48-5.48V3.5ZM17 12a5 5 0 1 0-10 0 5 5 0 0 0 10 0Z"></path></svg>';
  }

  function zoomInSvg() {
    return '<svg viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M18 11c0-3.86-3.14-7-7-7s-7 3.14-7 7 3.14 7 7 7 7-3.14 7-7ZM3 11a8 8 0 1 1 14 5.292l3.854 3.854a.5.5 0 1 1-.707.708l-3.855-3.855A8 8 0 0 1 3 11Zm4 0a.5.5 0 0 1 .5-.5h3v-3a.5.5 0 0 1 1 0v3h3a.5.5 0 0 1 0 1h-3v3a.5.5 0 0 1-1 0v-3h-3A.5.5 0 0 1 7 11Z"></path></svg>';
  }

  function zoomOutSvg() {
    return '<svg viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M11 4c3.86 0 7 3.14 7 7s-3.14 7-7 7-7-3.14-7-7 3.14-7 7-7Zm0-1a8 8 0 1 0 5.292 14l3.854 3.854a.5.5 0 0 0 .708-.707l-3.855-3.855A8 8 0 0 0 11 3Zm-3.5 7.5a.5.5 0 0 0 0 1h7a.5.5 0 0 0 0-1h-7Z"></path></svg>';
  }

  function checkSvg() {
    return '<svg viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M21 12c0-4.963-4.037-9-9-9s-9 4.037-9 9 4.037 9 9 9 9-4.037 9-9ZM2 12C2 6.477 6.477 2 12 2s10 4.477 10 10-4.477 10-10 10S2 17.523 2 12Zm15.028-2.009a.498.498 0 0 0 0-.708.502.502 0 0 0-.708 0l-5.303 5.304-3.163-3.164a.498.498 0 0 0-.708 0 .5.5 0 0 0 0 .707l3.164 3.164a1 1 0 0 0 1.414 0l5.304-5.303Z" fill="currentColor"></path></svg>';
  }

  function xSvg() {
    return '<svg viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M12 3a9 9 0 1 1 0 18 9 9 0 0 1 0-18Zm10 9c0-5.523-4.477-10-10-10S2 6.477 2 12s4.477 10 10 10 10-4.477 10-10Zm-6.465 3.535a.5.5 0 0 1-.707 0L12 12.707l-2.829 2.829a.5.5 0 0 1-.707-.707L11.293 12 8.464 9.171a.5.5 0 1 1 .707-.707L12 11.293l2.828-2.828a.5.5 0 1 1 .707.707L12.707 12l2.828 2.828a.5.5 0 0 1 0 .707Z" fill="currentColor"></path></svg>';
  }

  function searchSvg() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>';
  }

  function refreshSvg() {
    return '<svg viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M15.084 2.906c-.224.243-.36.567-.36.922v4.738c0 .355.26.673.614.707a.682.682 0 0 0 .747-.679V4.845a8.246 8.246 0 0 1 4.153 7.153c0 4.543-3.695 8.239-8.238 8.239-.464 0-.92-.038-1.362-.113v1.378c.446.064.899.096 1.362.096 5.293 0 9.6-4.307 9.6-9.6a9.602 9.602 0 0 0-4.564-8.17h3.815a.682.682 0 0 0 .678-.747c-.034-.354-.351-.614-.706-.614h-4.738c-.396 0-.753.169-1 .44ZM3.762 11.998C3.762 7.456 7.457 3.76 12 3.76c.464 0 .92.038 1.362.113V2.495A9.555 9.555 0 0 0 12 2.398c-5.293 0-9.6 4.307-9.6 9.6a9.602 9.602 0 0 0 4.564 8.17l.005.004H3.15a.682.682 0 0 0-.678.747c.034.354.351.614.707.614h4.737c.396 0 .753-.168 1-.44.226-.242.362-.566.362-.921v-4.766a.682.682 0 0 0-.748-.678c-.354.034-.614.351-.614.706v3.718a8.246 8.246 0 0 1-4.153-7.154Z"></path></svg>';
  }

  function calendarSvg() {
    return '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-label="自定义日期"><rect x="3" y="4" width="14" height="13" rx="2"/><path d="M6 2.5v3M14 2.5v3M3 8h14"/><path d="M6.5 11h.01M10 11h.01M13.5 11h.01M6.5 14h.01M10 14h.01M13.5 14h.01"/></svg>';
  }

  function activitySvg() {
    return '<svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M5 4.5a.75.75 0 0 1 .75-.75h2.5a.75.75 0 0 1 .75.75v11a.75.75 0 0 1-.75.75h-2.5A.75.75 0 0 1 5 15.5v-11Zm6 3a.75.75 0 0 1 .75-.75h2.5a.75.75 0 0 1 .75.75v8a.75.75 0 0 1-.75.75h-2.5a.75.75 0 0 1-.75-.75v-8ZM2 10.5a.75.75 0 0 1 .75-.75h1.5a.75.75 0 0 1 .75.75v5a.75.75 0 0 1-.75.75h-1.5A.75.75 0 0 1 2 15.5v-5Z"/></svg>';
  }

  function checkOnlySvg() {
    return '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m4 10.4 3.4 3.4L16 5.2"/></svg>';
  }

  function infoSvg() {
    return '<svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm-.75-9.25a.75.75 0 0 1 1.5 0V14a.75.75 0 0 1-1.5 0V8.75ZM10 5.5a1 1 0 1 0 0 2 1 1 0 0 0 0-2Z" clip-rule="evenodd"/></svg>';
  }

  function summaryTrafficSvg() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M7 4v16"/><path d="m3.5 8.5 3.5-4 3.5 4"/><path d="M17 20V4"/><path d="m13.5 15.5 3.5 4 3.5-4"/></svg>';
  }

  function emptyStateSvg(kind) {
    if (kind === 'application') {
      return '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M21 4a1 1 0 0 0-1-1H9a1 1 0 0 0-1 1v3h8a1 1 0 0 1 1 1v8h3a1 1 0 0 0 1-1V4ZM4 8h11a1 1 0 0 1 1 1v11a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1Z"/></svg>';
    }
    if (kind === 'client') {
      return '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M21 7V5a1 1 0 0 0-1-1H4a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h7v-4a1 1 0 0 1 1-1h1V8a1 1 0 0 1 1-1h7Zm-4 13a1 1 0 0 0 1-1v-6a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h4Zm5-11v10a1 1 0 0 1-1 1h-1a1 1 0 0 1-1-1v-7a1 1 0 0 0-1-1h-3a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1ZM5 20h6v-3H3c-.552 0-1.016.46-.836.982A3.001 3.001 0 0 0 5 20Z"/></svg>';
    }
    return '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M14.465 2.307a9.928 9.928 0 0 0-2.329-.305C12.091 2 12.046 2 12 2a9.927 9.927 0 0 0-2.466.307A10.017 10.017 0 0 0 2.457 9h1.589a8.54 8.54 0 0 1 5.687-5.193A11.964 11.964 0 0 0 6.878 9h1.558a10.51 10.51 0 0 1 2.813-4.587V9h1.5V4.413A10.509 10.509 0 0 1 15.563 9h1.558a11.964 11.964 0 0 0-2.856-5.193A8.54 8.54 0 0 1 19.953 9h1.588a10.017 10.017 0 0 0-7.076-6.693ZM9.533 21.693A10.017 10.017 0 0 1 2.457 15h1.589a8.54 8.54 0 0 0 5.687 5.193A11.964 11.964 0 0 1 6.878 15h1.558a10.51 10.51 0 0 0 2.813 4.587V15h1.5v4.587A10.509 10.509 0 0 0 15.563 15h1.558a11.964 11.964 0 0 1-2.856 5.193A8.54 8.54 0 0 0 19.953 15h1.588a10.017 10.017 0 0 1-7.076 6.693 9.928 9.928 0 0 1-2.329.305C12.091 22 12.046 22 12 22c-.046 0-.092 0-.137-.002a9.927 9.927 0 0 1-2.329-.305ZM8.221 10.088 7.055 13.8h-.803a.176.176 0 0 1-.112-.04.258.258 0 0 1-.072-.133l-.604-2.009a4.688 4.688 0 0 1-.065-.226 7.834 7.834 0 0 1-.047-.23 10.686 10.686 0 0 1-.115.464l-.612 2.001c-.034.115-.106.173-.216.173h-.763l-1.167-3.712h.792a.31.31 0 0 1 .18.05c.05.034.084.078.1.13l.458 1.836a8.023 8.023 0 0 1 .136.67l.09-.328c.034-.11.07-.224.105-.342l.544-1.843a.248.248 0 0 1 .097-.126.288.288 0 0 1 .17-.05h.439a.3.3 0 0 1 .176.05c.05.034.084.076.1.126l.526 1.843c.034.116.066.23.097.342.032.11.06.222.087.335l.061-.331c.024-.113.052-.228.083-.346l.479-1.836a.247.247 0 0 1 .097-.13.288.288 0 0 1 .17-.05h.755Zm6.549 0L13.604 13.8H12.8a.176.176 0 0 1-.112-.04.258.258 0 0 1-.072-.133l-.605-2.009a4.688 4.688 0 0 1-.064-.226 7.834 7.834 0 0 1-.047-.23 10.686 10.686 0 0 1-.115.464l-.612 2.001c-.034.115-.106.173-.216.173h-.764l-1.166-3.712h.792a.31.31 0 0 1 .18.05c.05.034.084.078.1.13l.458 1.836a8.023 8.023 0 0 1 .136.67l.09-.328c.034-.11.07-.224.105-.342l.544-1.843a.248.248 0 0 1 .097-.126.288.288 0 0 1 .17-.05h.438a.3.3 0 0 1 .177.05c.05.034.084.076.1.126l.526 1.843c.034.116.066.23.097.342.032.11.06.222.087.335.019-.11.04-.22.061-.331.024-.113.052-.228.083-.346l.479-1.836a.247.247 0 0 1 .097-.13.288.288 0 0 1 .169-.05h.756Zm5.383 3.712 1.166-3.712h-.756a.288.288 0 0 0-.17.05.247.247 0 0 0-.096.13l-.48 1.836a7.155 7.155 0 0 0-.143.677 7.596 7.596 0 0 0-.087-.335 25.5 25.5 0 0 0-.097-.342l-.525-1.843a.243.243 0 0 0-.101-.126.3.3 0 0 0-.177-.05h-.439a.288.288 0 0 0-.17.05.248.248 0 0 0-.096.126l-.544 1.843-.104.342c-.032.11-.061.22-.09.328l-.061-.328a7.466 7.466 0 0 0-.076-.342l-.457-1.836a.242.242 0 0 0-.101-.13.306.306 0 0 0-.18-.05h-.792l1.166 3.712h.764c.11 0 .182-.058.215-.173l.612-2.001c.024-.077.045-.154.062-.23l.054-.235c.014.077.03.154.047.23.019.075.04.15.064.227l.605 2.01a.25.25 0 0 0 .072.132c.034.027.07.04.112.04h.802Z"/></svg>';
  }

  function cyberMapLoaderMarkup() {
    const letters = 'Loading...'.split('').map((letter) => `<span class="loader-letter">${letter}</span>`).join('');
    return `
      <div class="loader-wrapper insights-cyber-loader" aria-label="地图加载中">
        ${letters}
        <div class="loader" aria-hidden="true"></div>
      </div>`;
  }

  function cyberMapUnavailableMarkup(message) {
    return `
      <div class="insights-cyber-map-unavailable">
        <span>Local map unavailable</span>
        <strong>离线地图资源暂不可用</strong>
        ${message ? `<small>${escapeAttr(message)}</small>` : ''}
      </div>`;
  }

  window.DWRTInsightsFlows = { create };
})();
