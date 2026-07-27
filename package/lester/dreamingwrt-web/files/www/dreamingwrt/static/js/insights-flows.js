(() => {
  'use strict';

  const VERSION = '20260714-03';
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
      activityStatMetric: 'total',
      activityAnchor: 'client',
      activitySection: 'overview',
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
      return firstNumber(item.bytes, item.total_bytes, item.traffic_bytes, item.rx_bytes) + firstNumber(item.tx_bytes);
    }

    function countFromObject(map) {
      if (!map || typeof map !== 'object') return 0;
      return Object.values(map).reduce((sum, value) => sum + firstNumber(value), 0);
    }

    function summaryCounts() {
      const data = state.summary || {};
      const allowed = data.allowed_count_by_risk || data.allowed || {};
      const blocked = data.blocked_count_by_risk || data.blocked || {};
      const all = data.all_count_by_risk || data.risk || {};
      const low = firstNumber(data.low, all.low, all.LOW, allowed.low, allowed.LOW) + firstNumber(blocked.low, blocked.LOW);
      const suspicious = firstNumber(data.suspicious, data.medium, all.suspicious, all.SUSPICIOUS, all.medium, all.MEDIUM, allowed.suspicious, allowed.SUSPICIOUS) + firstNumber(blocked.suspicious, blocked.SUSPICIOUS);
      const concern = firstNumber(data.concern, data.high, all.concern, all.CONCERN, all.high, all.HIGH, all.very_high, all.VERY_HIGH, allowed.concern, allowed.high) + firstNumber(blocked.concern, blocked.high, blocked.VERY_HIGH);
      const total = firstNumber(data.total, data.total_count, data.flow_count, countFromObject(data.all_count_by_region), countFromObject(allowed) + countFromObject(blocked), low + suspicious + concern, state.flows.length);
      return { total, low, suspicious, concern };
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

    function geoDestinationItems() {
      const points = mapPoints();
      if (!points.length) return [];
      return dedupeTopItems(points.map((point) => ({
        ...point,
        __top_label: geoDestinationLabel(point),
        bytes: firstNumber(point.bytes, point.total_bytes, point.traffic_bytes, point.rx_bytes + point.tx_bytes),
        count: firstNumber(point.count, point.flow_count, point.total, point.value, 1)
      })).filter((point) => point.__top_label), 'destination');
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
      if (state.mapScope !== 'china') return routes;
      return routes.filter((route) => isChinaScopedMapPoint(route.from) && isChinaScopedMapPoint(route.to));
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

    function applyMapResults(requestSeq, geo, requestStartedAt) {
      if (!state.root || requestSeq !== state.refreshSeq || state.mode !== 'flows') return;
      const focusState = captureFocusState();
      const nextGeo = normalizePayload(geo);
      if (nextGeo && !hasRealtimeSince('insights.flows.geo', requestStartedAt)) state.geo = nextGeo;
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
        render();
        restoreFocusState(focusState);
        scheduleGlassCardsRender?.(260);
        return;
      }
      const activeRange = nowRange();
      let geo = { ok: true, data: state.geo };
      let mapResultsSettled = false;
      if (state.mode === 'flows' && state.mapEnabled) {
        fetchWithRetry('insights_geo', ENDPOINTS.geo(queryPeriod(), activeRange, state.mapScope), 3, 550)
          .then((nextGeoResult) => {
          geo = nextGeoResult;
          mapResultsSettled = true;
          applyMapResults(requestSeq, geo, requestStartedAt);
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
          <strong>统计</strong>
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
            <span class="insights-switch">
              <input type="checkbox" data-summary-toggle ${state.summaryEnabled ? 'checked' : ''}>
              <span class="insights-switch-ui" aria-hidden="true"></span>
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
            <span class="insights-switch">
              <input type="checkbox" data-map-toggle ${state.mapEnabled ? 'checked' : ''}>
              <span class="insights-switch-ui" aria-hidden="true"></span>
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
          <button class="insights-icon-button" data-insights-refresh type="button" title="刷新">${refreshSvg()}</button>
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
      const pct = (value) => counts.total ? `${Math.round(value / counts.total * 100)}%` : '0%';
      const totalRow = { id: 'total', label: '总计', value: counts.total, detail: '', icon: summaryTrafficSvg() };
      const riskRows = [
        { id: 'low', label: '低', value: counts.low, detail: `${counts.low} (${pct(counts.low)})` },
        { id: 'suspicious', label: '可疑', value: counts.suspicious, detail: `${counts.suspicious} (${pct(counts.suspicious)})` },
        { id: 'concern', label: '令人担忧', value: counts.concern, detail: `${counts.concern} (${pct(counts.concern)})` }
      ];
      return `
        <section class="insights-summary-section" aria-label="流量摘要">
          <article class="insights-summary-card dwrt-glass-card insights-stable-glass" data-insights-overview-card="summary">
            <div class="insights-card-content" data-insights-card-content>
              <h2>流量摘要</h2>
              <div class="insights-summary-list">
                <div class="insights-summary-row ${totalRow.id}">
                  <span class="insights-summary-mark" aria-hidden="true">${totalRow.icon}</span>
                  <span class="insights-summary-label">${html(totalRow.label)}</span>
                  <strong>${html(formatInteger(totalRow.value))}</strong>
                </div>
                ${riskRows.map((row) => `
                  <div class="insights-summary-row insights-summary-risk-entry ${row.id}">
                    <span class="dwrt-risk-bars insights-summary-risk-bars ${row.id}" aria-hidden="true"><i></i><i></i><i></i></span>
                    <span class="insights-summary-label">${html(row.label)}</span>
                    <strong>${html(row.detail)}</strong>
                  </div>
                `).join('')}
              </div>
            </div>
          </article>
        </section>`;
    }

    function topItemName(item, kind) {
      if (item && item.__top_label) return item.__top_label;
      if (kind === 'destination') {
        return firstText(geoDestinationLabel(item), item.destination, item.destination_name, item.destination_host, item.domain, item.host, item.region, item.country, item.ip, item.name, item.label, '--');
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
      if (hasTrafficBytes(item) || item.__top_has_bytes) {
        return formatBytes(bytesOf(item));
      }
      return formatInteger(firstNumber(item.count, item.flow_count, item.total, item.value));
    }

    function topCard(title, empty, items, kind) {
      return `
        <article class="insights-top-card dwrt-glass-card insights-stable-glass" data-insights-overview-card="${html(kind)}">
          <div class="insights-card-content" data-insights-card-content>
            <div class="insights-card-title">
              <strong>${html(title)}</strong>
              <span>${html(items.length ? `${items.length}` : empty)}</span>
            </div>
            ${items.length ? `
              <div class="insights-list">
                ${items.slice(0, 6).map((item) => `
                  <div class="insights-list-item">
                    <b>${html(topItemName(item, kind))}</b>
                    <small>${html(topItemMetric(item))}</small>
                  </div>`).join('')}
              </div>` : `
              <div class="insights-empty insights-top-empty">
                <span class="insights-empty-icon ${html(kind)}" aria-hidden="true">${emptyStateSvg(kind)}</span>
                <strong>${html(empty)}</strong>
              </div>`}
          </div>
        </article>`;
    }

    function overviewMarkup() {
      const destinationItems = geoDestinationItems();
      return `
        <section class="insights-overview-row" aria-label="流量概览">
          ${summaryMarkup()}
          ${topCard('热门目的地', '无目的地', destinationItems.length ? destinationItems : dedupeTopItems(topList(['top_all_count_by_destination', 'top_destinations', 'destinations']), 'destination'), 'destination')}
          ${topCard('热门客户端', '无受影响客户端', dedupeTopItems(topList(['top_all_count_by_client', 'top_clients', 'clients']), 'client'), 'client')}
          ${topCard('热门应用', '无受影响应用', dedupeTopItems(topList(['top_all_traffic_by_application', 'top_applications', 'applications', 'apps']), 'application'), 'application')}
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
            <div class="insights-map-controls" aria-label="地图控制">
              <button type="button" data-map-control="reset" title="重置视图">${targetSvg()}</button>
              <button type="button" data-map-control="zoom-in" title="放大">${zoomInSvg()}</button>
              <button type="button" data-map-control="zoom-out" title="缩小">${zoomOutSvg()}</button>
            </div>
          </div>
        </section>`;
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
      const series = activityRateSeries();
      const width = 1000;
      const height = 310;
      const pad = { left: 44, right: 16, top: 24, bottom: 36 };
      const maxPoint = Math.max(0, ...series.map((item) => item.total || item.download || item.upload));
      const max = maxPoint > 0 ? maxPoint : 500000;
      const yTicks = [0.25, 0.5, 0.75, 1];
      const x = (index) => pad.left + (series.length <= 1 ? 0 : index / (series.length - 1) * (width - pad.left - pad.right));
      const y = (value) => pad.top + (1 - Math.min(1, Math.max(0, value / max))) * (height - pad.top - pad.bottom);
      const line = (key) => series.map((item, index) => `${index ? 'L' : 'M'} ${x(index).toFixed(1)} ${y(item[key]).toFixed(1)}`).join(' ');
      const labels = series.filter((_, index) => index === 0 || index === series.length - 1 || index % Math.max(1, Math.floor(series.length / 5)) === 0).slice(0, 7);
      return `
        <section class="insights-activity-chart dwrt-glass-card insights-stable-glass" aria-label="互联网活动趋势" data-insights-activity-card="chart">
          <div class="insights-card-content insights-activity-chart-content" data-insights-card-content>
            <span class="activity-axis-unit">Mbps</span>
            <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
              ${yTicks.map((ratio) => `<path class="activity-grid-line" d="M ${pad.left} ${y(max * ratio).toFixed(1)} H ${width - pad.right}"/><text class="activity-y-label" x="${pad.left - 10}" y="${y(max * ratio).toFixed(1)}">${activityRateTick(max * ratio)}</text>`).join('')}
              ${labels.map((item, idx) => `<text class="activity-x-label" x="${x(series.indexOf(item)).toFixed(1)}" y="${height - 10}" text-anchor="${idx === 0 ? 'start' : idx === labels.length - 1 ? 'end' : 'middle'}">${html(activityTimeLabel(item.timestamp))}</text>`).join('')}
              <path class="activity-area-download" d="${line('download')} L ${x(series.length - 1).toFixed(1)} ${height - pad.bottom} L ${pad.left} ${height - pad.bottom} Z"/>
              <path class="activity-line-download" d="${line('download')}"/>
              <path class="activity-line-upload" d="${line('upload')}"/>
            </svg>
          </div>
        </section>`;
    }

    function activityTimeLabel(timestamp) {
      const value = Number(timestamp);
      const date = new Date(value > 1e12 ? value : value * 1000);
      if (!Number.isFinite(date.getTime())) return '--';
      return new Intl.DateTimeFormat('zh-CN', { hour: 'numeric', minute: '2-digit' }).format(date);
    }

    function activityRateTick(bytesPerSecond) {
      const mbps = Math.max(0, Number(bytesPerSecond) || 0) * 8 / 1000000;
      if (mbps >= 10) return String(Math.round(mbps));
      return mbps.toFixed(1);
    }

    function activityTableMarkup() {
      const rows = activityRows();
      const total = Math.max(1, rows.reduce((sum, item) => sum + activityBytes(item), 0));
      return `
        <section class="insights-activity-table dwrt-glass-card insights-stable-glass" data-insights-activity-card="table">
          <div class="insights-card-content insights-activity-table-scroll" data-insights-card-content>
            <table>
              <thead>
                <tr>
                  <th>应用程序</th>
                  <th>总数据（流量 %）</th>
                  <th>下载</th>
                  <th>上传</th>
                  <th>主要客户端</th>
                  <th>客户端</th>
                </tr>
              </thead>
              <tbody>
                ${rows.length ? rows.map((item) => {
                  const bytes = activityBytes(item);
                  const download = firstNumber(item.download, item.download_bytes, item.rx_bytes, item.rx_byte, item.topAppBytesReceived);
                  const upload = firstNumber(item.upload, item.upload_bytes, item.tx_bytes, item.tx_byte, item.topAppBytesTransmitted);
                  const pct = bytes > 0 ? Math.max(0.1, bytes / total * 100).toFixed(1) : '0.0';
                  return `<tr>
                    <td>${html(activityName(item))}</td>
                    <td>${html(formatBytes(bytes))} (${pct}%)</td>
                    <td class="traffic-down">${html(formatBytes(download))}</td>
                    <td class="traffic-up">${html(formatBytes(upload))}</td>
                    <td>${html(activityTopClient(item))}</td>
                    <td>${html(formatInteger(firstNumber(item.client_count, item.clients, item.clientCount, item.app_count, item.appCount)))}</td>
                  </tr>`;
                }).join('') : `
                  <tr>
                    <td colspan="6">
                      <div class="insights-activity-empty">
                        <span>${infoSvg()}</span>
                        <strong>此网络上没有流量。</strong>
                      </div>
                    </td>
                  </tr>`}
              </tbody>
            </table>
          </div>
        </section>`;
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

    function modalMarkup() {
      return `
        <div class="insights-modal" data-insights-modal hidden>
          <button class="insights-modal-backdrop" data-modal-close type="button" aria-label="关闭"></button>
          <section class="insights-modal-panel dwrt-glass-card insights-stable-glass" role="dialog" aria-modal="true" aria-label="自定义列">
            <h3>自定义列</h3>
            <div class="insights-column-grid">
              ${DEFAULT_COLUMNS.map(([id, label]) => `
                <label>
                  <input type="checkbox" data-column="${id}" ${state.columns.has(id) ? 'checked' : ''}>
                  <span>${html(label)}</span>
                </label>`).join('')}
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
      return `<span class="insights-audit-main-cell"><strong>${html(title || '--')}</strong>${subtitle ? `<small>${html(subtitle)}</small>` : ''}</span>`;
    }

    function auditMetric(label, value, hint = '') {
      return `<div class="insights-audit-metric"><span>${html(label)}</span><strong>${html(value)}</strong>${hint ? `<em>${html(hint)}</em>` : ''}</div>`;
    }

    function auditStatsMarkup(items = []) {
      const stats = (items || []).filter((item) => item && firstText(item.label) && firstText(item.value) !== '');
      if (!stats.length) return '';
      return `<div class="insights-audit-toolbar-stats" aria-label="审计统计">
        ${stats.map((item) => `<span class="insights-audit-stat-chip ${html(item.tone || '')}"><em>${html(item.label)}</em><strong>${html(item.value)}</strong></span>`).join('')}
      </div>`;
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

    function auditSearchToolbar(section, controls = '') {
      const query = auditQuery(section);
      const ranges = Object.entries(ACTIVITY_PERIODS).filter(([id]) => id !== 'month');
      const rangeButtons = `<div class="insights-audit-range" role="tablist" aria-label="审计时间范围">${ranges.map(([id, item]) => `
        <button type="button" ${id === 'custom' ? 'data-date-range-trigger title="自定义时间范围"' : `data-period="${id}"`} class="${state.period === id ? 'is-active' : ''}">${id === 'custom' ? calendarSvg() : html(item.label)}</button>
      `).join('')}</div>`;
      return `<div class="insights-audit-toolbar">
        <label class="insights-audit-search" data-dwrt-component="expand-search">${searchSvg()}<input type="search" value="${html(query.q || '')}" placeholder="搜索" data-audit-search="${html(section)}" autocomplete="off" spellcheck="false"></label>
        ${rangeButtons}
        ${controls}
        <button class="insights-icon-button" data-audit-refresh type="button" title="刷新">${refreshSvg()}</button>
        <button class="insights-audit-link" data-audit-export type="button">导出</button>
      </div>`;
    }

    function auditTabs(section, tabs) {
      const query = auditQuery(section);
      return `<div class="insights-audit-tabs dwrt-kit-tabs" role="tablist">
        ${tabs.map(([id, label]) => `<button class="dwrt-kit-tab ${query.view === id ? 'is-active' : ''}" data-audit-view="${html(section)}" data-value="${html(id)}" type="button" aria-selected="${query.view === id ? 'true' : 'false'}">${html(label)}</button>`).join('')}
      </div>`;
    }

    function auditTableMarkup(title, subtitle, count, columns, rows, empty, tableClass = '', options = {}) {
      const error = firstText(options.error);
      const loadingText = state.loading || state.audit.loading ? '读取中' : `${formatInteger(count)} 条`;
      const subtitleText = error ? `${subtitle} · 接口未完全就绪：${error}` : subtitle;
      return `<section class="insights-audit-table-card dwrt-kit-table-wrap dwrt-glass-card insights-stable-glass ${html(tableClass)}">
        <div class="dwrt-kit-table-toolbar">
          <div class="dwrt-kit-table-title"><strong>${html(title)}</strong><span class="${error ? 'is-warning' : ''}" title="${html(subtitleText)}">${html(subtitleText)}</span></div>
          <div class="insights-audit-table-meta">
            ${auditStatsMarkup(options.stats || [])}
            <span class="dwrt-kit-table-count">${html(loadingText)}</span>
          </div>
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
        hits: firstNumber(row.hits, row.count, row.requests, 1),
        up_bytes: firstNumber(row.up_bytes, row.tx_bytes, row.upload_bytes),
        down_bytes: firstNumber(row.down_bytes, row.rx_bytes, row.download_bytes),
        wan: firstText(row.wan, row.ifname, row.interface),
        evidence: firstText(row.evidence, row.reason, row.rule, row.source),
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
        const current = map.get(host) || { host, app: row.app, category: row.category, clientsSet: new Set(), hits: 0, up_bytes: 0, down_bytes: 0, first_seen: row.ts, last_seen: row.ts, action: row.action };
        if (row.mac || row.ip || row.client) current.clientsSet.add(row.mac || row.ip || row.client);
        current.hits += firstNumber(row.hits, 1);
        current.up_bytes += firstNumber(row.up_bytes);
        current.down_bytes += firstNumber(row.down_bytes);
        current.first_seen = Math.min(auditTimestamp(current.first_seen) || auditTimestamp(row.ts), auditTimestamp(row.ts) || auditTimestamp(current.first_seen));
        current.last_seen = Math.max(auditTimestamp(current.last_seen), auditTimestamp(row.ts));
        if (!current.app) current.app = row.app;
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
        if (query.unknownFirst) output = output.slice().sort((a, b) => (/未知|unknown/i.test(`${b.name} ${b.type}`) ? 1 : 0) - (/未知|unknown/i.test(`${a.name} ${a.type}`) ? 1 : 0));
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
        { label: '域名', sort: 'host', render: (row) => auditMainCell(row.host, row.app || row.category || '') },
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
        { label: '应用', sort: 'app', render: (row) => html(row.app || '--') },
        { label: '分类', sort: 'category', render: (row) => html(row.category || '--') },
        { label: '动作', sort: 'action', render: (row) => `<span class="insights-audit-pill ${auditTone(row.action)}">${html(auditActionLabel(row.action))}</span>` },
        { label: '次数', sort: 'hits', className: 'num', render: (row) => html(formatInteger(row.hits)) },
        { label: '流量', sort: 'bytes', className: 'num', render: (row) => html(formatBytes(row.up_bytes + row.down_bytes)) },
        { label: '证据', render: (row) => html(firstText(row.evidence, row.wan, row.method, row.status, '--')) }
      ];
      const stats = [
        { label: 'URL 记录', value: formatInteger(records.length) },
        { label: '独立域名', value: formatInteger(uniqueHosts) },
        { label: '阻断/关注', value: formatInteger(blocked), tone: blocked ? 'warn' : '' },
        { label: '关联流量', value: formatBytes(totalBytes) }
      ];
      return auditWorkbenchMarkup(section, `
        ${auditSearchToolbar(section, controls)}
        ${auditTableMarkup(query.view === 'domains' ? 'URL 域名' : 'URL 审计', query.view === 'domains' ? '按域名聚合的访问记录' : '真实 URL / Host 访问明细', auditCount(source, rows), columns, rows, { title: '没有 URL 审计记录', detail: state.audit.errors[section] ? '后端接口未返回可用数据。' : '当前筛选条件下没有记录。' }, 'url-audit-table', { stats, error: state.audit.errors[section] })}`);
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
        { label: '设备', sort: 'client', render: (row) => auditMainCell(row.client || '--', [row.vendor, row.device_type, row.os].filter(Boolean).join(' / ')) },
        { label: '动作', sort: 'action', render: (row) => `<span class="insights-audit-pill ${auditTone(row.action)}">${html(auditActionLabel(row.action))}</span>` },
        { label: 'IP / MAC', sort: 'ip', render: (row) => auditMainCell(row.ip || '--', row.mac || '') },
        { label: '接口', sort: 'ifname', render: (row) => html(row.ifname || '--') },
        { label: '网络', sort: 'network', render: (row) => html(row.network || '--') },
        { label: '在线时长', sort: 'duration', className: 'num', render: (row) => html(auditDuration(row.duration)) },
        { label: '来源 / 原因', render: (row) => auditMainCell(row.source || '--', row.reason || row.connection || '') }
      ];
      const stats = [
        { label: '事件数', value: formatInteger(rows.length) },
        { label: '上线/续期', value: formatInteger(online), tone: online ? 'good' : '' },
        { label: '离线', value: formatInteger(offline), tone: offline ? 'bad' : '' },
        { label: '漫游', value: formatInteger(roam), tone: roam ? 'warn' : '' }
      ];
      return auditWorkbenchMarkup(section, `
        ${auditSearchToolbar(section, controls)}
        ${auditTableMarkup('终端在线', '设备上线、离线、租约续期和漫游事件', auditCount(auditPayload('onlineRecords'), rows), columns, rows, { title: '没有终端在线记录', detail: state.audit.errors[section] ? '后端接口未返回可用数据。' : '当前筛选条件下没有记录。' }, 'online-record-table', { stats, error: state.audit.errors[section] })}`);
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
        evidence: firstText(row.evidence, row.reason, row.rule),
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
        { label: '应用', sort: 'app', render: (row) => auditMainCell(row.app || '--', row.last_domain || row.evidence || '') },
        { label: '账号 / 状态', sort: 'account', render: (row) => auditMainCell(row.account || '--', `<span>${row.state || '--'}</span>`.replace(/<[^>]+>/g, '')) },
        { label: '终端', sort: 'client', render: (row) => auditMainCell(row.client || '--', [row.device_type, row.os].filter(Boolean).join(' / ')) },
        { label: 'IP / MAC', sort: 'ip', render: (row) => auditMainCell(row.ip || '--', row.mac || '') },
        { label: '心跳', sort: 'heartbeat_count', className: 'num', render: (row) => html(formatInteger(row.heartbeat_count)) },
        { label: '持续时间', sort: 'duration', className: 'num', render: (row) => html(auditDuration(row.duration)) },
        { label: '置信度', sort: 'confidence', className: 'num', render: (row) => html(row.confidence ? auditPercent(row.confidence, 0) : '--') }
      ];
      const stats = [
        { label: '记录数', value: formatInteger(rows.length) },
        { label: '在线状态', value: formatInteger(online), tone: online ? 'good' : '' },
        { label: '后台/离开', value: formatInteger(away), tone: away ? 'warn' : '' },
        { label: '账号数', value: formatInteger(accounts) }
      ];
      return auditWorkbenchMarkup(section, `
        ${auditSearchToolbar(section, controls)}
        ${auditTableMarkup('IM 在线', '即时通讯应用、账号和终端状态', auditCount(auditPayload('imRecords'), rows), columns, rows, { title: '没有 IM 在线记录', detail: state.audit.errors[section] ? '后端接口未返回可用数据。' : '当前筛选条件下没有记录。' }, 'im-record-table', { stats, error: state.audit.errors[section] })}`);
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
          category: firstText(row.category, parts[0], type),
          subcategory: firstText(row.subcategory, parts.slice(1).join('/')),
          connections: firstNumber(row.connections, row.conn_count, row.connection_count),
          up_rate: firstNumber(row.up_rate, row.tx_rate, row.rate_up),
          down_rate: firstNumber(row.down_rate, row.rx_rate, row.rate_down),
          bytes: firstNumber(row.bytes, row.total_bytes, row.traffic_bytes),
          clients: firstNumber(row.clients, row.client_count, row.devices),
          evidence: firstText(row.evidence, row.domain, row.host, row.rule),
          wan: firstText(row.wan, row.ifname, row.interface),
          last_seen: firstNumber(row.last_seen, row.ts, row.time),
          confidence: firstNumber(row.confidence, row.score),
          domains: Array.isArray(row.domains) ? row.domains.join(', ') : firstText(row.domains, row.domain),
          ports: Array.isArray(row.ports) ? row.ports.join(', ') : firstText(row.ports, row.port)
        };
      });
      return auditClientFilterRows(rows, ['name', 'type', 'category', 'subcategory', 'evidence', 'domains', 'ports', 'wan']);
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
      const unknown = rows.filter((row) => /未知|unknown/i.test(`${row.name} ${row.type}`)).length;
      const columns = [
        { label: '名称', sort: 'name', render: (row) => auditMainCell(row.name || '--', row.evidence || row.domains || '') },
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
        { label: query.view === 'apps' ? '应用数' : '协议数', value: formatInteger(rows.length) },
        { label: '连接数', value: formatInteger(totalConnections) },
        { label: '累计流量', value: formatBytes(totalBytes) },
        { label: '未知项', value: formatInteger(unknown), tone: unknown ? 'warn' : '' }
      ];
      return auditWorkbenchMarkup(section, `
        ${auditSearchToolbar(section, controls)}
        ${auditTableMarkup(title, '协议 / 应用识别结果、速率、证据与终端覆盖', rows.length, columns, rows, { title: `没有${query.view === 'apps' ? '应用' : '协议'}审计记录`, detail: state.audit.errors[section] ? '后端接口未返回可用数据。' : '当前筛选条件下没有记录。' }, 'protocol-app-table', { stats, error: state.audit.errors[section] })}`);
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
        { label: '状态', value: status.enabled === false ? '未启用' : status.enabled === true ? '正在记录' : firstText(status.status, '--'), tone: status.enabled === false ? 'bad' : status.enabled === true ? 'good' : '' },
        { label: '保留', value: `${firstText(status.retention_days, status.retention, '--')} 天` },
        { label: '库体积', value: formatBytes(firstNumber(status.db_size_bytes, status.db_bytes)) },
        { label: '丢弃事件', value: formatInteger(firstNumber(status.dropped_events, status.dropped)), tone: firstNumber(status.dropped_events, status.dropped) ? 'warn' : '' }
      ];
      return auditWorkbenchMarkup(section, `
        ${auditSearchToolbar(section, '')}
        ${auditTableMarkup('审计状态', '审计引擎配置、能力与运行状态', rows.length, columns, rows, { title: '没有审计状态数据', detail: state.audit.errors[section] ? '后端接口未返回可用数据。' : '等待 /api/v1/audit/status 返回状态。' }, 'audit-status-table', { stats, error: state.audit.errors[section] })}`);
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
            <div class="insights-activity-board">
              ${activityChartMarkup()}
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

    function render() {
      if (!state.root) return;
      const preservedSearch = preserveActiveSearch();
      if (state.mounted) disposeRenderedMaps(state.root);
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
    }

    function disposeRenderedMaps(root) {
      if (!root) return;
      root.querySelectorAll('[data-insights-echarts-map]').forEach((container) => disposeCyberMap(container));
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
      });
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
      const chartUpdated = patchStableCard(chart, activityChartMarkup(), '[data-insights-activity-card="chart"]');
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

    function bindDom(preservedInput = null) {
      const root = state.root;
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
      root.querySelector('[data-insights-refresh]')?.addEventListener('click', () => refresh({ forceFilters: filtersAreFresh() || hasVisibleFilterDictionary() }));
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
      root.querySelector('[data-map-toggle]')?.addEventListener('change', (event) => {
        state.mapEnabled = Boolean(event.target.checked);
        state.geo = state.mapEnabled ? state.geo : null;
        subscribeInsightsRealtime();
        render();
        if (state.mapEnabled) refresh();
      });
      root.querySelectorAll('[data-map-scope]').forEach((button) => button.addEventListener('click', () => {
        const next = button.dataset.mapScope === 'china' ? 'china' : 'world';
        if (next === state.mapScope) return;
        state.mapScope = next;
        state.geo = null;
        refresh();
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
      root.querySelector('[data-audit-refresh]')?.addEventListener('click', () => refresh());
      root.querySelector('[data-audit-export]')?.addEventListener('click', downloadAuditCsv);
    }

    function scheduleMapRender() {
      if (state.mode !== 'flows' || !state.root) return;
      window.requestAnimationFrame(() => renderVectorMap());
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
          chart.setOption(cyberMapOption(mapName, scope, role, mapView), replace ? true : { notMerge: false, lazyUpdate: true });
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

    function cyberMapOption(mapName, scope, role, mapView) {
      const routes = cyberMapRoutes(role);
      const points = cyberMapPoints(routes);
      const maxPoint = Math.max(1, ...points.map((point) => point.metric));
      const maxRoute = Math.max(1, ...routes.map((route) => route.metric));
      const view = { ...cyberMapView(scope, role), ...(mapView || {}) };
      const localPoints = points.filter((point) => point.local);
      const remotePoints = points.filter((point) => !point.local);
      const routeData = routes.map((route, index) => cyberRouteSeriesItem(route, index, maxRoute));
      return {
        backgroundColor: 'transparent',
        animation: true,
        animationDuration: 620,
        animationDurationUpdate: 420,
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
            lineStyle: { opacity: 0.15, width: 5.5, curveness: 0.28, color: 'rgba(55, 211, 255, 0.50)' },
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
            lineStyle: { opacity: 0.46, width: 1.6, curveness: 0.28, type: 'solid' },
            data: routeData
          },
          {
            id: 'dwrt-traffic-pulse',
            name: 'traffic pulse',
            type: 'lines',
            coordinateSystem: 'geo',
            zlevel: 4,
            silent: false,
            blendMode: 'lighter',
            effect: {
              show: true,
              constantSpeed: role === 'overview' ? 42 : 58,
              trailLength: 0.36,
              symbol: 'circle',
              symbolSize: 5.2,
              color: '#effbff'
            },
            lineStyle: { opacity: 0.26, width: 1.1, curveness: 0.28, color: 'rgba(90,220,255,0.52)' },
            data: routeData.map((item, index) => ({
              ...item,
              effect: {
                show: true,
                period: Math.max(2.2, 4.8 - Math.min(2.1, item.dataInfo.metric / maxRoute * 2.1)),
                delay: (index % 5) * 0.22,
                trailLength: 0.38,
                symbol: 'circle',
                symbolSize: item.dataInfo.direction === 'inbound' ? 5.6 : 4.8,
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
      const current = points.get(key);
      if (current) {
        current.metric += metric;
        current.routeCount += 1;
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
        shortLabel: local ? firstText(point.public_ip, point.ip, point.address, '本机') : label
      });
    }

    function cyberMapRoutes(role) {
      const limit = role === 'overview' ? 8 : CYBER_ROUTE_LIMIT;
      const normalized = mapRouteItems()
        .map((route) => {
          const from = mapCoordinates(route.from);
          const to = mapCoordinates(route.to);
          if (!from || !to || coordinatesEqual(from, to)) return null;
          const metric = Math.max(1, firstNumber(route.bytes, route.total_bytes, route.count, route.flow_count, route.value, 1));
          const direction = String(route.direction || '').toLowerCase() === 'inbound' ? 'inbound' : 'outbound';
          return {
            route,
            from,
            to,
            metric,
            direction,
            label: firstText(route.label, mapPointTitle(route.to), mapPointTitle(route.from), '流量路径')
          };
        })
        .filter(Boolean);
      const grouped = new Map();
      normalized.forEach((route) => {
        const key = `${route.direction}|${route.from.map((value) => Number(value).toFixed(3)).join(',')}|${route.to.map((value) => Number(value).toFixed(3)).join(',')}`;
        const existing = grouped.get(key);
        if (!existing) {
          grouped.set(key, { ...route, route: { ...route.route } });
          return;
        }
        existing.metric += route.metric;
        existing.route.bytes = firstNumber(existing.route.bytes) + firstNumber(route.route.bytes);
        existing.route.total_bytes = firstNumber(existing.route.total_bytes) + firstNumber(route.route.total_bytes);
        existing.route.count = firstNumber(existing.route.count, existing.route.flow_count, 1) + firstNumber(route.route.count, route.route.flow_count, 1);
        existing.route.flow_count = existing.route.count;
      });
      return Array.from(grouped.values())
        .sort((a, b) => b.metric - a.metric)
        .slice(0, limit);
    }

    function cyberPointSeriesItem(point, maxPoint) {
      const value = [point.coords[0], point.coords[1], point.metric];
      return {
        name: point.label,
        value,
        symbolSize: cyberPointSize(point.metric, maxPoint, point.local),
        itemStyle: {
          color: point.local ? '#27f0a8' : cyberMetricColor(point.metric, maxPoint, 'point'),
          shadowBlur: point.local ? 24 : 16,
          shadowColor: point.local ? 'rgba(39,240,168,0.86)' : 'rgba(57,217,255,0.70)',
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
          approximate: isApproximateMapPoint(point.point)
        }
      };
    }

    function cyberRouteSeriesItem(route, index, maxRoute) {
      const inbound = route.direction === 'inbound';
      const color = inbound ? '#ffb25f' : '#38d8ff';
      const packetColor = inbound ? '#ffd49b' : '#eefbff';
      const ratio = Math.max(0.08, Math.min(1, route.metric / maxRoute));
      return {
        name: route.label,
        coords: [route.from, route.to],
        value: route.metric,
        lineStyle: {
          color,
          opacity: 0.38 + ratio * 0.30,
          width: 1.0 + ratio * 2.2,
          curveness: inbound ? -0.31 : 0.31
        },
        dataInfo: {
          type: 'route',
          label: route.label,
          metric: route.metric,
          bytes: firstNumber(route.route.bytes, route.route.total_bytes),
          count: firstNumber(route.route.count, route.route.flow_count),
          direction: route.direction,
          packetColor,
          index
        }
      };
    }

    function cyberPointSize(value, maxPoint, local) {
      const ratio = Math.sqrt(Math.max(1, Number(value) || 1) / Math.max(1, Number(maxPoint) || 1));
      return Math.max(local ? 11 : 6, Math.min(local ? 20 : 18, (local ? 11 : 6) + ratio * (local ? 9 : 12)));
    }

    function cyberMetricColor(value, maxValue, mode) {
      const ratio = Math.max(0, Math.min(1, Number(value || 0) / Math.max(1, Number(maxValue) || 1)));
      if (ratio > 0.78) return '#ff6f83';
      if (ratio > 0.54) return '#ffb45f';
      if (ratio > 0.30) return '#8fffe0';
      return mode === 'point' ? '#39d9ff' : '#38d8ff';
    }

    function cyberMapTooltip(params) {
      const info = params && params.data && params.data.dataInfo;
      if (!info) return '';
      if (info.type === 'route') {
        const metric = info.bytes ? formatBytes(info.bytes) : `${formatInteger(info.count || info.metric)} 条`;
        return `<div class="insights-cyber-tip"><strong>${html(info.direction === 'inbound' ? '入站路径' : '出站路径')}</strong><span>${html(info.label)}</span><b>${html(metric)}</b></div>`;
      }
      const metric = info.bytes ? formatBytes(info.bytes) : `${formatInteger(info.count || info.metric)} 条`;
      return `<div class="insights-cyber-tip"><strong>${html(info.local ? '本机出口' : info.label)}</strong>${info.ip ? `<span>${html(info.ip)}</span>` : ''}<b>${html(metric)}</b>${info.approximate ? '<em>国家/省级坐标，等待 City GeoIP</em>' : ''}</div>`;
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
      refresh();
      return { unmount };
    }

    function unmount() {
      window.clearTimeout(state.refreshTimer);
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
    const classes = [
      'insights-map-point',
      local ? 'is-local' : '',
      isApproximateMapPoint(point) ? 'is-approximate' : ''
    ].filter(Boolean).join(' ');
    const title = mapPointTitle(point);
    const localLabel = local
      ? `<span class="insights-map-point-label">${escapeAttr(point.public_ip || point.ip || point.address || '本机')}</span>`
      : '';
    return `<span class="${classes}" style="--point-x:${x}%;--point-y:${y}%;--point-size:${size}px" title="${escapeAttr(title)}"><i class="insights-map-point-halo"></i><i class="insights-map-point-core"></i>${localLabel}</span>`;
  }

  function mapRouteLayerMarkup(routes) {
    return `<svg class="insights-map-route-layer" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">${mapRouteLayerInnerMarkup(routes)}</svg>`;
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
    const cx = clampPercent((from.x + to.x) / 2 + Math.sign(dx || 1) * Math.min(4, distance * 0.035));
    const cy = clampPercent((from.y + to.y) / 2 - bend * sign);
    const path = `M ${from.x.toFixed(2)} ${from.y.toFixed(2)} Q ${cx.toFixed(2)} ${cy.toFixed(2)} ${to.x.toFixed(2)} ${to.y.toFixed(2)}`;
    const delay = ((index % 7) * 0.24).toFixed(2);
    const metric = Math.max(1, Number(route.count || route.flow_count || route.bytes || 1));
    const width = Math.max(1.15, Math.min(3.2, 1.15 + Math.log10(metric) * 0.42));
    const duration = Math.max(2.4, Math.min(4.8, 4.8 - Math.log10(metric) * 0.34)).toFixed(2);
    const color = inbound ? '#ffb25f' : '#38d8ff';
    const accent = inbound ? '#ffd49b' : '#effbff';
    return `
      <path class="insights-map-route-glow ${inbound ? 'is-inbound' : 'is-outbound'}" d="${path}" pathLength="1" style="--route-width:${(width + 4).toFixed(2)};--route-color:${color};--route-delay:${delay}s"></path>
      <path class="insights-map-route-path ${inbound ? 'is-inbound' : 'is-outbound'}" d="${path}" pathLength="1" style="--route-width:${width.toFixed(2)};--route-color:${color};--route-delay:${delay}s"></path>
      <circle class="insights-map-route-packet primary" r="1.08" style="--route-delay:${delay}s;--packet-color:${accent}">
        <animateMotion dur="${duration}s" begin="${delay}s" repeatCount="indefinite" path="${path}" rotate="auto"></animateMotion>
      </circle>
      <circle class="insights-map-route-packet secondary" r="0.72" style="--route-delay:${delay}s;--packet-color:${color}">
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
    return {
      from,
      to,
      direction: String(route.direction || route.flow_direction || '').toLowerCase(),
      count: route.count || route.flow_count || route.bytes || 1,
      bytes: route.bytes || route.total_bytes || 0,
      label: route.label || route.name || ''
    };
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
