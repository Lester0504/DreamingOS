(() => {
  'use strict';

  const DEFAULT_VERSION = '20260722-07';
  window.DWRTDashboard = {
    create(context = {}) {
      const VERSION = context.version || DEFAULT_VERSION;
      const DASHBOARD_REFRESH_MS = 5000;
      const RATE_HOLD_MS = 9000;
      const APP_TRACK_ENTER_MS = 240;
      const APP_TRACK_MOVE_MS = 240;
      const APP_TRACK_EXIT_MS = 220;
      const APP_TRACK_REMOVE_GRACE_MS = 1400;
      const APP_TRACK_EMPTY_GRACE_MS = 1200;
      const PROBE_POLL_INTERVAL_MS = 700;
      const PROBE_POLL_LIMIT = 10;
      const WAN_REALTIME_WINDOW_SEC = 10 * 60;
      const WAN_REALTIME_MAX_POINTS = 1400;
      const THROUGHPUT_PATCH_MS = 250;
      const MAIN_CHART_SAMPLE_MS = 250;
      const DASHBOARD_HISTORY_ENDPOINT = '/api/v1/dashboard/traffic/history';
      const DASHBOARD_HISTORY_RANGES = [
        { id: 'realtime', label: '实时', windowSec: 2 * 60 },
        { id: '1h', label: '1H', windowSec: 60 * 60 },
        { id: '1d', label: '1D', windowSec: 24 * 60 * 60 },
        { id: '1w', label: '1W', windowSec: 7 * 24 * 60 * 60 },
        { id: '1m', label: '1M', windowSec: 30 * 24 * 60 * 60 }
      ];
      const DASHBOARD_ENDPOINTS = {
        snapshot: '/api/v1/dashboard/snapshot',
        system: '/api/v1/system/status',
        overview: '/api/v1/network/overview',
        wans: '/api/v1/network/wans',
        ports: '/api/v1/network/ports',
        clients: '/api/v1/clients',
        /*
         * Kernel forwarding stats. The dashboard's other endpoints carry no
         * kernel_* fields at all, so the WAN cards' "连接数" was conntrack
         * attribution with nothing to compare it against. This is the shared
         * read-only snapshot; it is not a second source for the same number.
         */
        kernelRuntime: '/api/v1/system/advanced/kernel-runtime'
      };
      const DASHBOARD_RESOURCE_TTL_MS = {
        snapshot: 15000,
        overview: 5000,
        wans: 5000,
        ports: 15000,
        clients: 15000,
        system: 30000,
        kernelRuntime: 15000
      };
      const DASHBOARD_RESOURCE_TIMEOUT_MS = {
        snapshot: 2500,
        system: 2500,
        history: 2500,
        default: 4500
      };
      const DASHBOARD_CRITICAL_RESOURCES = new Set(['overview', 'wans', 'ports', 'clients']);
      const PROBE_TARGETS = [
        { id: 'apple', label: 'Apple', host: 'apple.com' },
        { id: 'baidu', label: 'Baidu', host: 'baidu.com' },
        { id: 'bilibili', label: 'Bilibili', host: 'bilibili.com' },
        { id: 'wechat', label: 'WeChat', host: 'weixin.qq.com' }
      ];
      const $ = (id) => document.getElementById(id);
      const realtime = context.realtime || window.DWRTRealtime;
      const session = context.session || window.DWRT_SESSION;
      /*
       * Shared connection-truth normalizer. conntrack attribution and the JMX
       * kernel gauge are different numbers and must not be merged into one.
       */
      const connTruth = context.connTruth || window.DWRTConnTruth || null;
      const appShell = $('appShell');
      const consoleStage = document.querySelector('.console-stage');
      const routePreview = $('routePreview');
      const dashboardWorkspace = $('dashboardWorkspace');
      const dashboardStatusRail = $('dashboardStatusRail');
      const dashboardMetricGrid = $('dashboardMetricGrid');
      const routerMonitorCard = $('routerMonitorCard');
      const dashboardRankGrid = $('dashboardRankGrid');
      const dashboardActiveUrlCard = $('dashboardActiveUrlCard');
      const scheduleGlassCardsRender = typeof context.scheduleGlassCardsRender === 'function'
        ? context.scheduleGlassCardsRender
        : () => {};
      const shouldDeferRender = typeof context.shouldDeferRender === 'function'
        ? context.shouldDeferRender
        : (scope) => {
          const selection = window.getSelection && window.getSelection();
          return Boolean(selection && !selection.isCollapsed && scope && scope.contains(selection.anchorNode));
        };
      const state = {
        dashboard: {
          active: false,
          loading: false,
          slowLoading: false,
          timer: null,
          batchController: null,
          pollDelayMs: 0,
          resourceBackoffUntil: {},
          resourceBackoffMs: {},
          lastRenderKey: '',
          resourceCache: {},
          probeResults: {},
          trafficHistory: [],
          historyByRange: {},
          chartState: null,
          appTrackKeys: new Set(),
          activeWanId: 'all',
          trafficRange: 'realtime',
          lastModel: null,
          lastNonZeroTraffic: null,
          pendingRealtime: new Map(),
          wanRealtimePoints: new Map(),
          wanRailStructureKey: '',
          realtimeFrameTimer: 0,
          throughputFrameTimer: 0,
          deferredRenderTimer: 0,
          lastWsAt: 0,
          lastThroughputAt: 0,
          lastTrafficSampleAt: 0,
          pendingRealtimeChartUpdate: false,
          wanCounterSamples: new Map(),
          wanHealthSamples: new Map(),
          renderSectionKeys: {},
          appTrackStructureKey: '',
          appTrackEmptyTimer: 0,
          appTrackMissingSince: new Map(),
          appTrackLastApps: new Map(),
          rankStructureKey: '',
          chartHovering: false,
          pendingChartHistory: null,
          realtimeUnsubscribers: []
        }
      };
      let eventsBound = false;

      function clamp(value, min, max) {
        return Math.max(min, Math.min(max, value));
      }

  function setText(id, value) {
    const el = $(id);
    if (el) el.textContent = value === undefined || value === null || value === '' ? '--' : String(value);
  }

  function escapeHtml(value) {
    return String(value === undefined || value === null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function cssAttr(value) {
    return String(value === undefined || value === null ? '' : value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  }

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function textFromUnknown(value, depth = 0) {
    if (value === undefined || value === null) return '';
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value).trim();
    if (Array.isArray(value)) {
      for (const item of value) {
        const text = textFromUnknown(item, depth + 1);
        if (text) return text;
      }
      return '';
    }
    if (typeof value === 'object' && depth < 2) {
      const keys = ['domain', 'host', 'url', 'uri', 'ip', 'dst_host', 'dst_ip', 'name', 'label', 'title', 'value', 'text', 'rule', 'reason', 'evidence'];
      for (const key of keys) {
        if (Object.prototype.hasOwnProperty.call(value, key)) {
          const text = textFromUnknown(value[key], depth + 1);
          if (text) return text;
        }
      }
    }
    return '';
  }

  function firstText(...values) {
    for (const value of values) {
      const text = textFromUnknown(value);
      if (text) return text;
    }
    return '';
  }

  function displayBrandName(value) {
    const text = firstText(value);
    return /^DreamingWrt$/i.test(text) ? 'Dreaming OS' : text;
  }

  function isInternalAppIdLabel(value) {
    const text = firstText(value).trim();
    return Boolean(text) && (
      /^(?:app(?:lication)?[\s#:_-]*)?[+-]?\d+$/i.test(text) ||
      /^0x[0-9a-f]+$/i.test(text)
    );
  }

  function appDisplayName(app, fallback = '') {
    const source = app && typeof app === 'object' ? app : { name: app };
    const candidates = [
      source.app_name,
      source.appname,
      source.application_name,
      source.display_name,
      source.application,
      source.app,
      source.label,
      source.title,
      source.name,
      fallback
    ];
    for (const candidate of candidates) {
      const text = firstText(candidate).trim();
      if (text && !isInternalAppIdLabel(text)) return text;
    }
    return '';
  }

  function firstNumber(...values) {
    for (const value of values) {
      const num = Number(value);
      if (Number.isFinite(num)) return num;
    }
    return 0;
  }

  function firstFiniteNumber(...values) {
    for (const value of values) {
      if (value === undefined || value === null || value === '') continue;
      const num = Number(value);
      if (Number.isFinite(num)) return num;
    }
    return null;
  }

  function positiveNumber(...values) {
    for (const value of values) {
      const num = Number(value);
      if (Number.isFinite(num) && num > 0) return num;
    }
    return 0;
  }

  function rateHoldStore() {
    return state.dashboard.rateHoldCache || (state.dashboard.rateHoldCache = new Map());
  }

  function heldDashboardRate(key, incoming, fallback = 0) {
    const value = Number(incoming);
    const now = Date.now();
    const cache = rateHoldStore();
    if (Number.isFinite(value) && value > 0) {
      cache.set(key, { value, at: now });
      return value;
    }
    const previous = cache.get(key);
    if (previous && now - previous.at <= RATE_HOLD_MS) return previous.value;
    return Number(fallback) || 0;
  }

  function timestampSeconds(value, fallback = Date.now() / 1000) {
    const num = Number(value);
    if (!Number.isFinite(num) || num <= 0) return fallback;
    return num > 1000000000000 ? num / 1000 : num;
  }

  function liveTimestampSeconds(...values) {
    const now = Date.now() / 1000;
    for (const value of values) {
      const num = Number(value);
      if (!Number.isFinite(num) || num <= 0) continue;
      const normalized = timestampSeconds(num, now);
      return Math.abs(normalized - now) < 120 ? now : normalized;
    }
    return now;
  }

  function onlineState(value) {
    if (value === true || value === 1) return true;
    if (value === false || value === 0) return false;
    if (typeof value === 'string') {
      const text = value.trim().toLowerCase();
      if (['true', '1', 'yes', 'up', 'online', 'active', 'connected'].includes(text)) return true;
      if (['false', '0', 'no', 'down', 'offline', 'inactive', 'disconnected'].includes(text)) return false;
    }
    return null;
  }

  function authHeaders(extra) {
    return session?.authHeaders?.(extra) || { ...(extra || {}) };
  }

  function redirectToLogin() {
    return session?.requireLogin?.('access-rejected');
  }

  async function refreshAuthToken() {
    return session?.refresh?.({ force: true, retryRequired: true }) || false;
  }

  function unwrapApiData(payload) {
    if (!payload || typeof payload !== 'object') return {};
    if (payload.data && typeof payload.data === 'object') return payload.data;
    if (payload.body && typeof payload.body === 'object') return payload.body;
    return payload;
  }

  async function fetchDashboardResource(name, url, retry = true, externalSignal = undefined) {
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timeoutMs = name && String(name).startsWith('history:')
      ? DASHBOARD_RESOURCE_TIMEOUT_MS.history
      : DASHBOARD_RESOURCE_TIMEOUT_MS[name] || DASHBOARD_RESOURCE_TIMEOUT_MS.default;
    let timedOut = false;
    let timer = null;
    const armTimeout = () => {
      if (controller && timer === null) timer = window.setTimeout(() => {
        timedOut = true;
        controller.abort();
      }, timeoutMs);
    };
    let unlinkExternal = () => {};
    if (controller && externalSignal) {
      if (externalSignal.aborted) controller.abort();
      else {
        const abort = () => controller.abort();
        externalSignal.addEventListener('abort', abort, { once: true });
        unlinkExternal = () => externalSignal.removeEventListener('abort', abort);
      }
    }
    try {
      const requestUrl = `${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`;
      const doFetch = () => {
        armTimeout();
        return session
        ? session.fetch(requestUrl, {
          credentials: 'same-origin',
          cache: 'no-store',
          signal: controller ? controller.signal : undefined
        }, retry)
        : fetch(requestUrl, {
        credentials: 'same-origin',
        cache: 'no-store',
        headers: authHeaders(),
        signal: controller ? controller.signal : undefined
        });
      };
      const limiter = window.DWRT_API_LIMITER;
      const response = limiter && typeof limiter.run === 'function'
        ? await limiter.run(doFetch, controller ? controller.signal : undefined)
        : await doFetch();
      const text = await response.text();
      let json = {};
      if (text) {
        try {
          json = JSON.parse(text);
        } catch (error) {
          throw new Error(`${name}: invalid json`);
        }
      }
      if (!response.ok || json && json.ok === false) {
        const message = json && json.message || json && json.error && (json.error.message || json.error.code) || `${response.status}`;
        const error = new Error(`${name}: ${message}`);
        error.status = response.status;
        error.payload = json;
        if (!session && response.status === 401 && retry && await refreshAuthToken()) {
          return fetchDashboardResource(name, url, false);
        }
        if (response.status === 401) {
          redirectToLogin();
        }
        throw error;
      }
      return { name, ok: true, data: unwrapApiData(json), raw: json };
    } catch (error) {
      if (error && error.name === 'AbortError') {
        const timeoutError = new Error(`${name}: request timeout after ${timeoutMs}ms`);
        timeoutError.timeout = timedOut;
        timeoutError.cancelled = !timedOut;
        timeoutError.status = 0;
        return { name, ok: false, error: timeoutError };
      }
      return { name, ok: false, error };
    } finally {
      unlinkExternal();
      if (timer) window.clearTimeout(timer);
    }
  }

  async function fetchApiResource(name, url, retry = true) {
    return fetchDashboardResource(name, url, retry);
  }

  function formatUptime(seconds) {
    const total = Math.max(0, Math.floor(Number(seconds) || 0));
    if (!total) return '--';
    const days = Math.floor(total / 86400);
    const hours = Math.floor(total % 86400 / 3600);
    const mins = Math.floor(total % 3600 / 60);
    if (days > 0) return `${days}天 ${hours}小时`;
    if (hours > 0) return `${hours}小时 ${mins}分钟`;
    return `${mins}分钟`;
  }

  function isGlobalIpv6(value) {
    const text = firstText(value).trim().toLowerCase().split('%')[0].split('/')[0];
    return /^[23][0-9a-f]{0,3}:/.test(text);
  }

  function firstGlobalIpv6(...values) {
    const candidates = values.flatMap((value) => Array.isArray(value) ? value : [value]);
    for (const value of candidates) {
      const text = firstText(value).trim();
      if (isGlobalIpv6(text)) return text;
    }
    return '';
  }

  function trustedWanUptime(wan = {}, runtime = {}, systemUptime = 0) {
    const candidates = [
      wan.connected_seconds,
      runtime.connected_seconds,
      wan.online_seconds,
      runtime.online_seconds,
      wan.uptime,
      runtime.uptime
    ];
    const seconds = candidates.map(Number).find((value) => Number.isFinite(value) && value > 0) || 0;
    const limit = Number(systemUptime);
    if (!seconds || (Number.isFinite(limit) && limit > 0 && seconds > limit + 5)) return 0;
    return seconds;
  }

  function formatRate(bytesPerSecond) {
    const value = Math.max(0, Number(bytesPerSecond) || 0) * 8;
    const units = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
    let current = value;
    let index = 0;
    while (current >= 1000 && index < units.length - 1) {
      current /= 1000;
      index += 1;
    }
    const digits = current >= 100 || index === 0 ? 0 : current >= 10 ? 1 : 2;
    return `${current.toFixed(digits).replace(/\.0+$/, '')} ${units[index]}`;
  }

  function formatBytes(bytes) {
    const value = Math.max(0, Number(bytes) || 0);
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let current = value;
    let index = 0;
    while (current >= 1024 && index < units.length - 1) {
      current /= 1024;
      index += 1;
    }
    const digits = current >= 100 || index === 0 ? 0 : current >= 10 ? 1 : 2;
    return `${current.toFixed(digits)} ${units[index]}`;
  }

  function formatLatency(value) {
    const num = Number(value);
    if (!Number.isFinite(num) || num <= 0) return '--';
    return `${Math.round(num)} ms`;
  }

  function formatChartTime(ts, rangeId) {
    const date = new Date(Number(ts) * 1000);
    if (!Number.isFinite(date.getTime())) return '--';
    const common = { hour12: false };
    if (rangeId === 'realtime') {
      return new Intl.DateTimeFormat('zh-CN', { ...common, hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(date);
    }
    if (rangeId === '1h' || rangeId === '1d') {
      return new Intl.DateTimeFormat('zh-CN', { ...common, hour: '2-digit', minute: '2-digit' }).format(date);
    }
    return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit' }).format(date);
  }

  function formatDashboardTooltipTime(ts) {
    const date = new Date(Number(ts) * 1000);
    if (!Number.isFinite(date.getTime())) return '--';
    const pad = (value) => String(value).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  function tooltipMetricNumber(...values) {
    for (const value of values) {
      const num = Number(value);
      if (Number.isFinite(num) && num > 0) return num;
    }
    for (const value of values) {
      const num = Number(value);
      if (Number.isFinite(num)) return num;
    }
    return 0;
  }

  function dashboardChartTicks(rangeId, minTs, maxTs, maxValue, plotWidth = 720, xPad = 0) {
    const span = Math.max(1, maxTs - minTs);
    const usableWidth = Math.max(1, plotWidth - (xPad * 2));
    const xCount = rangeId === 'realtime' ? 6 : 5;
    const xTicks = Array.from({ length: xCount }, (_, index) => {
      const pos = xCount === 1 ? 0 : index / (xCount - 1);
      const x = xPad + (usableWidth * pos);
      return {
        pos: plotWidth > 0 ? x / plotWidth : pos,
        label: formatChartTime(minTs + span * pos, rangeId)
      };
    });
    const yCount = 4;
    const safeMax = Math.max(1, Number(maxValue) || 1);
    const yTicks = Array.from({ length: yCount + 1 }, (_, index) => {
      const pos = index / yCount;
      return {
        pos,
        label: index === 0 ? '0' : formatRate(safeMax * pos)
      };
    });
    return { xTicks, yTicks };
  }

  function formatInteger(value) {
    const num = Number(value);
    if (!Number.isFinite(num)) return '--';
    return new Intl.NumberFormat('zh-CN').format(num);
  }

  function carrierEvidence(wan) {
    if (!wan || typeof wan !== 'object') return '';
    const fields = [
      wan.carrier_key,
      wan.isp_key,
      wan.operator_key,
      wan.operator_code,
      wan.carrier,
      wan.carrier_name,
      wan.isp,
      wan.isp_name,
      wan.operator,
      wan.operator_name,
      wan.provider,
      wan.provider_name,
      wan.note,
      wan.description,
      wan.name,
      wan.ifname,
      wan.device,
      wan.interface,
      wan.port,
      wan.public_ip,
      wan.ip,
      wan.gateway
    ];
    const runtime = wan.runtime && typeof wan.runtime === 'object' ? wan.runtime : {};
    fields.push(
      runtime.carrier_key,
      runtime.isp_key,
      runtime.operator_key,
      runtime.operator_code,
      runtime.carrier,
      runtime.carrier_name,
      runtime.isp,
      runtime.operator,
      runtime.provider,
      runtime.gateway,
      runtime.ipv4
    );
    return fields.map((value) => firstText(value)).filter(Boolean).join(' ');
  }

  function carrierKey(value) {
    const text = String(value || '').toLowerCase();
    if (/unicom|联通|cucc|china\s*unicom/.test(text)) return 'unicom';
    if (/mobile|移动|cmcc|china\s*mobile/.test(text)) return 'mobile';
    if (/telecom|电信|ctcc|china\s*telecom/.test(text)) return 'telecom';
    if (/cernet|教育网|edu/.test(text)) return 'cernet';
    return 'unknown';
  }

  function carrierMeta(wan) {
    const evidence = carrierEvidence(wan);
    const key = carrierKey(evidence);
    const labels = {
      unicom: '中国联通',
      mobile: '中国移动',
      telecom: '中国电信',
      cernet: '教育网',
      unknown: firstText(wan.note, wan.carrier_name, wan.carrier, wan.isp, wan.provider, wan.operator, '运营商未配置')
    };
    const logos = {
      unicom: '/static/images/logo/china-unicom.svg',
      mobile: '/static/images/logo/china-mobile.svg',
      telecom: '/static/images/logo/china-telecom.svg',
      cernet: '/static/images/logo/china-cernet.svg'
    };
    const explicitLogoRaw = firstText(wan.carrier_logo, wan.carrier_svg, wan.logo, wan.image, wan.icon);
    const explicitLogo = window.DWRT_DEVICE_IMAGES?.normalizeUrl?.(explicitLogoRaw) || explicitLogoRaw;
    return { key, label: labels[key] || labels.unknown, logo: explicitLogo || logos[key] || '' };
  }

  function carrierMarkup(wan) {
    const meta = carrierMeta(wan || {});
    if (meta.logo) {
      return `<span class="carrier-mark carrier-mark--${escapeHtml(meta.key)}" title="${escapeHtml(meta.label)}"><img src="${escapeHtml(meta.logo)}" alt="${escapeHtml(meta.label)}"></span>`;
    }
    return `<span class="carrier-mark carrier-mark--unknown" title="${escapeHtml(meta.label)}" aria-label="${escapeHtml(meta.label)}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3 4 7.5v9L12 21l8-4.5v-9L12 3Z"/><path d="M12 12 4.6 7.8"/><path d="M12 12l7.4-4.2"/><path d="M12 12v8.4"/></svg>
    </span>`;
  }

  function mergeDashboardWanInputs(baseRows, liveRows) {
    const base = asArray(baseRows);
    const live = asArray(liveRows);
    if (!live.length) return base;
    if (!base.length) return live;
    const liveByKey = new Map();
    live.forEach((wan, index) => {
      uniqueStrings([wanRealtimeKey(wan, index), wan && wan.id, wan && wan.name, wan && wan.ifname, wan && wan.interface, wan && wan.device], 8)
        .forEach((key) => liveByKey.set(key, { wan, index }));
    });
    const usedLiveIndexes = new Set();
    const merged = base.map((wan, index) => {
      const candidates = uniqueStrings([wanRealtimeKey(wan, index), wan && wan.id, wan && wan.name, wan && wan.ifname, wan && wan.interface, wan && wan.device], 8);
      const matched = candidates.map((key) => liveByKey.get(key)).find(Boolean);
      if (!matched) return wan;
      usedLiveIndexes.add(matched.index);
      const baseRuntime = wan && wan.runtime && typeof wan.runtime === 'object' ? wan.runtime : {};
      const liveRuntime = matched.wan && matched.wan.runtime && typeof matched.wan.runtime === 'object' ? matched.wan.runtime : {};
      const baseConnections = firstFiniteNumber(baseRuntime.connections, wan && wan.connections, wan && wan.conn_count);
      const liveConnections = firstFiniteNumber(liveRuntime.connections, matched.wan && matched.wan.connections, matched.wan && matched.wan.conn_count);
      const baseUptime = trustedWanUptime(wan || {}, baseRuntime);
      const liveUptime = trustedWanUptime(matched.wan || {}, liveRuntime);
      return {
        ...wan,
        ...matched.wan,
        connections: liveConnections > 0 || !(baseConnections > 0) ? liveConnections : baseConnections,
        connected_seconds: liveUptime > 0 ? liveUptime : baseUptime,
        online_seconds: liveUptime > 0 ? liveUptime : baseUptime,
        uptime: liveUptime > 0 ? liveUptime : baseUptime,
        runtime: {
          ...baseRuntime,
          ...liveRuntime,
          connections: liveConnections > 0 || !(baseConnections > 0) ? liveConnections : baseConnections,
          connected_seconds: liveUptime > 0 ? liveUptime : baseUptime,
          online_seconds: liveUptime > 0 ? liveUptime : baseUptime,
          uptime: liveUptime > 0 ? liveUptime : baseUptime
        }
      };
    });
    live.forEach((wan, index) => {
      if (!usedLiveIndexes.has(index)) merged.push(wan);
    });
    return merged;
  }

  function normalizeDashboardData(resources) {
    const get = (name) => resources.find((item) => item.name === name && item.ok)?.data || {};
    const errors = resources.filter((item) => !item.ok);
    const snapshot = get('snapshot');
    const systemData = get('system');
    const overview = get('overview');
    const wansData = get('wans');
    const portsData = get('ports');
    const clientsData = get('clients');
    const kernelRuntimeData = get('kernelRuntime');
    const system = {
      ...(snapshot.system || {}),
      ...(systemData.system || systemData || {})
    };
    const overviewWans = overview.wans && Array.isArray(overview.wans.wans) ? overview.wans.wans : [];
    const snapshotWans = asArray(snapshot.wans);
    const configuredWans = asArray(wansData.wans).length ? asArray(wansData.wans) : overviewWans;
    const wans = mergeDashboardWanInputs(configuredWans, snapshotWans);
    const overviewLans = overview.lans && Array.isArray(overview.lans.lans) ? overview.lans.lans : [];
    const lan = {
      ...(snapshot.lan || {}),
      ...(overviewLans[0] || {})
    };
    return {
      errors,
      system,
      lan,
      wans: wans.map((wan, index) => normalizeWan(wan, index, snapshot.traffic || {}, system.uptime, kernelRuntimeData)),
      kernelRuntime: connTruth ? connTruth.kernelAggregate({
        kernel_stats_available: kernelRuntimeData.available,
        kernel_stats_degraded: kernelRuntimeData.degraded,
        kernel_active_conn_semantics: kernelRuntimeData.active_conn_semantics,
        kernel_active_conn_stale_possible: kernelRuntimeData.active_conn_stale_possible,
        kernel_active_conn_total: kernelRuntimeData.active_conn_total,
        kernel_stats_observed_at: kernelRuntimeData.observed_at,
        kernel_stats_reason: kernelRuntimeData.reason
      }) : null,
      ports: asArray(portsData.ports).map(normalizePort).filter((port) => port.kind !== 'virtual'),
      traffic: snapshot.traffic || {},
      apps: normalizeDashboardApps(dashboardAppInputs(snapshot, clientsData), clientsData),
      activeUrls: normalizeActiveUrls(activeUrlInputs(snapshot, clientsData)),
      ranks: normalizeDashboardRanks(snapshot, clientsData),
      clients: normalizeDashboardClients(snapshot, system, clientsData)
    };
  }

  function dashboardBootModel() {
    const error = new Error('正在读取 dashboard 数据源');
    error.status = 0;
    return normalizeDashboardData([{ name: 'bootstrap', ok: false, error }]);
  }

  function mergeDashboardResources(resources) {
    const cache = state.dashboard.resourceCache || {};
    asArray(resources).forEach((resource) => {
      if (!resource || !resource.name) return;
      if (resource.ok) {
        const previous = cache[resource.name] || {};
        const nextData = resource.name === 'snapshot'
          ? mergeDashboardSnapshotData(previous.data, resource.data)
          : resource.data;
        cache[resource.name] = {
          ...resource,
          data: nextData,
          fetchedAt: Date.now()
        };
      } else if (!cache[resource.name]) {
        cache[resource.name] = {
          ...resource,
          fetchedAt: Date.now()
        };
      } else {
        cache[resource.name] = {
          ...cache[resource.name],
          lastError: resource.error
        };
      }
    });
    state.dashboard.resourceCache = cache;
    return Object.keys(DASHBOARD_ENDPOINTS)
      .map((name) => cache[name])
      .filter(Boolean);
  }

  function mergeObjectShallow(previous, next) {
    if (!previous || typeof previous !== 'object') return next && typeof next === 'object' ? next : previous;
    if (!next || typeof next !== 'object') return previous;
    return { ...previous, ...next };
  }

  function mergeDashboardSnapshotData(previous, next) {
    const prev = previous && typeof previous === 'object' ? previous : {};
    const incoming = next && typeof next === 'object' ? next : {};
    const merged = { ...prev, ...incoming };
    ['system', 'lan', 'traffic', 'dpi', 'audit', 'runtime_diagnostics'].forEach((key) => {
      if (prev[key] || incoming[key]) merged[key] = mergeObjectShallow(prev[key], incoming[key]);
    });
    return merged;
  }

  function wanRealtimeKey(wan, index = 0) {
    return firstText(
      wan && wan.id,
      wan && wan.name,
      wan && wan.ifname,
      wan && wan.interface,
      wan && wan.device,
      `wan${index + 1}`
    );
  }

  function appendWanRealtimePoints(payload, options = {}) {
    const data = payload && typeof payload === 'object' ? payload : {};
    const trustIncomingConnections = options.trustIncomingConnections !== false;
    let rows = asArray(data.wans);
    if (!rows.length) {
      const traffic = data.traffic && typeof data.traffic === 'object' ? data.traffic : data;
      const hasRate = [
        traffic && traffic.down_rate,
        traffic && traffic.rate_down,
        traffic && traffic.rx_rate,
        traffic && traffic.up_rate,
        traffic && traffic.rate_up,
        traffic && traffic.tx_rate
      ].some((value) => value !== undefined && value !== null && value !== '');
      if (hasRate) {
        const id = firstText(traffic.wan_id, traffic.id, traffic.ifname, traffic.interface, state.dashboard.activeWanId, 'wan');
        rows = [{ ...traffic, id, name: firstText(traffic.name, id), ifname: firstText(traffic.ifname, traffic.interface, id) }];
      }
    }
    const ts = liveTimestampSeconds(data.ts, data.updated_at, data.traffic && data.traffic.updated_at);
    if (!rows.length || !ts) return;
    const seen = new Set();
    rows.forEach((wan, index) => {
      if (!wan || typeof wan !== 'object') return;
      const key = wanRealtimeKey(wan, index);
      if (!key) return;
      seen.add(key);
      const downIncoming = firstFiniteNumber(wan.down_rate, wan.rate_down, wan.rx_rate, wan.downRate);
      const upIncoming = firstFiniteNumber(wan.up_rate, wan.rate_up, wan.tx_rate, wan.upRate);
      if (downIncoming === null && upIncoming === null) return;
      if (wan.sample_valid === false || wan.degraded === true && /no_sample|stale|missing|unavailable/.test(firstText(wan.zero_reason, wan.reason).toLowerCase())) return;
      const down = heldDashboardRate(`wan:${key}:down`, downIncoming, downIncoming);
      const up = heldDashboardRate(`wan:${key}:up`, upIncoming, upIncoming);
      const latency = positiveNumber(wan.latency_ms, wan.latency, wan.latency_avg);
      const currentWan = asArray(state.dashboard.lastModel && state.dashboard.lastModel.wans).find((item, itemIndex) => {
        const candidateKeys = uniqueStrings([wanRealtimeKey(item, itemIndex), item && item.id, item && item.name, item && item.ifname, item && item.device], 8);
        return candidateKeys.includes(key);
      });
      const incomingConnections = firstFiniteNumber(wan.connections, wan.conn_count);
      const currentConnections = firstNumber(currentWan && currentWan.connections);
      const connections = trustIncomingConnections && incomingConnections !== null && (incomingConnections > 0 || !(currentConnections > 0))
        ? firstNumber(incomingConnections)
        : currentConnections;
      const point = {
        ts,
        down,
        up,
        latency,
        latencyMax: positiveNumber(wan.latency_max, wan.rtt_max, latency),
        latencyMin: positiveNumber(wan.latency_min, wan.rtt_min, latency),
        connections,
        connectionsMax: firstNumber(wan.connections_max, wan.conn_max, connections)
      };
      const points = state.dashboard.wanRealtimePoints.get(key) || [];
      const last = points[points.length - 1];
      if (last && point.ts - last.ts < MAIN_CHART_SAMPLE_MS / 1000) points[points.length - 1] = { ...point, ts: last.ts };
      else if (!last || last.ts !== point.ts || last.down !== point.down || last.up !== point.up) points.push(point);
      const cutoff = ts - WAN_REALTIME_WINDOW_SEC;
      while (points.length > WAN_REALTIME_MAX_POINTS || (points[0] && points[0].ts < cutoff)) points.shift();
      state.dashboard.wanRealtimePoints.set(key, points);
    });
    Array.from(state.dashboard.wanRealtimePoints.keys()).forEach((key) => {
      if (!seen.has(key)) {
        const points = state.dashboard.wanRealtimePoints.get(key) || [];
        const last = points[points.length - 1];
        if (last && ts - last.ts > WAN_REALTIME_WINDOW_SEC) state.dashboard.wanRealtimePoints.delete(key);
      }
    });
  }

  function rateSampleUnavailable(sample = {}) {
    const reason = firstText(sample.zero_reason, sample.reason).toLowerCase();
    return sample.sample_valid === false
      || sample.degraded === true && /no_sample|stale|missing|unavailable/.test(reason);
  }

  function deriveWanRatesFromCounters(payload) {
    const data = payload && typeof payload === 'object' ? payload : {};
    const rows = asArray(data.wans);
    if (!rows.length) return data;
    const sampledAt = Date.now();
    let derivedCount = 0;
    const wans = rows.map((wan, index) => {
      if (!wan || typeof wan !== 'object') return wan;
      const key = wanRealtimeKey(wan, index);
      const downBytes = firstFiniteNumber(wan.down_bytes, wan.rx_bytes, wan.downBytes);
      const upBytes = firstFiniteNumber(wan.up_bytes, wan.tx_bytes, wan.upBytes);
      if (!key || downBytes === null || upBytes === null) return wan;
      const previous = state.dashboard.wanCounterSamples.get(key);
      state.dashboard.wanCounterSamples.set(key, { downBytes, upBytes, sampledAt });
      if (!rateSampleUnavailable(wan)) return wan;
      const elapsed = previous ? (sampledAt - previous.sampledAt) / 1000 : 0;
      if (!previous || elapsed < 0.2 || elapsed > 30 || downBytes < previous.downBytes || upBytes < previous.upBytes) return wan;
      derivedCount += 1;
      const downRate = Math.max(0, (downBytes - previous.downBytes) / elapsed);
      const upRate = Math.max(0, (upBytes - previous.upBytes) / elapsed);
      return {
        ...wan,
        down_rate: downRate,
        up_rate: upRate,
        sample_valid: true,
        degraded: true,
        zero_reason: downRate || upRate ? '' : 'idle',
        rate_source: 'frontend_counter_delta'
      };
    });
    if (!derivedCount) return data;
    const upRate = wans.reduce((sum, wan) => sum + firstNumber(wan && wan.up_rate), 0);
    const downRate = wans.reduce((sum, wan) => sum + firstNumber(wan && wan.down_rate), 0);
    return {
      ...data,
      wans,
      traffic: {
        ...(data.traffic && typeof data.traffic === 'object' ? data.traffic : {}),
        up_rate: upRate,
        down_rate: downRate,
        sample_valid: true,
        degraded: true,
        zero_reason: upRate || downRate ? '' : 'idle',
        rate_source: 'frontend_counter_delta'
      }
    };
  }

  function normalizeThroughputWan(wan, index = 0) {
    const row = wan && typeof wan === 'object' ? wan : {};
    const id = wanRealtimeKey(row, index);
    return {
      id,
      name: firstText(row.name, row.ifname, id),
      ifname: firstText(row.ifname, row.interface, id),
      device: firstText(row.device, row.runtime_device),
      downRate: heldDashboardRate(`wan:${id}:down`, firstNumber(row.down_rate, row.rate_down, row.rx_rate, row.downRate), firstNumber(row.downRate)),
      upRate: heldDashboardRate(`wan:${id}:up`, firstNumber(row.up_rate, row.rate_up, row.tx_rate, row.upRate), firstNumber(row.upRate)),
      downBytes: firstNumber(row.down_bytes, row.rx_bytes, row.downBytes),
      upBytes: firstNumber(row.up_bytes, row.tx_bytes, row.upBytes),
      latency: positiveNumber(row.latency_ms, row.latency),
      loss: firstNumber(row.loss_pct, row.loss),
      // dashboard.throughput is a rate plane. Per-WAN connection ownership comes
      // from /network/wans or line-load and must not be inferred from this topic.
    };
  }

  function throughputWanRows(payload) {
    const data = payload && typeof payload === 'object' ? payload : {};
    const rows = asArray(data.wans);
    if (data.sample_valid === false || rateSampleUnavailable(data)) return [];
    if (rows.length) return rows.filter((row) => !rateSampleUnavailable(row)).map(normalizeThroughputWan);
    const traffic = data.traffic && typeof data.traffic === 'object' ? data.traffic : data;
    if (!traffic || typeof traffic !== 'object') return [];
    const id = firstText(traffic.wan_id, traffic.id, traffic.ifname, traffic.interface, state.dashboard.activeWanId, 'wan');
    const hasRate = [
      traffic.down_rate,
      traffic.rate_down,
      traffic.rx_rate,
      traffic.up_rate,
      traffic.rate_up,
      traffic.tx_rate
    ].some((value) => value !== undefined && value !== null && value !== '');
    return hasRate ? [normalizeThroughputWan({ ...traffic, id, name: firstText(traffic.name, id), ifname: firstText(traffic.ifname, traffic.interface, id) }, 0)] : [];
  }

  function mergeThroughputIntoLastModel(payload) {
    if (!state.dashboard.lastModel) return null;
    const incoming = throughputWanRows(payload);
    if (!incoming.length) return state.dashboard.lastModel;
    const byKey = new Map();
    incoming.forEach((wan, index) => {
      uniqueStrings([wanRealtimeKey(wan, index), wan.id, wan.name, wan.ifname, wan.device], 8)
        .forEach((key) => byKey.set(key, wan));
    });
    let changed = false;
    const currentWans = asArray(state.dashboard.lastModel.wans);
    const nextWans = currentWans.map((wan, index) => {
      const candidates = uniqueStrings([wanRealtimeKey(wan, index), wan.id, wan.name, wan.ifname, wan.device], 8);
      const live = candidates.map((key) => byKey.get(key)).find(Boolean);
      if (!live) return wan;
      changed = true;
      return {
        ...wan,
        downRate: live.downRate,
        upRate: live.upRate,
        downBytes: live.downBytes || wan.downBytes,
        upBytes: live.upBytes || wan.upBytes,
        latency: live.latency || wan.latency,
        loss: live.loss || wan.loss
      };
    });
    incoming.forEach((live) => {
      const exists = currentWans.some((wan, index) => {
        const candidates = uniqueStrings([wanRealtimeKey(wan, index), wan.id, wan.name, wan.ifname, wan.device], 8);
        return candidates.some((key) => byKey.get(key) === live);
      });
      if (!exists) {
        changed = true;
        nextWans.push(live);
      }
    });
    const totalUp = nextWans.reduce((sum, wan) => sum + firstNumber(wan.upRate), 0);
    const totalDown = nextWans.reduce((sum, wan) => sum + firstNumber(wan.downRate), 0);
    const traffic = {
      ...(state.dashboard.lastModel.traffic || {}),
      up_rate: totalUp || firstNumber(payload && payload.up_rate, payload && payload.traffic && payload.traffic.up_rate),
      down_rate: totalDown || firstNumber(payload && payload.down_rate, payload && payload.traffic && payload.traffic.down_rate),
      ts: liveTimestampSeconds(payload && payload.ts, payload && payload.updated_at, payload && payload.traffic && payload.traffic.updated_at)
    };
    if (!changed && traffic.up_rate === state.dashboard.lastModel.traffic?.up_rate && traffic.down_rate === state.dashboard.lastModel.traffic?.down_rate) {
      return state.dashboard.lastModel;
    }
    state.dashboard.lastModel = {
      ...state.dashboard.lastModel,
      traffic,
      wans: nextWans
    };
    return state.dashboard.lastModel;
  }

  function hasFreshThroughput() {
    return Boolean(state.dashboard.lastThroughputAt && Date.now() - state.dashboard.lastThroughputAt < 2000);
  }

  function preserveFreshThroughput(model) {
    if (!model || !hasFreshThroughput() || !state.dashboard.lastModel) return model;
    const liveWans = asArray(state.dashboard.lastModel.wans);
    if (!liveWans.length) return model;
    const byKey = new Map();
    liveWans.forEach((wan, index) => {
      uniqueStrings([wanRealtimeKey(wan, index), wan.id, wan.name, wan.ifname, wan.device], 8)
        .forEach((key) => byKey.set(key, wan));
    });
    const nextWans = asArray(model.wans).map((wan, index) => {
      const live = uniqueStrings([wanRealtimeKey(wan, index), wan.id, wan.name, wan.ifname, wan.device], 8)
        .map((key) => byKey.get(key)).find(Boolean);
      if (!live) return wan;
      return {
        ...wan,
        upRate: live.upRate,
        downRate: live.downRate,
        upBytes: live.upBytes || wan.upBytes,
        downBytes: live.downBytes || wan.downBytes
      };
    });
    const totalUp = nextWans.reduce((sum, wan) => sum + firstNumber(wan.upRate), 0);
    const totalDown = nextWans.reduce((sum, wan) => sum + firstNumber(wan.downRate), 0);
    return {
      ...model,
      wans: nextWans,
      traffic: {
        ...(model.traffic || {}),
        up_rate: totalUp,
        down_rate: totalDown,
        ts: firstNumber(state.dashboard.lastModel.traffic?.ts, model.traffic?.ts)
      }
    };
  }

  function latestDashboardPoint(model) {
    const fallbackModel = model || state.dashboard.lastModel || {};
    const traffic = fallbackModel.traffic || {};
    const wans = asArray(fallbackModel.wans);
    const wanId = selectedDashboardWanId();
    const activeWan = wanId === 'all' ? wans[0] || {} : wans.find((wan) => wan.id === wanId) || {};
    const points = visibleTrafficPoints('realtime', wanId).points;
    const latest = points[points.length - 1];
    if (latest) {
      const latency = positiveNumber(latest.latency, activeWan.latency, traffic.latency_ms, traffic.latency);
      return {
        ...latest,
        latency,
        latencyMax: positiveNumber(latest.latencyMax, latency),
        latencyMin: positiveNumber(latest.latencyMin, latency)
      };
    }
    return {
      up: wanId === 'all' ? firstNumber(traffic.up_rate, traffic.tx_rate) : firstNumber(activeWan.upRate),
      down: wanId === 'all' ? firstNumber(traffic.down_rate, traffic.rx_rate) : firstNumber(activeWan.downRate),
      latency: positiveNumber(activeWan.latency, traffic.latency_ms, traffic.latency),
      latencyMax: positiveNumber(activeWan.latency, traffic.latency_ms, traffic.latency),
      latencyMin: positiveNumber(activeWan.latency, traffic.latency_ms, traffic.latency),
      connections: wanId === 'all'
        ? firstNumber(fallbackModel.system && fallbackModel.system.connections)
        : firstNumber(activeWan.connections),
      connectionsMax: wanId === 'all'
        ? firstNumber(fallbackModel.system && fallbackModel.system.connections)
        : firstNumber(activeWan.connections)
    };
  }

  function normalizeRealtimeResource(topic, data) {
    const payload = data && typeof data === 'object' ? data : {};
    if (topic === 'dashboard.metrics') return { name: 'snapshot', ok: true, data: payload };
    if (topic === 'clients.metrics') {
      return {
        name: 'clients',
        ok: true,
        data: payload.clients || payload.users || payload.list || payload.items ? payload : { clients: asArray(payload) }
      };
    }
    if (topic === 'apps.metrics') {
      const current = state.dashboard.resourceCache.snapshot && state.dashboard.resourceCache.snapshot.data || {};
      return {
        name: 'snapshot',
        ok: true,
        data: {
          apps: payload.apps || payload.items || payload.list || current.apps,
          online_apps: payload.online_apps || payload.active_apps || current.online_apps,
          active_apps: payload.active_apps || payload.apps || current.active_apps,
          top_apps: payload.top_apps || payload.rank || payload.top || current.top_apps,
          active_urls: payload.active_urls || payload.urls || current.active_urls,
          active_hosts: payload.active_hosts || payload.hosts || current.active_hosts,
          dpi: {
            ...(current.dpi || {}),
            ...(payload.dpi || {}),
            apps: payload.apps || payload.items || payload.list || payload.dpi?.apps || current.dpi?.apps,
            active_urls: payload.active_urls || payload.urls || payload.dpi?.active_urls || current.dpi?.active_urls,
            active_hosts: payload.active_hosts || payload.hosts || payload.dpi?.active_hosts || current.dpi?.active_hosts
          }
        }
      };
    }
    return null;
  }

  function hasPositiveRateValue(...values) {
    return values.some((value) => Number.isFinite(Number(value)) && Number(value) > 0);
  }

  function stabilizeDashboardRates(model) {
    if (!model || typeof model !== 'object') return model;
    const traffic = model.traffic || {};
    const wans = asArray(model.wans);
    const trafficUpRaw = firstNumber(traffic.up_rate, traffic.tx_rate) || wans.reduce((sum, wan) => sum + firstNumber(wan.upRate), 0);
    const trafficDownRaw = firstNumber(traffic.down_rate, traffic.rx_rate) || wans.reduce((sum, wan) => sum + firstNumber(wan.downRate), 0);
    const nextWans = wans.map((wan, index) => {
      const key = firstText(wan.id, wan.name, wan.ifname, `wan${index + 1}`);
      return {
        ...wan,
        upRate: heldDashboardRate(`wan:${key}:up`, firstNumber(wan.upRate), wan.upRate),
        downRate: heldDashboardRate(`wan:${key}:down`, firstNumber(wan.downRate), wan.downRate)
      };
    });
    const nextTraffic = {
      ...traffic,
      up_rate: heldDashboardRate('traffic:up', trafficUpRaw, traffic.up_rate),
      down_rate: heldDashboardRate('traffic:down', trafficDownRaw, traffic.down_rate)
    };
    const changed = nextTraffic.up_rate !== traffic.up_rate || nextTraffic.down_rate !== traffic.down_rate
      || nextWans.some((wan, index) => wan.upRate !== wans[index]?.upRate || wan.downRate !== wans[index]?.downRate);
    if (!changed) return model;
    return { ...model, traffic: nextTraffic, wans: nextWans };
  }

  function applyDashboardRealtime(topic, data) {
    if (!state.dashboard.active) return;
    const payload = topic === 'dashboard.metrics' ? deriveWanRatesFromCounters(data) : data;
    if (topic === 'dashboard.metrics' && !hasFreshThroughput()) appendWanRealtimePoints(payload);
    const resource = normalizeRealtimeResource(topic, payload);
    if (!resource) return;
    state.dashboard.lastWsAt = Date.now();
    state.dashboard.pendingRealtime.set(topic, resource);
    if (state.dashboard.realtimeFrameTimer) return;
    state.dashboard.realtimeFrameTimer = window.setTimeout(() => {
      state.dashboard.realtimeFrameTimer = 0;
      if (!state.dashboard.active || !state.dashboard.pendingRealtime.size) return;
      const resources = Array.from(state.dashboard.pendingRealtime.values());
      state.dashboard.pendingRealtime.clear();
      const model = stabilizeDashboardRates(normalizeDashboardData(mergeDashboardResources(resources)));
      renderDashboardCard(model);
    }, document.hidden ? 500 : 180);
  }

  function applyDashboardThroughputRealtime(data) {
    if (!state.dashboard.active) return;
    if (!throughputWanRows(data).length) {
      state.dashboard.lastWsAt = Date.now();
      state.dashboard.lastThroughputAt = 0;
      return;
    }
    appendWanRealtimePoints(data, { trustIncomingConnections: false });
    state.dashboard.lastWsAt = Date.now();
    state.dashboard.lastThroughputAt = Date.now();
    const model = mergeThroughputIntoLastModel(data);
    if (!model) return;
    if (appendTrafficSample(model, { live: true })) state.dashboard.pendingRealtimeChartUpdate = true;
    if (state.dashboard.throughputFrameTimer) return;
    state.dashboard.throughputFrameTimer = window.setTimeout(() => {
      state.dashboard.throughputFrameTimer = 0;
      if (!state.dashboard.active || !state.dashboard.lastModel) return;
      patchDashboardThroughputRealtime(state.dashboard.lastModel);
    }, document.hidden ? 500 : THROUGHPUT_PATCH_MS);
  }

  function applyDashboardWanMetrics(data) {
    if (!state.dashboard.active) return;
    const envelope = data && typeof data === 'object' && !Array.isArray(data) ? data : {};
    const rows = Array.isArray(data) ? data : asArray(envelope.wans || envelope.items || envelope.list);
    if (!rows.length) return;
    rows.forEach((wan, index) => {
      if (!wan || typeof wan !== 'object') return;
      const key = wanRealtimeKey(wan, index);
      if (key) state.dashboard.wanHealthSamples.set(key, wan);
    });
    if (!state.dashboard.lastModel) return;
    const nextWans = asArray(state.dashboard.lastModel.wans).map((wan, index) => {
      const health = state.dashboard.wanHealthSamples.get(wanRealtimeKey(wan, index));
      if (!health) return wan;
      return {
        ...wan,
        latency: positiveNumber(health.latency_ms, health.latency, wan.latency),
        loss: firstNumber(health.loss_pct, health.loss, wan.loss),
        connections: firstNumber(health.connections, health.conn_count) > 0
          ? firstNumber(health.connections, health.conn_count)
          : firstNumber(wan.connections),
        uptime: trustedWanUptime(health, health.runtime || {}, 0) || wan.uptime,
        history: asArray(health.health_history || health.status_history || health.history).length
          ? asArray(health.health_history || health.status_history || health.history)
          : wan.history
      };
    });
    state.dashboard.lastWsAt = Date.now();
    state.dashboard.lastModel = { ...state.dashboard.lastModel, wans: nextWans };
    if (!ensureMonitorShell()) return;
    renderMonitorMetrics(latestDashboardPoint(state.dashboard.lastModel));
    renderMonitorAvailability(nextWans);
    updateWanRailRealtime(nextWans);
  }

  function subscribeDashboardRealtime() {
    if (state.dashboard.realtimeUnsubscribers.length || !realtime || typeof realtime.subscribe !== 'function') return;
    state.dashboard.realtimeUnsubscribers = [
      realtime.subscribe('dashboard.throughput', (data) => applyDashboardThroughputRealtime(data)),
      realtime.subscribe('dashboard.metrics', (data) => applyDashboardRealtime('dashboard.metrics', data)),
      realtime.subscribe('wan.metrics', (data) => applyDashboardWanMetrics(data)),
      realtime.subscribe('clients.metrics', (data) => applyDashboardRealtime('clients.metrics', data)),
      realtime.subscribe('apps.metrics', (data) => applyDashboardRealtime('apps.metrics', data))
    ];
  }

  function unsubscribeDashboardRealtime() {
    state.dashboard.realtimeUnsubscribers.forEach((unsubscribe) => unsubscribe && unsubscribe());
    state.dashboard.realtimeUnsubscribers = [];
  }

  function dashboardResourceEntriesDue(force = false) {
    const cache = state.dashboard.resourceCache || {};
    const backoff = state.dashboard.resourceBackoffUntil || {};
    const now = Date.now();
    return Object.entries(DASHBOARD_ENDPOINTS).filter(([name]) => {
      // 超时退避:刚超时/失败的端点先歇一会,别每个 tick 都重打一个已经卡住的后端。
      if (backoff[name] && now < backoff[name] && cache[name]) return false;
      if (force || !cache[name]) return true;
      const ttl = DASHBOARD_RESOURCE_TTL_MS[name] || DASHBOARD_REFRESH_MS;
      return now - (cache[name].fetchedAt || 0) >= ttl;
    });
  }

  function noteDashboardResourceResult(resource, elapsedMs) {
    if (!resource || !resource.name) return;
    const backoff = state.dashboard.resourceBackoffUntil || (state.dashboard.resourceBackoffUntil = {});
    if (resource.ok) {
      delete backoff[resource.name];
      return;
    }
    if (resource.error && resource.error.cancelled) return;
    const slow = resource.error && resource.error.timeout;
    const base = DASHBOARD_RESOURCE_TTL_MS[resource.name] || DASHBOARD_REFRESH_MS;
    const previous = state.dashboard.resourceBackoffMs?.[resource.name] || 0;
    const next = Math.min(60000, Math.max(slow ? base * 2 : base, previous * 2));
    (state.dashboard.resourceBackoffMs || (state.dashboard.resourceBackoffMs = {}))[resource.name] = next;
    backoff[resource.name] = Date.now() + next;
    void elapsedMs;
  }

  // 顺序小并发地取数,避免每 5 秒向单线程后端同时轰 4-6 个请求造成排队拥塞。
  async function fetchDashboardResourcesQueued(entries, signal, concurrency = 2) {
    const queue = entries.slice();
    const results = [];
    const worker = async () => {
      while (queue.length) {
        if (signal && signal.aborted) return;
        const [name, url] = queue.shift();
        const startedAt = Date.now();
        const resource = await fetchDashboardResource(name, url, true, signal);
        noteDashboardResourceResult(resource, Date.now() - startedAt);
        results.push(resource);
      }
    };
    await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, entries.length)) }, worker));
    return results;
  }

  function normalizeDashboardClients(snapshot, system, clientsData = {}) {
    const clientEnvelope = clientsData.clients || clientsData.users || clientsData.list || clientsData.items || clientsData;
    const users = dashboardListFrom(clientEnvelope).length
      ? dashboardListFrom(clientEnvelope)
      : asArray(snapshot.clients_list || snapshot.clients_detail || snapshot.users || snapshot.online_clients);
    const hasExplicitOnlineState = users.some((user) => user && typeof user === 'object' && onlineState(user.online) !== null);
    const onlineTotal = hasExplicitOnlineState
      ? users.filter((user) => user && typeof user === 'object' && onlineState(user.online) === true).length
      : null;
    const total = onlineTotal !== null ? onlineTotal : firstNumber(
      clientsData.online,
      clientsData.online_count,
      snapshot.online_clients_count,
      snapshot.online_clients,
      system.online_clients,
      system.online_client_count,
      snapshot.clients,
      snapshot.client_count,
      system.clients,
      system.client_count
    );
    const wifiValue = firstNumber(
      snapshot.wifi_clients,
      snapshot.wifi_client_count,
      snapshot.wireless_clients,
      snapshot.wireless_client_count,
      snapshot.clients_by_access && snapshot.clients_by_access.wifi
    );
    const hasWifiValue = [
      snapshot.wifi_clients,
      snapshot.wifi_client_count,
      snapshot.wireless_clients,
      snapshot.wireless_client_count,
      snapshot.clients_by_access && snapshot.clients_by_access.wifi
    ].some((value) => value !== undefined && value !== null && value !== '');
    const explicitWifiUnsupported = snapshot.wifi_supported === false || snapshot.wireless_supported === false;
    const wifiSupported = !explicitWifiUnsupported && (
      snapshot.wifi_supported === true ||
      snapshot.wireless_supported === true ||
      (hasWifiValue && wifiValue > 0)
    );
    return {
      total,
      users,
      wifi: hasWifiValue ? wifiValue : null,
      wifiSupported
    };
  }

  function dashboardListFrom(value) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    return asArray(value.list || value.items || value.apps || value.clients || value.users || value.data);
  }

  function activeUrlInputs(snapshot = {}, clientsData = {}) {
    const inputs = [];
    [
      snapshot.active_urls,
      snapshot.active_url,
      snapshot.urls,
      snapshot.url_audit && snapshot.url_audit.records,
      snapshot.audit && snapshot.audit.urls,
      snapshot.dpi && snapshot.dpi.active_urls
    ].forEach((source) => inputs.push(...dashboardListFrom(source)));

    [
      snapshot.active_hosts,
      snapshot.active_host,
      snapshot.hosts,
      snapshot.dpi && snapshot.dpi.active_hosts
    ].forEach((source) => {
      dashboardListFrom(source).forEach((row) => inputs.push(row));
    });

    dashboardListFrom(clientsData.clients || clientsData.users || clientsData.list || clientsData.items || clientsData).forEach((client) => {
      const clientApps = dashboardListFrom(client && (client.apps || client.applist || client.app_list || client.active_apps));
      clientApps.forEach((app) => {
        const value = firstText(app && (app.url || app.domain || app.host || app.dst_host || app.ip || app.dst_ip));
        if (!value) return;
        inputs.push({
          ...(app && typeof app === 'object' ? app : {}),
          url: value,
          app: appDisplayName(app),
          client: firstText(client.display_name, client.nickname, client.hostname, client.name, client.mac, client.ip),
          client_ip: firstText(client.ip, client.ipv4, client.ipaddr),
          client_mac: firstText(client.mac)
        });
      });
    });
    return inputs;
  }

  function looksLikeUrl(value) {
    const text = firstText(value);
    return /^https?:\/\//i.test(text) || /^[\w.-]+\.[a-z]{2,}(?::\d+)?(\/|$)/i.test(text);
  }

  function normalizeActiveUrls(rawUrls) {
    const byKey = new Map();
    dashboardListFrom(rawUrls).forEach((source, index) => {
      const row = source && typeof source === 'object' ? source : { url: source };
      const url = firstText(row.url, row.full_url, row.uri, row.host, row.domain, row.dst_host, row.ip, row.dst_ip);
      if (!url || !looksLikeUrl(url)) return;
      const client = firstText(row.client, row.client_name, row.hostname, row.device_name, row.src_name);
      const normalized = {
        id: firstText(row.id, row.key, `${url}-${client || index}`),
        url,
        app: firstText(row.app, row.app_name, row.appname, row.application, row.dpi_app),
        category: firstText(row.category, row.type),
        client,
        ip: firstText(row.client_ip, row.src_ip, row.ip),
        mac: firstText(row.client_mac, row.mac, row.src_mac),
        wan: firstText(row.wan, row.ifname, row.line),
        method: firstText(row.method),
        status: firstText(row.status, row.http_status),
        action: firstText(row.action, row.policy),
        evidence: firstText(row.evidence, row.rule, row.reason),
        ts: firstNumber(row.ts, row.time, row.timestamp),
        upBytes: firstNumber(row.up_bytes, row.tx_bytes),
        downBytes: firstNumber(row.down_bytes, row.rx_bytes),
        duration: firstNumber(row.duration, row.seconds, row.active_seconds)
      };
      const key = `${normalized.url}|${normalized.client}|${normalized.ip}`;
      const current = byKey.get(key);
      if (!current || normalized.ts > current.ts) byKey.set(key, normalized);
    });
    return Array.from(byKey.values())
      .sort((a, b) => (b.ts || 0) - (a.ts || 0))
      .slice(0, 24);
  }

  function dashboardAppInputs(snapshot = {}, clientsData = {}) {
    const inputs = [];
    [
      snapshot.apps,
      snapshot.online_apps,
      snapshot.active_apps,
      snapshot.active_app,
      snapshot.activeApps,
      snapshot.dpi_apps,
      snapshot.dpi && snapshot.dpi.apps
    ].forEach((source) => inputs.push(...dashboardListFrom(source)));

    [
      snapshot.active_urls,
      snapshot.active_hosts,
      snapshot.active_url,
      snapshot.active_host
    ].forEach((source) => {
      dashboardListFrom(source).forEach((row) => {
        if (!row || typeof row !== 'object') return;
        const appId = firstText(row.app_id, row.appid, row.dpi_id, row.proto_id);
        const appName = appDisplayName({
          ...row,
          app_name: firstText(row.app_name, row.appname),
          application: firstText(row.application, row.dpi_app, row.app)
        });
        if (!appId && !appName) return;
        inputs.push({
          id: appId || appName,
          name: appName || appId,
          icon: row.icon || row.icon_url || row.icon_file || row.app_icon,
          domain: firstText(row.host, row.domain, row.url, row.dst_host),
          ip: firstText(row.ip, row.dst_ip),
          duration: firstNumber(row.duration, row.seconds, row.active_seconds),
          down_rate: firstNumber(row.down_rate, row.rate_down),
          up_rate: firstNumber(row.up_rate, row.rate_up),
          devices: [{
            name: firstText(row.hostname, row.client_name, row.device_name, row.mac, row.ip),
            mac: firstText(row.mac, row.client_mac),
            ip: firstText(row.ip, row.src_ip, row.client_ip)
          }]
        });
      });
    });

    const clients = dashboardListFrom(clientsData.clients || clientsData.users || clientsData.list || clientsData.items || clientsData);
    clients.forEach((client) => {
      const apps = dashboardListFrom(client && (client.apps || client.applist || client.app_list || client.active_apps));
      apps.forEach((app) => {
        inputs.push({
          ...(app && typeof app === 'object' ? app : { name: app }),
          devices: [{
            name: firstText(client.display_name, client.nickname, client.hostname, client.name, client.mac, client.ip),
            mac: firstText(client.mac),
            ip: firstText(client.ip, client.ipv4, client.ipaddr)
          }]
        });
      });
    });
    return inputs;
  }

  function normalizeAppIconPath(icon) {
    if (Array.isArray(icon)) {
      for (const item of icon) {
        const resolved = normalizeAppIconPath(item);
        if (resolved) return resolved;
      }
      return '';
    }
    const text = firstText(icon);
    if (!text) return '';
    if (/^(https?:)?\/\//i.test(text)) return text;
    const shared = window.DWRT_DEVICE_IMAGES;
    if (shared && typeof shared.normalizeUrl === 'function') {
      const normalized = shared.normalizeUrl(text);
      if (normalized !== text || normalized.startsWith('/static/images/logo/')) return normalized;
    }
    if (text.startsWith('/static/images/logo/')) return text;
    if (text.startsWith('/')) {
      const legacy = text.match(/^\/(?:luci-static\/(?:dreamingwrt\/dashboard\/assets|resources)\/app_icons|static\/images\/brand-logos)\/(.+)$/i);
      if (!legacy) return text;
      const legacyFile = legacy[1].split(/[?#]/)[0].split('/').pop();
      return legacyFile ? `/static/images/logo/${encodeURIComponent(legacyFile)}` : '';
    }
    const candidates = text.split(',').map((item) => item.trim()).filter(Boolean);
    if (candidates.length > 1) return normalizeAppIconPath(candidates);
    const file = text.split(/[?#]/)[0].split('/').pop();
    if (!/\.(svg|png|jpe?g|webp|gif)$/i.test(file || '')) return '';
    return file ? `/static/images/logo/${encodeURIComponent(file)}` : '';
  }

  function appDisplayKey(app) {
    const id = firstText(app.id, app.app_id, app.appid, app.proto_id, app.dpi_id);
    if (id && !/^(0|unknown|active)$/i.test(id)) return `id:${id.toLowerCase()}`;
    return `name:${firstText(app.name, app.appname, app.app_name, app.label).toLowerCase()}`;
  }

  function isDisplayableApp(app) {
    const name = firstText(app.name);
    if (!name || isInternalAppIdLabel(name)) return false;
    return !/^(unknown|active|0|未识别应用|未知应用|未知|其他|其它)$/i.test(name);
  }

  function uniqueStrings(values, limit = 8) {
    const seen = new Set();
    const out = [];
    values.forEach((value) => {
      const text = firstText(value);
      if (!text || seen.has(text)) return;
      seen.add(text);
      out.push(text);
    });
    return out.slice(0, limit);
  }

  function isIpAddress(value) {
    const text = firstText(value).split('/')[0].trim();
    if (!text) return false;
    if (text.includes(':')) return /^[0-9a-f:]+$/i.test(text);
    const parts = text.split('.');
    return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
  }

  function clientRowsFromData(clientsData = {}) {
    return dashboardListFrom(clientsData.clients || clientsData.users || clientsData.list || clientsData.items || clientsData);
  }

  function clientByMac(clientsData = {}) {
    return new Map(clientRowsFromData(clientsData).map((client) => [firstText(client.mac).toLowerCase(), client]).filter(([mac]) => mac));
  }

  function normalizeAppDevice(device) {
    if (!device) return null;
    if (typeof device !== 'object') {
      const text = firstText(device);
      if (!text) return null;
      return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(text) ? { name: text, ip: '', mac: text } : { name: text, ip: isIpAddress(text) ? text : '', mac: '' };
    }
    const mac = firstText(device.mac, device.client_mac, device.device_mac, device.src_mac);
    const ip = firstText(device.src_ip, device.client_ip, device.ip, device.ipv4, device.ipaddr);
    const name = firstText(device.name, device.hostname, device.display_name, device.nickname, mac, ip);
    if (!name && !ip && !mac) return null;
    return { name, ip, mac };
  }

  function enrichAppDevice(device, clientsByMac) {
    const normalized = normalizeAppDevice(device);
    if (!normalized) return null;
    const client = clientsByMac && clientsByMac.get(normalized.mac.toLowerCase());
    if (!client) return normalized;
    return {
      name: firstText(client.display_name, client.nickname, client.hostname, client.name, normalized.name, normalized.mac, normalized.ip),
      ip: firstText(client.ip, client.ipv4, client.ipaddr, normalized.ip),
      mac: firstText(client.mac, normalized.mac)
    };
  }

  function normalizeClientRankItem(source, index) {
    const client = source && typeof source === 'object' ? source : { name: source };
    const online = onlineState(client.online);
    const name = firstText(client.display_name, client.nickname, client.hostname, client.name, client.mac, client.ip, `client-${index + 1}`);
    const idForRate = firstText(client.id, client.mac, client.ip, client.name, `client-${index + 1}`);
    const upRate = heldDashboardRate(`client:${idForRate}:up`, firstNumber(client.up_rate, client.rate_up, client.tx_rate));
    const downRate = heldDashboardRate(`client:${idForRate}:down`, firstNumber(client.down_rate, client.rate_down, client.rx_rate));
    const upBytes = firstNumber(client.up_bytes, client.tx_bytes, client.bytes_up);
    const downBytes = firstNumber(client.down_bytes, client.rx_bytes, client.bytes_down);
    const deviceImage = window.DWRT_DEVICE_IMAGES?.resolve?.(client) || {};
    return {
      id: firstText(client.id, client.mac, client.ip, name),
      name,
      ip: firstText(client.ip, client.ipv4, client.ipaddr),
      mac: firstText(client.mac),
      online,
      upRate,
      downRate,
      upBytes,
      downBytes,
      totalBytes: firstNumber(client.bytes, client.total_bytes) || upBytes + downBytes,
      connections: firstNumber(client.connections, client.conn_count),
      detail: firstText(client.vendor, client.vendor_name, client.type, client.device_type, client.interface, client.network),
      image: firstText(client.effective_image, client.detected_image, client.image_url, client.image, deviceImage.src),
      imageKind: firstText(deviceImage.kind),
      apps: dashboardListFrom(client.apps || client.applist || client.app_list || client.active_apps)
    };
  }

  function enrichClientRankSource(source, clientsByMac) {
    if (!source || typeof source !== 'object') return source;
    const client = clientsByMac.get(firstText(source.mac, source.client_mac).toLowerCase());
    if (!client) return source;
    const merged = {
      ...client,
      ...source,
      fingerprint: {
        ...(client.fingerprint && typeof client.fingerprint === 'object' ? client.fingerprint : {}),
        ...(source.fingerprint && typeof source.fingerprint === 'object' ? source.fingerprint : {})
      }
    };
    merged.custom_image_path = firstText(source.custom_image_path, client.custom_image_path);
    merged.custom_icon = firstText(source.custom_icon, client.custom_icon);
    merged.effective_image = firstText(source.effective_image, client.effective_image);
    merged.detected_image = firstText(source.detected_image, client.detected_image);
    merged.image_url = firstText(source.image_url, client.image_url);
    merged.image = firstText(source.image, client.image);
    merged.fingerprint.image = firstText(source.fingerprint?.image, client.fingerprint?.image);
    merged.fingerprint.web_image = firstText(source.fingerprint?.web_image, client.fingerprint?.web_image);
    return merged;
  }

  function normalizeAppDevicesFrom(app) {
    const direct = [
      ...asArray(app.devices),
      ...asArray(app.device),
      ...asArray(app.clients_detail),
      ...asArray(app.client_devices)
    ];
    const inline = normalizeAppDevice({
      name: firstText(app.client_name, app.hostname, app.device_name, app.display_name, app.src_name),
      mac: firstText(app.client_mac, app.mac, app.src_mac, app.device_mac),
      ip: firstText(app.src_ip, app.client_ip, app.ipv4, app.ipaddr)
    });
    const devices = direct.map(normalizeAppDevice).filter(Boolean);
    if (inline) devices.push(inline);
    const byKey = new Map();
    devices.forEach((device) => {
      const key = firstText(device.mac, device.ip, device.name).toLowerCase();
      if (!key || byKey.has(key)) return;
      byKey.set(key, device);
    });
    return Array.from(byKey.values());
  }

  function normalizeAppEvidence(app) {
    return uniqueStrings([
      app.evidence,
      app.domain,
      app.host,
      app.url,
      app.dst_host,
      app.dst_ip,
      app.ip,
      ...asArray(app.evidence).map((item) => firstText(item.value, item.domain, item.host, item.url, item.dst_ip, item.ip, item)),
      ...asArray(app.domains || app.hosts || app.rules).map((item) => firstText(item.domain, item.host, item.url, item.value, item.ip, item))
    ], 8);
  }

  function normalizeAppRankItem(source, index) {
    const app = source && typeof source === 'object' ? source : { name: source };
    const id = firstText(app.appid, app.app_id, app.id, app.key, app.proto_id, app.dpi_id, app.name, `app-${index + 1}`);
    const name = appDisplayName(app);
    const icon = normalizeAppIconPath([
      app.icon_url,
      app.icon,
      app.icon_path,
      app.icon_file,
      app.app_icon,
      app.logo,
      app.logo_url,
      app.image,
      app.signature_icon,
      app.icon_candidates,
      app.icons
    ]);
    const upRate = heldDashboardRate(`app:${id}:up`, firstNumber(app.up_rate, app.rate_up, app.tx_rate));
    const downRate = heldDashboardRate(`app:${id}:down`, firstNumber(app.down_rate, app.rate_down, app.rx_rate));
    const upBytes = firstNumber(app.up_bytes, app.tx_bytes, app.bytes_up);
    const downBytes = firstNumber(app.down_bytes, app.rx_bytes, app.bytes_down);
    const devices = normalizeAppDevicesFrom(app);
    const normalized = {
      id,
      name,
      icon,
      category: firstText(app.category, app.category_name, app.type, app.group),
      upRate,
      downRate,
      upBytes,
      downBytes,
      totalBytes: firstNumber(app.bytes, app.total_bytes) || upBytes + downBytes,
      connections: firstNumber(app.connections, app.conn_count),
      activeSessions: firstNumber(app.active_sessions, app.sessions, app.session_count),
      clients: firstNumber(app.clients, app.client_count) || devices.length,
      devices,
      evidenceList: normalizeAppEvidence(app),
      evidence: firstText(normalizeAppEvidence(app))
    };
    return isDisplayableApp(normalized) ? normalized : null;
  }

  function mergeAppRankItems(items) {
    const byKey = new Map();
    asArray(items).filter(Boolean).forEach((item) => {
      const key = appDisplayKey(item);
      if (!key) return;
      const current = byKey.get(key);
      if (!current) {
        byKey.set(key, {
          ...item,
          trackKey: key,
          evidenceList: uniqueStrings(asArray(item.evidenceList).length ? item.evidenceList : [item.evidence], 8),
          devices: asArray(item.devices).map(normalizeAppDevice).filter(Boolean)
        });
        return;
      }
      current.name = current.name || item.name;
      current.icon = current.icon || item.icon;
      current.category = current.category || item.category;
      current.upRate += firstNumber(item.upRate);
      current.downRate += firstNumber(item.downRate);
      current.upBytes += firstNumber(item.upBytes);
      current.downBytes += firstNumber(item.downBytes);
      current.totalBytes += firstNumber(item.totalBytes);
      current.connections += firstNumber(item.connections);
      current.activeSessions += firstNumber(item.activeSessions);
      current.evidenceList = uniqueStrings([...(current.evidenceList || []), ...(item.evidenceList || []), item.evidence], 8);
      current.evidence = firstText(current.evidenceList);
      const deviceMap = new Map(asArray(current.devices).map((device) => [firstText(device.mac, device.ip, device.name).toLowerCase(), device]));
      asArray(item.devices).map(normalizeAppDevice).filter(Boolean).forEach((device) => {
        const deviceKey = firstText(device.mac, device.ip, device.name).toLowerCase();
        if (deviceKey && !deviceMap.has(deviceKey)) deviceMap.set(deviceKey, device);
      });
      current.devices = Array.from(deviceMap.values()).slice(0, 8);
      current.clients = Math.max(firstNumber(current.clients), firstNumber(item.clients), current.devices.length);
    });
    return Array.from(byKey.values());
  }


  function sortRankItems(items) {
    return asArray(items)
      .filter((item) => item && item.name)
      .sort((a, b) => {
        const bScore = firstNumber(b.totalBytes) || firstNumber(b.downRate) + firstNumber(b.upRate) || firstNumber(b.connections) || firstNumber(b.activeSessions) || firstNumber(b.clients);
        const aScore = firstNumber(a.totalBytes) || firstNumber(a.downRate) + firstNumber(a.upRate) || firstNumber(a.connections) || firstNumber(a.activeSessions) || firstNumber(a.clients);
        return bScore - aScore;
      })
      .slice(0, 17);
  }

  function normalizeDashboardRanks(snapshot = {}, clientsData = {}) {
    const clientsByMac = clientByMac(clientsData);
    const clientSources = [
      snapshot.top_clients,
      snapshot.client_rank,
      snapshot.traffic_clients,
      snapshot.traffic_audit && snapshot.traffic_audit.mac,
      snapshot.audit && snapshot.audit.clients
    ];
    let clientRows = clientSources.flatMap((source) => dashboardListFrom(source));
    if (!clientRows.length) {
      clientRows = dashboardListFrom(clientsData.clients || clientsData.users || clientsData.list || clientsData.items || clientsData)
        .filter((client) => onlineState(client && client.online) === true);
    }

    const appSources = [
      snapshot.top_apps,
      snapshot.top_protocols,
      snapshot.app_rank,
      snapshot.protocol_rank,
      snapshot.traffic_apps,
      snapshot.apps,
      snapshot.online_apps,
      snapshot.active_apps,
      snapshot.dpi_apps,
      snapshot.audit && snapshot.audit.apps,
      snapshot.audit && snapshot.audit.protocols
    ];
    const appRows = [
      ...appSources.flatMap((source) => dashboardListFrom(source)),
      ...dashboardAppInputs(snapshot, clientsData)
    ];
    return {
      clients: sortRankItems(clientRows.map((client, index) => normalizeClientRankItem(enrichClientRankSource(client, clientsByMac), index))),
      apps: sortRankItems(mergeAppRankItems(appRows.map(normalizeAppRankItem).filter(Boolean)))
    };
  }

  /*
   * Match a WAN against the kernel-runtime snapshot. The snapshot keys rows by
   * proc directory (wan1..wan4) while if_stats' first row is named `wan`, so an
   * id-only match silently misses the first WAN. Both spellings are tried.
   */
  function kernelWanRow(kernelRuntimeData, id, index) {
    const rows = asArray(kernelRuntimeData && kernelRuntimeData.wans);
    if (!rows.length) return null;
    const key = String(id || '').toLowerCase();
    return rows.find((row) => {
      const rowId = String(row && row.id || '').toLowerCase();
      const statsName = String(row && row.if_stats_name || '').toLowerCase();
      return (key && (rowId === key || statsName === key)) || Number(row && row.index) === index + 1;
    }) || null;
  }

  function normalizeWan(wan, index, fallbackTraffic = {}, systemUptime = 0, kernelRuntimeData = {}) {
    const runtime = wan && typeof wan.runtime === 'object' ? wan.runtime : {};
    const id = firstText(wan.id, wan.name, wan.ifname, `wan${index + 1}`);
    const health = state.dashboard.wanHealthSamples.get(id) || {};
    const downRate = firstFiniteNumber(wan.down_rate, wan.rate_down, wan.rx_rate, runtime.down_rate, runtime.rate_down, runtime.rx_rate);
    const upRate = firstFiniteNumber(wan.up_rate, wan.rate_up, wan.tx_rate, runtime.up_rate, runtime.rate_up, runtime.tx_rate);
    const fallbackDownRate = index === 0 ? firstFiniteNumber(fallbackTraffic.down_rate, fallbackTraffic.rx_rate) : null;
    const fallbackUpRate = index === 0 ? firstFiniteNumber(fallbackTraffic.up_rate, fallbackTraffic.tx_rate) : null;
    return {
      id,
      name: firstText(wan.name, wan.ifname, id),
      ifname: firstText(wan.ifname, wan.interface),
      device: firstText(wan.device, wan.port, wan.port_label),
      proto: firstText(wan.access_mode, wan.proto, wan.protocol),
      carrier: firstText(wan.carrier, wan.carrier_name, wan.isp, wan.isp_name, wan.operator, wan.operator_name, wan.provider, wan.provider_name, wan.note, runtime.carrier, runtime.carrier_name, runtime.isp),
      ip: firstText(wan.ip, wan.ipv4, wan.ipaddr, runtime.ipv4),
      ipv6: firstGlobalIpv6(
        wan.ipv6_global,
        wan.global_ipv6,
        wan.public_ipv6,
        wan.wan_ipv6,
        wan.ipv6_addrs,
        wan.addresses,
        runtime.ipv6_global,
        runtime.global_ipv6,
        runtime.public_ipv6,
        runtime.ipv6_addrs,
        runtime.addresses,
        wan.ipv6,
        wan.ipv6_addr,
        runtime.ipv6
      ),
      gateway: firstText(wan.gateway, runtime.gateway),
      uptime: trustedWanUptime(wan, runtime, systemUptime),
      status: firstText(wan.status, runtime.online === true ? 'ok' : runtime.online === false ? 'down' : ''),
      online: wan.health === true || runtime.online === true || firstText(wan.status) === 'ok',
      downRate: heldDashboardRate(`wan:${id}:down`, downRate === null ? fallbackDownRate : downRate, downRate === null ? fallbackDownRate : downRate),
      upRate: heldDashboardRate(`wan:${id}:up`, upRate === null ? fallbackUpRate : upRate, upRate === null ? fallbackUpRate : upRate),
      downBytes: firstNumber(wan.down_bytes, wan.rx_bytes, runtime.down_bytes, runtime.rx_bytes),
      upBytes: firstNumber(wan.up_bytes, wan.tx_bytes, runtime.up_bytes, runtime.tx_bytes),
      monthlyUsageBytes: firstNumber(wan.monthly_usage_bytes, wan.month_usage_bytes, wan.month_bytes, wan.month_total_bytes, wan.data_usage_bytes, runtime.monthly_usage_bytes, runtime.month_bytes, runtime.data_usage_bytes),
      monthlyLimitBytes: firstNumber(wan.monthly_limit_bytes, wan.month_limit_bytes, wan.data_cap_bytes, wan.quota_bytes, runtime.monthly_limit_bytes, runtime.data_cap_bytes),
      monthlyUsageLabel: firstText(wan.monthly_usage_label, wan.month_usage_label, wan.month_total_label, wan.usage_label, wan.data_usage_label, runtime.monthly_usage_label, runtime.data_usage_label),
      monthlyLimitLabel: firstText(wan.monthly_limit_label, wan.month_limit_label, wan.data_cap_label, wan.quota_label, runtime.monthly_limit_label, runtime.data_cap_label),
      linkSpeed: firstText(wan.link_speed, wan.speed_label, wan.speed, wan.negotiated_speed),
      latency: positiveNumber(wan.latency_ms, runtime.latency_ms, runtime.latency, health.latency_ms, health.latency),
      loss: firstNumber(wan.loss_pct, runtime.loss_pct, runtime.loss, health.loss_pct, health.loss),
      connections: firstNumber(runtime.connections, wan.connections, wan.conn_count),
      /*
       * conntrack attribution above; the kernel gauge stays in its own field so
       * the card can label both instead of showing one number with no source.
       * kernel-runtime spells its fields without the `kernel_` prefix, so they
       * are mapped onto the shared contract shape before normalizing.
       */
      kernel: (() => {
        if (!connTruth) return null;
        const row = kernelWanRow(kernelRuntimeData, id, index);
        const available = kernelRuntimeData && kernelRuntimeData.available === true;
        if (!row || !available) {
          return connTruth.kernelRuntime({
            kernel_active_conn_valid: false,
            kernel_stats_reason: firstText(
              kernelRuntimeData && kernelRuntimeData.reason,
              kernelRuntimeData && kernelRuntimeData.if_stats_reason,
              row ? '' : 'wan_absent_from_if_stats'
            )
          });
        }
        return connTruth.kernelRuntime({
          kernel_active_conn: row.active_conn,
          kernel_active_conn_valid: true,
          kernel_active_conn_semantics: firstText(row.active_conn_semantics, kernelRuntimeData.active_conn_semantics),
          kernel_active_conn_source: firstText(row.if_stats_source, row.source),
          kernel_active_conn_stale_possible: kernelRuntimeData.active_conn_stale_possible === true,
          kernel_tx_packets: row.tx_packets,
          kernel_rx_packets: row.rx_packets,
          kernel_tx_bytes: row.tx_bytes,
          kernel_rx_bytes: row.rx_bytes,
          kernel_stats_observed_at: kernelRuntimeData.observed_at,
          kernel_stats_reason: firstText(row.categories_reason, kernelRuntimeData.if_stats_reason),
          kernel_proc_id: row.id,
          kernel_categories: row.categories,
          kernel_categories_source: row.source
        });
      })(),
      history: asArray(wan.status_history || wan.health_history || wan.history).length
        ? asArray(wan.status_history || wan.health_history || wan.history)
        : asArray(health.status_history || health.health_history || health.history),
      probes: wan.probes || wan.latency || {}
    };
  }

  function normalizeDashboardApps(rawApps, clientsData = {}) {
    const byKey = new Map();
    const clientsByMac = clientByMac(clientsData);
    asArray(rawApps).forEach((source, index) => {
      const app = source && typeof source === 'object' ? source : { name: source };
      const id = firstText(app.appid, app.app_id, app.id, app.key, app.proto_id, app.dpi_id, app.name, app.appname, `app-${index}`);
      const name = appDisplayName(app);
      const icon = normalizeAppIconPath([
        app.icon_url,
        app.icon,
        app.icon_path,
        app.icon_file,
        app.app_icon,
        app.logo,
        app.logo_url,
        app.image,
        app.signature_icon,
        app.icon_candidates,
        app.icons
      ]);
      const evidence = asArray(app.evidence);
      const domains = uniqueStrings([
        app.domain,
        app.host,
        app.url,
        app.dst_host,
        ...asArray(app.domains || app.hosts || app.rules).map((item) => firstText(item.domain, item.host, item.url, item.value, item)),
        ...evidence.map((item) => firstText(item.domain, item.host, item.url, item.value))
      ], 6).filter((value) => !isIpAddress(value));
      const targetIps = uniqueStrings([
        app.target_ip,
        app.dst_ip,
        app.destination_ip,
        app.ip,
        ...evidence.map((item) => firstText(item.dst_ip, item.target_ip, item.destination_ip, item.ip))
      ], 6).filter(isIpAddress);
      const duration = firstNumber(app.duration, app.seconds, app.active_seconds)
        || Math.max(0, firstNumber(app.last_seen) - firstNumber(app.first_seen));
      const durationKnown = [app.duration, app.seconds, app.active_seconds, app.first_seen].some((value) => value !== undefined && value !== null && value !== '');
      const normalized = {
        id,
        name,
        icon,
        upRate: heldDashboardRate(`app:${id}:up`, firstNumber(app.up_rate, app.rate_up, app.tx_rate)),
        downRate: heldDashboardRate(`app:${id}:down`, firstNumber(app.down_rate, app.rate_down, app.rx_rate)),
        clients: firstNumber(app.clients, app.client_count, app.hosts),
        duration,
        durationKnown,
        domains,
        targetIps,
        devices: asArray(app.devices).map((device) => enrichAppDevice(device, clientsByMac)).filter(Boolean)
      };
      if (!isDisplayableApp(normalized)) return;
      const key = appDisplayKey(normalized);
      const current = byKey.get(key);
      if (!current) {
        byKey.set(key, { ...normalized, trackKey: key });
        return;
      }
      current.icon = current.icon || normalized.icon;
      current.upRate += normalized.upRate;
      current.downRate += normalized.downRate;
      current.clients = Math.max(current.clients || 0, normalized.clients || normalized.devices.length || 0);
      current.duration = Math.max(current.duration || 0, normalized.duration || 0);
      current.durationKnown = current.durationKnown || normalized.durationKnown;
      current.domains = uniqueStrings([...(current.domains || []), ...(normalized.domains || [])], 6);
      current.targetIps = uniqueStrings([...(current.targetIps || []), ...(normalized.targetIps || [])], 6);
      current.devices = uniqueStrings([
        ...asArray(current.devices).map((device) => JSON.stringify(device)),
        ...asArray(normalized.devices).map((device) => JSON.stringify(device))
      ], 8).map((item) => {
        try { return JSON.parse(item); } catch (_) { return null; }
      }).filter(Boolean);
    });
    return Array.from(byKey.values())
      .sort((a, b) => (b.downRate + b.upRate) - (a.downRate + a.upRate))
      .slice(0, 24);
  }

  function normalizePort(port) {
    const name = firstText(port.name, port.ifname, port.id);
    const ownerType = firstText(port.owner_type, port.type).toLowerCase();
    const status = firstText(port.status, port.state).toLowerCase();
    const virtual = /^(docker|dummy|teql|lo|ifb|br-|pppoe-|wan6)/.test(name) && !ownerType;
    return {
      id: name,
      label: firstText(port.label, name),
      kind: virtual ? 'virtual' : ownerType === 'wan' ? 'wan' : ownerType === 'lan' ? 'lan' : 'lan',
      ownerId: firstText(port.owner_id, port.network),
      status,
      active: status === 'up' || status === 'online',
      speed: firstText(port.speed_label, port.link_speed, port.speed),
      duplex: firstText(port.duplex)
    };
  }

  function portMatchesWan(port, wan) {
    if (!port || !wan) return false;
    const portKeys = [
      port.id,
      port.label,
      port.ownerId
    ].map((value) => String(value || '').toLowerCase()).filter(Boolean);
    const wanKeys = [
      wan.id,
      wan.name,
      wan.ifname,
      wan.device
    ].map((value) => String(value || '').toLowerCase()).filter(Boolean);
    return portKeys.some((key) => wanKeys.includes(key));
  }

  function setDashboardStatus(text, level) {
    const el = $('railCardStatus');
    if (!el) return;
    el.textContent = text;
    el.classList.remove('is-ok', 'is-warn', 'is-error');
    if (level) el.classList.add(`is-${level}`);
  }

  function dashboardStatusSummary(model) {
    const authError = model.errors.find((item) => item.error && item.error.status === 401);
    if (authError) {
      return { level: 'error', title: '认证过期', detail: '请重新登录' };
    }
    if (model.errors.length) {
      return { level: 'warn', title: '部分接口不可用', detail: `${model.errors.length} 个接口失败` };
    }
    const wans = model.wans || [];
    const onlineWans = wans.filter((wan) => wan.online);
    if (wans.length && !onlineWans.length) {
      return { level: 'error', title: '无网络', detail: '所有 WAN 未在线' };
    }
    const riskyWan = wans.find((wan) => (wan.latency && wan.latency >= 180) || (wan.loss && wan.loss > 5));
    if (riskyWan) {
      return { level: 'warn', title: '线路质量波动', detail: riskyWan.name || riskyWan.id || 'WAN' };
    }
    return { level: 'ok', title: '正常', detail: '核心状态稳定' };
  }

  function dashboardIcon(name) {
    const icons = {
      status: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M20 7 10 17l-5-5"/></svg>',
      users: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
      apps: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/></svg>',
      traffic: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M3 17h18"/><path d="m7 13 4-4 3 3 4-6"/><path d="M18 6h-4"/><path d="M18 6v4"/></svg>',
      wifi: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M5 13a10 10 0 0 1 14 0"/><path d="M8.5 16.5a5 5 0 0 1 7 0"/><path d="M12 20h.01"/><path d="M2 9a15 15 0 0 1 20 0"/></svg>'
    };
    return icons[name] || icons.status;
  }

  function dashboardMetricCard(card) {
    const level = card.level ? ` is-${escapeHtml(card.level)}` : '';
    return `
      <article class="dashboard-metric-card dwrt-glass-card${level}">
        <span class="dashboard-metric-light" aria-hidden="true"></span>
        <span class="dashboard-metric-icon" aria-hidden="true">${dashboardIcon(card.icon)}</span>
        <span class="dashboard-metric-title">${escapeHtml(card.title)}</span>
        <strong>${escapeHtml(card.value)}</strong>
        <small>${escapeHtml(card.detail || '')}</small>
      </article>`;
  }

  function dashboardMetricCards(model) {
    const status = dashboardStatusSummary(model);
    const traffic = model.traffic || {};
    const apps = model.apps || [];
    const cards = [
      {
        title: '系统状态',
        value: status.title,
        detail: status.detail,
        icon: 'status',
        level: status.level
      },
      {
        title: '在线用户',
        value: formatInteger(model.clients && model.clients.total),
        detail: '当前在线终端',
        icon: 'users',
        level: 'neutral'
      },
      {
        title: '在线 APP',
        value: formatInteger(apps.length),
        detail: apps.length ? 'DPI 在线应用' : '后端暂无在线 APP',
        icon: 'apps',
        level: apps.length ? 'neutral' : 'muted'
      },
      {
        title: '今日流量',
        value: formatBytes(firstNumber(traffic.today_up) + firstNumber(traffic.today_down)),
        detail: `↑ ${formatBytes(traffic.today_up)} / ↓ ${formatBytes(traffic.today_down)}`,
        icon: 'traffic',
        level: 'neutral'
      }
    ];
    if (model.clients && model.clients.wifiSupported) {
      cards.push({
        title: 'Wi-Fi 终端',
        value: formatInteger(model.clients.wifi),
        detail: '无线接入终端',
        icon: 'wifi',
        level: 'neutral'
      });
    }
    return cards;
  }


  function stableSignature(value) {
    try { return JSON.stringify(value); } catch (_) { return String(value || ''); }
  }

  function sectionKeys() {
    return state.dashboard.renderSectionKeys || (state.dashboard.renderSectionKeys = {});
  }

  function setSectionHtml(element, key, html, afterRender) {
    if (!element) return false;
    const cache = sectionKeys();
    if (cache[key] === html) return false;
    cache[key] = html;
    element.innerHTML = html;
    if (typeof afterRender === 'function') afterRender(element);
    return true;
  }

  function monitorPart(selector) {
    return routerMonitorCard ? routerMonitorCard.querySelector(selector) : null;
  }

  function ensureMonitorShell() {
    if (!routerMonitorCard) return false;
    if (routerMonitorCard.querySelector('[data-dashboard-monitor-toolbar]')) return true;
    routerMonitorCard.innerHTML = `
      <header class="dashboard-monitor-toolbar" data-dashboard-monitor-toolbar></header>
      <div class="dashboard-monitor-metrics" data-dashboard-monitor-metrics></div>
      <div class="dashboard-chart-wrap" data-dashboard-chart-wrap></div>
      <div class="dashboard-monitor-foot dashboard-availability-row" data-dashboard-availability></div>
      <div data-dashboard-app-track-mount></div>`;
    ['monitorToolbar', 'monitorMetrics', 'monitorChart', 'monitorAvailability', 'monitorAppTrack'].forEach((key) => delete sectionKeys()[key]);
    state.dashboard.appTrackStructureKey = '';
    state.dashboard.appTrackMissingSince = new Map();
    state.dashboard.appTrackLastApps = new Map();
    window.clearTimeout(state.dashboard.appTrackEmptyTimer);
    state.dashboard.appTrackEmptyTimer = 0;
    return true;
  }

  function resetDashboardRenderCache() {
    state.dashboard.renderSectionKeys = {};
    state.dashboard.appTrackStructureKey = '';
    state.dashboard.appTrackMissingSince = new Map();
    state.dashboard.appTrackLastApps = new Map();
    window.clearTimeout(state.dashboard.appTrackEmptyTimer);
    state.dashboard.appTrackEmptyTimer = 0;
    state.dashboard.rankStructureKey = '';
    state.dashboard.wanRailStructureKey = '';
    if (routerMonitorCard) routerMonitorCard.innerHTML = '';
    if (dashboardMetricGrid) dashboardMetricGrid.innerHTML = '';
    if (dashboardRankGrid) dashboardRankGrid.innerHTML = '';
    if (dashboardActiveUrlCard) dashboardActiveUrlCard.innerHTML = '';
  }

  function appendTrafficSample(model, options = {}) {
    const traffic = model.traffic || {};
    const wans = model.wans || [];
    const activeWan = wans[0] || {};
    const live = Boolean(options && options.live);
    const nowMs = Date.now();
    const coalesceLiveSample = Boolean(
      live &&
      state.dashboard.lastTrafficSampleAt &&
      nowMs - state.dashboard.lastTrafficSampleAt < MAIN_CHART_SAMPLE_MS
    );
    const hasRateSignal = [
      traffic.up_rate,
      traffic.down_rate,
      traffic.tx_rate,
      traffic.rx_rate,
      traffic.latency_ms,
      traffic.latency,
      activeWan.upRate,
      activeWan.downRate,
      model.system && model.system.connections
    ].some((value) => value !== undefined && value !== null && value !== '');
    if (!hasRateSignal) return false;
    const up = firstNumber(traffic.up_rate, traffic.tx_rate, (model.wans || [])[0] && (model.wans || [])[0].upRate);
    const down = firstNumber(traffic.down_rate, traffic.rx_rate, (model.wans || [])[0] && (model.wans || [])[0].downRate);
    const latency = positiveNumber(activeWan.latency, traffic.latency_ms, traffic.latency);
    const connections = firstNumber(model.system.connections);
    const point = {
      ts: liveTimestampSeconds(traffic.ts, model.system && model.system.ts),
      up,
      down,
      upMax: firstNumber(traffic.up_max, traffic.tx_max, traffic.up_peak, traffic.tx_peak, up),
      downMax: firstNumber(traffic.down_max, traffic.rx_max, traffic.down_peak, traffic.rx_peak, down),
      latency,
      latencyMax: positiveNumber(traffic.latency_max, traffic.rtt_max, activeWan.latency_max, latency),
      latencyMin: positiveNumber(traffic.latency_min, traffic.rtt_min, activeWan.latency_min, latency),
      connections,
      connectionsMax: firstNumber(model.system.connections_max, traffic.connections_max, traffic.conn_max, connections)
    };
    const history = state.dashboard.trafficHistory;
    const last = history[history.length - 1];
    if (last && point.ts <= last.ts) point.ts = coalesceLiveSample ? last.ts : last.ts + (live ? MAIN_CHART_SAMPLE_MS / 1000 : 0.001);
    point._addedAt = nowMs;
    if (live) {
      if (coalesceLiveSample && last) history[history.length - 1] = point;
      else {
        history.push(point);
        state.dashboard.lastTrafficSampleAt = nowMs;
      }
    } else if (!last || point.ts !== last.ts || point.up !== last.up || point.down !== last.down || nowMs - (last._addedAt || 0) > DASHBOARD_REFRESH_MS - 200) {
      history.push(point);
      state.dashboard.lastTrafficSampleAt = nowMs;
    }
    const cutoff = point.ts - (DASHBOARD_HISTORY_RANGES[0].windowSec || 600);
    const maxRealtimePoints = Math.ceil((DASHBOARD_HISTORY_RANGES[0].windowSec || 600) / (MAIN_CHART_SAMPLE_MS / 1000)) + 8;
    while (history.length > maxRealtimePoints || history[0] && history[0].ts < cutoff) history.shift();
    return true;
  }

  function dashboardRangeMeta(rangeId) {
    return DASHBOARD_HISTORY_RANGES.find((range) => range.id === rangeId) || DASHBOARD_HISTORY_RANGES[0];
  }

  function selectedDashboardWanId(value = state.dashboard.activeWanId) {
    const normalized = firstText(value, 'all').toLowerCase();
    return normalized === 'all' ? 'all' : normalized;
  }

  function dashboardHistoryKey(rangeId, wanId = state.dashboard.activeWanId) {
    return `${dashboardRangeMeta(rangeId).id}:${selectedDashboardWanId(wanId)}`;
  }

  function realtimePointsForWan(wanId) {
    const id = selectedDashboardWanId(wanId);
    if (id === 'all') return state.dashboard.trafficHistory;
    const wans = asArray(state.dashboard.lastModel && state.dashboard.lastModel.wans);
    const wan = wans.find((item) => selectedDashboardWanId(item && item.id) === id);
    const points = wan ? wanRealtimePoints(wan) : state.dashboard.wanRealtimePoints.get(id);
    return asArray(points).map((point) => ({
      ...point,
      up: firstNumber(point.up, point.upRate),
      down: firstNumber(point.down, point.downRate)
    }));
  }

  function normalizeHistoryPoint(point) {
    if (!point || typeof point !== 'object') return null;
    const ts = firstNumber(point.ts, point.time, point.timestamp, point.bucket_ts);
    if (!ts) return null;
    return {
      ts,
      up: firstNumber(point.up_rate, point.up_avg, point.tx_rate, point.tx_avg, point.up),
      down: firstNumber(point.down_rate, point.down_avg, point.rx_rate, point.rx_avg, point.down),
      upMax: firstNumber(point.up_max, point.tx_max, point.up_peak, point.tx_peak),
      downMax: firstNumber(point.down_max, point.rx_max, point.down_peak, point.rx_peak),
      latency: positiveNumber(point.latency_ms, point.latency_avg, point.rtt, point.avg_ms, point.latency),
      latencyMax: positiveNumber(point.latency_max, point.rtt_max),
      latencyMin: positiveNumber(point.latency_min, point.rtt_min),
      connections: firstNumber(point.connections, point.conn_count, point.connections_avg),
      connectionsMax: firstNumber(point.connections_max, point.conn_max),
      samples: firstNumber(point.sample_count, point.samples)
    };
  }

  function normalizeHistoryPayload(raw, rangeId, wanId = state.dashboard.activeWanId) {
    const data = raw && typeof raw === 'object' ? raw : {};
    const points = dashboardListFrom(data.points || data.traffic || data.items || data.series || data.history)
      .map(normalizeHistoryPoint)
      .filter(Boolean)
      .sort((a, b) => a.ts - b.ts);
    return {
      range: firstText(data.range, rangeId),
      wanId: firstText(data.wan_id, selectedDashboardWanId(wanId)),
      ts: firstNumber(data.ts, Date.now() / 1000),
      degraded: data.degraded === true,
      missing: firstText(data.missing, data.error && data.error.message),
      bucketSec: firstNumber(data.bucket_sec, data.bucket, data.interval),
      retentionSec: firstNumber(data.retention_sec),
      points
    };
  }

  async function fetchTrafficHistoryPayload(rangeId, wanId) {
    const selectedWanId = selectedDashboardWanId(wanId);
    const query = new URLSearchParams({ range: rangeId });
    if (selectedWanId !== 'all') query.set('wan_id', selectedWanId);
    const resource = await fetchDashboardResource(
      `history:${rangeId}:${selectedWanId}`,
      `${DASHBOARD_HISTORY_ENDPOINT}?${query}`
    );
    return resource.ok ? normalizeHistoryPayload(resource.data, rangeId, selectedWanId) : null;
  }

  function visibleTrafficPoints(rangeId, wanId = state.dashboard.activeWanId) {
    const meta = dashboardRangeMeta(rangeId);
    const selectedWanId = selectedDashboardWanId(wanId);
    if (rangeId === 'realtime') {
      const now = Date.now() / 1000;
      const cutoff = now - meta.windowSec;
      const points = realtimePointsForWan(selectedWanId).filter((point) => point.ts >= cutoff);
      return {
        range: rangeId,
        wanId: selectedWanId,
        mode: 'realtime',
        points,
        missing: points.length ? '' : selectedWanId === 'all' ? '等待实时采样' : `等待 ${selectedWanId.toUpperCase()} 实时采样`,
        degraded: false,
        windowSec: meta.windowSec
      };
    }
    const history = state.dashboard.historyByRange[dashboardHistoryKey(rangeId, selectedWanId)] || {};
    const payload = history.data || history;
    return {
      ...payload,
      range: rangeId,
      wanId: selectedWanId,
      mode: 'history',
      points: asArray(payload.points),
      windowSec: meta.windowSec,
      missing: firstText(payload.missing, asArray(payload.points).length ? '' : '历史样本不足')
    };
  }

  async function syncTrafficHistory(rangeId, force = false, wanId = state.dashboard.activeWanId) {
    const normalizedRange = dashboardRangeMeta(rangeId).id;
    const selectedWanId = selectedDashboardWanId(wanId);
    if (normalizedRange === 'realtime') return visibleTrafficPoints('realtime', selectedWanId);
    const cacheKey = dashboardHistoryKey(normalizedRange, selectedWanId);
    const current = state.dashboard.historyByRange[cacheKey] || {};
    const staleMs = normalizedRange === '1m' ? 10 * 60 * 1000 : normalizedRange === '1w' ? 5 * 60 * 1000 : 90 * 1000;
    if (!force && current.data && current.fetchedAt && Date.now() - current.fetchedAt < staleMs) {
      return current.data;
    }
    if (current.loading && current.promise) return current.promise;
    const entry = {
      ...current,
      loading: true,
      error: null
    };
    const promise = fetchTrafficHistoryPayload(normalizedRange, selectedWanId)
      .then((payload) => {
        const data = payload || {
          range: normalizedRange,
          wanId: selectedWanId,
          ts: Date.now() / 1000,
          degraded: true,
          missing: '历史样本不足',
          points: []
        };
        state.dashboard.historyByRange[cacheKey] = {
          ...entry,
          loading: false,
          fetchedAt: Date.now(),
          data,
          error: payload ? null : new Error('历史样本不足'),
          promise: null
        };
        return data;
      })
      .catch((error) => {
        const data = {
          range: normalizedRange,
          wanId: selectedWanId,
          ts: Date.now() / 1000,
          degraded: true,
          missing: firstText(error && error.message, '历史样本不足'),
          points: []
        };
        state.dashboard.historyByRange[cacheKey] = {
          ...entry,
          loading: false,
          fetchedAt: Date.now(),
          data,
          error,
          promise: null
        };
        return data;
      });
    entry.promise = promise;
    state.dashboard.historyByRange[cacheKey] = entry;
    return promise;
  }

  function valueMax(points, keys) {
    return Math.max(
      1,
      ...points.flatMap((point) => keys.map((key) => Number(point[key]) || 0))
    );
  }

  function svgPolyline(points, width, height, key, minTs, maxTs, maxValue, allowZero = true, xPad = 0) {
    const usable = points.filter((point) => {
      const value = Number(point[key]);
      return Number.isFinite(value) && (allowZero ? value >= 0 : value > 0);
    });
    if (!usable.length) return '';
    const span = Math.max(1, maxTs - minTs);
    const usableWidth = Math.max(1, width - (xPad * 2));
    return usable.map((point) => {
      const value = Number(point[key]) || 0;
      const x = Math.max(xPad, Math.min(width - xPad, xPad + ((point.ts - minTs) / span) * usableWidth));
      const y = height - (value / maxValue) * (height - 18) - 9;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
  }

  function svgCoordinates(points, width, height, key, minTs, maxTs, maxValue, allowZero = true, xPad = 0) {
    const span = Math.max(1, maxTs - minTs);
    const usableWidth = Math.max(1, width - (xPad * 2));
    const coordinates = points.reduce((result, point) => {
      const value = Number(point[key]);
      if (!Number.isFinite(value) || (allowZero ? value < 0 : value <= 0)) return result;
      const x = Math.max(xPad, Math.min(width - xPad, xPad + ((point.ts - minTs) / span) * usableWidth));
      const y = height - (value / maxValue) * (height - 18) - 9;
      const previous = result[result.length - 1];
      if (previous && Math.abs(previous.x - x) < 0.01) result[result.length - 1] = { x, y };
      else result.push({ x, y });
      return result;
    }, []);
    return coordinates;
  }

  // Monotone cubic interpolation rounds rapid changes without overshooting the sampled peaks.
  function monotoneSvgPath(coordinates) {
    if (!coordinates.length) return '';
    if (coordinates.length === 1) return `M${coordinates[0].x.toFixed(1)} ${coordinates[0].y.toFixed(1)}`;
    const slopes = [];
    const widths = [];
    for (let index = 0; index < coordinates.length - 1; index += 1) {
      const width = Math.max(0.001, coordinates[index + 1].x - coordinates[index].x);
      widths.push(width);
      slopes.push((coordinates[index + 1].y - coordinates[index].y) / width);
    }
    const tangents = [slopes[0]];
    for (let index = 1; index < coordinates.length - 1; index += 1) {
      const previous = slopes[index - 1];
      const next = slopes[index];
      if (!previous || !next || previous * next <= 0) {
        tangents.push(0);
        continue;
      }
      const previousWidth = widths[index - 1];
      const nextWidth = widths[index];
      const leftWeight = (2 * nextWidth) + previousWidth;
      const rightWeight = nextWidth + (2 * previousWidth);
      tangents.push((leftWeight + rightWeight) / ((leftWeight / previous) + (rightWeight / next)));
    }
    tangents.push(slopes[slopes.length - 1]);
    let path = `M${coordinates[0].x.toFixed(1)} ${coordinates[0].y.toFixed(1)}`;
    for (let index = 0; index < coordinates.length - 1; index += 1) {
      const current = coordinates[index];
      const next = coordinates[index + 1];
      const width = widths[index];
      const controlWidth = width / 3;
      path += ` C${(current.x + controlWidth).toFixed(1)} ${(current.y + tangents[index] * controlWidth).toFixed(1)}`;
      path += ` ${(next.x - controlWidth).toFixed(1)} ${(next.y - tangents[index + 1] * controlWidth).toFixed(1)}`;
      path += ` ${next.x.toFixed(1)} ${next.y.toFixed(1)}`;
    }
    return path;
  }

  function svgPathArea(path, coordinates, height) {
    if (!path || !coordinates.length) return '';
    const first = coordinates[0];
    const last = coordinates[coordinates.length - 1];
    return `${path} L${last.x.toFixed(1)} ${height} L${first.x.toFixed(1)} ${height} Z`;
  }

  function svgArea(line, width, height) {
    if (!line) return '';
    const first = line.split(' ')[0] || `0,${height}`;
    const last = line.split(' ').slice(-1)[0] || `${width},${height}`;
    const firstX = first.split(',')[0] || '0';
    const lastX = last.split(',')[0] || String(width);
    return `${line} ${lastX},${height} ${firstX},${height}`;
  }

  function renderTrafficChart(series) {
    const points = asArray(series && series.points);
    const plotWidth = 720;
    const height = 220;
    const axisWidth = 48;
    const rightPad = 62;
    const xPad = 20;
    const bottomAxis = 38;
    const rangeId = series && series.range || state.dashboard.trafficRange;
    const meta = dashboardRangeMeta(rangeId);
    const endTs = rangeId === 'realtime'
      ? Math.max(Date.now() / 1000, ...(points.map((point) => point.ts || 0)))
      : firstNumber(series && series.ts, points.length ? points[points.length - 1].ts : Date.now() / 1000);
    const maxTs = endTs || Date.now() / 1000;
    const windowSec = series && series.retentionSec || meta.windowSec;
    let minTs = Math.max(0, maxTs - windowSec);
    if (rangeId === 'realtime' && points.length) {
      const firstPointTs = points[0].ts || minTs;
      if (firstPointTs > minTs + windowSec * 0.25) {
        minTs = Math.max(0, firstPointTs - Math.min(60, windowSec * 0.06));
      }
    }
    const rateMax = valueMax(points, ['down', 'up', 'downMax', 'upMax']);
    const connMax = valueMax(points, ['connections', 'connectionsMax']);
    const latencyMax = valueMax(points, ['latency', 'latencyMax']);
    const downCoordinates = svgCoordinates(points, plotWidth, height, 'down', minTs, maxTs, rateMax, true, xPad);
    const upCoordinates = svgCoordinates(points, plotWidth, height, 'up', minTs, maxTs, rateMax, true, xPad);
    const downLine = monotoneSvgPath(downCoordinates);
    const upLine = monotoneSvgPath(upCoordinates);
    const connLine = svgPolyline(points, plotWidth, height, 'connections', minTs, maxTs, connMax, true, xPad);
    const latencyLine = svgPolyline(points, plotWidth, height, 'latency', minTs, maxTs, latencyMax, false, xPad);
    const downArea = svgPathArea(downLine, downCoordinates, height);
    const upArea = svgPathArea(upLine, upCoordinates, height);
    const ticks = dashboardChartTicks(rangeId, minTs, maxTs, rateMax, plotWidth, xPad);
    const empty = !points.length || (!downLine && !upLine && !connLine && !latencyLine);
    const note = empty ? firstText(series && series.missing, '等待历史样本') : '';
    state.dashboard.chartState = {
      rangeId,
      meta,
      points,
      minTs,
      maxTs,
      rateMax,
      plotWidth,
      axisWidth,
      rightPad,
      xPad,
      bottomAxis,
      height,
      ticks,
      downLine,
      upLine,
      connLine,
      latencyLine,
      downArea,
      upArea,
      empty,
      note
    };
    return `
      <div class="dashboard-chart-frame" data-dashboard-chart="${escapeHtml(rangeId)}" style="--chart-axis-width:${axisWidth}px; --chart-right-pad:${rightPad}px; --chart-bottom-axis:${bottomAxis}px; --chart-plot-width:${plotWidth}px;">
        <div class="dashboard-chart-stage">
          <div class="dashboard-chart-plot">
            <svg class="dashboard-speed-chart" viewBox="0 0 ${plotWidth} ${height}" role="img" aria-label="Dashboard ${escapeHtml(meta.label)} 速率与状态折线图" preserveAspectRatio="none">
              <defs>
                <linearGradient id="dwrtDownFill-${escapeHtml(rangeId)}" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="0%" stop-color="rgba(34, 211, 238, 0.24)"/>
                  <stop offset="100%" stop-color="rgba(34, 211, 238, 0)"/>
                </linearGradient>
                <linearGradient id="dwrtUpFill-${escapeHtml(rangeId)}" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="0%" stop-color="rgba(183, 116, 232, 0.19)"/>
                  <stop offset="100%" stop-color="rgba(183, 116, 232, 0)"/>
                </linearGradient>
              </defs>
              <g class="chart-grid">
                <path d="M${xPad} 55H${plotWidth - xPad}M${xPad} 110H${plotWidth - xPad}M${xPad} 165H${plotWidth - xPad}"/>
              </g>
              ${downArea ? `<path class="chart-area down" d="${downArea}" style="fill:url(#dwrtDownFill-${escapeHtml(rangeId)})"></path>` : ''}
              ${upArea ? `<path class="chart-area up" d="${upArea}" style="fill:url(#dwrtUpFill-${escapeHtml(rangeId)})"></path>` : ''}
              ${downLine ? `<path class="chart-line down" d="${downLine}"></path>` : ''}
              ${upLine ? `<path class="chart-line up" d="${upLine}"></path>` : ''}
              ${connLine ? `<polyline class="chart-line connections" points="${connLine}"></polyline>` : ''}
              ${latencyLine ? `<polyline class="chart-line latency" points="${latencyLine}"></polyline>` : ''}
            </svg>
          </div>
          <div class="dashboard-chart-yaxis" aria-hidden="true">
            ${ticks.yTicks.map((tick) => `<span style="top:${(1 - tick.pos) * 100}%">${escapeHtml(tick.label)}</span>`).join('')}
          </div>
          <div class="dashboard-chart-xaxis" aria-hidden="true">
            ${ticks.xTicks.map((tick) => `<span style="left:${(tick.pos * 100).toFixed(2)}%">${escapeHtml(tick.label)}</span>`).join('')}
          </div>
          <div class="dashboard-chart-crosshair" aria-hidden="true" hidden>
            <span class="dashboard-chart-crosshair-v"></span>
            <span class="dashboard-chart-crosshair-h"></span>
            <span class="dashboard-chart-crosshair-dot"></span>
          </div>
          <div class="dashboard-chart-tooltip" hidden></div>
          ${empty ? `<div class="dashboard-chart-empty"><strong>${escapeHtml(meta.label)}</strong><span>${escapeHtml(note)}</span></div>` : ''}
        </div>
      </div>`;
  }

  function compactHealthBuckets(points, limit = 24) {
    const rows = asArray(points).filter(Boolean);
    if (rows.length <= limit) return rows;
    const chunkSize = Math.ceil(rows.length / limit);
    const buckets = [];
    for (let index = 0; index < rows.length; index += chunkSize) {
      const slice = rows.slice(index, index + chunkSize);
      const worst = slice.reduce((acc, item) => {
        const latency = Number(item && (item.latency || item.latency_avg || item.latency_ms || item.avg || 0)) || 0;
        const loss = Number(item && (item.loss || item.loss_pct || item.packet_loss || 0)) || 0;
        const score = loss * 1000 + latency;
        return score >= acc.score ? { item, score } : acc;
      }, { item: slice[slice.length - 1], score: -1 }).item;
      buckets.push(worst);
    }
    return buckets.slice(-limit);
  }

  function dashboardHealthHistoryPoints(limit = 24) {
    const day = visibleTrafficPoints('1d');
    const hour = visibleTrafficPoints('1h');
    const realtime = visibleTrafficPoints('realtime');
    const source = asArray(day.points).length ? day.points : asArray(hour.points).length ? hour.points : asArray(realtime.points);
    return compactHealthBuckets(source, limit);
  }

  function dashboardAvailability(wans) {
    const buckets = asArray(wans).flatMap((wan) => asArray(wan.history));
    const effectiveBuckets = buckets.length ? buckets : dashboardHealthHistoryPoints(96);
    if (!effectiveBuckets.length) return { label: '--', value: 0, known: false };
    const known = effectiveBuckets.map((item) => {
      const status = String(typeof item === 'string' ? item : item.status || item.state || '').toLowerCase();
      const latency = Number(typeof item === 'object' ? item.latency || item.latency_avg || item.latency_ms || item.avg || 0 : 0);
      const loss = Number(typeof item === 'object' ? item.loss || item.loss_pct || item.packet_loss || 0 : 0);
      if (!status && !latency && !loss) return null;
      return status === 'down' || status === 'bad' || loss > 20 ? 'bad' : 'ok';
    }).filter(Boolean);
    if (!known.length) return { label: '--', value: 0, known: false };
    const ok = known.filter((level) => level !== 'bad').length;
    const value = ok / known.length * 100;
    return { label: `${value.toFixed(2)}%`, value, known: true };
  }


  function wanAvailability(wan) {
    const history = asArray(wan && wan.history);
    if (history.length) {
      const base = dashboardAvailability([{ history }]);
      const last = history[history.length - 1] || {};
      const latency = positiveNumber(last.latency, last.latency_avg, last.latency_ms, last.avg, wan && wan.latency);
      const loss = firstNumber(last.loss, last.loss_pct, last.packet_loss, wan && wan.loss);
      const status = firstText(last.status, last.state, wan && wan.status).toLowerCase();
      const offline = /^(down|offline|bad|error|failed)$/.test(status) || (wan && wan.online === false);
      if (offline || loss > 20 || latency >= 300) return { ...base, tone: 'bad', stateLabel: offline ? '离线' : loss > 20 ? `丢包 ${loss.toFixed(1)}%` : `${Math.round(latency)} ms` };
      if (loss > 3 || latency >= 120) return { ...base, tone: 'warn', stateLabel: loss > 3 ? `丢包 ${loss.toFixed(1)}%` : `${Math.round(latency)} ms` };
      return { ...base, tone: 'ok', stateLabel: latency ? `${Math.round(latency)} ms` : '正常' };
    }
    const status = firstText(wan && wan.status).toLowerCase();
    const latency = positiveNumber(wan && wan.latency);
    const loss = firstNumber(wan && wan.loss);
    const online = wan && wan.online !== false && !/^(down|offline|bad|error|failed)$/.test(status);
    if (!online) return { label: '0.00%', value: 100, known: true, tone: 'bad', stateLabel: '离线' };
    if (loss > 20 || latency >= 300) return { label: '严重', value: 100, known: true, tone: 'bad', stateLabel: loss > 20 ? `丢包 ${loss.toFixed(1)}%` : `${Math.round(latency)} ms` };
    if (loss > 3 || latency >= 120) return { label: '偏高', value: 100, known: true, tone: 'warn', stateLabel: loss > 3 ? `丢包 ${loss.toFixed(1)}%` : `${Math.round(latency)} ms` };
    return { label: '100.00%', value: 100, known: true, tone: 'ok', stateLabel: latency ? `${Math.round(latency)} ms` : '正常' };
  }

  function carrierAvailabilityIcon(wan) {
    const meta = carrierMeta(wan || {});
    if (meta.logo) {
      return `<span class="dashboard-wan-availability-icon carrier-mark--${escapeHtml(meta.key)}" title="${escapeHtml(meta.label)}"><img src="${escapeHtml(meta.logo)}" alt="${escapeHtml(meta.label)}"></span>`;
    }
    return `<span class="dashboard-wan-availability-icon is-fallback" title="${escapeHtml(meta.label)}" aria-label="${escapeHtml(meta.label)}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3.5 12h17"/><path d="M12 3a13.5 13.5 0 0 1 0 18M12 3a13.5 13.5 0 0 0 0 18"/></svg></span>`;
  }

  function appTrackIcon(app) {
    if (app.icon) {
      return `<span class="app-track-icon"><img src="${escapeHtml(app.icon)}" alt="${escapeHtml(app.name)}" loading="lazy" onerror="this.closest('.app-track-icon').classList.add('is-missing'); this.remove();"></span>`;
    }
    const letters = Array.from(app.name || '?').slice(0, 2).join('').toUpperCase();
    return `<span class="app-track-icon fallback" aria-hidden="true">${escapeHtml(letters || '?')}</span>`;
  }

  function normalizeVisibleArtworkIcon(img) {
    if (!img || img.dataset.iconNormalized === '1') return;
    if (!img.complete || !img.naturalWidth || !img.naturalHeight) {
      img.addEventListener('load', () => normalizeVisibleArtworkIcon(img), { once: true });
      return;
    }
    img.dataset.iconNormalized = '1';
    const holder = img.closest('.app-track-icon, .rank-icon.app');
    if (!holder) return;
    const isRankIcon = holder.classList.contains('rank-icon');
    const scaleProperty = isRankIcon ? '--rank-icon-scale' : '--app-track-icon-scale';
    try {
      const size = 96;
      const canvas = normalizeVisibleArtworkIcon.canvas || (normalizeVisibleArtworkIcon.canvas = document.createElement('canvas'));
      canvas.width = size;
      canvas.height = size;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.clearRect(0, 0, size, size);
      const fitScale = Math.min(size / img.naturalWidth, size / img.naturalHeight);
      const drawWidth = img.naturalWidth * fitScale;
      const drawHeight = img.naturalHeight * fitScale;
      ctx.drawImage(img, (size - drawWidth) / 2, (size - drawHeight) / 2, drawWidth, drawHeight);
      const pixels = ctx.getImageData(0, 0, size, size).data;
      let minX = size;
      let minY = size;
      let maxX = -1;
      let maxY = -1;
      for (let y = 0; y < size; y += 1) {
        for (let x = 0; x < size; x += 1) {
          const alpha = pixels[(y * size + x) * 4 + 3];
          if (alpha <= 8) continue;
          if (x < minX) minX = x;
          if (x > maxX) maxX = x;
          if (y < minY) minY = y;
          if (y > maxY) maxY = y;
        }
      }
      if (maxX < minX || maxY < minY) return;
      const visibleWidth = (maxX - minX + 1) / size;
      const visibleHeight = (maxY - minY + 1) / size;
      const artworkAspect = visibleWidth / Math.max(visibleHeight, 0.01);
      const elongated = artworkAspect > 1.8 || artworkAspect < 0.56;
      const visible = isRankIcon
        ? elongated ? Math.max(visibleWidth, visibleHeight) : Math.sqrt(visibleWidth * visibleHeight)
        : Math.max(visibleWidth, visibleHeight);
      const target = isRankIcon ? elongated ? 0.92 : 0.98 : 0.82;
      const minScale = isRankIcon ? 0.90 : 0.76;
      const maxScale = isRankIcon ? 1.40 : 1.18;
      const scale = Math.max(minScale, Math.min(maxScale, target / Math.max(visible, 0.01)));
      holder.style.setProperty(scaleProperty, scale.toFixed(3));
      holder.classList.add('is-normalized');
    } catch (_) {
      holder.style.setProperty(scaleProperty, isRankIcon ? '1' : '0.86');
      holder.classList.add('is-normalized');
    }
  }

  function normalizeVisibleArtworkIcons(root) {
    const scope = root || routerMonitorCard || document;
    scope.querySelectorAll('.app-track-icon img, .rank-icon.app img').forEach(normalizeVisibleArtworkIcon);
  }

  function appTrackDuration(seconds) {
    const total = Math.max(0, Math.floor(Number(seconds) || 0));
    return total < 60 ? `${total}秒` : formatUptime(total);
  }

  function appTrackTitle(app) {
    const devices = asArray(app.devices).map(normalizeAppDevice).filter(Boolean);
    const names = uniqueStrings(devices.map((device) => firstText(device.name, device.mac)), 6);
    const ips = uniqueStrings(devices.map((device) => device.ip), 6);
    const domains = uniqueStrings(asArray(app.domains), 6).filter((value) => !isIpAddress(value));
    const targetIps = uniqueStrings(asArray(app.targetIps), 6).filter(isIpAddress);
    return [
      `设备：${names.length ? names.join('、') : app.clients ? `${formatInteger(app.clients)} 台设备` : '--'}`,
      `IP：${ips.length ? ips.join('、') : '--'}`,
      `命中：${domains.length ? `（${domains.join('、')}）` : '--'}`,
      `目标IP：${targetIps.length ? targetIps.join('、') : '--'}`,
      `持续时间：${app.durationKnown ? appTrackDuration(app.duration) : '--'}`
    ].join('\n');
  }

  function setAppTrackTooltip(item, app) {
    if (!item) return;
    const text = appTrackTitle(app);
    if (item.dataset.dwrtTooltip !== text) item.dataset.dwrtTooltip = text;
    item.removeAttribute('title');
  }

  function appTrackKey(app) {
    return firstText(app && app.trackKey, app && app.id, app && app.name, app && appDisplayKey(app));
  }

  function appTrackStructureKey(apps) {
    return stableSignature(asArray(apps).filter((app) => app && app.name).map((app) => ({
      key: appTrackKey(app),
      name: app.name,
      icon: app.icon || ''
    })).sort((a, b) => String(a.key).localeCompare(String(b.key))));
  }

  function updateAppTrackTitles(apps, root) {
    if (!root) return;
    const strip = root.querySelector('.app-track-strip');
    const rows = new Map(Array.from(root.querySelectorAll('.app-track-item[data-dashboard-app-key]')).map((item) => [item.dataset.dashboardAppKey, item]));
    asArray(apps).filter((app) => app && app.name).forEach((app, index) => {
      const key = appTrackKey(app);
      const item = rows.get(key);
      if (!item) return;
      setAppTrackTooltip(item, app);
      item.style.setProperty('--track-index', index);
      if (strip && item.parentElement === strip) strip.appendChild(item);
    });
  }

  function appTrackItem(app, index, isNew = false) {
    const key = appTrackKey(app);
    return `
      <div class="app-track-item${isNew ? ' is-entering' : ''}" data-dashboard-app-key="${escapeHtml(key)}" data-dashboard-app-name="${escapeHtml(app.name || '')}" data-dashboard-app-icon="${escapeHtml(app.icon || '')}" data-dwrt-tooltip="${escapeHtml(appTrackTitle(app))}" tabindex="0" style="--track-index:${index}">
        ${appTrackIcon(app)}
        <span class="app-track-label">${escapeHtml(app.name)}</span>
      </div>`;
  }

  function renderAppTrack(apps, enter = false) {
    const list = asArray(apps).filter((app) => app && app.name);
    const nextKeys = new Set(list.map(appTrackKey));
    if (!list.length) {
      state.dashboard.appTrackKeys = nextKeys;
      return `
        <div class="dashboard-app-track is-empty" aria-label="在线应用轨道">
          <span class="app-track-empty">等待 DPI 应用数据</span>
        </div>`;
    }
    const html = `
      <div class="dashboard-app-track" aria-label="在线应用轨道">
        <span class="app-track-fade left" aria-hidden="true"></span>
        <span class="app-track-fade right" aria-hidden="true"></span>
        <div class="app-track-strip">
          ${list.map((app, index) => appTrackItem(app, index, enter)).join('')}
        </div>
      </div>`;
    state.dashboard.appTrackKeys = nextKeys;
    return html;
  }

  function dashboardAppTrackList(apps) {
    const seen = new Set();
    return asArray(apps).filter((app) => {
      if (!app || !app.name) return false;
      const key = appTrackKey(app);
      if (!key || seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  function appTrackAppFromItem(item) {
    if (!item) return null;
    const key = item.dataset.dashboardAppKey || '';
    const name = item.dataset.dashboardAppName || (appTrackLabelElement(item) && appTrackLabelElement(item).textContent || '').trim();
    if (!key || !name) return null;
    return {
      id: key,
      trackKey: key,
      name,
      icon: item.dataset.dashboardAppIcon || '',
      upRate: 0,
      downRate: 0,
      clients: 0,
      domains: [],
      devices: []
    };
  }

  function orderedDashboardAppTrackList(apps, strip) {
    const incoming = dashboardAppTrackList(apps);
    const now = Date.now();
    const missingSince = state.dashboard.appTrackMissingSince || (state.dashboard.appTrackMissingSince = new Map());
    const lastApps = state.dashboard.appTrackLastApps || (state.dashboard.appTrackLastApps = new Map());
    incoming.forEach((app) => {
      const key = appTrackKey(app);
      missingSince.delete(key);
      lastApps.set(key, app);
    });
    if (!strip) return incoming;
    const byKey = new Map(incoming.map((app) => [appTrackKey(app), app]));
    const kept = [];
    strip.querySelectorAll('.app-track-item[data-dashboard-app-key]').forEach((item) => {
      if (item.classList.contains('app-track-ghost')) return;
      const key = item.dataset.dashboardAppKey;
      const app = byKey.get(key);
      if (app) {
        kept.push(app);
        return;
      }
      if (!missingSince.has(key)) missingSince.set(key, now);
      if (now - (missingSince.get(key) || now) <= APP_TRACK_REMOVE_GRACE_MS) {
        const held = lastApps.get(key) || appTrackAppFromItem(item);
        if (held) kept.push(held);
      } else {
        missingSince.delete(key);
        lastApps.delete(key);
      }
    });
    if (!kept.length) return incoming;
    const keptKeys = new Set(kept.map(appTrackKey));
    const added = incoming.filter((app) => !keptKeys.has(appTrackKey(app)));
    return kept.concat(added);
  }

  function appTrackItemFromHtml(app, index, enter = false) {
    const wrap = document.createElement('div');
    wrap.innerHTML = appTrackItem(app, index, enter).trim();
    return wrap.firstElementChild;
  }

  function appTrackLabelElement(item) {
    return item && (item.querySelector('.app-track-label') || item.querySelector(':scope > span:last-child'));
  }

  function updateAppTrackItem(item, app, index) {
    if (!item || !app) return;
    setAppTrackTooltip(item, app);
    item.style.setProperty('--track-index', index);
    const name = app.name || '';
    if (item.dataset.dashboardAppName !== name) {
      item.dataset.dashboardAppName = name;
      const label = appTrackLabelElement(item);
      if (label && label.textContent !== name) label.textContent = name;
    }
    const icon = app.icon || '';
    if (item.dataset.dashboardAppIcon !== icon) {
      item.dataset.dashboardAppIcon = icon;
      const currentIcon = item.querySelector('.app-track-icon');
      if (currentIcon) currentIcon.outerHTML = appTrackIcon(app);
    }
  }

  function startAppTrackEnter(item, strip) {
    if (!item) return;
    const distance = Math.max(44, Math.min(140, (strip && strip.clientWidth ? strip.clientWidth * 0.18 : 72)));
    item.style.setProperty('--app-track-enter-x', `${distance}px`);
    window.requestAnimationFrame(() => {
      item.classList.remove('is-entering');
      window.setTimeout(() => {
        item.style.removeProperty('--app-track-enter-x');
      }, APP_TRACK_ENTER_MS + 60);
    });
  }

  function appTrackItemRectMap(strip) {
    const rects = new Map();
    if (!strip) return rects;
    strip.querySelectorAll('.app-track-item[data-dashboard-app-key]').forEach((item) => {
      if (item.classList.contains('app-track-ghost')) return;
      rects.set(item.dataset.dashboardAppKey, item.getBoundingClientRect());
    });
    return rects;
  }

  function animateAppTrackMoves(strip, firstRects, skipItems = new Set()) {
    if (!strip || !firstRects || !firstRects.size) return;
    const items = Array.from(strip.querySelectorAll('.app-track-item[data-dashboard-app-key]'));
    items.forEach((item) => {
      if (skipItems.has(item)) return;
      const key = item.dataset.dashboardAppKey;
      const first = firstRects.get(key);
      if (!first) return;
      const last = item.getBoundingClientRect();
      const dx = first.left - last.left;
      const dy = first.top - last.top;
      if (Math.abs(dx) < 0.5 && Math.abs(dy) < 0.5) return;
      item.classList.add('is-moving');
      item.style.transition = 'none';
      item.style.transform = `translate(${dx}px, ${dy}px)`;
      item.getBoundingClientRect();
      window.requestAnimationFrame(() => {
        item.style.transition = '';
        item.style.transform = '';
        window.setTimeout(() => {
          item.classList.remove('is-moving');
          item.style.transition = '';
          item.style.transform = '';
        }, APP_TRACK_MOVE_MS + 80);
      });
    });
  }

  function animateAppTrackGhostLeave(item, track) {
    if (!item || !track) return;
    const itemRect = item.getBoundingClientRect();
    const trackRect = track.getBoundingClientRect();
    const ghost = item.cloneNode(true);
    ghost.classList.add('app-track-ghost');
    ghost.classList.remove('is-entering', 'is-moving');
    ghost.style.left = `${itemRect.left - trackRect.left}px`;
    ghost.style.top = `${itemRect.top - trackRect.top}px`;
    ghost.style.width = `${itemRect.width}px`;
    ghost.style.height = `${itemRect.height}px`;
    ghost.style.setProperty('--track-index', item.style.getPropertyValue('--track-index') || '0');
    track.appendChild(ghost);
    window.requestAnimationFrame(() => {
      ghost.classList.add('is-leaving');
      window.setTimeout(() => ghost.remove(), APP_TRACK_EXIT_MS + 80);
    });
  }

  function showAppTrackEmptyWhenSettled(mount) {
    window.clearTimeout(state.dashboard.appTrackEmptyTimer);
    state.dashboard.appTrackEmptyTimer = window.setTimeout(() => {
      state.dashboard.appTrackEmptyTimer = 0;
      const strip = mount && mount.querySelector('.app-track-strip');
      if (strip && strip.querySelector('.app-track-item[data-dashboard-app-key]')) return;
      if (mount && !dashboardAppTrackList(state.dashboard.lastModel && state.dashboard.lastModel.apps).length) {
        mount.innerHTML = renderAppTrack([]);
      }
    }, APP_TRACK_EXIT_MS + 90);
  }

  function patchAppTrack(root, apps) {
    let list = dashboardAppTrackList(apps);
    window.clearTimeout(state.dashboard.appTrackEmptyTimer);
    state.dashboard.appTrackEmptyTimer = 0;
    let track = root && root.querySelector('.dashboard-app-track');
    let strip = root && root.querySelector('.app-track-strip');
    if (!root) return;
    list = orderedDashboardAppTrackList(apps, strip);
    if (!list.length) {
      if (!strip) {
        root.innerHTML = renderAppTrack([]);
        root.dataset.dashboardAppEmptyConfirmed = '';
        return;
      }
      const oldItems = Array.from(strip.querySelectorAll('.app-track-item[data-dashboard-app-key]'));
      if (oldItems.length && root.dataset.dashboardAppEmptyConfirmed !== '1') {
        root.dataset.dashboardAppEmptyConfirmed = '1';
        state.dashboard.appTrackEmptyTimer = window.setTimeout(() => {
          state.dashboard.appTrackEmptyTimer = 0;
          if (state.dashboard.active) patchAppTrack(root, []);
        }, APP_TRACK_EMPTY_GRACE_MS);
        return;
      }
      const firstRects = appTrackItemRectMap(strip);
      oldItems.forEach((item) => {
        animateAppTrackGhostLeave(item, track);
        item.remove();
      });
      animateAppTrackMoves(strip, firstRects);
      state.dashboard.appTrackKeys = new Set();
      state.dashboard.appTrackStructureKey = '';
      showAppTrackEmptyWhenSettled(root);
      return;
    }

    root.dataset.dashboardAppEmptyConfirmed = '';
    if (!track || !strip) {
      root.innerHTML = renderAppTrack(list, true);
      track = root.querySelector('.dashboard-app-track');
      strip = root.querySelector('.app-track-strip');
      normalizeVisibleArtworkIcons(root);
      Array.from(strip ? strip.querySelectorAll('.app-track-item.is-entering') : []).forEach((item) => startAppTrackEnter(item, strip));
      state.dashboard.appTrackStructureKey = appTrackStructureKey(list);
      return;
    }

    track.classList.remove('is-empty');
    const firstRects = appTrackItemRectMap(strip);
    const appByKey = new Map();
    list.forEach((app, index) => appByKey.set(appTrackKey(app), { app, index }));
    const nextKeys = new Set(appByKey.keys());
    const existing = new Map(Array.from(strip.querySelectorAll('.app-track-item[data-dashboard-app-key]')).map((item) => [item.dataset.dashboardAppKey, item]));
    const entering = new Set();

    existing.forEach((item, key) => {
      const next = appByKey.get(key);
      if (!next) {
        animateAppTrackGhostLeave(item, track);
        item.remove();
        return;
      }
      updateAppTrackItem(item, next.app, next.index);
    });

    list.forEach((app, index) => {
      const key = appTrackKey(app);
      const existingItem = existing.get(key);
      if (existingItem) return;
      const item = appTrackItemFromHtml(app, index, true);
      if (!item) return;
      entering.add(item);
      strip.appendChild(item);
    });

    animateAppTrackMoves(strip, firstRects, entering);
    entering.forEach((item) => startAppTrackEnter(item, strip));
    normalizeVisibleArtworkIcons(root);
    state.dashboard.appTrackKeys = nextKeys;
    state.dashboard.appTrackStructureKey = appTrackStructureKey(list);
  }

  function rankIcon(item, index, kind) {
    if (kind === 'app' && item.icon) {
      return `<span class="rank-icon app"><img src="${escapeHtml(item.icon)}" alt="" loading="lazy" onerror="this.closest('.rank-icon').classList.add('is-missing'); this.remove();"></span>`;
    }
    const text = kind === 'client'
      ? Array.from(item.name || '?').slice(0, 1).join('').toUpperCase()
      : String(index + 1);
    if (kind === 'client' && item.image) {
      return `<span class="rank-icon client has-image" data-fallback="${escapeHtml(text || '?')}"><img src="${escapeHtml(item.image)}" alt="" loading="lazy" onerror="const holder=this.closest('.rank-icon'); holder.classList.remove('has-image'); holder.classList.add('is-missing'); this.remove();"></span>`;
    }
    return `<span class="rank-icon ${escapeHtml(kind)}">${escapeHtml(text || '?')}</span>`;
  }

  function appDeviceMacs(item) {
    const devices = asArray(item && item.devices).map(normalizeAppDevice).filter(Boolean);
    return uniqueStrings(devices.map((device) => device.mac), 64);
  }

  function appDeviceValue(item) {
    const devices = asArray(item && item.devices).map(normalizeAppDevice).filter(Boolean);
    const macs = appDeviceMacs(item);
    if (macs.length) return macs.length === 1 ? macs[0] : `${macs[0]} ...`;
    const names = uniqueStrings(devices.map((device) => device.name || device.ip), 2);
    if (names.length) return names.length === 1 ? names[0] : `${names[0]} ...`;
    return '';
  }

  function appDeviceTooltip(item) {
    const macs = appDeviceMacs(item);
    if (!macs.length) return '';
    return `设备 MAC：${macs.join(' · ')}`;
  }

  function rankValue(item, kind) {
    const rate = firstNumber(item.downRate) + firstNumber(item.upRate);
    if (kind === 'client') return formatRate(rate);
    if (item.totalBytes) return formatBytes(item.totalBytes);
    if (rate) return formatRate(rate);
    if (kind === 'app') {
      const deviceValue = appDeviceValue(item);
      if (deviceValue) return deviceValue;
    }
    if (item.connections) return `${formatInteger(item.connections)} 连接`;
    return '--';
  }

  function rankSecondary(item, kind) {
    return kind === 'client'
      ? [item.ip, item.detail, item.connections ? `${formatInteger(item.connections)} 连接` : ''].filter(Boolean).join(' · ')
      : [item.category, item.evidence, item.clients ? `${formatInteger(item.clients)} 台设备` : ''].filter(Boolean).join(' · ');
  }

  function rankRatesMarkup(item, kind) {
    const down = firstNumber(item.downRate);
    const up = firstNumber(item.upRate);
    if (kind === 'client') return `<span class="rank-rates"><b data-rank-rate="down">↓ ${escapeHtml(formatRate(down))}</b><b data-rank-rate="up">↑ ${escapeHtml(formatRate(up))}</b></span>`;
    return down || up
      ? `<span class="rank-rates"><b data-rank-rate="down">↓ ${escapeHtml(formatRate(down))}</b><b data-rank-rate="up">↑ ${escapeHtml(formatRate(up))}</b></span>`
      : '';
  }

  function rankRow(item, index, kind) {
    const secondary = rankSecondary(item, kind);
    const rates = rankRatesMarkup(item, kind);
    const key = rankStructureItem(item, index, kind).key;
    const tooltip = kind === 'app' ? appDeviceTooltip(item) : '';
    const valueTitle = tooltip || rankValue(item, kind);
    return `
      <li class="dashboard-rank-row" data-dashboard-rank-key="${escapeHtml(key)}">
        <span class="rank-index">${String(index + 1).padStart(2, '0')}</span>
        ${rankIcon(item, index, kind)}
        <span class="rank-copy">
          <strong>${escapeHtml(item.name)}</strong>
          <small>${escapeHtml(secondary || (kind === 'client' ? '真实终端数据' : '真实 DPI 数据'))}</small>
        </span>
        <span class="rank-value">
          <strong title="${escapeHtml(valueTitle)}" ${tooltip ? `data-dwrt-tooltip="${escapeHtml(tooltip)}"` : ''}>${escapeHtml(rankValue(item, kind))}</strong>
          ${rates}
        </span>
      </li>`;
  }

  function renderRankCard(title, subtitle, items, kind) {
    const rows = asArray(items);
    return `
      <article class="dashboard-rank-card dwrt-glass-card" data-dashboard-rank-kind="${escapeHtml(kind)}">
        <header class="dashboard-section-head">
          <div>
            <span>${escapeHtml(subtitle)}</span>
            <h2>${escapeHtml(title)}</h2>
          </div>
          <strong>Top17</strong>
        </header>
        ${rows.length ? `
          <ol class="dashboard-rank-list">
            ${rows.map((item, index) => rankRow(item, index, kind)).join('')}
          </ol>` : `
          <div class="dashboard-data-empty">
            <strong>${kind === 'client' ? '暂无真实终端排行' : '暂无真实应用排行'}</strong>
            <span>${kind === 'client' ? '等待 webd 返回在线终端流量字段' : '等待 jmxd/webd 输出在线 APP 或协议排行'}</span>
          </div>`}
      </article>`;
  }

  function rankStructureItem(item, index, kind) {
    return {
      key: firstText(item.id, item.mac, item.ip, kind === 'app' ? appDisplayKey(item) : '', item.name, `${kind}-${index}`),
      name: item.name || '',
      icon: item.icon || item.image || '',
      kind
    };
  }

  function rankStructureList(items, kind) {
    return asArray(items).map((item, index) => rankStructureItem(item, index, kind))
      .sort((a, b) => String(a.key).localeCompare(String(b.key)));
  }

  function rankStructureKey(ranks = {}) {
    return stableSignature({
      clients: rankStructureList(ranks.clients, 'client'),
      apps: rankStructureList(ranks.apps, 'app')
    });
  }

  function updateRankValues(items, kind) {
    if (!dashboardRankGrid) return;
    const card = dashboardRankGrid.querySelector(`[data-dashboard-rank-kind="${kind}"]`);
    const list = card && card.querySelector('.dashboard-rank-list');
    const rows = new Map(Array.from(card ? card.querySelectorAll('.dashboard-rank-row[data-dashboard-rank-key]') : []).map((row) => [row.dataset.dashboardRankKey, row]));
    asArray(items).forEach((item, index) => {
      const key = rankStructureItem(item, index, kind).key;
      const row = rows.get(key);
      if (!row) return;
      const indexEl = row.querySelector('.rank-index');
      const indexText = String(index + 1).padStart(2, '0');
      if (indexEl && indexEl.textContent !== indexText) indexEl.textContent = indexText;
      const small = row.querySelector('.rank-copy small');
      const secondary = rankSecondary(item, kind) || (kind === 'client' ? '真实终端数据' : '真实 DPI 数据');
      if (small && small.textContent !== secondary) small.textContent = secondary;
      const value = row.querySelector('.rank-value');
      if (value) {
        const strong = value.querySelector(':scope > strong');
        const nextValue = rankValue(item, kind);
        const tooltip = kind === 'app' ? appDeviceTooltip(item) : '';
        const title = tooltip || nextValue;
        if (strong) {
          if (strong.textContent !== nextValue) strong.textContent = nextValue;
          if (strong.getAttribute('title') !== title) strong.setAttribute('title', title);
          if (tooltip) strong.setAttribute('data-dwrt-tooltip', tooltip);
          else strong.removeAttribute('data-dwrt-tooltip');
        }
        const shouldShowRates = kind === 'client' || firstNumber(item.downRate) || firstNumber(item.upRate);
        let rates = value.querySelector(':scope > .rank-rates');
        if (shouldShowRates && !rates) {
          const template = document.createElement('template');
          template.innerHTML = rankRatesMarkup(item, kind).trim();
          rates = template.content.firstElementChild;
          if (rates) value.appendChild(rates);
        }
        if (!shouldShowRates && rates) {
          rates.remove();
        } else if (rates) {
          const down = `↓ ${formatRate(firstNumber(item.downRate))}`;
          const up = `↑ ${formatRate(firstNumber(item.upRate))}`;
          const downNode = rates.querySelector('[data-rank-rate="down"]');
          const upNode = rates.querySelector('[data-rank-rate="up"]');
          if (downNode && downNode.textContent !== down) downNode.textContent = down;
          if (upNode && upNode.textContent !== up) upNode.textContent = up;
        }
      }
      if (list && row.parentElement === list) list.appendChild(row);
    });
  }


  function rankListScrollState() {
    if (!dashboardRankGrid) return {};
    const stateMap = {};
    dashboardRankGrid.querySelectorAll('.dashboard-rank-card[data-dashboard-rank-kind]').forEach((card) => {
      const list = card.querySelector('.dashboard-rank-list');
      if (!list) return;
      stateMap[card.dataset.dashboardRankKind] = list.scrollTop;
    });
    return stateMap;
  }

  function restoreRankListScroll(scrollState) {
    if (!dashboardRankGrid || !scrollState) return;
    window.requestAnimationFrame(() => {
      Object.entries(scrollState).forEach(([kind, top]) => {
        const list = dashboardRankGrid.querySelector(`.dashboard-rank-card[data-dashboard-rank-kind="${kind}"] .dashboard-rank-list`);
        if (!list || !(top > 0)) return;
        list.scrollTop = Math.min(top, Math.max(0, list.scrollHeight - list.clientHeight));
      });
    });
  }

  function renderRankSections(model) {
    if (!dashboardRankGrid) return;
    const ranks = model.ranks || {};
    const scrollState = rankListScrollState();
    const structureKey = rankStructureKey(ranks);
    let structureChanged = false;
    if (state.dashboard.rankStructureKey !== structureKey) {
      state.dashboard.rankStructureKey = structureKey;
      dashboardRankGrid.innerHTML = [
        renderRankCard('终端流量排行', '当前在线与实时速率', ranks.clients || [], 'client'),
        renderRankCard('应用/协议排行', 'DPI 识别与流量占比', ranks.apps || [], 'app')
      ].join('');
      structureChanged = true;
    }
    updateRankValues(ranks.clients || [], 'client');
    updateRankValues(ranks.apps || [], 'app');
    normalizeVisibleArtworkIcons(dashboardRankGrid);
    if (structureChanged) window.DWRT_UI_KIT?.mountAll(dashboardRankGrid);
    restoreRankListScroll(scrollState);
  }

  function compactUrl(url) {
    const text = String(url || '').replace(/^https?:\/\//i, '');
    if (text.length <= 58) return text;
    return `${text.slice(0, 28)}…${text.slice(-24)}`;
  }

  function activeUrlAppName(item, urlLabel) {
    const app = appDisplayName({
      ...item,
      app_name: firstText(item.app_name, item.appname),
      application: firstText(item.application, item.dpi_app, item.app)
    });
    if (!app) return '';
    const appKey = app.toLowerCase();
    const urlKey = firstText(urlLabel, item.url).toLowerCase();
    if (appKey === 'url' || appKey === urlKey || looksLikeUrl(app)) return '';
    return app;
  }

  function activeUrlLabel(item) {
    const urlLabel = compactUrl(item.url);
    const app = activeUrlAppName(item, urlLabel);
    return app ? `${urlLabel} · ${app}` : urlLabel;
  }

  function activeUrlRow(item) {
    const label = activeUrlLabel(item);
    const traffic = firstNumber(item.downBytes) || firstNumber(item.upBytes)
      ? `<span class="active-url-traffic">↓ ${escapeHtml(formatBytes(item.downBytes))} · ↑ ${escapeHtml(formatBytes(item.upBytes))}</span>`
      : '';
    return `
      <li class="active-url-row is-single">
        <span class="active-url-dot" aria-hidden="true"></span>
        <span class="active-url-copy">
          <strong title="${escapeHtml(item.url)}">${escapeHtml(label)}</strong>
        </span>
        ${traffic || `<span class="active-url-traffic">${item.duration ? escapeHtml(formatUptime(item.duration)) : ''}</span>`}
      </li>`;
  }

  function renderActiveUrlSection(model) {
    if (!dashboardActiveUrlCard) return;
    const urls = asArray(model.activeUrls);
    const html = `
      <header class="dashboard-section-head">
        <div>
          <span>URL activity</span>
          <h2>Active URLs</h2>
        </div>
        <strong>${urls.length ? formatInteger(urls.length) : '--'}</strong>
      </header>
      ${urls.length ? `
        <ul class="active-url-list">
          ${urls.map(activeUrlRow).join('')}
        </ul>` : `
        <div class="dashboard-data-empty">
          <strong>暂无真实 Active URL</strong>
          <span>webd 当前返回 active_urls 为空；已记录后端缺口。</span>
        </div>`}`;
    const oldList = dashboardActiveUrlCard.querySelector('.active-url-list');
    const oldScrollTop = oldList ? oldList.scrollTop : 0;
    const changed = setSectionHtml(dashboardActiveUrlCard, 'activeUrls', html);
    if (changed && oldScrollTop > 0) {
      window.requestAnimationFrame(() => {
        const nextList = dashboardActiveUrlCard.querySelector('.active-url-list');
        if (nextList) nextList.scrollTop = Math.min(oldScrollTop, Math.max(0, nextList.scrollHeight - nextList.clientHeight));
      });
    }
  }

  function renderMonitorToolbar(wans, activeWan, ranges) {
    const toolbar = monitorPart('[data-dashboard-monitor-toolbar]');
    const activeWanId = selectedDashboardWanId();
    const choices = [{ id: 'all', name: 'ALL' }, ...asArray(wans)];
    const html = `
      <div class="dashboard-segmented" aria-label="WAN 选择">
        ${choices.map((wan) => `
          <button type="button" data-dashboard-wan="${escapeHtml(wan.id || wan.name || 'all')}" class="${selectedDashboardWanId(wan.id || wan.name) === activeWanId ? 'is-active primary' : ''}">
            ${escapeHtml((wan.name || wan.id || 'WAN').toUpperCase())}
          </button>`).join('')}
      </div>
      <div class="dashboard-segmented compact" aria-label="时间范围">
        ${ranges.map((range) => `<button type="button" data-dashboard-range="${range.id}" class="${state.dashboard.trafficRange === range.id ? 'is-active' : ''}">${escapeHtml(range.label)}</button>`).join('')}
      </div>`;
    setSectionHtml(toolbar, 'monitorToolbar', html);
  }

  function renderMonitorMetrics(latest) {
    const metrics = monitorPart('[data-dashboard-monitor-metrics]');
    if (!metrics) return;
    if (!metrics.querySelector('[data-dashboard-monitor-metric="down"]')) {
      metrics.innerHTML = `
      <button type="button" class="monitor-tile down is-visible" data-dashboard-monitor-metric="down">
        <span>下行</span>
        <strong></strong>
        <small>实时速率</small>
      </button>
      <button type="button" class="monitor-tile up is-visible" data-dashboard-monitor-metric="up">
        <span>上行</span>
        <strong></strong>
        <small>实时速率</small>
      </button>
      <button type="button" class="monitor-tile latency" data-dashboard-monitor-metric="latency">
        <span>延迟</span>
        <strong></strong>
        <small></small>
      </button>
      <button type="button" class="monitor-tile connections is-visible" data-dashboard-monitor-metric="connections">
        <span>连接数</span>
        <strong></strong>
        <small>系统连接</small>
      </button>`;
    }
    const values = {
      down: [formatRate(latest.down), '实时速率', true],
      up: [formatRate(latest.up), '实时速率', true],
      latency: [formatLatency(latest.latency), latest.latency ? 'WAN 实测' : '后端暂无有效延迟', Boolean(latest.latency)],
      connections: [formatInteger(latest.connections), '系统连接', true]
    };
    Object.entries(values).forEach(([key, value]) => {
      const tile = metrics.querySelector(`[data-dashboard-monitor-metric="${key}"]`);
      if (!tile) return;
      const strong = tile.querySelector('strong');
      const small = tile.querySelector('small');
      if (strong && strong.textContent !== value[0]) strong.textContent = value[0];
      if (small && small.textContent !== value[1]) small.textContent = value[1];
      tile.classList.toggle('is-visible', value[2]);
      tile.classList.toggle('is-muted', !value[2]);
    });
  }

  function patchTrafficChart(wrap, chart) {
    const frame = wrap?.querySelector('[data-dashboard-chart]');
    if (!frame || frame.dataset.dashboardChart !== chart.rangeId) return false;
    const paths = [
      ['.chart-area.down', 'd', chart.downArea],
      ['.chart-area.up', 'd', chart.upArea],
      ['.chart-line.down', 'd', chart.downLine],
      ['.chart-line.up', 'd', chart.upLine],
      ['.chart-line.connections', 'points', chart.connLine],
      ['.chart-line.latency', 'points', chart.latencyLine]
    ];
    if (paths.some(([selector, , value]) => Boolean(frame.querySelector(selector)) !== Boolean(value))) return false;
    if (Boolean(frame.querySelector('.dashboard-chart-empty')) !== Boolean(chart.empty)) return false;
    const yTicks = Array.from(frame.querySelectorAll('.dashboard-chart-yaxis span'));
    const xTicks = Array.from(frame.querySelectorAll('.dashboard-chart-xaxis span'));
    if (yTicks.length !== chart.ticks.yTicks.length || xTicks.length !== chart.ticks.xTicks.length) return false;
    paths.forEach(([selector, attribute, value]) => {
      const node = frame.querySelector(selector);
      if (node && node.getAttribute(attribute) !== value) node.setAttribute(attribute, value);
    });
    chart.ticks.yTicks.forEach((tick, index) => {
      const node = yTicks[index];
      const top = `${(1 - tick.pos) * 100}%`;
      if (node.style.top !== top) node.style.top = top;
      if (node.textContent !== tick.label) node.textContent = tick.label;
    });
    chart.ticks.xTicks.forEach((tick, index) => {
      const node = xTicks[index];
      const left = `${(tick.pos * 100).toFixed(2)}%`;
      if (node.style.left !== left) node.style.left = left;
      if (node.textContent !== tick.label) node.textContent = tick.label;
    });
    return true;
  }

  function renderMonitorChart(history) {
    const wrap = monitorPart('[data-dashboard-chart-wrap]');
    if (state.dashboard.chartHovering && wrap && wrap.querySelector('.dashboard-chart-tooltip:not([hidden])')) {
      state.dashboard.pendingChartHistory = history;
      return;
    }
    const html = renderTrafficChart(history);
    if (patchTrafficChart(wrap, state.dashboard.chartState)) {
      sectionKeys().monitorChart = html;
      return;
    }
    delete sectionKeys().monitorChart;
    setSectionHtml(wrap, 'monitorChart', html, bindDashboardChartInteractions);
  }

  function renderMonitorAvailability(wans) {
    const row = monitorPart('[data-dashboard-availability]');
    const list = asArray(wans).length ? asArray(wans) : [{ id: 'wan', name: 'WAN', online: false, status: 'unknown' }];
    const html = list.map((wan, index) => {
      const availability = wanAvailability(wan);
      const width = availability.known ? Math.max(0, Math.min(100, availability.value)).toFixed(2) : 0;
      const label = firstText(wan.name, wan.id, `WAN ${index + 1}`);
      const tone = firstText(availability.tone, 'ok');
      const carrier = carrierMeta(wan || {}).label;
      const description = `${carrier && carrier !== label ? `${carrier} ` : ''}${label}，可用率 ${availability.label}，${availability.stateLabel || '状态未知'}`;
      return `<button type="button" class="dashboard-wan-availability is-${escapeHtml(tone)}" data-wan-id="${escapeHtml(wan.id || label)}" title="${escapeHtml(`${label} · ${availability.label} · ${availability.stateLabel || ''}`)}" aria-label="${escapeHtml(description)}">
        ${carrierAvailabilityIcon(wan)}
        <span class="dashboard-availability-track" aria-hidden="true"><i style="width:${width}%"></i></span>
        <svg class="dashboard-wan-availability-chevron" viewBox="0 0 16 16" aria-hidden="true"><path d="M6 3.5 10.5 8 6 12.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </button>`;
    }).join('');
    setSectionHtml(row, 'monitorAvailability', html);
  }

  function renderMonitorAppTrack(apps) {
    const mount = monitorPart('[data-dashboard-app-track-mount]');
    if (!mount) return;
    patchAppTrack(mount, apps);
  }

  function renderDashboardMain(model) {
    const metricHtml = dashboardMetricCards(model).map(dashboardMetricCard).join('');
    setSectionHtml(dashboardMetricGrid, 'metricGrid', metricHtml);
    renderRankSections(model);
    renderActiveUrlSection(model);
    if (!ensureMonitorShell()) return;
    const wans = model.wans || [];
    const selectedWanId = selectedDashboardWanId();
    if (selectedWanId !== 'all' && !wans.some((wan) => selectedDashboardWanId(wan.id) === selectedWanId)) {
      state.dashboard.activeWanId = 'all';
    }
    const activeWan = selectedDashboardWanId() === 'all'
      ? { id: 'all', name: 'ALL' }
      : wans.find((wan) => selectedDashboardWanId(wan.id) === selectedDashboardWanId()) || { id: 'all', name: 'ALL' };
    const selectedRange = dashboardRangeMeta(state.dashboard.trafficRange).id;
    const history = visibleTrafficPoints(selectedRange);
    const latest = latestDashboardPoint(model);
    const ranges = DASHBOARD_HISTORY_RANGES;
    renderMonitorToolbar(wans, activeWan, ranges);
    renderMonitorMetrics(latest);
    renderMonitorChart(history);
    renderMonitorAvailability(wans);
    renderMonitorAppTrack(model.apps);
  }

  function patchDashboardThroughputRealtime(model) {
    if (!model || !ensureMonitorShell()) return;
    const wans = asArray(model.wans);
    updateWanRailRealtime(wans);
    renderMonitorMetrics(latestDashboardPoint(model));
    if (dashboardRangeMeta(state.dashboard.trafficRange).id === 'realtime' && state.dashboard.pendingRealtimeChartUpdate) {
      state.dashboard.pendingRealtimeChartUpdate = false;
      renderMonitorChart(visibleTrafficPoints('realtime'));
    }
  }

  function probeKey(wanId, host) {
    return `${firstText(wanId, 'wan')}:${firstText(host)}`;
  }

  function probeResult(wanId, host) {
    return state.dashboard.probeResults[probeKey(wanId, host)] || null;
  }

  function saveProbeResult(wanId, host, result) {
    state.dashboard.probeResults[probeKey(wanId, host)] = {
      ...(state.dashboard.probeResults[probeKey(wanId, host)] || {}),
      ...result
    };
  }

  function currentProbeButton(wanId, host) {
    if (!dashboardStatusRail) return null;
    return dashboardStatusRail.querySelector(`.rail-probe[data-wan-id="${cssAttr(firstText(wanId, 'wan'))}"][data-probe-host="${cssAttr(firstText(host))}"]`);
  }

  function updateProbeResult(wanId, host, result, fallbackButton) {
    saveProbeResult(wanId, host, result);
    renderProbeButton(currentProbeButton(wanId, host) || fallbackButton, result);
  }

  function waitProbePollDelay() {
    return new Promise((resolve) => window.setTimeout(resolve, PROBE_POLL_INTERVAL_MS));
  }

  function probeIcon(target) {
    if (target === 'apple') {
      return '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M16.7 12.6c0-2.4 2-3.6 2.1-3.7-1.1-1.6-2.8-1.9-3.4-1.9-1.5-.1-2.8.9-3.6.9-.7 0-1.9-.9-3.1-.8-1.6 0-3.1.9-3.9 2.4-1.7 2.9-.4 7.1 1.2 9.4.8 1.1 1.8 2.4 3 2.3 1.2 0 1.7-.8 3.1-.8s1.9.8 3.2.8 2.2-1.1 3-2.3c.9-1.3 1.3-2.6 1.3-2.7 0 0-2.9-1.1-2.9-3.6ZM14.4 5.5c.7-.9 1.2-2 1.1-3.2-1.1.1-2.3.7-3.1 1.6-.7.8-1.2 2-1.1 3.1 1.2.1 2.4-.6 3.1-1.5Z"/></svg>';
    }
    if (target === 'baidu') {
      return '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M9.1 0C7.7 0 6.5 1.7 6.5 3.7s1.2 3.7 2.6 3.7 2.6-1.7 2.6-3.7S10.6 0 9.1 0Zm7 .6c-1.3 0-2.8 2-2.9 3.3-.2 1.7.3 3.5 2.2 3.7 1.9.3 3.2-1.8 3.4-3.3.3-1.6-.9-3.4-2.4-3.7h-.3ZM3.6 5.5h-.2C1.3 5.7 1 8.8 1 8.8c-.3 1.4.7 4.4 3.3 3.9s2.3-3.7 2.2-4.4c-.1-1-1.3-2.8-2.9-2.8Zm16.5 1.8c-2.3 0-2.6 2.1-2.6 3.6 0 1.4.1 3.4 3 3.4s2.5-3.2 2.5-4c0-.7-.6-3-2.9-3Zm-8.3 2.5c-1.4 0-2.7.9-3.3 1.9-1.1 1.9-2.9 3.1-3.1 3.4-.3.3-3.6 2.1-2.9 5.4s3.4 3.2 3.4 3.2 1.9.2 4.2-.3c2.2-.5 4.2.1 4.2.1s5.2 1.7 6.7-1.6c1.4-3.4-.8-5.1-.8-5.1s-3-2.3-4.8-4.8c-1-1.7-2.3-2.3-3.6-2.2Z"/></svg>';
    }
    if (target === 'bilibili') {
      return '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M8.3 3.4 10 5.1h4l1.7-1.7c.4-.4 1-.4 1.4 0s.4 1 0 1.4l-.3.3h1.4c1.6 0 2.8 1.3 2.8 2.8v8.7c0 1.6-1.3 2.8-2.8 2.8H5.8C4.3 19.4 3 18.1 3 16.6V7.9c0-1.6 1.3-2.8 2.8-2.8h1.4l-.3-.3c-.4-.4-.4-1 0-1.4s1-.4 1.4 0ZM5 7.9v8.7c0 .5.4.8.8.8h12.4c.5 0 .8-.4.8-.8V7.9c0-.5-.4-.8-.8-.8H5.8c-.5 0-.8.4-.8.8Zm3.4 2.7c.6 0 1 .5 1 1v1c0 .6-.5 1-1 1s-1-.5-1-1v-1c0-.6.5-1 1-1Zm7.2 0c.6 0 1 .5 1 1v1c0 .6-.5 1-1 1s-1-.5-1-1v-1c0-.6.5-1 1-1Z"/></svg>';
    }
    return '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M8.7 2.2C3.9 2.2 0 5.5 0 9.5c0 2.2 1.2 4.2 3 5.6.2.1.3.4.2.7l-.4 1.5c0 .2.1.4.3.4l.2-.1 1.9-1.1c.2-.1.5-.2.7-.1.9.3 1.8.4 2.8.4h.8c-.9-2.6.1-5 1.9-6.4 1.7-1.4 3.9-2 5.9-1.8-.6-3.6-4.2-6.4-8.6-6.4Zm-2.9 3.8c.6 0 1.1.5 1.1 1.2 0 .6-.5 1.2-1.1 1.2S4.6 7.8 4.6 7.2 5.1 6 5.8 6Zm5.8 0c.6 0 1.2.5 1.2 1.2 0 .6-.5 1.2-1.2 1.2-.6 0-1.2-.5-1.2-1.2S11 6 11.6 6Zm5.3 2.9c-1.8 0-3.7.5-5.3 1.8-1.7 1.4-2.7 3.7-1.8 6.2.9 2.5 3.7 4.2 6.9 4.2.8 0 1.6-.1 2.4-.3.2-.1.4 0 .6.1l1.6.9h.1c.1 0 .2-.1.2-.2v-.2l-.3-1.2c-.1-.2 0-.4.2-.6 1.5-1.1 2.5-2.8 2.5-4.6 0-3.2-2.9-5.8-6.7-6.1h-.4Z"/></svg>';
  }

  function probeMarkup(wan, target) {
    const result = probeResult(wan.id, target.host);
    const fromWan = wan.probes && (wan.probes[target.host] || wan.probes[target.id] || wan.probes[target.label.toLowerCase()]);
    const value = result ? result.latency : Number(fromWan || 0);
    const pending = result && result.loading;
    const failed = result && result.error;
    const cls = pending ? 'loading' : failed ? 'failed' : value > 0 ? (value < 80 ? 'good' : value < 180 ? 'warn' : 'bad') : 'unknown';
    const label = pending ? '...' : failed ? '--' : value > 0 ? formatLatency(value) : 'Test';
    return `
      <button class="rail-probe ${escapeHtml(cls)}" type="button" data-wan-id="${escapeHtml(wan.id)}" data-probe-host="${escapeHtml(target.host)}" data-probe-id="${escapeHtml(target.id)}" title="${escapeHtml(`${target.label} · ${target.host}`)}">
        <span class="probe-icon ${escapeHtml(target.id)}">${probeIcon(target.id)}</span>
        <span class="probe-name">${escapeHtml(target.label)}</span>
        <strong class="probe-value">${escapeHtml(label)}</strong>
      </button>`;
  }

  async function readProbeOnce(wanId, host, id) {
    const urls = [
      `/api/v1/network/wans/${encodeURIComponent(wanId)}/probe?target=${encodeURIComponent(id)}&host=${encodeURIComponent(host)}`,
      `/api/v1/network/probe?wan_id=${encodeURIComponent(wanId)}&target=${encodeURIComponent(id)}&host=${encodeURIComponent(host)}`
    ];
    let body = null;
    let ok = false;
    let lastStatus = 0;
    for (const url of urls) {
      const response = session
        ? await session.fetch(url, {
          credentials: 'same-origin',
          cache: 'no-store'
        })
        : await fetch(url, {
        credentials: 'same-origin',
        cache: 'no-store',
        headers: authHeaders()
        });
      lastStatus = response.status;
      const text = await response.text();
      try { body = text ? JSON.parse(text) : null; } catch (_) { body = null; }
      if (!session && response.status === 401 && await refreshAuthToken()) {
        return readProbeOnce(wanId, host, id);
      }
      ok = response.ok && !(body && body.ok === false);
      if (ok || response.status !== 404) break;
    }
    const data = body && (body.data || body.body || body) || {};
    const latency = firstNumber(data.latency, data.latency_ms, data.avg, data.avg_ms, data.rtt, data.ms);
    const status = firstText(data.status, data.state).toLowerCase();
    const pending = data.pending === true || data.refreshing === true || status === 'pending' || status === 'running' || status === 'refreshing' || data.async === true && data.has_result !== true && !latency;
    const failed = !ok || ['failed', 'error', 'timeout', 'unavailable'].includes(status) || !pending && !latency;
    return { ok, statusCode: lastStatus, data, latency, status, pending, failed };
  }

  async function runProbe(button) {
    if (!button || button.classList.contains('loading')) return;
    const wanId = button.dataset.wanId || 'wan';
    const host = button.dataset.probeHost || '';
    const id = button.dataset.probeId || host;
    updateProbeResult(wanId, host, { loading: true, pending: true, error: false, latency: 0 }, button);
    try {
      let last = null;
      for (let attempt = 0; attempt < PROBE_POLL_LIMIT; attempt += 1) {
        last = await readProbeOnce(wanId, host, id);
        if (last.pending) {
          updateProbeResult(wanId, host, { loading: true, pending: true, error: false, latency: 0 }, button);
          if (attempt < PROBE_POLL_LIMIT - 1) {
            await waitProbePollDelay();
            continue;
          }
        }
        break;
      }
      updateProbeResult(wanId, host, {
        loading: false,
        pending: false,
        error: !last || last.failed || last.pending,
        latency: last && last.latency || 0
      }, button);
    } catch (_) {
      updateProbeResult(wanId, host, { loading: false, pending: false, error: true, latency: 0 }, button);
    }
  }

  function renderProbeButton(button, result) {
    if (!button) return;
    button.classList.remove('good', 'warn', 'bad', 'unknown', 'loading', 'failed');
    const valueEl = button.querySelector('.probe-value');
    if (result && result.loading) {
      button.classList.add('loading');
      if (valueEl) valueEl.textContent = '...';
      return;
    }
    if (result && result.error) {
      button.classList.add('failed');
      if (valueEl) valueEl.textContent = '--';
      return;
    }
    const latency = Number(result && result.latency);
    if (Number.isFinite(latency) && latency > 0) {
      button.classList.add(latency < 80 ? 'good' : latency < 180 ? 'warn' : 'bad');
      if (valueEl) valueEl.textContent = formatLatency(latency);
      return;
    }
    button.classList.add('unknown');
    if (valueEl) valueEl.textContent = 'Test';
  }

  function renderDashboardCard(model) {
    if (shouldDeferRender(dashboardWorkspace || document.body)) {
      state.dashboard.lastModel = model;
      window.clearTimeout(state.dashboard.deferredRenderTimer);
      state.dashboard.deferredRenderTimer = window.setTimeout(() => {
        if (state.dashboard.active && state.dashboard.lastModel) renderDashboardCard(state.dashboard.lastModel);
      }, 500);
      return;
    }
    model = preserveFreshThroughput(model);
    const wans = model.wans || [];
    const ports = model.ports || [];
    const freshThroughput = hasFreshThroughput();
    if (!freshThroughput) {
      appendWanRealtimePoints({
        ts: liveTimestampSeconds(
          model.traffic && model.traffic.ts,
          model.traffic && model.traffic.updated_at,
          model.system && model.system.ts,
          Date.now() / 1000
        ),
        wans
      });
      appendTrafficSample(model);
    }
    const renderKey = JSON.stringify({
      sys: model.system,
      lan: model.lan,
      wans,
      ports,
      traffic: model.traffic,
      apps: model.apps,
      activeUrls: model.activeUrls,
      ranks: model.ranks,
      clients: model.clients,
      errors: model.errors.map((item) => `${item.name}:${item.error && item.error.status || ''}:${item.error && item.error.message || ''}`)
    });
    if (state.dashboard.lastRenderKey === renderKey) {
      renderDashboardMain(model);
      return;
    }
    state.dashboard.lastRenderKey = renderKey;
    state.dashboard.lastModel = model;

    setText('railModel', displayBrandName(firstText(model.system.hostname, model.system.model, 'Dreaming OS')));
    setText('railVersion', firstText(model.system.build_date, model.system.build_id, '--'));
    setText('railGatewayIp', firstText(model.lan.ip, model.lan.ipaddr, model.lan.gateway));
    setText('railUptime', formatUptime(model.system.uptime));
    setText('railWanTotal', wans.length ? `${wans.length} WAN` : '--');
    setText('railPortTotal', ports.length ? `${ports.length}` : '--');

    if (model.errors.length) {
      const authError = model.errors.find((item) => item.error && item.error.status === 401);
      const uptime = formatUptime(model.system.uptime);
      const statusText = uptime === '--' ? dashboardStatusSummary(model).title : `系统运行时间：${uptime}`;
      setDashboardStatus(authError ? '认证已过期，请重新登录' : statusText, authError ? 'error' : 'warn');
    } else {
      setDashboardStatus(`系统运行时间：${formatUptime(model.system.uptime)}`, 'ok');
    }
    renderWanCards(wans);
    renderPortCards(ports, wans);
    renderDashboardMain(model);
  }

  function wanUsageSummary(wan) {
    if (!wan) return null;
    const explicitLabel = firstText(wan.monthlyUsageLabel);
    const monthlyUsage = firstNumber(wan.monthlyUsageBytes);
    const monthlyLimit = firstNumber(wan.monthlyLimitBytes);
    const monthlyLimitLabel = firstText(wan.monthlyLimitLabel);
    if (explicitLabel) {
      return { title: '月度数据使用量', label: explicitLabel, source: 'monthly-label' };
    }
    if (monthlyUsage > 0) {
      const usageLabel = formatBytes(monthlyUsage);
      if (monthlyLimit > 0) return { title: '月度数据使用量', label: `${usageLabel} / ${formatBytes(monthlyLimit)}`, source: 'monthly-bytes' };
      if (monthlyLimitLabel) return { title: '月度数据使用量', label: `${usageLabel} / ${monthlyLimitLabel}`, source: 'monthly-bytes' };
      return { title: '月度数据使用量', label: usageLabel, source: 'monthly-bytes' };
    }
    const lineUsage = firstNumber(wan.downBytes) + firstNumber(wan.upBytes);
    if (lineUsage > 0) {
      return { title: '流量用量', label: formatBytes(lineUsage), source: 'wan-bytes' };
    }
    return null;
  }

  function wanRealtimePoints(wan) {
    const key = wanRealtimeKey(wan || {}, 0);
    const direct = key ? state.dashboard.wanRealtimePoints.get(key) : null;
    if (asArray(direct).length >= 2) return asArray(direct);
    const candidates = uniqueStrings([
      wan && wan.name,
      wan && wan.ifname,
      wan && wan.device
    ], 4);
    for (const candidate of candidates) {
      const points = state.dashboard.wanRealtimePoints.get(candidate);
      if (asArray(points).length >= 2) return asArray(points);
    }
    return [];
  }

  function throughputSparkPoints(wan) {
    const perWanPoints = wanRealtimePoints(wan);
    if (perWanPoints.length >= 2) {
      return perWanPoints.slice(-56).map((point) => ({
        ts: firstNumber(point.ts),
        down: firstNumber(point.down, point.downRate),
        up: firstNumber(point.up, point.upRate)
      }));
    }
    const wanId = selectedDashboardWanId(wan && wan.id);
    const realtime = visibleTrafficPoints('realtime', wanId);
    const hour = visibleTrafficPoints('1h', wanId);
    let points = asArray(realtime.points).length >= 3 ? asArray(realtime.points) : asArray(hour.points);
    points = points.slice(-32).filter((point) => point && Number.isFinite(Number(point.ts)));
    if (!points.length) {
      const now = Date.now() / 1000;
      points = [
        { ts: now - 30, down: firstNumber(wan && wan.downRate), up: firstNumber(wan && wan.upRate) },
        { ts: now, down: firstNumber(wan && wan.downRate), up: firstNumber(wan && wan.upRate) }
      ];
    }
    return points.map((point) => ({
      ts: firstNumber(point.ts),
      down: firstNumber(point.down, point.downRate),
      up: firstNumber(point.up, point.upRate)
    }));
  }

  function renderWanThroughputParts(wan) {
    const width = 280;
    const height = 78;
    const points = throughputSparkPoints(wan);
    const maxValue = valueMax(points, ['down', 'up']);
    const downPath = sparkSmoothLine(points, width, height, 'down', maxValue, 0, 7);
    const upPath = sparkSmoothLine(points, width, height, 'up', maxValue, 0, 7);
    const downArea = downPath ? `${downPath} L${width} ${height} L0 ${height} Z` : '';
    return { width, height, downPath, upPath, downArea };
  }

  function updateWanThroughputMini(card, wan) {
    if (!card) return;
    const rates = card.querySelector('.rail-throughput-rates');
    if (rates) {
      const html = `<b class="down">↓ ${escapeHtml(formatRate(wan.downRate))}</b><b class="up">↑ ${escapeHtml(formatRate(wan.upRate))}</b>`;
      if (rates.innerHTML !== html) rates.innerHTML = html;
    }
    const parts = renderWanThroughputParts(wan);
    const area = card.querySelector('.rail-throughput-area.down');
    const down = card.querySelector('.rail-throughput-line.down');
    const up = card.querySelector('.rail-throughput-line.up');
    if (area && area.getAttribute('d') !== parts.downArea) area.setAttribute('d', parts.downArea);
    if (down && down.getAttribute('d') !== parts.downPath) down.setAttribute('d', parts.downPath);
    if (up && up.getAttribute('d') !== parts.upPath) up.setAttribute('d', parts.upPath);
  }

  function sparkPointCoords(points, width, height, key, maxValue, xPad = 0, yPad = 4) {
    const rows = asArray(points).filter((point) => point && Number.isFinite(Number(point.ts)));
    if (!rows.length) return [];
    const minTs = rows[0].ts || 0;
    const maxTs = rows[rows.length - 1].ts || minTs + 1;
    const span = Math.max(0.001, maxTs - minTs);
    const usableWidth = Math.max(1, width - xPad * 2);
    const usableHeight = Math.max(1, height - yPad * 2);
    const coords = rows.map((point) => {
      const x = xPad + ((point.ts - minTs) / span) * usableWidth;
      const ratio = clamp((Number(point[key]) || 0) / Math.max(1, maxValue), 0, 1);
      const y = yPad + (1 - ratio) * usableHeight;
      return [Number.isFinite(x) ? x : xPad, Number.isFinite(y) ? y : height - yPad];
    });
    if (coords.length === 1) coords.push([width - xPad, coords[0][1]]);
    return coords;
  }

  function sparkSmoothLine(points, width, height, key, maxValue, xPad = 0, yPad = 4) {
    const coords = sparkPointCoords(points, width, height, key, maxValue, xPad, yPad);
    if (!coords.length) return '';
    if (coords.length === 1) return `M${coords[0][0].toFixed(1)} ${coords[0][1].toFixed(1)}`;
    let d = `M${coords[0][0].toFixed(1)} ${coords[0][1].toFixed(1)}`;
    for (let index = 1; index < coords.length; index += 1) {
      const [x0, y0] = coords[index - 1];
      const [x1, y1] = coords[index];
      const dx = x1 - x0;
      const c1x = x0 + dx * 0.46;
      const c2x = x1 - dx * 0.46;
      d += ` C${c1x.toFixed(1)} ${y0.toFixed(1)}, ${c2x.toFixed(1)} ${y1.toFixed(1)}, ${x1.toFixed(1)} ${y1.toFixed(1)}`;
    }
    return d;
  }

  function renderWanThroughputMini(wan) {
    const parts = renderWanThroughputParts(wan);
    const usageSummary = wanUsageSummary(wan);
    return `
      <section class="rail-throughput-card${usageSummary ? '' : ' no-quota'}" aria-label="流量用量与吞吐量">
        ${usageSummary ? `<div class="rail-throughput-quota" data-source="${escapeHtml(usageSummary.source)}"><span>${escapeHtml(usageSummary.title)}</span><strong>${escapeHtml(usageSummary.label)}</strong></div>` : ''}
        <div class="rail-throughput-head">
          <span>吞吐量</span>
          <strong class="rail-throughput-rates"><b class="down">↓ ${escapeHtml(formatRate(wan.downRate))}</b><b class="up">↑ ${escapeHtml(formatRate(wan.upRate))}</b></strong>
        </div>
        <svg class="rail-throughput-chart" viewBox="0 0 ${parts.width} ${parts.height}" preserveAspectRatio="none" aria-hidden="true">
          <defs>
            <linearGradient id="railThroughputDownFill" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stop-color="rgba(69, 190, 255, 0.26)"/>
              <stop offset="100%" stop-color="rgba(69, 190, 255, 0.045)"/>
            </linearGradient>
          </defs>
          ${parts.downArea ? `<path class="rail-throughput-area down" d="${parts.downArea}"></path>` : ''}
          ${parts.downPath ? `<path class="rail-throughput-line down" d="${parts.downPath}"></path>` : ''}
          ${parts.upPath ? `<path class="rail-throughput-line up" d="${parts.upPath}"></path>` : ''}
        </svg>
      </section>`;
  }

  function wanRailStructureItem(wan, index) {
    const meta = carrierMeta(wan);
    const usageSummary = wanUsageSummary(wan);
    return {
      key: wanRealtimeKey(wan, index),
      name: wan.name || '',
      proto: wan.proto || '',
      ip: wan.ip || '',
      ipv6: wan.ipv6 || '',
      uptime: formatUptime(wan.uptime),
      carrier: meta.key,
      carrierLabel: meta.label,
      usageTitle: usageSummary && usageSummary.title || '',
      usageLabel: usageSummary && usageSummary.label || '',
      usageSource: usageSummary && usageSummary.source || '',
      /*
       * Kernel row presence is structure, not runtime text. Without this the card
       * keeps its old shape when the proc snapshot appears or disappears, so the
       * row would never show up until something else forced a rebuild.
       */
      kernelState: wan.kernel
        ? `${wan.kernel.valid ? 'valid' : 'unavailable'}:${wan.kernel.confirmed ? 'confirmed' : 'unconfirmed'}`
        : 'absent',
      probes: PROBE_TARGETS.map((target) => probeKey(wan.id, target.host)).join('|')
    };
  }

  function wanRailStructureKey(wans) {
    return stableSignature(asArray(wans).map((wan, index) => wanRailStructureItem(wan, index)));
  }

  function updateWanRailRealtime(wans) {
    const root = $('railIspList');
    if (!root) return;
    asArray(wans).forEach((wan, index) => {
      const key = wanRealtimeKey(wan, index);
      const card = root.querySelector(`.rail-isp-card[data-wan-key="${cssAttr(key)}"]`);
      if (!card) return;
      const uptime = card.querySelector('[data-wan-runtime="uptime"]');
      const connections = card.querySelector('[data-wan-runtime="connections"]');
      const uptimeText = formatUptime(wan.uptime);
      const connectionsText = formatInteger(wan.connections);
      if (uptime && uptime.textContent !== uptimeText) uptime.textContent = uptimeText;
      if (connections && connections.textContent !== connectionsText) connections.textContent = connectionsText;
      /*
       * The kernel row is patched only from a real kernel projection. wan.metrics
       * frames carry no kernel_* fields, so leaving the existing text in place is
       * correct: blanking it would report the proc nodes as missing when they are
       * simply not part of this topic.
       */
      const kernelCell = card.querySelector('[data-wan-runtime="kernelConnections"]');
      if (kernelCell && connTruth && wan.kernel && wan.kernel.valid) {
        const kernelText = wan.kernel.confirmed
          ? connTruth.formatInteger(wan.kernel.activeConn)
          : `${connTruth.formatInteger(wan.kernel.activeConn)}（${connTruth.UNCONFIRMED_TEXT}）`;
        if (kernelCell.textContent !== kernelText) kernelCell.textContent = kernelText;
      }
      updateWanThroughputMini(card.querySelector('.rail-throughput-card'), wan);
    });
  }

  /*
   * Kernel forwarding row for a WAN card. Rendered only when the kernel snapshot
   * has a usable row for this WAN: an unavailable node shows the reason, never 0
   * and never the conntrack number from the row above.
   */
  function renderWanKernelRow(wan) {
    const runtime = wan && wan.kernel;
    if (!connTruth || !runtime) return '';
    if (!runtime.valid) {
      const reason = runtime.reason ? `：${runtime.reason}` : '';
      return `<div class="rail-isp-row is-kernel"><span>内核转发连接</span><strong class="is-unavailable" data-dwrt-tooltip="${escapeHtml(`内核转发统计不可用${reason}`)}">${escapeHtml(connTruth.UNAVAILABLE_TEXT)}</strong></div>`;
    }
    const tip = [`语义 ${runtime.semanticsLabel}`, runtime.source ? `来源 ${runtime.source}` : '']
      .filter(Boolean).join(' · ');
    const value = runtime.confirmed
      ? connTruth.formatInteger(runtime.activeConn)
      : `${connTruth.formatInteger(runtime.activeConn)}（${connTruth.UNCONFIRMED_TEXT}）`;
    return `<div class="rail-isp-row is-kernel"><span>内核转发连接</span><strong data-wan-runtime="kernelConnections" data-dwrt-tooltip="${escapeHtml(tip)}">${escapeHtml(value)}</strong></div>`;
  }

  function renderWanCards(wans) {
    const root = $('railIspList');
    if (!root) return;
    if (!wans.length) {
      root.innerHTML = '<div class="rail-empty">没有可用 WAN 数据</div>';
      state.dashboard.wanRailStructureKey = 'empty';
      return;
    }
    const structureKey = wanRailStructureKey(wans);
    if (state.dashboard.wanRailStructureKey === structureKey) {
      updateWanRailRealtime(wans);
      return;
    }
    state.dashboard.wanRailStructureKey = structureKey;
    root.innerHTML = wans.map((wan, index) => {
      const meta = carrierMeta(wan);
      return `
        <article class="rail-isp-card" data-wan-key="${escapeHtml(wanRealtimeKey(wan, index))}">
          <div class="rail-isp-head">
            <strong class="rail-isp-title">${carrierMarkup(wan)}<span>${escapeHtml(meta.label)}</span></strong>
            <span class="rail-isp-interface">${escapeHtml(firstText(wan.name, wan.id, wan.ifname, 'WAN').toUpperCase())}</span>
          </div>
          <div class="rail-isp-row"><span>协议</span><strong>${escapeHtml((wan.proto || '--').toUpperCase())}</strong></div>
          <div class="rail-isp-row"><span>WAN IP</span><strong>${escapeHtml(wan.ip || '--')}</strong></div>
          <div class="rail-isp-row is-ipv6"><span>IPv6</span><strong data-dwrt-tooltip="${escapeHtml(wan.ipv6 || '--')}" aria-label="${escapeHtml(wan.ipv6 || '--')}">${escapeHtml(wan.ipv6 || '--')}</strong></div>
          <div class="rail-isp-row"><span>连接时间</span><strong data-wan-runtime="uptime">${escapeHtml(formatUptime(wan.uptime))}</strong></div>
          <div class="rail-isp-row"><span>连接数</span><strong data-wan-runtime="connections" data-dwrt-tooltip="conntrack 公网地址归属统计">${escapeHtml(formatInteger(wan.connections))}</strong></div>
          ${renderWanKernelRow(wan)}
          ${renderWanThroughputMini(wan)}
          <div class="rail-probe-row">
            ${PROBE_TARGETS.map((target) => probeMarkup(wan, target)).join('')}
          </div>
        </article>`;
    }).join('');
  }

  function renderHealthDots(history) {
    const rows = asArray(history).length ? asArray(history).slice(-24) : dashboardHealthHistoryPoints(24);
    if (!rows.length) {
      return Array.from({ length: 24 }, () => '<span class="rail-health-dot muted" title="暂无历史采样"></span>').join('');
    }
    return rows.map((item) => {
      const status = String(typeof item === 'string' ? item : item.status || item.state || '').toLowerCase();
      const latency = Number(typeof item === 'object' ? item.latency || item.latency_avg || item.latency_ms || item.avg || 0 : 0);
      const loss = Number(typeof item === 'object' ? item.loss || item.loss_pct || item.packet_loss || 0 : 0);
      const cls = status === 'down' || status === 'bad' || loss > 20
        ? 'bad'
        : status === 'warn' || latency >= 80 || loss > 0
          ? 'warn'
          : status === 'ok' || status === 'healthy' || latency > 0
            ? 'good'
          : 'muted';
      const ts = typeof item === 'object' ? firstText(item.ts, item.timestamp, item.time) : '';
      const tip = [
        status || 'ok',
        ts ? `采样: ${ts}` : '',
        latency ? `延迟: ${formatLatency(latency)}` : '',
        loss ? `丢包: ${loss}%` : ''
      ].filter(Boolean).join(' · ');
      return `<span class="rail-health-dot ${cls}" title="${escapeHtml(tip)}"></span>`;
    }).join('');
  }

  function renderPortCards(ports, wans) {
    const root = $('railPortGrid');
    if (!root) return;
    if (!ports.length) {
      root.innerHTML = '<div class="rail-empty">没有可用端口数据</div>';
      return;
    }
    const orderedPorts = [...ports].sort((left, right) => {
      const leftKey = firstText(left.id, left.label, left.ownerId).toLowerCase();
      const rightKey = firstText(right.id, right.label, right.ownerId).toLowerCase();
      return leftKey.localeCompare(rightKey, undefined, { numeric: true, sensitivity: 'base' });
    });
    root.innerHTML = orderedPorts.map((port) => {
      const wan = wans.find((item) => portMatchesWan(port, item)) || {};
      const kind = wan.id ? 'wan' : port.kind;
      const speed = firstText(port.speed, wan.linkSpeed, port.status);
      return `
        <button class="rail-port ${escapeHtml(kind)} ${port.active ? 'active' : 'idle'}" type="button">
          ${kind === 'wan' ? `<span class="rail-port-carrier">${carrierMarkup(wan)}</span>` : '<span class="rail-port-lan-icon" aria-hidden="true"></span>'}
          <span class="rail-port-copy">
            <strong>${escapeHtml(port.label || port.id || '--')}</strong>
            <small>${escapeHtml(speed || '--')}</small>
          </span>
        </button>`;
    }).join('');
  }

  function scheduleNextDashboardRefresh(delayMs) {
    if (!state.dashboard.active) return;
    window.clearTimeout(state.dashboard.timer);
    state.dashboard.timer = window.setTimeout(refreshDashboard, delayMs);
  }

  async function refreshDashboard() {
    if (!state.dashboard.active) return;
    if (state.dashboard.loading || state.dashboard.slowLoading) {
      scheduleNextDashboardRefresh(1000);
      return;
    }
    const wsFresh = state.dashboard.lastWsAt && Date.now() - state.dashboard.lastWsAt < DASHBOARD_REFRESH_MS * 2;
    state.dashboard.loading = true;
    if (!state.dashboard.lastRenderKey) setDashboardStatus('正在读取真实状态');
    const entries = dashboardResourceEntriesDue(!state.dashboard.lastRenderKey);
    const criticalEntries = wsFresh
      ? entries.filter(([name]) => DASHBOARD_CRITICAL_RESOURCES.has(name) && !['clients', 'overview'].includes(name))
      : entries.filter(([name]) => DASHBOARD_CRITICAL_RESOURCES.has(name));
    const optionalEntries = entries.filter(([name]) => !DASHBOARD_CRITICAL_RESOURCES.has(name));
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    state.dashboard.batchController = controller;
    const batchStartedAt = Date.now();
    const resources = criticalEntries.length
      ? await fetchDashboardResourcesQueued(criticalEntries, controller ? controller.signal : undefined)
      : [];
    state.dashboard.loading = false;
    if (!state.dashboard.active) return;
    renderDashboardCard(stabilizeDashboardRates(normalizeDashboardData(mergeDashboardResources(resources))));
    if (optionalEntries.length && !state.dashboard.slowLoading) {
      state.dashboard.slowLoading = true;
      fetchDashboardResourcesQueued(optionalEntries, controller ? controller.signal : undefined)
        .then((optionalResources) => {
          if (!state.dashboard.active) return;
          renderDashboardCard(stabilizeDashboardRates(normalizeDashboardData(mergeDashboardResources(optionalResources))));
        })
        .catch(() => {})
        .finally(() => {
          state.dashboard.slowLoading = false;
        });
    }
    // 后端响应慢时自动拉长轮询,快时逐步恢复,避免把拥塞的后端越打越死。
    const batchElapsed = Date.now() - batchStartedAt;
    const previousDelay = state.dashboard.pollDelayMs || DASHBOARD_REFRESH_MS;
    const nextDelay = batchElapsed > 1500
      ? Math.min(30000, Math.max(previousDelay, DASHBOARD_REFRESH_MS) * 2)
      : Math.max(DASHBOARD_REFRESH_MS, Math.round(previousDelay * 0.6));
    state.dashboard.pollDelayMs = nextDelay;
    scheduleNextDashboardRefresh(nextDelay);

    const selectedRange = dashboardRangeMeta(state.dashboard.trafficRange).id;
    if (selectedRange !== 'realtime') {
      const historyWanId = selectedDashboardWanId();
      syncTrafficHistory(selectedRange, false, historyWanId).then(() => {
        if (!state.dashboard.active) return;
        if (state.dashboard.lastModel) renderDashboardMain(state.dashboard.lastModel);
      }).catch(() => {});
    }
  }

  async function switchDashboardRange(rangeId) {
    const normalized = dashboardRangeMeta(rangeId).id;
    state.dashboard.trafficRange = normalized;
    if (normalized !== 'realtime') {
      await syncTrafficHistory(normalized, true, selectedDashboardWanId());
    }
    if (state.dashboard.lastModel) renderDashboardMain(state.dashboard.lastModel);
  }

  function startDashboard() {
    if (!dashboardWorkspace) return;
    state.dashboard.active = true;
    dashboardWorkspace.hidden = false;
    if (dashboardStatusRail) dashboardStatusRail.hidden = false;
    if (routePreview) routePreview.hidden = true;
    appShell?.classList.add('dashboard-active');
    consoleStage?.classList.add('is-dashboard');
    if (!state.dashboard.lastRenderKey) renderDashboardCard(dashboardBootModel());
    subscribeDashboardRealtime();
    state.dashboard.pollDelayMs = DASHBOARD_REFRESH_MS;
    window.clearTimeout(state.dashboard.timer);
    refreshDashboard();
  }

  function stopDashboard(options = {}) {
    state.dashboard.active = false;
    unsubscribeDashboardRealtime();
    window.clearTimeout(state.dashboard.timer);
    // 离开仪表盘立即中止在途请求,把浏览器连接和后端队列让给要进入的页面。
    if (state.dashboard.batchController) {
      try { state.dashboard.batchController.abort(); } catch (_) {}
      state.dashboard.batchController = null;
    }
    state.dashboard.loading = false;
    state.dashboard.slowLoading = false;
    window.clearTimeout(state.dashboard.deferredRenderTimer);
    window.clearTimeout(state.dashboard.realtimeFrameTimer);
    window.clearTimeout(state.dashboard.throughputFrameTimer);
    state.dashboard.timer = null;
    state.dashboard.realtimeFrameTimer = 0;
    state.dashboard.throughputFrameTimer = 0;
    state.dashboard.pendingRealtimeChartUpdate = false;
    state.dashboard.pendingRealtime.clear();
    resetDashboardRenderCache();
    if (dashboardWorkspace) dashboardWorkspace.hidden = true;
    if (dashboardStatusRail) dashboardStatusRail.hidden = true;
    if (routePreview && options.showRoutePreview !== false) routePreview.hidden = false;
    appShell?.classList.remove('dashboard-active');
    consoleStage?.classList.remove('is-dashboard');
  }

  function bindDashboardChartInteractions() {
    if (!routerMonitorCard) return;
    const stage = routerMonitorCard.querySelector('.dashboard-chart-stage');
    const svg = routerMonitorCard.querySelector('.dashboard-speed-chart');
    const tooltip = routerMonitorCard.querySelector('.dashboard-chart-tooltip');
    const crosshair = routerMonitorCard.querySelector('.dashboard-chart-crosshair');
    const chart = state.dashboard.chartState;
    if (!stage || !svg || !tooltip || !crosshair || !chart || !chart.points.length) return;
    const crosshairV = crosshair.querySelector('.dashboard-chart-crosshair-v');
    const crosshairH = crosshair.querySelector('.dashboard-chart-crosshair-h');
    const crosshairDot = crosshair.querySelector('.dashboard-chart-crosshair-dot');
    const show = () => {
      state.dashboard.chartHovering = true;
      crosshair.hidden = false;
      tooltip.hidden = false;
    };
    const hide = () => {
      state.dashboard.chartHovering = false;
      crosshair.hidden = true;
      tooltip.hidden = true;
      if (state.dashboard.pendingChartHistory) {
        const pending = state.dashboard.pendingChartHistory;
        state.dashboard.pendingChartHistory = null;
        window.requestAnimationFrame(() => renderMonitorChart(pending));
      }
    };
    const update = (event) => {
      const stageRect = stage.getBoundingClientRect();
      const rect = svg.getBoundingClientRect();
      if (!stageRect.width || !rect.width || !rect.height) return;
      const insetX = Number(chart.xPad) || 0;
      const usableWidth = Math.max(1, rect.width - (insetX * 2));
      const plotLeft = rect.left - stageRect.left;
      const plotTop = rect.top - stageRect.top;
      const localX = clamp(event.clientX - rect.left, insetX, rect.width - insetX);
      const span = Math.max(1, chart.maxTs - chart.minTs);
      const targetTs = chart.minTs + ((localX - insetX) / usableWidth) * span;
      let nearest = chart.points[0];
      let nearestDelta = Infinity;
      chart.points.forEach((point, index) => {
        const delta = Math.abs(point.ts - targetTs);
        if (delta < nearestDelta) {
          nearest = point;
          nearestDelta = delta;
          nearest._index = index;
        }
      });
      const nearestRatio = chart.points.length > 1
        ? clamp((nearest.ts - chart.minTs) / span, 0, 1)
        : 0.5;
      const hoverX = chart.points.length > 1
        ? plotLeft + insetX + nearestRatio * usableWidth
        : plotLeft + insetX + usableWidth / 2;
      const downRatio = clamp((Number(nearest.down) || 0) / Math.max(1, chart.rateMax), 0, 1);
      const hoverY = plotTop + rect.height - downRatio * (rect.height - 18) - 9;
      const showLeft = hoverX > plotLeft + rect.width * 0.68;
      const timeLabel = formatDashboardTooltipTime(nearest.ts);
      const avgUp = firstNumber(nearest.up);
      const avgDown = firstNumber(nearest.down);
      const avgLatency = positiveNumber(nearest.latency);
      const avgConnections = firstNumber(nearest.connections);
      const tooltipRows = [
        ['平均上行：', formatRate(avgUp), 'up'],
        ['最大上行：', formatRate(tooltipMetricNumber(nearest.upMax, avgUp)), 'up'],
        ['平均下行：', formatRate(avgDown), 'down'],
        ['最大下行：', formatRate(tooltipMetricNumber(nearest.downMax, avgDown)), 'down'],
        ['平均延迟：', formatLatency(avgLatency), 'latency'],
        ['最大延迟：', formatLatency(tooltipMetricNumber(nearest.latencyMax, avgLatency)), 'latency'],
        ['最小延迟：', formatLatency(tooltipMetricNumber(nearest.latencyMin, avgLatency)), 'latency'],
        ['连接数：', formatInteger(avgConnections), 'connections']
      ].map(([label, value, tone]) => `<div class="dashboard-chart-tooltip-row ${tone}"><span>${escapeHtml(label)}</span><b>${escapeHtml(value)}</b></div>`).join('');
      tooltip.innerHTML = `
        <strong>${escapeHtml(timeLabel)}</strong>
        <div class="dashboard-chart-tooltip-grid">${tooltipRows}</div>
      `;
      crosshair.style.left = `${hoverX}px`;
      crosshair.style.top = `${hoverY}px`;
      crosshairV.style.left = `${hoverX}px`;
      crosshairV.style.top = `${plotTop}px`;
      crosshairV.style.height = `${rect.height}px`;
      crosshairH.style.left = `${plotLeft + insetX}px`;
      crosshairH.style.top = `${hoverY}px`;
      crosshairH.style.width = `${usableWidth}px`;
      crosshairDot.style.left = `${hoverX}px`;
      crosshairDot.style.top = `${hoverY}px`;
      crosshair.classList.toggle('is-left', showLeft);
      tooltip.classList.toggle('is-left', showLeft);
      const tooltipWidth = tooltip.offsetWidth || 320;
      const tooltipHeight = tooltip.offsetHeight || 210;
      const leftMin = showLeft ? tooltipWidth + 12 : 12;
      const leftMax = showLeft ? stageRect.width - 12 : Math.max(12, stageRect.width - tooltipWidth - 12);
      const topMin = tooltipHeight / 2 + 10;
      const topMax = Math.max(topMin, stageRect.height - tooltipHeight / 2 - 10);
      tooltip.style.left = `${clamp(showLeft ? hoverX - 16 : hoverX + 16, leftMin, leftMax)}px`;
      tooltip.style.top = `${clamp(hoverY, topMin, topMax)}px`;
      show();
    };
    svg.onpointerenter = update;
    svg.onpointermove = update;
    svg.onpointerleave = hide;
    stage.onpointerleave = hide;
    stage.onblur = hide;
  }

      function bindDashboardEvents() {
        if (eventsBound) return;
        eventsBound = true;
        dashboardStatusRail && dashboardStatusRail.addEventListener('click', (event) => {
          const probe = event.target.closest('.rail-probe');
          if (probe) runProbe(probe);
        });
        routerMonitorCard && routerMonitorCard.addEventListener('click', (event) => {
          const wanButton = event.target.closest('[data-dashboard-wan]');
          const rangeButton = event.target.closest('[data-dashboard-range]');
          if (wanButton) {
            state.dashboard.activeWanId = selectedDashboardWanId(wanButton.dataset.dashboardWan);
            if (state.dashboard.lastModel) renderDashboardMain(state.dashboard.lastModel);
            const rangeId = dashboardRangeMeta(state.dashboard.trafficRange).id;
            if (rangeId !== 'realtime') {
              syncTrafficHistory(rangeId, false, state.dashboard.activeWanId).then(() => {
                if (state.dashboard.active && state.dashboard.lastModel) renderDashboardMain(state.dashboard.lastModel);
              }).catch(() => {});
            }
          }
          if (rangeButton) {
            switchDashboardRange(rangeButton.dataset.dashboardRange || 'realtime');
          }
        });
      }

      bindDashboardEvents();

      return {
        start: startDashboard,
        stop: stopDashboard,
        refresh: refreshDashboard,
        state: state.dashboard
      };
    }
  };
})();
