(() => {
  const VERSION = '20260802-sheet-portal-scope-01';
  const STATIC_MENU_URL = '/static/menu/main.json';
  const RUNTIME_MENU_URL = '/dynamic/menu/1.json';
  const MENU_URLS = window.DWRT_RUNTIME_MENU === false || document.documentElement.dataset.runtimeMenu === 'false'
    ? [STATIC_MENU_URL]
    : [RUNTIME_MENU_URL, STATIC_MENU_URL];
  const TOPOLOGY_PREF_KEYS = {
    rotateMap: 'dreamingwrt.web.topology.rotateMap'
  };
  const SHELL_FETCH_TIMEOUT_MS = {
    static: 4000,
    runtime: 4000,
    theme: 1500,
    default: 2500
  };
  const TOPOLOGY_REFRESH_MS = 10000;
  const TOPOLOGY_ENDPOINT = '/api/v1/topology';
  const TOPOLOGY_FLOW_ENDPOINTS = [
    '/api/v1/topology/flow',
    '/api/v1/topology_flow',
    '/api/v1/dreamingwrt/topology_flow'
  ];
  const MONITOR_DATA_REFRESH_MS = 5000;
  const ECHARTS_VENDOR_URL = '/static/vendor/echarts.min.js';
  const SYSTEM_HEALTH_RANGE_OPTIONS = {
    '1h': { label: '近一小时', range: '1h' },
    '1d': { label: '近一天', range: '1d' },
    '1w': { label: '近一周', range: '1w' },
    '1m': { label: '近一个月', range: '1m' }
  };
  const SYSTEM_HEALTH_DEFAULT_RANGE = '1h';
  const SYSTEM_HEALTH_HISTORY_ENDPOINT = '/api/v1/system/health/history';
  const SYSTEM_TRAFFIC_HISTORY_ENDPOINT = '/api/v1/dashboard/traffic/history';
  const MONITOR_DATA_PAGES = {
    systemHealth: {
      id: 'system-health',
      label: '系统健康',
      hash: '/monitor/system-health',
      title: '系统健康',
      subtitle: '系统资源、连接数与健康摘要来自 /api/v1/system/health 和 /api/v1/dashboard/status。',
      description: '系统健康页读取 webd/jmxd 真实运行指标；缺失项显示为空态或 --，不使用本地推测值。',
      empty: '后端暂未返回系统健康数据。'
    }
  };
  const SESSION_KEYS = {
    access: 'dreamingwrt.web.accessToken',
    refresh: 'dreamingwrt.web.refreshToken',
    expiresAt: 'dreamingwrt.web.expiresAt',
    username: 'dreamingwrt.web.username',
    role: 'dreamingwrt.web.role'
  };
  const SHELL_WARM_CACHE = {
    version: '20260720-41',
    menu: 'dreamingwrt.shellWarm.menu.v4',
    theme: 'dreamingwrt.shellWarm.theme.v2',
    maxAgeMs: 10 * 60 * 1000
  };
  const APP_LIQUID_GLASS = {
    cornerRadius: 25,
    blurRadius: 6,
    baseBlur: 3.2,
    refractionOffset: 120,
    refractionHeight: 12,
    borderWidth: 1,
    opacity: 1,
    neutralDensity: 0.06,
    neutralColor: '10 16 25',
    saturation: 140,
    displacementScale: 80,
    aberrationIntensity: 2,
    highlight: 0.28,
    highlightAngle: 135,
    preserveCenter: true,
    borderColor: '#ffffff25',
    edgeIntensity: 0.012,
    rimIntensity: 0.060,
    baseIntensity: 0.010,
    edgeDistance: 0.15,
    rimDistance: 0.80,
    baseDistance: 0.10,
    cornerBoost: 0.020,
    rippleEffect: 0.100,
    tintOpacity: 0,
    warp: false
  };
  const MENU_LIQUID_GLASS = Object.freeze({
    mode: 'shader',
    displacementScale: 80,
    baseBlur: 3.2,
    blurAmount: 0,
    saturation: 140,
    aberrationIntensity: 2,
    neutralDensity: 0.06,
    neutralColor: '10 16 25',
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.22)',
    highlight: 0.28,
    cornerRadius: 0,
    overLight: false,
    highlightAngle: 135,
    preserveCenter: true,
    mapResolution: 0.25,
    trackMotion: false,
    trackScroll: false
  });
  const PAGE_GLASS_MAP_CACHE = new Map();
  const PAGE_GLASS_MAP_WORKER_URL = `/static/js/page-glass-map-worker.js?v=${VERSION}`;
  const PAGE_GLASS_MAP_WORKER_TIMEOUT_MS = 5000;
  const PAGE_GLASS_MAP_CANCELLED = Symbol('page-glass-map-cancelled');
  const pageGlassMapWorkerRequests = new Map();
  let pageGlassMapWorker = null;
  let pageGlassMapWorkerDisabled = false;
  let pageGlassMapWorkerRequestId = 0;
  const PAGE_SCRIPTS = {
    dashboard: {
      url: '/static/js/dashboard.js',
      globalName: 'DWRTDashboard',
      version: '20260726-poll-discipline-05'
    },
    topology: {
      url: '/static/js/unifi-topology.js',
      globalName: 'DWRT_UNIFI_TOPOLOGY',
      version: '20260722-04'
    },
    lineStatus: {
      url: '/static/js/line-status.js',
      globalName: 'DWRTLineStatus',
      version: '20260723-line-health-history-01'
    },
    clientDetails: {
      url: '/static/js/client-details.js',
      globalName: 'DWRTClientDetails',
      version: '20260802-sheet-portal-scope-01'
    },
    insightsFlows: {
      url: '/static/js/insights-flows.js',
      globalName: 'DWRTInsightsFlows',
      version: '20260802-sheet-portal-scope-01'
    },
  };
  const PAGE_STYLES = {
    lineStatus: [
      { url: '/static/css/line-status.css', version: '20260723-line-health-history-01' }
    ],
    clientDetails: [
      { url: '/static/css/client-details.css', version: '20260802-sheet-portal-scope-01' }
    ],
    insightsFlows: [
      { url: '/static/css/insights-flows.css', version: '20260802-sheet-portal-scope-01' }
    ],
  };
  const GLOBAL_AI_ASSETS = Object.freeze({
    module: { url: '/plugins/native/ai-assistant.js', version: '20260802-sheet-portal-scope-01' },
    style: { url: '/static/css/ai-assistant.css', version: '20260802-sheet-portal-scope-01' }
  });

  let topologyVisibilityTimer = 0;
  let dashboardLoadId = 0;
  let topologyLoadId = 0;
  window.__DWRT_SHELL_VERSION = VERSION;

  const $ = (id) => document.getElementById(id);
  const cssEscape = (value) => {
    const text = String(value || '');
    if (window.CSS && typeof window.CSS.escape === 'function') return window.CSS.escape(text);
    return text.replace(/["\\]/g, '\\$&');
  };
  const appShell = $('appShell');
  const appWallpaper = $('appWallpaper');
  const appMenuGlass = $('appMenuGlass');
  const primaryMenu = $('primaryMenu');
  const bottomMenu = $('bottomMenu');
  const secondaryMenu = $('secondaryMenu');
  const submenu = $('submenu');
  const submenuTitle = $('submenuTitle');
  const pageEyebrow = $('pageEyebrow');
  const pageTitle = $('pageTitle');
  const pageDescription = $('pageDescription');
  const routePath = $('routePath');
  const menuSource = $('menuSource');
  const sidebarToggle = $('sidebarToggle');
  const userButton = $('userButton');
  const themeButton = $('themeButton');
  const accountPopover = $('accountPopover');
  const primaryActivePill = $('primaryActivePill');
  const secondaryActivePill = $('secondaryActivePill');
  const bottomActivePill = $('bottomActivePill');
  const menuSearchTrigger = $('menuSearchTrigger');
  const commandPalette = $('commandPalette');
  const commandPaletteBackdrop = $('commandPaletteBackdrop');
  const commandPaletteInput = $('commandPaletteInput');
  const commandPaletteResults = $('commandPaletteResults');
  const commandPaletteEmpty = $('commandPaletteEmpty');
  const commandPaletteTitle = $('commandPaletteTitle');
  const commandEnterAction = $('commandEnterAction');
  const aiGlobalRoot = $('aiGlobalRoot');
  const aiBootstrap = $('aiBootstrap');
  const consolePageFooter = $('consolePageFooter');
  const consolePageFooterVersion = $('consolePageFooterVersion');
  const consoleMain = $('consoleMain');
  const consoleStage = document.querySelector('.console-stage');
  const routePreview = $('routePreview');
  const topologyWorkspace = $('topologyWorkspace');
  const topologyShell = $('topologyShell');
  const topologyStatus = $('topologyStatus');
  const topologyCanvas = $('topologyCanvas');
  const topologyEmpty = $('topologyEmpty');
  const topologyInfrastructureEmpty = $('topologyInfrastructureEmpty');
  const topologyTimeMachine = $('topologyTimeMachine');
  const topologyContentContainer = $('topology-content-container');
  const topologyZoomContainer = $('topology-zoom-container');
  const topologyLinkLayer = $('topology-link-layer');
  const topologyNodeLayer = $('topology-node-layer');
  const topologyLabelLayer = $('label-layer');
  const topologyToggleLayer = $('toggle-layer');
  const topologyDetailDrawer = $('topologyDetailDrawer');

  const state = {
    menu: [],
    source: '',
    activePrimary: null,
    activeSecondary: null,
    commandEntries: [],
    commandStaticEntries: [],
    commandEntityEntries: [],
    commandFiltered: [],
    commandSelected: 0,
    commandOpen: false,
    commandReturnFocus: null,
    commandMode: 'search',
    commandEntitiesLoading: false,
    commandEntitiesLoadedAt: 0,
    commandEntityLoadId: 0,
    routePages: {},
    routeModules: new Map(),
    activeRouteModule: null,
    activeRouteSignature: '',
    routeLoadId: 0,
    routeAbortController: null,
    capabilities: {},
    topology: {
      active: false,
      loading: false,
      timer: null,
      view: 'topology',
      panelCollapsed: false,
      navigationMode: 'hand',
      rotateMap: false,
      trafficEnabled: true,
      clientsEnabled: true,
      filters: {
        statusOnline: true,
        statusOffline: true,
        wiredClients: true,
        wirelessClients: true,
        vlanDefault: true
      },
      labels: {
        ssid: true,
        signal: true,
        channel: true,
        wifi: true,
        wired: true,
        stp: true
      },
      lastRenderKey: '',
      lastModel: null,
      infrastructureModel: null,
      infrastructureData: null,
      infrastructureHealthData: null,
      infrastructureError: '',
      timeMachineEnabled: false,
      timeMachineLoading: false,
      timeMachineError: '',
      timeMachineStart: 0,
      timeMachineEnd: 0,
      timeMachineTimestamps: [],
      timeMachineEvents: [],
      timeMachineSelectedTimestamp: 0,
      timeMachineSnapshot: null,
      timeMachineZoom: 0.35,
      timeMachineLoadId: 0,
      transform: { x: 0, y: 0, k: 1 },
      transformSet: false,
      dragging: null,
      statusTimer: null,
      zoomTimer: null,
      flowEndpoint: '',
      flowUnavailableUntil: 0,
      fallbackReason: '',
      selectedNodeMac: '',
      detailTab: 'overview',
	      detailOpen: false,
	      lastTopologyData: null,
	      lastFlowData: null,
	      lastNonZeroFlowData: null,
	      lastWsAt: 0,
	      flowFrameTimer: 0,
	      pendingFlowData: null,
	      wsUnsubscribe: null,
      clientsCacheData: null,
      clientsCacheAt: 0,
      collapsedBranches: {},
      collapsedSections: {}
	    },
    liquidGlass: {
      image: null,
      imageUrl: '',
      menuRenderer: null,
      menuOptions: { ...MENU_LIQUID_GLASS },
      pageScopes: new Map(),
      pagePendingScopes: new Set(),
      pageScrollTimers: new Map(),
      pageIdleHandle: 0,
      pageIdleHandleType: '',
      pageObserver: null,
      pageResizeObserver: null,
      pageObservedCards: new Set(),
      pageReconciling: false,
      pageRouteTransition: false,
      pageRouteToken: 0,
      pageRouteTimer: 0,
      pageRouteStartedAt: 0,
      pendingTransitionRelease: null,
      materialVersion: 0,
      legacyCanvasesCleared: false,
      raf: 0,
      loopUntil: 0,
      settleTimer: 0,
      foregroundTimer: null,
      foregroundIdle: 0,
      foregroundMap: null,
      foregroundModes: new WeakMap(),
      foregroundTargets: new Set(),
      appearancePreviewBaseline: null,
      vars: { ...APP_LIQUID_GLASS }
    }
  };
  let aiGlobalController = null;
  let aiGlobalPromise = null;
  const pillRects = new WeakMap();
  const pillAnimations = new WeakMap();
  const pageScriptPromises = new Map();
  const pageStylePromises = new Map();
  let echartsLoadingPromise = null;
  const menuJsonCache = new Map();
  let dashboardPage = null;
  let lineStatusPage = null;
  let clientDetailsPage = null;
  let insightsFlowsPage = null;
  let pendingMenuRouteToken = 0;
  let menuColumnSwitchToken = 0;
  let idleRouteWarmupScheduled = false;
  let initialRouteMounted = false;

  function pageScriptUrl(entry) {
    const version = encodeURIComponent(entry.version || VERSION);
    return `${entry.url}${entry.url.includes('?') ? '&' : '?'}v=${version}`;
  }

  function loadPageStyle(entry) {
    if (!entry || !entry.url) return Promise.resolve();
    const key = `${entry.url}?${entry.version || VERSION}`;
    if (document.querySelector(`link[data-dwrt-page-style="${cssEscape(key)}"]`)) return Promise.resolve();
    const existing = pageStylePromises.get(key);
    if (existing) return existing;
    const href = `${entry.url}${entry.url.includes('?') ? '&' : '?'}v=${encodeURIComponent(entry.version || VERSION)}`;
    const promise = new Promise((resolve, reject) => {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = href;
      link.dataset.dwrtPageStyle = key;
      link.onload = () => resolve();
      link.onerror = () => {
        pageStylePromises.delete(key);
        link.remove();
        reject(new Error(`failed to load ${entry.url}`));
      };
      const materialContract = document.getElementById('dwrtControlMaterial');
      if (materialContract) document.head.insertBefore(link, materialContract);
      else document.head.appendChild(link);
    });
    pageStylePromises.set(key, promise);
    return promise;
  }

  function loadPageStyles(key) {
    return Promise.all((PAGE_STYLES[key] || []).map(loadPageStyle));
  }

  function currentAiPageContext() {
    const cleanHash = cleanRouteHash();
    const { primary, secondary } = findByHash(cleanHash);
    const title = secondary?.label || primary?.label || pageTitle?.textContent || document.title;
    const sources = [
      routePreview && !routePreview.hidden ? routePreview : null,
      $('dashboardWorkspace') && !$('dashboardWorkspace').hidden ? $('dashboardWorkspace') : null,
      topologyWorkspace && !topologyWorkspace.hidden ? topologyWorkspace : null,
      consoleMain
    ].filter(Boolean);
    const text = firstText(...sources.map((element) => element.innerText)).slice(0, 8000);
    return { title, route: cleanHash, text };
  }

  async function ensureGlobalAi() {
    if (aiGlobalController) return aiGlobalController;
    if (aiGlobalPromise) return aiGlobalPromise;
    aiBootstrap?.setAttribute('aria-busy', 'true');
    aiGlobalPromise = loadPageStyle(GLOBAL_AI_ASSETS.style).then(() => (
      import(`${GLOBAL_AI_ASSETS.module.url}?v=${encodeURIComponent(GLOBAL_AI_ASSETS.module.version)}`)
    )).then(async (moduleRecord) => {
      if (!aiGlobalRoot) return null;
      aiGlobalController = await moduleRecord.mount({
        root: aiGlobalRoot,
        mode: 'global-drawer',
        api: { fetch: fetchApiResource, authHeaders, routeTo },
        ui: {
          mountAll: (root = aiGlobalRoot) => window.DWRT_UI_KIT?.mountAll(root),
          scheduleGlassCardsRender,
          scheduleAdaptiveForegroundSample: (delay = 0, root = aiGlobalRoot) => scheduleAdaptiveForegroundSample(delay, root),
          statusBadgeMarkup: (...args) => window.DWRT_UI_KIT?.statusBadgeMarkup?.(...args)
        },
        utils: { escapeHtml, formatInteger },
        getPageContext: currentAiPageContext
      });
      return aiGlobalController;
    }).catch((error) => {
      aiGlobalPromise = null;
      if (aiGlobalRoot && aiBootstrap && !aiBootstrap.isConnected) {
        aiGlobalRoot.className = 'ai-global-root';
        aiGlobalRoot.replaceChildren(aiBootstrap);
      }
      aiBootstrap?.setAttribute('aria-busy', 'false');
      console.warn('[dreamingwrt-web] global AI failed to load', error);
      return null;
    });
    return aiGlobalPromise;
  }

  async function openGlobalAi(options = {}) {
    const controller = await ensureGlobalAi();
    controller?.open?.(options);
  }


  function loadECharts() {
    if (window.echarts) return Promise.resolve(window.echarts);
    if (echartsLoadingPromise) return echartsLoadingPromise;
    echartsLoadingPromise = new Promise((resolve, reject) => {
      const existing = document.querySelector(`script[src^="${ECHARTS_VENDOR_URL}"]`);
      const script = existing || document.createElement('script');
      const done = () => window.echarts ? resolve(window.echarts) : reject(new Error('echarts unavailable'));
      script.addEventListener('load', done, { once: true });
      script.addEventListener('error', () => {
        echartsLoadingPromise = null;
        reject(new Error('echarts load failed'));
      }, { once: true });
      if (!existing) {
        script.src = `${ECHARTS_VENDOR_URL}?v=${encodeURIComponent(VERSION)}`;
        script.async = true;
        script.dataset.dwrtVendor = 'echarts';
        document.head.appendChild(script);
      } else if (window.echarts) {
        done();
      }
    });
    return echartsLoadingPromise;
  }

  function loadClassicPageScript(key) {
    const entry = PAGE_SCRIPTS[key];
    if (!entry) return Promise.reject(new Error(`unknown page script: ${key}`));
    if (entry.globalName && window[entry.globalName]) return Promise.resolve(window[entry.globalName]);
    const existing = pageScriptPromises.get(key);
    if (existing) return existing;

    const promise = new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = pageScriptUrl(entry);
      script.async = true;
      script.dataset.dwrtPageScript = key;
      script.onload = () => {
        const exported = entry.globalName ? window[entry.globalName] : true;
        if (!exported) {
          pageScriptPromises.delete(key);
          reject(new Error(`${entry.url} did not expose ${entry.globalName}`));
          return;
        }
        resolve(exported);
      };
      script.onerror = () => {
        pageScriptPromises.delete(key);
        script.remove();
        reject(new Error(`failed to load ${entry.url}`));
      };
      document.head.appendChild(script);
    });

    pageScriptPromises.set(key, promise);
    return promise;
  }

  function ensureDashboardPage() {
    if (dashboardPage) return dashboardPage;
    if (window.DWRTDashboard && typeof window.DWRTDashboard.create === 'function') {
      dashboardPage = window.DWRTDashboard.create({
        version: VERSION,
        scheduleGlassCardsRender,
        shouldDeferRender,
        realtime: window.DWRTRealtime,
        session: window.DWRT_SESSION
      });
    }
    return dashboardPage;
  }

  async function ensureDashboardPageLoaded() {
    await loadClassicPageScript('dashboard');
    return ensureDashboardPage();
  }

  function ensureLineStatusPage() {
    if (lineStatusPage) return lineStatusPage;
    if (window.DWRTLineStatus && typeof window.DWRTLineStatus.create === 'function') {
      lineStatusPage = window.DWRTLineStatus.create({
        routePreview,
        fetchApiResource,
        scheduleGlassCardsRender,
        mountUiKit: (target) => window.DWRT_UI_KIT?.mountAll(target),
        escapeHtml,
        asArray,
        firstText,
        firstNumber,
        positiveNumber,
        onlineState,
        formatRate,
        formatBitRate,
        formatLatency,
        carrierMarkup,
        shouldDeferRender,
        realtime: window.DWRTRealtime
      });
    }
    return lineStatusPage;
  }

  async function ensureLineStatusPageLoaded() {
    await Promise.all([loadPageStyles('lineStatus'), loadClassicPageScript('lineStatus')]);
    return ensureLineStatusPage();
  }

  function ensureClientDetailsPage() {
    if (clientDetailsPage) return clientDetailsPage;
    if (window.DWRTClientDetails && typeof window.DWRTClientDetails.create === 'function') {
      clientDetailsPage = window.DWRTClientDetails.create({
        routePreview,
        fetchApiResource,
        scheduleGlassCardsRender,
        mountUiKit: (target) => window.DWRT_UI_KIT?.mountAll(target),
        escapeHtml,
        firstText,
        firstNumber,
        formatBytes,
        formatInteger,
        formatRate,
        formatUptime,
        shouldDeferRender,
        realtime: window.DWRTRealtime
      });
    }
    return clientDetailsPage;
  }

  async function ensureClientDetailsPageLoaded() {
    await Promise.all([loadPageStyles('clientDetails'), loadClassicPageScript('clientDetails')]);
    return ensureClientDetailsPage();
  }

  function ensureInsightsFlowsPage() {
    if (insightsFlowsPage) return insightsFlowsPage;
    if (window.DWRTInsightsFlows && typeof window.DWRTInsightsFlows.create === 'function') {
      insightsFlowsPage = window.DWRTInsightsFlows.create({
        routePreview,
        fetchApiResource,
        scheduleGlassCardsRender,
        mountUiKit: (target) => window.DWRT_UI_KIT?.mountAll(target),
        escapeHtml,
        asArray,
        firstText,
        firstNumber,
        formatBytes,
        formatInteger,
        formatRate,
        shouldDeferRender,
        realtime: window.DWRTRealtime,
        authHeaders
      });
    }
    return insightsFlowsPage;
  }

  async function ensureInsightsFlowsPageLoaded() {
    await Promise.all([loadPageStyles('insightsFlows'), loadClassicPageScript('insightsFlows')]);
    return ensureInsightsFlowsPage();
  }


  async function ensureTopologyRendererLoaded() {
    await loadClassicPageScript('topology');
    return window.DWRT_UNIFI_TOPOLOGY;
  }

  function iconSvg(name) {
    const icons = window.DWRT_MENU_ICON || {};
    return icons[name] || icons.default || '';
  }

  function actionSvg(name) {
    const icons = window.DWRT_ACTION_ICON || {};
    return icons[name] || '';
  }

  function setupActionIcons() {
    const userIcon = userButton && userButton.querySelector('.action-icon');
    const collapseIcon = sidebarToggle && sidebarToggle.querySelector('.action-icon');
    if (userIcon && actionSvg('user')) userIcon.innerHTML = actionSvg('user');
    if (collapseIcon && actionSvg('collapse')) collapseIcon.innerHTML = actionSvg('collapse');
  }

  async function fetchWithTimeout(url, options = {}, timeoutMs = SHELL_FETCH_TIMEOUT_MS.default) {
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = controller ? window.setTimeout(() => controller.abort(), timeoutMs) : null;
    const { dwrtSession, ...request } = options;
    try {
      const next = { ...request, signal: controller ? controller.signal : request.signal };
      return dwrtSession && window.DWRT_SESSION
        ? await window.DWRT_SESSION.fetch(url, next)
        : await fetch(url, next);
    } catch (error) {
      if (error && error.name === 'AbortError') {
        const timeoutError = new Error(`${url} timeout after ${timeoutMs}ms`);
        timeoutError.timeout = true;
        throw timeoutError;
      }
      throw error;
    } finally {
      if (timer) window.clearTimeout(timer);
    }
  }

  async function readJson(url, timeoutMs = SHELL_FETCH_TIMEOUT_MS.static) {
    const res = await fetchWithTimeout(`${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`, {
      credentials: 'same-origin',
      cache: 'no-store'
    }, timeoutMs);
    if (!res.ok) throw new Error(`${url} ${res.status}`);
    return res.json();
  }

  async function readRuntimeJson(url) {
    const res = await fetchWithTimeout(`${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`, {
      credentials: 'same-origin',
      cache: 'no-store',
      headers: authHeaders({ Accept: 'application/json' }),
      dwrtSession: true
    }, SHELL_FETCH_TIMEOUT_MS.runtime);
    if (!res.ok) throw new Error(`${url} ${res.status}`);
    return res.json();
  }

  // /api/v1/bootstrap 在启动时会被菜单、主题、realtime 三方各拉一次;
  // 共享同一个 promise,10 秒内只发一次请求。
  let bootstrapSharedPromise = null;
  let bootstrapSharedAt = 0;
  function fetchBootstrapShared() {
    const now = Date.now();
    if (bootstrapSharedPromise && now - bootstrapSharedAt < 10000) return bootstrapSharedPromise;
    bootstrapSharedAt = now;
    bootstrapSharedPromise = readRuntimeJson('/api/v1/bootstrap').catch((error) => {
      bootstrapSharedPromise = null;
      throw error;
    });
    return bootstrapSharedPromise;
  }
  window.DWRT_BOOTSTRAP_FETCH = fetchBootstrapShared;

  function readWarmShellValue(key) {
    const prewarm = window.DWRTShellPrewarm;
    if (prewarm && typeof prewarm.read === 'function') return prewarm.read(key);
    try {
      const record = JSON.parse(sessionStorage.getItem(key) || 'null');
      if (!record || record.version !== SHELL_WARM_CACHE.version || Date.now() - Number(record.at || 0) > SHELL_WARM_CACHE.maxAgeMs) return null;
      return record.value;
    } catch (_) {
      return null;
    }
  }

  function promotePrimaryUsersMenu(items) {
    const source = Array.isArray(items) ? items : [];
    let usersItem = null;
    const withoutUsers = source.reduce((result, item) => {
      if (!item || typeof item !== 'object') return result;
      const isUsers = itemKey(item) === 'system-users' || routeHashFromPath(item.path) === '#/system/users';
      if (isUsers) {
        usersItem ||= item;
        return result;
      }
      const children = Array.isArray(item.children) ? item.children.filter((child) => {
        const childIsUsers = child && (itemKey(child) === 'system-users' || routeHashFromPath(child.path) === '#/system/users');
        if (childIsUsers) usersItem ||= child;
        return !childIsUsers;
      }) : [];
      result.push({ ...item, children });
      return result;
    }, []);
    if (!usersItem) return withoutUsers;
    const primaryUsers = { ...usersItem, bottom: true, children: [] };
    const systemIndex = withoutUsers.findIndex((item) => itemKey(item) === 'system');
    withoutUsers.splice(systemIndex >= 0 ? systemIndex + 1 : withoutUsers.length, 0, primaryUsers);
    return withoutUsers;
  }

  function normalizeMenu(data) {
    if (Array.isArray(data)) return { items: promotePrimaryUsersMenu(data), hidePages: [], hideFuncs: [], addFuncs: [], capabilities: {}, disabledCapabilities: [] };
    return {
      items: promotePrimaryUsersMenu(Array.isArray(data && data.items) ? data.items : []),
      hidePages: Array.isArray(data && data.hidePages) ? data.hidePages : [],
      hideFuncs: Array.isArray(data && data.hideFuncs) ? data.hideFuncs : [],
      addFuncs: Array.isArray(data && data.addFuncs) ? data.addFuncs : [],
      capabilities: data && typeof data.capabilities === 'object' ? data.capabilities : {},
      disabledCapabilities: Array.isArray(data && data.disabledCapabilities) ? data.disabledCapabilities : []
    };
  }

  function mergeMenuConfig(base, extra) {
    return {
      ...base,
      hidePages: [...new Set([...(base.hidePages || []), ...(extra.hidePages || [])])],
      hideFuncs: [...new Set([...(base.hideFuncs || []), ...(extra.hideFuncs || [])])],
      disabledCapabilities: [...new Set([...(base.disabledCapabilities || []), ...(extra.disabledCapabilities || [])])],
      capabilities: { ...(base.capabilities || {}), ...(extra.capabilities || {}) }
    };
  }

  async function loadRuntimeMenuConfig() {
    const config = { hidePages: [], hideFuncs: [], disabledCapabilities: [], capabilities: {} };
    try {
      const bootstrap = await fetchBootstrapShared();
      const data = bootstrap && bootstrap.data ? bootstrap.data : bootstrap;
      if (window.DWRTRealtime && typeof window.DWRTRealtime.configure === 'function') {
        window.DWRTRealtime.configure(data || {});
      }
      if (data && typeof data.capabilities === 'object') Object.assign(config.capabilities, data.capabilities);
      const device = data && data.device || {};
      if (device.wifi_supported === false || data.wifi_supported === false || data.wireless_supported === false) config.capabilities.wifi = false;
      if (device.qwrt_modules_supported === false || data.qwrt_modules_supported === false || data.qwrt_supported === false) config.capabilities.qwrt_modules = false;
      if (Array.isArray(data && data.hideFuncs)) config.hideFuncs.push(...data.hideFuncs);
      if (Array.isArray(data && data.hidePages)) config.hidePages.push(...data.hidePages);
      if (Array.isArray(data && data.disabledCapabilities)) config.disabledCapabilities.push(...data.disabledCapabilities);
    } catch (_) {}
    return config;
  }

  function itemKey(item) {
    return item.id || item.func_name || item.path || item.label;
  }

  function itemPath(item) {
    return normalizeRoutePath(item.path || `#/menu/${encodeURIComponent(itemKey(item))}`);
  }

  function routeHashFromPath(path) {
    const value = String(path || '');
    const index = value.indexOf('#');
    return index >= 0 ? value.slice(index) : value;
  }

  function normalizeRoutePath(path) {
    const value = String(path || '');
    const hash = routeHashFromPath(value) || value;
    const cleanHash = cleanRouteHash(hash);
    if (cleanHash === '#/insights' || cleanHash === '#/insights/') {
      return value.includes('#')
        ? value.replace(/#\/insights\/?(?=$|[?])/, '#/insights/flows')
        : '/app/#/insights/flows';
    }
    if (/^#\/network\/(?:lan-config|wan-config)$/.test(cleanHash)) {
      return value.includes('#')
        ? value.replace(/#\/network\/(?:lan-config|wan-config)(?=$|[?])/, '#/network/global-config')
        : '/app/#/network/global-config';
    }
    return path;
  }

  function safePluginModuleUrl(resource) {
    if (typeof resource !== 'string') return '';
    let value = resource.trim();
    if (!value || value.includes('\\') || value.includes('?') || value.includes('#') || /[\x00-\x1f]/.test(value)) return '';
    if (/^[a-z][a-z0-9+.-]*:/i.test(value) || value.startsWith('//')) return '';
    value = value.replace(/^\/+/, '');
    if (value.startsWith('plugins/')) value = value.slice('plugins/'.length);
    if (!/^(native|third-party)\//.test(value) || !value.endsWith('.js')) return '';
    if (!/^[A-Za-z0-9._~@/-]+$/.test(value)) return '';
    const parts = value.split('/');
    if (parts.some((part) => !part || part === '.' || part === '..')) return '';
    return `/plugins/${value}`;
  }

  function itemRouteModuleResource(item) {
    if (!item || typeof item !== 'object') return '';
    const plugin = item.plugin && typeof item.plugin === 'object' ? item.plugin : {};
    return item.module || item.route_module || item.plugin_module || item.resource || item.plugin_resource || plugin.module || plugin.resource || '';
  }

  function safeStaticStyleUrl(resource) {
    if (typeof resource !== 'string') return '';
    const value = resource.trim();
    if (!value || value.includes('\\') || value.includes('#') || /[\x00-\x1f]/.test(value)) return '';
    const match = value.match(/^(\/static\/css\/[A-Za-z0-9._~-]+\.css)(?:\?v=([A-Za-z0-9._-]+))?$/);
    return match ? match[1] : '';
  }

  function itemRouteStyleResource(item) {
    if (!item || typeof item !== 'object') return '';
    const plugin = item.plugin && typeof item.plugin === 'object' ? item.plugin : {};
    return item.style || item.route_style || item.css || item.plugin_style || plugin.style || plugin.css || '';
  }

  function routeItemStyleEntry(item) {
    const url = safeStaticStyleUrl(itemRouteStyleResource(item));
    if (!url) return null;
    const rawVersion = item && (item.style_version || item.module_version || item.resource_version || item.version);
    const shellVersioned = new Set(['/static/css/system-settings.css', '/static/css/global-config.css', '/static/css/network-interface-config.css', '/static/css/network-services.css', '/static/css/policy-status.css', '/static/css/user-authentication.css', '/static/css/vpn-config.css']);
    const requestedVersion = shellVersioned.has(url) ? VERSION : (rawVersion || VERSION);
    const version = String(requestedVersion).replace(/[^A-Za-z0-9._-]/g, '') || VERSION;
    return { url, version };
  }

  function loadRouteItemStyle(item) {
    const entry = routeItemStyleEntry(item);
    if (!entry) return Promise.resolve();
    return loadPageStyle(entry);
  }

  function routeModuleCacheUrl(item, url) {
    const rawVersion = item && (item.module_version || item.resource_version || item.version);
    const shellVersioned = new Set(['/plugins/native/system-settings.js', '/plugins/native/global-config.js', '/plugins/native/network-interface-config.js', '/plugins/native/network-services.js', '/plugins/native/policy-status.js', '/plugins/native/user-authentication.js', '/plugins/native/vpn-config.js']);
    const requestedVersion = shellVersioned.has(url) ? VERSION : (rawVersion || VERSION);
    const version = String(requestedVersion).replace(/[^A-Za-z0-9._-]/g, '') || VERSION;
    return `${url}?v=${encodeURIComponent(version)}`;
  }

  function routeModuleKeys(item) {
    if (!item) return [];
    return [...new Set([
      itemKey(item),
      item.id,
      item.func_name,
      item.path,
      itemPath(item),
      routeHashFromPath(itemPath(item))
    ].filter(Boolean).map(String))];
  }

  function flattenMenuItems(items, out = []) {
    (items || []).forEach((item) => {
      if (!item || typeof item !== 'object') return;
      out.push(item);
      flattenMenuItems(item.children || [], out);
    });
    return out;
  }

  function buildRouteModuleManifest() {
    const modules = new Map();
    flattenMenuItems(state.menu).forEach((item) => {
      const url = safePluginModuleUrl(itemRouteModuleResource(item));
      if (!url) return;
      const entry = { item, url: routeModuleCacheUrl(item, url) };
      routeModuleKeys(item).forEach((key) => modules.set(key, entry));
    });
    state.routeModules = modules;
  }

  function filterItems(items, config) {
    const hideFuncs = new Set(['ai', 'audit_view', 'advanced_audit', 'lan_config', 'wan_config', 'container_service', 'advanced_plugins', 'advanced_plugins_index', ...(config.hideFuncs || [])]);
    const hidePages = new Set(['/app/#/ai/assistant', '/app/#/network/lan-config', '/app/#/network/wan-config', '/app/#/plugins/advanced', ...(config.hidePages || [])]);
    const disabledCapabilities = new Set(config.disabledCapabilities || []);
    // The runtime menu gate drops qwrt_modules whenever no capability bit declares
    // it, but /api/v1/services/cellular and its slot/apn/status siblings are
    // registered unconditionally. A resource endpoint is the authority on its own
    // availability, so the route stays reachable and the page classifies real
    // failures (404/405/501 vs 401 vs 5xx) itself instead of showing a stub.
    const alwaysVisible = new Set(['wifi-config', 'wireless-status', 'qwrt-modules']);
    Object.entries(config.capabilities || {}).forEach(([key, value]) => {
      if (value === false || value === 0 || String(value).toLowerCase() === 'false') disabledCapabilities.add(key);
    });
    const capabilityEnabled = (key) => {
      if (!key) return false;
      const value = config.capabilities && config.capabilities[key];
      return value === true || value === 1 || String(value).toLowerCase() === 'true';
    };
    return (items || [])
      .filter((item) => item && (alwaysVisible.has(itemKey(item)) || item.hidden !== true))
      .filter((item) => alwaysVisible.has(itemKey(item)) || item.availability === 'unavailable' || !hideFuncs.has(item.func_name) && !hidePages.has(item.path))
      .filter((item) => alwaysVisible.has(itemKey(item)) || item.availability === 'unavailable' || !item.capability || !disabledCapabilities.has(item.capability))
      .map((item) => {
        const children = filterItems(item.children || [], config);
        const gated = item.availability === 'unavailable' && !capabilityEnabled(item.capability);
        return {
          ...item,
          children,
          availability: gated ? 'unavailable' : item.availability === 'unavailable' ? 'available' : item.availability,
          disabled: gated && !children.length
        };
      });
  }

  function mergeStaticRouteResources(runtimeItems, staticItems) {
    const resourceKeys = ['module', 'module_version', 'style', 'style_version', 'resource_version', 'capability', 'availability', 'unavailable_reason'];
    const references = new Map();
    flattenMenuItems(staticItems).forEach((item) => {
      routeModuleKeys(item).forEach((key) => references.set(String(key), item));
    });
    const sharesRouteKey = (left, right) => {
      const leftKeys = new Set(routeModuleKeys(left).map(String));
      return routeModuleKeys(right).some((key) => leftKeys.has(String(key)));
    };
    const cloneFrontendItem = (item) => ({
      ...item,
      children: (item.children || []).map(cloneFrontendItem)
    });
    const merge = (items, staticSiblings = []) => {
      const merged = (items || []).map((item) => {
      const reference = routeModuleKeys(item).map((key) => references.get(String(key))).find(Boolean);
      const next = { ...item };
      if (reference) resourceKeys.forEach((key) => {
        if (reference[key] !== undefined && reference[key] !== null && reference[key] !== '') next[key] = reference[key];
      });
      if (reference?.override_runtime_label === true && reference.label) next.label = reference.label;
      next.children = merge(item.children || [], reference?.children || []);
      return next;
      });
      (staticSiblings || []).forEach((item) => {
        const preserveFrontendContract = item?.frontend_owned === true || item?.availability === 'unavailable';
        if (item?.frontend_owned !== true && item?.availability !== 'unavailable') return;
        if (!preserveFrontendContract || merged.some((existing) => sharesRouteKey(existing, item))) return;
        merged.push(cloneFrontendItem(item));
      });
      return merged;
    };
    return merge(runtimeItems, staticItems);
  }

  async function loadMenu(options = {}) {
    const includeRuntimeConfig = options.includeRuntimeConfig !== false;
    const urls = includeRuntimeConfig ? MENU_URLS : [STATIC_MENU_URL];
    let lastError = null;
    for (const url of urls) {
      try {
        let raw = menuJsonCache.get(url);
        if (!raw) {
          try {
            raw = await readJson(url);
          } catch (error) {
            raw = url === STATIC_MENU_URL ? readWarmShellValue(SHELL_WARM_CACHE.menu) : null;
            if (!raw) throw error;
          }
          menuJsonCache.set(url, raw);
        }
        const normalized = normalizeMenu(raw);
        if (url === RUNTIME_MENU_URL) {
          let staticRaw = menuJsonCache.get(STATIC_MENU_URL);
          if (!staticRaw) {
            try {
              staticRaw = await readJson(STATIC_MENU_URL);
            } catch (error) {
              staticRaw = readWarmShellValue(SHELL_WARM_CACHE.menu);
              if (!staticRaw) throw error;
            }
            menuJsonCache.set(STATIC_MENU_URL, staticRaw);
          }
          const staticMenu = normalizeMenu(staticRaw);
          normalized.items = mergeStaticRouteResources(normalized.items, staticMenu.items);
          normalized.hidePages = [...new Set([...(normalized.hidePages || []), ...(staticMenu.hidePages || [])])];
          normalized.hideFuncs = [...new Set([...(normalized.hideFuncs || []), ...(staticMenu.hideFuncs || [])])];
        }
        const runtimeConfig = includeRuntimeConfig
          ? await loadRuntimeMenuConfig()
          : { hidePages: [], hideFuncs: [], disabledCapabilities: [], capabilities: {} };
        const merged = mergeMenuConfig(normalized, runtimeConfig);
        state.capabilities = { ...(merged.capabilities || {}) };
        state.menu = filterItems(normalized.items, merged);
        buildRouteModuleManifest();
        state.source = url;
        if (menuSource) {
          menuSource.textContent = includeRuntimeConfig
            ? (url.includes('/dynamic/') ? '运行时菜单' : '静态菜单')
            : '静态菜单';
        }
        return;
      } catch (error) {
        lastError = error;
      }
    }
    if (menuSource) menuSource.textContent = `菜单加载失败: ${lastError ? lastError.message : 'unknown'}`;
    state.menu = [];
    buildRouteModuleManifest();
  }

  function cleanRouteHash(hash) {
    const value = String(hash || window.location.hash || '#/dashboard');
    const queryIndex = value.indexOf('?');
    return queryIndex >= 0 ? value.slice(0, queryIndex) : value;
  }

  function findByHash(hash) {
    const target = cleanRouteHash(hash);
    for (const primary of state.menu) {
      for (const secondary of primary.children || []) {
        if (itemPath(secondary).endsWith(target)) return { primary, secondary };
      }
      if (itemPath(primary).endsWith(target)) return { primary, secondary: null };
      if (primary.id === 'insights' && target.startsWith('#/insights/')) {
        const matched = (primary.children || []).find((secondary) => itemPath(secondary).endsWith(target));
        return { primary, secondary: matched || null };
      }
      if (primary.id === 'log-center' && (target === '#/logs' || target === '#/logs/' || target.startsWith('#/logs/'))) return { primary, secondary: null };
    }
    return { primary: state.menu[0] || null, secondary: null };
  }

  function commitRoute(path) {
    const target = normalizeRoutePath(path);
    if (!target) return;
    history.replaceState(null, '', target);
    syncFromLocation();
  }

  function routeTo(path) {
    pendingMenuRouteToken += 1;
    beginPageGlassRouteTransition(true);
    commitRoute(path);
  }

  function routeToAfterMenuPaint(path) {
    const target = normalizeRoutePath(path);
    if (!target) return;
    const token = ++pendingMenuRouteToken;
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        if (token === pendingMenuRouteToken) commitRoute(target);
      });
    });
  }

  function searchableText(parts) {
    return parts.filter(Boolean).join(' ').toLowerCase();
  }

  function normalizeCommandValue(value) {
    return String(value || '').trim().toLowerCase();
  }

  function normalizeMacValue(value) {
    return normalizeCommandValue(value).replace(/[^0-9a-f]/g, '');
  }

  function commandListFrom(payload, keys) {
    const source = unwrapApiData(payload);
    if (Array.isArray(source)) return source;
    for (const key of keys) {
      if (Array.isArray(source && source[key])) return source[key];
    }
    return [];
  }

  function commandEntrySearch(parts) {
    const values = parts.flatMap((value) => Array.isArray(value) ? value : [value]).filter(Boolean);
    const plain = searchableText(values);
    const compactMacs = values.map(normalizeMacValue).filter((value) => value.length >= 6);
    return `${plain} ${compactMacs.join(' ')}`.trim();
  }

  function buildCommandEntries() {
    const entries = [];
    state.menu.forEach((primary) => {
      const children = Array.isArray(primary.children) ? primary.children : [];
      const primaryKey = itemKey(primary);
      const firstChild = children[0];
      const primaryPath = itemPath(firstChild || primary);
      if (!primary.disabled) entries.push({
        id: `primary:${primaryKey}`,
        label: primary.label || primaryKey,
        group: primary.bottom ? '系统' : '一级菜单',
        kind: 'navigation',
        description: firstChild ? `打开 ${firstChild.label || itemKey(firstChild)}` : itemPath(primary),
        icon: primary.icon,
        path: primaryPath,
        search: searchableText([primary.label, primaryKey, primary.func_name, itemPath(primary), firstChild && firstChild.label])
      });
      children.filter((child) => !child.disabled).forEach((child) => {
        const childKey = itemKey(child);
        entries.push({
          id: `secondary:${primaryKey}:${childKey}`,
          label: child.label || childKey,
          group: primary.label || '二级菜单',
          kind: 'navigation',
          description: itemPath(child),
          icon: child.icon || primary.icon,
          path: itemPath(child),
          search: searchableText([primary.label, child.label, childKey, child.func_name, itemPath(child)])
        });
      });
    });
    entries.push(
      {
        id: 'action:refresh', label: '刷新当前页面', group: '操作', kind: 'action', icon: 'refresh',
        description: '重新读取当前页面数据', action: 'refresh', search: searchableText(['刷新', '重载', 'reload', 'refresh'])
      },
      {
        id: 'action:theme', label: '切换明暗主题', group: '操作', kind: 'action', icon: 'theme',
        description: '切换当前界面主题', action: 'theme', search: searchableText(['主题', '深色', '浅色', '暗色', 'theme', 'dark', 'light'])
      },
      {
        id: 'action:sidebar', label: '展开或收起侧栏', group: '操作', kind: 'action', icon: 'menu',
        description: '调整主菜单宽度', action: 'sidebar', search: searchableText(['侧栏', '菜单', '折叠', '展开', 'sidebar'])
      }
    );
    state.commandStaticEntries = entries;
    state.commandEntries = [...entries, ...state.commandEntityEntries];
    state.commandFiltered = entries;
    state.commandSelected = 0;
  }

  function commandClientEntries(payload) {
    return commandListFrom(payload, ['clients', 'users', 'active_users', 'items', 'rows', 'list', 'records']).map((client, index) => {
      const mac = firstText(client.mac, client.client_mac, client.hwaddr);
      const ips = [
        client.ip, client.ipv4, client.ipaddr, client.client_ip, client.management_ip,
        client.ipv6, client.ipv6_global, client.global_ipv6,
        ...asArray(client.ipv6_addrs), ...asArray(client.ipv6_addresses)
      ].map((value) => firstText(value)).filter(Boolean);
      const label = firstText(client.custom_name, client.display_name, client.nickname, client.name, client.hostname, mac, ips[0], `终端 ${index + 1}`);
      const vendor = firstText(client.vendor_name, client.vendor, client.manufacturer, client.brand);
      const model = firstText(client.model, client.device_name, client.device_model);
      const network = firstText(client.network, client.interface, client.ifname);
      const status = onlineState(client.online ?? client.status) === false ? '离线' : '在线';
      return {
        id: `client:${normalizeMacValue(mac) || normalizeCommandValue(ips[0]) || index}`,
        label,
        group: '终端',
        kind: 'client',
        icon: 'client_detail',
        image: topologyClientImage(client),
        description: [ips[0], mac, vendor || model, status].filter(Boolean).join(' · '),
        path: '/app/#/monitor/client-details',
        mac,
        identifiers: [mac, ...ips],
        search: commandEntrySearch([label, mac, ips, vendor, model, network, client.port, client.type, client.category])
      };
    }).filter((entry) => entry.mac || entry.identifiers.length);
  }

  function commandNetworkEntries(wanPayload, lanPayload) {
    const entries = [];
    const physical = new Map();
    const addPhysical = (name, parent, role, path, addresses) => {
      const id = normalizeCommandValue(name);
      if (!id || physical.has(id)) return;
      const entry = {
        id: `interface:${id}`,
        label: name,
        group: '网络接口',
        kind: 'interface',
        icon: role === 'WAN' ? 'line_status' : 'network_config',
        description: `${role} 物理接口 · ${parent}${addresses.length ? ` · ${addresses[0]}` : ''}`,
        path,
        identifiers: [name],
        search: commandEntrySearch([name, parent, role, addresses, '物理接口', '端口'])
      };
      physical.set(id, entry);
      entries.push(entry);
    };
    commandListFrom(wanPayload, ['wans', 'interfaces', 'items', 'lines']).forEach((wan, index) => {
      const id = firstText(wan.id, wan.ifname, wan.name, `wan${index || ''}`);
      const device = firstText(wan.device, wan.runtime && wan.runtime.device);
      const runtimeDevice = firstText(wan.runtime_device, wan.runtime && wan.runtime.runtime_device);
      const addresses = [wan.ip, wan.ipv4, wan.ipaddr, wan.public_ip, wan.ipv6, wan.ipv6_global].map((value) => firstText(value)).filter(Boolean);
      entries.push({
        id: `wan:${normalizeCommandValue(id)}`,
        label: firstText(wan.name, id).toUpperCase(),
        group: 'WAN 线路',
        kind: 'wan',
        icon: 'line_status',
        description: [firstText(wan.carrier_name, wan.carrier, wan.note), device, addresses[0], onlineState(wan.online ?? wan.runtime?.online) === false ? '离线' : '在线'].filter(Boolean).join(' · '),
        path: '/app/#/network/global-config',
        identifiers: [id, wan.ifname, device, runtimeDevice, ...addresses],
        search: commandEntrySearch([id, wan.name, wan.ifname, device, runtimeDevice, addresses, wan.carrier, wan.carrier_name, wan.note, '线路'])
      });
      addPhysical(device, id, 'WAN', '/app/#/network/global-config', addresses);
    });
    commandListFrom(lanPayload, ['lans', 'interfaces', 'items', 'lines']).forEach((lan, index) => {
      const id = firstText(lan.id, lan.ifname, lan.name, `lan${index || ''}`);
      const device = firstText(lan.device);
      const ports = [...new Set([...asArray(lan.ports), ...asArray(lan.port_labels)].map((value) => firstText(value)).filter(Boolean))];
      const addresses = [lan.ip, lan.ipv4, lan.ipaddr].map((value) => firstText(value)).filter(Boolean);
      entries.push({
        id: `lan:${normalizeCommandValue(id)}`,
        label: firstText(lan.name, id).toUpperCase(),
        group: 'LAN 网络',
        kind: 'lan',
        icon: 'network_config',
        description: [device, addresses[0], ports.length ? `${ports.length} 个端口` : ''].filter(Boolean).join(' · '),
        path: '/app/#/network/global-config',
        identifiers: [id, lan.ifname, device, ...ports, ...addresses],
        search: commandEntrySearch([id, lan.name, lan.ifname, device, ports, addresses, lan.note, '局域网', '接口'])
      });
      [device, ...ports].forEach((port) => addPhysical(port, id, 'LAN', '/app/#/network/global-config', addresses));
    });
    return entries;
  }

  async function loadCommandEntities() {
    const now = Date.now();
    if (state.commandEntitiesLoading || state.commandEntityEntries.length && now - state.commandEntitiesLoadedAt < 60000) return;
    const loadId = ++state.commandEntityLoadId;
    state.commandEntitiesLoading = true;
    updateCommandChrome();
    const [clients, wans, lans] = await Promise.all([
      fetchApiResource('command_clients', '/api/v1/clients'),
      fetchApiResource('command_wans', '/api/v1/network/wans'),
      fetchApiResource('command_lans', '/api/v1/network/lans')
    ]);
    if (loadId !== state.commandEntityLoadId) return;
    state.commandEntitiesLoading = false;
    state.commandEntitiesLoadedAt = Date.now();
    state.commandEntityEntries = [
      ...(clients.ok ? commandClientEntries(clients.data) : []),
      ...commandNetworkEntries(wans.ok ? wans.data : {}, lans.ok ? lans.data : {})
    ];
    state.commandEntries = [...state.commandStaticEntries, ...state.commandEntityEntries];
    if (!state.commandOpen) return;
    state.commandFiltered = filterCommandEntries(commandPaletteInput?.value || '');
    state.commandSelected = 0;
    renderCommandResults();
    updateCommandChrome();
  }

  function springStep(value, velocity, target, dt, response = 0.34, damping = 1) {
    const omega = (Math.PI * 2) / response;
    const acceleration = omega * omega * (target - value) - 2 * damping * omega * velocity;
    const nextVelocity = velocity + acceleration * dt;
    return [value + nextVelocity * dt, nextVelocity];
  }

  function paintMenuPill(pill, motion) {
    pill.style.transform = `translate3d(${motion.x}px, ${motion.y}px, 0)`;
    pill.style.width = `${motion.w}px`;
    pill.style.height = `${motion.h}px`;
  }

  function updateActivePill(container, pill, smooth = true) {
    if (!container || !pill) return;
    const resetPill = () => {
      pill.classList.remove('is-visible', 'is-bouncing');
      const motion = pillAnimations.get(pill);
      if (motion?.frame) cancelAnimationFrame(motion.frame);
      pillAnimations.delete(pill);
      pillRects.delete(pill);
      pill.style.setProperty('--pill-x', '0px');
      pill.style.setProperty('--pill-y', '0px');
      pill.style.setProperty('--pill-w', '0px');
      pill.style.setProperty('--pill-h', '0px');
      pill.style.setProperty('--pill-scale-y', '1');
      pill.style.setProperty('--pill-origin-y', '50%');
      pill.style.setProperty('--pill-bounce-y', '1.10');
    };
    const active = container.querySelector('.menu-item.active');
    const hiddenSecondary = container === secondaryMenu && appShell && appShell.classList.contains('submenu-hidden');
    const waitingForSubmenu = container === secondaryMenu && (
      container.offsetWidth < 80 || active && active.offsetWidth < 64
    );
    if (!active || hiddenSecondary || !container.offsetWidth || !active.offsetWidth || waitingForSubmenu) {
      resetPill();
      if (waitingForSubmenu) window.setTimeout(() => updateActivePill(container, pill, false), 160);
      return;
    }
    const next = {
      x: active.offsetLeft,
      y: active.offsetTop,
      w: active.offsetWidth,
      h: active.offsetHeight
    };
    let motion = pillAnimations.get(pill);
    if (!motion) {
      motion = { x: next.x, y: next.y, w: next.w, h: next.h, vx: 0, vy: 0, vw: 0, vh: 0, target: next, frame: 0, last: 0 };
      pillAnimations.set(pill, motion);
    }
    motion.target = next;
    pill.classList.add('is-visible');
    pill.classList.remove('is-bouncing');
    if (!smooth || window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) {
      Object.assign(motion, { x: next.x, y: next.y, w: next.w, h: next.h, vx: 0, vy: 0, vw: 0, vh: 0 });
      if (motion.frame) cancelAnimationFrame(motion.frame);
      motion.frame = 0;
      paintMenuPill(pill, motion);
      pillRects.set(pill, next);
      return;
    }
    if (!motion.frame) {
      motion.last = performance.now();
      const tick = (now) => {
        const dt = Math.min(0.032, Math.max(0.001, (now - motion.last) / 1000));
        motion.last = now;
        [motion.x, motion.vx] = springStep(motion.x, motion.vx, motion.target.x, dt);
        [motion.y, motion.vy] = springStep(motion.y, motion.vy, motion.target.y, dt);
        [motion.w, motion.vw] = springStep(motion.w, motion.vw, motion.target.w, dt);
        [motion.h, motion.vh] = springStep(motion.h, motion.vh, motion.target.h, dt);
        paintMenuPill(pill, motion);
        const done = Math.abs(motion.target.x - motion.x) < 0.12 && Math.abs(motion.vx) < 0.96
          && Math.abs(motion.target.y - motion.y) < 0.12 && Math.abs(motion.vy) < 0.96
          && Math.abs(motion.target.w - motion.w) < 0.12 && Math.abs(motion.vw) < 0.96
          && Math.abs(motion.target.h - motion.h) < 0.12 && Math.abs(motion.vh) < 0.96;
        if (done || !pill.isConnected) {
          Object.assign(motion, { x: motion.target.x, y: motion.target.y, w: motion.target.w, h: motion.target.h, vx: 0, vy: 0, vw: 0, vh: 0, frame: 0 });
          if (pill.isConnected) paintMenuPill(pill, motion);
          return;
        }
        motion.frame = requestAnimationFrame(tick);
      };
      motion.frame = requestAnimationFrame(tick);
    }
    pillRects.set(pill, next);
  }

  function updateActivePills(smooth = true) {
    window.requestAnimationFrame(() => {
      updateActivePill(primaryMenu, primaryActivePill, smooth);
      updateActivePill(bottomMenu, bottomActivePill, smooth);
      updateActivePill(secondaryMenu, secondaryActivePill, smooth);
    });
  }

  function setSidebarCollapsed(collapsed) {
    if (!appShell) return;
    appShell.classList.toggle('sidebar-collapsed', collapsed);
    sidebarToggle && sidebarToggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    try {
      localStorage.setItem('dreamingwrt.web.sidebarCollapsed', collapsed ? '1' : '0');
    } catch (_) {}
    window.setTimeout(() => updateActivePills(false), 560);
  }

  function setCommandOpen(open) {
    if (!commandPalette) return;
    state.commandOpen = !!open;
    commandPalette.hidden = !open;
    menuSearchTrigger && menuSearchTrigger.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open) {
      state.commandReturnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : menuSearchTrigger;
      if (accountPopover && !accountPopover.hidden) toggleAccountPopover(false);
      state.commandMode = 'search';
      state.commandFiltered = filterCommandEntries('');
      state.commandSelected = 0;
      if (commandPaletteInput) commandPaletteInput.value = '';
      renderCommandResults();
      updateCommandChrome();
      loadCommandEntities();
      window.setTimeout(() => commandPaletteInput && commandPaletteInput.focus(), 40);
    } else {
      if (commandPaletteInput) commandPaletteInput.value = '';
      const returnFocus = state.commandReturnFocus;
      state.commandReturnFocus = null;
      window.requestAnimationFrame(() => {
        if (returnFocus && returnFocus.isConnected && typeof returnFocus.focus === 'function') returnFocus.focus();
        else menuSearchTrigger?.focus();
      });
    }
  }

  function selectCommand(index) {
    if (!state.commandFiltered.length) return;
    state.commandSelected = (index + state.commandFiltered.length) % state.commandFiltered.length;
    updateCommandSelection();
  }

  function filterCommandEntries(query) {
    const normalized = normalizeCommandValue(query);
    if (state.commandMode === 'ai') {
      if (!normalized) return [];
      return [{
        id: 'ai:query', label: '发送给 AI', group: 'AI', kind: 'ai', icon: 'ai',
        description: String(query || '').trim(), action: 'ai', search: normalized
      }];
    }
    if (!normalized) return state.commandStaticEntries;
    const tokens = normalized.split(/\s+/).filter(Boolean);
    const compactQuery = normalizeMacValue(normalized);
    return state.commandEntries
      .map((entry, order) => {
        if (!tokens.every((token) => entry.search.includes(token) || normalizeMacValue(token).length >= 4 && entry.search.includes(normalizeMacValue(token)))) return null;
        const identifiers = asArray(entry.identifiers).map(normalizeCommandValue);
        const compactIdentifiers = identifiers.map(normalizeMacValue).filter(Boolean);
        let rank = 50;
        if (identifiers.includes(normalized) || compactQuery.length >= 4 && compactIdentifiers.includes(compactQuery)) rank = 0;
        else if (identifiers.some((value) => value.startsWith(normalized)) || compactQuery.length >= 4 && compactIdentifiers.some((value) => value.startsWith(compactQuery))) rank = 5;
        else if (normalizeCommandValue(entry.label) === normalized) rank = 10;
        else if (normalizeCommandValue(entry.label).startsWith(normalized)) rank = 20;
        else if (entry.kind === 'client') rank = 30;
        else if (entry.kind === 'interface' || entry.kind === 'wan' || entry.kind === 'lan') rank = 35;
        return { entry, rank, order };
      })
      .filter(Boolean)
      .sort((a, b) => a.rank - b.rank || a.order - b.order)
      .slice(0, 60)
      .map((item) => item.entry);
  }

  function openCommandEntry(entry) {
    if (!entry) return;
    if (entry.action === 'ai') {
      const prompt = String(commandPaletteInput?.value || entry.description || '').trim();
      if (!prompt) return;
      setCommandOpen(false);
      openGlobalAi({ prompt, autoSend: true });
      return;
    }
    if (entry.action === 'refresh') {
      setCommandOpen(false);
      window.location.reload();
      return;
    }
    if (entry.action === 'theme') {
      setCommandOpen(false);
      cycleThemePreference();
      return;
    }
    if (entry.action === 'sidebar') {
      setCommandOpen(false);
      setSidebarCollapsed(!appShell.classList.contains('sidebar-collapsed'));
      return;
    }
    if (!entry.path) return;
    const clientDetailsAlreadyOpen = cleanRouteHash() === '#/monitor/client-details';
    if (entry.kind === 'client' && entry.mac) {
      if (!clientDetailsAlreadyOpen) {
        try { sessionStorage.setItem('dreamingwrt.clientDetails.initialMac', entry.mac); } catch (_) {}
      }
    }
    setCommandOpen(false);
    routeTo(entry.path);
    if (entry.kind === 'client' && entry.mac && clientDetailsAlreadyOpen) {
      window.setTimeout(() => window.dispatchEvent(new CustomEvent('dwrt:open-client-detail', { detail: { mac: entry.mac } })), 120);
    }
  }

  function setCommandMode(mode) {
    const next = mode === 'ai' ? 'ai' : 'search';
    if (state.commandMode === next) {
      if (next === 'ai' && commandPaletteInput?.value.trim()) openCommandEntry(filterCommandEntries(commandPaletteInput.value)[0]);
      return;
    }
    state.commandMode = next;
    state.commandFiltered = filterCommandEntries(commandPaletteInput?.value || '');
    state.commandSelected = 0;
    renderCommandResults();
    updateCommandChrome();
    commandPaletteInput?.focus();
  }

  function updateCommandChrome() {
    const ai = state.commandMode === 'ai';
    commandPalette?.querySelectorAll('[data-command-mode]').forEach((button) => {
      const active = button.dataset.commandMode === state.commandMode;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-pressed', active ? 'true' : 'false');
    });
    if (commandPaletteInput) commandPaletteInput.placeholder = ai ? '输入问题，按 Enter 直接发送给 AI' : '搜索菜单、IP、MAC、eth0、lan、wan…';
    if (commandPaletteTitle) commandPaletteTitle.textContent = ai ? '询问 AI' : state.commandEntitiesLoading ? '快速打开 · 正在读取终端与接口' : '快速打开';
    if (commandEnterAction) commandEnterAction.textContent = ai ? '发送' : '打开';
    if (commandPaletteEmpty) commandPaletteEmpty.textContent = ai ? '输入问题后按 Enter 发送给 AI' : state.commandEntitiesLoading ? '正在读取终端与接口…' : '没有找到匹配的菜单、终端或接口';
  }

  function updateCommandSelection() {
    commandPaletteResults?.querySelectorAll('[data-command-index]').forEach((button) => {
      const active = Number(button.dataset.commandIndex) === state.commandSelected;
      button.classList.toggle('is-selected', active);
      button.setAttribute('aria-selected', active ? 'true' : 'false');
      if (active) button.scrollIntoView({ block: 'nearest' });
    });
  }

  function renderCommandResults() {
    if (!commandPaletteResults || !commandPaletteEmpty) return;
    commandPaletteResults.textContent = '';
    commandPaletteEmpty.hidden = state.commandFiltered.length > 0;
    if (!state.commandFiltered.length) return;
    const groups = [];
    state.commandFiltered.forEach((entry, index) => {
      let group = groups.find((item) => item.label === entry.group);
      if (!group) {
        group = { label: entry.group, items: [] };
        groups.push(group);
      }
      group.items.push({ entry, index });
    });
    groups.forEach((group) => {
      const label = document.createElement('div');
      label.className = 'command-group-label';
      label.textContent = group.label;
      commandPaletteResults.appendChild(label);
      group.items.forEach(({ entry, index }) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = `command-item${index === state.commandSelected ? ' is-selected' : ''}`;
        button.dataset.commandIndex = String(index);
        button.setAttribute('role', 'option');
        button.setAttribute('aria-selected', index === state.commandSelected ? 'true' : 'false');
        const imageMarkup = entry.image ? `<img src="${escapeHtml(entry.image)}" alt="">` : iconSvg(entry.icon);
        button.innerHTML = `
          <span class="command-item-icon">${imageMarkup}</span>
          <span class="command-item-text"><strong></strong><span></span></span>
          <span class="command-item-arrow" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m13 5 7 7-7 7"/></svg>
          </span>`;
        button.querySelector('strong').textContent = entry.label;
        button.querySelector('.command-item-text span').textContent = entry.description || entry.path || '';
        button.addEventListener('mouseenter', () => {
          state.commandSelected = index;
          updateCommandSelection();
        });
        button.addEventListener('click', () => openCommandEntry(entry));
        commandPaletteResults.appendChild(button);
        if (index === state.commandSelected) {
          window.requestAnimationFrame(() => button.scrollIntoView({ block: 'nearest' }));
        }
      });
    });
  }

  function setMenuActive(container, activeKey) {
    if (!container) return;
    Array.from(container.children).forEach((node) => {
      if (!(node instanceof HTMLButtonElement) || !node.classList.contains('menu-item')) return;
      const active = node.dataset.key === activeKey;
      node.classList.toggle('active', active);
      if (active) node.setAttribute('aria-current', 'page');
      else node.removeAttribute('aria-current');
    });
  }

  function previewMenuSelection(item, level) {
    beginPageGlassRouteTransition();
    if (level === 'primary') {
      const children = Array.isArray(item.children) ? item.children : [];
      const firstChild = children[0] || null;
      state.activePrimary = itemKey(item);
      state.activeSecondary = firstChild ? itemKey(firstChild) : null;
      setMenuActive(primaryMenu, state.activePrimary);
      setMenuActive(bottomMenu, state.activePrimary);
      renderSecondary(item, state.activeSecondary);
      updateActivePills(true);
      routeToAfterMenuPaint(itemPath(firstChild || item));
      return;
    }
    state.activeSecondary = itemKey(item);
    setMenuActive(secondaryMenu, state.activeSecondary);
    updateActivePills(true);
    routeToAfterMenuPaint(itemPath(item));
  }

  const prefetchedRouteResources = new Set();
  const CLASSIC_PAGE_PREFETCH = [
    { match: '#/monitor/line-status', script: 'lineStatus', styles: 'lineStatus' },
    { match: '#/monitor/client-details', script: 'clientDetails', styles: 'clientDetails' },
    { match: '#/insights', script: 'insightsFlows', styles: 'insightsFlows' },
    { match: '#/monitor/topology', script: 'topology', styles: '' },
    { match: '#/dashboard', script: 'dashboard', styles: '' }
  ];

  function prefetchClassicPageAssets(path) {
    const hash = routeHashFromPath(path || '');
    const config = CLASSIC_PAGE_PREFETCH.find((candidate) => hash.startsWith(candidate.match));
    if (!config) return;
    const assets = [];
    const script = PAGE_SCRIPTS[config.script];
    if (script) assets.push({ href: pageScriptUrl(script), as: 'script' });
    (PAGE_STYLES[config.styles] || []).forEach((style) => {
      assets.push({ href: `${style.url}?v=${encodeURIComponent(style.version || VERSION)}`, as: 'style' });
    });
    assets.forEach((asset) => {
      if (prefetchedRouteResources.has(asset.href)) return;
      prefetchedRouteResources.add(asset.href);
      const link = document.createElement('link');
      link.rel = 'preload';
      link.as = asset.as;
      link.href = asset.href;
      document.head.appendChild(link);
    });
  }

  function prefetchRouteResourcesForItem(item) {
    if (!item || item.disabled) return;
    const targets = [item, ...(Array.isArray(item.children) ? item.children.slice(0, 1) : [])];
    targets.forEach((target) => prefetchClassicPageAssets(itemPath(target)));
    targets.forEach((target) => {
      const entry = routeModuleForItem(target);
      if (entry && entry.url && !prefetchedRouteResources.has(entry.url)) {
        prefetchedRouteResources.add(entry.url);
        const link = document.createElement('link');
        link.rel = 'modulepreload';
        link.href = entry.url;
        document.head.appendChild(link);
      }
      const styleEntry = routeItemStyleEntry((entry && entry.item) || target);
      if (styleEntry) {
        const styleHref = `${styleEntry.url}?v=${encodeURIComponent(styleEntry.version)}`;
        if (!prefetchedRouteResources.has(styleHref)) {
          prefetchedRouteResources.add(styleHref);
          const link = document.createElement('link');
          link.rel = 'preload';
          link.as = 'style';
          link.href = styleHref;
          document.head.appendChild(link);
        }
      }
    });
  }

  function createMenuButton(level) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'menu-item';
    button.innerHTML = '<span class="menu-icon"></span><span class="menu-label"></span>';
    button._dwrtMenuLevel = level;
    // 悬停即预取路由模块与样式(静态资源,不打扰 API 后端),点击时基本零等待。
    button.addEventListener('pointerenter', () => {
      const item = button._dwrtMenuItem;
      if (item) prefetchRouteResourcesForItem(item);
    });
    button.addEventListener('pointerdown', () => {
      const token = beginPageGlassRouteTransition(true);
      window.setTimeout(() => settlePageGlassRouteTransition(token), 0);
    });
    button.addEventListener('click', () => {
      const item = button._dwrtMenuItem;
      if (item.disabled) return;
      previewMenuSelection(item, button._dwrtMenuLevel);
    });
    return button;
  }

  function updateMenuButton(button, item, active, level) {
    const key = itemKey(item);
    const iconName = item.icon || '';
    const label = item.label || key;
    const icon = button.querySelector('.menu-icon');
    const labelNode = button.querySelector('.menu-label');
    if (button.dataset.icon !== iconName && icon) icon.innerHTML = iconSvg(iconName);
    if (labelNode && labelNode.textContent !== label) labelNode.textContent = label;
    button._dwrtMenuItem = item;
    button._dwrtMenuLevel = level;
    button.dataset.key = key;
    button.dataset.icon = iconName;
    button.dataset.path = itemPath(item);
    const unavailableReason = item.disabled ? firstText(item.unavailable_reason, '当前固件未提供所需能力。') : '';
    button.title = unavailableReason ? `${label}：${unavailableReason}` : label;
    button.setAttribute('aria-label', unavailableReason ? `${label}，不可用：${unavailableReason}` : label);
    button.dataset.availability = item.availability || 'available';
    button.disabled = Boolean(item.disabled);
    button.setAttribute('aria-disabled', item.disabled ? 'true' : 'false');
    button.classList.toggle('active', active);
    if (active) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  }

  function reconcileMenuItems(container, items, activeKey, level) {
    if (!container) return;
    const existing = new Map();
    Array.from(container.children).forEach((node) => {
      if (node instanceof HTMLButtonElement && node.classList.contains('menu-item')) {
        existing.set(node.dataset.key || '', node);
      }
    });
    const retained = new Set();
    let previous = container.querySelector(':scope > .menu-active-pill');
    items.forEach((item) => {
      const key = itemKey(item);
      let button = existing.get(key);
      if (!button) button = createMenuButton(level);
      updateMenuButton(button, item, key === activeKey, level);
      const expected = previous ? previous.nextElementSibling : container.firstElementChild;
      if (button !== expected) container.insertBefore(button, expected || null);
      retained.add(button);
      previous = button;
    });
    existing.forEach((button) => {
      if (!retained.has(button)) button.remove();
    });
  }

  function renderPrimary(activePrimary) {
    if (!primaryMenu) return;
    reconcileMenuItems(primaryMenu, state.menu.filter((item) => !item.bottom), activePrimary, 'primary');
    if (!bottomMenu) return;
    reconcileMenuItems(bottomMenu, state.menu.filter((item) => item.bottom), activePrimary, 'primary');
  }

  function beginMenuColumnSwitch() {
    if (!appShell) return;
    const token = ++menuColumnSwitchToken;
    appShell.classList.add('menu-columns-switching');
    beginPageGlassRouteTransition();
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          if (token === menuColumnSwitchToken) appShell.classList.remove('menu-columns-switching');
        });
      });
    });
  }

  function renderSecondary(primary, activeSecondary) {
    if (!secondaryMenu || !submenu || !submenuTitle) return;
    const children = primary && Array.isArray(primary.children) ? primary.children : [];
    const nextHidden = children.length === 0;
    if (appShell && appShell.classList.contains('submenu-hidden') !== nextHidden) beginMenuColumnSwitch();
    submenu.classList.toggle('empty', children.length === 0);
    submenu.hidden = nextHidden;
    submenu.setAttribute('aria-hidden', nextHidden ? 'true' : 'false');
    appShell && appShell.classList.toggle('submenu-hidden', nextHidden);
    submenuTitle.textContent = primary ? primary.label : '菜单';
    reconcileMenuItems(secondaryMenu, children, activeSecondary, 'secondary');
  }

  function clearRoutePageState() {
    state.routeLoadId += 1;
    state.routeAbortController?.abort('route-unmount');
    state.routeAbortController = null;
    const active = state.activeRouteModule;
    state.activeRouteModule = null;
    if (active && typeof active.unmount === 'function') {
      try { active.unmount(); } catch (error) { console.warn('[dreamingwrt-web] route module unmount failed', error); }
    }
    if (routePreview) window.DWRT_UI_KIT?.unmount?.(routePreview);
    Object.values(state.routePages || {}).forEach((page) => {
      if (page && page.timer) window.clearInterval(page.timer);
      if (page && page.charts) {
        page.charts.forEach((entry) => {
          try { entry && entry.chart && entry.chart.dispose(); } catch (_) {}
        });
      }
    });
    state.routePages = {};
    // A new route gets a fresh verdict on the reserved footer strip.
    resetPageFooterReserve();
  }

  async function renderLineStatusPage() {
    const loadId = state.routeLoadId;
    renderRouteModuleLoading({ label: '线路状态' }, '/app/#/monitor/line-status');
    try {
      const page = await ensureLineStatusPageLoaded();
      if (loadId !== state.routeLoadId) return;
      if (page && typeof page.mount === 'function') {
        const instance = page.mount();
        state.activeRouteModule = instance || page;
        return;
      }
    } catch (error) {
      console.warn('[dreamingwrt-web] line status page load failed', error);
    }
    if (loadId === state.routeLoadId && routePreview) renderRoutePlaceholder({ label: '线路状态' }, '/app/#/monitor/line-status');
  }

  async function renderClientDetailsPage() {
    const loadId = state.routeLoadId;
    renderRouteModuleLoading({ label: '终端详情' }, '/app/#/monitor/client-details');
    try {
      const page = await ensureClientDetailsPageLoaded();
      if (loadId !== state.routeLoadId) return;
      if (page && typeof page.mount === 'function') {
        const instance = page.mount();
        state.activeRouteModule = instance || page;
        return;
      }
    } catch (error) {
      console.warn('[dreamingwrt-web] client details page load failed', error);
    }
    if (loadId === state.routeLoadId && routePreview) renderRoutePlaceholder({ label: '终端详情' }, '/app/#/monitor/client-details');
  }

  async function renderInsightsFlowsPage(mode = 'flows', section = '') {
    const loadId = state.routeLoadId;
    const activityLabels = {
      'url-audit': 'URL 审计',
      'online-records': '终端在线',
      'im-records': 'IM 在线',
      'protocol-app': '协议与应用',
      'audit-status': '审计状态'
    };
    const label = mode === 'activity' ? (activityLabels[section] || '活动') : '流量';
    const path = mode === 'activity'
      ? `/app/#/insights/activity${section && section !== 'overview' ? `/${section}` : ''}`
      : '/app/#/insights/flows';
    renderRouteModuleLoading({ label }, path);
    try {
      const page = await ensureInsightsFlowsPageLoaded();
      if (loadId !== state.routeLoadId) return;
      if (page && typeof page.mount === 'function') {
        const instance = page.mount({ mode, section: section || 'overview' });
        state.activeRouteModule = instance || page;
        return;
      }
    } catch (error) {
      console.warn('[dreamingwrt-web] insights page load failed', error);
    }
    if (loadId === state.routeLoadId && routePreview) renderRoutePlaceholder({ label }, path);
  }

  function routeContentSignature(parts = {}) {
    if (parts.dashboardRoute) return 'dashboard';
    if (parts.topologyRoute) return 'topology';
    if (parts.lineStatusRoute) return 'monitor:line-status';
    if (parts.clientDetailsRoute) return 'monitor:client-details';
    if (parts.insightsDetailRoute) return `insights:${parts.insightsActivityRoute ? `activity:${parts.insightsActivitySection || 'overview'}` : 'flows'}`;
    if (parts.insightsHomeRoute) return 'insights:home';
    if (parts.monitorDataConfig) return `monitor-data:${parts.monitorDataConfig.id}`;
    return `route:${parts.currentKey || ''}:${parts.currentPath || ''}`;
  }

  function renderInsightsHomePage() {
    if (!routePreview) return;
    routePreview.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host');
    routePreview.classList.add('route-workspace', 'route-insights-home');
    routePreview.hidden = false;
    routePreview.innerHTML = `
      <section class="insights-entry-grid" aria-label="洞察入口">
        <button type="button" class="insights-entry-card dwrt-glass-card insights-stable-glass" data-insights-entry="/app/#/insights/flows">
          <span class="insights-entry-icon" aria-hidden="true">${iconSvg('insights')}</span>
          <strong>流量</strong>
          <small>查看真实流量记录、摘要、目的地、客户端、应用与筛选条件</small>
        </button>
        <button type="button" class="insights-entry-card dwrt-glass-card insights-stable-glass" data-insights-entry="/app/#/insights/activity">
          <span class="insights-entry-icon" aria-hidden="true">${iconSvg('log_center')}</span>
          <strong>活动</strong>
          <small>查看安全事件、网络活动与后续审计记录</small>
        </button>
      </section>`;
    routePreview.querySelectorAll('[data-insights-entry]').forEach((button) => {
      button.addEventListener('click', () => routeTo(button.dataset.insightsEntry));
    });
    window.DWRT_UI_KIT?.mountAll(routePreview);
    scheduleGlassCardsRender(360);
  }

  function genericListFrom(value) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of ['clients', 'events', 'items', 'rows', 'list', 'records', 'data']) {
      if (Array.isArray(value[key])) return value[key];
    }
    return [];
  }

  function formatTimestamp(value) {
    const raw = Number(value);
    if (!Number.isFinite(raw) || raw <= 0) return '--';
    const ms = raw > 100000000000 ? raw : raw * 1000;
    const date = new Date(ms);
    if (!Number.isFinite(date.getTime())) return '--';
    return new Intl.DateTimeFormat('zh-CN', {
      hour12: false,
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    }).format(date);
  }

  function formatPercent(used, total) {
    const usedValue = Number(used);
    const totalValue = Number(total);
    if (!Number.isFinite(usedValue) || !Number.isFinite(totalValue) || totalValue <= 0) return '--';
    const percent = usedValue / totalValue * 100;
    return `${percent.toFixed(percent >= 10 ? 0 : 1)}%`;
  }

  function formatBytesPair(used, total) {
    if (used === undefined || used === null || total === undefined || total === null) return '--';
    return `${formatBytes(used)} / ${formatBytes(total)}`;
  }

  function normalizedRisk(value) {
    const text = String(value || '').trim().toLowerCase();
    if (['critical', 'danger', 'high', '严重', '高'].includes(text)) return { key: 'high', label: '高' };
    if (['medium', 'warn', 'warning', '中', '警告'].includes(text)) return { key: 'medium', label: '中' };
    if (['low', 'info', 'notice', '低', '普通'].includes(text)) return { key: 'low', label: '低' };
    return { key: 'unknown', label: text || '--' };
  }

  function clientRowsFrom(payload) {
    return genericListFrom(payload).map((client, index) => {
      const fingerprint = client && typeof client.fingerprint === 'object' ? client.fingerprint : {};
      const online = onlineState(client && client.online);
      const mac = firstText(client && client.mac, `client-${index + 1}`);
      return {
        name: firstText(client && client.display_name, client && client.hostname, client && client.name, client && client.ip, mac),
        meta: firstText(client && client.vendor_name, client && client.vendor, fingerprint.vendor, mac),
        ip: firstText(client && client.ip, client && client.ipv4, client && client.ipaddr),
        type: firstText(fingerprint.device_type, client && client.device_type, client && client.type, client && client.link_type),
        access: firstText(client && client.link_type, client && client.interface, client && client.network, client && client.ssid),
        online,
        downRate: firstNumber(client && client.down_rate, client && client.rx_rate, client && client.rate_down),
        upRate: firstNumber(client && client.up_rate, client && client.tx_rate, client && client.rate_up),
        connections: firstNumber(client && client.connections, client && client.conn_count),
        confidence: firstNumber(fingerprint.confidence, client && client.confidence)
      };
    });
  }

  function auditRowsFrom(payload) {
    return genericListFrom(payload).map((event) => {
      const risk = normalizedRisk(firstText(event && event.risk, event && event.level, event && event.severity));
      return {
        ts: firstNumber(event && event.ts, event && event.time, event && event.created_at),
        actor: firstText(event && event.actor, event && event.user, event && event.username, event && event.device_id),
        action: firstText(event && event.action, event && event.event, event && event.method, event && event.path),
        target: firstText(event && event.target, event && event.path, event && event.uri, event && event.resource),
        device: firstText(event && event.device_id, event && event.ip, event && event.remote_addr),
        risk
      };
    });
  }

  function averageNumbers(values) {
    const nums = asArray(values).map((value) => Number(value)).filter((value) => Number.isFinite(value) && value > 0);
    if (!nums.length) return 0;
    return nums.reduce((sum, value) => sum + value, 0) / nums.length;
  }

  function latestNumberFromPoints(points, ...keys) {
    const list = asArray(points);
    for (let index = list.length - 1; index >= 0; index -= 1) {
      const point = list[index] || {};
      for (const key of keys) {
        const num = Number(point[key]);
        if (Number.isFinite(num)) return num;
      }
    }
    return 0;
  }

  function averageLatencyFromPayloads(healthPayload, statusPayload, historyPayload) {
    const historyLatency = averageNumbers(healthHistoryPoints(historyPayload || {}).map((point) => point.latency));
    if (historyLatency) return historyLatency;
    const samples = [];
    const collect = (value) => {
      const num = Number(value);
      if (Number.isFinite(num) && num > 0) samples.push(num);
    };
    const scan = (source, depth = 0) => {
      if (!source || depth > 4) return;
      if (Array.isArray(source)) {
        source.forEach((item) => scan(item, depth + 1));
        return;
      }
      if (typeof source !== 'object') return;
      ['latency_avg', 'avg_latency', 'latency_ms', 'latency', 'rtt', 'avg_ms'].forEach((key) => collect(source[key]));
      ['wans', 'wan', 'line', 'lines', 'traffic', 'points', 'history', 'health_history'].forEach((key) => scan(source[key], depth + 1));
    };
    scan(historyPayload);
    scan(statusPayload && statusPayload.line);
    scan(statusPayload && statusPayload.wan_list);
    scan(healthPayload);
    return averageNumbers(samples);
  }

  function historyPayloadPoints(historyPayload) {
    return asArray(historyPayload && (historyPayload.points || historyPayload.traffic || historyPayload.items || historyPayload.history));
  }

  function normalizeHealthHistoryPoint(point) {
    return {
      ts: firstNumber(point && point.ts, point && point.time, point && point.timestamp),
      cpu: firstNumber(point && point.cpu_avg, point && point.cpu_percent, point && point.cpu),
      cpuMax: firstNumber(point && point.cpu_max),
      mem: firstNumber(point && point.mem_avg, point && point.mem_percent, point && point.memory_percent),
      memMax: firstNumber(point && point.mem_max),
      disk: firstNumber(point && point.disk_avg, point && point.disk_percent),
      diskMax: firstNumber(point && point.disk_max),
      connections: firstNumber(point && point.connections_avg, point && point.connections, point && point.conn_count),
      connectionsMax: firstNumber(point && point.connections_max, point && point.conn_max),
      forwardPps: firstNumber(point && point.forward_pps_avg, point && point.forward_pps),
      forwardPpsMax: firstNumber(point && point.forward_pps_max),
      clientNum: firstNumber(point && point.client_num_avg, point && point.client_num),
      clientNumMax: firstNumber(point && point.client_num_max)
    };
  }

  function normalizeTrafficHistoryPoint(point) {
    return {
      ts: firstNumber(point && point.ts, point && point.time, point && point.timestamp),
      up: firstNumber(point && point.up_avg, point && point.up_rate, point && point.up, point && point.tx_rate),
      down: firstNumber(point && point.down_avg, point && point.down_rate, point && point.down, point && point.rx_rate),
      upMax: firstNumber(point && point.up_max, point && point.up_peak),
      downMax: firstNumber(point && point.down_max, point && point.down_peak),
      latency: firstNumber(point && point.latency_avg, point && point.latency_ms, point && point.latency),
      latencyMin: firstNumber(point && point.latency_min),
      latencyMax: firstNumber(point && point.latency_max)
    };
  }

  function mergeHistoryByTimestamp(systemPayload, trafficPayload) {
    const byTs = new Map();
    historyPayloadPoints(systemPayload).map(normalizeHealthHistoryPoint).forEach((point) => {
      if (!point.ts) return;
      byTs.set(point.ts, { ...(byTs.get(point.ts) || {}), ...point });
    });
    historyPayloadPoints(trafficPayload).map(normalizeTrafficHistoryPoint).forEach((point) => {
      if (!point.ts) return;
      byTs.set(point.ts, { ...(byTs.get(point.ts) || {}), ...point });
    });
    return Array.from(byTs.values()).sort((a, b) => a.ts - b.ts);
  }

  function healthHistoryPoints(historyPayload) {
    if (historyPayload && (historyPayload.system || historyPayload.traffic)) {
      return mergeHistoryByTimestamp(historyPayload.system, historyPayload.traffic).filter((point) => point.ts > 0);
    }
    return historyPayloadPoints(historyPayload)
      .map((point) => ({ ...normalizeHealthHistoryPoint(point), ...normalizeTrafficHistoryPoint(point) }))
      .filter((point) => point.ts > 0);
  }

  function systemMetricRows(healthPayload, statusPayload, historyPayload) {
    const system = healthPayload && typeof healthPayload.system === 'object' ? healthPayload.system : {};
    const traffic = healthPayload && typeof healthPayload.traffic === 'object' ? healthPayload.traffic : {};
    const status = statusPayload && typeof statusPayload === 'object' ? statusPayload : {};
    const points = healthHistoryPoints(historyPayload || {});
    const avgLatency = averageLatencyFromPayloads(healthPayload, statusPayload, historyPayload);
    const rows = [
      ['整体状态', firstText(status.summary, status.status, healthPayload && healthPayload.summary), firstText(status.source, 'dashboard/status')],
      ['CPU', system.cpu_percent !== undefined ? `${formatInteger(system.cpu_percent)}%` : '--', firstText(status.status, 'system/health')],
      ['内存', formatBytesPair(system.mem_used, system.mem_total), formatPercent(system.mem_used, system.mem_total)],
      ['磁盘', formatBytesPair(system.disk_used, system.disk_total), formatPercent(system.disk_used, system.disk_total)],
      ['平均延迟', avgLatency ? formatLatency(avgLatency) : '--', points.length ? `近一小时 ${points.length} 个样本` : '线路探测平均'],
      ['连接数', formatInteger(firstNumber(system.connections, latestNumberFromPoints(points, 'connections'))), firstText(traffic.rate_source, 'dashboard/traffic/history')],
      ['终端数', formatInteger(system.client_num), '已识别在线终端'],
      ['上行速率', formatRate(firstNumber(traffic.up_rate, latestNumberFromPoints(points, 'up'))), '实时采样'],
      ['下行速率', formatRate(firstNumber(traffic.down_rate, latestNumberFromPoints(points, 'down'))), '实时采样'],
      ['转发 PPS', formatInteger(system.forward_pps), '内核转发统计'],
      ['运行时间', formatUptime(system.uptime), firstText(system.hostname, system.model)]
    ];
    return rows.map(([name, value, note]) => ({ name, value, note }));
  }

  function systemHealthSummary(healthPayload, statusPayload, historyPayload) {
    const system = healthPayload && typeof healthPayload.system === 'object' ? healthPayload.system : {};
    const traffic = healthPayload && typeof healthPayload.traffic === 'object' ? healthPayload.traffic : {};
    const points = healthHistoryPoints(historyPayload || {});
    const latestConnections = firstNumber(system.connections, latestNumberFromPoints(points, 'connections'));
    const latestLatency = firstNumber(averageLatencyFromPayloads(healthPayload, statusPayload, historyPayload));
    const forwardPps = firstNumber(system.forward_pps, latestNumberFromPoints(points, 'forwardPps'));
    const percent = (used, total) => {
      const a = Number(used);
      const b = Number(total);
      return Number.isFinite(a) && Number.isFinite(b) && b > 0 ? a / b * 100 : 0;
    };
    return {
      system,
      traffic,
      points,
      cpu: firstNumber(system.cpu_percent),
      memPercent: percent(system.mem_used, system.mem_total),
      diskPercent: percent(system.disk_used, system.disk_total),
      upRate: firstNumber(traffic.up_rate, latestNumberFromPoints(points, 'up')),
      downRate: firstNumber(traffic.down_rate, latestNumberFromPoints(points, 'down')),
      clientNum: firstNumber(system.client_num),
      connections: latestConnections,
      forwardPps,
      avgLatency: latestLatency,
      uptime: firstNumber(system.uptime)
    };
  }

  function formatLoadPercent(value) {
    const num = Number(value);
    if (!Number.isFinite(num)) return '--';
    const digits = num >= 10 ? 0 : 1;
    return `${num.toFixed(digits).replace(/\.0$/, '')}%`;
  }

  function systemHealthChartCard(id, title, legend, footer = '') {
    return `<section class="dwrt-kit-load-card system-health-glass-card" data-system-health-card="${escapeHtml(id)}">
      <div class="dwrt-kit-load-card-head">
        <h3>${escapeHtml(title)}</h3>
        <span class="dwrt-kit-load-card-actions">
          <button type="button" class="dwrt-kit-load-action drag-handle" draggable="true" data-system-health-action="drag" data-card-id="${escapeHtml(id)}" aria-label="拖动排序 ${escapeHtml(title)}" title="拖动排序">
            <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M14.208 7.91 12.214 6.338a.113.113 0 0 0-.183.089v1.01H8.562V3.97h1.013a.113.113 0 0 0 .088-.184L8.09 1.793a.113.113 0 0 0-.178 0L6.338 3.786a.113.113 0 0 0 .088.184h1.011v3.468H3.97V6.426a.113.113 0 0 0-.184-.088L1.793 7.91a.113.113 0 0 0 0 .178l1.993 1.574a.113.113 0 0 0 .184-.088V8.562h3.468v3.467H6.426a.113.113 0 0 0-.088.184l1.573 1.994a.113.113 0 0 0 .178 0l1.574-1.994a.113.113 0 0 0-.088-.184H8.562V8.562h3.468v1.012c0 .095.11.147.184.088l1.994-1.574a.113.113 0 0 0 0-.178Z"/></svg>
          </button>
          <span class="dwrt-kit-load-menu-wrap">
            <button type="button" class="dwrt-kit-load-action" data-system-health-action="menu" data-card-id="${escapeHtml(id)}" aria-label="打开 ${escapeHtml(title)} 操作菜单" title="更多操作" aria-haspopup="menu" aria-expanded="false">
              <svg viewBox="0 0 16 16" aria-hidden="true"><g transform="rotate(90 8 8)"><path d="M13.125 13.063H2.875a.125.125 0 0 1-.125-.126v-1.25c0-.069.056-.125.125-.125h10.25c.069 0 .125.056.125.126v1.25a.125.125 0 0 1-.125.124ZM13.125 4.438H2.875a.125.125 0 0 1-.125-.126v-1.25c0-.069.056-.125.125-.125h10.25c.069 0 .125.056.125.126v1.25a.125.125 0 0 1-.125.124ZM9.875 8.75h-3.75A.125.125 0 0 1 6 8.625v-1.25c0-.069.056-.125.125-.125h3.75c.069 0 .125.056.125.125v1.25a.125.125 0 0 1-.125.125Z"/></g></svg>
            </button>
            <div class="dwrt-kit-load-menu" role="menu" hidden>
              <button type="button" role="menuitem" data-system-health-menu="wide" data-card-id="${escapeHtml(id)}">切换宽度</button>
              <button type="button" role="menuitem" data-system-health-menu="reset" data-card-id="${escapeHtml(id)}">重置视图</button>
            </div>
          </span>
        </span>
      </div>
      <div class="dwrt-kit-load-chart" data-system-health-chart="${escapeHtml(id)}"></div>
      ${footer ? `<div class="dwrt-kit-load-note">${escapeHtml(footer)}</div>` : ''}
    </section>`;
  }

  function renderSystemHealthLoadShell(summary) {
    return `<section class="system-health-load-grid" aria-label="系统健康图表">
      ${systemHealthChartCard('performance', '性能负载(%)', [
        { label: `CPU ${formatLoadPercent(summary.cpu)}`, color: '#4da0ff' },
        { label: `内存 ${formatLoadPercent(summary.memPercent)}`, color: '#3f7cff' },
        { label: `硬盘 ${formatLoadPercent(summary.diskPercent)}`, color: '#46bf67' }
      ])}
      ${systemHealthChartCard('network', '网络负载', [
        { label: '上行速率', color: '#3631b5' },
        { label: '下行速率', color: '#178b25' }
      ])}
      ${systemHealthChartCard('clients', '在线终端(台)', [{ label: '在线终端', color: '#007d83' }])}
      ${systemHealthChartCard('packets', '转发 PPS', [{ label: '转发 PPS', color: '#7866ff' }])}
      ${systemHealthChartCard('connections', '网络连接数', [{ label: '网络连接数', color: '#ff78bd' }])}
      ${systemHealthChartCard('latency', '平均延迟(ms)', [{ label: '平均延迟', color: '#f59f00' }])}
    </section>`;
  }

  function systemHealthLegendLabels(summary) {
    return {
      performance: [`CPU ${formatLoadPercent(summary.cpu)}`, `内存 ${formatLoadPercent(summary.memPercent)}`, `硬盘 ${formatLoadPercent(summary.diskPercent)}`],
      network: [`上行 ${formatRate(summary.upRate)}`, `下行 ${formatRate(summary.downRate)}`],
      clients: [`在线终端 ${formatInteger(summary.clientNum)}`],
      packets: [`转发 PPS ${formatInteger(summary.forwardPps)}`],
      connections: [`网络连接数 ${formatInteger(summary.connections)}`],
      latency: [`平均延迟 ${formatLatency(summary.avgLatency)}`]
    };
  }

  function updateSystemHealthLoadShell(page, summary) {
    if (!page || !page.loadHost) return;
    if (!page.loadHost.dataset.ready) {
      page.loadHost.innerHTML = renderSystemHealthLoadShell(summary);
      page.loadHost.dataset.ready = '1';
    }
    const labels = systemHealthLegendLabels(summary);
    Object.entries(labels).forEach(([cardId, values]) => {
      const card = page.loadHost.querySelector(`[data-system-health-card="${cssEscape(cardId)}"]`);
      if (!card) return;
      values.forEach((value, index) => {
        const target = card.querySelector(`[data-system-health-legend="${index}"] b`);
        if (target && target.textContent !== value) target.textContent = value;
      });
    });
  }

  function systemHealthApplyControlLabels(page) {
    if (!page || !page.root) return;
    const metric = page.systemHealthMetric === 'peak' ? 'peak' : 'avg';
    const range = page.systemHealthRange || SYSTEM_HEALTH_DEFAULT_RANGE;
    const metricLabel = page.root.querySelector('[data-system-health-metric-label]');
    const rangeLabel = page.root.querySelector('[data-system-health-range-label]');
    if (metricLabel) metricLabel.textContent = metric === 'peak' ? '峰值' : '平均值';
    if (rangeLabel) rangeLabel.textContent = (SYSTEM_HEALTH_RANGE_OPTIONS[range] || SYSTEM_HEALTH_RANGE_OPTIONS[SYSTEM_HEALTH_DEFAULT_RANGE]).label;
    page.root.querySelectorAll('[data-system-health-metric]').forEach((item) => item.setAttribute('aria-checked', item.dataset.systemHealthMetric === metric ? 'true' : 'false'));
    page.root.querySelectorAll('[data-system-health-range]').forEach((item) => item.setAttribute('aria-checked', item.dataset.systemHealthRange === range ? 'true' : 'false'));
  }

  function closeSystemHealthToolbarMenus(page) {
    if (!page || !page.root) return;
    page.root.querySelectorAll('.system-health-tool-group.is-open').forEach((group) => {
      group.classList.remove('is-open');
      const menu = group.querySelector('.system-health-menu');
      const trigger = group.querySelector('[data-system-health-trigger]');
      if (menu) menu.hidden = true;
      if (trigger) trigger.setAttribute('aria-expanded', 'false');
    });
  }

  function systemHealthMetricValue(page, point, avgKey, peakKey) {
    if (page && page.systemHealthMetric === 'peak') {
      const peak = Number(point && point[peakKey]);
      if (Number.isFinite(peak)) return peak;
    }
    return Number(point && point[avgKey]) || 0;
  }

  function formatSystemHealthAxisTime(ts, rangeId) {
    const date = new Date(Number(ts) * 1000);
    if (!Number.isFinite(date.getTime())) return '';
    const pad = (value) => String(value).padStart(2, '0');
    const time = `${pad(date.getHours())}:${pad(date.getMinutes())}`;
    if (rangeId === '1m') return `${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
    if (rangeId === '1w') return `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${time}`;
    return time;
  }

  function systemHealthAxisLabels(points, rangeId) {
    const rows = asArray(points);
    if (!rows.length) return [];
    const labels = rows.map((point) => formatSystemHealthAxisTime(point && point.ts, rangeId));
    const targetByRange = { '1h': 20, '1d': 14, '1w': 12, '1m': 12 };
    const target = targetByRange[rangeId] || 14;
    const step = Math.max(1, Math.round(labels.length / target));
    const shown = new Set();
    return labels.map((label, index) => {
      if (!label) return '';
      const isLast = index === labels.length - 1;
      const shouldShow = isLast || index === 0 || index % step === 0;
      if (!shouldShow) return '';
      if (shown.has(label) && !isLast) return '';
      shown.add(label);
      return label;
    });
  }

  function collectSystemHealthLiveSample(page, summary) {
    if (!page) return [];
    const now = firstNumber(summary.system && summary.system.ts, Date.now() / 1000);
    page.systemHealthSamples = page.systemHealthSamples || [];
    const sample = {
      ts: now,
      cpu: Number(summary.cpu) || 0,
      mem: Number(summary.memPercent) || 0,
      disk: Number(summary.diskPercent) || 0,
      clients: Number(summary.clientNum) || 0,
      packets: Number(summary.forwardPps) || 0,
      forwardPps: Number(summary.forwardPps) || 0,
      forwardPpsMax: Number(summary.forwardPps) || 0
    };
    const last = page.systemHealthSamples[page.systemHealthSamples.length - 1];
    if (!last || Math.abs(last.ts - sample.ts) >= 1) page.systemHealthSamples.push(sample);
    else page.systemHealthSamples[page.systemHealthSamples.length - 1] = sample;
    const cutoff = now - 3600;
    while (page.systemHealthSamples.length > 61 || (page.systemHealthSamples[0] && page.systemHealthSamples[0].ts < cutoff)) page.systemHealthSamples.shift();
    if (page.systemHealthSamples.length === 1) {
      const only = page.systemHealthSamples[0];
      const rangeId = page.systemHealthRange || SYSTEM_HEALTH_DEFAULT_RANGE;
      const spanByRange = { '1h': 3600, '1d': 86400, '1w': 604800, '1m': 2592000 };
      return [{ ...only, ts: only.ts - (spanByRange[rangeId] || 3600) }, only];
    }
    return page.systemHealthSamples;
  }

  function systemHealthTooltipValue(id, value) {
    const num = Number(Array.isArray(value) ? value[value.length - 1] : value);
    if (!Number.isFinite(num)) return '--';
    if (id === 'performance') return `${Math.round(num)}%`;
    if (id === 'network') return formatRate(num / 8);
    if (id === 'latency') return `${Math.round(num)} ms`;
    if (id === 'packets') return `${formatInteger(Math.round(num))} pps`;
    return formatInteger(Math.round(num));
  }

  function systemHealthTooltipFormatter(id) {
    return (params) => {
      const list = Array.isArray(params) ? params : [params];
      const title = firstText(list[0] && (list[0].axisValueLabel || list[0].name), '');
      const lines = title ? [`<strong>${escapeHtml(title)}</strong>`] : [];
      list.forEach((item) => {
        if (!item) return;
        const marker = item.marker || '';
        lines.push(`${marker}${escapeHtml(item.seriesName || '')}: ${escapeHtml(systemHealthTooltipValue(id, item.value))}`);
      });
      return lines.join('<br/>');
    };
  }

  function systemHealthChartOption(id, summary, page) {
    const points = asArray(summary.points);
    const rangeId = page && page.systemHealthRange || SYSTEM_HEALTH_DEFAULT_RANGE;
    const times = systemHealthAxisLabels(points, rangeId);
    const dark = document.documentElement.dataset.themeResolved === 'dark';
    const axisColor = dark ? 'rgba(216,226,240,0.72)' : 'rgba(92,105,124,0.76)';
    const splitColor = dark ? 'rgba(226,236,255,0.13)' : 'rgba(120,134,154,0.15)';
    const tooltipBg = dark ? 'rgba(12, 18, 30, 0.88)' : 'rgba(255, 255, 255, 0.86)';
    const tooltipBorder = dark ? 'rgba(255,255,255,0.14)' : 'rgba(255,255,255,0.58)';
    const gridById = { performance: { left: 52, right: 34 }, network: { left: 72, right: 28 }, clients: { left: 42, right: 28 }, packets: { left: 82, right: 28 }, connections: { left: 62, right: 28 }, latency: { left: 46, right: 28 } };
    const chartGrid = gridById[id] || { left: 58, right: 28 };
    const grid = { ...chartGrid, top: 16, bottom: 78 };
    const base = {
      animation: false,
      color: ['#4da0ff', '#3f7cff', '#46bf67'],
      grid,
      tooltip: {
        trigger: 'axis',
        confine: true,
        appendToBody: true,
        formatter: systemHealthTooltipFormatter(id),
        backgroundColor: tooltipBg,
        borderColor: tooltipBorder,
        borderWidth: 1,
        textStyle: { color: dark ? 'rgba(248,251,255,0.94)' : 'rgba(24,31,42,0.92)', fontSize: 12 },
        extraCssText: 'border-radius:10px;box-shadow:0 14px 34px rgba(0,0,0,.18);backdrop-filter:blur(12px) saturate(135%);-webkit-backdrop-filter:blur(12px) saturate(135%);'
      },
      legend: {
        show: true,
        bottom: 0,
        left: 'center',
        icon: 'circle',
        itemWidth: 8,
        itemHeight: 8,
        itemGap: 18,
        selectedMode: true,
        textStyle: { color: axisColor, fontSize: 12, fontWeight: 500 }
      },
      xAxis: {
        type: 'category',
        boundaryGap: false,
        data: times,
        axisTick: { show: false },
        axisLine: { lineStyle: { color: dark ? 'rgba(226,236,255,0.16)' : 'rgba(128,143,163,0.24)' } },
        axisLabel: {
          color: axisColor,
          rotate: 45,
          margin: 16,
          fontSize: 12,
          fontWeight: 520,
          hideOverlap: false,
          align: 'right',
          verticalAlign: 'middle',
          interval: 0
        }
      },
      yAxis: {
        type: 'value',
        min: 0,
        splitLine: { lineStyle: { color: splitColor, type: 'dashed' } },
        axisLabel: { color: axisColor, fontSize: 12 }
      },
      series: []
    };
    const line = (name, data, color, area = false) => ({
      name, type: 'line', smooth: true, symbol: data.length <= 2 ? 'circle' : 'none', symbolSize: 4, showSymbol: data.length <= 2,
      lineStyle: { width: 1.45, color }, itemStyle: { color },
      areaStyle: area ? { color, opacity: 0.12 } : undefined, data
    });
    if (!points.length) return { ...base, legend: { ...base.legend, show: false }, graphic: [{ type: 'text', left: 'center', top: 'middle', style: { text: '等待历史样本', fill: axisColor, fontSize: 12 } }] };
    if (id === 'performance') {
      return {
        ...base,
        color: ['#4aa3ad', '#477dff', '#81d6ad'],
        yAxis: { ...base.yAxis, max: 100, axisLabel: { ...base.yAxis.axisLabel, formatter: (value) => `${Math.round(Number(value) || 0)}` } },
        series: [
          line('CPU', points.map((p) => systemHealthMetricValue(page, p, 'cpu', 'cpuMax')), '#4aa3ad'),
          line('内存', points.map((p) => systemHealthMetricValue(page, p, 'mem', 'memMax')), '#477dff'),
          line('硬盘', points.map((p) => systemHealthMetricValue(page, p, 'disk', 'diskMax')), '#81d6ad')
        ]
      };
    }
    if (id === 'clients') return { ...base, color: ['#007d83'], series: [line('在线终端', points.map((p) => systemHealthMetricValue(page, p, 'clientNum', 'clientNumMax')), '#007d83', true)] };
    if (id === 'packets') {
      const hasPacketHistory = points.some((point) => Number(point && (point.forwardPpsMax || point.forwardPps)) > 0);
      const packetPoints = hasPacketHistory ? points : asArray(summary.livePoints);
      const packetBase = packetPoints === points ? base : { ...base, xAxis: { ...base.xAxis, data: systemHealthAxisLabels(packetPoints, rangeId) } };
      return { ...packetBase, color: ['#7866ff'], yAxis: { ...packetBase.yAxis, axisLabel: { ...packetBase.yAxis.axisLabel, formatter: (value) => `${formatInteger(Math.round(Number(value) || 0))}` } }, series: [line('转发 PPS', packetPoints.map((p) => systemHealthMetricValue(page, p, 'forwardPps', 'forwardPpsMax')), '#7866ff', true)] };
    }
    if (id === 'network') return { ...base, color: ['#3631b5', '#178b25'], yAxis: { ...base.yAxis, axisLabel: { ...base.yAxis.axisLabel, formatter: (value) => formatRate(Number(value) / 8) } }, series: [line('上行速率', points.map((p) => systemHealthMetricValue(page, p, 'up', 'upMax') * 8), '#3631b5'), line('下行速率', points.map((p) => systemHealthMetricValue(page, p, 'down', 'downMax') * 8), '#178b25')] };
    if (id === 'connections') return { ...base, color: ['#ff78bd'], series: [line('网络连接数', points.map((p) => systemHealthMetricValue(page, p, 'connections', 'connectionsMax')), '#ff78bd', true)] };
    if (id === 'latency') return { ...base, color: ['#f59f00'], yAxis: { ...base.yAxis, axisLabel: { ...base.yAxis.axisLabel, formatter: (value) => `${Math.round(Number(value) || 0)}` } }, series: [line('平均延迟', points.map((p) => page && page.systemHealthMetric === 'peak' ? Math.max(Number(p.latencyMax) || 0, Number(p.latency) || 0) : Number(p.latency) || 0), '#f59f00', true)] };
    return base;
  }

  function renderSystemHealthCharts(page, summary) {
    if (!page || !page.root) return;
    const nodes = Array.from(page.root.querySelectorAll('[data-system-health-chart]'));
    if (!nodes.length) return;
    loadECharts().then((echarts) => {
      if (state.routePages.monitorData !== page) return;
      page.charts = page.charts || new Map();
      const active = new Set(nodes.map((node) => node.dataset.systemHealthChart));
      page.charts.forEach((entry, key) => {
        if (!active.has(key)) {
          try { entry.chart.dispose(); } catch (_) {}
          page.charts.delete(key);
        }
      });
      nodes.forEach((node) => {
        const id = node.dataset.systemHealthChart;
        let entry = page.charts.get(id);
        if (!entry) {
          entry = { chart: echarts.init(node, null, { renderer: 'canvas' }) };
          page.charts.set(id, entry);
        }
        const option = systemHealthChartOption(id, summary, page);
        const optionSignature = `${page.systemHealthRange || SYSTEM_HEALTH_DEFAULT_RANGE}:${page.systemHealthMetric || 'avg'}:${id}:${option && option.xAxis && option.xAxis.data ? option.xAxis.data.length : 0}`;
        const replaceOption = entry.optionSignature !== optionSignature;
        entry.optionSignature = optionSignature;
        entry.chart.setOption(option, { notMerge: replaceOption, lazyUpdate: true });
        entry.chart.resize();
      });
    }).catch((error) => console.warn('[dreamingwrt-web] system health chart failed', error));
  }

  function monitorDataPageConfig(routeId) {
    const key = String(routeId || '');
    return Object.values(MONITOR_DATA_PAGES).find((item) => item.id === key || item.hash === key || `#${item.hash}` === key || key.includes(item.hash)) || null;
  }

  function systemHealthToolbarShell() {
    const rangeItems = Object.entries(SYSTEM_HEALTH_RANGE_OPTIONS).map(([key, item]) => `<button type="button" role="menuitemradio" data-system-health-range="${escapeHtml(key)}" aria-checked="${key === SYSTEM_HEALTH_DEFAULT_RANGE ? 'true' : 'false'}">${escapeHtml(item.label)}</button>`).join('');
    return `<div class="system-health-toolbar" id="systemHealthToolbar" aria-label="系统健康图表工具栏">
      <div class="system-health-tool-group is-metric" data-system-health-dropdown="metric">
        <button type="button" class="system-health-tool-button" data-system-health-trigger="metric" aria-haspopup="menu" aria-expanded="false">
          <svg class="system-health-metric-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><g fill="currentColor"><path d="M0 0h16v16H0z" opacity="0"></path><path d="M13.248 9.25H2.375a.125.125 0 0 0-.125.125v.938c0 .068.056.124.125.124h9.456l-2.254 2.86a.126.126 0 0 0 .098.203h1.133a.25.25 0 0 0 .197-.095l2.637-3.346a.5.5 0 0 0-.394-.809m.377-3.687H4.169l2.254-2.86a.126.126 0 0 0-.098-.203H5.192a.25.25 0 0 0-.197.095L2.358 5.941a.5.5 0 0 0 .392.809h10.875a.125.125 0 0 0 .125-.125v-.937a.125.125 0 0 0-.125-.125"></path></g></svg>
          <span data-system-health-metric-label>平均值</span>
        </button>
        <div class="system-health-menu" role="menu" hidden>
          <button type="button" role="menuitemradio" data-system-health-metric="avg" aria-checked="true">平均值</button>
          <button type="button" role="menuitemradio" data-system-health-metric="peak" aria-checked="false">峰值</button>
        </div>
      </div>
      <div class="system-health-tool-group is-range" data-system-health-dropdown="range">
        <button type="button" class="system-health-tool-button" data-system-health-trigger="range" aria-haspopup="menu" aria-expanded="false">
          <span data-system-health-range-label>${escapeHtml(SYSTEM_HEALTH_RANGE_OPTIONS[SYSTEM_HEALTH_DEFAULT_RANGE].label)}</span>
          <svg viewBox="0 0 18 18" aria-hidden="true" class="chevron"><path d="M5.2 7.2 9 11l3.8-3.8" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </button>
        <div class="system-health-menu" role="menu" hidden>${rangeItems}</div>
      </div>
      <button type="button" class="system-health-reset" data-system-health-reset>恢复默认</button>
    </div>`;
  }

  function monitorPageHead(config) {
    if (config && config.id === 'system-health') return systemHealthToolbarShell();
    return `
      <header class="route-page-head">
        <div>
          <span>${escapeHtml(config.title)}</span>
          <h2>${escapeHtml(config.label)}</h2>
        </div>
      </header>`;
  }

  function monitorTableShell(config) {
    const system = config && config.id === 'system-health';
    if (system) {
      return `
        <section class="monitor-data-panel system-health-panel">
          <div class="system-health-load-host" id="systemHealthLoadHost"></div>
        </section>`;
    }
    return `
      <section class="monitor-data-panel">
        <div class="dwrt-kit-table-wrap">
          <div class="dwrt-kit-table-toolbar">
            <div class="dwrt-kit-table-title" id="monitorDataTitle"><strong>${escapeHtml(config.title)}</strong><span>${escapeHtml(config.subtitle)}</span></div>
            <span class="dwrt-kit-table-count" id="monitorDataCount">--</span>
          </div>
          <div class="dwrt-kit-table-scroll">
            <table class="dwrt-kit-table" id="monitorDataTable" aria-label="${escapeHtml(config.label)}"><tbody><tr><td>正在读取真实后端数据。</td></tr></tbody></table>
          </div>
        </div>
      </section>`;
  }

  function renderMonitorClientTable(page, payload, errorText) {
    const rows = clientRowsFrom(payload);
    page.count.textContent = `${rows.length} 台`;
    page.title.innerHTML = `<strong>终端详情</strong><span>${escapeHtml(errorText || page.config.subtitle)}</span>`;
    const body = rows.length ? rows.map((row) => {
      const stateClass = row.online === true ? 'is-online' : row.online === false ? 'is-offline' : 'is-unknown';
      const stateText = row.online === true ? '在线' : row.online === false ? '离线' : '未知';
      return `<tr>
      <td><span class="line-name"><strong>${escapeHtml(row.name)}</strong><small>${escapeHtml(row.meta || '--')}</small></span></td>
      <td>${escapeHtml(row.ip || '--')}</td>
      <td>${escapeHtml(firstText(row.type, row.access, '--'))}</td>
      <td><span class="line-state ${stateClass}">${escapeHtml(stateText)}</span></td>
      <td class="num">${escapeHtml(formatRate(row.downRate))}</td>
      <td class="num">${escapeHtml(formatRate(row.upRate))}</td>
      <td class="num">${escapeHtml(formatInteger(row.connections))}</td>
    </tr>`;
    }).join('') : `<tr><td colspan="7">${escapeHtml(errorText || page.config.empty)}</td></tr>`;
    page.table.innerHTML = `<thead><tr><th>终端</th><th>IP</th><th>类型</th><th>状态</th><th class="num">下行</th><th class="num">上行</th><th class="num">连接</th></tr></thead><tbody>${body}</tbody>`;
  }

  function renderMonitorAuditTable(page, payload, errorText) {
    const rows = auditRowsFrom(payload);
    page.count.textContent = `${rows.length} 条`;
    page.title.innerHTML = `<strong>审计视图</strong><span>${escapeHtml(errorText || page.config.subtitle)}</span>`;
    const body = rows.length ? rows.map((row) => `<tr>
      <td>${escapeHtml(formatTimestamp(row.ts))}</td>
      <td><span class="line-state risk-${escapeHtml(row.risk.key)}">${escapeHtml(row.risk.label)}</span></td>
      <td>${escapeHtml(row.actor || '--')}</td>
      <td>${escapeHtml(row.action || '--')}</td>
      <td>${escapeHtml(row.target || '--')}</td>
      <td>${escapeHtml(row.device || '--')}</td>
    </tr>`).join('') : `<tr><td colspan="6">${escapeHtml(errorText || page.config.empty)}</td></tr>`;
    page.table.innerHTML = `<thead><tr><th>时间</th><th>风险</th><th>Actor</th><th>动作</th><th>目标</th><th>设备</th></tr></thead><tbody>${body}</tbody>`;
  }

  function renderMonitorSystemTable(page, healthPayload, statusPayload, historyPayload, errorText) {
    const summary = systemHealthSummary(healthPayload || {}, statusPayload || {}, historyPayload || {});
    if (page.count) page.count.textContent = '';
    if (page.title) page.title.innerHTML = `<strong>系统健康</strong><span>${escapeHtml(errorText || page.config.subtitle)}</span>`;
    if (page.loadHost) {
      summary.livePoints = collectSystemHealthLiveSample(page, summary);
      updateSystemHealthLoadShell(page, summary);
      renderSystemHealthCharts(page, summary);
    }
  }

  async function refreshMonitorDataPage() {
    const page = state.routePages && state.routePages.monitorData;
    if (!page || page.loading) return;
    page.loading = true;
    let resources = [];
    if (page.kind === 'client-details') {
      resources = [await fetchApiResource('clients', '/api/v1/clients')];
    } else if (page.kind === 'audit-view') {
      resources = [await fetchApiResource('audit', '/api/v1/audit/events')];
    } else if (page.kind === 'system-health') {
      resources = await Promise.all([
        fetchApiResource('health', '/api/v1/system/health'),
        fetchApiResource('status', '/api/v1/dashboard/status'),
        fetchApiResource('systemHistory', `${SYSTEM_HEALTH_HISTORY_ENDPOINT}?range=${encodeURIComponent(page.systemHealthRange || SYSTEM_HEALTH_DEFAULT_RANGE)}`),
        fetchApiResource('trafficHistory', `${SYSTEM_TRAFFIC_HISTORY_ENDPOINT}?range=${encodeURIComponent(page.systemHealthRange || SYSTEM_HEALTH_DEFAULT_RANGE)}`)
      ]);
    }
    page.loading = false;
    if (state.routePages.monitorData !== page) return;
    const get = (name) => resources.find((item) => item.name === name && item.ok)?.data || {};
    const errors = resources.filter((item) => !item.ok).map((item) => item.error && item.error.message).filter(Boolean);
    const errorText = errors[0] || '';
    if (page.kind === 'client-details') renderMonitorClientTable(page, get('clients'), errorText);
    else if (page.kind === 'audit-view') renderMonitorAuditTable(page, get('audit'), errorText);
    else renderMonitorSystemTable(page, get('health'), get('status'), { system: get('systemHistory'), traffic: get('trafficHistory') }, errorText);
    window.DWRT_UI_KIT?.mountAll(routePreview);
    scheduleGlassCardsRender(120);
  }

  function resizeSystemHealthCharts(page) {
    if (!page || !page.charts) return;
    window.requestAnimationFrame(() => {
      page.charts.forEach((entry) => {
        try { entry && entry.chart && entry.chart.resize(); } catch (_) {}
      });
    });
  }

  function closeSystemHealthMenus(page) {
    if (!page || !page.loadHost) return;
    page.loadHost.querySelectorAll('.dwrt-kit-load-menu-wrap.is-open').forEach((wrap) => {
      wrap.classList.remove('is-open');
      const menu = wrap.querySelector('.dwrt-kit-load-menu');
      const trigger = wrap.querySelector('[data-system-health-action="menu"]');
      if (menu) menu.hidden = true;
      if (trigger) trigger.setAttribute('aria-expanded', 'false');
    });
  }

  function applySystemHealthCardMenu(page, cardId, action) {
    const card = page && page.loadHost && page.loadHost.querySelector(`[data-system-health-card="${cssEscape(cardId)}"]`);
    if (!card) return;
    if (action === 'wide') {
      card.classList.toggle('is-wide');
      const wide = card.classList.contains('is-wide');
      const trigger = card.querySelector('[data-system-health-action="menu"]');
      if (trigger) trigger.classList.toggle('is-active', wide);
      resizeSystemHealthCharts(page);
      return;
    }
    if (action === 'reset') {
      const entry = page.charts && page.charts.get(cardId);
      try {
        if (entry && entry.chart) {
          entry.chart.dispatchAction({ type: 'dataZoom', start: 0, end: 100 });
          entry.chart.resize();
        }
      } catch (_) {}
      card.animate([
        { transform: 'scale(1)' },
        { transform: 'scale(0.992)' },
        { transform: 'scale(1)' }
      ], { duration: 180, easing: 'cubic-bezier(.2,.8,.2,1)' });
    }
  }

  function bindSystemHealthActions(page) {
    if (!page || !page.loadHost || page.actionsBound) return;
    page.actionsBound = true;
    page.root.addEventListener('click', (event) => {
      const trigger = event.target.closest('[data-system-health-trigger]');
      if (trigger && page.root.contains(trigger)) {
        const group = trigger.closest('.system-health-tool-group');
        const wasOpen = group && group.classList.contains('is-open');
        closeSystemHealthToolbarMenus(page);
        if (group && !wasOpen) {
          group.classList.add('is-open');
          const menu = group.querySelector('.system-health-menu');
          if (menu) menu.hidden = false;
          trigger.setAttribute('aria-expanded', 'true');
        }
        event.preventDefault();
        return;
      }
      const metricItem = event.target.closest('[data-system-health-metric]');
      if (metricItem && page.root.contains(metricItem)) {
        page.systemHealthMetric = metricItem.dataset.systemHealthMetric === 'peak' ? 'peak' : 'avg';
        systemHealthApplyControlLabels(page);
        closeSystemHealthToolbarMenus(page);
        refreshMonitorDataPage();
        event.preventDefault();
        return;
      }
      const rangeItem = event.target.closest('[data-system-health-range]');
      if (rangeItem && page.root.contains(rangeItem)) {
        const nextRange = rangeItem.dataset.systemHealthRange || SYSTEM_HEALTH_DEFAULT_RANGE;
        page.systemHealthRange = SYSTEM_HEALTH_RANGE_OPTIONS[nextRange] ? nextRange : SYSTEM_HEALTH_DEFAULT_RANGE;
        page.systemHealthSamples = [];
        systemHealthApplyControlLabels(page);
        closeSystemHealthToolbarMenus(page);
        refreshMonitorDataPage();
        event.preventDefault();
        return;
      }
      const reset = event.target.closest('[data-system-health-reset]');
      if (reset && page.root.contains(reset)) {
        page.systemHealthMetric = 'avg';
        page.systemHealthRange = SYSTEM_HEALTH_DEFAULT_RANGE;
        page.systemHealthSamples = [];
        page.loadHost.querySelectorAll('.dwrt-kit-load-card.is-wide').forEach((card) => card.classList.remove('is-wide'));
        systemHealthApplyControlLabels(page);
        closeSystemHealthToolbarMenus(page);
        refreshMonitorDataPage();
        resizeSystemHealthCharts(page);
        event.preventDefault();
        return;
      }
      if (!event.target.closest('.system-health-toolbar')) closeSystemHealthToolbarMenus(page);
    });
    page.loadHost.addEventListener('click', (event) => {
      const menuItem = event.target.closest('[data-system-health-menu]');
      if (menuItem && page.loadHost.contains(menuItem)) {
        applySystemHealthCardMenu(page, menuItem.dataset.cardId || '', menuItem.dataset.systemHealthMenu || '');
        closeSystemHealthMenus(page);
        event.preventDefault();
        return;
      }
      const menuButton = event.target.closest('[data-system-health-action="menu"]');
      if (menuButton && page.loadHost.contains(menuButton)) {
        const wrap = menuButton.closest('.dwrt-kit-load-menu-wrap');
        const wasOpen = wrap && wrap.classList.contains('is-open');
        closeSystemHealthMenus(page);
        if (wrap && !wasOpen) {
          wrap.classList.add('is-open');
          const menu = wrap.querySelector('.dwrt-kit-load-menu');
          if (menu) menu.hidden = false;
          menuButton.setAttribute('aria-expanded', 'true');
        }
        event.preventDefault();
      }
    });
    page.loadHost.addEventListener('dragstart', (event) => {
      const handle = event.target.closest('[data-system-health-action="drag"]');
      if (!handle || !page.loadHost.contains(handle)) return;
      const card = handle.closest('[data-system-health-card]');
      if (!card) return;
      page.draggingCard = card;
      card.classList.add('is-dragging');
      try {
        event.dataTransfer.effectAllowed = 'move';
        event.dataTransfer.setData('text/plain', card.dataset.systemHealthCard || '');
      } catch (_) {}
      closeSystemHealthMenus(page);
    });
    page.loadHost.addEventListener('dragover', (event) => {
      const dragging = page.draggingCard;
      if (!dragging) return;
      const target = event.target.closest('[data-system-health-card]');
      if (!target || target === dragging || !page.loadHost.contains(target)) return;
      event.preventDefault();
      const rect = target.getBoundingClientRect();
      const before = event.clientY < rect.top + rect.height / 2 || (Math.abs(event.clientY - (rect.top + rect.height / 2)) < rect.height * 0.25 && event.clientX < rect.left + rect.width / 2);
      target.parentNode.insertBefore(dragging, before ? target : target.nextSibling);
      resizeSystemHealthCharts(page);
    });
    page.loadHost.addEventListener('drop', (event) => {
      if (!page.draggingCard) return;
      event.preventDefault();
      page.draggingCard.classList.remove('is-dragging');
      page.draggingCard = null;
      resizeSystemHealthCharts(page);
    });
    page.loadHost.addEventListener('dragend', () => {
      if (page.draggingCard) page.draggingCard.classList.remove('is-dragging');
      page.draggingCard = null;
      resizeSystemHealthCharts(page);
    });
    document.addEventListener('click', (event) => {
      if (!page.loadHost || page.loadHost.contains(event.target)) return;
      closeSystemHealthMenus(page);
    });
  }

  function renderMonitorDataPage(kind) {
    if (!routePreview) return;
    const config = monitorDataPageConfig(kind);
    if (!config) return;
    routePreview.hidden = false;
    routePreview.classList.add('route-workspace', 'route-data-page');
    routePreview.classList.remove('route-line-status', 'route-client-details-host');
    routePreview.innerHTML = `${monitorPageHead(config)}${monitorTableShell(config)}`;
    const page = {
      kind: config.id,
      config,
      loading: false,
      title: $('monitorDataTitle'),
      count: $('monitorDataCount'),
      table: $('monitorDataTable'),
      root: routePreview,
      loadHost: $('systemHealthLoadHost'),
      charts: new Map(),
      systemHealthMetric: 'avg',
      systemHealthRange: SYSTEM_HEALTH_DEFAULT_RANGE,
      timer: window.setInterval(refreshMonitorDataPage, MONITOR_DATA_REFRESH_MS)
    };
    state.routePages.monitorData = page;
    bindSystemHealthActions(page);
    systemHealthApplyControlLabels(page);
    window.DWRT_UI_KIT?.mountAll(routePreview);
    refreshMonitorDataPage();
    scheduleGlassCardsRender(360);
  }

  function renderRoutePlaceholder(current, currentPath) {
    if (!routePreview) return;
    routePreview.classList.remove('route-workspace', 'route-line-status', 'route-data-page', 'route-client-details-host');
    routePreview.hidden = false;
    routePreview.innerHTML = `<span>当前路径</span><code id="routePath">${escapeHtml(currentPath)}</code>`;
  }

  function renderUnavailableRoute(current, currentPath) {
    if (!routePreview) return;
    const label = current?.label || '当前功能';
    const reason = current?.unavailable_reason || `当前固件未提供 ${label} 所需的后端能力。`;
    const capability = current?.capability || '未声明';
    routePreview.className = 'route-preview route-workspace dwrt-kit-page-shell';
    routePreview.dataset.dwrtComponent = 'page-shell';
    routePreview.dataset.dwrtPageShell = 'focused-task';
    routePreview.dataset.dwrtSurface = 'stable-glass';
    routePreview.hidden = false;
    routePreview.innerHTML = `<section data-dwrt-component="state-panel" data-dwrt-state="unavailable" class="dwrt-kit-state-panel">
      <strong>${escapeHtml(label)}不可用</strong>
      <p>${escapeHtml(reason)}</p>
      <small>所需能力：${escapeHtml(capability)} · 路由：${escapeHtml(routeHashFromPath(currentPath))}</small>
    </section>`;
    window.DWRT_UI_KIT?.mount(routePreview);
  }

  function renderRouteModuleLoading(current, currentPath) {
    if (!routePreview) return;
    routePreview.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host');
    routePreview.classList.add('route-workspace');
    routePreview.hidden = false;
    routePreview.innerHTML = `<span>${escapeHtml(current && current.label || '页面')}</span><code id="routePath">${escapeHtml(currentPath)}</code>`;
  }

  function routeModuleForItem(item) {
    for (const key of routeModuleKeys(item)) {
      const entry = state.routeModules.get(key);
      if (entry) return entry;
    }
    return null;
  }

  async function mountRouteModule(moduleRecord, context) {
    const exported = moduleRecord && (moduleRecord.default || moduleRecord);
    let result = null;
    if (typeof exported === 'function') {
      result = await exported(context);
    } else if (exported && typeof exported.mount === 'function') {
      result = await exported.mount(context);
    } else {
      throw new Error('route module does not export a mount function');
    }
    if (result instanceof Node) {
      context.root.replaceChildren(result);
      return null;
    }
    if (result && typeof result.unmount === 'function') return result;
    if (exported && typeof exported.unmount === 'function') return exported;
    return null;
  }

  async function activateRouteModule(current, currentPath) {
    const entry = routeModuleForItem(current);
    if (!entry || !routePreview) {
      renderRoutePlaceholder(current, currentPath);
      return;
    }
    const loadId = ++state.routeLoadId;
    state.routeAbortController?.abort('route-replaced');
    const routeController = new AbortController();
    state.routeAbortController = routeController;
    renderRouteModuleLoading(current, currentPath);
    try {
      // 样式与模块并行拉取,消除“先等 CSS 再拉 JS”的串行瀑布。
      const [, moduleRecord] = await Promise.all([
        loadRouteItemStyle(entry.item || current),
        import(/* webpackIgnore: true */ entry.url)
      ]);
      if (loadId !== state.routeLoadId) return;
      const instance = await mountRouteModule(moduleRecord, {
        root: routePreview,
        item: current,
        path: currentPath,
        route: routeHashFromPath(currentPath),
        signal: routeController.signal,
        registry: window.DWRT_DATA_REGISTRY,
        capabilities: Object.freeze({ ...state.capabilities }),
        api: {
          fetch: (name, url, retry = true) => fetchApiResource(name, url, retry, routeController.signal),
          request: async (name, url, init = {}) => {
            const hasBody = init.body !== undefined;
            const response = await withApiSlot(() => window.DWRT_SESSION
              ? window.DWRT_SESSION.fetch(url, {
                ...init,
                credentials: 'same-origin',
                cache: 'no-store',
                signal: routeController.signal,
                headers: authHeaders({ Accept: 'application/json', ...(hasBody ? { 'Content-Type': 'application/json' } : {}), ...(init.headers || {}) }),
                body: hasBody && typeof init.body !== 'string' ? JSON.stringify(init.body) : init.body
              })
              : fetch(url, {
                ...init,
                credentials: 'same-origin',
                cache: 'no-store',
                signal: routeController.signal,
                headers: authHeaders({ Accept: 'application/json', ...(hasBody ? { 'Content-Type': 'application/json' } : {}), ...(init.headers || {}) }),
                body: hasBody && typeof init.body !== 'string' ? JSON.stringify(init.body) : init.body
              }), routeController.signal);
            const text = await response.text();
            let json = {};
            if (text) {
              try { json = JSON.parse(text); } catch (_) { throw new Error(`${name}: invalid json`); }
            }
            if (!response.ok || json?.ok === false) {
              const error = new Error(`${name}: ${json?.message || json?.error?.message || json?.error?.code || response.status}`);
              error.status = response.status;
              error.payload = json;
              throw error;
            }
            return unwrapApiData(json);
          },
          authHeaders,
          routeTo
        },
        realtime: window.DWRTRealtime,
        ui: {
          mountAll: (root = routePreview) => window.DWRT_UI_KIT?.mountAll(root),
          scheduleGlassCardsRender,
          scheduleAdaptiveForegroundSample: (delay = 0, root = routePreview) => scheduleAdaptiveForegroundSample(delay, root),
          overviewCardsMarkup: (...args) => window.DWRT_UI_KIT?.overviewCardsMarkup?.(...args),
          floatingSavebarMarkup: (...args) => window.DWRT_UI_KIT?.floatingSavebarMarkup?.(...args),
          statusBadgeMarkup: (...args) => window.DWRT_UI_KIT?.statusBadgeMarkup?.(...args),
          confirmationMarkup: (...args) => window.DWRT_UI_KIT?.confirmationMarkup?.(...args)
        },
        utils: {
          escapeHtml,
          formatBytes,
          formatInteger,
          formatLatency,
          formatRate
        }
      });
      if (loadId !== state.routeLoadId) {
        routeController.abort('stale-route-mount');
        if (instance && typeof instance.unmount === 'function') instance.unmount();
        return;
      }
      state.activeRouteModule = instance || null;
      window.DWRT_UI_KIT?.mountAll(routePreview);
      scheduleGlassCardsRender(360);
    } catch (error) {
      console.warn('[dreamingwrt-web] route module load failed', entry.url, error);
      if (loadId === state.routeLoadId) renderRoutePlaceholder(current, currentPath);
    }
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

  function firstNumber(...values) {
    for (const value of values) {
      const num = Number(value);
      if (Number.isFinite(num)) return num;
    }
    return 0;
  }

  function positiveNumber(...values) {
    for (const value of values) {
      const num = Number(value);
      if (Number.isFinite(num) && num > 0) return num;
    }
    return 0;
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

  function authTokens() {
    if (window.DWRT_SESSION) return window.DWRT_SESSION.tokens();
    try {
      return {
        access: localStorage.getItem(SESSION_KEYS.access) || '',
        refresh: localStorage.getItem(SESSION_KEYS.refresh) || '',
        expiresAt: Number(localStorage.getItem(SESSION_KEYS.expiresAt) || 0)
      };
    } catch (_) {
      return { access: '', refresh: '', expiresAt: 0 };
    }
  }

  function saveAuthTokens(data) {
    if (window.DWRT_SESSION) return window.DWRT_SESSION.save(data);
    if (!data || !data.access_token) return;
    try {
      localStorage.setItem(SESSION_KEYS.access, data.access_token);
      if (data.refresh_token) localStorage.setItem(SESSION_KEYS.refresh, data.refresh_token);
      if (data.expires_in) localStorage.setItem(SESSION_KEYS.expiresAt, String(Date.now() + Number(data.expires_in) * 1000));
      if (data.username) localStorage.setItem(SESSION_KEYS.username, data.username);
      if (data.role) localStorage.setItem(SESSION_KEYS.role, data.role);
    } catch (_) {}
  }

  function clearAuthTokens() {
    if (window.DWRT_SESSION) return window.DWRT_SESSION.clear();
    try {
      Object.values(SESSION_KEYS).forEach((key) => localStorage.removeItem(key));
    } catch (_) {}
  }

  function authHeaders(extra) {
    if (window.DWRT_SESSION) return window.DWRT_SESSION.authHeaders(extra);
    const headers = { ...(extra || {}) };
    const { access } = authTokens();
    if (access) headers.Authorization = `Bearer ${access}`;
    return headers;
  }

  function redirectToLogin() {
    if (window.DWRT_SESSION) return window.DWRT_SESSION.requireLogin('access-rejected');
    clearAuthTokens();
    if (location.pathname.startsWith('/login')) return;
    const next = `${location.pathname}${location.search}${location.hash}`;
    location.href = `/login/?next=${encodeURIComponent(next)}`;
  }

  function initSessionRecovery() {
    const recovery = $('sessionRecovery');
    const login = $('sessionRecoveryLogin');
    if (!recovery || !login || recovery.dataset.bound === 'true') return;
    recovery.dataset.bound = 'true';
    const dialog = recovery.querySelector('.session-recovery-dialog');
    let glassRenderer = null;
    const mountGlass = () => {
      if (glassRenderer || !dialog || !appWallpaper) return;
      const factory = window.DWRTSampledLiquidGlass;
      if (!factory || typeof factory.create !== 'function') return;
      glassRenderer = factory.create({
        root: dialog,
        backgroundElement: appWallpaper,
        backgroundSrc: appWallpaper.currentSrc || appWallpaper.getAttribute('src') || '',
        options: {
          mode: 'shader',
          cornerRadius: 20,
          displacementScale: 80,
          baseBlur: 3.2,
          blurAmount: 0,
          saturation: 140,
          aberrationIntensity: 2,
          neutralDensity: 0.06,
          neutralColor: '10 16 25',
          preserveCenter: true,
          borderWidth: 1,
          opacity: 1,
          highlight: 0.28,
          borderColor: '#25FFFFFF',
          mapResolution: 0.25,
          trackMotion: false,
          trackScroll: false
        }
      });
    };
    const unmountGlass = () => {
      glassRenderer?.destroy?.();
      glassRenderer = null;
    };
    const show = (detail = {}) => {
      login.dataset.loginUrl = detail.loginUrl || window.DWRT_SESSION?.loginUrl?.() || '/login/';
      if (!recovery.hidden && recovery.classList.contains('is-open')) return;
      window.DWRT_UI_KIT?.unmount(recovery);
      recovery.hidden = false;
      recovery.classList.add('is-open');
      window.DWRT_UI_KIT?.mount(recovery);
      mountGlass();
    };
    const hide = () => {
      unmountGlass();
      recovery.classList.remove('is-open');
      recovery.hidden = true;
      login.disabled = false;
      login.removeAttribute('aria-busy');
      window.DWRT_UI_KIT?.unmount(recovery);
    };
    login.addEventListener('click', () => {
      if (login.disabled) return;
      const loginUrl = login.dataset.loginUrl || window.DWRT_SESSION?.loginUrl?.() || '/login/';
      login.disabled = true;
      login.setAttribute('aria-busy', 'true');
      window.DWRT_SESSION?.clear?.();
      location.href = loginUrl;
    });
    window.addEventListener('dwrt-session-required', (event) => show(event.detail || {}));
    window.addEventListener('dwrt-session-restored', hide);
    if (window.DWRT_SESSION?.required) show({ loginUrl: window.DWRT_SESSION.loginUrl() });
  }

  async function refreshAuthToken() {
    if (window.DWRT_SESSION) return window.DWRT_SESSION.refresh({ force: true, retryRequired: true });
    const { refresh } = authTokens();
    if (!refresh) {
      redirectToLogin();
      return false;
    }
    const refreshPromise = fetch('/api/v1/session/refresh', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refresh })
    }).then(async (response) => {
      const text = await response.text();
      let json = null;
      try { json = text ? JSON.parse(text) : null; } catch (_) {}
      const data = json && (json.data || json.body);
      if (response.ok && data && data.access_token) {
        saveAuthTokens(data);
        return true;
      }
      clearAuthTokens();
      return false;
    }).catch(() => false);
    return refreshPromise;
  }

  function unwrapApiData(payload) {
    if (!payload || typeof payload !== 'object') return {};
    if (payload.data && typeof payload.data === 'object') return payload.data;
    if (payload.body && typeof payload.body === 'object') return payload.body;
    return payload;
  }

  // 全局 API 并发闸门:后端 webd 串行处理请求,页面挂载时 6-8 个并发请求会
  // 相互排队并触发超线性的拥塞惩罚(实测串行 20-130ms/个,8 并发时 2-5.7s/个)。
  // 客户端限流后请求逐个快速返回,页面渐进渲染,整体反而更快。
  const API_LIMITER_MAX = 2;
  let apiLimiterActive = 0;
  const apiLimiterWaiters = [];
  async function withApiSlot(run, signal) {
    if (apiLimiterActive >= API_LIMITER_MAX) {
      await new Promise((resolve) => {
        const waiter = () => resolve();
        apiLimiterWaiters.push(waiter);
        if (signal) signal.addEventListener('abort', () => {
          const index = apiLimiterWaiters.indexOf(waiter);
          if (index >= 0) apiLimiterWaiters.splice(index, 1);
          resolve();
        }, { once: true });
      });
    }
    apiLimiterActive += 1;
    try {
      return await run();
    } finally {
      apiLimiterActive -= 1;
      const next = apiLimiterWaiters.shift();
      if (next) next();
    }
  }
  window.DWRT_API_LIMITER = { run: withApiSlot };

  async function fetchDashboardResource(name, url, retry = true, signal = undefined) {
    try {
      const requestUrl = `${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`;
      if (signal && signal.aborted) throw Object.assign(new Error(`${name}: aborted`), { name: 'AbortError' });
      const response = await withApiSlot(() => window.DWRT_SESSION
        ? window.DWRT_SESSION.fetch(requestUrl, {
          credentials: 'same-origin',
          cache: 'no-store',
          signal
        }, retry)
        : fetch(requestUrl, {
        credentials: 'same-origin',
        cache: 'no-store',
        headers: authHeaders(),
        signal
        }), signal);
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
        if (!window.DWRT_SESSION && response.status === 401 && retry && await refreshAuthToken()) {
          return fetchDashboardResource(name, url, false, signal);
        }
        if (response.status === 401) {
          redirectToLogin();
        }
        throw error;
      }
      return { name, ok: true, data: unwrapApiData(json), raw: json };
    } catch (error) {
      return { name, ok: false, error };
    }
  }

  async function fetchApiResource(name, url, retry = true, signal = undefined) {
    return fetchDashboardResource(name, url, retry, signal);
  }

  function configureDataRegistry() {
    const registry = window.DWRT_DATA_REGISTRY;
    if (!registry || registry.__dwrtConfigured) return registry || null;
    registry.__dwrtConfigured = true;
    registry.fetcher = async (url, request = {}, retry = true) => {
      const response = await withApiSlot(() => window.DWRT_SESSION
        ? window.DWRT_SESSION.fetch(url, {
          ...request,
          credentials: 'same-origin',
          cache: request.cache || 'no-store'
        }, retry)
        : fetch(url, {
        ...request,
        credentials: 'same-origin',
        cache: request.cache || 'no-store',
        headers: authHeaders(request.headers)
        }), request.signal);
      if (!window.DWRT_SESSION && response.status === 401 && retry && await refreshAuthToken()) {
        return registry.fetcher(url, request, false);
      }
      if (response.status === 401) redirectToLogin();
      return response;
    };
    [
      ['system.runtime', '/api/v1/system/status', 'webd.system', 3000, { uptime: 's', connections: 'count' }],
      ['system.health', '/api/v1/system/health', 'jmxd.system-health', 3000, { cpu: 'percent', memory: 'bytes', temperature: 'celsius' }],
      ['network.lans', '/api/v1/network/lans', 'jmxd.network', 5000, { prefix: 'cidr', mtu: 'bytes' }],
      ['network.wans', '/api/v1/network/wans', 'jmxd.network', 3000, { rx_bps: 'bytes/s', tx_bps: 'bytes/s', latency: 'ms' }],
      ['network.physicalPorts', '/api/v1/topology/node/ports', 'jmxd.topology', 3000, { speed: 'bits/s', rx_bps: 'bytes/s', tx_bps: 'bytes/s' }],
      ['network.ipam', '/api/v1/bulk-ip', 'jmxd.ipam', 5000, { total: 'count', used: 'count', reserved: 'count', conflicts: 'count', last_seen: 's' }],
      ['clients.inventory', '/api/v1/clients', 'jmxd.clients', 3000, { rx_bps: 'bytes/s', tx_bps: 'bytes/s', connections: 'count' }],
      ['policy.runtime', '/api/v1/route_status', 'jmxd.policy', 2000, { active_flows: 'count' }],
      ['dashboard.aggregate', '/api/v1/dashboard/snapshot', 'webd.dashboard', 2000, { rx_bps: 'bytes/s', tx_bps: 'bytes/s', connections: 'count' }],
      ['services.dns', '/api/v1/services/dns', 'jmxd.services-dns', 5000, { port: 'tcp/udp-port' }],
      ['logs.entries', '/api/v1/logs/search', 'jmxd.log-center', 3000, { timestamp: 'ms', count: 'count' }],
      ['logs.filters', '/api/v1/logs/filter-data', 'jmxd.log-center', 30000, { count: 'count' }],
      ['logs.settings', '/api/v1/logs/settings', 'jmxd.log-center', 30000, { retention_days: 'days', max_size_mb: 'MiB' }],
      ['policy.objects', '/api/v1/policy-engine/objects', 'webd.policy-engine', 5000, { total: 'count' }],
      ['policy.regions', '/api/v1/policy-engine/zones', 'webd.policy-engine', 5000, { total: 'count' }],
      ['policy.zoneMatrix', '/api/v1/policy-engine/zone-matrix', 'webd.policy-engine', 5000, { policy_count: 'count' }],
      ['policy.table', '/api/v1/policy-engine/policy-table?include_default=1', 'webd.policy-engine', 3000, { total: 'count' }],
      ['flow.engineStatus', '/api/v1/flowd/status', 'webd.flowd', 5000, { qos_classes: 'count', apply_jobs: 'count' }],
      ['flow.engineRuntime', '/api/v1/flowd/runtime', 'webd.flowd', 5000, { uptime: 's', connections: 'count' }],
      ['flow.nftRevision', '/api/v1/flowd/nft-revision', 'webd.flowd', 5000, { observed_at: 's' }],
      ['flow.engineSettings', '/api/v1/flowd/settings', 'webd.flowd', 10000, {}],
      ['flow.qosSettings', '/api/v1/flowd/qos/settings', 'webd.flowd', 10000, { headroom_pct: 'percent' }],
      ['flow.qosClasses', '/api/v1/flowd/qos/classes', 'webd.flowd', 10000, { guarantee_pct: 'percent', ceiling_pct: 'percent', latency_ms: 'ms' }],
      ['flow.applyJobs', '/api/v1/flowd/apply-jobs', 'webd.flowd', 5000, { total: 'count' }],
      ['flow.wanCapacity', '/api/v1/flowd/wan-capacity', 'webd.flowd', 10000, { total: 'count' }],
      ['flow.wanHealth', '/api/v1/flowd/wan-health', 'webd.flowd', 3000, { latency_ms: 'ms', loss_pct: 'percent', down_rate: 'bytes/s', up_rate: 'bytes/s' }],
      ['flow.smartControl', '/api/v1/flow-control', 'webd.flow-control', 5000, { total_download_mbps: 'Mbit/s', total_upload_mbps: 'Mbit/s', latency_target_ms: 'ms' }]
    ].forEach(([key, url, owner, ttlMs, units]) => registry.define(key, { url, owner, ttlMs, units }));
    registry.define('appearance.settings', {
      url: '/api/v1/system/basic',
      owner: 'webd.appearance-settings',
      ttlMs: 10000,
      units: { neutral_density: 'ratio', base_blur: 'px', saturation: 'percent' },
      project: (payload) => {
        const data = unwrapApiData(payload) || {};
        return { dreamingwrt: data.dreamingwrt || {}, capabilities: data.capabilities || {} };
      }
    });
    registry.define('appearance.media', {
      url: '/api/v1/bootstrap?appearance=1',
      owner: 'webd.public-appearance',
      ttlMs: 30000,
      units: {},
      project: (payload) => {
        const data = unwrapApiData(payload) || {};
        return { appearance: data.appearance || {} };
      }
    });
    return registry;
  }

  function releaseVersionLabel(value) {
    const text = firstText(value).replace(/^(?:Dreaming OS|DreamingWrt)\s*/i, '').trim();
    if (!text) return '7.2-RC3';
    return text.replace(/-?rc\s*(\d+)/ig, '-RC$1');
  }

  function releaseBuildLabel(value) {
    const text = firstText(value).trim();
    if (!text) return 'Build202607180016';
    return /^build/i.test(text) ? `Build${text.slice(5)}` : `Build${text}`;
  }

  /* Footer geometry. The version strip used to claim a fixed 58px band across the
     full content width, which cut through page-level side rails and stole rows
     from routes that scroll on their own. Both numbers are measured instead:
     how far the footer must stay clear of a page rail, and whether the route
     actually leaves the strip empty. */
  const footerLayout = { frame: 0, observer: null, watched: null };
  const FOOTER_RAIL_DEPTH = 5;
  const FOOTER_RAIL_BUDGET = 240;

  /* How far the footer must stay clear of a page-level rail. Detection is
     geometric rather than a list of class names, so a rail on any route is
     honoured: it has to hug the left edge of the content column, run tall and
     narrow, and reach down to where the footer starts. Once it does, drawing the
     footer rule across it reads as the rail being chopped off, so the footer
     steps aside and centres in what is left. A rail that ends well above the
     footer is not in the way and returns 0. The dashboard status rail is a shell
     grid column of its own and never enters this search. */
  function footerRailInset() {
    const host = consoleStage;
    if (!consolePageFooter || !consoleMain || !host) return 0;
    const column = consoleMain.getBoundingClientRect();
    const band = consolePageFooter.getBoundingClientRect();
    if (band.height <= 0) return 0;
    const minHeight = Math.max(180, host.clientHeight * 0.5);
    let inset = 0;
    let budget = FOOTER_RAIL_BUDGET;
    let level = [...host.children];
    for (let depth = 0; depth < FOOTER_RAIL_DEPTH && level.length && budget > 0; depth += 1) {
      const next = [];
      for (const node of level) {
        if (budget-- <= 0) break;
        if (!(node instanceof Element) || node.hidden) continue;
        const style = getComputedStyle(node);
        if (style.display === 'none' || style.visibility === 'hidden') continue;
        const rect = node.getBoundingClientRect();
        const hugsLeft = rect.left - column.left <= 24;
        const isColumn = rect.width >= 120 && rect.width <= column.width * 0.45;
        const isTall = rect.height >= minHeight;
        const meetsBand = rect.bottom >= band.top - 4;
        if (hugsLeft && isColumn && isTall && meetsBand) {
          inset = Math.max(inset, Math.round(rect.right - column.left));
          continue;
        }
        // Wrappers are transparent to this search; only their children can be rails.
        if (rect.height >= minHeight && node.children.length) next.push(...node.children);
      }
      level = next;
    }
    return inset;
  }

  function syncPageFooterLayout() {
    if (!consolePageFooter || !consoleMain) return;
    footerLayout.frame = 0;
    const inset = footerRailInset();
    consolePageFooter.style.setProperty('--console-footer-inset', `${inset}px`);
    consolePageFooter.dataset.railAvoid = inset > 0 ? 'true' : 'false';
    // The reserved strip is only justified when the route leaves it empty. Once
    // content spills, the strip is content the footer displaced, so it is given
    // back and the footer trails the content instead.
    //
    // Dropping the strip makes the stage taller, which can clear the very
    // overflow that triggered it, so the decision never reverses on its own:
    // each route render and each resize restarts from "reserved" via
    // resetPageFooterReserve(), and from there the strip can only be released.
    const root = document.documentElement;
    if (root.dataset.footerReserve === 'off') return;
    const overflow = Math.max(
      consoleStage ? consoleStage.scrollHeight - consoleStage.clientHeight : 0,
      consoleMain.scrollHeight - consoleMain.clientHeight
    );
    if (overflow > 4) root.dataset.footerReserve = 'off';
  }

  function resetPageFooterReserve() {
    if (!consolePageFooter) return;
    document.documentElement.dataset.footerReserve = 'on';
    schedulePageFooterLayout();
  }

  function schedulePageFooterLayout() {
    if (!consolePageFooter || footerLayout.frame) return;
    footerLayout.frame = requestAnimationFrame(syncPageFooterLayout);
  }

  function watchPageFooterLayout() {
    if (!consolePageFooter || typeof ResizeObserver === 'undefined') return;
    if (!footerLayout.observer) {
      footerLayout.observer = new ResizeObserver(() => schedulePageFooterLayout());
    }
    const targets = [consoleMain, consoleStage, routePreview].filter(Boolean);
    footerLayout.observer.disconnect();
    targets.forEach((target) => footerLayout.observer.observe(target));
    footerLayout.watched = targets;
    schedulePageFooterLayout();
  }

  function initPageFooterLayout() {
    if (!consolePageFooter) return;
    watchPageFooterLayout();
    // Route swaps replace the preview subtree wholesale, and a rail can appear or
    // disappear without changing any observed box, so mutations are watched too.
    if (typeof MutationObserver !== 'undefined' && routePreview) {
      new MutationObserver(() => schedulePageFooterLayout())
        .observe(routePreview, { childList: true, subtree: true, attributes: true, attributeFilter: ['class', 'hidden', 'style'] });
    }
    if (typeof MutationObserver !== 'undefined' && consoleStage) {
      new MutationObserver(() => schedulePageFooterLayout())
        .observe(consoleStage, { attributes: true, attributeFilter: ['class'] });
    }
    consoleMain?.addEventListener('scroll', schedulePageFooterLayout, { passive: true });
  }

  function updatePageFooterRelease(payload = {}) {
    if (!consolePageFooterVersion) return;
    const source = payload && typeof payload === 'object' ? payload : {};
    const system = source.system && typeof source.system === 'object' ? source.system : source;
    const version = releaseVersionLabel(firstText(
      system.dreamingwrt_version,
      system.release_version,
      source.dreamingwrt_version,
      source.release_version
    ));
    const build = releaseBuildLabel(firstText(
      system.build_date,
      system.build_id,
      source.build_date,
      source.build_id
    ));
    consolePageFooterVersion.textContent = `Dreaming OS ${version} ${build}`;
    consolePageFooter.dataset.releaseLoaded = 'true';
    scheduleAdaptiveForegroundSample(60, consolePageFooter);
  }

  async function loadPageFooterRelease() {
    const result = await fetchApiResource('system.release', '/api/v1/system/status');
    if (result.ok) updatePageFooterRelease(result.data);
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

  function formatBitRate(bytesPerSecond) {
    return formatRate(bytesPerSecond);
  }

  function shouldDeferRender(scope) {
    const selection = window.getSelection && window.getSelection();
    if (!selection || selection.isCollapsed || !String(selection).trim()) return false;
    const rootNode = scope || document.body;
    if (!rootNode || typeof rootNode.contains !== 'function') return true;
    return rootNode.contains(selection.anchorNode) || rootNode.contains(selection.focusNode);
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

  function carrierKey(value) {
    const text = String(value || '').toLowerCase();
    if (/unicom|联通|cucc|china\s*unicom/.test(text)) return 'unicom';
    if (/mobile|移动|cmcc|china\s*mobile/.test(text)) return 'mobile';
    if (/telecom|电信|ctcc|china\s*telecom/.test(text)) return 'telecom';
    if (/cernet|教育网|edu/.test(text)) return 'cernet';
    return 'unknown';
  }

  function carrierEvidence(wan) {
    if (!wan || typeof wan !== 'object') return '';
    const runtime = wan.runtime && typeof wan.runtime === 'object' ? wan.runtime : {};
    return [
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
      wan.gateway,
      runtime.carrier,
      runtime.carrier_key,
      runtime.carrier_name,
      runtime.isp_key,
      runtime.isp,
      runtime.operator_key,
      runtime.operator,
      runtime.operator_code,
      runtime.provider,
      runtime.gateway,
      runtime.ipv4
    ].map((value) => firstText(value)).filter(Boolean).join(' ');
  }

  function carrierMeta(wan) {
    const key = carrierKey(carrierEvidence(wan));
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

  function loadTopologyPreferences() {
    try {
      state.topology.rotateMap = localStorage.getItem(TOPOLOGY_PREF_KEYS.rotateMap) === '1';
    } catch (_) {}
  }

  function saveTopologyPreference(key, value) {
    try {
      localStorage.setItem(key, value ? '1' : '0');
    } catch (_) {}
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

  function applyTopologyTransform() {
    const t = state.topology.transform;
    const target = state.topology.view === 'infrastructure'
      ? topologyInfrastructureEmpty?.querySelector('.topology-infra-zoom-container')
      : topologyZoomContainer;
    if (!target) return;
    target.style.transform = `translate(${t.x}px, ${t.y}px) scale(${t.k})`;
  }

  function ensureSelectedTopologyNodeVisible() {
    if (!topologyCanvas || !topologyZoomContainer || !state.topology.detailOpen || !state.topology.selectedNodeMac) return;
    const selected = topologyNodeLayer?.querySelector(`.topology-node[data-node-mac="${cssEscape(state.topology.selectedNodeMac)}"]`);
    if (!selected) return;
    const canvasRect = topologyCanvas.getBoundingClientRect();
    const nodeRect = selected.getBoundingClientRect();
    const margin = 18;
    let dx = 0;
    let dy = 0;
    if (nodeRect.right > canvasRect.right - margin) dx = (canvasRect.right - margin) - nodeRect.right;
    if (nodeRect.left < canvasRect.left + margin) dx = (canvasRect.left + margin) - nodeRect.left;
    if (nodeRect.bottom > canvasRect.bottom - margin) dy = (canvasRect.bottom - margin) - nodeRect.bottom;
    if (nodeRect.top < canvasRect.top + margin) dy = (canvasRect.top + margin) - nodeRect.top;
    if (Math.abs(dx) < 1 && Math.abs(dy) < 1) return;
    state.topology.transform = {
      ...state.topology.transform,
      x: state.topology.transform.x + dx,
      y: state.topology.transform.y + dy
    };
    applyTopologyTransform();
  }

  function scheduleSelectedTopologyNodeVisible() {
    if (!state.topology.detailOpen || !state.topology.selectedNodeMac) return;
    window.requestAnimationFrame(() => {
      ensureSelectedTopologyNodeVisible();
      window.requestAnimationFrame(ensureSelectedTopologyNodeVisible);
    });
    if (topologyVisibilityTimer) window.clearTimeout(topologyVisibilityTimer);
    topologyVisibilityTimer = window.setTimeout(() => {
      topologyVisibilityTimer = 0;
      ensureSelectedTopologyNodeVisible();
    }, 360);
  }

  function topologyNodeState(node) {
    const value = String(node && node.state || '').toLowerCase();
    if (/offline|down|disconnected|isolated/.test(value)) return 'offline';
    if (node && node.online === false) return 'offline';
    return 'online';
  }

  function topologyNodeEdge(model, node) {
    const mac = String(node && node.mac || '');
    if (!model || !mac) return null;
    return asArray(model.edges).find((edge) => edge.downlinkMac === mac || edge.downlink_mac === mac) || null;
  }

  function topologyConnectionKind(model, node) {
    const edge = topologyNodeEdge(model, node);
    const type = String(firstText(
      edge && (edge.type || edge.connection_type),
      node && (node.connection_type || node.connection || node.uplink_type || node.network_type)
    )).toUpperCase();
    if (type === 'WIRELESS' || /wifi|wireless/i.test(type)) return 'wireless';
    if (type === 'WIRED' || /wired|ethernet|lan/i.test(type)) return 'wired';
    return '';
  }

  function topologyNetworkName(model, node) {
    const edge = topologyNodeEdge(model, node);
    return firstText(
      node && (node.network_name || node.networkName || node.vlan_name || node.vlanName),
      edge && (edge.networkName || edge.network_name || edge.vlanName || edge.vlan_name),
      edge && (edge.networkId || edge.network_id),
      node && (node.networkId || node.network_id || node.vlan || node.vlan_id)
    );
  }

  function topologyPortText(...values) {
    const value = firstText(...values);
    if (!value || value === '0') return '';
    return value;
  }

  function topologyActiveModel() {
    return state.topology.view === 'infrastructure'
      ? (state.topology.infrastructureModel || state.topology.lastModel)
      : state.topology.lastModel;
  }

  function topologyFindNode(mac) {
    const model = topologyActiveModel();
    const nodeMac = String(mac || '');
    if (!model || !nodeMac) return null;
    return asArray(model.vertices).find((node) => String(node.mac || '') === nodeMac) || null;
  }

  function topologyTypeLabel(type) {
    const value = String(type || '').toUpperCase();
    if (value === 'ISP') return 'ISP';
    if (value === 'DEVICE') return '网关设备';
    if (value === 'CLIENT') return '客户端';
    if (value === 'USW_WAN') return 'WAN 设备';
    if (value === 'CABLE_INTERNET') return 'Cable Internet';
    if (value === 'THIRD_PARTY_CLIENT') return '第三方客户端';
    return value || '节点';
  }

  function topologyNodeTitle(node) {
    return firstText(
      node && node.name,
      node && node.display_name,
      node && node.hostname,
      node && node.carrier_name,
      node && node.carrier,
      node && node.mac,
      '拓扑节点'
    );
  }

  function topologyWanRows(node, edge) {
    return [
      ['IP 地址', firstText(node && (node.public_ip || node.wan_ip || node.ip), edge && edge.public_ip)],
      ['MAC 地址', firstText(node && (node.wan_mac || node.mac), edge && edge.wan_mac)],
      ['运营商', firstText(node && node.carrier_name, node && node.carrier, edge && edge.carrier)],
      ['协议', firstText(node && (node.protocol || node.wan_protocol), edge && edge.protocol)],
      ['网关', firstText(node && node.gateway, edge && edge.gateway)],
      ['DNS 服务器 1', firstText(node && node.dns1, node && node.dns && node.dns[0])],
      ['DNS 服务器 2', firstText(node && node.dns2, node && node.dns && node.dns[1])],
      ['下行活动', formatRate(firstNumber(node && node.traffic && node.traffic.rx, edge && edge.traffic && edge.traffic.rx))],
      ['上行活动', formatRate(firstNumber(node && node.traffic && node.traffic.tx, edge && edge.traffic && edge.traffic.tx))]
    ].filter((row) => firstText(row[1]) && row[1] !== '0 bps');
  }

  function topologyInfoRows(node, edge) {
    const traffic = node && node.traffic || {};
    const rows = [
      ['状态', topologyNodeState(node) === 'online' ? '在线' : '离线'],
      ['型号', node && node.model],
      ['IP 地址', node && node.ip],
      ['MAC 地址', node && node.mac],
      ['运行时间', firstText(node && node.uptime_text, node && node.uptime && formatUptime(node.uptime))],
      ['内存使用率', firstText(node && node.mem, node && node.memory, node && node.memory_percent)],
      ['连接方式', topologyConnectionKind(topologyActiveModel(), node) === 'wireless' ? '无线' : topologyConnectionKind(topologyActiveModel(), node) === 'wired' ? '有线' : ''],
      ['网络', topologyNetworkName(topologyActiveModel(), node)],
      ['SSID', firstText(node && node.ssid, edge && edge.essid)],
      ['信号', firstText(node && node.signal, edge && edge.signal)],
      ['信道', firstText(node && node.channel, edge && edge.channel, edge && edge.radioBand)],
      ['上联端口', topologyPortText(edge && edge.uplinkPortNumber, edge && edge.uplink_port)],
      ['下联端口', topologyPortText(edge && edge.downlinkPortNumber, edge && edge.downlink_port)],
      ['WAN', firstText(node && node.wan_id, edge && edge.wan_id)],
      ['运营商', firstText(node && node.carrier_name, node && node.carrier, edge && edge.carrier)],
      ['连接数', node && node.connections ? String(node.connections) : ''],
      ['应用', node && node.app_name],
      ['判定依据', firstText(node && node.route_reason, edge && edge.route_reason)],
      ['下行', traffic.rx ? formatRate(traffic.rx) : ''],
      ['上行', traffic.tx ? formatRate(traffic.tx) : '']
    ];
    return rows.filter((row) => firstText(row[1]));
  }

  function topologyDetailRowsHtml(rows, className = 'topology-property-list') {
    if (!rows.length) return '';
    return `<dl class="${className}">
      ${rows.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`).join('')}
    </dl>`;
  }

  function topologyDetailSectionHtml(title, body, options = {}) {
    if (!body) return '';
    const collapsed = options.collapsed === true;
    return `<section class="topology-property-card topology-property-section ${collapsed ? 'is-collapsed' : ''}" data-topology-detail-section>
      <button type="button" class="topology-property-section-toggle" data-topology-detail-section-toggle aria-expanded="${collapsed ? 'false' : 'true'}">
        <strong>${escapeHtml(title)}</strong>
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 8 5 5 5-5"/></svg>
      </button>
      <div class="topology-property-section-body">${body}</div>
    </section>`;
  }

  function topologyConnectedRows(node) {
    const model = topologyActiveModel() || {};
    const children = asArray(model.edges)
      .filter((edge) => firstText(edge.uplinkMac, edge.uplink_mac) === node.mac)
      .map((edge) => {
        const childMac = firstText(edge.downlinkMac, edge.downlink_mac);
        const child = topologyFindNode(childMac);
        if (!child) return null;
        return {
          name: topologyNodeTitle(child),
          network: topologyNetworkName(model, child) || 'Default',
          port: topologyPortText(edge.uplinkPortNumber, edge.uplink_port, edge.port)
        };
      })
      .filter(Boolean);
    if (!children.length) return '';
    return `<table class="topology-property-table">
        <thead><tr><th>名称</th><th>网络</th><th>端口</th></tr></thead>
        <tbody>${children.map((row) => `<tr>
          <td>${escapeHtml(row.name)}</td>
          <td>${escapeHtml(row.network)}</td>
          <td>${escapeHtml(row.port || '--')}</td>
        </tr>`).join('')}</tbody>
      </table>`;
  }

  function topologyPortLegendHtml(node) {
    const model = topologyActiveModel() || {};
    const ports = asArray(model.edges)
      .filter((edge) => firstText(edge.uplinkMac, edge.uplink_mac) === node.mac)
      .map((edge) => topologyPortText(edge.uplinkPortNumber, edge.uplink_port, edge.port))
      .filter(Boolean)
      .slice(0, 8);
    const portCells = Array.from({ length: 10 }, (_, index) => {
      const port = ports[index] || '';
      const active = Boolean(port);
      return `<span class="topology-port-cell ${active ? 'is-active' : 'is-empty'}">${escapeHtml(port)}</span>`;
    }).join('');
    return `<section class="topology-property-card topology-port-card">
      <div class="topology-port-device">
        <span class="topology-port-device-image" aria-hidden="true"><img src="/static/images/gateway-wide.png" alt=""></span>
        <strong>${escapeHtml(topologyNodeTitle(node))}</strong>
      </div>
      <div class="topology-port-grid" aria-label="端口状态">${portCells}</div>
      <div class="topology-port-legend" aria-label="端口速率图例">
        <span><i class="fe"></i>FE</span>
        <span><i class="gbe"></i>GbE</span>
        <span><i class="g25"></i>2.5 GbE</span>
        <span><i class="g10"></i>10 GbE</span>
        <span><i class="down"></i>已断开连接</span>
        <span><i class="disabled"></i>已禁用</span>
      </div>
      <div class="topology-property-actions">
        <button type="button" data-topology-detail-action="ports">端口管理器</button>
        <button type="button" data-topology-detail-action="capture">数据包捕获</button>
      </div>
    </section>`;
  }

  function topologyWarningHtml(node) {
    if (topologyNodeState(node) === 'online') return '';
    return `<section class="topology-property-card topology-property-warning">
      <span aria-hidden="true">!</span>
      <p>设备无法连接。请确认设备已通电，且连接未被防火墙规则或端口限制中断。</p>
    </section>`;
  }

  function topologyRateSummaryHtml(node) {
    const tx = firstNumber(node && node.traffic && node.traffic.tx);
    const rx = firstNumber(node && node.traffic && node.traffic.rx);
    if (!tx && !rx) return '';
    return `<div class="topology-property-rate" aria-label="实时速率">
      <span class="down">↓ ${escapeHtml(formatRate(rx))}</span>
      <span class="up">↑ ${escapeHtml(formatRate(tx))}</span>
    </div>`;
  }

  function topologyOverviewHtml(node, edge) {
    const type = String(node && node.type || '').toUpperCase();
    const infoRows = topologyInfoRows(node, edge);
    if (type === 'DEVICE' || type === 'USW_WAN' || type === 'CABLE_INTERNET') {
      return [
        topologyPortLegendHtml(node),
        topologyWarningHtml(node),
        topologyDetailSectionHtml('连接的设备', topologyConnectedRows(node), { collapsed: false }),
        topologyDetailSectionHtml('设备信息', topologyDetailRowsHtml(infoRows), { collapsed: false }),
        topologyDetailSectionHtml('WAN', topologyDetailRowsHtml(topologyWanRows(node, edge)), { collapsed: false })
      ].filter(Boolean).join('');
    }
    if (type === 'ISP') {
      return [
        topologyRateSummaryHtml(node),
        topologyDetailSectionHtml('ISP 信息', topologyDetailRowsHtml([
          ['名称', topologyNodeTitle(node)],
          ['运营商', firstText(node.carrier_name, node.carrier)],
          ['WAN', firstText(node.wan_id, edge && edge.wan_id)],
          ['IP 地址', firstText(node.public_ip, node.wan_ip, node.ip)],
          ['ASN', node.asn],
          ['负载模式', firstText(node.load_balancing_mode, node.lb_mode)],
          ['状态', topologyNodeState(node) === 'online' ? '在线' : '离线']
        ].filter((row) => firstText(row[1]))), { collapsed: false })
      ].filter(Boolean).join('');
    }
    return [
      topologyRateSummaryHtml(node),
      topologyDetailSectionHtml('设备信息', topologyDetailRowsHtml(infoRows), { collapsed: false })
    ].filter(Boolean).join('');
  }

  function topologyStatsHtml(node) {
    const rows = [
      ['实时下行', formatRate(firstNumber(node && node.traffic && node.traffic.rx))],
      ['实时上行', formatRate(firstNumber(node && node.traffic && node.traffic.tx))],
      ['连接数', node && node.connections],
      ['应用', node && node.app_name],
      ['判定依据', node && node.route_reason]
    ].filter((row) => firstText(row[1]) && row[1] !== '0 bps');
    return topologyDetailSectionHtml('历史记录', '<p class="topology-property-empty">此设备没有记录的活动</p>', { collapsed: false }) +
      topologyDetailSectionHtml('系统统计', rows.length ? topologyDetailRowsHtml(rows) : '<p class="topology-property-empty">当前节点没有可展示的实时统计。</p>', { collapsed: false });
  }

  function topologySettingsHtml(node, edge) {
    const rows = [
      ['类型', topologyTypeLabel(node && node.type)],
      ['ID', node && node.id],
      ['MAC 地址', node && node.mac],
      ['上联端口', topologyPortText(edge && edge.uplinkPortNumber, edge && edge.uplink_port)],
      ['下联端口', topologyPortText(edge && edge.downlinkPortNumber, edge && edge.downlink_port)],
      ['网络', topologyNetworkName(topologyActiveModel(), node)]
    ].filter((row) => firstText(row[1]));
    const name = topologyNodeTitle(node);
    const nameCard = `<label class="topology-property-field">
      <span>设备名称</span>
      <input type="text" value="${escapeHtml(name)}" readonly>
    </label>`;
    return topologyDetailSectionHtml('设备名称', nameCard, { collapsed: false }) +
      topologyDetailSectionHtml('高级', topologyDetailRowsHtml(rows), { collapsed: false });
  }

  function renderTopologyDetailDrawer() {
    if (!topologyDetailDrawer) return;
    const node = topologyFindNode(state.topology.selectedNodeMac);
    if (!state.topology.detailOpen || !node) {
      topologyDetailDrawer.hidden = true;
      topologyDetailDrawer.classList.remove('is-open');
      if (!node) state.topology.selectedNodeMac = '';
      return;
    }
    const edge = topologyNodeEdge(topologyActiveModel(), node);
    const currentTab = ['overview', 'insights', 'settings'].includes(state.topology.detailTab) ? state.topology.detailTab : 'overview';
    const body = currentTab === 'insights'
      ? topologyStatsHtml(node)
      : currentTab === 'settings'
        ? topologySettingsHtml(node, edge)
        : topologyOverviewHtml(node, edge);
    const currentScroll = topologyDetailDrawer.querySelector('.topology-property-scroll')?.scrollTop || 0;
    const renderKey = `${state.topology.selectedNodeMac}|${currentTab}`;
    topologyDetailDrawer.hidden = false;
    topologyDetailDrawer.classList.add('is-open');
    if (topologyDetailDrawer.dataset.renderKey === renderKey) return;
    topologyDetailDrawer.dataset.renderKey = renderKey;
    topologyDetailDrawer.innerHTML = `
      <header class="topology-property-head">
        <h2>${escapeHtml(topologyNodeTitle(node))}</h2>
        <button type="button" class="topology-property-close topology-icon-button" data-topology-detail-close aria-label="关闭节点详情">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M5 5l10 10"/><path d="M15 5 5 15"/></svg>
        </button>
      </header>
      <div class="topology-property-tabs" role="tablist" aria-label="拓扑节点详情">
        <button type="button" data-topology-detail-tab="overview" aria-selected="${currentTab === 'overview'}" title="概览">
          <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M3 5.5A2.5 2.5 0 0 1 5.5 3h9A2.5 2.5 0 0 1 17 5.5v9a2.5 2.5 0 0 1-2.5 2.5h-9A2.5 2.5 0 0 1 3 14.5v-9Zm2.5-1A1 1 0 0 0 4.5 5.5v9a1 1 0 0 0 1 1h9a1 1 0 0 0 1-1v-9a1 1 0 0 0-1-1h-9Zm1.25 3h6.5V9h-6.5V7.5Zm0 3.5h3.5v1.5h-3.5V11Z"/></svg>
        </button>
        <button type="button" data-topology-detail-tab="insights" aria-selected="${currentTab === 'insights'}" title="洞察">
          <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M4 14.5h12V16H4v-1.5Zm1-2.5h2.2V6H5v6Zm3.9 0h2.2V3.5H8.9V12Zm3.9 0H15V8h-2.2v4Z"/></svg>
        </button>
        <button type="button" data-topology-detail-tab="settings" aria-selected="${currentTab === 'settings'}" title="设置">
          <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M8.9 2.5h2.2l.35 1.62c.33.12.64.25.93.43l1.46-.9 1.56 1.55-.9 1.47c.17.3.32.6.42.93l1.63.34v2.2l-1.63.35c-.1.33-.25.64-.42.93l.9 1.46-1.56 1.56-1.46-.9c-.3.17-.6.32-.93.43l-.35 1.62H8.9l-.35-1.62a5.8 5.8 0 0 1-.93-.43l-1.46.9-1.56-1.56.9-1.46a5.8 5.8 0 0 1-.42-.93l-1.63-.35v-2.2l1.63-.34c.1-.33.25-.64.42-.93L4.6 5.2l1.56-1.55 1.46.9c.3-.18.6-.31.93-.43L8.9 2.5ZM10 7a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z"/></svg>
        </button>
      </div>
      <div class="topology-property-scroll">
        ${body || '<section class="topology-property-card"><p class="topology-property-empty">当前节点没有可展示的详情。</p></section>'}
      </div>`;
    const nextScroll = topologyDetailDrawer.querySelector('.topology-property-scroll');
    if (nextScroll && currentScroll > 0) nextScroll.scrollTop = currentScroll;
    window.DWRT_UI_KIT?.mountAll(topologyDetailDrawer);
  }

  function closeTopologyDetail(options = {}) {
    state.topology.selectedNodeMac = '';
    state.topology.detailTab = 'overview';
    state.topology.detailOpen = false;
    if (topologyDetailDrawer) delete topologyDetailDrawer.dataset.renderKey;
    state.topology.transformSet = false;
    renderTopologyDetailDrawer();
    if (!options.skipRender) renderCurrentTopologyModel();
  }

  function openTopologyDetail(mac) {
    const node = topologyFindNode(mac);
    if (!node) return;
    state.topology.selectedNodeMac = node.mac;
    state.topology.detailTab = 'overview';
    state.topology.detailOpen = true;
    if (topologyDetailDrawer) delete topologyDetailDrawer.dataset.renderKey;
    state.topology.transformSet = false;
    renderCurrentTopologyModel();
    renderTopologyDetailDrawer();
  }

  function topologyCountSummary(model) {
    const vertices = asArray(model && model.vertices);
    const clients = vertices.filter((node) => String(node.type || '').toUpperCase() === 'CLIENT');
    const online = vertices.filter((node) => topologyNodeState(node) === 'online').length;
    const offline = vertices.filter((node) => topologyNodeState(node) === 'offline').length;
    const wired = clients.filter((node) => topologyConnectionKind(model, node) !== 'wireless').length;
    const wireless = clients.filter((node) => topologyConnectionKind(model, node) === 'wireless').length;
    const vlanDefault = vertices.filter((node) => {
      const name = topologyNetworkName(model, node);
      return !name || /default/i.test(name) || name === '1' || name === '0';
    }).length;
    return { online, offline, wired, wireless, vlanDefault };
  }

  function infrastructureRoot(payload = {}) {
    const data = unwrapApiData(payload);
    return data && typeof data === 'object' ? data : {};
  }

  function infrastructureList(value, nestedKey) {
    if (Array.isArray(value)) return value;
    if (value && typeof value === 'object') {
      if (nestedKey && Array.isArray(value[nestedKey])) return value[nestedKey];
      if (Array.isArray(value.items)) return value.items;
      if (Array.isArray(value.list)) return value.list;
    }
    return [];
  }

  function infrastructureContract(payload = {}) {
    const root = infrastructureRoot(payload);
    const infra = root.infrastructure && typeof root.infrastructure === 'object' ? root.infrastructure : {};
    const rootVertices = infrastructureList(root.vertices, 'vertices');
    const infraGateways = infrastructureList(infra.gateways, 'gateways');
    const rootGateways = infrastructureList(root.gateways, 'gateways');
    const snapshotGateways = rootVertices.filter((item) => {
      const mac = firstText(item && item.mac);
      return mac && (mac === firstText(root.gatewayMac, root.gateway_mac) || /udm|gateway/i.test(firstText(item.deviceType, item.type, item.role)));
    });
    const infraWans = infrastructureList(infra.wans, 'wans');
    const rootWans = infrastructureList(root.wans, 'wans');
    const snapshotWans = infrastructureList(root.ispData, 'ispData');
    const wans = infraWans.length ? infraWans : rootWans.length ? rootWans : snapshotWans;
    const wanNodes = infrastructureList(root.wan_nodes, 'wan_nodes');
    return {
      root,
      infra,
      gateways: infraGateways.length ? infraGateways : rootGateways.length ? rootGateways : snapshotGateways.length ? snapshotGateways : root.gateway ? [root.gateway] : [],
      switches: infrastructureList(infra.switches, 'switches').length ? infrastructureList(infra.switches, 'switches') : infrastructureList(root.switches, 'switches'),
      aps: infrastructureList(infra.aps, 'aps').length ? infrastructureList(infra.aps, 'aps') : infrastructureList(root.aps, 'aps'),
      wans: wans.length ? wans : wanNodes,
      wanNodes,
      ports: infrastructureList(infra.ports, 'ports').length ? infrastructureList(infra.ports, 'ports') : infrastructureList(root.ports, 'ports'),
      clients: infrastructureList(infra.clients, 'clients').length ? infrastructureList(infra.clients, 'clients') : infrastructureList(root.clients, 'clients'),
      links: infrastructureList(infra.links, 'links').length ? infrastructureList(infra.links, 'links') : infrastructureList(root.links, 'links'),
      digitalTwin: infra.digital_twin || root.digital_twin || root.digitalTwin || {},
      diagnostics: infra.diagnostics || root.diagnostics || {}
    };
  }

  function infrastructureIcon(type) {
    const key = String(type || '').toLowerCase();
    if (key.includes('gateway')) return '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 6.2A2.2 2.2 0 0 1 6.2 4h7.6A2.2 2.2 0 0 1 16 6.2v7.6a2.2 2.2 0 0 1-2.2 2.2H6.2A2.2 2.2 0 0 1 4 13.8V6.2Z"></path><path d="M7 8h6M7 11h3"></path></svg>';
    if (key.includes('wan') || key.includes('internet')) return '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M10 3a7 7 0 1 1 0 14 7 7 0 0 1 0-14Z"></path><path d="M3.6 10h12.8M10 3.4c2 2.1 2 11.1 0 13.2M10 3.4c-2 2.1-2 11.1 0 13.2"></path></svg>';
    if (key.includes('port')) return '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 5h10v7H5V5Z"></path><path d="M7 15h6M8 12v3M12 12v3"></path></svg>';
    if (key.includes('client')) return '<svg viewBox="0 0 20 20" aria-hidden="true"><rect x="4" y="5" width="12" height="8" rx="2"></rect><path d="M8 16h4M10 13v3"></path></svg>';
    if (key.includes('link')) return '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M7.5 6.5h-1A3.5 3.5 0 0 0 3 10a3.5 3.5 0 0 0 3.5 3.5h1"></path><path d="M12.5 6.5h1A3.5 3.5 0 0 1 17 10a3.5 3.5 0 0 1-3.5 3.5h-1"></path><path d="M7 10h6"></path></svg>';
    return '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 4h12v12H4V4Z"></path><path d="M7 7h6v6H7V7Z"></path></svg>';
  }

  function infrastructureStatusClass(value) {
    const text = firstText(value).toLowerCase();
    if (/^(online|connected|ok|up|active|healthy|true)$/.test(text)) return 'is-ok';
    if (/^(warn|warning|degraded|partial)$/.test(text)) return 'is-warn';
    if (/^(offline|down|disconnected|bad|error|failed|false)$/.test(text)) return 'is-bad';
    return 'is-muted';
  }

  function infrastructureStatusText(value, fallback = '未知') {
    const text = firstText(value);
    if (!text) return fallback;
    const key = text.toLowerCase();
    if (/^(online|connected|ok|up|active|healthy|true)$/.test(key)) return '在线';
    if (/^(offline|down|disconnected|bad|error|failed|false)$/.test(key)) return '离线';
    return text;
  }

  function infrastructureNodeCard(item = {}, type = 'node') {
    const title = firstText(item.name, item.label, item.display_name, item.hostname, item.id, item.mac, '--');
    const subtitle = firstText(item.model, item.product, item.role, item.ifname, item.device, item.ip, item.ipv4, item.mac, item.note, '--');
    const status = firstText(item.state, item.status, item.online === true ? 'online' : item.online === false ? 'offline' : '');
    const cls = infrastructureStatusClass(status);
    const meta = [
      firstText(item.ip, item.ipv4, item.public_ipv4, item.public_ip),
      firstText(item.port, item.ifname, item.device),
      firstText(item.carrier_name, item.carrier, item.provider),
      firstText(item.link_speed, item.speed)
    ].filter(Boolean).slice(0, 2);
    return `<article class="topology-infra-card ${escapeHtml(cls)}">
      <span class="topology-infra-icon ${escapeHtml(type)}">${infrastructureIcon(type)}</span>
      <span class="topology-infra-copy"><strong>${escapeHtml(title)}</strong><small>${escapeHtml(subtitle)}</small>${meta.length ? `<em>${meta.map(escapeHtml).join(' · ')}</em>` : ''}</span>
      <span class="topology-infra-state">${escapeHtml(infrastructureStatusText(status, ''))}</span>
    </article>`;
  }

  function infrastructureMetric(label, value, type) {
    return `<div class="topology-infra-metric"><span class="topology-infra-icon ${escapeHtml(type || '')}">${infrastructureIcon(type)}</span><strong>${escapeHtml(String(value ?? 0))}</strong><small>${escapeHtml(label)}</small></div>`;
  }

  function topologyInfraCpuMem(item = {}, fallback = {}) {
    const cpu = firstNumber(item.cpu, item.cpu_usage, item.cpu_percent, item.cpuPercent, item.system_stats && item.system_stats.cpu, fallback.cpu, fallback.cpu_usage, fallback.cpu_percent);
    const mem = firstNumber(item.mem, item.memory, item.mem_usage, item.mem_percent, item.memPercent, item.system_stats && item.system_stats.mem, fallback.mem, fallback.mem_usage, fallback.mem_percent);
    return { cpu, mem };
  }

  function topologyInfraPortNumber(port = {}, index = 0) {
    const explicit = firstText(port.port_idx, port.portIndex, port.port_number, port.portNumber, port.port_no, port.number, port.index);
    if (explicit) return explicit;
    const name = firstText(port.name, port.label, port.ifname, port.device, port.id);
    const match = name.match(/(?:eth|port|lan|wan)[^0-9]*([0-9]+)/i) || name.match(/([0-9]+)$/);
    if (match) return match[1];
    return String(index + 1);
  }

  function topologyInfraWanOrdinal(wan = {}, index = 0) {
    return firstNumber(wan.order, wan.priority, wan.portIdx, wan.port_idx) || index + 1;
  }

  function topologyInfraWanKey(wan = {}) {
    return firstText(wan.wan_id, wan.owner_id, wan.id, wan.ifname, wan.name).toLowerCase().replace(/^wan:/, '');
  }

  function topologyInfraMergeWans(primary = [], detail = [], nodes = []) {
    const detailByKey = new Map();
    detail.concat(nodes).forEach((item) => {
      const key = topologyInfraWanKey(item);
      if (key && !detailByKey.has(key)) detailByKey.set(key, item);
    });
    const source = primary.length ? primary : detail.concat(nodes);
    return source.map((item, index) => {
      const key = topologyInfraWanKey(item);
      const extra = key ? detailByKey.get(key) : null;
      return extra && extra !== item ? { ...extra, ...item, __infra_index: index } : { ...item, __infra_index: index };
    });
  }

  function topologyInfraFindWanPort(wan = {}, ports = []) {
    const wanted = [wan.device, wan.ifname, wan.runtime_device, wan.owner_id, wan.id, wan.wan_id, wan.name]
      .map((value) => firstText(value).toLowerCase()).filter(Boolean);
    if (!wanted.length) return null;
    return ports.find((port) => {
      const haystack = [port.ifname, port.device, port.name, port.label, port.owner_id, port.id, port.runtime_device]
        .map((value) => firstText(value).toLowerCase()).filter(Boolean);
      return wanted.some((needle) => haystack.includes(needle));
    }) || null;
  }

  function topologyInfraWanPortNumber(wan = {}, index = 0, ports = []) {
    const port = wan.port && typeof wan.port === 'object' ? wan.port : topologyInfraFindWanPort(wan, ports) || {};
    return firstText(wan.portIdx, wan.port_idx, wan.port_number, port.port_idx, port.portIndex, port.port_number, port.portNumber)
      || topologyInfraPortNumber(port, index);
  }

  function topologyInfraWanTitle(wan = {}, index = 0) {
    const carrier = firstText(wan.carrier_name, wan.isp_name, wan.provider, wan.note, wan.name);
    if (carrier && !/^wan\d*$/i.test(carrier) && !/^wan:/i.test(carrier)) return carrier;
    return 'ISP';
  }

  function topologyInfraWanLabel(wan = {}, index = 0) {
    const explicit = firstText(wan.display_name, wan.label);
    if (explicit && !/^wan:/i.test(explicit)) return explicit;
    const order = topologyInfraWanOrdinal(wan, index);
    const rawWan = firstText(wan.wan_label, wan.wan_id, wan.ifname, wan.id, wan.name, `WAN${order}`).replace(/^wan:/i, '');
    const wanName = rawWan.toUpperCase();
    const normalizedWan = /^WAN\d*$/i.test(wanName) ? (wanName === 'WAN' ? `WAN${order}` : wanName) : /^WAN:/i.test(wanName) ? `WAN${order}` : wanName;
    const mode = firstText(wan.loadBalancingMode, wan.load_balancing_mode, wan.mode, wan.priority ? 'FAILOVER_ONLY' : '');
    const modeText = mode === 'FAILOVER_ONLY' || /failover|backup/i.test(mode) ? '仅故障转移' : mode ? mode : '';
    return [normalizedWan, modeText].filter(Boolean).join(' · ');
  }

  function topologyInfraPercent(value, fallback = '0%') {
    const num = Number(value);
    if (!Number.isFinite(num) || num < 0) return fallback;
    const digits = num >= 10 ? 1 : 0;
    return `${num.toFixed(digits).replace(/\.0$/, '')}%`;
  }

  function topologyInfraWanLoad(wan = {}) {
    const explicit = firstNumber(wan.utilization_pct, wan.utilization, wan.load, wan.busy);
    if (explicit > 0) return explicit;
    const up = firstNumber(wan.up_rate, wan.tx_rate, wan.rate_up, wan['tx_bytes-r']);
    const down = firstNumber(wan.down_rate, wan.rx_rate, wan.rate_down, wan['rx_bytes-r']);
    const capacity = firstNumber(wan.capacity, wan.configured_down_rate, wan.expected_down_rate, wan.link_speed_mbps) * 125000;
    if (capacity > 0) return Math.max(0, Math.min(100, (up + down) / capacity * 100));
    return 0;
  }

  function topologyInfraStatusClass(item = {}) {
    const status = firstText(item.status, item.state, item.online === true ? 'online' : item.online === false ? 'offline' : '');
    const key = status.toLowerCase();
    if (item.isOnline === false || item.online === false || /down|offline|disconnected|failed|error|false/.test(key)) return 'is-offline';
    if (/warn|degraded|loss|unstable/.test(key) || firstNumber(item.loss) > 0 || item.degraded === true) return 'is-warn';
    return 'is-online';
  }

  function topologyInfraDeviceImage(gateway = {}) {
    const image = firstText(gateway.image, gateway.icon, gateway.device_image, gateway.model_image, '/static/images/gateway-wide.png');
    return `<img src="${escapeHtml(image)}" alt="${escapeHtml(firstText(gateway.name, 'Gateway'))}">`;
  }

  function topologyInfraCpuIcon() {
    return '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M6 2v3M10 2v3M14 2v3M6 15v3M10 15v3M14 15v3M2 6h3M2 10h3M2 14h3M15 6h3M15 10h3M15 14h3M6 6h8v8H6z"/></svg>';
  }

  function topologyInfraMemoryIcon() {
    return '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 7h12v7H4zM6 5v2M9 5v2M12 5v2M14 5v2M6 14v2M9 14v2M12 14v2M14 14v2"/></svg>';
  }

  function topologyInfraMetric(value, icon) {
    const num = Number(value);
    if (!Number.isFinite(num) || num <= 0) return '';
    return `<em>${escapeHtml(topologyInfraPercent(num))}${icon}</em>`;
  }

  function topologyInfraPortChips(wans, ports) {
    return wans.map((wan, index) => {
      const port = topologyInfraFindWanPort(wan, ports) || {};
      const speed = firstText(port.speed_label, wan.link_speed, port.link_speed_mbps ? `${port.link_speed_mbps}M` : '');
      const title = [firstText(port.ifname, wan.device, wan.ifname), speed].filter(Boolean).join(' · ');
      return `<span class="topology-infra-port-chip" title="${escapeHtml(title)}"><i>${infrastructureIcon('wan')}</i><strong>${escapeHtml(topologyInfraWanPortNumber(wan, index, ports))}</strong></span>`;
    }).join('');
  }

  function topologyInfraSyntheticMac(prefix, item = {}, index = 0) {
    const hardware = firstText(item.mac, item.wan_mac, item.client_mac, item.hwaddr);
    const raw = hardware || firstText(item.id, item.owner_id, item.ifname, item.name, `${prefix}-${index}`);
    const normalized = String(raw).trim().toLowerCase().replace(/[^a-z0-9:._-]/g, '-').replace(/-+/g, '-');
    if (hardware) return normalized || `${prefix}-${index}`;
    return `${prefix}-${index}-${normalized || 'node'}`;
  }

  function topologyInfraNodeState(item = {}) {
    return topologyInfraStatusClass(item) === 'is-offline' ? 'OFFLINE' : 'CONNECTED';
  }

  function topologyInfraRate(item = {}) {
    const tx = firstNumber(item.up_rate, item.tx_rate, item.rate_up, item.txBytesRate, item.tx_bytes_r, item['tx_bytes-r'], item.traffic && item.traffic.tx);
    const rx = firstNumber(item.down_rate, item.rx_rate, item.rate_down, item.rxBytesRate, item.rx_bytes_r, item['rx_bytes-r'], item.traffic && item.traffic.rx);
    return { tx, rx, sum: tx + rx, known: Boolean(tx || rx || item.up_rate !== undefined || item.down_rate !== undefined || item.tx_rate !== undefined || item.rx_rate !== undefined) };
  }

  function topologyInfraClientConnection(client = {}) {
    const raw = firstText(client.connection, client.connection_type, client.uplink_type, client.network_type, client.type).toLowerCase();
    return /wifi|wireless|wlan|无线/.test(raw) ? 'WIRELESS' : 'WIRED';
  }

  function topologyInfraClientImage(client = {}) {
    const fingerprint = client.fingerprintData || client.fingerprint || {};
    return firstText(
      client.custom_image_path,
      client.custom_icon,
      client.override_image,
      client.override_icon,
      client.web_image,
      client.image,
      client.icon,
      client.icon_url,
      client.fingerprint_image,
      fingerprint.custom_image_path,
      fingerprint.image,
      fingerprint.icon
    );
  }

  function topologyInfraGatewayImage(gateway = {}) {
    return firstText(gateway.image, gateway.icon, gateway.device_image, gateway.model_image, '/static/images/gateway-wide.png');
  }

  function topologyInfraLinkSpeed(item = {}) {
    const speed = firstNumber(item.rateMbps, item.rate_mbps, item.speed_mbps, item.link_speed_mbps, item.port && item.port.link_speed_mbps);
    if (speed > 0) return speed;
    const text = firstText(item.link_speed, item.speed, item.port && item.port.speed_label).toLowerCase();
    const match = text.match(/([0-9]+(?:\.[0-9]+)?)/);
    if (!match) return 0;
    const value = Number(match[1]);
    if (!Number.isFinite(value)) return 0;
    if (/gbps|gbit|\bg\b/.test(text)) return value * 1000;
    if (/kbps|kbit|\bk\b/.test(text)) return value / 1000;
    return value;
  }

  function topologyInfraToModel(contract, healthRoot = {}) {
    const root = contract.root || {};
    const gateway = contract.gateways[0] || root.gateway || contract.infra && contract.infra.gateways && contract.infra.gateways[0] || {};
    const rootWans = infrastructureList(root.wans, 'wans');
    const rootWanNodes = infrastructureList(root.wan_nodes, 'wan_nodes');
    const wans = topologyInfraMergeWans(
      contract.wans.length ? contract.wans : infrastructureList(root.ispData, 'ispData'),
      rootWans,
      rootWanNodes
    );
    const ports = contract.ports || [];
    const systemHealth = healthRoot.system && typeof healthRoot.system === 'object' ? healthRoot.system : healthRoot;
    const metrics = topologyInfraCpuMem(gateway, systemHealth);
    const gatewayMac = topologyInfraSyntheticMac('gateway', {
      mac: firstText(gateway.mac, gateway.gateway_mac, root.gatewayMac, root.gateway_mac, 'dreamingwrt-gateway')
    }, 0);
    const vertices = [{
      ...gateway,
      id: firstText(gateway.id, gatewayMac),
      mac: gatewayMac,
      type: 'DEVICE',
      name: firstText(gateway.name, gateway.display_name, gateway.model, root.gatewayName, root.gatewayMac, 'Dreaming OS'),
      model: firstText(gateway.model, gateway.product, gateway.device_model, 'Dreaming OS'),
      ip: firstText(gateway.ip, gateway.ipv4, gateway.management_ip, root.gateway_ip),
      state: topologyInfraNodeState(gateway),
      uptime: firstNumber(gateway.uptime, gateway.uptime_seconds, systemHealth.uptime),
      cpu: metrics.cpu ? topologyInfraPercent(metrics.cpu) : '',
      memory: metrics.mem ? topologyInfraPercent(metrics.mem) : '',
      image: topologyInfraGatewayImage(gateway),
      unifiDevice: true,
      infrastructure_kind: 'gateway'
    }];
    const edges = [];

    wans.forEach((wan, index) => {
      const wanPort = topologyInfraFindWanPort(wan, ports) || {};
      const wanKey = topologyInfraSyntheticMac('wan', {
        id: firstText(wan.wan_id, wan.owner_id, wan.id, wan.ifname, wan.name, `wan${index + 1}`)
      }, index);
      const wanMac = `${wanKey}-node`;
      const ispMac = `${wanKey}-isp`;
      const rate = topologyInfraRate(wan);
      const status = topologyInfraNodeState(wan);
      const carrier = topologyInfraWanTitle(wan, index);
      const label = topologyInfraWanLabel(wan, index);
      const wanId = firstText(wan.wan_id, wan.id, wan.ifname, wan.name, `wan${index + 1}`);
      vertices.push({
        ...wan,
        id: ispMac,
        mac: ispMac,
        type: 'ISP',
        name: carrier,
        model: label,
        state: status,
        carrier_name: firstText(wan.carrier_name, wan.isp_name, wan.provider, carrier),
        carrier: firstText(wan.carrier, wan.provider, carrier),
        wan_id: wanId,
        ip: firstText(wan.public_ip, wan.public_ipv4, wan.wan_ip, wan.ip, wan.ipv4),
        public_ip: firstText(wan.public_ip, wan.public_ipv4, wan.wan_ip, wan.ip, wan.ipv4),
        protocol: firstText(wan.protocol, wan.wan_protocol, wan.proto),
        gateway: firstText(wan.gateway, wan.gateway_ip),
        dns: wan.dns,
        load_balancing_mode: firstText(wan.loadBalancingMode, wan.load_balancing_mode, wan.mode),
        traffic: rate,
        route_reason: firstText(wan.route_reason, wan.reason),
        infrastructure_kind: 'isp'
      });
      vertices.push({
        ...wanPort,
        ...wan,
        id: wanMac,
        mac: wanMac,
        type: 'USW_WAN',
        name: firstText(label, wanId.toUpperCase(), `WAN${index + 1}`),
        model: firstText(wanPort.ifname, wan.ifname, wan.device, wan.runtime_device),
        state: status,
        wan_id: wanId,
        ip: firstText(wan.ip, wan.ipv4, wan.public_ip, wan.public_ipv4),
        traffic: rate,
        rateMbps: topologyInfraLinkSpeed({ ...wanPort, ...wan }),
        infrastructure_kind: 'wan'
      });
      edges.push({
        uplinkMac: ispMac,
        downlinkMac: wanMac,
        type: 'WIRED',
        wan_id: wanId,
        traffic: rate,
        rateMbps: topologyInfraLinkSpeed(wan)
      });
      edges.push({
        uplinkMac: wanMac,
        downlinkMac: gatewayMac,
        type: 'WIRED',
        uplinkPortNumber: topologyInfraWanPortNumber(wan, index, ports),
        wan_id: wanId,
        traffic: rate,
        rateMbps: topologyInfraLinkSpeed({ ...wanPort, ...wan })
      });
    });

    contract.switches.forEach((item, index) => {
      const mac = topologyInfraSyntheticMac('switch', item, index);
      vertices.push({
        ...item,
        id: firstText(item.id, mac),
        mac,
        type: 'DEVICE',
        name: firstText(item.name, item.display_name, item.hostname, item.model, `Switch ${index + 1}`),
        model: firstText(item.model, item.product, item.role, 'Switch'),
        ip: firstText(item.ip, item.ipv4, item.management_ip),
        state: topologyInfraNodeState(item),
        image: firstText(item.image, item.icon, item.device_image),
        infrastructure_kind: 'switch'
      });
      edges.push({ uplinkMac: gatewayMac, downlinkMac: mac, type: 'WIRED', uplinkPortNumber: topologyInfraPortNumber(item, index) });
    });

    contract.aps.forEach((item, index) => {
      const mac = topologyInfraSyntheticMac('ap', item, index);
      vertices.push({
        ...item,
        id: firstText(item.id, mac),
        mac,
        type: 'DEVICE',
        name: firstText(item.name, item.display_name, item.hostname, item.model, `AP ${index + 1}`),
        model: firstText(item.model, item.product, item.role, 'Access Point'),
        ip: firstText(item.ip, item.ipv4, item.management_ip),
        state: topologyInfraNodeState(item),
        image: firstText(item.image, item.icon, item.device_image),
        infrastructure_kind: 'ap'
      });
      edges.push({ uplinkMac: gatewayMac, downlinkMac: mac, type: 'WIRELESS' });
    });

    contract.links.forEach((link) => {
      const uplinkMac = firstText(link.uplinkMac, link.uplink_mac, link.source, link.parent, link.from);
      const downlinkMac = firstText(link.downlinkMac, link.downlink_mac, link.target, link.child, link.to);
      if (!uplinkMac || !downlinkMac) return;
      if (!vertices.some((node) => node.mac === uplinkMac) || !vertices.some((node) => node.mac === downlinkMac)) return;
      if (edges.some((edge) => edge.uplinkMac === uplinkMac && edge.downlinkMac === downlinkMac)) return;
      edges.push({
        ...link,
        uplinkMac,
        downlinkMac,
        type: firstText(link.type, link.connection_type).toUpperCase() === 'WIRELESS' ? 'WIRELESS' : 'WIRED',
        traffic: topologyInfraRate(link),
        uplinkPortNumber: firstNumber(link.uplinkPortNumber, link.uplink_port, link.port)
      });
    });

    return {
      valid: vertices.length > 1 && edges.length > 0,
      reason: vertices.length > 1 && edges.length > 0 ? '' : 'infrastructure contract has no drawable links',
      vertices,
      edges,
      layout: { rotateMap: Boolean(state.topology.rotateMap), labelWidth: true },
      diagnostics: contract.diagnostics || {},
      source: 'topology_infrastructure_contract'
    };
  }

  function topologyInfraNodeByKind(model, kind) {
    return asArray(model && model.vertices).find((node) => node.infrastructure_kind === kind) || null;
  }

  function topologyInfraNodesByKind(model, kind) {
    return asArray(model && model.vertices).filter((node) => node.infrastructure_kind === kind);
  }

  function topologyInfraCardSelected(mac) {
    return state.topology.selectedNodeMac && mac && state.topology.selectedNodeMac === mac ? ' is-selected' : '';
  }

  function topologyInfraPairs(contract, model) {
    const root = contract.root || {};
    const rootWans = infrastructureList(root.wans, 'wans');
    const rootWanNodes = infrastructureList(root.wan_nodes, 'wan_nodes');
    const wans = topologyInfraMergeWans(
      contract.wans.length ? contract.wans : infrastructureList(root.ispData, 'ispData'),
      rootWans,
      rootWanNodes
    );
    const ispNodes = topologyInfraNodesByKind(model, 'isp');
    const wanNodes = topologyInfraNodesByKind(model, 'wan');
    return wans.map((wan, index) => ({
      wan,
      isp: ispNodes[index] || null,
      wanNode: wanNodes[index] || null,
      index
    })).filter((pair) => pair.isp || pair.wanNode);
  }

  function topologyInfraPortButtons(pairs, ports) {
    return pairs.map(({ wan, wanNode, index }) => {
      if (!wanNode) return '';
      const port = topologyInfraFindWanPort(wan, ports) || {};
      const speed = firstText(port.speed_label, wan.link_speed, port.link_speed_mbps ? `${port.link_speed_mbps}M` : '');
      const title = [firstText(port.ifname, wan.device, wan.ifname), speed].filter(Boolean).join(' · ');
      return `<button type="button" class="topology-infra-port-chip${topologyInfraCardSelected(wanNode.mac)}" data-topology-infra-node data-node-mac="${escapeHtml(wanNode.mac)}" title="${escapeHtml(title || topologyNodeTitle(wanNode))}"><i>${infrastructureIcon('wan')}</i><strong>${escapeHtml(topologyInfraWanPortNumber(wan, index, ports))}</strong></button>`;
    }).join('');
  }

  function topologyInfraLines(pairs = []) {
    const count = Math.max(1, pairs.length);
    if (!pairs.length) return '';
    const mid = (count - 1) / 2;
    const spacing = count <= 1 ? 0 : Math.min(310, Math.max(178, 530 / Math.max(1, count - 1)));
    const wanXs = pairs.map((_, index) => Math.max(120, Math.min(880, 500 + (index - mid) * spacing)));
    const portSpacing = count <= 1 ? 0 : Math.min(128, Math.max(76, 230 / Math.max(1, count - 1)));
    const portXs = pairs.map((_, index) => Math.max(360, Math.min(720, 575 + (index - mid) * portSpacing)));
    const gatewayX = 690;
    const wanY = 192;
    const portY = 415;
    const gatewayY = 486;
    const paths = pairs.map((pair, index) => {
      const x1 = wanXs[index];
      const x2 = portXs[index];
      const gOffset = (index - mid) * 28;
      const x3 = gatewayX + gOffset;
      return [
        `M ${x1} ${wanY} C ${x1} ${wanY + 86}, ${x2 - 72} ${portY - 100}, ${x2} ${portY - 30}`,
        `M ${x2} ${portY + 22} C ${x2 + 18} ${portY + 52}, ${x3 - 52} ${gatewayY - 36}, ${x3} ${gatewayY}`
      ].map((d) => `<path d="${d}"></path>`).join('');
    }).join('');
    return `<svg class="topology-infra-lines" viewBox="0 0 1000 650" preserveAspectRatio="none" aria-hidden="true">${paths}</svg>`;
  }

  function topologyInfraCanvasHtml(contract, model) {
    const ports = contract.ports || [];
    const pairs = topologyInfraPairs(contract, model);
    const gateway = topologyInfraNodeByKind(model, 'gateway') || asArray(model && model.vertices).find((node) => String(node.type || '').toUpperCase() === 'DEVICE') || {};
    const stats = [
      topologyInfraMetric(firstNumber(String(gateway.cpu || '').replace('%', ''), gateway.cpu), topologyInfraCpuIcon()),
      topologyInfraMetric(firstNumber(String(gateway.memory || '').replace('%', ''), gateway.memory, gateway.mem), topologyInfraMemoryIcon())
    ].filter(Boolean).join('');
    return `<div class="topology-infra-zoom-container"><section class="topology-infra-canvas" aria-label="基础设施">
      ${topologyInfraLines(pairs)}
      <div class="topology-infra-wans ${pairs.length > 1 ? 'is-multi' : ''}" style="--infra-wan-count:${Math.max(1, pairs.length)}">
        ${pairs.map(({ wan, isp, index }) => {
          const mac = isp && isp.mac;
          return `<button type="button" class="topology-infra-wan-card ${topologyInfraStatusClass(wan)}${topologyInfraCardSelected(mac)}" data-topology-infra-node data-node-mac="${escapeHtml(mac || '')}" ${mac ? '' : 'disabled'}>
            <span class="topology-infra-wan-icon">${infrastructureIcon('wan')}</span>
            <strong>${escapeHtml(topologyInfraWanTitle(wan, index))}</strong>
            <em>${escapeHtml(topologyInfraPercent(topologyInfraWanLoad(wan)))}</em>
            <small>${escapeHtml(topologyInfraWanLabel(wan, index))}</small>
          </button>`;
        }).join('')}
      </div>
      <div class="topology-infra-port-row">${topologyInfraPortButtons(pairs, ports)}</div>
      <button type="button" class="topology-infra-gateway-card${topologyInfraCardSelected(gateway.mac)}" data-topology-infra-node data-node-mac="${escapeHtml(gateway.mac || '')}">
        <span class="topology-infra-device-image" aria-hidden="true">${topologyInfraDeviceImage(gateway)}</span>
        <span class="topology-infra-device-icon">${infrastructureIcon('wan')}</span>
        <strong>${escapeHtml(topologyNodeTitle(gateway))}</strong>
        ${stats ? `<span class="topology-infra-device-stats">${stats}</span>` : ''}
      </button>
    </section></div>`;
  }

  function clearTopologyCanvasLayers() {
    if (topologyNodeLayer) topologyNodeLayer.innerHTML = '';
    if (topologyLinkLayer) topologyLinkLayer.innerHTML = '';
    if (topologyLabelLayer) topologyLabelLayer.innerHTML = '';
    if (topologyToggleLayer) topologyToggleLayer.innerHTML = '';
  }

  function renderTopologyInfrastructureView() {
    if (!topologyInfrastructureEmpty) return false;
    if (state.topology.view !== 'infrastructure') {
      topologyInfrastructureEmpty.hidden = true;
      return false;
    }
    const payload = state.topology.timeMachineSelectedTimestamp && state.topology.timeMachineSnapshot
      ? state.topology.timeMachineSnapshot
      : state.topology.infrastructureData || state.topology.lastTopologyData || {};
    const contract = infrastructureContract(payload);
    const total = contract.gateways.length + contract.switches.length + contract.aps.length + contract.wans.length + contract.ports.length + contract.clients.length + contract.links.length;
    if (!total) {
      state.topology.infrastructureModel = null;
      clearTopologyCanvasLayers();
      if (topologyContentContainer) topologyContentContainer.hidden = true;
      topologyInfrastructureEmpty.classList.remove('is-ready', 'is-unifi-canvas');
      topologyInfrastructureEmpty.hidden = false;
      topologyInfrastructureEmpty.innerHTML = `<strong>正在读取基础设施</strong><span>${escapeHtml(state.topology.infrastructureError || '等待 /api/v1/topology/infrastructure 返回真实 infrastructure contract。')}</span>`;
      return false;
    }
    const model = topologyInfraToModel(contract, state.topology.infrastructureHealthData || {});
    state.topology.infrastructureModel = model;
    if (!model.valid) {
      clearTopologyCanvasLayers();
      if (topologyContentContainer) topologyContentContainer.hidden = true;
      topologyInfrastructureEmpty.classList.remove('is-ready', 'is-unifi-canvas');
      topologyInfrastructureEmpty.hidden = false;
      topologyInfrastructureEmpty.innerHTML = `<strong>基础设施暂不可绘制</strong><span>${escapeHtml(model.reason || '后端返回的数据缺少 WAN / 网关 / 端口链路。')}</span>`;
      return false;
    }
    clearTopologyCanvasLayers();
    if (topologyContentContainer) topologyContentContainer.hidden = true;
    topologyInfrastructureEmpty.classList.add('is-ready', 'is-unifi-canvas');
    topologyInfrastructureEmpty.hidden = false;
    topologyInfrastructureEmpty.innerHTML = topologyInfraCanvasHtml(contract, model);
    if (!state.topology.transformSet) state.topology.transform = { x: 0, y: 0, k: 1 };
    applyTopologyTransform();
    renderTopologyTimeMachine();
    renderTopologyDetailDrawer();
    scheduleSelectedTopologyNodeVisible();
    if (topologyStatus) topologyStatus.textContent = '';
    return true;
  }

  async function fetchTopologyInfrastructureOptional() {
    const [result, health] = await Promise.all([
      fetchApiResource('topology_infrastructure', '/api/v1/topology/infrastructure'),
      fetchApiResource('system_health_for_infrastructure', '/api/v1/system/health')
    ]);
    if (result.ok) {
      state.topology.infrastructureData = result.data;
      state.topology.infrastructureError = '';
    } else {
      state.topology.infrastructureError = result.error ? result.error.message : 'topology infrastructure endpoint unavailable';
    }
    if (health.ok) state.topology.infrastructureHealthData = health.data;
    if (state.topology.view === 'infrastructure') renderTopologyInfrastructureView();
    return result;
  }

  function timeMachinePayloadList(payload, key) {
    const data = unwrapApiData(payload);
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data[key])) return data[key];
    if (data && Array.isArray(data.items)) return data.items;
    return [];
  }

  function timeMachineEventLabel(event = {}) {
    const type = firstText(event.type, event.event_type).toUpperCase();
    const labels = {
      NETWORK_OFFLINE: '网络离线',
      NETWORK_ONLINE: '网络恢复',
      DEVICE_OFFLINE: '设备离线',
      DEVICE_ONLINE: '设备上线',
      DEVICE_ADOPTED: '设备接入',
      DEVICE_REMOVED: '设备移除',
      LINK_UP: '链路恢复',
      LINK_DOWN: '链路断开'
    };
    return labels[type] || firstText(event.name, event.message, type.replace(/_/g, ' '), '基础设施事件');
  }

  function formatTimeMachineTime(timestamp, includeDate = false) {
    const value = Number(timestamp);
    const date = new Date(value > 1e12 ? value : value * 1000);
    if (!Number.isFinite(date.getTime())) return '--';
    return new Intl.DateTimeFormat('zh-CN', includeDate
      ? { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }
      : { hour: '2-digit', minute: '2-digit', hour12: false }).format(date);
  }

  function nearestTimeMachineTimestamp(timestamp) {
    const wanted = Number(timestamp) || 0;
    const values = state.topology.timeMachineTimestamps;
    if (!values.length) return wanted;
    return values.reduce((closest, value) => Math.abs(value - wanted) < Math.abs(closest - wanted) ? value : closest, values[0]);
  }

  function renderTopologyTimeMachine() {
    if (!topologyTimeMachine) return;
    const topology = state.topology;
    const visible = topology.view === 'infrastructure' && topology.timeMachineEnabled;
    topologyTimeMachine.hidden = !visible;
    topologyShell?.classList.toggle('is-time-machine-open', visible);
    if (!visible) return;
    const events = topology.timeMachineEvents;
    const timestamps = topology.timeMachineTimestamps;
    const start = topology.timeMachineStart;
    const end = topology.timeMachineEnd;
    const span = Math.max(1, end - start);
    const selected = topology.timeMachineSelectedTimestamp;
    const markers = events.map((event) => {
      const eventTimestamp = Number(event.timestamp || event.at || event.ts) || 0;
      if (!eventTimestamp) return '';
      const snapshotTimestamp = nearestTimeMachineTimestamp(eventTimestamp);
      const position = Math.max(2, Math.min(98, (end - eventTimestamp) / span * 100));
      const active = selected && snapshotTimestamp === selected;
      const title = `${formatTimeMachineTime(eventTimestamp, true)} · ${timeMachineEventLabel(event)}${event.name ? ` · ${event.name}` : ''}`;
      return `<button type="button" class="topology-time-machine-event${active ? ' is-selected' : ''}" style="top:${position.toFixed(2)}%" data-topology-time-event="${snapshotTimestamp}" title="${escapeHtml(title)}" aria-label="${escapeHtml(title)}"><span></span></button>`;
    }).join('');
    const stateText = topology.timeMachineLoading
      ? '正在读取历史记录'
      : topology.timeMachineError
        ? '历史记录暂不可用'
        : `过去 24 小时 (${events.length} 个事件)`;
    topologyTimeMachine.innerHTML = `
      <header class="topology-time-machine-head">
        <strong>${escapeHtml(stateText)}</strong>
        <div class="topology-time-machine-scale" aria-label="时间轴缩放">
          <button type="button" data-topology-time-zoom="out" aria-label="缩小时间轴">-</button>
          <input type="range" min="0" max="1" step="0.05" value="${topology.timeMachineZoom}" data-topology-time-zoom-range aria-label="时间轴缩放">
          <button type="button" data-topology-time-zoom="in" aria-label="放大时间轴">+</button>
        </div>
      </header>
      <div class="topology-time-machine-track">
        <div class="topology-time-machine-ruler" style="--time-machine-zoom:${topology.timeMachineZoom}">
          <button type="button" class="topology-time-machine-live${selected ? '' : ' is-selected'}" data-topology-time-live>实时</button>
          ${topology.timeMachineLoading ? '<span class="topology-time-machine-message">加载中</span>' : ''}
          ${!topology.timeMachineLoading && topology.timeMachineError ? `<span class="topology-time-machine-message">${escapeHtml(topology.timeMachineError)}</span>` : ''}
          ${!topology.timeMachineLoading && !topology.timeMachineError && !timestamps.length ? '<span class="topology-time-machine-message">暂无历史快照</span>' : markers}
          ${selected ? `<time>${escapeHtml(formatTimeMachineTime(selected, true))}</time>` : ''}
        </div>
      </div>`;
  }

  async function loadTopologyTimeMachineSnapshot(timestamp) {
    const target = nearestTimeMachineTimestamp(timestamp);
    if (!target || state.topology.timeMachineLoading) return;
    const loadId = ++state.topology.timeMachineLoadId;
    state.topology.timeMachineLoading = true;
    state.topology.timeMachineError = '';
    renderTopologyTimeMachine();
    const result = await fetchApiResource('topology_infrastructure_history_snapshot', `/api/v1/topology/infrastructure/history/at/${encodeURIComponent(target)}`);
    if (loadId !== state.topology.timeMachineLoadId || !state.topology.timeMachineEnabled) return;
    state.topology.timeMachineLoading = false;
    if (!result.ok) {
      state.topology.timeMachineError = result.error ? result.error.message : '无法读取历史快照';
      renderTopologyTimeMachine();
      return;
    }
    state.topology.timeMachineSelectedTimestamp = target;
    state.topology.timeMachineSnapshot = result.data;
    state.topology.transformSet = false;
    closeTopologyDetail({ skipRender: true });
    renderCurrentTopologyModel();
  }

  function leaveTopologyTimeMachineHistory() {
    state.topology.timeMachineLoadId += 1;
    state.topology.timeMachineLoading = false;
    state.topology.timeMachineSelectedTimestamp = 0;
    state.topology.timeMachineSnapshot = null;
    state.topology.timeMachineError = '';
    state.topology.transformSet = false;
    renderCurrentTopologyModel();
  }

  async function enableTopologyTimeMachine() {
    const now = Date.now();
    const start = now - 24 * 60 * 60 * 1000;
    const loadId = ++state.topology.timeMachineLoadId;
    state.topology.timeMachineLoading = true;
    state.topology.timeMachineError = '';
    state.topology.timeMachineStart = start;
    state.topology.timeMachineEnd = now;
    state.topology.timeMachineEvents = [];
    state.topology.timeMachineTimestamps = [];
    renderTopologyTimeMachine();
    const query = `start=${start}&end=${now}`;
    const [timeline, timestamps] = await Promise.all([
      fetchApiResource('topology_infrastructure_history_timeline', `/api/v1/topology/infrastructure/history/timeline?${query}`),
      fetchApiResource('topology_infrastructure_history_timestamps', `/api/v1/topology/infrastructure/history/timestamps?${query}`)
    ]);
    if (loadId !== state.topology.timeMachineLoadId || !state.topology.timeMachineEnabled) return;
    state.topology.timeMachineLoading = false;
    state.topology.timeMachineEvents = timeline.ok ? timeMachinePayloadList(timeline.data, 'events') : [];
    state.topology.timeMachineTimestamps = timestamps.ok
      ? timeMachinePayloadList(timestamps.data, 'timestamps').map(Number).filter((value) => Number.isFinite(value) && value > 0).sort((a, b) => a - b)
      : [];
    if (!timeline.ok || !timestamps.ok) {
      const error = timeline.error || timestamps.error;
      state.topology.timeMachineError = error && error.status === 404
        ? '后端尚未提供基础设施历史接口'
        : '基础设施历史记录暂不可用';
    }
    renderTopologyTimeMachine();
  }

  function syncTopologyControls() {
    if (!topologyShell) return;
    const topology = state.topology;
    topologyShell.classList.toggle('is-panel-collapsed', topology.panelCollapsed);
    topologyShell.classList.toggle('is-infrastructure-view', topology.view === 'infrastructure');
    topologyShell.classList.toggle('is-pointer-mode', topology.navigationMode === 'pointer');
    topologyShell.classList.toggle('is-clients-hidden', topology.clientsEnabled === false);
    topologyShell.classList.toggle('is-detail-open', topology.detailOpen && Boolean(topology.selectedNodeMac));
    topologyShell.classList.toggle('is-time-machine-open', topology.view === 'infrastructure' && topology.timeMachineEnabled);
    topologyShell.querySelectorAll('[data-topology-view]').forEach((button) => {
      const selected = button.dataset.topologyView === topology.view;
      button.setAttribute('aria-selected', selected ? 'true' : 'false');
      button.tabIndex = selected ? 0 : -1;
    });
    topologyShell.querySelectorAll('[data-topology-action="traffic"]').forEach((control) => {
      if (control.matches('input')) control.checked = topology.trafficEnabled !== false;
      control.setAttribute('aria-pressed', topology.trafficEnabled !== false ? 'true' : 'false');
    });
    topologyShell.querySelectorAll('[data-topology-action="time-machine"]').forEach((control) => {
      if (control.matches('input')) control.checked = topology.timeMachineEnabled;
      control.setAttribute('aria-pressed', topology.timeMachineEnabled ? 'true' : 'false');
    });
    topologyShell.querySelectorAll('[data-topology-action="clients-toggle"]').forEach((control) => {
      if (control.matches('input')) control.checked = topology.clientsEnabled !== false;
      control.setAttribute('aria-pressed', topology.clientsEnabled !== false ? 'true' : 'false');
    });
    topologyShell.querySelectorAll('[data-topology-action="panel-collapse"]').forEach((button) => {
      button.setAttribute('aria-pressed', topology.panelCollapsed ? 'true' : 'false');
      button.setAttribute('aria-label', topology.panelCollapsed ? '展开拓扑控制面板' : '折叠拓扑控制面板');
    });
    topologyShell.querySelectorAll('[data-topology-action="rotate"]').forEach((button) => {
      button.setAttribute('aria-pressed', topology.rotateMap ? 'true' : 'false');
    });
    topologyShell.querySelectorAll('[data-topology-filter]').forEach((control) => {
      const key = control.dataset.topologyFilter;
      control.checked = topology.filters[key] !== false;
    });
    topologyShell.querySelectorAll('[data-topology-label]').forEach((control) => {
      const key = control.dataset.topologyLabel;
      control.checked = topology.labels[key] !== false;
    });
    topologyShell.querySelectorAll('[data-topology-nav]').forEach((button) => {
      button.setAttribute('aria-pressed', button.dataset.topologyNav === topology.navigationMode ? 'true' : 'false');
    });
    topologyShell.querySelectorAll('[data-topology-section]').forEach((section) => {
      const id = section.dataset.topologySection || '';
      const collapsed = Boolean(id && topology.collapsedSections && topology.collapsedSections[id]);
      section.classList.toggle('is-collapsed', collapsed);
      const toggle = section.querySelector('[data-topology-section-toggle]');
      if (toggle) {
        toggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
        toggle.setAttribute('aria-label', `${collapsed ? '展开' : '收起'}${toggle.textContent.trim() || '筛选分组'}`);
      }
    });
    const summary = topologyCountSummary(topologyActiveModel() || {});
    setText('topologyOnlineCount', summary.online ? `(${summary.online})` : '(0)');
    setText('topologyOfflineCount', summary.offline ? `(${summary.offline})` : '(0)');
    setText('topologyWiredCount', summary.wired ? `(${summary.wired})` : '(0)');
    setText('topologyWirelessCount', summary.wireless ? `(${summary.wireless})` : '(0)');
    setText('topologyVlanDefaultCount', summary.vlanDefault ? `(${summary.vlanDefault})` : '(0)');
    renderTopologyTimeMachine();
  }

  function renderCurrentTopologyModel() {
    const renderer = window.DWRT_UNIFI_TOPOLOGY;
    syncTopologyControls();
    if (state.topology.view === 'infrastructure') {
      if (topologyEmpty) topologyEmpty.hidden = true;
      if (topologyContentContainer) topologyContentContainer.hidden = true;
      renderTopologyInfrastructureView();
      syncTopologyControls();
      if (!state.topology.infrastructureData && state.topology.active && !state.topology.loading) fetchTopologyInfrastructureOptional();
      return;
    }
    if (topologyInfrastructureEmpty) topologyInfrastructureEmpty.hidden = true;
    if (topologyContentContainer) topologyContentContainer.hidden = false;
    if (!renderer || !state.topology.lastModel || !renderer.isRenderable(state.topology.lastModel)) return;
    const result = renderer.render(state.topology.lastModel, {
      canvas: topologyCanvas,
      linkLayer: topologyLinkLayer,
      nodeLayer: topologyNodeLayer,
      labelLayer: topologyLabelLayer,
      toggleLayer: topologyToggleLayer,
      zoomContainer: topologyZoomContainer
    }, {
      state: state.topology,
      formatRate
    });
    if (topologyStatus && result.ok) topologyStatus.textContent = '';
    renderTopologyDetailDrawer();
    syncTopologyControls();
    scheduleSelectedTopologyNodeVisible();
  }

  function resetTopologyView() {
    state.topology.transformSet = false;
    if (state.topology.view === 'infrastructure') state.topology.transform = { x: 0, y: 0, k: 1 };
    renderCurrentTopologyModel();
  }

  function setTopologyStatus(message, ttl = 2600) {
    if (!topologyStatus) return;
    topologyStatus.textContent = message || '';
    if (!message || !ttl) return;
    window.clearTimeout(state.topology.statusTimer);
    state.topology.statusTimer = window.setTimeout(() => {
      if (topologyStatus.textContent === message) topologyStatus.textContent = '';
    }, ttl);
  }

  function setTopologyScaleAtCenter(multiplier) {
    if (!topologyCanvas) return;
    const rect = topologyCanvas.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;
    zoomTopologyAt(centerX, centerY, multiplier < 1 ? 1 : -1, multiplier);
  }

	  function clearTopologyFilters() {
	    Object.keys(state.topology.filters).forEach((key) => {
	      state.topology.filters[key] = true;
	    });
    Object.keys(state.topology.labels).forEach((key) => {
      state.topology.labels[key] = true;
    });
    state.topology.trafficEnabled = true;
    state.topology.clientsEnabled = true;
    state.topology.navigationMode = 'hand';
	    renderCurrentTopologyModel();
	  }

	  function toggleTopologyBranch(sourceMac) {
	    const mac = String(sourceMac || '').trim();
	    if (!mac) return;
	    state.topology.collapsedBranches = state.topology.collapsedBranches || {};
	    state.topology.collapsedBranches[mac] = !state.topology.collapsedBranches[mac];
	    if (!state.topology.collapsedBranches[mac]) delete state.topology.collapsedBranches[mac];
	    state.topology.transformSet = false;
	    closeTopologyDetail({ skipRender: true });
	    renderCurrentTopologyModel();
	  }

  async function fetchTopologyFlowOptional() {
    const now = Date.now();
    const cached = state.topology.flowEndpoint;
    const endpoints = cached ? [cached] : TOPOLOGY_FLOW_ENDPOINTS;
    if (!cached && state.topology.flowUnavailableUntil && now < state.topology.flowUnavailableUntil) {
      return { ok: false, skipped: true };
    }
    for (const endpoint of endpoints) {
      const result = await fetchApiResource('topology_flow', endpoint);
      if (result.ok) {
        state.topology.flowEndpoint = endpoint;
        state.topology.flowUnavailableUntil = 0;
        return result;
      }
      if (cached) {
        state.topology.flowEndpoint = '';
        break;
      }
    }
    state.topology.flowUnavailableUntil = Date.now() + 60000;
    return { ok: false };
  }

  function objectValue(value) {
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  }

  function topologyClientRows(payload = {}) {
    const source = Array.isArray(payload) ? payload : unwrapApiData(payload);
    if (Array.isArray(source)) return source;
    for (const key of ['clients', 'users', 'active_users', 'items', 'rows', 'list', 'records', 'data']) {
      const rows = source && source[key];
      if (Array.isArray(rows)) return rows;
    }
    return [];
  }

  function topologyClientImage(client = {}) {
    const shared = window.DWRT_DEVICE_IMAGES;
    if (shared && typeof shared.resolve === 'function') {
      const resolved = shared.resolve(client);
      if (resolved && resolved.src) return resolved.src;
    }
    const fingerprint = objectValue(client.fingerprint);
    return firstText(
      client.custom_image_path,
      client.custom_icon,
      client.override_image,
      client.override_icon,
      client.web_image,
      client.image,
      client.icon,
      client.icon_url,
      client.fingerprint_image,
      fingerprint.custom_image_path,
      fingerprint.image,
      fingerprint.icon
    );
  }

  function topologyBuildClientIndexes(clientsPayload) {
    const byMac = new Map();
    const byIp = new Map();
    topologyClientRows(clientsPayload).forEach((client) => {
      if (!client || typeof client !== 'object') return;
      const mac = firstText(client.mac, client.client_mac, client.hwaddr).toLowerCase();
      const ipValues = [
        client.ip,
        client.ipv4,
        client.ipaddr,
        client.client_ip,
        client.management_ip,
        ...asArray(client.ipv6_addrs),
        ...asArray(client.ipv6_addresses)
      ];
      if (mac && !byMac.has(mac)) byMac.set(mac, client);
      ipValues.forEach((value) => {
        const ip = firstText(value).toLowerCase();
        if (ip && ip !== '0.0.0.0' && !byIp.has(ip)) byIp.set(ip, client);
      });
    });
    return { byMac, byIp };
  }

  function enrichTopologyDataWithClients(topologyData, clientsPayload) {
    if (!topologyData || typeof topologyData !== 'object') return topologyData;
    const vertices = asArray(topologyData.vertices);
    if (!vertices.length) return topologyData;
    const indexes = topologyBuildClientIndexes(clientsPayload);
    if (!indexes.byMac.size && !indexes.byIp.size) return topologyData;
    let changed = false;
    const nextVertices = vertices.map((node) => {
      if (!node || typeof node !== 'object') return node;
      const mac = firstText(node.mac, node.id).toLowerCase();
      const ip = firstText(node.ip, node.ipv4, node.ipaddr, node.client_ip).toLowerCase();
      const client = (mac && indexes.byMac.get(mac)) || (ip && indexes.byIp.get(ip));
      if (!client) return node;
      const clientFingerprint = objectValue(client.fingerprint);
      const nodeFingerprint = objectValue(node.fingerprintData || node.fingerprint);
      const sharedImage = window.DWRT_DEVICE_IMAGES && typeof window.DWRT_DEVICE_IMAGES.resolve === 'function'
        ? window.DWRT_DEVICE_IMAGES.resolve({ ...client, ...node, fingerprint: { ...clientFingerprint, ...nodeFingerprint } }).src
        : '';
      const image = firstText(
        node.custom_image_path,
        node.custom_icon,
        node.override_image,
        node.override_icon,
        node.web_image,
        node.image,
        node.icon,
        node.icon_url,
        node.fingerprint_image,
        nodeFingerprint.custom_image_path,
        nodeFingerprint.image,
        topologyClientImage(client),
        sharedImage
      );
      const mergedFingerprint = {
        ...nodeFingerprint,
        ...clientFingerprint,
        image: firstText(nodeFingerprint.image, clientFingerprint.image, image),
        custom_image_path: firstText(nodeFingerprint.custom_image_path, clientFingerprint.custom_image_path, client.custom_image_path),
        device_type: firstText(nodeFingerprint.device_type, clientFingerprint.device_type, client.device_type, client.type),
        vendor_name: firstText(nodeFingerprint.vendor_name, clientFingerprint.vendor_name, client.vendor_name, client.vendor)
      };
      const next = {
        ...node,
        name: firstText(node.name, client.custom_name, client.nickname, client.name, client.hostname, node.mac),
        display_name: firstText(node.display_name, client.custom_name, client.nickname, client.name, node.display_name),
        hostname: firstText(node.hostname, client.hostname),
        ip: firstText(node.ip, client.ip, client.ipv4, client.ipaddr),
        vendor_name: firstText(node.vendor_name, client.vendor_name, client.vendor, client.manufacturer, client.brand),
        vendor: firstText(node.vendor, client.vendor, client.vendor_name, client.manufacturer, client.brand),
        manufacturer: firstText(node.manufacturer, client.manufacturer, client.vendor_name, client.vendor),
        brand: firstText(node.brand, client.brand, client.vendor_name, client.vendor),
        model: firstText(node.model, client.model, client.device_model, client.device_name),
        device_type: firstText(node.device_type, client.device_type, client.type, client.category),
        custom_image_path: firstText(node.custom_image_path, client.custom_image_path),
        custom_icon: firstText(node.custom_icon, client.custom_icon),
        override_image: firstText(node.override_image, client.override_image),
        override_icon: firstText(node.override_icon, client.override_icon),
        web_image: firstText(node.web_image, client.web_image),
        fingerprint_image: firstText(node.fingerprint_image, client.fingerprint_image, clientFingerprint.image),
        image,
        fingerprintData: mergedFingerprint,
        fingerprint: mergedFingerprint
      };
      changed = true;
      return next;
    });
    return changed ? { ...topologyData, vertices: nextVertices } : topologyData;
  }

  async function fetchTopologyClientsOptional() {
    const now = Date.now();
    if (state.topology.clientsCacheData && now - Number(state.topology.clientsCacheAt || 0) < 30000) {
      return { ok: true, data: state.topology.clientsCacheData, cached: true };
    }
    const result = await fetchApiResource('topology_clients', '/api/v1/clients');
    if (result.ok) {
      state.topology.clientsCacheData = result.data;
      state.topology.clientsCacheAt = now;
    }
    return result;
  }

  window.addEventListener('dwrt:client-image-updated', (event) => {
    const detail = event && event.detail || {};
    const mac = firstText(detail.mac).toLowerCase();
    const src = firstText(detail.src);
    if (!mac || !src) return;
    const rows = topologyClientRows(state.topology.clientsCacheData);
    if (rows.length) {
      state.topology.clientsCacheData = {
        ...objectValue(state.topology.clientsCacheData),
        clients: rows.map((client) => firstText(client.mac, client.client_mac, client.hwaddr).toLowerCase() === mac
          ? { ...client, custom_image_path: src, custom_icon: src, image: src }
          : client)
      };
    }
    if (!state.topology.lastTopologyData) return;
    state.topology.lastTopologyData = enrichTopologyDataWithClients(state.topology.lastTopologyData, state.topology.clientsCacheData);
    if (state.topology.active) renderTopologyFromData(state.topology.lastTopologyData, state.topology.lastFlowData);
  });

  function topologyHasInlineTraffic(payload) {
    const source = unwrapApiData(payload);
    const raw = unwrapApiData(source.topology || source.model || source);
    const hasRate = (item) => {
      if (!item || typeof item !== 'object') return false;
      return firstNumber(
        item.tx,
        item.rx,
        item.up_rate,
        item.down_rate,
        item.tx_rate,
        item.rx_rate,
        item['tx_bytes-r'],
        item['rx_bytes-r'],
        item.traffic && item.traffic.tx,
        item.traffic && item.traffic.rx,
        item.traffic && item.traffic.sum
      ) > 0;
    };
    return asArray(raw.edges).some(hasRate) || asArray(raw.vertices).some(hasRate);
  }

  function renderTopologyFromData(topologyData, flowData = null) {
    const renderer = window.DWRT_UNIFI_TOPOLOGY;
    if (!renderer || typeof renderer.normalize !== 'function' || typeof renderer.render !== 'function') {
      topologyShell?.classList.add('is-locked');
      if (topologyEmpty) topologyEmpty.hidden = false;
      if (topologyStatus) topologyStatus.textContent = '';
      return false;
    }
    const model = renderer.normalize({ topology: topologyData, flow: flowData });
    if (!renderer.isRenderable(model)) {
      if (state.topology.lastModel && renderer.isRenderable(state.topology.lastModel)) {
        topologyShell?.classList.remove('is-locked');
        if (topologyEmpty) topologyEmpty.hidden = true;
        if (topologyStatus) topologyStatus.textContent = '拓扑数据本次刷新为空，已保留上一帧真实拓扑。';
        renderCurrentTopologyModel();
        return false;
      }
      state.topology.lastModel = null;
      topologyShell?.classList.add('is-locked');
      if (topologyEmpty) topologyEmpty.hidden = false;
      if (topologyNodeLayer) topologyNodeLayer.innerHTML = '';
      if (topologyLinkLayer) topologyLinkLayer.innerHTML = '';
      if (topologyLabelLayer) topologyLabelLayer.innerHTML = '';
      if (topologyToggleLayer) topologyToggleLayer.innerHTML = '';
      closeTopologyDetail({ skipRender: true });
      if (topologyStatus) topologyStatus.textContent = '';
      return false;
    }
    topologyShell?.classList.remove('is-locked');
    if (topologyEmpty) topologyEmpty.hidden = true;
    state.topology.lastModel = model;
    renderCurrentTopologyModel();
    if (topologyStatus) topologyStatus.textContent = '';
    scheduleGlassCardsRender(120);
    return true;
  }

  function topologyFlowHasPositiveRate(data) {
    const payload = data && typeof data === 'object' ? data : {};
    const rows = [
      ...asArray(payload.flows),
      ...asArray(payload.wan_totals),
      ...asArray(payload.edges),
      ...asArray(payload.vertices)
    ];
    return rows.some((row) => firstNumber(
      row && row.up_rate,
      row && row.down_rate,
      row && row.tx_rate,
      row && row.rx_rate,
      row && row['tx_bytes-r'],
      row && row['rx_bytes-r'],
      row && row.rate_bytes_per_sec,
      row && row.rate_Bps,
      row && row.rate_bps
    ) > 0);
  }

  function topologyFlowHasExplicitRateSample(data) {
    const payload = data && typeof data === 'object' ? data : {};
    const rows = [
      ...asArray(payload.flows),
      ...asArray(payload.wan_totals),
      ...asArray(payload.edges),
      ...asArray(payload.vertices)
    ];
    return rows.some((row) => row && row.sample_valid !== false && [
      row.up_rate,
      row.down_rate,
      row.tx_rate,
      row.rx_rate,
      row['tx_bytes-r'],
      row['rx_bytes-r'],
      row.rate_bytes_per_sec,
      row.rate_Bps,
      row.rate_bps
    ].some((value) => value !== undefined && value !== null && value !== ''));
  }

  function stableTopologyFlowData(data) {
    if (!data || typeof data !== 'object') return data;
    const now = Date.now();
    if (topologyFlowHasPositiveRate(data)) {
      state.topology.lastNonZeroFlowData = { at: now, data };
      return data;
    }
    if (topologyFlowHasExplicitRateSample(data)) return data;
    const cached = state.topology.lastNonZeroFlowData;
    if (cached && now - cached.at <= 4500) return cached.data;
    return data;
  }

  function flushTopologyFlowRealtime() {
    state.topology.flowFrameTimer = 0;
    if (!state.topology.active || !state.topology.pendingFlowData) return;
    const data = stableTopologyFlowData(state.topology.pendingFlowData);
    state.topology.pendingFlowData = null;
    state.topology.lastFlowData = data;
    state.topology.lastWsAt = Date.now();
    if (!state.topology.lastTopologyData) return;
    renderTopologyFromData(state.topology.lastTopologyData, data);
  }

  function applyTopologyFlowRealtime(data) {
    if (!state.topology.active || !data) return;
    state.topology.pendingFlowData = data;
    if (state.topology.flowFrameTimer) return;
    state.topology.flowFrameTimer = window.setTimeout(flushTopologyFlowRealtime, document.hidden ? 180 : 80);
  }

  function subscribeTopologyRealtime() {
    if (state.topology.wsUnsubscribe || !window.DWRTRealtime || typeof window.DWRTRealtime.subscribe !== 'function') return;
    state.topology.wsUnsubscribe = window.DWRTRealtime.subscribe('topology.flow', applyTopologyFlowRealtime);
  }

  function unsubscribeTopologyRealtime() {
    if (!state.topology.wsUnsubscribe) return;
    state.topology.wsUnsubscribe();
    state.topology.wsUnsubscribe = null;
  }

  function zoomTopologyAt(clientX, clientY, delta, multiplier) {
    const zoomTarget = state.topology.view === 'infrastructure'
      ? topologyInfrastructureEmpty?.querySelector('.topology-infra-zoom-container')
      : topologyZoomContainer;
    if (!topologyCanvas || !zoomTarget) return;
    const rect = topologyCanvas.getBoundingClientRect();
    const current = state.topology.transform;
    const zoomLimits = window.DWRT_UNIFI_TOPOLOGY?.C?.ku || { min: 0.3, max: 2.5 };
    const normalizedDelta = Math.max(-90, Math.min(90, Number(delta) || 0));
    const factor = Number.isFinite(multiplier) ? multiplier : Math.exp(-normalizedDelta * 0.0026);
    const nextK = Math.max(zoomLimits.min, Math.min(zoomLimits.max, current.k * factor));
    if (Math.abs(nextK - current.k) < 0.001) return;
    const originX = clientX - rect.left;
    const originY = clientY - rect.top;
    const worldX = (originX - current.x) / current.k;
    const worldY = (originY - current.y) / current.k;
    topologyCanvas.classList.add('is-zooming');
    window.clearTimeout(state.topology.zoomTimer);
    state.topology.zoomTimer = window.setTimeout(() => {
      topologyCanvas?.classList.remove('is-zooming');
    }, 140);
    state.topology.transform = {
      x: originX - worldX * nextK,
      y: originY - worldY * nextK,
      k: nextK
    };
    state.topology.transformSet = true;
    applyTopologyTransform();
  }

  async function refreshTopology() {
    if (!state.topology.active || state.topology.loading) return;
    state.topology.loading = true;
    if (topologyStatus && !state.topology.lastRenderKey) topologyStatus.textContent = '';
    const topology = await fetchApiResource('topology', TOPOLOGY_ENDPOINT);
    const clients = topology.ok ? await fetchTopologyClientsOptional() : { ok: false, skipped: true, data: state.topology.clientsCacheData };
    const topologyData = topology.ok ? enrichTopologyDataWithClients(topology.data, clients.ok ? clients.data : state.topology.clientsCacheData) : topology.data;
    const wsFresh = state.topology.lastWsAt && Date.now() - state.topology.lastWsAt < TOPOLOGY_REFRESH_MS * 2;
    const flow = topology.ok && !wsFresh && !topologyHasInlineTraffic(topologyData)
      ? await fetchTopologyFlowOptional()
      : { ok: false, skipped: true, data: state.topology.lastFlowData };
    state.topology.loading = false;
    if (!state.topology.active) return;
    if (!topology.ok) {
      state.topology.fallbackReason = topology.error ? topology.error.message : 'topology endpoint unavailable';
      if (state.topology.lastModel) {
        topologyShell?.classList.remove('is-locked');
        if (topologyEmpty) topologyEmpty.hidden = true;
        if (topologyStatus) topologyStatus.textContent = '拓扑接口本次不可用，已保留上一帧真实拓扑。';
        renderCurrentTopologyModel();
      } else {
        topologyShell?.classList.add('is-locked');
        if (topologyEmpty) topologyEmpty.hidden = false;
        if (topologyNodeLayer) topologyNodeLayer.innerHTML = '';
        if (topologyLinkLayer) topologyLinkLayer.innerHTML = '';
        if (topologyLabelLayer) topologyLabelLayer.innerHTML = '';
        if (topologyToggleLayer) topologyToggleLayer.innerHTML = '';
        state.topology.lastModel = null;
        closeTopologyDetail({ skipRender: true });
        if (topologyStatus) topologyStatus.textContent = '';
      }
      return;
    }
    state.topology.lastTopologyData = topologyData;
    if (topologyData && topologyData.infrastructure) state.topology.infrastructureData = topologyData;
    renderTopologyInfrastructureView();
    renderTopologyFromData(topologyData, flow.ok ? flow.data : state.topology.lastFlowData);
    if (!state.topology.infrastructureData || state.topology.view === 'infrastructure') fetchTopologyInfrastructureOptional();
  }

  async function startTopology() {
    if (!topologyWorkspace) return;
    const loadId = ++topologyLoadId;
    state.topology.active = true;
    state.topology.loading = false;
    state.topology.lastModel = null;
    state.topology.lastRenderKey = '';
    state.topology.selectedNodeMac = '';
    state.topology.detailOpen = false;
    state.topology.flowUnavailableUntil = 0;
    state.topology.lastTopologyData = null;
    state.topology.infrastructureData = null;
    state.topology.infrastructureError = '';
    state.topology.timeMachineEnabled = false;
    state.topology.timeMachineLoading = false;
    state.topology.timeMachineError = '';
    state.topology.timeMachineEvents = [];
    state.topology.timeMachineTimestamps = [];
    state.topology.timeMachineSelectedTimestamp = 0;
    state.topology.timeMachineSnapshot = null;
    state.topology.timeMachineLoadId += 1;
    state.topology.lastFlowData = null;
    state.topology.lastNonZeroFlowData = null;
    state.topology.lastWsAt = 0;
    state.topology.pendingFlowData = null;
    state.topology.clientsCacheData = null;
    state.topology.clientsCacheAt = 0;
    window.clearTimeout(state.topology.flowFrameTimer);
    state.topology.flowFrameTimer = 0;
    topologyWorkspace.hidden = false;
    if (routePreview) routePreview.hidden = true;
    appShell?.classList.add('topology-active');
    consoleStage?.classList.add('is-topology');
    topologyShell?.classList.add('is-locked');
    if (topologyStatus) topologyStatus.textContent = '';
    if (topologyEmpty) topologyEmpty.hidden = false;
    if (topologyNodeLayer) topologyNodeLayer.innerHTML = '';
    if (topologyLinkLayer) topologyLinkLayer.innerHTML = '';
    if (topologyLabelLayer) topologyLabelLayer.innerHTML = '';
    if (topologyToggleLayer) topologyToggleLayer.innerHTML = '';
    renderTopologyDetailDrawer();
    syncTopologyControls();
    if (!window.DWRT_UNIFI_TOPOLOGY) {
      if (topologyStatus) topologyStatus.textContent = '正在加载拓扑渲染器';
    }
    try {
      await ensureTopologyRendererLoaded();
    } catch (error) {
      console.warn('[dreamingwrt-web] topology renderer load failed', error);
      if (loadId === topologyLoadId && state.topology.active && topologyStatus) {
        topologyStatus.textContent = '拓扑渲染器加载失败';
      }
      return;
    }
    if (loadId !== topologyLoadId || !state.topology.active) return;
    subscribeTopologyRealtime();
    window.clearInterval(state.topology.timer);
    refreshTopology();
    state.topology.timer = window.setInterval(refreshTopology, TOPOLOGY_REFRESH_MS);
  }

  function stopTopology() {
    topologyLoadId += 1;
    state.topology.active = false;
    unsubscribeTopologyRealtime();
    window.clearInterval(state.topology.timer);
    window.clearTimeout(state.topology.flowFrameTimer);
    state.topology.timer = null;
    state.topology.flowFrameTimer = 0;
    state.topology.pendingFlowData = null;
    state.topology.timeMachineLoadId += 1;
    state.topology.timeMachineLoading = false;
    state.topology.timeMachineEnabled = false;
    state.topology.timeMachineSelectedTimestamp = 0;
    state.topology.timeMachineSnapshot = null;
    renderTopologyTimeMachine();
    if (topologyWorkspace) topologyWorkspace.hidden = true;
    topologyShell?.classList.remove('is-locked');
    closeTopologyDetail({ skipRender: true });
    appShell?.classList.remove('topology-active');
    consoleStage?.classList.remove('is-topology');
  }

  async function startDashboard() {
    const loadId = ++dashboardLoadId;
    const workspace = $('dashboardWorkspace');
    const rail = $('dashboardStatusRail');
    if (workspace) workspace.hidden = false;
    if (rail) rail.hidden = false;
    if (routePreview) routePreview.hidden = true;
    resetPageFooterReserve();
    appShell?.classList.add('dashboard-active');
    consoleStage?.classList.add('is-dashboard');
    try {
      const page = await ensureDashboardPageLoaded();
      if (loadId !== dashboardLoadId) return;
      if (page) page.start();
    } catch (error) {
      console.warn('[dreamingwrt-web] dashboard page load failed', error);
    }
  }

  function stopDashboard(options = {}) {
    dashboardLoadId += 1;
    const page = ensureDashboardPage();
    if (page) {
      page.stop(options);
      return;
    }
    const workspace = $('dashboardWorkspace');
    const rail = $('dashboardStatusRail');
    if (workspace) workspace.hidden = true;
    if (rail) rail.hidden = true;
    if (routePreview && options.showRoutePreview !== false) routePreview.hidden = false;
    appShell?.classList.remove('dashboard-active');
    consoleStage?.classList.remove('is-dashboard');
  }

  function syncFromLocation(options = {}) {
    if (consoleMain && consoleMain.scrollTop) consoleMain.scrollTop = 0;
    const currentHash = window.location.hash || '#/dashboard';
    const cleanHash = cleanRouteHash(currentHash);
    if (cleanHash === '#/ai/assistant' || cleanHash === '#/ai' || cleanHash === '#/ai/') {
      history.replaceState(null, '', '/app/#/dashboard');
      openGlobalAi();
      syncFromLocation(options);
      return;
    }
    if (/^#\/network\/(?:lan-config|wan-config)$/.test(cleanHash)) {
      history.replaceState(null, '', '/app/#/network/global-config');
      syncFromLocation(options);
      return;
    }
    const retiredNetworkRoute = {
      '#/network/firewall': '#/policy-engine/table',
      '#/network/custom-config': '#/policy-engine/objects',
      '#/network/advanced-routing': '#/policy-engine/routes',
      '#/network/flow-control': '#/policy-engine/flow-engine'
    }[cleanHash];
    if (retiredNetworkRoute) {
      history.replaceState(null, '', `/app/${retiredNetworkRoute}`);
      syncFromLocation(options);
      return;
    }
    if (cleanHash === '#/insights' || cleanHash === '#/insights/') {
      history.replaceState(null, '', '/app/#/insights/flows');
      syncFromLocation(options);
      return;
    }
    const dashboardHashRoute = cleanHash === '#/dashboard' || cleanHash.includes('/dashboard');
    const topologyHashRoute = cleanHash.includes('/monitor/topology');
    const lineStatusHashRoute = cleanHash.includes('/monitor/line-status');
    const insightsHomeHashRoute = false;
    const insightsFlowsHashRoute = cleanHash.includes('/insights/flows');
    const insightsActivityHashRoute = cleanHash.includes('/insights/activity');
    const insightsActivitySection = insightsActivityHashRoute ? (cleanHash.match(/#\/insights\/activity\/([^/?#]+)/) || [])[1] || 'overview' : '';
    const monitorDataHashConfig = monitorDataPageConfig(cleanHash);
    const { primary, secondary } = findByHash(cleanHash);
    state.activePrimary = primary ? itemKey(primary) : null;
    state.activeSecondary = secondary ? itemKey(secondary) : null;
    renderPrimary(state.activePrimary);
    renderSecondary(primary, state.activeSecondary);
    const current = secondary || primary || (dashboardHashRoute ? {
      id: 'dashboard',
      func_name: 'dashboard',
      label: '仪表盘',
      path: '/app/#/dashboard'
    } : topologyHashRoute ? {
      id: 'topology',
      func_name: 'topology',
      label: '拓扑图',
      path: '/app/#/monitor/topology'
    } : lineStatusHashRoute ? {
      id: 'line-status',
      func_name: 'line-status',
      label: '线路状态',
      path: '/app/#/monitor/line-status'
    } : insightsHomeHashRoute ? {
      id: 'insights',
      func_name: 'insights',
      label: '洞察',
      path: '/app/#/insights'
    } : insightsFlowsHashRoute ? {
      id: 'insights-flows',
      func_name: 'insights_flows',
      label: '流量',
      path: '/app/#/insights/flows'
    } : insightsActivityHashRoute ? {
      id: 'insights-activity',
      func_name: 'insights_activity',
      label: '活动',
      path: '/app/#/insights/activity'
    } : monitorDataHashConfig ? {
      id: monitorDataHashConfig.id,
      func_name: monitorDataHashConfig.id,
      label: monitorDataHashConfig.label,
      path: `/app/#${monitorDataHashConfig.hash}`
    } : {});
    if (pageEyebrow) pageEyebrow.textContent = primary && secondary ? primary.label : 'Console shell';
    if (pageTitle) pageTitle.textContent = current.label || '控制台';
    const currentPath = itemPath(current);
    const dashboardRoute = dashboardHashRoute || (currentPath || '').includes('#/dashboard') || (itemKey(current) === 'dashboard' && !(current.children || []).length);
    const topologyRoute = topologyHashRoute || (currentPath || '').includes('#/monitor/topology') || itemKey(current) === 'topology';
    const lineStatusRoute = lineStatusHashRoute || (currentPath || '').includes('#/monitor/line-status') || itemKey(current) === 'line-status';
    const clientDetailsRoute = (currentPath || '').includes('#/monitor/client-details') || itemKey(current) === 'client-details' || itemKey(current) === 'client_detail';
    const insightsHomeRoute = insightsHomeHashRoute || itemKey(current) === 'insights';
    const insightsDetailRoute = insightsFlowsHashRoute || insightsActivityHashRoute || itemKey(current) === 'insights-flows' || itemKey(current) === 'insights-activity';
    const insightsRoute = insightsHomeRoute || insightsDetailRoute;
    const currentKey = itemKey(current) || '';
    const logCenterRoute = cleanHash === '#/logs' || cleanHash === '#/logs/' || currentKey === 'log-center';
    const monitorDataConfig = monitorDataPageConfig(currentPath) || monitorDataPageConfig(itemKey(current));
    const routeModuleEntry = routeModuleForItem(current);
    const policyTableRoute = currentKey === 'policy-table' || cleanHash === '#/policy-engine/table';
    const policyStatusRoute = currentKey === 'policy-status' || cleanHash === '#/monitor/policy-status';
    const policyWorkbenchRoute = policyTableRoute || currentKey === 'policy-aegisx' || cleanHash === '#/policy-engine/aegisx'
      || currentKey === 'policy-terminal-groups' || cleanHash === '#/policy-engine/terminal-groups'
      || currentKey === 'policy-routes' || cleanHash === '#/policy-engine/routes'
      || currentKey === 'policy-region' || cleanHash === '#/policy-engine/regions'
      || currentKey === 'policy-object' || cleanHash === '#/policy-engine/objects';
    const globalConfigRoute = currentKey === 'global-config' || cleanHash === '#/network/global-config';
    const networkInterfaceConfigRoute = false;
    const appearanceSettingsRoute = currentKey === 'system-appearance' || cleanHash === '#/system/appearance';
    const systemSettingsRoute = ['system-general', 'system-admin', 'system-users', 'system-notifications', 'system-startup', 'system-crontab', 'system-advanced', 'system-flash', 'storage-mounts'].includes(currentKey)
      || /^#\/system\/(?:general|admin|users|notifications|startup|crontab|advanced|flash)$/.test(cleanHash)
      || cleanHash === '#/storage/mounts';
    const routeSignature = routeContentSignature({
      dashboardRoute,
      topologyRoute,
      lineStatusRoute,
      clientDetailsRoute,
      insightsHomeRoute,
      insightsDetailRoute,
      insightsActivityRoute: insightsActivityHashRoute || itemKey(current) === 'insights-activity',
      insightsActivitySection,
      logCenterRoute,
      monitorDataConfig,
      currentKey,
      currentPath,
      networkInterfaceConfigRoute,
      systemSettingsRoute
    });
    const routeChanged = state.activeRouteSignature !== routeSignature;
    if (pageDescription) {
      pageDescription.textContent = current.slot
        ? '插件本体安装并被 webd/jmxd 汇总到运行时菜单后，才会显示对应入口。未安装的插件不会出现在菜单里。'
        : dashboardRoute
          ? '设备详情卡片读取 webd/jmxd 真实状态；缺失的后端能力会显示为空态，不使用演示数据。'
          : topologyRoute
            ? '拓扑图仅在真实 UniFi 合同可用时显示。'
            : lineStatusRoute
              ? '线路状态页展示真实 WAN 负载、健康与 IPv6 状态。'
              : clientDetailsRoute
                ? '终端详情按旧版信息架构展示在线/离线、IPv6、速率、连接与识别信息。'
                : insightsRoute
                  ? '洞察页按 UniFi Insights / Flows 信息架构展示真实流量、风险、地区与筛选条件。'
              : monitorDataConfig
                ? monitorDataConfig.description
                : routeModuleEntry
                  ? currentKey === 'policy-table'
                    ? '策略表按 UniFi Policy Table 信息架构展示真实策略；筛选在抽屉中打开，不展示假数据。'
                    : currentKey === 'system-general'
                      ? '系统常规页按 luci-app-dreamingwrt 对应页面的信息架构迁移，只替换为当前玻璃材质。'
                    : currentKey === 'system-flash'
                        ? '备份 / 升级页沿用 LuCI 信息架构，并整合特征库更新与当前统一玻璃控件。'
                    : currentKey === 'system-appearance'
                        ? '外观页统一管理主题、壁纸、可读性与动效，并通过固定沙盒即时预览。'
                      : '该页面由原生模块按需加载，未进入页面不会拉取对应资源。'
                  : '当前阶段只显示菜单与路由骨架，不展示假数据。具体页面会按这个菜单顺序逐个迁移。';
    }
    if (options.shellOnly) {
      updateActivePills(false);
      return;
    }
    if (routeChanged) state.activeRouteSignature = routeSignature;
    if (dashboardRoute) {
      if (routeChanged) clearRoutePageState();
      if (routeChanged || !appShell?.classList.contains('dashboard-active')) startDashboard();
    } else if (routeChanged || appShell?.classList.contains('dashboard-active')) {
      stopDashboard({ showRoutePreview: !topologyRoute && !lineStatusRoute && !clientDetailsRoute && !insightsRoute && !logCenterRoute && !monitorDataConfig });
    }
    if (topologyRoute) {
      if (routeChanged) clearRoutePageState();
      if (routeChanged || !state.topology.active) startTopology();
    } else if (state.topology.active) {
      stopTopology();
    }
    consoleStage?.classList.toggle('is-line-status', lineStatusRoute && !dashboardRoute && !topologyRoute);
    consoleStage?.classList.toggle('is-client-details', clientDetailsRoute && !lineStatusRoute && !dashboardRoute && !topologyRoute);
    consoleStage?.classList.toggle('is-insights', insightsRoute && !clientDetailsRoute && !lineStatusRoute && !dashboardRoute && !topologyRoute);
    consoleStage?.classList.toggle('is-log-center', logCenterRoute && !insightsRoute && !clientDetailsRoute && !lineStatusRoute && !dashboardRoute && !topologyRoute);
    consoleStage?.classList.toggle('is-monitor-table', !!monitorDataConfig && !lineStatusRoute && !clientDetailsRoute && !dashboardRoute && !topologyRoute && !logCenterRoute);
    consoleStage?.classList.toggle('is-policy-status', policyStatusRoute && !lineStatusRoute && !clientDetailsRoute && !dashboardRoute && !topologyRoute && !logCenterRoute);
    consoleStage?.classList.toggle('is-policy-table', policyWorkbenchRoute && !lineStatusRoute && !clientDetailsRoute && !dashboardRoute && !topologyRoute && !logCenterRoute && !monitorDataConfig);
    consoleStage?.classList.toggle('is-system-settings', systemSettingsRoute && !lineStatusRoute && !clientDetailsRoute && !dashboardRoute && !topologyRoute && !logCenterRoute && !monitorDataConfig);
    consoleStage?.classList.toggle('is-appearance-settings', appearanceSettingsRoute && !lineStatusRoute && !clientDetailsRoute && !dashboardRoute && !topologyRoute && !logCenterRoute && !monitorDataConfig);
    consoleStage?.classList.toggle('is-global-config', globalConfigRoute && !lineStatusRoute && !clientDetailsRoute && !dashboardRoute && !topologyRoute && !logCenterRoute && !monitorDataConfig);
    consoleStage?.classList.toggle('is-network-interface-config', networkInterfaceConfigRoute && !lineStatusRoute && !clientDetailsRoute && !dashboardRoute && !topologyRoute && !logCenterRoute && !monitorDataConfig);
    if (!dashboardRoute && !topologyRoute) {
      if (!routeChanged) {
        updateActivePills(true);
        window.setTimeout(() => updateActivePills(false), 80);
        window.setTimeout(() => updateActivePills(false), 180);
        window.setTimeout(() => updateActivePills(false), 560);
        settlePageGlassRouteTransition();
        return;
      }
      clearRoutePageState();
      if (lineStatusRoute) renderLineStatusPage();
      else if (clientDetailsRoute) renderClientDetailsPage();
      else if (insightsDetailRoute) renderInsightsFlowsPage(insightsActivityHashRoute || itemKey(current) === 'insights-activity' ? 'activity' : 'flows', insightsActivitySection);
      else if (insightsHomeRoute) renderInsightsHomePage();
      else if (monitorDataConfig) renderMonitorDataPage(monitorDataConfig.id);
      else if (current.availability === 'unavailable' || current.disabled) renderUnavailableRoute(current, currentPath);
      else activateRouteModule(current, currentPath);
    } else if (routeChanged) {
      clearRoutePageState();
    }
    updateActivePills(true);
    window.setTimeout(() => updateActivePills(false), 80);
    window.setTimeout(() => updateActivePills(false), 180);
    window.setTimeout(() => updateActivePills(false), 560);
    scheduleAdaptiveForegroundSample(120);
    settlePageGlassRouteTransition();
  }

  function numberFromTheme(data, keys, fallback) {
    for (const key of keys) {
      if (data && data[key] !== undefined && data[key] !== null && data[key] !== '') {
        const value = Number(data[key]);
        if (Number.isFinite(value)) return value;
      }
    }
    return fallback;
  }

  function cssColorFromTheme(value) {
    const raw = String(value || '').trim();
    const hex = raw.match(/^#([0-9a-f]{8})$/i);
    if (hex) {
      const body = hex[1];
      const alphaFirst = body.slice(0, 2);
      const rgb = body.slice(2);
      const cssRgba = `#${rgb}${alphaFirst}`;
      const cssAlpha = Number.parseInt(body.slice(6), 16);
      const androidAlpha = Number.parseInt(alphaFirst, 16);
      return androidAlpha < cssAlpha ? cssRgba : raw;
    }
    return raw;
  }

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function materialDensityFromLegacyOpacity(value) {
    const legacy = clamp(Number.isFinite(Number(value)) ? Number(value) : 1, 0, 1);
    return 0.025 + legacy * 0.035;
  }

  function setAdaptiveForegroundPreset(mode) {
    const root = document.documentElement;
    const darkInk = {
      '--adaptive-ink': 'rgba(8, 13, 21, 0.98)',
      '--adaptive-text': 'rgba(8, 13, 21, 0.96)',
      '--adaptive-muted': 'rgba(8, 13, 21, 0.88)',
      '--adaptive-faint': 'rgba(8, 13, 21, 0.78)',
      '--adaptive-selected': 'rgba(8, 13, 21, 0.99)',
      '--adaptive-text-shadow': 'none'
    };
    const lightInk = {
      '--adaptive-ink': 'rgba(251, 253, 255, 0.99)',
      '--adaptive-text': 'rgba(251, 253, 255, 0.96)',
      '--adaptive-muted': 'rgba(251, 253, 255, 0.88)',
      '--adaptive-faint': 'rgba(251, 253, 255, 0.78)',
      '--adaptive-selected': 'rgba(251, 253, 255, 0.99)',
      '--adaptive-text-shadow': '0 1px 1px rgba(0, 0, 0, 0.28)'
    };
    const vars = mode === 'dark-ink' ? darkInk : lightInk;
    root.dataset.adaptiveForeground = mode === 'dark-ink' ? 'dark' : 'light';
    Object.entries(vars).forEach(([key, value]) => root.style.setProperty(key, value));
  }

  function applyAdaptiveForeground(luma, contrast = 0) {
    const root = document.documentElement;
    const safeLuma = clamp(Number.isFinite(luma) ? luma : 0.18, 0, 1);
    const density = clamp(state.liquidGlass.vars.neutralDensity ?? APP_LIQUID_GLASS.neutralDensity, 0, 0.35);
    const glassAdjustedLuma = safeLuma * (1 - density);
    const mode = readableForegroundMode(glassAdjustedLuma, root.dataset.adaptiveForeground) === 'dark'
      ? 'dark-ink'
      : 'light-ink';
    root.style.setProperty('--adaptive-bg-luma', safeLuma.toFixed(3));
    root.style.setProperty('--adaptive-effective-luma', glassAdjustedLuma.toFixed(3));
    setAdaptiveForegroundPreset(mode);
    root.toggleAttribute('data-adaptive-mixed', contrast > 0.11);
  }

  function coverDrawArgs(image, viewportW, viewportH) {
    const imageW = image && (image.naturalWidth || image.width) || 1;
    const imageH = image && (image.naturalHeight || image.height) || 1;
    const scale = Math.max(viewportW / imageW, viewportH / imageH);
    const width = imageW * scale;
    const height = imageH * scale;
    return {
      width,
      height,
      x: (viewportW - width) / 2,
      y: (viewportH - height) / 2
    };
  }

  function relativeLumaChannel(value) {
    const channel = value / 255;
    return channel <= 0.04045 ? channel / 12.92 : Math.pow((channel + 0.055) / 1.055, 2.4);
  }

  function integralValue(integral, stride, x0, y0, x1, y1) {
    return integral[y1 * stride + x1]
      - integral[y0 * stride + x1]
      - integral[y1 * stride + x0]
      + integral[y0 * stride + x0];
  }

  function readableForegroundMode(backgroundLuma, previous) {
    const darkInkLuma = 0.004;
    const lightInkLuma = 0.982;
    const darkContrast = (backgroundLuma + 0.05) / (darkInkLuma + 0.05);
    const lightContrast = (lightInkLuma + 0.05) / (backgroundLuma + 0.05);
    if (previous === 'dark' && darkContrast >= 4.5) return 'dark';
    if (previous === 'light' && lightContrast >= 4.5) return 'light';
    return darkContrast >= lightContrast ? 'dark' : 'light';
  }

  function buildAdaptiveForegroundMap(image) {
    if (!image || !(image.complete || image.tagName === 'CANVAS')) return null;
    const viewportW = window.innerWidth || document.documentElement.clientWidth || 1;
    const viewportH = window.innerHeight || document.documentElement.clientHeight || 1;
    const landscape = viewportW >= viewportH;
    const width = landscape ? 160 : clamp(Math.round(160 * viewportW / viewportH), 90, 160);
    const height = landscape ? clamp(Math.round(160 * viewportH / viewportW), 90, 160) : 160;
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) return null;
    const cover = coverDrawArgs(image, viewportW, viewportH);
    const scaleX = width / viewportW;
    const scaleY = height / viewportH;
    ctx.drawImage(
      image,
      cover.x * scaleX,
      cover.y * scaleY,
      cover.width * scaleX,
      cover.height * scaleY
    );
    let pixels;
    try {
      pixels = ctx.getImageData(0, 0, width, height).data;
    } catch (_) {
      return null;
    }
    const stride = width + 1;
    const cells = stride * (height + 1);
    const sum = new Float32Array(cells);
    const sumSq = new Float32Array(cells);
    const dark = new Uint32Array(cells);
    const bright = new Uint32Array(cells);
    for (let y = 1; y <= height; y += 1) {
      let rowSum = 0;
      let rowSumSq = 0;
      let rowDark = 0;
      let rowBright = 0;
      for (let x = 1; x <= width; x += 1) {
        const pixel = ((y - 1) * width + x - 1) * 4;
        const luma = 0.2126 * relativeLumaChannel(pixels[pixel])
          + 0.7152 * relativeLumaChannel(pixels[pixel + 1])
          + 0.0722 * relativeLumaChannel(pixels[pixel + 2]);
        rowSum += luma;
        rowSumSq += luma * luma;
        rowDark += luma < 0.075 ? 1 : 0;
        rowBright += luma > 0.32 ? 1 : 0;
        const at = y * stride + x;
        const above = at - stride;
        sum[at] = sum[above] + rowSum;
        sumSq[at] = sumSq[above] + rowSumSq;
        dark[at] = dark[above] + rowDark;
        bright[at] = bright[above] + rowBright;
      }
    }
    return { source: image, width, height, viewportW, viewportH, stride, sum, sumSq, dark, bright };
  }

  function adaptiveStatsForRects(map, rects) {
    if (!map || !Array.isArray(rects) || !rects.length) return null;
    let count = 0;
    let sum = 0;
    let sumSq = 0;
    let dark = 0;
    let bright = 0;
    rects.forEach((rect) => {
      if (!rect || rect.width <= 0 || rect.height <= 0) return;
      const x0 = clamp(Math.floor(rect.left / map.viewportW * map.width), 0, map.width - 1);
      const y0 = clamp(Math.floor(rect.top / map.viewportH * map.height), 0, map.height - 1);
      const x1 = clamp(Math.ceil(rect.right / map.viewportW * map.width), x0 + 1, map.width);
      const y1 = clamp(Math.ceil(rect.bottom / map.viewportH * map.height), y0 + 1, map.height);
      const rectCount = Math.max(1, (x1 - x0) * (y1 - y0));
      count += rectCount;
      sum += integralValue(map.sum, map.stride, x0, y0, x1, y1);
      sumSq += integralValue(map.sumSq, map.stride, x0, y0, x1, y1);
      dark += integralValue(map.dark, map.stride, x0, y0, x1, y1);
      bright += integralValue(map.bright, map.stride, x0, y0, x1, y1);
    });
    if (!count) return null;
    const mean = sum / count;
    const deviation = Math.sqrt(Math.max(0, sumSq / count - mean * mean));
    const darkRatio = dark / count;
    const brightRatio = bright / count;
    return {
      mean,
      deviation,
      mixed: deviation > 0.11 || (darkRatio > 0.16 && brightRatio > 0.16)
    };
  }

  function adaptiveStatsForRect(map, rect) {
    return adaptiveStatsForRects(map, [rect]);
  }

  const ADAPTIVE_FOREGROUND_DETAIL_SELECTOR = [
    '[data-adaptive-sample]',
    '.rail-card',
    '.rail-throughput-card',
    '.rail-probe',
    '.rail-port',
    '.dashboard-metric-card',
    '.dashboard-monitor-toolbar',
    '.monitor-tile',
    '.dashboard-chart-yaxis',
    '.dashboard-chart-xaxis',
    '.app-track-item',
    '.topology-node',
    '.topology-infra-wan-card',
    '.topology-infra-gateway-card',
    '.topology-infra-port-chip',
    '.dwrt-kit-tabs',
    '.dwrt-kit-tab',
    '.dwrt-kit-table-toolbar',
    '.dwrt-kit-table thead th',
    '.dwrt-kit-table tbody td',
    '.dwrt-kit-sheet-header',
    '.dwrt-kit-sheet-body',
    '.dwrt-kit-sheet-footer',
    '.dwrt-kit-modal',
    '.system-demo-panel',
    '.system-settings-item',
    '.system-preference-item',
    '.system-zram-item',
    '.system-admin-hero-card',
    '.system-admin-credential-well',
    '.system-admin-input-group',
    '.system-admin-policy-tile',
    '.system-admin-status-row',
    '.system-api-row',
    '.system-settings-route-host .system-demo-panel-title',
    '.system-settings-route-host .system-demo-row',
    '.system-settings-route-host .system-advanced-hero-card',
    '.system-settings-route-host .system-advanced-field',
    '.system-settings-route-host .system-advanced-debug-tile',
    '.system-settings-route-host .system-flash-action-card',
    '.system-settings-route-host .system-admin-unit-field',
    '.system-settings-route-host .system-code-page-header',
    '.system-settings-route-host .system-mount-card',
    '.system-settings-route-host .system-signature-header',
    '.system-terminal-navigation',
    '.system-terminal-console-bar',
    '.system-terminal-instance-list > header',
    '.system-terminal-instance-list > div > button',
    '.system-terminal-form > header',
    '.system-terminal-capability',
    '.system-terminal-form-section',
    '.system-terminal-field',
    '.system-terminal-switch-field',
    '.network-interface-toolbar',
    '.network-interface-search',
    '.network-interface-form-section',
    '.network-interface-editor-group > h3',
    '.network-interface-editor-group-body',
    '.network-interface-segmented label > span',
    '.network-interface-dependent',
    '.network-interface-availability',
    '.network-interface-capability-stack fieldset',
    '.network-interface-field',
    '.network-interface-switch-row',
    '.network-interface-port-picker label > span',
    '.network-interface-notice',
    '.global-page-tabs',
    '.global-page-tabs .dwrt-kit-tab',
    '.global-advanced-group > header',
    '.global-settings-section',
    '.global-setting-row',
    '.global-mode-options label',
    '.global-wan-policy-list article',
    '.global-advanced-savebar',
    '.aegisx-tabs',
    '.aegisx-panel',
    '.aegisx-setting-row',
    '.aegisx-setting-label',
    '.aegisx-setting-control',
    '.aegisx-section-header',
    '.aegisx-resource-card',
    '.aegisx-resource-meta > span',
    '.aegisx-domain-block',
    '.aegisx-capability-note',
    '.aegisx-stat-grid article',
    '.aegisx-events-card > header',
    '.aegisx-events-table thead th',
    '.aegisx-events-table tbody td',
    '.aegisx-empty',
    '.aegisx-drawer-intro',
    '.aegisx-drawer-toolbar',
    '.aegisx-country-list > label',
    '.aegisx-honeypot-list article',
    '.aegisx-honeypot-events > span',
    '.aegisx-drawer-field',
    '.aegisx-drawer-body > label',
    '.network-service-page-header',
    '.network-service-settings',
    '.network-service-setting-row',
    '.network-service-field',
    '.network-service-table-card thead',
    '.network-service-table-card tbody tr',
    '.user-auth-web-section > header',
    '.user-auth-web-option',
    '.user-auth-web-field',
    '.user-auth-web-choice',
    '.user-auth-web-range',
    '.user-auth-web-color',
    '.user-auth-web-access > div',
    '.user-auth-web-savebar',
    '.wifi-channel-band',
    '.wifi-unifi-label',
    '.wifi-width-picker',
    '.wifi-width-picker fieldset',
    '.wifi-setting-row',
    '.wifi-inline-setting',
    '.wifi-field',
    '.wifi-management-shell thead',
    '.wifi-management-shell tbody tr',
    '.airview-topbar',
    '.airview-top-actions',
    '.airview-sidebar',
    '.airview-ai-row',
    '.airview-broadcast-select',
    '.airview-ap-select',
    '.airview-range-picker',
    '.airview-range-picker button',
    '.airview-link-actions',
    '.airview-signal-range',
    '.airview-sidebar details',
    '.airview-sidebar summary',
    '.airview-check',
    '.airview-filter-empty',
    '.airview-mini-plan > div',
    '.airview-mini-plan small',
    '.airview-empty',
    '.airview-radio-table',
    '.airview-radio-card',
    '.airview-spectrum-view > header',
    '.airview-spectrum-chart',
    '.airview-spectrum-table thead',
    '.airview-spectrum-table tbody tr',
    '.airview-spectrum-empty',
    '.airview-connectivity-empty',
    '.client-detail-drawer-head',
    '.client-detail-drawer-head > div',
    '.client-detail-drawer-head > div > strong',
    '.client-detail-drawer-head > div > span',
    '.client-detail-hero',
    '.client-detail-identity',
    '.client-detail-tabs',
    '.client-detail-card',
    '.client-detail-meta-item',
    '.client-overview-chart-title',
    '.client-overview-chart',
    '.client-chart-legend',
    '.client-protocol-rate-title',
    '.client-protocol-rate-chart',
    '.client-protocol-chart-legend',
    '.ai-copilot-drawer',
    '.ai-copilot-header',
    '.ai-message',
    '.ai-composer',
    '.ai-drawer-history-toolbar',
    '.ai-history-strip',
    '.ai-settings-heading',
    '.ai-settings-section',
    '.ai-settings-footer',
    '.ai-provider-button',
    '.ai-field',
    '.dp-resource-tabs',
    '.dp-node-toolbar',
    '.dp-node-summary',
    '.dp-node-card',
    '.dp-preview-metrics article',
    '.dp-preview-metrics span',
    '.dp-preview-metrics strong',
    '.dp-preview-metrics small',
    '.dp-preview-meta dt',
    '.dp-preview-meta dd',
    '.dp-preview-section > header',
    '.dp-protocol-list > div',
    '.dp-protocol-list span',
    '.dp-protocol-list strong',
    '.dp-node-samples article',
    '.dp-preview-warnings p'
  ].join(',');

  function expandedAdaptiveRect(rect, padding, viewportW, viewportH) {
    const left = clamp(rect.left - padding, 0, viewportW);
    const top = clamp(rect.top - padding, 0, viewportH);
    const right = clamp(rect.right + padding, left, viewportW);
    const bottom = clamp(rect.bottom + padding, top, viewportH);
    return { left, top, right, bottom, width: right - left, height: bottom - top };
  }

  function adaptiveTextSampleRects(element) {
    if (!(element instanceof HTMLElement)) return [];
    const viewportW = window.innerWidth || document.documentElement.clientWidth || 1;
    const viewportH = window.innerHeight || document.documentElement.clientHeight || 1;
    const rects = [];
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        if (!node.nodeValue || !node.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
        const parent = node.parentElement;
        const nestedTarget = parent && parent.closest(ADAPTIVE_FOREGROUND_DETAIL_SELECTOR);
        if (!parent || (nestedTarget && nestedTarget !== element)) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    let node;
    while ((node = walker.nextNode())) {
      const range = document.createRange();
      range.selectNodeContents(node);
      Array.from(range.getClientRects()).forEach((rect) => {
        if (rect.width > 0 && rect.height > 0) {
          rects.push(expandedAdaptiveRect(rect, 5, viewportW, viewportH));
        }
      });
    }
    const control = element.matches('input, select, textarea')
      ? element
      : element.querySelector(':scope > input, :scope > select, :scope > textarea');
    if (control instanceof HTMLElement) {
      const rect = control.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) {
        const style = getComputedStyle(control);
        const inset = Math.max(4, Number.parseFloat(style.paddingLeft) || 0);
        const sampleWidth = Math.min(rect.width * 0.72, Math.max(72, rect.width - inset - 28));
        rects.push(expandedAdaptiveRect({
          left: rect.left + inset,
          top: rect.top,
          right: rect.left + inset + sampleWidth,
          bottom: rect.bottom,
          width: sampleWidth,
          height: rect.height
        }, 3, viewportW, viewportH));
      }
    }
    return rects;
  }

  function adaptiveStatsForElement(map, element) {
    const textRects = adaptiveTextSampleRects(element);
    return adaptiveStatsForRects(map, textRects.length ? textRects : [element.getBoundingClientRect()]);
  }

  function visibleAdaptiveForegroundTargets(scopeRoot = document) {
    const shellSelector = [
      '.menu-item',
      '.menu-search-trigger',
      '.sidebar-actions',
      '#menuSource',
      '.submenu-heading',
      '.stage-header',
      '.route-preview',
      '.command-panel',
      '.account-card',
      '.console-page-footer',
    ].join(',');
    const pageSurfaceSelector = [
      '.dwrt-kit-modal',
      '.dwrt-kit-sheet',
      '.dwrt-kit-page-surface',
      '.dwrt-kit-table-wrap',
      '.system-settings-route-host',
      '.ai-settings-route-host',
      PAGE_GLASS_SELECTOR
    ].join(',');
    const viewportW = window.innerWidth || document.documentElement.clientWidth || 1;
    const viewportH = window.innerHeight || document.documentElement.clientHeight || 1;
    const maxTargets = viewportW < 760 ? 64 : 120;
    const detailBudget = viewportW < 760 ? 40 : 84;
    const pageSurfaceBudget = viewportW < 760 ? 10 : 20;
    const targets = [];
    const seen = new Set();
    const collect = (selector) => {
      const elements = [];
      if (scopeRoot instanceof Element && scopeRoot.matches(selector)) elements.push(scopeRoot);
      scopeRoot.querySelectorAll(selector).forEach((element) => elements.push(element));
      return elements;
    };
    const appendVisible = (elements, budget = maxTargets) => {
      let added = 0;
      for (const element of elements) {
        if (targets.length >= maxTargets || added >= budget) break;
        if (!(element instanceof HTMLElement) || seen.has(element) || element.closest('[hidden]')) continue;
        const rect = element.getBoundingClientRect();
        if (rect.width < 8 || rect.height < 8
          || rect.right <= 0 || rect.bottom <= 0 || rect.left >= viewportW || rect.top >= viewportH) continue;
        const style = getComputedStyle(element);
        if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) === 0) continue;
        seen.add(element);
        targets.push(element);
        added += 1;
      }
    };
    const detailElements = collect(ADAPTIVE_FOREGROUND_DETAIL_SELECTOR);
    appendVisible(detailElements, detailBudget);
    appendVisible(collect(pageSurfaceSelector), pageSurfaceBudget);
    appendVisible(collect(shellSelector));
    appendVisible(detailElements);
    return targets;
  }

  function clearAdaptiveRegion(element) {
    if (!(element instanceof HTMLElement)) return;
    element.removeAttribute('data-adaptive-region');
    element.removeAttribute('data-adaptive-mixed');
    element.style.removeProperty('--adaptive-region-luma');
  }

  function adaptiveTargetsWithin(node) {
    if (!(node instanceof Element)) return [];
    const targets = [];
    if (node.matches(ADAPTIVE_FOREGROUND_DETAIL_SELECTOR)) targets.push(node);
    node.querySelectorAll(ADAPTIVE_FOREGROUND_DETAIL_SELECTOR).forEach((element) => targets.push(element));
    return targets;
  }

  function adaptiveTransferKey(element) {
    const classes = Array.from(element.classList)
      .filter((name) => name !== 'dwrt-adaptive-foreground-snap')
      .sort()
      .join('.');
    return `${element.tagName.toLowerCase()}|${classes}`;
  }

  function transferAdaptiveRegions(record) {
    if (!record || record.type !== 'childList') return false;
    const removed = Array.from(record.removedNodes).flatMap(adaptiveTargetsWithin);
    const added = Array.from(record.addedNodes).flatMap(adaptiveTargetsWithin);
    if (!removed.length && !added.length) return false;

    const snapshots = new Map();
    removed.forEach((element) => {
      state.liquidGlass.foregroundTargets.delete(element);
      const mode = element.dataset.adaptiveRegion;
      if (!mode) return;
      const key = adaptiveTransferKey(element);
      const bucket = snapshots.get(key) || [];
      bucket.push({
        mode,
        mixed: element.hasAttribute('data-adaptive-mixed'),
        luma: element.style.getPropertyValue('--adaptive-region-luma')
      });
      snapshots.set(key, bucket);
    });

    let needsSample = false;
    added.forEach((element) => {
      const bucket = snapshots.get(adaptiveTransferKey(element));
      const snapshot = bucket && bucket.shift();
      if (!snapshot) {
        needsSample = true;
        return;
      }
      element.dataset.adaptiveRegion = snapshot.mode;
      element.toggleAttribute('data-adaptive-mixed', snapshot.mixed);
      if (snapshot.luma) element.style.setProperty('--adaptive-region-luma', snapshot.luma);
      state.liquidGlass.foregroundModes.set(element, snapshot.mode);
      state.liquidGlass.foregroundTargets.add(element);
    });
    return needsSample;
  }

  function applyAdaptiveRegion(element, stats) {
    if (!element || !stats) return;
    const density = clamp(state.liquidGlass.vars.neutralDensity ?? APP_LIQUID_GLASS.neutralDensity, 0, 0.35);
    let effectiveLuma = stats.mean * (1 - density);
    if (element.matches('.menu-item.active')) effectiveLuma = effectiveLuma * 0.88 + 0.12;
    const previous = state.liquidGlass.foregroundModes.get(element);
    const mode = readableForegroundMode(effectiveLuma, previous);
    if (previous && previous !== mode) {
      element.classList.add('dwrt-adaptive-foreground-snap');
      requestAnimationFrame(() => requestAnimationFrame(() => {
        if (element.isConnected) element.classList.remove('dwrt-adaptive-foreground-snap');
      }));
    }
    if (previous !== mode || element.dataset.adaptiveRegion !== mode) {
      state.liquidGlass.foregroundModes.set(element, mode);
      element.dataset.adaptiveRegion = mode;
    }
    if (element.hasAttribute('data-adaptive-mixed') !== stats.mixed) {
      element.toggleAttribute('data-adaptive-mixed', stats.mixed);
    }
    const lumaText = effectiveLuma.toFixed(3);
    if (element.style.getPropertyValue('--adaptive-region-luma') !== lumaText) {
      element.style.setProperty('--adaptive-region-luma', lumaText);
    }
  }

  function sampleImageForeground(image, scopeRoot = document) {
    if (!image || !(image.complete || image.tagName === 'CANVAS')) return false;
    const viewportW = window.innerWidth || document.documentElement.clientWidth || 1;
    const viewportH = window.innerHeight || document.documentElement.clientHeight || 1;
    const cached = state.liquidGlass.foregroundMap;
    const map = cached
      && cached.source === image
      && cached.viewportW === viewportW
      && cached.viewportH === viewportH
      ? cached
      : buildAdaptiveForegroundMap(image);
    if (!map) return false;
    state.liquidGlass.foregroundMap = map;
    const whole = adaptiveStatsForRect(map, {
      left: 0,
      top: 0,
      right: map.viewportW,
      bottom: map.viewportH,
      width: map.viewportW,
      height: map.viewportH
    });
    if (whole) applyAdaptiveForeground(whole.mean, whole.deviation);
    const targets = visibleAdaptiveForegroundTargets(scopeRoot);
    const targetSet = new Set(targets);
    state.liquidGlass.foregroundTargets.forEach((element) => {
      const inScope = scopeRoot === document || element === scopeRoot || scopeRoot.contains(element);
      if (inScope && !targetSet.has(element)) {
        clearAdaptiveRegion(element);
        state.liquidGlass.foregroundTargets.delete(element);
      }
    });
    targets.forEach((element) => applyAdaptiveRegion(element, adaptiveStatsForElement(map, element)));
    targets.forEach((element) => state.liquidGlass.foregroundTargets.add(element));
    return true;
  }

  function scheduleAdaptiveForegroundSample(delay = 0, scopeRoot = document) {
    window.clearTimeout(state.liquidGlass.foregroundTimer);
    if (state.liquidGlass.foregroundIdle && typeof window.cancelIdleCallback === 'function') {
      window.cancelIdleCallback(state.liquidGlass.foregroundIdle);
    }
    state.liquidGlass.foregroundIdle = 0;
    state.liquidGlass.foregroundTimer = window.setTimeout(() => {
      const run = () => {
        state.liquidGlass.foregroundIdle = 0;
        if (sampleImageForeground(state.liquidGlass.image || appWallpaper, scopeRoot)) return;
        const targets = scopeRoot === document
          ? document.querySelectorAll('[data-adaptive-region]')
          : scopeRoot.querySelectorAll('[data-adaptive-region]');
        targets.forEach(clearAdaptiveRegion);
        if (scopeRoot === document) state.liquidGlass.foregroundTargets.clear();
        setAdaptiveForegroundPreset(document.documentElement.dataset.themeResolved === 'light' ? 'dark-ink' : 'light-ink');
      };
      if (typeof window.requestIdleCallback === 'function') {
        state.liquidGlass.foregroundIdle = window.requestIdleCallback(run, { timeout: 180 });
      } else {
        requestAnimationFrame(run);
      }
    }, delay);
  }

  const PAGE_GLASS_SELECTOR = [
    '.dwrt-glass-card',
    '.dwrt-kit-tabs',
    '.dashboard-segmented',
    '.topology-panel-tabs',
    '.topology-property-tabs',
    '.object-target-tabs',
    '.client-filter-tabs',
    '.client-connection-options-tabs',
    '.dwrt-kit-glass-surface',
    // Pages that adopted the shared Kit surface contract instead of the legacy glass class
    // must still participate in page-level sampling, otherwise their text stays unreadable.
    '[data-dwrt-surface="stable-glass"]',
    '[data-dwrt-surface="dense-surface"]',
    '.dwrt-kit-overview-card',
    '.system-demo-panel',
    '.client-stable-glass',
    '.policy-stable-glass',
    '.insights-stable-glass',
    '.topology-control-panel',
    '.account-card'
  ].join(',');

  const PAGE_GLASS_EXCLUDE = [
    '#appMenuGlass',
    '.route-workspace',
    '.route-preview',
    '.console-stage',
    '.console-main',
    '.dashboard-main-panel',
    '.topology-shell',
    '.topology-canvas',
    '.topology-workspace',
    '.dwrt-kit-sheet-overlay'
  ].join(',');

  const PAGE_GLASS_SCOPES = ['main', 'rail', 'overlay'];
  const PAGE_GLASS_TRANSIENT_SELECTOR = [
    '.dashboard-chart-tooltip',
    '.line-status-tooltip',
    '#dwrtKitTooltip',
    '[role="tooltip"]'
  ].join(',');

  function pageGlassScopeForElement(element) {
    if (!(element instanceof Element)) return 'main';
    if (PAGE_GLASS_SCOPES.includes(element.dataset?.pageGlassScope)) return element.dataset.pageGlassScope;
    if (element.closest('#dashboardStatusRail')) return 'rail';
    if (element.closest('#consoleMain')) return 'main';
    return 'overlay';
  }

  function clearLegacyGlassCanvases() {
    if (state.liquidGlass.legacyCanvasesCleared) return;
    state.liquidGlass.legacyCanvasesCleared = true;
    document.querySelectorAll('.dwrt-glass-canvas').forEach((canvas) => {
      canvas.parentElement?.classList.remove('canvas-ready');
      const gl = canvas.__dwrtGlassGl || null;
      const ext = gl && gl.getExtension && gl.getExtension('WEBGL_lose_context');
      if (ext && ext.loseContext) {
        try { ext.loseContext(); } catch (_) {}
      }
      try { canvas.__dwrtGlassRenderer?.destroy?.(); } catch (_) {}
      canvas.remove();
    });
  }

  function visiblePageGlassCandidates(scopeKey = '') {
    const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 1;
    const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 1;
    const visible = Array.from(document.querySelectorAll(PAGE_GLASS_SELECTOR)).filter((card) => {
      if (!(card instanceof HTMLElement) || card.matches(PAGE_GLASS_EXCLUDE) || card.closest('[hidden]')) return false;
      const style = getComputedStyle(card);
      if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) === 0) return false;
      const rect = card.getBoundingClientRect();
      return rect.width >= 96 && rect.height >= 54
        && rect.right > 0 && rect.bottom > 0 && rect.left < viewportWidth && rect.top < viewportHeight;
    });
    const visibleSet = new Set(visible);
    return visible.filter((card) => {
      const parent = card.parentElement?.closest(PAGE_GLASS_SELECTOR);
      return (!parent || !visibleSet.has(parent))
        && (!scopeKey || pageGlassScopeForElement(card) === scopeKey);
    });
  }

  function clearPageGlassCard(card) {
    card.classList.remove('dwrt-page-glass-surface', 'dwrt-page-liquid-glass', 'dwrt-shared-glass-cutout', 'canvas-ready');
    card.removeAttribute('data-page-glass');
    card.removeAttribute('data-glass-renderer');
    card.removeAttribute('data-page-glass-scope');
    card.style.removeProperty('--dwrt-shared-glass-radius');
  }

  function pageGlassOptions() {
    return {
      ...state.liquidGlass.menuOptions,
      cornerRadius: 0,
      mapResolution: MENU_LIQUID_GLASS.mapResolution,
      trackMotion: false,
      trackScroll: false
    };
  }

  function ensurePageGlassScope(scopeKey) {
    const existing = state.liquidGlass.pageScopes.get(scopeKey);
    if (existing?.renderer && existing.sampler?.isConnected) return existing;
    const factory = window.DWRTSampledLiquidGlass;
    if (!factory || typeof factory.create !== 'function' || !appWallpaper) return null;
    const sampler = document.createElement('div');
    sampler.className = `page-glass-shared-sampler page-glass-shared-sampler--${scopeKey}`;
    sampler.id = `pageGlass${scopeKey[0].toUpperCase()}${scopeKey.slice(1)}Sampler`;
    sampler.dataset.pageGlassScope = scopeKey;
    sampler.setAttribute('aria-hidden', 'true');
    appMenuGlass?.before(sampler);
    sampler.addEventListener('dwrt:sampled-glass-ready', () => {
      appShell.classList.add('page-glass-ready');
    });
    const renderer = factory.create({
      root: sampler,
      backgroundElement: appWallpaper,
      backgroundSrc: appWallpaper.currentSrc || appWallpaper.getAttribute('src') || '',
      options: pageGlassOptions()
    });
    const scope = {
      key: scopeKey,
      sampler,
      renderer,
      signature: '',
      displacementMapLabel: '',
      mapRequestToken: 0,
      mapTimer: 0,
      mapSettlePending: false,
      materialVersion: -1,
      reconcileCount: 0
    };
    state.liquidGlass.pageScopes.set(scopeKey, scope);
    return scope;
  }

  function pageGlassGeometry(cards) {
    const viewportWidth = Math.max(1, Math.round(window.innerWidth || document.documentElement.clientWidth || 1));
    const viewportHeight = Math.max(1, Math.round(window.innerHeight || document.documentElement.clientHeight || 1));
    const viewportRects = cards.map((card) => {
      const rect = card.getBoundingClientRect();
      const style = window.getComputedStyle(card);
      const radius = clamp(Number.parseFloat(style.borderTopLeftRadius) || Number.parseFloat(style.borderRadius) || 0, 0, 80);
      const x = clamp(rect.left, 0, viewportWidth);
      const y = clamp(rect.top, 0, viewportHeight);
      const right = clamp(rect.right, 0, viewportWidth);
      const bottom = clamp(rect.bottom, 0, viewportHeight);
      card.style.setProperty('--dwrt-shared-glass-radius', `${radius}px`);
      if (right <= x || bottom <= y) return null;
      return { x, y, width: right - x, height: bottom - y, radius };
    }).filter(Boolean);
    if (!viewportRects.length) return { x: 0, y: 0, width: 1, height: 1, rects: [] };
    const left = Math.floor(Math.min(...viewportRects.map((rect) => rect.x)));
    const top = Math.floor(Math.min(...viewportRects.map((rect) => rect.y)));
    const right = Math.ceil(Math.max(...viewportRects.map((rect) => rect.x + rect.width)));
    const bottom = Math.ceil(Math.max(...viewportRects.map((rect) => rect.y + rect.height)));
    return {
      x: left,
      y: top,
      width: Math.max(1, right - left),
      height: Math.max(1, bottom - top),
      rects: viewportRects.map((rect) => ({ ...rect, x: rect.x - left, y: rect.y - top }))
    };
  }

  function pageGlassMask(geometry) {
    const { width, height, rects } = geometry;
    const markup = rects.map((rect) =>
      `<rect x="${rect.x.toFixed(2)}" y="${rect.y.toFixed(2)}" width="${rect.width.toFixed(2)}" height="${rect.height.toFixed(2)}" rx="${Math.min(rect.radius, rect.width / 2, rect.height / 2).toFixed(2)}" fill="white"/>`
    ).join('');
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">${markup}</svg>`;
    return `url("data:image/svg+xml,${encodeURIComponent(svg)}")`;
  }

  function pageGlassFragment(x, y) {
    const ix = x - 0.5;
    const iy = y - 0.5;
    const radius = 0.6;
    const qx = Math.abs(ix) - 0.3 + radius;
    const qy = Math.abs(iy) - 0.2 + radius;
    const distance = Math.min(Math.max(qx, qy), 0) + Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) - radius;
    const smooth = (a, b, value) => {
      const t = clamp((value - a) / (b - a), 0, 1);
      return t * t * (3 - 2 * t);
    };
    const displacement = smooth(0.8, 0, distance - 0.15);
    const scale = smooth(0, 1, displacement);
    return { x: ix * scale + 0.5, y: iy * scale + 0.5 };
  }

  function trimPageGlassMapCache() {
    if (PAGE_GLASS_MAP_CACHE.size <= 8) return;
    const activeLabels = new Set(Array.from(state.liquidGlass.pageScopes.values())
      .map((scope) => scope.displacementMapLabel)
      .filter(Boolean));
    for (const [signature, entry] of PAGE_GLASS_MAP_CACHE) {
      if (PAGE_GLASS_MAP_CACHE.size <= 8) break;
      if (!entry?.url || activeLabels.has(signature)) continue;
      PAGE_GLASS_MAP_CACHE.delete(signature);
      URL.revokeObjectURL(entry.url);
    }
  }

  function finishPageGlassMapWorkerRequests(result) {
    for (const request of pageGlassMapWorkerRequests.values()) {
      window.clearTimeout(request.timer);
      request.resolve(result);
    }
    pageGlassMapWorkerRequests.clear();
  }

  function disablePageGlassMapWorker(worker) {
    if (worker && pageGlassMapWorker !== worker) return;
    pageGlassMapWorker?.terminate();
    pageGlassMapWorker = null;
    pageGlassMapWorkerDisabled = true;
    finishPageGlassMapWorkerRequests(null);
  }

  function stopPageGlassMapWorker() {
    pageGlassMapWorker?.terminate();
    pageGlassMapWorker = null;
    finishPageGlassMapWorkerRequests(PAGE_GLASS_MAP_CANCELLED);
  }

  function ensurePageGlassMapWorker() {
    if (pageGlassMapWorker) return pageGlassMapWorker;
    if (pageGlassMapWorkerDisabled || typeof window.Worker !== 'function') return null;
    try {
      const worker = new Worker(PAGE_GLASS_MAP_WORKER_URL);
      worker.addEventListener('message', (event) => {
        if (pageGlassMapWorker !== worker) return;
        const message = event.data || {};
        const request = pageGlassMapWorkerRequests.get(Number(message.id));
        if (!request || request.signature !== String(message.signature || '')) return;
        pageGlassMapWorkerRequests.delete(Number(message.id));
        window.clearTimeout(request.timer);
        if (message.error || !(message.blob instanceof Blob)) {
          request.resolve(null);
          disablePageGlassMapWorker(worker);
          return;
        }
        appShell.dataset.pageGlassMapExecution = 'worker';
        request.resolve(message.blob);
      });
      worker.addEventListener('error', (event) => {
        event.preventDefault?.();
        disablePageGlassMapWorker(worker);
      });
      worker.addEventListener('messageerror', () => disablePageGlassMapWorker(worker));
      pageGlassMapWorker = worker;
      return worker;
    } catch (_) {
      pageGlassMapWorkerDisabled = true;
      return null;
    }
  }

  function requestPageGlassMapBlob(mapWidth, mapHeight, scaledRects, signature) {
    const worker = ensurePageGlassMapWorker();
    if (!worker) return Promise.resolve(null);
    const id = ++pageGlassMapWorkerRequestId;
    return new Promise((resolve) => {
      const timer = window.setTimeout(() => {
        if (!pageGlassMapWorkerRequests.has(id)) return;
        pageGlassMapWorkerRequests.delete(id);
        resolve(null);
        disablePageGlassMapWorker(worker);
      }, PAGE_GLASS_MAP_WORKER_TIMEOUT_MS);
      pageGlassMapWorkerRequests.set(id, { resolve, signature, timer });
      try {
        worker.postMessage({ id, mapWidth, mapHeight, scaledRects, signature });
      } catch (_) {
        pageGlassMapWorkerRequests.delete(id);
        window.clearTimeout(timer);
        resolve(null);
        disablePageGlassMapWorker(worker);
      }
    });
  }

  function pageGlassMapBlobFallback(mapWidth, mapHeight, scaledRects) {
    appShell.dataset.pageGlassMapExecution = 'main-thread-fallback';
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    if (!context) return Promise.resolve(null);
    canvas.width = mapWidth;
    canvas.height = mapHeight;
    const vectors = new Float32Array(mapWidth * mapHeight * 2);
    let maxScale = 1;
    scaledRects.forEach((rect) => {
      const startX = Math.max(0, Math.floor(rect.x));
      const startY = Math.max(0, Math.floor(rect.y));
      const endX = Math.min(mapWidth, Math.ceil(rect.x + rect.width));
      const endY = Math.min(mapHeight, Math.ceil(rect.y + rect.height));
      for (let y = startY; y < endY; y += 1) {
        for (let x = startX; x < endX; x += 1) {
          const localX = x - rect.x;
          const localY = y - rect.y;
          const position = pageGlassFragment(localX / rect.width, localY / rect.height);
          const edgeDistance = Math.min(localX, localY, rect.width - localX - 1, rect.height - localY - 1);
          const seamFactor = Math.min(1, Math.max(0, edgeDistance) / 2);
          const normalizedEdge = Math.max(0, edgeDistance) / Math.max(1, Math.min(rect.width, rect.height));
          const centerT = clamp((normalizedEdge - 0.035) / (0.24 - 0.035), 0, 1);
          const centerFactor = 1 - centerT * centerT * (3 - 2 * centerT);
          const dx = (position.x * rect.width - localX) * seamFactor * centerFactor;
          const dy = (position.y * rect.height - localY) * seamFactor * centerFactor;
          const index = (y * mapWidth + x) * 2;
          vectors[index] = dx;
          vectors[index + 1] = dy;
          maxScale = Math.max(maxScale, Math.abs(dx), Math.abs(dy));
        }
      }
    });
    const image = context.createImageData(mapWidth, mapHeight);
    for (let pixel = 0; pixel < mapWidth * mapHeight; pixel += 1) {
      const vector = pixel * 2;
      const target = pixel * 4;
      image.data[target] = clamp((vectors[vector] / maxScale + 0.5) * 255, 0, 255);
      image.data[target + 1] = clamp((vectors[vector + 1] / maxScale + 0.5) * 255, 0, 255);
      image.data[target + 2] = image.data[target + 1];
      image.data[target + 3] = 255;
    }
    context.putImageData(image, 0, 0);
    return new Promise((resolve) => canvas.toBlob(resolve, 'image/png'));
  }

  function pageGlassDisplacementMap(geometry) {
    const resolution = MENU_LIQUID_GLASS.mapResolution;
    const mapWidth = Math.max(1, Math.round(geometry.width * resolution));
    const mapHeight = Math.max(1, Math.round(geometry.height * resolution));
    const scaledRects = geometry.rects.map((rect) => ({
      x: rect.x * resolution,
      y: rect.y * resolution,
      width: Math.max(1, rect.width * resolution),
      height: Math.max(1, rect.height * resolution)
    }));
    const signature = `${mapWidth}x${mapHeight}:` + scaledRects
      .map((rect) => [rect.x, rect.y, rect.width, rect.height].map((value) => Math.round(value * 2) / 2).join(','))
      .join(';');
    const cached = PAGE_GLASS_MAP_CACHE.get(signature);
    if (cached) {
      PAGE_GLASS_MAP_CACHE.delete(signature);
      PAGE_GLASS_MAP_CACHE.set(signature, cached);
      return cached.promise;
    }

    const entry = { url: '', promise: null };
    entry.promise = requestPageGlassMapBlob(mapWidth, mapHeight, scaledRects, signature)
      .then((blob) => {
        if (blob === PAGE_GLASS_MAP_CANCELLED) return blob;
        return blob || pageGlassMapBlobFallback(mapWidth, mapHeight, scaledRects);
      })
      .then((blob) => {
        if (!blob || blob === PAGE_GLASS_MAP_CANCELLED) {
          PAGE_GLASS_MAP_CACHE.delete(signature);
          return { url: '', label: signature };
        }
        entry.url = URL.createObjectURL(blob);
        return { url: entry.url, label: signature };
      });
    PAGE_GLASS_MAP_CACHE.set(signature, entry);
    return entry.promise;
  }

  function schedulePageGlassDisplacementMap(scope, geometry, signature) {
    const mapRequestToken = ++scope.mapRequestToken;
    const routeToken = state.liquidGlass.pageRouteToken;
    window.clearTimeout(scope.mapTimer);
    scope.mapTimer = window.setTimeout(() => {
      scope.mapTimer = 0;
      if (scope.mapRequestToken !== mapRequestToken || scope.signature !== signature
          || state.liquidGlass.pageRouteToken !== routeToken || !scope.sampler.isConnected) {
        finishPageGlassMapSettle(scope);
        return;
      }
      pageGlassDisplacementMap(geometry).then((displacementMap) => {
        if (scope.mapRequestToken !== mapRequestToken || scope.signature !== signature
            || state.liquidGlass.pageRouteToken !== routeToken || !scope.sampler.isConnected) {
          trimPageGlassMapCache();
          finishPageGlassMapSettle(scope);
          return;
        }
        if (displacementMap.url && typeof scope.renderer.setDisplacementMap === 'function') {
          scope.renderer.setDisplacementMap(displacementMap.url, displacementMap.label);
          scope.displacementMapLabel = displacementMap.label;
        }
        trimPageGlassMapCache();
        finishPageGlassMapSettle(scope);
      });
    }, 0);
  }

  // 路由过渡收尾时,几何/遮罩已更新但位移图还在异步生成:若此刻就摘掉过渡类,
  // 采样器会先按旧位移图光栅一次、图到后再光栅一次(两次 200-300ms 的主线程
  // 渲染停顿)。将过渡类的移除推迟到所有 scope 的位移图应用完毕,合并为一次光栅。
  function finishPageGlassMapSettle(scope) {
    if (scope) scope.mapSettlePending = false;
    releasePageGlassRouteTransition();
  }

  function releasePageGlassRouteTransition(force = false) {
    const release = state.liquidGlass.pendingTransitionRelease;
    if (!release) return;
    if (release.token !== state.liquidGlass.pageRouteToken) {
      state.liquidGlass.pendingTransitionRelease = null;
      return;
    }
    if (!force) {
      for (const scope of state.liquidGlass.pageScopes.values()) {
        if (scope.mapSettlePending) return;
      }
    }
    window.clearTimeout(release.timer);
    state.liquidGlass.pendingTransitionRelease = null;
    state.liquidGlass.pageRouteTransition = false;
    appShell.classList.remove('page-glass-route-transition');
    PAGE_GLASS_SCOPES.forEach((scopeKey) => setPageGlassScopeInteracting(scopeKey, false));
  }

  function cancelPageGlassIdleWork() {
    if (state.liquidGlass.pageIdleHandle) {
      if (state.liquidGlass.pageIdleHandleType === 'idle' && typeof window.cancelIdleCallback === 'function') {
        window.cancelIdleCallback(state.liquidGlass.pageIdleHandle);
      } else {
        window.clearTimeout(state.liquidGlass.pageIdleHandle);
      }
    }
    state.liquidGlass.pageIdleHandle = 0;
    state.liquidGlass.pageIdleHandleType = '';
  }

  function normalizePageGlassScopes(scopes) {
    if (!scopes) return PAGE_GLASS_SCOPES;
    const values = typeof scopes === 'string' ? [scopes] : Array.from(scopes);
    return values.filter((scope) => PAGE_GLASS_SCOPES.includes(scope));
  }

  function markPageGlassScopesPending(scopes) {
    normalizePageGlassScopes(scopes).forEach((scope) => state.liquidGlass.pagePendingScopes.add(scope));
  }

  function setPageGlassScopeInteracting(scope, interacting) {
    appShell.classList.toggle(`page-glass-${scope}-interacting`, Boolean(interacting));
    state.liquidGlass.pageScopes.get(scope)?.sampler.classList.toggle('is-scroll-tracking', Boolean(interacting));
  }

  function finishPageGlassReconcile(routeToken = 0) {
    state.liquidGlass.raf = 0;
    if (routeToken && routeToken !== state.liquidGlass.pageRouteToken) return;
    const scopes = state.liquidGlass.pagePendingScopes.size
      ? Array.from(state.liquidGlass.pagePendingScopes)
      : PAGE_GLASS_SCOPES;
    state.liquidGlass.pagePendingScopes.clear();
    reconcilePageGlassRenderers(scopes);
    scopes.forEach((scope) => {
      if (!state.liquidGlass.pageScrollTimers.has(scope)) setPageGlassScopeInteracting(scope, false);
    });
    if (routeToken && routeToken === state.liquidGlass.pageRouteToken) {
      let mapPending = false;
      for (const scope of state.liquidGlass.pageScopes.values()) {
        if (scope.mapSettlePending) { mapPending = true; break; }
      }
      if (state.liquidGlass.pendingTransitionRelease?.timer) {
        window.clearTimeout(state.liquidGlass.pendingTransitionRelease.timer);
      }
      const release = { token: routeToken, timer: 0 };
      state.liquidGlass.pendingTransitionRelease = release;
      if (mapPending) {
        release.timer = window.setTimeout(() => releasePageGlassRouteTransition(true), 400);
      } else {
        releasePageGlassRouteTransition(true);
      }
    }
  }

  function queuePageGlassIdleReconcile(scopes, routeToken = 0) {
    markPageGlassScopesPending(scopes);
    cancelPageGlassIdleWork();
    const run = () => {
      state.liquidGlass.pageIdleHandle = 0;
      state.liquidGlass.pageIdleHandleType = '';
      if (routeToken && routeToken !== state.liquidGlass.pageRouteToken) return;
      if (!state.liquidGlass.raf) {
        state.liquidGlass.raf = requestAnimationFrame(() => finishPageGlassReconcile(routeToken));
      }
    };
    if (typeof window.requestIdleCallback === 'function') {
      state.liquidGlass.pageIdleHandleType = 'idle';
      state.liquidGlass.pageIdleHandle = window.requestIdleCallback(run, { timeout: 700 });
    } else {
      state.liquidGlass.pageIdleHandleType = 'timeout';
      state.liquidGlass.pageIdleHandle = window.setTimeout(run, 48);
    }
  }

  function pageGlassScopesAffectedByScroll(event) {
    const target = event?.target;
    if (!target || target === document || target === window || target === document.documentElement
        || target === document.body || target === document.scrollingElement || target === window.visualViewport) {
      return PAGE_GLASS_SCOPES;
    }
    if (!(target instanceof Element) || target.closest(PAGE_GLASS_TRANSIENT_SELECTOR)) return [];
    if (target.closest('#primaryMenu, #secondaryMenu, #bottomMenu, #dashboardStatusRail')) return [];
    if (target.closest(PAGE_GLASS_SELECTOR)) return [];
    const scopes = new Set();
    visiblePageGlassCandidates().forEach((card) => {
      if (target.contains(card)) scopes.add(pageGlassScopeForElement(card));
    });
    return Array.from(scopes);
  }

  function setPageGlassScrolling(event) {
    const scopes = pageGlassScopesAffectedByScroll(event);
    if (!scopes.length) return;
    scopes.forEach((scope) => {
      setPageGlassScopeInteracting(scope, true);
      const previous = state.liquidGlass.pageScrollTimers.get(scope);
      if (previous) window.clearTimeout(previous);
      const timer = window.setTimeout(() => {
        state.liquidGlass.pageScrollTimers.delete(scope);
        queuePageGlassIdleReconcile([scope]);
      }, 180);
      state.liquidGlass.pageScrollTimers.set(scope, timer);
    });
    cancelPageGlassIdleWork();
    if (state.liquidGlass.raf) {
      cancelAnimationFrame(state.liquidGlass.raf);
      state.liquidGlass.raf = 0;
    }
  }

  function pageGlassGeometrySignature(geometry) {
    return `${geometry.x},${geometry.y},${geometry.width},${geometry.height}:` + geometry.rects
      .map((rect) => [rect.x, rect.y, rect.width, rect.height, rect.radius]
        .map((value) => Math.round(value * 2) / 2).join(','))
      .join(';');
  }

  function syncPageGlassCardResizeObservation(candidates) {
    if (!state.liquidGlass.pageResizeObserver && typeof ResizeObserver !== 'undefined') {
      state.liquidGlass.pageResizeObserver = new ResizeObserver((entries) => {
        const scopes = new Set();
        entries.forEach((entry) => {
          if (entry.target instanceof Element && entry.target.isConnected) {
            scopes.add(pageGlassScopeForElement(entry.target));
          }
        });
        if (scopes.size && !state.liquidGlass.pageReconciling) scheduleGlassCardsRender(80, scopes);
      });
    }
    const observer = state.liquidGlass.pageResizeObserver;
    if (!observer) return;
    const next = new Set(candidates);
    state.liquidGlass.pageObservedCards.forEach((card) => {
      if (!next.has(card)) observer.unobserve(card);
    });
    next.forEach((card) => {
      if (!state.liquidGlass.pageObservedCards.has(card)) observer.observe(card);
    });
    state.liquidGlass.pageObservedCards = next;
  }

  function reconcilePageGlassRenderers(requestedScopes = PAGE_GLASS_SCOPES) {
    if (state.liquidGlass.pageReconciling || !appWallpaper) return;
    state.liquidGlass.pageReconciling = true;
    try {
      clearLegacyGlassCanvases();
      const scopes = normalizePageGlassScopes(requestedScopes);
      const allCandidates = visiblePageGlassCandidates();
      const candidateSet = new Set(allCandidates);
      const canSample = Boolean(
        !window.matchMedia?.('(prefers-reduced-transparency: reduce)').matches &&
        !window.matchMedia?.('(forced-colors: active)').matches &&
        appWallpaper.complete && appWallpaper.naturalWidth &&
        state.liquidGlass.image
      );
      document.querySelectorAll('.dwrt-page-glass-surface').forEach((card) => {
        const scope = card.dataset.pageGlassScope || pageGlassScopeForElement(card);
        if (scopes.includes(scope) && !candidateSet.has(card)) clearPageGlassCard(card);
      });
      scopes.forEach((scopeKey) => {
        const candidates = allCandidates.filter((card) => pageGlassScopeForElement(card) === scopeKey);
        const scope = canSample && candidates.length ? ensurePageGlassScope(scopeKey) : state.liquidGlass.pageScopes.get(scopeKey);
        if (scope) {
          scope.reconcileCount += 1;
          scope.sampler.dataset.glassReconcileCount = String(scope.reconcileCount);
        }
        candidates.forEach((card) => {
          card.classList.add('dwrt-page-glass-surface');
          card.dataset.pageGlassScope = scopeKey;
          if (!scope || !canSample) {
            card.classList.remove('dwrt-page-liquid-glass', 'dwrt-shared-glass-cutout', 'canvas-ready');
            card.dataset.pageGlass = 'fallback';
            card.removeAttribute('data-glass-renderer');
            return;
          }
          card.classList.add('dwrt-page-liquid-glass', 'dwrt-shared-glass-cutout');
          card.classList.remove('canvas-ready');
          card.dataset.pageGlass = 'sampled';
          card.dataset.glassRenderer = `shared-svg-explicit-sampling:${scopeKey}`;
        });
        if (!scope) return;
        if (!canSample || !candidates.length) {
          scope.mapRequestToken += 1;
          window.clearTimeout(scope.mapTimer);
          scope.mapTimer = 0;
          scope.sampler.hidden = true;
          scope.signature = '';
          scope.mapSettlePending = false;
          return;
        }
        if (scope.materialVersion !== state.liquidGlass.materialVersion) {
          scope.renderer.update(pageGlassOptions());
          scope.materialVersion = state.liquidGlass.materialVersion;
        }
        const src = appWallpaper.currentSrc || appWallpaper.getAttribute('src') || '';
        if (src && scope.sampler.dataset.backgroundSrc !== src) scope.renderer.setBackground(appWallpaper, src);
        const geometry = pageGlassGeometry(candidates);
        const signature = pageGlassGeometrySignature(geometry);
        if (scope.signature !== signature) {
          Object.assign(scope.sampler.style, {
            left: `${geometry.x}px`,
            top: `${geometry.y}px`,
            width: `${geometry.width}px`,
            height: `${geometry.height}px`
          });
          const mask = pageGlassMask(geometry);
          scope.sampler.style.maskImage = mask;
          scope.sampler.style.webkitMaskImage = mask;
          scope.renderer.measure?.();
          scope.signature = signature;
          scope.mapSettlePending = state.liquidGlass.pageRouteTransition;
          schedulePageGlassDisplacementMap(scope, geometry, signature);
        }
        scope.sampler.hidden = false;
      });
      syncPageGlassCardResizeObservation(allCandidates);
      appShell.dataset.pageGlassSurfaceCount = String(allCandidates.length);
      appShell.dataset.pageGlassSampledCount = String(canSample ? allCandidates.length : 0);
      appShell.dataset.pageGlassRenderer = canSample && allCandidates.length
        ? 'scoped-shared-svg-explicit-sampling'
        : 'scoped-shared-css-stable-fallback';
    } finally {
      state.liquidGlass.pageReconciling = false;
    }
  }

  function scheduleGlassCardsRender(duration = 0, scopes) {
    markPageGlassScopesPending(scopes);
    if (state.liquidGlass.pageRouteTransition) return;
    const scheduleFrame = () => {
      if (!state.liquidGlass.raf) state.liquidGlass.raf = requestAnimationFrame(() => finishPageGlassReconcile());
    };
    window.clearTimeout(state.liquidGlass.settleTimer);
    cancelPageGlassIdleWork();
    if (duration && state.liquidGlass.raf) {
      cancelAnimationFrame(state.liquidGlass.raf);
      state.liquidGlass.raf = 0;
    }
    if (!duration) {
      scheduleFrame();
      return;
    }
    state.liquidGlass.settleTimer = window.setTimeout(() => {
      state.liquidGlass.settleTimer = 0;
      queuePageGlassIdleReconcile(scopes);
    }, Math.min(420, Math.max(80, duration)));
  }

  function beginPageGlassRouteTransition(restart = false) {
    if (!appShell) return 0;
    if (state.liquidGlass.pageRouteTransition && !restart) return state.liquidGlass.pageRouteToken;
    const token = ++state.liquidGlass.pageRouteToken;
    state.liquidGlass.pageScopes.forEach((scope) => {
      scope.mapRequestToken += 1;
      window.clearTimeout(scope.mapTimer);
      scope.mapTimer = 0;
      scope.mapSettlePending = false;
    });
    if (state.liquidGlass.pendingTransitionRelease) {
      window.clearTimeout(state.liquidGlass.pendingTransitionRelease.timer);
      state.liquidGlass.pendingTransitionRelease = null;
    }
    state.liquidGlass.pageRouteTransition = true;
    state.liquidGlass.pageRouteStartedAt = performance.now();
    appShell.classList.add('page-glass-route-transition');
    cancelPageGlassIdleWork();
    window.clearTimeout(state.liquidGlass.settleTimer);
    window.clearTimeout(state.liquidGlass.pageRouteTimer);
    if (state.liquidGlass.raf) cancelAnimationFrame(state.liquidGlass.raf);
    state.liquidGlass.raf = 0;
    state.liquidGlass.pageScrollTimers.forEach((timer) => window.clearTimeout(timer));
    state.liquidGlass.pageScrollTimers.clear();
    PAGE_GLASS_SCOPES.forEach((scope) => setPageGlassScopeInteracting(scope, false));
    markPageGlassScopesPending(PAGE_GLASS_SCOPES);
    return token;
  }

  function settlePageGlassRouteTransition(token = state.liquidGlass.pageRouteToken) {
    if (!state.liquidGlass.pageRouteTransition || token !== state.liquidGlass.pageRouteToken) return;
    window.clearTimeout(state.liquidGlass.pageRouteTimer);
    requestAnimationFrame(() => requestAnimationFrame(() => {
      if (token !== state.liquidGlass.pageRouteToken) return;
      window.clearTimeout(state.liquidGlass.pageRouteTimer);
      const elapsed = performance.now() - state.liquidGlass.pageRouteStartedAt;
      // 采样器 SVG filter 重光栅是一次 200-300ms 的主线程渲染停顿(实测 LoAF)。
      // 把它推迟到菜单动画(520ms clip-path)结束之后:切换动画期间停留在
      // backdrop-filter 回退材质上(流畅),连续快速切换时每次点击都会重置
      // token,重光栅被一路顺延,直到用户停下来才发生一次。
      state.liquidGlass.pageRouteTimer = window.setTimeout(() => {
        state.liquidGlass.pageRouteTimer = 0;
        queuePageGlassIdleReconcile(PAGE_GLASS_SCOPES, token);
      }, Math.max(96, 560 - elapsed));
    }));
  }

  function initPageGlassObserver() {
    if (state.liquidGlass.pageObserver || typeof MutationObserver === 'undefined' || !appShell) return;
    const isTrackedGlassSurface = (node) => node instanceof Element && node.matches(PAGE_GLASS_SELECTOR);
    const containsGlassSurface = (node) => node instanceof Element && (
      isTrackedGlassSurface(node)
      || Array.from(node.querySelectorAll(PAGE_GLASS_SELECTOR)).some(isTrackedGlassSurface)
    );
    const isTransientRecord = (record) => {
      if (record.target instanceof Element && record.target.closest(PAGE_GLASS_TRANSIENT_SELECTOR)) return true;
      const changed = [...Array.from(record.addedNodes || []), ...Array.from(record.removedNodes || [])]
        .filter((node) => node instanceof Element);
      return changed.length > 0 && changed.every((node) => node.matches(PAGE_GLASS_TRANSIENT_SELECTOR));
    };
    state.liquidGlass.pageObserver = new MutationObserver((records) => {
      let needsForegroundSample = false;
      records.forEach((record) => {
        if (isTransientRecord(record)) return;
        if (transferAdaptiveRegions(record)) needsForegroundSample = true;
      });
      const changedScopes = new Set();
      records.forEach((record) => {
        if (isTransientRecord(record)) return;
        if (record.type === 'attributes') {
          const target = record.target;
          if (containsGlassSurface(target)) changedScopes.add(pageGlassScopeForElement(target));
          return;
        }
        const changed = [...Array.from(record.addedNodes), ...Array.from(record.removedNodes)]
          .filter(containsGlassSurface);
        if (changed.length) changedScopes.add(pageGlassScopeForElement(record.target));
      });
      if (changedScopes.size) {
        scheduleGlassCardsRender(80, changedScopes);
        if (state.liquidGlass.pageRouteTransition) settlePageGlassRouteTransition();
        needsForegroundSample = true;
      }
      if (needsForegroundSample) {
        scheduleAdaptiveForegroundSample(120);
      }
    });
    state.liquidGlass.pageObserver.observe(appShell, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['hidden']
    });
  }

  function loadGlassImage(url) {
    if (!url || url === state.liquidGlass.imageUrl) {
      scheduleGlassCardsRender(0);
      scheduleAdaptiveForegroundSample(0);
      return;
    }
    state.liquidGlass.imageUrl = url;
    state.liquidGlass.foregroundMap = null;
    const image = new Image();
    image.decoding = 'async';
    image.crossOrigin = 'anonymous';
    image.onload = () => {
      state.liquidGlass.image = image;
      state.liquidGlass.foregroundMap = null;
      scheduleAdaptiveForegroundSample(0);
      scheduleGlassCardsRender(1200);
    };
    image.onerror = () => {
      if (image.crossOrigin) {
        image.crossOrigin = '';
        image.src = url;
        return;
      }
      setAdaptiveForegroundPreset(document.documentElement.dataset.themeResolved === 'light' ? 'dark-ink' : 'light-ink');
    };
    image.src = url;
  }

  function menuGlassOptions(source = {}) {
    const data = source && typeof source === 'object' ? source : {};
    const modes = new Set(['shader', 'standard', 'prominent', 'polar']);
    const mode = modes.has(String(data.mode || '')) ? String(data.mode) : MENU_LIQUID_GLASS.mode;
    return {
      mode,
      displacementScale: clamp(Number(data.displacement_scale ?? data.displacementScale ?? MENU_LIQUID_GLASS.displacementScale), 0, 180),
      baseBlur: clamp(Number(data.base_blur ?? data.baseBlur ?? state.liquidGlass.vars.baseBlur ?? MENU_LIQUID_GLASS.baseBlur), 0, 16),
      blurAmount: 0,
      saturation: clamp(Number(data.saturation ?? MENU_LIQUID_GLASS.saturation), 70, 220),
      aberrationIntensity: clamp(Number(data.aberration_intensity ?? data.aberrationIntensity ?? MENU_LIQUID_GLASS.aberrationIntensity), 0, 8),
      neutralDensity: clamp(Number(data.neutral_density ?? data.neutralDensity ?? state.liquidGlass.vars.neutralDensity ?? MENU_LIQUID_GLASS.neutralDensity), 0.025, 0.18),
      neutralColor: String(data.neutral_color ?? data.neutralColor ?? state.liquidGlass.vars.neutralColor ?? MENU_LIQUID_GLASS.neutralColor),
      borderWidth: clamp(Number(data.border_width ?? data.borderWidth ?? state.liquidGlass.vars.borderWidth ?? MENU_LIQUID_GLASS.borderWidth), 0, 2),
      borderColor: cssColorFromTheme(data.border_color ?? data.borderColor ?? state.liquidGlass.vars.borderColor ?? MENU_LIQUID_GLASS.borderColor),
      highlight: clamp(Number(data.highlight ?? state.liquidGlass.vars.highlight ?? MENU_LIQUID_GLASS.highlight), 0, 0.65),
      cornerRadius: 0,
      overLight: false,
      highlightAngle: clamp(Number(data.highlight_angle ?? data.highlightAngle ?? MENU_LIQUID_GLASS.highlightAngle), 0, 360),
      preserveCenter: data.preserve_center ?? data.preserveCenter ?? MENU_LIQUID_GLASS.preserveCenter,
      mapResolution: MENU_LIQUID_GLASS.mapResolution,
      trackMotion: MENU_LIQUID_GLASS.trackMotion,
      trackScroll: MENU_LIQUID_GLASS.trackScroll
    };
  }

  function ensureMenuGlassRenderer() {
    if (state.liquidGlass.menuRenderer || !appMenuGlass || !appWallpaper) return state.liquidGlass.menuRenderer;
    const factory = window.DWRTSampledLiquidGlass;
    if (!factory || typeof factory.create !== 'function') return null;
    const src = appWallpaper.currentSrc || appWallpaper.getAttribute('src') || '';
    state.liquidGlass.menuRenderer = factory.create({
      root: appMenuGlass,
      backgroundElement: appWallpaper,
      backgroundSrc: src,
      options: state.liquidGlass.menuOptions
    });
    return state.liquidGlass.menuRenderer;
  }

  function applyMenuGlassOptions(source = {}) {
    const options = menuGlassOptions(source);
    state.liquidGlass.menuOptions = options;
    state.liquidGlass.vars = {
      ...state.liquidGlass.vars,
      baseBlur: options.baseBlur,
      neutralDensity: options.neutralDensity,
      neutralColor: options.neutralColor,
      saturation: options.saturation,
      displacementScale: options.displacementScale,
      aberrationIntensity: options.aberrationIntensity,
      borderWidth: options.borderWidth,
      borderColor: options.borderColor,
      highlight: options.highlight,
      highlightAngle: options.highlightAngle,
      preserveCenter: options.preserveCenter
    };
    document.documentElement.style.setProperty('--dwrt-glass-base-blur', `${options.baseBlur}px`);
    document.documentElement.style.setProperty('--dwrt-glass-neutral-density', `${options.neutralDensity}`);
    document.documentElement.style.setProperty('--dwrt-glass-neutral-color', options.neutralColor);
    document.documentElement.style.setProperty('--dwrt-glass-saturation', `${options.saturation}%`);
    document.documentElement.style.setProperty('--dwrt-glass-highlight-strength', `${options.highlight}`);
    document.documentElement.style.setProperty('--lg-highlight', `${options.highlight}`);
    document.documentElement.style.setProperty('--lg-border-width', `${options.borderWidth}px`);
    document.documentElement.style.setProperty('--lg-border-color', options.borderColor);
    document.documentElement.style.setProperty('--menu-glass-rim-angle', `${options.highlightAngle}deg`);
    state.liquidGlass.materialVersion += 1;
    const renderer = ensureMenuGlassRenderer();
    if (renderer) renderer.update(options);
    scheduleGlassCardsRender(120);
  }

  function appearanceAccentColor(value) {
    const raw = String(value || '').trim();
    if (/^#[0-9a-f]{6}$/i.test(raw)) return raw;
    return {
      violet: '#AF52DE', blue: '#007AFF', emerald: '#34C759', rose: '#FF2D55', amber: '#FF9500',
      indigo: '#5856D6', cyan: '#0891B2', teal: '#0F766E', slate: '#475569'
    }[raw] || '';
  }

  function currentAppearancePreviewValue() {
    const options = state.liquidGlass.menuOptions || MENU_LIQUID_GLASS;
    return {
      material_glass: {
        mode: options.mode,
        base_blur: options.baseBlur,
        neutral_density: options.neutralDensity,
        neutral_color: options.neutralColor,
        saturation: options.saturation,
        displacement_scale: options.displacementScale,
        aberration_intensity: options.aberrationIntensity,
        border_width: options.borderWidth,
        border_color: options.borderColor,
        highlight: options.highlight,
        highlight_angle: options.highlightAngle,
        preserve_center: options.preserveCenter
      },
      accent_color: document.documentElement.style.getPropertyValue('--app-accent').trim(),
      wallpaper: { url: appWallpaper?.currentSrc || appWallpaper?.getAttribute('src') || '' },
      animation_level: document.documentElement.dataset.animationLevel || 'balanced'
    };
  }

  function applyAppearancePreview(detail = {}) {
    if (detail.material_glass) applyMenuGlassOptions(detail.material_glass);
    if (Object.prototype.hasOwnProperty.call(detail, 'accent_color')) {
      const accent = appearanceAccentColor(detail.accent_color);
      if (accent) document.documentElement.style.setProperty('--app-accent', accent);
      else document.documentElement.style.removeProperty('--app-accent');
    }
    if (detail.wallpaper?.url) setAppWallpaper(detail.wallpaper.url);
    if (detail.animation_level) document.documentElement.dataset.animationLevel = detail.animation_level;
    scheduleAdaptiveForegroundSample(0);
  }

  function handleAppearancePreview(event) {
    const detail = event.detail || {};
    const action = detail.action || 'preview';
    if (action === 'rollback') {
      if (state.liquidGlass.appearancePreviewBaseline) applyAppearancePreview(state.liquidGlass.appearancePreviewBaseline);
      state.liquidGlass.appearancePreviewBaseline = null;
      return;
    }
    if (!state.liquidGlass.appearancePreviewBaseline) state.liquidGlass.appearancePreviewBaseline = currentAppearancePreviewValue();
    applyAppearancePreview(detail);
    if (action === 'commit') {
      const committed = currentAppearancePreviewValue();
      if (detail.wallpaper?.url) committed.wallpaper.url = detail.wallpaper.url;
      state.liquidGlass.appearancePreviewBaseline = committed;
    }
  }

  function setAppWallpaper(url) {
    if (!appWallpaper || !url) return;
    const current = appWallpaper.currentSrc || appWallpaper.getAttribute('src') || '';
    const sync = () => {
      const src = appWallpaper.currentSrc || appWallpaper.getAttribute('src') || url;
      const renderer = ensureMenuGlassRenderer();
      if (renderer) renderer.setBackground(appWallpaper, src);
      loadGlassImage(src);
    };
    if (current === url && appWallpaper.complete && appWallpaper.naturalWidth) {
      sync();
      return;
    }
    appWallpaper.addEventListener('load', sync, { once: true });
    appWallpaper.src = url;
  }

  function applyTheme(data) {
    const material = data && data.material_glass && typeof data.material_glass === 'object'
      ? data.material_glass
      : null;
    if (material) {
      const accent = appearanceAccentColor(data.accent_color);
      if (accent) document.documentElement.style.setProperty('--app-accent', accent);
      const options = menuGlassOptions(material);
      state.liquidGlass.vars = {
        ...state.liquidGlass.vars,
        blurRadius: options.baseBlur,
        opacity: options.neutralDensity,
        baseBlur: options.baseBlur,
        neutralDensity: options.neutralDensity,
        neutralColor: options.neutralColor,
        saturation: options.saturation,
        displacementScale: options.displacementScale,
        aberrationIntensity: options.aberrationIntensity,
        borderWidth: options.borderWidth,
        borderColor: options.borderColor,
        highlight: options.highlight,
        highlightAngle: options.highlightAngle,
        preserveCenter: options.preserveCenter
      };
      document.documentElement.style.setProperty('--lg-blur-radius', `${options.baseBlur}px`);
      document.documentElement.style.setProperty('--lg-glass-opacity', '1');
      applyMenuGlassOptions(material);
      const images = Array.isArray(data.images) ? data.images.filter(Boolean) : [];
      const selected = data.selected && data.selected.url;
      if (appWallpaper && (selected || images[0])) setAppWallpaper(selected || images[0]);
      else if (appWallpaper) setAppWallpaper(appWallpaper.getAttribute('src') || '/static/background/dwrt-default-bg.jpg');
      return;
    }
    const source = data && data.liquid_glass ? { ...data, ...data.liquid_glass } : (data || {});
    const rawOpacity = numberFromTheme(source, ['login_glass_opacity', 'glass_opacity', 'opacity'], 1);
    const legacyBlur = numberFromTheme(source, ['login_glass_blur', 'glass_blur', 'blur_radius'], APP_LIQUID_GLASS.blurRadius);
    const vars = {
      cornerRadius: numberFromTheme(source, ['login_glass_corner_radius', 'glass_corner_radius', 'corner_radius'], APP_LIQUID_GLASS.cornerRadius),
      blurRadius: legacyBlur,
      baseBlur: clamp(3.2 + (legacyBlur - 6) * 0.08, 2.4, 6),
      refractionOffset: numberFromTheme(source, ['login_glass_refraction_offset', 'refraction_offset'], APP_LIQUID_GLASS.refractionOffset),
      refractionHeight: numberFromTheme(source, ['login_glass_refraction_height', 'refraction_height'], APP_LIQUID_GLASS.refractionHeight),
      borderWidth: numberFromTheme(source, ['login_glass_border_width', 'border_width'], APP_LIQUID_GLASS.borderWidth),
      opacity: clamp(rawOpacity, 0, 1),
      neutralDensity: materialDensityFromLegacyOpacity(rawOpacity),
      neutralColor: APP_LIQUID_GLASS.neutralColor,
      highlight: numberFromTheme(source, ['login_glass_highlight', 'highlight_strength', 'highlight'], APP_LIQUID_GLASS.highlight),
      borderColor: cssColorFromTheme(source.login_glass_border_color || source.border_color || APP_LIQUID_GLASS.borderColor),
      edgeIntensity: numberFromTheme(source, ['login_glass_edge_intensity', 'edge_intensity'], APP_LIQUID_GLASS.edgeIntensity),
      rimIntensity: numberFromTheme(source, ['login_glass_rim_intensity', 'rim_intensity'], APP_LIQUID_GLASS.rimIntensity),
      baseIntensity: numberFromTheme(source, ['login_glass_base_intensity', 'base_intensity'], APP_LIQUID_GLASS.baseIntensity),
      edgeDistance: numberFromTheme(source, ['login_glass_edge_distance', 'edge_distance'], APP_LIQUID_GLASS.edgeDistance),
      rimDistance: numberFromTheme(source, ['login_glass_rim_distance', 'rim_distance'], APP_LIQUID_GLASS.rimDistance),
      baseDistance: numberFromTheme(source, ['login_glass_base_distance', 'base_distance'], APP_LIQUID_GLASS.baseDistance),
      cornerBoost: numberFromTheme(source, ['login_glass_corner_boost', 'corner_boost'], APP_LIQUID_GLASS.cornerBoost),
      rippleEffect: numberFromTheme(source, ['login_glass_ripple_effect', 'ripple_effect'], APP_LIQUID_GLASS.rippleEffect),
      tintOpacity: numberFromTheme(source, ['login_glass_tint_opacity', 'tint_opacity'], APP_LIQUID_GLASS.tintOpacity),
      warp: numberFromTheme(source, ['login_glass_warp', 'warp'], APP_LIQUID_GLASS.warp ? 1 : 0) > 0.5
    };
    state.liquidGlass.vars = vars;
    document.documentElement.style.setProperty('--lg-corner-radius', `${vars.cornerRadius}px`);
    document.documentElement.style.setProperty('--lg-blur-radius', `${vars.blurRadius}px`);
    document.documentElement.style.setProperty('--lg-refraction-offset', `${vars.refractionOffset}px`);
    document.documentElement.style.setProperty('--lg-refraction-height', `${vars.refractionHeight}px`);
    document.documentElement.style.setProperty('--lg-border-width', `${vars.borderWidth}px`);
    document.documentElement.style.setProperty('--lg-glass-opacity', `${vars.opacity}`);
    document.documentElement.style.setProperty('--dwrt-glass-base-blur', `${vars.baseBlur}px`);
    document.documentElement.style.setProperty('--dwrt-glass-neutral-density', `${vars.neutralDensity}`);
    document.documentElement.style.setProperty('--lg-highlight', `${vars.highlight}`);
    document.documentElement.style.setProperty('--lg-border-color', vars.borderColor);
    const menuGlass = data && (data.menu_liquid_glass || data.menu_glass);
    applyMenuGlassOptions(menuGlass || {});
    const images = Array.isArray(data && data.images) ? data.images.filter(Boolean) : [];
    const selected = data && data.selected && data.selected.url;
    if (appWallpaper && (selected || images[0])) {
      const url = selected || images[0];
      setAppWallpaper(url);
    } else if (appWallpaper) {
      setAppWallpaper(appWallpaper.getAttribute('src') || '/static/background/dwrt-default-bg.jpg');
    }
  }

  function setThemePreference(pref) {
    const next = pref || 'system';
    const resolved = next === 'dark' || (next === 'system' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
    document.documentElement.dataset.themePref = next;
    document.documentElement.dataset.themeResolved = resolved;
    setAdaptiveForegroundPreset(resolved === 'light' ? 'dark-ink' : 'light-ink');
    scheduleAdaptiveForegroundSample(80);
    document.documentElement.classList.toggle('theme-night', resolved === 'dark');
    document.documentElement.classList.add('theme-switching');
    document.body?.classList.toggle('theme-night', resolved === 'dark');
    document.body?.classList.add('theme-switching');
    window.clearTimeout(setThemePreference.timer);
    setThemePreference.timer = window.setTimeout(() => {
      document.documentElement.classList.remove('theme-switching');
      document.body?.classList.remove('theme-switching');
    }, 520);
    if (themeButton) {
      themeButton.dataset.themePref = next;
      themeButton.title = next === 'dark' ? '深色' : next === 'light' ? '浅色' : '跟随系统';
      themeButton.setAttribute('aria-label', themeButton.title);
      themeButton.innerHTML = next === 'dark'
        ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3a6 6 0 0 0 9 7.7A9 9 0 1 1 12 3Z"/></svg>'
        : next === 'light'
          ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>'
          : 'A';
    }
    try {
      localStorage.setItem('dreamingwrt.web.themePref', next);
    } catch (_) {}
  }

  function cycleThemePreference() {
    const current = themeButton?.dataset.themePref || document.documentElement.dataset.themePref || 'system';
    setThemePreference(current === 'system' ? 'light' : current === 'light' ? 'dark' : 'system');
  }

  function positionAccountPopover() {
    if (!userButton || !accountPopover || accountPopover.hidden) return;
    const rect = userButton.getBoundingClientRect();
    accountPopover.style.left = `${Math.max(12, rect.right + 12)}px`;
    accountPopover.style.bottom = `${Math.max(12, window.innerHeight - rect.bottom)}px`;
  }

  function toggleAccountPopover(force) {
    if (!accountPopover) return;
    const open = force === undefined ? accountPopover.hidden : !!force;
    accountPopover.hidden = !open;
    accountPopover.classList.toggle('is-open', open);
    if (open) positionAccountPopover();
  }

  async function initTheme() {
    const warmTheme = readWarmShellValue(SHELL_WARM_CACHE.theme);
    if (warmTheme) {
      const warmBody = warmTheme && warmTheme.data ? warmTheme.data : warmTheme;
      applyTheme(warmBody || {});
    }
    const correct = async () => {
      try {
        const response = await fetchBootstrapShared();
        const bootstrap = response && response.data ? response.data : response;
        const appearance = bootstrap && bootstrap.appearance && typeof bootstrap.appearance === 'object' ? bootstrap.appearance : {};
        const material = appearance.login && typeof appearance.login === 'object' ? appearance.login : appearance;
        applyTheme(material || {});
      } catch (_) {
        if (!warmTheme) applyTheme({});
      }
    };
    if (!warmTheme) return correct();
    if (typeof requestIdleCallback === 'function') requestIdleCallback(() => correct(), { timeout: 1400 });
    else window.setTimeout(correct, 480);
  }

  function initEvents() {
    aiBootstrap?.addEventListener('click', () => openGlobalAi());
    window.addEventListener('dwrt:appearance-material-preview', (event) => {
      applyMenuGlassOptions(event.detail || {});
    });
    window.addEventListener('dwrt:appearance-preview', handleAppearancePreview);
    document.addEventListener('pointerdown', (event) => {
      const control = event.target.closest('button:not(:disabled), [role="button"]');
      if (!control) return;
      control.classList.add('is-pointer-down');
      const pointerId = event.pointerId;
      const clear = (endEvent) => {
        if (endEvent.pointerId !== pointerId) return;
        control.classList.remove('is-pointer-down');
        document.removeEventListener('pointerup', clear, true);
        document.removeEventListener('pointercancel', clear, true);
      };
      document.addEventListener('pointerup', clear, true);
      document.addEventListener('pointercancel', clear, true);
    }, true);
    sidebarToggle && sidebarToggle.addEventListener('click', () => {
      const collapsed = !appShell.classList.contains('sidebar-collapsed');
      setSidebarCollapsed(collapsed);
    });
    menuSearchTrigger && menuSearchTrigger.addEventListener('click', () => setCommandOpen(true));
    commandPaletteBackdrop && commandPaletteBackdrop.addEventListener('click', () => setCommandOpen(false));
    commandPaletteInput && commandPaletteInput.addEventListener('input', () => {
      state.commandFiltered = filterCommandEntries(commandPaletteInput.value);
      state.commandSelected = 0;
      renderCommandResults();
    });
    commandPalette?.querySelectorAll('[data-command-mode]').forEach((button) => {
      button.addEventListener('click', () => setCommandMode(button.dataset.commandMode));
    });
    userButton && userButton.addEventListener('click', (event) => {
      event.stopPropagation();
      toggleAccountPopover();
    });
    themeButton && themeButton.addEventListener('click', cycleThemePreference);
    topologyShell && topologyShell.addEventListener('click', (event) => {
      const closeDetailButton = event.target.closest('[data-topology-detail-close]');
      if (closeDetailButton) {
        closeTopologyDetail();
        return;
      }
      const detailTabButton = event.target.closest('[data-topology-detail-tab]');
      if (detailTabButton) {
        state.topology.detailTab = detailTabButton.dataset.topologyDetailTab || 'overview';
        renderTopologyDetailDrawer();
        return;
      }
      const detailActionButton = event.target.closest('[data-topology-detail-action]');
      if (detailActionButton) {
        const actionLabel = detailActionButton.dataset.topologyDetailAction === 'capture' ? '数据包捕获' : '端口管理器';
        setTopologyStatus(`${actionLabel}需要后端提供对应接口。`);
        return;
      }
      const detailSectionToggle = event.target.closest('[data-topology-detail-section-toggle]');
      if (detailSectionToggle) {
        const card = detailSectionToggle.closest('[data-topology-detail-section]');
        if (card) {
          const collapsed = !card.classList.contains('is-collapsed');
          card.classList.toggle('is-collapsed', collapsed);
          detailSectionToggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
        }
        return;
      }
      const branchButton = event.target.closest('.topology-branch-button[data-branch-source]');
      if (branchButton) {
        event.preventDefault();
        event.stopPropagation();
        toggleTopologyBranch(branchButton.dataset.branchSource);
        return;
      }
      const sectionToggle = event.target.closest('[data-topology-section-toggle]');
      if (sectionToggle) {
        const section = sectionToggle.closest('[data-topology-section]');
        const id = section && section.dataset.topologySection;
        if (id) {
          state.topology.collapsedSections[id] = !state.topology.collapsedSections[id];
          if (!state.topology.collapsedSections[id]) delete state.topology.collapsedSections[id];
          syncTopologyControls();
        }
        return;
      }
      const infraNodeButton = event.target.closest('[data-topology-infra-node][data-node-mac]');
      if (infraNodeButton) {
        event.stopPropagation();
        openTopologyDetail(infraNodeButton.dataset.nodeMac);
        return;
      }
      const timeMachineEvent = event.target.closest('[data-topology-time-event]');
      if (timeMachineEvent) {
        loadTopologyTimeMachineSnapshot(Number(timeMachineEvent.dataset.topologyTimeEvent));
        return;
      }
      if (event.target.closest('[data-topology-time-live]')) {
        leaveTopologyTimeMachineHistory();
        return;
      }
      const timeMachineZoom = event.target.closest('[data-topology-time-zoom]');
      if (timeMachineZoom) {
        const direction = timeMachineZoom.dataset.topologyTimeZoom === 'in' ? 1 : -1;
        state.topology.timeMachineZoom = Math.max(0, Math.min(1, state.topology.timeMachineZoom + direction * 0.1));
        renderTopologyTimeMachine();
        return;
      }
      const nodeButton = event.target.closest('.topology-node[data-node-mac]');
	      if (nodeButton) {
	        event.stopPropagation();
	        if (nodeButton.dataset.wanOverflow === 'true') return;
	        openTopologyDetail(nodeButton.dataset.nodeMac);
        return;
      }
      const viewButton = event.target.closest('[data-topology-view]');
      if (viewButton) {
        state.topology.view = viewButton.dataset.topologyView === 'infrastructure' ? 'infrastructure' : 'topology';
        if (state.topology.view === 'infrastructure') {
          closeTopologyDetail({ skipRender: true });
          fetchTopologyInfrastructureOptional();
        }
        state.topology.transformSet = false;
        renderCurrentTopologyModel();
        return;
      }
      const navButton = event.target.closest('[data-topology-nav]');
      if (navButton) {
        state.topology.navigationMode = navButton.dataset.topologyNav === 'pointer' ? 'pointer' : 'hand';
        syncTopologyControls();
        return;
      }
      const button = event.target.closest('[data-topology-action]');
      if (!button) return;
      if (button.matches('input')) return;
      const action = button.dataset.topologyAction;
      switch (action) {
        case 'traffic':
          state.topology.trafficEnabled = !state.topology.trafficEnabled;
          renderCurrentTopologyModel();
          break;
        case 'panel-collapse':
          state.topology.panelCollapsed = !state.topology.panelCollapsed;
          syncTopologyControls();
          window.setTimeout(() => resetTopologyView(), 220);
          break;
        case 'reset':
        case 'fit':
          resetTopologyView();
          break;
        case 'rotate':
          state.topology.rotateMap = !state.topology.rotateMap;
          saveTopologyPreference(TOPOLOGY_PREF_KEYS.rotateMap, state.topology.rotateMap);
          state.topology.transformSet = false;
          renderCurrentTopologyModel();
          break;
        case 'zoom-in':
          setTopologyScaleAtCenter(1.16);
          break;
        case 'zoom-out':
          setTopologyScaleAtCenter(0.86);
          break;
        case 'clear-filters':
          clearTopologyFilters();
          break;
        case 'add':
          setTopologyStatus('添加拓扑对象需要后端提供 digital twin / infrastructure 写入接口。');
          break;
        default:
          break;
      }
    });
    topologyShell && topologyShell.addEventListener('change', (event) => {
      const input = event.target && event.target.closest ? event.target.closest('input') : null;
      if (!input) return;
      if (input.dataset.topologyAction === 'traffic') {
        state.topology.trafficEnabled = Boolean(input.checked);
        renderCurrentTopologyModel();
        return;
      }
      if (input.dataset.topologyAction === 'time-machine') {
        state.topology.timeMachineEnabled = Boolean(input.checked);
        state.topology.timeMachineSelectedTimestamp = 0;
        state.topology.timeMachineSnapshot = null;
        state.topology.transformSet = false;
        if (state.topology.timeMachineEnabled) enableTopologyTimeMachine();
        else {
          state.topology.timeMachineLoadId += 1;
          state.topology.timeMachineLoading = false;
          state.topology.timeMachineError = '';
          renderCurrentTopologyModel();
        }
        syncTopologyControls();
        return;
      }
      if (input.matches('[data-topology-time-zoom-range]')) {
        state.topology.timeMachineZoom = Math.max(0, Math.min(1, Number(input.value) || 0));
        renderTopologyTimeMachine();
        return;
      }
      if (input.dataset.topologyAction === 'clients-toggle') {
        state.topology.clientsEnabled = Boolean(input.checked);
        state.topology.transformSet = false;
        renderCurrentTopologyModel();
        return;
      }
      if (input.dataset.topologyFilter) {
        state.topology.filters[input.dataset.topologyFilter] = Boolean(input.checked);
        state.topology.transformSet = false;
        renderCurrentTopologyModel();
        return;
      }
      if (input.dataset.topologyLabel) {
        state.topology.labels[input.dataset.topologyLabel] = Boolean(input.checked);
        renderCurrentTopologyModel();
      }
    });
    topologyNodeLayer && topologyNodeLayer.addEventListener('error', (event) => {
      const img = event.target && event.target.closest ? event.target.closest('img') : null;
      if (!img || img.dataset.fallbackApplied === 'true') return;
      const visual = img.closest('.topology-node-visual');
      const type = visual ? String(visual.dataset.nodeType || 'CLIENT').toUpperCase() : 'CLIENT';
      img.dataset.fallbackApplied = 'true';
      if (visual) {
        visual.innerHTML = type === 'ISP'
          ? '<span class="topology-glyph isp"></span>'
          : type === 'USW_WAN' || type === 'CABLE_INTERNET'
            ? '<span class="topology-glyph wan"></span>'
            : '<span class="topology-glyph client"></span>';
      }
    }, true);
    topologyCanvas && topologyCanvas.addEventListener('pointerdown', (event) => {
      if (state.topology.navigationMode !== 'hand') return;
      if (event.button !== 0 || event.target.closest('.topology-node, [data-topology-infra-node], .topology-branch-button, .topology-icon-button, .topology-control-panel, .topology-property-panel, .topology-time-machine')) return;
      state.topology.dragging = {
        pointerId: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
        originX: state.topology.transform.x,
        originY: state.topology.transform.y
      };
      topologyCanvas.setPointerCapture(event.pointerId);
      topologyCanvas.classList.add('is-dragging');
    });
    topologyCanvas && topologyCanvas.addEventListener('pointermove', (event) => {
      const drag = state.topology.dragging;
      if (!drag || drag.pointerId !== event.pointerId) return;
      state.topology.transform = {
        ...state.topology.transform,
        x: drag.originX + event.clientX - drag.startX,
        y: drag.originY + event.clientY - drag.startY
      };
      state.topology.transformSet = true;
      applyTopologyTransform();
    });
    const endTopologyDrag = (event) => {
      const drag = state.topology.dragging;
      if (!drag || drag.pointerId !== event.pointerId) return;
      state.topology.dragging = null;
      try { topologyCanvas.releasePointerCapture(event.pointerId); } catch (_) {}
      topologyCanvas.classList.remove('is-dragging');
    };
    topologyCanvas && topologyCanvas.addEventListener('pointerup', endTopologyDrag);
    topologyCanvas && topologyCanvas.addEventListener('pointercancel', endTopologyDrag);
    topologyCanvas && topologyCanvas.addEventListener('wheel', (event) => {
      if (!state.topology.active) return;
      if (event.target.closest('.topology-property-panel, .topology-time-machine')) return;
      event.preventDefault();
      const modeFactor = event.deltaMode === 1 ? 16 : event.deltaMode === 2 ? 360 : 1;
      const gestureFactor = event.ctrlKey ? 0.32 : 1;
      zoomTopologyAt(event.clientX, event.clientY, event.deltaY * modeFactor * gestureFactor);
    }, { passive: false });
    document.addEventListener('pointerdown', (event) => {
      if (!accountPopover || accountPopover.hidden) return;
      if (event.target.closest('#accountPopover, #userButton')) return;
      toggleAccountPopover(false);
    });
    window.addEventListener('resize', () => {
      positionAccountPopover();
      updateActivePills(false);
      if (state.topology.active) resetTopologyView();
      scheduleGlassCardsRender(520);
      scheduleAdaptiveForegroundSample(180);
      resetPageFooterReserve();
    });
    const settleAdaptiveForegroundAfterScroll = (event) => {
      const target = event?.target;
      if (target instanceof Element) {
        if (target.closest('#primaryMenu, #bottomMenu')) return scheduleAdaptiveForegroundSample(160, $('sidebar'));
        if (target.closest('#secondaryMenu')) return scheduleAdaptiveForegroundSample(160, submenu);
        if (target.closest('#dashboardStatusRail')) return scheduleAdaptiveForegroundSample(160, $('dashboardStatusRail'));
        const pageGlass = target.closest(PAGE_GLASS_SELECTOR);
        if (pageGlass) return scheduleAdaptiveForegroundSample(160, pageGlass);
        if (target.closest('#consoleMain')) return scheduleAdaptiveForegroundSample(160, $('consoleMain'));
      }
      scheduleAdaptiveForegroundSample(160);
    };
    primaryMenu && primaryMenu.addEventListener('scroll', () => {
      updateActivePills(false);
      settleAdaptiveForegroundAfterScroll();
    }, { passive: true });
    secondaryMenu && secondaryMenu.addEventListener('scroll', () => {
      updateActivePills(false);
      settleAdaptiveForegroundAfterScroll();
    }, { passive: true });
    document.addEventListener('scroll', settleAdaptiveForegroundAfterScroll, { passive: true, capture: true });
    document.addEventListener('scroll', setPageGlassScrolling, { passive: true, capture: true });
    window.addEventListener('pagehide', stopPageGlassMapWorker);
    window.addEventListener('hashchange', syncFromLocation);
    window.addEventListener('keydown', (event) => {
      const key = event.key || '';
      if ((event.metaKey || event.ctrlKey) && key.toLowerCase() === 'k') {
        event.preventDefault();
        setCommandOpen(!state.commandOpen);
        return;
      }
      if (!state.commandOpen && key === 'Escape' && state.topology.detailOpen) {
        event.preventDefault();
        closeTopologyDetail();
        return;
      }
      if (!state.commandOpen) return;
      if (key === 'Tab') {
        const focusable = [commandPaletteInput, ...commandPalette.querySelectorAll('[data-command-mode]')].filter((element) => element && !element.disabled);
        if (!focusable.length) return;
        const current = focusable.indexOf(document.activeElement);
        const next = event.shiftKey
          ? (current <= 0 ? focusable.length - 1 : current - 1)
          : (current < 0 || current === focusable.length - 1 ? 0 : current + 1);
        event.preventDefault();
        focusable[next].focus();
        return;
      }
      if (key === 'Escape') {
        event.preventDefault();
        setCommandOpen(false);
        return;
      }
      if (key === 'ArrowDown') {
        event.preventDefault();
        selectCommand(state.commandSelected + 1);
        return;
      }
      if (key === 'ArrowUp') {
        event.preventDefault();
        selectCommand(state.commandSelected - 1);
        return;
      }
      if (key === 'Enter') {
        event.preventDefault();
        if (state.commandMode === 'ai') openCommandEntry(filterCommandEntries(commandPaletteInput?.value || '')[0]);
        else openCommandEntry(state.commandFiltered[state.commandSelected]);
      }
    });
    if (window.matchMedia) {
      const media = window.matchMedia('(prefers-color-scheme: dark)');
      const syncSystemTheme = () => {
        if ((themeButton?.dataset.themePref || document.documentElement.dataset.themePref || 'system') === 'system') setThemePreference('system');
      };
      media.addEventListener ? media.addEventListener('change', syncSystemTheme) : media.addListener?.(syncSystemTheme);
    }
    try {
      const collapsed = localStorage.getItem('dreamingwrt.web.sidebarCollapsed') === '1';
      setSidebarCollapsed(collapsed);
      setThemePreference(localStorage.getItem('dreamingwrt.web.themePref') || 'system');
      loadTopologyPreferences();
    } catch (_) {
      setThemePreference('system');
    }
  }

  function refreshShellAfterMenuLoad(options = {}) {
    buildCommandEntries();
    syncFromLocation(options);
    updateActivePills(false);
    scheduleAdaptiveForegroundSample(120);
  }

  function afterNextPaint() {
    return new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  }

  function scheduleIdleRouteWarmup() {
    if (idleRouteWarmupScheduled) return;
    idleRouteWarmupScheduled = true;
    const warm = () => {
      loadClassicPageScript('topology').catch(() => {});
    };
    if (typeof window.requestIdleCallback === 'function') {
      window.requestIdleCallback(warm, { timeout: 3000 });
    } else {
      window.setTimeout(warm, 1200);
    }
  }

  async function hydrateShell() {
    initTheme().then(() => {
      scheduleGlassCardsRender(360);
    }).catch(() => {});

    await loadMenu({ includeRuntimeConfig: false });
    refreshShellAfterMenuLoad({ shellOnly: true });
    await afterNextPaint();
    syncFromLocation();
    initialRouteMounted = true;
    appShell.dataset.initialRouteMounted = 'true';
    scheduleGlassCardsRender(180);

    loadMenu({ includeRuntimeConfig: true }).then(() => {
      refreshShellAfterMenuLoad();
    }).catch(() => {}).finally(scheduleIdleRouteWarmup);
  }

  // Chromium 将 svg 用作 <img> 源时(SVGImage)由主线程绘制,dashboard/洞察等页的
  // logo 图标会在挂载后造成多帧 150-450ms 的不可归因渲染停顿(实测隐藏这些 <img>
  // 后停顿归零)。这里把 svg <img> 离屏栅格化为等视觉的 PNG blob 并替换 src,
  // 之后的绘制走合成器位图路径,不再阻塞主线程。
  const svgImageBitmapCache = new Map();
  const svgImageBitmapPending = new Map();

  function isSvgImageSource(src) {
    return /\.svg(?:\?|$)/i.test(src) || /^data:image\/svg/i.test(src);
  }

  function rasterizeSvgImageUrl(url) {
    if (svgImageBitmapCache.has(url)) return Promise.resolve(svgImageBitmapCache.get(url));
    const pending = svgImageBitmapPending.get(url);
    if (pending) return pending;
    const promise = new Promise((resolve) => {
      const image = new Image();
      image.decoding = 'async';
      image.onload = () => {
        try {
          const sourceW = Math.max(1, image.naturalWidth || 64);
          const sourceH = Math.max(1, image.naturalHeight || 64);
          const targetMax = Math.min(512, 128 * Math.min(3, window.devicePixelRatio || 1));
          const scale = Math.min(8, Math.max(1, targetMax / Math.max(sourceW, sourceH)));
          const canvas = document.createElement('canvas');
          canvas.width = Math.max(1, Math.round(sourceW * scale));
          canvas.height = Math.max(1, Math.round(sourceH * scale));
          const context = canvas.getContext('2d');
          if (!context) {
            resolve('');
            return;
          }
          context.drawImage(image, 0, 0, canvas.width, canvas.height);
          canvas.toBlob((blob) => {
            const blobUrl = blob ? URL.createObjectURL(blob) : '';
            svgImageBitmapCache.set(url, blobUrl);
            resolve(blobUrl);
          }, 'image/png');
        } catch (_) {
          resolve('');
        }
      };
      image.onerror = () => {
        svgImageBitmapCache.set(url, '');
        resolve('');
      };
      image.src = url;
    }).finally(() => svgImageBitmapPending.delete(url));
    svgImageBitmapPending.set(url, promise);
    return promise;
  }

  function upgradeSvgImageElement(img) {
    if (!(img instanceof HTMLImageElement)) return;
    const src = img.getAttribute('src') || '';
    if (!src || !isSvgImageSource(src)) return;
    const cached = svgImageBitmapCache.get(src);
    if (cached !== undefined) {
      if (cached) img.src = cached;
      return;
    }
    rasterizeSvgImageUrl(src).then((blobUrl) => {
      if (!blobUrl || !img.isConnected) return;
      if ((img.getAttribute('src') || '') !== src) return;
      img.src = blobUrl;
    });
  }

  function upgradeSvgImagesWithin(node) {
    if (!(node instanceof Element)) return;
    if (node instanceof HTMLImageElement) {
      upgradeSvgImageElement(node);
      return;
    }
    node.querySelectorAll('img').forEach(upgradeSvgImageElement);
  }

  function initSvgImageBitmapObserver() {
    if (typeof MutationObserver === 'undefined' || !appShell) return;
    const observer = new MutationObserver((records) => {
      records.forEach((record) => {
        if (record.addedNodes) record.addedNodes.forEach(upgradeSvgImagesWithin);
      });
    });
    observer.observe(appShell, { childList: true, subtree: true });
    upgradeSvgImagesWithin(appShell);
  }

  function main() {
    configureDataRegistry();
    initSessionRecovery();
    ensureMenuGlassRenderer();
    initPageGlassObserver();
    initSvgImageBitmapObserver();
    setupActionIcons();
    initEvents();
    initPageFooterLayout();
    loadPageFooterRelease().catch(() => {});
    if (!window.location.hash) history.replaceState(null, '', '/app/#/dashboard');
    hydrateShell().catch(() => {
      if (menuSource) menuSource.textContent = '菜单加载失败';
    });
  }

  main();
})();
