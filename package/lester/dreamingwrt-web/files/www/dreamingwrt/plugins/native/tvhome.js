import {createOperations} from './tvhome-operations.js?v=20261005-tvhome-host-01';
// TVHome 管理台 —— 传统模式原生插件（Package A：合同与基础）。
//
// 契约冻结见 todo/2026-09-23/Handoff/PM-tvhome-package-a-contract.md（A/* 管理路由、bootstrap、
// 字段名 v1）；主题 spec 与 3 个 fixture 见 PM-tvhome-schema-and-fixtures.md（字段真值源）。
// 本模块只消费共享 DreamingOS UI Kit（--dwrt-*/--lg-* 令牌、floatingSavebarMarkup、
// overviewCardsMarkup、statusBadgeMarkup、confirmationMarkup），不搬 roceos 的 React 壳/私有 CSS。
//
// 模块契约同其它原生插件（见 plugins/native/aegisx.js）：导出 mount(context)，context.root 是
// 路由预览容器，context.api/ui/utils 由 menu-shell 注入，返回 { unmount }。离开路由 signal abort → unmount。
//
// Package A 完成面：概览 / 主题设计(编辑器) / 终端与分组 / 桌面设置 为可用实现；
// 素材库 / 公告与应急 / TV 应用 / TV 桌面升级 / 事件与诊断 为骨架占位（B–E 工作包）。
// 媒体 provider 一律 provider_not_configured：显示禁用/空态，绝不出现 SampleCard 或伪影视/摄像头数据。

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  if (!(root instanceof HTMLElement)) return { unmount() {} };
  const stage = root.closest ? root.closest('.console-stage') : null;
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const VERSION = '20261001-tvhome-n2-01';
  let operations;
  const SETTINGS_DRAFT_KEY = 'dwrt.tvhome.settings-draft.v1';
  const THEME_DRAFT_KEY = 'dwrt.tvhome.theme-draft.v1';
  const ACTIVE_TAB_KEY = 'dreamingwrt.tvhome.activeTab.v1';

  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));

  // 管理前缀 A=/api/v1/tvhome（契约 §3）。终端前缀 T=/api/v1/tv/client 属 TV 端，本管理台不调用。
  const A = '/api/v1/tvhome';
  const ENDPOINTS = {
    overview: `${A}/overview`,
    settings: `${A}/settings`,
    themes: `${A}/themes`,
    themeValidate: `${A}/themes/validate`,
    themePreview: `${A}/themes/preview`,
    theme: (id) => `${A}/themes/${encodeURIComponent(id)}`,
    themeDefault: (id) => `${A}/themes/${encodeURIComponent(id)}/default`,
    themeDuplicate: (id) => `${A}/themes/${encodeURIComponent(id)}/duplicate`,
    terminals: `${A}/terminals`,
    terminal: (id) => `${A}/terminals/${encodeURIComponent(id)}`,
    terminalDisplay: (id) => `${A}/terminals/${encodeURIComponent(id)}/display`,
    groups: `${A}/groups`,
    group: (id) => `${A}/groups/${encodeURIComponent(id)}`,
    groupDisplay: (id) => `${A}/groups/${encodeURIComponent(id)}/display`
  };
  // 9 页信息架构（契约单 §2）。Package A 完成 overview/theme/terminals/settings；其余骨架占位。
  const TABS = [
    { id: 'overview', label: '概览', ready: true },
    { id: 'theme', label: '主题设计', ready: true },
    { id: 'assets', label: '素材库', ready: false },
    { id: 'terminals', label: '终端与分组', ready: true },
    { id: 'notice', label: '公告与应急', ready: false },
    { id: 'apps', label: 'TV 应用', ready: true },
    { id: 'upgrade', label: 'TV 桌面升级', ready: true },
    { id: 'events', label: '事件与诊断', ready: false },
    { id: 'settings', label: '桌面设置', ready: true }
  ];

  // 契约 §2 稳定错误码 → 中文动作提示。前端据此定位，不把重试当成功。
  const ERROR_TEXT = {
    invalid_theme: '主题校验未通过，请按高亮字段修正（草稿已保留）。',
    invalid_parameter: '参数无效，请检查输入后重试。',
    tv_session_expired: 'TV 会话已过期。',
    tv_session_revoked: 'TV 会话已被撤销。',
    tv_forbidden: '当前身份无此操作权限。',
    module_disabled: '该模块已被停用。',
    pin_required: '此操作需要 PIN。',
    device_bound: '该设备已被其它主体绑定。',
    resource_not_found: '资源不存在或已被删除。',
    state_not_found: '状态不存在（真空态）。',
    revision_conflict: '版本冲突：配置已被他处更新，草稿已保留，请对比后重试。',
    asset_in_use: '素材正在被引用，无法删除。',
    default_theme_in_use: '默认主题不可删除或停用。',
    upload_too_large: '上传超出大小上限。',
    state_too_large: '状态数据超出上限。',
    rate_limited: '请求过于频繁，请稍后再试。',
    provider_unavailable: '内容服务暂不可用，请稍后重试。',
    service_not_ready: '服务尚未就绪。',
    provider_not_configured: '尚未配置内容服务'
  };

  // 内容模块能力键（契约 §4 capabilities）。home/settings/search 是外壳模块，恒在，不进能力表。
  const SHELL_MODULES = new Set(['home', 'settings', 'search']);
  const MODULE_LABELS = {
    home: '首页', settings: '设置', search: '搜索',
    live: '直播', vod: '点播', music: '音乐', photos: '相册', files: '文件', nvr: '监控', apps: '应用'
  };
  // 令牌默认值（schema §3）。缺字段一律回默认，渲染器不得因缺字段白屏。
  const TOKEN_DEFAULTS = { colorBackground: '#202326', colorSurface: '#2A2E33', colorPrimary: '#3F8CFF', foreground: '#F2F4F7', focusColor: '', radius: 16, fontScale: 1.0, blur: 18, focusScale: 1.06 };

  // 3 个内建 fixture（schema §10，字段真值源）。编辑器内明确标注为“预览 fixture”，
  // 供 F04（Web/TV 同一份 flow/grid 渲染一致）与后端未接通时的骨架预览。运行中 TV 绝不出现此数据。
  const FIXTURE_FLOW = {
    version: 1, style: 'flow',
    tokens: { colorBackground: '#202326', colorPrimary: '#3F8CFF', foreground: '#F2F4F7', radius: 16, fontScale: 1.0, blur: 18, focusScale: 1.06 },
    background: { mode: 'slideshow', assetIds: ['asset-bg-1', 'asset-bg-2'], intervalSec: 30, effect: 'fade', dim: 0.2 },
    screensaver: { enabled: true, mode: 'clock', idleMinutes: 10 },
    header: { clock: true, weather: true, date: true },
    parental: { lockedModules: ['files'] },
    nav: [
      { id: 'home', type: 'module', module: 'home', label: '首页' },
      { id: 'live', type: 'module', module: 'live', label: '直播' },
      { id: 'vod', type: 'module', module: 'vod', label: '影视点播中心与专题推荐' },
      { id: 'nvr', type: 'module', module: 'nvr', label: '监控' },
      { id: 'shop', type: 'weblink', url: 'https://example.invalid/mall', label: '商城' },
      { id: 'hidden-diag', type: 'page', pageId: 'diag', label: '诊断', hidden: true }
    ],
    home: { sections: [
      { id: 'hero', type: 'hero', source: 'manual', cardStyle: 'wide', tiles: [
        { id: 'h1', kind: 'banner', image: 'asset-hero-1', x: 0, y: 0, w: 1, h: 1 },
        { id: 'h2', kind: 'weblink', url: 'https://example.invalid/promo', label: '活动', x: 0, y: 0, w: 1, h: 1 }
      ] },
      { id: 'cw', type: 'row', title: '继续观看', source: 'continueWatching', limit: 12, cardStyle: 'poster' },
      { id: 'add', type: 'row', title: '最近添加', source: 'recentAdded', limit: 12, cardStyle: 'poster' },
      { id: 'apps', type: 'tiles', title: '应用', source: 'apps', limit: 8, cardStyle: 'square' },
      { id: 'cams', type: 'row', title: '摄像机', source: 'cameras', limit: 6, cardStyle: 'wide' }
    ] }
  };
  const FIXTURE_GRID = {
    version: 1, style: 'grid',
    tokens: { colorBackground: '#141719', colorSurface: '#20262B', colorPrimary: '#57C7A6', foreground: '#EEF2F4', radius: 20, fontScale: 1.1, blur: 24, focusScale: 1.08 },
    background: { mode: 'color', color: '#141719' },
    screensaver: { enabled: true, mode: 'photos', idleMinutes: 15, intervalSec: 8, photoQuery: 'album:客厅' },
    header: { clock: true, weather: true, date: false },
    parental: { lockedModules: [] },
    nav: [
      { id: 'main', type: 'page', pageId: 'main', label: '主页' },
      { id: 'media', type: 'page', pageId: 'media', label: '影音' },
      { id: 'settings', type: 'module', module: 'settings', label: '设置' }
    ],
    home: {
      columns: 12, rows: 6,
      pages: [
        { id: 'main', label: '主页', tiles: [
          { id: 't-files', kind: 'module', module: 'files', label: '文件', x: 0, y: 0, w: 3, h: 2 },
          { id: 't-live', kind: 'liveWindow', label: '客厅直播', x: 3, y: 0, w: 6, h: 3, params: { channelId: 'cctv-1' } },
          { id: 't-clock', kind: 'clockCard', x: 9, y: 0, w: 3, h: 2 },
          { id: 't-weather', kind: 'weatherCard', x: 9, y: 2, w: 3, h: 2 },
          { id: 't-nvr', kind: 'nvrWindow', label: '门口', x: 0, y: 2, w: 3, h: 2, params: { cameraId: 'cam-door' } },
          { id: 't-shop', kind: 'weblink', url: 'https://example.invalid/mall', label: '商城', showLabel: true, x: 0, y: 4, w: 3, h: 2 },
          { id: 't-kodi', kind: 'app', appPackage: 'org.xbmc.kodi', label: 'Kodi', x: 3, y: 3, w: 3, h: 3 },
          { id: 't-photos', kind: 'photoCarousel', label: '相册', x: 6, y: 3, w: 3, h: 3, params: { photoQuery: 'recent' } },
          { id: 't-cal', kind: 'calendar', x: 9, y: 4, w: 3, h: 2 }
        ] },
        { id: 'media', label: '影音', tiles: [
          { id: 'm-vod', kind: 'module', module: 'vod', label: '点播', x: 0, y: 0, w: 6, h: 3 },
          { id: 'm-music', kind: 'module', module: 'music', label: '音乐', x: 6, y: 0, w: 6, h: 3 },
          { id: 'm-note', kind: 'text', label: '公告：本页为自定义磁贴页', x: 0, y: 3, w: 12, h: 1 },
          { id: 'm-banner', kind: 'banner', image: 'asset-banner-1', x: 0, y: 4, w: 12, h: 2 }
        ] }
      ],
      dock: [
        { id: 'd-home', kind: 'module', module: 'home', icon: 'home', x: 0, y: 0, w: 1, h: 1 },
        { id: 'd-search', kind: 'module', module: 'search', icon: 'search', x: 1, y: 0, w: 1, h: 1 }
      ]
    }
  };
  // 显示逐项继承对照（schema §10.3 / 主规格 §3.3）。terminal>group>theme，background 与 screensaver 各自独立 firstNonNull。
  const FIXTURE_INHERIT = {
    input: {
      theme: { background: { mode: 'static', assetId: 'asset-A' }, screensaver: { enabled: true, mode: 'clock', idleMinutes: 10 } },
      group: { background: { mode: 'color', color: '#0B1E2D' }, screensaver: null },
      terminal: { background: null, screensaver: { enabled: true, mode: 'video', assetId: 'asset-C', idleMinutes: 20 } }
    },
    resolved: {
      background: { mode: 'color', color: '#0B1E2D' },
      screensaver: { enabled: true, mode: 'video', assetId: 'asset-C', idleMinutes: 20 },
      source: { background: 'group', screensaver: 'terminal' }
    }
  };

  const FIXTURES = [
    { id: 'fixture-flow', name: 'Fixture · Flow（手工 hero + 动态行 + 隐藏导航 + 长中文 + weblink）', style: 'flow', spec: FIXTURE_FLOW },
    { id: 'fixture-grid', name: 'Fixture · Grid（12×6 两页 + 跨格磁贴 + dock + 自定义页）', style: 'grid', spec: FIXTURE_GRID }
  ];
  // ---- 通用工具 ----
  const clone = (value) => (value == null ? value : JSON.parse(JSON.stringify(value)));
  const asArray = (value) => (Array.isArray(value) ? value : []);
  const isObject = (value) => value != null && typeof value === 'object' && !Array.isArray(value);
  let uidCounter = 0;
  const uid = (prefix) => `${prefix}-${Date.now().toString(36)}-${(uidCounter++).toString(36)}`;
  const clampNum = (value, min, max, fallback) => {
    const n = Number(value);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, n));
  };
  const HEX_RE = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;
  const safeColor = (value, fallback) => (typeof value === 'string' && HEX_RE.test(value.trim()) ? value.trim() : fallback);

  // 会话角色：viewer/user 只读；其它角色可写（与 aegisx 一致，读 localStorage）。
  const currentRole = () => {
    try { return String(window.localStorage?.getItem('dreamingwrt.web.role') || '').toLowerCase(); } catch (_) { return ''; }
  };
  const writeAllowed = () => ['owner', 'admin'].includes(currentRole());

  const readDraft = (key) => {
    try { const raw = window.sessionStorage?.getItem(key); return raw ? JSON.parse(raw) : null; } catch (_) { return null; }
  };
  const writeDraft = (key, value) => {
    try { if (value == null) window.sessionStorage?.removeItem(key); else window.sessionStorage?.setItem(key, JSON.stringify(value)); } catch (_) {}
  };

  // 从抛出的错误里取契约 §2 稳定 code（menu-shell 的 api.request 把后端信封挂在 error.payload）。
  const errorCode = (err) => {
    const p = err && err.payload;
    const e = p && (p.error ?? p.err);
    if (typeof e === 'string') return e;
    if (isObject(e) && typeof e.code === 'string') return e.code;
    if (p && typeof p.code === 'string') return p.code;
    return '';
  };
  const messageForError = (err, fallback) => {
    const code = errorCode(err);
    if (code && ERROR_TEXT[code]) return ERROR_TEXT[code];
    const status = err && err.status;
    if (status === 404) return '服务尚未就绪或路由不存在（后端未接通）。';
    if (status === 401) return '会话已失效，请重新登录。';
    if (status === 403) return '当前身份无此操作权限。';
    if (err && err.message) return String(err.message);
    return fallback || '请求失败。';
  };

  // 契约 §2 字段定位：从错误里取字段路径（后端返回 details/field），供高亮。
  const errorFields = (err) => {
    const p = err && err.payload;
    const d = p && (p.details || p.fields || (isObject(p.error) ? p.error.details : null));
    if (Array.isArray(d)) return d.map((x) => (typeof x === 'string' ? x : (x && (x.field || x.path)) || '')).filter(Boolean);
    if (isObject(d)) return Object.keys(d);
    const f = p && (p.field || (isObject(p.error) ? p.error.field : null));
    return f ? [String(f)] : [];
  };
  // ---- 状态 ----
  const initialTab = () => {
    let saved = '';
    try { saved = window.sessionStorage?.getItem(ACTIVE_TAB_KEY) || ''; } catch (_) {}
    return TABS.some((t) => t.id === saved) ? saved : 'overview';
  };

  const state = {
    mounted: true,
    seq: 0,
    tab: initialTab(),
    overview: { loading: true, error: '', data: null },
    settings: { loading: true, error: '', baseline: null, draft: null, saving: false, fields: [], msg: '' },
    themes: {
      loading: true, error: '', list: [], usingFixtures: false, capabilities: null,
      activeId: '', baseline: null, draft: null, revision: 0, name: '', saving: false,
      view: 'visual', selection: { kind: 'appearance' }, page: 0, fields: [], msg: ''
    },
    terminals: { loading: true, error: '', list: [], groups: [], groupsError: '', activations: [], activationError: '', themes: [], query: '', editor: null, message: '', grant: null }
  };

  // ---- 能力模型（契约 §4）：Package A 内 provider 全未接通 → provider_not_configured ----
  const CONTENT_MODULES = ['live', 'vod', 'music', 'photos', 'files', 'nvr', 'apps'];
  const defaultCapabilities = () => {
    const caps = {};
    CONTENT_MODULES.forEach((m) => { caps[m] = { available: false, enabled: false, permitted: false, reason: 'provider_not_configured' }; });
    return caps;
  };
  const capabilityOf = (module) => {
    if (SHELL_MODULES.has(module)) return { available: true, enabled: true, permitted: true, shell: true };
    const caps = state.themes.capabilities || defaultCapabilities();
    return caps[module] || { available: false, enabled: false, permitted: false, reason: 'provider_not_configured' };
  };
  const capabilityUsable = (module) => {
    const c = capabilityOf(module);
    return !!(c.available && c.enabled && c.permitted);
  };
  // ---- 规范化/校验（客户端镜像；服务端权威，预览不自补另一套默认值，仅补 §3 已声明默认） ----
  const resolveTokens = (tokens) => {
    const t = isObject(tokens) ? tokens : {};
    const primary = safeColor(t.colorPrimary, TOKEN_DEFAULTS.colorPrimary);
    return {
      colorBackground: safeColor(t.colorBackground, TOKEN_DEFAULTS.colorBackground),
      colorSurface: safeColor(t.colorSurface, TOKEN_DEFAULTS.colorSurface),
      colorPrimary: primary,
      foreground: safeColor(t.foreground, TOKEN_DEFAULTS.foreground),
      focusColor: safeColor(t.focusColor, primary),
      radius: clampNum(t.radius, 0, 48, TOKEN_DEFAULTS.radius),
      fontScale: clampNum(t.fontScale, 0.85, 1.4, TOKEN_DEFAULTS.fontScale),
      blur: clampNum(t.blur, 0, 48, TOKEN_DEFAULTS.blur),
      focusScale: clampNum(t.focusScale, 1.0, 1.2, TOKEN_DEFAULTS.focusScale)
    };
  };

  // 把 token 落成隔离作用域的 CSS 变量（预览画布=TV 屏模拟，用主题自身字面色，不碰控制台玻璃族）。
  const canvasStyleVars = (tokens) => {
    const t = resolveTokens(tokens);
    return [
      `--tvh-bg:${t.colorBackground}`, `--tvh-surface:${t.colorSurface}`, `--tvh-primary:${t.colorPrimary}`,
      `--tvh-fg:${t.foreground}`, `--tvh-focus:${t.focusColor}`, `--tvh-radius:${t.radius}px`,
      `--tvh-font-scale:${t.fontScale}`, `--tvh-blur:${t.blur}px`, `--tvh-focus-scale:${t.focusScale}`
    ].join(';');
  };

  // §7 规则 2：grid 磁贴 x/y/w/h、越界、页内重叠、页内 id 唯一（客户端提示，最终由后端裁决）。
  const gridIssues = (spec) => {
    const issues = [];
    if (!spec || spec.style !== 'grid' || !isObject(spec.home)) return issues;
    const cols = clampNum(spec.home.columns, 4, 24, 12);
    const rows = clampNum(spec.home.rows, 2, 12, 6);
    asArray(spec.home.pages).forEach((page) => {
      const seen = new Set();
      const occ = [];
      asArray(page.tiles).forEach((tile) => {
        const label = page.label || page.id;
        if (seen.has(tile.id)) issues.push(`页“${label}”磁贴 id 重复：${tile.id}`);
        seen.add(tile.id);
        const x = Number(tile.x), y = Number(tile.y), w = Number(tile.w), h = Number(tile.h);
        if (!(x >= 0 && y >= 0 && w >= 1 && h >= 1)) { issues.push(`磁贴 ${tile.id} 坐标非法（需 x≥0,y≥0,w≥1,h≥1）`); return; }
        if (x + w > cols || y + h > rows) issues.push(`磁贴 ${tile.id} 越界（超出 ${cols}×${rows}）`);
        for (const r of occ) {
          if (x < r.x + r.w && x + w > r.x && y < r.y + r.h && y + h > r.y) { issues.push(`磁贴 ${tile.id} 与 ${r.id} 重叠`); break; }
        }
        occ.push({ id: tile.id, x, y, w, h });
      });
    });
    return issues;
  };
  // ---- API 访问（走 menu-shell 注入的 api.request：成功解包 data，失败抛带 .status/.payload 的错误） ----
  const jsonInit = (method, body) => ({ method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  async function requestJson(name, url, init) {
    if (typeof api.request === 'function') return await api.request(name, url, init || {});
    const res = await fetch(url, Object.assign({ headers: { Accept: 'application/json' } }, init || {}));
    const json = await res.json().catch(() => null);
    if (!res.ok || (json && json.ok === false)) {
      const err = new Error((json && (json.message || json.error)) || `HTTP ${res.status}`);
      err.status = res.status; err.payload = json; throw err;
    }
    return json && typeof json === 'object' && 'data' in json ? json.data : json;
  }

  async function loadOverview() {
    const seq = state.seq; const o = state.overview;
    o.loading = true; o.error = ''; render();
    try {
      const data = await requestJson('tvhome-overview', ENDPOINTS.overview);
      if (seq !== state.seq) return;
      o.data = isObject(data) ? data : null;
      if (isObject(data) && isObject(data.capabilities)) state.themes.capabilities = data.capabilities;
    } catch (err) {
      if (seq !== state.seq) return;
      o.error = messageForError(err, '概览加载失败。'); o.data = null;
    } finally { if (seq === state.seq) { o.loading = false; render(); } }
  }

  async function loadSettings() {
    const seq = state.seq; const s = state.settings;
    s.loading = true; s.error = ''; render();
    try {
      const data = await requestJson('tvhome-settings', ENDPOINTS.settings);
      if (seq !== state.seq) return;
      s.baseline = isObject(data) ? data : {};
      const saved = readDraft(SETTINGS_DRAFT_KEY);
      if (!isSettingsDirty()) s.draft = isObject(saved) ? saved : clone(s.baseline);
    } catch (err) {
      if (seq !== state.seq) return;
      s.error = messageForError(err, '桌面设置加载失败。'); s.baseline = null;
      const saved = readDraft(SETTINGS_DRAFT_KEY);
      if (isObject(saved)) s.draft = saved;
    } finally { if (seq === state.seq) { s.loading = false; render(); } }
  }
  // 后端未接通时用内建 fixture 顶替主题列表，明确标注 _fixture，供编辑器/F04 演示（运行中 TV 绝不消费此数据）。
  const fixtureThemeList = () => FIXTURES.map((f, i) => ({
    id: f.id, name: f.name, style: f.spec.style, revision: 1, schema_version: 1,
    is_default: i === 0, usage_count: 0, _fixture: true, spec: clone(f.spec)
  }));

  async function loadThemes() {
    const seq = state.seq; const t = state.themes;
    t.loading = true; t.error = ''; render();
    try {
      const data = await requestJson('tvhome-themes', ENDPOINTS.themes);
      if (seq !== state.seq) return;
      if (isObject(data) && isObject(data.capabilities)) t.capabilities = data.capabilities;
      const list = asArray(isObject(data) ? (data.themes || data.items || data.list) : data);
      if (list.length) { t.list = list; t.usingFixtures = false; }
      else { t.list = []; t.usingFixtures = false; }
    } catch (err) {
      if (seq !== state.seq) return;
      t.error = messageForError(err, '主题列表加载失败。');
      t.list = []; t.usingFixtures = false;
    } finally {
      if (seq !== state.seq) return;
      t.loading = false;
      if (!t.capabilities) t.capabilities = defaultCapabilities();
      if (isThemeDirty()) render(); else restoreThemeSelection();
    }
  }

  function restoreThemeSelection() {
    const t = state.themes;
    const saved = readDraft(THEME_DRAFT_KEY);
    let targetId = t.activeId || (saved && saved.id) || (t.list[0] && t.list[0].id) || '';
    if (!t.list.some((x) => x.id === targetId)) targetId = t.list[0] ? t.list[0].id : '';
    if (!targetId) { t.activeId = ''; t.baseline = null; t.draft = null; render(); return; }
    selectTheme(targetId, { keepDraft: true });
  }

  async function selectTheme(id, opts = {}) {
    const t = state.themes;
    const row = t.list.find((x) => x.id === id);
    if (!row) return;
    if (t.activeId !== id && isThemeDirty() && !window.confirm('放弃当前主题未保存的更改？')) return;
    t.activeId = id; t.page = 0; t.selection = { kind: 'appearance' }; t.fields = []; t.msg = '';
    let spec = row.spec ? clone(row.spec) : null;
    let revision = Number(row.revision) || 0;
    let name = row.name || id;
    if (!spec && !row._fixture) {
      const seq = state.seq;
      try {
        const data = await requestJson('tvhome-theme', ENDPOINTS.theme(id));
        if (seq !== state.seq) return;
        spec = clone(isObject(data) ? (data.spec || data) : null);
        if (isObject(data)) { if (data.revision != null) revision = Number(data.revision) || 0; if (data.name) name = data.name; }
      } catch (err) { if (seq !== state.seq) return; t.msg = messageForError(err, '主题详情加载失败。'); }
    }
    t.baseline = spec ? { name, spec: clone(spec), revision } : null;
    const saved = readDraft(THEME_DRAFT_KEY);
    if (opts.keepDraft && saved && saved.id === id && isObject(saved.spec)) {
      t.draft = clone(saved.spec); t.name = saved.name != null ? saved.name : name;
    } else { t.draft = spec ? clone(spec) : null; t.name = name; }
    t.revision = revision;
    t.history=[{name:t.name,spec:clone(t.draft)}];t.redo=[];
    render();
  }
  async function loadTerminals() {
    const seq = state.seq; const t = state.terminals;
    t.loading = true; t.error = ''; t.groupsError = ''; render();
    const [term, grp, act, themes] = await Promise.allSettled([
      requestJson('tvhome-terminals', ENDPOINTS.terminals),
      requestJson('tvhome-groups', ENDPOINTS.groups),
      requestJson('tvhome-activations', '/api/v1/tvhome/activations'),
      requestJson('tvhome-record-themes', ENDPOINTS.themes)
    ]);
    if (seq !== state.seq) return;
    if (term.status === 'fulfilled') {
      const d = term.value; t.list = asArray(isObject(d) ? (d.terminals || d.items || d.list) : d);
    } else { t.error = messageForError(term.reason, '终端列表加载失败。'); t.list = []; }
    if (grp.status === 'fulfilled') {
      const d = grp.value; t.groups = asArray(isObject(d) ? (d.groups || d.items || d.list) : d);
    } else { t.groupsError = messageForError(grp.reason, '分组加载失败。'); t.groups = []; }
    t.activations = act.status === 'fulfilled' ? asArray(act.value.activations) : [];
    t.activationError = act.status === 'rejected' ? messageForError(act.reason, '申请列表加载失败') : '';
    t.themes = themes.status === 'fulfilled' ? asArray(themes.value.themes) : [];
    t.loading = false; render();
  }

  // 按需加载：只拉当前 tab（避免隐藏页后台轮询；契约单 §2.1）。force=手动刷新。
  function ensureTabData(force) {
    if(operations?.owns(state.tab)){operations.load(state.tab,force);return;}
    switch (state.tab) {
      case 'overview': if (force || (!state.overview.data && !state.overview.error)) loadOverview(); break;
      case 'settings': if (force || (!state.settings.baseline && !state.settings.error)) loadSettings(); break;
      case 'theme': if (force || !state.themes.list.length) loadThemes(); break;
      case 'terminals': if (force || (!state.terminals.list.length && !state.terminals.error)) loadTerminals(); break;
      default: break;
    }
  }
  // ---- 渲染：通用 ----
  const q = (sel) => root.querySelector(sel);
  const qa = (sel) => Array.from(root.querySelectorAll(sel));
  const badge = (label, tone) => (ui.statusBadgeMarkup ? ui.statusBadgeMarkup(label, tone) : `<span class="dwrt-kit-status-badge is-${tone || 'muted'}">${escapeHtml(label)}</span>`);
  const statePanel = (opts) => {
    const o = opts || {};
    return `<div class="dwrt-kit-state-panel tvhome-state" data-dwrt-state="${escapeHtml(o.tone || 'info')}">
      <p class="tvhome-state-title">${escapeHtml(o.title || '')}</p>
      ${o.desc ? `<p class="tvhome-state-desc">${escapeHtml(o.desc)}</p>` : ''}
    </div>`;
  };
  const stableJson = (v) => { try { return JSON.stringify(v); } catch (_) { return ''; } };
  const isThemeDirty = () => {
    const t = state.themes;
    if (!t.baseline || !t.draft) return false;
    return stableJson(t.draft) !== stableJson(t.baseline.spec) || t.name !== t.baseline.name;
  };
  const isSettingsDirty = () => {
    const s = state.settings;
    if (!s.baseline || !s.draft) return false;
    return stableJson(s.draft) !== stableJson(s.baseline);
  };

  function renderTabs() {
    const icons = {overview:'dashboard',theme:'custom',assets:'storage_files',terminals:'policy_terminal_groups',notice:'notification_center',apps:'plugin_market',upgrade:'refresh',events:'log_center',settings:'system'};
    return `<aside class="tvhome-rail dwrt-rail"><div class="dwrt-rail-brand"><img src="/static/images/logo-wide.png" alt="DreamingOS"></div><nav class="dwrt-rail-list" aria-label="TV 桌面管理">${TABS.map(tab=>`<button class="dwrt-rail-item ${state.tab===tab.id?'is-active':''}" type="button" data-tv-tab="${tab.id}" title="${tab.label}" aria-label="${tab.label}" aria-current="${state.tab===tab.id?'page':'false'}"><span class="dwrt-rail-item-icon" aria-hidden="true">${window.DWRT_MENU_ICON?.[icons[tab.id]] || window.DWRT_MENU_ICON?.monitor || ''}</span><span class="dwrt-rail-item-text"><span class="dwrt-rail-item-title">${tab.label}</span></span></button>`).join('')}</nav></aside>`;
  }

  function renderSkeleton(title, desc, pkg) {
    return `<div class="tvhome-panel dwrt-kit-glass-surface">
      <div class="tvhome-panel-head"><h2>${escapeHtml(title)}</h2>${badge(pkg || '骨架', 'muted')}</div>
      ${statePanel({ title: '暂未开放', desc, tone: 'info' })}
      
    </div>`;
  }
  // ---- 渲染：概览 ----
  const loadingPanel = (text) => `<div class="tvhome-panel dwrt-kit-glass-surface"><div class="tvhome-loading" role="status">${escapeHtml(text || '加载中…')}</div></div>`;

  const capabilitySummaryMarkup = () => {
    const caps = state.themes.capabilities || defaultCapabilities();
    const rows = CONTENT_MODULES.map((m) => {
      const c = caps[m] || {};
      const usable = capabilityUsable(m);
      const tone = usable ? 'ok' : 'muted';
      const text = usable ? '可用' : (ERROR_TEXT[c.reason] || 'provider 未接通');
      return `<li class="tvhome-cap-row"><span class="tvhome-cap-name">${escapeHtml(MODULE_LABELS[m] || m)}</span>${badge(text, tone)}</li>`;
    }).join('');
    return `<div class="tvhome-cap-panel dwrt-kit-glass-surface">
      <div class="tvhome-panel-head"><h2>内容能力</h2></div>
      <p class="tvhome-note">内容服务接通并获得授权后，对应入口才会开放。</p>
      <ul class="tvhome-cap-list">${rows}</ul>
    </div>`;
  };

  function renderOverview() {
    const o = state.overview;
    if (o.loading) return loadingPanel('概览加载中…');
    const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : '—');
    const jumps = `<div class="tvhome-jump-row">
      <button class="dwrt-kit-btn" type="button" data-tv-tab="terminals">终端与分组</button>
      <button class="dwrt-kit-btn" type="button" data-tv-tab="theme">主题设计</button>
      <button class="dwrt-kit-btn" type="button" data-tv-tab="upgrade">TV 桌面升级</button>
      <button class="dwrt-kit-btn" type="button" data-tv-tab="events">事件与诊断</button>
    </div>`;
    if (o.error) {
      return `<div class="tvhome-panel dwrt-kit-glass-surface">
        <div class="tvhome-panel-head"><h2>概览</h2>${badge('服务未就绪', 'warn')}</div>
        ${statePanel({ title: '概览计数暂不可用', desc: o.error, tone: 'warn' })}
        <p class="tvhome-note">计数需后端 A/overview（connected≠online）；后端未接通时不臆造数字。</p>
        ${jumps}</div>${capabilitySummaryMarkup()}`;
    }
    const d = o.data || {};
    const cards = [
      { key: 'terminals', label: '终端总数', value: num(d.terminals?.total), tone: 'info', detail: '档案数（删除≠停用身份）' },
      { key: 'online', label: '心跳在线', value: num(d.terminals?.online), tone: 'ok', detail: '最近心跳在有效期内' },
      { key: 'connected', label: 'WS 连接', value: d.ws?.supported ? num(d.ws.connected) : '暂不可用', tone: 'neutral', detail: '实际推送连接' },
      { key: 'themes', label: '主题数', value: num(d.themes?.total), tone: 'info', detail: d.default_theme_id ? `默认 ${d.default_theme_id}` : '默认 —' },
      { key: 'config', label: '配置版本', value: num(d.config_version ?? d.version), tone: 'neutral', detail: '已保存≠已应用' }
    ];
    const cardsMarkup = ui.overviewCardsMarkup ? ui.overviewCardsMarkup(cards, { className: 'tvhome-overview', label: 'TVHome 概览' })
      : `<div class="dwrt-kit-overview-grid">${cards.map((c) => `<div class="dwrt-kit-overview-card"><span class="k">${escapeHtml(c.label)}</span><b class="v">${escapeHtml(String(c.value))}</b><span class="d">${escapeHtml(c.detail)}</span></div>`).join('')}</div>`;
    return `<div class="tvhome-panel dwrt-kit-glass-surface">
      <div class="tvhome-panel-head"><h2>概览</h2>${badge('已连接后端', 'ok')}</div>
      ${cardsMarkup}${jumps}</div>${capabilitySummaryMarkup()}`;
  }
  // ---- 渲染：主题设计（列表 + 16:9 预览画布 + 属性面板 + Savebar） ----
  const draftSpec = () => state.themes.draft;
  const canWrite = () => writeAllowed();

  function themeListMarkup() {
    const t = state.themes;
    const rows = t.list.map((th) => {
      const active = th.id === t.activeId;
      const rev = th._fixture ? 'fixture' : `rev ${Number(th.revision) || 0}`;
      const meta = `${th.enabled===false?'已停用 · ':''}${th.style || ''}${th.is_default ? ' · 默认' : ''} · ${rev}${Number(th.usage_count) ? ' · 引用' + th.usage_count : ''}`;
      return `<button class="tvhome-theme-row ${active ? 'is-active' : ''}" type="button" data-tv-theme="${escapeHtml(th.id)}" aria-pressed="${active}">
        <span class="tvhome-theme-name">${escapeHtml(th.name || th.id)}</span>
        <span class="tvhome-theme-meta">${escapeHtml(meta)}</span>
      </button>`;
    }).join('');
    const note = t.usingFixtures
      ? statePanel({ title: '正在使用内建预览 fixture', desc: `${t.error || '后端 A/themes 未接通'}：下列为明确标注的 fixture，用于演示编辑器与 Web/TV 一致性（F04）；保存需后端接通。`, tone: 'warn' })
      : '';
    return `<aside class="tvhome-theme-list dwrt-kit-glass-surface">
      <div class="tvhome-panel-head"><h2>主题</h2><button class="dwrt-kit-btn is-small" type="button" data-tv-theme-new ${canWrite() ? '' : 'disabled'}>新建</button></div>
      <label class="tvhome-field">导入主题 JSON<input type="file" accept="application/json,.json" data-tv-theme-file ${canWrite()?'':'disabled'}></label><button class="dwrt-kit-btn" data-tv-theme-import ${canWrite()?'':'disabled'}>导入已选择的文件</button>
      <p class="tvhome-note" data-tv-theme-filename>${escapeHtml(t.importFile?.name||'JSON 不包含素材文件')}</p>
      ${note}
      <div class="tvhome-theme-rows" role="list">${rows || statePanel({ title: '暂无主题', tone: 'info' })}</div>
    </aside>`;
  }

  function themeToolbar() {
    const t = state.themes;
    const row = t.list.find((x) => x.id === t.activeId) || {};
    const dirty = isThemeDirty();
    const style = draftSpec() ? draftSpec().style : '';
    return `<div class="tvhome-canvas-toolbar dwrt-kit-table-toolbar">
      <label class="tvhome-field tvhome-field-name"><span>名称</span>
        <input type="text" class="dwrt-kit-input" data-tv-theme-name value="${escapeHtml(t.name || '')}" ${canWrite() ? '' : 'disabled'} /></label>
      <label class="tvhome-field"><span>首页样式</span>
        <select class="dwrt-kit-input" data-tv-theme-style ${canWrite() ? '' : 'disabled'}>
          <option value="flow" ${style === 'flow' ? 'selected' : ''}>flow 瀑布</option>
          <option value="grid" ${style === 'grid' ? 'selected' : ''}>grid 磁贴</option>
        </select></label>
      <div class="tvhome-toolbar-spacer"></div>
      <div class="tvhome-view-toggle" role="group" aria-label="视图">
        <button class="dwrt-kit-btn is-small ${t.view === 'visual' ? 'is-active' : ''}" type="button" data-tv-view-mode="visual">可视化</button>
        <button class="dwrt-kit-btn is-small ${t.view === 'json' ? 'is-active' : ''}" type="button" data-tv-view-mode="json">JSON</button>
      </div>
      <button class="dwrt-kit-btn is-small" type="button" data-tv-theme-validate>校验</button>
      <button class="dwrt-kit-btn is-small" type="button" data-tv-theme-preview>预览规范化</button>
      <button class="dwrt-kit-btn is-small" type="button" data-tv-theme-duplicate ${canWrite() ? '' : 'disabled'}>复制</button>
      <button class="dwrt-kit-btn is-small" type="button" data-tv-theme-default ${canWrite() && !row.is_default ? '' : 'disabled'}>设默认</button>
      <button class="dwrt-kit-btn is-small is-danger" type="button" data-tv-theme-delete ${canWrite() && !row.is_default ? '' : 'disabled'}>删除</button>
      <button class="dwrt-kit-btn is-small" data-tv-theme-undo ${(t.history?.length||0)>1?'':'disabled'}>撤销一步</button>
      <button class="dwrt-kit-btn is-small" data-tv-theme-redo ${t.redo?.length?'':'disabled'}>重做</button>
      <button class="dwrt-kit-btn is-small" data-tv-theme-export ${t.usingFixtures?'disabled':''}>导出已保存主题</button>
      <button class="dwrt-kit-btn is-small" data-tv-theme-toggle ${canWrite()&&!row.is_default&&!dirty&&!t.usingFixtures?'':'disabled'}>${row.enabled===false?'启用':'停用'}</button>
      ${row.builtin?`<button class="dwrt-kit-btn is-small" data-tv-theme-reset ${canWrite()&&!dirty?'':'disabled'}>恢复内置主题</button>`:''}
      <span data-tv-dirty>${dirty ? badge('未保存', 'warn') : ''}</span>
    </div>`;
  }
  function themeJsonView() {
    const json = JSON.stringify(draftSpec() || {}, null, 2);
    return `<div class="tvhome-json-view">
      <p class="tvhome-note">JSON 为辅助只读视图（可视化编辑为主，不取代）；规范化由后端权威，此处不自补另一套默认值。</p>
      <pre class="tvhome-json"><code>${escapeHtml(json)}</code></pre></div>`;
  }

  function themeSavebar() {
    const t = state.themes;
    if (t.usingFixtures) {
      const dirty = isThemeDirty();
      return `<div class="tvhome-inline-savebar dwrt-kit-glass-surface"><span>${escapeHtml(dirty ? 'fixture 预览有未保存更改' : 'fixture 预览模式')}</span>${badge('保存需后端接通', 'muted')}<button class="dwrt-kit-btn is-small" type="button" data-tv-theme-revert ${dirty ? '' : 'disabled'}>还原 fixture</button></div>`;
    }
    if (!t.baseline) return '';
    const dirty = isThemeDirty();
    const issues = gridIssues(draftSpec());
    const message = t.msg || (issues.length ? `布局问题：${issues[0]}` : (dirty ? '有未保存更改' : '已是最新'));
    return ui.floatingSavebarMarkup ? ui.floatingSavebarMarkup({
      visible: dirty || !!t.msg, busy: t.saving, disabled: !dirty || issues.length > 0 || !canWrite(),
      message, discardLabel: '撤销更改', saveLabel: '保存主题'
    }) : `<div class="tvhome-inline-savebar dwrt-kit-glass-surface"><span>${escapeHtml(message)}</span>
        <button class="dwrt-kit-btn is-small" type="button" data-dwrt-savebar-discard ${dirty ? '' : 'disabled'}>撤销更改</button>
        <button class="dwrt-kit-btn is-small is-primary" type="button" data-dwrt-savebar-save ${dirty && !issues.length && canWrite() ? '' : 'disabled'}>保存主题</button></div>`;
  }

  function renderThemeTab() {
    const t = state.themes;
    if (t.loading) return loadingPanel('主题加载中…');
    if (!t.draft && !t.list.length) {
      return `<div class="tvhome-panel dwrt-kit-glass-surface">${statePanel({ title: t.error ? '主题加载失败' : '暂无主题', desc: t.error || '创建一个主题开始配置电视桌面。', tone: t.error ? 'warn' : 'info' })}${operationButton('新建主题','data-tv-theme-new','',!t.error)}<button class="dwrt-kit-btn" data-tv-fixtures>打开示例预览</button></div>`;
    }
    const center = !t.draft ? statePanel({ title: '请选择主题', tone: 'info' }) : (t.view === 'json' ? themeJsonView() : renderThemeCanvas(draftSpec()));
    const issues = t.draft ? gridIssues(draftSpec()) : [];
    const issuesMarkup = issues.length
      ? `<b>布局校验（客户端提示，最终以后端为准）：</b><ul>${issues.map((i) => `<li>${escapeHtml(i)}</li>`).join('')}</ul>`
      : '';
    return `<div class="tvhome-editor-panels"><button class="dwrt-kit-btn" data-tv-editor-panel="list">主题列表</button><button class="dwrt-kit-btn" data-tv-editor-panel="canvas">画布</button><button class="dwrt-kit-btn" data-tv-editor-panel="properties">属性</button></div><div class="tvhome-theme-workspace" data-editor-panel="${state.themes.panel || 'canvas'}">
      ${themeListMarkup()}
      <section class="tvhome-canvas-panel dwrt-kit-glass-surface">
        ${themeToolbar()}
        <div class="tvhome-canvas-scroll" data-tv-canvas-scroll>${center}</div>
        <div class="tvhome-issues" role="alert" data-tv-issues>${issuesMarkup}</div>
      </section>
      <aside class="tvhome-prop-panel dwrt-kit-glass-surface" data-tv-prop>${renderPropertyPanel()}</aside>
    </div><div data-tv-savebar>${themeSavebar()}</div>`;
  }
  // ---- 共享 flow/grid 预览渲染器（F04：同一 fixture 在 Web 与 TV 字段含义/磁贴位置/来源一致） ----
  // 画布=TV 屏模拟，消费主题字面 token；动态源/未接通 provider 一律空态或禁用态，绝不 SampleCard。
  function renderThemeCanvas(spec) {
    if (!isObject(spec)) return statePanel({ title: '无 spec', tone: 'warn' });
    const styleVars = canvasStyleVars(spec.tokens);
    const home = spec.style === 'grid' ? renderCanvasGrid(spec.home) : renderCanvasFlow(spec.home);
    return `<div class="tvhome-canvas" style="${styleVars}" data-tv-canvas data-style="${escapeHtml(spec.style || 'flow')}">
      ${renderCanvasBackground(spec.background)}
      <div class="tvhome-canvas-inner">
        ${renderCanvasHeader(spec.header)}
        <div class="tvhome-canvas-body">
          ${renderCanvasNav(spec.nav)}
          <div class="tvhome-canvas-home">${home}</div>
        </div>
      </div>
      <div class="tvhome-canvas-tag">16:9 预览 · ${escapeHtml(spec.style || 'flow')}</div>
    </div>`;
  }

  function renderCanvasBackground(bg) {
    const b = isObject(bg) ? bg : { mode: 'color' };
    const dim = clampNum(b.dim, 0, 1, 0);
    let label = '背景：纯色'; let refs = '';
    if (b.mode === 'slideshow') { label = `背景：轮播 ${b.intervalSec || 30}s/${b.effect || 'fade'}`; refs = asArray(b.assetIds).join(' · ') || (b.photoQuery || ''); }
    else if (b.mode === 'static') { label = '背景：静态图'; refs = b.assetId || b.photoId || ''; }
    else if (b.mode === 'video') { label = `背景：视频${b.mute ? '/静音' : ''}${b.loop ? '/循环' : ''}`; refs = b.assetId || ''; }
    else if (b.mode === 'photos') { label = `背景：媒体照片 ${b.intervalSec || 30}s`; refs = b.photoQuery || ''; }
    const nonColor = b.mode && b.mode !== 'color';
    return `<div class="tvhome-canvas-bg"></div>
      ${dim > 0 ? `<div class="tvhome-canvas-dim" style="opacity:${dim}"></div>` : ''}
      ${nonColor ? `<div class="tvhome-canvas-bg-note">${escapeHtml(label)}${refs ? ` · 素材未接通：${escapeHtml(refs)}` : ''}</div>` : ''}`;
  }

  function renderCanvasHeader(header) {
    const h = isObject(header) ? header : {};
    const chips = [];
    if (h.clock) chips.push('12:00');
    if (h.date) chips.push('周一');
    return `<div class="tvhome-canvas-header">
      <span class="tvhome-canvas-brand">TVHome</span>
      <div class="tvhome-canvas-hchips">${chips.map((c) => `<span class="tvhome-chip">${escapeHtml(c)}</span>`).join('')}${h.weather ? '<span class="tvhome-chip is-muted">天气未接通</span>' : ''}</div>
    </div>`;
  }

  function renderCanvasNav(nav) {
    const sel = state.themes.selection;
    const items = asArray(nav).map((it) => {
      const active = sel && sel.kind === 'nav' && sel.id === it.id;
      const disabled = it.type === 'module' && !SHELL_MODULES.has(it.module) && !capabilityUsable(it.module);
      const cls = `tvhome-nav-item${it.hidden ? ' is-hidden' : ''}${disabled ? ' is-disabled' : ''}${active ? ' is-selected' : ''}`;
      const flag = it.hidden ? '<span class="tvhome-nav-flag">隐藏</span>' : (disabled ? '<span class="tvhome-nav-flag">未接通</span>' : '');
      return `<button class="${cls}" type="button" data-tv-select="nav:${escapeHtml(it.id)}" title="${escapeHtml(it.label || '')}"><span class="tvhome-nav-label">${escapeHtml(it.label || it.id)}</span>${flag}</button>`;
    }).join('');
    return `<nav class="tvhome-canvas-nav" aria-label="TV 导航">${items || '<span class="tvhome-empty">无导航项</span>'}</nav>`;
  }
  const SOURCE_LABELS = { manual: '手工', continueWatching: '继续观看', liveNow: '正在直播', recentPhotos: '最近照片', recentAdded: '最近添加', playlists: '歌单', apps: '应用', cameras: '摄像机' };
  const SOURCE_PROVIDER = { continueWatching: 'vod', liveNow: 'live', recentPhotos: 'photos', recentAdded: 'vod', playlists: 'music', apps: 'apps', cameras: 'nvr' };

  function renderCanvasFlow(home) {
    const sections = asArray(isObject(home) ? home.sections : null);
    if (!sections.length) return '<div class="tvhome-empty">flow 无 section</div>';
    return `<div class="tvhome-flow">${sections.map(renderFlowSection).join('')}</div>`;
  }

  function renderFlowSection(sec) {
    const sel = state.themes.selection;
    const active = sel && sel.kind === 'section' && sel.id === sec.id;
    const title = sec.title || SOURCE_LABELS[sec.source] || sec.type;
    let body;
    if (sec.source === 'manual') {
      const tiles = asArray(sec.tiles);
      body = tiles.length
        ? `<div class="tvhome-flow-tiles cs-${escapeHtml(sec.cardStyle || 'poster')}">${tiles.map((t) => renderTile(t, sec.id)).join('')}</div>`
        : '<div class="tvhome-empty">手工 section 无磁贴</div>';
    } else {
      const prov = SOURCE_PROVIDER[sec.source];
      const usable = prov ? capabilityUsable(prov) : false;
      body = usable
        ? '<div class="tvhome-flow-empty" role="note">已接通 · 运行时载入真实数据（预览不模拟）</div>'
        : `<div class="tvhome-flow-empty" role="note">动态源「${escapeHtml(SOURCE_LABELS[sec.source] || sec.source)}」· provider（${escapeHtml(MODULE_LABELS[prov] || prov || '未知')}）未接通 · 空态，不填样例卡片</div>`;
    }
    return `<section class="tvhome-flow-section ${active ? 'is-selected' : ''}" data-tv-select="section:${escapeHtml(sec.id)}">
      <header class="tvhome-flow-head"><span class="tvhome-flow-title">${escapeHtml(title)}</span>
        <span class="tvhome-flow-src">${escapeHtml(sec.type)} · ${escapeHtml(sec.source || '')}${sec.limit ? ' · limit ' + sec.limit : ''}</span></header>
      ${body}
    </section>`;
  }

  function tileInner(tile) {
    const label = tile.label || '';
    switch (tile.kind) {
      case 'module': {
        const usable = SHELL_MODULES.has(tile.module) || capabilityUsable(tile.module);
        return `<span class="tvhome-tile-k">${escapeHtml(MODULE_LABELS[tile.module] || tile.module || '模块')}</span>${usable ? '' : '<span class="tvhome-tile-flag">未接通</span>'}`;
      }
      case 'app': return `<span class="tvhome-tile-k">${escapeHtml(label || '应用')}</span><span class="tvhome-tile-sub">${escapeHtml(tile.appPackage || '')}</span>`;
      case 'weblink': return `<span class="tvhome-tile-k">${escapeHtml(label || '网页')}</span><span class="tvhome-tile-sub">${escapeHtml(tile.url || '')}</span>`;
      case 'liveWindow': return `<span class="tvhome-tile-k">${escapeHtml(label || '直播窗')}</span><span class="tvhome-tile-flag">直播未接通</span>`;
      case 'nvrWindow': return `<span class="tvhome-tile-k">${escapeHtml(label || '监控窗')}</span><span class="tvhome-tile-flag">监控未接通</span>`;
      case 'photoCarousel': return `<span class="tvhome-tile-k">${escapeHtml(label || '相册')}</span><span class="tvhome-tile-flag">相册未接通</span>`;
      case 'banner': return `<span class="tvhome-tile-k">横幅</span><span class="tvhome-tile-sub">${escapeHtml(tile.image || '')} · 素材未接通</span>`;
      case 'clockCard': return '<span class="tvhome-tile-k">时钟</span>';
      case 'weatherCard': return '<span class="tvhome-tile-k">天气</span><span class="tvhome-tile-flag">未接通</span>';
      case 'calendar': return '<span class="tvhome-tile-k">日历</span>';
      case 'text': return `<span class="tvhome-tile-text">${escapeHtml(label)}</span>`;
      default: return `<span class="tvhome-tile-k">${escapeHtml(tile.kind || '磁贴')}</span>`;
    }
  }

  function renderTile(tile, ownerId) {
    const sel = state.themes.selection;
    const active = sel && sel.kind === 'tile' && sel.id === tile.id;
    return `<button class="tvhome-tile cardstyle ${active ? 'is-selected' : ''}" type="button" data-tv-select="tile:${escapeHtml(tile.id)}" data-tv-owner="${escapeHtml(ownerId || '')}">${tileInner(tile)}</button>`;
  }
  function renderGridTile(tile, ownerId, cols, rows) {
    const sel = state.themes.selection;
    const active = sel && sel.kind === 'tile' && sel.id === tile.id;
    const x = clampNum(tile.x, 0, cols - 1, 0), y = clampNum(tile.y, 0, rows - 1, 0);
    const w = clampNum(tile.w, 1, cols, 1), h = clampNum(tile.h, 1, rows, 1);
    const gs = `grid-column:${x + 1}/span ${w};grid-row:${y + 1}/span ${h}`;
    return `<button class="tvhome-tile tvhome-grid-tile ${active ? 'is-selected' : ''}" style="${gs}" type="button" data-tv-select="tile:${escapeHtml(tile.id)}" data-tv-owner="${escapeHtml(ownerId || '')}">${tileInner(tile)}</button>`;
  }

  function renderCanvasGrid(home) {
    const h = isObject(home) ? home : {};
    const cols = clampNum(h.columns, 4, 24, 12);
    const rows = clampNum(h.rows, 2, 12, 6);
    const pages = asArray(h.pages);
    if (!pages.length) return '<div class="tvhome-empty">grid 无页</div>';
    const pageIdx = Math.min(Math.max(0, state.themes.page || 0), pages.length - 1);
    const page = pages[pageIdx] || pages[0];
    const pageTabs = pages.map((p, i) => `<button class="tvhome-page-tab ${i === pageIdx ? 'is-active' : ''}" type="button" data-tv-page="${i}">${escapeHtml(p.label || p.id)}</button>`).join('');
    const gridStyle = `grid-template-columns:repeat(${cols},1fr);grid-template-rows:repeat(${rows},1fr)`;
    const tiles = asArray(page.tiles).map((t) => renderGridTile(t, page.id, cols, rows)).join('');
    const dock = asArray(h.dock);
    const sel = state.themes.selection;
    const dockMarkup = dock.length
      ? `<div class="tvhome-dock" aria-label="dock">${dock.map((t) => `<button class="tvhome-dock-item ${sel && sel.kind === 'dock' && sel.id === t.id ? 'is-selected' : ''}" type="button" data-tv-select="dock:${escapeHtml(t.id)}">${escapeHtml(MODULE_LABELS[t.module] || t.module || t.label || t.id)}</button>`).join('')}</div>`
      : '';
    return `<div class="tvhome-grid-wrap">
      <div class="tvhome-page-tabs" role="tablist">${pageTabs}<span class="tvhome-grid-meta">${cols}×${rows}</span></div>
      <div class="tvhome-grid" style="${gridStyle}">${tiles || '<span class="tvhome-empty">本页无磁贴</span>'}</div>
      ${dockMarkup}
    </div>`;
  }
  // ---- 渲染：属性面板（编辑只改 draft，input 即时重绘预览，不动 baseline） ----
  const editInput = (key, value, type, attrs) => `<input class="dwrt-kit-input" type="${type || 'text'}" data-tv-edit="${escapeHtml(key)}" value="${escapeHtml(String(value ?? ''))}" ${attrs || ''} ${canWrite() ? '' : 'disabled'} />`;
  const editColor = (key, value) => `<span class="tvhome-color-field"><input class="tvhome-color" type="color" data-tv-edit="${escapeHtml(key)}" value="${escapeHtml(safeColor(value, '#000000'))}" ${canWrite() ? '' : 'disabled'} /><input class="dwrt-kit-input tvhome-hex" type="text" data-tv-edit="${escapeHtml(key)}" value="${escapeHtml(String(value ?? ''))}" ${canWrite() ? '' : 'disabled'} /></span>`;
  const editSelect = (key, value, options) => `<select class="dwrt-kit-input" data-tv-edit="${escapeHtml(key)}" ${canWrite() ? '' : 'disabled'}>${options.map((o) => `<option value="${escapeHtml(o.value)}" ${String(value) === String(o.value) ? 'selected' : ''}>${escapeHtml(o.label)}</option>`).join('')}</select>`;
  const editToggle = (key, checked, labelText) => `<label class="tvhome-toggle"><input type="checkbox" data-tv-edit="${escapeHtml(key)}" ${checked ? 'checked' : ''} ${canWrite() ? '' : 'disabled'} /><span>${escapeHtml(labelText)}</span></label>`;
  const propField = (labelText, control) => `<label class="tvhome-field tvhome-prop-field"><span>${escapeHtml(labelText)}</span>${control}</label>`;

  function propHeader() {
    const sel = state.themes.selection || { kind: 'appearance' };
    const tabs = [['appearance', '外观'], ['navlist', '导航']];
    const btns = tabs.map(([k, l]) => `<button class="dwrt-kit-btn is-small ${sel.kind === k || (k === 'navlist' && sel.kind === 'nav') ? 'is-active' : ''}" type="button" data-tv-prop-tab="${k}">${l}</button>`).join('');
    let crumb = '';
    if (sel.kind === 'section') crumb = `当前：flow section「${escapeHtml(sel.id)}」`;
    else if (sel.kind === 'tile') crumb = `当前：磁贴「${escapeHtml(sel.id)}」`;
    else if (sel.kind === 'dock') crumb = `当前：dock「${escapeHtml(sel.id)}」`;
    else if (sel.kind === 'nav') crumb = `当前：导航项「${escapeHtml(sel.id)}」`;
    return `<div class="tvhome-prop-head"><h2>属性</h2><div class="tvhome-prop-tabs">${btns}</div>${crumb ? `<p class="tvhome-prop-crumb">${crumb}</p>` : ''}</div>`;
  }

  function renderPropertyPanel() {
    const spec = draftSpec();
    if (!spec) return `${'<div class="tvhome-prop-head"><h2>属性</h2></div>'}${statePanel({ title: '未选择主题', tone: 'info' })}`;
    const sel = state.themes.selection || { kind: 'appearance' };
    let body;
    switch (sel.kind) {
      case 'navlist': body = propNavList(spec); break;
      case 'nav': body = propNavItem(spec, sel.id); break;
      case 'section': body = propSection(spec, sel.id); break;
      case 'tile': body = propTile(spec, sel.id); break;
      case 'dock': body = propDockTile(spec, sel.id); break;
      default: body = propAppearance(spec);
    }
    return `${propHeader()}<div class="tvhome-prop-body">${body}</div>`;
  }
  function propAppearance(spec) {
    const t = isObject(spec.tokens) ? spec.tokens : {};
    const bg = isObject(spec.background) ? spec.background : { mode: 'color' };
    const ss = isObject(spec.screensaver) ? spec.screensaver : { enabled: false };
    const hd = isObject(spec.header) ? spec.header : {};
    const par = isObject(spec.parental) ? spec.parental : {};
    const locked = asArray(par.lockedModules);
    const tokenBlock = `<section class="tvhome-prop-group"><h3>令牌 tokens</h3>
      ${propField('背景 colorBackground', editColor('token:colorBackground', t.colorBackground))}
      ${propField('表面 colorSurface', editColor('token:colorSurface', t.colorSurface))}
      ${propField('主色 colorPrimary', editColor('token:colorPrimary', t.colorPrimary))}
      ${propField('前景 foreground', editColor('token:foreground', t.foreground))}
      ${propField('焦点色 focusColor（留空跟随主色）', editColor('token:focusColor', t.focusColor))}
      ${propField('圆角 radius (0-48)', editInput('token:radius', t.radius, 'number', 'min="0" max="48" step="1"'))}
      ${propField('字号比 fontScale (0.85-1.4)', editInput('token:fontScale', t.fontScale, 'number', 'min="0.85" max="1.4" step="0.05"'))}
      ${propField('模糊 blur (0-48)', editInput('token:blur', t.blur, 'number', 'min="0" max="48" step="1"'))}
      ${propField('焦点缩放 focusScale (1.0-1.2)', editInput('token:focusScale', t.focusScale, 'number', 'min="1" max="1.2" step="0.01"'))}</section>`;
    const bgModes = [['color', '纯色'], ['static', '静态图（素材）'], ['slideshow', '幻灯片（素材）'], ['video', '视频（素材）'], ['photos', '相册（未接通）']];
    let bgExtra = '';
    if (bg.mode === 'color') bgExtra = propField('颜色 color', editColor('bg:color', bg.color));
    else if (bg.mode === 'static') bgExtra = propField('素材 assetId', editInput('bg:assetId', bg.assetId, 'text', 'placeholder="asset-…"'));
    else if (bg.mode === 'slideshow') bgExtra = `${propField('素材集 assetIds（逗号分隔）', editInput('bg:assetIds', asArray(bg.assetIds).join(','), 'text', 'placeholder="asset-1,asset-2"'))}${propField('间隔秒 intervalSec', editInput('bg:intervalSec', bg.intervalSec, 'number', 'min="1" step="1"'))}${propField('切换特效 effect', editSelect('bg:effect', bg.effect || 'fade', [{ value: 'fade', label: 'fade' }, { value: 'none', label: 'none' }, { value: 'slide', label: 'slide' }]))}`;
    else if (bg.mode === 'video') bgExtra = propField('素材 assetId', editInput('bg:assetId', bg.assetId, 'text', 'placeholder="asset-…"'));
    else if (bg.mode === 'photos') bgExtra = `<p class="tvhome-note">相册背景依赖照片 provider，Package A 未接通，运行时呈现空态。</p>${propField('查询 photoQuery', editInput('bg:photoQuery', bg.photoQuery, 'text', 'placeholder="album:客厅"'))}`;
    const bgBlock = `<section class="tvhome-prop-group"><h3>背景 background</h3>
      ${propField('模式 mode', editSelect('bg:mode', bg.mode || 'color', bgModes.map(([value, label]) => ({ value, label }))))}
      ${bgExtra}
      ${propField('压暗 dim (0-0.8)', editInput('bg:dim', bg.dim, 'number', 'min="0" max="0.8" step="0.05"'))}</section>`;
    const ssModes = [['clock', '时钟'], ['blank', '黑屏'], ['photos', '相册（未接通）'], ['video', '视频（素材）']];
    const ssBlock = `<section class="tvhome-prop-group"><h3>屏保 screensaver</h3>
      ${propField('', editToggle('ss:enabled', !!ss.enabled, '启用屏保'))}
      ${propField('模式 mode', editSelect('ss:mode', ss.mode || 'clock', ssModes.map(([value, label]) => ({ value, label }))))}
      ${propField('空闲分钟 idleMinutes', editInput('ss:idleMinutes', ss.idleMinutes, 'number', 'min="1" step="1"'))}
      ${ss.mode === 'photos' ? propField('相册查询 photoQuery', editInput('ss:photoQuery', ss.photoQuery, 'text', 'placeholder="album:…"')) + propField('间隔秒 intervalSec', editInput('ss:intervalSec', ss.intervalSec, 'number', 'min="1" step="1"')) : ''}
      ${ss.mode === 'video' ? propField('素材 assetId', editInput('ss:assetId', ss.assetId, 'text', 'placeholder="asset-…"')) : ''}</section>`;
    const hdBlock = `<section class="tvhome-prop-group"><h3>顶栏 header</h3>
      ${propField('', editToggle('hd:clock', hd.clock !== false, '时钟'))}
      ${propField('', editToggle('hd:date', hd.date !== false, '日期'))}
      ${propField('', editToggle('hd:weather', !!hd.weather, '天气（provider 未接通，仅占位）'))}</section>`;
    const parBlock = `<section class="tvhome-prop-group"><h3>家长锁 parental.lockedModules</h3>
      <div class="tvhome-lock-grid">${CONTENT_MODULES.map((m) => `<label class="tvhome-toggle"><input type="checkbox" data-tv-lock="${m}" ${locked.includes(m) ? 'checked' : ''} ${canWrite() ? '' : 'disabled'} /><span>${escapeHtml(MODULE_LABELS[m] || m)}</span></label>`).join('')}</div>
      <p class="tvhome-note">PIN 验证尚未配置；选中的入口在 TV 端保持不可用。</p></section>`;
    let layoutBlock = '';
    if (spec.style === 'grid' && isObject(spec.home)) {
      layoutBlock = `<section class="tvhome-prop-group"><h3>栅格 layout</h3>
        ${propField('列 columns (4-24)', editInput('root:columns', spec.home.columns, 'number', 'min="4" max="24" step="1"'))}
        ${propField('行 rows (2-12)', editInput('root:rows', spec.home.rows, 'number', 'min="2" max="12" step="1"'))}
        <p class="tvhome-note">改变列/行不会移动既有磁贴；越界磁贴会在校验中报错，请到画布逐页调整。</p></section>`;
    }
    return `${tokenBlock}${bgBlock}${ssBlock}${hdBlock}${parBlock}${layoutBlock}${state.themes.usingFixtures?inheritDemoMarkup():''}`;
  }
  const NAV_TYPES = [{ value: 'module', label: '模块' }, { value: 'page', label: '自定义页' }, { value: 'app', label: '应用' }, { value: 'weblink', label: '网页' }];
  const SECTION_TYPES = [{ value: 'hero', label: 'hero 主推' }, { value: 'row', label: 'row 横排' }, { value: 'tiles', label: 'tiles 磁贴组' }];
  const SECTION_SOURCES = [{ value: 'manual', label: '手工' }, { value: 'continueWatching', label: '继续观看' }, { value: 'liveNow', label: '正在直播' }, { value: 'recentPhotos', label: '最近照片' }, { value: 'recentAdded', label: '最近添加' }, { value: 'playlists', label: '歌单' }, { value: 'apps', label: '应用' }, { value: 'cameras', label: '摄像机' }];
  const CARD_STYLES = [{ value: 'poster', label: 'poster' }, { value: 'wide', label: 'wide' }, { value: 'square', label: 'square' }, { value: 'banner', label: 'banner' }];
  const TILE_KINDS = ['module', 'app', 'weblink', 'liveWindow', 'nvrWindow', 'photoCarousel', 'banner', 'clockCard', 'weatherCard', 'calendar', 'text'].map((v) => ({ value: v, label: v }));
  const MODULE_OPTIONS = ['home', 'search', 'settings', 'live', 'vod', 'music', 'photos', 'files', 'nvr', 'apps'].map((v) => ({ value: v, label: `${MODULE_LABELS[v] || v} (${v})` }));

  function findTile(spec, id) {
    const home = isObject(spec) ? spec.home : null;
    if (!isObject(home)) return null;
    for (const sec of asArray(home.sections)) { for (const t of asArray(sec.tiles)) if (t && t.id === id) return t; }
    for (const pg of asArray(home.pages)) { for (const t of asArray(pg.tiles)) if (t && t.id === id) return t; }
    for (const t of asArray(home.dock)) if (t && t.id === id) return t;
    return null;
  }
  function findSection(spec, id) {
    const home = isObject(spec) ? spec.home : null;
    if (!isObject(home)) return null;
    return asArray(home.sections).find((s) => s && s.id === id) || null;
  }

  function inheritDemoMarkup() {
    const inp = FIXTURE_INHERIT.input || {}; const res = FIXTURE_INHERIT.resolved || {};
    const cell = (v) => v == null ? '<i>null（继承）</i>' : escapeHtml(typeof v === 'object' ? JSON.stringify(v) : String(v));
    const row = (label, th, gr, tm) => `<tr><th>${escapeHtml(label)}</th><td>${cell(th)}</td><td>${cell(gr)}</td><td>${cell(tm)}</td></tr>`;
    return `<section class="tvhome-prop-group tvhome-inherit"><h3>继承演示（§8：终端 &gt; 分组 &gt; 主题，逐字段 firstNonNull）</h3>
      <table class="tvhome-mini-table"><thead><tr><th>字段</th><th>主题</th><th>分组</th><th>终端</th></tr></thead><tbody>
        ${row('background', inp.theme && inp.theme.background, inp.group && inp.group.background, inp.terminal && inp.terminal.background)}
        ${row('screensaver', inp.theme && inp.theme.screensaver, inp.group && inp.group.screensaver, inp.terminal && inp.terminal.screensaver)}
      </tbody></table>
      <p class="tvhome-note">解析结果：background 取自 <b>${escapeHtml((res.source || {}).background || '')}</b> → ${cell(res.background)}；screensaver 取自 <b>${escapeHtml((res.source || {}).screensaver || '')}</b> → ${cell(res.screensaver)}。此为只读固定演示（fixture §10.3），非当前主题字段。</p>
    </section>`;
  }

  function propNavList(spec) {
    const nav = asArray(spec.nav);
    const rows = nav.map((it, i) => {
      const disabled = it.type === 'module' && !SHELL_MODULES.has(it.module) && !capabilityUsable(it.module);
      return `<li class="tvhome-navrow ${it.hidden ? 'is-hidden' : ''}">
        <button class="tvhome-navrow-main" type="button" data-tv-select="nav:${escapeHtml(it.id)}"><span>${escapeHtml(it.label || it.id)}</span><em>${escapeHtml(it.type)}${it.hidden ? ' · 隐藏' : ''}${disabled ? ' · 未接通' : ''}</em></button>
        <span class="tvhome-navrow-ops">
          <button class="dwrt-kit-btn is-icon" type="button" data-tv-nav-move="${escapeHtml(it.id)}:up" ${i === 0 || !canWrite() ? 'disabled' : ''} title="上移">↑</button>
          <button class="dwrt-kit-btn is-icon" type="button" data-tv-nav-move="${escapeHtml(it.id)}:down" ${i === nav.length - 1 || !canWrite() ? 'disabled' : ''} title="下移">↓</button>
          <button class="dwrt-kit-btn is-icon" type="button" data-tv-nav-hide="${escapeHtml(it.id)}" ${canWrite() ? '' : 'disabled'} title="显隐">${it.hidden ? '显' : '隐'}</button>
          <button class="dwrt-kit-btn is-icon is-danger" type="button" data-tv-nav-del="${escapeHtml(it.id)}" ${canWrite() ? '' : 'disabled'} title="删除">✕</button>
        </span></li>`;
    }).join('');
    return `<section class="tvhome-prop-group"><h3>导航项（${nav.length}）</h3>
      <ul class="tvhome-navlist">${rows || '<li class="tvhome-empty">无导航项</li>'}</ul>
      <button class="dwrt-kit-btn is-small" type="button" data-tv-nav-add ${canWrite() ? '' : 'disabled'}>+ 新增导航项</button>
      <p class="tvhome-note">点击某项进入编辑；隐藏项仍在配置中但 TV 不呈现；未接通模块在 TV 端为禁用态。</p></section>`;
  }

  function propNavItem(spec, id) {
    const it = asArray(spec.nav).find((n) => n && n.id === id);
    if (!it) return statePanel({ title: '导航项不存在', tone: 'warn' });
    let typeFields = '';
    if (it.type === 'module') typeFields = propField('模块 module', editSelect(`nav:${id}:module`, it.module || 'home', MODULE_OPTIONS));
    else if (it.type === 'page') typeFields = propField('页 pageId', editInput(`nav:${id}:pageId`, it.pageId, 'text', 'placeholder="页 id"'));
    else if (it.type === 'app') typeFields = propField('应用包名 appPackage', editInput(`nav:${id}:appPackage`, it.appPackage, 'text', 'placeholder="org.example.app"'));
    else if (it.type === 'weblink') typeFields = propField('网址 url', editInput(`nav:${id}:url`, it.url, 'text', 'placeholder="https://…"'));
    return `<section class="tvhome-prop-group">
      <button class="dwrt-kit-btn is-small" type="button" data-tv-prop-tab="navlist">← 返回列表</button>
      <h3>导航项 ${escapeHtml(id)}</h3>
      ${propField('类型 type', editSelect(`nav:${id}:type`, it.type || 'module', NAV_TYPES))}
      ${propField('标签 label', editInput(`nav:${id}:label`, it.label, 'text'))}
      ${typeFields}
      ${propField('', editToggle(`nav:${id}:hidden`, !!it.hidden, '隐藏（不在 TV 呈现）'))}
      ${propField('图标 icon', editInput(`nav:${id}:icon`, it.icon, 'text', 'placeholder="可选"'))}</section>`;
  }
  function propSection(spec, id) {
    const sec = findSection(spec, id);
    if (!sec) return statePanel({ title: 'section 不存在', tone: 'warn' });
    const isManual = sec.source === 'manual';
    const prov = SOURCE_PROVIDER[sec.source];
    return `<section class="tvhome-prop-group"><h3>flow section ${escapeHtml(id)}</h3>
      ${propField('类型 type', editSelect(`sec:${id}:type`, sec.type || 'row', SECTION_TYPES))}
      ${propField('标题 title', editInput(`sec:${id}:title`, sec.title, 'text'))}
      ${propField('来源 source', editSelect(`sec:${id}:source`, sec.source || 'manual', SECTION_SOURCES))}
      ${propField('卡片样式 cardStyle', editSelect(`sec:${id}:cardStyle`, sec.cardStyle || 'poster', CARD_STYLES))}
      ${isManual ? '' : propField('数量 limit', editInput(`sec:${id}:limit`, sec.limit, 'number', 'min="1" max="50" step="1"'))}
      ${isManual
        ? `<div class="tvhome-subtiles"><b>手工磁贴（${asArray(sec.tiles).length}）</b><div class="tvhome-subtile-list">${asArray(sec.tiles).map((t) => `<button class="dwrt-kit-btn is-small" type="button" data-tv-select="tile:${escapeHtml(t.id)}">${escapeHtml(t.label || t.kind || t.id)}</button>`).join('') || '<span class="tvhome-empty">无</span>'}</div><button class="dwrt-kit-btn is-small" type="button" data-tv-sec-addtile="${escapeHtml(id)}" ${canWrite() ? '' : 'disabled'}>+ 新增磁贴</button></div>`
        : `<p class="tvhome-note">动态源由 provider（${escapeHtml(MODULE_LABELS[prov] || prov || '未知')}）在 TV 端填充；${prov && capabilityUsable(prov) ? '已接通。' : 'Package A 未接通，预览空态。'}</p>`}
    </section>`;
  }

  function propTile(spec, id) {
    const tile = findTile(spec, id);
    if (!tile) return statePanel({ title: '磁贴不存在', tone: 'warn' });
    let kindFields = '';
    switch (tile.kind) {
      case 'module': kindFields = propField('模块 module', editSelect(`tile:${id}:module`, tile.module || 'home', MODULE_OPTIONS)); break;
      case 'app': kindFields = propField('应用包名 appPackage', editInput(`tile:${id}:appPackage`, tile.appPackage, 'text', 'placeholder="org.example.app"')); break;
      case 'weblink': kindFields = propField('网址 url', editInput(`tile:${id}:url`, tile.url, 'text', 'placeholder="https://…"')) + propField('', editToggle(`tile:${id}:showLabel`, !!tile.showLabel, '显示标签 showLabel')); break;
      case 'banner': kindFields = propField('素材 image', editInput(`tile:${id}:image`, tile.image, 'text', 'placeholder="asset-…"')) + '<p class="tvhome-note">素材 provider 未接通，预览占位。</p>'; break;
      case 'liveWindow': kindFields = propField('频道 params.channelId', editInput(`tile:${id}:params.channelId`, (tile.params || {}).channelId, 'text', 'placeholder="cctv-1"')) + '<p class="tvhome-note">直播 尚未配置内容服务</p>'; break;
      case 'nvrWindow': kindFields = propField('摄像机 params.cameraId', editInput(`tile:${id}:params.cameraId`, (tile.params || {}).cameraId, 'text', 'placeholder="cam-door"')) + '<p class="tvhome-note">监控 尚未配置内容服务</p>'; break;
      case 'photoCarousel': kindFields = propField('相册查询 params.photoQuery', editInput(`tile:${id}:params.photoQuery`, (tile.params || {}).photoQuery, 'text', 'placeholder="recent"')) + '<p class="tvhome-note">相册 尚未配置内容服务</p>'; break;
      default: kindFields = '';
    }
    return `<section class="tvhome-prop-group"><h3>磁贴 ${escapeHtml(id)}</h3>
      ${propField('种类 kind', editSelect(`tile:${id}:kind`, tile.kind || 'module', TILE_KINDS))}
      ${propField('标签 label', editInput(`tile:${id}:label`, tile.label, 'text'))}
      ${propField('图标 icon', editInput(`tile:${id}:icon`, tile.icon, 'text', 'placeholder="可选"'))}
      ${kindFields}
      <div class="tvhome-geo"><span class="tvhome-geo-h">位置（仅 grid 生效，单位=格）</span>
        <div class="tvhome-geo-grid">
          ${propField('x', editInput(`tile:${id}:x`, tile.x, 'number', 'min="0" step="1"'))}
          ${propField('y', editInput(`tile:${id}:y`, tile.y, 'number', 'min="0" step="1"'))}
          ${propField('w', editInput(`tile:${id}:w`, tile.w, 'number', 'min="1" step="1"'))}
          ${propField('h', editInput(`tile:${id}:h`, tile.h, 'number', 'min="1" step="1"'))}
        </div></div>
      <button class="dwrt-kit-btn is-small is-danger" type="button" data-tv-tile-del="${escapeHtml(id)}" ${canWrite() ? '' : 'disabled'}>删除此磁贴</button></section>`;
  }

  function propDockTile(spec, id) {
    const tile = findTile(spec, id);
    if (!tile) return statePanel({ title: 'dock 项不存在', tone: 'warn' });
    return `<section class="tvhome-prop-group"><h3>dock 项 ${escapeHtml(id)}</h3>
      ${propField('种类 kind', editSelect(`tile:${id}:kind`, tile.kind || 'module', TILE_KINDS))}
      ${tile.kind === 'module' ? propField('模块 module', editSelect(`tile:${id}:module`, tile.module || 'home', MODULE_OPTIONS)) : ''}
      ${propField('标签 label', editInput(`tile:${id}:label`, tile.label, 'text'))}
      ${propField('图标 icon', editInput(`tile:${id}:icon`, tile.icon, 'text'))}</section>`;
  }
  // ---- 渲染：外壳 + tab 分发 ----
  function renderActiveTab() {
    switch (state.tab) {
      case 'overview': return renderOverview();
      case 'theme': return renderThemeTab();
      case 'terminals': return renderTerminalsTab();
      case 'settings': return renderSettingsTab();
      case 'assets': return operations.render('assets');
      case 'notice': return operations.render('notice');
      case 'apps': return operations.render('apps');
      case 'upgrade': return operations.render('upgrade');
      case 'events': return operations.render('events');
      default: return renderOverview();
    }
  }

  function render() {
    if (!state.mounted) return;
    const role = currentRole();
    const roleBadge = canWrite() ? badge('可写', 'ok') : badge(`只读（${role || 'viewer'}）`, 'muted');
    const backend = state.themes.usingFixtures ? badge('示例预览', 'warn') : '';
    const shell = `<div class="tvhome-shell dwrt-kit-page-surface">${renderTabs()}<main class="tvhome-main">
      <header class="tvhome-head">
        <div class="tvhome-head-titles">
          <h1 class="tvhome-title">${escapeHtml(TABS.find(x=>x.id===state.tab)?.label || 'TV 桌面 2.0')}</h1>
          
        </div>
        <div class="tvhome-head-ops">${backend}${roleBadge}
          <button class="dwrt-kit-btn is-small" type="button" data-tv-refresh title="刷新当前页数据">刷新</button></div>
      </header>
      <div class="tvhome-tabview" data-tv-view>${renderActiveTab()}</div>
    </main></div>`;
    root.innerHTML = shell;
    qa('button.dwrt-kit-btn').forEach(button=>{button.classList.add('dwrt-kit-button');button.dataset.dwrtComponent='button';if(button.classList.contains('is-primary'))button.dataset.variant='primary';if(button.classList.contains('is-danger'))button.dataset.variant='danger';});
    qa('input:not([type=checkbox]),textarea,select').forEach(input=>{let field=input.closest('label,.tvhome-prop-field,.dwrt-kit-field');if(!field){field=document.createElement('span');field.className='dwrt-kit-adopted-field';input.before(field);field.append(input);}field.classList.add('dwrt-kit-field');if(input.tagName==='SELECT')input.classList.add('dwrt-kit-select');});
    if (typeof ui.mountAll === 'function') { try { ui.mountAll(root); } catch (_) { /* kit optional */ } }
    bindEvents();
  }

  // 局部重绘：编辑文本/数字/颜色时只刷新预览+校验+Savebar，避免属性面板输入失焦。
  function repaintPreview() {
    const scroll = q('[data-tv-canvas-scroll]');
    if (scroll) scroll.innerHTML = state.themes.view === 'json' ? themeJsonView() : renderThemeCanvas(draftSpec());
    const issuesHost = q('[data-tv-issues]');
    if (issuesHost) {
      const issues = draftSpec() ? gridIssues(draftSpec()) : [];
      issuesHost.innerHTML = issues.length ? `<b>布局校验（客户端提示，最终以后端为准）：</b><ul>${issues.map((i) => `<li>${escapeHtml(i)}</li>`).join('')}</ul>` : '';
    }
    const savebarHost = q('[data-tv-savebar]');
    if (savebarHost) savebarHost.innerHTML = themeSavebar();
    const undo = q('[data-tv-theme-undo]'), redo = q('[data-tv-theme-redo]');
    if (undo) undo.disabled = (state.themes.history?.length || 0) < 2;
    if (redo) redo.disabled = !state.themes.redo?.length;
    const dirtyHost = q('[data-tv-dirty]');
    if (dirtyHost) dirtyHost.innerHTML = isThemeDirty() ? badge('未保存', 'warn') : '';
  }
  // ---- 渲染：终端与分组（online≠connected；观看主体空=需选择，绝不回退管理员） ----
  const dash = (v) => (v == null || v === '' ? '—' : escapeHtml(String(v)));
  const pick = (o, ...keys) => { for (const k of keys) { if (o && o[k] != null && o[k] !== '') return o[k]; } return undefined; };
  const fmtTime = (v) => {
    if (v == null || v === '') return '—';
    const n = Number(v); const d = new Date(n > 1e12 ? n : (n > 1e9 ? n * 1000 : v));
    return Number.isNaN(d.getTime()) ? escapeHtml(String(v)) : escapeHtml(d.toLocaleString());
  };
  function groupName(id) {
    const g = state.terminals.groups.find((x) => String(pick(x, 'id', 'group_id')) === String(id));
    return g ? (pick(g, 'name', 'title') || id) : (id || '');
  }
  function terminalDisplaySummary(term) {
    const disp = isObject(term.display) ? term.display : term;
    const bg = pick(disp, 'background'); const ss = pick(disp, 'screensaver');
    const parts = [];
    if (bg != null) parts.push('背景');
    if (ss != null) parts.push('屏保');
    return parts.length ? `覆盖：${parts.join('/')}` : '继承';
  }

  const operationButton = (label, attr, value, enabled = true) => `<button type="button" class="dwrt-kit-btn is-small" ${attr}="${escapeHtml(value || '')}" ${canWrite() && enabled ? '' : 'disabled'}>${escapeHtml(label)}</button>`;
  const managementDirty = () => !!state.terminals.editor && stableJson(state.terminals.editor.draft) !== stableJson(state.terminals.editor.baseline);
  const hasDirty = () => isThemeDirty() || isSettingsDirty() || managementDirty() || !!operations?.dirty();
  const beforeLeave = (event) => { if (hasDirty()) { event.preventDefault(); event.returnValue = ''; } };
  const termStatus = (term) => {
    const ws = term.ws;
    return `${badge(term.online ? '心跳在线' : '心跳离线', term.online ? 'ok' : 'muted')}
      ${badge(!ws?.supported ? '实时通道暂不可用' : ws.connected ? 'WS 已连接' : 'WS 未连接', ws?.connected ? 'info' : 'muted')}
      ${badge((term.session_active ?? term.connected) ? '会话有效' : '无有效会话', 'muted')}`;
  };
  function renderTerminalsTab() {
    const t = state.terminals;
    if (t.loading) return loadingPanel('终端与分组加载中…');
    const filtered = t.list.filter(x => `${x.name || ''} ${x.device_id || ''} ${x.model || ''}`.toLowerCase().includes(t.query.toLowerCase()));
    const rows = filtered.map(term => `<tr>
      <td><b>${dash(term.name || term.id)}</b><small class="tvhome-record-sub">${dash(term.device_id)}</small></td>
      <td>${dash(groupName(term.group_id))}<small class="tvhome-record-sub">${dash(term.theme_id)}</small></td>
      <td>${dash(term.model)}<small class="tvhome-record-sub">SDK ${dash(term.device?.sdk_int)} · ${escapeHtml((term.device?.supported_abis || []).join(', ') || '未知')}</small></td>
      <td>${termStatus(term)}<small class="tvhome-record-sub">${fmtTime(term.last_seen_ms)}</small></td>
      <td>${dash(term.desired_config_version)} / ${term.applied_config_version > 0 ? dash(term.applied_config_version) : '待上报'}</td>
      <td><div class="tvhome-record-actions">${operationButton('编辑','data-tv-record',`terminal:${term.id}`)}
        ${operationButton('刷新配置','data-tv-command',`${term.id}:refresh`)}${operationButton('踢出会话','data-tv-command',`${term.id}:kick`)}
        ${operationButton(term.enabled === false ? '恢复身份' : '停用身份','data-tv-command',`${term.id}:${term.enabled === false ? 'enable' : 'disable'}`)}
        ${operationButton('删除档案','data-tv-command',`${term.id}:delete`,!(term.session_active ?? term.connected))}</div></td>
    </tr>`).join('');
    const requests = t.activations.map(a => `<tr><td>${dash(a.device?.model || a.device?.device_id)}<small class="tvhome-record-sub">${dash(a.device?.device_id)}</small></td><td>${dash(({pending:'待审批',approved:'已批准',expired:'已过期',revoked:'已撤销',consumed:'已激活'})[a.status] || a.status)}</td><td>${fmtTime(a.expires_at_ms)}</td><td>${operationButton('批准并生成激活码','data-tv-approve',a.id,a.status==='pending')}${operationButton('撤销申请','data-tv-revoke',a.id,['pending','approved'].includes(a.status))}</td></tr>`).join('');
    return `<section class="tvhome-panel dwrt-kit-glass-surface"><div class="tvhome-panel-head"><h2>终端</h2><input class="dwrt-kit-input" data-tv-terminal-search type="search" aria-label="搜索终端" placeholder="搜索名称、设备或型号" value="${escapeHtml(t.query)}"></div>
      ${t.error ? statePanel({title:'终端列表加载失败',desc:t.error,tone:'warn'}) : `<div class="tvhome-table-wrap"><table class="tvhome-table"><thead><tr><th>终端</th><th>分组 / 主题</th><th>设备</th><th>连接状态</th><th>目标 / 已应用</th><th>操作</th></tr></thead><tbody>${rows || '<tr><td colspan="6">暂无符合条件的终端</td></tr>'}</tbody></table></div>`}
      ${t.message ? `<p role="status">${escapeHtml(t.message)}</p>` : ''}</section>
      <section class="tvhome-panel dwrt-kit-glass-surface"><div class="tvhome-panel-head"><h2>设备激活</h2></div>
      <p class="tvhome-note">电视先提交开通申请。核对设备后批准，将当次显示的激活码交给对应电视输入。</p>
      ${t.activationError ? statePanel({title:'申请列表不可用',desc:t.activationError,tone:'warn'}) : `<div class="tvhome-table-wrap"><table class="tvhome-table"><thead><tr><th>设备</th><th>状态</th><th>有效期至</th><th>操作</th></tr></thead><tbody>${requests || '<tr><td colspan="4">暂无开通申请</td></tr>'}</tbody></table></div>`}
      ${t.grant ? `<div class="tvhome-panel"><b>本次激活码</b><p class="tvhome-code">${escapeHtml(t.grant.activation_code)}</p><p>有效期至 ${fmtTime(t.grant.expires_at_ms)}，只能使用一次。</p><button class="dwrt-kit-btn" data-tv-hide-grant>已交付，隐藏</button></div>` : ''}</section>
      <section class="tvhome-panel dwrt-kit-glass-surface"><div class="tvhome-panel-head"><h2>分组</h2>${operationButton('新建分组','data-tv-record','group:')}</div>
      ${t.groupsError ? statePanel({title:'分组加载失败',desc:t.groupsError,tone:'warn'}) : `<div class="tvhome-table-wrap"><table class="tvhome-table"><thead><tr><th>分组</th><th>主题</th><th>终端数</th><th>操作</th></tr></thead><tbody>${t.groups.map(g=>`<tr><td>${dash(g.name)}</td><td>${dash(g.theme_id)}</td><td>${dash(g.member_count)}</td><td>${operationButton('编辑','data-tv-record',`group:${g.id}`)}${operationButton('删除分组','data-tv-group-delete',g.id)}</td></tr>`).join('') || '<tr><td colspan="4">暂无分组</td></tr>'}</tbody></table></div>`}</section>${renderRecordEditor()}`;
  }
  function recordSelect(field, value, options) {
    return `<select class="dwrt-kit-input" data-tv-record-field="${field}">${options.map(([v,l])=>`<option value="${escapeHtml(v)}" ${String(value || '')===v?'selected':''}>${escapeHtml(l)}</option>`).join('')}</select>`;
  }
  function renderRecordEditor() {
    const e=state.terminals.editor;if(!e) return '';
    const d=e.draft;
    return `<section class="tvhome-panel tvhome-record-editor dwrt-kit-glass-surface" role="region" aria-label="编辑${e.kind==='group'?'分组':'终端'}">
      <div class="tvhome-panel-head"><h2>${e.id?'编辑':'新建'}${e.kind==='group'?'分组':'终端'}</h2><button class="dwrt-kit-btn" data-tv-record-close>关闭编辑</button></div>
      <div class="tvhome-record-grid"><label>名称<input class="dwrt-kit-input" data-tv-record-field="name" value="${escapeHtml(d.name)}"></label>
      <label>主题${recordSelect('theme_id',d.theme_id,[['','继承上层主题'],...state.terminals.themes.map(x=>[x.id,x.name])])}</label>
      ${e.kind==='terminal'?`<label>分组${recordSelect('group_id',d.group_id,[['','未分组'],...state.terminals.groups.map(x=>[x.id,x.name])])}</label>`:''}
      <label>背景${recordSelect('background_mode',d.background_mode,[['inherit','继承上层'],['color','纯色'],['static','素材图片']])}</label>
      <label>背景颜色<input class="dwrt-kit-input" type="color" data-tv-record-field="background_color" value="${escapeHtml(d.background_color)}"></label>
      <label>图片素材 ID<input class="dwrt-kit-input" data-tv-record-field="background_asset" value="${escapeHtml(d.background_asset)}"></label>
      <label>屏保${recordSelect('screensaver_mode',d.screensaver_mode,[['inherit','继承上层'],['off','禁用屏保'],['clock','时钟屏保']])}</label>
      <label>空闲分钟<input class="dwrt-kit-input" type="number" min="1" max="120" data-tv-record-field="idle_minutes" value="${escapeHtml(String(d.idle_minutes))}"></label></div>
      <p class="tvhome-note">当前生效来源：背景 ${escapeHtml(e.source?.background || '未知')}，屏保 ${escapeHtml(e.source?.screensaver || '未知')}。背景与屏保分别继承。</p>
      ${e.error?`<p role="alert">${escapeHtml(e.error)}</p>`:''}<div data-tv-record-savebar>${recordSavebar()}</div></section>`;
  }
  function recordSavebar() { const e=state.terminals.editor;return e?ui.floatingSavebarMarkup?.({visible:managementDirty(),busy:e.saving,disabled:e.saving||!managementDirty(),message:'终端与分组有未保存更改',saveLabel:'保存',discardLabel:'撤销'} ) || '':''; }
  async function openRecord(raw) {
    if (managementDirty() && !window.confirm('放弃当前未保存的编辑？')) return;
    const [kind,id]=raw.split(':');const collection=kind==='group'?'groups':'terminals';
    const row=state.terminals[collection==='groups'?'groups':'list'].find(x=>x.id===id) || {name:'',theme_id:null};
    let display=row.display || {},override=row.display_override || {};
    try {
      if(id) { display=await requestJson('tvhome-display',`/api/v1/tvhome/${collection}/${encodeURIComponent(id)}/display`);override=display.override || override; }
      const draft={name:row.name||'',theme_id:row.theme_id||'',group_id:row.group_id||'',background_mode:override.background?.mode||'inherit',background_color:override.background?.color||'#202326',background_asset:override.background?.assetId||'',screensaver_mode:override.screensaver==null?'inherit':override.screensaver.enabled===false?'off':'clock',idle_minutes:override.screensaver?.idleMinutes||10};
      state.terminals.editor={kind,id,baseline:clone(draft),draft,source:display.source,error:'',saving:false};
      if(!id) state.terminals.editor.baseline=null;
      render();q('.tvhome-record-editor')?.scrollIntoView({block:'nearest'});
    } catch(err) {state.terminals.message=messageForError(err,'显示配置加载失败');render();}
  }
  async function saveRecord() {
    const e=state.terminals.editor;if(!e||e.saving||!canWrite())return;
    e.saving=true;e.error='';render();
    const d=clone(e.draft),collection=e.kind==='group'?'groups':'terminals';
    const metadata={name:d.name,theme_id:d.theme_id||null,...(e.kind==='terminal'?{group_id:d.group_id||null}:{})};
    const display={background:d.background_mode==='inherit'?null:d.background_mode==='color'?{mode:'color',color:d.background_color}:{mode:'static',assetId:d.background_asset},screensaver:d.screensaver_mode==='inherit'?null:{enabled:d.screensaver_mode!=='off',mode:'clock',idleMinutes:Number(d.idle_minutes)}};
    try {
      const saved=await requestJson('tvhome-record',`/api/v1/tvhome/${collection}${e.id?'/'+encodeURIComponent(e.id):''}`,jsonInit(e.id?'PUT':'POST',metadata));
      e.id=e.id||saved.id;
      await requestJson('tvhome-record-display',`/api/v1/tvhome/${collection}/${encodeURIComponent(e.id)}/display`,jsonInit('PUT',display));
      const [records,readback]=await Promise.all([requestJson('tvhome-record-read',`/api/v1/tvhome/${collection}`),requestJson('tvhome-display-read',`/api/v1/tvhome/${collection}/${encodeURIComponent(e.id)}/display`)]);
      const row=(records[collection]||[]).find(x=>x.id===e.id);
      if(!row||row.name!==d.name||(row.theme_id||'')!==d.theme_id||(e.kind==='terminal'&&(row.group_id||'')!==d.group_id)||stableJson(readback.override)!==stableJson(display))throw new Error('保存回读不一致，草稿已保留。');
      e.baseline=clone(d);e.source=readback.source;state.terminals.message='配置已保存；终端是否应用以回执为准。';await loadTerminals();
    } catch(err) {e.error=messageForError(err,'保存失败');} finally {e.saving=false;render();}
  }
  async function managementCommand(kind,value) {
    if(!canWrite())return;const t=state.terminals;
    try {
      if(kind==='approve') {
        if(!window.confirm('确认已核对这台电视，并为它签发一次性激活码？'))return;
        t.grant=await requestJson('tvhome-approve',`/api/v1/tvhome/activations/${encodeURIComponent(value)}/approve`,jsonInit('POST',{}));
      } else if(kind==='revoke') {
        if(!window.confirm('撤销这份开通申请？'))return;
        await requestJson('tvhome-revoke',`/api/v1/tvhome/activations/${encodeURIComponent(value)}/revoke`,jsonInit('POST',{}));
      } else if(kind==='group-delete') {
        if(!window.confirm('删除分组后，成员将回到未分组。继续？'))return;
        await requestJson('tvhome-group-delete',`/api/v1/tvhome/groups/${encodeURIComponent(value)}`,{method:'DELETE'});
      } else {
        const [id,action]=value.split(':');
        const labels={kick:'撤销当前会话，电视需重新激活',disable:'停用此电视身份并撤销会话',enable:'恢复身份；旧会话不会恢复',delete:'删除终端档案，保留独立 TV 身份',refresh:'通知电视重取配置'};
        if(!window.confirm(`${labels[action]}。继续？`))return;
        await requestJson('tvhome-command',`/api/v1/tvhome/terminals/${encodeURIComponent(id)}${action==='delete'?'':'/'+action}`,action==='delete'?{method:'DELETE'}:jsonInit('POST',{}));
        t.message=action==='refresh'?'刷新请求已保存，等待终端应用。':'操作已保存。';
      }
      await loadTerminals();
    } catch(err) {t.message=messageForError(err,'操作失败');render();}
  }

  // ---- 渲染：桌面设置（Savebar 驱动；media_principal 空=需选择，PIN 只显状态不回显值） ----
  const getPath = (obj, path) => path.split('.').reduce((acc, k) => (acc == null ? undefined : acc[k]), obj);
  const setInput = (path, value, type, attrs) => `<input class="dwrt-kit-input" type="${type || 'text'}" data-tv-set="${escapeHtml(path)}" value="${escapeHtml(String(value ?? ''))}" ${attrs || ''} ${canWrite() ? '' : 'disabled'} />`;
  const setSelect = (path, value, options) => `<select class="dwrt-kit-input" data-tv-set="${escapeHtml(path)}" ${canWrite() ? '' : 'disabled'}>${options.map((o) => `<option value="${escapeHtml(o.value)}" ${String(value) === String(o.value) ? 'selected' : ''}>${escapeHtml(o.label)}</option>`).join('')}</select>`;
  const setToggle = (path, checked, labelText) => `<label class="tvhome-toggle"><input type="checkbox" data-tv-set="${escapeHtml(path)}" ${checked ? 'checked' : ''} ${canWrite() ? '' : 'disabled'} /><span>${escapeHtml(labelText)}</span></label>`;

  function settingsSavebar() {
    const s = state.settings; const dirty = isSettingsDirty();
    return ui.floatingSavebarMarkup
      ? ui.floatingSavebarMarkup({ visible: dirty || !!s.msg, busy: s.saving, disabled: !dirty || !canWrite(), message: s.msg || (dirty ? '桌面设置有未保存更改' : '已是最新'), discardLabel: '撤销更改', saveLabel: '保存设置' })
      : `<div class="tvhome-inline-savebar dwrt-kit-glass-surface"><span>${escapeHtml(s.msg || (dirty ? '桌面设置有未保存更改' : '已是最新'))}</span>
          <button class="dwrt-kit-btn is-small" type="button" data-dwrt-savebar-discard ${dirty ? '' : 'disabled'}>撤销更改</button>
          <button class="dwrt-kit-btn is-small is-primary" type="button" data-dwrt-savebar-save ${dirty && canWrite() ? '' : 'disabled'}>保存设置</button></div>`;
  }

  function renderSettingsTab() {
    const s = state.settings;
    if (s.loading) return loadingPanel('桌面设置加载中…');
    if (s.error && !s.draft) {
      return `<div class="tvhome-panel dwrt-kit-glass-surface"><div class="tvhome-panel-head"><h2>桌面设置</h2>${badge('服务未就绪', 'warn')}</div>
        ${statePanel({ title: '设置不可用', desc: s.error, tone: 'warn' })}
        <p class="tvhome-note">设置读写需后端 A/settings；未接通时不臆造默认值，也不允许保存。</p></div>`;
    }
    const d = isObject(s.draft) ? s.draft : {};
    const themeOptions = state.themes.list.filter(x=>!x._fixture&&x.enabled!==false).map(x=>({value:x.id,label:x.name||x.id}));
    const themeGroup = `<section class="tvhome-set-group"><h3>默认主题</h3>${propField('主题',setSelect('default_theme_id',d.default_theme_id||'',themeOptions))}</section>`;
    const discoveryGroup = `<section class="tvhome-set-group"><h3>连接状态</h3>
      ${propField('心跳间隔（秒）',setInput('heartbeat_seconds',d.heartbeat_seconds,'number','min="5" max="86400" step="1"'))}
      ${propField('在线判定窗口（秒）',setInput('online_window_seconds',d.online_window_seconds,'number','min="10" max="86400" step="1"'))}
      <p class="tvhome-note">心跳、WebSocket 连接与有效会话分别显示。局域网自动发现尚未接入。</p></section>`;
    const localGroup = `<section class="tvhome-set-group"><h3>终端权限</h3>${propField('',setToggle('exit_to_system',!!d.exit_to_system,'允许退出到原生系统'))}
      <p class="tvhome-note">终端本地编辑和 PIN 验证尚未开放。主题中受 PIN 保护的入口保持不可用。</p></section>`;
    const providerGroup = `<section class="tvhome-set-group"><h3>内容来源</h3><p class="tvhome-note">直播、影音、照片、文件与监控来源尚未配置，待服务接通后开放授权和模块设置。</p></section>`;
    const dirty = isSettingsDirty();
    return `<div class="tvhome-panel dwrt-kit-glass-surface">
        <div class="tvhome-panel-head"><h2>桌面设置</h2><span data-tv-set-dirty>${dirty ? badge('未保存', 'warn') : badge('已同步', 'ok')}</span></div>
        ${s.error ? statePanel({ title: '部分保存失败', desc: s.error, tone: 'warn' }) : ''}
        <div class="tvhome-set-grid">${themeGroup}${discoveryGroup}${localGroup}${providerGroup}</div>
      </div><div data-tv-savebar>${settingsSavebar()}</div>`;
  }
  // ---- 动作：草稿变更（只改 draft，持久化到 sessionStorage，不触碰 baseline） ----
  const coerceNumber = (v) => { if (v === '' || v == null) return undefined; const n = Number(v); return Number.isFinite(n) ? n : undefined; };
  const TOKEN_NUM = new Set(['radius', 'fontScale', 'blur', 'focusScale']);
  function persistThemeDraft(record=true) {
    if (!state.themes.draft) return;
    const t=state.themes,snapshot={name:t.name,spec:clone(t.draft)};
    if(record){t.history ||= [];if(stableJson(t.history.at(-1))!==stableJson(snapshot)){t.history.push(snapshot);if(t.history.length>60)t.history.shift();t.redo=[];}}
    writeDraft(THEME_DRAFT_KEY, { id: t.activeId, name: t.name, spec: t.draft });
  }
  function persistSettingsDraft() { if (state.settings.draft) writeDraft(SETTINGS_DRAFT_KEY, state.settings.draft); }

  function applyThemeEdit(key, value) {
    const spec = state.themes.draft; if (!isObject(spec)) return;
    const parts = key.split(':'); const head = parts[0];
    if (head === 'token') {
      const name = parts[1]; if (!isObject(spec.tokens)) spec.tokens = {};
      if (TOKEN_NUM.has(name)) { const n = coerceNumber(value); if (n == null) delete spec.tokens[name]; else spec.tokens[name] = n; }
      else if (value === '') delete spec.tokens[name]; else spec.tokens[name] = String(value);
    } else if (head === 'bg') {
      const f = parts[1]; if (!isObject(spec.background)) spec.background = { mode: 'color' };
      const b = spec.background;
      if (f === 'assetIds') b.assetIds = String(value).split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);
      else if (f === 'dim' || f === 'intervalSec') { const n = coerceNumber(value); if (n == null) delete b[f]; else b[f] = n; }
      else if (value === '') delete b[f]; else b[f] = String(value);
    } else if (head === 'ss') {
      const f = parts[1]; if (!isObject(spec.screensaver)) spec.screensaver = { enabled: false };
      const ssv = spec.screensaver;
      if (f === 'enabled') ssv.enabled = value === true || value === 'true';
      else if (f === 'idleMinutes' || f === 'intervalSec') { const n = coerceNumber(value); if (n == null) delete ssv[f]; else ssv[f] = n; }
      else if (value === '') delete ssv[f]; else ssv[f] = String(value);
    } else if (head === 'hd') {
      const f = parts[1]; if (!isObject(spec.header)) spec.header = {};
      spec.header[f] = value === true || value === 'true';
    } else if (head === 'root') {
      if (!isObject(spec.home)) spec.home = {};
      const n = coerceNumber(value); if (n != null) spec.home[parts[1]] = n;
    } else if (head === 'nav') {
      const it = asArray(spec.nav).find((n) => n && n.id === parts[1]); if (!it) return;
      const f = parts[2];
      if (f === 'hidden') it.hidden = value === true || value === 'true';
      else if (f === 'label') it.label = String(value);
      else if (value === '' && ['module', 'pageId', 'appPackage', 'url', 'icon'].includes(f)) delete it[f];
      else it[f] = String(value);
    } else if (head === 'sec') {
      const sec = findSection(spec, parts[1]); if (!sec) return;
      const f = parts[2];
      if (f === 'limit') { const n = coerceNumber(value); if (n == null) delete sec.limit; else sec.limit = n; }
      else sec[f] = String(value);
    } else if (head === 'tile') {
      const tile = findTile(spec, parts[1]); if (!tile) return;
      const f = parts.slice(2).join(':');
      if (['x', 'y', 'w', 'h'].includes(f)) { const n = coerceNumber(value); if (n != null) tile[f] = n; }
      else if (f === 'showLabel') tile.showLabel = value === true || value === 'true';
      else if (f.startsWith('params.')) { const pk = f.slice(7); if (!isObject(tile.params)) tile.params = {}; if (value === '') delete tile.params[pk]; else tile.params[pk] = String(value); }
      else if (value === '' && ['icon', 'module', 'appPackage', 'url', 'image'].includes(f)) delete tile[f];
      else tile[f] = String(value);
    }
    persistThemeDraft();
  }

  function applyLock(module, checked) {
    const spec = state.themes.draft; if (!isObject(spec)) return;
    if (!isObject(spec.parental)) spec.parental = {};
    const set = new Set(asArray(spec.parental.lockedModules));
    if (checked) set.add(module); else set.delete(module);
    spec.parental.lockedModules = Array.from(set);
    persistThemeDraft();
  }
  function navAdd() {
    const spec = state.themes.draft; if (!isObject(spec)) return;
    if (!Array.isArray(spec.nav)) spec.nav = [];
    const id = uid('nav');
    spec.nav.push({ id, type: 'module', module: 'home', label: '新导航项' });
    state.themes.selection = { kind: 'nav', id };
    persistThemeDraft(); render();
  }
  function navDelete(id) {
    const spec = state.themes.draft; if (!isObject(spec) || !Array.isArray(spec.nav)) return;
    spec.nav = spec.nav.filter((n) => n && n.id !== id);
    if (state.themes.selection && state.themes.selection.id === id) state.themes.selection = { kind: 'navlist' };
    persistThemeDraft(); render();
  }
  function navMove(id, dir) {
    const spec = state.themes.draft; if (!isObject(spec) || !Array.isArray(spec.nav)) return;
    const i = spec.nav.findIndex((n) => n && n.id === id); if (i < 0) return;
    const j = dir === 'up' ? i - 1 : i + 1; if (j < 0 || j >= spec.nav.length) return;
    const tmp = spec.nav[i]; spec.nav[i] = spec.nav[j]; spec.nav[j] = tmp;
    persistThemeDraft(); render();
  }
  function navHide(id) {
    const spec = state.themes.draft; const it = isObject(spec) ? asArray(spec.nav).find((n) => n && n.id === id) : null;
    if (!it) return; it.hidden = !it.hidden; persistThemeDraft(); render();
  }
  function tileDelete(id) {
    const spec = state.themes.draft; const home = isObject(spec) ? spec.home : null; if (!isObject(home)) return;
    asArray(home.sections).forEach((s) => { if (Array.isArray(s.tiles)) s.tiles = s.tiles.filter((t) => t && t.id !== id); });
    asArray(home.pages).forEach((p) => { if (Array.isArray(p.tiles)) p.tiles = p.tiles.filter((t) => t && t.id !== id); });
    if (Array.isArray(home.dock)) home.dock = home.dock.filter((t) => t && t.id !== id);
    if (state.themes.selection && state.themes.selection.id === id) state.themes.selection = { kind: 'appearance' };
    persistThemeDraft(); render();
  }
  function sectionAddTile(secId) {
    const spec = state.themes.draft; const sec = findSection(spec, secId); if (!sec) return;
    if (!Array.isArray(sec.tiles)) sec.tiles = [];
    const id = uid('tile');
    sec.tiles.push({ id, kind: 'weblink', label: '新磁贴', url: '', x: 0, y: 0, w: 1, h: 1 });
    state.themes.selection = { kind: 'tile', id };
    persistThemeDraft(); render();
  }
  function switchStyle(newStyle) {
    const spec = state.themes.draft; if (!isObject(spec) || spec.style === newStyle) return;
    const ok = (typeof window !== 'undefined' && window.confirm)
      ? window.confirm('切换首页样式会保留 tokens/背景/导航，但另一种首页布局（flow sections 或 grid pages）不会自动迁移，可能被清空。是否继续？')
      : true;
    if (!ok) { render(); return; }
    spec.style = newStyle;
    if (newStyle === 'grid') {
      if (!isObject(spec.home) || !Array.isArray(spec.home.pages)) spec.home = { columns: 12, rows: 6, pages: [{ id: 'main', label: '主页', tiles: [] }], dock: [] };
    } else if (!isObject(spec.home) || !Array.isArray(spec.home.sections)) spec.home = { sections: [] };
    state.themes.page = 0; state.themes.selection = { kind: 'appearance' };
    persistThemeDraft(); render();
  }

  // 设置：按点分路径写入 draft
  function setSettingsPath(path, value) {
    const d = state.settings.draft; if (!isObject(d)) return;
    const keys = path.split('.'); let cur = d;
    for (let i = 0; i < keys.length - 1; i++) { if (!isObject(cur[keys[i]])) cur[keys[i]] = {}; cur = cur[keys[i]]; }
    cur[keys[keys.length - 1]] = value;
    persistSettingsDraft();
  }
  // ---- 动作：主题异步操作（校验/预览规范化/保存/复制/设默认/删除；后端权威） ----
  const fixtureBlocked = (msg) => { if (state.themes.usingFixtures) { state.themes.msg = msg || '后端未接通（当前为 fixture 预览），此操作需后端支持。'; render(); return true; } return false; };

  async function validateTheme() {
    const t = state.themes; if (!t.draft) return;
    if (t.usingFixtures) { const issues = gridIssues(t.draft); t.msg = issues.length ? `客户端校验发现问题：${issues[0]}` : '客户端校验通过（后端未接通，未做服务端校验）。'; render(); return; }
    const seq = state.seq; t.msg = '校验中…'; render();
    try {
      await requestJson('tvhome-theme-validate', ENDPOINTS.themeValidate, jsonInit('POST', { spec: t.draft }));
      if (seq !== state.seq) return; t.fields = []; t.msg = '服务端校验通过。';
    } catch (err) { if (seq !== state.seq) return; t.fields = errorFields(err); t.msg = `校验未通过：${messageForError(err, '')}${t.fields.length ? `（字段 ${t.fields.join(', ')}）` : ''}`; }
    finally { if (seq === state.seq) render(); }
  }

  async function previewTheme() {
    const t = state.themes; if (!t.draft || fixtureBlocked('后端未接通：无法获取服务端规范化预览。')) return;
    const seq = state.seq; t.msg = '获取规范化预览中…'; render();
    try {
      const data = await requestJson('tvhome-theme-preview', ENDPOINTS.themePreview, jsonInit('POST', { spec: t.draft }));
      if (seq !== state.seq) return;
      const norm = clone(isObject(data) ? (data.spec || data.normalized || data) : null);
      if (isObject(norm)) { t.draft = norm; persistThemeDraft(); t.msg = '已套用服务端规范化结果（预览，尚未保存）。'; }
      else t.msg = '预览返回为空。';
    } catch (err) { if (seq !== state.seq) return; t.msg = `预览失败：${messageForError(err, '')}`; }
    finally { if (seq === state.seq) render(); }
  }

  async function saveTheme() {
    const t = state.themes; if (!t.draft || !t.baseline || fixtureBlocked('后端未接通：fixture 预览不可保存。')) return;
    const issues = gridIssues(t.draft); if (issues.length) { t.msg = `请先修复布局问题：${issues[0]}`; render(); return; }
    const seq = state.seq; t.saving = true; t.msg = ''; render();
    const intendedName=t.name, intendedSpec=clone(t.draft);
    try {
      const normalized=await requestJson('tvhome-theme-preview',ENDPOINTS.themePreview,jsonInit('POST',{spec:intendedSpec}));
      const written=await requestJson('tvhome-theme-save', ENDPOINTS.theme(t.activeId), jsonInit('PUT', { expected_revision: t.revision, name: t.name, spec: t.draft }));
      const data = await requestJson('tvhome-theme-read', ENDPOINTS.theme(t.activeId));
      if (seq !== state.seq) return;
      const spec = clone(isObject(data) ? (data.spec || data) : t.draft);
      const revision = isObject(data) && data.revision != null ? Number(data.revision) || 0 : t.revision + 1;
      const name = isObject(data) && data.name ? data.name : t.name;
      t.baseline = { name, spec: clone(spec), revision }; t.revision=revision; t.fields=[];
      const matched=name===intendedName && stableJson(spec)===stableJson(normalized.spec) && revision===Number(written.revision);
      if(matched){t.draft=clone(spec);t.name=name;t.msg='已保存，并核对服务端规范化回读。';writeDraft(THEME_DRAFT_KEY,null);t.history=[{name,spec:clone(spec)}];t.redo=[];}
      else {t.draft=intendedSpec;t.name=intendedName;persistThemeDraft(false);t.msg='服务端回读与本次提交不同，草稿已保留；请比较最新基线后再保存。';}
      const row = t.list.find((x) => x.id === t.activeId); if (row) { row.revision = revision; row.name = name; }
    } catch (err) {
      if (seq !== state.seq) return;
      const code = errorCode(err);
      if (code === 'revision_conflict') t.msg = '版本冲突：他处已更新该主题。草稿已保留，请点“刷新”取回最新版本后再合并保存。';
      else if (code === 'invalid_theme') { t.fields = errorFields(err); t.msg = `主题校验失败${t.fields.length ? `：字段 ${t.fields.join(', ')}` : `：${messageForError(err, '')}`}`; }
      else t.msg = messageForError(err, '保存失败。');
    } finally { if (seq === state.seq) { t.saving = false; render(); } }
  }

  function undoTheme(redo=false){const t=state.themes;
    if(redo){const snapshot=t.redo?.pop();if(!snapshot)return;t.history.push(snapshot);}else{if((t.history?.length||0)<2)return;(t.redo ||= []).push(t.history.pop());}
    const current=t.history.at(-1);t.name=current.name;t.draft=clone(current.spec);persistThemeDraft(false);render();
  }
  async function themeOperation(action){const t=state.themes;if(t.usingFixtures)return;
    try{
      if(action==='export'){const saved=await requestJson('tvhome-theme-export',ENDPOINTS.theme(t.activeId)+'/export');const url=URL.createObjectURL(new Blob([JSON.stringify(saved,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=(saved.name||'theme')+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);t.msg='已导出主题 JSON；素材需另行迁移，并按摘要核对。';}
      else if(canWrite()){
        if(action==='import') {if(!t.importFile)throw Error('请先选择主题 JSON 文件。');if(t.importFile.size>1024*1024)throw Error('主题 JSON 超过 1 MiB。');const data=JSON.parse(await t.importFile.text());const created=await requestJson('tvhome-theme-import',ENDPOINTS.themes+'/import',jsonInit('POST',data));t.importFile=null;await loadThemes();await selectTheme(created.id);t.msg='主题已导入；素材依赖已按摘要核对。';}
        else {if(isThemeDirty())throw Error('请先保存或撤销当前草稿。');const row=t.list.find(x=>x.id===t.activeId);if(action==='reset'){if(!window.confirm('将内置主题恢复到出厂设计？'))return;await requestJson('tvhome-theme-reset',ENDPOINTS.theme(t.activeId)+'/reset',jsonInit('POST',{expected_revision:t.revision}));}else await requestJson('tvhome-theme-toggle',ENDPOINTS.theme(t.activeId),jsonInit('PUT',{expected_revision:t.revision,enabled:row.enabled===false}));await loadThemes();t.msg='主题状态已更新并回读。';}
      }
    }catch(e){t.msg=messageForError(e,'主题操作失败。');}render();
  }

  async function duplicateTheme() {
    const t = state.themes; if (fixtureBlocked('后端未接通：无法复制。')) return;
    const seq = state.seq; t.msg = '复制中…'; render();
    try {
      const data = await requestJson('tvhome-theme-dup', ENDPOINTS.themeDuplicate(t.activeId), jsonInit('POST', {}));
      if (seq !== state.seq) return;
      const newId = isObject(data) ? (data.id || data.theme_id || (data.theme && data.theme.id)) : null;
      await loadThemes(); if (newId) { t.activeId = newId; await selectTheme(newId); }
      t.msg = '已复制主题。'; render();
    } catch (err) { if (seq !== state.seq) return; t.msg = `复制失败：${messageForError(err, '')}`; render(); }
  }

  async function setDefaultTheme() {
    const t = state.themes; if (fixtureBlocked('后端未接通：无法设默认。')) return;
    const seq = state.seq; t.msg = '设为默认中…'; render();
    try { await requestJson('tvhome-theme-default', ENDPOINTS.themeDefault(t.activeId), jsonInit('POST', {})); if (seq !== state.seq) return; await loadThemes(); t.msg = '已设为默认主题。'; render(); }
    catch (err) { if (seq !== state.seq) return; t.msg = `设默认失败：${messageForError(err, '')}`; render(); }
  }

  async function deleteTheme() {
    const t = state.themes; const row = t.list.find((x) => x.id === t.activeId) || {};
    if (row.is_default) { t.msg = '默认主题不可删除，请先切换默认。'; render(); return; }
    if (fixtureBlocked('后端未接通：无法删除。')) return;
    if (typeof window !== 'undefined' && window.confirm && !window.confirm(`确认删除主题「${t.name || t.activeId}」？此操作不可撤销。`)) return;
    const seq = state.seq; t.msg = '删除中…'; render();
    try { await requestJson('tvhome-theme-del', ENDPOINTS.theme(t.activeId), { method: 'DELETE' }); if (seq !== state.seq) return; writeDraft(THEME_DRAFT_KEY, null); t.activeId = ''; t.baseline = null; t.draft = null; await loadThemes(); t.msg = '已删除主题。'; render(); }
    catch (err) { if (seq !== state.seq) return; t.msg = `删除失败：${messageForError(err, '')}`; render(); }
  }

  function discardTheme() {
    const t = state.themes; if (!t.baseline) return;
    t.draft = clone(t.baseline.spec); t.name = t.baseline.name; t.selection = { kind: 'appearance' }; t.page = 0; t.fields = []; t.msg = '';
    writeDraft(THEME_DRAFT_KEY, null); render();
  }

  async function saveSettings() {
    const s = state.settings; if (!s.draft || !canWrite()) return;
    const seq = state.seq; s.saving = true; s.msg = ''; s.error = ''; const intended=clone(s.draft); render();
    try {
      await requestJson('tvhome-settings-save', ENDPOINTS.settings, jsonInit('PUT', s.draft));
      const data = await requestJson('tvhome-settings-read', ENDPOINTS.settings);
      if (seq !== state.seq) return;
      if(!isObject(data))throw Error('设置回读为空，草稿已保留。');
      const matched=['default_theme_id','heartbeat_seconds','online_window_seconds','exit_to_system'].every(k=>String(data[k])===String(intended[k]));
      s.baseline=data;s.draft=matched?clone(data):{...intended,config_version:data.config_version};
      s.msg=matched?'设置已保存并核对回读。':'回读与提交不同，草稿已保留，请比较后再保存。';
      if(matched)writeDraft(SETTINGS_DRAFT_KEY,null);else persistSettingsDraft();
    } catch (err) { if (seq !== state.seq) return; s.msg = ''; s.error = messageForError(err, '设置保存失败。'); }
    finally { if (seq === state.seq) { s.saving = false; render(); } }
  }
  function discardSettings() {
    const s = state.settings; if (!s.baseline) return;
    s.draft = clone(s.baseline); s.msg = ''; writeDraft(SETTINGS_DRAFT_KEY, null); render();
  }

  function refreshActive() {
    state.themes.msg = ''; state.settings.msg = '';
    ensureTabData(true);
  }
  async function createTheme() {
    const t = state.themes; if (fixtureBlocked('后端未接通：无法新建主题。')) return;
    const seq = state.seq; t.msg = '新建中…'; render();
    const spec = { version: 1, style: 'flow', tokens: { colorBackground: '#101418', colorSurface: '#1A2026', colorPrimary: '#3F8CFF', foreground: '#F2F4F7', radius: 16, fontScale: 1.0, blur: 16, focusScale: 1.06 }, background: { mode: 'color', color: '#101418' }, screensaver: { enabled: false, mode: 'clock', idleMinutes: 10 }, header: { clock: true, date: true, weather: false }, parental: { lockedModules: [] }, nav: [{ id: 'home', type: 'module', module: 'home', label: '首页' }], home: { sections: [] } };
    try {
      const data = await requestJson('tvhome-theme-create', ENDPOINTS.themes, jsonInit('POST', { name: '新主题', spec }));
      if (seq !== state.seq) return;
      const newId = isObject(data) ? (data.id || data.theme_id || (data.theme && data.theme.id)) : null;
      await loadThemes(); if (newId) { t.activeId = newId; await selectTheme(newId); }
      t.msg = '已新建主题。'; render();
    } catch (err) { if (seq !== state.seq) return; t.msg = `新建失败：${messageForError(err, '')}`; render(); }
  }

  function switchTab(tabId) {
    if (!TABS.some((x) => x.id === tabId) || state.tab === tabId) return;
    state.tab = tabId;
    try { window.sessionStorage?.setItem(ACTIVE_TAB_KEY, tabId); } catch (_) {}
    render(); ensureTabData();
  }
  // ---- 事件绑定：root 上一次性事件委托（render 只替换 innerHTML，委托不重复绑定） ----
  function onClick(e) {
    if(operations?.handleClick(e))return;
    const hit = (sel) => e.target.closest(`[${sel}]`);
    let el;
    if ((el=hit('data-tv-record'))) { openRecord(el.dataset.tvRecord); return; }
    if (hit('data-tv-record-close')) { if (!managementDirty() || window.confirm('放弃未保存更改？')) {state.terminals.editor=null;render();} return; }
    if (hit('data-tv-hide-grant')) {state.terminals.grant=null;render();return;}
    for (const kind of ['approve','revoke','command','group-delete']) if((el=hit('data-tv-'+kind))) { managementCommand(kind,el.getAttribute('data-tv-'+kind));return; }
    if ((el=hit('data-tv-editor-panel'))) {state.themes.panel=el.dataset.tvEditorPanel;render();return;}
    if (hit('data-tv-fixtures')) {state.themes.list=fixtureThemeList();state.themes.usingFixtures=true;restoreThemeSelection();return;}
    if ((el = hit('data-tv-tab'))) { switchTab(el.getAttribute('data-tv-tab')); return; }
    if (hit('data-tv-refresh')) { refreshActive(); return; }
    if ((el = hit('data-tv-theme')) && !hit('data-tv-theme-new')) { selectTheme(el.getAttribute('data-tv-theme')); return; }
    if(hit('data-tv-theme-undo')){undoTheme();return;}
    if(hit('data-tv-theme-redo')){undoTheme(true);return;}
    for(const action of ['export','import','toggle','reset'])if(hit('data-tv-theme-'+action)){themeOperation(action);return;}
    if (hit('data-tv-theme-new')) { createTheme(); return; }
    if (hit('data-tv-theme-validate')) { validateTheme(); return; }
    if (hit('data-tv-theme-preview')) { previewTheme(); return; }
    if (hit('data-tv-theme-duplicate')) { duplicateTheme(); return; }
    if (hit('data-tv-theme-default')) { setDefaultTheme(); return; }
    if (hit('data-tv-theme-delete')) { deleteTheme(); return; }
    if (hit('data-tv-theme-revert')) { discardTheme(); return; }
    if ((el = hit('data-tv-view-mode'))) { state.themes.view = el.getAttribute('data-tv-view-mode') === 'json' ? 'json' : 'visual'; render(); return; }
    if ((el = hit('data-tv-page'))) { state.themes.page = Number(el.getAttribute('data-tv-page')) || 0; render(); return; }
    if ((el = hit('data-tv-prop-tab'))) { state.themes.selection = { kind: el.getAttribute('data-tv-prop-tab') }; render(); return; }
    if ((el = hit('data-tv-select'))) {
      const raw = el.getAttribute('data-tv-select'); const idx = raw.indexOf(':');
      state.themes.selection = { kind: raw.slice(0, idx), id: raw.slice(idx + 1) }; render(); return;
    }
    if (hit('data-tv-nav-add')) { navAdd(); return; }
    if ((el = hit('data-tv-nav-move'))) { const [id, dir] = el.getAttribute('data-tv-nav-move').split(':'); navMove(id, dir); return; }
    if ((el = hit('data-tv-nav-hide'))) { navHide(el.getAttribute('data-tv-nav-hide')); return; }
    if ((el = hit('data-tv-nav-del'))) { navDelete(el.getAttribute('data-tv-nav-del')); return; }
    if ((el = hit('data-tv-tile-del'))) { tileDelete(el.getAttribute('data-tv-tile-del')); return; }
    if ((el = hit('data-tv-sec-addtile'))) { sectionAddTile(el.getAttribute('data-tv-sec-addtile')); return; }
    if (hit('data-dwrt-savebar-save')) { if(operations?.owns(state.tab)){operations.save();return;} if (state.tab === 'terminals') saveRecord(); else if (state.tab === 'settings') saveSettings(); else if (state.tab === 'theme') saveTheme(); return; }
    if (hit('data-dwrt-savebar-discard')) { if(operations?.owns(state.tab)){operations.discard();return;} if (state.tab === 'terminals') { const ed=state.terminals.editor; if(ed) {if(ed.baseline)ed.draft=clone(ed.baseline);else state.terminals.editor=null;render();} } else if (state.tab === 'settings') discardSettings(); else if (state.tab === 'theme') discardTheme(); return; }
  }

  function onInput(e) {
    if(operations?.handleInput(e))return;
    const el = e.target;
    if (el.matches('[data-tv-terminal-search]')) {state.terminals.query=el.value;const pos=el.selectionStart;render();const input=q('[data-tv-terminal-search]');input.focus();try{input.setSelectionRange(pos,pos);}catch(_){} return;}
    if (el.matches('[data-tv-record-field]')) {state.terminals.editor.draft[el.dataset.tvRecordField]=el.value;const sb=q('[data-tv-record-savebar]');if(sb)sb.innerHTML=recordSavebar();return;}
    if (el.matches('[data-tv-theme-name]')) { state.themes.name = el.value; persistThemeDraft(); repaintPreview(); return; }
    if (el.matches('[data-tv-edit]') && el.type !== 'checkbox' && el.tagName !== 'SELECT') {
      const key = el.getAttribute('data-tv-edit');
      applyThemeEdit(key, el.value);
      qa(`[data-tv-edit="${key}"]`).forEach((sib) => { if (sib !== el && sib.value !== el.value) sib.value = el.value; });
      repaintPreview(); return;
    }
    if (el.matches('[data-tv-set]') && el.type !== 'checkbox' && el.tagName !== 'SELECT') {
      setSettingsPath(el.getAttribute('data-tv-set'), el.value);
      const sb = q('[data-tv-savebar]'); if (sb) sb.innerHTML = settingsSavebar();
      const dh = q('[data-tv-set-dirty]'); if (dh) dh.innerHTML = isSettingsDirty() ? badge('未保存', 'warn') : badge('已同步', 'ok');
    }
  }

  function onChange(e) {
    if(operations?.handleInput(e))return;
    const el = e.target;
    if (el.matches('[data-tv-record-field]')) {state.terminals.editor.draft[el.dataset.tvRecordField]=el.value;const sb=q('[data-tv-record-savebar]');if(sb)sb.innerHTML=recordSavebar();return;}
    if(el.matches('[data-tv-theme-file]')){state.themes.importFile=el.files?.[0]||null;const label=q('[data-tv-theme-filename]');if(label)label.textContent=state.themes.importFile?.name||'JSON 不包含素材文件';return;}
    if (el.matches('[data-tv-theme-style]')) { switchStyle(el.value); return; }
    if (el.matches('[data-tv-lock]')) { applyLock(el.getAttribute('data-tv-lock'), el.checked); render(); return; }
    if (el.matches('[data-tv-edit]')) {
      const key = el.getAttribute('data-tv-edit');
      applyThemeEdit(key, el.type === 'checkbox' ? el.checked : el.value);
      render(); return;
    }
    if (el.matches('[data-tv-set]')) {
      setSettingsPath(el.getAttribute('data-tv-set'), el.type === 'checkbox' ? el.checked : el.value);
      render();
    }
  }

  function bindEvents() {
    if (state._bound) return;
    state._bound = true;
    root.addEventListener('click', onClick);
    root.addEventListener('input', onInput);
    root.addEventListener('change', onChange);
  }
  function unbindEvents() {
    root.removeEventListener('click', onClick);
    root.removeEventListener('input', onInput);
    root.removeEventListener('change', onChange);
    state._bound = false;
  }
  // ---- 注入样式：外壳消费共享 --dwrt/--lg 玻璃令牌；画布（TV 屏模拟）用隔离的 --tvh-* 字面色，二者不串扰 ----
  let TVHOME_CSS = '';
  TVHOME_CSS += `
  .tvhome-shell{display:flex;flex-direction:column;gap:16px;height:100%;box-sizing:border-box;padding:18px 20px 96px;color:var(--dwrt-text-strong,#e9eef5);font:inherit;overflow:auto}
  .tvhome-shell *{box-sizing:border-box}
  .tvhome-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap}
  .tvhome-title{margin:0;font-size:20px;font-weight:650;letter-spacing:.2px}
  .tvhome-subtitle{margin:2px 0 0;font-size:12.5px;color:var(--dwrt-text-muted,#9aa7b8)}
  .tvhome-head-ops{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
  .tvhome-tabs{flex-wrap:wrap}
  .tvhome-tab-flag{margin-inline-start:6px;font-size:10px;padding:1px 6px;border-radius:999px;background:var(--lg-surface-2,rgba(255,255,255,.08));color:var(--dwrt-text-muted,#9aa7b8);vertical-align:middle}
  .tvhome-panel{padding:16px 18px;border-radius:var(--dwrt-radius-lg,16px);display:flex;flex-direction:column;gap:12px}
  .tvhome-panel-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .tvhome-panel-head h2{margin:0;font-size:15.5px;font-weight:620}
  .tvhome-note{margin:0;font-size:12px;line-height:1.55;color:var(--dwrt-text-muted,#9aa7b8)}
  .tvhome-loading{padding:28px;text-align:center;color:var(--dwrt-text-muted,#9aa7b8)}
  .tvhome-state{margin:0}
  .tvhome-empty{padding:14px;text-align:center;color:var(--dwrt-text-muted,#9aa7b8);font-size:12.5px}
  .tvhome-jump-row{display:flex;gap:8px;flex-wrap:wrap;margin-top:4px}
  .tvhome-cap-panel{padding:16px 18px;border-radius:var(--dwrt-radius-lg,16px);display:flex;flex-direction:column;gap:10px;margin-top:16px}
  .tvhome-cap-list{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px}
  .tvhome-cap-row{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 10px;border-radius:10px;background:var(--lg-surface-1,rgba(255,255,255,.05))}
  .tvhome-cap-name{font-size:13px}
  `;
  TVHOME_CSS += `
  .tvhome-theme-workspace{display:grid;grid-template-columns:240px minmax(0,1fr) 320px;gap:14px;align-items:start}
  .tvhome-theme-list,.tvhome-canvas-panel,.tvhome-prop-panel{padding:14px;border-radius:var(--dwrt-radius-lg,16px);display:flex;flex-direction:column;gap:10px;min-width:0}
  .tvhome-theme-rows{display:flex;flex-direction:column;gap:6px}
  .tvhome-theme-row{display:flex;flex-direction:column;gap:2px;text-align:left;padding:8px 10px;border-radius:10px;border:1px solid transparent;background:var(--lg-surface-1,rgba(255,255,255,.05));color:inherit;cursor:pointer}
  .tvhome-theme-row.is-active{border-color:var(--dwrt-accent,#3f8cff);background:var(--lg-surface-2,rgba(63,140,255,.14))}
  .tvhome-theme-name{font-size:13px;font-weight:560}
  .tvhome-theme-meta{font-size:11px;color:var(--dwrt-text-muted,#9aa7b8)}
  .tvhome-canvas-toolbar{display:flex;align-items:flex-end;gap:10px;flex-wrap:wrap}
  .tvhome-toolbar-spacer{flex:1 1 auto}
  .tvhome-field{display:flex;flex-direction:column;gap:4px;font-size:11.5px;color:var(--dwrt-text-muted,#9aa7b8);min-width:0}
  .tvhome-field>span{font-size:11px}
  .tvhome-field .dwrt-kit-input,.tvhome-prop-field .dwrt-kit-input{width:100%}
  .tvhome-field-name{min-width:180px;flex:1 1 200px}
  .tvhome-view-toggle{display:inline-flex;gap:4px}
  .tvhome-canvas-scroll{width:100%;overflow:auto;border-radius:12px;background:var(--lg-surface-0,rgba(0,0,0,.18));padding:10px}
  .tvhome-issues:empty{display:none}
  .tvhome-issues{font-size:12px;color:#ffd7d7;background:rgba(220,80,80,.14);border:1px solid rgba(220,80,80,.4);border-radius:10px;padding:8px 12px}
  .tvhome-issues ul{margin:6px 0 0;padding-inline-start:18px}
  .tvhome-json-view{display:flex;flex-direction:column;gap:8px}
  .tvhome-json{margin:0;max-height:60vh;overflow:auto;font-size:11.5px;line-height:1.5;background:rgba(0,0,0,.3);border-radius:10px;padding:12px;white-space:pre-wrap;word-break:break-word}
  .tvhome-prop-head{display:flex;flex-direction:column;gap:8px}
  .tvhome-prop-head h2{margin:0;font-size:14px}
  .tvhome-prop-tabs{display:flex;gap:6px}
  .tvhome-prop-crumb{margin:0;font-size:11.5px;color:var(--dwrt-text-muted,#9aa7b8)}
  .tvhome-prop-body{display:flex;flex-direction:column;gap:14px;max-height:64vh;overflow:auto;padding-inline-end:2px}
  .tvhome-prop-group{display:flex;flex-direction:column;gap:8px;padding-bottom:10px;border-bottom:1px solid var(--lg-border,rgba(255,255,255,.08))}
  .tvhome-prop-group>h3{margin:0;font-size:12.5px;font-weight:620;color:var(--dwrt-text,#c7d2e0)}
  .tvhome-prop-field{flex-direction:row;align-items:center;justify-content:space-between;gap:10px}
  .tvhome-prop-field>span{flex:0 0 auto;max-width:56%}
  .tvhome-prop-field .dwrt-kit-input,.tvhome-prop-field select,.tvhome-color-field{flex:1 1 auto;max-width:150px}
  .tvhome-color-field{display:inline-flex;gap:6px;align-items:center}
  .tvhome-color{width:34px;height:28px;padding:0;border:none;background:none;cursor:pointer}
  .tvhome-hex{max-width:100px}
  .tvhome-toggle{display:inline-flex;align-items:center;gap:8px;font-size:12.5px;color:var(--dwrt-text,#c7d2e0);cursor:pointer}
  .tvhome-lock-grid,.tvhome-mod-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:6px}
  .tvhome-inline-savebar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:10px 14px;border-radius:12px;font-size:12.5px;margin-top:4px}
  .tvhome-navlist{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:6px}
  .tvhome-navrow{display:flex;align-items:center;gap:6px;padding:6px 8px;border-radius:10px;background:var(--lg-surface-1,rgba(255,255,255,.05))}
  .tvhome-navrow.is-hidden{opacity:.6}
  .tvhome-navrow-main{flex:1 1 auto;display:flex;flex-direction:column;gap:1px;text-align:left;background:none;border:none;color:inherit;cursor:pointer;min-width:0}
  .tvhome-navrow-main em{font-style:normal;font-size:10.5px;color:var(--dwrt-text-muted,#9aa7b8)}
  .tvhome-navrow-ops{display:inline-flex;gap:3px}
  .dwrt-kit-btn.is-icon{padding:3px 7px;min-width:0;font-size:12px}
  .dwrt-kit-btn.is-danger{color:#ff9d9d}
  .tvhome-geo-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:6px}
  .tvhome-geo-h{font-size:11px;color:var(--dwrt-text-muted,#9aa7b8)}
  .tvhome-subtile-list{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0}
  .tvhome-mini-table{width:100%;border-collapse:collapse;font-size:11.5px}
  .tvhome-mini-table th,.tvhome-mini-table td{border:1px solid var(--lg-border,rgba(255,255,255,.1));padding:4px 6px;text-align:left}
  .tvhome-inherit td i{color:var(--dwrt-text-muted,#8b98a9)}
  `;
  TVHOME_CSS += `
  .tvhome-canvas{position:relative;aspect-ratio:16/9;width:100%;min-height:280px;border-radius:calc(var(--tvh-radius,16px)*.6);overflow:hidden;color:var(--tvh-fg,#f2f4f7);background:var(--tvh-bg,#202326);font-size:clamp(10px,1.4vw,15px);box-shadow:0 8px 30px rgba(0,0,0,.35)}
  .tvhome-canvas-bg{position:absolute;inset:0;background:var(--tvh-bg,#202326)}
  .tvhome-canvas-dim{position:absolute;inset:0;background:#000}
  .tvhome-canvas-bg-note{position:absolute;left:10px;bottom:10px;font-size:11px;padding:3px 8px;border-radius:8px;background:rgba(0,0,0,.5);color:#fff}
  .tvhome-canvas-inner{position:relative;z-index:1;height:100%;display:flex;flex-direction:column;padding:3% 4%}
  .tvhome-canvas-header{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:2.5%}
  .tvhome-canvas-brand{font-weight:700;letter-spacing:.5px;color:var(--tvh-primary,#3f8cff)}
  .tvhome-canvas-hchips{display:inline-flex;gap:6px}
  .tvhome-chip{font-size:.8em;padding:2px 8px;border-radius:999px;background:color-mix(in srgb,var(--tvh-surface,#2a2f36) 80%,transparent)}
  .tvhome-chip.is-muted{opacity:.6}
  .tvhome-canvas-body{flex:1 1 auto;display:flex;gap:3%;min-height:0}
  .tvhome-canvas-nav{display:flex;flex-direction:column;gap:6px;min-width:88px;max-width:22%}
  .tvhome-nav-item{display:flex;align-items:center;justify-content:space-between;gap:6px;text-align:left;padding:6px 10px;border-radius:calc(var(--tvh-radius,16px)*.5);border:2px solid transparent;background:color-mix(in srgb,var(--tvh-surface,#2a2f36) 70%,transparent);color:inherit;cursor:pointer;font-size:.85em}
  .tvhome-nav-item.is-selected{border-color:var(--tvh-focus,#3f8cff);transform:scale(var(--tvh-focus-scale,1.06))}
  .tvhome-nav-item.is-hidden{opacity:.4;text-decoration:line-through}
  .tvhome-nav-item.is-disabled{opacity:.55}
  .tvhome-nav-flag{font-size:.7em;padding:0 5px;border-radius:6px;background:rgba(0,0,0,.4)}
  .tvhome-canvas-home{flex:1 1 auto;min-width:0;overflow:hidden}
  .tvhome-flow{display:flex;flex-direction:column;gap:3%}
  .tvhome-flow-head{display:flex;align-items:baseline;justify-content:space-between;gap:8px;margin-bottom:4px}
  .tvhome-flow-title{font-weight:600}
  .tvhome-flow-src{font-size:.72em;opacity:.6}
  .tvhome-flow-section{border:2px solid transparent;border-radius:calc(var(--tvh-radius,16px)*.5);padding:6px}
  .tvhome-flow-section.is-selected{border-color:var(--tvh-focus,#3f8cff)}
  .tvhome-flow-tiles{display:flex;gap:8px;flex-wrap:wrap}
  .tvhome-flow-empty{font-size:.8em;opacity:.7;padding:10px;border:1px dashed color-mix(in srgb,var(--tvh-fg,#fff) 30%,transparent);border-radius:8px}
  .tvhome-tile{display:flex;flex-direction:column;gap:2px;justify-content:center;align-items:flex-start;padding:8px 10px;min-width:74px;min-height:48px;border-radius:calc(var(--tvh-radius,16px)*.5);border:2px solid transparent;background:color-mix(in srgb,var(--tvh-surface,#2a2f36) 85%,transparent);color:inherit;cursor:pointer;font-size:.82em;overflow:hidden}
  .tvhome-tile.is-selected{border-color:var(--tvh-focus,#3f8cff);transform:scale(var(--tvh-focus-scale,1.06))}
  .tvhome-tile-k{font-weight:600}
  .tvhome-tile-sub,.tvhome-tile-flag{font-size:.78em;opacity:.7;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}
  .tvhome-tile-flag{color:#ffcaca}
  .tvhome-grid-wrap{display:flex;flex-direction:column;gap:6px;height:100%}
  .tvhome-page-tabs{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
  .tvhome-page-tab{font-size:.8em;padding:3px 10px;border-radius:999px;border:none;background:color-mix(in srgb,var(--tvh-surface,#2a2f36) 70%,transparent);color:inherit;cursor:pointer}
  .tvhome-page-tab.is-active{background:var(--tvh-primary,#3f8cff);color:#fff}
  .tvhome-grid-meta{margin-inline-start:auto;font-size:.72em;opacity:.6}
  .tvhome-grid{flex:1 1 auto;display:grid;gap:6px;min-height:120px}
  .tvhome-grid-tile{min-height:0;min-width:0}
  .tvhome-dock{display:flex;gap:8px;justify-content:center;padding-top:6px}
  .tvhome-dock-item{padding:6px 12px;border-radius:calc(var(--tvh-radius,16px)*.5);border:2px solid transparent;background:color-mix(in srgb,var(--tvh-surface,#2a2f36) 90%,transparent);color:inherit;cursor:pointer;font-size:.82em}
  .tvhome-dock-item.is-selected{border-color:var(--tvh-focus,#3f8cff)}
  .tvhome-canvas-tag{position:absolute;right:8px;top:8px;z-index:2;font-size:10px;padding:2px 8px;border-radius:8px;background:rgba(0,0,0,.5);color:#fff}
  `;
  TVHOME_CSS += `
  .tvhome-table-wrap{width:100%;overflow:auto;border-radius:12px}
  .tvhome-table{width:100%;border-collapse:collapse;font-size:12.5px;min-width:820px}
  .tvhome-table th,.tvhome-table td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--lg-border,rgba(255,255,255,.08));white-space:nowrap}
  .tvhome-table thead th{position:sticky;top:0;background:var(--lg-surface-2,rgba(20,26,32,.9));font-weight:600;font-size:11.5px;color:var(--dwrt-text-muted,#9aa7b8)}
  .tvhome-mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px}
  .tvhome-principal.is-empty{color:#ffcf8f}
  .tvhome-set-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
  .tvhome-set-group{display:flex;flex-direction:column;gap:10px;padding:14px;border-radius:12px;background:var(--lg-surface-1,rgba(255,255,255,.04))}
  .tvhome-set-group>h3{margin:0;font-size:13px;font-weight:620}
  .tvhome-set-sub{font-size:11.5px;color:var(--dwrt-text-muted,#9aa7b8)}
  .tvhome-mod-grid{gap:8px}
  .tvhome-mod-row{display:flex;align-items:center;justify-content:space-between;gap:8px;font-size:12.5px}
  @media (max-width:1439px){.tvhome-theme-workspace{grid-template-columns:220px minmax(0,1fr) 300px}}
  @media (max-width:1279px){
    .tvhome-theme-workspace{grid-template-columns:200px minmax(0,1fr);}
    .tvhome-prop-panel{grid-column:1 / -1}
    .tvhome-prop-body{max-height:none}
  }
  @media (max-width:820px){
    .tvhome-theme-workspace{grid-template-columns:1fr}
    .tvhome-theme-list,.tvhome-prop-panel{grid-column:auto}
    .tvhome-prop-field{flex-direction:column;align-items:stretch}
    .tvhome-prop-field>span{max-width:none}
    .tvhome-prop-field .dwrt-kit-input,.tvhome-prop-field select,.tvhome-color-field{max-width:none}
  }
  @media (max-width:480px){
    .tvhome-shell{padding:14px 12px 96px}
    .tvhome-head{flex-direction:column;align-items:stretch}
    .tvhome-canvas-nav{min-width:64px}
    .tvhome-set-grid{grid-template-columns:1fr}
  }
  @media (max-width:360px){
    .tvhome-title{font-size:18px}
    .tvhome-canvas-body{flex-direction:column}
    .tvhome-canvas-nav{flex-direction:row;max-width:none;overflow:auto}
  }
  .tvhome-shell [disabled]{opacity:.55;cursor:not-allowed}
  `;

  function injectStyles() {
    if (typeof document === 'undefined' || document.getElementById('tvhome-styles')) return;
    const style = document.createElement('style');
    style.id = 'tvhome-styles';
    style.textContent = TVHOME_CSS;
    (document.head || document.documentElement).appendChild(style);
  }
  function persistDrafts() {
    try { if (state.themes.draft && isThemeDirty()) persistThemeDraft(); if (state.settings.draft && isSettingsDirty()) persistSettingsDraft(); } catch (_) {}
  }

  operations=createOperations({request:requestJson,render,root,ui,canWrite,escape:escapeHtml,activeTab:()=>state.tab});
  // ---- 挂载 ----
  for(const [id,href] of [['tvhome-rail-css','/static/desktop/dwrt-rail.css?v=20261008-desktop-material-01'],['tvhome-app-css','/plugins/native/tvhome.css?v=20261005-tvhome-table-03']]) {if(!document.getElementById(id)){const link=document.createElement('link');link.id=id;link.rel='stylesheet';link.href=href;document.head.appendChild(link);}}
  window.addEventListener('beforeunload',beforeLeave);
  injectStyles();
  if (stage && stage.classList) stage.classList.add('has-tvhome');
  render();
  ensureTabData();

  return {
    unmount() {
      persistDrafts();
      operations.destroy();
      state.mounted = false; state.seq += 1;
      unbindEvents();
      window.removeEventListener('beforeunload',beforeLeave);
      if (stage && stage.classList) stage.classList.remove('has-tvhome');
      const style = typeof document !== 'undefined' ? document.getElementById('tvhome-styles') : null;
      if (style) style.remove();
      if (root && typeof root.replaceChildren === 'function') root.replaceChildren();
      else if (root) root.innerHTML = '';
    }
  };
}

export default { mount };
