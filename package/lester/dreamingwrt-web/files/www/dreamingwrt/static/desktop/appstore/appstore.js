/* DreamingOS 应用中心 (App Store) — 独立市场页面。
 *
 * 唯一数据面 = 本机 /api/v1/appstore/*（app_registry 为已安装真值）：
 *   GET  /catalog                 顶层裸对象 {ok,schema,capabilities,device,index,categories,apps}
 *   GET  /installed               {ok,data:{apps,installed,count,truth_source}}
 *   GET  /apps/{id}/status        {ok,data:{installStatus,runtimeState,operation,selectedRelease,...}}
 *   POST /catalog/refresh         202 {ok,data:{task_id}}
 *   GET  /tasks/{taskId}          {ok,data:{state,stage,percent,error,...}}
 *   POST /apps/{id}/{install|update|uninstall|rollback}  202 {ok,data:{task_id,operation}}
 *
 * 诚实原则：不读随包静态 catalog.json，不用 /plugins/native 冒充安装真值，不展示无真实
 * 来源的评分/下载量。安装动作仅在 capabilities.installer==='dapp-v1' 时开启。
 */
(function () {
  'use strict';

  var API = '/api/v1/appstore';
  var HERO_INTERVAL = 5000;
  var POLL_MIN = 1000, POLL_MAX = 3000;

  // ---------------- Icons (Lucide-style, stroke) ----------------
  var ICON_PATHS = {
    compass: '<circle cx="12" cy="12" r="10"/><polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"/>',
    installed: '<path d="M18 6 7 17l-5-5"/><path d="m22 10-7.5 7.5L13 16"/>',
    star: '<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>',
    film: '<rect width="18" height="18" x="3" y="3" rx="2"/><path d="M7 3v18M17 3v18M3 7.5h4M17 7.5h4M3 12h18M3 16.5h4M17 16.5h4"/>',
    'hard-drive': '<line x1="22" x2="2" y1="12" y2="12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" x2="6.01" y1="16" y2="16"/><line x1="10" x2="10.01" y1="16" y2="16"/>',
    zap: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    code: '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>',
    globe: '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20M2 12h20"/>',
    shield: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
    settings: '<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>',
    bot: '<path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2M20 14h2M15 13v2M9 13v2"/>',
    activity: '<path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/>',
    cpu: '<rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2M15 20v2M2 15h2M2 9h2M20 15h2M20 9h2M9 2v2M9 20v2"/>',
    'credit-card': '<rect width="20" height="14" x="2" y="5" rx="2"/><line x1="2" x2="22" y1="10" y2="10"/>'
  };
  function icon(name) {
    var p = ICON_PATHS[name] || ICON_PATHS.star;
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
      'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + p + '</svg>';
  }
  // ---------------- Request layer ----------------
  // DWRT_REQUEST.json 会话门控：非 2xx / ok:false 抛错(err.status,err.payload)，否则返回解析体。
  function req(url, opts) {
    if (window.DWRT_REQUEST && typeof window.DWRT_REQUEST.json === 'function')
      return window.DWRT_REQUEST.json(url, opts);
    return fetch(url, Object.assign({ credentials: 'same-origin', cache: 'no-store' }, opts || {}))
      .then(function (r) {
        return r.text().then(function (t) {
          var j = {}; if (t) { try { j = JSON.parse(t); } catch (e) { throw new Error('invalid json'); } }
          if (!r.ok || (j && j.ok === false)) {
            var msg = (j && j.error && (j.error.message || j.error.code)) || ('HTTP ' + r.status);
            var e = new Error(msg); e.status = r.status; e.payload = j; throw e;
          }
          return j;
        });
      });
  }
  function postJSON(url, body) {
    return req(url, { method: 'POST', body: JSON.stringify(body || {}) });
  }
  function errText(e) {
    if (!e) return '未知错误';
    if (e.payload && e.payload.error) return e.payload.error.message || e.payload.error.code || '请求失败';
    return e.message || '请求失败';
  }

  // ---------------- Utilities ----------------
  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function initial(name) {
    var s = String(name || '').trim();
    return s ? s.charAt(0).toUpperCase() : '#';
  }
  function fmtBytes(n) {
    n = Number(n);
    if (!isFinite(n) || n <= 0) return '';
    var u = ['B', 'KB', 'MB', 'GB'], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : n.toFixed(1).replace(/\.0$/, '')) + ' ' + u[i];
  }
  // 精简签名 catalog 无品牌色：由 id 派生稳定色，仅作占位视觉，不冒充官方素材。
  function hashColor(id) {
    var s = String(id || ''), h = 0;
    for (var i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
    return 'hsl(' + (h % 360) + ' 60% 46%)';
  }
  function tileBg(id) {
    var c = hashColor(id);
    return 'linear-gradient(135deg, ' + c + ' 0%, color-mix(in srgb, ' + c + ' 55%, #000) 100%)';
  }
  // ---------------- State ----------------
  var state = {
    ready: false,
    installerEnabled: false,          // capabilities.installer === 'dapp-v1'
    capabilities: {}, device: {}, index: {},
    categories: [], apps: [], byId: {}, catById: {},
    installed: {},                    // id -> /installed data.apps 条目（安装真值）
    catalogError: null, installedError: null,
    configs: {}, nativePlugins: [], nativeError: null, nativeMount: null, nativeId: null,
    statusById: {},                   // id -> /apps/{id}/status data（详情缓存）
    polls: {},                        // id -> {taskId,type,gen,delay,op,timer}
    opGen: 0,
    view: 'discover',
    detailId: null, detailGen: 0, detailFrom: null,
    lastCat: null, lastQuery: '',
    hero: { list: [], index: 0, timer: null }
  };

  // ---------------- View switching ----------------
  var VIEWS = {
    discover: 'asViewDiscover', category: 'asViewCategory',
    search: 'asViewSearch', installed: 'asViewInstalled', detail: 'asViewDetail'
  };
  function showView(name) {
    if (name !== 'detail' && !allowNativeLeave()) return false;
    state.view = name;
    if (name !== 'detail') { if (state.nativeMount) state.nativeMount.unmount(); state.nativeMount = null; state.nativeId = null; }
    Object.keys(VIEWS).forEach(function (k) {
      var el = $(VIEWS[k]); if (el) el.hidden = (k !== name);
    });
    if (name !== 'discover') stopHero();
    var main = $('asMain'); if (main) main.scrollTop = 0;
  }

  // ---------------- Derived helpers ----------------
  function categoryName(catId) { var c = state.catById[catId]; return c ? c.name : ''; }
  function installedEntry(id) { return state.installed[id] || null; }
  function isBusy(id) { return !!state.polls[id]; }
  function opVerb(type) {
    return ({ install: '安装', update: '更新', uninstall: '卸载', rollback: '回滚', configure: '保存配置', 'catalog-refresh': '刷新' })[type] || '处理';
  }
  function unavailableText(reason, app) {
    app = app || {};
    if (reason === 'requirements_invalid') return '应用的安装要求声明无效，需发布方修正';
    if (reason === 'capability_unavailable') {
      var missing = Array.isArray(app.missingCapabilities) ? app.missingCapabilities.filter(function (name) { return typeof name === 'string'; }) : [];
      if (app.capabilityReason === 'capability_unknown')
        return '平台尚未识别应用要求的能力' + (missing.length ? '：' + missing.join('、') : '');
      if (missing.indexOf('tun') >= 0) {
        if (app.capabilityReason === 'tun_unavailable') return '当前设备无法访问 TUN 接口';
        return '当前设备缺少可用的 TUN 内核支持';
      }
      return '应用所需能力不可用' + (missing.length ? '：' + missing.join('、') : '');
    }
    return ({
      architecture_unsupported: '当前设备架构不支持',
      platform_unsupported: '平台接口版本不匹配'
    })[reason] || '暂不可安装';
  }
  function runtimeText(rs) {
    return ({ running: '运行中', stopped: '已停止', degraded: '运行异常', starting: '启动中', unknown: '状态未知' })[rs] || (rs || '');
  }
  function stageText(stage) {
    return ({
      queued: '排队中', download: '下载中', verify: '验签中', unpack: '解包中',
      manifest: '读取清单', configure: '校验与应用配置', config: '写入配置', staging: '暂存中', preflight: '预检中',
      activate: '启用中', health: '健康检查', 'health-check': '健康检查',
      rollback: '回滚中', cleanup: '清理中'
    })[stage] || (stage ? esc(stage) : '处理中');
  }
  // ---------------- Reusable card pieces ----------------
  // 应用图标解析（优先级）：①目录下发的 app.icon（Lucide 名，需 webd 透传）→
  // ②内置首方映射 APP_ICONS → ③所属分类图标 → ④首字母底色块（占位，不冒充官方素材）。
  var APP_ICONS = {};
  function resolveAppIcon(app) {
    if (!app) return null;
    if (app.icon && ICON_PATHS[app.icon]) return app.icon;
    if (app.id && APP_ICONS[app.id]) return APP_ICONS[app.id];
    var c = (app.category && state.catById) ? state.catById[app.category] : null;
    if (c && c.icon && ICON_PATHS[c.icon]) return c.icon;
    return null;
  }
  function logoTile(app, px) {
    px = px || 48;
    var images = {openlist:'/static/desktop/assets/openlist.png',easytier:'/static/desktop/assets/EasyTier.png'};
    if (images[app.id]) return '<img class="as-logo-image" src="' + images[app.id] + '" width="' + px + '" height="' + px + '" alt="" draggable="false">';
    var ic = resolveAppIcon(app);
    var inner = ic ? icon(ic) : esc(initial(app.name));
    return '<div class="as-logo" style="width:' + px + 'px;height:' + px + 'px;font-size:' +
      Math.round(px * 0.42) + 'px;background:' + tileBg(app.id) + '">' + inner + '</div>';
  }
  function badges(app) {
    return app.featured ? '<span class="as-badge as-badge-featured">精选</span>' : '';
  }
  function metaLine(app) {
    var bits = [];
    var cn = categoryName(app.category); if (cn) bits.push(esc(cn));
    if (app.version) bits.push('v' + esc(app.version));
    return bits.join(' · ');
  }
  // 卡片副文本：安装真值优先（/installed），否则不可装原因，否则未安装。
  function cardState(app) {
    if (isBusy(app.id)) return opVerb(state.polls[app.id].type) + '中…';
    var inst = installedEntry(app.id);
    if (inst) return '已安装 · ' + runtimeText(inst.runtimeState) + (inst.installedVersion ? ' · v' + esc(inst.installedVersion) : '');
    if (!app.installable) return unavailableText(app.unavailableReason, app);
    return '未安装';
  }
  function actionBtn(app) {
    if (isBusy(app.id))
      return '<button type="button" class="as-btn as-btn-pending" disabled>' + opVerb(state.polls[app.id].type) + '中</button>';
    if (installedEntry(app.id))
      return '<button type="button" class="as-btn as-btn-open" data-detail="' + esc(app.id) + '">管理</button>';
    if (!app.installable)
      return '<button type="button" class="as-btn as-btn-pending" disabled title="' + esc(unavailableText(app.unavailableReason, app)) + '">不可安装</button>';
    if (!state.installerEnabled)
      return '<button type="button" class="as-btn as-btn-pending" disabled title="当前后端未启用安装器">获取</button>';
    return '<button type="button" class="as-btn as-btn-get" data-get="' + esc(app.id) + '">获取</button>';
  }
  function featuredCard(app) {
    return '<div class="as-featured-card" data-detail="' + esc(app.id) + '">' +
      '<div class="as-fc-top">' + logoTile(app, 52) +
        '<div class="as-fc-body">' +
          '<div class="as-card-meta">' + esc(categoryName(app.category)) + '</div>' +
          '<div class="as-fc-name">' + esc(app.name) + ' ' + badges(app) + '</div>' +
          '<p class="as-fc-desc">' + esc(cardState(app)) + '</p>' +
        '</div>' +
      '</div>' +
      '<div class="as-fc-foot">' + actionBtn(app) + '</div>' +
    '</div>';
  }
  function gridCard(app) {
    return '<div class="as-card" data-detail="' + esc(app.id) + '">' + logoTile(app, 46) +
      '<div class="as-card-body">' +
        '<div class="as-card-name">' + esc(app.name) + ' ' + badges(app) + '</div>' +
        '<p class="as-card-desc">' + esc(metaLine(app)) + '</p>' +
        '<div class="as-card-meta">' + esc(cardState(app)) + '</div>' +
      '</div>' + actionBtn(app) + '</div>';
  }
  // ---------------- Hero carousel ----------------
  function buildHero() {
    var host = $('asHero'); if (!host) return;
    var list = state.hero.list;
    if (!list.length) { host.innerHTML = ''; host.hidden = true; return; }
    host.hidden = false;
    host.innerHTML =
      '<div class="as-hero-track">' + list.map(function (app, i) {
        return '<div class="as-hero-slide' + (i === 0 ? ' is-active' : '') + '" data-hi="' + i +
          '" data-detail="' + esc(app.id) + '" style="background:' + tileBg(app.id) + '">' +
          '<div class="as-hero-inner">' +
            '<div class="as-hero-eyebrow">' + esc(categoryName(app.category) || '精选应用') + '</div>' +
            '<h2 class="as-hero-name">' + esc(app.name) + '</h2>' +
            '<p class="as-hero-sub">' + esc(metaLine(app)) + '</p>' +
          '</div>' + logoTile(app, 72) +
        '</div>';
      }).join('') + '</div>' +
      (list.length > 1 ? '<div class="as-hero-dots">' + list.map(function (_, i) {
        return '<button type="button" class="as-hero-dot' + (i === 0 ? ' is-active' : '') + '" data-hi="' + i + '" aria-label="幻灯片 ' + (i + 1) + '"></button>';
      }).join('') + '</div>' : '');
    state.hero.index = 0;
    startHero();
  }
  function goHero(i) {
    var list = state.hero.list; if (!list.length) return;
    state.hero.index = (i + list.length) % list.length;
    var host = $('asHero'); if (!host) return;
    host.querySelectorAll('.as-hero-slide').forEach(function (el, k) { el.classList.toggle('is-active', k === state.hero.index); });
    host.querySelectorAll('.as-hero-dot').forEach(function (el, k) { el.classList.toggle('is-active', k === state.hero.index); });
  }
  function startHero() {
    stopHero();
    if (state.hero.list.length > 1)
      state.hero.timer = setInterval(function () { goHero(state.hero.index + 1); }, HERO_INTERVAL);
  }
  function stopHero() { if (state.hero.timer) { clearInterval(state.hero.timer); state.hero.timer = null; } }

  // ---------------- Navigation ----------------
  // Shared desktop rail item (dwrt-rail.css): icon tile + title (+ gray description),
  // same markup contract as the 系统设置 rail; data-nav keeps this page's routing.
  function navItem(id, label, ic, active, desc) {
    return '<button type="button" class="dwrt-rail-item' + (active ? ' is-active' : '') +
      '" data-nav="' + esc(id) + '" title="' + esc(label) + '"' + (active ? ' aria-current="page"' : '') + '>' +
      '<span class="dwrt-rail-item-icon" aria-hidden="true">' + icon(ic) + '</span>' +
      '<span class="dwrt-rail-item-text"><span class="dwrt-rail-item-title">' + esc(label) + '</span>' +
      (desc ? '<span class="dwrt-rail-item-desc">' + esc(desc) + '</span>' : '') + '</span></button>';
  }
  function renderNav() {
    var host = $('asNav'); if (!host) return;
    var out = navItem('discover', '发现', 'compass', state.view === 'discover', '今日推荐与精选') +
      navItem('installed', '已安装', 'installed', state.view === 'installed', '管理已安装的应用');
    if (state.categories.length) {
      out += '<div class="dwrt-rail-group-label">分类</div>' +
        state.categories.map(function (c) {
          return navItem('cat:' + c.id, c.name, c.icon || 'star', state.view === 'category' && state.lastCat === c.id);
        }).join('');
    }
    host.innerHTML = out;
  }
  function setActiveNav() { renderNav(); }
  // ---------------- Discover view ----------------
  function renderDiscover() {
    state.hero.list = state.apps.filter(function (a) { return a.homepage; });
    if (!state.hero.list.length) state.hero.list = state.apps.slice(0, Math.min(4, state.apps.length));
    if (state.view === 'discover') buildHero();

    var featured = state.apps.filter(function (a) { return a.featured; });
    var fEl = $('asFeatured'); if (fEl) fEl.innerHTML = featured.map(featuredCard).join('');
    var fSec = $('asFeaturedSection'); if (fSec) fSec.hidden = !featured.length;

    var rEl = $('asRank'); if (rEl) rEl.innerHTML = state.apps.length ? state.apps.map(gridCard).join('') :
      '<div class="as-empty">目录暂无应用。' + (state.catalogError ? esc(state.catalogError) : '可点击右上角「刷新」拉取最新目录。') + '</div>';
  }

  // ---------------- Category view ----------------
  function openCategory(catId) {
    state.lastCat = catId;
    showView('category'); setActiveNav();
    var cat = state.catById[catId];
    var eb = $('asCategoryEyebrow'); if (eb) eb.textContent = '分类';
    var ti = $('asCategoryTitle'); if (ti) ti.textContent = cat ? cat.name : catId;
    var list = state.apps.filter(function (a) { return a.category === catId; });
    var grid = $('asCategoryGrid'); if (grid) grid.innerHTML = list.map(gridCard).join('');
    var empty = $('asCategoryEmpty'); if (empty) empty.hidden = !!list.length;
  }

  // ---------------- Search view ----------------
  function runSearch(q) {
    state.lastQuery = q;
    var norm = String(q || '').trim().toLowerCase();
    showView('search'); setActiveNav();
    var ti = $('asSearchTitle'); if (ti) ti.textContent = norm ? '搜索：' + q : '搜索';
    var list = norm ? state.apps.filter(function (a) {
      return String(a.name || '').toLowerCase().indexOf(norm) >= 0 ||
        String(a.id || '').toLowerCase().indexOf(norm) >= 0 ||
        String(categoryName(a.category) || '').toLowerCase().indexOf(norm) >= 0;
    }) : [];
    var grid = $('asSearchGrid'); if (grid) grid.innerHTML = list.map(gridCard).join('');
    var empty = $('asSearchEmpty'); if (empty) { empty.hidden = !!list.length; empty.textContent = norm ? '没有匹配「' + q + '」的应用。' : '输入关键字搜索应用。'; }
  }

  // ---------------- Installed view (app_registry truth) ----------------
  function renderInstalled() {
    var ids = Object.keys(state.installed), native = state.nativePlugins.filter(function (p) { return p.id === 'openlist'; });
    var cnt = $('asInstalledCount'); if (cnt) cnt.textContent = ids.length + ' 个商店应用' + (native.length ? ' · ' + native.length + ' 个本机插件' : '');
    var grid = $('asInstalledGrid'), empty = $('asInstalledEmpty');
    var html = state.installedError ? '<div class="as-detail-note">无法读取商店应用：' + esc(state.installedError) + ' <button class="as-btn as-btn-white" data-retry="installed">重试</button></div>' : ids.map(function (id) { return gridCard(mergedApp(id)); }).join('');
    if (native.length) html += '<div class="as-native-heading">本机插件</div>' + native.map(function (p) {
      return '<div class="as-card">' + logoTile({id:p.id,name:p.label || p.name || p.id},46) + '<div class="as-card-body"><div class="as-card-name">' + esc(p.label || p.name || p.id) + '</div><p class="as-card-desc">部署配置、服务与日志</p></div><button class="as-btn as-btn-open" data-native-manage="' + esc(p.id) + '">修改配置</button></div>';
    }).join('');
    if (state.nativeError) html += '<div class="as-detail-note">本机插件列表暂不可用：' + esc(state.nativeError) + '</div>';
    if (grid) grid.innerHTML = html;
    if (empty) { empty.hidden = !!html; empty.textContent = '还没有安装任何应用。'; }
  }
  function reloadNative() {
    return req('/api/v1/plugins/native').then(function (r) { state.nativePlugins = r.data && Array.isArray(r.data.plugins) ? r.data.plugins : []; state.nativeError = null; })
      .catch(function (e) { state.nativeError = errText(e); });
  }
  function openNative(id) {
    if (!allowNativeLeave()) return;
    var plugin = state.nativePlugins.find(function (p) { return p.id === id && p.id === 'openlist'; });
    if (!plugin) { toast('本机未发现该插件'); return; }
    if (state.nativeMount) { state.nativeMount.unmount(); state.nativeMount = null; }
    state.nativeId = id; state.detailId = null; state.detailFrom = 'installed'; ++state.detailGen;
    showView('detail'); setActiveNav();
    var body = $('asDetailBody');
    body.innerHTML = '<div class="as-native-intro"><h1 class="as-detail-name">' + esc(plugin.label || id) + '</h1><p class="as-cfg-help">应用设置与服务维护。文件、存储挂载与用户管理请在 OpenList 中操作。</p></div><div id="asNativeHost"></div>';
    var modulePath = plugin.module, stylePath = plugin.style;
    if (typeof modulePath === 'string' && /^native\/[A-Za-z0-9_-]+\.js$/.test(modulePath)) modulePath = '/plugins/' + modulePath;
    if (typeof modulePath !== 'string' || !/^\/(?:static|plugins)\/[A-Za-z0-9_./-]+\.js$/.test(modulePath)) { body.innerHTML += '<div class="as-detail-note">插件未提供可加载的配置入口。</div>'; return; }
    if (typeof stylePath === 'string' && /^\/(?:static|plugins)\/[A-Za-z0-9_./-]+\.css$/.test(stylePath) && !document.querySelector('link[data-native-style="' + id + '"]')) {
      var css = document.createElement('link'); css.rel = 'stylesheet'; css.href = stylePath; css.dataset.nativeStyle = id; document.head.appendChild(css);
    }
    import(modulePath).then(function (module) {
      if (state.nativeId !== id || state.view !== 'detail') return;
      if (typeof module.mount !== 'function') throw new Error('插件未提供设置挂载入口');
      return module.mount({ element: $('asNativeHost'), initialTab: 'basic', management: true });
    }).then(function (handle) { if (handle && state.nativeId === id) state.nativeMount = handle; else if (handle && handle.unmount) handle.unmount(); })
      .catch(function (e) { if (state.nativeId === id) $('asNativeHost').textContent = '无法打开配置：' + errText(e); });
  }
  // 已安装条目无 name/category：与 catalog 交叉引用，缺失回退 id。
  function mergedApp(id) {
    var cat = state.byId[id] || {};
    var inst = state.installed[id] || {};
    return {
      id: id, name: cat.name || id, category: cat.category || '',
      version: inst.installedVersion || cat.version, featured: !!cat.featured,
      homepage: !!cat.homepage, installable: cat.installable !== false,
      unavailableReason: cat.unavailableReason || null,
      requirementsChecked: cat.requirementsChecked,
      missingCapabilities: cat.missingCapabilities,
      capabilityReason: cat.capabilityReason
    };
  }
  // ---------------- Detail view ----------------
  function allowNativeLeave() {
    if (!state.nativeId) return true;
    var dirty = state.nativeMount && state.nativeMount.isDirty && state.nativeMount.isDirty();
    dirty = dirty || Array.from(document.querySelectorAll('#asNativeHost [data-dwrt-savebar]')).some(function (el) { return !el.classList.contains('is-hidden') && getComputedStyle(el).display !== 'none'; });
    return !dirty || window.confirm('OpenList 配置尚未保存，是否放弃修改并离开？');
  }
  function openDetail(id) {
    if (!allowNativeLeave()) return;
    if (state.nativeMount) { state.nativeMount.unmount(); state.nativeMount = null; state.nativeId = null; }
    state.nativeId = null;
    state.detailId = id;
    var gen = ++state.detailGen;
    showView('detail'); setActiveNav();
    var body = $('asDetailBody');
    if (body) body.innerHTML = '<div class="as-detail-loading">正在读取应用状态…</div>';
    reloadStatus(id).then(function (st) {
      if (gen !== state.detailGen) return;      // 详情已切换，丢弃过期结果
      renderDetail(st);
      if (st.installStatus === 'installed') loadConfiguration(id);
    }).catch(function (e) {
      if (gen !== state.detailGen) return;
      if (body) body.innerHTML = '<div class="as-empty">无法读取应用「' + esc(id) + '」：' + esc(errText(e)) +
        ' <button type="button" class="as-btn as-btn-white" data-detail="' + esc(id) + '">重试</button></div>';
    });
  }
  function releaseLine(st, catApp) {
    var sel = st.selectedRelease || {};
    var ver = st.installedVersion || sel.version || (catApp && catApp.version) || '';
    var bits = [];
    if (ver) bits.push('v' + esc(ver));
    var build = (st.installedBuild != null ? st.installedBuild : sel.build);
    if (build != null) bits.push('build ' + esc(build));
    if (sel.target) bits.push(esc(sel.target));
    var sz = fmtBytes(sel.sizeBytes); if (sz) bits.push(sz);
    return bits.join(' · ');
  }
  function renderDetail(st) {
    var body = $('asDetailBody'); if (!body) return;
    var id = st.id;
    var catApp = state.byId[id] || {};
    var name = catApp.name || id;
    var installed = st.installStatus === 'installed';
    var busy = isBusy(id);
    var op = state.polls[id] ? state.polls[id].op : (st.operation || null);
    var opActive = op && (op.state === 'queued' || op.state === 'running');

    var head =
      '<div class="as-detail-head">' + logoTile({ id: id, name: name }, 72) +
        '<div class="as-detail-headmain">' +
          '<div class="as-detail-eyebrow">' + esc(categoryName(catApp.category) || '应用') + ' ' + (catApp.featured ? '<span class="as-badge as-badge-featured">精选</span>' : '') + '</div>' +
          '<h1 class="as-detail-name">' + esc(name) + '</h1>' +
          '<div class="as-detail-sub">' + (releaseLine(st, catApp) || '暂无版本信息') + '</div>' +
        '</div>' +
      '</div>';

    var chips = '<div class="as-detail-chips">';
    chips += '<span class="as-chip">' + (installed ? '已安装' : (st.installStatus === 'available' ? '未安装' : esc(st.installStatus || '未知'))) + '</span>';
    if (installed) chips += '<span class="as-chip">' + esc(runtimeText(st.runtimeState)) + '</span>';
    if (st.updateAvailable && st.availableVersion) chips += '<span class="as-chip is-accent">可更新 v' + esc(st.availableVersion) + '</span>';
    chips += '</div>';

    var notice = '';
    if (!installed && !st.installable) notice = '<div class="as-detail-note is-warn">' + esc(unavailableText(st.unavailableReason, st)) + '，无法在本设备安装。</div>';
    else if (!installed && !state.installerEnabled) notice = '<div class="as-detail-note is-warn">当前后端未启用安装器（capabilities.installer≠dapp-v1）。</div>';
    else if (!installed && st.requirementsChecked === false) notice = '<div class="as-detail-note">目录尚未提供完整的能力声明，安装前仍会核查签名应用要求。</div>';

    var progress = opActive ? opProgressHtml(op) : (op && op.state === 'failed' ? '<div class="as-detail-note is-warn">上次' + esc(opVerb(op.type)) + '失败：' + esc(op.error && (op.error.message || op.error.code) || '未知错误') + '</div>' : '');

    var launchInfo = launchHtml(st);
    var cfg = configFormHtml(st, installed);
    var actions = detailActions(st, installed, busy || opActive);

    var preserved = body.querySelector('#asConfigForm');
    if (preserved && preserved.dataset.appId !== id) preserved = null;
    body.innerHTML = head + chips + notice + '<div id="asTaskProgress">' + progress + '</div>' + launchInfo + cfg +
      '<div class="as-detail-actions">' + actions + '</div>';

    if (preserved && $('asConfigForm') && state.configs[id] && state.configs[id].open) $('asConfigForm').replaceWith(preserved);
    updateConfigFeedback(id);
    if (opActive && !state.polls[id]) startPoll(id, op.task_id, op.type, op);  // 载入即恢复轮询
  }
  function opProgressHtml(op) {
    var pct = (op && typeof op.percent === 'number') ? Math.max(0, Math.min(100, op.percent)) : null;
    var bar = pct == null
      ? '<div class="as-progress is-indeterminate"><span></span></div>'
      : '<div class="as-progress"><span style="width:' + pct + '%"></span></div>';
    return '<div class="as-detail-note is-busy"><div class="as-op-line">' + esc(opVerb(op.type)) + ' · ' +
      stageText(op.stage) + (pct == null ? '' : ' · ' + pct + '%') + '</div>' + bar + '</div>';
  }
  // 启动入口：仅当后端给出同源 route（以 / 开头）时才可在浏览器打开；
  // hello-web 只有设备本地端口(portKey)，非同源 → 诚实地不显示「打开」。
  function launchHtml(st) {
    var l = st.launch;
    if (!l || st.installStatus !== 'installed' || st.runtimeState !== 'running') return '';
    if (l.route && typeof l.route === 'string' && l.route.charAt(0) === '/') return '';  // 由按钮处理
    if (l.kind === 'web' && l.portKey) {
      return '<div class="as-detail-note">该应用为设备本地网络服务，运行于本机端口，需在设备局域网内访问，无法从本页直接打开。</div>';
    }
    return '';
  }
  function canOpen(st) {
    var l = st.launch;
    return !!(l && l.kind === 'web' && st.installStatus === 'installed' && st.runtimeState === 'running' &&
      l.route && typeof l.route === 'string' && /^\/[A-Za-z0-9._-][A-Za-z0-9._/-]*$/.test(l.route));
  }

  document.addEventListener('click', function (event) {
    var link = event.target.closest('a.as-btn-open');
    if (!link || window.parent === window || !window.parent.DWRT_DESKTOP_HOST) return;
    var st = state.statusById[state.detailId];
    if (!st || !canOpen(st) || st.launch.openMode === 'new-window') return;
    event.preventDefault();
    window.parent.postMessage({ source:'dwrt-appstore', type:'open-app', appId:state.detailId }, location.origin);
  });

  // ---------------- Config form (from configSchema) ----------------
  function canConfigure() {
    var role = window.DWRT_SESSION && window.DWRT_SESSION.tokens().role;
    return role === 'owner' || role === 'admin';
  }
  function configDirty(c) { return c && JSON.stringify(c.draft) !== JSON.stringify(c.baseline); }
  function configFormHtml(st, installed) {
    var c = state.configs[st.id];
    if (installed && (!c || !c.open)) return '';
    if (installed && !c.loaded) return '<div class="as-detail-note">' + esc(c.error || '正在读取当前配置…') + '<button class="as-btn as-btn-white" data-config-retry="' + esc(st.id) + '">重试读取</button></div>';
    var schema = installed ? c.schema : (st.configSchema || []);
    if (!schema.length) return installed ? '<div class="as-detail-note">该应用未提供可编辑的宿主设置。</div>' : '';
    if (!installed && (!st.installable || !state.installerEnabled)) return '';
    function row(f) {
      var key = f.key, label = f.label || f.title || '应用设置', secret = f.type === 'password' || f.type === 'secret';
      var val = installed ? (c.draft[key] == null ? '' : c.draft[key]) : (f.default == null ? '' : f.default);
      var attr = ' data-cfg="' + esc(key) + '" aria-label="' + esc(label) + '"' + (!canConfigure() ? ' disabled' : '');
      var required = f.required && !(installed && secret) ? ' required' : '';
      var input, options = f.enum || f.options;
      if (options && options.length) {
        input = '<select class="as-input"' + attr + required + '>' + options.map(function (o) {
          var v = o && o.value != null ? o.value : o, title = o && o.label != null ? o.label : o;
          return '<option value="' + esc(v) + '"' + (String(v) === String(val) ? ' selected' : '') + '>' + esc(title) + '</option>';
        }).join('') + '</select>';
      } else if (f.type === 'bool' || f.type === 'boolean') {
        input = '<label class="as-switch"><input type="checkbox" data-type="bool"' + attr + (val ? ' checked' : '') + '><span></span></label>';
      } else if (['port', 'integer', 'number'].indexOf(f.type) >= 0) {
        var min = f.minimum != null ? f.minimum : (f.min != null ? f.min : (f.type === 'port' ? 1 : null));
        var max = f.maximum != null ? f.maximum : (f.max != null ? f.max : (f.type === 'port' ? 65535 : null));
        input = '<input class="as-input" type="number" data-type="number"' + attr + required + ' value="' + esc(val) + '"' + (min == null ? '' : ' min="' + esc(min) + '"') + (max == null ? '' : ' max="' + esc(max) + '"') + '>';
      } else input = '<input class="as-input" type="' + (secret ? 'password' : 'text') + '"' + attr + required + ' value="' + esc(val) + '"' + (secret ? ' autocomplete="new-password" placeholder="' + (installed ? '留空保持原值' : '请输入') + '"' : '') + '>';
      return '<div class="as-cfg-row"><label class="as-cfg-label">' + esc(label) + (f.required ? ' *' : '') + '</label>' + input +
        (f.help || f.description ? '<div class="as-cfg-help">' + esc(f.help || f.description) + '</div>' : '') +
        (installed && secret && c.secretsSet[key] ? '<div class="as-cfg-help">已设置，留空保持原值</div>' : '') + '</div>';
    }
    var basic = schema.filter(function (f) { return f.required; }), advanced = schema.filter(function (f) { return !f.required; });
    if (!basic.length) { basic = advanced; advanced = []; }
    return '<div class="as-cfg" id="asConfigForm" data-app-id="' + esc(st.id) + '"><div class="as-cfg-title">' + (installed ? '修改配置' : '安装配置') + '</div>' +
      (installed ? '<p class="as-cfg-help">保存后将重启正在运行的本应用；已停止的应用保持停止。数据目录或数据库变更不会自动迁移原数据。</p>' : '') +
      (!canConfigure() ? '<p class="as-cfg-help">当前账号仅可查看配置。</p>' : '') +
      basic.map(row).join('') + (advanced.length ? '<details class="as-cfg-advanced"><summary>更多设置</summary>' + advanced.map(row).join('') + '</details>' : '') +
      '<div id="asConfigFeedback" role="status" aria-live="polite"></div>' + (installed ? '<button class="as-btn as-btn-white" type="button" data-config-retry="' + esc(st.id) + '">读取最新配置</button>' : '') + '<div id="asConfigSavebar"></div></div>';
  }
  function loadConfiguration(id, force) {
    var c = state.configs[id] || (state.configs[id] = { open: false, baseline: {}, draft: {}, secretsSet: {} });
    if (c.loading || (c.loaded && !force)) return Promise.resolve(c);
    c.loading = true;
    return req(API + '/apps/' + encodeURIComponent(id) + '/configuration').then(function (r) {
      var d = r.data || {};
      if (!d.configuration || !d.revision || !Array.isArray(d.configSchema)) throw new Error('配置响应不完整');
      c.loaded = true; c.schema = d.configSchema; c.secretsSet = d.secretsSet || {}; c.revision = d.revision;
      c.baseline = Object.assign({}, d.configuration); c.draft = Object.assign({}, c.baseline); c.error = '';
      if (state.detailId === id) { var old = $('asConfigForm'); if (old) old.remove(); renderDetail(state.statusById[id]); }
      return c;
    }).catch(function (e) {
      c.error = '无法读取当前配置：' + errText(e);
      if (state.detailId === id) renderDetail(state.statusById[id]);
      return c;
    }).finally(function () { c.loading = false; });
  }
  function updateConfigFeedback(id) {
    var c = state.configs[id], form = $('asConfigForm');
    if (!c || !form || form.dataset.appId !== id) return;
    var feedback = $('asConfigFeedback'); if (feedback) feedback.textContent = c.error || c.message || '';
    var bar = $('asConfigSavebar');
    if (bar && window.DWRT_UI_KIT) bar.innerHTML = window.DWRT_UI_KIT.floatingSavebarMarkup({ visible: !!(canConfigure() && (configDirty(c) || c.busy)), busy: c.busy, disabled: isBusy(id), message: '配置有未保存的更改' });
    form.querySelectorAll('[data-cfg]').forEach(function (el) { el.disabled = !canConfigure() || !!c.busy || isBusy(id); });
  }
  function saveConfiguration(id) {
    var c = state.configs[id], form = $('asConfigForm');
    if (!c || !c.loaded || c.busy || isBusy(id) || !canConfigure() || !configDirty(c)) return;
    var invalid = Array.from(form.querySelectorAll('[data-cfg]')).find(function (el) { return !el.checkValidity(); });
    if (invalid) { invalid.reportValidity(); return; }
    var patch = {};
    c.schema.forEach(function (f) {
      var value = c.draft[f.key];
      if ((f.type === 'password' || f.type === 'secret') && !value) return;
      if (JSON.stringify(value) !== JSON.stringify(c.baseline[f.key])) patch[f.key] = value;
    });
    c.pending = patch; c.busy = true; c.error = ''; c.message = '正在提交配置…'; updateConfigFeedback(id);
    postJSON(API + '/apps/' + encodeURIComponent(id) + '/configure', { revision: c.revision, configuration: patch })
      .then(function (r) { afterAccept(id, r, 'configure'); })
      .catch(function (e) { c.busy = false; c.error = '保存失败：' + errText(e); c.message = ''; updateConfigFeedback(id); });
  }

  function readConfigForm() {
    var form = $('asConfigForm'); if (!form) return {};
    var out = {};
    form.querySelectorAll('[data-cfg]').forEach(function (el) {
      var k = el.getAttribute('data-cfg'), t = el.getAttribute('data-type');
      if (t === 'bool') out[k] = !!el.checked;
      else if (t === 'number') { var n = el.value.trim(); if (n !== '') out[k] = Number(n); }
      else { var v = el.value; if (v != null && v !== '') out[k] = v; }
    });
    return out;
  }
  function detailActions(st, installed, locked) {
    var id = st.id;
    if (locked) return '<button type="button" class="as-btn as-btn-pending as-btn-lg" disabled>' +
      esc(state.polls[id] ? opVerb(state.polls[id].type) : '处理') + '中…</button>';
    var out = '';
    if (!installed) {
      if (st.installable && state.installerEnabled)
        out += '<button type="button" class="as-btn as-btn-get as-btn-lg" data-get="' + esc(id) + '">获取</button>';
      else
        out += '<button type="button" class="as-btn as-btn-pending as-btn-lg" disabled>' +
          (st.installable ? '安装器未启用' : '不可安装') + '</button>';
      return out;
    }
    if (canOpen(st))
      out += '<a class="as-btn as-btn-open as-btn-lg" href="' + esc(st.launch.route) + '" target="_blank" rel="noopener">打开</a>';
    out += '<button type="button" class="as-btn as-btn-white" data-config-open="' + esc(id) + '">修改配置</button>';
    if (st.updateAvailable && state.installerEnabled)
      out += '<button type="button" class="as-btn as-btn-white" data-update="' + esc(id) + '">更新到 v' + esc(st.availableVersion || '') + '</button>';
    if (st.canRollback && state.installerEnabled)
      out += '<button type="button" class="as-btn as-btn-white" data-rollback="' + esc(id) + '">回退上一版本</button>';
    out += '<button type="button" class="as-btn as-btn-danger" data-uninstall="' + esc(id) + '">卸载</button>';
    return out;
  }

  // ---------------- Write actions ----------------
  function afterAccept(id, resp, type) {
    var d = (resp && resp.data) || {};
    if (d.task_id) { startPoll(id, d.task_id, type, d.operation || null); }
    else {
      // 幂等：200 且 task_id=null —— 目标态已满足，直接刷新真值。
      toast(opVerb(type) + '：已是目标状态');
      refreshAfterOp(id);
    }
  }
  function doGet(id) {
    var st = state.statusById[id] || {};
    var sel = st.selectedRelease || {};
    var body = { configuration: readConfigForm() };
    if (sel.releaseId) body.releaseId = sel.releaseId;
    postJSON(API + '/apps/' + encodeURIComponent(id) + '/install', body)
      .then(function (r) { afterAccept(id, r, 'install'); })
      .catch(function (e) { handleWriteError(id, e, 'install'); });
  }
  function doUpdate(id) {
    var st = state.statusById[id] || {};
    var sel = st.selectedRelease || {};
    if (configDirty(state.configs[id])) { toast('请先保存或撤销配置修改'); return; }
    var body = {};
    if (sel.releaseId) body.releaseId = sel.releaseId;
    postJSON(API + '/apps/' + encodeURIComponent(id) + '/update', body)
      .then(function (r) { afterAccept(id, r, 'update'); })
      .catch(function (e) { handleWriteError(id, e, 'update'); });
  }
  function doRollback(id) {
    if (!window.confirm('确定回退「' + (state.byId[id] && state.byId[id].name || id) + '」到上一版本？')) return;
    postJSON(API + '/apps/' + encodeURIComponent(id) + '/rollback', {})
      .then(function (r) { afterAccept(id, r, 'rollback'); })
      .catch(function (e) { handleWriteError(id, e, 'rollback'); });
  }
  function doUninstall(id) {
    if (!window.confirm('确定卸载「' + (state.byId[id] && state.byId[id].name || id) + '」？应用数据默认保留。')) return;
    postJSON(API + '/apps/' + encodeURIComponent(id) + '/uninstall', { retainData: true })
      .then(function (r) { afterAccept(id, r, 'uninstall'); })
      .catch(function (e) { handleWriteError(id, e, 'uninstall'); });
  }
  function doRefresh() {
    var btn = $('asRefresh'); if (btn) btn.disabled = true;
    postJSON(API + '/catalog/refresh', {})
      .then(function (r) {
        var d = (r && r.data) || {};
        if (d.task_id) startPoll('catalog', d.task_id, 'catalog-refresh', d.operation || null);
        else { if (btn) btn.disabled = false; }
      })
      .catch(function (e) { if (btn) btn.disabled = false; toast('刷新失败：' + errText(e)); });
  }
  function handleWriteError(id, e, type) {
    var code = e && e.payload && e.payload.error && e.payload.error.code;
    if (code === 'release_changed') { toast('版本已更新，正在重新载入'); openDetail(id); return; }
    if (code === 'app_busy') { toast('该应用有进行中的操作'); reloadStatus(id).then(function (st) { if (state.detailId === id) renderDetail(st); }); return; }
    toast(opVerb(type) + '失败：' + errText(e));
  }
  // ---------------- Task polling (one poller per app, 1s→3s, generation-guarded) ----------------
  function startPoll(id, taskId, type, op0) {
    if (!taskId) return;
    if (state.polls[id] && state.polls[id].timer) clearTimeout(state.polls[id].timer);
    state.polls[id] = { taskId: taskId, type: type, gen: ++state.opGen, delay: POLL_MIN, op: op0 || null, timer: null };
    renderLists();
    if (state.detailId === id && state.statusById[id]) renderDetail(state.statusById[id]);
    schedulePoll(id, 400);
  }
  function schedulePoll(id, delay) {
    var p = state.polls[id]; if (!p) return;
    if (document.hidden) { p.timer = null; return; }   // 后台标签暂停，可见时恢复
    p.timer = setTimeout(function () { pollTick(id); }, delay == null ? p.delay : delay);
  }
  function pollTick(id) {
    var p = state.polls[id]; if (!p) return;
    var gen = p.gen, tid = p.taskId;
    req(API + '/tasks/' + encodeURIComponent(tid)).then(function (resp) {
      var cur = state.polls[id];
      if (!cur || cur.gen !== gen || cur.taskId !== tid) return;       // 已被取代
      var op = (resp && resp.data) || {};
      if (op.task_id && op.task_id !== tid) { schedulePoll(id); return; }
      cur.op = op;
      if (op.state === 'succeeded' || op.state === 'failed') { finishPoll(id, op); return; }
      cur.delay = POLL_MAX;                                            // 首轮后退避到 3s
      if (state.detailId === id && state.statusById[id]) renderDetail(state.statusById[id]);
      renderLists();
      schedulePoll(id);
    }).catch(function (e) {
      var cur = state.polls[id];
      if (!cur || cur.gen !== gen) return;
      if (cur.type === 'configure' && state.configs[id]) { state.configs[id].message = '暂时无法确认保存结果，正在重新查询；请勿重复提交。'; updateConfigFeedback(id); }
      cur.delay = POLL_MAX;                                            // 进度暂不可读，不判失败，继续重试
      schedulePoll(id);
    });
  }
  function finishPoll(id, op) {
    var type = (state.polls[id] && state.polls[id].type) || (op && op.type) || 'install';
    if (state.polls[id] && state.polls[id].timer) clearTimeout(state.polls[id].timer);
    delete state.polls[id];
    if (type === 'configure') { finishConfiguration(id, op); return; }
    if (op && op.state === 'failed') toast(opVerb(type) + '失败：' + (op.error && (op.error.message || op.error.code) || '未知错误'));
    else toast(opVerb(type) + '完成');
    if (type === 'catalog-refresh') {
      var btn = $('asRefresh'); if (btn) btn.disabled = false;
      reloadCatalog().then(function () { renderNav(); if (state.view === 'discover') renderDiscover(); renderLists(); });
      return;
    }
    refreshAfterOp(id);
  }
  function finishConfiguration(id, op) {
    var c = state.configs[id]; if (!c) { refreshAfterOp(id); return; }
    c.busy = false;
    if (op.state === 'failed') {
      c.error = '保存失败：' + (op.error && (op.error.message || op.error.code) || '未知错误') + (op.result && op.result.restored === true ? '；旧配置已恢复。' : '');
      updateConfigFeedback(id); refreshAfterOp(id); return;
    }
    req(API + '/apps/' + encodeURIComponent(id) + '/configuration').then(function (r) {
      var d = r.data || {}, patch = c.pending || {};
      var consistent = Object.keys(patch).every(function (key) {
        var secret = c.schema.some(function (f) { return f.key === key && (f.type === 'password' || f.type === 'secret'); });
        return secret ? !!(d.secretsSet && d.secretsSet[key]) : JSON.stringify(d.configuration && d.configuration[key]) === JSON.stringify(patch[key]);
      });
      if (!consistent || !d.revision) throw new Error('应用返回的配置与本次修改不一致，草稿已保留');
      c.revision = d.revision; c.secretsSet = d.secretsSet || {}; c.baseline = Object.assign({}, d.configuration); c.draft = Object.assign({}, c.baseline); c.pending = null; c.error = '';
      c.message = op.result && op.result.applyState === 'saved/stopped' ? '配置已保存，应用保持停止。' : (op.result && op.result.applyState === 'unchanged' ? '配置未改变。' : '配置已保存并应用。');
      if (state.detailId === id) { var form = $('asConfigForm'); if (form) form.remove(); }
      refreshAfterOp(id);
    }).catch(function (e) { c.error = '结果待确认：' + errText(e); updateConfigFeedback(id); });
  }
  function refreshAfterOp(id) {
    reloadInstalled().then(function () {
      if (state.detailId === id && state.view === 'detail') {
        reloadStatus(id).then(function (st) { if (state.detailId === id) renderDetail(st); }).catch(function () {});
      }
      renderNav(); renderLists();
    });
  }

  // 轻量重绘：只刷新当前列表视图的网格，不重建 hero、不切换视图。
  function renderLists() {
    if (state.view === 'discover') {
      var featured = state.apps.filter(function (a) { return a.featured; });
      var fEl = $('asFeatured'); if (fEl) fEl.innerHTML = featured.map(featuredCard).join('');
      var rEl = $('asRank'); if (rEl && state.apps.length) rEl.innerHTML = state.apps.map(gridCard).join('');
    } else if (state.view === 'category' && state.lastCat != null) {
      var list = state.apps.filter(function (a) { return a.category === state.lastCat; });
      var g = $('asCategoryGrid'); if (g) g.innerHTML = list.map(gridCard).join('');
    } else if (state.view === 'search') {
      renderListSearch();
    } else if (state.view === 'installed') {
      renderInstalled();
    }
  }
  function renderListSearch() {
    var g = $('asSearchGrid'); if (!g) return;
    var norm = String(state.lastQuery || '').trim().toLowerCase(); if (!norm) return;
    var list = state.apps.filter(function (a) {
      return String(a.name || '').toLowerCase().indexOf(norm) >= 0 || String(a.id || '').toLowerCase().indexOf(norm) >= 0;
    });
    g.innerHTML = list.map(gridCard).join('');
  }
  // ---------------- Loaders ----------------
  function reloadCatalog() {
    return req(API + '/catalog').then(function (j) {
      state.catalogError = null;
      state.capabilities = j.capabilities || {};
      state.device = j.device || {};
      state.index = j.index || {};
      state.installerEnabled = (state.capabilities.installer === 'dapp-v1');
      state.categories = (j.categories || []).slice().sort(function (a, b) { return (a.sort || 0) - (b.sort || 0); });
      state.apps = j.apps || [];
      state.byId = {}; state.catById = {};
      state.apps.forEach(function (a) { state.byId[a.id] = a; });
      state.categories.forEach(function (c) { state.catById[c.id] = c; });
      renderIndexBar();
    }).catch(function (e) {
      state.catalogError = errText(e);
      if (e && e.status === 401) state.catalogError = '未登录或会话失效';
      renderIndexBar();
      throw e;
    });
  }
  function reloadInstalled() {
    return req(API + '/installed').then(function (j) {
      state.installedError = null;
      var d = (j && j.data) || {};
      var map = {};
      (d.apps || []).forEach(function (a) { map[a.id] = a; });
      state.installed = map;
      if (window.parent !== window) window.parent.postMessage({ source:'dwrt-appstore', type:'installed-changed' }, location.origin);
    }).catch(function (e) {
      state.installedError = (e && e.status === 401) ? '未登录或会话失效' : errText(e);
    });
  }
  function reloadStatus(id) {
    return req(API + '/apps/' + encodeURIComponent(id) + '/status').then(function (j) {
      var d = (j && j.data) || {};
      state.statusById[id] = d;
      return d;
    });
  }
  function renderIndexBar() {
    var el = $('asIndexBar'); if (!el) return;
    if (state.catalogError) {
      el.className = 'as-index-bar is-warn';
      el.innerHTML = '目录不可用：' + esc(state.catalogError) +
        ' <button type="button" class="as-btn as-btn-white as-btn-sm" data-retry="catalog">重试</button>';
      return;
    }
    var idx = state.index || {};
    var srcTxt = ({ remote: '在线目录', cache: '本地缓存', bundled: '随包目录' })[idx.source] || (idx.source || '');
    var parts = [];
    if (srcTxt) parts.push(srcTxt);
    if (idx.channel) parts.push('通道 ' + esc(idx.channel));
    if (idx.revision != null) parts.push('修订 ' + esc(idx.revision));
    var cls = 'as-index-bar';
    if (idx.stale) { parts.push('目录可能过期'); cls += ' is-warn'; }
    if (idx.lastError) { parts.push('上次刷新失败'); cls += ' is-warn'; }
    el.className = cls;
    el.innerHTML = '<span class="as-index-info">' + esc(parts.join(' · ')) + '</span>' +
      (state.capabilities.refresh !== false
        ? '<button type="button" class="as-btn as-btn-white as-btn-sm" id="asRefresh">刷新</button>' : '');
  }

  // ---------------- Toast ----------------
  var toastTimer = null;
  function toast(msg) {
    var el = $('asToast'); if (!el) return;
    el.textContent = msg; el.classList.add('is-visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.classList.remove('is-visible'); }, 2800);
  }
  // ---------------- Events ----------------
  function goDiscover() { showView('discover'); setActiveNav(); renderDiscover(); }
  function goInstalled() {
    showView('installed'); setActiveNav(); renderInstalled();
    Promise.all([reloadInstalled(), reloadNative()]).then(function () { if (state.view === 'installed') renderInstalled(); });
  }
  function handleClick(e) {
    var t = e.target.closest('[data-config-open],[data-config-retry],[data-dwrt-savebar-save],[data-dwrt-savebar-discard],[data-native-manage],[data-nav],[data-get],[data-update],[data-rollback],[data-uninstall],[data-retry],[data-detail],[data-hi],#asBack,#asRefresh');
    if (!t) return;
    if (t.hasAttribute('data-config-open')) { var id = t.getAttribute('data-config-open'); var c = state.configs[id] || (state.configs[id] = {baseline:{},draft:{},secretsSet:{}}); c.open = true; renderDetail(state.statusById[id]); loadConfiguration(id); return; }
    if (t.hasAttribute('data-config-retry')) { var id = t.getAttribute('data-config-retry'), c = state.configs[id]; if (c && c.busy) return; if (configDirty(c) && !window.confirm('读取最新配置会替换当前未保存的修改，是否继续？')) return; loadConfiguration(id, true); return; }
    if (t.hasAttribute('data-dwrt-savebar-save') && !state.nativeId) { saveConfiguration(state.detailId); return; }
    if (t.hasAttribute('data-dwrt-savebar-discard') && !state.nativeId) { var c = state.configs[state.detailId]; if (c && !c.busy) { c.draft = Object.assign({}, c.baseline); c.error = ''; c.message = ''; var form = $('asConfigForm'); if (form) form.remove(); renderDetail(state.statusById[state.detailId]); } return; }
    if (t.hasAttribute('data-native-manage')) { openNative(t.getAttribute('data-native-manage')); return; }
    if (t.id === 'asRefresh') { e.preventDefault(); doRefresh(); return; }
    if (t.id === 'asBack') { e.preventDefault(); var f = state.detailFrom || 'discover'; state.detailId = null; if (f === 'installed') goInstalled(); else if (f === 'category' && state.lastCat != null) openCategory(state.lastCat); else if (f === 'search') runSearch(state.lastQuery); else goDiscover(); return; }
    var nav = t.getAttribute('data-nav');
    if (nav != null) { e.preventDefault(); if (nav === 'discover') goDiscover(); else if (nav === 'installed') goInstalled(); else if (nav.indexOf('cat:') === 0) openCategory(nav.slice(4)); return; }
    var g;
    if ((g = t.getAttribute('data-get')) != null) { e.preventDefault(); doGet(g); return; }
    if ((g = t.getAttribute('data-update')) != null) { e.preventDefault(); doUpdate(g); return; }
    if ((g = t.getAttribute('data-rollback')) != null) { e.preventDefault(); doRollback(g); return; }
    if ((g = t.getAttribute('data-uninstall')) != null) { e.preventDefault(); doUninstall(g); return; }
    if ((g = t.getAttribute('data-retry')) != null) {
      e.preventDefault();
      if (g === 'catalog') reloadCatalog().then(function () { renderNav(); goDiscover(); }).catch(function () {});
      else if (g === 'installed') reloadInstalled().then(renderInstalled);
      return;
    }
    if ((g = t.getAttribute('data-detail')) != null) { e.preventDefault(); state.detailFrom = (state.view === 'detail' ? state.detailFrom : state.view); openDetail(g); return; }
    var hi = t.getAttribute('data-hi');
    if (hi != null) { e.preventDefault(); goHero(parseInt(hi, 10) || 0); return; }
  }
  function bindEvents() {
    document.addEventListener('click', handleClick);
    document.addEventListener('input', function (e) { var el = e.target.closest('[data-cfg]'), c = state.configs[state.detailId]; if (!el || !c || !c.loaded || c.busy) return; var t = el.dataset.type; c.draft[el.dataset.cfg] = t === 'bool' ? el.checked : (t === 'number' ? (el.value === '' ? '' : Number(el.value)) : el.value); c.error = ''; c.message = ''; updateConfigFeedback(state.detailId); });
    window.addEventListener('message', function (e) { if (e.origin === location.origin && e.source === window.parent && e.data && e.data.type === 'dwrt-appstore:manage' && state.installed[e.data.appId]) openDetail(e.data.appId); });
    window.addEventListener('beforeunload', function (e) { if ((state.nativeMount && state.nativeMount.isDirty && state.nativeMount.isDirty()) || Object.keys(state.configs).some(function (id) { return configDirty(state.configs[id]) || state.configs[id].busy; })) { e.preventDefault(); e.returnValue = ''; } });
    var s = $('asSearch');
    if (s) {
      var deb = null;
      s.addEventListener('input', function () {
        clearTimeout(deb);
        var v = s.value;
        deb = setTimeout(function () {
          if (!String(v).trim()) { if (state.view === 'search') goDiscover(); }
          else runSearch(v);
        }, 180);
      });
    }
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) { Object.keys(state.polls).forEach(function (id) { var p = state.polls[id]; if (p && p.timer) { clearTimeout(p.timer); p.timer = null; } }); return; }
      Object.keys(state.polls).forEach(function (id) { if (!state.polls[id].timer) schedulePoll(id, 300); });
      if (state.detailId && state.view === 'detail') reloadStatus(state.detailId).then(function (st) { if (state.detailId === st.id) renderDetail(st); }).catch(function () {});
    });
  }
  // 载入时恢复后台进行中的操作（catalog 应用集很小，逐个探测 status.operation）。
  function resumeInFlight() {
    var ids = {}; state.apps.forEach(function (a) { ids[a.id] = 1; }); Object.keys(state.installed).forEach(function (id) { ids[id] = 1; });
    Object.keys(ids).forEach(function (id) {
      if (state.polls[id]) return;
      reloadStatus(id).then(function (st) {
        var op = st.operation;
        if (op && (op.state === 'queued' || op.state === 'running') && op.task_id && !state.polls[id]) {
          startPoll(id, op.task_id, op.type || 'install', op);
        }
      }).catch(function () {});
    });
  }
  function boot() {
    bindEvents();
    renderNav(); showView('discover');
    var rank = $('asRank'); if (rank) rank.innerHTML = '<div class="as-empty">正在载入应用目录…</div>';
    Promise.all([reloadCatalog().catch(function () {}), reloadInstalled(), reloadNative()]).then(function () {
      state.ready = true;
      renderNav(); renderDiscover(); renderInstalled();
      resumeInFlight();
      var requested = new URLSearchParams(location.search).get('app'); if (requested && state.installed[requested]) openDetail(requested);
      if (new URLSearchParams(location.search).get('native') === 'openlist') openNative('openlist');
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
