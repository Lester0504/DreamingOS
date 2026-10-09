/* DreamingOS 虚拟机：左侧常驻导航 + 主内容区，消费冻结的 vm.v1 契约。
 * 材质由桌面窗口提供；本模块只经共享令牌取色，不做本地毛玻璃。
 *
 * 契约（todo/2026-09-23/Handoff/Backend-to-Front-dreamingos-vm.md）：
 *   信封 { ok, data|error, meta }；§3 未安装时 /status 与 /capabilities 返回
 *   200 且 installed:false，其余路由 503。本构建后端已落地：
 *   status/capabilities/overview、instances(list/create/validate/get/action/
 *   delete)、tasks(list/get/cancel)、pools/networks 只读列表。创建向导只使用
 *   活跃池网的真实 UUID；完整存储/网络管理、硬件/设置仍按能力降级展示。
 *
 * 授权统一走 window.DWRT_REQUEST.json（会话闸门注入并刷新 Bearer token）。
 */
(function () {
  'use strict';

  var API = '/api/v1/vm';
  var $ = function (sel) { return document.querySelector(sel); };
  var app = $('#vmApp');
  var kit = window.DWRT_UI_KIT;

  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  var glyph = function (name) { return '<i data-lucide="' + name + '" aria-hidden="true"></i>'; };
  function paintIcons() {
    if (window.lucide) window.lucide.createIcons({ attrs: { 'stroke-width': 1.7, 'aria-hidden': 'true' } });
  }
  function bytes(n) {
    if (n == null || !isFinite(Number(n))) return '—';
    var b = Number(n) || 0;
    if (b < 1024) return b + ' B';
    var u = Math.min(4, Math.floor(Math.log(Math.max(1, b)) / Math.log(1024)));
    return (b / Math.pow(1024, u)).toFixed(u ? 1 : 0) + ' ' + ['B', 'KB', 'MB', 'GB', 'TB'][u];
  }
  function mib(mb) { return mb == null ? '—' : bytes(Number(mb) * 1024 * 1024); }
  function num(v, dflt) { return v == null ? (dflt == null ? '—' : dflt) : v; }

  // ---------------- state ----------------
  var state = {
    booted: false, loading: false, seq: 0,
    installed: false, enabled: false, serviceState: 'unknown', reason: '', deps: null,
    caps: {}, capsRaw: null, limits: {}, hostArch: '', guestArches: [], capReasons: {},
    view: 'overview',
    overview: null,
    list: null, page: 1, pageSize: 50, total: 0, query: '', filter: '',
    detailId: '', detail: null, detailTab: 'summary',
    tasks: null,
    sheet: null, confirming: false
  };

  var NAV = [
    { id: 'overview',  label: '概览',       icon: 'layout-dashboard', needsDaemon: true },
    { id: 'instances', label: '虚拟机',     icon: 'monitor',          needsDaemon: true },
    { id: 'storage',   label: '存储与镜像', icon: 'hard-drive',       needsDaemon: true },
    { id: 'networks',  label: '网络',       icon: 'network',          needsDaemon: true },
    { id: 'hardware',  label: '硬件',       icon: 'cpu',              needsDaemon: true },
    { id: 'tasks',     label: '任务',       icon: 'list-checks',      needsDaemon: true },
    { id: 'settings',  label: '设置',       icon: 'settings',         needsDaemon: false }
  ];
  var NAV_TITLE = {};
  NAV.forEach(function (n) { NAV_TITLE[n.id] = n.label; });

  var STATE_LABEL = {
    running: '运行中', paused: '已暂停', shutoff: '已关闭', shutdown: '正在关闭',
    crashed: '已崩溃', pmsuspended: '已挂起', blocked: '阻塞', nostate: '未知', unknown: '未知'
  };
  var SERVICE_LABEL = {
    not_installed: '未安装', stopped: '已停止', starting: '启动中',
    ready: '就绪', degraded: '降级', unknown: '未知'
  };
  var ACTION_META = {
    start:     { label: '启动',     icon: 'play' },
    resume:    { label: '恢复',     icon: 'play' },
    shutdown:  { label: '关机',     icon: 'power' },
    reboot:    { label: '重启',     icon: 'rotate-ccw' },
    pause:     { label: '暂停',     icon: 'pause' },
    suspend:   { label: '挂起',     icon: 'moon' },
    poweroff:  { label: '强制关机', icon: 'square', danger: true },
    force_off: { label: '强制关机', icon: 'square', danger: true },
    reset:     { label: '强制重启', icon: 'zap',    danger: true }
  };

  // ---------------- transport ----------------
  function apiJson(url, opts) {
    if (window.DWRT_REQUEST && window.DWRT_REQUEST.json) return window.DWRT_REQUEST.json(url, opts);
    var tok = '';
    try { tok = localStorage.getItem('dreamingwrt.web.accessToken') || ''; } catch (e) {}
    var init = opts || {};
    var headers = { Accept: 'application/json' };
    if (init.body) headers['Content-Type'] = 'application/json';
    if (tok) headers.Authorization = 'Bearer ' + tok;
    return fetch(url, {
      method: init.method || 'GET', body: init.body,
      headers: headers, cache: 'no-store', credentials: 'same-origin'
    }).then(function (r) {
      return r.text().then(function (t) {
        var j = {}; if (t) { try { j = JSON.parse(t); } catch (e) { throw new Error('invalid json'); } }
        if (!r.ok || (j && j.ok === false)) { var e = new Error(String(r.status)); e.status = r.status; e.payload = j; throw e; }
        return j;
      });
    });
  }
  function get(path) { return apiJson(API + path); }
  function send(path, body, method) {
    return apiJson(API + path, { method: method || 'POST', body: body ? JSON.stringify(body) : undefined });
  }
  function errInfo(err) {
    var p = err && err.payload, e = p && p.error;
    return {
      status: (err && err.status) || 0,
      code: (e && e.code) || (err && err.status === 401 ? 'unauthorized' : 'service_unavailable'),
      message: (e && e.message) || '',
      details: (e && e.details) || null
    };
  }
  var ERR_TEXT = {
    unauthorized: '请重新登录后再操作。', forbidden: '当前账号没有执行此操作的权限。',
    not_found: '对象不存在，或该功能未在此固件中提供。', invalid_config: '配置无效，请检查后重试。',
    name_conflict: '名称已存在，请更换。', revision_conflict: '对象已被其他操作修改，请刷新后重试。',
    vm_busy: '虚拟机正忙，请稍后再试。', vm_must_be_stopped: '请先关闭虚拟机再执行此操作。',
    insufficient_space: '存储空间不足。', resource_in_use: '资源正被占用，无法删除。',
    capability_disabled: '该能力在当前环境未启用。', requires_confirm: '此操作需要确认。',
    dependency_missing: '缺少运行所需的依赖组件。', service_unavailable: '虚拟化服务当前不可用。'
  };
  function errText(err) {
    var info = errInfo(err);
    return info.message || ERR_TEXT[info.code] || '操作失败';
  }

  // ---------------- render primitives ----------------
  function setView(v) { if (app) app.dataset.view = v; }
  function setTitle(t) { var el = $('#vmPageTitle'); if (el) el.textContent = t; }
  function notice(text, tone) {
    var el = $('#vmNotice');
    if (!el) return;
    el.hidden = !text; el.textContent = text || '';
    if (tone) el.dataset.tone = tone; else el.removeAttribute('data-tone');
  }
  function setContent(html) { var c = $('#vmContent'); if (c) { c.innerHTML = html; paintIcons(); } }
  function centered(icon, title, desc) {
    return '<div class="vm-state">' + glyph(icon) + '<h2>' + esc(title) + '</h2>' +
      (desc ? '<p>' + esc(desc) + '</p>' : '') + '</div>';
  }
  // §3 service_state enum is not_installed|stopped|starting|ready|degraded — the
  // healthy value is "ready" (vm_libvirt.c vm_service_state()), never "running"
  // (that is a per-VM domain state). Gate the daemon-backed views on "ready".
  function daemonReady() { return state.installed && state.enabled && state.serviceState === 'ready'; }
  function canCreate() { return daemonReady() && !!state.caps.create; }

  function pill(st) {
    var s = String(st || 'unknown').toLowerCase().replace(/\s+/g, '');
    var key = STATE_LABEL[s] ? s : 'unknown';
    return '<span class="vm-pill" data-state="' + esc(key) + '">' + esc(STATE_LABEL[key] || st) + '</span>';
  }
  function card(title, metric, sub) {
    return '<div class="vm-card"><h3>' + esc(title) + '</h3><div class="vm-metric">' + esc(metric) + '</div>' +
      (sub ? '<div class="vm-sub">' + esc(sub) + '</div>' : '') + '</div>';
  }
  function stateBlock(opts) {
    var actions = (opts.actions || []).map(function (a) {
      return '<button type="button" class="dwrt-kit-button' + (a.primary ? ' is-primary' : '') +
        '" data-action="' + a.action + '"' + (a.disabled ? ' disabled' : '') + '>' +
        (a.icon ? glyph(a.icon) : '') + '<span>' + esc(a.label) + '</span></button>';
    }).join('');
    var deps = (opts.deps && opts.deps.length)
      ? '<div class="vm-dep-list">' + opts.deps.map(function (d) {
          return '<span class="vm-pill" data-state="' + esc(d.state) + '">' +
            esc(d.name) + ' · ' + esc(d.label) + '</span>';
        }).join('') + '</div>'
      : '';
    return '<div class="vm-state">' + glyph(opts.icon || 'info') + '<h2>' + esc(opts.title) + '</h2>' +
      (opts.desc ? '<p>' + esc(opts.desc) + '</p>' : '') + deps +
      (actions ? '<div class="vm-state-actions">' + actions + '</div>' : '') + '</div>';
  }
  function contentError(err) {
    var info = errInfo(err);
    if (info.status === 503) { render(); return; }
    setContent(stateBlock({ icon: 'triangle-alert', title: '加载失败', desc: errText(err),
      actions: [{ action: 'refresh', label: '重试', icon: 'refresh-cw', primary: true }] }));
  }

  // ---------------- chrome (nav / badge / top actions) ----------------
  function renderNav() {
    var nav = $('#vmNav');
    if (!nav) return;
    var ready = daemonReady();
    nav.innerHTML = NAV.map(function (n) {
      var gated = n.needsDaemon && !ready;
      var active = n.id === state.view;
      return '<button type="button" class="dwrt-rail-item' + (active ? ' is-active' : '') + '"' +
        ' data-nav="' + n.id + '"' + (active ? ' aria-current="page"' : '') +
        (gated ? ' data-cap-off="true"' : '') + ' title="' + esc(n.label) + '">' +
        '<span class="dwrt-rail-item-icon" aria-hidden="true">' + glyph(n.icon) + '</span>' +
        '<span class="dwrt-rail-item-text"><span class="dwrt-rail-item-title">' + esc(n.label) +
        '</span></span></button>';
    }).join('');
    paintIcons();
  }
  function renderBadge() {
    var el = $('#vmServiceBadge');
    if (!el) return;
    el.hidden = false;
    if (!state.installed) { el.textContent = 'dreamingos-vm · 未安装'; return; }
    el.textContent = 'dreamingos-vm · ' + (SERVICE_LABEL[state.serviceState] || state.serviceState);
  }
  function renderTopActions() {
    var host = $('#vmTopActions');
    if (!host) { return; }
    var html = '';
    if (state.view === 'instances' && state.detailId) {
      html = '<button type="button" class="dwrt-kit-button" data-action="back-to-list">' +
        glyph('arrow-left') + '<span>返回列表</span></button>';
    } else if (state.installed && (state.view === 'instances' || state.view === 'overview')) {
      var ok = canCreate();
      html = '<button type="button" class="dwrt-kit-button is-primary" data-action="new-vm"' +
        (ok ? '' : ' disabled data-cap-off="true" title="当前环境不支持创建虚拟机"') + '>' +
        glyph('plus') + '<span>新建虚拟机</span></button>';
    }
    host.innerHTML = html;
    paintIcons();
  }
  function depPills() {
    if (!state.deps) return [];
    var name = { libvirt: 'libvirt', qemu: 'QEMU', kvm: 'KVM' };
    var label = { ok: '就绪', present: '就绪', available: '就绪', missing: '缺失',
      unknown: '未知', disabled: '未启用', unavailable: '不可用' };
    return Object.keys(name).filter(function (k) { return state.deps[k] != null; }).map(function (k) {
      var v = String(state.deps[k]);
      var good = v === 'ok' || v === 'present' || v === 'available';
      var bad = v === 'missing' || v === 'unavailable';
      return { name: name[k], label: label[v] || v, state: good ? 'running' : (bad ? 'crashed' : 'shutoff') };
    });
  }

  // ---------------- boot + router ----------------
  function ingestStatus(d) {
    state.installed = !!d.installed;
    state.enabled = !!d.enabled;
    state.serviceState = d.service_state || (state.installed ? 'unknown' : 'not_installed');
    state.reason = d.reason || '';
    state.deps = d.dependency_state || null;
  }
  // §5 capabilities envelope: capabilities{} is nested; host_arch/guest_arches/
  // limits{}/capability_reasons{} are top-level siblings (see vm_capabilities.c
  // vm_capabilities_json). Keep them separate — the wizard reads limits.max_vcpus
  // / limits.max_memory_bytes and caps.firmware, not flattened caps.* aliases.
  function ingestCaps(d) {
    state.capsRaw = d || null;
    state.caps = (d && d.capabilities) || {};
    state.limits = (d && d.limits) || {};
    state.hostArch = (d && d.host_arch) || '';
    state.guestArches = (d && d.guest_arches) || [];
    state.capReasons = (d && d.capability_reasons) || {};
  }

  function boot() {
    state.loading = true;
    setView('loading');
    setContent(centered('loader', '正在连接虚拟化服务…'));
    var seq = ++state.seq;
    Promise.all([
      get('/status').then(function (j) { return j; }, function (e) { return { __err: e }; }),
      get('/capabilities').then(function (j) { return j; }, function (e) { return { __err: e }; })
    ]).then(function (res) {
      if (seq !== state.seq) return;
      state.loading = false;
      var st = res[0], cp = res[1];
      if (st && st.__err) { bootFailed(st.__err); return; }
      ingestStatus((st && st.data) || {});
      if (cp && !cp.__err) ingestCaps(cp.data || {});
      state.booted = true;
      notice('');
      renderNav(); renderBadge();
      render();
    });
  }
  function bootFailed(err) {
    var info = errInfo(err);
    state.booted = false;
    setView('error');
    setTitle('虚拟机');
    renderNav(); renderBadge(); renderTopActions();
    if (info.status === 401) {
      setContent(stateBlock({ icon: 'lock', title: '需要登录', desc: '请登录后再访问虚拟机。',
        actions: [{ action: 'reload', label: '重新加载', icon: 'refresh-cw', primary: true }] }));
    } else {
      setContent(stateBlock({ icon: 'plug-zap', title: '虚拟化服务不可用', desc: errText(err),
        actions: [{ action: 'reload', label: '重试', icon: 'refresh-cw', primary: true }] }));
    }
  }
  function render() {
    if (!state.booted) return;
    var isDetail = state.view === 'instances' && state.detailId;
    setTitle(isDetail ? ((state.detail && state.detail.name) || '虚拟机详情') : (NAV_TITLE[state.view] || '虚拟机'));
    renderNav(); renderTopActions();
    if (!state.installed) { renderNotInstalled(); return; }
    if (NAV_TITLE[state.view] && !daemonReady() && state.view !== 'settings') { renderServiceDown(); return; }
    if (state.view === 'overview') return loadOverview();
    if (state.view === 'instances') return isDetail ? loadDetail() : loadInstances();
    if (state.view === 'tasks') return loadTasks();
    if (state.view === 'settings') return renderSettings();
    return renderPlanned(state.view);
  }

  // ---------------- degradation states ----------------
  function renderNotInstalled() {
    setView('empty');
    var why = {
      package_not_installed: '尚未安装 dreamingos-vm 虚拟化套件。',
      service_stopped: '虚拟化服务已安装但未运行。'
    }[state.reason] || '虚拟化功能当前不可用。';
    setContent(stateBlock({
      icon: 'box',
      title: '虚拟机功能未启用',
      desc: why + ' 该功能依赖 KVM/QEMU 与 libvirt，随后续固件更新提供；' +
            '安装并启用后，此处将显示概览、虚拟机列表与创建向导。',
      deps: depPills()
    }));
  }
  function renderServiceDown() {
    setView('empty');
    var msg = (!state.enabled || state.serviceState === 'stopped')
      ? '虚拟化服务已安装但未运行。'
      : ('虚拟化服务状态：' + (SERVICE_LABEL[state.serviceState] || state.serviceState) + '。');
    setContent(stateBlock({
      icon: 'power',
      title: '虚拟化服务未运行',
      desc: msg + ' 服务的启用与启动由系统服务管理；此固件未在虚拟机应用内提供服务控制入口。',
      deps: depPills()
    }));
  }
  function renderPlanned(view) {
    setView('empty');
    var text = {
      storage: '存储池、卷与镜像管理将在后续固件中提供。',
      networks: '虚拟网络与桥接管理将在后续固件中提供。',
      hardware: '硬件直通与设备管理将在后续固件中提供。'
    }[view] || '该功能将在后续固件中提供。';
    setContent(stateBlock({ icon: 'hard-hat', title: (NAV_TITLE[view] || '功能') + ' · 即将推出', desc: text }));
  }
  function renderSettings() {
    setView('ready');
    var rows = [
      ['服务状态', SERVICE_LABEL[state.serviceState] || state.serviceState],
      ['已安装', state.installed ? '是' : '否'],
      ['已启用', state.enabled ? '是' : '否'],
      ['契约版本', (state.capsRaw && state.capsRaw.schema) || 'vm.v1']
    ];
    if (state.caps && typeof state.caps.create === 'boolean')
      rows.push(['支持创建', state.caps.create ? '是' : '否（当前环境）']);
    setContent('<section class="vm-card"><h3>虚拟化服务</h3><dl class="vm-kv">' +
      rows.map(function (r) { return '<dt>' + esc(r[0]) + '</dt><dd>' + esc(r[1]) + '</dd>'; }).join('') +
      '</dl><p class="vm-cap-reason">更多设置项将在后续固件中开放。</p></section>');
  }

  // ---------------- overview ----------------
  function loadOverview() {
    setView('ready');
    setContent(centered('loader', '加载中…'));
    var seq = ++state.seq;
    get('/overview').then(function (j) {
      if (seq !== state.seq || state.view !== 'overview') return;
      state.overview = j.data || {};
      renderOverview();
    }, function (e) {
      if (seq !== state.seq || state.view !== 'overview') return;
      contentError(e);
    });
  }
  function renderOverview() {
    var o = state.overview || {};
    var c = o.instances || o.counts || {};
    var host = o.host || {};
    var total = c.total != null ? c.total : o.total_instances;
    var cards = [
      card('虚拟机', num(total), '共计'),
      card('运行中', num(c.running), '活动实例'),
      card('已分配 vCPU', num(o.allocated_vcpus), host.vcpus != null ? ('宿主 ' + host.vcpus + ' 核') : ''),
      card('已分配内存', o.allocated_memory_mb != null ? mib(o.allocated_memory_mb) : '—',
        host.memory_mb != null ? ('宿主 ' + mib(host.memory_mb)) : '')
    ].join('');
    setContent('<section class="vm-stat-grid">' + cards + '</section>' + hostCard(host));
  }
  function hostCard(host) {
    if (!host || !Object.keys(host).length) return '';
    var rows = [];
    if (host.hostname) rows.push(['主机', host.hostname]);
    if (host.hypervisor) rows.push(['虚拟化', host.hypervisor + (host.hypervisor_version ? ' ' + host.hypervisor_version : '')]);
    if (host.cpu_model) rows.push(['CPU', host.cpu_model]);
    if (host.kvm != null) rows.push(['KVM 加速', host.kvm ? '可用' : '不可用（TCG 软件模拟）']);
    if (!rows.length) return '';
    return '<section class="vm-card"><h3>宿主机</h3><dl class="vm-kv">' +
      rows.map(function (r) { return '<dt>' + esc(r[0]) + '</dt><dd>' + esc(r[1]) + '</dd>'; }).join('') +
      '</dl></section>';
  }

  // ---------------- instances list ----------------
  function loadInstances() {
    setView('ready');
    if (!state.list) setContent(centered('loader', '加载中…'));
    var seq = ++state.seq;
    var q = ['page=' + state.page, 'page_size=' + state.pageSize];
    if (state.query) q.push('q=' + encodeURIComponent(state.query));
    if (state.filter) q.push('state=' + encodeURIComponent(state.filter));
    get('/instances?' + q.join('&')).then(function (j) {
      if (seq !== state.seq || state.view !== 'instances' || state.detailId) return;
      var d = j.data || {};
      state.list = d.instances || d.items || [];
      var pg = d.pagination || {};
      state.total = pg.total != null ? pg.total : state.list.length;
      renderInstances();
    }, function (e) {
      if (seq !== state.seq || state.view !== 'instances' || state.detailId) return;
      contentError(e);
    });
  }
  function listToolbar() {
    var opts = [['', '全部状态'], ['running', '运行中'], ['paused', '已暂停'], ['shutoff', '已关闭']];
    return '<div class="vm-toolbar">' +
      '<label class="vm-search">' + glyph('search') +
      '<input type="search" data-vm-search placeholder="搜索名称…" value="' + esc(state.query) + '" aria-label="搜索虚拟机"></label>' +
      '<select class="dwrt-kit-input" data-vm-filter aria-label="按状态筛选">' +
      opts.map(function (o) { return '<option value="' + o[0] + '"' + (state.filter === o[0] ? ' selected' : '') + '>' + o[1] + '</option>'; }).join('') +
      '</select><span class="vm-spacer"></span></div>';
  }
  function renderInstances() {
    var list = state.list || [];
    var body;
    if (!list.length) {
      body = state.query || state.filter
        ? centered('search-x', '没有匹配的虚拟机', '尝试调整搜索或筛选条件。')
        : centered('monitor', '还没有虚拟机', canCreate() ? '点击右上角“新建虚拟机”开始创建。' : '当前环境暂不支持创建虚拟机。');
    } else {
      var rows = list.map(function (vm) {
        return '<tr data-vm-id="' + esc(vm.id || vm.uuid || vm.name) + '"><td>' + esc(vm.name || '—') + '</td>' +
          '<td>' + pill(vm.state) + '</td>' +
          '<td class="vm-num">' + num(vm.vcpus != null ? vm.vcpus : vm.vcpu) + '</td>' +
          '<td class="vm-num">' + (vm.memory_mb != null ? mib(vm.memory_mb) : '—') + '</td>' +
          '<td>' + esc(vm.os || vm.os_variant || '—') + '</td></tr>';
      }).join('');
      body = '<table class="vm-table"><thead><tr><th>名称</th><th>状态</th>' +
        '<th class="vm-num">vCPU</th><th class="vm-num">内存</th><th>系统</th></tr></thead><tbody>' +
        rows + '</tbody></table>' + pager();
    }
    setContent(listToolbar() + body);
  }
  function pager() {
    var pages = Math.max(1, Math.ceil(state.total / state.pageSize));
    if (pages <= 1) return '';
    return '<div class="vm-actions" style="justify-content:flex-end;align-items:center">' +
      '<button type="button" class="dwrt-kit-button" data-page="' + (state.page - 1) + '"' + (state.page <= 1 ? ' disabled' : '') + '>' + glyph('chevron-left') + '<span>上一页</span></button>' +
      '<span class="vm-cap-reason">第 ' + state.page + ' / ' + pages + ' 页 · 共 ' + state.total + '</span>' +
      '<button type="button" class="dwrt-kit-button" data-page="' + (state.page + 1) + '"' + (state.page >= pages ? ' disabled' : '') + '>' + glyph('chevron-right') + '<span>下一页</span></button></div>';
  }

  // ---------------- instance detail ----------------
  function loadDetail() {
    setView('ready');
    if (!state.detail || (state.detail.id || state.detail.uuid) !== state.detailId)
      setContent(centered('loader', '加载中…'));
    var seq = ++state.seq;
    get('/instances/' + encodeURIComponent(state.detailId)).then(function (j) {
      if (seq !== state.seq || state.view !== 'instances' || !state.detailId) return;
      state.detail = (j.data && (j.data.instance || j.data)) || {};
      setTitle(state.detail.name || '虚拟机详情');
      renderDetail();
    }, function (e) {
      if (seq !== state.seq || state.view !== 'instances' || !state.detailId) return;
      contentError(e);
    });
  }
  var DETAIL_TABS = [['summary', '概要'], ['config', '配置'], ['console', '控制台'], ['snapshots', '快照']];
  function renderDetail() {
    var vm = state.detail || {};
    var tabs = '<div class="vm-detail-tabs">' + DETAIL_TABS.map(function (t) {
      return '<button type="button" data-tab="' + t[0] + '"' + (state.detailTab === t[0] ? ' class="is-active"' : '') + '>' + esc(t[1]) + '</button>';
    }).join('') + '</div>';
    var actions = actionBar(vm);
    var pane;
    if (state.detailTab === 'config') pane = detailConfig(vm);
    else if (state.detailTab === 'console') pane = detailConsole(vm);
    else if (state.detailTab === 'snapshots') pane = centered('camera', '快照 · 即将推出', '快照管理将在后续固件中提供。');
    else pane = detailSummary(vm);
    setContent('<div class="vm-detail-head"><span>' + pill(vm.state) + '</span></div>' + actions + tabs + pane);
  }
  function actionBar(vm) {
    var allowed = vm.allowed_actions || [];
    if (!allowed.length) return '';
    var btns = allowed.map(function (a) {
      var m = ACTION_META[a] || { label: a, icon: 'chevron-right' };
      return '<button type="button" class="dwrt-kit-button' + (m.danger ? ' is-danger' : '') +
        '" data-action="power" data-power="' + esc(a) + '">' + glyph(m.icon) + '<span>' + esc(m.label) + '</span></button>';
    }).join('');
    var del = '<button type="button" class="dwrt-kit-button is-danger" data-action="delete-vm">' + glyph('trash-2') + '<span>删除</span></button>';
    return '<div class="vm-actions">' + btns + del + '</div>';
  }

  function kvList(rows) {
    var body = rows.filter(function (r) { return r[1] != null && r[1] !== ''; })
      .map(function (r) { return '<dt>' + esc(r[0]) + '</dt><dd>' + esc(r[1]) + '</dd>'; }).join('');
    return '<dl class="vm-kv">' + body + '</dl>';
  }
  function detailSummary(vm) {
    return '<section class="vm-card">' + kvList([
      ['名称', vm.name], ['状态', STATE_LABEL[String(vm.state || '').toLowerCase()] || vm.state],
      ['UUID', vm.uuid || vm.id], ['系统', vm.os || vm.os_variant],
      ['vCPU', vm.vcpus != null ? vm.vcpus : vm.vcpu],
      ['内存', vm.memory_mb != null ? mib(vm.memory_mb) : null],
      ['固件', vm.firmware], ['自启动', vm.autostart == null ? null : (vm.autostart ? '是' : '否')]
    ]) + '</section>';
  }
  function detailConfig(vm) {
    var disks = (vm.disks || []).map(function (d) {
      return '<tr><td>' + esc(d.target || d.device || '磁盘') + '</td><td>' + esc(d.bus || '—') +
        '</td><td class="vm-num">' + (d.capacity_bytes != null ? bytes(d.capacity_bytes) : (d.size_gb != null ? d.size_gb + ' GB' : '—')) + '</td></tr>';
    }).join('');
    var nics = (vm.interfaces || vm.networks || []).map(function (n) {
      return '<tr><td>' + esc(n.model || '虚拟网卡') + '</td><td>' + esc(n.source || n.network || n.bridge || '—') +
        '</td><td>' + esc(n.mac || '—') + '</td></tr>';
    }).join('');
    var out = '<section class="vm-card"><h3>存储</h3>' + (disks
      ? '<table class="vm-table"><thead><tr><th>目标</th><th>总线</th><th class="vm-num">容量</th></tr></thead><tbody>' + disks + '</tbody></table>'
      : '<p class="vm-cap-reason">无磁盘信息。</p>') + '</section>';
    out += '<section class="vm-card"><h3>网络</h3>' + (nics
      ? '<table class="vm-table"><thead><tr><th>型号</th><th>来源</th><th>MAC</th></tr></thead><tbody>' + nics + '</tbody></table>'
      : '<p class="vm-cap-reason">无网络信息。</p>') + '</section>';
    out += '<p class="vm-cap-reason">配置编辑（PATCH）将在后续固件中提供。</p>';
    return out;
  }
  function detailConsole(vm) {
    var running = String(vm.state || '').toLowerCase() === 'running';
    return stateBlock({ icon: 'monitor-play', title: '控制台',
      desc: running ? '图形控制台（noVNC）将在后续固件中提供；届时可在此直接连接虚拟机显示。'
                    : '虚拟机未在运行，无法连接控制台。' });
  }

  // ---------------- actions (power / delete) ----------------
  function confirmDialog(opts) {
    if (state.confirming) return Promise.resolve(false);
    state.confirming = true;
    var host = $('#vmConfirmHost');
    host.innerHTML = kit.confirmationMarkup({
      title: opts.title, description: opts.description,
      confirmLabel: opts.confirmLabel || '确认', cancelLabel: opts.cancelLabel || '取消',
      icon: glyph(opts.icon || 'triangle-alert')
    });
    kit.mountAll(host); paintIcons();
    return new Promise(function (resolve) {
      function finish(v) {
        host.removeEventListener('click', onClick);
        kit.unmount(host); host.replaceChildren();
        state.confirming = false; resolve(v);
      }
      function onClick(e) {
        if (e.target.closest('[data-dwrt-confirm-accept]')) finish(true);
        else if (e.target.closest('[data-dwrt-confirm-cancel]')) finish(false);
      }
      host.addEventListener('click', onClick);
    });
  }
  function doPower(action) {
    var m = ACTION_META[action] || { label: action };
    var id = state.detailId;
    if (!id) return;
    var run = function (confirm) {
      var body = { action: action };
      if (confirm) body.confirm = true;
      notice('正在' + m.label + '…');
      send('/instances/' + encodeURIComponent(id) + '/actions', body).then(function (j) {
        notice(m.label + '请求已提交', 'ok');
        setTimeout(function () { notice(''); }, 2500);
        if (j && j.data && (j.data.task_id || j.data.task)) trackTask(j.data.task_id || (j.data.task && j.data.task.task_id));
        loadDetail();
      }, function (e) {
        var info = errInfo(e);
        if (info.code === 'requires_confirm') {
          confirmDialog({ title: m.label + '虚拟机', description: info.message || '此操作可能中断运行中的系统，确认继续？', confirmLabel: m.label, icon: 'triangle-alert' })
            .then(function (ok) { if (ok) run(true); else notice(''); });
          return;
        }
        notice(errText(e), 'err');
      });
    };
    if (m.danger) {
      confirmDialog({ title: m.label + '虚拟机', description: '这会强制中断虚拟机，可能导致未保存的数据丢失，确认继续？', confirmLabel: m.label, icon: 'triangle-alert' })
        .then(function (ok) { if (ok) run(false); });
    } else { run(false); }
  }

  function deleteVm() {
    var id = state.detailId;
    var vm = state.detail || {};
    if (!id) return;
    confirmDialog({
      title: '删除虚拟机', description: '将永久删除虚拟机“' + (vm.name || id) + '”及其定义，此操作无法撤销。',
      confirmLabel: '永久删除', icon: 'trash-2'
    }).then(function (ok) {
      if (!ok) return;
      notice('正在删除…');
      send('/instances/' + encodeURIComponent(id) + '/delete', { confirm: true }).then(function () {
        notice('已删除', 'ok');
        setTimeout(function () { notice(''); }, 2500);
        state.detailId = ''; state.detail = null; state.list = null;
        state.view = 'instances'; render();
      }, function (e) { notice(errText(e), 'err'); });
    });
  }

  // ---------------- tasks ----------------
  function loadTasks() {
    setView('ready');
    if (!state.tasks) setContent(centered('loader', '加载中…'));
    var seq = ++state.seq;
    get('/tasks').then(function (j) {
      if (seq !== state.seq || state.view !== 'tasks') return;
      var d = j.data || {};
      state.tasks = d.tasks || d.items || [];
      renderTasks();
    }, function (e) {
      if (seq !== state.seq || state.view !== 'tasks') return;
      contentError(e);
    });
  }
  function renderTasks() {
    var list = state.tasks || [];
    if (!list.length) { setContent(centered('list-checks', '没有进行中的任务', '虚拟机的创建、删除等异步操作会在此显示进度。')); return; }
    var rows = list.map(function (t) {
      var id = t.task_id || t.id;
      var st = String(t.state || t.status || '').toLowerCase();
      var running = st === 'running' || st === 'pending' || st === 'queued';
      var prog = t.progress != null ? Math.round(t.progress) + '%' : (running ? '进行中' : '');
      var cancel = running && t.cancelable !== false
        ? '<button type="button" class="dwrt-kit-button" data-action="task-cancel" data-task-id="' + esc(id) + '">' + glyph('x') + '<span>取消</span></button>' : '';
      return '<tr><td>' + esc(t.kind || t.type || '任务') + '</td><td>' + esc(t.target || t.target_name || '—') +
        '</td><td>' + esc(TASK_STATE[st] || st || '—') + '</td><td class="vm-num">' + esc(prog) + '</td><td>' + cancel + '</td></tr>';
    }).join('');
    setContent('<table class="vm-table"><thead><tr><th>类型</th><th>对象</th><th>状态</th><th class="vm-num">进度</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>');
  }
  var TASK_STATE = { running: '进行中', pending: '排队中', queued: '排队中', success: '已完成', succeeded: '已完成', done: '已完成', failed: '失败', error: '失败', canceled: '已取消', cancelled: '已取消' };

  function trackTask(taskId, onDone) {
    if (!taskId) { if (onDone) onDone(null); return; }
    var tries = 0;
    (function poll() {
      get('/tasks/' + encodeURIComponent(taskId)).then(function (j) {
        var t = (j.data && (j.data.task || j.data)) || {};
        var st = String(t.state || t.status || '').toLowerCase();
        if (state.view === 'tasks') loadTasks();
        var terminal = ['success', 'succeeded', 'done', 'failed', 'error', 'canceled', 'cancelled'];
        if (terminal.indexOf(st) >= 0) { if (onDone) onDone(t); return; }
        if (++tries > 150) { if (onDone) onDone(null); return; }
        setTimeout(poll, 2000);
      }, function () { if (++tries <= 3) setTimeout(poll, 2000); else if (onDone) onDone(null); });
    })();
  }
  function cancelTask(id) {
    if (!id) return;
    send('/tasks/' + encodeURIComponent(id) + '/cancel', {}).then(function () {
      notice('已请求取消任务', 'ok');
      setTimeout(function () { notice(''); }, 2000);
      loadTasks();
    }, function (e) { notice(errText(e), 'err'); });
  }

  // ---------------- create wizard ----------------
  var WIZ_STEPS = ['基础信息', '计算资源', '网络与存储'];
  function newRequestId() {
    try { if (window.crypto && crypto.randomUUID) return crypto.randomUUID(); } catch (e) {}
    return 'vm-' + Date.now().toString(16) + '-' + Math.random().toString(16).slice(2, 10);
  }
  function openCreate() {
    if (!canCreate() || state.sheet) return;
    // §10 idempotency: one request_id per wizard session, reused on retry so a
    // double-submit dedupes to a single task instead of building two VMs.
    state.sheet = { kind: 'create', step: 0, busy: false, errors: {}, requestId: newRequestId(), data: {
      name: '', os_variant: '', firmware: (state.caps.firmware && state.caps.firmware[0]) || 'uefi',
      vcpus: 2, memory_mb: 2048, disk_gb: 20, pool_id: '', network: ''
    }, refs: { loading: true, pools: [], networks: [], error: '' }, trigger: document.activeElement };
    renderWizard();
    loadWizardReferences();
  }
  function loadWizardReferences() {
    var s = state.sheet;
    if (!s || s.busy) return;
    wizardCollect();
    s.refs.loading = true; s.refs.error = '';
    if (s.step === 2) renderWizardStep();
    function list(path, page, items) {
      return get(path + '?state=active&page=' + page + '&page_size=200').then(function (j) {
        var d = j.data || {};
        if (!Array.isArray(d.items)) throw new Error('池网列表格式不正确');
        var all = items.concat(d.items);
        if (all.length < Number(d.total) && d.items.length) return list(path, page + 1, all);
        return all.filter(function (item) {
          return item.active === true && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(item.id || '');
        });
      });
    }
    Promise.all([list('/pools', 1, []), list('/networks', 1, [])]).then(function (lists) {
      if (state.sheet !== s) return;
      wizardCollect();
      s.refs.pools = lists[0]; s.refs.networks = lists[1];
      if (!lists[0].some(function (p) { return p.id === s.data.pool_id; })) s.data.pool_id = '';
      if (!lists[1].some(function (n) { return n.id === s.data.network; })) s.data.network = '';
      s.refs.loading = false;
      if (s.step === 2) renderWizardStep();
    }, function (e) {
      if (state.sheet !== s) return;
      wizardCollect();
      s.refs.loading = false; s.refs.error = errText(e);
      if (s.step === 2) renderWizardStep();
    });
  }
  function wizardReferencesReady(s) {
    return !s.refs.loading && !s.refs.error &&
      s.refs.pools.some(function (p) { return p.id === s.data.pool_id; }) &&
      s.refs.networks.some(function (n) { return n.id === s.data.network; });
  }
  function closeWizard() {
    if (!state.sheet || state.sheet.busy) return;
    var host = $('#vmSheetHost');
    kit && kit.unmount(host);
    host.replaceChildren();
    var trigger = state.sheet.trigger;
    state.sheet = null;
    if (trigger && trigger.isConnected) trigger.focus({ preventScroll: true });
  }
  function renderWizard() {
    var s = state.sheet;
    if (!s) return;
    var host = $('#vmSheetHost');
    host.innerHTML = '<button type="button" class="dwrt-kit-sheet-overlay is-open" data-wiz="cancel" aria-label="关闭"></button>' +
      '<aside class="dwrt-kit-sheet vm-sheet is-open" data-dwrt-component="sheet" data-dwrt-sheet-size="standard" aria-label="新建虚拟机">' +
      '<header class="dwrt-kit-sheet-header"><strong>新建虚拟机</strong>' +
      '<button type="button" class="dwrt-kit-sheet-close" data-wiz="cancel" aria-label="关闭">' + glyph('x') + '</button></header>' +
      '<div class="dwrt-kit-sheet-body"><div class="vm-wizard"></div></div>' +
      '<footer class="dwrt-kit-sheet-footer vm-actions"></footer></aside>';
    kit && kit.mountAll(host);
    // kit.mountAll() relocates the sheet + overlay into the body-level
    // #dwrtKitSheetPortal (dwrt-ui-kit.js elevateSheet), so #vmSheetHost is empty
    // afterwards. Keep a handle to the portaled sheet; step changes rewrite only
    // its body/footer via renderWizardStep() rather than rebuilding #vmSheetHost
    // and re-mounting — a full re-mount would strand the previous step's sheet in
    // the portal (reclaimStaleSheets can't orphan-detect a host whose only
    // children were already portaled out), stacking duplicates.
    var mounted = document.querySelectorAll('.vm-sheet');
    s.element = mounted[mounted.length - 1] || null;
    renderWizardStep();
  }
  function renderWizardStep() {
    var s = state.sheet;
    if (!s || !s.element) return;
    var wizBody = s.element.querySelector('.vm-wizard');
    var footBar = s.element.querySelector('.dwrt-kit-sheet-footer');
    if (!wizBody || !footBar) return;
    var stepsBar = '<div class="vm-wizard-steps">' + WIZ_STEPS.map(function (label, i) {
      var cls = i === s.step ? 'is-active' : (i < s.step ? 'is-done' : '');
      return '<span class="' + cls + '">' + (i + 1) + '. ' + esc(label) + '</span>';
    }).join('') + '</div>';
    var pctW = Math.round(((s.step + 1) / WIZ_STEPS.length) * 100);
    var footer = '<button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-wiz="cancel">取消</button>' +
      (s.step > 0 ? '<button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-wiz="back">上一步</button>' : '') +
      (s.step < WIZ_STEPS.length - 1
        ? '<button type="button" class="dwrt-kit-button is-primary" data-dwrt-component="button" data-variant="primary" data-wiz="next">下一步</button>'
        : '<button type="button" class="dwrt-kit-button is-primary" data-dwrt-component="button" data-variant="primary" data-wiz="submit"' + (wizardReferencesReady(s) ? '' : ' disabled') + '>创建</button>');
    wizBody.innerHTML = stepsBar +
      '<div class="vm-progress"><span style="width:' + pctW + '%"></span></div>' +
      '<form class="vm-wizard-form">' + wizardStep(s) + '<p class="vm-field-error" data-wiz-error role="alert" hidden></p></form>';
    footBar.innerHTML = footer;
    // wizBody/footBar are plain containers (not sheets), so mountAll wires their
    // inputs/selects/buttons without re-touching the portal.
    kit && kit.mountAll(wizBody);
    kit && kit.mountAll(footBar);
    paintIcons();
    s.form = s.element.querySelector('.vm-wizard-form');
    var first = s.form && s.form.querySelector('input, select');
    if (first) first.focus();
  }

  function wizField(label, name, value, attrs, hint) {
    return '<label class="vm-field"><span>' + esc(label) + '</span>' +
      '<input class="dwrt-kit-input" name="' + name + '" value="' + esc(value) + '" ' + (attrs || '') + '>' +
      (hint ? '<span class="vm-cap-reason">' + esc(hint) + '</span>' : '') + '</label>';
  }
  function wizSelect(label, name, value, options) {
    return '<label class="vm-field"><span>' + esc(label) + '</span><select class="dwrt-kit-input" name="' + name + '">' +
      options.map(function (o) { return '<option value="' + esc(o[0]) + '"' + (String(value) === String(o[0]) ? ' selected' : '') + '>' + esc(o[1]) + '</option>'; }).join('') +
      '</select></label>';
  }
  function wizardStep(s) {
    var d = s.data;
    if (s.step === 0) {
      var fw = (state.caps.firmware || ['uefi', 'bios']).map(function (f) { return [f, f === 'uefi' ? 'UEFI（推荐）' : f === 'bios' ? 'BIOS（传统）' : f === 'uefi_secureboot' ? 'UEFI + 安全启动' : f]; });
      return wizField('名称', 'name', d.name, 'required autocomplete="off" placeholder="例如 win11-test"') +
        wizField('操作系统', 'os_variant', d.os_variant, 'placeholder="例如 win11 / ubuntu24.04（可留空）"') +
        wizSelect('固件', 'firmware', d.firmware, fw);
    }
    if (s.step === 1) {
      // §5 limits: max_vcpus / max_memory_bytes live under limits{}; 0 means the
      // server decides against the measured host ceiling at validate time, so we
      // show no client-side max hint then. memory field is MB, limit is bytes.
      var maxV = state.limits.max_vcpus, maxBytes = state.limits.max_memory_bytes;
      var maxM = maxBytes ? Math.floor(maxBytes / (1024 * 1024)) : 0;
      return '<div class="vm-field-row">' +
        wizField('vCPU', 'vcpus', d.vcpus, 'type="number" min="1" step="1"' + (maxV ? ' max="' + maxV + '"' : ''), maxV ? ('最多 ' + maxV + ' 核') : '') +
        wizField('内存 (MB)', 'memory_mb', d.memory_mb, 'type="number" min="256" step="128"' + (maxM ? ' max="' + maxM + '"' : ''), maxM ? ('最多 ' + mib(maxM)) : '') +
        '</div>' + wizField('系统盘 (GB)', 'disk_gb', d.disk_gb, 'type="number" min="1" step="1"', '将创建 qcow2 系统盘');
    }
    var refs = s.refs;
    var status = refs.loading ? '正在读取可用的存储池与网络…' : refs.error
      ? '无法读取存储池与网络：' + refs.error
      : !refs.pools.length ? '没有已启用的存储池，请先在宿主机配置并启用存储池。'
      : !refs.networks.length ? '没有已启用的网络，请先在宿主机配置并启用网络。' : '';
    var pools = [['', '请选择存储池']].concat(refs.pools.map(function (p) {
      return [p.id, p.name + '（可用 ' + bytes(p.available_bytes) + '）'];
    }));
    var nets = [['', '请选择网络']].concat(refs.networks.map(function (n) {
      return [n.id, n.name + (n.mode ? ' · ' + n.mode : '')];
    }));
    return (status ? '<p class="vm-cap-reason" role="status">' + esc(status) + '</p>' : '') +
      (!refs.loading ? '<button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-wiz="references">刷新池网列表</button>' : '') +
      wizSelect('系统盘存储池', 'pool_id', d.pool_id, pools) + wizSelect('网络', 'network', d.network, nets) +
      '<section class="vm-card"><h3>确认</h3>' + kvList([
        ['名称', d.name || '（未填写）'], ['操作系统', d.os_variant || '未指定'],
        ['固件', d.firmware], ['vCPU', d.vcpus], ['内存', mib(d.memory_mb)],
        ['系统盘', d.disk_gb + ' GB']
      ]) + '</section>';
  }
  function wizardCollect() {
    var s = state.sheet;
    if (!s) return;
    var form = s.form || (s.element && s.element.querySelector('.vm-wizard-form'));
    if (!form) return;
    var fd = new FormData(form);
    fd.forEach(function (v, k) {
      if (['vcpus', 'memory_mb', 'disk_gb'].indexOf(k) >= 0) s.data[k] = Number(v) || 0;
      else s.data[k] = String(v);
    });
  }

  function wizError(text) {
    var s = state.sheet;
    var n = s && s.element && s.element.querySelector('[data-wiz-error]');
    if (n) { n.textContent = text || ''; n.hidden = !text; }
  }
  function wizBusy(b) {
    var s = state.sheet;
    if (!s) return;
    s.busy = b;
    if (s.element) s.element.querySelectorAll('button[data-wiz], input, select').forEach(function (n) {
      n.disabled = b || (n.getAttribute('data-wiz') === 'submit' && !wizardReferencesReady(s));
    });
  }
  function wizardNext() {
    wizardCollect();
    var s = state.sheet;
    if (s.step === 0 && !String(s.data.name).trim()) { wizError('请填写虚拟机名称。'); return; }
    wizError('');
    s.step = Math.min(WIZ_STEPS.length - 1, s.step + 1);
    renderWizardStep();
  }
  function wizardBack() {
    wizardCollect();
    state.sheet.step = Math.max(0, state.sheet.step - 1);
    renderWizardStep();
  }
  function buildConfig(d) {
    var cores = Number(d.vcpus) || 1;
    var cfg = {
      name: String(d.name).trim(),
      description: '',
      guest_arch: state.hostArch || 'x86_64',
      accelerator: 'auto',
      machine: (state.caps.machines && state.caps.machines[0]) || 'q35',
      firmware: d.firmware || 'uefi',
      cpu: { sockets: 1, cores: cores, threads: 1 },
      memory_bytes: (Number(d.memory_mb) || 512) * 1024 * 1024,
      disks: [{ source: 'new', capacity_bytes: (Number(d.disk_gb) || 1) * 1024 * 1024 * 1024, format: 'qcow2', bus: 'virtio' }],
      cdroms: [],
      nics: [{ network_id: d.network, model: 'virtio', mac: 'auto' }],
      host_devices: [], tpm: false, autostart: false, start_after_create: false
    };
    if (d.os_variant) cfg.os_template = d.os_variant;
    cfg.disks[0].pool_id = d.pool_id;
    return cfg;
  }
  function wizardSubmit() {
    wizardCollect();
    var s = state.sheet;
    if (!s || s.busy) return;
    if (!wizardReferencesReady(s)) { wizError('请选择已启用的存储池与网络后再创建。'); return; }
    if (!String(s.data.name).trim()) { s.step = 0; renderWizardStep(); wizError('请填写虚拟机名称。'); return; }
    var config = buildConfig(s.data);
    wizError(''); wizBusy(true);
    send('/instances/validate', { config: config }).then(function () {
      return send('/instances', { request_id: s.requestId, config: config });
    }).then(function (j) {
      var data = j.data || {};
      var task = data.task_id || (data.task && data.task.task_id);
      var newId = data.id || (data.instance && (data.instance.id || data.instance.uuid));
      notice('已提交创建请求', 'ok');
      wizBusy(false); // clear busy before closeWizard — its busy-guard would else keep the sheet open
      closeWizard();
      state.list = null;
      if (task) trackTask(task, function (t) {
        var okDone = t && ['success', 'succeeded', 'done'].indexOf(String(t.state || t.status).toLowerCase()) >= 0;
        notice(okDone ? '虚拟机创建完成' : '创建任务已结束，请查看任务列表', okDone ? 'ok' : '');
        setTimeout(function () { notice(''); }, 3000);
        var id = newId || (t && (t.target_id || t.result_id));
        if (id) { state.view = 'instances'; state.detailId = String(id); state.detail = null; render(); }
        else if (state.view === 'instances') loadInstances();
      });
      if (!task && newId) { state.view = 'instances'; state.detailId = String(newId); state.detail = null; render(); }
      else if (!task && state.view === 'instances') loadInstances();
    }, function (e) {
      wizBusy(false);
      var info = errInfo(e);
      var extra = '';
      if (info.details && info.details.fields) {
        var f = info.details.fields;
        extra = Object.keys(f).map(function (k) { return k + '：' + f[k]; }).join('；');
      }
      wizError(extra || errText(e));
    });
  }

  // ---------------- navigation + events ----------------
  function selectView(id) {
    if (!NAV_TITLE[id]) return;
    if (id === state.view && !state.detailId) return;
    state.view = id; state.detailId = ''; state.detail = null;
    if (id === 'instances') { state.detailTab = 'summary'; }
    setRail(false);
    render();
  }
  function openInstance(id) {
    state.detailId = String(id); state.detail = null; state.detailTab = 'summary';
    render();
  }
  function refresh() {
    if (!state.booted) { boot(); return; }
    if (state.view === 'overview') state.overview = null;
    else if (state.view === 'instances' && !state.detailId) state.list = null;
    else if (state.view === 'tasks') state.tasks = null;
    // Re-pull status so install/enable transitions are reflected, then re-render.
    get('/status').then(function (j) {
      ingestStatus(j.data || {}); renderNav(); renderBadge(); render();
    }, function () { render(); });
  }
  function setRail(open) {
    var shell = $('#vmApp');
    if (shell) shell.dataset.rail = open ? 'open' : 'closed';
    var bd = $('.vm-rail-backdrop');
    if (bd) bd.hidden = !open;
  }
  var searchTimer = 0;
  function onInput(e) {
    var box = e.target.closest('[data-vm-search]');
    if (!box) return;
    window.clearTimeout(searchTimer);
    var val = box.value;
    searchTimer = window.setTimeout(function () {
      state.query = val.trim(); state.page = 1; loadInstances();
    }, 250);
  }
  function onChange(e) {
    if (state.sheet && e.target.closest('.vm-wizard-form')) {
      wizardCollect();
      var submit = state.sheet.element.querySelector('[data-wiz="submit"]');
      if (submit) submit.disabled = state.sheet.busy || !wizardReferencesReady(state.sheet);
      return;
    }
    var sel = e.target.closest('[data-vm-filter]');
    if (!sel) return;
    state.filter = sel.value; state.page = 1; loadInstances();
  }

  function onClick(e) {
    var nav = e.target.closest('[data-nav]');
    if (nav) { selectView(nav.getAttribute('data-nav')); return; }
    var wiz = e.target.closest('[data-wiz]');
    if (wiz) {
      var w = wiz.getAttribute('data-wiz');
      if (w === 'cancel') closeWizard();
      else if (w === 'back') wizardBack();
      else if (w === 'next') wizardNext();
      else if (w === 'submit') wizardSubmit();
      else if (w === 'references') loadWizardReferences();
      return;
    }
    var act = e.target.closest('[data-action]');
    if (act) {
      var a = act.getAttribute('data-action');
      if (a === 'reload' || a === 'refresh') refresh();
      else if (a === 'new-vm') openCreate();
      else if (a === 'back-to-list') { state.detailId = ''; state.detail = null; render(); }
      else if (a === 'power') doPower(act.getAttribute('data-power'));
      else if (a === 'delete-vm') deleteVm();
      else if (a === 'task-cancel') cancelTask(act.getAttribute('data-task-id'));
      else if (a === 'sidebar') setRail(true);
      else if (a === 'sidebar-close') setRail(false);
      return;
    }
    var tab = e.target.closest('[data-tab]');
    if (tab) { state.detailTab = tab.getAttribute('data-tab'); renderDetail(); return; }
    var page = e.target.closest('[data-page]');
    if (page && !page.disabled) { state.page = Math.max(1, Number(page.getAttribute('data-page')) || 1); loadInstances(); return; }
    var row = e.target.closest('tr[data-vm-id]');
    if (row && state.view === 'instances' && !state.detailId) { openInstance(row.getAttribute('data-vm-id')); }
  }

  // ---------------- lifecycle ----------------
  function init() {
    if (!app) return;
    setRail(false);
    document.addEventListener('click', onClick);
    document.addEventListener('input', onInput);
    document.addEventListener('change', onChange);
    document.addEventListener('submit', function (e) {
      if (!e.target.closest('.vm-wizard-form')) return;
      e.preventDefault();
      if (state.sheet && state.sheet.step < WIZ_STEPS.length - 1) wizardNext();
      else wizardSubmit();
    });
    document.addEventListener('keydown', function (e) {
      if (e.key !== 'Escape') return;
      if (state.sheet) closeWizard();
      else if (app.dataset.rail === 'open') setRail(false);
    });
    boot();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
