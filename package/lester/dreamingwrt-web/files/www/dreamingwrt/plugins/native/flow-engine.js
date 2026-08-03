const FLOW_ENGINE_TABS = [
  { id: 'engine', label: '引擎状态' },
  { id: 'qos', label: 'QoS 引擎' },
  { id: 'capacity', label: '容量与健康' }
];

export function normalizeFlowEngineStatus(payload = {}) {
  const data = payload && typeof payload.data === 'object' && payload.data !== null ? payload.data : payload;
  const number = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
  const text = (...values) => values.map((value) => String(value ?? '').trim()).find(Boolean) || '';
  const geoip = data.geoip && typeof data.geoip === 'object' ? data.geoip : {};
  const capabilities = data.capabilities && typeof data.capabilities === 'object' ? data.capabilities : {};
  const reasons = capabilities.reasons && typeof capabilities.reasons === 'object' ? capabilities.reasons : {};
  const counters = [
    ['split_rules', '分流规则'],
    ['domain_rules', '域名规则'],
    ['app_rules', '应用规则'],
    ['country_policies', '国家策略'],
    ['route_groups', '路由组'],
    ['objects', '流量对象'],
    ['custom_protocols', '自定义协议'],
    ['qos_rules', 'QoS 规则'],
    ['smart_qos_categories', '智能 QoS 分类'],
    ['quota_rules', '配额规则'],
    ['conn_limit_rules', '连接限制规则']
  ].map(([key, label]) => ({
    key,
    label,
    total: number(data[key]),
    enabled: number(data[`enabled_${key}`])
  }));
  return {
    service: text(data.service, 'dreamingwrt-flowd'),
    version: text(data.version),
    schemaVersion: number(data.schema_version),
    schemaSource: text(data.schema_source),
    migrationState: text(data.migration_state),
    settingsAvailable: data.settings_available === true,
    configuredEnabled: typeof data.configured_enabled === 'boolean' ? data.configured_enabled : data.enabled === true,
    configuredApplyMode: text(data.configured_apply_mode, data.apply_mode),
    applyMode: text(data.apply_mode),
    planOnly: text(data.apply_mode).toLowerCase() === 'plan-only',
    runtimeContractVersion: text(data.runtime_contract_version),
    runtimeApplied: typeof data.runtime_applied === 'boolean' ? data.runtime_applied : null,
    runtimeReason: text(data.runtime_reason),
    capabilities: {
      nftRevisionReadback: capabilities.nft_revision_readback === true,
      nftRevisionSentinelOnly: capabilities.nft_revision_sentinel_only === true,
      nftRevisionReason: text(reasons.nft_revision_readback)
    },
    geoipDir: text(data.geoip_dir),
    runtimeDir: text(data.runtime_dir),
    sources: number(data.sources),
    enabledSources: number(data.enabled_sources),
    qosClasses: number(data.qos_classes),
    enabledQosClasses: number(data.enabled_qos_classes),
    applyJobs: number(data.apply_jobs),
    counters,
    geoip: {
      mmdbPresent: geoip.configured_mmdb_present === true,
      mmdbValid: geoip.configured_mmdb_valid === true,
      autoImportNeeded: geoip.auto_import_needed === true,
      defaultSource: text(geoip.default_source),
      runtimeDirPresent: geoip.runtime_dir_present === true
    }
  };
}

export function normalizeFlowEngineRuntime(payload = {}) {
  const data = payload && typeof payload.data === 'object' && payload.data !== null ? payload.data : payload;
  const text = (...values) => values.map((value) => String(value ?? '').trim()).find(Boolean) || '';
  return {
    service: text(data.service),
    workerAvailable: data.worker_available === true,
    degraded: data.degraded === true,
    source: text(data.source),
    message: text(data.message),
    runtimeContractVersion: text(data.runtime_contract_version),
    runtimeApplied: typeof data.runtime_applied === 'boolean' ? data.runtime_applied : null,
    runtimeReason: text(data.runtime_reason),
    summary: data.summary && typeof data.summary === 'object' ? data.summary : null
  };
}

export function normalizeFlowNftRevision(payload = {}) {
  const data = payload && typeof payload.data === 'object' && payload.data !== null ? payload.data : payload;
  const text = (...values) => values.map((value) => String(value ?? '').trim()).find(Boolean) || '';
  const number = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
  return {
    available: data.available === true,
    present: data.present === true,
    ownershipVerified: data.ownership_verified === true,
    sentinelOnly: data.sentinel_only === true,
    revision: text(data.revision),
    containsPolicyRules: data.contains_policy_rules === true,
    runtimeApplied: typeof data.runtime_applied === 'boolean' ? data.runtime_applied : null,
    runtimeReason: text(data.runtime_reason),
    source: text(data.source),
    tableFamily: text(data.table_family),
    tableName: text(data.table_name),
    observedAt: number(data.observed_at),
    error: text(data.error)
  };
}

export function normalizeFlowQosSettings(payload = {}) {
  const data = payload && typeof payload.data === 'object' && payload.data !== null ? payload.data : payload;
  const number = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
  const text = (...values) => values.map((value) => String(value ?? '').trim()).find(Boolean) || '';
  return {
    enabled: data.enabled === true,
    scheduler: text(data.scheduler),
    defaultClass: text(data.default_class),
    unknownClass: text(data.unknown_class),
    headroomPct: number(data.headroom_pct),
    diffserv: data.diffserv === true || text(data.diffserv),
    ackFilter: data.ack_filter === true,
    fairness: text(data.fairness),
    remark: text(data.remark)
  };
}

export function normalizeFlowQosClasses(payload = {}) {
  const data = payload && typeof payload.data === 'object' && payload.data !== null ? payload.data : payload;
  const list = Array.isArray(data.classes) ? data.classes : [];
  const number = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
  const text = (...values) => values.map((value) => String(value ?? '').trim()).find(Boolean) || '';
  return list.map((item = {}, index) => ({
    id: text(item.id, `class-${index + 1}`),
    name: text(item.name, item.id, `类别 ${index + 1}`),
    enabled: item.enabled === true,
    priority: number(item.priority),
    guaranteePct: number(item.guarantee_pct),
    ceilingPct: number(item.ceiling_pct),
    latencyMs: number(item.latency_ms),
    dscp: text(item.dscp),
    remark: text(item.remark)
  })).sort((a, b) => a.priority - b.priority);
}

export function normalizeFlowApplyJobs(payload = {}) {
  const data = payload && typeof payload.data === 'object' && payload.data !== null ? payload.data : payload;
  const list = Array.isArray(data.jobs) ? data.jobs : [];
  const text = (...values) => values.map((value) => String(value ?? '').trim()).find(Boolean) || '';
  const number = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
  return list.map((item = {}, index) => ({
    id: text(item.id, `job-${index + 1}`),
    kind: text(item.kind),
    state: text(item.state),
    dryRun: item.dry_run === true,
    planPath: text(item.plan_path),
    error: text(item.error),
    requestedBy: text(item.requested_by),
    createdAt: number(item.created_at),
    completedAt: number(item.completed_at)
  })).sort((a, b) => b.createdAt - a.createdAt);
}

export function normalizeFlowWanHealth(payload = {}) {
  const data = payload && typeof payload.data === 'object' && payload.data !== null ? payload.data : payload;
  const list = Array.isArray(data.wans) ? data.wans : [];
  const number = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
  const text = (...values) => values.map((value) => String(value ?? '').trim()).find(Boolean) || '';
  return {
    workerAvailable: data.worker_available === true,
    degraded: data.degraded === true,
    source: text(data.source),
    message: text(data.message),
    wans: list.map((item = {}, index) => ({
      id: text(item.id, item.name, `wan-${index + 1}`),
      name: text(item.note, item.name, item.id, `WAN ${index + 1}`),
      ifname: text(item.ifname),
      carrier: text(item.carrier),
      proto: text(item.proto),
      online: item.online === true,
      health: item.health === true,
      status: text(item.status),
      latencyMs: number(item.latency_ms ?? item.latency),
      lossPct: number(item.loss_pct ?? item.loss),
      downRate: number(item.down_rate),
      upRate: number(item.up_rate),
      configuredDownRate: number(item.configured_down_rate),
      configuredUpRate: number(item.configured_up_rate),
      connectedSeconds: number(item.connected_seconds ?? item.online_seconds),
      ip: text(item.ip)
    }))
  };
}

export function normalizeFlowWanCapacity(payload = {}) {
  const data = payload && typeof payload.data === 'object' && payload.data !== null ? payload.data : payload;
  const list = Array.isArray(data.entries) ? data.entries : [];
  const number = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
  const text = (...values) => values.map((value) => String(value ?? '').trim()).find(Boolean) || '';
  return list.map((item = {}, index) => ({
    id: text(item.id, item.wan, `capacity-${index + 1}`),
    wan: text(item.wan, item.wan_id, item.ifname),
    enabled: item.enabled === true,
    downMbps: number(item.download_mbps ?? item.down_mbps),
    upMbps: number(item.upload_mbps ?? item.up_mbps),
    remark: text(item.remark)
  }));
}

export function normalizeFlowSmartControl(payload = {}) {
  const data = payload && typeof payload.data === 'object' && payload.data !== null ? payload.data : payload;
  const number = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
  const text = (...values) => values.map((value) => String(value ?? '').trim()).find(Boolean) || '';
  const smart = data.smart && typeof data.smart === 'object' ? data.smart : {};
  const global = data.global && typeof data.global === 'object' ? data.global : {};
  const qos = data.qos && typeof data.qos === 'object' ? data.qos : {};
  const priorities = smart.priorities && typeof smart.priorities === 'object' ? smart.priorities : {};
  const CATEGORY_LABELS = {
    game: '游戏', web: '网页', social: '社交', unknown: '未识别', productivity: '生产力',
    work: '办公', education: '教育', life: '生活', finance: '金融',
    entertainment: '娱乐', download: '下载'
  };
  return {
    mode: text(smart.mode, global.mode),
    applyState: text(global.applyState, global.apply_state),
    lastApplyAt: number(global.last_apply_at),
    engine: text(global.engine),
    globalEnabled: global.enabled === true,
    defaultPolicy: text(global.default_policy),
    unknownPolicy: text(global.unknown_policy),
    stickySession: global.sticky_session === true,
    logDecisions: global.log_decisions === true,
    dpiRequired: global.dpi_required === true,
    qos: {
      enabled: qos.enabled === true,
      scheduler: text(qos.scheduler),
      totalDownloadMbps: number(qos.total_download_mbps),
      totalUploadMbps: number(qos.total_upload_mbps),
      latencyTargetMs: number(qos.latency_target_ms),
      perHostFairness: qos.per_host_fairness === true,
      ackFilter: qos.ack_filter === true,
      diffserv: text(qos.diffserv)
    },
    priorities: Object.entries(priorities)
      .map(([key, value]) => ({ key, label: CATEGORY_LABELS[key] || key, priority: number(value) }))
      .sort((a, b) => a.priority - b.priority || a.key.localeCompare(b.key)),
    wans: (Array.isArray(data.wans) ? data.wans : []).map((item = {}, index) => ({
      id: text(item.id, item.name, `wan-${index + 1}`),
      name: text(item.name, item.id, `WAN ${index + 1}`),
      ifname: text(item.ifname),
      carrier: text(item.carrier),
      enabled: item.enabled === true,
      status: text(item.status)
    }))
  };
}

export function flowEngineTabFromLocation(hash = '') {
  const match = String(hash || '').match(/[?&]tab=([a-z-]+)/i);
  const id = match ? match[1].toLowerCase() : '';
  return FLOW_ENGINE_TABS.some((tab) => tab.id === id) ? id : FLOW_ENGINE_TABS[0].id;
}

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const stage = root?.closest('.console-stage');
  const registry = context.registry;
  const capabilities = context.capabilities || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const signal = context.signal;
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const formatInteger = utils.formatInteger || ((value) => new Intl.NumberFormat('zh-CN').format(Number(value) || 0));
  const formatRate = utils.formatRate || ((value) => `${formatInteger(value)} B/s`);

  const state = {
    mounted: true,
    tab: flowEngineTabFromLocation(window.location.hash),
    snapshots: {
      status: null, runtime: null, settings: null, qosSettings: null,
      qosClasses: null, applyJobs: null, wanCapacity: null, wanHealth: null, smart: null,
      nftRevision: null
    },
    status: null,
    runtime: null,
    qosSettings: null,
    qosClasses: [],
    applyJobs: [],
    wanCapacity: [],
    wanHealth: null,
    smart: null,
    nftRevision: null,
    refreshing: false,
    refreshQueued: false,
    refreshPromise: null,
    suppressRegistryRender: true,
    renderFrame: 0,
    pollTimer: 0
  };

  const pageHost = document.createElement('div');
  const overlayHost = document.createElement('div');
  pageHost.className = 'policy-entity-page-host';
  overlayHost.className = 'policy-entity-overlay-host';

  const icon = (name) => window.DWRT_UI_KIT?.lucideIcon?.(name, { size: 18, strokeWidth: 1.8 }) || '';
  const statusBadge = (label, tone = 'muted') => ui.statusBadgeMarkup?.(label, tone) || `<span>${escapeHtml(label)}</span>`;
  const statePanel = (name, title, detail) => `<section data-dwrt-component="state-panel" data-dwrt-state="${name}"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(detail)}</p></section>`;
  const button = (label, attributes = '', variant = 'secondary', iconName = '') => `<button type="button" data-dwrt-component="button" data-variant="${variant}" ${attributes}>${iconName ? icon(iconName) : ''}<span>${escapeHtml(label)}</span></button>`;

  const BASE_REGISTRY_SLOTS = [
    ['flow.engineStatus', 'status'],
    ['flow.engineRuntime', 'runtime'],
    ['flow.engineSettings', 'settings'],
    ['flow.qosSettings', 'qosSettings'],
    ['flow.qosClasses', 'qosClasses'],
    ['flow.applyJobs', 'applyJobs'],
    ['flow.wanCapacity', 'wanCapacity'],
    ['flow.wanHealth', 'wanHealth'],
    ['flow.smartControl', 'smart']
  ];
  const NFT_REGISTRY_SLOT = ['flow.nftRevision', 'nftRevision'];
  const REGISTRY_SLOTS = [...BASE_REGISTRY_SLOTS, NFT_REGISTRY_SLOT];

  function hydrate() {
    const value = (slot) => state.snapshots[slot]?.value;
    if (value('status') !== undefined) state.status = normalizeFlowEngineStatus(value('status'));
    if (value('runtime') !== undefined) state.runtime = normalizeFlowEngineRuntime(value('runtime'));
    if (value('qosSettings') !== undefined) state.qosSettings = normalizeFlowQosSettings(value('qosSettings'));
    if (value('qosClasses') !== undefined) state.qosClasses = normalizeFlowQosClasses(value('qosClasses'));
    if (value('applyJobs') !== undefined) state.applyJobs = normalizeFlowApplyJobs(value('applyJobs'));
    if (value('wanCapacity') !== undefined) state.wanCapacity = normalizeFlowWanCapacity(value('wanCapacity'));
    if (value('wanHealth') !== undefined) state.wanHealth = normalizeFlowWanHealth(value('wanHealth'));
    if (value('smart') !== undefined) state.smart = normalizeFlowSmartControl(value('smart'));
    if (value('nftRevision') !== undefined) state.nftRevision = normalizeFlowNftRevision(value('nftRevision'));
  }

  function supportsNftRevisionReadback() {
    return state.status?.capabilities?.nftRevisionReadback === true;
  }

  function pageState() {
    if (!registry) return { name: 'unavailable', title: '流量引擎数据合同不可用', detail: '当前页面没有获得共享 DataRegistry。' };
    const required = [state.snapshots.status, state.snapshots.runtime];
    const terminal = required.find((snapshot) => ['forbidden', 'error', 'unavailable'].includes(snapshot?.status) && snapshot.value === undefined);
    if (terminal) {
      if (terminal.status === 'forbidden') return { name: 'forbidden', title: '无权读取流量引擎', detail: '当前账号没有流量引擎的读取权限。' };
      return { name: terminal.status, title: '无法读取流量引擎', detail: terminal.error?.message || '流量引擎接口当前不可用。' };
    }
    if (!state.status || !state.runtime) return { name: 'loading', title: '正在读取流量引擎', detail: '页面骨架已就绪，等待引擎状态与运行时快照。' };
    return null;
  }

  // 写侧一律 fail-closed：正式 capability 与运行时应用链必须同时就绪。
  function canWrite() {
    return capabilities.flow_engine_config_write === true
      && capabilities.flow_engine_apply === true
      && state.runtime?.workerAvailable === true
      && state.status?.planOnly === false;
  }

  function formatTimestamp(seconds) {
    if (!Number.isFinite(seconds) || seconds <= 0) return '--';
    try {
      return new Date(seconds * 1000).toLocaleString('zh-CN', { hour12: false });
    } catch (_) {
      return String(seconds);
    }
  }

  function formatDuration(seconds) {
    if (!Number.isFinite(seconds) || seconds <= 0) return '--';
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (days > 0) return `${days} 天 ${hours} 小时`;
    if (hours > 0) return `${hours} 小时 ${minutes} 分`;
    return `${minutes} 分`;
  }

  function degradedBannerMarkup() {
    if (!state.status && !state.runtime) return '';
    const planOnly = state.status?.planOnly === true;
    const workerDown = state.runtime?.workerAvailable === false;
    const runtimeApplied = state.status?.runtimeApplied ?? state.runtime?.runtimeApplied;
    if (!planOnly && !workerDown && runtimeApplied !== false) return '';
    const reasons = [];
    if (workerDown) reasons.push(state.runtime?.message || 'flowd worker 未注册');
    if (planOnly) reasons.push(`应用模式为 ${state.status?.applyMode || 'plan-only'}，规则只会编译成计划，不会下发到内核`);
    if (runtimeApplied === false) reasons.push(state.status?.runtimeReason || state.runtime?.runtimeReason || '运行态尚未应用');
    return `<div class="policy-entity-alert is-warning" role="status"><strong>流量引擎当前为只读</strong><span>${escapeHtml(reasons.join('；'))}。配置写入已按合同关闭，等后端注册 worker 并打通 apply 后开放。</span></div>`;
  }

  function tabsMarkup() {
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs flow-engine-tabs" data-dwrt-component="tabs" data-dwrt-tabs-key="flow-engine" role="tablist" aria-label="流量引擎">
      <span class="dwrt-kit-tab-pill" aria-hidden="true"></span>
      ${FLOW_ENGINE_TABS.map((tab) => `<button class="dwrt-kit-tab ${state.tab === tab.id ? 'is-active' : ''}" type="button" role="tab" aria-selected="${state.tab === tab.id ? 'true' : 'false'}" data-value="${escapeHtml(tab.id)}" data-flow-tab="${escapeHtml(tab.id)}">${escapeHtml(tab.label)}</button>`).join('')}
    </nav>`;
  }

  function summaryMarkup() {
    const status = state.status;
    const runtimeApplied = status.runtimeApplied ?? state.runtime?.runtimeApplied;
    const runtimeValue = runtimeApplied === true ? '已应用' : runtimeApplied === false ? '未应用' : '未证实';
    const cards = [
      { key: 'configured', label: '配置状态', value: status.configuredEnabled ? '已启用' : '已停用', detail: status.configuredApplyMode || status.service || 'dreamingwrt-flowd', tone: status.configuredEnabled ? 'info' : 'neutral', icon: icon('sliders-horizontal') },
      { key: 'runtime', label: '运行应用', value: runtimeValue, detail: status.runtimeReason || state.runtime?.runtimeReason || '当前固件未提供运行态真值', tone: runtimeApplied === true ? 'ok' : runtimeApplied === false ? 'bad' : 'warn', icon: icon('circle-gauge') },
      { key: 'apply-mode', label: '应用模式', value: status.applyMode || '--', detail: status.planOnly ? '仅生成计划，不下发内核' : '允许进入应用阶段', tone: status.planOnly ? 'warn' : 'ok', icon: icon('git-compare-arrows') },
      { key: 'worker', label: 'Worker', value: state.runtime?.workerAvailable ? '已注册' : '未注册', detail: state.runtime?.source || '等待运行时来源', tone: state.runtime?.workerAvailable ? 'ok' : 'bad', icon: icon('cpu') },
      { key: 'qos', label: 'QoS 配置', value: `${formatInteger(status.enabledQosClasses)} / ${formatInteger(status.qosClasses)}`, detail: '配置启用 / 总数，不代表内核已应用', tone: 'info', icon: icon('gauge') },
      { key: 'jobs', label: '作业记录', value: formatInteger(status.applyJobs), detail: '编译、演练与应用历史', tone: 'neutral', icon: icon('list-checks') }
    ];
    const renderer = ui.overviewCardsMarkup || window.DWRT_UI_KIT?.overviewCardsMarkup;
    const overview = typeof renderer === 'function'
      ? renderer(cards, { className: 'flow-engine-overview', label: '流量引擎概览' })
      : '';
    const fallback = `<dl class="flow-engine-overview-fallback" aria-label="流量引擎概览">${cards.map((card) => `<div><dt>${escapeHtml(card.label)}</dt><dd>${escapeHtml(card.value)}</dd><small>${escapeHtml(card.detail)}</small></div>`).join('')}</dl>`;
    return `<section class="policy-entity-section flow-engine-summary"><header><div><h2>引擎概览</h2><p>来自 <code>flowd/status</code> 与 <code>flowd/runtime</code> 的真实值。</p></div></header>
      ${overview || fallback}
    </section>`;
  }

  function countersMarkup() {
    const rows = state.status.counters;
    return `<section class="policy-entity-section"><header><div><h2>规则库存</h2><p>规则的编辑入口在策略表、区域与对象页；这里只汇总引擎侧计数。</p></div></header>
      <div data-dwrt-component="data-table" class="policy-entity-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table">
        <thead><tr><th>规则类型</th><th>启用 / 总数</th><th>状态</th></tr></thead>
        <tbody>${rows.map((row) => `<tr><td><strong>${escapeHtml(row.label)}</strong><small>${escapeHtml(row.key)}</small></td><td>${formatInteger(row.enabled)} / ${formatInteger(row.total)}</td><td>${row.total === 0 ? statusBadge('未配置', 'muted') : statusBadge(row.enabled > 0 ? '已启用' : '全部停用', row.enabled > 0 ? 'success' : 'warning')}</td></tr>`).join('')}</tbody>
      </table></div></div>
    </section>`;
  }

  function applyJobsMarkup() {
    const jobs = state.applyJobs;
    const content = jobs.length
      ? `<div data-dwrt-component="data-table" class="policy-entity-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table">
          <thead><tr><th>作业</th><th>类型</th><th>状态</th><th>发起方</th><th>创建时间</th></tr></thead>
          <tbody>${jobs.map((job) => `<tr><td><strong>${escapeHtml(job.id)}</strong>${job.error ? `<small>${escapeHtml(job.error)}</small>` : ''}</td><td>${escapeHtml(job.kind || '--')}${job.dryRun ? statusBadge('dry-run', 'warning') : ''}</td><td>${statusBadge(job.state || '--', job.state === 'compiled' ? 'success' : job.error ? 'danger' : 'muted')}</td><td>${escapeHtml(job.requestedBy || '--')}</td><td>${escapeHtml(formatTimestamp(job.createdAt))}</td></tr>`).join('')}</tbody>
        </table></div></div>`
      : statePanel('empty', '没有应用作业', '引擎尚未产生编译或应用作业。');
    const allDryRun = jobs.length > 0 && jobs.every((job) => job.dryRun);
    const note = allDryRun
      ? `<div class="policy-entity-alert is-warning" role="status"><strong>全部作业均为 dry-run</strong><span>当前 ${formatInteger(jobs.length)} 个作业都是编译演练，没有任何一次真实下发。</span></div>`
      : '';
    return `<section class="policy-entity-section"><header><div><h2>编译与应用作业</h2><p>来自 <code>flowd/apply-jobs</code>。</p></div></header>${note}${content}</section>`;
  }

  function engineDetailMarkup() {
    const status = state.status;
    const runtime = state.runtime;
    const rows = [
      ['服务', status.service],
      ['版本', status.version || '--'],
      ['Schema 版本', `${status.schemaVersion || '--'}${status.schemaSource ? `（${status.schemaSource}）` : ''}`],
      ['迁移状态', status.migrationState || '--'],
      ['运行时合同', status.runtimeContractVersion || runtime?.runtimeContractVersion || '当前固件未提供'],
      ['运行时来源', runtime?.source || '--'],
      ['GeoIP 目录', status.geoipDir || '--'],
      ['计划产物目录', `${status.runtimeDir || '--'}${status.geoip.runtimeDirPresent ? '' : '（目录不存在）'}`],
      ['默认 GeoIP 源', status.geoip.defaultSource || '--'],
      ['MMDB', status.geoip.mmdbPresent ? (status.geoip.mmdbValid ? '存在且有效' : '存在但无效') : '缺失']
    ];
    return `<section class="policy-entity-section"><header><div><h2>引擎详情</h2><p>只读元数据，用于定位后端与固件状态。</p></div></header>
      <dl class="policy-entity-detail-list flow-engine-detail-list">${rows.map(([key, value]) => `<div><dt>${escapeHtml(key)}</dt><dd>${escapeHtml(String(value))}</dd></div>`).join('')}</dl>
    </section>`;
  }

  function nftRevisionMarkup() {
    if (!supportsNftRevisionReadback()) {
      const reason = state.status?.capabilities?.nftRevisionReason || '当前固件未提供 NFT revision 探针';
      return `<section class="policy-entity-section"><header><div><h2>NFT 运行证据</h2><p>只有后端声明 readback capability 后才会读取探针。</p></div>${statusBadge('未提供', 'muted')}</header>
        <div class="policy-entity-alert is-warning" role="status"><strong>未读取 NFT revision</strong><span>${escapeHtml(reason)}；页面没有请求未声明的接口，也不会把配置计数当成运行态。</span></div>
      </section>`;
    }
    const snapshot = state.snapshots.nftRevision;
    if (!snapshot || (snapshot.status === 'loading' && snapshot.value === undefined))
      return statePanel('loading', '正在读取 NFT revision', '等待 flowd 所有权与 revision readback。');
    if (['forbidden', 'error', 'unavailable'].includes(snapshot.status) && snapshot.value === undefined)
      return statePanel(snapshot.status, 'NFT revision 探针不可用', snapshot.error?.message || '后端已声明能力，但本次 readback 失败。');
    const nft = state.nftRevision;
    if (!nft)
      return statePanel('empty', '没有 NFT revision 数据', '后端没有返回可解析的 readback。');
    const rows = [
      ['NFT 表', [nft.tableFamily, nft.tableName].filter(Boolean).join(' ') || '--'],
      ['探针来源', nft.source || '--'],
      ['表是否存在', nft.present ? '是' : '否'],
      ['所有权已验证', nft.ownershipVerified ? '是' : '否'],
      ['Revision', nft.revision || '--'],
      ['包含策略规则', nft.containsPolicyRules ? '是' : '否'],
      ['运行态已应用', nft.runtimeApplied === true ? '是' : nft.runtimeApplied === false ? '否' : '未证实'],
      ['观测时间', formatTimestamp(nft.observedAt)]
    ];
    const note = nft.sentinelOnly
      ? `<div class="policy-entity-alert is-warning" role="status"><strong>仅所有权 sentinel</strong><span>该表只证明 flowd 对 NFT 表的所有权和 revision；不包含分流、QoS、路由、配额或应用策略规则。</span></div>`
      : nft.error
        ? `<div class="policy-entity-alert is-warning" role="status"><strong>Readback 不完整</strong><span>${escapeHtml(nft.error)}</span></div>`
        : '';
    return `<section class="policy-entity-section"><header><div><h2>NFT 运行证据</h2><p>来自 <code>flowd/nft-revision</code>，不等同于完整数据面 readback。</p></div>${statusBadge(nft.ownershipVerified ? '所有权已验证' : '未验证', nft.ownershipVerified ? 'success' : 'warning')}</header>
      ${note}<dl class="policy-entity-detail-list flow-engine-detail-list">${rows.map(([key, value]) => `<div><dt>${escapeHtml(key)}</dt><dd>${escapeHtml(String(value))}</dd></div>`).join('')}</dl>
    </section>`;
  }

  function qosConflictMarkup() {
    const flowd = state.qosSettings;
    const smart = state.smart?.qos;
    if (!flowd || !smart) return '';
    const conflicts = [];
    if (flowd.enabled !== smart.enabled) conflicts.push(`启用状态：flowd=${flowd.enabled ? 'true' : 'false'} / flow-control=${smart.enabled ? 'true' : 'false'}`);
    if (flowd.scheduler && smart.scheduler && flowd.scheduler !== smart.scheduler) conflicts.push(`调度器：flowd=${flowd.scheduler} / flow-control=${smart.scheduler}`);
    if (flowd.ackFilter !== smart.ackFilter) conflicts.push(`ACK 过滤：flowd=${flowd.ackFilter ? 'true' : 'false'} / flow-control=${smart.ackFilter ? 'true' : 'false'}`);
    if (!conflicts.length) return '';
    return `<div class="policy-entity-alert is-warning" role="status"><strong>两套 QoS 配置不一致</strong><span>${escapeHtml(conflicts.join('；'))}。后端存在 flowd 与 flow-control 两份互不同步的配置，前端无法判定权威来源，已按只读展示并登记后端缺口。</span></div>`;
  }

  function qosSettingsMarkup() {
    const qos = state.qosSettings;
    if (!qos) return statePanel('loading', '正在读取 QoS 设置', '等待 flowd QoS 设置快照。');
    const rows = [
      ['启用', qos.enabled ? '是' : '否'],
      ['调度器', qos.scheduler || '--'],
      ['默认类别', qos.defaultClass || '--'],
      ['未识别流量类别', qos.unknownClass || '--'],
      ['带宽余量', qos.headroomPct ? `${qos.headroomPct}%` : '--'],
      ['DiffServ', typeof qos.diffserv === 'boolean' ? (qos.diffserv ? '启用' : '停用') : (qos.diffserv || '--')],
      ['ACK 过滤', qos.ackFilter ? '启用' : '停用'],
      ['公平性', qos.fairness || '--']
    ];
    return `<section class="policy-entity-section"><header><div><h2>QoS 引擎设置</h2><p>来自 <code>flowd/qos/settings</code>。</p></div>${statusBadge(canWrite() ? '可写' : '只读', canWrite() ? 'success' : 'warning')}</header>
      <dl class="policy-entity-detail-list flow-engine-detail-list">${rows.map(([key, value]) => `<div><dt>${escapeHtml(key)}</dt><dd>${escapeHtml(String(value))}</dd></div>`).join('')}</dl>
    </section>`;
  }

  function qosClassesMarkup() {
    const classes = state.qosClasses;
    const content = classes.length
      ? `<div data-dwrt-component="data-table" class="policy-entity-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table">
          <thead><tr><th>类别</th><th>优先级</th><th>保障</th><th>上限</th><th>时延目标</th><th>DSCP</th><th>状态</th></tr></thead>
          <tbody>${classes.map((item) => `<tr><td><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.id)}</small></td><td>${formatInteger(item.priority)}</td><td>${item.guaranteePct ? `${item.guaranteePct}%` : '--'}</td><td>${item.ceilingPct ? `${item.ceilingPct}%` : '--'}</td><td>${item.latencyMs ? `${item.latencyMs} ms` : '--'}</td><td>${escapeHtml(item.dscp || '--')}</td><td>${statusBadge(item.enabled ? '已启用' : '已停用', item.enabled ? 'success' : 'muted')}</td></tr>`).join('')}</tbody>
        </table></div></div>`
      : statePanel('empty', '没有 QoS 类别', 'flowd 未返回任何 QoS 类别定义。');
    return `<section class="policy-entity-section"><header><div><h2>QoS 类别</h2><p>来自 <code>flowd/qos/classes</code>，按优先级升序。</p></div></header>${content}</section>`;
  }

  function smartPrioritiesMarkup() {
    const smart = state.smart;
    if (!smart) return '';
    const content = smart.priorities.length
      ? `<div data-dwrt-component="data-table" class="policy-entity-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table">
          <thead><tr><th>业务类别</th><th>优先级</th></tr></thead>
          <tbody>${smart.priorities.map((item) => `<tr><td><strong>${escapeHtml(item.label)}</strong><small>${escapeHtml(item.key)}</small></td><td>${formatInteger(item.priority)}</td></tr>`).join('')}</tbody>
        </table></div></div>`
      : statePanel('empty', '没有智能优先级', 'flow-control 未返回业务类别优先级。');
    const applyNote = smart.applyState && smart.applyState !== 'applied'
      ? `<div class="policy-entity-alert is-warning" role="status"><strong>智能流控从未应用</strong><span>${escapeHtml(`apply_state=${smart.applyState}，last_apply_at=${smart.lastApplyAt || 0}`)}；声明的引擎为 ${escapeHtml(smart.engine || '--')}，但内核中没有对应的 qdisc 或 nft 表。</span></div>`
      : '';
    return `<section class="policy-entity-section"><header><div><h2>智能流控优先级</h2><p>来自 <code>flow-control/smart</code>，模式 ${escapeHtml(smart.mode || '--')}。</p></div>${statusBadge('只读', 'warning')}</header>${applyNote}${content}</section>`;
  }

  function wanHealthMarkup() {
    const health = state.wanHealth;
    if (!health) return statePanel('loading', '正在读取 WAN 健康', '等待 flowd WAN 健康快照。');
    const content = health.wans.length
      ? `<div data-dwrt-component="data-table" class="policy-entity-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table">
          <thead><tr><th>线路</th><th>协议</th><th>时延</th><th>丢包</th><th>下行</th><th>上行</th><th>在线时长</th><th>状态</th></tr></thead>
          <tbody>${health.wans.map((wan) => `<tr><td><strong>${escapeHtml(wan.name)}</strong><small>${escapeHtml([wan.ifname, wan.ip].filter(Boolean).join(' · ') || '--')}</small></td><td>${escapeHtml(wan.proto || '--')}</td><td>${wan.latencyMs ? `${wan.latencyMs} ms` : '--'}</td><td>${wan.lossPct ? `${wan.lossPct}%` : '0%'}</td><td>${escapeHtml(formatRate(wan.downRate))}</td><td>${escapeHtml(formatRate(wan.upRate))}</td><td>${escapeHtml(formatDuration(wan.connectedSeconds))}</td><td>${statusBadge(wan.online ? (wan.health ? '健康' : '在线') : '离线', wan.online && wan.health ? 'success' : wan.online ? 'warning' : 'danger')}</td></tr>`).join('')}</tbody>
        </table></div></div>`
      : statePanel('empty', '没有 WAN 健康数据', '引擎未返回任何线路健康记录。');
    const note = health.workerAvailable === false
      ? `<div class="policy-entity-alert is-warning" role="status"><strong>健康数据来自核心运行时</strong><span>${escapeHtml(health.message || 'flowd worker 未注册')}，来源 ${escapeHtml(health.source || '--')}。</span></div>`
      : '';
    return `<section class="policy-entity-section"><header><div><h2>WAN 健康</h2><p>来自 <code>flowd/wan-health</code>。</p></div></header>${note}${content}</section>`;
  }

  function wanCapacityMarkup() {
    const entries = state.wanCapacity;
    const content = entries.length
      ? `<div data-dwrt-component="data-table" class="policy-entity-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table">
          <thead><tr><th>线路</th><th>下行容量</th><th>上行容量</th><th>状态</th></tr></thead>
          <tbody>${entries.map((item) => `<tr><td><strong>${escapeHtml(item.wan || item.id)}</strong>${item.remark ? `<small>${escapeHtml(item.remark)}</small>` : ''}</td><td>${item.downMbps ? `${formatInteger(item.downMbps)} Mbps` : '--'}</td><td>${item.upMbps ? `${formatInteger(item.upMbps)} Mbps` : '--'}</td><td>${statusBadge(item.enabled ? '已启用' : '已停用', item.enabled ? 'success' : 'muted')}</td></tr>`).join('')}</tbody>
        </table></div></div>`
      : statePanel('empty', '尚未配置线路容量', 'flowd 的 WAN 容量表为空；QoS 需要每条线路的真实上下行容量才能正确分配带宽。');
    const smartQos = state.smart?.qos;
    const declared = smartQos && (smartQos.totalDownloadMbps || smartQos.totalUploadMbps)
      ? `<dl class="policy-entity-detail-list flow-engine-detail-list"><div><dt>flow-control 声明总下行</dt><dd>${formatInteger(smartQos.totalDownloadMbps)} Mbps</dd></div><div><dt>flow-control 声明总上行</dt><dd>${formatInteger(smartQos.totalUploadMbps)} Mbps</dd></div><div><dt>时延目标</dt><dd>${smartQos.latencyTargetMs ? `${smartQos.latencyTargetMs} ms` : '--'}</dd></div></dl>`
      : '';
    return `<section class="policy-entity-section"><header><div><h2>线路容量</h2><p>来自 <code>flowd/wan-capacity</code> 与 <code>flow-control</code>。</p></div></header>${content}${declared}</section>`;
  }

  function tabContentMarkup() {
    if (state.tab === 'qos') return `${qosConflictMarkup()}${qosSettingsMarkup()}${qosClassesMarkup()}${smartPrioritiesMarkup()}`;
    if (state.tab === 'capacity') return `${wanHealthMarkup()}${wanCapacityMarkup()}`;
    return `${summaryMarkup()}${engineDetailMarkup()}${nftRevisionMarkup()}${countersMarkup()}${applyJobsMarkup()}`;
  }

  function workbenchMarkup() {
    const stale = Object.values(state.snapshots).some((snapshot) => snapshot?.stale)
      ? `<div class="policy-entity-alert is-warning" role="status"><strong>正在显示上次可用快照</strong><span>部分刷新失败，页面仍保留最后一次成功数据。</span></div>` : '';
    return `<section class="flow-engine-page">
      <div class="flow-engine-page-toolbar">${tabsMarkup()}<div class="flow-engine-toolbar-actions">${statusBadge(canWrite() ? '写入可用' : '只读', canWrite() ? 'success' : 'warning')}</div></div>
      <main class="flow-engine-workbench">${degradedBannerMarkup()}${stale}<div class="flow-engine-tab-content">${tabContentMarkup()}</div></main>
    </section>`;
  }

  function replaceMarkup(host, markup) {
    window.DWRT_UI_KIT?.unmount?.(host);
    host.replaceChildren(document.createRange().createContextualFragment(markup));
    ui.mountAll?.(host);
  }

  function renderPage() {
    if (!root || !state.mounted) return;
    const terminal = pageState();
    replaceMarkup(pageHost, terminal
      ? `<section class="flow-engine-page is-terminal"><main class="flow-engine-workbench">${statePanel(terminal.name, terminal.title, terminal.detail)}</main></section>`
      : workbenchMarkup());
  }

  function render() {
    renderPage();
  }

  function scheduleRender() {
    if (!state.mounted || state.suppressRegistryRender || state.renderFrame) return;
    state.renderFrame = window.requestAnimationFrame(() => {
      state.renderFrame = 0;
      if (!state.mounted || state.suppressRegistryRender) return;
      hydrate();
      renderPage();
    });
  }

  function refresh(force = true) {
    if (!registry) return Promise.resolve();
    if (state.refreshPromise) {
      state.refreshQueued = state.refreshQueued || force;
      return state.refreshPromise;
    }
    state.refreshPromise = (async () => {
      let nextForce = force;
      do {
        state.refreshQueued = false;
        state.refreshing = true;
        renderPage();
        state.suppressRegistryRender = true;
        await Promise.allSettled(BASE_REGISTRY_SLOTS.map(([key]) => registry.request(key, { signal, force: nextForce })));
        hydrate();
        if (supportsNftRevisionReadback()) {
          await registry.request(NFT_REGISTRY_SLOT[0], { signal, force: nextForce }).catch(() => {});
          hydrate();
        } else {
          state.snapshots.nftRevision = null;
          state.nftRevision = null;
        }
        nextForce = state.refreshQueued;
      } while (state.mounted && state.refreshQueued);
      if (!state.mounted) return;
      state.suppressRegistryRender = false;
      state.refreshing = false;
      renderPage();
    })().finally(() => {
      state.refreshPromise = null;
      state.suppressRegistryRender = false;
      if (state.mounted && state.refreshing) {
        state.refreshing = false;
        renderPage();
      }
    });
    return state.refreshPromise;
  }

  function onClick(event) {
    const tabButton = event.target.closest?.('[data-flow-tab]');
    if (tabButton) {
      const next = tabButton.getAttribute('data-flow-tab');
      if (next && next !== state.tab) {
        state.tab = next;
        renderPage();
      }
      return;
    }
  }

  function subscribe(key, slot) {
    return registry?.subscribe?.(key, (snapshot) => {
      if (!state.mounted) return;
      state.snapshots[slot] = snapshot;
      scheduleRender();
    });
  }

  root.hidden = false;
  root.className = 'route-preview route-workspace flow-engine-route-host';
  stage?.classList.add('is-flow-engine');
  root.replaceChildren(pageHost, overlayHost);
  root.addEventListener('click', onClick);
  const unsubscribers = REGISTRY_SLOTS.map(([key, slot]) => subscribe(key, slot)).filter(Boolean);
  render();
  if (registry) Promise.allSettled(BASE_REGISTRY_SLOTS.map(([key]) => registry.request(key, { signal })))
    .then(async () => {
      if (!state.mounted) return;
      hydrate();
      if (supportsNftRevisionReadback()) {
        await registry.request(NFT_REGISTRY_SLOT[0], { signal }).catch(() => {});
        if (!state.mounted) return;
        hydrate();
      }
      state.suppressRegistryRender = false;
      renderPage();
    });

  /*
   * 手动刷新按钮按用户第 9 条删除。这一页订阅了 registry，但 registry 只按 TTL
   * 缓存、不自轮询，所以补一条可见性受控的轮询强制重取（QoS 队列、apply 任务、
   * WAN 健康都是运行态数据）。
   */
  state.pollTimer = window.setInterval(() => {
    if (!state.mounted || document.hidden) return;
    if (state.refreshing || state.refreshPromise) return;
    refresh(true);
  }, 15000);

  return {
    refresh,
    unmount() {
      state.mounted = false;
      window.clearInterval(state.pollTimer);
      if (state.renderFrame) window.cancelAnimationFrame(state.renderFrame);
      unsubscribers.forEach((unsubscribe) => unsubscribe());
      root.removeEventListener('click', onClick);
      window.DWRT_UI_KIT?.unmount?.(root);
      root.replaceChildren();
      root.classList.remove('route-workspace', 'flow-engine-route-host');
      stage?.classList.remove('is-flow-engine');
    }
  };
}

export default { mount };
