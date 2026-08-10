const FLOW_ENGINE_TABS = [
  { id: 'engine', label: '引擎状态' },
  { id: 'qos', label: 'QoS 引擎' },
  { id: 'smart', label: '智能流控' },
  { id: 'capacity', label: '容量与健康' },
  { id: 'balance', label: '多线负载' },
  { id: 'geoip', label: 'GeoIP 数据源' }
];

/*
 * 11 类自定义协议优先级的显示定义与缺省值。
 *
 * 显示名与说明取自老实现 `luci-app.bak/.../pages/flow-control.js:288 flowPriorityItems()`，
 * 缺省值取自 `JMXD_FLOW_CONTROL_SMART_ADVANCED_GAPS_20260604.md` 第 3 节的默认值表。
 * 量纲是 0 最高、7 最低（同文档），与 flowd 的 `priority` 默认 500 不是一套量纲，
 * 这里只用于展示 legacy `flow-control/smart` 返回的值。
 *
 * 缺省值只在后端**没有返回该 key** 时用于补位，并显式标注为默认值；
 * 后端返回了就一律用后端的数，前端不做任何覆盖或推断。
 */
export const SMART_CATEGORY_DEFS = [
  { key: 'game', label: '网络游戏', detail: 'UDP、实时对战', fallback: 0 },
  { key: 'web', label: '网页浏览', detail: 'HTTP、HTTPS、DNS', fallback: 1 },
  { key: 'social', label: '社交通讯', detail: 'IM、语音、视频通话', fallback: 1 },
  { key: 'unknown', label: '未知应用', detail: '未识别流量', fallback: 2 },
  { key: 'productivity', label: '效率工具', detail: '同步、笔记、自动化', fallback: 3 },
  { key: 'work', label: '办公协作', detail: '会议、远程桌面', fallback: 4 },
  { key: 'education', label: '学习教育', detail: '网课、资料、课堂互动', fallback: 4 },
  { key: 'life', label: '生活服务', detail: '地图、外卖、出行', fallback: 5 },
  { key: 'finance', label: '金融理财', detail: '交易、支付、行情', fallback: 5 },
  { key: 'entertainment', label: '休闲娱乐', detail: '视频、音乐、社交内容', fallback: 6 },
  { key: 'download', label: '传输下载', detail: 'BT、网盘、大文件', fallback: 7 }
];

/* 5 个线路场景档位，取自老实现 `flow-control.js:210 flowSmartModes()`。
 * 本阶段只用于把 `smart.mode` / `smart.line_modes[id]` 的机器值翻成中文显示，
 * 不作为可点选控件：写侧权威源（legacy 表 vs flowd smart-qos）后端未定，见本页只读说明。 */
export const SMART_LINE_MODES = [
  { id: 'custom', label: '自定义', detail: '自定义协议优先级' },
  { id: 'web', label: '网页优先', detail: '浏览、DNS、办公优先' },
  { id: 'game', label: '游戏优先', detail: '低延迟与实时流量优先' },
  { id: 'entertainment', label: '休闲娱乐', detail: '视频与社交体验优先' },
  { id: 'download', label: '下载优先', detail: '大文件传输优先' }
];

/*
 * 后端边界（flowd_internal.h:44-46、flowd_db.c 的 save_one 校验）：
 * 间隔只接受 86400 ~ 7776000 秒，时间窗只接受 0~23 的整点，越界后端直接拒绝整条记录。
 * 这里的档位必须落在该区间内，否则表单能填但存不进去。
 */
export const GEOIP_UPDATE_INTERVAL_MIN_S = 86400;
export const GEOIP_UPDATE_INTERVAL_MAX_S = 7776000;
export const GEOIP_INTERVAL_CHOICES = [
  { value: 86400, label: '每天' },
  { value: 604800, label: '每周' },
  { value: 1209600, label: '每两周' },
  { value: 2592000, label: '每月' },
  { value: 7776000, label: '每季度' }
];

/* 后端扫描周期（flowd_db.c:1383 的 schedule.tick_interval_s = 900）。next_run_at 到点后
 * 最多还要等一个扫描周期才真正开始执行，所以「到点」不等于「正在更新」。 */
export const GEOIP_SCHEDULE_TICK_S = 900;

/* last_error 是半结构化的：第一个冒号前是稳定的机器可读 code，冒号后是细节。
 * code 出处见 flowd_db.c：probe_failed:1884、download_failed:1623、
 * insufficient_space:2023、not_maxmind_mmdb:1458、unchanged:2013。
 * 只按 code 分类配色，细节原文放到详情里，不在前端猜语义。 */
export const GEOIP_ERROR_CODES = {
  unchanged: { label: '上游无更新', tone: 'success', detail: false },
  probe_failed: { label: '探测上游失败', tone: 'warning', detail: true },
  download_failed: { label: '下载失败', tone: 'warning', detail: true },
  insufficient_space: { label: '磁盘空间不足', tone: 'warning', detail: true },
  not_maxmind_mmdb: { label: '下载内容不是合法 MMDB', tone: 'warning', detail: false },
  invalid_size: { label: '文件大小异常', tone: 'warning', detail: false },
  too_small: { label: '文件过小，疑似残缺', tone: 'warning', detail: false },
  rename_failed: { label: '落盘失败（重命名）', tone: 'warning', detail: false },
  download_fsync_failed: { label: '落盘失败（同步）', tone: 'warning', detail: false },
  source_not_found: { label: '源配置不存在', tone: 'warning', detail: false },
  invalid_source_url: { label: '源地址不合法', tone: 'warning', detail: false }
};

/* insufficient_space 的两个数字是字节，给用户看要换算。 */
function geoipBytesText(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return '';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let index = 0;
  let scaled = bytes;
  while (scaled >= 1024 && index < units.length - 1) {
    scaled /= 1024;
    index += 1;
  }
  return `${index === 0 ? scaled : scaled.toFixed(scaled < 10 ? 1 : 0)} ${units[index]}`;
}

/* 把 last_error 拆成 { code, label, tone, detail, failed }。
 * failed=false 只有 unchanged 一种：那是成功态，绝不能渲染成失败。
 * 未知 code 一律按失败处理,宁可多报一次失败，也不要把真失败显示成正常。 */
export function parseGeoipLastError(lastError) {
  const raw = String(lastError ?? '').trim();
  if (!raw) return null;
  const code = raw.split(':')[0];
  const known = GEOIP_ERROR_CODES[code] || null;
  const rest = raw.slice(code.length + 1);
  let detail = known?.detail ? rest : '';
  if (code === 'insufficient_space') {
    const match = /^need_(\d+):free_(\d+)$/.exec(rest);
    /* 格式变了就退回原文，不要因为解析不了就把信息吞掉。 */
    detail = match
      ? `需要 ${geoipBytesText(match[1])}，可用 ${geoipBytesText(match[2])}`
      : rest;
  }
  return {
    code,
    label: known ? known.label : code,
    tone: known ? known.tone : 'warning',
    detail,
    failed: code !== 'unchanged',
    raw
  };
}

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

export function normalizeWanPolicy(payload = {}) {
  const data = payload && typeof payload.data === 'object' && payload.data !== null ? payload.data : payload;
  const number = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
  /* number() 把缺失折叠成 0，对「延迟」「丢包」这类指标会撒谎（0ms / 0% 是好成绩，
     而缺失是不知道）。optional() 缺失时返回 null，交由渲染层整项省略。 */
  const optional = (value) => (value === null || value === undefined || value === '' ? null
    : Number.isFinite(Number(value)) ? Number(value) : null);
  const text = (...values) => values.map((value) => String(value ?? '').trim()).find(Boolean) || '';
  const uniqueIds = (values) => [...new Set((Array.isArray(values) ? values : [])
    .map(Number).filter((value) => Number.isInteger(value) && value > 0))].sort((a, b) => a - b);
  const smart = data.smart_path && typeof data.smart_path === 'object' ? data.smart_path : {};
  return {
    mode: text(data.mode, data.algorithm),
    algorithm: text(data.algorithm, data.mode),
    fallbackMode: text(data.fallback_mode),
    availableModes: (Array.isArray(data.available_modes) ? data.available_modes : []).map((item = {}) => ({
      id: text(item.id, item.algorithm),
      label: text(item.label, item.id, item.algorithm),
      description: text(item.description)
    })).filter((item) => item.id),
    wanIds: uniqueIds(data.wan_ids),
    wans: (Array.isArray(data.wans) ? data.wans : []).map((item = {}, index) => ({
      id: number(item.id ?? item.kernel_wan_id ?? item.wan_id ?? index + 1),
      name: text(item.name, item.ifname, `WAN ${index + 1}`),
      ifname: text(item.ifname, item.interface, item.device),
      carrier: text(item.carrier, item.carrier_name),
      online: item.online !== false && item.health !== false,
      connections: number(item.active_conn ?? item.connections ?? item.conn_count),
      /* 后端在同一响应里已经给了这些实测值，成员卡片要显示它们才有决策价值。
         health_measured 为 false 时延迟/丢包是未测量而非 0，所以只在测量过时接出。 */
      /* 用 optional 而不是 number()：number() 缺失时返回 0，会让「后端没给」
         和「真的是 0 ms / 0% 丢包」在界面上不可区分。 */
      latencyMs: item.health_measured === false ? null : optional(item.latency_ms ?? item.latency),
      lossPct: item.health_measured === false ? null : optional(item.loss_pct ?? item.loss),
      /* sample_valid 为 false 时速率样本不可信，宁可不显示也不显示错的。 */
      downRate: item.sample_valid === false ? null : optional(item.down_rate ?? item.rate_down),
      upRate: item.sample_valid === false ? null : optional(item.up_rate ?? item.rate_up)
    })).filter((item) => Number.isInteger(item.id) && item.id > 0),
    writeSupported: data.write_supported === true,
    memberSelection: data.member_selection === true,
    runtimeApplied: data.runtime_applied === true,
    existingConnections: text(data.existing_connections, 'unchanged'),
    configAuthority: text(data.config_authority),
    carrierNeutral: data.carrier_neutral === true,
    smartPath: {
      enabledRequested: smart.enabled_requested === true,
      schedulerActive: smart.scheduler_active === true,
      nftActive: smart.nft_active === true,
      nftReadbackOk: smart.nft_readback_ok === true,
      active: smart.active === true,
      lastError: text(smart.last_error),
      wanPathCount: number(smart.wan_path_count)
    }
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
  const lineModes = smart.line_modes && typeof smart.line_modes === 'object' ? smart.line_modes : {};
  const defaultMode = text(smart.mode, global.mode);
  /* 11 类固定展示：后端有值用后端值，缺 key 用缺口文档默认值补位并标 fallback，
   * 不显示空行（验收标准第 3 条）。后端多返回的 key 追加在后面，不丢数据。 */
  const knownKeys = new Set(SMART_CATEGORY_DEFS.map((item) => item.key));
  const categoryRows = SMART_CATEGORY_DEFS.map((def) => {
    const present = Object.prototype.hasOwnProperty.call(priorities, def.key)
      && Number.isFinite(Number(priorities[def.key]));
    return {
      key: def.key,
      label: def.label,
      detail: def.detail,
      priority: present ? number(priorities[def.key]) : def.fallback,
      fallback: !present
    };
  }).concat(Object.keys(priorities)
    .filter((key) => !knownKeys.has(key))
    .map((key) => ({ key, label: key, detail: '后端新增类别', priority: number(priorities[key]), fallback: false })))
    .sort((a, b) => a.priority - b.priority || a.key.localeCompare(b.key));
  return {
    mode: defaultMode,
    applyState: text(global.applyState, global.apply_state),
    lastApplyAt: number(global.last_apply_at),
    engine: text(global.engine),
    globalEnabled: global.enabled === true,
    defaultPolicy: text(global.default_policy),
    unknownPolicy: text(global.unknown_policy),
    stickySession: global.sticky_session === true,
    logDecisions: global.log_decisions === true,
    dpiRequired: global.dpi_required === true,
    /* runtime_applied / runtime_reason 直接取后端真值，前端不推断「已生效」（design.md:1076）。
     * 顶层与 global 都带这两个字段，取顶层优先、global 兜底。 */
    runtimeApplied: typeof data.runtime_applied === 'boolean' ? data.runtime_applied
      : typeof global.runtime_applied === 'boolean' ? global.runtime_applied : null,
    runtimeReason: text(data.runtime_reason, global.runtime_reason),
    sourceOfTruth: text(data.source_of_truth),
    authoritativeRuntimeSource: text(data.authoritative_runtime_source),
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
    prioritiesReported: Object.keys(priorities).length,
    priorities: categoryRows,
    lineModesSaved: Object.keys(lineModes).length,
    wans: (Array.isArray(data.wans) ? data.wans : []).map((item = {}, index) => {
      const id = text(item.id, item.name, `wan-${index + 1}`);
      const saved = text(lineModes[id]);
      return {
        id,
        name: text(item.name, item.id, `WAN ${index + 1}`),
        ifname: text(item.ifname),
        carrier: text(item.carrier),
        enabled: item.enabled === true,
        status: text(item.status),
        /* 该线路没保存过档位就回落全局 smart.mode，并标明是回落值而不是逐线路配置。 */
        mode: saved || defaultMode,
        modeInherited: !saved
      };
    })
  };
}

export function flowEngineTabFromLocation(hash = '') {
  const match = String(hash || '').match(/[?&]tab=([a-z-]+)/i);
  const id = match ? match[1].toLowerCase() : '';
  return FLOW_ENGINE_TABS.some((tab) => tab.id === id) ? id : FLOW_ENGINE_TABS[0].id;
}

export function normalizeFlowGeoipSources(payload = {}) {
  const data = payload && typeof payload.data === 'object' && payload.data !== null ? payload.data : payload;
  const text = (...values) => values.map((value) => String(value ?? '').trim()).find(Boolean) || '';
  const number = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
  const list = Array.isArray(data.sources) ? data.sources : [];
  const fs = data.filesystem && typeof data.filesystem === 'object' ? data.filesystem : {};
  return {
    ok: data.ok !== false,
    error: text(data.error),
    filesystem: {
      configuredMmdb: fs.configured_mmdb === true,
      configuredMmdbValid: fs.configured_mmdb_valid === true,
      configuredMmdbPath: text(fs.configured_mmdb_path),
      autoImportNeeded: fs.auto_import_needed === true
    },
    sources: list.filter((item) => item && typeof item === 'object').map((item) => {
      const meta = item.meta && typeof item.meta === 'object' ? item.meta : {};
      return {
        id: text(item.id),
        name: text(item.name, item.id),
        type: text(item.type),
        path: text(item.path),
        edition: text(item.edition),
        enabled: item.enabled === true,
        pathPresent: item.path_present === true,
        url: text(meta.url),
        /* auto_update 是启动期 bootstrap 开关，与周期刷新 update_enabled 不是一回事，
         * 后端注释（flowd_db.c:164）明确要求两者分开，这里不合并。 */
        bootstrapEnabled: item.auto_update === true,
        updateEnabled: item.update_enabled === true,
        updateIntervalS: number(item.update_interval_s),
        windowStartH: number(item.update_window_start_h),
        windowEndH: number(item.update_window_end_h),
        lastCheckAt: number(item.last_check_at),
        lastSuccessAt: number(item.last_success_at),
        lastImportAt: number(item.last_import_at),
        lastImportStatus: text(item.last_import_status),
        lastError: text(item.last_error),
        nextRunAt: number(item.next_run_at),
        consecutiveFailures: number(item.consecutive_failures),
        remoteEtag: text(item.remote_etag),
        remoteLastModified: text(item.remote_last_modified),
        /* 有无 URL 决定它能不能被下载刷新；本地文件源没有远端可查。 */
        remoteCapable: Boolean(text(meta.url))
      };
    })
  };
}

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const stage = root?.closest('.console-stage');
  const registry = context.registry;
  const api = context.api || {};
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
      nftRevision: null, wanPolicy: null, geoipSources: null
    },
    status: null,
    runtime: null,
    qosSettings: null,
    qosClasses: [],
    applyJobs: [],
    wanCapacity: [],
    wanHealth: null,
    wanPolicy: null,
    balanceDraft: null,
    balanceSaving: false,
    balanceNotice: '',
    smart: null,
    nftRevision: null,
    geoip: null,
    geoipDrafts: new Map(),
    geoipSavingId: '',
    geoipImportingId: '',
    geoipNotices: new Map(),
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

  registry?.define?.('network.wanPolicy', {
    url: '/api/v1/network/wan-policy',
    owner: 'webd.network.wan-policy',
    ttlMs: 3000,
    units: { connections: 'count' }
  });

  /* import/status 比 sources 多一个 filesystem 块（flowd_db.c:1224），空态文案要用它，
   * 所以订阅这个端点而不是 /geoip/sources。 */
  registry?.define?.('flow.geoipSources', {
    url: '/api/v1/flowd/geoip/import/status',
    owner: 'webd.flowd',
    ttlMs: 10000,
    units: {}
  });

  const BASE_REGISTRY_SLOTS = [
    ['flow.engineStatus', 'status'],
    ['flow.engineRuntime', 'runtime'],
    ['flow.engineSettings', 'settings'],
    ['flow.qosSettings', 'qosSettings'],
    ['flow.qosClasses', 'qosClasses'],
    ['flow.applyJobs', 'applyJobs'],
    ['flow.wanCapacity', 'wanCapacity'],
    ['flow.wanHealth', 'wanHealth'],
    ['flow.smartControl', 'smart'],
    ['network.wanPolicy', 'wanPolicy'],
    ['flow.geoipSources', 'geoipSources']
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
    if (value('wanPolicy') !== undefined) {
      const next = normalizeWanPolicy(value('wanPolicy'));
      const dirty = state.balanceDraft && state.wanPolicy && (
        state.balanceDraft.mode !== state.wanPolicy.mode ||
        JSON.stringify(state.balanceDraft.wanIds) !== JSON.stringify(state.wanPolicy.wanIds)
      );
      state.wanPolicy = next;
      if (!dirty && !state.balanceSaving) {
        state.balanceDraft = { mode: next.mode, wanIds: [...next.wanIds] };
      }
    }
    if (value('wanCapacity') !== undefined) state.wanCapacity = normalizeFlowWanCapacity(value('wanCapacity'));
    if (value('wanHealth') !== undefined) state.wanHealth = normalizeFlowWanHealth(value('wanHealth'));
    if (value('smart') !== undefined) state.smart = normalizeFlowSmartControl(value('smart'));
    if (value('nftRevision') !== undefined) state.nftRevision = normalizeFlowNftRevision(value('nftRevision'));
    if (value('geoipSources') !== undefined) {
      state.geoip = normalizeFlowGeoipSources(value('geoipSources'));
      /* 轮询每 15s 就会回来一次，不能覆盖用户正在填的草稿；只丢弃已消失的源。 */
      const ids = new Set(state.geoip.sources.map((source) => source.id));
      [...state.geoipDrafts.keys()].forEach((id) => {
        if (!ids.has(id)) state.geoipDrafts.delete(id);
      });
    }
  }

  function supportsNftRevisionReadback() {
    return state.status?.capabilities?.nftRevisionReadback === true;
  }

  function pageState() {
    if (!registry) return { name: 'unavailable', title: '流量引擎数据合同不可用', detail: '当前页面没有获得共享 DataRegistry。' };
    if (state.tab === 'geoip') {
      const snapshot = state.snapshots.geoipSources;
      if (state.geoip) return null;
      if (snapshot?.status === 'forbidden') return { name: 'forbidden', title: '无权读取 GeoIP 数据源', detail: '当前账号没有 GeoIP 源的读取权限。' };
      if (['error', 'unavailable'].includes(snapshot?.status)) {
        const code = String(snapshot.error?.code || '');
        if (code === 'method_not_registered') return { name: 'unavailable', title: 'GeoIP 源管理尚未接入', detail: '后端还没有注册 geoip_import_status 方法。' };
        return { name: snapshot.status, title: '无法读取 GeoIP 数据源', detail: snapshot.error?.message || 'GeoIP 源接口当前不可用。' };
      }
      return { name: 'loading', title: '正在读取 GeoIP 数据源', detail: '等待源列表与库文件状态快照。' };
    }
    if (state.tab === 'balance') {
      const snapshot = state.snapshots.wanPolicy;
      if (state.wanPolicy) return null;
      if (snapshot?.status === 'forbidden') return { name: 'forbidden', title: '无权读取多线负载', detail: '当前账号没有 WAN 策略读取权限。' };
      if (['error', 'unavailable'].includes(snapshot?.status)) return { name: snapshot.status, title: '无法读取多线负载', detail: snapshot.error?.message || 'WAN 策略接口当前不可用。' };
      return { name: 'loading', title: '正在读取多线负载', detail: '等待 WAN 策略、成员与连接数快照。' };
    }
    /* 智能流控只依赖 flow-control 快照；引擎状态或运行时读失败不该把这一页也整页封掉，
     * 它自己的加载/无权/失败态由 smartMarkup() 就地渲染。 */
    if (state.tab === 'smart') return null;
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
    return `<section class="policy-entity-section flow-engine-summary"><header class="dwrt-kit-glass-surface"><div><h2>引擎概览</h2><p>来自 <code>flowd/status</code> 与 <code>flowd/runtime</code> 的真实值。</p></div></header>
      ${overview || fallback}
    </section>`;
  }

  function countersMarkup() {
    const rows = state.status.counters;
    return `<section class="policy-entity-section"><header class="dwrt-kit-glass-surface"><div><h2>规则库存</h2><p>规则的编辑入口在策略表、区域与对象页；这里只汇总引擎侧计数。</p></div></header>
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
    return `<section class="policy-entity-section"><header class="dwrt-kit-glass-surface"><div><h2>编译与应用作业</h2><p>来自 <code>flowd/apply-jobs</code>。</p></div></header>${note}${content}</section>`;
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
    return `<section class="policy-entity-section"><header class="dwrt-kit-glass-surface"><div><h2>引擎详情</h2><p>只读元数据，用于定位后端与固件状态。</p></div></header>
      <dl class="policy-entity-detail-list flow-engine-detail-list">${rows.map(([key, value]) => `<div><dt>${escapeHtml(key)}</dt><dd>${escapeHtml(String(value))}</dd></div>`).join('')}</dl>
    </section>`;
  }

  function nftRevisionMarkup() {
    if (!supportsNftRevisionReadback()) {
      const reason = state.status?.capabilities?.nftRevisionReason || '当前固件未提供 NFT revision 探针';
      return `<section class="policy-entity-section"><header class="dwrt-kit-glass-surface"><div><h2>NFT 运行证据</h2><p>只有后端声明 readback capability 后才会读取探针。</p></div>${statusBadge('未提供', 'muted')}</header>
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
    return `<section class="policy-entity-section"><header class="dwrt-kit-glass-surface"><div><h2>NFT 运行证据</h2><p>来自 <code>flowd/nft-revision</code>，不等同于完整数据面 readback。</p></div>${statusBadge(nft.ownershipVerified ? '所有权已验证' : '未验证', nft.ownershipVerified ? 'success' : 'warning')}</header>
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
    return `<section class="policy-entity-section"><header class="dwrt-kit-glass-surface"><div><h2>QoS 引擎设置</h2><p>来自 <code>flowd/qos/settings</code>。</p></div>${statusBadge(canWrite() ? '可写' : '只读', canWrite() ? 'success' : 'warning')}</header>
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
    return `<section class="policy-entity-section"><header class="dwrt-kit-glass-surface"><div><h2>QoS 类别</h2><p>来自 <code>flowd/qos/classes</code>，按优先级升序。</p></div></header>${content}</section>`;
  }

  function smartModeLabel(mode) {
    const raw = String(mode || '').trim();
    if (!raw) return '--';
    const item = SMART_LINE_MODES.find((entry) => entry.id === raw);
    return item ? item.label : raw;
  }

  /* 优先级数字翻成人话，量纲固定 0 最高 / 7 最低，与老实现 flowPriorityItem() 一致。 */
  function smartPriorityText(value) {
    if (!Number.isFinite(Number(value))) return '--';
    const level = Number(value);
    if (level === 0) return '最高';
    if (level === 7) return '最低';
    return `P${level}`;
  }

  /*
   * 生效状态横幅：只展示后端真值。
   *
   * 后端顶层与 global 都返回 runtime_applied=false / runtime_reason，30.1 实测为
   * `dataplane_apply_executor_missing`（apply 执行器缺失），队列实为 fq_codel。
   * 所以这里必须说清「保存的优先级当前不影响真实队列」，reason 原文照抄，
   * 不由前端按 apply_state 或引擎字符串反推结论（design.md:1076）。
   */
  function smartRuntimeNoticeMarkup(smart) {
    if (smart.runtimeApplied === true) return '';
    const bits = [];
    if (smart.runtimeReason) bits.push(`runtime_reason=${smart.runtimeReason}`);
    if (smart.applyState) bits.push(`apply_state=${smart.applyState}`);
    bits.push(`last_apply_at=${smart.lastApplyAt || 0}`);
    if (smart.engine) bits.push(`声明引擎=${smart.engine}`);
    const headline = smart.runtimeApplied === false ? '当前优先级未落到内核队列' : '内核是否生效未获证实';
    return `<div class="policy-entity-alert is-warning" role="status"><strong>${escapeHtml(headline)}</strong><span>${escapeHtml(bits.join('；'))}。后端报告下发链未应用，因此下面这些优先级只是配置库里的值，不代表真实 qdisc 或 tc class 行为。</span></div>`;
  }

  function smartContractNoticeMarkup() {
    return `<div class="policy-entity-alert" role="status"><strong>本页当前只读</strong><span>后端存在 legacy <code>flow_smart_priority</code>（0-7）与 flowd <code>smart_qos_categories</code>（默认 500，越小越前）两套并行实现，权威源与量纲尚未确定，因此这里不提供滑块、档位切换或保存。等后端定下写入合同再开放编辑，避免出现点了没有实际效果的控件。</span></div>`;
  }

  function smartLineModesMarkup() {
    const smart = state.smart;
    if (!smart) return '';
    const wans = smart.wans;
    const content = wans.length
      ? `<div data-dwrt-component="data-table" class="policy-entity-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table">
          <thead><tr><th>线路</th><th>接口</th><th>运营商</th><th>状态</th><th>当前场景</th></tr></thead>
          <tbody>${wans.map((item) => `<tr><td><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.id)}</small></td><td>${escapeHtml(item.ifname || '--')}</td><td>${escapeHtml(item.carrier || '--')}</td><td>${statusBadge(item.status || '未知', item.status === 'ok' ? 'success' : 'warning')}</td><td class="flow-smart-mode-cell"><strong>${escapeHtml(smartModeLabel(item.mode))}</strong><small>${escapeHtml(item.modeInherited ? '沿用全局模式' : '逐线路已保存')}</small></td></tr>`).join('')}</tbody>
        </table></div></div>`
      : statePanel('empty', '没有可分配的线路', 'flow-control 未返回 WAN 线路列表，线路场景无从展示。');
    const savedNote = wans.length && !smart.lineModesSaved
      ? `<div class="policy-entity-alert" role="status"><strong>尚未做过逐线路分配</strong><span>后端 <code>smart.line_modes</code> 为空，所有线路显示的都是全局模式 <code>${escapeHtml(smart.mode || '--')}</code> 的回落值。</span></div>`
      : '';
    /* header 的 <p> 里 <code> 是 display:block（本页既有样式），每个都会独占一行，
     * 所以这里只引用一处端点，其余用普通文字，避免说明被撑成五六行。 */
    return `<section class="policy-entity-section"><header class="dwrt-kit-glass-surface"><div><h2>线路场景分配</h2><p>线路、运营商与状态来自 <code>flow-control</code> 的 wans；运营商仅作显示元数据，不参与档位预设。</p></div>${statusBadge(`${formatInteger(wans.length)} 条线路`, 'muted')}</header>${savedNote}${content}</section>`;
  }

  function smartPrioritiesMarkup() {
    const smart = state.smart;
    if (!smart) return '';
    const fallbackCount = smart.priorities.filter((item) => item.fallback).length;
    const content = smart.priorities.length
      ? `<div data-dwrt-component="data-table" class="policy-entity-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table">
          <thead><tr><th>业务类别</th><th>典型归类</th><th>优先级</th><th>档位</th><th>来源</th></tr></thead>
          <tbody>${smart.priorities.map((item) => `<tr><td><strong>${escapeHtml(item.label)}</strong><small>${escapeHtml(item.key)}</small></td><td>${escapeHtml(item.detail || '--')}</td><td>${formatInteger(item.priority)}</td><td>${escapeHtml(smartPriorityText(item.priority))}</td><td>${item.fallback ? statusBadge('默认值', 'warning') : statusBadge('后端已保存', 'success')}</td></tr>`).join('')}</tbody>
        </table></div></div>`
      : statePanel('empty', '没有智能优先级', 'flow-control 未返回业务类别优先级。');
    const fallbackNote = fallbackCount
      ? `<div class="policy-entity-alert" role="status"><strong>${formatInteger(fallbackCount)} 类使用默认值展示</strong><span>后端 <code>smart.priorities</code> 没有返回这些 key，表中显示的是缺口文档给出的默认值，并非配置库里的已保存值。</span></div>`
      : '';
    return `<section class="policy-entity-section"><header class="dwrt-kit-glass-surface"><div><h2>自定义协议优先级</h2><p>来自 <code>flow-control/smart</code>，量纲 0 最高 / 7 最低；全局模式 ${escapeHtml(smartModeLabel(smart.mode))}。</p></div>${statusBadge(`${formatInteger(smart.prioritiesReported)}/${formatInteger(SMART_CATEGORY_DEFS.length)} 已保存`, smart.prioritiesReported >= SMART_CATEGORY_DEFS.length ? 'success' : 'warning')}</header>${fallbackNote}${content}</section>`;
  }

  function smartMarkup() {
    const smart = state.smart;
    if (!smart) {
      const snapshot = state.snapshots.smart;
      if (snapshot?.status === 'forbidden') return statePanel('forbidden', '无权读取智能流控', '当前账号没有 flow-control 的读取权限。');
      if (snapshot?.error) return statePanel('error', '无法读取智能流控', snapshot.error?.message || 'flow-control 接口当前不可用。');
      return statePanel('loading', '正在读取智能流控', '等待 flow-control 的模式、线路与协议优先级快照。');
    }
    return `${smartRuntimeNoticeMarkup(smart)}${smartContractNoticeMarkup()}${smartLineModesMarkup()}${smartPrioritiesMarkup()}`;
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
    return `<section class="policy-entity-section"><header class="dwrt-kit-glass-surface"><div><h2>WAN 健康</h2><p>来自 <code>flowd/wan-health</code>。</p></div></header>${note}${content}</section>`;
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
    return `<section class="policy-entity-section"><header class="dwrt-kit-glass-surface"><div><h2>线路容量</h2><p>来自 <code>flowd/wan-capacity</code> 与 <code>flow-control</code>。</p></div></header>${content}${declared}</section>`;
  }

  function balanceDraft() {
    if (state.balanceDraft) return state.balanceDraft;
    const current = state.wanPolicy;
    state.balanceDraft = {
      mode: current?.mode || '',
      wanIds: Array.isArray(current?.wanIds) ? [...current.wanIds] : []
    };
    return state.balanceDraft;
  }

  function balanceDirty() {
    const draft = balanceDraft();
    const base = state.wanPolicy;
    if (!base) return false;
    return draft.mode !== base.mode || JSON.stringify(draft.wanIds) !== JSON.stringify(base.wanIds);
  }

  function balanceWritable() {
    return state.wanPolicy?.writeSupported === true
      && state.wanPolicy?.memberSelection === true
      && typeof api.request === 'function';
  }

  function balanceAlgorithmCardsMarkup() {
    const draft = balanceDraft();
    const modes = state.wanPolicy?.availableModes || [];
    if (!modes.length) return `<section class="policy-entity-section"><header class="dwrt-kit-glass-surface"><div><h2>分流模式</h2></div></header>${statePanel('empty', '没有可用模式', 'WAN 策略接口没有返回 available_modes。')}</section>`;
    /* 「当前选择」是草稿，「运行中」是后端回读的真实生效模式。改动未保存时两者会分开，
       只给一个徽章会让人以为改动已经生效。 */
    const runningMode = state.wanPolicy?.mode || '';
    const cards = modes.map((mode) => {
      const active = draft.mode === mode.id;
      const running = runningMode === mode.id;
      return `<button type="button" class="flow-balance-algorithm dwrt-kit-glass-surface ${active ? 'is-active' : ''} ${running ? 'is-running' : ''}" role="radio" aria-checked="${active ? 'true' : 'false'}" data-flow-balance-algorithm="${escapeHtml(mode.id)}" ${state.balanceSaving || !balanceWritable() ? 'disabled' : ''}>
        <span class="flow-balance-algorithm-head">
          <strong>${escapeHtml(mode.label)}</strong>
          <span class="flow-balance-algorithm-flags">${running ? statusBadge('运行中', 'success') : ''}${active && !running ? statusBadge('待保存', 'warning') : ''}</span>
        </span>
        <span class="flow-balance-algorithm-desc">${escapeHtml(mode.description)}</span>
        <code class="flow-balance-algorithm-value">${escapeHtml(mode.id)}</code>
      </button>`;
    }).join('');
    const fallback = state.wanPolicy?.fallbackMode && state.wanPolicy.fallbackMode !== runningMode
      ? `<p class="flow-balance-algorithm-fallback">线路不可用时回退到 <code>${escapeHtml(state.wanPolicy.fallbackMode)}</code>。</p>`
      : '';
    return `<section class="policy-entity-section">
      <header class="dwrt-kit-glass-surface"><div><h2>分流模式</h2><p>选项来自 <code>network/wan-policy.available_modes</code>；前端不维护独立算法目录。</p></div></header>
      <div class="flow-balance-algorithm-grid" role="radiogroup" aria-label="分流模式">${cards}</div>${fallback}
    </section>`;
  }

  function balanceMembersMarkup() {
    const wans = state.wanPolicy?.wans || [];
    if (!wans.length) {
      return `<section class="policy-entity-section"><header class="dwrt-kit-glass-surface"><div><h2>参与成员</h2></div></header>${statePanel('empty', '没有可用线路', 'WAN 策略接口没有返回任何线路。')}</section>`;
    }
    const draft = balanceDraft();
    const tiles = wans.map((wan) => {
      const on = draft.wanIds.includes(wan.id);
      const meta = [wan.carrier || '运营商未标注', wan.ifname].filter(Boolean).join(' · ');
      /* 后端每条 WAN 都带 latency / loss / down_rate / connections，
         原先只显示一个恒为 100 的权重，等于什么都没说。只渲染真实存在的字段，
         缺失的整项不出现，不用 0 冒充。 */
      const metrics = [
        Number.isFinite(wan.latencyMs) ? { label: '延迟', value: `${formatInteger(wan.latencyMs)} ms`, warn: wan.latencyMs >= 100 } : null,
        Number.isFinite(wan.lossPct) ? { label: '丢包', value: `${wan.lossPct}%`, warn: wan.lossPct > 0 } : null,
        Number.isFinite(wan.downRate) ? { label: '下行', value: formatRate(wan.downRate), warn: false } : null,
        Number.isFinite(wan.connections) ? { label: '', value: `${formatInteger(wan.connections)} 条连接`, warn: false } : null
      ].filter(Boolean);
      const metricsMarkup = metrics.length
        ? `<span class="flow-balance-member-metrics">${metrics.map((item) => `<span class="flow-balance-member-metric ${item.warn ? 'is-warn' : ''}">${item.label ? escapeHtml(item.label) : ''}<b>${escapeHtml(item.value)}</b></span>`).join('')}</span>`
        : '';
      return `<label class="flow-balance-member dwrt-kit-glass-surface ${on ? 'is-active' : ''} ${state.balanceSaving || !balanceWritable() ? 'is-disabled' : ''}">
        <input type="checkbox" data-flow-balance-member="${escapeHtml(wan.id)}" ${on ? 'checked' : ''} ${state.balanceSaving || !balanceWritable() ? 'disabled' : ''}>
        <span class="flow-balance-member-body">
          <span class="flow-balance-member-name">${escapeHtml(wan.name)}</span>
          <span class="flow-balance-member-meta">${escapeHtml(meta)}</span>
        </span>
        <span class="flow-balance-member-side">${statusBadge(wan.online ? '在线' : '离线', wan.online ? 'success' : 'warning')}</span>
        ${metricsMarkup}
      </label>`;
    }).join('');
    const insufficient = draft.wanIds.length < 2
      ? `<div class="policy-entity-alert is-warning" role="status"><strong>参与线路不足</strong><span>至少选择两条 WAN 线路才能保存多线负载策略。</span></div>`
      : '';
    /* demo 里有「unicom 1+3 / mobile 2+4」这类按运营商的分组快选，这里刻意不做。

       后端在同一响应里声明 `carrier_neutral: true`：分流对运营商中立，运营商不参与
       调度决策。按运营商预设成员会在界面上暗示一种后端并不存在的分组语义，
       所以只保留「全部线路」这个不引入新语义的快选。运营商仍在成员卡上展示。 */
    const allIds = wans.map((wan) => wan.id);
    const sameSelection = allIds.length === draft.wanIds.length && allIds.every((id) => draft.wanIds.includes(id));
    const presetButtons = `<button type="button" class="flow-balance-preset ${sameSelection ? 'is-active' : ''}" data-flow-balance-preset="${escapeHtml(allIds.join(','))}" ${state.balanceSaving || !balanceWritable() || wans.length < 2 ? 'disabled' : ''}>全部线路</button>`;
    return `<section class="policy-entity-section">
      <header class="dwrt-kit-glass-surface"><div><h2>参与成员</h2><p>勾选的线路接收新连接；运营商只作信息展示，不参与优先级、权重或分组。</p></div></header>
      ${insufficient}
      <div class="flow-balance-member-grid">${tiles}</div>
      <div class="flow-balance-presets"><span>成员操作</span>${presetButtons}</div>
    </section>`;
  }

  function smartPathMarkup() {
    const smart = state.wanPolicy?.smartPath;
    if (!smart) return '';
    const rows = [
      ['启用请求', smart.enabledRequested],
      ['调度器', smart.schedulerActive],
      ['nft 规则', smart.nftActive],
      ['nft 回读', smart.nftReadbackOk],
      ['整体状态', smart.active]
    ];
    const warning = smart.enabledRequested && !smart.active
      ? `<div class="policy-entity-alert is-warning" role="status"><strong>智能路径尚未完整生效</strong><span>${escapeHtml(smart.lastError || '调度器、nft 规则或回读状态至少有一项未就绪。')}</span></div>`
      : '';
    return `<section class="policy-entity-section"><header class="dwrt-kit-glass-surface"><div><h2>智能路径运行态</h2><p>这些状态来自后端实际回读，不由前端按数值推断。</p></div>${statusBadge(`${formatInteger(smart.wanPathCount)} 条路径`, 'muted')}</header>
      ${warning}<dl class="policy-entity-detail-list flow-engine-detail-list">${rows.map(([label, active]) => `<div><dt>${escapeHtml(label)}</dt><dd>${statusBadge(active ? '正常' : '未就绪', active ? 'success' : 'warning')}</dd></div>`).join('')}</dl>
    </section>`;
  }

  function balanceActionBarMarkup() {
    const draft = balanceDraft();
    const selected = state.wanPolicy?.availableModes.find((mode) => mode.id === draft.mode);
    const writable = balanceWritable();
    const dirty = balanceDirty();
    const blocked = state.balanceSaving || !writable || !dirty || draft.wanIds.length < 2 || !draft.mode;
    const hint = !writable
      ? '当前响应未开放模式或成员写入'
      : draft.wanIds.length < 2
        ? '至少选择两条线路'
        : dirty ? '有未保存的改动' : '与运行态回读一致';
    return `<div class="flow-balance-actionbar dwrt-kit-glass-surface">
      <div class="flow-balance-actionbar-text">
        <strong>${escapeHtml(selected?.label || draft.mode || '未选择模式')}</strong>
        <span>已选 ${formatInteger(draft.wanIds.length)} / ${formatInteger(state.wanPolicy?.wans.length || 0)} 条线路 · ${escapeHtml(hint)}；已有连接保持原出口</span>
      </div>
      <button type="button" class="policy-primary" data-flow-balance-save ${blocked ? 'disabled' : ''}>${state.balanceSaving ? '正在应用' : '保存并应用'}</button>
    </div>${state.balanceNotice ? `<div class="policy-entity-alert ${/失败|不一致|无权/.test(state.balanceNotice) ? 'is-warning' : ''}" role="status"><strong>${escapeHtml(state.balanceNotice)}</strong></div>` : ''}`;
  }

  function balanceMarkup() {
    if (!state.wanPolicy) return statePanel('loading', '正在读取多线负载', '等待 WAN 策略快照。');
    const contract = balanceWritable() ? '' : `<div class="policy-entity-alert is-warning" role="status"><strong>当前响应为只读</strong><span>WAN 策略已读取，但后端没有同时声明 write_supported 与 member_selection；页面不会模拟保存。</span></div>`;
    return `${contract}${balanceAlgorithmCardsMarkup()}${smartPathMarkup()}${balanceMembersMarkup()}${balanceActionBarMarkup()}`;
  }

  function geoipSource(id) {
    return (state.geoip?.sources || []).find((source) => source.id === id) || null;
  }

  function geoipDraft(id) {
    if (!state.geoipDrafts.has(id)) {
      const source = geoipSource(id);
      if (!source) return null;
      /* 旧后端没有这些列，回读会是 0。0 不是合法频率（下限 86400），
       * 直接塞进 select 会渲染成空选项，所以回落到默认档与后端默认时间窗。 */
      const interval = GEOIP_INTERVAL_CHOICES.some((choice) => choice.value === source.updateIntervalS)
        ? source.updateIntervalS
        : 604800;
      const hasWindow = source.windowStartH > 0 || source.windowEndH > 0;
      state.geoipDrafts.set(id, {
        updateEnabled: source.updateEnabled,
        updateIntervalS: interval,
        windowStartH: hasWindow ? source.windowStartH : 3,
        windowEndH: hasWindow ? source.windowEndH : 5
      });
    }
    return state.geoipDrafts.get(id);
  }

  function geoipDraftDirty(id) {
    const source = geoipSource(id);
    const draft = state.geoipDrafts.get(id);
    if (!source || !draft) return false;
    /* 开关是唯一在旧后端也有对应列的字段（update_enabled 缺列时回读为 false）。
     * 频率与时间窗在旧后端回读为 0，草稿用的是回落默认值，两者不等并不代表用户改过；
     * 只有开关已开时，频率与时间窗的差异才是真实的待保存改动。 */
    if (draft.updateEnabled !== source.updateEnabled) return true;
    if (!draft.updateEnabled) return false;
    return Number(draft.updateIntervalS) !== source.updateIntervalS
      || Number(draft.windowStartH) !== source.windowStartH
      || Number(draft.windowEndH) !== source.windowEndH;
  }

  /* GeoIP 源写入走 flowd 配置库，与规则下发无关，因此不要求 apply 链就绪；
   * 但仍受 flowd 配置写 capability 约束，capability 未声明就保持只读。 */
  function geoipWritable() {
    return capabilities.flow_engine_config_write === true;
  }

  function geoipIntervalLabel(seconds) {
    const choice = GEOIP_INTERVAL_CHOICES.find((item) => item.value === Number(seconds));
    if (choice) return choice.label;
    if (!Number.isFinite(Number(seconds)) || Number(seconds) <= 0) return '--';
    return `每 ${formatDuration(Number(seconds))}`;
  }

  function geoipStatusTone(source) {
    if (!source.pathPresent) return { label: '未安装', tone: 'warning' };
    /* last_import_status 只在真正换库或换库失败时被写；unchanged 不经过它，
     * 所以这里不需要再排除 unchanged。 */
    if (source.lastImportStatus === 'failed') return { label: '已安装（上次更新失败）', tone: 'warning' };
    const parsed = parseGeoipLastError(source.lastError);
    if (parsed?.failed) return { label: '已安装（上次检查失败）', tone: 'warning' };
    return { label: '已安装', tone: 'success' };
  }

  /* last_error 的第一个 token 是稳定 code（见 parseGeoipLastError 的出处注释），
   * 按 code 给人类可读标题，冒号后的细节放在同一条里作为补充。 */
  function geoipErrorText(source) {
    const parsed = parseGeoipLastError(source.lastError);
    if (!parsed) return '';
    return parsed.detail ? `${parsed.label}（${parsed.detail}）` : parsed.label;
  }

  /* next_run_at 到点后后端最多还要一个 15 分钟扫描周期才动手，
   * 所以到点只能说「等待后端扫描」，不能说「正在更新」。 */
  function geoipNextRunText(source) {
    if (!source.updateEnabled) return '未启用自动更新';
    if (!source.nextRunAt) return '未排期';
    const nowS = Math.floor(Date.now() / 1000);
    const stamp = formatTimestamp(source.nextRunAt);
    if (source.nextRunAt > nowS) return stamp;
    return `${stamp}（已到期，等待后端扫描，最多 ${Math.round(GEOIP_SCHEDULE_TICK_S / 60)} 分钟）`;
  }

  function geoipSourceCardMarkup(source) {
    const draft = geoipDraft(source.id) || {};
    const status = geoipStatusTone(source);
    const busy = state.geoipSavingId === source.id || state.geoipImportingId === source.id;
    const disabled = !geoipWritable() || busy ? 'disabled' : '';
    const dirty = geoipDraftDirty(source.id);
    const notice = state.geoipNotices.get(source.id) || '';
    const parsedError = parseGeoipLastError(source.lastError);
    const failing = source.consecutiveFailures > 0;
    const hourOptions = (selected) => Array.from({ length: 24 }, (_, hour) => `<option value="${hour}" ${Number(selected) === hour ? 'selected' : ''}>${String(hour).padStart(2, '0')}:00</option>`).join('');
    const rows = [
      ['库文件', source.path || '--'],
      ['版本标识', source.remoteEtag || source.remoteLastModified || '--'],
      ['下次计划更新', geoipNextRunText(source)],
      ['上次检查', formatTimestamp(source.lastCheckAt)],
      /* 契约第 4 节问题 5：检查成功与实际换库是两个时间，混在一起会让
       * 「上游无更新」看起来像刚更新过库，所以分两行。 */
      ['上次成功检查', formatTimestamp(source.lastSuccessAt)],
      ['上次更新到新版本', formatTimestamp(source.lastImportAt)]
    ];
    return `<article class="flow-geoip-source dwrt-kit-glass-surface">
      <header class="flow-geoip-source-head">
        <div>
          <h3>${escapeHtml(source.name)}</h3>
          <p>${escapeHtml(source.edition || '未声明版本')} · ${escapeHtml(source.type || '未声明类型')}</p>
        </div>
        ${statusBadge(status.label, status.tone)}
      </header>
      <dl class="flow-geoip-facts">
        ${rows.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(String(value))}</dd></div>`).join('')}
      </dl>
      ${source.remoteCapable ? `<div class="flow-geoip-controls">
        <label class="flow-geoip-switch-row">
          <span><strong>自动更新</strong><small>GeoLite2 上游每周重建，按周或按月即可；开启后由后端在时间窗内执行。</small></span>
          <span class="dwrt-kit-switch" data-dwrt-component="switch"><input type="checkbox" data-geoip-field="updateEnabled" data-geoip-id="${escapeHtml(source.id)}" ${draft.updateEnabled ? 'checked' : ''} ${disabled} aria-label="自动更新"><span aria-hidden="true"></span></span>
        </label>
        <div class="flow-geoip-form-grid">
          <label class="dwrt-kit-field" data-dwrt-component="field">
            <span data-dwrt-field-label>更新频率</span>
            <select class="dwrt-kit-select" data-dwrt-component="select" data-geoip-field="updateIntervalS" data-geoip-id="${escapeHtml(source.id)}" ${disabled || (draft.updateEnabled ? '' : 'disabled')}>
              ${GEOIP_INTERVAL_CHOICES.map((choice) => `<option value="${choice.value}" ${Number(draft.updateIntervalS) === choice.value ? 'selected' : ''}>${escapeHtml(choice.label)}</option>`).join('')}
            </select>
          </label>
          <label class="dwrt-kit-field" data-dwrt-component="field">
            <span data-dwrt-field-label>时间窗开始</span>
            <select class="dwrt-kit-select" data-dwrt-component="select" data-geoip-field="windowStartH" data-geoip-id="${escapeHtml(source.id)}" ${disabled || (draft.updateEnabled ? '' : 'disabled')}>${hourOptions(draft.windowStartH)}</select>
          </label>
          <label class="dwrt-kit-field" data-dwrt-component="field">
            <span data-dwrt-field-label>时间窗结束</span>
            <select class="dwrt-kit-select" data-dwrt-component="select" data-geoip-field="windowEndH" data-geoip-id="${escapeHtml(source.id)}" ${disabled || (draft.updateEnabled ? '' : 'disabled')}>${hourOptions(draft.windowEndH)}</select>
          </label>
        </div>
      </div>` : `<p class="flow-geoip-note">这个源没有配置远端地址，只能由本地文件提供，不参与自动更新。</p>`}
      ${/* 开启自动更新等于同意周期性下载整包；按流量计费的线路要提前知道量级。
          * City 版本约 66 MB，Country 版本小得多，所以按 edition 区分措辞。 */ ''}
      ${source.remoteCapable && draft.updateEnabled ? `<p class="flow-geoip-note">已开启自动更新：后端会按上述频率在时间窗内下载整包。${escapeHtml(/city/i.test(source.edition || source.id) ? 'City 库约 66 MB' : '库文件通常为数 MB 到数十 MB')}，按流量计费的线路请注意；上游版本未变化时会跳过下载，不产生流量。</p>` : ''}
      ${failing ? `<div class="policy-entity-alert is-warning" role="status"><strong>连续失败 ${formatInteger(source.consecutiveFailures)} 次</strong><span>${escapeHtml(geoipErrorText(source) || '后端未给出失败原因。')}</span></div>`
        /* unchanged 是成功态（flowd_db.c:2013 把它写进 last_error），
         * 按失败渲染会让「已是最新」显示成红字，所以按 failed 分流。 */
        : parsedError?.failed ? `<div class="policy-entity-alert is-warning" role="status"><strong>最近一次更新失败</strong><span>${escapeHtml(geoipErrorText(source))}</span></div>`
        : parsedError ? `<div class="policy-entity-alert" role="status"><strong>上次检查：已是最新</strong><span>上游版本未变化，未重新下载。</span></div>` : ''}
      ${notice ? `<div class="policy-entity-alert ${/失败|无权|不一致/.test(notice) ? 'is-warning' : ''}" role="status"><strong>${escapeHtml(notice)}</strong></div>` : ''}
      <footer class="flow-geoip-source-foot">
        <span class="flow-geoip-foot-hint">${escapeHtml(source.remoteCapable
          ? (source.updateEnabled ? `当前：${geoipIntervalLabel(source.updateIntervalS)} · ${String(source.windowStartH).padStart(2, '0')}:00-${String(source.windowEndH).padStart(2, '0')}:00` : '当前：未启用自动更新')
          : '当前：仅本地文件')}</span>
        ${/* 没有远端地址的源没有任何可提交字段，放按钮等于给一个点了没反应的控件。 */ ''}
        ${source.remoteCapable ? `<div class="flow-geoip-foot-actions">
          <button type="button" data-dwrt-component="button" data-variant="secondary" data-geoip-import="${escapeHtml(source.id)}" ${disabled}>${icon('download')}<span>${state.geoipImportingId === source.id ? '正在下载' : '立即检查更新'}</span></button>
          <button type="button" class="policy-primary" data-geoip-save="${escapeHtml(source.id)}" ${disabled || (dirty ? '' : 'disabled')}>${state.geoipSavingId === source.id ? '正在保存' : '保存设置'}</button>
        </div>` : ''}
      </footer>
    </article>`;
  }

  function geoipMarkup() {
    if (!state.geoip) return statePanel('loading', '正在读取 GeoIP 数据源', '等待源列表快照。');
    if (!state.geoip.ok) {
      return statePanel('error', '无法读取 GeoIP 数据源', state.geoip.error === 'geoip_sources_unavailable'
        ? '后端报告源表不可用，通常是 flowd 配置库未就绪。'
        : state.geoip.error || '后端没有返回可用的源列表。');
    }
    const contract = geoipWritable() ? '' : `<div class="policy-entity-alert is-warning" role="status"><strong>当前为只读</strong><span>后端没有声明 flow_engine_config_write，页面不会模拟保存。</span></div>`;
    const sources = state.geoip.sources;
    const body = sources.length
      ? sources.map((source) => geoipSourceCardMarkup(source)).join('')
      : statePanel('empty', '暂无 GeoIP 数据源', '后端源表为空，还没有任何 GeoIP 库登记在管理内。');
    const missing = sources.filter((source) => !source.pathPresent);
    const missingNote = missing.length
      ? `<div class="policy-entity-alert" role="status"><strong>${formatInteger(missing.length)} 个源尚未安装库文件</strong><span>${escapeHtml(missing.map((source) => source.name).join('、'))}。可以用「立即检查更新」下载；City 库约 66 MB，按流量计费的线路请注意。</span></div>`
      : '';
    return `<section class="policy-entity-section flow-geoip-section">
      <header class="dwrt-kit-glass-surface"><div><h2>GeoIP 数据源</h2><p>定时升级由后端在时间窗内执行，这里只设置策略。</p></div>${statusBadge(`${formatInteger(sources.length)} 个源`, 'muted')}</header>
      ${contract}${missingNote}
      <div class="flow-geoip-grid">${body}</div>
    </section>`;
  }

  function tabContentMarkup() {
    /* 智能流控已独立成 Tab，QoS Tab 不再重复渲染同一份优先级（避免两处真相）。 */
    if (state.tab === 'qos') return `${qosConflictMarkup()}${qosSettingsMarkup()}${qosClassesMarkup()}`;
    if (state.tab === 'smart') return smartMarkup();
    if (state.tab === 'capacity') return `${wanHealthMarkup()}${wanCapacityMarkup()}`;
    if (state.tab === 'balance') return balanceMarkup();
    if (state.tab === 'geoip') return geoipMarkup();
    return `${summaryMarkup()}${engineDetailMarkup()}${nftRevisionMarkup()}${countersMarkup()}${applyJobsMarkup()}`;
  }

  const SNAPSHOT_LABELS = {
    status: '引擎状态', runtime: '运行时', settings: '引擎设置', qosSettings: 'QoS 设置',
    qosClasses: 'QoS 分类', applyJobs: '下发任务', wanCapacity: 'WAN 容量',
    wanHealth: 'WAN 健康', smart: '智能限速', nftRevision: 'nft 版本',
    wanPolicy: 'WAN 策略', geoipSources: 'GeoIP 源'
  };

  /*
   * 判 snapshot.error，而不是 snapshot.stale。
   *
   * registry 在真正 fetch 之前就按龄期置 `stale`（dwrt-data-registry.js 的
   * request()：`entry.stale = hasValue && age > ttlMs`），与请求成败无关，所以
   * 后端全程 200 时刷新窗口里也会亮起「刷新失败」。status === 'stale' 同样不行：
   * 中断（换页、卸载）也是 stale，但 error 为 null，那是正常取消。
   */
  function refreshFailureMarkup(entries) {
    const failed = entries
      .filter(([, snapshot]) => snapshot?.error)
      .map(([slot]) => SNAPSHOT_LABELS[slot] || slot);
    if (!failed.length) return '';
    return `<div class="policy-entity-alert is-warning" role="status"><strong>正在显示上次可用快照</strong><span>${escapeHtml(failed.join('、'))}刷新失败，页面仍保留最后一次成功数据。</span></div>`;
  }

  function workbenchMarkup() {
    const entries = state.tab === 'balance' ? [['wanPolicy', state.snapshots.wanPolicy]]
      : state.tab === 'geoip' ? [['geoipSources', state.snapshots.geoipSources]]
      : state.tab === 'smart' ? [['smart', state.snapshots.smart]]
      : Object.entries(state.snapshots);
    const stale = refreshFailureMarkup(entries);
    /* 智能流控本阶段一律只读：后端写入权威源未定，所以不看 capability，直接标只读，
     * 免得徽章写着「写入可用」而页面里没有任何可提交控件。 */
    const writable = state.tab === 'smart' ? false
      : state.tab === 'balance' ? balanceWritable()
      : state.tab === 'geoip' ? geoipWritable()
      : canWrite();
    /* GeoIP 源写的是配置库，plan-only 与 apply 链状态跟它无关，那条降级横幅不适用。 */
    /* 智能流控自带一条取 flow-control 真值的生效说明，再叠一条引擎降级横幅就是两处同义警告。 */
    const degraded = ['balance', 'geoip', 'smart'].includes(state.tab) ? '' : degradedBannerMarkup();
    return `<section class="flow-engine-page">
      <div class="flow-engine-page-toolbar">${tabsMarkup()}<div class="flow-engine-toolbar-actions">${statusBadge(writable ? '写入可用' : '只读', writable ? 'success' : 'warning')}</div></div>
      <main class="flow-engine-workbench">${degraded}${stale}<div class="flow-engine-tab-content">${tabContentMarkup()}</div></main>
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

  async function saveBalance() {
    if (state.balanceSaving || !balanceWritable() || !balanceDirty()) return;
    const draft = balanceDraft();
    const modeIds = new Set((state.wanPolicy?.availableModes || []).map((mode) => mode.id));
    const wanIds = [...new Set(draft.wanIds.map(Number).filter((id) => Number.isInteger(id) && id > 0))].sort((a, b) => a - b);
    if (!modeIds.has(draft.mode)) {
      state.balanceNotice = '保存失败：所选模式不在后端 available_modes 中';
      renderPage();
      return;
    }
    if (wanIds.length < 2) {
      state.balanceNotice = '保存失败：至少选择两条 WAN 线路';
      renderPage();
      return;
    }
    state.balanceSaving = true;
    state.balanceNotice = '';
    renderPage();
    try {
      await api.request('wan-policy-save', '/api/v1/network/wan-policy', {
        method: 'PUT',
        body: { mode: draft.mode, wan_ids: wanIds }
      });
      let readbackPayload = null;
      let readback = null;
      for (let attempt = 0; attempt < 8; attempt += 1) {
        if (attempt > 0) await new Promise((resolve) => window.setTimeout(resolve, 500));
        readbackPayload = await api.request('wan-policy-readback', '/api/v1/network/wan-policy');
        readback = normalizeWanPolicy(readbackPayload);
        if (readback.mode === draft.mode && JSON.stringify(readback.wanIds) === JSON.stringify(wanIds)) break;
      }
      if (!readback || readback.mode !== draft.mode || JSON.stringify(readback.wanIds) !== JSON.stringify(wanIds)) {
        throw new Error('保存已提交，但运行态回读与所选模式或成员不一致');
      }
      state.wanPolicy = readback;
      state.balanceDraft = { mode: readback.mode, wanIds: [...readback.wanIds] };
      state.balanceSaving = false;
      state.balanceNotice = '策略已应用；已有连接保持原出口';
      registry?.patch?.('network.wanPolicy', readbackPayload);
      renderPage();
    } catch (error) {
      state.balanceSaving = false;
      const status = Number(error?.status) || 0;
      state.balanceNotice = status === 403
        ? '保存失败：当前账号没有修改 WAN 策略的权限'
        : `保存失败：${error?.message || '未知错误'}`;
      renderPage();
    }
  }

  function geoipFailureText(error, prefix) {
    const status = Number(error?.status) || 0;
    const code = String(error?.code || error?.data?.error || '');
    if (status === 403) return `${prefix}：当前账号没有修改 GeoIP 源的权限`;
    if (status === 401) return `${prefix}：会话已失效，请重新登录`;
    if ([404, 405, 501].includes(status) || code === 'method_not_registered') return `${prefix}：后端尚未接入该接口`;
    if (status >= 500) return `${prefix}：后端错误（HTTP ${status}）`;
    if (!status && !code) return `${prefix}：网络不可用`;
    return `${prefix}：${error?.message || code || '未知错误'}`;
  }

  async function refreshGeoip() {
    if (!registry) return null;
    const payload = await registry.request('flow.geoipSources', { force: true, signal });
    if (!state.mounted) return null;
    state.geoip = normalizeFlowGeoipSources(payload);
    return state.geoip;
  }

  async function saveGeoipSource(id) {
    if (state.geoipSavingId || state.geoipImportingId || !geoipWritable()) return;
    const source = geoipSource(id);
    const draft = state.geoipDrafts.get(id);
    if (!source || !draft || !geoipDraftDirty(id)) return;
    const interval = Number(draft.updateIntervalS);
    if (!Number.isFinite(interval) || interval < GEOIP_UPDATE_INTERVAL_MIN_S || interval > GEOIP_UPDATE_INTERVAL_MAX_S) {
      state.geoipNotices.set(id, '保存失败：更新频率超出后端允许区间');
      renderPage();
      return;
    }
    state.geoipSavingId = id;
    state.geoipNotices.delete(id);
    renderPage();
    try {
      /* 后端 save_one 会先读回现有行再合并（flowd_db.c 的 load_existing），
       * 所以只提交 id 与本表单负责的字段，不回传 path/meta 之类不属于本界面的内容。 */
      await api.request('geoip-source-save', '/api/v1/flowd/geoip/sources', {
        method: 'PUT',
        body: {
          id,
          update_enabled: draft.updateEnabled === true,
          update_interval_s: interval,
          update_window_start_h: Number(draft.windowStartH),
          update_window_end_h: Number(draft.windowEndH)
        }
      });
      const readback = await refreshGeoip();
      if (!state.mounted) return;
      const saved = readback?.sources.find((item) => item.id === id) || null;
      state.geoipSavingId = '';
      if (!saved) {
        state.geoipNotices.set(id, '保存已提交，但回读时源已不在列表中');
      } else if (saved.updateEnabled !== (draft.updateEnabled === true)
        || saved.updateIntervalS !== interval
        || saved.windowStartH !== Number(draft.windowStartH)
        || saved.windowEndH !== Number(draft.windowEndH)) {
        state.geoipNotices.set(id, '保存已提交，但回读值与提交值不一致，后端可能拒绝了部分字段');
      } else {
        state.geoipDrafts.delete(id);
        state.geoipNotices.set(id, saved.updateEnabled
          ? `已保存；下次计划更新 ${formatTimestamp(saved.nextRunAt)}`
          : '已保存；自动更新保持关闭');
      }
      renderPage();
    } catch (error) {
      state.geoipSavingId = '';
      state.geoipNotices.set(id, geoipFailureText(error, '保存失败'));
      renderPage();
    }
  }

  async function importGeoipSource(id) {
    if (state.geoipImportingId || state.geoipSavingId || !geoipWritable()) return;
    const source = geoipSource(id);
    if (!source || !source.remoteCapable) return;
    state.geoipImportingId = id;
    /* geoip_update_check 是同步阻塞的：HEAD 探测 +（必要时）整个下载都在请求内完成，
     * 后端 curl 超时上限 300 秒，且没有可轮询的中间态字段。所以这里只能用不确定态
     * 文案，不假造进度百分比；防重复提交靠 geoipImportingId 禁用按钮。 */
    state.geoipNotices.set(id, '正在检查上游版本，如有新版本会直接下载；City 库约 66 MB，可能需要几分钟，完成前请勿离开本页');
    renderPage();
    try {
      /* force:false 让后端用 ETag 比对跳过整包下载（flowd_db.c:2008 那段），
       * 这才是「检查更新」；无条件重下留给将来的次要入口。 */
      /* 关于超时：api.request（menu-shell.js:3137-3153）在展开 init 之后硬写
       * signal: routeController.signal，所以模块侧传入的 signal 会被覆盖,这里不能
       * 自己叠加 AbortController，否则是个不起作用的假超时。好在 api.request 本身
       * 不设任何超时，只在离开路由时取消，因此后端占满 300 秒也不会被前端提前掐断，
       * 满足「fetch 超时 >= 300 秒」。若将来要一个客户端硬上限，需要改共享外壳，
       * 见 todo 里的 HandoffWorker-to-Front-api-request-ignores-module-signal 单。 */
      const payload = await api.request('geoip-update-check', '/api/v1/flowd/geoip/update/check', {
        method: 'POST',
        body: { id, force: false }
      });
      const data = payload && typeof payload.data === 'object' && payload.data !== null ? payload.data : payload;
      await refreshGeoip();
      if (!state.mounted) return;
      state.geoipImportingId = '';
      /* 三态互不混淆（契约第 4 节问题 5）：
       *   installed  真的下载并换库了
       *   unchanged  上游无更新，已是最新,这也是成功
       *   其余       失败 */
      if (data?.installed === true) {
        state.geoipNotices.set(id, '已更新到新版本，库文件已就位');
      } else if (data?.unchanged === true) {
        state.geoipNotices.set(id, '已检查：上游无更新，当前库已是最新');
      } else {
        const parsed = parseGeoipLastError(data?.error);
        const reason = parsed
          ? (parsed.detail ? `${parsed.label}（${parsed.detail}）` : parsed.label)
          : String(data?.message || '').trim();
        state.geoipNotices.set(id, `检查失败：${reason || '后端未给出原因'}`);
      }
      renderPage();
    } catch (error) {
      state.geoipImportingId = '';
      /* 失败也要把源状态重新读回来，last_error 由后端在失败时写入。 */
      await refreshGeoip().catch(() => {});
      if (!state.mounted) return;
      state.geoipNotices.set(id, geoipFailureText(error, '检查失败'));
      renderPage();
    }
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

    const geoipSave = event.target.closest?.('[data-geoip-save]');
    if (geoipSave) {
      saveGeoipSource(geoipSave.getAttribute('data-geoip-save'));
      return;
    }

    const geoipImport = event.target.closest?.('[data-geoip-import]');
    if (geoipImport) {
      importGeoipSource(geoipImport.getAttribute('data-geoip-import'));
      return;
    }

    const algorithm = event.target.closest?.('[data-flow-balance-algorithm]');
    if (algorithm) {
      const next = algorithm.getAttribute('data-flow-balance-algorithm');
      if (next && state.wanPolicy?.availableModes.some((item) => item.id === next)) {
        balanceDraft().mode = next;
        state.balanceNotice = '';
        renderPage();
      }
      return;
    }

    const preset = event.target.closest?.('[data-flow-balance-preset]');
    if (preset) {
      const ids = String(preset.getAttribute('data-flow-balance-preset') || '').split(',').map(Number);
      const known = new Set((state.wanPolicy?.wans || []).map((wan) => wan.id));
      balanceDraft().wanIds = [...new Set(ids.filter((id) => known.has(id)))].sort((a, b) => a - b);
      state.balanceNotice = '';
      renderPage();
      return;
    }

    if (event.target.closest?.('[data-flow-balance-save]')) {
      saveBalance();
      return;
    }
  }

  function onChange(event) {
    const geoipField = event.target.closest?.('[data-geoip-field]');
    if (geoipField) {
      const id = geoipField.getAttribute('data-geoip-id');
      const field = geoipField.getAttribute('data-geoip-field');
      const draft = geoipDraft(id);
      if (!draft) return;
      if (field === 'updateEnabled') draft.updateEnabled = geoipField.checked === true;
      else if (field === 'updateIntervalS') draft.updateIntervalS = Number(geoipField.value);
      else if (field === 'windowStartH') draft.windowStartH = Number(geoipField.value);
      else if (field === 'windowEndH') draft.windowEndH = Number(geoipField.value);
      state.geoipNotices.delete(id);
      renderPage();
      return;
    }

    const member = event.target.closest?.('[data-flow-balance-member]');
    if (!member) return;
    const id = Number(member.getAttribute('data-flow-balance-member'));
    if (!Number.isInteger(id) || id <= 0) return;
    const draft = balanceDraft();
    const chosen = new Set(draft.wanIds);
    if (member.checked) chosen.add(id); else chosen.delete(id);
    draft.wanIds = (state.wanPolicy?.wans || []).map((wan) => wan.id).filter((wanId) => chosen.has(wanId)).sort((a, b) => a - b);
    state.balanceNotice = '';
    renderPage();
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
  root.addEventListener('change', onChange);
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
    /* 同步导入可能持续几分钟，期间不要让周期刷新插进来重绘掉进度提示与草稿。 */
    if (state.geoipImportingId || state.geoipSavingId) return;
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
      root.removeEventListener('change', onChange);
      window.DWRT_UI_KIT?.unmount?.(root);
      root.replaceChildren();
      root.classList.remove('route-workspace', 'flow-engine-route-host');
      stage?.classList.remove('is-flow-engine');
    }
  };
}

export default { mount };
