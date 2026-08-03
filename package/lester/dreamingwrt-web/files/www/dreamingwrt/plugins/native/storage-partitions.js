const VERSION = '20260802-sheet-portal-scope-01';
const PARTITION_ENDPOINT = '/api/v1/storage/partitions';
const OVERVIEW_ENDPOINT = '/api/v1/storage/overview?range=1h';
const MOUNTS_ENDPOINT = '/api/v1/system/mounts';
const DISCOVERY_ENDPOINT = '/api/v1/system/mounts/discovery';

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  if (!(root instanceof HTMLElement) || context.signal?.aborted) return { unmount() {} };

  const api = context.api || {};
  const ui = context.ui || window.DWRT_UI_KIT || {};
  const utils = context.utils || {};
  const stage = root.closest('.console-stage');
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const formatBytes = utils.formatBytes || fallbackFormatBytes;
  const state = {
    mounted: true,
    loading: true,
    refreshing: false,
    loaded: false,
    error: '',
    notice: '',
    noticeTone: 'info',
    source: 'fallback',
    disks: [],
    selectedDiskId: '',
    capabilities: emptyCapabilities(),
    sheet: '',
    selectedPartitionId: '',
    editor: emptyEditor(),
    confirmation: null,
    working: false,
    seq: 0,
    pollTimer: 0
  };

  function emptyCapabilities() {
    return {
      inventory: false,
      transactionPreview: false,
      transactionCommit: false,
      create: false,
      delete: false,
      format: false,
      mount: false,
      unmount: false,
      resize: false
    };
  }

  function emptyEditor() {
    return { size: '', unit: 'GiB', filesystem: 'ext4', label: '', mountPoint: '', mountOptions: 'defaults' };
  }

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }

  function finite(...values) {
    for (const value of values) {
      if (value === '' || value === undefined || value === null) continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return null;
  }

  function bool(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') return !['0', 'false', 'off', 'no', 'disabled'].includes(value.toLowerCase());
    return Boolean(value);
  }

  function asArray(value, keys = []) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of [...keys, 'items', 'rows', 'list', 'data']) if (Array.isArray(value[key])) return value[key];
    return [];
  }

  function normalizeCodeFailure(json) {
    const code = Number(json?.code);
    if (!Number.isFinite(code)) return false;
    return code !== 2000 && !(code >= 200 && code < 300);
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
    return {
      Accept: 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}),
      ...extra
    };
  }

  async function request(url, options = {}) {
    const response = await sessionFetch(`${url}${url.includes('?') ? '&' : '?'}v=${encodeURIComponent(VERSION)}`, {
      credentials: 'same-origin',
      cache: 'no-store',
      signal: context.signal,
      ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const json = await response.json().catch(() => ({}));
    const payload = json?.data ?? json?.body ?? json;
    if (!response.ok || json?.ok === false || payload?.ok === false || normalizeCodeFailure(json) || normalizeCodeFailure(payload)) {
      const error = new Error(firstText(payload?.error?.message, payload?.error, payload?.message, json?.error?.message, json?.error, json?.message, `HTTP ${response.status}`));
      error.status = response.status;
      error.payload = json;
      throw error;
    }
    return payload || {};
  }

  function explicitCapability(source, names) {
    return names.some((name) => source?.[name] === true || source?.[name] === 1 || source?.[name] === 'true');
  }

  function normalizeCapabilities(payload = {}) {
    const caps = payload.capabilities || {};
    return {
      inventory: true,
      transactionPreview: explicitCapability(caps, ['transaction_preview', 'partition_transaction_preview', 'preview']),
      transactionCommit: explicitCapability(caps, ['transaction_commit', 'partition_transaction_commit', 'commit']),
      create: explicitCapability(caps, ['partition_create', 'create']),
      delete: explicitCapability(caps, ['partition_delete', 'delete']),
      format: explicitCapability(caps, ['partition_format', 'format']),
      mount: explicitCapability(caps, ['partition_mount', 'mount']),
      unmount: explicitCapability(caps, ['partition_unmount', 'unmount']),
      resize: explicitCapability(caps, ['partition_resize', 'resize'])
    };
  }

  function normalizeMount(item = {}) {
    return {
      id: firstText(item.id),
      device: firstText(item.device, item.source).replace(/\[.*$/, ''),
      target: firstText(item.mount, item.target, item.path),
      filesystem: firstText(item.fstype, item.filesystem_type, item.filesystem, item.fs),
      totalBytes: finite(item.size_bytes, item.total_bytes, item.size),
      usedBytes: finite(item.used_bytes, item.used),
      availableBytes: finite(item.available_bytes, item.free_bytes, item.available),
      usedPercent: finite(item.used_percent, item.percent),
      mounted: firstText(item.status) === 'mounted' || Boolean(firstText(item.mount, item.target)),
      configured: bool(item.configured),
      editable: bool(item.editable),
      bind: bool(item.bind_mount)
    };
  }

  function matchingMounts(partition, mounts) {
    const device = firstText(partition.device, partition.path);
    const embeddedPaths = asArray(partition.mounts).map((item) => firstText(item.path, item.mount, item.target)).filter(Boolean);
    return mounts.filter((mount) => !mount.bind && ((device && mount.device === device) || embeddedPaths.includes(mount.target)));
  }

  function normalizePartition(item = {}, index, disk, mounts, discovery) {
    const name = firstText(item.name, item.id, item.partition, item.device?.split('/').pop(), `partition-${index + 1}`);
    const device = firstText(item.device, item.path, name.startsWith('/') ? name : disk.device ? `${disk.device}${/\d$/.test(disk.device) ? 'p' : ''}${name.replace(/^\D+/, '')}` : name);
    const discovered = discovery.find((entry) => firstText(entry.devnode, entry.device) === device || firstText(entry.name) === name) || {};
    const relatedMounts = matchingMounts({ ...item, device }, mounts);
    const primaryMount = relatedMounts[0] || {};
    const embeddedMount = asArray(item.mounts)[0] || {};
    const filesystem = firstText(item.filesystem, item.fstype, item.fs, discovered.fstype, primaryMount.filesystem);
    const mountPoints = [...new Set([
      ...relatedMounts.map((mount) => mount.target),
      ...asArray(item.mounts).map((mount) => firstText(mount.path, mount.mount, mount.target)),
      firstText(item.mount_point, item.mountpoint)
    ].filter(Boolean))];
    const capacityBytes = finite(item.capacity_bytes, item.size_bytes, item.size, primaryMount.totalBytes, embeddedMount.total_bytes);
    const usedBytes = finite(item.used_bytes, item.used, primaryMount.usedBytes, embeddedMount.used_bytes);
    const availableBytes = finite(item.available_bytes, item.free_bytes, item.available, primaryMount.availableBytes, embeddedMount.available_bytes);
    const usedPercent = finite(item.used_percent, item.usage_percent, primaryMount.usedPercent, capacityBytes && usedBytes !== null ? usedBytes / capacityBytes * 100 : null);
    const system = bool(item.system, bool(item.system_partition, bool(discovered.system_disk)));
    const mounted = mountPoints.length > 0 || bool(item.mounted);
    const protectedPartition = system || mountPoints.some((path) => path === '/' || path === '/boot' || path === '/data');
    return {
      id: firstText(item.stable_id, item.uuid, item.id, device, name),
      name,
      device,
      type: firstText(item.partition_type, item.type, item.kind),
      filesystem,
      label: firstText(item.label, item.partlabel, discovered.label, discovered.partlabel),
      uuid: firstText(item.uuid, discovered.uuid),
      capacityBytes,
      usedBytes,
      availableBytes,
      usedPercent,
      startSector: finite(item.start_sector, item.start),
      endSector: finite(item.end_sector, item.end),
      mountPoints,
      mountId: firstText(primaryMount.id),
      mounted,
      system,
      protected: protectedPartition,
      readOnly: bool(item.read_only, bool(item.ro)),
      capabilities: item.capabilities && typeof item.capabilities === 'object' ? item.capabilities : {}
    };
  }

  function normalizeDisk(item = {}, index, mounts = [], discovery = []) {
    const name = firstText(item.name, item.device?.split('/').pop(), item.path?.split('/').pop(), `disk-${index + 1}`);
    const device = firstText(item.device, item.path, name.startsWith('/') ? name : `/dev/${name}`);
    const discovered = discovery.find((entry) => firstText(entry.devnode, entry.device) === device || firstText(entry.name) === name) || {};
    const disk = {
      id: firstText(item.stable_id, item.id, item.wwid, item.serial, device, name),
      name,
      device,
      model: firstText(item.model, item.label, item.product),
      serial: firstText(item.serial, item.serial_number),
      transport: firstText(item.transport, item.tran, item.bus),
      table: firstText(item.partition_table, item.pttype, item.table),
      totalBytes: finite(item.total_bytes, item.capacity_bytes, item.size_bytes, item.size),
      sectorSize: finite(item.sector_size, item.logical_sector_size),
      physicalSectorSize: finite(item.physical_sector_size),
      smartStatus: firstText(item.smart_status, item.health),
      system: bool(item.system, bool(item.system_disk, bool(discovered.system_disk))),
      removable: bool(item.removable, bool(item.rm)),
      partitions: []
    };
    disk.partitions = asArray(item.partitions, ['volumes']).map((partition, partitionIndex) => normalizePartition(partition, partitionIndex, disk, mounts, discovery));
    disk.unallocatedBytes = finite(item.unallocated_bytes, item.free_unallocated_bytes, item.unallocated);
    disk.maxPartitions = finite(item.max_partitions, item.partition_limit);
    return disk;
  }

  function mergePartitionPayload(partitionPayload = {}, overviewPayload = {}, mountsPayload = {}, discoveryPayload = {}) {
    const mounts = asArray(mountsPayload.mounted_filesystems || mountsPayload.points).map(normalizeMount);
    const discovery = asArray(discoveryPayload.items || discoveryPayload.devices);
    const source = partitionPayload.storage && typeof partitionPayload.storage === 'object' ? partitionPayload.storage : partitionPayload;
    const fallback = overviewPayload.storage && typeof overviewPayload.storage === 'object' ? overviewPayload.storage : overviewPayload;
    const sourceDisks = asArray(source.disks, ['devices', 'block_devices']);
    const fallbackDisks = asArray(fallback.disks, ['devices']);
    const disks = (sourceDisks.length ? sourceDisks : fallbackDisks).map((item, index) => normalizeDisk(item, index, mounts, discovery));
    const sourceCapabilities = sourceDisks.length ? normalizeCapabilities(source) : emptyCapabilities();
    sourceCapabilities.inventory = disks.length > 0;
    return { disks, capabilities: sourceCapabilities, source: sourceDisks.length ? 'partition-api' : 'fallback' };
  }

  async function load(background = false) {
    const seq = ++state.seq;
    if (background) state.refreshing = true; else state.loading = true;
    state.error = '';
    if (!background) render();
    try {
      const [partitionResult, overviewResult, mountsResult, discoveryResult] = await Promise.allSettled([
        request(PARTITION_ENDPOINT),
        request(OVERVIEW_ENDPOINT),
        request(MOUNTS_ENDPOINT),
        request(DISCOVERY_ENDPOINT)
      ]);
      if (!state.mounted || seq !== state.seq) return;
      const partitionPayload = partitionResult.status === 'fulfilled' ? partitionResult.value : {};
      const overviewPayload = overviewResult.status === 'fulfilled' ? overviewResult.value : {};
      const mountsPayload = mountsResult.status === 'fulfilled' ? mountsResult.value : {};
      const discoveryPayload = discoveryResult.status === 'fulfilled' ? discoveryResult.value : {};
      if (!Object.keys(partitionPayload).length && !Object.keys(overviewPayload).length) {
        throw partitionResult.status === 'rejected' ? partitionResult.reason : overviewResult.reason;
      }
      const normalized = mergePartitionPayload(partitionPayload, overviewPayload, mountsPayload, discoveryPayload);
      state.disks = normalized.disks;
      state.capabilities = normalized.capabilities;
      state.source = normalized.source;
      if (!state.disks.some((disk) => disk.id === state.selectedDiskId)) state.selectedDiskId = state.disks[0]?.id || '';
      state.loaded = true;
      if (normalized.source === 'fallback') {
        state.notice = '当前由存储概览与挂载接口合并真实只读信息；分区事务接口尚未开放。';
        state.noticeTone = 'warning';
      }
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.disks = [];
      state.capabilities = emptyCapabilities();
      state.error = `读取失败：${firstText(error?.message, '磁盘与分区接口不可用')}`;
    } finally {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      render();
    }
  }

  function icon(name, size = 20) {
    const fromKit = ui.lucideIcon?.(name, { size, strokeWidth: 1.9 });
    if (fromKit) return fromKit;
    const paths = {
      HardDrive: '<path d="M22 12H2"></path><path d="m5.45 5.11-2.9 5.8A2 2 0 0 0 4.34 14h15.32a2 2 0 0 0 1.79-3.11l-2.9-5.8A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11Z"></path><path d="M6 18h.01M10 18h.01"></path><path d="M2 14v4a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-4"></path>',
      RefreshCw: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      Plus: '<path d="M12 5v14M5 12h14"></path>',
      Ellipsis: '<circle cx="5" cy="12" r="1"></circle><circle cx="12" cy="12" r="1"></circle><circle cx="19" cy="12" r="1"></circle>',
      X: '<path d="m6 6 12 12M18 6 6 18"></path>',
      TriangleAlert: '<path d="m21.73 18-8-14a2 2 0 0 0-3.46 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><path d="M12 9v4M12 17h.01"></path>',
      Info: '<circle cx="12" cy="12" r="10"></circle><path d="M12 16v-4M12 8h.01"></path>'
    };
    return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.Info}</svg>`;
  }

  function statusBadge(label, tone = 'muted') {
    return ui.statusBadgeMarkup?.(label, tone) || `<span class="dwrt-kit-status-badge is-${escapeHtml(tone)}"><span>${escapeHtml(label)}</span></span>`;
  }

  function selectedDisk() {
    return state.disks.find((disk) => disk.id === state.selectedDiskId) || state.disks[0] || null;
  }

  function selectedPartition() {
    const disk = selectedDisk();
    return disk?.partitions.find((partition) => partition.id === state.selectedPartitionId) || null;
  }

  function canTransact(action, target = null) {
    if (!state.capabilities.transactionPreview || !state.capabilities.transactionCommit || !state.capabilities[action]) return false;
    if (!target) return true;
    if (target.capabilities && Object.prototype.hasOwnProperty.call(target.capabilities, action) && !bool(target.capabilities[action])) return false;
    if (target.protected && ['delete', 'format', 'resize', 'unmount'].includes(action)) return false;
    if (target.mounted && ['delete', 'format', 'resize'].includes(action)) return false;
    return true;
  }

  function capabilityReason(action, target = null) {
    if (!state.capabilities.transactionPreview || !state.capabilities.transactionCommit) return '后端未提供分区事务预览、确认令牌与提交读回接口';
    if (!state.capabilities[action]) return `后端未声明“${actionLabel(action)}”能力`;
    if (target?.protected) return '系统分区受保护，不能在 Web 管理台执行此操作';
    if (target?.mounted && ['delete', 'format', 'resize'].includes(action)) return '分区仍在挂载中，必须先安全卸载';
    return '';
  }

  function actionLabel(action) {
    return ({ create: '创建分区', delete: '删除分区', format: '格式化', mount: '挂载', unmount: '卸载', resize: '调整容量' })[action] || action;
  }

  function noticeMarkup() {
    const text = state.error || state.notice;
    if (!text) return '';
    const tone = state.error ? 'error' : state.noticeTone;
    return `<div class="storage-partitions-notice is-${escapeHtml(tone)}" role="status">${icon(tone === 'error' || tone === 'warning' ? 'TriangleAlert' : 'Info', 18)}<span>${escapeHtml(text)}</span></div>`;
  }

  function diskTabsMarkup() {
    const tabs = state.disks.map((disk) => `<button class="dwrt-kit-tab ${disk.id === state.selectedDiskId ? 'is-active' : ''}" type="button" role="tab" aria-selected="${disk.id === state.selectedDiskId}" data-disk-id="${escapeHtml(disk.id)}"><span>${escapeHtml(disk.name)}</span><small>${escapeHtml(formatBytes(disk.totalBytes))}</small></button>`).join('');
    return `<div class="storage-partitions-disk-tabs"><div class="dwrt-kit-tabs dwrt-kit-page-tabs" data-dwrt-component="tabs" role="tablist" aria-label="选择物理磁盘">${tabs || '<button class="dwrt-kit-tab is-active" type="button" role="tab" aria-selected="true" disabled>没有磁盘</button>'}</div></div>`;
  }

  /*
   * 磁盘切换与新增分区都是控制表格的控件，按用户第 9 条收进表格工具条；
   * 手动刷新按钮删除，数据由 startPartitionPolling() 的轮询与写操作后的读回驱动。
   */
  function createButtonMarkup() {
    const reason = capabilityReason('create');
    return `<button class="dwrt-kit-button" data-dwrt-component="button" data-variant="primary" type="button" data-partition-create ${canTransact('create') ? '' : 'disabled'} ${reason ? `data-dwrt-tooltip="${escapeHtml(reason)}"` : ''}>${icon('Plus')}<span>新增分区</span></button>`;
  }

  /*
   * 磁盘详情三段式（验收单第 3 条）：身份区在 header，技术规格进深槽，分区映射条在最下。
   * 深槽的六项都是后端真读数，缺就写 `--`，不推导也不补默认值。
   */
  function diskFactsMarkup(disk) {
    const facts = [
      ['设备节点', disk.device || '--'],
      ['分区表类型', disk.table ? disk.table.toUpperCase() : '--'],
      ['物理扇区', disk.sectorSize ? `${disk.sectorSize}${disk.physicalSectorSize ? ` / ${disk.physicalSectorSize}` : ''} B` : '--'],
      ['接口类型', disk.transport ? disk.transport.toUpperCase() : '--'],
      ['序列号', disk.serial || '--'],
      ['健康状态', disk.smartStatus || '未上报']
    ];
    return `<dl class="storage-partitions-facts">${facts.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`).join('')}</dl>`;
  }

  function layoutMarkup(disk) {
    const total = disk.totalBytes || disk.partitions.reduce((sum, partition) => sum + (partition.capacityBytes || 0), 0);
    const segments = disk.partitions.map((partition) => {
      const ratio = total && partition.capacityBytes !== null ? Math.max(2, partition.capacityBytes / total * 100) : 8;
      return `<button type="button" style="--partition-ratio:${ratio}" data-partition-detail="${escapeHtml(partition.id)}" aria-label="${escapeHtml(`${partition.name}，${formatBytes(partition.capacityBytes)}`)}" data-dwrt-tooltip="${escapeHtml(`${partition.name}\n${formatBytes(partition.capacityBytes)}\n${partition.filesystem || '文件系统未知'}${partition.mountPoints.length ? `\n${partition.mountPoints.join('、')}` : ''}`)}"><span>${escapeHtml(partition.name)}</span></button>`;
    });
    if (disk.unallocatedBytes !== null && disk.unallocatedBytes > 0) {
      const ratio = total ? Math.max(2, disk.unallocatedBytes / total * 100) : 8;
      segments.push(`<span class="is-unallocated" style="--partition-ratio:${ratio}"><span>未分配</span></span>`);
    }
    return `<section class="storage-partitions-layout" aria-label="分区布局"><header><div><strong>分区布局</strong><span>${disk.partitions.length} 个分区${disk.maxPartitions ? ` / 上限 ${disk.maxPartitions}` : ''}</span></div><span>${disk.unallocatedBytes === null ? '未分配空间待后端提供' : `未分配 ${formatBytes(disk.unallocatedBytes)}`}</span></header><div class="storage-partitions-layout-track">${segments.join('') || '<span class="is-unallocated" style="--partition-ratio:100"><span>未返回分区</span></span>'}</div></section>`;
  }

  function partitionStatus(partition) {
    if (partition.protected) return statusBadge('系统保护', 'warning');
    if (partition.mounted) return statusBadge('已挂载', 'success');
    if (partition.filesystem) return statusBadge('未挂载', 'muted');
    return statusBadge('未格式化', 'info');
  }

  /* 用量条着色只反映后端真实读数：低占用绿、常规蓝、接近写满橙；无读数不画条。 */
  function usageTone(percent) {
    if (percent === null) return 'unknown';
    if (percent >= 85) return 'warn';
    if (percent >= 60) return 'busy';
    return 'ok';
  }

  function usageMarkup(partition) {
    const percent = partition.usedBytes === null || partition.capacityBytes === null ? null : partition.usedPercent;
    const tone = usageTone(percent);
    const ratio = percent === null ? 0 : Math.max(1, Math.min(100, Math.round(percent)));
    const track = percent === null
      ? '<span class="storage-partitions-usage-track is-unknown" aria-hidden="true"></span>'
      : `<span class="storage-partitions-usage-track" aria-hidden="true"><i style="--partition-usage:${ratio}%"></i></span>`;
    const detail = percent === null
      ? '用量未知'
      : `${formatBytes(partition.usedBytes)} / ${formatBytes(partition.capacityBytes)} · ${ratio}%`;
    const mount = partition.mountPoints.join('、');
    return `<span class="storage-partitions-usage is-${escapeHtml(tone)}">${track}<span class="storage-partitions-usage-meta"><small>${escapeHtml(detail)}</small><small class="storage-partitions-usage-mount" data-dwrt-tooltip="${escapeHtml(partition.mountPoints.join('\n') || '未挂载')}">${escapeHtml(mount || '未挂载')}</small></span></span>`;
  }

  function sectorRangeMarkup(partition) {
    if (partition.startSector === null && partition.endSector === null) return '<span class="storage-partitions-sectors"><span>--</span></span>';
    const start = partition.startSector === null ? '--' : partition.startSector.toLocaleString();
    const end = partition.endSector === null ? '--' : partition.endSector.toLocaleString();
    return `<span class="storage-partitions-sectors"><span>${escapeHtml(start)}</span><small>${escapeHtml(`→ ${end}`)}</small></span>`;
  }

  function tableMarkup(disk) {
    const rows = disk.partitions.map((partition) => `<tr class="storage-partitions-row ${partition.mounted ? '' : 'is-idle'}"><td><span class="storage-partitions-primary"><strong>${escapeHtml(partition.name)}</strong><small>${escapeHtml(partition.device || '--')}</small></span></td><td>${usageMarkup(partition)}</td><td><span class="storage-partitions-primary"><strong>${escapeHtml(partition.label || '无卷标')}</strong><small>${escapeHtml(partition.filesystem || '文件系统未知')}</small></span></td><td>${sectorRangeMarkup(partition)}</td><td>${partitionStatus(partition)}</td><td><button class="dwrt-kit-button dwrt-kit-icon-button storage-partitions-row-action" data-dwrt-component="icon-button" data-variant="ghost" type="button" data-partition-detail="${escapeHtml(partition.id)}" aria-label="查看 ${escapeHtml(partition.name)} 详情" data-dwrt-tooltip="详情与操作">${icon('Ellipsis')}</button></td></tr>`).join('');
    return `<section class="storage-partitions-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface" data-dwrt-component="table"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><span class="dwrt-kit-table-count">${disk.partitions.length} 个分区</span></div>${diskTabsMarkup()}<div class="storage-partitions-table-actions">${createButtonMarkup()}</div></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table"><thead><tr><th>名称 / 设备</th><th>用量 / 挂载点</th><th>卷标 / 文件系统</th><th>扇区范围</th><th>状态</th><th>操作</th></tr></thead><tbody>${rows || '<tr><td colspan="6" class="dwrt-kit-table-empty">后端没有返回这个磁盘的分区</td></tr>'}</tbody></table></div></section>`;
  }

  function emptyMarkup() {
    const text = state.loading && !state.loaded ? '正在读取磁盘与分区信息' : state.error ? '磁盘与分区信息读取失败' : '没有发现可管理的物理磁盘';
    return `<section class="dwrt-kit-state-panel storage-partitions-empty" data-dwrt-component="state-panel" aria-busy="${state.loading}">${icon('HardDrive', 28)}<strong>${escapeHtml(text)}</strong><p>${state.error ? escapeHtml(state.error) : '页面不会生成示例磁盘。连接磁盘后刷新重试。'}</p></section>`;
  }

  function workbenchMarkup() {
    const disk = selectedDisk();
    if (!disk) return emptyMarkup();
    return `<div class="storage-partitions-scroll"><section class="storage-partitions-disk-summary dwrt-kit-glass-surface" data-dwrt-surface="stable-glass"><header><span class="storage-partitions-disk-icon">${icon('HardDrive', 24)}</span><div><strong>${escapeHtml(disk.name)}</strong><span>${escapeHtml([disk.model || '型号未上报', formatBytes(disk.totalBytes), disk.removable ? '可移除' : ''].filter(Boolean).join(' · '))}</span></div>${disk.system ? statusBadge('系统磁盘', 'warning') : statusBadge('数据磁盘', 'info')}</header>${diskFactsMarkup(disk)}${layoutMarkup(disk)}</section>${tableMarkup(disk)}</div>`;
  }

  function detailPair(label, value, code = false) {
    return `<div><dt>${escapeHtml(label)}</dt><dd class="${code ? 'is-code' : ''}">${escapeHtml(value || '--')}</dd></div>`;
  }

  function partitionDetailBody(partition) {
    if (!partition) return '<div class="dwrt-kit-state-panel"><strong>分区不存在</strong><p>刷新页面后重试。</p></div>';
    return `<div class="storage-partitions-sheet-stack"><dl class="storage-partitions-detail-list">${detailPair('设备', partition.device, true)}${detailPair('容量', formatBytes(partition.capacityBytes))}${detailPair('文件系统', partition.filesystem)}${detailPair('卷标', partition.label)}${detailPair('UUID', partition.uuid, true)}${detailPair('挂载点', partition.mountPoints.join('、'), true)}${detailPair('起始扇区', partition.startSector === null ? '--' : String(partition.startSector))}${detailPair('结束扇区', partition.endSector === null ? '--' : String(partition.endSector))}</dl>${partition.protected ? '<div class="storage-partitions-inline-warning">这是系统保护分区，删除、格式化、调整容量和卸载均被禁用。</div>' : ''}<section class="storage-partitions-action-list"><header><strong>分区操作</strong><span>危险操作必须先由后端返回变更预览</span></header>${actionRow('mount', partition.mounted ? 'unmount' : 'mount', partition)}${actionRow('format', 'format', partition)}${actionRow('delete', 'delete', partition)}</section></div>`;
  }

  function actionRow(iconName, action, partition) {
    const enabled = canTransact(action, partition);
    const reason = capabilityReason(action, partition);
    const descriptions = {
      mount: '将文件系统连接到明确的挂载路径。',
      unmount: '停止使用该文件系统；系统与持久化分区不可卸载。',
      format: '重建文件系统并清除分区上的现有数据。',
      delete: '从分区表移除此分区并形成未分配空间。'
    };
    return `<div class="storage-partitions-action-row"><div><strong>${escapeHtml(actionLabel(action))}</strong><span>${escapeHtml(reason || descriptions[action])}</span></div><button class="dwrt-kit-button" data-dwrt-component="button" data-variant="${action === 'delete' || action === 'format' ? 'danger' : 'secondary'}" type="button" data-partition-action="${escapeHtml(action)}" ${enabled ? '' : 'disabled'} ${reason ? `data-dwrt-tooltip="${escapeHtml(reason)}"` : ''}>${escapeHtml(actionLabel(action))}</button></div>`;
  }

  function field(label, name, value, options = {}) {
    const description = options.description ? `<small data-dwrt-field-description>${escapeHtml(options.description)}</small>` : '';
    const control = options.options
      ? `<select class="dwrt-kit-select" data-partition-field="${escapeHtml(name)}">${options.options.map(([id, text]) => `<option value="${escapeHtml(id)}" ${String(value) === String(id) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select>`
      : `<input type="${options.type || 'text'}" data-partition-field="${escapeHtml(name)}" value="${escapeHtml(value)}" ${options.min !== undefined ? `min="${escapeHtml(options.min)}"` : ''} ${options.step !== undefined ? `step="${escapeHtml(options.step)}"` : ''} placeholder="${escapeHtml(options.placeholder || '')}">`;
    return `<label class="dwrt-kit-field ${options.wide ? 'is-wide' : ''}" data-dwrt-component="field"><span>${escapeHtml(label)}</span>${control}${description}</label>`;
  }

  function editorBody(mode) {
    const disk = selectedDisk();
    const partition = selectedPartition();
    const action = mode === 'create' ? 'create' : 'format';
    const reason = capabilityReason(action, partition);
    return `<div class="storage-partitions-form"><div class="storage-partitions-form-context"><span class="storage-partitions-disk-icon">${icon('HardDrive', 22)}</span><div><strong>${escapeHtml(mode === 'create' ? disk?.name || '--' : partition?.name || '--')}</strong><span>${escapeHtml(mode === 'create' ? `${disk?.device || '--'} · 未分配 ${formatBytes(disk?.unallocatedBytes)}` : `${partition?.device || '--'} · ${formatBytes(partition?.capacityBytes)}`)}</span></div></div><div class="storage-partitions-field-grid">${mode === 'create' ? field('容量', 'size', state.editor.size, { type: 'number', min: 1, step: 1, description: '不得超过后端预览返回的可分配范围。' }) + field('单位', 'unit', state.editor.unit, { options: [['MiB', 'MiB'], ['GiB', 'GiB'], ['TiB', 'TiB']] }) : ''}${field('文件系统', 'filesystem', state.editor.filesystem, { options: [['ext4', 'EXT4'], ['btrfs', 'Btrfs'], ['xfs', 'XFS'], ['f2fs', 'F2FS'], ['vfat', 'FAT32'], ['exfat', 'exFAT'], ['ntfs', 'NTFS']], description: '可用类型最终由后端按已安装工具返回。' })}${field('卷标', 'label', state.editor.label, { placeholder: '可选', description: '用于在挂载点和文件管理中识别卷。' })}${field('挂载点', 'mountPoint', state.editor.mountPoint, { wide: true, placeholder: '/mnt/data', description: '留空表示只创建或格式化，不自动挂载。' })}</div>${reason ? `<div class="storage-partitions-inline-warning">${escapeHtml(reason)}。当前表单不会写入本地存储，也不会绕过产品 API 调用系统命令。</div>` : ''}</div>`;
  }

  function sheetTitle() {
    if (state.sheet === 'create') return '新增分区';
    if (state.sheet === 'format') return `格式化 ${selectedPartition()?.name || '分区'}`;
    return selectedPartition()?.name || '分区详情';
  }

  function sheetMarkup() {
    if (!state.sheet) return '';
    const body = state.sheet === 'detail' ? partitionDetailBody(selectedPartition()) : editorBody(state.sheet);
    const action = state.sheet === 'create' ? 'create' : state.sheet === 'format' ? 'format' : '';
    const footer = action ? `<button class="dwrt-kit-button" data-dwrt-component="button" data-variant="ghost" type="button" data-partition-close>取消</button><button class="dwrt-kit-button ${state.working ? 'is-loading' : ''}" data-dwrt-component="async-button" data-variant="primary" type="button" data-partition-review="${escapeHtml(action)}" ${canTransact(action, selectedPartition()) && !state.working ? '' : 'disabled'}>${state.working ? '正在生成预览' : `审阅${actionLabel(action)}`}</button>` : '<button class="dwrt-kit-button" data-dwrt-component="button" data-variant="primary" type="button" data-partition-close>完成</button>';
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-partition-close aria-label="关闭分区面板"></button><aside class="dwrt-kit-sheet dwrt-kit-glass-surface storage-partitions-sheet is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" role="dialog" aria-modal="true" aria-labelledby="storage-partitions-sheet-title"><header class="dwrt-kit-sheet-header"><div><span>磁盘分区</span><strong id="storage-partitions-sheet-title">${escapeHtml(sheetTitle())}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-partition-close aria-label="关闭">${icon('X')}</button></header><div class="dwrt-kit-sheet-body">${body}</div><footer class="dwrt-kit-sheet-footer">${footer}</footer></aside>`;
  }

  function confirmationMarkup() {
    if (!state.confirmation) return '';
    const preview = state.confirmation.preview || {};
    const operations = asArray(preview.operations, ['changes']).map((item) => firstText(item.summary, item.description, item.action)).filter(Boolean);
    const description = firstText(preview.summary, preview.description, operations.join('；'), `${actionLabel(state.confirmation.action)}将修改磁盘分区状态。请核对对象和影响后再继续。`);
    return ui.confirmationMarkup?.({
      id: 'storage-partition-confirmation',
      action: `partition-${state.confirmation.action}`,
      tone: ['delete', 'format'].includes(state.confirmation.action) ? 'danger' : 'warning',
      title: `确认${actionLabel(state.confirmation.action)}`,
      description,
      confirmLabel: state.working ? '正在提交' : `确认${actionLabel(state.confirmation.action)}`,
      cancelLabel: '返回检查',
      disabled: state.working
    }) || '';
  }

  function render() {
    if (!state.mounted) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'storage-partitions-route-host');
    stage?.classList.add('is-storage-partitions');
    root.innerHTML = `<section class="storage-partitions-shell">${noticeMarkup()}<main class="storage-partitions-workbench">${workbenchMarkup()}</main>${sheetMarkup()}${confirmationMarkup()}</section>`;
    ui.mountAll?.(root);
  }

  /* 删掉手动刷新按钮的前提是页面自己会更新，所以这里补一条可见性受控的轮询。 */
  function startPolling() {
    stopPolling();
    state.pollTimer = window.setInterval(() => {
      if (!state.mounted) return;
      if (document.hidden) return;
      if (state.loading || state.refreshing || state.working) return;
      if (state.sheet || state.confirmation) return;
      load(true);
    }, 20000);
  }

  function stopPolling() {
    if (!state.pollTimer) return;
    window.clearInterval(state.pollTimer);
    state.pollTimer = 0;
  }

  function openCreate() {
    if (!canTransact('create')) return;
    const disk = selectedDisk();
    state.editor = emptyEditor();
    if (disk?.unallocatedBytes) state.editor.size = String(Math.max(1, Math.floor(disk.unallocatedBytes / (1024 ** 3))));
    state.sheet = 'create';
    state.selectedPartitionId = '';
    render();
  }

  function openDetail(id) {
    const disk = selectedDisk();
    if (!disk?.partitions.some((partition) => partition.id === id)) return;
    state.selectedPartitionId = id;
    state.sheet = 'detail';
    render();
  }

  function closeOverlay() {
    if (state.working) return;
    state.sheet = '';
    state.selectedPartitionId = '';
    state.editor = emptyEditor();
    state.confirmation = null;
    render();
  }

  function payloadFor(action) {
    const disk = selectedDisk();
    const partition = selectedPartition();
    return {
      action,
      disk_id: disk?.id || '',
      disk_device: disk?.device || '',
      partition_id: partition?.id || '',
      partition_device: partition?.device || '',
      ...(action === 'create' || action === 'format' ? {
        filesystem: state.editor.filesystem,
        label: state.editor.label.trim(),
        mount_point: state.editor.mountPoint.trim()
      } : {}),
      ...(action === 'create' ? { size: Number(state.editor.size), unit: state.editor.unit, alignment: 'optimal' } : {}),
      observed_contract: state.source
    };
  }

  function editorValidation(action) {
    if (action === 'create' && (!Number.isFinite(Number(state.editor.size)) || Number(state.editor.size) <= 0)) return '请输入大于 0 的分区容量';
    if ((action === 'create' || action === 'format') && !state.editor.filesystem) return '请选择文件系统';
    if (state.editor.mountPoint && !state.editor.mountPoint.startsWith('/')) return '挂载点必须使用绝对路径';
    return '';
  }

  async function requestPreview(action) {
    const partition = selectedPartition();
    if (!canTransact(action, partition) || state.working) return;
    const validation = editorValidation(action);
    if (validation) {
      state.notice = validation;
      state.noticeTone = 'error';
      render();
      return;
    }
    state.working = true;
    render();
    try {
      const preview = await request(`${PARTITION_ENDPOINT}/preview`, { method: 'POST', body: JSON.stringify(payloadFor(action)) });
      if (!state.mounted) return;
      const token = firstText(preview.preview_token, preview.transaction_token, preview.token);
      if (!token) throw new Error('后端预览未返回一次性事务令牌');
      state.confirmation = { action, token, preview };
      state.working = false;
      render();
    } catch (error) {
      if (!state.mounted) return;
      state.working = false;
      state.notice = `预览失败：${firstText(error?.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  async function commitConfirmation() {
    if (!state.confirmation || state.working) return;
    const { action, token } = state.confirmation;
    state.working = true;
    render();
    try {
      const result = await request(`${PARTITION_ENDPOINT}/commit`, {
        method: 'POST',
        body: JSON.stringify({ preview_token: token, confirm_destructive: true })
      });
      if (!state.mounted) return;
      state.confirmation = null;
      state.sheet = '';
      state.selectedPartitionId = '';
      state.working = false;
      state.notice = firstText(result.message, result.status === 'queued' ? `${actionLabel(action)}任务已提交` : `${actionLabel(action)}已提交，正在读回`);
      state.noticeTone = 'info';
      await load(true);
    } catch (error) {
      if (!state.mounted) return;
      state.working = false;
      state.notice = `提交失败：${firstText(error?.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  function onClick(event) {
    const target = event.target.closest('button');
    if (!target || !root.contains(target)) return;
    if (target.matches('[data-disk-id]')) {
      state.selectedDiskId = target.dataset.diskId || '';
      state.sheet = '';
      state.selectedPartitionId = '';
      render();
      return;
    }
    if (target.matches('[data-partition-create]')) { openCreate(); return; }
    if (target.matches('[data-partition-detail]')) { openDetail(target.dataset.partitionDetail || ''); return; }
    if (target.matches('[data-partition-close], [data-dwrt-confirm-cancel], [data-dwrt-modal-close]')) { closeOverlay(); return; }
    if (target.matches('[data-partition-action]')) {
      const action = target.dataset.partitionAction || '';
      if (action === 'format') {
        state.editor = { ...emptyEditor(), filesystem: selectedPartition()?.filesystem || 'ext4', label: selectedPartition()?.label || '' };
        state.sheet = 'format';
        render();
      } else requestPreview(action);
      return;
    }
    if (target.matches('[data-partition-review]')) { requestPreview(target.dataset.partitionReview || ''); return; }
    if (target.matches('[data-dwrt-confirm-accept]')) commitConfirmation();
  }

  function onInput(event) {
    const input = event.target.closest('[data-partition-field]');
    if (!input || !root.contains(input)) return;
    const key = input.dataset.partitionField;
    if (key && Object.prototype.hasOwnProperty.call(state.editor, key)) state.editor[key] = input.value;
  }

  function onKeydown(event) {
    if (event.key === 'Escape' && (state.sheet || state.confirmation)) closeOverlay();
  }

  function unmount() {
    if (!state.mounted) return;
    state.mounted = false;
    state.seq += 1;
    stopPolling();
    root.removeEventListener('click', onClick);
    root.removeEventListener('input', onInput);
    root.removeEventListener('change', onInput);
    document.removeEventListener('keydown', onKeydown, true);
    context.signal?.removeEventListener('abort', unmount);
    ui.unmount?.(root);
    stage?.classList.remove('is-storage-partitions');
    root.classList.remove('storage-partitions-route-host');
  }

  root.addEventListener('click', onClick);
  root.addEventListener('input', onInput);
  root.addEventListener('change', onInput);
  document.addEventListener('keydown', onKeydown, true);
  context.signal?.addEventListener('abort', unmount, { once: true });
  load();
  startPolling();

  return { unmount };
}

function fallbackFormatBytes(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0) return '--';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let result = number;
  let index = 0;
  while (result >= 1024 && index < units.length - 1) { result /= 1024; index += 1; }
  const digits = result >= 100 || index === 0 ? 0 : result >= 10 ? 1 : 2;
  return `${result.toFixed(digits)} ${units[index]}`;
}

export default { mount };
