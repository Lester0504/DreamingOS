export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const VERSION = '20260716-20';
  const MODULE_CLASS = 'storage-raid-route-host';
  const stage = root?.closest('.console-stage');
  const ENDPOINT = '/api/v1/storage/raid';
  const READ_ENDPOINTS = [ENDPOINT, '/api/v1/storage/raids'];
  const LEVELS = {
    jbod: { label: 'JBOD（线性）', min: 2, description: '将多个磁盘合并为一个存储空间，容量接近成员容量总和，不提供数据冗余。' },
    raid0: { label: 'RAID 0（条带）', min: 2, description: '把数据块分散到多个磁盘以提高吞吐性能，不提供数据冗余。' },
    raid1: { label: 'RAID 1（镜像）', min: 2, description: '向成员磁盘写入相同数据，可在单个成员故障时保留数据。' },
    raid5: { label: 'RAID 5', min: 3, description: '数据与单层奇偶校验分布在所有成员磁盘上，兼顾容量与单盘冗余。' },
    raid6: { label: 'RAID 6', min: 4, description: '使用双层奇偶校验，可承受两个成员磁盘故障。' },
    raid10: { label: 'RAID 10', min: 4, even: true, description: '由镜像组组成条带，同时提供 RAID 0 的性能与 RAID 1 的数据保护。' }
  };

  const state = {
    mounted: true,
    seq: 0,
    loading: true,
    refreshing: false,
    saving: false,
    loaded: false,
    error: '',
    notice: '',
    noticeTone: '',
    query: '',
    arrays: [],
    disks: [],
    recoverable: [],
    capabilities: {},
    drawer: '',
    selectedId: '',
    editor: emptyEditor(),
    confirmDelete: false
  };

  function emptyEditor() {
    return { name: '', level: 'raid5', members: [], format: true, note: '' };
  }

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (typeof value === 'object' && !Array.isArray(value)) {
        const nested = firstText(value.message, value.name, value.label, value.value, value.id);
        if (nested) return nested;
        continue;
      }
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }

  function firstNumber(...values) {
    for (const value of values) {
      if (value === '' || value === undefined || value === null) continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return 0;
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

  function clone(value) {
    try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value || {})); }
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

  async function requestJson(url, options = {}) {
    const response = await fetch(`${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`, {
      credentials: 'same-origin', cache: 'no-store', ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    const payload = json?.data ?? json?.body ?? json;
    if (!response.ok || json?.ok === false || payload?.ok === false) {
      const error = new Error(firstText(payload?.message, payload?.error, json?.message, json?.error, `HTTP ${response.status}`));
      error.status = response.status;
      throw error;
    }
    return payload || {};
  }

  function normalizeStatus(...values) {
    const status = firstText(...values, 'unknown').toLowerCase().replace(/[\s-]+/g, '_');
    if (['active', 'clean', 'online', 'healthy', 'normal', 'running'].includes(status)) return 'healthy';
    if (['degraded', 'faulty', 'failed', 'inactive', 'offline', 'broken'].includes(status)) return status === 'degraded' ? 'degraded' : 'failed';
    if (['recovering', 'recovery', 'resync', 'resyncing', 'rebuilding', 'checking', 'reshape'].includes(status)) return 'syncing';
    if (['assembling', 'stopped', 'unmounted'].includes(status)) return status;
    return status || 'unknown';
  }

  function normalizeMember(item, index = 0) {
    if (typeof item === 'string') return { id: item, device: item, status: 'unknown' };
    return {
      ...item,
      id: firstText(item.id, item.uuid, item.device, item.path, `member-${index + 1}`),
      device: firstText(item.device, item.path, item.name, item.id),
      model: firstText(item.model, item.product),
      serial: firstText(item.serial, item.serial_number),
      status: normalizeStatus(item.status, item.state),
      size_bytes: firstNumber(item.size_bytes, item.size)
    };
  }

  function normalizeArray(item, index = 0) {
    const members = asArray(item.members, ['devices', 'disks']).map(normalizeMember);
    return {
      ...item,
      id: firstText(item.id, item.uuid, item.device, item.name, `raid-${index + 1}`),
      name: firstText(item.name, item.label, item.id, `RAID ${index + 1}`),
      device: firstText(item.device, item.path, item.md_device),
      level: firstText(item.level, item.raid_level, item.type).toLowerCase().replace(/[\s_-]+/g, ''),
      status: normalizeStatus(item.status, item.state, item.health),
      size_bytes: firstNumber(item.size_bytes, item.capacity_bytes, item.size, item.capacity),
      members,
      mount_point: firstText(item.mount_point, item.mount, item.target),
      filesystem: firstText(item.filesystem, item.fs, item.fstype),
      note: firstText(item.note, item.remark, item.description),
      sync_percent: firstNumber(item.sync_percent, item.progress, item.resync_percent),
      action: firstText(item.action, item.sync_action, item.recovery_action),
      capabilities: item.capabilities || {}
    };
  }

  function normalizeDisk(item, index = 0) {
    return {
      ...item,
      id: firstText(item.id, item.uuid, item.device, item.path, `disk-${index + 1}`),
      device: firstText(item.device, item.path, item.name),
      model: firstText(item.model, item.product, '未知型号'),
      serial: firstText(item.serial, item.serial_number),
      transport: firstText(item.transport, item.tran, item.bus),
      size_bytes: firstNumber(item.size_bytes, item.capacity_bytes, item.size),
      eligible: bool(item.eligible, item.available === undefined ? true : item.available),
      reason: firstText(item.reason, item.unavailable_reason),
      in_use: bool(item.in_use, item.used),
      system: bool(item.system, item.is_system),
      members: asArray(item.members)
    };
  }

  function normalizePayload(payload = {}) {
    const source = payload.raid && typeof payload.raid === 'object' ? payload.raid : payload;
    return {
      arrays: asArray(source.arrays, ['raids', 'md_arrays']).map(normalizeArray),
      disks: asArray(source.disks, ['available_disks', 'devices']).map(normalizeDisk),
      recoverable: asArray(source.recoverable, ['recoverable_arrays', 'candidates']).map(normalizeArray),
      capabilities: source.capabilities && typeof source.capabilities === 'object' ? source.capabilities : {}
    };
  }

  async function load(background = false) {
    const seq = ++state.seq;
    if (background) state.refreshing = true; else state.loading = true;
    state.error = '';
    render();
    try {
      let payload;
      let lastError;
      for (const endpoint of READ_ENDPOINTS) {
        try { payload = await requestJson(endpoint); break; } catch (error) { lastError = error; }
      }
      if (!payload) throw lastError || new Error('RAID API 不可用');
      if (!state.mounted || seq !== state.seq) return;
      const normalized = normalizePayload(payload);
      state.arrays = normalized.arrays;
      state.disks = normalized.disks;
      state.recoverable = normalized.recoverable;
      state.capabilities = normalized.capabilities;
      state.loaded = true;
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.error = 'RAID 后端接口尚未开放。页面保留完整管理结构，但不会伪造磁盘、阵列或操作结果。';
    } finally {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      render();
    }
  }

  function hasCapability(action, item = null) {
    const local = item?.capabilities || {};
    return local[action] === true || state.capabilities[action] === true || state.capabilities[`raid_${action}`] === true;
  }

  function supportedLevelEntries() {
    const declared = Array.isArray(state.capabilities.supported_levels)
      ? new Set(state.capabilities.supported_levels.map(normalizeLevelKey))
      : null;
    const entries = Object.entries(LEVELS);
    return declared && declared.size ? entries.filter(([id]) => declared.has(id)) : entries;
  }

  function normalizeLevelKey(level) {
    const key = String(level || '').toLowerCase().replace(/[\s_-]+/g, '');
    if (key === 'linear' || key === 'jbod') return 'jbod';
    return key.startsWith('raid') ? key : `raid${key}`;
  }

  function icon(name) {
    const paths = {
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      scan: '<path d="M4 7V5a1 1 0 0 1 1-1h2M17 4h2a1 1 0 0 1 1 1v2M20 17v2a1 1 0 0 1-1 1h-2M7 20H5a1 1 0 0 1-1-1v-2"></path><circle cx="12" cy="12" r="4"></circle>',
      disk: '<ellipse cx="12" cy="6" rx="8" ry="3"></ellipse><path d="M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"></path>',
      edit: '<path d="m4 20 4.2-1 10.9-10.9a2 2 0 0 0-2.8-2.8L5.4 16.2 4 20Z"></path>',
      activity: '<path d="M3 12h4l2-7 4 14 2-7h6"></path>',
      mount: '<path d="M12 3v12m-5-5 5 5 5-5"></path><path d="M5 21h14"></path>',
      unmount: '<path d="M12 21V9m-5 5 5-5 5 5"></path><path d="M5 3h14"></path>',
      trash: '<path d="M4 7h16M9 7V4h6v3m-9 0 1 13h10l1-13M10 11v5m4-5v5"></path>',
      recover: '<path d="M3 12a9 9 0 1 0 3-6.7"></path><path d="M3 4v6h6"></path>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.disk}</svg>`;
  }

  function formatBytes(value) {
    const bytes = Number(value || 0);
    if (!Number.isFinite(bytes) || bytes <= 0) return '--';
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const amount = bytes / (1024 ** index);
    return `${amount >= 100 || index === 0 ? amount.toFixed(0) : amount >= 10 ? amount.toFixed(1) : amount.toFixed(2)} ${units[index]}`;
  }

  function levelInfo(level) {
    const normalized = normalizeLevelKey(level);
    if (normalized === 'jbod') return { key: 'jbod', ...LEVELS.jbod };
    return { key: normalized, ...(LEVELS[normalized] || { label: String(level || '--').toUpperCase(), min: 2, description: '' }) };
  }

  function statusInfo(status) {
    const map = {
      healthy: ['正常', 'is-healthy'], degraded: ['已降级', 'is-warning'], failed: ['故障', 'is-danger'],
      syncing: ['同步中', 'is-syncing'], assembling: ['组装中', 'is-syncing'], stopped: ['已停止', 'is-muted'],
      unmounted: ['未挂载', 'is-muted'], unknown: ['未知', 'is-muted']
    };
    return map[status] || [status || '未知', 'is-muted'];
  }

  function statusMarkup(item) {
    const [label, tone] = statusInfo(item.status);
    const progress = item.status === 'syncing' && item.sync_percent > 0 ? `<small>${Math.min(100, item.sync_percent).toFixed(1)}%</small>` : '';
    const semanticTone = tone === 'is-healthy' ? 'success' : tone === 'is-warning' ? 'warning' : tone === 'is-danger' ? 'error' : tone === 'is-syncing' ? 'info' : 'muted';
    const badge = ui.statusBadgeMarkup?.(label, semanticTone) || `<span>${escapeHtml(label)}</span>`;
    return `<span class="raid-status-group">${badge}${progress}</span>`;
  }

  function matchesQuery(item) {
    const query = state.query.trim().toLowerCase();
    if (!query) return true;
    const text = [item.name, item.device, item.level, item.status, item.mount_point, item.filesystem, item.note, ...item.members.flatMap((member) => [member.device, member.model, member.serial])].join(' ').toLowerCase();
    return text.includes(query);
  }

  function toolbarMarkup() {
    return `<header class="policy-toolbar raid-toolbar"><label class="policy-search policy-search-main raid-search" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-raid-search value="${escapeHtml(state.query)}" placeholder="搜索名称、设备、成员或挂载点"></label><div class="policy-toolbar-actions"><button class="policy-filter-button" type="button" data-raid-scan>${icon('scan')}<span>扫描恢复 RAID</span></button><button class="policy-filter-button" type="button" data-raid-refresh ${state.refreshing ? 'disabled' : ''}>${icon('refresh')}<span>${state.refreshing ? '正在刷新' : '刷新'}</span></button><button class="policy-create-button" type="button" data-raid-create>${icon('plus')}<span>创建 RAID</span></button></div></header>`;
  }

  function emptyText() {
    if (state.loading && !state.loaded) return '正在读取 RAID 与磁盘状态';
    if (state.error) return '后端 RAID 管理能力尚未接入';
    if (state.query) return '没有符合搜索条件的 RAID 阵列';
    return '暂无 RAID 阵列';
  }

  function memberMarkup(item) {
    if (!item.members.length) return '--';
    const visible = item.members.slice(0, 3);
    const remaining = item.members.length - visible.length;
    return `<span class="raid-member-list">${visible.map((member) => `<code>${escapeHtml(member.device || member.id)}</code>`).join('')}${remaining > 0 ? `<span data-dwrt-tooltip="${escapeHtml(item.members.slice(3).map((member) => member.device || member.id).join('、'))}">+${remaining}</span>` : ''}</span>`;
  }

  function tableMarkup() {
    const rows = state.arrays.filter(matchesQuery).map((item) => {
      const level = levelInfo(item.level);
      const mount = [item.filesystem, item.mount_point].filter(Boolean).join(' · ') || '--';
      return `<tr data-raid-row="${escapeHtml(item.id)}"><td>${statusMarkup(item)}</td><td><button class="raid-name-button" type="button" data-raid-detail="${escapeHtml(item.id)}"><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.device || '--')}</small></button></td><td>${escapeHtml(level.label)}</td><td>${formatBytes(item.size_bytes)}</td><td>${memberMarkup(item)}</td><td><span class="raid-mount-cell" data-dwrt-tooltip="${escapeHtml(mount)}">${escapeHtml(mount)}</span></td><td><span class="raid-note-cell" data-dwrt-tooltip="${escapeHtml(item.note || '--')}">${escapeHtml(item.note || '--')}</span></td><td><button class="raid-icon-button" type="button" data-raid-detail="${escapeHtml(item.id)}" aria-label="查看 RAID 详情" data-dwrt-tooltip="详情">${icon('edit')}</button></td></tr>`;
    });
    return `<section class="raid-table-card dwrt-kit-table-wrap dwrt-kit-datatable-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>RAID 阵列</strong><span>磁盘成员、阵列健康、同步进度与挂载状态</span></div><span class="dwrt-kit-table-count">${rows.length} 条</span></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-datatable raid-table"><thead><tr><th>状态</th><th>RAID 名称 / 设备</th><th>RAID 类型</th><th>容量</th><th>磁盘成员</th><th>挂载信息</th><th>备注</th><th>操作</th></tr></thead><tbody>${rows.length ? rows.join('') : `<tr><td colspan="8" class="dwrt-kit-table-empty">${escapeHtml(emptyText())}</td></tr>`}</tbody></table></div></section>`;
  }

  function noticeMarkup() {
    const text = state.notice || state.error;
    if (!text) return '';
    return `<div class="raid-notice is-${escapeHtml(state.notice ? state.noticeTone || 'info' : 'warning')}">${escapeHtml(text)}</div>`;
  }

  function drawerTitle() {
    if (state.drawer === 'create') return '创建 RAID';
    if (state.drawer === 'detail') return state.arrays.find((item) => item.id === state.selectedId)?.name || 'RAID 详情';
    if (state.drawer === 'recover') return '扫描恢复 RAID';
    return '';
  }

  function field(label, path, value, options = {}) {
    const control = options.options
      ? `<select data-raid-draft="${escapeHtml(path)}">${options.options.map(([id, text]) => `<option value="${escapeHtml(id)}" ${String(value) === String(id) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select>`
      : options.multiline
        ? `<textarea data-raid-draft="${escapeHtml(path)}" maxlength="${escapeHtml(options.maxlength || 256)}" placeholder="${escapeHtml(options.placeholder || '')}">${escapeHtml(value || '')}</textarea>`
        : `<input data-raid-draft="${escapeHtml(path)}" value="${escapeHtml(value || '')}" placeholder="${escapeHtml(options.placeholder || '')}" ${options.maxlength ? `maxlength="${escapeHtml(options.maxlength)}"` : ''}>`;
    return `<label class="raid-field ${options.wide ? 'is-wide' : ''}"><span>${escapeHtml(label)}</span>${control}${options.help ? `<small>${escapeHtml(options.help)}</small>` : ''}</label>`;
  }

  function selectedMemberCount() {
    return Array.isArray(state.editor.members) ? state.editor.members.length : 0;
  }

  function createValidation() {
    const info = levelInfo(state.editor.level);
    const count = selectedMemberCount();
    if (!firstText(state.editor.name)) return '请填写 RAID 名称';
    if (count < info.min) return `${info.label} 至少需要 ${info.min} 块磁盘`;
    if (info.even && count % 2 !== 0) return `${info.label} 的成员数量必须为偶数`;
    return '';
  }

  function diskChoiceMarkup(disk) {
    const disabled = !disk.eligible || disk.in_use || disk.system;
    const checked = state.editor.members.includes(disk.id);
    const detail = [formatBytes(disk.size_bytes), disk.model, disk.transport ? disk.transport.toUpperCase() : ''].filter((value) => value && value !== '--').join(' · ');
    const reason = disk.system ? '系统磁盘不可加入阵列' : disk.in_use ? '磁盘正在使用' : disk.reason;
    return `<label class="raid-disk-choice ${disabled ? 'is-disabled' : ''}"><input type="checkbox" data-raid-member="${escapeHtml(disk.id)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}><span class="raid-disk-icon">${icon('disk')}</span><span><strong>${escapeHtml(disk.device || disk.id)}</strong><small>${escapeHtml(detail || '--')}${reason ? ` · ${escapeHtml(reason)}` : ''}</small></span></label>`;
  }

  function createDrawerBody() {
    const info = levelInfo(state.editor.level);
    const eligible = state.disks.filter((disk) => disk.eligible && !disk.in_use && !disk.system).length;
    return `<div class="raid-form">${field('RAID 名称', 'name', state.editor.name, { wide: true, placeholder: '例如 data-array', maxlength: 64 })}${field('RAID 类型', 'level', state.editor.level, { wide: true, options: supportedLevelEntries().map(([id, item]) => [id, item.label]) })}</div><div class="raid-level-description"><strong>${escapeHtml(info.label)} · 至少 ${info.min} 块磁盘${info.even ? ' · 成员数须为偶数' : ''}</strong><span>${escapeHtml(info.description)}</span></div><section class="raid-member-section"><header><strong>磁盘阵列成员</strong><span>已选择 ${selectedMemberCount()} 块 · ${eligible} 块可用</span></header><div class="raid-disk-list">${state.disks.length ? state.disks.map(diskChoiceMarkup).join('') : '<div class="raid-disk-empty">后端尚未返回可用物理磁盘。USB 磁盘是否允许加入阵列必须由后端按设备稳定性明确标记。</div>'}</div></section><label class="raid-format-row"><input type="checkbox" data-raid-format ${state.editor.format ? 'checked' : ''}><span><strong>清除成员磁盘上的现有分区与文件系统签名</strong><small>创建阵列会破坏所选磁盘上的数据。后端必须再次确认并以事务方式执行。</small></span></label><div class="raid-form">${field('备注', 'note', state.editor.note, { wide: true, multiline: true, maxlength: 64, placeholder: '可选，最多 64 个字符' })}</div>${!hasCapability('create') ? '<div class="raid-capability">后端创建能力尚未开放。当前表单不会写入浏览器本地数据或直接调用 mdadm。</div>' : ''}${state.notice ? noticeMarkup() : ''}`;
  }

  function detailPair(label, value, options = {}) {
    return `<div><dt>${escapeHtml(label)}</dt><dd class="${options.code ? 'is-code' : ''}">${escapeHtml(value || '--')}</dd></div>`;
  }

  function detailDrawerBody(item) {
    if (!item) return '<div class="raid-disk-empty">找不到该 RAID 阵列</div>';
    const level = levelInfo(item.level);
    const [statusLabel] = statusInfo(item.status);
    const members = item.members.length ? item.members.map((member) => `<div class="raid-detail-member"><span class="raid-disk-icon">${icon('disk')}</span><span><strong>${escapeHtml(member.device || member.id)}</strong><small>${escapeHtml([member.model, member.serial, statusInfo(member.status)[0]].filter(Boolean).join(' · '))}</small></span></div>`).join('') : '<div class="raid-disk-empty">后端未返回阵列成员</div>';
    const progress = item.status === 'syncing' ? `<section class="raid-sync"><header><strong>${escapeHtml(item.action || '阵列同步')}</strong><span>${Math.min(100, item.sync_percent).toFixed(1)}%</span></header><div><i style="width:${Math.min(100, Math.max(0, item.sync_percent))}%"></i></div></section>` : '';
    return `<dl class="raid-detail-list">${detailPair('设备', item.device, { code: true })}${detailPair('状态', statusLabel)}${detailPair('RAID 类型', level.label)}${detailPair('可用容量', formatBytes(item.size_bytes))}${detailPair('文件系统', item.filesystem)}${detailPair('挂载点', item.mount_point, { code: true })}${detailPair('备注', item.note)}</dl>${progress}<section class="raid-detail-members"><header><strong>磁盘成员</strong><span>${item.members.length} 块</span></header>${members}</section>${state.notice ? noticeMarkup() : ''}`;
  }

  function recoveryDrawerBody() {
    return `<div class="raid-recovery-copy"><span class="raid-recovery-icon">${icon('recover')}</span><div><strong>扫描未组装的 RAID 元数据</strong><p>用于系统重启、重置或设备节点变化后重新发现已有阵列。扫描和恢复不得初始化、格式化或覆盖成员磁盘。</p></div></div><div class="raid-recovery-list">${state.recoverable.length ? state.recoverable.map((item) => `<article><div><strong>${escapeHtml(item.name)}</strong><span>${escapeHtml([item.device, levelInfo(item.level).label, `${item.members.length} 块成员`, formatBytes(item.size_bytes)].filter(Boolean).join(' · '))}</span></div><button class="policy-primary" type="button" data-raid-recover="${escapeHtml(item.id)}" ${hasCapability('recover', item) && !state.saving ? '' : 'disabled'}>恢复阵列</button></article>`).join('') : `<div class="raid-disk-empty">${hasCapability('scan') ? '尚未发现可恢复的 RAID 阵列' : '后端扫描与恢复能力尚未开放'}</div>`}</div>${state.notice ? noticeMarkup() : ''}`;
  }

  function detailFooter(item) {
    if (!item) return '';
    const action = item.status === 'syncing' ? 'stop' : 'check';
    const actionLabel = item.status === 'syncing' ? '停止当前操作' : '检查阵列';
    const mountAction = item.mount_point ? 'unmount' : 'mount';
    return `<button class="policy-secondary danger" type="button" data-raid-delete ${hasCapability('delete', item) && !state.saving ? '' : 'disabled'}>${state.confirmDelete ? '再次点击删除阵列' : '删除阵列'}</button><div><button class="policy-secondary" type="button" data-raid-action="${action}" ${hasCapability(action, item) && !state.saving ? '' : 'disabled'}>${actionLabel}</button><button class="policy-primary" type="button" data-raid-action="${mountAction}" ${hasCapability(mountAction, item) && !state.saving ? '' : 'disabled'}>${mountAction === 'mount' ? '挂载' : '卸载'}</button></div>`;
  }

  function drawerMarkup() {
    if (!state.drawer) return '';
    const item = state.arrays.find((entry) => entry.id === state.selectedId);
    const body = state.drawer === 'create' ? createDrawerBody() : state.drawer === 'detail' ? detailDrawerBody(item) : recoveryDrawerBody();
    let footer = '';
    if (state.drawer === 'create') footer = `<span></span><div><button class="policy-secondary" type="button" data-raid-close>取消</button><button class="policy-primary" type="button" data-raid-save ${hasCapability('create') && !state.saving && !createValidation() ? '' : 'disabled'}>${state.saving ? '正在创建' : hasCapability('create') ? '创建 RAID' : '等待后端能力'}</button></div>`;
    if (state.drawer === 'detail') footer = detailFooter(item);
    if (state.drawer === 'recover') footer = `<span></span><div><button class="policy-secondary" type="button" data-raid-close>关闭</button><button class="policy-primary" type="button" data-raid-run-scan ${hasCapability('scan') && !state.saving ? '' : 'disabled'}>${state.saving ? '正在扫描' : hasCapability('scan') ? '开始扫描' : '等待后端能力'}</button></div>`;
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-raid-close aria-label="关闭 RAID 面板"></button><aside class="raid-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" aria-label="${escapeHtml(drawerTitle())}"><header class="dwrt-kit-sheet-header"><div><span>RAID</span><strong>${escapeHtml(drawerTitle())}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-raid-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body raid-drawer-body">${body}</div><footer class="dwrt-kit-sheet-footer raid-drawer-footer">${footer}</footer></aside>`;
  }

  function render() {
    if (!root) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'policy-table-route-host', MODULE_CLASS);
    root.innerHTML = `<section class="raid-shell">${noticeMarkup()}<main class="raid-workbench">${toolbarMarkup()}${tableMarkup()}</main>${drawerMarkup()}</section>`;
    ui.mountAll?.(root);
  }

  function patchTable() {
    const current = root?.querySelector('.raid-table-card');
    if (!current) { render(); return; }
    const scroll = current.querySelector('.dwrt-kit-table-scroll');
    const left = scroll?.scrollLeft || 0;
    const top = scroll?.scrollTop || 0;
    const template = document.createElement('template');
    template.innerHTML = tableMarkup();
    const next = template.content.firstElementChild;
    if (!next) return;
    current.replaceWith(next);
    const nextScroll = next.querySelector('.dwrt-kit-table-scroll');
    if (nextScroll) { nextScroll.scrollLeft = left; nextScroll.scrollTop = top; }
    ui.mountAll?.(next);
  }

  function closeDrawer() {
    state.drawer = '';
    state.selectedId = '';
    state.editor = emptyEditor();
    state.notice = '';
    state.noticeTone = '';
    state.confirmDelete = false;
    render();
  }

  function openCreate() {
    state.drawer = 'create';
    state.editor = emptyEditor();
    state.editor.level = supportedLevelEntries()[0]?.[0] || 'raid1';
    state.notice = '';
    state.noticeTone = '';
    state.confirmDelete = false;
    render();
  }

  function openDetail(id) {
    if (!state.arrays.some((item) => item.id === id)) return;
    state.drawer = 'detail';
    state.selectedId = id;
    state.notice = '';
    state.noticeTone = '';
    state.confirmDelete = false;
    render();
  }

  function openRecovery() {
    state.drawer = 'recover';
    state.notice = '';
    state.noticeTone = '';
    render();
  }

  async function createRaid() {
    const validation = createValidation();
    if (!hasCapability('create') || state.saving) return;
    if (validation) { state.notice = validation; state.noticeTone = 'error'; render(); return; }
    state.saving = true;
    state.notice = '';
    render();
    try {
      await requestJson(ENDPOINT, { method: 'POST', body: JSON.stringify({ name: state.editor.name.trim(), level: levelInfo(state.editor.level).key, members: state.editor.members, format: Boolean(state.editor.format), note: state.editor.note.trim(), confirm_destructive: Boolean(state.editor.format) }) });
      if (!state.mounted) return;
      state.saving = false;
      state.drawer = '';
      state.notice = 'RAID 创建任务已提交';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      if (!state.mounted) return;
      state.saving = false;
      state.notice = `创建失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  async function runScan() {
    if (!hasCapability('scan') || state.saving) return;
    state.saving = true;
    state.notice = '';
    render();
    try {
      const payload = await requestJson(`${ENDPOINT}/scan`, { method: 'POST', body: JSON.stringify({ non_destructive: true }) });
      if (!state.mounted) return;
      state.recoverable = asArray(payload.recoverable, ['recoverable_arrays', 'candidates']).map(normalizeArray);
      state.saving = false;
      state.notice = state.recoverable.length ? `发现 ${state.recoverable.length} 个可恢复阵列` : '未发现可恢复的 RAID 阵列';
      state.noticeTone = 'info';
      render();
    } catch (error) {
      if (!state.mounted) return;
      state.saving = false;
      state.notice = `扫描失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  async function recoverRaid(id) {
    const item = state.recoverable.find((entry) => entry.id === id);
    if (!item || !hasCapability('recover', item) || state.saving) return;
    state.saving = true;
    state.notice = '';
    render();
    try {
      await requestJson(`${ENDPOINT}/recover`, { method: 'POST', body: JSON.stringify({ candidate_id: id, assemble_only: true }) });
      if (!state.mounted) return;
      state.saving = false;
      state.drawer = '';
      state.notice = 'RAID 恢复任务已提交';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      if (!state.mounted) return;
      state.saving = false;
      state.notice = `恢复失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  async function runArrayAction(action) {
    const item = state.arrays.find((entry) => entry.id === state.selectedId);
    if (!item || !hasCapability(action, item) || state.saving) return;
    state.saving = true;
    state.notice = '';
    render();
    try {
      await requestJson(`${ENDPOINT}/${encodeURIComponent(item.id)}/actions`, { method: 'POST', body: JSON.stringify({ action }) });
      if (!state.mounted) return;
      state.saving = false;
      state.drawer = '';
      state.notice = 'RAID 操作已提交';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      if (!state.mounted) return;
      state.saving = false;
      state.notice = `操作失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  async function deleteRaid() {
    const item = state.arrays.find((entry) => entry.id === state.selectedId);
    if (!item || !hasCapability('delete', item) || state.saving) return;
    if (!state.confirmDelete) { state.confirmDelete = true; render(); return; }
    state.saving = true;
    render();
    try {
      await requestJson(`${ENDPOINT}/${encodeURIComponent(item.id)}`, { method: 'DELETE', body: JSON.stringify({ confirm_destructive: true, preserve_members: true }) });
      if (!state.mounted) return;
      state.saving = false;
      state.drawer = '';
      state.notice = 'RAID 删除任务已提交';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      if (!state.mounted) return;
      state.saving = false;
      state.notice = `删除失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  function onClick(event) {
    if (event.target.closest('[data-raid-close]')) { closeDrawer(); return; }
    if (event.target.closest('[data-raid-refresh]')) { load(true); return; }
    if (event.target.closest('[data-raid-create]')) { openCreate(); return; }
    if (event.target.closest('[data-raid-scan]')) { openRecovery(); return; }
    if (event.target.closest('[data-raid-save]')) { createRaid(); return; }
    if (event.target.closest('[data-raid-run-scan]')) { runScan(); return; }
    if (event.target.closest('[data-raid-delete]')) { deleteRaid(); return; }
    const detail = event.target.closest('[data-raid-detail]');
    if (detail) { openDetail(detail.dataset.raidDetail); return; }
    const recover = event.target.closest('[data-raid-recover]');
    if (recover) { recoverRaid(recover.dataset.raidRecover); return; }
    const action = event.target.closest('[data-raid-action]');
    if (action) runArrayAction(action.dataset.raidAction);
  }

  function onInput(event) {
    const search = event.target.closest('[data-raid-search]');
    if (search) { state.query = search.value; patchTable(); return; }
    const input = event.target.closest('[data-raid-draft]');
    if (!input || input.tagName === 'SELECT') return;
    state.editor[input.dataset.raidDraft] = input.value;
    const save = root?.querySelector('[data-raid-save]');
    if (save) save.disabled = !hasCapability('create') || state.saving || Boolean(createValidation());
  }

  function onChange(event) {
    const draft = event.target.closest('[data-raid-draft]');
    if (draft) {
      state.editor[draft.dataset.raidDraft] = draft.value;
      if (draft.dataset.raidDraft === 'level') render();
      return;
    }
    const member = event.target.closest('[data-raid-member]');
    if (member) {
      const id = member.dataset.raidMember;
      state.editor.members = member.checked ? [...new Set([...state.editor.members, id])] : state.editor.members.filter((value) => value !== id);
      render();
      return;
    }
    const format = event.target.closest('[data-raid-format]');
    if (format) state.editor.format = format.checked;
  }

  function onKeyDown(event) {
    if (event.key === 'Escape' && state.drawer) closeDrawer();
  }

  root?.addEventListener('click', onClick);
  root?.addEventListener('input', onInput);
  root?.addEventListener('change', onChange);
  document.addEventListener('keydown', onKeyDown);
  stage?.classList.add('is-storage-raid');
  render();
  load();

  return {
    refresh() { return load(true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      root?.removeEventListener('click', onClick);
      root?.removeEventListener('input', onInput);
      root?.removeEventListener('change', onChange);
      document.removeEventListener('keydown', onKeyDown);
      root?.replaceChildren();
      root?.classList.remove('route-workspace', 'policy-table-route-host', MODULE_CLASS);
      stage?.classList.remove('is-storage-raid');
    }
  };
}

export default { mount };
