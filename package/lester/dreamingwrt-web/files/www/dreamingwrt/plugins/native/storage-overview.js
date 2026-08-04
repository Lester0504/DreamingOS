export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const formatBytes = utils.formatBytes || fallbackFormatBytes;
  const VERSION = '20260804-disk-charts-moved-01';
  const MODULE_CLASS = 'storage-overview-route-host';
  const stage = root?.closest('.console-stage');
  const RANGE_LABELS = { '1h': '近一小时', '1d': '近一天', '7d': '近七天' };
  const RANGE_ALIASES = { '1h': '1h', '1d': '1d', '7d': '1w' };
  const state = {
    mounted: true,
    seq: 0,
    loading: true,
    refreshing: false,
    loaded: false,
    error: '',
    range: '1h',
    data: emptyData(),
    pollTimer: 0
  };

  /*
   * 手动刷新按钮按用户第 9 条删除。占用率、I/O 与延迟三张图都是时序数据，
   * 所以补一条可见性受控的轮询，跟随当前选中的历史范围后台重取。
   */
  function startPolling() {
    stopPolling();
    state.pollTimer = window.setInterval(() => {
      if (!state.mounted) return;
      if (document.hidden) return;
      if (state.loading || state.refreshing) return;
      load(true);
    }, 20000);
  }

  function stopPolling() {
    if (!state.pollTimer) return;
    window.clearInterval(state.pollTimer);
    state.pollTimer = 0;
  }

  /*
   * 会话闸门适配器：见 dwrt-session-gate.js 的 DWRT_REQUEST。裸 fetch 会绕过 token 刷新，
   * 过期时并发请求集体拿 401，切走再切回来才恢复；走闸门可自动刷新并单次重试。
   */
  function sessionFetch(url, init = {}) {
    return window.DWRT_REQUEST ? window.DWRT_REQUEST.fetch(url, init) : fetch(url, init);
  }

  function emptyData() {
    return { disks: [], history: [], smart: [], summary: {}, aggregateOnly: false };
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
    for (const key of [...keys, 'items', 'rows', 'list', 'data', 'points']) if (Array.isArray(value[key])) return value[key];
    return [];
  }

  function payloadData(result) {
    if (!result || result.ok === false) return null;
    if ('data' in result && result.ok === true) return result.data || {};
    return result.data ?? result.body ?? result;
  }

  async function read(name, url) {
    if (typeof api.fetch === 'function') {
      const result = await api.fetch(name, `${url}${url.includes('?') ? '&' : '?'}_=${VERSION}`);
      if (!result?.ok) throw result?.error || new Error(`${name} API 不可用`);
      return result.data || {};
    }
    const response = await sessionFetch(`${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`, {
      credentials: 'same-origin', cache: 'no-store', headers: typeof api.authHeaders === 'function' ? api.authHeaders() : {}
    });
    const json = await response.json();
    if (!response.ok || json?.ok === false) throw new Error(firstText(json?.message, json?.error, `HTTP ${response.status}`));
    return payloadData(json) || {};
  }

  function normalizeDisk(item = {}, index = 0) {
    const id = firstText(item.id, item.uuid, item.device, item.path, item.name, `disk-${index + 1}`);
    const name = firstText(item.label, item.name, item.device, item.path, id);
    const total = finite(item.total_bytes, item.size_bytes, item.capacity_bytes, item.total, item.size);
    const used = finite(item.used_bytes, item.used, item.usage_bytes);
    const available = finite(item.available_bytes, item.free_bytes, item.available, item.free, total !== null && used !== null ? total - used : null);
    const usedPercent = finite(item.used_percent, item.usage_percent, item.percent, total && used !== null ? used / total * 100 : null);
    return {
      ...item, id, name, total, used, available, usedPercent,
      model: firstText(item.model, item.product),
      serial: firstText(item.serial, item.serial_number),
      transport: firstText(item.transport, item.tran, item.bus),
      smartStatus: firstText(item.smart_status, item.health, item.status),
      temperature: finite(item.temperature_c, item.temperature, item.temp_c)
    };
  }

  function normalizeHistoryPoint(point = {}, diskId = '') {
    return {
      ts: finite(point.ts, point.time, point.timestamp),
      diskId: firstText(point.disk_id, point.disk, point.device, point.name, diskId),
      usage: finite(point.used_percent, point.usage_percent, point.disk_percent, point.disk_avg, point.usage),
      read: finite(point.read_bps, point.read_bytes_per_second, point.read_rate, point.read),
      write: finite(point.write_bps, point.write_bytes_per_second, point.write_rate, point.write),
      readLatency: finite(point.read_latency_ms, point.await_read_ms, point.read_await_ms),
      writeLatency: finite(point.write_latency_ms, point.await_write_ms, point.write_await_ms)
    };
  }

  function normalizeOverview(payload = {}) {
    const source = payload.storage && typeof payload.storage === 'object' ? payload.storage : payload;
    const disks = asArray(source.disks, ['devices']).map(normalizeDisk);
    const history = [];
    asArray(source.history, ['metrics', 'points']).forEach((point) => history.push(normalizeHistoryPoint(point)));
    disks.forEach((disk) => asArray(disk.history, ['metrics', 'points']).forEach((point) => history.push(normalizeHistoryPoint(point, disk.id))));
    return {
      disks,
      history: history.filter((point) => point.ts !== null && point.diskId),
      smart: asArray(source.smart, ['smart_devices', 'smart_info']),
      summary: source.summary && typeof source.summary === 'object' ? source.summary : source,
      aggregateOnly: false
    };
  }

  function normalizeAggregate(healthPayload = {}, historyPayload = {}) {
    const system = healthPayload.system && typeof healthPayload.system === 'object' ? healthPayload.system : healthPayload;
    const total = finite(system.disk_total);
    const used = finite(system.disk_used);
    const available = total !== null && used !== null ? Math.max(0, total - used) : null;
    const disk = normalizeDisk({ id: 'system-storage', name: '系统存储', total_bytes: total, used_bytes: used, available_bytes: available, used_percent: finite(system.disk_percent, total && used !== null ? used / total * 100 : null) });
    const points = asArray(historyPayload, ['history']).map((point) => normalizeHistoryPoint(point, disk.id)).filter((point) => point.ts !== null && point.usage !== null);
    return { disks: total !== null ? [disk] : [], history: points, smart: [], summary: { total_bytes: total, used_bytes: used, available_bytes: available }, aggregateOnly: true };
  }

  async function load(background = false) {
    const seq = ++state.seq;
    if (background) state.refreshing = true; else state.loading = true;
    state.error = '';
    if (!background) render();
    try {
      let next;
      try {
        next = normalizeOverview(await read('storageOverview', `/api/v1/storage/overview?range=${encodeURIComponent(state.range)}`));
      } catch (overviewError) {
        const results = await Promise.allSettled([
          read('systemHealth', '/api/v1/system/health'),
          read('systemHealthHistory', `/api/v1/system/health/history?range=${encodeURIComponent(RANGE_ALIASES[state.range])}&aggregate=avg&points=120`)
        ]);
        if (results[0].status !== 'fulfilled') throw overviewError;
        next = normalizeAggregate(results[0].value, results[1].status === 'fulfilled' ? results[1].value : {});
        state.error = '后端暂未提供逐盘 I/O、延迟和 SMART 数据，当前仅显示系统存储聚合占用率。';
      }
      if (!state.mounted || seq !== state.seq) return;
      state.data = next;
      state.loaded = true;
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.data = emptyData();
      state.error = '存储概览后端接口暂不可用。';
    } finally {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      render();
    }
  }

  function icon(name) {
    const paths = {
      disk: '<ellipse cx="12" cy="6" rx="8" ry="3"></ellipse><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"></path>',
      layers: '<path d="m12 2 9 5-9 5-9-5 9-5Z"></path><path d="m3 12 9 5 9-5M3 17l9 5 9-5"></path>',
      available: '<path d="M12 2a10 10 0 1 0 10 10"></path><path d="M12 6v6l4 2M16 2h6v6"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      usage: '<path d="M4 19V9M10 19V5M16 19v-7M22 19V3"></path>',
      io: '<path d="M4 7h13m0 0-4-4m4 4-4 4M20 17H7m0 0 4 4m-4-4 4-4"></path>',
      latency: '<circle cx="12" cy="12" r="9"></circle><path d="M12 7v5l3 2"></path>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.disk}</svg>`;
  }

  function summaryValues() {
    const declared = state.data.summary || {};
    const known = state.data.disks.filter((disk) => disk.total !== null);
    const total = finite(declared.total_bytes, declared.total, known.length ? known.reduce((sum, disk) => sum + (disk.total || 0), 0) : null);
    const available = finite(declared.available_bytes, declared.free_bytes, declared.available, known.length ? known.reduce((sum, disk) => sum + (disk.available || 0), 0) : null);
    return { count: state.data.aggregateOnly ? null : finite(declared.disk_count, declared.count, state.data.disks.length || null), total, available };
  }

  function summaryMarkup() {
    const values = summaryValues();
    const renderer = ui.overviewCardsMarkup || window.DWRT_UI_KIT?.overviewCardsMarkup;
    const cards = [
      { key: 'count', label: '硬盘', value: values.count === null ? '--' : String(values.count), detail: values.count === null ? '等待逐盘清单' : '已识别物理磁盘', tone: 'info', icon: icon('disk') },
      { key: 'total', label: '总容量', value: values.total === null ? '--' : formatBytes(values.total), detail: '所有已识别磁盘', tone: 'ok', icon: icon('layers') },
      { key: 'available', label: '可用空间', value: values.available === null ? '--' : formatBytes(values.available), detail: '当前可分配容量', tone: 'info', icon: icon('available') }
    ];
    return typeof renderer === 'function'
      ? renderer(cards, { label: '存储概览', className: 'storage-overview-summary' })
      : `<section class="dwrt-kit-overview-grid storage-overview-summary">${cards.map((card) => `<article class="dwrt-kit-overview-card is-${card.tone}"><div class="dwrt-kit-overview-content"><span class="dwrt-kit-overview-label">${card.label}</span><strong>${card.value}</strong><small>${card.detail}</small></div><span class="dwrt-kit-overview-icon">${card.icon}</span></article>`).join('')}</section>`;
  }




  function smartMarkup() {
    const rows = state.data.smart.length ? state.data.smart : state.data.disks.filter((disk) => disk.smartStatus || disk.temperature !== null);
    return `<section class="storage-smart-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>SMART 信息</strong><span>磁盘健康、温度与寿命指标</span></div><span class="dwrt-kit-table-count">${state.data.smart.length ? `${state.data.smart.length} 块` : '--'}</span></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table storage-smart-table"><thead><tr><th>磁盘</th><th>型号</th><th>序列号</th><th>接口</th><th>健康</th><th>温度</th><th>通电时间</th><th>坏扇区</th></tr></thead><tbody>${rows.length ? rows.map((item, index) => { const disk = normalizeDisk(item, index); const healthy = /pass|healthy|good|ok|正常/i.test(disk.smartStatus); return `<tr><td><strong>${escapeHtml(disk.name)}</strong></td><td>${escapeHtml(disk.model || '--')}</td><td><code>${escapeHtml(disk.serial || '--')}</code></td><td>${escapeHtml(disk.transport || '--')}</td><td>${ui.statusBadgeMarkup?.(disk.smartStatus || '--', healthy ? 'success' : 'error') || escapeHtml(disk.smartStatus || '--')}</td><td>${disk.temperature === null ? '--' : `${disk.temperature} °C`}</td><td>${escapeHtml(firstText(item.power_on_hours, item.power_hours, '--'))}</td><td>${escapeHtml(firstText(item.reallocated_sector_count, item.bad_sectors, '--'))}</td></tr>`; }).join('') : `<tr><td colspan="8" class="dwrt-kit-table-empty">后端尚未提供 SMART 信息</td></tr>`}</tbody></table></div></section>`;
  }

  function render() {
    if (!root) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', MODULE_CLASS);
    const notice = state.error ? `<div class="storage-overview-notice">${escapeHtml(state.error)}</div>` : '';
    /* 用户第 14 条：I/O 与读写延迟两张图搬到监控中心 - 系统健康（那边是时序图
       的归属地，且有范围/峰值工具栏），占用率变化整张删除。范围按钮随之删除：
       概览剩下的容量卡与 SMART 表都不是时序数据，范围对它们没有意义。 */
    root.innerHTML = `<section class="storage-overview-shell"><main class="storage-overview-scroll">${notice}${summaryMarkup()}${smartMarkup()}</main></section>`;
    ui.mountAll?.(root);
  }


  function formatTime(value) {
    const raw = Number(value);
    const date = new Date(raw > 1e12 ? raw : raw * 1000);
    if (!Number.isFinite(date.getTime())) return '--';
    const options = state.range === '1h' ? { hour: '2-digit', minute: '2-digit' } : { month: '2-digit', day: '2-digit', hour: '2-digit' };
    return new Intl.DateTimeFormat('zh-CN', { ...options, hour12: false }).format(date);
  }




  function fallbackFormatBytes(value) {
    const bytes = Math.max(0, Number(value) || 0);
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let current = bytes; let index = 0;
    while (current >= 1024 && index < units.length - 1) { current /= 1024; index += 1; }
    return `${current.toFixed(current >= 100 || index === 0 ? 0 : current >= 10 ? 1 : 2)} ${units[index]}`;
  }

  function compactBytes(value) {
    return fallbackFormatBytes(value).replace(' ', '');
  }



  stage?.classList.add('is-storage-overview');
  render();
  load();
  startPolling();

  return {
    refresh() { return load(true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      stopPolling();
      root?.replaceChildren();
      root?.classList.remove('route-workspace', MODULE_CLASS);
      stage?.classList.remove('is-storage-overview');
    }
  };
}

export default { mount };
