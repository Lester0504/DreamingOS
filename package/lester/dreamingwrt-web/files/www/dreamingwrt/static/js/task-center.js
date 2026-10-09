(() => {
  'use strict';
  const SOURCES = [
    { key: 'ota.task', label: 'OTA', url: '/api/v1/system/ota/task' },
    { key: 'wifi.task', label: 'Wi-Fi 配置', url: '/api/v1/wifi/tasks' }
  ];
  const ACTIVE = new Set(['pending', 'in_progress', 'cooldown']);
  const STATES = { idle: '待命', pending: '等待执行', in_progress: '进行中', cooldown: '等待重启确认', success: '已完成', failed: '失败', rolled_back: '已回滚' };
  const RETENTION_MS = 86400000;
  const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

  class TaskCenterStore {
    constructor(clock = Date.now) { this.clock = clock; this.tasks = new Map(); this.terminalTimes = new Map(); this.sources = new Map(); }
    accept(source, envelope) {
      if (envelope?.ok === false) throw new Error(envelope.error?.message || envelope.error?.code || '任务来源返回错误');
      const data = envelope?.data ?? envelope;
      const rows = Array.isArray(data?.tasks) ? data.tasks : data?.task_id ? [data] : [];
      const time = this.clock();
      const received = new Set();
      rows.forEach(row => {
        const id = String(row.task_id ?? '');
        if (!id || row.state === 'idle' && !Number(row.started_at)) return;
        const key = `${source.key}:${id}`;
        const previous = this.tasks.get(key);
        const state = Object.hasOwn(STATES, row.state) ? row.state : 'unknown';
        const rawProgress = row.progress;
        const progress = rawProgress == null || rawProgress === '' ? null : Number(rawProgress);
        const terminal = !ACTIVE.has(state) && state !== 'unknown' && state !== 'idle';
        const finishedAt = terminal ? Number(row.completed_at || row.updated_at) * 1000 || this.terminalTimes.get(key) || previous?.finishedAt || time : 0;
        if (terminal) this.terminalTimes.set(key, finishedAt);
        else this.terminalTimes.delete(key);
        this.tasks.set(key, { key, id, source: source.key, label: source.label, state,
          progress: Number.isFinite(progress) && progress >= 0 && progress <= 100 ? progress : null,
          message: String(row.message || row.error?.message || row.error?.code || ''),
          startedAt: Number(row.started_at) || 0, finishedAt, seenAt: time, stale: envelope?.meta?.stale === true });
        received.add(key);
      });
      this.tasks.forEach(task => { if (task.source === source.key && !received.has(task.key)) task.stale = true; });
      this.sources.set(source.key, { label: source.label, ok: true, count: rows.length, truncated: data?.truncated === true });
      this.prune();
    }
    fail(source, error) {
      this.sources.set(source.key, { label: source.label, ok: false, message: error.message || String(error) });
      this.tasks.forEach(task => { if (task.source === source.key) task.stale = true; });
    }
    prune() {
      const time = this.clock();
      this.tasks.forEach((task, key) => {
        if (task.finishedAt && time - task.finishedAt > RETENTION_MS || time - task.seenAt > RETENTION_MS) this.tasks.delete(key);
      });
    }
    list() {
      this.prune();
      return [...this.tasks.values()].sort((a, b) => Number(ACTIVE.has(b.state)) - Number(ACTIVE.has(a.state)) || b.startedAt - a.startedAt || a.key.localeCompare(b.key));
    }
  }
  window.DWRTTaskCenterStore = TaskCenterStore;
  if (typeof document === 'undefined') return;

  const store = new TaskCenterStore();
  let busy = false;
  let layer = null;
  let renderKey = '';
  let timer = 0;
  let returnFocus = null;
  function token() {
    try { return window.DWRT_SESSION?.tokens().access || localStorage.getItem('dreamingwrt.web.accessToken') || ''; } catch (_) { return ''; }
  }
  async function readSource(source) {
    const response = window.DWRT_SESSION?.fetch
      ? await window.DWRT_SESSION.fetch(source.url, { credentials: 'same-origin', cache: 'no-store' })
      : await fetch(source.url, { credentials: 'same-origin', cache: 'no-store', headers: { Authorization: `Bearer ${token()}` } });
    let payload;
    try { payload = await response.json(); } catch (_) { throw new Error(`HTTP ${response.status}：任务响应不可读`); }
    if (!response.ok || payload?.ok === false) {
      const detail = payload?.error || payload?.data?.error;
      const text = response.status === 401 ? '会话已失效' : response.status === 403 ? '没有读取权限'
        : [404, 405, 501].includes(response.status) ? '任务接口尚未接入' : '任务来源暂不可用';
      throw new Error(`${text}${detail?.code ? ` (${detail.code})` : ''}`);
    }
    window.DWRT_DATA_REGISTRY?.accept?.(source.key, payload);
    store.accept(source, payload);
  }
  async function poll() {
    if (busy || document.hidden) return;
    if (!token()) {
      store.tasks.clear(); store.terminalTimes.clear(); store.sources.clear(); render(); return;
    }
    busy = true;
    await Promise.all(SOURCES.map(source => readSource(source).catch(error => store.fail(source, error))));
    busy = false; render();
  }
  function render() {
    const tasks = store.list();
    const count = tasks.filter(task => ACTIVE.has(task.state)).length;
    const button = document.getElementById('dwrtTaskCenterButton');
    if (button) {
      button.textContent = count ? `任务 ${count}` : '任务';
      button.setAttribute('aria-label', count ? `任务中心，${count} 项进行中` : '任务中心');
    }
    if (!layer || layer.hidden) return;
    const signature = JSON.stringify([tasks, [...store.sources]]);
    if (signature === renderKey) return;
    const selection = window.getSelection();
    if (selection && !selection.isCollapsed && layer.contains(selection.anchorNode)) return;
    renderKey = signature;
    const body = layer.querySelector('[data-task-body]');
    const sources = SOURCES.map(source => {
      const status = store.sources.get(source.key);
      return `<p class="task-center-source${status?.ok === false ? ' is-error' : ''}">${escapeHtml(source.label)}：${escapeHtml(!status ? '正在读取' : !status.ok ? status.message : status.truncated ? '已显示最近 64 项' : '已更新')}</p>`;
    }).join('');
    const scrollTop = body.scrollTop;
    body.innerHTML = `${sources}${tasks.length ? `<ol class="task-center-list">${tasks.map(task => `<li class="task-center-row" data-task-id="${escapeHtml(task.key)}"><header><strong>${escapeHtml(task.label)}</strong><span>${escapeHtml(STATES[task.state] || '状态未知')}${task.stale ? ' · 数据待更新' : ''}</span></header>${task.progress === null ? (ACTIVE.has(task.state) ? '<p>进度尚未上报</p>' : '') : `<progress max="100" value="${task.progress}" aria-label="${escapeHtml(task.label)}进度 ${task.progress}%"></progress><small>${task.progress}%</small>`}${task.message ? `<p>${escapeHtml(task.message)}</p>` : ''}<time>${task.startedAt ? escapeHtml(new Date(task.startedAt * 1000).toLocaleString('zh-CN', { hour12: false })) : '开始时间未提供'}</time></li>`).join('')}</ol>` : '<p class="task-center-empty">暂无任务。已完成与失败的任务最多保留 24 小时。</p>'}`;
    body.scrollTop = scrollTop;
  }
  function close() {
    if (!layer) return;
    layer.hidden = true; layer.classList.remove('is-open');
    document.getElementById('dwrtTaskCenterButton')?.setAttribute('aria-expanded', 'false');
    returnFocus?.focus();
  }
  function open() {
    returnFocus = document.activeElement;
    if (!layer) {
      layer = document.createElement('div');
      layer.className = 'dwrt-kit-modal-layer task-center-layer';
      layer.innerHTML = '<button class="dwrt-kit-modal-backdrop" type="button" data-task-close aria-label="关闭任务中心"></button><section class="dwrt-kit-modal dwrt-kit-glass-surface" data-dwrt-component="modal" role="dialog" aria-modal="true" aria-labelledby="dwrtTaskCenterTitle"><header class="dwrt-kit-modal-header"><h2 id="dwrtTaskCenterTitle">任务中心</h2><button class="dwrt-kit-modal-close" type="button" data-task-close aria-label="关闭">×</button></header><div class="dwrt-kit-modal-body" data-task-body></div><footer class="dwrt-kit-modal-footer"><span>仅查看任务；关闭此面板不会取消后台操作。</span></footer></section>';
      layer.addEventListener('click', event => { if (event.target.closest('[data-task-close]')) close(); });
      layer.addEventListener('keydown', event => {
        if (event.key === 'Escape') { event.preventDefault(); close(); }
        if (event.key === 'Tab') { event.preventDefault(); layer.querySelector('.dwrt-kit-modal-close').focus(); }
      });
      document.body.appendChild(layer);
    }
    layer.hidden = false; layer.classList.add('is-open'); renderKey = ''; render();
    window.DWRT_UI_KIT?.mountAll(layer);
    document.getElementById('dwrtTaskCenterButton')?.setAttribute('aria-expanded', 'true');
    layer.querySelector('.dwrt-kit-modal-close').focus();
    poll();
  }
  function init() {
    document.getElementById('dwrtTaskCenterButton')?.addEventListener('click', open);
    poll(); timer = window.setInterval(poll, 5000);
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
  window.addEventListener('pagehide', () => window.clearInterval(timer), { once: true });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true }); else init();
})();
