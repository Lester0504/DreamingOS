(() => {
  'use strict';
  // Only the outer shell receives; registry and app iframes share its inbox.
  if (window.top !== window || !window.DWRTAnnouncementState) return;
  const base = 'https://update-os.dreamingnet.com/v1/announcements';
  const labels = { info: '信息', warning: '警告', danger: '紧急' };
  const state = new window.DWRTAnnouncementState.State();
  let user = '', storageKey = '', source = null, request = null, timer = null;
  let selected = null, error = '', button = null, toast = null, toastKey = '';
  let paused = false;
  const dialog = document.createElement('dialog');
  dialog.className = 'cloud-announcements dwrt-kit-modal';
  dialog.setAttribute('aria-label', '公告');
  document.body.append(dialog);
  function node(tag, text, cls) {
    const el = document.createElement(tag);
    if (text !== undefined) el.textContent = text;
    if (cls) el.className = cls;
    return el;
  }
  function action(text, fn, cls) {
    const el = node('button', text, cls);
    el.type = 'button'; el.addEventListener('click', fn);
    return el;
  }
  function load() {
    try { state.preferences = JSON.parse(localStorage.getItem(storageKey) || '{}') || {}; }
    catch (_) { state.preferences = {}; }
  }
  function save() {
    try { localStorage.setItem(storageKey, JSON.stringify(state.preferences)); }
    catch (_) { error = '已读状态无法保存到此浏览器'; }
  }
  function clearToast() { toast?.remove(); toast = null; toastKey = ''; }
  function open(id) {
    if (!user) return;
    selected = id || null;
    const item = state.items.find((item) => item.id === selected);
    if (item) { state.read(item); save(); clearToast(); }
    render();
    if (!dialog.open) dialog.showModal();
  }
  function render() {
    const detail = state.items.find((item) => item.id === selected);
    if (!detail) selected = null;
    dialog.replaceChildren();
    const head = node('header');
    head.append(node('h2', detail ? '公告详情' : '公告'));
    head.append(action('关闭', () => dialog.close()));
    dialog.append(head);
    if (detail) {
      dialog.append(action('返回公告', () => { selected = null; render(); }));
      dialog.append(node('p', labels[detail.type], `cloud-level cloud-level--${detail.type}`));
      dialog.append(node('h3', detail.title));
      const content = node('div', detail.content, 'cloud-announcements-content');
      content.tabIndex = 0;
      dialog.append(content);
    } else {
      const settings = node('div', undefined, 'cloud-announcements-tools');
      const label = node('label');
      const mute = node('input');
      mute.type = 'checkbox'; mute.checked = state.preferences.muted === true;
      mute.addEventListener('change', () => {
        state.preferences.muted = mute.checked; save(); clearToast(); render();
      });
      label.append(mute, document.createTextNode('静音公告提醒'));
      settings.append(label, action('全部已读', () => {
        state.items.forEach((item) => state.read(item)); save(); clearToast(); render();
      }));
      dialog.append(settings);
      if (error) {
        const status = node('div', undefined, 'cloud-announcements-status');
        status.append(node('span', error), action('重试', () => refresh()));
        dialog.append(status);
      }
      const list = node('div', undefined, 'cloud-announcements-list');
      if (!state.items.length) list.append(node('p', state.revision < 0 ? '正在加载公告' : '暂无公告'));
      state.items.forEach((item) => {
        const row = action('', () => open(item.id), 'cloud-announcements-row');
        row.append(node('span', `${labels[item.type]} · ${state.isRead(item) ? '已读' : '未读'}`, `cloud-level cloud-level--${item.type}`));
        row.append(node('strong', item.title));
        list.append(row);
      });
      dialog.append(list);
    }
    updateEntry();
  }
  function updateEntry() {
    const label = `公告${state.unread.length ? `（${state.unread.length} 条未读）` : ''}`;
    [button, ...document.querySelectorAll('[data-cloud-announcements]')].filter(Boolean).forEach((entry) => {
      entry.title = label; entry.setAttribute('aria-label', label);
      entry.dataset.unread = String(state.unread.length > 0);
      entry.hidden = !user;
    });
    const drawer = document.getElementById('desktopDrawer');
    if (drawer?.dataset.kind === 'notifications' && !drawer.hidden) {
      let entry = drawer.querySelector('.cloud-announcements-entry');
      if (!entry) {
        entry = action(label, () => open(), 'cloud-announcements-entry');
        drawer.append(entry);
      } else if (entry.textContent !== label) entry.textContent = label;
    }
  }
  function notify() {
    if (state.preferences.muted || dialog.open || document.hidden) return;
    const item = state.unread.find((item) => state.preferences.presented?.[item.id] !== item.revision);
    if (!item || toast?.isConnected) return;
    state.preferences.presented = { ...state.preferences.presented, [item.id]: item.revision };
    save();
    toastKey = `${item.id}:${item.revision}`;
    toast = window.DreamingWrtNotify?.show(item.type, `${labels[item.type]} · ${item.title}`, '', {
      duration: item.type === 'danger' ? 15000 : item.type === 'warning' ? 9000 : 5000
    });
    if (toast) {
      const view = action('查看公告', () => open(item.id), 'cloud-announcements-view');
      toast.querySelector('.dwrt-notify__body')?.append(view);
    }
  }
  function receive(value) {
    const previous = state.revision;
    const hadError = Boolean(error);
    if (!state.replace(value)) return;
    error = '';
    if (previous === state.revision && !hadError) return;
    if (!state.items.some((item) => `${item.id}:${item.revision}` === toastKey)) clearToast();
    // An edited detail must be opened explicitly before the new revision is read.
    if (selected && !state.items.some((item) => item.id === selected && state.isRead(item))) selected = null;
    render(); notify();
  }
  async function refresh() {
    if (!user || document.hidden || paused || request) return;
    const controller = new AbortController();
    request = controller;
    const timeout = setTimeout(() => controller.abort(), 12000);
    try {
      const response = await fetch(`${base}?target=router`, {
        credentials: 'omit', cache: 'no-store', signal: controller.signal, headers: { Accept: 'application/json' }
      });
      if (!response.ok) throw new Error('http');
      const body = await response.json();
      if (body.ok !== true) throw new Error('envelope');
      if (request === controller) receive(body.data);
    } catch (_) {
      if (request === controller && !document.hidden && !paused) { error = '公告连接失败，保留上次内容'; render(); }
    } finally {
      clearTimeout(timeout);
      if (request === controller) request = null;
    }
  }
  function stop() {
    source?.close(); source = null;
    request?.abort(); request = null;
    clearInterval(timer); timer = null; clearToast();
  }
  function sync() {
    const gate = window.DWRT_SESSION;
    const tokens = gate?.tokens();
    const next = !gate?.required && tokens?.access ? tokens.username || 'local' : '';
    if (next !== user) {
      stop(); dialog.close(); selected = null; user = next;
      storageKey = `dreamingwrt.cloud-announcements.v1.${user}`;
      state.revision = -1; state.items = []; error = ''; load(); render();
    }
    if (button) button.hidden = !user;
    if (!user || document.hidden || paused) { stop(); return; }
    if (!timer) { refresh(); timer = setInterval(() => { sync(); refresh(); notify(); }, 30000); }
    if (!source && typeof EventSource !== 'undefined') {
      source = new EventSource(`${base}/stream?target=router`);
      const current = source;
      current.addEventListener('announcements', (event) => {
        if (source !== current || document.hidden || paused) return;
        try { receive(JSON.parse(event.data)); }
        catch (_) { error = '公告数据无效，保留上次内容'; render(); }
      });
      current.onerror = () => {
        if (source === current) { error = '公告重连中'; render(); }
      };
    }
  }
  const actions = document.querySelector('.sidebar-actions');
  if (actions) {
    button = action('', () => open(), 'sidebar-action cloud-announcements-bell');
    button.innerHTML = window.DWRT_MENU_ICON?.system_notifications || '';
    actions.prepend(button);
  }
  const drawer = document.getElementById('desktopDrawer');
  if (drawer) new MutationObserver(updateEntry).observe(drawer, { childList: true, attributes: true, attributeFilter: ['hidden', 'data-kind'] });
  else {
    // Older desktop builds have no drawer; use their existing utility controls.
    const legacyEntries = () => {
      for (const [id, selector, cls] of [
        ['desktopDock', null, 'dock-item'],
        ['desktopSidebar', '.sidebar-utilities', 'sidebar-item'],
      ]) {
        const container = document.getElementById(id);
        const target = selector ? container?.querySelector(selector) : container;
        if (!target || target.querySelector('[data-cloud-announcements]')) continue;
        const entry = action('', () => open(), `${cls} cloud-announcements-launcher`);
        entry.dataset.cloudAnnouncements = 'true';
        entry.innerHTML = `<span class="app-glyph" aria-hidden="true">${window.DWRT_MENU_ICON?.system_notifications || ''}</span><span class="app-label">公告</span>`;
        target.append(entry);
      }
      updateEntry();
    };
    ['desktopDock', 'desktopSidebar'].forEach((id) => {
      const container = document.getElementById(id);
      if (container) new MutationObserver(legacyEntries).observe(container, { childList: true, subtree: true });
    });
    legacyEntries();
  }
  window.addEventListener('storage', (event) => {
    if (event.key === storageKey) { load(); clearToast(); render(); }
    else if (event.key?.startsWith('dreamingwrt.web.')) sync();
  });
  window.addEventListener('dwrt-session-required', sync);
  window.addEventListener('dwrt-session-restored', sync);
  document.addEventListener('visibilitychange', sync);
  window.addEventListener('online', () => { sync(); refresh(); });
  window.addEventListener('pagehide', () => { paused = true; stop(); });
  window.addEventListener('pageshow', () => { paused = false; sync(); });
  window.DWRTCloudAnnouncements = { open };
  updateEntry();
  sync();
})();
