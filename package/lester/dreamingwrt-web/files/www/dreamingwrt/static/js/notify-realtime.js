(() => {
  'use strict';

  const seen = new Set();
  const startedAtSec = Math.floor(Date.now() / 1000);
  let subscribed = false;

  function severityToType(severity) {
    const value = String(severity || '').toLowerCase();
    if (value === 'error' || value === 'critical' || value === 'fatal') return 'error';
    if (value === 'warning' || value === 'warn') return 'warning';
    if (value === 'success' || value === 'done' || value === 'completed') return 'success';
    return 'info';
  }

  function itemTime(item) {
    return Number(item?.updated_at || item?.created_at || item?.ts || 0);
  }

  function itemDescription(item) {
    const payload = item?.payload && typeof item.payload === 'object' ? item.payload : {};
    const detail = payload.detail_json && typeof payload.detail_json === 'object' ? payload.detail_json : {};
    return String(payload.message || item?.message || detail.message || detail.reason || item?.event || '');
  }

  function showItem(item) {
    const notify = window.DreamingWrtNotify;
    if (!notify || !item || typeof item !== 'object') return;
    const id = String(item.id || item.event_id || '');
    if (!id || seen.has(id)) return;
    seen.add(id);
    if (itemTime(item) && itemTime(item) < startedAtSec - 2) return;
    const type = severityToType(item.severity);
    const title = String(item.title || item.event || '系统通知');
    notify.show(type, title, itemDescription(item), { duration: type === 'error' ? 7200 : 5200 });
  }

  function rememberSnapshot(items) {
    items.forEach((item) => {
      if (item && item.id) seen.add(String(item.id));
    });
  }

  function handleNotifications(data, message) {
    const items = Array.isArray(data?.items)
      ? data.items
      : (Array.isArray(data?.notifications) ? data.notifications : []);
    if (!items.length) return;
    if (message?.type === 'snapshot') {
      rememberSnapshot(items);
      return;
    }
    items.forEach(showItem);
  }

  function subscribe() {
    if (subscribed) return;
    if (!window.DWRTRealtime || typeof window.DWRTRealtime.subscribe !== 'function') return;
    subscribed = true;
    window.DWRTRealtime.subscribe('notifications', handleNotifications);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', subscribe, { once: true });
  } else {
    subscribe();
  }
  window.addEventListener('dwrt-realtime-status', subscribe);
})();
