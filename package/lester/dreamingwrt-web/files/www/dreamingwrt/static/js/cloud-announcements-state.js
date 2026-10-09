(function (root) {
  'use strict';
  const levels = { info: 0, warning: 1, danger: 2 };
  function snapshot(value, target = 'router') {
    if (!value || !Number.isSafeInteger(value.revision) || value.revision < 0 || !Array.isArray(value.announcements)) {
      throw new Error('Invalid announcement snapshot');
    }
    const ids = new Set();
    const items = value.announcements.map((item) => {
      if (!item || typeof item.id !== 'string' || !item.id || ids.has(item.id) ||
          !Number.isSafeInteger(item.revision) || item.revision < 1 || item.revision > value.revision ||
          typeof item.title !== 'string' || !item.title.trim() ||
          typeof item.content !== 'string' || !item.content.trim() ||
          !Object.hasOwn(levels, item.type) || typeof item.published !== 'boolean' ||
          !Array.isArray(item.targets) || !item.targets.every((t) => ['router', 'android', 'ios', 'tv'].includes(t))) {
        throw new Error('Invalid announcement');
      }
      ids.add(item.id);
      return { ...item };
    }).filter((item) => item.published && item.targets.includes(target));
    items.sort((a, b) => levels[b.type] - levels[a.type] || b.revision - a.revision);
    return { revision: value.revision, announcements: items };
  }
  class State {
    constructor(preferences = {}) {
      this.revision = -1;
      this.items = [];
      this.preferences = preferences;
    }
    replace(value) {
      const next = snapshot(value);
      if (next.revision < this.revision) return false;
      this.revision = next.revision;
      this.items = next.announcements;
      return true;
    }
    isRead(item) { return this.preferences.read?.[item.id] === item.revision; }
    read(item) {
      this.preferences.read = { ...this.preferences.read, [item.id]: item.revision };
    }
    get unread() { return this.items.filter((item) => !this.isRead(item)); }
  }
  const api = { snapshot, State };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.DWRTAnnouncementState = api;
})(typeof window === 'undefined' ? globalThis : window);
