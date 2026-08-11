(function () {
  'use strict';

  const VERSION = '20260810-insights-audit-poll-stability-02';
  const STORAGE = Object.freeze({
    menu: 'dreamingwrt.shellWarm.menu.v4',
    theme: 'dreamingwrt.shellWarm.theme.v2'
  });
  const MAX_AGE_MS = 10 * 60 * 1000;
  const STATIC_RESOURCES = Object.freeze([
    '/app/index.html',
    '/static/ui-kit/dwrt-ui-kit.css?v=20260810-front-release-01',
    '/static/ui-kit/dwrt-sampled-liquid-glass.css?v=20260810-front-release-01',
    '/static/css/menu-shell.css?v=20260810-insights-audit-poll-stability-02',
    '/static/css/dwrt-theme.css?v=20260722-03',
    '/static/ui-kit/dwrt-control-material.css?v=20260719-16',
    '/static/js/menu-icons.js?v=20260722-auth-control-01',
    '/static/js/device-images.js?v=20260723-airview-radio-sheet-01',
    '/static/ui-kit/dwrt-sampled-liquid-glass.js?v=20260810-front-release-01',
    '/static/ui-kit/lucide.min.js?v=1.25.0',
    '/static/ui-kit/dwrt-ui-kit.js?v=20260810-front-release-01',
    '/static/js/dwrt-session-gate.js?v=20260808-region-ink-uses-painted-density-01',
    '/static/js/dwrt-data-registry.js?v=20260721-02',
    '/static/js/dwrt-conn-truth.js?v=20260809-remove-kernel-forward-conn-01',
    '/static/js/menu-shell.js?v=20260810-insights-audit-poll-stability-02'
  ]);

  function write(key, value) {
    try {
      sessionStorage.setItem(key, JSON.stringify({ version: VERSION, at: Date.now(), value }));
    } catch (_) {}
  }

  function read(key) {
    try {
      const record = JSON.parse(sessionStorage.getItem(key) || 'null');
      if (!record || record.version !== VERSION || Date.now() - Number(record.at || 0) > MAX_AGE_MS) return null;
      return record.value;
    } catch (_) {
      return null;
    }
  }

  async function fetchJson(url, key) {
    const response = await fetch(`${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`, {
      credentials: 'same-origin',
      cache: 'force-cache',
      headers: { Accept: 'application/json' }
    });
    if (!response.ok) return;
    write(key, await response.json());
  }

  function themeSnapshot(data) {
    const source = data && data.data ? data.data : data;
    if (!source || typeof source !== 'object') return null;
    return {
      material_glass: source.material_glass || null,
      selected: source.selected || null,
      opacity: source.opacity ?? 1
    };
  }

  function writeThemeSnapshot(data) {
    const snapshot = themeSnapshot(data);
    if (snapshot) write(STORAGE.theme, snapshot);
  }

  function addResourceHint(url) {
    const exists = Array.from(document.head.querySelectorAll('link[rel="prefetch"]'))
      .some((link) => link.getAttribute('href') === url);
    if (exists) return;
    const link = document.createElement('link');
    link.rel = 'prefetch';
    link.href = url;
    if (/\.css(?:\?|$)/.test(url)) link.as = 'style';
    else if (/\.js(?:\?|$)/.test(url)) link.as = 'script';
    else if (/\.html(?:\?|$)/.test(url)) link.as = 'document';
    document.head.appendChild(link);
  }

  function prewarmDisplacementMap() {
    const glass = window.DWRTSampledLiquidGlass;
    if (!glass || typeof glass.prewarm !== 'function') return;
    glass.prewarm({
      width: 278,
      height: Math.max(240, window.innerHeight),
      mode: 'shader',
      preserveCenter: true,
      mapResolution: 0.25
    });
  }

  function run() {
    STATIC_RESOURCES.forEach(addResourceHint);
    Promise.allSettled([
      fetchJson('/static/menu/main.json', STORAGE.menu)
    ]).catch(() => {});
    prewarmDisplacementMap();
    try {
      sessionStorage.setItem('dreamingwrt.shellWarm.ready', JSON.stringify({ version: VERSION, at: Date.now() }));
    } catch (_) {}
  }

  function schedule() {
    if (typeof requestIdleCallback === 'function') requestIdleCallback(run, { timeout: 1800 });
    else window.setTimeout(run, 650);
  }

  window.DWRTShellPrewarm = { version: VERSION, keys: STORAGE, read, run, schedule, writeThemeSnapshot };
})();
