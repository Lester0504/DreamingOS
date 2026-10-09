/* File and NAS pages consume the desktop's theme without adding another material. */
(() => {
  'use strict';
  const root = document.documentElement;
  const families = ['frosted-glass', 'liquid-glass', 'traditional'];
  const darkMode = matchMedia('(prefers-color-scheme: dark)');
  let host = null;
  try {
    if (parent !== window && parent.location.origin === location.origin && parent.DWRT_DESKTOP_HOST) {
      host = parent.document.documentElement;
      window.DWRT_SESSION = parent.DWRT_SESSION;
      root.dataset.desktopApp = 'true';
    }
  } catch (_) {}
  function theme() {
    let family = 'frosted-glass', pref = 'system';
    try {
      family = localStorage.getItem('dreamingwrt.web.themeFamily') || family;
      pref = localStorage.getItem('dreamingwrt.web.themePref') || pref;
    } catch (_) {}
    if (host) {
      family = host.dataset.themeFamily || family;
      pref = host.dataset.themePref || pref;
      // A different document scheme makes the browser paint an opaque iframe canvas.
      // Controls receive their resolved scheme from body instead.
      root.style.colorScheme = parent.getComputedStyle(window.frameElement).colorScheme;
    }
    root.dataset.themeFamily = families.includes(family) ? family : 'frosted-glass';
    root.dataset.themePref = pref;
    root.dataset.themeResolved = host?.dataset.themeResolved ||
      (pref === 'dark' || (pref === 'system' && darkMode.matches) ? 'dark' : 'light');
  }
  const observer = host ? new MutationObserver(theme) : null;
  function connect() {
    theme();
    observer?.observe(host, {attributes:true, attributeFilter:[
      'data-theme-family', 'data-theme-pref', 'data-theme-resolved', 'class', 'style'
    ]});
  }
  connect();
  addEventListener('storage', theme);
  darkMode.addEventListener('change', theme);
  addEventListener('pagehide', () => observer?.disconnect());
  addEventListener('pageshow', connect);
  // The shared directory picker embeds an existing console page in these tools.
  window.DWRT_DESKTOP_HOST = true;
})();
