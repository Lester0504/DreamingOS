import { mount } from '/plugins/native/storage-file-services.js?v=20261005-remote-share-ftp-01';

const root = document.documentElement;
const media = matchMedia('(prefers-color-scheme: dark)');
function theme() {
  let family = 'frosted-glass', preference = 'system';
  try {
    family = localStorage.getItem('dreamingwrt.web.themeFamily') || family;
    preference = localStorage.getItem('dreamingwrt.web.themePref') || preference;
    if (parent !== window && parent.location.origin === location.origin && parent.DWRT_DESKTOP_HOST) {
      root.dataset.desktopApp = 'true';
      family = parent.document.documentElement.dataset.themeFamily || family;
      root.dataset.themeResolved = parent.document.documentElement.dataset.themeResolved || 'light';
    } else root.dataset.themeResolved = preference === 'dark' || (preference === 'system' && media.matches) ? 'dark' : 'light';
  } catch (_) {}
  root.dataset.themeFamily = ['frosted-glass', 'liquid-glass', 'traditional'].includes(family) ? family : 'traditional';
}
theme();
addEventListener('storage', theme);
media.addEventListener('change', theme);
let observer;
try {
  if (parent !== window && parent.location.origin === location.origin) {
    observer = new MutationObserver(theme);
    observer.observe(parent.document.documentElement, { attributes: true, attributeFilter: ['data-theme-family', 'data-theme-resolved'] });
  }
} catch (_) {}
const kit = window.DWRT_UI_KIT;
const instance = mount({ root: document.getElementById('remoteShareRoot'), remoteShare: true, ui: kit || {} });
addEventListener('pagehide', () => {
  instance.unmount(); observer?.disconnect();
  removeEventListener('storage', theme); media.removeEventListener('change', theme);
}, { once: true });
