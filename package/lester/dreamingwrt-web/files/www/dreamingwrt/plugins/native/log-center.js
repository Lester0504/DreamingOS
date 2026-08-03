const LEGACY_CONTROLLER_URL = '/static/js/log-center.js?v=20260802-ui-batch-01';

let controllerPromise = null;

function firstText(...values) {
  for (const value of values) {
    if (value === undefined || value === null) continue;
    const text = String(value).trim();
    if (text) return text;
  }
  return '';
}

function firstNumber(...values) {
  for (const value of values) {
    const number = Number(value);
    if (Number.isFinite(number)) return number;
  }
  return 0;
}

async function loadLegacyController() {
  if (window.DWRTLogCenter?.create) return window.DWRTLogCenter;
  controllerPromise ||= import(LEGACY_CONTROLLER_URL).then(() => {
    if (!window.DWRTLogCenter?.create) throw new Error('legacy log center did not register');
    return window.DWRTLogCenter;
  });
  return controllerPromise;
}

export async function mount(context = {}) {
  const root = context.root;
  if (!(root instanceof HTMLElement)) return { unmount() {} };

  const legacy = await loadLegacyController();
  if (context.signal?.aborted) return { unmount() {} };

  const controller = legacy.create({
    routePreview: root,
    fetchApiResource: (name, url) => context.api?.fetch?.(name, url),
    scheduleGlassCardsRender: context.ui?.scheduleGlassCardsRender || (() => {}),
    mountUiKit: context.ui?.mountAll || ((target) => window.DWRT_UI_KIT?.mountAll(target)),
    escapeHtml: context.utils?.escapeHtml,
    firstText,
    firstNumber,
    formatBytes: context.utils?.formatBytes,
    formatInteger: context.utils?.formatInteger,
    formatRate: context.utils?.formatRate,
    authHeaders: context.api?.authHeaders,
    routeTo: context.api?.routeTo
  });
  const instance = controller.mount({
    item: context.item,
    id: context.item?.id,
    section: context.item?.id,
    route: context.route,
    path: context.path
  });
  let mounted = true;
  const unmount = () => {
    if (!mounted) return;
    mounted = false;
    context.signal?.removeEventListener('abort', unmount);
    instance?.unmount?.();
    window.DWRT_UI_KIT?.unmount?.(root);
    root.replaceChildren();
  };
  context.signal?.addEventListener('abort', unmount, { once: true });
  return { unmount };
}

export default { mount };
