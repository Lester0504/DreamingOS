const ACCENT_PRESETS = Object.freeze([
  ['violet', '紫罗兰', '#AF52DE'],
  ['blue', '蓝色', '#007AFF'],
  ['emerald', '绿色', '#34C759'],
  ['rose', '玫红', '#FF2D55'],
  ['amber', '橙色', '#FF9500'],
  ['indigo', '靛蓝', '#5856D6'],
  ['cyan', '青色', '#0891B2'],
  ['teal', '蓝绿', '#0F766E'],
  ['slate', '灰蓝', '#475569']
]);

const READABILITY_LEVELS = Object.freeze([
  { value: 0, label: '轻透', density: 0.045 },
  { value: 1, label: '均衡', density: 0.07 },
  { value: 2, label: '清晰', density: 0.105 }
]);

const ANIMATION_LEVELS = Object.freeze([
  ['off', '静止'],
  ['soft', '柔和'],
  ['balanced', '标准'],
  ['rich', '灵动']
]);

const WALLPAPER_MODES = Object.freeze([
  ['fixed', '固定'],
  ['argon', '随机'],
  ['interval', '轮换']
]);

const WALLPAPER_INTERVALS = Object.freeze([
  ['medium', '中'],
  ['slow', '慢'],
  ['relaxed', '舒缓'],
  ['long', '长']
]);

const clone = (value) => {
  try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value ?? null)); }
};

const numberValue = (value, fallback, min = -Infinity, max = Infinity) => {
  const numeric = Number(value);
  return Math.max(min, Math.min(max, Number.isFinite(numeric) ? numeric : fallback));
};

const booleanValue = (value, fallback = false) => value === undefined || value === null
  ? fallback
  : typeof value === 'string'
    ? !['0', 'false', 'off', 'no'].includes(value.toLowerCase())
    : Boolean(value);

const textValue = (...values) => {
  for (const value of values) {
    if (value === undefined || value === null) continue;
    const text = String(value).trim();
    if (text) return text;
  }
  return '';
};

function accentHex(value) {
  const raw = textValue(value, 'violet');
  if (/^#[0-9a-f]{6}$/i.test(raw)) return raw.toUpperCase();
  return (ACCENT_PRESETS.find(([id]) => id === raw) || ACCENT_PRESETS[0])[2];
}

export function readabilityLevel(material = {}) {
  const density = numberValue(material.neutral_density, 0.06, 0.025, 0.18);
  return density < 0.0575 ? 0 : density < 0.0875 ? 1 : 2;
}

export function normalizeAppearanceSettings(payload = {}) {
  const source = payload?.dreamingwrt && typeof payload.dreamingwrt === 'object' ? payload.dreamingwrt : payload;
  const material = source?.material_glass && typeof source.material_glass === 'object' ? source.material_glass : {};
  const wallpaper = source?.wallpaper && typeof source.wallpaper === 'object' ? source.wallpaper : {};
  const dashboard = source?.dashboard && typeof source.dashboard === 'object' ? source.dashboard : {};
  return {
    ...clone(source || {}),
    accent_color: textValue(source?.accent_color, 'violet'),
    material_glass: {
      ...clone(material),
      version: numberValue(material.version, 1, 1),
      mode: ['shader', 'standard', 'prominent', 'polar'].includes(material.mode) ? material.mode : 'shader',
      base_blur: numberValue(material.base_blur, 3.2, 0, 16),
      neutral_density: numberValue(material.neutral_density, 0.06, 0.025, 0.18),
      neutral_color: textValue(material.neutral_color, '10 16 25'),
      saturation: numberValue(material.saturation, 140, 70, 220),
      displacement_scale: numberValue(material.displacement_scale, 80, 0, 180),
      aberration_intensity: numberValue(material.aberration_intensity, 2, 0, 8),
      border_width: numberValue(material.border_width, 1, 0, 2),
      border_color: textValue(material.border_color, '#25FFFFFF'),
      highlight: numberValue(material.highlight, 0.28, 0, 0.65),
      highlight_angle: numberValue(material.highlight_angle, 135, 0, 360),
      preserve_center: booleanValue(material.preserve_center, true)
    },
    wallpaper: {
      ...clone(wallpaper),
      enabled: booleanValue(wallpaper.enabled, false),
      directory: textValue(wallpaper.directory, '/www/dreamingwrt/static/background'),
      image: textValue(wallpaper.image),
      opacity: numberValue(wallpaper.opacity, 0.16, 0, 1),
      mode: ['argon', 'fixed', 'interval'].includes(wallpaper.mode) ? wallpaper.mode : 'argon',
      interval: WALLPAPER_INTERVALS.some(([value]) => value === wallpaper.interval) ? wallpaper.interval : 'medium',
      login_enabled: booleanValue(wallpaper.login_enabled, true),
      login_image: textValue(wallpaper.login_image),
      login_opacity: numberValue(wallpaper.login_opacity, 1, 0, 1),
      login_mode: ['argon', 'fixed', 'interval'].includes(wallpaper.login_mode) ? wallpaper.login_mode : 'argon',
      login_interval: WALLPAPER_INTERVALS.some(([value]) => value === wallpaper.login_interval) ? wallpaper.login_interval : 'medium'
    },
    dashboard: {
      ...clone(dashboard),
      animation_level: ANIMATION_LEVELS.some(([value]) => value === dashboard.animation_level) ? dashboard.animation_level : 'balanced'
    }
  };
}

function mergeDeep(base, patch) {
  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) return clone(patch);
  const next = base && typeof base === 'object' && !Array.isArray(base) ? clone(base) : {};
  Object.entries(patch).forEach(([key, value]) => {
    next[key] = value && typeof value === 'object' && !Array.isArray(value) ? mergeDeep(next[key], value) : clone(value);
  });
  return next;
}

function setPath(target, path, value) {
  const parts = String(path).split('.').filter(Boolean);
  let node = target;
  while (parts.length > 1) {
    const key = parts.shift();
    if (!node[key] || typeof node[key] !== 'object') node[key] = {};
    node = node[key];
  }
  if (parts.length) node[parts[0]] = clone(value);
}

function valueAt(target, path) {
  return String(path).split('.').filter(Boolean).reduce((value, key) => value?.[key], target);
}

function relativeLumaChannel(value) {
  const channel = value / 255;
  return channel <= 0.04045 ? channel / 12.92 : Math.pow((channel + 0.055) / 1.055, 2.4);
}

function readableForegroundMode(backgroundLuma, previous) {
  const darkContrast = (backgroundLuma + 0.05) / (0.004 + 0.05);
  const lightContrast = (0.982 + 0.05) / (backgroundLuma + 0.05);
  if (previous === 'dark' && darkContrast >= 4.5) return 'dark';
  if (previous === 'light' && lightContrast >= 4.5) return 'light';
  return darkContrast >= lightContrast ? 'dark' : 'light';
}

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const registry = context.registry || window.DWRT_DATA_REGISTRY;
  const api = context.api || {};
  const ui = context.ui || {};
  const signal = context.signal;
  const capabilities = context.capabilities || {};
  const escapeHtml = context.utils?.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const stage = root?.closest('.console-stage');
  const state = {
    mounted: true,
    settingsSnapshot: null,
    mediaSnapshot: null,
    baseline: null,
    draft: null,
    media: [],
    touched: new Set(),
    saving: false,
    mediaRequested: false,
    previewWallpaperScope: 'wallpaper',
    feedback: '',
    feedbackTone: 'neutral'
  };

  const icon = (name) => window.DWRT_UI_KIT?.lucideIcon?.(name, { size: 18, strokeWidth: 1.8 }) || '';
  const writable = (name) => capabilities.appearance !== false && state.settingsSnapshot?.value?.capabilities?.[name] !== false;
  const dirty = () => state.touched.size > 0;

  function normalizeMedia(payload = {}) {
    const appearance = payload?.appearance && typeof payload.appearance === 'object' ? payload.appearance : payload;
    const source = appearance?.login && typeof appearance.login === 'object' ? appearance.login : appearance;
    const entries = [];
    const append = (item) => {
      const url = typeof item === 'string' ? item : textValue(item?.url, item?.src, item?.path);
      if (!url || entries.some((entry) => entry.url === url)) return;
      const filename = textValue(item?.filename, item?.name, url.split('/').pop());
      entries.push({ url, filename, label: textValue(item?.label, filename) });
    };
    (Array.isArray(source?.media) ? source.media : []).forEach(append);
    (Array.isArray(source?.images) ? source.images : []).forEach(append);
    append(source?.selected);
    return entries;
  }

  function hydrateSettings() {
    if (!state.settingsSnapshot?.value || dirty() || state.saving) return false;
    const normalized = normalizeAppearanceSettings(state.settingsSnapshot.value);
    state.baseline = normalized;
    state.draft = clone(normalized);
    return true;
  }

  function pageState() {
    if (capabilities.appearance === false) return { name: 'unavailable', title: '外观设置不可用', detail: '当前固件未开放外观设置能力。' };
    const snapshot = state.settingsSnapshot;
    if (snapshot && ['forbidden', 'unavailable', 'error'].includes(snapshot.status) && snapshot.value === undefined) {
      if (snapshot.status === 'forbidden') return { name: 'forbidden', title: '无权读取外观设置', detail: '当前账号没有读取外观配置的权限。' };
      if (snapshot.status === 'unavailable') return { name: 'unavailable', title: '外观设置接口不可用', detail: '当前固件没有提供页面所需的权威配置合同。' };
      return { name: 'error', title: '无法读取外观设置', detail: textValue(snapshot.error?.message, '保留当前页面后重试。') };
    }
    if (!state.draft) return { name: 'loading', title: '正在读取外观设置', detail: '页面骨架已就绪，等待外观权威快照。' };
    return null;
  }

  function statePanel(view) {
    const action = view.name === 'error' ? `<button type="button" data-dwrt-component="button" data-appearance-action="retry">${icon('refresh-cw')}<span>重试</span></button>` : '';
    return `<section data-dwrt-component="state-panel" data-dwrt-state="${escapeHtml(view.name)}"><strong>${escapeHtml(view.title)}</strong><p>${escapeHtml(view.detail)}</p>${action}</section>`;
  }

  function segmented(path, value, options, label, disabled = false) {
    return `<div data-dwrt-component="segmented" data-appearance-field="${escapeHtml(path)}" data-dwrt-value="${escapeHtml(value)}" aria-label="${escapeHtml(label)}">${options.map(([key, text]) => `<button type="button" data-dwrt-segment data-value="${escapeHtml(key)}" ${key === value ? 'aria-checked="true"' : ''} ${disabled ? 'disabled' : ''}>${escapeHtml(text)}</button>`).join('')}</div>`;
  }

  function switchRow(path, title, detail, checked, disabled = false) {
    return `<label data-dwrt-component="switch" class="appearance-switch-row" data-adaptive-sample><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(detail)}</small></span><input type="checkbox" data-appearance-field="${escapeHtml(path)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}></label>`;
  }

  function mediaOptions(value) {
    const current = textValue(value);
    const entries = state.media.slice();
    if (current && !entries.some((entry) => entry.filename === current)) entries.unshift({ filename: current, label: current, url: '' });
    const placeholder = !entries.length ? `<option value="">${state.mediaRequested ? '未发现可用壁纸' : '展开后读取壁纸'}</option>` : '<option value="">自动选择</option>';
    return placeholder + entries.map((entry) => `<option value="${escapeHtml(entry.filename)}" ${entry.filename === current ? 'selected' : ''}>${escapeHtml(entry.label)}</option>`).join('');
  }

  function mediaField(path, title, value, disabled = false) {
    return `<label data-dwrt-component="field"><span data-dwrt-field-label>${escapeHtml(title)}</span><select data-dwrt-component="select" data-appearance-field="${escapeHtml(path)}" ${disabled ? 'disabled' : ''} data-appearance-media-select>${mediaOptions(value)}</select><small data-dwrt-field-description>图片来自已配置的壁纸目录。</small></label>`;
  }

  function disclosure(id, title, summary, content, open = false) {
    return `<section data-dwrt-component="disclosure" data-appearance-disclosure="${escapeHtml(id)}" data-adaptive-sample><button type="button" data-dwrt-disclosure-trigger aria-expanded="${open ? 'true' : 'false'}"><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(summary)}</small></span>${icon('chevron-down')}</button><div data-dwrt-disclosure-panel ${open ? '' : 'hidden'}>${content}</div></section>`;
  }

  function themeGroup() {
    const disabled = !writable('appearance_accent_write');
    const active = state.draft.accent_color;
    return disclosure('theme', '主题', '设置界面的强调色', `<div class="appearance-accent-field" role="radiogroup" aria-label="强调色">${ACCENT_PRESETS.map(([id, label, color]) => `<button type="button" class="appearance-accent-option ${active === id || accentHex(active) === color ? 'is-active' : ''}" data-appearance-accent="${escapeHtml(id)}" role="radio" aria-checked="${active === id || accentHex(active) === color ? 'true' : 'false'}" aria-label="${escapeHtml(label)}" title="${escapeHtml(label)}" style="--appearance-swatch:${escapeHtml(color)}" ${disabled ? 'disabled' : ''}><span aria-hidden="true"></span></button>`).join('')}</div>`, true);
  }

  function wallpaperSource(prefix, title, enabled, mode, image, interval, disabled) {
    const fields = prefix === 'login'
      ? { enabled: 'wallpaper.login_enabled', mode: 'wallpaper.login_mode', image: 'wallpaper.login_image', interval: 'wallpaper.login_interval' }
      : { enabled: 'wallpaper.enabled', mode: 'wallpaper.mode', image: 'wallpaper.image', interval: 'wallpaper.interval' };
    return `<section class="appearance-wallpaper-source" data-appearance-wallpaper-source="${escapeHtml(prefix)}"><header><strong>${escapeHtml(title)}</strong></header>${switchRow(fields.enabled, `启用${title}`, prefix === 'wallpaper' ? '控制后台工作区的壁纸来源。' : '登录页与后台使用同一媒体目录。', enabled, disabled)}<div class="appearance-field-stack"><div data-dwrt-component="field"><span data-dwrt-field-label>来源</span>${segmented(fields.mode, mode, WALLPAPER_MODES, `${title}来源`, disabled)}</div><div data-appearance-wallpaper-dependent="fixed" ${mode === 'fixed' ? '' : 'hidden'}>${mediaField(fields.image, '固定图片', image, disabled)}</div><div data-appearance-wallpaper-dependent="interval" ${mode === 'interval' ? '' : 'hidden'}><div data-dwrt-component="field"><span data-dwrt-field-label>轮换间隔</span>${segmented(fields.interval, interval, WALLPAPER_INTERVALS, `${title}轮换间隔`, disabled)}</div></div></div></section>`;
  }

  function wallpaperGroup() {
    const wallpaper = state.draft.wallpaper;
    const disabled = !writable('appearance_wallpaper_write');
    const mediaState = state.mediaSnapshot?.status;
    const status = state.mediaRequested
      ? mediaState === 'loading' ? '正在读取壁纸目录'
        : mediaState === 'forbidden' ? '无权读取壁纸目录'
          : mediaState === 'error' ? '壁纸目录读取失败'
            : `${state.media.length} 张可用壁纸`
      : '展开后按需读取壁纸目录';
    const admin = wallpaperSource('wallpaper', '后台壁纸', wallpaper.enabled, wallpaper.mode, wallpaper.image, wallpaper.interval, disabled);
    const login = wallpaperSource('login', '登录页壁纸', wallpaper.login_enabled, wallpaper.login_mode, wallpaper.login_image, wallpaper.login_interval, disabled);
    return disclosure('wallpaper', '壁纸', status, `<div class="appearance-wallpaper-grid">${admin}${login}</div>`);
  }

  function readabilityGroup() {
    const disabled = !writable('appearance_glass_write');
    const level = readabilityLevel(state.draft.material_glass);
    return disclosure('readability', '可读性', '平衡透明度与文字对比度', `<div data-dwrt-component="field"><span data-dwrt-field-label>玻璃吸收强度</span><div data-dwrt-component="slider" data-appearance-field="material_glass.neutral_density" data-dwrt-slider-labels="轻透|均衡|清晰"><input type="range" min="0" max="2" step="1" value="${level}" ${disabled ? 'disabled' : ''}><output data-dwrt-slider-output>${escapeHtml(READABILITY_LEVELS[level].label)}</output></div><small data-dwrt-field-description>只调整中性吸收层，不改变折射、边缘与高光参数。</small></div>`);
  }

  function motionGroup() {
    const disabled = !writable('appearance_runtime_apply');
    return disclosure('motion', '动效', '设置界面反馈的运动强度', `<div data-dwrt-component="field"><span data-dwrt-field-label>交互动画</span>${segmented('dashboard.animation_level', state.draft.dashboard.animation_level, ANIMATION_LEVELS, '交互动画', disabled)}<small data-dwrt-field-description>系统的“减少动态效果”偏好始终优先。</small></div>`);
  }

  function previewMarkup() {
    const level = readabilityLevel(state.draft.material_glass);
    return `<section class="appearance-preview" aria-labelledby="appearance-preview-title"><header data-adaptive-sample><span data-appearance-preview-context>后台预览</span><strong id="appearance-preview-title">实时预览</strong><small>主题、可读性与动效共用宿主外观合同。</small></header><div class="appearance-preview-stage"><img data-appearance-preview-image alt=""><div class="appearance-preview-glass"><span class="appearance-preview-kicker">Dreaming OS</span><strong>网络运行正常</strong><p>主文本、辅助信息和交互控件在同一材质上保持清晰。</p><div class="appearance-preview-controls"><span class="appearance-preview-toggle" aria-hidden="true"><i></i></span><span class="appearance-preview-action">保存设置</span><span class="appearance-preview-status"><i></i>已应用</span></div></div></div><footer><span>吸收强度</span><strong data-appearance-preview-level>${escapeHtml(READABILITY_LEVELS[level].label)}</strong></footer></section>`;
  }

  function shellMarkup(content) {
    return `<main class="appearance-page-shell" data-dwrt-component="page-shell" data-dwrt-page-shell="settings-workbench" data-dwrt-surface="stable-glass"><header class="appearance-page-header" data-adaptive-sample><div><h1>外观</h1><p>统一后台、登录页与原生插件的主题和材质。</p></div><span data-appearance-status>${state.settingsSnapshot?.stale ? '使用最近一次配置' : '配置已同步'}</span></header>${content}</main>`;
  }

  function savebarMarkup() {
    return window.DWRT_UI_KIT?.floatingSavebarMarkup?.({ visible: dirty(), busy: state.saving, message: state.feedback || '外观配置已修改，请保存生效' }) || '';
  }

  function render() {
    if (!root || !state.mounted) return;
    const view = pageState();
    window.DWRT_UI_KIT?.unmount?.(root);
    root.className = `${root.className.split(/\s+/).filter((name) => name && name !== 'appearance-settings-route-host' && name !== 'route-workspace').join(' ')} route-workspace appearance-settings-route-host`;
    root.hidden = false;
    root.innerHTML = shellMarkup(view
      ? statePanel(view)
      : `<div class="appearance-workbench"><div class="appearance-groups">${themeGroup()}${wallpaperGroup()}${readabilityGroup()}${motionGroup()}</div>${previewMarkup()}</div><div class="appearance-feedback is-${escapeHtml(state.feedbackTone)}" data-appearance-feedback ${state.feedback ? '' : 'hidden'}>${escapeHtml(state.feedback)}</div>${savebarMarkup()}`);
    if (typeof ui.mountAll === 'function') ui.mountAll(root);
    else window.DWRT_UI_KIT?.mountAll?.(root);
    if (!view) syncPreview();
    ui.scheduleAdaptiveForegroundSample?.(0, root);
  }

  function wallpaperUrl(filename) {
    if (!filename) return '';
    const match = state.media.find((entry) => entry.filename === filename);
    if (match?.url) return match.url;
    return `/static/background/${encodeURIComponent(filename)}`;
  }

  function activeWallpaperUrl() {
    const wallpaper = state.draft?.wallpaper || {};
    const login = state.previewWallpaperScope === 'login';
    const mode = login ? wallpaper.login_mode : wallpaper.mode;
    const image = login ? wallpaper.login_image : wallpaper.image;
    if (mode === 'fixed' && image) return wallpaperUrl(image);
    return textValue(document.getElementById('appWallpaper')?.currentSrc, document.getElementById('appWallpaper')?.src, '/static/background/dwrt-default-bg.jpg');
  }

  function samplePreviewForeground(image) {
    const stageElement = root.querySelector('.appearance-preview-stage');
    const glass = root.querySelector('.appearance-preview-glass');
    if (!state.mounted || !image?.complete || !image.naturalWidth || !stageElement || !glass) return false;
    const stageRect = stageElement.getBoundingClientRect();
    const glassRect = glass.getBoundingClientRect();
    if (stageRect.width < 1 || stageRect.height < 1 || glassRect.width < 1 || glassRect.height < 1) return false;

    const sampleWidth = 96;
    const sampleHeight = Math.max(48, Math.round(sampleWidth * stageRect.height / stageRect.width));
    const canvas = document.createElement('canvas');
    canvas.width = sampleWidth;
    canvas.height = sampleHeight;
    const context = canvas.getContext('2d', { willReadFrequently: true });
    if (!context) return false;

    const scale = Math.max(stageRect.width / image.naturalWidth, stageRect.height / image.naturalHeight);
    const renderedWidth = image.naturalWidth * scale;
    const renderedHeight = image.naturalHeight * scale;
    context.drawImage(
      image,
      ((stageRect.width - renderedWidth) / 2) * sampleWidth / stageRect.width,
      ((stageRect.height - renderedHeight) / 2) * sampleHeight / stageRect.height,
      renderedWidth * sampleWidth / stageRect.width,
      renderedHeight * sampleHeight / stageRect.height
    );

    const x = Math.max(0, Math.floor((glassRect.left - stageRect.left) * sampleWidth / stageRect.width));
    const y = Math.max(0, Math.floor((glassRect.top - stageRect.top) * sampleHeight / stageRect.height));
    const width = Math.max(1, Math.min(sampleWidth - x, Math.ceil(glassRect.width * sampleWidth / stageRect.width)));
    const height = Math.max(1, Math.min(sampleHeight - y, Math.ceil(glassRect.height * sampleHeight / stageRect.height)));
    let pixels;
    try {
      pixels = context.getImageData(x, y, width, height).data;
    } catch (_) {
      return false;
    }

    let sum = 0;
    let count = 0;
    for (let pixel = 0; pixel < pixels.length; pixel += 4) {
      if (pixels[pixel + 3] === 0) continue;
      sum += 0.2126 * relativeLumaChannel(pixels[pixel])
        + 0.7152 * relativeLumaChannel(pixels[pixel + 1])
        + 0.0722 * relativeLumaChannel(pixels[pixel + 2]);
      count += 1;
    }
    if (!count) return false;
    const effectiveLuma = (sum / count) * (1 - numberValue(state.draft?.material_glass?.neutral_density, 0.06, 0, 0.35));
    glass.dataset.adaptiveRegion = readableForegroundMode(effectiveLuma, glass.dataset.adaptiveRegion);
    glass.style.setProperty('--adaptive-region-luma', effectiveLuma.toFixed(3));
    return true;
  }

  function previewDetail(action = 'preview') {
    return {
      action,
      material_glass: clone(state.draft.material_glass),
      accent_color: state.draft.accent_color,
      wallpaper: { url: activeWallpaperUrl() },
      animation_level: state.draft.dashboard.animation_level
    };
  }

  function emitPreview(action = 'preview') {
    if (!state.draft) return;
    window.dispatchEvent(new CustomEvent('dwrt:appearance-preview', { detail: previewDetail(action) }));
  }

  function syncPreview() {
    if (!state.draft) return;
    const preview = root.querySelector('.appearance-preview');
    if (preview) {
      preview.style.setProperty('--appearance-preview-accent', accentHex(state.draft.accent_color));
      preview.style.setProperty('--appearance-preview-density', String(state.draft.material_glass.neutral_density));
      preview.dataset.animationLevel = state.draft.dashboard.animation_level;
    }
    const image = root.querySelector('[data-appearance-preview-image]');
    const url = activeWallpaperUrl();
    if (image) {
      image.onload = () => {
        if (state.mounted && image === root.querySelector('[data-appearance-preview-image]')) samplePreviewForeground(image);
      };
      if (url && image.getAttribute('src') !== url) image.setAttribute('src', url);
      else if (image.complete && image.naturalWidth) samplePreviewForeground(image);
    }
    const level = root.querySelector('[data-appearance-preview-level]');
    if (level) level.textContent = READABILITY_LEVELS[readabilityLevel(state.draft.material_glass)].label;
    const context = root.querySelector('[data-appearance-preview-context]');
    if (context) context.textContent = state.previewWallpaperScope === 'login' ? '登录页预览' : '后台预览';
    emitPreview('preview');
  }

  function syncSavebar() {
    const bar = root.querySelector('[data-dwrt-savebar]');
    if (!bar) return;
    bar.classList.toggle('is-hidden', !dirty());
    const message = bar.querySelector(':scope > span');
    if (message) message.textContent = state.feedback || '外观配置已修改，请保存生效';
    bar.querySelectorAll('button').forEach((button) => { button.disabled = state.saving; });
    const save = bar.querySelector('[data-dwrt-savebar-save]');
    if (save) save.textContent = state.saving ? '保存中...' : '保存并应用';
  }

  function syncFeedback() {
    const feedback = root.querySelector('[data-appearance-feedback]');
    if (!feedback) return;
    feedback.hidden = !state.feedback;
    feedback.textContent = state.feedback;
    feedback.className = `appearance-feedback is-${state.feedbackTone}`;
  }

  function markTouched(path, value) {
    setPath(state.draft, path, value);
    const original = valueAt(state.baseline, path);
    if (JSON.stringify(original) === JSON.stringify(value)) state.touched.delete(path);
    else state.touched.add(path);
    state.feedback = '';
    state.feedbackTone = 'neutral';
  }

  function syncAccentControls() {
    root.querySelectorAll('[data-appearance-accent]').forEach((button) => {
      const active = button.dataset.appearanceAccent === state.draft.accent_color;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-checked', active ? 'true' : 'false');
    });
  }

  function syncMediaSelects() {
    root.querySelectorAll('[data-appearance-media-select]').forEach((select) => {
      const value = valueAt(state.draft, select.dataset.appearanceField) || '';
      select.innerHTML = mediaOptions(value);
      select.value = value;
    });
    const summary = root.querySelector('[data-appearance-disclosure="wallpaper"] [data-dwrt-disclosure-trigger] small');
    if (summary) {
      summary.textContent = state.mediaSnapshot?.status === 'loading' ? '正在读取壁纸目录'
        : state.mediaSnapshot?.status === 'forbidden' ? '无权读取壁纸目录'
          : state.mediaSnapshot?.status === 'error' ? '壁纸目录读取失败'
            : `${state.media.length} 张可用壁纸`;
    }
  }

  async function loadMedia() {
    if (state.mediaRequested || !registry) return;
    state.mediaRequested = true;
    syncMediaSelects();
    await registry.request('appearance.media', { signal });
  }

  function syncWallpaperDependencies() {
    root.querySelectorAll('[data-appearance-wallpaper-source]').forEach((source) => {
      const prefix = source.dataset.appearanceWallpaperSource;
      const modePath = prefix === 'login' ? 'wallpaper.login_mode' : 'wallpaper.mode';
      const mode = valueAt(state.draft, modePath);
      source.querySelectorAll('[data-appearance-wallpaper-dependent]').forEach((field) => {
        field.hidden = field.dataset.appearanceWallpaperDependent !== mode;
      });
    });
  }

  function onClick(event) {
    const accent = event.target.closest('[data-appearance-accent]');
    if (accent && !accent.disabled) {
      markTouched('accent_color', accent.dataset.appearanceAccent);
      syncAccentControls();
      syncPreview();
      syncSavebar();
      return;
    }
    if (event.target.closest('[data-appearance-action="retry"]')) {
      registry?.request?.('appearance.settings', { force: true, signal });
      return;
    }
    if (event.target.closest('[data-dwrt-savebar-discard]')) discard();
    if (event.target.closest('[data-dwrt-savebar-save]')) save();
  }

  function onInput(event) {
    const slider = event.target.closest('[data-dwrt-component="slider"]');
    if (!slider || !state.draft) return;
    const level = READABILITY_LEVELS[numberValue(event.target.value, 1, 0, 2)];
    markTouched(slider.dataset.appearanceField, level.density);
    syncPreview();
    syncSavebar();
  }

  function onChange(event) {
    const field = event.target.dataset.appearanceField;
    if (!field || !state.draft) return;
    const value = event.target.type === 'checkbox' ? event.target.checked : event.target.value;
    if (field.startsWith('wallpaper.login_')) state.previewWallpaperScope = 'login';
    else if (field.startsWith('wallpaper.')) state.previewWallpaperScope = 'wallpaper';
    markTouched(field, value);
    if (field.endsWith('.mode')) syncWallpaperDependencies();
    syncPreview();
    syncSavebar();
  }

  function onSegmentChange(event) {
    const field = event.target.dataset.appearanceField;
    if (!field || !state.draft) return;
    if (field.startsWith('wallpaper.login_')) state.previewWallpaperScope = 'login';
    else if (field.startsWith('wallpaper.')) state.previewWallpaperScope = 'wallpaper';
    markTouched(field, event.detail.value);
    if (field.endsWith('.mode')) syncWallpaperDependencies();
    syncPreview();
    syncSavebar();
  }

  function onDisclosureChange(event) {
    const disclosureRoot = event.target.closest('[data-appearance-disclosure]');
    if (disclosureRoot?.dataset.appearanceDisclosure === 'wallpaper' && event.detail.open) loadMedia();
  }

  function discard() {
    if (!state.baseline) return;
    state.draft = clone(state.baseline);
    state.touched.clear();
    state.feedback = '';
    window.dispatchEvent(new CustomEvent('dwrt:appearance-preview', { detail: { action: 'rollback' } }));
    render();
  }

  function readbackMatches(candidate, expected, paths) {
    return paths.every((path) => JSON.stringify(valueAt(candidate, path)) === JSON.stringify(valueAt(expected, path)));
  }

  function savePayload() {
    const dreamingwrt = {};
    state.touched.forEach((path) => setPath(dreamingwrt, path, valueAt(state.draft, path)));
    return { dreamingwrt };
  }

  async function save() {
    if (!dirty() || state.saving) return;
    state.saving = true;
    state.feedback = '';
    syncSavebar();
    let result = null;
    let saved = false;
    let lastError = null;
    for (const url of ['/api/v1/system/settings', '/api/v1/save_system_settings']) {
      try {
        result = typeof api.request === 'function'
          ? await api.request('appearance-save', url, { method: 'POST', body: savePayload() })
          : await fetch(url, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(savePayload()), signal }).then(async (response) => {
            const payload = await response.json().catch(() => ({}));
            if (!response.ok || payload?.ok === false) throw new Error(payload?.error?.message || payload?.message || response.statusText);
            return payload?.data ?? payload;
          });
        saved = true;
        break;
      } catch (error) {
        lastError = error;
      }
    }
    if (!saved) {
      state.saving = false;
      state.feedback = lastError?.message || '保存失败';
      state.feedbackTone = 'error';
      syncFeedback();
      syncSavebar();
      return;
    }
    const localCommitted = clone(state.draft);
    const committedPaths = Array.from(state.touched);
    let verified = false;
    try {
      registry?.invalidate?.('appearance.settings', { abort: false });
      const snapshot = await registry?.request?.('appearance.settings', { force: true, signal });
      if (snapshot?.value) {
        state.settingsSnapshot = snapshot;
        const readback = normalizeAppearanceSettings(snapshot.value);
        verified = readbackMatches(readback, localCommitted, committedPaths);
        state.baseline = verified ? readback : localCommitted;
        state.draft = clone(state.baseline);
      }
    } catch (_) {}
    if (!verified) {
      const current = state.settingsSnapshot?.value || {};
      registry?.patch?.('appearance.settings', mergeDeep(current, { dreamingwrt: localCommitted }));
      state.baseline = localCommitted;
      state.draft = clone(localCommitted);
    }
    state.touched.clear();
    state.saving = false;
    state.feedback = verified ? '已保存并完成回读' : '已保存，运行态未确认';
    state.feedbackTone = verified ? 'success' : 'warning';
    emitPreview('commit');
    render();
  }

  root.addEventListener('click', onClick);
  root.addEventListener('input', onInput);
  root.addEventListener('change', onChange);
  root.addEventListener('dwrt-segment-change', onSegmentChange);
  root.addEventListener('dwrt-disclosure-change', onDisclosureChange);
  stage?.classList.add('is-appearance-settings');

  const unsubscribers = [];
  if (registry) {
    unsubscribers.push(registry.subscribe('appearance.settings', (snapshot) => {
      if (!state.mounted) return;
      state.settingsSnapshot = snapshot;
      const hydrated = hydrateSettings();
      if (hydrated || !state.draft) render();
      else {
        const status = root.querySelector('[data-appearance-status]');
        if (status) status.textContent = snapshot.stale ? '使用最近一次配置' : '配置已同步';
      }
    }));
    unsubscribers.push(registry.subscribe('appearance.media', (snapshot) => {
      if (!state.mounted || !state.mediaRequested) return;
      state.mediaSnapshot = snapshot;
      if (snapshot.value) state.media = normalizeMedia(snapshot.value);
      syncMediaSelects();
      syncPreview();
    }, { abortWhenUnused: true }));
  }
  render();
  registry?.request?.('appearance.settings', { signal });

  return {
    refresh() { return registry?.request?.('appearance.settings', { force: true, signal }); },
    unmount() {
      window.dispatchEvent(new CustomEvent('dwrt:appearance-preview', { detail: { action: 'rollback' } }));
      state.mounted = false;
      const previewImage = root.querySelector('[data-appearance-preview-image]');
      if (previewImage) previewImage.onload = null;
      unsubscribers.filter(Boolean).forEach((unsubscribe) => unsubscribe());
      root.removeEventListener('click', onClick);
      root.removeEventListener('input', onInput);
      root.removeEventListener('change', onChange);
      root.removeEventListener('dwrt-segment-change', onSegmentChange);
      root.removeEventListener('dwrt-disclosure-change', onDisclosureChange);
      window.DWRT_UI_KIT?.unmount?.(root);
      root.replaceChildren();
      root.classList.remove('route-workspace', 'appearance-settings-route-host');
      stage?.classList.remove('is-appearance-settings');
    }
  };
}

export default { mount };
