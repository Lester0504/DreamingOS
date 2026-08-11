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

const MATERIAL_MODES = Object.freeze([
  ['shader', '折射'],
  ['standard', '标准'],
  ['prominent', '强调'],
  ['polar', '极光']
]);

/*
 * 材质控件的取值区间必须与后端校验一致，否则会做出"点了就失败"的控件。
 * 逐项对齐 jmxd/src/jmx_netconfig_db.c:29159-29178 的 nc_appearance_patch 返回判据：
 * base_blur 0-16、neutral_density 0.025-0.18、saturation 70-220、highlight 0-0.65、
 * border_width 0-2、displacement_scale 0-180、aberration_intensity 0-8、
 * highlight_angle 0-360。区间之外后端整包拒收，不是只忽略这一个字段。
 */
const MATERIAL_FIELDS = Object.freeze([
  { key: 'base_blur', label: '模糊', min: 0, max: 16, step: 0.1, unit: 'px', decimals: 1, advanced: false, description: '玻璃背后的壁纸模糊半径。调大更容易读，调小更能看清壁纸。' },
  { key: 'neutral_density', label: '吸收强度', min: 0.025, max: 0.18, step: 0.005, unit: '', decimals: 3, advanced: false, description: '中性吸收层的浓度，压制壁纸亮度起伏；预设档位只是常用值，可继续精调。' },
  { key: 'saturation', label: '饱和度', min: 70, max: 220, step: 1, unit: '%', decimals: 0, advanced: false, description: '透过玻璃看到的颜色浓度。' },
  { key: 'highlight', label: '高光强度', min: 0, max: 0.65, step: 0.01, unit: '', decimals: 2, advanced: true, description: '玻璃顶部的反光量。' },
  { key: 'highlight_angle', label: '高光角度', min: 0, max: 360, step: 1, unit: '°', decimals: 0, advanced: true, description: '反光与边缘光的方向。' },
  { key: 'border_width', label: '边缘光宽度', min: 0, max: 2, step: 0.1, unit: 'px', decimals: 1, advanced: true, description: '玻璃轮廓的边缘光粗细。' },
  { key: 'displacement_scale', label: '折射强度', min: 0, max: 180, step: 1, unit: '', decimals: 0, advanced: true, description: '仅在折射模式下由采样渲染器使用。' },
  { key: 'aberration_intensity', label: '色散强度', min: 0, max: 8, step: 0.1, unit: '', decimals: 1, advanced: true, description: '边缘的彩色偏移量，仅折射模式可见。' }
]);

const MATERIAL_FIELD_MAP = Object.freeze(Object.fromEntries(MATERIAL_FIELDS.map((field) => [field.key, field])));

/* 正文 4.5:1、大字与图标边界 3:1，取自 design.md 的可读性合同。 */
const CONTRAST_BODY_MIN = 4.5;
const CONTRAST_LARGE_MIN = 3;

export function relativeLuma(r, g, b) {
  return 0.2126 * relativeLumaChannel(r) + 0.7152 * relativeLumaChannel(g) + 0.0722 * relativeLumaChannel(b);
}

/*
 * 解析一个 CSS 颜色为 { luma, alpha }。半透明必须保留 alpha：墨色与吸收层都会
 * 与身后的东西合成，合成后的颜色才是屏幕上真正出现的那个。
 *
 * 两种写法都要认：`rgba(8, 13, 21, 0.88)`（getComputedStyle 的输出）与
 * `rgb(10 16 25 / 0.06)`（令牌 --dwrt-glass-absorption 的空格语法）。
 * 只认逗号那一种会把吸收层解析失败，判决随即退回未叠吸收的表面，系统性高估亮度。
 */
export function parseForeground(value) {
  const match = String(value || '').match(/rgba?\(([^)]+)\)/);
  if (!match) return null;
  const body = match[1].replace(/\//g, ' ');
  const parts = body.split(/[\s,]+/).filter(Boolean).map((part) => (part.endsWith('%') ? Number(part.slice(0, -1)) / 100 : Number(part)));
  if (parts.length < 3 || parts.slice(0, 3).some((part) => !Number.isFinite(part))) return null;
  const alpha = parts.length > 3 && Number.isFinite(parts[3]) ? Math.max(0, Math.min(1, parts[3])) : 1;
  return { luma: relativeLuma(parts[0], parts[1], parts[2]), alpha };
}

/*
 * 判据是**渲染后**的前景/表面对，两个数都来自 DOM 实测，不由本模块推导：
 *   surfaceLuma —— 采样器写在玻璃元素上的 --adaptive-region-luma
 *   foreground  —— 该元素正文的 getComputedStyle().color（含 alpha）
 *
 * 为什么不自己建模：曾试过按 density 折算壁纸亮度再套一个假定墨色，结果与真实渲染
 * 在 30.1 上系统性对不上，且趋势相反 —— 页面里同时有两个采样器在写同一个变量
 * （本页预览采样与 menu-shell 的玻璃卡采样），而墨色又由采样结果反过来决定。
 * 任何"再算一遍"的版本都只是第三个互相矛盾的估计。直接读渲染结果就没有这个问题。
 */
export function contrastRatio(surfaceLuma, foreground) {
  if (!Number.isFinite(surfaceLuma) || !foreground) return null;
  const composited = foreground.luma * foreground.alpha + surfaceLuma * (1 - foreground.alpha);
  return composited > surfaceLuma
    ? (composited + 0.05) / (surfaceLuma + 0.05)
    : (surfaceLuma + 0.05) / (composited + 0.05);
}

export function contrastState(ratio) {
  if (!Number.isFinite(ratio)) return 'unknown';
  return ratio >= CONTRAST_BODY_MIN ? 'pass' : ratio >= CONTRAST_LARGE_MIN ? 'large-only' : 'fail';
}

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

export function materialFieldText(key, value) {
  const field = MATERIAL_FIELD_MAP[key];
  if (!field) return String(value ?? '');
  return `${numberValue(value, field.min, field.min, field.max).toFixed(field.decimals)}${field.unit}`;
}

/*
 * 对比度按渲染后的前景/表面对计算，不是令牌孤立值：把吸收层按 density 合成到实测壁纸
 * 亮度上，再与该区域实际使用的墨色比。design.md 要求正文 4.5:1、大字与图标 3:1。
 * 这里只警告不钳制 —— 用户有权把材质调成自己想要的样子，但必须知道代价。
 */
/*
 * 判据是**渲染后**的前景/表面对，不是令牌孤立值。
 *
 * 入参是壁纸实测亮度与起伏（预览卡背后那块区域的采样结果）；表面亮度在这里按
 * 当前吸收强度折算，口径与 menu-shell.js:6220 的 glassAdjustedLuma 一致
 * （backgroundLuma * (1 - density)），起伏同样按 (1 - density) 缩放（:6223）。
 *
 * 折算必须放在这里而不是采样器里：采样只在壁纸 load 时发生一次，
 * 而吸收强度会被滑块反复改动。让判决自己折算，提示才能跟着滑块走。
 */

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

/*
 * 与 menu-shell.js:6288 同口径：不均匀壁纸的可读性由最暗处与最亮处共同决定，
 * 取两端的较小对比度，避免"均值达标、实际读不出来"。deviation 为 0 时退化为均值判决，
 * 与本页原有行为一致。
 */
function readableForegroundMode(backgroundLuma, previous, deviation = 0) {
  const contrastAgainst = (luma, inkLuma) => (luma > inkLuma
    ? (luma + 0.05) / (inkLuma + 0.05)
    : (inkLuma + 0.05) / (luma + 0.05));
  const spread = Math.max(0, Math.min(0.5, Number.isFinite(deviation) ? deviation : 0));
  const lowLuma = Math.max(0, Math.min(1, backgroundLuma - spread));
  const highLuma = Math.max(0, Math.min(1, backgroundLuma + spread));
  const darkContrast = Math.min(contrastAgainst(lowLuma, 0.004), contrastAgainst(highLuma, 0.004));
  const lightContrast = Math.min(contrastAgainst(lowLuma, 0.982), contrastAgainst(highLuma, 0.982));
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
    contrastFrame: 0,
    feedback: '',
    feedbackTone: 'neutral'
  };

  const icon = (name) => window.DWRT_UI_KIT?.lucideIcon?.(name, { size: 18, strokeWidth: 1.8 }) || '';
  const writable = (name) => capabilities.appearance !== false && state.settingsSnapshot?.value?.capabilities?.[name] !== false;
  const dirty = () => state.touched.size > 0;

  /*
   * 会话闸门适配器：见 dwrt-session-gate.js 的 DWRT_REQUEST。裸 fetch 会绕过 token 刷新，
   * 过期时并发请求集体拿 401，切走再切回来才恢复；走闸门可自动刷新并单次重试。
   */
  function sessionFetch(url, init = {}) {
    return window.DWRT_REQUEST ? window.DWRT_REQUEST.fetch(url, init) : fetch(url, init);
  }

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
    return `<label data-dwrt-component="switch" class="appearance-switch-row dwrt-kit-switch" data-adaptive-sample><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(detail)}</small></span><input type="checkbox" data-appearance-field="${escapeHtml(path)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}></label>`;
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

  /*
   * 连续值滑块。步进与上下限直接取 MATERIAL_FIELDS，也就是后端校验区间，
   * 因此拖到端点仍是合法值，不会出现"拖满就保存失败"。
   */
  function materialSlider(field, value, disabled) {
    const current = numberValue(value, field.min, field.min, field.max);
    /*
     * 交给 Kit 的 data-dwrt-slider-unit 生成读数，而不是自己再写一遍 output：
     * mountSlider 的 sync() 在每次 input/change 时都会覆盖 output.textContent，
     * 页面若同时写入，两边格式不一致时会来回跳字。
     */
    return `<div data-dwrt-component="field"><span data-dwrt-field-label>${escapeHtml(field.label)}</span><div data-dwrt-component="slider" data-appearance-field="material_glass.${escapeHtml(field.key)}" data-appearance-material-slider="${escapeHtml(field.key)}" data-dwrt-slider-unit="${escapeHtml(field.unit)}"><input type="range" min="${field.min}" max="${field.max}" step="${field.step}" value="${current}" aria-valuetext="${escapeHtml(materialFieldText(field.key, current))}" ${disabled ? 'disabled' : ''}><output data-dwrt-slider-output>${escapeHtml(materialFieldText(field.key, current))}</output></div><small data-dwrt-field-description>${escapeHtml(field.description)}</small></div>`;
  }

  function contrastNoticeMarkup() {
    /*
     * 首次渲染时玻璃还没上屏，量不到前景/表面对，所以先落一个占位。
     * 真实判决由 syncContrastNotice() 在采样完成后写入。
     */
    return `<p class="appearance-contrast-notice is-unknown" data-appearance-contrast role="status">${escapeHtml(contrastNoticeText({ state: 'unknown' }))}</p>`;
  }

  function contrastNoticeText(verdict) {
    if (verdict.state === 'unknown') return '正在按预览壁纸测量正文对比度。';
    const ratio = verdict.ratio.toFixed(2);
    if (verdict.state === 'pass') return `当前组合在预览壁纸上的正文对比度约 ${ratio}:1，满足 4.5:1。`;
    if (verdict.state === 'large-only') return `当前组合的正文对比度约 ${ratio}:1，低于正文要求的 4.5:1，仅够大字与图标（3:1）。建议提高吸收强度或模糊。`;
    return `当前组合的正文对比度约 ${ratio}:1，低于大字与图标要求的 3:1，正文将难以辨认。建议提高吸收强度或模糊。`;
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
    const material = state.draft.material_glass;
    const summary = disabled
      ? '当前账号不可修改材质参数'
      : `模糊 ${materialFieldText('base_blur', material.base_blur)} · 吸收 ${materialFieldText('neutral_density', material.neutral_density)} · 饱和 ${materialFieldText('saturation', material.saturation)}`;
    const reason = disabled
      ? `<p class="appearance-locked-note" data-appearance-locked>固件未开放 <code>appearance_glass_write</code> 能力位，材质参数只读。</p>`
      : '';
    const modeField = `<div data-dwrt-component="field"><span data-dwrt-field-label>材质模式</span>${segmented('material_glass.mode', material.mode, MATERIAL_MODES, '材质模式', disabled)}<small data-dwrt-field-description>折射模式使用壁纸采样渲染器；标准模式只用 CSS 材质，开销更低。</small></div>`;
    const presets = `<div class="appearance-density-presets" role="group" aria-label="吸收强度预设">${READABILITY_LEVELS.map((level) => `<button type="button" data-dwrt-component="button" data-variant="ghost" data-appearance-density-preset="${level.density}" aria-pressed="${Math.abs(numberValue(material.neutral_density, 0.06, 0.025, 0.18) - level.density) < 0.0005 ? 'true' : 'false'}" ${disabled ? 'disabled' : ''}>${escapeHtml(level.label)}</button>`).join('')}</div>`;
    const basic = MATERIAL_FIELDS.filter((field) => !field.advanced)
      .map((field) => materialSlider(field, material[field.key], disabled) + (field.key === 'neutral_density' ? presets : ''))
      .join('');
    const advanced = MATERIAL_FIELDS.filter((field) => field.advanced)
      .map((field) => materialSlider(field, material[field.key], disabled))
      .join('');
    const readOnly = `<dl class="appearance-material-readonly"><dt>吸收色</dt><dd>${escapeHtml(textValue(material.neutral_color, '10 16 25'))}</dd><dt>边缘光颜色</dt><dd>${escapeHtml(textValue(material.border_color, '#25FFFFFF'))}</dd><dt>中心保留</dt><dd>${material.preserve_center ? '开启' : '关闭'}</dd></dl><small data-dwrt-field-description>这三项仍由共享令牌与合同默认值提供，本页暂未开放编辑，后端已能存储。</small>`;
    return disclosure('readability', '可读性', summary, `${reason}<div class="appearance-field-stack">${modeField}${basic}${contrastNoticeMarkup()}</div>${disclosure('material-advanced', '高级材质参数', '折射、高光与边缘光', `<div class="appearance-field-stack">${advanced}${readOnly}</div>`)}`);
  }

  function motionGroup() {
    const disabled = !writable('appearance_runtime_apply');
    return disclosure('motion', '动效', '设置界面反馈的运动强度', `<div data-dwrt-component="field"><span data-dwrt-field-label>交互动画</span>${segmented('dashboard.animation_level', state.draft.dashboard.animation_level, ANIMATION_LEVELS, '交互动画', disabled)}<small data-dwrt-field-description>系统的“减少动态效果”偏好始终优先。</small></div>`);
  }

  function previewMarkup() {
    const level = readabilityLevel(state.draft.material_glass);
    /*
     * 预览卡的材质必须来自共享令牌，但采样归属只能有一个。
     *
     * 它不能带 `data-dwrt-surface="stable-glass"`，也不能带 `.dwrt-kit-glass-surface`：
     * 两者都命中 menu-shell 的 PAGE_GLASS_SELECTOR（:6892、:6895），会把这张卡注册成
     * **页面级**采样目标。页面级采样量的是桌面壁纸，而这张卡浮在预览台自己的那张图上，
     * 场景不同却共写同一个 `--adaptive-region-luma`：30.1 实测本页写 0.296、
     * 宿主随后改写 0.134，等待时长不同结果还会翻覆，对比度提示的趋势因此与真实渲染相反。
     *
     * 所以这里用页面自己的 `.appearance-preview-glass`，其材质在 CSS 里**只引用**
     * 共享令牌（--dwrt-glass-surface / --dwrt-glass-edge / --dwrt-glass-shadow-raised
     * 与 --dwrt-glass-backdrop），不新增任何档位或私有玻璃参数。令牌由外观页设置驱动，
     * 所以拖滑块时这张卡仍与整个控制台同步变化。
     */
    return `<section class="appearance-preview" aria-labelledby="appearance-preview-title"><header data-adaptive-sample><span data-appearance-preview-context>后台预览</span><strong id="appearance-preview-title">实时预览</strong><small>主题、可读性与动效共用宿主外观合同。</small></header><div class="appearance-preview-stage"><img data-appearance-preview-image alt=""><div class="appearance-preview-glass"><span class="appearance-preview-kicker">Dreaming OS</span><strong>网络运行正常</strong><p>主文本、辅助信息和交互控件在同一材质上保持清晰。</p><div class="appearance-preview-controls"><span class="appearance-preview-toggle" aria-hidden="true"><i></i></span><span class="appearance-preview-action">保存设置</span><span class="appearance-preview-status"><i></i>已应用</span></div></div></div><footer><span>吸收强度</span><strong data-appearance-preview-level>${escapeHtml(READABILITY_LEVELS[level].label)}</strong><span data-appearance-preview-readout>${escapeHtml(previewReadoutText())}</span></footer></section>`;
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
    if (!view) {
      syncMaterialSliders();
      syncDensityPresets();
      syncPreview();
    }
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
    let sumSq = 0;
    let count = 0;
    const samples = [];
    for (let pixel = 0; pixel < pixels.length; pixel += 4) {
      if (pixels[pixel + 3] === 0) continue;
      const luma = 0.2126 * relativeLumaChannel(pixels[pixel])
        + 0.7152 * relativeLumaChannel(pixels[pixel + 1])
        + 0.0722 * relativeLumaChannel(pixels[pixel + 2]);
      sum += luma;
      sumSq += luma * luma;
      samples.push(luma);
      count += 1;
    }
    if (!count) return false;
    /*
     * 亮度取中位数而不是均值。
     *
     * 这张预览壁纸方差很大（实测卡片身后那块图 均值 0.361 / 中位 0.211）。均值被少量
     * 高光像素拉高，用它折算表面会系统性高估亮度：对比度提示因此偏乐观，
     * 而用户看到的正文其实压在中位那一档亮度上。中位数才是"文字大多数时候贴着的底色"。
     * 均值仍保留用于计算起伏（deviation），那是它本来的用途。
     */
    const meanLuma = sum / count;
    samples.sort((a, b) => a - b);
    const backgroundLuma = samples[Math.floor(samples.length / 2)];
    const backgroundDeviation = Math.sqrt(Math.max(0, sumSq / count - meanLuma * meanLuma));
    const density = numberValue(state.draft?.material_glass?.neutral_density, 0.06, 0, 0.35);
    const effectiveLuma = backgroundLuma * (1 - density);
    /*
     * 起伏按 (1 - density) 缩放后参与墨色判决，与 menu-shell.js:6223 同口径：
     * 不均匀壁纸的可读性由最暗处与最亮处共同决定，只看均值会挑错墨色。
     */
    glass.dataset.adaptiveRegion = readableForegroundMode(effectiveLuma, glass.dataset.adaptiveRegion, backgroundDeviation * (1 - density));
    glass.style.setProperty('--adaptive-region-luma', effectiveLuma.toFixed(3));
    scheduleContrastNotice();
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
    const readout = root.querySelector('[data-appearance-preview-readout]');
    if (readout) readout.textContent = previewReadoutText();
    const context = root.querySelector('[data-appearance-preview-context]');
    if (context) context.textContent = state.previewWallpaperScope === 'login' ? '登录页预览' : '后台预览';
    scheduleContrastNotice();
    emitPreview('preview');
  }

  function previewReadoutText() {
    const material = state.draft.material_glass;
    return `模糊 ${materialFieldText('base_blur', material.base_blur)} · 饱和 ${materialFieldText('saturation', material.saturation)}`;
  }

  function syncContrastNotice() {
    const notice = root.querySelector('[data-appearance-contrast]');
    if (!notice || !state.draft) return;
    /*
     * 判据取渲染后的前景/表面对，两端都来自实测，不重建一套材质光学：
     *
     *   表面 = 采样得到的壁纸亮度（--adaptive-region-luma，已含吸收层的 (1-density) 压暗）
     *          再叠一次玻璃自身的中性吸收层。那一层是实心色 rgb(neutral_color / density)，
     *          画在壁纸之上，所以正文真正贴着的是叠加之后的颜色。
     *          少叠这一层会系统性高估表面亮度：30.1 实测区域值 0.338 而像素实测 0.074。
     *   前景 = 正文的计算色，含 alpha（半透明墨色会与该表面合成）。
     */
    const glass = root.querySelector('.appearance-preview-glass');
    const body = glass?.querySelector('p');
    const backdropLuma = glass ? Number(glass.style.getPropertyValue('--adaptive-region-luma')) : NaN;
    const foreground = body ? parseForeground(getComputedStyle(body).color) : null;
    /*
     * 吸收层要从令牌读，不能从 backgroundColor 读：--dwrt-glass-surface 是 gradient 列表，
     * 元素的 backgroundColor 实测是 rgba(0,0,0,0)，拿它合成等于没叠。
     */
    const absorption = glass
      ? parseForeground(getComputedStyle(glass).getPropertyValue('--dwrt-glass-absorption'))
      : null;
    const surfaceLuma = Number.isFinite(backdropLuma) && absorption
      ? absorption.luma * absorption.alpha + backdropLuma * (1 - absorption.alpha)
      : backdropLuma;
    const ratio = contrastRatio(surfaceLuma, foreground);
    const verdict = { state: contrastState(ratio), ratio };
    notice.className = `appearance-contrast-notice is-${verdict.state}`;
    notice.textContent = contrastNoticeText(verdict);
    notice.hidden = false;
  }

  /*
   * 对比度必须在宿主采样器落笔之后再读。
   *
   * `--adaptive-region-luma` 上有两个写入者：本页的 samplePreviewForeground（只看预览台
   * 那张图）与 menu-shell 的 applyAdaptiveRegion（按视口真实几何采样，见 :6814）。
   * 后者晚一步执行并覆盖前者，且它的取值才是屏幕上真正生效的那个
   * （30.1 实测：本页写 0.296，宿主随后改写 0.134，像素实测表面 0.093 —— 宿主更接近）。
   * 若在 syncPreview 里同步读取，读到的永远是被覆盖前的中间值，
   * 于是提示的趋势与真实渲染相反：吸收强度调高、画面变暗、提示反而说更差。
   *
   * 因此这里排到宿主之后：先让出一帧给 applyAdaptiveRegion，再量前景/表面对。
   */
  function scheduleContrastNotice() {
    if (state.contrastFrame) cancelAnimationFrame(state.contrastFrame);
    state.contrastFrame = requestAnimationFrame(() => {
      state.contrastFrame = requestAnimationFrame(() => {
        state.contrastFrame = 0;
        if (state.mounted) syncContrastNotice();
      });
    });
  }

  function syncMaterialSummary() {
    const summary = root.querySelector('[data-appearance-disclosure="readability"] > [data-dwrt-disclosure-trigger] small');
    if (!summary || !state.draft) return;
    if (!writable('appearance_glass_write')) {
      summary.textContent = '当前账号不可修改材质参数';
      return;
    }
    const material = state.draft.material_glass;
    summary.textContent = `模糊 ${materialFieldText('base_blur', material.base_blur)} · 吸收 ${materialFieldText('neutral_density', material.neutral_density)} · 饱和 ${materialFieldText('saturation', material.saturation)}`;
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
    const preset = event.target.closest('[data-appearance-density-preset]');
    if (preset && !preset.disabled) {
      markTouched('material_glass.neutral_density', Number(preset.dataset.appearanceDensityPreset));
      syncDensityPresets();
      syncMaterialSliders();
      syncMaterialSummary();
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
    const key = slider.dataset.appearanceMaterialSlider;
    const field = MATERIAL_FIELD_MAP[key];
    if (!field) return;
    /* saturation 在后端是整型列，float 会被 json_object_get_int 截断，回读比对随之判失败。 */
    const raw = numberValue(event.target.value, field.min, field.min, field.max);
    const value = field.decimals === 0 ? Math.round(raw) : Number(raw.toFixed(field.decimals));
    markTouched(slider.dataset.appearanceField, value);
    syncDensityPresets();
    syncMaterialSummary();
    syncPreview();
    syncSavebar();
  }

  function syncDensityPresets() {
    const density = numberValue(state.draft?.material_glass?.neutral_density, 0.06, 0.025, 0.18);
    root.querySelectorAll('[data-appearance-density-preset]').forEach((button) => {
      const preset = Number(button.dataset.appearanceDensityPreset);
      button.setAttribute('aria-pressed', Math.abs(density - preset) < 0.0005 ? 'true' : 'false');
    });
  }

  function syncMaterialSliders() {
    if (!state.draft) return;
    root.querySelectorAll('[data-appearance-material-slider]').forEach((slider) => {
      const field = MATERIAL_FIELD_MAP[slider.dataset.appearanceMaterialSlider];
      if (!field) return;
      const input = slider.querySelector('input[type="range"]');
      const value = numberValue(state.draft.material_glass[field.key], field.min, field.min, field.max);
      if (input && Number(input.value) !== value) {
        input.value = String(value);
        input.dispatchEvent(new Event('change', { bubbles: false }));
      }
    });
  }

  function onChange(event) {
    const field = event.target.dataset.appearanceField;
    if (!field || !state.draft) return;
    const value = event.target.type === 'checkbox' ? event.target.checked : event.target.value;
    if (field.startsWith('wallpaper.login_')) state.previewWallpaperScope = 'login';
    else if (field.startsWith('wallpaper.')) state.previewWallpaperScope = 'wallpaper';
    /* 材质滑块的 change 已由 onInput 按类型写入，这里再按字符串写一次会把数值变成字符串。 */
    if (event.target.closest('[data-appearance-material-slider]')) return;
    markTouched(field, value);
    if (field.startsWith('wallpaper.') && field.endsWith('mode')) syncWallpaperDependencies();
    syncPreview();
    syncSavebar();
  }

  function onSegmentChange(event) {
    const field = event.target.dataset.appearanceField;
    if (!field || !state.draft) return;
    if (field.startsWith('wallpaper.login_')) state.previewWallpaperScope = 'login';
    else if (field.startsWith('wallpaper.')) state.previewWallpaperScope = 'wallpaper';
    markTouched(field, event.detail.value);
    /* material_glass.mode 也以 .mode 结尾，但它没有依赖字段；只有壁纸来源需要联动。 */
    if (field.startsWith('wallpaper.') && field.endsWith('mode')) syncWallpaperDependencies();
    if (field.startsWith('material_glass.')) syncMaterialSummary();
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
          : await sessionFetch(url, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(savePayload()), signal }).then(async (response) => {
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
      if (state.contrastFrame) {
        cancelAnimationFrame(state.contrastFrame);
        state.contrastFrame = 0;
      }
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
