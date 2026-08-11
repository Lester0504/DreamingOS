import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const root = new URL('..', import.meta.url);
const source = readFileSync(new URL('files/www/dreamingwrt/plugins/native/appearance-settings.js', root), 'utf8');
const style = readFileSync(new URL('files/www/dreamingwrt/static/css/appearance-settings.css', root), 'utf8');
const systemSource = readFileSync(new URL('files/www/dreamingwrt/plugins/native/system-settings.js', root), 'utf8');
const systemStyle = readFileSync(new URL('files/www/dreamingwrt/static/css/system-settings.css', root), 'utf8');
const shell = readFileSync(new URL('files/www/dreamingwrt/static/js/menu-shell.js', root), 'utf8');
const menu = JSON.parse(readFileSync(new URL('files/www/dreamingwrt/static/menu/main.json', root), 'utf8'));
const manifest = JSON.parse(readFileSync(new URL('redesign/route-manifest.json', root), 'utf8'));

const system = menu.items.find((item) => item.id === 'system');
const page = system.children.find((item) => item.id === 'system-appearance');
assert.equal(page.module, 'native/appearance-settings.js');
assert.match(page.module_version, /^\d{8}-[a-z0-9-]+$/);
assert.equal(page.style, '/static/css/appearance-settings.css');
assert.equal(page.style_version, page.module_version);
assert.equal(page.frontend_owned, true);
assert.equal(page.capability, 'appearance');

const route = manifest.routes.find((item) => item.route === '#/system/appearance');
assert.equal(route.owner, 'plugins/native/appearance-settings.js');
assert.equal(route.page_shell, 'settings-workbench');
assert.deepEqual(route.registry, ['appearance.settings', 'appearance.media']);

assert.match(shell, /registry\.define\('appearance\.settings'/);
assert.match(shell, /url: '\/api\/v1\/system\/basic'/);
assert.match(shell, /registry\.define\('appearance\.media'/);
assert.match(shell, /url: '\/api\/v1\/bootstrap\?appearance=1'/);
assert.match(shell, /removeProperty\('--app-accent'\)/);
assert.match(shell, /const appearanceSettingsRoute = currentKey === 'system-appearance'/);

for (const group of ['主题', '壁纸', '可读性', '动效']) assert.match(source, new RegExp("'" + group + "'"));
for (const primitive of ['page-shell', 'disclosure', 'field', 'switch', 'segmented', 'slider', 'state-panel']) {
  assert.match(source, new RegExp('data-dwrt-component="' + primitive + '"'));
}
for (const state of ['loading', 'error', 'forbidden', 'unavailable']) assert.match(source, new RegExp("name: '" + state + "'"));
assert.match(source, /registry\?\.request\?\.\('appearance\.settings'/);
assert.match(source, /if \(state\.mediaRequested \|\| !registry\) return/);
assert.match(source, /registry\.request\('appearance\.media'/);
assert.match(source, /state\.touched\.forEach\(\(path\) => setPath\(dreamingwrt/);
assert.match(source, /readbackMatches\(readback, localCommitted, committedPaths\)/);
assert.match(source, /verified \? '已保存并完成回读' : '已保存，运行态未确认'/);
assert.match(source, /let saved = false/);
assert.match(source, /saved = true/);
assert.match(source, /window\.DWRT_UI_KIT\?\.unmount\?\.\(root\)/);
assert.match(source, /action: 'rollback'/);
assert.match(source, /emitPreview\('commit'\)/);
assert.match(source, /unsubscribers\.filter\(Boolean\)\.forEach/);
assert.match(source, /samplePreviewForeground\(image\)/);
assert.match(source, /glass\.dataset\.adaptiveRegion = readableForegroundMode/);

assert.doesNotMatch(source, /setInterval\s*\(|MutationObserver|<select(?![^>]*data-dwrt-component)/);
/*
 * 页面 CSS 仍不得自定材质：禁字面色值、禁 !important。
 *
 * 但 backdrop-filter 由"整条禁止"收窄为"只能引用共享令牌"。原先的全禁把预览卡逼去借
 * Kit 的 stable-glass 取材质，而那个属性同时命中 menu-shell 的 PAGE_GLASS_SELECTOR，
 * 会把这张卡注册成页面级采样目标 —— 它浮在预览台自己的图上而不是桌面壁纸上，
 * 两个采样器争写同一个 --adaptive-region-luma，对比度提示的趋势因此与真实渲染相反。
 * 预览卡需要真实模糊（否则模糊滑块调了看不见），所以允许它声明 backdrop-filter，
 * 前提是值必须是 var(--dwrt-glass-backdrop)，档位仍由合同与令牌决定。
 */
assert.doesNotMatch(style, /!important|#[0-9a-fA-F]{3,8}|rgba?\(\s*[\d.]/);
for (const declaration of style.match(/backdrop-filter:[^;]+;/g) || []) {
  assert.match(declaration, /var\(--dwrt-glass-backdrop\)/, `页面不得自定模糊档位: ${declaration}`);
}
assert.doesNotMatch(systemSource, /DREAMINGWRT_ACCENT_PRESETS|systemAppearancePanel|materialPreviewValue|emitMaterialPreview|updateAppearanceRangeValue|system-appearance/);
assert.doesNotMatch(systemStyle, /system-appearance-|system-accent-picker/);

console.log('ok: Phase 2 appearance owns one Registry-driven workbench, lazy media, delta save/readback, preview rollback, and no legacy renderer');
