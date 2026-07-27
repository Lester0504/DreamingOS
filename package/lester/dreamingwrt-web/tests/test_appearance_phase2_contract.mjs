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
assert.equal(page.module_version, '20260725-dreaming-os-01');
assert.equal(page.style, '/static/css/appearance-settings.css');
assert.equal(page.style_version, '20260722-04');
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
assert.doesNotMatch(style, /!important|backdrop-filter|#[0-9a-fA-F]{3,8}|rgba?\(\s*[\d.]/);
assert.doesNotMatch(systemSource, /DREAMINGWRT_ACCENT_PRESETS|systemAppearancePanel|materialPreviewValue|emitMaterialPreview|updateAppearanceRangeValue|system-appearance/);
assert.doesNotMatch(systemStyle, /system-appearance-|system-accent-picker/);

console.log('ok: Phase 2 appearance owns one Registry-driven workbench, lazy media, delta save/readback, preview rollback, and no legacy renderer');
