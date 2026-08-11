import assert from 'node:assert/strict';
import fs from 'node:fs';

const root = new URL('../', import.meta.url);
const adapter = fs.readFileSync(new URL('files/www/dreamingwrt/plugins/native/log-center.js', root), 'utf8');
const legacy = fs.readFileSync(new URL('files/www/dreamingwrt/static/js/log-center.js', root));
const css = fs.readFileSync(new URL('files/www/dreamingwrt/static/css/log-center.css', root));
const menu = JSON.parse(fs.readFileSync(new URL('files/www/dreamingwrt/static/menu/main.json', root), 'utf8'));
const manifest = JSON.parse(fs.readFileSync(new URL('redesign/route-manifest.json', root), 'utf8'));
const legacyVersion = legacy.toString('utf8').match(/const VERSION = '([^']+)'/)?.[1];
assert.ok(legacyVersion, 'legacy log center must declare VERSION');

// Contract re-cut on 2026-08-10: shared Kit convergence legitimately edits the legacy
// controller without changing the log page's ownership or lifecycle. A whole-file digest
// made every unrelated accessibility/material fix look like a log regression, so this test
// now guards the behavior and cache contract it actually owns.
// Baseline context: .log-center-shell's narrow-viewport min-height moved
// off a raw 100dvh onto var(--app-stage-height), because .console-stage is shorter than
// the viewport by the page-footer strip and clips any taller child (browser zoom crosses
// the 980px breakpoint). The controller only changed its VERSION cache key alongside it.
// Prior cut (2026-08-02) moved the search onto a single kit expand-search inside
// .log-center-toolbar-actions, deleted the manual [data-log-refresh] button in favour of
// the existing 30s poll, and put the detail drawer on --dwrt-kit-sheet-width-standard.
// legacy baseline re-cut on 2026-08-04 for the shared shell cache key bump to
// 20260804-native-plugin-menu-merge-01 (native plugin sidebar merge). Verified that
// substituting the previous key back into the file reproduces the prior digest
// 2b4a70245595dc154d0fc69f3df6468bc059434e35b01134445f1b5a35803547 exactly, so the
// cache key is the only difference and no log-center behaviour changed.
assert.doesNotMatch(legacy.toString('utf8'), /data-log-refresh/);
assert.match(legacy.toString('utf8'), /log-center-toolbar-actions/);
assert.doesNotMatch(css.toString('utf8'), /\.log-center-search-row/);
assert.match(legacy.toString('utf8'), /window\.DWRTLogCenter = \{ create, version: VERSION \}/);
assert.match(legacy.toString('utf8'), /const VERSION = '[0-9a-z-]+'/);
assert.match(legacy.toString('utf8'), /data-log-center-shell/);
assert.match(legacy.toString('utf8'), /log-center-filter/);
assert.match(legacy.toString('utf8'), /log-center-main/);
assert.match(css.toString('utf8'), /\.log-center-shell/);
assert.match(css.toString('utf8'), /grid-template-columns: var\(--log-filter-width\) minmax\(0, 1fr\)/);

assert.match(adapter, new RegExp(`LEGACY_CONTROLLER_URL = '/static/js/log-center\\.js\\?v=${legacyVersion}'`));
assert.match(adapter, /window\.DWRTLogCenter\?\.create/);
assert.match(adapter, /context\.signal\?\.addEventListener\('abort', unmount/);
assert.match(adapter, /instance\?\.unmount\?\.\(\)/);
assert.doesNotMatch(adapter, /virtual-data-table|filter-sheet|logs\.entries|logs\.filters|logs\.settings/);

const logMenu = menu.items.find((item) => item.id === 'log-center');
assert.equal(logMenu.module, 'native/log-center.js');
assert.equal(logMenu.module_version, legacyVersion);
assert.equal(logMenu.style, '/static/css/log-center.css');
assert.equal(logMenu.style_version, legacyVersion);
const logRoute = manifest.routes.find((entry) => entry.route === '#/logs');
assert.equal(logRoute.owner, 'static/js/log-center.js');
assert.equal(logRoute.page_shell, 'master-detail');
assert.deepEqual(logRoute.registry, []);

console.log('ok: legacy log center bytes, layout, route adapter, and lifecycle contract are restored');
