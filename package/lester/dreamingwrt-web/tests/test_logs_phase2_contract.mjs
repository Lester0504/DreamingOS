import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';

const root = new URL('../', import.meta.url);
const adapter = fs.readFileSync(new URL('files/www/dreamingwrt/plugins/native/log-center.js', root), 'utf8');
const legacy = fs.readFileSync(new URL('files/www/dreamingwrt/static/js/log-center.js', root));
const css = fs.readFileSync(new URL('files/www/dreamingwrt/static/css/log-center.css', root));
const menu = JSON.parse(fs.readFileSync(new URL('files/www/dreamingwrt/static/menu/main.json', root), 'utf8'));
const manifest = JSON.parse(fs.readFileSync(new URL('redesign/route-manifest.json', root), 'utf8'));

// Baselines re-cut on 2026-08-02: the search moved onto a single kit expand-search
// inside .log-center-toolbar-actions (both left-rail call sites removed), the manual
// [data-log-refresh] button was deleted in favour of the existing 30s poll, and the
// detail drawer moved onto the kit's named width tier (--dwrt-kit-sheet-width-standard).
assert.equal(crypto.createHash('sha256').update(legacy).digest('hex'), 'dabf280b74ed79fccd49812d239dbfab2e1a8c167ca14b93e29a9c134cebac25');
assert.equal(crypto.createHash('sha256').update(css).digest('hex'), '3a7dcec6645221fa543c16a9ef5278c3ae4bc556f5148935c280467a77e378ae');
assert.doesNotMatch(legacy.toString('utf8'), /data-log-refresh/);
assert.match(legacy.toString('utf8'), /log-center-toolbar-actions/);
assert.doesNotMatch(css.toString('utf8'), /\.log-center-search-row/);
assert.match(legacy.toString('utf8'), /window\.DWRTLogCenter = \{ create, version: VERSION \}/);
assert.match(legacy.toString('utf8'), /data-log-center-shell/);
assert.match(legacy.toString('utf8'), /log-center-filter/);
assert.match(legacy.toString('utf8'), /log-center-main/);
assert.match(css.toString('utf8'), /\.log-center-shell/);
assert.match(css.toString('utf8'), /grid-template-columns: var\(--log-filter-width\) minmax\(0, 1fr\)/);

assert.match(adapter, /LEGACY_CONTROLLER_URL = '\/static\/js\/log-center\.js\?v=20260802-ui-batch-01'/);
assert.match(adapter, /window\.DWRTLogCenter\?\.create/);
assert.match(adapter, /context\.signal\?\.addEventListener\('abort', unmount/);
assert.match(adapter, /instance\?\.unmount\?\.\(\)/);
assert.doesNotMatch(adapter, /virtual-data-table|filter-sheet|logs\.entries|logs\.filters|logs\.settings/);

const logMenu = menu.items.find((item) => item.id === 'log-center');
assert.equal(logMenu.module, 'native/log-center.js');
assert.equal(logMenu.module_version, '20260802-ui-batch-01');
assert.equal(logMenu.style, '/static/css/log-center.css');
assert.equal(logMenu.style_version, '20260802-ui-batch-01');
const logRoute = manifest.routes.find((entry) => entry.route === '#/logs');
assert.equal(logRoute.owner, 'static/js/log-center.js');
assert.equal(logRoute.page_shell, 'master-detail');
assert.deepEqual(logRoute.registry, []);

console.log('ok: legacy log center bytes, layout, route adapter, and lifecycle contract are restored');
