import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';

const root = new URL('../', import.meta.url);
const adapter = fs.readFileSync(new URL('files/www/dreamingwrt/plugins/native/log-center.js', root), 'utf8');
const legacy = fs.readFileSync(new URL('files/www/dreamingwrt/static/js/log-center.js', root));
const css = fs.readFileSync(new URL('files/www/dreamingwrt/static/css/log-center.css', root));
const menu = JSON.parse(fs.readFileSync(new URL('files/www/dreamingwrt/static/menu/main.json', root), 'utf8'));
const manifest = JSON.parse(fs.readFileSync(new URL('redesign/route-manifest.json', root), 'utf8'));

assert.equal(crypto.createHash('sha256').update(legacy).digest('hex'), '21596128c7c2d62a4baff7a5e8155dc3da88fd87cd2a7c4f8591215844f491f7');
assert.equal(crypto.createHash('sha256').update(css).digest('hex'), 'de25f901ed79fda56b9c6ae4c7d75ef8704f752fbe289a4c0d335a13ed749fcf');
assert.match(legacy.toString('utf8'), /window\.DWRTLogCenter = \{ create, version: VERSION \}/);
assert.match(legacy.toString('utf8'), /data-log-center-shell/);
assert.match(legacy.toString('utf8'), /log-center-filter/);
assert.match(legacy.toString('utf8'), /log-center-main/);
assert.match(css.toString('utf8'), /\.log-center-shell/);
assert.match(css.toString('utf8'), /grid-template-columns: var\(--log-filter-width\) minmax\(0, 1fr\)/);

assert.match(adapter, /LEGACY_CONTROLLER_URL = '\/static\/js\/log-center\.js\?v=20260722-legacy-restore-01'/);
assert.match(adapter, /window\.DWRTLogCenter\?\.create/);
assert.match(adapter, /context\.signal\?\.addEventListener\('abort', unmount/);
assert.match(adapter, /instance\?\.unmount\?\.\(\)/);
assert.doesNotMatch(adapter, /virtual-data-table|filter-sheet|logs\.entries|logs\.filters|logs\.settings/);

const logMenu = menu.items.find((item) => item.id === 'log-center');
assert.equal(logMenu.module, 'native/log-center.js');
assert.equal(logMenu.module_version, '20260722-legacy-restore-01');
assert.equal(logMenu.style, '/static/css/log-center.css');
assert.equal(logMenu.style_version, '20260722-legacy-restore-01');
const logRoute = manifest.routes.find((entry) => entry.route === '#/logs');
assert.equal(logRoute.owner, 'static/js/log-center.js');
assert.equal(logRoute.page_shell, 'master-detail');
assert.deepEqual(logRoute.registry, []);

console.log('ok: legacy log center bytes, layout, route adapter, and lifecycle contract are restored');
