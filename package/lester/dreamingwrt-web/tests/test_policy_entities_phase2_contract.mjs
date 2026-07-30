import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { normalizePolicyObjects } from '../files/www/dreamingwrt/plugins/native/policy-objects.js';
import { normalizePolicyRegions, normalizeZoneMatrix } from '../files/www/dreamingwrt/plugins/native/policy-regions.js';

const objectsSource = readFileSync(new URL('../files/www/dreamingwrt/plugins/native/policy-objects.js', import.meta.url), 'utf8');
const regionsSource = readFileSync(new URL('../files/www/dreamingwrt/plugins/native/policy-regions.js', import.meta.url), 'utf8');
const css = readFileSync(new URL('../files/www/dreamingwrt/static/css/policy-entities.css', import.meta.url), 'utf8');
const menu = JSON.parse(readFileSync(new URL('../files/www/dreamingwrt/static/menu/main.json', import.meta.url), 'utf8'));
const manifest = JSON.parse(readFileSync(new URL('../redesign/route-manifest.json', import.meta.url), 'utf8'));

const objects = normalizePolicyObjects({
  items: [{ id: 'servers', name: '服务器', object_type: 'device_group', family: 'ipv4', enabled: true }],
  legacy_route_objects: [{ id: 'legacy-vpn', label: '旧 VPN 目标', type: 'route_object', enabled: false }],
  capabilities: { objects_crud: true, objects_atomic_apply: false },
  objects_write_blocked_reason: 'cross_component_firewall_pbr_sqm_flowd_transaction_pending'
});
assert.equal(objects.items[0].name, '服务器');
assert.equal(objects.legacy[0].legacy, true);
assert.equal(objects.readOnly, true);

const regions = normalizePolicyRegions({
  zones: [{ id: 'lan', name: 'lan', display_name: 'LAN', members: ['lan'], reference_count: 3 }],
  virtual_zones: [{ id: 'gateway', name: 'gateway', display_name: 'Gateway' }],
  capabilities: { zones_crud: true },
  network_membership_unique: true
});
assert.equal(regions.zones.length, 2);
assert.equal(regions.zones[1].virtual, true);
assert.equal(regions.zones[1].locked, true);
assert.equal(regions.membershipUnique, true);

const matrix = normalizeZoneMatrix({
  zones: ['lan', 'wan'],
  pairs: [{ source_zone_id: 'lan', destination_zone_id: 'wan', effective_action: 'allow', forwarding_enabled: true, policy_count: 2, ipv4_policy_count: 1, ipv6_policy_count: 1, rule_ids: ['rule-1'] }]
});
assert.deepEqual(matrix.zoneIds, ['lan', 'wan']);
assert.equal(matrix.pairs[0].action, 'allow');
assert.equal(matrix.pairs[0].policyCount, 2);

for (const key of ['policy.objects']) assert.match(objectsSource, new RegExp(`registry\\.request\\('${key}'`));
for (const forbidden of ['clients.inventory', 'network.lans', 'network.wans', '/api/v1/clients', '/catalog']) {
  assert.doesNotMatch(objectsSource, new RegExp(forbidden.replaceAll('.', '\\.')));
}
assert.match(objectsSource, /objects_atomic_apply/);
assert.match(objectsSource, /页面不会展示无法提交的名称、成员或模块开关/);
assert.doesNotMatch(objectsSource, /data-object-create|data-object-save|disabled[^\n]*添加对象/);
assert.match(objectsSource, /policy-entity-page-host/);
assert.match(objectsSource, /policy-entity-overlay-host/);

for (const key of ['policy.regions', 'policy.zoneMatrix', 'policy.table', 'network.lans', 'network.wans']) {
  assert.match(regionsSource, new RegExp(`registry\\.request\\('${key}'`));
}
assert.match(regionsSource, /data-dwrt-component="data-grid"/);
assert.match(regionsSource, /dwrt-grid-select/);
assert.match(regionsSource, /dwrt-grid-activate/);
assert.match(regionsSource, /\/api\/v1\/policy-engine\/zones/);
assert.match(regionsSource, /method: creating \? 'POST' : 'PUT'/);
assert.match(regionsSource, /method: 'DELETE'/);
assert.match(regionsSource, /refreshQueued/);
assert.doesNotMatch(regionsSource, /\/zones\/matrix|FIXED_ZONES|区域 CRUD 不存在/);
assert.doesNotMatch(objectsSource + regionsSource, /\.innerHTML\s*=/);

const policy = menu.items.find((item) => item.id === 'policy-engine');
const objectMenu = policy.children.find((item) => item.id === 'policy-object');
const regionMenu = policy.children.find((item) => item.id === 'policy-region');
const SHARED_STYLE_VERSION = '20260730-policy-workbench-unify-14';
for (const item of [objectMenu, regionMenu]) {
  assert.equal(item.style, '/static/css/policy-entities.css');
  // the two pages share one stylesheet, so the style version must stay in lockstep
  assert.equal(item.style_version, SHARED_STYLE_VERSION);
}
assert.equal(objectMenu.module_version, '20260730-policy-objects-unify-03');
assert.equal(regionMenu.module_version, '20260730-policy-regions-unify-10');
assert.equal(objectMenu.module, 'native/policy-objects.js');
assert.equal(regionMenu.module, 'native/policy-regions.js');

const objectRoute = manifest.routes.find((entry) => entry.route === '#/policy-engine/objects');
const regionRoute = manifest.routes.find((entry) => entry.route === '#/policy-engine/regions');
assert.equal(objectRoute.owner, 'plugins/native/policy-objects.js');
assert.equal(objectRoute.page_shell, 'data-workbench');
assert.deepEqual(objectRoute.registry, ['policy.objects']);
assert.equal(regionRoute.owner, 'plugins/native/policy-regions.js');
assert.deepEqual(regionRoute.registry, ['policy.regions', 'policy.zoneMatrix', 'policy.table', 'network.lans', 'network.wans']);

assert.doesNotMatch(css, /!important|backdrop-filter|#[0-9a-fA-F]{3,8}|rgba?\(/);
assert.match(css, /overscroll-behavior:\s*contain/);
assert.match(css, /policy-entity-overlay-host:empty/);

// --- 区域 must follow the shared page grammar, not invent its own surface ---
// no page-level frosted panel: the material comes from Kit table/sheet surfaces
assert.doesNotMatch(regionsSource, /stable-glass/);
assert.doesNotMatch(regionsSource, /data-dwrt-component="page-shell"|data-dwrt-page-shell=/);
// no separate page header; status and refresh remain in the zone table toolbar
assert.doesNotMatch(regionsSource, /policy-region-page-header|policy-region-header-heading/);
assert.match(regionsSource, /class="policy-region-workbench"/);
assert.match(css, /\.policy-region-workbench\s*\{[^}]*overflow:\s*auto/);
assert.match(css, /\.policy-region-zone-table \[data-region-refresh\][^}]*min-width:\s*44px[^}]*min-height:\s*44px/);
assert.match(regionsSource, /dwrt-kit-table-toolbar-actions[^]*data-region-refresh/);
assert.match(regionsSource, /事务写入可用/);
// relationship diagram, zone table, matrix and policy table ride shared stable glass
assert.match(regionsSource, /function topologyMarkup\(\)/);
assert.match(regionsSource, /class="policy-region-flow dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"/);
for (const marker of [
  'class="policy-entity-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface policy-region-zone-table"',
  'class="policy-entity-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface policy-region-matrix-section"',
  'class="policy-entity-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface policy-region-policy-section"'
]) {
  assert.ok(regionsSource.includes(marker), marker);
}
assert.equal((regionsSource.match(/dwrt-kit-glass-surface/g) || []).length, 4);
assert.doesNotMatch(regionsSource, /data-dwrt-surface="dense-surface"/);
assert.doesNotMatch(css, /policy-region-flow-node[^}]*border:\s*1px dashed/);
assert.doesNotMatch(css, /policy-region-flow-node[^}]*background:[^;}]*color-accent/);
assert.doesNotMatch(css, /policy-region-flow-(?:node\s*>\s*span|link)[^}]*color:[^;}]*color-accent/);
assert.match(css, /policy-region-flow-node\s*>\s*span[^}]*color:\s*var\(--app-text-muted/);
assert.match(css, /policy-region-flow-link[^}]*color:\s*var\(--app-text-muted/);
assert.match(regionsSource, /data-region-family="ipv4"/);
assert.match(regionsSource, /data-region-family="ipv6"/);
assert.match(regionsSource, /data-region-policy-search/);
assert.match(regionsSource, /data-region-manage-policies/);
assert.match(regionsSource, /<button type="button" role="gridcell"/);
assert.match(regionsSource, /state\.selectedPair = pair/);
assert.match(regionsSource, /function visiblePolicies\(\)/);
assert.match(css, /.console-stage:has\(\.policy-regions-route-host\)[^{]*\{[^}]*grid-template-rows:\s*minmax\(0, 1fr\)/);
assert.match(css, /\.policy-region-matrix\s*\{[^}]*background:\s*transparent/);
assert.match(css, /\.policy-region-matrix-cell\s*\{[^}]*min-height:\s*32px/);
assert.doesNotMatch(css, /\.policy-region-matrix-cell\.is-(?:success|danger|return) strong\s*\{[^}]*color:\s*var\(--color-(?:success|danger|info)/);
assert.match(regionsSource, /state\.sheetReturnFocus = trigger instanceof HTMLElement \? trigger : null/);
assert.match(regionsSource, /focusTarget instanceof HTMLElement\) focusTarget\.focus\(\{ preventScroll: true \}\)/);
assert.match(regionsSource, /returnFocus\?\.isConnected\) returnFocus\.focus\(\{ preventScroll: true \}\)/);
// drawers reuse the shared copilot sheet instead of a hand-rolled panel
assert.equal((regionsSource.match(/data-dwrt-sheet-variant="copilot"/g) || []).length, 2);
assert.match(css, /\.policy-entity-sheet\s*\{[^}]*--dwrt-kit-sheet-width:\s*min\(460px,/);
// UniFi zone semantics stay intact: 6 zone rows/columns driven by real pair data
assert.match(regionsSource, /source_zone_id/);
assert.match(regionsSource, /destination_zone_id/);
assert.match(regionsSource, /policy_count/);

// Objects use the same transparent route grammar and shared Kit surfaces.
assert.doesNotMatch(objectsSource, /data-dwrt-component="page-shell"|data-dwrt-page-shell=|data-dwrt-surface="stable-glass"|data-dwrt-surface="dense-surface"/);
assert.match(objectsSource, /class="policy-object-toolbar"/);
assert.match(objectsSource, /class="policy-object-workbench"/);
assert.match(objectsSource, /overviewCardsMarkup/);
assert.match(objectsSource, /policy-object-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface/);
assert.equal((objectsSource.match(/data-dwrt-sheet-variant="copilot"/g) || []).length, 1);
assert.match(css, /.console-stage:has\(\.policy-objects-route-host\)[^{]*\{[^}]*grid-template-rows:\s*minmax\(0, 1fr\)/);
assert.match(css, /\.policy-object-workbench\s*\{[^}]*gap:\s*12px[^}]*overflow:\s*auto/);
assert.match(css, /\.policy-entity-table\.dwrt-kit-table-wrap\s*\{[^}]*border-radius:\s*var\(--app-radius-card/);

console.log('ok: policy entity contracts enforce read-only object capabilities, real zone CRUD/matrix data, scoped Registry use, stable overlays, and shared Kit ownership');
