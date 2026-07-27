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
for (const item of [objectMenu, regionMenu]) {
  assert.equal(item.style, '/static/css/policy-entities.css');
  assert.equal(item.module_version, '20260721-02');
  assert.equal(item.style_version, '20260721-02');
}
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

console.log('ok: policy entity contracts enforce read-only object capabilities, real zone CRUD/matrix data, scoped Registry use, stable overlays, and shared Kit ownership');
