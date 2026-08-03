import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { normalizeFlowdCustomProtocols, normalizeFlowdObjects, normalizePolicyObjects, normalizeRoutingObjects } from '../files/www/dreamingwrt/plugins/native/policy-objects.js';
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

const routingObjects = normalizeRoutingObjects({
  ok: true,
  source: 'dreamingwrt.routed',
  revision: 19,
  items: [{ id: 'office-nets', name: '办公网段', type: 'ip_group', family: 'ipv4', members: [{ value: '10.20.0.0/16', label: '办公' }], ref_count: 2 }],
  capabilities: { object_crud: true }
});
assert.equal(routingObjects.items[0].members[0].value, '10.20.0.0/16');
assert.equal(routingObjects.items[0].refCount, 2);
assert.equal(routingObjects.source, 'dreamingwrt.routed');
assert.equal(routingObjects.readOnly, true);

const flowdProtocols = normalizeFlowdCustomProtocols({
  ok: true,
  total: 1,
  protocols: [{ id: 'quic-lab', name: '实验 QUIC', kind: 'l7', proto: 'udp', dst_port: '443', match: { sni: 'lab.example' }, tags: ['lab'], priority: 120 }]
});
assert.equal(flowdProtocols.items[0].dstPort, '443');
assert.equal(flowdProtocols.items[0].kind, 'l7');
assert.deepEqual(flowdProtocols.items[0].tags, ['lab']);
assert.equal(flowdProtocols.readOnly, true);

const flowdObjects = normalizeFlowdObjects({
  ok: true,
  total: 1,
  objects: [{
    id: 'office-dns', name: '办公 DNS', type: 'ipv4', enabled: true,
    value: ['10.20.0.53', '10.20.0.54'], value_count: 2, runtime_kind: 'nft_set',
    reference_count: 1, delete_locked: true,
    referenced_by: [{ kind: 'split_rule', id: 'office-route', name: '办公分流', field: 'dst_object', enabled: true }]
  }]
});
assert.equal(flowdObjects.items[0].valueCount, 2);
assert.equal(flowdObjects.items[0].runtimeKind, 'nft_set');
assert.equal(flowdObjects.items[0].refCount, 1);
assert.equal(flowdObjects.items[0].references[0].field, 'dst_object');
assert.equal(flowdObjects.items[0].deleteLocked, true);
assert.equal(flowdObjects.readOnly, true);

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
for (const endpoint of ['/api/v1/routing/objects', '/api/v1/flowd/objects', '/api/v1/flowd/custom-protocols']) {
  assert.ok(objectsSource.includes(endpoint), endpoint);
}
for (const forbidden of ['clients.inventory', 'network.lans', 'network.wans', '/api/v1/clients', '/catalog']) {
  assert.doesNotMatch(objectsSource, new RegExp(forbidden.replaceAll('.', '\\.')));
}
assert.match(objectsSource, /objects_atomic_apply/);
assert.match(objectsSource, /页面不会展示无法提交的名称、成员或模块开关/);
assert.doesNotMatch(objectsSource, /data-object-create|data-object-save|disabled[^\n]*添加对象/);
assert.doesNotMatch(objectsSource, /method:\s*['"](?:POST|PUT|PATCH|DELETE)['"]/);
assert.match(objectsSource, /data-object-tab="\$\{id\}"/);
assert.match(objectsSource, /不包含系统 catalog、内置应用签名或协议目录/);
assert.match(objectsSource, /引用关系仅覆盖 flowd 内部规则/);
assert.match(objectsSource, /runtime_kind 表示计划产物类型，不代表已经应用到数据面/);
assert.match(objectsSource, /referenced_by/);
assert.match(objectsSource, /数据面仍为 plan-only，未提供运行态应用证明/);
assert.match(objectsSource, /新增、编辑与删除归“策略引擎 → 路由表”所有/);
assert.match(objectsSource, /source\.status = error\?\.status === 403 \? 'forbidden' : error\?\.status === 404 \? 'unavailable' : 'error'/);
assert.match(objectsSource, /返回的列表合同无效/);
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
const SHARED_STYLE_VERSION = '20260802-ui-batch-01';
for (const item of [objectMenu, regionMenu]) {
  assert.equal(item.style, '/static/css/policy-entities.css');
  // the two pages share one stylesheet, so the style version must stay in lockstep
  assert.equal(item.style_version, SHARED_STYLE_VERSION);
}
assert.equal(objectMenu.module_version, '20260802-ui-batch-01');
assert.equal(regionMenu.module_version, '20260802-ui-batch-01');
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
// no separate page header; the write-capability badge stays in the zone table toolbar
assert.doesNotMatch(regionsSource, /policy-region-page-header|policy-region-header-heading/);
assert.match(regionsSource, /class="policy-region-workbench"/);
assert.match(css, /\.policy-region-workbench\s*\{[^}]*overflow:\s*auto/);
// 手动刷新按钮按用户第 9 条删除（连同它的 44px 命中区规则），改为可见性受控的轮询。
assert.doesNotMatch(regionsSource, /data-region-refresh/);
assert.doesNotMatch(css, /data-region-refresh/);
assert.match(regionsSource, /state\.pollTimer = window\.setInterval/);
assert.match(regionsSource, /dwrt-kit-table-toolbar-actions/);
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
assert.match(css, /\.policy-entity-sheet\s*\{[^}]*--dwrt-kit-sheet-width:\s*var\(--dwrt-kit-sheet-width-standard\)/);
// UniFi zone semantics stay intact: 6 zone rows/columns driven by real pair data
assert.match(regionsSource, /source_zone_id/);
assert.match(regionsSource, /destination_zone_id/);
assert.match(regionsSource, /policy_count/);

// Objects use the same transparent route grammar and shared Kit surfaces.
assert.doesNotMatch(objectsSource, /data-dwrt-component="page-shell"|data-dwrt-page-shell=|data-dwrt-surface="stable-glass"|data-dwrt-surface="dense-surface"/);
assert.match(objectsSource, /class="policy-object-toolbar"/);
assert.match(objectsSource, /class="policy-object-workbench"/);
assert.match(objectsSource, /dwrt-kit-tabs dwrt-kit-page-tabs policy-object-tabs/);
assert.match(objectsSource, /overviewCardsMarkup/);
assert.match(objectsSource, /policy-object-table policy-object-table-\$\{kind\} dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface/);
assert.equal((objectsSource.match(/data-dwrt-sheet-variant="copilot"/g) || []).length, 1);
assert.match(objectsSource, /\['flowObjects', '流量对象'\]/);
assert.match(objectsSource, /policy-object-reference-list/);
assert.match(objectsSource, /scrollIntoView\?\.\(\{ block: 'nearest', inline: 'center' \}\)/);
assert.match(css, /\.policy-object-source-view\s*\{[^}]*display:\s*grid/);
assert.match(css, /.console-stage:has\(\.policy-objects-route-host\)[^{]*\{[^}]*grid-template-rows:\s*minmax\(0, 1fr\)/);
assert.match(css, /\.policy-object-workbench\s*\{[^}]*gap:\s*12px[^}]*overflow:\s*auto/);
assert.match(css, /\.policy-entity-table\.dwrt-kit-table-wrap\s*\{[^}]*border-radius:\s*var\(--app-radius-card/);
assert.match(css, /@media \(max-width: 760px\)[^]*\.policy-object-tabs\s*\{[^}]*width:\s*0[^}]*flex:\s*1 1 0[^}]*overflow:\s*auto hidden/);
assert.match(css, /\.policy-object-toolbar \.policy-entity-header-actions\s*\{[^}]*width:\s*44px[^}]*flex:\s*0 0 44px/);
assert.match(css, /\.policy-object-toolbar \.policy-object-readonly-status\s*\{[^}]*display:\s*none/);

console.log('ok: policy entity contracts enforce read-only object capabilities, real zone CRUD/matrix data, scoped Registry use, stable overlays, and shared Kit ownership');
