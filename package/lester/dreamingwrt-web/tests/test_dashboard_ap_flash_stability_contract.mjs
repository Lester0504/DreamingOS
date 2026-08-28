import assert from 'node:assert/strict';
import fs from 'node:fs';

const source = fs.readFileSync(new URL('../files/www/dreamingwrt/static/js/dashboard.js', import.meta.url), 'utf8');

const mainStart = source.indexOf('  function renderDashboardMain(model) {');
const mainEnd = source.indexOf('\n\n  function patchDashboardThroughputRealtime(', mainStart);
const main = source.slice(mainStart, mainEnd);
assert.match(main, /if \(apView\) clearGatewayDetailCards\(\);\s*else \{\s*renderRankSections\(model\);\s*renderActiveUrlSection\(model\);/s);

const clearStart = source.indexOf('  function clearGatewayDetailCards() {');
const clearEnd = source.indexOf('\n\n  function switchDashboardView()', clearStart);
const clear = source.slice(clearStart, clearEnd);
assert.match(clear, /dashboardRankGrid\.childNodes\.length/);
assert.match(clear, /dashboardActiveUrlCard\.childNodes\.length/);

const chartStart = source.indexOf('  function renderTrafficChart(series) {');
const chartEnd = source.indexOf('\n\n  function compactHealthBuckets(', chartStart);
const chart = source.slice(chartStart, chartEnd);
for (const selector of ['chart-area down', 'chart-area up', 'chart-line down', 'chart-line up', 'chart-line connections', 'chart-line latency']) {
  assert.match(chart, new RegExp(`class="${selector}"`));
}
assert.match(chart, /class="dashboard-chart-empty"\$\{empty \? '' : ' hidden'\}/);

const patchStart = source.indexOf('  function patchTrafficChart(wrap, chart) {');
const patchEnd = source.indexOf('\n\n  function renderMonitorChart(', patchStart);
const patch = source.slice(patchStart, patchEnd);
assert.match(patch, /node\.hidden = !value/);
assert.match(patch, /empty\.hidden = !chart\.empty/);
assert.doesNotMatch(patch, /Boolean\(frame\.querySelector\('\.dashboard-chart-empty'\)\) !== Boolean\(chart\.empty\)/);

console.log('dashboard AP flash stability contract: ok');
