import assert from 'node:assert/strict';
import fs from 'node:fs';

const root = new URL('../', import.meta.url);
const read = (relative) => fs.readFileSync(new URL(relative, root), 'utf8');

const app = read('files/www/dreamingwrt/app/index.html');
const shell = read('files/www/dreamingwrt/static/js/menu-shell.js');
const prewarm = read('files/www/dreamingwrt/static/js/shell-prewarm.js');
const dashboard = read('files/www/dreamingwrt/static/js/dashboard.js');
const menu = JSON.parse(read('files/www/dreamingwrt/static/menu/main.json'));

assert.doesNotMatch(app, /<link[^>]+ai-assistant\.css/, 'app shell must not load AI CSS before user intent');
assert.doesNotMatch(prewarm, /ai-assistant\.(?:css|js)/, 'shell prewarm must not fetch AI assets');
assert.match(shell, /loadPageStyle\(GLOBAL_AI_ASSETS\.style\)[\s\S]*import\(`\$\{GLOBAL_AI_ASSETS\.module\.url\}/,
  'global AI must load its CSS before importing the module');
assert.match(shell, /aiGlobalPromise = null;[\s\S]*aiBootstrap\?\.setAttribute\('aria-busy', 'false'\)/,
  'failed AI loading must remain retryable and restore the bootstrap state');

const system = menu.items.find((item) => item.id === 'system');
const llm = system.children.find((item) => item.id === 'system-llm-settings');
assert.equal(llm.style, '/static/css/ai-assistant.css', 'LLM settings route still owns AI CSS');
assert.equal(llm.module, 'native/ai-assistant.js', 'LLM settings route still owns the AI module');

for (const legacy of ['warmDashboardHistory', 'didWarmHistory', 'prefetchTrafficHistory', 'historyLoading']) {
  assert.doesNotMatch(dashboard, new RegExp(legacy), `Dashboard must not retain ${legacy}`);
}
assert.doesNotMatch(dashboard, /selectedRange === 'realtime'\s*\?\s*\['1h', '1d'\]/,
  'realtime refresh must not expand into unselected history ranges');
assert.doesNotMatch(dashboard, /syncTrafficHistory\('1h', false, selectedDashboardWanId\(\)\)/,
  'switching back to realtime must not fetch 1h history');
assert.match(dashboard, /if \(selectedRange !== 'realtime'\)[\s\S]*syncTrafficHistory\(selectedRange, false, historyWanId\)/,
  'background refresh may only refresh the actively selected history range');
assert.match(dashboard, /if \(normalized !== 'realtime'\)[\s\S]*syncTrafficHistory\(normalized, true, selectedDashboardWanId\(\)\)/,
  'user range selection must request exactly that range for the selected WAN');
assert.match(dashboard, /if \(rangeId !== 'realtime'\)[\s\S]*syncTrafficHistory\(rangeId, false, state\.dashboard\.activeWanId\)/,
  'WAN switching must request only the currently selected historical range');
assert.doesNotMatch(dashboard, /aggregateWanHistoryPayloads|wanIds\.map\(fetchOne\)/,
  'ALL history must use its aggregate object instead of N+1 per-WAN requests');
assert.match(dashboard, /if \(selectedWanId !== 'all'\) query\.set\('wan_id', selectedWanId\)/,
  'history requests must scope only an explicitly selected WAN');
assert.match(dashboard, /class="dashboard-wan-availability[\s\S]*aria-label="\$\{escapeHtml\(description\)\}"/,
  'graphical WAN availability controls need a real accessible name');

console.log('dashboard and AI demand-loading contract: ok');
