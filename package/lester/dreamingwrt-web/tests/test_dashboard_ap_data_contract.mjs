import assert from 'node:assert/strict';
import fs from 'node:fs';

const source = fs.readFileSync(new URL('../files/www/dreamingwrt/static/js/dashboard.js', import.meta.url), 'utf8');

assert.match(source, /wifiStatus:\s*'\/api\/v1\/wifi\/status'/);
assert.match(source, /activeApId:\s*'all'/);
assert.match(source, /apRealtimePoints:\s*new Map\(\)/);
assert.match(source, /function normalizeDashboardAp\(/);
assert.match(source, /function dashboardApSelection\(/);
assert.match(source, /function appendApTrafficSample\(/);
assert.match(source, /const sampledAt = Math\.max\(0, Number\(station\.observedAt\) \|\| 0\) \* 1000/);
assert.match(source, /if \(!sampledAt \|\| previous && sampledAt <= previous\.sampledAt\) return/);
assert.match(source, /const elapsed = previous \? \(sampledAt - previous\.sampledAt\) \/ 1000 : 0/);
assert.match(source, /const up = Math\.max\(0, \(station\.rxBytes - previous\.rxBytes\) \/ elapsed\)/);
assert.match(source, /const down = Math\.max\(0, \(station\.txBytes - previous\.txBytes\) \/ elapsed\)/);
assert.match(source, /elapsed < 0\.2 \|\| elapsed > 60/);
assert.match(source, /title:\s*'在线 SSID'/);
assert.match(source, /title:\s*'今日流量'/);
assert.match(source, /data-dashboard-\$\{apView \? 'ap' : 'wan'\}/);
assert.match(source, /missing:\s*'后端尚未提供 AP 历史流量'/);
assert.match(source, /if \(state\.dashboard\.viewMode === 'ap'\) return visibleTrafficPoints\(normalizedRange\)/);
assert.match(source, /<span>\$\{apView \? '信道利用率' : '延迟'\}<\/span>/);
assert.match(source, /<span>\$\{apView \? '在线终端' : '连接数'\}<\/span>/);
assert.doesNotMatch(source, /AP[^\n]{0,80}DPI 在线应用/);

console.log('dashboard AP data contract: ok');
