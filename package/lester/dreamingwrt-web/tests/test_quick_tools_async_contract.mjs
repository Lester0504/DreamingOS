/* Quick tools must not present a pending probe as a measurement, and the long
   throughput job must be observable and abortable.

   Both defects were reported by acceptance against live 30.1 behaviour:
   ubus ping answers the first call with latency 0 / loss 100 / pending:true, and
   the throughput status/stop routes existed but were never called. */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = fs.readFileSync(path.join(root, 'files/www/dreamingwrt/plugins/native/quick-tools.js'), 'utf8');
const css = fs.readFileSync(path.join(root, 'files/www/dreamingwrt/static/css/quick-tools.css'), 'utf8');
const menu = JSON.parse(fs.readFileSync(path.join(root, 'files/www/dreamingwrt/static/menu/main.json'), 'utf8'));

const VERSION = source.match(/const VERSION = '([^']+)'/)?.[1];
if (!VERSION) throw new Error('quick-tools must declare VERSION');

for (const expected of [
  `const VERSION = '${VERSION}'`,
  'const ASYNC_POLL_INTERVAL_MS = 1000',
  'const ASYNC_POLL_TIMEOUT_MS = 15000',
  'function isPending(payload)',
  'payload.pending === true',
  'payload.has_result === false',
  'async function awaitAsyncResult(',
  'pendingTimeout: true',
  'async function trackThroughput(',
  'async function stopThroughput(',
  'async function refreshThroughput(',
  '/api/v1/toolkit/throughput/status?id=',
  "'/api/v1/toolkit/throughput/stop'",
  'data-throughput-stop',
  'function isMissingCapability(error)',
  "'method_not_registered'",
  'function failureNotice(error, prefix)',
  "'source_unavailable'",
  'function stale(seq)',
  'function clearTimers()',
  // Backend shipped traceroute and nslookup; both answer with object arrays the
  // generic key/value renderer would drop, so each needs a real table.
  "nslookup: '/api/v1/diagnostics/nslookup'",
  'function hopTable()',
  'function answerTable()',
  'data-hop-table',
  'data-answer-table',
  'function isEmptyAnswer(payload)',
  "'nxdomain_or_no_answer'",
  'error.payload = unwrap(json)'
]) {
  if (!source.includes(expected)) throw new Error(`missing quick-tools contract symbol: ${expected}`);
}

// 抓包任务、流表与吞吐进度三个手动刷新按钮按用户第 9 条删除；这三张表都是运行态视图，
// 所以改为按当前工具自动轮询（吞吐只在 running 时跟进），并在 busy 期间跳过。
for (const forbidden of ['data-capture-refresh', 'data-flow-refresh', 'data-throughput-refresh']) {
  if (source.includes(forbidden)) throw new Error(`quick-tools must not ship a manual refresh button: ${forbidden}`);
}
for (const expected of ['function pollActive()', 'function startPolling()', 'function stopPolling()', 'async function refreshThroughput(background = false)', 'async function loadFlows(background = false)']) {
  if (!source.includes(expected)) throw new Error(`missing quick-tools polling contract: ${expected}`);
}

// A daemon that is not answering on ubus is not the same thing as a random
// failure, and the backend asked for retry wording on 503 while older webd
// builds still report a never-registered method this way.
if (!source.includes('后端服务暂时不可用，请稍后重试')) {
  throw new Error('source_unavailable must not be reported as a generic execution failure');
}

// ubus ping only accepts wan_id / target / ifname. A count field would be sent
// and silently ignored, implying control the backend does not offer.
if (/field\('请求次数'/.test(source)) {
  throw new Error('ping must not offer a count field: the ubus policy does not accept it');
}

// A hop that does not answer is read from `timeout`, not from an empty address:
// some hops respond without giving up a name.
if (!/const timeout = hop\?\.timeout === true;/.test(source)) {
  throw new Error('hop rows must read timeout from the flag, not from an empty address');
}

// An empty resolver answer is a real result. webd maps ok:false to 400, so
// without this branch a valid NXDOMAIN reads as a broken call.
if (!/state\.result = error\.payload;/.test(source)) {
  throw new Error('an empty-but-valid diagnostics answer must render as a result, not a failure');
}

// Speedtest is a deliberate backend hold. The page must say so rather than
// letting the user click into a 501.
if (!source.includes('data-tool-pending')) {
  throw new Error('speedtest must explain why the capability is held back');
}

// The pending payload must never reach the render path unfiltered.
if (!/state\.result = isPending\(first\) \? await awaitAsyncResult\(/.test(source)) {
  throw new Error('runTool must poll before publishing an async result');
}

// A task without an id cannot be polled or stopped; that must be stated, not hidden.
if (!source.includes('后端未返回任务 id，无法查询进度或停止该任务')) {
  throw new Error('a throughput task without an id must be reported honestly');
}

// throughput/status returns iperf3 JSON under `result`; string-only console output
// used to print [object Object].
if (!/const rawCandidate = \[value\.output, value\.stdout, value\.result, value\.message\]\.find\(\(item\) => typeof item === 'string'/.test(source)) {
  throw new Error('console block must only accept string payloads');
}

if (!source.includes('unmount() { state.mounted = false; state.seq += 1; clearTimers();')) {
  throw new Error('unmount must cancel pending polls');
}

for (const expected of ['.quick-tool-task {', '.quick-tool-task-copy small {', '.quick-tool-pending {', '[data-hop-table] table']) {
  if (!css.includes(expected)) throw new Error(`missing throughput task bar style: ${expected}`);
}

// The DNS tool needs its own artwork; borrowing ping.svg would read as a
// duplicate card in the grid.
if (!fs.existsSync(path.join(root, 'files/www/dreamingwrt/static/toolkit/dns-lookup.svg'))) {
  throw new Error('missing static/toolkit/dns-lookup.svg');
}

function findQuickTools(items) {
  for (const item of items || []) {
    if (item.module === 'native/quick-tools.js') return item;
    const nested = findQuickTools(item.children);
    if (nested) return nested;
  }
  return null;
}

const entry = findQuickTools(menu.items || menu.menu || menu);
if (!entry) throw new Error('quick tools menu entry not found');
if (entry.module_version !== VERSION) {
  throw new Error(`quick-tools module_version must be bumped to ${VERSION}, saw ${entry.module_version}`);
}
if (entry.style_version !== VERSION) {
  throw new Error(`quick-tools style_version must be bumped to ${VERSION}, saw ${entry.style_version}`);
}

console.log('ok: quick tools polls async probes, tables traceroute hops and DNS answers, tracks and stops throughput, and names missing capabilities honestly');
