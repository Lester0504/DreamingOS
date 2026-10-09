/*
 * 「24H丢包」口径契约。
 *
 * 数值来自 healthd 的主动探测（每轮 ping -c 3），后端只有一个 loss 值，
 * 所以页面必须：
 *   1) 只显示一个数字，不得画成上行/下行两个独立读数；
 *   2) 把探测口径写进提示，不得让人读成真实转发流量丢包率；
 *   3) 缺数据显示「不可用」，绝不显示 0%。
 *
 * 第 3 条是这个测试真正要守的地方：firstNumber() 对缺字段返回 0，
 * 一旦有人把 lossValue() 改回 firstNumber()，页面就会把「没采到样」
 * 画成「线路很好」。
 */
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../files/www/dreamingwrt/static/js/line-status.js', import.meta.url), 'utf8');

function nestedFunctionSource(name) {
  const start = source.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`missing ${name}`);
  const next = source.indexOf('\n    function ', start + 1);
  if (next < 0) throw new Error(`unterminated ${name}`);
  return source.slice(start, next).trim();
}

const LOSS_PROBE_TIP = source.match(/const LOSS_PROBE_TIP = '([^']+)'/)?.[1];
if (!LOSS_PROBE_TIP) throw new Error('LOSS_PROBE_TIP missing: the probe-source wording is no longer declared once');
for (const token of ['主动探测', 'ping 3 包', '非真实转发流量']) {
  if (!LOSS_PROBE_TIP.includes(token)) {
    throw new Error(`loss tooltip no longer names its source: missing "${token}"`);
  }
}

const context = {
  asArray: (value) => Array.isArray(value) ? value : [],
  firstText: (...values) => {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  },
  firstNumber: (...values) => {
    for (const value of values) {
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return 0;
  },
  escapeHtml: (value) => String(value === undefined || value === null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;'),
  LOSS_PROBE_TIP
};
vm.createContext(context);
vm.runInContext([
  nestedFunctionSource('lossValue'),
  nestedFunctionSource('formatPercent'),
  nestedFunctionSource('healthLossCellMarkup')
].join('\n'), context);

/* 缺失必须是「不可用」，不是 0% */
const missing = context.healthLossCellMarkup({});
if (!missing.includes('不可用')) throw new Error('missing loss must render 不可用');
if (/0%/.test(missing)) throw new Error('missing loss must never render as 0%');

/* 真实的 0 仍然是 0%，「没数据」与「零丢包」是两个事实 */
const zero = context.healthLossCellMarkup({ loss24h: 0 });
if (!/0%/.test(zero)) throw new Error('a genuine zero loss must still render 0%');
if (zero.includes('不可用')) throw new Error('a genuine zero must not be reported as unavailable');

function nestedFunctionSourceByName(name) {
  const start = source.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`missing ${name}`);
  const next = source.indexOf('\n    function ', start + 1);
  if (next < 0) throw new Error(`unterminated ${name}`);
  return source.slice(start, next).trim();
}
vm.runInContext([
  nestedFunctionSourceByName('lossValue'),
  nestedFunctionSourceByName('healthHistoryBuckets'),
  nestedFunctionSourceByName('healthBucketTone'),
  nestedFunctionSourceByName('healthTone'),
  nestedFunctionSourceByName('healthClass')
].join('\n'), context);
if (context.healthTone({ online: true, upLoss24h: null, downLoss24h: null, latencyAvg: 0, history: [] }) === 'ok') {
  throw new Error('missing loss and latency must not render as healthy');
}
if (context.healthTone({ online: true, upLoss24h: 0, downLoss24h: 0, latencyAvg: 18, history: [] }) !== 'ok') {
  throw new Error('a genuine zero loss with measured latency must be healthy');
}
if (context.healthClass({ online: true, upLoss24h: null, downLoss24h: null, latencyAvg: 0, history: [] }) !== 'health-unknown') {
  throw new Error('unknown health must use the neutral class');
}

/* 单值渲染：不得再出现上下行两个箭头读数 */
const both = context.healthLossCellMarkup({ loss24h: 33.33, lossSource: 'wan_health_bucket', lossSamples: 6803 });
if (both.includes('↑') || both.includes('↓')) {
  throw new Error('loss cell still renders two directional values from a single ping loss');
}
if (!both.includes('33.33%')) throw new Error('loss value not rendered');
if (!both.includes('主动探测')) throw new Error('loss cell tooltip must name the probe source');
if (!both.includes('6803')) throw new Error('sample count should be surfaced in the tooltip when known');

/*
 * 表头不得暗示真实转发口径，且必须挂本页 tooltip 机制。
 * 列名保持 4 字：实测 102px 列宽下「24H丢包（探测）」会被截断成
 * 「24H丢包（探...」，长文案要留给 tooltip，不能塞进表头。
 */
const header = source.match(/<thead><tr><th>线路<\/th><th>接入方式<\/th>[\s\S]*?<\/tr><\/thead>/)?.[0] || '';
if (!header.includes('探测丢包')) {
  throw new Error('line-health header no longer marks the loss column as probe-based');
}
if (/<th[^>]*>[^<]{7,}丢包[^<]*<\/th>/.test(header)) {
  throw new Error('loss header text is long enough to clip at the measured 102px column width');
}
if (!header.includes('data-line-tooltip')) {
  throw new Error('loss header must use the page tooltip mechanism, not a bare title');
}

/* 分桶提示同样只报一个丢包数字 */
const bucketTip = nestedFunctionSource('healthBucketTooltip');
if (bucketTip.includes('上行 ${formatPercent')) {
  throw new Error('bucket tooltip still splits one ping loss into up/down');
}
if (!bucketTip.includes('探测口径')) {
  throw new Error('bucket tooltip must state the probe measurement basis');
}

console.log('line health loss probe source contract: ok');
