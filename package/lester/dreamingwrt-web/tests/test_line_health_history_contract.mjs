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

const context = {
  lossValue: (...values) => {
    for (const value of values) {
      if (value === undefined || value === null || value === '') continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return null;
  },
  asArray: (value) => Array.isArray(value) ? value : [],
  firstText: (...values) => String(values.find((value) => value !== undefined && value !== null && String(value).trim()) || ''),
  firstNumber: (...values) => {
    for (const value of values) {
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return 0;
  }
};
vm.createContext(context);
vm.runInContext([
  nestedFunctionSource('healthHistoryBuckets'),
  nestedFunctionSource('healthBucketTone')
].join('\n'), context);

const history = Array.from({ length: 48 }, (_, index) => ({
  ts: 1784700000 + index * 1800,
  status: index === 46 ? 'down' : 'ok',
  latency_avg: index === 46 ? 999 : 12,
  loss_up: index === 46 ? 100 : 0,
  loss_down: index === 46 ? 100 : 0,
  samples: 120
}));

const buckets = context.healthHistoryBuckets({
  online: false,
  status: 'down',
  history
});
if (buckets.length !== 48) throw new Error(`expected 48 buckets, got ${buckets.length}`);
if (context.healthBucketTone(buckets[0]) !== 'ok') throw new Error('current WAN state recolored prior healthy history');
if (context.healthBucketTone(buckets[46]) !== 'bad') throw new Error('recorded down bucket must remain bad');
if (context.healthBucketTone(buckets[47]) !== 'ok') throw new Error('later recovered bucket must remain healthy');

const realtimeMerge = nestedFunctionSource('mergeWanRealtimeIntoHealth');
if (!realtimeMerge.includes('const retainedHistory')) {
  throw new Error('realtime merge must preserve REST health history');
}
if (!realtimeMerge.includes('merged.history = history')) {
  throw new Error('realtime merge must keep a single stable history source');
}

const style = fs.readFileSync(new URL('../files/www/dreamingwrt/static/css/line-status.css', import.meta.url), 'utf8');
if (!style.includes('.line-health-summary-track i.is-ok') || !style.includes('.line-health-summary-track i.is-bad')) {
  throw new Error('health timeline must render per-bucket tone classes');
}

console.log('line health history semantics: ok');
