import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../files/www/dreamingwrt/static/js/dashboard.js', import.meta.url), 'utf8');

function functionSource(name) {
  const start = source.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`missing ${name}`);
  const next = source.indexOf('\n  function ', start + 1);
  if (next < 0) throw new Error(`unterminated ${name}`);
  return source.slice(start, next).trim();
}

const context = {
  Date: { now: () => context.now },
  now: 1000,
  state: { dashboard: { wanCounterSamples: new Map() } },
  asArray: (value) => Array.isArray(value) ? value : [],
  firstText: (...values) => String(values.find((value) => value !== undefined && value !== null && String(value).trim()) || ''),
  firstFiniteNumber: (...values) => {
    for (const value of values) {
      if (value === undefined || value === null || value === '') continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return null;
  },
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
  functionSource('wanRealtimeKey'),
  functionSource('rateSampleUnavailable'),
  functionSource('deriveWanRatesFromCounters')
].join('\n'), context);

const invalid = (down, up) => ({
  wans: [{
    id: 'wan',
    down_bytes: down,
    up_bytes: up,
    down_rate: 0,
    up_rate: 0,
    sample_valid: false,
    degraded: true,
    zero_reason: 'atomic_sample_missing'
  }]
});

const first = context.deriveWanRatesFromCounters(invalid(1000, 2000));
if (first.wans[0].sample_valid !== false) throw new Error('first counter sample must stay invalid');

context.now = 3000;
const derived = context.deriveWanRatesFromCounters(invalid(5000, 3000));
if (derived.wans[0].down_rate !== 2000 || derived.wans[0].up_rate !== 500) throw new Error('counter delta rate mismatch');
if (derived.wans[0].rate_source !== 'frontend_counter_delta') throw new Error('missing fallback source');

context.now = 5000;
const idle = context.deriveWanRatesFromCounters(invalid(5000, 3000));
if (idle.wans[0].down_rate !== 0 || idle.wans[0].up_rate !== 0 || idle.wans[0].zero_reason !== 'idle') throw new Error('idle delta mismatch');

context.now = 7000;
const reset = context.deriveWanRatesFromCounters(invalid(10, 20));
if (reset.wans[0].sample_valid !== false) throw new Error('counter reset must stay invalid');

console.log('dashboard WAN counter fallback: ok');
