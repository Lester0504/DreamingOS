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
  functionSource('trustedWanUptime'),
  functionSource('wanRealtimeKey'),
  functionSource('uniqueStrings'),
  functionSource('mergeDashboardWanInputs')
].join('\n'), context);

const configured = [
  { id: 'wan', runtime: { connections: 520, connected_seconds: 3600 } },
  { id: 'wan2', runtime: { connections: 210, connected_seconds: 7200 } }
];
const zeroSnapshot = [
  { id: 'wan', connections: 0, connected_seconds: 0 },
  { id: 'wan2', connections: 0, connected_seconds: 0 }
];
const preserved = context.mergeDashboardWanInputs(configured, zeroSnapshot);
if (preserved[0].connections !== 520 || preserved[1].connections !== 210) {
  throw new Error(`snapshot zero overwrote valid WAN counts: ${JSON.stringify(preserved)}`);
}
if (preserved[0].connected_seconds !== 3600 || preserved[1].connected_seconds !== 7200) {
  throw new Error(`snapshot zero overwrote valid WAN uptimes: ${JSON.stringify(preserved)}`);
}

const liveSnapshot = [
  { id: 'wan', connections: 531, connected_seconds: 3610 },
  { id: 'wan2', connections: 219, connected_seconds: 7210 }
];
const updated = context.mergeDashboardWanInputs(configured, liveSnapshot);
if (updated[0].connections !== 531 || updated[1].connections !== 219) throw new Error('valid live counts did not take over');
if (updated[0].connected_seconds !== 3610 || updated[1].connected_seconds !== 7210) throw new Error('valid live uptimes did not take over');
const throughputMerge = functionSource('mergeThroughputIntoLastModel');
if (/connections:\s*preferredDashboardConnectionCount\(live\.connections/.test(throughputMerge)) {
  throw new Error('dashboard.throughput still owns per-WAN connection counts');
}
const throughputApply = functionSource('applyDashboardThroughputRealtime');
if (!/appendWanRealtimePoints\(data,\s*\{\s*trustIncomingConnections:\s*false\s*\}\)/.test(throughputApply)) {
  throw new Error('dashboard.throughput chart points still trust incoming connection counts');
}
const freshPreservation = functionSource('preserveFreshThroughput');
if (/connections\s*:/.test(freshPreservation)) {
  throw new Error('fresh throughput preservation still overwrites refreshed WAN connection counts');
}

console.log('dashboard WAN merge semantics: ok');
