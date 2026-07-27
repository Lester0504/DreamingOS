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
  nestedFunctionSource('connectionCountOf'),
  nestedFunctionSource('preferredConnectionCount')
].join('\n'), context);

if (context.preferredConnectionCount({ connections: 0 }, { connections: 197 }) !== 197) {
  throw new Error('realtime zero must not overwrite the REST line count');
}
if (context.preferredConnectionCount({ connections: 205 }, { connections: 197 }) !== 205) {
  throw new Error('a valid realtime line count must take over');
}
if (context.preferredConnectionCount({ connections: 0 }, { connections: 0 }) !== 0) {
  throw new Error('a genuine zero count must remain zero');
}

const realtimeApply = nestedFunctionSource('applyWanRealtime');
if (!realtimeApply.includes('mergeWanRealtimeIntoLineLoad(previousLoad, payload)')) {
  throw new Error('wan.metrics still replaces the REST line-load snapshot wholesale');
}
const refreshPanel = nestedFunctionSource('refreshPanel');
if (/panel\.id\s*===\s*['"]line-load['"]/.test(refreshPanel.match(/const wsCanSatisfyPanel[^;]+;/)?.[0] || '')) {
  throw new Error('active WebSocket still suppresses the 5-second line-load REST refresh');
}

console.log('line status connection precedence: ok');
