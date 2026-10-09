/* RSSI 分布行为验证：服务器分桶优先；缺少分桶时只按唯一 interface 映射 station。 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = fs.readFileSync(path.join(root, 'files/www/dreamingwrt/plugins/native/wifi-management.js'), 'utf8');

function grab(name) {
  const start = source.indexOf(`function ${name}`);
  if (start < 0) throw new Error(`not found: ${name}`);
  const brace = source.indexOf(') {', start) + 2;
  if (brace < 2) throw new Error(`body not found: ${name}`);
  let depth = 0;
  for (let index = brace; index < source.length; index += 1) {
    if (source[index] === '{') depth += 1;
    if (source[index] === '}' && --depth === 0) return source.slice(start, index + 1);
  }
  throw new Error(`unbalanced: ${name}`);
}

const harness = `
${grab('firstText')}
${grab('firstNumber')}
${grab('optionalNumber')}
${grab('asArray')}
${grab('radioInterfaceNames')}
${grab('signalBucketIndex')}
${grab('deriveStationSignalDistributions')}
${grab('signalDistributionData')}
${grab('signalDistributionCoverageCopy')}
return { deriveStationSignalDistributions, signalDistributionData, signalDistributionCoverageCopy };
`;
const api = new Function(harness)();
const checks = [];
const check = (name, condition, detail = '') => checks.push([condition ? 'PASS' : 'FAIL', name, detail]);

const radios = [
  { id: '2g', clients: 23, interfaces: [{ interface: 'ath0' }, { interface: 'ath01' }] },
  { id: '5g', clients: 8, interfaces: [{ interface: 'ath1' }, { interface: 'ath11' }] },
  { id: '6g', clients: 0, interfaces: [{ interface: 'ath2' }] }
];
const stations = [
  ...Array.from({ length: 23 }, (_, index) => ({ interface: index < 2 ? 'ath0' : 'ath01', signal_dbm: -69 + (index % 47) })),
  ...Array.from({ length: 8 }, (_, index) => ({ interface: index < 6 ? 'ath1' : 'ath11', signal_dbm: -65 + index * 4 }))
];
const derived = api.deriveStationSignalDistributions(radios, stations);
check('31 个现场 fixture 全部被唯一映射', derived.reduce((sum, row) => sum + row.sample_count, 0) === 31, JSON.stringify(derived));
check('2.4G 与 5G 样本保持隔离', derived[0].sample_count === 23 && derived[1].sample_count === 8 && derived[2].sample_count === 0);
check('每个 Radio 的桶计数之和等于有效样本数', derived.every((row) => row.counts.reduce((sum, value) => sum + value, 0) === row.sample_count));

const invalid = api.deriveStationSignalDistributions(radios, [
  { interface: 'ath0', signal_dbm: null },
  { signal_dbm: -50 },
  { interface: 'unknown0', signal_dbm: -40 }
]);
check('null RSSI 不进入图表', invalid[0].sample_count === 0 && invalid[0].missing_signal_count === 1);
check('缺 interface 与未知 interface 不塞进任意 Radio', invalid.every((row) => row.sample_count === 0));

const ambiguous = api.deriveStationSignalDistributions([
  { interfaces: ['ath0'] },
  { interfaces: ['ath0'] }
], [{ interface: 'ath0', signal_dbm: -42 }]);
check('跨 Radio 重名 interface 不作猜测', ambiguous.every((row) => row.sample_count === 0));

const withDerived = { ...radios[0], derived_signal_distribution: derived[0] };
const derivedData = api.signalDistributionData(withDerived);
check('无服务器桶时消费 station 派生结果', derivedData.source === 'stations' && derivedData.sample_count === 23);
check('覆盖完整时文案给出真实样本数', api.signalDistributionCoverageCopy(withDerived, derivedData).includes('23 个有效样本'));

const serverData = api.signalDistributionData({
  ...withDerived,
  signal_distribution: [1, 2, 3, 4, 5]
});
check('服务器分桶优先于本地派生', serverData.source === 'server' && serverData.counts.join(',') === '1,2,3,4,5');

const partial = api.signalDistributionData({
  clients: 4,
  signal_distribution: [],
  derived_signal_distribution: { counts: [0, 0, 1, 1, 0], sample_count: 2, matched_station_count: 3, missing_signal_count: 1 }
});
check('覆盖不全时不假定全量', api.signalDistributionCoverageCopy({ clients: 4 }, partial).includes('2/4'));

const zero = api.signalDistributionData({ clients: 0, signal_distribution: [1, 2, 3, 4, 5] });
check('0 client Radio 保持空态', zero.available === false && zero.sample_count === 0);

for (const [status, name, detail] of checks) console.log(`${status} - ${name}${detail ? ` [${detail}]` : ''}`);
if (checks.some(([status]) => status === 'FAIL')) process.exit(1);
console.log('\nok: station RSSI 只进入唯一 Radio，服务器桶优先且覆盖率诚实');
