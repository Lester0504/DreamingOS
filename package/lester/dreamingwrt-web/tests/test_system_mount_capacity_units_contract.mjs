/*
 * 挂载点容量单位与绑定挂载折叠合同。
 *
 * 两条缺陷各对应一组断言：
 *   1. 容量必须由 `*_bytes` 语义的字节数推导，不得对纯数字猜单位。
 *      sda5 的 20886798336 B 必须显示 19.5 GB，而不是 19.5 TB。
 *   2. 绑定挂载按 `bind_host_target` 折叠到宿主卡片，不并列成十几行同容量的 sda5。
 *
 * 反向验证方式记录在交接单里：把 `formatBytes(n)` 改回 `formatBytes(n * 1024)`，
 * 单位断言必须转红；去掉 `foldBindMounts` 的调用，折叠断言必须转红。
 */
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';

const source = fs.readFileSync(
  new URL('../files/www/dreamingwrt/plugins/native/system-settings.js', import.meta.url),
  'utf8'
);

function functionSource(name) {
  const start = source.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`missing ${name}`);
  const next = source.indexOf('\n  function ', start + 1);
  if (next < 0) throw new Error(`unterminated ${name}`);
  return source.slice(start, next).trim();
}

const context = {
  stringOr: (value) => (value === undefined || value === null ? '' : String(value).trim()),
  escapeHtml: (value) => String(value === undefined || value === null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;')
};
vm.createContext(context);
vm.runInContext([
  functionSource('formatBytes'),
  functionSource('mountBytesText'),
  functionSource('mountIsBind'),
  functionSource('mountBindHostTarget'),
  functionSource('mountTargetOf'),
  functionSource('mountRootIsPrefix'),
  functionSource('mountDerivedHostTarget'),
  functionSource('foldBindMounts'),
  functionSource('mountBindHosts')
].join('\n'), context);

const { mountBytesText, foldBindMounts, mountBindHosts, mountIsBind, mountRootIsPrefix } = context;

/* 30.1 实测取值：GET /api/v1/system/mounts 的 sda5 条目。 */
const SDA5_SIZE = 20886798336;
const SDA5_USED = 7861833728;
const SDA5_AVAIL = 11938013184;

/* --- 1. 单位：字节进字节出，禁止 KB 猜测 --- */
assert.equal(mountBytesText(SDA5_SIZE), '19.5 GB',
  'size_bytes 必须按字节格式化；显示 TB 说明又被当成 KB 乘了 1024');
assert.equal(mountBytesText(SDA5_USED), '7.32 GB');
assert.equal(mountBytesText(SDA5_AVAIL), '11.1 GB');

/* `size` 与 `size_bytes` 同值，两条路径必须给同一个结果。 */
assert.equal(mountBytesText(SDA5_SIZE), mountBytesText(undefined, SDA5_SIZE),
  'size 与 size_bytes 是同一个字节值，不得因字段名不同而差 1024 倍');

/* 量级哨兵：19.5 GB 与 19.5 TB 之间正好差一次 1024，直接把错误值钉死。 */
assert.notEqual(mountBytesText(SDA5_SIZE), '19.5 TB');
assert.equal(mountBytesText(SDA5_SIZE * 1024), '19.5 TB',
  '这条固定住换算基准：只有多乘一次 1024 才会得到 TB');

/* 带单位的字符串原样透传，不再二次换算。 */
assert.equal(mountBytesText('19.5G'), '19.5G');
/* 非法/空值不得渲染成 0 或 NaN。 */
assert.equal(mountBytesText(undefined, null, '', 0, -1), '');

/* --- 2. 折叠：15 条绑定挂载归到 /data 之下 --- */
const bindTargets = [
  '/etc/dreamingwrt', '/etc/config', '/etc/dropbear', '/etc/ssh', '/etc/nginx',
  '/etc/samba', '/etc/.app_store.id', '/etc/crontabs', '/etc/rc.local', '/etc/shadow',
  '/root', '/tmp/lib/dreamingwrt', '/opt/dreamingwrt', '/opt/docker', '/opt/containerd'
];
const points = [
  { device: '/dev/root', target: '/', root: '/', bind_mount: false, origin: 'runtime', fstype: 'ext4', size_bytes: 6284738560 },
  { device: '/dev/sda5', target: '/data', root: '/', bind_mount: false, origin: 'runtime', fstype: 'ext4',
    size_bytes: SDA5_SIZE, used_bytes: SDA5_USED, available_bytes: SDA5_AVAIL, used_percent: 37 },
  ...bindTargets.map((target) => ({
    device: '/dev/sda5', target, root: `/persist${target}`, bind_mount: true, origin: 'bind',
    bind_host_target: '/data', capacity_is_host_filesystem: true, fstype: 'ext4',
    size_bytes: SDA5_SIZE, used_bytes: SDA5_USED, available_bytes: SDA5_AVAIL, used_percent: 37
  }))
];

assert.equal(points.filter((p) => p.device === '/dev/sda5').length, 16, 'fixture 应复现 16 行 sda5');

const folded = foldBindMounts(points);
const sda5Rows = folded.filter((p) => p.device === '/dev/sda5');
assert.equal(sda5Rows.length, 1, `折叠后 sda5 只应剩宿主 1 行，实际 ${sda5Rows.length} 行`);
assert.equal(sda5Rows[0].target, '/data', '保留下来的必须是宿主整卷挂载');
assert.equal(sda5Rows[0].bind_children.length, 15, '15 条绑定挂载必须挂到宿主条目上，不能被丢弃');

/* 折叠是归组而不是删除：所有挂载路径都还在。 */
const visible = new Set(folded.flatMap((p) => [p.target, ...(p.bind_children || []).map((k) => k.target)]));
bindTargets.forEach((target) => assert.ok(visible.has(target), `${target} 不得在折叠中消失`));

/* 宿主卡片的摘要行列出子挂载，且不重复渲染容量数字。 */
const summary = mountBindHosts(sda5Rows[0]);
assert.match(summary, /绑定挂载 15 处/);
assert.match(summary, /\/opt\/containerd/);
assert.ok(!/19\.5/.test(summary), '折叠摘要不得重复宿主容量，否则又变成"16 个 19.5 GB 卷"的观感');

/* 宿主不在列表里时，绑定挂载必须独立成行而不是被藏掉。 */
const orphan = foldBindMounts([
  { device: '/dev/sda6', target: '/mnt/x', root: '/persist/x', bind_mount: true, origin: 'bind', bind_host_target: '/nowhere' }
]);
assert.equal(orphan.length, 1, '宿主缺失时不得隐藏绑定挂载');
assert.equal(orphan[0].target, '/mnt/x');

/* origin 别名也应识别为绑定挂载（后端同时下发 origin: 'bind'）。 */
assert.ok(mountIsBind({ origin: 'bind' }) && mountIsBind({ bind_mount: true }));
assert.ok(!mountIsBind({ origin: 'runtime', bind_mount: false }));

/*
 * --- 3. 旧 payload（contract v2，无 bind_host_target）也必须折叠 ---
 * 30.1 当前部署的 webd 就是 v2：只有 root / device，没有宿主字段。前端若只认新字段，
 * 页面得等后端先部署才会好，所以宿主要能就地按 root 前缀推导。
 */
const v2Points = points.map(({ bind_host_target, capacity_is_host_filesystem, ...rest }) => rest);
assert.ok(v2Points.every((p) => p.bind_host_target === undefined), 'v2 fixture 不得含宿主字段');
const v2Folded = foldBindMounts(v2Points);
const v2Sda5 = v2Folded.filter((p) => p.device === '/dev/sda5');
assert.equal(v2Sda5.length, 1, `v2 payload 也必须折叠成 1 行，实际 ${v2Sda5.length} 行`);
assert.equal(v2Sda5[0].target, '/data');
assert.equal(v2Sda5[0].bind_children.length, 15);

/* 推导宿主取最长前缀：嵌套绑定挂载的宿主是上一层，不是整卷挂载。 */
const nested = foldBindMounts([
  { device: '/dev/sda5', target: '/data', root: '/', bind_mount: false, origin: 'runtime' },
  { device: '/dev/sda5', target: '/mnt/outer', root: '/persist/outer', bind_mount: true, origin: 'bind' },
  { device: '/dev/sda5', target: '/mnt/outer/inner', root: '/persist/outer/inner', bind_mount: true, origin: 'bind' }
]);
assert.equal(nested.length, 1, '嵌套绑定挂载应逐层折叠到唯一的整卷挂载卡片');
assert.equal(nested[0].target, '/data');

/* 前缀判据按 `/` 分界，不做裸字符串比较。 */
assert.ok(mountRootIsPrefix('/persist/etc', '/persist/etc/config'));
assert.ok(!mountRootIsPrefix('/persist/etc', '/persist/etcetera'),
  '裸前缀比较会把 /persist/etcetera 错认成 /persist/etc 的子挂载');
assert.ok(mountRootIsPrefix('/', '/persist/etc'));

/* 跨设备不得互认宿主：同名 root 但不同 device 必须各自成行。 */
const crossDevice = foldBindMounts([
  { device: '/dev/sda5', target: '/data', root: '/', bind_mount: false, origin: 'runtime' },
  { device: '/dev/sda6', target: '/mnt/other', root: '/persist/other', bind_mount: true, origin: 'bind' }
]);
assert.equal(crossDevice.length, 2, '不同设备的绑定挂载不得被折叠到别的卷之下');

console.log('system_mount_capacity_units_contract: PASS');
