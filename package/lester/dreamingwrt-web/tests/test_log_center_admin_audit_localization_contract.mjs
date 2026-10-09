import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(
  new URL('../files/www/dreamingwrt/static/js/log-center.js', import.meta.url),
  'utf8'
);

const window = {
  CSS: { escape: (value) => String(value) },
  clearTimeout() {},
  setTimeout() { return 1; }
};
const document = { getElementById() { return null; } };
vm.runInNewContext(source, {
  window,
  document,
  localStorage: { getItem() { return ''; } },
  fetch: async () => { throw new Error('network disabled in contract test'); },
  Intl,
  Date,
  JSON,
  Number,
  String,
  Array,
  Set,
  Map,
  Math,
  Object,
  RegExp,
  Boolean,
  Error
});

const controller = window.DWRTLogCenter.create({ routePreview: null });
controller.__test.setMode('AUDIT');

const liveLogin = {
  id: 'evt-login',
  category: 'ADMIN',
  event: 'auth.login.success',
  title: 'auth.login.success: agent-ro',
  message: 'auth.login.success: agent-ro',
  source_id: 'audit',
  program: 'dreamingwrt-webd',
  program_label: 'DreamingWrt Web',
  severity: 'LOW',
  type: 'AUDIT',
  timestamp: 1786900143000,
  client_ip: '192.168.30.2',
  result: 'success',
  object: 'agent-ro',
  parameters: {
    DEVICE: { name: 'DreamingWrt' },
    CLIENT: { ip: '192.168.30.2' },
    ADMIN: { id: 'agent-ro', name: 'agent-ro', actor: 'web:agent-ro' },
    AUDIT: { action: 'auth.login.success', client_ip: '192.168.30.2', result: 'success' },
    RAW: {
      detail_json: {
        web_audit: true,
        admin_name: 'agent-ro',
        actor: 'web:agent-ro',
        actor_channel: 'web',
        client_ip: '192.168.30.2',
        risk: 'low',
        result: 'success'
      }
    }
  },
  cef: 'CEF:0|DreamingWrt|Network|31.6|auth.login.success|raw title|3|src=192.168.30.2'
};

const login = controller.__test.normalizeLogItem(liveLogin, 0, 'logs/search');
assert.equal(login.eventLabel, 'Web 登录成功');
assert.equal(login.admin.name, 'agent-ro');
assert.equal(login.audit.channelLabel, 'Web');
assert.equal(login.audit.clientIp, '192.168.30.2');
assert.equal(login.audit.resultLabel, '成功');
assert.equal(login.audit.riskLabel, '低');
assert.match(login.message, /agent-ro 使用 Web 登录了 DreamingOS（DreamingWrt）/);
assert.doesNotMatch(login.message, /dreamingwrt-webd|auth\.login\.success:/);

const unknown = controller.__test.normalizeLogItem({
  ...liveLogin,
  id: 'evt-unknown',
  event: 'custom.future.action',
  action: 'custom.future.action',
  parameters: {
    ...liveLogin.parameters,
    AUDIT: { action: 'custom.future.action', result: 'success' },
    RAW: { detail_json: { ...liveLogin.parameters.RAW.detail_json, action: 'custom.future.action' } }
  }
}, 1, 'logs/search');
assert.equal(unknown.eventLabel, 'custom.future.action（未翻译事件）');

const dhcp = controller.__test.normalizeLogItem({
  ...liveLogin,
  id: 'evt-dhcp',
  event: 'network.dhcp.apply.failed',
  action: 'network.dhcp.apply.failed',
  object: 'AA:BB:CC:DD:EE:FF / 192.168.30.50',
  result: 'failed',
  failure_reason: 'dhcp_apply_failed_rolled_back',
  parameters: {
    ...liveLogin.parameters,
    AUDIT: {
      action: 'network.dhcp.apply.failed',
      object: 'AA:BB:CC:DD:EE:FF / 192.168.30.50',
      result: 'failed',
      failure_reason: 'dhcp_apply_failed_rolled_back',
      failure_stage: 'dhcpv6_readback',
      runtime_rolled_back: true,
      scope: 'lan'
    },
    RAW: {
      detail_json: {
        ...liveLogin.parameters.RAW.detail_json,
        action: 'network.dhcp.apply.failed',
        object: 'AA:BB:CC:DD:EE:FF / 192.168.30.50',
        result: 'failed',
        failure_reason: 'dhcp_apply_failed_rolled_back',
        failure_stage: 'dhcpv6_readback',
        runtime_rolled_back: true,
        scope: 'lan'
      }
    }
  }
}, 2, 'logs/search');
assert.equal(dhcp.eventLabel, '应用 DHCP 配置失败');
assert.equal(dhcp.audit.failureLabel, '应用失败，已回滚');
assert.equal(dhcp.audit.runtimeRolledBack, true);
assert.match(dhcp.message, /运行态已回滚/);
assert.match(dhcp.message, /阶段：dhcpv6_readback/);

const drawer = controller.__test.auditDrawerMarkup(dhcp);
for (const label of ['事件', '操作风险', '管理员名称', '访问方式', '源 IP 地址', '详情']) {
  assert.match(drawer, new RegExp(label));
}
assert.match(drawer, /<details class="log-detail-section log-detail-raw">/);
assert.match(drawer, /CEF 日志（高级）/);
assert.match(drawer, /失败原因/);
assert.match(drawer, /失败阶段/);
assert.match(drawer, /运行态回滚/);

assert.equal(controller.__test.isAuditReadNoise({ event: '/api/v1/logs/search', audit: {} }), true);
assert.equal(controller.__test.isAuditReadNoise({ event: '/api/v1/logs/query', audit: {} }), true);
assert.equal(controller.__test.isAuditReadNoise({ event: 'network.dhcp.reservation.create', audit: { operationType: 'create' } }), false);
const partial = controller.__test.normalizeLogItem({
  ...liveLogin,
  id: 'evt-partial',
  result: 'partial',
  parameters: {
    ...liveLogin.parameters,
    AUDIT: { ...liveLogin.parameters.AUDIT, result: 'partial' },
    RAW: { detail_json: { ...liveLogin.parameters.RAW.detail_json, result: 'partial' } }
  }
}, 3, 'logs/search');
assert.equal(partial.audit.resultLabel, '部分完成');
assert.match(controller.__test.auditDrawerMarkup(partial), /部分完成/);
// Sheet lifetime is exercised by the browser interaction fixture, independent
// of the names used by its close/unmount implementation.

console.log('ok: admin audit fields, Chinese labels, DHCP failure semantics, and folded CEF contract');
