import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';


const source = fs.readFileSync(new URL('../files/www/dreamingwrt/static/js/dwrt-session-gate.js', import.meta.url), 'utf8');
const values = new Map([
  ['dreamingwrt.web.accessToken', 'old-access'],
  ['dreamingwrt.web.refreshToken', 'refresh-token'],
  ['dreamingwrt.web.expiresAt', String(Date.now() + 60000)]
]);
const storage = {
  getItem: (key) => values.get(key) || null,
  setItem: (key, value) => values.set(key, String(value)),
  removeItem: (key) => values.delete(key)
};
const context = {
  window: { localStorage: storage, location: { pathname: '/app/', search: '', hash: '#/network/dns-service' } },
  localStorage: storage,
  location: { pathname: '/app/', search: '', hash: '#/network/dns-service' },
  fetch: globalThis.fetch,
  Response,
  CustomEvent: undefined,
  Date,
  Object,
  Number,
  String,
  Boolean,
  JSON,
  encodeURIComponent,
  console
};
vm.createContext(context);
vm.runInContext(source, context, { filename: 'dwrt-session-gate.js' });
const SessionGate = context.window.DWRTSessionGate;
assert.equal(typeof SessionGate, 'function');

let refreshCalls = 0;
let apiCalls = 0;
let releaseRefresh;
const refreshPending = new Promise((resolve) => { releaseRefresh = resolve; });
const gate = new SessionGate({
  storage,
  location: context.location,
  fetcher: async (url, request) => {
    if (url === '/api/v1/session/refresh') {
      refreshCalls += 1;
      await refreshPending;
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ data: { access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 900 } })
      };
    }
    apiCalls += 1;
    const authorized = request.headers?.Authorization === 'Bearer new-access';
    return {
      ok: authorized,
      status: authorized ? 200 : 401,
      text: async () => authorized ? '{"ok":true}' : '{"ok":false}'
    };
  }
});

const first = gate.fetch('/api/v1/system/status');
const second = gate.fetch('/api/v1/network/wans');
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(apiCalls, 2, 'both requests should observe the same expired access token');
assert.equal(refreshCalls, 1, 'concurrent 401 responses must share one refresh request');
releaseRefresh();
const [firstResponse, secondResponse] = await Promise.all([first, second]);
assert.equal(firstResponse.status, 200);
assert.equal(secondResponse.status, 200);
assert.equal(refreshCalls, 1);
assert.equal(values.get('dreamingwrt.web.accessToken'), 'new-access');

let requiredCount = 0;
const failedStorage = {
  getItem: (key) => key.endsWith('refreshToken') ? 'bad-refresh' : key.endsWith('accessToken') ? 'bad-access' : key.endsWith('expiresAt') ? '1' : null,
  setItem() {},
  removeItem() {}
};
const failedGate = new SessionGate({
  storage: failedStorage,
  location: context.location,
  onRequired: () => { requiredCount += 1; },
  fetcher: async () => ({ ok: false, status: 401, text: async () => '{"ok":false}' })
});
const failed = await Promise.all([failedGate.ensureFresh(), failedGate.ensureFresh(), failedGate.ensureFresh()]);
assert.deepEqual(failed, [false, false, false]);
assert.equal(requiredCount, 1, 'failed refresh must expose one recovery flow');
assert.equal(failedGate.required, true);
assert.match(failedGate.loginUrl(), /next=%2Fapp%2F%23%2Fnetwork%2Fdns-service/);
assert.equal(context.location.href, undefined, 'session failure must not destroy the current page by redirecting');

console.log('ok: SessionGate atomically merges refresh, retries requests, and preserves the current route on expiry');
