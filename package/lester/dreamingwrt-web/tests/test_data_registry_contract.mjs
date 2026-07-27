import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';


const source = fs.readFileSync(new URL('../files/www/dreamingwrt/static/js/dwrt-data-registry.js', import.meta.url), 'utf8');
const context = {
  window: {},
  fetch: globalThis.fetch,
  AbortController,
  DOMException,
  Error,
  Date,
  Map,
  Set,
  Object,
  Array,
  Number,
  TypeError,
  queueMicrotask,
  console
};
vm.createContext(context);
vm.runInContext(source, context, { filename: 'dwrt-data-registry.js' });

const DataRegistry = context.window.DWRTDataRegistry;
assert.equal(typeof DataRegistry, 'function');

let clock = 1000;
let calls = 0;
let release;
const pending = new Promise((resolve) => { release = resolve; });
const registry = new DataRegistry({
  now: () => clock,
  defaultTtlMs: 100,
  fetcher: async (_url, request) => {
    calls += 1;
    await pending;
    if (request.signal.aborted) throw new DOMException('aborted', 'AbortError');
    return { ok: true, json: async () => ({ data: { value: 42 }, meta: { generated_at: clock } }) };
  }
});
registry.define('test.entity', { url: '/api/test', owner: 'test', ttlMs: 100, units: { value: 'count' } });

const states = [];
const unsubscribe = registry.subscribe('test.entity', (snapshot) => states.push(snapshot.status));
const first = registry.request('test.entity');
const concurrent = registry.request('test.entity');
assert.equal(calls, 1, 'concurrent GETs must be merged');
release();
const [firstSnapshot, concurrentSnapshot] = await Promise.all([first, concurrent]);
assert.equal(firstSnapshot.value.value, 42);
assert.equal(concurrentSnapshot.revision, firstSnapshot.revision);
assert.deepEqual(states.slice(0, 3), ['empty', 'loading', 'ready']);

clock += 50;
await registry.request('test.entity');
assert.equal(calls, 1, 'fresh TTL data must be reused');
registry.patch('test.entity', { value: 43 }, { observedAt: clock });
assert.equal(registry.snapshot('test.entity').value.value, 43);
assert.equal(registry.snapshot('test.entity').observed_at, clock);
unsubscribe();

let queryCalls = 0;
const queryRegistry = new DataRegistry({
  fetcher: async (_url, request) => {
    queryCalls += 1;
    return { ok: true, json: async () => ({ data: { body: request.body } }) };
  }
});
queryRegistry.define('query.entity', { url: '/api/query', owner: 'test', ttlMs: 1000, request: { method: 'POST' } });
const queryStates = [];
const unsubscribeQuery = queryRegistry.subscribe('query.entity', (snapshot) => queryStates.push(snapshot), { cacheKey: 'alpha' });
await queryRegistry.request('query.entity', { cacheKey: 'alpha', request: { body: '{"query":"a"}' } });
await queryRegistry.request('query.entity', { cacheKey: 'alpha', request: { body: '{"query":"a"}' } });
await queryRegistry.request('query.entity', { cacheKey: 'beta', request: { body: '{"query":"b"}' } });
assert.equal(queryCalls, 2, 'query cache keys must isolate POST projections while preserving TTL reuse');
assert.equal(queryRegistry.snapshot('query.entity', { cacheKey: 'alpha' }).cache_key, 'alpha');
assert.equal(queryRegistry.snapshot('query.entity', { cacheKey: 'beta' }).value.body, '{"query":"b"}');
assert.deepEqual(queryStates.map((snapshot) => snapshot.status), ['empty', 'loading', 'ready']);
queryRegistry.invalidate('query.entity');
assert.equal(queryRegistry.snapshot('query.entity', { cacheKey: 'alpha' }).stale, true);
assert.equal(queryRegistry.snapshot('query.entity', { cacheKey: 'beta' }).stale, true);
unsubscribeQuery();

let abortObserved = false;
const abortRegistry = new DataRegistry({
  fetcher: (_url, request) => new Promise((_resolve, reject) => {
    request.signal.addEventListener('abort', () => {
      abortObserved = true;
      reject(new DOMException('aborted', 'AbortError'));
    }, { once: true });
  })
});
abortRegistry.define('abort.entity', { url: '/api/abort', owner: 'test' });
const route = new AbortController();
const abortedRequest = abortRegistry.request('abort.entity', { signal: route.signal });
route.abort();
const abortedSnapshot = await abortedRequest;
assert.equal(abortObserved, true, 'route AbortSignal must cancel the underlying GET');
assert.equal(abortedSnapshot.status, 'empty');

let fail = false;
const staleRegistry = new DataRegistry({
  now: () => clock,
  defaultTtlMs: 1,
  fetcher: async () => {
    if (fail) throw new Error('offline');
    return { ok: true, json: async () => ({ data: { value: 'last-known-good' } }) };
  }
});
staleRegistry.define('stale.entity', { url: '/api/stale', owner: 'test', ttlMs: 1 });
await staleRegistry.request('stale.entity');
clock += 10;
fail = true;
const stale = await staleRegistry.request('stale.entity');
assert.equal(stale.status, 'stale');
assert.equal(stale.stale, true);
assert.equal(stale.value.value, 'last-known-good');
assert.match(stale.error.message, /offline/);

console.log('ok: DataRegistry merges GET/query requests and preserves keyed TTL, subscriptions, Abort, patch, and last-known-good state');
