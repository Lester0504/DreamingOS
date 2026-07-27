(() => {
  'use strict';

  const DEFAULT_TTL_MS = 5000;

  function now() {
    return Date.now();
  }

  function abortError() {
    try { return new DOMException('The operation was aborted.', 'AbortError'); } catch (_) {
      const error = new Error('The operation was aborted.');
      error.name = 'AbortError';
      return error;
    }
  }

  function linkSignal(signal, controller) {
    if (!signal) return () => {};
    if (signal.aborted) {
      controller.abort(signal.reason || abortError());
      return () => {};
    }
    const abort = () => controller.abort(signal.reason || abortError());
    signal.addEventListener('abort', abort, { once: true });
    return () => signal.removeEventListener('abort', abort);
  }

  function unwrap(payload) {
    if (!payload || typeof payload !== 'object') return payload;
    if (payload.data !== undefined) return payload.data;
    if (payload.body !== undefined) return payload.body;
    return payload;
  }

  class DataRegistry {
    constructor(options = {}) {
      this.fetcher = options.fetcher || ((url, request) => fetch(url, request));
      this.now = options.now || now;
      this.defaultTtlMs = Math.max(0, Number(options.defaultTtlMs) || DEFAULT_TTL_MS);
      this.entries = new Map();
      this.schemas = new Map();
    }

    define(key, schema = {}) {
      if (!key) throw new TypeError('DataRegistry key is required');
      const normalized = {
        key,
        owner: schema.owner || '',
        url: schema.url || '',
        ttlMs: Math.max(0, Number(schema.ttlMs ?? this.defaultTtlMs) || 0),
        units: schema.units || {},
        project: typeof schema.project === 'function' ? schema.project : unwrap,
        request: schema.request || {}
      };
      this.schemas.set(key, normalized);
      return normalized;
    }

    entryKey(key, options = {}) {
      const cacheKey = String(options.cacheKey || '').trim();
      return cacheKey ? `${key}::${cacheKey}` : key;
    }

    entry(key) {
      let entry = this.entries.get(key);
      if (!entry) {
        entry = {
          key,
          status: 'empty',
          value: undefined,
          error: null,
          observedAt: 0,
          updatedAt: 0,
          stale: false,
          promise: null,
          controller: null,
          subscribers: new Set(),
          revision: 0
        };
        this.entries.set(key, entry);
      }
      return entry;
    }

    snapshot(key, options = {}) {
      const entry = this.entry(this.entryKey(key, options));
      return Object.freeze({
        key: entry.key,
        schema_key: key,
        cache_key: String(options.cacheKey || ''),
        status: entry.status,
        value: entry.value,
        error: entry.error,
        observed_at: entry.observedAt || null,
        updated_at: entry.updatedAt || null,
        stale: entry.stale,
        revision: entry.revision
      });
    }

    notify(entry) {
      const snapshot = Object.freeze({
        key: entry.key,
        schema_key: entry.schemaKey || entry.key,
        cache_key: entry.cacheKey || '',
        status: entry.status,
        value: entry.value,
        error: entry.error,
        observed_at: entry.observedAt || null,
        updated_at: entry.updatedAt || null,
        stale: entry.stale,
        revision: entry.revision
      });
      entry.subscribers.forEach((listener) => {
        try { listener(snapshot); } catch (error) { queueMicrotask(() => { throw error; }); }
      });
      return snapshot;
    }

    subscribe(key, listener, options = {}) {
      if (typeof listener !== 'function') throw new TypeError('DataRegistry listener must be a function');
      const entryKey = this.entryKey(key, options);
      const entry = this.entry(entryKey);
      entry.schemaKey = key;
      entry.cacheKey = String(options.cacheKey || '');
      entry.subscribers.add(listener);
      if (options.immediate !== false) listener(this.snapshot(key, options));
      return () => {
        entry.subscribers.delete(listener);
        if (!entry.subscribers.size && entry.controller && options.abortWhenUnused !== false) {
          entry.controller.abort(abortError());
        }
      };
    }

    async request(key, options = {}) {
      const schema = this.schemas.get(key) || this.define(key, options);
      const entryKey = this.entryKey(key, options);
      const entry = this.entry(entryKey);
      entry.schemaKey = key;
      entry.cacheKey = String(options.cacheKey || '');
      const ttlMs = Math.max(0, Number(options.ttlMs ?? schema.ttlMs) || 0);
      const age = this.now() - entry.updatedAt;
      const fresh = entry.value !== undefined && age <= ttlMs;
      if (!options.force && fresh) return this.snapshot(key, options);
      if (entry.promise) return entry.promise;

      const url = options.url || schema.url;
      if (!url) {
        entry.status = 'unavailable';
        entry.error = new Error(`DataRegistry ${key} has no URL`);
        return this.notify(entry);
      }

      const hasValue = entry.value !== undefined;
      entry.status = hasValue ? 'refreshing' : 'loading';
      entry.stale = hasValue && age > ttlMs;
      entry.error = null;
      this.notify(entry);

      const controller = new AbortController();
      const unlink = linkSignal(options.signal, controller);
      entry.controller = controller;
      entry.promise = (async () => {
        try {
          const response = await this.fetcher(url, {
            ...schema.request,
            ...(options.request || {}),
            signal: controller.signal
          });
          let payload = response;
          if (response && typeof response === 'object' && typeof response.json === 'function') {
            if ('ok' in response && !response.ok) {
              const error = new Error(`DataRegistry ${key}: HTTP ${response.status}`);
              error.status = response.status;
              throw error;
            }
            payload = await response.json();
          }
          const projected = (options.project || schema.project)(payload);
          entry.value = projected;
          entry.status = 'ready';
          entry.stale = false;
          entry.error = null;
          entry.observedAt = Number(options.observedAt || projected?.observed_at || payload?.meta?.generated_at || this.now());
          entry.updatedAt = this.now();
          entry.revision += 1;
          return this.notify(entry);
        } catch (error) {
          if (controller.signal.aborted || error?.name === 'AbortError') {
            entry.status = entry.value === undefined ? 'empty' : 'stale';
            entry.stale = entry.value !== undefined;
            entry.error = null;
            return this.notify(entry);
          }
          entry.error = error;
          entry.status = entry.value === undefined ? (error?.status === 403 ? 'forbidden' : 'error') : 'stale';
          entry.stale = entry.value !== undefined;
          return this.notify(entry);
        } finally {
          unlink();
          if (entry.controller === controller) entry.controller = null;
          entry.promise = null;
        }
      })();
      return entry.promise;
    }

    patch(key, patch, options = {}) {
      const entry = this.entry(this.entryKey(key, options));
      entry.schemaKey = key;
      entry.cacheKey = String(options.cacheKey || '');
      const previous = entry.value;
      entry.value = typeof patch === 'function'
        ? patch(previous)
        : previous && typeof previous === 'object' && patch && typeof patch === 'object' && !Array.isArray(previous)
          ? { ...previous, ...patch }
          : patch;
      entry.status = 'ready';
      entry.stale = false;
      entry.error = null;
      entry.observedAt = Number(options.observedAt || patch?.observed_at || this.now());
      entry.updatedAt = this.now();
      entry.revision += 1;
      return this.notify(entry);
    }

    invalidate(key, options = {}) {
      const cacheKey = String(options.cacheKey || '').trim();
      if (cacheKey) {
        const entry = this.entry(this.entryKey(key, options));
        entry.updatedAt = 0;
        entry.stale = entry.value !== undefined;
        if (options.abort !== false) entry.controller?.abort(abortError());
        return this.snapshot(key, options);
      }
      const matches = Array.from(this.entries.values()).filter((entry) => entry.key === key || entry.schemaKey === key);
      if (!matches.length) matches.push(this.entry(key));
      matches.forEach((entry) => {
        entry.updatedAt = 0;
        entry.stale = entry.value !== undefined;
        if (options.abort !== false) entry.controller?.abort(abortError());
      });
      return this.snapshot(key);
    }

    clear(key) {
      if (key) {
        Array.from(this.entries.entries()).forEach(([entryKey, entry]) => {
          if (entryKey !== key && entry.schemaKey !== key) return;
          entry.controller?.abort(abortError());
          this.entries.delete(entryKey);
        });
        return;
      }
      this.entries.forEach((entry) => entry.controller?.abort(abortError()));
      this.entries.clear();
    }
  }

  window.DWRTDataRegistry = DataRegistry;
  window.DWRT_DATA_REGISTRY = window.DWRT_DATA_REGISTRY || new DataRegistry();
})();
