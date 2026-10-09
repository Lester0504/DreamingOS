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
          capabilities: null,
          permissions: null,
          entitlement: null,
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
        capabilities: entry.capabilities,
        permissions: entry.permissions,
        entitlement: entry.entitlement,
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
        capabilities: entry.capabilities,
        permissions: entry.permissions,
        entitlement: entry.entitlement,
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

    projectAccess(entry, payload) {
      // Envelope fields belong to this resource; never turn entitlement into a global gate.
      const source = payload?.contract === 'product-plane.v1' ? payload : unwrap(payload);
      entry.capabilities = source?.capabilities ?? null;
      entry.permissions = source?.permissions ?? null;
      entry.entitlement = source?.entitlement ?? null;
    }

    hasCapability(key, capability, options = {}) {
      const caps = this.snapshot(key, options).capabilities;
      if (caps == null) return true; // Legacy resource, keep its existing page gates.
      const value = caps[capability];
      if (typeof value === 'boolean') return value;
      if (!value || typeof value !== 'object') return false;
      return value.supported !== false && value.readable !== false && value.writable !== false;
    }

    hasPermission(key, permission, options = {}) {
      const permissions = this.snapshot(key, options).permissions;
      if (permissions == null) return true;
      const action = String(permission).split(':').pop();
      const value = permissions[permission] ?? permissions[action];
      return value === true || value?.allowed === true;
    }

    access(key, requirements = {}, options = {}) {
      const snap = this.snapshot(key, options);
      const { capability, permission } = requirements;
      if (permission && !this.hasPermission(key, permission, options)) {
        return { allowed: false, state: 'forbidden', reason: snap.permissions?.reason || `缺少权限 ${permission}` };
      }
      if (capability && !this.hasCapability(key, capability, options)) {
        return { allowed: false, state: 'unavailable', reason: snap.capabilities?.[capability]?.reason || snap.capabilities?.reasons?.[capability] || `当前设备不支持 ${capability}` };
      }
      const entitlement = snap.entitlement;
      if (entitlement?.required === true && entitlement.valid !== true) {
        return { allowed: false, state: 'license_required', reason: entitlement.reason || '此功能需要有效授权' };
      }
      return { allowed: true, state: 'ready', reason: '' };
    }

    bindControl(key, control, requirements = {}, options = {}) {
      return this.subscribe(key, () => {
        const access = this.access(key, requirements, options);
        control.disabled = !access.allowed;
        control.setAttribute('aria-disabled', String(!access.allowed));
        control.setAttribute('data-dwrt-tooltip', access.reason);
        control.title = access.reason;
      }, options);
    }

    accept(key, payload, options = {}) {
      const entry = this.entry(this.entryKey(key, options));
      entry.schemaKey = key;
      entry.cacheKey = String(options.cacheKey || '');
      this.projectAccess(entry, payload);
      const schema = this.schemas.get(key);
      entry.value = (options.project || schema?.project || unwrap)(payload);
      entry.stale = payload?.meta?.stale === true;
      entry.status = entry.stale ? 'stale' : 'ready';
      entry.error = null;
      entry.observedAt = Number(options.observedAt || payload?.meta?.observed_at || entry.value?.observed_at || payload?.meta?.generated_at || this.now());
      entry.updatedAt = this.now();
      entry.revision += 1;
      return this.notify(entry);
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
          if (payload?.ok === false) {
            const error = new Error(payload.error?.message || payload.error?.code || '读取资源失败');
            error.code = payload.error?.code;
            throw error;
          }
          return this.accept(key, payload, { ...options, project: options.project || schema.project });
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
