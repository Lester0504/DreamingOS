(() => {
  'use strict';

  const WS_PATH = '/api/v1/realtime/ws';
  const DEFAULT_BACKOFF_MS = 800;
  const MAX_BACKOFF_MS = 12000;
  const CAPABILITY_KEYS = [
    'realtime_ws',
    'realtime_websocket',
    'websocket_realtime',
    'ws_realtime'
  ];
  const SESSION_KEYS = {
    access: 'dreamingwrt.web.accessToken',
    refresh: 'dreamingwrt.web.refreshToken',
    expiresAt: 'dreamingwrt.web.expiresAt',
    username: 'dreamingwrt.web.username',
    role: 'dreamingwrt.web.role'
  };

  const state = {
    socket: null,
    status: 'idle',
    reconnectTimer: 0,
    reconnectAttempt: 0,
    subscriptions: new Map(),
    parameterizedSubscriptions: new Map(),
    wantedTopics: new Set(),
    lastByTopic: new Map(),
    pendingByTopic: new Map(),
    flushTimer: 0,
    visibleAgainAt: 0,
    authRefresh: null,
    capabilityKnown: false,
    capabilityProbe: null,
    /*
     * Retry bookkeeping for a failed capability source (not for a denial).
     * A non-zero count also forces the probe off the shared 10s-cached bootstrap
     * promise, so a retry actually re-asks the server.
     */
    capabilityRetries: 0,
    capabilityRetryTimer: 0,
    available: false,
    disabledUntil: 0,
    unavailableReason: '',
    /*
     * Server-declared session parameters, from the frame webd sends immediately
     * after the handshake (`type: "session"`, no `topic`). Until this landed the
     * frame was dropped by the topic guard below, so pages hardcoded their own
     * copy of the server's cadence — dashboard.js had THROUGHPUT_PATCH_MS = 250
     * next to the server's WEBD_WS_THROUGHPUT_INTERVAL_MS = 250, two independent
     * constants that agreed only by coincidence and would silently diverge the
     * moment the server changed. Pages should read cadence() instead.
     */
    session: null
  };

  function authTokens() {
    try {
      return {
        access: localStorage.getItem(SESSION_KEYS.access) || '',
        refresh: localStorage.getItem(SESSION_KEYS.refresh) || '',
        expiresAt: Number(localStorage.getItem(SESSION_KEYS.expiresAt) || 0)
      };
    } catch (_) {
      return { access: '', refresh: '', expiresAt: 0 };
    }
  }

  function saveAuthTokens(data) {
    if (!data || !data.access_token) return;
    try {
      localStorage.setItem(SESSION_KEYS.access, data.access_token);
      if (data.refresh_token) localStorage.setItem(SESSION_KEYS.refresh, data.refresh_token);
      if (data.expires_in) localStorage.setItem(SESSION_KEYS.expiresAt, String(Date.now() + Number(data.expires_in) * 1000));
      if (data.username) localStorage.setItem(SESSION_KEYS.username, data.username);
      if (data.role) localStorage.setItem(SESSION_KEYS.role, data.role);
    } catch (_) {}
  }

  function clearAuthTokens() {
    try {
      Object.values(SESSION_KEYS).forEach((key) => localStorage.removeItem(key));
    } catch (_) {}
  }

  function redirectToLogin() {
    clearAuthTokens();
    if (location.pathname.startsWith('/login')) return;
    const next = `${location.pathname}${location.search}${location.hash}`;
    location.href = `/login/?next=${encodeURIComponent(next)}`;
  }

  async function refreshAuthToken() {
    if (window.DWRT_SESSION) return window.DWRT_SESSION.refresh({ force: true, retryRequired: true });
    if (state.authRefresh) return state.authRefresh;
    const { refresh } = authTokens();
    if (!refresh) return false;
    state.authRefresh = fetch('/api/v1/session/refresh', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refresh })
    }).then(async (response) => {
      const text = await response.text();
      let json = null;
      try { json = text ? JSON.parse(text) : null; } catch (_) {}
      const data = json && (json.data || json.body);
      if (response.ok && data && data.access_token) {
        saveAuthTokens(data);
        return true;
      }
      return false;
    }).catch(() => false).finally(() => {
      state.authRefresh = null;
    });
    return state.authRefresh;
  }

  function wsUrl() {
    const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${scheme}//${location.host}${WS_PATH}`;
  }

  function nestedCapability(value) {
    if (!value || typeof value !== 'object') return null;
    for (const key of ['ws', 'websocket', 'enabled', 'available']) {
      if (typeof value[key] === 'boolean') return value[key];
    }
    return null;
  }

  function realtimeCapabilityFrom(input) {
    const data = input && input.data && typeof input.data === 'object' ? input.data : input || {};
    const caps = data.capabilities && typeof data.capabilities === 'object' ? data.capabilities : data;
    for (const key of CAPABILITY_KEYS) {
      if (typeof caps[key] === 'boolean') return caps[key];
      if (caps[key] === 1 || caps[key] === 'true') return true;
      if (caps[key] === 0 || caps[key] === 'false') return false;
    }
    const realtime = nestedCapability(caps.realtime);
    if (typeof realtime === 'boolean') return realtime;
    return null;
  }

  /*
   * Did the capability source itself fail, rather than answer "no"?
   *
   * webd answers `ok: true` with a *reduced* payload when it cannot reach jmxd:
   * `backend.jmxd_online === false` plus `capabilities_error: "source_unavailable"`,
   * and the capabilities object drops from ~192 keys to ~13 — realtime_ws simply
   * is not in it. Captured on 30.1 while chasing an intermittent dead socket.
   *
   * That is an unknown, not a denial, and the difference matters: a denial is
   * final, an unknown must be retried. design.md requires the two to stay
   * distinguishable ("能力未知（其来源请求失败）" is an independent third state).
   */
  function capabilitySourceFailed(input) {
    const data = input && input.data && typeof input.data === 'object' ? input.data : input || {};
    if (!data || typeof data !== 'object') return true;
    const backend = data.backend && typeof data.backend === 'object' ? data.backend : null;
    if (backend) {
      if (backend.jmxd_online === false) return true;
      if (backend.capabilities_error) return true;
    }
    /* An empty object carries no evidence either way; treat it as unknown. */
    const caps = data.capabilities && typeof data.capabilities === 'object' ? data.capabilities : null;
    if (!caps) return Object.keys(data).length === 0;
    return false;
  }

  function configure(input = {}) {
    const explicit = realtimeCapabilityFrom(input);
    if (typeof explicit !== 'boolean') {
      /*
       * Unknown stays unknown and stays retryable: leaving capabilityKnown false
       * lets the next probe ask again. Latching it here is what turned one
       * degraded bootstrap into a whole session with no realtime push.
       */
      if (capabilitySourceFailed(input)) {
        state.capabilityKnown = false;
        state.available = false;
        state.unavailableReason = 'capability_source_unavailable';
        setStatus('unavailable');
        return false;
      }
      if (!state.capabilityKnown) {
        state.capabilityKnown = true;
        state.available = false;
        state.unavailableReason = 'capability_not_advertised';
        setStatus('unavailable');
      }
      return state.available;
    }
    state.capabilityKnown = true;
    state.available = explicit;
    state.unavailableReason = explicit ? '' : 'capability_disabled';
    if (!explicit) {
      closeSocket();
      setStatus('unavailable');
      return false;
    }
    if (state.wantedTopics.size) connect();
    else setStatus('idle');
    return true;
  }

  async function probeCapability() {
    if (state.capabilityKnown) return state.available;
    if (state.capabilityProbe) return state.capabilityProbe;
    const request = {
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { Accept: 'application/json' }
    };
    /*
     * menu-shell 提供共享的 bootstrap 拉取(启动时三方去重);不可用时退回独立请求。
     * `direct` skips that shared promise: it caches for 10s, so a retry after a
     * degraded payload would otherwise re-read the very same bad object and the
     * retry would be pointless.
     */
    const ownFetch = () => (window.DWRT_SESSION
      ? window.DWRT_SESSION.fetch('/api/v1/bootstrap?realtime=1', request)
      : fetch('/api/v1/bootstrap?realtime=1', request)).then(async (response) => {
      if (!response.ok) return configure({});
      let json = null;
      try { json = await response.json(); } catch (_) {}
      return configure(json || {});
    });
    const sharedFetch = !state.capabilityRetries && typeof window.DWRT_BOOTSTRAP_FETCH === 'function'
      ? window.DWRT_BOOTSTRAP_FETCH().then((json) => configure(json || {}))
      : ownFetch();
    state.capabilityProbe = sharedFetch.catch(() => configure({})).finally(() => {
      state.capabilityProbe = null;
    });
    state.capabilityProbe.then(() => scheduleCapabilityRetry());
    return state.capabilityProbe;
  }

  /*
   * Re-probe after the capability source failed. webd serves a reduced bootstrap
   * while jmxd is still coming up, which is transient by nature, so the only
   * thing needed is to ask again a moment later. Bounded and backing off, because
   * a genuinely absent jmxd must not turn into an endless request loop.
   */
  /*
   * Measured on 30.1 rather than guessed: polling bootstrap every 400ms for 30s
   * returned 62 samples with exactly 1 degraded, and it was an isolated hit, not a
   * sustained outage window. So the failure mode is "landed on an unlucky sample",
   * which wants more attempts rather than longer waits — a 3-step schedule was
   * observed giving up on a run that a 4th attempt would have recovered.
   *
   * Front-loaded because the common case clears almost immediately; the tail still
   * backs off so a genuinely absent jmxd is not hammered. Worst case ~13s spread
   * over 5 attempts.
   */
  const CAPABILITY_RETRY_MS = [500, 1200, 2500, 4000, 5000];
  function scheduleCapabilityRetry() {
    if (state.capabilityKnown) return;
    if (state.unavailableReason !== 'capability_source_unavailable') return;
    if (!state.wantedTopics.size) return;
    if (state.capabilityRetryTimer) return;
    const delay = CAPABILITY_RETRY_MS[Math.min(state.capabilityRetries, CAPABILITY_RETRY_MS.length - 1)];
    if (state.capabilityRetries >= CAPABILITY_RETRY_MS.length) {
      /*
       * Out of retries. Settle on the honest reason rather than pretending the
       * server denied the capability, and stop asking.
       */
      state.capabilityKnown = true;
      state.unavailableReason = 'capability_source_unavailable';
      setStatus('unavailable');
      return;
    }
    state.capabilityRetries += 1;
    state.capabilityRetryTimer = window.setTimeout(() => {
      state.capabilityRetryTimer = 0;
      if (state.capabilityKnown || !state.wantedTopics.size) return;
      probeCapability().then((available) => {
        if (available && state.wantedTopics.size) connect();
      });
    }, delay);
  }

  function canConnect() {
    if (!state.available || Date.now() < state.disabledUntil) {
      if (state.wantedTopics.size) setStatus('unavailable');
      return false;
    }
    return true;
  }

  function notify(topic, message) {
    const handlers = state.subscriptions.get(topic);
    if (!handlers) return;
    handlers.forEach((handler) => {
      try { handler(message.data, message); } catch (error) {
        console.warn('[dwrt-realtime] subscriber failed', topic, error);
      }
    });
  }

  function flushPending() {
    if (document.hidden) return;
    if (state.flushTimer) {
      window.clearTimeout(state.flushTimer);
      state.flushTimer = 0;
    }
    const pending = Array.from(state.pendingByTopic.entries());
    state.pendingByTopic.clear();
    pending.forEach(([topic, message]) => notify(topic, message));
  }

  function scheduleFlush() {
    if (document.hidden) return;
    const delay = Date.now() - state.visibleAgainAt < 1500 ? 220 : 120;
    if (state.flushTimer) return;
    state.flushTimer = window.setTimeout(() => {
      state.flushTimer = 0;
      flushPending();
    }, delay);
  }

  function enqueueNotify(topic, message) {
    state.pendingByTopic.set(topic, message);
    scheduleFlush();
  }

  function setStatus(status) {
    state.status = status;
    window.dispatchEvent(new CustomEvent('dwrt-realtime-status', {
      detail: { status, topics: Array.from(state.wantedTopics) }
    }));
  }

  function send(type, topics) {
    const socket = state.socket;
    const list = Array.from(topics || []);
    if (!socket || socket.readyState !== WebSocket.OPEN || !list.length) return;
    socket.send(JSON.stringify({ type, topics: list }));
  }

  function sendParameterizedSubscriptions() {
    const items = Array.from(state.parameterizedSubscriptions.values()).map((entry) => ({
      topic: entry.topic,
      params: { ...entry.params }
    }));
    if (!items.length) return;
    const socket = state.socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) return;
    socket.send(JSON.stringify({
      type: 'subscribe',
      request_id: `req-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      subscriptions: items
    }));
  }

  function sendSubscribeAll() {
    send('subscribe', state.wantedTopics);
  }

  function scheduleReconnect() {
    if ((!state.wantedTopics.size && !state.parameterizedSubscriptions.size) || state.reconnectTimer) return;
    if (!canConnect()) return;
    const delay = Math.min(MAX_BACKOFF_MS, DEFAULT_BACKOFF_MS * Math.pow(1.7, state.reconnectAttempt));
    state.reconnectAttempt += 1;
    setStatus('reconnecting');
    state.reconnectTimer = window.setTimeout(() => {
      state.reconnectTimer = 0;
      connect();
    }, delay);
  }

  async function handleAuthExpired() {
    setStatus('auth-expired');
    if (await refreshAuthToken()) {
      reconnectNow();
      return;
    }
    if (window.DWRT_SESSION) window.DWRT_SESSION.requireLogin('websocket-auth-expired');
    else redirectToLogin();
  }

  function closeSocket() {
    const socket = state.socket;
    state.socket = null;
    if (!socket) return;
    socket.onopen = null;
    socket.onmessage = null;
    socket.onerror = null;
    socket.onclose = null;
    try { socket.close(); } catch (_) {}
  }

  function connect() {
    if (!state.wantedTopics.size && !state.parameterizedSubscriptions.size) return null;
    if (!state.capabilityKnown) {
      probeCapability().then((available) => {
        if (available && (state.wantedTopics.size || state.parameterizedSubscriptions.size)) connect();
      });
      setStatus('checking');
      return null;
    }
    if (!canConnect()) return null;
    if (state.socket && [WebSocket.CONNECTING, WebSocket.OPEN].includes(state.socket.readyState)) return state.socket;
    closeSocket();
    setStatus('connecting');
    const socket = new WebSocket(wsUrl());
    let opened = false;
    state.socket = socket;
    socket.onopen = () => {
      opened = true;
      state.reconnectAttempt = 0;
      setStatus('open');
      sendSubscribeAll();
      sendParameterizedSubscriptions();
    };
    socket.onmessage = (event) => {
      let message = null;
      try { message = JSON.parse(event.data); } catch (_) { return; }
      if (!message || typeof message !== 'object') return;
      if (message.type === 'error') {
        if (message.code === 'auth.expired') handleAuthExpired();
        window.dispatchEvent(new CustomEvent('dwrt-realtime-error', { detail: message }));
        return;
      }
      /*
       * The session frame carries no topic, so it must be handled before the
       * topic guard drops it. It is the server's own statement of its push
       * cadence and session limits; treating it as data lets pages follow the
       * server instead of guessing.
       */
      if (message.type === 'session') {
        state.session = message;
        window.dispatchEvent(new CustomEvent('dwrt-realtime-session', { detail: message }));
        return;
      }
      if (message.type === 'subscription_ack' && Array.isArray(message.accepted)) {
        message.accepted.forEach((accepted) => {
          const entityId = String(accepted.entity_id || '').toLowerCase();
          for (const entry of state.parameterizedSubscriptions.values()) {
            if (entry.topic === accepted.topic && String(entry.params.mac || '').toLowerCase() === entityId) {
              entry.subscriptionId = accepted.subscription_id || '';
            }
          }
        });
        return;
      }
      const topic = message.topic || '';
      if (!topic) return;
      if (message.subscription_id) {
        for (const entry of state.parameterizedSubscriptions.values()) {
          if (entry.subscriptionId !== message.subscription_id) continue;
          try { entry.handler(message.data || message, message); } catch (error) {
            console.warn('[dwrt-realtime] parameterized subscriber failed', topic, error);
          }
          return;
        }
      }
      state.lastByTopic.set(topic, message);
      enqueueNotify(topic, message);
    };
    socket.onerror = () => {
      setStatus('error');
    };
    socket.onclose = () => {
      if (state.socket === socket) state.socket = null;
      if (!opened) {
        state.available = false;
        state.disabledUntil = Date.now() + 5 * 60 * 1000;
        state.unavailableReason = 'websocket_handshake_failed';
        setStatus('unavailable');
        return;
      }
      if (state.wantedTopics.size || state.parameterizedSubscriptions.size) scheduleReconnect();
      else setStatus('idle');
    };
    return socket;
  }

  function reconnectNow() {
    if (state.reconnectTimer) {
      window.clearTimeout(state.reconnectTimer);
      state.reconnectTimer = 0;
    }
    closeSocket();
    connect();
  }

  function subscribe(topic, handler) {
    if (!topic || typeof handler !== 'function') return () => {};
    let handlers = state.subscriptions.get(topic);
    if (!handlers) {
      handlers = new Set();
      state.subscriptions.set(topic, handlers);
    }
    handlers.add(handler);
    const wasWanted = state.wantedTopics.has(topic);
    state.wantedTopics.add(topic);
    if (wasWanted) {
      const last = state.lastByTopic.get(topic);
      if (last) {
        try { handler(last.data, last); } catch (_) {}
      }
    } else {
      send('subscribe', [topic]);
    }
    connect();
    return () => {
      const current = state.subscriptions.get(topic);
      if (!current) return;
      current.delete(handler);
      if (current.size) return;
      state.subscriptions.delete(topic);
      state.wantedTopics.delete(topic);
      send('unsubscribe', [topic]);
      if (!state.wantedTopics.size && !state.parameterizedSubscriptions.size) {
        if (state.reconnectTimer) {
          window.clearTimeout(state.reconnectTimer);
          state.reconnectTimer = 0;
        }
        /* Nobody is listening any more, so stop re-probing the capability. */
        if (state.capabilityRetryTimer) {
          window.clearTimeout(state.capabilityRetryTimer);
          state.capabilityRetryTimer = 0;
        }
        closeSocket();
        setStatus('idle');
      }
    };
  }

  function subscribeParameterized(topic, params, handler) {
    if (!topic || !params || typeof params !== 'object' || typeof handler !== 'function') return () => {};
    const key = `${topic}:${String(params.mac || params.entity_id || '')}`.toLowerCase();
    const entry = { topic, params: { ...params }, handler, subscriptionId: '' };
    state.parameterizedSubscriptions.set(key, entry);
    if (state.socket && state.socket.readyState === WebSocket.OPEN) sendParameterizedSubscriptions();
    else connect();
    return () => {
      const current = state.parameterizedSubscriptions.get(key);
      if (!current) return;
      const socket = state.socket;
      if (socket && socket.readyState === WebSocket.OPEN && current.subscriptionId) {
        socket.send(JSON.stringify({
          type: 'unsubscribe',
          request_id: `req-${Date.now()}-${Math.random().toString(16).slice(2)}`,
          subscription_id: current.subscriptionId
        }));
      }
      state.parameterizedSubscriptions.delete(key);
    };
  }

  function status() {
    return {
      status: state.status,
      topics: Array.from(state.wantedTopics),
      connected: Boolean(state.socket && state.socket.readyState === WebSocket.OPEN),
      available: state.available,
      capabilityKnown: state.capabilityKnown,
      unavailableReason: state.unavailableReason
    };
  }

  /* The session frame verbatim, or null before the handshake completes. */
  function session() {
    return state.session;
  }

  /*
   * Server-declared push cadence for a topic, in ms, or `fallback` when the
   * server has not said. Only `dashboard.throughput` is declared today
   * (`throughput_interval_ms`); the rest are read from `topic_intervals_ms` if
   * and when Backend adds it, so a page written against this helper picks up new
   * declarations without another frontend change.
   *
   * A page must still pass a sane fallback: an unconnected socket, an older webd,
   * or a topic the server does not describe all yield null here, and guessing a
   * number on the caller's behalf would recreate the hardcoding this replaces.
   */
  function cadence(topic, fallback = null) {
    const frame = state.session;
    if (!frame || typeof frame !== 'object') return fallback;
    const table = frame.topic_intervals_ms;
    if (table && typeof table === 'object') {
      const declared = Number(table[topic]);
      if (Number.isFinite(declared) && declared > 0) return declared;
    }
    if (topic === 'dashboard.throughput') {
      const throughput = Number(frame.throughput_interval_ms);
      if (Number.isFinite(throughput) && throughput > 0) return throughput;
    }
    return fallback;
  }

  window.DWRTRealtime = {
    subscribe,
    subscribeParameterized,
    connect,
    configure,
    session,
    cadence,
    reconnect: reconnectNow,
    status,
    refreshAuthToken
  };

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) return;
    state.visibleAgainAt = Date.now();
    scheduleFlush();
  });
})();
