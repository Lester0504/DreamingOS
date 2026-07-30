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
    wantedTopics: new Set(),
    lastByTopic: new Map(),
    pendingByTopic: new Map(),
    flushTimer: 0,
    visibleAgainAt: 0,
    authRefresh: null,
    capabilityKnown: false,
    capabilityProbe: null,
    available: false,
    disabledUntil: 0,
    unavailableReason: ''
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

  function configure(input = {}) {
    const explicit = realtimeCapabilityFrom(input);
    if (typeof explicit !== 'boolean') {
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
    // menu-shell 提供共享的 bootstrap 拉取(启动时三方去重);不可用时退回独立请求。
    const sharedFetch = typeof window.DWRT_BOOTSTRAP_FETCH === 'function'
      ? window.DWRT_BOOTSTRAP_FETCH().then((json) => configure(json || {}))
      : (window.DWRT_SESSION
        ? window.DWRT_SESSION.fetch('/api/v1/bootstrap?realtime=1', request)
        : fetch('/api/v1/bootstrap?realtime=1', request)).then(async (response) => {
        if (!response.ok) return configure({});
        let json = null;
        try { json = await response.json(); } catch (_) {}
        return configure(json || {});
      });
    state.capabilityProbe = sharedFetch.catch(() => configure({})).finally(() => {
      state.capabilityProbe = null;
    });
    return state.capabilityProbe;
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

  function sendSubscribeAll() {
    send('subscribe', state.wantedTopics);
  }

  function scheduleReconnect() {
    if (!state.wantedTopics.size || state.reconnectTimer) return;
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
    if (!state.wantedTopics.size) return null;
    if (!state.capabilityKnown) {
      probeCapability().then((available) => {
        if (available && state.wantedTopics.size) connect();
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
      const topic = message.topic || '';
      if (!topic) return;
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
      if (state.wantedTopics.size) scheduleReconnect();
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
      if (!state.wantedTopics.size) {
        if (state.reconnectTimer) {
          window.clearTimeout(state.reconnectTimer);
          state.reconnectTimer = 0;
        }
        closeSocket();
        setStatus('idle');
      }
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

  window.DWRTRealtime = {
    subscribe,
    connect,
    configure,
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
