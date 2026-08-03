(() => {
  'use strict';

  const SESSION_KEYS = Object.freeze({
    access: 'dreamingwrt.web.accessToken',
    refresh: 'dreamingwrt.web.refreshToken',
    expiresAt: 'dreamingwrt.web.expiresAt',
    username: 'dreamingwrt.web.username',
    role: 'dreamingwrt.web.role'
  });

  class SessionGate {
    constructor(options = {}) {
      this.fetcher = options.fetcher || ((url, request) => fetch(url, request));
      this.storage = options.storage || window.localStorage;
      this.clock = options.clock || (() => Date.now());
      this.refreshUrl = options.refreshUrl || '/api/v1/session/refresh';
      this.location = options.location || window.location;
      this.onRequired = options.onRequired || null;
      this.refreshPromise = null;
      this.required = false;
      this.requiredReason = '';
    }

    tokens() {
      try {
        return {
          access: this.storage.getItem(SESSION_KEYS.access) || '',
          refresh: this.storage.getItem(SESSION_KEYS.refresh) || '',
          expiresAt: Number(this.storage.getItem(SESSION_KEYS.expiresAt) || 0),
          username: this.storage.getItem(SESSION_KEYS.username) || '',
          role: this.storage.getItem(SESSION_KEYS.role) || ''
        };
      } catch (_) {
        return { access: '', refresh: '', expiresAt: 0, username: '', role: '' };
      }
    }

    save(data) {
      if (!data || !data.access_token) return false;
      try {
        this.storage.setItem(SESSION_KEYS.access, data.access_token);
        if (data.refresh_token) this.storage.setItem(SESSION_KEYS.refresh, data.refresh_token);
        if (data.expires_in) this.storage.setItem(SESSION_KEYS.expiresAt, String(this.clock() + Number(data.expires_in) * 1000));
        if (data.username) this.storage.setItem(SESSION_KEYS.username, data.username);
        if (data.role) this.storage.setItem(SESSION_KEYS.role, data.role);
      } catch (_) {}
      this.required = false;
      this.requiredReason = '';
      this.dispatch('dwrt-session-restored', {});
      return true;
    }

    clear() {
      try { Object.values(SESSION_KEYS).forEach((key) => this.storage.removeItem(key)); } catch (_) {}
    }

    returnPath() {
      const location = this.location || {};
      return `${location.pathname || '/app/'}${location.search || ''}${location.hash || ''}`;
    }

    loginUrl() {
      return `/login/?next=${encodeURIComponent(this.returnPath())}`;
    }

    dispatch(name, detail) {
      if (typeof window.dispatchEvent !== 'function' || typeof CustomEvent !== 'function') return;
      window.dispatchEvent(new CustomEvent(name, { detail }));
    }

    requireLogin(reason = 'session-expired') {
      if (this.required) return false;
      this.required = true;
      this.requiredReason = reason;
      const detail = { reason, next: this.returnPath(), loginUrl: this.loginUrl() };
      if (typeof this.onRequired === 'function') this.onRequired(detail);
      this.dispatch('dwrt-session-required', detail);
      return false;
    }

    redirectToLogin() {
      this.clear();
      if (this.location && !String(this.location.pathname || '').startsWith('/login')) this.location.href = this.loginUrl();
    }

    authHeaders(extra = {}) {
      const headers = { ...extra };
      const { access } = this.tokens();
      if (access) headers.Authorization = `Bearer ${access}`;
      return headers;
    }

    isFresh(skewMs = 15000) {
      const { access, expiresAt } = this.tokens();
      return Boolean(access && (!expiresAt || expiresAt > this.clock() + Math.max(0, Number(skewMs) || 0)));
    }

    async refresh(options = {}) {
      if (this.refreshPromise) return this.refreshPromise;
      if (this.required && options.retryRequired !== true) return false;
      if (!options.force && this.isFresh(options.skewMs)) return true;
      const { refresh } = this.tokens();
      if (!refresh) return this.requireLogin('missing-refresh-token');

      this.refreshPromise = this.fetcher(this.refreshUrl, {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refresh })
      }).then(async (response) => {
        const text = await response.text();
        let payload = null;
        try { payload = text ? JSON.parse(text) : null; } catch (_) {}
        const data = payload && (payload.data || payload.body);
        if (response.ok && data && data.access_token) return this.save(data);
        return this.requireLogin(response.status === 401 ? 'refresh-rejected' : 'refresh-failed');
      }).catch(() => this.requireLogin('refresh-unreachable')).finally(() => {
        this.refreshPromise = null;
      });
      return this.refreshPromise;
    }

    async ensureFresh(options = {}) {
      if (this.required) return false;
      if (this.isFresh(options.skewMs)) return true;
      return this.refresh({ force: true, skewMs: options.skewMs });
    }

    async fetch(url, options = {}, retry = true) {
      const request = { ...options };
      const skipSession = request.dwrtSkipSession === true;
      delete request.dwrtSkipSession;
      if (!skipSession && !await this.ensureFresh()) {
        return new Response('', { status: 401, statusText: 'Authentication required' });
      }
      const response = await this.fetcher(url, {
        ...request,
        headers: skipSession ? request.headers : this.authHeaders(request.headers)
      });
      if (!skipSession && response.status === 401 && retry && await this.refresh({ force: true, retryRequired: true })) {
        return this.fetch(url, request, false);
      }
      if (!skipSession && response.status === 401) this.requireLogin('access-rejected');
      return response;
    }
  }

  window.DWRTSessionGate = SessionGate;
  window.DWRT_SESSION = window.DWRT_SESSION || new SessionGate();

  /*
   * 页面插件的共享 JSON 请求入口。
   *
   * 此前 30 个插件各自写了一份私有 requestJson：裸 fetch + 直接从 localStorage 取
   * access token，完全绕过会话闸门。后果是 token 过期时它们既不刷新也不重试，并发请求
   * 会集体拿 401 —— 通知推送页六个并发请求就显示成「unauthorized · unauthorized · ...」
   * 六连，切走再切回来（其他页面走闸门刷新了 token）又恢复正常。
   *
   * 这里统一走 DWRT_SESSION.fetch()，它内部已经处理 ensureFresh -> 401 -> refresh ->
   * 单次重试，并且 refreshPromise 是单例，并发刷新会自动合并成一次。
   */
  async function sessionRequestJson(url, options = {}) {
    const { version, errorMessages, ...request } = options || {};
    const requestUrl = version
      ? `${url}${url.includes('?') ? '&' : '?'}v=${encodeURIComponent(version)}`
      : url;
    const messages = errorMessages || {};
    const headers = {
      Accept: 'application/json',
      ...(request.body ? { 'Content-Type': 'application/json' } : {}),
      ...(request.headers || {})
    };
    const gate = window.DWRT_SESSION;
    const init = { credentials: 'same-origin', cache: 'no-store', ...request, headers };
    const response = gate ? await gate.fetch(requestUrl, init) : await fetch(requestUrl, init);
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error(messages.invalidJson || 'invalid json'); }
    }
    if (!response.ok || json?.ok === false) {
      const detail = json?.error?.message || json?.error?.code || json?.error || json?.message || json?.code;
      const error = new Error(String(detail || response.status));
      error.status = response.status;
      error.payload = json;
      throw error;
    }
    return json;
  }

  /*
   * 纯传输层入口：签名与原生 fetch 完全一致，返回同一个 Response。
   *
   * 各页面插件对响应的解包、业务码判定与报错文案差异很大（有的看 json.code、有的看
   * payload.ok、有的自带中文兜底），这些逻辑不应被共享层接管。所以插件只把那一次
   * fetch 换成这里，其余代码原样保留：改动面最小，同时补上 token 刷新与 401 重试。
   *
   * 闸门会自行注入 Authorization，所以调用方传入的 headers 不需要再带 token。
   */
  function sessionFetch(url, init = {}) {
    const gate = window.DWRT_SESSION;
    return gate ? gate.fetch(url, init) : fetch(url, init);
  }

  window.DWRT_REQUEST = window.DWRT_REQUEST || { json: sessionRequestJson, fetch: sessionFetch };
})();
