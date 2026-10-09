/*
 * 根路径入口门禁。
 *
 * 原行为：`/` 无条件渲染初始化向导，已建过账号的设备访问根地址也会被向导挡住，
 * 观感是「设备没配过」。此前判据取 `setup/status.initialized`，而该字段表示的是
 * **向导流程是否走完**，不是设备是否可用；30.1 这类跳过向导直接建用户的设备，
 * 向导完成标记从未写入，于是永远被判为「未初始化」。
 *
 * 现行判据是后端给出的 `setup_gate_required`（双方一致的门禁结论，取登录能力而非
 * 向导完成度）：
 *   false -> 设备已可用，重定向到 /app/ 或登录页，不展示向导
 *   true  -> 真的没有账号，展示向导
 * 字段缺失（旧固件）时退回旧行为 `!initialized`，不把 undefined 当 false。
 *
 * 读接口用未认证可访问的 `/api/setup/status`；`/api/v1/setup/status` 需要 Bearer
 * token，未登录访问根路径时只会拿到 401。
 *
 * 本文件在 <head> 中同步加载，仅注册一个 Promise，不阻塞解析；向导脚本
 * (setup-welcome.js) 会 await 它的结论后再决定是否启动向导流程。
 *
 * 另两件事，都是「后端说不该拦、用户仍被向导顶掉」的直接来源：
 *   1. 向导 DOM 在 setup-welcome.js 模块顶层就挂好了，比门禁结论早一个网络往返，
 *      所以放行前必须遮住页面（dwrt-setup-gate-pending），否则先闪一屏向导。
 *   2. 控制台是 hash 路由。放行时要把 `#/...` 原样带到 /app/，否则用户的目标
 *      路由在重定向里丢掉，落到默认仪表盘，观感同样是「进不去我要去的页面」。
 */
(() => {
  'use strict';

  const STATUS_URL = '/api/setup/status';
  const CONTROL_URL = '/app/';
  const LOGIN_URL = '/login/';
  const ACCESS_TOKEN_KEY = 'dreamingwrt.web.accessToken';
  const PENDING_CLASS = 'dwrt-setup-gate-pending';
  /* 结论最多遮这么久。后端不响应时宁可露出向导，也不要把页面永久留白。 */
  const PENDING_TIMEOUT_MS = 2500;

  /* 向导 DOM 由 setup-welcome.js 在模块顶层挂载，早于门禁结论；不遮住的话
   * 已配置设备会先闪一屏向导再被重定向走，看起来就是控制台被向导接管。
   * 本文件在 <head> 同步执行，所以这个类能在首次绘制前生效。 */
  function markPending() {
    try {
      document.documentElement.classList.add(PENDING_CLASS);
    } catch (_) {}
  }

  function clearPending() {
    try {
      document.documentElement.classList.remove(PENDING_CLASS);
    } catch (_) {}
  }

  /* ?wizard=1 是「重新运行向导」入口用的显式旁路：用户主动要求走向导时不再重定向。
   * 它只跳过重定向，不改变后端任何状态。 */
  function wizardForced() {
    try {
      const value = new URLSearchParams(window.location.search).get('wizard');
      return value === '1' || value === 'true';
    } catch (_) {
      return false;
    }
  }

  function hasLocalSession() {
    try {
      return !!window.localStorage.getItem(ACCESS_TOKEN_KEY);
    } catch (_) {
      return false;
    }
  }

  /* 控制台是 hash 路由，而向导住在根路径。访问 `/#/policy-engine/table` 时
   * 放行如果只跳 `/app/`，用户的目标路由就在重定向里丢了，落到默认仪表盘——
   * 观感和「被向导接管」一样是「进不去我要去的页面」。所以把 hash 原样带走。
   * 只接受 `#/` 开头的应用内路由，避免把任意片段拼进跳转目标。 */
  function routeHash() {
    try {
      const hash = String(window.location.hash || '');
      return hash.startsWith('#/') ? hash : '';
    } catch (_) {
      return '';
    }
  }

  function unwrap(body) {
    if (!body) return null;
    if (body.data !== undefined) return body.data;
    return body;
  }

  async function readStatus() {
    const res = await fetch(STATUS_URL, { credentials: 'same-origin', cache: 'no-store' });
    /* 401/403 说明这台设备已经在要求认证，不可能处于「无账号首次开机」状态；
     * 空 body 当成读取失败，交由调用方按 unknown 处理。 */
    if (res.status === 401 || res.status === 403) return { authRequired: true, data: null };
    if (!res.ok) return { authRequired: false, data: null };
    const text = await res.text();
    let body = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch (_) {
      body = null;
    }
    return { authRequired: false, data: unwrap(body) };
  }

  function decide(status) {
    if (status.authRequired) {
      return { needsWizard: false, reason: 'status_requires_auth_device_is_provisioned', data: null };
    }
    const data = status.data;
    if (!data || typeof data !== 'object') {
      /* 读不到状态时不重定向：宁可多展示一次向导，也不要把人挡在控制台之外。 */
      return { needsWizard: true, reason: 'status_unreadable_keep_wizard', data: null };
    }
    const gate = data.setup_gate_required;
    if (typeof gate === 'boolean') {
      return {
        needsWizard: gate,
        reason: data.setup_gate_reason || (gate ? 'setup_gate_required_true' : 'setup_gate_required_false'),
        data
      };
    }
    /* 旧固件没有 setup_gate_required，退回旧判据。 */
    return {
      needsWizard: !data.initialized,
      reason: 'legacy_initialized_fallback',
      data
    };
  }

  function targetUrl() {
    /* 有本地会话就直接进控制台，否则先去登录页并带上返回地址，
     * 避免未登录用户落到 /app/ 后再被会话闸门弹一次。 */
    const target = CONTROL_URL + routeHash();
    if (hasLocalSession()) return target;
    return `${LOGIN_URL}?next=${encodeURIComponent(target)}`;
  }

  const gate = (async () => {
    const forced = wizardForced();
    /* 强制走向导时没有遮挡的必要：结论必然是「展示向导」。 */
    if (!forced) {
      markPending();
      try {
        window.setTimeout(clearPending, PENDING_TIMEOUT_MS);
      } catch (_) {}
    }
    let decision;
    try {
      decision = decide(await readStatus());
    } catch (_) {
      decision = { needsWizard: true, reason: 'status_request_failed_keep_wizard', data: null };
    }
    decision.forced = forced;
    if (!decision.needsWizard && !forced) {
      decision.redirected = true;
      /* replace 而不是 href：不要在历史里留下一个会再次触发重定向的根路径条目。 */
      window.location.replace(targetUrl());
      /* 重定向在途时保持遮挡，避免在新页面接手前又闪一屏向导。 */
    } else {
      clearPending();
    }
    return decision;
  })();

  window.DWRT_SETUP_GATE = {
    ready: gate,
    /* 向导脚本用它决定是否启动向导流程；重定向在途时不应再发 setup 写接口。 */
    async shouldRunWizard() {
      const decision = await gate;
      return !!(decision.needsWizard || decision.forced);
    }
  };
})();
