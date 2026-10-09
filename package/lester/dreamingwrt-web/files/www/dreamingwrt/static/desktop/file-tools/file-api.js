(() => {
  'use strict';
  const base = '/api/v1/storage/files';
  const path = (value) => String(value || '/').replace(/\/+/g, '/').replace(/\/$/, '') || '/';
  const url = (suffix = '', values = {}) => `${base}${suffix}?${new URLSearchParams(values)}`;
  async function request(suffix = '', values = {}, init = {}) {
    const response = await window.DWRT_REQUEST.fetch(url(suffix, values), { credentials: 'same-origin', cache: 'no-store', ...init });
    if (response.status === 401 || response.status === 403) throw Object.assign(new Error(response.status === 401 ? '会话已过期，请重新登录。' : '当前账号没有此操作权限。'), { status: response.status });
    let payload;
    try { payload = await response.json(); } catch (_) { throw new Error(`响应无效（HTTP ${response.status}）`); }
    const data = payload?.data ?? payload?.body ?? payload;
    if (!response.ok || payload?.ok === false || data?.ok === false || data?.error || (typeof payload?.code === 'number' && payload.code >= 4000)) {
      throw Object.assign(new Error(data?.message || payload?.message || `HTTP ${response.status}`), {
        status: response.status, code: data?.error?.code || data?.error || payload?.error?.code, data
      });
    }
    return data;
  }
  const post = (suffix, body) => request(suffix, {}, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const can = (entry, action) => ['owner', 'admin'].includes(window.DWRT_SESSION?.tokens().role) && entry?.capabilities?.[action] === true;
  async function stream(file, { disposition = 'inline', signal } = {}) {
    const target = url('/raw', { root_id: file.root_id, path: path(file.path), disposition });
    if (!await window.DWRT_SESSION.ensureFresh()) throw Object.assign(new Error('会话已过期，请重新登录。'), { status: 401 });
    // A native media element cannot set Authorization. Verify the existing
    // HttpOnly cookie directly, refreshing once if it has not yet been set.
    let response = await fetch(target, { method: 'HEAD', credentials: 'same-origin', cache: 'no-store', signal });
    if (response.status === 401 && await window.DWRT_SESSION.refresh({ force: true })) {
      response = await fetch(target, { method: 'HEAD', credentials: 'same-origin', cache: 'no-store', signal });
    }
    if (!response.ok) throw Object.assign(new Error(response.status === 401 ? '会话已过期，请重新登录。' : response.status === 403 ? '当前账号没有文件读取权限。' : `文件无法读取（HTTP ${response.status}）`), { status: response.status });
    return target;
  }
  function open(appId, file) {
    const context = { root_id: file.root_id, path: path(file.path), name: file.name, mime: file.mime || '' };
    if (parent !== window && document.documentElement.dataset.desktopApp === 'true') {
      parent.postMessage({ type: 'dwrt-files:open', appId, context }, location.origin);
    } else {
      window.open(`/app/${appId}.html?${new URLSearchParams(context)}`, '_blank', 'noopener');
    }
  }
  window.DWRT_FILES = Object.freeze({ path, url, request, post, can, stream, open });
})();
