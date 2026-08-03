const VERSION = '20260802-ui-batch-01';
const ENDPOINT = '/api/v1/container_service';
const REFRESH_MS = 5000;

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]));
  const stage = root?.closest('.console-stage');
  const mode = /(?:container-lxc|\/container\/lxc)/.test(`${context.item?.id || ''} ${context.path || ''}`) ? 'lxc' : 'docker';

  const state = {
    mounted: true,
    seq: 0,
    loading: true,
    refreshing: false,
    error: '',
    query: '',
    tab: 'overview',
    signature: '',
    timer: 0,
    data: {
      capabilities: {},
      docker: {
        available: false, service: {}, info: {}, config: {}, containers: [], images: [], networks: [], volumes: [],
        diskUsage: {}, counts: { containers: 0, running: 0, images: 0 }, version: '', driver: '', dataRoot: '', capabilities: {}
      },
      lxc: { available: false, service: {}, containers: [], commands: {}, missing: [], config: {}, capabilities: {} }
    }
  };

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (typeof value === 'object' && !Array.isArray(value)) {
        const nested = firstText(value.name, value.label, value.value, value.id, value.message);
        if (nested) return nested;
        continue;
      }
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }

  function bool(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') return !/^(0|false|off|no|disabled|stopped)$/i.test(value);
    return Boolean(value);
  }

  function number(...values) {
    for (const value of values) {
      if (value === undefined || value === null || value === '') continue;
      const parsed = Number(value);
      if (Number.isFinite(parsed)) return parsed;
    }
    return 0;
  }

  function array(value, keys = []) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of [...keys, 'items', 'rows', 'list', 'data']) if (Array.isArray(value[key])) return value[key];
    return [];
  }

  function unwrap(value) {
    let current = value?.data ?? value ?? {};
    for (let index = 0; index < 3; index += 1) {
      if (!current || typeof current !== 'object' || Array.isArray(current) || !current.data || typeof current.data !== 'object') break;
      current = current.data;
    }
    return current || {};
  }

  /*
   * 会话闸门适配器。此前这里是裸 fetch 直接读 localStorage 的 access token，token 过期时
   * 既不刷新也不重试，并发请求会集体拿 401（通知推送页就表现为 unauthorized 六连）。
   * 闸门内部处理 ensureFresh -> 401 -> refresh -> 单次重试，refreshPromise 单例会合并并发刷新。
   */
  function sessionFetch(url, init = {}) {
    return window.DWRT_REQUEST ? window.DWRT_REQUEST.fetch(url, init) : fetch(url, init);
  }

  function authHeaders(extra = {}) {
    let token = '';
    try { token = localStorage.getItem('dreamingwrt.web.accessToken') || ''; } catch (_) {}
    return {
      Accept: 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}),
      ...extra
    };
  }

  async function requestJson() {
    if (typeof api.fetch === 'function') {
      const result = await api.fetch('container-service', ENDPOINT);
      if (!result?.ok) throw result?.error || new Error('容器服务接口不可用');
      return unwrap(result.data ?? result.raw ?? {});
    }
    const response = await sessionFetch(`${ENDPOINT}?v=${VERSION}`, {
      credentials: 'same-origin',
      cache: 'no-store',
      headers: authHeaders()
    });
    const text = await response.text();
    let json = {};
    try { json = text ? JSON.parse(text) : {}; } catch (_) { throw new Error('后端返回了无效 JSON'); }
    if (!response.ok || json?.ok === false) throw new Error(firstText(json?.message, json?.error, `HTTP ${response.status}`));
    return unwrap(json);
  }

  function serviceState(service = {}) {
    if (bool(service.running, false) || /running|active/i.test(firstText(service.status, service.state))) return '运行中';
    if (bool(service.enabled, false)) return '已启用';
    return firstText(service.status, service.state, '未运行');
  }

  function normalize(payload = {}) {
    const docker = payload.docker && typeof payload.docker === 'object' ? payload.docker : {};
    const lxc = payload.lxc && typeof payload.lxc === 'object' ? payload.lxc : {};
    const info = docker.info && typeof docker.info === 'object' ? docker.info : {};
    const config = docker.uci_config || docker.config || {};
    const containers = array(docker.containers);
    const images = array(docker.images);
    const commands = lxc.commands && typeof lxc.commands === 'object' ? lxc.commands : {};
    const missing = array(lxc.missing).length ? array(lxc.missing) : Object.entries(commands).filter(([, enabled]) => !bool(enabled)).map(([name]) => name);
    return {
      ...payload,
      capabilities: payload.capabilities || {},
      docker: {
        ...docker,
        available: bool(docker.available),
        service: docker.service || docker.service_status || {},
        info,
        config,
        containers,
        images,
        networks: array(docker.networks),
        volumes: array(docker.volumes),
        diskUsage: array(docker.disk_usage).length ? array(docker.disk_usage) : docker.system_df || {},
        counts: {
          containers: number(docker.counts?.containers, info.Containers, containers.length),
          running: number(docker.counts?.running, info.ContainersRunning, containers.filter((row) => /running|up/i.test(firstText(row.state, row.State, row.status, row.Status))).length),
          images: number(docker.counts?.images, info.Images, images.length)
        },
        version: firstText(info.version, info.ServerVersion),
        driver: firstText(info.storage_driver, info.Driver, info.StorageDriver),
        dataRoot: firstText(info.data_root, info.DockerRootDir, config.data_root, config.globals?.data_root)
      },
      lxc: {
        ...lxc,
        available: bool(lxc.available),
        service: lxc.service || lxc.service_status || {},
        containers: array(lxc.containers),
        commands,
        missing,
        config: lxc.config && typeof lxc.config === 'object' ? lxc.config : {},
        capabilities: lxc.capabilities || {}
      }
    };
  }

  function semanticSignature(value) {
    return JSON.stringify(value, (key, item) => ['ts', 'timestamp', 'generated_at'].includes(key) ? undefined : item);
  }

  function icon(name) {
    const icons = {
      refresh: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11a8 8 0 1 0 2 5.3"/><path d="M20 4v7h-7"/></svg>',
      search: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>',
      docker: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 11h16c-.4 5.6-4 9-9.8 9C5 20 2.4 17.6 2 13h12c1.5 0 2.8-.5 3.8-1.4.8-.7 1.5-1.6 1.9-2.7 1.3.1 2.2.5 2.8 1.1-.8 1.3-2 2-3.6 2"/><path d="M5 8h3v3H5zM8 5h3v3H8zM8 8h3v3H8zM11 8h3v3h-3zM11 5h3v3h-3z"/></svg>',
      lxc: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m12 3 4 2.3v4.5L12 12l-4-2.2V5.3L12 3Z"/><path d="m7 12 4 2.3v4.5L7 21l-4-2.2v-4.5L7 12Zm10 0 4 2.3v4.5L17 21l-4-2.2v-4.5l4-2.3Z"/></svg>',
      box: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m21 8-9-5-9 5 9 5 9-5Z"/><path d="M3 8v8l9 5 9-5V8M12 13v8"/></svg>',
      image: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="9" cy="9" r="1.5"/><path d="m5 18 5-5 3 3 2-2 4 4"/></svg>',
      disk: '<svg viewBox="0 0 24 24" aria-hidden="true"><ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg>',
      terminal: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m5 7 5 5-5 5M12 19h7"/></svg>',
      network: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="8" y="3" width="8" height="5" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/><rect x="14" y="16" width="7" height="5" rx="1"/><path d="M12 8v4M6.5 16v-4h11v4"/></svg>'
    };
    return icons[name] || icons.box;
  }

  function overviewCard(label, value, detail, glyph, tone = 'info') {
    return `<article class="dwrt-kit-overview-card is-${tone}"><div class="dwrt-kit-overview-content"><span class="dwrt-kit-overview-label">${escapeHtml(label)}</span><strong>${escapeHtml(value || '--')}</strong><small>${escapeHtml(detail || '--')}</small></div><span class="dwrt-kit-overview-icon">${icon(glyph)}</span></article>`;
  }

  function overview() {
    if (mode === 'lxc') {
      const lxc = state.data.lxc;
      const availableCommands = Object.values(lxc.commands).filter((value) => bool(value)).length;
      const path = firstText(lxc.config.lxcpath, lxc.config.path, lxc.config.root);
      return `<section class="dwrt-kit-overview-grid container-service-overview" aria-label="LXC 概览">
        ${overviewCard('LXC', lxc.available ? '可用' : '未检测到', serviceState(lxc.service), 'lxc', lxc.available ? 'ok' : 'warn')}
        ${overviewCard('容器', String(lxc.containers.length), `${lxc.containers.filter((row) => /running/i.test(firstText(row.state, row.State))).length} 个运行中`, 'box')}
        ${overviewCard('命令', `${availableCommands} / ${Object.keys(lxc.commands).length}`, lxc.missing.length ? `缺少 ${lxc.missing.length} 个命令` : '命令完整', 'terminal', lxc.missing.length ? 'warn' : 'ok')}
        ${overviewCard('配置路径', path || '--', Object.keys(lxc.config).length ? '配置已读取' : '后端未返回路径', 'disk', path ? 'info' : 'warn')}
      </section>`;
    }
    const docker = state.data.docker;
    return `<section class="dwrt-kit-overview-grid container-service-overview" aria-label="Docker 概览">
      ${overviewCard('Docker', docker.available ? '可用' : '未检测到', [docker.version, serviceState(docker.service)].filter(Boolean).join(' · '), 'docker', docker.available ? 'ok' : 'warn')}
      ${overviewCard('运行容器', `${docker.counts.running} / ${docker.counts.containers}`, '运行中 / 总数', 'box')}
      ${overviewCard('镜像', String(docker.counts.images), '本地镜像', 'image')}
      ${overviewCard('存储驱动', docker.driver || '--', docker.dataRoot || '后端未返回数据目录', 'disk', docker.driver ? 'info' : 'warn')}
    </section>`;
  }

  function tabs() {
    const items = mode === 'docker'
      ? [['overview', '概览'], ['containers', '容器'], ['images', '镜像'], ['networks', '网络'], ['volumes', '卷'], ['config', '配置']]
      : [['overview', '概览'], ['containers', '容器'], ['config', '配置']];
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs container-service-tabs" role="tablist" aria-label="${mode === 'docker' ? 'Docker' : 'LXC'} 视图"><span class="dwrt-kit-tab-pill" aria-hidden="true"></span>${items.map(([id, label]) => `<button class="dwrt-kit-tab ${state.tab === id ? 'is-active' : ''}" type="button" data-container-tab="${id}" data-value="${id}" aria-selected="${state.tab === id ? 'true' : 'false'}">${label}</button>`).join('')}</nav>`;
  }

  function toolbar() {
    const searchable = state.tab !== 'overview' && state.tab !== 'config';
    return `<header class="container-service-header">${tabs()}<div class="container-service-actions">${searchable ? `<label class="policy-search policy-search-main container-service-search" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-container-search value="${escapeHtml(state.query)}" placeholder="搜索当前列表" autocomplete="off"></label>` : ''}</div></header>`;
  }

  function statusPill(value) {
    const text = firstText(value, '--');
    const lower = text.toLowerCase();
    const tone = /running|up|active|enabled|true/.test(lower) ? 'success' : /exited|stopped|down|disabled|false/.test(lower) ? 'error' : 'warning';
    return ui.statusBadgeMarkup?.(text, tone) || `<span>${escapeHtml(text)}</span>`;
  }

  function compactId(value) {
    const text = firstText(value, '--');
    return text.length > 14 ? text.slice(0, 12) : text;
  }

  function matches(row) {
    const query = state.query.trim().toLowerCase();
    return !query || JSON.stringify(row || {}).toLowerCase().includes(query);
  }

  function table(title, rows, columns, empty) {
    const filtered = rows.filter(matches);
    return `<section class="container-service-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface policy-stable-glass"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>${escapeHtml(title)}</strong><span>${rows.length} 项</span></div></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table"><thead><tr>${columns.map((column) => `<th>${escapeHtml(column.label)}</th>`).join('')}</tr></thead><tbody>${state.loading ? `<tr><td colspan="${columns.length}" class="dwrt-kit-table-empty">正在读取容器服务</td></tr>` : filtered.length ? filtered.map((row) => `<tr>${columns.map((column) => `<td data-label="${escapeHtml(column.label)}">${column.render(row)}</td>`).join('')}</tr>`).join('') : `<tr><td colspan="${columns.length}" class="dwrt-kit-table-empty">${escapeHtml(state.query ? '没有匹配的项目' : empty)}</td></tr>`}</tbody></table></div></section>`;
  }

  function dockerPanel() {
    const docker = state.data.docker;
    if (state.tab === 'overview') return overview();
    if (state.tab === 'images') return table('Docker 镜像', docker.images, [
      { label: '仓库', render: (row) => escapeHtml(firstText(row.repository, row.Repository, row.name, row.Name, '--')) },
      { label: '标签', render: (row) => escapeHtml(firstText(row.tag, row.Tag, '--')) },
      { label: '大小', render: (row) => escapeHtml(firstText(row.size, row.Size, '--')) },
      { label: '创建时间', render: (row) => escapeHtml(firstText(row.created_since, row.CreatedSince, row.created, row.CreatedAt, '--')) },
      { label: 'ID', render: (row) => `<code>${escapeHtml(compactId(firstText(row.id, row.ID, row.Id)))}</code>` }
    ], '没有检测到 Docker 镜像');
    if (state.tab === 'networks') return table('Docker 网络', docker.networks, [
      { label: '名称', render: (row) => `<strong>${escapeHtml(firstText(row.name, row.Name, '--'))}</strong>` },
      { label: '驱动', render: (row) => escapeHtml(firstText(row.driver, row.Driver, '--')) },
      { label: '作用域', render: (row) => escapeHtml(firstText(row.scope, row.Scope, '--')) },
      { label: 'ID', render: (row) => `<code>${escapeHtml(compactId(firstText(row.id, row.ID, row.Id)))}</code>` }
    ], '没有检测到 Docker 网络');
    if (state.tab === 'volumes') return table('Docker 卷', docker.volumes, [
      { label: '名称', render: (row) => `<strong>${escapeHtml(firstText(row.name, row.Name, '--'))}</strong>` },
      { label: '驱动', render: (row) => escapeHtml(firstText(row.driver, row.Driver, '--')) },
      { label: '挂载点', render: (row) => `<code>${escapeHtml(firstText(row.mountpoint, row.Mountpoint, '--'))}</code>` }
    ], '没有检测到 Docker 卷');
    if (state.tab === 'config') return configGrid([
      ['Docker 信息', docker.info, 'Docker info 暂无返回'],
      ['Dockerd 配置', docker.config, 'Dockerd 配置为空'],
      ['空间占用', docker.diskUsage, 'Docker system df 暂无返回'],
      ['操作能力', { docker_actions: bool(state.data.capabilities.docker_actions) || bool(docker.capabilities?.actions), mode: bool(state.data.capabilities.docker_actions) || bool(docker.capabilities?.actions) ? '可管理' : '只读' }, '能力信息为空']
    ]);
    return table('Docker 容器', docker.containers, [
      { label: '名称', render: (row) => `<span class="container-service-name"><strong>${escapeHtml(firstText(row.names, row.Names, row.name, row.Name, '--'))}</strong><small>${escapeHtml(compactId(firstText(row.id, row.ID, row.Id)))}</small></span>` },
      { label: '镜像', render: (row) => escapeHtml(firstText(row.image, row.Image, '--')) },
      { label: '状态', render: (row) => statusPill(firstText(row.state, row.State, row.status, row.Status)) },
      { label: '运行信息', render: (row) => escapeHtml(firstText(row.status, row.Status, '--')) },
      { label: '端口', render: (row) => escapeHtml(firstText(row.ports, row.Ports, '未映射')) }
    ], '没有检测到 Docker 容器');
  }

  function lxcPanel() {
    const lxc = state.data.lxc;
    if (state.tab === 'overview') return overview();
    if (state.tab === 'config') return configGrid([['LXC 配置', lxc.config, '配置为空'], ['命令能力', lxc.commands, '没有命令能力返回']]);
    const list = table('LXC 容器', lxc.containers, [
      { label: '名称', render: (row) => `<span class="container-service-name"><strong>${escapeHtml(firstText(row.name, row.Name, '--'))}</strong><small>${escapeHtml(firstText(row.groups, row.group, 'default'))}</small></span>` },
      { label: '状态', render: (row) => statusPill(firstText(row.state, row.State)) },
      { label: '自启动', render: (row) => statusPill(bool(firstText(row.autostart, row.Autostart)) ? '已启用' : '已禁用') },
      { label: 'IPv4', render: (row) => escapeHtml(firstText(row.ipv4, row.IPV4, row.ip, '--')) },
      { label: 'IPv6', render: (row) => `<code>${escapeHtml(firstText(row.ipv6, row.IPV6, '--'))}</code>` }
    ], '没有检测到 LXC 容器');
    return `${!lxc.available ? `<div class="container-service-notice is-warning">当前系统未检测到完整 LXC 运行环境；下方显示后端实际探测到的容器。</div>` : ''}${list}`;
  }

  function flatten(value, prefix = '', output = {}) {
    if (Array.isArray(value)) {
      value.forEach((item, index) => flatten(item, prefix ? `${prefix}.${index}` : String(index), output));
      return output;
    }
    if (value && typeof value === 'object') {
      Object.entries(value).forEach(([key, item]) => flatten(item, prefix ? `${prefix}.${key}` : key, output));
      return output;
    }
    if (prefix) output[prefix] = value;
    return output;
  }

  function valueText(value) {
    if (typeof value === 'boolean') return value ? '是' : '否';
    return firstText(value, '--');
  }

  function configGrid(cards) {
    return `<section class="container-service-config-grid">${cards.map(([title, value, empty]) => {
      const entries = Object.entries(flatten(value || {})).filter(([, item]) => item !== undefined && item !== null && item !== '');
      return `<article class="container-service-info dwrt-kit-table-wrap dwrt-kit-glass-surface policy-stable-glass"><header><strong>${escapeHtml(title)}</strong><span>${entries.length} 项</span></header>${entries.length ? `<dl>${entries.slice(0, 48).map(([key, item]) => `<div><dt>${escapeHtml(key)}</dt><dd>${escapeHtml(valueText(item))}</dd></div>`).join('')}</dl>` : `<div class="container-service-empty">${escapeHtml(empty)}</div>`}</article>`;
    }).join('')}</section>`;
  }

  function panel() {
    return `<div class="container-service-panel" data-container-panel>${mode === 'docker' ? dockerPanel() : lxcPanel()}</div>`;
  }

  function render() {
    if (!root || !state.mounted) return;
    root.className = `route-preview route-workspace policy-table-route-host container-service-route-host is-${mode}`;
    root.innerHTML = `<div class="container-service-shell">${toolbar()}<main class="container-service-workbench">${state.error ? `<div class="container-service-notice is-error">读取失败：${escapeHtml(state.error)}</div>` : ''}${panel()}</main></div>`;
    ui.mountAll?.(root);
  }

  function patchPanel() {
    const current = root?.querySelector('[data-container-panel]');
    if (!current) { render(); return; }
    const template = document.createElement('template');
    template.innerHTML = panel();
    current.replaceWith(template.content.firstElementChild);
  }

  async function load(explicit = false) {
    if (!state.mounted || state.refreshing) return;
    const seq = ++state.seq;
    state.refreshing = true;
    state.error = '';
    try {
      const next = normalize(await requestJson());
      if (!state.mounted || seq !== state.seq) return;
      const signature = semanticSignature(next);
      const changed = signature !== state.signature;
      state.data = next;
      state.signature = signature;
      state.loading = false;
      state.refreshing = false;
      if (changed || explicit) render();
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      state.error = firstText(error.message, '接口不可用');
      render();
    }
  }

  function onClick(event) {
    const tab = event.target.closest('[data-container-tab]');
    if (tab && state.tab !== tab.dataset.containerTab) {
      state.tab = tab.dataset.containerTab;
      state.query = '';
      render();
      requestAnimationFrame(() => root?.querySelector(`[data-container-tab="${state.tab}"]`)?.scrollIntoView({ block: 'nearest', inline: 'nearest' }));
      return;
    }
  }

  function onInput(event) {
    const input = event.target.closest('[data-container-search]');
    if (!input) return;
    state.query = input.value || '';
    patchPanel();
  }

  root?.addEventListener('click', onClick);
  root?.addEventListener('input', onInput);
  stage?.classList.add('is-container-service');
  render();
  load();
  state.timer = window.setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);

  return {
    refresh() { return load(true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      if (state.timer) window.clearInterval(state.timer);
      root?.removeEventListener('click', onClick);
      root?.removeEventListener('input', onInput);
      root?.replaceChildren();
      root?.classList.remove('route-workspace', 'policy-table-route-host', 'container-service-route-host', 'is-docker', 'is-lxc');
      stage?.classList.remove('is-container-service');
    }
  };
}

export default { mount };
