const VERSION = '20260723-vpn-01';

const ENDPOINTS = Object.freeze({
  overview: '/api/v1/network/settings-overview',
  aggregate: '/api/v1/vpn',
  server: '/api/v1/vpn/servers',
  client: '/api/v1/vpn/clients',
  site: '/api/v1/vpn/site-to-site',
  account: '/api/v1/vpn/accounts',
  certificate: '/api/v1/vpn/certificates'
});

const PROTOCOLS = Object.freeze({
  server: [
    ['wireguard', 'WireGuard', '现代、高性能的远程接入', 'recommended'],
    ['openvpn', 'OpenVPN', '使用配置文件的兼容方案', ''],
    ['l2tp', 'L2TP', '适用于传统客户端', 'legacy'],
    ['ikev2', 'IKEv2 / IPsec', 'LuCI 扩展的移动接入', 'extended'],
    ['pppoe', 'PPPoE', 'LuCI 扩展的拨号服务', 'extended'],
    ['pptp', 'PPTP', '仅用于遗留兼容', 'legacy']
  ],
  client: [
    ['wireguard', 'WireGuard', '文件导入或手动配置', 'recommended'],
    ['openvpn', 'OpenVPN', '上传 .ovpn 配置文件', ''],
    ['l2tp', 'L2TP', 'LuCI 扩展客户端', 'extended'],
    ['pptp', 'PPTP', '仅用于遗留兼容', 'legacy'],
    ['ipsec', 'IPsec VPN', 'LuCI 扩展客户端', 'extended'],
    ['ikev2', 'IKEv2 / IPsec', 'LuCI 扩展客户端', 'extended']
  ],
  site: [
    ['ipsec', 'IPsec', '标准站点到站点隧道', 'recommended'],
    ['openvpn', 'OpenVPN', '基于预共享密钥的站点互联', ''],
    ['wireguard', 'WireGuard', 'LuCI 扩展站点互联', 'extended']
  ]
});

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const stage = root?.closest('.console-stage');
  const state = {
    mounted: true,
    loading: true,
    refreshing: false,
    seq: 0,
    error: '',
    notice: '',
    overview: {},
    server: [],
    client: [],
    site: [],
    account: [],
    certificate: [],
    readable: { server: false, client: false, site: false, account: false, certificate: false },
    writable: { server: false, client: false, site: false, account: false, certificate: false },
    drawer: '',
    drawerSettled: false,
    protocol: '',
    draft: {},
    advanced: false,
    saving: false,
    localUsers: [],
    localClients: []
  };

  function icon(name, size = 20) {
    return `<i data-lucide="${escapeHtml(name)}" width="${size}" height="${size}" aria-hidden="true"></i>`;
  }

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (typeof value === 'object' && !Array.isArray(value)) {
        const nested = firstText(value.label, value.name, value.id, value.address, value.value);
        if (nested) return nested;
        continue;
      }
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }

  function asArray(value, keys = []) {
    if (Array.isArray(value)) return value;
    for (const key of keys) if (Array.isArray(value?.[key])) return value[key];
    return [];
  }

  function asBoolean(value, fallback = false) {
    if (typeof value === 'boolean') return value;
    if (value === 1 || value === '1' || value === 'true') return true;
    if (value === 0 || value === '0' || value === 'false') return false;
    return fallback;
  }

  function unwrap(result) {
    return result?.data ?? result?.raw?.data ?? result?.raw ?? result ?? {};
  }

  async function read(name, url) {
    if (typeof api.fetch === 'function') {
      const result = await api.fetch(name, url);
      if (result?.ok === false) {
        const error = new Error(firstText(result?.raw?.message, result?.raw?.error, result?.status, '接口不可用'));
        error.status = Number(result?.status || result?.raw?.status || 0);
        throw error;
      }
      return unwrap(result);
    }
    const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store', signal: context.signal, headers: { Accept: 'application/json' } });
    const json = await response.json().catch(() => ({}));
    if (!response.ok || json?.ok === false) {
      const error = new Error(firstText(json?.message, json?.error, response.status));
      error.status = response.status;
      throw error;
    }
    return json?.data ?? json;
  }

  function capability(payload, action) {
    const capabilities = payload?.capabilities || payload?.capability || {};
    const candidates = [
      capabilities[action], capabilities[`vpn_${action}`], capabilities[`${action}_supported`],
      context.capabilities?.[`vpn_${action}`], context.capabilities?.[action]
    ];
    return candidates.some((value) => value === true || value === 1 || value === 'true');
  }

  function normalizeItem(item = {}, index = 0, kind = 'server') {
    const protocol = firstText(item.protocol, item.type, item.kind).toLowerCase().replace(/[\s/]+/g, '-');
    const status = firstText(item.status, item.runtime?.status, item.state) || (item.enabled === false ? 'disabled' : 'unknown');
    return {
      ...item,
      id: firstText(item.id, item.uuid, item.name, `${kind}-${index + 1}`),
      name: firstText(item.name, item.label, `${kind === 'site' ? '站点' : kind === 'client' ? '客户端' : '服务器'} ${index + 1}`),
      protocol,
      status,
      enabled: item.enabled !== false,
      endpoint: firstText(item.endpoint, item.remote, item.server_address, item.peer, item.listen_address),
      address: firstText(item.address, item.address_pool, item.gateway, item.interface_address),
      networks: asArray(item.networks || item.remote_networks || item.routes).map(String)
    };
  }

  function applyPayload(kind, payload) {
    const plural = kind === 'site' ? ['site_to_site', 'sites', 'tunnels', 'items'] : [`${kind}s`, kind, 'items'];
    state[kind] = asArray(payload, plural).map((item, index) => normalizeItem(item, index, kind));
    state.readable[kind] = true;
    state.writable[kind] = capability(payload, `${kind}_create`) || capability(payload, 'create');
  }

  async function load(force = false) {
    const seq = ++state.seq;
    state.loading = !force;
    state.refreshing = force;
    state.error = '';
    if (!force) render();
    const overviewPromise = read('vpn-overview', ENDPOINTS.overview).catch(() => ({}));
    let aggregate = null;
    try { aggregate = await read('vpn-aggregate', ENDPOINTS.aggregate); } catch (_) {}
    if (!state.mounted || seq !== state.seq) return;
    if (aggregate && typeof aggregate === 'object') {
      for (const kind of ['server', 'client', 'site', 'account', 'certificate']) applyPayload(kind, aggregate[kind] ?? aggregate);
    } else {
      const results = await Promise.allSettled(['server', 'client', 'site', 'account', 'certificate'].map((kind) => read(`vpn-${kind}`, ENDPOINTS[kind])));
      if (!state.mounted || seq !== state.seq) return;
      results.forEach((result, index) => {
        const kind = ['server', 'client', 'site', 'account', 'certificate'][index];
        if (result.status === 'fulfilled') applyPayload(kind, result.value);
      });
    }
    state.overview = await overviewPromise;
    if (!state.mounted || seq !== state.seq) return;
    state.loading = false;
    state.refreshing = false;
    render();
  }

  function statusBadge(item) {
    const value = firstText(item.status, 'unknown').toLowerCase();
    const online = ['online', 'connected', 'active', 'running', 'up', 'ok'].includes(value);
    const stopped = ['offline', 'failed', 'error', 'down', 'stopped'].includes(value);
    const label = online ? '已连接' : stopped ? '异常' : item.enabled === false ? '已停用' : '未连接';
    return ui.statusBadgeMarkup?.(label, online ? 'success' : stopped ? 'error' : 'muted') || `<span>${escapeHtml(label)}</span>`;
  }

  function actionButton(label, action, options = {}) {
    return `<button class="dwrt-kit-button vpn-action-button" data-dwrt-component="button" data-variant="${options.primary ? 'primary' : 'ghost'}" type="button" data-vpn-action="${escapeHtml(action)}" ${options.disabled ? 'disabled' : ''}>${options.icon ? icon(options.icon, 17) : ''}<span>${escapeHtml(label)}</span></button>`;
  }

  function emptyState(kind) {
    const readable = state.readable[kind];
    const labels = { server: 'VPN 服务器', client: 'VPN 客户端', site: '站点到站点 VPN' };
    return `<div class="vpn-empty-state" data-dwrt-component="state-panel" data-dwrt-state="${readable ? 'empty' : 'unavailable'}">
      ${icon(readable ? 'circle-off' : 'unplug', 24)}
      <strong>${readable ? `尚未配置${labels[kind]}` : `${labels[kind]}接口未开放`}</strong>
      <p>${readable ? '创建后，连接状态与远端信息会显示在这里。' : '前端不会使用示例隧道填充列表；后端开放读取合同后将自动显示真实配置。'}</p>
    </div>`;
  }

  function listTable(kind) {
    const rows = state[kind];
    if (!rows.length) return emptyState(kind);
    const headings = kind === 'site' ? ['状态', '名称', '类型', '对端', '远端网络'] : ['状态', '名称', '协议', kind === 'client' ? '服务器' : '监听地址', '地址'];
    return `<div class="dwrt-kit-table-wrap vpn-table-wrap" data-dwrt-component="data-table"><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table vpn-table"><thead><tr>${headings.map((heading) => `<th>${heading}</th>`).join('')}</tr></thead><tbody>${rows.map((item) => `<tr data-vpn-open-item="${escapeHtml(kind)}" data-vpn-id="${escapeHtml(item.id)}"><td>${statusBadge(item)}</td><td><button type="button" class="vpn-row-link" data-vpn-open-item="${escapeHtml(kind)}" data-vpn-id="${escapeHtml(item.id)}">${escapeHtml(item.name)}</button></td><td>${escapeHtml(item.protocol || '--')}</td><td>${escapeHtml(item.endpoint || '--')}</td><td>${escapeHtml((item.networks || []).join(', ') || item.address || '--')}</td></tr>`).join('')}</tbody></table></div></div>`;
  }

  function teleportPanel() {
    return `<article class="vpn-section vpn-teleport dwrt-kit-glass-surface" data-adaptive-sample>
      <div class="vpn-section-icon is-teleport">${icon('sparkles', 22)}</div>
      <div class="vpn-section-copy"><strong>Teleport</strong><p>使用一次性邀请快速连接到此网络，无需手动分发 VPN 配置。</p></div>
      <div class="vpn-section-actions">${ui.statusBadgeMarkup?.('后端未开放', 'muted', { dot: false }) || ''}${actionButton('生成邀请', 'teleport', { icon: 'send', disabled: true })}</div>
    </article>`;
  }

  function managementActions() {
    return `<div class="vpn-resource-actions" aria-label="本地认证资源">${actionButton('账号', 'manage-account', { icon: 'users' })}${actionButton('证书', 'manage-certificate', { icon: 'badge-check' })}</div>`;
  }

  function sectionPanel(kind, title, description, iconName) {
    return `<article class="vpn-section dwrt-kit-glass-surface" data-vpn-section="${kind}" data-adaptive-sample>
      <header class="vpn-section-header">
        <div class="vpn-section-icon">${icon(iconName, 22)}</div>
        <div class="vpn-section-copy"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(description)}</p></div>
        <div class="vpn-section-actions">${kind === 'server' ? managementActions() : ''}${actionButton('新建', `create-${kind}`, { primary: true, icon: 'plus' })}</div>
      </header>
      <div class="vpn-section-body">${state.loading ? `<div class="vpn-loading" data-dwrt-component="state-panel" data-dwrt-state="loading"><strong>正在读取 ${escapeHtml(title)}</strong></div>` : listTable(kind)}</div>
    </article>`;
  }

  function renderPage() {
    return `<section class="vpn-config-shell" data-vpn-version="${VERSION}">
      <header class="vpn-page-toolbar" data-dwrt-component="toolbar"><div><strong>VPN</strong><span>远程接入、策略出口与站点互联</span></div>${actionButton(state.refreshing ? '正在刷新' : '刷新', 'refresh', { icon: 'refresh-cw', disabled: state.refreshing })}</header>
      ${state.error ? `<div class="vpn-notice is-error" role="alert">${escapeHtml(state.error)}</div>` : ''}
      ${state.notice ? `<div class="vpn-notice" role="status">${escapeHtml(state.notice)}</div>` : ''}
      <main class="vpn-section-stack">
        ${teleportPanel()}
        ${sectionPanel('server', 'VPN 服务器', '允许远程客户端安全接入此网关和本地网络。', 'shield-check')}
        ${sectionPanel('client', 'VPN 客户端', '让选定设备、网络或目标内容通过外部 VPN 服务。', 'route')}
        ${sectionPanel('site', '站点到站点 VPN', '在两个网络之间建立持久的加密连接。', 'waypoints')}
      </main>
      ${drawerMarkup()}
    </section>`;
  }

  function defaultProtocol(kind) {
    return PROTOCOLS[kind]?.[0]?.[0] || '';
  }

  function defaultDraft(kind, protocol = defaultProtocol(kind)) {
    const base = { enabled: true, name: '', protocol, advanced_mode: 'auto', mtu: '', ipv4_mss: '', ipv6_mss: '' };
    if (kind === 'server') return { ...base, server_address_mode: 'wan', server_address: '', port: protocol === 'openvpn' ? 1194 : protocol === 'wireguard' ? 51820 : 500, fallback_address: '', listen_mode: 'all', listen_addresses: '', ipv4_gateway: protocol === 'wireguard' ? '192.168.2.1/24' : '', ipv6_gateway: '', auto_dns: true, auth_mode: 'local', preshared_key: '', address_pool: '', strong_auth: true, legacy_clients: false, public_key: '' };
    if (kind === 'client') return { ...base, setup_mode: protocol === 'wireguard' ? 'file' : 'file', config_file: '', device_route_mode: 'off', devices: '', content_route_mode: 'off', content_targets: '', username: '', password: '', endpoint: '', private_key: '', address: '' };
    if (kind === 'site') return { ...base, preshared_key: '', local_ip_mode: 'wan', local_ip: '', remote_ip: '', routing_mode: 'policy', tunnel_ip: '', local_networks: '', remote_network_mode: 'static', remote_networks: '', local_port: 1194, remote_tunnel_ip: '', remote_port: 1194, cipher: 'default', ike_version: 'ikev2', ike_encryption: 'aes256', ike_hash: 'sha256', ike_dh: '14', ike_lifetime: 28800, esp_encryption: 'aes256', esp_hash: 'sha256', esp_dh: '14', esp_lifetime: 3600, pfs: true, local_id: '', remote_id: '', route_distance: 30 };
    if (kind === 'account') return { username: '', password: '', group: 'default', protocols: 'L2TP, OpenVPN, PPPoE', max_sessions: 1, vlan: '', expires: '' };
    return { name: '', type: 'client', common_name: '', lifetime_days: 3650 };
  }

  function openDrawer(kind, item = null) {
    state.drawer = kind;
    state.drawerSettled = false;
    state.protocol = item?.protocol || defaultProtocol(kind);
    state.draft = item ? { ...defaultDraft(kind, state.protocol), ...item } : defaultDraft(kind, state.protocol);
    state.advanced = false;
    state.localUsers = [];
    state.localClients = [];
    state.notice = '';
    render();
    state.drawerSettled = true;
  }

  function closeDrawer() {
    state.drawer = '';
    state.drawerSettled = false;
    state.draft = {};
    state.notice = '';
    render();
  }

  function protocolChooser(kind) {
    return `<fieldset class="vpn-protocol-chooser"><legend>VPN 类型</legend><div>${PROTOCOLS[kind].map(([value, label, detail, badge]) => `<button type="button" class="vpn-protocol-option ${state.protocol === value ? 'is-selected' : ''}" data-vpn-protocol="${value}" aria-pressed="${state.protocol === value}"><span class="vpn-protocol-radio" aria-hidden="true"></span><span><strong>${escapeHtml(label)}</strong><small>${escapeHtml(detail)}</small></span>${badge ? `<em>${badge === 'recommended' ? '推荐' : badge === 'legacy' ? '旧版' : '扩展'}</em>` : ''}</button>`).join('')}</div></fieldset>`;
  }

  function field(label, key, options = {}) {
    const value = state.draft[key] ?? '';
    const wide = options.wide ? ' is-wide' : '';
    const help = options.help ? `<small data-dwrt-field-description>${escapeHtml(options.help)}</small>` : '';
    let control = '';
    if (options.type === 'select') control = `<select data-vpn-field="${escapeHtml(key)}">${options.options.map(([option, text]) => `<option value="${escapeHtml(option)}" ${String(value) === String(option) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select>`;
    else if (options.type === 'file') control = `<input type="file" data-vpn-file="${escapeHtml(key)}" accept="${escapeHtml(options.accept || '')}">`;
    else control = `<input type="${escapeHtml(options.type || 'text')}" data-vpn-field="${escapeHtml(key)}" value="${options.type === 'password' ? '' : escapeHtml(value)}" placeholder="${escapeHtml(options.placeholder || '')}" ${options.autocomplete ? `autocomplete="${escapeHtml(options.autocomplete)}"` : ''}>`;
    return `<label class="vpn-field${wide}" data-dwrt-component="field"><span data-dwrt-field-label>${escapeHtml(label)}</span>${control}${help}</label>`;
  }

  function switchField(label, key, detail = '') {
    return `<label class="vpn-switch-field" data-dwrt-component="switch"><span><strong>${escapeHtml(label)}</strong>${detail ? `<small>${escapeHtml(detail)}</small>` : ''}</span><input type="checkbox" data-vpn-field="${escapeHtml(key)}" ${state.draft[key] ? 'checked' : ''}></label>`;
  }

  function userRows() {
    return `<div class="vpn-inline-list"><div class="vpn-inline-list-head"><strong>本地用户</strong><button type="button" data-vpn-add-user>${icon('plus', 15)} 添加</button></div>${state.localUsers.length ? state.localUsers.map((user, index) => `<div class="vpn-inline-row"><input type="text" value="${escapeHtml(user.username || '')}" data-vpn-user="${index}" data-vpn-user-field="username" aria-label="用户名"><input type="password" value="" data-vpn-user="${index}" data-vpn-user-field="password" aria-label="密码" autocomplete="new-password"><button type="button" data-vpn-remove-user="${index}" aria-label="删除用户">${icon('trash-2', 16)}</button></div>`).join('') : '<p>使用本地认证时，可在此添加用户名和密码。</p>'}</div>`;
  }

  function wireGuardClients() {
    return `<div class="vpn-inline-list"><div class="vpn-inline-list-head"><strong>客户端</strong><button type="button" data-vpn-add-client>${icon('plus', 15)} 添加客户端</button></div>${state.localClients.length ? state.localClients.map((client, index) => `<div class="vpn-inline-row is-client"><input type="text" value="${escapeHtml(client.name || '')}" data-vpn-client="${index}" aria-label="客户端名称"><span>配置文件将在后端创建成功后生成</span><button type="button" data-vpn-remove-client="${index}" aria-label="删除客户端">${icon('trash-2', 16)}</button></div>`).join('') : '<p>创建服务器时可以同时定义需要生成配置的客户端。</p>'}</div>`;
  }

  function disclosure(title, summary, content) {
    return `<section class="vpn-advanced" data-dwrt-component="disclosure"><button type="button" data-dwrt-disclosure-trigger aria-expanded="${state.advanced}"><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(summary)}</small></span>${icon('chevron-down', 18)}</button><div data-dwrt-disclosure-panel ${state.advanced ? '' : 'hidden'}>${content}</div></section>`;
  }

  function serverFields() {
    const protocol = state.protocol;
    const common = `${field('名称', 'name', { placeholder: `例如 ${PROTOCOLS.server.find(([value]) => value === protocol)?.[1] || 'VPN'} 服务器`, wide: true })}`;
    if (protocol === 'wireguard') return `${common}<div class="vpn-form-grid">${field('服务器地址', 'server_address_mode', { type: 'select', options: [['wan', 'WAN IP'], ['manual', '手动 IP']] })}${state.draft.server_address_mode === 'manual' ? field('手动 IP', 'server_address') : field('客户端备用地址', 'fallback_address', { placeholder: '可选域名或 IP' })}${field('端口', 'port', { type: 'number' })}</div>${wireGuardClients()}${disclosure('高级', '接口、地址、DNS 与 MTU', `<div class="vpn-form-grid">${field('侦听', 'listen_mode', { type: 'select', options: [['all', '所有接口'], ['selected', '所选接口地址']] })}${state.draft.listen_mode === 'selected' ? field('接口地址', 'listen_addresses', { placeholder: 'wan, wan2' }) : ''}${field('IPv4 网关 / 子网', 'ipv4_gateway')}${field('IPv6 网关 / 子网', 'ipv6_gateway')}${field('MTU', 'mtu', { type: 'number' })}${field('IPv4 MSS', 'ipv4_mss', { type: 'number' })}${field('IPv6 MSS', 'ipv6_mss', { type: 'number' })}${field('公钥', 'public_key', { wide: true, help: '创建成功后由后端生成或返回。' })}</div>${switchField('自动 DNS', 'auto_dns')}`)}`;
    if (protocol === 'openvpn') return `${common}<div class="vpn-form-grid">${field('服务器地址', 'server_address_mode', { type: 'select', options: [['wan', 'WAN IP'], ['manual', '手动 IP']] })}${field('端口', 'port', { type: 'number' })}${field('客户端备用地址', 'fallback_address')}${field('认证', 'auth_mode', { type: 'select', options: [['local', '本地认证'], ['radius', '外部 RADIUS']] })}${field('IPv4 地址池', 'address_pool')}</div>${state.draft.auth_mode === 'local' ? userRows() : ''}${disclosure('高级', 'DNS、MTU 与 MSS', `<div class="vpn-form-grid">${field('MTU', 'mtu', { type: 'number' })}${field('IPv4 MSS', 'ipv4_mss', { type: 'number' })}</div>${switchField('自动 DNS', 'auto_dns')}`)}`;
    if (protocol === 'l2tp' || protocol === 'pptp') return `<div class="vpn-legacy-note">${icon('triangle-alert', 18)}<span><strong>传统 VPN</strong><small>${protocol === 'pptp' ? 'PPTP 不提供现代加密，仅用于遗留兼容。' : 'L2TP 适用于仍依赖系统内置传统客户端的设备。'}</small></span></div>${common}<div class="vpn-form-grid">${protocol === 'l2tp' ? field('预共享密钥', 'preshared_key', { type: 'password', autocomplete: 'new-password' }) : ''}${field('服务器地址', 'server_address_mode', { type: 'select', options: [['wan', 'WAN IP'], ['manual', '手动 IP']] })}${field('认证', 'auth_mode', { type: 'select', options: [['local', '本地认证'], ['radius', '外部 RADIUS']] })}${field('IPv4 地址池', 'address_pool')}</div>${state.draft.auth_mode === 'local' ? userRows() : ''}${switchField('自动 DNS', 'auto_dns')}${switchField('要求强身份验证', 'strong_auth')}${switchField('旧版客户端支持', 'legacy_clients')}`;
    return `${common}<div class="vpn-form-grid">${field('监听接口', 'listen_addresses', { placeholder: 'wan' })}${field('地址池', 'address_pool')}${field('认证', 'auth_mode', { type: 'select', options: [['local', '本地认证'], ['radius', '外部 RADIUS']] })}${field('端口', 'port', { type: 'number' })}</div>${state.draft.auth_mode === 'local' ? userRows() : ''}${disclosure('高级', 'LuCI 扩展协议参数', `<div class="vpn-form-grid">${field('MTU', 'mtu', { type: 'number' })}${field('IPv4 MSS', 'ipv4_mss', { type: 'number' })}</div>${switchField('自动 DNS', 'auto_dns')}`)}`;
  }

  function routingSelectors() {
    return `<div class="vpn-routing-groups"><section><strong>设备向导</strong><div class="vpn-segmented" data-dwrt-component="segmented">${[['off', '关'], ['devices', '设备'], ['networks', '网络']].map(([value, label]) => `<button type="button" data-dwrt-segment="${value}" data-vpn-segment-field="device_route_mode" class="${state.draft.device_route_mode === value ? 'is-active' : ''}">${label}</button>`).join('')}</div>${state.draft.device_route_mode !== 'off' ? field(state.draft.device_route_mode === 'devices' ? '设备' : '网络', 'devices', { placeholder: '选择或输入对象', wide: true }) : ''}</section><section><strong>内容向导</strong><div class="vpn-segmented" data-dwrt-component="segmented">${[['off', '关'], ['domain', '域'], ['ip', 'IP'], ['region', '地区']].map(([value, label]) => `<button type="button" data-dwrt-segment="${value}" data-vpn-segment-field="content_route_mode" class="${state.draft.content_route_mode === value ? 'is-active' : ''}">${label}</button>`).join('')}</div>${state.draft.content_route_mode !== 'off' ? field('目标', 'content_targets', { placeholder: '每行或逗号分隔', wide: true }) : ''}</section></div>`;
  }

  function clientFields() {
    const protocol = state.protocol;
    const common = `${field('名称', 'name', { placeholder: '例如 办公 VPN', wide: true })}`;
    if (protocol === 'wireguard') return `${common}<div class="vpn-form-grid">${field('设置', 'setup_mode', { type: 'select', options: [['file', '文件'], ['manual', '手动']] })}${state.draft.setup_mode === 'file' ? field('配置文件', 'config_file', { type: 'file', accept: '.conf,.txt' }) : field('端点', 'endpoint', { placeholder: 'host:port' })}${state.draft.setup_mode === 'manual' ? field('接口地址', 'address') + field('私钥', 'private_key', { type: 'password', autocomplete: 'new-password' }) : ''}</div>${routingSelectors()}${disclosure('高级', 'MTU 与 MSS', `<div class="vpn-form-grid">${field('MTU', 'mtu', { type: 'number' })}${field('IPv4 MSS', 'ipv4_mss', { type: 'number' })}${field('IPv6 MSS', 'ipv6_mss', { type: 'number' })}</div>`)}`;
    if (protocol === 'openvpn') return `${common}${field('上传配置文件', 'config_file', { type: 'file', accept: '.ovpn,.conf', wide: true })}${routingSelectors()}<div class="vpn-form-grid">${field('用户名', 'username')}${field('密码', 'password', { type: 'password', autocomplete: 'new-password' })}</div>${disclosure('高级', 'MTU 与 MSS', `<div class="vpn-form-grid">${field('MTU', 'mtu', { type: 'number' })}${field('IPv4 MSS', 'ipv4_mss', { type: 'number' })}</div>`)}`;
    return `${common}<div class="vpn-form-grid">${field('服务器', 'endpoint', { placeholder: '主机名或 IP' })}${field('用户名', 'username')}${field('密码', 'password', { type: 'password', autocomplete: 'new-password' })}${field('本地地址', 'address')}</div>${routingSelectors()}${disclosure('高级', 'LuCI 扩展客户端参数', `<div class="vpn-form-grid">${field('MTU', 'mtu', { type: 'number' })}${field('IPv4 MSS', 'ipv4_mss', { type: 'number' })}</div>`)}`;
  }

  function siteFields() {
    const protocol = state.protocol;
    const common = `${field('名称', 'name', { placeholder: '例如 上海分部', wide: true })}${field('预共享密钥', 'preshared_key', { type: 'password', autocomplete: 'new-password', wide: true })}`;
    if (protocol === 'ipsec') return `${common}<div class="vpn-form-grid">${field('本地 IP', 'local_ip_mode', { type: 'select', options: [['wan', 'WAN IP'], ['manual', '手动 IP']] })}${state.draft.local_ip_mode === 'manual' ? field('手动本地 IP', 'local_ip') : ''}${field('远程 IP / 主机名', 'remote_ip')}${field('路由方式', 'routing_mode', { type: 'select', options: [['route', '基于路由'], ['policy', '基于策略']] })}${state.draft.routing_mode === 'route' ? field('隧道 IP', 'tunnel_ip') : field('本地网络', 'local_networks')}${field('远程网络', 'remote_network_mode', { type: 'select', options: [['static', '静态'], ['none', '无']] })}${state.draft.remote_network_mode === 'static' ? field('远程网段', 'remote_networks') : ''}</div>${disclosure('高级', 'IKE、ESP、身份、路由与 MTU', `<div class="vpn-form-grid">${field('IKE 版本', 'ike_version', { type: 'select', options: [['ikev2', 'IKEv2'], ['ikev1', 'IKEv1']] })}${field('IKE 加密', 'ike_encryption', { type: 'select', options: [['aes256', 'AES-256'], ['aes128', 'AES-128']] })}${field('IKE 哈希', 'ike_hash', { type: 'select', options: [['sha256', 'SHA-256'], ['sha1', 'SHA-1']] })}${field('IKE DH 组', 'ike_dh')}${field('IKE 生存期（秒）', 'ike_lifetime', { type: 'number' })}${field('ESP 加密', 'esp_encryption', { type: 'select', options: [['aes256', 'AES-256'], ['aes128', 'AES-128']] })}${field('ESP 哈希', 'esp_hash', { type: 'select', options: [['sha256', 'SHA-256'], ['sha1', 'SHA-1']] })}${field('ESP DH 组', 'esp_dh')}${field('ESP 生存期（秒）', 'esp_lifetime', { type: 'number' })}${field('本地身份 ID', 'local_id')}${field('远程身份 ID', 'remote_id')}${field('路由距离', 'route_distance', { type: 'number' })}${field('MTU', 'mtu', { type: 'number' })}${field('MSS', 'ipv4_mss', { type: 'number' })}</div>${switchField('Perfect Forward Secrecy', 'pfs')}`)}`;
    if (protocol === 'openvpn') return `${common}<div class="vpn-form-grid">${field('本地隧道 IP', 'local_ip')}${field('本地端口', 'local_port', { type: 'number' })}${field('加密算法', 'cipher', { type: 'select', options: [['default', '默认'], ['aes-256-cbc', 'AES-256-CBC'], ['bf-cbc', 'BF-CBC']] })}${field('远程网络', 'remote_networks')}${field('远程 IP', 'remote_ip')}${field('远程隧道 IP', 'remote_tunnel_ip')}${field('远程端口', 'remote_port', { type: 'number' })}</div>${disclosure('高级', 'MTU 与 MSS', `<div class="vpn-form-grid">${field('MTU', 'mtu', { type: 'number' })}${field('MSS', 'ipv4_mss', { type: 'number' })}</div>`)}`;
    return `${common}<div class="vpn-form-grid">${field('本地接口地址', 'local_ip')}${field('远程端点', 'remote_ip')}${field('本地网络', 'local_networks')}${field('远程网络', 'remote_networks')}</div>${disclosure('高级', 'WireGuard 站点参数', `<div class="vpn-form-grid">${field('MTU', 'mtu', { type: 'number' })}${field('MSS', 'ipv4_mss', { type: 'number' })}</div>`)}`;
  }

  function resourceFields(kind) {
    if (kind === 'account') return `<div class="vpn-form-grid">${field('用户名', 'username')}${field('密码', 'password', { type: 'password', autocomplete: 'new-password' })}${field('分组', 'group')}${field('协议权限', 'protocols')}${field('最大并发', 'max_sessions', { type: 'number' })}${field('绑定 VLAN', 'vlan')}${field('有效期', 'expires')}</div>`;
    return `<div class="vpn-form-grid">${field('名称', 'name')}${field('类型', 'type', { type: 'select', options: [['client', '客户端证书'], ['server', '服务器证书'], ['ca', '证书颁发机构']] })}${field('通用名称', 'common_name')}${field('有效天数', 'lifetime_days', { type: 'number' })}</div>`;
  }

  function drawerTitle(kind) {
    return { server: '新建 VPN 服务器', client: '新建 VPN 客户端', site: '新建站点到站点 VPN', account: '管理本地账号', certificate: '管理证书' }[kind] || 'VPN';
  }

  function drawerMarkup() {
    const kind = state.drawer;
    if (!kind) return '';
    const protocolKind = ['server', 'client', 'site'].includes(kind);
    const writable = state.writable[kind] === true;
    const body = kind === 'server' ? serverFields() : kind === 'client' ? clientFields() : kind === 'site' ? siteFields() : resourceFields(kind);
    return `<button class="dwrt-kit-sheet-overlay vpn-sheet-overlay" type="button" data-vpn-action="close" aria-label="关闭 VPN 配置"></button><aside class="dwrt-kit-sheet vpn-config-sheet is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" ${state.drawerSettled ? 'data-dwrt-sheet-motion="settled"' : ''} aria-label="${escapeHtml(drawerTitle(kind))}">
      <header class="dwrt-kit-sheet-header"><div><span>VPN CONFIGURATION</span><strong>${escapeHtml(drawerTitle(kind))}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-vpn-action="close" aria-label="关闭">×</button></header>
      <div class="dwrt-kit-sheet-body vpn-sheet-body">${protocolKind ? protocolChooser(kind) : ''}<div class="vpn-sheet-form">${body}</div>${!writable ? `<div class="vpn-backend-gate">${icon('unplug', 18)}<span><strong>后端写入接口未开放</strong><small>可以核对全部字段和交互；当前不会向不存在的接口发送配置。</small></span></div>` : ''}</div>
      <footer class="dwrt-kit-sheet-footer"><button class="dwrt-kit-button" data-dwrt-component="button" data-variant="ghost" type="button" data-vpn-action="close">取消</button><button class="dwrt-kit-button" data-dwrt-component="async-button" data-variant="primary" type="button" data-vpn-action="save" ${writable && !state.saving ? '' : 'disabled'}>${state.saving ? '正在创建' : writable ? '创建' : '等待后端接口'}</button></footer>
    </aside>`;
  }

  function render() {
    if (!root) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'vpn-config-route-host');
    stage?.classList.add('is-vpn-config');
    root.innerHTML = renderPage();
    ui.mountAll?.(root);
  }

  function updateDraft(target) {
    const key = target.dataset.vpnField;
    if (!key) return;
    state.draft[key] = target.type === 'checkbox' ? target.checked : target.type === 'number' ? (target.value === '' ? '' : Number(target.value)) : target.value;
    if (['server_address_mode', 'listen_mode', 'auth_mode', 'setup_mode', 'local_ip_mode', 'routing_mode', 'remote_network_mode'].includes(key)) render();
  }

  async function save() {
    const kind = state.drawer;
    if (!kind || !state.writable[kind]) return;
    state.saving = true;
    render();
    try {
      const payload = { ...state.draft, protocol: state.protocol || state.draft.protocol, users: state.localUsers, clients: state.localClients };
      await api.request?.(`vpn-${kind}-create`, ENDPOINTS[kind], { method: 'POST', body: payload });
      state.saving = false;
      state.drawer = '';
      state.notice = 'VPN 配置已提交，正在读取权威状态。';
      await load(true);
    } catch (error) {
      state.saving = false;
      state.notice = `创建失败：${firstText(error?.message, '后端未返回原因')}`;
      render();
    }
  }

  function onClick(event) {
    const action = event.target.closest('[data-vpn-action]')?.dataset.vpnAction;
    if (action === 'refresh') { load(true); return; }
    if (action === 'close') { closeDrawer(); return; }
    if (action === 'teleport') return;
    if (action === 'save') { save(); return; }
    if (action?.startsWith('create-')) { openDrawer(action.replace('create-', '')); return; }
    if (action === 'manage-account') { openDrawer('account'); return; }
    if (action === 'manage-certificate') { openDrawer('certificate'); return; }
    const protocol = event.target.closest('[data-vpn-protocol]')?.dataset.vpnProtocol;
    if (protocol) {
      state.protocol = protocol;
      state.draft = defaultDraft(state.drawer, protocol);
      state.localUsers = [];
      state.localClients = [];
      render();
      return;
    }
    const segment = event.target.closest('[data-vpn-segment-field]');
    if (segment) {
      state.draft[segment.dataset.vpnSegmentField] = segment.dataset.dwrtSegment;
      render();
      return;
    }
    if (event.target.closest('[data-vpn-add-user]')) { state.localUsers.push({ username: '', password: '' }); render(); return; }
    if (event.target.closest('[data-vpn-add-client]')) { state.localClients.push({ name: '' }); render(); return; }
    const removeUser = event.target.closest('[data-vpn-remove-user]');
    if (removeUser) { state.localUsers.splice(Number(removeUser.dataset.vpnRemoveUser), 1); render(); return; }
    const removeClient = event.target.closest('[data-vpn-remove-client]');
    if (removeClient) { state.localClients.splice(Number(removeClient.dataset.vpnRemoveClient), 1); render(); return; }
    const row = event.target.closest('[data-vpn-open-item]');
    if (row) {
      const kind = row.dataset.vpnOpenItem;
      const item = state[kind]?.find((candidate) => candidate.id === row.dataset.vpnId);
      if (item) openDrawer(kind, item);
    }
  }

  function onInput(event) {
    const user = event.target.closest('[data-vpn-user]');
    if (user) { state.localUsers[Number(user.dataset.vpnUser)][user.dataset.vpnUserField] = user.value; return; }
    const client = event.target.closest('[data-vpn-client]');
    if (client) { state.localClients[Number(client.dataset.vpnClient)].name = client.value; return; }
    updateDraft(event.target);
  }

  function onChange(event) {
    const file = event.target.closest('[data-vpn-file]');
    if (file) { state.draft[file.dataset.vpnFile] = file.files?.[0]?.name || ''; return; }
    updateDraft(event.target);
  }

  function onDisclosure(event) {
    const disclosure = event.target.closest('.vpn-advanced');
    if (disclosure) state.advanced = event.detail?.open ?? disclosure.querySelector('[aria-expanded]')?.getAttribute('aria-expanded') === 'true';
  }

  root.addEventListener('click', onClick);
  root.addEventListener('input', onInput);
  root.addEventListener('change', onChange);
  root.addEventListener('dwrt-disclosure-change', onDisclosure);
  render();
  load();

  return {
    refresh() { return load(true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      root.removeEventListener('click', onClick);
      root.removeEventListener('input', onInput);
      root.removeEventListener('change', onChange);
      root.removeEventListener('dwrt-disclosure-change', onDisclosure);
      window.DWRT_UI_KIT?.unmount?.(root);
      root.replaceChildren();
      root.classList.remove('route-workspace', 'vpn-config-route-host');
      stage?.classList.remove('is-vpn-config');
    }
  };
}

export default { mount };
