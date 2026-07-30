export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));
  const VERSION = '20260711-01';
  const MODULE_CLASS = 'quick-tools-route-host';
  const ASSET_ROOT = '/static/toolkit';

  const TOOLS = [
    { id: 'router-check', title: '路由体检', description: '集中检查路由器资源、上联与关键网络服务，快速定位影响联网体验的异常。', image: 'router-check.svg' },
    { id: 'health-check', title: '健康检测', description: '查看系统负载、温度、内存和存储状态，识别持续运行中的健康风险。', image: 'health-check.svg' },
    { id: 'packet-capture', title: '抓包工具', description: '按接口、主机和协议采集网关流量，生成可下载的 PCAP 文件用于进一步分析。', image: 'packet-capture.svg' },
    { id: 'flow-table', title: '流表查看', description: '检查当前连接的五元组、方向、状态与流量，追踪终端正在建立的网络会话。', image: 'flow-table.svg' },
    { id: 'ping', title: 'Ping 测试', description: '从指定出口探测目标的可达性、往返延迟与丢包情况。', image: 'ping.svg' },
    { id: 'traceroute', title: '路由追踪', description: '逐跳显示到目标地址的转发路径和响应时间，辅助定位链路故障位置。', image: 'traceroute.svg' },
    { id: 'port-mirror', title: '端口镜像', description: '将选定接口的流量复制到监测端口，供旁路分析设备持续观察。', image: 'port-mirror.svg' },
    { id: 'ddns', title: '动态域名', description: '维护公网地址与域名记录的同步状态，让动态线路拥有稳定访问入口。', image: 'ddns.svg' },
    { id: 'wake-on-lan', title: '网络唤醒', description: '向局域网设备发送 Magic Packet，远程唤醒支持 WOL 的主机。', image: 'wake-on-lan.svg' },
    { id: 'throughput', title: '吞吐测试', description: '在网关与测试端之间测量实际传输能力，评估局域网或指定链路性能。', image: 'throughput.svg' },
    { id: 'speedtest', title: '线路测速', description: '测试所选 WAN 的下载、上传和时延，核对运营商线路的实际表现。', image: 'speedtest.svg' },
    { id: 'subnet', title: '子网换算', description: '根据 IPv4 地址和前缀计算网络地址、广播地址、掩码与可用主机范围。', image: 'subnet-calculator.svg' }
  ];

  const state = { mounted: true, active: '', busy: false, notice: '', result: null, captures: [], flows: [], health: null, wans: [], seq: 0 };

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

  function unwrap(value) {
    let current = value?.data ?? value ?? {};
    for (let index = 0; index < 3; index += 1) {
      if (!current || typeof current !== 'object' || Array.isArray(current) || !current.data || typeof current.data !== 'object') break;
      current = current.data;
    }
    return current || {};
  }

  function asArray(value, keys = []) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of [...keys, 'items', 'rows', 'data']) if (Array.isArray(value[key])) return value[key];
    return [];
  }

  function authHeaders(extra = {}) {
    let token = '';
    try { token = localStorage.getItem('dreamingwrt.web.accessToken') || ''; } catch (_) {}
    return { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}), ...extra };
  }

  async function requestJson(url, options = {}) {
    const response = await fetch(`${url}${url.includes('?') ? '&' : '?'}v=${encodeURIComponent(VERSION)}`, {
      credentials: 'same-origin', cache: 'no-store', ...options,
      headers: authHeaders({ Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    try { json = text ? JSON.parse(text) : {}; } catch (_) { throw new Error('后端返回了无效 JSON'); }
    if (!response.ok || json?.ok === false) {
      const error = new Error(firstText(json?.error?.message, json?.message, json?.error, `${response.status}`));
      error.status = response.status;
      throw error;
    }
    return unwrap(json);
  }

  function icon(name) {
    const paths = {
      back: '<path d="m15 18-6-6 6-6"></path>',
      play: '<path d="m8 5 11 7-11 7V5Z"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      download: '<path d="M12 4v12m0 0 4-4m-4 4-4-4"></path><path d="M5 20h14"></path>',
      stop: '<rect x="7" y="7" width="10" height="10" rx="1"></rect>'
    };
    return `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.play}</svg>`;
  }

  function toolCards() {
    return `<section class="quick-tools-grid" aria-label="快捷工具">${TOOLS.map((tool) => `<button class="quick-tool-card policy-stable-glass" type="button" data-quick-tool="${tool.id}">
      <span class="quick-tool-copy"><strong>${escapeHtml(tool.title)}</strong><small>${escapeHtml(tool.description)}</small></span>
      <img src="${ASSET_ROOT}/${tool.image}" alt="" loading="eager">
    </button>`).join('')}</section>`;
  }

  function field(label, input) { return `<label class="quick-tool-field"><span>${escapeHtml(label)}</span>${input}</label>`; }
  function textInput(name, value, placeholder = '') { return `<input name="${name}" value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}" autocomplete="off">`; }
  function numberInput(name, value, min, max) { return `<input name="${name}" type="number" value="${value}" min="${min}" max="${max}">`; }
  function wanOptions() { return `<option value="">自动选择</option>${state.wans.map((wan) => `<option value="${escapeHtml(firstText(wan.ifname, wan.interface, wan.id))}">${escapeHtml(firstText(wan.name, wan.label, wan.ifname, wan.id))}</option>`).join('')}`; }

  function resultMarkup() {
    if (state.busy) return '<div class="quick-tool-empty"><span class="quick-tool-spinner"></span><strong>正在执行</strong><small>等待路由器返回真实结果</small></div>';
    if (state.notice) return `<div class="quick-tool-empty is-warning"><strong>${escapeHtml(state.notice)}</strong><small>未使用模拟数据填充结果。</small></div>`;
    if (!state.result) return '<div class="quick-tool-empty"><strong>等待执行</strong><small>填写参数后开始测试。</small></div>';
    const value = state.result;
    if (typeof value === 'string') return `<pre class="quick-tool-console">${escapeHtml(value)}</pre>`;
    const rows = Object.entries(value).filter(([, item]) => item !== undefined && item !== null && typeof item !== 'object').slice(0, 30);
    const raw = value.output || value.stdout || value.result || value.message;
    return `${raw ? `<pre class="quick-tool-console">${escapeHtml(raw)}</pre>` : ''}<dl class="quick-tool-result-list">${rows.map(([key, item]) => `<div><dt>${escapeHtml(key.replace(/_/g, ' '))}</dt><dd>${escapeHtml(item)}</dd></div>`).join('')}</dl>`;
  }

  function diagnosticsPanel(tool) {
    const traceroute = tool.id === 'traceroute';
    const speedtest = tool.id === 'speedtest';
    return `<form class="quick-tool-form" data-tool-form="${tool.id}">
      <div class="quick-tool-fields">
        ${speedtest ? field('线路', `<select name="ifname">${wanOptions()}</select>`) : field('目标地址', textInput('target', '1.1.1.1', 'IP 或域名'))}
        ${traceroute ? field('最大跳数', numberInput('max_hops', 30, 1, 64)) : ''}
        ${tool.id === 'ping' ? field('请求次数', numberInput('count', 4, 1, 20)) : ''}
      </div>
      <button class="policy-primary quick-tool-run" type="submit">${icon('play')}<span>${speedtest ? '开始测速' : traceroute ? '开始追踪' : '开始测试'}</span></button>
    </form><section class="quick-tool-result policy-stable-glass">${resultMarkup()}</section>`;
  }

  function healthPanel(tool) {
    const checks = tool.id === 'router-check'
      ? ['存储状态', '内存状态', '线路连通', 'DHCP 服务', 'PPPoE 服务', '网关冲突', '核心服务']
      : ['CPU 负载', '内存占用', '存储空间', '设备温度', '系统运行时间', '关键服务'];
    return `<section class="quick-tool-checks policy-stable-glass">${checks.map((check) => `<div><span>${escapeHtml(check)}</span><em>${state.health ? '已读取' : '等待检测'}</em></div>`).join('')}</section>
      <button class="policy-primary quick-tool-run" type="button" data-tool-health>${icon('play')}<span>开始检测</span></button>
      <section class="quick-tool-result policy-stable-glass">${resultMarkup()}</section>`;
  }

  function capturePanel() {
    return `<form class="quick-tool-form" data-tool-form="packet-capture"><div class="quick-tool-fields">
      ${field('接口', textInput('ifname', 'any', 'any / eth0 / br-lan'))}
      ${field('主机', textInput('host', '', '可选 IP 或域名'))}
      ${field('协议', '<select name="protocol"><option value="">全部</option><option>tcp</option><option>udp</option><option>icmp</option><option>arp</option></select>')}
      ${field('端口', numberInput('port', 0, 0, 65535))}
      ${field('持续时间', numberInput('duration_s', 20, 1, 300))}
      ${field('数据包上限', numberInput('packet_count', 1000, 1, 100000))}
    </div><button class="policy-primary quick-tool-run" type="submit">${icon('play')}<span>开始抓包</span></button></form>
    <section class="quick-tool-result policy-stable-glass">${resultMarkup()}</section>${captureTable()}`;
  }

  function captureTable() {
    return `<section class="quick-tool-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap policy-stable-glass"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>抓包任务</strong><span>网关本地 PCAP</span></div><button class="quick-tool-icon-button" data-capture-refresh type="button" title="刷新">${icon('refresh')}</button></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table"><thead><tr><th>任务</th><th>接口</th><th>状态</th><th>大小</th><th>操作</th></tr></thead><tbody>${state.captures.length ? state.captures.map((item) => `<tr><td>${escapeHtml(firstText(item.id, '--'))}</td><td>${escapeHtml(firstText(item.ifname, '--'))}</td><td>${escapeHtml(firstText(item.state, item.status, '--'))}</td><td>${escapeHtml(formatBytes(item.size_bytes))}</td><td><div class="quick-tool-row-actions">${item.running ? `<button data-capture-stop="${escapeHtml(item.id)}" type="button" title="停止">${icon('stop')}</button>` : ''}${item.download_available || item.download_url ? `<a href="${escapeHtml(item.download_url || `/api/v1/topology/capture/download?id=${encodeURIComponent(item.id)}`)}" title="下载">${icon('download')}</a>` : ''}</div></td></tr>`).join('') : '<tr><td colspan="5" class="dwrt-kit-table-empty">暂无抓包任务</td></tr>'}</tbody></table></div></section>`;
  }

  function flowPanel() {
    return `<div class="quick-tool-flow-toolbar"><button class="policy-filter-button" type="button" data-flow-refresh>${icon('refresh')}<span>刷新流表</span></button></div><section class="quick-tool-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap policy-stable-glass"><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table"><thead><tr><th>协议</th><th>源</th><th>目标</th><th>状态</th><th>流量</th></tr></thead><tbody>${state.flows.length ? state.flows.slice(0, 500).map((item) => `<tr><td>${escapeHtml(firstText(item.protocol, item.proto, '--'))}</td><td>${escapeHtml(endpoint(item, 'source'))}</td><td>${escapeHtml(endpoint(item, 'destination'))}</td><td>${escapeHtml(firstText(item.state, item.status, item.direction, '--'))}</td><td>${escapeHtml(formatBytes(Number(item.bytes) || Number(item.total_bytes) || 0))}</td></tr>`).join('') : '<tr><td colspan="5" class="dwrt-kit-table-empty">点击刷新读取当前真实连接</td></tr>'}</tbody></table></div></section>`;
  }

  function contractPanel(tool) {
    const configs = {
      'port-mirror': [['源接口', textInput('source_ifname', '', '例如 eth0')], ['监测接口', textInput('target_ifname', '', '例如 eth2')], ['方向', '<select name="direction"><option value="both">双向</option><option value="ingress">入站</option><option value="egress">出站</option></select>']],
      ddns: [['服务商', '<select name="provider"><option value="cloudflare">Cloudflare</option><option value="aliyun">阿里云</option><option value="dnspod">DNSPod</option><option value="custom">自定义</option></select>'], ['域名', textInput('hostname', '', 'router.example.com')], ['线路', `<select name="ifname">${wanOptions()}</select>`]],
      'wake-on-lan': [['MAC 地址', textInput('mac', '', 'AA:BB:CC:DD:EE:FF')], ['广播地址', textInput('broadcast', '255.255.255.255')], ['接口', textInput('ifname', 'br-lan')]],
      throughput: [['模式', '<select name="mode"><option value="client">客户端</option><option value="server">服务端</option></select>'], ['测试端', textInput('host', '', 'IP 或域名')], ['端口', numberInput('port', 5201, 1, 65535)], ['持续时间', numberInput('duration_s', 10, 1, 300)]]
    };
    return `<form class="quick-tool-form" data-tool-form="${tool.id}"><div class="quick-tool-fields">${(configs[tool.id] || []).map(([label, control]) => field(label, control)).join('')}</div><button class="policy-primary quick-tool-run" type="submit">${icon('play')}<span>${tool.id === 'wake-on-lan' ? '发送唤醒' : tool.id === 'ddns' ? '立即更新' : '开始执行'}</span></button></form><section class="quick-tool-result policy-stable-glass">${resultMarkup()}</section>`;
  }

  function subnetPanel() {
    return `<form class="quick-tool-form" data-tool-form="subnet"><div class="quick-tool-fields">${field('IPv4 地址', textInput('address', '192.168.1.1', '例如 192.168.1.1'))}${field('前缀长度', numberInput('prefix', 24, 0, 32))}</div><button class="policy-primary quick-tool-run" type="submit">${icon('play')}<span>开始换算</span></button></form><section class="quick-tool-result policy-stable-glass">${resultMarkup()}</section>`;
  }

  function formatBytes(value) {
    let bytes = Number(value) || 0;
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let index = 0;
    while (bytes >= 1024 && index < units.length - 1) { bytes /= 1024; index += 1; }
    return `${bytes.toFixed(bytes >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
  }

  function endpoint(item, side) {
    const source = side === 'source';
    const address = firstText(source ? item.source_ip : item.destination_ip, source ? item.src_ip : item.dst_ip, source ? item.local_ip : item.remote_ip, '--');
    const port = Number(source ? item.source_port || item.src_port : item.destination_port || item.dst_port) || 0;
    return port ? `${address}:${port}` : address;
  }

  function panelMarkup(tool) {
    if (['ping', 'traceroute', 'speedtest'].includes(tool.id)) return diagnosticsPanel(tool);
    if (['router-check', 'health-check'].includes(tool.id)) return healthPanel(tool);
    if (tool.id === 'packet-capture') return capturePanel();
    if (tool.id === 'flow-table') return flowPanel();
    if (tool.id === 'subnet') return subnetPanel();
    return contractPanel(tool);
  }

  function detailMarkup(tool) {
    return `<section class="quick-tool-workspace"><header class="quick-tool-header"><button class="quick-tool-back" type="button" data-tool-back aria-label="返回快捷工具">${icon('back')}</button><div><span>快捷工具</span><strong>${escapeHtml(tool.title)}</strong><p>${escapeHtml(tool.description)}</p></div><img src="${ASSET_ROOT}/${tool.image}" alt=""></header><main class="quick-tool-body">${panelMarkup(tool)}</main></section>`;
  }

  function render() {
    if (!root || !state.mounted) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'policy-table-route-host', MODULE_CLASS);
    const tool = TOOLS.find((item) => item.id === state.active);
    root.innerHTML = tool ? detailMarkup(tool) : toolCards();
    bindEvents();
    ui.mountAll?.(root);
    ui.scheduleGlassCardsRender?.(100);
  }

  function formPayload(form) {
    const payload = {};
    Array.from(form.elements).forEach((field) => {
      if (!field.name) return;
      payload[field.name] = field.type === 'number' ? Number(field.value) : field.value.trim();
    });
    return payload;
  }

  function calculateSubnet(address, prefix) {
    const parts = String(address).split('.').map(Number);
    if (parts.length !== 4 || parts.some((item) => !Number.isInteger(item) || item < 0 || item > 255)) throw new Error('请输入有效 IPv4 地址');
    const bits = Number(prefix);
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) throw new Error('前缀长度必须为 0-32');
    const ip = parts.reduce((value, part) => ((value << 8) | part) >>> 0, 0);
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const network = (ip & mask) >>> 0;
    const broadcast = (network | (~mask >>> 0)) >>> 0;
    const format = (value) => [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join('.');
    const total = 2 ** (32 - bits);
    return { address: format(ip), prefix: `/${bits}`, netmask: format(mask), wildcard: format(~mask >>> 0), network: format(network), broadcast: format(broadcast), first_host: bits >= 31 ? format(network) : format((network + 1) >>> 0), last_host: bits >= 31 ? format(broadcast) : format((broadcast - 1) >>> 0), total_addresses: total, usable_hosts: bits >= 31 ? total : Math.max(0, total - 2) };
  }

  async function runTool(form) {
    const id = form.dataset.toolForm;
    const payload = formPayload(form);
    state.busy = true; state.notice = ''; state.result = null; render();
    try {
      if (id === 'subnet') state.result = calculateSubnet(payload.address, payload.prefix);
      else {
        const endpoints = { ping: '/api/v1/diagnostics/ping', traceroute: '/api/v1/diagnostics/traceroute', speedtest: '/api/v1/diagnostics/speedtest', 'packet-capture': '/api/v1/topology/capture', 'port-mirror': '/api/v1/toolkit/port-mirror', ddns: '/api/v1/toolkit/ddns/update', 'wake-on-lan': '/api/v1/toolkit/wake-on-lan', throughput: '/api/v1/toolkit/throughput' };
        if (id === 'packet-capture') payload.action = 'start';
        state.result = await requestJson(endpoints[id], { method: 'POST', body: JSON.stringify(payload) });
        if (id === 'packet-capture') await loadCaptures(false);
      }
    } catch (error) {
      state.notice = [404, 405, 501].includes(Number(error.status)) ? '该工具的后端能力尚未接入' : `执行失败：${firstText(error.message, 'unknown')}`;
    } finally { state.busy = false; render(); }
  }

  async function loadHealth() {
    state.busy = true; state.notice = ''; state.result = null; render();
    try {
      const endpoint = state.active === 'router-check' ? '/api/v1/toolkit/router-check' : '/api/v1/system/health';
      state.health = await requestJson(endpoint);
      state.result = state.health;
    } catch (error) {
      if (state.active === 'router-check' && Number(error.status) === 404) {
        try { state.health = await requestJson('/api/v1/system/health'); state.result = state.health; }
        catch (fallback) { state.notice = `检测失败：${firstText(fallback.message, error.message)}`; }
      } else state.notice = [404, 405, 501].includes(Number(error.status)) ? '该工具的后端能力尚未接入' : `检测失败：${firstText(error.message)}`;
    } finally { state.busy = false; render(); }
  }

  async function loadCaptures(redraw = true) {
    try {
      const data = await requestJson('/api/v1/topology/capture/status');
      state.captures = asArray(data, ['captures', 'tasks', 'jobs']);
    } catch (error) { state.notice = `抓包任务读取失败：${firstText(error.message)}`; }
    if (redraw) render();
  }

  async function loadFlows() {
    state.busy = true; state.notice = ''; render();
    try {
      const data = await requestJson('/api/v1/insights/flows/current');
      state.flows = asArray(data, ['flows', 'connections', 'items']);
    } catch (error) { state.notice = `流表读取失败：${firstText(error.message)}`; }
    finally { state.busy = false; render(); }
  }

  async function stopCapture(id) {
    try { await requestJson('/api/v1/topology/capture/stop', { method: 'POST', body: JSON.stringify({ id, action: 'stop' }) }); await loadCaptures(); }
    catch (error) { state.notice = `停止失败：${firstText(error.message)}`; render(); }
  }

  function bindEvents() {
    root.querySelectorAll('[data-quick-tool]').forEach((button) => button.addEventListener('click', () => {
      state.active = button.dataset.quickTool; state.result = null; state.notice = ''; render();
      if (state.active === 'packet-capture') loadCaptures();
      if (state.active === 'flow-table') loadFlows();
    }));
    root.querySelector('[data-tool-back]')?.addEventListener('click', () => { state.active = ''; state.result = null; state.notice = ''; render(); });
    root.querySelectorAll('[data-tool-form]').forEach((form) => form.addEventListener('submit', (event) => { event.preventDefault(); runTool(form); }));
    root.querySelector('[data-tool-health]')?.addEventListener('click', loadHealth);
    root.querySelector('[data-capture-refresh]')?.addEventListener('click', () => loadCaptures());
    root.querySelector('[data-flow-refresh]')?.addEventListener('click', loadFlows);
    root.querySelectorAll('[data-capture-stop]').forEach((button) => button.addEventListener('click', () => stopCapture(button.dataset.captureStop)));
  }

  async function loadWans() {
    try { const data = await requestJson('/api/v1/network/wans'); state.wans = asArray(data, ['wans', 'interfaces']); } catch (_) {}
  }

  render();
  loadWans();
  return { unmount() { state.mounted = false; state.seq += 1; root?.replaceChildren(); root?.classList.remove(MODULE_CLASS, 'policy-table-route-host', 'route-workspace'); } };
}

export default { mount };
