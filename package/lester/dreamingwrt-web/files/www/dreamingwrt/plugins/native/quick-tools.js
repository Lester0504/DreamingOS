export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));
  const VERSION = '20260802-ui-batch-01';
  const MODULE_CLASS = 'quick-tools-route-host';
  const ASSET_ROOT = '/static/toolkit';
  /* ubus ping is asynchronous: the first call returns latency 0 / loss 100 with
     pending:true while the probe is still running. Rendering that verbatim reads
     as "target unreachable", so the result is polled until has_result flips. */
  const ASYNC_POLL_INTERVAL_MS = 1000;
  const ASYNC_POLL_TIMEOUT_MS = 15000;
  const THROUGHPUT_POLL_INTERVAL_MS = 1000;

  const TOOLS = [
    { id: 'router-check', title: '路由体检', description: '集中检查路由器资源、上联与关键网络服务，快速定位影响联网体验的异常。', image: 'router-check.svg' },
    { id: 'health-check', title: '健康检测', description: '查看系统负载、温度、内存和存储状态，识别持续运行中的健康风险。', image: 'health-check.svg' },
    { id: 'packet-capture', title: '抓包工具', description: '按接口、主机和协议采集网关流量，生成可下载的 PCAP 文件用于进一步分析。', image: 'packet-capture.svg' },
    { id: 'flow-table', title: '流表查看', description: '检查当前连接的五元组、方向、状态与流量，追踪终端正在建立的网络会话。', image: 'flow-table.svg' },
    { id: 'ping', title: 'Ping 测试', description: '从指定出口探测目标的可达性、往返延迟与丢包情况。', image: 'ping.svg' },
    { id: 'traceroute', title: '路由追踪', description: '逐跳显示到目标地址的转发路径和响应时间，辅助定位链路故障位置。', image: 'traceroute.svg' },
    { id: 'nslookup', title: 'DNS 查询', description: '按指定解析器查询域名的 A 与 AAAA 记录，核对解析结果与响应来源。', image: 'dns-lookup.svg' },
    { id: 'port-mirror', title: '端口镜像', description: '将选定接口的流量复制到监测端口，供旁路分析设备持续观察。', image: 'port-mirror.svg' },
    { id: 'ddns', title: '动态域名', description: '维护公网地址与域名记录的同步状态，让动态线路拥有稳定访问入口。', image: 'ddns.svg' },
    { id: 'wake-on-lan', title: '网络唤醒', description: '向局域网设备发送 Magic Packet，远程唤醒支持 WOL 的主机。', image: 'wake-on-lan.svg' },
    { id: 'throughput', title: '吞吐测试', description: '在网关与测试端之间测量实际传输能力，评估局域网或指定链路性能。', image: 'throughput.svg' },
    { id: 'speedtest', title: '线路测速', description: '测试所选 WAN 的下载、上传和时延，核对运营商线路的实际表现。', image: 'speedtest.svg' },
    { id: 'subnet', title: '子网换算', description: '根据 IPv4 地址和前缀计算网络地址、广播地址、掩码与可用主机范围。', image: 'subnet-calculator.svg' }
  ];

  const state = {
    mounted: true, active: '', busy: false, notice: '', result: null,
    captures: [], flows: [], health: null, wans: [], seq: 0,
    progress: '', throughput: null, timers: [], pollTimer: 0
  };

  /*
   * 三个手动刷新按钮（抓包任务、流表、吞吐进度）按用户第 9 条删除。
   * 这三张表都是运行态视图，所以按当前工具自动轮询：抓包与流表 8s，
   * 吞吐任务只在 running 时跟进。busy 期间跳过，避免和用户触发的动作互相打断。
   */
  function pollActive() {
    if (!state.mounted || document.hidden || state.busy) return;
    if (state.active === 'packet-capture') { loadCaptures(); return; }
    if (state.active === 'flow-table') { loadFlows(true); return; }
    if (throughputRunning()) refreshThroughput(true);
  }

  function startPolling() {
    stopPolling();
    state.pollTimer = window.setInterval(pollActive, 8000);
  }

  function stopPolling() {
    if (!state.pollTimer) return;
    window.clearInterval(state.pollTimer);
    state.pollTimer = 0;
  }

  function clearTimers() {
    state.timers.forEach((id) => window.clearTimeout(id));
    state.timers = [];
  }

  function sleep(ms) {
    return new Promise((resolve) => { state.timers.push(window.setTimeout(resolve, ms)); });
  }

  // Every async flow captures state.seq first and re-checks it after each await,
  // so a response for a tool the user already left can never paint over the new one.
  function stale(seq) {
    return !state.mounted || seq !== state.seq;
  }

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
    return { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}), ...extra };
  }

  async function requestJson(url, options = {}) {
    const response = await sessionFetch(`${url}${url.includes('?') ? '&' : '?'}v=${encodeURIComponent(VERSION)}`, {
      credentials: 'same-origin', cache: 'no-store', ...options,
      headers: authHeaders({ Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    try { json = text ? JSON.parse(text) : {}; } catch (_) { throw new Error('后端返回了无效 JSON'); }
    if (!response.ok || json?.ok === false) {
      const error = new Error(firstText(json?.error?.message, json?.message, json?.error, `${response.status}`));
      error.status = response.status;
      // The backend distinguishes "method never registered on this build" from a
      // transient failure. Keep the code so the UI can say "not wired up yet"
      // instead of blaming the network.
      error.code = firstText(json?.error?.code, json?.code);
      // Diagnostics report "resolved to nothing" as ok:false with the real data
      // still attached, so the payload travels with the error and the caller can
      // tell an empty-but-valid answer apart from a broken call.
      error.payload = unwrap(json);
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
    if (state.busy) return `<div class="quick-tool-empty"><span class="quick-tool-spinner"></span><strong>正在执行</strong><small>${escapeHtml(state.progress || '等待路由器返回真实结果')}</small></div>`;
    if (state.notice) return `<div class="quick-tool-empty is-warning"><strong>${escapeHtml(state.notice)}</strong><small>未使用模拟数据填充结果。</small></div>`;
    if (!state.result) return '<div class="quick-tool-empty"><strong>等待执行</strong><small>填写参数后开始测试。</small></div>';
    const value = state.result;
    if (typeof value === 'string') return `<pre class="quick-tool-console">${escapeHtml(value)}</pre>`;
    const owned = TABLE_OWNED_KEYS[state.active] || [];
    const rows = Object.entries(value)
      .filter(([key, item]) => item !== undefined && item !== null && typeof item !== 'object' && !owned.includes(key))
      .slice(0, 30);
    // Only strings belong in the console block. throughput/status returns an
    // object under `result` (iperf3 JSON), which used to render as [object Object].
    const rawCandidate = [value.output, value.stdout, value.result, value.message].find((item) => typeof item === 'string' && item.trim());
    const structured = value.result && typeof value.result === 'object' ? JSON.stringify(value.result, null, 2) : '';
    const raw = rawCandidate || structured;
    return `${raw ? `<pre class="quick-tool-console">${escapeHtml(raw)}</pre>` : ''}<dl class="quick-tool-result-list">${rows.map(([key, item]) => `<div><dt>${escapeHtml(resultLabel(key))}</dt><dd>${escapeHtml(formatResultValue(key, item))}</dd></div>`).join('')}</dl>`;
  }

  // The backend already classifies ping quality (195ms -> "bad"); mirroring its
  // wording beats re-deriving a verdict from the latency number in the UI.
  const PING_STATUS_LABELS = { good: '良好', ok: '正常', warn: '偏差', bad: '较差', pending: '探测中', fail: '失败' };

  /* Raw backend keys read as debug output ("Ts", "Max Hops", "Ifname"), so the
     summary list gets Chinese labels. Keys the tables already carry are dropped
     instead of repeated next to them. */
  const RESULT_LABELS = {
    ts: '采样时间', result_ts: '结果时间', target: '目标', host: '主机', latency: '延迟', loss: '丢包率',
    status: '判定', ok: '成功', available: '能力可用', ifname: '出口接口', resolver: '解析器',
    max_hops: '最大跳数', hop_count: '跳数', reached: '已到达目标', answer_count: '记录数',
    timed_out: '超时', truncated: '输出被截断', exit_code: '退出码', error: '错误',
    stale: '数据过期', refreshing: '正在刷新', pending: '等待结果', has_result: '已有结果', async: '异步执行',
    id: '任务 ID', pid: '进程号', mode: '模式', port: '端口', duration_s: '持续秒数',
    started_at: '开始时间', stopped_at: '停止时间', state: '状态', reason: '原因', bytes_sent: '已发送字节'
  };
  // The hop and answer tables state these in their own header.
  const TABLE_OWNED_KEYS = { traceroute: ['hop_count', 'reached', 'truncated'], nslookup: ['answer_count', 'resolver'] };

  function resultLabel(key) {
    return RESULT_LABELS[key] || key.replace(/_/g, ' ');
  }

  function formatResultValue(key, item) {
    if (key === 'status' && PING_STATUS_LABELS[String(item)]) return `${PING_STATUS_LABELS[String(item)]}（${item}）`;
    if ((key === 'ts' || key === 'result_ts' || key === 'started_at' || key === 'stopped_at') && Number(item) > 1e9) {
      return new Date(Number(item) * 1000).toLocaleString('zh-CN', { hour12: false });
    }
    if (key === 'loss') return `${item}%`;
    if (key === 'latency') return `${item} ms`;
    if (typeof item === 'boolean') return item ? '是' : '否';
    return item;
  }

  function diagnosticsPanel(tool) {
    const traceroute = tool.id === 'traceroute';
    const speedtest = tool.id === 'speedtest';
    const nslookup = tool.id === 'nslookup';
    const runLabel = speedtest ? '开始测速' : traceroute ? '开始追踪' : nslookup ? '开始查询' : '开始测试';
    /* Speedtest is a deliberate backend hold, not an oversight: a real run
       saturates the uplink for everyone on the network, so it waits on the
       user's call. Saying that up front beats letting them click into a 501. */
    const pending = speedtest ? '<p class="quick-tool-pending" data-tool-pending>真实测速会占满上行带宽、影响正在用网的设备，后端因此暂未开启该能力。点击执行会如实返回“尚未接入”，不会给出估算数据。</p>' : '';
    return `${pending}<form class="quick-tool-form" data-tool-form="${tool.id}">
      <div class="quick-tool-fields">
        ${speedtest ? field('线路', `<select name="ifname">${wanOptions()}</select>`) : field(nslookup ? '域名' : '目标地址', textInput('target', nslookup ? 'www.apple.com' : '1.1.1.1', nslookup ? '域名，如 www.apple.com' : 'IP 或域名'))}
        ${traceroute ? field('最大跳数', numberInput('max_hops', 30, 1, 64)) : ''}
        ${nslookup ? field('解析器', textInput('server', '', '留空使用系统解析器')) : ''}
      </div>
      <button class="policy-primary quick-tool-run" type="submit">${icon('play')}<span>${runLabel}</span></button>
    </form><section class="quick-tool-result policy-stable-glass">${resultMarkup()}</section>${traceroute ? hopTable() : ''}${nslookup ? answerTable() : ''}`;
  }

  /* traceroute answers with an array of hop objects and nslookup with an array of
     records. The generic key/value renderer drops objects, so both get a real
     table. A hop that times out is read from `timeout`, never from an empty
     address: some hops answer without giving up a name. */
  function hopTable() {
    const hops = asArray(state.result?.hops);
    const reached = state.result && typeof state.result.reached === 'boolean' ? state.result.reached : null;
    const truncated = state.result?.truncated === true;
    return `<section class="quick-tool-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap policy-stable-glass" data-hop-table>
      <div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>转发路径</strong><span>${hops.length ? `${hops.length} 跳${reached === null ? '' : reached ? ' · 已到达目标' : ' · 未到达目标'}${truncated ? ' · 输出被截断' : ''}` : '等待追踪结果'}</span></div></div>
      <div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table"><thead><tr><th>跳</th><th>主机</th><th>地址</th><th>往返时延</th><th>状态</th></tr></thead><tbody>${hops.length ? hops.map((hop) => {
        const rtt = asArray(hop?.rtt_ms).map((value) => `${Number(value).toFixed(1)} ms`).join(' / ');
        const timeout = hop?.timeout === true;
        const label = timeout ? '超时' : hop?.responded === false ? '无响应' : '已响应';
        const lost = Number(hop?.probes_lost) || 0;
        return `<tr><td>${escapeHtml(String(hop?.hop ?? '--'))}</td><td>${escapeHtml(firstText(hop?.host, '--'))}</td><td>${escapeHtml(firstText(hop?.address, '--'))}</td><td>${escapeHtml(rtt || '--')}</td><td>${escapeHtml(lost ? `${label}（丢失 ${lost}）` : label)}</td></tr>`;
      }).join('') : '<tr><td colspan="5" class="dwrt-kit-table-empty">填写目标后开始追踪</td></tr>'}</tbody></table></div>
    </section>`;
  }

  function answerTable() {
    const answers = asArray(state.result?.answers);
    const resolver = firstText(state.result?.resolver);
    return `<section class="quick-tool-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap policy-stable-glass" data-answer-table>
      <div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>解析记录</strong><span>${answers.length ? `${answers.length} 条${resolver ? ` · 解析器 ${escapeHtml(resolver)}` : ''}` : '等待查询结果'}</span></div></div>
      <div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table"><thead><tr><th>名称</th><th>地址</th><th>类型</th></tr></thead><tbody>${answers.length ? answers.map((item) => `<tr><td>${escapeHtml(firstText(item?.name, '--'))}</td><td>${escapeHtml(firstText(item?.address, '--'))}</td><td>${escapeHtml(firstText(item?.type, '--'))}</td></tr>`).join('') : '<tr><td colspan="3" class="dwrt-kit-table-empty">填写域名后开始查询</td></tr>'}</tbody></table></div>
    </section>`;
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
    return `<section class="quick-tool-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap policy-stable-glass"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>抓包任务</strong><span>网关本地 PCAP</span></div><span class="dwrt-kit-table-count">${state.captures.length} 个任务</span></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table"><thead><tr><th>任务</th><th>接口</th><th>状态</th><th>大小</th><th>操作</th></tr></thead><tbody>${state.captures.length ? state.captures.map((item) => `<tr><td>${escapeHtml(firstText(item.id, '--'))}</td><td>${escapeHtml(firstText(item.ifname, '--'))}</td><td>${escapeHtml(firstText(item.state, item.status, '--'))}</td><td>${escapeHtml(formatBytes(item.size_bytes))}</td><td><div class="quick-tool-row-actions">${item.running ? `<button data-capture-stop="${escapeHtml(item.id)}" type="button" title="停止">${icon('stop')}</button>` : ''}${item.download_available || item.download_url ? `<a href="${escapeHtml(item.download_url || `/api/v1/topology/capture/download?id=${encodeURIComponent(item.id)}`)}" title="下载">${icon('download')}</a>` : ''}</div></td></tr>`).join('') : '<tr><td colspan="5" class="dwrt-kit-table-empty">暂无抓包任务</td></tr>'}</tbody></table></div></section>`;
  }

  function flowPanel() {
    return `<section class="quick-tool-table dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap policy-stable-glass"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>实时流表</strong><span>网关活动连接</span></div><span class="dwrt-kit-table-count">${state.flows.length} 条</span></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table"><thead><tr><th>协议</th><th>源</th><th>目标</th><th>状态</th><th>流量</th></tr></thead><tbody>${state.flows.length ? state.flows.slice(0, 500).map((item) => `<tr><td>${escapeHtml(firstText(item.protocol, item.proto, '--'))}</td><td>${escapeHtml(endpoint(item, 'source'))}</td><td>${escapeHtml(endpoint(item, 'destination'))}</td><td>${escapeHtml(firstText(item.state, item.status, item.direction, '--'))}</td><td>${escapeHtml(formatBytes(Number(item.bytes) || Number(item.total_bytes) || 0))}</td></tr>`).join('') : '<tr><td colspan="5" class="dwrt-kit-table-empty">点击刷新读取当前真实连接</td></tr>'}</tbody></table></div></section>`;
  }

  function contractPanel(tool) {
    const configs = {
      'port-mirror': [['源接口', textInput('source_ifname', '', '例如 eth0')], ['监测接口', textInput('target_ifname', '', '例如 eth2')], ['方向', '<select name="direction"><option value="both">双向</option><option value="ingress">入站</option><option value="egress">出站</option></select>']],
      ddns: [['服务商', '<select name="provider"><option value="cloudflare">Cloudflare</option><option value="aliyun">阿里云</option><option value="dnspod">DNSPod</option><option value="custom">自定义</option></select>'], ['域名', textInput('hostname', '', 'router.example.com')], ['线路', `<select name="ifname">${wanOptions()}</select>`]],
      'wake-on-lan': [['MAC 地址', textInput('mac', '', 'AA:BB:CC:DD:EE:FF')], ['广播地址', textInput('broadcast', '255.255.255.255')], ['接口', textInput('ifname', 'br-lan')]],
      throughput: [['模式', '<select name="mode"><option value="client">客户端</option><option value="server">服务端</option></select>'], ['测试端', textInput('host', '', 'IP 或域名')], ['端口', numberInput('port', 5201, 1, 65535)], ['持续时间', numberInput('duration_s', 10, 1, 300)]]
    };
    const runLabel = tool.id === 'wake-on-lan' ? '发送唤醒' : tool.id === 'ddns' ? '立即更新' : tool.id === 'throughput' ? '开始测试' : '开始执行';
    return `<form class="quick-tool-form" data-tool-form="${tool.id}"><div class="quick-tool-fields">${(configs[tool.id] || []).map(([label, control]) => field(label, control)).join('')}</div><button class="policy-primary quick-tool-run" type="submit" ${tool.id === 'throughput' && throughputRunning() ? 'disabled' : ''}>${icon('play')}<span>${runLabel}</span></button></form>${tool.id === 'throughput' ? throughputTaskBar() : ''}<section class="quick-tool-result policy-stable-glass">${resultMarkup()}</section>`;
  }

  function throughputRunning() {
    return Boolean(state.throughput?.id) && state.throughput.state === 'running';
  }

  function throughputTaskBar() {
    const task = state.throughput;
    if (!task?.id) return '';
    const labels = { running: '进行中', completed: '已完成', stopped: '已停止' };
    const running = task.state === 'running';
    return `<section class="quick-tool-task policy-stable-glass" data-throughput-task>
      <div class="quick-tool-task-copy"><strong>吞吐任务 ${escapeHtml(labels[task.state] || task.state)}</strong><small>${escapeHtml(task.id)}</small></div>
      <div class="quick-tool-row-actions">
        ${running ? `<button class="quick-tool-icon-button" type="button" data-throughput-stop title="停止测试">${icon('stop')}</button>` : ''}
      </div>
    </section>`;
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
    if (['ping', 'traceroute', 'nslookup', 'speedtest'].includes(tool.id)) return diagnosticsPanel(tool);
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
    clearTimers();
    const seq = (state.seq += 1);
    state.busy = true; state.notice = ''; state.result = null; state.progress = ''; render();
    try {
      if (id === 'subnet') state.result = calculateSubnet(payload.address, payload.prefix);
      else {
        const endpoints = { ping: '/api/v1/diagnostics/ping', traceroute: '/api/v1/diagnostics/traceroute', nslookup: '/api/v1/diagnostics/nslookup', speedtest: '/api/v1/diagnostics/speedtest', 'packet-capture': '/api/v1/topology/capture', 'port-mirror': '/api/v1/toolkit/port-mirror', ddns: '/api/v1/toolkit/ddns/update', 'wake-on-lan': '/api/v1/toolkit/wake-on-lan', throughput: '/api/v1/toolkit/throughput' };
        if (id === 'packet-capture') payload.action = 'start';
        const first = await requestJson(endpoints[id], { method: 'POST', body: JSON.stringify(payload) });
        if (stale(seq)) return;
        if (id === 'throughput') { await trackThroughput(first, seq); return; }
        state.result = isPending(first) ? await awaitAsyncResult(endpoints[id], payload, first, seq) : first;
        if (stale(seq)) return;
        if (id === 'packet-capture') await loadCaptures(false);
      }
    } catch (error) {
      if (stale(seq)) return;
      /* A lookup that resolves to nothing is a real answer, not a fault: the
         daemon sets ok:false and webd maps that to 400. Showing it as a failure
         would send the user hunting for a broken resolver. */
      if (error?.payload && isEmptyAnswer(error.payload)) {
        state.result = error.payload;
        state.notice = emptyAnswerNotice(id, error.payload);
      } else state.notice = failureNotice(error, '执行失败');
    } finally { if (!stale(seq)) { state.busy = false; state.progress = ''; render(); } }
  }

  const EMPTY_ANSWER_CODES = new Set(['nxdomain_or_no_answer', 'no_hops_parsed', 'timeout']);

  function isEmptyAnswer(payload) {
    if (!payload || typeof payload !== 'object') return false;
    if (payload.available === false) return false;
    return EMPTY_ANSWER_CODES.has(String(firstText(payload.error, payload.error?.code)));
  }

  function emptyAnswerNotice(id, payload) {
    const code = String(firstText(payload.error, payload.error?.code));
    if (code === 'timeout') return '目标在超时时间内没有回应，这是真实结果';
    if (id === 'nslookup') return '解析器没有返回记录（NXDOMAIN 或无应答），这是真实结果';
    return '未能解析出任何跳，链路可能屏蔽了探测报文';
  }

  /* The backend is explicit about readiness, so the UI trusts those flags rather
     than guessing from the values: pending / has_result decide, not latency. */
  function isPending(payload) {
    if (!payload || typeof payload !== 'object') return false;
    if (payload.pending === true) return true;
    if (payload.has_result === false) return true;
    return payload.async === true && payload.status === 'pending';
  }

  /* "Capability not wired up yet" vs "it failed". A method the build never
     registered comes back as 501 method_not_registered; older webd builds may
     surface the same condition under a different status, so the error code is
     checked too. Showing these as a failure makes users chase a phantom fault. */
  const MISSING_CAPABILITY_CODES = new Set(['method_not_registered', 'capability_unavailable', 'unknown_command']);

  function isMissingCapability(error) {
    if (MISSING_CAPABILITY_CODES.has(String(error?.code || ''))) return true;
    return [404, 405, 501].includes(Number(error?.status));
  }

  /* source_unavailable means the daemon is not answering on ubus, so retrying is
     the right advice. Older webd builds that predate the 501 mapping also report a
     never-registered method this way, which is why the wording covers both
     without claiming the run itself failed. */
  function failureNotice(error, prefix) {
    if (error?.pendingTimeout) return '未能在预期时间内取得结果，路由器仍在探测';
    if (isMissingCapability(error)) return '该工具的后端能力尚未接入';
    if (String(error?.code || '') === 'source_unavailable' || Number(error?.status) === 503) {
      return '后端服务暂时不可用，请稍后重试（旧版固件也可能尚未注册该能力）';
    }
    return `${prefix}：${firstText(error?.message, 'unknown')}`;
  }

  async function awaitAsyncResult(endpoint, payload, firstResponse, seq) {
    const deadline = Date.now() + ASYNC_POLL_TIMEOUT_MS;
    let latest = firstResponse;
    while (Date.now() < deadline) {
      const left = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
      state.progress = `路由器仍在探测，正在等待结果（剩余 ${left} 秒）`;
      render();
      await sleep(ASYNC_POLL_INTERVAL_MS);
      if (stale(seq)) return latest;
      latest = await requestJson(endpoint, { method: 'POST', body: JSON.stringify(payload) });
      if (stale(seq)) return latest;
      if (!isPending(latest)) return latest;
    }
    // Never present pending numbers as a measurement.
    throw Object.assign(new Error('未能在预期时间内取得结果'), { pendingTimeout: true });
  }

  /* Throughput is a long job (up to 300s): start returns a task id, status
     reports running/completed, stop terminates it. Polling all three is what
     turns "click and wait blindly" into something the user can follow and abort. */
  async function trackThroughput(startResponse, seq) {
    const id = firstText(startResponse?.id, startResponse?.task_id, startResponse?.job_id);
    const duration = Number(startResponse?.duration_s) || 0;
    state.throughput = { id, state: 'running', startedAt: Date.now(), duration, result: null, reason: '' };
    if (!id) {
      // Without an id the task cannot be polled or stopped; say so instead of
      // pretending the run is being tracked.
      state.result = startResponse;
      state.notice = '后端未返回任务 id，无法查询进度或停止该任务';
      return;
    }
    state.result = startResponse;
    while (!stale(seq)) {
      const elapsed = Math.round((Date.now() - state.throughput.startedAt) / 1000);
      state.progress = duration
        ? `测试进行中 ${elapsed} / ${duration} 秒，可随时停止`
        : `测试进行中 ${elapsed} 秒，可随时停止`;
      render();
      await sleep(THROUGHPUT_POLL_INTERVAL_MS);
      if (stale(seq)) return;
      let status;
      try {
        status = await requestJson(`/api/v1/toolkit/throughput/status?id=${encodeURIComponent(id)}`);
      } catch (error) {
        if (stale(seq)) return;
        state.notice = failureNotice(error, '进度读取失败');
        return;
      }
      if (stale(seq)) return;
      const phase = firstText(status?.state, status?.status);
      state.throughput = { ...state.throughput, state: phase || 'running', result: status?.result || null, reason: firstText(status?.reason) };
      state.result = status;
      if (phase && phase !== 'running') {
        if (!status?.result && state.throughput.reason) state.notice = `任务已结束，但未取得 iperf3 结果：${state.throughput.reason}`;
        return;
      }
    }
  }

  async function stopThroughput() {
    const id = state.throughput?.id;
    if (!id) return;
    clearTimers();
    const seq = (state.seq += 1);
    state.progress = '正在停止任务'; render();
    try {
      const stopped = await requestJson('/api/v1/toolkit/throughput/stop', { method: 'POST', body: JSON.stringify({ id }) });
      if (stale(seq)) return;
      state.result = stopped;
      state.throughput = { ...state.throughput, state: firstText(stopped?.state, 'stopped') };
    } catch (error) {
      if (stale(seq)) return;
      state.notice = failureNotice(error, '停止失败');
    } finally { if (!stale(seq)) { state.busy = false; state.progress = ''; render(); } }
  }

  async function refreshThroughput(background = false) {
    const id = state.throughput?.id;
    if (!id) return;
    if (!background) clearTimers();
    const seq = (state.seq += 1);
    if (!background) { state.busy = true; state.progress = '正在读取任务状态'; render(); }
    try {
      const status = await requestJson(`/api/v1/toolkit/throughput/status?id=${encodeURIComponent(id)}`);
      if (stale(seq)) return;
      state.result = status;
      state.throughput = { ...state.throughput, state: firstText(status?.state, status?.status, 'running'), result: status?.result || null, reason: firstText(status?.reason) };
    } catch (error) {
      if (stale(seq)) return;
      if (background) return;
      state.notice = failureNotice(error, '进度读取失败');
    } finally { if (!stale(seq)) { if (!background) { state.busy = false; state.progress = ''; } render(); } }
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
      } else state.notice = failureNotice(error, '检测失败');
    } finally { state.busy = false; render(); }
  }

  async function loadCaptures(redraw = true) {
    try {
      const data = await requestJson('/api/v1/topology/capture/status');
      state.captures = asArray(data, ['captures', 'tasks', 'jobs']);
    } catch (error) { state.notice = `抓包任务读取失败：${firstText(error.message)}`; }
    if (redraw) render();
  }

  async function loadFlows(background = false) {
    if (!background) { state.busy = true; state.notice = ''; render(); }
    try {
      const data = await requestJson('/api/v1/insights/flows/current');
      state.flows = asArray(data, ['flows', 'connections', 'items']);
    } catch (error) { if (!background) state.notice = `流表读取失败：${firstText(error.message)}`; }
    finally { if (!background) state.busy = false; render(); }
  }

  async function stopCapture(id) {
    try { await requestJson('/api/v1/topology/capture/stop', { method: 'POST', body: JSON.stringify({ id, action: 'stop' }) }); await loadCaptures(); }
    catch (error) { state.notice = `停止失败：${firstText(error.message)}`; render(); }
  }

  function bindEvents() {
    root.querySelectorAll('[data-quick-tool]').forEach((button) => button.addEventListener('click', () => {
      clearTimers(); state.seq += 1;
      state.active = button.dataset.quickTool;
      state.result = null; state.notice = ''; state.progress = ''; state.busy = false; state.throughput = null;
      render();
      if (state.active === 'packet-capture') loadCaptures();
      if (state.active === 'flow-table') loadFlows();
    }));
    root.querySelector('[data-tool-back]')?.addEventListener('click', () => {
      clearTimers(); state.seq += 1;
      state.active = ''; state.result = null; state.notice = ''; state.progress = ''; state.busy = false; state.throughput = null;
      render();
    });
    root.querySelectorAll('[data-tool-form]').forEach((form) => form.addEventListener('submit', (event) => { event.preventDefault(); runTool(form); }));
    root.querySelector('[data-tool-health]')?.addEventListener('click', loadHealth);
    root.querySelector('[data-throughput-stop]')?.addEventListener('click', stopThroughput);
    root.querySelectorAll('[data-capture-stop]').forEach((button) => button.addEventListener('click', () => stopCapture(button.dataset.captureStop)));
  }

  async function loadWans() {
    try { const data = await requestJson('/api/v1/network/wans'); state.wans = asArray(data, ['wans', 'interfaces']); } catch (_) {}
  }

  render();
  loadWans();
  startPolling();
  return { unmount() { state.mounted = false; state.seq += 1; clearTimers(); stopPolling(); root?.replaceChildren(); root?.classList.remove(MODULE_CLASS, 'policy-table-route-host', 'route-workspace'); } };
}

export default { mount };
