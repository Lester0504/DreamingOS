// 网络工具箱 桌面 app 逻辑。对标 RoceOS 网络工具箱：左侧手风琴分组，右侧输入表单 +
// 结果卡。数据驱动：所有工具由 TOOLS 注册表声明（字段/端点/渲染），executor 统一发起。
// speedtest / iperf3 走异步 job 轮询；ping 走缓存刷新轮询；其余一次性 loading。外呼工具
// （public-ip/ip-geo/mac-lookup）显式提示并尊重后端 external_lookup 开关。encoding/regex/
// subnet-calc 纯客户端。前景一律走 CSS 令牌，JS 不注入任何颜色。
(function () {
  'use strict';

  // --- session-gated request (mirror resource-manager apiJson) ---
  function apiJson(url, opts) {
    if (window.DWRT_REQUEST && window.DWRT_REQUEST.json) return window.DWRT_REQUEST.json(url, opts);
    var tok = '';
    try { tok = localStorage.getItem('dreamingwrt.web.accessToken') || ''; } catch (e) {}
    var init = opts || {};
    var headers = { Accept: 'application/json' };
    if (init.body) headers['Content-Type'] = 'application/json';
    if (tok) headers.Authorization = 'Bearer ' + tok;
    return fetch(url, { method: init.method || 'GET', body: init.body, headers: headers, cache: 'no-store', credentials: 'same-origin' })
      .then(function (r) {
        return r.text().then(function (t) {
          var j = {};
          if (t) { try { j = JSON.parse(t); } catch (e) { throw new Error('invalid json'); } }
          if (!r.ok || (j && j.ok === false)) {
            var e = new Error(String(r.status)); e.status = r.status; e.payload = j; throw e;
          }
          return j;
        });
      });
  }
  // Unwrap { ok, data:{} } envelopes; tolerate bare objects.
  function dataOf(j) { return j && typeof j === 'object' && j.data && typeof j.data === 'object' ? j.data : j; }

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  var toastTimer = null;
  function toast(msg) {
    var t = $('#ntToast'); if (!t) return;
    t.textContent = msg; t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.hidden = true; }, 2200);
  }
  // --- formatting helpers ---
  function fmtMs(v) { return (v == null || v === '') ? '—' : (Math.round(Number(v) * 100) / 100) + ' ms'; }
  function fmtMbps(v) { return (v == null || v === '') ? '—' : (Math.round(Number(v) * 100) / 100) + ' Mbps'; }
  function fmtBytes(n) {
    n = Number(n) || 0;
    var u = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (Math.round(n * 100) / 100) + ' ' + u[i];
  }
  function fmtTs(v) {
    var n = Number(v); if (!n) return '—';
    if (n < 1e12) n *= 1000;
    try { return new Date(n).toLocaleString('zh-CN'); } catch (e) { return String(v); }
  }
  function titleize(k) {
    return String(k).replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
  }
  var STATUS_KIND = { ok: 'ok', up: 'ok', running: 'ok', completed: 'ok', connected: 'ok', valid: 'ok', found: 'ok',
    warning: 'warn', warn: 'warn', degraded: 'warn', pending: 'warn', partial: 'warn',
    error: 'crit', crit: 'crit', down: 'crit', failed: 'crit', unavailable: 'crit', invalid: 'crit' };
  function statusKind(s) { return STATUS_KIND[String(s || '').toLowerCase()] || ''; }

  // --- HTML builders (values escaped; class names static) ---
  function badge(text, kind) {
    return '<span class="nt-badge' + (kind ? ' is-' + kind : '') + '">' + esc(text) + '</span>';
  }
  function stats(items) {
    var body = items.filter(Boolean).map(function (it) {
      return '<div class="nt-stat"><div class="nt-stat-label">' + esc(it.label) + '</div>' +
        '<div class="nt-stat-value">' + esc(it.value) + (it.unit ? '<small>' + esc(it.unit) + '</small>' : '') + '</div></div>';
    }).join('');
    return body ? '<div class="nt-stats">' + body + '</div>' : '';
  }
  function kv(pairs) {
    var rows = pairs.filter(function (p) { return p && p[1] != null && p[1] !== ''; }).map(function (p) {
      var val = p[2] === 'html' ? p[1] : esc(p[1]);
      return '<dt>' + esc(p[0]) + '</dt><dd>' + val + '</dd>';
    }).join('');
    return rows ? '<dl class="nt-kv">' + rows + '</dl>' : '';
  }
  function section(label) { return '<div class="nt-section-label">' + esc(label) + '</div>'; }
  function chips(arr) {
    if (!arr || !arr.length) return '';
    return '<div class="nt-chips">' + arr.map(function (x) { return '<span class="nt-chip">' + esc(x) + '</span>'; }).join('') + '</div>';
  }
  // table(cols:[{key,label,fmt?}], rows:[obj]) → escaped table with horizontal scroll.
  function table(cols, rows) {
    if (!rows || !rows.length) return '';
    var head = '<tr>' + cols.map(function (c) { return '<th>' + esc(c.label) + '</th>'; }).join('') + '</tr>';
    var body = rows.map(function (r) {
      return '<tr>' + cols.map(function (c) {
        var v = r ? r[c.key] : '';
        if (c.fmt) return '<td>' + c.fmt(v, r) + '</td>';
        if (Array.isArray(v)) v = v.join(', ');
        else if (v && typeof v === 'object') v = JSON.stringify(v);
        return '<td>' + esc(v == null ? '' : v) + '</td>';
      }).join('') + '</tr>';
    }).join('');
    return '<div class="nt-table-wrap"><table class="nt-table"><thead>' + head + '</thead><tbody>' + body + '</tbody></table></div>';
  }
  var codeSeq = 0;
  function codeBlock(text, label) {
    var id = 'ntcode' + (++codeSeq);
    var raw = typeof text === 'string' ? text : JSON.stringify(text, null, 2);
    return (label ? section(label) : '') +
      '<div class="nt-code"><button type="button" class="nt-copy" data-copy="' + id + '">复制</button>' +
      '<span id="' + id + '">' + esc(raw) + '</span></div>';
  }
  // Generic fallback: scalars → KeyValue, object-arrays → table, scalar-arrays → chips,
  // nested objects → labelled sub-sections; always a raw JSON <details> at the end.
  function autoRender(data) {
    if (data == null) return '<div class="nt-result-empty">无数据</div>';
    if (typeof data !== 'object') return '<div class="nt-kv"><dl class="nt-kv"><dt>结果</dt><dd>' + esc(data) + '</dd></dl></div>';
    var pairs = [], html = '';
    Object.keys(data).forEach(function (k) {
      var v = data[k];
      if (v == null || v === '') return;
      if (Array.isArray(v)) {
        if (!v.length) return;
        if (typeof v[0] === 'object' && v[0]) {
          var cols = Object.keys(v[0]).slice(0, 8).map(function (ck) { return { key: ck, label: titleize(ck) }; });
          html += section(titleize(k) + ' (' + v.length + ')') + table(cols, v);
        } else { html += section(titleize(k)) + chips(v); }
      } else if (typeof v === 'object') {
        var sub = Object.keys(v).map(function (sk) { return [titleize(sk), typeof v[sk] === 'object' ? JSON.stringify(v[sk]) : v[sk]]; });
        html += section(titleize(k)) + kv(sub);
      } else if (typeof v === 'boolean') {
        pairs.push([titleize(k), v ? '是' : '否']);
      } else { pairs.push([titleize(k), v]); }
    });
    return kv(pairs) + html;
  }
  function errorBox(err) {
    var code = err && err.payload && (err.payload.error || (err.payload.data && err.payload.data.error));
    var msg = err && err.payload && (err.payload.message || (err.payload.data && err.payload.data.message));
    var human = code === 'external_lookup_disabled' ? '外部查询已被管理员关闭（[toolkit] external_lookup=0）。'
      : code === 'toolkit_unavailable' ? 'dreamingwrt-toolkit 未安装或不可用。'
      : code === 'capability_unavailable' ? '该能力所需的系统组件缺失（后端 501）。'
      : (msg || (err && err.message) || '请求失败');
    return '<div class="nt-error"><b>执行失败</b> · ' + esc(code || (err && err.status) || 'error') + '<br>' + esc(human) + '</div>';
  }
  // --- tool-specific renderers ---
  var R = {};
  R.ping = function (d) {
    var st = d.pending ? 'pending' : (d.status || '');
    return stats([
      { label: '延迟', value: d.latency != null ? d.latency : '—', unit: 'ms' },
      { label: '丢包', value: d.loss != null ? d.loss : '—', unit: '%' },
      { label: '状态', value: st === 'pending' ? '探测中' : (st || '—') }
    ]) + kv([
      ['目标', d.target], ['主机', d.host], ['出接口', d.bind_ifname || d.ifname],
      ['结果时间', d.result_ts ? fmtTs(d.result_ts) : ''],
      ['数据新鲜度', d.stale ? '刷新中…' : '最新', 'text']
    ]);
  };
  R.traceroute = function (d) {
    var hops = d.hops || [];
    var rows = hops.map(function (h) {
      var rtt = Array.isArray(h.rtt_ms) ? h.rtt_ms : (h.rtt_ms != null ? [h.rtt_ms] : []);
      return { hop: h.hop, address: h.address || h.host || '*', rtt: rtt.length ? rtt.map(function (x) { return Math.round(x * 100) / 100; }).join(' / ') + ' ms' : (h.timeout ? '超时' : '—'), state: h.responded ? '✓' : (h.timeout ? '✗' : '') };
    });
    return stats([
      { label: '跳数', value: d.hop_count != null ? d.hop_count : hops.length },
      { label: '是否到达', value: d.reached ? '已到达' : '未确认' },
      { label: '目标', value: d.target || '—' }
    ]) + table([
      { key: 'hop', label: '#' }, { key: 'address', label: '地址' },
      { key: 'rtt', label: 'RTT' }, { key: 'state', label: '响应' }
    ], rows) + (d.timed_out ? '<div class="nt-section-label">注：探测整体超时，结果可能不完整</div>' : '');
  };
  R.dns = function (d) {
    var recs = d.records || d.answers || [];
    var rows = recs.map(function (r) {
      if (typeof r === 'string') return { name: d.name || d.target || '', type: d.type || '', value: r };
      return { name: r.name || d.name || '', type: r.type || d.type || '', value: r.address || r.data || r.value || '' };
    });
    return kv([
      ['查询名', d.name || d.target], ['类型', d.type], ['服务器', d.server || d.resolver],
      ['提供者', d.provider], ['记录数', (d.count != null ? d.count : rows.length)]
    ]) + (rows.length ? section('记录') + table([
      { key: 'name', label: '名称' }, { key: 'type', label: '类型' }, { key: 'value', label: '值' }
    ], rows) : '<div class="nt-result-empty">无解析记录</div>');
  };
  function portRows(d) {
    var ports = d.open_ports || d.results || d.ports || [];
    return ports.map(function (p) {
      if (typeof p === 'object') return { port: p.port, state: p.state || (p.open ? 'open' : ''), service: p.service || '' };
      return { port: p, state: 'open', service: '' };
    });
  }
  R.portscan = function (d) {
    var rows = portRows(d);
    return stats([
      { label: '开放', value: d.open_count != null ? d.open_count : rows.filter(function (r) { return r.state === 'open'; }).length },
      { label: '关闭', value: d.closed_count != null ? d.closed_count : '—' },
      { label: '过滤', value: d.filtered_count != null ? d.filtered_count : '—' }
    ]) + kv([['主机', d.host], ['IP', d.ip], ['扫描端口', d.ports_scanned]]) +
      (rows.length ? section('端口') + table([
        { key: 'port', label: '端口' }, { key: 'state', label: '状态', fmt: function (v) { return badge(v || '', statusKind(v === 'open' ? 'ok' : v === 'closed' ? 'crit' : 'warn')); } },
        { key: 'service', label: '服务' }
      ], rows) : '<div class="nt-result-empty">无开放端口</div>');
  };
  R.sslcheck = function (d) {
    var c = d.certificate || {};
    var days = c.days_remaining;
    var dkind = days == null ? '' : (days < 0 ? 'crit' : days < 15 ? 'crit' : days < 30 ? 'warn' : 'ok');
    return stats([
      { label: 'TLS 版本', value: d.tls_version || '—' },
      { label: '证书有效', value: d.valid ? '有效' : '无效' },
      { label: '剩余天数', value: days != null ? days : '—', unit: days != null ? '天' : '' }
    ]) + kv([
      ['主机', d.host], ['IP', d.ip], ['端口', d.port], ['加密套件', d.cipher],
      ['校验结果', d.verify_result],
      ['剩余有效期', days != null ? badge(days + ' 天', dkind) : '', 'html']
    ]) + section('证书') + kv([
      ['主体', c.subject], ['颁发者', c.issuer], ['生效', c.not_before], ['到期', c.not_after],
      ['序列号', c.serial], ['签名算法', c.signature_algorithm]
    ]) + (c.subject_alt_names && c.subject_alt_names.length ? section('SAN') + chips(c.subject_alt_names) : '');
  };
  var SEC_HEADERS = [
    { key: 'strict-transport-security', label: 'HSTS' },
    { key: 'content-security-policy', label: 'CSP' },
    { key: 'x-frame-options', label: 'X-Frame-Options' },
    { key: 'x-content-type-options', label: 'X-Content-Type-Options' },
    { key: 'referrer-policy', label: 'Referrer-Policy' },
    { key: 'permissions-policy', label: 'Permissions-Policy' },
    { key: 'cross-origin-opener-policy', label: 'COOP' }
  ];
  function lowerKeys(obj) {
    var out = {}; if (obj) Object.keys(obj).forEach(function (k) { out[k.toLowerCase()] = obj[k]; }); return out;
  }
  R.headers = function (d) {
    var hdrs = lowerKeys(d.headers || {});
    var present = 0;
    var rows = SEC_HEADERS.map(function (h) {
      var val = hdrs[h.key];
      if (val) present++;
      return { name: h.label, ok: val ? '✓' : '✗', value: val || '（缺失）' };
    });
    var grade = ['F', 'F', 'D', 'C', 'B', 'B+', 'A', 'A+'][present] || 'F';
    var gkind = present >= 6 ? 'ok' : present >= 4 ? 'warn' : 'crit';
    return stats([
      { label: '安全头评分', value: grade },
      { label: '命中', value: present + ' / ' + SEC_HEADERS.length },
      { label: 'HTTP 状态', value: d.status != null ? d.status : '—' }
    ]) + '<div class="nt-section-label">安全响应头 ' + badge(present + '/' + SEC_HEADERS.length, gkind) + '</div>' +
      table([
        { key: 'name', label: '响应头' },
        { key: 'ok', label: '', fmt: function (v) { return v === '✓' ? badge('有', 'ok') : badge('无', 'crit'); } },
        { key: 'value', label: '值' }
      ], rows) +
      '<details class="nt-details"><summary>全部响应头（' + Object.keys(hdrs).length + '）</summary>' +
      table([{ key: 'k', label: '名称' }, { key: 'v', label: '值' }],
        Object.keys(hdrs).map(function (k) { return { k: k, v: hdrs[k] }; })) + '</details>';
  };
  R.httprequest = function (d) {
    var out = stats([
      { label: 'HTTP 状态', value: d.status != null ? d.status : '—' },
      { label: '耗时', value: d.elapsed_ms != null ? d.elapsed_ms : '—', unit: 'ms' },
      { label: 'TLS 校验', value: d.tls_verified ? '通过' : (d.insecure ? '已跳过' : '—') }
    ]) + kv([['URL', d.url], ['响应大小', d.body_size != null ? fmtBytes(d.body_size) : '']]);
    if (d.redirects && d.redirects.length) out += section('重定向 (' + d.redirects.length + ')') + chips(d.redirects.map(function (r) { return typeof r === 'object' ? (r.url || JSON.stringify(r)) : r; }));
    if (d.headers) out += '<details class="nt-details"><summary>响应头</summary>' + table([{ key: 'k', label: '名称' }, { key: 'v', label: '值' }], Object.keys(d.headers).map(function (k) { return { k: k, v: d.headers[k] }; })) + '</details>';
    if (d.body) out += codeBlock(typeof d.body === 'string' ? d.body : JSON.stringify(d.body, null, 2), '响应体');
    return out;
  };
  R.websitecheck = function (d) {
    var rows = (d.results || []).map(function (r) {
      return { url: r.url, up: r.up ? '在线' : '离线', status: r.status != null ? r.status : '', ssl: r.sslValid == null ? '' : (r.sslValid ? '有效' : '无效'), error: r.error || '' };
    });
    return stats([
      { label: '总数', value: d.total != null ? d.total : rows.length },
      { label: '在线', value: d.up != null ? d.up : '—' },
      { label: '离线', value: d.down != null ? d.down : '—' }
    ]) + table([
      { key: 'url', label: '网址' },
      { key: 'up', label: '状态', fmt: function (v) { return badge(v, v === '在线' ? 'ok' : 'crit'); } },
      { key: 'status', label: 'HTTP' }, { key: 'ssl', label: 'SSL' }, { key: 'error', label: '错误' }
    ], rows);
  };
  R.arpscan = function (d) {
    var rows = (d.neighbors || []).map(function (n) { return { ip: n.ip, mac: n.mac || '', iface: n.interface || '', state: n.state || '' }; });
    return stats([{ label: '发现主机', value: d.count != null ? d.count : rows.length }, { label: '方法', value: d.method || '—' }]) +
      table([{ key: 'ip', label: 'IP' }, { key: 'mac', label: 'MAC' }, { key: 'iface', label: '接口' }, { key: 'state', label: '状态' }], rows);
  };
  R.mdns = function (d) {
    var rows = (d.services || []).map(function (s) { return { name: s.name, type: s.type, host: s.host || '', address: s.address || '', port: s.port || '' }; });
    return stats([{ label: '发现服务', value: d.count != null ? d.count : rows.length }, { label: '方法', value: d.method || '—' }]) +
      (rows.length ? table([{ key: 'name', label: '名称' }, { key: 'type', label: '类型' }, { key: 'host', label: '主机' }, { key: 'address', label: '地址' }, { key: 'port', label: '端口' }], rows) : '<div class="nt-result-empty">未发现 mDNS 服务</div>');
  };
  R.localinfo = function (d) {
    var out = kv([['WAN 接口', d.wan_ifname], ['网关', d.gateway]]);
    if (d.dns_servers && d.dns_servers.length) out += section('DNS 服务器') + chips(d.dns_servers);
    var rows = (d.interfaces || []).map(function (i) {
      var addrs = (i.addresses || []).map(function (a) { return (a.family ? a.family + ' ' : '') + a.address; });
      return { name: i.name || '', state: (i.up ? 'up' : 'down') + (i.running ? ' · running' : ''), addresses: addrs.join('  ') || '无地址' };
    });
    if (rows.length) out += section('接口 (' + rows.length + ')') + table([
      { key: 'name', label: '接口' },
      { key: 'state', label: '状态', fmt: function (v) { return badge(v, v.indexOf('up') === 0 ? 'ok' : 'crit'); } },
      { key: 'addresses', label: '地址' }
    ], rows);
    return out;
  };
  R.localports = function (d) {
    var socks = d.sockets || [];
    return stats([{ label: '监听/连接', value: d.count != null ? d.count : socks.length }, { label: '来源', value: d.source || '—' }]) +
      (socks.length && typeof socks[0] === 'object'
        ? table(Object.keys(socks[0]).slice(0, 7).map(function (k) { return { key: k, label: titleize(k) }; }), socks)
        : chips(socks.map(function (s) { return typeof s === 'object' ? JSON.stringify(s) : s; })));
  };
  R.publicip = function (d, ctx) {
    if (ctx) ctx.externalOn = d.external_lookup !== false;
    var out = stats([
      { label: '公网 IP', value: d.public_ip || '未获取' },
      { label: '外呼开关', value: d.external_lookup === false ? '已关闭' : '开启' }
    ]);
    if (d.local_public_addresses && d.local_public_addresses.length) out += section('本机公网地址') + chips(d.local_public_addresses);
    if (d.note) out += '<div class="nt-section-label">' + esc(d.note) + '</div>';
    return out;
  };
  R.ipgeo = function (d) {
    return kv([
      ['查询', d.query || d.ip], ['国家', d.country], ['地区', d.regionName || d.region], ['城市', d.city],
      ['经纬度', (d.lat != null && d.lon != null) ? d.lat + ', ' + d.lon : ''],
      ['ISP', d.isp], ['组织', d.org], ['AS', d.as], ['反向', d.reverse], ['时区', d.timezone]
    ]);
  };
  R.whois = function (d) {
    var out = kv([['域名', d.domain], ['WHOIS 服务器', d.whois_server]]);
    if (d.status && d.status.length) out += section('状态') + chips(d.status);
    if (d.name_servers && d.name_servers.length) out += section('域名服务器') + chips(d.name_servers);
    if (d.raw) out += codeBlock(d.raw, '原始记录');
    return out;
  };
  R.maclookup = function (d) {
    return stats([{ label: '厂商', value: d.vendor || (d.found ? '—' : '未知') }, { label: '命中', value: d.found ? '是' : '否' }]) +
      kv([['MAC', d.mac], ['OUI', d.oui], ['厂商', d.vendor]]);
  };
  R.mtu = function (d) {
    return stats([
      { label: 'MTU', value: d.mtu != null ? d.mtu : '—' },
      { label: '最大载荷', value: d.max_payload != null ? d.max_payload : '—' },
      { label: '开销', value: d.overhead != null ? d.overhead : '—' }
    ]) + kv([['主机', d.host], ['解析 IP', d.resolved_ip], ['协议族', d.family]]);
  };
  R.latency = function (d) {
    var rows = (d.samples || []).map(function (s, i) { return typeof s === 'object' ? s : { seq: i + 1, rtt_ms: s }; });
    return stats([
      { label: '平均', value: d.avg_ms != null ? Math.round(d.avg_ms * 100) / 100 : '—', unit: 'ms' },
      { label: '抖动', value: d.jitter_ms != null ? Math.round(d.jitter_ms * 100) / 100 : '—', unit: 'ms' },
      { label: '丢包', value: d.loss_percent != null ? d.loss_percent : '—', unit: '%' }
    ]) + kv([
      ['主机', d.host], ['解析 IP', d.resolved_ip],
      ['发送/接收', (d.sent != null ? d.sent : '?') + ' / ' + (d.received != null ? d.received : '?')],
      ['最小/最大', fmtMs(d.min_ms) + ' / ' + fmtMs(d.max_ms)]
    ]) + (rows.length ? '<details class="nt-details"><summary>采样 (' + rows.length + ')</summary>' +
      table(Object.keys(rows[0]).map(function (k) { return { key: k, label: titleize(k) }; }), rows) + '</details>' : '');
  };
  R.routercheck = function (d) {
    var checks = d.checks || [];
    var rows = checks.map(function (c) { return { label: c.label || c.id, status: c.status, summary: c.summary || '', remediation: c.remediation || '' }; });
    var overall = d.status || '';
    return '<div class="nt-section-label">总体：' + badge(overall || '—', statusKind(overall)) +
      '　错误 ' + (d.error_count || 0) + '　警告 ' + (d.warning_count || 0) + '</div>' +
      table([
        { key: 'label', label: '检查项' },
        { key: 'status', label: '状态', fmt: function (v) { return badge(v || '', statusKind(v)); } },
        { key: 'summary', label: '摘要' }, { key: 'remediation', label: '建议' }
      ], rows);
  };
  // --- tool registry (declarative) ---
  // field: { name,label,type,def,required,placeholder,help,options,wide,min,max }
  // tool:  { id,title,desc,badge,external,long,method,endpoint,fields,build,render,mode,custom }
  var GROUPS = [
    { id: 'basic', title: '基础诊断', tools: [
      { id: 'ping', title: 'Ping', desc: '异步刷新探测目标的延迟与丢包（缓存刷新轮询）。', badge: '实时', mode: 'ping', endpoint: '/api/v1/diagnostics/ping', method: 'POST', render: R.ping,
        fields: [ { name: 'target', label: '目标', required: true, placeholder: '域名/IP，或 apple·baidu·bilibili·wechat', wide: true }, { name: 'ifname', label: '出接口(可选)', placeholder: '如 wan / pppoe-wan' } ] },
      { id: 'traceroute', title: 'Traceroute', desc: '逐跳路径与每跳 RTT（一次性，最长约 30s）。', badge: '实时', long: true, endpoint: '/api/v1/diagnostics/traceroute', method: 'POST', render: R.traceroute,
        fields: [ { name: 'target', label: '目标', required: true, placeholder: '域名或 IP', wide: true }, { name: 'max_hops', label: '最大跳数', type: 'number', def: 30, min: 1, max: 64 } ] },
      { id: 'dns', title: 'DNS 查询', desc: '按记录类型向指定 DNS 服务器查询（dig，缺失回退 getaddrinfo）。', endpoint: '/api/v1/diagnostics/dns-query', method: 'POST', render: R.dns,
        fields: [ { name: 'name', label: '查询名', required: true, placeholder: 'example.com', wide: true }, { name: 'type', label: '记录类型', type: 'select', def: 'A', options: ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR', 'SRV', 'CAA'] }, { name: 'server', label: 'DNS 服务器(可选)', placeholder: '如 1.1.1.1' } ] },
      { id: 'portscan', title: '端口扫描', desc: '扫描目标主机的开放端口（范围 ≤1000）。', long: true, endpoint: '/api/v1/diagnostics/port-scan', method: 'POST', render: R.portscan,
        fields: [ { name: 'host', label: '主机', required: true, placeholder: '域名或 IP', wide: true }, { name: 'ports', label: '端口范围', def: '1-1000', help: '≤1000 个', placeholder: '1-1000 或 22,80,443' }, { name: 'timeout_ms', label: '单端口超时', type: 'number', def: 1200, help: 'ms' } ] },
      { id: 'portcheck', title: '端口连通', desc: '检测指定端口是否开放。', endpoint: '/api/v1/diagnostics/port-check', method: 'POST', render: R.portscan,
        fields: [ { name: 'host', label: '主机', required: true, placeholder: '域名或 IP', wide: true }, { name: 'port', label: '端口', type: 'number', required: true, placeholder: '443', min: 1, max: 65535 }, { name: 'timeout_ms', label: '超时', type: 'number', def: 3000, help: 'ms' } ] },
      { id: 'localports', title: '本机端口', desc: '列出本机监听/连接的套接字。', mount: true, endpoint: '/api/v1/diagnostics/local-ports', method: 'GET', render: R.localports, fields: [] }
    ] },
    { id: 'info', title: '网络信息', tools: [
      { id: 'localinfo', title: '本机信息', desc: '本机接口、地址、DNS 与网关。', mount: true, endpoint: '/api/v1/diagnostics/local-info', method: 'GET', render: R.localinfo, fields: [] },
      { id: 'publicip', title: '公网 IP', desc: '探测本机公网出口 IP。', badge: '外呼', external: true, mount: true, endpoint: '/api/v1/diagnostics/public-ip', method: 'GET', render: R.publicip, fields: [] },
      { id: 'whois', title: 'WHOIS', desc: '查询域名注册与状态信息。', long: true, endpoint: '/api/v1/diagnostics/whois', method: 'POST', render: R.whois,
        fields: [ { name: 'domain', label: '域名', required: true, placeholder: 'example.com', wide: true }, { name: 'server', label: 'WHOIS 服务器(可选)' } ] },
      { id: 'ipgeo', title: 'IP 归属地', desc: '查询 IP/域名的地理位置与运营商。', badge: '外呼', external: true, endpoint: '/api/v1/diagnostics/ip-geo', method: 'POST', render: R.ipgeo,
        fields: [ { name: 'query', label: 'IP 或域名', required: true, placeholder: '8.8.8.8 或 example.com', wide: true } ] }
    ] },
    // NT_GROUPS_APPEND
    { id: 'http', title: 'HTTP 测试', tools: [
      { id: 'httprequest', title: 'HTTP 请求', desc: '发起 HTTP(S) 请求，查看状态、重定向、响应头与响应体。', long: true, endpoint: '/api/v1/diagnostics/http-request', method: 'POST', render: R.httprequest,
        fields: [ { name: 'url', label: 'URL', required: true, placeholder: 'https://example.com', wide: true }, { name: 'method', label: '方法', type: 'select', def: 'GET', options: ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'] }, { name: 'max_redirects', label: '最大重定向', type: 'number', def: 10 }, { name: 'timeout', label: '超时(s)', type: 'number', def: 15 }, { name: 'body', label: '请求体(可选)', type: 'textarea', wide: true }, { name: 'allow_private', label: '允许内网地址', type: 'checkbox' }, { name: 'insecure', label: '跳过 TLS 校验', type: 'checkbox' } ] },
      { id: 'websitecheck', title: '网站可用性', desc: '批量检测多个网址是否在线（含 SSL 有效性）。', long: true, endpoint: '/api/v1/diagnostics/website-check', method: 'POST', render: R.websitecheck,
        build: function (v) { var urls = String(v.urls || '').split(/\n+/).map(function (s) { return s.trim(); }).filter(Boolean); return { urls: urls, allow_private: !!v.allow_private }; },
        fields: [ { name: 'urls', label: '网址列表', type: 'textarea', required: true, wide: true, help: '每行一个 URL', placeholder: 'https://example.com\nhttps://openwrt.org' }, { name: 'allow_private', label: '允许内网地址', type: 'checkbox' } ] },
      { id: 'sslcheck', title: 'SSL 证书', desc: '检查 TLS 版本、加密套件与证书有效期。', endpoint: '/api/v1/diagnostics/ssl-check', method: 'POST', render: R.sslcheck,
        fields: [ { name: 'host', label: '主机', required: true, placeholder: 'example.com', wide: true }, { name: 'port', label: '端口', type: 'number', def: 443 }, { name: 'servername', label: 'SNI(可选)', placeholder: '默认同主机' }, { name: 'timeout_ms', label: '超时', type: 'number', def: 8000, help: 'ms' } ] },
      { id: 'headers', title: '响应头 / 安全评分', desc: '抓取响应头并对 7 个安全响应头做客户端评分。', long: true, endpoint: '/api/v1/diagnostics/headers', method: 'POST', render: R.headers,
        fields: [ { name: 'url', label: 'URL', required: true, placeholder: 'https://example.com', wide: true } ] }
    ] },
    { id: 'lan', title: '局域网', tools: [
      { id: 'arpscan', title: 'ARP 扫描', desc: '发现同网段在线主机（ip neigh）。', long: true, endpoint: '/api/v1/diagnostics/arp-scan', method: 'POST', render: R.arpscan,
        fields: [ { name: 'interface', label: '接口(可选)', placeholder: '如 br-lan' } ] },
      { id: 'wol', title: '网络唤醒 (WoL)', desc: '向局域网设备发送 Magic Packet 唤醒。', endpoint: '/api/v1/toolkit/wake-on-lan', method: 'POST', render: function (d) { return stats([{ label: '已发送', value: d.bytes_sent != null ? d.bytes_sent : '—', unit: 'B' }]) + kv([['MAC', d.mac], ['广播', d.broadcast], ['接口', d.ifname], ['时间', fmtTs(d.sent_at)]]); },
        fields: [ { name: 'mac', label: '目标 MAC', required: true, placeholder: 'AA:BB:CC:DD:EE:FF', wide: true }, { name: 'broadcast', label: '广播地址', def: '255.255.255.255' }, { name: 'ifname', label: '接口', def: 'br-lan' } ] },
      { id: 'maclookup', title: 'MAC 厂商', desc: '按 OUI 查询网卡厂商。', badge: '外呼', external: true, endpoint: '/api/v1/diagnostics/mac-lookup', method: 'POST', render: R.maclookup,
        fields: [ { name: 'mac', label: 'MAC 地址', required: true, placeholder: 'AA:BB:CC:DD:EE:FF', wide: true } ] },
      { id: 'mdns', title: 'mDNS 发现', desc: '发现局域网 mDNS/Bonjour 服务（需 avahi-browse）。', long: true, endpoint: '/api/v1/diagnostics/mdns', method: 'POST', render: R.mdns,
        fields: [ { name: 'service_type', label: '服务类型(可选)', placeholder: '_http._tcp（留空=全部）' }, { name: 'timeout_ms', label: '超时', type: 'number', def: 5000, help: '1000-15000 ms' } ] }
    ] },
    { id: 'perf', title: '性能测试', tools: [
      { id: 'speedtest', title: '测速 (Cloudflare)', desc: '延迟 → 下载 → 上传三段测速。会向 Cloudflare 发起外部请求。', badge: '实时', external: true, custom: 'speedtest' },
      { id: 'iperf3', title: 'iperf3 吞吐', desc: '我方独有：iperf3 客户端/服务端吞吐测试（异步 job）。', badge: '独有', custom: 'iperf3' },
      { id: 'mtu', title: 'MTU 探测', desc: '探测到目标的路径 MTU 与最大载荷。', long: true, endpoint: '/api/v1/diagnostics/mtu-detect', method: 'POST', render: R.mtu,
        fields: [ { name: 'host', label: '主机', required: true, placeholder: '域名或 IP', wide: true } ] },
      { id: 'latency', title: '延迟监测', desc: '连续采样统计延迟/抖动/丢包（一次性批量，最长约 200s）。', badge: '实时', long: true, endpoint: '/api/v1/diagnostics/latency-monitor', method: 'POST', render: R.latency,
        fields: [ { name: 'host', label: '主机', required: true, placeholder: '域名或 IP', wide: true }, { name: 'count', label: '采样数', type: 'number', def: 10, help: '≤100' } ] }
    ] },
    { id: 'router', title: '路由专属', tools: [
      { id: 'routercheck', title: '路由体检', desc: '我方独有：存储/内存/线路/DHCP/PPPoE/网关/核心服务 7 项体检。', badge: '独有', mount: true, endpoint: '/api/v1/toolkit/router-check', method: 'POST', render: R.routercheck, fields: [] },
      { id: 'portmirror', title: '端口镜像', desc: '我方独有：基于 tc clsact 的端口镜像（列表/新增/删除）。', badge: '独有', custom: 'portmirror' },
      { id: 'ddns', title: 'DDNS', desc: '我方独有：动态 DNS 配置（列表/保存/立即更新）。', badge: '独有', custom: 'ddns' }
    ] },
    { id: 'util', title: '实用工具', tools: [
      { id: 'subnetcalc', title: '子网计算', desc: '纯客户端：由 CIDR 计算网络/广播/可用地址范围。', badge: '客户端', custom: 'subnetcalc' },
      { id: 'encoding', title: '编码转换', desc: '纯客户端：Base64 / URL / Hex 编解码。', badge: '客户端', custom: 'encoding' },
      { id: 'regex', title: '正则测试', desc: '纯客户端：实时匹配与分组捕获。', badge: '客户端', custom: 'regex' }
    ] }
  ];
  // --- runtime state ---
  var TOOLS = {};
  GROUPS.forEach(function (g) { g.tools.forEach(function (t) { t.group = g.id; TOOLS[t.id] = t; }); });
  var ctx = { externalOn: null };   // external_lookup state, detected reactively
  var caps = null;                  // /api/v1/toolkit capabilities snapshot
  var activeId = null;
  var poller = null;                // { stop: fn } for the current polling job
  var CARET = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"></path></svg>';

  function stopPoller() {
    if (poller && typeof poller.stop === 'function') { try { poller.stop(); } catch (e) {} }
    poller = null;
  }
  function foot(text, kind) {
    var t = $('#ntFootText'), d = $('#ntFootDot');
    if (t) t.textContent = text;
    if (d) d.style.background = kind === 'busy' ? 'var(--nt-warn)' : kind === 'err' ? 'var(--nt-crit)' : 'var(--nt-ok)';
  }
  // A capability is unavailable when the toolkit status says so; used to soft-disable
  // iperf3 / speedtest / port-mirror rather than let them fail with a raw 501.
  function capOff(name) { return caps && caps.capabilities && caps.capabilities[name] === false; }

  // --- sidebar: the shared desktop rail (dwrt-rail.css, spec §9) ---
  // Collapsible groups of icon-tile items, like the 系统设置 rail. Each tool gets a Lucide
  // glyph for its tile (all names verified against the bundled lucide v1.25.0).
  var TOOL_ICON = {
    ping: 'activity', traceroute: 'route', dns: 'globe', portscan: 'scan-search', portcheck: 'plug-zap',
    localports: 'cable', localinfo: 'info', publicip: 'earth', whois: 'id-card', ipgeo: 'map-pin',
    httprequest: 'send', websitecheck: 'monitor-check', sslcheck: 'shield-check', headers: 'list-checks',
    arpscan: 'radar', wol: 'power', maclookup: 'fingerprint', mdns: 'radio-tower', speedtest: 'gauge',
    iperf3: 'arrow-left-right', mtu: 'ruler', latency: 'timer', routercheck: 'stethoscope',
    portmirror: 'copy', ddns: 'link', subnetcalc: 'calculator', encoding: 'binary', regex: 'regex'
  };
  function buildSidebar() {
    var nav = $('#ntNav'); if (!nav) return;
    var html = GROUPS.map(function (g) {
      var tools = g.tools.map(function (t) {
        var tag = t.badge ? '<span class="dwrt-rail-item-meta' + (t.external ? ' is-ext' : '') + '">' + esc(t.badge) + '</span>' : '';
        return '<button type="button" class="dwrt-rail-item" data-tool="' + esc(t.id) + '" data-search="' +
          esc(t.title + ' ' + (t.desc || '') + ' ' + g.title) + '" title="' + esc(t.desc || t.title) + '">' +
          '<span class="dwrt-rail-item-icon" aria-hidden="true"><i data-lucide="' + (TOOL_ICON[t.id] || 'wrench') + '"></i></span>' +
          '<span class="dwrt-rail-item-text"><span class="dwrt-rail-item-title">' + esc(t.title) + '</span></span>' + tag + '</button>';
      }).join('');
      return '<div class="dwrt-rail-group" data-group="' + esc(g.id) + '">' +
        '<button type="button" class="dwrt-rail-group-head" data-group-head="' + esc(g.id) + '" aria-expanded="true">' +
        '<span class="dwrt-rail-group-caret" aria-hidden="true">' + CARET + '</span>' + esc(g.title) +
        '<span class="dwrt-rail-group-count">' + g.tools.length + '</span></button>' +
        '<div class="dwrt-rail-group-items">' + tools + '</div></div>';
    }).join('') + '<p class="dwrt-rail-empty" id="ntNavEmpty" hidden>未找到工具</p>';
    nav.innerHTML = html;
    relucide();
    var total = Object.keys(TOOLS).length;
    foot(total + ' 个工具 · 就绪');
  }
  function setActive(id) {
    var nav = $('#ntNav'); if (!nav) return;
    Array.prototype.forEach.call(nav.querySelectorAll('.dwrt-rail-item[data-tool]'), function (b) {
      var on = b.getAttribute('data-tool') === id;
      b.classList.toggle('is-active', on);
      if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
    });
  }
  // Rail search pill: filter tools by title/description/group; groups with no hit hide,
  // groups with a hit open so the match is visible.
  function filterSidebar(query) {
    var nav = $('#ntNav'); if (!nav) return;
    var q = String(query || '').trim().toLowerCase(), shown = 0;
    Array.prototype.forEach.call(nav.querySelectorAll('.dwrt-rail-group'), function (g) {
      var hits = 0;
      Array.prototype.forEach.call(g.querySelectorAll('.dwrt-rail-item[data-tool]'), function (b) {
        var hit = !q || (b.getAttribute('data-search') || '').toLowerCase().indexOf(q) !== -1;
        b.hidden = !hit;
        if (hit) hits += 1;
      });
      g.hidden = !hits;
      if (q && hits) { g.classList.remove('is-collapsed'); g.querySelector('.dwrt-rail-group-head').setAttribute('aria-expanded', 'true'); }
      shown += hits;
    });
    var empty = $('#ntNavEmpty'); if (empty) empty.hidden = shown !== 0;
  }
  // --- form field rendering ---
  function fieldHtml(f) {
    var wide = f.wide ? ' is-wide' : '';
    var help = f.help ? ' <span class="nt-label-help">' + esc(f.help) + '</span>' : '';
    var req = f.required ? ' <span class="req">*</span>' : '';
    var val = f.def != null ? f.def : '';
    if (f.type === 'checkbox') {
      return '<label class="nt-field nt-check' + wide + '"><input type="checkbox" data-field="' + esc(f.name) + '"' +
        (f.def ? ' checked' : '') + '><span class="nt-label">' + esc(f.label) + help + '</span></label>';
    }
    var label = '<label class="nt-label" for="ntf_' + esc(f.name) + '">' + esc(f.label) + req + help + '</label>';
    var ctrl;
    if (f.type === 'select') {
      ctrl = '<select class="nt-select" id="ntf_' + esc(f.name) + '" data-field="' + esc(f.name) + '">' +
        (f.options || []).map(function (o) {
          var ov = typeof o === 'object' ? o.value : o, ol = typeof o === 'object' ? o.label : o;
          return '<option value="' + esc(ov) + '"' + (String(ov) === String(val) ? ' selected' : '') + '>' + esc(ol) + '</option>';
        }).join('') + '</select>';
    } else if (f.type === 'textarea') {
      ctrl = '<textarea class="nt-textarea" id="ntf_' + esc(f.name) + '" data-field="' + esc(f.name) + '"' +
        (f.placeholder ? ' placeholder="' + esc(f.placeholder) + '"' : '') + '>' + esc(val) + '</textarea>';
    } else {
      ctrl = '<input class="nt-input" id="ntf_' + esc(f.name) + '" data-field="' + esc(f.name) + '"' +
        ' type="' + (f.type === 'number' ? 'number' : 'text') + '" value="' + esc(val) + '"' +
        (f.placeholder ? ' placeholder="' + esc(f.placeholder) + '"' : '') +
        (f.min != null ? ' min="' + esc(f.min) + '"' : '') + (f.max != null ? ' max="' + esc(f.max) + '"' : '') + '>';
    }
    return '<div class="nt-field' + wide + '">' + label + ctrl + '</div>';
  }
  // Read the form back into a plain object; number fields coerce, empties drop.
  function collectForm(root, fields) {
    var out = {}, missing = null;
    (fields || []).forEach(function (f) {
      var el = root.querySelector('[data-field="' + f.name + '"]');
      if (!el) return;
      if (f.type === 'checkbox') { out[f.name] = !!el.checked; return; }
      var v = String(el.value == null ? '' : el.value).trim();
      if (v === '') { if (f.required && !missing) missing = f.label; return; }
      out[f.name] = (f.type === 'number') ? Number(v) : v;
      if (f.type === 'number' && !isFinite(out[f.name])) { if (!missing) missing = f.label; delete out[f.name]; }
    });
    return { values: out, missing: missing };
  }

  // --- generic pane (header + optional disclosure + input card + result card) ---
  function paneHead(tool) {
    var badge = tool.badge ? ' <span class="nt-tool-tag' + (tool.external ? ' is-ext' : '') + '" style="margin-left:8px">' + esc(tool.badge) + '</span>' : '';
    var out = '<div class="nt-head"><div class="nt-head-title">' + esc(tool.title) + badge + '</div>' +
      '<p class="nt-head-desc">' + esc(tool.desc || '') + '</p>';
    if (tool.external) {
      out += '<div class="nt-disclose">' +
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01"></path><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path></svg>' +
        '<span>此工具会向第三方发起外部请求。若管理员在 <code>[toolkit] external_lookup</code> 关闭了外呼，将返回提示而不发起请求。</span></div>';
    }
    return out + '</div>';
  }
  function resultCard() {
    return '<div class="nt-card" id="ntResultCard"><div class="nt-card-title">结果</div>' +
      '<div class="nt-result" id="ntResult"><div class="nt-result-empty">尚未执行</div></div></div>';
  }
  function showResult(html) { var r = $('#ntResult'); if (r) r.innerHTML = html; relucide(); }
  function showOverlay(text) {
    var card = $('#ntResultCard'); if (!card) return;
    var o = document.createElement('div'); o.className = 'nt-overlay'; o.id = 'ntOverlay';
    o.innerHTML = '<div class="nt-spinner"></div><span>' + esc(text || '执行中…') + '</span>';
    card.appendChild(o);
  }
  function hideOverlay() { var o = $('#ntOverlay'); if (o && o.parentNode) o.parentNode.removeChild(o); }
  function relucide() { if (window.lucide && window.lucide.createIcons) { try { window.lucide.createIcons(); } catch (e) {} } }
  // --- open a tool into the main pane ---
  function openTool(id) {
    var t = TOOLS[id]; if (!t) return;
    stopPoller();
    activeId = id; setActive(id);
    var main = $('#ntMain'), empty = $('#ntEmpty');
    if (empty) empty.style.display = 'none';
    if (t.custom) {
      main.innerHTML = paneHead(t) + '<div id="ntCustom"></div>';
      relucide();
      CUSTOM[t.custom] && CUSTOM[t.custom](t);
      return;
    }
    var fields = t.fields || [];
    var form = fields.length ? '<div class="nt-form">' + fields.map(fieldHtml).join('') + '</div>' : '';
    var runLabel = t.mode === 'ping' ? '开始探测' : t.mount && !fields.length ? '刷新' : '执行';
    var card = '<div class="nt-card" id="ntInputCard"><div class="nt-card-title">参数</div>' + form +
      '<div class="nt-actions"><button type="button" class="nt-btn" id="ntRun">' + runLabel + '</button>' +
      '<button type="button" class="nt-btn is-ghost" id="ntStop" hidden>停止</button>' +
      '<span class="nt-btn-hint" id="ntHint"></span></div></div>';
    main.innerHTML = paneHead(t) + card + resultCard();
    relucide();
    var runBtn = $('#ntRun');
    runBtn.addEventListener('click', function () { dispatchRun(t); });
    var inputCard = $('#ntInputCard');
    inputCard.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && e.target && e.target.tagName !== 'TEXTAREA') { e.preventDefault(); dispatchRun(t); }
    });
    if (t.mount) dispatchRun(t);
  }
  function dispatchRun(tool) {
    if (tool.mode === 'ping') return runPing(tool);
    if (tool.mode === 'job') return; // job tools are custom panels
    return runStandard(tool);
  }
  function setRunning(on, label) {
    var b = $('#ntRun'); if (!b) return;
    b.disabled = on;
    b.innerHTML = on ? '<span class="nt-btn-spinner"></span>' + esc(label || '执行中…') : b.getAttribute('data-label') || b.textContent;
  }
  function buildBody(tool, values) { return tool.build ? tool.build(values) : values; }
  function toQuery(obj) {
    var parts = [];
    Object.keys(obj || {}).forEach(function (k) {
      var v = obj[k]; if (v == null || v === '' || v === false) return;
      parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(v));
    });
    return parts.length ? '?' + parts.join('&') : '';
  }
  // --- generic one-shot executor ---
  function runStandard(tool) {
    var card = $('#ntInputCard');
    var got = collectForm(card, tool.fields);
    if (got.missing) { toast('请填写：' + got.missing); return; }
    var body = buildBody(tool, got.values);
    var method = (tool.method || 'POST').toUpperCase();
    var url = tool.endpoint, opts = {};
    if (method === 'GET') { url += toQuery(body); opts = { method: 'GET' }; }
    else { opts = { method: method, body: JSON.stringify(body) }; }
    var runBtn = $('#ntRun'); if (runBtn) runBtn.setAttribute('data-label', runBtn.textContent);
    setRunning(true); showOverlay('执行中…'); foot(tool.title + '…', 'busy');
    apiJson(url, opts).then(function (j) {
      var data = dataOf(j);
      showResult(tool.render ? tool.render(data, ctx) : autoRender(data));
      foot('完成 · ' + tool.title);
    }).catch(function (err) {
      showResult(errorBox(err));
      foot('失败 · ' + tool.title, 'err');
    }).then(function () { setRunning(false); hideOverlay(); });
  }
  function clamp(v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; }
  function toggleStop(on, fn) {
    var s = $('#ntStop'); if (!s) return;
    s.hidden = !on;
    s.onclick = on ? function () { if (fn) fn(); } : null;
  }
  // --- ping: async cache-poll (re-POST until has_result && !refreshing) ---
  function runPing(tool) {
    var card = $('#ntInputCard');
    var got = collectForm(card, tool.fields);
    if (got.missing) { toast('请填写：' + got.missing); return; }
    var alive = true, tries = 0, MAX = 24;
    poller = { stop: function () { alive = false; toggleStop(false); } };
    setRunning(true, '探测中…'); toggleStop(true, function () { stopPoller(); setRunning(false); foot('已停止 · ' + tool.title); });
    foot(tool.title + '…', 'busy');
    function tick() {
      if (!alive) return;
      tries++;
      apiJson(tool.endpoint, { method: 'POST', body: JSON.stringify(got.values) }).then(function (j) {
        if (!alive) return;
        var d = dataOf(j);
        showResult(tool.render(d, ctx));
        var done = d.has_result && !d.refreshing && !d.pending;
        if (done || tries >= MAX) {
          alive = false; setRunning(false); toggleStop(false);
          foot((done ? '完成' : '超时') + ' · ' + tool.title, done ? '' : 'err');
          poller = null;
        } else {
          setTimeout(tick, d.retry_after_ms || 1200);
        }
      }).catch(function (err) {
        if (!alive) return;
        alive = false; setRunning(false); toggleStop(false);
        showResult(errorBox(err)); foot('失败 · ' + tool.title, 'err'); poller = null;
      });
    }
    tick();
  }

  // --- custom-panel dispatch table (filled below) ---
  var CUSTOM = {};

  // --- speedtest (Cloudflare, async job with incremental gauge) ---
  function speedGauges(res, state) {
    res = res || {};
    var phase = res.phase || 'init';
    var lat = res.latency_ms, dl = res.download_mbps, ul = res.upload_mbps;
    function ring(label, num, pct, active) {
      return '<div class="nt-gauge-item' + (active ? ' is-active' : '') + '">' +
        '<div class="nt-gauge-ring" style="--pct:' + clamp(Math.round(pct || 0), 0, 100) + '">' +
        '<span class="nt-gauge-num">' + esc(num) + '</span></div>' +
        '<div class="nt-gauge-label">' + esc(label) + '</div></div>';
    }
    var done = state === 'completed' || res.done;
    var phaseText = done ? '完成' : phase === 'latency' ? '测量延迟…' : phase === 'download' ? '下载测速…' : phase === 'upload' ? '上传测速…' : '准备中…';
    return '<div class="nt-gauge">' +
      ring('延迟 (ms)', lat != null ? Math.round(lat) : '—', lat != null ? clamp(100 - lat / 2, 5, 100) : 0, phase === 'latency') +
      ring('下载 (Mbps)', dl != null ? Math.round(dl) : '—', dl != null ? dl / 10 : 0, phase === 'download') +
      ring('上传 (Mbps)', ul != null ? Math.round(ul) : '—', ul != null ? ul / 10 : 0, phase === 'upload') +
      '</div><div class="nt-phase">' + (done ? '' : '<span class="nt-btn-spinner" style="border-color:var(--nt-tint-strong);border-top-color:var(--nt-accent)"></span>') +
      '<span>' + esc(phaseText) + '</span></div>';
  }
  CUSTOM.speedtest = function (tool) {
    var host = $('#ntCustom');
    host.innerHTML = '<div class="nt-card" id="ntResultCard"><div class="nt-card-title">Cloudflare 测速</div>' +
      '<div class="nt-actions"><button type="button" class="nt-btn" id="ntSpeedGo">开始测速</button>' +
      '<button type="button" class="nt-btn is-ghost" id="ntSpeedStop" hidden>停止</button>' +
      '<span class="nt-btn-hint">依次测量延迟 → 下载 → 上传，约 30-60 秒</span></div>' +
      '<div class="nt-result" id="ntSpeedOut" style="margin-top:12px"><div class="nt-result-empty">尚未开始</div></div></div>';
    var go = $('#ntSpeedGo'), stopBtn = $('#ntSpeedStop'), out = $('#ntSpeedOut');
    if (capOff('speedtest')) { go.disabled = true; out.innerHTML = '<div class="nt-error">该设备当前不支持测速（缺少 curl/网络出口）。</div>'; return; }
    function paint(html) { out.innerHTML = html; relucide(); }
    go.addEventListener('click', function () {
      var jobId = null, alive = true;
      go.disabled = true; stopBtn.hidden = false; foot('测速中…', 'busy');
      function finish(kind, msg) {
        alive = false; go.disabled = false; stopBtn.hidden = true; poller = null;
        foot((kind === 'err' ? '失败' : '完成') + ' · 测速', kind === 'err' ? 'err' : '');
        if (msg) paint(msg);
      }
      poller = { stop: function () {
        alive = false; stopBtn.hidden = true; go.disabled = false;
        if (jobId) apiJson('/api/v1/diagnostics/speedtest/stop', { method: 'POST', body: JSON.stringify({ id: jobId }) }).catch(function () {});
      } };
      stopBtn.onclick = function () { stopPoller(); foot('已停止 · 测速'); };
      paint(speedGauges({ phase: 'init' }, 'running'));
      apiJson('/api/v1/diagnostics/speedtest', { method: 'POST', body: JSON.stringify({}) }).then(function (j) {
        var d = dataOf(j); jobId = d.id;
        if (!jobId) throw new Error('no job id');
        function poll() {
          if (!alive) return;
          apiJson('/api/v1/diagnostics/speedtest/status?id=' + encodeURIComponent(jobId), { method: 'GET' }).then(function (s) {
            if (!alive) return;
            var sd = dataOf(s), res = sd.result || {};
            paint(speedGauges(res, sd.state));
            if (sd.state === 'completed' || res.done) finish('ok');
            else setTimeout(poll, 1200);
          }).catch(function (err) { if (alive) finish('err', errorBox(err)); });
        }
        setTimeout(poll, 1000);
      }).catch(function (err) { finish('err', errorBox(err)); });
    });
  };
  // --- iperf3 throughput (our own, async job) ---
  function iperfResult(meta) {
    var res = meta.result || {};
    if (res.error) return '<div class="nt-error"><b>iperf3</b><br>' + esc(res.error) + '</div>';
    var end = res.end || {};
    var sent = (end.sum_sent || {}), recv = (end.sum_received || {});
    var toMbps = function (bps) { return bps != null ? Math.round(bps / 1e4) / 100 : null; };
    return stats([
      { label: '发送吞吐', value: toMbps(sent.bits_per_second) != null ? toMbps(sent.bits_per_second) : '—', unit: 'Mbps' },
      { label: '接收吞吐', value: toMbps(recv.bits_per_second) != null ? toMbps(recv.bits_per_second) : '—', unit: 'Mbps' },
      { label: '重传', value: sent.retransmits != null ? sent.retransmits : '—' }
    ]) + kv([
      ['模式', meta.mode], ['目标', meta.host], ['端口', meta.port], ['时长', meta.duration_s != null ? meta.duration_s + ' s' : ''],
      ['发送量', sent.bytes != null ? fmtBytes(sent.bytes) : ''], ['接收量', recv.bytes != null ? fmtBytes(recv.bytes) : '']
    ]) + (res.end ? '' : '<div class="nt-result-empty">未获得 iperf3 结果（对端不可达或被中止）</div>');
  }
  CUSTOM.iperf3 = function (tool) {
    var fields = [
      { name: 'mode', label: '模式', type: 'select', def: 'client', options: [{ value: 'client', label: '客户端 (连接对端)' }, { value: 'server', label: '服务端 (--one-off)' }] },
      { name: 'host', label: '对端主机', placeholder: 'iperf3 服务端 IP/域名', wide: true },
      { name: 'port', label: '端口', type: 'number', def: 5201 },
      { name: 'duration_s', label: '时长(s)', type: 'number', def: 10, min: 1, max: 300 },
      { name: 'parallel', label: '并发流', type: 'number', def: 1, min: 1, max: 16 },
      { name: 'ifname', label: '绑定接口(可选)' },
      { name: 'reverse', label: '反向 (下载方向)', type: 'checkbox' }
    ];
    var host = $('#ntCustom');
    host.innerHTML = '<div class="nt-card"><div class="nt-card-title">参数</div><div class="nt-form">' + fields.map(fieldHtml).join('') +
      '</div><div class="nt-actions"><button type="button" class="nt-btn" id="ntIperfGo">开始测试</button>' +
      '<button type="button" class="nt-btn is-ghost" id="ntIperfStop" hidden>停止</button>' +
      '<span class="nt-btn-hint">客户端模式需对端已运行 iperf3 -s</span></div></div>' +
      '<div class="nt-card" id="ntResultCard"><div class="nt-card-title">结果</div><div class="nt-result" id="ntIperfOut"><div class="nt-result-empty">尚未开始</div></div></div>';
    var go = $('#ntIperfGo'), stopBtn = $('#ntIperfStop'), out = $('#ntIperfOut'), form = host.querySelector('.nt-form');
    if (capOff('iperf3')) { go.disabled = true; out.innerHTML = '<div class="nt-error">该设备未安装 iperf3。</div>'; return; }
    go.addEventListener('click', function () {
      var got = collectForm(form, fields);
      if (got.values.mode === 'client' && !got.values.host) { toast('客户端模式需填写对端主机'); return; }
      var jobId = null, alive = true;
      go.disabled = true; stopBtn.hidden = false; foot('吞吐测试中…', 'busy');
      out.innerHTML = '<div class="nt-phase"><span class="nt-btn-spinner" style="border-color:var(--nt-tint-strong);border-top-color:var(--nt-accent)"></span><span>测试进行中…</span></div>';
      function done(kind, html) { alive = false; go.disabled = false; stopBtn.hidden = true; poller = null; foot((kind === 'err' ? '失败' : '完成') + ' · iperf3', kind === 'err' ? 'err' : ''); if (html) { out.innerHTML = html; relucide(); } }
      poller = { stop: function () { alive = false; stopBtn.hidden = true; go.disabled = false; if (jobId) apiJson('/api/v1/toolkit/throughput/stop', { method: 'POST', body: JSON.stringify({ id: jobId }) }).catch(function () {}); } };
      stopBtn.onclick = function () { stopPoller(); foot('已停止 · iperf3'); };
      apiJson('/api/v1/toolkit/throughput', { method: 'POST', body: JSON.stringify(got.values) }).then(function (j) {
        var d = dataOf(j); jobId = d.id; if (!jobId) throw new Error('no job id');
        function poll() {
          if (!alive) return;
          apiJson('/api/v1/toolkit/throughput/status?id=' + encodeURIComponent(jobId), { method: 'GET' }).then(function (s) {
            if (!alive) return;
            var sd = dataOf(s);
            if (sd.state === 'completed' || sd.state === 'stopped') done('ok', iperfResult(sd));
            else setTimeout(poll, 1500);
          }).catch(function (err) { if (alive) done('err', errorBox(err)); });
        }
        setTimeout(poll, 1500);
      }).catch(function (err) { done('err', errorBox(err)); });
    });
  };
  // --- port mirror (our own: list / add / delete) ---
  CUSTOM.portmirror = function (tool) {
    var host = $('#ntCustom');
    var fields = [
      { name: 'source_ifname', label: '源接口', required: true, placeholder: '如 eth0 / lan1' },
      { name: 'target_ifname', label: '目标接口', required: true, placeholder: '镜像输出接口' },
      { name: 'direction', label: '方向', type: 'select', def: 'both', options: [{ value: 'both', label: '双向' }, { value: 'ingress', label: '入向' }, { value: 'egress', label: '出向' }] }
    ];
    host.innerHTML = '<div class="nt-card"><div class="nt-card-title">新增镜像规则</div><div class="nt-form">' + fields.map(fieldHtml).join('') +
      '</div><div class="nt-actions"><button type="button" class="nt-btn" id="ntPmAdd">添加</button>' +
      '<span class="nt-btn-hint">基于 tc clsact，需内核 mirred 支持</span></div></div>' +
      '<div class="nt-card"><div class="nt-card-title">已配置规则 <button type="button" class="nt-copy" id="ntPmReload" style="position:static;float:right">刷新</button></div>' +
      '<div id="ntPmList"><div class="nt-result-empty">加载中…</div></div></div>';
    var form = host.querySelector('.nt-form'), list = $('#ntPmList');
    function load() {
      list.innerHTML = '<div class="nt-result-empty">加载中…</div>';
      apiJson('/api/v1/toolkit/port-mirror', { method: 'GET' }).then(function (j) {
        var items = dataOf(j).items || [];
        if (!items.length) { list.innerHTML = '<div class="nt-result-empty">暂无镜像规则</div>'; return; }
        list.innerHTML = '<div class="nt-rows">' + items.map(function (it) {
          return '<div class="nt-row"><div class="nt-row-main"><div class="nt-row-title">' + esc(it.source_ifname) + ' → ' + esc(it.target_ifname) + '</div>' +
            '<div class="nt-row-sub">' + esc(it.direction) + ' · ' + (it.enabled ? '已启用' : '已停用') + ' · ' + esc(it.id) + '</div></div>' +
            '<div class="nt-row-actions"><button type="button" class="nt-icon-btn is-danger" data-pm-del="' + esc(it.id) + '" title="删除">✕</button></div></div>';
        }).join('') + '</div>';
      }).catch(function (err) { list.innerHTML = errorBox(err); });
    }
    $('#ntPmReload').addEventListener('click', load);
    $('#ntPmAdd').addEventListener('click', function () {
      var got = collectForm(form, fields);
      if (got.missing) { toast('请填写：' + got.missing); return; }
      var b = $('#ntPmAdd'); b.disabled = true;
      apiJson('/api/v1/toolkit/port-mirror', { method: 'POST', body: JSON.stringify(got.values) })
        .then(function () { toast('已添加'); load(); })
        .catch(function (err) { list.innerHTML = errorBox(err); }).then(function () { b.disabled = false; });
    });
    list.addEventListener('click', function (e) {
      var id = e.target && e.target.getAttribute && e.target.getAttribute('data-pm-del');
      if (!id) return;
      apiJson('/api/v1/toolkit/port-mirror', { method: 'DELETE', body: JSON.stringify({ id: id }) })
        .then(function () { toast('已删除'); load(); }).catch(function (err) { list.innerHTML = errorBox(err); });
    });
    load();
  };
  // --- DDNS (our own: list / save / update-now / delete) ---
  CUSTOM.ddns = function (tool) {
    var host = $('#ntCustom');
    var fields = [
      { name: 'id', label: 'ID(留空=新建)', placeholder: '编辑现有条目时填写' },
      { name: 'provider', label: '服务商', required: true, placeholder: '如 cloudflare / dnspod' },
      { name: 'hostname', label: '主机名', required: true, placeholder: 'home.example.com', wide: true },
      { name: 'ifname', label: '接口(可选)', placeholder: '取该接口公网 IP' },
      { name: 'config', label: '配置 JSON', type: 'textarea', wide: true, placeholder: '{"zone_id":"...","record_id":"..."}', help: '服务商所需的非机密参数' },
      { name: 'credentials', label: '凭据 JSON(可选)', type: 'textarea', wide: true, placeholder: '{"token":"..."}', help: '仅在需更新时填写，加密存储' },
      { name: 'enabled', label: '启用', type: 'checkbox', def: true }
    ];
    host.innerHTML = '<div class="nt-card"><div class="nt-card-title">保存 DDNS 配置</div><div class="nt-form">' + fields.map(fieldHtml).join('') +
      '</div><div class="nt-actions"><button type="button" class="nt-btn" id="ntDdnsSave">保存</button>' +
      '<span class="nt-btn-hint">凭据经 AES-256-GCM 加密后存储；列表不回显</span></div></div>' +
      '<div class="nt-card"><div class="nt-card-title">已配置条目 <button type="button" class="nt-copy" id="ntDdnsReload" style="position:static;float:right">刷新</button></div>' +
      '<div id="ntDdnsList"><div class="nt-result-empty">加载中…</div></div></div>';
    var form = host.querySelector('.nt-form'), list = $('#ntDdnsList');
    function load() {
      list.innerHTML = '<div class="nt-result-empty">加载中…</div>';
      apiJson('/api/v1/toolkit/ddns', { method: 'GET' }).then(function (j) {
        var items = dataOf(j).items || [];
        if (!items.length) { list.innerHTML = '<div class="nt-result-empty">暂无 DDNS 条目</div>'; return; }
        list.innerHTML = '<div class="nt-rows">' + items.map(function (it) {
          var sub = [it.provider, it.enabled ? '已启用' : '已停用', it.credentials_set ? '含凭据' : '无凭据'];
          if (it.last_address) sub.push('IP ' + it.last_address);
          if (it.last_error) sub.push('错误: ' + it.last_error);
          return '<div class="nt-row"><div class="nt-row-main"><div class="nt-row-title">' + esc(it.hostname || it.id) + '</div>' +
            '<div class="nt-row-sub">' + esc(sub.join(' · ')) + '</div></div>' +
            '<div class="nt-row-actions"><button type="button" class="nt-btn is-ghost" data-ddns-upd="' + esc(it.id) + '">立即更新</button>' +
            '<button type="button" class="nt-icon-btn is-danger" data-ddns-del="' + esc(it.id) + '" title="删除">✕</button></div></div>';
        }).join('') + '</div>';
      }).catch(function (err) { list.innerHTML = errorBox(err); });
    }
    // NT_DDNS_HANDLERS
    $('#ntDdnsReload').addEventListener('click', load);
    $('#ntDdnsSave').addEventListener('click', function () {
      var got = collectForm(form, fields);
      if (got.missing) { toast('请填写：' + got.missing); return; }
      var v = got.values, body = { provider: v.provider, hostname: v.hostname, enabled: v.enabled !== false };
      if (v.id) body.id = v.id;
      if (v.ifname) body.ifname = v.ifname;
      try { if (v.config) body.config = JSON.parse(v.config); } catch (e) { toast('配置 JSON 格式错误'); return; }
      try { if (v.credentials) body.credentials = JSON.parse(v.credentials); } catch (e) { toast('凭据 JSON 格式错误'); return; }
      var b = $('#ntDdnsSave'); b.disabled = true;
      apiJson('/api/v1/toolkit/ddns', { method: 'POST', body: JSON.stringify(body) })
        .then(function () { toast('已保存'); load(); }).catch(function (err) { list.innerHTML = errorBox(err); })
        .then(function () { b.disabled = false; });
    });
    list.addEventListener('click', function (e) {
      var id = e.target && e.target.getAttribute && e.target.getAttribute('data-ddns-upd');
      if (!id) return;
      var btn = e.target; btn.disabled = true; btn.textContent = '更新中…';
      apiJson('/api/v1/toolkit/ddns/update', { method: 'POST', body: JSON.stringify({ id: id }) })
        .then(function (j) { var d = dataOf(j); toast('已更新' + (d.address ? '：' + d.address : '')); load(); })
        .catch(function (err) { list.innerHTML = errorBox(err); });
    });
    list.addEventListener('click', function (e) {
      var id = e.target && e.target.getAttribute && e.target.getAttribute('data-ddns-del');
      if (!id) return;
      apiJson('/api/v1/toolkit/ddns', { method: 'DELETE', body: JSON.stringify({ id: id }) })
        .then(function () { toast('已删除'); load(); }).catch(function (err) { list.innerHTML = errorBox(err); });
    });
    load();
  };
  // --- client-only: subnet calculator (IPv4) ---
  function ip2int(s) {
    var p = s.split('.'); if (p.length !== 4) return null;
    var n = 0;
    for (var i = 0; i < 4; i++) { var o = Number(p[i]); if (!/^\d+$/.test(p[i]) || o < 0 || o > 255) return null; n = (n * 256) + o; }
    return n >>> 0;
  }
  function int2ip(n) { n = n >>> 0; return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'); }
  CUSTOM.subnetcalc = function (tool) {
    var host = $('#ntCustom');
    host.innerHTML = '<div class="nt-card"><div class="nt-card-title">CIDR 输入</div>' +
      '<div class="nt-form"><div class="nt-field is-wide"><label class="nt-label" for="ntSnIn">CIDR <span class="nt-label-help">仅 IPv4</span></label>' +
      '<input class="nt-input" id="ntSnIn" value="192.168.1.0/24" placeholder="192.168.1.0/24"></div></div>' +
      '<div class="nt-actions"><button type="button" class="nt-btn" id="ntSnGo">计算</button></div></div>' +
      '<div class="nt-card"><div class="nt-card-title">结果</div><div id="ntSnOut"><div class="nt-result-empty">输入 CIDR 后计算</div></div></div>';
    var inp = $('#ntSnIn'), out = $('#ntSnOut');
    function calc() {
      var m = String(inp.value || '').trim().match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
      if (!m) { out.innerHTML = '<div class="nt-error">格式应为 a.b.c.d/n（如 192.168.1.0/24）。</div>'; return; }
      var ip = ip2int(m[1]), n = Number(m[2]);
      if (ip == null || n < 0 || n > 32) { out.innerHTML = '<div class="nt-error">IP 或前缀长度无效。</div>'; return; }
      var mask = n === 0 ? 0 : (0xFFFFFFFF << (32 - n)) >>> 0;
      var net = (ip & mask) >>> 0, bc = (net | (~mask >>> 0)) >>> 0;
      var total = Math.pow(2, 32 - n);
      var usable = n >= 31 ? (n === 32 ? 1 : 2) : total - 2;
      var first = n >= 31 ? net : (net + 1) >>> 0, last = n >= 31 ? bc : (bc - 1) >>> 0;
      out.innerHTML = stats([
        { label: '可用主机', value: usable.toLocaleString() },
        { label: '总地址', value: total.toLocaleString() },
        { label: '前缀', value: '/' + n }
      ]) + kv([
        ['网络地址', int2ip(net)], ['广播地址', int2ip(bc)], ['子网掩码', int2ip(mask)],
        ['通配符掩码', int2ip(~mask >>> 0)], ['可用范围', int2ip(first) + ' – ' + int2ip(last)],
        ['CIDR', int2ip(net) + '/' + n]
      ]);
    }
    $('#ntSnGo').addEventListener('click', calc);
    inp.addEventListener('input', calc);
    calc();
  };
  // --- client-only: encoding (Base64 / URL / Hex) ---
  function b64enc(s) { return btoa(unescape(encodeURIComponent(s))); }
  function b64dec(s) { return decodeURIComponent(escape(atob(s.replace(/\s+/g, '')))); }
  function hexenc(s) { var b = unescape(encodeURIComponent(s)), o = ''; for (var i = 0; i < b.length; i++) o += ('0' + b.charCodeAt(i).toString(16)).slice(-2); return o; }
  function hexdec(s) { s = s.replace(/[^0-9a-fA-F]/g, ''); var o = ''; for (var i = 0; i < s.length; i += 2) o += String.fromCharCode(parseInt(s.substr(i, 2), 16)); return decodeURIComponent(escape(o)); }
  var ENC_OPS = {
    'base64-encode': b64enc, 'base64-decode': b64dec,
    'url-encode': encodeURIComponent, 'url-decode': decodeURIComponent,
    'hex-encode': hexenc, 'hex-decode': hexdec
  };
  CUSTOM.encoding = function (tool) {
    var host = $('#ntCustom');
    var opts = [['base64-encode', 'Base64 编码'], ['base64-decode', 'Base64 解码'], ['url-encode', 'URL 编码'], ['url-decode', 'URL 解码'], ['hex-encode', 'Hex 编码'], ['hex-decode', 'Hex 解码']];
    host.innerHTML = '<div class="nt-card"><div class="nt-card-title">编码转换</div><div class="nt-form">' +
      '<div class="nt-field"><label class="nt-label" for="ntEncOp">操作</label><select class="nt-select" id="ntEncOp">' +
      opts.map(function (o) { return '<option value="' + o[0] + '">' + o[1] + '</option>'; }).join('') + '</select></div>' +
      '<div class="nt-field is-wide"><label class="nt-label" for="ntEncIn">输入</label><textarea class="nt-textarea" id="ntEncIn" placeholder="在此输入文本"></textarea></div>' +
      '</div></div><div class="nt-card"><div class="nt-card-title">输出</div><div id="ntEncOut"><div class="nt-result-empty">输入文本后自动转换</div></div></div>';
    var op = $('#ntEncOp'), inp = $('#ntEncIn'), out = $('#ntEncOut');
    function run() {
      var s = inp.value; if (s === '') { out.innerHTML = '<div class="nt-result-empty">输入文本后自动转换</div>'; return; }
      try { out.innerHTML = codeBlock(ENC_OPS[op.value](s), ''); relucide(); }
      catch (e) { out.innerHTML = '<div class="nt-error">转换失败：输入不是合法的 ' + esc(op.value.split('-')[0]) + ' 数据。</div>'; }
    }
    op.addEventListener('change', run); inp.addEventListener('input', run);
  };
  // --- client-only: regex tester ---
  CUSTOM.regex = function (tool) {
    var host = $('#ntCustom');
    host.innerHTML = '<div class="nt-card"><div class="nt-card-title">正则表达式</div><div class="nt-form">' +
      '<div class="nt-field is-wide"><label class="nt-label" for="ntRxP">模式</label><input class="nt-input" id="ntRxP" placeholder="\\b\\w+@\\w+\\.\\w+\\b"></div>' +
      '<div class="nt-field"><label class="nt-label" for="ntRxF">标志 <span class="nt-label-help">如 gi</span></label><input class="nt-input" id="ntRxF" value="g" placeholder="gimsuy"></div>' +
      '<div class="nt-field is-wide"><label class="nt-label" for="ntRxT">测试文本</label><textarea class="nt-textarea" id="ntRxT" placeholder="在此粘贴要匹配的文本"></textarea></div>' +
      '</div></div><div class="nt-card"><div class="nt-card-title">匹配结果</div><div id="ntRxOut"><div class="nt-result-empty">输入模式与文本后自动匹配</div></div></div>';
    var p = $('#ntRxP'), f = $('#ntRxF'), t = $('#ntRxT'), out = $('#ntRxOut');
    function run() {
      var pat = p.value, txt = t.value;
      if (!pat) { out.innerHTML = '<div class="nt-result-empty">请输入正则模式</div>'; return; }
      var flags = (f.value || '').replace(/[^gimsuy]/g, '');
      var re; try { re = new RegExp(pat, flags); } catch (e) { out.innerHTML = '<div class="nt-error"><b>无效正则</b><br>' + esc(e.message) + '</div>'; return; }
      var rows = [], m, guard = 0;
      if (flags.indexOf('g') >= 0) {
        while ((m = re.exec(txt)) !== null) {
          rows.push(m); if (m.index === re.lastIndex) re.lastIndex++;
          if (++guard > 5000) break;
        }
      } else { m = re.exec(txt); if (m) rows.push(m); }
      if (!rows.length) { out.innerHTML = stats([{ label: '匹配数', value: 0 }]) + '<div class="nt-result-empty">无匹配</div>'; return; }
      var trows = rows.map(function (mm, i) {
        var groups = mm.length > 1 ? mm.slice(1).map(function (g, gi) { return (gi + 1) + ':' + (g == null ? '∅' : g); }).join('  ') : '—';
        return { n: i + 1, index: mm.index, match: mm[0], groups: groups };
      });
      out.innerHTML = stats([{ label: '匹配数', value: rows.length }, { label: '标志', value: flags || '（无）' }]) +
        table([{ key: 'n', label: '#' }, { key: 'index', label: '位置' }, { key: 'match', label: '匹配' }, { key: 'groups', label: '分组' }], trows);
    }
    [p, f, t].forEach(function (el) { el.addEventListener('input', run); });
  };
  // --- copy-to-clipboard (delegated; buttons carry data-copy=<span id>) ---
  function wireCopy() {
    document.addEventListener('click', function (e) {
      var btn = e.target && e.target.closest ? e.target.closest('[data-copy]') : null;
      if (!btn) return;
      var el = document.getElementById(btn.getAttribute('data-copy'));
      if (!el) return;
      var text = el.textContent || '';
      var ok = function () { toast('已复制'); };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(ok, function () { fallbackCopy(text); });
      else fallbackCopy(text);
    });
  }
  function fallbackCopy(text) {
    try {
      var ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); toast('已复制');
    } catch (e) { toast('复制失败'); }
  }
  // --- nav interactions ---
  function wireNav() {
    var nav = $('#ntNav'); if (!nav) return;
    nav.addEventListener('click', function (e) {
      var head = e.target.closest ? e.target.closest('.dwrt-rail-group-head') : null;
      if (head) {
        var collapsed = head.parentNode.classList.toggle('is-collapsed');
        head.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
        return;
      }
      var tool = e.target.closest ? e.target.closest('.dwrt-rail-item[data-tool]') : null;
      if (tool) openTool(tool.getAttribute('data-tool'));
    });
    var search = $('#ntSearch');
    if (search) search.addEventListener('input', function () { filterSidebar(search.value); });
  }
  // --- capability probe (soft-disables iperf3/speedtest/port-mirror) ---
  function probeCaps() {
    apiJson('/api/v1/toolkit', { method: 'GET' }).then(function (j) { caps = dataOf(j); }).catch(function () { caps = null; });
  }
  // --- lifecycle: never leave a poller running in the background ---
  function wireLifecycle() {
    window.addEventListener('pagehide', stopPoller);
    document.addEventListener('visibilitychange', function () { if (document.hidden) stopPoller(); });
  }
  function init() {
    buildSidebar();
    wireNav();
    wireCopy();
    wireLifecycle();
    probeCaps();
    relucide();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
