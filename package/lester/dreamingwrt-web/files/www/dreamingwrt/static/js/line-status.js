(() => {
  'use strict';

  const DEFAULT_REFRESH_MS = 5000;
  const WAN_CONFIG_ENDPOINT = '/api/v1/network/wans';
  const SYSTEM_STATUS_ENDPOINT = '/api/v1/system/status';
  const PANELS = [
    { id: 'line-load', label: '线路负载', endpoint: '/api/v1/monitor/line-load', title: '线路负载' },
    { id: 'line-health', label: '线路健康', endpoint: '/api/v1/monitor/line-health', title: '线路健康' },
    { id: 'ipv6-load', label: 'IPv6负载', endpoint: '/api/v1/monitor/ipv6-load', title: 'IPv6负载' },
    { id: 'vpn-status', label: 'VPN负载', endpoint: '/api/v1/monitor/vpn-status', title: 'VPN负载' }
  ];
  const TAB_STORAGE_KEY = 'dreamingwrt.web.lineStatus.tab';
  const LINE_STATUS_HASH = '#/monitor/line-status';
  const VPN_PROTOCOLS = ['PPTP', 'L2TP', 'OpenVPN', 'IPSec VPN', 'IKEv2/IPSec', 'WireGuard'];
  /* The backend's liveness fact is a boolean: a WAN is present in kernel if_stats.
   * The old route-bound gauge was deliberately removed from this contract and
   * must not be used as a connection count or a presence heuristic. */
  const KERNEL_LIVENESS_FIELDS = Object.freeze(['kernel_stats_valid']);

  function fallbackEscape(value) {
    return String(value === undefined || value === null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function fallbackText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (Array.isArray(value)) {
        const nested = fallbackText(...value);
        if (nested) return nested;
        continue;
      }
      if (typeof value === 'object') {
        const nested = fallbackText(value.name, value.label, value.value, value.text, value.reason);
        if (nested) return nested;
        continue;
      }
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }

  function fallbackNumber(...values) {
    for (const value of values) {
      const num = Number(value);
      if (Number.isFinite(num)) return num;
    }
    return 0;
  }

  function create(context = {}) {
    const root = context.routePreview || document.getElementById('routePreview');
    const refreshMs = Number(context.refreshMs) || DEFAULT_REFRESH_MS;
    const escapeHtml = context.escapeHtml || fallbackEscape;
    const asArray = context.asArray || ((value) => Array.isArray(value) ? value : []);
    const firstText = context.firstText || fallbackText;
    const firstNumber = context.firstNumber || fallbackNumber;
    const formatRate = context.formatBitRate || context.formatRate || ((value) => {
      const bps = Math.max(0, Number(value) || 0) * 8;
      const units = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
      let current = bps;
      let index = 0;
      while (current >= 1000 && index < units.length - 1) {
        current /= 1000;
        index += 1;
      }
      const digits = current >= 100 || index === 0 ? 0 : current >= 10 ? 1 : 2;
      return `${current.toFixed(digits).replace(/\.0+$/, '')} ${units[index]}`;
    });
    const formatLatency = context.formatLatency || ((value) => {
      const num = Number(value);
      return Number.isFinite(num) && num > 0 ? `${Math.round(num)} ms` : '--';
    });
    const carrierMarkup = context.carrierMarkup || (() => '');
    const fetchApiResource = context.fetchApiResource || (async (name) => ({ name, ok: false, data: {}, error: new Error('fetchApiResource unavailable') }));
    const scheduleGlassCardsRender = context.scheduleGlassCardsRender || (() => {});
    const mountUiKit = context.mountUiKit || ((target) => window.DWRT_UI_KIT?.mountAll(target));
    const realtime = context.realtime || window.DWRTRealtime;
    /*
     * Shared connection-count normalizer, required rather than reimplemented
     * locally so this page cannot grow its own guess chain back. There is one
     * connection number on screen: conntrack public-address attribution.
     */
    const connTruth = context.connTruth || window.DWRTConnTruth || null;

    let page = null;

    function formatBytes(bytes) {
      const value = Math.max(0, Number(bytes) || 0);
      const units = ['B', 'KB', 'MB', 'GB', 'TB'];
      let current = value;
      let index = 0;
      while (current >= 1024 && index < units.length - 1) {
        current /= 1024;
        index += 1;
      }
      const digits = current >= 100 || index === 0 ? 0 : current >= 10 ? 1 : 2;
      return `${current.toFixed(digits).replace(/\.0+$/, '')} ${units[index]}`;
    }

    function connectionCountOf(source = {}, ...fallbacks) {
      /*
       * conntrack attribution only. The old chain reached as far as
       * `nf_conntrack_count` (a global total) and `flows`, so a WAN row could end
       * up showing a number that was never per-WAN. The shared normalizer keeps
       * the field set to names that actually mean per-WAN conntrack attribution;
       * route-bound kernel gauges are deliberately not among them.
       */
      const count = connTruth
        ? connTruth.conntrackCount(source)
        : (() => {
          for (const field of ['connections', 'conn_count', 'conntrack_count', 'active_connections', 'connection_count']) {
            if (!Object.prototype.hasOwnProperty.call(source, field)) continue;
            const num = Number(source[field]);
            if (Number.isFinite(num)) return num;
          }
          return null;
        })();
      if (count !== null) return count;
      return firstNumber(...fallbacks);
    }

    function preferredConnectionCount(primary = {}, fallback = {}) {
      const primaryCount = connectionCountOf(primary);
      const fallbackCount = connectionCountOf(fallback);
      return primaryCount > 0 || fallbackCount <= 0 ? primaryCount : fallbackCount;
    }

    function formatPercent(value, digits = 2) {
      const num = Number(value);
      if (!Number.isFinite(num)) return '--';
      return `${num.toFixed(digits).replace(/\.0+$/, '')}%`;
    }

    /*
     * 丢包读数：缺失必须保持 null，不能落成 0。
     * `firstNumber()` 对缺字段返回 0，用在丢包上会把"后端没给"画成"线路很好"，
     * 这是两个完全不同的事实。
     */
    function lossValue(...values) {
      for (const value of values) {
        if (value === undefined || value === null || value === '') continue;
        const num = Number(value);
        if (Number.isFinite(num)) return num;
      }
      return null;
    }

    function formatUptime(seconds) {
      const total = Math.max(0, Math.floor(Number(seconds) || 0));
      if (!total) return '--';
      const days = Math.floor(total / 86400);
      const hours = Math.floor((total % 86400) / 3600);
      const mins = Math.floor((total % 3600) / 60);
      if (days > 0) return `${days}天 ${hours}小时`;
      if (hours > 0) return `${hours}小时 ${mins}分钟`;
      if (mins > 0) return `${mins}分钟`;
      return `${total}秒`;
    }

    function compactAddress(value, max = 30) {
      const text = firstText(value);
      if (!text || text.length <= max) return text;
      const head = Math.max(8, Math.floor(max * 0.52));
      const tail = Math.max(6, max - head - 1);
      return `${text.slice(0, head)}…${text.slice(-tail)}`;
    }

    function isGlobalIpv6(value) {
      const text = firstText(value).toLowerCase();
      if (!text || !text.includes(':')) return false;
      return !(
        text === '::1' ||
        text.startsWith('fe80:') ||
        text.startsWith('fe90:') ||
        text.startsWith('fea0:') ||
        text.startsWith('feb0:') ||
        text.startsWith('fc') ||
        text.startsWith('fd')
      );
    }

    function firstGlobalIpv6(...values) {
      const pending = [];
      values.forEach((value) => {
        if (Array.isArray(value)) pending.push(...value);
        else pending.push(value);
      });
      for (const value of pending) {
        const text = firstText(value);
        if (isGlobalIpv6(text)) return text;
      }
      return '';
    }

    function trustedConnectionSeconds(wan = {}) {
      const candidates = [wan.connected_seconds, wan.online_seconds, wan.uptime];
      const seconds = candidates.map(Number).find((value) => Number.isFinite(value) && value > 0) || 0;
      if (!seconds) return 0;
      const sampledUptime = Number(page?.systemUptime);
      const elapsed = page?.systemUptimeAt ? Math.max(0, (Date.now() - page.systemUptimeAt) / 1000) : 0;
      const systemUptime = sampledUptime + elapsed;
      if (Number.isFinite(systemUptime) && systemUptime > 0 && seconds > systemUptime + 5) return 0;
      return seconds;
    }

    function shouldDeferRender() {
      if (typeof context.shouldDeferRender === 'function') return context.shouldDeferRender(root);
      const selection = window.getSelection && window.getSelection();
      return Boolean(selection && !selection.isCollapsed && root && root.contains(selection.anchorNode));
    }

    function panelById(id) {
      return PANELS.find((item) => item.id === id) || PANELS[0];
    }

    function validPanelId(id) {
      return PANELS.some((item) => item.id === id);
    }

    function initialPanelId() {
      const hash = String(window.location.hash || '');
      const queryIndex = hash.indexOf('?');
      if (queryIndex >= 0) {
        try {
          const params = new URLSearchParams(hash.slice(queryIndex + 1));
          const tab = params.get('tab');
          if (validPanelId(tab)) return tab;
        } catch (_) {}
      }
      try {
        const stored = localStorage.getItem(TAB_STORAGE_KEY);
        if (validPanelId(stored)) return stored;
      } catch (_) {}
      return PANELS[0].id;
    }

    function persistPanelId(panelId) {
      if (!validPanelId(panelId)) return;
      try {
        localStorage.setItem(TAB_STORAGE_KEY, panelId);
      } catch (_) {}
      const currentHash = String(window.location.hash || LINE_STATUS_HASH);
      const routeHash = currentHash.split('?')[0] || LINE_STATUS_HASH;
      if (!routeHash.includes('/monitor/line-status')) return;
      const nextHash = `${routeHash}?tab=${encodeURIComponent(panelId)}`;
      if (currentHash === nextHash) return;
      history.replaceState(null, '', `${location.pathname}${location.search}${nextHash}`);
    }

    function listFrom(data, keys) {
      if (Array.isArray(data)) return data;
      if (!data || typeof data !== 'object') return [];
      for (const key of keys) {
        if (Array.isArray(data[key])) return data[key];
      }
      return [];
    }

    function normalizeTrafficLine(line = {}, index = 0, fallbackType = '', options = {}) {
      const explicitType = String(firstText(line.type, line.family)).toLowerCase();
      const nameText = String(firstText(line.name, line.ifname, line.interface, line.id)).toLowerCase();
      const deviceText = String(firstText(line.ifname, line.interface, line.device, line.physical_device)).toLowerCase();
      const typeEvidence = `${nameText} ${deviceText}`;
      const isWan = /(^|[._\-\s])wan([._\-\s]|$)/.test(typeEvidence) || typeEvidence.includes('pppoe-wan');
      const isLan = /(^|[._\-\s])lan([._\-\s]|$)/.test(typeEvidence) || typeEvidence.includes('br-lan');
      const type = explicitType || (isWan ? 'wan' : isLan ? 'lan' : fallbackType || 'lan');
      const ipv6Mode = Boolean(options.ipv6);
      return {
        id: firstText(line.id, line.wan_id, line.name, line.ifname, `${type || 'line'}-${index + 1}`),
        order: Number(line.order || index + 1),
        type,
        name: firstText(line.name, line.label, line.ifname, line.interface, line.id, `line${index + 1}`),
        note: firstText(line.note, line.remark, line.description, line.alias, line.device),
        ifname: firstText(line.ifname, line.interface),
        device: firstText(line.device, line.physical_device),
        carrier_key: firstText(line.carrier_key, line.isp_key, line.operator_key, line.operator_code),
        carrier_name: firstText(line.carrier_name, line.isp_name, line.operator_name, line.provider_name),
        carrier_logo: firstText(line.carrier_logo, line.carrier_svg, line.logo, line.image, line.icon),
        carrier: firstText(line.carrier_key, line.carrier, line.carrier_name, line.isp, line.isp_name, line.provider, line.operator, line.operator_code),
        ip: firstText(
          line.ip,
          line.ipv4,
          line.ipaddr,
          line.address,
          line.public_ip,
          line.public_ipv4,
          line.wan_ip,
          line.external_ip,
          line.ipv4_address
        ),
        ipv6: firstGlobalIpv6(
          line.ipv6_global,
          line.global_ipv6,
          line.public_ipv6,
          line.wan_ipv6,
          line.ipv6_public,
          line.external_ipv6,
          line.ipv6_public_address,
          line.ipv6_global_address,
          line.ipv6_addr_global,
          line.ipv6_gua,
          line.gua,
          line.ipv6_addrs,
          line.ipv6,
          line.ipv6_addr,
          line.ipv6_address
        ),
        linkSpeed: firstText(line.link_speed, line.speed, line.speed_label),
        upRate: ipv6Mode
          ? firstNumber(line.ipv6_up_rate, line.v6_up_rate, line.ip6_up_rate, line.up_rate, line.tx_rate, line.rate_up)
          : firstNumber(line.up_rate, line.tx_rate, line.rate_up),
        upBytes: ipv6Mode
          ? firstNumber(line.ipv6_up_bytes, line.v6_up_bytes, line.ip6_up_bytes, line.up_bytes, line.tx_bytes)
          : firstNumber(line.up_bytes, line.tx_bytes),
        downRate: ipv6Mode
          ? firstNumber(line.ipv6_down_rate, line.v6_down_rate, line.ip6_down_rate, line.down_rate, line.rx_rate, line.rate_down)
          : firstNumber(line.down_rate, line.rx_rate, line.rate_down),
        downBytes: ipv6Mode
          ? firstNumber(line.ipv6_down_bytes, line.v6_down_bytes, line.ip6_down_bytes, line.down_bytes, line.rx_bytes)
          : firstNumber(line.down_bytes, line.rx_bytes),
        connections: ipv6Mode
          ? connectionCountOf(line, line.ipv6_connections, line.v6_connections, line.ip6_connections)
          : connectionCountOf(line),
        /*
         * Source of the conntrack column, so the header/tooltip can name it
         * instead of leaving "连接数" ambiguous.
         */
        conntrack: connTruth ? connTruth.conntrackTruth(line) : null,
        /* Liveness only, never rendered. IPv6 mode gets nothing because
         * /monitor/ipv6-load carries no kernel_* nodes. */
        kernelCounted: ipv6Mode
          ? false
          : line.kernel_stats_valid === true,
        uptime: firstNumber(line.uptime, line.online_seconds),
        ipv6Only: Boolean(line.ipv6_only || line.ipv6Only || line.family === 'ipv6' || line.address_family === 'ipv6')
      };
    }

    function sortTraffic(lines) {
      return lines.slice().sort((a, b) => {
        if (a.type !== b.type) {
          if (a.type === 'lan') return -1;
          if (b.type === 'lan') return 1;
        }
        if (a.order !== b.order) return a.order - b.order;
        return String(a.name || a.id).localeCompare(String(b.name || b.id), 'zh-Hans-CN', { numeric: true });
      });
    }

    function groupTraffic(lines) {
      const ordered = ['lan', 'wan'];
      const groups = [];
      ordered.forEach((type) => {
        const items = lines.filter((line) => line.type === type);
        if (items.length) groups.push({ type, label: type.toUpperCase(), lines: items });
      });
      const rest = lines.filter((line) => !ordered.includes(line.type));
      if (rest.length) groups.push({ type: 'other', label: 'OTHER', lines: rest });
      return groups;
    }

    function lineIcon(line) {
      if (String(line.type).toLowerCase() === 'wan') return carrierMarkup(line);
      return `<span class="line-port-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="4" y="5" width="16" height="14" rx="3"></rect><path d="M8 19v-5h8v5"></path><path d="M9 9h6"></path></svg></span>`;
    }

    function carrierLabel(line) {
      const text = firstText(line.carrier_key, line.carrier, line.carrier_name, line.isp, line.provider, line.operator, line.note).toLowerCase();
      if (/unicom|china.?unicom|联通/.test(text)) return '中国联通';
      if (/mobile|cmcc|china.?mobile|移动/.test(text)) return '中国移动';
      if (/telecom|ctcc|china.?telecom|电信/.test(text)) return '中国电信';
      if (/cernet|教育网/.test(text)) return '教育网';
      return '';
    }

    function isGenericWanName(value) {
      const text = firstText(value).toLowerCase();
      return !text || /^wan\d*$/.test(text) || text === 'pppoe-wan' || text === 'dhcp-wan';
    }

    function hasUsefulNumber(...values) {
      return values.some((value) => {
        const num = Number(value);
        return Number.isFinite(num) && Math.abs(num) > 0;
      });
    }

    function hasMeaningfulHealthBucket(bucket) {
      if (!bucket || typeof bucket !== 'object') return false;
      const status = String(firstText(bucket.status, bucket.state, bucket.reason)).toLowerCase();
      if (/(ok|up|online|normal|warn|warning|bad|down|offline|unstable|loss)/.test(status)) return true;
      return hasUsefulNumber(
        bucket.latency_avg, bucket.latency, bucket.avg, bucket.ms,
        bucket.loss, bucket.packet_loss, bucket.loss_up, bucket.loss_down,
        bucket.up_loss, bucket.down_loss, bucket.samples,
        bucket.avg_up_rate, bucket.avg_down_rate
      );
    }

    function hasUsefulTrafficLine(line) {
      const type = String(line?.type || '').toLowerCase();
      if (type !== 'wan') return true;
      /*
       * A WAN the kernel is actively counting is real, even when the config
       * ledger has not caught up. wan3/wan4 were dropped this way: no rate rows
       * yet, generic name, so the placeholder filter removed them while
       * /proc/dreamingwrt/jmx was reporting thousands of flows for them. This is
       * the only remaining use of the kernel gauge, and it decides visibility
       * rather than putting a number on screen.
       */
      if (line.kernelCounted) return true;
      if (!isGenericWanName(line.name) || !isGenericWanName(line.id)) return true;
      if (firstText(line.carrier_key, line.carrier_name, line.carrier, line.carrier_logo, line.ip, line.ipv6, line.linkSpeed)) return true;
      if (firstText(line.note) && firstText(line.note) !== firstText(line.ifname)) return true;
      return hasUsefulNumber(line.upRate, line.downRate, line.upBytes, line.downBytes, line.connections, line.uptime);
    }

    function hasUsefulHealthLine(wan) {
      if (!wan) return false;
      const history = asArray(wan.history);
      const status = String(firstText(wan.status, wan.state)).toLowerCase();
      const hasIdentity = firstText(wan.carrier_key, wan.carrier_name, wan.carrier, wan.carrier_logo, wan.accessMode, wan.ip, wan.ipv6, wan.gateway);
      const hasRealHealth = hasUsefulNumber(wan.uptime, wan.upLoss24h, wan.downLoss24h, wan.latencyAvg, wan.avgUpRate, wan.avgDownRate, wan.busy) || history.some(hasMeaningfulHealthBucket);
      if (!hasIdentity && !history.length && (wan.online === false || /down|offline|false/.test(status))) return false;
      if (!isGenericWanName(wan.name) || !isGenericWanName(wan.id)) return true;
      if (hasIdentity || firstText(wan.status)) return true;
      if (firstText(wan.note) && firstText(wan.note) !== firstText(wan.ifname)) return true;
      if (wan.healthKnown && hasRealHealth) return true;
      return hasRealHealth;
    }

    function dropEmptyWanPlaceholders(rows) {
      const list = asArray(rows);
      const usefulWanCount = list.filter((line) => String(line?.type || '').toLowerCase() === 'wan' && hasUsefulTrafficLine(line)).length;
      return list.filter((line) => {
        if (String(line?.type || '').toLowerCase() !== 'wan') return true;
        if (hasUsefulTrafficLine(line)) return true;
        return usefulWanCount === 0 && list.length <= 1;
      });
    }

    function displayLineName(line, showIpv6 = false) {
      const type = String(line.type || '').toLowerCase();
      if (type === 'wan' && (showIpv6 || isGenericWanName(line.name))) {
        return firstText(carrierLabel(line), isGenericWanName(line.name) ? '' : line.name, `WAN${line.order || ''}`) || 'WAN';
      }
      return firstText(line.name, line.id, '--');
    }

    function lineName(line, showIpv6 = false) {
      const address = showIpv6
        ? line.ipv6
        : line.ip;
      const type = String(line.type || '').toLowerCase();
      const detail = type === 'wan'
        ? ''
        : firstText(line.note, line.ifname, line.device);
      const subline = [detail, address].filter(Boolean).join(' · ');
      return `<span class="line-load-name">
        ${lineIcon(line)}
        <span>
          <strong>${escapeHtml(displayLineName(line, showIpv6))}</strong>
          <small data-line-tooltip="${escapeHtml(subline || '--')}" tabindex="0">${escapeHtml(subline || '--')}</small>
        </span>
      </span>`;
    }

    /*
     * conntrack attribution cell. The count keeps its historical position, but the
     * tooltip names the source so it can no longer be read as "all connections on
     * this WAN".
     */
    function conntrackCellMarkup(line) {
      const truth = line.conntrack;
      const count = truth && truth.valid ? truth.count : line.connections;
      const parts = [];
      if (truth) {
        if (truth.source) parts.push(`来源 ${truth.source}`);
        if (truth.state) parts.push(`状态 ${truth.state}`);
        if (truth.reason) parts.push(`口径 ${truth.reason}`);
        if (truth.markMatches !== null) parts.push(`ctmark 命中 ${truth.markMatches}`);
        if (truth.localIgnored !== null) parts.push(`本机探针排除 ${truth.localIgnored}`);
      }
      const tip = parts.length ? parts.join(' · ') : 'conntrack 公网地址归属统计';
      return `<span class="line-connections" data-line-tooltip="${escapeHtml(tip)}" tabindex="0">${escapeHtml(Number(count || 0).toLocaleString('en-US'))}</span>`;
    }

    function lineLoadRows(lines, options = {}) {
      return groupTraffic(lines).flatMap((group) => group.lines).map((line) => `
        <tr class="line-load-data-row ${escapeHtml(line.type || 'line')}">
          <td data-label="线路">${lineName(line, Boolean(options.showIpv6))}</td>
          <td data-label="上行速率" class="rate-up">${escapeHtml(formatRate(line.upRate))}</td>
          <td data-label="累计上行" class="rate-up total-up">${escapeHtml(formatBytes(line.upBytes))}</td>
          <td data-label="下行速率" class="rate-down">${escapeHtml(formatRate(line.downRate))}</td>
          <td data-label="累计下行" class="rate-down total-down">${escapeHtml(formatBytes(line.downBytes))}</td>
          <td data-label="连接数">${conntrackCellMarkup(line)}</td>
        </tr>
      `).join('');
    }

    function normalizeLineLoad(data) {
      return sortTraffic(dropEmptyWanPlaceholders(listFrom(data, ['interfaces', 'items', 'lines']).map((line, index) => normalizeTrafficLine(line, index))));
    }

    function normalizeIpv6Load(data) {
      const rows = dropEmptyWanPlaceholders(listFrom(data, ['wans', 'interfaces', 'items', 'lines'])
        .map((line, index) => normalizeTrafficLine(line, index, 'wan', { ipv6: true }))
        .filter((line) => String(line.type || '').toLowerCase() === 'wan'))
        .filter((line) => line.ipv6 || line.ipv6Only);
      return sortTraffic(rows);
    }

    function computeBusy(up, down, configuredUp, configuredDown) {
      const upBusy = configuredUp > 0 ? Number(up || 0) / configuredUp : 0;
      const downBusy = configuredDown > 0 ? Number(down || 0) / configuredDown : 0;
      return Math.max(0, Math.min(100, Math.round(Math.max(upBusy, downBusy, (upBusy + downBusy) / 2) * 100)));
    }

    function normalizeHealth(data) {
      return listFrom(data, ['wans', 'items', 'lines']).map((wan, index) => {
        const avgUp = firstNumber(wan.avg_up_rate, wan.up_avg, wan.rate_up, wan.up_rate);
        const avgDown = firstNumber(wan.avg_down_rate, wan.down_avg, wan.rate_down, wan.down_rate);
        const configuredUp = firstNumber(wan.configured_up_rate, wan.capacity_up, wan.up_capacity);
        const configuredDown = firstNumber(wan.configured_down_rate, wan.capacity_down, wan.down_capacity);
        const busy = wan.busy !== undefined ? firstNumber(wan.busy) : computeBusy(avgUp, avgDown, configuredUp, configuredDown);
        return {
          id: firstText(wan.id, wan.wan_id, wan.name, wan.ifname, `wan${index + 1}`),
          order: Number(wan.order || index + 1),
          name: firstText(wan.name, wan.label, wan.ifname, `wan${index + 1}`),
          note: firstText(wan.note, wan.remark, wan.description, wan.alias, wan.ifname),
          ifname: firstText(wan.ifname, wan.interface),
          carrier_key: firstText(wan.carrier_key, wan.isp_key, wan.operator_key, wan.operator_code),
          carrier_name: firstText(wan.carrier_name, wan.isp_name, wan.operator_name, wan.provider_name),
          carrier_logo: firstText(wan.carrier_logo, wan.carrier_svg, wan.logo, wan.image, wan.icon),
          carrier: firstText(wan.carrier_key, wan.carrier, wan.carrier_name, wan.isp),
          accessMode: firstText(wan.access_mode, wan.proto, wan.protocol, wan.internet),
          ip: firstText(wan.ip, wan.ipv4, wan.ipaddr),
          ipv6: firstGlobalIpv6(wan.ipv6_global, wan.global_ipv6, wan.public_ipv6, wan.wan_ipv6, wan.ipv6_addrs, wan.ipv6, wan.ipv6_addr, wan.ipv6_address),
          gateway: firstText(wan.gateway, wan.gw),
          status: firstText(wan.status, wan.state),
          online: typeof wan.online === 'boolean' ? wan.online : undefined,
          healthKnown: wan.health !== undefined || wan.health_measured !== undefined || wan.online !== undefined || wan.status !== undefined || wan.state !== undefined,
          uptime: trustedConnectionSeconds(wan),
          upLoss24h: firstNumber(wan.up_loss_24h, wan.loss_up_24h, wan.loss_up, wan.packet_loss_up, wan.packet_loss),
          downLoss24h: firstNumber(wan.down_loss_24h, wan.loss_down_24h, wan.loss_down, wan.packet_loss_down, wan.packet_loss),
          /*
           * 单一丢包读数：上下行同源于一次 ping，取二者中有值的较大者即可，
           * 全缺时保持 null 以便渲染成「不可用」而不是 0%。
           */
          loss24h: (() => {
            const up = lossValue(wan.up_loss_24h, wan.loss_up_24h, wan.loss_up, wan.packet_loss_up, wan.packet_loss);
            const down = lossValue(wan.down_loss_24h, wan.loss_down_24h, wan.loss_down, wan.packet_loss_down, wan.packet_loss);
            if (up === null) return down;
            if (down === null) return up;
            return Math.max(up, down);
          })(),
          lossSource: firstText(wan.loss_source),
          lossSamples: lossValue(wan.loss_sample_count),
          latencyAvg: firstNumber(wan.latency_avg, wan.avg_latency, wan.latency),
          avgUpRate: avgUp,
          avgDownRate: avgDown,
          busy,
          history: asArray(wan.status_history || wan.health_history || wan.history)
        };
      }).filter((wan) => {
        if (!hasUsefulHealthLine(wan)) return false;
        if (!page?.configuredWanKeys?.size) return true;
        return [wan.id, wan.ifname, wan.name]
          .map((value) => firstText(value).toLowerCase())
          .filter(Boolean)
          .some((key) => page.configuredWanKeys.has(key));
      }).sort((a, b) => a.order - b.order);
    }

    function healthTone(wan = {}) {
      const status = String(firstText(wan.status, wan.state)).toLowerCase();
      const offline = wan.online === false || /^(down|offline|bad|error|failed)$/.test(status);
      const latency = firstNumber(wan.latencyAvg, wan.latency, wan.latency_ms);
      const loss = Math.max(firstNumber(wan.upLoss24h, wan.loss_up, wan.loss), firstNumber(wan.downLoss24h, wan.loss_down, wan.loss));
      if (offline || loss > 20 || latency >= 300) return 'bad';
      if (loss > 3 || latency >= 120) return 'warn';
      return 'ok';
    }

    function healthClass(wan) {
      const tone = healthTone(wan);
      if (tone === 'bad') return 'health-bad';
      if (tone === 'warn') return 'health-warn';
      return 'health-good';
    }

    function healthHistoryBuckets(wan = {}) {
      return asArray(wan.history).slice(-48);
    }

    function healthBucketTone(bucket = {}) {
      if (!bucket || typeof bucket !== 'object' || bucket.synthetic || bucket.current_status_only) return 'muted';
      const status = String(firstText(bucket.status, bucket.state, bucket.health)).toLowerCase();
      const latency = firstNumber(bucket.latency_avg, bucket.latency, bucket.avg_latency, bucket.avg, bucket.ms);
      const loss = Math.max(
        firstNumber(bucket.loss, bucket.packet_loss, bucket.loss_up, bucket.up_loss, bucket.packet_loss_up),
        firstNumber(bucket.loss, bucket.packet_loss, bucket.loss_down, bucket.down_loss, bucket.packet_loss_down)
      );
      if (/(bad|down|offline|unavailable|failed|error|loss)/.test(status) || loss > 20 || latency >= 300) return 'bad';
      if (/(warn|warning|degraded|unstable|latency_spike|packet_loss)/.test(status) || loss > 0 || latency >= 80) return 'warn';
      if (/(unknown|missing|pending)/.test(status)) return 'muted';
      return 'ok';
    }

    function formatHealthBucketTime(value) {
      const timestamp = Number(value);
      if (!Number.isFinite(timestamp) || timestamp <= 0) return '';
      const date = new Date(timestamp * 1000);
      if (Number.isNaN(date.getTime())) return '';
      const hour = String(date.getHours()).padStart(2, '0');
      const minute = String(date.getMinutes()).padStart(2, '0');
      return `${date.getFullYear()}年${date.getMonth() + 1}月${date.getDate()}日${hour}:${minute}`;
    }

    function healthBucketTooltip(wan = {}, bucket = {}) {
      if (!bucket || typeof bucket !== 'object' || bucket.synthetic || bucket.current_status_only) {
        return '该时间段没有可用的线路健康采样，不代表线路异常。';
      }
      const status = String(firstText(bucket.status, bucket.state, bucket.health, 'unknown')).toLowerCase();
      const latency = firstNumber(bucket.latency_avg, bucket.latency, bucket.avg_latency, bucket.avg, bucket.ms);
      /*
       * 同一个 ping 的单一 loss 值，分不出方向，所以这里也只报一个数字。
       */
      const lossUp = lossValue(bucket.loss_up, bucket.up_loss, bucket.packet_loss_up, bucket.loss, bucket.packet_loss);
      const lossDown = lossValue(bucket.loss_down, bucket.down_loss, bucket.packet_loss_down, bucket.loss, bucket.packet_loss);
      const lossMerged = lossUp === null ? lossDown : lossDown === null ? lossUp : Math.max(lossUp, lossDown);
      const samples = firstNumber(bucket.samples);
      /*
       * 每行一个语义，顺序固定：时间 / 状态 / 平均延迟 / 丢包 / 采样次数。
       * 运营商名不再占一行——同一行健康条本来就属于那条线路，重复它只是挤掉真信息。
       */
      return [
        formatHealthBucketTime(bucket.ts || bucket.timestamp || bucket.time),
        `状态：${status || 'unknown'}`,
        Number.isFinite(latency) && latency > 0 ? `平均延迟：${Math.round(latency)} ms` : '平均延迟：--',
        lossMerged === null
          ? '丢包：--'
          : `丢包（探测口径）：${formatPercent(lossMerged, 2)}`,
        samples > 0 ? `采样：${Math.round(samples)} 次` : '采样：--'
      ].filter(Boolean).join('\n');
    }

    function healthAvailability(wan = {}) {
      const tone = healthTone(wan);
      const status = String(firstText(wan.status, wan.state)).toLowerCase();
      const latency = firstNumber(wan.latencyAvg, wan.latency, wan.latency_ms);
      const loss = Math.max(firstNumber(wan.upLoss24h, wan.loss_up, wan.loss), firstNumber(wan.downLoss24h, wan.loss_down, wan.loss));
      const history = healthHistoryBuckets(wan);
      const knownBuckets = history.filter((bucket) => healthBucketTone(bucket) !== 'muted');
      const healthyBuckets = knownBuckets.filter((bucket) => healthBucketTone(bucket) === 'ok');
      const online = wan.online !== false && !/^(down|offline|bad|error|failed)$/.test(status);
      const stateLabel = !online
        ? '离线'
        : loss > 3
          ? `丢包 ${loss.toFixed(1).replace(/\.0$/, '')}%`
          : latency > 0
            ? `${Math.round(latency)} ms`
            : '正常';
      return {
        tone,
        value: knownBuckets.length ? healthyBuckets.length / knownBuckets.length * 100 : 0,
        label: knownBuckets.length ? `${(healthyBuckets.length / knownBuckets.length * 100).toFixed(2)}%` : '暂无历史',
        stateLabel,
        history
      };
    }

    function healthSummaryBar(wan) {
      const availability = healthAvailability(wan);
      const iconLine = {
        type: 'wan',
        name: wan.name,
        id: wan.id,
        carrier: wan.carrier,
        carrier_key: wan.carrier_key,
        carrier_name: wan.carrier_name,
        carrier_logo: wan.carrier_logo
      };
      const title = [
        firstText(carrierLabel(wan), displayLineName(wan), wan.ifname, wan.id, 'WAN'),
        availability.label,
        availability.stateLabel
      ].filter(Boolean).join(' · ');
      const timeline = availability.history.length
        ? availability.history.map((bucket) => {
          const bucketTone = healthBucketTone(bucket);
          const bucketTitle = healthBucketTooltip(wan, bucket);
          return `<i class="is-${escapeHtml(bucketTone)}" data-line-tooltip="${escapeHtml(bucketTitle)}"></i>`;
        }).join('')
        : '<i class="is-muted is-empty" aria-hidden="true"></i>' ;
      return `<button type="button" class="line-health-summary is-${escapeHtml(availability.tone)}" data-line-tooltip="${escapeHtml(title)}" aria-label="${escapeHtml(title)}" data-health-summary="${escapeHtml(wan.id || wan.name || 'wan')}">
        ${lineIcon(iconLine)}
        <span class="line-health-summary-track" aria-label="过去 24 小时线路健康">${timeline}</span>
        <svg class="line-health-summary-chevron" viewBox="0 0 16 16" aria-hidden="true"><path d="M6 3.5 10.5 8 6 12.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"></path></svg>
      </button>`;
    }

    /*
     * 24H 丢包单元格。
     *
     * 当前数值来自主动探测：healthd 每轮 `ping -c 3`（check_main.c:671）写入
     * wan_health_bucket，jmx_db.c:6500 再按 samples 加权出 24h 均值。因此
     * `up_loss_24h` 与 `down_loss_24h` **是同一个 ping 的同一个 loss 值**，
     * 后端从未分方向测量过。之前这里画成 ↓x% / ↑y% 两个数字，等于凭空造出
     * 方向信息，所以合并为单值展示；等后端给出真实转发口径的分方向数据
     * （见 Acceptance-to-Backend-wan-packet-loss-must-count-real-traffic-not-probes）
     * 再恢复上下行两列。
     */
    const LOSS_PROBE_TIP = '主动探测口径：每 ~13 秒 ping 3 包（223.5.5.5 / 119.29.29.29）的 24 小时加权均值，非真实转发流量丢包率';

    function healthLossCellMarkup(wan = {}) {
      const loss = lossValue(wan.loss24h);
      const parts = [LOSS_PROBE_TIP];
      if (wan.lossSource) parts.push(`来源 ${wan.lossSource}`);
      if (Number.isFinite(wan.lossSamples) && wan.lossSamples > 0) parts.push(`采样 ${Math.round(wan.lossSamples)} 次`);
      const tip = parts.join(' · ');
      if (loss === null) {
        return `<span class="line-loss-unavailable" data-line-tooltip="${escapeHtml(`${tip}；当前无采样数据`)}" tabindex="0">不可用</span>`;
      }
      return `<span class="line-loss-value" data-line-tooltip="${escapeHtml(tip)}" tabindex="0">${escapeHtml(formatPercent(loss, 2))}</span>`;
    }

    function healthRows(lines) {
      return lines.map((wan) => `
        <tr class="line-health-data-row">
          <td data-label="线路">${lineName({
            type: 'wan',
            name: wan.name,
            id: wan.id,
            note: wan.note,
            ifname: wan.ifname,
            carrier: wan.carrier,
            carrier_key: wan.carrier_key,
            carrier_name: wan.carrier_name,
            carrier_logo: wan.carrier_logo,
            ip: wan.ip,
            ipv6: wan.ipv6
          })}</td>
          <td data-label="接入方式"><span class="line-mode">${escapeHtml(wan.accessMode || '--')}</span></td>
          <td data-label="IP地址">${escapeHtml(wan.ip || '--')}</td>
          <td data-label="网关">${escapeHtml(wan.gateway || '--')}</td>
          <td data-label="连接时间">${escapeHtml(formatUptime(wan.uptime))}</td>
          <td data-label="探测丢包">${healthLossCellMarkup(wan)}</td>
          <td data-label="平均延迟" class="${healthClass(wan)}">${escapeHtml(formatLatency(wan.latencyAvg))}</td>
          <td data-label="平均带宽"><span class="rate-text"><span class="rate-down">↓ ${escapeHtml(formatRate(wan.avgDownRate))}</span><span class="rate-up">↑ ${escapeHtml(formatRate(wan.avgUpRate))}</span></span></td>
          <td data-label="繁忙度"><span class="busy-meter" style="--busy:${Math.max(0, Math.min(100, Number(wan.busy) || 0))}%"><em></em><strong>${escapeHtml(formatPercent(wan.busy, 0))}</strong></span></td>
        </tr>
        <tr class="line-health-timeline-row">
          <td colspan="9">
            ${healthSummaryBar(wan)}
          </td>
        </tr>
      `).join('');
    }

    function normalizeVpn(data) {
      const groups = {};
      VPN_PROTOCOLS.forEach((protocol) => { groups[protocol] = []; });
      const protocols = data && typeof data.protocols === 'object' ? data.protocols : {};
      Object.keys(protocols).forEach((protocol) => {
        const lines = asArray(protocols[protocol]);
        groups[protocol] = lines.map((line, index) => normalizeVpnLine(line, protocol, index));
      });
      listFrom(data, ['lines', 'items']).forEach((line, index) => {
        const protocol = firstText(line.protocol, line.type, VPN_PROTOCOLS[0]);
        if (!groups[protocol]) groups[protocol] = [];
        groups[protocol].push(normalizeVpnLine(line, protocol, index));
      });
      return VPN_PROTOCOLS.map((protocol) => ({
        protocol,
        lines: asArray(groups[protocol]).sort((a, b) => a.order - b.order)
      }));
    }

    function normalizeVpnLine(line = {}, protocol, index) {
      return {
        id: firstText(line.id, line.name, `${protocol}-${index + 1}`),
        order: Number(line.order || index + 1),
        protocol: firstText(line.protocol, protocol),
        name: firstText(line.name, line.label, line.ifname, line.id, `${protocol}-${index + 1}`),
        note: firstText(line.note, line.remark, line.peer, line.remote, line.ifname),
        ifname: firstText(line.ifname, line.interface),
        upRate: firstNumber(line.up_rate, line.tx_rate),
        upBytes: firstNumber(line.up_bytes, line.tx_bytes),
        downRate: firstNumber(line.down_rate, line.rx_rate),
        downBytes: firstNumber(line.down_bytes, line.rx_bytes),
        connections: connectionCountOf(line, line.peers)
      };
    }

    function vpnIcon() {
      return '<span class="line-port-icon vpn-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 4.6-2.8 8-7 10-4.2-2-7-5.4-7-10V6l7-3z"></path><path d="M9 12l2 2 4-5"></path></svg></span>';
    }

    function vpnRows(groups) {
      return groups.map((group) => `
        <tr class="line-load-group-row vpn-protocol-row">
          <td colspan="7"><span>${escapeHtml(group.protocol)}</span><em>${group.lines.length}</em></td>
        </tr>
        ${group.lines.length ? group.lines.map((line) => `
          <tr class="line-load-data-row vpn-status-data-row">
            <td data-label="协议">${escapeHtml(line.protocol || group.protocol)}</td>
            <td data-label="线路"><span class="line-load-name">${vpnIcon()}<span><strong>${escapeHtml(line.name || line.id || '--')}</strong><small>${escapeHtml(line.note || line.ifname || '--')}</small></span></span></td>
            <td data-label="上行速率" class="rate-up">${escapeHtml(formatRate(line.upRate))}</td>
            <td data-label="累计上行" class="rate-up total-up">${escapeHtml(formatBytes(line.upBytes))}</td>
            <td data-label="下行速率" class="rate-down">${escapeHtml(formatRate(line.downRate))}</td>
            <td data-label="累计下行" class="rate-down total-down">${escapeHtml(formatBytes(line.downBytes))}</td>
            <td data-label="隧道连接"><span class="line-connections">${Number(line.connections || 0).toLocaleString()}</span></td>
          </tr>
        `).join('') : '<tr class="vpn-empty-line-row"><td></td><td colspan="6">无活动隧道</td></tr>'}
      `).join('');
    }

    function tableMarkup(panelId, data) {
      if (panelId === 'line-health') {
        const rows = normalizeHealth(data);
        return {
          count: rows.length,
          html: `<table class="dwrt-kit-table line-health-core">
            <thead><tr><th>线路</th><th>接入方式</th><th>IP地址</th><th>网关</th><th>连接时间</th><th data-line-tooltip="${escapeHtml(LOSS_PROBE_TIP)}" tabindex="0">探测丢包</th><th>平均延迟</th><th>平均带宽</th><th>繁忙度</th></tr></thead>
            <tbody>${rows.length ? healthRows(rows) : '<tr><td colspan="9">后端暂未返回线路健康数据。</td></tr>'}</tbody>
          </table>`
        };
      }
      if (panelId === 'ipv6-load') {
        const rows = normalizeIpv6Load(data);
        const warning = data && data.degraded ? `<div class="line-load-warning">${escapeHtml(asArray(data.missing).join(' · ') || 'IPv6 counters unavailable')}，已使用线路实时负载兜底。</div>` : '';
        return {
          count: rows.length,
          html: `${warning}<table class="dwrt-kit-table line-load-core ipv6-load-core">
            <thead><tr><th>线路</th><th>上行速率</th><th>累计上行</th><th>下行速率</th><th>累计下行</th><th data-line-tooltip="conntrack 公网地址归属统计" tabindex="0">连接数</th></tr></thead>
            <tbody>${rows.length ? lineLoadRows(rows, { showIpv6: true }) : '<tr><td colspan="6">后端暂未返回 IPv6 负载数据。</td></tr>'}</tbody>
          </table>`
        };
      }
      if (panelId === 'vpn-status') {
        const groups = normalizeVpn(data);
        const total = groups.reduce((sum, group) => sum + group.lines.length, 0);
        const warning = data && data.degraded ? `<div class="line-load-warning">${escapeHtml(asArray(data.missing).join(' · ') || 'VPN counters unavailable')}</div>` : '';
        return {
          count: total,
          html: `${warning}<table class="dwrt-kit-table line-load-core vpn-status-core">
            <thead><tr><th>协议</th><th>线路</th><th>上行速率</th><th>累计上行</th><th>下行速率</th><th>累计下行</th><th>隧道连接</th></tr></thead>
            <tbody>${vpnRows(groups)}</tbody>
          </table>`
        };
      }
      const rows = normalizeLineLoad(data);
      /*
       * One connection number, one source note. The kernel forwarding column and
       * its two caveat notices were removed on 2026-08-09 by user instruction;
       * the conntrack source is still named because "连接数" alone does not say
       * what was counted.
       */
      const conntrackSource = firstText(data && data.conntrack_source);
      const sourceNote = `<div class="line-load-source-note">连接数为 <strong>conntrack 归属</strong>${conntrackSource ? `（${escapeHtml(conntrackSource)}）` : ''}口径，按公网地址归属统计。</div>`;
      return {
        count: rows.length,
        html: `${sourceNote}<table class="dwrt-kit-table line-load-core">
          <thead><tr><th>线路</th><th>上行速率</th><th>累计上行</th><th>下行速率</th><th>累计下行</th><th data-line-tooltip="conntrack 公网地址归属统计" tabindex="0">连接数</th></tr></thead>
          <tbody>${rows.length ? lineLoadRows(rows) : '<tr><td colspan="6">后端暂未返回线路负载数据。</td></tr>'}</tbody>
        </table>`
      };
    }

    function renderPanel() {
      if (!page || !page.table) return;
      if (shouldDeferRender()) {
        page.renderPending = true;
        window.clearTimeout(page.deferredRenderTimer);
        page.deferredRenderTimer = window.setTimeout(renderPanel, 500);
        return;
      }
      page.renderPending = false;
      const cached = page.data[page.mode] || {};
      const result = tableMarkup(page.mode, cached.data || {});
      const keepLeft = page.table.scrollLeft || 0;
      const keepTop = page.table.scrollTop || 0;
      page.table.innerHTML = cached.error
        ? `<div class="line-status-error">${escapeHtml(cached.error)}</div>${result.html}`
        : result.html;
      if (keepLeft || keepTop) {
        window.requestAnimationFrame(() => {
          if (!page || !page.table) return;
          page.table.scrollLeft = keepLeft;
          page.table.scrollTop = keepTop;
        });
      }
      mountUiKit(root);
      scheduleGlassCardsRender(120);
    }

    function realtimeWanRows(data = {}) {
      if (Array.isArray(data)) return data;
      return listFrom(data, ['wans', 'items', 'lines', 'interfaces']);
    }

    function wanMergeKey(wan = {}) {
      return firstText(wan.id, wan.wan_id, wan.ifname, wan.interface, wan.name).toLowerCase();
    }

    function mergeWanRealtimeIntoHealth(existingData = {}, realtimePayload = {}) {
      const existingRows = listFrom(existingData, ['wans', 'items', 'lines', 'interfaces']);
      const realtimeRows = realtimeWanRows(realtimePayload);
      if (!existingRows.length) return realtimePayload;
      if (!realtimeRows.length) return existingData;
      const realtimeByKey = new Map();
      realtimeRows.forEach((wan, index) => {
        const normalized = {
          ...wan,
          order: wan.order || index + 1,
          up_rate: firstNumber(wan.up_rate, wan.tx_rate, wan.rate_up),
          down_rate: firstNumber(wan.down_rate, wan.rx_rate, wan.rate_down),
          up_bytes: firstNumber(wan.up_bytes, wan.tx_bytes),
          down_bytes: firstNumber(wan.down_bytes, wan.rx_bytes),
          connections: connectionCountOf(wan)
        };
        [wanMergeKey(normalized), firstText(normalized.ifname).toLowerCase(), firstText(normalized.name).toLowerCase()].filter(Boolean).forEach((key) => {
          if (!realtimeByKey.has(key)) realtimeByKey.set(key, normalized);
        });
      });
      const mergedRows = existingRows.map((wan) => {
        const rt = realtimeByKey.get(wanMergeKey(wan)) || realtimeByKey.get(firstText(wan.ifname).toLowerCase()) || realtimeByKey.get(firstText(wan.name).toLowerCase());
        if (!rt) return wan;
        const merged = { ...wan, ...rt };
        // wan.metrics is a fast rate plane. It may not carry the slower health plane fields.
        // Never let it erase connection uptime or 24h/today loss that came from /monitor/line-health.
        merged.uptime = firstNumber(rt.uptime, rt.online_seconds) > 0 ? firstNumber(rt.uptime, rt.online_seconds) : firstNumber(wan.uptime, wan.online_seconds);
        merged.online_seconds = firstNumber(rt.online_seconds) > 0 ? firstNumber(rt.online_seconds) : firstNumber(wan.online_seconds, wan.uptime);
        merged.connections = preferredConnectionCount(rt, wan);
        // Realtime WAN updates describe the present. A few producers still attach a
        // synthetic history based on that present state; never let it overwrite the
        // 24-hour bucket series returned by /monitor/line-health.
        const retainedHistory = [wan.status_history, wan.health_history, wan.history]
          .map((value) => asArray(value))
          .find((value) => value.length);
        const incomingHistory = [rt.status_history, rt.health_history, rt.history]
          .map((value) => asArray(value))
          .find((value) => value.length) || [];
        const history = retainedHistory || incomingHistory;
        merged.status_history = history;
        merged.health_history = history;
        merged.history = history;
        merged.up_loss_24h = rt.up_loss_24h !== undefined ? rt.up_loss_24h : wan.up_loss_24h;
        merged.loss_up_24h = rt.loss_up_24h !== undefined ? rt.loss_up_24h : wan.loss_up_24h;
        merged.loss_up = rt.loss_up !== undefined ? rt.loss_up : wan.loss_up;
        merged.down_loss_24h = rt.down_loss_24h !== undefined ? rt.down_loss_24h : wan.down_loss_24h;
        merged.loss_down_24h = rt.loss_down_24h !== undefined ? rt.loss_down_24h : wan.loss_down_24h;
        merged.loss_down = rt.loss_down !== undefined ? rt.loss_down : wan.loss_down;
        merged.latency_avg = rt.latency_avg !== undefined ? rt.latency_avg : wan.latency_avg;
        merged.avg_latency = rt.avg_latency !== undefined ? rt.avg_latency : wan.avg_latency;
        merged.avg_up_rate = rt.avg_up_rate !== undefined ? rt.avg_up_rate : wan.avg_up_rate;
        merged.avg_down_rate = rt.avg_down_rate !== undefined ? rt.avg_down_rate : wan.avg_down_rate;
        return merged;
      });
      const key = Array.isArray(existingData.wans) ? 'wans' : Array.isArray(existingData.items) ? 'items' : Array.isArray(existingData.lines) ? 'lines' : Array.isArray(existingData.interfaces) ? 'interfaces' : 'wans';
      return { ...existingData, ...realtimePayload, [key]: mergedRows };
    }

    function mergeWanRealtimeIntoLineLoad(existingData = {}, realtimePayload = {}) {
      const existingRows = listFrom(existingData, ['interfaces', 'items', 'lines', 'wans']);
      const realtimeRows = realtimeWanRows(realtimePayload);
      if (!existingRows.length) return realtimePayload;
      if (!realtimeRows.length) return existingData;
      const existingByKey = new Map();
      existingRows.forEach((wan) => {
        [wanMergeKey(wan), firstText(wan.ifname).toLowerCase(), firstText(wan.name).toLowerCase()].filter(Boolean)
          .forEach((key) => {
            if (!existingByKey.has(key)) existingByKey.set(key, wan);
          });
      });
      const mergedRows = realtimeRows.map((wan, index) => {
        const current = existingByKey.get(wanMergeKey(wan)) || existingByKey.get(firstText(wan.ifname).toLowerCase()) || existingByKey.get(firstText(wan.name).toLowerCase()) || {};
        const merged = {
          ...current,
          ...wan,
          type: firstText(wan.type, current.type, 'wan'),
          order: wan.order || current.order || index + 1,
          connections: preferredConnectionCount(wan, current)
        };
        /* wan.metrics is the conntrack/rate plane; retain the REST liveness fact
         * when a frame omits it so a partial WS update cannot hide a WAN. */
        if (!Object.prototype.hasOwnProperty.call(wan, 'kernel_stats_valid')) {
          KERNEL_LIVENESS_FIELDS.forEach((field) => {
            if (Object.prototype.hasOwnProperty.call(current, field)) merged[field] = current[field];
            else delete merged[field];
          });
        }
        return merged;
      });
      const key = Array.isArray(existingData.interfaces) ? 'interfaces' : Array.isArray(existingData.items) ? 'items' : Array.isArray(existingData.lines) ? 'lines' : Array.isArray(existingData.wans) ? 'wans' : 'interfaces';
      return { ...existingData, ...realtimePayload, [key]: mergedRows };
    }

    function applyWanRealtime(data) {
      if (!page || !page.active) return;
      const wans = realtimeWanRows(data);
      if (!wans.length) return;
      page.lastWsAt = Date.now();
      const payload = {
        ...(data && typeof data === 'object' && !Array.isArray(data) ? data : {}),
        wans,
        interfaces: wans.map((wan, index) => ({
          ...wan,
          type: 'wan',
          order: wan.order || index + 1,
          up_rate: firstNumber(wan.up_rate, wan.tx_rate, wan.rate_up),
          down_rate: firstNumber(wan.down_rate, wan.rx_rate, wan.rate_down),
          up_bytes: firstNumber(wan.up_bytes, wan.tx_bytes),
          down_bytes: firstNumber(wan.down_bytes, wan.rx_bytes),
          ipv6: firstGlobalIpv6(wan.ipv6_global, wan.global_ipv6, wan.public_ipv6, wan.wan_ipv6, wan.ipv6_addrs, wan.ipv6, wan.ipv6_addr, wan.ipv6_address),
          connections: connectionCountOf(wan)
        }))
      };
      const previousLoad = page.data['line-load'] && page.data['line-load'].data || {};
      page.data['line-load'] = { data: mergeWanRealtimeIntoLineLoad(previousLoad, payload), loading: false, error: '' };
      const previousHealth = page.data['line-health'] && page.data['line-health'].data || {};
      page.data['line-health'] = { data: mergeWanRealtimeIntoHealth(previousHealth, payload), loading: false, error: '' };
      if (page.mode === 'line-load' || page.mode === 'line-health') renderPanel();
    }

    function subscribeRealtime() {
      if (!page || page.wsUnsubscribe || !realtime || typeof realtime.subscribe !== 'function') return;
      page.wsUnsubscribe = realtime.subscribe('wan.metrics', applyWanRealtime);
    }

    function unsubscribeRealtime() {
      if (!page || !page.wsUnsubscribe) return;
      page.wsUnsubscribe();
      page.wsUnsubscribe = null;
    }

    async function refreshPanel(panelId) {
      if (!page || !page.active) return;
      const panel = panelById(panelId);
      const wsFresh = page.lastWsAt && Date.now() - page.lastWsAt < refreshMs * 2;
      const healthContractFresh = page.healthContractReady && Date.now() - page.lastHealthContractAt < 30000;
      const wsCanSatisfyPanel = panel.id === 'line-health' && healthContractFresh;
      if (wsFresh && wsCanSatisfyPanel && page.data[panel.id]) {
        if (page.mode === panel.id) renderPanel();
        return;
      }
      page.data[panel.id] = { ...(page.data[panel.id] || {}), loading: true, error: '' };
      if (page.mode === panel.id) renderPanel();
      const requests = [fetchApiResource(panel.id, panel.endpoint)];
      if (panel.id === 'line-health') {
        requests.push(
          fetchApiResource('line-health-wans', WAN_CONFIG_ENDPOINT),
          fetchApiResource('line-health-system', SYSTEM_STATUS_ENDPOINT)
        );
      }
      const [res, wanConfig, systemStatus] = await Promise.all(requests);
      if (!page || !page.active) return;
      if (panel.id === 'line-health') {
        const configuredWans = listFrom(wanConfig?.data || {}, ['wans', 'interfaces']);
        if (wanConfig?.ok && configuredWans.length) {
          page.configuredWanKeys = new Set(configuredWans.flatMap((wan) => [wan.id, wan.ifname, wan.interface, wan.name])
            .map((value) => firstText(value).toLowerCase()).filter(Boolean));
        }
        page.systemUptime = firstNumber(systemStatus?.data?.system?.uptime, systemStatus?.data?.uptime);
        page.systemUptimeAt = Date.now();
        page.healthContractReady = Boolean(res.ok && wanConfig?.ok && systemStatus?.ok);
        if (page.healthContractReady) page.lastHealthContractAt = Date.now();
      }
      if (res.ok) {
        page.data[panel.id] = { data: res.data || {}, loading: false, error: '' };
      } else {
        page.data[panel.id] = {
          data: page.data[panel.id]?.data || {},
          loading: false,
          error: res.error?.message || '读取线路数据失败'
        };
      }
      if (page.mode === panel.id) renderPanel();
    }

    function refresh() {
      if (!page || !page.active) return;
      refreshPanel(page.mode);
    }

    function selectPanel(panelId) {
      if (!page) return;
      page.mode = panelById(panelId).id;
      persistPanelId(page.mode);
      root.querySelectorAll('.line-status-tabs .dwrt-kit-tab').forEach((tab) => {
        const active = tab.dataset.value === page.mode;
        tab.classList.toggle('is-active', active);
        tab.setAttribute('aria-selected', active ? 'true' : 'false');
      });
      renderPanel();
      refreshPanel(page.mode);
    }

    function hideLineTooltip() {
      if (!page?.tooltip) return;
      page.tooltip.hidden = true;
      page.tooltip.textContent = '';
    }

    function placeLineTooltip(target, event) {
      if (!page?.tooltip || !target) return;
      const text = target.dataset.lineTooltip || '';
      if (!text) return;
      const rect = target.getBoundingClientRect();
      const x = Number.isFinite(event?.clientX) ? event.clientX : rect.left + rect.width / 2;
      const y = Number.isFinite(event?.clientY) ? event.clientY : rect.bottom;
      page.tooltip.textContent = text;
      page.tooltip.hidden = false;
      page.tooltip.style.left = '0px';
      page.tooltip.style.top = '0px';
      const tipRect = page.tooltip.getBoundingClientRect();
      const left = Math.max(10, Math.min(window.innerWidth - tipRect.width - 10, x - tipRect.width / 2));
      const top = Math.max(10, Math.min(window.innerHeight - tipRect.height - 10, y + 14));
      page.tooltip.style.left = `${Math.round(left)}px`;
      page.tooltip.style.top = `${Math.round(top)}px`;
    }

    function bindLineTooltips() {
      if (!page) return;
      page.onTooltipOver = (event) => {
        const target = event.target.closest('[data-line-tooltip]');
        if (target && root.contains(target)) placeLineTooltip(target, event);
      };
      page.onTooltipMove = (event) => {
        const target = event.target.closest('[data-line-tooltip]');
        if (target && root.contains(target)) placeLineTooltip(target, event);
      };
      page.onTooltipOut = (event) => {
        const target = event.target.closest('[data-line-tooltip]');
        if (!target || target.contains(event.relatedTarget)) return;
        hideLineTooltip();
      };
      page.onTooltipFocusIn = (event) => {
        const target = event.target.closest('[data-line-tooltip]');
        if (target && root.contains(target)) placeLineTooltip(target);
      };
      page.onTooltipFocusOut = hideLineTooltip;
      root.addEventListener('pointerover', page.onTooltipOver);
      root.addEventListener('pointermove', page.onTooltipMove);
      root.addEventListener('pointerout', page.onTooltipOut);
      root.addEventListener('focusin', page.onTooltipFocusIn);
      root.addEventListener('focusout', page.onTooltipFocusOut);
    }

    function mount() {
      if (!root) return { unmount() {} };
      root.hidden = false;
      root.classList.add('route-workspace', 'route-line-status');
      root.classList.remove('route-data-page');
      const activePanelId = initialPanelId();
      root.innerHTML = `
        <header class="route-page-head line-status-head">
          <div class="dwrt-kit-tabs line-status-tabs" id="lineStatusTabs" aria-label="线路状态视图">
            <span class="dwrt-kit-tab-pill" aria-hidden="true"></span>
            ${PANELS.map((panel) => `<button class="dwrt-kit-tab ${panel.id === activePanelId ? 'is-active' : ''}" type="button" data-value="${escapeHtml(panel.id)}" aria-selected="${panel.id === activePanelId ? 'true' : 'false'}">${escapeHtml(panel.label)}</button>`).join('')}
          </div>
        </header>
        <section class="line-status-panel">
          <div class="dwrt-kit-table-wrap">
            <div class="dwrt-kit-table-scroll" id="lineStatusTable"></div>
          </div>
        </section>
        <div class="line-status-tooltip" id="lineStatusTooltip" role="tooltip" hidden></div>`;
      page = {
        mode: activePanelId,
        active: true,
        data: {},
        table: root.querySelector('#lineStatusTable'),
        timer: window.setInterval(refresh, refreshMs),
        deferredRenderTimer: 0,
        renderPending: false,
        lastWsAt: 0,
        healthContractReady: false,
        configuredWanKeys: new Set(),
        systemUptime: 0,
        systemUptimeAt: 0,
        lastHealthContractAt: 0,
        wsUnsubscribe: null,
        tooltip: root.querySelector('#lineStatusTooltip')
      };
      root.querySelectorAll('.line-status-tabs .dwrt-kit-tab').forEach((button) => {
        button.addEventListener('click', () => selectPanel(button.dataset.value || PANELS[0].id));
      });
      mountUiKit(root);
      bindLineTooltips();
      subscribeRealtime();
      persistPanelId(page.mode);
      refreshPanel(page.mode);
      scheduleGlassCardsRender(360);
      return { unmount };
    }

    function unmount() {
      if (!page) return;
      page.active = false;
      unsubscribeRealtime();
      root.removeEventListener('pointerover', page.onTooltipOver);
      root.removeEventListener('pointermove', page.onTooltipMove);
      root.removeEventListener('pointerout', page.onTooltipOut);
      root.removeEventListener('focusin', page.onTooltipFocusIn);
      root.removeEventListener('focusout', page.onTooltipFocusOut);
      window.clearInterval(page.timer);
      window.clearTimeout(page.deferredRenderTimer);
      page = null;
      if (root) root.classList.remove('route-line-status');
    }

    return { mount, unmount, refresh };
  }

  window.DWRTLineStatus = { create };
})();
