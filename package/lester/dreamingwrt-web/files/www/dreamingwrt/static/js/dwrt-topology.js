(() => {
  'use strict';

  // DreamingOS network topology renderer.
  // Consumes the DreamingOS topology model and draws the SVG graph.

  const SOURCE = {
    renderer: 'dwrt-topology',
    endpoint: '/v2/api/site/{site}/topology',
    pollMs: 10000
  };

  const NODE_TYPE = new Set([
    'DEVICE',
    'CLIENT',
    'INVISIBLE_ROOT',
    'ISP',
    'USW_WAN',
    'CABLE_INTERNET',
    'THIRD_PARTY_CLIENT'
  ]);

  const EDGE_TYPE = new Set(['WIRED', 'WIRELESS']);

  const LINK_MODE = {
    NORMAL: 'NORMAL',
    MC_LAG_LEFT: 'MC_LAG_LEFT',
    MC_LAG_RIGHT: 'MC_LAG_RIGHT'
  };

  // Layout and animation constants shared with the topology page.
  const C = {
    hD: 140,
    VQ: 120,
    Ps: 40,
    Qb: 120,
    Y2: 0.3,
    L9: 0.3,
    rR: 0.4,
    Sh: 20,
    E5: 10,
    NX: 4,
    zU: 40,
    dB: 40,
    sM: 32,
    WS: 65,
    CH: 16,
    T6: 2,
    En: 4,
    BJ: 70,
    xt: 400,
    vf: 'cubic-bezier(0.65, 0, 0.35, 1)',
    pH: 0.55,
    WQ: 1.25,
    hK: 'all 0.15s ease-out',
    _K: 'invisibleNodeName',
    Aw: 'invisibleNodeMac',
    TD: 'uswWanNode',
    RE: 'ISP',
    D1: 'ispNodeMac',
    aC: 100,
    bx: 50,
    ku: { min: 0.3, max: 2.5 },
    mD: 1.25,
    Le: 0.75,
    hY: 1000,
    Zm: 0.8,
    ZZ: 0.7,
    cE: 10,
    OI: 30,
    dg: 'top',
    Sn: 'bottom',
    qx: 9,
    hc: 10,
    AD: 80,
    hq: 'topology-svg-container',
    Aj: 'topology-zoom-g',
    Hg: 1000
  };

  const TRAFFIC_LEVEL = [
    { id: 0, max: 0, backgroundWidth: 4, particlesWidth: 0, circlesInGroup: 0 },
    { id: 1, max: 20, backgroundWidth: 10, particlesWidth: 4, circlesInGroup: 3 },
    { id: 2, max: 40, backgroundWidth: 14, particlesWidth: 8, circlesInGroup: 6 },
    { id: 3, max: 60, backgroundWidth: 18, particlesWidth: 12, circlesInGroup: 10 },
    { id: 4, max: 80, backgroundWidth: 22, particlesWidth: 16, circlesInGroup: 13 },
    { id: 5, max: 100, backgroundWidth: 26, particlesWidth: 20, circlesInGroup: 15 }
  ];
  const LINK_TRACK_WIDTH = 4;
  const LINK_IDLE_WIDTH = 0.5;
  const ABSOLUTE_TRAFFIC_THRESHOLDS = [0, 256 * 1024, 1024 * 1024, 5 * 1024 * 1024, 20 * 1024 * 1024];
  const MAX_VISIBLE_WANS = 4;
  const WAN_OVERFLOW_PREFIX = 'dwrt-isp-overflow-';

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function unwrap(payload) {
    if (!payload || typeof payload !== 'object') return {};
    if (payload.data && typeof payload.data === 'object') return unwrap(payload.data);
    if (payload.result && typeof payload.result === 'object') return unwrap(payload.result);
    return payload;
  }

  function text(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      const stringValue = String(value).trim();
      if (stringValue) return stringValue;
    }
    return '';
  }

  function number(...values) {
    for (const value of values) {
      const numeric = Number(value);
      if (Number.isFinite(numeric)) return numeric;
    }
    return 0;
  }

  function parseMbps(value) {
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    const raw = text(value).toLowerCase();
    if (!raw) return 0;
    const match = raw.match(/([0-9]+(?:\.[0-9]+)?)/);
    if (!match) return 0;
    const numeric = Number(match[1]);
    if (!Number.isFinite(numeric)) return 0;
    if (/gbps|gbit|\bg\b/.test(raw)) return numeric * 1000;
    if (/kbps|kbit|\bk\b/.test(raw)) return numeric / 1000;
    return numeric;
  }

  function carrierKey(value) {
    const raw = text(value).toLowerCase();
    if (/unicom|联通|cucc|china\s*unicom/.test(raw)) return 'unicom';
    if (/mobile|移动|cmcc|china\s*mobile/.test(raw)) return 'mobile';
    if (/telecom|电信|ctcc|china\s*telecom/.test(raw)) return 'telecom';
    if (/cernet|教育网|edu/.test(raw)) return 'cernet';
    return '';
  }

  function carrierImage(node) {
    const explicitLogo = text(node.carrier_logo, node.carrier_svg, node.logo);
    return window.DWRT_DEVICE_IMAGES?.normalizeUrl?.(explicitLogo) || explicitLogo;
  }

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>'"]/g, (char) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[char]));
  }

  function typeName(value, fallback) {
    const type = text(value, fallback).toUpperCase().replace(/[^A-Z0-9_]/g, '_');
    return NODE_TYPE.has(type) ? type : fallback;
  }

  function edgeType(value) {
    const type = text(value, 'WIRED').toUpperCase().replace(/[^A-Z0-9_]/g, '_');
    return EDGE_TYPE.has(type) ? type : 'WIRED';
  }

  function key(value) {
    return text(value).toLowerCase();
  }

  function wanSortValue(node) {
    const raw = text(node && node.wan_id, node && node.networkId, node && node.id, node && node.name);
    const match = raw.match(/(?:wan|internet)[^0-9]*([0-9]+)$/i);
    return match ? Number(match[1]) + 1 : (/^(?:wan|internet)$/i.test(raw) ? 0 : Number.MAX_SAFE_INTEGER);
  }

  function compareWanNodes(a, b) {
    const order = wanSortValue(a) - wanSortValue(b);
    if (order) return order;
    return text(a && a.name, a && a.wan_id, a && a.mac).localeCompare(text(b && b.name, b && b.wan_id, b && b.mac));
  }

  function aggregateWanTraffic(nodes) {
    return asArray(nodes).reduce((sum, node) => {
      const item = node && node.traffic || {};
      sum.tx += number(item.tx);
      sum.rx += number(item.rx);
      sum.sum += number(item.sum, number(item.tx) + number(item.rx));
      sum.known = sum.known || Boolean(item.known);
      return sum;
    }, { tx: 0, rx: 0, sum: 0, topSum: 0, bottomSum: 0, known: false });
  }

  function createWanOverflowNode(gateway, omitted, gatewayEdges) {
    const id = `${WAN_OVERFLOW_PREFIX}${key(gateway && gateway.mac) || 'gateway'}`;
    const omittedWanIds = omitted.map((node) => text(node.wan_id, node.networkId, node.id, node.name)).filter(Boolean);
    return {
      id,
      mac: id,
      type: 'ISP',
      name: '...',
      state: omitted.some((node) => nodeState(node) === 'online') ? 'CONNECTED' : 'DISCONNECTED',
      carrier: 'unknown',
      carrier_name: '更多 WAN',
      wan_id: '',
      ip: '',
      model: '',
      connections: omitted.reduce((sum, node) => sum + number(node.connections), 0),
      traffic: aggregateWanTraffic(omitted),
      overflow: true,
      omittedWans: omitted.map((node) => ({
        id: text(node.wan_id, node.networkId, node.id),
        name: text(node.name, node.carrier_name, node.wan_id, node.id),
        carrier: text(node.carrier_name, node.carrier),
        ip: text(node.ip, node.public_ip),
        state: text(node.state)
      })),
      omittedWanIds,
      edge: {
        uplinkMac: id,
        downlinkMac: gateway.mac,
        type: 'WIRED',
        wan_id: omittedWanIds.join(','),
        traffic: aggregateWanTraffic(omitted),
        overflow: true,
        sourceEdges: gatewayEdges
      }
    };
  }

  function normalizeWanFanIn(model) {
    const vertices = asArray(model && model.vertices);
    const edges = asArray(model && model.edges);
    const ispNodes = vertices.filter((node) => node.type === 'ISP').sort(compareWanNodes);
    if (!ispNodes.length) return model;

    const ispMacs = new Set(ispNodes.map((node) => node.mac));
    const gatewayEdges = edges.filter((edge) => ispMacs.has(edge.uplinkMac));
    const gatewayCounts = new Map();
    gatewayEdges.forEach((edge) => gatewayCounts.set(edge.downlinkMac, (gatewayCounts.get(edge.downlinkMac) || 0) + 1));
    const gatewayMac = Array.from(gatewayCounts.entries()).sort((a, b) => b[1] - a[1])[0]?.[0];
    const gateway = vertices.find((node) => node.mac === gatewayMac) || vertices.find((node) => node.type === 'DEVICE');
    if (!gateway) return model;

    const displayWans = ispNodes.slice(0, MAX_VISIBLE_WANS);
    const omitted = ispNodes.slice(MAX_VISIBLE_WANS);
    const displayMacs = new Set(displayWans.map((node) => node.mac));
    const normalizedEdges = edges.filter((edge) => !ispMacs.has(edge.uplinkMac));
    displayWans.forEach((node) => {
      const edge = gatewayEdges.find((candidate) => candidate.uplinkMac === node.mac && candidate.downlinkMac === gateway.mac)
        || gatewayEdges.find((candidate) => candidate.uplinkMac === node.mac)
        || { type: 'WIRED', wan_id: node.wan_id, traffic: node.traffic };
      normalizedEdges.push({ ...edge, uplinkMac: node.mac, downlinkMac: gateway.mac });
    });

    const normalizedVertices = vertices.filter((node) => !ispMacs.has(node.mac) || displayMacs.has(node.mac));
    if (omitted.length) {
      const overflow = createWanOverflowNode(gateway, omitted, gatewayEdges.filter((edge) => omitted.some((node) => node.mac === edge.uplinkMac)));
      normalizedVertices.push(overflow);
      normalizedEdges.push(overflow.edge);
    }

    return {
      ...model,
      vertices: normalizedVertices,
      edges: normalizedEdges,
      wanPresentation: {
        gatewayMac: gateway.mac,
        total: ispNodes.length,
        visible: displayWans.length,
        omitted: omitted.length
      }
    };
  }

  function traffic(...sources) {
    const out = { tx: 0, rx: 0, sum: 0, topSum: 0, bottomSum: 0, known: false };
    sources.forEach((source) => {
      if (!source || typeof source !== 'object') return;
      const hasTrafficField = [
        'tx', 'up', 'up_rate', 'tx_rate', 'tx_bytes-r', 'tx_bytes_r', 'txBytesRate',
        'rx', 'down', 'down_rate', 'rx_rate', 'rx_bytes-r', 'rx_bytes_r', 'rxBytesRate',
        'sum', 'total_rate', 'rate'
      ].some((field) => Object.prototype.hasOwnProperty.call(source, field));
      const tx = number(
        source.tx,
        source.up,
        source.up_rate,
        source.tx_rate,
        source['tx_bytes-r'],
        source.tx_bytes_r,
        source.txBytesRate
      );
      const rx = number(
        source.rx,
        source.down,
        source.down_rate,
        source.rx_rate,
        source['rx_bytes-r'],
        source.rx_bytes_r,
        source.rxBytesRate
      );
      const sum = number(source.sum, source.total_rate, source.rate, tx + rx);
      out.known = out.known || hasTrafficField;
      out.tx = Math.max(out.tx, tx);
      out.rx = Math.max(out.rx, rx);
      out.sum = Math.max(out.sum, sum);
      out.topSum = Math.max(out.topSum, number(source.topSum, source.top_sum, rx));
      out.bottomSum = Math.max(out.bottomSum, number(source.bottomSum, source.bottom_sum, tx));
    });
    if (!out.sum) out.sum = out.tx + out.rx;
    if (!out.topSum) out.topSum = out.rx;
    if (!out.bottomSum) out.bottomSum = out.tx;
    return out;
  }

  function flowIndexes(flowPayload) {
    const flow = unwrap(flowPayload);
    const byMac = new Map();
    const byIp = new Map();
    const byWan = new Map();
    asArray(flow.flows).forEach((item) => {
      if (!item || typeof item !== 'object') return;
      const entry = {
        ...item,
        traffic: traffic({ tx: item.up_rate, rx: item.down_rate, sum: number(item.up_rate) + number(item.down_rate) })
      };
      const mac = key(item.client_mac || item.mac);
      const ip = key(item.client_ip || item.ip);
      if (mac) byMac.set(mac, entry);
      if (ip) byIp.set(ip, entry);
    });
    asArray(flow.wan_totals).forEach((item) => {
      if (!item || typeof item !== 'object') return;
      const wanId = key(item.wan_id || item.id || item.wan_name || item.name);
      if (!wanId) return;
      byWan.set(wanId, {
        ...item,
        traffic: traffic({ tx: item.up_rate, rx: item.down_rate, sum: number(item.up_rate) + number(item.down_rate) })
      });
    });
    return { byMac, byIp, byWan, raw: flow };
  }

  function normalizeVerticesEdges(raw, flowPayload) {
    const flow = flowIndexes(flowPayload || raw.topology_flow || raw.flow);
    const rawVertices = asArray(raw.vertices);
    const rawEdges = asArray(raw.edges);
    if (!rawVertices.length) {
      return { valid: false, reason: 'missing vertices', vertices: [], edges: [], source: SOURCE };
    }
    if (!rawEdges.length) {
      return { valid: false, reason: 'missing edges', vertices: [], edges: [], source: SOURCE };
    }

    const byMac = new Map();
    rawVertices.forEach((node, index) => {
      if (!node || typeof node !== 'object') return;
      const mac = text(node.mac, node.id);
      if (!mac) return;
      const normalizedType = typeName(node.type, 'CLIENT');
      const fingerprintData = node.fingerprintData || node.fingerprint || {};
      const flowEntry = flow.byMac.get(key(mac)) || flow.byIp.get(key(node.ip || node.ipaddr || node.ipv4));
      const wanEntry = normalizedType === 'ISP'
        ? flow.byWan.get(key(node.wan_id || node.networkId || node.id))
        : null;
      byMac.set(mac, {
        id: text(node.id, mac),
        mac,
        type: normalizedType,
        name: text(node.name, node.display_name, node.hostname, mac),
        state: text(node.state, node.status, node.online === false ? 'OFFLINE' : 'CONNECTED'),
        model: text(node.model, node.product, node.device_model, node.device_name, fingerprintData.device_name),
        vendor: text(node.vendor_name, node.vendor, node.manufacturer, node.brand, fingerprintData.vendor_name, fingerprintData.vendor, fingerprintData.fingerprint_device_vendor),
        device_type: text(node.device_type, node.type_hint, node.category, fingerprintData.device_type, fingerprintData.fingerprint_device_type),
        image: text(
          window.DWRT_DEVICE_IMAGES && window.DWRT_DEVICE_IMAGES.resolve
            ? window.DWRT_DEVICE_IMAGES.resolve({ ...node, fingerprint: fingerprintData }).src
            : '',
          node.custom_image_path,
          node.custom_icon,
          node.override_image,
          node.override_icon,
          node.web_image,
          node.image,
          node.icon,
          node.icon_url,
          node.fingerprint_image,
          fingerprintData.custom_image_path,
          fingerprintData.image,
          fingerprintData.icon
        ),
        carrier: text(node.carrier, wanEntry && wanEntry.carrier),
        carrier_name: text(node.carrier_name, wanEntry && wanEntry.carrier_name, wanEntry && wanEntry.wan_name),
        note: text(node.note, node.description),
        wan_id: text(node.wan_id, node.networkId, flowEntry && (flowEntry.wan_id || flowEntry.egress_wan_id)),
        connections: number(node.connections, flowEntry && flowEntry.connections, wanEntry && wanEntry.connections),
        app_name: text(node.app_name, node.active_app, flowEntry && flowEntry.app_name),
        route_reason: text(node.route_reason, flowEntry && flowEntry.route_reason),
        networkId: text(node.networkId, node.network_id, node.vlan, node.vlan_id, flowEntry && flowEntry.networkId),
        networkName: text(node.networkName, node.network_name, node.vlanName, node.vlan_name),
        ssid: text(node.ssid, node.essid, node.wlan, node.wlan_name),
        signal: text(node.signal, node.rssi, node.signal_strength),
        channel: text(node.channel, node.radio_channel),
        stpPriority: text(node.stpPriority, node.stp_priority),
        connectionType: text(node.connectionType, node.connection_type, node.uplink_type),
        allowedInVisualProgramming: node.allowedInVisualProgramming !== false,
        managedDevice: Boolean(node.managedDevice),
        wifiRadios: asArray(node.wifiRadios),
        fingerprintData,
        ip: text(node.ip, node.ipaddr, node.ipv4),
        traffic: wanEntry
          ? traffic(wanEntry.traffic)
          : flowEntry
            ? traffic(flowEntry.traffic)
            : traffic(node.traffic, node),
        rawIndex: index
      });
    });

    const edges = rawEdges.map((edge) => {
      const uplinkMac = text(edge && (edge.uplinkMac ?? edge.uplink_mac ?? edge.source ?? edge.parent ?? edge.from));
      const downlinkMac = text(edge && (edge.downlinkMac ?? edge.downlink_mac ?? edge.target ?? edge.child ?? edge.to));
      if (!uplinkMac || !downlinkMac || uplinkMac === downlinkMac) return null;
      const source = byMac.get(uplinkMac);
      const target = byMac.get(downlinkMac);
      const flowEntry = target && (flow.byMac.get(key(target.mac)) || flow.byIp.get(key(target.ip)));
      const wanEntry = source && source.type === 'ISP'
        ? flow.byWan.get(key(edge.wan_id || edge.networkId || source.wan_id))
        : null;
      return {
        uplinkMac,
        downlinkMac,
        type: edgeType(edge.type ?? edge.connection_type),
        uplinkPortNumber: number(edge.uplinkPortNumber, edge.uplink_port, edge.port),
        downlinkPortNumber: number(edge.downlinkPortNumber, edge.downlink_port),
        radioBand: text(edge.radioBand, edge.radio_band),
        essid: text(edge.essid, edge.ssid),
        signal: text(edge.signal, edge.rssi),
        channel: text(edge.channel, edge.radio_channel),
        stpPriority: text(edge.stpPriority, edge.stp_priority),
        networkName: text(edge.networkName, edge.network_name, edge.vlanName, edge.vlan_name),
        networkId: text(edge.networkId, edge.network_id),
        wan_id: text(edge.wan_id, target && target.wan_id),
        carrier: text(edge.carrier, target && target.carrier, wanEntry && wanEntry.carrier),
        traffic: wanEntry
          ? traffic(wanEntry.traffic)
          : flowEntry
            ? traffic(flowEntry.traffic)
            : traffic(edge.traffic, edge)
      };
    }).filter(Boolean).filter((edge) => byMac.has(edge.uplinkMac) && byMac.has(edge.downlinkMac));

    if (!byMac.size) return { valid: false, reason: 'no usable vertices', vertices: [], edges: [], source: SOURCE };
    if (!edges.length) return { valid: false, reason: 'no usable edges', vertices: Array.from(byMac.values()), edges: [], source: SOURCE };

      return normalizeWanFanIn({
        valid: true,
      reason: '',
      vertices: Array.from(byMac.values()),
      edges,
      layout: raw.layout || {},
      flow: flow.raw,
      diagnostics: raw.diagnostics || {},
        source: raw.source || SOURCE
      });
  }

  function normalize(payload) {
    const outer = unwrap(payload);
    const raw = unwrap(outer.topology || outer.model || outer);
    const flow = unwrap(outer.flow || outer.topology_flow || raw.flow || raw.topology_flow || {});
    if (asArray(raw.vertices).length || asArray(raw.edges).length) return normalizeVerticesEdges(raw, flow);
    return { valid: false, reason: 'missing vertices/edges contract', vertices: [], edges: [], source: SOURCE };
  }

  function arrangeChildren(children) {
    if (!children || children.length <= 1) return children || [];
    const isps = children.filter((child) => child.type === 'ISP').sort(compareWanNodes);
    if (isps.length) {
      const rest = children.filter((child) => child.type !== 'ISP');
      const middle = Math.ceil(rest.length / 2);
      return [...rest.slice(0, middle), ...isps, ...rest.slice(middle)];
    }
    const sorted = [...children].sort((a, b) => {
      const childDiff = (b.children?.length || 0) - (a.children?.length || 0);
      if (childDiff) return childDiff;
      const portDiff = (a.edge?.uplinkPortNumber || 9999) - (b.edge?.uplinkPortNumber || 9999);
      if (portDiff) return portDiff;
      return String(a.mac).localeCompare(String(b.mac));
    });
    const arranged = new Array(sorted.length);
    const center = Math.floor(sorted.length / 2);
    let offset = 0;
    sorted.forEach((child, index) => {
      arranged[center + offset] = child;
      offset = offset > 0 ? -offset : 1 - offset;
      if (index === sorted.length - 1) return;
    });
    return arranged.filter(Boolean);
  }

  function buildTree(vertices, edges) {
    const byMac = new Map(vertices.map((node) => [node.mac, { ...node, children: [] }]));
    const childSet = new Set();
    const parentByChild = new Map();
    const multiIsp = Array.from(byMac.values()).filter((node) => node.type === 'ISP').length > 1;
    edges.forEach((edge) => {
      const parent = byMac.get(edge.uplinkMac);
      const child = byMac.get(edge.downlinkMac);
      if (!parent || !child) return;
      if (multiIsp && parent.type === 'ISP') {
        parent.edge = edge;
        if (!parent.children.some((candidate) => candidate.mac === child.mac)) parent.children.push(child);
        return;
      }
      const existingParent = parentByChild.get(child.mac);
      if (existingParent) {
        return;
      }
      child.edge = edge;
      parent.children.push(child);
      childSet.add(child.mac);
      parentByChild.set(child.mac, parent);
    });
    byMac.forEach((node) => {
      node.children = arrangeChildren(node.children).map((child) => child);
    });
    const ispRoots = Array.from(byMac.values()).filter((node) => node.type === 'ISP');
    if (ispRoots.length > 1) {
      const gateway = Array.from(byMac.values()).find((node) => node.type === 'DEVICE' && ispRoots.some((isp) => (
        asArray(isp.children).some((child) => child.mac === node.mac)
      )));
      if (gateway) {
        ispRoots.forEach((isp) => { isp.children = []; });
        gateway.children = arrangeChildren(gateway.children.filter((child) => child.type !== 'ISP'));
        return {
          id: C._K,
          mac: C.Aw,
          name: C._K,
          type: 'INVISIBLE_ROOT',
          state: 'CONNECTED',
          children: [...ispRoots.sort(compareWanNodes), gateway],
          wanFanIn: { gatewayMac: gateway.mac, ispMacs: ispRoots.map((node) => node.mac) }
        };
      }
    }
    const roots = Array.from(byMac.values()).filter((node) => !childSet.has(node.mac));
    if (roots.length === 1) return roots[0];
    return {
      id: C._K,
      mac: C.Aw,
      name: C._K,
      type: 'INVISIBLE_ROOT',
      state: 'CONNECTED',
      children: arrangeChildren(roots)
    };
  }

  function nodeState(node) {
    const state = String(node.state || '').toLowerCase();
    if (/offline|down|disconnected|isolated/.test(state)) return 'offline';
    if (node.online === false) return 'offline';
    if (/pending|adopting/.test(state)) return 'pending';
    return 'online';
  }

  function edgeForNode(edges, node) {
    return asArray(edges).find((edge) => edge.downlinkMac === node.mac) || null;
  }

  function nodeConnectionKind(node, edge) {
    const raw = text(edge && edge.type, node.connectionType).toUpperCase();
    if (raw === 'WIRELESS' || /wifi|wireless/.test(raw.toLowerCase())) return 'wireless';
    if (raw === 'WIRED' || /wired|ethernet|lan/.test(raw.toLowerCase())) return 'wired';
    return '';
  }

  function nodeNetworkName(node, edge) {
    return text(node.networkName, edge && edge.networkName, edge && edge.networkId, node.networkId);
  }

  function passesFilters(node, edge, filters = {}, renderState = {}) {
    if (node.type === 'INVISIBLE_ROOT') return true;
    if (node.type === 'CLIENT' && renderState.clientsEnabled === false) return false;
    const status = nodeState(node);
    if (status === 'online' && filters.statusOnline === false) return false;
    if (status === 'offline' && filters.statusOffline === false) return false;
    if (node.type === 'CLIENT') {
      const kind = nodeConnectionKind(node, edge);
      if (kind === 'wireless' && filters.wirelessClients === false) return false;
      if (kind !== 'wireless' && filters.wiredClients === false) return false;
    }
    if (filters.vlanDefault === false) {
      const network = nodeNetworkName(node, edge);
      if (!network || /default/i.test(network) || network === '0' || network === '1') return false;
    }
    return true;
  }

	  function filterModel(model, filters = {}, state = {}) {
	    const edgeByChild = new Map(asArray(model.edges).map((edge) => [edge.downlinkMac, edge]));
	    const vertices = asArray(model.vertices).filter((node) => passesFilters(node, edgeByChild.get(node.mac), filters, state));
	    const macs = new Set(vertices.map((node) => node.mac));
	    const edges = asArray(model.edges).filter((edge) => macs.has(edge.uplinkMac) && macs.has(edge.downlinkMac));
	    return { ...model, vertices, edges };
	  }

	  function branchCollapsedSet(state = {}) {
	    const source = state.collapsedBranches || {};
	    if (source instanceof Set) return new Set(source);
	    if (Array.isArray(source)) return new Set(source.filter(Boolean));
	    if (source && typeof source === 'object') {
	      return new Set(Object.keys(source).filter((mac) => source[mac]));
	    }
	    return new Set();
	  }

	  function hiddenDescendants(root, collapsedSet) {
	    const hidden = new Set();
	    if (!collapsedSet || !collapsedSet.size) return hidden;
	    function visit(node, ancestorCollapsed = false) {
	      if (!node) return;
	      const hiddenByAncestor = ancestorCollapsed && node.type !== 'INVISIBLE_ROOT';
	      if (hiddenByAncestor && node.mac) hidden.add(node.mac);
	      const childAncestorCollapsed = ancestorCollapsed || collapsedSet.has(node.mac);
	      asArray(node.children).forEach((child) => visit(child, childAncestorCollapsed));
	    }
	    visit(root, false);
	    return hidden;
	  }

  function leafCount(node) {
    if (!node.children || !node.children.length) return 1;
    return node.children.reduce((sum, child) => sum + leafCount(child), 0);
  }

  function layout(root, options = {}) {
	    const nodes = [];
	    const labelWidth = options.labelWidth || 0;
	    const levelGap = C.hD + C.dB + labelWidth + 72;
	    let cursor = 0;
	    function visit(node, depth, parent) {
	      const start = cursor;
	      if (node.children && node.children.length) {
	        node.children.forEach((child) => visit(child, depth + 1, node));
        node.x = (start + cursor - C.hD) / 2;
	      } else {
	        node.x = cursor;
	        cursor += C.hD + 28;
	      }
      node.y = depth * levelGap;
      if (node.type === 'ISP') node.y += C.zU + labelWidth;
      node.parentX = parent ? parent.x : node.x;
      node.parentY = parent ? parent.y : node.y;
      nodes.push(node);
    }
    if (root && root.wanFanIn) {
      const wans = root.children.filter((node) => node.type === 'ISP');
      const gateway = root.children.find((node) => node.mac === root.wanFanIn.gatewayMac);
      const wanSpacing = C.hD + 34;
      const wanStart = -((wans.length - 1) * wanSpacing) / 2;
      wans.forEach((wan, index) => {
        wan.x = wanStart + index * wanSpacing;
        wan.y = 0;
        wan.parentX = wan.x;
        wan.parentY = wan.y;
        nodes.push(wan);
      });
      if (gateway) {
        cursor = 0;
        visit(gateway, 1, null);
        const gatewayX = gateway.x;
        const gatewayY = gateway.y;
        const shiftY = C.hD + C.dB + labelWidth + 72 - gatewayY;
        nodes.filter((node) => node !== gateway && node.type !== 'ISP').forEach((node) => {
          node.x -= gatewayX;
          node.y += shiftY;
          node.parentX -= gatewayX;
          node.parentY += shiftY;
        });
        gateway.x = 0;
        gateway.y += shiftY;
        gateway.parentX = gateway.x;
        gateway.parentY = gateway.y;
      }
    } else {
      visit(root, 0, null);
    }
    const center = root && root.wanFanIn
      ? nodes.find((node) => node.type === 'DEVICE')
      : (nodes.find((node) => node.type === 'ISP') || nodes.find((node) => node.type === 'DEVICE') || nodes[0]);
    const dx = center ? -center.x : 0;
    const dy = center ? -center.y : 0;
    nodes.forEach((node) => {
      node.x += dx;
      node.y += dy;
      node.parentX += dx;
      node.parentY += dy;
      if (options.rotateMap) {
        const x = node.x;
        node.x = node.y;
        node.y = x;
        const parentX = node.parentX;
        node.parentX = node.parentY;
        node.parentY = parentX;
      }
    });
    const links = [];
    nodes.forEach((node) => {
      asArray(node.children).forEach((child) => links.push({ source: node, target: child, edge: child.edge || {} }));
    });
    if (root && root.wanFanIn) {
      const gateway = nodes.find((node) => node.mac === root.wanFanIn.gatewayMac);
      if (gateway) nodes.filter((node) => node.type === 'ISP').forEach((wan) => links.push({ source: wan, target: gateway, edge: wan.edge || {} }));
    }
    return { nodes, links: links.filter((link) => link.source.type !== 'INVISIBLE_ROOT') };
  }

  function computeTransform(nodes, width, height, extraPoints = []) {
    const visible = nodes.filter((node) => node.type !== 'INVISIBLE_ROOT');
    if (!visible.length && !extraPoints.length) return { x: width / 2, y: height / 2, k: 1 };
    const bounds = visible.reduce((acc, node) => ({
      minX: Math.min(acc.minX, node.y - C.hD / 2),
      maxX: Math.max(acc.maxX, node.y + C.hD / 2),
      minY: Math.min(acc.minY, node.x - C.hD / 2),
      maxY: Math.max(acc.maxY, node.x + C.hD / 2)
    }), { minX: Infinity, maxX: -Infinity, minY: Infinity, maxY: -Infinity });
    extraPoints.forEach((point) => {
      if (!point || !Number.isFinite(point.x) || !Number.isFinite(point.y)) return;
      bounds.minX = Math.min(bounds.minX, point.x - 42);
      bounds.maxX = Math.max(bounds.maxX, point.x + 42);
      bounds.minY = Math.min(bounds.minY, point.y - 42);
      bounds.maxY = Math.max(bounds.maxY, point.y + 42);
    });
    const contentWidth = Math.max(1, bounds.maxX - bounds.minX);
    const contentHeight = Math.max(1, bounds.maxY - bounds.minY);
    const fit = Math.min((width * C.Zm) / contentWidth, (height * C.ZZ) / contentHeight);
    const k = Math.max(C.ku.min, Math.min(C.ku.max, fit));
    const center = {
      x: (bounds.minX + bounds.maxX) / 2,
      y: (bounds.minY + bounds.maxY) / 2
    };
    return {
      x: Math.round(width / 2 - center.x * k),
      y: Math.round(height / 2 - center.y * k),
      k
    };
  }

	  function linkPath(sourceX, sourceY, targetX, targetY, mode = LINK_MODE.NORMAL, rotateMap = false) {
	    if (mode === LINK_MODE.NORMAL) {
	      const start = { x: sourceY, y: sourceX };
	      const end = { x: targetY, y: targetX };
	      const horizontalDistance = end.x - start.x;
	      const verticalDistance = end.y - start.y;
	      if (rotateMap) {
	        if (Math.abs(horizontalDistance) < 4) {
	          const bend = Math.min(Math.max(Math.abs(verticalDistance) * 0.22, 32), 96);
	          return [
	            `M ${start.x} ${start.y}`,
	            `C ${start.x} ${start.y + bend}, ${end.x} ${end.y - bend}, ${end.x} ${end.y}`
	          ].join(' ');
	        }
	        const trunkOffset = Math.min(Math.max(Math.abs(verticalDistance) * 0.50, 96), 178);
	        const trunkY = verticalDistance >= 0
	          ? Math.min(start.y + trunkOffset, end.y - 58)
	          : Math.max(start.y - trunkOffset, end.y + 58);
	        const radius = Math.min(22, Math.max(12, Math.abs(horizontalDistance) * 0.16));
	        const verticalSign = verticalDistance >= 0 ? 1 : -1;
	        const horizontalSign = horizontalDistance >= 0 ? 1 : -1;
	        return [
	          `M ${start.x} ${start.y}`,
	          `L ${start.x} ${trunkY - verticalSign * radius}`,
	          `Q ${start.x} ${trunkY}, ${start.x + horizontalSign * radius} ${trunkY}`,
	          `L ${end.x - horizontalSign * radius} ${trunkY}`,
	          `Q ${end.x} ${trunkY}, ${end.x} ${trunkY + verticalSign * radius}`,
	          `L ${end.x} ${end.y}`
	        ].join(' ');
	      }
	      if (Math.abs(verticalDistance) < 4) {
	        const bend = Math.min(Math.max(Math.abs(horizontalDistance) * 0.22, 32), 96);
	        return [
	          `M ${start.x} ${start.y}`,
	          `C ${start.x + bend} ${start.y}, ${end.x - bend} ${end.y}, ${end.x} ${end.y}`
	        ].join(' ');
	      }
	      const trunkOffset = Math.min(Math.max(Math.abs(horizontalDistance) * 0.50, 96), 178);
	      const trunkX = horizontalDistance >= 0
	        ? Math.min(start.x + trunkOffset, end.x - 58)
	        : Math.max(start.x - trunkOffset, end.x + 58);
	      const radius = Math.min(22, Math.max(12, Math.abs(verticalDistance) * 0.18));
	      const verticalSign = verticalDistance >= 0 ? 1 : -1;
	      const horizontalSign = horizontalDistance >= 0 ? 1 : -1;
      return [
        `M ${start.x} ${start.y}`,
        `L ${trunkX - horizontalSign * radius} ${start.y}`,
        `Q ${trunkX} ${start.y}, ${trunkX} ${start.y + verticalSign * radius}`,
        `L ${trunkX} ${end.y - verticalSign * radius}`,
        `Q ${trunkX} ${end.y}, ${trunkX + horizontalSign * radius} ${end.y}`,
        `L ${end.x} ${end.y}`
      ].join(' ');
    }
    let target;
    const xOffset = rotateMap ? C.cE : 0;
    const yOffset = rotateMap ? 0 : C.cE;
    const targetInset = rotateMap ? 0 : C.OI;
    switch (mode) {
      case LINK_MODE.MC_LAG_LEFT:
        target = { x: targetY + xOffset - targetInset, y: targetX + yOffset };
        break;
      case LINK_MODE.MC_LAG_RIGHT:
        target = { x: targetY - xOffset - targetInset, y: targetX - yOffset };
        break;
      case LINK_MODE.NORMAL:
      default:
        target = { x: targetY, y: targetX };
    }
    const startX = sourceY;
    const startY = sourceX;
    const nodeOffset = C.AD + C.hc;
    const elbowStart = {
      x: startX + (rotateMap ? 0 : nodeOffset),
      y: startY + (rotateMap ? nodeOffset : 0)
    };
    let first;
    let q1;
    let mid;
    let beforeEnd;
    let q2;
    let last;
    const positive = Math.sign(rotateMap ? target.x - startX : target.y - startY) === 1;
    const sameLine = rotateMap ? startX === target.x : startY === target.y;
    const radius = mode === LINK_MODE.NORMAL && sameLine ? C.E5 : C.cE / 2;
    if (sameLine) {
      first = q1 = mid = beforeEnd = q2 = last = { x: elbowStart.x, y: elbowStart.y };
    } else {
      first = { x: elbowStart.x + (rotateMap ? 0 : C.NX), y: elbowStart.y + (rotateMap ? C.NX : 0) };
      q1 = { x: first.x + (rotateMap ? 0 : radius), y: first.y + (rotateMap ? radius : 0) };
      mid = {
        x: q1.x + (rotateMap ? (positive ? radius : -radius) : 0),
        y: q1.y + (rotateMap ? 0 : (positive ? radius : -radius))
      };
      if (rotateMap) {
        beforeEnd = { x: target.x + (positive ? -radius : radius), y: mid.y };
        q2 = { x: target.x, y: mid.y };
        last = { x: target.x, y: mid.y + radius };
      } else {
        beforeEnd = { x: mid.x, y: target.y + (positive ? -radius : radius) };
        q2 = { x: beforeEnd.x, y: target.y };
        last = { x: beforeEnd.x + radius, y: target.y };
      }
    }
    return [
      `M ${startX} ${startY}`,
      `L ${first.x} ${first.y}`,
      `Q ${q1.x} ${q1.y}, ${mid.x} ${mid.y}`,
      `L ${beforeEnd.x} ${beforeEnd.y}`,
      `Q ${q2.x} ${q2.y}, ${last.x} ${last.y}`,
      `L ${target.x} ${target.y}`
    ].join(' ');
  }

  function visualBox(node) {
    return ({
      ISP: { width: 76, height: 76, centerX: 0, centerY: -24 },
      DEVICE: { width: 112, height: 64, centerX: 0, centerY: -25 },
      USW_WAN: { width: 70, height: 70, centerX: 0, centerY: -24 },
      CABLE_INTERNET: { width: 70, height: 70, centerX: 0, centerY: -24 },
      CLIENT: { width: 72, height: 72, centerX: 0, centerY: -24 },
      THIRD_PARTY_CLIENT: { width: 72, height: 72, centerX: 0, centerY: -24 }
    }[node.type] || { width: 72, height: 72, centerX: 0, centerY: -24 });
  }

	  function nodeVisualCenter(node, rotateMap = false) {
	    const visual = visualBox(node);
	    return { x: node.x + visual.centerY, y: node.y + visual.centerX };
	  }

  function linkAnchors(link, rotateMap = false) {
    return {
      source: nodeVisualCenter(link.source, rotateMap),
      target: nodeVisualCenter(link.target, rotateMap)
    };
  }

  function linkPathBetween(link, mode = LINK_MODE.NORMAL, rotateMap = false) {
    const anchors = linkAnchors(link, rotateMap);
    return linkPath(anchors.source.x, anchors.source.y, anchors.target.x, anchors.target.y, mode, rotateMap);
  }

  function trafficLevel(value, maxValue) {
    if (!value || !maxValue) return TRAFFIC_LEVEL[0];
    const pct = Math.max(0, Math.min(100, value / maxValue * 100));
    return TRAFFIC_LEVEL.find((level) => pct <= level.max) || TRAFFIC_LEVEL[TRAFFIC_LEVEL.length - 1];
  }

  function explicitTrafficLevel(...sources) {
    for (const source of sources) {
      if (!source || typeof source !== 'object') continue;
      const raw = number(source.traffic_level, source.trafficLevel, source.particle_level, source.particleLevel, source.level);
      if (!raw) continue;
      if (raw >= 1 && raw <= 5) return TRAFFIC_LEVEL[Math.round(raw)];
      if (raw > 5 && raw <= 100) return TRAFFIC_LEVEL.find((level) => raw <= level.max) || TRAFFIC_LEVEL[TRAFFIC_LEVEL.length - 1];
    }
    return null;
  }

  function linkCapacityMbps(link) {
    const edge = link.edge || {};
    const target = link.target || {};
    const raw = number(edge.rateMbps, edge.rate_mbps, edge.speed_mbps, edge.link_speed_mbps, target.rateMbps, target.rate_mbps);
    return raw || parseMbps(edge.link_speed || edge.speed || target.link_speed || target.speed);
  }

  function trafficLevelForLink(link, value) {
    if (!(Number(value) > 0)) return TRAFFIC_LEVEL[0];
    const explicit = explicitTrafficLevel(link.edge, link.edge && link.edge.traffic, link.target && link.target.traffic);
    if (explicit) return explicit;
    const capacityMbps = linkCapacityMbps(link);
    if (capacityMbps > 0) return trafficLevel(value, capacityMbps * 125000);
    for (let index = 1; index < ABSOLUTE_TRAFFIC_THRESHOLDS.length; index += 1) {
      if (value <= ABSOLUTE_TRAFFIC_THRESHOLDS[index]) return TRAFFIC_LEVEL[index];
    }
    return TRAFFIC_LEVEL[TRAFFIC_LEVEL.length - 1];
  }

  function linkTraffic(link) {
    const edgeTraffic = link && link.edge && link.edge.traffic || {};
    const sourceTraffic = link && link.source && link.source.traffic || {};
    const targetTraffic = link && link.target && link.target.traffic || {};
    const wanLink = link && link.source.type === 'ISP';
    const preferred = wanLink
      ? (edgeTraffic.known ? edgeTraffic : sourceTraffic)
      : (targetTraffic.known ? targetTraffic : edgeTraffic);
    return number(preferred.sum, number(preferred.tx) + number(preferred.rx));
  }

  function particleCount(distance, rate, maxRate) {
    const units = Math.max(1, (Number(distance) || 0) / 150);
    const normalized = maxRate > 0 ? Math.max(0.18, Math.min(1, Number(rate || 0) / maxRate)) : 0.22;
    return Math.min(Math.floor(Math.max(16 * units, 16) + 64 * normalized * units), 130);
  }

  function formatTopologyRate(bytesPerSecond, showZero = false) {
    const bps = Math.max(0, Number(bytesPerSecond) || 0) * 8;
    if (bps <= 0) return showZero ? '0 bps' : '';
    const units = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
    let current = bps;
    let index = 0;
    while (current >= 1000 && index < units.length - 1) {
      current /= 1000;
      index += 1;
    }
    const digits = current >= 100 || index === 0 ? 0 : current >= 10 ? 1 : 2;
    return `${current.toFixed(digits).replace(/\.0+$/, '')} ${units[index]}`;
  }

  function ratePairMarkup(tx, rx, known = false) {
    if (!known && !tx && !rx) return '';
    const down = formatTopologyRate(rx, known);
    const up = formatTopologyRate(tx, known);
    return `<span class="topology-node-rate" aria-label="实时速率">${down ? `<span class="down">↓ ${escapeHtml(down)}</span>` : ''}${up ? `<span class="up">↑ ${escapeHtml(up)}</span>` : ''}</span>`;
  }

  function mergedRateForNode(node, edge) {
    const nodeTraffic = node && node.traffic || {};
    const edgeTraffic = edge && edge.traffic || {};
    return {
      tx: number(nodeTraffic.tx, edgeTraffic.tx, node && node.up_rate, node && node.tx_rate),
      rx: number(nodeTraffic.rx, edgeTraffic.rx, node && node.down_rate, node && node.rx_rate),
      known: Boolean(nodeTraffic.known || edgeTraffic.known || [
        nodeTraffic.tx, nodeTraffic.rx, edgeTraffic.tx, edgeTraffic.rx,
        node && node.up_rate, node && node.down_rate, node && node.tx_rate, node && node.rx_rate
      ].some((value) => value !== undefined && value !== null))
    };
  }

  function distance(a, b) {
    const dx = b.y - a.y;
    const dy = b.x - a.x;
    return Math.sqrt(dx * dx + dy * dy);
  }

  function nodeIcon(node) {
    const shared = window.DWRT_DEVICE_IMAGES;
    const resolved = shared && typeof shared.resolve === 'function' ? shared.resolve(node) : null;
    const image = text(resolved && resolved.src, node.image);
    if (image) return `<img src="${escapeHtml(image)}" alt="">`;
    if (node.type === 'ISP') {
      if (node.overflow) {
        return '<span class="topology-glyph isp-overflow" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="10" cy="12" r="7"/><path d="M3 12h14M10 5c2 2 3 4.3 3 7s-1 5-3 7M10 5c-2 2-3 4.3-3 7s1 5 3 7"/><circle cx="19" cy="8" r=".8" fill="currentColor" stroke="none"/><circle cx="19" cy="12" r=".8" fill="currentColor" stroke="none"/><circle cx="19" cy="16" r=".8" fill="currentColor" stroke="none"/></svg></span>';
      }
      const logo = carrierImage(node);
      if (logo) return `<img src="${escapeHtml(logo)}" alt="${escapeHtml(node.name || 'ISP')}">`;
      return '<span class="topology-glyph isp"></span>';
    }
    if (node.type === 'USW_WAN' || node.type === 'CABLE_INTERNET') return '<span class="topology-glyph wan"></span>';
    if (node.type === 'DEVICE') return '<img src="/static/images/gateway-wide.svg" alt="">';
    return '<span class="topology-glyph client"></span>';
  }

  function buildDefs() {
    if (buildDefs.cache) return buildDefs.cache;
    const colors = ['#2fc7ff', '#5e60fc'];
    buildDefs.cache = TRAFFIC_LEVEL.flatMap((level) => Array.from({ length: 6 }, (_, variant) => {
      const circles = Array.from({ length: level.circlesInGroup }, (_, index) => {
        const width = level.particlesWidth || 0;
        const cx = width ? Math.random() * width - width / 2 : 0;
        const cy = width ? Math.random() * width - width / 2 : 0;
        const fill = colors[Math.random() < 0.5 ? 0 : 1];
        return `<circle data-i="${index}" r="0.5" fill="${fill}" cx="${cx.toFixed(2)}" cy="${cy.toFixed(2)}"></circle>`;
      }).join('');
      return `<g id="dwrt-traffic-${level.id}-variant-${variant}">${circles}</g>`;
    })).join('') + `
      <linearGradient id="dwrt-link-flow-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="#7fcaff" stop-opacity="0"/>
        <stop offset="18%" stop-color="#7fcaff" stop-opacity="0.12"/>
        <stop offset="50%" stop-color="#5aa8ff" stop-opacity="0.30"/>
        <stop offset="82%" stop-color="#7fcaff" stop-opacity="0.12"/>
        <stop offset="100%" stop-color="#7fcaff" stop-opacity="0"/>
      </linearGradient>
      <filter id="dwrt-link-soft-glow" x="-12%" y="-45%" width="124%" height="190%">
        <feGaussianBlur stdDeviation="3" result="blur"/>
        <feMerge><feMergeNode in="blur"/></feMerge>
      </filter>`;
    return buildDefs.cache;
  }

  function labelMeta(node, labels, edge) {
    const bits = [];
    if (node.ip) bits.push(node.ip);
    if (node.model) bits.push(node.model);
    if (labels.ssid !== false) {
      const ssid = text(node.ssid, edge && edge.essid);
      if (ssid) bits.push(`SSID ${ssid}`);
    }
    if (labels.signal !== false) {
      const signal = text(node.signal, edge && edge.signal);
      if (signal) bits.push(`${signal}`.match(/dbm|%/i) ? signal : `信号 ${signal}`);
    }
    if (labels.channel !== false) {
      const channel = text(node.channel, edge && edge.channel, edge && edge.radioBand);
      if (channel) bits.push(`信道 ${channel}`);
    }
    const kind = nodeConnectionKind(node, edge);
    if (kind === 'wireless' && labels.wifi !== false) bits.push('WiFi');
    if (kind !== 'wireless' && kind && labels.wired !== false) bits.push('有线');
    if (labels.stp !== false) {
      const stp = text(node.stpPriority, edge && edge.stpPriority);
      if (stp) bits.push(`STP ${stp}`);
    }
    if (node.connections) bits.push(`${node.connections} 连接`);
    if (node.app_name) bits.push(node.app_name);
    return bits.filter(Boolean).join(' · ');
  }

	  function branchButtonPosition(link, rotateMap = false) {
	    const anchors = linkAnchors(link, rotateMap);
	    const start = { x: anchors.source.y, y: anchors.source.x };
	    const end = { x: anchors.target.y, y: anchors.target.x };
	    const horizontalDistance = end.x - start.x;
	    const verticalDistance = end.y - start.y;
	    if (rotateMap) {
	      if (Math.abs(horizontalDistance) < 4) return null;
	      const trunkOffset = Math.min(Math.max(Math.abs(verticalDistance) * 0.50, 96), 178);
	      const trunkY = verticalDistance >= 0
	        ? Math.min(start.y + trunkOffset, end.y - 58)
	        : Math.max(start.y - trunkOffset, end.y + 58);
	      return { x: start.x, y: trunkY };
	    }
	    if (Math.abs(verticalDistance) < 4) return null;
	    const trunkOffset = Math.min(Math.max(Math.abs(horizontalDistance) * 0.50, 96), 178);
	    const trunkX = horizontalDistance >= 0
	      ? Math.min(start.x + trunkOffset, end.x - 58)
	      : Math.max(start.x - trunkOffset, end.x + 58);
	    return { x: trunkX, y: start.y };
	  }

	  function collectBranchLinks(tree, hiddenMacs) {
	    const branchBySource = new Map();
	    asArray(tree && tree.links).forEach((link) => {
	      if (!link || !link.source) return;
	      if (link.source.type === 'INVISIBLE_ROOT' || hiddenMacs.has(link.source.mac)) return;
	      if (asArray(link.source.children).length <= 1 || branchBySource.has(link.source.mac)) return;
	      branchBySource.set(link.source.mac, link);
	    });
	    return Array.from(branchBySource.values());
	  }

  function patchTopologyNodes(nodeLayer, nodes, filteredModel, state, formatRate) {
    const existing = new Map(Array.from(nodeLayer.children).map((element) => [element.dataset.nodeMac, element]));
    const wanted = new Set();
    nodes.forEach((node, index) => {
      const mac = String(node.mac || '');
      wanted.add(mac);
      let element = existing.get(mac);
      if (!element) {
        element = document.createElement('button');
        element.type = 'button';
        element.className = 'topology-node';
        element.dataset.nodeMac = mac;
        element.innerHTML = '<span class="topology-node-visual"></span><span class="topology-node-label"><strong></strong><small></small><span class="topology-node-rate" aria-label="实时速率"></span></span>';
      }
      const expectedAt = nodeLayer.children[index];
      if (expectedAt !== element) nodeLayer.insertBefore(element, expectedAt || null);

      const nodeEdge = node.edge || edgeForNode(filteredModel.edges, node);
      const rates = mergedRateForNode(node, nodeEdge);
      const meta = labelMeta(node, state.labels || {}, nodeEdge);
      const selected = state.selectedNodeMac && state.selectedNodeMac === node.mac;
      const className = `topology-node topology-node--${node.type.toLowerCase()}${node.overflow ? ' topology-node--wan-overflow' : ''} is-${nodeState(node)}${selected ? ' is-selected' : ''}`;
      if (element.className !== className) element.className = className;
      element.style.left = `${node.y}px`;
      element.style.top = `${node.x}px`;
      const omittedWanLines = asArray(node.omittedWans).map((wan) => {
        const identity = [wan.name, wan.id && wan.id !== wan.name ? wan.id : '', wan.ip].filter(Boolean).join(' · ');
        return `${identity || 'WAN'}${/connected/i.test(wan.state || '') && !/disconnected/i.test(wan.state || '') ? ' · 已连接' : ''}`;
      });
      const title = node.overflow
        ? [`已省略 ${omittedWanLines.length} 条 WAN`, ...omittedWanLines].join('\n')
        : [node.name || node.mac, node.ip, node.model, rates.known ? `下行 ${formatRate(rates.rx)}` : '', rates.known ? `上行 ${formatRate(rates.tx)}` : '', node.connections ? `${node.connections} 连接` : '', node.route_reason].filter(Boolean).join('\n');
      const nativeTitle = node.overflow ? '' : title;
      if (element.title !== nativeTitle) element.title = nativeTitle;
      if (node.overflow) {
        element.dataset.wanOverflow = 'true';
        element.dataset.wanTooltip = title;
        element.setAttribute('aria-label', title.replace(/\n/g, '，'));
      } else {
        delete element.dataset.wanOverflow;
        delete element.dataset.wanTooltip;
        element.removeAttribute('aria-label');
      }

      const visual = element.querySelector('.topology-node-visual');
      const icon = nodeIcon(node);
      if (visual) {
        visual.dataset.nodeType = node.type;
        if (visual.dataset.iconMarkup !== icon) {
          visual.innerHTML = icon;
          visual.dataset.iconMarkup = icon;
        }
      }
      const nameElement = element.querySelector('.topology-node-label strong');
      const metaElement = element.querySelector('.topology-node-label small');
      const rateElement = element.querySelector('.topology-node-rate');
      const name = String(node.name || node.mac);
      if (nameElement && nameElement.textContent !== name) nameElement.textContent = name;
      if (metaElement && metaElement.textContent !== meta) metaElement.textContent = meta;
      if (rateElement) {
        const down = formatTopologyRate(rates.rx, rates.known);
        const up = formatTopologyRate(rates.tx, rates.known);
        const rateMarkup = `${down ? `<span class="down">↓ ${escapeHtml(down)}</span>` : ''}${up ? `<span class="up">↑ ${escapeHtml(up)}</span>` : ''}`;
        if (rateElement.innerHTML !== rateMarkup) rateElement.innerHTML = rateMarkup;
        rateElement.hidden = !rateMarkup;
      }
    });
    existing.forEach((element, mac) => {
      if (!wanted.has(mac)) element.remove();
    });
  }

  function render(model, dom, options = {}) {
    const canvas = dom.canvas;
    const linkLayer = dom.linkLayer;
    const nodeLayer = dom.nodeLayer;
    const labelLayer = dom.labelLayer;
    const toggleLayer = dom.toggleLayer;
    const zoomContainer = dom.zoomContainer;
    if (!canvas || !linkLayer || !nodeLayer || !zoomContainer) return { ok: false, reason: 'missing dom' };
	    const state = options.state || {};
	    const filteredModel = filterModel(model, state.filters || {}, state);
	    const root = buildTree(filteredModel.vertices, filteredModel.edges);
	    const rotateMap = Boolean(state.rotateMap || model.layout && model.layout.rotateMap);
	    const tree = layout(root, { rotateMap, labelWidth: model.layout && model.layout.labelWidth ? C.VQ : 0 });
	    const collapsedBranches = branchCollapsedSet(state);
	    const hiddenMacs = hiddenDescendants(root, collapsedBranches);
	    const nodes = tree.nodes.filter((node) => node.type !== 'INVISIBLE_ROOT' && !hiddenMacs.has(node.mac));
	    const links = tree.links.filter((link) => (
	      link.target.type !== 'INVISIBLE_ROOT' &&
	      !hiddenMacs.has(link.source.mac) &&
	      !hiddenMacs.has(link.target.mac)
	    ));
	    const branchLinks = collectBranchLinks(tree, hiddenMacs);
	    const branchPoints = branchLinks
	      .map((link) => branchButtonPosition(link, rotateMap))
	      .filter(Boolean);
    if (!nodes.length) {
      linkLayer.innerHTML = '';
      nodeLayer.innerHTML = '';
      if (labelLayer) labelLayer.innerHTML = '';
      if (toggleLayer) toggleLayer.innerHTML = '';
      return { ok: false, reason: 'empty rendered tree' };
    }
    const rect = canvas.getBoundingClientRect();
    const width = Math.max(320, Math.round(rect.width || 960));
    const height = Math.max(320, Math.round(rect.height || 640));
    if (!state.transformSet || !state.lastRenderKey) {
      state.transform = computeTransform(nodes, width, height, branchPoints);
      state.transformSet = true;
    }
    zoomContainer.style.width = `${width}px`;
    zoomContainer.style.height = `${height}px`;
    zoomContainer.style.transform = `translate(${state.transform.x}px, ${state.transform.y}px) scale(${state.transform.k})`;

    linkLayer.innerHTML = `<defs>${buildDefs()}</defs><g class="topology-link-group"></g><g id="traffic-animations"></g>`;
    const linkGroup = linkLayer.querySelector('.topology-link-group');
    const trafficGroup = linkLayer.querySelector('#traffic-animations');
    const maxTrafficValue = Math.max(
      1,
      ...links.map(linkTraffic)
    );
    links.forEach((link) => {
      const path = linkPathBetween(link, LINK_MODE.NORMAL, rotateMap);
      const trafficValue = linkTraffic(link);
      const level = trafficLevelForLink(link, trafficValue);
      const hasTraffic = state.trafficEnabled !== false && trafficValue > 0;
      if (linkGroup) {
        const trackWidth = hasTraffic ? level.backgroundWidth : LINK_TRACK_WIDTH;
        const particleWidth = hasTraffic ? level.particlesWidth : 0;
        const haloEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        haloEl.setAttribute('d', path);
        haloEl.setAttribute('class', `topology-link topology-link-halo ${link.edge.type === 'WIRELESS' ? 'is-wireless' : 'is-wired'}`);
        haloEl.setAttribute('stroke-width', String(hasTraffic ? trackWidth + 2 : LINK_IDLE_WIDTH));
        haloEl.setAttribute('data-traffic-level', String(level.id));
        linkGroup.appendChild(haloEl);
        const pipeEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        pipeEl.setAttribute('d', path);
        pipeEl.setAttribute('class', `topology-link topology-link-pipe ${link.edge.type === 'WIRELESS' ? 'is-wireless' : 'is-wired'}`);
        pipeEl.setAttribute('stroke-width', String(hasTraffic ? Math.max(trackWidth, LINK_TRACK_WIDTH) : LINK_TRACK_WIDTH));
        pipeEl.setAttribute('data-traffic-level', String(level.id));
        linkGroup.appendChild(pipeEl);
        const flowEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        flowEl.setAttribute('d', path);
        flowEl.setAttribute('class', `topology-link topology-link-flow ${hasTraffic ? 'is-traffic' : ''} ${link.edge.type === 'WIRELESS' ? 'is-wireless' : 'is-wired'}`);
        flowEl.setAttribute('stroke-width', String(hasTraffic ? particleWidth : 0));
        flowEl.setAttribute('data-traffic-level', String(level.id));
        flowEl.setAttribute('data-rate', String(Math.round(trafficValue)));
        flowEl.setAttribute('data-source', link.source.mac);
        flowEl.setAttribute('data-target', link.target.mac);
        if (link.source.type === 'ISP') flowEl.setAttribute('data-wan-id', text(link.edge.wan_id, link.source.wan_id));
        linkGroup.appendChild(flowEl);
      }
      if (trafficGroup && hasTraffic && level.circlesInGroup) {
        const particle = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        particle.setAttribute('class', `topology-traffic-particle topology-traffic-level-${level.id}`);
        const count = particleCount(distance(link.source, link.target), trafficValue, maxTrafficValue);
        particle.innerHTML = Array.from({ length: count }, (_, index) => {
          const normalized = Math.max(0.18, Math.min(1, trafficValue / maxTrafficValue));
          const duration = Math.max(4.6, 12 - normalized * 5.8);
          const begin = `-${((index / count) * duration).toFixed(2)}s`;
          const variant = index % 6;
          return `<g><use href="#dwrt-traffic-${level.id}-variant-${variant}"></use><animate attributeName="opacity" dur="${duration}s" values="0;1;1;0" keyTimes="0;0.05;0.95;1" begin="${begin}" repeatCount="indefinite"></animate><animateMotion dur="${duration}s" repeatCount="indefinite" path="${escapeHtml(path)}" begin="${begin}"></animateMotion></g>`;
        }).join('');
        trafficGroup.appendChild(particle);
      }
    });
	    const branchButtons = branchLinks.map((link) => {
	      const pos = branchButtonPosition(link, rotateMap);
	      if (!pos) return '';
	      const childCount = asArray(link.source.children).length;
	      const collapsed = collapsedBranches.has(link.source.mac);
	      return `<button type="button" class="topology-branch-button${collapsed ? ' is-collapsed' : ''}" style="left:${pos.x}px;top:${pos.y}px" title="${escapeHtml(`${collapsed ? '展开' : '折叠'} ${link.source.name || 'Gateway'} · ${childCount} 条链路`)}" aria-label="${escapeHtml(`${collapsed ? '展开' : '折叠'} ${link.source.name || 'Gateway'} 分支`)}" aria-pressed="${collapsed ? 'true' : 'false'}" data-branch-source="${escapeHtml(link.source.mac)}"><span aria-hidden="true">${collapsed ? '+' : '−'}</span></button>`;
	    }).join('');

    const formatRate = typeof options.formatRate === 'function' ? options.formatRate : (value) => `${Math.round(value)}/s`;
    patchTopologyNodes(nodeLayer, nodes, filteredModel, state, formatRate);
    if (toggleLayer) toggleLayer.innerHTML = branchButtons;
    if (labelLayer) labelLayer.innerHTML = '';
    state.lastRenderKey = JSON.stringify({
      vertices: filteredModel.vertices.map((node) => [node.mac, node.name, node.state]).slice(0, 160),
      edges: filteredModel.edges.map((edge) => [edge.uplinkMac, edge.downlinkMac, edge.type]).slice(0, 200),
      traffic: state.trafficEnabled !== false,
	      filters: state.filters,
	      labels: state.labels,
	      collapsedBranches: Array.from(collapsedBranches).sort(),
	      rotateMap
	    });
    return { ok: true, nodes: nodes.length, links: links.length, source: SOURCE };
  }

  function isRenderable(model) {
    return Boolean(model && model.valid && asArray(model.vertices).length && asArray(model.edges).length);
  }

  window.DWRT_TOPOLOGY = {
    SOURCE,
    C,
    LINK_MODE,
    normalize,
    isRenderable,
    render,
    linkPath
  };
})();
