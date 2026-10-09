(function (root) {
  'use strict';

  const MAX_HISTORY_GAP_MS = 360000;
  const array = value => Array.isArray(value) ? value : [];
  const text = value => typeof value === 'string' ? value.trim() : '';
  const number = value => typeof value === 'number' && Number.isFinite(value) ? value : null;
  // Managed AP IDs are UUIDs. Only real MAC addresses may lose separators.
  const identity = value => {
    const id = text(value).toLowerCase();
    return /^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/.test(id) ? id.replace(/[:-]/g, '') : id;
  };
  const aliases = node => [node.id, node.mac].map(identity).filter(Boolean);
  const offline = node => node.stale === true || node.online === false || /^(offline|disconnected)$/i.test(text(node.state));

  function historicalPath(snapshot, attachment, clientMac, requestedMs) {
    const data = snapshot && (snapshot.infrastructure ? snapshot : snapshot.data);
    const history = data?.history;
    const resolved = number(history?.resolved_timestamp ?? data?.resolved_timestamp);
    const hops = [];
    const result = (reason, complete = false) => ({
      status: complete ? 'complete' : hops.length ? 'partial' : 'unavailable',
      reason, resolved_timestamp: resolved, hops, complete
    });
    if (!(number(requestedMs) > 0)) return result('invalid_requested_timestamp');
    if (!data?.infrastructure || history?.historical !== true || !(resolved > 0)) return result('historical_snapshot_unavailable');
    if (resolved > requestedMs) return result('future_snapshot_rejected');
    if (requestedMs - resolved > MAX_HISTORY_GAP_MS) return result('historical_snapshot_stale');

    const infra = data.infrastructure;
    const nodes = new Map();
    const kinds = new Map();
    for (const [group, kind] of [['gateways', 'gateway'], ['aps', 'ap'], ['switches', 'switch'], ['clients', 'client']]) {
      for (const node of array(infra[group])) {
        if (!node || !aliases(node).length) continue;
        // A router's local AP has the same ID as its gateway, which remains the endpoint.
        for (const id of aliases(node)) if (!nodes.has(id)) nodes.set(id, node);
        if (!kinds.has(node)) kinds.set(node, kind);
      }
    }
    const find = value => nodes.get(identity(value));
    const clientKey = identity(clientMac);
    if (!clientKey) return result('client_identity_missing');
    let current = find(clientMac);
    const visited = new Set();
    const add = (node, detail) => {
      const id = text(node.id) || text(node.mac);
      for (const key of aliases(node)) visited.add(key);
      hops.push({ id, name: text(node.name) || id, kind: kinds.get(node) || 'client', detail });
    };

    if (attachment != null) {
      const timestamp = number(attachment.timestamp);
      if (attachment.complete !== true || !text(attachment.source) || !(timestamp > 0)) return result('attachment_incomplete');
      if (timestamp > requestedMs) return result('future_attachment_rejected');
      if (requestedMs - timestamp > MAX_HISTORY_GAP_MS) return result('attachment_stale');
      if (attachment.client_mac && identity(attachment.client_mac) !== clientKey) return result('attachment_client_mismatch');
      if (!text(attachment.ap_id)) return result('attachment_ap_missing');
      if (!current) current = { id: text(clientMac), mac: text(clientMac), name: text(clientMac) };
      add(current, '历史客户端');
      const ap = find(attachment.ap_id);
      if (!ap) return result('attachment_node_missing');
      if (!['ap', 'gateway'].includes(kinds.get(ap))) return result('attachment_node_not_ap');
      if (visited.has(identity(ap.id))) return result('topology_cycle');
      add(ap, ['历史附着', text(attachment.radio_id), text(attachment.interface)].filter(Boolean).join(' · '));
      current = ap;
    } else {
      if (!current || kinds.get(current) !== 'client') return result('client_node_missing');
      add(current, '历史客户端');
    }

    const trusted = new Set(['client_network_state.parent_mac', 'ac_station_roster', 'lldpcli.normalized_neighbors']);
    while (current) {
      if (offline(current)) return result('historical_node_offline');
      if (kinds.get(current) === 'gateway') return result('gateway_reached', true);
      const ids = aliases(current);
      const incoming = array(infra.links).filter(link => link && [link.downlink_node_id, link.downlink_mac]
        .some(id => ids.includes(identity(id))));
      if (!incoming.length) return result('uplink_missing');
      const usable = incoming.filter(link => link.relationship_complete === true && trusted.has(text(link.relationship_source))
        && link.bridge_fdb_conflict !== true && !/^(offline|disconnected)$/i.test(text(link.state)));
      if (!usable.length) {
        return result(incoming.some(link => link.relationship_source === 'ac_ap_adoption')
          ? 'adoption_uplink_not_measured' : 'uplink_unverified');
      }
      const parents = new Map();
      for (const link of usable) {
        const parent = find(link.uplink_node_id) || find(link.uplink_mac);
        const key = parent ? identity(parent.id || parent.mac) : identity(link.uplink_node_id || link.uplink_mac);
        parents.set(key, parent);
      }
      if (parents.size !== 1) return result('uplink_ambiguous');
      const parent = parents.values().next().value;
      if (!parent) return result('uplink_node_missing');
      if (aliases(parent).some(id => visited.has(id))) return result('topology_cycle');
      add(parent, kinds.get(parent) === 'gateway' ? '历史网关 · WAN 与每跳延迟未测量' : '历史拓扑关系');
      current = parent;
    }
    return result('uplink_missing');
  }

  function dnsGroups(rows, wanIds) {
    const allowed = new Set(array(wanIds).map(text).filter(Boolean));
    if (!allowed.size) return [];
    const groups = new Map();
    for (const row of array(rows)) {
      if (!row || row.method !== 'dns' || !allowed.has(text(row.wan_id))) continue;
      const finished = number(row.finished_at);
      const revision = number(row.sla_revision);
      if (!(finished > 0) || revision === null || !text(row.sla_id) || !text(row.target)) continue;
      const key = JSON.stringify([row.wan_id, row.sla_id, row.target, revision]);
      if (!groups.has(key)) groups.set(key, {
        key, label: `${row.wan_id} · ${row.target} · v${revision}`,
        wan_id: row.wan_id, sla_id: row.sla_id, target: row.target,
        sla_revision: revision, method: 'dns', scope: 'wan_bound_dns_probe', points: [], samples: new Set()
      });
      const group = groups.get(key);
      const sample = text(row.sample_id);
      if (sample && group.samples.has(sample)) continue;
      if (sample) group.samples.add(sample);
      const dns = number(row.dns_ms);
      const complete = row.valid === true && row.ok === true && dns !== null && dns >= 0;
      group.points.push({ timestamp: finished * 1000, dns_ms: complete ? dns : null, complete, segment: '', sample_id: sample });
    }
    return [...groups.values()].map(group => {
      let segment = 0;
      group.points.sort((a, b) => a.timestamp - b.timestamp || a.sample_id.localeCompare(b.sample_id));
      for (const point of group.points) {
        point.segment = `${group.key}:${segment}`;
        if (!point.complete) segment++;
      }
      delete group.samples;
      return group;
    }).sort((a, b) => a.key.localeCompare(b.key));
  }

  root.DWRTClientObservabilitySources = Object.freeze({ historicalPath, dnsGroups });
})(globalThis);
