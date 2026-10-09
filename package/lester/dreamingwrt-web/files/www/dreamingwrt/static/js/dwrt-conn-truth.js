/*
 * Shared connection-count normalizer.
 *
 * One number is presented to users: conntrack public-address attribution
 * (`connections`). The JMX route-bound gauge `kernel_active_conn` used to be
 * displayed beside it, but its semantics are `route_bound` rather than a live
 * connection count, which nobody could read correctly, so the user removed it
 * from the UI on 2026-08-09. The backend still ships the field for
 * troubleshooting; this module deliberately offers no reader for it, so a page
 * cannot quietly put it back on screen.
 *
 * This module exists so dashboard.js and line-status.js stop growing their own
 * `connections / conn_count / conntrack_count / active_connections ...` guess
 * chains. The field set stays narrow: only names that mean conntrack
 * attribution, and a missing node yields unavailable rather than 0, because
 * "no rows" and "zero connections" are different facts.
 */
(() => {
  'use strict';

  const UNAVAILABLE_TEXT = '不可用';

  function finiteNumber(value) {
    if (value === undefined || value === null || value === '') return null;
    const num = Number(value);
    return Number.isFinite(num) ? num : null;
  }

  function text(value) {
    return value === undefined || value === null ? '' : String(value).trim();
  }

  /*
   * conntrack attribution count. This keeps the historical field aliases because
   * several producers (REST line-load, wan.metrics WS frames, dashboard
   * snapshot) genuinely spell it differently, but it is deliberately narrow:
   * only names that mean "conntrack attribution", never a kernel gauge.
   */
  const CONNTRACK_FIELDS = Object.freeze([
    'connections',
    'conn_count',
    'conntrack_count',
    'active_connections',
    'connection_count'
  ]);

  function conntrackCount(source) {
    if (!source || typeof source !== 'object') return null;
    for (const field of CONNTRACK_FIELDS) {
      if (!Object.prototype.hasOwnProperty.call(source, field)) continue;
      const num = finiteNumber(source[field]);
      if (num !== null) return num;
    }
    return null;
  }

  /*
   * Per-category traffic rows pass through exactly as the backend reported
   * them. Unknown stays Unknown: the frontend does not reclassify it or spread
   * it across the named categories.
   *
   * No web page reads these two right now: their only consumer was the kernel
   * category detail table, removed on 2026-08-09. They are kept because the
   * per-category breakdown itself was not what the user objected to (only the
   * kernel connection count was), and the backend is moving `active_conn` onto a
   * conntrack projection, at which point a category table can return without
   * reintroducing a second connection number.
   */
  function categoryRows(rows) {
    if (!Array.isArray(rows)) return [];
    return rows.map((row) => ({
      category: text(row && row.category) || 'Unknown',
      activeConn: finiteNumber(row && row.active_conn),
      txPackets: finiteNumber(row && row.tx_packets),
      rxPackets: finiteNumber(row && row.rx_packets),
      txBytes: finiteNumber(row && row.tx_bytes),
      rxBytes: finiteNumber(row && row.rx_bytes)
    }));
  }

  /* Totals sum the passed-through rows; nothing is re-derived per category. */
  function categoryTotal(categories) {
    const rows = Array.isArray(categories) ? categories : [];
    return rows.reduce((acc, row) => ({
      activeConn: acc.activeConn + (row.activeConn || 0),
      txPackets: acc.txPackets + (row.txPackets || 0),
      rxPackets: acc.rxPackets + (row.rxPackets || 0),
      txBytes: acc.txBytes + (row.txBytes || 0),
      rxBytes: acc.rxBytes + (row.rxBytes || 0)
    }), { activeConn: 0, txPackets: 0, rxPackets: 0, txBytes: 0, rxBytes: 0 });
  }

  /* conntrack attribution state for one WAN, with its source named. */
  function conntrackTruth(source) {
    const wan = source && typeof source === 'object' ? source : {};
    const count = conntrackCount(wan);
    return {
      count,
      valid: count !== null,
      source: text(wan.connections_source),
      state: text(wan.conntrack_state),
      reason: text(wan.conntrack_reason),
      markMatches: finiteNumber(wan.conntrack_mark_matches),
      addrMatches: finiteNumber(wan.conntrack_addr_matches),
      ifMatches: finiteNumber(wan.conntrack_if_matches),
      localIgnored: finiteNumber(wan.conntrack_local_source_ignored)
    };
  }

  function formatInteger(value) {
    const num = finiteNumber(value);
    return num === null ? UNAVAILABLE_TEXT : Math.round(num).toLocaleString('en-US');
  }

  function formatBytes(value) {
    const num = finiteNumber(value);
    if (num === null) return UNAVAILABLE_TEXT;
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let current = Math.max(0, num);
    let index = 0;
    while (current >= 1024 && index < units.length - 1) {
      current /= 1024;
      index += 1;
    }
    const digits = current >= 100 || index === 0 ? 0 : current >= 10 ? 1 : 2;
    return `${current.toFixed(digits).replace(/\.0+$/, '')} ${units[index]}`;
  }

  const api = Object.freeze({
    UNAVAILABLE_TEXT,
    conntrackCount,
    conntrackTruth,
    categoryRows,
    categoryTotal,
    formatInteger,
    formatBytes
  });

  if (typeof window === 'object' && window) window.DWRTConnTruth = api;
  if (typeof module === 'object' && module.exports) module.exports = api;
})();
