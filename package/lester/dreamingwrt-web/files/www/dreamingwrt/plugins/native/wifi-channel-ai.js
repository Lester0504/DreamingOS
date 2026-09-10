/*
 * Read-only renderers. The host owns requests, view state and event binding.
 * click:  [data-channel-ai-band] -> view.band; [data-channel-ai-refresh] -> GET plan;
 *         [data-channel-ai-clear] -> signalMin=-70, channelModes.clear(), default stats.
 * change: [data-channel-ai-stat] -> view.stats; [data-channel-ai-mode] -> view.channelModes.
 * input:  [data-channel-ai-signal-min] -> Number(input.value), clamped to [-70, -30].
 * dwrt-segment-change: [data-channel-ai-bands] -> event.detail.value (keyboard too).
 * Clearing preserves the selected band. Refresh never scans, applies or schedules.
 */
const BAND_ORDER = ['2g', '5g', '6g'];
const STATS = [
  ['utilization', '24h 信道利用率'],
  ['retry', '平均 TX 重试'],
  ['signal', '平均信号'],
  ['clients', '客户端'],
  ['interference', '平均干扰']
];
const DEFAULT_STATS = ['retry', 'signal', 'clients', 'interference'];
const STATUS_LABELS = {
  ready: '计划可用',
  partial_support: '部分证据支持',
  insufficient_evidence: '证据不足',
  scan_recommended: '建议补充扫描证据',
  configuration_too_complex: '配置复杂度超出规划范围',
  stale: '计划证据已过期'
};
const REASON_LABELS = {
  lower_neighbor_overlap: '邻居信道重叠更低',
  keep_current_hysteresis: '改善未达到变更阈值，保持当前',
  lower_busy_ratio: '信道忙碌比例更低',
  width_segment_legal: '信道宽度通过目录合法性检查',
  channels_insufficient: '可用信道证据不足',
  scan_recommended: '需要新的扫描证据',
  configuration_too_complex: '配置复杂度超出规划范围'
};
const array = (value) => Array.isArray(value) ? value : [];
const object = (value) => value && typeof value === 'object' && !Array.isArray(value) ? value : null;
const text = (...values) => values.find((value) => typeof value === 'string' && value.trim()) || '';
const number = (...values) => {
  for (const value of values) {
    if (value === null || value === undefined || value === '' || typeof value === 'boolean') continue;
    const result = Number(value);
    if (Number.isFinite(result)) return result;
  }
  return null;
};
const positive = (...values) => {
  for (const value of values) {
    const result = number(value);
    if (result !== null && result > 0) return result;
  }
  return null;
};
const trueFlag = (value) => value === true || value === 1;
const has = (values, key) => values instanceof Set ? values.has(key) : array(values).includes(key);
const radioId = (radio) => text(radio.radio_id, radio.id, radio.local_id);
const localId = (id) => String(id || '').split(':radio:').pop();

export function channelAiBand(value) {
  const raw = String(value || '').toLowerCase().replace(/\s/g, '');
  return ({ '2g': '2g', '2.4g': '2g', '2ghz': '2g', '2.4ghz': '2g',
    '5g': '5g', '5ghz': '5g', '6g': '6g', '6ghz': '6g' })[raw] || '';
}

function matchesRadio(row, radio) {
  const id = radioId(row);
  const target = radioId(radio);
  if (!id || !target) return false;
  if (row.ap_id && radio.ap_id && row.ap_id !== radio.ap_id) return false;
  return id === target || Boolean(row.ap_id && row.ap_id === radio.ap_id && localId(id) === localId(target));
}

function catalogEntries(radio) {
  const catalog = object(radio.channel_catalog) || {};
  const entries = new Map();
  array(catalog.channels).forEach((entry) => {
    const channel = positive(entry?.channel);
    if (channel !== null) entries.set(channel, { ...entry, channel });
  });
  array(catalog.supported_channels).concat(array(radio.supported_channels)).forEach((value) => {
    const channel = positive(value);
    if (channel !== null && !entries.has(channel)) entries.set(channel, { channel });
  });
  return entries;
}

function channelState(radio, channel) {
  const entry = catalogEntries(radio).get(channel);
  const contains = (key) => array(radio[key]).some((value) => number(value) === channel);
  if (contains('excluded_channels')) return 'excluded';
  if (contains('unavailable_channels') || trueFlag(entry?.disabled) || trueFlag(entry?.no_ir) ||
      ['radar', 'unavailable'].includes(entry?.dfs_state)) return 'unavailable';
  if (contains('dfs_channels') || trueFlag(entry?.dfs) || trueFlag(entry?.radar_detection) ||
      entry?.dfs_state === 'required') return 'dfs';
  return entry ? 'catalog' : 'unknown';
}

function currentFor(radio, planned) {
  if (planned) return { channel: positive(planned.current?.channel), width: positive(planned.current?.width_mhz) };
  return {
    channel: positive(radio.channel_operating, radio.runtime_channel, radio.operating_channel,
      radio.channel_display, radio.channel),
    width: positive(radio.width_operating, radio.runtime_width, radio.operating_width,
      radio.width_display, radio.width_mhz, radio.width)
  };
}

function channelMode(radio) {
  if (radio.channel_auto === true || radio.channel_auto === 1) return 'auto';
  if (radio.channel_auto === false || radio.channel_auto === 0) return 'manual';
  if (radio.channel === 'auto' || number(radio.channel) === 0) return 'auto';
  return positive(radio.channel) !== null ? 'manual' : '';
}

function nearestNeighbor(status, radio, now, maxAge) {
  const scan = status.environment?.neighborScan || status.environment?.neighbor_scan || {};
  if (trueFlag(scan.stale)) return { signal: null, time: null, reason: '邻居扫描已过期' };
  const samples = array(status.interference).length ? status.interference : array(scan.samples);
  const matching = samples.filter((row) => matchesRadio(row, radio));
  let reason = '邻居信号未上报';
  const fresh = matching.flatMap((row) => {
    const signal = number(row.rssi_dbm, row.signal, row.rssi);
    const time = positive(row.received_at, row.last_received_at, row.sample_time,
      scan.received_at, scan.latest_received_at, scan.observed_at);
    if (trueFlag(row.stale) || (time !== null && now - time > maxAge)) {
      reason = '邻居扫描已过期';
      return [];
    }
    if (time === null || time > now + 60) {
      reason = '邻居扫描时间未确认';
      return [];
    }
    return signal !== null && signal < 0 ? [{ signal, time, reason: '' }] : [];
  });
  return fresh.sort((a, b) => b.signal - a.signal)[0] || { signal: null, time: null, reason };
}

export function channelAiModel(status = {}, view = {}, now = Date.now() / 1000) {
  const response = object(view.data);
  const error = text(view.error, response?.ok === false ? text(response.error, response.reason, 'channel_ai_request_failed') : '');
  // An explicit empty/failed dedicated response must not silently revive the aggregate plan.
  const plan = response ? object(response.plan) : object(status.channel_ai?.plan);
  const radios = array(status.radios);
  const planned = array(plan?.radios);
  const rows = radios.map((radio) => {
    const matches = planned.filter((row) => matchesRadio(row, radio));
    return { radio, planned: matches.length === 1 ? matches[0] : null };
  });
  planned.forEach((row) => {
    if (!rows.some((item) => item.planned === row)) {
      rows.push({ radio: { id: row.radio_id, ap_id: row.ap_id, band: row.band }, planned: row });
    }
  });
  rows.forEach((row) => {
    row.band = channelAiBand(row.planned?.band) || channelAiBand(row.radio.band) ||
      channelAiBand(row.radio.channel_catalog?.band);
    row.current = currentFor(row.radio, row.planned);
    row.proposed = { channel: positive(row.planned?.proposed?.channel), width: positive(row.planned?.proposed?.width_mhz) };
    row.mode = channelMode(row.radio);
    row.neighbor = nearestNeighbor(status, row.radio, now, positive(plan?.freshness_policy?.neighbor_max_age_s) || 86400);
    row.signal = row.neighbor.signal;
  });
  const bands = BAND_ORDER.filter((band) => rows.some((row) => row.band === band));
  const band = bands.includes(view.band) ? view.band : (bands.includes('5g') ? '5g' : bands[0] || '');
  const bandRows = rows.filter((row) => row.band === band);
  const signalMin = Math.max(-70, Math.min(-30, number(view.signalMin) ?? -70));
  const modes = view.channelModes || new Set();
  const filtered = bandRows.filter((row) => (!(modes.size || array(modes).length) || has(modes, row.mode)) &&
    (row.signal === null ? signalMin === -70 : row.signal >= signalMin));
  const channels = new Set();
  bandRows.forEach((row) => {
    catalogEntries(row.radio).forEach((_, channel) => channels.add(channel));
    ['supported_channels', 'dfs_channels', 'excluded_channels', 'unavailable_channels'].forEach((key) => {
      array(row.radio[key]).forEach((value) => { if (positive(value) !== null) channels.add(positive(value)); });
    });
    if (row.current.channel !== null) channels.add(row.current.channel);
    if (row.proposed.channel !== null) channels.add(row.proposed.channel);
  });
  return { plan, error, rows: filtered, bandRows, bands, band, signalMin,
    unknownBandCount: rows.filter((row) => !row.band).length,
    channels: [...channels].sort((a, b) => a - b),
    stats: STATS.filter(([key]) => has(view.stats || DEFAULT_STATS, key)) };
}

function timestamp(value) {
  const seconds = positive(value);
  if (seconds === null) return '未上报';
  const date = new Date(seconds * 1000);
  return Number.isNaN(date.getTime()) ? '未上报' : `${date.toISOString().replace('T', ' ').replace('.000Z', '')} UTC`;
}

function legend() {
  return `<div class="airview-channel-ai-legend">${[
    ['current', '当前'], ['proposed', '建议'], ['catalog', '目录信道'],
    ['dfs', 'DFS'], ['unavailable', '不可用'], ['excluded', '已排除'], ['unknown', '未上报']
  ].map(([state, label]) => `<span><i class="airview-channel-ai-cell airview-channel-ai-cell-${state}" aria-hidden="true"></i>${label}</span>`).join('')}</div>`;
}

function checkbox(attribute, key, label, checked, h) {
  return `<label class="airview-channel-ai-check dwrt-kit-field" data-dwrt-component="field"><input type="checkbox" ${attribute}="${key}" value="${key}" ${checked ? 'checked' : ''}><span>${h.escapeHtml(label)}</span></label>`;
}

export function channelAiSidebar(status = {}, view = {}, helpers) {
  const h = helpers;
  const e = h.escapeHtml;
  const model = channelAiModel(status, view);
  const progress = ((model.signalMin + 70) / 40) * 100;
  return `<div class="airview-channel-ai-sidebar">
    ${model.bands.length ? `<div class="dwrt-kit-segmented airview-channel-ai-bands" data-dwrt-component="segmented" data-channel-ai-bands data-dwrt-value="${model.band}" role="radiogroup" aria-label="频段">${model.bands.map((band) => `<button type="button" data-dwrt-segment data-value="${band}" data-channel-ai-band="${band}" role="radio" aria-checked="${model.band === band}" class="${model.band === band ? 'is-active' : ''}">${e(h.bandLabel(band))}</button>`).join('')}</div>` : '<p class="airview-channel-ai-note">暂无已上报频段</p>'}
    <button type="button" class="dwrt-kit-button airview-channel-ai-refresh" data-dwrt-component="button" data-variant="primary" data-channel-ai-refresh ${view.loading ? 'disabled' : ''}>${h.icon('refresh')}<span>${view.loading ? '正在读取计划' : '建议新信道方案'}</span></button>
    <fieldset class="airview-channel-ai-section"><legend>最近邻居信号</legend>
      <div class="dwrt-kit-slider airview-channel-ai-slider" data-dwrt-component="slider" data-dwrt-slider-unit=" dBm" style="--dwrt-slider-progress:${progress}%"><input type="range" min="-70" max="-30" step="1" value="${model.signalMin}" data-channel-ai-signal-min aria-label="最近邻居最低信号" aria-valuetext="${model.signalMin} dBm"><output data-dwrt-slider-output>${model.signalMin} dBm</output></div>
      <div class="airview-channel-ai-ruler" aria-hidden="true"><span>-70</span><span>-60</span><span>-50</span><span>-40</span><span>-30 dBm</span></div>
      ${[...new Set(model.bandRows.map((row) => row.neighbor.reason).filter(Boolean))].map((reason) => `<small class="airview-channel-ai-note">${e(reason)}</small>`).join('')}
    </fieldset>
    <fieldset class="airview-channel-ai-section"><legend>${e(model.band ? h.bandLabel(model.band) : '')} 信道规划</legend>
      <div class="airview-channel-ai-catalog">${model.channels.map((channel) => {
        const current = model.bandRows.some((row) => row.current.channel === channel);
        const states = model.bandRows.map((row) => channelState(row.radio, channel));
        const state = current ? 'current' : states.includes('catalog') ? 'catalog' : states.find((item) => item !== 'unknown') || 'unknown';
        return `<span class="airview-channel-ai-cell airview-channel-ai-cell-${state}" data-dwrt-tooltip="信道 ${channel}">${channel}</span>`;
      }).join('')}</div>${model.channels.length ? '' : '<small class="airview-channel-ai-note">信道目录未上报</small>'}${legend()}
    </fieldset>
    <fieldset class="airview-channel-ai-section"><legend>统计信息</legend>${STATS.map(([key, label]) => checkbox('data-channel-ai-stat', key, label, has(view.stats || DEFAULT_STATS, key), h)).join('')}</fieldset>
    <fieldset class="airview-channel-ai-section"><legend>信道选择</legend>${[['auto', '自动'], ['manual', '手动']].map(([key, label]) => checkbox('data-channel-ai-mode', key, label, has(view.channelModes, key), h)).join('')}</fieldset>
    <button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-variant="ghost" data-channel-ai-clear>清除筛选条件</button>
  </div>`;
}

function deviceMarkup(radio, h) {
  const className = 'airview-channel-ai-device-image';
  const markup = h.deviceImage(radio, className);
  // The legacy image helper emits onerror. This module's fragment has no inline events.
  if (!/\son[a-z]+\s*=/i.test(markup)) return markup;
  const source = text(radio.image_url, radio.web_image, radio.image);
  const safeSource = /^(?:\/(?!\/)|https?:\/\/)/i.test(source);
  return `<span class="${className}">${safeSource ? `<img src="${h.escapeHtml(source)}" alt="" loading="lazy" decoding="async">` : h.icon('radio')}</span>`;
}

function metricCell(row, key, h) {
  const radio = row.radio;
  if (key === 'utilization') return h.past24hCell({ ...radio,
    past_24h_points: radio.past_24h_points || radio.history_24h,
    past_24h_reason: text(radio.past_24h_reason, radio.history_24h_reason) });
  const definitions = {
    retry: [number(radio.retry_rate, radio.air_stats?.retry_rate_pct), text(radio.retry_rate_reason, radio.air_stats?.reason, radio.air_stats_reason)],
    signal: [number(radio.avg_signal, radio.avg_signal_dbm), text(radio.avg_signal_reason)],
    clients: [number(radio.clients, radio.station_count), text(radio.clients_reason, radio.station_count_reason)],
    interference: [number(radio.avg_interference, radio.avg_interference_pct, radio.air_stats?.obss_util_pct), text(radio.avg_interference_reason)]
  };
  const [value, reason] = definitions[key];
  const formatted = ['retry', 'interference'].includes(key) ? h.percentValue(value) : h.metricValue(value, key === 'signal' ? 'dBm' : '', key === 'clients' ? 0 : 1);
  return formatted !== null && formatted !== undefined
    ? h.escapeHtml(formatted)
    : `<span class="airview-channel-ai-missing" data-dwrt-tooltip="${h.escapeHtml(reason || '未上报')}">--<small>${h.escapeHtml(reason || '未上报')}</small></span>`;
}

function channelText(value) {
  return `${value.channel === null ? '--' : value.channel} / ${value.width === null ? '--' : value.width} MHz`;
}

function reasonText(reason) {
  if (typeof reason === 'string') return REASON_LABELS[reason] || reason;
  if (!object(reason)) return '';
  const code = text(reason.code, reason.reason);
  return [REASON_LABELS[code] || code, reason.channel ? `信道 ${reason.channel}` : '', text(reason.evidence, reason.source)].filter(Boolean).join(' · ');
}

function planCell(row, plan, h) {
  const p = row.planned;
  if (!p) return '<span class="airview-channel-ai-missing">计划不可用</span>';
  const e = h.escapeHtml;
  const confidence = ({ measured: '实测证据', degraded_bss_only: '仅 BSS 扫描（降级）', unknown: '未知' })[p.confidence] || text(p.confidence, '未上报');
  const action = ({ keep_current: '保持当前', suggest_change: '建议变更' })[p.action] || text(p.action, '未上报');
  const blocked = array(plan.blocked).filter((item) => matchesRadio(item, row.radio));
  const reasons = array(p.reasons).concat(blocked.map((item) => item.reason)).map(reasonText).filter(Boolean);
  const evidence = object(p.evidence) || {};
  const before = h.metricValue(number(p.score_before), '', 4);
  const after = h.metricValue(number(p.score_after), '', 4);
  const comparable = row.proposed.channel !== null;
  return `<div class="airview-channel-ai-plan"><strong>${e(action)}</strong>
    <span>可信度：${e(confidence)}</span>
    ${reasons.map((reason) => `<small>${e(reason)}</small>`).join('')}
    <span>评分：${e(before ?? '--')} → ${e(after ?? '--')}${comparable ? '' : '（无可用候选）'}</span>
    ${comparable && number(p.improvement_pct) !== null ? `<small>评分改善：${e(h.percentValue(p.improvement_pct))}</small>` : ''}
    <small>邻居：${e(timestamp(evidence.neighbor_observed_at))}</small>
    <small>目录：${e(timestamp(evidence.catalog_observed_at))}</small>
    <small>邻居 ${e(h.metricValue(number(evidence.neighbor_count), '', 0) ?? '--')} · Survey 样本 ${e(h.metricValue(number(evidence.survey_samples), '', 0) ?? '--')}</small>
  </div>`;
}

function planNotice(model, view, h) {
  const e = h.escapeHtml;
  if (model.error) return `<div class="airview-channel-ai-notice" role="alert"><strong>计划读取失败</strong><span>${e(model.error)}</span><span>${model.plan ? '显示上次计划，本次未刷新；新鲜度未确认。' : '计划不可用，以下仅显示已上报的 Radio 与信道目录。'}</span></div>`;
  if (view.loading) return `<div class="airview-channel-ai-notice" role="status">${model.plan ? '正在重新读取；以下为上次计划，尚未刷新。' : '正在读取信道计划；以下为已上报的 Radio 与信道目录。'}</div>`;
  if (!model.plan) return `<div class="airview-channel-ai-notice" role="status">计划不可用${view.loaded ? '' : '（尚未读取）'}，以下仅显示已上报的 Radio 与信道目录。</div>`;
  const state = text(model.plan.status, 'unknown');
  return `<div class="airview-channel-ai-notice" role="status"><strong>${e(STATUS_LABELS[state] || state)}</strong>${trueFlag(model.plan.stale) ? '<span>证据已过期</span>' : ''}<span>生成时间：${e(timestamp(model.plan.generated_at))}</span><span>评分模型：${e(text(model.plan.scoring_profile, '未上报'))}</span></div>`;
}

export function channelAiResults(status = {}, view = {}, helpers) {
  const h = helpers;
  const e = h.escapeHtml;
  const model = channelAiModel(status, view);
  const trackWidth = Math.max(260, model.channels.length * 30);
  const columns = [
    ['名称', 210], ['主信道轨道', trackWidth + 24],
    ...(model.plan ? [['建议信道 / 宽度', 150], ['计划与证据', 300]] : []),
    ...model.stats.map(([key, label]) => [label, key === 'clients' ? 80 : 140])
  ];
  const width = columns.reduce((sum, [, size]) => sum + size, 0);
  const heading = model.band ? `${h.bandLabel(model.band)} 信道方案` : '信道方案';
  return `<section class="airview-channel-ai-results dwrt-kit-table-wrap" data-dwrt-component="data-table" aria-label="${e(heading)}" aria-busy="${Boolean(view.loading)}">
    <div class="dwrt-kit-table-toolbar airview-channel-ai-toolbar"><div class="dwrt-kit-table-title"><strong>${e(heading)}</strong></div><span class="dwrt-kit-table-count">${model.rows.length} / ${model.bandRows.length} 个 Radio</span></div>
    ${planNotice(model, view, h)}
    <div class="dwrt-kit-table-scroll airview-channel-ai-scroll" data-channel-ai-scroll tabindex="0" aria-label="信道方案表格"><table class="dwrt-kit-table airview-channel-ai-table" style="width:${width}px;min-width:${width}px;--airview-channel-ai-track-columns:${Math.max(1, model.channels.length)}">
      <colgroup>${columns.map(([, size]) => `<col style="width:${size}px">`).join('')}</colgroup>
      <thead><tr>${columns.map(([label], index) => `<th scope="col">${index === 1 && model.channels.length ? `<div class="airview-channel-ai-track airview-channel-ai-axis" aria-label="${label}">${model.channels.map((channel) => `<span>${channel}</span>`).join('')}</div>` : e(label)}</th>`).join('')}</tr></thead>
      <tbody>${model.rows.map((row) => {
        const radio = row.radio;
        const name = text(radio.ap, radio.ap_name, radio.name, radio.ap_id, radioId(radio), '名称未上报');
        const detail = [text(radio.model), radioId(radio)].filter(Boolean).join(' · ');
        const title = `当前 ${channelText(row.current)}；建议 ${channelText(row.proposed)}`;
        return `<tr data-channel-ai-row="${e(radioId(radio))}"><td><div class="airview-channel-ai-device">${deviceMarkup(radio, h)}<span><strong title="${e(name)}">${e(name)}</strong><small title="${e(detail)}">${e(detail)}</small><small>当前 ${e(channelText(row.current))}</small><small>${row.mode ? row.mode === 'auto' ? '自动信道' : '手动信道' : '信道模式未上报'}</small>${row.signal !== null ? `<small data-dwrt-tooltip="收据时间：${e(timestamp(row.neighbor.time))}">最近邻居 ${e(h.metricValue(row.signal, 'dBm'))}</small>` : `<small>${e(row.neighbor.reason)}</small>`}</span></div></td>
          <td>${model.channels.length ? `<div class="airview-channel-ai-track" aria-label="${e(title)}">${model.channels.map((channel) => {
            const state = channelState(radio, channel);
            const current = row.current.channel === channel;
            const proposed = row.proposed.channel === channel;
            const label = `信道 ${channel}${current ? ` · 当前 ${channelText(row.current)}` : ''}${proposed ? ` · 建议 ${channelText(row.proposed)}` : ''} · ${state}`;
            return `<span class="airview-channel-ai-cell airview-channel-ai-cell-${state}${current ? ' airview-channel-ai-cell-current' : ''}${proposed ? ' airview-channel-ai-cell-proposed' : ''}" data-dwrt-tooltip="${e(label)}" aria-label="${e(label)}">${current || proposed ? channel : ''}</span>`;
          }).join('')}</div>` : '<span class="airview-channel-ai-missing">信道目录未上报</span>'}</td>
          ${model.plan ? `<td>${e(channelText(row.proposed))}</td><td>${planCell(row, model.plan, h)}</td>` : ''}${model.stats.map(([key]) => `<td>${metricCell(row, key, h)}</td>`).join('')}</tr>`;
      }).join('') || `<tr><td colspan="${columns.length}"><div class="airview-channel-ai-empty" data-dwrt-component="state-panel" data-dwrt-state="${view.loading ? 'loading' : 'empty'}">${h.icon('radio')}<strong>${model.bandRows.length ? '没有符合筛选条件的 Radio' : '本次快照未上报可展示的 Radio'}</strong>${model.bandRows.length ? '<button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-variant="ghost" data-channel-ai-clear>清除筛选条件</button>' : ''}</div></td></tr>`}</tbody>
    </table></div>
    <footer class="airview-channel-ai-footer">${legend()}${model.unknownBandCount ? `<small>${model.unknownBandCount} 个 Radio 的频段未上报</small>` : ''}${model.plan ? `<small>计划 ID：${e(text(model.plan.plan_id, '未上报'))} · 生成时间：${e(timestamp(model.plan.generated_at))}</small>` : ''}</footer>
  </section>`;
}
