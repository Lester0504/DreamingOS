const VERSION = '20260804-wifi-telemetry-reason-01';

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const item = context.item || {};
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const stage = root?.closest('.console-stage');
  const isStatus = item.id === 'wireless-status';
  const ENDPOINT = isStatus ? '/api/v1/wifi/status' : '/api/v1/wifi/config';
  const BANDS = [
    { id: '2g', label: '2.4 GHz', range: '2412-2484 MHz', widths: [20, 40], channels: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14] },
    { id: '5g', label: '5 GHz', range: '5180-5885 MHz', widths: [20, 40, 80, 160], channels: [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165] },
    { id: '6g-low', band: '6g', label: '6 GHz', range: '5935-6515 MHz', widths: [20, 40, 80, 160, 320], channels: [1, 2, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125] },
    { id: '6g-high', band: '6g', label: '6 GHz', range: '6535-7115 MHz', widths: [20, 40, 80, 160, 320], channels: [129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189, 193, 197, 201, 205, 209, 213, 217, 221, 225, 229, 233] }
  ];
  const SECURITY = [
    ['open', '开放'], ['wpa2-personal', 'WPA2 Personal'], ['wpa2-wpa3', 'WPA2 / WPA3'],
    ['wpa3-personal', 'WPA3 Personal'], ['wpa2-enterprise', 'WPA2 Enterprise'],
    ['wpa2-wpa3-enterprise', 'WPA2 / WPA3 Enterprise'], ['wpa3-enterprise', 'WPA3 Enterprise']
  ];

  const state = {
    mounted: true,
    seq: 0,
    loading: true,
    loaded: false,
    refreshing: false,
    saving: false,
    scanning: false,
    error: '',
    notice: '',
    noticeTone: '',
    query: '',
    config: emptyConfig(),
    status: emptyStatus(),
    rawConfig: {},
    dirty: false,
    sheet: '',
    draft: null,
    configView: 'broadcasts',
    selectedRadio: '',
    selectedRadios: new Set(),
    radioDrafts: new Map(),
    radioDirty: false,
    apSheetAp: '',
    apSheetTab: 'overview',
    statusView: 'radios',
    filters: {
      ai: false, broadcast: 'all', aps: new Set(), bands: new Set(), mimo: new Set(), types: new Set(), status: new Set(),
      connectivityRange: 48, environmentAp: 'all', environmentBand: '', environmentRange: '1d', environmentWidths: new Set(), signalMin: -90, signalMax: -30
    },
    columns: {
      connectivity: new Set(['client', 'event', 'ap', 'result', 'signal', 'band', 'broadcast', 'time']),
      environment: new Set(['ap', 'name', 'signal', 'channel', 'width', 'standard', 'mac', 'security', 'vendor', 'nearest'])
    },
    columnEditor: '',
    statusFiltersReady: false,
    environmentHistory: { points: [], reason: 'not_loaded', resolution_seconds: 0, loading: false, error: '' },
    environmentHistorySeq: 0,
    connectivityEvents: { items: [], reason: 'not_loaded', loading: false, error: '' },
    connectivityEventsSeq: 0,
    scanJobs: new Map(),
    scanEpoch: 0,
    scanWaitResolve: null,
    scanTimer: 0,
    refreshTimer: 0
  };

  function formatUptimeSeconds(value) {
    const seconds = Number(value);
    if (!Number.isFinite(seconds) || seconds < 0) return '';
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (days > 0) return `${days} 天 ${hours} 小时`;
    if (hours > 0) return `${hours} 小时 ${minutes} 分钟`;
    return `${minutes} 分钟`;
  }

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (typeof value === 'object' && !Array.isArray(value)) {
        const nested = firstText(value.message, value.name, value.label, value.value, value.id);
        if (nested) return nested;
        continue;
      }
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }

  // One shared cap for every device/AP label in this route. CSS ellipsis alone
  // cannot bound a flex row whose text node has no element of its own, and a
  // per-name special case would drift the moment a longer model ships.
  const LABEL_MAX_CHARS = 22;

  function clipLabel(value, max = LABEL_MAX_CHARS) {
    const text = String(value ?? '').trim();
    if (Array.from(text).length <= max) return text;
    return `${Array.from(text).slice(0, max - 1).join('').trimEnd()}…`;
  }

  function firstNumber(...values) {
    for (const value of values) {
      if (value === '' || value === null || value === undefined) continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return 0;
  }

  function optionalNumber(...values) {
    for (const value of values) {
      if (value === '' || value === null || value === undefined) continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return null;
  }

  function bool(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') return !['0', 'false', 'off', 'no', 'disabled', 'down'].includes(value.toLowerCase());
    return Boolean(value);
  }

  function asArray(value, keys = []) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of [...keys, 'items', 'rows', 'list', 'data']) if (Array.isArray(value[key])) return value[key];
    return [];
  }

  function clone(value) {
    try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value || {})); }
  }

  function emptyConfig() {
    return {
      ts: 0,
      capabilities: { wifi: false, bands: [], source: '', save_config: false, apply_config: false, scan: false },
      regdomains: [],
      global: {
        enabled: true, country: 'CN', speed_profile: 'conservative', mesh: false, mesh_monitor: 'gateway', mesh_monitor_ip: '',
        auto_link: false, wifiman: false, band_steering: false, fast_roaming: false, mlo: false, dfs_enabled: false,
        roam_assist: false, roam_threshold: -75, multicast_enhance: false, airtime_fairness: false, isolated_guest: false,
        qca_rrm: false, qca_qbssload: false, mu_beamformer: false, doth: false, sae_pwe: false,
        channel_ai: false, widths: { '2g': 20, '5g': 80, '6g': 160 }
      },
      radios: [], ssids: [], speed_limits: []
    };
  }

  function emptyStatus() {
    return {
      ts: 0,
      capabilities: { wifi: false, runtime_status: false, radio_runtime: false, radio_update: false, scan: false },
      // Unknown is null, not 0: the backend distinguishes "no telemetry yet"
      // (null plus a *_reason) from a real zero, and seeding these at 0 made the
      // pre-load skeleton claim zero clients as if it were measured.
      summary: { clients: null, station_count: null, interface_count: null, phy_count: null, avg_signal: null, avg_utilization: null, avg_retry_rate: null, worst_noise: null },
      managedAps: [], radios: [], ssids: [], stations: [], interference: [], connectivityEvents: [],
      environment: { channelSurvey: { samples: [], reason: 'not_loaded' }, neighborScan: { samples: [], reason: 'not_loaded' }, spectralFft: { samples: [], reason: 'not_loaded' } },
      runtime: { available: false, reason: 'not_loaded' }
    };
  }

  function normalizeBand(value) {
    const text = String(value || '').toLowerCase().replace(/\s/g, '');
    if (['2g', '2.4g', '2.4ghz', 'ng', '11ng', 'radio0'].includes(text) || text.includes('2.4')) return '2g';
    if (['5g', '5ghz', 'na', '11ac', '11ax', 'radio1'].includes(text) || text.startsWith('5')) return '5g';
    if (['6g', '6ghz', '11be', 'radio2'].includes(text) || text.startsWith('6')) return '6g';
    return text || '';
  }

  // Driver/regdb channel truth from the APD iw-phy channel_catalog.
  // disabled and no-IR channels cannot host an AP BSS -> unavailable;
  // radar/DFS-flagged channels -> dfs; the rest -> enabled. Nothing is
  // invented when the catalog is absent or incomplete.
  function catalogChannels(radio, kind) {
    const catalog = radio && radio.channel_catalog;
    if (!catalog || !bool(catalog.complete, false)) return [];
    return asArray(catalog.channels).filter((entry) => {
      const disabled = bool(entry.disabled, false);
      const noIr = bool(entry.no_ir, false);
      const dfs = bool(entry.radar_detection, false) || Boolean(entry.dfs_state);
      if (kind === 'unavailable') return disabled || noIr;
      if (kind === 'dfs') return !disabled && !noIr && dfs;
      return !disabled && !noIr && !dfs;
    }).map((entry) => Number(entry.channel)).filter(Boolean);
  }

  function normalizeRadio(radio = {}, index = 0) {
    const runtime = radio.runtime && typeof radio.runtime === 'object' ? radio.runtime : {};
    const band = normalizeBand(firstText(radio.band, radio.radio, radio.frequency_band, runtime.band));
    const widths = asArray(radio.supported_widths || radio.widths || runtime.supported_widths).map(Number).filter(Boolean);
    const interfaces = asArray(radio.interfaces || runtime.interfaces);
    const apId = firstText(radio.ap_id, runtime.ap_id, radio.controller_device_id, radio.host_id);
    const apName = firstText(radio.ap_name, radio.ap, radio.device_name, radio.host, radio.site_name, radio.model, radio.product, apId ? `AP ${apId.slice(0, 8)}` : '', radio.phy, radio.device, radio.ifname, `Radio ${index + 1}`);
    const txPower = firstNumber(radio.tx_power, radio.txpower, radio.txpower_dbm, runtime.tx_power, runtime.txpower_dbm, ...interfaces.map((item) => item.txpower_dbm));
    const online = bool(radio.online ?? runtime.online, bool(radio.enabled ?? radio.configured_enabled, true));
    return {
      ...radio,
      id: firstText(radio.id, radio.phy, radio.device, radio.ifname, `radio-${index}`),
      name: firstText(radio.name, radio.device_name, radio.phy, radio.device, radio.ifname, `Radio ${index + 1}`),
      ap_id: apId || firstText(radio.ap_name, radio.ap, radio.device_name, radio.host, radio.name, radio.phy, `ap-${index}`),
      ap: apName,
      model: firstText(radio.model, radio.product, radio.hardware, ''),
      image_url: firstText(radio.image_url, radio.web_image, radio.image, radio.icon_url, runtime.image_url, runtime.web_image),
      image_available: bool(radio.image_available ?? runtime.image_available, Boolean(firstText(radio.image_url, radio.web_image, radio.image, runtime.image_url))),
      image_source: firstText(radio.image_source, runtime.image_source),
      image_model_match: firstText(radio.image_model_match, runtime.image_model_match),
      band,
      channel: firstNumber(radio.channel, runtime.channel),
      width: firstNumber(radio.width, radio.channel_width, runtime.width, runtime.channel_width),
      tx_power: txPower,
      tx_power_mode: firstText(radio.tx_power_mode, radio.power_mode, runtime.tx_power_mode),
      clients: optionalNumber(radio.clients, radio.station_count, runtime.clients, runtime.station_count),
      // 后端发的是 channel_utilization / channel_utilization_pct（同为 0..100 百分数），
      // 以及 noise_dbm。此前只读 utilization / noise，两项在真机上恒为空。
      utilization: optionalNumber(radio.utilization, radio.channel_utilization, radio.channel_utilization_pct, radio.airtime, runtime.utilization, runtime.channel_utilization, runtime.channel_utilization_pct),
      utilization_reason: firstText(radio.channel_utilization_reason, radio.utilization_reason, runtime.channel_utilization_reason, ''),
      utilization_source: firstText(radio.channel_utilization_source, runtime.channel_utilization_source, ''),
      interference: firstNumber(radio.interference, radio.external_interference, runtime.interference),
      avg_interference: optionalNumber(radio.avg_interference, radio.average_interference, runtime.avg_interference, runtime.average_interference),
      retry_rate: firstNumber(radio.retry_rate, radio.tx_retry, runtime.retry_rate),
      noise: optionalNumber(radio.noise_dbm, radio.noise, radio.noise_floor, runtime.noise_dbm, runtime.noise, runtime.noise_floor),
      noise_reason: firstText(radio.noise_reason, runtime.noise_reason, ''),
      noise_source: firstText(radio.noise_source, runtime.noise_source, ''),
      tx_power_mode_reason: firstText(radio.tx_power_mode_reason, runtime.tx_power_mode_reason, ''),
      avg_signal: firstText(radio.avg_signal, radio.average_signal, radio.signal, runtime.avg_signal, runtime.average_signal),
      past_24h: firstText(radio.past_24h, radio.last_24h, radio.history_24h, runtime.past_24h, runtime.last_24h),
      mimo: firstText(radio.mimo, radio.spatial_streams, runtime.mimo, ''),
      type: firstText(radio.uplink_type, radio.connection_type, runtime.uplink_type, runtime.connection_type),
      enabled: bool(radio.enabled, true),
      online,
      excluded_channels: asArray(radio.excluded_channels).map(Number).filter(Boolean),
      dfs_channels: asArray(radio.dfs_channels || runtime.dfs_channels).map(Number).filter(Boolean)
        .concat(catalogChannels(radio, 'dfs')),
      unavailable_channels: asArray(radio.unavailable_channels || runtime.unavailable_channels).map(Number).filter(Boolean)
        .concat(catalogChannels(radio, 'unavailable')),
      supported_widths: widths,
      supported_channels: asArray(radio.supported_channels || radio.channels).map(Number).filter(Boolean)
        .concat(catalogChannels(radio, 'enabled')),
      country: firstText(radio.country, radio.country_code, radio.channel_catalog?.regdomain, ''),
      min_rssi_enabled: bool(radio.min_rssi_enabled ?? radio.minimum_rssi_enabled, false),
      min_rssi: optionalNumber(radio.min_rssi, radio.minimum_rssi, radio.min_rssi_dbm),
      tx_power_custom: optionalNumber(radio.tx_power_custom, radio.custom_tx_power, radio.tx_power_dbm),
      channel_history: asArray(radio.channel_history || radio.history?.channel || runtime.channel_history),
      signal_distribution: asArray(radio.signal_distribution || radio.client_signal_distribution || runtime.signal_distribution),
      standard: firstText(radio.standard, radio.wifi_standard, radio.protocol, runtime.standard, runtime.wifi_standard),
      tx_retry_history: asArray(radio.tx_retry_history || radio.retry_history || runtime.tx_retry_history),
      air_stats: radio.air_stats && typeof radio.air_stats === 'object' ? radio.air_stats : runtime.air_stats && typeof runtime.air_stats === 'object' ? runtime.air_stats : {}
    };
  }

  function normalizeAp(ap = {}, index = 0) {
    const runtime = ap.runtime && typeof ap.runtime === 'object' ? ap.runtime : {};
    const id = firstText(ap.ap_id, ap.id, ap.device_id, runtime.ap_id, `ap-${index}`);
    return {
      ...ap,
      id,
      name: firstText(ap.name, ap.device_name, ap.model, ap.product, `AP ${index + 1}`),
      model: firstText(ap.model, ap.product, ap.hardware, runtime.model),
      image_url: firstText(ap.image_url, ap.web_image, ap.image, runtime.image_url),
      online: bool(ap.online ?? runtime.online, false),
      connection: firstText(ap.connected_to, ap.parent_name, ap.uplink_name, ap.uplink?.name, runtime.connected_to),
      ip: firstText(ap.ip, ap.ip_address, ap.address, ap.management_ip, runtime.ip, runtime.ip_address),
      mac: firstText(ap.mac, ap.mac_address, ap.device_mac, runtime.mac, runtime.mac_address),
      version: firstText(ap.firmware_version, ap.device_version, ap.version, runtime.firmware_version),
      uptime: firstText(ap.uptime_text, ap.uptime, runtime.uptime_text, runtime.uptime,
        formatUptimeSeconds(ap.uptime_seconds ?? runtime.uptime_seconds)),
      tags: asArray(ap.tags || ap.device_tags),
      mesh_parent: firstText(ap.mesh_parent, ap.mesh?.parent, runtime.mesh_parent),
      ap_group: firstText(ap.ap_group, ap.group, ap.site_name, runtime.ap_group),
      ip_mode: firstText(ap.ip_mode, ap.addressing_mode, ap.network?.mode, runtime.ip_mode),
      led_enabled: ap.led_enabled ?? ap.led?.enabled ?? runtime.led_enabled
    };
  }

  function normalizeSsid(ssid = {}, index = 0) {
    const bands = asArray(ssid.bands || ssid.radio_bands || ssid.wlan_bands).map(normalizeBand).filter(Boolean);
    const securityRaw = firstText(ssid.security, ssid.security_protocol, ssid.encryption, 'open').toLowerCase();
    const security = securityRaw.includes('wpa3') && securityRaw.includes('wpa2') ? 'wpa2-wpa3'
      : securityRaw.includes('enterprise') && securityRaw.includes('wpa3') ? 'wpa3-enterprise'
        : securityRaw.includes('enterprise') ? 'wpa2-enterprise'
          : securityRaw.includes('wpa3') || securityRaw.includes('sae') ? 'wpa3-personal'
            : securityRaw === 'none' || securityRaw.includes('open') ? 'open' : 'wpa2-personal';
    return {
      ...ssid,
      id: firstText(ssid.id, ssid.section, ssid.ifname, ssid.name, `wifi-${index}`),
      name: firstText(ssid.name, ssid.ssid, ssid.essid, '未命名 Wi-Fi'),
      radio_id: firstText(ssid.radio_id, ssid.runtime?.radio_id),
      ap_id: firstText(ssid.ap_id, ssid.runtime?.ap_id),
      bssid: firstText(ssid.bssid, ssid.mac, ssid.runtime?.bssid),
      network: firstText(ssid.network, ssid.lan, ssid.network_name, 'lan'),
      broadcast: firstText(ssid.broadcast, ssid.ap_group, ssid.broadcasting_aps, '全部 AP'),
      broadcast_mode: firstText(ssid.broadcast_mode, 'all'),
      bands: bands.length ? bands : ['2g', '5g'],
      clients: firstNumber(ssid.clients, ssid.station_count),
      enabled: bool(ssid.enabled, true),
      security,
      password_present: bool(ssid.password_present, Boolean(ssid.key || ssid.password)),
      password: '',
      vlan: firstText(ssid.vlan, ssid.vlan_id, ''),
      protocol: firstText(ssid.protocol, ssid.wifi_protocol, 'auto'),
      encryption: firstText(ssid.encryption, security === 'open' ? 'none' : security === 'wpa3-personal' ? 'sae+ccmp' : 'psk2+ccmp'),
      pmf: firstText(ssid.pmf, security.includes('wpa3') ? 'required' : 'optional'),
      mlo: bool(ssid.mlo), ppsk: bool(ssid.ppsk || ssid.private_pre_shared_keys),
      band_steering: bool(ssid.band_steering), fast_roaming: bool(ssid.fast_roaming || ssid.ieee80211r),
      ieee80211r: bool(ssid.ieee80211r || ssid.ft), ieee80211k: bool(ssid.ieee80211k), ieee80211v: bool(ssid.ieee80211v),
      rrm: bool(ssid.rrm), qbssload: bool(ssid.qbssload),
      mobility_domain: firstText(ssid.mobility_domain, ''), nasid: firstText(ssid.nasid, ''),
      reassociation_deadline: firstNumber(ssid.reassociation_deadline, 1000), ft_over_ds: bool(ssid.ft_over_ds, true),
      ft_psk_generate_local: bool(ssid.ft_psk_generate_local, true), hidden: bool(ssid.hidden), isolate: bool(ssid.isolate || ssid.client_isolation),
      multicast_enhance: bool(ssid.multicast_enhance), multicast_control: bool(ssid.multicast_control), proxy_arp: bool(ssid.proxy_arp),
      radius_mac_auth: bool(ssid.radius_mac_auth), radius_profile: firstText(ssid.radius_profile, ''),
      mac_filter: firstText(ssid.mac_filter, 'off'), mac_addresses: asArray(ssid.mac_addresses),
      schedule_enabled: bool(ssid.schedule_enabled), schedule: firstText(ssid.schedule, ''),
      force_wifi4: bool(ssid.force_wifi4), speed_limit_id: firstText(ssid.speed_limit_id, 'default'), remark: firstText(ssid.remark, ssid.note, '')
    };
  }

  function normalizeConfig(payload = {}) {
    const source = payload.config && typeof payload.config === 'object' ? payload.config : payload;
    const base = emptyConfig();
    const caps = source.capabilities || {};
    const radios = asArray(source.radios, ['devices']).map(normalizeRadio);
    const bands = asArray(caps.bands).map(normalizeBand).filter(Boolean);
    const global = source.global && typeof source.global === 'object' ? source.global : {};
    return {
      ...base,
      ...source,
      capabilities: {
        ...base.capabilities,
        ...caps,
        wifi: bool(caps.wifi, radios.length > 0),
        bands,
        save_config: bool(caps.save_config ?? caps.config_write ?? caps.update, false),
        apply_config: bool(caps.apply_config ?? caps.apply, false),
        scan: bool(caps.scan ?? caps.airtime_scan, false)
      },
      regdomains: asArray(source.regdomains || source.regions),
      global: {
        ...base.global,
        ...global,
        widths: { ...base.global.widths, ...(global.widths || global.channel_widths || {}) }
      },
      radios,
      ssids: asArray(source.ssids, ['wlans', 'networks']).map(normalizeSsid),
      speed_limits: asArray(source.speed_limits, ['speed_profiles', 'limits']).map((limit, index) => ({
        ...limit,
        id: firstText(limit.id, limit.name, `limit-${index}`),
        name: firstText(limit.name, `档案 ${index + 1}`),
        download_mbps: firstNumber(limit.download_mbps, limit.download),
        upload_mbps: firstNumber(limit.upload_mbps, limit.upload)
      }))
    };
  }

  function normalizeStatus(payload = {}) {
    const source = payload.status && typeof payload.status === 'object' ? payload.status : payload;
    const base = emptyStatus();
    const runtime = source.runtime && typeof source.runtime === 'object' ? source.runtime : {};
    const radios = asArray(source.runtime_radios || runtime.radios || source.radios).map(normalizeRadio);
    const caps = source.capabilities || {};
    const environment = source.environment && typeof source.environment === 'object' ? source.environment : {};
    const channelSurvey = environment.channel_survey && typeof environment.channel_survey === 'object' ? environment.channel_survey : {};
    const neighborScan = environment.neighbor_scan && typeof environment.neighbor_scan === 'object' ? environment.neighbor_scan : {};
    const spectralFft = environment.spectral_fft && typeof environment.spectral_fft === 'object' ? environment.spectral_fft : {};
    const neighborSamples = asArray(neighborScan.samples);
    return {
      ...base,
      ...source,
      capabilities: { ...base.capabilities, ...caps, wifi: bool(caps.wifi, radios.length > 0), scan: bool(caps.scan ?? caps.airtime_scan, false) },
      summary: { ...base.summary, ...(source.summary || {}) },
      managedAps: asArray(source.managed_aps, ['items']).map(normalizeAp),
      radios,
      ssids: asArray(source.ssids, ['wlans']).map(normalizeSsid),
      stations: asArray(source.stations || runtime.stations || source.clients),
      interference: asArray(source.interference || runtime.interference).length ? asArray(source.interference || runtime.interference) : neighborSamples,
      connectivityEvents: asArray(source.connectivity_events || source.events || runtime.connectivity_events || runtime.events),
      environment: {
        channelSurvey: { ...channelSurvey, samples: asArray(channelSurvey.samples) },
        neighborScan: { ...neighborScan, samples: neighborSamples },
        spectralFft: { ...spectralFft, samples: asArray(spectralFft.samples) }
      },
      runtime: { ...base.runtime, ...runtime }
    };
  }

  function environmentRangeSeconds(value = state.filters.environmentRange) {
    return ({ '30m': 1800, '1h': 3600, '1d': 86400, '1w': 604800, '1m': 2592000 })[value] || 86400;
  }

  async function loadEnvironmentHistory() {
    if (!isStatus || !state.mounted) return;
    const seq = ++state.environmentHistorySeq;
    const end = Math.floor(Date.now() / 1000);
    const seconds = environmentRangeSeconds();
    const query = new URLSearchParams({
      start: String(end - seconds),
      end: String(end),
      resolution: seconds > 86400 ? '3600' : '300',
      limit: '2048'
    });
    if (state.filters.environmentAp !== 'all') query.set('ap_id', state.filters.environmentAp);
    state.environmentHistory.loading = true;
    state.environmentHistory.error = '';
    patchLiveRegion();
    try {
      const payload = await requestJson(`/api/v1/wifi/environment/survey-history?${query}`, { cacheVersion: false });
      if (!state.mounted || seq !== state.environmentHistorySeq) return;
      state.environmentHistory = {
        points: asArray(payload.points),
        reason: firstText(payload.reason, asArray(payload.points).length ? 'available' : 'no_samples'),
        resolution_seconds: firstNumber(payload.resolution_seconds),
        loading: false,
        error: ''
      };
    } catch (error) {
      if (!state.mounted || seq !== state.environmentHistorySeq) return;
      state.environmentHistory = { points: [], reason: 'request_failed', resolution_seconds: 0, loading: false, error: firstText(error.message, '读取失败') };
    }
    patchLiveRegion();
  }

  function normalizeConnectivityEvent(event = {}) {
    const ap = state.status.managedAps.find((item) => item.id === event.ap_id);
    const radio = state.status.radios.find((item) => item.ap_id === event.ap_id &&
      (item.phy === event.radio_id || String(item.id).endsWith(`:${event.radio_id}`)));
    const ssid = state.status.ssids.find((item) => item.ap_id === event.ap_id &&
      (String(item.id).endsWith(`:${event.ssid_id}`) || item.interface === event.interface));
    const signalValue = event.signal_dbm ?? event.previous_signal_dbm;
    return {
      ...event,
      client: firstText(event.station_mac, '--'),
      event: ({ connect: '连接', disconnect: '断开', roam: '漫游' })[event.event] || firstText(event.event, '--'),
      ap: firstText(ap?.name, ap?.model, event.ap_id),
      signal: signalValue === null || signalValue === undefined ? '' : `${signalValue} dBm`,
      band: firstText(radio?.band, ''),
      ssid: firstText(ssid?.name, event.interface, event.from_interface),
      date_time: event.observed_at ? new Date(event.observed_at * 1000).toLocaleString() : ''
    };
  }

  async function loadConnectivityEvents() {
    if (!isStatus || !state.mounted) return;
    if (!bool(state.status.capabilities.connectivity_events, false)) return;
    const seq = ++state.connectivityEventsSeq;
    const end = Math.floor(Date.now() / 1000);
    const query = new URLSearchParams({
      start: String(end - state.filters.connectivityRange * 3600),
      end: String(end),
      limit: '256'
    });
    state.connectivityEvents.loading = true;
    state.connectivityEvents.error = '';
    try {
      const payload = await requestJson(`/api/v1/wifi/connectivity/events?${query}`, { cacheVersion: false });
      if (!state.mounted || seq !== state.connectivityEventsSeq) return;
      const items = asArray(payload.items).map(normalizeConnectivityEvent).reverse();
      state.connectivityEvents = {
        items,
        reason: firstText(payload.reason, items.length ? 'available' : 'no_events'),
        loading: false,
        error: ''
      };
    } catch (error) {
      if (!state.mounted || seq !== state.connectivityEventsSeq) return;
      state.connectivityEvents = { items: [], reason: 'request_failed', loading: false, error: firstText(error.message, '读取失败') };
    }
    if (state.statusView === 'connectivity') render();
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
    return { Accept: 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}), ...extra };
  }

  async function requestJson(url, options = {}) {
    const cacheVersion = options.cacheVersion !== false;
    const fetchOptions = { ...options };
    delete fetchOptions.cacheVersion;
    const response = await sessionFetch(cacheVersion ? `${url}${url.includes('?') ? '&' : '?'}v=${VERSION}` : url, {
      credentials: 'same-origin', cache: 'no-store', ...fetchOptions,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    const payload = json?.data ?? json?.body ?? json;
    if (!response.ok || json?.ok === false || payload?.ok === false) {
      const error = new Error(firstText(payload?.message, payload?.error, json?.message, json?.error, `HTTP ${response.status}`));
      error.status = response.status;
      throw error;
    }
    return payload || {};
  }

  async function load(background = false) {
    const seq = ++state.seq;
    if (background) state.refreshing = true; else state.loading = true;
    state.error = '';
    if (!background && !root.querySelector('.wifi-management-shell')) render();
    try {
      const payload = await requestJson(ENDPOINT);
      if (!state.mounted || seq !== state.seq) return;
      if (isStatus) {
        const keptDefaultFilters = state.statusFiltersReady && radioFiltersDefault();
        state.status = normalizeStatus(payload);
        if (state.statusView === 'connectivity' &&
            state.connectivityEvents.reason === 'not_loaded') loadConnectivityEvents();
        const apIds = Array.from(new Set(state.status.radios.map((radio) => radio.ap_id).filter(Boolean)));
        if (!apIds.includes(state.filters.environmentAp)) state.filters.environmentAp = apIds[0] || 'all';
        if (!state.statusFiltersReady || keptDefaultFilters) {
          state.filters.aps = new Set(state.status.radios.map((radio) => radio.ap_id).filter(Boolean));
          state.filters.bands = new Set(state.status.radios.map((radio) => radio.band).filter(Boolean));
          state.statusFiltersReady = true;
        }
      } else {
        state.rawConfig = clone(payload);
        state.config = normalizeConfig(payload);
      }
      state.loaded = true;
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.error = `${isStatus ? '读取无线运行状态' : '读取 Wi-Fi 配置'}失败：${firstText(error.message, '未知错误')}`;
    } finally {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      if (background) patchLiveRegion(); else render();
    }
  }

  function icon(name) {
    const icons = {
      plus: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg>',
      refresh: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11a8 8 0 1 0 2 5M20 4v7h-7"/></svg>',
      search: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>',
      wifi: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.6a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M12 20h.01M2 9a14 14 0 0 1 20 0"/></svg>',
      radio: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M15.165 12.598C14.135 14.152 12.66 15.5 10.5 15.5c-.825 0-1.673-.318-2.477-.782-.81-.467-1.614-1.105-2.363-1.8l.68-.734c.716.665 1.46 1.25 2.183 1.668.728.42 1.398.648 1.977.648 1.673 0 2.883-1.024 3.831-2.455l.834.553Z" fill="currentColor"/><path fill-rule="evenodd" clip-rule="evenodd" d="M10 2a8.002 8.002 0 0 0-7.908 6.782l-.003.003.002.003A8 8 0 1 0 10 2Zm6.885 9.269a7.045 7.045 0 0 0 .045-2.26c-.143.36-.3.744-.472 1.138l-.916-.4c.197-.452.374-.894.539-1.308l.067-.17c.123-.31.24-.607.352-.871A7.002 7.002 0 0 0 3.15 8.552c.348.481.784 1.042 1.28 1.624l-.762.648c-.236-.277-.46-.55-.668-.814 0 .357.028.707.08 1.05a4.013 4.013 0 0 0 1.002-.003c.803-.097 2.079-.447 4.194-1.504 3.947-1.973 7.018.435 8.61 1.716Zm-.28 1.056a22.738 22.738 0 0 1-.284-.225c-1.615-1.288-4.202-3.35-7.597-1.653-2.172 1.086-3.563 1.487-4.522 1.603a5.077 5.077 0 0 1-.886.034 7.003 7.003 0 0 0 13.289.241Z" fill="currentColor"/></svg>',
      connectivity: '<svg viewBox="0 0 20 20" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M14.14 12.856a.497.497 0 0 1 0-.697L16.278 10H3.719l2.136 2.159c.19.192.19.504 0 .697a.484.484 0 0 1-.69 0L2.3 9.959a.5.5 0 0 1-.3-.484.495.495 0 0 1 .142-.373l2.927-2.958c.19-.192.5-.192.69 0 .19.193.19.505 0 .698L3.622 9h12.752L14.24 6.842a.497.497 0 0 1 0-.698.485.485 0 0 1 .69 0l2.926 2.958c.19.193.19.505 0 .697l-3.024 3.057a.484.484 0 0 1-.69 0Z" fill="currentColor"/></svg>',
      environment: '<svg viewBox="0 0 20 20" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M13.348 3.025a.453.453 0 0 0-.307.004.376.376 0 0 0-.214.194l-2.58 5.808A1.002 1.002 0 0 0 9 10a1 1 0 1 0 1.984-.18L17.5 7.5c.193-.056.307-.231.265-.405-.22-.898-.641-1.446-1.471-2.232-.833-.79-1.88-1.465-2.946-1.838Z" fill="currentColor"/><path fill-rule="evenodd" clip-rule="evenodd" d="M10.54 5.447a.511.511 0 0 0-.498-.567h-.037A5.121 5.121 0 0 0 4.882 10a5.121 5.121 0 0 0 5.123 5.12 5.122 5.122 0 0 0 5.105-4.693.512.512 0 0 0-.519-.547c-.3 0-.529.242-.557.525a4.049 4.049 0 0 1-4.029 3.642 4.048 4.048 0 1 1 0-8.093.526.526 0 0 0 .531-.47l.004-.037Z" fill="currentColor"/><path fill-rule="evenodd" clip-rule="evenodd" d="M10.265 2.625c.29.01.55-.202.577-.498a.521.521 0 0 0-.494-.573 8.604 8.604 0 0 0-.343-.007C5.334 1.547 1.547 5.33 1.547 10s3.787 8.453 8.458 8.453a8.456 8.456 0 0 0 8.448-8.03.521.521 0 0 0-.527-.543.555.555 0 0 0-.548.53 7.383 7.383 0 0 1-7.373 6.97A7.382 7.382 0 0 1 2.621 10a7.382 7.382 0 0 1 7.644-7.375Z" fill="currentColor"/><path fill-rule="evenodd" clip-rule="evenodd" d="M10.005 11.787c.987 0 1.788-.8 1.788-1.787v-.03l5.886-1.96a.537.537 0 0 0 .356-.622c-.236-1.097-.925-2.223-1.799-3.168-.877-.95-1.983-1.766-3.113-2.218a.537.537 0 0 0-.7.304l-2.3 5.911a1.787 1.787 0 1 0-.118 3.57ZM10.553 10a.547.547 0 1 1-1.095 0 .547.547 0 0 1 1.095 0Zm6.3-2.847-5.4 1.8a1.797 1.797 0 0 0-.33-.347l2.095-5.382c.793.406 1.576 1.016 2.23 1.724.652.706 1.148 1.48 1.405 2.205Z" fill="currentColor"/></svg>',
      scan: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7V4h3M17 4h3v3M20 17v3h-3M7 20H4v-3M7 12h10"/></svg>',
      overview: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 13a8 8 0 0 1 16 0M7 13a5 5 0 0 1 10 0M10 13a2 2 0 0 1 4 0M5 18h14"/></svg>',
      insights: '<svg viewBox="0 0 20 20" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M11 3H9a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h2a1 1 0 0 0 1-1V4a1 1 0 0 0-1-1Zm0 1v10H9V4h2Zm3 2h2a1 1 0 0 1 1 1v7a1 1 0 0 1-1 1h-2a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1Zm2 8V7h-2v7h2ZM4 10h2a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1Zm2 4v-3H4v3h2Z" fill="currentColor"/><path d="M3.5 16h13a.5.5 0 0 1 0 1h-13a.5.5 0 0 1 0-1Z" fill="currentColor"/></svg>',
      settings: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2.86 2.86-.06-.06A1.7 1.7 0 0 0 15 19.4a1.7 1.7 0 0 0-1 .6 1.7 1.7 0 0 0-.4 1.1V21h-4v-.09A1.7 1.7 0 0 0 8.5 19.4a1.7 1.7 0 0 0-1.88.34l-.06.06-2.86-2.86.06-.06A1.7 1.7 0 0 0 4.1 15a1.7 1.7 0 0 0-1.51-1H2.5v-4h.09A1.7 1.7 0 0 0 4.1 9a1.7 1.7 0 0 0-.34-1.88l-.06-.06L6.56 4.2l.06.06A1.7 1.7 0 0 0 8.5 4.6a1.7 1.7 0 0 0 1-1.51V3h4v.09A1.7 1.7 0 0 0 15 4.6a1.7 1.7 0 0 0 1.88-.34l.06-.06 2.86 2.86-.06.06A1.7 1.7 0 0 0 19.4 9a1.7 1.7 0 0 0 1.51 1H21v4h-.09A1.7 1.7 0 0 0 19.4 15Z"/></svg>',
      close: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg>',
      chevron: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m9 18 6-6-6-6"/></svg>',
      info: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/></svg>',
      copy: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M15 9V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h3"/></svg>',
      sliders: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h10M18 7h2M4 17h2M10 17h10"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="17" r="2"/></svg>'
    };
    return icons[name] || icons.wifi;
  }

  function canConfigWrite() {
    const caps = state.config.capabilities;
    return caps.wifi && caps.save_config && caps.apply_config;
  }

  function optionList(options, current) {
    return options.map(([value, label]) => `<option value="${escapeHtml(value)}" ${String(current) === String(value) ? 'selected' : ''}>${escapeHtml(label)}</option>`).join('');
  }

  function switchRow(path, title, detail, checked, disabled = false) {
    return `<label class="wifi-setting-row dwrt-kit-switch" data-dwrt-component="switch"><span><strong>${escapeHtml(title)}</strong><small>${escapeHtml(detail)}</small></span><input type="checkbox" role="switch" data-wifi-setting="${escapeHtml(path)}" aria-label="${escapeHtml(title)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}></label>`;
  }

  function setPath(target, path, value) {
    const keys = String(path).split('.');
    let cursor = target;
    keys.slice(0, -1).forEach((key) => { if (!cursor[key] || typeof cursor[key] !== 'object') cursor[key] = {}; cursor = cursor[key]; });
    cursor[keys[keys.length - 1]] = value;
  }

  function getPath(target, path, fallback = '') {
    let cursor = target;
    for (const key of String(path).split('.')) { if (!cursor || typeof cursor !== 'object' || !(key in cursor)) return fallback; cursor = cursor[key]; }
    return cursor;
  }

  function bandLabel(band) { return ({ '2g': '2.4 GHz', '5g': '5 GHz', '6g': '6 GHz' })[band] || band || '--'; }
  function securityLabel(value) { return SECURITY.find(([id]) => id === value)?.[1] || value || '--'; }
  function bandPills(bands) { return (bands || []).map((band) => `<span class="wifi-band-pill is-${escapeHtml(band)}">${escapeHtml(bandLabel(band))}</span>`).join(''); }

  function deviceImage(device = {}, className = 'airview-device-image') {
    const shared = window.DWRT_DEVICE_IMAGES;
    const resolved = shared && typeof shared.resolve === 'function' ? shared.resolve(device) : null;
    const src = firstText(resolved?.src, device.image_url, device.web_image, device.image);
    return src
      ? `<span class="${className}"><img src="${escapeHtml(src)}" alt="" loading="lazy" decoding="async" onerror="this.hidden=true;this.nextElementSibling.hidden=false"><span hidden aria-hidden="true">${icon('radio')}</span></span>`
      : `<span class="${className} is-fallback" aria-hidden="true">${icon('radio')}</span>`;
  }

  function configToolbar() {
    return `<div class="wifi-page-toolbar"><button class="policy-create-button" type="button" data-wifi-create>${icon('plus')}<span>新建 Wi-Fi</span></button></div>`;
  }

  function configNavigation() {
    const tabs = [
      ['broadcasts', 'Wi-Fi 广播'],
      ['radios', 'Radio 与信道'],
      ['extensions', '扩展能力']
    ];
    const hasConfigurableWifi = state.loaded && (state.config.capabilities.wifi || state.config.radios.length || state.config.ssids.length);
    const action = state.configView === 'broadcasts' && hasConfigurableWifi ? configToolbar() : '';
    return `<header class="wifi-config-navigation"><nav class="dwrt-kit-tabs dwrt-kit-page-tabs wifi-config-tabs" role="tablist" aria-label="Wi-Fi 配置视图"><span class="dwrt-kit-tab-pill" aria-hidden="true"></span>${tabs.map(([id, label]) => `<button class="dwrt-kit-tab ${state.configView === id ? 'is-active' : ''}" type="button" role="tab" data-wifi-config-tab="${id}" aria-selected="${state.configView === id ? 'true' : 'false'}">${label}</button>`).join('')}</nav>${action}</header>`;
  }

  function configTable() {
    const query = state.query.trim().toLowerCase();
    const rows = state.config.ssids.filter((ssid) => !query || [ssid.name, ssid.network, ssid.broadcast, securityLabel(ssid.security), ...(ssid.bands || [])].join(' ').toLowerCase().includes(query));
    return `<section class="wifi-panel-section wifi-config-table"><header class="wifi-panel-heading"><div><strong>无线广播</strong><small>${rows.length} 个当前可见网络</small></div></header><div class="wifi-table-scroll"><table class="dwrt-kit-table"><thead><tr><th>名称</th><th>网络</th><th>广播 AP</th><th>无线电频段</th><th>客户端</th><th>安全</th><th><span class="sr-only">操作</span></th></tr></thead><tbody data-wifi-table-body>${rows.map((ssid) => `<tr data-wifi-edit="${escapeHtml(ssid.id)}" tabindex="0"><td><span class="wifi-name-cell"><i class="${ssid.enabled ? 'is-on' : ''}"></i><strong>${escapeHtml(ssid.name)}</strong></span></td><td>${escapeHtml(ssid.network || '--')}</td><td>${escapeHtml(ssid.broadcast || '全部 AP')}</td><td><div class="wifi-band-list">${bandPills(ssid.bands)}</div></td><td>${ssid.clients}</td><td>${escapeHtml(securityLabel(ssid.security))}</td><td><button class="wifi-row-button" type="button" aria-label="编辑 ${escapeHtml(ssid.name)}">${icon('chevron')}</button></td></tr>`).join('')}</tbody></table></div>${rows.length ? '' : `<div class="wifi-table-empty" data-dwrt-component="state-panel" data-dwrt-state="empty"><span>${icon('wifi')}</span><strong>${query ? '没有匹配的 Wi-Fi' : '尚未创建 Wi-Fi'}</strong><small>${query ? '调整搜索条件后重试。' : state.config.capabilities.wifi ? '使用“新建 Wi-Fi”创建第一个广播。' : '当前设备没有检测到无线 Radio，配置结构仍可查看。'}</small></div>`}</section>`;
  }

  function radioSummary() {
    const radios = state.config.radios;
    if (!radios.length) return `<div class="wifi-radio-empty" data-dwrt-component="state-panel" data-dwrt-state="unavailable"><strong>未检测到 Radio</strong><p>当前没有可配置无线电，因此不生成信道计划；无线硬件或受管 AP 上线后会原位显示。</p></div>`;
    return `<section class="wifi-panel-section wifi-radio-summary"><header class="wifi-section-head"><div><strong>Radio 摘要</strong><small>${radios.length} 个无线电，先确认硬件与当前信道，再调整全局策略。</small></div></header><div class="wifi-table-scroll"><table class="dwrt-kit-table"><thead><tr><th>Radio</th><th>频段</th><th>信道</th><th>宽度</th><th>发射功率</th><th>状态</th></tr></thead><tbody>${radios.map((radio) => `<tr><td><strong>${escapeHtml(radio.name)}</strong></td><td>${escapeHtml(bandLabel(radio.band))}</td><td>${radio.channel || '--'}</td><td>${radio.width ? `${radio.width} MHz` : '--'}</td><td>${radio.tx_power ? `${radio.tx_power} dBm` : '--'}</td><td><span class="dwrt-kit-status-badge is-${radio.online ? 'success' : 'error'}" data-dwrt-status="${radio.online ? 'success' : 'error'}"><i class="dwrt-kit-status-badge-dot" aria-hidden="true"></i><span>${radio.online ? '在线' : '离线'}</span></span></td></tr>`).join('')}</tbody></table></div></section>`;
  }

  function channelAvailability(band, channel) {
    const country = String(state.config.global.country || 'CN').toUpperCase();
    if (band === '2g' && country === 'US' && channel > 11) return 'unavailable';
    if (band === '2g' && country !== 'JP' && channel > 13) return 'unavailable';
    if (band === '5g' && channel >= 52 && channel <= 144) return state.config.global.dfs_enabled ? 'dfs' : 'unavailable';
    if (band === '6g' && !state.config.capabilities.bands.includes('6g')) return 'unavailable';
    return 'enabled';
  }

  function radioForBand(band) { return state.config.radios.find((radio) => radio.band === band); }

  function channelPlanBand(def) {
    const band = def.band || def.id;
    const radio = radioForBand(band);
    const excluded = new Set((radio?.excluded_channels || []).map(Number));
    const columns = def.channels.length;
    return `<div class="wifi-channel-band"><header><strong>${def.label}</strong><span>${def.range}</span></header><div class="wifi-channel-grid" style="--channel-count:${columns}"><span class="wifi-channel-axis">信道</span>${def.channels.map((channel) => `<span class="wifi-channel-number">${channel}</span>`).join('')}${def.widths.map((width) => `<span class="wifi-channel-axis">${width} MHz</span>${def.channels.map((channel) => {
      const availability = channelAvailability(band, channel);
      const using = radio && radio.channel === channel && radio.width === width;
      const excludedChannel = excluded.has(channel);
      const className = using ? 'is-using' : excludedChannel ? 'is-excluded' : `is-${availability}`;
      const disabled = !canConfigWrite() || availability === 'unavailable' || !radio;
      return `<button type="button" class="wifi-channel-cell ${className}" data-wifi-channel="${channel}" data-wifi-channel-band="${band}" data-wifi-channel-width="${width}" ${disabled ? 'disabled' : ''} data-dwrt-tooltip="${escapeHtml(`${def.label} · 信道 ${channel} · ${width} MHz${using ? ' · 使用中' : excludedChannel ? ' · 已排除' : availability === 'dfs' ? ' · DFS' : availability === 'unavailable' ? ' · 不可用' : ' · 已启用'}`)}"></button>`; }).join('')}`).join('')}</div></div>`;
  }

  function channelPlan() {
    return `<section class="wifi-panel-section"><header class="wifi-section-head"><div><strong>信道计划</strong><small>点击信道以将其从使用中排除</small></div></header><div class="wifi-channel-scroll">${BANDS.map(channelPlanBand).join('')}</div><div class="wifi-channel-legend"><span class="using">使用中</span><span class="enabled">已启用</span><span class="dfs">DFS</span><span class="unavailable">不可用</span><span class="excluded">已排除</span></div><button class="wifi-link-button" type="button" data-wifi-reset-channels ${canConfigWrite() ? '' : 'disabled'}>恢复默认</button></section>`;
  }

  function defaultSpeed() {
    const profile = state.config.global.speed_profile || 'conservative';
    const widths = state.config.global.widths || {};
    const bands = [
      ['2g', '2.4 GHz', [20, 40]],
      ['5g', '5 GHz', [20, 40, 80, 160]],
      ['6g', '6 GHz', [20, 40, 80, 160, 320]]
    ];
    return `<section class="wifi-panel-section wifi-unifi-global"><div class="wifi-unifi-setting-grid"><div class="wifi-unifi-label"><strong>默认 Wi-Fi 速度</strong><small>为全部 AP 设置默认信道宽度策略。</small></div><div class="wifi-speed-controls"><div class="wifi-radio-options">${[['maximum', '最高速度'], ['conservative', '保守'], ['custom', '自定义']].map(([value, label]) => `<label><input type="radio" name="wifi-speed-profile" value="${value}" data-wifi-setting="global.speed_profile" ${profile === value ? 'checked' : ''} ${canConfigWrite() ? '' : 'disabled'}><span>${label}</span></label>`).join('')}<button class="wifi-link-button is-inline" type="button" data-wifi-apply-all ${canConfigWrite() ? '' : 'disabled'}>应用于所有 AP</button></div><div class="wifi-width-picker"><strong>信道宽度 (MHz)</strong><div>${bands.map(([band, label, options]) => `<fieldset><legend>${label}</legend><span>${options.map((width) => `<button type="button" class="${Number(widths[band]) === width ? 'is-active' : ''}" data-wifi-width-band="${band}" data-wifi-width="${width}" ${canConfigWrite() ? '' : 'disabled'}>${width}</button>`).join('')}</span></fieldset>`).join('')}</div></div>${switchRow('global.dfs_enabled', '扩展 5 GHz 频谱 (DFS)', '允许自动信道使用 DFS 频段。', state.config.global.dfs_enabled, !canConfigWrite())}</div></div></section>`;
  }

  function globalSettings() {
    const global = state.config.global;
    const disabled = !canConfigWrite();
    return `<section class="wifi-panel-section"><header class="wifi-section-head"><div><strong>控制器能力</strong><small>按依赖关系管理 Mesh、设备发现与信道优化入口。</small></div></header><div class="wifi-settings-list">${switchRow('global.mesh', '无线 Mesh', '允许 AP 通过无线回程互联并扩展覆盖。', global.mesh, disabled)}<div class="wifi-dependency-panel ${global.mesh ? 'is-active' : ''}" data-dwrt-component="dependency-group"><div class="wifi-inline-setting" data-dwrt-dependency-panel><span><strong>Mesh 监视器</strong><small>仅在 Mesh 启用后用于检测无线回程上行连通性。</small></span><div class="wifi-radio-options compact">${[['gateway', 'Gateway'], ['custom', '自定义 IP']].map(([value, label]) => `<label><input type="radio" name="mesh-monitor" value="${value}" data-wifi-setting="global.mesh_monitor" ${global.mesh_monitor === value ? 'checked' : ''} ${disabled || !global.mesh ? 'disabled' : ''}><span>${label}</span></label>`).join('')}</div></div>${global.mesh && global.mesh_monitor === 'custom' ? `<div class="wifi-inline-setting" data-dwrt-dependency-panel><span><strong>监视器 IP</strong><small>AP 用于连通性探测的地址。</small></span><input type="text" data-wifi-setting="global.mesh_monitor_ip" value="${escapeHtml(global.mesh_monitor_ip || '')}" ${disabled ? 'disabled' : ''}></div>` : ''}</div>${switchRow('global.auto_link', 'UniFi 自动链接', '自动关联兼容的无线摄像机和 IoT 设备。', global.auto_link, disabled)}${switchRow('global.wifiman', 'WiFiman 支持', '允许移动端进行本地发现和信号测绘。', global.wifiman, disabled)}<div class="wifi-inline-setting"><span><strong>信道 AI</strong><small>根据相邻 AP 和干扰优化信道分配。</small></span><a href="#/monitor/wireless-status">前往无线状态</a></div></div></section>`;
  }

  function speedLimits() {
    const rows = state.config.speed_limits;
    return `<section class="wifi-panel-section wifi-speed-limits"><header class="wifi-section-head"><div><strong>速度限制档案</strong><small>供 Wi-Fi 广播按需引用，不改变未选择档案的网络。</small></div><button class="policy-create-button compact" type="button" data-wifi-speed-create>${icon('plus')}<span>新建</span></button></header><div class="wifi-table-scroll"><table class="dwrt-kit-table"><thead><tr><th>名称</th><th>下载</th><th>上传</th><th></th></tr></thead><tbody>${rows.map((limit) => `<tr data-wifi-speed-edit="${escapeHtml(limit.id)}"><td><strong>${escapeHtml(limit.name)}</strong></td><td>${limit.download_mbps ? `${limit.download_mbps} Mbps` : '无限制'}</td><td>${limit.upload_mbps ? `${limit.upload_mbps} Mbps` : '无限制'}</td><td><button class="wifi-row-button" type="button" aria-label="编辑 ${escapeHtml(limit.name)}">${icon('chevron')}</button></td></tr>`).join('')}</tbody></table></div>${rows.length ? '' : `<div class="wifi-compact-empty" data-dwrt-component="state-panel" data-dwrt-state="empty"><strong>没有速度限制档案</strong><p>新建档案后可在 Wi-Fi 编辑抽屉中选择。</p></div>`}</section>`;
  }

  function extendedSettings() {
    const global = state.config.global;
    const disabled = !canConfigWrite();
    const regions = state.config.regdomains.length ? state.config.regdomains : [{ code: global.country || 'CN', name: global.country || 'CN' }];
    return `<section class="wifi-panel-section"><header class="wifi-section-head"><div><strong>Dreaming OS 扩展设置</strong><small>OpenWrt、hostapd 与 QCA 驱动提供的附加配置维度。</small></div></header><div class="wifi-extension-grid"><label class="wifi-field"><span>地区码</span><select data-wifi-setting="global.country" ${disabled ? 'disabled' : ''}>${regions.map((region) => `<option value="${escapeHtml(region.code)}" ${String(region.code) === String(global.country) ? 'selected' : ''}>${escapeHtml(`${region.code} · ${region.name || region.code}`)}</option>`).join('')}</select><small>最终合法信道以后端 regdb 与驱动裁剪结果为准。</small></label><label class="wifi-field"><span>5 GHz 漫游阈值</span><div class="wifi-field-unit"><input type="number" min="-95" max="-45" data-wifi-setting="global.roam_threshold" value="${firstNumber(global.roam_threshold, -75)}" ${disabled ? 'disabled' : ''}><b>dBm</b></div></label></div><div class="wifi-settings-list two-columns">${switchRow('global.band_steering', '频段引导', '引导兼容终端优先使用高频段。', global.band_steering, disabled)}${switchRow('global.fast_roaming', '快速漫游', '启用 802.11k/v 的全局默认值。', global.fast_roaming, disabled)}${switchRow('global.mlo', 'MLO', 'Wi-Fi 7 多链路操作，需至少两个 Radio。', global.mlo, disabled)}${switchRow('global.airtime_fairness', 'Airtime Fairness', '避免低速终端长期占用空口。', global.airtime_fairness, disabled)}${switchRow('global.multicast_enhance', '组播增强', '将部分无线组播转换为单播，降低空口占用。', global.multicast_enhance, disabled)}${switchRow('global.qca_rrm', 'RRM', '启用 QCA/OpenWrt 无线资源测量。', global.qca_rrm, disabled)}${switchRow('global.qca_qbssload', 'QBSS Load', '广播 BSS 负载辅助终端选择 AP。', global.qca_qbssload, disabled)}${switchRow('global.mu_beamformer', 'MU Beamformer', '启用支持硬件的多用户波束成形。', global.mu_beamformer, disabled)}${switchRow('global.doth', '802.11h / DFS', '启用频谱管理与雷达检测相关能力。', global.doth, disabled)}${switchRow('global.sae_pwe', 'SAE PWE', '使用 WPA3 SAE H2E/兼容模式。', global.sae_pwe, disabled)}${switchRow('global.roam_assist', '漫游辅助', '根据阈值辅助低信号终端重新关联。', global.roam_assist, disabled)}</div></section>`;
  }

  function configViewContent() {
    if (state.configView === 'radios') return state.config.radios.length ? `${radioSummary()}${defaultSpeed()}${channelPlan()}` : radioSummary();
    if (state.configView === 'extensions') return `${globalSettings()}${extendedSettings()}`;
    return `${configTable()}<div class="wifi-notice is-info">${icon('info')}<span>为了实现最佳的物联网互操作性，建议为 2.4 GHz 物联网设备创建专用网络。</span></div>${speedLimits()}`;
  }

  function configStatePanel() {
    if (state.loading && !state.loaded) return `<section class="wifi-config-surface dwrt-kit-table-wrap dwrt-kit-glass-surface"><div data-dwrt-component="state-panel" data-dwrt-state="loading"><strong>正在读取 Wi-Fi 配置</strong><p>页面结构已就绪，配置返回后会原位更新。</p></div></section>`;
    if (!state.loaded && state.error) return `<section class="wifi-config-surface dwrt-kit-table-wrap dwrt-kit-glass-surface"><div data-dwrt-component="state-panel" data-dwrt-state="error"><strong>Wi-Fi 配置暂不可用</strong><p>读取失败不会回退到示例数据或本地配置；后端恢复后重新进入页面即可更新。</p></div></section>`;
    if (state.loaded && !state.config.capabilities.wifi && !state.config.radios.length && !state.config.ssids.length) return `<section class="wifi-config-surface dwrt-kit-table-wrap dwrt-kit-glass-surface"><div data-dwrt-component="state-panel" data-dwrt-state="unavailable"><strong>未检测到无线硬件</strong><p>当前设备没有可用 PHY 或受管 AP，因此不构造信道矩阵；接入无线设备后此页会显示完整设置。</p></div></section>`;
    return `<section class="wifi-config-surface dwrt-kit-table-wrap dwrt-kit-glass-surface" role="tabpanel" aria-label="${state.configView === 'broadcasts' ? 'Wi-Fi 广播' : state.configView === 'radios' ? 'Radio 与信道' : '扩展能力'}">${configViewContent()}</section>`;
  }

  function configPage() {
    const savebar = ui.floatingSavebarMarkup?.({ visible: state.dirty, omitWhenHidden: true, busy: state.saving, disabled: !canConfigWrite(), message: '有未应用的 Wi-Fi 更改', discardLabel: '放弃', busyLabel: '正在应用' }) || '';
    return `<div class="wifi-management-shell wifi-config-shell">${configNavigation()}${state.error ? `<div class="wifi-notice is-error">${icon('info')}<span>${escapeHtml(state.error)}</span></div>` : ''}${state.notice ? `<div class="wifi-notice ${state.noticeTone ? `is-${state.noticeTone}` : ''}">${icon('info')}<span>${escapeHtml(state.notice)}</span></div>` : ''}${configStatePanel()}${savebar}${sheetMarkup()}</div>`;
  }

  function defaultDraft() {
    return normalizeSsid({
      id: `wifi-${Date.now()}`,
      name: '', network: 'lan', broadcast: '全部 AP', broadcast_mode: 'all', bands: ['2g', '5g'], enabled: true,
      security: 'wpa2-wpa3', pmf: 'optional', protocol: 'auto', encryption: 'psk2+ccmp', fast_roaming: false,
      reassociation_deadline: 1000, ft_over_ds: true, ft_psk_generate_local: true, speed_limit_id: 'default'
    });
  }

  function sheetField(label, path, value, options = {}) {
    const type = options.type || 'text';
    const help = options.help ? `<small>${escapeHtml(options.help)}</small>` : '';
    if (options.options) return `<label class="wifi-field ${options.wide ? 'is-wide' : ''}"><span>${escapeHtml(label)}</span><select data-wifi-draft="${escapeHtml(path)}" ${options.disabled ? 'disabled' : ''}>${optionList(options.options, value)}</select>${help}</label>`;
    return `<label class="wifi-field ${options.wide ? 'is-wide' : ''}"><span>${escapeHtml(label)}</span><input type="${type}" data-wifi-draft="${escapeHtml(path)}" value="${escapeHtml(value ?? '')}" ${options.placeholder ? `placeholder="${escapeHtml(options.placeholder)}"` : ''} ${options.min !== undefined ? `min="${options.min}"` : ''} ${options.max !== undefined ? `max="${options.max}"` : ''} ${options.disabled ? 'disabled' : ''}>${help}</label>`;
  }

  function draftToggle(path, title, detail, disabled = false) {
    return switchRow(path, title, detail, bool(getPath(state.draft, path)), disabled).replace('data-wifi-setting=', 'data-wifi-draft-toggle=');
  }

  function ssidSheet() {
    const draft = state.draft || defaultDraft();
    const isNew = !state.config.ssids.some((ssid) => ssid.id === draft.id);
    const six = draft.bands.includes('6g');
    const multiBand = draft.bands.length >= 2;
    const forceWpa3 = six || draft.mlo;
    const ppskDisabled = six || draft.mlo || draft.security !== 'wpa2-personal';
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-wifi-sheet-close aria-label="关闭 Wi-Fi 编辑"></button><aside class="dwrt-kit-sheet wifi-sheet policy-stable-glass is-open" aria-label="${isNew ? '新建 Wi-Fi' : '编辑 Wi-Fi'}"><header class="dwrt-kit-sheet-header"><div><strong>${isNew ? '新建 Wi-Fi' : '编辑 Wi-Fi'}</strong><small>${escapeHtml(draft.name || '配置无线广播')}</small></div><button class="dwrt-kit-sheet-close wifi-icon-button" type="button" data-wifi-sheet-close aria-label="关闭">${icon('close')}</button></header><div class="dwrt-kit-sheet-body wifi-sheet-body">${canConfigWrite() ? '' : `<div class="wifi-inline-warning">${icon('info')}<span>当前设备没有可验证的 Wi-Fi 保存与应用能力。可以查看和调整草稿，最终保存保持禁用。</span></div>`}<section><h3>常规</h3><div class="wifi-sheet-fields">${sheetField('名称 / SSID', 'name', draft.name, { wide: true, placeholder: 'Wi-Fi 名称' })}${sheetField('网络', 'network', draft.network, { options: [['lan', 'LAN'], ['guest', '访客网络'], ['iot', 'IoT 网络']] })}${sheetField('VLAN ID', 'vlan', draft.vlan, { type: 'number', min: 1, max: 4094 })}${sheetField('广播 AP', 'broadcast_mode', draft.broadcast_mode, { options: [['all', '全部 AP'], ['group', 'AP 组'], ['specific', '指定 AP']] })}</div><div class="wifi-band-picker"><span>无线电频段</span>${['2g', '5g', '6g'].map((band) => `<label><input type="checkbox" data-wifi-draft-band="${band}" ${draft.bands.includes(band) ? 'checked' : ''} ${!state.config.capabilities.bands.includes(band) ? 'disabled' : ''}><i></i><span>${bandLabel(band)}</span></label>`).join('')}</div><div class="wifi-sheet-fields">${sheetField('安全协议', 'security', forceWpa3 ? 'wpa3-personal' : draft.security, { options: SECURITY.map(([value, label]) => [value, label]), disabled: forceWpa3 })}${sheetField('密码', 'password', '', { type: 'password', wide: true, placeholder: draft.password_present ? '已保存，留空保持不变' : '8-63 个字符' })}${sheetField('PMF', 'pmf', forceWpa3 ? 'required' : draft.pmf, { options: [['disabled', '关闭'], ['optional', '可选'], ['required', '强制']], disabled: forceWpa3 })}</div>${forceWpa3 ? `<div class="wifi-inline-warning">${icon('info')}<span>${six ? '6 GHz' : 'MLO'} 要求 WPA3 与强制 PMF，保存时将按该组合提交。</span></div>` : ''}</section><section><h3>高级</h3><div class="wifi-settings-list">${draftToggle('mlo', 'MLO', multiBand ? '允许兼容的 Wi-Fi 7 终端同时关联多个频段。' : 'MLO 至少需要选择两个频段。', !multiBand)}${draftToggle('ppsk', '私有预共享密钥', ppskDisabled ? '仅 WPA2 Personal 且不含 6 GHz/MLO 时可用。' : '不同密码可映射到不同网络或 VLAN。', ppskDisabled)}${draftToggle('band_steering', '频段引导', '引导兼容的 2.4 GHz 终端使用 5/6 GHz。')}${draftToggle('fast_roaming', '快速漫游 (802.11r)', draft.mlo ? 'MLO 终端可能与快速漫游存在兼容问题。' : '不支持 802.11r 的终端可能出现连接问题。')}${draftToggle('isolate', '客户端设备隔离', '阻止同一 AP 下的无线客户端互相通信。')}${draftToggle('hidden', '隐藏 Wi-Fi 名称', '不在 Beacon 中公开 SSID。')}${draftToggle('multicast_enhance', '组播增强', '将组播转换为单播以降低空口占用。')}${draftToggle('multicast_control', '组播与广播控制', '阻止不必要的组播和广播流量。')}${draftToggle('proxy_arp', 'Proxy ARP', '由 AP 代理常见广播帧，可能改善延迟。')}${draftToggle('radius_mac_auth', 'RADIUS MAC 认证', '使用终端 MAC 作为 RADIUS 凭据。', draft.ppsk)}${draftToggle('schedule_enabled', 'Wi-Fi 计划', '指定该 Wi-Fi 停止广播的时间。')}${draftToggle('force_wifi4', '强制 Wi-Fi 4 模式', '提高旧 IoT 终端兼容性。')}</div><div class="wifi-sheet-fields">${sheetField('MAC 地址筛选', 'mac_filter', draft.mac_filter, { options: [['off', '关闭'], ['allow', '允许列表'], ['deny', '拒绝列表']] })}${sheetField('RADIUS Profile', 'radius_profile', draft.radius_profile, { placeholder: '未配置' })}${sheetField('速度限制', 'speed_limit_id', draft.speed_limit_id, { options: state.config.speed_limits.map((limit) => [limit.id, limit.name]) })}${sheetField('计划', 'schedule', draft.schedule, { placeholder: '例如 周一至周五 08:00-20:00' })}</div></section><section><h3>Dreaming OS 扩展</h3><div class="wifi-sheet-fields">${sheetField('Wi-Fi 协议', 'protocol', draft.protocol, { options: [['auto', '自动'], ['11n', 'Wi-Fi 4 / 802.11n'], ['11ac', 'Wi-Fi 5 / 802.11ac'], ['11ax', 'Wi-Fi 6 / 802.11ax'], ['11be', 'Wi-Fi 7 / 802.11be']] })}${sheetField('UCI 加密', 'encryption', draft.encryption, { options: [['sae+ccmp', 'sae+ccmp'], ['sae-mixed', 'sae-mixed'], ['psk2+ccmp', 'psk2+ccmp'], ['psk-mixed', 'psk-mixed'], ['none', 'none']] })}</div><div class="wifi-settings-list">${draftToggle('ieee80211r', '802.11r Fast Transition', '启用 FT 漫游。')}${draftToggle('ieee80211k', '802.11k 邻居报告', '向终端提供候选 AP。')}${draftToggle('ieee80211v', '802.11v BSS Transition', '允许 AP 建议终端漫游。')}${draftToggle('rrm', 'RRM', '启用无线资源测量。')}${draftToggle('qbssload', 'QBSS Load', '广播 BSS 负载。')}${draftToggle('ft_over_ds', 'FT over DS', '通过分布式系统完成 Fast Transition。')}${draftToggle('ft_psk_generate_local', '本地生成 FT PSK', '由本机生成 R0/R1 密钥材料。')}</div><div class="wifi-sheet-fields">${sheetField('Mobility Domain', 'mobility_domain', draft.mobility_domain, { placeholder: '4 位十六进制' })}${sheetField('NAS ID', 'nasid', draft.nasid, { placeholder: '留空自动生成' })}${sheetField('重关联期限', 'reassociation_deadline', draft.reassociation_deadline, { type: 'number', min: 100, max: 20000 })}${sheetField('备注', 'remark', draft.remark, { wide: true })}</div></section></div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-wifi-sheet-close>取消</button><button class="policy-primary" type="button" data-wifi-draft-save ${canConfigWrite() && draft.name.trim() && draft.bands.length ? '' : 'disabled'}>保存 Wi-Fi</button></footer></aside>`;
  }

  function speedSheet() {
    const draft = state.draft || { id: `limit-${Date.now()}`, name: '', download_mbps: 0, upload_mbps: 0 };
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-wifi-sheet-close aria-label="关闭速度限制编辑"></button><aside class="dwrt-kit-sheet wifi-sheet compact policy-stable-glass is-open" aria-label="编辑速度限制"><header class="dwrt-kit-sheet-header"><div><strong>Wi-Fi 速度限制</strong><small>${escapeHtml(draft.name || '新建档案')}</small></div><button class="dwrt-kit-sheet-close wifi-icon-button" type="button" data-wifi-sheet-close aria-label="关闭">${icon('close')}</button></header><div class="dwrt-kit-sheet-body wifi-sheet-body"><section><div class="wifi-sheet-fields">${sheetField('名称', 'name', draft.name, { wide: true })}${sheetField('下载限制', 'download_mbps', draft.download_mbps, { type: 'number', min: 0, max: 100000, help: '0 表示无限制，单位 Mbps。' })}${sheetField('上传限制', 'upload_mbps', draft.upload_mbps, { type: 'number', min: 0, max: 100000, help: '0 表示无限制，单位 Mbps。' })}</div></section></div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-wifi-sheet-close>取消</button><button class="policy-primary" type="button" data-wifi-draft-save ${canConfigWrite() && draft.name.trim() ? '' : 'disabled'}>保存档案</button></footer></aside>`;
  }

  function sheetMarkup() {
    if (state.sheet === 'ssid') return ssidSheet();
    if (state.sheet === 'speed') return speedSheet();
    return '';
  }

  function statusToolbar() {
    const views = [['radios', 'radio', '射频'], ['connectivity', 'connectivity', '连接性'], ['environment', 'environment', '环境']];
    return `<header class="airview-topbar"><div class="topology-panel-tabs airview-view-tabs" role="tablist" aria-label="无线状态视图">${views.map(([value, glyph, label]) => `<button class="topology-panel-tab" type="button" data-airview-view="${value}" aria-label="${label}" aria-selected="${state.statusView === value}">${icon(glyph)}<span>${label}</span></button>`).join('')}</div></header>`;
  }

  function filterCheckbox(group, value, label, checked = false, extra = '', disabled = false) {
    const text = String(label ?? '');
    const clipped = clipLabel(text);
    const title = clipped === text ? '' : ` title="${escapeHtml(text)}"`;
    return `<label class="airview-check ${disabled ? 'is-disabled' : ''}"${title}><input type="checkbox" data-airview-filter="${escapeHtml(group)}" value="${escapeHtml(value)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}><i></i><span>${extra}<span class="airview-check-label">${escapeHtml(clipped)}</span></span></label>`;
  }

  function miniChannelPlan() {
    const stateFor = (band, channel) => {
      const radios = state.status.radios.filter((radio) => radio.band === band);
      if (radios.some((radio) => radio.channel === channel)) return 'using';
      if (radios.some((radio) => radio.excluded_channels.includes(channel))) return 'excluded';
      if (radios.some((radio) => radio.dfs_channels.includes(channel))) return 'dfs';
      if (radios.some((radio) => radio.unavailable_channels.includes(channel))) return 'unavailable';
      if (radios.some((radio) => radio.supported_channels.includes(channel))) return 'enabled';
      return 'unknown';
    };
    const definitions = [BANDS[0], BANDS[1], BANDS[2]];
    const hasPlan = state.status.radios.some((radio) => radio.supported_channels.length || radio.dfs_channels.length || radio.unavailable_channels.length || radio.excluded_channels.length);
    return `<div class="airview-mini-plan ${hasPlan ? '' : 'is-partial'}">${definitions.map((def) => {
      const band = def.band || def.id;
      return `<div><span>${escapeHtml(def.label)}</span><b>${def.channels.slice(0, band === '2g' ? 14 : 18).map((channel) => `<i class="is-${stateFor(band, channel)}" data-dwrt-tooltip="${escapeHtml(`${def.label} · 信道 ${channel} · ${stateFor(band, channel) === 'using' ? '使用中' : stateFor(band, channel) === 'enabled' ? '已启用' : stateFor(band, channel) === 'dfs' ? 'DFS' : stateFor(band, channel) === 'unavailable' ? '不可用' : stateFor(band, channel) === 'excluded' ? '已排除' : '状态未提供'}`)}"></i>`).join('')}</b></div>`;
    }).join('')}<small><i class="is-using"></i>使用中 <i class="is-enabled"></i>已启用 <i class="is-dfs"></i>DFS <i class="is-unavailable"></i>不可用 <i class="is-excluded"></i>已排除${hasPlan ? '' : ' · 其余状态未提供'}</small></div>`;
  }

  function airviewAiCells() {
    const cells = asArray(state.status.channel_ai || state.status.channel_ai_cells || state.status.runtime?.channel_ai);
    return Array.from({ length: 30 }, (_, index) => {
      const cell = cells[index];
      if (!cell) return '<i class="is-unknown"></i>';
      const status = firstText(cell.status, cell.state, 'unknown').toLowerCase();
      const className = ['active', 'recommended', 'healthy'].includes(status) ? 'is-active' : ['alert', 'avoid', 'interference'].includes(status) ? 'is-alert' : 'is-unknown';
      return `<i class="${className}" data-dwrt-tooltip="${escapeHtml(firstText(cell.label, cell.message, '信道 AI'))}"></i>`;
    }).join('');
  }

  function apInventory() {
    const inventory = new Map(state.status.managedAps.map((ap) => [ap.id, ap]));
    state.status.radios.forEach((radio) => {
      const current = inventory.get(radio.ap_id) || {};
      inventory.set(radio.ap_id, {
        ...current,
        id: radio.ap_id,
        name: firstText(current.name, radio.ap),
        model: firstText(current.model, radio.model),
        online: current.online ?? radio.online,
        image_url: firstText(current.image_url, radio.image_url),
        image_available: current.image_available ?? radio.image_available,
        image_source: firstText(current.image_source, radio.image_source),
        image_model_match: firstText(current.image_model_match, radio.image_model_match)
      });
    });
    return Array.from(inventory.values());
  }

  function apRadios(apId) {
    return state.status.radios
      .filter((radio) => radio.ap_id === apId)
      .sort((left, right) => ({ '2g': 0, '5g': 1, '6g': 2 }[left.band] ?? 9) - ({ '2g': 0, '5g': 1, '6g': 2 }[right.band] ?? 9));
  }

  function broadcastInventory() {
    const broadcasts = new Map();
    state.status.ssids.forEach((ssid) => {
      const key = ssid.name;
      if (!broadcasts.has(key)) broadcasts.set(key, { id: key, name: ssid.name, radioIds: new Set(), apIds: new Set() });
      if (ssid.radio_id) broadcasts.get(key).radioIds.add(ssid.radio_id);
      if (ssid.ap_id) broadcasts.get(key).apIds.add(ssid.ap_id);
    });
    return Array.from(broadcasts.values());
  }

  const COLUMN_DEFS = {
    connectivity: [['client', '客户端'], ['event', '事件'], ['ap', 'AP'], ['result', '结果'], ['signal', '信号'], ['band', '频段'], ['broadcast', 'WiFi 广播'], ['time', '日期/时间']],
    environment: [['ap', 'AP'], ['name', 'WiFi 名称'], ['signal', '信号'], ['channel', '信道'], ['width', '信道宽度'], ['standard', '标准'], ['mac', 'MAC 地址'], ['security', '安全'], ['vendor', '供应商'], ['nearest', '最近的 AP']]
  };

  function columnEditor(view) {
    const definitions = COLUMN_DEFS[view] || [];
    const selected = state.columns[view];
    if (state.columnEditor !== view) return `<button type="button" class="wifi-link-button" data-airview-columns="${view}">自定义列</button>`;
    return `<section class="airview-column-editor"><h2>自定义列</h2><label class="airview-check"><input type="checkbox" data-airview-column-all="${view}" ${selected.size === definitions.length ? 'checked' : ''}><i></i><span>全部</span></label>${definitions.map(([key, label]) => filterCheckbox(`columns.${view}`, key, label, selected.has(key))).join('')}<footer><button type="button" class="wifi-link-button" data-airview-columns-reset="${view}" ${selected.size === definitions.length ? 'disabled' : ''}>恢复</button><button type="button" class="policy-primary compact" data-airview-columns-done>完成</button></footer></section>`;
  }

  function radioFiltersDefault() {
    const aps = new Set(state.status.radios.map((radio) => radio.ap_id).filter(Boolean));
    const bands = new Set(state.status.radios.map((radio) => radio.band).filter(Boolean));
    return !state.filters.ai && state.filters.broadcast === 'all'
      && state.filters.aps.size === aps.size && Array.from(aps).every((value) => state.filters.aps.has(value))
      && state.filters.bands.size === bands.size && Array.from(bands).every((value) => state.filters.bands.has(value))
      && !state.filters.mimo.size && !state.filters.types.size && !state.filters.status.size;
  }

  function selectedEnvironmentAp(aps = apInventory()) {
    return aps.find((ap) => ap.id === state.filters.environmentAp) || aps[0] || null;
  }

  function environmentBands() {
    const order = { '2g': 0, '5g': 1, '6g': 2 };
    const bands = new Set();
    const ap = selectedEnvironmentAp();
    apRadios(ap ? ap.id : '').forEach((radio) => { if (radio.band) bands.add(radio.band); });
    if (!bands.size) state.status.radios.forEach((radio) => { if (radio.band) bands.add(radio.band); });
    state.status.interference.forEach((row) => { const band = normalizeBand(row.band); if (band) bands.add(band); });
    return Array.from(bands).sort((left, right) => (order[left] ?? 9) - (order[right] ?? 9));
  }

  function selectedEnvironmentBand() {
    const bands = environmentBands();
    if (!bands.length) return '5g';
    if (state.filters.environmentBand && bands.includes(state.filters.environmentBand)) return state.filters.environmentBand;
    return bands.includes('5g') ? '5g' : bands[0];
  }

  function scanStateLabel(value) {
    return ({ creating: '正在创建', queued: '排队中', leased: '等待 AP', running: '扫描中', completed: '已完成', failed: '失败', cancelled: '已取消', expired: '已超时' })[value] || firstText(value, '等待状态');
  }

  function scanJobPayload(payload = {}) {
    if (payload.item && typeof payload.item === 'object') return payload.item;
    if (payload.job && typeof payload.job === 'object') return payload.job;
    return payload;
  }

  function scanJobsPanel() {
    const jobs = Array.from(state.scanJobs.values()).sort((left, right) => ({ '2g': 0, '5g': 1, '6g': 2 }[left.band] ?? 9) - ({ '2g': 0, '5g': 1, '6g': 2 }[right.band] ?? 9));
    if (!jobs.length) return '';
    return `<section class="airview-scan-jobs" data-airview-scan-jobs aria-live="polite"><header><strong>邻居扫描</strong><span>${jobs.filter((job) => ['completed', 'failed', 'cancelled', 'expired'].includes(job.state)).length} / ${jobs.length}</span></header>${jobs.map((job) => {
      const tone = job.state === 'completed' ? 'success' : ['failed', 'expired'].includes(job.state) ? 'error' : job.state === 'cancelled' ? 'warning' : 'progress';
      const detail = job.error ? environmentReason(job.error) : job.state === 'completed' ? `${firstNumber(job.result_count)} 个广播` : scanStateLabel(job.state);
      return `<div class="is-${tone}"><i aria-hidden="true"></i><span><strong>${escapeHtml(bandLabel(job.band))}</strong><small>${escapeHtml(detail)}</small></span><b>${escapeHtml(scanStateLabel(job.state))}</b></div>`;
    }).join('')}</section>`;
  }

  function signalRangeControl() {
    const minPct = ((state.filters.signalMin + 100) / 80 * 100).toFixed(2);
    const maxPct = ((state.filters.signalMax + 100) / 80 * 100).toFixed(2);
    return `<div class="airview-signal-range" style="--signal-min:${minPct}%;--signal-max:${maxPct}%"><div><span class="airview-signal-track" aria-hidden="true"></span><input class="is-min" type="range" min="-100" max="-20" value="${state.filters.signalMin}" data-airview-signal="min" aria-label="最低信号"><input class="is-max" type="range" min="-100" max="-20" value="${state.filters.signalMax}" data-airview-signal="max" aria-label="最高信号"></div><span>${state.filters.signalMin}</span><span>${state.filters.signalMax}</span></div>`;
  }

  function environmentApPicker(aps) {
    const selected = selectedEnvironmentAp(aps);
    const selectedId = selected?.id || '';
    return `<div class="airview-ap-picker"><label class="airview-ap-select">${selected ? deviceImage(selected, 'airview-filter-device-image') : `<span class="airview-filter-device-image is-fallback">${icon('radio')}</span>`}<select data-airview-environment-ap aria-label="选择 Access Point">${aps.map((ap) => `<option value="${escapeHtml(ap.id)}" ${selectedId === ap.id ? 'selected' : ''}>${escapeHtml(ap.name)}</option>`).join('')}</select><span class="airview-ap-chevron" aria-hidden="true">${icon('chevron')}</span></label><button class="airview-ap-insights" type="button" data-airview-ap-details="${escapeHtml(selectedId)}" aria-label="打开 ${escapeHtml(selected?.name || 'AP')} 详情" ${selected ? '' : 'disabled'}>${icon('insights')}</button></div>`;
  }

  function airviewSidebar() {
    const aps = apInventory();
    const broadcasts = broadcastInventory();
    const channelAiAvailable = bool(state.status.capabilities.channel_ai || state.status.capabilities.airview_realtime, false) && asArray(state.status.channel_ai || state.status.channel_ai_cells).length > 0;
    let body = '';
    if (state.statusView === 'connectivity') {
      body = `<div class="airview-range-picker" role="group" aria-label="连接性时间范围">${[6, 12, 24, 48].map((hours) => `<button type="button" data-airview-connectivity-range="${hours}" aria-pressed="${state.filters.connectivityRange === hours}">${hours} 小时</button>`).join('')}</div><div class="airview-link-actions"><button type="button" class="wifi-link-button" data-airview-clear ${state.filters.connectivityRange === 48 ? 'disabled' : ''}>清除筛选条件</button>${columnEditor('connectivity')}</div>`;
    } else if (state.statusView === 'environment') {
      const scannerAvailable = bool(state.status.capabilities.scan_execution || state.status.capabilities.scan, false);
      const envBands = environmentBands();
      const activeEnvBand = selectedEnvironmentBand();
      const bandSegment = envBands.length ? `<div class="airview-band-segment" role="group" aria-label="频段">${envBands.map((band) => `<button type="button" data-airview-environment-band="${band}" aria-pressed="${activeEnvBand === band}">${escapeHtml(bandLabel(band))}</button>`).join('')}</div>` : '';
      body = `${environmentApPicker(aps)}${bandSegment}<button type="button" class="policy-primary compact airview-scan-button" data-airview-scan ${scannerAvailable && !state.scanning && aps.length ? '' : 'disabled'}>${icon('scan')}<span>${state.scanning ? '扫描任务执行中' : '扫描环境'}</span></button>${scanJobsPanel()}<details open><summary>时间范围</summary><div class="airview-range-picker compact">${[['30m','30 分钟'],['1h','1 小时'],['1d','1 天'],['1w','1 周'],['1m','1 月']].map(([value, label]) => `<button type="button" data-airview-environment-range="${value}" aria-pressed="${state.filters.environmentRange === value}">${label}</button>`).join('')}</div></details><details open><summary>信道宽度</summary><div class="airview-filter-list two-columns">${[20,40,80,160,240].map((width) => filterCheckbox('environmentWidths', width, String(width), state.filters.environmentWidths.has(String(width)))).join('')}</div></details><details open><summary>信号</summary>${signalRangeControl()}</details><div class="airview-link-actions">${columnEditor('environment')}<button type="button" class="wifi-link-button" data-airview-clear>清除筛选条件</button></div>`;
    } else {
      body = `<div class="airview-ai-row"><span>信道 AI 视图</span><label class="airview-switch"><input type="checkbox" data-airview-ai ${state.filters.ai ? 'checked' : ''} ${channelAiAvailable ? '' : 'disabled'} aria-label="信道 AI 视图"><i></i></label></div><div class="airview-ai-map ${channelAiAvailable ? '' : 'is-unavailable'}" aria-label="信道 AI 状态" data-dwrt-tooltip="${channelAiAvailable ? '显示信道 AI 建议' : '后端尚未提供信道 AI 建议'}">${airviewAiCells()}</div><label class="airview-broadcast-select">${icon('search')}<select data-airview-broadcast><option value="all">所有 WiFi 广播 (${broadcasts.length})</option>${broadcasts.map((broadcast) => `<option value="${escapeHtml(broadcast.id)}" ${state.filters.broadcast === broadcast.id ? 'selected' : ''}>${escapeHtml(broadcast.name)}</option>`).join('')}</select></label><details open><summary>Access Point</summary><div class="airview-filter-list">${aps.length ? aps.map((ap) => filterCheckbox('aps', ap.id, ap.name, state.filters.aps.has(ap.id), deviceImage(ap, 'airview-filter-device-image'))).join('') : '<small class="airview-filter-empty">未检测到 AP</small>'}</div></details><details open><summary>频段</summary><div class="airview-filter-list">${['2g', '5g', '6g'].map((band) => filterCheckbox('bands', band, bandLabel(band), state.filters.bands.has(band))).join('')}</div></details><details open><summary>信道计划</summary>${miniChannelPlan()}</details><details open><summary>MIMO</summary><div class="airview-filter-list">${['1x1', '2x2', '3x3', '4x4'].map((mimo) => filterCheckbox('mimo', mimo, mimo, state.filters.mimo.has(mimo))).join('')}</div></details><details open><summary>类型</summary><div class="airview-filter-list">${[['wired', '有线'], ['meshed', '已 Mesh']].map(([value, label]) => filterCheckbox('types', value, label, state.filters.types.has(value))).join('')}</div></details><details open><summary>状态</summary><div class="airview-filter-list">${[['online', '在线'], ['offline', '离线']].map(([value, label]) => filterCheckbox('status', value, label, state.filters.status.has(value))).join('')}</div></details><button type="button" class="wifi-link-button" data-airview-clear ${radioFiltersDefault() ? 'disabled' : ''}>清除筛选条件</button>`;
    }
    return `<aside class="airview-sidebar topology-control-panel policy-stable-glass">${statusToolbar()}<div class="airview-sidebar-scroll">${body}</div></aside>`;
  }

  function filteredRadios() {
    const filters = state.filters;
    const aps = apInventory();
    const bands = new Set(state.status.radios.map((radio) => radio.band).filter(Boolean));
    return state.status.radios.filter((radio) => {
      if (aps.length && !filters.aps.has(radio.ap_id)) return false;
      if (bands.size && !filters.bands.has(radio.band)) return false;
      if (filters.mimo.size && !filters.mimo.has(radio.mimo)) return false;
      if (filters.types.size && !filters.types.has(String(radio.type).toLowerCase())) return false;
      if (filters.status.size && !filters.status.has(radio.online ? 'online' : 'offline')) return false;
      if (filters.broadcast !== 'all') {
        const broadcast = broadcastInventory().find((item) => item.id === filters.broadcast);
        if (!broadcast || !broadcast.radioIds.has(radio.id)) return false;
      }
      return true;
    }).sort((left, right) => {
      const apOrder = left.ap.localeCompare(right.ap, 'zh-CN');
      if (apOrder) return apOrder;
      return ({ '2g': 0, '5g': 1, '6g': 2 }[left.band] ?? 9) - ({ '2g': 0, '5g': 1, '6g': 2 }[right.band] ?? 9);
    });
  }

  function connectivityResults() {
    const supported = bool(state.status.capabilities.connectivity_events || state.status.capabilities.roaming_history, false);
    const remote = state.connectivityEvents;
    const events = supported ? remote.items : state.status.connectivityEvents;
    if (!events.length) {
      let title = '连接性历史不可用';
      let detail = '后端尚未提供漫游、断开、重连和 AP 切换事件历史。';
      if (supported && remote.error) {
        title = '连接性历史读取失败';
        detail = remote.error;
      } else if (supported && remote.loading) {
        title = '正在读取事件';
        detail = '正在从事件存储读取所选时间范围。';
      } else if (supported) {
        title = '无事件';
        detail = '所选时间范围内没有观测到连接、断开或漫游事件。事件来自周期快照差分 (ac_snapshot_diff)。';
      }
      return `<div class="airview-connectivity-empty"><strong>${title}</strong><span>${escapeHtml(detail)}</span></div>`;
    }
    const columns = state.columns.connectivity;
    const value = (event, key) => ({
      client: escapeHtml(firstText(event.client, event.name, event.mac, '--')),
      event: escapeHtml(firstText(event.event, event.type, event.message, '--')),
      ap: escapeHtml(firstText(event.ap, event.ap_name, '--')),
      result: escapeHtml(firstText(event.result, event.outcome, event.status, '--')),
      signal: escapeHtml(firstText(event.signal, event.rssi, '--')),
      band: escapeHtml(bandLabel(normalizeBand(event.band))),
      broadcast: escapeHtml(firstText(event.wifi_broadcast, event.broadcast, event.ssid, event.wifi_name, '--')),
      time: escapeHtml(firstText(event.date_time, event.occurred_at, event.time, event.timestamp, '--'))
    })[key];
    const visible = COLUMN_DEFS.connectivity.filter(([key]) => columns.has(key));
    return `<div class="airview-radio-table policy-stable-glass"><div class="wifi-table-scroll"><table><thead><tr>${visible.map(([, label]) => `<th>${label}</th>`).join('')}</tr></thead><tbody>${events.map((event) => `<tr>${visible.map(([key]) => `<td>${value(event, key)}</td>`).join('')}</tr>`).join('')}</tbody></table></div></div>`;
  }

  function environmentRows() {
    const band = selectedEnvironmentBand();
    return state.status.interference.filter((row) => {
      if (state.filters.environmentAp !== 'all' && firstText(row.ap_id, row.nearest_ap_id) !== state.filters.environmentAp) return false;
      if (band && normalizeBand(row.band) !== band) return false;
      const width = String(firstNumber(row.width, row.channel_width));
      if (state.filters.environmentWidths.size && !state.filters.environmentWidths.has(width)) return false;
      const signal = firstNumber(row.signal, row.rssi, -100);
      return signal >= state.filters.signalMin && signal <= state.filters.signalMax;
    });
  }

  function environmentReason(reason) {
    return ({
      available: '可用', scan_not_yet_run: '尚未执行扫描', no_samples: '当前范围没有历史样本',
      iw_survey_samples_stale_or_incomplete: 'Radio 已上报，但驱动未返回完整 Survey 数值',
      iw_survey_failed_or_unsupported: '驱动不支持 Survey 或读取失败',
      iw_survey_unsupported: '驱动不支持 Survey', survey_history_source_unavailable: '历史存储当前没有样本',
      iw_neighbor_scan_failed_or_unsupported: '驱动不支持邻居扫描或扫描失败', scan_job_create_failed: '扫描任务创建失败',
      iw_neighbor_scan_not_supported: '驱动不支持邻居扫描 (EOPNOTSUPP)',
      iw_neighbor_scan_interface_busy: '接口忙,驱动拒绝离开工作信道 (EBUSY)',
      iw_neighbor_scan_interface_down: '扫描接口未启用 (ENETDOWN)',
      iw_neighbor_scan_permission_denied: '驱动拒绝扫描权限 (EPERM)',
      iw_neighbor_scan_driver_rejected: '驱动拒绝扫描参数 (EINVAL)',
      iw_neighbor_scan_interface_missing: '扫描接口不存在 (ENODEV)',
      iw_neighbor_scan_timeout: '扫描命令执行超时',
      scan_job_id_missing: '后端未返回任务 ID', scan_job_status_failed: '扫描任务状态读取失败', scan_status_timeout: '扫描任务状态等待超时',
      neighbor_bssid_scan_producer_pending: '邻居扫描执行器未开放', spectral_fft_driver_producer_pending: '驱动未提供频谱 FFT',
      wifi_connectivity_event_store_pending: '连接事件存储尚未实现', wifi_roaming_event_store_pending: '漫游历史存储尚未实现',
      request_failed: '历史接口读取失败', not_loaded: '尚未读取'
    })[reason] || (typeof reason === 'string' &&
      reason.indexOf('iw_neighbor_scan_command_failed_exit_') === 0
        ? '扫描命令失败 (exit ' +
          reason.replace('iw_neighbor_scan_command_failed_exit_', '') + ')'
        : firstText(reason, '状态未知'));
  }

  function environmentCapabilitySummary() {
    const environment = state.status.environment;
    const survey = environment.channelSurvey;
    const neighbor = environment.neighborScan;
    const spectral = environment.spectralFft;
    const history = state.environmentHistory;
    const item = (label, ready, value, reason) => `<div class="${ready ? 'is-ready' : ''}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(environmentReason(reason))}</small></div>`;
    return `<section class="airview-environment-status" aria-label="环境数据状态">${item('邻居扫描', bool(neighbor.sample_available, false), `${asArray(neighbor.samples).length} 个广播`, neighbor.reason)}${item('实时 Survey', bool(survey.supported, false), `${firstNumber(survey.fresh_sample_count)} / ${firstNumber(survey.sample_count)} 新鲜`, survey.reason)}${item('Survey 历史', history.points.length > 1, `${history.points.length} 个点`, history.error ? 'request_failed' : history.reason)}${item('频谱 FFT', bool(spectral.supported, false), `${asArray(spectral.samples).length} 个样本`, spectral.reason)}</section>`;
  }

  function surveyHistoryChart() {
    const samples = state.environmentHistory.points;
    const points = linePoints(samples, 900, 210);
    if (!points) {
      const detail = state.environmentHistory.loading ? '正在读取所选时间范围的 Survey 历史。' : state.environmentHistory.error ? state.environmentHistory.error : environmentReason(state.environmentHistory.reason);
      return `<div class="airview-environment-history-empty"><strong>暂无可绘制的信道利用率历史</strong><span>${escapeHtml(detail)}</span></div>`;
    }
    return `<svg class="airview-environment-history-line" viewBox="0 0 900 210" preserveAspectRatio="none" aria-label="信道利用率历史"><polyline points="${points}"></polyline></svg>`;
  }

  function environmentBandRange(band) {
    return ({
      '2g': { min: 2400, max: 2496, ticks: [[2412, '1'], [2437, '6'], [2462, '11'], [2484, '14']] },
      '5g': { min: 5150, max: 5895, ticks: [[5180, '36'], [5260, '52'], [5320, '64'], [5500, '100'], [5580, '116'], [5660, '132'], [5745, '149'], [5825, '165']] },
      '6g': { min: 5925, max: 7125, ticks: [[5955, '1'], [6135, '37'], [6335, '77'], [6535, '117'], [6735, '157'], [6935, '197'], [7115, '233']] }
    })[band] || { min: 2400, max: 2496, ticks: [] };
  }

  function channelToFrequency(band, channel) {
    const ch = Number(channel);
    if (!ch) return 0;
    if (band === '2g') return ch === 14 ? 2484 : 2407 + ch * 5;
    if (band === '5g') return 5000 + ch * 5;
    if (band === '6g') return 5950 + ch * 5;
    return 0;
  }

  // Neighbor spectrum: each AP is a bell centred on its channel, width by its
  // bandwidth, peak at its RSSI. Mirrors UniFi's WiFi scanner spectrum chart.
  function environmentSpectrumChart(rows, band) {
    const W = 900, H = 232, padL = 4, padR = 4, padT = 6, padB = 4;
    const plotW = W - padL - padR;
    const plotH = H - padT - padB;
    const range = environmentBandRange(band);
    const span = Math.max(1, range.max - range.min);
    const fx = (freq) => padL + Math.min(1, Math.max(0, (freq - range.min) / span)) * plotW;
    const fy = (dbm) => padT + Math.min(1, Math.max(0, Math.abs(dbm) / 100)) * plotH;
    const baseY = padT + plotH;
    const bells = rows.map((row, index) => {
      const freq = firstNumber(row.frequency_mhz) || channelToFrequency(band, firstNumber(row.channel));
      if (!freq) return '';
      const width = firstNumber(row.width_mhz, row.width, row.channel_width) || 20;
      const signal = firstNumber(row.signal, row.rssi_dbm, row.rssi, -95);
      const cx = fx(freq);
      const half = Math.max(9, (width / span * plotW) / 2);
      const peakY = fy(signal);
      const left = cx - half;
      const right = cx + half;
      const path = `M ${left.toFixed(1)} ${baseY.toFixed(1)} C ${(left + half * 0.6).toFixed(1)} ${baseY.toFixed(1)} ${(cx - half * 0.4).toFixed(1)} ${peakY.toFixed(1)} ${cx.toFixed(1)} ${peakY.toFixed(1)} C ${(cx + half * 0.4).toFixed(1)} ${peakY.toFixed(1)} ${(right - half * 0.6).toFixed(1)} ${baseY.toFixed(1)} ${right.toFixed(1)} ${baseY.toFixed(1)} Z`;
      const tone = index % 6;
      const tip = `${firstText(row.ssid, row.name, '隐藏网络')} · 信道 ${firstText(row.channel, '--')} · ${width} MHz · ${signal} dBm`;
      return `<path class="airview-bell tone-${tone}" d="${path}" data-dwrt-tooltip="${escapeHtml(tip)}"></path>`;
    }).join('');
    return `<svg class="airview-environment-spectrum" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-label="邻居广播频谱">${bells}</svg>`;
  }

  function environmentResults() {
    const band = selectedEnvironmentBand();
    const range = environmentBandRange(band);
    const rows = environmentRows();
    const titleBand = bandLabel(band);
    const neighbor = state.status.environment.neighborScan;
    const columns = state.columns.environment;
    const cell = (row, key) => ({
      ap: escapeHtml(firstText(row.ap, row.ap_name, '--')),
      name: escapeHtml(firstText(row.ssid, row.name, '--')),
      signal: escapeHtml(firstText(row.signal, row.rssi, '--')),
      channel: escapeHtml(firstText(row.channel, '--')),
      width: escapeHtml(firstText(row.width, row.channel_width, '--')),
      standard: escapeHtml(firstText(row.standard, row.protocol, '--')),
      mac: escapeHtml(firstText(row.mac, row.bssid, '--')),
      security: escapeHtml(firstText(row.security, '--')),
      vendor: escapeHtml(firstText(row.vendor, '--')),
      nearest: escapeHtml(firstText(row.nearest_ap, row.ap, '--'))
    })[key];
    const visible = COLUMN_DEFS.environment.filter(([key]) => columns.has(key));
    const emptyText = bool(neighbor.execution_available, false) && neighbor.reason === 'scan_not_yet_run' ? '尚未执行邻居扫描，点击左侧“扫描环境”获取附近广播。' : environmentReason(neighbor.reason);
    const chartBody = rows.length
      ? environmentSpectrumChart(rows, band)
      : `<div class="airview-environment-history-empty"><strong>暂无可绘制的邻居广播</strong><span>${escapeHtml(emptyText)}</span></div>`;
    return `<section class="airview-spectrum-view"><header>环境 · ${escapeHtml(titleBand)}<small>${rows.length} 个邻居广播</small></header>${environmentCapabilitySummary()}<div class="airview-spectrum-chart" role="img" aria-label="${escapeHtml(`${titleBand} 邻居广播频谱`)}"><div class="airview-spectrum-y">${[-30,-45,-60,-75,-90].map((value) => `<span>${value}</span>`).join('')}</div><div class="airview-spectrum-grid"><i></i><i></i><i></i><i></i></div><span class="airview-spectrum-db">dBm</span>${chartBody}<div class="airview-spectrum-x">${range.ticks.map(([, label]) => `<span>${label}</span>`).join('')}</div><span class="airview-spectrum-channel">信道</span></div><div class="airview-spectrum-table wifi-table-scroll"><table><thead><tr>${visible.map(([, label]) => `<th>${label}</th>`).join('')}</tr></thead><tbody>${rows.map((row) => `<tr>${visible.map(([key]) => `<td>${cell(row, key)}</td>`).join('')}</tr>`).join('')}</tbody></table>${rows.length ? '' : `<div class="airview-spectrum-empty">${icon('info')}<span>${escapeHtml(emptyText)}</span></div>`}</div></section>`;
  }

  function selectedRadioEntries() {
    return state.status.radios.filter((radio) => state.selectedRadios.has(radio.id));
  }

  function radioWidths(radio) {
    const definition = BANDS.find((item) => (item.band || item.id) === radio.band);
    const values = radio.supported_widths.length ? radio.supported_widths : (definition?.widths || []);
    return Array.from(new Set([...values, radio.width].map(Number).filter(Boolean))).sort((left, right) => left - right);
  }

  function radioChannels(radio) {
    const definition = BANDS.find((item) => (item.band || item.id) === radio.band);
    const values = radio.supported_channels.length ? radio.supported_channels : (definition?.channels || []);
    return Array.from(new Set([...values, radio.channel].map(Number).filter(Boolean))).sort((left, right) => left - right);
  }

  function radioDraft(radio) {
    if (!state.radioDrafts.has(radio.id)) state.radioDrafts.set(radio.id, clone(radio));
    return state.radioDrafts.get(radio.id);
  }

  function canRadioWrite() {
    const caps = state.status.capabilities;
    return bool(caps.radio_update, false) && Boolean(radioUpdateEndpoint());
  }

  function radioUpdateEndpoint() {
    return firstText(
      state.status.capabilities.radio_update_endpoint,
      state.status.links?.radio_update,
      state.status.endpoints?.radio_update
    );
  }

  function updateRadioDrafts(band, path, value) {
    selectedRadioEntries().filter((radio) => radio.band === band).forEach((radio) => setPath(radioDraft(radio), path, value));
    state.radioDirty = true;
  }

  function setRadioSelection(id, selected) {
    const radio = state.status.radios.find((entry) => entry.id === id);
    if (!radio) return;
    if (selected) {
      state.selectedRadios.add(id);
      radioDraft(radio);
    } else {
      state.selectedRadios.delete(id);
      state.radioDrafts.delete(id);
    }
    state.selectedRadio = state.selectedRadios.values().next().value || '';
    if (!state.selectedRadios.size) state.radioDirty = false;
    render();
  }

  function closeRadioSheet() {
    state.selectedRadios.clear();
    state.radioDrafts.clear();
    state.selectedRadio = '';
    state.radioDirty = false;
    render();
  }

  async function saveRadioDrafts() {
    const endpoint = radioUpdateEndpoint();
    if (!canRadioWrite() || !state.radioDirty || !endpoint || state.saving) return;
    state.saving = true;
    render();
    try {
      await requestJson(endpoint, {
        method: 'PATCH',
        body: JSON.stringify({
          revision: state.status.revision,
          radios: selectedRadioEntries().map((radio) => ({
            id: radio.id,
            channel: radioDraft(radio).channel,
            width: radioDraft(radio).width,
            tx_power_mode: radioDraft(radio).tx_power_mode,
            tx_power_dbm: radioDraft(radio).tx_power_custom,
            min_rssi_enabled: radioDraft(radio).min_rssi_enabled,
            min_rssi_dbm: radioDraft(radio).min_rssi
          }))
        })
      });
      closeRadioSheet();
      state.notice = '无线电设置已提交，正在等待运行态 readback。';
      state.noticeTone = 'ok';
      await load(true);
    } catch (error) {
      state.error = `应用无线电设置失败：${firstText(error.message, '未知错误')}`;
      render();
    } finally {
      state.saving = false;
    }
  }

  function commonRadioValue(radios, key, fallback = '') {
    const values = radios.map((radio) => getPath(radioDraft(radio), key, fallback));
    return values.every((value) => String(value) === String(values[0])) ? values[0] : '';
  }

  function linePoints(samples, width = 560, height = 118) {
    const values = samples.map((sample) => optionalNumber(sample.value, sample.channel, sample.utilization, sample.count, sample.y)).filter((value) => value !== null);
    if (values.length < 2) return '';
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = Math.max(1, max - min);
    return values.map((value, index) => `${(index / (values.length - 1) * width).toFixed(1)},${(height - ((value - min) / span * (height - 12)) - 6).toFixed(1)}`).join(' ');
  }

  function radioHistory(radio) {
    const points = linePoints(radio.channel_history);
    const historyAvailable = bool(state.status.capabilities.airview_history, false) && points;
    return `<div class="airview-radio-history" role="img" aria-label="${escapeHtml(`${radio.ap} ${bandLabel(radio.band)} 信道历史`)}"><div class="airview-radio-chart-grid" aria-hidden="true"></div>${historyAvailable ? `<svg viewBox="0 0 560 118" preserveAspectRatio="none" aria-hidden="true"><polyline points="${points}"></polyline></svg>` : `<div class="airview-radio-chart-empty"><strong>暂无信道历史</strong><span>${escapeHtml(firstText(state.status.capabilities.reasons?.airview_history, '后端尚未提供按 Radio 的历史样本'))}</span></div>`}<div class="airview-radio-chart-axis"><span>12 小时前</span><span>8 小时前</span><span>4 小时前</span><span>现在</span></div></div>`;
  }

  function signalDistribution(radio) {
    const buckets = [-90, -75, -60, -45, -30];
    const samples = radio.signal_distribution;
    const counts = buckets.map((threshold, index) => {
      const sample = samples[index] || samples.find((item) => Number(item.threshold ?? item.rssi ?? item.min) === threshold);
      return firstNumber(sample?.count, sample?.clients, sample?.value);
    });
    const max = Math.max(1, ...counts);
    const available = bool(state.status.capabilities.station_metrics, false) && samples.length > 0;
    return `<div class="airview-signal-distribution"><div class="airview-signal-scale" aria-hidden="true">${buckets.map((value, index) => `<span style="--signal-tone:${index}"></span>`).join('')}</div><div class="airview-signal-labels">${buckets.map((value) => `<span>${value}</span>`).join('')}</div><div class="airview-signal-bars" aria-label="${escapeHtml(`${radio.ap} 活动客户端信号分布`)}">${available ? counts.map((count, index) => `<i style="--bar:${Math.max(3, count / max * 100).toFixed(1)}%;--signal-tone:${index}" data-dwrt-tooltip="${escapeHtml(`${buckets[index]} dBm：${count} 个客户端`)}"></i>`).join('') : `<div class="airview-radio-chart-empty compact"><strong>暂无客户端信号样本</strong><span>${escapeHtml(firstText(state.status.capabilities.reasons?.station_metrics, '后端尚未提供 Station RSSI 分布'))}</span></div>`}</div></div>`;
  }

  function radioBandSheet(band, radios) {
    const writable = canRadioWrite();
    const width = commonRadioValue(radios, 'width');
    const channel = commonRadioValue(radios, 'channel');
    const powerMode = commonRadioValue(radios, 'tx_power_mode');
    const minRssiEnabled = commonRadioValue(radios, 'min_rssi_enabled', false) === true;
    const minRssi = commonRadioValue(radios, 'min_rssi');
    const widths = Array.from(new Set(radios.flatMap(radioWidths))).sort((left, right) => left - right);
    const channels = Array.from(new Set(radios.flatMap(radioChannels))).sort((left, right) => left - right);
    const metricRadio = radios[0];
    return `<section class="airview-radio-sheet-band"><header><strong>${escapeHtml(bandLabel(band))}</strong></header><div class="airview-selected-aps">${radios.map((radio) => `<button type="button" data-airview-radio-remove="${escapeHtml(radio.id)}" aria-label="移除 ${escapeHtml(radio.ap)} ${escapeHtml(bandLabel(radio.band))}">${deviceImage(radio, 'airview-chip-device-image')}<span>${escapeHtml(radio.ap)}</span>${icon('close')}</button>`).join('')}</div><div class="airview-radio-controls"><fieldset><legend>信道宽度</legend><div class="airview-segmented">${widths.map((value) => `<button type="button" data-airview-radio-width="${escapeHtml(band)}:${value}" aria-pressed="${Number(width) === value}" ${writable ? '' : 'disabled'}>${value}</button>`).join('')}</div></fieldset><label><span>信道</span><select data-airview-radio-channel="${escapeHtml(band)}" ${writable ? '' : 'disabled'}>${channels.map((value) => `<option value="${value}" ${Number(channel) === value ? 'selected' : ''}>${value}</option>`).join('')}</select></label></div><fieldset class="airview-radio-power"><legend>发射功率 ${icon('info')}</legend><div class="airview-segmented wrap">${[['auto','自动'],['high','高'],['medium','中'],['low','低'],['custom','自定义'],['disabled','已禁用']].map(([value, label]) => `<button type="button" data-airview-radio-power="${escapeHtml(band)}:${value}" aria-pressed="${powerMode === value}" ${writable ? '' : 'disabled'}>${label}</button>`).join('')}</div>${powerMode ? '' : '<small>当前 AP 未上报发射功率模式。</small>'}${powerMode === 'custom' ? `<label class="airview-custom-power"><span>自定义功率</span><input type="number" min="1" max="40" value="${escapeHtml(commonRadioValue(radios, 'tx_power_custom'))}" data-airview-radio-custom-power="${escapeHtml(band)}" ${writable ? '' : 'disabled'}><b>dBm</b></label>` : ''}</fieldset><label class="airview-min-rssi"><input type="checkbox" data-airview-radio-min-rssi="${escapeHtml(band)}" ${minRssiEnabled ? 'checked' : ''} ${writable ? '' : 'disabled'}><i></i><span>最小 RSSI ${icon('info')}</span>${minRssiEnabled ? `<input type="number" min="-95" max="-45" value="${escapeHtml(minRssi ?? '')}" data-airview-radio-min-rssi-value="${escapeHtml(band)}" ${writable ? '' : 'disabled'}><b>dBm</b>` : ''}</label><details class="airview-radio-metrics" open><summary>关键指标</summary><div class="airview-radio-metric-device"><span>${deviceImage(metricRadio, 'airview-metric-device-image')}<strong>${escapeHtml(metricRadio.ap)}</strong></span><button type="button" data-airview-copy="${escapeHtml(metricRadio.ap)}" aria-label="复制 AP 名称">${icon('copy')}</button></div><p>信道: ${metricRadio.channel || '--'} (${metricRadio.width ? `${metricRadio.width} MHz` : '--'})</p>${radioHistory(metricRadio)}<h4>活动客户端分布</h4>${signalDistribution(metricRadio)}</details></section>`;
  }

  function radioSheet() {
    const radios = selectedRadioEntries();
    if (!radios.length || state.statusView !== 'radios') return '';
    const groups = new Map();
    radios.forEach((radio) => {
      if (!groups.has(radio.band)) groups.set(radio.band, []);
      groups.get(radio.band).push(radio);
    });
    const reason = firstText(state.status.capabilities.reasons?.radio_update, '无线电写入事务与 readback 尚未开放');
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-airview-radio-sheet-close aria-label="关闭无线电设置"></button><aside class="dwrt-kit-sheet airview-radio-sheet policy-stable-glass is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" data-dwrt-sheet-motion="settled" aria-label="无线电设置"><header class="dwrt-kit-sheet-header"><div><strong>无线电设置</strong><span>${radios.length} 个 Radio</span></div><button class="dwrt-kit-sheet-close wifi-icon-button" type="button" data-airview-radio-sheet-close aria-label="关闭">${icon('close')}</button></header><div class="dwrt-kit-sheet-body airview-radio-sheet-body">${canRadioWrite() ? '' : `<div class="wifi-inline-warning">${icon('info')}<span>${escapeHtml(reason)}。当前展示真实运行值，修改与保存保持禁用。</span></div>`}${Array.from(groups.entries()).sort((left, right) => ({'2g':0,'5g':1,'6g':2}[left[0]] ?? 9) - ({'2g':0,'5g':1,'6g':2}[right[0]] ?? 9)).map(([band, entries]) => radioBandSheet(band, entries)).join('')}</div><footer class="dwrt-kit-sheet-footer"><button class="policy-secondary" type="button" data-airview-radio-sheet-close>取消</button><button class="policy-primary" type="button" data-airview-radio-save ${canRadioWrite() && state.radioDirty ? '' : 'disabled'}>应用更改</button></footer></aside>`;
  }

  function apSheetMetric(label, value, note = '') {
    return `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(firstText(value, '--'))}</strong>${note ? `<small class="airview-kpi-note">${escapeHtml(note)}</small>` : ''}</div>`;
  }

  /* 驱动没暴露某项时后端会原样透出自己的 reason。这些是正常状态，不是错误，
     所以只在数值缺失时以浅色附注呈现，不走警示样式。 */
  const RADIO_METRIC_REASONS = {
    iw_survey_unsupported: '驱动不支持信道调查',
    iw_survey_failed_or_unsupported: '驱动未响应信道调查',
    iw_survey_current_frequency_unavailable: '驱动未上报当前频点',
    iw_survey_unavailable: '本次未取得信道调查',
    channel_survey_not_reported: 'AP 未上报信道调查',
    channel_utilization_not_sampled: '未采样信道利用率',
    noise_floor_not_reported_by_driver: '驱动未上报噪声底',
    tx_power_mode_not_exposed_by_driver_or_uci: '驱动与配置均未提供功率模式',
    // The backend deliberately returns null plus a reason instead of 0 so the UI
    // can tell "no data yet" apart from "genuinely zero clients". These two codes
    // arrive on summary.station_count / summary.clients when the managed AP has
    // not reported recently, which read as an unexplained blank before.
    telemetry_stale: '数据已过期，等待 AP 上报',
    managed_aps_offline_stale_or_without_snapshot: '受管 AP 离线，指标待其上线后恢复',
    no_phy_detected: '本机无无线网卡，仅作为控制器'
  };

  function radioMetricNote(reason) {
    const key = String(reason || '').trim();
    if (!key) return '';
    return RADIO_METRIC_REASONS[key] || key;
  }

  function apRadioStandard(radio) {
    const standard = firstText(radio.standard).toLowerCase().replace(/^802\.11/, '').replace(/^11/, '');
    if (!standard) return '--';
    if (standard.includes('be')) return 'WiFi 7';
    if (standard.includes('ax')) return 'WiFi 6';
    if (standard.includes('ac')) return 'WiFi 5';
    if (standard === 'n' || standard.includes('ng')) return 'WiFi 4';
    return firstText(radio.standard);
  }

  function apOverview(ap, radios) {
    const has6g = radios.some((radio) => radio.band === '6g');
    const broadcasts6g = state.status.ssids.filter((ssid) => ssid.ap_id === ap.id && ssid.enabled && ssid.bands.includes('6g'));
    const retryPoints = radios.flatMap((radio) => radio.tx_retry_history);
    return `<div class="airview-ap-sheet-stack"><section class="airview-ap-summary-card">${deviceImage(ap, 'airview-ap-sheet-image')}<div class="airview-ap-summary-copy"><strong>${escapeHtml(firstText(ap.model, ap.name))}</strong><span>${ap.connection ? `已连接到 ${escapeHtml(ap.connection)}` : '连接对象 --'}</span></div><div class="airview-ap-radio-list">${radios.map((radio) => `<div><strong>信道 ${radio.channel || '--'} <span>(${escapeHtml(bandLabel(radio.band))}, ${radio.width ? `${radio.width} MHz` : '--'})</span></strong><span>${radio.interference ? `${radio.interference}%` : '--'}</span><span>${escapeHtml(apRadioStandard(radio))}</span><span class="airview-ap-clients">${icon('connectivity')}${radio.clients === null ? '--' : radio.clients}</span></div>`).join('')}</div>${has6g && !broadcasts6g.length ? `<div class="airview-ap-warning">${icon('info')}<span>当前没有 Wi-Fi 广播使用 6 GHz Radio。</span></div>` : ''}<footer><button type="button" class="policy-secondary" disabled>端口管理器</button><button type="button" class="policy-secondary" disabled>AirView</button></footer></section><section class="airview-ap-chart-card"><header><strong>TX 重试</strong><span>${retryPoints.length ? `${retryPoints.length} 个样本` : '--'}</span></header>${retryPoints.length > 1 ? radioHistory({ ...radios[0], channel_history: retryPoints, ap: ap.name }) : `<div class="airview-ap-empty-chart"><span>后端尚未提供 TX 重试时间序列</span></div>`}</section><section class="airview-ap-facts">${apSheetMetric('型号', ap.model)}${apSheetMetric('IP 地址', ap.ip)}${apSheetMetric('MAC 地址', ap.mac)}${apSheetMetric('设备版本', ap.version)}${apSheetMetric('运行时间', ap.uptime)}</section><section class="airview-ap-table-card"><header><strong>空中统计</strong><span>按 Radio</span></header><div class="wifi-table-scroll"><table class="dwrt-kit-table"><thead><tr><th>频段</th><th>Tx 包</th><th>Tx 字节</th><th>Rx 包</th><th>Rx 字节</th><th>重试</th><th>丢弃</th></tr></thead><tbody>${radios.map((radio) => `<tr><td>${escapeHtml(bandLabel(radio.band))}</td><td>${escapeHtml(firstText(radio.air_stats.tx_packets, '--'))}</td><td>${escapeHtml(firstText(radio.air_stats.tx_bytes, '--'))}</td><td>${escapeHtml(firstText(radio.air_stats.rx_packets, '--'))}</td><td>${escapeHtml(firstText(radio.air_stats.rx_bytes, '--'))}</td><td>${escapeHtml(firstText(radio.air_stats.retries, '--'))}</td><td>${escapeHtml(firstText(radio.air_stats.dropped, '--'))}</td></tr>`).join('')}</tbody></table></div></section><section class="airview-ap-facts">${apSheetMetric('Mesh 父级', ap.mesh_parent)}${apSheetMetric('AP 组', ap.ap_group)}</section></div>`;
  }

  function apInsights(ap, radios) {
    return `<div class="airview-ap-sheet-stack">${radios.map((radio) => `<section class="airview-ap-insight-card"><header><div>${deviceImage(ap, 'airview-metric-device-image')}<span><strong>${escapeHtml(bandLabel(radio.band))}</strong><small>信道 ${radio.channel || '--'} · ${radio.width ? `${radio.width} MHz` : '--'}</small></span></div><b>${radio.clients === null ? '--' : radio.clients} 客户端</b></header><h4>关键指标</h4><div class="airview-ap-kpis">${apSheetMetric('发射功率', radio.tx_power ? `${radio.tx_power} dBm` : '--')}${apSheetMetric('平均信号', radio.avg_signal)}${apSheetMetric('利用率', radio.utilization === null ? '--' : `${radio.utilization}%`, radio.utilization === null ? radioMetricNote(radio.utilization_reason) : '')}${apSheetMetric('重试率', radio.retry_rate ? `${radio.retry_rate}%` : '--')}</div><h4>历史</h4>${radioHistory(radio)}<h4>活动客户端 RSSI 分布</h4>${signalDistribution(radio)}<h4>统计</h4><div class="airview-ap-kpis">${apSheetMetric('噪声', radio.noise === null ? '--' : `${radio.noise} dBm`, radio.noise === null ? radioMetricNote(radio.noise_reason) : '')}${apSheetMetric('平均干扰', radio.avg_interference === null ? '--' : `${radio.avg_interference}%`)}${apSheetMetric('Wi-Fi 标准', apRadioStandard(radio))}${apSheetMetric('MIMO', radio.mimo)}</div></section>`).join('')}</div>`;
  }

  function apSettings(ap, radios) {
    const gate = firstText(state.status.capabilities.reasons?.radio_update, 'AP 与 Radio 写事务尚未开放');
    return `<div class="airview-ap-sheet-stack"><div class="wifi-inline-warning">${icon('info')}<span>${escapeHtml(gate)}。当前设置仅用于核对字段与依赖关系。</span></div><section class="airview-ap-settings-card"><h3>设备</h3><div class="wifi-sheet-fields"><label class="wifi-field is-wide"><span>名称</span><input value="${escapeHtml(ap.name)}" disabled></label><label class="wifi-field is-wide"><span>设备标签</span><input value="${escapeHtml(ap.tags.join(', '))}" placeholder="未配置" disabled></label></div></section>${radios.map((radio) => `<section class="airview-ap-settings-card"><header><strong>${escapeHtml(bandLabel(radio.band))}</strong><small>Radio</small></header><div class="wifi-sheet-fields"><label class="wifi-field"><span>信道宽度</span><select disabled><option>${radio.width ? `${radio.width} MHz` : '--'}</option></select></label><label class="wifi-field"><span>信道</span><select disabled><option>${radio.channel || '--'}</option></select></label><label class="wifi-field"><span>发射功率</span><select disabled><option>${escapeHtml(firstText(radio.tx_power_mode, radio.tx_power ? `${radio.tx_power} dBm` : '--'))}</option></select></label><label class="wifi-field"><span>最小 RSSI</span><input value="${radio.min_rssi_enabled ? firstText(radio.min_rssi, '--') : '关闭'}" disabled></label></div></section>`).join('')}<section class="airview-ap-settings-card"><h3>Mesh</h3><div class="wifi-settings-list"><label class="wifi-setting-row"><span><strong>Mesh Connect</strong><small>允许无线 Mesh 上行。</small></span><input type="checkbox" role="switch" disabled></label></div><div class="wifi-sheet-fields"><label class="wifi-field"><span>Mesh 父级</span><select disabled><option>${escapeHtml(firstText(ap.mesh_parent, '--'))}</option></select></label><label class="wifi-field"><span>上行链路优先级</span><select disabled><option>--</option></select></label></div></section><section class="airview-ap-settings-card"><h3>网络</h3><div class="wifi-sheet-fields"><label class="wifi-field"><span>IP 配置</span><select disabled><option>${escapeHtml(firstText(ap.ip_mode, '--'))}</option></select></label><label class="wifi-field"><span>IP 地址</span><input value="${escapeHtml(firstText(ap.ip, '--'))}" disabled></label></div></section><section class="airview-ap-settings-card"><h3>设备操作</h3><div class="wifi-settings-list"><label class="wifi-setting-row"><span><strong>LED</strong><small>控制设备状态灯。</small></span><input type="checkbox" role="switch" ${ap.led_enabled === true ? 'checked' : ''} disabled></label></div><div class="airview-ap-actions">${['替换设备', '加载配置', '更新固件', '定位', '重启', '禁用', '移除'].map((label) => `<button type="button" class="policy-secondary" disabled>${label}</button>`).join('')}</div></section><footer class="airview-ap-settings-footer"><button class="policy-primary" type="button" disabled>应用更改</button></footer></div>`;
  }

  function apDetailsSheet() {
    if (!state.apSheetAp || state.statusView !== 'environment') return '';
    const ap = apInventory().find((entry) => entry.id === state.apSheetAp);
    if (!ap) return '';
    const radios = apRadios(ap.id);
    const tabs = [['overview', '概览', 'overview'], ['insights', '洞察', 'insights'], ['settings', '设置', 'settings']];
    const body = state.apSheetTab === 'settings' ? apSettings(ap, radios) : state.apSheetTab === 'insights' ? apInsights(ap, radios) : apOverview(ap, radios);
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-airview-ap-sheet-close aria-label="关闭 AP 详情"></button><aside class="dwrt-kit-sheet airview-ap-sheet policy-stable-glass is-open" data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot" data-dwrt-sheet-motion="settled" aria-label="${escapeHtml(ap.name)}"><header class="dwrt-kit-sheet-header"><div><strong>${escapeHtml(ap.name)}</strong></div><button class="dwrt-kit-sheet-close wifi-icon-button" type="button" data-airview-ap-sheet-close aria-label="关闭">${icon('close')}</button></header><nav class="airview-ap-sheet-tabs" role="tablist" aria-label="AP 详情视图">${tabs.map(([id, label, iconName]) => `<button type="button" role="tab" data-airview-ap-tab="${id}" aria-selected="${state.apSheetTab === id}" aria-label="${label}">${icon(iconName)}<span>${label}</span></button>`).join('')}</nav><div class="dwrt-kit-sheet-body airview-ap-sheet-body">${body}</div></aside>`;
  }

  function radioResults() {
    const radios = filteredRadios();
    if (state.statusView === 'connectivity') return connectivityResults();
    if (state.statusView === 'environment') return environmentResults();
    if (!radios.length) {
      const noHardware = !state.status.radios.length;
      const reason = firstText(state.status.runtime.reason, state.status.capabilities.runtime_reason, noHardware ? 'no_phy_detected' : 'filters_no_match');
      return `<div class="airview-empty"><span>${icon('radio')}</span><strong>${noHardware ? '未检测到无线 Radio' : '未找到匹配项'}</strong><small>${noHardware ? `后端运行态：${reason}。页面不会生成模拟 AP、客户端或频谱数据。` : '调整左侧显示选项，或清除筛选条件查看全部 AP。'}</small>${noHardware ? '' : '<button type="button" class="wifi-link-button" data-airview-clear>重置筛选</button>'}</div>`;
    }
    const selectedVisible = radios.filter((radio) => state.selectedRadios.has(radio.id));
    return `<div class="airview-radio-table policy-stable-glass" data-dwrt-component="data-table"><div class="wifi-table-scroll"><table><thead><tr><th class="airview-select-column"><input type="checkbox" data-airview-radio-select-all ${selectedVisible.length === radios.length ? 'checked' : ''} aria-label="选择全部射频"></th><th>名称</th><th>频段</th><th>信道</th><th>信道宽度</th><th>Tx 功率</th><th>客户端</th><th>平均信号</th><th>过去 24 小时</th><th>平均干扰</th></tr></thead><tbody>${radios.map((radio) => `<tr data-airview-radio-row="${escapeHtml(radio.id)}" class="${state.selectedRadios.has(radio.id) ? 'is-selected' : ''}" tabindex="0"><td class="airview-select-column"><input type="checkbox" data-airview-radio-select="${escapeHtml(radio.id)}" ${state.selectedRadios.has(radio.id) ? 'checked' : ''} aria-label="选择 ${escapeHtml(radio.ap)} ${escapeHtml(bandLabel(radio.band))}"></td><td><span class="airview-ap-cell">${deviceImage(radio)}<span><strong${radio.ap !== clipLabel(radio.ap) ? ` title="${escapeHtml(radio.ap)}"` : ''}>${escapeHtml(clipLabel(radio.ap))}</strong>${radio.model && radio.model !== radio.ap ? `<small${radio.model !== clipLabel(radio.model) ? ` title="${escapeHtml(radio.model)}"` : ''}>${escapeHtml(clipLabel(radio.model))}</small>` : ''}</span></span></td><td>${escapeHtml(bandLabel(radio.band))}</td><td>${radio.channel || '--'}</td><td>${radio.width || '--'}</td><td>${radio.tx_power_mode ? escapeHtml(radio.tx_power_mode) : radio.tx_power ? `${radio.tx_power} dBm` : '--'}</td><td>${radio.clients === null ? '--' : radio.clients}</td><td>${radio.avg_signal || '--'}</td><td>${radio.past_24h || '--'}</td><td>${radio.avg_interference === null ? '--' : `${radio.avg_interference}%`}</td></tr>`).join('')}</tbody></table></div></div>`;
  }

  /* Client, signal and 24h columns come back blank whenever the managed AP has
     not reported, which looked like the backend was missing the feature. The
     payload already says why, so the cause is stated once at the top instead of
     leaving the user to guess from a table full of dashes. Ordered most specific
     first: no local radio at all, then AP offline, then merely stale telemetry. */
  function telemetryNotice() {
    const summary = state.status.summary || {};
    const runtime = state.status.runtime || {};
    const managed = state.status.managedAps || [];
    const onlineCount = managed.filter((ap) => ap && ap.online).length;
    const noLocalPhy = Number(summary.phy_count) === 0 && !state.status.radios.length;
    const apOffline = managed.length > 0 && onlineCount === 0;
    const stale = summary.station_count === null || summary.clients === null;
    let text = '';
    if (noLocalPhy && !managed.length) text = radioMetricNote('no_phy_detected');
    else if (apOffline) text = radioMetricNote('managed_aps_offline_stale_or_without_snapshot');
    else if (stale) text = radioMetricNote(firstText(summary.station_count_reason, summary.clients_reason, 'telemetry_stale'));
    else if (runtime.available === false && runtime.reason) text = radioMetricNote(runtime.reason);
    if (!text) return '';
    return `<div class="wifi-notice is-warn" data-wifi-telemetry-notice>${icon('info')}<span>${escapeHtml(text)}</span></div>`;
  }

  function statusPage() {
    return `<div class="wifi-management-shell airview-shell">${state.error ? `<div class="wifi-notice is-error">${icon('info')}<span>${escapeHtml(state.error)}</span></div>` : ''}${state.notice ? `<div class="wifi-notice ${state.noticeTone ? `is-${state.noticeTone}` : ''}">${icon('info')}<span>${escapeHtml(state.notice)}</span></div>` : ''}${telemetryNotice()}<div class="airview-layout">${airviewSidebar()}<main class="airview-results" data-airview-results>${radioResults()}</main></div>${radioSheet()}${apDetailsSheet()}</div>`;
  }

  function render() {
    if (!root || !state.mounted) return;
    root.className = `route-preview route-workspace policy-table-route-host wifi-management-route-host ${isStatus ? 'wireless-status-route-host' : 'wifi-config-route-host'}`;
    root.innerHTML = isStatus ? statusPage() : configPage();
    if (typeof ui.mountAll === 'function') ui.mountAll(root);
    else window.DWRT_UI_KIT?.mountAll?.(root);
  }

  // Scroll containers are keyed by their DOM path inside the results region so
  // the offsets survive an innerHTML swap that replaces every node identity.
  function scrollAnchorKey(node, boundary) {
    if (!node || node === boundary || !boundary.contains(node)) return '';
    const parts = [];
    let current = node;
    while (current && current !== boundary) {
      const parent = current.parentElement;
      if (!parent) return '';
      parts.push(String(Array.prototype.indexOf.call(parent.children, current)));
      current = parent;
    }
    return parts.reverse().join('.');
  }

  function nodeFromAnchorKey(key, boundary) {
    if (!key) return null;
    let current = boundary;
    for (const part of key.split('.')) {
      const index = Number(part);
      if (!current || !Number.isFinite(index)) return null;
      current = current.children[index];
    }
    return current || null;
  }

  function captureScrollOffsets(boundary) {
    const offsets = [];
    boundary.querySelectorAll('.wifi-table-scroll, [data-airview-scroll]').forEach((node) => {
      if (!node.scrollLeft && !node.scrollTop) return;
      const key = scrollAnchorKey(node, boundary);
      if (key) offsets.push({ key, left: node.scrollLeft, top: node.scrollTop });
    });
    if (boundary.scrollLeft || boundary.scrollTop) offsets.push({ key: '', left: boundary.scrollLeft, top: boundary.scrollTop });
    return offsets;
  }

  function restoreScrollOffsets(boundary, offsets) {
    offsets.forEach(({ key, left, top }) => {
      const node = key ? nodeFromAnchorKey(key, boundary) : boundary;
      if (!node) return;
      if (left) node.scrollLeft = left;
      if (top) node.scrollTop = top;
    });
  }

  function patchLiveRegion() {
    if (!root || !state.mounted) return;
    if (isStatus) {
      const results = root.querySelector('[data-airview-results]');
      if (results && root.querySelector(`[data-airview-view="${state.statusView}"][aria-selected="true"]`)) {
        // The 5s live refresh rebuilds this subtree, which resets every scroll
        // offset inside it. Carry the offsets across the swap so a horizontal
        // scroll in the AP or radio table is not yanked back on the next tick.
        const offsets = captureScrollOffsets(results);
        const activeKey = scrollAnchorKey(document.activeElement, results);
        results.innerHTML = radioResults();
        restoreScrollOffsets(results, offsets);
        if (activeKey) {
          const next = nodeFromAnchorKey(activeKey, results);
          if (next && typeof next.focus === 'function') next.focus({ preventScroll: true });
        }
      } else render();
      return;
    }
    const body = root.querySelector('[data-wifi-table-body]');
    if (!body) render();
    else {
      const temp = document.createElement('tbody');
      temp.innerHTML = configTable().match(/<tbody data-wifi-table-body>([\s\S]*?)<\/tbody>/)?.[1] || '';
      body.replaceChildren(...temp.childNodes);
    }
  }

  function markDirty() {
    state.dirty = true;
    if (!root.querySelector('[data-dwrt-savebar]')) render();
  }

  function openSsid(id = '') {
    const existing = state.config.ssids.find((ssid) => ssid.id === id);
    state.sheet = 'ssid';
    state.draft = existing ? clone(existing) : defaultDraft();
    render();
  }

  function openSpeed(id = '') {
    const existing = state.config.speed_limits.find((limit) => limit.id === id);
    state.sheet = 'speed';
    state.draft = existing ? clone(existing) : { id: `limit-${Date.now()}`, name: '', download_mbps: 0, upload_mbps: 0 };
    render();
  }

  function closeSheet() { state.sheet = ''; state.draft = null; render(); }

  function saveDraft() {
    if (!state.draft || !canConfigWrite()) return;
    if (state.sheet === 'ssid') {
      const draft = normalizeSsid(state.draft);
      if (!draft.name.trim() || !draft.bands.length) return;
      if (draft.bands.includes('6g') || draft.mlo) { draft.security = 'wpa3-personal'; draft.pmf = 'required'; draft.ppsk = false; }
      const index = state.config.ssids.findIndex((ssid) => ssid.id === draft.id);
      if (index >= 0) state.config.ssids[index] = draft; else state.config.ssids.push(draft);
    } else if (state.sheet === 'speed') {
      const draft = clone(state.draft);
      const index = state.config.speed_limits.findIndex((limit) => limit.id === draft.id);
      if (index >= 0) state.config.speed_limits[index] = draft; else state.config.speed_limits.push(draft);
    }
    state.sheet = '';
    state.draft = null;
    state.dirty = true;
    render();
  }

  async function saveConfig() {
    if (!canConfigWrite() || state.saving) return;
    state.saving = true;
    state.error = '';
    render();
    try {
      const payload = { ...clone(state.rawConfig), global: state.config.global, radios: state.config.radios, ssids: state.config.ssids, speed_limits: state.config.speed_limits };
      await requestJson('/api/v1/wifi/config', { method: 'PUT', body: JSON.stringify(payload) });
      await requestJson('/api/v1/wifi/config/apply', { method: 'POST', body: JSON.stringify({ reason: 'web_console_apply' }) });
      state.notice = 'Wi-Fi 配置已保存并应用。';
      state.noticeTone = 'ok';
      state.dirty = false;
      await load(true);
    } catch (error) {
      state.error = `保存 Wi-Fi 配置失败：${firstText(error.message, '未知错误')}`;
    } finally {
      state.saving = false;
      render();
    }
  }

  async function scan() {
    if (!bool(state.status.capabilities.scan_execution || state.status.capabilities.scan, false) || !state.status.radios.length || state.scanning) return;
    const apId = state.filters.environmentAp === 'all' ? selectedEnvironmentAp()?.id : state.filters.environmentAp;
    const radios = state.status.radios
      .filter((radio) => !apId || radio.ap_id === apId)
      .sort((left, right) => ({ '2g': 0, '5g': 1, '6g': 2 }[left.band] ?? 9) - ({ '2g': 0, '5g': 1, '6g': 2 }[right.band] ?? 9));
    if (!radios.length) return;
    const epoch = ++state.scanEpoch;
    state.scanning = true;
    state.scanJobs = new Map(radios.map((radio) => [radio.id, { radio_id: radio.id, band: radio.band, state: 'creating', error: '', result_count: 0 }]));
    state.notice = `正在扫描 ${radios.length} 个 Radio，扫描期间客户端可能短暂断开。`;
    state.noticeTone = 'warn';
    render();
    try {
      const batch = Date.now().toString(36);
      const results = await Promise.allSettled(radios.map((radio, index) => requestJson('/api/v1/wifi/scan', {
        cacheVersion: false,
        method: 'POST',
        body: JSON.stringify({ ap_id: radio.ap_id, radio_id: radio.id, mode: 'neighbor', idempotency_key: `web.environment.${batch}.${index}` })
      })));
      if (!state.mounted || epoch !== state.scanEpoch) return;
      results.forEach((result, index) => {
        const radio = radios[index];
        const payload = result.status === 'fulfilled' ? result.value : {};
        const source = scanJobPayload(payload);
        const jobId = firstText(source.job_id, source.id, payload.job_id, payload.id);
        state.scanJobs.set(radio.id, {
          radio_id: radio.id,
          band: radio.band,
          job_id: jobId,
          state: result.status === 'fulfilled' && jobId ? firstText(source.state, source.status, 'queued').toLowerCase() : 'failed',
          error: result.status === 'rejected' ? firstText(result.reason?.message, 'scan_job_create_failed') : jobId ? firstText(source.error_code, source.error, source.reason) : 'scan_job_id_missing',
          result_count: firstNumber(source.result_count)
        });
      });
      const started = Array.from(state.scanJobs.values()).filter((job) => job.job_id).length;
      if (!started) throw results[0]?.reason || new Error('未能创建扫描任务');
      patchScanJobs();
      const terminal = new Set(['completed', 'failed', 'cancelled', 'expired']);
      const deadline = Date.now() + 180000;
      while (state.mounted && epoch === state.scanEpoch && Date.now() < deadline) {
        const pending = Array.from(state.scanJobs.entries()).filter(([, job]) => job.job_id && !terminal.has(job.state));
        if (!pending.length) break;
        await new Promise((resolve) => {
          state.scanWaitResolve = resolve;
          state.scanTimer = window.setTimeout(() => { state.scanWaitResolve = null; resolve(); }, 2000);
        });
        state.scanTimer = 0;
        if (!state.mounted || epoch !== state.scanEpoch) return;
        const updates = await Promise.allSettled(pending.map(([, job]) => requestJson(`/api/v1/wifi/scan/jobs/${encodeURIComponent(job.job_id)}`, { cacheVersion: false })));
        updates.forEach((result, index) => {
          const [key, previous] = pending[index];
          if (result.status === 'rejected') {
            state.scanJobs.set(key, { ...previous, poll_error: firstText(result.reason?.message, 'scan_job_status_failed') });
            return;
          }
          const payload = result.value;
          const source = scanJobPayload(payload);
          state.scanJobs.set(key, {
            ...previous,
            ...source,
            state: firstText(source.state, source.status, previous.state).toLowerCase(),
            error: firstText(source.error_code, source.error, source.reason, source.failure_reason),
            result_count: firstNumber(source.result_count, source.count, asArray(source.results).length)
          });
        });
        patchScanJobs();
      }
      Array.from(state.scanJobs.entries()).forEach(([key, job]) => {
        if (job.job_id && !terminal.has(job.state)) state.scanJobs.set(key, { ...job, state: 'expired', error: 'scan_status_timeout' });
      });
      const jobs = Array.from(state.scanJobs.values());
      const completed = jobs.filter((job) => job.state === 'completed').length;
      const failed = jobs.filter((job) => ['failed', 'expired'].includes(job.state)).length;
      state.notice = completed ? `${completed} 个 Radio 扫描完成${failed ? `，${failed} 个失败` : ''}。` : `${failed || jobs.length} 个 Radio 扫描失败，详情见左侧任务状态。`;
      state.noticeTone = completed && !failed ? 'ok' : 'warn';
      await load(true);
      await loadEnvironmentHistory();
    } catch (error) {
      state.error = `启动环境扫描失败：${firstText(error.message, '未知错误')}`;
    } finally {
      if (epoch === state.scanEpoch) {
        state.scanning = false;
        render();
      }
    }
  }

  function patchScanJobs() {
    if (!root || !state.mounted) return;
    const current = root.querySelector('[data-airview-scan-jobs]');
    const holder = document.createElement('div');
    holder.innerHTML = scanJobsPanel();
    const next = holder.firstElementChild;
    if (current && next) current.replaceWith(next);
    const button = root.querySelector('[data-airview-scan]');
    if (button) {
      button.disabled = state.scanning;
      const label = button.querySelector('span');
      if (label) label.textContent = state.scanning ? '扫描任务执行中' : '扫描环境';
    }
  }

  function onClick(event) {
    const origin = event.target;
    const target = origin.closest('button, tr[data-wifi-edit], tr[data-wifi-speed-edit], tr[data-airview-radio-row]');
    if (!target) return;
    if (target.matches('[data-wifi-config-tab]')) {
      const view = target.dataset.wifiConfigTab;
      if (!['broadcasts', 'radios', 'extensions'].includes(view) || state.configView === view) return;
      state.configView = view;
      render();
      return;
    }
    if (target.matches('[data-wifi-create]')) { openSsid(); return; }
    if (target.matches('[data-wifi-edit]')) { openSsid(target.dataset.wifiEdit); return; }
    if (target.matches('[data-wifi-speed-create]')) { openSpeed(); return; }
    if (target.matches('[data-wifi-speed-edit]')) { openSpeed(target.dataset.wifiSpeedEdit); return; }
    if (target.matches('[data-wifi-sheet-close]')) { closeSheet(); return; }
    if (target.matches('[data-wifi-draft-save]')) { saveDraft(); return; }
    if (target.matches('[data-dwrt-savebar-save]')) { saveConfig(); return; }
    if (target.matches('[data-dwrt-savebar-discard]')) { state.dirty = false; state.config = normalizeConfig(state.rawConfig); render(); return; }
    if (target.matches('[data-wifi-reset-channels]')) { state.config.radios.forEach((radio) => { radio.excluded_channels = []; }); markDirty(); return; }
    if (target.matches('[data-wifi-width]')) {
      const band = target.dataset.wifiWidthBand;
      const width = Number(target.dataset.wifiWidth);
      if (!canConfigWrite() || !['2g', '5g', '6g'].includes(band) || !width) return;
      state.config.global.widths[band] = width;
      state.config.global.speed_profile = 'custom';
      markDirty();
      return;
    }
    if (target.matches('[data-wifi-apply-all]')) {
      if (!canConfigWrite()) return;
      state.config.radios.forEach((radio) => {
        const desired = Number(state.config.global.widths[radio.band]);
        if (!desired) return;
        const supported = radio.supported_widths || [];
        radio.width = !supported.length || supported.includes(desired) ? desired : Math.max(...supported.filter((value) => value <= desired), supported[0] || desired);
      });
      state.notice = '默认信道宽度已应用到全部 AP 草稿。';
      state.noticeTone = 'ok';
      markDirty();
      return;
    }
    if (target.matches('[data-wifi-channel]')) {
      const radio = radioForBand(target.dataset.wifiChannelBand);
      if (!radio || !canConfigWrite()) return;
      const value = Number(target.dataset.wifiChannel);
      const set = new Set(radio.excluded_channels || []);
      if (set.has(value)) set.delete(value); else set.add(value);
      radio.excluded_channels = Array.from(set).sort((a, b) => a - b);
      markDirty();
      return;
    }
    if (target.matches('[data-airview-radio-sheet-close]')) { closeRadioSheet(); return; }
    if (target.matches('[data-airview-ap-details]')) {
      if (!target.dataset.airviewApDetails) return;
      state.apSheetAp = target.dataset.airviewApDetails;
      state.apSheetTab = 'overview';
      render();
      return;
    }
    if (target.matches('[data-airview-ap-sheet-close]')) { state.apSheetAp = ''; state.apSheetTab = 'overview'; render(); return; }
    if (target.matches('[data-airview-ap-tab]')) { state.apSheetTab = target.dataset.airviewApTab; render(); return; }
    if (target.matches('[data-airview-radio-remove]')) { setRadioSelection(target.dataset.airviewRadioRemove, false); return; }
    if (target.matches('[data-airview-radio-save]')) { saveRadioDrafts(); return; }
    if (target.matches('[data-airview-copy]')) {
      navigator.clipboard?.writeText(target.dataset.airviewCopy || '').catch(() => {});
      return;
    }
    if (target.matches('[data-airview-radio-width]')) {
      if (!canRadioWrite()) return;
      const [band, value] = target.dataset.airviewRadioWidth.split(':');
      updateRadioDrafts(band, 'width', Number(value));
      render();
      return;
    }
    if (target.matches('[data-airview-radio-power]')) {
      if (!canRadioWrite()) return;
      const [band, value] = target.dataset.airviewRadioPower.split(':');
      updateRadioDrafts(band, 'tx_power_mode', value);
      render();
      return;
    }
    if (target.matches('[data-airview-radio-row]')) {
      if (origin.closest('input, button, select, a, label')) return;
      const id = target.dataset.airviewRadioRow;
      setRadioSelection(id, !state.selectedRadios.has(id));
      return;
    }
    if (target.matches('[data-airview-view]')) {
      const view = target.dataset.airviewView;
      if (!['radios', 'connectivity', 'environment'].includes(view) || state.statusView === view) return;
      if (view !== 'environment') state.apSheetAp = '';
      state.statusView = view;
      render();
      if (view === 'environment') loadEnvironmentHistory();
      if (view === 'connectivity') loadConnectivityEvents();
      return;
    }
    if (target.matches('[data-airview-connectivity-range]')) { state.filters.connectivityRange = Number(target.dataset.airviewConnectivityRange); render(); loadConnectivityEvents(); return; }
    if (target.matches('[data-airview-environment-range]')) { state.filters.environmentRange = target.dataset.airviewEnvironmentRange; render(); loadEnvironmentHistory(); return; }
    if (target.matches('[data-airview-environment-band]')) { state.filters.environmentBand = target.dataset.airviewEnvironmentBand; render(); return; }
    if (target.matches('[data-airview-columns]')) { state.columnEditor = target.dataset.airviewColumns; render(); return; }
    if (target.matches('[data-airview-columns-done]')) { state.columnEditor = ''; render(); return; }
    if (target.matches('[data-airview-columns-reset]')) {
      const view = target.dataset.airviewColumnsReset;
      state.columns[view] = new Set((COLUMN_DEFS[view] || []).map(([key]) => key));
      render();
      return;
    }
    if (target.matches('[data-airview-clear]')) {
      if (state.statusView === 'connectivity' && state.filters.connectivityRange !== 48) {
        state.filters.connectivityRange = 48;
        loadConnectivityEvents();
      }
      state.filters.ai = false;
      state.filters.broadcast = 'all';
      state.filters.aps = new Set(state.status.radios.map((radio) => radio.ap_id).filter(Boolean));
      state.filters.bands = new Set(state.status.radios.map((radio) => radio.band).filter(Boolean));
      state.filters.mimo.clear();
      state.filters.types.clear();
      state.filters.status.clear();
      state.filters.environmentWidths.clear();
      state.filters.environmentAp = apInventory()[0]?.id || 'all';
      state.filters.environmentBand = '';
      render();
      return;
    }
    if (target.matches('[data-airview-scan]')) scan();
  }

  function onInput(event) {
    const target = event.target;
    if (target.matches('[data-wifi-search]')) {
      state.query = target.value || '';
      const table = root.querySelector('.wifi-config-table');
      if (table) table.outerHTML = configTable();
      requestAnimationFrame(() => root.querySelector('[data-wifi-search]')?.focus({ preventScroll: true }));
      return;
    }
    if (target.matches('[data-wifi-draft]')) {
      const path = target.dataset.wifiDraft;
      const value = target.type === 'number' ? Number(target.value || 0) : target.value;
      setPath(state.draft, path, value);
      const save = root.querySelector('[data-wifi-draft-save]');
      if (save) save.disabled = !canConfigWrite() || !String(state.draft.name || '').trim() || (state.sheet === 'ssid' && !state.draft.bands.length);
      return;
    }
    if (target.matches('[data-wifi-setting]') && !['checkbox', 'radio'].includes(target.type)) {
      setPath(state.config, target.dataset.wifiSetting, target.type === 'number' ? Number(target.value || 0) : target.value);
      markDirty();
      return;
    }
    if (target.matches('[data-airview-radio-custom-power]')) {
      if (!canRadioWrite()) return;
      updateRadioDrafts(target.dataset.airviewRadioCustomPower, 'tx_power_custom', Number(target.value || 0));
      return;
    }
    if (target.matches('[data-airview-radio-min-rssi-value]')) {
      if (!canRadioWrite()) return;
      updateRadioDrafts(target.dataset.airviewRadioMinRssiValue, 'min_rssi', Number(target.value || -75));
    }
  }

  function onChange(event) {
    const target = event.target;
    if (target.matches('[data-airview-radio-select-all]')) {
      filteredRadios().forEach((radio) => {
        if (target.checked) {
          state.selectedRadios.add(radio.id);
          radioDraft(radio);
        } else {
          state.selectedRadios.delete(radio.id);
          state.radioDrafts.delete(radio.id);
        }
      });
      state.selectedRadio = state.selectedRadios.values().next().value || '';
      if (!state.selectedRadios.size) state.radioDirty = false;
      render();
      return;
    }
    if (target.matches('[data-airview-radio-select]')) {
      setRadioSelection(target.dataset.airviewRadioSelect, target.checked);
      return;
    }
    if (target.matches('[data-airview-radio-channel]')) {
      if (!canRadioWrite()) return;
      updateRadioDrafts(target.dataset.airviewRadioChannel, 'channel', Number(target.value));
      render();
      return;
    }
    if (target.matches('[data-airview-radio-min-rssi]')) {
      if (!canRadioWrite()) return;
      updateRadioDrafts(target.dataset.airviewRadioMinRssi, 'min_rssi_enabled', target.checked);
      render();
      return;
    }
    if (target.matches('[data-wifi-setting]')) {
      const value = target.type === 'checkbox' ? target.checked : target.type === 'number' ? Number(target.value || 0) : target.value;
      const path = target.dataset.wifiSetting;
      setPath(state.config, path, value);
      if (path === 'global.mesh' || path === 'global.mesh_monitor') {
        state.dirty = true;
        render();
        return;
      }
      markDirty();
      return;
    }
    if (target.matches('[data-wifi-draft-toggle]')) { setPath(state.draft, target.dataset.wifiDraftToggle, target.checked); render(); return; }
    if (target.matches('[data-wifi-draft-band]')) {
      const bands = new Set(state.draft.bands || []);
      if (target.checked) bands.add(target.dataset.wifiDraftBand); else bands.delete(target.dataset.wifiDraftBand);
      state.draft.bands = Array.from(bands);
      render();
      return;
    }
    if (target.matches('[data-airview-ai]')) { state.filters.ai = target.checked; return; }
    if (target.matches('[data-airview-broadcast]')) { state.filters.broadcast = target.value; patchLiveRegion(); return; }
    if (target.matches('[data-airview-environment-ap]')) { state.filters.environmentAp = target.value; render(); loadEnvironmentHistory(); return; }
    if (target.matches('[data-airview-column-all]')) {
      const view = target.dataset.airviewColumnAll;
      state.columns[view] = target.checked ? new Set((COLUMN_DEFS[view] || []).map(([key]) => key)) : new Set();
      render();
      return;
    }
    if (target.matches('[data-airview-signal]')) {
      const value = Number(target.value);
      if (target.dataset.airviewSignal === 'min') state.filters.signalMin = Math.min(value, state.filters.signalMax);
      else state.filters.signalMax = Math.max(value, state.filters.signalMin);
      const control = target.closest('.airview-signal-range');
      if (control) {
        control.style.setProperty('--signal-min', `${(state.filters.signalMin + 100) / 80 * 100}%`);
        control.style.setProperty('--signal-max', `${(state.filters.signalMax + 100) / 80 * 100}%`);
        const labels = control.querySelectorAll(':scope > span');
        if (labels[0]) labels[0].textContent = String(state.filters.signalMin);
        if (labels[1]) labels[1].textContent = String(state.filters.signalMax);
      }
      patchLiveRegion();
      return;
    }
    if (target.matches('[data-airview-filter]')) {
      if (target.dataset.airviewFilter.startsWith('columns.')) {
        const view = target.dataset.airviewFilter.split('.')[1];
        const columns = state.columns[view];
        if (target.checked) columns.add(target.value); else columns.delete(target.value);
        render();
        return;
      }
      const set = state.filters[target.dataset.airviewFilter];
      if (!(set instanceof Set)) return;
      if (target.checked) set.add(target.value); else set.delete(target.value);
      patchLiveRegion();
    }
  }

  function onKeydown(event) {
    const row = event.target.closest('tr[data-airview-radio-row]');
    if (!row || event.target !== row || !['Enter', ' '].includes(event.key)) return;
    event.preventDefault();
    const id = row.dataset.airviewRadioRow;
    setRadioSelection(id, !state.selectedRadios.has(id));
  }

  root.addEventListener('click', onClick);
  root.addEventListener('input', onInput);
  root.addEventListener('change', onChange);
  root.addEventListener('keydown', onKeydown);
  stage?.classList.add('is-wifi-management');
  render();
  load();
  state.refreshTimer = window.setInterval(() => {
    if (!state.mounted || document.hidden || state.refreshing || state.scanning) return;
    if (state.dirty || state.radioDirty || state.saving || state.sheet) return;
    load(true);
  }, isStatus ? 5000 : 20000);

  return {
    refresh() { return load(true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      state.environmentHistorySeq += 1;
      state.scanEpoch += 1;
      if (state.refreshTimer) clearInterval(state.refreshTimer);
      if (state.scanTimer) clearTimeout(state.scanTimer);
      if (state.scanWaitResolve) state.scanWaitResolve();
      state.scanWaitResolve = null;
      root.removeEventListener('click', onClick);
      root.removeEventListener('input', onInput);
      root.removeEventListener('change', onChange);
      root.removeEventListener('keydown', onKeydown);
      root.replaceChildren();
      root.classList.remove('route-workspace', 'policy-table-route-host', 'wifi-management-route-host', 'wireless-status-route-host', 'wifi-config-route-host');
      stage?.classList.remove('is-wifi-management');
    }
  };
}

export default { mount };
